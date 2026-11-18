"""Tests for the per-flow audit trail (task 4.6).

The trail's contract is twofold, and both halves are asserted here:

* it carries enough to answer *who did what* for one flow — the flow id, the subject, the
  client, the toolset, and the credential call's result;
* it carries none of the material that would answer *with what* — no token, no code, no
  key, no verifier.

The second half needs a real instrument rather than an inspection: the records are built
from values that exist during the run, so the test drives a whole flow and then looks for
each of those values in what was actually written.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from gateway.__main__ import configure_logging, main
from gateway.audit import AuditTrail
from gateway.codes import code_challenge_for
from gateway.settings import Settings

from tests.conftest import (
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    make_client,
    runtime_of,
    surface_settings,
)

ORIGIN = "http://localhost:8090"
RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"

REALM_ISSUER = "https://keycloak:8443/realms/dial"
REALM_TOKEN_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/token"
REALM_CERTS_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/certs"
# Core's listing read — the flow's one toolset read — and the credential API.
CORE_LISTING_URL = f"http://core:8080/openai/toolsets/{TOOLSET_NAME}"
CORE_SIGNIN_URL = "http://core:8080/v1/ops/toolset/signin"

UPSTREAM_REDIRECT_URI = "http://localhost:8765/callback"
UPSTREAM_CHALLENGE = "the-upstream-code-challenge"
UPSTREAM_CODE = "the-upstream-authorization-code"

# The provider's session-bound refresh token, as the exchange returns it. It exists in the
# run so the audit-hygiene tests measure it as a value a careless record could carry.
PROVIDER_REFRESH_TOKEN = "the-provider-session-refresh-token"

SUBJECT = "3a0d60f4-0000-0000-0000-000000000000"
HARNESS_VERIFIER = "a-verifier-for-the-audit-test"
HARNESS_STATE = "the-harness-state"


def _b64_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Idp:
    """A generated identity-provider keypair, and the tokens it mints for the test."""

    def __init__(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        numbers = key.public_key().public_numbers()
        self.jwks: dict[str, Any] = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "the-idp-key",
                    "n": _b64_uint(numbers.n),
                    "e": _b64_uint(numbers.e),
                }
            ]
        }

    def token(self) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": REALM_ISSUER,
                "aud": "dial-chat",
                "typ": "Bearer",
                "iat": now,
                "exp": now + 300,
                "jti": "the-identity-token-id",
                "sub": SUBJECT,
                "roles": ["admin"],
                "project": "proj-alpha",
                "email": "dial@example.test",
            },
            self.pem,
            algorithm="RS256",
            headers={"kid": "the-idp-key"},
        )


def _gateway(private_key_pem: str, tmp_path: Path, idp: Idp) -> Any:
    """A gateway whose outbound calls are all intercepted, ready to drive a whole flow."""
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))
    router = respx.mock(assert_all_called=False)
    router.get(REALM_CERTS_URL).mock(return_value=httpx.Response(200, json=idp.jwks))
    router.post(REALM_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": idp.token(),
                "refresh_token": PROVIDER_REFRESH_TOKEN,
                "token_type": "Bearer",
            },
        )
    )
    router.get(CORE_LISTING_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "auth_settings": {
                    "authentication_type": "OAUTH",
                    "client_id": "core-upstream-client",
                    "authorization_endpoint": "https://mcp.notion.com/authorize",
                    "redirect_uri": UPSTREAM_REDIRECT_URI,
                    "code_challenge": UPSTREAM_CHALLENGE,
                    "code_challenge_method": "S256",
                    "scopes_supported": ["default"],
                    "user_level_auth_status": "SIGNED_OUT",
                    "global_auth_status": "SIGNED_OUT",
                }
            },
        )
    )
    router.post(CORE_SIGNIN_URL).mock(return_value=httpx.Response(200, json=True))
    return router, settings


def _run_flow(client: Any, *, signin_status: int = 200) -> str:
    """Drive a whole sign-in through the endpoints, returning the harness's code.

    The client is pre-approved: the retained flow-lifecycle scenarios carry the
    approved-client condition, so the checkpoint passes this flow through with no page and
    the trail is the flow's own story. The attribution events a first-attribution run adds
    are the checkpoint requirement's own tests.
    """
    runtime_of(client).approved_clients.approve(SUBJECT, PRE_REGISTERED_CLIENT_ID)
    response = client.get(
        "/dial/authorize",
        params={
            "response_type": "code",
            "client_id": PRE_REGISTERED_CLIENT_ID,
            "redirect_uri": LOOPBACK_REDIRECT_URI,
            "code_challenge": code_challenge_for(HARNESS_VERIFIER),
            "code_challenge_method": "S256",
            "resource": RESOURCE,
            "state": HARNESS_STATE,
        },
    )
    flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    client.get(
        "/dial/callback/idp",
        params={"state": flow_id, "code": "the-idp-code"},
    )
    done = client.get(
        "/dial/callback/upstream",
        params={"state": flow_id, "code": UPSTREAM_CODE},
    )
    assert done.status_code == HTTPStatus.FOUND
    location: str = done.headers["location"]
    return location


# ------------------------------------------------------------------ the record


def records_of(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    """The audit records a run emitted, as parsed documents.

    Read from the captured records rather than from the rendered text: the fields are the
    contract, and a text match would pass on a record whose fields had been renamed or
    dropped.
    """
    return [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]


def test_the_flow_emits_its_whole_story_with_identifiers(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Every event of one flow, each carrying who and what — and none carrying how.

    Read as JSON records rather than as text: the fields are the contract, and a text match
    would pass on a record whose fields had been renamed or dropped.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router, make_client(settings, private_key_pem) as client:
        _run_flow(client)

    records = records_of(caplog)
    events = [record["event"] for record in records]
    assert events == [
        "flow_allocated",
        "upstream_callback",
        "signin_result",
        "code_issued",
    ]

    for record in records:
        assert record["flow_id"]
        assert record["client_id"] == PRE_REGISTERED_CLIENT_ID
        # The flow's resource fact is the resource URI the flow serves — a toolset or an
        # app — and the allocation carries the kind alongside it.
        assert record["resource"] == RESOURCE
    assert records[0]["resource_kind"] == "toolset"

    # The subject appears once the flow knows who the user is: the events after the
    # identity leg carry it, and the allocation that precedes it cannot.
    for record in records[1:]:
        assert record["subject"] == SUBJECT
    assert next(r for r in records if r["event"] == "signin_result")["result"] == (
        "accepted"
    )


def test_the_allocation_record_carries_the_resource_kind(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A flow is now addressed to a toolset or an app, so allocation names which.

    A flat authorization server serves two kinds, so the kind is the fact that tells an
    operator reading the trail which namespace's authenticated read the flow's later stages
    will make — and the flow's single `resource` fact is the resource URI it serves.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router, make_client(settings, private_key_pem) as client:
        _run_flow(client)

    allocated = next(r for r in records_of(caplog) if r["event"] == "flow_allocated")
    assert allocated["resource_kind"] == "toolset"
    assert allocated["resource"] == RESOURCE
    # The renamed fact: the flow's own events no longer carry a `toolset` fact at all.
    assert "toolset" not in allocated


def test_a_refused_credential_call_is_recorded_as_a_refusal(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The outcome field distinguishes a refusal from a fault, which is the operator's question.

    A user without access to the toolset and a Core that could not be reached look identical
    from the outside — both leave the harness without a token — so the trail is what tells
    them apart.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router:
        router.post(CORE_SIGNIN_URL).mock(return_value=httpx.Response(403, json={}))
        with make_client(settings, private_key_pem) as client:
            response = client.get(
                "/dial/authorize",
                params={
                    "response_type": "code",
                    "client_id": PRE_REGISTERED_CLIENT_ID,
                    "redirect_uri": LOOPBACK_REDIRECT_URI,
                    "code_challenge": code_challenge_for(HARNESS_VERIFIER),
                    "code_challenge_method": "S256",
                    "resource": RESOURCE,
                },
            )
            flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
            client.get(
                "/dial/callback/idp",
                params={"state": flow_id, "code": "the-idp-code"},
            )
            client.get(
                "/dial/callback/upstream",
                params={"state": flow_id, "code": UPSTREAM_CODE},
            )

    records = records_of(caplog)
    results = [r for r in records if r["event"] == "signin_result"]
    assert [r["result"] for r in results] == ["access_refused"]
    assert any(r["event"] == "flow_leg_failed" for r in records)


def test_no_credential_material_reaches_any_record(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Every credential the flow handled, looked for in what was written.

    Each value below genuinely existed during the run — the identity token, the upstream
    code, the harness code, the gateway's own verifier, the signing key — so this is a
    measurement of the trail rather than of an empty log. The events assertion at the end
    is the control that the log is populated.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router, make_client(settings, private_key_pem) as client:
        location = _run_flow(client)
        harness_code = parse_qs(urlparse(location).query)["code"][0]
        identity_token = idp.token()

    rendered = caplog.text
    for secret in (
        harness_code,
        identity_token,
        UPSTREAM_CODE,
        UPSTREAM_CHALLENGE,
        idp.pem,
        private_key_pem,
        # The provider's session refresh token is the most powerful credential the flow
        # handles: it must not reach the trail either.
        PROVIDER_REFRESH_TOKEN,
    ):
        assert secret not in rendered, (
            "the audit trail must not carry credential material"
        )

    assert "flow_allocated" in rendered
    assert "code_issued" in rendered


def test_the_verifier_is_never_written(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The gateway's own PKCE verifier is a credential too, and it is never recorded.

    It is server-side for the leg's whole life, and a record that carried it would put it
    where the leg's own design says it must never be.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router, make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params={
                "response_type": "code",
                "client_id": PRE_REGISTERED_CLIENT_ID,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "code_challenge": code_challenge_for(HARNESS_VERIFIER),
                "code_challenge_method": "S256",
                "resource": RESOURCE,
            },
        )
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        record = runtime_of(client).flows.get(flow_id)
        assert record is not None
        verifier = record.idp_code_verifier

    assert verifier
    assert verifier not in caplog.text


def test_a_flow_refusal_is_recorded_with_this_gateways_own_text(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The reason is fixed text, so a caller cannot write arbitrary content into the log."""
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router, make_client(settings, private_key_pem) as client:
        client.get(
            "/dial/callback/upstream",
            params={"state": "<script>alert(1)</script>", "code": "x"},
        )

    # The refusal is a page, and nothing about the page's input reached the trail.
    assert "<script>" not in caplog.text


def test_the_trail_is_written_to_a_dedicated_logger() -> None:
    """A dedicated logger so an operator can route audit records apart from operations."""
    trail = AuditTrail()
    trail.client_registered("a-client", source="dcr")

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("gateway.audit")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        trail.client_registered("another-client", source="dcr")
    finally:
        logger.removeHandler(handler)

    assert logger.name == "gateway.audit"
    assert "another-client" in stream.getvalue()


def test_a_record_is_one_json_line() -> None:
    """One line per event, so a collector's line-oriented reader gets whole records."""
    trail = AuditTrail()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("gateway.audit")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        trail.client_registered("a-client", source="dcr")
    finally:
        logger.removeHandler(handler)

    line = stream.getvalue().strip()
    record = json.loads(line)
    assert line.count("\n") == 0
    assert record["event"] == "client_registered"
    assert isinstance(record["at"], float)


# -------------------------------------- task 4.10: refusals before a flow is allocated


def flow_refusals(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    """The `flow_refused` records a run emitted, as parsed documents."""
    return [
        record for record in records_of(caplog) if record["event"] == "flow_refused"
    ]


def authorize_params_for(**overrides: str) -> dict[str, str]:
    """A well-formed authorization request, with any parameter overridden."""
    params = {
        "response_type": "code",
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": "a-challenge",
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }
    params.update(overrides)
    return params


def test_an_unknown_client_refusal_writes_exactly_one_record(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The refusal class an operator debugs most: "my harness is rejected as unknown".

    One record, carrying the fixed reason and the request's own (public) facts — which is
    what lets the diagnosis start from the log rather than from an external reproduction.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router, make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=authorize_params_for(client_id="an-unknown-client"),
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "unknown_client"
    assert refusals[0]["client_id"] == "an-unknown-client"
    assert refusals[0]["redirect_uri"] == LOOPBACK_REDIRECT_URI
    assert refusals[0]["resource"] == RESOURCE
    assert refusals[0]["name"] == TOOLSET_NAME
    # The pre-allocation class carries no flow id at all — the field is absent, not null:
    # there is no flow, so there is nothing for the field to state.
    assert "flow_id" not in refusals[0]


def test_a_redirect_uri_refusal_names_the_client_the_uri_and_the_resource(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The field class the redirect-uri finding needed, recorded at the refusal itself."""
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)
    hostile_uri = "http://127.0.0.1:9999/not-registered"

    with router, make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize", params=authorize_params_for(redirect_uri=hostile_uri)
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "unregistered_redirect_uri"
    assert refusals[0]["client_id"] == PRE_REGISTERED_CLIENT_ID
    assert refusals[0]["redirect_uri"] == hostile_uri
    assert refusals[0]["resource"] == RESOURCE


def test_a_missing_resource_refusal_is_recorded(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)
    params = authorize_params_for()
    del params["resource"]

    with router, make_client(settings, private_key_pem) as client:
        response = client.get("/dial/authorize", params=params)

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.FOUND
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "missing_resource"


def test_a_limiter_refusal_on_authorize_is_recorded(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The limiter's 429 is a refusal class recorded facts-free.

    The limiter bounds how much work a caller may make, not how much log it may make: a
    refused request's facts are the caller's own values, and writing them at the rate the
    limiter exists to refuse is the volume the bound is about. So this branch records the
    reason and nothing else — the negative control is the record *shape*, since the same
    facts land on every other refusal of the same request.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=1,
        gateway_rate_global_per_minute=100,
    )

    with make_client(settings, private_key_pem) as client:
        client.get("/dial/authorize", params=authorize_params_for())
        limited = client.get("/dial/authorize", params=authorize_params_for())

    refusals = flow_refusals(caplog)
    assert limited.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "rate_limited"
    # No caller-supplied fact reached the record, although the request carried all four.
    assert refusals[0]["client_id"] is None
    assert refusals[0]["redirect_uri"] is None
    assert refusals[0]["resource"] is None
    assert refusals[0]["name"] is None


def test_a_discovery_guard_refusal_is_recorded(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The discovery guard's refusal, with the fixed reason and the offered path.

    The path is a reserved first segment, so the record names the reserved class rather
    than a mapping membership.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))

    with make_client(settings, private_key_pem) as client:
        response = client.get("/.well-known/oauth-protected-resource/dial/token/mcp")

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "reserved_path_segment"
    assert refusals[0]["name"] == "token"
    # The discovery guard serves one kind, so it names the namespace explicitly.
    assert refusals[0]["resource_kind"] == "toolset"


def test_a_path_guard_refusal_records_the_offered_path_truncated(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A path-guard refusal lands one record with the fixed reason and the offered path.

    The offered path is the truncated non-credential `name`/`resource` fact every
    caller-supplied value passes through; the fixed-vocabulary reason says which class
    refused it.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/.well-known/oauth-protected-resource/dial/toolsets/public/a%7Bb/mcp"
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "invalid_resource_path"
    assert refusals[0]["resource_kind"] == "toolset"


def test_a_restriction_excluded_name_is_recorded_with_its_own_reason(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The request-time guard's restriction class carries its own fixed-vocabulary token.

    With a restriction configured, a path it excludes is refused by the guard — not by any
    mapping membership check — and the trail distinguishes the exclusion from a shape
    violation and from a reserved first segment.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/.well-known/oauth-protected-resource/dial/not-in-the-restriction/mcp"
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "restricted_toolset"
    assert refusals[0]["name"] == "not-in-the-restriction"
    assert refusals[0]["resource_kind"] == "toolset"


def test_an_invalid_token_request_is_recorded_without_the_code_it_presented(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/token",
            data={
                "grant_type": "authorization_code",
                "code": "a-code-that-is-not-ours",
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "client_id": PRE_REGISTERED_CLIENT_ID,
                "code_verifier": HARNESS_VERIFIER,
                "resource": RESOURCE,
            },
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "invalid_grant"
    # The facts the request offered are recorded; the code and verifier it presented are not.
    assert refusals[0]["client_id"] == PRE_REGISTERED_CLIENT_ID
    assert refusals[0]["resource"] == RESOURCE
    assert "a-code-that-is-not-ours" not in json.dumps(refusals[0])
    assert HARNESS_VERIFIER not in json.dumps(refusals[0])


def test_a_disabled_registration_is_recorded(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The registration path's disabled refusal, with DCR off (the default)."""
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/register", json={"redirect_uris": [LOOPBACK_REDIRECT_URI]}
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "registration_disabled"


def test_an_injected_value_writes_no_free_form_content(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The negative control for the whole class: a caller cannot write content into the log.

    The values a caller controls are crafted to try to split the record (an embedded
    newline), forge a field (JSON as a parameter), and inject markup. None of it reaches the
    record as free-form text: each value lands in its own field, `json.dumps` encodes it,
    and the record stays one line with the gateway's own vocabulary in `reason`.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)
    hostile = (
        '{"event": "forged"} newline-> \n'
        '{"at": 0, "event": "a-second-record", "reason": "forged"} <script>alert(1)</script>'
    )

    with router, make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=authorize_params_for(
                client_id=hostile, redirect_uri=hostile, resource=hostile
            ),
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    # Exactly one record: the hostile value's embedded newline did not split it, and its
    # forged `event`/`reason` did not displace the gateway's own.
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "unknown_client"
    assert refusals[0]["event"] == "flow_refused"
    # The value is present as a value, entirely inside its own field.
    assert refusals[0]["client_id"] == hostile
    # The records are still one JSON line each: the collector sees one record per refusal.
    assert all("\n" not in record.getMessage() for record in caplog.records)


# ------------------------------------------------- the caller-supplied facts' length bound


def test_an_over_long_fact_lands_truncated(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The caller's values are bounded at the emit, so a record cannot be grown without limit.

    A fact is the caller's own value and its length is the caller's choice: an
    unauthenticated request naming a megabyte-long client id would otherwise land in the
    log in full, which makes the trail — the one place that records refusals at the rate
    they arrive — a volume amplifier the caller sizes. The truncation is the measurement:
    the record carries the cap's worth of the value and not one character more, while the
    prefix that identifies the client is intact.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    cap = 256
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"), audit_fact_max_length=cap
    )
    over_long = "c" * (cap * 40)

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize", params=authorize_params_for(client_id=over_long)
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "unknown_client"
    assert refusals[0]["client_id"] == "c" * cap
    # The whole value is nowhere in the record, not merely shortened in one field.
    assert over_long not in caplog.text


def test_the_bound_is_the_configured_cap_not_a_fixed_length(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The cap is an operator setting, and the gateway's own vocabulary is never cut by it.

    An absurdly small cap is the instrument: it is the setting at its least forgiving, and
    it separates the two kinds of field in a record. A caller's fact is truncated to the
    cap — that is what the cap is for — while the `reason` and `event` the trail exists to
    be read by come through whole. A bound applied to every string would have turned this
    record's reason into `unknown_`, and a log whose vocabulary is cut to the caller's own
    fact cap is a log an operator cannot group or alert on.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"), audit_fact_max_length=8
    )
    client_id = "client-id-longer-than-eight"

    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize", params=authorize_params_for(client_id=client_id)
        )

    refusals = flow_refusals(caplog)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert refusals[0]["client_id"] == client_id[:8]
    assert refusals[0]["reason"] == "unknown_client"
    assert refusals[0]["event"] == "flow_refused"


def test_a_trail_built_without_settings_is_bounded_too() -> None:
    """The bound is a property of the trail, not of the configuration that built it.

    A trail constructed with no arguments — a helper's, or a test's — is bounded by the
    default the settings model also carries, so the one construction path that does not
    read settings cannot be the one that omits the bound.
    """
    oversized = 5_000

    trail = AuditTrail()
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    logger = logging.getLogger("gateway.audit")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        trail.client_registered("c" * oversized, source="dcr")
    finally:
        logger.removeHandler(handler)

    record = json.loads(stream.getvalue().strip())
    assert len(record["client_id"]) < oversized


def test_no_credential_material_reaches_a_refusal_record(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A whole refused flow, with the token, the code, and the verifier absent from the trail.

    The instrument is the run: the identity token, the upstream code, and the harness's
    verifier all exist as values a careless refusal record could carry, so their absence is
    a measurement rather than an assertion about the source.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    idp = Idp()
    router, settings = _gateway(private_key_pem, tmp_path, idp)

    with router, make_client(settings, private_key_pem) as client:
        # A flow that allocates and runs, then a request refused before allocation: both
        # record classes are on the trail by the time the assertions run.
        _run_flow(client)
        client.get(
            "/dial/authorize",
            params=authorize_params_for(client_id="unknown-after-a-flow"),
        )
        identity = idp.token()

    rendered = caplog.text
    # The negative control: the refused request's facts are on the trail, so the absences
    # below measure a populated log.
    assert "unknown-after-a-flow" in rendered
    assert "flow_refused" in rendered

    for secret in (identity, UPSTREAM_CODE, HARNESS_VERIFIER, idp.pem):
        assert secret not in rendered, "a credential reached the audit trail"


# ------------------------------- the runtime wiring (task 4.11): the trail is observable

# The audit records are emitted at INFO on `gateway.audit`, and the platform's root logger
# carries no handlers and sits at WARNING — so a process that reaches `main()` without
# configuring logging drops every record before any sink sees it, and the gateway then has
# no audit trail an operator can read at all. Nothing above could catch that: every test
# attaches its own handler (through `caplog` or directly), which is what keeps the suite
# hermetic and is also what hid the defect from a green suite. The tests below pin the
# *runtime* wiring instead — the configuration `main()` performs — so the trail's
# reachability is asserted rather than assumed.


@contextmanager
def runtime_logging() -> Iterator[None]:
    """Apply the entry point's logging configuration, then put the loggers back.

    The configuration is process-wide by design, so a test that ran it and left it in
    place would silently change every later test's logging; the saved state is restored
    on the way out for the same reason the suite's fixtures disable `.env` reading.
    """
    logger = logging.getLogger("gateway")
    saved = (list(logger.handlers), logger.level, logger.propagate)
    configure_logging()
    try:
        yield
    finally:
        logger.handlers[:] = saved[0]
        logger.setLevel(saved[1])
        logger.propagate = saved[2]


def test_the_wiring_delivers_an_audit_record_to_the_container_log(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The record reaches standard output, which is where a container's collector reads.

    Captured from the stream rather than from `caplog`: the claim is that the process's
    own configuration writes the record, and a `caplog` assertion would pass on a handler
    this test attached rather than on the one `main()` installs.
    """
    with runtime_logging():
        AuditTrail().flow_refused("unknown_client", client_id="a-refused-client")

    rendered = capsys.readouterr().out
    lines = [line for line in rendered.splitlines() if "flow_refused" in line]
    assert len(lines) == 1, (
        "the audit record did not reach standard output exactly once"
    )
    # The line carries the record's fields as a JSON document, plus the metadata prefix.
    payload = json.loads(lines[0].split(" ", 3)[3])
    assert payload["event"] == "flow_refused"
    assert payload["reason"] == "unknown_client"
    assert payload["client_id"] == "a-refused-client"


def test_the_wiring_covers_every_logger_in_the_package() -> None:
    """One configuration point routes the audit, store, and app records alike.

    All three log under `gateway`, so a level set there is what decides whether their
    records survive — the level is the setting that was missing, so it is asserted
    directly rather than inferred from one record arriving.
    """
    with runtime_logging():
        logger = logging.getLogger("gateway")
        assert logger.level == logging.INFO
        for name in ("gateway.audit", "gateway.store", "gateway.app"):
            assert logging.getLogger(name).isEnabledFor(logging.INFO), name


def test_the_wiring_is_idempotent() -> None:
    """A second configuration attaches no second handler, so no record is written twice.

    A process can reach this function more than once — a re-import, a test, a reloader —
    and a trail that prints every event twice is worse than one that prints it once: a
    collector reading the log would count two flows where one ran.
    """
    with runtime_logging():
        logger = logging.getLogger("gateway")
        attached = len(logger.handlers)
        configure_logging()
        configure_logging()
        assert len(logger.handlers) == attached


def test_the_wiring_does_not_capture_the_process_root() -> None:
    """The gateway's records stop at its own logger rather than propagating to the root.

    Propagation is off so a deployment that also configures a root handler does not receive
    a second copy of every audit record.
    """
    with runtime_logging():
        logger = logging.getLogger("gateway")
        assert logger.propagate is False


def test_the_wiring_leaves_uvicorns_loggers_alone() -> None:
    """The wiring configures `gateway` and nothing else; uvicorn's logging is untouched.

    The access log carries request lines, and on the callback path those carry an
    authorization code — which is why the entry point asks uvicorn to keep the access log
    off. This is the check that the gateway's own configuration does not undo that by
    attaching a handler to `uvicorn.access` or by setting its level: a handler here would
    put those lines in the container log whatever `uvicorn.run` was asked for.
    """
    access = logging.getLogger("uvicorn.access")
    error = logging.getLogger("uvicorn.error")
    with runtime_logging():
        for logger in (access, error):
            assert not any(
                getattr(handler, "_dial_mcp_gateway_handler", False)
                for handler in logger.handlers
            ), f"the gateway's wiring installed a handler on {logger.name}"


def test_the_entry_point_asks_uvicorn_for_no_access_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half, on the call itself: `main()` passes `access_log=False`.

    The wiring above cannot prove the request line is never written — uvicorn's own
    configuration is what decides that, and it acts on the argument rather than on the
    gateway's loggers. So the call is intercepted and its arguments read. The app is
    stubbed because this test is about the arguments `main()` passes, not about building a
    serving application; the required settings are supplied through the environment and
    `.env` reading is switched off, so the test needs no local configuration.
    """
    captured: dict[str, Any] = {}

    def record(*_args: Any, **kwargs: Any) -> None:
        captured.update(kwargs)

    monkeypatch.setattr("uvicorn.run", record)
    monkeypatch.setattr("gateway.__main__.create_app", lambda _settings: object())
    monkeypatch.setattr(
        Settings, "model_config", {**Settings.model_config, "env_file": None}
    )
    monkeypatch.setenv("ROLES_SOURCE_PATH", "roles")
    monkeypatch.setenv("IDP_SSO_SESSION_MAX_SECONDS", "86400")
    # The client secret is required at startup in both toggle positions, so the
    # environment this test builds carries one; the test's subject is the uvicorn
    # arguments, not the secret.
    monkeypatch.setenv("IDP_CLIENT_SECRET", "the-client-secret")
    monkeypatch.setenv(
        "GATEWAY_CUSTODY_KEYS",
        '{"test-key": "hBTyfI0jIFOjTF0JSNsGVO586Eqiz93EkdncC7bvB4A="}',
    )

    main()

    assert captured["access_log"] is False
