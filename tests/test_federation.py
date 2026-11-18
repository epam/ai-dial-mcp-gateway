"""Tests for the federation flow's legs (tasks 4.1-4.3).

The flow is tested end to end through the real endpoints with respx standing in for the
identity provider, Core, and the upstream — deliberately, because the properties under
test are about what crosses each boundary and in what order, and a test that called the
flow's functions directly would assert the ordering it was handed rather than the ordering
the routes produce.

Every assertion about a credential is an assertion that it does *not* cross: the
identity-provider verifier never appears in a response, the user's identity token never
appears in a log, the upstream code is used once and never echoed, and no provider refresh
token is ever requested.
"""

from __future__ import annotations

import base64
import html
import json
import logging
import re
import time
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
from fastapi.testclient import TestClient
from gateway.codes import code_challenge_for
from gateway.core import CoreClient, ToolsetSettings, TrustFaultError
from gateway.flow import _undeliverable_parameters

from tests.conftest import (
    APPS_NAME,
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    assert_hardening_headers,
    generate_key_pem,
    make_client,
    make_settings,
    runtime_of,
    surface_settings,
)

ORIGIN = "http://localhost:8090"
RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"
APP_RESOURCE = f"{ORIGIN}/apps/{APPS_NAME}/mcp"

# The identity provider's endpoints, as the settings build them. The authorize endpoint is
# addressed at the browser-facing issuer; the token and JWKS ones go over the back channel,
# which is the split the flow depends on.
REALM_ISSUER = "https://keycloak:8443/realms/dial"
REALM_AUTHORIZE_URL = f"{REALM_ISSUER}/protocol/openid-connect/auth"
REALM_TOKEN_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/token"
REALM_CERTS_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/certs"

# Core's listing read — the flow's one toolset read, carrying availability, the
# settings projection, and the per-caller statuses in one answer — and the credential
# API the upstream leg calls.
CORE_LISTING_URL = f"http://core:8080/openai/toolsets/{TOOLSET_NAME}"
CORE_SIGNIN_URL = "http://core:8080/v1/ops/toolset/signin"

# The apps read the app flow makes: the single-app projection, as Core serves it.
CORE_APP_URL = f"http://core:8080/openai/applications/{APPS_NAME}"

# The toolset's public OAuth settings as Core's projection publishes them. `UPSTREAM_REDIRECT_URI`
# is the toolset's STORED callback — the Chat-editor shape a UX save writes — which the fix
# requires be an input to no leg; the gateway derives its own callback instead.
UPSTREAM_CLIENT_ID = "core-upstream-client"
UPSTREAM_AUTHORIZE_ENDPOINT = "https://mcp.notion.com/authorize"
UPSTREAM_REDIRECT_URI = "http://localhost:8765/callback"
UPSTREAM_CHALLENGE = "the-upstream-code-challenge-core-published"
UPSTREAM_SCOPES = ["default"]

# The gateway's own derived upstream callback (`{origin}/dial/callback/upstream`), the value
# every consent leg carries and the stored field can never steer.
UPSTREAM_CALLBACK_URI = f"{ORIGIN}/dial/callback/upstream"

# The upstream's callback parameters, as the consent returns them.
UPSTREAM_CODE = "the-upstream-authorization-code"
UPSTREAM_STATE = "the-upstream-state-value"

# The provider's session-bound refresh token, as its code exchange returns it. Its custody
# is asserted elsewhere; here it exists so the flow completes the way a real one does.
PROVIDER_REFRESH_TOKEN = "the-provider-session-refresh-token"

# The subject and claims a real identity token carries.
SUBJECT = "3a0d60f4-0000-0000-0000-000000000000"
IDENTITY_CLAIMS: dict[str, Any] = {
    "sub": SUBJECT,
    "roles": ["admin"],
    "project": "proj-alpha",
    "email": "dial@example.test",
    "preferred_username": "dial",
}

# The harness's own PKCE verifier, and the state it correlates its callback by.
HARNESS_VERIFIER = "a-verifier-for-the-flow-test"
HARNESS_STATE = "the-harness-state"


def _b64_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Idp:
    """A generated identity-provider keypair, and a token signed by it."""

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

    def token(self, *, pem: str | None = None, **overrides: Any) -> str:
        """A token signed by this key (or another, for the negative control)."""
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": REALM_ISSUER,
            "aud": "dial-chat",
            "azp": "dial-cli",
            "typ": "Bearer",
            "iat": now,
            "exp": now + 300,
            "jti": "the-identity-token-id",
            **IDENTITY_CLAIMS,
        }
        claims.update(overrides)
        return jwt.encode(
            claims, pem or self.pem, algorithm="RS256", headers={"kid": "the-idp-key"}
        )


@pytest.fixture
def idp() -> Idp:
    """A keypair generated per test, so the verification path is genuinely exercised."""
    return Idp()


def toolset_projection(**overrides: Any) -> dict[str, Any]:
    """Core's listing projection, with no verifier or secret anywhere in it.

    The per-caller statuses ride the same `auth_settings` member as the OAuth fields —
    the listing read's enrichment — so one answer carries everything the flow decides
    on. SIGNED_OUT by default, so the flow proceeds to the consent leg.
    """
    auth: dict[str, Any] = {
        "authentication_type": "OAUTH",
        "client_id": UPSTREAM_CLIENT_ID,
        "authorization_endpoint": UPSTREAM_AUTHORIZE_ENDPOINT,
        "redirect_uri": UPSTREAM_REDIRECT_URI,
        "code_challenge": UPSTREAM_CHALLENGE,
        "code_challenge_method": "S256",
        "scopes_supported": list(UPSTREAM_SCOPES),
        "dynamically_registered": True,
        "user_level_auth_status": "SIGNED_OUT",
        "global_auth_status": "SIGNED_OUT",
    }
    auth.update(overrides)
    return {"name": TOOLSET_NAME, "auth_settings": auth}


def authorize_params(**overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": code_challenge_for(HARNESS_VERIFIER),
        "code_challenge_method": "S256",
        "resource": RESOURCE,
        "state": HARNESS_STATE,
    }
    params.update(overrides)
    return params


def start_flow(client: TestClient, **overrides: str) -> str:
    """Authorize, and return the flow id the provider leg carries as its state."""
    response = client.get("/dial/authorize", params=authorize_params(**overrides))
    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    assert location.startswith(REALM_AUTHORIZE_URL)
    flow_id: str = parse_qs(urlparse(location).query)["state"][0]
    return flow_id


def idp_callback(client: TestClient, flow_id: str, **params: str) -> Any:
    return client.get(
        "/dial/callback/idp",
        params={"state": flow_id, "code": "the-idp-code", **params},
    )


def upstream_callback(client: TestClient, flow_id: str, **params: str) -> Any:
    return client.get(
        "/dial/callback/upstream",
        params={"state": flow_id, "code": UPSTREAM_CODE, **params},
    )


@contextmanager
def a_gateway(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    *,
    approved: bool = True,
    **overrides: object,
) -> Any:
    """A running gateway whose outbound calls are intercepted by the routes installed here.

    The routes are entered before the app so the flow's first outbound call is already
    intercepted — an app built first would have made its own Core read by the time a test
    added a route for it.

    `approved` defaults to True: the retained scenarios describe a client the user has
    already approved, so the checkpoint passes them through and the flow runs its
    pre-checkpoint shape. A test that exercises the first-attribution path passes
    `approved=False`, and the decision page renders where the flow would otherwise mint.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"), **overrides
    )
    with respx.mock(assert_all_called=False) as router:
        router.get(REALM_CERTS_URL).mock(
            return_value=httpx.Response(200, json=idp.jwks)
        )
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
            return_value=httpx.Response(200, json=toolset_projection())
        )
        router.post(CORE_SIGNIN_URL).mock(return_value=httpx.Response(200, json=True))
        with make_client(settings, private_key_pem) as client:
            if approved:
                _pre_approve(client)
            yield client, router


def _pre_approve(
    client: TestClient, *, resource_client: str = PRE_REGISTERED_CLIENT_ID
) -> None:
    """Record the attribution so the flow meets an approved client, the retained shape.

    The retained scenarios carry the approved-client condition: the checkpoint passes an
    approved (subject, client) through with no page, so a test of that shape seeds the
    registry the way a previous flow's approve action would have.
    """
    runtime_of(client).approved_clients.approve(SUBJECT, resource_client)


# ----------------------------- the resource path is the addressing vocabulary (task 3.5)


# A stored toolset's resource path and its resource URI, as an authorization request would
# name it.
STORED_TOOLSET_PATH = "toolsets/public/notion"
STORED_TOOLSET_RESOURCE = f"{ORIGIN}/dial/{STORED_TOOLSET_PATH}/mcp"


def test_a_stored_toolsets_path_is_accepted_as_a_resource(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A stored toolset's full resource path is a served resource, guard-passing and admitted.

    The flow record carries the resource's canonical identity and the flow's later stages
    address the listing read by the same path — the read URL is the canonical path appended
    to Core's fixed route prefix.
    """
    with a_gateway(private_key_pem, tmp_path, idp, toolsets="") as (client, router):
        listing = router.get(f"http://core:8080/openai/toolsets/{STORED_TOOLSET_PATH}")
        listing.mock(return_value=httpx.Response(200, json=toolset_projection()))
        response = client.get(
            "/dial/authorize",
            params=authorize_params(resource=STORED_TOOLSET_RESOURCE),
        )

    assert response.status_code == HTTPStatus.FOUND
    # The flow record carries the canonical path and resource URI.
    record = next(iter(runtime_of(client).flows._flows.values()))
    assert record.toolset == STORED_TOOLSET_PATH
    assert record.resource == STORED_TOOLSET_RESOURCE


def test_a_non_canonical_spelling_is_accepted_and_canonicalized(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A non-canonical spelling of a guard-passing path is accepted and canonicalized.

    `%78` is `x`, an equivalent spelling; the flow record, the token audience, and the
    restriction's verdict all carry the canonical form — the same identity the plain
    spelling produces.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(200, json=toolset_projection())
        )
        response = client.get(
            "/dial/authorize",
            params=authorize_params(resource=f"{ORIGIN}/dial/%6Eotion/mcp"),
        )

    assert response.status_code == HTTPStatus.FOUND
    record = next(iter(runtime_of(client).flows._flows.values()))
    assert record.toolset == TOOLSET_NAME
    assert record.resource == RESOURCE


def test_a_guard_refused_resource_is_invalid_target_with_its_audit_record(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A path the guard refuses is `invalid_target`, with the offered resource on the trail."""
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))
    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=authorize_params(resource=f"{ORIGIN}/dial/a%7Bb/mcp"),
        )

    assert response.status_code == HTTPStatus.FOUND
    redirected = parse_qs(urlparse(response.headers["location"]).query)
    assert redirected["error"] == ["invalid_target"]
    refusals = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in refusals if r["event"] == "flow_refused"]
    assert "invalid_resource_path" in reasons


def test_a_reserved_first_segment_is_invalid_target_at_authorize(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A reserved first segment names no served toolset at the authorization endpoint."""
    settings = surface_settings(
        toolsets="", dcr_store_path=str(tmp_path / "store.json")
    )
    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=authorize_params(resource=f"{ORIGIN}/dial/token/mcp"),
        )

    assert response.status_code == HTTPStatus.FOUND
    redirected = parse_qs(urlparse(response.headers["location"]).query)
    assert redirected["error"] == ["invalid_target"]


# -------------------------------------------- the Core read URLs (task 4.1) and body (4.2)


def test_the_listing_read_url_is_the_fixed_prefix_plus_the_canonical_path() -> None:
    """The read URL is built only as fixed-prefix + canonical-encoding — no raw substring.

    This is T-EP5-a's mitigation: a caller value can never steer the read off
    `/openai/toolsets/…` into another Core route, because the path is canonicalized first.
    """
    client = CoreClient(make_settings(dial_core_base_url="http://core:8080"))

    assert (
        client.listing_url("toolsets/public/x")
        == "http://core:8080/openai/toolsets/toolsets/public/x"
    )
    assert (
        client.application_url("applications/public/x")
        == "http://core:8080/openai/applications/applications/public/x"
    )
    # An encoded name is carried as its canonical encoding, never a raw decode.
    settings = make_settings()
    canonical = settings.canonical_path("toolsets/public/a%20b")
    assert (
        client.listing_url(canonical)
        == "http://core:8080/openai/toolsets/toolsets/public/a%20b"
    )


def test_a_path_with_percent_bearing_segments_is_re_encoded_for_the_read() -> None:
    """A path carrying `%`-bearing segments canonicalizes before the read URL is built.

    `100%25` decodes to `100%`, which the canonical encoder re-renders as `100%25` — one
    spelling, so the read can never be steered by a raw `%`.
    """
    settings = make_settings()
    canonical = settings.canonical_path("toolsets/public/100%25")

    assert canonical == "toolsets/public/100%25"


def test_the_decoded_path_is_used_for_the_credential_body_and_the_canonical_for_identity() -> (
    None
):
    """The named sites use the named forms: decoded for the body, canonical for identity.

    The credential store keys on the decoded path (Core's own `id` form); the flow record's
    resource field carries the canonical path. Both come from one resolution.
    """
    settings = make_settings()
    canonical = settings.canonical_path("toolsets/public/a%20b") or ""

    assert canonical == "toolsets/public/a%20b"
    assert settings.decoded_path(canonical) == "toolsets/public/a b"


def test_a_path_with_every_legal_punctuation_survives_a_json_round_trip() -> None:
    """The credential body's `url` member is a decoded string a JSON encode cannot break.

    The guard refuses `{`, `}`, `"` on the decoded path, but the body is JSON-encoded by the
    existing client regardless, so even a punctuation-rich path survives structurally intact.
    """
    settings = make_settings()
    path = "toolsets/public/a-b_c.d~e%20f"  # legal punctuation, encoded space
    canonical = settings.canonical_path(path) or ""
    decoded = settings.decoded_path(canonical)

    body = {"url": decoded, "credentialsLevel": "USER"}
    round_tripped = json.loads(json.dumps(body))

    assert round_tripped == body
    assert round_tripped["url"] == "toolsets/public/a-b_c.d~e f"


# ------------------------------------------------------ task 4.1: the provider leg


def test_the_redirect_carries_the_gateways_own_pkce_challenge(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The verifier is generated here and stays on the flow's record.

    Only its challenge travels, which is what makes the code the provider returns
    redeemable by this process alone.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        location = client.get("/dial/authorize", params=authorize_params()).headers[
            "location"
        ]
        record = runtime_of(client).flows.get(flow_id)

    assert record is not None
    assert record.idp_code_verifier
    assert record.idp_state == flow_id
    assert "profile+email" in location or "profile%20email" in location
    # The verifier never appears in the redirect, only the challenge derived from it.
    assert record.idp_code_verifier not in location


def test_the_redirect_requests_only_the_clients_default_scopes(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A relayed client scope can fail the whole leg, so none is relayed.

    The redirect asks for exactly the gateway client's defaults whatever the request's
    `scope` said — including `openid`, which is not a client scope in this realm at all and
    would fail the leg wholesale.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        response = client.get(
            "/dial/authorize",
            params=authorize_params(scope="openid profile email offline_access"),
        )
        params = parse_qs(urlparse(response.headers["location"]).query)

    assert params["scope"] == ["profile email"]


def test_the_exchange_verifies_the_identity_token_against_the_providers_keys(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The identity token is verified, not merely decoded.

    The payload becomes the claim set every minted token is copied from, so trusting it
    because it arrived over TLS would put the whole copy behind transport alone. A token
    the published key cannot verify establishes nothing.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        flow_id = start_flow(client)
        # The provider answers with a token signed by a key it does not publish.
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": Idp().token(pem=generate_key_pem()),
                    "token_type": "Bearer",
                },
            )
        )
        response = idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "could not be verified" in response.text
    assert record is not None
    assert record.identity_claims is None


def test_a_token_from_another_issuer_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The issuer check fixes the token's origin to this deployment's provider."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        flow_id = start_flow(client)
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(iss="https://evil.example/realms/dial"),
                    "token_type": "Bearer",
                },
            )
        )
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "could not be verified" in response.text


def test_an_expired_identity_token_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """An expired token is not an identity, whatever else it says."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        flow_id = start_flow(client)
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(exp=int(time.time()) - 1),
                    "token_type": "Bearer",
                },
            )
        )
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in response.text


def test_the_provider_refusing_the_exchange_is_reported(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A provider that refuses the code is a failed sign-in, not a gateway fault.

    The distinction is the status: a declined sign-in is a 4xx the user can retry, because
    nothing about the gateway is broken — a 5xx would read as a gateway fault in every
    metric the deployment keeps.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        flow_id = start_flow(client)
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"})
        )
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "refused the code exchange" in response.text


def test_a_provider_that_fails_is_reported_as_a_gateway_facing_fault(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A provider answering with its own failure is a fault the operator should see."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        flow_id = start_flow(client)
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(503, text="upstream down")
        )
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY


def test_no_offline_access_is_requested_at_the_exchange(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """No `offline_access`, so no beyond-session grant is acquired.

    What the gateway carries is the ordinary, session-bound refresh token the exchange issues
    by default — never an offline grant. Asserted on the request the gateway actually sent:
    the client carries no `offline_access` scope, and the exchange asks for the
    authorization-code grant alone.
    """
    sent: list[str] = []

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):

        def capture(request: httpx.Request) -> httpx.Response:
            sent.append(request.content.decode())
            return httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )

        router.post(REALM_TOKEN_URL).mock(side_effect=capture)
        flow_id = start_flow(client)
        idp_callback(client, flow_id)

    assert sent, "the exchange must have run"
    assert "offline_access" not in sent[0]
    assert "refresh_token" not in sent[0]


def test_the_exchange_captures_the_provider_refresh_token(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The session-bound refresh token the exchange issues is captured for the refresh window.

    It is carried server-side — never in the code or any client-visible artifact — and is
    what makes the refresh grant's claims re-read possible. Asserted on the flow record's own
    server-side state, which is where it transits.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert record is not None
    assert record.identity_refresh_token == PROVIDER_REFRESH_TOKEN


def test_an_exchange_with_no_refresh_token_refuses_at_sign_in(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A provider that issues no refresh token fails the flow now, not at the first refresh.

    The deployment prerequisite is named, the failure is loud and per flow, and no tokens
    are issued — failing at sign-in is where the cause is diagnosable.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200, json={"access_token": idp.token(), "token_type": "Bearer"}
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert "no refresh token" in response.text


def test_a_refresh_token_over_the_custody_bound_refuses_at_sign_in(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """An over-bound provider token fails the flow at sign-in, naming the bound.

    The carrier the token must fit inside is a refresh token handed to a harness token store
    the gateway does not control, so a token that cannot fit is a failure whose cause is
    diagnosable only here — never hours later at the first refresh.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": "p" * 5_000,
                    "token_type": "Bearer",
                },
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert "gateway_custody_provider_token_max_bytes" in response.text


def test_the_short_circuit_finish_clears_both_credentials_from_the_record(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The short-circuit's record holds no credential after `_finish`, only the claims.

    The consented path destroys the record at the upstream callback, but the short-circuit's
    record stays in the store until its TTL. `_finish` therefore clears both credentials —
    the identity access token and the provider's session refresh token — because the pending
    hand-off entry, not the record, is what carries the provider token to the code grant.
    A record that kept the provider refresh token would leave the flow's most powerful
    credential in memory for the flow's whole TTL after the flow had no further use for it.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)
        runtime = runtime_of(client)
        record = runtime.flows.get(flow_id)
        # The hand-off entry holds the provider token the record just gave up.
        pending = runtime.pending_custody.entry_count()

    assert response.status_code == HTTPStatus.FOUND
    assert record is not None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    # The claims survive, which is what the code the mint already produced needed.
    assert record.identity_claims is not None
    assert pending == 1


def test_the_identity_token_is_used_for_the_core_reads_and_dropped(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The provider's token is presented to Core, then discarded.

    On the short-circuit path both of its uses are spent inside the identity leg, so the
    record holds no provider credential by the time the flow finishes — and the flow's
    claims, which the code needs, are all that remains.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert response.status_code == HTTPStatus.FOUND
    assert record is not None
    assert record.identity_access_token is None
    assert record.identity_claims is not None
    assert record.identity_claims["sub"] == SUBJECT


# ------------------------------------------- task 4.2: the DIAL authorization check


def test_a_refused_settings_read_fails_before_any_upstream_round_trip(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """DIAL authorization is enforced before the upstream is contacted at all.

    The page says the user has no access and names what they can do about it; nothing
    upstream learns the flow existed, which is the whole point of checking here.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(403, json={}))
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert "do not have access to this toolset" in response.text
    # No upstream URL was ever built, let alone followed, and Core was asked about nothing
    # else: the listing read is the check, and it is the first thing the leg does.
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text
    assert not any(route.called for route in router.routes if route.method == "POST")


# ------------------------- the availability oracle (the live-run finding's regression)

NON_ADMIN_ROLES = ["partner-reader"]


def _non_admin_token_url_mock(router: Any, idp: Idp) -> None:
    """Put a non-admin identity in the exchange's token response."""
    router.post(REALM_TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": idp.token(roles=list(NON_ADMIN_ROLES)),
                "refresh_token": PROVIDER_REFRESH_TOKEN,
                "token_type": "Bearer",
            },
        )
    )


def test_a_non_admin_user_is_admitted_to_a_public_toolset(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The regression the live B2C run demands: no admin role, public toolset, pass.

    A user whose token carries no admin role runs the sign-in for a toolset with no
    user-roles restriction — the listing read answers 200 because Core's deployment
    resolution admits the caller, and the flow proceeds exactly as any authorized
    caller's. The gateway never asks an admin role of a user the data path would serve:
    the flow's availability decision is the listing read's, which is the data path's
    own, not the admin-only route the flow read before (the false denial the live run
    exposed).
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        _non_admin_token_url_mock(router, idp)
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    # The flow proceeds to the consent leg — not the no-access page.
    assert response.status_code == HTTPStatus.OK
    assert "do not have access" not in response.text
    assert UPSTREAM_AUTHORIZE_ENDPOINT in response.text


def test_a_non_admin_user_is_refused_where_the_data_path_refuses_them(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The listing read's 403 still refuses — a role-restricted toolset that excludes them.

    The alignment has a refusal half: when Core's deployment resolution denies the
    caller, the listing read answers 403 and the flow serves the no-access page with no
    upstream round-trip — the data path's own decision, enforced before any upstream leg.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        _non_admin_token_url_mock(router, idp)
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(403, json={}))
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert "do not have access to this toolset" in response.text
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text


def test_the_admin_axis_agrees_with_the_data_path_both_ways(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """An admin caller passes where the data path admits them, refuses where it refuses.

    Both axes of the alignment, on an admin token: the listing read's 200 admits the
    flow, and its 403 — a role-restricted toolset whose user_roles exclude this caller —
    refuses it. The prior read's admin axis disagreed with the data path in both
    directions; the listing read's answer is the data path's decision either way.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        # Admitted: the listing read answers 200 for a toolset the admin's roles admit.
        first = idp_callback(client, start_flow(client))
        assert first.status_code == HTTPStatus.OK
        assert UPSTREAM_AUTHORIZE_ENDPOINT in first.text

        # Refused: the data path's own 403 for a toolset that excludes this caller.
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(403, json={}))
        second = idp_callback(client, start_flow(client))
        assert second.status_code == HTTPStatus.FORBIDDEN
        assert "do not have access to this toolset" in second.text


def test_a_fault_listing_answer_is_a_fault_never_an_existence_answer(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A listing answer of 500 lands on the operator-facing fault page.

    An unreachable or unreadable answer is a deployment fault, never an existence
    answer: the page is not the not-registered page, and the toolset's name is never
    learned to be unserved from a failure.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(500, json={}))
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert "not registered in DIAL Core" not in response.text


def test_a_signed_in_user_short_circuits_to_code_issuance(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A stored credential means there is nothing to approve upstream.

    The flow skips the consent and issues its code directly, which is what makes a repeat
    sign-in one silent login rather than a second approval.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FOUND
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)


def test_the_settings_read_carries_the_users_identity_token(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The read is made as the user, which is what makes the 403 an authorization answer."""
    seen: list[str] = []

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):

        def capture(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("authorization", ""))
            return httpx.Response(200, json=toolset_projection())

        router.get(CORE_LISTING_URL).mock(side_effect=capture)
        flow_id = start_flow(client)
        idp_callback(client, flow_id)

    assert seen
    assert seen[0].lower().startswith("bearer ")


def test_the_stored_redirect_uri_is_an_input_to_no_leg(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """No code path reads `redirect_uri` off the projection (the F1 fix's regression row).

    The projection carries the Chat-editor shape (a different stored callback), and the flow
    is asserted to complete with the gateway's derived callback on both the upstream leg and
    the credential call. The projection's `redirect_uri` member is tolerated (not read), so
    the parse stays compatible with any Core projection shape.
    """
    # The projection's `redirect_uri` is tolerated by the parse but not carried on the
    # settings object: there is no member to read it from.
    assert "redirect_uri" not in ToolsetSettings.__dataclass_fields__

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        # The projection carries a different stored callback than any leg should use.
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(redirect_uri=UPSTREAM_REDIRECT_URI)
            )
        )
        flow_id = start_flow(client)
        page = idp_callback(client, flow_id).text
        upstream_url = _navigation_target_of(page)

    params = parse_qs(urlparse(upstream_url).query)
    assert params["redirect_uri"] == [UPSTREAM_CALLBACK_URI]


def test_the_settings_projection_is_read_for_the_challenge_and_no_verifier(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The fields the upstream leg is built from, and the one that must be absent.

    Core holds the verifier and never projects it, which is why only Core can redeem the
    upstream code — so a flow that read a verifier here would be reading something that
    cannot legitimately exist.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.OK
    assert UPSTREAM_CHALLENGE in response.text
    assert "code_verifier" not in response.text
    assert "client_secret" not in response.text


def test_the_dial_authorization_check_runs_for_every_flow(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The check is not skippable by a second sign-in: every flow reads the toolset."""
    calls: list[str] = []

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):

        def capture(_request: httpx.Request) -> httpx.Response:
            calls.append("listing")
            return httpx.Response(200, json=toolset_projection())

        router.get(CORE_LISTING_URL).mock(side_effect=capture)
        for _ in range(2):
            idp_callback(client, start_flow(client))

    assert calls == ["listing", "listing"]


# ----------------------------------------------- task 4.3: the upstream consent leg


def test_the_interstitial_is_an_attribution_page_with_the_client_name(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The user sees which client and which toolset before approving anything.

    The upstream consent names Core's client, so without this page the harness is invisible
    at exactly the moment the user is asked to grant access.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.OK
    assert "text/html" in response.headers["content-type"]
    assert TOOLSET_NAME in response.text
    assert "A pre-registered harness" in response.text
    assert UPSTREAM_AUTHORIZE_ENDPOINT in response.text


def test_the_interstitial_escapes_a_client_name_it_renders(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The name is rendered as text, so a registered name cannot become markup.

    A name comes from a registration — operator config or, for a dynamically registered
    client, the registrant — so this is the boundary between a stored string and HTML.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        pre_registered_clients={
            PRE_REGISTERED_CLIENT_ID: {
                "redirect_uris": [LOOPBACK_REDIRECT_URI],
                "client_name": "<script>alert(1)</script>",
            }
        },
    ) as (client, _router):
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert "<script>" not in response.text
    assert "&lt;script&gt;" in response.text


def test_the_upstream_url_is_built_from_cores_public_settings(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Every parameter of the upstream leg is Core's or the toolset's, none the client's.

    The assertion is made on the URL the page's continuation *produces*, derived the way a
    browser derives it — never on a URL drawn out of the page's text. That distinction is
    the whole point of this test: an assertion on rendered attribute text stayed green
    while the browser dropped every parameter in transit, because the question is not what
    the page says but where the browser ends up.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)
        upstream_url = _navigation_target_of(response.text)

    params = parse_qs(urlparse(upstream_url).query)
    assert params["response_type"] == ["code"]
    assert params["client_id"] == [UPSTREAM_CLIENT_ID]
    assert params["code_challenge"] == [UPSTREAM_CHALLENGE]
    assert params["code_challenge_method"] == ["S256"]
    # The callback is the gateway's derived one, NOT the stored field Core's projection
    # carries — the stored field is another component's value and steers nothing.
    assert params["redirect_uri"] == [UPSTREAM_CALLBACK_URI]
    assert params["redirect_uri"] != [UPSTREAM_REDIRECT_URI]
    assert params["scope"] == [" ".join(UPSTREAM_SCOPES)]
    assert params["state"] == [flow_id]
    # The upstream leg carries the toolset's advertised scopes and Core's challenge. The
    # harness's own scope parameter reached neither.
    assert "openid" not in upstream_url
    assert HARNESS_VERIFIER not in upstream_url


def test_the_interstitial_delivers_its_request_by_navigating_not_by_submitting(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The mechanism itself, asserted: no form, and the navigation target is complete.

    A `method="get"` form submission replaces its action URL's query with the form's own
    entry list, so a parameter-bearing action with no successful controls delivers nothing
    — the shape whose failure is invisible in the page and visible only at the upstream.
    The page therefore carries no form at all, and the navigation it performs is the URL
    built by the gateway, parameter for parameter.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        page = idp_callback(client, flow_id).text

    assert "<form" not in page
    # The page still says what it is for, and continues itself rather than waiting on a
    # manual button: an attribution notice the user has to act on is a second consent.
    assert "Connecting notion to DIAL" in page
    assert "A pre-registered harness" in page
    assert "<button" not in page
    # The two delivery routes a browser may take agree, so neither is a second version of
    # the request that could drift from the other.
    assert _refresh_target_of(page) == _anchor_target_of(page)


def test_the_interstitial_carries_the_web_hardening_headers(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The served interstitial carries the whole family, not the parts that are obvious.

    This page is the one the referrer rule exists for: it is served at the identity
    provider's callback, so the URL behind it still carries the provider's code and the
    flow id, and its own behavior is to navigate onward — a default `Referer` would hand
    both to the upstream's page and its third-party scripts. The framing guard is the
    other page-specific one: framed, an auto-continuing page would advance the flow inside
    a victim's browser.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert_hardening_headers(response)
    # The policy's second half is that the page needs no script at all: the continuation is
    # a meta refresh plus an anchor, so nothing here should ever have to be authorized.
    assert "<script" not in response.text


def _navigation_target_of(page: str) -> str:
    """The URL the page sends the browser to, derived the way a browser does.

    A browser does not read an attribute as text: it parses the document, entity-decodes
    the attribute value, and acts on what remains — which is why `&amp;` in the source is
    `&` in the URL it navigates to. The meta refresh and the anchor are both read, and
    their agreement is asserted by the caller, so a page whose two delivery routes had
    drifted apart could not pass by matching one of them.
    """
    return _refresh_target_of(page)


def _refresh_target_of(page: str) -> str:
    """The meta refresh's target, as the browser parses it out of the content attribute."""
    match = re.search(
        r'<meta[^>]*http-equiv="refresh"[^>]*content="([^"]*)"', page, re.IGNORECASE
    )
    assert match is not None, "the interstitial carries no auto-continuation"
    content = html.unescape(match.group(1))
    delay, _, target = content.partition(";")
    assert delay.strip().isdigit(), f"the refresh has no delay: {content!r}"
    return target.strip().removeprefix("url=").strip()


def _anchor_target_of(page: str) -> str:
    """The fallback anchor's href, as the browser parses it out of the attribute."""
    match = re.search(r'<a href="([^"]*)"', page)
    assert match is not None, "the interstitial carries no fallback navigation"
    return html.unescape(match.group(1))


def test_a_toolset_without_advertised_scopes_is_delivered_without_a_scope_parameter(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """`scope` is required only where the toolset advertises scopes.

    The parameter belongs to the upstream's own registration, so a toolset that advertises
    none is served correctly without it — demanding it there would refuse a request the
    upstream would have accepted, turning a working configuration into a broken one.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(scopes_supported=[])
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)
        upstream_url = _navigation_target_of(response.text)

    assert response.status_code == HTTPStatus.OK
    params = parse_qs(urlparse(upstream_url).query)
    assert "scope" not in params
    # The rest of the request is still complete: the parameter that is genuinely absent
    # from the toolset's registration is the only one omitted.
    assert params["state"] == [flow_id]
    assert params["client_id"] == [UPSTREAM_CLIENT_ID]


def test_an_incomplete_upstream_request_fails_closed_before_the_page_is_served(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A request that cannot be delivered completely is refused, never sent half-built.

    The shape exercised here is a projection Core accepts and this gateway cannot build a
    complete request from: a present-but-empty `code_challenge_method` passes the settings
    read (the field is there) and leaves the URL without the parameter the upstream needs.
    Delivering that would put the user in front of a consent screen that could never
    return; the guard catches it at the last point where the request is still the
    gateway's own.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(code_challenge_method="")
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert "text/html" in response.headers["content-type"]
    assert "code_challenge_method" in response.text
    # No delivery: the page the browser receives is the gateway's error page, and the
    # upstream endpoint is nowhere in it — no parameter-less request can be navigated to.
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text
    assert "http-equiv" not in response.text


def test_a_present_but_empty_parameter_counts_as_undeliverable() -> None:
    """The guard reads the built URL, so a value lost on the way into it is caught.

    A parameter present in the mapping and empty in the URL is the reading the upstream
    applies: it rejects an empty `client_id` exactly as it rejects a missing one. Asserted
    against the guard directly, because the route's listing read refuses the empty values
    it lists and this boundary is the one that answers for the rest.
    """
    url = "https://upstream.example/authorize?response_type=code&client_id=&state=x"
    # The five other required parameters are present, so the one reported is the empty one
    # and not an artifact of a URL this test left short.
    full = (
        "https://upstream.example/authorize?response_type=code&client_id={cid}"
        "&redirect_uri=https%3A%2F%2Fgw.example%2Fcallback"
        "&code_challenge=ch&code_challenge_method=S256&state=x"
    )
    assert _undeliverable_parameters(full.format(cid=""), scopes_advertised=False) == (
        "client_id",
    )
    assert (
        _undeliverable_parameters(full.format(cid="c"), scopes_advertised=False) == ()
    )
    # An entirely absent parameter is reported too, and the same reading applies to a
    # parameter the encoder dropped rather than one that arrived empty.
    assert _undeliverable_parameters(url, scopes_advertised=False) == (
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
    )

    complete = (
        "https://upstream.example/authorize?response_type=code&client_id=c"
        "&redirect_uri=https%3A%2F%2Fgw.example%2Fcallback"
        "&code_challenge=ch&code_challenge_method=S256&state=x&scope=default"
    )
    assert _undeliverable_parameters(complete, scopes_advertised=True) == ()
    # The same URL satisfies the guard without a scope where none is advertised.
    without_scope = complete.rsplit("&", 1)[0]
    assert _undeliverable_parameters(without_scope, scopes_advertised=False) == ()
    # ... and is reported as incomplete where a scope *is* advertised.
    assert _undeliverable_parameters(without_scope, scopes_advertised=True) == (
        "scope",
    )


def test_the_upstream_state_round_trips_the_flow_id(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The callback resolves by the state alone, so a wrong one must not resolve."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        response = upstream_callback(client, flow_id)
        consumed = runtime_of(client).flows.get(flow_id)

    assert response.status_code == HTTPStatus.FOUND
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    # The state round-tripped, and the record it resolved is consumed by this callback.
    assert consumed is None


def test_the_signin_body_is_the_documented_one(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The credential call's exact body, at USER level.

    `USER` is what makes Core stamp the stored credential with the calling token's `sub`;
    GLOBAL is an operator action this flow has no path to. The URL and the callback URI are
    the toolset's own, and the code is the one the upstream returned.
    """
    bodies: list[dict[str, Any]] = []
    authorizations: list[str] = []

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):

        def capture(request: httpx.Request) -> httpx.Response:
            bodies.append(dict(json.loads(request.content)))
            authorizations.append(request.headers.get("authorization", ""))
            return httpx.Response(200, json=True)

        router.post(CORE_SIGNIN_URL).mock(side_effect=capture)
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        upstream_callback(client, flow_id)

    assert bodies == [
        {
            "url": TOOLSET_NAME,
            "credentialsLevel": "USER",
            "authenticationType": "OAUTH",
            "code": UPSTREAM_CODE,
            "redirectUri": UPSTREAM_CALLBACK_URI,
        }
    ]
    assert authorizations[0].lower().startswith("bearer ")


def test_a_stored_redirect_uri_never_steers_the_credential_call(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The stored `redirect_uri` is an input to no leg — the F1 fix's regression row.

    The toolset's projection carries the Chat-editor shape (another component's callback, as
    a UX save writes it). The credential call's `redirectUri` is the gateway's own derived
    callback, never the stored value, so no editor of the toolset can steer where the
    consent's code returns.
    """
    bodies: list[dict[str, Any]] = []

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):

        def capture(request: httpx.Request) -> httpx.Response:
            bodies.append(dict(json.loads(request.content)))
            return httpx.Response(200, json=True)

        router.post(CORE_SIGNIN_URL).mock(side_effect=capture)
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        upstream_callback(client, flow_id)

    assert bodies[0]["redirectUri"] == UPSTREAM_CALLBACK_URI
    assert UPSTREAM_REDIRECT_URI not in bodies[0]["redirectUri"]


def test_a_replayed_upstream_callback_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Destroy-on-first-use: the second callback finds no flow.

    This is the leg where a credential is transferred, so a callback that could be
    processed twice is a callback that could transfer twice.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        first = upstream_callback(client, flow_id)
        second = upstream_callback(client, flow_id)

    assert first.status_code == HTTPStatus.FOUND
    assert second.status_code == HTTPStatus.BAD_REQUEST
    assert "sign-in session expired" in second.text


def test_an_unknown_flow_id_at_the_upstream_callback_injects_nothing(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The code-injection chain's first step, refused.

    An attacker arriving with their own upstream code and a guessed flow id finds no flow,
    so no victim's identity is ever paired with an attacker's code.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        response = upstream_callback(client, "a-guessed-flow-id")

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "sign-in session expired" in response.text
    assert not any(route.called for route in router.routes if route.method == "POST")


def test_a_callback_without_a_state_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        response = client.get("/dial/callback/upstream", params={"code": UPSTREAM_CODE})

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_a_leg_that_reported_an_error_is_refused_before_anything_else(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A provider or upstream that reports a failure is not an authorization code."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        response = client.get(
            "/dial/callback/idp",
            params={"state": flow_id, "error": "access_denied"},
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "not completed" in response.text


def test_the_harness_code_round_trips_state_and_issuer(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """RFC 9207's `iss` and the client's own `state`, on the success path."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        response = upstream_callback(client, flow_id)

    params = parse_qs(urlparse(response.headers["location"]).query)
    assert params["state"] == [HARNESS_STATE]
    assert params["iss"] == [ORIGIN]
    assert params["code"][0]


def test_a_flow_started_without_state_completes_with_none_echoed(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Absent `state` is tolerated end to end: the flow completes with nothing echoed.

    The authorization request carried no `state`, so the final redirect carries no `state`
    parameter — only the code and the `iss`. Nothing is echoed for a state that was never
    offered, which is the delta's absent-state scenario walked through the whole flow.
    """
    params = authorize_params()
    del params["state"]
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        response = client.get("/dial/authorize", params=params)
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        idp_callback(client, flow_id)
        final = upstream_callback(client, flow_id)

    echoed = parse_qs(urlparse(final.headers["location"]).query)
    assert "state" not in echoed
    assert echoed["code"][0]
    assert echoed["iss"] == [ORIGIN]


def test_the_flow_holds_no_credential_after_it_completes(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The record is consumed and the provider token dropped: a finished flow holds nothing."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        upstream_callback(client, flow_id)
        runtime = runtime_of(client)

    assert runtime.flows.get(flow_id) is None


# ------------------------------------------------------------------ audit hygiene


def test_no_credential_material_reaches_the_audit_trail(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The flow's whole story, with no token, code, or key in it.

    The instrument is the run itself: the identity token the flow held, the upstream code
    it transferred, and the harness code it issued all exist as values a careless log line
    could carry, so their absence from the captured records is a real measurement.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        response = upstream_callback(client, flow_id)
        harness_code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        identity = idp.token()

    rendered = caplog.text
    for secret in (harness_code, UPSTREAM_CODE, identity, idp.pem):
        assert secret not in rendered, (
            "the audit trail must not carry credential material"
        )
    # The events are there, carrying identifiers, so the assertions above measured a
    # populated log rather than an empty one.
    assert flow_id in rendered
    assert SUBJECT in rendered
    assert "upstream_callback" in rendered
    assert "code_issued" in rendered


def test_the_flow_respects_the_rate_limit_before_allocating(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The entry is bounded before any flow is created, as on the whole surface."""
    with a_gateway(
        private_key_pem, tmp_path, idp, gateway_rate_per_source_per_minute=1
    ) as (client, _router):
        first = client.get("/dial/authorize", params=authorize_params())
        second = client.get("/dial/authorize", params=authorize_params())

    assert first.status_code == HTTPStatus.FOUND
    assert second.status_code == HTTPStatus.TOO_MANY_REQUESTS


def test_the_flows_toolset_read_is_one_request(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The decision step is one Core request, on the listing route, every time.

    The listing read carries availability, the settings projection, and the per-caller
    statuses in one answer, so there is no second route to ask — the route asked twice
    could only repeat its answer. One Core GET, and the status it carried was the one
    acted on: the user was already signed in, so the flow short-circuited rather than
    building an upstream URL.
    """
    calls: list[str] = []

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):

        def listing_answer(_request: httpx.Request) -> httpx.Response:
            calls.append("listing")
            return httpx.Response(
                200,
                json=toolset_projection(
                    user_level_auth_status="SIGNED_IN",
                    global_auth_status="SIGNED_OUT",
                ),
            )

        router.get(CORE_LISTING_URL).mock(side_effect=listing_answer)
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FOUND
    assert calls == ["listing"]
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)


def test_the_interstitial_is_shown_only_after_the_authorization_check(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A refused user never reaches a consent screen's preparation.

    The ordering is the property: the listing read is the check, and it happens before the
    upstream URL — the thing the interstitial continues to — is built at all.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(403, json={}))
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text


def test_a_short_lived_identity_token_bounds_the_flow_below_its_own_ttl(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The flow's hold on the identity token is min(flow TTL, the token's own life).

    The flow TTL bounds *retention*, not the token's life — so a flow whose identity token
    expires sooner records the sooner bound, and a flow still holding a credential the
    provider has already killed is exactly what the shorter bound prevents.

    Asserted on the recorded bounds rather than by waiting: the two are compared as
    durations, so the assertion is about which one won, not about how long a sleep took.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(exp=int(time.time()) + 5),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )
        )
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert record is not None
    assert record.identity_expires_at is not None
    # Five seconds of token life against a ten-minute flow: the token wins, so the record
    # does not hold it past the provider's own expiry.
    assert record.identity_expires_at < record.expires_at


def test_an_expired_identity_bound_releases_the_flow_record(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Once the bound passes, the record is gone rather than serving a dead credential.

    The release is the same outcome an expired flow TTL produces, from the flow's own
    side: the browser's next callback finds no flow and gets the plain-language page.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(exp=int(time.time()) + 5),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )
        )
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        runtime = runtime_of(client)
        record = runtime.flows.get(flow_id)
        assert record is not None

        # The bound advanced past, as a wait would do — without the wait, so the assertion
        # does not depend on how the suite's load affects a sleep.
        record.identity_expires_at = time.monotonic() - 1

        assert runtime.flows.get(flow_id) is None


def test_the_identity_token_never_crosses_into_what_the_harness_holds(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The provider's credential does not travel, in any form, into the harness's tokens.

    The code and the tokens the flow issues are signed by the gateway's own key and carry
    the claim snapshot — never the identity token itself, its `jti`, or its signature. A
    harness that held the identity provider's token would hold the user's realm-wide
    credential, which is the invariant the whole alternative-C design exists to avoid.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        response = upstream_callback(client, flow_id)
        code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
        redeemed = client.post(
            "/dial/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "client_id": PRE_REGISTERED_CLIENT_ID,
                "code_verifier": HARNESS_VERIFIER,
                "resource": RESOURCE,
            },
        )

    assert redeemed.status_code == HTTPStatus.OK
    issued = redeemed.json()
    identity = idp.token()
    # Read without verification: the token is this test's own output, and what it is being
    # read for is its identifier, not its provenance.
    identity_identifier = jwt.decode(identity, options={"verify_signature": False})[
        "jti"
    ]

    # The identity token's own signature is not part of any of them, and neither is its
    # identifier: the tokens are new tokens, not wrapped ones.
    identity_signature = identity.rsplit(".", 1)[1]
    for name in ("access_token", "refresh_token"):
        assert identity_signature not in issued[name]
        assert identity_identifier not in issued[name]
    assert identity_identifier not in code


# ------------------------------------- the re-taken flow's stages (the routing decision)


def test_a_user_level_credential_short_circuits_with_no_upstream_leg(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A stored user-level credential means there is nothing to approve upstream.

    The flow completes with no upstream round-trip and no consent screen, and the tokens
    it issues are the same shape a consented flow issues — asserted here on the code the
    flow returns.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json=toolset_projection(
                    user_level_auth_status="SIGNED_IN",
                    global_auth_status="SIGNED_OUT",
                ),
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FOUND
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    # No upstream leg, and no credential call: the short-circuit is the whole path.
    assert not any(
        "signin" in str(route.pattern) and route.called for route in router.routes
    )
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text


def test_a_global_credential_short_circuits_a_non_oauth_toolset(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The delegation: a global credential serves every user, for any kind.

    A non-OAuth toolset whose credential an operator stored at GLOBAL level short-circuits
    the consent for a user who holds none: no credential call, no upstream leg, tokens
    issued. The flow uses the stored credential — it never establishes one.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json=toolset_projection(
                    authentication_type="API_KEY",
                    user_level_auth_status="SIGNED_OUT",
                    global_auth_status="SIGNED_IN",
                ),
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FOUND
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    # No credential was ever called: the short-circuit uses a stored credential, and Core
    # injects it on the data path — the flow has no path to establish one.
    assert not any(
        "signin" in str(route.pattern) and route.called for route in router.routes
    )


def test_a_non_oauth_toolset_with_no_credential_is_refused_on_the_impossible_branch(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """No stored credential plus a non-OAuth kind: the impossible-branch refusal.

    The page says the credential is configured directly in DIAL, no upstream round-trip
    happens, and the refusal is recorded with the fixed-vocabulary reason.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json=toolset_projection(
                    authentication_type="API_KEY",
                    user_level_auth_status="SIGNED_OUT",
                    global_auth_status="SIGNED_OUT",
                ),
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "configured directly in DIAL" in response.text
    # No upstream URL was ever built, let alone followed.
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text
    assert "http-equiv" not in response.text
    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in records if r["event"] == "flow_branch_refused"]
    assert reasons == ["non_oauth_toolset"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"user_level_auth_status": None, "global_auth_status": None},
        {"user_level_auth_status": "not-a-status", "global_auth_status": "SIGNED_OUT"},
        {"user_level_auth_status": "FAILED", "global_auth_status": "FAILED"},
    ],
)
def test_an_unreadable_or_failed_status_does_not_short_circuit(
    private_key_pem: str, tmp_path: Path, idp: Idp, overrides: dict[str, Any]
) -> None:
    """Absent, unreadable, or FAILED is not signed in: the flow falls through to the kind.

    For an OAUTH toolset that means the consent leg — the safest path the flow has, and the
    proof the check fails closed rather than minting on an unreadable status.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(200, json=toolset_projection(**overrides))
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    # The interstitial was served, not a redirect to the harness: the flow did not
    # short-circuit.
    assert response.status_code == HTTPStatus.OK
    assert "text/html" in response.headers["content-type"]
    assert UPSTREAM_AUTHORIZE_ENDPOINT in response.text


def test_an_app_level_only_status_does_not_short_circuit(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """An app-level credential is not a sign-in for a user's flow.

    The check reads the user and global members only, so a toolset whose only stored
    credential is APP_LEVEL falls through to the kind branch — here, a non-OAuth kind, so
    the impossible-branch refusal.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json=toolset_projection(
                    authentication_type="API_KEY",
                    user_level_auth_status="SIGNED_OUT",
                    global_auth_status="SIGNED_OUT",
                    app_level_auth_status="SIGNED_IN",
                ),
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "configured directly in DIAL" in response.text


def test_an_unknown_toolset_is_refused_at_the_settings_read(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The system's only existence refusal, with its fixed-vocabulary reason.

    Core answers no toolset for the offered name; the flow fails with a plain-language
    page, no upstream round-trip, and an `unknown_toolset` record.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(404, json={}))
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert "not registered in DIAL Core" in response.text
    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in records if r["event"] == "flow_branch_refused"]
    assert reasons == ["unknown_toolset"]


def test_an_unknown_toolset_refusal_leaves_no_flow_state(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The existence refusal consumes the flow: no record, no credential, no replay.

    The spec's refusal scenario says no flow state survives it. A record that outlived the
    refusal would still hold the identity access token the exchange captured — the read
    discards it only on its success path — and a re-presented flow id would re-run the leg
    rather than land on the expired page an unknown id gets.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        exchanges: list[int] = []

        def exchange(_request: httpx.Request) -> httpx.Response:
            exchanges.append(1)
            return httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )

        router.post(REALM_TOKEN_URL).mock(side_effect=exchange)
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(404, json={}))
        flow_id = start_flow(client)
        record = runtime_of(client).flows.get(flow_id)
        assert record is not None

        refusal = idp_callback(client, flow_id)
        survives = runtime_of(client).flows.get(flow_id)
        replay = idp_callback(client, flow_id)

    assert refusal.status_code == HTTPStatus.NOT_FOUND
    # The record is gone from the store and holds no identity credential.
    assert survives is None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    # Re-presenting the flow id lands on the expired page an unknown id gets, and the leg —
    # the provider code exchange above all — does not run a second time.
    assert replay.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in replay.text
    assert len(exchanges) == 1
    # The refusal's own record still landed, exactly once.
    records = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in records if r["event"] == "flow_branch_refused"]
    assert reasons == ["unknown_toolset"]


def test_a_refused_settings_read_leaves_no_flow_state(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The no-access refusal is a refusal too: the flow's credential does not survive it.

    The identity token's retention is bounded by the flow's own TTL; a refusal must not
    extend it by leaving a re-presentable record holding the token the exchange captured.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        exchanges: list[int] = []

        def exchange(_request: httpx.Request) -> httpx.Response:
            exchanges.append(1)
            return httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )

        router.post(REALM_TOKEN_URL).mock(side_effect=exchange)
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(403, json={}))
        flow_id = start_flow(client)
        record = runtime_of(client).flows.get(flow_id)
        assert record is not None

        refusal = idp_callback(client, flow_id)
        survives = runtime_of(client).flows.get(flow_id)
        replay = idp_callback(client, flow_id)

    assert refusal.status_code == HTTPStatus.FORBIDDEN
    assert survives is None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    assert replay.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in replay.text
    assert len(exchanges) == 1


# ------------------- task 9.2: the 401/403 refusal-class split (the trust fault)

TRUST_FAULT_MESSAGE = str(TrustFaultError())


def test_a_trust_fault_listing_answer_is_not_an_access_denial(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A 401 is the trust fault: an authentication failure with an operator's remedy.

    Core could not validate the sign-in's identity token — its provider entry (issuer,
    key set, audience) or that key set's reachability is the cause, and no access grant
    answers it. The page says so instead of showing the no-access verdict a 403 earns:
    the two codes are two classes with two audiences, never one.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(401, json={}))
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert TRUST_FAULT_MESSAGE in response.text
    assert "do not have access to this toolset" not in response.text
    assert "not registered in DIAL Core" not in response.text
    # The trust fault is a refusal like the 403: the flow ends before any upstream
    # round-trip — the listing read is the first thing the leg does after the exchange.
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text
    assert not any(route.called for route in router.routes if route.method == "POST")


def test_the_trust_fault_page_names_no_user_identifying_value(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The fault page is fixed vocabulary: no token, claim, or caller value on it.

    The read that failed was made with the user's identity token, and the failure is
    about that token's validation — exactly the material the page must never echo.
    """
    token = idp.token()
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.post(REALM_TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": token,
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )
        )
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(401, json={}))
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert TRUST_FAULT_MESSAGE in response.text
    assert token not in response.text
    assert SUBJECT not in response.text
    assert "dial@example.test" not in response.text
    assert "proj-alpha" not in response.text
    assert PROVIDER_REFRESH_TOKEN not in response.text


def test_a_trust_fault_refusal_consumes_the_flow(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The trust fault is a refusal: no record, no credential, no replayed leg.

    A record that outlived the refusal would hold the identity access token and the
    provider's session refresh token — the very material Core could not validate — and
    a re-presented flow id would re-run the leg rather than land on the expired page an
    unknown id gets. The audit record carries the fixed-vocabulary trust-fault reason,
    distinct from the access-denied class's.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        exchanges: list[int] = []

        def exchange(_request: httpx.Request) -> httpx.Response:
            exchanges.append(1)
            return httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )

        router.post(REALM_TOKEN_URL).mock(side_effect=exchange)
        router.get(CORE_LISTING_URL).mock(return_value=httpx.Response(401, json={}))
        flow_id = start_flow(client)
        record = runtime_of(client).flows.get(flow_id)
        assert record is not None

        refusal = idp_callback(client, flow_id)
        survives = runtime_of(client).flows.get(flow_id)
        replay = idp_callback(client, flow_id)

    assert refusal.status_code == HTTPStatus.BAD_GATEWAY
    # The record is gone from the store and holds no identity credential.
    assert survives is None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    # Re-presenting the flow id lands on the expired page an unknown id gets, and the
    # exchange does not run a second time.
    assert replay.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in replay.text
    assert len(exchanges) == 1
    # One audit record, with the class's own fixed text as its reason.
    records = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "gateway.audit"
    ]
    leg_failures = [r for r in records if r["event"] == "flow_leg_failed"]
    assert len(leg_failures) == 1
    assert leg_failures[0]["leg"] == "authorization"
    assert leg_failures[0]["reason"] == TRUST_FAULT_MESSAGE


def test_an_app_read_401_is_the_trust_fault_too(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The app read shares the one answer-to-refusal mapping, so its 401 lands there too.

    An authentication failure from the apps read is the same trust fault — the
    operator-facing page, never the no-access page a 403 from the same read earns.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_APP_URL).mock(return_value=httpx.Response(401, json={}))
        flow_id = start_flow(client, resource=APP_RESOURCE)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert TRUST_FAULT_MESSAGE in response.text
    assert "do not have access to this app" not in response.text
    assert "not registered in DIAL Core" not in response.text


def test_the_impossible_branch_refusal_leaves_no_flow_state(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The impossible-branch refusal consumes the flow and drops its credential material.

    It is a refusal — the flow is over for the user — not a fault to re-run, so it destroys
    the record exactly as the read refusals do. Left in the store, the record would hold the
    identity access token and the provider's session refresh token until the flow's TTL,
    re-presentable by anyone holding the flow id.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        exchanges: list[int] = []

        def exchange(_request: httpx.Request) -> httpx.Response:
            exchanges.append(1)
            return httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )

        router.post(REALM_TOKEN_URL).mock(side_effect=exchange)
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json=toolset_projection(
                    authentication_type="API_KEY",
                    user_level_auth_status="SIGNED_OUT",
                    global_auth_status="SIGNED_OUT",
                ),
            )
        )
        flow_id = start_flow(client)
        record = runtime_of(client).flows.get(flow_id)
        assert record is not None

        refusal = idp_callback(client, flow_id)
        survives = runtime_of(client).flows.get(flow_id)
        replay = idp_callback(client, flow_id)

    assert refusal.status_code == HTTPStatus.BAD_REQUEST
    assert "configured directly in DIAL" in refusal.text
    # The record is gone from the store and holds no credential material.
    assert survives is None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    # Re-presenting the flow id lands on the expired page, and the provider exchange does
    # not run a second time.
    assert replay.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in replay.text
    assert len(exchanges) == 1
    reasons = [
        json.loads(r.getMessage())["reason"]
        for r in caplog.records
        if r.name == "gateway.audit"
        and json.loads(r.getMessage())["event"] == "flow_branch_refused"
    ]
    assert reasons == ["non_oauth_toolset"]


def test_the_upstream_build_fault_does_not_consume_the_flow(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
) -> None:
    """The 502 upstream-build fault is operator-fault class: the record survives to re-run.

    An OAUTH toolset whose public settings are incomplete cannot be served by consent, and
    the flow refuses at the point the URL is built. That is a fault an administrator fixes,
    not a refusal of the user's request, so the record is left for the re-run — the same
    exemption the Core-unreachable fault branch carries.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        # An OAUTH kind whose projection omits every OAuth field the consent leg needs.
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": TOOLSET_NAME,
                    "auth_settings": {
                        "authentication_type": "OAUTH",
                        "user_level_auth_status": "SIGNED_OUT",
                        "global_auth_status": "SIGNED_OUT",
                    },
                },
            )
        )
        flow_id = start_flow(client)

        response = idp_callback(client, flow_id)
        survives = runtime_of(client).flows.get(flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    # The fault did not consume the record: the user re-runs after the operator fixes it.
    assert survives is not None


def test_the_short_circuit_never_builds_an_upstream_url(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The negative control: no upstream authorize URL on the short-circuit path.

    The toolset's projection advertises an upstream endpoint that must never appear in the
    response or in any request the flow makes, proving the short-circuit skips the upstream
    stage entirely.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json=toolset_projection(
                    user_level_auth_status="SIGNED_IN",
                    global_auth_status="SIGNED_OUT",
                ),
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text
    assert "http-equiv" not in response.text
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)


def test_a_non_oauth_projection_with_no_credential_does_not_refuse_the_listing_read(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A projection with no OAuth fields is readable — the completeness refusal moved.

    The listing read does not refuse a projection whose OAuth fields are absent; that
    refusal belongs to the consent branch alone, so a non-OAuth toolset's projection
    reads fine and the flow reaches the kind branch, refusing on the impossible branch
    rather than failing at the read.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": TOOLSET_NAME,
                    "auth_settings": {
                        "authentication_type": "API_KEY",
                        "user_level_auth_status": "SIGNED_OUT",
                        "global_auth_status": "SIGNED_OUT",
                    },
                },
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "configured directly in DIAL" in response.text


@pytest.mark.parametrize(
    "kind_override",
    [
        pytest.param({}, id="absent"),
        pytest.param({"authentication_type": None}, id="null"),
        pytest.param({"authentication_type": ["OAUTH"]}, id="non-string"),
    ],
)
def test_an_absent_or_unusable_authentication_kind_falls_into_the_impossible_branch(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
    kind_override: dict[str, Any],
) -> None:
    """An absent or unusable kind is unestablishable, refused like any non-OAuth one.

    The projection here carries every OAuth field a consent leg would need, so the only
    reason the leg must not be built is the kind itself: a value that is missing, or
    present as something other than a string, reads as no usable kind, and no usable kind
    can be establishable by consent. The flow falls into the same impossible-branch
    refusal a non-OAuth kind earns — not the consent leg the complete fields would
    otherwise invite.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    auth: dict[str, Any] = {
        "client_id": UPSTREAM_CLIENT_ID,
        "authorization_endpoint": UPSTREAM_AUTHORIZE_ENDPOINT,
        "redirect_uri": UPSTREAM_REDIRECT_URI,
        "code_challenge": UPSTREAM_CHALLENGE,
        "code_challenge_method": "S256",
        "user_level_auth_status": "SIGNED_OUT",
        "global_auth_status": "SIGNED_OUT",
    }
    auth.update(kind_override)

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json={"name": TOOLSET_NAME, "auth_settings": auth}
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "configured directly in DIAL" in response.text
    # The complete OAuth fields did not invite the consent leg: no upstream URL was built.
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text
    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in records if r["event"] == "flow_branch_refused"]
    assert reasons == ["non_oauth_toolset"]


def test_an_oauth_projection_with_missing_fields_is_refused_on_the_consent_branch(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """An OAUTH toolset with an incomplete projection is refused where the URL is built.

    The refusal moved to the consent branch — the only branch that builds a URL from these
    fields — so an OAuth toolset missing one of them is refused there, with a message
    naming the missing field, rather than at the listing read.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": TOOLSET_NAME,
                    "auth_settings": {
                        "authentication_type": "OAUTH",
                        "authorization_endpoint": UPSTREAM_AUTHORIZE_ENDPOINT,
                        "redirect_uri": UPSTREAM_REDIRECT_URI,
                        "code_challenge": UPSTREAM_CHALLENGE,
                        "code_challenge_method": "S256",
                        "user_level_auth_status": "SIGNED_OUT",
                        "global_auth_status": "SIGNED_OUT",
                        # `client_id` is absent: the consent branch cannot build the URL.
                    },
                },
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert "client_id" in response.text
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text


# ------------------------------------------------- the app flow (credential-free)


def app_authorize_params(**overrides: str) -> dict[str, str]:
    """A well-formed authorization request naming the app's resource."""
    params = {
        "response_type": "code",
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": code_challenge_for(HARNESS_VERIFIER),
        "code_challenge_method": "S256",
        "resource": APP_RESOURCE,
        "state": HARNESS_STATE,
    }
    params.update(overrides)
    return params


@contextmanager
def an_app_gateway(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    *,
    approved: bool = True,
    **overrides: object,
) -> Any:
    """A running gateway with an app restriction, its Core reads intercepted.

    The app read is intercepted so the flow's app branch runs against a stubbed Core the
    test steers per call — the same shape the toolset flow's listing read takes.

    `approved` defaults to True for the retained app scenarios, which carry the
    approved-client condition (the app kind's zero-page short-circuit is the approved
    client's, and the first-attribution shape is the checkpoint's own test).
    """
    settings = surface_settings(
        apps={APPS_NAME: {}}, dcr_store_path=str(tmp_path / "store.json"), **overrides
    )
    with respx.mock(assert_all_called=False) as router:
        router.get(REALM_CERTS_URL).mock(
            return_value=httpx.Response(200, json=idp.jwks)
        )
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
        router.get(CORE_APP_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "name": APPS_NAME,
                    "mcp": {"endpoint": "http://fixture:9000/mcp"},
                },
            )
        )
        with make_client(settings, private_key_pem) as client:
            if approved:
                _pre_approve(client)
            yield client, router


def test_an_app_sign_in_completes_with_no_consent_and_no_credential_call(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The app flow is the identity leg, the app read, and the mint — nothing else.

    No consent screen, no credential call, no upstream round-trip: the resource is
    credential-free by construction. The flow completes to a code, and the trail shows the
    kind-driven short-circuit and carries no consent-leg or credential-call event.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, router):
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FOUND
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    # No upstream leg, and no credential call: the short-circuit is the whole path.
    assert not any(
        "signin" in str(route.pattern) and route.called for route in router.routes
    )
    assert UPSTREAM_AUTHORIZE_ENDPOINT not in response.text

    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    events = [record["event"] for record in records]
    # The short-circuit record is present, naming the kind, and no consent or credential
    # event exists on the trail for this flow.
    assert "credential_free_short_circuit" in events
    short_circuit = next(
        r for r in records if r["event"] == "credential_free_short_circuit"
    )
    assert short_circuit["resource_kind"] == "app"
    assert "signin_result" not in events
    assert "upstream_callback" not in events


def test_the_app_flow_reads_the_app_as_the_user(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The app read is the DIAL authorization check, made with the live user's token."""
    seen: list[str] = []

    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, router):

        def capture(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("authorization", ""))
            return httpx.Response(200, json={"name": APPS_NAME})

        router.get(CORE_APP_URL).mock(side_effect=capture)
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        idp_callback(client, flow_id)

    assert seen
    assert seen[0].lower().startswith("bearer ")


def test_a_refused_app_read_fails_with_the_no_access_page(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A 403 is the user's own lack of access: the no-access page, and no mint."""
    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_APP_URL).mock(return_value=httpx.Response(403, json={}))
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert "do not have access to this app" in response.text
    assert "location" not in response.headers


def test_an_unknown_app_is_refused_at_the_flow_read(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A 404 is the apps namespace's existence refusal, audited `unknown_app`.

    Core does not know the name; the flow fails with a plain-language page, no round-trip
    beyond the read, and one fixed-vocabulary record naming the app.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_APP_URL).mock(return_value=httpx.Response(404, json={}))
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.NOT_FOUND
    assert "not registered in DIAL Core" in response.text
    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in records if r["event"] == "flow_branch_refused"]
    assert reasons == ["unknown_app"]


def test_an_unknown_app_refusal_leaves_no_flow_state(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The apps existence refusal consumes the flow, exactly as the toolset one does.

    The spec's app-resource refusal scenario says no flow state survives it. A record that
    outlived the refusal would still hold the identity access token the exchange captured,
    and a re-presented flow id would re-run the leg — the survivorship the live acceptance
    run falsified.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, router):
        exchanges: list[int] = []

        def exchange(_request: httpx.Request) -> httpx.Response:
            exchanges.append(1)
            return httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )

        router.post(REALM_TOKEN_URL).mock(side_effect=exchange)
        router.get(CORE_APP_URL).mock(return_value=httpx.Response(404, json={}))
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        record = runtime_of(client).flows.get(flow_id)
        assert record is not None

        refusal = idp_callback(client, flow_id)
        survives = runtime_of(client).flows.get(flow_id)
        replay = idp_callback(client, flow_id)

    assert refusal.status_code == HTTPStatus.NOT_FOUND
    assert survives is None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    assert replay.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in replay.text
    assert len(exchanges) == 1
    records = [
        json.loads(r.getMessage()) for r in caplog.records if r.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in records if r["event"] == "flow_branch_refused"]
    assert reasons == ["unknown_app"]


def test_a_refused_app_read_leaves_no_flow_state(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The app no-access refusal also consumes the flow and its identity credential."""
    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, router):
        exchanges: list[int] = []

        def exchange(_request: httpx.Request) -> httpx.Response:
            exchanges.append(1)
            return httpx.Response(
                200,
                json={
                    "access_token": idp.token(),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )

        router.post(REALM_TOKEN_URL).mock(side_effect=exchange)
        router.get(CORE_APP_URL).mock(return_value=httpx.Response(403, json={}))
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        record = runtime_of(client).flows.get(flow_id)
        assert record is not None

        refusal = idp_callback(client, flow_id)
        survives = runtime_of(client).flows.get(flow_id)
        replay = idp_callback(client, flow_id)

    assert refusal.status_code == HTTPStatus.FORBIDDEN
    assert survives is None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    assert replay.status_code == HTTPStatus.BAD_REQUEST
    assert "expired" in replay.text
    assert len(exchanges) == 1


def test_an_unreachable_app_read_is_a_deployment_fault_never_an_existence_answer(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """An unreadable answer fails closed as a fault, distinct from the not-registered page.

    The offered name is never learned to be unserved from a failure: a 500 from Core is a
    gateway-facing fault page, not the plain-language not-registered page.
    """
    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, router):
        router.get(CORE_APP_URL).mock(return_value=httpx.Response(500, json={}))
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_GATEWAY
    assert "not registered in DIAL Core" not in response.text


def test_the_app_flow_issues_tokens_addressed_to_the_app_resource(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The minted tokens name the app's resource, the same shape a toolset sign-in issues."""
    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        callback = idp_callback(client, flow_id)
        code = parse_qs(urlparse(callback.headers["location"]).query)["code"][0]
        redeemed = client.post(
            "/dial/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": LOOPBACK_REDIRECT_URI,
                "client_id": PRE_REGISTERED_CLIENT_ID,
                "code_verifier": HARNESS_VERIFIER,
                "resource": APP_RESOURCE,
            },
        )

    assert redeemed.status_code == HTTPStatus.OK
    access = jwt.decode(
        redeemed.json()["access_token"],
        options={"verify_signature": False},
    )
    refresh = jwt.decode(
        redeemed.json()["refresh_token"],
        options={"verify_signature": False},
    )
    assert access["aud"] == [APP_RESOURCE, "dial-mcp-proxy"]
    assert refresh["aud"] == [APP_RESOURCE]


def test_an_app_resource_request_allocates_a_flow_of_the_app_kind(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The flow record carries the kind its resource named, derived once at allocation."""
    with an_app_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        record = runtime_of(client).flows.get(flow_id)

    assert record is not None
    assert record.resource_kind == "app"
    assert record.toolset == APPS_NAME
    assert record.resource == APP_RESOURCE


def test_an_out_of_scope_app_resource_name_is_invalid_target(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The app shape passes the app guard: a shape violation is `invalid_target`.

    The wider app charset (`Not_An_App`, uppercase and underscore) is served, so the refusal
    exercised here is a decoded-shape violation (`%7B`) — the app guard's own class.
    """
    settings = surface_settings(apps="", dcr_store_path=str(tmp_path / "store.json"))
    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=app_authorize_params(resource=f"{ORIGIN}/apps/a%7Bb/mcp"),
        )

    assert response.status_code == HTTPStatus.FOUND
    redirected = parse_qs(urlparse(response.headers["location"]).query)
    assert redirected["error"] == ["invalid_target"]


def test_a_stored_app_path_is_accepted_as_a_resource(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A stored app's full resource path is a served resource, guard-passing and admitted.

    Under the resource-path vocabulary the stored-app shape (`applications/{bucket}/{name}`)
    is a path whose slashes are separators, not a charset violation — the pre-change refusal
    of "an app name carrying a slash" is reversed by this change.
    """
    settings = surface_settings(apps="", dcr_store_path=str(tmp_path / "store.json"))
    with make_client(settings, private_key_pem) as client:
        response = client.get(
            "/dial/authorize",
            params=app_authorize_params(
                resource=f"{ORIGIN}/apps/applications/public/MyApp.v2/mcp"
            ),
        )

    assert response.status_code == HTTPStatus.FOUND
    location = response.headers["location"]
    assert location.startswith(REALM_AUTHORIZE_URL)


# ------------------------- the consent/attribution checkpoint (the decision page)

# A hostile client name, for the escaping assertion: a registered name is stored text, and
# the decision page renders it in an HTML context.
HOSTILE_CLIENT_NAME = "<script>alert(1)</script>"


def approve(client: TestClient, flow_id: str) -> Any:
    return client.post("/dial/consent", data={"flow_id": flow_id, "action": "approve"})


def deny(client: TestClient, flow_id: str) -> Any:
    return client.post("/dial/consent", data={"flow_id": flow_id, "action": "deny"})


def audit_events(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The audit event names a run emitted, in order."""
    return [
        json.loads(record.getMessage())["event"]
        for record in caplog.records
        if record.name == "gateway.audit"
    ]


def mint_redirect(response: Any) -> str:
    """The harness URL an approve delivered the mint to, from its navigating page.

    The approve answers with a page (never a redirect): a form submission's redirect is
    governed by the decision page's `form-action 'self'`, so a browser refuses a 302 off the
    gateway's origin and the mint is delivered by the page's meta refresh instead. The
    target is read the way a browser parses the refresh, entity-decoded.
    """
    assert response.status_code == HTTPStatus.OK, response.status_code
    assert "text/html" in response.headers["content-type"]
    assert "location" not in response.headers
    match = re.search(
        r'<meta[^>]*http-equiv="refresh"[^>]*content="[^"]*url=([^"]+)"',
        response.text,
        re.IGNORECASE,
    )
    assert match is not None, "the approve page carried no navigation to the mint"
    return html.unescape(match.group(1))


def test_first_attribution_on_the_short_circuit_renders_the_decision_page(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The stored-credential short-circuit now renders the page where it minted silently.

    The registry is consulted after the identity leg and before the mint; an unapproved
    (subject, client) renders the decision page and no code is issued, and the flow waits
    for the user's act — audited `attribution_required`.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.OK
    assert "text/html" in response.headers["content-type"]
    # No mint: the page waits, and there is no redirect back to the harness.
    assert "location" not in response.headers
    assert "Approve access" in response.text
    assert "attribution_required" in audit_events(caplog)
    # No credential call runs on the short-circuit path, before the page or after.
    assert not any(
        "signin" in str(route.pattern) and route.called for route in router.routes
    )


def test_the_decision_page_names_the_client_resource_and_redirect(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The page names the registrant name beside the id, the resource, and the redirect.

    The name is presented as a name (registrant-supplied) and the id beside it always, the
    resource names its kind and served name, and the registered `redirect_uri` is shown in
    full — the one fact the false-name mis-use cannot forge.
    """
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        page = idp_callback(client, flow_id).text

    assert "A pre-registered harness" in page
    assert PRE_REGISTERED_CLIENT_ID in page
    assert TOOLSET_NAME in page
    assert LOOPBACK_REDIRECT_URI in page
    # No scope list: the surface accepts and drops the client `scope` parameter.
    assert "scope" not in page.lower()


def test_the_decision_page_carries_the_family_and_does_not_auto_continue(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The page inherits the web-hardening family and never navigates itself.

    The family is inherited through the one builder (including the family-wide
    `form-action 'self'`), the markup is script-free, and there is no `meta refresh`: the
    decision must not navigate itself.
    """
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert_hardening_headers(response, label="the decision page")
    assert "form-action 'self'" in response.headers["content-security-policy"]
    assert "<script" not in response.text
    assert "http-equiv" not in response.text
    # The form is the page's one interaction: two buttons, no auto-continue.
    assert "<form" in response.text
    assert "<button" in response.text


def test_the_decision_page_escapes_a_hostile_client_name(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A registered name is stored text, so it is escaped before it reaches the page."""
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        approved=False,
        pre_registered_clients={
            PRE_REGISTERED_CLIENT_ID: {
                "redirect_uris": [LOOPBACK_REDIRECT_URI],
                "client_name": HOSTILE_CLIENT_NAME,
            }
        },
    ) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        page = idp_callback(client, flow_id).text

    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_approve_records_the_attribution_and_mints_on_the_short_circuit(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Approve writes the registry, audits it, and continues to the deferred mint."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        runtime = runtime_of(client)
        approved_before = runtime.approved_clients.entry_count()
        response = approve(client, flow_id)

    # The mint is delivered as a navigating page, not a redirect: a form submission's
    # redirect is governed by the decision page's `form-action 'self'`, so the browser
    # refuses a 302 off the gateway's origin and the approve would appear to do nothing.
    assert mint_redirect(response).startswith(LOOPBACK_REDIRECT_URI)
    # The registry was written, keyed to the flow's verified subject.
    assert approved_before == 0
    assert runtime.approved_clients.is_approved(SUBJECT, PRE_REGISTERED_CLIENT_ID)
    events = audit_events(caplog)
    assert "attribution_required" in events
    assert "attribution_approved" in events
    assert "code_issued" in events
    # Required precedes approved precedes issuance: the decision is one story on the trail.
    assert events.index("attribution_required") < events.index("attribution_approved")
    assert events.index("attribution_approved") < events.index("code_issued")


def test_a_repeat_sign_in_for_an_approved_client_is_silent(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The zero-click property: once approved, the short-circuit mints with no page."""
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        first_id = start_flow(client)
        idp_callback(client, first_id)
        approve(client, first_id)

        # The repeat sign-in for the same (user, client): no page, straight to the code.
        second_id = start_flow(client)
        second = idp_callback(client, second_id)

    assert second.status_code == HTTPStatus.FOUND
    assert second.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    assert "Approve access" not in second.text


def test_deny_consumes_the_flow_with_no_code_issued(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Deny destroys the record, drops the credential, and redirects no OAuth error."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        runtime = runtime_of(client)
        record = runtime.flows.get(flow_id)
        assert record is not None
        response = deny(client, flow_id)
        gone = runtime.flows.get(flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "location" not in response.headers
    assert "declined" in response.text
    assert gone is None
    assert record.identity_access_token is None
    assert record.identity_refresh_token is None
    # No registry entry: the denial wrote nothing.
    assert runtime.approved_clients.entry_count() == 0
    assert "attribution_refused" in audit_events(caplog)


def test_an_approve_after_a_deny_mints_the_fresh_flow(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The deny-then-approve sequence: a fresh flow's approve mints, and is served as a page.

    The owner's blocking shape: deny flow A, then run flow B for the same (subject, client)
    and approve it. The deny wrote no registry entry and consumed only flow A's record, so
    flow B is a first attribution: its approve MUST record the attribution and mint — never
    re-ask (which would mean the approve's continuation looped back to the decision page) and
    never land on the expired page (which would mean the decision was spent without minting).
    The mint is delivered as a navigating page, not a redirect: the decision page's
    `form-action 'self'` makes a browser refuse a 302 off the gateway's origin, so a redirect
    here would strand the user on the decision page — the field symptom this test pins.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        # Flow A: deny.
        first_id = start_flow(client)
        idp_callback(client, first_id)
        denied = deny(client, first_id)
        assert denied.status_code == HTTPStatus.BAD_REQUEST

        # Flow B (fresh) for the same (subject, client): approve must mint.
        second_id = start_flow(client)
        idp_callback(client, second_id)
        approved = approve(client, second_id)
        runtime = runtime_of(client)

    # The approve minted — a page navigating to the harness's redirect, carrying a code —
    # and did not re-ask (the page is the mint navigation, not the decision page) nor expire.
    target = mint_redirect(approved)
    assert "Approve access" not in approved.text
    assert "sign-in session expired" not in approved.text
    assert target.startswith(LOOPBACK_REDIRECT_URI)
    # The mint carried a real code back to the harness.
    assert "code" in parse_qs(urlparse(target).query)
    assert runtime.approved_clients.is_approved(SUBJECT, PRE_REGISTERED_CLIENT_ID)
    events = audit_events(caplog)
    # The trail: A required-then-refused, B required-then-approved-then-issued — exactly one
    # decision page per flow, and B's approve minted.
    two_flows = 2
    assert events.count("attribution_required") == two_flows
    assert "attribution_refused" in events
    assert "attribution_approved" in events
    assert "code_issued" in events


def test_the_action_carries_only_the_flow_id_and_the_decision(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Extra POST fields are ignored: every continuation fact comes from the record.

    The form posts the flow id and the action and nothing else. A POST that also supplies a
    `redirect_uri` (or any other field) must not influence the outcome: the code is
    delivered to the flow's own registered redirect, re-derived from the record, never to a
    value the browser round-tripped.
    """
    attacker_redirect = "http://evil.example/collect"
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        response = client.post(
            "/dial/consent",
            data={
                "flow_id": flow_id,
                "action": "approve",
                "redirect_uri": attacker_redirect,
                "client_id": "some-other-client",
            },
        )

    target = mint_redirect(response)
    # The code went to the flow's registered redirect, not the one the POST offered.
    assert target.startswith(LOOPBACK_REDIRECT_URI)
    assert attacker_redirect not in target


def test_a_replayed_approve_advances_nothing(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Single-use-per-flow: the second POST lands on the expired page and writes nothing."""
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        first = approve(client, flow_id)
        count_after_first = runtime_of(client).approved_clients.entry_count()
        second = approve(client, flow_id)
        count_after_second = runtime_of(client).approved_clients.entry_count()

    assert first.status_code == HTTPStatus.OK
    assert mint_redirect(first).startswith(LOOPBACK_REDIRECT_URI)
    assert second.status_code == HTTPStatus.BAD_REQUEST
    assert "sign-in session expired" in second.text
    # The replay allocated nothing and wrote no second entry: one approval, one mint.
    assert count_after_first == 1
    assert count_after_second == 1


def test_a_foreign_post_against_no_live_flow_lands_on_the_expired_page(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A guessed or unknown flow id advances nothing and writes no registry entry."""
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, _router):
        response = approve(client, "a-guessed-flow-id")
        runtime = runtime_of(client)
        count = runtime.approved_clients.entry_count()

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "sign-in session expired" in response.text
    assert count == 0


def test_an_approval_covers_the_client_across_resources(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The approval is the client's: a second resource renders no page, but is still gated.

    The same user and client signing in for a different resource: the registry key carries
    no resource dimension, so no decision page renders — and the new resource's own DIAL
    authorization read still gates the flow, unchanged by the approval.
    """
    with an_app_gateway(private_key_pem, tmp_path, idp, approved=False) as (
        client,
        router,
    ):
        # The first attribution is on a toolset flow, so its listing read is mocked too.
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        # First attribution for the toolset: approve it.
        toolset_flow = start_flow(client)
        idp_callback(client, toolset_flow)
        approve(client, toolset_flow)

        # The same (subject, client) now signs in for the app: no page renders, because the
        # approval is the client's, not one resource's.
        response = client.get("/dial/authorize", params=app_authorize_params())
        app_flow = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        # The app read still gates: with it refused, the flow fails on the no-access page
        # before the checkpoint is ever reached.
        router.get(CORE_APP_URL).mock(return_value=httpx.Response(403, json={}))
        refused = idp_callback(client, app_flow)

    assert refused.status_code == HTTPStatus.FORBIDDEN
    assert "do not have access to this app" in refused.text
    assert "Approve access" not in refused.text


def test_an_approval_does_not_render_a_page_for_a_second_resource(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The positive half: with the app read admitted, the approved client mints with no page."""
    with an_app_gateway(private_key_pem, tmp_path, idp, approved=False) as (
        client,
        _router,
    ):
        _router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        toolset_flow = start_flow(client)
        idp_callback(client, toolset_flow)
        approve(client, toolset_flow)

        response = client.get("/dial/authorize", params=app_authorize_params())
        app_flow = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        minted = idp_callback(client, app_flow)

    assert minted.status_code == HTTPStatus.FOUND
    assert minted.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    assert "Approve access" not in minted.text


def test_registry_loss_re_prompts_never_bypasses(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A cap eviction forgets the oldest approval, so its next sign-in re-prompts.

    Loss fails safe in one direction only: a dropped approval is a re-prompt, never a
    skip. Driven by a registry capped at one entry, so a second user's approval evicts the
    first's.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        approved=False,
        gateway_approved_clients_max=1,
    ) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        # The user approves the client, then a second entry (another subject) evicts it.
        first = start_flow(client)
        idp_callback(client, first)
        approve(client, first)
        runtime = runtime_of(client)
        assert runtime.approved_clients.is_approved(SUBJECT, PRE_REGISTERED_CLIENT_ID)
        runtime.approved_clients.approve("another-subject", "another-client")

        # The evicted approval's next sign-in renders the decision page again — never a skip.
        second = start_flow(client)
        response = idp_callback(client, second)

    assert response.status_code == HTTPStatus.OK
    assert "Approve access" in response.text


def test_the_consent_route_answers_no_cors_headers(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The consent route is a member of the surface's back-channel-only posture."""
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, _router):
        response = approve(client, "no-such-flow")

    assert not any(
        name.lower().startswith("access-control-") for name in response.headers
    )


def test_the_consent_route_joins_the_limiter(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The route is unauthenticated, so it is bounded before it does any work."""
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        approved=False,
        gateway_rate_per_source_per_minute=1,
    ) as (client, _router):
        first = approve(client, "no-such-flow")
        second = approve(client, "no-such-flow")

    assert first.status_code != HTTPStatus.TOO_MANY_REQUESTS
    assert second.status_code == HTTPStatus.TOO_MANY_REQUESTS


def test_a_malformed_consent_body_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The action is a closed vocabulary: an unknown one is refused, not acted on."""
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, _router):
        response = client.post(
            "/dial/consent",
            content=b"flow_id=x&action=explode",
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "malformed" in response.text


def test_first_attribution_on_the_consent_branch_replaces_the_interstitial_once(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The consent branch's checkpoint rides the interstitial's position, once.

    On first attribution the decision page is served in the interstitial's place, with no
    auto-continue; on approve the flow continues from the record's stored continuation and
    serves the display interstitial as today. Every later attribution for that (subject,
    client) serves the display interstitial verbatim.
    """
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, _router):
        # The consent branch runs when no credential is stored (the default projection).
        flow_id = start_flow(client)
        page = idp_callback(client, flow_id)
        assert "Approve access" in page.text
        assert "http-equiv" not in page.text

        after_approve = approve(client, flow_id)
        # The continuation is the display interstitial: it auto-continues to the upstream.
        assert "http-equiv" in after_approve.text
        assert UPSTREAM_AUTHORIZE_ENDPOINT in after_approve.text

        # The flow still completes through the upstream and mints.
        done = upstream_callback(client, flow_id)
        assert done.status_code == HTTPStatus.FOUND

        # A later sign-in for the same (subject, client): the display interstitial verbatim.
        second_id = start_flow(client)
        second = idp_callback(client, second_id)

    assert second.status_code == HTTPStatus.OK
    assert "Approve access" not in second.text
    assert UPSTREAM_AUTHORIZE_ENDPOINT in second.text


def test_the_consent_branch_stores_the_continuation_on_the_record(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The decision point stores the built upstream URL so the action continues from it.

    The continuation is transient otherwise: the approve action must be able to reach the
    upstream redirect from the record alone, without rebuilding the authorization request.
    """
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, _router):
        flow_id = start_flow(client)
        idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert record is not None
    assert record.upstream_authorization_url is not None
    assert UPSTREAM_AUTHORIZE_ENDPOINT in record.upstream_authorization_url


def test_first_attribution_on_the_app_kind_renders_the_page_where_nothing_rendered(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The app kind's sharpest silent mint now meets the decision page on first attribution.

    No code is minted, no credential call and no upstream round-trip run, and the page names
    the resolved client, the app resource, and the registered redirect.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with an_app_gateway(private_key_pem, tmp_path, idp, approved=False) as (
        client,
        router,
    ):
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        page = idp_callback(client, flow_id)

    assert page.status_code == HTTPStatus.OK
    assert "location" not in page.headers
    assert "Approve access" in page.text
    assert APPS_NAME in page.text
    assert LOOPBACK_REDIRECT_URI in page.text
    assert "attribution_required" in audit_events(caplog)
    assert not any(
        "signin" in str(route.pattern) and route.called for route in router.routes
    )

    # Approve mints directly — the kind-driven short-circuit, gated on the user's act.
    with an_app_gateway(private_key_pem, tmp_path, idp, approved=False) as (
        client,
        router,
    ):
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        idp_callback(client, flow_id)
        approved = approve(client, flow_id)
        runtime = runtime_of(client)

    assert mint_redirect(approved).startswith(LOOPBACK_REDIRECT_URI)
    assert runtime.approved_clients.is_approved(SUBJECT, PRE_REGISTERED_CLIENT_ID)


def test_the_app_kind_approve_path_keeps_the_short_circuit_record(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Approving the app kind mints through the kind-driven short-circuit, and records it.

    The deferred mint must carry the same trail record the approved path emits, so the
    lifecycle requirement's "kind-driven short-circuit is recorded" holds on both the
    direct and the checkpoint-deferred mint — the trail answers that the flow minted with
    no upstream stage because the resource kind is credential-free.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with an_app_gateway(private_key_pem, tmp_path, idp, approved=False) as (
        client,
        _router,
    ):
        response = client.get("/dial/authorize", params=app_authorize_params())
        flow_id = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
        idp_callback(client, flow_id)
        approved = approve(client, flow_id)

    assert mint_redirect(approved).startswith(LOOPBACK_REDIRECT_URI)
    events = audit_events(caplog)
    assert "attribution_approved" in events
    assert "credential_free_short_circuit" in events
    # The short-circuit record precedes issuance, and no consent or credential event ran.
    assert events.index("attribution_approved") < events.index(
        "credential_free_short_circuit"
    )
    assert "signin_result" not in events


def test_no_operator_bypass_for_a_pre_registered_client(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A configured client id buys no skip: the surface has no client authentication.

    A crafted link can wear any configured client id with an attacker's own redirect, so an
    auto-trust keyed on the id would make that link the one shape that skips the page while
    naming a name the user trusts. The decision page is served exactly as for any client.
    """
    with a_gateway(private_key_pem, tmp_path, idp, approved=False) as (client, router):
        router.get(CORE_LISTING_URL).mock(
            return_value=httpx.Response(
                200, json=toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        # PRE_REGISTERED_CLIENT_ID is configured; the page still renders.
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.OK
    assert "Approve access" in response.text
