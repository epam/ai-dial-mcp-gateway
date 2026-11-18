"""Tests for the `/dial/token` authorization-code grant.

Every branch here is a check the grant must make, and the tests are written so each one
fails in isolation: a code bound to another client, another redirect URI, another
resource, a wrong verifier, a replayed code, an expired one. The bindings are checked
from the code's own contents, so the tests mint codes with the real issuance path and
present them with one binding altered — which is what an attacker's attempt looks like.

The single-use claim is the one check that needs state, and its test drives the same code
twice through the real cache rather than mocking it: the property being asserted is that
the second redemption fails, whatever the mechanism.
"""

from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient
from gateway.codes import CodeBindings, code_challenge_for, issue_code, verify_pkce
from gateway.keys import SigningKey
from gateway.state import new_token_id

from tests.conftest import (
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    generate_key_pem,
    make_client,
    make_settings,
    runtime_of,
    surface_settings,
)

# The gateway's origin, as the issuer and the resource URIs are built from it.
ORIGIN = "http://localhost:8090"

RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"

# A PKCE verifier and the challenge derived from it, computed once through the gateway's
# own transform so the test cannot disagree with the implementation about the mapping.
VERIFIER = "a-fixed-code-verifier-for-the-test-only"
CHALLENGE = code_challenge_for(VERIFIER)

# The subject a minted code carries, standing in for a real user's `sub`.
SUBJECT = "3a0d60f4-0000-0000-0000-000000000000"

# A non-empty claim set, so the copy assertions have something to observe.
CLAIMS: dict[str, object] = {
    "roles": ["admin"],
    "project": "proj-alpha",
    "email": "dial@example.test",
}

# The provider's session refresh token a seeded pending entry holds, so a successful
# redemption can seal it into the issued refresh token's custody claim.
PROVIDER_REFRESH_TOKEN = "the-provider-session-refresh-token"


def issue(
    signing_key: SigningKey,
    *,
    client: TestClient | None = None,
    ttl_seconds: int = 300,
    **overrides: Any,
) -> str:
    """Mint a code through the real issuance path, with any binding overridden.

    The bindings are minted directly rather than through a flow, so this file's tests do
    not depend on the copy-and-overlay configuration — the claim copy has its own file.

    When `client` is given, the code comes with a pending hand-off entry seeded exactly as
    `_finish` seeds it: the code grant refuses fail-closed without one, so every test whose
    redemption succeeds must hold the entry the real flow would have left under the code's
    id. A test that only asserts a refusal made before the custody step needs no entry and
    passes no client.
    """
    values: dict[str, Any] = {
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": CHALLENGE,
        "code_challenge_method": "S256",
        "resource": RESOURCE,
        "toolset": TOOLSET_NAME,
        "subject": SUBJECT,
        "claims": dict(CLAIMS),
    }
    values.update(overrides)
    code_id = new_token_id()
    if client is not None:
        runtime_of(client).pending_custody.put(code_id, PROVIDER_REFRESH_TOKEN)
    return issue_code(
        signing_key,
        CodeBindings(**values),
        issuer=ORIGIN,
        ttl_seconds=ttl_seconds,
        code_id=code_id,
    )


def exchange_params(code: str, **overrides: str) -> dict[str, str]:
    """A well-formed redemption request for a code."""
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "code_verifier": VERIFIER,
        "resource": RESOURCE,
    }
    params.update(overrides)
    return params


def post_exchange(client: TestClient, code: str, **overrides: str) -> Any:
    """Post a redemption request as a form, which is how every OAuth client posts one."""
    return client.post("/dial/token", data=exchange_params(code, **overrides))


@pytest.fixture
def token_client(private_key_pem: str, tmp_path: Path) -> Any:
    """A client whose runtime shares the signing key the tests mint codes with."""

    @contextmanager
    def open_client() -> Any:
        settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))
        with make_client(settings, private_key_pem) as client:
            yield client

    return open_client


@pytest.fixture
def signing_key_for(private_key_pem: str) -> SigningKey:
    return SigningKey(private_key_pem)


# -------------------------------------------------------------------- the happy path


def test_a_valid_code_exchanges_for_an_access_token(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """The positive control: what every refusal below is measured against."""
    with token_client() as client:
        response = post_exchange(client, issue(signing_key_for, client=client))

    assert response.status_code == HTTPStatus.OK
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] > 0
    assert body["access_token"]


def test_the_access_token_is_signed_by_the_gateway_and_names_the_subject(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """The token Core will verify: the gateway's issuer, the user's subject, the resource."""
    with token_client() as client:
        response = post_exchange(client, issue(signing_key_for, client=client))

    payload = jwt.decode(
        response.json()["access_token"],
        signing_key_for.public_key(),
        algorithms=["RS256"],
        options={"verify_aud": False},
    )

    assert payload["iss"] == ORIGIN
    assert payload["sub"] == SUBJECT
    # The audience carries the resource *and* the marker Core's provider entry verifies, so
    # a gateway-issuer token minted for anything else is not valid deployment-wide.
    assert payload["aud"] == [RESOURCE, "dial-mcp-proxy"]
    assert payload["exp"] > time.time()


def test_the_exchange_response_is_not_cacheable(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """An issued token must not survive in a proxy's cache."""
    with token_client() as client:
        response = post_exchange(client, issue(signing_key_for, client=client))

    assert response.headers["cache-control"] == "no-store"


def test_the_exchange_records_an_audit_event_without_the_token(
    token_client: Any,
    signing_key_for: SigningKey,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Attribution without credential material: the subject and client, not the token."""

    caplog.set_level(logging.INFO, logger="gateway.audit")

    with token_client() as client:
        token = post_exchange(client, issue(signing_key_for, client=client)).json()[
            "access_token"
        ]

    assert SUBJECT in caplog.text
    assert PRE_REGISTERED_CLIENT_ID in caplog.text
    assert token not in caplog.text


# ------------------------------------------------------------------- request shape


def test_a_missing_grant_type_is_refused(token_client: Any) -> None:
    with token_client() as client:
        response = client.post("/dial/token", data={})

    assert response.json()["error"] == "invalid_request"


def test_a_non_form_request_to_revoke_is_refused(token_client: Any) -> None:
    with token_client() as client:
        response = client.post("/dial/revoke", json={"token": "x"})

    assert response.json()["error"] == "invalid_request"


def test_an_unsupported_grant_type_is_refused(token_client: Any) -> None:
    """A grant this server does not implement is reported as one.

    `unsupported_grant_type` rather than `invalid_request`: the request is well formed and
    names a flow this server does not serve, which is the distinction a client's error
    handling acts on.
    """
    with token_client() as client:
        response = client.post("/dial/token", data={"grant_type": "client_credentials"})

    assert response.json()["error"] == "unsupported_grant_type"


def test_a_non_form_content_type_is_refused(token_client: Any) -> None:
    """A token request in any other shape is refused rather than guessed at."""
    with token_client() as client:
        response = client.post("/dial/token", json={"grant_type": "authorization_code"})

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_request"


@pytest.mark.parametrize(
    "missing", ["code", "redirect_uri", "client_id", "code_verifier", "resource"]
)
def test_each_required_parameter_is_required(
    token_client: Any, signing_key_for: SigningKey, missing: str
) -> None:
    """Each one names itself in the refusal, so a client can fix the request it sent."""
    params = exchange_params(issue(signing_key_for))
    del params[missing]

    with token_client() as client:
        response = client.post("/dial/token", data=params)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert missing in response.json()["error_description"]


def test_a_repeated_parameter_is_refused(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """A repeated parameter has no single meaning, so it has no meaning to validate."""
    code = issue(signing_key_for)
    body = exchange_params(code) | {"client_id": PRE_REGISTERED_CLIENT_ID}
    pairs = "&".join(f"{name}={value}" for name, value in body.items())
    pairs += f"&client_id={PRE_REGISTERED_CLIENT_ID}"

    with token_client() as client:
        response = client.post(
            "/dial/token",
            content=pairs.encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.json()["error"] == "invalid_request"
    assert "more than once" in response.json()["error_description"]


# ------------------------------------------------------------------ code validation


def test_a_code_issued_to_another_client_is_refused(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    code = issue(signing_key_for, client_id="another-client")

    with token_client() as client:
        response = post_exchange(client, code)

    assert response.json()["error"] == "invalid_grant"


def test_a_code_issued_for_another_redirect_uri_is_refused(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    code = issue(signing_key_for, redirect_uri="http://127.0.0.1:9999/elsewhere")

    with token_client() as client:
        response = post_exchange(client, code)

    assert response.json()["error"] == "invalid_grant"


def test_a_code_redeemed_for_another_resource_is_invalid_target(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """The resource is the toolset signal on both endpoints, so it must match."""
    code = issue(signing_key_for)

    with token_client() as client:
        response = post_exchange(client, code, resource=f"{ORIGIN}/dial/other/mcp")

    assert response.json()["error"] == "invalid_target"


def test_a_missing_resource_on_redemption_is_invalid_target(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """Absent is not "the same as the code's": it is a request that named no toolset."""
    code = issue(signing_key_for)
    params = exchange_params(code)
    del params["resource"]

    with token_client() as client:
        response = client.post("/dial/token", data=params)

    assert response.json()["error"] == "invalid_target"


def test_a_wrong_verifier_is_refused(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """The PKCE binding: a code without its verifier establishes nothing."""
    code = issue(signing_key_for)

    with token_client() as client:
        response = post_exchange(client, code, code_verifier="a-different-verifier")

    assert response.json()["error"] == "invalid_grant"


def test_a_plain_challenge_method_cannot_be_redeemed(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """`plain` would put the verifier on the wire, so it is never accepted."""
    code = issue(
        signing_key_for,
        code_challenge=VERIFIER,
        code_challenge_method="plain",
    )

    with token_client() as client:
        response = post_exchange(client, code)

    assert response.json()["error"] == "invalid_grant"


def test_a_replayed_code_is_refused(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """Single use: the second redemption fails even with the correct verifier."""
    with token_client() as client:
        code = issue(signing_key_for, client=client)
        first = post_exchange(client, code)
        second = post_exchange(client, code)

    assert first.status_code == HTTPStatus.OK
    assert second.json()["error"] == "invalid_grant"
    assert "already been used" in second.json()["error_description"]


def test_an_expired_code_is_refused(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """The code's life is minutes; past it the harness must re-run the sign-in."""
    code = issue(signing_key_for, ttl_seconds=-1)

    with token_client() as client:
        response = post_exchange(client, code)

    assert response.json()["error"] == "invalid_grant"
    assert "expired" in response.json()["error_description"]


def test_a_code_signed_by_another_key_is_refused(token_client: Any) -> None:
    """A code is a signed token, so an unsigned or foreign-signed one establishes nothing."""
    foreign = SigningKey(generate_key_pem())
    code = issue(foreign)

    with token_client() as client:
        response = post_exchange(client, code)

    assert response.json()["error"] == "invalid_grant"


def test_an_access_token_is_not_accepted_as_an_authorization_code(
    token_client: Any, signing_key_for: SigningKey
) -> None:
    """All three token kinds are signed by one key, so the type claim is what separates them.

    Without the check, an access token would be redeemable as a code — and an access token
    is a bearer string a harness holds for minutes.
    """
    with token_client() as client:
        access_token = post_exchange(
            client, issue(signing_key_for, client=client)
        ).json()["access_token"]
        response = post_exchange(client, access_token)

    assert response.json()["error"] == "invalid_grant"


def test_a_nonsense_code_is_refused(token_client: Any) -> None:
    with token_client() as client:
        response = post_exchange(client, "not-a-code-at-all")

    assert response.json()["error"] == "invalid_grant"


def test_a_refusal_does_not_echo_the_code(token_client: Any) -> None:
    """An error description must not carry request material back out."""
    secret_looking_code = "SECRET-CODE-VALUE-THAT-MUST-NOT-BE-ECHOED"

    with token_client() as client:
        response = post_exchange(client, secret_looking_code)

    assert secret_looking_code not in response.text


def test_the_exchange_response_is_not_cacheable_on_refusal(token_client: Any) -> None:
    with token_client() as client:
        response = post_exchange(client, "not-a-code")

    assert response.headers["cache-control"] == "no-store"


# ------------------------------------------------------------------- PKCE transform


def test_the_challenge_transform_is_the_standard_s256() -> None:
    """Pinned against a value computed outside this implementation.

    The transform is what a client computes for itself, so the gateway and the client
    must agree on it exactly — an independent value is the only way to check that.
    """
    # RFC 7636 appendix B's verifier and its S256 challenge.
    assert (
        code_challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_pkce_verification_rejects_a_mismatch() -> None:
    assert verify_pkce("whatever", CHALLENGE, "S256") is False
    assert verify_pkce(VERIFIER, CHALLENGE, "S256") is True


def test_pkce_verification_rejects_an_unknown_method() -> None:
    assert verify_pkce(VERIFIER, CHALLENGE, "S512") is False


def test_pkce_verification_handles_empty_values() -> None:
    """An empty verifier or challenge must not be accepted as a match."""
    assert verify_pkce("", "", "S256") is False
    assert verify_pkce(VERIFIER, "", "S256") is False


def test_a_code_carries_its_bindings_and_no_verifier(
    signing_key_for: SigningKey,
) -> None:
    """The code carries the challenge, never the verifier.

    A verifier in the code would be the verifier on the wire, which is the property PKCE
    exists to establish.
    """
    code = issue(signing_key_for)
    payload = jwt.decode(
        code,
        signing_key_for.public_key(),
        algorithms=["RS256"],
        options={"verify_aud": False},
    )

    assert payload["code_challenge"] == CHALLENGE
    assert "code_verifier" not in payload
    assert VERIFIER not in code


def test_the_issuer_matches_the_settings_origin() -> None:
    """A code minted under a different issuer would be rejected by the decode step."""
    settings = make_settings()
    assert settings.gateway_public_origin == ORIGIN
