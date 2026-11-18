"""Tests for the identity leg's endpoint source (tasks 3.1, 3.3, 3.4).

Every endpoint the identity leg uses comes from one configured source — the provider's
OpenID Connect discovery document, or the operator's directly configured trio — and never
from URL arithmetic on the issuer's spelling. The tests here state that from both sides:

* **Discovery mode** — the document's endpoints serve all four legs (the authorization
  redirect, the code exchange, the refresh grant, the key-set fetch) from one fetch, the
  document is validated against the configured issuer before any of it is used, the
  validated result is cached for the TTL, and a provider that cannot be reached or
  answers an unusable document fails the leg closed with no fallback construction.
* **Direct mode** — the configured trio serves all four legs with no fetch attempted at
  all, the back-channel override re-addresses the server-to-server pair only, a stale
  configured endpoint fails the leg closed, and issuer pinning is unchanged by the mode.

The provider under test is deliberately *not* shaped like the local development
instance: its endpoints are spelled independently of its issuer's path, so an arithmetic
construction — a realm name, a hard-coded suffix — would produce URLs nothing serves and
every test here would fail loudly rather than pass on a coincidental match.

The startup refusals both modes carry (the partial or malformed trio, the plain-http
endpoint, the plain-http issuer) live in `tests/test_settings.py`, where this suite
keeps every startup refusal.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import gateway.idp as idp_module
import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from gateway.codes import code_challenge_for
from gateway.idp import (
    _DISCOVERY_MAX_BYTES,
    _RESPONSE_MAX_BYTES,
    backchannel_addressed,
)
from pydantic import SecretStr

from tests.conftest import (
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    discovery_url_of,
    make_client,
    runtime_of,
    surface_settings,
)

ORIGIN = "http://localhost:8090"
RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"

# The provider under test: a single-origin external provider whose endpoints are its own
# discovery document's. The issuer's path is a journey, not an endpoint prefix — the
# shape that makes "no endpoint is derived by arithmetic" observable.
ISSUER = "https://signin.example.com/journey"
OTHER_JOURNEY_ISSUER = "https://signin.example.com/other-journey"
# A canonical issuer that ends in `/` — the per-journey issuer form some providers
# carry — spelling the pin the trailing-slash tests below federate at.
TRAILING_SLASH_ISSUER = "https://signin.example.com/journey/v2.0/"
AUTHORIZATION_ENDPOINT = "https://signin.example.com/oauth2/authorize"
TOKEN_ENDPOINT = "https://signin.example.com/oauth2/token"
JWKS_URI = "https://signin.example.com/oauth2/keys"

# An internal plain-http origin, for the back-channel override tests.
BACKCHANNEL_BASE_URL = "http://internal.example:8081"

# Core's two reads, as the flow makes them.
CORE_LISTING_URL = f"http://core:8080/openai/toolsets/{TOOLSET_NAME}"

# The harness client's PKCE pair and state.
HARNESS_VERIFIER = "a-verifier-for-the-endpoint-source-tests"
HARNESS_STATE = "the-harness-state"

# The provider's session-bound refresh token, as its exchange returns it.
PROVIDER_REFRESH_TOKEN = "the-provider-session-refresh-token"

# The number of token-endpoint posts the exchange and the refresh grant make together,
# and the number of discovery fetches a process has spent once its cache expired once.
EXCHANGE_AND_REFRESH = 2
INITIAL_FETCH_AND_REFETCH = 2
# The same count in the failed-fetch regime: the outage's one failed attempt, then one
# more after the failure window closes.
FAILED_WINDOW_FETCH_AND_REFETCH = 2

SUBJECT = "3a0d60f4-0000-0000-0000-000000000000"
IDENTITY_CLAIMS: dict[str, Any] = {
    "sub": SUBJECT,
    "roles": ["admin"],
    "project": "proj-alpha",
}


def _b64_uint(value: int) -> str:
    """An RSA modulus or exponent, as a JWK's base64url integer."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Idp:
    """A generated identity-provider keypair, and the tokens it signs."""

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
                    "kid": "the-provider-key",
                    "n": _b64_uint(numbers.n),
                    "e": _b64_uint(numbers.e),
                }
            ]
        }

    def token(self, *, iss: str = ISSUER, **overrides: Any) -> str:
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": iss,
            "aud": "the-gateways-client",
            "iat": now,
            "exp": now + 300,
            **IDENTITY_CLAIMS,
        }
        claims.update(overrides)
        return jwt.encode(
            claims, self.pem, algorithm="RS256", headers={"kid": "the-provider-key"}
        )


def discovery_document(**overrides: Any) -> dict[str, Any]:
    """The provider's discovery document, as a well-formed one advertises itself."""
    document: dict[str, Any] = {
        "issuer": ISSUER,
        "authorization_endpoint": AUTHORIZATION_ENDPOINT,
        "token_endpoint": TOKEN_ENDPOINT,
        "jwks_uri": JWKS_URI,
    }
    document.update(overrides)
    return document


@pytest.fixture
def idp() -> Idp:
    """A keypair generated per test, so the verification path is genuinely exercised."""
    return Idp()


def toolset_projection(**overrides: Any) -> dict[str, Any]:
    """Core's listing projection, with no verifier anywhere in it.

    The per-caller statuses ride the same `auth_settings` member — the listing read's
    enrichment — SIGNED_OUT by default, so the flow proceeds to the consent leg.
    """
    auth: dict[str, Any] = {
        "authentication_type": "OAUTH",
        "client_id": "core-upstream-client",
        "authorization_endpoint": "https://mcp.example.com/authorize",
        "redirect_uri": "http://localhost:8765/callback",
        "code_challenge": "the-upstream-challenge",
        "code_challenge_method": "S256",
        "scopes_supported": ["default"],
        "dynamically_registered": True,
        "user_level_auth_status": "SIGNED_OUT",
        "global_auth_status": "SIGNED_OUT",
    }
    auth.update(overrides)
    return {"name": TOOLSET_NAME, "auth_settings": auth}


def authorize_params() -> dict[str, str]:
    """A well-formed authorization request for the pre-registered client."""
    return {
        "response_type": "code",
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": code_challenge_for(HARNESS_VERIFIER),
        "code_challenge_method": "S256",
        "resource": RESOURCE,
        "state": HARNESS_STATE,
    }


@contextmanager
def a_gateway(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    *,
    discovery_answer: Any = None,
    install_discovery_route: bool = True,
    **settings_overrides: object,
) -> Iterator[tuple[TestClient, respx.Router, respx.Route | None]]:
    """A running gateway whose outbound answers are intercepted by the routes here.

    The routes are entered before the app, so the flow's first outbound call — the
    discovery fetch, on the first authorize — is already intercepted. The discovery route
    is installed too unless asked not to, so a test that means to prove a fetch never
    happens can count on it staying at zero calls; a test that means to make the provider
    unreachable or lying passes its own `discovery_answer`. The token and key-set routes
    are addressed to the URLs the leg will actually use — the settings' endpoints through
    the back-channel override — so a routing bug fails as an unmatched request.

    The back-channel override is defaulted OFF here (the shared fixture supplies the local
    realm's), because this file's provider is single-origin by construction: a test that
    wants the override passes it, and the assertions then name its URLs.
    """
    values: dict[str, object] = {
        "idp_issuer": ISSUER,
        "idp_backchannel_base_url": None,
        "dcr_store_path": str(tmp_path / "store.json"),
    }
    values.update(settings_overrides)
    settings = surface_settings(**values)
    token_url = backchannel_addressed(
        settings.idp_token_endpoint or TOKEN_ENDPOINT, settings
    )
    jwks_url = backchannel_addressed(settings.idp_jwks_uri or JWKS_URI, settings)
    with respx.mock(assert_all_called=False) as router:
        discovery_route: respx.Route | None = None
        if install_discovery_route:
            discovery_route = router.get(discovery_url_of(settings))
            if discovery_answer is None:
                discovery_route.mock(
                    return_value=httpx.Response(200, json=discovery_document())
                )
            elif isinstance(discovery_answer, Exception):
                discovery_route.mock(side_effect=discovery_answer)
            else:
                discovery_route.mock(return_value=discovery_answer)
        router.get(jwks_url).mock(return_value=httpx.Response(200, json=idp.jwks))
        router.post(token_url).mock(
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
        router.post("http://core:8080/v1/ops/toolset/signin").mock(
            return_value=httpx.Response(200, json=True)
        )
        with make_client(settings, private_key_pem) as client:
            yield client, router, discovery_route


def start_flow(client: TestClient) -> str:
    """Authorize, and return the flow id the provider leg carries as its state."""
    response = client.get("/dial/authorize", params=authorize_params())
    assert response.status_code == HTTPStatus.FOUND, response.text
    location = response.headers["location"]
    assert location.startswith(AUTHORIZATION_ENDPOINT), location
    flow_id: str = parse_qs(urlparse(location).query)["state"][0]
    return flow_id


def idp_callback(client: TestClient, flow_id: str) -> Any:
    return client.get(
        "/dial/callback/idp", params={"state": flow_id, "code": "the-provider-code"}
    )


def complete_flow(client: TestClient, flow_id: str) -> str:
    """Run the flow through the upstream consent and return the harness's code."""
    callback = idp_callback(client, flow_id)
    assert callback.status_code == HTTPStatus.OK, callback.text
    done = client.get(
        "/dial/callback/upstream",
        params={"state": flow_id, "code": "the-upstream-code"},
    )
    assert done.status_code == HTTPStatus.FOUND, done.text
    code: str = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    return code


def urls_of(router: respx.Router) -> list[str]:
    """Every URL an intercepted outbound call was addressed to, in order."""
    return [str(call.request.url) for call in router.calls]


def _refusal_reasons(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The `flow_refused` reasons a run emitted, in order."""
    return [
        json.loads(record.getMessage())["reason"]
        for record in caplog.records
        if record.name == "gateway.audit"
        and json.loads(record.getMessage())["event"] == "flow_refused"
    ]


# ------------------------------------------------- discovery mode: the one endpoint source


def test_the_discovered_endpoints_serve_all_four_legs_from_one_fetch(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """One document answers for the redirect, the exchange, the refresh, and the keys.

    The property is the one-spelling rule, and it is asserted on the requests the gateway
    actually made: the redirect goes to the discovered authorization endpoint, the code
    exchange and the refresh grant both post to the discovered token endpoint, the key
    set is fetched from the discovered `jwks_uri`, and the discovery document itself is
    fetched exactly once for all of it — cached across the legs. No URL the gateway
    touches is derived from the issuer by a provider-specific suffix.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, router, discovery_route):
        flow_id = start_flow(client)
        code = complete_flow(client, flow_id)

        # Redeem the harness's code, then refresh with the issued refresh token: the
        # refresh grant is the fourth leg, and it must reuse the same endpoint set.
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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text
        refreshed = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == HTTPStatus.OK, refreshed.text

        # Read the interceptors inside the gateway's lifetime: a router's calls are its
        # own to clear when it stops.
        assert discovery_route is not None
        urls = urls_of(router)

    assert discovery_route.call_count == 1

    token_posts = [u for u in urls if u == TOKEN_ENDPOINT]
    assert token_posts == [TOKEN_ENDPOINT, TOKEN_ENDPOINT]
    key_set_fetches = [u for u in urls if u == JWKS_URI]
    assert len(key_set_fetches) >= 1
    # No provider-specific arithmetic anywhere: no request carries the local instance's
    # endpoint suffix or any path built from the issuer's journey segment.
    assert not any("/protocol/openid-connect/" in url for url in urls)


def test_a_discovery_document_advertising_another_issuer_is_refused_whole(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A document claiming another authority is not this provider's, and none of it is used.

    The configured issuer is the trust anchor the document is validated against; a
    document whose `issuer` member differs is refused whole, the sign-in fails with the
    operator-facing error, and no endpoint from it is ever addressed.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        discovery_answer=httpx.Response(
            200, json=discovery_document(issuer=OTHER_JOURNEY_ISSUER)
        ),
    ) as (client, router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())
        assert response.status_code == HTTPStatus.BAD_GATEWAY
        assert "names another issuer" in response.text
        # No endpoint from the refused document was used: nothing was posted, no key set
        # fetched.
        assert not [u for u in urls_of(router) if u in (TOKEN_ENDPOINT, JWKS_URI)]


def test_an_out_of_origin_discovered_endpoint_is_refused_whole(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """No endpoint the document names can steer a credential-bearing call elsewhere.

    The document advertises a token endpoint on another origin; the whole document is
    refused rather than used partially — the SSRF-shaped bound on a provider-asserted
    input, so the code and the carried refresh token never ride a leg an attacker chose.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        discovery_answer=httpx.Response(
            200,
            json=discovery_document(token_endpoint="https://evil.example/oauth2/token"),
        ),
    ) as (client, router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())
        assert response.status_code == HTTPStatus.BAD_GATEWAY
        assert "origin that is neither" in response.text
        # The steered-to origin was never contacted — an attempted call would fail this
        # test as an unintercepted request before the assertion below could even run.
        assert not [u for u in urls_of(router) if u.startswith("https://evil.example")]


def test_an_unreachable_provider_fails_the_leg_closed_with_no_fallback(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A provider that cannot be fetched leaves nothing to fall back to — by design.

    There is no arithmetic construction behind the document, so an unreachable provider
    fails the sign-in with the operator-facing error, and no token endpoint, key-set, or
    authorize URL is ever built from the issuer's spelling as a substitute.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        discovery_answer=httpx.ConnectError("unreachable"),
    ) as (client, router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())
        assert response.status_code == HTTPStatus.BAD_GATEWAY
        assert "discovery document could not be reached" in response.text
        # No fallback construction: the only outbound call attempted was the fetch itself.
        assert urls_of(router) == [discovery_url_of(runtime_of(client).settings)]


def test_an_oversized_discovery_document_is_refused_while_being_read(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The size cap is enforced while the document is read, not after it is buffered.

    The provider answers with a body far past the cap; the gateway refuses the document
    the moment the cap is crossed and abandons the answer's tail unread. A cap checked
    after a full buffered read would have drained the whole answer into memory before
    refusing it — the test's counters say the tail was never pulled, so the cap bounds
    what the gateway buffers, not merely what it parses.
    """
    chunk_size = 4096
    chunks_in_answer = 1000  # about 4 MB, far past the 64 KiB cap
    chunks_pulled = 0

    def oversized_answer() -> Iterator[bytes]:
        nonlocal chunks_pulled
        for _ in range(chunks_in_answer):
            chunks_pulled += 1
            yield b"x" * chunk_size

    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        discovery_answer=httpx.Response(200, content=oversized_answer()),
    ) as (client, _router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())
        pulled_at_refusal = chunks_pulled

    assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
    assert "larger than this gateway accepts" in response.text
    # Reading stops at the cap: the refusal comes within one chunk of crossing it, and
    # nothing like the whole answer was ever buffered.
    assert pulled_at_refusal <= _DISCOVERY_MAX_BYTES // chunk_size + 1
    assert pulled_at_refusal < chunks_in_answer


def test_an_oversized_token_response_is_refused_while_being_read(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The code exchange's answer is capped while it is read, like every leg answer.

    The exchange and the refresh grant serve external providers the deployment does not
    operate, so a compromised or misbehaving provider must not be able to make the
    gateway buffer an unbounded answer inside the outbound timeout. The same
    read-time discipline the discovery fetch and the refresh grant obey is asserted the
    same way here: the answer streams from a counter, and the refusal lands within one
    chunk of crossing the cap — the tail was never pulled, so the cap bounds what the
    gateway buffers, not merely what it later parses.
    """
    chunk_size = 4096
    chunks_in_answer = 1000  # about 4 MB, far past the 64 KiB cap
    chunks_pulled = 0

    def oversized_answer() -> Iterator[bytes]:
        nonlocal chunks_pulled
        for _ in range(chunks_in_answer):
            chunks_pulled += 1
            yield b"x" * chunk_size

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router, _route):
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(200, content=oversized_answer())
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)
        pulled_at_refusal = chunks_pulled

    assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
    assert "token response is larger than this gateway accepts" in response.text
    # Reading stops at the cap: the refusal comes within one chunk of crossing it, and
    # nothing like the whole answer was ever buffered.
    assert pulled_at_refusal <= _RESPONSE_MAX_BYTES // chunk_size + 1
    assert pulled_at_refusal < chunks_in_answer


def test_an_oversized_key_set_is_refused_while_being_read(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The published key set is capped while it is read, like every leg answer.

    The key set verifies the tokens the mint copies claims from, and it now comes from
    external providers too — so a hostile key-set answer is refused the moment it
    crosses the cap, on the same counted-chunks instrument as the discovery document
    and the token answer, and never buffered whole.
    """
    chunk_size = 4096
    chunks_in_answer = 1000  # about 4 MB, far past the 64 KiB cap
    chunks_pulled = 0

    def oversized_answer() -> Iterator[bytes]:
        nonlocal chunks_pulled
        for _ in range(chunks_in_answer):
            chunks_pulled += 1
            yield b"x" * chunk_size

    with a_gateway(private_key_pem, tmp_path, idp) as (client, router, _route):
        router.get(JWKS_URI).mock(
            return_value=httpx.Response(200, content=oversized_answer())
        )
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)
        pulled_at_refusal = chunks_pulled

    assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
    assert "key set is larger than this gateway accepts" in response.text
    # Reading stops at the cap: the refusal comes within one chunk of crossing it, and
    # nothing like the whole answer was ever buffered.
    assert pulled_at_refusal <= _RESPONSE_MAX_BYTES // chunk_size + 1
    assert pulled_at_refusal < chunks_in_answer


def test_an_unaddressable_issuer_fails_the_leg_with_the_fixed_vocabulary(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A URL the HTTP client cannot parse is a leg failure, not an unhandled error.

    Startup's well-formedness check refuses what a URL parser refuses; a value that
    passes it and that the HTTP client still cannot address — a malformed port — is
    caught at the fetch and translated into the leg's fixed-vocabulary failure, so the
    browser gets the leg's error page and the operator a named cause instead of a bare
    500.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        discovery_answer=httpx.InvalidURL("unaddressable"),
    ) as (client, _router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())

    assert response.status_code == HTTPStatus.BAD_GATEWAY, response.text
    assert "discovery document could not be reached (InvalidURL)" in response.text


def test_the_cache_is_honored_within_the_ttl_and_refetched_after(
    private_key_pem: str, tmp_path: Path, idp: Idp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cold start costs one fetch per window; the first leg after expiry re-fetches.

    The TTL is the documented bound on how long a provider's endpoint change goes
    unnoticed, so both halves are pinned: legs inside the window reuse the cached
    endpoints with no fetch, and the cache clock's passing (moved here, as a wait would
    move it) makes the next leg fetch again.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (
        client,
        _router,
        discovery_route,
    ):
        assert discovery_route is not None

        start_flow(client)
        assert discovery_route.call_count == 1

        # A second sign-in in the same process, inside the window: the cache serves it.
        start_flow(client)
        assert discovery_route.call_count == 1

        # The TTL passes, as a wait would — without the wait.
        ttl = runtime_of(client).settings.idp_discovery_cache_ttl_seconds
        monkeypatch.setattr(
            idp_module, "_monotonic_now", lambda: time.monotonic() + ttl + 1
        )
        start_flow(client)
        assert discovery_route.call_count == INITIAL_FETCH_AND_REFETCH


def test_a_failed_fetch_costs_one_attempt_per_window(
    private_key_pem: str, tmp_path: Path, idp: Idp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A provider outage costs at most one fetch attempt per window, like a success.

    A fetch that fails fills nothing, so without a record of the failure every sign-in
    during an outage would pay its own fetch attempt and the one-fetch-per-window bound
    would hold only while the provider answers. The failure is therefore remembered for
    the same window: sign-ins inside it are refused again — the same operator-facing
    error, no new fetch — and the first sign-in after the window retries the provider,
    once.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        discovery_answer=httpx.ConnectError("unreachable"),
    ) as (client, _router, discovery_route):
        assert discovery_route is not None

        for _ in range(3):
            response = client.get("/dial/authorize", params=authorize_params())
            assert response.status_code == HTTPStatus.BAD_GATEWAY, response.text
            assert "discovery document could not be reached" in response.text
        assert discovery_route.call_count == 1

        # The window passes, as a wait would — without the wait.
        ttl = runtime_of(client).settings.idp_discovery_cache_ttl_seconds
        monkeypatch.setattr(
            idp_module, "_monotonic_now", lambda: time.monotonic() + ttl + 1
        )
        response = client.get("/dial/authorize", params=authorize_params())
        assert response.status_code == HTTPStatus.BAD_GATEWAY, response.text
        assert discovery_route.call_count == FAILED_WINDOW_FETCH_AND_REFETCH


def test_a_refused_document_is_served_from_the_failure_window(
    private_key_pem: str, tmp_path: Path, idp: Idp, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A document the validation refuses is remembered for the window too.

    Refusal is not absence: a document naming another issuer is refused whole, and the
    recorded refusal — not a fresh fetch — is what the window's remaining sign-ins are
    served. A provider lying about its own identity cannot buy one fetch per sign-in
    that way either; the retry comes when the window closes.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        discovery_answer=httpx.Response(
            200, json=discovery_document(issuer=OTHER_JOURNEY_ISSUER)
        ),
    ) as (client, _router, discovery_route):
        assert discovery_route is not None

        for _ in range(3):
            response = client.get("/dial/authorize", params=authorize_params())
            assert response.status_code == HTTPStatus.BAD_GATEWAY, response.text
            assert "names another issuer" in response.text
        assert discovery_route.call_count == 1

        # The window passes, as a wait would — without the wait.
        ttl = runtime_of(client).settings.idp_discovery_cache_ttl_seconds
        monkeypatch.setattr(
            idp_module, "_monotonic_now", lambda: time.monotonic() + ttl + 1
        )
        response = client.get("/dial/authorize", params=authorize_params())
        assert response.status_code == HTTPStatus.BAD_GATEWAY, response.text
        assert discovery_route.call_count == FAILED_WINDOW_FETCH_AND_REFETCH


def test_the_back_channel_override_readdresses_the_server_calls_only(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The override's scheme-and-host swap touches the server-to-server pair alone.

    With a single-origin discovery document and a back-channel base configured, the
    discovery fetch, the code exchange, the refresh grant, and the key-set fetch are
    addressed to the override's origin with the document's paths kept; the browser-facing
    authorization redirect carries the discovered endpoint unchanged; and the identity
    token's issuer check still matches the configured issuer exactly — the exchange
    completes, which is that check passing.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_backchannel_base_url=BACKCHANNEL_BASE_URL,
        # The document is the single-origin provider's: every endpoint it advertises is
        # at the issuer's origin, and the override is what re-addresses the back legs.
        discovery_answer=httpx.Response(
            200,
            json=discovery_document(
                token_endpoint=TOKEN_ENDPOINT,
                jwks_uri=JWKS_URI,
            ),
        ),
    ) as (client, router, discovery_route):
        flow_id = start_flow(client)
        code = complete_flow(client, flow_id)
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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text

        internal_token = f"{BACKCHANNEL_BASE_URL}/oauth2/token"
        internal_jwks = f"{BACKCHANNEL_BASE_URL}/oauth2/keys"

        # The refresh grant proves the fourth leg rides the override too.
        refreshed = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == HTTPStatus.OK, refreshed.text

        assert discovery_route is not None
        urls = urls_of(router)

    assert discovery_route.call_count == 1

    # The discovery fetch itself rides the override — scheme and host swapped, path kept.
    assert (
        urls.count(f"{BACKCHANNEL_BASE_URL}/journey/.well-known/openid-configuration")
        == 1
    )
    assert (
        urls.count(internal_token) == EXCHANGE_AND_REFRESH
    )  # exchange + refresh grant
    assert urls.count(internal_jwks) >= 1
    # The browser-facing leg keeps the discovered endpoint at the issuer's own origin:
    # nothing rode the override's origin except the server-to-server pair and the fetch.
    for url in urls:
        if url.startswith(BACKCHANNEL_BASE_URL):
            assert url in (
                f"{BACKCHANNEL_BASE_URL}/journey/.well-known/openid-configuration",
                internal_token,
                internal_jwks,
            )


# ------------------------------------------- varying-issuer pinning (discovery mode)


def test_a_token_from_another_journeys_issuer_is_refused_at_sign_in(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The pin is exact-string: a sibling journey's token is not this deployment's.

    The provider's issuers vary by sign-in journey; the configured issuer is the one
    journey this deployment federates. A token whose `iss` names the sibling journey —
    same provider, same host, different journey segment — is refused at the exchange.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (
        client,
        router,
        _discovery_route,
    ):
        flow_id = start_flow(client)
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(iss=OTHER_JOURNEY_ISSUER),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )
        )
        response = idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)
        assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
        assert "could not be verified" in response.text
        assert record is not None
        assert record.identity_claims is None


def test_a_token_from_another_journeys_issuer_is_refused_at_refresh(
    private_key_pem: str, tmp_path: Path, idp: Idp, caplog: pytest.LogCaptureFixture
) -> None:
    """The same pin at the refresh site: one verification path, both ends.

    A fresh token naming the sibling journey's issuer fails verification, the refresh is
    refused with `invalid_grant`, and the refusal audits as a claims-read failure — the
    token was unusable, not the session ended.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (
        client,
        router,
        _discovery_route,
    ):
        flow_id = start_flow(client)
        code = complete_flow(client, flow_id)
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
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(iss=OTHER_JOURNEY_ISSUER),
                    "token_type": "Bearer",
                },
            )
        )
        response = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == ["claims_read_failed"]


# --------------- the issuer pin's exact spelling: a canonical issuer ending in a slash


def test_a_trailing_slash_issuer_is_federated_at_its_exact_spelling(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A canonical issuer ending in `/` federates: the configured spelling is the pin.

    Some providers' canonical issuer ends in `/` (the per-journey issuer form the tested
    deployments carry). The pin is the operator's spelling, kept verbatim: the discovery
    document's `issuer` member and the token's `iss` claim both carry the same trailing
    slash, and the leg completes through discovery validation and token verification
    alike. The well-known URL is joined with exactly one separator at the fetch, never
    by normalizing the pin.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_issuer=TRAILING_SLASH_ISSUER,
        discovery_answer=httpx.Response(
            200, json=discovery_document(issuer=TRAILING_SLASH_ISSUER)
        ),
    ) as (client, router, discovery_route):
        flow_id = start_flow(client)
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(iss=TRAILING_SLASH_ISSUER),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )
        )
        code = complete_flow(client, flow_id)
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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text
        assert discovery_route is not None
        # The fetch went to the joined spelling — one separator between the issuer's
        # path and the well-known suffix, at the configured origin.
        assert discovery_route.call_count == 1


def test_a_discovery_document_issuer_missing_only_the_slash_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The exact-string pin cuts both ways: a near-miss document is not this provider's.

    The configured issuer ends in `/`; the document's `issuer` member names the same
    authority without it. The spellings differ by one character and the document is
    refused whole — the pin is exact, and a normalized comparison would let either
    spelling stand for the other.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_issuer=TRAILING_SLASH_ISSUER,
        discovery_answer=httpx.Response(200, json=discovery_document(issuer=ISSUER)),
    ) as (client, _router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())

    assert response.status_code == HTTPStatus.BAD_GATEWAY, response.text
    assert "names another issuer" in response.text


def test_a_token_issuer_missing_only_the_slash_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The same exact pin at verification: a token whose `iss` lacks the slash is refused.

    The discovery document carries the configured trailing slash and validates; the
    exchange's token names the same authority without it, and verification refuses it —
    the pin is the configured spelling at both comparison sites, and the sign-in fails
    closed rather than accepting the near-miss issuer.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_issuer=TRAILING_SLASH_ISSUER,
        discovery_answer=httpx.Response(
            200, json=discovery_document(issuer=TRAILING_SLASH_ISSUER)
        ),
    ) as (client, _router, _discovery_route):
        # The token route's default answer carries the issuer without the slash — the
        # near-miss spelling.
        flow_id = start_flow(client)
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
    assert "could not be verified" in response.text


# ------------------------------------ the pinned algorithm and the pinned key material


def _raw_jwt(header: dict[str, Any], claims: dict[str, Any]) -> str:
    """A JWT assembled from a header and a payload, with an empty signature.

    Built by hand rather than through `jwt.encode` because the scenarios here present
    headers PyJWT will not mint through its high-level API — `alg: none` above all — and
    the gateway's refusal has to be exercised on the token a hostile issuer would actually
    send, not on the encoder's own guard.
    """

    def segment(document: dict[str, Any]) -> str:
        raw = json.dumps(document, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{segment(header)}.{segment(claims)}."


def test_an_alg_none_token_is_refused_by_the_pinned_algorithm(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The algorithm is never taken from the token: `alg: none` cannot sign.

    A token whose header reads `alg: none` asks the verifier to accept an unsigned
    payload. The pinned algorithm is the leg's own, so the header's choice is never
    consulted and the exchange refuses the token rather than reading claims from it.
    """
    now = int(time.time())
    unsigned = _raw_jwt(
        {"alg": "none", "typ": "JWT", "kid": "the-provider-key"},
        {"iss": ISSUER, "sub": SUBJECT, "iat": now, "exp": now + 300},
    )

    with a_gateway(private_key_pem, tmp_path, idp) as (
        client,
        router,
        _discovery_route,
    ):
        flow_id = start_flow(client)
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": unsigned, "token_type": "Bearer"},
            )
        )
        response = idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
    assert "could not be verified" in response.text
    assert record is not None
    assert record.identity_claims is None


def test_an_embedded_jwk_in_the_header_is_ignored_and_the_token_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Header-carried key material is never used: the pinned key set alone verifies.

    The token is signed by a key foreign to the provider's published set and carries that
    key as a header `jwk`, the self-signed shape an attacker sends to make verification
    trust the header. The embedded material is never consulted — the signature is checked
    against the provider's published key only — so the token is refused.
    """
    embedded = Idp()
    headers = {
        "kid": "the-provider-key",
        "jwk": embedded.jwks["keys"][0],
    }
    forged = jwt.encode(
        {
            "iss": ISSUER,
            "sub": SUBJECT,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        embedded.pem,
        algorithm="RS256",
        headers=headers,
    )

    with a_gateway(private_key_pem, tmp_path, idp) as (
        client,
        router,
        _discovery_route,
    ):
        flow_id = start_flow(client)
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": forged, "token_type": "Bearer"},
            )
        )
        response = idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
    assert "could not be verified" in response.text
    assert record is not None
    assert record.identity_claims is None


def test_a_provider_token_kid_absent_from_the_published_set_is_refused(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A `kid` naming no key of the provider's own set is refused by the lookup.

    The token is otherwise well-formed and signed by the provider's real key, but its
    header names a `kid` the published key set does not hold. The key selection resolves
    inside that set alone, so the lookup fails and the token is refused as not issued by
    the provider — the literal absent-`kid` branch, distinct from a signature mismatch.
    """
    absent = "a-kid-the-provider-does-not-publish"
    token = jwt.encode(
        {
            "iss": ISSUER,
            "sub": SUBJECT,
            "iat": int(time.time()),
            "exp": int(time.time()) + 300,
        },
        idp.pem,
        algorithm="RS256",
        headers={"kid": absent},
    )

    with a_gateway(private_key_pem, tmp_path, idp) as (
        client,
        router,
        _discovery_route,
    ):
        flow_id = start_flow(client)
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={"access_token": token, "token_type": "Bearer"},
            )
        )
        response = idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST, response.text
    # The refusal is the lookup's own, not a signature mismatch: the key-id named no
    # key of the published set, so the token is refused as not issued by the provider.
    assert "no signing key matching" in response.text
    assert record is not None
    assert record.identity_claims is None


# ------------------------------------------------- direct mode: the configured trio


def test_the_full_trio_serves_all_four_legs_and_skips_discovery_entirely(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Where the trio is configured, no discovery fetch is attempted at all.

    Skipped, not fetched-and-ignored: the discovery route is installed and armed here,
    and a single call would fail the count. All four legs run on the configured
    endpoints, so one configuration decides the whole leg's source.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_authorization_endpoint=AUTHORIZATION_ENDPOINT,
        idp_token_endpoint=TOKEN_ENDPOINT,
        idp_jwks_uri=JWKS_URI,
    ) as (client, router, discovery_route):
        flow_id = start_flow(client)
        code = complete_flow(client, flow_id)
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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text
        refreshed = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == HTTPStatus.OK, refreshed.text

        assert discovery_route is not None
        assert discovery_route.call_count == 0
        urls = urls_of(router)
        assert urls.count(TOKEN_ENDPOINT) == EXCHANGE_AND_REFRESH
        assert not any("well-known" in url for url in urls)


def test_the_override_readdresses_the_configured_server_to_server_calls_only(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The override's swap applies to the configured token and key-set legs alone.

    The configured authorization endpoint is browser-facing and stays untouched; the
    token endpoint and key-set URI are re-addressed to the override's origin with their
    configured paths kept; and the issuer check is unaffected — the exchange completes
    against the pinned issuer.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_authorization_endpoint=AUTHORIZATION_ENDPOINT,
        idp_token_endpoint=TOKEN_ENDPOINT,
        idp_jwks_uri=JWKS_URI,
        idp_backchannel_base_url=BACKCHANNEL_BASE_URL,
        install_discovery_route=False,
    ) as (client, router, _discovery_route):
        flow_id = start_flow(client)
        code = complete_flow(client, flow_id)

        internal_token = f"{BACKCHANNEL_BASE_URL}/oauth2/token"
        internal_jwks = f"{BACKCHANNEL_BASE_URL}/oauth2/keys"

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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text
        refreshed = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == HTTPStatus.OK, refreshed.text

        urls = urls_of(router)

    assert urls.count(internal_token) == EXCHANGE_AND_REFRESH
    assert urls.count(internal_jwks) >= 1
    # The redirect kept the configured authorization endpoint at its own origin — the
    # `start_flow` assertion checked it — and no call went to the un-swapped spellings.
    assert not any(u in (TOKEN_ENDPOINT, JWKS_URI) for u in urls)


def test_a_stale_configured_endpoint_fails_the_leg_closed(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A moved endpoint is the mode's priced trade: the leg fails, and fails alone.

    The provider has moved its token endpoint since the operator configured it; the leg
    fails closed with the fixed-vocabulary error, no token is minted, and no fallback —
    no discovery fetch, no construction from the issuer — is attempted.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_authorization_endpoint=AUTHORIZATION_ENDPOINT,
        idp_token_endpoint=TOKEN_ENDPOINT,
        idp_jwks_uri=JWKS_URI,
    ) as (client, router, discovery_route):
        flow_id = start_flow(client)
        # The provider has moved its token endpoint: the configured one is unreachable.
        router.post(TOKEN_ENDPOINT).mock(
            side_effect=httpx.ConnectError("the provider moved this endpoint")
        )
        # The exchange cannot reach the stale endpoint: the callback fails the leg.
        response = idp_callback(client, flow_id)
        record = runtime_of(client).flows.get(flow_id)
        assert response.status_code == HTTPStatus.BAD_GATEWAY
        assert "token endpoint could not be reached" in response.text
        assert record is not None
        assert record.identity_claims is None
        assert discovery_route is not None
        # No fallback: not even the discovery document was fetched to repair the leg, and
        # no other endpoint was addressed — the stale one is the only call the leg made.
        assert discovery_route.call_count == 0
        assert not [u for u in urls_of(router) if "well-known" in u]


def test_the_varying_issuer_refusal_holds_in_direct_mode(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """Issuer pinning is unaffected by the endpoint source: the pin is on the issuer.

    A directly configured endpoint set is operator input, and nothing about it widens the
    exact-string `iss` check — a sibling journey's token is refused here exactly as it is
    in discovery mode.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_authorization_endpoint=AUTHORIZATION_ENDPOINT,
        idp_token_endpoint=TOKEN_ENDPOINT,
        idp_jwks_uri=JWKS_URI,
        install_discovery_route=False,
    ) as (client, router, _discovery_route):
        flow_id = start_flow(client)
        router.post(TOKEN_ENDPOINT).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": idp.token(iss=OTHER_JOURNEY_ISSUER),
                    "refresh_token": PROVIDER_REFRESH_TOKEN,
                    "token_type": "Bearer",
                },
            )
        )
        response = idp_callback(client, flow_id)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "could not be verified" in response.text


# ------------------------- the confidential client and the PKCE toggle (tasks 4.1/4.2)
#
# The leg's client is confidential in both toggle positions, pinned on the requests the
# leg actually sends: with the challenge off the redirect carries no challenge, the
# exchange presents no verifier, and both token requests authenticate with the secret;
# with the challenge on (the default) the challenge composes with the secret — both
# bindings on the same requests, pinned byte for byte.

# The deployment's client secret in the mode tests. A distinctive value so the
# secret-never-outside-the-token-leg sweep cannot pass on a coincidence.
CLIENT_SECRET = "the-confidential-client-secret-value"

# The client id the settings default to — the client the token requests name.
GATEWAY_CLIENT_ID = "dial-mcp-proxy"

# The identity leg's redirect URI, derived the way the client derives it: the gateway's
# public origin plus the callback path.
IDP_REDIRECT_URI = f"{ORIGIN}/dial/callback/idp"


def token_request_bodies(router: respx.Router, url: str) -> list[bytes]:
    """The bodies of the POSTs the leg sent to the named URL, in order."""
    return [
        call.request.content
        for call in router.calls
        if call.request.url == url and call.request.method == "POST"
    ]


def test_the_challenge_off_redirect_carries_no_challenge_and_the_token_requests_authenticate_with_the_secret(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The challenge-off mode's shape, asserted on the leg's actual requests.

    The authorization redirect carries the client's other parameters and no
    `code_challenge` or `code_challenge_method`; the exchange presents the secret and no
    verifier (no challenge was issued, so there is none to present); the refresh grant
    authenticates with the secret too — the client's authentication on both token
    requests, which the challenge-on mode carries as well.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_pkce_enabled=False,
        idp_client_secret=SecretStr(CLIENT_SECRET),
    ) as (client, router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())
        assert response.status_code == HTTPStatus.FOUND, response.text
        redirect_query = parse_qs(urlparse(response.headers["location"]).query)
        assert "code_challenge" not in redirect_query
        assert "code_challenge_method" not in redirect_query
        assert redirect_query["response_type"] == ["code"]
        assert redirect_query["client_id"] == [GATEWAY_CLIENT_ID]
        assert redirect_query["redirect_uri"] == [IDP_REDIRECT_URI]
        assert "state" in redirect_query

        flow_id = redirect_query["state"][0]
        code = complete_flow(client, flow_id)
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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text
        refreshed = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == HTTPStatus.OK, refreshed.text

        bodies = token_request_bodies(router, TOKEN_ENDPOINT)

    assert len(bodies) == EXCHANGE_AND_REFRESH
    exchange, refresh = (parse_qs(body.decode()) for body in bodies)
    assert exchange["grant_type"] == ["authorization_code"]
    assert exchange["client_secret"] == [CLIENT_SECRET]
    assert "code_verifier" not in exchange
    assert refresh["grant_type"] == ["refresh_token"]
    assert refresh["client_secret"] == [CLIENT_SECRET]


def test_the_default_mode_presents_the_client_secret_under_the_challenge(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The default mode's requests, pinned byte for byte — the secret included.

    The delta spec's inverted property: with PKCE enabled (the default) and the secret
    configured, both bindings ride together — the redirect carries the S256 challenge,
    and the exchange and the refresh grant each authenticate with the secret. "Byte for
    byte" is the assertion's shape: each request's raw body must equal an expected body
    spelled here in the leg's own member order, the `client_secret` member where the
    client authentication is appended (the exchange's last member, after the verifier;
    the refresh grant's last, after the client id). A missing secret member, an extra
    one, any reorder, any re-encoding fails the equality; the challenge parameters are
    pinned on the redirect alongside.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_client_secret=SecretStr(CLIENT_SECRET),
    ) as (client, router, _discovery_route):
        response = client.get("/dial/authorize", params=authorize_params())
        assert response.status_code == HTTPStatus.FOUND, response.text
        redirect_url = response.headers["location"]
        flow_id = parse_qs(urlparse(redirect_url).query)["state"][0]
        verifier = runtime_of(client).flows.get(flow_id)
        assert verifier is not None
        code = complete_flow(client, flow_id)
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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text
        refreshed = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == HTTPStatus.OK, refreshed.text

        bodies = token_request_bodies(router, TOKEN_ENDPOINT)

    # The redirect: the challenge-on query, byte for byte.
    expected_query = urlencode(
        {
            "response_type": "code",
            "client_id": GATEWAY_CLIENT_ID,
            "redirect_uri": IDP_REDIRECT_URI,
            "scope": "profile email",
            "state": flow_id,
            "code_challenge": code_challenge_for(verifier.idp_code_verifier),
            "code_challenge_method": "S256",
        }
    )
    assert redirect_url == f"{AUTHORIZATION_ENDPOINT}?{expected_query}"

    # The exchange and the refresh grant: both bindings on, the secret the form's last
    # member in each — the client authentication under the challenge.
    expected_exchange = urlencode(
        {
            "grant_type": "authorization_code",
            "code": "the-provider-code",
            "redirect_uri": IDP_REDIRECT_URI,
            "client_id": GATEWAY_CLIENT_ID,
            "code_verifier": verifier.idp_code_verifier,
            "client_secret": CLIENT_SECRET,
        }
    )
    expected_refresh = urlencode(
        {
            "grant_type": "refresh_token",
            "refresh_token": PROVIDER_REFRESH_TOKEN,
            "client_id": GATEWAY_CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        }
    )
    assert len(bodies) == EXCHANGE_AND_REFRESH
    assert bodies[0] == expected_exchange.encode()
    assert bodies[1] == expected_refresh.encode()


def test_a_harness_authorization_request_without_pkce_is_still_refused_in_the_challenge_off_mode(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The client-facing surface keeps requiring PKCE, whatever the identity-leg mode.

    The challenge-off mode is the identity leg's alone: the gateway's own authorization
    endpoint refuses a harness request without a challenge exactly as it does in the
    default mode —
    `tests/test_authorize.py::test_a_missing_code_challenge_is_redirected_to_the_client`
    pins the same refusal on the default mode's client.
    """
    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_pkce_enabled=False,
        idp_client_secret=SecretStr(CLIENT_SECRET),
    ) as (client, _router, _discovery_route):
        params = authorize_params()
        del params["code_challenge"]

        response = client.get("/dial/authorize", params=params)

    assert response.status_code == HTTPStatus.FOUND
    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)
    assert parse_qs(urlparse(response.headers["location"]).query)["error"] == [
        "invalid_request"
    ]


@pytest.mark.parametrize("pkce_enabled", [True, False])
def test_the_client_secret_appears_only_in_the_token_request_bodies(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
    pkce_enabled: bool,
) -> None:
    """The secret reaches the provider's token endpoint and nothing else.

    With the secret planted and both of the leg's outcomes exercised — an exchange that
    succeeds, and one the provider refuses — every log record (the audit trail included),
    every error page, and every response the gateway emits is swept for the secret's
    bytes, in either toggle position. A provider refusal naming the client is recorded by
    its fixed-vocabulary class ("the identity provider refused the code exchange (400)"),
    never by the credential it refused.
    """
    caplog.set_level(logging.DEBUG)
    caplog.set_level(logging.DEBUG, logger="gateway.audit")
    emitted: list[str] = []

    with a_gateway(
        private_key_pem,
        tmp_path,
        idp,
        idp_pkce_enabled=pkce_enabled,
        idp_client_secret=SecretStr(CLIENT_SECRET),
    ) as (client, router, _discovery_route):
        # A sign-in that succeeds end to end, refresh grant included: the secret rode
        # both token requests, and must appear in nothing the gateway emitted.
        flow_id = start_flow(client)
        code = complete_flow(client, flow_id)
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
        assert redeemed.status_code == HTTPStatus.OK, redeemed.text
        refreshed = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": redeemed.json()["refresh_token"],
                "resource": RESOURCE,
            },
        )
        assert refreshed.status_code == HTTPStatus.OK, refreshed.text
        # And one the provider refuses: the error page is where a leaked credential
        # would surface to the browser.
        failed_flow = start_flow(client)
        router.post(TOKEN_ENDPOINT).mock(
            # The provider's fixed-vocabulary refusal class, not a credential material
            # string: the value is the OAuth error code `invalid_client`.
            return_value=httpx.Response(400, json={"error": "invalid_client"})
        )
        refused = idp_callback(client, failed_flow)
        assert refused.status_code == HTTPStatus.BAD_REQUEST, refused.text

        emitted.extend(
            record.getMessage() + (record.exc_text or "") for record in caplog.records
        )
        # The plant is real — the secret actually rode the token request — so the sweep
        # below cannot pass vacuously on a secret nothing used. What the sweep asserts is
        # that it stopped there: no output surface carries it onward.
        token_bodies = token_request_bodies(router, TOKEN_ENDPOINT)
        assert any(
            f"client_secret={CLIENT_SECRET}" in body.decode() for body in token_bodies
        )
        for tracked in (redeemed, refreshed, refused):
            emitted.append(tracked.text)
            emitted.extend(str(value) for value in tracked.headers.values())

    assert emitted, "the sweep captured nothing: the run itself failed"
    carrying = [text for text in emitted if CLIENT_SECRET in text]
    assert carrying == [], (
        f"the client secret reached {len(carrying)} emitted record(s)"
    )
    # The refused exchange's page names the refusal class, not the credential.
    assert "the identity provider refused the code exchange (400)" in refused.text


# --------------------------------------------- the cache lock and the event loop

# How long the in-flight fetch holds the cache lock, how often the loop-side heartbeat
# must still complete while it does, and the floor the heartbeat count must clear. The
# interval is a small fraction of the hold, so a loop parked on the lock — which would
# collect one or two beats at most before the fast path blocked it — could not pass the
# floor by accident.
LOCK_HOLD_SECONDS = 1.0
HEARTBEAT_INTERVAL_SECONDS = 0.05
HEARTBEAT_FLOOR = 6


@pytest.mark.anyio
async def test_a_fetch_in_flight_never_blocks_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A discovery fetch in flight delays only the legs waiting on it — never the loop.

    The fetch runs on a worker thread and holds the cache lock for its whole duration;
    every other request's leg takes a fast path that must read the cache without
    waiting on that lock. The instrument shares the loop the resolution runs on, which
    is what makes the property observable: one coroutine races the held fetch (a second
    sign-in arriving together), and beside it a heartbeat coroutine — the `/healthz`
    shape, a request touching nothing the identity leg touches — must keep completing
    while the lock is held. A fast path that acquired the lock blocking-style would park
    the loop on the fetch thread's lock for the rest of the hold, and the heartbeat
    would stop mid-hold; the floor says it did not.

    The two sign-ins run on separate loops, as two requests do; the heartbeat and the
    second resolution share one loop, as one process's requests do.
    """
    settings = surface_settings(idp_issuer=ISSUER, idp_backchannel_base_url=None)
    leg = idp_module.IdentityProviderClient(settings)

    fetch_entered = threading.Event()
    fetch_done = threading.Event()
    fetch_attempts = 0

    def fetch(_settings: object) -> dict[str, Any]:
        # The fetch in flight: entered under the lock, held for the while the test
        # measures against, then answered with a document the validation accepts.
        nonlocal fetch_attempts
        fetch_attempts += 1
        fetch_entered.set()
        time.sleep(LOCK_HOLD_SECONDS)
        fetch_done.set()
        return discovery_document()

    monkeypatch.setattr(idp_module, "_fetch_discovery_document", fetch)

    def first_sign_in() -> None:
        # A whole request's leg of its own, on its own loop — the caller whose fetch
        # holds the cache lock while it runs.
        asyncio.run(leg._endpoints())

    holder = threading.Thread(target=first_sign_in)
    holder.start()
    assert fetch_entered.wait(5), "the fetch never entered the outbound call"

    beats: list[float] = []

    async def heartbeat() -> None:
        # The /healthz shape: a coroutine on the shared loop that must keep completing
        # while the fetch is in flight, asking nothing of the identity leg.
        while not fetch_done.is_set():
            beats.append(time.monotonic())
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

    second_sign_in = asyncio.create_task(leg._endpoints())
    pulse = asyncio.create_task(heartbeat())
    await asyncio.to_thread(holder.join)
    await second_sign_in
    await pulse

    # The negative control first: the fetch ran once — the second sign-in waited out the
    # hold and shared it, it did not fetch again — so the floor below measures a
    # populated instrument.
    assert fetch_attempts == 1, (
        "the second sign-in fetched instead of sharing the fetch"
    )
    assert beats, "the heartbeat never ran: the instrument itself failed"
    assert len(beats) >= HEARTBEAT_FLOOR, (
        f"the loop completed only {len(beats)} heartbeats while the fetch held the "
        f"lock for {LOCK_HOLD_SECONDS}s: the fast path waited on the fetch's lock on "
        f"the event loop"
    )
