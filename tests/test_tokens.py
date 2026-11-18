"""Tests for the claim copy and the token lifecycle (tasks 4.4-4.5).

Every normative scenario of the claim-copy, token, and refresh requirements lives here,
and each is stated as the property it protects:

* the copy preserves what a deployment consumes — every claim, under its own name;
* the overlay is what makes the roles Core authorizes on, and the two ways it can go wrong
  are *different* failures, because a misconfigured path and a user with no roles are not
  the same fact;
* the audience is the binding Core verifies, and the refresh token is deliberately *not*
  Core-acceptable (no marker, no copied claims);
* a refresh re-reads the user's current claims from the identity provider's own refresh
  grant — the same carrier and verification path as issuance — and fails closed, with the
  three failure classes distinguishable on the trail, when the read cannot complete;
* rotation cannot extend the window, which is the whole staleness bound;
* the provider's session refresh token rides the gateway's own refresh token as an
  encrypted custody claim, and nowhere else a client can see.

Codes are minted through the gateway's own copy-and-overlay step, and the refresh tests
intercept the identity provider's token endpoint the way the flow reaches it, so a test
varies the behavior a real flow would produce rather than a fixture that agrees with it by
construction.
"""

from __future__ import annotations

import base64
import json
import logging
import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http import HTTPStatus
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from gateway.codes import CodeBindings, code_challenge_for, issue_code
from gateway.errors import INVALID_TARGET
from gateway.keys import SigningKey
from gateway.settings import Settings
from gateway.state import new_token_id
from gateway.token import (
    CLAIMS_READ_FAILED,
    CUSTODY_DECRYPT_FAILED,
    IDP_SESSION_ENDED,
    TokenRequestError,
)
from gateway.tokens import (
    CUSTODY_CLAIM_MEMBER,
    REFRESH_TOKEN_TYPE,
    IssuanceError,
    copied_claims,
    initial_refresh_expiry,
    mint_refresh_token,
    resolve_claim_path,
)

from tests.conftest import (
    APPS_NAME,
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    generate_key_pem,
    make_client,
    make_settings,
    runtime_of,
    surface_settings,
)

ORIGIN = "http://localhost:8090"
RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"

# The identity provider's endpoints, as the settings build them: the browser-facing issuer
# for the authorize leg, the internal base URL for the token and key-set calls.
REALM_ISSUER = "https://keycloak:8443/realms/dial"
REALM_TOKEN_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/token"
REALM_CERTS_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/certs"

VERIFIER = "a-verifier-for-the-token-lifecycle-tests"
CHALLENGE = code_challenge_for(VERIFIER)

SUBJECT = "3a0d60f4-0000-0000-0000-000000000000"

# The provider's session-bound refresh token, as the flow captures it. The custody tests
# below vary it; the lifecycle tests only need one to be present.
PROVIDER_REFRESH_TOKEN = "the-provider-session-refresh-token"

# The provider's *latest* refresh token, as a rotating provider returns it from a grant.
NEW_PROVIDER_REFRESH_TOKEN = "the-providers-newest-session-refresh-token"

# How many refreshes the non-sliding chain test walks through, so the distinctness check
# below names the number it is asserting rather than a bare literal.
ROTATION_CHAIN_LENGTH = 3

# The distinct failure classes the four-way burst test expects to see on the trail.
DISTINCT_FAILURE_CLASSES = 2

# A claim set shaped like a real deployment's: the fields Core reads, and fields only
# telemetry would ever see — which is the point of copying the whole payload.
CLAIMS: dict[str, Any] = {
    "roles": ["admin"],
    "project": "proj-alpha",
    "email": "dial@example.test",
    "preferred_username": "dial",
    "user-projects": ["proj-alpha", "proj-beta"],
    "resource_access": {"dial-cli": {"roles": ["admin"]}},
    "realm_access": {"roles": ["offline_access"]},
}


def _b64_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class Idp:
    """A generated identity-provider keypair, and the tokens it mints for a refresh.

    The refresh grant's fresh token is verified against the provider's published keys, so a
    test that wants a verifiable fresh token needs a key pair the gateway will fetch a JWKS
    for — the same path issuance's exchange uses.
    """

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

    def token(
        self,
        *,
        pem: str | None = None,
        omit: tuple[str, ...] = (),
        **overrides: Any,
    ) -> str:
        """A provider token carrying the given claims, verifiable against this key set.

        `omit` removes claims from the default set, so a test can produce a fresh token that
        *lacks* a claim the roles path names — the shape a misconfigured provider mints.
        """
        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": REALM_ISSUER,
            "aud": "dial-chat",
            "iat": now,
            "exp": now + 300,
            "sub": SUBJECT,
            **CLAIMS,
        }
        claims.update(overrides)
        for name in omit:
            claims.pop(name, None)
        return jwt.encode(
            claims, pem or self.pem, algorithm="RS256", headers={"kid": "the-idp-key"}
        )

    def refresh_response(
        self,
        *,
        pem: str | None = None,
        new_refresh_token: str | None = None,
        **overrides: Any,
    ) -> httpx.Response:
        """The token-endpoint answer to a refresh grant: a fresh, verifiable access token.

        `new_refresh_token` is optional because RFC 6749 §6 makes the response's
        `refresh_token` optional: where the provider rotates its own token it is present, and
        where it does not it is absent and the gateway keeps the one it presented.
        """
        document: dict[str, Any] = {
            "access_token": self.token(pem=pem, **overrides),
            "token_type": "Bearer",
        }
        if new_refresh_token is not None:
            document["refresh_token"] = new_refresh_token
        return httpx.Response(200, json=document)


class Stack:
    """A running gateway, its settings, and the provider and Core it reaches.

    The pieces travel together because a code has to be minted for the *same* configuration
    the app runs with: a test that varied the roles path on one side only would be measuring
    its own fixture. The provider's key set and token endpoint are intercepted here, so the
    refresh grant's outbound leg runs against a stub the test steers per call — the same
    shape a real leg takes.
    """

    def __init__(
        self,
        client: TestClient,
        settings: Settings,
        signing_key: SigningKey,
        idp: Idp,
        router: respx.Router,
    ):
        self.client = client
        self.settings = settings
        self.signing_key = signing_key
        self.idp = idp
        self.router = router

    def issue(
        self,
        *,
        identity_claims: dict[str, Any] | None = None,
        subject: str = SUBJECT,
        provider_refresh_token: str | None = PROVIDER_REFRESH_TOKEN,
    ) -> str:
        """Mint a code the way a flow issues one, seeding the pending custody entry.

        The code's id keys the pending hand-off entry, exactly as `_finish` does it, so the
        redemption seals the provider token into the refresh token's custody claim.
        """
        claims = copied_claims(identity_claims or dict(CLAIMS), self.settings)
        code_id = new_token_id()
        if provider_refresh_token is not None:
            runtime_of(self.client).pending_custody.put(code_id, provider_refresh_token)
        return issue_code(
            self.signing_key,
            CodeBindings(
                client_id=PRE_REGISTERED_CLIENT_ID,
                redirect_uri=LOOPBACK_REDIRECT_URI,
                code_challenge=CHALLENGE,
                code_challenge_method="S256",
                resource=RESOURCE,
                toolset=TOOLSET_NAME,
                subject=subject,
                claims=claims,
            ),
            issuer=ORIGIN,
            ttl_seconds=300,
            code_id=code_id,
        )

    def redeem(self, code: str, **overrides: str) -> Any:
        params = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": LOOPBACK_REDIRECT_URI,
            "client_id": PRE_REGISTERED_CLIENT_ID,
            "code_verifier": VERIFIER,
            "resource": RESOURCE,
        }
        params.update(overrides)
        return self.client.post("/dial/token", data=params)

    def tokens(
        self, *, identity_claims: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """A freshly issued access and refresh token, the refresh token carrying custody."""
        response = self.redeem(self.issue(identity_claims=identity_claims))
        assert response.status_code == HTTPStatus.OK, response.text
        body: dict[str, Any] = response.json()
        return body

    def refresh(self, token: str, **overrides: str) -> Any:
        params = {
            "grant_type": "refresh_token",
            "refresh_token": token,
            "resource": RESOURCE,
        }
        params.update(overrides)
        return self.client.post("/dial/token", data=params)

    def provider_answers(self, response: httpx.Response) -> None:
        """Steer the next refresh grant's answer from the provider's token endpoint."""
        self.router.post(REALM_TOKEN_URL).mock(return_value=response)

    def claims_of(self, token: str) -> dict[str, Any]:
        """Decode a token this gateway minted, as a verifier would."""
        payload: dict[str, Any] = jwt.decode(
            token,
            self.signing_key.public_key(),
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
        return payload


@pytest.fixture
def idp() -> Idp:
    """An identity-provider keypair generated per test, so verification is exercised."""
    return Idp()


def _refusal_reasons(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The `flow_refused` reasons a run emitted, in order."""
    return [
        json.loads(record.getMessage())["reason"]
        for record in caplog.records
        if record.name == "gateway.audit"
        and json.loads(record.getMessage())["event"] == "flow_refused"
    ]


def _another_custody_key() -> str:
    """A base64 32-byte custody key, distinct from the suite's own."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


def _resign_refresh_token(stack: Stack, payload: dict[str, Any]) -> str:
    """Re-sign a refresh token's payload with the stack's key, for the forged-claim tests.

    The tests that exercise the custody seam need a token whose *signature* is valid (so the
    grant reaches the seam) and whose *claim* is the value under test. Signing through the
    real key is what makes the seam, and not the signature check, the thing measured.
    """
    return stack.signing_key.sign(dict(payload))


@pytest.fixture
def stack(private_key_pem: str, tmp_path: Path, idp: Idp) -> Any:
    """Builds a gateway (and its settings) per call, over a store of its own."""

    @contextmanager
    def open_stack(**overrides: object) -> Iterator[Stack]:
        settings = surface_settings(
            dcr_store_path=str(tmp_path / "store.json"), **overrides
        )
        with respx.mock(assert_all_called=False) as router:
            router.get(REALM_CERTS_URL).mock(
                return_value=httpx.Response(200, json=idp.jwks)
            )
            # The refresh grant's default answer: a fresh verifiable token, plus the provider's own
            # rotated refresh token (a rotating provider's shape). A test that wants another answer
            # steers it through `Stack.provider_answers`.
            router.post(REALM_TOKEN_URL).mock(
                return_value=idp.refresh_response(
                    new_refresh_token=NEW_PROVIDER_REFRESH_TOKEN
                )
            )
            with make_client(settings, private_key_pem) as client:
                yield Stack(client, settings, SigningKey(private_key_pem), idp, router)

    return open_stack


# ------------------------------------------------------------- the claim copy


def test_the_copy_preserves_every_claim_under_its_own_name(stack: Any) -> None:
    """The whole payload, minus the registry claims the gateway owns.

    Every claim a deployment consumes varies by deployment, and Core forwards the whole
    payload to telemetry and matches authorization rules on arbitrary claim paths — so an
    allowlist copy would be authorization policy expressed as configuration, whose failure
    mode is silent.
    """
    with stack() as s:
        payload = s.claims_of(s.tokens()["access_token"])

    for name, value in CLAIMS.items():
        assert payload[name] == value
    assert payload["preferred_username"] == "dial"
    assert payload["user-projects"] == ["proj-alpha", "proj-beta"]
    assert payload["realm_access"] == {"roles": ["offline_access"]}


def test_the_copy_drops_the_registry_claims_the_gateway_owns(stack: Any) -> None:
    """The claims that describe the *provider's* token must not describe this one.

    A copied `iss`, `aud`, or `exp` would state something false about the new token, and a
    copied `typ` or `jti` would collide with a field the new token has to set itself.
    """
    with stack() as s:
        payload = s.claims_of(s.tokens()["access_token"])

    assert payload["iss"] == ORIGIN
    assert payload["aud"] == [RESOURCE, "dial-mcp-proxy"]
    assert payload["typ"] == "access"
    assert payload["exp"] > time.time()
    assert payload.get("sid") is None
    assert payload.get("azp") is None


def test_the_copy_carries_the_providers_session_claims_nowhere(stack: Any) -> None:
    """Session-bound claims stay with the session they describe.

    The gateway's tokens outlive the provider session they were derived from, so carrying
    its `sid` or `session_state` would make a token claim a session it is not part of.
    """
    with stack() as s:
        payload = s.claims_of(
            s.tokens(
                identity_claims={
                    **CLAIMS,
                    "sid": "the-provider-session",
                    "session_state": "abc",
                }
            )["access_token"]
        )

    assert "sid" not in payload
    assert "session_state" not in payload


def test_the_providers_auth_time_is_never_copied(stack: Any) -> None:
    """A provider-minted `auth_time` must not become a fact of a gateway token.

    The gateway is an OAuth 2.x server, not an OIDC provider: it never sees the provider's
    ID token and holds no authentication-time fact of its own, so a copied `auth_time` would
    state the provider's authentication event as if it were this token's. It is stripped
    like `acr` — the same false-claim class — at *both* claim-source sites: the code
    exchange at issuance and the refresh grant's fresh provider token. The minted token's
    own recency is its `iat`/`exp`.
    """
    provider_auth_time = 1_600_000_000

    with stack() as s:
        # Issuance: the identity answer the code exchange carries mints the access token.
        issued = s.tokens(identity_claims={**CLAIMS, "auth_time": provider_auth_time})
        issued_payload = s.claims_of(issued["access_token"])

        # Refresh: the fresh token the provider's refresh grant returns re-reads the claims.
        s.provider_answers(s.idp.refresh_response(auth_time=provider_auth_time))
        refreshed = s.refresh(issued["refresh_token"])
        refreshed_payload = s.claims_of(refreshed.json()["access_token"])

    assert "auth_time" not in issued_payload
    assert "auth_time" not in refreshed_payload
    # The recency facts the mint actually knows are its own, not the provider's event.
    assert issued_payload["iat"] != provider_auth_time
    assert refreshed_payload["iat"] != provider_auth_time


def test_a_provider_answer_carrying_custody_plants_no_claim(stack: Any) -> None:
    """A provider answer cannot plant a custody member into any minted artifact.

    `custody` rides the refresh token alone, and the write side never puts one on any other
    artifact — but the inputs to the mint are the provider's answers, not the gateway's own
    choices, so both copy functions strip a member of that name as they strip the registry
    claims: `copied_claims` on the identity answer the refresh grant re-reads, and
    `claims_for_tokens` on a code payload that already carried one. Both are exercised here.
    """
    forged_custody = "a-forged-custody-member"

    with stack() as s:
        # The refresh path: the provider's fresh answer carries the member, and the access
        # token the refresh mints must not carry it.
        issued = s.tokens()
        s.provider_answers(
            s.idp.refresh_response(**{CUSTODY_CLAIM_MEMBER: forged_custody})
        )
        refreshed = s.refresh(issued["refresh_token"])

        # The code path: an identity answer that carried the member (copied_claims strips it
        # at issuance), and a code payload that carried one (claims_for_tokens strips it at
        # redemption) — the second built directly, as the defense it is, since the first
        # function would already have removed the member from a code this gateway issued.
        issued_code = s.issue(
            identity_claims={**CLAIMS, CUSTODY_CLAIM_MEMBER: forged_custody}
        )
        raw_code_id = new_token_id()
        raw_code = issue_code(
            s.signing_key,
            CodeBindings(
                client_id=PRE_REGISTERED_CLIENT_ID,
                redirect_uri=LOOPBACK_REDIRECT_URI,
                code_challenge=CHALLENGE,
                code_challenge_method="S256",
                resource=RESOURCE,
                toolset=TOOLSET_NAME,
                subject=SUBJECT,
                claims={
                    **copied_claims(dict(CLAIMS), s.settings),
                    CUSTODY_CLAIM_MEMBER: forged_custody,
                },
            ),
            issuer=ORIGIN,
            ttl_seconds=300,
            code_id=raw_code_id,
        )
        runtime_of(s.client).pending_custody.put(raw_code_id, PROVIDER_REFRESH_TOKEN)
        redeemed = s.redeem(raw_code)

    assert refreshed.status_code == HTTPStatus.OK, refreshed.text
    assert CUSTODY_CLAIM_MEMBER not in s.claims_of(refreshed.json()["access_token"])
    assert CUSTODY_CLAIM_MEMBER not in jwt.decode(
        issued_code, options={"verify_signature": False}
    )
    assert redeemed.status_code == HTTPStatus.OK, redeemed.text
    assert CUSTODY_CLAIM_MEMBER not in s.claims_of(redeemed.json()["access_token"])
    # The forged value never reaches any issued artifact.
    assert forged_custody not in issued_code
    assert forged_custody not in refreshed.text
    assert forged_custody not in redeemed.text


# --------------------------------------------------------- the roles overlay


def test_the_roles_overlay_re_emits_roles_at_the_configured_name(stack: Any) -> None:
    """The overlay is what makes the claim Core's provider entry reads exist."""
    with stack(roles_claim_name="dial_roles") as s:
        payload = s.claims_of(s.tokens()["access_token"])

    assert payload["dial_roles"] == ["admin"]
    # The copied `roles` claim is still there — it is a deployment claim — but it is not
    # what Core's provider entry reads under this configuration.
    assert payload["roles"] == ["admin"]


def test_the_roles_overlay_wins_over_a_copied_claim_of_the_same_name(
    stack: Any,
) -> None:
    """Overlay order is copy-first, overlay-second — so the overlay is the value.

    The identity token's own `roles` claim says one thing and the configured source path
    says another; what Core authorizes on is the second.
    """
    with stack(roles_source_path="realm_access.roles") as s:
        payload = s.claims_of(
            s.tokens(
                identity_claims={**CLAIMS, "roles": ["not-the-authoritative-roles"]}
            )["access_token"]
        )

    assert payload["roles"] == ["offline_access"]


def test_the_roles_path_may_be_a_nested_path(stack: Any) -> None:
    """A deployment whose roles live under a nested claim configures the path to them.

    This is the shape the design warns about: a token whose roles live at
    `resource_access.<client>.roles` and which has no top-level `roles` claim at all would
    yield a role-less token under a literal copy, and 403s with nothing in the logs.
    """
    without_top_level_roles = {
        name: value for name, value in CLAIMS.items() if name != "roles"
    }

    with stack(roles_source_path="resource_access.dial-cli.roles") as s:
        payload = s.claims_of(
            s.tokens(identity_claims=without_top_level_roles)["access_token"]
        )

    assert payload["roles"] == ["admin"]


def test_an_absent_roles_path_refuses_issuance_loudly() -> None:
    """A misconfigured path is a deployment error, and it must not be silent.

    The failure it replaces is undiagnosable: a role-less token produces a 403 the user
    cannot act on and the operator cannot explain. Issuing a token with no roles at all
    would be the silent version of the same misconfiguration, so issuance refuses — and it
    refuses before any credential is handed out, because the copy is made at issuance.
    """
    settings = make_settings(roles_source_path="a.path.this.token.does.not.have")

    with pytest.raises(IssuanceError) as refusal:
        copied_claims(dict(CLAIMS), settings)

    assert "a.path.this.token.does.not.have" in str(refusal.value)


def test_the_roles_path_refusal_is_an_operator_facing_one() -> None:
    """The message is written for the operator, because the operator can fix it.

    A user cannot act on a claims-configuration error, so the flow shows the generic page
    and records this detail — the flag is what makes that distinction possible.
    """
    settings = make_settings(roles_source_path="nope")

    with pytest.raises(IssuanceError) as refusal:
        copied_claims(dict(CLAIMS), settings)

    assert refusal.value.operator_facing is True


def test_a_roles_claim_of_the_wrong_shape_refuses_issuance() -> None:
    """Roles must be strings; a mapping or a number is a fact this cannot use."""
    settings = make_settings(roles_source_path="roles")

    with pytest.raises(IssuanceError):
        copied_claims({**CLAIMS, "roles": {"admin": True}}, settings)


def test_an_empty_roles_value_is_copied_as_an_empty_array(stack: Any) -> None:
    """An empty value is legitimate user state, not a configuration error.

    The distinction is the whole point of the two-part resolution: absent is a deployment
    error, empty is a user with no roles.
    """
    with stack() as s:
        payload = s.claims_of(
            s.tokens(identity_claims={**CLAIMS, "roles": []})["access_token"]
        )

    assert payload["roles"] == []


def test_an_explicitly_null_roles_value_is_an_empty_array(stack: Any) -> None:
    """A provider that mints `null` chose to mint it: present, and empty."""
    with stack() as s:
        payload = s.claims_of(
            s.tokens(identity_claims={**CLAIMS, "roles": None})["access_token"]
        )

    assert payload["roles"] == []


def test_a_single_valued_roles_claim_becomes_an_array(stack: Any) -> None:
    """Core's `rolePath` accepts a string or an array, and this gateway emits the array."""
    with stack() as s:
        payload = s.claims_of(
            s.tokens(identity_claims={**CLAIMS, "roles": "admin"})["access_token"]
        )

    assert payload["roles"] == ["admin"]


def test_an_empty_string_roles_claim_is_no_roles(stack: Any) -> None:
    """An empty string is the provider's own spelling of the same fact as an empty list."""
    with stack() as s:
        payload = s.claims_of(
            s.tokens(identity_claims={**CLAIMS, "roles": ""})["access_token"]
        )

    assert payload["roles"] == []


def test_the_claim_path_resolution_distinguishes_absent_from_empty() -> None:
    """The two-part answer is what the loud-versus-quiet rule is built on.

    Asserted directly because it is the mechanism two scenarios above depend on, and a
    refactor that made absent and empty the same value would break them silently.
    """
    assert resolve_claim_path({"roles": []}, "roles") == (True, [])
    assert resolve_claim_path({"roles": None}, "roles") == (True, None)
    assert resolve_claim_path({}, "roles") == (False, None)
    assert resolve_claim_path({"a": "not-a-mapping"}, "a.b") == (False, None)


# ---------------------------------------------------------------- the audience


def test_the_access_token_carries_the_resource_and_the_marker(stack: Any) -> None:
    """Both, because they answer different questions.

    The resource is what the token is for; the marker is what makes Core's provider entry
    accept a gateway-issued token and reject anything else presenting this issuer.
    """
    with stack() as s:
        payload = s.claims_of(s.tokens()["access_token"])

    assert payload["aud"] == [RESOURCE, "dial-mcp-proxy"]


def test_the_marker_is_configurable(stack: Any) -> None:
    """The marker is a deployment's choice, mirrored from Core's provider entry."""
    with stack(gateway_audience_marker="another-marker") as s:
        payload = s.claims_of(s.tokens()["access_token"])

    assert payload["aud"] == [RESOURCE, "another-marker"]


# -------------------------------------------------------------- the refresh mint


def test_the_refresh_token_carries_no_claim_snapshot(stack: Any) -> None:
    """The refresh token's payload is session bindings plus the one custody member.

    No `roles`, no deployment claim — nothing copied from the identity token. That is what
    makes the frozen-snapshot fallback structurally impossible: there is no snapshot to
    serve, so a claims-read failure at refresh cannot silently fall back to one.
    """
    with stack() as s:
        payload = s.claims_of(s.tokens()["refresh_token"])

    for name in CLAIMS:
        assert name not in payload, name
    assert "preferred_username" not in payload
    # The members that are present are the session bindings and the custody member alone.
    assert set(payload) == {
        "iss",
        "sub",
        "aud",
        "typ",
        "jti",
        "iat",
        "exp",
        "client_id",
        "resource",
        CUSTODY_CLAIM_MEMBER,
    }


def test_the_refresh_token_audience_is_the_resource_alone(stack: Any) -> None:
    """The token-type separation, pinned: the marker is on the access token, never here.

    The marker is what makes a gateway-issued token a Core-acceptable access token, so its
    absence is what keeps the refresh token from ever being one.
    """
    with stack() as s:
        body = s.tokens()
        access = s.claims_of(body["access_token"])["aud"]
        refresh = s.claims_of(body["refresh_token"])["aud"]

    assert access == [RESOURCE, "dial-mcp-proxy"]
    assert refresh == [RESOURCE]


def test_the_refresh_token_is_not_a_core_acceptable_token(stack: Any) -> None:
    """The negative control: the same shape Core applies refuses the refresh token.

    Core's identity-provider entry verifies the signature, the issuer, and the audience
    marker. The refresh token passes the first two and fails the third — and with no copied
    claims aboard it authorizes nothing at role-path matching even absent the marker check.
    """
    with stack() as s:
        refresh = s.tokens()["refresh_token"]

    # Core's check: signature, issuer, and the marker among the audiences.
    payload = jwt.decode(
        refresh,
        s.signing_key.public_key(),
        algorithms=["RS256"],
        issuer=ORIGIN,
        options={"verify_aud": False},
    )
    marker = s.settings.gateway_audience_marker
    assert payload["iss"] == ORIGIN
    assert marker not in payload["aud"]
    with pytest.raises(jwt.exceptions.InvalidAudienceError):
        jwt.decode(
            refresh,
            s.signing_key.public_key(),
            algorithms=["RS256"],
            issuer=ORIGIN,
            audience=marker,
        )


def test_a_refresh_token_is_typed_and_carries_its_resource(stack: Any) -> None:
    """The type keeps a refresh token from being used where an access token belongs."""
    with stack() as s:
        payload = s.claims_of(s.tokens()["refresh_token"])

    assert payload["typ"] == REFRESH_TOKEN_TYPE
    assert payload["resource"] == RESOURCE
    assert payload["jti"]


def test_a_resource_mismatch_on_refresh_is_invalid_target(stack: Any) -> None:
    """A refresh must name its toolset, and it must be the one it was minted for.

    The answer is `invalid_target`, matching the code grant's resource-mismatch analogue:
    the request does not name this token's toolset, so it is a target problem, not a
    grant problem.
    """
    with stack() as s:
        body = s.tokens()
        mismatched = s.refresh(
            body["refresh_token"], resource=f"{ORIGIN}/dial/other/mcp"
        )
        missing = s.refresh(body["refresh_token"], resource="")

    assert mismatched.json()["error"] == "invalid_target"
    assert missing.json()["error"] == "invalid_target"


# ------------------------------------------------------ the claims re-read at refresh


def test_a_refresh_re_reads_the_claims_from_the_provider(stack: Any) -> None:
    """The refreshed access token's claims come from the fresh provider token, not a snapshot.

    The provider answers the grant with a token whose roles differ from the ones at issuance;
    the minted access token carries the *fresh* roles, which is the whole point of the
    mechanism — a claim change reaches minted tokens within the access TTL.
    """
    with stack() as s:
        body = s.tokens()
        s.provider_answers(s.idp.refresh_response(roles=["changed-at-the-provider"]))
        refreshed = s.refresh(body["refresh_token"]).json()

        claims = s.claims_of(refreshed["access_token"])

    assert claims["roles"] == ["changed-at-the-provider"]
    # Every other copied claim comes from the fresh token too.
    for name, value in CLAIMS.items():
        if name != "roles":
            assert claims[name] == value
    assert claims["sub"] == SUBJECT
    assert claims["aud"] == [RESOURCE, "dial-mcp-proxy"]


def test_a_refresh_contacts_the_identity_provider(stack: Any) -> None:
    """The mechanism's whole premise: refresh performs one outbound identity-provider call.

    The call is the RFC 6749 §6 refresh grant against the token endpoint the exchange uses,
    carrying the recovered provider refresh token — so it is both observed and inspected.
    """
    seen: list[str] = []

    with stack() as s:
        body = s.tokens()

        def capture(request: httpx.Request) -> httpx.Response:
            seen.append(request.content.decode())
            answer: httpx.Response = s.idp.refresh_response()
            return answer

        s.router.post(REALM_TOKEN_URL).mock(side_effect=capture)
        response = s.refresh(body["refresh_token"])

    assert response.status_code == HTTPStatus.OK
    assert seen, (
        "a refresh must present the provider refresh token to the token endpoint"
    )
    assert "grant_type=refresh_token" in seen[0]
    assert PROVIDER_REFRESH_TOKEN in seen[0]


def test_the_refresh_grant_authenticates_with_the_client_secret(stack: Any) -> None:
    """The refresh grant authenticates the confidential client with the secret.

    The secret authenticates every identity-leg token request, in both toggle positions —
    the grant included. Asserted on the captured request with a secret planted: the
    form carries the `client_secret` member beside the grant type and the recovered
    provider refresh token.
    """
    seen: list[str] = []

    with stack(idp_client_secret="a-configured-secret") as s:
        body = s.tokens()

        def capture(request: httpx.Request) -> httpx.Response:
            seen.append(request.content.decode())
            answer: httpx.Response = s.idp.refresh_response()
            return answer

        s.router.post(REALM_TOKEN_URL).mock(side_effect=capture)
        response = s.refresh(body["refresh_token"])

    assert response.status_code == HTTPStatus.OK
    assert seen
    assert "grant_type=refresh_token" in seen[0]
    assert "client_secret=a-configured-secret" in seen[0]


def test_a_silent_refresh_returns_a_fresh_access_token(stack: Any) -> None:
    """A refresh is silent to the harness: no browser, no upstream — one back-channel call."""
    with stack() as s:
        body = s.tokens()
        response = s.refresh(body["refresh_token"])

    assert response.status_code == HTTPStatus.OK
    assert response.json()["access_token"] != body["access_token"]


def test_no_request_field_can_steer_the_refresh_grant_url(stack: Any) -> None:
    """The leg goes to the configured token endpoint, whatever the request carries.

    The refresh grant posts to the same URL the exchange uses — derived from the configured
    internal base URL and the issuer's realm — and no request value reaches that
    construction. Asserted by aiming an evil-looking resource at the request and observing
    the gateway still calls the configured endpoint.
    """
    seen: list[str] = []

    with stack() as s:
        body = s.tokens()

        def capture(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            answer: httpx.Response = s.idp.refresh_response()
            return answer

        s.router.post(REALM_TOKEN_URL).mock(side_effect=capture)
        # A resource the guard lets through would be the steering vector if one existed; the
        # token's own resource is what the URL is never built from.
        s.refresh(body["refresh_token"])

    assert seen == [REALM_TOKEN_URL]


# ------------------------------------------------------- the refresh failure classes


def test_a_provider_session_ended_refusal_audits_the_session_token(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The provider's `invalid_grant` is the session-gone class, and only it.

    RFC 6749 §6's session-gone code means the session was revoked, expired, or consumed — a
    distinct operator signal from every other refresh failure.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        s.provider_answers(httpx.Response(400, json={"error": "invalid_grant"}))
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [IDP_SESSION_ENDED]


def test_a_provider_invalid_client_refusal_audits_the_claims_read_token(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A non-`invalid_grant` provider 4xx is a read failure, never a session end.

    `invalid_client` from a misconfigured client secret is the canonical case: a wrong secret
    answering every refresh must read as the misconfiguration it is, not as mass revocation.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        s.provider_answers(httpx.Response(401, json={"error": "invalid_client"}))
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CLAIMS_READ_FAILED]


@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(503, text="upstream down"),
        httpx.Response(200, text="not json at all"),
        httpx.Response(200, json={"token_type": "Bearer"}),  # no access token
    ],
)
def test_an_unusable_provider_answer_audits_the_claims_read_token(
    stack: Any, caplog: pytest.LogCaptureFixture, answer: httpx.Response
) -> None:
    """An outage, a non-JSON answer, and a missing token are one class: the read failed."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        s.provider_answers(answer)
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CLAIMS_READ_FAILED]


def test_an_unreachable_provider_audits_the_claims_read_token(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A transport failure is a read failure: the provider could not be reached at all."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        s.router.post(REALM_TOKEN_URL).mock(
            side_effect=httpx.ConnectError("unreachable")
        )
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CLAIMS_READ_FAILED]


def test_an_unverifiable_fresh_token_audits_the_claims_read_token(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A fresh token that fails verification is a read failure — no claim can be taken."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        s.provider_answers(s.idp.refresh_response(pem=generate_key_pem()))
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CLAIMS_READ_FAILED]


def test_a_fresh_token_subject_mismatch_refuses_the_refresh(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The subject cross-check binds every mint to the subject the provider just re-asserted.

    The refresh token's `sub` is this gateway's own signed claim, so no provider answer alone
    can move the mint to another principal.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        s.provider_answers(s.idp.refresh_response(sub="someone-else"))
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CLAIMS_READ_FAILED]


def test_a_roles_path_absent_from_the_fresh_token_refuses_the_refresh(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The roles path is required at refresh exactly as at issuance.

    A fresh token without the configured roles path would mint a role-less token, whose
    symptom is a 403 nothing explains — so the refresh refuses, with the read-failure class.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack(roles_source_path="realm_access.roles") as s:
        body = s.tokens()
        # The fresh token carries no `realm_access`: the configured path is absent.
        s.provider_answers(s.idp.refresh_response(omit=("realm_access",)))
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CLAIMS_READ_FAILED]


def test_the_custody_claim_absent_refuses_the_refresh(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A pre-change refresh token carries no custody claim, and fails closed on that class.

    This is the migration: a token minted before the gateway carried custody has no claim to
    present, so its next refresh refuses on the custody class and the user re-signs-in.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        # A refresh token with the session bindings but no custody member, signed by the real
        # mint (its `custody_claim` defaults to `None`).
        legacy = mint_refresh_token(
            s.signing_key,
            s.settings,
            subject=SUBJECT,
            resource=RESOURCE,
            client_id=PRE_REGISTERED_CLIENT_ID,
            expires_at=initial_refresh_expiry(s.settings),
        )
        response = s.refresh(legacy)

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CUSTODY_DECRYPT_FAILED]


def test_a_tampered_custody_claim_refuses_the_refresh(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A spliced or truncated envelope fails the AEAD tag and refuses on the custody class."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        payload = s.claims_of(s.tokens()["refresh_token"])
        claim = payload[CUSTODY_CLAIM_MEMBER]
        tampered = claim[:-4] + ("AAAA" if not claim.endswith("AAAA") else "BBBB")
        forged = _resign_refresh_token(s, payload | {CUSTODY_CLAIM_MEMBER: tampered})
        response = s.refresh(forged)

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CUSTODY_DECRYPT_FAILED]


def test_a_custody_claim_under_another_key_refuses_the_refresh(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """A hard-cut rotation supersedes a key, and every outstanding blob refuses under it.

    Handing the token a claim sealed under a different key is the shape a superseded key
    produces: the key id does not match the active one, so it refuses at the seam.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        other_key = make_settings(
            gateway_custody_keys={"other-key": _another_custody_key()}
        ).custody_key
        payload = s.claims_of(s.tokens()["refresh_token"])
        foreign = other_key.encrypt(
            subject=SUBJECT,
            expires_at=int(payload["exp"]),
            token=PROVIDER_REFRESH_TOKEN,
        )
        forged = _resign_refresh_token(s, payload | {CUSTODY_CLAIM_MEMBER: foreign})
        response = s.refresh(forged)

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CUSTODY_DECRYPT_FAILED]


def test_a_custody_claim_sealed_for_another_subject_refuses_the_refresh(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The embedded subject binds the blob to the token that carries it.

    A blob swapped between two users' refresh tokens decrypts perfectly, so the tag cannot
    catch it — the seam's subject check is what does.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        payload = s.claims_of(s.tokens()["refresh_token"])
        swapped = s.settings.custody_key.encrypt(
            subject="another-user",
            expires_at=int(payload["exp"]),
            token=PROVIDER_REFRESH_TOKEN,
        )
        forged = _resign_refresh_token(s, payload | {CUSTODY_CLAIM_MEMBER: swapped})
        response = s.refresh(forged)

    assert response.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [CUSTODY_DECRYPT_FAILED]


def test_an_expired_custody_envelope_refuses_the_refresh(stack: Any) -> None:
    """An envelope whose own `exp` has passed refuses at the seam.

    The envelope's expiry is the refresh token's own absolute expiry; a blob kept past it is
    refused before the provider is ever called.
    """
    with stack() as s:
        # The refresh token's own window is long, so the token decodes; the envelope is
        # sealed with an already-past expiry.
        payload = s.claims_of(s.tokens()["refresh_token"])
        expired = s.settings.custody_key.encrypt(
            subject=SUBJECT,
            expires_at=int(time.time()) - 1,
            token=PROVIDER_REFRESH_TOKEN,
        )
        forged = _resign_refresh_token(s, payload | {CUSTODY_CLAIM_MEMBER: expired})
        response = s.refresh(forged)

    assert response.json()["error"] == "invalid_grant"


def test_the_four_invalid_grant_bursts_are_mutually_distinguishable(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The four refresh failure classes audit under four distinct committed tokens.

    A custody fault, a provider outage, a session-policy break, and mass revocation must be
    four distinguishable bursts on the operator's trail.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        # Session ended.
        s.provider_answers(httpx.Response(400, json={"error": "invalid_grant"}))
        s.refresh(body["refresh_token"])
        # Claims read failed.
        s.provider_answers(httpx.Response(500, text="boom"))
        s.refresh(body["refresh_token"])
        # Custody failed.
        s.refresh("not-a-token")

    reasons = set(_refusal_reasons(caplog))
    assert {IDP_SESSION_ENDED, CLAIMS_READ_FAILED}.issubset(reasons)
    assert len(reasons) >= DISTINCT_FAILURE_CLASSES


# ------------------------------------------------------------------ the rotation


def test_rotation_is_on_by_default_and_returns_a_new_refresh_token(stack: Any) -> None:
    with stack() as s:
        body = s.tokens()
        rotated = s.refresh(body["refresh_token"]).json()

    assert rotated["refresh_token"]
    assert rotated["refresh_token"] != body["refresh_token"]


def test_a_rotated_refresh_token_keeps_the_original_absolute_expiry(stack: Any) -> None:
    """The non-sliding window, which is the entire bound.

    A rotated token that received a fresh `exp` would extend the carried window, and
    `refreshTtl` would stop bounding anything.
    """
    with stack() as s:
        body = s.tokens()
        original = s.claims_of(body["refresh_token"])
        rotated = s.claims_of(s.refresh(body["refresh_token"]).json()["refresh_token"])

    assert rotated["exp"] == original["exp"]
    assert rotated["jti"] != original["jti"]


def test_rotation_near_the_end_of_life_still_keeps_the_original_expiry(
    stack: Any,
) -> None:
    """Rotated late, the replacement still ends when the window ends — not later."""
    with stack(gateway_refresh_ttl_seconds=2) as s:
        body = s.tokens()
        original = s.claims_of(body["refresh_token"])
        rotated = s.claims_of(s.refresh(body["refresh_token"]).json()["refresh_token"])

    assert rotated["exp"] == original["exp"]


def test_every_rotation_keeps_the_same_absolute_expiry(stack: Any) -> None:
    """A chain of refreshes cannot walk the window forward one step at a time."""
    with stack(gateway_refresh_ttl_seconds=3600) as s:
        body = s.tokens()
        first = s.claims_of(body["refresh_token"])
        second_body = s.refresh(body["refresh_token"]).json()
        second = s.claims_of(second_body["refresh_token"])
        third_body = s.refresh(second_body["refresh_token"]).json()
        third = s.claims_of(third_body["refresh_token"])

    # Three distinct tokens — so the shared expiry below is a shared window, not a shared
    # token read three times.
    assert len({first["jti"], second["jti"], third["jti"]}) == ROTATION_CHAIN_LENGTH
    assert first["exp"] == second["exp"] == third["exp"]


def test_the_replacement_carries_the_providers_latest_refresh_token(stack: Any) -> None:
    """Latest-wins: where the provider rotates its own token, the replacement tracks it.

    The provider answers the grant with a new refresh token of its own; the gateway's rotated
    token must carry *that* one, re-encrypted, so the next refresh presents the live token.
    """
    with stack() as s:
        body = s.tokens()
        rotated = s.refresh(body["refresh_token"]).json()

        # The rotated gateway token's custody claim decrypts to the provider's latest token.
        rotated_claim = s.claims_of(rotated["refresh_token"])[CUSTODY_CLAIM_MEMBER]
        recovered = s.settings.custody_key.decrypt(rotated_claim, subject=SUBJECT)

    assert recovered == NEW_PROVIDER_REFRESH_TOKEN


def test_a_refresh_with_no_new_provider_token_keeps_the_carried_one(stack: Any) -> None:
    """Where the provider does not rotate, the carried token is re-sealed unchanged."""
    with stack() as s:
        body = s.tokens()
        # The provider's answer carries no new refresh token, so the carried one is kept.
        s.provider_answers(s.idp.refresh_response())
        rotated = s.refresh(body["refresh_token"]).json()
        rotated_claim = s.claims_of(rotated["refresh_token"])[CUSTODY_CLAIM_MEMBER]
        recovered = s.settings.custody_key.decrypt(rotated_claim, subject=SUBJECT)

    assert recovered == PROVIDER_REFRESH_TOKEN


def test_a_rotated_token_is_refused_after_its_grace_window(stack: Any) -> None:
    """Rotation is meaningful because the replaced token stops working."""
    with stack(gateway_rotation_grace_seconds=1) as s:
        body = s.tokens()
        first = s.refresh(body["refresh_token"])
        time.sleep(1.5)
        replay = s.refresh(body["refresh_token"])

    assert first.status_code == HTTPStatus.OK
    assert replay.json()["error"] == "invalid_grant"


def test_a_rotated_token_inside_its_grace_window_still_works(stack: Any) -> None:
    """A client that raced the rotation and lost is not logged out for losing.

    Its replacement carries the same original expiry, so serving the race cannot extend the
    window — which is why the grace window is safe to have at all.
    """
    with stack(gateway_rotation_grace_seconds=300) as s:
        body = s.tokens()
        first = s.refresh(body["refresh_token"])
        raced = s.refresh(body["refresh_token"])
        later = s.refresh(raced.json()["refresh_token"])

    assert first.status_code == HTTPStatus.OK
    assert raced.status_code == HTTPStatus.OK
    assert later.status_code == HTTPStatus.OK


def test_a_grace_window_presentation_carries_its_own_stale_blob(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The pre-rotation token's blob is stale, so the grace window cannot be a live session.

    The provider rotates its refresh token per grant (latest-wins), so after the first
    refresh the live provider token is the newest one. A client that lost the race and
    presents the pre-rotation gateway token inside the grace window still carries *its own*
    blob — the superseded provider token — and the provider refuses it. Each token is
    self-consistent, so the failure lands in the session-ended class, not the custody one.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack(gateway_rotation_grace_seconds=300) as s:
        body = s.tokens()
        first = s.refresh(body["refresh_token"])

        def rotating_provider(request: httpx.Request) -> httpx.Response:
            presented = parse_qs(request.content.decode())["refresh_token"][0]
            if presented == PROVIDER_REFRESH_TOKEN:
                # The superseded token: the provider has rotated past it per grant.
                return httpx.Response(400, json={"error": "invalid_grant"})
            answer: httpx.Response = s.idp.refresh_response(
                new_refresh_token=NEW_PROVIDER_REFRESH_TOKEN
            )
            return answer

        s.router.post(REALM_TOKEN_URL).mock(side_effect=rotating_provider)
        raced = s.refresh(body["refresh_token"])

    assert first.status_code == HTTPStatus.OK
    assert raced.json()["error"] == "invalid_grant"
    assert _refusal_reasons(caplog) == [IDP_SESSION_ENDED]


def test_rotation_can_be_switched_off(stack: Any) -> None:
    """The setting exists because rotation is a client-compatibility question, not a rule."""
    with stack(gateway_rotate_refresh_tokens=False) as s:
        body = s.tokens()
        refreshed = s.refresh(body["refresh_token"]).json()

    assert refreshed["refresh_token"] == body["refresh_token"]


def test_an_expired_refresh_token_is_invalid_grant(stack: Any) -> None:
    """Past the window the harness must re-run the sign-in — which is the bound working."""
    with stack(gateway_refresh_ttl_seconds=1) as s:
        body = s.tokens()
        time.sleep(1.5)
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"


def test_an_access_token_is_not_accepted_as_a_refresh_token(stack: Any) -> None:
    """All three kinds are signed by one key, so the type claim is what separates them."""
    with stack() as s:
        response = s.refresh(s.tokens()["access_token"])

    assert response.json()["error"] == "invalid_grant"


def test_a_foreign_signed_refresh_token_is_refused(stack: Any) -> None:
    """A token this gateway did not sign is not a token it will act on."""
    forged = jwt.encode(
        {
            "iss": ORIGIN,
            "sub": SUBJECT,
            "typ": REFRESH_TOKEN_TYPE,
            "jti": "forged",
            "exp": int(time.time()) + 600,
            "resource": RESOURCE,
            "client_id": PRE_REGISTERED_CLIENT_ID,
        },
        generate_key_pem(),
        algorithm="RS256",
    )

    with stack() as s:
        response = s.refresh(forged)

    assert response.json()["error"] == "invalid_grant"


def test_a_refresh_response_is_not_cacheable(stack: Any) -> None:
    with stack() as s:
        response = s.refresh(s.tokens()["refresh_token"])

    assert response.headers["cache-control"] == "no-store"


# ----------------------------------------------------------------- revocation


def test_a_revoked_refresh_token_is_refused(stack: Any) -> None:
    """Revocation is local: an id denylisted until the token would have expired."""
    with stack() as s:
        body = s.tokens()
        revoked = s.client.post("/dial/revoke", data={"token": body["refresh_token"]})
        response = s.refresh(body["refresh_token"])

    assert revoked.status_code == HTTPStatus.OK
    # RFC 7009 §2.2's answer, in the shape it specifies: 200 with no body at all. The
    # successful case has to carry the same empty body as the useless one, or the response
    # itself would distinguish a token that existed from one that did not.
    assert revoked.content == b""
    assert response.json()["error"] == "invalid_grant"


def test_revocation_survives_rotation_grace(stack: Any) -> None:
    """A revocation is not a rotation: it takes effect immediately, not after a grace."""
    with stack(gateway_rotation_grace_seconds=600) as s:
        body = s.tokens()
        s.client.post("/dial/revoke", data={"token": body["refresh_token"]})
        response = s.refresh(body["refresh_token"])

    assert response.json()["error"] == "invalid_grant"


def test_revoking_an_unknown_token_answers_the_same_way(stack: Any) -> None:
    """RFC 7009 §2.2: the answer must not reveal whether the token was real.

    Otherwise the endpoint is an oracle for whether a held token is live — which is exactly
    the question an attacker holding a stolen token would be asking. The answer is
    therefore an **empty** 200, and this test asserts on the bytes rather than on a status
    code alone: a body of any shape is a place a difference could be reported, and a body
    that happened to be equal today could stop being equal without the status changing.
    """
    with stack() as s:
        first = s.client.post("/dial/revoke", data={"token": "not-a-token"})
        second = s.client.post("/dial/revoke", data={"token": "also-not-a-token"})

    assert first.status_code == HTTPStatus.OK
    assert second.status_code == HTTPStatus.OK
    assert first.content == b""
    assert second.content == b""


def test_revoking_nothing_at_all_is_a_malformed_request(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """RFC 7009 §2.1 requires `token`, and the refusal is on the trail.

    A request that names no token is not probing one — it is malformed — so it earns
    `invalid_request` rather than the uniform 200. That is not an oracle: it reports the
    shape of the request, not the state of any token. The audit record is the half an
    operator reads: the refusal class is distinguishable from the form-shape refusals
    beside it, because "a client sent no token" and "a client sent a body that was not a
    form" are different things to go and look at.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        # A well-formed form that simply carries no `token`: the refusal under test is the
        # missing parameter and not the request's shape, so the body has another parameter
        # to make it a form at all.
        response = s.client.post(
            "/dial/revoke", data={"token_type_hint": "refresh_token"}
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_request"
    assert "token" in response.json()["error_description"]
    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    refusals = [r for r in records if r["event"] == "flow_refused"]
    assert len(refusals) == 1
    assert refusals[0]["reason"] == "missing_revocation_token"


def test_a_refresh_naming_another_client_is_refused(stack: Any) -> None:
    """RFC 6749 §6: a client that presents `client_id` must present its own.

    Nothing else at the refresh grant binds the request to the client the token was minted
    for — the token is the only credential there — so a request that names a different
    client is refused rather than served. The refusal is the error vocabulary's own
    `invalid_grant`, the same one every other unusable-refresh-token case gets, because
    telling the two apart would report whose token it is to someone holding it.
    """
    with stack() as s:
        body = s.tokens()
        response = s.refresh(body["refresh_token"], client_id="some-other-client")

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


def test_a_refresh_naming_its_own_client_is_served(stack: Any) -> None:
    """The negative control for the check above: the matching client is not refused.

    Without this the mismatch test could pass on a grant that refused every request
    carrying a `client_id` at all — which would break the clients that send the parameter
    faithfully.
    """
    with stack() as s:
        body = s.tokens()
        response = s.refresh(body["refresh_token"], client_id=PRE_REGISTERED_CLIENT_ID)

    assert response.status_code == HTTPStatus.OK
    assert response.json()["access_token"]


def test_an_access_token_cannot_be_revoked(stack: Any) -> None:
    """Only refresh tokens are tracked; an access token dies within its own lifetime.

    Its answer is still the uniform empty 200 — the distinction is in the denylist, not in
    the response — and the refresh token it belongs to keeps working.
    """
    with stack() as s:
        body = s.tokens()
        response = s.client.post("/dial/revoke", data={"token": body["access_token"]})
        still_works = s.refresh(body["refresh_token"])

    assert response.status_code == HTTPStatus.OK
    assert response.content == b""
    assert still_works.status_code == HTTPStatus.OK


def test_the_denylist_holds_only_live_tokens(stack: Any) -> None:
    """An entry is kept only while the token could still be presented.

    The bound is the token's own expiry, so the list holds at most one entry per live
    refresh token — which is why no separate cap is needed.
    """
    with stack() as s:
        body = s.tokens()
        s.client.post("/dial/revoke", data={"token": body["refresh_token"]})
        assert runtime_of(s.client).denylist.entry_count() == 1


def test_the_revocation_endpoint_is_advertised_in_the_metadata(stack: Any) -> None:
    """A client that discovers the document learns where it may end a session."""
    with stack() as s:
        document = s.client.get("/.well-known/oauth-authorization-server").json()

    assert document["revocation_endpoint"] == f"{ORIGIN}/dial/revoke"


# ------------------------------------------------------------------ audit hygiene


def test_the_refresh_and_revocation_events_carry_no_token(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The audit events name the session, never the credential that is the session."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        rotated = s.refresh(body["refresh_token"]).json()
        s.client.post("/dial/revoke", data={"token": rotated["refresh_token"]})

    rendered = caplog.text
    assert "token_refreshed" in rendered
    assert "token_revoked" in rendered
    assert SUBJECT in rendered
    for token in (
        body["access_token"],
        body["refresh_token"],
        rotated["refresh_token"],
        # The provider's session refresh token is the most powerful credential on the path;
        # it never reaches the trail, plaintext or as the ciphertext the refresh token holds.
        PROVIDER_REFRESH_TOKEN,
    ):
        assert token not in rendered


def test_the_custody_ciphertext_never_reaches_a_log_record(
    stack: Any, caplog: pytest.LogCaptureFixture
) -> None:
    """The custody claim's ciphertext is delivered in the refresh token, never logged."""
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with stack() as s:
        body = s.tokens()
        claim = s.claims_of(body["refresh_token"])[CUSTODY_CLAIM_MEMBER]
        s.refresh(body["refresh_token"])

    assert claim not in caplog.text
    assert PROVIDER_REFRESH_TOKEN not in caplog.text


# ------------------------------------------------------------------- settings


def test_the_refresh_window_may_not_exceed_the_declared_session_bound() -> None:
    """The bound the refresh window rests on, machine-checked at startup."""
    with pytest.raises(ValueError, match="exceeds"):
        make_settings(
            gateway_refresh_ttl_seconds=100_000,
            idp_sso_session_max_seconds=86_400,
        )


def test_the_refusal_names_both_values() -> None:
    """An operator learns what to change from the message, not by reading the source."""
    with pytest.raises(ValueError, match="exceeds") as refusal:
        make_settings(
            gateway_refresh_ttl_seconds=100_000,
            idp_sso_session_max_seconds=86_400,
        )

    assert "100000" in str(refusal.value)
    assert "86400" in str(refusal.value)
    assert "idp_sso_session_max_seconds" in str(refusal.value)


def test_settings_carry_the_roles_claim_name() -> None:
    """The overlay's target name is a setting, mirroring the source path."""
    assert make_settings().roles_claim_name == "roles"


# ---------------------------------------------- the name guard at the refresh grant


# The claims the refresh token's session bindings need; a helper below signs a token with
# a caller-chosen resource so the guard on the token's own resource can be exercised for
# names no flow could have served.
def _signed_refresh_token(stack: Any, *, resource: str) -> str:
    """A refresh token this gateway signed, bound to a caller-chosen resource.

    Minted directly through the real mint so the signature and payload shape are the
    gateway's own; only the resource is unusual, which is exactly the input the guard on
    the token's own resource exists to refuse. The guard runs before the custody seam, so a
    token with no custody claim still exercises it.
    """
    return mint_refresh_token(
        stack.signing_key,
        stack.settings,
        subject=SUBJECT,
        resource=resource,
        client_id=PRE_REGISTERED_CLIENT_ID,
        expires_at=initial_refresh_expiry(stack.settings),
    )


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("a%7Bb", "invalid_resource_path"),
        ("token", "reserved_path_segment"),
        ("other", "restricted_toolset"),
    ],
)
def test_a_guard_refused_path_on_a_refresh_is_invalid_target(
    stack: Any, caplog: pytest.LogCaptureFixture, path: str, reason: str
) -> None:
    """The refresh grant's resource-to-path resolution passes the same guard as every site.

    The request's resource matches the token's own, so the mismatch check does not fire;
    what refuses it is the path guard on the token's resource — a shape violation, a
    reserved first segment, or a restriction exclusion — each answered as `invalid_target`
    with its own fixed-vocabulary reason from the closed table.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    resource = f"{ORIGIN}/dial/{path}/mcp"

    with stack() as s:
        token = _signed_refresh_token(s, resource=resource)
        response = s.refresh(token, resource=resource)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_target"
    refusals = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    reasons = [r["reason"] for r in refusals if r["event"] == "flow_refused"]
    assert reason in reasons


def test_the_guard_refusal_response_shape_matches_the_resource_mismatch(
    stack: Any,
) -> None:
    """A guard refusal answers the same harness-visible shape the mismatch refusal does.

    Both are `invalid_target` on this surface, so a client's error handling is identical
    whether the resource named a different toolset or a guard-refused name; only the audit
    reason differs, and a harness never sees that.
    """
    with stack() as s:
        # The resource-mismatch analogue: a resource this token was not minted for.
        mismatch = s.refresh(
            s.tokens()["refresh_token"], resource=f"{ORIGIN}/dial/other/mcp"
        )
        # A guard refusal: the request's resource matches the token's own, but the name is
        # reserved.
        resource = f"{ORIGIN}/dial/token/mcp"
        guarded = s.refresh(
            _signed_refresh_token(s, resource=resource), resource=resource
        )

    assert mismatch.status_code == guarded.status_code == HTTPStatus.BAD_REQUEST
    assert mismatch.json()["error"] == guarded.json()["error"] == "invalid_target"
    assert set(mismatch.json()) == set(guarded.json())


def test_each_guard_refusal_class_lands_on_its_committed_token(stack: Any) -> None:
    """Every guard refusal class reaches the record through the closed table.

    The table maps (error code, refusal class) to a committed token, and an unmapped key
    raises rather than logging an unrecognized token. This drives all three classes and
    asserts the resulting reason is the class token itself — proving no refusal bypasses
    the table.
    """
    for expected in (
        "invalid_resource_path",
        "reserved_path_segment",
        "restricted_toolset",
    ):
        refusal = TokenRequestError(
            INVALID_TARGET, "fixed text", refusal_class=expected
        )
        assert refusal.reason == expected

    # The negative control: an unmapped class raises rather than silently returning a token.
    unmapped = TokenRequestError(
        INVALID_TARGET, "fixed text", refusal_class="not-a-class"
    )
    with pytest.raises(KeyError):
        _ = unmapped.reason


# ---------------------------------------------- the resource resolution across kinds


# The app the cross-kind tests address, and its resource URI in the apps namespace.
APP_NAME = APPS_NAME
APP_RESOURCE = f"{ORIGIN}/apps/{APP_NAME}/mcp"


def _app_code(stack: Any) -> str:
    """A code bound to an app resource, minted the way a flow for an app would issue one."""
    code_id = new_token_id()
    runtime_of(stack.client).pending_custody.put(code_id, PROVIDER_REFRESH_TOKEN)
    return issue_code(
        stack.signing_key,
        CodeBindings(
            client_id=PRE_REGISTERED_CLIENT_ID,
            redirect_uri=LOOPBACK_REDIRECT_URI,
            code_challenge=CHALLENGE,
            code_challenge_method="S256",
            resource=APP_RESOURCE,
            toolset=APP_NAME,
            subject=SUBJECT,
            claims=copied_claims(dict(CLAIMS), stack.settings),
        ),
        issuer=ORIGIN,
        ttl_seconds=300,
        code_id=code_id,
    )


def test_an_app_kind_code_grant_carries_the_app_resource_and_the_marker(
    stack: Any,
) -> None:
    """The code grant resolves the app shape, and the audience names the app's resource.

    The audience is the same shape a toolset sign-in issues: the resource plus the marker on
    the access token, the resource alone on the refresh token.
    """
    with stack(apps={APP_NAME: {}}) as s:
        redeemed = s.redeem(_app_code(s), resource=APP_RESOURCE)

    assert redeemed.status_code == HTTPStatus.OK, redeemed.text
    access = jwt.decode(
        redeemed.json()["access_token"], options={"verify_signature": False}
    )
    refresh = jwt.decode(
        redeemed.json()["refresh_token"], options={"verify_signature": False}
    )
    assert access["aud"] == [APP_RESOURCE, "dial-mcp-proxy"]
    assert refresh["aud"] == [APP_RESOURCE]


def test_a_refresh_names_the_app_resource(stack: Any) -> None:
    """The refresh grant resolves the app shape and mints for the app's resource."""
    with stack(apps={APP_NAME: {}}) as s:
        redeemed = s.redeem(_app_code(s), resource=APP_RESOURCE)
        refreshed = s.refresh(redeemed.json()["refresh_token"], resource=APP_RESOURCE)

    assert refreshed.status_code == HTTPStatus.OK, refreshed.text
    access = jwt.decode(
        refreshed.json()["access_token"], options={"verify_signature": False}
    )
    assert access["aud"] == [APP_RESOURCE, "dial-mcp-proxy"]


def test_an_app_resource_on_a_toolset_tokens_refresh_is_refused(stack: Any) -> None:
    """A resource must match the one the token was minted for, across kinds too.

    A toolset token's refresh naming the app resource is a mismatch — the same check the
    resource-mismatch case makes, now across the two shapes.
    """
    with stack(apps={APP_NAME: {}}) as s:
        redeemed = s.redeem(s.issue())
        refreshed = s.refresh(redeemed.json()["refresh_token"], resource=APP_RESOURCE)

    assert refreshed.status_code == HTTPStatus.BAD_REQUEST
    assert refreshed.json()["error"] == "invalid_target"


def test_a_toolset_resource_on_an_app_tokens_refresh_is_refused(stack: Any) -> None:
    """The inverse: an app token's refresh naming the toolset resource is refused."""
    with stack(apps={APP_NAME: {}}) as s:
        redeemed = s.redeem(_app_code(s), resource=APP_RESOURCE)
        refreshed = s.refresh(redeemed.json()["refresh_token"], resource=RESOURCE)

    assert refreshed.status_code == HTTPStatus.BAD_REQUEST
    assert refreshed.json()["error"] == "invalid_target"


def test_a_refresh_matches_the_resource_canonically(stack: Any) -> None:
    """The refresh match is canonical-vs-canonical: a non-canonical spelling is accepted.

    The token's own `resource` is the canonical identity the flow recorded, so a client that
    refreshes with an equivalent spelling of the same resource is served — two spellings of
    one resource cannot re-key the match. `%6E` is `n`, so the offered resource is the
    canonical one's spelling.
    """
    with stack(toolsets="") as s:
        redeemed = s.redeem(s.issue())
        refreshed = s.refresh(
            redeemed.json()["refresh_token"],
            resource=f"{ORIGIN}/dial/%6Eotion/mcp",
        )

    assert refreshed.status_code == HTTPStatus.OK, refreshed.text


def test_a_code_matches_the_resource_canonically(stack: Any) -> None:
    """The code grant's resource match is canonical-vs-canonical: a non-canonical spelling
    is accepted.

    The code's own `resource` is the canonical identity the flow recorded, so a client that
    redeems with an equivalent spelling of the same resource is served — two spellings of
    one resource cannot re-key the match. `%6E` is `n`, so the offered resource is the
    canonical one's spelling — the refresh grant's twin,
    `test_a_refresh_matches_the_resource_canonically`.
    """
    with stack(toolsets="") as s:
        redeemed = s.redeem(s.issue(), resource=f"{ORIGIN}/dial/%6Eotion/mcp")

    assert redeemed.status_code == HTTPStatus.OK, redeemed.text


def test_a_refresh_naming_a_different_resource_is_refused_across_spellings(
    stack: Any,
) -> None:
    """A mismatch is still `invalid_target`, whatever spelling names the other resource."""
    with stack(toolsets="") as s:
        redeemed = s.redeem(s.issue())
        refreshed = s.refresh(
            redeemed.json()["refresh_token"], resource=f"{ORIGIN}/dial/%6Fther/mcp"
        )

    assert refreshed.status_code == HTTPStatus.BAD_REQUEST
    assert refreshed.json()["error"] == "invalid_target"


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("a%7Bb", "invalid_resource_path"),
        ("other", "restricted_app"),
    ],
)
def test_an_app_guard_refused_name_on_a_refresh_is_invalid_target(
    stack: Any, caplog: pytest.LogCaptureFixture, path: str, reason: str
) -> None:
    """The refresh grant's app-shaped resource passes the app guard, with its own tokens.

    A shape violation and a restriction exclusion each land on their own committed token
    from the closed table — the app classes, distinct from the toolset ones. The record's
    reason is asserted, because the response shape is the same for either kind's guard and
    only the reason says which guard ran.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    resource = f"{ORIGIN}/apps/{path}/mcp"

    with stack(apps={APP_NAME: {}}) as s:
        token = _signed_refresh_token(s, resource=resource)
        response = s.refresh(token, resource=resource)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_target"
    reasons = _refusal_reasons(caplog)
    assert reason in reasons


def test_the_app_grant_reasons_are_committed_tokens(stack: Any) -> None:
    """The app guard classes reach the record through the closed table, never a free form."""
    for expected in ("invalid_resource_path", "restricted_app"):
        refusal = TokenRequestError(
            INVALID_TARGET, "fixed text", refusal_class=expected
        )
        assert refusal.reason == expected


# ----------------------------------- revoke-on-double-redemption (task 5.2)


def test_a_replayed_code_revokes_the_refresh_token_it_first_bought(stack: Any) -> None:
    """RFC 9700 §4.2.4 as one family, walked in one flow.

    The first redemption mints an access token and a refresh token; the token is then
    rotated (its successor carrying a fresh `jti`); the replay of the same code is refused
    as before, and the refusal now denylists the refresh token the first redemption minted,
    so that token's next presentation is refused `invalid_grant`. The two disclosed bounds
    are asserted here as the bound the clause actually buys, not implied wider: the access
    token the first redemption minted stays live (bearer and short-TTL, the SHOULD's
    tolerated shape), and the already-rotated successor survives and still refreshes,
    because rotation mints a fresh id and no code-to-successor mapping exists.
    """
    with stack() as s:
        code = s.issue()
        first = s.redeem(code)
        assert first.status_code == HTTPStatus.OK, first.text
        body = first.json()
        original = body["refresh_token"]
        original_jti = s.claims_of(original)["jti"]

        # Rotate before the replay is detected: the presented token is replaced by a fresh
        # one with its own jti.
        rotated = s.refresh(original)
        assert rotated.status_code == HTTPStatus.OK, rotated.text
        successor = rotated.json()["refresh_token"]
        successor_jti = s.claims_of(successor)["jti"]
        assert successor_jti != original_jti

        # The detected replay: refused, and it denylists the refresh token the first
        # redemption minted.
        replay = s.redeem(code)
        assert replay.json()["error"] == "invalid_grant"
        assert runtime_of(s.client).denylist.is_revoked(original_jti) is True

        # That token's next presentation is refused; the successor's is still granted —
        # partial 2, the bound the clause states.
        refused = s.refresh(original)
        assert refused.json()["error"] == "invalid_grant"
        assert runtime_of(s.client).denylist.is_revoked(successor_jti) is False
        still_works = s.refresh(successor)
        assert still_works.status_code == HTTPStatus.OK, still_works.text

        # Partial 1: the access token the first redemption minted stays live — bearer,
        # unrevocable by design, under its own short TTL (the SHOULD's tolerated shape).
        access_payload = s.claims_of(body["access_token"])
        assert access_payload["exp"] > time.time()
        assert (
            access_payload["exp"] - access_payload["iat"]
            <= s.settings.gateway_access_token_ttl_seconds
        )
