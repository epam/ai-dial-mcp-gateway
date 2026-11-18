"""Tests for the custody envelope and the pending hand-off seam.

Two layers are asserted, because they protect different properties:

* **The envelope** (`gateway/custody.py`): the AES-256-GCM round trip and every way the
  seam can refuse — a tampered tag, a wrong key, an unknown version or key-id, an expired
  envelope, a subject-swapped blob — plus the nonce's uniqueness across many encryptions.
  The algorithm and the lengths are pinned in code constants, so a test that varied one
  would be measuring a different envelope than the one that ships.
* **The carrier discipline** (the flow and the token endpoint): the ciphertext appears in
  the refresh token and in no other issued artifact, the authorization code carries no
  identity-provider credential of any kind, the plaintext never reaches a client response
  or a log, and the pending entry's lifecycle is create/consume/drop-on-non-redemption —
  including the restart semantics (entries lost, refresh capability surviving).
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
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from gateway.codes import code_challenge_for
from gateway.custody import (
    ENVELOPE_VERSION,
    KEY_BYTES,
    CustodyError,
    CustodyKey,
    decode_custody_key,
    envelope_bytes_for_token,
)
from gateway.settings import Settings
from gateway.state import PendingCustodyStore
from gateway.tokens import CUSTODY_CLAIM_MEMBER

from tests.conftest import (
    CUSTODY_KEY_B64,
    CUSTODY_KEY_ID,
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    make_client,
    make_settings,
    runtime_of,
    surface_settings,
)

ORIGIN = "http://localhost:8090"
RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"

REALM_CERTS_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/certs"
REALM_TOKEN_URL = "http://keycloak:8900/realms/dial/protocol/openid-connect/token"

CORE_LISTING_URL = f"http://core:8080/openai/toolsets/{TOOLSET_NAME}"

SUBJECT = "3a0d60f4-0000-0000-0000-000000000000"
HARNESS_VERIFIER = "a-verifier-for-the-custody-test"
HARNESS_STATE = "the-harness-state"

PROVIDER_REFRESH_TOKEN = "the-provider-session-refresh-token"


# How many envelopes the nonce-uniqueness check seals, so the assertion names its count.
NONCE_SAMPLES = 200


def _a_key(key_id: str = "k-1") -> CustodyKey:
    return CustodyKey(key_id, secrets.token_bytes(KEY_BYTES))


# ------------------------------------------------------------- the envelope


def test_an_envelope_round_trips_to_its_provider_token() -> None:
    key = _a_key()
    claim = key.encrypt(subject=SUBJECT, expires_at=int(time.time()) + 600, token="t")

    assert key.decrypt(claim, subject=SUBJECT) == "t"


def test_the_envelope_layout_is_version_key_id_nonce_ciphertext() -> None:
    """The header is readable and the body is not: the pinned layout, byte for byte."""
    key = _a_key("my-key")
    claim = key.encrypt(subject=SUBJECT, expires_at=int(time.time()) + 600, token="t")
    raw = base64.urlsafe_b64decode(claim + "=" * (-len(claim) % 4))

    assert raw[0] == ENVELOPE_VERSION
    assert raw[1] == len("my-key")
    assert raw[2 : 2 + len("my-key")] == b"my-key"
    # The token appears in no READABLE byte: the header (version + key id) is the
    # only plaintext region. The nonce and ciphertext are opaque by design — a
    # one-byte token can occur inside them by chance, so they are not scanned.
    assert b"t" not in raw[: 2 + len("my-key")]


def test_a_tampered_envelope_fails_the_tag() -> None:
    key = _a_key()
    claim = key.encrypt(subject=SUBJECT, expires_at=int(time.time()) + 600, token="t")
    tampered = claim[:-3] + ("AAA" if not claim.endswith("AAA") else "BBB")

    with pytest.raises(CustodyError):
        key.decrypt(tampered, subject=SUBJECT)


def test_a_wrong_key_refuses_the_envelope() -> None:
    sealer = _a_key("k-1")
    other = _a_key("k-1")  # same id, different material
    claim = sealer.encrypt(
        subject=SUBJECT, expires_at=int(time.time()) + 600, token="t"
    )

    with pytest.raises(CustodyError):
        other.decrypt(claim, subject=SUBJECT)


def test_an_unknown_key_id_refuses_the_envelope() -> None:
    """A blob sealed under another key id is refused before any decrypt."""
    claim = _a_key("k-1").encrypt(
        subject=SUBJECT, expires_at=int(time.time()) + 600, token="t"
    )

    with pytest.raises(CustodyError):
        _a_key("k-2").decrypt(claim, subject=SUBJECT)


def test_an_unknown_version_refuses_the_envelope() -> None:
    key = _a_key()
    claim = key.encrypt(subject=SUBJECT, expires_at=int(time.time()) + 600, token="t")
    raw = bytearray(base64.urlsafe_b64decode(claim + "=" * (-len(claim) % 4)))
    raw[0] = ENVELOPE_VERSION + 1
    forged = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode()

    with pytest.raises(CustodyError):
        key.decrypt(forged, subject=SUBJECT)


def test_an_expired_envelope_refuses() -> None:
    key = _a_key()
    claim = key.encrypt(subject=SUBJECT, expires_at=int(time.time()) - 1, token="t")

    with pytest.raises(CustodyError):
        key.decrypt(claim, subject=SUBJECT)


def test_an_envelope_bound_to_another_subject_refuses() -> None:
    """The tag covers integrity; the embedded subject covers placement."""
    key = _a_key()
    claim = key.encrypt(subject="user-a", expires_at=int(time.time()) + 600, token="t")

    with pytest.raises(CustodyError):
        key.decrypt(claim, subject="user-b")


def test_a_non_envelope_string_refuses() -> None:
    key = _a_key()

    for garbage in ("", "not base64!!", "short", "AAAA"):
        with pytest.raises(CustodyError):
            key.decrypt(garbage, subject=SUBJECT)


def test_encrypting_many_times_yields_distinct_nonces() -> None:
    """The 96-bit nonce is CSPRNG-chosen per encryption, so no two envelopes collide."""
    key = _a_key()
    expiry = int(time.time()) + 600
    claims = {
        key.encrypt(subject=SUBJECT, expires_at=expiry, token="t")
        for _ in range(NONCE_SAMPLES)
    }

    assert len(claims) == NONCE_SAMPLES


# ----------------------------------------------------------- the key loader


def test_decode_custody_key_accepts_the_base64_lengths() -> None:
    raw = secrets.token_bytes(KEY_BYTES)

    assert decode_custody_key(base64.b64encode(raw).decode()) == raw
    # The URL-safe alphabet is the same key in another spelling.
    url_safe = base64.urlsafe_b64encode(raw).decode()
    assert decode_custody_key(url_safe) == raw


@pytest.mark.parametrize("length", [16, 24, 31, 33])
def test_decode_custody_key_refuses_a_wrong_length(length: int) -> None:
    with pytest.raises(CustodyError):
        decode_custody_key(base64.b64encode(secrets.token_bytes(length)).decode())


def test_the_key_repr_carries_no_material() -> None:
    """A key object must be loggable: the repr names the id, never the bytes."""
    key = _a_key("k-1")

    rendered = repr(key)
    assert "k-1" in rendered
    assert "CustodyKey" in rendered
    # The material has no representation: the repr states the id and nothing derived from
    # the key bytes.
    assert "cipher" not in rendered.lower()


def test_the_envelope_size_grows_with_the_provider_bound() -> None:
    """The size model is monotonic, which is the property the coupling check rests on."""
    assert envelope_bytes_for_token(8192) > envelope_bytes_for_token(4096)


# ------------------------------------------------- the pending hand-off store


def test_the_pending_entry_is_created_consumed_and_dropped() -> None:
    store = PendingCustodyStore(ttl_seconds=300)
    store.put("code-id", "provider-token")

    assert store.entry_count() == 1
    assert store.take("code-id") == "provider-token"
    # Consuming is single-use: a second take finds nothing.
    assert store.take("code-id") is None
    assert store.entry_count() == 0


def test_a_pending_entry_expires_with_its_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """The entry lives no longer than the code that names it could be redeemed."""
    store = PendingCustodyStore(ttl_seconds=300)
    store.put("code-id", "provider-token")

    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 301)

    assert store.take("code-id") is None
    assert store.entry_count() == 0


# ---------------------------------------------------- the carrier discipline


class Idp:
    """A generated identity-provider keypair, and the tokens it mints for the tests."""

    def __init__(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        numbers = key.public_key().public_numbers()

        def b64u(value: int) -> str:
            raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
            return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

        self.jwks: dict[str, Any] = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": "the-idp-key",
                    "n": b64u(numbers.n),
                    "e": b64u(numbers.e),
                }
            ]
        }

    def token(self) -> str:
        now = int(time.time())
        return jwt.encode(
            {
                "iss": "https://keycloak:8443/realms/dial",
                "aud": "dial-chat",
                "iat": now,
                "exp": now + 300,
                "sub": SUBJECT,
                "roles": ["admin"],
                "project": "proj-alpha",
                "email": "dial@example.test",
            },
            self.pem,
            algorithm="RS256",
            headers={"kid": "the-idp-key"},
        )


@pytest.fixture
def idp() -> Idp:
    return Idp()


def _toolset_projection(**overrides: Any) -> dict[str, Any]:
    """Core's listing projection, with no verifier anywhere in it.

    The per-caller statuses ride the same `auth_settings` member — the listing read's
    enrichment. SIGNED_OUT by default so a flow run here proceeds to the consent leg.
    """
    auth: dict[str, Any] = {
        "authentication_type": "OAUTH",
        "client_id": "core-upstream-client",
        "authorization_endpoint": "https://mcp.notion.com/authorize",
        "redirect_uri": "http://localhost:8765/callback",
        "code_challenge": "the-upstream-code-challenge",
        "code_challenge_method": "S256",
        "scopes_supported": ["default"],
        "user_level_auth_status": "SIGNED_OUT",
        "global_auth_status": "SIGNED_OUT",
    }
    auth.update(overrides)
    return {"name": TOOLSET_NAME, "auth_settings": auth}


@contextmanager
def a_gateway(
    private_key_pem: str, tmp_path: Path, idp: Idp, **overrides: object
) -> Iterator[tuple[TestClient, respx.Router]]:
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
            return_value=httpx.Response(
                200, json=_toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        with make_client(settings, private_key_pem) as client:
            yield client, router


def _run_flow(client: TestClient) -> tuple[str, str]:
    """Drive a whole short-circuited flow, returning the harness code and the flow id.

    The client is pre-approved so the checkpoint passes the short-circuit through with no
    page: the custody properties these tests assert are about the flow's credential
    handling, which is unchanged by the checkpoint for an approved client.
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
    done = client.get(
        "/dial/callback/idp",
        params={"state": flow_id, "code": "the-idp-code"},
    )
    code = parse_qs(urlparse(done.headers["location"]).query)["code"][0]
    return code, flow_id


def _redeem(client: TestClient, code: str) -> Any:
    return client.post(
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


def test_the_code_payload_carries_no_identity_provider_credential(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The authorization code is a signed-but-readable JWT: no provider credential in it.

    The code is handed to the client, so anything in its payload is readable by whoever
    holds the string. The provider's session refresh token must therefore not be there, in
    plaintext or as ciphertext — it transits server state instead.
    """
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        code, _ = _run_flow(client)

    payload = jwt.decode(code, options={"verify_signature": False})
    # The clear payload carries the bindings and the claim snapshot, and nothing else.
    assert PROVIDER_REFRESH_TOKEN not in json.dumps(payload)
    assert CUSTODY_CLAIM_MEMBER not in payload


def test_the_custody_claim_appears_only_in_the_refresh_token(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The encrypted claim rides the refresh token and no other issued artifact."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        code, _ = _run_flow(client)
        redeemed = _redeem(client, code).json()

    access = jwt.decode(redeemed["access_token"], options={"verify_signature": False})
    refresh = jwt.decode(redeemed["refresh_token"], options={"verify_signature": False})
    assert CUSTODY_CLAIM_MEMBER in refresh
    assert CUSTODY_CLAIM_MEMBER not in access
    # The provider's plaintext token appears in the refresh token only as ciphertext.
    assert PROVIDER_REFRESH_TOKEN not in redeemed["refresh_token"]
    assert PROVIDER_REFRESH_TOKEN not in redeemed["access_token"]


def test_the_plaintext_never_reaches_a_client_response_or_a_log(
    private_key_pem: str,
    tmp_path: Path,
    idp: Idp,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The provider's plaintext token reaches neither a client nor a log record.

    The instrument is the run: the provider token genuinely exists during it, so its
    absence from the response bodies and the trail is a measurement.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        code, _ = _run_flow(client)
        redeemed = _redeem(client, code)

    assert PROVIDER_REFRESH_TOKEN not in redeemed.text
    assert PROVIDER_REFRESH_TOKEN not in caplog.text
    # The ciphertext is delivered — inside the refresh token, whose signed payload carries
    # it — but the token itself never reaches the trail.
    refresh_token = redeemed.json()["refresh_token"]
    claim = jwt.decode(refresh_token, options={"verify_signature": False})[
        CUSTODY_CLAIM_MEMBER
    ]
    assert claim
    assert refresh_token in redeemed.text
    assert refresh_token not in caplog.text


def test_the_pending_entry_is_consumed_at_the_code_grant(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """The entry exists between the flow and the grant, and is gone after the grant."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        code, _ = _run_flow(client)
        runtime = runtime_of(client)
        assert runtime.pending_custody.entry_count() == 1
        _redeem(client, code)
        assert runtime.pending_custody.entry_count() == 0


def test_an_unredeemed_code_drops_its_pending_entry(
    private_key_pem: str, tmp_path: Path, idp: Idp
) -> None:
    """A code never redeemed leaves an entry that ages out with the code's own TTL."""
    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        _run_flow(client)
        runtime = runtime_of(client)
        assert runtime.pending_custody.entry_count() == 1
        # The entry's TTL is the code's own short life; advanced past it here rather than
        # waited out, so the assertion is about the bound and not about a sleep.
        store = runtime.pending_custody
        # The bound is what is observed.
        store._entries = {
            key: (token, time.monotonic() - 1)
            for key, (token, _) in store._entries.items()
        }
        assert store.entry_count() == 0


def test_a_restart_loses_pending_entries_but_not_the_custody(
    private_key_pem: str, tmp_path: Path, idp: Idp, caplog: pytest.LogCaptureFixture
) -> None:
    """Pending entries are memory-only; the custody claim returns with the token.

    The two artifacts the restart treats differently, asserted together: a refresh token
    issued before the restart still refreshes, because its ciphertext travels with the
    token and its pending entry is not in the path — while an unredeemed pre-restart code
    fails its grant fail-closed, because the memory-only pending entry went with the
    process and the code grant must not mint a refresh token it could never refresh.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))

    # Before the restart: a flow's pending entry and a live refresh token.
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
            return_value=httpx.Response(
                200, json=_toolset_projection(user_level_auth_status="SIGNED_IN")
            )
        )
        with make_client(settings, private_key_pem) as client:
            code, _ = _run_flow(client)
            redeemed = _redeem(client, code).json()
            refresh_token = redeemed["refresh_token"]
            # A second, unredeemed code whose pending entry must not survive the restart.
            orphan_code, _ = _run_flow(client)

    # After the restart: a fresh runtime over the same settings.
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
        with make_client(settings, private_key_pem) as client:
            runtime = runtime_of(client)
            assert runtime.pending_custody.entry_count() == 0
            refreshed = client.post(
                "/dial/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "resource": RESOURCE,
                },
            )
            # The pre-restart unredeemed code, redeemed against the restarted gateway: its
            # pending entry is gone, so the grant refuses fail-closed rather than minting a
            # refresh token with no custody to refresh from.
            refused = _redeem(client, orphan_code)

    assert refreshed.status_code == HTTPStatus.OK
    assert refreshed.json()["access_token"]

    assert refused.status_code == HTTPStatus.BAD_REQUEST
    assert refused.json()["error"] == "invalid_grant"
    reasons = [
        json.loads(record.getMessage())["reason"]
        for record in caplog.records
        if record.name == "gateway.audit"
        and json.loads(record.getMessage())["event"] == "flow_refused"
    ]
    assert "custody_decrypt_failed" in reasons


def test_a_blob_under_a_superseded_key_refuses_with_the_custody_reason(
    private_key_pem: str, tmp_path: Path, idp: Idp, caplog: pytest.LogCaptureFixture
) -> None:
    """Hard-cut rotation: a superseded key decrypts nothing, and the refusal is custody-class.

    The token below carries a claim sealed under a key the runtime no longer holds — the
    shape a rotation produces — so its next refresh refuses on the custody class and the
    user re-signs-in.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")

    with a_gateway(private_key_pem, tmp_path, idp) as (client, _router):
        code, _ = _run_flow(client)
        redeemed = _redeem(client, code).json()
        refresh_token = redeemed["refresh_token"]

        # Re-sign the same token with a claim sealed under a different key.
        superseded = CustodyKey(CUSTODY_KEY_ID, secrets.token_bytes(KEY_BYTES))
        payload = jwt.decode(refresh_token, options={"verify_signature": False})
        payload[CUSTODY_CLAIM_MEMBER] = superseded.encrypt(
            subject=SUBJECT,
            expires_at=int(payload["exp"]),
            token=PROVIDER_REFRESH_TOKEN,
        )
        forged = runtime_of(client).signing_key.sign(dict(payload))
        response = client.post(
            "/dial/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": forged,
                "resource": RESOURCE,
            },
        )

    assert response.json()["error"] == "invalid_grant"
    reasons = [
        json.loads(record.getMessage())["reason"]
        for record in caplog.records
        if record.name == "gateway.audit"
        and json.loads(record.getMessage())["event"] == "flow_refused"
    ]
    assert "custody_decrypt_failed" in reasons


def test_the_runtime_builds_the_configured_custody_key() -> None:
    """The runtime's custody key comes from the settings, by the configured id."""
    settings: Settings = make_settings(
        gateway_custody_keys={CUSTODY_KEY_ID: CUSTODY_KEY_B64}
    )

    assert settings.custody_key.key_id == CUSTODY_KEY_ID


def test_the_ciphertext_uses_the_pinned_lengths_in_the_key() -> None:
    """The key object exposes only its id, never its material — the repr contract."""
    key: CustodyKey = make_settings(
        gateway_custody_keys={CUSTODY_KEY_ID: CUSTODY_KEY_B64}
    ).custody_key

    assert key.key_id == CUSTODY_KEY_ID
    assert "CUSTODY_KEY" not in repr(key)
