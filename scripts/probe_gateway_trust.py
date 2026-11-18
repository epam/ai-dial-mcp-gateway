"""Prove Core trusts tokens signed by the *gateway's* key, through the gateway's JWKS.

The Stage 0 spike proved the shape — Core accepts an RS256 JWT minted outside Keycloak —
against a throwaway keypair served by a one-shot container. The deployed arrangement is
different in exactly one respect, and it is the respect that can be wrong: the key Core
fetches is the gateway's own, published by the gateway at `/dial/jwks.json`, and the
provider entry points at that endpoint rather than at the spike container.

So this probe re-establishes the same claim against the real endpoint:

1. **The negative control runs first.** A token signed by a key the gateway does not
   publish must be refused. Without it, a Core that accepted every token regardless would
   read as a pass.
2. The gateway's JWKS endpoint (through the front door) publishes a key whose `kid` is
   the one the configured signing key derives.
3. A token signed with the configured gateway signing key, with the gateway's public
   origin as `iss` and the audience marker present, resolves a real user identity at
   Core's `/v1/user/info`.

Nothing here prints a credential: the signing key is read from the environment and used,
never echoed, and the minted token appears as a redacted handle.

Usage:
    PYTHONUTF8=1 python scripts/probe_gateway_trust.py
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gateway.keys import SigningKey

from spike_env import (
    HTTP_OK,
    SpikeError,
    decode_claims,
    load_env,
    redact,
    request,
    require,
)
from spike_mint_jwt import REGISTRY_CLAIMS, fetch_identity_token

# The one status Core answers for a token it will not accept. Named here so a probe's
# expectation reads as the status rather than as a bare number.
HTTP_UNAUTHORIZED = 401

# The audience marker Core's `dial-mcp-proxy` provider entry verifies.
AUDIENCE_MARKER = "dial-mcp-proxy"

# How long the minted probe token lives. Ten minutes, matching the gateway's own short
# access-token bound: the probes run immediately after minting.
_PROBE_TOKEN_TTL_SECONDS = 600


class ProbeError(SpikeError):
    """A probe found something other than what the deployment requires."""


class JwksUnreachableError(ProbeError):
    """The gateway's JWKS endpoint did not answer."""

    def __init__(self, url: str, status: int) -> None:
        super().__init__(f"GET {url} answered HTTP {status}")


class SigningKeyNotPublishedError(ProbeError):
    """The key the gateway signs with is not the key it publishes."""

    def __init__(self) -> None:
        super().__init__("the signing key and the published JWKS disagree")


class UnpublishedSignerAcceptedError(ProbeError):
    """Core accepted a token signed by a key it does not publish."""

    def __init__(self, status: int) -> None:
        super().__init__(f"an unpublished signer was accepted (HTTP {status})")


class GatewayTokenRejectedError(ProbeError):
    """Core refused a token signed with the gateway's own key."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(
            f"Core did not resolve the gateway-signed token (HTTP {status}): {body[:200]}"
        )


def gateway_jwks(origin: str) -> dict[str, Any]:
    """Fetch the JWKS the gateway publishes through the front door."""
    status, body, _ = request("GET", f"{origin}/dial/jwks.json")
    if status != HTTP_OK:
        raise JwksUnreachableError(f"{origin}/dial/jwks.json", status)
    document: dict[str, Any] = json.loads(body)
    return document


def _b64url_uint(value: int) -> str:
    """The JWK encoding of an unsigned big-endian integer: base64url, no padding."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _thumbprint_kid(public: rsa.RSAPublicKey) -> str:
    """The kid a key derives to, computed the way the gateway computes it.

    Derived from the public key rather than read from a document, so a token can be
    minted under a key Core has never seen — which is what the negative control needs.
    """
    numbers = public.public_numbers()
    material = f"{_b64url_uint(numbers.n)}.{_b64url_uint(numbers.e)}"
    return hashlib.sha256(material.encode()).hexdigest()[:16]


def identity_claims(env: dict[str, str], issuer: str) -> dict[str, Any]:
    """A real realm user's claim set, carried over a fresh registry payload.

    The `sub` has to be a user Core knows: authorization runs on the token's claims, so a
    synthetic subject proves nothing about the deployment. The identity comes from the
    realm through the client whose mappers carry the full claim set.
    """
    claims = decode_claims(fetch_identity_token(env))
    payload: dict[str, Any] = {
        key: value for key, value in claims.items() if key not in REGISTRY_CLAIMS
    }
    now = int(time.time())
    payload.update(
        {
            "iss": issuer,
            "aud": [issuer, AUDIENCE_MARKER],
            "iat": now,
            "exp": now + _PROBE_TOKEN_TTL_SECONDS,
            # A distinct id keeps this token addressable in logs and denies reuse of a
            # previously captured one.
            "jti": base64.urlsafe_b64encode((now * 1_000_000).to_bytes(8, "big"))
            .decode()
            .rstrip("="),
        }
    )
    return payload


def probe_published_key(env: dict[str, str], signing_key: str, origin: str) -> str:
    """Assert the key the gateway signs with is the key its endpoint publishes."""
    published = gateway_jwks(origin)
    kids = [key.get("kid") for key in published.get("keys", [])]
    print("=== the published JWKS (through the front door) ===")
    print(f"  GET {origin}/dial/jwks.json -> keys={json.dumps(kids)}")

    expected = SigningKey(signing_key.replace("\\n", "\n")).kid
    print(f"  derived from GATEWAY_SIGNING_KEY -> kid={expected}")
    if expected not in kids:
        print("FAIL: the key the gateway signs with is not the key it publishes")
        raise SigningKeyNotPublishedError
    print("  verdict: green — the signing key is the published key")
    return expected


def probe_unpublished_signer(claims: dict[str, Any], core: str) -> None:
    """The negative control: a token signed by a key the gateway does not publish."""
    print()
    print("=== negative control: a token signed by an unpublished key ===")
    foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    foreign_pem = foreign.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    foreign_kid = _thumbprint_kid(foreign.public_key())
    token = jwt.encode(
        claims, foreign_pem.decode(), algorithm="RS256", headers={"kid": foreign_kid}
    )
    print(f"  token     {redact(token)}  kid={foreign_kid}")
    status, _body, _ = request("GET", f"{core}/v1/user/info", token=token)
    print(f"  GET /v1/user/info -> HTTP {status}")
    if status != HTTP_UNAUTHORIZED:
        print("FAIL: Core accepted a token signed by a key it does not publish")
        raise UnpublishedSignerAcceptedError(status)
    print("  verdict: red as required — an unpublished signer is refused")


def probe_gateway_signed(core: str, claims: dict[str, Any], key: SigningKey) -> None:
    """The positive control: a token signed with the gateway's own key."""
    print()
    print("=== positive control: a token signed with the gateway's key ===")
    token = key.sign(claims)
    print(f"  token     {redact(token)}  kid={key.kid}")
    print(f"  iss       {json.dumps(claims.get('iss'))}")
    print(f"  aud       {json.dumps(claims.get('aud'))}")
    print(f"  sub       {json.dumps(claims.get('sub'))}")
    status, body, _ = request("GET", f"{core}/v1/user/info", token=token)
    print(f"  GET /v1/user/info -> HTTP {status}")
    if status != HTTP_OK:
        print(f"  body      {body[:300]}")
        raise GatewayTokenRejectedError(status, body)
    info = json.loads(body)
    print(f"  userId    {info.get('userId')}")
    print(f"  roles     {json.dumps(info.get('roles'))}")
    print(
        "  verdict: green — Core validated the gateway's own key via the gateway's JWKS"
    )


def main() -> int:
    env = load_env()
    origin = require(env, "GATEWAY_PUBLIC_ORIGIN")
    signing_key = require(env, "GATEWAY_SIGNING_KEY")
    core = env["DIAL_CORE_URL"]

    probe_published_key(env, signing_key, origin)
    claims = identity_claims(env, origin)
    probe_unpublished_signer(claims, core)
    probe_gateway_signed(core, claims, SigningKey(signing_key.replace("\\n", "\n")))

    print()
    print("=== probe verdict ===")
    print("  the published kid matches the signing key, the unpublished signer is")
    print("  refused, and a gateway-signed token resolves a real identity:")
    print("  Core trusts the gateway's key through the gateway's own JWKS endpoint")
    return 0


if __name__ == "__main__":
    sys.exit(main())
