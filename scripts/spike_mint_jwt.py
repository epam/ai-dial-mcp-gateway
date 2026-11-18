"""Mint a gateway-shaped RS256 JWT and serve the matching JWKS (Stage 0 spike).

The spike asks one question: does DIAL Core accept a token this repository's gateway
would mint? Everything downstream of the answer depends on it, so the token is minted
here, offline, from a keypair generated at runtime, and shaped exactly as the gateway
mints: `iss` equal to the gateway's public origin, `sub`/`roles`/`project`/`email` read
from a real realm user's identity token, and an `aud` carrying the audience marker the
gateway's provider entry in Core is configured with.

The key and every minted token land in gitignored paths (`.gitignore` blocks `*.pem`,
`*.key`, `*.jwt`, and `.secrets/`), because a signing key is IdP-grade material: whoever
holds it can mint any identity Core will trust.

Nothing is printed but the token's non-secret shape and a redacted handle.

Usage:
    PYTHONUTF8=1 python scripts/spike_mint_jwt.py
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import (
    REPO_ROOT,
    decode_claims,
    load_env,
    minted_token_path,
    redact,
    request_user_token,
    require,
    write_secret,
)

KEY_DIR = REPO_ROOT / ".secrets"
PRIVATE_KEY_PATH = KEY_DIR / "spike-signing-key.pem"
JWKS_PATH = KEY_DIR / "spike-jwks.json"
IDENTITY_TOKEN_PATH = KEY_DIR / "spike-identity-token.jwt"
# The document a container serves to Core. Only the public JWKS ever goes in here: the
# serving directory is mounted into a container, so anything else placed beside it would
# be readable from inside the instance's network.
SERVED_DIR = KEY_DIR / "served"
SERVED_JWKS_PATH = SERVED_DIR / "jwks.json"

# The claims the gateway owns and therefore never copies from the identity token. Those
# the gateway re-states are set explicitly below; the rest are dropped because the minted
# token gets its own.
REGISTRY_CLAIMS = frozenset(
    {
        "iss",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "typ",
        "azp",
        "nonce",
        "at_hash",
        "c_hash",
        "acr",
        "cnf",
        "scope",
        "session_state",
        "sid",
    }
)


def b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def generate_keypair() -> tuple[bytes, dict, str]:
    """Generate an RSA-2048 keypair, its public JWKS document, and its key id.

    A fresh keypair per run keeps the spike honest: the spike is proving that Core trusts
    a *newly registered* signer, not that a previously cached JWK still works. The `kid`
    is derived from the public key, so a regenerated keypair is a genuinely new,
    unpublished key rather than a new key under a trusted name.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_numbers = key.public_key().public_numbers()
    modulus, exponent = b64url_uint(public_numbers.n), b64url_uint(public_numbers.e)
    kid = hashlib.sha256(f"{modulus}.{exponent}".encode()).hexdigest()[:16]
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": modulus,
                "e": exponent,
            }
        ]
    }
    return private_pem, jwks, kid


def fetch_identity_token(env: dict[str, str]) -> str:
    """Obtain a real realm user's identity token from the local Keycloak.

    The token is needed only for its claims: the minted token must carry the same
    `sub`, `roles`, `project`, and `email` a real user's token carries, because Core
    resolves the user bucket and the authorization rules from exactly those paths. The
    client used is the one whose claim mappers carry that full set.
    """
    return request_user_token(
        env, "KEYCLOAK_IDENTITY_CLIENT_ID", "KEYCLOAK_IDENTITY_CLIENT_SECRET"
    )


def copy_identity_claims(identity_token: str, issuer: str, audience: list[str]) -> dict:
    """Build the minted payload: the identity claims, minus the gateway's own, plus ours."""
    claims = decode_claims(identity_token)
    payload = {k: v for k, v in claims.items() if k not in REGISTRY_CLAIMS}

    now = datetime.now(UTC)
    payload.update(
        {
            "iss": issuer,
            "aud": audience,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=10)).timestamp()),
            # A distinct id keeps this token addressable in logs and denies reuse of a
            # previously captured one.
            "jti": base64.urlsafe_b64encode(
                int(now.timestamp() * 1_000_000).to_bytes(8, "big")
            )
            .decode()
            .rstrip("="),
        }
    )
    return payload


def published_kid() -> str:
    """The key id the currently published JWKS carries, for reuse by a control probe."""
    return json.loads(JWKS_PATH.read_text(encoding="utf-8"))["keys"][0]["kid"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--issuer",
        default=None,
        help="issuer claim to mint with (default: the .env gateway public origin)",
    )
    parser.add_argument(
        "--audience",
        default="dial-mcp-proxy",
        help="audience marker to mint with",
    )
    parser.add_argument(
        "--no-audience",
        action="store_true",
        help="mint without the audience marker (a negative control)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="sign with the key at this path instead of the published one (a control)",
    )
    parser.add_argument(
        "--unpublished-key",
        action="store_true",
        help="sign with a throwaway keypair and publish nothing — the unknown-kid control",
    )
    parser.add_argument(
        "--kid",
        default=None,
        help="key id for the token header (default: the signing key's own)",
    )
    parser.add_argument(
        "--out",
        default="default",
        help="name of the minted token file under .secrets/",
    )
    parser.add_argument(
        "--fresh-key",
        action="store_true",
        help="generate and publish a new keypair instead of reusing the published one",
    )
    args = parser.parse_args()

    env = load_env()
    issuer = args.issuer or require(env, "GATEWAY_PUBLIC_ORIGIN")

    published = PRIVATE_KEY_PATH.is_file() and JWKS_PATH.is_file()

    if args.unpublished_key:
        # A key Core has never seen. The `kid` is derived from the key itself, so it
        # cannot accidentally name the published key, and nothing is published here —
        # which is precisely what the unknown-key control needs.
        signing_key, _, kid = generate_keypair()
        print("NOTE: signing with a throwaway key and publishing nothing — the JWKS")
        print("      still holds only the previously published key.\n")
    elif args.key_file:
        signing_key = Path(args.key_file).read_bytes()
        kid = args.kid or published_kid()
        print("NOTE: signing with a supplied key under the published kid: the JWKS")
        print("      resolves the key id, so this exercises signature verification.\n")
    elif published and not args.fresh_key:
        # Reuse is the default so that every probe signed by one keypair is judged by the
        # published JWKS; a control that silently rotated the key would test the wrong
        # thing.
        signing_key = PRIVATE_KEY_PATH.read_bytes()
        kid = args.kid or published_kid()
    else:
        signing_key, jwks, kid = generate_keypair()
        write_secret(PRIVATE_KEY_PATH, signing_key.decode())
        write_secret(JWKS_PATH, json.dumps(jwks, indent=2) + "\n")
        # The served copy is the same document; keeping it at a second path is what lets
        # the serving directory hold nothing but publishable material.
        write_secret(SERVED_JWKS_PATH, json.dumps(jwks, indent=2) + "\n")
        print(f"NOTE: generated a new keypair, kid={kid}, and published its JWKS.")

    identity_token = fetch_identity_token(env)
    write_secret(IDENTITY_TOKEN_PATH, identity_token)

    audience = [] if args.no_audience else [issuer, args.audience]
    payload = copy_identity_claims(identity_token, issuer, audience)

    token = jwt.encode(payload, signing_key, algorithm="RS256", headers={"kid": kid})
    write_secret(minted_token_path(args.out), token)

    print("=== minted token (no secret material below) ===")
    for claim in ("iss", "sub", "aud", "roles", "project", "email", "exp"):
        if claim in payload:
            print(f"  {claim:8s} = {json.dumps(payload[claim])}")
    print(f"  header   = {json.dumps({'alg': 'RS256', 'kid': kid, 'typ': 'JWT'})}")
    print(f"  claims   = {sorted(payload.keys())}")
    print()
    print(f"  token    = {redact(token)}")
    print(
        f"  key      = {redact(signing_key.decode() if isinstance(signing_key, bytes) else signing_key)}"
    )
    print()
    if not args.key_file:
        print(f"private key  -> {PRIVATE_KEY_PATH.relative_to(REPO_ROOT)}")
        print(f"JWKS         -> {JWKS_PATH.relative_to(REPO_ROOT)}")
    print(f"token        -> {minted_token_path(args.out).relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
