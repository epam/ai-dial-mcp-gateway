"""The gateway's signing keyset and the JWKS Core verifies its tokens against.

The material is injected, never file content in this repository: whoever holds it can mint
an identity Core will trust for any subject, so it is treated as the deployment's own
identity-provider key. It arrives as a PEM in an environment variable or as a file on a
read-only mount, is parsed once at startup, and is never logged — not the PEM, not its
modulus, not a fingerprint derived from it.

The keyset holds one **active** entry and any number of **retained** entries. Signing is
through the active entry alone; the JWKS publishes every entry's public half, the active
entry first, so a verifier that resolves a `kid`-less token to the first published key
selects the key that signs. Verification accepts the active entry or a retained one, the
presented token's `kid` selecting within the startup-fixed keyset — a retired entry's `kid`
no longer resolves, so its removal is the immediate cut.
"""

from __future__ import annotations

import base64
import hashlib
import json

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from gateway.errors import ConfigurationError
from gateway.keysets import KeysetEntry, resolve_material
from gateway.settings import Settings

# The only algorithm Core's verifier implements for this provider class, and the size
# below which a generated key would not be taken seriously as identity-provider material.
_SIGNING_ALGORITHM = "RS256"
_MINIMUM_KEY_SIZE = 2048

# The name the singular compat setting's errors carry, so the two spellings report in their
# own vocabulary while sharing one parser.
_SINGULAR_SETTING_NAME = "gateway_signing_key"


def _b64url_uint(value: int) -> str:
    """The JWK encoding of an unsigned big-endian integer: base64url, no padding."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class SigningKey:
    """A loaded RSA private key, its key id, and the public JWK that publishes it.

    The key id is derived from the public key, so two different keys cannot present the
    same `kid` — an unpublished key is a genuinely new key rather than a new key under a
    name Core already trusts.
    """

    def __init__(
        self, private_pem: str, *, setting_name: str = _SINGULAR_SETTING_NAME
    ) -> None:
        self._setting_name = setting_name
        try:
            key = serialization.load_pem_private_key(
                private_pem.encode("utf-8"), password=None
            )
        except (ValueError, TypeError) as exc:
            # The message names the expected shape, never the material: a parsing error
            # can echo the input it choked on.
            message = (
                f"{setting_name} is not a readable PEM private key; expected an "
                f"unencrypted RSA private key in PEM form"
            )
            raise ConfigurationError(message) from exc

        if not isinstance(key, rsa.RSAPrivateKey):
            message = (
                f"{setting_name} must be an RSA private key: the identity provider "
                f"verifies tokens with RS256"
            )
            raise ConfigurationError(message)
        if key.key_size < _MINIMUM_KEY_SIZE:
            message = (
                f"{setting_name} is {key.key_size} bits; an identity-provider "
                f"signing key must be at least {_MINIMUM_KEY_SIZE} bits"
            )
            raise ConfigurationError(message)

        self._key = key
        numbers = key.public_key().public_numbers()
        modulus = _b64url_uint(numbers.n)
        exponent = _b64url_uint(numbers.e)
        self._kid = hashlib.sha256(f"{modulus}.{exponent}".encode()).hexdigest()[:16]
        self._private_pem = private_pem
        self._public_jwk = {
            "kty": "RSA",
            "use": "sig",
            "alg": _SIGNING_ALGORITHM,
            "kid": self._kid,
            "n": modulus,
            "e": exponent,
        }

    @property
    def kid(self) -> str:
        """The key id carried in every token header and published in the JWKS."""
        return self._kid

    @property
    def algorithm(self) -> str:
        return _SIGNING_ALGORITHM

    def public_jwk(self) -> dict[str, str]:
        """This key's public JWK — the member a keyset's JWKS publishes for it."""
        return self._public_jwk

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """The single-key JWKS document, for the one-active compat shape.

        Public material only: the modulus and exponent are what verification needs, and
        publishing them is the point. The private key has no representation here.
        """
        return {"keys": [self.public_jwk()]}

    def sign(self, payload: dict[str, object]) -> str:
        """Sign a JWT payload with this key."""
        return jwt.encode(
            payload,
            self._private_pem,
            algorithm=_SIGNING_ALGORITHM,
            headers={"kid": self._kid, "typ": "JWT"},
        )

    def public_key(self) -> rsa.RSAPublicKey:
        """The verification key, for decoding what this key signed.

        Exposed as a key object rather than as a PEM so a caller cannot accidentally use
        it for signing, and so verification needs no parsing step of its own.
        """
        return self._key.public_key()

    def __repr__(self) -> str:
        """A representation that carries no key material.

        The default object repr is safe today, but a dataclass or a debugger dump would
        not be: this states the rule where someone would change it.
        """
        return f"SigningKey(kid={self._kid!r}, algorithm={self.algorithm!r})"


def load_signing_key(settings: Settings) -> SigningKey:
    """Load the configured signing key, refusing to start without a usable one.

    The refusal is loud and specific because the alternative is a service that starts,
    serves discovery documents, and cannot mint a token — a failure whose symptom
    appears at a harness, far from its cause.

    This is the no-rotation shape: it loads the singular `gateway_signing_key` (or, where
    the structured keyset is configured, the keyset's single active entry) as the one key.
    A deployment with retained entries goes through `load_signing_keyset`.
    """
    keyset = load_signing_keyset(settings)
    return keyset.active


class SigningKeyset:
    """The loaded signing keyset: the active entry that signs, and every published entry.

    Signing goes through the active entry alone. Verification selects an entry by the
    presented token's `kid` within this startup-fixed set — never from a fetch, never from
    header-carried material. The JWKS publishes every entry's public half with the active
    entry first.
    """

    def __init__(self, entries: list[tuple[str, SigningKey]]) -> None:
        self._entries = entries
        self._by_kid = {key.kid: key for _id, key in entries}

    @property
    def active(self) -> SigningKey:
        """The entry every token is signed with."""
        return self._entries[0][1]

    @property
    def active_kid(self) -> str:
        return self.active.kid

    def get(self, kid: str) -> SigningKey | None:
        """The entry a `kid` names, or `None` when it names none of this keyset's entries."""
        return self._by_kid.get(kid)

    def key_for_token(self, token: str) -> SigningKey | None:
        """The entry a presented token's `kid` selects, or `None` when it names none.

        The `kid` is read from the token's unverified header and resolved only against the
        startup-fixed keyset — never a fetch, never header-carried material. A token whose
        header carries no `kid`, an unreadable header, or a `kid` naming no entry (a removed
        retained key's included) all return `None`, so each caller maps that to its own
        refusal class: a token this gateway cannot verify is one it did not issue.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None
        kid = header.get("kid")
        return self._by_kid.get(kid) if isinstance(kid, str) else None

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Every entry's public half, active first.

        The ordering is the contract with a kid-less verifier (Core's own resolution rule):
        the first published key is the one that signs.
        """
        return {"keys": [key.public_jwk() for _id, key in self._entries]}

    def __repr__(self) -> str:
        return f"SigningKeyset(kids={[key.kid for _id, key in self._entries]!r})"


def _entries_from_settings(settings: Settings) -> list[KeysetEntry]:
    """The signing keyset as normalized entries, folding the singular compat spelling in.

    The singular `gateway_signing_key` is one active `env`-sourced entry, and the structured
    `gateway_signing_keys` is the multi-entry shape. The two configured simultaneously is a
    settings-level refusal; here at most one is present, or neither.
    """
    if settings.gateway_signing_keys:
        return [
            KeysetEntry(
                id=entry_id,
                source=configured.source,
                role=configured.role,
                ref=configured.ref,
            )
            for entry_id, configured in settings.gateway_signing_keys.items()
        ]
    singular = settings.gateway_signing_key
    if singular is not None:
        return [
            KeysetEntry(
                id=_SINGULAR_SETTING_NAME,
                source="env",
                role="active",
                material=singular.get_secret_value(),
            )
        ]
    return []


def load_signing_keyset(settings: Settings) -> SigningKeyset:
    """Load the configured signing keyset, refusing to start on anything unusable.

    The refusal is loud and specific because the alternative is a service that starts,
    serves discovery documents, and cannot mint a token — a failure whose symptom appears
    at a harness, far from its cause. On top of the settings-level checks (one active entry,
    the reserved `kms` value), this loader parses every entry's material and refuses two
    entries that derive the same `kid`: the `kid` is a truncated hash over the public
    numbers, so a shared one is either the same key configured twice or a collision between
    two distinct keys, and the refusal stands either way because one `kid` must name exactly
    one entry. Every message names entries by their configured ids only.
    """
    entries = _entries_from_settings(settings)
    if not entries:
        message = (
            "gateway_signing_key is not set and gateway_signing_keys configures no entry: "
            "the gateway has no key to sign tokens with. Generate an RSA key and set "
            "GATEWAY_SIGNING_KEY in .env, or configure the GATEWAY_SIGNING_KEYS keyset"
        )
        raise ConfigurationError(message)

    loaded: list[tuple[bool, str, SigningKey]] = []
    kids: dict[str, str] = {}
    for entry in entries:
        raw = resolve_material(entry)
        # An environment or file value cannot carry real newlines in every deployment path;
        # the escaped form is what a secret store or a compose interpolation produces.
        key = SigningKey(
            raw.replace("\\n", "\n"),
            setting_name=f"signing keyset entry {entry.id!r}",
        )
        holder = kids.get(key.kid)
        if holder is not None:
            message = (
                f"signing keyset entries {holder!r} and {entry.id!r} derive the same key "
                f"id: one `kid` must name exactly one entry, whether the same key is "
                f"configured twice or two distinct keys collide in the truncated hash"
            )
            raise ConfigurationError(message)
        kids[key.kid] = entry.id
        loaded.append((entry.is_active, entry.id, key))

    # The active entry is published first and signs; retained entries follow. The settings
    # model guarantees exactly one active entry.
    active = [(entry_id, key) for is_active, entry_id, key in loaded if is_active]
    retained = [(entry_id, key) for is_active, entry_id, key in loaded if not is_active]
    return SigningKeyset(active + retained)


def jwks_document(signing_key: SigningKey | SigningKeyset) -> str:
    """The JWKS as its wire form, used by the endpoint and by deployment checks."""
    return json.dumps(signing_key.jwks())
