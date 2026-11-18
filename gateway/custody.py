"""Custody of the identity provider's session refresh token.

The gateway carries exactly one credential per live refresh session: the provider's
*current* session-bound refresh token, held as an encrypted claim inside the gateway's own
refresh token. There is no long-lived per-session store — the ciphertext rides the token
the harness stores, and the key that opens it never leaves this process.

The envelope is pinned here, in code, so nothing about it is negotiable at runtime:

* **AES-256-GCM.** An AEAD with no padding, so a tampered, truncated, or spliced envelope
  fails the tag check with no partial plaintext released, and there is no padding-oracle
  class to probe.
* **A 256-bit key and a 96-bit random nonce.** Both lengths are constants. The key's length
  is enforced at startup (`gateway/settings.py`), because `AESGCM` would otherwise follow a
  shorter key's length and silently run AES-128 or AES-192 for the key's whole life.
* **`version | key-id | nonce | ciphertext‖tag`**, base64url. The version and key-id are
  clear header bytes and are bound into the AEAD's associated data, so a header transplanted
  from another envelope fails the tag rather than selecting a different key.

The plaintext is a small JSON document carrying the provider token, the refresh token's
signed subject, and the envelope's own expiry. The subject and the expiry are checked here,
at the seam, before any use: the tag covers *integrity*, and the subject check covers
*placement* — a blob moved between two users' refresh tokens would otherwise decrypt
perfectly. The plaintext exists only inside `encrypt`/`decrypt` and, once, at the grant's
outbound presentation; it is never logged and never delivered.

The key itself follows `gateway/keys.py`'s discipline: never logged, never in a `repr`.

Sealing is always under the **active** key; opening accepts the active key or any
**retained** one, the envelope's own key-id selecting which. A superseded key retained for
a drain window therefore keeps every outstanding blob usable through a routine rotation,
and each such presentation re-seals under the active key. Removing a retained key is the
immediate cut: its outstanding blobs refuse at their next presentation in this module's one
refusal class.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# The envelope's version byte. A future format reads a different value; today's reader
# refuses anything that is not this one.
ENVELOPE_VERSION = 1

# The pinned algorithm's lengths, in bytes. Never read from the envelope: the envelope
# carries a version and a key id, and nothing that could select the algorithm or its
# parameters.
KEY_BYTES = 32
NONCE_BYTES = 12

# The longest key id the header can carry, which bounds the one length the header states.
KEY_ID_MAX_BYTES = 32

# The layout's fixed parts, so the parser can be read against the picture above.
_VERSION_BYTES = 1
_LENGTH_BYTES = 1

# The JSON members of the plaintext. Short names, because every byte here expands by four
# thirds on the way into the base64url envelope the refresh token carries.
_SUBJECT_MEMBER = "s"
_EXPIRY_MEMBER = "e"
_TOKEN_MEMBER = "t"  # noqa: S105  # nosec B105 - a JSON member name, not a credential


# The AEAD tag's length, which the envelope carries after the ciphertext.
TAG_BYTES = 16

# The plaintext's JSON scaffolding around the token, the subject, and the expiry: the two
# short member names, their quotes and separators, the braces, and a subject and expiry of
# generous length. Stated rather than computed because it is an allowance the size-bound
# coupling in `gateway/settings.py` adds, and an allowance has to be a number.
_PLAINTEXT_SCAFFOLDING_BYTES = 128


class CustodyError(Exception):
    """An envelope that cannot be used, with a message safe to log.

    One refusal class for every way the custody seam can fail — absent, malformed,
    tampered, under an unknown key id or version, expired, or bound to another subject.
    The audit trail names the class as its own token, so a custody-key mistake or a botched
    rotation never reads as a provider event.
    """


def decode_custody_key(value: str) -> bytes:
    """A configured custody key as its raw bytes, or a refusal naming what is wrong.

    One spelling, base64, because it is what `openssl rand -base64 32` prints and what an
    operator can paste into `.env` without a second tool. Both the standard and the URL-safe
    alphabets are accepted, with or without padding, since the two differ only in two
    characters and refusing one of them would be a refusal about nothing.
    """
    normalized = value.strip().replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        raw = base64.b64decode(normalized, validate=True)
    except (binascii.Error, ValueError) as exc:
        message = (
            "a custody key must be base64; generate one with `openssl rand -base64 32`"
        )
        raise CustodyError(message) from exc
    if len(raw) != KEY_BYTES:
        message = (
            f"a custody key must be exactly {KEY_BYTES} bytes ({KEY_BYTES * 8} bits) "
            f"before base64; this one is {len(raw)} bytes. AES-GCM follows the key's "
            f"length, so a shorter key would silently run a weaker cipher"
        )
        raise CustodyError(message)
    return raw


def custody_key_id_is_valid(key_id: str) -> bool:
    """Whether a key id fits the header's one length-prefixed field.

    The id is a header byte string, not a credential: it names which key encrypted the
    blob so a rotation can be diagnosed. The bound is what keeps the header decodable.
    """
    if not key_id:
        return False
    try:
        encoded = key_id.encode("ascii")
    except UnicodeEncodeError:
        return False
    return 0 < len(encoded) <= KEY_ID_MAX_BYTES


class CustodyKey:
    """One custody key: the AESGCM cipher and the id that names it.

    A key seals and opens envelopes under its own key-id, which is carried in the clear
    header and bound into the AAD. A `CustodyKeyset` holds one active key (the only one
    that seals) plus any retained keys (which open only).
    """

    def __init__(self, key_id: str, key: bytes) -> None:
        if len(key) != KEY_BYTES:
            message = f"a custody key must be exactly {KEY_BYTES} bytes"
            raise CustodyError(message)
        if not custody_key_id_is_valid(key_id):
            message = (
                f"a custody key id must be 1 to {KEY_ID_MAX_BYTES} ASCII characters"
            )
            raise CustodyError(message)
        self._key_id = key_id
        self._key_id_bytes = key_id.encode("ascii")
        self._cipher = AESGCM(key)

    @property
    def key_id(self) -> str:
        """The key id carried in the envelope's header and bound into its AAD."""
        return self._key_id

    def encrypt(self, *, subject: str, expires_at: int, token: str) -> str:
        """Seal a provider token into a base64url envelope bound to one subject.

        `expires_at` is the refresh token's own absolute expiry: the envelope must not
        outlive the token that carries it, because past that instant the gateway refuses
        the token before the claim is ever touched.
        """
        plaintext = json.dumps(
            {
                _SUBJECT_MEMBER: subject,
                _EXPIRY_MEMBER: int(expires_at),
                _TOKEN_MEMBER: token,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        header = self._header()
        nonce = secrets.token_bytes(NONCE_BYTES)
        sealed = self._cipher.encrypt(nonce, plaintext, header)
        return _b64url(header + nonce + sealed)

    def decrypt(self, claim: str, *, subject: str, now: int | None = None) -> str:
        """Open an envelope and return the provider token, or refuse it.

        Every check fails closed and lands on the one `CustodyError` class: the envelope's
        shape and version, the key id (an unknown one is a superseded key after a rotation,
        or a blob from another deployment), the AEAD tag, the embedded subject, and the
        embedded expiry. The order is the cheapest first, and the tag check is the one that
        makes everything after it trustworthy.
        """
        header_end = _VERSION_BYTES + _LENGTH_BYTES + len(self._key_id_bytes)
        try:
            raw = _unb64url(claim)
        except (binascii.Error, ValueError) as exc:
            message = "the custody claim is not a readable envelope"
            raise CustodyError(message) from exc

        if len(raw) < header_end + NONCE_BYTES + 1:
            message = "the custody claim is too short to be an envelope"
            raise CustodyError(message)

        version = raw[0]
        if version != ENVELOPE_VERSION:
            message = (
                f"the custody claim carries an unknown envelope version ({version})"
            )
            raise CustodyError(message)

        key_id_length = raw[_VERSION_BYTES]
        if key_id_length != len(self._key_id_bytes):
            message = "the custody claim was sealed under another key id"
            raise CustodyError(message)
        carried_key_id = raw[_VERSION_BYTES + _LENGTH_BYTES : header_end]
        if carried_key_id != self._key_id_bytes:
            message = "the custody claim was sealed under another key id"
            raise CustodyError(message)

        header = raw[:header_end]
        nonce = raw[header_end : header_end + NONCE_BYTES]
        sealed = raw[header_end + NONCE_BYTES :]
        try:
            plaintext = self._cipher.decrypt(nonce, sealed, header)
        except InvalidTag as exc:
            message = "the custody claim failed its integrity check"
            raise CustodyError(message) from exc

        try:
            document = json.loads(plaintext)
        except ValueError as exc:
            message = "the custody claim's contents are not readable"
            raise CustodyError(message) from exc
        if not isinstance(document, dict):
            message = "the custody claim's contents are not readable"
            raise CustodyError(message)

        embedded_subject = document.get(_SUBJECT_MEMBER)
        if not isinstance(embedded_subject, str) or embedded_subject != subject:
            message = "the custody claim is bound to a different subject"
            raise CustodyError(message)
        expiry = document.get(_EXPIRY_MEMBER)
        if not isinstance(expiry, int) or expiry <= (
            now if now is not None else int(time.time())
        ):
            message = "the custody claim has expired"
            raise CustodyError(message)
        token = document.get(_TOKEN_MEMBER)
        if not isinstance(token, str) or not token:
            message = "the custody claim carries no provider token"
            raise CustodyError(message)
        return token

    def _header(self) -> bytes:
        """The clear header: the version byte and the length-prefixed key id.

        Bound into the AEAD as associated data, so the header is authenticated without
        being encrypted — a header transplanted between envelopes fails the tag.
        """
        return bytes([ENVELOPE_VERSION, len(self._key_id_bytes)]) + self._key_id_bytes

    def __repr__(self) -> str:
        """A representation that carries no key material.

        The default object repr is safe today, but a dataclass or a debugger dump would
        not be: this states the rule where someone would change it.
        """
        return f"CustodyKey(key_id={self._key_id!r})"


class CustodyKeyset:
    """The custody keyset: the active key that seals, plus any retained keys that open.

    Sealing is always under the active key, so every newly sealed blob carries the active
    key-id. Opening looks the envelope's own key-id up across the active key and the
    retained ones, so a superseded key retained for a drain window keeps its outstanding
    blobs usable; an unknown key-id (a removed entry's, or another deployment's) refuses
    before any decrypt, exactly as the single-key seam refused a foreign key-id.
    """

    def __init__(
        self, active: CustodyKey, retained: list[CustodyKey] | None = None
    ) -> None:
        self._active = active
        self._by_key_id = {active.key_id: active}
        for key in retained or []:
            self._by_key_id[key.key_id] = key

    @property
    def active(self) -> CustodyKey:
        """The one key that seals; every newly issued envelope carries its key-id."""
        return self._active

    @property
    def key_id(self) -> str:
        """The active key's id, the id every newly sealed envelope the keyset writes carries."""
        return self._active.key_id

    def encrypt(self, *, subject: str, expires_at: int, token: str) -> str:
        """Seal a provider token under the active key alone.

        Sealing never looks back: a retained key opens, it never seals, so a rotation's new
        envelopes all carry the new active key-id and the overlap shrinks as sessions
        present.
        """
        return self._active.encrypt(subject=subject, expires_at=expires_at, token=token)

    def decrypt(self, claim: str, *, subject: str, now: int | None = None) -> str:
        """Open an envelope under the key its header names, active or retained.

        The key-id is read from the envelope's clear header and selected against the
        keyset; an id naming no entry refuses in the custody class before any decrypt, and
        the selected key then runs its own checks (tag, subject, expiry). A malformed
        envelope that carries no readable header refuses the same way.
        """
        key_id = carried_key_id(claim)
        key = self._by_key_id.get(key_id) if key_id is not None else None
        if key is None:
            message = (
                "the custody claim was sealed under a key this gateway does not hold"
            )
            raise CustodyError(message)
        return key.decrypt(claim, subject=subject, now=now)

    def __repr__(self) -> str:
        return f"CustodyKeyset(key_ids={list(self._by_key_id)!r})"


def carried_key_id(claim: str) -> str | None:
    """The key-id an envelope's clear header carries, or `None` when it carries none.

    The header is `version | key-id-length | key-id`, unencrypted by design; a value too
    short or in an unknown version to carry a header yields `None`, which the keyset turns
    into the same unknown-key refusal a removed entry's id earns.
    """
    try:
        raw = _unb64url(claim)
    except (binascii.Error, ValueError):
        return None
    header_end = _VERSION_BYTES + _LENGTH_BYTES
    if len(raw) < header_end:
        return None
    if raw[0] != ENVELOPE_VERSION:
        return None
    key_id_length = raw[_VERSION_BYTES]
    if key_id_length == 0 or len(raw) < header_end + key_id_length:
        return None
    try:
        return raw[header_end : header_end + key_id_length].decode("ascii")
    except UnicodeDecodeError:
        return None


def envelope_bytes_for_token(provider_token_max_bytes: int) -> int:
    """The envelope's size for a provider token at the configured bound.

    The refresh request's form body carries the envelope inside the gateway's own refresh
    token, so this is the part of that body the custody design is responsible for: the
    plaintext (the token plus the JSON around it), the ciphertext of the same length, the
    AEAD tag, the nonce, the header, and the base64 expansion of all of it. Stated as a
    function so the settings model can hold the two bounds together rather than leaving
    the relationship to a comment.
    """
    plaintext = provider_token_max_bytes + _PLAINTEXT_SCAFFOLDING_BYTES
    sealed = plaintext + TAG_BYTES
    framed = _VERSION_BYTES + _LENGTH_BYTES + KEY_ID_MAX_BYTES + NONCE_BYTES + sealed
    # base64url's expansion, rounded up to whole characters.
    return (framed * 4 + 2) // 3


def _b64url(raw: bytes) -> str:
    """base64url without padding, the one spelling the envelope is written in."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(value: str) -> bytes:
    """The bytes a base64url string carries, padding restored.

    The alphabet is translated back to the standard one before decoding, and `validate=True`
    refuses a character outside it rather than silently ignoring it in part — the envelope is
    a wire value, and a value this gateway did not write is not one it should guess at.
    """
    normalized = value.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    return base64.b64decode(normalized, validate=True)
