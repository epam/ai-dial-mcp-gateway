"""Tests for the signing and custody keysets (the C3 keyset seam).

Two layers are asserted here, because they protect different properties:

* **The settings schema and its refusals**: the structured signing keyset (per-entry
  `source`/`ref`/`role`), the structured custody keyset beside the flat compat spelling, the
  mutual-exclusion of the two signing spellings, the reserved `kms` refusal, the
  zero-/multi-active refusals, the mixed-custody-document refusal, and the `file`-source
  refusals — each naming entries by configured id or path only, never material.
* **The loaded keysets' behavior**: the JWKS publishes every entry's public half with the
  active entry first; verification selects by `kid` (a retained key verifies, an unknown
  `kid` refuses); signing is through the active entry alone; custody seals under the active
  key and opens by the envelope's key-id across active-or-retained.

Synthetic keys are generated per test; nothing here is committed material.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from pathlib import Path

import jwt
import pytest
from gateway.custody import (
    KEY_BYTES,
    CustodyError,
    CustodyKey,
    CustodyKeyset,
    carried_key_id,
)
from gateway.errors import ConfigurationError
from gateway.keys import (
    SigningKey,
    jwks_document,
    load_signing_keyset,
)
from gateway.settings import Settings
from gateway.tokens import decode_own_token
from pydantic import ValidationError

from tests.conftest import (
    CUSTODY_KEY_B64,
    CUSTODY_KEY_ID,
    generate_key_pem,
    make_settings,
)

# A subject and a token the custody tests seal, standing in for a refresh session.
SUBJECT = "3a0d60f4-0000-0000-0000-000000000000"
PROVIDER_TOKEN = "the-provider-session-refresh-token"
ISSUER = "http://localhost:8090"


def _custody_key_b64() -> str:
    """A fresh base64 32-byte custody key, for a test that needs one of its own."""
    return base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode()


def _a_custody_key(key_id: str) -> CustodyKey:
    return CustodyKey(key_id, secrets.token_bytes(KEY_BYTES))


# ------------------------------------------------ the signing keyset: schema refusals


def test_both_signing_spellings_configured_refuse_startup() -> None:
    """The singular setting and the structured keyset have no single reading together.

    The singular setting means "one active key, no retention"; the structured setting means
    a keyset. Configuring both leaves two candidate active keys, so startup refuses naming
    both settings rather than guessing.
    """
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_signing_key=generate_key_pem(),
            gateway_signing_keys={
                "k1": {"source": "env", "ref": "SIGNING_KEY_ENV", "role": "active"}
            },
        )

    message = str(refused.value)
    assert "gateway_signing_key" in message
    assert "gateway_signing_keys" in message


# ------------------------------- the singular signing key's blank normalization (C3)


def test_a_blank_singular_signing_key_beside_a_keyset_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blank singular counts as unset, so the structured keyset is authoritative.

    The composition path fronts every setting explicitly, so an unset singular arrives as
    an empty string rather than as absent. Read as unset, it does not count as configuring
    the spelling and the structured keyset signs.
    """
    pem = generate_key_pem()
    monkeypatch.setenv("SIGNING_KEY_STRUCTURED", pem)
    settings = make_settings(
        gateway_signing_key="",
        gateway_signing_keys={
            "only": {
                "source": "env",
                "ref": "SIGNING_KEY_STRUCTURED",
                "role": "active",
            }
        },
    )

    assert settings.gateway_signing_key is None
    loaded = load_signing_keyset(settings)
    assert loaded.active.kid == SigningKey(pem).kid


def test_a_whitespace_singular_signing_key_beside_a_keyset_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A whitespace-only singular is as unset as an empty one, so the keyset signs.

    The blank class is "empty or whitespace-only": the normalization strips before it
    decides, so a value that is spaces alone never counts as a configured spelling.
    """
    pem = generate_key_pem()
    monkeypatch.setenv("SIGNING_KEY_STRUCTURED", pem)
    settings = make_settings(
        gateway_signing_key="   ",
        gateway_signing_keys={
            "only": {
                "source": "env",
                "ref": "SIGNING_KEY_STRUCTURED",
                "role": "active",
            }
        },
    )

    assert settings.gateway_signing_key is None
    loaded = load_signing_keyset(settings)
    assert loaded.active.kid == SigningKey(pem).kid


def test_a_real_singular_signing_key_beside_a_keyset_refuses_naming_both() -> None:
    """A real singular beside a keyset leaves two candidate active keys: refused.

    The both-configured refusal fires on a real value only — the matrix's control against
    the blank cases above, which read the same singular shape as unconfigured.
    """
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_signing_key=generate_key_pem(),
            gateway_signing_keys={
                "k1": {"source": "env", "ref": "SIGNING_KEY_ENV", "role": "active"}
            },
        )

    message = str(refused.value)
    assert "gateway_signing_key" in message
    assert "gateway_signing_keys" in message


def test_a_blank_singular_signing_key_alone_refuses_as_neither_configured() -> None:
    """A blank singular with no keyset is the missing-key refusal, never a parse refusal.

    Read as unset by the field, the singular reaches the loader's fold as no entry at all,
    so the refusal names the setting as unset rather than failing to parse empty material
    as a PEM.
    """
    settings = make_settings(gateway_signing_key="")

    assert settings.gateway_signing_key is None
    with pytest.raises(ConfigurationError) as refused:
        load_signing_keyset(settings)

    message = str(refused.value)
    assert "gateway_signing_key is not set" in message
    assert "PEM" not in message


def test_a_blank_structured_keyset_beside_a_real_singular_is_accepted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blank structured keyset is unset, so the real singular is honored.

    The always-on compose shape: both signing settings are forwarded, the structured one
    blank and the singular real. The blank keyset parses to no document, leaving the
    singular as the one configured spelling — the compat deployment's own start.
    """
    pem = generate_key_pem()
    settings = make_settings(gateway_signing_key=pem, gateway_signing_keys="")

    assert settings.gateway_signing_keys == {}
    loaded = load_signing_keyset(settings)
    assert loaded.active.kid == SigningKey(pem).kid


def test_a_zero_active_signing_keyset_refuses_startup() -> None:
    """A keyset with no active entry has no key to sign with, so it cannot start."""
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_signing_keys={
                "old": {"source": "env", "ref": "SIGNING_KEY_OLD", "role": "retained"}
            }
        )

    message = str(refused.value)
    assert "gateway_signing_keys" in message
    assert "0 active" in message


def test_a_multi_active_signing_keyset_refuses_startup() -> None:
    """Two active entries mean two keys that sign: exactly one entry signs."""
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_signing_keys={
                "a": {"source": "env", "ref": "SIGNING_KEY_A", "role": "active"},
                "b": {"source": "env", "ref": "SIGNING_KEY_B", "role": "active"},
            }
        )

    message = str(refused.value)
    assert "gateway_signing_keys" in message
    assert "2 active" in message


def test_a_kms_sourced_signing_entry_refuses_startup_naming_the_gap() -> None:
    """The reserved source is refused, never ignored and never fallen back.

    A deployment that configured `kms` believes it holds KMS-protected material; the
    refusal names the gap so that belief is corrected at the first start.
    """
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_signing_keys={
                "k1": {"source": "kms", "ref": "some-key-ref", "role": "active"}
            }
        )

    message = str(refused.value)
    assert "k1" in message
    assert "kms" in message
    assert "KMS sign-interface is not built" in message


def test_an_unknown_source_on_a_signing_entry_refuses_startup() -> None:
    """A source outside the vocabulary is refused as unknown, not treated as a third kind."""
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_signing_keys={
                "k1": {"source": "vault", "ref": "x", "role": "active"}
            }
        )

    assert "vault" in str(refused.value)


def test_a_signing_entry_carrying_an_unknown_member_is_refused_at_parse() -> None:
    """A misspelled field is refused loudly, naming it, rather than silently ignored."""
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_signing_keys={
                "k1": {
                    "source": "env",
                    "ref": "SIGNING_KEY_A",
                    "role": "active",
                    "rotated": True,
                }
            }
        )

    assert "rotated" in str(refused.value)


# ------------------------------------------------ the signing keyset: load and behavior


def _keyset_settings(**overrides: object) -> Settings:
    """Settings carrying a two-entry signing keyset (one active, one retained)."""
    values: dict[str, object] = {
        "gateway_signing_keys": {
            "active-key": {
                "source": "env",
                "ref": "SIGNING_KEY_ACTIVE",
                "role": "active",
            },
            "retained-key": {
                "source": "env",
                "ref": "SIGNING_KEY_RETAINED",
                "role": "retained",
            },
        }
    }
    values.update(overrides)
    return make_settings(**values)


def test_a_file_sourced_signing_entry_loads_and_refuses_a_missing_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `file` entry loads from its path; an unreadable path refuses naming the path.

    The two halves are one test because they are one behavior: the file source is read at
    startup, and a path that cannot be read is refused loudly (never silently downgraded to
    env, never falling back to another source).
    """
    key_file = tmp_path / "signing-key.pem"
    key_file.write_text(generate_key_pem(), encoding="utf-8")
    monkeypatch.setenv("SIGNING_KEY_ACTIVE", generate_key_pem())

    loaded = load_signing_keyset(
        make_settings(
            gateway_signing_keys={
                "act": {"source": "env", "ref": "SIGNING_KEY_ACTIVE", "role": "active"},
                "old": {
                    "source": "file",
                    "ref": str(key_file),
                    "role": "retained",
                },
            }
        )
    )
    # The file-sourced retained entry loads and behaves as any retained entry does.
    entry_count = 2  # one active entry, one retained
    assert len(loaded.jwks()["keys"]) == entry_count

    missing = tmp_path / "no-such-key.pem"
    with pytest.raises(ConfigurationError) as refused:
        load_signing_keyset(
            make_settings(
                gateway_signing_keys={
                    "act": {
                        "source": "env",
                        "ref": "SIGNING_KEY_ACTIVE",
                        "role": "active",
                    },
                    "old": {"source": "file", "ref": str(missing), "role": "retained"},
                }
            )
        )
    message = str(refused.value)
    assert "no-such-key.pem" in message
    assert "old" in message
    # The material never reaches the message: the file was never read.
    assert "PRIVATE KEY" not in message


def test_a_source_heterogeneous_keyset_is_valid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A retained `env` entry beside an active `file` entry is accepted.

    The source is per-entry, so the future migration to a KMS-sourced active key is a
    rotation beside retained injected keys, not a redesign.
    """
    pem = generate_key_pem()
    key_file = tmp_path / "active.pem"
    key_file.write_text(pem, encoding="utf-8")
    monkeypatch.setenv("SIGNING_KEY_RETAINED", generate_key_pem())

    loaded = load_signing_keyset(
        make_settings(
            gateway_signing_keys={
                "act": {"source": "file", "ref": str(key_file), "role": "active"},
                "old": {
                    "source": "env",
                    "ref": "SIGNING_KEY_RETAINED",
                    "role": "retained",
                },
            }
        )
    )

    assert loaded.active.kid == SigningKey(pem).kid
    entry_count = 2  # one active entry, one retained
    assert len(loaded.jwks()["keys"]) == entry_count


def test_two_entries_deriving_the_same_kid_refuse_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A shared `kid` is refused naming both entries — one `kid` names one entry.

    The refusal closes both shapes: the same key configured under two names, and a
    collision between two distinct keys in the truncated hash.
    """
    pem = generate_key_pem()
    monkeypatch.setenv("SIGNING_KEY_A", pem)
    monkeypatch.setenv("SIGNING_KEY_B", pem)

    with pytest.raises(ConfigurationError) as refused:
        load_signing_keyset(
            make_settings(
                gateway_signing_keys={
                    "a": {"source": "env", "ref": "SIGNING_KEY_A", "role": "active"},
                    "b": {"source": "env", "ref": "SIGNING_KEY_B", "role": "retained"},
                }
            )
        )

    message = str(refused.value)
    assert "'a'" in message
    assert "'b'" in message
    assert "same key id" in message


def test_the_jwks_publishes_every_entry_with_the_active_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every entry's public half is published, the active entry first.

    The ordering is the contract with a kid-less verifier: the first published key is the
    one that signs.
    """
    active_pem = generate_key_pem()
    retained_pem = generate_key_pem()
    monkeypatch.setenv("SIGNING_KEY_ACTIVE", active_pem)
    monkeypatch.setenv("SIGNING_KEY_RETAINED", retained_pem)

    loaded = load_signing_keyset(_keyset_settings())
    document = json.loads(jwks_document(loaded))
    kids = [jwk["kid"] for jwk in document["keys"]]

    entry_count = 2  # the keyset holds one active entry and one retained
    assert len(kids) == entry_count
    assert kids[0] == SigningKey(active_pem).kid
    assert kids[1] == SigningKey(retained_pem).kid
    # Public material only: no private component of any entry reaches the document.
    for jwk in document["keys"]:
        assert set(jwk) == {"kty", "use", "alg", "kid", "n", "e"}


def test_signing_goes_through_the_active_entry_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every minted token carries the active entry's `kid`, never a retained one's."""
    active_pem = generate_key_pem()
    monkeypatch.setenv("SIGNING_KEY_ACTIVE", active_pem)
    monkeypatch.setenv("SIGNING_KEY_RETAINED", generate_key_pem())

    loaded = load_signing_keyset(_keyset_settings())
    token = loaded.active.sign({"sub": "someone"})

    assert jwt.get_unverified_header(token)["kid"] == loaded.active.kid


def test_a_retained_key_token_verifies_and_a_removed_kid_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The drain window's whole point, and the immediate cut's verification-side effect.

    A token signed under a retained key verifies while the entry is present; once the entry
    is removed, its `kid` names no entry and the token is refused as not issued by this
    gateway.
    """
    retained_pem = generate_key_pem()
    monkeypatch.setenv("SIGNING_KEY_ACTIVE", generate_key_pem())
    monkeypatch.setenv("SIGNING_KEY_RETAINED", retained_pem)
    retained_token = SigningKey(retained_pem).sign(
        {"sub": "someone", "iss": ISSUER, "typ": "access"}
    )

    with_entry = load_signing_keyset(_keyset_settings())
    payload = decode_own_token(
        with_entry, retained_token, issuer=ISSUER, expected_type="access"
    )
    assert payload["sub"] == "someone"

    # Without the retained entry (the cut), the same token's `kid` names nothing.
    without_entry = load_signing_keyset(
        make_settings(
            gateway_signing_keys={
                "active-key": {
                    "source": "env",
                    "ref": "SIGNING_KEY_ACTIVE",
                    "role": "active",
                }
            }
        )
    )
    with pytest.raises(Exception, match="not issued by this gateway"):
        decode_own_token(
            without_entry, retained_token, issuer=ISSUER, expected_type="access"
        )


def test_the_singular_spelling_constructs_the_same_one_active_keyset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compat spelling rides the same code path as the structured one-active keyset.

    The singular `gateway_signing_key` and a structured keyset holding exactly one active
    `env` entry loading the same material produce the same active key and the same JWKS —
    the compat shape is one code path, not a parallel one.
    """
    pem = generate_key_pem()
    monkeypatch.setenv("SIGNING_KEY_ONLY", pem)
    singular = load_signing_keyset(make_settings(gateway_signing_key=pem))
    structured = load_signing_keyset(
        make_settings(
            gateway_signing_keys={
                "only": {
                    "source": "env",
                    "ref": "SIGNING_KEY_ONLY",
                    "role": "active",
                }
            }
        )
    )

    assert singular.active.kid == structured.active.kid == SigningKey(pem).kid
    assert (
        singular.jwks() == structured.jwks() == {"keys": [SigningKey(pem).public_jwk()]}
    )


def test_an_empty_signing_keyset_refuses_startup() -> None:
    """No key in either spelling is the pre-existing missing-key refusal, by name."""
    with pytest.raises(ConfigurationError, match="gateway_signing_key"):
        load_signing_keyset(make_settings())


# ------------------------------------------------ the custody keyset: schema refusals


def test_the_flat_custody_spelling_is_one_active_env_entry() -> None:
    """The pre-keyset flat spelling means one active env-sourced key, no retention."""
    settings = make_settings(gateway_custody_keys={CUSTODY_KEY_ID: CUSTODY_KEY_B64})
    keyset = settings.custody_keyset

    assert keyset.active.key_id == CUSTODY_KEY_ID


def test_the_structured_custody_spelling_carries_retained_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The structured spelling accepts an active entry beside retained ones.

    Both entries are loaded: a blob sealed under the retained key's own material opens
    through the keyset, which is what carrying a retained entry means.
    """
    old_material = _custody_key_b64()
    monkeypatch.setenv("CUSTODY_ACTIVE", _custody_key_b64())
    monkeypatch.setenv("CUSTODY_OLD", old_material)
    settings = make_settings(
        gateway_custody_keys={
            "active-key": {"source": "env", "ref": "CUSTODY_ACTIVE", "role": "active"},
            "old-key": {"source": "env", "ref": "CUSTODY_OLD", "role": "retained"},
        }
    )

    keyset = settings.custody_keyset
    assert keyset.active.key_id == "active-key"
    retained = CustodyKey("old-key", base64.b64decode(old_material))
    claim = retained.encrypt(
        subject=SUBJECT, expires_at=int(time.time()) + 600, token=PROVIDER_TOKEN
    )
    assert keyset.decrypt(claim, subject=SUBJECT) == PROVIDER_TOKEN


def test_a_mixed_custody_document_refuses_startup() -> None:
    """One spelling per document: a flat entry and a structured one cannot coexist.

    The flat shape cannot carry retention, so a mixed document would let a compat shape
    carry it by accident; the refusal names the keyset.
    """
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_custody_keys={
                "flat": _custody_key_b64(),
                "structured": {
                    "source": "env",
                    "ref": "CUSTODY_ACTIVE",
                    "role": "active",
                },
            }
        )

    assert "gateway_custody_keys" in str(refused.value)
    assert "mixes" in str(refused.value)


def test_a_structured_custody_keyset_with_no_active_entry_refuses_startup() -> None:
    """Exactly one key seals; a keyset holding only retained entries cannot seal."""
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_custody_keys={
                "old-key": {
                    "source": "env",
                    "ref": "CUSTODY_OLD",
                    "role": "retained",
                }
            }
        )

    message = str(refused.value)
    assert "gateway_custody_keys" in message
    assert "0 active" in message


def test_a_kms_sourced_custody_entry_refuses_startup_naming_the_gap() -> None:
    """The custody `kms` refusal names the envelope interface's gap, not the sign one's."""
    with pytest.raises(ValidationError) as refused:
        make_settings(
            gateway_custody_keys={
                "k1": {"source": "kms", "ref": "some-key", "role": "active"}
            }
        )

    message = str(refused.value)
    assert "KMS envelope interface is not built" in message


# ------------------------------------------------ the custody keyset: seal and open


def test_custody_seals_under_the_active_key_and_opens_by_the_envelope_key_id() -> None:
    """Seal under active; open under whichever key the envelope's header names.

    A blob sealed under a retained key opens while the entry is present — the overlap — and
    a removed key-id refuses in the custody class.
    """
    active = _a_custody_key("active-key")
    retained = _a_custody_key("old-key")
    keyset = CustodyKeyset(active, [retained])

    sealed_now = keyset.encrypt(
        subject=SUBJECT, expires_at=int(time.time()) + 600, token=PROVIDER_TOKEN
    )
    assert carried_key_id(sealed_now) == "active-key"
    assert keyset.decrypt(sealed_now, subject=SUBJECT) == PROVIDER_TOKEN

    # A blob sealed under the retained key (the pre-rotation shape) opens through it.
    sealed_before = retained.encrypt(
        subject=SUBJECT, expires_at=int(time.time()) + 600, token=PROVIDER_TOKEN
    )
    assert keyset.decrypt(sealed_before, subject=SUBJECT) == PROVIDER_TOKEN

    # Remove the retained key (the cut): its blob refuses in the custody class.
    cut = CustodyKeyset(active)
    with pytest.raises(CustodyError):
        cut.decrypt(sealed_before, subject=SUBJECT)


def test_the_flat_spelling_behaves_as_its_structured_one_active_equivalent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A flat custody document equals the structured one-active document, key for key.

    The flat spelling is one active `env`-sourced entry carrying the base64 value; the
    structured one-active spelling reads the same value from its variable. A blob sealed
    under one opens under the other, which is the equivalence the compat shape promises.
    """
    key_b64 = _custody_key_b64()
    monkeypatch.setenv("CUSTODY_KEY", key_b64)
    flat = make_settings(gateway_custody_keys={CUSTODY_KEY_ID: key_b64}).custody_keyset
    structured = make_settings(
        gateway_custody_keys={
            CUSTODY_KEY_ID: {
                "source": "env",
                "ref": "CUSTODY_KEY",
                "role": "active",
            }
        }
    ).custody_keyset

    claim = flat.encrypt(
        subject=SUBJECT, expires_at=int(time.time()) + 600, token=PROVIDER_TOKEN
    )
    assert structured.decrypt(claim, subject=SUBJECT) == PROVIDER_TOKEN
    assert structured.active.key_id == flat.active.key_id


def test_a_removed_retained_key_id_refuses_before_any_decrypt() -> None:
    """A key-id naming no entry refuses in the custody class, like the single-key seam."""
    keyset = CustodyKeyset(_a_custody_key("active-key"))

    with pytest.raises(CustodyError):
        keyset.decrypt("not-an-envelope", subject=SUBJECT)
