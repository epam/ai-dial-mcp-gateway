"""The keyset entry schema the signing and custody keysets share.

Both keysets name their material the same way. An entry carries a **source** (`env`, `file`,
or the reserved `kms`), a **ref** that locates the material — an environment variable's name
or a file's path — and a **role** (`active` or `retained`). The document is *structure, never
secret material*: an entry's material sits in its own environment variable or its own file,
so the keyset document itself classifies non-secret, a rotation adds one Secret or mount
rather than re-quoting a growing blob of key material, and a source-heterogeneous keyset (a
retained `env` entry beside an active `file` entry) is valid from day one.

`kms` is a **reserved** source: an entry carrying it is refused at startup, naming the gap,
because a deployment that configured it believes it holds KMS-protected material and the
gateway cannot honor that belief. The reserved value is schema-carried so the future real
`kms` is additive, never a reinterpretation of the refusal.

The module is deliberately dependency-light (only `gateway.errors`) so the settings model,
the signing-key loader, and the custody loader can all use it without an import cycle. The
two compat spellings — the singular signing key and the flat custody document — are folded
into this same entry shape by `gateway/settings.py`, so the compat path rides one code path
rather than a parallel one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from gateway.errors import ConfigurationError

# The source vocabulary. `env` and `file` are implemented; `kms` is reserved and refused.
SOURCE_ENV = "env"
SOURCE_FILE = "file"
SOURCE_KMS = "kms"
SOURCES: tuple[str, ...] = (SOURCE_ENV, SOURCE_FILE, SOURCE_KMS)

# The role vocabulary. A keyset holds exactly one `active` entry and any number `retained`.
ROLE_ACTIVE = "active"
ROLE_RETAINED = "retained"
ROLES: tuple[str, ...] = (ROLE_ACTIVE, ROLE_RETAINED)

# The refusal an entry carrying the reserved `kms` source yields, per keyset. Each names the
# gap in the operator's own vocabulary — which interface is missing — and the sources that
# are implemented, so the message corrects the wrong belief instead of merely stopping.
SIGNING_KMS_REFUSAL = (
    "signing keyset entry {entry!r} names the reserved source `kms`, which this gateway "
    "does not implement: the KMS sign-interface is not built, so the entry would name a "
    "protection the gateway cannot honor. `env` and `file` are implemented — configure the "
    "entry with one of those"
)
CUSTODY_KMS_REFUSAL = (
    "custody keyset entry {entry!r} names the reserved source `kms`, which this gateway "
    "does not implement: the KMS envelope interface is not built, so the entry would name a "
    "protection the gateway cannot honor. `env` and `file` are implemented — configure the "
    "entry with one of those"
)


@dataclass(frozen=True)
class KeysetEntry:
    """One normalized keyset entry: where its material comes from, and its role.

    `ref` locates the material for a structured entry — an environment variable's name (for
    `env`) or a file's path (for `file`). `material` carries it inline for the compat
    spellings — the singular signing key's value, and the flat custody document's base64
    value — so those spellings skip a second indirection rather than a second code path.
    Exactly one of the two is set; the loader resolves whichever is present.
    """

    id: str
    source: str
    role: str
    ref: str | None = None
    material: str | None = None

    @property
    def is_active(self) -> bool:
        return self.role == ROLE_ACTIVE


def validate_entries(
    entries: list[KeysetEntry] | tuple[KeysetEntry, ...],
    keyset_name: str,
    *,
    kms_refusal: str,
    one_active_phrase: str,
) -> None:
    """Refuse a keyset document that cannot describe a usable keyset.

    Raised as a `ValueError` so it lands at the settings model's own validation, naming the
    keyset and the offending entry by its configured id only — never material, never a
    fingerprint, never file content. The checks, in order: every source is known; no entry
    carries the reserved `kms`; every role is known; every structured entry names the `ref`
    its material is read from; and exactly one entry is `active`. The caller supplies the
    per-keyset `kms_refusal` text and the `one_active_phrase` the violation names, so the
    two keysets read in their own vocabulary while sharing one implementation.
    """
    for entry in entries:
        if entry.source not in SOURCES:
            message = (
                f"{keyset_name} entry {entry.id!r} names an unknown source "
                f"{entry.source!r}; a source is `env` or `file` (implemented), or `kms` "
                f"(reserved)"
            )
            raise ValueError(message)
        if entry.source == SOURCE_KMS:
            raise ValueError(kms_refusal.format(entry=entry.id))
        if entry.role not in ROLES:
            message = (
                f"{keyset_name} entry {entry.id!r} names an unknown role {entry.role!r}; "
                f"a role is `active` or `retained`"
            )
            raise ValueError(message)
        if not entry.ref and not entry.material:
            message = (
                f"{keyset_name} entry {entry.id!r} names no material: a structured entry "
                f"carries `ref`, the environment variable or file path its material is "
                f"read from"
            )
            raise ValueError(message)

    actives = [entry.id for entry in entries if entry.is_active]
    if len(actives) != 1:
        message = (
            f"{keyset_name} holds {len(actives)} active entries; {one_active_phrase}. "
            f"Entries: {', '.join(entry.id for entry in entries)}"
        )
        raise ValueError(message)


def resolve_material(entry: KeysetEntry) -> str:
    """An entry's material, read from wherever its source locates it, or a loud refusal.

    The compat spellings carry their material inline; a structured entry reads it from its
    own environment variable (`env`) or file (`file`) — once, at startup. Every refusal
    names the entry by its configured id and the locator (the variable's name, the file's
    path), never the material or the file's content: a read error can echo what it choked
    on, and a material-shaped value in an error is a credential in a log line.
    """
    if entry.material is not None:
        value = entry.material
    elif entry.source == SOURCE_FILE:
        try:
            value = Path(entry.ref or "").read_text(encoding="utf-8")
        except OSError as exc:
            message = (
                f"keyset entry {entry.id!r} names the file source {entry.ref!r}, which "
                f"cannot be read. The material must be a readable file on a read-only "
                f"mount at that path"
            )
            raise ConfigurationError(message) from exc
    elif entry.source == SOURCE_ENV:
        resolved = os.environ.get(entry.ref or "")
        if resolved is None:
            message = (
                f"keyset entry {entry.id!r} names the environment variable "
                f"{entry.ref!r}, which is not set. The material must be injected in that "
                f"variable"
            )
            raise ConfigurationError(message)
        value = resolved
    else:
        # A `kms` entry is refused during validation, before any load; this is the
        # fail-closed backstop for a path that reached the loader without it.
        message = (
            f"keyset entry {entry.id!r} names an unimplemented source {entry.source!r}"
        )
        raise ConfigurationError(message)

    if not value.strip():
        where = entry.ref if entry.ref is not None else "its inline value"
        message = (
            f"keyset entry {entry.id!r} reads its material from {where!r}, which is blank. "
            f"A blank source is a misconfiguration, not a key"
        )
        raise ConfigurationError(message)
    return value
