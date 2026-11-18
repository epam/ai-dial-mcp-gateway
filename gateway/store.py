"""The dynamic client registration store: one JSON file in a mounted volume.

Registrations are the only gateway state that both outlives a restart and is cached by
clients indefinitely, so they are the only state made durable. The mechanism is the
simplest one that survives a restart — no database, no lock manager, no schema: a flat
JSON object mapping client id to a record limited to the client id, its redirect URIs,
its name, and when it was created. No secret is ever stored, because every client here is
a public PKCE client and there is no secret to store.

Three properties are worth stating because each is a deliberate choice about failure:

* A save is atomic — a temporary file in the same directory, then a rename over the
  store. A crash mid-write can leave a temporary file behind, never a half-written store
  that would load as a truncated set of registrations.
* A store that cannot be read or parsed refuses startup, naming the path. Starting empty
  instead would invalidate every registered client id without a trace, and the operator
  would learn about it from a harness, not from the gateway. Recovery is one command:
  rename the file aside and restart, which is also the operator's acknowledgment that the
  old contents are gone.
* At the configured cap, new registrations are refused and existing ones are untouched.
  Evicting the oldest would invalidate a possibly live client — the same loss as a dropped
  store, but silent. There is no expiry: a registration's lifetime is the client's own
  choice, and an expired registration would recreate the cached-client-id problem the
  store exists to prevent.
* The owner-only file mode is best-effort hardening, never a guarantee. The durability the
  store exists for is atomicity — the temporary file plus the rename — and that works on
  every filesystem the volume could be mounted from. A filesystem without POSIX permission
  changes (a Windows host path reaching the container as 9p/DrvFs, where `chmod` fails with
  `EPERM`) is tolerated with a logged warning naming the store path, and the rename
  proceeds: a registration is never refused for the mode. The store's integrity is the
  host/volume owner's boundary either way — the same trust boundary as the signing key —
  and on such a mount every file in the volume is equally world-shaped, so the mode is
  unenforceable there in principle rather than an implementation gap.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from gateway.errors import ConfigurationError
from gateway.redirect_uris import ADMISSION_RULE, scheme_admission_refusal
from gateway.settings import Settings

# A dedicated logger so the mode tolerance is visible to an operator without interleaving
# with the per-request audit records.
_LOGGER = logging.getLogger("gateway.store")


class RegistrationError(Exception):
    """A registration that cannot be accepted, with a message safe to show a client."""


class RegistrationStore:
    """The durable registration records, backed by one JSON file.

    The in-memory map is the working set; the file is written through on every accepted
    registration, before the response is returned, so a client that has cached the id it
    just received never holds an id the store does not know.
    """

    def __init__(self, settings: Settings) -> None:
        self._path = Path(settings.dcr_store_path)
        self._max_registrations = settings.dcr_max_registrations
        self._records: dict[str, dict[str, object]] = self._load()

    def _load(self) -> dict[str, dict[str, object]]:
        """Read the store at startup, refusing to start on anything unreadable.

        A missing file is not a corrupt one: the first run of a deployment has no store
        yet, and starting empty is exactly right. A file that exists and cannot be read
        or parsed is the case that must not be absorbed silently.

        The redirect-URI admission rule is validated here too, and this is its fourth
        site: client resolution reads the store without re-checking, so a record admitted
        before the rule landed — or planted on the volume per the store's own threat row —
        would otherwise keep a non-loopback plain-`http` redirect URI usable after the rule
        landed. A record carrying one refuses startup in the corrupt-store discipline's
        shape: the gateway names the record and the recovery is the same — the store
        renamed aside or the record removed, after which the affected harnesses re-register.
        """
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        except OSError as exc:
            message = (
                f"the dynamic client registration store at {self._path} could not be "
                f"read ({type(exc).__name__}); rename it aside and restart to start from "
                f"an empty store, then re-register the clients that need it"
            )
            raise ConfigurationError(message) from exc

        try:
            document = json.loads(raw)
        except ValueError as exc:
            message = (
                f"the dynamic client registration store at {self._path} is not valid "
                f"JSON ({exc}); rename it aside and restart to start from an empty "
                f"store, then re-register the clients that need it"
            )
            raise ConfigurationError(message) from exc
        if not isinstance(document, dict):
            message = (
                f"the dynamic client registration store at {self._path} does not hold a "
                f"JSON object of client id to record; rename it aside and restart to "
                f"start from an empty store"
            )
            raise ConfigurationError(message)

        records: dict[str, dict[str, object]] = {}
        for client_id, record in document.items():
            if not isinstance(record, dict):
                message = (
                    f"the dynamic client registration store at {self._path} holds a "
                    f"malformed record for client {client_id!r}; rename it aside and "
                    f"restart to start from an empty store"
                )
                raise ConfigurationError(message)
            self._refuse_inadmissible_record(client_id, record)
            records[client_id] = record
        return records

    def _refuse_inadmissible_record(
        self, client_id: str, record: dict[str, object]
    ) -> None:
        """Refuse a stored record whose redirect URIs violate the admission rule, by name.

        Only records that actually carry a `redirect_uris` list of strings are checked here:
        a record shaped otherwise is the malformed-record case only where the resolution
        path would read it, and the store holds whatever the registration endpoint wrote —
        which the endpoint's own admission check already bounds. This load-side leg closes
        the pre-rule and planted windows for the values it can see.
        """
        redirect_uris = record.get("redirect_uris")
        if not isinstance(redirect_uris, list):
            return
        for uri in redirect_uris:
            if not isinstance(uri, str):
                continue
            if scheme_admission_refusal(uri) is not None:
                message = (
                    f"the dynamic client registration store at {self._path} holds a record "
                    f"for client {client_id!r} with a redirect URI this gateway cannot admit "
                    f"({uri!r}): {ADMISSION_RULE}. The record never resolves; rename the "
                    f"store aside or remove the record and restart, then re-register the "
                    f"affected clients"
                )
                raise ConfigurationError(message)

    @property
    def path(self) -> Path:
        return self._path

    def get(self, client_id: str) -> dict[str, object] | None:
        """The stored record for a client id, or `None` when it is not registered."""
        return self._records.get(client_id)

    def is_full(self) -> bool:
        return len(self._records) >= self._max_registrations

    def add(
        self,
        client_id: str,
        redirect_uris: list[str],
        client_name: str | None,
    ) -> dict[str, object]:
        """Persist a new registration and return its record.

        The record is written to disk before this returns, so the caller can answer the
        client knowing the id it is about to cache is already durable.
        """
        if client_id in self._records:
            # A registration that already exists is returned unchanged: re-registering
            # the same client id is not an error, and rewriting the record would be a way
            # for one client to take over another's redirect URIs.
            return self._records[client_id]
        if self.is_full():
            message = (
                f"this gateway holds its maximum of {self._max_registrations} dynamic "
                f"client registrations and cannot accept another. Existing registrations "
                f"are unchanged. An administrator can raise the limit or remove "
                f"registrations that are no longer needed."
            )
            raise RegistrationError(message)

        record: dict[str, object] = {
            "client_id": client_id,
            "redirect_uris": list(redirect_uris),
            "client_name": client_name,
            # This is the store's own at-rest format for the instant, not the wire format:
            # an RFC 7591 registration response answers the same instant as a JSON number
            # of epoch seconds, converted at the response boundary in `gateway/routes.py`.
            # The two formats meet there and nowhere else, so this field is never
            # serialized into a response as it stands.
            "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        self._records[client_id] = record
        try:
            self._save()
        except OSError:
            # The in-memory map must not claim a registration the store does not hold:
            # a client id answered but not persisted is an id that stops resolving on
            # the next restart, which is the failure the store exists to prevent.
            del self._records[client_id]
            message = (
                f"the registration could not be written to the gateway's store at "
                f"{self._path}; no registration was created. An administrator should "
                f"check that the volume is writable."
            )
            raise RegistrationError(message) from None
        return record

    def _save(self) -> None:
        """Write the store atomically: temporary file beside it, then rename over it."""
        directory = self._path.parent
        directory.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=directory, prefix=self._path.name + ".", suffix=".tmp"
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(self._records, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            # Owner-only: the file holds client ids and redirect URIs — not credentials,
            # but not something to publish to every local account either.
            #
            # Best-effort, and deliberately not part of the failure handling below: a
            # filesystem without POSIX permission changes (a Windows host path reaching
            # the container as 9p/DrvFs, where `chmod` answers `EPERM`) cannot carry the
            # mode at all, and the durability this store exists for is the rename, not the
            # mode. So a refused mode change is reported and the save continues; a
            # registration is never refused for it.
            try:
                temporary.chmod(0o600)
            except OSError as exc:
                _LOGGER.warning(
                    "the registration store at %s could not be given its owner-only file "
                    "mode (%s); the save continues and the file keeps the mode its "
                    "filesystem assigns. Where the volume enforces POSIX modes the file "
                    "would be readable only by its owner; this filesystem does not, so "
                    "every file on the mount is equally readable and the store's "
                    "protection is the host or volume owner's boundary.",
                    self._path,
                    exc,
                )
            temporary.replace(self._path)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise
