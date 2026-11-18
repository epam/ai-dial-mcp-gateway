# Tasks

## 1. The fix — RFC 7591 §3.2.1 conformance at the registration response boundary

- [x] 1.1 Convert the issued-at member at the response site: in `gateway/routes.py`'s
  registration response assembly, `client_id_issued_at` is computed as an `int` of
  seconds since 1970-01-01T00:00:00Z by parsing the record's stored `created_at`
  (ISO-8601) — the same instant the store recorded, never a second `datetime.now()`.
  Both branches — new registration and idempotent re-registration of an existing client
  id — pass through this one site. Mark the store's `created_at` field with a comment
  that it is the storage format, not the wire format. Verify: the store file's records
  and the write path are untouched (`git diff` shows no `gateway/store.py` record-shape
  change), and a re-registration returns the existing record's instant.
- [x] 1.2 Regression tests assert the type and the same instant: in the
  accepted-registration test, assert `isinstance(body["client_id_issued_at"], int)`,
  that the value is within a sane epoch range for "now", and that it equals the epoch
  form of the store record's `created_at` (the same-instant property a second `now()`
  would fail); add the same assertions for the idempotent re-registration branch (same
  client id returns the stored record's instant as a number). Verify: the new rows fail
  against the unfixed code (negative control) and pass after 1.1, with the full unit
  suite green.
- [x] 1.3 Bind the typed sweep into the live probe: `scripts/probe_dcr.py`'s
  `register()` asserts a typed sweep over the whole response document — every RFC 7591
  member present checked against its expected JSON type, with the hand-built conformant
  document as the negative control that must show no violation — instead of printing
  `client_id_issued_at` unchecked. Verify: run the probe against the composed stack
  (front door) and see the typed sweep pass; break the type deliberately once and see
  the probe fail on it (instrument distinguishes).
- [x] 1.4 Operational step on live state — prune the diagnostic registrations: the
  store file is the live container state, so this is an operator action, not code —
  remove the four throwaway diagnostic registrations (loopback callbacks
  `http://127.0.0.1:8769|8770|8771|8772/callback`; three with `client_name`
  `troubleshoot-dcr-issued-at-type` / `troubleshoot-typed-sweep`, one with no
  `client_name`) from `data/dcr-registrations.json`, leaving the harness registrations
  and `group8-dcr-probe` untouched. Verify: the store is valid JSON, the remaining
  records are byte-identical to before the prune, and the gateway stays healthy.
- [ ] 1.5 Run the gate ladder on the diff: static gates (`ruff check`,
  `ruff format --check`, `mypy`, `bandit`, `pip-audit`, Trivy with `--skip-db-update`
  if the DB is stale), the compose-boot gate with a health probe, the change's
  conformance rows (the two new scenarios), the security review gate on the diff at
  focused depth (its job is to falsify the no-security-impact claim), and the
  independent review gate. Verify each gate's output is captured; commit only after all
  gates pass.
  - *Implementer status (partial — the reviewer gates and the commit are not this role's):*
    static gates green (`ruff check`, `ruff format --check`, `mypy` strict, `pytest -q`
    387 passed / 1 skipped, `bandit`, `pip-audit`, Trivy), the compose-boot gate green
    with a health probe through the front door, and the two new scenarios exercised live.
    The security review gate on the diff and the independent review gate are separate
    reviewer subagents and remain to be run; nothing is committed. Outputs in
    `evidence/implementation.md` §1.5.

## 2. Release notes

- [x] 2.1 Finalize `release-notes-draft.md` with both sections — the user-facing fix
  (strict harnesses can now complete registration; existing registrations unaffected,
  no action needed) and the team-facing record (the response-site conversion and its
  reasons, the unchanged store format, the probe's permanent typed sweep, the open
  question on `client_name: null`). Verify: both sections present, no credential or
  harness-specific detail beyond what is already public in the change's artifacts.
