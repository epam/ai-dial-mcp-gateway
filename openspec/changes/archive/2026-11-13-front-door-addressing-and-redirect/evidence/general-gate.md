# General review gate — front-door addressing and redirect

PROCESS.md step 8 / the change's tasks 9.5. Branch
`change/front-door-addressing-and-redirect`; HEAD `f900ac1`. The general review gate
(the independent reviewer subagent, run after the security review gate) returns
**PASS — zero blocking findings**, with four should-fixes (SF-G1..G4) and three cheap
notes. This file records the gate verdict and the remediation pass that landed the
should-fixes and the notes, with its verification results.

## Gate verdict

**PASS, zero blocking.** The gate read the diff against the change's design and SIA and
raised four should-fixes plus three cheap notes; none was a blocking defect. The
remediation pass below lands all four should-fixes and all three notes, changing nothing
else.

## Remediation — SF-G1..G4, and the notes

### SF-G1 — probe fixture leak (`scripts/probe_front_door_paths.py`)

**Landed.** The fixture creations (`admin_token`/`test_user_token`, then `public_id`,
then `ubucket_id`) previously ran BEFORE the `try:` whose `finally` deleted them, so a
failure between two creations — after `public_id` exists, before `ubucket_id` does —
leaked the already-created toolset: the `finally` named both ids, and one of them did not
exist yet (a `NameError` would have masked the original failure and skipped cleanup).

The fix moves the creations INSIDE the `try:` and registers each fixture in a
`created: list[tuple[str, str]]` **the moment it exists** — `created.append((admin,
public_id))` right after the create, `created.append((owner, ubucket_id))` likewise — so
the `finally` deletes every registered fixture whatever happened, covering partial setup.
The realm user's own guard is untouched, per the fix's scope. The comment at the top of
`main()` now states the ordering rule (each fixture covered from the moment it exists).

### SF-G2 — threat-model stale rows (`docs/threat-model.md`)

**Landed.** The four sites the gate named, re-worded against the SHIPPED mechanism (the
`map $request_uri` raw-URI map with the segment grammar, the decoded path guard mirroring
Core's resolution rules, the first-segment reserved scoping), table row format kept:

- **EP6 "routing regexes" row** → relabeled **EP6 (the routing map)**; the removed
  single-segment `[a-z0-9-]+` location regex and "unanchored regex" language replaced by
  the first-segment reserved rule, the ordered prefix locations, and the raw-URI map's
  whole-request-URI match domain (M39); the apps half names the disjoint `/apps/` map.
- **EP6 "apps location" row** → relabeled **EP6 (the apps map and location)**; the
  `~ ^/apps/(?<aname>[a-z0-9-]+)/mcp$` regex replaced by the `~ ^/apps/` prefix location
  driven by `$apps_target` from the `map $request_uri` grammar.
- **M10's mitigation row** — the `^[a-z0-9-]+$` charset replaced by the decoded
  per-segment path rules; the placement note records the re-base by this change.
- **Narrative mentions (:1845 T6-2, :2321/M10 placement)** — both re-worded: T6-2's
  "Reduce Attack Surface" clause now names the decoded per-segment rules, and the two
  historical D2-reconciliation narratives (the §9 header and OQ-3) now record the charset
  as "then a one-segment `^[a-z0-9-]+$`, re-based by this change" rather than asserting it.

**Cross-check (per the fix's instruction — grep `[a-z0-9-]`, "anchored", "charset"):**
the sweep found four further sites still asserting the removed mechanism, all re-worded:
**M15** ("anchored ordered regexes" → the end-anchored `map $request_uri` grammars and
the stated buffer bound), **M24** (the app name guard / "anchored regex" apps location →
the decoded per-segment rules and the `/apps/` prefix location driven by `$apps_target`),
**T6-7** (the disposition row), and **T6-8** (the apps disposition row). No site now
asserts the old `[a-z0-9-]+` charset as current or an anchored data-path location regex;
every surviving `anchored`/`charset` mention describes the SHIPPED map grammar, an
end-anchored whole-request-URI match domain, or a historical note marked as re-based.

### SF-G3 — tasks.md 1.2's verify clause overclaim (`tasks.md`)

**Landed.** The clause "raw non-ASCII input is refused (the wire grammar's refusal,
mirrored gateway-side)" is corrected to the truth: the refusal is the **request-target's**
(the router's), asserted live by probe row 4; the gateway's surfaces
**accept-and-canonicalize** a wire-conforming spelling per the canonical-identity rule
(D4) rather than mirroring the refusal, and only discovery's `raw_path` latin-1 decode
yields a harmless phantom identity for a raw non-ASCII byte. The raw-non-ASCII mojibake
micro-class is appended to `design.md`'s SIA gap list beside N-1/N-2 (the residual-minor
format): disposition **phantom-path (nowhere routed), Core reads 404 — harmless, owner may
promote**.

### SF-G4 — tick tasks.md 9.1–9.4 (`tasks.md`)

**Landed.** 9.1 (pytest `759 passed, 1 skipped`; ruff check clean; touched-file format
clean), 9.2 (green after the round-1 remediation — the `opentelemetry-api` floor and the
Trivy `krb5-libs` parity), 9.3 (compose-boot: both services `(healthy)`, health probe per
service 200), and 9.4 (round-3 PASS, literal invocation: the failing probe 12 rows green
/ 2 controls red as designed exit 0, `probe_routing.py` 13 probes green exit 0) are all
ticked, each citing `evidence/gate-run.md`'s recorded round. **9.5's boxes stay unticked**
until the general gate (this one) is recorded.

### Cheap notes

- **Suite gap — the code grant's canonical resource match (`tests/test_tokens.py`).**
  **Landed.** Added `test_a_code_matches_the_resource_canonically`, mirroring the refresh
  twin `test_a_refresh_matches_the_resource_canonically` in style: a client redeeming a
  code with a non-canonical spelling (`%6E` for `n`) of the same resource matches
  canonically and is served (`gateway/token.py:447-451`).
- **Typo (`tests/test_federation.py`).** **Landed.** "an equrivalent spelling" →
  "an equivalent spelling" (:322).
- **Release notes — pre-change-refresh-token migration line
  (`release-notes-draft.md`).** **Landed** in the For-users section: a refresh token
  minted before the deploy carries a non-canonical resource and fails the now-canonical
  match → one re-sign-in within the 8-hour window.

## Verification results

All commands `PYTHONUTF8=1`.

| Check | Command | Result |
|---|---|---|
| pytest | `.venv\Scripts\python.exe -m pytest -q` | **`762 passed, 1 skipped, 1 warning in 99.13s`** (exit 0) — the baseline 761 plus the new code-grant canonical-match row |
| ruff check (touched) | `.venv\Scripts\ruff.exe check scripts/probe_front_door_paths.py tests/test_tokens.py tests/test_federation.py` | `All checks passed!` (exit 0) |
| ruff format (touched, CRLF-safe) | `tr -d '\r' < F \| ruff format --check --stdin-filename F -` | clean for all three (exit 0 each) |
| probe battery | `.venv\Scripts\python.exe scripts/probe_front_door_paths.py` | **exit 0** — 12 rows green, 2 negative controls red as designed; the fixture-hygiene fix does not break the battery |

The probe battery's negative controls remain red as designed (`encoded name not refused
by the router`; `full-URL listing read resolves`), so the instrument still proves it can
fail; the fixture cleanup ran (the probe created and deleted its `public_id` and
`ubucket_id` fixtures with no leak — the registered-list `finally` deletes both).

## Scope

Touched only: `scripts/probe_front_door_paths.py`, `docs/threat-model.md`,
`openspec/changes/2026-11-13-front-door-addressing-and-redirect/tasks.md`,
`.../design.md` (gap list), `.../release-notes-draft.md`, `tests/test_tokens.py`,
`tests/test_federation.py`, and this evidence file. Nothing committed.