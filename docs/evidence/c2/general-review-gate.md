# The general review gate — `generalized-idp-federation` (C2)

The independent general review of the change's full diff (`8c6dbe5^..HEAD`, 33 files,
including the security gate's fix round e55e488), run per CLAUDE.md gate 5. The reviewer
is fresh and independent of the authoring, implementation, and security-gate passes.
The security gate's record (`security-review-gate.md`, same folder) was read to avoid
duplicating its passes — its findings are NOT re-litigated here, and nothing below
rests on trusting them; every claim below was re-derived from the diff.

**Verdict: pass-with-findings.** The spec conformance, the rename sweep, the docs, the
tests, and the evidence trail all hold — with one availability defect the change
introduces (GRG-1, empirically reproduced) that should be fixed before push, one
mitigation-claim inaccuracy in the failed-fetch regime (GRG-2) that needs at minimum a
wording fix before push, and three hygiene items (GRG-3..GRG-5) plus one wording nit.

Re-verification run during this review (main checkout's venv, `PYTHONUTF8=1`):

- `pytest -q` (full suite) — **610 passed, 1 skipped** (matches the fix-round record).
- `python scripts/check_publication_leaks.py` — **PASS** (214 files, 3 waived
  pre-existing, 0 unwaived).
- `ruff check .` — **all checks passed**.
- Task 2.5's two rename greps — **clean** (no old setting spelling anywhere on the
  rename surface; remaining `keycloak` hits are the D8-licensed helper settings,
  local-instance fixtures, and probe login-flow driving only).
- Task 2.7's family-name grep (the D14 machine check) — **zero hits**.
- Dead-code check — `realm_of`, the three suffix constants, `_token_url`: **gone**.
- GRG-1's repro: a real uvicorn server (one event loop, the production topology) with
  a deliberately delayed local IdP — run twice, then deleted from the worktree.

## Findings

### GRG-1 — The discovery cache lock is acquired on the event loop; a slow or failing discovery fetch freezes the whole gateway, `/healthz` included

- **Severity:** high — a process-wide availability defect introduced by this change;
  must be fixed before push. The fix is small and the property is pin-able in a test.
- **Where:** `gateway/idp.py:437-450` (`_resolved_without_fetch` — the `with
  self._lock:` block runs synchronously inside the async `_endpoints`, i.e. on the
  event loop) holding against `gateway/idp.py:473-487` (`_discovered_endpoints` — the
  network fetch `_fetch_discovery_document(...)` runs **inside** the lock on a worker
  thread, so the lock is held for the whole fetch, up to
  `gateway_outbound_timeout_seconds`, default 30 s).
- **Evidence (empirical, reproduced twice with a real uvicorn gateway on one event
  loop; a plain `http.server` IdP whose well-known answer blocks until released):**
  with authorize request A in flight and its discovery fetch held open (the lock held
  by A's worker thread), a second `/dial/authorize` (B) enters the fast path on the
  event loop and blocks in `self._lock.acquire()` — and the loop stops serving
  **anything**: `/healthz`, a route with no identity-leg involvement at all, timed out
  at a 2 s probe timeout while the fetch was held, and answered only after the fetch
  was released. In the control run (no second authorize), `/healthz` answered in
  0.03 s with the same fetch in flight. A starlette `TestClient` cannot observe this
  (it runs each request on its own portal/event loop), which is why the suite is green
  while the defect is real in the production topology (one uvicorn loop).
- **When it bites:** every cold start and every TTL expiry where two authorize
  requests overlap (the second parks the loop for up to the remaining fetch duration);
  continuously under authorize traffic while the provider is unreachable or its
  document refused — every failed fetch leaves the cache unfilled, so requests keep
  paying fetches and the lock is held nearly all the time. The freeze includes the
  `/healthz` the compose healthcheck probes, so a provider outage plus sign-in
  traffic can render the container unhealthy while the process is otherwise correct —
  the exact failure shape `gateway/app.py`'s healthcheck comment says the probe must
  not have. Note the security gate's "what held" record priced *worker-thread*
  serialization on this lock but not the fast path's loop-thread acquisition — this
  finding complements, not duplicates, that note.
- **Requested disposition:** before push — make the fast path never block the loop.
  The smallest shape: a non-blocking acquire in `_resolved_without_fetch` (fall
  through to the worker-thread hop when the lock is contended, so the wait happens on
  a worker thread like every other outbound wait), or an immutable-snapshot read with
  no lock on the loop. Land a test that pins it — either the real-server shape above
  (cleaned up) or a unit-level pin that the fast path never blocks on a held lock.

### GRG-2 — The T5-10/M27/DT-EP5-2 claim "at most one fetch per TTL per process however many requests arrive — the fetch rate is min(rate limit, 1/TTL)" is false in the failed-fetch regime

- **Severity:** medium — a mitigation-claim accuracy defect, the same class the
  security gate's SRG-1 ruled "prose that claims more than the code does is equally
  unlanded"; wording minimum before push, a failure-cache preferred.
- **Where:** `docs/threat-model.md:705` (T5-10's row: "Bounded by the cache (M27): at
  most one fetch per TTL per process however many requests arrive... the fetch rate
  is min(rate limit, 1/TTL)"), the same wording at `docs/threat-model.md:1957`
  (dispositions) and `:1885` (M27), and the change's `design.md` §5 DT-EP5-2
  mitigations 1 and 7; against `gateway/idp.py:473-487` — the cache entry is assigned
  only after a successful, validated fetch (`self._discovered = cached` runs only on
  the success path), so a fetch that raises (unreachable provider) or a document that
  is refused (validation failure) leaves the cache empty.
- **Evidence:** with the cache unfilled, every `/dial/authorize` request pays one
  discovery fetch attempt (each takes the lock, serially), bounded only by the
  authorize surface's limiter — up to 600 attempts/min global — not by 1/TTL
  (1 per 300 s). The "however many requests arrive" bound holds only while the cache
  holds a validated document. An unauthenticated caller cannot steer the fetch's
  target (fixed by configuration), so this is amplification toward a fixed origin
  plus the GRG-1 loop stalls, not an SSRF shape — but the stated numeric bound is
  wrong by orders of magnitude in exactly the regime the threat row describes
  ("could try to spend discovery fetches").
- **Requested disposition:** before push — either land a short failure-cache
  (remember the failed attempt for a bounded window, so outages also cost 1/TTL), or
  amend T5-10/M27 and design.md §5 DT-EP5-2 to state the true bound: the cache bounds
  fetches only in the success regime; while the provider is unreachable or its
  document refused, each authorize request pays one fetch attempt, bounded by the
  authorize limiter and the lock's serialization. (If GRG-1 is fixed by moving the
  wait off the loop, this finding still stands as a claim-accuracy item on its own.)

### GRG-3 — `tasks.md`: every row 1.1–6.2 is done with an evidence record, but all 23 checkboxes are unticked

- **Severity:** low — mechanical honesty-of-record; fix before push/archive.
- **Where:** `openspec/changes/generalized-idp-federation/tasks.md` (all `- [ ]`).
- **Evidence:** rows 1.1–6.2 are each backed by `docs/evidence/c2/task-{1..6}-*.md`
  (spot-verified: the task-2 record carries the provisioning idempotency run and the
  end-to-end probe through the new route; task-6 carries both gate runs), yet no box
  is ticked. All five archived changes ticked their completed rows (59/5/1/24/17
  `[x]` respectively) — the convention this change breaks. Rows 7.1 (owner-dependent)
  and 7.2 (conditional) legitimately stay open.
- **Requested disposition:** tick rows 1.1–6.2 before push (or at latest at archive).

### GRG-4 — Task 7.2's own standing clause — "record the suite's absence and the date of the check in the evidence folder" — is unmet

- **Severity:** low — a missing deferral record the task row itself requires.
- **Where:** `openspec/changes/generalized-idp-federation/tasks.md:45`; searched
  `docs/evidence/c2/`, the change folder, and `docs/` — no record of the MCP
  conformance suite's absence and check date exists anywhere.
- **Evidence:** the row is conditional on the ecosystem and correctly not executed,
  but its own text makes the absence-record a standing requirement until a suite
  exists; a fresh auditor looking for it finds nothing.
- **Requested disposition:** one short paragraph in `docs/evidence/c2/` (a 7.x
  deferral record: suite absent as of 2026-11-05, row stays conditional) before push.

### GRG-5 — The fix round's response-cap asymmetry: the code exchange (`_post_token`) and the key-set fetch remain uncapped while the refresh grant and the discovery fetch got streaming caps

- **Severity:** low — consistency/completeness of the security gate's own SRG-1
  disposition; needs an explicit record, not silence.
- **Where:** `gateway/idp.py:574-624` (`_post_token` — non-streaming `httpx.post`,
  no size cap) and `gateway/idp.py:859-883` (`_fetch_key_set` — non-streaming
  `httpx.get`, no cap), against the fix round's streamed `_fetch_discovery_document`
  and `_post_refresh`.
- **Evidence:** the security gate's fix-round record dispositioned `_post_token` as
  "the trusted internal leg" — a rationale that predates this change's own
  generalization: the exchange and key-set legs now serve external internet providers
  too, and a compromised or misbehaving provider can make the gateway buffer an
  unbounded exchange answer inside the timeout, exactly the shape SRG-1 landed the
  streaming cap for on the two sister sites. No credential reaches an output either
  way (fail-closed parsing), so this is buffering discipline, not exposure — but the
  asymmetry inside one diff deserves a disposition that names the current shape.
- **Requested disposition:** either extend the same `_read_capped` streaming shape to
  `_post_token` and `_fetch_key_set` (small, symmetric), or record the accepted
  residue with reasoning that holds for the external-provider leg (not the retired
  internal-leg rationale).

### GRG-6 — The docs spell the discovery fetch `{IDP_ISSUER}/.well-known/openid-configuration`; the code joins with exactly one separator

- **Severity:** informational — wording nit; optional.
- **Where:** `docs/gateway-configuration.md` (the endpoint-source section), `.env.example`
  (implicitly), against `gateway/idp.py:738-740`
  (`settings.idp_issuer.rstrip('/') + _DISCOVERY_PATH`).
- **Evidence:** for the trailing-slash issuer form this change itself targets, the
  doc's literal reading would double the slash; the code is right (single separator,
  per the SRG-2 fix), and the doc's brace notation is generic rather than wrong — but
  one half-sentence ("joined with a single path separator") would remove the
  ambiguity for the operator of a trailing-slash issuer, the exact operator the
  pinning rules make spelling-sensitive.
- **Requested disposition:** optional wording clarification at archive time.

## What was checked and held

- **Spec conformance, requirement by requirement (code, not tests):** the four ADDED
  requirements' every scenario verified against the implementation — discovery
  serving all four legs from one resolution (`_resolved_endpoints`, no arithmetic
  anywhere); unreachable-provider fail-closed with no fallback construction;
  cache-honored-within-TTL / re-fetch-after (`age < ttl`, clock moved in tests); the
  override re-addressing the fetch/exchange/refresh/key-set with the authorization
  endpoint untouched (`_with_backchannel_applied`, applied identically to both
  sources); the one-hostname no-override shape; direct mode's full-trio-skips-
  discovery (short-circuit before any fetch), partial-set refusal naming both sides,
  well-formed-absolute-URL and HTTPS-or-override startup checks, override-on-
  server-legs-only, stale-endpoint fail-closed, pin unchanged; validation's issuer
  equality (raw string, verbatim issuer), origin-bound endpoints (scheme+netloc
  tuple, lowercased), plain-http-issuer startup refusal; the confidential-client
  requirement's five scenarios including the default mode's never-present converse
  (removed opportunistic send, pinned byte-for-byte by the suite) and the
  client-facing PKCE surface unchanged. The five MODIFIED requirements' amendments
  are wording-only and consistent with the code. Task 1.2's cross-check holds: every
  gateway-owned mitigation named in design.md §6 has a requirement in the delta spec.
  No undocumented behavior found beyond GRG-5's asymmetry (which the spec does not
  claim either way).
- **Tasks honesty:** rows 1.1–6.2 all done with per-group evidence records that
  state commands, outcomes, and triage as they ran — including self-reported findings
  (task 5's record surfaced the compose environment gap, fixed in a80c830). The two
  gaps are GRG-3 (unticked boxes) and GRG-4 (the missing 7.2 absence-record).
- **Code quality:** comments carry behavior and reason, no provenance (the
  provenance grep over added lines is clean; the task-number citations in test
  docstrings follow the suite's pre-existing convention); one resolution layer with
  no duplication between modes (`_resolved_endpoints` is the single meeting point);
  the settings validators are readable and each names its setting(s) in its refusal;
  no dead code from the rename (grep clean); naming consistent
  (`IDP_CALLBACK_PATH`/`IDP_CALLBACK_ROUTE`/`leg="idp"` in step).
- **Test adequacy:** the new tests assert behavior (request URLs, request bodies,
  response shapes, audit reasons), not implementation details; the failure-mode
  tests are genuine negative controls — the oversize-discovery test counts chunks
  pulled and fails a buffered-then-capped implementation on the counter; the
  byte-identical default-mode test pins member order and would fail on any added
  member; the never-emit test plants the secret, proves it rode the wire, and sweeps
  logs (chained exception text included), pages, and headers. The reviewer's
  suggested uncovered paths were all in fact covered (TTL boundary via the moved
  clock; override×direct-mode; the authorize-leg error path). The one uncovered path
  is GRG-1's (and it is unobservable through `TestClient` — see the finding).
- **Docs truthfulness:** README, `docs/gateway-configuration.md`,
  `docs/local-environment.md` match the code and each other — every settings-table
  value spot-checked against `gateway/settings.py` (defaults 300 s TTL, PKCE on,
  placeholder issuer, trio unset); the startup-refusal table matches the validators
  one-for-one; the documented local bring-up (compose up, provision, probe) ran as
  written per the task-2/task-6 records, and this review re-ran the static tier
  (pytest, leak check, ruff) green. The D14 boundary holds on the final state of
  every touched file (machine grep zero).
- **The change's coherence:** proposal ↔ design (D1–D14) ↔ tasks ↔ release-notes tell
  one story — discovery as the default source, D11's direct trio as the
  configuration-time alternative, D13's env-slot delivery, D14's vocabulary boundary
  with the machine check behind it; the evidence folder (task groups 1–6, the
  security gate with its fix round, this record) is complete enough for a fresh
  auditor to reconstruct what happened, including the two mid-change findings
  (compose completion, the security fix round).

## Disposition summary

| id | severity | must fix before push? | must fix before live run? |
|---|---|---|---|
| GRG-1 | high | yes | yes |
| GRG-2 | medium | yes — wording minimum, failure-cache preferred | wording suffices if not fixed as code |
| GRG-3 | low | yes (mechanical) | no |
| GRG-4 | low | yes (one paragraph) | no |
| GRG-5 | low | no — an explicit disposition record suffices | recommended |
| GRG-6 | informational | no | no |

## General-gate dispositions (the fix round)

The implementer's fix round against the six findings above, run 2026-11-05 in the
change's worktree, on the same branch state the review read. Nothing was committed by
the round; the diff sits in the working tree for the next stage's gates.

### GRG-1 — fixed as the gate's smallest shape; pinned by a test the old shape fails

`_resolved_without_fetch` no longer waits on the cache lock: the fast path attempts a
**non-blocking** acquire (`lock.acquire(blocking=False)`); on contention it returns
`None` and the caller (`_endpoints`) falls through to the existing worker-thread hop —
`anyio.to_thread.run_sync(self._resolved_endpoints)` — so the event loop never blocks
on the lock, and a contended lock means a fetch is already in flight, so there was
nothing to read yet anyway. The fetch thread keeps the lock for its whole duration, as
before.

**The pinning test** (`tests/test_idp.py::test_a_fetch_in_flight_never_blocks_the_event_loop`,
an `anyio` test) shares the loop the resolution runs on — the production topology's
one-loop shape, which a `TestClient` cannot observe:

- A worker thread runs a whole first sign-in's resolution on its own loop, with the
  discovery fetch instrumented to signal its entry and hold for 1.0 s — the fetch in
  flight, holding the cache lock for its duration, exactly as the real fetch does.
- On a second loop, two coroutines run concurrently: a second `_endpoints()` (the
  sign-in racing the held fetch) and a **heartbeat** — the `/healthz` shape, a
  coroutine touching nothing of the identity leg that must keep completing while the
  lock is held. The assertion: the heartbeat completed at least 6 times against the
  1.0 s hold (the interval is 0.05 s; a loop parked on the lock collects one or two),
  and the second sign-in shared the held fetch (one fetch attempt, not two).
- **The old shape fails it**: with the fix temporarily reverted to the blocking
  `with self._lock:` acquire, the test fails with an empty heartbeat list — the second
  resolution parks the loop in the acquire, and the heartbeat coroutine never gets to
  run at all. Verified by running the test against the reverted shape (failed:
  `assert []`), then restored (passes).

### GRG-2 — fixed as code: a short negative cache; the model text states the implemented bound

The preferred disposition is landed. A fetch that fails **or a document that is
refused** is now recorded in the cache (`_discovered_endpoints`, under the same lock):
the failure's fixed-vocabulary message and status, stamped with the monotonic instant.
For the same TTL window the recorded refusal is served to every leg — re-raised fresh,
no re-fetch — and a success clears the record; the first leg after the window retries
the provider. The claim "at most one fetch per TTL per process however many requests
arrive — the fetch rate is min(rate limit, 1/TTL)" is now true as implemented in both
regimes, and the bound is stated explicitly in all four prose sites:
`docs/threat-model.md` T5-10's row (§8), M27 (§12), the T5-10 disposition (§13), and
design.md §5 DT-EP5-2 mitigations 1 and 7 (the §6 mitigation summary and the §5 threat
grid, which carried the same wording, were updated to agree). The delta spec's
discovery requirement and its cache scenario are conditioned on a fetched-and-validated
document and remain true as written — the failure record is an implementation
strengthening the spec does not contradict, and the spec was not touched.

Tests (`tests/test_idp.py`, full-flow, fetch counted on the discovery route):
`test_a_failed_fetch_costs_one_attempt_per_window` — an unreachable provider: three
sequential authorizes produce exactly **one** fetch attempt, all refused with the same
fixed-vocabulary error; after the moved clock closes the window, exactly **one** more.
`test_a_refused_document_is_served_from_the_failure_window` — the same counts for a
document refused on issuer mismatch, so a lying provider cannot buy one fetch per
sign-in either.

### GRG-3 — done

`openspec/changes/generalized-idp-federation/tasks.md`: all twenty rows 1.1–6.2
ticked, matching the five archived changes' convention and the evidence records in this
folder. Rows 6.3, 7.1, and 7.2 stay unticked: 6.3's own text — landing both gates'
findings and dispositions — is completed by this very section but is left for the
scheduler to close with it in view; 7.1 is owner-dependent; 7.2 is conditional (see
GRG-4).

### GRG-4 — done

`docs/evidence/c2/conformance-suite-absence.md` — the task-7.2 absence record the row
itself requires: no MCP conformance suite exists as of the check date 2026-11-05, the
row stays conditional and open, and the acceptance evidence until then is named. (The
web search this session could have run to re-derive the absence was unavailable; the
record claims only the row's standing fact and the check date, not a fresh search.)

### GRG-5 — fixed as code: the streaming cap extended to both sister sites

`_post_token` and `_fetch_key_set` now read their answers through the same
`_read_capped` streaming shape as the discovery fetch and `_post_refresh` — the body
read stops the moment it crosses `_RESPONSE_MAX_BYTES` (64 KiB, the constant's comment
updated to name all four answers) and the connection is abandoned mid-read, refused
with the fixed vocabulary ("the identity provider's token response / key set is larger
than this gateway accepts"). The retired "trusted internal leg" rationale is gone with
the asymmetry: the exchange and key-set legs serve external providers this change
itself generalizes to, and a hostile answer is now bounded at reading on every leg.

Tests (the discovery test's chunk-counting shape reused):
`test_an_oversized_token_response_is_refused_while_being_read` and
`test_an_oversized_key_set_is_refused_while_being_read` — each streams an ~4 MB answer
from a counting generator through the real flow and asserts the refusal landed within
one chunk of the cap (the tail never pulled).

### GRG-6 — done

`docs/gateway-configuration.md`, the endpoint-source section's discovery bullet: the
well-known path is joined to the issuer with exactly one separator, so a trailing-slash
issuer spelling works as configured. The same bullet also states the failure record's
window (GRG-2), keeping the operator doc truthful about the new behavior.

## The fix round's gates

Run from the worktree with the main checkout's venv, `PYTHONUTF8=1`:

- `ruff check .` — **all checks passed**; `ruff format --check gateway/idp.py
  tests/test_idp.py` — **2 files already formatted** (two iterations: the first run
  flagged two magic-value comparisons in the new tests and one long line — fixed, not
  triaged away).
- `pytest -q` (full suite) — **615 passed, 1 skipped** in 101.7 s (was 610 passed,
  1 skipped: +5, the five new tests).
- `bandit -q -r gateway/` — **exit 0**, no findings (the pre-existing `nosec`/
  test-in-comment warnings unchanged; nothing new to triage).
- `python scripts/check_publication_leaks.py` — **PASS** (214 files, 3 waived
  pre-existing, 0 unwaived — the same counts the review's re-verification ran).
- The leak check and the static tier cover the new evidence and doc files; the
  compose-boot gate is not re-run by this round (no compose, settings, or dependency
  surface touched — code, tests, and prose only).
