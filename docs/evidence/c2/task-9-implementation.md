# Task group 9 — the 401/403 refusal-class split (D16)

Date: 2026-11-06. Implementer pass; worktree `d0a-publication-discipline`.
Normative sources: design.md D16 and its §7 delta, the delta spec's trust-fault
scenario (authoring round 7). Landed in the standing order: the threat model first
(9.1), then the code (9.2). Not committed; no containers touched.

## 9.1 — the threat-model note (landed before the code)

`docs/threat-model.md` per design.md §7's trust-fault delta:

| Where | What changed |
|---|---|
| The EP5 listing-read row (T5-7's class) | the row's closing statement gains the fourth refusal shape: the read's refusals are four distinguishable classes on the page and the audit trail — no-access (403), unknown-toolset (404), the **trust fault** (401: Core could not validate the sign-in's identity token — an authentication failure whose remedy is the operator's check of Core's provider entry for the identity provider, its issuer pattern, key set, or audience, or that key set's reachability), and the deployment fault — where the prior mapping collapsed the 401 into the no-access class; the **wrong-class diagnosability defect the second live B2C run exposed is recorded as removed by this change's refusal-class split**; the forged-answer residue keeps T5-7's acceptance unchanged (a forged 401 costs one flow, the same as a forged 404) |
| §12's M23 row | the routing-decision mitigation now carries the four-shape discipline — "no-access (403) / unknown-toolset (404) / trust fault (401, the operator-facing fault page, fixed vocabulary) / deployment fault — the 401 never answered or audited as an access denial" |
| §12's M25 row | the app read's enumeration gains the 401 trust-fault member — the same class the listing read's split carries, both reads sharing the gateway's one answer-to-refusal mapping, never an access denial |
| §13's T5-7 disposition | gains the wrong-class defect's removal record and the unchanged forged-answer acceptance |
| §13's T5-8 disposition | gains the app read's 401 riding the listing read's trust-fault class (the shared mapping) |

**The row's grep check** — every remaining `401` hit in the model after the edit:
the data-path challenge (§3), the phantom-app data-path yields ("404/401 at Core"),
and the six new/updated split statements — no hit anywhere describes the listing
read's 401 as an access-denied class; every shape enumeration in the model (EP5 row,
M23, M25, both dispositions) carries the same four shapes with the same vocabulary.

## 9.2 — the split

### The mapping and the class

`gateway/core.py`:

- **New `TrustFaultError(CoreError)`** — raised on Core's UNAUTHORIZED. Its message
  is fixed vocabulary chosen in the class and naming nothing user-identifying — no
  token, claim, caller, or provider value: *"Core could not validate the sign-in's
  identity token; the administrator must check the trust configuration for this
  provider"*. Default status (502), like the deployment-fault `CoreError`.
- **`_read_json` splits the two codes**: `UNAUTHORIZED` raises `TrustFaultError`;
  `FORBIDDEN` raises the caller's access-denied class as before
  (`ToolsetAccessDeniedError` / `AppAccessDeniedError`); 404 and the
  unreadable/5xx shapes unchanged. The mapping is the one answer-to-refusal mapping
  both resource kinds' reads share, so the app read's 401 lands on the same
  trust-fault class.
- Docstrings re-worded: the module docstring's route enumeration names the 401 as
  the trust fault (neither an access verdict nor an existence answer), and
  `read_app_for_flow`'s "three shapes" becomes four.
- `gateway/flow.py` **untouched** — the credential call's own 401/403 branch stays
  folded, per D16's scope record (the adjacent site, its own future finding against
  its own live evidence). Verified: no diff reaches `gateway/flow.py`.

### The flow's page, consumption, and audit

`gateway/federation.py` `_core_read_refusal`:

- The trust fault is a **refusal**, so the record is consumed
  (`_consume_refused_flow`) before the page renders: a re-presented flow id lands on
  the expired page, and the identity access token and the provider's session refresh
  token — the very material Core could not validate — are dropped, retained by no
  re-run.
- **One audit record** on the `authorization` leg, its reason the class's own fixed
  text (the same fixed vocabulary the page carries) — distinct from the
  access-denied record's message, so the trail tells an authentication failure from
  an authorization verdict. Core logs no record of its 401s; the gateway's record is
  the only diagnosable trace.
- The page rendered is the operator-facing fault page with the class's fixed text
  (through the unchanged `core_error_response` → `gateway_error_page` path — see
  Deviations, item 1). The docstring's refusal/fault boundary re-worded to the
  four-shape reality.

### Operator docs

`docs/gateway-configuration.md`, "The Core routes the flow reads, and why": a new
"The read's refusal shapes, and who each one is for" block after the one-read
paragraph — 403 access denied (the no-access page, no upstream round-trip), 404 not
registered, **401 the trust fault, never an access denial** (the user's page text;
the operator's checklist: Core's provider entry's issuer pattern vs `IDP_ISSUER`,
its key set, its audience, or that key set's reachability; a 401 burst is a
trust-configuration or reachability event, never an access-change event; Core logs
no record of its 401s, so the gateway's audit record is the diagnosable trace), and
anything else a deployment fault. The block also states that all three refusals
consume the flow and that no user-identifying value reaches the page or the record.

### Tests — new (all in `tests/test_federation.py`, on the listing read unless noted)

- `test_a_trust_fault_listing_answer_is_not_an_access_denial` — the 401→trust-fault
  mapping: the trust-fault page (502, the class's fixed text), never the no-access
  page, never the not-registered page, no upstream round-trip.
- `test_the_trust_fault_page_names_no_user_identifying_value` — the page carries the
  fixed text and does NOT echo the identity token string, the `sub`, the email, the
  `project` claim value, or the provider session refresh token.
- `test_a_trust_fault_refusal_consumes_the_flow` — the flow-consumed behavior: the
  record is gone from the store and holds no identity credential; a replayed callback
  lands on the expired page; the exchange ran exactly once; one audit record
  (`flow_leg_failed`, leg `authorization`) whose reason equals the class's own fixed
  text — the fixed-vocabulary trust-fault reason.
- `test_an_app_read_401_is_the_trust_fault_too` — the app read's 401 lands on the
  same trust-fault class (the shared mapping), never the no-access page.
- The 403→denial mapping is the existing coverage, re-based by task 8 on the listing
  read (`test_a_refused_settings_read_fails_before_any_upstream_round_trip`, the
  non-admin refusal half, the admin both-ways test, the no-flow-state test).

### Gate outputs

| Gate | Result |
|---|---|
| `ruff check .` | All checks passed (exit 0) |
| `ruff format --check` on the touched files | 3 files already formatted (exit 0) |
| `pytest -q` (full suite) | **626 passed, 1 skipped** in 122.2s (622 → 626: the four new trust-fault tests) |
| `bandit -r gateway` | **0 findings** in `gateway/`; `bandit -r gateway scripts` totals unchanged from the task-8 triage (12 pre-existing, all in `scripts/`) — none new in this diff |
| `python scripts/check_publication_leaks.py` | **PASS** (exit 0): 3 waived findings, 0 unwaived |

The compose-boot gate and the group-6 review gates re-run on this group's diff are
the caller's to schedule (this pass touches no container and commits nothing).

### Deviations and decisions

1. **The trust-fault page reuses the generic operator-fault template, not a new one.**
   `gateway/errors.py` is outside this task's touch list, so the page is rendered
   through the unchanged `core_error_response` → `gateway_error_page` path with the
   class's fixed text as the reason: the page says the sign-in could not complete and
   that an administrator must check the trust configuration — the delta scenario's
   content — in fixed vocabulary only. The rendered page is distinct in content from
   the deployment-fault renderings (different fixed reason) and from the no-access and
   not-registered pages (different template), matching how the unknown-toolset shape
   already distinguishes itself from the deployment fault on the shared template. A
   dedicated template would be a one-line follow-up in `errors.py` if the reviewer
   wants the template itself distinct.
2. **The audit reason is the class's own text, on the existing `flow_leg_failed`
   event** (leg `authorization`) rather than a new closed-vocabulary token on
   `flow_branch_refused` — the prompt's "a distinct reason string, e.g. the class's
   own text"; the message is fixed vocabulary chosen in `gateway.core`, so the trail's
   distinction is exact and no new event vocabulary is introduced.
3. `openspec/changes/generalized-idp-federation/tasks.md` rows 9.1/9.2 ticked (the
   caller's brief includes tasks.md in this group's touch list).

### Per-row status

- **9.1 — done.** The threat model carries the fourth refusal shape on the
  listing-read row, the wrong-class diagnosability defect recorded as removed, the
  forged-answer residue's acceptance unchanged, and the register, dispositions, and
  grouped list consistent; the grep check green.
- **9.2 — done.** The 401/403 split landed in `_read_json` with the new
  `TrustFaultError` class; the flow renders the fixed fault page, consumes the record,
  and audits the fixed-vocabulary reason; the credential call's 401/403 branch in
  `gateway/flow.py` untouched per D16; the operator docs carry the trust-fault shape
  with the operator's checklist; four new tests green; all gates green.
