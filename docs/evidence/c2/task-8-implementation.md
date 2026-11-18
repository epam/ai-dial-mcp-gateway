# Task group 8 — the availability oracle re-implementation (D15)

Date: 2026-11-06. Implementer pass; worktree `d0a-publication-discipline`.
Normative sources: design.md D15 and its §7 delta, the delta spec's re-pinned rows
(authoring round 6), the diagnosis at `docs/evidence/c2/availability-read-diagnosis.md`.
Landed in the standing order: the threat model first (8.1), then the code (8.2).
Not committed; no containers touched.

## 8.1 — the threat-model re-pin (landed before the code)

Every mechanism-level "settings read" mention in `docs/threat-model.md` re-worded to
the listing read's, per design.md §7's enumeration:

| Where | What changed |
|---|---|
| §3's flow sketch | "existence is decided post-authentication, at the flow's per-user settings read" → "per-user listing read" |
| EP5's title and shape note | the route list now names "the toolset listing read — the deployment-listing route `GET /openai/toolsets/{name}`, the one read that carries the flow's availability decision, the settings projection, and the per-caller statuses"; the kind-and-signed-in decisions ride the per-user listing read; the shape note states the listing read's **authorization-equals-the-data-path property** and records the **false-denial defect as removed by the re-pinning** (the admin-role route "answered a question the data path never asks and refused non-admin users public toolsets the data path serves") |
| The mint-without-consent row's bounding | "the DIAL authorization check (the per-user settings read)" → "(the per-user listing read)" |
| The forged signed-in answer row (T5-7) | entry point cell and body re-pinned to the per-user listing read; the row's closing bounds now name the listing route as "the answer's latest member" and state that the false-denial defect the prior admin-role read carried is removed by the re-pinning, not accepted |
| The forged app answer row's comparison | "the same trust that already carries the toolset settings" → "the toolset listing read's projection" |
| The app-read residual's T5-7 comparison (RES-19's extension record) | "the toolset settings read's forged answer (T5-7)" → "the toolset listing read's" |
| T5-2 items 4 and 8 | "a forged settings answer"/"the refreshed settings read" → the listing read; "settings-read refusals … audited" → "the listing read's refusals" |
| T5-3 items 7–8 and disposition | "one settings read per flow" → "one listing read per flow"; "settings-read refusals on the trail" → the listing read's; the disposition's "the per-user settings read is the toolset namespace's existence decision" → "the per-user listing read" |
| The never-cut table's row 4 | the flow's per-user listing read, with the deployment-listing route's authorization-equals-the-data-path property and the false-denial removal stated in the ruling |
| M23's routing-decision row | "on its own settings read" → "on its own listing read" |
| §13's T5-3 and T5-7 disposition rows | T5-3 re-worded to the listing read; T5-7's class extended — "the listing route, the re-pinned availability oracle, whose authorization is the data path's own, so the false-denial defect the prior admin-role availability read carried is removed by the re-pinning rather than accepted" (RES-19's acceptance unchanged) |

Two adjacent records the fallback deletion obsoleted, re-worded with the same sweep
(mechanism vocabulary, no substantive re-pricing): **RES-3** (the token-use rule's
presentations — the one-to-three-presentations shape, priced on the two-read fallback,
becomes at most two: the listing read and the credential call; the re-open trigger is a
second decision-step read reintroduced) and the **A2 asset row / T5-1 row / T5-1's
Reduce-Attack-Surface item** (the same one-to-three → at-most-two correction).

**The closing grep check the row names** — `grep -i "settings read|settings-read|settings
route|settings answer" docs/threat-model.md` after the edit: **zero hits**. No
mechanism-level "settings read" survives; the D8-scoped local-deployment facts are
untouched (none named the toolset read).

## 8.2 — the re-implementation

### The one-read shape — what merged where

`gateway/core.py`:

- `read_toolset_settings` now addresses `GET /openai/toolsets/{name}`
  (`listing_url()`; `settings_url()`/`status_url()` deleted with the
  `toolset_bucket` spelling they consumed). One read serves all three purposes:
  availability (the 403 is the data path's own deployment-resolution decision),
  the settings projection the consent branch builds from, and the per-caller
  statuses read off the same answer's `auth_settings` enrichment.
- `read_toolset_status` **deleted**; the two-call fallback inside
  `read_toolset_for_flow` **deleted** — the method is now the one listing read plus
  the status object derived from the settings the same answer carried. Its helpers
  `_status_projection` and `_status_of` are deleted with it; `_status_of_settings`
  survives as the merge point.
- The absence rule, fail closed: statuses absent or unreadable in the listing
  answer → not signed in → the flow falls into the kind branch (an OAUTH toolset
  re-runs its consent, the benign loop; a non-OAuth toolset is refused as ever).
  No second read exists to ask.
- The status-field mappings stay: 403 (and 401) → `ToolsetAccessDeniedError`
  (the no-access page), 404 → `ToolsetUnknownError` (the existence refusal,
  `unknown_toolset`), 500 or otherwise unreadable → the operator-facing
  `CoreError` fault page, never an existence answer.
- Field parity: the listing projection's `auth_settings` is snake_case NON_NULL
  with the same member spellings the flow reads (`authentication_type`,
  `client_id`, `authorization_endpoint`, `redirect_uri`, `code_challenge`,
  `code_challenge_method`, `scopes_supported`, `user_level_auth_status`,
  `global_auth_status`) — D15's verified-parity record; `ToolsetSettings`' parsing
  needed no wire-spelling change. The module docstring is re-worded to the
  one-read story.

`gateway/flow.py`: the toolset-read comment and the `ToolsetLegResult` docstring
re-worded to the one-read story.

`gateway/settings.py`: `toolset_bucket` retired (field and its comment removed; no
validator referenced it).

Configuration surfaces: `.env.example`'s `TOOLSET_BUCKET` line and its comment
removed; `docker-compose.yml`'s `TOOLSET_BUCKET` entry removed (the D8-scoped helper
block untouched). `scripts/spike_establish_credential.py`'s dead `TOOLSET_BUCKET`
constant removed, its route comment now naming the one listing route.
`scripts/spike_register_toolset.py` **unchanged by design** — toolset registration
through the platform admin API (`PUT /v1/toolsets/platform/{name}`) is that route's
designed purpose, a registration operation and never a flow read; the post-change
`TOOLSET_BUCKET` grep's one live hit is this deliberate keeper.

Operator docs: `docs/gateway-configuration.md` — "The Core routes the flow reads, and
why" rewritten to the ONE-read story (the listing route as the availability oracle
carrying authorization, settings, and statuses; the platform settings-route row, the
status row, and the content-decided fallback paragraph deleted; the app row kept); both
`TOOLSET_BUCKET` table rows gone; the token-presentation paragraph ("twice or three
times") corrected to at most two, and the doc's remaining "settings read" phrases
re-pinned to the listing read's. `docs/local-environment.md` — the toolset-route block
rewritten the same way: one route, the listing read, carrying the stored settings and
the per-caller statuses, no fallback.

### Tests — re-based and new

Fixture re-base (the constants collapse to the single listing URL,
`http://core:8080/openai/toolsets/{name}`): `tests/test_audit.py`,
`tests/test_custody.py`, `tests/test_federation.py`, `tests/test_idp.py` — the
`CORE_SETTINGS_URL`/`CORE_STATUS_URL` pairs are now one `CORE_LISTING_URL`, and the
listing projection carries the per-caller statuses beside the OAuth fields (SIGNED_OUT
by default, overridden to SIGNED_IN where the short-circuit is under test).

- The denial scenario re-based on the listing read's 403 (no-access page, no upstream
  round-trip) — previously split across two routes, now one.
- The unknown-toolset scenarios re-based on the listing read's 404
  (`unknown_toolset`, the existence refusal, no flow state surviving).
- The absence-rule scenarios (absent / unreadable / FAILED status → no short-circuit,
  fail closed into the kind branch; app-level-only status → the same) now run on the
  listing read's own answer.
- `read_toolset_status`'s deletion reflected: the fallback test
  (`test_the_flow_falls_back_to_the_status_route_when_the_settings_route_omits_it`)
  is **removed**; its coverage is merged into
  `test_the_flows_toolset_read_is_one_request` (one Core GET on the listing route,
  the statuses it carries are the ones acted on) and the absence-rule tests (no
  readable status → no short-circuit, never a second read).
- **The regression the live run demands** —
  `test_a_non_admin_user_is_admitted_to_a_public_toolset`: a non-admin identity
  (`roles=["<tenant-role>"]`), a public toolset (no `user_roles` restriction, so
  Core's listing read answers 200) → the flow **PASSES availability** and proceeds to
  the consent leg, never the no-access page. The delta spec's public-toolset scenario,
  machine-checked.
- The refusal half — `test_a_non_admin_user_is_refused_where_the_data_path_refuses_them`:
  the listing read's 403 still refuses a non-admin, no upstream round-trip.
- The admin axis both ways — `test_the_admin_axis_agrees_with_the_data_path_both_ways`:
  an admin caller passes for a toolset their roles admit (listing 200 → the flow
  proceeds) and is refused for a role-restricted toolset that excludes them (listing
  403 → the no-access page) — the data path's own decision, both axes.
- The fault shape — `test_a_fault_listing_answer_is_a_fault_never_an_existence_answer`:
  a listing answer of 500 lands on the operator-facing fault page (502), never the
  not-registered page.

### Gate outputs

| Gate | Result |
|---|---|
| `ruff check .` | All checks passed (exit 0) |
| `ruff format --check` on the touched files | 8 files already formatted (exit 0) |
| `pytest -q` (full suite) | **622 passed, 1 skipped** in 129.8s |
| `bandit -r gateway scripts` | 12 findings, all pre-existing (B404/B603/B607/B310/B105 in `scripts/check_publication_leaks.py`, `scripts/probe_*.py`, `scripts/spike_env.py`); **none new** in this diff — `gateway/` carries none |
| `python scripts/check_publication_leaks.py` | **PASS** (exit 0): 3 waived findings, 0 unwaived |

The compose-boot gate and the group-6 review gates re-run on this group's diff are the
caller's to schedule (this pass touches no container and commits nothing).

### Deviations and flags

1. **The threat-model sweep reached three adjacent records the enumeration did not
   name** — RES-3's presentations shape, the A2 asset row, and T5-1's
   Reduce-Attack-Surface item — because the two-read fallback's deletion makes their
   "one to three presentations" figure false; re-worded as vocabulary, no re-pricing.
2. **`.env.example`'s TOOLSETS comment and `gateway/settings.py`'s two guard
   docstrings** said "at the flow's settings read"; re-pinned to "the flow's listing
   read" (files already in this task's touch list; vocabulary only).
3. **Out-of-scope vocabulary residue, flagged not touched**: four sibling module
   docstrings outside this task's touch list still use "settings read" as generic
   vocabulary for the flow's authenticated read — `gateway/authorize.py` (the
   two-kind existence note), `gateway/discovery.py`, `gateway/routes.py`, and
   `gateway/federation.py` (the routing-decision and reason-vocabulary docstrings).
   The behavior they describe is the re-pinned read already; a later vocabulary
   sweep or the reviewer's disposal can rename them.
4. `openspec/changes/generalized-idp-federation/tasks.md` rows 8.1/8.2 left
   unticked — the task's touch list did not include the change folder; the caller
   disposes of the checkboxes.

### Per-row status

- **8.1 — done.** The threat model re-pinned before the code (the standing order);
  the closing grep check green (zero mechanism-level "settings read" hits); the
  false-denial defect recorded as removed; T5-7's class extended to the listing
  route with RES-19's acceptance unchanged; the register and grouped list consistent.
- **8.2 — done.** The one-read shape landed in `gateway/core.py` and
  `gateway/flow.py`; `toolset_bucket` retired from `gateway/settings.py`,
  `.env.example`, `docker-compose.yml`, both operator docs, and the dead spike
  constant (the registration spike kept by design); the tests re-based on the single
  listing URL with the regression, both-axis, absence-rule, and fault cases green;
  all gates green.
