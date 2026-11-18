# Review round 7 — the focused review of authoring round 6 (the availability-oracle re-pinning, D15)

Reviewer: the independent reviewer subagent (fresh pass, falsify). Scope: the round-6
revisions to design.md (D15, the SIA, the Risks, Migration Plan step 8), the revised
delta spec, tasks group 8, the proposal and release-notes changes, and the two
evidence records — with every Core-side claim spot-checked fresh against the Core
checkout at `6dae044` (READ ONLY, `<the-sibling-core-checkout>`; the personal path
elided per the publication-discipline personal-path rule),
and the two extra spec re-pins verified against the main spec. No code, spec, or task
was changed by this review; no commit was made.

## The Core spot-checks — every cited fact verified at `6dae044`

- **ToolSetController.getToolSet** (`server/.../controller/ToolSetController.java:66-79`):
  resolves through `deploymentService.findDeployment(context, toolSetId)` at line 68,
  enriches the per-caller statuses on every answer (lines 70-71,
  `ResourceAuthStatusEnricher.enrichToolSet`), and answers 403 on
  `PermissionDeniedException`, 404 on `ResourceNotFoundException`, 500 otherwise
  (`respondError`, lines 172-183). Verified.
- **McpProxyController.handle** (`server/.../controller/McpProxyController.java:113-138`):
  the same `findDeployment` call at line 120; the admin gate (117-119) fires only on
  `useAllowedTools=false` (never the normal call); consent (:121) and rate limit
  (:124) are deployment-scoped, not role gates — exactly as the diagnosis states.
  Verified.
- **DeploymentService.findDeployment** (`server/.../service/DeploymentService.java:63-78`):
  config-sourced deployments check `deployment.hasAccess(context.getUserRoles())`
  (:66); resource-sourced toolsets fall through to the resource branch
  (:71-78) with `hasReadAccess` (:134) — the branch both routes share. Verified.
- **RoleBasedEntity.hasAccess** (`config/.../RoleBasedEntity.java:24-33`): `user_roles`
  null → allow everyone (:27-29). Verified — with one completeness note recorded as
  R7-O1 below (an explicitly empty, non-null set denies everyone; the artifacts never
  claim otherwise).
- **AdminRoleAuthorizationService** (`server/.../security/AdminRoleAuthorizationService.java:20-32`):
  the `platform` bucket answers `hasExplicitAdminAccess` alone — the entity's
  `user_roles` and publicness play no part; `public` reads are open to any
  authenticated caller; user buckets fall to the owner check. Verified.
- **Routing** (`server/.../data/RouteTemplate.java`): `PLATFORM_APP_TOOLSET_RESOURCE`
  (106-109), the listing route `TOOL_SET` (371-374), and `TOOL_SET_MCP_PROXY`
  (387-390) all match the cited patterns. Verified.
- **The projection parity** (`server/.../data/ToolSetData.java:68` →
  `ResourceAuthSettingsData.java:21-33`, snake_case, `NON_NULL`): every member the
  gateway's `ToolsetSettings` consumes — `authentication_type`, `client_id`,
  `authorization_endpoint`, `code_challenge`, `code_challenge_method`,
  `redirect_uri`, `scopes_supported`, `user_level_auth_status`,
  `global_auth_status` (`gateway/core.py:54-62, 339-362`) — is projected under the
  same wire spelling. The projection type has no fields for `client_secret`,
  `code_verifier`, `client_secret_hint`, `token_endpoint`, or
  `token_endpoint_auth_method`, and the gateway reads the toolset's
  `token_endpoint` nowhere (every `token_endpoint` hit in `gateway/` is the IdP
  leg's discovery/direct-mode member or the client-facing AS metadata) — the
  non-consumed claim and the structural never-cut-2 narrowing both hold. Verified.
- **The platform route's redaction and enrichment**
  (`server/.../controller/ConfigResourceController.java`): enriches toolsets
  identically at 1129-1138 and redacts `client_secret`/`code_verifier`/
  `client_secret_hint` for every non-admin caller (`redactSecretFields` 2030-2043,
  `redactAuthSettingsSecrets` 2045-2048). Verified.
- **The 500-on-missing-`auth_settings` claim**: `ToolSetData.toData` passes the
  stored block to `ResourceAuthSettingsData.toData`, which dereferences it — a null
  block NPEs inside the submitted task, landing on `respondError`'s default branch
  (500 "Internal error"). Verified by mechanism.
- **The invalid-entity-404 claim**: `MergedConfigStore.rebuildMergedConfig` tracks
  invalid blobs in `pendingInvalid` (line 1252) outside the merged toolsets map
  (folded at 1225/1247), so `selectDeployment` returns null and the resource branch
  404s — the data path's own resolution. Verified.
- **"One decision, never two"**: both the listing read and the data path call the
  same `DeploymentService.findDeployment` with the same id against the same caller
  context — the authorization decisions are one code path, not two that happen to
  agree. Verified.

## Gates re-run this pass

- `openspec validate generalized-idp-federation --strict` — **valid** (exit 0).
- `python scripts/check_publication_leaks.py` — **PASS** (exit 0; 222 tracked files;
  3 findings, all pre-existing and waived; 0 unwaived) — matching the round-6 record.

## The two extra re-pins (the flagged judgment call)

Verified against the main spec: "Unset mapping serves dynamically"
(`openspec/specs/mcp-signin/spec.md:472-474`) ends "…learned at the flow's
authenticated **settings read**", and "A valid dynamic name resolves with no local
configuration" (:550-552) ends "…is decided by the flow's authenticated **settings
read**, never by local configuration" — both genuinely name the settings read as the
existence/availability decider, and after the D15 re-pinning that read no longer
exists, so without the re-pin the main spec would survive the archive naming a
surface the flow no longer reads. Both requirements are carried in the delta as
MODIFIED with the re-pin declared as its own scenario amendment, and the proposal's
Capabilities bullet names the toolset-mapping and name-guard requirements. The
extension is within the amendment's declared scope and is not merely justified but
necessary for coherence. **The judgment call is right.**

The one-read shape: the listing route's enrichment is field-verified
(`user_level_auth_status`/`global_auth_status` in the projection, enriched on every
answer at `ToolSetController.java:70-71`), and the absence rule is stated fail-closed
in the delta spec (the "signed-in check fails closed" scenario: no readable status at
either level, or FAILED → no short-circuit) and priced in the design's Risks. Sound.

The SIA: the new EP5 table and DT-EP5-9 block carry the re-pricing ("the read's
authorization becomes the data path's own… never exceeding it, never refusing what it
serves"), the aligned-not-stricter claim is true by construction (one shared
`findDeployment`), never-cut 4's statement is correct (Core re-authorizes per data-path
call at `McpProxyController.java:120`, independent of the pre-check — the pre-check can
grant nothing), the level stays High with reasons, and the structural narrowing
(no projection fields for the verifier or secret) is recorded. Sound.

Task 8.1's enumerated threat-model mentions were each found in `docs/threat-model.md`
(§3's flow sketch :88; EP5's title/shape note :597-601; the mint-without-consent
bounding :645; the forged-answer rows :1503-1507; the app-read T5-7 comparison :343;
M23 :1886; the never-cut row 4; T5-3's disposition :1955; "one settings read per flow"
:1541) — the row is executable as written.

## Findings

### R7-1 — Task 8.2's operator-doc surface is under-enumerated: two live doc sections document the retired read as the flow's own, and neither is in any task row

**Severity: MEDIUM (blocking for task group 8's execution as written).**

**Evidence:**

- `docs/gateway-configuration.md` §"The Core routes the flow reads, and why"
  (lines 680-696): the table's first row names `GET /v1/toolsets/{bucket}/{name}` as
  "the read that enforces DIAL authorization (403 when the user has no access)"; the
  second row describes the per-caller status read "on the builds whose settings route
  does not return them" — the read D15 deletes; and the closing paragraph (688-696)
  documents the two-read, content-decided fallback — deleted by D15's one-read shape.
  Task 8.2 names `docs/gateway-configuration.md` only as "(both table rows)" — the two
  `TOOLSET_BUCKET` rows at lines 65 and 542. The §680 section's table and prose are
  unnamed under any reading of "both table rows".
- `docs/local-environment.md` lines 102-118: "`GET {core}/v1/toolsets/platform/notion`
  # the stored settings, **as the sign-in flow reads them**" (line 105), and the
  paragraph at 114-118 describing the settings-route-then-listing fallback. Task 8.2
  does not mention `docs/local-environment.md` at all (the proposal's Impact line
  names it, but the executable row — what the implementer runs — does not).

**Why it matters:** an implementer executing 8.2 as written leaves the operator
reference and the local-environment guide documenting the retired platform route as
the flow's authorization-enforcing read and the deleted fallback as current behavior —
operator docs are Class A surfaces (D14) and would contradict the re-pinned spec. The
functional gates would stay green (the platform route still exists and answers), so
nothing else catches it.

**Disposition (for the author, next round):** extend task 8.2's doc surface (or add a
row) to rewrite both sections to the one-read story — the listing read as the
authorization-bearing, settings-carrying, status-carrying read; the fallback and the
status row deleted. One tasks.md edit; no design or spec change follows from it.

### R7-2 — D15's "answers 200 exactly when the data path would serve the caller" outruns the verified property by two data-path gates the listing read does not run

**Severity: LOW (wording precision; the normative text is correctly scoped).**

**Evidence:** the data path additionally runs `consentService.verifyUserConsent`
(`McpProxyController.java:121`) and the rate limiter (:124) — the diagnosis itself
calls these "deployment-scoped, not role gates". A 200 listing answer therefore does
not guarantee the data path serves the call (a missing consent or a rate-limit hit
still refuses it). The delta spec's requirement scopes the claim correctly ("both are
Core's deployment resolution of the name against the caller's roles"); the design
prose — D15's decision paragraph and the EP5 row's "equals the data path's on every
axis" — is authorization-scoped in context, but the bare "exactly when it would serve"
sentence reads one gate wider than what was verified.

**Disposition:** optional tightening of the D15 sentence to "exactly when the data
path's *authorization* would admit them"; the EP5 row already carries the correct
scoping statement as its substance. Not blocking.

### R7-3 — The spike scripts' platform-route use is undispositioned in the change's artifacts

**Severity: LOW (hygiene; the design's claim is unaffected).**

**Evidence:** `scripts/spike_register_toolset.py:52,112` addresses the platform admin
route for toolset *registration* — a legitimate admin operation and the route's
designed purpose, unaffected by D15. `scripts/spike_establish_credential.py:51` carries
a `TOOLSET_BUCKET = "platform"` constant that is already dead today (the spike reads
the listing route, lines 62/99; nothing else references the constant). Task 8.2's
retirement sweep does not name the spikes, so a post-change `TOOLSET_BUCKET` grep hits
them with no stated disposition — and this repo's discipline is that greps back claims.

**Disposition:** a one-line disposition in task 8.2 or the round evidence: delete the
dead constant in `spike_establish_credential.py`; state that the registration spike's
admin-route use is out of the flow's scope and stays. The design's "no read the flow
makes addresses a bucket any more" remains true as written.

### R7-O1 — Observation, no action: `RoleBasedEntity.hasAccess` has a third case the record's wording skips

`user_roles` null → allow everyone (`RoleBasedEntity.java:27-29`, verified); an
explicitly **empty, non-null** set → deny everyone (`!expectedUserRoles.isEmpty() && …`
is false, lines 31-32); non-empty → any intersection. The diagnosis and D15 state only
"null → allow everyone; non-empty → intersection" — the omission is in the safe
direction (an empty set denies, it never falsely admits), and the delta scenario's "a
toolset with no user-roles restriction" is the null case, so nothing normative is
affected. Recorded so the record's three-case semantics are complete.

### R7-O2 — Observation, already declared: the retained scenario title keeps the historical spelling

"Unknown toolset refused at the flow's settings read" retains its title verbatim as
the delta-discipline identifier while the body names the listing read; the amendment
note declares this and the reason (the delta discipline matches scenarios by header
and has no rename). Handled as well as the tooling allows; the main spec will carry a
title whose phrase no longer names a live surface, with the body and requirement text
precise. No action available or needed.

## Verdict

**Findings — one blocking for the next round, none touching the decision itself.**
The D15 decision, the field-parity verification, the semantic notes, the SIA
re-pricing, the delta spec's re-pinned rows (the diagnosed four and the author's two
extra — both verified necessary), and the proposal/release-notes changes all verify
against the Core source at `6dae044`; both gates pass as recorded. R7-1 (task 8.2's
operator-doc surface) must be fixed before task group 8 is handed to an implementer —
it is a tasks-file completeness gap, not a design or spec defect. R7-2 and R7-3 are
optional tightenings that may be dispositioned in the round evidence. With R7-1
repaired, the change is ready for implementation.

## Dispositions (the authoring round after this review, 2026-11-06)

The three actionable findings were disposed in the artifacts only — no implementation
code was touched and no commit was made; the two observations need no action, as the
review itself states.

- **R7-1 (medium, blocking) — disposed in `tasks.md`, task 8.2.** The operator-doc
  surface is extended to the two live sections the review pinned: the
  `docs/gateway-configuration.md` sweep now names, beyond the two `TOOLSET_BUCKET`
  table rows, the "The Core routes the flow reads, and why" section (the
  platform-route row, the status-read row, and the two-read content-decided fallback
  paragraph), and `docs/local-environment.md`'s toolset-route block (the two-route
  sketch and the fallback paragraph that follows it) joins the sweep. Both are
  rewritten to the one-read story — the listing route as the availability oracle, the
  one authorization-bearing, settings-carrying, status-carrying read the flow makes —
  with the platform settings route, the status row, and the fallback deleted. The row
  is now executable as written for the whole operator surface; no design or spec
  change follows, exactly as the review's disposition anticipated.
- **R7-2 (low) — disposed in `design.md`, D15.** The sentence tightened to the
  verified property, one sentence: "the listing read answers 200 exactly when the
  data path's authorization — the deployment resolution of the name against the
  caller's roles — would admit the caller, 403 when that decision would refuse them,
  and 404 for a name it does not know; the data path additionally runs consent and
  rate-limit gates the listing read does not run, so the verified property is that
  resolution-and-roles decision — what the availability pre-check needs, and all it
  can claim: the pre-check grants nothing, and Core re-authorizes on every data-path
  call." The EP5 row's scoping statement was already correct and is unchanged.
- **R7-3 (low) — disposed in `tasks.md`, task 8.2** (the sweep row, so the
  implementer's own grep surface carries the disposition): the sweep deletes the dead
  `TOOLSET_BUCKET` constant in `scripts/spike_establish_credential.py` (dead today —
  the spike reads the listing route and nothing references the constant), and records
  that `scripts/spike_register_toolset.py`'s platform-admin-route addressing stays —
  toolset registration through the platform admin API is the route's designed
  purpose, a registration operation and never a flow read, so D15 retires nothing of
  it. A post-change `TOOLSET_BUCKET` grep now has a stated disposition for every hit.
- **R7-O1 / R7-O2** — observations recorded by the review; no action, per the
  review's own statements (the omission is in the safe direction; the retained title
  is the delta discipline's identifier).

Gates re-run after the disposition edits (from the worktree, the main checkout's venv
python, `PYTHONUTF8=1`):

- `openspec validate generalized-idp-federation --strict` — **valid** (exit 0).
- `python scripts/check_publication_leaks.py` — **PASS** (exit 0; 222 tracked files
  scanned; 3 findings, all pre-existing and waived — two in
  `docs/evidence/d0a/review-round-1.md`, one in `scripts/import_background.py`;
  0 unwaived).

With R7-1 repaired in the executable row, the review's own readiness statement holds:
the change is ready for implementation.

