# Review 1 — findings and dispositions (planning-artifact fix pass)

The first independent review of this change's planning artifacts (2026-11-03)
returned ten findings. All ten are addressed in the planning artifacts only —
no code was touched. Per finding: the finding's substance, the disposition,
and where the fix landed. Two additional defects of the same class as F3 were
found and fixed during the pass (recorded below as F3-d and F3-e).

## F1 (MAJOR) — design.md D4 mis-quoted the charter

D4's closing paragraph attributed a quote to the charter ("decide honestly what
serves that question for apps, and record the choice either way") that exists
only in design.md; the charter (`docs/production-roadmap.md` §C1.5) is silent on
a status surface.

**Disposition: fixed.** The sentence now states the fact: the charter is silent
on a status surface for apps; the choice is recorded either way, as a decision
of record. Re-checked proposal.md and release-notes-draft.md for echoes of the
attribution — none found. Landed: design.md D4's closing paragraph.

## F2 (MAJOR) — the delta's first ADDED requirement mis-stated a verified Core fact (401 vs 403)

The requirement's 401 enumeration included "a valid token whose user cannot
pass Core's per-call authorization" as a 401 cause; the Core source shows the
opposite: `DeploymentService.findDeployment` → `PermissionDeniedException` →
**403** (`McpProxyController.handleError:479-481`), and `ResourceNotFound` →
404 (`:484-485`).

**Disposition: fixed.** The enumeration is re-worded to "no token, or an
invalid or expired token", and the requirement now teaches the actual
outcomes: an access denial answers Core's own 403 and an unknown app a 404,
both crossing the router untouched because the challenge synthesis fires on
401 only — neither a sign-in cause. Verified in the Core source this pass and
recorded as evidence fact 8. Landed: delta spec, the apps front-door
requirement's first paragraph.

## F3 (MINOR) — declared-amendment notes mis-named/omitted retained-scenario re-wordings

Three declared notes did not match what the delta actually re-words, so the
migration plan's byte-identical-except-declared claim did not hold
truthfully.

**(a)** The authorization-requests note named only "Unknown resource" while
"One-toolset inference" and "Guard-failing resource refused" are also
re-worded. **Fixed:** the note now declares all three by title, each with its
re-wording stated.

**(b)** The toolset-mapping note named "the retained 'One-toolset inference'
scenario" — a scenario that requirement does not carry; the re-worded scenario
is "Inference without a single-entry restriction refused". **Fixed:** the note
names it by its actual title with the exact WHEN re-wording.

**(c)** The abuse-bounds note said the retained scenario "is unchanged" while
"Over-limit discovery requests"' WHEN is re-worded. **Fixed:** the note
declares the WHEN re-wording ("— on the toolset route or the apps route —"
inserted).

**F3-d (found during the fix, same class):** the lifecycle note said "the
retained scenarios are otherwise unchanged" while "A completed flow's chain is
attributable end to end"'s THEN is re-worded (the facts vocabulary's
"toolset"→"resource"). **Fixed:** the note declares that scenario's re-wording
by title.

**F3-e (found during the fix, same class):** the issued-tokens note declared
the retained scenarios' re-wording only generically ("unchanged except the
same resource wording") without naming titles. **Fixed:** the note now names
"Token carries the marker audience" and "The refresh token is not a
Core-acceptable token" with their exact wording change.

All landed: delta spec, the four requirements' declared-amendment notes.

## F4 (MINOR) — the threat-model delta had two ledger-consistency defects

**(a)** "T5-9 (new)" skipped the free id — the ledger's EP5 threats run
T5-1..T5-7; no T5-8 exists. **Fixed:** renumbered to **T5-8**; cross-references
updated (task 6.2, release-notes-draft.md). Design.md §7's entry and every
other reference now say T5-8.

**(b)** The apps discovery-route enumeration was mapped onto T1-15 — an E9
threat on the *authenticated* status endpoint whose controls explicitly refuse
anonymous probing; the apps enumerable set is served on an *unauthenticated*
discovery route, so amending T1-15 contradicts that row's controls. **Fixed by
the first option:** landed as a new row **T1-24** (T1-23 is taken by the app
mint), with the reason it is a row of its own stated in §7; the
attacker-inventory bullet, the no-new-residual bullet, the Risks echo, task
6.2, and the release notes all updated. The no-new-residual claim is
re-worded to match: the apps-inventory disclosure lands as T1-24's stated
disposition, not as an amendment of an existing row.

## F5 (MINOR) — tasks/Impact omitted two files the delta's requirements force changes in

The routing decision the app branch hooks lives in
`gateway/federation.py::_run_identity_leg` (not `gateway/flow.py`, which task
3.2 named alone), and the lifecycle requirement's changes land in
`gateway/audit.py` (the allocation record's resource-kind fact, the facts
vocabulary's "toolset"→"resource" across the emit sites, the closed
vocabulary's new reason tokens).

**Disposition: fixed.** Task 3.2 names `gateway/federation.py` (with the
reason — the decision lives in `_run_identity_leg`) and carries the
`gateway/audit.py` work with its verify rows; the proposal's Impact list
mirrors both files. Verified in the source this pass: `_run_identity_leg` is
`gateway/federation.py:99`, and every audit emit site carries the `toolset`
fact field (`gateway/audit.py`).

## F6 (MINOR) — task 7.1 omitted the configured `mypy` static gate

`mypy` is configured in `pyproject.toml` (`[tool.mypy]`, pydantic plugin);
CLAUDE.md gate 1 names "mypy (if configured)"; C1's gate task included it.

**Disposition: fixed.** `mypy` added to task 7.1's gate list, between
`ruff format --check` and `pytest -q`.

## F7 (MINOR) — the main spec's toolset guard requirement was left kind-ambiguous

The main spec's "Toolset names are guarded at request time" lists surfaces
(the authorization request's `resource`, the refresh grant's resource) that
after this change resolve two kinds under two guards, while naming only the
toolset guard.

**Disposition: fixed.** The delta gains a MODIFIED entry for that requirement
carrying the full amended text — one added sentence: where a listed surface
serves both kinds, the resource's kind decides which guard applies, and the
apps shape passes the app guard of the app-resource requirement — with a
declared note (the retained scenarios are unchanged) and the four retained
scenarios carried verbatim. The proposal's Modified Capabilities list and the
release notes mirror the scoping.

## F8 (NOTE) — D4's "only token-shape causes" was slightly overbroad

The app's own upstream MCP endpoint can answer 401 — no stored credential is
attached on the app MCP leg (`McpUpstreamAuthInjector.java:60-74`, the
`Application` overload attaches app id, optional per-request key, and config
delivery only) — and the router's rewrite would point a harness at the
gateway's sign-in for a 401 the flow cannot resolve: the same benign-loop
class as the toolset path's upstream-401 rewrite.

**Disposition: fixed, as the one-clause caveat.** The caveat lands in the
delta spec's status requirement (and its "No app status surface" scenario),
in D4's opening paragraph, and in the proposal's status bullet — each now
separates the token-shape 401s (which the flow resolves) from the app's own
upstream 401 (which nothing resolves, the benign loop). Verified in the Core
source this pass and recorded as evidence fact 9. No new threat shape opened,
per the finding.

## F9 (NOTE) — evidence file:line anchors drifted a line or two

Every cited fact was verified; the anchors drifted.

**Disposition: fixed where verified** (all anchors were re-checked against the
Core source this pass): RouteTemplate `APPLICATION_MCP_PROXY` 390-393 →
391-394 and `TOOL_SET_MCP_PROXY` 386-389 → 387-390; ControllerSelector's
toolset wiring 306-309 → 304-307; Proxy `isMcpResourcePath` 501-509 →
501-503; WellKnownResourceMetadataService's disabled-empty return "~83-85" →
92-95 (+ `isDisabled` 169-171) and the path build 95-104 → 92-103;
WellKnownResourceMetadataController 22-31 → 22-44 (404 at 25-29);
ApplicationController's single-app GET 105-119 → 102-126 (404 at 104-106) and
fact 7's 105-106 → 104-106; ResourceCredentialsController 84-99 → 83-99;
ExternalServiceCredentialsController 545-558 → 552-558; IdentityProvider
`verifyJwt` 344-352 → 342-357 (`withAudience` at 351). Anchors that were
already exact (AiDial.java:393; the 403-406/399-402 metadata templates;
Proxy 347-363; the service constructor 38-46; Application.java:24 and 42-44;
SecuredResource.java:14-15; ResourceAuthSettings.java:38-41;
DeploymentService.java:63-78; IdentityProvider.java:204) are unchanged.

## F10 (NOTE) — the "No app status surface" scenario had no probe

The scenario held by construction; a one-row routing probe would make it
checkable.

**Disposition: fixed.** Task 5.1's probe battery gains the row: a status path
under the apps namespace (`GET /apps/<name>/status`) falls to the router's
catch-all and is answered by Core's 404 — the scenario made checkable.
(Verified against the current router config: no location matches that shape,
so the catch-all `location /` proxies it to Core, which has no `/apps/…`
route.)

## Validation

`openspec validate apps-with-mcp-endpoints` re-run after all fixes: **valid**.

---

# Round 2 — re-review findings and dispositions (declaratory fix pass)

The re-review round (2026-11-03) returned two undeclared re-wording items, two
MINOR findings, and two NOTEs. All are addressed in the planning artifacts only —
no design change, no code, no Core-fact re-verification. Per item: the finding,
the disposition, and where the fix landed.

## (i) Undeclared re-wording — federation requirement, "Unknown toolset refused
at the flow's settings read" THEN

Beyond the declared clause ("the system's only existence refusal" → the toolset
namespace's), the mirror-property parenthetical also gained "in both namespaces"
("registry-independent on both sides of the front door **in both namespaces**"),
while the amendment note said "in one clause only".

**Disposition: fixed by declaring, not reverting.** The note now declares both
re-wordings — the clause swap (with the app read named as the app namespace's)
and the parenthetical's "in both namespaces" — each with its before/after
wording, and the reason covers both (the app read's existence refusal and the
mirror property's extension to the second namespace). Landed: delta spec, the
federation requirement's declared-amendment note.

## (ii) Undeclared re-wording — issued-tokens requirement, "Token carries the
marker audience" THEN

Beyond the declared resource-wording swap, the delta appends "— the marker being
the member Core's check reads"; the note declared the retained scenarios
"otherwise unchanged".

**Disposition: fixed by declaring, not reverting.** The note now names the
appended closing clause for "Token carries the marker audience" verbatim (it
restates the verified Core fact the requirement text now carries) and states
that "The refresh token is not a Core-acceptable token" is the scenario that is
otherwise unchanged. Landed: delta spec, the issued-tokens requirement's
declared-amendment note.

## R1 (MINOR) — the existence-refusal wording migration was incomplete; a
post-sync main spec would contradict itself

The "per-namespace" landing covered the federation requirement's scenario, but
the same phrase survives in the main spec's unmodified discovery requirement
("…the federation requirement's unknown-toolset scenario, the system's only
existence refusal"), and `docs/threat-model.md` T5-3 says "the per-user
settings read is the system's only existence decision" — false once the app read
exists — with neither design.md §7 nor task 6.2 listing T5-3's wording among
the amendments.

**Disposition: fixed, both halves.**

- The delta gains a MODIFIED entry for the discovery requirement ("Discovery
  documents describe one flat authorization server"), carrying the main spec's
  text byte-identical except one declared clause — "the system's only existence
  refusal" becomes "the toolset namespace's existence refusal" — with a declared
  note and all five retained scenarios carried verbatim. The MODIFIED-entry form
  was picked over extending the federation note because the discovery
  requirement is a separate requirement: only a delta entry of its own makes the
  sync change its text. Landed: delta spec (the new MODIFIED entry, placed after
  the federation flow requirement); mirrored in the proposal's What Changes
  bullet and Modified Capabilities list, in design.md D2 (the amendment now
  names both places the phrase lives), and in the Migration Plan's Spec sync
  bullet (below, R2).
- T5-3's wording is added to design.md §7's amendment list (a new T5-3 amended
  bullet: the settings read is the toolset namespace's existence decision, the
  app read the apps namespace's, both post-authentication on the same internal
  leg — in both the §8 threat row and its disposition row) and to task 6.2's
  amend list and verify rows. The threat-model file itself is untouched here —
  it is updated at implementation time by task 6.2, which now catches the
  wording. Landed: design.md §7; tasks.md task 6.2; release-notes-draft.md's
  threat-model enumeration gains "T5-3" among the amended rows.

## R2 (MINOR) — design.md Migration Plan's "Spec sync" bullet overstated
completeness

The bullet claimed the six named declared amendments were "the only main-spec
text changes", but eight requirements were MODIFIED — the authorization
requirement's two-shape rewrite and the status requirement's
scoping-plus-caveat are main-spec text changes outside the six.

**Disposition: fixed by enumerating.** The bullet now enumerates all MODIFIED
requirements by name — nine, counting R1's discovery entry: discovery
(the existence-refusal clause), authorization requests (the two-shape resource
resolution, three retained scenario re-wordings declared), the federation flow
(the declared existence-refusal amendment), issued tokens (the audience and
Core-side enforcement wording, two retained scenario re-wordings declared),
sign-in status (scoped to toolset resources with the no-app-status reason), the
toolset guard (the kind-decides-the-guard scoping), the toolset mapping (the
inference wording names the toolset restriction), abuse bounds (the limiter
clause covers both discovery routes), and flow lifecycle audit (the
resource-kind fact and the app flow's events) — and keeps the "only main-spec
text changes" claim, now truthfully. Landed: design.md, Migration Plan, the
Spec sync bullet.

## R3 (NOTE) — temporal phrase "after this change" in normative text

The delta's toolset-guard requirement read "where a listed surface serves both
kinds after this change" — a process reference once synced.

**Disposition: fixed.** The phrase is dropped; "where a listed surface serves
both kinds" carries the rule. The requirement's declared note ("one sentence
added, the kind-decides-the-guard rule") stays truthful — the sentence is still
one added sentence. Landed: delta spec, the toolset-guard requirement's text.

## R4 (NOTE) — the SIA's shape judgment; flagged for the owner, not fixed

The SIA prices the change as delta tables on existing surface classes, while
the standing method's "adds a surface" trigger names "a new endpoint" — and
this change adds new endpoints (a new public path shape, a new unauthenticated
discovery route) without adding a trust boundary, credential, or grant type.

**Disposition: not fixed — recorded for the owner's ruling.** A "Questions for
the owner" block is added to design.md §8 stating the judgment, the trigger it
sits against, and what each answer implies (the tables stand as written, or the
complete new-entry-point enumeration is owed) — behavior and reason only. The
SIA's own shape judgment stays as authored; falsifying or confirming it is the
owner's call. Landed: design.md §8, the "Questions for the owner" block.

## Round-2 validation

`openspec validate apps-with-mcp-endpoints` (and `--specs`) re-run after all
fixes: **valid**. The mechanical byte-diff re-run across all nine MODIFIED
requirements and every retained scenario: every diff site is covered by a
declared amendment note or is the MODIFIED entry's own requirement text; all
retained scenarios not named by a note are byte-identical, so the Migration
Plan's Spec sync claim now holds truthfully. *(This "every diff site is
covered" claim did not hold for one site — corrected by round 3, below.)*

---

# Round 3 — narrow re-check correction (one declaratory defect)

The narrow re-check round (2026-11-03) found exactly one defect: the
discovery requirement's MODIFIED-entry body spelled "CIMID-capable" where the
main spec's same sentence reads "CIMD-capable" — one inserted "I", an
undeclared normalization that falsified the entry's own "amended by this
change in one clause only" note and the byte-identity claim. The round-2
validation's "every diff site is covered" statement above did not hold for
this site; it is corrected by this round.

**Disposition: fixed by reverting to byte-identity.** The character is
reverted — the delta body now reads "CIMD-capable", matching the main spec's
sentence exactly. The main spec's own internal inconsistency (its scenario
titles use "CIMD", other prose uses "CIMID") is pre-existing and out of scope
for this change: nothing in the main spec is normalized here, and no
normalization is declared. Landed: delta spec
(`specs/mcp-signin/spec.md`), the discovery requirement's body — the one
character, nowhere else.

Re-verified after the revert: a mechanical diff of the discovery requirement's
block (delta vs main spec) shows exactly one body-text difference — the
declared clause ("the system's only existence refusal" → "the toolset
namespace's existence refusal") — plus the delta-only declared-amendment note
itself; all five retained scenarios are byte-identical, so the note's "one
clause only" claim now holds mechanically. A grep of the whole change folder
for "CIMID" returns no matches; no other artifact (proposal, design.md
Migration Plan, release notes) carries the spelling. `openspec validate
apps-with-mcp-endpoints` (and `--specs`) re-run: **valid**.

---

# Round 4 — the owner's rulings folded (planning artifacts only)

The owner ruled at the 3c pause (2026-11-03). Two rulings, both folded into the
planning artifacts this round — no code, no commit; a narrow re-review follows.
Where a statement in the rounds above is superseded, it is named here rather
than rewritten above.

## Ruling 1 — the sign-in status API is dropped, both namespaces

The owner did not know the endpoint existed and wants it gone from the gateway's
surface. **Disposition: folded as a removal, everywhere the surface was named.**
Landed:

- Delta spec (`specs/mcp-signin/spec.md`): the status requirement moves from
  MODIFIED (scoped to toolsets) to a **REMOVED** entry — the C1-archive
  convention: the requirement header, a **Reason** quoting the requirement's
  normative sentence with the removal reason, a **Migration** mapping what dies
  with it and what is reconciled. Its scenarios — "Signed in", "Not signed in",
  "Signed in through a global credential", and the delta-only "No app status
  surface" — die with it. A new MODIFIED entry for "Refusals before flow
  allocation are audited" drops `/dial/{name}/status` from the refusal
  enumeration (declared). The toolset-guard entry's surface list drops "the
  status endpoint's path" and its refusal-shapes twin ("and the status
  endpoint" leaves the 404 enumeration) — both declared in that entry's note,
  which now declares two amendments: the kind-decides-the-guard scoping and the
  status drop.
- proposal.md: the What Changes status bullet is the drop (with the operational
  cost recorded); the Modified Capabilities list gains the REMOVED entry and the
  pre-allocation-audit MODIFIED, and the guard bullet names the surface-list
  drop; the Impact list has `gateway/status.py` deleted (the Core status read
  the flow's signed-in check uses stays, in `gateway/core.py`) and
  `docs/routing.md` added; the Operational section states the status path now
  falls to the catch-all (Core's 404), that the router and gateway must deploy
  together for the removal, and names the remaining diagnostic path.
- design.md: **D4 rewritten** as the toolset status drop — the owner's ruling,
  superseding the no-app-status decision this change first authored, with the
  reasoning extended rather than contradicted (no stored state for apps; for
  toolsets the 401 shapes already answer the harness's question — the
  "valid token, no stored credential" 401 is the not-signed-in answer,
  delivered by the data path itself) and the operational cost stated honestly
  (ops loses the per-user sign-in probe; the 401 challenge shapes and the audit
  trail remain the diagnostic path). §7 gains the T1-15 retirement bullet (the
  cross-references to reconcile enumerated: the row and its disposition, E9 in
  the entry-point inventory, the `gateway/status.py` citations in the EP1
  toolset/leg-confusion row and T1-4's disposition, the M6/M11/M23 Addresses
  entries, the attacker-inventory bullet) and re-words the T1-24 bullet, which
  had justified itself against T1-15 as a living row. The SIA's change
  description and implementation shape carry the removal; §4's preamble states
  why a removed surface carries no delta threat table; the no-new-residual
  bullet notes the retirement closes a formerly accepted disclosure. The
  Migration Plan's Rollout, Rollback, and Spec-sync bullets are re-derived (the
  status removal is the one existing-surface behavior change; the rollback
  restores the endpoint; the sync enumeration re-counted). Risks gains the
  lost-probe trade-off.
- tasks.md: new task 1.1 deletes the surface (`gateway/status.py` and its
  `gateway/app.py` registration; `read_toolset_status` stays for the flow's
  signed-in check; the status-only reason tokens `missing_token` and
  `invalid_token` retire after a grep proves no other emit site uses them — the
  shared tokens stay; the status tests deleted). Task 5.1 removes the router's
  status location and the routing doc's row, and its probe row becomes
  both-namespaces status paths falling to the catch-all (Core's 404). Task 6.1
  removes the operator reference's status material. Task 6.2 retires T1-15 with
  the ledger-consistency discipline (the retirement stated, no cross-reference
  orphaned — a repo-wide grep for "T1-15", "E9", and `gateway/status.py`
  among its verify rows). Section 1 is re-titled and re-numbered: the deletion
  is task 1.1, the old 1.1 and 1.2 are now 1.2 and 1.3, the internal
  "task 1.2" references in the flow and token tasks updated to 1.3, and the
  historical "C1's task 1.2" reference left untouched.
- release-notes-draft.md: "For users" gains the endpoint-is-gone bullet with
  the diagnostic replacement (a 401 with the challenge means run the sign-in; a
  403 means no access; the audit trail for operators); "For the team" carries
  the REMOVED, the T1-15 retirement, and the lost-probe cost.

**Supersessions named (history not rewritten above):** F4(b)'s T1-24
justification argued against amending T1-15 — that row is retired by this
round, and the T1-24 bullet's reason is re-stated standing on its own (an
unauthenticated discovery route, the mirror property's class). F8's caveat
landed "in the delta spec's status requirement (and its 'No app status surface'
scenario)" — that requirement is now removed; the caveat's content survives in
D4 (the app-upstream-401 benign loop) and the release notes. F10's probe row
made the "No app status surface" scenario checkable — that scenario is gone
with the requirement, and the probe row is re-purposed to assert the removal
itself. R2's "nine MODIFIED" enumeration listed the sign-in-status requirement
among them — the membership is re-derived this round: the count stays nine, the
status requirement leaves the MODIFIED set, the pre-allocation-audit
requirement enters it, and one REMOVED is added.

## Ruling 2 — the `/dial/` vs `/apps/` asymmetry stays; unification deferred

The owner will deal with unification later. **Disposition: the path grammar
stays as authored; the deferral is recorded where the repo records such
things.** Landed: proposal.md's "Not in scope" gains the
path-grammar-unification line (one prefix per concern; would retire the
reserved-name class; naturally landing with E1, the Core merge, or its own
change with a migration window); tasks.md task 6.1 extends to add the
deferred-rows entry to `docs/production-roadmap.md`'s "Deferred — to later
iterations" table — the roadmap's deferred table being the decision-record
register for owner-decision provenance, with behavior-and-reason wording and
no process citation in normative text; design.md's Non-Goals carries the same
boundary; the release notes' path-shape bullet states the kept asymmetry and
where the deferral is recorded.

## Round-4 validation

`openspec validate apps-with-mcp-endpoints` (and `--specs`) re-run after both
rulings were folded: **valid** (the `--specs` INFO notices are the main spec's
pre-existing length advisories). The mechanical byte-diff re-run across all
nine MODIFIED requirements: **every retained-scenario diff site is covered by a
declared amendment note** — the nine retained-scenario re-wordings ("Unknown
resource", "One-toolset inference", and "Guard-failing resource refused" in the
authorization requirement; "Unknown toolset refused at the flow's settings
read" in the federation requirement; "Token carries the marker audience" and
"The refresh token is not a Core-acceptable token" in the issued-tokens
requirement; "Inference without a single-entry restriction refused" in the
mapping requirement; "Over-limit discovery requests are refused without a
record" in the abuse-bounds requirement; "A completed flow's chain is
attributable end to end" in the lifecycle requirement) — and every other
retained scenario is byte-identical; no MODIFIED requirement drops a scenario
silently. The two status-drop bodies diff exactly at their declared sites: the
toolset-guard requirement at three (the surface-list deletion and the
refusal-shapes twin — both new this round — plus the previously declared
scoping sentence), and the pre-allocation-audit requirement at one (the
`/dial/{name}/status` deletion). The REMOVED entry names a requirement the main
spec carries. Counts: **9 MODIFIED, 4 ADDED, 1 REMOVED** — the Migration
Plan's Spec-sync enumeration re-counted to match (nine MODIFIED with changed
membership, plus one REMOVED).

---

# Round 5 — re-check touch-ups (planning artifacts only)

The re-check pass (2026-11-03) passed the package with two non-blocking flags.
Both are addressed in the planning artifacts only — no code, no commit, no
design change. Per flag: the finding, the disposition, and where the fix
landed.

## Flag 1 — task 6.2's T1-15 cross-reference enumeration was incomplete by three sites

Task 6.2 (and design.md §7's matching T1-15 retirement bullet) enumerated the
threat-model cross-reference sites to reconcile on T1-15's retirement. Three
further sites exist in `docs/threat-model.md` and were not named: the EP4
verification-surface row (~line 597, `E4/E9/E10 verification`); T4-7's grid
(~lines 1364-1365, "verifies JWTs at exactly three endpoints (E4, E9, E10)");
and the resolved OQ-1 record (~lines 1892-1899, citing `gateway/status.py:111-122`).

**Disposition: fixed by enumerating all three in both places, with the OQ-1
disposition stated.** design.md §7's retirement bullet and task 6.2's list now
name the EP4 and T4-7 sites as re-counted enumerations (E4/E9/E10 → E4/E10,
three endpoints → two) and add an explicit OQ-1 call: the historical resolution
record keeps its original wording — a dated record of a question resolved
before the endpoint's removal is not re-worded — and the retirement's repo-wide
grep treats its citation as a known, accepted remaining reference, so the
implementer does not have to adjudicate it. Task 6.2's verify row is updated to
match (the grep returns the retirement's own statements, the re-counted
surfaces, and the OQ-1 dated citation as the allowed remainder). Landed:
design.md §7 (the T1-15 retirement bullet); tasks.md task 6.2 (the retirement
body and its verify row).

## Flag 2 — task 6.1's verify row was overbroad

Task 6.1's verify row read "no status reference survives in the operator
reference". The collision: `docs/gateway-configuration.md` documents the flow's
Core status read (`read_toolset_status`, the per-caller statuses deciding the
short-circuit; ~lines 378-394, 439, 442-444), which legitimately stays — only
the dropped *endpoint* is being removed.

**Disposition: fixed by scoping to the endpoint.** The verify row now reads "no
status-**endpoint** reference survives in the operator reference", with the
scope stated (the dropped endpoint's own section and the status mention dropped
from the guard description — the task body's sites — not every occurrence of
"status"), and the flow's Core status read named as the material that stays.
Landed: tasks.md task 6.1 (the verify row).

## Round-5 validation

`openspec validate apps-with-mcp-endpoints` re-run after both touch-ups:
**valid**.

---

# Round 6 — the app test fixture (the owner's question; planning artifacts only)

The owner asked, on reading the package, where the real MCP app for the live
acceptance (task 7.3) comes from. **Gap found: nowhere.** No application resource
existed in the local environment, and no task created one — the local environment
carries exactly one MCP upstream, the public Notion server, registered in Core as a
**toolset** by `scripts/spike_register_toolset.py`; task 7.3's acceptance run assumes
an app resource but never says where it comes from; and Core's
`ApplicationMcpProxyController` refuses an application whose `mcp` block is null, so
the run has nothing to point at until a fixture lands. Neither proposal.md's Impact
list nor the tasks accounted for the fixture. **Disposition: the fixture task added
(planning artifacts only — no code, no commit).** Landed:

- tasks.md — new task **7.2a** (placed after the compose-boot gate 7.2 and before the
  acceptance run 7.3, so the run's precondition is built by it; the `7.2a` alphabetic
  suffix follows the file's existing convention of suffixing a task into a list without
  renumbering the tasks that follow, and no internal reference numbers 7.3, so none was
  disturbed — task 7.3 now names 7.2a instead). The task adds: a minimal MCP-speaking
  upstream service in `docker-compose.yml` (the reference MCP test server image or an
  equivalent minimal local fixture; joined to the instance network, no external
  credential — the app's upstream leg attaches no stored credential, the injector
  sending the app id and optional header config only, so a keyless fixture keeps the
  acceptance hermetic — reachable by Core by service name at `http://<service>:<port>/mcp`);
  a registration script `scripts/spike_register_app.py` (the sibling of
  `scripts/spike_register_toolset.py`: idempotent, admin-gated as that script is,
  creating the application resource in Core with an `mcp` block whose `endpoint` is the
  fixture's URL, safe to re-run); and the acceptance harness pointed at the app resource
  it registers. Verify rows: the fixture answers an MCP initialize/handshake from inside
  the compose network (negative control first); the script re-runs without error and the
  app resolves in Core (`GET /openai/applications/{id}` shows the `mcp` block); and
  deleting and re-registering the app works.
- tasks.md task 7.3 — references 7.2a as the source of the app resource the acceptance
  run uses.
- proposal.md Impact — `docker-compose.yml` and `scripts/spike_register_app.py` added to
  the Code/files list, each marked a test fixture with no production behavior.
- tasks.md task 6.1 — `docs/local-environment.md` added to the file list (it was **not**
  previously named there; the operator reference that 6.1 updates did not cover the
  local-environment document), with the fixture's usage for the operator stated among
  6.1's documented items, so the fixture is documented for the operator rather than
  living only in the task list.

## Round-6 validation

`openspec validate apps-with-mcp-endpoints` re-run after the fixture task landed:
**valid**.

---

# Round 7 — the owner's correction on the Skills MCP demo app (planning artifacts only)

**The correction.** Round 6's gap statement — "no application resource existed in the
local environment" / "the run has nothing to point at" — was wrong on one point. The
**Skills MCP demo app** (`../dial-instance/skills-mcp-demo/server.py`, outside
this repo) **is** an honest MCP app, and it was registered into Core **via the API**
(bucket storage) — which is why Core's static `config.json` shows zero applications.
Round 6's text above is not rewritten; the correction lives here.

**What was verified this round.** The demo server is a real MCP app: it serves
`POST /mcp` with the JSON-RPC method surface — `initialize`, `notifications/initialized`,
`tools/list`, `tools/call` — at `../dial-instance/skills-mcp-demo/server.py:170-205`.
Not verifiable from these files: whether the app is *still* registered in the live Core,
and whether its declaration carries the `mcp` block Core's apps MCP proxy requires. Both
are checkable at implementation time with one authenticated
`GET /openai/applications/{bucket}/{name}`.

**Disposition.** Task 7.2a gains a leading probe step: before provisioning the fixture,
probe the live Core for the Skills MCP demo app and its `mcp` block; if both hold, it may
serve the acceptance as a verified-real app, with the fixture as the fallback the task
then provisions. The fixture stays the task's **primary deliverable** either way —
self-sufficiency is the owner's stated preference, and the probe only avoids duplicate
work. Landed: tasks.md, task 7.2a (the leading probe paragraph; the Round-6 gap wording
in the task body is scoped to this repo's local environment — its Compose stack and Core's
static `config.json` — so it no longer overstates the earlier claim).

## Round-7 validation

`openspec validate apps-with-mcp-endpoints` re-run after the correction landed:
**valid**.

---

# Round 8 — the consent-gap finding and the C2.5 ruling (planning artifacts only)

## The team's finding

The gateway has **no consent page of its own**, which leaves a
drive-by/malicious-client hijack scenario open, stated concretely: an attacker
hosting a CIMD document on an operator-allowlisted origin (their
`redirect_uris` pointing at a collector they control) crafts an
`/dial/authorize` link; a victim with a live IdP session clicks it; the IdP
leg completes silently — the gateway relays nothing client-identifying into
the IdP leg, so the IdP cannot name the harness client to the user; a stored
credential — or, on the app path, the unconditional short-circuit with zero
user-visible pages — completes the flow with no decision point anywhere; the
code lands on the attacker's registered redirect; the attacker redeems it
with their own verifier and holds a gateway token **as the victim**. PKCE,
`state`, and single-use codes bound the interception class, not this one (the
attacker holds every binding legitimately); the standing control is CIMD
allowlist curation; the standard remedy is a consent page naming the resolved
client and resource. This change widens exactly that surface: the app kind's
zero-page short-circuit is a variant that would not exist without it — the
row's subject in this change's SIA by the method's own letter (enumerate the
new threats the change brings), with the toolset stored-credential
short-circuit named as the class's pre-existing other member.

## The owner's ruling

Plan one more change — an AS-specific security-hardening pass against the
OAuth2/OIDC security recommendations (RFC 9700, the OAuth 2.0 Security Best
Current Practice, plus the OIDC recommendations) — **folded into the roadmap**
as **C2.5 — AS security hardening (RFC 9700 alignment)**. Mid-flight, the
owner reviewed the scope and trimmed one piece: the RES-7/DPoP
remedy-naming amendment (naming DPoP as the structural remedy for the
bearer-token residual in this change's threat-model materials) was **dropped
entirely** — naming remedies for a pre-existing residual is the future
change's author's business, and that evaluation lives in the C2.5 roadmap
item's scope seed, which already names it. The T1-25 row's disposition names
the standing control and records the deferral — a disposition pointing at
where the fix lands is the method's own "state where it is implemented and
who owns it" rule.

## The coordinator's positioning rationale (recorded as proposed; no defect
found in it this round)

C2.5 sits **after C2 (generalized IdP federation), before C3 (the K8s pod)**:
(a) the consent-page acceptance needs the local compose — the same reasoning
that orders C2 before C3; (b) C2's `KEYCLOAK_*` → `IDP_*` rename churns the
IdP leg the hardening touches; (c) both C2.5 and C3 must land before D3 so
the closing re-judge judges the final shape. One interaction noted for
C2.5's author, not a defect: a consent/attribution checkpoint on the app path
will need to reconcile with the app-resource requirement's "no consent
screen" wording (an attribution page is not credential consent — the
amendment is C2.5's to declare). The scope seed, each item dispositioned by
that change itself (landed, deferred, or accepted with reasoning): (1) the
consent/attribution checkpoint; (2) sender-constrained tokens (DPoP,
RFC 9449) evaluated as the structural remedy for the bearer-token residual
(evaluate, don't promise); (3) step-up/re-authentication (`max_age`,
`prompt=login`, `auth_time`); (4) `state` strictness made explicit; (5) the
CORS/back-channel posture statement.

## Where each edit landed (planning artifacts only — no code, no commit)

- **design.md §4** — the new EP1 delta-threat row (DT-EP1-A6): the drive-by
  scenario via the app path's zero-page short-circuit, the widened-surface
  statement (a variant that would not exist without this change; the toolset
  stored-credential short-circuit named as the class's pre-existing other
  member), the standing control (CIMD allowlist curation), footprint and
  compromise classification (Use Control Misconfiguration → Elevation of
  Privilege → Spoofing of caller; A3/A4/A8/A10; I, Access).
- **design.md §5** — the DT-EP1-A6 mitigation block in the fixed
  control-category order, closing with the disposition: remediation deferred
  to C2.5 — AS security hardening (RFC 9700 alignment).
- **design.md §6** — the accepted-remainders paragraph gains the DT-EP1-A6
  deferral (standing control + deferred remedy, recorded in the roadmap and
  the threat model, not accepted as a residual).
- **design.md §7** — the new **T1-25** bullet (the row, its scenario, the
  standing control, the deferred-to-C2.5 disposition, the roadmap
  cross-reference) and the no-new-residual bullet amended (T1-25 is a new
  threat row, not a new residual record — an open item with a named roadmap
  home, not an acceptance).
- **tasks.md task 6.1** — extended: besides the deferred-table entry, it
  inserts the **C2.5** item into `docs/production-roadmap.md`'s iteration
  ordering between C2 and C3 — ordering block and prose, the section's
  framing sentence re-counted (four grouped OpenSpec changes), the scope
  seed, the first-two-rows acceptance (the RFC 9700 checklist re-judge, the
  consent-page decision), and the positioning rationale. Verify rows added
  (the item present in the right position; the T1-25 disposition names it).
- **tasks.md task 6.2** — extended: the apply list gains the **T1-25** row
  (the next free EP1 id, T1-23/T1-24 being this change's own) with its
  cross-references, and the verify rows gain the row's content and the C2.5
  cross-reference. No RES-7 amendment — dropped by the owner's mid-flight
  trim.
- **proposal.md** — "Not in scope" gains the C2.5 deferral (the
  consent/attribution checkpoint is remediated there, not here); the Impact
  Security paragraph's SIA delta summary mentions the new row.
- **release-notes-draft.md** — "For the team" gains the consent-threat
  disclosure with the C2.5 pointer, and the Security bullet's threat-model
  enumeration gains T1-25.
- **The delta spec — deliberately unchanged.** The consent gap is
  threat-model/roadmap material, not behavior this change ships: no delta
  requirement's normative text is falsified by the new row (the
  app-resource requirement's "no consent could establish anything" stays
  true — an attribution page is not credential establishment; the acceptance
  requirement's "no consent screen" describes exactly what ships, now priced
  by the row), and no mitigation is claimed in prose (the disposition is a
  deferral with a named home, so the "mitigation only in prose is not
  landed" rule is not tripped). Verified by re-running the mechanical
  byte-diff: no diff site changed.

## The T1-25 free-id verification

`docs/threat-model.md`'s EP1 ledger today tops out at T1-22 (T1-20 was a
consult-era row deleted by C1; the archived change's records confirm);
T1-23 and T1-24 are this change's own reserved ids (design.md §7, landing
with task 6.2) — so **T1-25 is the next free EP1 id**. T5-8, reused by this
change, is likewise free (the consult-era T5-8 was deleted with T1-20), per
round F4(a) of this file.

## Round-8 validation

`openspec validate apps-with-mcp-endpoints` (and `--specs`) re-run after all
edits: **valid** (the `--specs` INFO notices are the main spec's pre-existing
length advisories). The mechanical byte-diff re-run across all nine MODIFIED
requirements, every retained scenario, and the REMOVED entry: **every diff
site is covered by a declared amendment note or is the MODIFIED entry's own
requirement text** — the nine retained-scenario re-wordings and the
status-drop sites exactly as rounds 2-4 declared them, no new site, no
undeclared re-wording; the delta spec is byte-identical to its pre-round
state (untouched this round).

## Round-8 addendum

The task 6.1 re-count arithmetic is corrected (four → five grouped OpenSpec
changes, the count covering C1, C1.5, C2, C2.5, and C3), with the note that
the roadmap sentence being re-counted has been stale since C1.5's own
addition — the implementer corrects the stale count, not merely updates it.

---

# Round 9 — the threat-model ledger sites (declared design amendment; docs + design only)

## The conditional finding

The docs pass (task 6.2) applied §7's authoritative edit list exactly and,
correctly, declined two further `docs/threat-model.md` edits the list does not
name: §1's "The system as it stands" description still presented the gateway as
serving toolsets alone, and §10's compromise-points table still described gains
in toolset-only terms. Neither site appeared among §7's bullets, so the pass
left them alone rather than widening beyond its instruction.

## The orchestrator's ruling

Both edits are owed, under the standing rule that every change updates the
threat model's affected entries (a mitigation or surface that exists only in
prose is not landed). Apps are now a **served resource kind**: the gateway serves
an app's MCP endpoint through the apps front door and mints app-addressed tokens,
so the model's own system description and its compromise-point table — the two
ledger sites that name what is served and what a compromise yields — must say so.
Declining them was the right call for the pass to make on an edit list that did
not name them; the list itself was incomplete, and the completeness gap is closed
by a declared design amendment, not by the implementer's discretion.

## The declared §7 amendment

`design.md` §7 gains a declared bullet naming both sites: §1's system description
gains the apps kind (the apps front door, the guard-decided registry-independent
apps discovery tier, the unconditional credential-free short-circuit — no new
trust boundary, credential, or grant type), and §10's compromise-point rows whose
text names a served surface class extend to the second kind (the Core row states
Core serves the apps MCP path to gateway-minted tokens exactly as it serves the
toolset path; the Keycloak row — whose text names no served surface — is
unchanged). The bullet states the reason in behavior terms (the standing rule:
the model must describe what the system now serves).

## Where the ledger edits landed

- **`docs/threat-model.md` §1** — the "system as it stands" description now states
  the served set spans two resource kinds; adds the apps front-door path
  (`/apps/{name}/mcp` → Core's deployments MCP path), its own optional operator
  restriction and registry-independent discovery tier (mirroring Core's own apps
  tier, existence decided post-authentication at the per-user app read), the note
  that the app path introduces no new trust boundary, credential, or grant type
  (it rides the existing public front door and internal Core leg), and the app
  kind's unconditional credential-free short-circuit (no consent screen, no
  credential call, no upstream round-trip).
- **`docs/threat-model.md` §10** — the rows whose text names a served surface
  class were widened: the Harness row ("toolset access" → "toolset and app
  access"; "other proxied toolsets" → "other proxied resources — toolsets and
  apps"), the Gateway-process row ("toolset access via the MCP endpoint" →
  "toolset or app access via the MCP endpoints"), and the DIAL Core row (adds
  that Core serves the apps MCP path to gateway-minted tokens exactly as it does
  the toolset path, per-call DIAL authorization on both). No new rows; no counts
  changed; the register retained. The Keycloak row is unchanged — its text names
  no served surface class.

Nothing else in the change folder or the repository was touched; no commit. The
delta spec, the proposal, the tasks, and the release notes are unchanged (the
amendment is a design-level declaration of an edit already owed, not a change to
the change's delivered behavior).

## Round-9 validation

`openspec validate apps-with-mcp-endpoints` re-run after the amendment and its
two ledger edits: **valid**.

---

# Round 10 — the gate runner's two findings (implementation fix pass)

The gate-run pass (tasks 7.1 and 7.2; evidence:
`evidence/gates-implementation.md`) returned two findings. Both are addressed —
one code edit and the design/task wording corrected to the verified live
behavior. Per finding: the finding's substance, the disposition, and where the
fix landed.

## Find-1 (BLOCKING) — a ruff-format violation in `tests/test_audit.py`

The LF-normalized `ruff format --check` sweep over `gateway/`, `tests/`, and
`scripts/` (the gate's method, since `core.autocrlf=true` makes the raw check a
false positive on every file) returned exactly one real content violation: a
stale hand-wrapped `next(...)` call in `tests/test_audit.py` (lines ~274-276)
that ruff wants collapsed onto one line (the collapsed line is 85 characters,
within the 88-column limit). The hunk was added by this change's diff, so it is
a new finding, not pre-existing.

**Disposition: fixed — the wrap is collapsed.** The call is now the single line
ruff wants; the file's CRLF line endings are unchanged.

```
allocated = next(r for r in records_of(caplog) if r["event"] == "flow_allocated")
```

Re-verified: `sed 's/\r$//' tests/test_audit.py | ruff format --check
--stdin-filename tests/test_audit.py -` exits 0 (the LF-normalized check the
gate's evidence describes); `ruff check tests/test_audit.py` — "All checks
passed!"; `python -m pytest -q tests/test_audit.py` — **27 passed** (unchanged
from the pre-fix baseline). Landed: `tests/test_audit.py`.

## Find-2 (wording defect) — the "Core's 404" prediction for a removed status path

The compose-boot section of `evidence/gates-implementation.md` records the live
probe's finding: an *unauthenticated* request to a removed status path
(`GET /dial/x/status`, `GET /apps/x/status`) is answered by **Core's 401**
(`At least API-KEY or Authorization header must be provided`), with no gateway
challenge — Core's auth filter runs before routing and 401s every
unauthenticated request (control: a nonexistent path also 401s). The design and
task text predicted "falls to the router's catch-all and is answered by Core's
404"; that is true only for an *authenticated* request. The removal itself is
confirmed correct — the *status code* the design predicted for the
unauthenticated probe is what is wrong. The delta spec is unaffected: its
REMOVED entry rests on the data path's 401 shapes answering the status
question, not on the fall-through code, so no spec text is falsified.

**Disposition: fixed by re-wording to the verified behavior (design/task text
only — the delta spec is correct as authored).** Each site now states the
verified fact: an unauthenticated request to a removed status path falls
through to Core, whose auth filter precedes any routing and answers it with
Core's own 401 — the same fact of the enabled route the mirror property names —
carrying no gateway challenge; a 404 is what an authenticated request would
meet. Landed:

- **design.md D4** — the closing paragraph's probe row re-worded from "falls to
  the router's catch-all and is answered by Core's 404" to the verified
  fall-through-to-Core 401 behavior.
- **design.md, Migration Plan, Rollout** — the same 404 claim in the
  rollout/rollback wording re-worded identically (the atomic-deploy reasoning
  is unchanged: the router location and the gateway endpoint still land
  together).
- **tasks.md, task 5.1** — the probe row's assertion re-worded from "falling to
  the router's catch-all and answered by Core's 404" to the verified probe
  result (falling through to Core, whose auth filter answers the
  unauthenticated call with Core's 401, no gateway challenge; a 404 is what an
  authenticated request would meet), so the task's verify wording matches what
  the gate now asserts.

The task's completion convention is the checkbox: task 5.1 is already checked
(`- [x]`), and the probe it describes was run in the gate pass (the status-path
row in `evidence/gates-implementation.md`'s boot-probe table), so no checkbox
changed.

**Propagated to the three remaining sites (the same wording defect, same
correction).** The same "answered by Core's 404" claim stood in three further
artifacts, each re-worded to the verified behavior with its own register kept:
`proposal.md` (the Operational bullet — falls through to Core, whose auth filter
answers an unauthenticated request with Core's own 401, no gateway challenge; a
404 is the authenticated case), `release-notes-draft.md` (the user-facing
"status endpoint is gone" bullet), and `docs/routing.md` (both the status-location
prose paragraph and the probe-table row 10). Landed: those three files.

## Round-10 validation

`openspec validate apps-with-mcp-endpoints` re-run after both fixes: **valid**.

---

# Round 11 — the live-acceptance falsification, fixed (defect-fix; code + test + evidence)

The live-acceptance pass (task 7.3; evidence: `evidence/acceptance-live.md`) recorded
**Finding 1**: the delta spec's refusal scenarios claim "no flow state surviving the
refusal", and the live run **falsified** it — after an `unknown_app` refusal at the flow's
app read, re-presenting the same flow id to `/dial/callback/keycloak` resolved the surviving
record and re-ran the provider code exchange (400 "the provider refused the code exchange")
instead of landing on the unknown-id "expired" page.

## The finding (verified)

**Root cause, verified in source this round.** `gateway/federation.py`'s
`_core_read_refusal` wrote the audit record and rendered the refusal page but never consumed
the flow record: `runtime.flows.destroy` was called only at the upstream callback
(the *success* path, ~line 241 pre-fix). The read's own credential drop — `flow.discard_
identity_token()`, called inside `complete_identity_leg` — runs only after the read
*succeeds*, so a refused read left the record holding the identity **access token** (the
`_read_core` call raised before the discard) and the captured provider **session refresh
token**. The record's TTL alone bounded that retention, and a re-presented flow id re-ran
the leg — the exact survivorship the live run measured.

**Scope — the sibling refusal paths carry the same hole.** The finding named the app read's
`AppUnknownError` and the toolset read's `ToolsetUnknownError`. The no-access refusal (403)
reaches the same `_core_read_refusal` through `AccessDeniedError` (`ToolsetAccessDenied`
`Error` / `AppAccessDeniedError`) and had the same hole: the spec's no-access scenario
("the flow fails with a clear no-access page") does not state "no flow state surviving",
but the **custody rule** does — the identity token's retention is bounded by the flow TTL,
and a refusal that leaves a re-presentable record holding the token extends that retention.
Fixed under the same rule.

## The spec-gate decision (made; no spec change)

**No spec change.** The delta spec already demands the behavior — the app-resource
requirement's "no flow state surviving the refusal" and the (re-worded) unknown-toolset
scenario's "no flow state survives the refusal" are normative as authored. The code was
wrong; the code is fixed to match. The no-access path's spec text names no survivorship
clause, so nothing there is falsified either — the fix aligns it with the custody discipline
the spec states elsewhere (the flow record is destroyed on first use; the token's retention
is the flow's TTL).

## The fix

**`gateway/federation.py`** — one helper, wired into every refusal branch of
`_core_read_refusal`:

```python
def _consume_refused_flow(runtime: Runtime, record: FlowRecord) -> None:
    """Destroy a refused flow's record and drop the credential material it holds. ..."""
    runtime.flows.destroy(record.flow_id)
    record.discard_identity_token()
    record.identity_refresh_token = None
```

- **The two existence refusals** (`ToolsetUnknownError`, `AppUnknownError`): the
  `flow_branch_refused` audit record still lands first, then `_consume_refused_flow`, then
  the page — the audit ordering is unchanged (the record is written before the flow state
  is torn down, so the trail reads the same).
- **The no-access refusal** (`AccessDeniedError`): the `flow_leg_failed` record lands, then
  `_consume_refused_flow`, then the no-access page.
- **The fault branch** (any other `CoreError` — unreachable/unreadable Core): **not**
  consumed. That is a deployment fault the operator fixes and the user re-runs; the flow is
  not *refused*, and the record's retention stays bounded by its own TTL as before. The
  three-shape discipline (403 access, 404 existence, 5xx fault) is preserved: only the two
  refusal shapes consume state.

The module docstring gained a paragraph stating that a flow's refusal consumes its record
exactly as a completed callback does.

## The test-first record (probe-fail-first)

Four unit tests added to `tests/test_federation.py` — the app pair beside the app-flow
tests, the toolset pair beside the unknown-toolset test. Each drives the refusal, then
asserts: the store no longer resolves the id, the record's `identity_access_token` and
`identity_refresh_token` are both `None`, re-presenting the id yields the expired page
(400, "expired") **and the provider code exchange does not run a second time** (a counted
mock proves it — the live run's exact symptom), and the refusal's audit record still landed
once.

- `test_an_unknown_toolset_refusal_leaves_no_flow_state`
- `test_a_refused_settings_read_leaves_no_flow_state` (403 no-access)
- `test_an_unknown_app_refusal_leaves_no_flow_state`
- `test_a_refused_app_read_leaves_no_flow_state` (403 no-access)

**Before the fix** (against the unpatched `federation.py`):

```
FAILED tests/test_federation.py::test_an_unknown_toolset_refusal_leaves_no_flow_state
FAILED tests/test_federation.py::test_a_refused_settings_read_leaves_no_flow_state
FAILED tests/test_federation.py::test_an_unknown_app_refusal_leaves_no_flow_state
FAILED tests/test_federation.py::test_a_refused_app_read_leaves_no_flow_state
4 failed, 64 deselected
```

Each failed on the survivorship assertion (`assert survives is None` returned the surviving
`FlowRecord`), reproducing the finding in the unit suite.

**After the fix:**

```
4 passed, 64 deselected
```

## The gates (re-run this round)

- `pytest -q` (full suite, `PYTHONUTF8=1`): **546 passed, 1 skipped** (the skip is
  pre-existing).
- `ruff check gateway tests`: **All checks passed!**
- `ruff format --check` (LF-normalized, the gate's method): `gateway/federation.py` and
  `tests/test_federation.py` both exit 0.
- `mypy gateway tests`: **Success: no issues found in 39 source files.**

## Round-11 validation

`openspec validate apps-with-mcp-endpoints` re-run: **valid** (no spec text changed, so the
validation is a formality — recorded for completeness). No commit; the change's gates (7.4
review, 7.5 commit) remain.

---

# Round 12 — the security review gate's findings (fix pass; code + test + docs + tasks)

The security review gate (task 7.4, the security half) returned **PASS-with-findings**:
three MINOR findings and one NOTE. All four are addressed. No commit. Per finding: the
substance, the disposition, and where the fix landed.

## MINOR 1 — apps-route refusal records carried the app name under a kind-specific field name

The pre-allocation `flow_refused` record carried the request's name under the `toolset`
fact field. The **reason tokens** are correctly kind-specific (`invalid_app_name`,
`restricted_app` for apps; `invalid_toolset_name`, `reserved_toolset_name`,
`restricted_toolset` for toolsets), but the **field name** misled: an apps-namespace
discovery refusal wrote `{"reason": "invalid_app_name", "toolset": "Skills_Demo"}` — a
record whose field name asserts a namespace the refusal did not serve.

**Disposition: fixed — the fact field is renamed to the kind-neutral `name`, and
`resource_kind` is added where the site serves exactly one kind.** The choice and its
reason:

- **`toolset` → `name` on the `flow_refused` record.** The field carries the name the
  request offered under *either* namespace, so a kind-specific field name is the defect;
  the minimal fix that leaves no caller-supplied name under a kind-specific field name is
  a kind-neutral one. `name` was chosen over the alternatives:
  - *`resource_name`* would collide conceptually with the record's existing `resource` fact
    (the resource **URI**), and would read as "the name part of the `resource` URI", which
    is only true at the sites that resolved a URI — the discovery guards carry a bare path
    segment, not a URI.
  - *`toolset` kept, with `resource_kind` disambiguating* was rejected: the finding's point
    is the field **name** misleads, and a reader (or a log query grouping by `toolset`)
    would still read an app's name as a toolset fact.
  - *`name`* is the neutral spelling the deltas already use for the value (`resource kind
    and name`), and it names exactly what the field holds.

  The rename touches every `flow_refused` emit site's **parameter list** and the emit
  body; the call sites that pass no name are unchanged in behavior (the field is null, as
  before).
- **`resource_kind` added where the site serves one kind.** The two discovery guards each
  serve exactly one namespace (the toolset route, the apps route), so each now passes
  `resource_kind="toolset"` / `"app"` — a fixed token from this gateway's own vocabulary,
  not a caller value. The `/dial/authorize` refusal site **does not** pass it: the
  authorization endpoint resolves the resource's kind only after validation, and several
  refusal classes (an unregistered redirect URI, a missing `resource`) are reached before
  the kind is known, so the field is left unset there rather than guessed. The record's
  shape stays one shape: `name` and `resource_kind` are present and null when a site does
  not set them.
- **The authorization site's name derivation** changed from `toolset_name_from_resource`
  (which returns a name **only** for a toolset-shaped URI) to a new kind-neutral
  `resource_name_from_resource`, so an app-shaped resource that reaches a validation
  refusal is recorded under `name` rather than dropped. Landed:
  `gateway/settings.py::resource_name_from_resource` (the shared resolution's neutral
  reading).
- **Bounded and non-credential, both unchanged.** `name` joins `_CALLER_FACT_FIELDS` so it
  is truncated at `AUDIT_FACT_MAX_LENGTH` exactly as `toolset` was; `resource_kind` is
  deliberately **not** a caller fact (it is this gateway's own fixed token) and so is not
  bounded — same treatment the event name and reason get.

**The lifecycle events' `resource`/`resource_kind` vocabulary is untouched** — this fix is
confined to the pre-allocation `flow_refused` record.

Landed:
- `gateway/audit.py` — `flow_refused`'s signature (`toolset` → `name`, new
  `resource_kind`), its emit body, the module docstring's fact enumeration, the
  `_CALLER_FACT_FIELDS` set and its comment, and `_bounded`'s docstring.
- `gateway/routes.py` — both discovery-guard refusal calls now `name=…, resource_kind=…`.
- `gateway/authorize.py` — the `/dial/authorize` refusal call now `name=…` (kind-neutral).
- `gateway/settings.py` — new `resource_name_from_resource`; the audit-bounds comment's
  fact enumeration.
- `.env.example` — `AUDIT_FACT_MAX_LENGTH`'s comment enumeration.
- `docs/gateway-configuration.md` — the audit section: `flow_refused`'s field list
  (`toolset` → `name`, with `resource_kind` where a site serves one kind, and why the name
  is kind-neutral), and the flow-events sentence's `the toolset` → `the resource`.
- Tests asserting the old field name: `tests/test_audit.py` (the unknown-client record's
  `name`, the limiter's null-fact list, both discovery-guard records' `name` +
  `resource_kind`), `tests/test_discovery.py` (the app guard's two records), and
  `tests/test_limits.py` (the field allow-set).

## MINOR 2 — the impossible-branch refusal left the credential-bearing record live until TTL

`gateway/federation.py::_toolset_after_read`'s `non_oauth_toolset` branch rendered its
plain-language page while the flow record stayed in the store — holding the identity
access token and the provider's session refresh token — until the flow's TTL. This is a
**refusal** (the flow is over for the user), not a re-runnable fault, so the Finding-1 fix's
own principle — "a refusal consumes the record" — covers it; the four read refusals consume
the record, and this fifth refusal did not.

**Disposition: fixed — `_consume_refused_flow` is called on the impossible branch too.**

**The exemption's recorded reason.** The `FlowError` branch that follows the routing
decision (the upstream-build fault → 502) is deliberately **not** consumed, and one
docstring sentence now states why: it is the **operator-fault class** — the upstream
request could not be built because the toolset's registration is incomplete — which is the
same class as the Core-unreachable fault the Finding-1 fix deliberately excluded. The user
re-runs the flow after an administrator fixes the registration, so the record is left for
that re-run and its retention stays bounded by the flow's own TTL, exactly as the fault
branch's does.

Landed:
- `gateway/federation.py` — `_consume_refused_flow` on the `non_oauth_toolset` branch
  (with the reason in the branch comment); the `_run_identity_leg` docstring's new
  paragraph on the refusal-consumes / operator-fault-does-not split.
- `tests/test_federation.py` — two new tests:
  - `test_the_impossible_branch_refusal_leaves_no_flow_state` — the refusal consumes the
    record (store no longer resolves the id, both credential fields `None`, re-presented id
    → 400 "expired" page, the provider exchange counted once, the `non_oauth_toolset`
    record still landed).
  - `test_the_upstream_build_fault_does_not_consume_the_flow` — an OAUTH toolset with an
    incomplete projection (502 at the URL build) leaves the record in the store (the
    re-run property).

## MINOR 3 — the fixture shipped unconditionally in the deployment compose

`docker-compose.yml`'s `mcp-app-fixture` service had `restart: unless-stopped` and no
profile gate, so a plain `docker compose up -d` started a test fixture in the deployment
stack.

**Disposition: fixed — the service is gated behind `profiles: ["acceptance"]`, and the
consequences kept coherent.**

- (a) **The start command.** The fixture now comes up with `docker compose --profile
  acceptance up -d mcp-app-fixture`. `docs/local-environment.md`'s fixture section states
  the gate and the command; `tasks.md` task 7.2a's fixture wording states the same (the
  gate, the plain-up consequence, and the profile-up command the acceptance run and the
  boot-gate probe use). *(The registration script itself takes no compose command — it
  only names the fixture's in-network URL — so it needed no edit.)*
- (b) **The compose-boot gate's per-service probe — verified this round.** Config-level:
  `docker compose config --services` → `mcp-signin-gateway, mcp-signin-router` (no
  fixture); with `--profile acceptance` → the three. Live: with the fixture stopped,
  `docker compose --profile acceptance up -d mcp-app-fixture` → the container starts and
  reaches **`healthy`** (`docker inspect … .State.Health` → `Status:"healthy"`,
  `FailingStreak:0`, **5/5 healthchecks exit 0**). The fixture was then **stopped** and
  left stopped; the gateway and router were verified **still `healthy`** afterwards.
- (c) **The plain boot no longer includes it — verified.** `docker compose up -d` (no
  profile) created and started **only** `mcp-signin-gateway` and `mcp-signin-router`
  (gateway reached `Healthy` during startup; `docker ps` showed exactly those two, both
  `healthy`, with no fixture container). The deployment stack boots healthy without the
  profile.

Landed:
- `docker-compose.yml` — `profiles: ["acceptance"]` on `mcp-app-fixture`, with the comment
  stating why (a test fixture must not start in a deployment).
- `docs/local-environment.md` — the fixture bullet.
- `tasks.md` — task 7.2a's fixture wording.

## NOTE 1 — the tasks.md checkboxes lagged the landed work

**Disposition: fixed — the boxes are ticked for work that is landed and evidenced:**
6.1, 6.2, 7.1, 7.2, 7.3 (their boxes were `- [ ]` and are now `- [x]`). 7.2a and 7.3a were
already `- [x]` (verified, left as they were). 7.4 (the review gates) and 7.5 (the commit)
stay `- [ ]` — not yet done. Landed: `tasks.md`.

## The gates (re-run this round)

- `pytest -q` (full suite, `PYTHONUTF8=1`): **548 passed, 1 skipped, 1 warning in 147.56s**
  — the two new MINOR-2 tests included; the skip and the warning are pre-existing.
- `ruff check gateway tests scripts`: **All checks passed!** (one `# noqa: PLR0913` added to
  `flow_refused` — 6 keyword-only fact parameters — matching the file's existing convention
  and its explicit reason).
- `ruff format --check` (LF-normalized, the gate's method): all nine touched files exit 0
  (`gateway/audit.py`, `gateway/authorize.py`, `gateway/routes.py`, `gateway/settings.py`,
  `gateway/federation.py`, `tests/test_audit.py`, `tests/test_discovery.py`,
  `tests/test_limits.py`, `tests/test_federation.py`).
- `mypy gateway tests`: **Success: no issues found in 39 source files.**

## Round-12 validation

No spec text was touched this round (the delta spec is unaffected: the `flow_refused` fact
vocabulary is documented in `docs/gateway-configuration.md`, not normatively in the delta;
the spec's own fact enumeration — "the non-credential facts (client id, redirect URI,
resource, toolset)" — is the *class* of facts, and the concrete field naming is the
operator reference's business, which is where the rename landed). `openspec validate
apps-with-mcp-endpoints` re-run: **valid**. No commit; the change's gates (7.4's general
review, 7.5 commit) remain.

---

# Round 13 — the general review gate's findings (fix pass; code + docs + evidence)

The general diff review gate (task 7.4, the general half) returned **FAIL**: one BLOCKING, one
MAJOR, four MINOR, five NOTEs. All are addressed. No commit. Per finding: the substance, the
disposition, and where the fix landed.

## B1 (BLOCKING) — `APPS` was missing from the gateway's compose environment

`docker-compose.yml`'s `mcp-signin-gateway` service listed `TOOLSETS` under `environment:`
but not `APPS`. The second resource kind's operator restriction therefore never reached the
container: the gateway read `apps` from its settings model with no environment line to feed
it, so an operator setting `APPS` would see no effect, and the omission was invisible until
then. The compose file is the deployment's whole environment surface — the gateway is the one
component with a public surface, so it is handed settings one by one rather than by
`env_file:` — and the apps restriction is a first-class setting this change added; its
absence from that list is the completeness defect.

**Disposition: fixed — the line is added beside `TOOLSETS`, matching its exact escaping
and spacing.** `APPS: ${APPS:-{}}` now sits directly under `TOOLSETS: ${TOOLSETS:-{}}`, so
an unset `APPS` yields the empty JSON object the settings model parses, exactly as `TOOLSETS`
does. The block's leading comment ("The toolset mapping and the pre-registered client list")
was re-worded to "The toolset and apps mappings and the pre-registered client list", so it
names what the block now carries.

**Live re-verification.** `wsl -e docker compose up -d mcp-signin-gateway` recreated the
container (Recreate → Recreated → Starting → Started). `docker inspect … .Config.Env` shows
`APPS={}`; `docker exec … sh -c 'echo "$APPS"'` → `{}`, and the same container's `TOOLSETS`
still carried the mapped toolset (`{"notion":{"scopes_supported":["default"]}}`), confirming
the two lines coexist. The local `.env` sets no `APPS`, so the empty default is the value —
the wiring, not the value, is what was verified. The gateway returned to **`healthy`**
(`FailingStreak 0`) after the recreate.

**Known gap (recorded, not fixed): no automated guard covers compose-environment
completeness.** Nothing in the unit suite or the static gates asserts that every setting the
gateway reads has a matching compose `environment:` line, so an omitted variable of this
class is caught only by a live re-verification or by an operator noticing a setting has no
effect. A compose-environment-completeness test would close the class; it is out of this
change's scope and is recorded as a known gap in `evidence/gates-implementation.md`'s Round
13 tail.

Landed: `docker-compose.yml` (the `APPS` line and the block comment);
`evidence/gates-implementation.md` (the Round 12–13 boot re-verification tail, including the
known gap).

## M1 (MAJOR) — probe 10 asserted the falsified 404

`scripts/probe_routing.py::probe_status_path_dropped` (probe 10) made an *unauthenticated*
request to `/dial/{name}/status` and `/apps/{name}/status` and asserted a **404** from Core.
The verified live behavior (this change's own gates evidence, Find-2, Round 10) is Core's
**401**: Core's auth filter precedes routing, so an unauthenticated request to a removed
status path — or to any nonexistent path — is answered with Core's own 401 and no gateway
challenge. The probe asserted a status the deployment does not return, so it would have
failed against the correct stack; its "404" was the authenticated-request case, not the
probe's.

**Disposition: fixed — the probe asserts the verified shape.** It now asserts **status
401** with **no `WWW-Authenticate` header** (the gateway-challenge absence is the real
evidence the status route is gone — the MCP paths' 401s carry a rewritten challenge quoting
the gateway's metadata, so a challenge here would mean the request reached a gateway
handler). The probe's docstring and the module docstring's probe-10 entry were re-worded to
the corrected behavior; the battery label is now "status paths dropped to Core's own 401".

**Live re-verification — the full battery.** `PYTHONUTF8=1 .venv/Scripts/python
scripts/probe_routing.py` ran against the live composed stack: **all 10 probes passed**,
including the fixed probe 10, whose output was:

```
[10/10] status paths dropped to Core's own 401
  request   GET http://localhost:8090/dial/notion/status
  status    401
  challenges []
  request   GET http://localhost:8090/apps/notion/status
  status    401
  challenges []
  verdict   green — both status paths fall through to Core's own 401, with no gateway challenge
```

Landed: `scripts/probe_routing.py` (the probe body, its docstring, the module docstring's
probe-10 entry, the battery label).

## m1 (MINOR) — `routes.py::protected_resource` docstring, two stale sites

**(a)** the phrase "the system's only existence refusal" — falsified by this change, which
landed the per-namespace wording everywhere else. **Fixed:** → "the toolset namespace's
existence refusal".
**(b)** the rate-limiter enumeration named "the authorization, token, revocation, and
status endpoints" — the status endpoint is deleted by this change. **Fixed:** the
enumeration drops it ("the authorization, token, and revocation endpoints").

Landed: `gateway/routes.py`, `protected_resource`'s docstring.

## m2 (MINOR) — `authorize.py`'s toolset-only opening, and the app-unaware refusal text

**(a)** the module docstring opened "The `resource` parameter is required and is the
toolset disambiguator. One flat authorization server serves every toolset…" — the toolset-only
shape this change generalized. **Fixed:** re-worded to the two-kind shape
(`_resolve_resource`'s refusals already use): "the resource disambiguator. One flat
authorization server serves both resource kinds — toolsets and apps…", with the inference
clause now stating it resolves only to a toolset.
**(b)** `_INVALID_TARGET_DESCRIPTION` told a client to "name a toolset this gateway serves…
because one authorization server serves every toolset" — an app harness reading this would
be told to name a toolset. **Fixed:** → "must name a toolset or app this gateway serves; it
is required because one authorization server serves both resource kinds".

Landed: `gateway/authorize.py` (module docstring, `_INVALID_TARGET_DESCRIPTION`).

## m3 (MINOR) — the kind-specific `toolset` fields carried a two-kind value unexplained

`FlowRecord.toolset` (`gateway/state.py`) and `CodeBindings.toolset` (`gateway/codes.py`)
hold the addressed resource's name of either kind — an app-kind flow stores the app's name —
but neither stated so, leaving a reader to infer a toolset-only meaning from the field name.

**Disposition: fixed — one sentence at each field.** The field keeps the kind-specific
`toolset` spelling as retained *spelling*, not retained *meaning*.

- `gateway/state.py` — a comment on `FlowRecord.toolset` ("The addressed resource's name, of
  either kind (its kind is `resource_kind` beside it). The field keeps the kind-specific
  `toolset` spelling, but not that meaning: an app-kind flow stores the app's name here.").
- `gateway/codes.py` — a sentence in `CodeBindings`' class docstring, the JWT `toolset` claim
  in `issue_code` (an inline comment), the module docstring ("the addressed resource (a
  toolset or an app)"), and `decode_code`'s `aud` comment ("the addressed resource (a toolset
  or an app)").

Cross-checked against `gateway/token.py`'s matching comments (see n5 below, fixed in the same
pass).

Landed: `gateway/state.py`; `gateway/codes.py`.

## m4 (MINOR) — `discovery.py`'s module docstring first line

"Discovery documents: the flat authorization-server metadata and **per-toolset resources**."
**Fixed:** → "…and **per-resource documents**", with the body's "every toolset shares it" →
"every resource kind shares it" and the protected-resource paragraph re-worded to the
two-kind, two-path shape (`/dial/{name}/mcp` for a toolset, `/apps/{name}/mcp` for an app).

Landed: `gateway/discovery.py`, module docstring.

## n5 (NOTE, applied) — `token.py`'s stale comments and the compose router comment

- `gateway/token.py` — the `_INVALID_TARGET_DESCRIPTION` comment ("…identify the toolset the
  token is for") → "…identify the resource the token is for"; the code-grant comment ("a
  request that names no toolset… which toolset it is for") → the resource wording; the
  refresh-grant comment ("One flat authorization server serves every toolset") → "serves
  both resource kinds".
- `docker-compose.yml` — the router-service comment ("It splits the authorization surface to
  the gateway and the toolset MCP path straight to Core") → "…and the MCP data paths — the
  toolset path and the apps path — straight to Core".

Landed: `gateway/token.py`; `docker-compose.yml`.

## n1 (NOTE) — the roadmap deferred row's garbled reserved-name claim

`docs/production-roadmap.md`'s deferred path-grammar row read as if **keeping** the
asymmetry retires the reserved-name class ("…disjoint by construction and retires the
reserved-name class"). False: the reserved names exist precisely because the `/dial/` prefix
serves **both** concerns — the authorization surface (`/dial/authorize`, `/dial/token`, …)
and the toolset MCP data path (`/dial/{name}/mcp`) — so a toolset named for a gateway-owned
endpoint would shadow it. What retires the class is **unification** (giving each concern its
own prefix, the grammar the apps namespace already follows, whose name segment covers only its
own data path and so carries no reserved names), and that needs a migration window.

**Disposition: fixed — the parenthetical re-worded to the intended sense.** The row now
states that keeping the asymmetry does **not** retire the class, names why the reserved names
exist, and attributes the retirement to unification with its migration cost.

Landed: `docs/production-roadmap.md`, the "Deferred — to later iterations" table's
path-grammar-unification row.

## n2 (NOTE) — the gates evidence's boot record predated the profile gate

The boot section of `evidence/gates-implementation.md` recorded the pre-profile-gate stack
(the fixture unconditional); Round 12's MINOR-3 fix gated the fixture behind `profiles:
["acceptance"]`, changing the composed set.

**Disposition: fixed — an appended tail, the original section left as recorded.** A new
section, "Boot re-verifications after the compose shape changed (Rounds 12–13)", records that
the original boot predates two later stack changes, then the Round-12 profile-gate
re-verification (config-level services list; the fixture healthy under the profile; the plain
boot bringing up only the gateway and router) and the Round-13 B1 re-verification above, so
the file's tail reads as one consistent history. See B1 for the B1 half.

Landed: `evidence/gates-implementation.md`.

## n3 (NOTE) — the overstated file list named `gateway/tokens.py`

`proposal.md`'s Impact list and `tasks.md` task 4.1 both named `gateway/tokens.py` ("the
audience mint parameterized by the addressed resource"). False: `tokens.py` is **untouched**
by this change — the mint was already resource-parameterized (it takes `resource` for the
access token's `aud` and the refresh token's `aud`), so the app-kind work changed only the
*caller* (`gateway/token.py`), never the mint.

**Disposition: fixed — `tokens.py` removed from both lists.** The file is gone from
`proposal.md`'s Impact Code list and from task 4.1's parenthetical, which now names
`gateway/token.py` alone.

Landed: `proposal.md` (Impact); `tasks.md` (task 4.1).

## n4 (NOTE) — no action (recorded)

The empty-name-segment 404 shape is pre-existing on both routes (a `/dial//mcp` or
`/apps//mcp` request meets the same shape today as before this change); it is not introduced
or worsened here, so no fix is owed. Recorded for completeness.

## The gates (re-run this round)

- `pytest -q` (full suite, `PYTHONUTF8=1`): **548 passed, 1 skipped, 1 warning**. One
  first-run failure in `tests/test_custody.py::test_the_envelope_layout_is_version_key_id_nonce_ciphertext`
  was a pre-existing flaky assertion (it asserts a random 12-byte nonce does not contain the
  one-byte plaintext `b"t"` — a ~5% chance occurrence); the file is untouched by this change
  and the suite is green on re-run.
- `ruff check gateway tests scripts`: **All checks passed!**
- `ruff format --check` (LF-normalized, the gate's method): all seven Python files touched
  this round (`gateway/routes.py`, `gateway/authorize.py`, `gateway/state.py`,
  `gateway/codes.py`, `gateway/discovery.py`, `gateway/token.py`, `scripts/probe_routing.py`)
  are format-clean.
- `mypy`: **Success: no issues found in 39 source files.**
- The live probe battery: **all 10 probes passed** (probe 10 included).
- B1 live re-verification: `APPS={}` in the container; gateway `healthy`.

## Round-13 validation

No delta spec text was touched this round (every fix is a comment, a compose line, a probe
assertion, or a docs/evidence re-wording). `openspec validate apps-with-mcp-endpoints`
re-run: **valid**. No commit; the change's remaining gates (7.5, the commit) stand.

---

# Round 14 — the owner's ruling on the SIA shape judgment (planning artifact only)

## The R4 question

Recorded in round 2 above (R4), the one method-conformance judgment left for a ruling
rather than settled in the design: the SIA prices this change as delta threat tables on
**existing surface classes**, while the standing method's "adds a surface" trigger names
"a new endpoint" — and this change adds new endpoints (a new public path shape, a new
unauthenticated discovery route) without adding a trust boundary, credential, or grant
type. Whether a class-instance route counts as an existing surface (the tables stand as
written), or every new route demands the complete new-entry-point enumeration (the tables
need widening), was the question put to the owner.

## The owner's vote (2026-11-04): tables stand

The owner ruled: **the SIA's shape judgment is accepted — the tables stand.** The change's
new endpoints (the apps PRM route, the apps MCP path) are treated as instances of existing
surface classes, priced with delta threat tables, and the full new-entry-point enumeration
is **not** owed. The reason: no new trust boundary, credential, or grant type exists; every
new threat row lands in a class the model already enumerates; and the security review gate
at medium depth ran against exactly these tables and held them. The ruling sets the
precedent for future changes: a new endpoint that is an instance of an analyzed surface
class is priced with delta rows, not a fresh chapter.

## Where the ruling landed

- **design.md §8, "Questions for the owner"** — the SIA-shape-judgment question is marked
  **ruled** (2026-11-04): the heading now reads "the SIA shape judgment: RULED 2026-11-04;
  the tables stand", the question's framing is kept as the record of what was asked
  (recast to past tense), and a closing paragraph carries the disposition — the ruling, its
  reason (no new trust boundary, credential, or grant type; every new row in an enumerated
  class; the medium-depth security review gate ran against these tables and held them), and
  the precedent it sets for future changes. The SIA's own shape judgment (§"Security impact
  analysis", opening paragraph) is unchanged — it was accepted as written, not re-worded.
- No other site: the delta spec, the proposal, the tasks, the release notes, and the threat
  model are unchanged. The ruling confirms the SIA's tables as authored; it lands no new
  behavior and no new mitigation, so no other artifact carries it.

## Round-14 validation

`openspec validate apps-with-mcp-endpoints` re-run after the ruling was recorded:
**valid**. No commit; the change's remaining gate (7.5, the commit) stands.
