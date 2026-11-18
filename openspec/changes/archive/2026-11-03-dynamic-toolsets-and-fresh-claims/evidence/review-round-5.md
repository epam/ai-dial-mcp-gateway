# Independent review — round 5 (the final correction: the consult deleted, guard-only discovery)

Change: `dynamic-toolsets-and-fresh-claims` as re-taken on the owner's final correction
(2026-10-31, issued after empirical testing): the discovery consult and its Core service
API key are deleted, restoring guard-only discovery — the PRM route answers any
guard-passing name, mirroring Core's own registry-independent unauthenticated tier, with
existence decided solely at the flow's settings read. Reviewer: a fresh independent pass —
rounds 1–4, the mechanism opinion, and the custody opinion were read as history to verify
against, not verdicts to inherit. Ground truth verified this pass: `docs/security-analysis.md`
(the method), `docs/threat-model.md` (the at-a-glance counts, the locations the §7 delta
cites), the main spec (`openspec/specs/mcp-signin/spec.md`, scenario-by-scenario against
the delta), the code (`gateway/core.py`, `gateway/flow.py`, `gateway/token.py`,
`gateway/tokens.py`, `gateway/status.py`, `gateway/keys.py`, `gateway/routes.py`,
`router/nginx.conf`), `docs/production-roadmap.md` (P3, C1/C1.5), and — for the mirror
property's facts — **the DIAL Core source itself** (`dial/dial-core/ai-dial-core`:
`Proxy.java` (`handleRequest`, `authorizeRequest`, `isMcpResourcePath`,
`isMcpResourceMetadataPath`), `WellKnownResourceMetadataController.java`,
`WellKnownResourceMetadataService.java`, `RouteTemplate.java` (`TOOL_SET_MCP_PROXY`,
`TOOL_SET_PROXY_METADATA`), `ResourceAuthSettingsData.java`). The two live facts are taken
from the owner's recorded empirical test, not re-run this pass (no composed stack was
assumed); both were independently re-verified in the source, which is the verification
class round 3 used for the logging facts. `openspec validate
dynamic-toolsets-and-fresh-claims --strict` run this pass: **green**.

**Overall verdict: LAND AFTER FINDINGS** — four minors, no blocker, no major. The
deletion is complete (the recurring defect class does not recur: every consult-era hit in
all five artifacts sits inside the deletion's own record, a negation, or the sweep
instructions); the mirror property's facts verify against the Core source; the
stage-order argument holds end to end with the merged existence edge priced, not weakened;
the custody half is untouched; and the at-a-glance counts are counted, correct in all
three artifacts. Nothing below reopens a design decision.

---

## Findings

### BLOCKER

None.

### MAJOR

None.

### MINOR

**R5-m1 — Three retained scenarios (and one requirement's subject) differ from the main
spec beyond the declared amendments — the mapped→served/restriction vocabulary shift is
real, required, and undeclared.**
`specs/mcp-signin/spec.md:13` (Per-toolset protected-resource fetch: WHEN "for a mapped
toolset" → "for a served toolset" — the declared amendment names only "the per-toolset
fetch's omitted kind extension"), `:18` (Unmapped toolset: WHEN "a name absent from the
mapping" → "a name the configured operator restriction excludes" — undeclared), `:48`
(One-toolset inference: WHEN "exactly one toolset is mapped" → "the operator restriction
is configured with exactly one entry" — undeclared), `:173` (the status requirement's "a
mapped toolset's" → "a served toolset's", beyond the declared boolean-semantics
amendment); against the declared-amendments list at `design.md:1952-1958`, whose own
standard ("any undeclared diff is a finding") this violates. Every diff is forced by the
declared mapping→restriction redesign and semantically faithful — no drift — but a
byte-identity audit executed against the declared list alone would flag these three as
unexplained. Remedy: one line in the declared list ("the retained scenarios'
mapped→served/restriction vocabulary re-wording"), or fold each into its requirement's
existing declaration.

**R5-m2 — The backstop's non-existence failure ways are pinned in design, tasks, and
code — but not in the delta spec, on the read the change itself names the system's only
existence refusal.**
The unknown-toolset scenario (`specs/mcp-signin/spec.md:95-97`) fully pins the absent-name
case: refusal shape (plain-language page), no upstream round-trip, no surviving flow
state, one audit record. The fails-closed scenario (`:91-93`) pins absent/unreadable/FAILED
statuses. But (a) the **Core-down** shape at the settings read — the one failure way that
matters most now that discovery no longer fails when Core does — has no normative sentence
or scenario: it lives in `design.md:642-644` ("where it already lives today"),
`tasks.md:463-466` (task 3.2's live check), and the code (`gateway/core.py:169-170`'s
transport refusal; `gateway/flow.py:452-462`'s two-page split, which renders it as the
operator-facing fault page, distinct from the not-registered page — verified); (b) the
**unreadable projection/kind** shape is pinned only in `tasks.md:135-136` ("an unusable or
absent kind value fails closed the same way as a non-OAuth kind") and DT-EP5-3's category
6 — the spec's impossible-branch scenario covers it only by implication ("is not OAUTH");
and (c) the scenario's "the fixed-vocabulary reason" never names the token — `design.md:680`
(D10) says `unknown_toolset`, but no task row pins which token the settings-read refusal
lands on, and today's code has no such home to inherit (`routes.py:81`'s discovery home
dies with the mapping gate). Concrete failure: an implementer writing conformance rows
from the spec alone has no row for "Core stopped mid-flow" and no committed token for the
unknown-name audit record, on the surface the spec itself calls the system's only
existence refusal. Remedy: one sentence in the federation requirement (the settings read
fails closed on an unreachable or unreadable Core answer with the operator-facing fault
page — not an existence answer; an absent or unusable kind value falls into the impossible
branch) and the token named once (D10's `unknown_toolset`) in the scenario or task 1.4.

**R5-m3 — The mirror property's two Core facts are stated unconditionally; both are
conditional on the route being enabled.**
`design.md:597-608` (D8) and `specs/mcp-signin/spec.md:7` state that Core's MCP path
answers an unauthenticated call "with 401 plus WWW-Authenticate" and that Core's PRM route
"answers any well-formed name with 200". Verified in the source: both true — but only when
`toolsets.security.authorizationServers` is configured.
`WellKnownResourceMetadataService.isDisabled()` (authorizationServers == null) makes
`resolveResourceMetadataPath` return empty, so the MCP 401 carries **no** challenge header
(`Proxy.java:340-362` builds the header map from that Optional), and
`resolveResourceMetadata` returns empty, so the controller answers **404**
(`WellKnownResourceMetadataController.handle`). The live verification ran on the configured
local deployment, so the recorded facts are true of the ground truth; the unqualified
wording is the overstatement — the one class attack point 1 names. The mirror's
load-bearing half is unaffected (a disabled PRM route is no existence oracle either, and
the gateway serves its own document regardless), so this is wording, not substance.
Remedy: a parenthetical in D8 and the spec sentence ("when the route is enabled — Core's
`authorizationServers` configuration disables it"), matching how round 4 recorded the same
edge.

**R5-m4 — The old-mapping parse refusal (the migration's loud refusal) has design, task,
and release-note homes but no spec scenario.**
`design.md:574-577` (D7: a mapping entry carrying the removed `authentication_type` member
is refused loudly at parse, `extra="forbid"` naming the field), `tasks.md:42-44` (task 1.1),
`release-notes-draft.md:10-12` — but the delta spec pins only "the `authentication_type`
member is removed from the mapping's schema" (`specs/mcp-signin/spec.md:205`) and the
REMOVED migration note (`:191-193`) declares the dropped scenario without naming the
replacement refusal. Concrete failure: the one breaking change an upgrading operator hits
(their pinned mapping refusing startup) is not conformance-pinned — an implementation that
silently ignores the unknown member passes every spec row. Remedy: one scenario in the
ADDED mapping requirement (WHEN a restriction entry carries the removed member, THEN
startup refuses naming the field).

*Checked and not a finding:* the short-circuit's flow-record lifecycle is design-pinned
only (`design.md:379-383`, A2: TTL-bounded, identity-free) — but the abuse-bounds
requirement's retention bound ("exposed at most min(flow TTL, its own expiry)") already
caps the exposure the lifecycle would govern, so no spec gap of consequence. The status
endpoint's phantom-name shape (guard passes, Core's authenticated route 404s) follows
Core's own per-user answer on an authenticated surface — no unauthenticated oracle, and
task 1.2's "identical to the unknown-name refusal on the same surface" row covers the
shape.

---

## Verdicts on the eight attack points

1. **The mirror property's Core facts — PASS, source-verified this pass, with one wording
   caveat (R5-m3).** (a) The MCP path: `Proxy.handleRequest` runs `authorizeRequest`
   before any deployment/registry resolution; a credential-less GET/POST on
   `TOOLSET_PROXY_PATTERN` (`/v1/toolset/{id}/mcp`, `RouteTemplate.java:351-354`) fails
   401 with `WWW-Authenticate: Bearer resource_metadata="{schema}://{host}/.well-known/
   oauth-protected-resource/v1/toolset/{name}/mcp"` — the exact challenge shape D8 states,
   with no registry lookup anywhere before it: no unauthenticated existence oracle.
   (b) The PRM route: `isMcpResourceMetadataPath` GETs are dispatched to
   `WellKnownResourceMetadataController` **before** `authorizeRequest`
   (`Proxy.java:298-301` — unauthenticated, stronger than "registry-independent" alone),
   and the service builds the document from static `toolsets.security` settings with the
   requested path echoed as `resource` — no registry read; a phantom earns its 200.
   (c) The router: `router/nginx.conf:54,106` — the challenge map names the gateway's own
   PRM route, and the location serves it; D8's "today's 404-for-unmapped answer is the
   mapping's answer" verifies against `gateway/routes.py:81`. (d) "Every registry-bound
   route sits behind `authorizeRequest`" verifies: only health, version, and the PRM
   route bypass it. The live claims are the owner's recorded empirical test — not re-run
   this pass, honestly stated; the source verification stands on its own and confirms
   both. The one overstatement is the disabled-route edge (R5-m3).
2. **The deletion's completeness — PASS.** Grepped all five artifacts for the full
   consult vocabulary (consult, service key/service credential/service API key,
   `dial_core_api_key`, `gateway_discovery_max_concurrent_consults`, concurrency,
   `core_unavailable`, 503, 403-omits-kind, OQ-I, RES-24, T1-20/T5-8/T4-9, M22, G9/G10,
   DT-EP1-10/DT-EP5-5/DT-EP4-2, phantom-refused, amplifier, cache, the 65/24/18/23
   counts). Every surviving hit is inside the deletion's own record (the Context
   ruling-2 paragraph; D8's "Why the consult is deleted"/"What is deleted with the
   consult"; the impact level's negation; DT-EP5-3's merge record; §7's deletion notes;
   §8's pushback record and this round's attack list; the Risks entry), a negation ("no
   service key", "consults nothing", the spec's "no consult, no service credential, no
   cache, and no Core-unavailable failure shape"), or the sweep/verify instructions
   (tasks 1.3/1.5/4.1/5.8). No stray survivor. The deleted tokens leave nothing dangling:
   `core_unavailable` appears nowhere in spec, tasks, or release notes.
3. **The settings-read backstop's full weight — PASS with R5-m2.** The weighted scenario
   pins the absent-name refusal completely (shape, audit, no surviving state, no upstream
   leg) and the requirement pins the stage order and the status fail-closed; the
   authorization requirement names the backstop's home (R4-M3's remedy, landed and
   verified). The two failure ways the spec does not pin — Core-down and the unreadable
   projection/kind — plus the unnamed audit token are R5-m2. The refusal-shape claim
   itself verifies against the code: today's 404 CoreError renders the plain-language
   "not registered in DIAL Core" page, distinct from the Core-down fault page.
4. **The stage order as an authorization argument — PASS.** Re-traced against the delta's
   federation requirement and the code's real paths: no mint without (the live identity
   leg — the short-circuit sits after the exchange; the token endpoint mints only from a
   PKCE-bound single-use code or a valid refresh) + (the per-user DIAL read — 403-refused,
   and the signed-in check rides that same read, so no branch precedes authorization) +
   (a positive SIGNED_IN at user or global level OR a completed consent leg with its
   credential call). The forged-status path (DT-EP5-4) and the forged-existence path both
   yield a misleading token and data-path 401s, not access. The merged existence edge
   (DT-EP5-5 into DT-EP5-3) did not weaken the pricing: the forged not-found is priced as
   the same denial-of-one-flow shape on the same leg under the same trust (internal-leg,
   RES-19's class), the forged-existence gain is bounded by the data-path 401 in the same
   row, and T5-3's model-row amendment carries the edge with the disposition unchanged.
   One wording compression noted, not a finding: DT-EP5-3's "its forged-existence sibling
   (a phantom served past this read) cannot happen" — the *event* can happen on the leg;
   what cannot happen is access, which the colon's clause ("no answer this leg returns
   can make a phantom's data path answer anything but 401") states correctly.
5. **Use-vs-establish — PASS.** The main spec's "GLOBAL-level establishment refused"
   scenario is untouched (the credential-model requirement is not in the MODIFIED list)
   and remains true: the credential call stays USER-level on every establishing path, and
   the delta's federation requirement states the distinction explicitly ("the flow never
   establishes a credential at GLOBAL level … a GLOBAL credential the short-circuit uses
   is one an operator configured — the flow uses it, it does not establish it"); the
   global-credential scenario's "the flow establishes no credential itself" is the exact
   anti-blur wording. No delta text says the flow establishes, grants, or configures a
   global credential. Invariant 3's model-row amendment (§7) is coherent after the
   deletion: it adds the GLOBAL-use sentence to a row that carries no level wording,
   cites no consult material, and the four model homes round 4 found (RES-9, T5-4's
   row/grid/disposition) are all in the §7/task-4.1 list.
6. **Byte-identity of the retained rows — PASS with R5-m1.** Every retained scenario was
   compared against the main spec: the mapping requirement's two retained scenarios
   byte-identical; the refresh requirement's three retained scenarios byte-identical with
   exactly the three declared amendments; the abuse-bounds requirement's four retained
   scenarios byte-identical with the restored opening, the declared custody amendments,
   and the new discovery parenthetical (a negation); the federation, issued-tokens, and
   claim-copy retained scenarios byte-identical; the status scenarios identical plus the
   declared boolean semantics and the new global scenario; the per-toolset fetch and
   unknown-resource amendments declared and landed (R4-M3's re-wording verified:
   `invalid_target` keyed on the guard-and-restriction admission, the backstop named).
   The one undeclared-diff class is R5-m1's mapped→served/restriction vocabulary — three
   scenarios plus one requirement subject, all forced by the declared redesign.
7. **The custody half untouched — PASS, with the verification's honest limit stated.** No
   VCS baseline exists for the change folder (untracked in git), so byte-level comparison
   is impossible by construction; the verification is semantic plus the code citations,
   and it passes: D1–D6, the custody delta rows (DT-EP1-4–9, DT-EP4-1, DT-EP5-1/2),
   G3–G8, tasks 2.x/3.1/3.3, and the custody-era §7 entries carry no P3 or discovery
   content; every code fact they cite re-verified this pass (`gateway/tokens.py:202`
   access `aud=[resource, marker]`, `:232` refresh `aud=[resource]`;
   `gateway/keys.py:63-68`'s minimum-size load check; `gateway/token.py:96-126`'s closed
   `_REFUSAL_REASONS` table, `:289-291` and `:359-362`'s `invalid_target` resource
   mismatches — task 2.6's correction claim is accurate against the code). The one
   custody-adjacent text that changed is declared: the abuse-bounds requirement's
   discovery parenthetical (this re-taking), and R4-m4's cap≥bound coupling sentence,
   which landed in the federation requirement exactly as round 3 specified — the round-4
   remnant is closed. Every round-4 finding is verifiably landed (R4-M1's four model
   homes, R4-M2's T1-4/T6-7/§6 locations, R4-M3's re-wording, R4-m1's counts, R4-m3's
   app-level sentence in D12 and task 1.4, R4-m5's task 1.6); R4-m2 is moot by deletion.
8. **The counts and the audit-vocabulary closure — PASS.** Recounted from the pre-change
   model's at-a-glance (`docs/threat-model.md:27-30`: 55 threats — EP1 16, EP4 7, EP5 6;
   19 residuals; 15 assets; 20 grouped mitigations) plus the actual delta: +T1-17/18/19/21/22
   → EP1 21; +T4-8 → EP4 8; +T5-7 → EP5 7; total 62. Residuals 19+RES-20..23 = 23.
   Assets 15+2 = 17. Mitigations 20+M21+M23 = 22 (M22 deleted). Design §7, task 4.1, and
   the release notes all carry 62/23/17/22 with the same EP split — counted, not carried;
   task 4.1's intermediate custody-era numbers (59/…) describe the custody half's
   contribution inside one edit pass and are superseded by the final counts in the same
   task, coherently. No dangling `core_unavailable` or consult token anywhere; the
   surviving tokens (`non_oauth_toolset`, `unknown_toolset`, the guard's three, the
   refresh three) all reach the record through the fixed-vocabulary discipline — the
   closed-table extension (error code plus named refusal class) is specified in tasks
   1.2/2.3 with the no-bypass and mutual-distinguishability rows.

## Method conformance, scope discipline, validation

- **SIA shape per `docs/security-analysis.md` — PASS.** All eight sections in order; the
  per-change delta shape correctly chosen; mis-use cases marked (DT-EP1-2, DT-EP1-7,
  DT-EP1-12, T1-22); the control-category order with threat-specific N/A reasoning
  throughout; G1–G8 with homes and owners, every DT row addressed by some G and every G
  addressing existing DTs — **no ancestorless or orphaned row**: the numbering gaps
  (DT-EP1-10 absent, DT-EP4-2 absent, DT-EP5-5 merged) are the deletion's own record,
  declared in D8. EP3's touched-but-tableless treatment is justified in §4's preamble.
  The invariant rows are honest (row 1's "strengthened in wording" is earned — the
  short-circuit reads a status, never a credential).
- **Scope discipline (no C1.5 creep) — PASS.** The change builds the general rule and
  states the unification; it does not build the apps resource surface, its routes, its
  discovery documents, or the router's apps MCP path; DIAL_NATIVE appears only as a Core
  vocabulary value and in D11's declared split of what remains C1.5's. The roadmap's stale
  P3/C1.5 lines (`docs/production-roadmap.md:35-40, 183-192`) are reconciled by task 1.6
  — R4-m5's remedy, landed.
- **The Core-ask's parked wording — PASS.** Design §8 states it as "the OQ-4 pattern (a
  suggestion to the Core team, explicitly not a dependency of this system, not built
  here)", the proposal and release notes carry the same non-dependency framing, and the
  mirror property is stated as the standing shape ("until then") rather than as
  contingent on the ask. Not an owner ruling slot, correctly.

## Clean areas (one line each)

- The deletion record itself: complete, self-describing, and honest about what died
  versus what moved (the 503 shape's move to the settings read, where the code already
  has it).
- The pushback record: both orchestrator objections answered with verified facts — the
  GLOBAL delegation priced as DT-EP1-12, the phantom-traffic objection resolved by
  deletion with its premise (no unauthenticated existence route) re-verified in the
  source this pass.
- The guard requirement: one predicate, the router's own constants, per-surface response
  shapes, fixed-vocabulary refusals — and the router needs no change (its locations are
  generic; `nginx.conf` verified).
- The status requirement's boolean re-derivation and the app-level member's named
  exclusion (R4-m3 landed in D12 and task 1.4).
- The REMOVED+ADDED migrations: both reasons argue the right rule, and both notes declare
  their drops — with R5-m4 the one unpinned edge.
- The release notes: accurate on both audiences, including the honest "one less
  dependency than the earlier draft promised".
- `openspec validate --strict` — green, run this pass.

## What the owner pause must decide

- **OQ-A / OQ-G / OQ-H** — as parked (design §8); OQ-B, OQ-C, OQ-E, OQ-F remain
  discharged/resolved-with-source; OQ-D remains a recorded requirement for the later
  secret-management scope. The Core-side ask is not a ruling slot.
- **Pre-pause fixes to require landed** (authoring completeness, not rulings): R5-m1's
  declared-amendments line; R5-m2's one normative sentence plus the named audit token;
  R5-m3's disabled-route parenthetical; R5-m4's parse-refusal scenario. All mechanical.
- **Carried from rounds 3/4** (defaults landed in the artifacts, confirm or overrule):
  rotation-off's priced semantics; the associated-data binding / single-active-keyset
  commitment rationale; the hard-cut rotation wave as the accepted cost.
- **Task 5.7 stands** — the `gateway/tokens.py` docstring correction has its task home
  and its pause assignment; nothing this round changes that.

## Bottom line

**LAND AFTER FINDINGS.** Land R5-m1 through R5-m4 — all mechanical, none reopening a
design decision — in the change artifacts before the owner pause. The deletion this round
was built to falsify is complete: not one consult-era artifact survives outside its own
deletion record across all five files, the counts were re-derived rather than inherited
and are right, and the guard-only discovery carries the weight the flow restructure puts
on it — the mirror property's facts verify against the Core source (with one wording
caveat), the settings-read backstop's absent-name row is fully pinned, and the stage
order remains an authorization argument end to end. The recurring edit-list defect class
of rounds 2–4 does not recur. The findings that remain are the spec's last unpinned
edges on the surfaces this re-taking itself re-weighted.
