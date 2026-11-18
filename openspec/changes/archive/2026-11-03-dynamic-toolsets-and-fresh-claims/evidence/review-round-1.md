# Independent review — round 1 (PROCESS.md step 3b)

Change: `dynamic-toolsets-and-fresh-claims` (C1 = P3 dynamic toolsets + P2 fresh claims).
Reviewer: independent pass, not the author. Method: falsification against the ground
truth — `docs/production-roadmap.md` §"The iteration, packaged and ordered",
`docs/security-analysis.md`, `docs/threat-model.md`, the main spec, the code, and the
OIDC/Microsoft specifications the mechanism's claims rest on. Read-only except this file.

**Overall verdict: LAND AFTER FINDINGS.** The architecture (D1–D10) survives
falsification: the mechanism choice is defensible, the fail-closed refresh semantics are
normative and leak-free, the retention bounds are specified, and the scope discipline
holds. The findings below are completeness and honesty defects — concentrated in the
SIA's threat-model delta (task 4.1), the token-use purposes text, one under-specified
security-relevant seam, and one pre-existing spec/code contradiction the rewrite carries
forward. None reopens a design decision; all are fixable without re-architecting.

---

## Findings

### BLOCKER

None.

### MAJOR

**M1 — The universality claim is overstated against documented provider facts; the
availability dependency is unnamed.**
`proposal.md:53-58`, `design.md:64-100` (D1), `design.md:102-115` (D2).
Verified against the specifications: `userinfo_endpoint` **is** an OIDC Discovery member,
but it is **RECOMMENDED, not REQUIRED** (OIDC Discovery 1.0 §3) — a conformant OP may
omit it, so "discoverable from the issuer" does not mean "guaranteed by the issuer".
Harder: the Microsoft identity platform's UserInfo endpoint returns a fixed,
non-customizable claim set — "You can't add to or customize the information returned by
the UserInfo endpoint" (learn.microsoft.com/en-us/entra/identity-platform/userinfo) —
so **role and custom claims never appear in Entra's userinfo**; B2C exposes a userinfo
endpoint **only through custom policies** with per-policy claim wiring
(learn.microsoft.com/en-us/azure/active-directory-b2c/userinfo-endpoint), and B2C is
end-of-sale for new customers since 2025-05. Concrete failure: a C2 (B2C) deployment
under D2 fails at sign-in for **every user** — not misconfiguration, but a provider fact
no `ROLES_SOURCE_PATH` value can satisfy — so P2's acceptance (roles reflected within
the access TTL) is unachievable on the roadmap's own named tested case via this
mechanism. D2 prices "a deployment that misses it fails loudly" as a configuration
error; it does not name that a named future target categorically cannot meet the
requirement. The local deployment is fine — `scripts/provision_keycloak.py:256-281`
already sets `userinfo.token.claim: true` on the roles and project mappers, and task 2.5
verifies it — so this is not a local blocker. Remedy: qualify the universality claim in
D1/D2 and the proposal (universal among providers whose userinfo can carry the
deployment's claims for the client's scopes; `userinfo_endpoint` is RECOMMENDED), move
the Entra/B2C fact from silence into the strict gap list or an open question, and hand
it to the owner pause as an input to C2's planning.

**M2 — The token-use purposes list omits the issuance-time userinfo read; the spec text
lands already incomplete.**
Delta spec `specs/mcp-signin/spec.md:123` ("its presentations are the flow's decision
step and credential call plus one userinfo read per refresh"), `design.md:280-281`
(DT-EP5-2's count language), `design.md:558-559` (§7's T5-1/RES-3 edit: "purposes now
include one userinfo read per refresh"). D2 itself introduces and prices a **per-flow
issuance** read ("one more identity-provider call and one more token presentation per
flow", `design.md:113-115`) — but the normative purposes sentence in the abuse-bounds
requirement, DT-EP5-2's description, and the specified RES-3 re-derivation all count
only the refresh-time read. Concrete failure: the day this spec lands, its token-use
rule — the exact subject of RES-3, a purposes rule — is stale relative to the design it
specifies, and the threat-model edit lands the same omission. Also `design.md:115` cites
"(DT9)", a numbering that does not exist in this SIA (the delta threats are DT-EP1-1…6,
DT-EP4-1, DT-EP5-1…3) — a dangling citation from an earlier draft. Remedy: amend the
purposes sentence to "…the flow's decision step, credential call, and one userinfo read
at issuance, plus one userinfo read per refresh while retained"; fix DT-EP5-2 and the
§7 T5-1/RES-3 edit to match; repair the citation.

**M3 — The threat-model delta (§7 / task 4.1) is incomplete: entries whose current text
this change invalidates are missing from the edit list.**
`design.md:540-574` (§7), `tasks.md:128-136` (4.1). Checked line by line against
`docs/threat-model.md`:
- **RES-10** (`threat-model.md:172-176`): its accepting condition reads "The mapping is
  OAUTH-only, **enforced at startup with no escape**" — false in dynamic mode the day
  this lands (the kind check moves to the flow). Not in the edit list. This is
  DT-EP5-3's own residual; the SIA prices the moved check but never lands the re-price.
- **RES-15** (`threat-model.md:204-210`): "(b) … **issued tokens and refresh survive**
  (self-contained JWTs)" — after this change a restart kills refresh *capability* (the
  retention store is lost; refreshes fail closed), which the spec, D3, and the release
  notes all state — but RES-15, the record of exactly those loss semantics, is not in
  the edit list, so the model's restart row becomes false as written.
- **T6-2** (`threat-model.md:1362-1364`, control 4): "the startup reserved-name check
  refuses the collision before the router ever serves it" — for dynamic names there is
  no startup check; the request-time guard does this work. The M10 amendment names the
  moved halves, but T6-2's own row is left stating a control that no longer covers the
  dynamic case.
- **T1-7** (`threat-model.md:615-628`): DT-EP1-5 says the refresh flood gains "a
  per-request cost it did not have" (one outbound IdP call per refresh) — T1-7's row is
  not in the edit list.
- **DT-EP1-6's accepted availability trade has no landing.** §6 lists it as an accepted
  remainder ("the priced cost of freshness"); per the standing method an accepted
  remainder **is** a disclosed residual and must land in the model's register — no new
  RES entry is specified anywhere in §7 or task 4.1.
Task 4.1's own verify clause ("no other entry's disposition changes") makes the
omission worse: an implementer following it literally would *protect* RES-10/RES-15's
now-false text from edit. Remedy: add the five entries above to §7 and task 4.1.

**M4 — A pre-existing spec/code contradiction is carried verbatim into the replacement
requirement.**
Main spec `openspec/specs/mcp-signin/spec.md:224-226` (scenario "Resource mismatch on
refresh" → `invalid_grant`) vs `gateway/token.py:359-362` (raises `invalid_target`) and
`tests/test_tokens.py:447-457` (asserts `invalid_target`). The delta's ADDED requirement
carries the scenario byte-identically (`specs/mcp-signin/spec.md:195-197`) while its
Migration section presents byte-identity as the safety property. Concrete failure: task
5.3's gate ("the retained rows unchanged" green) cannot pass as written — the row is red
against the code today, and the REMOVED+ADDED rewrite was precisely the moment to
reconcile it. Remedy: pick one (the code's `invalid_target` matches the code-grant
analogue at `token.py:289-291` and the existing test; changing the scenario is the
cheaper, honest fix) and record the reconciliation in the migration note.

**M5 — The identity-token hand-off seam (flow end → code grant) is under-specified, with
a dangerous easy path unnamed.**
`tasks.md:72-81` (2.2: "keyed by the live refresh token's `jti`, **written at the code
grant** (the flow hands the identity access token over at `_finish`…)"), delta spec
`specs/mcp-signin/spec.md:55` ("handed to the refresh-window retention at flow end").
The refresh token's `jti` does not exist until the code grant at `/dial/token`, minutes
after `_finish`, and the flow record is destroyed before `_finish` runs
(`gateway/routes.py:170`) — so the identity token must transit a server-side
intermediate (a pending-retention entry keyed by the code's `jti`, bounded by the code
TTL, dropped on non-redemption). No task or spec sentence names that transit, its key,
or its bound. Concrete failure: the implementation's easiest path — embedding the
identity access token in the authorization code's payload — **delivers the IdP access
token to the client**: the code is a signed-but-unencrypted JWT handed to the harness
through the browser (`gateway/flow.py:348-370`, `gateway/routes.py:241-261`), so its
payload is base64-readable by anyone holding the code string, violating the retention
requirement's own "MUST NOT be … delivered to any client" and never-cut 5. The security
review gate would catch it at implementation, but the change's job is to make the wrong
path unbuildable, not merely detectable. Remedy: one task clause naming the hand-off
store, its key, its TTL bound, and the explicit prohibition on the code payload as a
carrier.

**M6 — The audit-vocabulary extension at the token endpoint is under-specified against
`tokens.py`'s closed-table property, and the claims-read failure class has no distinct
audit token.**
`tasks.md:21-34` (1.2), `tasks.md:82-96` (2.3), `gateway/token.py:96-126`
(`_REFUSAL_REASONS` — closed, keyed by OAuth error code; `reason` raises outside it).
Three gaps: (a) task 1.2 applies the guard at "the refresh grant's resource-to-name
resolution (`gateway/tokens.py`)" and audits `reserved_toolset_name` /
`invalid_toolset_name` / `restricted_toolset` there — but the token endpoint's audit
path is the closed table keyed by error code, and no task says how a guard reason
reaches the record without breaking the table's one-directional property (a direct
`flow_refused` call bypassing `TokenRequestError`, or a table extension — unspecified).
(b) The guard-failure **response shape** at the token endpoint is unnamed (task 1.2
lists shapes for discovery/status/authorize only; `invalid_grant` vs `invalid_target`
matters and interacts with M4). (c) The claims-read failure at refresh refuses with
`invalid_grant` and therefore audits as `invalid_grant` — indistinguishable from
expiry/revocation — yet DT-EP1-4 cat. 8 and DT-EP1-6 cat. 8 both promise the operator a
distinctive signal ("a pattern of them during an incident is the operator's signal that
freshness failed closed"; "a provider outage reads as a burst of them"). Concrete
failure: during an IdP outage the audit trail shows ordinary `invalid_grant` refusals
indistinguishable from mass token revocation — the SIA's stated detective control does
not exist as tasked. Remedy: name the mechanism and the reason tokens (e.g.
`claims_read_failed`) in tasks 1.2/2.3, keeping the closed table's property explicit.

**M7 — P3's "unknown names fail closed" acceptance has no conformance scenario.**
Delta spec `specs/mcp-signin/spec.md:53-83` (the federation requirement carries "Non-OAuth
toolset refused before the upstream leg" but nothing for a name Core does not know);
`proposal.md:45-47` claims "Unknown names fail closed as today — … at the flow's settings
read for names Core does not know"; task 3.2 exercises it live only. Per the repo's own
rule (a behavior that exists only in prose is not landed), the second half of P3's
acceptance clause ("non-OAUTH **and unknown** names fail closed as today") has no spec
row to gate on. Remedy: one scenario ("Unknown toolset refused at the flow's settings
read" — plain-language page, audited, no upstream round-trip), symmetric with the
non-OAuth one.

### MINOR

**m1 — Byte-identity drift in a retained scenario.** Delta spec line 151: "not
signed-in" → "not-signed-in" (hyphenation normalized against the main spec's line 252).
Cosmetic, but the change's own migration discipline is byte-identity; restore or declare
it.

**m2 — The spec's "resolved from the issuer" overstates what C1 implements.** Delta
spec lines 7 and 189 call the userinfo endpoint "the OIDC Discovery claims endpoint,
resolved from the issuer", while task 2.1 derives the URL by the Keycloak suffix
convention — D6 discloses the tension, but the *normative* sentence describes a
discovery-document read that C1 never performs; a from-spec reimplementation would
diverge from the implementation shape on day one. Reword to "the issuer's userinfo
endpoint" (the discovery resolution belongs to C2).

**m3 — Task 2.4 keeps the operator-facing refusal message unchanged while D5's principle
demands otherwise.** `gateway/settings.py:442-450`'s message argues the *superseded*
staleness reading ("claims could then be staler than one the identity provider would
issue"); D5 says "a validator that no longer means what it says is worse than none", yet
task 2.4 pins the message for the unchanged test row. Re-derive the message's
justification (the retained-token-outlives-window reading) and update the test row with
it — the row exists to pin the operator-facing text, not to freeze it.

**m4 — OQ-1 is carried as open while the code answers it.** `design.md:596-597` (OQ-E:
E9's per-toolset binding "stays open") vs `gateway/status.py:111-122`, which already
enforces the presented token's audience/resource binding at E9. The change amends T1-15
(E9's threat) anyway; resolving OQ-1 against the code in the same edit is nearly free
and stops the model carrying a question the codebase answers.

**m5 — The "valid dynamic name resolves" scenario blends surfaces.** Delta spec
`specs/mcp-signin/spec.md:243-245`: its WHEN names a Core fact ("a toolset that Core
serves as OAUTH") that no pre-flow surface can observe (D8: kind is decided at the
flow). Read at discovery/authorize the scenario is untestable as written; fold into the
M7 remedy (state the phantom-name behavior per surface).

*One-line observation, not a finding:* EP3 (browser callbacks/HTML pages) is touched
(the kind refusal renders a new plain-language page on the identity-leg callback) but
not enumerated in the delta tables — defensible under the per-change shape (the page is
fixed text through the shared hardening helper; no new threat shape), worth one
justifying sentence in the SIA.

---

## Verdicts on the author's attack list

1. **D1's universality / D2's claim pricing — PARTIAL FAIL (M1).** The endpoint
   membership claim is true; the REQUIRED-status implication is not (RECOMMENDED), and
   the claims-availability dependency has documented counterexamples among named future
   targets (Entra: userinfo not customizable at all; B2C: custom-policy-only). The
   omission-omitted-IdP case fails loudly at sign-in under D2 (covered by task 2.1's
   refusal classes) — fail-closed, not a runtime surprise. Local acceptance is
   achievable (the provisioning mappers already carry `userinfo.token.claim`).
2. **D4's fail-closed refresh — PASS.** The ADDED requirement pins it normatively
   ("MUST refuse … a frozen-snapshot fallback MUST NOT be used"), the scenarios cover
   both failure classes (read failure, sub mismatch), no scenario or task clause permits
   a snapshot path, and OQ-A parks the fallback for the owner as designed.
3. **D3's retention store — PASS with findings.** RES-2's re-pricing is specified
   (§7, T4-2/RES-2); the restart semantics are stated in the spec (ADDED retention
   requirement), the release notes, and D3, with a verify row in task 2.2; the
   leak discipline is specified (never logged/persisted/delivered + a dedicated test
   row). The gaps are the transit seam (M5) and RES-15's missing edit (M3).
4. **The REMOVED+ADDED pair's byte-identity — PASS mechanically, FAIL on content (M4,
   m1).** Compared programmatically: five scenarios byte-identical, "Silent refresh"
   amended exactly as the migration note declares, all MODIFIED-requirement retained
   scenarios byte-identical except deliberate semantics-carrying amendments
   (mapped→served, identity-token→userinfo-response, the inference condition) and one
   hyphenation drift (m1). But byte-identity preserved a scenario the code contradicts
   (M4).
5. **D8's discovery decision — PASS.** The trade is stated and bounded (D8, the Risks
   section, the release notes: one wasted browser round vs an availability dependency on
   every discovery fetch); the rewritten "Unmapped toolset" scenario holds as written.
   The phantom-name-at-the-flow behavior lacks a spec row (M7, m5).
6. **The audit vocabulary — PARTIAL FAIL (M6).** The guard reasons extend the
   authorize/discovery/status vocabularies cleanly (the `AuthorizeError.reason` pattern
   and `flow_refused`); the token endpoint's closed table and the claims-read failure
   class are the unhandled half.
7. **The threat-model updates — PARTIAL FAIL (M3, M2).** Every *named* edit was checked
   against the model's current text and is consistent and non-overstating: T1-16's new
   disposition matches the delta spec's actual guarantees; RES-6's shrink and re-open
   trigger are accurate; invariant 4's restatement is accurate; RES-19/T5-2's extension
   states the forgery gain honestly (any-claims-for-an-existing-sub, narrower than
   mint-any-sub); T1-15's widening keeps its disposition; M9/M10 amendments and the
   compromise-table row match what the change delivers. The defect is what the list
   *omits* (M3) and the T5-1/RES-3 count (M2).
8. **Scope discipline — PASS.** No C1.5 creep (apps-as-MCP explicitly excluded in the
   proposal and absent from the delta spec; the kind check refuses non-OAUTH rather than
   short-circuiting a new kind); the mechanism in the delta spec is the one design.md
   justifies against the roadmap's deliberately-open mechanism choice; MODIFIED
   requirements carry full amended text; `openspec validate --strict` is green; the
   hyphenation drift (m1) is the only byte-identity blemish.
9. **The SIA's shape — PASS with the M2 seam.** Per `docs/security-analysis.md` §5's
   per-change structure, in order, all eight sections present: delta threats at the
   touched entry points (EP1 discovery/authorize/status/refresh, EP4 process memory,
   EP5 the userinfo leg and the served-set decision — the settings-read-as-surface is
   DT-EP5-3); mis-use cases marked; every control category present per threat with
   threat-specific N/A reasoning (no boilerplate found); the grouped list (G1–G8) with
   homes and owners; the invariant table is honest — the retention widening is ruled
   against invariants 3 (strengthened by the sub cross-check) and 5 (bounded, never
   logged), and invariant 4's bound shrink is stated as the change's own deliverable.
   The one shape defect is the dangling "(DT9)" citation and the purposes undercount
   (M2), plus the EP3 one-liner above.

## Clean areas (one line each)

- D5's re-derivation of the startup validator: the check's new meaning is correctly
  derived and the delta spec's "Refresh TTL exceeds the provider lifespan" scenario is
  carried intact.
- D7's startup/request-time split: exhaustive and consistent with the code's constants
  (`RESERVED_TOOLSET_NAMES`, `_TOOLSET_NAME`) and the router's static locations.
- D9's empty `scopes_supported` for dynamic names: consistent with the discovery
  module's existing no-gateway-scopes reasoning; the informational-member argument holds.
- D10's response shapes: match the code's actual refusal shapes per surface
  (`routes.py:76-83`, `status.py:54-56`, `authorize.py`'s `invalid_target` path).
- The REMOVED requirement's reason and migration notes: accurate and complete.
- Tasks 3.1/3.2 map one-to-one onto P2's and P3's roadmap acceptance texts, including
  the "by test and by a live run" halves.
- Release-notes draft: two-audience shape, no real instance/issuer values, claims match
  the design (no overstatement found beyond M1's inherited universality wording).
- The invariant ruling table's seven rows and the impact level (Medium) with reasons:
  conforming and honest.

## What the owner pause must decide

- **OQ-A** (bounded stale-claim fallback at refresh) — as parked; the design's
  rejection is sound and the spec's MUST NOT is testable; an owner ruling for
  availability reopens D4 deliberately.
- **OQ-B** (retention persistence before HA) and OQ-C/D/E — as parked (OQ-E see m4).
- **Surfaced by this review:** (1) the userinfo claim-set availability as a deployment
  requirement with named counterexamples — whether the universality claim is qualified
  as M1 asks, and whether C2's plan gains a per-provider claim-source decision now
  rather than at its own gate (M1); (2) the refresh resource-mismatch error code — spec
  fix or code change (M4); (3) whether the claims-read refusal gets its distinct audit
  token, i.e. whether DT-EP1-4/DT-EP1-6's detective control is built as priced (M6);
  (4) the hand-off store's shape (M5) — confirm the server-side pending entry, never
  the code payload, as the named transit.

## Bottom line

LAND AFTER FINDINGS: fix M1–M7 (m1–m5 alongside) in the change artifacts before the
owner pause; no design decision needs to be reopened, and no finding requires moving
ground truth other than the five threat-model entries M3 adds to the change's own edit
list. The findings' common root is one sentence worth saying at the pause: the change
prices its own behavior honestly inside the SIA's tables, but several of those prices —
the presentation count, the accepted availability trade, the moved check's residual,
the restart loss — do not yet reach the artifacts that are supposed to carry them: the
delta spec's purposes sentence and the threat-model edit list.
