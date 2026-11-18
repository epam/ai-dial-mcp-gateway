# Independent review — round 4 (the P3 ruling re-take)

Change: `dynamic-toolsets-and-fresh-claims` as re-taken on the owner's two P3 rulings
(the kind check as the upstream stage's routing decision, D11/D12; discovery consulting
Core and refusing phantoms, D8-reversal) with the two orchestrator pushbacks worked in
(the GLOBAL use-vs-establish delegation; the phantom-traffic-is-new premise correction).
Reviewer: a fresh independent pass — rounds 1–3, the mechanism opinion, and the custody
opinion were read as history to verify against, not verdicts to inherit. Ground truth
re-verified this pass: `docs/security-analysis.md` (the method), `docs/threat-model.md`
(whole — §1, §3 register, §4 assets, §5 TB4, §6, §7 entry points, §8 tables, §9 grids,
§10 compromise table, §11 invariants, §12 mitigations, §13 dispositions, §14 OQs, the
at-a-glance counts), the main spec (`openspec/specs/mcp-signin/spec.md`,
scenario-by-scenario against the delta), the code (`gateway/settings.py`,
`gateway/core.py`, `gateway/federation.py`, `gateway/flow.py`, `gateway/status.py`,
`gateway/authorize.py`, `gateway/token.py:60-199`, `gateway/audit.py`,
`gateway/discovery.py`, `gateway/keys.py`, `router/nginx.conf`), `docs/production-roadmap.md`
(§C1/C1.5, the P-items), and — for the four Core facts — **the DIAL Core source itself**
(`dial/dial-core/ai-dial-core`: `Proxy.java` (`authorizeRequest`, `extractApiKey`,
`handleRequest`), `WellKnownResourceMetadataController.java` +
`WellKnownResourceMetadataService.java`, `ToolSetController.java` (`respondError`),
`DeploymentService.java` (`findDeployment`), `ResourceAuthSettingsData.java`,
`ResourceAuthStatusEnricher.java`, `AuthenticationType.java`, `ResourceAuthStatus.java`).
`openspec validate dynamic-toolsets-and-fresh-claims --strict` run this pass: **green**.

**Overall verdict: LAND AFTER FINDINGS.** The re-take's design substance survives
falsification on every axis that matters: the stage order holds as an authorization
argument end to end; all four Core facts the consult rests on verify against the Core
source; the use-vs-establish wording coexists with the main spec's invariant without a
blur; the D8 reversal's prices are all landed as first-class artifacts; and the custody
(v3/P2) half stands as round 3 left it (every round-3 finding verifiably landed; the
ruling-era additions are additive where they touch custody-era rows). What remains is
one more instance of the recurring defect class — model locations whose current text the
re-take falsifies that the §7/task-4.1 edit list still misses (R2-M1, R3-M1 were this
class) — plus one spec-text enforceability gap the re-take introduced in the
authorization requirement, and a handful of minors led by an off-by-one in the
at-a-glance counts. No design decision is reopened by anything below.

---

## Findings

### BLOCKER

None.

### MAJOR

**R4-M1 — The edit list (§7 / task 4.1) still misses the model locations that carry the
GLOBAL use-vs-establish wording the re-take falsifies: the falsified text lives in
RES-9, T5-4's row, grid, and disposition — not in the "§11's invariant-3 row" the list
names, and §11's actual row carries none of that wording.**
`docs/threat-model.md:167-171` (RES-9: "The flow covers USER level only;
GLOBAL/app-level sign-in stays an operator action"), `:458` (§8 T5-4 row: "The flow
signs in at USER level only; GLOBAL is admin-gated in Core and stays an operator
action"), `:1290-1292` (§9 T5-4 control 4, the same wording plus "Disposition: preserved
by absence"), `:1630` (§13: "T5-4 | Preserved by absence — RES-9"); the list's amendment
(`design.md:1786-1793`, `tasks.md:557`) cites "§11's invariant-3 row" and quotes "the
gateway signs in at USER level only; GLOBAL stays an operator action" — a phrase that
appears in the model only at the four T5-4/RES-9 locations above; §11's actual
invariant-3 row (`threat-model.md:1535`) says "Credentials are stamped and resolved per
`sub` unchanged…" and carries no level wording at all. Concrete failure: an implementer
executing task 4.1 literally — whose verify clause says "the entries and sections it
names are exactly what changes" — amends a §11 row that did not carry the falsified
wording and leaves all four locations that do carry it stating "the flow signs in at
USER level only" in a system where the flow now *uses* a GLOBAL credential on every
short-circuited mint. The next SIA starts from a model whose GLOBAL statement is false
precisely at the entry that governs it. Remedy: add RES-9 (§3), T5-4's §8 row, §9
control 4, and §13 disposition to the list with the use-vs-establish amendment, and
re-derive what §11's invariant-3 row actually needs to gain (the delegation stated —
it currently says nothing about levels and needs the GLOBAL-use sentence added, not
re-worded).

**R4-M2 — Two further model locations falsified by this change sit outside the edit
list: T1-4's row and disposition still say E9's resource binding "stays open (OQ-1)"
that this change resolves, and T6-7's row and grid still name startup-on-mapping-entry
as the charset's enforcement point that the request-time guard now shares.**
`docs/threat-model.md:399` (§8 T1-4 row: "whether E9 enforces the token's resource
binding is an open question (OQ-1)"), `:1591` (§13 T1-4: "E9's resource binding stays
open (OQ-1)") — the list resolves OQ-1 in §14 and widens T1-15 but never touches T1-4's
two carried statements, so the model would simultaneously carry OQ-1 as resolved and
T1-4 as blocked on it. `docs/threat-model.md:472` (§8 T6-7: "The `^[a-z0-9-]+$` charset
enforced at startup on every mapping entry closes it") and `:1442-1445` (§9 T6-7
control 6, the same) — under the re-take the mapping may be unset and dynamic names are
checked by the request-time guard; the list amends T6-2's control 4 and RES-16 with the
startup/guard split but not T6-7's own text. Same class as R4-M1 (the R2-M1/R3-M1
lineage); remedy is the same — add the locations to §7/task 4.1. (A third, weaker
instance of the class: `threat-model.md:335`, §6 attacker 2's "walking statuses across
the mapping (T1-15)" — in dynamic mode the enumerable set is Core's registry, not the
mapping.)

**R4-M3 — The delta's authorization requirement retains a MUST and a scenario the
re-taken mechanism cannot enforce at that endpoint: "a resource naming no served
toolset … MUST be rejected as `invalid_target`" is undecidable at `/dial/authorize` in
dynamic mode.**
`specs/mcp-signin/spec.md:41-51` (the MODIFIED authorization requirement and its
retained "Unknown resource" scenario, amended mapped→served), against `tasks.md:48-60`
(task 1.2: the guard *replaces* the mapping lookup at `gateway/authorize.py`) and
`design.md` D7/D11 (no consult is designed at E3; the unknown-name backstop is the
flow's per-user settings read, which refuses with a plain-language page — its own
scenario at spec line 105-107 — not with `invalid_target` at the authorization
endpoint). Concrete failure: with no restriction configured, a phantom guard-passing
name's resource URI is shape-identical to a served toolset's (both
`{origin}/dial/{name}/mcp`), so the endpoint cannot distinguish them; a conformance row
written against the "Unknown resource" scenario either fails in dynamic mode or forces
an undisclosed Core consult onto E3 — a second amplification surface the SIA never
priced. In pinned mode the scenario holds (the restriction lookup decides it). Remedy:
re-word the requirement and scenario to the check the endpoint actually performs — a
resource that is not the resource URI of a name the request-time guard and the operator
restriction admit is `invalid_target` — and name the unknown-name backstop's home (the
flow's settings read) in the requirement text, or spec an E3 consult explicitly with
its own threat pricing.

### MINOR

**R4-m1 — The final at-a-glance counts are off by one in all three artifacts.** The
ruling era adds **six** new threat rows (T1-20, T1-21, T1-22, T5-7, T5-8, T4-9), not
five: `design.md:1725-1732` ("the threat tables gain nine rows — 64 threats … the five
ruling-era rows … (EP1 — 21)"), `tasks.md:592-596` ("gain nine rows — 64 threats, EP1
21"), `release-notes-draft.md:224` ("the counts land at 64 threats"). The custody-era
half is right (four rows; 59 threats; EP1 19, EP4 8 — 16+3, 7+1 check out); the ruling
era makes it ten rows, **65** threats, **EP1 22** (16+3+3), EP4 9, EP5 8. The same
count-slip class as round 3's m1 ("three bursts" naming four); here it lands in the
model's at-a-glance self-description, which task 4.1's verify clause makes
authoritative for the implementer. Remedy: six rows / ten total / 65 threats / EP1 22
in all three artifacts.

**R4-m2 — The consult's fail-closed enumeration misses non-5xx error statuses.**
`design.md` D8 ("transport failure, 5xx, non-JSON, oversize"), `tasks.md:87-95` (task
1.3: "anything else (transport, 5xx, non-JSON, oversize)"), and the delta's scenario
(`specs/mcp-signin/spec.md:33-35`: "Core is unreachable, answers a 5xx, or returns an
unusable body") all enumerate the failure set exhaustively-sounding but incompletely: a
**401** (the service key rejected or rotated Core-side — the one failure an operator
will actually hit), a 400, or a 3xx answer is in none of the three lists. The intended
behavior is obviously fail-closed, but the closed enumerations invite a literal
implementation that maps only the listed shapes. Remedy: "any answer other than
200/403/404 fails closed with the 503" in D8, task 1.3, and the scenario.

**R4-m3 — D12's "verified" member list is incomplete against the verified class.**
`design.md:713-716` (D12: "Core's answer distinguishes the levels by wire member
(`user_level_auth_status`, `global_auth_status` — verified against Core's
`ResourceAuthSettingsData`") — the class (`ResourceAuthSettingsData.java:28-30`) carries
a **third** status member, `appLevelAuthStatus` (`app_level_auth_status`), which the
design nowhere mentions. The flow's treatment of it is unspecified (presumably ignored
→ fails closed into the kind branch, which is safe, but it should be stated): an
operator who stores an APP_LEVEL credential for a non-OAUTH toolset gets the
impossible-branch refusal even though a level exists — correct or not, it is a behavior
the spec should name. Remedy: one sentence in D12/task 1.4 (the check reads the user
and global members only; an app-level status is not a sign-in for this flow).

**R4-m4 — Round 3's m2 remedy is only half-landed: the cap≥bound coupling sentence
never reached the delta spec.** R3-m2 asked for "one sentence in the delta spec's
custody requirement and in `.env.example`'s/gateway-configuration.md's bound
documentation"; the coupling invariant (cap ≥ bound + envelope expansion + JWT
overhead) is in `design.md` A5 and tasks 2.2/2.4 but absent from the delta's custody
requirement (`specs/mcp-signin/spec.md:305-343`) and its federation-requirement size
bound. The tasks carry the operator documentation, so the practical gap is the
normative home only — but the re-take claims the custody half untouched, and this is
the one round-3 remnant not landed where round 3 specified it. Remedy: one sentence in
the custody requirement (or the federation requirement beside the size bound).

**R4-m5 — The roadmap's P3 and C1.5 lines are now partially stale, and no task updates
them.** `docs/production-roadmap.md:35-40` (P3's accepts: "non-OAUTH and unknown names
fail closed as today" — under ruling 1 a non-OAuth toolset with a stored credential is
*served*, and the unknown name is refused at discovery, not "as today") and `:183-192`
(C1.5: "adds a new resource kind and a short-circuit branch to the flow" — the branch
machinery is now built by this change, as the proposal itself declares). The rulings
are the owner's and supersede the tracker's older acceptance phrasing, but the proposal
declares the C1.5 shrink only inside the change folder; nothing tasks the one-line
roadmap reconciliation, so the tracker drifts against the change that altered its
facts. Remedy: a sentence in task 1.5 (or the pause list) naming the two roadmap lines
to re-state.

---

## Verdicts on the eight attack points

1. **The consult's four Core facts — PASS, all four verified against the Core source,
   plus the two supporting facts.** (a) No unauthenticated Core route answers
   existence: `Proxy.authorizeRequest` (`Proxy.java:340-362`) 401s any credential-less
   request, the only credential-less exception being the MCP data-path GET/POST
   challenge (still 401, with `WWW-Authenticate`); the listing route
   (`ToolSetController.getToolSet`, `@ApiOperation path =
   "/openai/toolsets/{toolset_name}"`) sits behind that authorization. (b) The
   well-known route serves any well-formed id without a registry read:
   `Proxy.handleRequest` dispatches `isMcpResourceMetadataPath` to
   `WellKnownResourceMetadataController` **before** `authorizeRequest` (unauthenticated,
   in fact — stronger than the design states), and `WellKnownResourceMetadataService`
   builds the document from static `toolsets.security` settings with no registry
   lookup — a phantom gets a 200 (or 404 only when `authorizationServers` is
   unconfigured, i.e. the route disabled). (c) The status mapping:
   `ToolSetController.respondError` (`:172-183`) — `PermissionDeniedException` → 403,
   `ResourceNotFoundException` → 404 — and `DeploymentService.findDeployment`
   (`:63-69, :142`) throws Forbidden only for a deployment that exists but fails
   `hasAccess`, NotFound otherwise, so 200/403 prove existence and 404 is the phantom;
   `IllegalArgumentException` → 400 exists as a fourth shape (R4-m2's enumeration gap).
   (d) The wire members and vocabulary: `ResourceAuthSettingsData` carries
   `authentication_type` and the level statuses under snake-case naming;
   `ResourceAuthStatus` is SIGNED_IN/SIGNED_OUT/FAILED; `AuthenticationType` is
   OAUTH/API_KEY/NONE/DIAL_NATIVE; `ResourceAuthStatusEnricher.enrichToolSet` fills the
   per-caller statuses for toolsets, and for DIAL_NATIVE sets user-level status from
   the caller's offline credentials — the fact D11's C1.5-unification claim rests on.
   The key rides Core's `API-KEY` header (`Proxy.HEADER_API_KEY`/`extractApiKey`). The
   one incompleteness is `app_level_auth_status` (R4-m3) — a missing member in the
   design's list, not a wrong fact.
2. **The stage order as an authorization argument — PASS.** Traced end to end against
   the code's actual paths and the delta's scenarios: `_finish` (the only mint site for
   the harness code) is reachable from exactly two places — the identity-leg
   short-circuit and the upstream callback after a successful credential call. The
   short-circuit requires (a) a completed code exchange (`complete_identity_leg` — a
   live IdP authentication under the gateway's PKCE client; the code is single-use and
   the flow id unguessable), (b) the per-user settings read (the DIAL authorization
   check, 403-refused, inside `complete_identity_leg` before any branch), and (c) a
   positive SIGNED_IN at user or global level; absent/unreadable/FAILED falls through
   to the kind branch (the delta's fails-closed scenario), where OAUTH gets the consent
   leg and anything else the impossible-branch refusal. The token endpoint mints only
   from a valid PKCE-bound code or a valid refresh token. The forged-status path
   (DT-EP5-4) and the forged-consult path (DT-EP5-5) both yield a misleading token and
   401s on the data path, not access — the one-leg-deeper per-user read is a real
   structural backstop. The use-vs-establish rule is asserted by test in task 1.4
   (negative controls: no upstream authorize URL built on the short-circuit and refusal
   paths; no path reads or transits a stored credential). No mint path bypasses the
   identity leg, the authorization read, or the consent/signed-in disjunction.
3. **The use-vs-establish wording vs the main spec — PASS.** The main spec's
   "GLOBAL-level establishment refused" scenario (`openspec/specs/mcp-signin/spec.md:340-342`)
   is untouched by the delta (the credential-model invariants requirement is not in the
   MODIFIED list) and remains true: the credential call stays `credentialsLevel: USER`
   on every establishing path (`gateway/flow.py:280-287` today; asserted by test in
   task 1.4). The delta's federation requirement states the distinction explicitly and
   correctly ("The flow never establishes a credential at GLOBAL level … it never reads
   or transits any stored upstream credential on any path, the short-circuit included …
   a GLOBAL credential the short-circuit uses is one an operator configured — the flow
   uses it, it does not establish it"), and the global-credential scenario's "the flow
   establishes no credential itself" is the exact anti-blur wording. No delta text says
   the flow establishes, grants, or configures a global credential. The blur the
   objection exists to catch is absent — but its *model-side* homes are the ones
   R4-M1 catches.
4. **The D8 reversal's prices — PASS.** The amplification is priced first-class in
   DT-EP1-10's own row and eight-category grid, in the abuse-bounds requirement's new
   discovery scenario (over-limit refused *without* a consult), in G9, in T1-20, and in
   RES-24's register record. The "phantom traffic is NEW" framing is **accurate and
   verified**: pre-gateway, the phantom discovery fetch hit Core's well-known route —
   unauthenticated and registry-independent (verified, attack point 1b) — so the
   per-request *authenticated registry read* on attacker-chosen names is new traffic of
   a new kind, and the honest counter-point (the availability coupling *restores* the
   pre-gateway topology where discovery WAS Core) is stated rather than buried. OQ-I's
   analysis is falsifiable and its numbers check: a name-keyed existence cache is
   missed by a distinct-name flood by construction (nothing in the proposed cache shape
   — short TTL, keyed by name — changes that); 600/min global = 10/s one-to-one with
   admitted requests (`gateway_rate_global_per_minute: 600`); the concurrency bound
   follows the CIMD fetch pattern (`gateway_cimd_max_concurrent_fetches: 8` → the new
   `gateway_discovery_max_concurrent_consults`); each call bounded by the 30 s outbound
   timeout. Both staleness edges (add-refused-for-TTL, removed-served-for-TTL) are
   priced. The cache is rejected as default with reasons and parked with the numbers —
   the ruling slot is real, not decorative.
5. **Byte-identity of the retained rows and the migration notes' declared drops —
   PASS.** Every retained scenario was compared against the main spec: the mapping
   requirement's "Reserved name refused" and "Name outside the routed charset refused"
   byte-identical; the refresh requirement's non-sliding window, revoked, and expired
   scenarios byte-identical with exactly the three declared amendments (silent refresh,
   the `invalid_target` correction — verified against `gateway/token.py`'s behavior
   claim, the code grant's analogue at `:289-291` per task 2.6's cited lines, and the
   TTL re-derivation); the abuse-bounds requirement's four retained scenarios
   byte-identical with the min(flow TTL, own expiry) sentence **restored** (R3-m4
   landed) and the declared outbound-call additions; the status scenarios identical
   plus the declared boolean semantics and new global scenario; the federation,
   issued-tokens, and claim-copy retained scenarios identical. Both REMOVED
   requirements' migration notes declare exactly their drops (the "Non-OAuth mapping
   refused" scenario; the three amended refresh scenarios) and the replacements carry
   them. One undeclared-diff class found — not a byte diff but an enforceability break
   in the amended "Unknown resource" wording (R4-M3).
6. **The custody half untouched — PASS, with the verification's honest limit stated.**
   No VCS baseline exists for the change folder (it is untracked in git), so
   byte-level comparison against the round-3 landing is impossible by construction;
   the verification is therefore semantic plus spot-checks of round 3's own quotations,
   and it passes: every round-3 finding is verifiably landed (R3-M1's model homes —
   T1-17/18/19, T4-8, RES-22/23, M21, the TB4/§2/§7-EP4 locations, the mitigation
   count; R3-M2's 32-byte key refusal in design A3, task 2.2, and the delta's custody
   requirement; m1 "four bursts" in the release notes; m3's NIST 2^32 bound and the
   associated-data binding in A4; m4's restored sentence; m5's rotation-off pricing in
   A8 and task 2.4; m6's operator rows in task 2.4; m7's pending entries in the EP4 row
   summary), and the ruling-era additions are additive where they touch custody-era
   rows (the §7 bullets say "neither row's custody-era text is displaced" and the texts
   read that way: DT-EP1-4–9, DT-EP4-1, DT-EP5-1/2, G3–G8, tasks 2.x/3.1/3.3 carry no
   P3 content). The one remnant is R4-m4 (round 3's m2 spec sentence). The P3 half's
   SIA additions to shared rows (impact level's third secret, invariant rows 1/3/4/5)
   are the declared P3 re-take, not custody regressions.
7. **Edit-list completeness — FAIL in part (R4-M1, R4-M2).** The grep-sweep of the
   model against the re-take found four falsified locations outside the list (RES-9,
   T5-4's row/grid/disposition — the GLOBAL wording's actual homes; T1-4's row and
   disposition on OQ-1; T6-7's row and grid on the startup/guard split; §6 attacker
   2's "across the mapping" as a weaker fifth). Everything the list *does* name was
   checked entry-by-entry and is consistent: the ruling-era set (T1-20/21/22, T5-7/8,
   T4-9, RES-24, the service-key asset row, §7's EP1/EP5 descriptions, §1's P3
   sentences, the compromise-table extensions, M22/M23, invariant-3) and the custody-era
   set it inherits. The counts are the one arithmetic slip (R4-m1). This is the third
   round running for the class; the fix is mechanical (add the locations), and the
   artifacts' own closing rule ("any other model location whose current text this
   change falsifies is a defect in this list") already obligates it.
8. **The audit-vocabulary closure — PASS.** The new tokens (`non_oauth_toolset`,
   `unknown_toolset` — reused, the token the status endpoint already carries at
   `gateway/status.py:55`; `core_unavailable`; the guard's `reserved_toolset_name` /
   `invalid_toolset_name` / `restricted_toolset`; the refresh three) all reach the
   record through the existing discipline: at the token endpoint the closed
   `_REFUSAL_REASONS` table (`gateway/token.py:96-126`, one-directional, unmapped
   raises) is extended by keying on error code plus named refusal class with every
   token committed and no `flow_refused` bypass (task 1.2/2.3, with the mutual-
   distinguishability and `invalid_client`-never-session-ended negative rows); on the
   other surfaces the reasons are fixed strings at the call sites, the shape the
   `audit.py` docstring already pins. No Core error text reaches any record: today's
   `CoreError` messages are gateway-chosen (`core.py:169-190`), and the consult client
   is specified to keep that discipline ("the exception type, never a Core message" —
   task 1.3, and `ToolSetController.respondError`'s relayed messages like "Toolset is
   not found: …" are never surfaced). Never-cut 5 is not breached by any specified
   path.

## Method conformance, scope discipline, validation

- **SIA shape per `docs/security-analysis.md` §5 — PASS.** All eight sections in order;
  per-change delta shape correctly chosen (existing surfaces; the new secrets sit
  inside the process boundary the signing key already occupies, and the
  asset/compromise tables are updated — the "adds a surface" obligations that apply to
  new secret material are met through EP4's delta rows and §7's table updates); mis-use
  cases marked (DT-EP1-2, DT-EP1-7, DT-EP1-12, T1-22); the control-category order with
  threat-specific N/A reasoning throughout; G1–G10 with homes and owners; the strict
  gap list present with the ruling-era Core facts recorded as closed-by-verification
  (and my independent verification confirms them).
- **The invariant rows are honest — PASS.** Row 1's "strengthened in wording" is
  earned (the short-circuit reads a *status*, never a credential); row 3 states the
  delegation rather than minimizing it; row 4's claim that the per-user settings read
  runs on every path matches the code's actual ordering; row 5's M13-style amendment
  (plaintext never delivered, ciphertext by design) is the honest sentence.
- **Scope discipline (no C1.5 creep) — PASS.** The change builds the general rule
  (the kind branch, the signed-in check, the short-circuit) and states the C1.5
  unification; it does not build the apps resource surface, its routes, its discovery
  documents, or the router's apps MCP path, and D11's "what remains C1.5's" is the
  correct split. The DIAL_NATIVE kind appears only as one of Core's vocabulary values
  under the general rule. The roadmap's own stale lines are R4-m5, a documentation
  flag, not creep.
- **`openspec validate --strict` — green**, run this pass.

## Clean areas (one line each)

- The stage machine (D11/D12): kind-agnostic identity leg, authorization read before
  every branch, positive-answer short-circuit, impossible-branch refusal — coherent
  across design, delta spec, and the code's real paths, with the loop analysis honest
  (ends out-of-band, rate-bounded).
- The consult's design: the right route (the one `status_url` already reads), the right
  credential shape (SecretStr, placeholder-refused, minimal principal), the right
  403-omits-kind rule (per-caller visibility left to the per-user read).
- The status requirement's boolean re-derivation: `signed_in` as either level with the
  raw statuses alongside — matches `gateway/status.py`'s existing response shape and
  the harness's actual question.
- The guard requirement: one predicate, the router's own constants, the same response
  shapes per surface, fixed-vocabulary refusals — and the router needs no change
  (verified: its locations are generic and ordered as the design claims).
- The REMOVED+ADDED migrations: both reasons argue the right rule (a requirement whose
  first sentence no longer holds is worse than none), and both notes declare exactly
  their drops.
- The pushback record: both orchestrator objections are answered in the artifacts with
  verified facts and their own threat rows (DT-EP1-12, DT-EP1-10/RES-24), not buried.
- The release notes: the two rulings, the pushback trail, and the four-burst count
  (R3-m1 fixed) are all present and accurate except the counts slip (R4-m1).
- The `.env.example`/settings plan: the new slots follow the signing key's established
  placeholder-refusal pattern; the body-cap raise and its re-pricing are stated, not
  slipped in.

## What the owner pause must decide

- **OQ-I (new, this round's headline ruling slot)** — the discovery consult's cache:
  per-request as designed, or a short-TTL existence cache at production scale, with
  both staleness edges priced and the TTL a named deployment fact.
- **OQ-A / OQ-G / OQ-H** — as parked (design §8); OQ-B, OQ-C, OQ-E, OQ-F remain
  discharged/resolved-with-source, nothing new for the pause in them.
- **Pre-pause fixes to require landed** (authoring completeness, not rulings): R4-M1
  and R4-M2's model locations added to the §7/task-4.1 edit list (the GLOBAL
  wording's four homes, T1-4's two, T6-7's two, §6's one); R4-M3's authorization
  requirement re-wording; R4-m1's counts corrected in all three artifacts; R4-m2's
  fail-closed enumeration closed ("any answer other than 200/403/404"); R4-m3's
  app-level sentence; R4-m4's coupling sentence in the delta spec.
- **Carried from round 3** (its ruling slots, all landed as defaults in the artifacts):
  rotation-off's priced semantics; the associated-data binding / single-active-keyset
  commitment rationale; the hard-cut wave as the accepted rotation cost — confirm or
  overrule.
- **R4-m5** — who re-states the roadmap's P3-accepts and C1.5 lines now that this
  change (and the rulings) have altered their facts: this change's task 1.5, or the
  owner's own tracker pass.
- **Task 5.7 stands** — the `gateway/tokens.py` docstring correction has its task home
  and its pause assignment; nothing this round changes that.

## Bottom line

**LAND AFTER FINDINGS.** Land R4-M1/R4-M2 (the edit-list additions — the recurring
class, third round running, mechanical to fix), R4-M3 (the authorization requirement's
enforceability wording), and m1–m5 alongside, in the change artifacts before the owner
pause. Nothing above reopens a design decision: the stage order, the consult and its
credential, the use-vs-establish delegation, the D8 reversal with its prices, and the
untouched custody half all survive this round's falsification attempts — including the
four Core facts, every one of which I verified against the Core source rather than the
design's own record, and the phantom-traffic premise, which the Core source makes
*stronger* than the design states it (the pre-gateway well-known route was
unauthenticated as well as registry-independent). The findings' common root is narrower
than round 3's: the re-authoring pass landed every price and every scenario it looked
at, and left the model's own carry-overs — the rows that still speak the pre-ruling
vocabulary — outside the list one more time.
