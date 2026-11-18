# Tasks

## 1. Main-spec repair verification — the C2 archive-sync corruption (precondition for this change's own archive pass)

The C2 archive-sync commit welded the synced main spec's structure shut: requirement
headers sit mid-line at six sites (`openspec/specs/mcp-signin/spec.md:150` the
federation-flow header, `:370` the inbound-tokens header, `:372` the toolset-mapping
header, `:441` the refresh-claims header, `:443` the toolset-names header, and `:578` the
app-resources header — six headers welded into other requirements' bodies), a stale
pre-C2 "App resources" block survives at line ~632 (the "public PKCE client"/"three-shape"
wording C2 amended away), "Refresh re-reads current
claims from the identity provider" and "Toolset names are guarded at request time" each
appear twice, and two whole requirements are absent outright — "End-to-end acceptance
on a real harness gates completion" (pre-sync line 372) and "App MCP resources are
served through the apps front-door path" (pre-sync line 594) have zero occurrences in
the corrupted file, not welded, not duplicated: gone. Only 26 line-start requirement headers exist where the C2 sync was to land
31 (27 clean line-start headers in the pre-sync spec — verified — plus the C2 delta's 4
ADDED requirements). Root cause, per the C2 session: its sync script computed all 8
replacement spans against the original file but applied them to the mutated string
without recomputing offsets, so every replacement after the first cut at stale
positions.

**The repair EXISTS: C2's session owns it** — commit `f19dcfb` on branch
`fix/main-spec-c2-sync-repair`, reconstructed from the two clean sources (the pre-sync
parent `4519c93^` + the archived delta's blocks applied per-block by name), and
**independently verified by this session**: 31 line-start headers, zero mid-line
welds, zero duplicated requirement names, both lost requirements restored at line
start, the stale wordings appearing only inside declared-amendment records (which
legitimately quote the old spellings). That branch is parked for the owner's merge.
This group's remaining job is to make the repaired spec the base this change builds
on, and to keep the reconstruction recipe as the fallback should the merge stall.

- [x] 1.1 Rebase this branch onto the repaired spec — take the owner's merge of
  `fix/main-spec-c2-sync-repair` into master if it has landed (rebase onto master), or
  otherwise rebase onto `fix/main-spec-c2-sync-repair` itself; verify after the rebase
  that `openspec/specs/mcp-signin/spec.md` in this branch's working tree is the
  repaired content (`git merge-base` sanity + the assertion of task 1.2 passing
  against the working file)
- [x] 1.2 Machine-verify the repaired spec this branch builds on — run a
  header-inventory assertion over the working-tree
  `openspec/specs/mcp-signin/spec.md` (a Python one-liner or short script: the count of
  line-start `### Requirement:` headers equals 31 (27 pre-sync + the C2 delta's 4 ADDED)
  and the name set equals the set the two
  sources jointly define; no occurrence of `### Requirement:` anywhere but at line start;
  no duplicated header names; every requirement body non-empty with at least one
  `#### Scenario:` header; the stale wordings absent outside declared-amendment
  records), and run `openspec validate` — the change's two known ERRORs (the authreq
  and lifecycle blocks' parse artifacts of the corrupted on-disk spec, per
  `evidence/review-1-findings-and-dispositions.md`) must CLEAR, leaving the change
  validate-green — and record the assertion output, the grep results, and
  the validate result in `docs/evidence/c2p5/spec-repair.md` (the evidence folder this
  change's records live in, per house convention), alongside the fallback: should the
  repair branch or its merge stall, this group falls back to performing the
  reconstruction itself per the recipe above (the two authoritative sources, the
  per-block application, the same assertion), coordinated with the C2 session to
  avoid a double fix

## 2. Threat-model delta (the standing order — landed before implementation)

Design.md §7 names the docs work: a mitigation that exists only in prose is not landed,
so the model's rows move before the code that carries them. The conformance ledger
itself is group 6's artifact (D10) and lands with the re-judge, before the change closes
— everything else in §7 lands here.

- [x] 2.1 Update `docs/threat-model.md` per design.md §7 — T1-25's EP1 threat-table row
  (~line 658) gains its mitigation statement (the checkpoint's position: after the
  identity leg, before every mint, all three paths; the per-(subject, client) registry;
  first-attribution-only prompting) and its honest scope statement (the drive-by shape
  bounded; the on-path shape keeping RES-12/RES-1's existing acceptance with T1-1's
  strictly-cheaper-attack note; the mis-named-registration shape priced at DT-EP3-3's
  re-priced bound); the dispositions-table row (~line 1937) rewrites from deferred to
  mitigated (M31) and **corrects the cross-reference defect** — the standing control it
  cites is CIMD allowlist curation on M7's control set (~line 1881), not M24's apps
  front-door surface (~line 1897), and the corrected row names M7; M31 joins the grouped
  mitigation list as Placed — spec (the checkpoint requirement and its flow amendments) —
  with the registry's in-memory bound stated in its own record (single instance, restart
  forgets and re-prompts, hard cap with oldest-first eviction: the RES-15 acceptance
  class extended to one more in-memory store, named); the new threat rows land (the
  forged-approval row and the registry-flooding row in EP1's table; the decision-page
  injection, framed-approval, and false-attribution rows in EP3's table, the last marked
  mis-use); the folded layer's rows and records land with them (the
  cleartext-redirect-delivery row **DT-EP1-5** in EP1's table — M32 as its control, no
  new residual: the on-path class keeps RES-12's acceptance and the loopback exception
  keeps the fielded population's shape; the token-family-survival row **DT-EP1-6** —
  M33 as its control, its two partials as the stated bound; and **M32/M33 join the
  grouped mitigation list** as Placed — M32 the redirect-URI scheme admission rule,
  spec (the client-registration requirement's amendment, the startup-bounds family,
  the store-load validation), its four-site scope and the loopback exception stated in
  its record; M33 the redemption-replay revocation, spec (the issued-tokens
  requirement's code-clause amendment, where the delta lands it — the code clause the
  rule extends is that requirement's own), its two partials stated as the clause's
  bound and the rotation-chain memo recorded as the known extension, not built —
  their controls and disclosed bounds per design.md SIA §4/§5); the two
  ruling-driven docs records — RES-25's three-part record (task 6.3) and the DPoP
  record-wording (task 6.3, the D6 fix) — are group 6's landing tasks, so §7's
  coverage is complete across the groups; RES-11 re-prices one notch wider (display-level attribution becomes
  approval-harvesting on a decision page — the acceptance kept, the page's
  verifiable-facts rule named as the compensating control, the re-open trigger
  unchanged); and the bearer residual's record gains DPoP (RFC 9449) as its named
  structural remedy with the two-sided precondition (client side: the MCP authorization
  specification or a successor requiring or permitting it, and the flagship harnesses
  presenting proofs; resource-server side: Core validating DPoP-bound tokens, the E1
  line's natural scope) — and verify the register, the dispositions section, and the
  grouped mitigation list stay consistent with every row added or reworded; landed
  before group 3's code, per the standing order
- [x] 2.2 Re-read the updated threat model against the delta spec and confirm every
  gateway-owned mitigation design.md §6 names has a requirement in
  `openspec/changes/as-security-hardening/specs/mcp-signin/spec.md` — the checkpoint
  (item 1: the ADDED requirement plus the federation-flow and app-resource amendments),
  the header family with `form-action 'self'` and the decision page's no-auto-continue
  rule (item 2), the `state` rule with its bound (item 3), the CORS/back-channel posture
  with its pin (item 4), the `auth_time` registry addition (item 5), the conformance
  ledger's landing home (item 6), the redirect-URI scheme admission rule (item 7 —
  M32: the client-registration requirement's amendment plus the DCR-durability
  requirement's load-path clause, the fourth site), and the redemption-replay
  revocation (item 8 — M33: the issued-tokens requirement's code-clause amendment,
  where the delta lands it, its two partials asserted by the added scenario) — a
  missing requirement is a finding to fix in the
  delta, not in the model

## 3. The consent/attribution checkpoint (one lockstep change — no intermediate commit leaves the flow half-gated)

Design.md D1–D5. The six tasks implement in order and land as one lockstep (the migration
plan's rule): a checkpoint whose route is unrouted is a flow that dead-ends at the page,
so the group's code commits together once the routing probe battery is green.

- [x] 3.1 Implement the approved-client registry in `gateway/state.py`'s family (the
  flow store's own class pattern) — keyed (subject, client_id), written only by the
  approve action (one write path; no other caller reaches it), no TTL (an approval is
  durable for the process's life), a hard cap with oldest-first eviction (the cap a
  `gateway/settings.py` setting with an `.env.example` placeholder, the flow cap's naming
  discipline), entries as (subject, client id) pairs with no caller-supplied free text,
  and no persistence and no cookie — and verify new unit tests pass covering the delta's
  registry scenarios: an approved (subject, client) consulted and passing with no page;
  the approval covering the client across resources (a different resource's sign-in
  renders no decision page, the new resource's own DIAL authorization read still gating
  the flow); registry loss re-prompting, never bypassing (an emptied registry and a
  cap-evicted oldest entry both render the page again on the next sign-in); and no path
  other than the approve action creating an entry
- [x] 3.2 Implement the decision page as a new page class through the one shared builder
  (`html_page`, `gateway/pages.py`) — naming the resolved client (the registration's
  `client_name` where one exists, presented as a name, not a verified fact, with the
  client id beside it always), the addressed resource (the kind and the served name in
  the pages' plain vocabulary), and the registered `redirect_uri` the code will be
  delivered to; no scope list (the surface's `scope` parameter is accepted and dropped);
  script-free, two buttons (approve and deny) in a plain form posting the flow id and the
  chosen action and nothing else; no `meta refresh` and nothing that navigates itself;
  every interpolated value through the interstitial's existing escape (`gateway/flow.py`'s
  discipline — the client name registrant-supplied and the resource name
  caller-path-derived, both hostile text in an HTML context) — and make
  `form-action 'self'` a family-wide CSP directive (on the policy every page the builder
  stamps, never per-page, so no page class can drift off it), extending the
  header-assertion battery (`tests/conftest.py`'s CSP prefix and the per-page-class
  tests) to the decision page — and verify the delta's header-family scenarios pass: the
  decision page carries the full family with `form-action 'self'`, is script-free with no
  auto-continue, and escapes every interpolated value, and the retained interstitial and
  error-page scenarios carry the directive with the family
- [x] 3.3 Store the consent branch's continuation on the flow record — the built
  upstream authorization URL (`upstream_authorization`'s product from the
  `ToolsetLegResult`) joins the record beside `upstream_redirect_uri`'s existing
  discipline (`gateway/flow.py`), because the approve action continues the flow from the
  record alone; the identity-leg outcomes the action needs are record-resident already
  (the claim snapshot, the client facts, and the provider's session refresh token held
  until `_finish` moves it to the pending hand-off entry) — and verify by unit test that
  a flow parked at the decision point carries everything the approve action's
  continuation reads, with no identity token needed (the read paths may already have
  discarded it)
- [x] 3.4 Implement `POST /dial/consent` on the browser-facing surface (the routing
  table's own pattern, `gateway/federation.py`/`gateway/routes.py` as built) — reading
  exactly the flow id and the chosen action (every other fact re-derived from the
  record, never round-tripped through the browser), joining the shared limiter (the
  callbacks' own pattern), and answering no CORS headers (the posture rule's surface
  set): *approve* records the attribution in the registry keyed to the flow's own
  verified subject, audits `attribution_approved`, and continues the flow to the stage
  the decision point deferred (the mint via `_finish` for both short-circuits; the
  record's stored continuation for the consent branch, after which the display
  interstitial is served as today); *deny* consumes the flow (the
  `_consume_refused_flow` discipline: record destroyed, identity material dropped,
  plain-language page) and audits `attribution_refused`, redirecting no OAuth error to
  any target; the action is single-use-per-flow (a re-presented approve, or a POST
  against a flow already advanced, lands on the expired-flow page and allocates nothing —
  one approval cannot mint twice); an approve or deny naming no live flow lands on the
  expired-flow page and allocates nothing — and add the three fixed-vocabulary audit
  events to `gateway/audit.py`'s closed vocabulary (`attribution_required` when the page
  renders, `attribution_approved`/`attribution_refused` at the action), non-credential
  facts only (client id, client name, redirect URI, resource, kind) — and verify unit
  tests pass covering the checkpoint requirement's route scenarios: approve records the
  attribution and continues the flow; deny consumes the flow with no code issued; a
  replayed or foreign POST advances nothing and writes no registry entry; the action
  carries only the flow id and the decision
- [x] 3.5 Insert the checkpoint on all three mint paths in `gateway/federation.py` —
  the registry consulted after the identity leg and before every mint (each path ends
  in `_finish`, the one funnel every mint path passes through): the app kind's zero-page
  short-circuit and the toolset consent branch in `_run_identity_leg` (an unapproved
  (subject, client) renders the decision page where nothing
  rendered before; an approved one mints exactly as today); the toolset
  stored-credential short-circuit in `_toolset_after_read` (the same insertion before
  the mint itself); and the
  toolset consent branch (the checkpoint riding the interstitial's existing position,
  after the read and before the upstream redirect — on first attribution the
  interstitial's display-only auto-continue is replaced by the decision page for that
  one presentation, and once the client is approved the flow keeps the display
  interstitial verbatim), with `attribution_required` audited wherever the page renders —
  and verify the flow tests pass for the delta's amended and new scenarios: the retained
  short-circuit scenarios with the approved-client condition in their WHEN ("Already
  signed in short-circuits the consent", "A global credential serves every user without
  consent", "App sign-in completes with no consent and no credential call", "Repeat app
  sign-in is silent"); the new first-attribution scenarios on all three paths (the
  stored-credential short-circuit, the consent branch's one-time interstitial
  replacement with every later attribution serving the display interstitial verbatim,
  the app kind's zero-page); and the checkpoint requirement's no-bypass scenario (a
  configured or pre-registered client id earns no skip — the surface has no client
  authentication to key an auto-trust on)
- [x] 3.6 Add the `consent` segment to the router's AS-surface alternation
  (`router/nginx.conf`'s `/dial/` location regex gains `consent`) with the routing probe
  battery's new rows (`scripts/probe_routing.py`: the consent route reachable through
  the front door, the probe's alternation expectations updated) — one lockstep with
  3.1–3.5, the same locked-routing discipline the C2 change's callback rotation used; a
  half-routed deployment fails the probe, not a user — and verify the probe battery
  passes against a composed stack before the lockstep commits

## 4. The stated rules and pins (the `state` bound, the claim hygiene, the CORS posture)

Design.md D7's landed hygiene rule, D8, and D9: statements-and-pins on existing surfaces.
No behavior change backs the CORS statement — the code already is the posture; the change
is the rule and its machine-checkable pin.

- [x] 4.1 Implement the `state` rule's bound in `gateway/authorize.py` — a `state` over
  2048 bytes refused as `invalid_request` with the fixed-vocabulary reason
  `oversized_state`, on the flow-record allocation path, before the record exists, the
  refusal joining the pre-allocation refusals' audited enumeration (`gateway/audit.py`,
  the audit record naming the class, never the value); the tolerated-absent and
  echoed-unchanged-when-present behavior is today's and becomes the stated rule — and
  verify unit tests pass covering the delta's three scenarios: an absent `state`
  tolerated with the flow allocated exactly as a state-carrying one's and nothing echoed
  on the final redirect; a carried `state` stored on the record at allocation and echoed
  back unchanged (never modified, filtered, or extended); and an oversized `state`
  refused with no flow record allocated and one audit record carrying `oversized_state`
- [x] 4.2 Join `auth_time` to `REGISTRY_CLAIMS` in `gateway/tokens.py` (beside `acr`) —
  a provider that mints its authentication-time claim into its access token must not
  have it copied verbatim into a gateway token, where it would state the provider's
  authentication event as a fact of the gateway's own token, the same false-claim class
  `acr`'s strip exists for; the mint's recency facts stay its own `iat`/`exp` — and
  verify the copied-claims test battery extends with the delta's scenario: a provider
  token carrying `auth_time` mints a gateway token carrying none of it, at both claim
  source sites (the code exchange at issuance and the refresh grant's fresh token)
- [x] 4.3 Pin the CORS/back-channel posture in the test battery — a test asserting that
  no response from any AS-surface endpoint (`/dial/authorize`, the callbacks, the
  consent route, `/dial/token`, `/dial/revoke`, the discovery documents, the
  registration endpoint) carries any `Access-Control-*` header, and that an `OPTIONS`
  preflight against `/dial/token` receives the framework's 405 with no preflight
  handling — joining the header-assertion family's discipline, so one future
  `add_middleware(CORSMiddleware)` line cannot silently open the surface — and verify
  the delta's abuse-requirement scenario passes ("No CORS headers on any AS-surface
  response")
- [x] 4.4 State the posture and the checkpoint's operator facts in
  `docs/gateway-configuration.md` — the back-channel-only paragraph (no CORS headers on
  any AS-surface endpoint, no preflight handling, a browser frontend not a supported
  client shape: the clients are harness processes exchanging codes and tokens on their
  own loopback redirects and back channels — an operator integrating a web frontend
  finds the refusal stated where they look, not discovered as a bug), and the
  checkpoint's operator notes (the first-attribution decision page and what it names;
  the in-memory registry's semantics — a restart re-prompts every user once per client,
  by design and fail-safe; no operator bypass exists for configured or pre-registered
  client ids, the honest zero-page path being the user's own one approval; the CIMD
  allowlist remaining the naming control it always was, the checkpoint being the
  attribution control) — and verify the documented posture matches the pinned test's
  assertions by cross-reading them in one pass

## 5. The owner-accepted re-judge findings (B-1+B-3 the admission rule; B-2 the replay revocation; B-5 the `iss` advertisement)

The owner's ruling on the re-judge report (2026-11-07): B-1+B-3 ACCEPTED — the
redirect-URI scheme admission rule, `https` or loopback-`http` only, at all four
admission sites; B-2 ACCEPTED — revoke-on-double-redemption, riding the existing
replay memo and the existing denylist; B-5 ACCEPTED — the `authorization_response_iss_parameter_supported`
advertisement member, a pure trueness fix; B-4 DEFERRED with reasoning (group 6 lands
its residual record — no behavior change). Design.md's decisions for the accepted
findings (D11–D14, landing in parallel with this update) carry the mechanisms; the
delta's requirements for them carry the rules.

- [x] 5.1 Implement the redirect-URI scheme admission rule at all four sites — a
  registered redirect URI MUST be `https` or a loopback `http` URI (the RFC 8252 §7.3
  shape `_loopback_target` already knows, `gateway/cimd.py`): the DCR body check
  (`gateway/routes.py`'s `_redirect_uris_refusal` gains the scheme refusal clause),
  the CIMD document's `redirect_uris` validation (`gateway/cimd.py`), a startup
  refusal for pre-registered `redirect_uris` (`gateway/settings.py`, the settings
  validators' own pattern, naming the offending entry), and load-time validation of
  the durable DCR store (`gateway/store.py`'s load path) — so records admitted before
  the rule landed, or planted inside the host/volume boundary per the store's own
  threat row, cannot keep a non-conforming URI usable after the rule lands (the
  pre-rule-records boundary stated per the delta's scope sentence, DCR's default-off
  bound named) — and verify unit tests pass per site: a non-loopback plain-`http` URI
  refused at each of the four; a loopback `http` URI admitted at each; an `https` URI
  admitted; the load-path refusal naming the store's offending record; and a
  conforming fielded harness's loopback registration passing untouched (no UX change
  for the conforming population)
- [x] 5.2 Implement revoke-on-double-redemption on the code grant's replay path — the
  existing replay memo (`gateway/state.py`'s replay-cache entry, the store family the
  custody hand-off already keys by code id) carries the minted refresh token's `jti`
  from the first redemption, and the detected replay's refusal path
  (`gateway/token.py`'s replay refusal) makes one call to the existing `TokenDenylist`
  — no new surface, route, or page — and verify unit tests pass as one
  replay-revokes-family test, not three disconnected asserts: the replayed code's
  refusal denylists the refresh token its first redemption minted (the next
  presentation of that `jti` refused with `invalid_grant`), and the two disclosed
  partials the spec clause states are pinned as the bound the clause actually buys —
  the already-minted access token stays unrevocable by design (accepted until its own
  short TTL, the standing bound), and a refresh token that already rotated before the
  replay was detected survives (the successor `jti` never denylisted, its refresh
  still granted) — so the battery asserts the bound rather than implying a wider one
- [x] 5.3 Advertise the `iss` support the authorize flow already delivers (B-5, the
  report's row for the MCP `2026-07-28` revision's Authorization Response Validation
  MUST: an AS that includes the `iss` parameter MUST advertise it via
  `authorization_response_iss_parameter_supported`) — the AS metadata document's fixed
  payload (`gateway/discovery.py`) gains `"authorization_response_iss_parameter_supported":
  true`, the discovery requirement's advertisement clause gains the member (the
  requirement already enumerates the advertised members; this joins them — the delta's
  requirement for the finding lands in parallel, D14), and one metadata-assertion test
  verifies the member's presence and its `true` value — and verify no behavior change
  anywhere else: the emission itself already rides every authorization response,
  success and redirected error alike, and the member only states it

## 6. The RFC 9700 re-judge's landing (the walk is done; this group lands its record)

The walk no longer needs carrying: 98 rows walked, every verdict grounded in a named
code fact, spec requirement, or model row (`evidence/rfc9700-rejudge-report.md`), the
report independently falsified and held (`evidence/rejudge-report-review.md` — both
accepted findings survived, its presentation findings corrected in the carrying, not
copied), and the owner's ruling (2026-11-07) resolved the five undecided rows (B-1+B-3,
B-2, and B-5 → group 5's implementation; B-4 → the residual record below). The method
and the four-value verdict vocabulary are D10's; this group lands what the walk produced
into the standing record.

- [x] 6.1 Land the conformance-ledger section in `docs/threat-model.md` FROM THE REPORT
  — one row per recommendation, its verdict in the four-value vocabulary, and where the
  satisfaction or the price lives (the M-number, the RES-number, the delta-spec
  requirement, or the roadmap home), the report's Part 6 partition the ledger's
  structure, carried as disjoint buckets whose counts sum (the falsification review's
  finding-1 direction, applied in the carrying), and the owner's ruling resolving the
  five previously-undecided rows into their buckets (B-1+B-3, B-2, and B-5 → landed by
  this change; B-4 → deferred with its residual); cross-check that every row verdicted
  "landed by this change" names a delta requirement that exists and an implementation
  task that landed (groups 3–5); and verify, as before, the ledger is consistent with
  the threat-model delta group 2 landed — T1-25's flip to mitigated with its corrected
  M7 cross-reference (the standing control is the CIMD allowlist on M7's control set,
  not M24's apps surface), the M32/M33 Placed records with their DT-EP1-5/DT-EP1-6
  rows, RES-11's re-price, the DPoP precondition record, and RES-25's record (task
  6.3's landing) — and that the roadmap's closing re-judge (its D3 stage) will find
  every residual priced rather than forgotten
- [x] 6.2 Verify the report's borderline rows against the built code — the rows the
  falsification review flagged or that walked close to a boundary: the
  current-revision (`2026-07-28`) display and validation statements (the
  redirect-hostname display MUST, discharged by the decision page's naming of the
  redirect destination — said in the ledger, not left implicit; the localhost-warning
  SHOULD, B-4's row; the `iss`-advertisement MUST, B-5's row), and the
  revision-choice deltas the re-walked Part 4 scores against the current text (the
  DCR row's deprecation posture — MAY, deprecated, matching the gateway's default-off
  CIMD-first shape; the CIMD row scored member-by-member against the gateway's built
  `client_id_metadata_document_supported` surface) — each re-derived from the code and
  the delta as built, so the ledger's rows are grounded in what shipped rather than
  what the report read; any row the verification moves joins the same discipline,
  dispositioned, never silently dropped
- [x] 6.3 Land the B-4 deferral's residual record and the D6 wording fix in
  `docs/threat-model.md` — B-4: **RES-25** lands, the localhost-warning deferral's
  disclosed residual with its three-part record per design.md §7 (the accepting
  condition: the attack shape it mitigates requires code execution on the victim's
  host — priced by the attacker model's classes 3/4, T1-3's stolen-token pricing, and
  RES-21 part i's machine-control statement, where the attacker holds
  strictly cheaper attacks — the grounding rows per design.md D13's record (which
  also corrects the earlier draft's RES-23 attribution, a record no local-compromise
  acceptance ever existed on); the
  compensating bound: the checkpoint's first-attribution display of the full
  `redirect_uri`, port included, which also discharges the current revision's
  redirect-hostname-display MUST; the re-open trigger: a client population where
  loopback is anomalous), no behavior change anywhere; D6: the DPoP deferral's
  record carries the current ecosystem state the walk's re-verification found (the
  opt-in client-side RFC 9449 implementation that now exists; the specification's
  Bearer mandate and Core's bearer-style validation unchanged on the decisive
  resource-server ground) — the verdict untouched, the record's wording current

## 7. Live acceptance on the local compose stack (design.md D5's rows)

Both field-proven harness shapes on the same compose stack C2's acceptance used, the
stack brought up by the compose-boot gate's method (the main checkout's `.env` copied
into the worktree; Docker in WSL2 driven through the PowerShell tool). Evidence under
`docs/evidence/c2p5/` per house convention. The rows are owner-dependent only where a
real account is needed; the compose-stack harnesses run them directly.

- [x] 7.1 The CLI harness shape (CIMD registration) — a first sign-in renders the
  decision page naming the resolved client, the resource, and the redirect destination,
  and the approve click completes the flow to the harness (the toolset consent branch
  completing through the upstream; the stored-credential short-circuit minting
  directly); an immediately repeated sign-in for the same (user, client) completes with
  zero pages on the short-circuit path — the zero-click property the harness UX depends
  on, proven rather than asserted — and record the run in `docs/evidence/c2p5/` (what
  the page showed, the sequence of the browser's responses, the harness's completion)
- [x] 7.2 The IDE harness shape (DCR registration) and the app kind — the same
  first-attribution and repeat rows through the DCR-registered client; the app kind's
  zero-page short-circuit gated: a first app sign-in renders the decision page where
  nothing rendered before (no code minted, no credential call, no upstream round-trip),
  the approve click mints directly, and a repeat app sign-in is silent; and the deny row
  on either shape — a denied flow consumes with the refusal page and no code issued, and
  the harness's re-run after denial renders the page again (the registry was not
  written) — and record the runs in the evidence folder
- [x] 7.3 The audit-trail sequence check — the trail carries the new fixed-vocabulary
  events in sequence (`attribution_required` → `attribution_approved`/
  `attribution_refused` → the existing `code_issued`/`credential_free_short_circuit`
  records) for the runs of 7.1 and 7.2, read from the audit output the stack produced —
  and record the verification in the evidence folder; these records are the live
  evidence the conformance walk (group 6) cites for the checkpoint's live rows

## 8. Gates (integration checks only — the order PROCESS.md fixes)

- [x] 8.1 Static tier green with findings triaged — `ruff check`; `ruff format --check`
  via the verified LF-stdin workaround (`sed 's/\r$//' <file> | ruff format --check
  --stdin-filename <file> -` per file — this checkout's core.autocrlf makes a tree-wide
  `ruff format --check` red); `mypy` if configured; `bandit`; `pip-audit` (BLOCKING — a
  reachable vulnerability, transitive included, blocks; the remedy is a dependency bump,
  and a stale scanner is not a green gate); Trivy via WSL (`wsl -e trivy
  --skip-db-update` when the DB is stale); and the publication leak check
  `python scripts/check_publication_leaks.py` (exit 0; no new internal hostnames,
  personal paths, or real issuer/tenant/org values in tracked files, docs, evidence, or
  commit messages) — and record the run in the change's evidence folder
- [x] 8.2 The compose-boot gate and the full unit suite — copy the main checkout's
  `.env` into the worktree (it is gitignored and absent here), bring the stack up with
  WSL2 Docker driven through the PowerShell tool (`wsl -e docker …`), and pass a health
  probe for every service; run `pytest -q` green — and record both outcomes in the
  evidence folder
- [x] 8.3 The conformance rows — walk every scenario of the delta spec
  (`openspec/changes/as-security-hardening/specs/mcp-signin/spec.md`, each scenario a
  conformance row) against the test that covers it and the evidence that proves it,
  recording the row-by-row outcome in the evidence folder; a row with neither is a
  finding, not a waivable gap
- [x] 8.4 The security review gate — an independent reviewer subagent (different from
  the implementer) reviews the diff against this change's SIA and the updated threat
  model, at the depth the SIA's Medium impact level sets: a full-depth review of the new
  route, the decision page, and the registry mechanics, with the falsification pass
  focused on the claim that the checkpoint's own surfaces (the forged-approval,
  registry-flooding, page-injection, framed-approval, and false-attribution threats)
  are bounded as designed — and, per the SIA's post-ruling re-check, on the two folded
  mitigations' rows (DT-EP1-5 the cleartext-redirect-delivery threat and DT-EP1-6 the
  token-family-survival threat): the admission rule's refusal behavior on the three
  live admission paths and the store's load path, and the replay revocation's two
  disclosed partials held as the bound the clause buys — and confirming the SIA's invariant rulings hold on the diff (no
  never-cut invariant amended: the upstream token and the upstream PKCE verifier never
  leave Core, per-user isolation, DIAL authorization on every call, no credential in
  logs, argv, or error messages) — running before the general review gate, with findings
  and dispositions landed in the evidence folder
- [x] 8.5 The review gate — an independent reviewer subagent reviews the diff (code,
  tests, specs, docs, evidence) for correctness and coherence with the design's
  decisions D1–D14, findings and dispositions landed in the evidence folder — and on
  green, close `docs/production-roadmap.md`'s C2.5 row as this change's acceptance rows
  pass
