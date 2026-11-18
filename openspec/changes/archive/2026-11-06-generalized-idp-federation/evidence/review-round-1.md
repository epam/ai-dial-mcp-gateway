# Independent review — round 1 (planning artifacts, before the owner pause)

Reviewer: the PROCESS.md step-3b independent reviewer (opus subagent, not the author).
Method: falsification — every falsifiable claim in the package was checked against the
code it cites, the specs it amends, the method documents it must conform to, and (for
the load-bearing Microsoft provider facts) the live public documentation. No code was
touched; nothing was fixed here.

Inputs read in full: the change folder (proposal, design incl. the SIA, delta spec,
tasks, release-notes draft); `openspec/specs/mcp-signin/spec.md`; `CLAUDE.md`,
`PROCESS.md`, `ROADMAP.md` (never-cut list); `docs/production-roadmap.md` (§"C2 = P4
alone", C1/C1.5 sections); `docs/security-analysis.md`; `docs/threat-model.md`; the
archived C1 change (2026-11-03-dynamic-toolsets-and-fresh-claims, design.md's OQ-F and
provider-agnosticism record); `gateway/idp.py`, `gateway/federation.py`,
`gateway/flow.py`, `gateway/settings.py`, `gateway/tokens.py`, `gateway/custody.py`,
`gateway/token.py` (refresh leg), `gateway/discovery.py`, `gateway/app.py`,
`router/nginx.conf`, `.env.example`, `docker-compose.yml`, and the KEYCLOAK-vocabulary
grep across the tree. A programmatic unified diff of every MODIFIED requirement
(delta vs main spec) was run to catch undeclared drift. Microsoft's public docs
(`learn.microsoft.com/.../active-directory-b2c/tokens-overview` and `.../openid-connect`)
were fetched live to check the B2C facts D1/D3/D6/D9 rest on; the retired fabrikam
sample tenant's discovery endpoint was probed and 404s (no live B2C tenant exists to
probe — consistent with the change's own owner-dependent-live-run framing).

## Verdict

The package is strong and its central claims held under adversarial checking: the
outcome matches the roadmap's C2 fix without re-designing what C1 landed (the
refresh-grant fold is real in the code the design cites); the delta operations are
well-formed with only declared changes (verified by diff, not by reading); the main
spec genuinely carries no other Keycloak/realm/internal-base statement to amend; the
never-cut-2 boundary analysis is correct against the code; the SIA follows the standing
method's structure exactly, and its EP5 threat tables cover the classes the review was
asked to probe. The findings below are completeness and precision defects, not
mechanism defects: three medium (the threat-model delta understates its own rewording
scope; the compromise-point tables — required by the method for exactly this change's
shape — are not updated; and the classic-B2C per-policy issuer chain rests on two
provider facts the public docs do not actually state, which the design presents as
verified and which are absent from the live-run verification list) and five minor. F1–F3
should be dispositioned before the owner pause; none of them requires re-opening D1–D10's
mechanism choices.

## Findings

### F1 — the threat-model delta's provider-neutral rewording scope is understated; mechanism-level Keycloak spellings survive task 1.1 as written

- **Severity:** medium
- **Evidence:** design.md §7 and tasks.md 1.1 enumerate the entries to reword: EP5's
  title/framing, TB3/TB7, the four new EP5 rows, the EP4 row + A18, A2/A8, the attacker
  inventory, A12, RES-19. But `docs/threat-model.md` carries Keycloak vocabulary at the
  *mechanism* level in entries outside that list: A5 (line 429, "Keycloak code, upstream
  code, gateway code"), the EP3 callback-URL row (line 610, "the E6/E7 callback URLs
  carry the Keycloak code"), T3-3's mitigation prose (line 1150, "the gateway's for the
  Keycloak leg"), T5-2's mitigation prose (lines 1417–1427, "verifying against
  Keycloak's published keys", "the Keycloak legs"), and M2 in the grouped mitigation
  list (line 1793, "three independent S256 pairs (harness↔gateway, gateway↔Keycloak,
  Core↔upstream)"). After the change, the code has no Keycloak-spelled leg, so these
  rows describe the mechanism in a vocabulary the system no longer has — the exact
  drift the rename exists to remove. (Distinct from these, the model's §1 "as it
  stands" description of the *local compose deployment* — lines 54–63, 306–310 — stays
  legitimately Keycloak, per D8: the local dev shape remains a Keycloak deployment.)
- **Disposition requested:** task 1.1 (and design.md §7) gains the scoping rule —
  mechanism-level spellings go provider-neutral (A5, the EP3 callback row, T3-3/T5-2
  prose, M2 at minimum; a grep of the model after the edit is the check), while
  local-deployment facts keep the Keycloak name with the two-leg-shape note §7 already
  carries — or the residual spellings are dispositioned on record as deliberate.

### F2 — the compromise-point tables are not updated, though the method requires it for exactly this change's shape

- **Severity:** medium
- **Evidence:** `docs/security-analysis.md` §4 ("A change that adds a surface" — the
  section that names C2's shape as its example) requires that "where a trust boundary
  or credential changes, the asset/footprint **and compromise-point tables** are
  updated with it." The change adds both: an external-internet provider shape (a new
  compromisable component beyond the compose network) and the client secret as
  load-bearing credential material. design.md §7 updates the asset table (A18, A2/A8,
  A12) and the entry-point/threat rows, but names no change to `docs/threat-model.md`
  §10 (compromise points): the "Keycloak" component row (line 1746, blast radius
  "Unchanged") is wrong vocabulary post-generalization, and no row prices a compromised
  *external* provider — a party that mints tokens under the configured issuer that the
  gateway's exact pin then accepts (the TB7 trust restated for the internet shape, the
  TB3-peer gain of T5-2 relocated beyond the compose network). tasks.md 1.1 mirrors §7
  and so omits §10 too.
- **Disposition requested:** add the compromise-point delta to design.md §7 and task
  1.1: reword the Keycloak component row to the two IdP shapes, and add the
  external-provider compromise row (gain: any-`sub` token under the pinned issuer the
  gateway copies; bound: the provider is the trust anchor, same as TB7 today;
  distinguishable in no way by the gateway — an accepted trust, stated as such).

### F3 — the classic-B2C per-policy issuer chain rests on two provider facts the public docs do not state, presented as verified and absent from the live-run verification list

- **Severity:** medium (blocking for the classic-B2C-with-tfp configuration; not for
  the mechanism)
- **Evidence:** design.md Context/D1/D3/D6 present these as "verified against
  Microsoft's public documentation this pass": (a) the discovery document is served at
  the **tfp-issuer-appended** path — D1 fetches `{issuer}/.well-known/openid-configuration`
  with the issuer `https://<domain>/tfp/{tenant GUID}/{policy}/v2.0/`, but the docs'
  metadata-URL spelling is `https://<tenant>.b2clogin.com/<tenant>.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration`
  (openid-connect page, fetched live this pass) — a different path shape; whether
  b2clogin also serves the well-known document under the `/tfp/…` path is not stated
  anywhere in the docs; (b) the discovery document's **`issuer` member** equals the tfp
  issuer — D3's first control refuses the document whole unless it does, and the docs
  never state the metadata document's issuer value. What the docs *do* state
  (tokens-overview, fetched live): the tfp issuer is a **per-policy token-compatibility
  setting** ("Issuer (iss) claim"; default is the tenant-wide
  `https://<domain>/{B2C tenant GUID}/v2.0/`; the tfp value is what makes B2C
  "compliant with the OpenID Connect Discovery 1.0 spec") — i.e. the tfp form is
  **opt-in per policy, off by default**. Two consequences: (i) task 5.1's operator
  guidance and task 7.1's live-run fact list omit the prerequisite that the policy's
  "Issuer (iss) claim" must be set to the policy-specific value — a tenant on the
  default setting fails every sign-in at issuer verification, and a from-docs operator
  cannot diagnose that from anything this change ships; (ii) D6's and DT-EP5-5's
  "refused **by construction**" is provider-configuration-dependent, not by
  construction: under the default tenant-wide issuer, sibling policies' tokens share
  one `iss`, and the per-policy pin cannot refuse them (the delta scenario stays true —
  the gateway refuses any non-configured issuer — but the security claim that a
  sibling policy's token *arrives with a different issuer* does not hold in that
  configuration). D9's "two provider facts the live run must verify" and OQ-A/OQ-B do
  not cover either fact. An attempt to probe a live B2C discovery document this pass
  failed (the docs' fabrikam sample tenant is retired — 404), so neither fact is
  empirically settled here either.
- **Disposition requested:** add the two facts to D9's live-run list (and OQ-A):
  "b2clogin serves the well-known document at the tfp-issuer-appended path" and "the
  policy's discovery document's `issuer` member equals the tfp issuer (with the policy's
  'Issuer (iss) claim' token-compatibility property set to the policy-specific value)";
  task 5.1's classic-B2C profile gains that property as a stated configuration
  prerequisite; and DT-EP5-5's "refused by construction" gains the condition (the
  per-policy issuer configuration) or is re-worded to what is by construction (the
  exact-string pin). Alternatively, disposition with reasoning if the author has a
  source for (a)/(b) the review could not find.

### F4 — the first MODIFIED requirement silently drops the main spec's existing scenario-amendment record

- **Severity:** minor
- **Evidence:** programmatic diff of the delta against the main spec (run this pass):
  the MODIFIED "Authorization requests require a valid resource and allocate protected
  flow state" replaces the main spec's standing note "*Scenario amendments, declared:*
  three retained scenarios are re-worded by this change…" (main spec line 130, the
  apps-change record) with its own new note, without declaring the removal — while the
  federation-flow MODIFIED handles the same situation explicitly ("the retained
  scenario-amendment record below stays part of the requirement's text as it stands in
  the main spec", delta spec line 41). On archive/sync the apps-change record is lost
  from the first requirement's text and survives in the second's — inconsistent, and an
  undeclared deletion of spec text.
- **Disposition requested:** either retain the prior record in the MODIFIED text and
  declare the retention (the federation-flow requirement's pattern), or declare its
  removal in the amendment note with a reason.

### F5 — surfaces that spell the old vocabulary are absent from the impact list and from every task's file list; the drift grep's scope misses two of them

- **Severity:** minor
- **Evidence:** `gateway/app.py:75` (comment "Reachability of Core or Keycloak is
  measured by the flow paths") — in gateway/ but not in task 2.5's file list; the
  2.5 grep would catch it, so the gate holds, but the list under-states the work.
  `pyproject.toml:29` (comment "Core, Keycloak, or upstream MCP server") and
  `docs/routing.md:223` ("the gateway's Keycloak client") are outside the 2.5 grep's
  scope (`gateway/ tests/ scripts/probe_*.py`) and outside tasks 5.1/5.2's doc lists —
  nothing in the package would catch them. (`docs/HANDOFF.md`,
  `docs/demo-slide.html`, `docs/hosting-options.html`, and `docs/background/*` carry
  the old name too, but are PoC-era/historical records — plausibly out of scope, which
  is itself a scoping statement the tasks should make once.) Also noted: the roadmap's
  C2 line says "six test files"; the repo has eight, and the proposal/design's "eight"
  is the verified current count — the roadmap figure is stale, not the change's defect.
- **Disposition requested:** add app.py and pyproject.toml to task 2.5's list (or state
  that comments in non-gateway-surface files are deliberately kept), decide
  routing.md's disposition explicitly, and state the historical-docs exclusion once.

### F6 — the fate of the Keycloak-shaped defaults under the rename is undecided anywhere in the package

- **Severity:** minor
- **Evidence:** `gateway/settings.py:225` (`keycloak_issuer: str =
  "https://keycloak:8443/realms/dial"`) and `docker-compose.yml:141`
  (`KEYCLOAK_ISSUER: ${KEYCLOAK_ISSUER:-https://keycloak:8443/realms/dial}`) carry the
  local instance's issuer as a *default value*; `docker-compose.yml:142` hardcodes
  `KEYCLOAK_INTERNAL_BASE_URL: http://keycloak:8900` (no `${VAR:-}` indirection at all,
  so "optional, unset by default" for `IDP_BACKCHANNEL_BASE_URL` cannot be what compose
  ships). Tasks 2.1/2.3 rename the settings but no decision (D2, D8, or the migration
  plan) says whether `idp_issuer` keeps the Keycloak-realm-shaped default. D8's own
  honesty argument cuts both ways: a provider-neutral `IDP_ISSUER` whose default is a
  Keycloak realm path advertises a specificity the setting no longer has, and D0b's
  cleanup list (roadmap §D0b) names exactly these default-value exposures — the rename
  touches the same three files without deciding their disposition.
- **Disposition requested:** one sentence in D2 or D8: keep the local-profile default
  (documented as the compose profile's value) or drop to no-default-required (the
  `idp_sso_session_max_seconds` pattern), and say what compose passes for the
  back-channel base in the local profile.

### F7 — the confidential-client requirement does not state its converse: whether a configured secret is presented in the default PKCE mode

- **Severity:** minor
- **Evidence:** delta spec's no-PKCE requirement (lines 241–259) pins the no-PKCE
  direction ("in that mode … the exchange and the refresh grant MUST authenticate the
  client with the configured client secret") but no scenario or clause pins the
  converse; task 4.2 carries it ("the client secret presented on the exchange and the
  refresh grant **(and only then: the default mode never sends it)**"). Today's code
  sends the secret opportunistically whenever it is set, PKCE or not
  (`gateway/idp.py:318-320, 373-375`), so the change *removes* existing behavior — and
  a from-spec reimplementation that keeps the opportunistic send satisfies every
  scenario in the delta. The behavior is task-carried but not spec-carried.
- **Disposition requested:** one clause in the confidential-client requirement (or a
  fourth scenario): in the default PKCE mode the client secret is not presented on any
  leg.

### F8 — the proposal's capabilities summary undercounts the delta's amendments (four named, five modified)

- **Severity:** minor
- **Evidence:** proposal.md's "Modified Capabilities" bullet names "the flow, app-flow,
  refresh, and token-verification requirements"; the delta modifies five — the
  authorization-requests requirement's "Valid request allocates a flow" scenario is
  also re-worded ("the gateway's public PKCE client" → "the gateway's identity-provider
  client", delta spec lines 9, 21). The delta is coherent; the proposal's summary is
  not complete against it.
- **Disposition requested:** add the authorization-requests requirement (its one
  scenario re-wording) to the proposal's list.

## Observations (verified claims — recorded so the owner pause can rely on them)

These are the falsification attempts that **failed** — the claims held:

1. **Outcome fidelity (roadmap §"C2 = P4 alone"):** discovery from the issuer replaces
   the URL arithmetic; the rename file list matches the roadmap's (plus the
   callback-route rotation, carried consistently); the no-PKCE confidential-client
   option, the B2C-with-placeholders tested case, and the userinfo-federation
   recorded-not-built extension (D10, matching the roadmap's "Open extension" line and
   C1's OQ-F discharge record verbatim) are all present; the acceptance rows carry the
   roadmap's two criteria (live B2C run owner-dependent, conformance suite conditional).
2. **The inheritance constraint holds.** The refresh leg today rides exactly the
   Keycloak arithmetic the change deletes (`gateway/idp.py:347-357` `_token_url`,
   `475-495` `_fetch_key_set`; called from `gateway/token.py:650-653` via
   `idp.refresh_identity`/`verified_claims`), and the delta's discovery requirement plus
   the refresh and verification amendments put all four legs (redirect, exchange,
   refresh, key set) on the one discovered document with no fallback construction —
   one spelling, C1 folded in, not forked. No second Keycloak-spelled path survives the
   delta's world; the current code's Keycloak paths are exactly the ones the tasks
   delete. The roles mechanism needs no change, as claimed (`gateway/tokens.py:157-204`
   resolves an operator-configured path against whatever the verified token carries).
3. **Spec hygiene:** the programmatic diff of all five MODIFIED requirements shows
   only the declared changes (finding F4 is the one exception, and it is in the
   declaration layer, not the normative text). The main spec contains **zero**
   Keycloak/realm/internal-base spellings; the only stale statements are the three
   "public PKCE client" wordings (lines 142, 158, 628) and the refresh requirement's
   "the provider's token endpoint" (line 486) — all four amended. The claim-copy
   requirement's "the provider's published keys" (line 266) remains true under
   discovery-based resolution — not stale, noted for completeness. All ADDED scenarios
   are testable as failing-then-passing tests (each names a WHEN a fixture can build
   and a THEN an assertion can check).
4. **Never-cut 2 boundary is correct in the code:** the IdP-leg verifier is the
   gateway's own (`gateway/flow.py:158-162`); the upstream leg carries Core's published
   challenge only (`flow.py:303-304, 435-436`), verifier never at the gateway — the
   no-PKCE mode touches only the former, and the delta's client-facing-PKCE scenario
   pins the AS surface. The invariant table rules all seven never-cut invariants
   (matches `ROADMAP.md`'s list count and wording) with real reasons, not boilerplate.
5. **SIA structure conforms to `docs/security-analysis.md` §5** (all eight sections in
   order; the fixed eight control categories with threat-specific N/A reasons, not
   generic dismissals; mis-use row marked; every mitigation names its home). The EP5
   threat tables cover the classes probed for: forged discovery document (DT-EP5-1,
   with the mint-any-`sub` chain priced), discovery-fetch amplification (bounded
   min(limiter, 1/TTL) — the limiter claim matches the main spec's abuse-bounds
   requirement), no-PKCE interception with the plain-http residue disclosed (DT-EP5-3),
   secret on the wire and at rest (DT-EP5-4/DT-EP4-1, including the override leg now
   carrying a secret it did not carry before), per-policy issuer confusion (DT-EP5-5 —
   but see F3 for its "by construction" claim), override mis-use (DT-EP5-7), provider
   outage (DT-EP5-6). The mitigations are feasible and land in the delta spec (the
   discovery, validation, and confidential-client requirements carry them; task 1.2
   cross-checks this).
6. **Router claim verified:** `router/nginx.conf:134`'s alternation
   `^/dial/(callback|jwks\.json|authorize|token|register|revoke)(/|$)` matches both
   callback spellings; EP6 genuinely needs no change.
7. **Rename surface verified:** eight test files carry the old vocabulary
   (test_federation 91 hits, test_settings 15, test_tokens 14, test_custody 11,
   test_audit 10, test_leak_check 4, test_limits 2, test_authorize 1) and the tasks
   cover all eight across 2.1/2.2/2.5; the helper-scoped `KEYCLOAK_*` names in
   `.env.example` (ADMIN_*, TOKEN_CLIENT_*, IDENTITY_CLIENT_*) match D8's list exactly
   and are consumed by scripts only, not the settings model;
   `scripts/provision_keycloak.py:98` writes the redirect URI at the old callback
   spelling (task 2.4's target, real); `tests/test_settings.py:923-932` carries the
   derived-callback-path assertions task 2.1 names; `scripts/check_publication_leaks.py`
   exists (task 6.1 is runnable). The gate ladder would catch a half-done rename inside
   its grep scope (see F5 for what is outside it).
8. **Publication discipline:** every tenant/policy/domain reference in the change
   folder uses `<tenant>`/`<policy>`/`<domain>` placeholders; no internal hostnames,
   tenant values, personal paths, or org names appear (grep-verified). The B2C/External
   ID facts that are stated as verified were checked against the live public docs and
   held: end-of-sale 2025-05-01, SPA/auth-code-with-PKCE 24-hour refresh tokens without
   `offline_access`, per-grant rotation, 14-day default refresh lifetime, the default
   vs tfp issuer values — all as design.md states (the two facts that did NOT hold as
   "verified" are F3's).
9. **Internal coherence:** D1–D10 each land in the delta spec or the tasks as claimed
   (D1/D2/D4 → the discovery requirement; D3 → the validation requirement; D5 → the
   confidential-client requirement, with F7's converse gap; D6 → the verification
   amendment's scenario; D7 → tasks 2.2/2.4 + migration plan; D8 → tasks 2.1/2.3 and
   OQ-D; D9 → task 5.1 + the live-run rows; D10 → recorded, and the delta spec
   anticipates nothing beyond it — only issuer/authorization/token/jwks are read from
   the document, matching DT-EP5-1's mitigation 1). Release-notes draft follows the
   two-audience house format (checked against the archived C1 draft). OQ-A–E each name
   their resolution owner (live run / ecosystem / owner pause / implementation).
10. **Two wording nits, recorded for the fix pass, not numbered:** the SIA's EP4
    heading "the process boundary" is a loose paraphrase of the baseline's EP4 ("the
    signing key and the dedicated custody key" — the baseline entry does cover process
    memory and host files, so the mapping is sound once the implementer reconciles the
    title); and D5/DT-EP5-3 anchor the no-PKCE residue on "the E7/RES-1 interception
    class" — the IdP-leg callback is E6 in the threat model's numbering (E7 is the
    upstream callback; T3-3/RES-1 is the shared class), so the threat-model delta
    should anchor on T3-3/RES-1 to avoid importing the slip into the model.

## Dispositions (revision round, 2026-11-04)

Applied by the revision-round author against the owner-approved disposition list; no
mechanism decision (D1–D10) was re-opened — every fix below is a completeness or
precision fix in the change artifacts.

- **F1 — applied.** design.md §7 and task 1.1 gained the explicit scoping rule —
  local-deployment facts (the compose service, the dev realm, the provisioning
  helper's targets) stay Keycloak-named per D8, while MECHANISM vocabulary (the
  federation leg, its tokens and codes, its trust boundary, its key set) goes
  provider-neutral — with the missed rows enumerated: A5's code inventory, the EP3
  callback-URL row, T3-3's and T5-2's mitigation prose, M2's pair list, and §10's
  compose-network row's leg list. Task 1.1's verification is now a checkable grep:
  after the edit, every remaining `Keycloak` hit in `docs/threat-model.md` must be a
  D8-scoped local-deployment fact, no mechanism-level hit surviving.
- **F2 — applied.** design.md §7 and task 1.1 extend to `docs/threat-model.md` §10,
  per `docs/security-analysis.md` §4's adds-a-surface requirement: the Keycloak
  component row rewords to the two IdP shapes (the local development instance; the
  external provider), and a new row prices a compromised external IdP — mints
  any-`sub` under the pinned issuer and publishes the matching key set, which the
  gateway's exact pin then accepts (TB7's trust restated for the internet shape) —
  recorded as accepted-with-reasoning: the pinned issuer plus its published key set
  IS the trust; the provider is the trust anchor by design, indistinguishable from
  an honest one by the gateway, exactly as a compromised Core is today.
- **F3 — applied.** Both provider facts downgraded from verified to
  live-run-to-verify in design.md's Context grounding bullet, D1, and D9, with
  exactly what IS verified now stated (the tfp issuer is a per-policy "Issuer (iss)
  claim" token-compatibility setting, off by default; the docs state each policy's
  metadata document at the `<tenant>.onmicrosoft.com` path — a different shape from
  the tfp-issuer-appended path D1 fetches). Task 5.1 gained the operator prerequisite
  row (enable the per-policy issuer setting on the B2C policy — without it a
  tfp-configured deployment fails every sign-in at issuer verification, diagnosable
  only from the stated prerequisite); task 7.1's live-run facts list and OQ-A gained
  the fact pair. D6, the SIA's DT-EP5-5 row and its control 3, the invariant table's
  row 3, and the delta spec's verification amendment note now separate what is by
  construction (the gateway-side exact-string pin refuses any token whose `iss`
  differs, and no document can widen it) from what is provider-configuration (the
  provider must issue policy-distinct issuers — the per-policy setting — for sibling
  policies to be distinguishable by the pin). The delta spec's per-policy scenario
  already conditioned on "issuers vary by policy", so its normative text needed no
  change — only the amendment note's "by construction" phrasing was corrected.
- **F4 — applied.** The delta's first MODIFIED requirement (authorization requests)
  now retains the main spec's standing apps-change scenario-amendments record
  verbatim, declared as retained in the new amendment note — the federation-flow
  requirement's own pattern ("stays part of the requirement's text as it stands in
  the main spec").
- **F5 — applied.** `gateway/app.py`'s healthcheck comment, `pyproject.toml`'s
  description comment, and `docs/routing.md`'s end-to-end sketch joined the rename
  surface in design.md's Context file list, the proposal's Impact list, and task
  2.5's file list; task 2.5's drift grep now covers `pyproject.toml` and
  `docs/routing.md` alongside `gateway/ tests/ scripts/probe_*.py`; and the
  PoC-era/historical-docs exclusion (`docs/HANDOFF.md`, `docs/demo-slide.html`,
  `docs/hosting-options.html`, `docs/background/*`) is stated once in the design and
  mirrored in the task.
- **F6 — applied.** D8 gained the defaults ruling, verified against the roadmap
  §D0b exposure list (these lines are its "internal instance name across
  `.env.example`, `docker-compose.yml`, `gateway/settings.py`'s default" items, so
  the change retires the exposures rather than renaming them): `idp_issuer`'s
  default becomes the provider-neutral placeholder `https://idp.example.com/`
  (RFC 2606 reserved domain), compose's `IDP_ISSUER` loses its Keycloak-realm
  fallback, and `IDP_BACKCHANNEL_BASE_URL` in compose becomes the explicit
  override's example (`${IDP_BACKCHANNEL_BASE_URL:-}`, unset by default — what D2's
  optional-override claim already required). The local profile's real values move to
  the deployment's `.env`, documented in `docs/local-environment.md`; task 2.6
  carries the ruling with its own compose-boot and probe verifications; the
  proposal's Impact and the release-notes draft's breaking paragraph state the
  now-explicit configuration.
- **F7 — applied.** The delta's confidential-client requirement gained the converse
  clause (in the default PKCE mode the configured client secret MUST NOT be
  presented on any leg — the presentation is the no-PKCE mode's compensating
  control, never an opportunistic add-on) and a fourth scenario, "The default mode
  never presents the client secret", so a from-spec reimplementation cannot keep
  today's opportunistic send; task 4.2 cross-references the scenario and its
  byte-identical check now names the removed opportunistic send explicitly.
- **F8 — applied.** The proposal's Modified Capabilities summary now names all five
  amended requirements (authorization-requests, federation-flow, app-flow, refresh,
  token-verification).

The two unnumbered wording nits from observation 10 were fixed in the same pass: the
SIA's EP4 heading is reconciled to the baseline's EP4 (the signing key; process
memory and host files — this change adds the client secret to the class), and
D5/DT-EP5-3 now anchor the no-PKCE interception residue on the T3-3/RES-1 class (the
shared callback-URL class; the identity-leg callback is E6) instead of "E7/RES-1".

Validation this round: `openspec validate generalized-idp-federation` — **valid**
(exit 0); `python scripts/check_publication_leaks.py` — **PASS** (193 tracked files
scanned, 3 findings, all pre-existing and waived, 0 unwaived; the change folder is
untracked until commit, so the sweep's next run after the commit re-covers it).
