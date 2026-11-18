# Independent review — round 2 (PROCESS.md step 3b, second round)

Change: `dynamic-toolsets-and-fresh-claims` — the **re-taken** change (the userinfo
mechanism overruled; the RFC 6749 §6 refresh-grant mechanism in its place). Reviewer: a
fresh independent pass — round 1's conclusions were **not** inherited; every claim below
was re-verified against the ground truth: the round-1 review and the independent
mechanism opinion (read as history, not verdicts), `docs/security-analysis.md` (the
method), `docs/threat-model.md`, `docs/production-roadmap.md` §"The iteration, packaged
and ordered" (§C1), `docs/background/design.md` §6.3, the main spec
(`openspec/specs/mcp-signin/spec.md`), the code (`gateway/idp.py`, `gateway/token.py`,
`gateway/tokens.py`, `gateway/federation.py`, `gateway/flow.py`, `gateway/settings.py`,
`gateway/status.py`, `gateway/core.py`, `scripts/provision_keycloak.py`), and the
OIDC/OAuth specifications and vendor documentation the provider-behavior facts rest on.
Read-only except this file.

**Overall verdict: LAND AFTER FINDINGS.** The re-taken mechanism survives
falsification on every axis that matters: the refresh grant genuinely resolves the three
verified objections (the token endpoint is the OIDC Discovery **REQUIRED** member, the
claim carrier is the *same token-endpoint access token the exchange already verifies* —
confirmed in the code, `gateway/idp.py:193-194` — and the credential lives on the
provider's own session clock), the snapshot-free refresh token makes the fail-closed
fallback structural, the custody hand-off is specified against the code's actual seams,
and the M13 amendment is priced honestly as RES-21. Round 1's findings M1–M7 and m1–m5
are all verifiably addressed. What remains is the same defect class round 1 called out
in M3 — prices the SIA states inside its own tables that do not reach the artifacts
supposed to carry them — plus rename propagation into two operator-facing documents. No
design decision needs reopening; no finding moves ground truth.

---

## Findings

### BLOCKER

None.

### MAJOR

**R2-M1 — The threat-model delta (§7 / task 4.1) is still incomplete: five model
locations whose current text the change invalidates are outside the edit list, and the
task's verify clause protects them from edit.**
`design.md:754-871` (§7), `tasks.md:225-271` (task 4.1; the verify clause at
`tasks.md:266-271` — "every other entry's disposition is untouched"). Checked line by
line against `docs/threat-model.md`:

- **RES-4** (`threat-model.md:125-131`): its bounding control reads "the CIMD capacity
  limiter bounds **the one attacker-steered slow leg's** pool share." After this change
  there is a second attacker-triggered slow leg: the refresh grant, one outbound call
  per refresh, each holding a worker-thread slot for up to the outbound timeout —
  exactly the shape DT-EP1-5 prices (`design.md:541-563`) and whose residual it lands on
  ("Residual queue-wait within the limits is the already-disclosed RES-4 class",
  `design.md:559-561`). The design leans on RES-4 as the disclosure vehicle for its own
  new remainder but never amends RES-4's record to carry it.
- **The compromise table's internal-compose-network row** (`threat-model.md:1520`): its
  "Attacker gains" list ("Sniff the identity-token presentations and the `/signin`
  bodies…") omits what DT-EP5-2 prices — a network peer reading the refresh-grant leg
  now holds **the retained mintable provider refresh token**, "the most powerful
  credential the flow ever held" (`design.md:448`). §7 and task 4.1 re-price only the
  table's *gateway-process* row (`design.md:860-864`, `tasks.md:260-262`).
- **§1 "The system as it stands"** (`threat-model.md:68-77`): three false statements the
  day this lands — "refresh tokens 8 hours, non-sliding, **role-snapshot semantics**"
  (the snapshot is deleted, D4); "**startup-checked against the realm's 24 h
  `accessTokenLifespan`**" (the check is renamed and re-meaninged onto
  `IDP_SSO_SESSION_MAX_SECONDS`, D6); and the state inventory ("flow records … replay
  cache … refresh denylist — all in memory") gains the retention store and the pending
  hand-off entries, which §1 does not list. This paragraph is the anchor every reader of
  the model starts from; leaving it describing a system that no longer exists is the
  model-lags-the-code failure the method's own preamble names
  (`docs/security-analysis.md`, "Why a full SIA on every change").
- **§4's asset inventory** (`threat-model.md:266-283`, the at-a-glance count "15 assets
  (§4)" at `threat-model.md:27-32`): the retained provider session refresh token is a
  new sensitive asset — mintable, one per active refresh session, in process memory for
  up to the refresh window, exactly A2's class — and no asset row carries it; A2's
  footprint line ("Gateway process memory for ≤ flow TTL") is unchanged and does not
  cover it. §7 updates the at-a-glance counts only for the register and the
  revocation-summary table (`design.md:869-871`).
- **RES-16** (`threat-model.md:216-218`): its bounding control cites "Startup
  reserved-name enforcement" — in dynamic mode startup enforces reserved names only for
  *configured* restriction entries; the request-time guard does the dynamic-name work.
  T6-2's control 4 is amended (§7, `design.md:797-800`) but RES-16's own record is left
  naming the startup half as if it still covered the whole surface.

Concrete failure: an implementer executing task 4.1 literally — its verify clause
enumerates the editable set exhaustively — leaves all five locations stale, and the
security review gate (5.4) then reads a threat model that understates the change's own
disclosed prices. Remedy: add the five entries to §7 and task 4.1's list (a new asset
row or an amended A2/A4 footprint for the retained token; §1's snapshot/validator/state
sentences; RES-4's widened slow-leg membership; RES-16's moved control half; the
compromise table's internal-network row alongside the gateway-process row).

**R2-M2 — The setting rename's operator-facing propagation is incomplete:
`docs/gateway-configuration.md` and `README.md` carry the old setting name and the
superseded staleness rationale, and no task touches them for the rename.**
Task 2.4 (`tasks.md:154-174`) lists `gateway/settings.py`, `.env.example`, and
`docker-compose.yml`. But `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` and the old rationale
also live in `docs/gateway-configuration.md:27` (the "missing setting" refusal-table
row), `:29` (the refresh-window refusal row, arguing the superseded "the gateway must
never be staler than the client it replaces" bound), `:378-379` (the settings table),
and `:446` (the non-sliding prose) — and in `README.md:82` and `:93` (both stating the
setting is required with no default). Task 1.5 (`tasks.md:65-71`) updates
`docs/gateway-configuration.md`'s *mapping* section and README's *quickstart* only.
Concrete failure: after the change, the deployment's operator-facing reference names a
setting that no longer exists, argues a rationale D6 explicitly retires ("the old
staleness rationale … is removed — a validator whose meaning no longer matches its name
is worse than none", `tasks.md:168-170`), and never mentions
`IDP_SSO_SESSION_MAX_SECONDS` or the operator-assertion semantics; an operator upgrading
by the doc sets a dead variable while the required new one is unset (a loud startup
refusal, but a preventable one), and the local-realm guidance (where the SSO Session Max
value comes from) never reaches the person who needs it. Remedy: add both files'
affected rows/sections to task 2.4's file list (or a 2.4b), with the same re-derived
operator-facing text discipline the task already applies to `.env.example`.

### MINOR

**R2-m1 — `idp_session_ended` classification conflates every provider 4xx with
"session gone", mislabeling gateway-side misconfiguration as mass revocation.**
`tasks.md:86-88` (task 2.1: "a 4xx refusal from the provider (**the session is gone** —
revoked, expired by session policy, or consumed by a lost rotation)"), mirrored in
`design.md:437-440` (D4) and the delta spec's session-ended scenario
(`specs/mcp-signin/spec.md:231-233`). RFC 6749 §6 distinguishes the refusal codes:
`invalid_grant` is the session-gone signal; `invalid_request` (a gateway bug) and
`invalid_client`/401 (a misconfigured client secret) are 4xx refusals that say nothing
about the session. Concrete failure: a deployment with a wrong `KEYCLOAK_CLIENT_SECRET`
answers every refresh with 401 → the trail fills with `idp_session_ended` → the operator
reads a mass IdP-session revocation or a session-policy break and chases the wrong
incident — precisely the misdiagnosis the two-burst design exists to prevent
(DT-EP1-6 cat. 8, `design.md:584-587`). Remedy: key the session-ended class on the
provider's `invalid_grant` error specifically (the RFC's session-gone code); every other
4xx lands on `claims_read_failed` with the transport/5xx/unusable classes.

**R2-m2 — RES-21's "scope-limited" bounding phrase overstates the bound, and the
bounding list omits two controls the design itself names elsewhere.**
`design.md:821-823` (§7's RES-21 record: "the grant is session-bound and
**scope-limited** … it grants … **nothing beyond the gateway client's own scopes**").
The gateway client's scopes are `profile,email` (`.env.example`, the provisioning's
converged set) — but Core authorizes on the **role claims embedded in the token**, which
the local mappers place in the access token regardless of OAuth scope
(`scripts/provision_keycloak.py:252-284`, `access.token.claim: "true"` on the roles
mapper). The minted provider token therefore carries the user's full DIAL role set; the
scope limit bounds nothing DIAL-relevant. The record's real bounds — per-user,
session-bound, revocation-killed — are stated and hold; the phrase "scope-limited"
invites the reader to count a bound that does not exist. Also missing from the (b)
bounding list: **provider rotation reuse detection** — D3's own custody strength
(`design.md:193-197`: reuse revokes the chain), which bounds a *lifted* string the
moment the gateway's own next refresh races the thief (the session dies for both) — and
the explicit **SSO Session Idle/Max pair** as the clock ("the provider's session policy"
is named only in the abstract). Remedy: drop or rephrase "scope-limited" (state that
the token carries the user's role claims and that the bound is per-user and
session-bound, not scope); add reuse detection and the idle/max pair to the bounding
controls.

**R2-m3 — The idle-refresh-on-use fact is design-load-bearing for the local 8 h window,
but no driven check verifies it.**
`design.md:146-157` (D1 dependency 3: "refresh use refreshes the session's *idle*
timer, so under a normal refresh cadence the operative cap is SSO Session Max"), the
strict gap list `design.md:931-934`, task 2.5 (`tasks.md:175-191`). Task 2.5(b)
refreshes immediately after the exchange, 2.5(d) reads the realm's Idle/Max values and
checks the window against them, and 3.1's live runs complete within minutes — none
drives a refresh after a gap longer than SSO Session Idle. If the idle-refresh-on-use
fact were false on the local realm (default idle 30 min), every session would die at
~30–40 min after the last browser activity and the 8 h window would be a fiction — the
exact failure shape the overruled mechanism's O3 arithmetic exposed. The fact is almost
certainly true for Keycloak, but it is the one load-bearing provider fact left to
inference. Remedy: one driven check in task 2.5 — a refresh grant presented after a
deliberate gap longer than the realm's SSO Session Idle (and shorter than Max) still
succeeds; the machine-checked version of the fact the window rests on.

**R2-m4 — The migration note's "except those four" contradicts task 5.3's "the three
amendments".**
`specs/mcp-signin/spec.md:191` (Migration: "Every conformance row written against the
removed requirement maps onto the replacement unchanged **except those four**") — but
the paragraph declares **three** amended scenarios (Silent refresh, Resource mismatch,
Refresh TTL), and the "four" it apparently counts are the *new* scenarios, which have no
pre-existing conformance rows to map. Task 5.3 (`tasks.md:287-290`) correctly says
"unchanged except **the three amendments** the migration note declares". Concrete
failure: an implementer or gate-runner reconciling the note against the task finds a
count that does not parse, and the migration discipline (byte-identity with declared
amendments) loses its audit trail. Remedy: "except those three".

**R2-m5 — Task 1.2 cites the wrong module for the refresh grant's guard site.**
`tasks.md:30-31`: "the refresh grant's resource-to-name resolution (`gateway/tokens.py`)".
The refresh grant is implemented in `gateway/token.py` (`_refresh_grant`,
`gateway/token.py:328-431`; `gateway/tokens.py` is the mint/verify module and handles no
requests). Task 2.3 (`tasks.md:124`) names both correctly. Harmless to a reader who
knows the code; a stale citation in the task an implementer executes. Remedy:
`gateway/token.py`.

**R2-m6 — D3's hand-off premise is stated as universal but holds on one of the two
paths.**
`design.md:201-203`: "the flow record is already destroyed when `_finish` runs." True
on the consented path (`gateway/federation.py:170` destroys, `:178` finishes) but not on
the already-signed-in short-circuit, where `_finish` runs at
`gateway/federation.py:115` with the record still live (it dies by TTL; the identity
token on it is already discarded at `gateway/flow.py:210`). The conclusion — the
provider refresh token cannot ride the flow record to the code grant, minutes later, on
another endpoint — holds on both paths; only the stated fact is half-true. Remedy:
reword ("the flow record never reaches the code grant — destroyed on the consented path,
TTL-bounded and identity-free on the short-circuit").

---

## Verdicts on the attack list

1. **The provider-behavior facts (D1/D5/D6) — PASS, honestly deferred, with one
   load-bearing gap (m3).** Verified against the specifications: `token_endpoint` is a
   REQUIRED member of both OIDC Discovery §3 and RFC 8414 §2 (the "REQUIRED member
   every OP exposes" claim is exact); RFC 6749 §6 makes the response's `access_token`
   REQUIRED and `refresh_token` OPTIONAL, and permits an AS to decline issuing refresh
   tokens (dependency 1's failure shape is real and answered loudly at sign-in); OIDC
   Core §12.2 leaves the refresh-response ID token to the provider and the design
   correctly does not depend on it — the carrier is the access token, which the code
   already reads and verifies at the exchange (`gateway/idp.py:193-194`,
   `_verified_claims`, `verify_aud` off, issuer pinned — the same path the grant will
   use, so D2's one-vocabulary claim is verified against the implementation, not just
   asserted). The Keycloak facts (session-bound refresh tokens dying with the SSO
   session; refresh use refreshing idle but not Max, default 10 h; rotation-on-use with
   chain-revoking reuse detection as the default) and the Entra facts (~24 h
   public-client bound without `offline_access`; sign-out/admin revocation killing them)
   match the vendors' documented behavior as I can verify it; they are gap-listed as
   not-repo-verifiable (`design.md:929-940`), live-verified for the local realm by
   tasks 2.5/3.1, and the Entra facts are handed to C2 rather than silently assumed.
   That deferral is honest — every fact the *local acceptance* rests on has a driven
   check except the idle-refresh-on-use fact (m3). The provisioning already converges
   the client's default scopes away from the realm's inherited `offline_access`
   (`scripts/provision_keycloak.py:407-413`), so the amended M13 line ("never
   requested") is enforced twice over locally.
2. **The structural no-snapshot claim — PASS.** Verified in both directions: today's
   refresh token carries the full snapshot (`gateway/tokens.py:211-240`; read back at
   `gateway/token.py:384`), and the delta spec deletes it normatively ("The gateway's
   refresh token MUST NOT carry a claim snapshot — the verified fresh read is the
   mint's only claim input", `specs/mcp-signin/spec.md:197`) with task 2.3 reducing the
   payload to the session bindings and a negative control asserting no code path mints
   without a completed read and that the payload carries no copied claims. Every
   scenario was checked for claim/escrow remnants: the only snapshot left is the
   authorization code's own, explicitly retained with its 5-minute TTL as the freshness
   bound (D4, task 2.3) — it cannot serve a refresh (single-use, replay-cached by
   `jti`, and consumed at the code grant). The REMOVED requirement's reason and
   migration carry the amendment discipline, with one count slip (m4).
3. **The hand-off seam and the closed-table extension — PASS with findings (m1, m5).**
   The seam is specified against the code's real shape: the refresh token's `jti` cannot
   exist before the code grant, the flow record never reaches `/dial/token` (verified at
   `gateway/federation.py:115/170/178` — with the m6 wording nit), the pending entry is
   keyed by the code's `jti`, TTL-bounded by the code's own life, dropped unredeemed,
   and the prohibition names the dangerous easy path (the code payload — a
   signed-but-unencrypted JWT, base64-readable by the code string's holder) with a
   decode-and-assert test row. The closed-table extension preserves the property I
   verified in the code (`gateway/token.py:96-126`: one-directional, keyed by error
   code, unmapped values raise): the keying widens to error-code-plus-named-class with
   every token committed in the table and no `flow_refused` bypass
   (`tasks.md:36-44`). The two bursts do distinguish outage from revocation from mass
   local revocation as claimed — transport/5xx/unusable → `claims_read_failed`,
   provider-refused → `idp_session_ended`, denylist/expiry → plain `invalid_grant` —
   except that "provider-refused" is keyed on any 4xx rather than on `invalid_grant`
   specifically (m1).
4. **Threat-model-delta completeness — FAIL (R2-M1).** The entries §7 *does* name were
   each checked against the model's current text and are consistent and non-overstating
   (T1-16's new disposition matches what the delta spec actually guarantees; RES-6's
   shrink, invariant 4's restatement, the T4-2/RES-2 custody re-price with the identity
   access token's retention reverted to the flow TTL, the T5-1/RES-3 purposes
   re-derivation, the RES-19/T5-2 extension with the forgery gain honestly narrowed to
   any-claims-for-an-existing-`sub`, RES-10's excluded-by-construction →
   refused-per-flow, RES-15's restart semantics, T6-2's moved control, T1-7's cost row,
   M13/M9/M10, the revocation-summary row — verified against
   `docs/background/design.md:524-533`, which carries exactly the row §7 quotes — and
   OQ-1's resolution, whose source I verified: `gateway/status.py:111-122` does enforce
   the presented token's audience/resource binding at E9). The defect is what the list
   omits: RES-4, RES-16, the compromise table's internal-network row, §1's
   system-as-it-stands, and the asset inventory (R2-M1). One observation, not a
   finding: the SIA rules invariant 3 "Preserved, strengthened" (the `sub` cross-check),
   and the model's invariant-3 row is *not* in §7's edit list — the row's text stays
   true as written (the strengthening lands via the new grouped-mitigation row), so
   this is consistent, but §7 could say so in one line rather than leave the
   strengthening unlanded in the model.
5. **RES-21's pricing — PASS with one honesty defect (m2).** The three-part record is
   real and the central sentence is the honest one: "a lifted string does not observe
   the gateway's store bounds … can keep refreshing past the gateway's own window for as
   long as the provider's session policy allows" (`design.md:818-821`) — no
   understatement found. The does-NOT-grant list holds as stated (no upstream
   credential — those exist only inside Core, never-cut 1; no other user's identity —
   the credential is that session's). The two defects are the "scope-limited" phrase,
   which reads as a security bound the deployment's claim wiring does not actually
   provide (roles ride the token regardless of scope), and the omission of reuse
   detection and the explicit idle/max pair from the bounding controls (m2).
6. **OQ-G and OQ-H — PASS.** Both are framed as owner rulings with stated defaults, not
   pre-decided: OQ-G (`design.md:911-919`) parks the keepalive bound (default accepted
   and disclosed; the tighter alternative named as the provider-specific introspection
   the design deliberately does not build); OQ-H (`design.md:920-927`) parks upward
   revocation symmetry (default no, the local denylist specified). Neither is built
   into the delta spec — I checked: no scenario or requirement mandates a keepalive
   bound or an RFC 7009 leg against the IdP. DT-EP1-7 is proportionate: one mis-use
   row, an eight-category pass with threat-specific reasoning, bounded by SSO Session
   Max and the non-sliding window, and a disposition that hands the residual to OQ-G
   rather than claiming it closed.
7. **D5/D6's validator re-derivation — PASS on the mechanism, FAIL on propagation
   (R2-M2).** The three layers are honest and correctly split: startup keeps an
   *arithmetic* check on an operator-*declared* bound with the un-catchable failure
   named (a green check is arithmetic, not provider truth); the provisioning check
   machine-verifies the one realm this repo administers (2.5d); the runtime break fails
   loud as the `idp_session_ended` burst. The rename is consistent across the proposal,
   design, tasks, delta spec (the re-derived scenario
   `specs/mcp-signin/spec.md:211-213`), and the release notes — and inconsistent in
   exactly two places no task touches: `docs/gateway-configuration.md` (five locations)
   and `README.md` (two), both carrying the dead name and the superseded rationale
   (R2-M2). The old setting's footprint is otherwise confirmed small:
   `gateway/settings.py:214,442-446`, `.env.example:94-101`, `docker-compose.yml:64-68`
   — all tasked.
8. **General — PASS.** `openspec validate dynamic-toolsets-and-fresh-claims --strict`
   is green (run this pass). Delta format conforms: every MODIFIED requirement carries
   the full amended text; retained scenarios are byte-identical to the main spec except
   the declared semantics-carrying amendments (mapped→served, the inference condition,
   the retention sentence, the sub authority), which I compared side by side; the
   round-1 hyphenation drift (m1) is fixed. The resource-mismatch correction (round-1
   M4) is verified against the code and its test: `gateway/token.py:359-362` raises
   `invalid_target`, `tests/test_tokens.py:447-457` asserts it, matching the code
   grant's analogue at `gateway/token.py:289-291` — task 2.6's no-code-change
   reconciliation is the right shape. Scope discipline holds: no C1.5 creep (the kind
   check *refuses* non-OAuth rather than short-circuiting a new resource kind;
   apps-as-resources is excluded in the proposal, the design's non-goals, and absent
   from the delta spec). The SIA conforms to `docs/security-analysis.md` §5's eight
   sections in order, at the per-change shape (delta threats at the touched entry
   points; untouched surfaces covered by the invariant table), with mis-use cases
   marked, threat-specific N/A reasoning throughout (no boilerplate found), the grouped
   list G1–G8 with homes and owners, and the EP3 no-table decision now carrying the
   justifying sentence round 1 asked for. Cross-artifact consistency holds otherwise:
   the release notes match the design (including the OQ parking list and the
   transitional re-sign-in note), no userinfo remnant survives outside historical
   context, and the tasks map one-to-one onto the roadmap's P2/P3 acceptance texts
   including the live-run halves.

## Round-1 findings — re-verified, not inherited

All twelve were independently confirmed addressed in the re-taken artifacts: M1
(universality restated as three loud dependencies; OQ-F discharged), M2 (the purposes
sentence now complete — no issuance-time read exists at all under the new mechanism;
the dangling "(DT9)" is gone), M3 (RES-10/RES-15/T6-2/T1-7 added; RES-20 created — the
round-2 residue is R2-M1's five *different* locations), M4 (corrected to
`invalid_target`, verified against code and test), M5 (the pending entry specified with
key, TTL, both paths, and the code-payload prohibition), M6 (the closed-table extension
and both audit tokens specified), M7 (the unknown-name scenario added; the blended
scenario reworded per-surface), m1 (hyphenation restored), m2 (moot — no userinfo
language remains), m3 (the message re-derived), m4 (OQ-1 resolved with a source I
verified), m5 (folded into the M7 remedy), and the EP3 one-liner now present.

## Clean areas (one line each)

- D2's one-vocabulary claim, verified against the implementation: the exchange reads the
  token-endpoint access token and verifies it through `_verified_claims` — the exact
  carrier and path the refresh grant will use, so no new claim-source requirement
  appears anywhere.
- The local realm's carrier wiring: the provisioning mappers already set
  `access.token.claim` on the roles and project mappers, so the refresh-grant carrier
  carries the roles path locally — dependency 2 is already machine-true here.
- D4's fail-closed semantics: every failure class has a normative MUST-refuse sentence
  and a scenario, including the subject mismatch and the retention-absent case.
- D5's amendment record: M13 amended with the pre-amendment wording replaced on the
  record, the gains stated as gains (session-bound capability, revocation propagation),
  and the price landed as RES-21 with the compromise tables re-priced.
- The revocation-summary migration: the §6.3 row quoted in §7 matches
  `docs/background/design.md:524-533` verbatim, and the re-priced row's new text is
  exactly what the mechanism delivers (verified against the delta spec's session-ended
  scenario).
- DT-EP5-1's forgery bound: honestly narrower than the exchange chain's mint-any-sub,
  with the `sub` cross-check named as the bound and the channel named as the control.
- D7/D8/D9/D10 (unchanged from round 1's verification where the mechanism is
  independent of them): the startup/request-time split is exhaustive against the code's
  constants (`RESERVED_TOOLSET_NAMES`, `_TOOLSET_NAME`, `gateway/settings.py:40-46`) and
  the router's static locations; the discovery decision's trade is stated and bounded.
- The no-refresh-token sign-in refusal (dependency 1's failure shape) is normative in
  the federation requirement with its own scenario — the loudest possible placement for
  a deployment prerequisite.
- The restart semantics: consistent across the spec's retention requirement, D3, RES-15's
  specified amendment, and the release notes' transitional note (pre-change tokens fail
  closed once, at their next refresh).
- The release-notes draft: two-audience, no real instance or issuer values, claims match
  the design with no overstatement found beyond the m2-adjacent "nothing beyond the
  gateway client's own scopes" phrasing it inherits.

## What the owner pause must decide

- **OQ-A / OQ-B / OQ-C / OQ-D / OQ-G / OQ-H** — as parked (design.md §8). OQ-G and
  OQ-H are new to this taking and correctly framed; neither is pre-decided.
- **Surfaced by this review:** (1) the two MAJOR edit-list completions — R2-M1's five
  threat-model locations and R2-M2's two operator-facing documents — are pre-pause fixes
  the owner should require landed (they are authoring completeness, not rulings, but
  the pause is the natural checkpoint); (2) whether the `idp_session_ended` class keys
  on the provider's `invalid_grant` specifically rather than any 4xx (m1) — an
  operator-diagnostics decision; (3) whether the idle-refresh-on-use driven check joins
  task 2.5 (m3) — it converts the one remaining load-bearing local-realm inference into
  a machine-checked fact; (4) RES-21's "scope-limited" wording (m2) — an
  honesty-of-record touch-up in the same edit that lands the register entry.

## Bottom line

**LAND AFTER FINDINGS.** Fix R2-M1 and R2-M2 (and m1–m6 alongside) in the change
artifacts before the owner pause; no design decision is reopened by anything above, and
no finding requires touching code that exists today — the two MAJORs are completions of
lists the change already maintains (the threat-model edit list, the rename's file list).
The re-taking itself is sound: the mechanism resolves all three verified objections on
standard surfaces, the structural no-snapshot claim is true as specified, the custody
hand-off is specified against the code's actual seams, and the M13 amendment's price is
disclosed with unusual directness. The findings' common root is narrower than round 1's:
the re-authoring pass updated every list it looked at, and missed the two it did not —
the model's descriptive sections and non-code operator docs.
