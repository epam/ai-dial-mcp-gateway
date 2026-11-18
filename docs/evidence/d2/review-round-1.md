# D2 review round 1 — the independent review pass

**What this is.** The independent review of the D2 landing package: `docs/threat-model.md`
(the merged baseline), `docs/security-analysis.md` + `.claude/skills/security-analysis/SKILL.md`
(the method as amended by E-1..E-7), and the evidence trail (`comparison.md`,
`reconciliation.md`, `gap-list-runA.md`, `gap-list-runB.md`, `owner-sanity-test-1.md`).
The reviewer authored, compared, and reconciled none of them. The pass is falsification,
not validation: claims were checked against the vendored instructions, the synced spec,
the committed deployment shape, the gateway source, and the archived PoC evidence.

**Method of this pass.** Every count was mechanically verified (grep); every "Placed —
spec" claim was checked against `openspec/specs/mcp-signin/spec.md` text; every repo
placement was checked against committed files and source (`docker-compose.yml`,
`router/nginx.conf`, `.env.example`, `gateway/*.py`, `scripts/*`); RES-18's closure was
checked against `poc-c-runbook.md` in full; the merged tables were checked row by row
against the comparison's A-only/B-only lists; the model was then read as an attacker and
as the operator of an IdP-equivalent key.

---

## Findings

### MAJOR-1 — M10's toolset-name charset is claimed spec-placed; the spec carries no such requirement (a fourth spec gap, silently kept)

- **Where.** `docs/threat-model.md` §12 M10 ("Startup-enforced bounds: … `^[a-z0-9-]+$`
  toolset-name charset … — **Placed** — spec"); §9 T6-7 cat 6 ("`^[a-z0-9-]+$` enforced
  at startup on every mapping entry … (spec)"); M15 ("the charset-validated name
  (repo; spec)").
- **Check.** `openspec/specs/mcp-signin/spec.md`'s "The toolset mapping is safe to
  configure" requirement carries exactly two name rules: the non-OAuth refusal and the
  reserved names (`authorize`, `token`, `register`, `revoke`, `callback`, `jwks.json`).
  No charset requirement exists anywhere in the spec. The control is repo-real
  (`gateway/settings.py:40` `_TOOLSET_NAME = re.compile(r"^[a-z0-9-]+$")`; `.env.example`
  documents it) — but it is not spec-pinned.
- **Why it matters.** The D2 reconciliation's placement verification exists precisely to
  catch this, and it claims "M10 (all five startup refusals)" verified and "No placement
  was silently kept" (`reconciliation.md`). Both statements are false as written: the
  charset is a sixth element of M10's list carried under "Placed — spec" with no spec
  text behind it — the same defect class as M9's `iss` / M11's per-flow records / M20's
  hygiene, except undisclosed.
- **Failure scenario.** A future change relaxes or drops the startup charset check in
  code, believing the spec pins it. The spec-sync check finds nothing (the requirement
  never existed); T6-7's control — the only barrier between toolset names and nginx
  regex metacharacters — silently disappears while the threat model still asserts it is
  "Placed — spec".
- **Fix.** Split M10 the way M11 was split: charset element re-placed to repo
  (`gateway/settings.py`), flagged as a fourth candidate spec change; correct T6-7 cat 6
  and M15's parenthetical; correct the reconciliation record's two false statements (or
  annotate them as corrected by this review).

### MAJOR-2 — 92 of the per-threat grid's "not applicable" cells carry no reason, violating the method's anti-boilerplate guard

- **Where.** `docs/threat-model.md` §9 — 92 cells matching the bare pattern
  "`<category> — not applicable.`" (e.g. T1-2 cat 7, T1-3 cats 6/7, T4-1 cat 7, T1-16
  cat 7). The method (`docs/security-analysis.md` §5.5; SKILL.md step 6) requires every
  N/A to "name the threat-specific property that defeats the category … never a generic
  dismissal — boilerplate N/A trains author and reviewer to skim, and the one genuine
  Anti-DoS or Detective mitigation is exactly what skimming loses."
- **Check.** The grids are structurally complete — 55 threats × 8 categories = 440
  category lines, all present — but ~21% of the N/A cells are bare. The contrast is
  visible inside the same document: T1-2's cat 8 carries the phished-user
  operator-visible-gap Detective note while T1-3's cats 6/7 next door are bare — the
  guard's own rationale demonstrated in the negative.
- **Failure scenario.** The baseline is the template every later per-change SIA copies;
  the bare-N/A style becomes the house style; a genuine control-need hiding behind an
  "obvious" N/A is skipped, and the security review gate cannot falsify a cell that
  states nothing.
- **Provenance note.** The style is inherited from run A (run B wrote ~12 bare cells);
  the comparison did not flag the style divergence — a missed repeat-shaped signal, since
  both runs' gap lists emphasize the guard.
- **Fix.** One threat-specific line per cell. Mechanical, no judgment changes.

### MAJOR-3 — The Keycloak back-channel's inbound verification chain enables full identity forgery from a compose-network MITM position; the blast radius is absent from the record (and run B's own grid carries a circular comfort statement about it)

- **Grounding (code, not inference).** The gateway's identity-leg token exchange and its
  JWKS fetch both ride the internal plain-http base URL: `gateway/idp.py:208`
  (`{keycloak_internal_base_url}/realms/{realm}` token endpoint) and `gateway/idp.py:321`
  (same base, `{…}/protocol/openid-connect/certs` JWKS); `docker-compose.yml`
  `KEYCLOAK_INTERNAL_BASE_URL: http://keycloak:8900`.
- **The vector.** Attacker 7 (a compromised sibling container on TB3) in a MITM position
  on the bridge network answers the gateway's token-endpoint call with a forged
  `id_token` and the JWKS fetch with the matching hostile keys. `iss` matches
  (attacker-chosen), the signature verifies against the attacker's key set, and roles are
  read from the forged token (`ROLES_SOURCE_PATH`) — so the gateway mints a gateway token
  for **any `sub` with any roles, including admin**. The blast radius equals the
  signing-key row's (§10), reached from a *network peer* position (TB3) rather than the
  host (TB5) — a strictly lower-privilege entry. No victim is needed: the attacker drives
  their own flow.
- **Where the record under-prices it.** T5-2 ("Internal-leg man in the middle") names the
  gains "capturing the identity token and the upstream code, or forging toolset settings"
  — one-user capture and consent misdirection; identity forgery for any `sub` is not
  named, and the Compromised column (C, I on A2/A5/A11) does not carry it. §10's
  "Internal compose network" row lists "MITM the gateway↔Core/Keycloak legs" without the
  gain. RES-19's acceptance record describes the legs as exposing "the identity-token
  presentations" — the *inbound verification chain* (the gateway's own trust decision,
  not a presentation) is not called out. Run B's T5.3 grid (runB lines 1288–1291) is
  worse: it treats "verifies the returned token against Keycloak's JWKS" as bounding "a
  rogue Keycloak" — circular, because the JWKS arrives over the same rogue-controlled
  channel; the comparison missed this reasoning error too. (The merge did not inherit
  B's circular sentence — but it inherited the silence.)
- **Disposition impact.** Probably none: the vector is bounded by the same acceptance
  (RES-19: private-bridge membership; TLS named, deployment-owned). But the model's own
  honesty standard — the key-compromise blast radius stated once, plainly (§10); the
  ruling vocabulary exact — requires this vector's blast radius stated where it lives,
  and the comparison's own D-6 standard ("a control without a threat row is exactly what
  the security review gate cannot falsify against") applies symmetrically to a *gain*
  without a row.
- **Fix.** Name the forgery chain and its mint-any-identity blast radius in T5-2's
  description and Compromised column, in §10's internal-network row, and in RES-19's
  part (a). Decide explicitly (on record) whether the acceptance still holds with the
  true blast radius stated — the private-bridge bound argues it does, but that is the
  owner's priced call to see in the record, not a reviewer's inference.

### MINOR-1 — T1-16 appears in no §12 Addresses column, and its §13 disposition cites no M id

§12's closing note claims "every one traces to at least one table row above"; T1-16
traces only via "RES-6's bound" (M10) and "RES-6/7/8's bounds" (M9) — residual
indirection, not the threat-id association §5.6 requires ("each mitigation associated
with the threats it addresses"). The post-reconciliation edit added the row, grid, and
§13 entry but did not extend M9/M10/M11's Addresses columns (the reconciliation had
extended them for the 13 merged rows). Failure scenario: the grouped list — the
"reviewed result" the gate reads — silently omits the owner-input threat from its
coverage map. Fix: add T1-16 to M9, M10, and M11's Addresses columns; name M9/M10 in the
§13 row.

### MINOR-2 — M7's nuance note stretches "implementation of spec MUSTs" past breaking for timeouts and User-Agent

The spec's SSRF requirement names HTTPS-only, allowlist, no redirects,
private/loopback/link-local refused, size cap, cache — not connect/total timeouts, JSON
content type, or the explicit User-Agent. The reconciliation discloses this as a nuance
note, so it is on record, but a timeout is its own control, not an implementation shape
of a refusal requirement. Same defect class as MAJOR-1 at lower strength and honestly
disclosed — fold into MAJOR-1's fix pass (either land them in the spec or re-place).

### MINOR-3 — OQ-2/OQ-3 recorded as resolved inside the "Open questions" section

The method (§5.8) defines the section as "what the analysis could not resolve." Two of
its seven entries are resolutions. The content is right (both name their inputs; keeping
them prevents re-litigation), and the reconciliation flags it for the owner — but the
form contradicts the section's contract. Fix: retitle the resolved entries or move them
to a "resolved" note under §14. Cosmetic; no judgment at stake.

---

## Verdicts on the four judgment calls

**(a) Invariant 3 in A's favor — "Preserved with a disclosed bound" (the E7 interception
variant). UPHELD.** The bound is real and live today, verified against the committed
shape: `router/nginx.conf` listens on plain `8090` with `$mcp_origin =
"http://localhost:8090"`, and the E6/E7 callbacks route through that front door — the
interception variant's precondition is the deployed default, not a hypothetical. B's flat
"Preserved" rests on "controlled at the transport layer," which the comparison correctly
refuted (a named, unplaced control of an accepted residual is not a control in place
today). I looked for a B-side argument the comparison missed and found none that
survives: the strongest candidate — that invariant 3's letter ("a stored upstream
credential is resolvable only by the identity that created it") is not violated because
the victim's `sub` still resolves only the victim's credential — fails on the integrity
of the binding itself: the E7 chain stores the *attacker's* credential under the
*victim's* `sub`, which is exactly the per-user isolation property the invariant
protects. A's ruling is correct and conformant to the ruling vocabulary.

**(b) RES-18 closed on the archived PoC C runbook. SOUND — closure stands.**
`poc-c-runbook.md` records all five criteria CLOSED on field runs 1–5, including the one
previously-owed half: (b)'s TTL-forced rotation double-invoke, closed in field run 5
with a decisive third `token_refreshed` 2m15s after the first rotation (past the 60 s
grace — the rotated token was necessarily presented). The record is first-hand, carries
negative controls (probe batteries, the 401 negative control, the audit-trail defect it
diagnosed on itself), and documents its own earlier capture gap rather than hiding it —
the falsification-stop discipline the residual's part (b) names. Closure on archive
evidence is the right call: the residual's own re-open condition was the gate's outcome,
the outcome is green and now allowlisted (E-3), and the re-open trigger ("only if the
acceptance evidence is later falsified") is carried in the entry. Keeping it disclosed
until D3 would misprice it — D3 re-juges production-shape residuals, and this one is an
evidence-status question about the PoC, already answered. The reconciliation's one
deliberate count deviation (18 open + 1 closed, not "19 disclosed") is the honest
statement and is correctly recorded as such.

**(c) The three re-placed mitigations (M9 RFC 9207 `iss`, M11 per-flow records, M20
verification hygiene). HONEST AND SUFFICIENT — with one exception that is not theirs.**
All three spec-absence claims verified against the spec text: the discovery requirement
names RFC 8414/9728 only and no `iss` authorization-response parameter exists; the only
audit requirement is pre-allocation refusals (no success-path per-flow records); the spec
pins RS256 *minting* with no verification-side requirement. All three repo claims
verified in source: `gateway/flow.py:381` + `gateway/errors.py:82` (`iss` in the
authorization response), `gateway/audit.py` (flow_allocated, upstream_callback,
signin_result, code_issued, token_issued — the exact event set claimed),
`gateway/tokens.py:289` (`algorithms=[signing_key.algorithm]`, key passed directly) and
`gateway/idp.py:47/258` (pinned RS256, `kid` resolved against the provider's own JWKS).
The flags appear at the §12 entries and in the grids. The exception is MAJOR-1: the
placement verification missed a fourth gap of the same class (M10's charset) and
overstated its own completeness — the three flagged re-placements are honest, but "no
placement was silently kept" is false.

**(d) T1-16 (the owner's stale-claims row). CONFORMANT, one cell short of the guard.**
Classification verified: Use Control Misconfiguration → Elevation of Privilege → Bypass
Authorization follows the gains-based convention (access beyond current authorization)
and matches the owner's sanity-test ruling; the description names the flaw (claim
staleness) per the convention. The grid's substantive cells are threat-specific and
correct (cat 1 the TTL lattice with the spec/deployment split; cat 3 the live
re-authentication bound; cat 4 Core's per-call authorization on the disclosed snapshot
with the revocation-latency paths; cat 8 the per-flow records with M11's placement
note). Cats 2/5/6 carry genuine threat-specific N/A reasons. Cat 7 is a bare
"not applicable." — counted in MAJOR-2. The disposition ("mitigated to its bound →
RES-6") is consistent across grid, §13, and RES-6's corrected cross-reference
(`(T1-16 bounding, invariant 4's bound)` — the owner's cross-reference defect is fixed).
The residual-minor gap is MINOR-1 (no §12 Addresses coverage).

---

## Method-edit verdict — E-1..E-7

**Holds together; both allowlist shapes match; no contradiction with the owner rulings
in `production-roadmap.md` §D1/D2. One execution gap, noted below.**

- **E-1** (spec + as-built on the full-run allowlist): landed in `docs/security-analysis.md`
  §4 and §7 and in the skill's input list, identically in both — and it was *used*: the
  reconciliation's placement verification and this review both ran against
  `openspec/specs/mcp-signin/spec.md` and the committed compose/router/env. Consistent.
- **E-2** (whole archived `design.md`): landed in both lists ("the whole document, its
  decision sections included"), with the rationale stated. Consistent.
- **E-3** (evidence folder / PoC C outcome): landed in both lists; RES-18's re-judge was
  executed on it. Consistent.
- **E-4** (D1/D2/D3 boundary): resolved by folding the boundary paragraph into the method
  (§4's "The disposition boundary"), one of the two permitted fixes. Consistent.
- **E-5** (gains-based leaf selection as a general convention, with worked shapes):
  landed in §5.4 with the four worked shapes the comparison asked for, mirrored in the
  skill's step 5. Consistent — and T1-16's classification demonstrates it working.
- **E-6** (baseline extends §5.1; count not fixed at six): landed in §1's vocabulary row,
  §4's baseline bullet, and the skill's "Entry-point inventory" note; the merged §7
  preamble carries the corrected phrasing ("§5.1's six plus the as-built EP7").
  Consistent.
- **E-7** (register placed early; full grid in-document): landed in §4 and the skill
  (additions 1 and 5); the merged document conforms (register at §3, 440 grid cells).
  Consistent.

The comparison's deferred item — B's G-3 collision (the allowlist's "once it exists"
threat-model clause vs. a double-run brief's forbidding rule, biting at D3) — is resolved
*implicitly*: §7 scopes the double-run to "the shape's first application," so no D3
double-run brief exists to collide. Acceptable, but one sentence saying so explicitly
would prevent the next brief author from re-deriving it. The comparison's
"recommended, not required" I1–I5 mapping was (correctly) not added — consistent with
its "checked, not earned" ruling. The owner rulings are not contradicted: E-1's added
sources are *verification* inputs strengthening D2's stated source list, not a scope
change; the never-cut list, the full-SIA ruling, and the landing rule are carried
verbatim.

**Execution gap:** the method's own conformance bar ("a reviewer cannot run that gate
from what the SIA produced ⇒ non-conforming") is met by the package *except* for the
placement-integrity miss (MAJOR-1) and the N/A guard (MAJOR-2) — both are failures of
execution under the amended method, not of the edits themselves. The edits hold.

---

## Clean areas (one line each)

- **Merge fidelity, directives 1–16:** all sixteen executed; every directive's content
  verified present in the merged document, including directive 6's folded facts (24 h
  lifespan in T4-2/T5-1/§10, SSE/`proxy_read_timeout` in T6-6, the mis-use half in
  T5-1) and directive 16's sequencing.
- **Do-not-adopt list:** respected — RES-9/RES-10 stay split, invariant 3 carries the
  bound, A7/A8/A14 survive uncoarsened, M20 addresses the enumerated T4-7, the register
  is early (§3).
- **Union test:** all 13 A-only and all 13 B-only rows from the comparison's analysis
  are present in the merged tables; no row from either run was lost.
- **Counts:** 55 threats (16/6/10/7/6/7/3), 55 grid headers, 440 grid cells (8 × 55),
  55 §13 disposition rows, 15 assets, 9 boundaries, 8 attackers, 7 entry points, 19
  residual records (18 open + RES-18 closed), 4+3 invariant rulings, 20 grouped
  mitigations — the at-a-glance block is true.
- **Taxonomy and control order:** every leaf path and the 8-category order reproduce the
  vendored instructions exactly; classification conventions applied per §5.4.
- **Never-cut mapping:** §11's seven rows match `ROADMAP.md`'s list one-to-one; ruling
  vocabulary (`Preserved` / `Preserved with a disclosed bound`) used exactly.
- **As-built verification:** the model's shape claims match the committed deployment —
  plain-http `:8090` front door, gateway `:8091` never host-published (compose comment
  states the invariant), `DCR_ENABLED` default off, `.env`-injected signing key, single
  instance, internal plain-http legs, `GATEWAY_PUBLIC_ORIGIN` default.
- **M15/M16/M19 repo placements:** verified in `router/nginx.conf` (map/proxy_hide_header,
  configured origin, `$is_args$args`, anchored ordered locations), `docker-compose.yml`
  (no ports on the gateway, external network), and `scripts/` (probe batteries,
  provisioning script all exist).
- **Forwarded-header trust:** the per-source rate limit's spoofing resistance verified in
  code (`gateway/errors.py` reads `X-Real-IP`, falls back to X-Forwarded-For's *last*
  entry) and the router sets both — a third-eyes candidate checked and dismissed.
- **Today's-shape discipline:** dispositions carry today's verdict plus re-open
  conditions; no production-shape pre-judgement or "resolved by D3" promise found.

**Third-eyes candidates checked and dismissed** (for the record): rate-limit evasion via
forwarded-header spoofing (closed — router states the headers, gateway reads the
unspoofable values); loopback redirect-port race (closed — codes are PKCE-bound);
request smuggling at the router (default `Connection: close` semantics, stock nginx,
both upstreams HTTP/1.1 — nothing load-bearing to attack beyond T6-6's connection
class); audit log injection via DCR `client_name` (closed — structure-only records with
fixed vocabulary and truncation, per spec and `audit.py`); revoke-endpoint abuse (closed
— requires holding the token). The one candidate that survived is MAJOR-3.

---

## Overall verdict

**LAND AFTER FINDINGS.** No BLOCKER: the merge is faithful, the counts are true, the
judgment calls (a), (b), (c) and (d) are sound, and the method edits hold. Three MAJORs
must be fixed before the baseline is trusted as the standing record — MAJOR-1 (a false
placement-integrity claim: M10's charset is spec-claimed with no spec text, and the
reconciliation's "no placement was silently kept" is wrong as written), MAJOR-2 (92 bare
N/A cells violating the method's explicit anti-boilerplate guard in the document that
sets the example for every later SIA), and MAJOR-3 (an understated blast radius on a
live vector: the Keycloak back-channel's verification chain over internal plain http
yields mint-any-identity from a compose-network MITM position, priced nowhere in the
record). All three are documentation fixes — no control, disposition, or residual
acceptance must change on MAJOR-2; MAJOR-1 needs a re-placement or a spec change;
MAJOR-3 needs the blast radius stated and the acceptance explicitly re-priced with it
in view. The MINORs (T1-16's §12 coverage, M7's nuance stretch, the resolved-OQ form)
should ride the same fix pass.
