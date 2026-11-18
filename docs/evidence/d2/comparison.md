# D2 double-run comparison — the reproducibility evidence

**What this is.** The comparison of the two independent fresh runs of the D2 baseline
threat model, per `docs/security-analysis.md` §7's reproducibility rule ("two
independent fresh runs of the same case; their outputs are compared — threat sets per
entry point, dispositions, the grouped mitigation lists; divergence beyond naming
noise means the method underspecifies") and the skill's step 10 ("a Blocking or
repeated gap is a defect in the method docs — fix `docs/security-analysis.md` and the
skill before trusting the analysis"). Run A is `docs/threat-model.md` (the working
deliverable); run B is `docs/evidence/d2/threat-model-runB.md`. Neither run was
authored by the comparer; this file is the comparer's only write.

**Citation convention.** "A §7 EP1" = run A, section 7, entry point 1; "B §8 AEP1" =
run B, section 8, attack-surface entry point 1. A's threat ids are `Tn-m`; B's are
`Tn.m`. A's residuals are `RES-n`; B's are `REG-n`.

**Two corrections to the comparison tasking itself, on record.** The tasking brief's
figures "A: 36 total threats" and "both claim 5 Preserved + 2 with disclosed bound"
are miscounts of the artifacts. Run A's §7 tables contain **41** threat rows
(EP1 12, EP2 4, EP3 8, EP4 6, EP5 5, EP6 6 — matching the 41 per-threat grids of
A §8), and A §10 rules **4 Preserved + 3 with a disclosed bound** (rows 3, 4, 7).
Run B's 42 (AEP1 13, AEP2 5, AEP3 8, AEP4 4, AEP5 4, AEP6 5, AEP7 3) and 5+2 are
correct. Everything below uses the actual counts.

---

## 1. Convergence table

| Element | Run A | Run B | Verdict |
|---|---|---|---|
| Impact level (A §2 vs B §2) | High — IdP-equivalent signing key; new public AS surface; the E7 chain decides whose credential is stored under which `sub` | High — the same three reasons ("brokers the deposit of upstream credentials into Core") | **Convergent.** Same level, same reasons, same honesty framing (both refuse any "no impact" position). |
| Asset count and identity (A §3 vs B §4) | 14 assets, A1–A14 | 14 assets, unnumbered rows | **Same count by coincidence, not the same 14.** ~10 rows correspond one-to-one; each run holds items the other lacks. See §1.1. |
| Trust boundaries (A §4 vs B §5) | 8 (TB1–TB8): workstation, front door, compose network, gateway container, host, Core, Keycloak, upstream | 8 bullets: public perimeter, browser/user session, harness, gateway container, compose network, Core's credential boundary, host/volume, operator/deployment-owner | **Same count, different sets.** B splits the user side (browser, harness) and adds the operator boundary; A splits the deployment side (front door, Keycloak, upstream). Mostly compatible coarsenings; B's operator boundary is a genuine addition. See D-9. |
| Attacker inventory (A §5 vs B §6) | 8 attackers | 7 attackers | **A's prediction verified — this is the section that diverged most in composition**, but the divergence is granularity (different merges of the same underlying set), not substance: no attacker exists in one run that the other lacks entirely. See D-10. |
| Entry points (A §6 vs B §7) | 6 (EP1–EP6, per design-review §5.1's six) | 7 (AEP1–AEP6 + **AEP7 — the DCR store on its host volume**, "the implemented system's addition") | **The difference is AEP7**, and it is substantive: B's separate enumeration surfaces three threat rows (T7.1–T7.3) that A has nowhere. A treats the store inside EP1/EP4 and residual RES-5. See D-2. |
| Threat counts per entry point (A §7 vs B §8) | 41 total (12 / 4 / 8 / 6 / 5 / 6) | 42 total (13 / 5 / 8 / 4 / 4 / 5 / 3) | **Near-equal totals mask ~30% non-overlap**: 28 A rows have B counterparts, 29 B rows have A counterparts; **13 rows are A-only and 13 are B-only.** The +1 net for B is not "B found one more threat" — it is two different edge-enumerations over a shared ~29-row core. See §1.2. |
| Disclosed-residual register (A §11 vs B §3) | 19 (RES-1..RES-19) | 14 (REG-1..REG-14) | **Reconciles to the same underlying core.** 14 of A's 19 map directly to B's 14 (one B entry merges two A entries); 4 A entries exist in B only as prose, a ruling bound, or an open question; **1 (RES-16) B genuinely lacks anywhere.** No B-only residuals. See §1.3. |
| Invariant rulings (A §10 vs B §10) | 4 Preserved + **3** with a disclosed bound (invariants 3, 4, 7) | 5 Preserved + **2** with a disclosed bound (invariants 4, 7) | **Divergent in ruling value, not just naming: the open slot is invariant 3 (per-user credential isolation).** A rules it "Preserved with a disclosed bound" (the bound is the E7 interception variant, RES-1); B rules it flat "Preserved" while its own REG-2 discloses the same unmitigated today-hole in the reason column. **A is right; see D-1 (MAJOR).** The tasking's premise "both 5+2" is wrong about A. |
| Grouped mitigation count (A §12 vs B §12) | 19 (M1–M19) | 20 (M1–M20) | **The delta is one substance item plus grouping choices.** B's M19 (JWT verification hygiene) is a genuine control A lacks entirely — the mitigation-side shadow of the threat A missed (D-3). The other differences (B splitting escaping M13 from headers M12; B's standalone issuerPattern M7; B's TLS-first M1 ordering) are grouping, with the same control inventory. See D-11. |
| Compromise points (A §9 vs B §9) | 9 component rows | 9 component rows + a "key-compromise blast radius, stated once, plainly" paragraph | **Convergent on every shared row** (same blast-radius honesty: use-of-access, never theft of upstream tokens; the 24 h identity-token life). B adds browser/session and DCR-store rows A lacks; A adds the internal-network row. Union is cheap. |
| Disposition style (A §8 inline vs B §13 table) | Dispositions inline in the per-threat grids ("**Disposition: accepted (RES-n)**") | A consolidated disposition table (§13) mapping every threat to mitigated / accepted+REG | B's consolidated table is the more gate-ready form; A's is complete but distributed. Naming/structure noise. |

### 1.1 Asset identity — the two 14s are not the same 14

| A §3 | B §4 | Relationship |
|---|---|---|
| A1 signing key | Gateway signing key | same |
| A2 in-flight identity token | In-flight identity token | same (B adds the 24 h realm lifespan figure) |
| A3 / A4 access / refresh tokens | Gateway access / refresh tokens | same |
| A5 codes and flow ids (all four codes + flow id bundled) | split into three rows: harness-leg code, Keycloak code, flow record/flow id | B's split is finer |
| A6 per-user upstream credentials | Upstream access/refresh tokens (per user) | same |
| — | **Upstream PKCE verifier** (high C, Core only, nulled on public projections) | B-only asset; A carries the verifier only inside invariant 2 |
| **A7 toolset MCP traffic** (queries, tool arguments, results) | — (no asset row; the traffic appears only inside B §8 T6.2's "everything the front door carries") | A-only asset |
| **A8 user authentication material** (Keycloak credentials, SSO session) | — (the browser boundary covers the session; no asset row) | A-only asset |
| A9 audit trail | Audit trail | same |
| A10 DCR registration records | DCR registration store | same |
| A11 Core IdP/toolset-security configuration | Toolset mapping / routing configuration (subsumes nginx config too) | same, B coarser |
| A12 Keycloak admin credentials | folded into B's `.env` row (which also names **test-user credentials** — an A-absent item) | B coarser, but adds test-user creds |
| A13 routing and challenge integrity | folded into B's mapping/routing row | B coarser |
| **A14 gateway availability** | — (availability appears only as threat footprints, e.g. T1.7) | A-only asset |
| — | **Attribution on the interstitial** (display-only) | B-only asset; A carries attribution as a footprint inside T1-11/T3-4 |

Vocabulary noise: A grades high/med-high/med/low and fills every CIA cell; B grades
critical/high/medium and marks "—" where a property is not first-order. Also B's §4
gains rows A §3 lacks ("Theft mints any `sub`, any roles, including admin") — same
substance as A's §2 prose.

### 1.2 Threat-set reconciliation per entry point

Shared core (28 A rows ↔ 29 B rows; the double map is A T1-3 ↔ B T1.3 + B T1.4, and
A T1-6 ↔ B T1.5 + B T1.9):

- EP1 shared: T1-1↔T1.11, T1-2↔T1.12, T1-3↔T1.3+T1.4, T1-5↔T1.1, T1-6↔T1.5+T1.9,
  T1-7↔T1.6, T1-8↔T1.7, T1-10↔T1.8+T3.5, T1-12↔T1.3 (mis-use half).
- EP2 shared: T2-1↔T2.1, T2-2↔T2.2, T2-4↔T2.3.
- EP3 shared: T3-1↔T3.1, T3-2↔T3.2, T3-4↔T1.8/T3.5, T3-5↔T3.7, T3-6↔T3.3,
  T3-7↔T3.6.
- EP4 shared: T4-1↔T4.1, T4-2↔T4.2, T4-6↔T4.4.
- EP5 shared: T5-1↔T5.2 (B's T5.1 carries the same lift's consequence), T5-2↔T5.3.
- EP6 shared: T6-1↔T6.1, T6-2↔T6.4, T6-5↔T6.2, T6-6↔T6.3.

A-only rows (13):

| A row | Subject | B's nearest treatment |
|---|---|---|
| T1-4 | per-toolset resource confusion (mix-up within the flat AS) | none — B's T1.2 is the *foreign-AS* mix-up, a different confusion axis |
| T1-9 | log injection into the audit trail | control present (B M13, B §10 invariant-5 reason: "a caller cannot write content into the log") but no threat row |
| T1-11 | DCR registrant `client_name` impersonation [mis-use] | class covered by REG-10; no row |
| T2-3 | fetched-document content injection / poisoned CIMD cache | render escaping present via M12/T1.8; no row, no cache-poison angle |
| T3-3 | callback-URL interception of codes (the "codes alone are PKCE-useless" analysis row) | folded into T1.11/T3.2 prose |
| T3-8 | cached-page stale resubmission | control present (M12 `no-store`); no row |
| T4-3 | key / mint-path tampering by host write | folded into the host-boundary acceptance (T4.1/T7.1 context); no row |
| T4-4 | JWKS trust-path manipulation (what Core fetches) | controls present (M7 issuerPattern, M20 isolation); no row |
| T4-5 | unauthenticated floods of E8 / `/healthz` | endpoints listed in AEP1; no row |
| T5-3 | settings-field content injection (operator-config source) | gains covered by T5.3; the injection framing absent |
| T5-5 | upstream-dependency stalls (Core/Keycloak unavailability, resource consumption) | B's T5.4 is the *hostile-response crash* — a different failure mode |
| T6-3 | query-string loss on the data path (`?sessionId=…`) | **B's M17 claims to address "the query-string survival class" — a class B §8 never enumerates.** An internal-consistency defect in B (D-14) |
| T6-4 | router bypass via the container port `:8091` | boundary prose + M20 control; no row |

B-only rows (13):

| B row | Subject | A's nearest treatment |
|---|---|---|
| T1.2 | AS mix-up at the token endpoint (a foreign AS's code presented at E4) | none — A's T1-4 is the *per-toolset* confusion; A's T1-2 is MITM, not mix-up |
| T1.10 | **pre-registered client impersonation** [mis-use] — any local process wears the flagship harness's `client_id`; works with DCR **off** | none as a row (A's T1-11 is the DCR-gated name variant) |
| T1.13 | status enumeration via E9 [mis-use] | A's OQ-1 asks E9's resource binding but enumerates no mis-use |
| T2.4 | attacker-chosen redirect URIs via a (compromised) allowlisted CIMD origin | none; A's T1-5 bounds by registration, but CIMD-fetched URIs *are* the registration on that path |
| T2.5 | DNS rebinding / fetch MITM between validation and connection | control present in A's T2-1 mitigation (address pinning); no threat row |
| T3.4 | on-path rewrite of the interstitial's auto-continue target | adjacent to A's T1-2 (challenge rewrite, harness leg) but a distinct browser-leg vector; no row |
| T3.8 | callback flood (lookup/pool consumption, no allocation) | folded into A's T3-7 bounding note |
| T4.3 | **crafted JWT against verification** — algorithm confusion, embedded-`jwk`/`x5c` headers, `kid` steering | none — A's T1-8 is crash/DoS on malformed input, not key-material confusion |
| T5.1 | lifted identity-token replay / use beyond the flow (mis-use half: the gateway itself over-presenting) | consequence carried inside A's T5-1 description and compromise table; the 24 h figure and the distinct mis-use half are B's |
| T5.4 | hostile upstream response bodies crash the parser mid-flow | A's T2-4 covers hostile *CIMD* documents only |
| T6.5 | toolset-name injection into nginx config (regex metacharacters) | charset control present in A's T6-2 mitigation; no Injection-leaf row |
| T7.1–T7.3 | the DCR store: tamper → redirect-URI substitution; corrupt → startup refusal; hostile JSON at parse | RES-5 discloses the boundary; **no threat rows anywhere in A** |

### 1.3 Residual-register mapping (A RES-n ↔ B REG-n)

| A | B | Status |
|---|---|---|
| RES-1 E7 interception variant | REG-2 | same |
| RES-2 memory zeroization | REG-3 | same (B adds traceback-retention detail) |
| RES-3 token-use rule in presentations | REG-4 | same (B names the three-presentation fallback fact) |
| RES-4 shared worker-pool queue | REG-5 | same |
| RES-5 DCR store host/volume boundary (+ what enabling DCR accepts) | REG-6 (store half); the attribution half ↔ REG-10 | same core; A bundles, B splits |
| RES-6 role staleness | REG-7 | same (B stresses machine-checked startup enforcement) |
| RES-7 marker-level audience binding | REG-8 | same |
| RES-8 no per-user kill of live tokens | REG-9 | same |
| RES-9 GLOBAL not reachable from the flow | REG-11 (half) | same; B merges with non-OAUTH |
| RES-10 non-OAUTH toolsets excluded | REG-11 (half) | same |
| RES-11 consent attribution display-level | REG-10 | same |
| RES-12 plain-http front door | REG-1 | same |
| RES-13 file-based signing-key custody | — (B §10 invariant-7 bound only) | substance same, **placement differs** (D-7) |
| RES-14 new-AS trust concentration / audit budget | — (B §9's closing paragraph only) | substance same, **placement differs** (D-7) |
| RES-15 single instance / in-memory state loss | REG-13 | same |
| RES-16 nginx config fragility (config-carried, measured, not machine-checked end to end) | — | **A-only: B has it nowhere** (D-7) |
| RES-17 CIMD draft churn / harness conformance beyond the flagship | REG-12 | same |
| RES-18 assembled chain's evidence status (PoC C outcome) | — (B §14 open question 1 + gap G-2) | substance same, **placement differs** (D-7) |
| RES-19 internal plain-http server-to-server legs | REG-14 | same |

B-only residuals: **none.** The 19-vs-14 delta is entirely A's four extra treatments
plus one genuine A-only find (RES-16).

---

## 2. Divergence analysis

Class codes: **(a) granularity** (compatible — one is a coarsening of the other),
**(b) substance** (one run found a threat/residual/control the other missed — which
is right and why), **(c) judgment** (both defensible; the chooser's trade stated).

**D-1 — Invariant 3's ruling value (A §10 vs B §10). MAJOR. (b) substance — A is
right.** A rules per-user credential isolation "Preserved with a disclosed bound,"
the bound being the E7 interception variant under the plain-http front door (RES-1).
B rules it flat "Preserved," with the reason column naming the same residual
("the *interception* variant is disclosed residual REG-2, controlled at the transport
layer"). B under-rules its own finding: REG-2 is an unmitigated, today-exploitable
path to store the attacker's upstream credential under the victim's `sub` — exactly
what invariant 3 protects — and the method's ruling vocabulary
(`docs/security-analysis.md` §1: "preserved outright, or preserved with the bound
stated") exists so that a bound shows in the ruling value, not only in the reason
prose. "Controlled at the transport layer" is not a control in place today; it is the
named, unplaced control of an accepted residual. A's ruling is the conformant one;
B's is wrong on the ruling value even though its disclosure content is identical.

**D-2 — Entry point 7, the DCR store (A §6/§7 vs B §7/§8 AEP7). MAJOR. (b) substance
— B is right.** B enumerates the store as its own entry point with three threats:
T7.1 (host write rewrites `redirect_uris` → future code capture — T1.1's capture path
entered through the volume), T7.2 (corrupt store → fail-closed startup refusal),
T7.3 (well-formed hostile records loaded and trusted at parse). A discloses the
store's boundary as RES-5 and touches it inside T1-6, T4-3, and T4-6, but has **no
threat row for the store-tamper code-capture path** — the one AEP7 threat that is a
confidentiality attack on the harness-leg code, not merely a boundary acceptance.
The method requires threats to be enumerated in tables with dispositions; a residual
record is not a substitute for the enumeration. B's treatment is the stronger one
and the merge adopts it.

**D-3 — Crafted JWT against verification (B §8 T4.3 + §12 M19 vs A — absent).
MAJOR. (b) substance — B is right.** B enumerates the verifier's key-material
confusion surface: algorithm confusion, embedded-`jwk`/`x5c` headers selecting
attacker key material, `kid` steering — with the control set (pinned RSA256,
own-keys-only `kid` lookup, maintained `pyjwt[crypto]`, dependency-audit gates;
B M19). A's nearest row, T1-8 "malformed request crafting," is a crash/DoS vector
and explicitly about parsing/validation *breaking*; the confusion attack does not
break anything — it persuades the verifier to verify with the attacker's key, an
integrity compromise of the token-acceptance decision. A missed both the threat and
the control. This is the single clearest "one run found what the other missed" item
on the mitigation side too (A's M1–M19 contain nothing on verification hygiene).

**D-4 — Two different mix-up threats (A §7 T1-4 vs B §8 T1.2). MINOR each. (b)
substance, both directions.** A's T1-4 is confusion *within* the flat AS — a code or
token issued under one toolset's `resource` exchanged or used under another's
(bounded by the strict required `resource` check; A's OQ-1 on E9's binding). B's
T1.2 is the classic *cross-AS* mix-up — a foreign AS's code presented at E4
(collapsed by the single-issuer shape and the self-contained code's embedded
bindings). Each run found one confusion axis and missed the other's. Both are
mitigated by controls both runs place (strict `resource`; single issuer; embedded
`client_id`/`redirect_uri`/`code_challenge`), so neither changes a disposition — but
the merged table carries both rows.

**D-5 — Two different attribution mis-use vectors (A §7 T1-11 vs B §8 T1.10).
MINOR. (b) substance, both directions; B's is the more valuable find.** A's T1-11:
a DCR registrant supplies a `client_name` impersonating another organization —
possible only with DCR enabled (default off; accepted, RES-5). B's T1.10: any local
process presents a *pre-registered* `client_id` (e.g. the flagship harness's) with
its own loopback redirect and is attributed as that harness — **reachable in the
default shape**, since public PKCE clients have no secret by design. B's vector is
the default-shape-reachable one and absent from A; A's is the flag-gated one and
absent from B. Both land on the same residual (RES-11/REG-10: attribution is
display-level; the audit chain attributes to the acting user regardless of label),
so the disposition is unchanged — the union of rows is the fix.

**D-6 — A's enumeration edge on EP4/EP5/EP6 (13 A-only rows, §1.2). MINOR per row;
the *pattern* is MAJOR for the method. (b) substance — A is right on each.** A
enumerated rows B left to controls, boundary prose, or nothing: log injection
(T1-9), key/mint-path tampering (T4-3), JWKS trust-path manipulation (T4-4), E8 and
`/healthz` floods (T4-5), settings-field injection (T5-3), dependency stalls
(T5-5), query-string loss (T6-3), router bypass via `:8091` (T6-4), cached-page
resubmission (T3-8), CIMD cache poisoning (T2-3), the codes-interception analysis
row (T3-3), and per-toolset confusion (T1-4, counted in D-4). In every case the
*control* exists in B's §12 (or its boundary prose); what B lacks is the enumerated
threat with its own disposition. The method wants threats in tables — a control
without a threat row is exactly what the security review gate cannot falsify
against. The pattern (two runs, same core, different edges) is the reproducibility
signal §7 exists to catch, and it traces to A's own gap G-6: the method never says
whether the baseline may extend or must merely reuse design-review §5.1's inventory
and at what granularity to enumerate inside each entry point.

**D-7 — The residual register's four A-only treatments (§1.3). MINOR. (b) substance
for RES-16; (c) judgment for RES-13/14/18 — A's placement is stronger in all four.**
RES-16 (nginx config fragility: the routing's correctness is config-carried and
probe-measured, not machine-checked end to end) is a genuine A-only find — B marks
M17 "In place" and never discloses the residual the probe battery leaves. RES-13
(file-based key custody), RES-14 (trust concentration / smaller audit budget), and
RES-18 (the assembled chain's evidence status) exist in B as, respectively, the
invariant-7 bound, §9's closing paragraph, and open question 1 — same substance,
non-register placement. The method (`docs/security-analysis.md` §1) makes the
register the disclosure's home with the three-part record; a ruling bound or an
open question does not carry parts (a)–(c) in the form a later re-judge (D3)
sweeps. A's register is the conformant shape.

**D-8 — Asset identity, 14 ≠ 14 (§1.1). MINOR. Mixed (a) and (b).** The granularity
items (B's code split; A's bundled codes; B's `.env` bundle vs A's standalone A12)
are compatible. The substance items: B missed **A7 toolset MCP traffic** (the
business data itself — high C, high I in A; B's asset table has no row for the data
the whole system exists to carry), **A8 user authentication material**, and **A14
gateway availability**; A missed the **upstream PKCE verifier** as an asset (B's
row is correct — it is high-value secret material with its own footprint), the
**attribution-on-interstitial** asset, and **test-user credentials** (inside B's
`.env` row). The count coincidence must not be read as convergence.

**D-9 — Trust-boundary sets, 8 ≠ 8 (A §4 vs B §5). MINOR. (a) granularity plus one
(c) judgment worth keeping.** B's browser/harness split of A's TB1 is a coarsening
in reverse (finer on the user side); A's separate front-door (TB2), Keycloak (TB7),
and upstream (TB8) boundaries are finer on the deployment side — all compatible.
The one genuine addition is B's **operator / deployment-owner boundary** (Core
configuration, the mapping, key rotation, the DCR flag, the audit sink): both runs
enumerate the deployment administrator as an attacker (A §5 item 6; B §6 item 4)
and both carry operator mis-use threats, but only B draws the boundary those
attackers live behind. The merge keeps A's set and adds B's boundary.

**D-10 — Attacker inventory (A §5 vs B §6). MINOR. (a) granularity — A's own
prediction verified.** A's gap-list meta flagged this as the section most likely to
diverge; it did — in composition, not in coverage. Both runs' sets reconcile to the
same attackers: A's items 1+3 ≈ B's item 1 (B names the co-located workstation
process as the realistic resident — a sharper local-shape fact); A's 2 ≈ B's 2; A's
5+6 ≈ B's 4 (B merges host operator and deployment administrator); A's 7 ≈ B's 7 + 
part of B's 6 (B splits compromised sibling *components* from untrusted *tenants*
on the network); A's 8 ≔ B's 5 (B's framing — the upstream operator as the
*beneficiary* of the E7 exfiltration channel — is the better sentence). A's set is
the finer merge and stands, enriched with B's two sharper phrasings.

**D-11 — Grouped mitigations, 19 vs 20 (A §12 vs B §12). MINOR. One (b) substance
item inside (a) grouping noise.** The control inventories converge almost
completely (PKCE set, resource strictness, redirect-URI exact-match, TTL lattice,
abuse limits, CIMD SSRF set, HTML header family, audit trail, key discipline,
mapping safety, challenge synthesis, fail-closed family, TLS-as-named-control). The
one substance delta is B's **M19, JWT verification hygiene** — absent from A because
A missed the threat it controls (D-3); the merge adds it. The remaining differences
are grouping: B splits output escaping (M13) from the header family (M12) and gives
`issuerPattern` its own entry (M7) where A folds both into M8 and M14 — no coverage
difference. B's choice to list TLS first (M1, "not in place") versus A's M18 is
emphasis, not substance.

**D-12 — Document placement of the residual register (A §11 vs B §3). MINOR. (c)
judgment — but the method must pick one.** Both runs assembled the register first
(per the method's work order); A placed it late (§11, after the threat tables, with
a preamble note), B placed it early (§3, before assets and threats). B's placement
reads better against the method's own logic — the register is the anchor that
dispositions cite backward ("this threat lands on that already-priced residual"),
and B's §13 disposition table reads exactly that way. A's meta-commentary flagged
the method's silence on document order as a reproducibility defect; it materialized
as this divergence. Method edit E-7 (§3 below) pins it.

**D-13 — Classification of framing (A §7 T3-5 vs B §8 T3.7). MINOR. (c) judgment,
resolved by a method edit.** The same threat (framing the auto-continuing
interstitial to advance the upstream consent with the victim's IdP session) lands
on different leaves: A chooses Use Control Misconfiguration → Elevation of
Privilege → **Bypass Authorization**; B chooses → **Spoofing of caller's identity**
(B's own gap G-7 concedes "a reviewer may dispute" the leaf). Both runs' gap lists
carry the same MINOR gap (A G-7, B G-7): the vendored taxonomy has no leaf for
several real shapes, and the gains-based leaf-selection rule is stated in the
method only for Use-Control flaws. Stating it as a general convention (edit E-5)
makes the next two runs classify identically; for the merge, either leaf is
defensible and A's stands (the victim's consent/authorization context is what the
frame abuses).

**D-14 — B's M17 addresses a threat class B never enumerates. MINOR. A defect in
run B.** B §12 M17 says it addresses "the query-string survival class"; no row in
B §8 carries that threat (A's T6-3 is the only enumeration of it in either run).
A grouped-list entry that cites an unenumerated class is precisely the
control-without-a-threat-row shape D-6 objects to, internal to B's own document.
The merge fixes it by carrying A's T6-3.

**D-15 — The 24 h realm lifespan fact (B §1, T4.2, T5.1, §9 vs A — abstract only).
MINOR. (b) substance, B sharper.** A consistently writes "until the JWT's own
`exp`" / "the provider's own `exp`"; B establishes from its allowed inputs that the
realm's `accessTokenLifespan` is **24 h** and prices the post-lift life of a lifted
identity token concretely (T4.2: "the identity token's 24 h realm lifespan makes
its post-lift life the sharper half"). The concrete figure changes no disposition
(A's compromise table already carries the retention-vs-life distinction) but is the
stronger record; the merge adopts it.

---

## 3. Conformance verdict

**The repeated gaps, per the method's own rule.** The skill's step 10 and
`docs/security-analysis.md` §7: a Blocking gap, or a gap that repeats across
independent runs, is a defect in the method docs, fixed before either run's result
is trusted. Both runs' gap lists carry:

- **MAJOR, repeated — the current spec is outside the full-run allowlist** (A G-1;
  B G-1). The synced `mcp-signin` capability spec (`openspec/specs/`) is not on the
  full-run list, so the method's own landing rule (§3.3: "a gateway-owned mitigation
  that exists only in prose is not landed") cannot be *verified* by the run — every
  "gateway spec" placement in both models cites the archived change's design
  instead. Both runs propose the same fix.
- **MAJOR, repeated — the PoC C acceptance-gate outcome is not determinable from
  allowed inputs** (A G-4; B G-2). The archived change's location implies closure;
  no allowed document records the outcome. A carried it as RES-18 with the outcome
  as re-open condition; B carried it as open question 1. Same gap, both runs.

**Near-repeats (tagged in one run, meta-commentary in the other) — the fix pass
should treat them as repeats, because both runs hit the same wall:** the as-built
shape had to be synthesized from the archived change's context/decision sections
(A G-2 + G-3, both MAJOR; B's meta items 3), and `docs/production-roadmap.md` is
cited by the method but not allowlisted (A G-5, B G-4 — both MINOR, a clean repeat).
**MINOR, cleanly repeated: the taxonomy's leaf gaps** (A G-7; B G-7) — the
gains-based classification convention must be stated generally (D-13 is the
materialized instance).

**The earned method-doc/skill edits** (a fix pass applies these mechanically; the
first two are mandatory before either run's result is trusted):

- **E-1** — `docs/security-analysis.md` §7, full-run allowlist, and the skill's
  "Inputs — the strict allowlist" full-run list: **add the current synced capability
  spec — `openspec/specs/mcp-signin` (at run time: whatever capability spec paths
  exist under `openspec/specs/`)**, and **an as-built deployment-shape source: this
  repo's committed `docker-compose.yml`, router configuration, and `.env.example`**
  (A G-1 + G-2; B G-1). This is the single change both runs say would most improve
  the next run.
- **E-2** — same two lists: **replace "the archived PoC change's `design.md`,
  §SIA and §Risks" with the whole archived `design.md`** (or name its decision
  sections D2–D13 explicitly) — both runs needed the decision sections the two
  named sections define their substance by reference to (A G-3; B's meta 3).
- **E-3** — same two lists: **add the PoC C outcome record — the archived change's
  evidence folder (`openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/`
  evidence material) or a named closing record** (A G-4; B G-2). Until it lands,
  RES-18's three-part record keeps the outcome as its re-open condition — which is
  the correct holding state, not an assumption either way.
- **E-4** — `docs/security-analysis.md`: **fold the D1/D2/D3 boundary paragraph
  from `docs/production-roadmap.md` into the method (§4 or §7), or add the roadmap
  to both allowlists** (A G-5; B G-4 — repeated MINOR).
- **E-5** — `docs/security-analysis.md` §5.4: **state the gains-based
  leaf-selection convention as a general classification rule** (not only for
  Use-Control flaws), and name the known leaf-gap shapes (host-file secret reads,
  configuration tampering, log-content injection, information disclosure at rest,
  framing) so independent runs classify identically (A G-7; B G-7 — repeated MINOR;
  D-13 the instance).
- **E-6** — `docs/security-analysis.md` §1's vocabulary row ("design-review §5.1 —
  six entry points today") and §4's baseline bullet: **state that the baseline
  *extends* the §5.1 inventory to the system as built, and that the entry-point
  count is not fixed at six** (A G-6; D-2/D-6 the materialized divergence — one run
  added AEP7 and thirteen edge rows, the other did not).
- **E-7** — `docs/security-analysis.md` §4/§5: **state the baseline document's
  placement of the residual register** (recommended: early, B §3's shape — the
  anchor dispositions cite backward) **and that the baseline document carries the
  full eight-category per-threat grid** (both runs wrote it in full; A's meta asked
  the question, B's meta endorsed the answer — codify it so volume cannot diverge).

**The stated trust rule (the conditional alternative to E-1).** B's G-1 offers two
resolutions: allowlist the spec, *or* state a trust rule — "the full-run baseline
takes the archived change's design as normative for placement, and records
spec-text verification as a standing gap." The comparison verdict: **take E-1, not
the trust rule** — both runs converge on the allowlist fix, it is mechanical, and
it removes the gap rather than disclosing it permanently. If the owner declines
E-1, the trust rule must be written into §3.3/step 7 in exactly B's formulation,
and every future baseline carries the standing verification gap.

**Checked, not earned (single-run items):** B's MINOR G-5 (the I1–I5 vs never-cut
1–7 vocabulary mapping absent from §1's table) is *not* repeated (A's gap list does
not raise it), so the repeat rule does not mandate a fix — but the mapping is cheap
to add to §1 and prevents vocabulary drift; recommended with E-5, not required. A's
meta-item on the eight-category grid *is* earned — as E-7 — because B's meta
independently confirmed the grid's value while the method stays silent, and the two
runs only coincidentally matched in volume. B's G-3 (the `docs/threat-model.md`
allowlist-vs-brief collision) does not bite until D3's re-judge; resolve it in the
same fix pass (D3 re-judges an existing model, so the allowlist clause "once it
exists" becomes live and the double-run brief's forbidding rule must be scoped to
first applications only).

**Verdict.** The double-run found no Blocking gap, but it found two repeated MAJOR
gaps and one repeated MINOR gap, plus two near-repeats — the method doc and the
skill are therefore **fixed (E-1..E-7) before either run's result is trusted**. The
runs themselves converged on everything that carries a disposition: impact level,
the shared threat core (~29 rows with identical dispositions), the residual
register's core, five of seven invariant rulings, and the grouped control
inventory. The divergence is concentrated exactly where the method is silent —
enumeration granularity (D-2, D-6), classification conventions (D-13), document
order (D-12), and inventory extension (E-6) — which is the reproducibility check
doing its job.

---

## 4. Reconciliation directives

Executable by a fresh agent without re-doing this analysis. Base document: **run A's
`docs/threat-model.md`** (finer splits, complete register, conformant invariant
rulings). The merge is union minus error — preserve the stronger treatment wherever
the runs differ in coverage.

1. **Assets.** Keep A1–A14. Add **A15 — the upstream PKCE verifier** (B §4's row:
   high C, Core only, nulled on every public projection of toolset settings). Extend
   A12's footprint to name the **test-user credentials** alongside the Keycloak
   admin credentials (B §4's `.env` row). Canonical count: **15 assets**.
2. **Trust boundaries.** Keep TB1–TB8; add **TB9 — the operator / deployment-owner
   boundary** (B §5's last bullet: Core configuration, the mapping, key rotation,
   the DCR flag, the audit sink) — it is the boundary A §5's attacker 6 and both
   runs' operator mis-use rows live behind. Canonical count: **9**.
3. **Attacker inventory.** Keep A's 8 unchanged. Fold in B's two sharper phrasings:
   attacker 1 gains "in today's shape, a co-located process on the development host
   is the realistic resident of this class" (B §6 item 1); attacker 8 gains "the
   beneficiary of the E7 code-injection chain's exfiltration channel" (B §6 item 5).
   Canonical count: **8**.
4. **Entry points.** Keep EP1–EP6; add **EP7 — the DCR store on its host volume**
   (B §7 AEP7: one JSON file, parsed at startup, written on registration, present
   only if DCR is enabled). Canonical count: **7**. Strike the inherited "six entry
   points" phrasing in §6's preamble (see directive 14).
5. **Threat tables — add B's 13 rows** (texts from B §8, renumbered into A's scheme,
   homes re-expressed in A's placement vocabulary):
   - EP1: **T1-13** AS mix-up at the token endpoint (B T1.2); **T1-14** pre-registered
     client impersonation [mis-use] (B T1.10); **T1-15** status enumeration via E9
     [mis-use] (B T1.13).
   - EP2: **T2-5** attacker-chosen redirect URIs via CIMD (B T2.4); **T2-6** DNS
     rebinding / fetch MITM (B T2.5).
   - EP3: **T3-9** on-path rewrite of the auto-continue (B T3.4); **T3-10** callback
     flood (B T3.8).
   - EP4: **T4-7** crafted JWT against verification (B T4.3).
   - EP5: **T5-6** hostile upstream response (B T5.4).
   - EP6: **T6-7** toolset-name injection into nginx config (B T6.5).
   - EP7: **T7-1, T7-2, T7-3** (B T7.1–T7.3).
   Canonical count: **54 threats** (EP1 15, EP2 6, EP3 10, EP4 7, EP5 6, EP6 7,
   EP7 3).
6. **Threat tables — keep every A row unchanged** (A's splits are the finer ones:
   stolen vs own replay, crash vs flood, guessing vs interception). Fold B's
   sharper facts in place: the **realm's 24 h `accessTokenLifespan`** into T4-2,
   T5-1, and §9's gateway-process row (B §1/T4.2 — A says only "the JWT's own
   `exp`"); B's SSE / connection-table / `proxy_read_timeout` detail into T6-6
   (B T6.3); B's T5.1 mis-use half (the gateway over-presenting beyond the flow's
   decision step) into T5-1's description — no new row; A's T5-1 + RES-3 already
   carry the substance.
7. **Residual register.** Keep RES-1..RES-19 with A's numbering and A's early
   placement of the three-part records; do **not** adopt B's REG-11 merge (RES-9
   and RES-10 stay split — A is finer). Enrich from B: RES-3 gains the
   non-enriching-Core-build fallback fact (B REG-4); RES-6 gains "machine-checked,
   not documented" startup enforcement (B REG-7); RES-5 gains the 9p/DrvFs
   `chmod`-failure mechanism (B REG-6). Canonical count: **19 residuals**.
8. **Invariant table.** Keep A's rulings verbatim: **4 Preserved + 3 with a
   disclosed bound**, invariant 3 = "Preserved with a disclosed bound" (RES-1).
   Do **not** adopt B's flat "Preserved" on invariant 3 (D-1: B's own REG-2
   discloses an unmitigated today-hole in exactly what invariant 3 protects; the
   method's ruling values require the bound in the ruling).
9. **Mitigation grid.** A's §8 grids stand for A's threats. Write the
   eight-category grid for each of the 13 added rows, carrying B §11's grids over
   (B wrote all thirteen in full) with A's home vocabulary (spec / Core config /
   deployment / repo / upstream).
10. **Grouped list.** Keep M1–M19; add **M20 — JWT verification hygiene: pinned
    RSA256 only, own-keys-only `kid` lookup (embedded-`jwk`/`x5c` headers never
    select key material), maintained verification library (`pyjwt[crypto]`),
    bandit/pip-audit on every diff — Placed: spec + repo gates** (B M19),
    addressing T4-7 and bounding T1-8. Canonical count: **20**.
11. **Compromise points.** Keep A's §9 table; add B's **browser / user session**
    row (phished consents, framed auto-continues, false attribution — display-level
    bound, RES-11) and **DCR store** row (registration rewrite → redirect-URI
    substitution, T7-1; no secret material; only present if DCR enabled). Carry B's
    two honesty lines into the key rows: "the audience marker does not shrink this
    radius — an attacker holding the key mints the marker too" and "no
    `offlineClient` on the IdP entry."
12. **Disposition table.** Add B §13's consolidated disposition table as a new
    section after the grouped list — every threat (all 54) mapped to mitigated /
    mitigated-to-bound / accepted+RES. It is the form the security review gate
    reads in one pass; A's inline dispositions stay in the grids.
13. **Open questions.** Keep A's five; add B's OQ-4 (**the mint-path watch** — is a
    mint-rate metric or the KMS move worth scheduling, or does rotation-reach
    suffice for the local shape's lifetime?) and OQ-5 (**DCR's enabled state on
    record** — AEP7/EP7 is dormant surface if the flag has never been enabled).
    A's OQ-1 (E9 resource binding) and OQ-2 (the gate outcome) already cover B's
    OQ-1/OQ-2 territory.
14. **Counts the merged document states about itself:** 15 assets, 9 trust
    boundaries, 8 attackers, 7 entry points, 54 threats (15/6/10/7/6/7/3), 19
    disclosed residuals, invariant rulings 4 Preserved + 3 with a disclosed bound,
    20 grouped mitigations. Update §6's preamble to say the design-review §5.1 six
    **plus the as-built EP7** — and note in the D2 evidence trail that this
    extension is method edit E-6's subject.
15. **Do not adopt from B:** the REG-11 merge (RES-9/10 stay split); the flat
    invariant-3 ruling (D-1); the asset-table coarsening that drops MCP traffic,
    user authentication material, and gateway availability (D-8); the
    M-addresses-an-unenumerated-class pattern (D-14 — every grouped-list entry must
    address enumerated rows); the register-late document order (D-12).
16. **Sequencing.** The merge may be drafted now, but per the method's own rule the
    method-doc edits E-1..E-3 land **first** — E-1 gates every "Placed — spec"
    claim's verification, and E-3 is RES-18's re-open condition. After E-1 lands,
    run the one-time mechanical verification of every gateway-spec placement against
    `openspec/specs/mcp-signin` (both gap lists' standing ask); after E-3 lands,
    re-judge RES-18 against the recorded PoC C outcome.

---

## Register — the divergence register

| ID | Subject | Class | Severity | Resolution (merge) |
|---|---|---|---|---|
| D-1 | Invariant 3 ruling value (A §10 vs B §10) | substance | MAJOR | A's "Preserved with a disclosed bound" stands; B under-ruled its own REG-2 |
| D-2 | EP7 / DCR store threats (B §7–§8 vs A — none) | substance | MAJOR | adopt B's AEP7 + T7-1..T7-3 |
| D-3 | Crafted JWT against verification + control (B T4.3/M19 vs A — none) | substance | MAJOR | adopt B's row and M20 |
| D-4 | Mix-up axes: per-toolset (A T1-4) vs foreign-AS (B T1.2) | substance, both | MINOR | keep both rows |
| D-5 | Attribution mis-use: DCR name (A T1-11) vs pre-registered id (B T1.10) | substance, both | MINOR | keep both rows; B's is default-shape-reachable |
| D-6 | A's 13 edge rows (EP4/5/6-heavy) absent from B | substance | MINOR rows / MAJOR pattern | keep all A rows; method edit E-6 |
| D-7 | Register: RES-16 B-absent; RES-13/14/18 B-placement | substance + judgment | MINOR | keep A's 19-entry register |
| D-8 | Asset identity 14 ≠ 14 | granularity + substance | MINOR | A's table + verifier asset + test-user creds |
| D-9 | Boundary sets 8 ≠ 8; B's operator boundary | granularity + judgment | MINOR | A's TB1–8 + TB9 |
| D-10 | Attacker inventory 8 vs 7 | granularity | MINOR | A's 8 + B's phrasings; A's divergence prediction verified |
| D-11 | Mitigations 19 vs 20 | granularity + one substance | MINOR | A's list + M20 (JWT hygiene) |
| D-12 | Register placement: A §11 late vs B §3 early | judgment | MINOR | B's early placement; method edit E-7 |
| D-13 | Framing leaf: Bypass Authorization (A) vs Spoofing (B) | judgment | MINOR | A's leaf; method edit E-5 |
| D-14 | B M17 cites a class B never enumerates | B-internal defect | MINOR | fixed by carrying A's T6-3 |
| D-15 | 24 h realm lifespan: B concrete, A abstract | substance (fact) | MINOR | adopt B's figure |
| — | Tasking-brief miscounts (A "36" threats; "both 5+2") | not a run divergence | record-only | corrected in this file's preamble |

Convergence (no action beyond the merge's carry-forward): impact level High; the
~29-row shared threat core with identical dispositions; the residual core (14 direct
mappings); invariant rulings 1, 2, 4, 5, 6, 7; the grouped control inventory minus
M20; the compromise-point rows; the never-store/PKCE/TTL/SSRF/header-family control
set both runs place identically.
