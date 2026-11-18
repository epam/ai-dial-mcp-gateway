# Review round 3 — the vocabulary boundary (2026-11-04)

Reviewer: the independent review subagent (PROCESS.md step 3b, round 3). Mandate:
falsify the round-3 reformulation — verify the sweep is real and complete, that the
neutral re-wordings are lossless, that the coined vocabulary is sound, that rounds
1–2's dispositions survive, and that the gates are green. No fixes applied; findings
and dispositions requested only.

## What was checked, independently

- **A fresh vocabulary sweep** over the whole change folder, case-insensitive, with a
  pattern list wider than the author's: `b2c`, `entra`, `microsoft`, `azure`, `tfp`,
  `ciamlogin`, `b2clogin`, `onmicrosoft`, `fabrikam`, `contoso`, `external id`,
  `customer-identity`, `polic(y|ies)`, `user flow`, `sibling`, `per-policy`,
  `sign-in policy`, `tenant`, `keycloak`, `okta`, `auth0`, `ping`, `forgerock`,
  `google`, `gitlab`, plus terms the author's list does not carry: `msal`,
  `login.microsoftonline`, `sts.windows`, `live.com`, `outlook`, `hotmail`, `aad`,
  `adfs`, `active directory`, `B2C_1`, `msidentity`, `trustframework`,
  `signuporsignin`, `identityexperienceframework`. The extra patterns return zero
  hits anywhere in the folder.
- **Every core-pattern hit located and dispositioned against D14 as recorded** (the
  sharp test: does the rule classify the hit the way the artifacts do?). Hit counts:
  `specs/mcp-signin/spec.md` 0; `release-notes-draft.md` 0; `proposal.md` 2 (the Why
  tested-case identification and the What-Changes tested-case bullet — both Class B
  per D14's enumeration, both identification, not prescription); `tasks.md` 1 product
  hit (task 7.1, the enumerated live-run row); `design.md` 32 (Context paragraph,
  D9, D14's own rule text, OQ-A/OQ-B — enumerated Class B — and OQ-E, which is not;
  see R3-2); `evidence/` historical records (Class B by declaration, quoting text as
  it stood).
- **The delta spec read whole.** Zero product vocabulary; the only `polic*`
  occurrences are generic "session policy" (the refresh requirement, unchanged) —
  correctly ruled not the product concept. No provenance citations: the amendment
  notes name mechanisms ("an operator prerequisite the change's configuration
  reference states, not a property this spec grants"), never meetings or rounds;
  the "tested provider family" phrase that used to sit in the verification
  amendment note is gone.
- **The round-3 diff read whole** (`git diff` vs `ac86d6e`, all five artifacts,
  207 insertions / 123 deletions) — the basis for every losslessness and regression
  claim below.
- **Gates re-run:** `openspec validate generalized-idp-federation` — **valid**
  (exit 0). `python scripts/check_publication_leaks.py` (main checkout venv,
  `PYTHONUTF8=1`, run against the worktree's tracked files) — **PASS** (202 files
  scanned; 3 findings, all pre-existing and waived — two in
  `docs/evidence/d0a/review-round-1.md`, one in `scripts/import_background.py`; 0
  unwaived). Matches the authoring note's record.

## Losslessness under neutral wording — verified

- **(a) The D6 pin.** Spec, verification requirement: "a token from any other
  issuer, another policy of the same tenant included" became "a token whose issuer
  differs in any way — another journey's issuer of the same provider included …
  MUST be refused as not issued by the configured provider". Same force — "any other
  issuer" and "differs in any way" are the same set, the refusal reason is retained,
  and "same tenant" → "same provider" is the correct class-level rendering (the
  issuer-embedding gloss moves with it). The scenario's WHEN/THEN pair carries the
  same content; the amendment note's provider-configuration caveat ("whether another
  journey's tokens carry a distinct issuer at all is provider-configuration — the
  provider must issue journey-distinct issuers for its journeys to be
  distinguishable by the pin") preserves R1-F3's construction-vs-configuration split
  exactly. The proposal's pinning bullet got *stronger*, not weaker: "No
  `{tenantid}`-style templating" became "No pattern, prefix, or templated issuer
  matching". D6's concrete issuer spellings moved to Context/D9 and remain reachable
  by pointer; which flavor the owner's tenant uses "decides only the literal, never
  the mechanism" — no dilution found.
- **(b) F3's operator prerequisite.** Task 5.1's generic row is followable by an
  operator of any varying-issuer provider: configure the provider for
  journey-distinct issuance; where that is a provider-side setting it must be
  enabled; with it absent every sign-in fails at issuer verification, and that
  failure is diagnosable from this stated prerequisite. The concrete property
  ("Issuer (iss) claim", off by default), the tfp-path fact, and the
  `<tenant>.onmicrosoft.com/{policy}` direct-mode spellings all live in the
  Context/D9 record and OQ-A, and task 7.1 cites them explicitly (including "the
  concrete form of the generic prerequisite task 5.1's operator row states") — the
  live run is executable from 7.1 + D9 + OQ-A without anything the round removed.
  The verified vs live-run-to-verify separation is intact in Context, D1, D9, OQ-A,
  and 7.1.
- **(c) The threat row.** EP5/DT-EP5-5 "Sibling-policy token accepted by a relaxed
  issuer match" → "Another journey's token accepted by a relaxed issuer match": same
  threat class — a "helpful" prefix/tenant/templated issuer match accepting a token
  minted under a different sign-in configuration of the same provider, minting a
  gateway token from its claims. The distinguishability precondition and the
  priced-not-mitigated framing are unchanged. Task 1.1's re-worded row name matches
  DT-EP5-5's new title, so the task and the SIA stay in lockstep (F1/F4 preserved).

## Neologism quality — verified, one nuance recorded

The four coined terms are defined at first coinage (D14), used consistently across
the spec, release notes, proposal, tasks, and design (no two-ways drift found:
"journey" always means the sign-in journey; "journey-varying issuers" /
"varying-issuer provider" / "journey-distinct issuance" are stable adjectival
variants), and the spec uses them with an inline gloss ("the issuer embedding the
journey that issued the token") while the normative force never depends on the
reader's interpretation of "journey" — the MUST is "a token whose issuer differs in
any way … MUST be refused". One nuance, not a defect: D14 defines "varying-issuer
provider" as issuers varying "across the provider's sign-in journeys **or
tenants**" — which honestly includes the tenant-varying workforce shape Context
marks out of scope; this is coherent because Non-Goals rejects only `{tenantid}`
*templating*, not the exact pin of one tenant's issuer, and the pin treats both
variation kinds identically. Design keeps the richer wording (family anaphora with
Context/D9 pointers), which is where it belongs.

## Regression — rounds 1–2 dispositions hold

- **F3** survives re-homed (verified above). **F4** survives: task 1.1's
  threat-model scoping rule is untouched except the row name, which matches the
  SIA's re-titled row. **R2-2** survives: the plain-http-issuer scenario's
  anchor-rationale ("the configured issuer is the identity anchor in both modes…")
  is untouched by the round-3 diff. **R2-4** survives: the qualifier-seated key-set
  clause ("the origin-bound qualifier belongs to the discovery alternative only —
  the operator-configured key-set URL is operator input at the issuer setting's own
  trust level, not a discovered endpoint") is untouched.
- **D11 and its six scenarios** are intact in the delta spec (full trio skips
  discovery; partial refuses startup; malformed/non-absolute refuses startup;
  plain-http refused without the override; override re-addresses server-to-server
  legs only; stale endpoint fails the leg closed) — the round-3 diff does not touch
  the requirement.
- **The never-cut table** is unchanged in membership and rulings; row 3 alone was
  re-worded ("exact issuer pinning (D6) strengthens identity provenance — a sibling
  journey's token is refused wherever the provider issues journey-distinct
  issuers"), substance preserved.
- **Publication discipline**: `<tenant>`/`<policy>`/`<domain>` placeholders retained
  in the working artifacts; no real hostnames anywhere in the folder (the leak
  check's waived baseline is pre-existing and untouched by this change); the D8
  local-instance boundary (Keycloak rename objects, helper-scoped settings) is
  untouched and correctly outside this round's scope.

## Findings

### R3-1 — task 5.1's direct-mode trigger embeds a tested-family reference inside the operator-doc content prescription

- **Severity:** medium (not blocking for the owner re-pause; must be dispositioned
  before task 5.1 executes, because the row prescribes the very doc content at
  issue).
- **Evidence:** tasks.md 5.1, the direct-configuration clause: "when to configure
  the trio instead of discovery — a provider whose discovery is unavailable,
  nonstandard, or served at a spelling the fetch does not reach, **the tested
  family's classic flavor included should its per-journey-path discovery fact fail
  (design.md D9)**". The row's own opening declares the boundary — "all of it in
  provider-neutral vocabulary per the round-3 boundary (design.md D14 — the operator
  reference names classes and mechanisms, never the tested family's products)" —
  and D14's Class A includes "the operator-facing documentation content the tasks
  prescribe … These name provider classes and mechanisms only." The clause sits
  inside that content description. Round 2's version ("including classic B2C should
  the tfp-path discovery fact fail") worked as doc content because round-2 operator
  docs could still name the family; round 3 changed the doc-content rule but kept
  the clause's shape, swapping in an anaphor ("the tested family's classic flavor",
  "its per-journey-path discovery fact") that resolves only inside the change
  folder — by D14's own rule the published reference can never define it. Followed
  literally, the operator reference would carry an unresolvable family reference.
  The neutral class condition already subsumes the trigger completely.
- **Disposition requested:** re-word the clause to the provider-class condition
  alone (a provider whose discovery is unavailable, nonstandard, or served at a
  spelling the fetch does not reach), or explicitly mark the family clause as
  implementer context (why the mode exists) rather than doc content, so the
  implementer cannot transcribe it into `docs/gateway-configuration.md`.

### R3-2 — D14's Class B enumeration is narrower than the artifacts' practice; the check claim is falsified in the letter

- **Severity:** low.
- **Evidence:** three instances, one root cause. (a) OQ-E carries outright product
  names — "the live B2C run may show Microsoft's discovery endpoint is slow enough
  to prefer a longer default" (design.md §8) — but D14's Class B enumerates only
  "the open questions that track live-run facts (OQ-A, OQ-B)"; the authoring note
  claims OQ-A/OQ-B/OQ-E were kept as Class B. The rule as recorded does not
  classify the hit the way the artifacts treat it, so D14's own check claim ("every
  remaining hit in the change folder sits inside an enumerated Class B zone") is
  false as stated. (b) Task 6.1 — a Class-A gate row — contains the quotative
  "`<policy>`" placeholder mention, also outside the enumerated zones (quotative,
  describing what the working artifacts carry; no product concept is being used).
  (c) Design mechanism sections outside Context/D9 (Goals, SIA §1, D6, D10, D11,
  D12) carry family anaphora — "the tested family", "the external
  customer-identity family", "either flavor", "the classic flavor", "the
  successor", "that vendor" — which D14's two-class enumeration does not classify
  at all. None of it names a product, so the owner's directive is honored; but the
  recorded rule describes a binary the round did not actually implement (design
  mechanism sections are a third, intermediate tier: Class A vocabulary plus family
  anaphora with pointers). Relatedly, the author's own sweep pattern list includes
  `customer-identity`, yet Class-A-treated sections (Goals, SIA §1) still carry
  "customer-identity family" with no recorded disposition — the term is a generic
  CIAM category, not a vendor product, but the sweep record never says so.
- **Disposition requested:** extend D14's enumeration to match the practice — add
  OQ-E to the live-run open questions; state the design mechanism sections' status
  (family anaphora with Context/D9 pointers permitted, product names not); record
  the ruling that `customer-identity` is a generic category term, not product
  vocabulary, so the sweep's pattern list and its dispositions agree. Alternatively
  neutralize OQ-E's "Microsoft" mention ("the tested provider's discovery
  endpoint") — the sentence loses nothing.

### R3-3 — the accepted reachability trade for the tested family's operator, recorded for the owner re-pause

- **Severity:** low (observation-grade; D14 already acknowledges the trade — this
  records it so the owner decides with it visible).
- **Evidence:** after this change, an operator of the tested family who hits
  "every sign-in fails at issuer verification" finds the generic
  journey-distinct-issuance prerequisite in the published operator reference but
  not the concrete property ("Issuer (iss) claim", off by default) — that lives in
  the D9 record and task 7.1, which stay in-repo through archive but never reach
  the operator docs. D14 states the reachability path ("the tested family's
  operator reaches the concrete setting through the record this change ships") and
  F3's diagnosability rationale survives in generic form; the cost is one search
  step for one provider family's operators.
- **Disposition requested:** none beyond acknowledgment at the pause; if the owner
  wants the concrete property reachable from the reference without naming the
  product, a neutral pointer ("see the change record for the tested provider's
  concrete property") is the compatible form.

## Verdict

The reformulation is real, near-complete, and lossless where it matters: the delta
spec and release notes are verifiably zero-hit under a wider pattern net than the
author's; every re-worded normative clause carries the same or stronger force; the
D6 pin, the F3 prerequisite chain, the D11 requirement, and the never-cut table are
intact; both gates reproduce green independently. The sweep is not a whitewash —
the one place it over-claimed is D14's own enumeration (R3-2), not the Class-A
surfaces. **The package is ready for the re-pause**; R3-1 must be dispositioned
before task 5.1 executes, and R3-2's enumeration fix keeps the boundary checkable
as written.

## Dispositions (the revision round, 2026-11-04)

Author: the revision-round author. No mechanism decision re-opened and D14's boundary
stands — all three findings are precision fixes that make the recorded rule and the
artifacts agree.

- **R3-1 — fixed by re-wording to the provider-class condition** (the option that
  keeps the operator docs self-contained). Task 5.1's direct-configuration trigger
  now reads "a provider whose discovery is unavailable, nonstandard, or served at a
  spelling the fetch does not reach, journey-distinct-issuance providers whose
  discovery document cannot be relied upon included" — pure class vocabulary, every
  term defined inside the operator reference itself (journey-distinct issuance is
  defined by the row's own prerequisite statement), so transcribing the row into
  `docs/gateway-configuration.md` can no longer plant an unresolvable family
  reference. The choice, recorded as requested: re-word rather than relocate the
  clause to implementer context, because the class condition already subsumes the
  concrete case completely (a flavor whose per-journey-path discovery fact fails is
  a journey-distinct-issuance provider whose discovery document cannot be relied
  upon), so the published reference loses nothing by stating only the class, while a
  relocated implementer-context clause would have preserved the family shape at the
  cost of a second thing the implementer must remember not to transcribe. Nothing is
  lost for the live run: the concrete contingency stays where it is read from —
  design.md D9 and D11, OQ-A, and task 7.1's own "if the tfp-path fact fails,
  configure the direct endpoint trio" clause — and the proposal's direct-endpoint
  bullet already stated the same class condition, so the task row and the proposal
  agree again.
- **R3-2 — fixed by extending the enumeration** (the preferred option; OQ-E's
  product mention stands as Class B rather than being neutralized). Design.md D14
  changed in four places: (a) Class B's live-run open questions now enumerate
  OQ-A, OQ-B, OQ-E; (b) a new paragraph states the intermediate tier the artifacts
  in fact implement — the design's mechanism sections outside the Class B record
  zones (Goals, Non-Goals, the decisions D1–D8 and D10–D13, the SIA, the Risks, the
  Migration Plan) use Class A vocabulary and may carry family anaphora ("the tested
  family", "either flavor", "the classic flavor", "the successor", "that vendor",
  "the tested external tenant/provider", "the tested deployment/shape") resolving
  through Context/D9 pointers, never product names — with the sections that carry
  it today named, so the statement is checkable against the sweep; (c) the explicit
  ruling that "customer-identity" (and "the external customer-identity family") is
  the generic CIAM category — external providers whose user population is the
  deployment's customers — not product vocabulary, so the sweep's pattern list
  (which carries the term) and its dispositions agree; (d) the check paragraph now
  counts the mechanism sections' anaphora and task 6.1's quotative
  `<tenant>`/`<policy>` placeholder mention among the permitted remaining hits, so
  the self-check claim — every remaining hit in the change folder sits inside an
  enumerated Class B zone, permitted anaphora, a quotative placeholder mention, or
  the D8 boundary — is true in the letter.
- **R3-3 — acknowledged; no artifact change.** The reachability trade is
  D14-acknowledged ("the tested family's operator reaches the concrete setting
  through the record this change ships") and stays as recorded: the concrete
  operator property ("Issuer (iss) claim", off by default) lives in design.md
  D9/Context and task 7.1 — in-repo through archive, never in the published
  operator reference — a cost of one search step for the one family's operators,
  left visible for the owner at the re-pause. The compatible neutral-pointer form
  ("see the change record for the tested provider's concrete property"), should the
  owner want the property reachable without naming the product, is on record in the
  finding above.

Validation this round: `openspec validate generalized-idp-federation` — **valid**
(exit 0); `python scripts/check_publication_leaks.py` (main checkout venv,
`PYTHONUTF8=1`, run against the worktree's tracked files) — **PASS** (202 files
scanned; 3 findings, all pre-existing and waived — two in
`docs/evidence/d0a/review-round-1.md`, one in `scripts/import_background.py`; 0
unwaived). Both gates reproduce the round-3 review's and the authoring note's
records.
