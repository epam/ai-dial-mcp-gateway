# D1 — independent review round 1 (the standing TM/SIA instructions)

Reviewer: a fresh independent review subagent (opus), separate from the authoring pass.
Scope: the six D1 artifacts (the two vendored instructions, `docs/security-analysis.md`,
`.claude/skills/security-analysis/SKILL.md`, the `CLAUDE.md` bullet, the `PROCESS.md`
step-8 clause), against the D1/D2 rulings in `docs/production-roadmap.md` §"The iteration,
packaged and ordered", the operator's two source instruction documents, and the repo
context. Two lenses: process/drift conformance, and a security-expert assessment added at
the owner's request mid-pass.

## Verdict: LAND AFTER FINDINGS — no BLOCKERs

## Part A — Drift falsification (the primary duty): PASS

- **Vendored content identity: PASS.** Both `<...-instructions>` blocks diffed
  byte-for-byte against the originals at `dial/documentation/security/instructions/`. The
  TM block is identical except the original's missing final newline; the SIA block is
  identical outright. Both LF, UTF-8, trailing tab after "Eavesdropping" preserved. The
  only added material is the vendoring headers outside the verbatim blocks.
- **Taxonomy and control-order reproduction: PASS.** The taxonomy appears in full only in
  the vendored file (deliberate); the eight control categories are excerpted twice
  (`docs/security-analysis.md` §5.5, `SKILL.md` step 6) — exact source order, no
  paraphrase.
- **The load-bearing sentence is preserved** ("Mitigations are proposed for every
  identified threat — it effectively means that we need to consider mitigations from
  every category (in the order, provided above) for every identified threat"): intact in
  the vendored block and carried with full force by method §5.5 and skill step 6,
  including the "not applicable, with the description why" rule.
- No dropped or reinterpreted source requirement found: the depth dial is superseded
  openly with its reason (R1); the collaborative pause maps to PROCESS 3b/3c (§6);
  "already in-place or planned" maps to the never-cut list + threat model (a
  concretization); R2's fixed order is §3's five steps; R3's placement rule is §5.5 +
  §3.3.

## Part B — Findings (process lens)

**F1 — MAJOR. The skill's input allowlist is insufficient for the run it explicitly
claims to cover (the D2 baseline), and "the disclosed-residual register" does not exist
as a findable artifact.**
`SKILL.md` lines 19–38 (Inputs) and line 3; `docs/security-analysis.md` line 110;
`production-roadmap.md` line 161.
Failure: D2's fresh authoring agent runs the skill as written. The allowlist bars it from
the material the baseline must assemble — the E7 interception variant, the worker-pool
flood queue, the memory-zeroization disclosure, and the token-use rule live in the
archived PoC change's `design.md` (SIA + Risks sections), and the honesty list is
`background/design.md`'s Appendix, not §6. "The disclosed-residual register" is a term
with no document behind it. Outcome: an incomplete baseline (residuals silently missing —
the worst case, because D3 re-judges from that baseline) or a guaranteed Blocking gap.
**Fix before D2:** extend the allowlist for the baseline run (the archived PoC
`design.md`'s SIA and Risks sections; `design.md`'s honesty appendix) and state where the
residual register is assembled from — or make "assemble the register from these named
locations" the baseline run's explicit first step.

**F2 — MINOR. The method cites the PoC archive as precedent while the skill's allowlist
forbids reading it.** `docs/security-analysis.md` lines 54, 38, 121–123; `SKILL.md`
lines 36–38. Internal contradiction (the worked example is unreachable) plus a mild
provenance-as-reason pattern ("fixed by precedent"). Fix: drop "fixed by precedent" or
add the precedent to the allowlist for the per-change run too.

**F3 — MINOR. The `CLAUDE.md` bullet references `docs/threat-model.md`, which does not
exist until D2 lands.** Fix: a one-line parenthetical ("until the D2 baseline lands, the
change's design.md — `docs/security-analysis.md` §3"). Acceptable to land without it if
D2 follows immediately.

**F4 — MINOR. The validation section's conformance test names only the per-change
structure; the baseline shape has no conformance test of its own.**
`docs/security-analysis.md` §7. Fix: one sentence — the baseline and every update to it
get the same fresh-agent, gap-list, double-run treatment.

**F5 — MINOR. The baseline's required content is under-specified** relative to both the
vendored instructions and repo practice: it omits the **attacker inventory** (source
Step 1), the **compromise-point tables** (design.md §6.4 / design-review §5.5 —
key-compromise blast radius is not optional for an AS/key-custody system), and the
**grouped final mitigation list** as the TM's result (the source's closing step). Pin
these three before D2 authoring starts.

Everything else in the process lens clean: no contradictions on the superseded depth dial
across the four artifacts; pre-baseline landing consistent (method §3.4 = skill step 9);
provenance discipline pass; process fit pass (no CI wiring, no OpenSpec-izing); D0a
hygiene pass ("DIAL, DIAL Admin" in the verbatim block is the operator's own text and a
product name, not an internal identifier).

## Part C — Security-expert assessment (owner-requested lens)

**C1. Fitness for this system: capable, with one classification gap.** Token
theft/replay → Spoofing of caller's identity; SSRF/confused-deputy/mix-up → expressible
under Use Control Misconfiguration; key compromise, memory zeroization, store
host-write → expressible via memory/file-system attack surfaces and the compromise-point
tables; role staleness → invariant bound + residual path; denial-of-wallet → Resource
Consumption; consent attribution → mis-use case + Detective control; supply chain → the
source's broad Injection gloss + static gates.

**C2 (the gap) — MINOR. The taxonomy has no logic/flow-flaw leaf**; confused deputy,
SSRF, and mix-up are squatters under the UCM parent, and "use only leaf-level
categories" forces a loose choice (SSRF classifies as Spoofing-of-caller for one agent
and Bypass-Authorization for another — defensible both ways, so the §7 double-run would
flag divergence beyond naming noise and the method would be wrongly tightened). **Fix: a
method note, not a taxonomy extension** (an extension is the operator's ruling and isn't
warranted — the classes are expressible): add a classification convention — flow/logic
flaws classify under Use Control Misconfiguration, the leaf chosen by what the attacker
gains (identity → Spoofing of caller's identity; access → Bypass Authorization), with
the flaw named in the attack-type description.

**C3. The reproduction test: PASS — no known finding the method would have missed.**
Applied as written to design.md §6, design-review §5.1's six entry points, and the
disclosed residuals: the interception-not-guessing distinction is reproduced *more*
structurally than the prose precedent (a full leaf-level enumeration at E6/E7 necessarily
emits both the Spoofing row and the Interception row); the audience-marker's
non-shrinking of key-compromise blast radius reproduces through the compromise-point
tables — with the caveat that per-change SIAs have no compromise-point slot by design, so
C3's SIA must actually exercise the shape-2 clause and the review gate should check it
does; worker-pool flood, memory zeroization, store/host-write, role staleness, consent
attribution all reproduce. Strongest available validation; passed.

**C4 — MINOR. The acceptance path is guarded but the required content of an acceptance is
under-specified.** Gate 4's falsification duty is defined for "no security impact"
claims, not for acceptance *quality* — a reviewer handed "accepted with reasoning:
mitigation not feasible" has no stated criterion to falsify against. The E7 residual is
the model (compensating control: TLS-fronting; accepting condition; re-open trigger). Fix
(one sentence in §1 or §5.7): every disclosed residual records (a) the accepting
condition, (b) the compensating or bounding control where one exists, (c) what change or
deployment fact re-opens it.

**C5 — MINOR. The defense-in-depth order is right; add an anti-boilerplate guard.**
Detective sits last but the audit trail here is load-bearing — the order works because
every category must be *considered* per threat; the position must not demote it. The real
risk is erosion: C2's complete IdP-leg enumeration could produce 20+ threats × 8
categories = 160+ cells, mostly trivially N/A, and N/A boilerplate trains author and
reviewer to skim — the one genuine Anti-DoS or Detective mitigation gets missed. Guard
(one sentence in §5.5 / skill step 6): an N/A reason must name the threat-specific
property that defeats the category, and the per-threat grid is working paper whose
reviewed result is the grouped mitigation list (§5.6).

## Verdicts on the author's four open points

1. **Descriptive canonical-source pointer: satisfies R4's intent** — a literal sibling
   path would have violated the ruling's own purpose (no sibling-path dependencies, D0a
   discipline); the snapshot date is the version identifier for re-vendors.
2. **"No impact" + full SIA: coherent and stronger than it looks** — the full tables are
   what make the claim falsifiable rather than self-certified.
3. **Deferred baseline layout: acceptable division of labor, with F4/F5 as the boundary
   conditions.**
4. **`CLAUDE.md` bullet placement and register: fits**; only nit is F3's dangling
   `docs/threat-model.md` reference until D2 lands.

## Dispositions

All eight findings (F1–F5, C2, C4, C5) were closed by fix pass 1 — see `fix-pass-1.md`
in this folder for the per-finding resolutions. No ruling conflicts arose; C2 landed as
a method note, explicitly not a taxonomy change.
