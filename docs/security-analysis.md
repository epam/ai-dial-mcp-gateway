# Security analysis — the standing method

**What this document is.** The normative method for threat modeling (TM) and security
impact analysis (SIA) in this repository: what a full SIA contains, what the threat
model records, in what order the work runs, and how both are validated. The substance —
the attack-type taxonomy and the security-control categories and their order — is the
operator's, vendored verbatim in
[`docs/background/instructions/`](background/instructions/) and never paraphrased or
redesigned here. This document carries the *adaptation*: how the operator's process
runs inside this repo's loop. The rulings it encodes are recorded in
[`docs/production-roadmap.md`](production-roadmap.md) §D1. The operational checklist is
the local `security-analysis` skill (`.claude/skills/security-analysis/`); this document
is the method that skill implements.

**Why a full SIA on every change.** The vendored SIA instruction's two-step depth dial
(impact level first; the detailed exercise only if medium/high) exists to ration a
security *team's* involvement. This repo runs the analysis itself — the SIA is authored
by the change's own authoring pass (`PROCESS.md`'s roles: authoring is an opus
subagent) inside the change folder — so there is no involvement to ration. The analysis
runs in full every time; the impact level is still evaluated and recorded, and it sets
the security review gate's depth, never whether the analysis happens. The point of
running it every time is not ceremony: **the SIA's essence is keeping the threat model
current with every change**, and a threat model that lags the code is a record of a
system that no longer exists.

## 1. Vocabulary — the mapping is normative

The vendored instructions and this repo's established practice name the same things
differently in a few places. The mapping is normative: use the repo's term in repo
artifacts, and read the operator's term in the vendored instructions through it.

| The vendored instructions say | This repo says | The mapping |
|---|---|---|
| a threat **accepted with reasoning** | a **disclosed residual** | the same act: a threat knowingly not mitigated, on record in three parts — (a) the accepting condition, (b) the compensating or bounding control where one exists, (c) what change or deployment fact re-opens it. The disclosure's home is the threat model — not a risk paragraph alone — and re-judging every disclosed residual in the production shape is the closing pass (`production-roadmap.md` §D3). The complete record's shape is modeled by the E7 interception-variant residual in `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/design.md`, §"Security impact analysis (against the never-cut list)" (accepting condition: the committed deployment's plain-http front door; bounding control: TLS-fronting the public origin; re-open trigger: a TLS-fronted deployment). |
| "controls and mitigations **already in-place or planned**" | the **never-cut list** plus the threat model's mapped mitigations | the standing control inventory every SIA starts from (§2); the never-cut list is the never-traded floor of that inventory. |
| Trust Boundaries; attack surface; attack vectors | the same terms | as established in [`background/design.md`](background/design.md) §6 and [`background/design-review.md`](background/design-review.md) §5.1. |
| attack surface **entry point** | **attack-surface entry point** | the itemized inventory — `design-review.md` §5.1's six entry points as the *starting* inventory, which the baseline **extends to the system as built** (§4): the entry-point count is not fixed at six. The unit a threat table is written per. |
| — (no source term) | **Preserved / Preserved with a disclosed bound** | the ruling values of the invariant check (§2): every invariant is ruled explicitly — preserved outright, or preserved with the bound stated. |
| — (no source term) | **compromise points** | the component-compromise tables (`design.md` §6.4, `design-review.md` §5.5): what an attacker gains per compromised component. |
| — (no source term) | **disposition** | a threat's verdict: mitigated (implementation and owner named) or accepted with reasoning (= a disclosed residual). |

## 2. The never-cut list is the standing control inventory

Every SIA starts from what is already in place — the vendored instruction's "specify
which controls and mitigations already in-place or planned". In this repo that
inventory is not recollected per analysis; it stands in two documents:

- **The never-cut list** (`ROADMAP.md`) — seven invariants that hold at every stage and
  are never cut. It is the inventory's floor: an SIA does not evaluate whether these
  controls are a good idea; it checks the change against them.
- **The threat model's mapped mitigations** (`docs/threat-model.md`, once the baseline
  exists) — the per-surface record of what is already deployed against which threat.

The check against the inventory is the SIA's first table, and its format follows from
the check itself: one row per never-cut invariant, ruled **Preserved** or **Preserved
with a disclosed bound**, with the reason — the check is per invariant, so the table
is too, and nothing is summarized away. A row that cannot be ruled either way does not
proceed to implementation: the change either gains the mitigation that preserves the
invariant, or it stops at the owner review pause (`PROCESS.md` step 3c) with the
violation stated.

## 3. The order of work

The SIA is not a report written after the design; it is part of the design, and its
order is the point (`production-roadmap.md` §D1):

1. **Plan the change** — the proposal and design as authored so far.
2. **Enumerate the new threats** the change brings, per touched attack-surface entry
   point (§4–§5).
3. **Land the necessary mitigations in the delta specs.** A gateway-owned mitigation
   that exists only in the SIA's prose is not landed: it is a delta-spec requirement,
   or it does not exist. A mitigation the gateway does not own is stated with its
   implementation home — Core configuration, the deployment, an upstream — and its
   owner.
4. **Update the threat model.** New threats, changed dispositions, and re-judged
   residuals land in `docs/threat-model.md`. Until the baseline exists (the D2
   workstream), they land in the change's `design.md` as the baseline's input; from the
   baseline on, every change updates the affected entries directly — the standing rule
   (`production-roadmap.md` §D3).
5. **Then implement.** The security review gate (`CLAUDE.md` gate 4 / `PROCESS.md`
   step 8) reviews the implementation diff against exactly the two artifacts this
   order produced: the change's SIA and the threat model. That is the conformance
   requirement: **if a reviewer cannot run that gate from what the SIA produced, the
   SIA is non-conforming** and is fixed before implementation proceeds.

## 4. What "full" means — proportional enumeration

The vendored instruction's depth dial is not used (§ "Why a full SIA on every change");
"full" therefore does not scale by impact level. It scales by what the change touches —
proportional enumeration, not a fixed page count:

- **A change on existing surfaces** — touches existing flows; adds no endpoint, grant
  type, trust boundary, or credential (C1's shape: dynamic MCPs, fresh claims at
  refresh). For every entry point the change touches: a threat table of the threats the
  change *newly enables or alters* (the delta threats), and a full control-category
  pass for each of them (§5.5). Surfaces the change does not touch are covered by the
  invariant ruling table (§2), not re-enumerated.
- **A change that adds a surface** — a new endpoint or trust boundary, or new secret
  material the process holds (C2's shape: the generalized IdP leg against a new
  provider; C3's shape: the KMS sign-interface and the pod). Everything in the previous
  shape, plus: the new entry point is enumerated *completely* — every leaf-level
  attack-type category considered, the component's nature, hosting, stack, and language
  taken into account per the vendored instructions — and, where a trust boundary or
  credential changes, the asset/footprint and compromise-point tables are updated with
  it.
- **The full threat model** — the D2 baseline and the D3 closing re-judge: all attack
  surfaces and attack vectors enumerated, all mitigations mapped, in the vendored
  instructions' structure, with no delta scoping. The baseline's sources are
  `background/design.md` §6 (consent attribution, trust concentration, the revocation
  and component-compromise tables, invariants re-checked), `design-review.md` §5.1 (the
  itemized attack surface — the *starting* inventory, which the baseline extends to the
  system as built: the as-built shape adds surface §5.1 does not itemize, so an entry
  point the running system presents is enumerated in the baseline even where §5.1 does
  not name it, and the entry-point count is not fixed at six), the never-cut list, and
  the disclosed-residual register; its structure must carry all of that
  (`production-roadmap.md` §D2). The baseline also sources the **current synced capability
  spec** (`openspec/specs/mcp-signin/spec.md`, or whatever capability spec paths exist
  under `openspec/specs/` at run time) — without it every "placed in the gateway spec"
  claim is unverifiable — and the **as-built deployment shape**: this repo's committed
  `docker-compose.yml`, `router/nginx.conf`, and `.env.example`, the sources that fix the
  facts a run must verify against reality rather than infer from the archived design (the
  published ports, the plain-http front door, the file-based signing key, the single
  instance). The register is not a standing document: it is assembled as the baseline
  run's **first step, and placed early in the baseline document** — before assets and
  threats — so dispositions can cite backward to the already-priced residual they land
  on. It is assembled from the archived PoC change's `design.md` (**whole**, its decision
  sections included: the named sections define their substance only by reference to the
  decisions, so a run cannot read them in isolation) and from `background/design.md`
  (§6.5's role-staleness caveat; the Appendix's honesty list). The baseline's required
  content, beyond the per-change structure (§5): the **attacker inventory** — potential
  attackers including legitimate business users and high-privileged users such as
  technical support or administrators, per the vendored TM instruction's Step 1; the
  **compromise-point tables** — what an attacker gains by compromising each
  component, the key-compromise blast radius included (`background/design.md` §6.4 is
  the current shape, carried forward to the system as it stands); the **grouped
  final mitigation list** (§5.6) as the threat model's reviewed result; and the
  **full per-threat control grid** — all eight categories for every threat, written in
  the baseline document itself, so the grid's volume cannot differ between runs.

**The disposition boundary — today's shape, then the production-shape re-judge.** The D2
baseline records the system **as built**, today's committed deployment — it is not the
finished production shape and does not re-judge residuals against one. The re-judgement
of every disclosed residual in the production shape (K8s ingress TLS, KMS key, no HA,
real users) is D3's closing pass, and its verdicts land in the same threat model
(`production-roadmap.md` §D2, §D3). A baseline run therefore holds each residual at its
accepting condition as recorded; it neither anticipates the production shape nor treats a
production-shape change as a re-open trigger. From the baseline on, the standing rule is
that every change updates the threat model's affected entries as part of its own SIA
(`production-roadmap.md` §D3).

Mis-use cases belong to enumeration in every shape, per the vendored SIA instruction: a
legitimate user, or a privileged one (technical support, an administrator), using the
new behavior exactly as permitted, in a way the system should not reward. They are
where per-user isolation and authorization invariants are usually attacked, and they
are enumerated as threats in the same tables.

## 5. The per-change SIA's output structure

A conforming per-change SIA is a section of the change's `design.md` and contains, in
order:

1. **Change description** — the business description and the implementation shape (the
   vendored instruction's opening step).
2. **Impact level, with reasons** — no / low / medium / high, judged on which sensitive
   assets are involved and how exposed they are to confidentiality/integrity/availability
   attacks once the change lands. Always recorded. It sets the security review gate's
   depth — a "no impact" level is exactly the claim `CLAUDE.md` gate 4 exists to
   *falsify* — and never gates the exercise.
3. **Invariant ruling table** — one row per never-cut invariant (§2).
4. **Threat tables, per touched entry point** — the vendored structure, exactly:
   *attack surface entry point for the component, attack type category (use only
   leaf-level categories, show a full path to the category), attack type name, target
   sensitive footprint of the asset, what is being compromised (Confidentiality,
   Integrity or Availability), attack type description*. Mis-use cases included (§4).
   Classification convention for flow and logic flaws — a method note, not a taxonomy
   change: confused-deputy, SSRF, and OAuth mix-up situations classify under Use
   Control Misconfiguration, whose own gloss they are (persuading a component to do
   the wrong thing without hacking it). The leaf is chosen by what the attacker
   gains: identity → Spoofing of caller's identity; access → Bypass Authorization.
   The flaw itself is named in the attack-type description.
   **Choosing the leaf is a general convention, not a special rule for Use-Control
   flaws.** In every case the leaf follows the attacker's *gain*, not the mechanism that
   produced it: a mechanism the taxonomy has no leaf for is filed under the leaf of what
   the attacker ends up holding. Worked shapes so independent runs classify identically:
   reading a secret file on the host → the confidentiality leaf for the material read
   (the host boundary named in the description), never a new "file read" leaf;
   tampering with configuration the process trusts → the integrity leaf for the decision
   the tampered config steers; manipulating what reaches the log → the integrity leaf for
   the audit record's content; information disclosure of material at rest → the
   confidentiality leaf, the store named as the footprint. Treat the taxonomy as closed:
   a real shape with no obvious leaf is filed by gain, and the mismatch is raised as a
   gap (step 10) rather than resolved by inventing a leaf.
5. **Mitigations per threat, in the vendored control-category order** — Reduce Attack
   Surface, Isolation, Authentication, Authorization, Data Protection, Anti-Injection,
   Anti-DoS, Detective controls. Every category appears for every threat, including as
   an explicit "not applicable, because …". Each mitigation names where it is
   implemented (delta spec / Core configuration / deployment / upstream) and who owns
   it; a gateway-owned mitigation's requirement is in the delta spec itself (§3.3).
   An explicit "not applicable" names the threat-specific property that defeats the
   category ("this vector never crosses a boundary an isolation control could draw"),
   never a generic dismissal — boilerplate N/A trains author and reviewer to skim, and
   the one genuine Anti-DoS or Detective mitigation is exactly what skimming loses.
   The per-threat grid is working paper; the reviewed result is the grouped
   mitigation list (§5.6).
6. **The grouped mitigation list** — the vendored instruction's closing step: the
   per-threat proposals are reviewed and grouped (one mitigation often addresses
   several threats) into the final list, each mitigation associated with the threats it
   addresses. This list is the analysis's result.
7. **The threat-model delta** — the entries `docs/threat-model.md` gains or changes:
   new threats, changed dispositions, residuals this change re-judges (§3.4).
8. **Open questions** — what the analysis could not resolve, phrased for the reviews
   (§6), never left implicit.

## 6. Where the collaborative step lives

The vendored TM instructions pause after each component or flow: "stop and let others
evaluate, ask questions and comment". Mapped onto this repo's loop, that step is not an
interactive pause during authoring; it is the loop's fixed review points (`PROCESS.md`
step 3):

- **The independent review of the change artifacts (3b)** reviews the SIA with the rest
  of the design — the evaluator and commenter the instruction calls for, at the
  artifact level.
- **The owner review pause (3c)** presents the complete package, the SIA and its
  rulings included, and nothing proceeds without the owner's go.

The SIA is therefore authored as one exercise, not interleaved component-by-component
with human pauses, and its unresolved questions land in its open-questions list (§5.8)
so they reach both reviews as artifacts rather than as scrollback. That is how an
interactive instruction becomes a workflow instruction, at exactly the points the loop
already guarantees an evaluator.

## 7. Validation — the conformance test

The method is validated by use, and its test is a fresh agent — `PROCESS.md`'s
agent-freshness rule applied to this method itself (`production-roadmap.md` §D1):

- **First full application: C1's SIA.** The authored artifacts are proven by C1 using
  them. A defect C1 finds in the method is fixed in this document and in the skill —
  not patched around in the analysis.
- **The conformance test.** A fresh subagent, given only this repository's documents,
  must be able to produce a conforming analysis (§5's structure, §4's scope). The
  input allowlist has two shapes, one per run. The **per-change run** (an SIA,
  including a threat-model update made inside a change): this document; the vendored
  instructions; `ROADMAP.md`; `docs/threat-model.md` once it exists; the change
  folder being analyzed; and `background/design.md` §6 + `background/design-review.md`
  §5.1 for the surface inventory. The **full threat-model run** (the D2 baseline, and
  a full re-judge of it) uses the same list minus the change folder, plus the
  archived PoC change's `design.md` (**whole** — its decision sections carry the
  substance the named sections define by reference), the archived PoC change's
  **evidence folder** (the PoC C acceptance-gate outcome record, so the acceptance
  gate's result is determinable rather than inferred from the change's archived
  location), the **current synced capability spec** (`openspec/specs/mcp-signin/spec.md`
  — at run time, whatever capability spec paths exist under `openspec/specs/`), the
  **as-built deployment shape** (this repo's committed `docker-compose.yml`,
  `router/nginx.conf`, and `.env.example` — the ports, the plain-http front door, the
  file-based signing key, and the single instance a run must verify rather than infer),
  and `background/design.md`'s Appendix —
  the sources of the disclosed-residual register the baseline assembles first (§4).
  Nothing outside the repository — the operator's originals included — and no session
  context, under either shape. With the analysis, the agent emits a **strict gap
  list**: every point where the allowed inputs did not suffice, severity-tagged
  (Blocking / Major / Minor). A Blocking gap, or a gap that repeats across independent
  runs, means this document is wrong and is fixed before the analysis's results are
  trusted.
- **The baseline shape is not exempt.** The D2 baseline and every update to the
  threat model after it — per-change deltas and full re-judges alike — get the same
  treatment the conformance test defines: a fresh agent from the allowed inputs, the
  strict gap list, and the double-run at the shape's first application (the
  baseline's first application is D2 itself).
- **Reproducibility.** At the first application, two independent fresh runs of the same
  case; their outputs are compared (threat sets per entry point, dispositions, the
  grouped mitigation lists). Divergence beyond naming noise means the method
  underspecifies, and this document is tightened before either run's result is used.

## 8. Local-run, not CI

The `security-analysis` skill is a local Claude Code skill — a checklist a session runs
while authoring. Nothing in this method wires into CI: machine enforcement in the
pipeline is the static tier's leak check, a separate workstream; the SIA's own
enforcement is the review gates that read what it produced (§3 step 5, §5).
