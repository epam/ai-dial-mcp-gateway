---
name: security-analysis
description: Author the security impact analysis for a change (or the threat-model baseline / an update to it) using the repo's standing method — full SIA on every change, never-cut invariant ruling table, threat tables per touched attack-surface entry point, mitigations in the fixed control-category order. Use when authoring an OpenSpec change's design.md security section, when a change touches a trust boundary, attack surface, or secret material, or when updating docs/threat-model.md.
metadata:
  author: ai-dial-mcp-gateway
  version: "1.0"
---

# Security analysis — operational checklist

A local-run skill: a checklist a session runs while authoring. It is not a CI step, and
nothing here is wired into `.gitlab-ci.yml`. The method and its rationale live in
`docs/security-analysis.md` — read it first; this file is the checklist, not the method.
The attack-type taxonomy and the control categories are the operator's, vendored
verbatim at `docs/background/instructions/threat-modeling.md` and
`docs/background/instructions/security-impact-analysis.md`: reproduce them exactly,
never paraphrase them.

## Inputs — the strict allowlist

Read, and only these. The allowlist has two shapes, one per run — which shape governs
is fixed by what is being authored, not chosen by the agent: the **per-change run**
(an SIA, including a threat-model update made inside a change) and the **full
threat-model run** (the D2 baseline, and a full re-judge of it).

The per-change run:

- `docs/security-analysis.md` — the method (vocabulary mapping, output structure,
  conformance requirement).
- `docs/background/instructions/threat-modeling.md` — the attack-type taxonomy and the
  control categories, verbatim.
- `docs/background/instructions/security-impact-analysis.md` — the SIA's source shape.
- `ROADMAP.md` — the never-cut list: the standing control inventory the SIA starts
  from.
- `docs/threat-model.md` — the current threat model, once it exists. Until the baseline
  exists, the change's own threat material is the baseline's input.
- The change folder being authored — proposal, design so far, delta specs so far.
- `docs/background/design.md` §6 and `docs/background/design-review.md` §5.1 — assets
  and footprints, trust boundaries, the attack-surface inventory, compromise points.

The full threat-model run — the same list, minus the change folder, plus:

- `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/design.md` —
  **the whole document**, its decision sections included: the sections named below
  define their substance only by reference to those decisions, so they cannot be read
  in isolation. It carries the disclosed residuals the baseline must record: memory
  zeroization, the token-use rule, the E7 callback-interception variant, the
  worker-pool flood queue, the store's host/volume boundary.
- The same change's `evidence/` folder — the PoC C acceptance-gate outcome. Without
  it the gate's result is not determinable from allowed inputs; the outcome is a
  disclosed residual's re-open condition.
- The current synced capability spec — `openspec/specs/mcp-signin/spec.md` (at run
  time: whatever capability spec paths exist under `openspec/specs/`). Without it a
  "placed in the gateway spec" claim is unverifiable.
- The as-built deployment shape — this repo's committed `docker-compose.yml`,
  `router/nginx.conf`, and `.env.example`: the published ports, the plain-http front
  door, the file-based signing key, the single instance. A run verifies today's
  deployment facts against these, not against the archived design.
- `docs/background/design.md`'s Appendix ("what is deliberately NOT solved") — the
  honesty list: per-toolset audience binding, live-token revocation, role staleness,
  GLOBAL gating, non-OAUTH exclusion, consent attribution.

Nothing else under either shape: no sibling repositories, no operator originals
outside this repo, no prior-session context. If the analysis cannot be completed from
the list that governs its run, that is a gap — record it in the strict gap list
(step 10); do not go looking elsewhere.

## The full threat-model run

The baseline (D2) and a full re-judge (D3) run the checklist below with these
additions, all required content, not suggestions:

1. **Assemble the disclosed-residual register first.** The register is not a standing
   document; it is assembled at the start of the run from the locations the allowlist
   names for this shape: the archived PoC change's **whole** `design.md` (the decision
   sections included) and the change's `evidence/` folder (the PoC C acceptance-gate
   outcome), plus `background/design.md` (§6.5's role-staleness caveat; the Appendix's
   honesty list). Every residual found there enters the threat model with its
   acceptance record — the accepting condition, the compensating or bounding control
   where one exists, and what change or deployment fact re-opens it
   (`docs/security-analysis.md` §1). **Place the register early in the baseline
   document — before assets and threats** — so dispositions cite backward to the
   already-priced residual they land on. The baseline records the system **as built**,
   today's committed deployment; the re-judge against the finished production shape is
   D3, a separate pass (`production-roadmap.md` §D2/§D3), and the baseline neither
   anticipates it nor treats a production-shape change as a re-open trigger.
2. **The attacker inventory** — potential attackers including legitimate business
   users and high-privileged users such as technical support or administrators, per
   the vendored TM instruction's Step 1.
3. **The compromise-point tables** — what an attacker gains by compromising each
   component, the key-compromise blast radius included (`background/design.md` §6.4
   is the current shape, carried forward to the system as it stands).
4. **The grouped final mitigation list** (step 8) is the threat model's reviewed
   result — required, not a summary.
5. **The full per-threat control grid, in the baseline document itself** — all eight
   categories for every threat, written out (step 6). It is required content, not
   optional volume: the grouped list is the result, but the grid is what the security
   review gate falsifies a "no security impact" claim against.

**Entry-point inventory — the baseline extends §5.1.** The baseline's surface is the
system as built, not `design-review.md` §5.1's six entry points alone: an entry point
the running system presents is enumerated in the baseline even where §5.1 does not name
it (the count is not fixed at six). Each added entry point is enumerated completely,
per step 2's "adds a surface" shape.

## Checklist

1. **State the change** — the business description and the implementation shape. This
   opens the SIA.
2. **Fix the surface scope** — list the attack-surface entry points the change touches
   or creates, from the `design-review.md` §5.1 inventory and the threat model. Name
   which shape this change is: a change on existing surfaces enumerates the delta
   threats (what the change newly enables or alters) per touched entry point; a change
   that adds a surface enumerates that entry point completely — every leaf-level
   attack-type category, the component's nature, hosting, stack, and language taken
   into account. Untouched surfaces are covered by step 4, not re-enumerated.
3. **Impact level, with reasons** — no / low / medium / high, judged on which sensitive
   assets are involved and how exposed they become. Always recorded. It sets the
   security review gate's depth (`CLAUDE.md` gate 4 — a "no impact" claim gets a
   focused pass whose job is to falsify it); it never skips the exercise.
4. **Invariant ruling table** — one row per never-cut invariant, all seven, each ruled
   Preserved or Preserved with a disclosed bound, with the reason. A row that cannot be
   ruled either way stops the change at the owner review pause with the violation
   stated; it is never waved through.
5. **Threat tables, per touched entry point** — the vendored structure, exactly:
   *attack surface entry point for the component, attack type category (use only
   leaf-level categories, show a full path to the category), attack type name, target
   sensitive footprint of the asset, what is being compromised (Confidentiality,
   Integrity or Availability), attack type description*. Attack vectors start from a
   trust boundary or another component and target a sensitive asset's footprint via the
   entry point. Include **mis-use cases** — a legitimate or privileged user (technical
   support, an administrator) using the new behavior exactly as permitted, in a way the
   system should not reward. Flow and logic flaws — confused deputy, SSRF, mix-up —
   classify under Use Control Misconfiguration; the leaf is what the attacker gains
   (identity → Spoofing of caller's identity, access → Bypass Authorization), and the
   flaw is named in the attack-type description (`docs/security-analysis.md` §5.4).
   **Leaf selection is a general convention, not a Use-Control special rule:** the leaf
   follows the attacker's *gain*, not the mechanism, so a shape with no obvious leaf
   (host secret-file read, configuration tampering, log-content manipulation,
   information disclosure at rest) is filed under the leaf of what the attacker ends up
   holding — never under a leaf invented for it. Treat the taxonomy as closed; a shape
   with no fitting leaf is a gap (step 10), not a new category
   (`docs/security-analysis.md` §5.4).
6. **Mitigations, per threat, in this exact order** — the operator's control
   categories; every category appears for every threat, "not applicable, because …"
   where it is:
   1. Reduce Attack Surface
   2. Isolation
   3. Authentication
   4. Authorization
   5. Data Protection
   6. Anti-Injection
   7. Anti-DoS
   8. Detective controls

   Every "not applicable, because …" names the threat-specific property that defeats
   the category, never a generic dismissal — boilerplate N/A trains author and
   reviewer to skim, and the one genuine Anti-DoS or Detective mitigation is exactly
   what skimming loses. The per-threat grid is working paper; the reviewed result is
   the grouped mitigation list (step 8).
7. **Name every mitigation's home** — delta spec (gateway-owned behavior; the
   requirement must actually be in the delta spec, not only in this analysis — a
   mitigation that exists only in prose is not landed), Core configuration, the
   deployment, or an upstream, with its owner. A threat with no mitigation is accepted
   with reasoning: a **disclosed residual**, landing in the threat model with its
   acceptance record — the accepting condition, the compensating or bounding control
   where one exists, and what change or deployment fact re-opens it
   (`docs/security-analysis.md` §1).
8. **Group the mitigations** — review the per-threat proposals and group them (one
   mitigation often addresses several threats) into the final list, each mitigation
   associated with the threats it addresses. This grouped list is the SIA's result.
9. **Update the threat model** — new threats, changed dispositions, re-judged
   residuals: the affected entries of `docs/threat-model.md` (or, before the baseline
   exists, the change's design.md section that the baseline will absorb).
10. **Record open questions and the strict gap list** — unresolved questions for the
    reviews (`PROCESS.md` step 3b independent review, step 3c owner pause — that is
    where "stop and let others evaluate" lives); and the strict gap list: every point
    where the allowed inputs did not suffice, severity-tagged (Blocking / Major /
    Minor). A Blocking or repeated gap is a defect in the method docs — fix
    `docs/security-analysis.md` (and this skill) before trusting the analysis.

## Conformance

The SIA is done when a fresh reviewer can run the security review gate (`CLAUDE.md`
gate 4 / `PROCESS.md` step 8) against the implementation diff using only the change's
SIA and the threat model — falsifying "no security impact" claims included. If the gate
cannot be run from what this checklist produced, the SIA is not done.
