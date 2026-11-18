# D2 baseline run B — strict gap list

**What this is.** The strict gap list of the full threat-model run (D2, run B):
every point where the run's allowed inputs were missing, ambiguous, or contradictory
for producing the baseline, severity-tagged (BLOCKING / MAJOR / MINOR), plus
meta-commentary on where the method was hard to follow. The threat model itself is
`docs/evidence/d2/threat-model-runB.md`. No gap below was worked around by reading
outside the allowlist.

## Gaps

- **[MAJOR] G-1 — the current spec is not on the full-run allowlist.** The method's
  own landing rule ("a gateway-owned mitigation that exists only in prose is not
  landed: it is a delta-spec requirement, or it does not exist") cannot be verified
  by this run: the `mcp-signin` spec's text (now under `openspec/specs/`) is outside
  the full-threat-model run's allowlist, which names only the *archived* change's
  design.md. Every "gateway spec" placement in the threat model therefore cites the
  archived design's normative statements instead of the requirements themselves. The
  baseline's in-place claims should be verified against the spec text once. If the
  method intends the baseline to verify landing, the allowlist should name the
  current spec; if not, the landing rule should say the baseline takes the archived
  design's normativity on trust.

- **[MAJOR] G-2 — the PoC C outcome is not on record in the allowed inputs.** The
  archived change's design (both its context and its risks) still describes the
  assembled chain as "unproven until PoC C" with §7-style gated rows, but the change
  sits in `openspec/changes/archive/` — an archived change's gates are closed. No
  allowed document records the gate's outcome or the gated rows' post-PoC
  dispositions. The baseline had to state today's dispositions from the archive's
  location alone (threat model §1, §14 open question 1). A record of the PoC C
  result — or a pointer to where it lives — belongs on the baseline run's input
  list or in the archived change.

- **[MINOR] G-3 — `docs/threat-model.md` on the allowlist vs. this run's brief.**
  The allowlist includes "the current threat model, once it exists"; the run B brief
  forbids reading that path (run A writes it, independence first). No conflict
  materialized — the file does not exist at run time (this run is producing the
  baseline) — but for the D3 full re-judge the two rules will collide if the
  double-run shape is kept: the allowlist will name a path the brief forbids.
  Resolving that before D3 is a method-doc fix, not a per-run workaround.

- **[MINOR] G-4 — `docs/production-roadmap.md` is cited by the method but not
  allowlisted.** `docs/security-analysis.md` repeatedly defers to
  `production-roadmap.md` (§D1 for the rulings it encodes, §D3 for the scope
  boundary between "today's disposition" and "the production-shape re-judge") — a
  document the run may not read. The run B brief carried the boundary statement
  itself, which sufficed, but the method doc directing readers to a
  non-allowlisted path for normative context is an inconsistency worth fixing: fold
  the D1/D2/D3 boundary paragraph into `docs/security-analysis.md`, or add the
  roadmap to the allowlist.

- **[MINOR] G-5 — the I1–I5 vocabulary is unmapped.** The design docs and the
  design review argue in I1–I5 (the problem statement's invariants); the never-cut
  list and the method's ruling table argue in never-cut 1–7. The mapping is
  inferable (I1↔1, I2↔2, I3↔3-ish, I4↔4, I5↔5) but the normative vocabulary
  mapping table (`docs/security-analysis.md` §1) does not cover it, and the sets are
  not coextensive (never-cut 6 and 7 have no I-number). The baseline uses the
  never-cut numbering throughout and cites I-numbers only where the design does.

- **[MINOR] G-6 — the compromise-point tables in the allowed inputs are
  pre-implementation shapes.** `docs/background/design.md` §6.4 and
  `design-review.md` §5.5 describe the *designed* system ("the proxy", "signing key
  only", KMS/HSM-held). The as-built system added concrete footprints they do not
  cover: the `.env`-injected key file, the DCR store volume, the worker pool, the
  `/healthz` endpoint. §9 of the threat model is an extension assembled from the
  other allowed sections (the archived change's context and decisions), which
  sufficed — but the method should say that the baseline *extends* the §6.4/§5.5
  tables to the as-built shape rather than "carrying them forward", since carrying
  them forward verbatim would omit the local shape's actual root boundary (the
  development host).

- **[MINOR] G-7 — the vendored taxonomy has no leaf for several real shapes.**
  Log-content threats (a caller writing content into the audit trail) and
  clickjacking/framing had to be classified by the repo's convention (leaf = what
  the attacker gains; the flaw named in the description) into categories whose
  glosses do not obviously cover them — framing landed as Spoofing of caller's
  identity by its endgame, which a reviewer may dispute. The convention carries the
  load; the taxonomy's parents (Use Control Misconfiguration, Injection) are broad
  enough that nothing was unclassifiable, but two judgment calls are on record here
  rather than in the method.

## Meta-commentary — where the method was hard to follow

- **The per-threat eight-category grid is the method's heaviest demand, and it is
  the right one.** Forty-two threats × eight categories, every "not applicable"
  owing a threat-specific reason, produced several hundred grid cells; the temptation
  the method itself warns about (boilerplate N/A training author and reviewer to
  skim) was real, and resisting it is where the time went. The payoff was concrete:
  the grid surfaced genuine controls the tables alone would have lost — the CIMD
  capacity limiter as an Anti-DoS control for T2.2, the pre-allocation audit trail
  as the Detective control for half of AEP1, the `map $status` + `proxy_hide_header`
  form as Data Protection for the challenge's integrity property. The grouping step
  (§12) then earned its keep by collapsing the grid into twenty placements.
- **The register-first ordering works.** Assembling the disclosed-residual register
  before enumerating threats made the acceptance records the *anchor* the threat
  tables cite backward, instead of an appendix; dispositions in §13 read as "this
  threat lands on that already-priced residual," which is exactly the model the
  method wants. No reordering needed.
- **Judging "as the system stands" required one inference the inputs did not make
  explicit.** The as-built shape (plain http, file-based key, single instance) is
  spread across the archived change's context and decisions, never stated as one
  "current deployment state" paragraph anywhere in the allowlist; the baseline had
  to synthesize it (§1). A standing "system state" note — or the D3 re-judge's
  production-shape counterpart — would remove the synthesis step.
- **The scope boundary was enforced by the brief, not by the allowlist.** Holding
  the line ("state today's disposition and the re-open condition; never the
  production verdict; never 'resolved by D3'") required constant discipline because
  several allowed inputs argue in the production direction (KMS/HSM, Redis, TLS) as
  *the* control. The brief's boundary paragraph did the work the non-allowlisted
  roadmap would otherwise have done (G-4).

One gap repeats across the two gap-list shapes if run A found the spec-allowlist and
PoC-record gaps too: per the method's own rule, a repeated gap means
`docs/security-analysis.md` (and the skill) is fixed before either run's result is
trusted — the comparison of the two lists is that check.
