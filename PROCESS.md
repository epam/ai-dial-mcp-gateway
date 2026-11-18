# The defect-fight cycle

The repeatable loop this repo runs whenever behavior fails its gate — a stage row, a
conformance row, an integration failure, or a defect found in play. The specs under
`openspec/specs/` are the contract the cycle fixes toward; the loop ends only when the
failing tier's rows are green (or cut per `ROADMAP.md`'s scope-cut order — never the
security invariants).

## The loop

0. **Instrument** — reproduce the failure as a repeatable probe with captured evidence
   (stderr, log files, HTTP captures). The instrument must be able to fail: one negative
   control (a deliberately wrong expectation) runs first, before any verdict from the
   probe is trusted.
1. **Diagnose** — localize the failing leg; establish the root cause from evidence, not
   plausibility. Output is a **finding record**: symptom / evidence / root cause /
   proposed fix. Hard root-causes escalate to a reviewer run.
2. **Spec gate** — does the fix change behavior the specs describe?
   - **No** → go straight to implementation (step 4).
   - **Yes** → stop; the spec changes first (step 3). Never fix-then-spec.
3. **Spec change** — an OpenSpec change (`/opsx:propose`: proposal + delta spec + design
   + tasks), then an **independent review of the change artifacts** (step 3b); its
   findings are addressed before implementation starts. After the review's findings are
   addressed, the change enters an **owner review pause** (3c): the complete package —
   proposal, design (including the security impact analysis and its rulings), tasks, and
   the delta specs — is presented to the owner, and nothing proceeds without the owner's
   explicit go: no implementation, no packaging, no branch work. The pause sits after the
   independent review deliberately — it is the last point at which changing the design is
   cheap. If the owner requests changes: back to authoring (3a) → re-review (3b) →
   re-pause (3c).
4. **Implement** — against the `tasks.md` checklist, unit tests alongside the code.
5. **Lightweight gates** — `ruff check` + `ruff format --check` + unit tests
   (`pytest -q`) first; then the static gates (`bandit`, `pip-audit`, Trivy, and the
   publication leak check `python scripts/check_publication_leaks.py`, whose boundary
   `CLAUDE.md`'s publication discipline section states). The cheap tiers run before
   any expensive re-test.
6. **Compose-boot gate** — `docker compose up` and a health probe per service. A green
   unit suite proves nothing about the composed stack; this gate is what stands in for a
   multi-platform compile gate.
7. **Re-test** — the SAME failing probe first (it must now pass), then the full gate tier
   the failure belongs to (the stage's conformance rows).
8. **Review gates** — a security review gate on the diff (an independent reviewer
   subagent, not the implementer; runs against the change's security impact analysis and
   the threat model, and its job includes falsifying a "no security impact" claim; the
   SIA it reviews is authored at step 3 per `docs/security-analysis.md` — the
   `security-analysis` skill is its checklist), then a review gate on the diff by an
   independent reviewer.
9. **Loop** — new failure evidence opens iteration +1 at step 0, inside the same stage.
   **Exit:** the stage's row table is green (or the row is cut per `ROADMAP.md`'s
   scope-cut order; the never-cut list is never cut).

## Roles (orchestrator → subagents)

One session runs the whole loop; the orchestrator does not implement or review — it
routes artifacts and makes the spec-gate decision.

- **Orchestrator** (main session): owns the loop state, decides spec-gate outcomes,
  sequences subagents. No finding is ever allowed to live only in chat scrollback — every
  finding lands in the active change folder or the stage's evidence file.
- **opus subagents**: spec/proposal authoring when a spec change is needed, the
  spec-change review (3b), the security review gate (8), and the diff review gate (8).
- **sonnet subagents**: troubleshooting fan-out (probes, captures, log
  forensics), implementation (4), and gate and test runs (5).

**Agent freshness (one agent per pass).** A *pass* — an authoring round, a review round,
an implementation round, an owner-change-request round — runs on a **fresh subagent**,
briefed from artifacts: the change folder (the design's decisions-of-record list is the
core brief) plus the specific findings being addressed — never from a resumed agent's
accumulated transcript.

- One pass, one fresh agent. Within a single pass the same agent may be messaged for
  clarifications; across passes, never.
- **A review pass is a fresh agent every time** — independence is per-pass, not
  per-change; a reviewer re-reviewing a revision it ruled on before is the weakened form.
- The brief lives in the change folder, so a fresh agent's pickup is itself a quality
  gate: if the fresh agent cannot run the pass from the folder, the folder is defective —
  that is found and fixed first.
- The standing context each role needs (repo rules, gate ladder, spec conventions) comes
  from this repo's own docs (`CLAUDE.md`, `PROCESS.md`, the main specs), which a fresh
  agent reads anyway.

## Artifacts

- **Finding record**: symptom / evidence / root cause / proposed fix — lands in the
  active change's design notes or the stage's evidence file.
- **OpenSpec change folder**: proposal, delta specs, design, tasks, evidence (row
  tables, captures, negative-probe records).
- **Memory files**: cross-session state (stage progress, tooling gotchas) — the loop
  survives a session boundary through them, never through chat memory.

## Rules

- **Probe-fail-first**: no verdict from an unproven instrument; the negative control
  precedes the positive claim.
- **Unspecified behavior is spec'd first**: a defect that reveals a behavior the specs
  never stated adds the spec line FIRST, then the test. A defect is not closed by a fix
  plus a test while the behavior it exposed is still absent from the spec — the spec
  delta lands in the same change.
- **The spec gate is a hard stop**: behavior changes go through their own OpenSpec change
  before the code does.
- **One change per finding-cluster** (a diagnosis may decompose into several spec deltas —
  that is one change); loop-back failures reopen the same change's tasks.
- **Cross-repo defects are reported, never fixed** in this repo.
- **Security invariants are never cut** (`ROADMAP.md`'s never-cut list); scope cuts
  follow `ROADMAP.md`'s cut order only.
- **Commit locally; push after the change's gates pass. Never force-push.**
- **The merge to master is the owner's act — sessions land gated branches and never merge; a change is done when its gates pass and its branch is pushed, and the mainline advances by owner merge.**
- **Release notes:** every OpenSpec change authors a `release-notes-draft.md` in its
  change folder as a standard authoring task (step 3), in the two-audience format —
  `### For users` then `### For the team` (no user-visible behavior → a single
  `No visible change this release.` For-users line; the section always carries both
  subsections).
