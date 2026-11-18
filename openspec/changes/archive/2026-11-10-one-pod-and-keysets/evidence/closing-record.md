# The closing record — one-pod-and-keysets (task 7.7)

Date: 2026-11-09. Branch `worktree-c3-one-pod-and-keysets`, base origin/master
`846017d`.

**The state this record closes:**

- Task 0.1's go: recorded (`evidence/owner-go.md`) — the amended package, the P1–P5
  pushback nods, the DevOps documentation-first path.
- Groups 1–6: landed and committed — the threat-model delta (verified
  reconstructable), the keyset code (713 passed / 1 skipped), the Alpine image
  (Trivy 0 HIGH/CRITICAL — the 44-HIGH Debian debt cleared), the pod shape on the
  composed stack (probe battery 11/11, the port boundary proven, the DCR restart
  survival, the quirk check's honest record), the pod contract + configuration
  surface, and the migration drill's live legs (the negative control failed first
  as required; the pre-publish proof with the 615 s observed wait ≥ the declared
  600 s bound; the custody overlap re-seal; both emergency cuts refusing in their
  classes).
- One defect found in play (the blank-singular exclusivity — the drill's own
  catch), closed through the full cycle: spec'd first (the blank-equals-unset rule,
  both exclusive pairs), then the field-level fix, then re-proven live (`1b91c64`).
- Group 7: the static tier green (ruff, format on LF content, mypy at the
  2-error pre-existing baseline, bandit, pip-audit clean, Trivy, the leak check
  PASS); the compose-boot gate re-confirmed on the current tree; the conformance
  map complete — 50/50 delta scenarios mapped, zero flags. The security review
  gate: PASS (0 blocking; the SIA's falsification target — the retained-key
  windows' pricing — held under every attempt). The general review gate: FAIL on
  one blocking finding (the flat custody material rendering in repr/model_dump),
  fixed, and verified-closed by a focused re-review with empirical teeth. The
  re-review's three residuals (the last `key_source` naming, the contract §1
  summary row, the delta spec's absolute port phrasings — the wording that syncs
  into the main spec at archive) closed in the closing micro-pass. Both gates'
  dispositions recorded in their findings files' closure sections.
- Group 8: the release notes finalized — the compatibility sentence verified true
  of the diff by the general gate (every existing deployment's configuration keeps
  working: the singular and flat spellings ride the same code path); the
  rotation-behavior change stated plainly.
- The orchestrator-touched stretch disclosure: commit `6b5ee1c` contains small
  lint-triage fixes made directly by the orchestrator (ruff auto-fixes, an
  assert→cast replacement, named test constants) — reviewed as part of the diff
  by both gates with no assumed prior review; no issue found.

**Open rows and their owners:**

- **7.6 (DevOps review of the pod contract)** — open by design: the owner chose
  the documentation-first path; `docs/pod-contract.md` is the shareable artifact
  ("what to deploy and how to configure it properly"), and the row closes when
  DevOps's explicit confirmation is recorded in `docs/evidence/c3/` — silence is
  not acceptance.
- **The merge to master is the owner's act** (PROCESS.md's final rule): this
  branch is pushed with its gates passed; the owner merges when satisfied, after
  any real-harness round they choose to run.

**How to re-verify:** the unit suite (713 passed / 1 standing skip), the probe
battery against the pod-shaped stack (`scripts/probe_routing.py`), and the drill
(`scripts/drill_rotation.py` — control/signing/custody/status/restore), with the
records under `docs/evidence/c3/`.
