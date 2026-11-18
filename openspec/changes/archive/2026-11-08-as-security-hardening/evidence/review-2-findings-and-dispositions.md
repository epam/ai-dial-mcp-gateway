# Review round 2 — findings and dispositions

Round 2 was a focused independent pass over everything folded since round 1: the
owner's 2026-11-07 rulings (B-1+B-3, B-2, B-5 accepted; B-4 deferred), the design's
D11–D14 and SIA delta, the three new delta blocks and the B-5 discovery amendment
(11 MODIFIED + 2 ADDED requirements, 92 scenarios), the RFC 9700 re-judge report with
its 2026-07-28 re-walk, and the re-scoped tasks. Findings file:
`evidence/review-2-findings.md` (the reviewer's record, unedited here). This file
records what was done about each finding. Verdict: **0 blocking, 6 should-fix, 4
notes** — every finding a fold-seam defect (stale names, counts, un-revisited
sections), mechanically fixable; none falsified a design claim, a delta requirement,
or a ruled disposition. The verified floor the reviewer held: the three new delta
blocks complete against their baselines; the currency spot-checks on the live
2026-07-28 pages verbatim-true; B-1/B-2/B-5's code facts verified; the partition
reconciling; M32/M33 in the fixed 8-category order; the rejudge review's findings
genuinely folded; the publication leak check PASS.

## Should-fix

- **F1 — the SIA's folded rows had no task coverage** (DT-EP1-5, DT-EP1-6, M32, M33
  absent from tasks.md's model-delta enumeration, §6 checklist, ledger-verify list,
  and falsification focus — the change would have violated its own standing order, "a
  mitigation that exists only in prose is not landed"). **Disposition: FIXED** — tasks
  2.1, 2.2, 6.1, 6.3, and 8.4 now carry the new rows/records explicitly, with task
  6.3 landing RES-25's three-part record and the D6 wording by name.
- **F2 — B-2's spec home misnamed** ("the public-endpoints requirement's token-grant
  clause" in D12, §6 item 8, and DT-EP1-6; the delta lands it in the issued-tokens
  requirement's code clause) — round-1 F6's class. **Disposition: FIXED in four
  places** (the three named, plus §7's M33 record where the same misname had spread);
  tasks 2.1/2.2 named the correct home from the start rather than perpetuating it.
- **F3 — a stale pre-re-walk partition ("53/12/3/6/21") in SIA §6 item 6.**
  **Disposition: FIXED** — the fully-reconciled 55/13/3/6/22 everywhere, the sibling
  phrases aligned.
- **F4 — the Non-Goals still disclaimed registration-surface changes,** falsified by
  D11. **Disposition: FIXED** — rewritten: the surfaces' controls unchanged; the
  surfaces gain exactly the admission rule and the page's fact-naming.
- **F5 — D13's deferral grounds cited "RES-23's accepted local-compromise floor"** —
  a record that does not exist (RES-23 is the ungated-harness-stores availability
  bound). **Disposition: FIXED by re-grounding, the honest path** — all six
  occurrences now ground on the model's actual rows (the attacker model's classes
  3/4, T1-3's stolen-token pricing, RES-21 part i's machine-control statement), with
  D13 carrying the explicit correction record; task 6.3's echo names the grounding
  rows and the correction.
- **F6 — stale "D1–D13" ranges** in the Migration Plan and task 8.5.
  **Disposition: FIXED** — D1–D14 in both.

## Notes

- **N1 (the replay memo's retention bound):** D12 now states the code-level TTL as
  the bound, with the reasoning that no replay can be detected after code expiry —
  and the revocation's own persistence (the denylist entry living to the token's
  `exp`) is the retention that matters.
- **N2 (the falsification review's superseded currency header):** the review file now
  carries a dated note — its per-finding substance stands; its `2025-11-25`-as-current
  claims are superseded by the re-walk.
- **N3 (the proposal's "two further requirements" undercount):** the Capabilities
  bullet now names the amendments across the registration, durability, issued-tokens,
  and discovery requirements.
- **N4 (the settings/store-load sites' entry-point homes):** SIA §4's preamble now
  declares them — the pre-registered check is operator configuration inside the
  configured trust boundary (priced in DT-EP1-5's row); the DCR store's load path is
  EP7/T7-1 territory, narrowed by the load-time refusal (noted in §7's M32 record).

## The standing `openspec validate` ERRORs

Unchanged: both are parse artifacts of the corrupted on-disk main spec, clearing when
tasks group 1's verify-on-rebase runs (the repair is merged on master at `f19dcfb`;
the rebase happens at apply time).
