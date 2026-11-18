# Retro-review — the two orchestrator-implemented edits (PROCESS.md roles-split violation)

Reviewer: independent retro-review pass, ordered by the owner after the orchestrator
session implemented two edits itself instead of routing them to subagents. Both edits
belong to this change's record: the `kid`-less-fallback clause is its delta; the
placement flips are its task 3.2. Duty: falsification — each edit checked as if an
untrusted implementer had made it. Read-only except this file. Date: 2026-10-30.

Scope: commit `dc02604` (the change folder, including the F3 clause in the delta spec)
and commit `1d63874` (the main-spec sync, the archive move, and the `docs/threat-model.md`
M9/M10/M11/M20 flips plus the OQ-3 rewrite). Verified against `gateway/idp.py`, the
archived delta, `review-round-1.md`, `design.md`'s pause recommendation, the main spec,
the full diffs of both commits, `4254a1f`, and a live test run.

## Findings

### R1 — MAJOR — the task-3.2 edit is half-executed and leaves the threat model self-contradictory

Task 3.2 (this change's `tasks.md`, owner-approved per its own header) has two
deliverables: flip the four M-row placement homes, **and** "drop the matching 'the
spec carries no … requirement' notes in the T4-7, T6-2, and T6-7 grids." Commit
`1d63874` did the first and not the second. Every named note is still present and —
as of the same commit's own main-spec sync — now false:

- T4-7 grid, lines 1200-1202: "the spec pins RS256 *minting* but carries no
  verification-hygiene requirement: flagged for a spec change — M20".
- T6-2 grid, lines 1348-1349: "the charset is M10's re-placed element; the spec
  carries no charset requirement".
- T6-7 grid, lines 1424-1425 and 1432-1435: two "the spec carries no charset
  requirement … see M10" notes.

The flip also stranded citations outside the task's own (under-scoped) list, so even a
faithful execution of task 3.2 as written would have left the model contradictory:

- §9's preamble, lines 490-495: "the four elements the spec does not carry are placed
  **repo** and flagged there (M9's RFC 9207 `iss`, M11's per-flow records, M20, and
  M10's … charset)" — false in its entirety; the sentence points to §12's placement
  notes, which now say the opposite.
- T1-13 grid, lines 723-726: "the current spec carries no `iss` requirement: flagged,
  see M9" — not named in task 3.2 at all.
- T6-7 detective cell, lines 1438-1439: "the charset refusal is repo — M10's
  placement note".
- Per-flow-records citations still reading "(repo — …)" with pointers to M11's note:
  lines 758-760 ("the spec pins the refusal records only, see M11"), 813-816 (same,
  "see M11's placement note"), 943-945, 1224, 1258, 1301, 1463.

Post-`1d63874` the model's §12 says all four elements are spec-placed while §9 and at
least ten threat-grid cells say the same elements are repo/unpinned — several with
"see M1x's placement note" pointers that resolve to notes contradicting the citing
cell. Task 3.2's own verification step ("a grep for 'candidate spec change' finds none
of the four stale flags") passes only on the M rows; the grep still matches M7's
"candidate spec changes" (a different, still-repo element), and the grid-note half of
the step was never run.

**Failure scenario:** the next SIA author or coverage auditor reads T6-7's "the spec
carries no charset requirement" or §9's preamble, concludes the charset / `iss` /
verification-hygiene / per-flow records are unpinned, and proposes a redundant spec
change or reports the spec weaker than it is; OQ-3's "closed" claim fails the model's
own citation-resolution standard — the exact standard `4254a1f` was committed to
enforce and the standard the M10 charset was re-placed under on 2026-10-29.

Mitigating: the defect direction under-claims spec coverage (never over-claims it);
every disposition is unchanged; no security posture is affected.

### R2 — MINOR — OQ-3's closure sentence overstates the "(repo)" citation hygiene for the two owner-declined elements

OQ-3 now reads: the two owner-declined elements "remain repo controls and are cited as
'(repo)' in their grids." Partially true. The T5-2/T5-5/T5-6 cells (post-`4254a1f`) and
most CIMD cells (T2-1 line 832, T2-3 line 866, T2-4 line 878) do cite repo. But T2-4's
Anti-DoS cell, line 879, still cites **"(spec)"** for the same CIMD fetch timeouts
("timeouts and size cap bound the parse cost (spec)") — contradicting the model's own
repo re-placement of those timeouts — and the User-Agent control has no threat-grid
citation at all (only M7's §12 cell names it). The T2-4 cell predates both reviewed
commits, but the sentence was added by `1d63874` and asserts a citation state the
grids do not fully have.

### R3 — MINOR — the change was archived with an all-open task list

The archived `tasks.md` shows every task unchecked — 1.1 through 4.1, including 2.5
(owner pause), 3.1 (post-sync conformance check), and 3.2 itself. The work for 1.1-2.5
is evidenced (review round, pause, archive), but the archived record shows no task as
done, and 3.1/4.1 have no completion record at all. 3.2's open checkbox is at least
honest given R1.

### R4 — MINOR (judgment) — the F3 clause carries meta-commentary in normative prose

The clause's aside — "the behavior the implementation has, stated so a from-spec
reimplementation cannot silently refuse such tokens" — justifies the spec line by
pointing at the implementation, and the fallback sentence is descriptive ("resolves
to") inside a MUST requirement without its own modal. The normative content is present
and correct; a reimplementer could still read the clause as informative rather than
binding. Borderline against the repo's spec-text rule (WHAT and WHY, never
provenance).

## Edit 1 — the F3 clause (`dc02604`): verdict **SOUND**

- **Clause vs code, verified precisely** (`gateway/idp.py:253, 273-312`): a `kid`-less
  header yields `kid = ""` (`header.get("kid", "")`), the guard `if kid and
  document.get("kid") != kid` is skipped, and the loop returns the **first key in
  JWKS array order** with `kty == "RSA"` and `use` in `(None, "sig")` — the provider's
  first published RSA signing key, exactly as the clause states (an `enc`-marked RSA
  key is skipped, consistent with "signing key"; an unreadable first key hard-refuses,
  fail-closed). Single-key key set → resolution is that key, unambiguous: true.
  Rotation argument: a kid-less token signed by a non-first key resolves to the first
  key and the pinned-algorithm signature check fails → refused; a forgery fails the
  same check regardless of which key it resolves to — the fallback never accepts
  anything `kid`-resolution would refuse. Fail-closed claim verified against the code
  path, not just read off the clause.
- **Clause vs the approved delta:** added to the right requirement (the
  verification-hygiene requirement), in the requirement prose, as one sentence; no
  scenario added, none altered — the delta's twelve scenario blocks and its line
  positions (requirement prose at line 39, `kid`-scenario at 49-51) still match
  `review-round-1.md`'s quoted line numbers, so the clause was an inline append with
  no reflow. It matches `design.md`'s owner-pause recommendation verbatim in its
  naming clause, plus an accurate elaboration (unambiguity, fail-closed rotation)
  verified above. No other requirement in the delta was touched.
- **Tests:** `pytest -q tests/test_federation.py tests/test_tokens.py` — 89 passed.
  No dedicated `kid`-less unit row exists (every test mints with `kid:
  "the-idp-key"`); this is disclosed as design.md's open question 1, and this
  retro-review's code walk is the verification the clause rests on.

## Edit 2 — the task-3.2 flips (`1d63874`): verdict **DEFECT** (R1; the flips themselves are true)

- **Each flip is true against the post-sync main spec:** the RFC 9207 `iss`
  requirement, the per-flow lifecycle audit requirement, the verification-hygiene
  requirement including the `kid`-less clause, and the charset sentence + scenario in
  the MODIFIED mapping requirement all exist in `openspec/specs/mcp-signin/spec.md`,
  byte-identical to the delta.
- **Ordering verified:** `dc02604` (16:28:32) carried the clause into the change
  folder; `1d63874` (16:30:12) landed the requirement in the main spec and flipped the
  model in the same commit — so the M20 flip's claim (the requirement "now exists",
  fallback stated) was true at the moment it was committed, and the archive-move
  renames are R100 (byte-identical).
- **Nothing else in the rows changed:** the full `git show 1d63874 --
  docs/threat-model.md` diff touches only the four placement cells (threats columns
  byte-identical, mitigation descriptions untouched, no §8 disposition hunks) and the
  OQ-3 rewrite.
- **OQ-3 rewrite:** states what happened (four elements pinned; the fourth
  review-caught; the two owner-declined elements staying repo) — accurate in
  substance, overstated on citation hygiene per R2, and undercut as a "closure" claim
  by R1's contradictions.
- **Nothing smuggled:** `dc02604` = seven new files, all inside the change folder
  (its `.openspec.yaml` is in-folder metadata; no root, code, or main-spec file
  touched — the "spec-only" claim holds). `1d63874` = the threat-model edit, the
  main-spec sync (+54), and the seven R100 renames. Nothing else.

## Overall verdict: **NEEDS FIX**

Edit 1 stands as committed. Edit 2's committed content is accurate but incomplete
against its own owner-approved task, and the incompleteness leaves the threat model
internally contradictory. Required fix (a docs-only follow-up edit, routed to a
subagent per the roles split): drop or re-place the stale grid notes in T4-7, T6-2,
and T6-7 per task 3.2 as written; extend the same pass to §9's preamble (490-495),
T1-13 (723-726), T6-7's detective cell (1438-1439), and the per-flow-records
citations at 758-760, 813-816, 943-945, 1224, 1258, 1301, 1463; and reconcile T2-4's
Anti-DoS "(spec)" timeouts cell (R2). Tick the tasks.md boxes (or record why not) in
the same pass (R3).

## Verified clean (one line each)

- `idp.py` key selection: kid-less fallback is first-in-JWKS-order RSA signing key,
  use-filtered, fail-closed on unreadable keys — matches the clause exactly.
- Fail-closed rotation argument: re-derived from the code path; holds.
- Clause placement: right requirement, prose not scenario, inline append, no reflow —
  confirmed against the review round's quoted line numbers.
- Delta vs pause recommendation: the named clause matches `design.md` OQ-2 verbatim;
  elaboration verified accurate.
- Delta archive fidelity: archived spec.md byte-identical to `dc02604`'s committed
  text (diff empty).
- Main-spec sync: all four requirements byte-identical to the delta; MODIFIED block
  retains the original prose as prefix.
- Commit ordering: `dc02604` precedes `1d63874` by ~100 s; the flip's claims were
  true at commit time.
- Flip rows: threats columns, descriptions, and all §8 dispositions untouched.
- Tests: `tests/test_federation.py` + `tests/test_tokens.py` — 89 passed.
- Commit hygiene: both commits contain exactly what they describe; no smuggling.
- Working tree clean at review time; the two owner-declined elements' T5 grid cells
  do read "(repo — …)" post-`4254a1f`.
