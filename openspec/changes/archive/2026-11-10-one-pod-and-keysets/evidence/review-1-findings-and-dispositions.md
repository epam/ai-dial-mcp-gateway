# Review round 1 — findings and dispositions

The independent review pass (a fresh reviewer subagent, per PROCESS.md step 3b) ran
over the authored artifacts on 2026-11-08. Findings file:
`evidence/review-1-findings.md` (the reviewer's own record, unedited here — its
delta-threat citations describe the pre-fix state and stay as written; the mapping
below keeps them resolvable). This file records what the finding-addressing
authoring round did about each finding, before the owner review pause (PROCESS step
3c). Verdict: 0 blocking, 3 should-fix, 4 notes; the reviewer held the package's
load-bearing claims as falsification-checked (the code-reality claims, the Alpine
precedent, the ruling deviations P1–P5 on their merits, the delta-spec hygiene
against the main spec, the SIA's method conformance, the mechanical gates).

## Should-fix

- **SF-1 — the implementation brief omitted `gateway/codes.py` and
  `gateway/routes.py`, the two files the keyset change necessarily touches.**
  **Disposition: FIXED.** `gateway/codes.py` (the decode side — `decode_code`
  verifies codes with its own `jwt.decode` against `signing_key.public_key()`, no
  `kid` selection, so it moves with the keyset; `issue_code`'s sign path keeps
  today's shape through the active entry) and `gateway/routes.py` (the JWKS route,
  which must serve the keyset's document — every entry's public half, active first —
  where it serves the single key's) are now named in proposal.md §Impact (a new
  `codes.py` bullet; `routes.py` joined to the call-sites bullet), in design.md §SIA
  §1's implementation shape, and in tasks 2.5 (`gateway/tokens.py`,
  `gateway/codes.py` — both verification paths) and 2.6 (`gateway/runtime.py`,
  `gateway/token.py`, `gateway/routes.py` — the JWKS route named). The
  old-key-code-redeemed-across-a-promotion case is added to task 2.7's unit tests
  (a code minted under the pre-rotation key verifies through the retained entry —
  `decode_code`'s path), with the tier choice recorded in the task itself: the
  code's own minutes TTL bounds it far below the drain window, which is why the
  drill's named legs are the access and refresh tokens that span the window. The
  delta's inbound-tokens requirement already names codes in its own-tokens clause
  ("codes, access tokens, refresh tokens … the token's `kid` selects the entry"), so
  the requirement's coverage, the unit test, and the drill's legs tell one story;
  the drill requirement's own legs are untouched.
- **SF-2 — task 7.7 placed the owner review pause after implementation, against
  PROCESS.md step 3c's ordering.** **Disposition: FIXED.** A group 0 now precedes
  group 1: task 0.1 is the precondition record — the pause with the complete
  package (proposal, design with the SIA and its rulings, tasks, delta specs), the
  owner's explicit go recorded in this change's evidence folder, and nothing in
  groups 1–8 running without it ("no implementation, no packaging, no branch work"),
  stated as the checklist's front gate so a fresh implementation agent reading
  top-down meets the pause before group 1. Task 7.7 is restated as the closing
  record: 0.1's go and the checklist's rows complete, the branch committed and
  pushed — the merge-is-the-owner's-act statement (PROCESS.md's final rule) stays
  at the end, where the merge question actually arises.
- **SF-3 — the delta-threat IDs DT-EP4-1/DT-EP4-2 (and DT-EP1-1/DT-EP1-2) collided
  with live citations in `docs/threat-model.md` (RES-21's "T4-8; DT-EP4-1; the D5
  amendment's priced trade" from C1; the dispositions table's DT-EP1-1/DT-EP1-2
  from the consent-checkpoint change).** **Disposition: FIXED — renumbered to
  continue the live model's sequences, not scoped with a change marker.** The
  mapping:

  | This change's row (old) | Landed ID (new) | Why free |
  |---|---|---|
  | DT-EP4-1 retained signing key extends the mint window | **DT-EP4-2** | C1 owns DT-EP4-1 |
  | DT-EP4-2 retained custody key extends the decrypt window | **DT-EP4-3** | — |
  | DT-EP4-3 key file read off its mount | **DT-EP4-4** | — |
  | DT-EP4-4 forged or malformed keyset document | **DT-EP4-5** | — |
  | DT-EP4-5 indefinite retention [mis-use] | **DT-EP4-6** | — |
  | DT-EP4-6 silent source fallback [mis-use] | **DT-EP4-7** | — |
  | DT-EP1-1 crafted JWT steering verification across the keyset | **DT-EP1-10** | the consent change owns DT-EP1-1..7 and DT-EP1-9; the unused DT-EP1-8 hole is not reused |
  | DT-EP1-2 rotation-window verification gap at Core | **DT-EP1-11** | — |
  | DT-EP6-1, DT-EP6-2, DT-EP7-1 | unchanged | the first rows of their entry points in the live model |

  The choice and its reason are recorded in design.md §7's new "ID numbering"
  paragraph: the model's citation surface is cumulative, the per-change
  restart-at-1 convention has already produced the collision, and a plain unique ID
  resolves to exactly one design §5 grid with no change-scope marker — which is
  what task 1.3's freshness rule asks of every citation; later changes continue the
  sequences from wherever the model then stands. Applied consistently: every
  DT citation in design.md (§2, §3's invariant table, §5's grid headers and
  cross-references, §6, §7, §8, Risks, D3), release-notes-draft.md's SIA
  cross-reference (now DT-EP4-2/DT-EP4-3), tasks 1.1 (the ID list, landed as
  written) and 1.3 (the uniqueness clause). Verified: all eleven landed IDs have
  zero occurrences in the live `docs/threat-model.md`; M34–M36 were already
  collision-free (the model's grouped list ends at M33) and stand as numbered.
  Every citation the change lands in the model is unambiguous without session
  context.

## Notes

- **N-1 — the MODIFIED inbound-tokens requirement dropped the prior amendment note
  (the endpoint-source key-set resolution rationale) without declaring it.**
  **Disposition: FIXED** — the prior note is carried in the delta's MODIFIED block
  marked `*Amendment, declared (retained):*`, verbatim, ahead of this change's own
  note — the persist convention the main spec's toolset-mapping requirement already
  models (its retained notes at its own lines 638/640); the rationale record
  survives the archive sync. The proposal's Modified-Capabilities summary says so.
- **N-2 — the retained "Embedded key refused" scenario's "the pinned key only" read
  against the keyset amendment.** **Disposition: FIXED** — a declared one-clause
  scenario re-wording (the form this change's own custody amendment already
  models): "checks the signature against the pinned key only" becomes "checks the
  signature against the pinned key set's selected entry only, never header-carried
  material", declared in the amendment note (which now states one retained scenario
  is re-worded and the remaining retained scenarios are unchanged and carried
  verbatim). The scenario's property is unchanged — verification never uses
  header-carried key material, whichever side pinned the key material — and the
  requirement text was already unambiguous, so no behavior moves. The proposal's
  summary names the touch.
- **N-3 — invariant-table ruling values drifted off the method's two allowed values
  (`docs/security-analysis.md` §2: "Preserved" or "Preserved with a disclosed
  bound").** **Disposition: FIXED** — row 5 is ruled **Preserved** (the new surfaces
  are named inside the reason column, where the method puts them); row 7 is ruled
  **Preserved with a disclosed bound**, with the strengthening moved into the
  reason ("Strengthened within the ruling — never committed, never logged,
  `kid`-published, rotatable — now proven by rehearsal…") and the bound already
  stated there (the injection-path custody, the retained-entry window). The same
  fix shape the archived as-security-hardening round applied to its F7.
- **N-4 — the duplicate-derived-`kid` parenthetical overstated what the truncated
  `kid` hash proves (the `kid` is 16 hex characters of a SHA-256 over the public
  numbers, `gateway/keys.py`, so two distinct keys can in principle derive one
  `kid`).** **Disposition: FIXED** — the wording now states exactly what the
  mechanism guarantees, at four sites: the delta requirement's validation clause (a
  shared `kid` is either the same key configured twice, under one name or two, or a
  collision between two distinct keys in the truncated hash; the refusal stands
  either way, because one `kid` must name exactly one entry), the "Duplicate
  derived kids refuse startup" scenario's THEN (one `kid` naming two entries —
  same key under two names, or a truncated-hash collision — is a keyset that
  miscounts its own keys, and the refusal closes both shapes), design.md D2, and
  the DT-EP4-5 grid's anti-injection row (the document cannot hold two entries
  under one `kid`, so its `kid` set stays an honest count of its entries). The
  refusal's normative shape is unchanged — the keyset must not hold two entries
  with one `kid`, whatever the material; only the causal claim was corrected.

## The mechanical gates after the round

- `openspec validate one-pod-and-keysets` — green ("Change 'one-pod-and-keysets' is
  valid").
- `openspec validate --all` — 2 passed, 0 failed (INFO-only requirement-length
  notices, the pre-existing style of the whole spec).
- Plain `openspec validate` — the tool's no-args usage message, exit 1 (nothing
  validated, not a validation failure; the same behavior the review round
  observed).
- `python scripts/check_publication_leaks.py` (PYTHONUTF8=1) — PASS, exit 0: 3
  findings, all waived in the committed baseline, none new. Manual scan of the
  change folder's new text for the leak classes (personal paths, internal
  hostnames, real issuer/tenant/org values, credential-shaped literals): clean —
  repo-relative paths, public vocabulary, and `<>`-free generic prose only.

## Coherence re-check after the edits

Every SIA mitigation still lands in the delta spec or a named repo home (the §6
grouped list's homes are unchanged; the renumbering moved IDs only, not homes);
the proposal, design, tasks, and delta tell one story — the file lists name every
touched file including `codes.py` and `routes.py`, the pause precedes group 1, the
threat IDs are unique across the live model, and the inbound-tokens block carries
both its amendment notes (retained prior, declared new) with the one declared
scenario re-wording. The drill's legs, the unit tests' code-across-promotion case,
and the inbound-tokens requirement's own-tokens clause (which names codes) are the
same story at three tiers.

## Owner-pause amendments (round 2)

The owner reviewed the package at the pause (PROCESS step 3c) and requested four
amendments — the pod security-context section, the store's governance/storage-class
statements, the deployment diagram, and the IdP client secret's file spelling — with a
mid-round correction (no preference language between delivery spellings; storage
requirements named by properties, never products). The amendment round is recorded
in `pause-amendments.md`; the gates after it are recorded there too (both openspec
validations green, the leak check PASS with no new findings).
