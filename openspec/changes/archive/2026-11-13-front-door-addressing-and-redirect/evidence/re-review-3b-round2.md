# Independent re-review 3b, round 2 — findings record

Reviewer: independent opus pass (fresh agent, round 2), 2026-11-14. Scope: the amended
change package against `evidence/review-3b-findings.md` (round 1), plus fresh-eyes checks
of the amendments themselves, diff-verification of the two N2 re-pin entries against the
main spec, and re-derivation of the three load-bearing claims the amendments touch.

**Verdict: READY for the owner review pause (3c)**, with F1 below recommended as a
pre-pause wording pass. Round-1 verdict items all landed.

## Per-finding verdicts (round 1 → amended text)

- **B1 — ADDRESSED**, coherently in every named location: delta spec addressing
  requirement (match domain = the whole raw request URI, both-ends anchored, optional
  `?query` tail after `/mcp`, nothing after `/mcp` but the query) + the dedicated
  post-`/mcp`-tail scenario; design D3 with the `^/dial/(GRAMMAR)/mcp(\?.*)?$` form and
  the both-naive-patterns-breakage argument; tasks 5.1 verbatim; probe evidence Part 2
  records the grammar and honestly marks the tail as not-yet-exercised-live; task 8.1
  row (3b) carries the two match-domain probe rows (query-bearing routes raw+intact,
  `%2F` in the value included; tail refused 404); SIA T-EP6-c mitigation + detective
  rows carry them. Both rows can fail — negative-control discipline holds.
- **B2 — ADDRESSED everywhere; the falsified sentence is gone.** Delta guard
  requirement: "a stated division of labor, not two encodings of one rule" (map =
  routability filter over the wire form; guard = authority over the decoded form; the
  asymmetric class documented — forwarded on the data path, refused at
  discovery/authorize, challenge dead-ending at a 404 document by design,
  same-answer-as-Core) + the dedicated asymmetry scenario + the battery sentence
  ("asserts this asymmetry explicitly … rather than an agreement between the grammars
  that does not exist"). Design D4 rewritten around the division; D3, SIA T-EP6-a
  (mitigation 1, detective 8), grouped mitigations #3/#6, task 8.2's asymmetry rows
  (`%7B`, `%2e`, over-length), release notes — one story. Grep: no "two encodings"
  straggler outside the round-1 record's own quotations. Rows falsifiable on both sides.
- **S1 — ADDRESSED.** `/` out of the parity-refusal list (now `{`, `}`, `"`, control
  ≤ U+001F only); `%2F` ruled the only reachable wire spelling of a decoded `/` —
  forwarded, Core's own resolution refusal, same-answer not a cut. Delta, design D4,
  evidence matrix row 44, proposal — one story.
- **S2 — ADDRESSED.** Trailing-dot restated everywhere as a front-door ruling mirroring
  Core's creation-side constraint, deliberately stricter than resolution, offered to the
  owner pause as a ruling (with the verified source fact: `isValidResourcePath` called
  only from write/upload). "Refused as parity" phrasing gone.
- **S3 — ADDRESSED.** Strict UTF-8 pinned (invalid/over-long/CESU-8-surrogate refused
  with the guard's fixed reason, never lossily replaced — aliasing-merge reason stated);
  `+` literal in path position; dedicated scenario (`%FF`, `%C0%AF`, `%ED%A0%80`);
  design D4 + tasks 1.2 with the unit rows. Rows fail against a default
  `unquote(errors='replace')` implementation.
- **S4 — ADDRESSED.** New task 3.6 names the pages and sites (`_DECISION_PAGE`/
  `_INTERSTITIAL`, the `_escape` call sites, the note pages in `gateway/flow.py`);
  SIA T-EP3-b mitigation 6 + detective 8 name task 3.6 as home.
- **S5 — ADDRESSED.** Corrected semantics (Core's bound applies to the absolute storage
  path, not the resource URL) + deliberate adoption ("deliberately stricter at the
  890–900-byte edge, an acknowledged edge cut") in delta, design D4, tasks 1.1,
  finding-f2, proposal, release notes. Re-verified: `MAX_PATH_SIZE = 900` at
  ResourceDescriptorFactory.java:21, applied to `getAbsoluteFilePath()` at :72.
- **N1–N6 — ALL ADDRESSED.** N1: the DCR response-echo fact in design D7/tasks 6.1/
  matrix evidence — re-verified `DynamicResourceRegistrationStrategy.java:100` is
  `clientRegistrationResponse.getRedirectUris().getFirst()`. N2: two declared re-pin
  MODIFIED entries; diffed against the main spec — ONLY the declared name→path strings
  differ; verbatim otherwise; behavior-neutral. N3: proposal Impact re-worded. N4: task
  3.4 names `request.scope["raw_path"]` and the multi-segment capture change. N5: task
  6.2 absorbs the `consent` lag (verified real). N6: the `%`-exclusion clause in tasks
  5.1 + design D4.

## Package-level checks

- Counts: 2 ADDED / 13 MODIFIED / 1 REMOVED; scenarios counted requirement-by-requirement:
  104 — exact.
- Publication discipline: placeholders only; the only leak-pattern string is a bare
  port number in the matrix evidence. Clean.
- Load-bearing claims re-verified (all HOLD): the DCR response first-entry fact;
  `MAX_PATH_SIZE` on the absolute file path; the raw-URI map's premise against the live
  router config (today's anchored decoded single-segment captures survive query strings
  only because nginx location-matching ignores args — hence the map's explicit
  `(\?.*)?$` tail; the argument is sound).

## NEW findings from the fresh-eyes pass (wording/bookkeeping only)

- **F1 (SHOULD-FIX — amendment-record accuracy):** five retained scenarios and one body
  clause were re-worded name→path while their own amendment notes declare them unchanged:
  (a) discovery — "Unmapped toolset" and "Dynamic toolset served without local
  configuration" under "carried verbatim"; (b) authorization — "App resource accepted"
  beyond the declared two; (c) toolset mapping — "Unset mapping serves dynamically"
  beyond the declared two; (d) app flow — "Unreachable Core" THEN under "no other
  scenario changes"; (e) abuse-bounds body — "looping guard-failing names"→"paths" under
  a note declaring only the path-bounds addition. Fix: amend the five declarations to
  name their re-wordings. Nothing mechanical breaks; it is the record that is wrong.
- **F2 (NOTE):** the apps document's echo rule lives only in a scenario; the apps
  requirement body lacks the spelling sentence its toolset twin has. One sentence closes
  the twin gap.
- **F3 (NOTE):** the canonicalizer's split-then-decode order is implied, never stated.
  Decode-then-split would merge `%2F`-escaped and raw-slash spellings onto one canonical
  identity — the merge direction T-EP1-b prices. One clause (delta paragraph or task
  1.2) pins it.
