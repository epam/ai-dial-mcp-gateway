# D0a review — round 1

The independent review of the D0a change (the six uncommitted files: the `CLAUDE.md`
section, the `PROCESS.md` gate-list line, the check, the baseline, the tests, and
`leak-check-and-discipline.md`). The reviewer did not author the change; the method was
falsification — every claim the change makes was either re-run or probed adversarially,
with scratch fixtures in an untracked scratch repo (built, run, deleted; never
committed).

## Verdict

The change is faithful to the authoring brief, self-clean under its own rules, and its
gate claims reproduce exactly. Two medium findings are undisclosed false-negative
shapes inside rule classes the note presents as covered; both are fixable by disclosure
(or, for F1, by a small rule extension). Nothing found blocks the commit once F1–F3 are
disposed of; F4–F5 are minor.

## Findings

### F1 — a PEM private key embedded on one line with literal `\n` escapes evades every detector

- **Severity:** medium
- **Evidence:** Probed `scan_file` directly with
  `PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nMII…\n-----END PRIVATE KEY-----"` as one
  physical line (literal backslash-n, the standard `.env`/compose/JSON embedding for
  key material): no finding. Three reasons stack: the block detector counts only
  *physical* follower lines after the header line; the assignment detector's
  `_VALUE_CHARSET` rejects the backslash, so the value fails even under a
  secret-named key (`CLIENT_SECRET="-----BEGIN…"` also passes); and no other detector
  applies. The multi-line form is caught correctly (verified: a scratch file with real
  newlines and an 80+ base64 body flagged). The evidence note's rule table presents
  "a PEM private-key block with a real-sized base64 body" as covered and discloses
  only the body-minimum tuning ("prose quoting a header and one-line test fixtures
  pass") — not this embedding shape.
- **Disposition requested:** Either extend the boundary paragraph in
  `leak-check-and-discipline.md` to name the single-line escaped form as inside the
  pass-side (with the review gates as its coverage), or extend
  `_private_key_blocks` to also count base64 separated by literal `\n` on the
  header's own line — in which case the prose-header pass case must stay passing
  (the existing tests cover it).

### F2 — the mixed-case gate's blind spot contains this repo's own primary credential shape

- **Severity:** medium
- **Evidence:** A UUID-shaped value assigned to a secret-named key
  (`KEYCLOAK_CLIENT_SECRET=3f2b9c1e-…`, 36 chars, single case) passes — verified by
  direct probe. Keycloak's default client secrets are exactly this shape (lowercase
  hex plus dashes), and Keycloak client secrets are the credential class this gateway
  handles first. The note discloses the cost generically ("a real secret that happens
  to be all-lowercase or all-caps") but does not say that the repo's central real-world
  secret shape sits inside the boundary. Lowercase 40-char and all-caps values also
  pass, as disclosed.
- **Disposition requested:** One sentence in the note's tuning paragraph naming the
  UUID/lowercase-hex shape explicitly and naming its coverage (review gates; gitleaks
  at T7). Tightening the rule is likely not available: the repo's own fixture
  vocabulary is lowercase words joined by dashes — the same character class as a UUID
  — so disclosure is the realistic fix. If the author sees a discriminator, the rule
  may be tightened instead; the reviewer does not require it.

### F3 — the personal-path rule's case tolerance is narrower than its comment claims, and inconsistent across branches

- **Severity:** low
- **Evidence:** Probed: `C:/users/<name>/…` matches (Windows branch tolerates
  first-letter drift) but `/users/<name>/…` does not (the POSIX alternation
  `(?:[Hh]ome|Users)` matches `Users` with a capital U only); `/USERS/…`, `/HOME/…`,
  and `C:/USERS/…` all pass everywhere. The comment on the pattern says the profile
  directory is "matched case-insensitively", which overstates it — only the first
  letter of `Users`/`Home` drifts. Practical exposure is small (`/users/<name>` is an
  unusual spelling on real systems), but the comment states a coverage the regex does
  not have.
- **Disposition requested:** Either correct the comment to the actual tolerance, or
  make the directory names fully case-insensitive (`re.IGNORECASE` scoped to the
  alternation, keeping the profile-name segment as is). If left as-is, the note's rule
  table should carry the same one-line precision.

### F4 — the gates table omits pip-audit, Trivy, and the compose-boot gate without a stated reason

- **Severity:** low
- **Evidence:** `leak-check-and-discipline.md`'s gates table lists leak check, ruff
  lint/format, unit tests, and bandit. `CLAUDE.md`'s gate list presents pip-audit,
  Trivy, and compose-boot as unconditional before a stage is done. For this
  docs/config change they are vacuous — no dependency, image, or stack change — and
  the brief does not require them; but the note claims to stand alone, and a fresh
  reader cannot tell "not applicable" from "not run".
- **Disposition requested:** One line in the gates table stating why the three do not
  apply to this change.

### F5 — `files_scanned` counts the tracked list, not the files actually read

- **Severity:** info
- **Evidence:** `scan_repo` sets `files_scanned=len(paths)`; tracked `.env` files are
  deliberately not read (the file-level finding already fails them) and
  missing-from-worktree paths are skipped, yet both are counted. The summary's
  "scanned N" is the `git ls-files` size. Cosmetic; today's numbers are honest at
  that definition (191 = the tracked-list size, matching the note's closing run).
- **Disposition requested:** None required. If the script is touched for F1, renaming
  the field (e.g. `tracked_files`) or excluding the unread paths would make the
  summary self-describing.

## What was verified (and held)

- **Fidelity to the brief.** Every deliverable bullet is present: the `CLAUDE.md`
  section (fact/stake, prospective rule, placeholder convention, the never-cut 6
  reference without duplication, the machine check, the boundary), the gate-list
  updates in both files, the script's design points (stdlib-only, `git ls-files` via
  argv list, the three rule classes, binary skip, archive not skipped, file+rule
  baseline with no matched values, `file:line: rule-id` output, deterministic
  ordering, exit 0/1, tests factored for direct call, no subprocess in tests). No
  silent narrowing or scope creep beyond the two documented deviations (the 32-char
  mixed-case tuning; `git add -N` for the closing run) — both are disclosed in the
  note. The placeholder vocabulary is a superset of the brief's, in the safe
  direction.
- **The rules catch what they claim.** Scratch-repo run: a personal path mid-line
  (Windows, forward slashes), `/home/<name>`, a real-shaped `client_secret`
  assignment in both the `=` and `:` spellings, a YAML-nested assignment, a JWT
  literal, a multi-line PEM with an 80+ body, and a tracked `.env` all flagged;
  placeholders (`<…>`, `${…}`, `changeme`, empty, and a long mixed-case
  `ChangeMe…` compound) all passed; a URL-valued token key, short values, and a
  NUL-led binary carrying a personal path all passed (binary skipped). The 32-char
  threshold is exact (31 passes, 32 flags).
- **Exit codes and failure modes.** Empty-baseline scratch run: exit 1 with the
  unwaived findings listed. All-waived: exit 0, waiver printed inline, and one
  waiver covering two findings on the same file+rule (waiver is per file+rule, not
  per line — as documented). Corrupted JSON, missing baseline, unknown rule, missing
  reason, duplicate waiver, wrong document shape: all exit 2 with a specific message.
  An unused waiver prints the removal note. Two consecutive runs are byte-identical.
- **Self-discipline.** Grep of all six files for personal names, personal path
  shapes, hostnames, domains, and tenant/issuer values: clean — prose names the
  sensitive classes only in the abstract; the test fixtures are assembled from parts
  at run time (`"C:" + "/Users/" + "alice/…"`) so no committed file carries a whole
  matchable path, and `alice`/`bob` are synthetic names. The repo scan itself (run
  from the worktree) returns exactly the one waived finding, exit 0, "scanned 191
  tracked files" — reproducing the note's closing run line for line.
- **Comment rule.** No provenance in the script or tests — no owner references, no
  ruling citations, no change-folder paths. The script's docstring restates the
  *reasons* the rule set is narrow (that is behavior and rationale), not who ruled.
- **Baseline rot-resistance.** Validated in code and exercised: unknown rule,
  missing/empty reason, duplicates, and wrong shape all refuse loudly (exit 2);
  unused waivers are reported with a removal note.
- **Docs consistency.** `CLAUDE.md` gate 1 and `PROCESS.md` step 5 name the check in
  the same words (`python scripts/check_publication_leaks.py`, boundary deferred to
  the discipline section). The new `# Publication discipline` section is a sibling
  heading of `# Repo rules` and matches the file's voice.
- **Gate claims re-run.** Leak check from the worktree: exit 0, one waived finding.
  `pytest tests/test_leak_check.py -q`: 18 passed. Full `pytest -q`: 566 passed,
  1 skipped — matching the note. `ruff check` and `ruff format --check` on both new
  files: green. `bandit -c pyproject.toml -r gateway scripts`: 11 findings — the 4
  new ones on the check (B404/B105/B603/B607) match the note's triage table
  one-for-one, and the 7 pre-existing ones match the note's pre-existing list
  exactly. The tree-wide `ruff format --check .` is indeed red on this checkout for
  the pre-existing CRLF reason, as the note states. The two inline `noqa`s each carry
  a reason. mypy's `files` was not extended, per the brief.

## What could not be verified

- The **first run's** output ("scanned 187 tracked files") is historical and cannot
  be re-run; it is arithmetic-consistent (187 + the 4 new artifacts = 191, today's
  count) and the closing run reproduces exactly, so the reviewer treats it as
  credible.
- The claim that the repo's pre-existing PEM-header quotations "all sit over bodies
  too short or not base64 at all" was verified only in aggregate (the full scan
  surfaces no unwaived secret-shape finding), not file by file.

## Dispositions (round 1 fix pass)

Every finding disposed; F1 and F3 by rule change, F2/F4/F5 by documentation. All
gates re-run green after the changes — the closing leak-check output is unchanged
(exit 0, one waived finding, 191 tracked files), and the note's gates table now
carries the fresh test count (570 passed).

- **F1 (medium) — fixed by rule extension.** `_private_key_blocks` now also counts
  base64 following literal `\n` escapes on the header's own physical line
  (`_escaped_body_chars`; only base64 after an escape counts, so a header quoted in
  prose — followed by prose, not payload — still passes), subject to the same
  80-character body minimum as the multi-line form. A one-line escaped PEM in a
  `.env`-style assignment and in a compose-style value now flags; the prose-header
  pass case keeps its passing test, plus new pass tests for an escaped header with
  no payload and an escaped body too short to be a key.
- **F2 (medium) — disclosed, rule untouched.** The note's tuning paragraph now names
  the UUID shape explicitly: a Keycloak client secret (lowercase hex + dashes, the
  repo's own primary credential form) sits inside the all-lowercase blind spot
  because the synthetic fixture vocabulary shares its character class, and its
  coverage is the review gates today and gitleaks with a secret-injected
  configuration at CI/CD time (T7).
- **F3 (low) — fixed in the code.** The profile directory is now matched genuinely
  case-insensitively (scoped `(?i:...)` on the directory names, profile-name segment
  unchanged), so `/users/`, `/USERS/`, `/HOME/`, and `C:/USERS` all flag; the
  comment above the pattern now states what the regex does. New test covers the
  uppercase and lowercase POSIX spellings and the uppercase Windows spelling.
- **F4 (low) — disclosed.** The note's gates table carries one line stating that
  pip-audit, Trivy, and the compose-boot gate are not applicable to a docs-and-config
  change (no dependency, image, or composed stack), so "not applicable" is
  distinguishable from "not run".
- **F5 (info) — stated, count unchanged.** The `ScanResult` docstring and the note's
  exit-status paragraph both state in one sentence that `scanned N` is the size of
  the tracked list (`git ls-files`), not a count of files read: tracked `.env` files
  and worktree-missing paths are counted as tracked but never opened.

Fix-pass gates, all re-run from the worktree: leak check exit 0 (one waived
finding); `ruff check .` exit 0; `ruff format --check` on the script and tests exit
0; `pytest -q` — 570 passed, 1 skipped; bandit — the same 11 findings as the
round-1 triage, none new (4 on the check, 7 pre-existing).
