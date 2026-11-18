# D0a authoring brief — the publication discipline and the leak check

**What this workstream is.** D0a of the production roadmap
(`docs/production-roadmap.md` §"D0 — publication hygiene"): a GitLab remote plus the
standing public-repo discipline, with a repeatable leak check in the static gate tier
"so the discipline is a gate rather than a hope". The GitLab remote already exists;
what remains are the two artifacts this brief specifies. This is a docs/config
workstream — a direct commit after an independent review pass, not an OpenSpec change
(the D1/D2 precedent).

**The design ruling this brief records (settled with the owner; do not re-litigate):**

1. **The check scans structural classes only, and commits nothing sensitive.** A
   deny-list containing the literal sensitive values (the internal GitLab hostname, the
   internal instance name) would itself be a disclosure — the script publishes with the
   repo — and would violate D0a's own rule (no new problematic content). An allowlist
   ("flag any host not on this public list") was rejected with the owner: it blocks
   legitimate situations, and every new legitimate domain becomes a gate chore. An
   uncommitted local deny-list was rejected too: it is invisible to the fresh agents
   that run these gates (the agent-freshness rule briefs from committed artifacts) and
   never reaches other team members.
2. **The hostname/URL class is deliberately NOT machine-scanned.** It is covered at
   write-time by the placeholder convention (below) and at review-time by the review
   gates. This concession is recorded in the evidence note, with the upgrade path: when
   CI/CD lands (deferred T7), gitleaks with a secret-injected config is the
   off-the-shelf replacement — noted, not built.
3. **Pre-existing exposures are waived, not fixed.** The repo carries known D0b
   backlog items (the personal path in `scripts/import_background.py`; any other
   findings the first run surfaces). The script needs a committed waiver baseline keyed
   by file + rule — never by the matched value — each entry reasoned. The matched
   values stay out of the baseline file; the waiver says the exposure is known and
   awaits the pre-publication cleanup.

## Deliverable 1 — the discipline section in `CLAUDE.md`

A new section in `CLAUDE.md` (a sibling of `# Repo rules`, or clearly separable
bullets within it — author's choice, keep the file's existing voice: normative,
reasoned, terse). Content the section must carry:

- **The fact and the stake:** the repository will be published publicly under the
  `epam` GitHub organization as one of the `ai-dial` components. Publication is a
  one-way door — it exposes the full history and cannot be recalled.
- **The standing rule (prospective only):** from now on, every change adds **no new
  problematic content**: no new internal hostnames, instance or cluster names, personal
  paths, or real issuer/tenant/org values — in tracked files, docs, evidence, and
  commit messages alike.
- **The placeholder-in-prose convention:** issuer, tenant, and org values that prose
  must mention are written as `<>` placeholders (the same discipline `.env.example`
  applies to credentials), never as real values.
- **The credentials sentence already stands** (never-cut 6) — reference it, do not
  duplicate it.
- **The machine check:** name the script, its one-word invocation, and the gate tier
  it joins (static tier, alongside `ruff`/`bandit` — update the gate list in
  `CLAUDE.md` gate 1 and `PROCESS.md` step 5 to include it).
- **The boundary:** known pre-existing exposures are the pre-publication cleanup's
  backlog (D0b in `docs/production-roadmap.md`); they are waived in the check's
  baseline, and adding new ones is a violation.

## Deliverable 2 — `scripts/check_publication_leaks.py`

A single-file, dependency-free script (stdlib only), runnable as
`python scripts/check_publication_leaks.py` from the repo root. Design:

- **Input:** the tracked file set (`git ls-files`, via `subprocess.run` with a list of
  arguments — no shell). `.env` (and `.env.local`/`.env.*.local`) being tracked is
  itself a finding class.
- **Rule classes (the whole set — nothing else):**
  1. *Personal path* — `C:\Users\<name>\…`, `/home/<name>/…`, `/Users/<name>/…` as
     regex shapes. Note Windows text read: open files with UTF-8 and
     `errors="replace"`; the console must not crash on Unicode (repo quirk:
     `PYTHONUTF8=1` for any process printing it — the script should set/rebind its own
     stdout encoding defensively or be run with the env var set; the evidence note
     records the invocation used).
  2. *Secret shape* — literal credentials outside placeholders: assignments of long
     literal values to `client_secret`/`password`/`token`-named keys, PEM private-key
     blocks, three-segment `eyJ…` JWT literals. Placeholder forms (`<…>`, `${…}`,
     `changeme`, empty) must NOT flag — `.env.example` is placeholder-by-design.
  3. *Tracked .env* — any `.env`-shaped file (not `.env.example`) in `git ls-files`.
- **Skip list:** binary-looking files (NUL byte in the first chunk); `openspec/changes/archive/`
  is NOT skipped — published content publishes the archive too, so the archive is
  scanned like everything else.
- **Baseline:** a committed waiver file (JSON; author picks the name, e.g.
  `scripts/leak-baseline.json`) mapping waiver entries of `{file, rule, reason}`.
  Matching is by file path + rule id only. The `reason` states the disposition in
  generic terms ("known exposure, awaits the pre-publication cleanup"). No matched
  values, no sensitive literals, in the baseline ever.
- **Output:** one line per finding, `file:line: rule-id`, then a summary; exit 1 on
  any non-waived finding; exit 0 when only waived findings remain. Deterministic
  ordering.
- **Tests:** a small `tests/test_leak_check.py` — pytest, no subprocess for the rule
  engine itself (factor the scan so rules are callable on text and testable directly);
  cover each rule's positive, negative, and placeholder cases, and a baseline-waive
  case.
- **Static gates must pass on the script itself:** `ruff check`, `ruff format --check`
  (LF endings), `bandit`. The script will trip `subprocess`-family findings
  (ruff `S603`, bandit `B404`/`B603`); the repo triages findings rather than
  silencing them wholesale — a narrow per-file ruff ignore with a reason comment, or
  `noqa` with a reason, is the repo's accepted voice for that (see how
  `pyproject.toml` documents its per-file-ignores). mypy does not cover `scripts/`
  (deliberately — do not extend `files`).

## Deliverable 3 — the evidence note

`docs/evidence/d0a/leak-check-and-discipline.md` — the D0a record: what landed, the
design ruling (the three points at the top of this brief, in the note's own words),
the first run's full output (it will show the waived backlog items — that output is
the note's value), the invocation used, and the recorded concession + upgrade path
(point  2 above). This file is read by fresh reviewers; it must stand alone.

## Constraints

- Repo comment rule (`CLAUDE.md`): comments explain behavior and reason, never
  provenance — no "per the owner", no meeting/ruling citations. The design ruling
  lives in THIS brief and the evidence note, not in code comments.
- No real internal hostname, instance name, tenant value, or personal path may appear
  in any committed file this workstream adds — including this rule's own exceptions
  (write `<>` placeholders where prose would name one).
- ruff line-length 88 wraps prose by hand; the formatter wraps code (`pyproject.toml`
  documents the split).
