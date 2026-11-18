# D0a — the leak check and the publication discipline

The D0a record. What landed, why it is shaped the way it is, the first run's output,
and the gates. Written to stand alone: a fresh reviewer needs nothing but this note
and the files it names.

D0a of `docs/production-roadmap.md` §"D0 — publication hygiene" is the standing half
of publication hygiene: the GitLab remote (already in place) plus the discipline and
the machine check recorded here. The cleanup itself is D0b and is deliberately not
attempted here — D0a's requirement is to stop making the situation worse, which is
what keeps the eventual cleanup bounded.

## What landed

- `CLAUDE.md` — a `# Publication discipline` section (the fact and the stake, the
  standing rule, the placeholder convention, the machine check, the boundary), and
  the leak check added to gate 1's static-gate list.
- `PROCESS.md` — step 5's static-gate list extended with the same check.
- `scripts/check_publication_leaks.py` — the check itself: stdlib-only, single file,
  `python scripts/check_publication_leaks.py` from the repo root.
- `scripts/leak-baseline.json` — the committed waiver baseline.
- `tests/test_leak_check.py` — the rule engine's tests (the rules are factored to be
  callable on text directly; no test runs the script through a subprocess).

## The design ruling

Three points, settled before implementation:

1. **Structural rules only; the check itself commits nothing sensitive.** A
   deny-list holding the literal sensitive values (the internal GitLab hostname, the
   internal instance name) would itself be a disclosure — the script publishes with
   the repository — and would break D0a's own rule. An allowlist ("flag any host not
   on this public list") was rejected: it blocks legitimate situations and turns
   every new legitimate domain into a gate chore. An uncommitted local deny-list was
   rejected too: it is invisible to the fresh agents that run these gates (they are
   briefed from committed artifacts) and never reaches the rest of the team.
2. **The hostname/URL class is deliberately not machine-scanned.** It is held at
   write time by the `<>` placeholder convention and at review time by the review
   gates. Concession and upgrade path below.
3. **Pre-existing exposures are waived, not fixed.** The known backlog (the personal
   path in `scripts/import_background.py`, and anything else the first run surfaced)
   stays; the baseline records it keyed by **file + rule**, each entry reasoned, and
   **never by matched value** — a baseline that quoted what it waived would publish
   the material it exists to keep out.

## The rule set (the whole set — nothing else)

| Rule id | What it flags |
|---|---|
| `personal-path` | A user-profile path: `C:\Users\<name>\…` (either slash direction), `/home/<name>/…`, `/Users/<name>/…`. |
| `secret-shape` | Machine-shaped secret literals: a 32+-character mixed-case value assigned to a secret-, password-, or token-named key; a PEM private-key block with a real-sized base64 body (80+ characters — as follower lines after a multi-line PEM, or on one physical line joined by literal `\n` escapes, the `.env`/compose/JSON embedding; prose quoting a header and one-line test fixtures pass); a three-segment `eyJ…` JWT literal. |
| `tracked-env` | Any `.env`-shaped file in `git ls-files` other than `.env.example` — the finding is the file's existence. |

Tuning worth knowing, because a reviewer will ask why the obvious fakes in
`tests/` do not trip the assignment rule: the value must be **mixed-case** within a
32+ character credential charset and free of the placeholder vocabulary
(`change-me`, `generate-me`, `<…>`, `${…}` — the last two fail the charset on their
own). Synthetic fixtures in this repository are lowercase words joined by dashes, so
they pass by design — the same stance `pyproject.toml`'s tests per-file-ignores take
for ruff. The cost of that tuning is a real secret that happens to be all-lowercase
or all-caps; the review gates are the backstop for it, and this is the check's
stated boundary, not an accident. **That blind spot contains this deployment's own
primary credential shape**: a Keycloak client secret is by default a UUID —
lowercase hex and dashes, the same character class the synthetic fixture vocabulary
lives in — so a leaked one passes this check. Its coverage is the review gates on
every diff today and gitleaks with a secret-injected configuration at CI/CD time
(T7); the rule cannot be tightened without taxing the fixture vocabulary with it.

Binary-looking files (a NUL byte in the first 8 KiB) are skipped. The OpenSpec
archive is **not** skipped — published content publishes the archive too.

Exit status: 0 when only waived findings remain, 1 on any unwaived finding, 2 when
the baseline itself cannot be read. Waivers cover a file's exposure under one rule,
not one line of it, so harmless edits above a waived exposure do not break the gate.
An unused waiver is reported as a note so the baseline cannot silently rot. The
summary's `scanned N` counts the tracked list (`git ls-files`), not the files whose
contents were read: tracked `.env` files — already findings at the file level — and
paths missing from the worktree are counted as tracked but never opened.

## The first run

Invocation (from the repo root, repo venv):

```
PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python scripts/check_publication_leaks.py
```

First run, before the D0a artifacts themselves were in the tracked set:

```
scripts/import_background.py:15: personal-path (waived: known exposure; awaits the pre-publication cleanup)
summary: scanned 187 tracked files; 1 finding(s): 1 waived, 0 unwaived
verdict: PASS
```

Exit 0. The run surfaced exactly the one known D0b backlog item — the personal path
in `scripts/import_background.py` — and nothing else: no tracked `.env`, no PEM
block with a real-sized body, no JWT literal, no machine-shaped secret assignment
(the PEM headers quoted in `tests/` and in an archived evidence file all sit over
bodies too short or not base64 at all, which is the tuning working as intended).

Closing run, with every D0a artifact — including this note — marked intent-to-add so
the check scans the files that carry it (the check reads `git ls-files`, so a
not-yet-committed file is invisible to it until it enters the index; `git add -N`
puts it there without committing):

```
scripts/import_background.py:15: personal-path (waived: known exposure; awaits the pre-publication cleanup)
summary: scanned 191 tracked files; 1 finding(s): 1 waived, 0 unwaived
verdict: PASS
```

Exit 0. The check's own script, baseline, and tests — and this note — are clean
under the rules they carry: the fixtures in `tests/test_leak_check.py` are assembled
from parts at run time precisely so the committed file does not itself contain a
whole match for the rule it tests. The round-1 fix pass (the one-line escaped-key
detection and the case-insensitive profile directory) re-ran the check and
reproduced this output exactly — the extension changes no verdict on this tree.

## The baseline

`scripts/leak-baseline.json`, two entries today:

| file | rule | reason |
|---|---|---|
| `scripts/import_background.py` | `personal-path` | known exposure; awaits the pre-publication cleanup |
| `docs/evidence/d0a/review-round-1.md` | `personal-path` | the review record quotes synthetic probe samples; the quotes are the evidence |

The disposition is generic on purpose: the baseline states that an exposure is known
and belongs to D0b; the matched values stay out of the file. Adding a new entry for
a new exposure, in the change that adds the exposure, is a violation of the
discipline — the baseline records debt, it does not license it. One class is
waived by file on a different ground: review and evidence records that quote
detector trigger samples are waived by file, because the quotes are the record.

## Gates

| Gate | Command | Result |
|---|---|---|
| leak check | `python scripts/check_publication_leaks.py` | exit 0, output above |
| ruff lint | `ruff check .` | exit 0 — all checks passed |
| ruff format | `ruff format --check scripts/check_publication_leaks.py tests/test_leak_check.py` | exit 0 — both files formatted (LF) |
| unit tests | `pytest -q` | exit 0 — 570 passed, 1 skipped (the D0a tests included) |
| bandit | `bandit -c pyproject.toml -r gateway scripts` | findings triaged below |
| pip-audit / Trivy / compose-boot | — | not applicable: this change touches docs and config only — no dependency, no image, no composed stack — so there is nothing for these three gates to examine |

The tree-wide `ruff format --check .` is red on this checkout for the pre-existing,
documented reason: `core.autocrlf` makes every tracked file CRLF and the formatter
requires LF. That is a property of the checkout, not of this change; the D0a files
themselves are LF and pass the format check directly.

Bandit, triaged per the repo's practice (findings stay visible; the dispositions
live here). Pre-existing on the tree, untouched by D0a: `probe_dcr.py` B105 (`'none'`
read as a password), `probe_liveness.py` B310, `probe_routing.py` B404/B310/B603/B607,
`spike_env.py` B310. New, all on `scripts/check_publication_leaks.py`:

| Finding | Disposition |
|---|---|
| B404 (`import subprocess`) | The module needs `git ls-files` — the tracked file set is the check's input. No shell is used. |
| B105 (`'secret-shape'`) | Name-collision false positive: the constant is the rule's own id string, not a credential. The ruff twin (S105) is triaged inline at the line with a noqa and reason. |
| B603 (subprocess call) | The argv is a fixed literal list (`git`, `ls-files`, `-z`); nothing caller-supplied reaches it, and the cwd is the repo root. |
| B607 (partial path `git`) | PATH resolution is by design: an absolute path would embed this host's installation layout into a committed script. |

## The concession and the upgrade path

The hostname/URL class — the internal GitLab hostname, the internal instance name,
issuer and tenant values in URL shape — is **not machine-scanned**, and D0a accepts
that knowingly: every machine approach either discloses the values (deny-list),
taxes every legitimate new domain (allowlist), or hides from the agents and
teammates that run the gates (local config). Until CI/CD lands (deferred T7 in
`docs/production-roadmap.md`), that class is held by two humans-in-the-loop layers:
the `<>` placeholder convention at write time (`CLAUDE.md`'s publication discipline
section) and the review gates on every diff.

Upgrade path, noted and not built: when CI/CD exists, gitleaks with a
secret-injected configuration — the sensitive literals living only in the CI
environment, never in the repository — is the off-the-shelf replacement for this
concession, and can also take over the URL-shaped secret scanning this script
deliberately does not attempt.

## Constraints honored

No real internal hostname, instance name, tenant value, or personal path appears in
any file D0a adds — prose that would name one carries a `<>` placeholder instead.
Code comments in the new files carry behavior and reason, never provenance; the
rulings summarized above live here, not in the code.
