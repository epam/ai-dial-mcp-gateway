# Repo rules

- **Spec-first.** The normative specs live under `openspec/specs/`; read them before
  writing code, and change a spec before changing the design it describes — through its
  own OpenSpec change, never by drift. If a spec looks wrong, stop and flag.
- **Code comments carry behavior and its reason — never provenance.** A comment (and a
  spec) explains WHAT the code does and WHY, in terms that survive an org change and make
  sense to an outside reader. It does NOT cite rulings or process artifacts — no "the
  owner", no change-folder paths, no "per the review". WHO decided and WHEN lives in the
  change folder (`design.md`, `evidence/`), the commit message, and git history.
- **Stages.** Work follows `ROADMAP.md`'s stages, each gated on its spec's conformance
  rows. One stage per session, criteria-triggered (no calendar dates).
- **Defects and gate failures run the documented cycle** (`PROCESS.md`): instrument
  (negative control first) → diagnose → spec gate → spec change (reviewed) → implement →
  lightweight gates → re-test — iterating until the stage's rows are green.
- **Gates, in order, before any stage is "done":**
  1) static gates green with findings triaged: `ruff check`, `ruff format --check`,
     `mypy` (if configured), `bandit`, `pip-audit` (BLOCKING — a reachable vulnerability
     blocks the release, including transitive ones; the remedy is a dependency bump, and
     a stale scanner is not a green gate), Trivy (`wsl -e trivy --skip-db-update` if
     the DB is stale), and the publication leak check
     `python scripts/check_publication_leaks.py` (exit 0; only waived findings —
     the publication discipline below names the boundary);
  2) **the compose-boot gate** — `docker compose up` brings the stack up and a health
     probe passes for every service. A green unit suite proves nothing about the
     composed stack; this gate is the analogue of a multi-platform compile gate;
  3) the change's conformance/spec rows green;
  4) a security review gate on the diff — an independent reviewer subagent (different
     from the implementer, ideally from the spec author) reviews every change against its
     security impact analysis and the threat model. Its depth scales with that analysis;
     a change claiming "no security impact" gets a focused pass whose job is to
     *falsify* that claim. Runs before the general review gate;
  5) a review gate on the diff by an independent reviewer subagent.
  Commit locally; push only after the change's gates pass. Never force-push.
- **Security invariants are never cut** (see `ROADMAP.md`'s never-cut list); scope cuts
  follow `ROADMAP.md`'s cut order only.
- **A full security impact analysis on every change.** Each change's design carries a
  complete SIA — no depth dial; the impact level is recorded and sets the security
  review gate's depth, never whether the analysis runs. Method:
  `docs/security-analysis.md` (operational checklist: the `security-analysis` skill).
  The change's mitigations land in its delta spec and in the threat model
  (`docs/threat-model.md`; until the D2 baseline lands, the change's `design.md` —
  `docs/security-analysis.md` §3) before implementation — a mitigation that exists
  only in prose is not landed.
- **Roles split** — authoring and review are **opus** subagents; troubleshooting,
  implementation, and gate/test runs are **sonnet** subagents: `PROCESS.md`'s Roles
  section.
- **Credentials.** No credential, token, secret or password is ever committed. Local
  configuration goes in `.env` (gitignored) with committed `.env.example` placeholders.
  A hardcoded `client_secret`, password or JWT is a blocking defect.
- **Authoritative public references.** The DIAL Core source and documentation
  (https://github.com/epam/ai-dial-core, https://docs.dialx.ai), the MCP specification
  (https://modelcontextprotocol.io), and IETF RFCs.
- Python toolchain: `python -m venv .venv`; run tooling from `.venv/Scripts`. Trivy lives
  in WSL (`wsl -e trivy`); use `--skip-db-update` when the vuln-DB download fails and the
  cached DB is recent. Docker is in WSL2, not Docker Desktop (`wsl -e docker …`).
  Set `PYTHONUTF8=1` / `PYTHONIOENCODING=utf-8` for any process that prints Unicode
  (the Windows console is cp1252 and crashes on the default).

# Publication discipline

- **The fact and the stake.** This repository is published publicly under the
  `epam` GitHub organization as one of the `ai-dial` components. Publication is a
  one-way door: it exposes the full history, and history cannot be recalled. The
  internal GitLab remote is the archived private record of the pre-publication
  history. The standing rules below — prospective-only, placeholders, the machine
  check — keep applying to every change.
- **The standing rule — prospective only: no new problematic content.** From D0a on,
  every change adds no new internal hostnames, instance or cluster names, personal
  paths, or real issuer/tenant/org values — in tracked files, docs, evidence, and
  commit messages alike.
- **Placeholders in prose.** Where prose must name an issuer, tenant, or org value,
  write a `<>` placeholder — the same discipline `.env.example` applies to
  credentials — never the real value.
- **Credentials** are already governed by the repo rules above (never-cut 6); nothing
  in this section relaxes that.
- **The machine check.** `python scripts/check_publication_leaks.py` scans every
  tracked file for the structural leak classes — personal paths, machine-shaped
  secret literals, a tracked `.env` — and runs in the static gate tier alongside
  `ruff` and `bandit` (gate 1 above, step 5 of `PROCESS.md`). A new finding blocks
  the change.
- **The boundary.** Known pre-existing exposures are the pre-publication cleanup's
  backlog (D0b); each is waived in the check's committed baseline
  (`scripts/leak-baseline.json`) with a stated reason, keyed by file + rule and never
  by matched value. Adding a new exposure is a violation — the baseline records debt,
  it does not license it.
