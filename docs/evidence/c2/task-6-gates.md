# Task group 6 — gates (tasks 6.1–6.2; 6.3's review gates run separately)

Change: `generalized-idp-federation` (C2). Scope of this record: the compose
completion (the task-5 finding), the static tier (6.1), and the compose-boot gate plus
full suite (6.2), each with the exact command, its outcome, and the triage. Task 6.3's
security review gate and general review gate are **not this record's**: they are run by
the orchestrator with fresh, independent reviewer subagents, and their findings land in
their own records. No commit made. Files touched by this record: `docker-compose.yml`
(the completion only) and this file — nothing else.

## The compose completion (the finding from task 5's evidence)

`docker-compose.yml`'s gateway environment block named each setting one by one but did
not pass the five settings group 3 and 4 added to the model. Added, in the identity
provider block immediately after `IDP_CLIENT_SCOPES`, following the block's own pattern
(`IDP_PKCE_ENABLED` and `IDP_DISCOVERY_CACHE_TTL_SECONDS` with their model defaults;
the direct endpoint trio with the group-2 `${VAR:-}` empty-default form — the model's
`_blank_optional_url_is_unset` validator reads a blank optional URL as unset, which is
exactly why that form is safe):

    IDP_PKCE_ENABLED: ${IDP_PKCE_ENABLED:-true}
    IDP_DISCOVERY_CACHE_TTL_SECONDS: ${IDP_DISCOVERY_CACHE_TTL_SECONDS:-300}
    IDP_AUTHORIZATION_ENDPOINT: ${IDP_AUTHORIZATION_ENDPOINT:-}
    IDP_TOKEN_ENDPOINT: ${IDP_TOKEN_ENDPOINT:-}
    IDP_JWKS_URI: ${IDP_JWKS_URI:-}

Diff summary: **12 insertions, 0 deletions** (7 lines of comment in the block's existing
style + the 5 settings); no EOL churn, no other line touched.

Verification after the edit:

- `python -m pytest tests/test_settings.py -q` — **106 passed**. The suite's
  example-completeness test reads `.env.example` (which already carried all five) and
  passes; a grep over `tests/` confirms no other test asserts compose contents (the only
  `docker-compose.yml` mention in the suite is a unit-test fixture list in
  `tests/test_leak_check.py`, not an assertion about the real file).
- The compose-boot gate re-run after the edit — green, recorded under 6.2 below. The
  boot is itself the functional check of the empty-trio form: the container receives
  `IDP_AUTHORIZATION_ENDPOINT=""` (etc.) and starts, i.e. the blank trio reads as unset
  rather than as a malformed endpoint.

## Task 6.1 — the static tier

Environment: the change worktree, the main checkout's venv python
(`.venv/Scripts/python`), `PYTHONUTF8=1`/`PYTHONIOENCODING=utf-8`.

### `ruff check .`

**Green** — "All checks passed!" (exit 0), tree-wide, no triage needed.

### `ruff format --check` (tree-wide)

**Red tree-wide, and the state found is the documented checkout quirk, not a touched
file's drift.** `ruff format --check .` reports **37 files would be reformatted, 155
already formatted** (exit 1). Mechanism: the repo's committed format config pins
`line-ending = "lf"` (pyproject.toml `[tool.ruff.format]`), while the checkout's
`core.autocrlf=true` materializes every file CRLF on disk — the quirk recorded in the
session-ops memory since C1.5, where the same red was triaged the same way.

The verified triage method (the memory's LF-normalized stdin form):
`sed 's/\r$//' <file> | ruff format --check --stdin-filename <file> -`.

- All **19 Python files this change touched** (every `.py` in the change's diff —
  `gateway/__main__.py`, `gateway/app.py`, `gateway/authorize.py`,
  `gateway/federation.py`, `gateway/flow.py`, `gateway/idp.py`, `gateway/settings.py`,
  `scripts/provision_keycloak.py`, `tests/conftest.py`, `tests/test_audit.py`,
  `tests/test_authorize.py`, `tests/test_concurrency.py`, `tests/test_custody.py`,
  `tests/test_federation.py`, `tests/test_idp.py`, `tests/test_leak_check.py`,
  `tests/test_limits.py`, `tests/test_settings.py`, `tests/test_tokens.py`) — **clean
  under LF normalization**, each individually verified.
- The 37 drifted files **include no file this change touched**: they are the untouched
  remainder of the tree (the un-renamed `gateway/` modules, the spike/probe scripts,
  the un-renamed test modules), exactly the pre-existing drift class. Cross-checked
  against `git diff --name-only 8c6dbe5^ HEAD`.
- One oddity recorded for honesty: the drift list's annotations include
  `openspec/changes/archive/2026-11-04-apps-with-mcp-endpoints/evidence/review-1-findings-and-dispositions.md:944:73`
  — a markdown archive record, which `ruff format` does not process as a target; read
  it as an annotation artifact of the renderer, and either way a pre-existing, untouched
  archive file outside this change's scope.
- **Verdict: the touched files are clean; the tree-wide red is the documented checkout
  quirk.** The recorded candidate fix (a committed `.gitattributes`) remains un-landed
  and is not this change's row.

### `python -m pytest -q` (full suite)

**601 passed, 1 skipped** (exit 0), in 105.74s. (The 1 skip is the standing one; the
known ~5%-flaky custody test did not bite. Re-run again post-compose under 6.2 with the
identical outcome — 601 passed, 1 skipped, 90.33s.)

### `bandit -c pyproject.toml -r gateway scripts`

Exit 1 (findings present) — **11 findings: 8 LOW, 3 MEDIUM, 0 HIGH**; triaged:

| File | Findings | Triage |
|---|---|---|
| `scripts/probe_liveness.py` | B310 MEDIUM | pre-existing, untouched by this change |
| `scripts/probe_routing.py` | B310 MEDIUM + B404/B607/B603 LOW | pre-existing, untouched |
| `scripts/spike_env.py` | B310 MEDIUM | pre-existing, untouched (the call already carries an ruff-side `noqa: S310`; bandit does not honor it) |
| `scripts/check_publication_leaks.py` | B404/B105/B607/B603 LOW | pre-existing, untouched |
| `scripts/probe_dcr.py` | B105 LOW | pre-existing, untouched |

**Zero findings in any file this change touched** (the only `scripts/` file the change
touches, `scripts/provision_keycloak.py`, is clean, as is all of `gateway/`). The set
matches the pre-existing triaged class recorded in task 2's evidence (same untouched
helper scripts; the per-file split differs from that record's because that run omitted
`-c pyproject.toml`, this run uses the gate's canonical invocation — all findings
remain in pre-existing, untouched host-run helper scripts, none in shipped `gateway/`
code). Nothing to re-triage; nothing new introduced.

### `pip-audit` (BLOCKING)

**Green — ran live.** `python -m pip_audit` exit 0: **"No known vulnerabilities
found"**. The scanner did not fail or degrade (pip-audit queries the PyPI advisory API
directly; there is no local DB to go stale, and the run completed — no "stale scanner"
caveat applies). The local project itself is reported skipped ("dial-mcp-gateway —
Dependency not found on PyPI") — the normal skip for the installed local package, not a
scan failure; every third-party dependency was audited.

### Trivy (`wsl -e trivy fs --skip-db-update --scanners vuln,secret,misconfig .`)

Ran with the cached DB (the `--skip-db-update` form; DB freshness not re-verified —
recorded as such). Outcomes, triaged:

- **Vulnerabilities: none detected.** Trivy found **no language-specific lockfile to
  scan** ("Number of language-specific files num=0" — the repo pins dependencies in
  `pyproject.toml` without a lockfile, which Trivy's vuln scanner does not consume).
  The dependency-vulnerability verdict therefore rests on **pip-audit above, which ran
  live and is the blocking gate** — recorded as the division of labor, not as a Trivy
  green.
- **Misconfigurations: 1 LOW** — `DS-0026` (no `HEALTHCHECK` instruction in the
  Dockerfile), **pre-existing and triaged identically in the archived C1.5 gates
  evidence**; the compose-level healthchecks (which the 6.2 gate exercises) are the
  operative liveness mechanism here. Untouched by this change.
- **Secrets: 1 HIGH** — an asymmetric private key detected in **`.env`** (the local
  deployment's own `GATEWAY_SIGNING_KEY`). Triaged as a **true positive by design, not
  an exposure**: `.env` is the gitignored local configuration file (verified:
  `git check-ignore -v .env` → `.gitignore:12`, and `git ls-files .env` → untracked),
  holding the self-generated local signing key exactly where the credentials rule says
  it must live. The gate over tracked content is the publication leak check below,
  which passes. No secret material is committed or introduced by this change.

### `python scripts/check_publication_leaks.py`

**PASS** (exit 0): 212 tracked files scanned, **3 findings — 3 waived, 0 unwaived**
(`docs/evidence/d0a/review-round-1.md` ×2, `scripts/import_background.py` ×1 — all
pre-existing, all under recorded waivers; no new exposure).

### Task 2.7's family-name grep, re-run (the D14 machine check)

`grep -icE 'entra|b2c|azure|microsoft|tfp|b2clogin|ciamlogin|onmicrosoft|external id|statgpt'`
over `gateway/`, `tests/`, `pyproject.toml`, `.env.example`, `docker-compose.yml`,
`README.md`, `docs/gateway-configuration.md`, `docs/local-environment.md` —
**zero hits on every surface** (the Grep tool: 0 occurrences across both trees; the
file-level grep: 0 for each of the six files). No internal hostname added by the
compose completion (its new lines carry no hostnames — defaults `true`/`300`/empty).

**6.1 verdict: the static tier is green with findings triaged.** The one red
encountered (tree-wide `ruff format --check`) is the documented CRLF checkout quirk,
verified not to include a touched file; every scanner outcome recorded as it ran, none
inflated.

## Task 6.2 — the compose-boot gate and the full suite

### `docker compose up -d --build` (WSL docker, from the worktree)

**Green** (exit 0). The DIAL instance (`dial-instance-*`, including
`core` and `keycloak`) was up beforehand; the worktree's own stack rebuilt the gateway
image with the completed environment block (`dial-mcp-gateway:local`), recreated
`mcp-signin-gateway`, and compose reported **Healthy** while `up` waited on it.

### Health probe per service

- `docker ps` / `docker inspect` on both of the stack's services:
  `mcp-signin-gateway` — `Up (healthy)`, `health=healthy`;
  `mcp-signin-router` — `Up (healthy)`, `health=healthy`.
- Host probe through the front router: `GET http://localhost:8090/healthz` → **200**.
- The acceptance-profile fixture (`mcp-app-fixture`) is not part of the plain
  deployment stack and is not started by this gate (it boots only under
  `--profile acceptance`, per the compose file's own contract).

### `scripts/probe_end_to_end.py` through the new route (post-edit)

**Exit 0, smoke verdict green.** The probe drove the full chain against the rebuilt
stack: the IdP login form submitted (302s through the hops), **reached the client
redirect URI — the `/dial/callback/idp` spelling this change rotated to** — with
`code`/`iss`/`state` round-tripped; `/dial/token` returned 200 with an access token
(issuer `http://localhost:8090`, roles resolved, refresh present); and the minted
token authenticated a live tool call through the front door (`/dial/notion/mcp`,
HTTP 200, 74 tools listed). The sign-in completes end to end through the new route on
the completed compose configuration.

### `pytest -q` (post-edit re-run)

**601 passed, 1 skipped** (exit 0), in 90.33s — identical to the 6.1 run; the compose
edit changed no Python, and the suite agrees.

**6.2 verdict: green** — build, per-service health, front-door probe, end-to-end sign-in
through the new route, and the full suite, all recorded as they ran.

## Not this record: task 6.3

The security review gate (full depth per the SIA's High impact level) and the general
review gate are the orchestrator's separate runs with fresh independent reviewer
subagents; their findings and dispositions land in their own evidence records. This
record claims no review-gate pass.
