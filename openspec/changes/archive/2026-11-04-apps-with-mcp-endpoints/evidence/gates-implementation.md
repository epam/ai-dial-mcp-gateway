# Gate run — tasks 7.1 and 7.2 (static + compose-boot)

The gate-run pass for `apps-with-mcp-endpoints`: the lightweight/static tier (7.1) and
the compose-boot tier (7.2). No commits; no code fixed. All host commands run from the
worktree on the Windows host with the sibling checkout's `.venv/Scripts` (the worktree
carries no `.venv`; it is gitignored). Docker and Trivy run via WSL. Toolchain:
Python 3.12.13, ruff 0.17.1, mypy 2.4.0, bandit 1.9.4, pip-audit 2.10.1, Trivy 0.71.2
(the same versions the C1 gate run used).

## 7.1 Lightweight / static tier

| Gate | Command | Result |
|---|---|---|
| pytest | `python -m pytest -q` | **green** — `542 passed, 1 skipped, 1 warning in 154.40s` (matches the implementation-time count) |
| ruff check | `ruff check gateway tests scripts` | **green** — "All checks passed!" |
| ruff format | LF-normalized stdin sweep (see below) | **RED — one new finding** (`tests/test_audit.py`) |
| mypy | `mypy` (project config: `files = ["gateway","tests"]`) | **green** — "Success: no issues found in 39 source files" |
| bandit | `bandit -c pyproject.toml -r gateway` | **green** — "No issues identified." (6030 LOC; 9 `#nosec B105`, same set as C1) |
| pip-audit | `pip-audit` | **green** — "No known vulnerabilities found" (skip: the un-published project itself) |
| Trivy image | `trivy image --skip-db-update --severity HIGH,CRITICAL dial-mcp-gateway:local` | **green at CRITICAL; 44 HIGH, all OS-package, 0 fixable — the accepted base-image residual, unchanged** |
| Trivy fs | `trivy fs --skip-db-update --scanners vuln,secret,misconfig .` | **1 LOW misconfig** — `DS-0026` (no `HEALTHCHECK` in `Dockerfile`), pre-existing, triaged below |
| openspec | `openspec validate --all --strict` | **green** — 2 passed, 0 failed (13 INFO length advisories, all on the main spec) |

### ruff format — the CRLF note holds, but one file has a real content violation

`core.autocrlf=true` and no `.gitattributes`, so the working tree is CRLF. The raw
`ruff format --check` flags **51 files** tree-wide — every file, from line endings alone,
which is the known false positive.

The implementation agent's interpretation (content cleanliness verified through
LF-normalized stdin) was reproduced: each of the 52 Python files under
`gateway/`, `tests/`, `scripts/` was LF-normalized and piped to
`ruff format --check --stdin-filename <path>`. **Result: 51 clean, 1 violation.**

```
$ # LF-normalized sweep over gateway/tests/scripts (52 files)
checked 52 files; LF-normalized violations: 1
VIOLATION tests\test_audit.py
```

The violation is real content, not EOL. `ruff format --diff` on the LF-normalized file:

```diff
--- tests/test_audit.py
+++ tests/test_audit.py
@@ -271,9 +271,7 @@
     with router, make_client(settings, private_key_pem) as client:
         _run_flow(client)

-    allocated = next(
-        r for r in records_of(caplog) if r["event"] == "flow_allocated"
-    )
+    allocated = next(r for r in records_of(caplog) if r["event"] == "flow_allocated")
     assert allocated["resource_kind"] == "toolset"
```

The collapsed line is exactly **85 characters** (≤ 88), so the formatter wants it joined;
the file holds a stale hand-wrap. The offending hunk is **added by this change**
(`git diff HEAD -- tests/test_audit.py` shows the three lines as `+` lines), so this is a
**new format finding introduced by the diff**, not pre-existing. The static-tier
conclusion therefore depends on the interpretation: raw check is a false positive on 51
files and a real hit on this one; the LF-normalized check is the true reading and it is
**RED**.

**Disposition: reported, not fixed** (gate-runner does not edit code). The one-line fix
is to let ruff collapse the call onto one line. This blocks a fully-green 7.1 until the
implementation pass applies it.

### bandit `#nosec B105` suppressions (9) — unchanged from C1

The warnings are the RFC 7591/RFC 6749 method-name vocabulary, not credentials
(`gateway/routes.py` and `gateway/tokens.py`): `token_endpoint_auth_method: "none"`, the
grant-type strings in the DCR response, `ACCESS_TOKEN_TYPE`/`REFRESH_TOKEN_TYPE`, and
`CUSTODY_CLAIM_MEMBER` ("custody"), a claim *name*. Bandit reports "nosec encountered
(B105), but no failed test on file" — the suppressions currently mask nothing, the safe
direction. Triaged: retained; same 9 as C1.

### pip-audit — green

```
No known vulnerabilities found
Name             Skip Reason
---------------- -------------------------------------------------------------------------------
dial-mcp-gateway Dependency not found on PyPI and could not be audited: dial-mcp-gateway (0.1.0)
```

The skip is the un-published project itself, expected. The certifi finding C1 recorded
(certifi < 2026.10.18, remedied) does not recur: the local venv carries `certifi
2026.10.23`, and the freshly built image resolves the same.

### Trivy — DB freshness and the accepted residual

`wsl -e trivy image --download-db-only` **failed twice**, both with
`read: connection reset by peer` against `mirror.gcr.io/aquasec/trivy-db:2` (a network
fault reaching the mirror, not a scanner fault). The retry did not clear it. The cached
DB is `UpdatedAt 2026-11-01 07:08 UTC` (3 days old) and was used with
`--skip-db-update`, per the standing fallback. **This is a cache-based scan, recorded as
such** — a fresh DB was not obtainable this run.

Image (rebuilt this pass, `docker build -t dial-mcp-gateway:local .`):

```
dial-mcp-gateway:local (debian 13.7)   debian     44   -
Python                                 python-pkg  0   -
```

- **CRITICAL: 0. HIGH: 44**, all in the **Debian 13.7 base-image OS packages**. Python
  packages: **0 findings** (certifi 2026.10.23, cryptography 50.0.2, pyjwt 2.15.1,
  starlette 1.10.0, fastapi 0.162.0, httpx 0.28.1). **No secret findings.**
- The 8 distinct CVEs are **identical to C1's accepted set**: `CVE-2025-69720`,
  `CVE-2026-16742`, `CVE-2026-54369`, `CVE-2026-76642`, `CVE-2026-78408`, `CVE-2026-78409`,
  `CVE-2026-78410`, `CVE-2026-9538`. **0 of 45 rows carry a `FixedVersion`** (43
  `affected`, 1 `fix_deferred`). **No new finding beyond the accepted base-image set** — the
  accepted-residual triage (roadmap deferred table; base-image packages off the gateway's
  execution path) still holds, unremedied upstream.

`trivy fs` over the repository: **no vulnerabilities, no secrets**, and **one LOW
misconfiguration** — `DS-0026 "Add HEALTHCHECK instruction in your Dockerfile"` on
`Dockerfile`. **Pre-existing and triaged**: `Dockerfile` is unmodified by this diff
(`git status` shows no `Dockerfile` entry), and the health probe deliberately lives in
`docker-compose.yml` (`healthcheck:` per service) rather than the Dockerfile — the
compose-boot gate below confirms every service reports healthy. Not a finding of this
change.

## 7.2 Compose-boot gate

The sibling `dial-instance` stack was already running (Core, Keycloak, and the
rest, up 2 days) on network `dial-instance_default`. The gateway stack that had
been running from the **main checkout** on port 8090 was stopped (`docker compose down`
from the main checkout) to free the port and avoid a duplicate project. The worktree has
no local `.env` (gitignored), so the main checkout's `.env` was copied in (gitignored,
not a diff).

```
$ wsl -e docker compose up -d --build      # from the worktree
# image built (dial-mcp-gateway:local, sha256:ce53357d…); three services created and started
```

```
NAME                                               STATUS
c15-apps-with-mcp-endpoints-mcp-app-fixture-1      Up (healthy)
c15-apps-with-mcp-endpoints-mcp-signin-gateway-1   Up (healthy)
c15-apps-with-mcp-endpoints-mcp-signin-router-1    Up (healthy)
dial-instance-core-1                      Up 2 days (healthy)
```

Health statuses (`docker inspect … {{.State.Health.Status}}`): gateway `healthy` (5/5 exit
0), router `healthy` (5/5 exit 0), **`mcp-app-fixture` `healthy`** (5/5 exit 0 — the new
fixture's own compose healthcheck passes). Core `healthy`. **Keycloak's instance-compose
definition carries no healthcheck** (it reports no `Health` key), so a health status
cannot be read there; it is running and answering (below).

### Boot probes (all green)

| Probe | Command | Output |
|---|---|---|
| Router health through the front door | `GET http://localhost:8090/healthz` | **HTTP 200** `{"status":"ok"}` (the router probes the gateway through itself — its compose healthcheck) |
| Core through the front door | `GET http://localhost:8090/health` | **HTTP 200** |
| Fixture MCP `initialize` (in-network) | `python` from the gateway container → `http://mcp-app-fixture:9000/mcp` | **200** `{"result":{"protocolVersion":"2025-06-18",…,"serverInfo":{"name":"mcp-app-fixture","version":"0.1.0"}}}` |
| Fixture MCP `tools/list` | same | **200** `{"result":{"tools":[{"name":"echo",…}]}}` |
| Fixture query-string preservation | same, path `?sessionId=probe-123` | **200** `{"result":{"sessionId":"probe-123"}}` |
| **Negative control** — fixture stopped | same three calls with the fixture down | **all three ERR** `[Errno -2] Name or service not known`; after `docker start`, the fixture returns to `healthy` and all three calls return 200 again |

### Composed-surface smoke checks (7.2's boot-gate scope, not the 7.3 acceptance)

| Check | Command | Output |
|---|---|---|
| AS metadata | `GET /…/oauth-authorization-server` | **200**, flat RFC 8414 document (issuer `http://localhost:8090`, the gateway's endpoints) |
| Apps PRM, guard-passing name | `GET /…/oauth-protected-resource/apps/my-app/mcp` | **200** `{"resource":"http://localhost:8090/apps/my-app/mcp","authorization_servers":["http://localhost:8090"],"scopes_supported":[]}` |
| Apps PRM, bad-charset name | `GET /…/oauth-protected-resource/apps/Bad_Name/mcp` | **404** `{"detail":"unknown app"}` (guard refusal at discovery) |
| Apps PRM, reserved name | `GET /…/oauth-protected-resource/apps/token/mcp` | **200** — correct per the delta spec: app names have no reserved-name refusal (reserved names are `/dial/`-scoped), only the charset guard applies |
| Apps MCP path, unauthenticated | `GET /apps/my-app/mcp` | **401** with `WWW-Authenticate: Bearer resource_metadata="http://localhost:8090/.well-known/oauth-protected-resource/apps/my-app/mcp"` — the apps challenge names the apps metadata path |
| Toolset MCP path, unauthenticated (contrast) | `GET /dial/notion/mcp` | **401** with `WWW-Authenticate: …oauth-protected-resource/dial/notion/mcp` — the toolset challenge, unchanged |
| Status path removed | `GET /dial/x/status` | **401 from Core**, body `At least API-KEY or Authorization header must be provided`, **no `WWW-Authenticate`** — see the note |

### Note — the status-path probe's expected answer

The task text and design.md (`§D4`, the migration plan) both say a status path under
either namespace "falls to the router's catch-all and is answered by **Core's 404**". The
live probe returns **Core's 401**, not 404. The *removal* is confirmed exactly as
intended — `HEAD:router/nginx.conf` carried `location ~ ^/dial/[a-z0-9-]+/status$` →
gateway; the new config drops it, so the path reaches `location /` → Core unmodified, and
`status.py` with its route is deleted (no `gateway/routes.py` status route remains). What
differs is only Core's *status code* for the fall-through request: Core's auth filter runs
before routing and answers **every** unauthenticated request with 401 — confirmed with a
control: `GET /nonexistent-xyz-123` also returns 401 with the same body, and
`GET /dial/notion/mcp` returns 401-with-challenge. So "answered by Core's 404" is true only
for an *authenticated* request; for the unauthenticated probe the observable is "answered by
Core, with Core's own auth refusal and none of the gateway's challenge". The removal itself
is observable and correct; the design's one-word expectation ("404") is imprecise for an
unauthenticated probe. **Recorded for the orchestrator; not a defect in code or routing.**

## Summary

| Gate | Result |
|---|---|
| 7.1 pytest | **green** — 542 passed, 1 skipped |
| 7.1 ruff check | **green** |
| 7.1 ruff format (LF-normalized) | **RED — 1 new finding** (`tests/test_audit.py`, the stale `next(...)` wrap; blocking for a fully-green 7.1) |
| 7.1 mypy | **green** — 39 files |
| 7.1 bandit | **green** — 9 suppressions, same as C1 |
| 7.1 pip-audit | **green** (BLOCKING gate satisfied) |
| 7.1 Trivy image | **0 CRITICAL; 44 HIGH base-image OS, 0 fixable — accepted residual, unchanged** (cache-based: DB download failed twice) |
| 7.1 Trivy fs | **1 LOW misconfig `DS-0026`, pre-existing, triaged** |
| 7.1 openspec validate --strict | **green** — 2 passed, 0 failed |
| 7.2 compose boot | **green** — gateway, router, fixture all healthy; every boot probe passes |
| 7.2 composed-surface smoke | **green** — AS metadata, apps PRM, apps MCP 401-with-apps-challenge all as intended; status path confirmed removed (returns Core's 401, not the design's predicted 404 — noted) |

**Blocking for the change's completion:** the one ruff-format finding
(`tests/test_audit.py`) — a one-line edit for the implementation pass. Everything else is
green or a triaged pre-existing/accepted residual. **The tree is otherwise ready for the
7.3 live acceptance**: the composed stack is up and healthy, the app fixture answers a live
MCP handshake (with the negative control passing), and the apps front-door surface answers
as the delta spec requires.

## Boot re-verifications after the compose shape changed (Rounds 12–13)

The boot record above predates two later changes to the composed stack; this section
carries the re-verifications, so the tail reads as one consistent history. The original
boot section is left as recorded.

**The profile gate (Round 12, MINOR 3).** The boot above ran with `mcp-app-fixture`
unconditional — a plain `docker compose up -d` started the test fixture beside the gateway
and router. The service was then gated behind `profiles: ["acceptance"]`, which changes the
composed *set* the deployment stack brings up: the plain boot is now exactly
`mcp-signin-gateway` + `mcp-signin-router`, and the fixture comes up only under the
`acceptance` profile. Round 12 verified both live: `docker compose config --services` →
the gateway and router alone (three with `--profile acceptance`); the fixture under the
profile reached `healthy` (5/5 healthchecks exit 0) and was then stopped; and the plain
boot created and started only the gateway and router, both `healthy`.

**The `APPS` wiring (Round 13, B1).** The gateway's compose `environment:` block listed
`TOOLSETS` but not `APPS`, so the second resource kind's operator restriction never reached
the container — the gateway served every guard-passing app name with no way to restrict the
set, and the omission would have stayed invisible until an operator set `APPS` and saw no
effect. The line `APPS: ${APPS:-{}}` was added beside `TOOLSETS: ${TOOLSETS:-{}}`, matching
its escaping and spacing. Re-verified live this round: `docker compose up -d
mcp-signin-gateway` recreated the container, `docker inspect … .Config.Env` shows `APPS={}`
(`docker exec … echo "$APPS"` → `{}`; the local `.env` sets no `APPS`, so the empty default
is the value, and the wiring — not the value — is what was verified), and the gateway
returned to `healthy` (FailingStreak 0) after the recreate. `TOOLSETS` in the same container
still carried the mapped toolset (`{"notion":{…}}`), confirming the two lines coexist.

**Known gap (recorded, not fixed): no automated guard covers compose-environment
completeness.** Nothing in the suite or the gates asserts that every setting the gateway
reads has a compose `environment:` line, so an omitted variable (this B1) is caught only by
a live re-verification or an operator noticing the setting has no effect. A
compose-environment-completeness test would close the class; it is not part of this change.
Recorded as a known gap here rather than silently left.

Both re-verifications were run against the same worktree stack (`c15-apps-with-mcp-endpoints`
project) on the live `dial-instance_default` network; no other service was
disturbed.
