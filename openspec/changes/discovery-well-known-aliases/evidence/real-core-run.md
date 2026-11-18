# Real-Core run — the full battery against a live DIAL Core

The run task 6.5b asks for: the full `scripts/probe_routing.py` with no flags, against a
**real** composed instance, closing the "Core stand-in" caveat that tasks 6.3 and 6.4 carry.
Hostnames in this record are the composed stack's loopback ones; container and instance
names are described rather than spelled, per the publication discipline.

**Verdict: the battery did NOT go green.** It stops at its own first control (W0), whose
premise does not hold against the Core build on this host. The run is recorded in full
below, with the root cause; 6.5b stays open.

## Environment

| Fact | Value |
|---|---|
| Change branch | `mr-2-discovery`, commit `bdaff70` (one commit ahead of `master` `7c3206e`) |
| Stack | this repository's compose project brought up from the change worktree: `mr-2-discovery-mcp-signin-gateway-1` (`dial-mcp-gateway:local`, healthy) and `mr-2-discovery-mcp-signin-router-1` (`nginx:1.27-alpine`, healthy), publishing `8090` |
| Core ("the real Core") | the sibling local DIAL instance's Core container, healthy, published at `localhost:8081`; image a locally built September-2026 Core (source commit `894328d6`, tag `deps-v2`) |
| Probe origin | the deployment's configured public origin, `http://127.0.0.1:8090` (see the origin note below) |
| Core-direct origin | `http://localhost:8081` |
| Docker | WSL2 (`wsl -e docker`), not Docker Desktop |

The main checkout's `mcp-signin` stack (which occupied `8090`) was brought down first; the
instance's own containers were left running and untouched.

## Compose-boot gate

`docker compose up -d` from the change worktree, after the gateway image build: both
containers report **healthy**, and `GET http://localhost:8090/healthz` through the router
answers **200**. (The image build needed three attempts: two `pip` downloads inside the
build failed mid-stream with `BrokenPipeError` — the known WSL-NAT/VPN egress flake, not a
build defect; the third succeeded.)

Pre-flight sanity (the change's new alias):
`GET /.well-known/oauth-authorization-server` and `GET /.well-known/openid-configuration`
return the **same document byte for byte** — the alias works on the running stack.

## The battery (task 6.5b)

`python scripts/probe_routing.py` (no flags), from the change worktree against the running
stack. It mints its own token; both query-string rows read Core's request line from the
instance Core container's log.

The run stops at the W0 control, so the battery's own runner reports the remaining rows as
`not run`:

```text
[1/31] negative control — Core's own challenge
  request   GET http://localhost:8081/v1/toolset/notion/mcp  (direct to Core, outside the router)
  status    401
  challenge 'Bearer resource_metadata="http://localhost:8081/.well-known/oauth-protected-resource/v1/toolset/notion/mcp"'
  verdict   control red — Core's own challenge names its own metadata

[2/31] W0 negative control — Core's own answer on a discovery path
  request   GET /.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 401  type -  core-trace absent  nosniff absent
  (direct to Core, outside the router)
  record    Core's answer carries X-Content-Type-Options: False
  FAILED    W0: expected Core's 401, text/plain, with its trace header; observed status 401, type -, body b'At least API-KEY or Authorization header must be provided'. The discriminator the later rows rely on does not hold, so none of their verdicts means anything

the control failed, so no later probe's acceptance means anything
=== battery verdict ===
  pass      negative control — Core's own challenge
  FAIL      W0 negative control — Core's own answer on a discovery path
  not run   W0c negative control — the gateway's own 404
  not run   ... (all remaining rows) ...
```

## Root cause of W0 (and W7)

W0 asserts that Core's own `401` on a discovery path carries `X-Dial-Trace-Id` (and a
`text/plain` content type). The Core build on this host does neither: its `401` is
`At least API-KEY or Authorization header must be provided` with **no** `Content-Type` and
**no** trace header (only `access-control-allow-origin: *`). Verified three ways:

- `curl -D -` direct to Core: no `x-dial-trace-id`, no `content-type` on the `401`.
- The Core container's own `server-0.0.0.jar` `Proxy.class` contains no `X-DIAL-TRACE-ID`
  string at all (the only trace-related strings are `traceparent` in unrelated code paths).
- Core's source: the response trace headers come from `putTraceHeaders`, added in Core
  commit `493965be` ("opt-in OpenTelemetry GenAI span enrichment and trace correlation
  headers", 2026-09-23), whose first release tag is **0.49.0**. The image on this host is a
  **September-2026** build at source commit `894328d6` (2026-09-04) — **before** that commit,
  which is not an ancestor of it. Beyond the version gap, the feature is *opt-in*:
  `responseTraceHeaders` defaults to `false` in Core's static settings, and this instance's
  settings carry no `tracing` block.

So the discriminator W0 (and W7) depends on is doubly unavailable here: the local Core
predates the feature, and even a newer Core would emit the header only when the operator
turns `responseTraceHeaders` on. This is a property of the **Core build/instance**, not of
this change's router, gateway, or probe logic.

## What the run does establish

W0's message is a shared failure, so the runner gates the rest. To see whether the change's
own behaviour holds against a live Core, each row was also called directly against this
stack (read-only diagnostic; no repository file changed). With the probe pointed at the
deployment's configured origin (`--origin http://127.0.0.1:8090`):

| Row | Result against the live Core |
|---|---|
| W0 (control) | **FAIL** — Core's `401` has no trace header, no content type (root cause above) |
| W0c (control) | pass — the gateway's own JSON `404`, no discriminator header |
| query string survives the routing | **pass** — Core's own log line carried the parameter, both methods |
| query string survives the apps routing | **pass** — same, apps path |
| flat AS metadata through the router | pass |
| per-toolset PRM / apps PRM through the router | pass |
| data-path 401 rewritten to the gateway's challenge | pass |
| apps data-path 401 rewritten to the apps challenge | pass |
| gateway paths reachable through the front door | pass |
| consent action route reachable through the front door | pass |
| status paths refused by the router's map | pass |
| lockstep: the map and the guard hold their documented division | pass |
| lockstep: the apps map/guard division | pass |
| W1 openid-configuration serves the canonical document | pass |
| W2 path-insertion aliases serve the canonical document | pass |
| W4 unserved well-known paths are the router's 404 | pass |
| W5 closure is method-blind, no CORS | pass |
| W6 precedence: AS, toolset, and app documents still served | pass |
| W7 Core's templates through the front door equal Core direct | **FAIL** — Core's trace header absent via the front door (both sides answered `200` with the same shape; the row fails only on the trace-header assertion, same root cause as W0) |
| W8 off-template shapes under Core's prefix are closed | pass |
| W10 a–g normalization (both directions) | pass |
| W12 served locations' end edges are closed | pass |
| W13 path-appended forms are the data path's refusal | pass |

Net: with the correct origin, **every row passes except the two that assert Core's trace
header (W0 and W7)** — including both query-string rows against a real Core and its real
log, and W7's comparison against Core-direct up to the trace-header assertion. The router's
and the gateway's behaviour is established against a live Core; the two trace-header rows
are blocked by the Core build, not by the change.

## Second finding — the origin the router publishes disagrees with `GATEWAY_PUBLIC_ORIGIN`

The router answers every challenge with `$mcp_origin`, documented (`docs/routing.md`,
`router/nginx.conf`) as *the value that must equal the gateway's `GATEWAY_PUBLIC_ORIGIN`*.
On this checkout they disagree:

- `router/nginx.conf`: `set $mcp_origin "http://localhost:8090";` (a literal)
- `.env` (the local profile): `GATEWAY_PUBLIC_ORIGIN=http://127.0.0.1:8090`

Measured on the running stack:

- `GET /dial/notion/mcp` (no auth) → `WWW-Authenticate: Bearer resource_metadata="http://**localhost**:8090/.well-known/oauth-protected-resource/dial/notion/mcp"` — the router's `$mcp_origin`.
- `GET /.well-known/oauth-authorization-server` → `"issuer": "http://**127.0.0.1**:8090"` — the gateway's `GATEWAY_PUBLIC_ORIGIN`.
- `GET /.well-known/oauth-protected-resource/dial/notion/mcp` → `"resource": "http://**127.0.0.1**:8090/dial/notion/mcp"`.

So a client that follows the challenge is sent to a *different origin* than the one the
documents and minted tokens carry — the exact mis-assembly `router/nginx.conf` and
`docs/routing.md` warn against. Its consequences in this run:

- Run with the probe's default origin (`http://localhost:8090`), the AS-metadata,
  PRM, challenge, and W1/W2/W6/W10a rows **fail** on the issuer/origin mismatch
  (`its issuer is 'http://127.0.0.1:8090', expected 'http://localhost:8090'`), and the two
  query-string rows fail because a token minted with `iss=localhost:8090` is rejected by
  Core, whose provider `issuerPattern` is pinned to `^http://127.0.0.1:8090$`.
- Run with `--origin http://127.0.0.1:8090`, those rows pass.

Which side is authoritative is a deployment decision, but as checked out the two settings
differ, and the probe's default origin assumes the router's literal (`localhost`) rather
than the `.env` value. Flagged for the owner; this record does not change either file.

## Lightweight static gates (from the change worktree)

| Gate | Result |
|---|---|
| `ruff check .` | green — "All checks passed!" |
| `ruff format --check --config 'format.line-ending = "cr-lf"' .` | green — 282 files already formatted |
| `bandit -r gateway -c pyproject.toml` | no issues (0 low, 0 medium, 0 high; 9 `nosec`) |
| `pytest -q` | **771 passed, 1 skipped**, 1 warning in 146.12s |
| `python scripts/check_publication_leaks.py` | exit 0 — 322 tracked files scanned; 3 findings, all waived; 0 unwaived |

`pip-audit` and Trivy were **skipped**: no dependency or image-layer change has landed since
their results were recorded in `evidence/gate-run.md`, so they are unchanged.

## Closing note

- The implementation and re-test gates (tasks 6.3, 6.4) remain as recorded in
  `evidence/gate-run.md`; the compose-boot gate reproduced green here as well.
- 6.5b stays **open**: the battery did not go green, blocked by the Core build's missing
  trace header (W0, W7) and, secondarily, by the origin mismatch above. The dev-deployment
  smoke (task 6.5, W11) and a re-run of 6.5b against a Core that emits
  `X-Dial-Trace-Id` (release ≥ 0.49.0 with `responseTraceHeaders` enabled) remain to be
  done before archive.
- No credential appears in this record; the probe's token is printed only as a redacted
  handle. The stack was left running.

## 2026-11-17 — the battery went green, under the local origin override

The re-run the original entry above asked for. Two findings from the 2026-11-16 attempt are
now closed: (1) the W0/W7 trace-header premise, by an owner-ruled instrument amendment; and
(2) the origin mismatch, by a recorded **local override** of the router conf (the owner's
ruling: do not touch the committed `router/nginx.conf`, `.env`, or any instance config; run
the battery against a self-consistent origin locally and record the deviation plainly).

**Verdict: the full battery passes 31/31 against the real Core**, run from the change
worktree against the composed stack, after the W0/W7 relaxation and under the local origin
override described below. Task 6.5b is satisfied.

### Finding 1 — the W0/W7 trace-header pin, relaxed (a post-review instrument change)

The 2026-11-16 entry established that W0 and W7 asserted Core's opt-in `X-Dial-Trace-Id`
header (a Core ≥ 0.49.0 feature, `responseTraceHeaders`, off by default in this instance).
That assertion is a property of the Core build and instance settings, not of the change, so
it made the two controls unusable on this host. Per the owner's ruling, `scripts/probe_routing.py`
is amended so the header is **informational** rather than asserted:

- **W0** now asserts what holds on any Core build and any deployment — Core's own `401` is
  distinct from the router's closure by status and by the router's discriminator header
  (`X-Content-Type-Options: nosniff` absent on Core's answer, present on the router's fixed
  JSON `404` body). The `X-Dial-Trace-Id` value is printed under `record`, not checked.
- **W7** now asserts the equality of the two answers (status and document shape, which hold
  on any build) and, when a build does emit the header, its agreement across the front-door
  and direct answers — rather than requiring its presence.

This is an **instrument change made after the review gates ran**, and is disclosed as such
for the MR description. It narrows the assertion to what the row's purpose needs (that
Core's own answer is distinguishable from the router's), and removes a version-dependent
premise the original probe never should have pinned. The change's router and gateway
behaviour is not touched.

### Finding 2 — the origin mismatch, corrected, and the local override

The 2026-11-16 entry listed rows 7 and 11 (`data-path 401 rewritten to the gateway's
challenge` and `apps data-path 401 rewritten to the apps challenge`) as **pass**. That was
**wrong**: with the router's committed `$mcp_origin` literal (`localhost`) disagreeing with
the profile's `GATEWAY_PUBLIC_ORIGIN` (`127.0.0.1`), those two rows answer on the wrong
origin and fail. **This entry corrects that table**: rows 7 and 11 were mis-labelled pass;
in a self-consistent origin (this run) they pass, and on the mismatched committed origin
they do not.

**Root cause of the profile's spelling.** The profile uses `127.0.0.1`, not `localhost`,
because on this Windows/WSL2 host `localhost` resolves to `::1`; the WSL2 NAT relay accepts
a connection on `::1` but never answers it, so a bare Windows client cannot reach the stack
by `localhost` at all. `127.0.0.1` works everywhere. The profile therefore stays
`127.0.0.1` (owner ruling), and the router's committed literal remains `localhost` (not
touched) — the two are reconciled only for this local run, by the override below.

**The local override (uncommitted, deliberately).** So the battery runs against a
self-consistent origin without editing any committed file:

- `router/nginx.local-override.conf` — a copy of `router/nginx.conf` with **exactly one line
  changed** (line 197):
  ```text
  -        set $mcp_origin "http://localhost:8090";
  +        set $mcp_origin "http://127.0.0.1:8090";
  ```
  (`git diff --no-index` confirms 1 insertion, 1 deletion, nothing else; byte-identical
  otherwise, CRLF preserved.)
- `docker-compose.override.yml` — untracked, at the worktree root: overrides only the
  `mcp-signin-router` service's `volumes` to mount `./router/nginx.local-override.conf` at
  `/etc/nginx/nginx.conf:ro` in place of the committed file.
- Both files are kept out of git via `.git/info/exclude` (the committed `.gitignore` is
  untouched). `git status --porcelain` in the worktree shows only `M scripts/probe_routing.py`.

**Deviation, named plainly for the MR description.** The battery below ran against a router
conf that **deviates from the committed `router/nginx.conf` in exactly the `$mcp_origin`
literal** (`127.0.0.1` instead of `localhost`). Every other byte of the router configuration
is identical to the committed file. The override is local-only and uncommitted; the
committed conf is unchanged.

Verified the running container mounts the override:

```text
$ docker exec <router-container> grep mcp_origin /etc/nginx/nginx.conf
        set $mcp_origin "http://127.0.0.1:8090";
```

Router recreated and healthy; `GET http://127.0.0.1:8090/healthz` → `200`.

### Three-way origin sanity (all quoting `http://127.0.0.1:8090`)

| Surface | Observed |
|---|---|
| AS metadata issuer (`/.well-known/oauth-authorization-server`) | `"issuer": "http://127.0.0.1:8090"` |
| OIDC alias (`/.well-known/openid-configuration`) | byte-identical to the canonical document; same issuer |
| Unauthenticated data-path challenge (`POST /dial/toolsets/x/mcp`) | `WWW-Authenticate: Bearer resource_metadata="http://127.0.0.1:8090/.well-known/oauth-protected-resource/dial/toolsets/x/mcp"` |

All three agree on `http://127.0.0.1:8090` — the self-consistency the mismatch denied.

### The battery (task 6.5b)

`python scripts/probe_routing.py --origin http://127.0.0.1:8090`, from the change worktree,
after the W0/W7 relaxation and under the override. It mints its own token; both query-string
rows read Core's request line from the instance Core container's log.

Key rows (tokens redacted; loopback literals only):

```text
[2/31] W0 negative control — Core's own answer on a discovery path
  request   GET /.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 401  type -  core-trace absent  nosniff absent
  (direct to Core, outside the router)
  record    Core's content-type: none
  record    X-Dial-Trace-Id: absent — a Core 0.49.0+ opt-in feature (responseTraceHeaders), informational only
  verdict   control red — Core's 401 is its own answer, distinct from the router's closure

[4/31] query string survives the routing
  request   POST http://127.0.0.1:8090/dial/notion/mcp?sessionId=<probe-id>
  token     <redacted len=1170 sha256=2007353e5cc2>
  core log  request.uri='/v1/toolset/notion/mcp?sessionId=probe-<id>'
  verdict   green — the parameter reached Core unchanged, on both methods

[7/31] data-path 401 rewritten to the gateway's challenge
  status    401
  challenges ['Bearer resource_metadata="http://127.0.0.1:8090/.well-known/oauth-protected-resource/dial/notion/mcp"']
  verdict   green — the 401 names the gateway's metadata, not Core's

[11/31] apps data-path 401 rewritten to the apps challenge
  status    401
  challenges ['Bearer resource_metadata="http://127.0.0.1:8090/.well-known/oauth-protected-resource/apps/skills-demo/mcp"']
  verdict   green — the apps 401 names the apps metadata, not the toolset's

[12/31] query string survives the apps routing
  verdict   green — the parameter reached Core unchanged, on both methods

[21/31] W7 Core's templates through the front door equal Core direct
  front door GET .../v1/toolset/notion/mcp            status 200  core-trace absent  nosniff absent
  Core direct GET .../v1/toolset/notion/mcp           status 200  core-trace absent  nosniff absent
  front door GET .../v1/deployments/skills-demo/mcp   status 200  core-trace absent  nosniff absent
  Core direct GET .../v1/deployments/skills-demo/mcp  status 200  core-trace absent  nosniff absent
  verdict   green — Core's templates through the front door equal Core direct
```

Final table:

```text
=== battery verdict ===
  pass      negative control — Core's own challenge
  pass      W0 negative control — Core's own answer on a discovery path
  pass      W0c negative control — the gateway's own 404
  pass      query string survives the routing
  pass      flat AS metadata through the router
  pass      per-toolset PRM through the router
  pass      data-path 401 rewritten to the gateway's challenge
  pass      gateway paths reachable through the front door
  pass      consent action route reachable through the front door
  pass      apps PRM through the router
  pass      apps data-path 401 rewritten to the apps challenge
  pass      query string survives the apps routing
  pass      status paths refused by the router's map (no gateway handler)
  pass      lockstep: the map and the guard hold their documented division
  pass      lockstep: the apps map/guard division
  pass      W1 openid-configuration serves the canonical document
  pass      W2 path-insertion aliases serve the canonical document
  pass      W4 unserved well-known paths are the router's 404
  pass      W5 closure is method-blind, no CORS
  pass      W6 precedence: AS, toolset, and app documents still served
  pass      W7 Core's templates through the front door equal Core direct
  pass      W8 off-template shapes under Core's prefix are closed
  pass      W10a normalization: into the alias location, the document
  pass      W10b normalization: out of the alias location, the closure
  pass      W10c normalization: into the Core location from outside its raw spelling, the closure
  pass      W10d normalization: out of the namespace into the catch-all, the closure
  pass      W10e normalization: decoded trailing line break, the closure
  pass      W10f normalization: into a gateway location, the gateway's answer (recorded)
  pass      W10g normalization: into a data-path location, the data path's refusal (recorded)
  pass      W12 served locations' end edges are closed
  pass      W13 path-appended forms are the data path's refusal

all 31 probes passed
```

**Verdict: 31/31 green, first attempt.** (A back-to-back re-run of the capture hit the
gateway's own per-source rate limit — rows 14, 15, and W6 returned `429` rather than the
data-path challenge — the known `GATEWAY_RATE_PER_SOURCE_PER_MINUTE` bound, not a routing
defect; the run above, after the rate window reset, is clean.)

### The structural fix — routed as a follow-up, not landed here

The local override is a diagnostic bridge, not a fix. The durable remedy is a **configurable
router origin**: `$mcp_origin` derived from an environment value (the same
`GATEWAY_PUBLIC_ORIGIN` the gateway uses) rather than a committed literal, so no deployment
can spell the router's published origin differently from the gateway's `iss`. This remains
**routed as a follow-up change** — the dev deployment's pod contract needs it too, not only
this host. This change does not touch the committed conf.