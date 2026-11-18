# Group 5 — front routing (Stage 3)

Tasks 5.1–5.3 of `build-mcp-sign-in-gateway-poc`. Records what was built, what was run to
verify it, the two defects the live battery found, and one behavior gap the group
recorded rather than improvised around. Every capture below is redacted at capture time:
no token, code, key, password, or client secret appears in this file.

## Verdict

**Group 5 complete, with one recorded gap.** The full front-router config replaces the
group-2 skeleton, the authorization surface and the MCP data path both route correctly
through the composed stack, query strings survive intact, every 401 on the data path
carries the gateway's challenge and nothing of the upstream's, and the gateway's
authorize/token paths are reachable through the front door. The `route_only` gap below is
a spec-versus-implementation divergence recorded for the authoring pass, not a defect this
group patched around.

## What each task landed

| Task | Deliverable | Where |
|---|---|---|
| 5.1 | The full front-router nginx config: five authorization-surface locations to the gateway, the anchored data-path regex to Core with `$is_args$args`, the 401 challenge, and the catch-all to Core | `router/nginx.conf` |
| 5.2 | The scripted routing probe battery — six probes, negative control first, minting its own token rather than reading a stale one | `scripts/probe_routing.py` |
| 5.3 | The routing reference: the location map, the reserved names, the `$mcp_origin` rule, why `error_page 401` is *not* the mechanism, and the probe battery | `docs/routing.md` |

Two prose corrections folded into this pass at the authoring pass's request (outside its
own scope):

- `docs/gateway-configuration.md`, "The two Core routes the flow reads, and why both" —
  reframed to the content-decided behavior the code already had: the flow keeps the
  statuses the settings answer carries and asks `GET /openai/toolsets/{name}` only when
  that answer omits them, decided by content and never by an error.
- `gateway/core.py` module docstring — aligned with the same behavior, which its
  `read_toolset_for_flow` docstring already stated.

## The routing map as configured

Order is the config's own order, because nginx evaluates regex locations in it.

| Location | Target |
|---|---|
| `= /healthz` | gateway |
| `= /.well-known/oauth-authorization-server` | gateway |
| `~ ^/\.well-known/oauth-protected-resource/dial/` | gateway |
| `~ ^/dial/(callback\|jwks\.json\|authorize\|token\|register\|revoke)(/\|$)` | gateway |
| `~ ^/dial/[a-z0-9-]+/status$` | gateway |
| `~ ^/dial/(?<tname>[a-z0-9-]+)/mcp$` | Core: `http://core:8080/v1/toolset/$tname/mcp$is_args$args`, `proxy_buffering off`, `proxy_request_buffering off`, `proxy_hide_header WWW-Authenticate`, `add_header WWW-Authenticate $mcp_challenge always` |
| `/` | Core, unchanged |

`nginx -t` inside the composed router:

```
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
nginx: configuration file /etc/nginx/nginx.conf test is successful
```

`nginx -t` needs the upstream hostnames resolvable, so it is run in the composed router
rather than in a throwaway container: outside the compose network it fails with
`host not found in upstream "core:8080"`, which is the check working rather than a config
defect.

## Defects found by the live battery, and fixed

### D-9 — Core's challenge survived the rewrite, so the response carried two challenges

- **Symptom:** a 401 on `/dial/notion/mcp` through the router carried **both** Core's
  `WWW-Authenticate` (naming `localhost:8081/.well-known/oauth-protected-resource/...`)
  and the gateway's. A harness that read the first, or read headers as a list, would
  follow the challenge no harness can complete — the exact failure the rewrite exists to
  remove.
- **Evidence:** `curl -D-` through the composed router before the fix:
  `WWW-Authenticate: Bearer resource_metadata="http://localhost:8081/.../v1/toolset/notion/mcp"`
  followed by a second `WWW-Authenticate: Bearer resource_metadata="http://localhost:8090/.../dial/notion/mcp"`.
  The battery's probe 5 read only the first, so it *also* had to be corrected: reading one
  of two header values is how this passed silently in the first run.
- **Root cause:** `proxy_intercept_errors on` + `error_page 401 = @mcp_challenge` does not
  replace the upstream response's headers — measured on `nginx:1.27-alpine`, an
  intercepted 401 re-serves Core's headers into the synthesized response, and
  `proxy_hide_header` in the proxying location has no effect on that path (the hide runs
  where the upstream response was produced, and the error_page re-creation does not
  consult it). Four further configurations were measured and all leak Core's challenge:
  hide inside the named location, an `add_header` in the named location, `error_page`
  without `=`, and an `http`-level `proxy_hide_header`.
- **Fix:** the challenge is synthesized by the data-path location itself, from a
  status-conditioned `map`, with the upstream header hidden by `proxy_hide_header`. Both
  halves are required: the hide removes Core's, the `map`-driven `add_header` adds the
  gateway's on a 401 and adds nothing on any other status.
  `router/nginx.conf`, `scripts/probe_routing.py` (which now asserts the *count* as well
  as the content). Pinned by the battery's probe 5, which fails on any second challenge.

The mechanism chosen is a deliberate departure from the sketch in
`docs/background/design.md` §4.4 (`error_page 401 = @mcp_challenge`). The sketch's shape
cannot satisfy its own stated property — "converts every 401 ... into the proxy's own
challenge" — and the property is what the spec requires.

### D-10 — The query-string probe read a stale token and reported a routing failure

- **Symptom:** the first battery run failed probe 2 with "Core's log carried no request
  line containing `<marker>`", while the routing was in fact correct.
- **Evidence:** the same probe with a freshly minted token passed immediately; the token
  file the probe had read (`.secrets/spike-token-default.jwt`) carried
  `exp=1792327562` against a clock at `1792358580` — expired by about nine hours.
- **Root cause:** two compounding ones. The probe read a *file*, and minted tokens live ten
  minutes, so a token file is stale almost whenever a later session reads it. And an
  unauthenticated or expired-token call is refused by Core **before** the point where Core
  logs the request URI, so its log carries nothing — meaning the negative signal the probe
  keyed on was produced by an authentication failure, not by a routing failure. A battery
  that cannot tell those apart reports the wrong one.
- **Fix:** the probe mints its own token, reusing `spike_mint_jwt`'s claim-copy and the
  key whose JWKS Core's provider entry already points at, so the measured request is one
  Core actually served. A mint failure is reported as a setup failure and stops the
  battery rather than reading as a routing result. `scripts/probe_routing.py`.

## The battery, as run

Composed stack up (`mcp-signin-gateway` and `mcp-signin-router`, both healthy,
`nginx -t` green), `PYTHONUTF8=1 python scripts/probe_routing.py`:

```
=== battery verdict ===
  pass      negative control — Core's own challenge
  pass      query string survives the routing
  pass      flat AS metadata through the router
  pass      per-toolset PRM through the router
  pass      data-path 401 rewritten to the gateway's challenge
  pass      gateway paths reachable through the front door

all 6 probes passed
```

### Probe 1 — negative control (runs first)

```
request   GET http://localhost:8081/v1/toolset/notion/mcp  (direct to Core, outside the router)
status    401
challenge 'Bearer resource_metadata="http://localhost:8081/.well-known/oauth-protected-resource/v1/toolset/notion/mcp"'
verdict   control red — Core's own challenge names its own metadata
```

The control is what makes probe 5's green mean something: it shows the unrewritten
challenge a client would otherwise receive, on a host the router does not publish — so a
probe 5 pass cannot be Core's own answer.

### Probe 2 — query-string survival (criterion (d)'s precursor)

```
request   POST http://localhost:8090/dial/notion/mcp?sessionId=<probe-id>
token     <redacted len=1170 sha256=6f48bf9c561b>
status    200
request   GET http://localhost:8090/dial/notion/mcp?sessionId=<probe-id>-get
status    405
core log  request.uri='/v1/toolset/notion/mcp?sessionId=probe-c9fa944cd07e'
core log  request.uri='/v1/toolset/notion/mcp?sessionId=probe-c9fa944cd07e-get'
(2 + 4 identical lines elided)
verdict   green — the parameter reached Core unchanged, on both methods
```

Core logs the same request on several lines (proxy-context, handler entry, response), so
the probe reports each and asserts that at least one carries the `request.uri` with the
marker.

The evidence is Core's own log line for the request — `request.uri` includes the query
string — because a proxy that dropped the parameter would still return the response Core
produced without it, so the loss is visible only in what Core recorded receiving. Both
methods are exercised because streamable-HTTP sessions resume with a GET while the
JSON-RPC call is a POST, and a routing that survived one could lose the other. The GET's
`405` is Core's own answer to a GET on that path with a valid token: the request reached
Core and Core refused the method, which is the routing working.

### Probe 3/4 — discovery through the front door

```
GET http://localhost:8090/.well-known/oauth-authorization-server  → 200
  issuer http://localhost:8090
  authorization_endpoint http://localhost:8090/dial/authorize
  token_endpoint         http://localhost:8090/dial/token
  jwks_uri               http://localhost:8090/dial/jwks.json

GET http://localhost:8090/.well-known/oauth-protected-resource/dial/notion/mcp  → 200
  resource http://localhost:8090/dial/notion/mcp
  servers  ['http://localhost:8090']
  kind     OAUTH
```

### Probe 5 — the 401 rewrite

```
request   GET http://localhost:8090/dial/notion/mcp  (no Authorization header)
status    401
challenges ['Bearer resource_metadata="http://localhost:8090/.well-known/oauth-protected-resource/dial/notion/mcp"']
verdict   green — the 401 names the gateway's metadata, not Core's
```

Exactly one challenge, naming the gateway's metadata. Also probed live, outside the
battery:

- **An invalid token** on the data path → `401` with the same single gateway challenge
  (Core's own answer for a bad token, rewritten).
- **A valid gateway token** for the `notion` toolset, currently `SIGNED_IN` → `200`
  through the front door, so the rewrite is on the 401 path only and does not touch a
  served response.
- **A valid token, unknown toolset** (`/dial/ghost/mcp`) → Core's own `404`, passed through
  unchanged: the rewrite is scoped to 401, not to every error.

### Probe 6 — the gateway's own paths

```
GET  http://localhost:8090/dial/authorize  → 400 error 'invalid_request'
POST http://localhost:8090/dial/token      → 400 error 'invalid_request'
```

Both are asked with unusable parameters on purpose: what is asserted is *whose* answer
comes back. Core serves nothing at those paths and answers 404, so a gateway-shaped OAuth
error document is the evidence the location reached the gateway.

## Composition checks

| Check | Result |
|---|---|
| `wsl -e docker compose config` | parses |
| `docker compose up -d --build` | gateway built, both services started |
| `mcp-signin-gateway` health | `healthy` |
| `mcp-signin-router` health | `healthy` |
| `GET /healthz` through the router (port 8090) | `200` |
| A plain Core path through the router (`/v1/user/info`) | Core's own `401` — the catch-all reaches Core |

## The recorded gap: `route_only` entries still get the challenge

The spec's mapping-safety requirement says a `route_only` toolset's paths are served
"through the front door **without** the challenge rewrite". The rewrite as configured is
unconditional, so a `route_only` entry's MCP path still answers the gateway's challenge.

Measured directly: with `TOOLSETS={"notion":{"authentication_type":"API_KEY","route_only":true}}`
and the gateway recreated, an unauthenticated `GET /dial/notion/mcp` answered
`401` with the gateway's challenge — the rewrite ran. The mapping was restored to the
OAuth entry immediately afterwards.

**Why this is recorded and not fixed here.** The gateway knows which entries are
route-only (`Settings.is_route_only`), but the router is static nginx config with no view
of that mapping, so closing the gap means one of: a per-toolset location list generated
from the mapping, a runtime route table the router reads, or moving the challenge
synthesis into the gateway. Each is a design decision about where the mapping is written
down — and the design decides that question in D6 (the startup guard and the routing
"stay in step"), while the delta spec states *both* the reserved-name mechanism and the
route-only behavior. The spec's own reserved-name list omitted `status`, `signin`,
`signout` for the same reason the alternation is generous: a toolset so named could never
route. `route_only` inherits no such guard. The choice belongs to the authoring pass as a
spec-vs-implementation reconciliation, not to this group as an improvised config branch.

It is recorded in `docs/routing.md` too, so an operator reading the routing reference
learns the limitation where they would look for it.

## Gates

Run from `.venv/Scripts` with `PYTHONUTF8=1`.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 85 files already formatted |
| `mypy` (strict) | Success: no issues found in 35 source files |
| `pytest -q` | 320 passed, 1 skipped |
| `bandit -c pyproject.toml -r gateway` | No issues identified |
| `pip-audit` | No known vulnerabilities found |
| `wsl -e docker compose config` | parses |
| `nginx -t` (composed router) | syntax ok, test successful |
| Routing probe battery | all 6 probes passed |

The skipped test is the same Windows one groups 3 and 4 recorded: POSIX permission bits
are not implemented there, so the DCR store's owner-only mode is asserted in the Linux
container where it is enforced.

Trivy on the built image reports 44 HIGH findings, all in the Debian base image's own
packages (`util-linux`/`bsdutils`, `ncurses`, `systemd`, `perl-base`, `libacl1`), every
one with **no fixed version available** — so the remedy the repo's rule names (a
dependency bump) does not exist yet for any of them. They are pre-existing base-image
findings, none introduced by this group's change, which touches only nginx config, a
probe script, and docs. Triage is group 7's task; recorded here because the newest
`util-linux` and `ncurses` advisories postdate the group-4 image build.

## Deliberate limits of this group

- **The live end-to-end sign-in through the front door is not run.** The gateway's
  Keycloak client does not exist until group 6 provisions it, so the browser leg cannot
  complete against the real realm. The routing is proven on the paths that do not need it.
- **The `spike-jwks` container still serves Core's JWKS.** The battery mints its token
  against that key, which is why the query-string probe's call authenticates at all; group
  6 repoints the provider entry at the gateway's own `/dial/jwks.json`.
- **One owned probe script, no unit test.** The routing is nginx configuration and its
  correctness is a property of the composed stack — a unit test could only assert the
  config's text, which is the thing that was already wrong. The battery is the test.

## Resolutions (authoring pass, 2026-10-19)

### D-9 — the challenge mechanism, reconciled

The shipped mechanism (`proxy_hide_header WWW-Authenticate` + a status-conditioned
`map`-driven `add_header` in the data-path location) is now the designed mechanism, not
a deviation: the change's `design.md` D7 describes it with the measured reason (an
intercepted 401 re-serves the upstream response's headers on this image; five
configurations measured, all leak), and owner ruling 2 names the same form. **No spec
ripple:** the delta spec's challenge requirement pins the property only — 401 answered
with the gateway's own challenge, the upstream's never visible, query strings surviving
— and names no mechanism, so the map+hide form satisfies it unchanged.

### The `route_only` gap — resolved by dropping the escape

The v1 answer is (a): `route_only` is removed from the mapping; a non-OAuth entry
refuses startup unconditionally. The static router cannot know the mapping, and the
only mechanisms that could keep the route-only promise are generated per-toolset
locations (every mapping change becomes a router regeneration and reload) or moving
challenge synthesis into the gateway (putting the gateway on the MCP data path it is
deliberately absent from). No v1 consumer exists for the escape, non-OAuth toolsets
stay reachable through Core's own paths via the catch-all location, and a front-door
spelling for non-OAuth kinds is recorded with the API-key wrapper work (design.md open
question 3), which brings its own routing mechanism. Aligned artifacts: the delta
spec's mapping-safety requirement (escape clause and Route-only scenario removed),
`design.md` (D6, MA-3, open question 3), `tasks.md` (3.1 letter; new 3.10 removes the
field, `Settings.is_route_only`, the validator escape branch, and aligns the tests,
`.env.example`, and `README.md`), `docs/routing.md`, and `docs/gateway-configuration.md`.
The change stays shippable on the current build: the live mapping is OAUTH-only, so the
unconditional refusal changes no deployed behavior; 3.10 lands before the change's
gates.