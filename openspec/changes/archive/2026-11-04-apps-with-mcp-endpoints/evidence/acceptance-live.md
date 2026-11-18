# Live-acceptance pass — task 7.3 (the app-resource acceptance, four legs + negatives)

The live-acceptance run for `apps-with-mcp-endpoints` (C1.5), run against the composed stack
(Core 8081, gateway front door 8090, Keycloak admin 8900, fixture `mcp-app-fixture` on the
instance network) on 2026-11-03/04. Every run below is a real drive against the live realm,
the live Core, and the live apps front door; nothing is simulated. Toolchain: Python 3.12.13
from the sibling checkout's `.venv/Scripts` on the Windows host, Docker in WSL2.

**No credential material appears in this file.** Access tokens, refresh tokens, authorization
codes and the client id are represented by redacted handles (`<redacted len=… sha256=…>`);
decoded claims are excerpted by name, never a whole token. The subject
(`3a0d60f4-fad0-4164-8903-20e5adf408c3`) and the app name `skills-demo` are non-credential
identifiers (the app name is in the request path) and are kept.

**Harness used — and the one deviation from the PoC's field method.** The PoC's evidence names
Claude Code as the real harness (task 7.3's wording: "the PoC's method … the harness — Claude
Code pointed at the front door as an MCP client"). This acceptance agent runs headless and
cannot drive a Claude Code session with a browser (the PoC's first-use rows were owner-driven
for exactly that reason). The run therefore uses the PoC's *scripted* harness — the same
machinery `scripts/probe_end_to_end.py` uses (the browser-free Keycloak login driver, the
loopback callback listener, the PKCE pair), re-pointed at the app resource URI. This is the
same driver the C1 live-acceptance pass used for its script-driven legs. The difference from
the PoC's field rows is the harness binary (scripted client vs. Claude Code), not the chain:
discovery → registration → authorization → flow → code exchange → live tool call all run
against the live composed stack. **The owner's own Claude Code first-use run remains owed if
the record wants a real-harness row for the app path** (see the summary).

## Environment and preconditions

- The composed stack was up and healthy at the start (`gateway /healthz` 200, router healthy,
  fixture healthy, Core healthy); it was restored to that state at the end.
- The app under acceptance: **the fixture `skills-demo`**, registered by
  `scripts/spike_register_app.py` into Core's platform bucket
  (`PUT /v1/applications/platform/skills-demo`), resolving at `GET /openai/applications/skills-demo`
  with its `mcp` block. See "Why the fixture, not the Skills demo app" below.
- Client: `group6-smoke` (pre-registered, `GATEWAY_E2E_CLIENT_ID`), redirect
  `http://127.0.0.1:8767/callback`.

### Why the fixture, not the Skills demo app

Task 7.3 step 1 directs: probe whether the owner's Skills MCP demo app is still live in Core
with its `mcp` block, and use it as a verified-real app if so; otherwise register the fixture.

The Skills demo **is** still live in Core, with an `mcp` block — but it is **bucket-scoped**:

```
GET /openai/applications                          -> 200 (list)
  ... "applications/public/skills-crud-demo" | Skills CRUD Demo | mcp: True
GET /v1/applications/public/skills-crud-demo      -> 200
  "mcp":{"endpoint":"http://skills-mcp-demo:5000/mcp", ...}
```

Its id carries a bucket prefix (`applications/public/skills-crud-demo`), and the gateway's app
flow reads the app at `GET /openai/applications/{name}` (design.md D2; `gateway/core.py`
`application_url`). Core answers that route **404 "Unknown deployment"** for a bucket-scoped id
short name and for the raw slash-bearing id alike:

```
GET /openai/applications/skills-crud-demo         -> 404 Unknown deployment: skills-crud-demo
GET /openai/applications/platform/skills-crud-demo -> 404 Unknown deployment: platform/skills-demo
```

The gateway serves **deployment-registry** apps only (design.md D1/D2: bucket-scoped ids never
pass the routed-path charset), so the Skills demo app cannot serve this acceptance. The fixture
`skills-demo` **is** a deployment-registry app (it resolves at `GET /openai/applications/skills-demo`
→ 200 with the `mcp` block), so it is the acceptance app. Registration is idempotent: the
re-run answered `412` (idempotent success), and the read-back carried the `mcp` block:

```
PUT /v1/applications/platform/skills-demo  -> 200 (first run)
PUT /v1/applications/platform/skills-demo  -> 412 (repeat: idempotent success)
GET /v1/applications/platform/skills-demo  -> 200
  mcp = {"endpoint": "http://mcp-app-fixture:9000/mcp", "transport": "HTTP", ...}
```

---

## Step 0 — the negative controls (run before any verdict)

### Control A — the fixture container down (precondition falsifier)

With the fixture stopped, the fixture's service name no longer resolves inside the instance
network, so nothing could answer an app MCP call:

```
$ wsl -e docker stop c15-apps-with-mcp-endpoints-mcp-app-fixture-1
$ wsl -e docker exec …-mcp-signin-gateway-1 python -c "urlopen('http://mcp-app-fixture:9000/mcp')"
URLError: <urlopen error [Errno -2] Name or service not known>
```

Then the full app run with the fixture still down: the **flow leg completes** (the app is
credential-free; Core never contacts the fixture during sign-in), but the **live tool call
fails**:

```
=== step 5: /dial/token ===  status 200   aud ["http://localhost:8090/apps/skills-demo/mcp","dial-mcp-proxy"]
=== app acceptance: live tool call through the apps front door ===
  POST /apps/skills-demo/mcp tools/list -> 502
  verdict   RED — the tool call did not succeed
```

After `docker start` the fixture returns to `healthy` and the same run is green again. The
control shows the tool-call leg genuinely measures the app data path (a 502 with the fixture
down, a 200 with it up), and that the *flow* leg is credential-free by construction.

### Control B — a phantom app name (the flow-read refusal)

The same scripted harness pointed at `phantom-app-xyz` (a guard-passing name Core does not
know). Discovery serves the document (registry-independent, the mirror property), the flow
runs, and the flow's app read refuses:

```
2026-11-03T22:41:35Z INFO gateway.audit {… "event":"flow_allocated", "flow_id":"KoIDufPAjJPF_srsG9NdBA",
  "resource":"http://localhost:8090/apps/phantom-app-xyz/mcp", "resource_kind":"app"}
2026-11-03T22:41:38Z INFO gateway.audit {… "event":"flow_branch_refused", "flow_id":"KoIDufPAjJPF_srsG9NdBA",
  "reason":"unknown_app", "resource":"http://localhost:8090/apps/phantom-app-xyz/mcp",
  "subject":"3a0d60f4-fad0-4164-8903-20e5adf408c3"}
```

The refusal is `unknown_app`, audited, at the flow's authenticated app read — the phantom's
existence is decided post-authentication, not on the discovery surface. (The "no flow state
surviving" claim this scenario also carries is **falsified** — see Finding 1.)

---

## Leg (a) — first use end to end on the app resource

Command:

```
PYTHONUTF8=1 python <probe_app_end_to_end.py> scripts --app skills-demo
```

(the probe is the PoC harness re-pointed at `/apps/<app>/mcp`; kept outside the repo)

Observed:

```
=== app acceptance: discovery ===
  GET apps PRM -> 200
  resource  http://localhost:8090/apps/skills-demo/mcp
  servers   ['http://localhost:8090']
  scopes    []
  verdict   green — discovery document names the app resource
=== app acceptance: registration (pre-registered client) ===
  client_id <redacted len=12 sha256=67b262e0f7c2>
=== step 2: /dial/authorize through the front door (resource = app URI) ===
  status    302 -> keycloak:8443
  client    dial-mcp-proxy
  scope     profile email
=== step 3: the identity provider's login form ===
  credentials submitted -> HTTP 302
  hop 2: HTTP 302
  hop 3: reached the client redirect URI
=== step 4: the gateway's callback ===
  params    ['code', 'iss', 'state']
  state     round-tripped
  code      <redacted len=1220 sha256=6360d06ddea5>
=== step 5: /dial/token ===
  status    200
  access    <redacted len=984 sha256=6360d06ddea5>
    iss      "http://localhost:8090"
    sub      "3a0d60f4-fad0-4164-8903-20e5adf408c3"
    aud      ["http://localhost:8090/apps/skills-demo/mcp", "dial-mcp-proxy"]
    roles    ["admin"]
    project  "proj-alpha"
  refresh   present
=== app acceptance: live tool call through the apps front door ===
  POST /apps/skills-demo/mcp tools/list -> 200
  tools     1
  first     ["echo"]
  verdict   green — the tool call succeeded through the apps front door
```

Capture summary: discovery document served; registration resolved (pre-registered client);
authorization request carried `resource = http://localhost:8090/apps/skills-demo/mcp`; the
flow completed; the code exchanged for a gateway-signed token whose `iss` is the gateway's
public origin, whose `aud` names the **app resource URI** and the marker, and which carries
the user's `sub`; a live `tools/list` through the apps front door returned the fixture's tool.

**Verdict — (a): GREEN.**

---

## Leg (b) — the credential-free claim, positively and negatively

### The gateway's audit trail (the positive half)

The run's complete trail (one flow, `j1TZhc4mJV4ErvjjBj5tLQ`):

```
2026-11-03T23:16:28Z INFO gateway.audit {… "event":"flow_allocated", "flow_id":"j1TZhc4mJV4ErvjjBj5tLQ",
  "resource":"http://localhost:8090/apps/skills-demo/mcp", "resource_kind":"app"}
2026-11-03T23:16:28Z INFO gateway.audit {… "event":"credential_free_short_circuit", "flow_id":"j1TZhc4mJV4ErvjjBj5tLQ",
  "resource":"http://localhost:8090/apps/skills-demo/mcp", "resource_kind":"app",
  "subject":"3a0d60f4-fad0-4164-8903-20e5adf408c3"}
2026-11-03T23:16:28Z INFO gateway.audit {… "event":"code_issued", "flow_id":"j1TZhc4mJV4ErvjjBj5tLQ",
  "resource":"http://localhost:8090/apps/skills-demo/mcp", "subject":"3a0d60f4-…"}
2026-11-03T23:16:29Z INFO gateway.audit {… "event":"token_issued",
  "resource":"http://localhost:8090/apps/skills-demo/mcp", "subject":"3a0d60f4-…"}
```

The `credential_free_short_circuit` record is present, carrying `resource_kind":"app"` — the
kind-driven short-circuit, exactly as the delta spec's scenario asks.

### The negative half — the events that MUST be absent

- **No `upstream_callback`.** The full-window event tally
  (`flow_allocated`, `credential_free_short_circuit`, `code_issued`, `token_issued`) contains
  no `upstream_callback` and no `signin_result` — the flow never built or ran an upstream leg.
- **No consent-screen event.** No interstitial page is rendered on this path (`_finish` is
  reached directly from the app branch); the harness saw no interstitial (the login chain went
  straight from the Keycloak form to the client callback).
- **No credential-call event, and Core sees none.** Core's log for the window carries **no**
  `/v1/ops/toolset/signin` and no `/v1/applications/{id}/external-services/…/consent`:

```
$ wsl -e docker logs --since 10m dial-instance-core-1 | grep -E "signin|signout|external-services"
(no output)
```

  The only Core records for the run are the data-path calls:
  `"request.uri":"/v1/deployments/skills-demo/mcp"` with
  `"Body":"Connected to origin: mcp-app-fixture:9000"` → `status=200` — Core proxying the app
  MCP call to the fixture on the caller's own identity. **No upstream round-trip of any kind**
  ran during sign-in.

**Verdict — (b): GREEN.** The flow completed with no consent screen and no credential call;
the trail shows the kind-driven short-circuit (`resource_kind":"app"`); no consent-leg event
and no credential-call event exist for the flow.

---

## Leg (c) — query strings survive the apps front routing

`scripts/probe_routing.py --app skills-demo`, probe 9 (green), plus a direct capture from
Core's own log:

```
$ PYTHONUTF8=1 python scripts/probe_routing.py --app skills-demo
[9/10] query string survives the apps routing
  request   POST http://localhost:8090/apps/skills-demo/mcp?sessionId=<probe-id>
  status    200
  request   GET http://localhost:8090/apps/skills-demo/mcp?sessionId=<probe-id>-get
  status    200
  verdict   green — the parameter reached Core unchanged, on both methods
```

Direct Core-log capture (host-driven, marker `c15-app-…`):

```
POST http://localhost:8090/apps/skills-demo/mcp?sessionId=c15-app-4b9b5a2cac -> 200
GET  http://localhost:8090/apps/skills-demo/mcp?sessionId=c15-app-4b9b5a2cac-get -> 200
core request.uri = /v1/deployments/skills-demo/mcp?sessionId=c15-app-4b9b5a2cac
core request.uri = /v1/deployments/skills-demo/mcp?sessionId=c15-app-4b9b5a2cac-get
```

Core's own recorded URI carries the parameter **unchanged on both methods** — the router's
apps location (`$is_args$args`) preserved the streamable session parameter across the front
door. The fixture also echoes `?sessionId=` itself (`{"sessionId":"probe-123"}`), corroborating
the parameter's end-to-end survival.

**Verdict — (c): GREEN.**

---

## Leg (d) — the toolset flow is unchanged

The PoC's own end-to-end script against the `notion` toolset (through `/dial/notion/mcp`):

```
$ PYTHONUTF8=1 python scripts/probe_end_to_end.py --toolset notion
=== step 1: discovery through the front door ===  resource http://localhost:8090/dial/notion/mcp
=== step 2: /dial/authorize …  status 302 -> keycloak:8443   scope profile email
=== step 3: the identity provider's login form ===  credentials submitted -> HTTP 302
=== step 4: the gateway's callback ===  params ['code','iss','state']   state round-tripped
=== step 5: /dial/token ===  status 200
    aud ["http://localhost:8090/dial/notion/mcp", "dial-mcp-proxy"]   roles ["admin"]   project "proj-alpha"
=== step 6: a live tool call through the front door (/dial/notion/mcp) ===
  status 200   tools 73
```

Its trail (one flow, `zmS8pHQw5bLzBWdAJ4oFIQ`) is the normal toolset shape:

```
… "event":"flow_allocated", "resource":"http://localhost:8090/dial/notion/mcp", "resource_kind":"toolset"
… "event":"code_issued",     "resource":"http://localhost:8090/dial/notion/mcp"
… "event":"token_issued",    "resource":"http://localhost:8090/dial/notion/mcp"
```

The toolset sign-in completes exactly as before (short-circuit on the stored notion credential:
`flow_allocated → code_issued → token_issued`, no consent leg), the issued token's `aud` names
the **toolset** resource URI, and 73 live tools resolve. The `resource_kind` is `"toolset"`,
distinct from the app flow's `"app"`.

**Verdict — (d): GREEN.**

---

## Negative legs from the delta's scenarios

| Scenario | Command | Observed | Verdict |
|---|---|---|---|
| Phantom app name — discovery serves a document (registry-independent) | `GET /.well-known/oauth-protected-resource/apps/phantom-app-xyz/mcp` | 200, `{"resource":"…/apps/phantom-app-xyz/mcp", …}` | GREEN (mirror property holds) |
| Phantom app name — flow refuses at the app read | scripted harness on `phantom-app-xyz` | flow fails at the app read; `flow_branch_refused` `reason":"unknown_app"` audited; **record survived** (Finding 1) | refusal GREEN; survivorship **RED** |
| Bad-charset app name refused at discovery | `GET /.well-known/oauth-protected-resource/apps/Bad_Name/mcp` | 404 `{"detail":"unknown app"}`; audit `flow_refused` `"reason":"invalid_app_name"`, `"toolset":"Bad_Name"` | GREEN |
| Unauthenticated apps MCP call → apps challenge | `GET /apps/skills-demo/mcp` | 401, `WWW-Authenticate: Bearer resource_metadata="http://localhost:8090/.well-known/oauth-protected-resource/apps/skills-demo/mcp"` (exactly one; Core's challenge absent) | GREEN |
| Toolset challenge contrast | `GET /dial/notion/mcp` | 401, `resource_metadata="…/oauth-protected-resource/dial/notion/mcp"` (the toolset's, unchanged) | GREEN |
| Fixture down → tool call fails | see Control A | 502 | GREEN (control) |
| User without the app's access → 403 page | **NOT TESTABLE** | — | see below |

### The 403 leg — not testable with the local credentials (recorded, not skipped silently)

The "App authorization denied" scenario needs an authenticated user **without** read access to
the app. The fixture app `skills-demo` is owned by `organization-owner` and carries **no access
restriction** (the `GET /openai/applications/skills-demo` projection carries `owner` and no
`access`/`deployment_id` rule), so every realm user can read it. `.env` carries exactly one
test-user credential pair (`TEST_USER_NAME`/`TEST_USER_PASSWORD`); there is no second credential
whose user the app excludes, and provisioning one (a second Keycloak user + a Core per-app deny
rule) is outside this acceptance's scope and would change realm/Core state. The 403 leg is
therefore **recorded as not run, with the reason**, per the task's "run what the local
credentials permit, record what you could not test and why". The adjacent refusals (404
`unknown_app`, 200 served) were both exercised live, and unit tests cover the 403 rendering
(`tests/test_federation.py`).

### The status-path probe's known answer

`probe_routing.py` probe 10 (`GET /dial/<name>/status`) reports FAIL — the request reaches Core,
which answers **401** (its auth filter runs before routing), not the design's predicted 404.
This is the **already-recorded** 7.2 note (`evidence/gates-implementation.md` §"the status-path
probe's expected answer"): the removal is correct (the router's status location is gone and
`gateway/status.py` deleted), and the design's one-word "404" is imprecise for an unauthenticated
probe. Not a finding of this acceptance; re-noted here only because the battery prints it.

---

## Finding 1 (falsification) — the flow record SURVIVES the existence refusal

**Claim under test.** The delta spec's app-resource requirement states, for the 404 refusal at
the app read: *"no flow state surviving the refusal"* (scenario "Unknown app refused at the
flow's app read", and the same words in the modified "Unknown toolset refused at the flow's
settings read" scenario).

**Method.** Drive the app flow to the Keycloak callback with `phantom-app-xyz` (the refusal
fires at the app read), then re-present the **same flow id** (`state`) to
`/dial/callback/keycloak`. The flow-record lookup (`_live_flow`) runs **before** the code
exchange, so the two outcomes are distinguishable:

- record destroyed → the "expired" page
  (*"expired or the sign-in was started again"*);
- record surviving → the leg proceeds to the code exchange and fails **there**.

The "expired" page was captured independently with an unknown flow id (distinct text).

**Observed.**

```
flow id (IdP state) = 5VK9vDP_xvhWVXdE-aKvfw
=== the refusal page (first presentation) ===
  body   "red in DIAL Core</p>\n<p>Go back to your tool and start the sign-in again…"
=== callback re-presentation (same flow id; survivorship test) ===
  status 400
  body   "efused the code exchange (400); the sign-in has to be started again…"
  verdict: flow record SURVIVED the refusal
```

The re-presented callback **resolved the record** and re-ran the leg — it reached the code
exchange and its `400 "the provider refused the code exchange"` — rather than the "expired"
page a destroyed record yields. `_core_read_refusal` (`gateway/federation.py`) issues the
`unknown_app` audit record and the refusal page but **does not** call `runtime.flows.destroy`
(the only `destroy` site is the upstream callback, line 241). So the flow record — which by
then still holds the user's identity access token (the app read discards it only *after* it
succeeds; `complete_identity_leg` drops it on the success path, not on the refusal) — survives
the refusal until its TTL.

**Consequence.** The claim "no flow state surviving the refusal" is **falsified by the live
run**. This touches both the app-resource scenario and the (re-worded) unknown-toolset scenario.
The refusal's *authorization* effect is intact (no token is minted, no upstream leg starts),
but the record — and the identity token it still holds — outlives the refusal, contradicting
the stated design. Per the process rule, this is recorded as a finding for the defect cycle,
**not patched around** (this agent fixes no code).

**Severity note.** The surviving record is TTL-bounded and keyed by an unguessable id, and the
refusal page is still rendered; the exposure is the retention of a credential the design says
is gone, not a bypass of the refusal itself. Scoping the fix (destroy on the refusal path vs.
correct the spec wording) is the design owner's call — flagged, not decided here.

### Finding 1 — resolution (defect-fix pass, 2026-11-04)

**Spec gate: NO spec change.** The delta spec already demands the behavior ("no flow state
surviving the refusal" / "no flow state survives the refusal"); the code was wrong and is
fixed to match. No normative text changed.

**Root cause, verified in source.** `gateway/federation.py`'s `_core_read_refusal` wrote the
audit record and rendered the refusal page but never consumed the flow record —
`runtime.flows.destroy` was called only at the upstream callback (the success path). The
read's credential drop (`discard_identity_token()`, inside `complete_identity_leg`) runs only
after the read succeeds, so a refused read left the record holding the identity access token
*and* the captured provider refresh token, bounded only by the flow TTL.

**Fix.** `gateway/federation.py` gained `_consume_refused_flow(runtime, record)` — it
destroys the flow record and drops the identity access token and the provider refresh token —
and every refusal branch of `_core_read_refusal` now calls it before rendering its page: both
existence refusals (`unknown_app`, `unknown_toolset`) and the no-access refusal (403
`AccessDeniedError`). The fault branch (unreachable/unreadable Core) does not consume state —
that is a fault the user re-runs, not a refusal, and the three-shape discipline is preserved.
The audit ordering is unchanged: the refusal record still lands before the state is torn down.

**Sibling path fixed under the same rule.** The no-access (403) refusal had the same hole; it
is fixed under the custody discipline (a refusal must not extend the identity token's
retention past the flow TTL), not because its spec text states a survivorship clause — it
does not.

**Test-first record.** Four unit tests added to `tests/test_federation.py` (the app pair and
the toolset pair). Each drives the refusal and asserts the store no longer resolves the id,
the record holds no identity credential, re-presenting the id yields the expired page **and
the provider code exchange does not run a second time** (a counted mock — the live symptom),
and the refusal's audit record still landed once. Failing against the unpatched code
(`4 failed`), passing after the fix (`4 passed`) — see
`evidence/review-1-findings-and-dispositions.md` Round 11.

**Gate re-runs.** `pytest -q` 546 passed / 1 skipped (pre-existing skip); `ruff check`
clean; LF-normalized `ruff format --check` clean on both changed files; `mypy` clean.
No commit this pass.

**Effect on the finding.** The falsification is closed in code: a re-presented flow id after
either existence refusal — and after either no-access refusal — now lands on the expired page
an unknown id gets, the record is gone, and no identity credential remains retrievable.

---

## Summary

| Leg | Verdict | Key evidence |
|---|---|---|
| **0** negative control — fixture down | GREEN | name unresolvable; tool call 502 with fixture down, 200 restored |
| **0** negative control — phantom app | GREEN (refusal) / RED (survivorship) | `unknown_app` audited at the app read; record survived → Finding 1 |
| **(a)** first use end to end | **GREEN** | discovery → authorize(`resource`=app URI) → flow → code exchange → live `tools/list` 200 (1 tool); `aud` = app resource URI + marker, `sub` = user |
| **(b)** credential-free | **GREEN** | `credential_free_short_circuit` (`resource_kind":"app")` present; no `upstream_callback`/`signin_result`; no consent; Core log shows no `/v1/ops/toolset/signin` |
| **(c)** query strings | **GREEN** | Core `request.uri = /v1/deployments/skills-demo/mcp?sessionId=…` on POST and GET |
| **(d)** toolset unchanged | **GREEN** | `probe_end_to_end.py --toolset notion`: 73 tools; trail `flow_allocated → code_issued → token_issued`, `resource_kind":"toolset"` |
| negatives — phantom / charset / challenge / fixture | GREEN (each) | see table above |
| negative — 403 no-access | NOT RUN | no second credential / no app access rule; reason recorded |
| **Finding 1** | **FALSIFICATION** | flow record survives the existence refusal, contra the delta spec's "no flow state surviving" |

**Is 7.3 green for the review gates?** The four conformance legs (a)–(d) are **all green** on
the live composed stack, as are every testable negative leg. **The run is not unconditionally
green**: Finding 1 falsifies a normative clause of the delta spec's refusal scenarios, so
7.3 is **green for (a)–(d) with one open falsification** — the delta spec's "no flow state
surviving the refusal" clause and its code path need the defect cycle before 7.4's review
gates can treat 7.3 as fully closed. No code was changed and nothing was committed by this
pass. **Owed separately:** an owner-driven Claude Code first-use run, if the record wants a
real-harness row rather than the scripted-harness row captured above.

---

## Real-harness first-use (owner, 2026-11-04)

The real-harness row the live-acceptance report flagged as owed is now **closed**. This is the
PoC's field method and task 7.3's named harness — the owner's own Claude Code, an MCP client
pointing at the gateway's apps front door — not the scripted driver the earlier legs used.

**Run.** The owner registered the MCP client at the app resource URI

```
http://localhost:8090/apps/skills-demo/mcp
```

and drove the first use end to end: the sign-in flow completed with successful authentication
and the client received its credentials, carrying a **gateway-minted token**. On reconnecting,
the app's tools listed — a live tool surface reached through the apps path, exercised by a
real MCP client rather than the acceptance harness. The gateway's part of the run was green
throughout: the flow completed, the token carried the user's identity (`user.project` and
`user.id` both resolved), and the authenticated request reached Core's MCP proxy.

### The 502 on the post-auth reconnect — diagnosis and resolution

One incident occurred during the run, fully diagnosed from Core's own logs. The post-auth
reconnect answered **502**: Core's `McpProxyController` could not resolve the app's upstream:

```
POST /v1/deployments/skills-demo/mcp
  Can't connect to origin: Failed to resolve 'mcp-app-fixture'
```

The cause is environmental, not in the gateway's path: the fixture container was **stopped** —
it had been left stopped by the Round-12 profile-gate verification (the checklist that runs the
plain `docker compose up -d` profile, which by design excludes the `acceptance`-profile
fixture). With the fixture down, its service name no longer resolves inside the instance
network, so Core's proxy had no origin to reach — the same failure the negative Control A
above measures deliberately.

Starting the fixture resolved it, and the reconnect then listed the app's tools:

```
$ wsl -e docker compose --profile acceptance up -d mcp-app-fixture
```

This closes the real-harness row: the app resource signs in through the apps front door on the
PoC's named harness, and a live tool surface resolves through the apps path with a
gateway-minted token. The 502 was the fixture's absence, not the gateway's behavior.