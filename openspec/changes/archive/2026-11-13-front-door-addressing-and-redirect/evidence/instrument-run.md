# The instrument run — the front-door path probe and the runbook application

Run 2026-11-14 against the composed stack (this repository's `docker compose up`, the
gateway and the front router) beside the owner's local instance
(`../dial-instance`, Core and Keycloak). Every verdict below was produced by a
request actually sent; nothing is inferred from documentation.

Owner delegation: task 6.3 is the **owner-delegated session act** — the owner
pre-authorized applying the runbook to their local instance from this session, and the
record below is that act.

## Task 6.3 — the runbook applied to the local instance (owner-delegated)

The instance's `docker-compose.yml` carried the retired two-callback list
(`["http://localhost:8090/dial/callback/upstream","http://localhost:8765/callback"]`).
It was replaced with the three-callback list, gateway first, the retired 8765 loopback
dropped:

```
'aidial.toolsets.security.allowedRedirectUris': '["http://localhost:8090/dial/callback/upstream","http://localhost:3100/auth/toolset-signin","http://localhost:3102/toolset-signin"]'
```

Core was recreated (`wsl -e docker compose up -d --force-recreate core`, run in the
instance folder). The applied value, read back from the running container's environment:

```
aidial.toolsets.security.allowedRedirectUris=["http://localhost:8090/dial/callback/upstream","http://localhost:3100/auth/toolset-signin","http://localhost:3102/toolset-signin"]
```

**No repair was needed for the `notion` toolset.** Its stored `redirect_uri` already reads
the gateway's callback (it is a dynamically-registered toolset whose stored field was the
gateway's callback before this change; the allowlist's first entry still is). Read back
from Core's own answer (`GET {core}/openai/toolsets/notion`, an authenticated identity
token):

```
redirect_uri            = http://localhost:8090/dial/callback/upstream
dynamically_registered  = True
```

So the gateway's derived callback is in Core's allowlist (first), and the one stored
field a still-stored-field-reading component would consume reads the gateway's own
callback — the runbook's step-1-before-step-3 ordering is satisfied for this instance
without a repair. The end-to-end Chat sign-in and gateway consent completion (the
runbook's verification step) are the interactive acceptance run's, not automatable here;
this record claims only the configuration act and the stored-field verification.

## Task 8.1 — `scripts/probe_front_door_paths.py`

The new probe battery. Run green (exit 0):

```
=== battery verdict ===
  red       control: encoded name not refused by the router
  red       control: full-URL listing read resolves
  pass      (2) stored-toolset chain
  pass      (2) authorize admits the resource path
  pass      (2) live tool call through the front door
  pass      (2) apps twin — stored-app path routed and challenged
  pass      (2b) user-bucket chain and isolation
  pass      (3) byte fidelity
  pass      (3b) match domain
  pass      (4) refused shapes
  pass      (5) canonicalization
  pass      (6) bounds and ReDoS

all 12 rows green (controls red as designed)
```

The two **negative controls ran first and are red as designed** — they assert the pre-fix
shapes and must FAIL against the fixed stack:

- *encoded name not refused by the router* — `GET /dial/toolsets/public/probe%20encoded/mcp`
  answered **401** (the router forwarded it byte-faithfully); the pre-fix single-segment
  capture would have refused it 404. The control's pre-fix shape is gone.
- *full-URL listing read resolves* — `GET {core}/openai/toolsets/toolsets/public/{probe}`
  answered **200** (Core resolved the stored path); the pre-fix addressing would have 404'd.

A control that *held* would stop the battery before any positive verdict (the
`ControlHoldsError` path returns non-zero with the acceptance untrusted).

**Rows that ran automated (green):**

- **(2) stored-toolset chain** — the front-door 401 challenged the multi-segment metadata
  path (`…/oauth-protected-resource/dial/toolsets/public/{probe}/mcp`); discovery served the
  document naming that resource; `/dial/authorize` admitted the resource-URI path (a 302 to
  the identity provider); Core's listing read resolved the same id (echoed verbatim).
- **(2) live tool call** — `POST /dial/toolsets/public/{probe}/mcp` with a gateway-minted
  Core-accepted token answered **200** with a real `tools/list` result (`echo`), through the
  front door to Core's data path. The fixture points at the local MCP fixture service
  (keyless by construction), so this leg needs no human sign-in.
- **(2) apps twin** — a stored-app path under `/apps/` answered the apps 401 challenge and
  the apps discovery document, both quoting the stored path.
- **(2b) user-bucket chain and isolation** — the ciphertext bucket was learned from Core's
  `GET /v1/bucket` and the resource id copied **verbatim** from Core's `PUT` response
  (`toolsets/{ciphertext}/{probe}`); the same chain ran against it; and a second realm user
  (provisioned through the Keycloak admin API, deleted after) was refused **403** on both the
  front-door data path and the listing read — the isolation assertion, same-answer-as-Core.
- **(3) byte fidelity** — `%20`, `%3F`, `%25`, non-ASCII (`%C3%A9`), `%2F` each reached Core
  byte-identically, asserted from the URI Core's own log recorded
  (e.g. `/v1/toolset/toolsets/public/{marker}%20b/mcp`).
- **(3b) match domain** — a query-bearing request (`…/mcp?sessionId={marker}%2F1`) routed
  with the parameter forwarded raw and intact; a post-`/mcp` path tail
  (`/dial/{path}/mcp/extra`, `/apps/{path}/mcp/extra`) was refused **404** and never forwarded.
- **(4) refused shapes** — dot-segments (`.`/`..`), an empty segment, a trailing dot, a
  reserved first segment (`/dial/authorize/x/mcp`) each answered **404**; raw non-ASCII
  (`/dial/toolsets/public/café/mcp`) answered **400** (nginx refuses the invalid request
  line before any location — the router refusing the shape without forwarding).
- **(5) canonicalization** — a `%78`-spelled path (non-canonical escape of `x`) was admitted
  at discovery (the document echoed the offered spelling) and Core's listing read resolved
  **both** the canonical and the `%78` spelling to the same `id` — one identity.
- **(6) bounds and ReDoS** — a 90-segment, 3695-char non-matching URI was refused **404 in
  0.016s** (no catastrophic backtracking); a URI past the ~8 KB request-line bound answered
  **414** (nginx's own bound, upstream of the regex); an over-depth path (40 segments, past the
  32-segment cap) and an over-length path (950 decoded bytes, past the 900-byte cap) were each
  refused **404** at discovery with the fixed-vocabulary reason `invalid_resource_path` on the
  audit trail.

Fixture cleanup: the probe creates and deletes its own public, user-bucket, and apps-path
fixtures and the second realm user; after the run Core's registry held only `notion` and
the realm held no probe user.

**Rows deferred to the interactive acceptance run (not faked):** the credential-call and
token-exchange legs of row (2)/(2b) — they need a human sign-in against a real upstream (the
`notion` toolset) and are the interactive harness's
(`scripts/probe_end_to_end_interactive.py`). Likewise the **token-audience-equality leg** of
row (5) — that two spellings mint one token audience — needs the interactive mint. The
battery prints these boundaries at their rows rather than asserting a pass.

## Task 8.2 — `scripts/probe_routing.py`, extended

The lockstep rows added (per the task text): the stated division of labor asserted on both
surfaces — the shapes both sides admit, the shapes both sides refuse, and the documented
asymmetry class asserted as the asymmetry it is, plus the apps twins. Run green (exit 0):

```
=== battery verdict ===
  pass      negative control — Core's own challenge
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

all 13 probes passed
```

The two lockstep rows, in full:

```
[12/13] lockstep: the map and the guard hold their documented division
  -- both sides admit --
  a stored path                          data=401 challenge=True discovery=200
  a user-bucket alphanumeric segment     data=401 challenge=True discovery=200
  -- both sides refuse --
  dot-segment ..                         data=404 discovery=404
  dot-segment .                          data=404 discovery=404
  empty segment                          data=404 discovery=404
  trailing dot                           data=404 discovery=404
  reserved first segment                 data=404 discovery=404
  -- the documented asymmetry (forwarded on the data path, refused at discovery) --
  encoded forbidden character %7B        data=401 challenge=True discovery=404
  escaped trailing dot %2e               data=401 challenge=True discovery=404
  verdict   green — the map/guard division holds: both-admit, both-refuse, and the documented asymmetry

[13/13] lockstep: the apps map/guard division
  an apps stored path                    data=401 challenge=True discovery=200
  apps dot-segment ..                    data=404 discovery=404
  verdict   green — the apps map/guard division holds
```

The user-bucket lockstep row uses an **alphanumeric single-segment** spelling (the shape a
real ciphertext Core hands a harness has), asserting both sides admit it — the row the task
names. The asymmetry row asserts the class the delta spec documents: `%7B` (an encoded
forbidden character) and `%2e` (an escaped trailing dot) are wire-conforming (the map
forwards them, a 401 challenge) yet guard-refused (discovery 404); the challenge names a
document the gateway answers 404 — the dead end by design.

## The one changed pre-existing row (a finding, recorded rather than hidden)

`probe_routing.py`'s probe 10 ("status paths…") was the battery's one pre-existing row
whose expectation this change alters. Before the change the data-path locations were
anchored (`^/dial/(?<tname>[a-z0-9-]+)/mcp$`, `^/apps/(?<aname>[a-z0-9-]+)/mcp$`), so
`/dial/{name}/status` fell through to the catch-all and reached Core, which answered an
unauthenticated call **401**. This change replaces them with prefix locations (`~ ^/dial/`,
`~ ^/apps/`) whose routability a raw-URI map decides, and the map's grammar **requires the
`/mcp` suffix** — the delta spec's conformance condition ("the `/mcp` suffix present …
MUST be refused by the router with 404 and never forwarded"). So `/dial/{name}/status` now
does not match the map, the location's `if ($dial_target = "") { return 404; }` refuses it,
and it never reaches Core: nginx answers **404** with no gateway challenge.

This is the spec-mandated shape, not a defect: the status surface is still unserved by any
gateway handler (the row's actual property — no gateway challenge on the path), and 404 is
what the change's own addressing requirement produces for a `/dial/`-prefixed path without
the `/mcp` suffix. The probe row's assertion and the `docs/routing.md` sentence describing
the fall-through were the stale halves; both were reconciled to the shipped router (the
probe now asserts a bare 404 with no gateway challenge; the doc states the prefix-location
refusal). The reference run above shows the reconciled row green.

## What this run does not cover

- The interactive sign-in legs (a human's upstream consent) — the interactive harness's.
- The token-audience-equality leg (row (5)) — needs the interactive mint.
- The compose-boot gate and the static gate tier are tasks 9.2/9.3, not this instrument run.
