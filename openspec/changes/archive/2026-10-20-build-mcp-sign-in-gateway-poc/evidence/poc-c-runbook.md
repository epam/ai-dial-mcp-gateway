# PoC C — the owner's acceptance run (group 9)

The five criteria, in running order. After each: record the row here (expected /
observed / verdict) — redact every token, code, and key. The change archives only
when all five rows are green.

**Status.** **(a), (c), (d), and (e) are CLOSED.** (c) closed in field run 2; (d) and (e)
in field run 1; **(a) closed in field run 4 (2026-10-20)** — the sign-out-FIRST recipe field
run 3's lesson produced ran the credential leg and put the full chain
(`flow_allocated → upstream_callback → signin_result(accepted) → code_issued → token_issued`)
in the live audit trail. (b) has its **silent** half audit-evidenced (field run 2's
`token_refreshed`), but still owes the **TTL-forced rotation double-invoke**. No pass is
inferred for (b).

## State reset (before the run, once)

`claude mcp remove notion-gw` then re-add — criterion (a) is FIRST USE on a real
harness, and Claude Code caches its client registration:
`claude mcp add --transport http notion-gw http://localhost:8090/dial/notion/mcp`

## (a) First use, end to end, via CIMD

Invoke any tool of `notion-gw` in Claude Code. Expect: the browser opens → Keycloak
(SSO-silent) → the interstitial (self-continues in ~1 s, no button) → Notion's
consent (one click) → back in the harness → the tool returns live workspace data.
Record: the consent sequence observed, the tool result.

## (b) Silent repeat use + refresh-on-401 with rotation

With the token cached: invoke tools again — expect NO browser. Then force expiry:
set `GATEWAY_ACCESS_TOKEN_TTL_SECONDS=30` in `.env`, `docker compose build
mcp-signin-gateway && docker compose up -d --force-recreate mcp-signin-gateway`,
restart the router, wait ~40 s, invoke again — expect the harness refreshes
transparently (no browser) and the tool works. Invoke once more — a SECOND successful
refresh proves the harness adopted the ROTATED refresh token. Restore the TTL to 600
and recreate afterwards.

## (c) Sign-out mid-session → the sign-in-again branch

Sign the toolset out (DIAL Chat, or the ops sign-out), then invoke from the harness:
expect the harness's session survives and it reports "needs sign-in"; run re-login:
Keycloak → interstitial → (consent — often suppressed) → live tool call. NOT a 401
loop; the harness's DIAL token is never discarded. This exact path was field-proven
on 2026-10-19 (the interstitial finding's fix followed it).

## (d) Query strings survive the data path

Covered by `scripts/probe_routing.py` (probe 2, negative control first): Core's own
log carries the full request URI with `?sessionId=…` on POST and GET. Re-run the
battery for the run's own capture.

## (e) Direct-to-Core coexistence

With the front door live: a direct-to-Core client with a Keycloak-issued token keeps
working unchanged — `scripts/probe_gateway_trust.py`'s Keycloak-issued control
resolves against Core on 8081 (and/or the PoC-A helper's flow on `:8081/v1/toolset/
notion/mcp`). Record: both surfaces answer while the front door serves.

## After the run

All five green → the rows are the change's final conformance evidence → sync +
archive. Any red row → it is a finding for the defect cycle (criterion failure =
design falsification; anything else = change defect) — record, don't patch around.

## Field run (owner-driven, 2026-10-19)

Two scenarios were run on the real harness (Claude Code) by the owner, both reported
successful. Below is what the containers' logs yield for each. **Redaction:** no token,
code, key, secret or password appears below; the subject and the storage bucket are
recorded as sha256-prefixed handles only (`subject` = `sha256:906f2ef4ac94`, `bucket` =
`sha256:548153266148`); the toolset name `notion` is public (it is in the request path)
and is kept.

Container window: the gateway container started `20:03:10Z` and is still up, so its log
covers the whole run (`20:18Z–20:34Z`). Docker's `json-file` driver, no rotation in
window.

### The gateway audit trail yielded NO records (blocking capture gap)

**Status: FIXED + VERIFIED 2026-10-19 — see "The defect: fixed + verified" below.** The
diagnosis and the run consequences below are kept as the record of what this run could not
capture; the records are now observable in the container.

The runbook's core ask — extract the gateway's audit event sequence — **cannot be met**:
`docker logs ai-dial-mcp-gateway-mcp-signin-gateway-1` contains **four lines, all uvicorn
startup, and not one audit record**. Root cause, confirmed live in the container:

- `gateway/audit.py` logs on the `gateway.audit` logger at INFO, and **nothing attaches a
  handler to it or to the root logger**. `uvicorn.run`'s `LOG_CONFIG` configures only
  `uvicorn` / `uvicorn.error` / `uvicorn.access` — the root logger keeps **no handlers** and
  level `WARNING` (30).
- `gateway.audit`'s effective level is therefore `WARNING` (30), so `isEnabledFor(INFO)` is
  `False`: every audit record is dropped before it can be emitted. The only fallback,
  `logging.lastResort`, is itself a `WARNING`-level handler, so it does not catch them
  either.
- Reproduced in-container: importing `gateway.audit` and calling `flow_allocated(...)`
  prints nothing.

So the gateway has no observable audit trail **at all** in the container — this is not a
gap specific to these two scenarios. Consequence for this run: every criterion whose
evidence is a gateway event sequence has its audit half unavailable, and the **absence of
`flow_refused` / `flow_leg_failed` cannot be read as "none occurred"** — nothing would have
been recorded either way. The chain below is therefore reconstructed from **Core's** log
(and the owner's observation), which is real evidence that the flow ran, but it is **not
the gateway's own audit evidence the runbook asks for**. This is a change defect for the
defect cycle (not a criterion failure), recorded here, not patched around.

### Scenario 1 — SILENT repeat use

Expected: no flow allocation, no IdP leg, no browser; either no gateway events at all
(data path is router→Core) or a `token_refreshed` if the harness refreshed.

Observed (Core's log, `20:18:42Z–20:19:20Z`): a burst of `POST /v1/toolset/notion/mcp`
running straight to the upstream — `20:18:42.546 → 20:18:43.311 (200)`,
`20:18:43.472 → 20:18:43.921 (200)`, `20:18:44.107/44.110 → 44.552/44.555 (200)`, then
`20:19:19.050/19.053/19.059 → 19.703/19.707/19.811 (200)` and `20:19:19.963 → 20:19:20.727
(200)`. These are Core proxying MCP to `mcp.notion.com:443` and answering 200 — the tool
calls succeeded with **no 401, no challenge, and no gateway-side hop** (the data path is
router→Core by design). No gateway audit record exists for the window (see the gap above),
so a `token_refreshed` *may* have occurred but is unobservable.

Verdict — (b)'s **silent** part: **owner-observed and indirectly corroborated.** The
harness re-invoked tools with no browser and every call returned live data (HTTP 200 from
the upstream via Core). Consistent with expectation. NOT closed as an audit row: the
gateway's own trail is empty by defect, so "no flow allocation" is unfalsifiable from the
log rather than affirmatively proven.

### Scenario 2 — full RE-LOGIN (sign-out → harness re-login → interstitial → consent → live call)

Expected chain: `flow_allocated → Keycloak leg → upstream_callback → signin_result
(success) → code_issued → token_issued`; and NO `flow_refused` / `flow_leg_failed`.

Observed — the gateway's own records are **absent** (gap above). Core's log carries the
correlated chain, `20:30:18Z–20:34:07Z`:

1. `20:30:18.648` `POST /v1/ops/toolset/signout` → "Deleting resource credentials for
   resourceId=toolsets/config/notion" (the owner's Chat sign-out); `20:30:18.668` →
   "finished. Result: true".
2. `20:31:29.264 → 20:31:36.156` eight `POST /v1/toolset/notion/mcp` calls, each answered
   **401** by the upstream through Core — the harness's session alive and being challenged
   (the router replaces Core's `WWW-Authenticate` with the gateway's protected-resource
   challenge). No unbounded 401 loop; the challenge led to re-login.
3. `20:33:03.400` `POST /v1/ops/toolset/signin` → "Adding resource credentials for
   resourceId=toolsets/config/notion, credentialsLevel=USER" — **this is the gateway's
   credential call landing** (the flow's decisive leg; the body carries the user's identity
   token, `user.id = subject sha256:906f2ef4ac94`, `user.project = proj-alpha`).
   `20:33:05.306` → "stored successfully". The store bucket is `sha256:548153266148`.
4. `20:33:06.416 → 20:33:07.037 (200)` and `20:33:07.198 → 20:33:07.669 (200)` — live tool
   calls immediately after the credential was stored (the post-consent success).
5. `20:33:07.902–20:33:08.438`, `20:33:29.639 → 20:33:30.288 (200)`,
   `20:33:34.514 → 20:33:35.435 (200)`, `20:34:06.269–20:34:07.797 (200)` — continued
   successful use.

Verdict — (c): **owner-observed and indirectly corroborated.** Sign-out removed the stored
credential (Core, step 1); the harness's session survived and its calls were challenged
rather than the token discarded (step 2); a re-login ran end-to-end and re-established the
credential at USER level (step 3); a live tool call then succeeded (step 4). The
interstitial/consent steps are owner-observed (no container log carries them; the router's
`access_log` is off by design). NOT closed as an audit row: the gateway's own
`flow_allocated / upstream_callback / signin_result / code_issued / token_issued` sequence
— the thing this row wanted — is empty by defect, and "no `flow_refused`/`flow_leg_failed`"
is unverifiable from the log.

Verdict — (a) (FIRST USE end-to-end, via CIMD): **not captured in this run.** This field
run exercised repeat-use + re-login, not a first use; the gateway's own trail is empty by
defect regardless, so (a)'s row is still owed.

### What each criterion still needs to close

The audit trail these three rows need is now observable (see "The defect: fixed + verified"
below); what remains is the owner's own harness run for each.

- **(a) first use end to end** — a fresh first-use run after `claude mcp remove` / re-add
  (the reset above): the `flow_allocated → … → token_issued` chain plus the CIMD fetch.
- **(b) refresh-on-401 with rotation** — the still-unrun half: set
  `GATEWAY_ACCESS_TOKEN_TTL_SECONDS=30`, rebuild + recreate the gateway, restart the router,
  wait ~40 s, invoke (expect a transparent refresh, no browser), invoke again (a SECOND
  refresh proves rotation adoption). The **silent** half is owner-observed here. Both halves
  need the gateway's `token_refreshed` record.
- **(c) sign-out → sign-in-again** — behaviors owner-observed and Core-corroborated in this
  run (above); needs the gateway's own audit sequence to close the row, and a re-run.
- **(d) query strings survive the data path** — re-run `scripts/probe_routing.py` for this
  run's own capture (negative control first). **CLOSED 2026-10-19** (below).
- **(e) direct-to-Core coexistence** — still to run: `scripts/probe_gateway_trust.py`'s
  Keycloak-issued control against Core on 8081 (and/or the PoC-A helper's flow) while the
  front door serves; record both surfaces answering. **CLOSED 2026-10-19** (below).

## (d) — query strings survive the data path: CLOSED

Re-run of `scripts/probe_routing.py` with the front door live, after the logging fix's
compose rebuild + recreate + router restart. **Negative control first, as required**: Core
called directly on `http://localhost:8081/v1/toolset/notion/mcp` answers its *own* challenge
naming its *own* metadata (`resource_metadata="http://localhost:8081/.well-known/
oauth-protected-resource/v1/toolset/notion/mcp"`) — a challenge different from the
router's, so probe 5's rewritten challenge is measured against a real alternative and not
against a coincidence.

Observed (probe 2): `POST` and `GET` to `http://localhost:8090/dial/notion/mcp?sessionId=…`
through the router, and Core's own log carries the full request URI with the parameter
intact on both methods — `request.uri='/v1/toolset/notion/mcp?sessionId=probe-218b782e0a8b'`
(POST) and `…?sessionId=probe-218b782e0a8b-get` (GET). The session id is the probe's own
public generated value, not a credential.

**Battery verdict: all 6 probes passed** — the negative control, query-string survival, the
flat AS metadata, the per-toolset PRM, the rewritten data-path 401 (naming
`http://localhost:8090/.well-known/oauth-protected-resource/dial/notion/mcp`), and both
gateway paths answering as the gateway (`400 invalid_request`) rather than as Core (`404`).

## (e) — direct-to-Core coexistence: CLOSED

`scripts/probe_gateway_trust.py`, run with the front door live. The Keycloak-issued control
is the identity leg: the probe mints a token from a **real realm user's claim set fetched
over Keycloak** (`identity_claims` → `fetch_identity_token`), re-signed under the gateway's
key, and resolves it at Core on `:8081`.

- Negative control (before the positives): a token signed by a key the gateway does not
  publish → `GET /v1/user/info` → **HTTP 401**. Red as required.
- The gateway's published JWKS (through the front door, `http://localhost:8090/dial/
  jwks.json`) carries `kid=a119a0a9bee68848`, matching the `kid` derived from
  `GATEWAY_SIGNING_KEY`.
- Positive: that token → `GET /v1/user/info` → **HTTP 200**, `userId` = the realm user
  (subject `sha256:906f2ef4ac94`), `roles=["admin"]`.

Both surfaces answer while the front door serves: Core's own `:8081` toolset path keeps
answering direct-to-Core clients (probe (d)'s control above, a direct-to-Core call answered
by Core), and the gateway's front door serves the flat AS, the PRM, and the rewritten 401.
The coexistence requirement holds on this run's capture.

**The blocking item** for the audit half of every row above was the gateway's audit trail
being unobservable in the container (no handler on `gateway.audit`; effective level WARNING
dropped the INFO records). **It is fixed and verified** — see the next section; the audit
evidence for (a), (b), and (c) becomes obtainable on the owner's next run, which is still
owed.

## The defect: fixed + verified (2026-10-19)

### The wiring

`gateway/__main__.py` gains `configure_logging()`, called from `main()` and nowhere else:

- a `StreamHandler(sys.stdout)` attached to the **`gateway`** logger — the namespace
  `gateway.audit`, `gateway.store`, and `gateway.app` all descend from, so one attachment
  routes all three — at level `INFO`, with the logger's own level set to `INFO`;
- `propagate = False`, so a deployment that also configures the root logger does not get a
  second copy of every record;
- a single-line format, `%(asctime)s %(levelname)s %(name)s %(message)s`, stamped in UTC
  (a `_UtcFormatter` overriding `formatTime`, because the default renders a naive local
  time and `%z` renders nothing from one) — so the audit rows order against Core's and
  Keycloak's UTC logs. The message body is unchanged: for an audit record it is still
  exactly the JSON document `AuditTrail._emit` writes, so no record's content changed.
- **idempotent**: the handler carries a marker attribute and a second call finds it and
  returns, so a re-import cannot duplicate every line.

Uvicorn's loggers are deliberately left alone and `uvicorn.run` keeps `access_log=False`,
so no request line (and therefore no code or token on the callback paths) is written.

The configuration is at **run/startup** time, not at import of `gateway.app` — importing
still validates nothing and configures nothing, which is what keeps the suite hermetic (it
attaches its own handlers) and is the recorded lesson from the import-time validation
defect.

### Test outcomes

`tests/test_audit.py` gains six tests pinning the **runtime** wiring rather than a test
handler: the record reaches **stdout** (read via `capsys`, not `caplog`, so the assertion
is on the configuration `main()` installs); the `gateway` level makes audit/store/app all
INFO-enabled; a second `configure_logging()` attaches no second handler; `propagate` is off;
the wiring puts no handler on `uvicorn.access`/`uvicorn.error`; and `main()` passes
`access_log=False`.

**Negative control.** With `configure_logging()` neutered to a bare `return`, three of the
six fail (`test_the_wiring_delivers_an_audit_record_to_the_container_log`,
`test_the_wiring_covers_every_logger_in_the_package`,
`test_the_wiring_does_not_capture_the_process_root`); restored, all six pass. The suite
would have caught this defect.

### The live container log now carries the trail

Rebuilt and `--force-recreate`d the gateway and restarted the router. The container window
is this fix's own run. Two record classes are shown, both redacted (the gateway-generated
`flow_id` is an opaque identifier, not a credential; the subject is the runbook's own
handle, which this run reproduces exactly — `sha256:906f2ef4ac94`).

A `flow_refused` from the negative traffic (an unknown client, before any flow):

```
2026-10-19T22:08:03Z INFO gateway.audit {"at": …, "client_id": "unknown-probe",
  "event": "flow_refused", "reason": "unknown_client",
  "redirect_uri": "http://127.0.0.1:9999/cb",
  "resource": "http://localhost:8090/dial/notion/mcp", "toolset": "notion"}
```

The full successful sign-in chain, from `scripts/probe_end_to_end.py` driven through the
front door (discovery → Keycloak login → the gateway callback → `/dial/token` → a live
`tools/list` of 65 tools, all steps green):

```
2026-10-19T22:07:41Z INFO gateway.audit {… "client_id": "group6-smoke",
  "event": "flow_allocated", "flow_id": "MIaLRtRbYzDiosqsJOe3PA", "toolset": "notion"}
2026-10-19T22:07:42Z INFO gateway.audit {… "event": "code_issued",
  "flow_id": "MIaLRtRbYzDiosqsJOe3PA", "subject": "sha256:906f2ef4ac94", …}
2026-10-19T22:07:43Z INFO gateway.audit {… "event": "token_issued",
  "subject": "sha256:906f2ef4ac94", "toolset": "notion"}
```

So the chain the runbook's scenario 2 wanted — `flow_allocated → … → code_issued →
token_issued` — is now readable from the gateway's own log, and the absence of
`flow_refused` / `flow_leg_failed` for a window is now falsifiable (the refusal class is
demonstrably written). The capture above is the **final** image's window (rebuilt after
the last source edit, so the running container matches the tree): six audit records and
four uvicorn startup lines, and **no access-log line** — the container-log scan for
`GET /dial`, `POST /dial`, and `HTTP/1.1` request lines returns **0**, so the
`access_log=False` property holds.

### What is still owed (the OWNER's harness)

The fix unblocks the audit half of (a), (b), and (c); it does not run them. Still owed,
because each needs the owner's clicks and a real harness, and simulating them proves
nothing:

- **(a) first use end to end** — the `claude mcp remove` / re-add reset, then the
  `flow_allocated → … → token_issued` chain plus the CIMD fetch, now observable.
- **(b) refresh-on-401 with rotation** — the TTL-30 half (rebuild, recreate, restart,
  ~40 s, invoke twice) and the `token_refreshed` record it should now produce.
- **(c) sign-out → sign-in-again** — a re-run of the owner's proven path, this time with
  the gateway's own audit sequence available to close the row.

## Field run 2 (owner-driven, 2026-10-19) — the audit trail LIVE

The owner re-ran two harness scenarios with the observability fix deployed. The gateway
container started `22:06:38Z` and is still up (`RestartCount=0`), so its log covers the
whole window; Docker's `json-file` driver, no rotation in window. **Redaction:** no token,
code, key, secret or password appears below. The subject is the runbook's own handle
(`sha256:906f2ef4ac94`); the storage bucket is `sha256:548153266148`; the gateway-generated
`flow_id` and JWT `jti` (`token_id`) values are the gateway's own opaque identifiers, not
credentials, and are kept. The client id `https://claude.ai/oauth/claude-code-client-metadata`
is a public client-id-metadata URL (it is what the client presents, not a secret), and the
toolset name `notion` is public (it is in the request path).

The audit trail is **no longer empty**. The container's stdout carries 17 audit records and
its stderr the 4 uvicorn startup lines; no `HTTP/1.1` access-log line is present
(`access_log=False` holds). Across the whole window there are **0 `flow_leg_failed`**
records, so the absence of a failure below is falsifiable rather than vacuous.

The window also contains the logging fix's own verification traffic (`22:07–22:08Z`:
`group6-smoke`'s end-to-end probe chain, and the `unknown-probe` / `invalid_response_type` /
`invalid_token_request` refusals) — not part of either scenario, noted so the reader does not
attribute them to the owner's run.

### Scenario (a)-variant — flow chain on a CACHED registration

**The owner did NOT run the reset** (`claude mcp remove` / re-add). Instead: signed out in
the harness, disabled the toolset, re-enabled it, re-authenticated. The harness's client
registration was therefore **cached** — no fresh CIMD registration event, and **no
`client_registered` record appears in the whole window**. So this run covers the flow chain
on an *existing* registration; it is **not** the clean first-use criterion (a) asks for.

Gateway audit sequence for the re-login (`22:22:51Z–22:22:52Z`), one flow id, one chain:

```
2026-10-19T22:22:51Z INFO gateway.audit {"client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "event": "flow_allocated", "flow_id": "QVfh_-fi6VF2v8sqliTcQQ", "toolset": "notion"}   (22:22:51)

2026-10-19T22:22:51Z INFO gateway.audit {"client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "event": "code_issued", "flow_id": "QVfh_-fi6VF2v8sqliTcQQ",
  "subject": "sha256:906f2ef4ac94", "toolset": "notion"}                                   (22:22:51)

2026-10-19T22:22:51Z INFO gateway.audit {"client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "event": "token_issued", "subject": "sha256:906f2ef4ac94", "toolset": "notion"}          (22:22:51)
```

**Read this chain correctly — the identity leg short-circuited.** `flow_allocated` is
immediately followed by `code_issued` and `token_issued` with **no `upstream_callback` and
no `signin_result` in between**. That is the designed short-circuit, not a gap: the
identity leg's `complete_identity_leg` found `status.signed_in` true (Core still held a
USER-level credential for `notion` at that instant), so `_run_identity_leg` took the
`_finish` branch — nothing upstream to approve, so no interstitial and no credential call,
hence no `upstream_callback` / `signin_result`. What the owner's disable/enable did was
force a fresh *harness* authorization code and token, not a new upstream consent. This
matches criterion (a)'s cursor expectation **only partially**: the flow allocation and the
code/token issuance are recorded, but the Keycloak leg, the interstitial, and the upstream
leg did not run in this flow.

Corroboration in Core's log (`22:22:53Z–22:22:55Z`): five `POST /v1/toolset/notion/mcp`
calls, each `Connected to origin: mcp.notion.com:443` → `status=200` (the live tool calls
after the re-auth). No `/v1/ops/toolset/signin` in this sub-window — consistent with the
short-circuit (the credential was already stored).

The same window also carries the pure-TTL refresh that preceded the sign-out, which is
criterion (b)'s **silent-refresh half** caught live:

```
2026-10-19T22:21:02Z INFO gateway.audit {"client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "event": "token_refreshed", "subject": "sha256:906f2ef4ac94", "toolset": "notion"}
```

and the harness's own revoke of the pre-sign-out refresh token (Core's
`/v1/ops/toolset/signout` equivalent at the harness layer), at `22:22:30Z`:

```
2026-10-19T22:22:30Z INFO gateway.audit {"event": "token_revoked", "token_id": "SuNGwqnnq6RdiZZY63P9Xg"}
```

Verdict — (a): **one clean run owed.** This run is the *variant* (cached registration,
short-circuited identity leg); it is recorded for what it shows — the trail is live, a flow
chain on an existing registration is readable end to end, and a `token_refreshed` and a
`token_revoked` are both observable — but it does not exercise first-use. The criterion
still owes **exactly one clean first-use**: `claude mcp remove notion-gw` → `claude mcp add
--transport http notion-gw http://localhost:8090/dial/notion/mcp` → invoke any tool, so the
**fresh CIMD registration** plus the *full* chain
(`flow_allocated → Keycloak leg → interstitial → upstream → upstream_callback →
signin_result → code_issued → token_issued`) lands in the observable trail. The earlier
field run (2026-10-19, run 1) observed this flow but was before the trail was live.

### Scenario (c) — sign-out mid-session → sign-in-again: **CLOSED**

This is the exact criterion (c) behavior: the owner signed out in **DIAL Chat**, then
re-authenticated **in the harness**.

Gateway audit sequence — the full re-login chain, one flow id, `22:23:42Z–22:23:59Z`:

```
2026-10-19T22:23:42Z INFO gateway.audit {"client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "event": "flow_allocated", "flow_id": "XW7UiyWwnwbZWL07kebz4w", "toolset": "notion"}      (22:23:42)

2026-10-19T22:23:57Z INFO gateway.audit {… "event": "upstream_callback",
  "flow_id": "XW7UiyWwnwbZWL07kebz4w", "subject": "sha256:906f2ef4ac94", "toolset": "notion"} (22:23:57)

2026-10-19T22:23:58Z INFO gateway.audit {… "event": "signin_result", "result": "accepted",
  "flow_id": "XW7UiyWwnwbZWL07kebz4w", "subject": "sha256:906f2ef4ac94", "toolset": "notion"} (22:23:58)

2026-10-19T22:23:58Z INFO gateway.audit {… "event": "code_issued",
  "flow_id": "XW7UiyWwnwbZWL07kebz4w", "subject": "sha256:906f2ef4ac94", "toolset": "notion"} (22:23:58)

2026-10-19T22:23:59Z INFO gateway.audit {… "event": "token_issued",
  "subject": "sha256:906f2ef4ac94", "toolset": "notion"}                                     (22:23:59)
```

The 15-second gap between `flow_allocated` (22:23:42) and `upstream_callback` (22:23:57) is
the browser legs the container does not log: Keycloak, the interstitial (`upstream_authorization`
built and served at ~22:23:42+), and Notion's consent — owner-observed. `signin_result` is
`accepted` (not `access_refused` / `failed`).

Core's log corroborates the same flow, `22:23:20Z–22:24:02Z`:

1. `22:23:20.203` `POST /v1/ops/toolset/signout` → "Deleting resource credentials for
   resourceId=toolsets/config/notion."; `22:23:20.221` → "…bucket=sha256:548153266148
   finished. Result: true" — **the Chat sign-out landed** (user.id = subject
   `sha256:906f2ef4ac94`, user.project = `proj-alpha`).
2. `22:23:57.073` `POST /v1/ops/toolset/signin` → "Adding resource credentials …,
   credentialsLevel=USER"; `22:23:58.809` → "…stored successfully" — **the gateway's
   credential call landed**, and its timestamp sits between the gateway's `upstream_callback`
   (22:23:57.049) and `signin_result` (22:23:58.812), exactly where the flow's credential
   leg belongs.
3. `22:23:59.753 → 22:24:01.04 (200)` and a burst of further `POST /v1/toolset/notion/mcp`
   calls, all `status=200` — **live tool calls immediately after the credential was stored**.
   No 401 in this sub-window: the re-login produced a working credential at once.

The harness's own token bookkeeping closes the loop at `22:24:03Z`:

```
2026-10-19T22:24:03Z INFO gateway.audit {"event": "token_revoked", "token_id": "Inq1rWP2j7cuhtwAM6BPzQ"}
```

(the refresh token the pre-re-login session held, revoked as the new one was adopted).

**Row (c) — CLOSED.** Sequence complete and clean: `flow_allocated → (Keycloak → interstitial
→ consent, owner-observed) → upstream_callback → signin_result(accepted) → code_issued →
token_issued`, followed by a live tool call. No `flow_refused`, no `flow_leg_failed`, and no
401 loop anywhere in the window (0 `flow_leg_failed` container-wide). Evidence basis:
owner-observed + gateway-audit-recorded + Core-corroborated (`/v1/ops/toolset/signout` then
`/v1/ops/toolset/signin`, the credential stored at USER level, live calls after). Contrast
run 1's scenario 2, where the same behaviors were owner-observed but the gateway's own
sequence was unobservable — that gap is what this run closes.

### What (a) and (b) still owe the owner

- **(a) ONE clean first-use — now with a sign-out BEFORE the reset** (field run 3 showed
  the reset alone is not enough: the upstream credential lives in Core, not in the harness,
  so `remove`/re-add leaves it in place and the flow short-circuits). Sign the toolset out
  (`/v1/ops/toolset/signout`), *then* `claude mcp remove notion-gw` → `claude mcp add
  --transport http notion-gw http://localhost:8090/dial/notion/mcp` → invoke any tool.
  Expect the browser → Keycloak (SSO-silent) → interstitial (self-continues, no button) →
  Notion consent (one click) → the tool returns live data; and in the gateway trail the
  full chain `flow_allocated → upstream_callback → signin_result(accepted) → code_issued →
  token_issued`. The distinguishing mark versus both runs recorded so far:
  `upstream_callback` and `signin_result` are **present** (the credential leg ran), not
  skipped. Note the CIMD fetch itself has no audit event, so the fresh-registration half
  rests on the owner's observation of the reset, not on a `client_registered` record — a
  CIMD client never produces one (that event is the DCR path).
- **(b) TTL-forced refresh with rotation — the still-unrun half.** The **silent** half is
  now audit-evidenced (`token_refreshed`, 22:21:02Z); the TTL-forced half is owed: set
  `GATEWAY_ACCESS_TOKEN_TTL_SECONDS=30` in `.env`, `docker compose build
  mcp-signin-gateway && docker compose up -d --force-recreate mcp-signin-gateway`, restart
  the router, wait ~40 s, invoke (expect a transparent refresh, no browser — a new
  `token_refreshed` record), then **invoke once more**: a **SECOND** `token_refreshed`
  proves the harness adopted the **rotated** refresh token. Restore the TTL to 600 and
  recreate afterwards.

## Field run 3 (owner-driven, 2026-10-19) — criterion (a)'s reset, short-circuited

The owner ran the (a) reset: `claude mcp remove notion-gw`, then re-added it
(`claude mcp add --transport http notion-gw http://localhost:8090/dial/notion/mcp`), then
invoked a tool. The gateway container is the same one from field run 2 (started
`22:06:38Z`, `RestartCount=0`), so its log covers the whole window. **Redaction:** the
subject is the runbook's handle (`sha256:906f2ef4ac94`); the storage bucket is
`sha256:548153266148`; the client-metadata URL is public. The `flow_id` values are the
gateway's own opaque identifiers.

**The harness-side config changed in the run's own minute.** The harness snapshots its
config before each write: the `22:47:10Z` snapshot lists the gateway server under the alias
`notion-via-gateway` (same URL, `http://localhost:8090/dial/notion/mcp`), and the
`22:48:23Z` snapshot lists it as `notion-gw`. So a registration write landed between those
two instants — consistent with the stated reset, though the pre-reset alias differs from
the name the runbook's command removes, so what is *proven* here is that the harness rewrote
its gateway registration in that minute, not the exact command sequence. Either way the
trail shows no fresh-consent path.

### The run's flow chain — short-circuited again

One flow, `22:48:19Z`, one flow id:

```
2026-10-19T22:48:19Z INFO gateway.audit {"client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "event": "flow_allocated", "flow_id": "FvxaACjUlCCMrLxsInW4iQ", "toolset": "notion"}

2026-10-19T22:48:19Z INFO gateway.audit {… "event": "code_issued",
  "flow_id": "FvxaACjUlCCMrLxsInW4iQ", "subject": "sha256:906f2ef4ac94", "toolset": "notion",
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata"}

2026-10-19T22:48:19Z INFO gateway.audit {… "event": "token_issued",
  "subject": "sha256:906f2ef4ac94", "toolset": "notion",
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata"}
```

**This is the short-circuit, exactly as in field run 2's variant**: `flow_allocated` is
followed immediately by `code_issued` and `token_issued`, with **no `upstream_callback` and
no `signin_result`** anywhere in the window. The identity leg's `complete_identity_leg` read
Core's status, found `signed_in` true — Core still held a **USER-level credential for
`notion`**, stored by field run 2's re-login at `22:23:57Z` and never removed since — and
took the `_finish` branch. Nothing upstream was left to approve, so no interstitial, no
Notion consent, no credential call.

The `claude mcp remove` / re-add reset does **not** touch that credential: it clears the
harness's own registration and its client-side tokens, but the upstream Notion credential
lives in **Core**, per user and per toolset, and survives the reset. That is why the same
short-circuit signature recurs.

### No fresh-CIMD registration is auditable — and no `client_registered` is expected

`grep client_registered` over the **whole** container window returns **0**. This is
**correct and not a gap**: `client_registered` is the DCR event (`gateway/routes.py`, the
`/dial/register` path, `source="dcr"`). A CIMD client never calls that endpoint — the
gateway resolves the metadata URL through `gateway/cimd.py`, whose `resolve_client_async`
path **emits no audit event at all**; the first record a CIMD flow produces is
`flow_allocated`. The fresh registration therefore has **no audit representation**; the only
observable is the `client_id` on the flow records, and for a CIMD client that URL is
byte-identical between a fresh registration and a cached one. So this run can neither
confirm nor deny a fresh registration from the trail — the distinguishing mark must be the
**chain shape**, and the chain shape here is the short-circuit.

### Correlated evidence

- Core's log, `22:46:40Z–22:48:40Z`: the harness's `token_refreshed` at `22:46:40Z` is
  followed by live `POST /v1/toolset/notion/mcp` calls at `22:46:41/42` (status 200), then
  after the reset the `22:48:19Z` flow is followed by live calls at `22:48:20–22:48:22` and
  `22:48:40` (all 200). **No `/v1/ops/toolset/signout` and no `/v1/ops/toolset/signin` in
  this window** — the credential call that a fresh consent would have produced never ran,
  which is exactly what the absent `upstream_callback` / `signin_result` says. The last
  signin/signout pair in Core's log remains field run 2's (`22:23:20Z` / `22:23:57Z`).
- Zero `flow_leg_failed` and zero `client_registered` container-wide; the three
  `flow_refused` records are field run 2's probe traffic (`22:08Z`), outside this window.

### Row (a) — verdict

**Still owed, and now with a sharper recipe.** This run *did* exercise the harness-side
reset (remove/re-add is corroborated), but the flow **short-circuited on the credential that
field run 2's re-login had left in Core**, so the run recorded is the **chain-on-a-cached-
credential**, not the fresh-consent first-use. Sequence-complete but the credential leg is
absent — the same verdict field run 2's variant earned, reached by a different route.

What (a) still needs is one run in which the upstream credential is **gone before the
invoke**, so the consent legs actually run:

1. **Sign the toolset out** (`/v1/ops/toolset/signout` via DIAL Chat, or the ops sign-out) —
   this is the step both runs so far omitted, and it is what clears Core's USER-level
   credential. (`claude mcp remove` / re-add does **not** clear it.)
2. *Then* `claude mcp remove notion-gw` → `claude mcp add --transport http notion-gw
   http://localhost:8090/dial/notion/mcp`.
3. Invoke any tool.

Expect the browser → Keycloak (SSO-silent) → interstitial (self-continues, no button) →
Notion consent (one click) → live data; and in the trail the **full** chain
`flow_allocated → upstream_callback → signin_result(accepted) → code_issued → token_issued`
with `upstream_callback` and `signin_result` **present**. Note the trail cannot show the
CIMD fetch itself (no event exists for it) — the fresh-registration half of (a)'s evidence
rests on the owner's observation of the reset plus the chain shape, not on a
`client_registered` record.

Field run 1 (pre-trail, `2026-10-19`) is the one run that did observe the fresh-consent path
end to end; it predates the audit trail, so its audit half is unavailable — which is why
this row still owes the run, not a re-reading of field run 1.

## Field run 4 (owner-driven, 2026-10-20) — criterion (a) CLOSED

The owner ran field run 3's corrected recipe: **sign the toolset out FIRST**, then
`claude mcp remove notion-gw` → `claude mcp add --transport http notion-gw
http://localhost:8090/dial/notion/mcp` → invoke any tool. This time the credential leg ran —
the sign-out removed Core's stored USER-level credential, so the flow could not
short-circuit.

The gateway container is the same one from field runs 2/3 (started `2026-10-19T22:06:38Z`,
`RestartCount=0`), so its log covers the whole window; Docker's `json-file` driver, no
rotation in window. **Redaction:** the subject is the runbook's own handle
(`sha256:906f2ef4ac94` — the raw subject and the handle were recomputed this run and match);
the storage bucket is `sha256:548153266148` (likewise re-derived and matching); the
client-id-metadata URL is public; the toolset name `notion` is public (it is in the request
path). The `flow_id` is the gateway's own opaque identifier, not a credential.

### The gateway audit trail — the full credential-leg chain

The window new to this run is `2026-10-20T09:08Z–09:14Z`; five audit records, one flow id,
one chain:

```
2026-10-20T09:12:18Z INFO gateway.audit {"client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "event": "flow_allocated", "flow_id": "9-NlvfesJS55qNNIjchypw", "toolset": "notion"}       (09:12:18)

2026-10-20T09:12:42Z INFO gateway.audit {… "event": "upstream_callback",
  "flow_id": "9-NlvfesJS55qNNIjchypw", "subject": "sha256:906f2ef4ac94", "toolset": "notion"} (09:12:42)

2026-10-20T09:12:43Z INFO gateway.audit {… "event": "signin_result", "result": "accepted",
  "flow_id": "9-NlvfesJS55qNNIjchypw", "subject": "sha256:906f2ef4ac94", "toolset": "notion"} (09:12:43)

2026-10-20T09:12:43Z INFO gateway.audit {… "event": "code_issued",
  "flow_id": "9-NlvfesJS55qNNIjchypw", "subject": "sha256:906f2ef4ac94", "toolset": "notion"} (09:12:43)

2026-10-20T09:12:44Z INFO gateway.audit {… "event": "token_issued",
  "subject": "sha256:906f2ef4ac94", "toolset": "notion"}                                     (09:12:44)
```

**This is the distinguishing mark both earlier (a) runs lacked.** `flow_allocated` is
followed by **`upstream_callback`** and **`signin_result(result="accepted")`** — the
credential leg ran. Contrast field runs 2/3, where `flow_allocated` fell straight through to
`code_issued` with no `upstream_callback` / `signin_result`: that absence was the
short-circuit on the still-stored credential. Here the whole chain is present in the
gateway's own trail.

The **23.9-second gap** between `flow_allocated` (09:12:18) and `upstream_callback`
(09:12:42) is the browser legs the container does not log: Keycloak (SSO-silent), the
interstitial (self-continues, no button), and Notion's consent (one click) — all
owner-observed. `signin_result` is `accepted`, not a refusal kind.

**No `flow_refused` and no `flow_leg_failed` anywhere in the window** — the ledger is now
non-vacuous (both classes are demonstrably written: three `flow_refused` and zero
`flow_leg_failed` exist container-wide from field run 2's probe traffic, and the new window
adds none of either). The 5 new records sit alongside 4 uvicorn startup lines and **no
access-log line** (`access_log=False` holds).

### Core correlation

Core's log corroborates the same flow, `09:08:30Z–09:14:16Z`:

1. `09:08:30.929` `POST /v1/ops/toolset/signout` → "Deleting resource credentials for
   resourceId=toolsets/config/notion."; `09:08:30.956` → "…bucket=sha256:548153266148
   finished. Result: **true**" — **the owner's sign-out landed and removed the credential**
   (user.id = subject `sha256:906f2ef4ac94`). This is the step field runs 2/3 omitted, and
   the reason this run's flow did not short-circuit.
2. `09:12:42.050` `POST /v1/ops/toolset/signin` → "Adding resource credentials for
   resourceId=toolsets/config/notion, bucket=sha256:548153266148, **credentialsLevel=USER**"
   (user.id = `sha256:906f2ef4ac94`, user.project = `proj-alpha`); `09:12:43.876` →
   "…**stored successfully**" — **the gateway's credential call landed**, timestamped
   between the gateway's `upstream_callback` (09:12:42.008) and `signin_result`
   (09:12:43.880), exactly where the flow's credential leg belongs.
3. `09:12:45.266 → 09:12:47.03` and `09:13:36Z–09:14:16Z` — a run of `POST
   /v1/toolset/notion/mcp` calls, each "Connected to origin: mcp.notion.com:443" →
   "Received response header from origin: **status=200**" — **live tool calls after the
   credential was stored**. Nine `status=200` in the window and no 401 challenge: the
   post-consent success. (`09:13:37–38` carries three transient "Connection reset" → "No
   route" WARNs against the upstream, immediately followed by 200s again at `09:13:42` — a
   momentary upstream socket reset, not a credential failure; no 401 and no re-auth.)

### Harness-side reset — corroborated, and no `client_registered` is expected

The harness's config snapshots bracket the reset: the snapshot at `09:11:33Z` lists **no**
gateway server (no `localhost:8090` URL at all), and the snapshot at `09:12:48Z` lists the
gateway under the alias **`notion-gw`** at `http://localhost:8090/dial/notion/mcp`. So the
re-add landed in `(09:11:33, 09:12:48)` — the flow allocated at `09:12:18`, inside that
interval: consistent with the stated `remove`/re-add preceding the invoke.

`grep client_registered` over the **whole** container window still returns **0** — correct,
not a gap: `client_registered` is the DCR event, and a CIMD client resolves through
`gateway/cimd.py`, which emits no audit event; the first record a CIMD flow produces is
`flow_allocated`, and its `client_id` URL is byte-identical between a fresh and a cached
registration. So the **fresh-registration half** of (a)'s evidence rests on the owner's
observation of the reset (corroborated by the config snapshots above) plus the **chain
shape** — not on a `client_registered` record, which a CIMD client never produces.

### Row (a) — CLOSED

**Verdict: CLOSED.** Sequence complete and clean, this time with the credential leg:
`flow_allocated → (Keycloak → interstitial → consent, owner-observed) → upstream_callback →
signin_result(accepted) → code_issued → token_issued`, followed by live tool calls. The
distinguishing mark — `upstream_callback` + `signin_result(accepted)` **present** — is
exactly what field runs 2/3 could not show and what (a)'s cursor requires.

**Evidence basis and why the criterion's halves are jointly covered.** Criterion (a) asks for
a *first use, end to end, via CIMD*: the fresh harness registration on one side, the
gateway-observed fresh-consent flow on the other.

- **The fresh-consent path** was observed owner-side in **field run 1** (2026-10-19): the
  browser → Keycloak → interstitial → Notion consent → live data, end to end — but that run
  predates the audit trail, so its gateway half was unavailable.
- **This run (field run 4)** makes the credential leg *auditable*: the sign-out-FIRST recipe
  produced the full chain, with `upstream_callback` / `signin_result(accepted)` present in
  the live trail, and Core corroborating the credential stored at USER level followed by 200
  tool calls.
- **The fresh registration** is owner-observed here (the `remove`/re-add reset, bracketed by
  the harness config snapshots) and — because a CIMD client emits no `client_registered` —
  is read off the reset, not off the log; the runbook records that limit explicitly rather
  than implying a record exists.

Together the two runs cover both halves of the criterion: field run 1 observed the
fresh-consent path (owner-side, pre-trail); this run observed it *with the audit trail live*
and the credential leg recorded. **Row (a) — CLOSED**, on owner observation + gateway audit +
Core correlation.

## Scoreboard (after field run 4, 2026-10-20)

| # | Criterion | State | Evidence |
|---|-----------|-------|----------|
| (a) | First use, end to end, via CIMD | **CLOSED** | Field run 4: full chain with `upstream_callback` + `signin_result(accepted)` in the live trail; Core's signout→signin→200 correlation; fresh registration owner-observed. Fresh-consent path observed end to end in field run 1 (pre-trail). |
| (b) | Silent repeat use + refresh-on-401 with rotation | **OPEN — silent half evidenced, TTL-forced half owed** | Silent half: field run 2's `token_refreshed` (22:21:02Z) with live calls. TTL-forced rotation double-invoke still owed (set `GATEWAY_ACCESS_TOKEN_TTL_SECONDS=30`, rebuild+recreate, restart router, wait ~40 s, invoke TWICE — expect two `token_refreshed`). |
| (c) | Sign-out mid-session → the sign-in-again branch | **CLOSED** | Field run 2: full re-login chain, Core's signout+signin correlation, live calls. |
| (d) | Query strings survive the data path | **CLOSED** | Field run 1 / the logging-fix run: `scripts/probe_routing.py` battery, all 6 probes green, negative control first. |
| (e) | Direct-to-Core coexistence | **CLOSED** | Field run 1: `scripts/probe_gateway_trust.py`, Keycloak-issued control → Core `:8081` 200, negative control 401. |

**Remaining before archive: (b)'s TTL-forced rotation double-invoke** — the one still-unrun
half. On that run, expect a first transparent refresh (no browser) and a **second** one
proving the harness adopted the rotated refresh token, both as `token_refreshed` records;
restore the TTL to 600 and recreate afterwards. With (b) green the change's five rows are
all green and archive is unblocked.

## (b) CLOSED — the TTL-forced rotation double-invoke (field run 5, owner-driven, 2026-10-20)

With `GATEWAY_ACCESS_TOKEN_TTL_SECONDS=30` live (recreate; runtime env — no rebuild
needed) and the owner's harness invoking on the expired token:

- `10:06:45Z` **token_refreshed** — the transparent on-401 refresh, NO browser (the
  09:12 token, expired).
- `10:06:54Z` **token_refreshed** — 9 s later (either an early adoption or the
  grace-reuse; not decisive alone).
- `10:09:00Z` **token_refreshed** — 2m15s after the first rotation. DECISIVE: the
  rotation grace is 60 s (`GATEWAY_ROTATION_GRACE_SECONDS=60`, verified in the
  container), so the original's grace was long closed — this refresh necessarily
  presented a ROTATED refresh token. **The harness adopts rotated refresh tokens.**

Zero `flow_leg_failed`/`flow_refused` in the window; no browser at any point. TTL
restored to 600 and the deployment recreated healthy.

## Scoreboard — all five criteria CLOSED

(a) CLOSED (field run 4) · (b) CLOSED (runs 2/5) · (c) CLOSED (run 2) · (d) CLOSED
(probe capture) · (e) CLOSED (probe capture). The design's acceptance gate is PASSED.
