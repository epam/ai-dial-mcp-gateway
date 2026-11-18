# Security review round 1 — implementation fixes (F1–F5)

Diff base: `d91813b` (group 8 closed). Fixes the five IMPLEMENTATION findings of
`evidence/security-review-round-1.md`. Evidence captured redacted; no credential appears.

## F1 (MAJOR) — a slow outbound leg must not block the event loop

**Mechanism shipped: threadpool offload (`anyio.to_thread.run_sync`), not an
`httpx.AsyncClient` conversion.** The proven synchronous call chain stays byte-identical:
the CIMD fetch (with its SSRF connection pinning, `follow_redirects=False`,
`trust_env=False`, the content-decided read, the at-most-twice token rule), the Keycloak
exchange, the Core reads, and the credential call are unchanged as calls. Each is now
entered through `anyio.to_thread.run_sync`, so the blocking work happens on a worker thread
and the event loop keeps serving every other request.

Rationale recorded for the owner: the pinned-address transport is delicate and field-proven,
and the async conversion would rewrite every signature and the test wiring of the chain just
validated live. The offload shields that chain without touching it.

State mutation stays on the event loop: the CIMD cache's lookup-before and store-after the
fetch happen on the loop, so the map is shared without a lock and the fetch decision is
single. The blocking calls themselves are pure network waits and touch no shared state.

### Live proof — `/healthz` answers during a deliberately slowed outbound call

Probe: `scripts/probe_liveness.py` (new, committed). It measures a control (`/healthz` with
nothing in flight), then drives `/dial/authorize` with a client-id URL on a deliberately
slow origin so the gateway enters a held-open fetch, then issues `/healthz` while that fetch
is in flight.

Run against the composed stack, gateway recreated with the allowlist pointed at a slow
origin (`GATEWAY_CIMD_ALLOWED_ORIGINS=https://httpbin.org`, via a temporary compose
override that was removed afterwards):

```
control /healthz: samples=['0.1870s', '0.0000s', '0.0160s']
[PASS] control: worst=0.1870s
during the held-open leg: /healthz 200 in 0.0000s
[PASS] healthz answers during a slow outbound leg: status=200 duration=0.0000s budget=1.8700s
[INFO] the slow leg answered 400 in 8.55s (the fetch was held for ~5.0s)
VERDICT: PASS
```

`/healthz` answered in ~0 ms while the outbound fetch was held 8.55 s. A gateway that
fetched on the loop would have answered only after the origin gave up.

### Unit proof, with falsification

`tests/test_concurrency.py` (new): an ASGI transport on the same loop the app runs on, so a
request can observe whether the loop is free.

* `test_healthz_answers_while_a_metadata_fetch_is_held_open` — the probe's unit analogue,
  timed from the fetch's entry into the outbound call. **Falsified**: patching the async
  resolve back to a direct blocking fetch makes it fail at 2.02 s (the hold), as required.
* `test_a_held_open_metadata_fetch_still_completes` — the offload shields the loop without
  breaking the leg; the authorization request completes with the document's redirect URI.
* `test_the_metadata_fetch_runs_off_the_event_loop` — asserted on the thread identity
  itself. **Falsified**: the blocking patch fails it (`seen[0] == loop_thread`).

## F2 (MINOR) — the per-source limit binds to the actual peer

`gateway/errors.py`'s `client_source` now prefers the router's authoritative `X-Real-IP`
(`$remote_addr`), else the **last** `X-Forwarded-For` entry (the router appends the real
peer via `$proxy_add_x_forwarded_for`), else the socket peer. Reading the first XFF entry
let an attacker rotate a fake one per request and defeat the limit.

Tests (`tests/test_limits.py`): `test_the_client_source_prefers_the_routers_own_x_real_ip`,
`test_the_client_source_takes_the_last_forwarded_entry`,
`test_a_spoofed_first_entry_does_not_change_the_source` (five rotated first entries all
count as the same source).

## F3 (MINOR) — the unhandled-exception handler logs

`gateway/app.py`'s handler now logs the exception type and traceback to a new `gateway.app`
logger before returning the fixed-text page. Defining the handler suppresses Starlette's own
500 logging, so this is what stands in for it.

Test (`tests/test_app.py`): `test_an_unhandled_failure_is_logged_with_its_traceback` — an
exploding route produces a log record with the traceback, and the response is the fixed
text with the exception's message **not** reflected. **Falsified**: removing the logging
line fails it.

## F4 (MINOR) — the DCR registration body is bounded

`gateway/routes.py`: the body is read under a byte cap **while it is read** (a chunked read
that returns on the first byte past the cap), and per-record bounds cap the redirect-URI
count, each URI's length, and `client_name`'s length. Settings-configurable with safe
defaults in `gateway/settings.py` (`DCR_MAX_BODY_BYTES=8192`, `DCR_MAX_REDIRECT_URIS=16`,
`DCR_MAX_REDIRECT_URI_LENGTH=2048`, `DCR_MAX_CLIENT_NAME_LENGTH=256`), named in
`.env.example`, wired in `docker-compose.yml`, documented in `docs/gateway-configuration.md`.

Tests (`tests/test_store.py`): oversized body refused (and nothing persisted), a body at the
cap still accepted (so the oversized test cannot pass on an endpoint that refuses
everything), oversized `client_name` refused, too many redirect URIs refused, an oversized
redirect URI refused, and a small valid registration unaffected by the **default** bounds.

## F5 (MINOR) — the limiter runs on the remaining unauthenticated routes

`gateway/token.py`: `/dial/token` and `/dial/revoke` are limited before any work (the token
endpoint's validation costs RSA verifications, so the count closes the CPU-exhaustion path).
`gateway/federation.py`: both `/dial/callback/*` routes are limited, and a limited callback
renders the plain-language page with status 429 — **not** a redirect, so a browser mid-flow
is never sent to a URL carrying a refusal the harness never asked about. `gateway/status.py`:
`/dial/{name}/status` is limited before it reaches Core with the caller's token.

Tests (`tests/test_limits.py`): every unauthenticated route driven past the limit
(`test_the_unauthenticated_routes_are_all_bounded`), the token endpoint's 429 shape, a
limited callback carrying the page and no `Location`, and ordinary traffic below the limit
reaching each route's own logic rather than the limiter.

## Task 4.10 — pre-allocation refusals are audited (authoring pass had landed)

The spec requirement and task row landed in the working tree during this pass, so the ripple
was implemented. `gateway/audit.py`'s `flow_refused` gained the safe-fact parameters
(`client_id`, `redirect_uri`, `resource`, `toolset`), each recorded as its own JSON field —
never interpolated into text — so a caller value carrying a newline or a brace cannot become
a second line or a second record. Call sites: `/dial/authorize` (every validation branch and
its limiter 429), `/dial/token` and `/dial/revoke` validation failures, the
registration-resolution, `/dial/register` refusals and its limiter 429, the
`/dial/{name}/status` refusals, and the discovery 404s. The callback pages stay excluded
(their refusals answer for a flow already allocated, audited by that flow's events).

Tests (`tests/test_audit.py`): each refusal class writes exactly one record with the fixed
reason and the safe facts; a redirect-URI refusal names the client, the URI, and the
resource; the injection negative control (a hostile parameter with embedded newlines and
forged JSON) writes exactly one record with the gateway's own `event`/`reason` and the value
confined to its own field; a refused token request records the facts but not the code or
verifier it presented; and no credential material reaches any record.

## Gates

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 104 files already formatted |
| `mypy` (strict) | Success: no issues found in 37 source files |
| `pytest -q` | **363 passed, 1 skipped** (was 337 passing at baseline) |
| `bandit -r gateway` | No issues identified |
| `pip-audit` | No known vulnerabilities found |
| compose build + `--force-recreate` | gateway and router healthy |
| `/healthz` during a slowed outbound leg | PASS (above) |
| `probe_routing.py` | all 6 probes passed |
| `probe_gateway_trust.py` | green (JWKS kid match, unpublished signer refused, gateway-signed token resolves a real identity) |
| `probe_end_to_end.py` | green (full chain, 65 tools via `/dial/notion/mcp`) |

Note on the end-to-end run: an intermediate attempt returned 502 at the live tool call.
Core's own log showed `Can't connect to origin: The timeout ... to mcp.notion.com:443` —
Core resolved notion to IPv6 with no IPv6 route in its container. The gateway is not on the
data path (the router proxies `/dial/<name>/mcp` straight to Core), and a retry succeeded
(200, 65 tools), so this was a transient Core-container egress failure, not a gateway
regression.