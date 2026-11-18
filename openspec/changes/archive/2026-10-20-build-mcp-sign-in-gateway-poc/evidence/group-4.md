# Group 4 — the federation flow and the token lifecycle (Stage 2)

Tasks 4.1–4.7 of `build-mcp-sign-in-gateway-poc`. Records what was built, what was run to
verify it, and the defects the tests found. Every capture below is redacted at capture
time: no token, code, key, password, or client secret appears in this file.

## Verdict

**Group 4 complete.** The gateway now runs the whole sign-in: it redirects the browser to
the identity provider under its own PKCE client, exchanges the callback code over the
back channel and verifies the resulting identity token, enforces DIAL authorization before
any upstream round-trip, runs the attribution interstitial and the upstream consent,
consumes the callback's flow record before calling Core's credential API at USER level,
mints a signed code, and exchanges it for a gateway-signed access token and a rotating,
non-sliding refresh token — with local revocation and a queryable status. Gates: all
green (below).

## What each task landed

| Task | Deliverable | Where |
|---|---|---|
| 4.1 | The identity-provider leg: the redirect under the gateway's own PKCE pair (the verifier generated per flow and never leaving the record), the callback, the back-channel code exchange over the provider's internal base URL, the identity token verified against the provider's own published keys, and the token discarded at flow end | `gateway/idp.py` |
| 4.2 | The toolset-settings read as the flow's user, the 403 no-access branch that fails before any upstream round-trip, and the signed-in short-circuit | `gateway/core.py`, `gateway/flow.py` |
| 4.3 | The attribution interstitial, the upstream authorize redirect built from the toolset's public settings, the upstream callback with state round-trip and destroy-on-first-use, and the USER-level `POST /v1/ops/toolset/signin` call | `gateway/federation.py`, `gateway/flow.py` |
| 4.4 | Token minting with the whole-payload claim copy, the roles overlay with its loud absent-versus-empty distinction, `aud` = resource + marker; the refresh grant (resource match, rotation with grace, non-sliding expiry) and the revoke endpoint with its denylist | `gateway/tokens.py`, `gateway/token.py`, `gateway/state.py` |
| 4.5 | The status endpoint (`/dial/{name}/status`, Bearer gateway JWT, read as the token's user) | `gateway/status.py` |
| 4.6 | The per-flow audit events with no token, code, or key material | `gateway/audit.py`, `gateway/federation.py` |
| 4.7 | The configuration reference: the flow walkthrough, the two Core routes, the token TTLs, the claim copy, rotation and revocation, the status endpoint, the audit trail | `docs/gateway-configuration.md` |

## Test coverage, by task

`pytest -q`: **320 passed, 1 skipped**.

| File | Tests | Covers |
|---|---|---|
| `tests/test_federation.py` | 38 | The redirect's PKCE pair and its scope set; the exchange and its verification against the provider's keys (foreign key, foreign issuer, expired, provider refusal, provider fault); the identity token's use count and the identity bound; the 403 branch, the short-circuit, the settings projection's challenge-without-verifier, the authorization check running on every flow, the one-read path against a status-enriched settings route; **the interstitial's continuation asserted on the URL the browser navigates to** (derived the way a browser derives it, never on rendered attribute text — task 4.8), its escaping, and its mechanism (no form, no button); **the interstitial's web-hardening header family** (task 4.9); the upstream URL's every parameter; the conditional-`scope` case; the delivery guard's fail-closed branch and its empty-value reading; the state round-trip and its refused wrong-state; the exact `/signin` body; the replayed and unknown-flow callbacks; the flow's release; the audit trail's fields and its credential-free content |
| `tests/test_tokens.py` | 49 | The claim copy's preservation and its registry exclusions; the roles overlay at a configured name, over a colliding copied claim, at a nested path, and its refusals (absent, malformed); empty/null/single-valued/empty-string roles; the audience and the marker; the refresh's no-network property, its claim preservation, its resource match, rotation's default, its grace window and its expiry, the non-sliding window across a chain; revocation and the uniform answer; the status endpoint's five branches; the settings |
| `tests/test_audit.py` | 8 | The whole-story event sequence and its fields; the reply for a refused credential call; the credential scan over every value the run handled (harness code, identity token, upstream code, challenge, both keys, the PKCE verifier); the refusal text's fixed vocabulary; the dedicated logger and the one-line record shape |

## Defects found by the tests, and fixed

### D-5 — The identity token was presented to Core twice per flow

- **Symptom:** a completed flow made the settings read twice — once in the identity leg and
  again to build the upstream authorize URL. The flow's design says the token is used at
  most twice (settings + `/signin`), and the second settings read was a third use that the
  stale-grant-window rule exists to prevent.
- **Evidence:** a respx capture of the settings route on a two-flow run recorded four
  calls where two were expected, and the second call per flow carried the identity token
  again.
- **Root cause:** the leg that could resolve the short-circuit released the credential
  before the caller had built the upstream URL, so the caller re-read the settings with the
  token it had just been told to drop. The two reads were also on opposite sides of a
  module boundary that owned no state.
- **Fix:** the identity leg returns what it read — the settings and the status — as one
  result object, the redirect URI is carried on the flow record, and no later leg reads
  Core with the user's token. The short-circuit is decided on the status the leg already
  had, so the drop happens after the leg's last use rather than before it.
  `gateway/flow.py`, `gateway/federation.py`.

### D-6 — The flow's identity bound used a different clock from the flow's TTL

- **Symptom:** every upstream callback after the identity leg answered the expired-session
  page, and no flow ever completed.
- **Evidence:** the callback returned 400 with the plain-language page while
  `Flows.get(flow_id)` was called microseconds after the record was written. The record's
  field held a wall-clock instant (`time.time() + …`, about 1.79e9) compared against
  `time.monotonic()` (about 6e4 on this host), so the identity bound read as long past on
  every flow.
- **Root cause:** the flow's TTL runs on the monotonic clock and the identity token's
  `exp` arrives as a wall-clock instant; the new bound stored the wall-clock value and then
  compared it on the monotonic clock. Both comparisons were individually reasonable and the
  pair was not.
- **Fix:** the leg converts the token's `exp` to a *duration* and stores
  `min(flow.expires_at, time.monotonic() + duration)`, so both bounds live on the one clock
  the store compares against, and the comparison's clock is now stated where the field is
  declared. `gateway/flow.py`, `gateway/state.py`; pinned by
  `test_a_short_lived_identity_token_bounds_the_flow_below_its_own_ttl` and
  `test_an_expired_identity_bound_releases_the_flow_record`.

### D-7 — The flow's Core read was two routes even where one carries both

- **Symptom:** the flow made two Core calls on every sign-in, and the status call was
  issued unconditionally against a route the deployment might not need.
- **Evidence:** measured live against the instance: the settings route
  (`GET /v1/toolsets/platform/notion`) returns the stored settings with
  `user_level_auth_status` absent, while the listing route
  (`GET /openai/toolsets/notion`) returns the same fields plus both statuses — the Stage 0
  spike's finding 1, re-confirmed on this run. Core's own source at HEAD has since added
  the enrichment to the settings route (`PlatformAppToolsetApiTest`),
  so a build that returns it there needs no second call.
- **Root cause:** the read was written against one deployment's measured behavior only.
  The delta spec pins no route and the design's mi-2 row explicitly describes the split, so
  neither is wrong — but the flow had no path that used a single answer when one carries
  everything.
- **Fix:** the settings read keeps the statuses when its answer carries them, and the
  status route is asked only when it does not. The decision is made on what the first
  answer *contained*, never on an error — a refused read is a refusal, not a hint to ask
  elsewhere. `gateway/core.py`, `gateway/flow.py`; pinned by
  `test_the_flow_reads_core_once_when_the_settings_route_carries_the_status` and
  `test_the_flow_falls_back_to_the_status_route_when_the_settings_route_omits_it`.

### D-8 — A host-side identity-provider probe reached the wrong clock, not a wrong URL

- **Symptom:** the live probe of the built authorize URL answered
  `{"error":"Client not found."}` — correct, since group 6 provisions the client — but the
  **control** run with a client the realm does have failed to connect at all.
- **Evidence:** the control URL (`client_id=dial-cli`, otherwise identical) produced
  `URLError: [WinError 10061] connection refused` on `https://localhost:8443`, after the
  first probe had answered a real JSON body on the same host and port.
- **Root cause:** not a defect in the gateway. The first response redirected into
  Keycloak's own login pages, which are served on a port the Windows host does not map;
  the probe followed the redirect into that dead port. The gateway's URL was already
  confirmed by the first probe (a real Keycloak JSON error body, naming the client it could
  not find).
- **Fix:** none needed — recorded because the probe's *first* result is the evidence and
  the control's failure is an artifact of the probe's host-side redirect following, not of
  the URL the gateway builds.

## Task 4.8 — the interstitial's delivery fix (the defect `finding-empty-upstream-redirect.md` recorded)

**Mechanism chosen: the page continues itself.** A `<meta http-equiv="refresh">` navigation
to the gateway-built URL, with a plain anchor beside it as the fallback for a browser that
ignores a refresh. No form and no button, which is what the page's own docstring already
said it did ("the page continues itself … stopping there would turn an attribution notice
into a second consent"). It needs no scripting, so it adds no script policy to the page,
and it delivers the URL exactly as the gateway built it — the property a form submission
could not provide, because the submission *replaces* its action URL's query with the entry
list built from the form's successful controls.

**The delivery guard.** `upstream_authorization` now reads the **finished URL** — never the
mapping that built it — for `response_type`, `client_id`, `redirect_uri`, `code_challenge`,
`code_challenge_method` and `state`, plus `scope` where the toolset advertises scopes at
all (a toolset that advertises none is served correctly without the parameter, so demanding
it there would refuse a working configuration). A missing or empty parameter raises before
the page is served: the browser gets the plain-language error page (`502`) and the audit
trail records `flow_leg_failed` with `leg="upstream"`. This is the step *after* the
settings-read refusal, which already guards the incomplete-projection case before the URL
is built.

### Unit-tier verification

`pytest -q tests/test_federation.py`: **37 passed** (was 33; net +4 after the attribute-level
helper was removed).

| Test | What it pins |
|---|---|
| `test_the_upstream_url_is_built_from_cores_public_settings` | Now derives the **navigation target** the way a browser does (parse the document, entity-decode the attribute, act on the result) and asserts every parameter on *that* URL. The old `_upstream_url_of` — which lifted `action="…"` out of the page text — is deleted: that assertion class is exactly what stayed green through this defect |
| `test_the_interstitial_delivers_its_request_by_navigating_not_by_submitting` | The mechanism itself: no `<form>`, no `<button>`, the content/attribution text kept, and the refresh target agrees with the anchor fallback (so neither can drift into a second version of the request) |
| `test_a_toolset_without_advertised_scopes_is_delivered_without_a_scope_parameter` | The conditional-`scope` case (L1): a toolset advertising none is delivered, and the rest of the request is still complete |
| `test_an_incomplete_upstream_request_fails_closed_before_the_page_is_served` | The fail-closed branch end to end: a projection Core accepts (present-but-empty `code_challenge_method`) yields `502`, an error page naming the parameter, and **no** upstream endpoint or meta refresh anywhere in the response |
| `test_a_present_but_empty_parameter_counts_as_undeliverable` | The guard's own reading, against the built URL: empty counts as absent, an absent parameter is named, and `scope` is required only where advertised |

### Live verification — the URL the browser actually navigates to

The stack was rebuilt and recreated with the fix (`docker compose build
mcp-signin-gateway` → `up`), then the router restarted (after a gateway-only recreate the
router needs one — the recorded operational fact). The signed-out flow was driven from
`/dial/authorize` through the Keycloak leg to the gateway's callback, with the test user's
credential (`.env`), and the served page captured — the user's stored upstream credential
was **not** re-established and no upstream consent was attempted.

The served interstitial (redacted: `state` is real; nothing else here is secret — the
`client_id` and `code_challenge` are Core's public projection of the toolset's
registration, which the finding record already prints):

```html
<head>
<meta http-equiv="refresh" content="1; url=https://mcp.notion.com/authorize?response_type=code&amp;client_id=Ohk3BbaVnj3lemIy&amp;redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fcallback&amp;code_challenge=mNP5WzNVunZyuJG9r0Lb9KuTzs51FhhBRoGi0yCyWM8&amp;code_challenge_method=S256&amp;state=aUbKiU…&amp;scope=default">
<title>Continue to notion</title>
…
<p>Continuing to the approval page&hellip; If nothing happens,
<a href="https://mcp.notion.com/authorize?…">continue to notion</a>.</p>
```

`<form` present: **False**. `<button` present: **False**.

That captured page was then served from a local origin and driven in headless Chrome over
CDP — the method `finding-empty-upstream-redirect.md` documents — measuring the
**navigation target** the page produces, with requests to the upstream intercepted so
nothing reached Notion:

```
=== the fixed page, driven as a user's browser would ===
  navigation target: https://mcp.notion.com/authorize?response_type=code&client_id=Ohk3BbaVnj3lemIy&redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fcallback&code_challenge=mNP5WzNVunZyuJG9r0Lb9KuTzs51FhhBRoGi0yCyWM8&code_challenge_method=S256&state=aUbKiU…&scope=default

=== negative control: the pre-fix page (form, no controls) ===
  navigation target: http://127.0.0.1:8899/upstream?

=== verdict ===
  fixed page carries: response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope
  missing:            <none>
  control (pre-fix):  query ""   (empty — the parameter list was dropped)
```

The negative control is the pre-fix template verbatim (a `method="get"` form with a
parameter-bearing action and no successful controls), driven identically: it lands on a
bare `?`, reproducing the field symptom byte for byte. So the instrument can distinguish,
and the all-parameters result above is not an artifact of a probe that reports green
whatever it is handed.

**Not done here, deliberately:** completing the upstream consent. The test user's stored
credential stays absent (the finding record's state), so re-consenting is the owner's
one-time browser action after this fix — and the flow's own continuation is what this task
had to fix. Re-read after the run, `GET /openai/toolsets/notion` as the test user:

```
  negative control (no token): 401
  authenticated read:          200
  user_level_auth_status       SIGNED_OUT
  global_auth_status           SIGNED_OUT
```

The negative control runs first, so the `200` above means the read resolved the user's own
credential state rather than answering an unauthenticated request. `SIGNED_OUT` is the
state this pass inherited and left unchanged: no consent was given here, and the flow now
takes a re-consenting user to the upstream with a complete request.

### Gates after the pass

Run from `.venv/Scripts` with `PYTHONUTF8=1`.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 98 files already formatted |
| `mypy` (strict) | Success: no issues found in 35 source files |
| `pytest -q` | 332 passed, 1 skipped |
| `bandit -c pyproject.toml -r gateway` | No issues identified |
| `pip-audit` | No known vulnerabilities found |
| Compose rebuild + recreate | `mcp-signin-gateway` up and healthy; `mcp-signin-router` up and healthy after its restart |

**Host note, unchanged from group 8's observation:** Windows→WSL `localhost` forwarding is
still down on this host (`curl http://localhost:8090/healthz` refuses from Windows while
`wsl -e curl … http://localhost:8090/healthz` answers `200`, and the WSL address answers
from Windows). The live probe above therefore ran **from inside WSL**. This is a host
condition, not a stack fault: both services report healthy throughout.

Nothing was committed.

## Task 4.9 — the web-hardening header family on the HTML pages

**Where it lives.** `gateway/pages.py` owns the family and the single construction path
(`html_page`); the interstitial's response (`gateway/federation.py`, the `HTMLResponse`
built for `interstitial_page`) and all three plain-language pages
(`gateway/errors.py`'s `flow_expired_page`, `gateway_error_page`, `no_access_page`) go
through it. The JSON and redirect error responses keep `_NO_STORE`, unchanged. The inline
style is satisfied **by hash** over the shared `PAGE_STYLE` constant, whose text both
templates substitute, so the served `<style>` element is byte-for-byte the string the CSP
hashes.

**The stale rows this pass corrects (the standing note 4.8 left).**

- `tests/test_federation.py`: **37 → 38**. The added test is
  `test_the_interstitial_carries_the_web_hardening_headers`; the coverage phrase gained
  "the interstitial's web-hardening header family (task 4.9)".
- The **error-page** assertions do not live under `tests/test_federation.py` at all —
  they are in `tests/test_limits.py` (`test_an_error_page_is_plain_language` and the new
  `test_every_error_page_carries_the_web_hardening_headers`), whose coverage row is in
  `evidence/group-3.md`. That row's count is stale too on the same change and is corrected
  there (23 → 24); the 4.9 note named `group-4.md` for both classes, and this is where the
  error-page half actually landed.

**Gates after the pass** (run from `.venv/Scripts` with `PYTHONUTF8=1`): `ruff check` and
`ruff format --check` clean; `mypy` strict clean over 36 source files; `pytest -q`
**337 passed, 1 skipped**; `bandit` no issues; `pip-audit` no known vulnerabilities;
`docker compose config` parses; both composed services healthy after the gateway rebuild
and the router restart.

## Live probes

The gateway was not run as a container in this group (the compose-boot gate is group 7's),
but two facts were measured against the live instance rather than assumed:

**The identity-provider URL shape.** Built by the real `IdentityProviderClient` from a
gateway-shaped settings object and fetched from the host:

```
https://keycloak:8443/realms/dial/protocol/openid-connect/auth
  ?response_type=code
  &client_id=dial-mcp-proxy
  &redirect_uri=http%3A%2F%2Flocalhost%3A8090%2Fdial%2Fcallback%2Fkeycloak
  &scope=profile+email
  &state=<flow id>
  &code_challenge=<S256 challenge>
  &code_challenge_method=S256
```

→ 400 `{"error":"Client not found."}` — a real Keycloak answer naming the client group 6
has not yet provisioned. `scope` is `profile+email` and carries neither `openid` nor
`offline_access`; the verifier is absent from the URL by construction.

**A live gateway process**, run on `GATEWAY_PUBLIC_ORIGIN=http://localhost:8099` with a
generated key and one mapped toolset, exercised the new surface over a real socket:

| Probe | Result |
|---|---|
| `GET /healthz` | 200 `{"status":"ok"}` |
| `GET /.well-known/oauth-authorization-server` | 200, `revocation_endpoint` = `http://localhost:8099/dial/revoke` |
| `GET /dial/jwks.json` | 200, one key |
| `GET /dial/authorize` (pre-registered client, PKCE S256, resource, `state`, and `scope=openid profile`) | **302** to `https://keycloak:8443/realms/dial/protocol/openid-connect/auth` with `response_type=code`, `client_id=dial-mcp-proxy`, `redirect_uri=http://localhost:8099/dial/callback/keycloak`, **`scope=profile email`**, `state=<the flow id>`, `code_challenge=<S256>`, `code_challenge_method=S256` — and **no verifier and no `openid`** |
| `GET /dial/callback/upstream?state=nope&code=x` | 400 with the plain-language expired-session page |
| `GET /dial/notion/status` (no token / a non-token) | 401 both times |
| `GET /dial/revoke` | 405 (POST-only) |

The authorize probe is the whole client-facing→provider handoff in one measurement: the
request's `scope=openid profile` did not reach the redirect, the scope set is exactly the
client's configured defaults, the state is the flow id, and the browser carries a challenge
with no verifier anywhere in the URL.

**Core's two routes.** Measured with the test user's own token:

| Route | `user_level_auth_status` | `global_auth_status` | `code_challenge` | `code_verifier` |
|---|---|---|---|---|
| `GET /v1/toolsets/platform/notion` | absent | absent | present | absent |
| `GET /openai/toolsets/notion` | `SIGNED_IN` | `SIGNED_OUT` | present | absent |

This is finding D-7's measurement, and the reason the flow reads the settings route
authoritatively and falls back to the listing route only for the statuses.

## Gates

Run from `.venv/Scripts` with `PYTHONUTF8=1`.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 81 files already formatted |
| `mypy` (strict) | Success: no issues found in 35 source files |
| `pytest -q` | 320 passed, 1 skipped |
| `bandit -c pyproject.toml -r gateway` | No issues identified (7 B105 findings triaged in place) |
| `pip-audit` | No known vulnerabilities found |
| `wsl -e docker build` | Image built (`dial-mcp-gateway:group4`) |

The skipped test is the same Windows one group 3 recorded: POSIX permission bits are not
implemented there, so the store's owner-only mode is asserted in the container where it is
enforced.

Bandit's findings are all B105 on values that are token and grant *type names*, not
credentials (`_ACCESS_TOKEN_TYPE`, `_REFRESH_TOKEN_TYPE`, `CODE_TOKEN_TYPE`,
`_REFRESH_TOKEN_GRANT`, the RFC 7591 `token_endpoint_auth_method: "none"`, and the
identity provider's `/protocol/openid-connect/token` path segment). Each carries a
`# nosec` with a comment stating what the value is, rather than a configuration silence.

## The security invariants, as test-pinned properties

Each is a test that fails if the property is broken, not a documented hope:

| Invariant | Where it is pinned |
|---|---|
| The upstream credential never reaches the gateway | The gateway never calls upstream's token endpoint; the flow's only upstream contact is the browser redirect, and Core's `/signin` receives the code — asserted by the `/signin` body test and by the absence of any upstream token endpoint in the flow |
| The PKCE verifier never crosses a boundary | The provider leg's verifier is generated per flow, stored only on the record, and asserted absent from the redirect; the upstream leg carries Core's published challenge and asserted never Core's verifier |
| Per-user credential isolation | The `/signin` body is USER level and the settings read carries the user's own token — both asserted on the captured request |
| No credential in logs, argv, or errors | `test_no_credential_material_reaches_any_record` and `test_the_verifier_is_never_written` scan the rendered output for every credential the run handled |
| The identity token is used at most twice | One leg owns both Core calls; the short-circuit drops the token after the leg's last use, and the flow's release is asserted |
| The upstream code is single-use | `test_a_replayed_upstream_callback_is_refused` and `test_an_unknown_flow_id_at_the_upstream_callback_injects_nothing` |

## Deliberate limits of this group

- **No container was run** for this group's verification: the compose-boot gate is group
  7's, and this group's own claims are unit- and probe-verified. The image build was run
  because a new module's import wiring is exactly what a build catches and a unit suite
  does not.
- **The live end-to-end sign-in was not run**: the gateway's Keycloak client does not
  exist yet (group 6 provisions it), so the browser leg cannot complete against the real
  realm. Every leg is respx-verified and the two environment facts it depends on are
  measured live (above); the composed run is groups 7–9.
- **`/dial/{name}/status` is the only data-path-adjacent endpoint landed here.** The front
  router and the 401 rewrite are group 5's, so nothing yet feeds the status endpoint a
  token obtained through the front door.

## Carry-forward for the deployment-configuration group

This group added three settings — `KEYCLOAK_CLIENT_SCOPES`, `ROLES_CLAIM_NAME`, and
`GATEWAY_OUTBOUND_TIMEOUT_SECONDS` — to the model and to `.env.example`, but not to this
repository's `docker-compose.yml`, whose `environment:` block names settings one by one
(group 2's shape; group 6 finalizes it). No gate fails from the omission: each new setting's
model default is the value the local deployment wants (`profile,email`, `roles`, `30`), so
the composed stack behaves identically with or without the entries. The gap is operator
reachability only — with the entries absent, an operator cannot set these three through
compose — and it belongs to the task that completes the deployment's configuration surface.
A test pins the `.env.example` side of the same contract
(`test_every_settings_field_is_named_in_the_example`), which is what caught nothing here
because the example was updated.
