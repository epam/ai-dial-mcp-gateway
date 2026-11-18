# Tasks

## 1. Stage 0 spike — Core trusts a gateway-minted JWT (falsification stop)

- [x] 1.1 Write the offline JWT-minting probe (`scripts/spike_mint_jwt.py`): generate an
  RS256 keypair at runtime into a gitignored path (`.gitignore` already blocks
  `*.pem`/`*.key`/`*.jwt`), mint a JWT with `iss=http://localhost:8090`, the `sub` of a
  real realm user, plus `roles`, `project`, `email` matching the live Core entry paths,
  and `aud` containing `dial-mcp-proxy`; serve the matching JWKS. Verify by running it
  with `PYTHONUTF8=1`, decoding the token, and confirming `git status` shows no key or
  token artifact staged.
- [x] 1.2 Make the spike JWKS reachable from Core (serve it from a one-shot container
  on the instance's compose network). Verify by fetching the JWKS URL from inside the
  Core container (`wsl -e docker exec core …`) and seeing the published `kid`.
- [x] 1.3 Add the spike Core env vars on the sibling instance (`docker-compose.yml`,
  Core `environment`): a `dial-mcp-proxy` provider entry (`jwksUrl`, `issuerPattern
  ^http://localhost:8090$`, `rolePath: roles`, `audience: dial-mcp-proxy`, `loggingKey:
  email`, `loggingSalt: loggingSalt`) **and `issuerPattern:
  ^https://keycloak:8443/realms/dial$` on the existing keycloak entry**. Apply with
  `wsl -e docker compose up -d --force-recreate core` (run in the instance folder).
  Verify: core reaches healthy state and an existing Keycloak login still resolves
  (regression control).
- [x] 1.4 Run the negative controls FIRST, and capture redacted evidence into
  `evidence/` (redact at capture time — the `.gitignore` blocks `*.jwt`/`*.pem`/`*.key`
  and unredacted captures silently fail to commit): (a) a token with a mismatched
  issuer is rejected 401; (b) a correctly-signed token without the `dial-mcp-proxy`
  audience marker is rejected 401; (c) a token signed by an unpublished key (unknown
  `kid`) is rejected 401. Verify all three probes fail as expected before trusting the
  probe at all.
- [x] 1.5 Establish the spike's first precondition from committed material: write
  `scripts/spike_register_toolset.py` implementing the documented registration recipe
  and run it — `PUT /v1/toolsets/platform/notion` (admin-gated in Core: 403 unless
  authorized; locally the test user's `admin` client role reaches the token's `roles`
  through the chat client's client-roles mapper) with the body limited to
  `display_name`, `endpoint` (`https://mcp.notion.com/mcp`), `transport: HTTP`, and
  `auth_settings` (`authentication_type: OAUTH`, `redirect_uri` set to the loopback
  callback already allowlisted in Core's `allowedRedirectUris`; no other
  `auth_settings` field — the validator forbids them in dynamic-registration mode).
  Any machine credential the helper uses — the admin-authorized login, and any client
  credential its token request needs — comes from `.env` (gitignored) with
  `.env.example` placeholders (`TEST_USER_NAME`/`TEST_USER_PASSWORD` are already
  present), never hardcoded, mirroring 6.2's `.env` pattern. Verify by reading the
  toolset's public settings back and seeing `client_id`, `authorization_endpoint`,
  `code_challenge`, `code_challenge_method`, `scopes_supported`,
  `dynamically_registered`, and no verifier and no client secret; capture redacted
  evidence in `evidence/` and confirm no credential material is printed or committed.
- [x] 1.6 Establish the spike's second precondition from committed material: write
  `scripts/spike_establish_credential.py` implementing the documented sign-in recipe
  and run it — resolve the real realm user's DIAL token (a fresh identity-provider
  flow; the identity is client-independent), build the upstream authorize URL from the
  toolset's public settings, catch the allowlisted loopback callback, and call
  `POST /v1/ops/toolset/signin` with the user's identity token and the body
  `{url, credentialsLevel: USER, authenticationType: OAUTH, code, redirectUri}` — one
  browser consent. Where the helper drives the test user's login itself (rather than
  the human typing it in the browser), that machine credential — like any other the
  helper uses — comes from `.env` (gitignored) with `.env.example` placeholders
  (`TEST_USER_NAME`/`TEST_USER_PASSWORD` are already present), never hardcoded,
  mirroring 6.2's `.env` pattern. Verify the toolset's auth status read as that user
  reports `user_level_auth_status: SIGNED_IN`; capture redacted evidence in `evidence/`
  and confirm no credential material is printed or committed.
- [x] 1.7 Run the positive control: with the gateway-minted JWT, `GET /v1/user/info`
  resolves the real user identity (`sub`, roles), and a toolset MCP call as that user
  — against the toolset registered in 1.5, with the upstream credential established
  in 1.6 — resolves that user's credential; probe with `tools/list` on the MCP path
  (the admin tools-listing endpoint 403s for ordinary users and reads as a false
  failure). Verify both succeed; capture redacted evidence in `evidence/`.
- [x] 1.8 FALSIFICATION STOP: if the positive control fails — Core refuses the
  gateway-minted JWT for any reason not covered by a negative control — HALT. Record
  the failure in `evidence/spike.md`, do NOT proceed to group 2, and reopen the design
  (the "gateway as an additional identity provider" premise is falsified and must be
  revised; this is not a defect to iterate around). Verify by writing the explicit
  verdict line in `evidence/spike.md`: "spike passed — proceed" or "halt — design
  revision opened".
- [x] 1.9 Record the spike outcome as the group's documentation: `evidence/spike.md`
  with the three negative controls, the positive control, the preconditions
  established in 1.5/1.6 (naming the committed helper scripts that established them),
  the env diff applied, and the verdict. Verify the file contains no token, code, or
  key material.

## 2. Repository scaffolding and toolchain

- [x] 2.1 Create `pyproject.toml`: Python 3.12, FastAPI + uvicorn, `pyjwt[crypto]`,
  httpx, pydantic-settings; dev extras pytest + respx; ruff (check + format), mypy,
  bandit, pip-audit configuration. Verify by creating `.venv`
  (`python -m venv .venv`), installing, and running `ruff check` green on the empty
  package.
- [x] 2.2 Create the `gateway/` package skeleton (settings model, application factory,
  `/healthz` endpoint) and the `.env.example` additions it reads
  (`GATEWAY_INTERNAL_PORT`, `DIAL_CORE_BASE_URL`, `KEYCLOAK_ISSUER`,
  `KEYCLOAK_INTERNAL_BASE_URL`, `DIAL_COMPOSE_NETWORK`, `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS`
  (the staleness bound's operator input, validated at startup against the refresh
  TTL), the DCR settings (`DCR_ENABLED` default off, `DCR_STORE_PATH`,
  `DCR_MAX_REGISTRATIONS`), gateway token/limit settings as placeholders — no real
  values). Verify the app imports and `/healthz` answers 200
  in a local run.
- [x] 2.3 Create `Dockerfile` (`python:3.12-slim`, non-root user) and
  `docker-compose.yml` with services `mcp-signin-gateway` (internal :8091, healthcheck
  on `/healthz`, a bind-mounted volume holding the DCR registration store file at its
  configured path — the one gateway state that must survive recreation) and
  `mcp-signin-router` (host :8090), joined to the instance network
  as external (`${DIAL_COMPOSE_NETWORK:-dial-instance_default}`). Verify with
  `wsl -e docker compose config` and an image build.
- [x] 2.4 Verify the scaffolding group's own gates: `ruff check`,
  `ruff format --check`, `mypy`, `pytest -q` (collects and passes with the skeleton's
  health test) all green.
- [x] 2.5 Land the group's docs: the repo `README.md` development section — venv
  creation (`.venv`, tooling from `.venv/Scripts`), the static gate commands, and the
  `.env`-from-`.env.example` step (`.env.example` is this group's configuration
  deliverable, documented here rather than only shipped). Verify the documented
  commands run as written.

## 3. Gateway skeleton — discovery, registration, AS surface (Stage 1)

- [x] 3.1 Implement settings loading and startup validation: OAUTH-only mapping,
  reserved toolset names, required roles source path (no
  default), required `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` with the startup refusal
  when the refresh TTL exceeds it (the gateway must never be staler than vanilla),
  CIMD allowed origins, rate limits, flow caps, external origin. Verify with unit
  tests covering each startup refusal (non-OAuth entry, reserved name, missing roles
  source path, refresh TTL exceeding the IdP lifespan) and each acceptance.
- [x] 3.2 Implement the signing-key loading (RSA-256, `kid` header) and the JWKS
  endpoint; the key is injected material, never logged. Verify with unit tests
  (correct JWKS shape, `kid` present) and a test asserting no key material appears in
  captured logs.
- [x] 3.3 Implement E1 (per-toolset protected-resource document with the
  authentication-kind extension, carrying the toolset's upstream `scopes_supported`
  verbatim) and E2 (flat host-root AS metadata: single path-less issuer, both grants,
  S256, auth method `none`, CIMD support flag, no scopes of its own — gateway scopes
  do not exist, and advertised scopes are echoed back by clients — and no
  registration endpoint while DCR is off, it appears only while enabled). Verify with
  unit tests asserting the exact document shapes, the shared endpoints, and 404 for
  unmapped names.
- [x] 3.4 Implement CIMD resolution: fetch the client-id URL's document under the
  SSRF control set (HTTPS only, allowlisted origins, no redirects, private/loopback/
  link-local refusal with connection pinning, 64 KiB cap, timeouts, TTL cache, an
  explicit non-default User-Agent — the document origin's bot protection rejects
  library-default agents) and validate `redirect_uri` against the fetched
  `redirect_uris`. Verify with respx unit tests including every negative (http URL,
  non-allowlisted origin, redirect, private-range resolution, oversize body) and the
  positive registration flow with no `/register` call, plus a test asserting the
  fetch carries the explicit User-Agent.
- [x] 3.5 Implement the `/dial/authorize` entry (client id, redirect URI, strict
  `resource` with `invalid_target` and the one-toolset inference flag, PKCE S256
  required, the client's `scope` parameter accepted and dropped — never relayed to the
  identity provider — flow record keyed by a 128-bit CSPRNG id with TTL) and the
  config-gated DCR endpoint (default off → 404, the documented disabled-error, and no
  registration endpoint advertised in the AS metadata while off; while on, accepted
  registrations are persisted through the durable store of 3.6 before the response is
  returned, and `redirect_uri` on later authorization requests is validated against
  the stored record). Verify with unit tests for each validation branch, the scope
  drop, the DCR-disabled branch (404), and flow-record allocation.
- [x] 3.6 Implement the DCR registration record store: one JSON file at the configured
  path (default `/data/dcr-registrations.json` in a mounted volume), loaded at
  startup, write-through on registration, saved atomically (temporary file in the
  same directory + rename, owner-only file mode — a crash can leave a temporary file,
  never a half-written store), records limited to `client_id`, `redirect_uris`,
  `client_name`, `created_at` (no secret ever stored); an unreadable or corrupt
  store refuses startup with an operator-facing error naming the path; a configured
  registration cap refuses new registrations with a plain-language error while
  leaving existing registrations untouched; no registration expiry. Verify with
  unit tests: persist a registration → a fresh app instance over the same file
  resolves the client with no re-registration; corrupt file → startup refusal
  naming the path; cap reached → refusal with existing records untouched; a save
  leaves no temporary file behind; a lost store self-heals — after a registration,
  delete the store file and load a fresh app instance over the missing store (missing
  is not corrupt — it starts empty), see the cached client id rejected as
  unregistered on its next authorization request, then re-register through the
  endpoint and see acceptance restored (the lost-store self-heal scenario).
- [x] 3.7 Implement `/dial/token`'s authorization-code grant against a stubbed flow
  outcome: PKCE verification, single-use code (jti replay cache), short code TTL, and
  RFC 9207 `iss` in the authorization response. Verify with unit tests covering the
  happy path, wrong verifier, replayed code, and expired code.
- [x] 3.8 Implement the rate limits (per source, global) and the live-flow cap with
  oldest-first eviction, plus the plain-language HTML error page for unknown/expired
  flows on the callback endpoints. Verify with unit tests driving requests past the
  limits and cap.
- [x] 3.9 Land the group's docs: the gateway configuration reference (settings, env
  placeholders, startup refusals — including the DCR store settings: the volume mount,
  the corruption startup refusal with its rename-aside recovery, the registration cap,
  and the plain-language loss semantics for harnesses holding cached client ids) in
  `docs/`. Verify the documented example values run
  as written.
- [x] 3.10 Remove the `route_only` escape from the mapping, so a non-OAuth entry
  refuses startup unconditionally (the design decision recorded in
  `evidence/group-5.md`): delete the `route_only` field, `Settings.is_route_only`, and
  the escape branch in the mapping validator (its refusal message no longer suggests
  marking the entry route-only); update the tests (the route-only acceptance test
  becomes a refusal test, with and without the field set), the `.env.example`
  comment, and the `README.md` startup-check sentence to match. Verify the unit
  tests cover a non-OAuth entry refusing startup with and without `route_only` set,
  and `pytest -q` is green.
- [x] 3.11 Fix the redirect-URI matcher for loopback registrations: in
  `gateway/cimd.py`, a registered entry that is a loopback redirect URI (`http`
  scheme; host `localhost`, `127.0.0.1`, or `[::1]`) matches a request URI with
  identical scheme, host, and path, the port ignored on both sides — a registered
  explicit-port entry, a default port included, matches a port-varied request too
  (a native client binds an ephemeral port per launch and cannot pre-register it);
  only the port is excepted, so any query or fragment presence or difference is
  non-matching; every other registered entry keeps exact string equality; the
  exception is keyed on the registered entry, never on the request's value — a
  request cannot self-declare loopback. Split `test_redirect_uri_matching_is_exact`:
  the test's registration is itself a loopback entry with an explicit port
  (`http://127.0.0.1:8766/callback`), so its path, case, and trailing-slash
  rejections run against the loopback registration and stay in the loopback half;
  the assert that inverts is the port-only loopback difference —
  `http://127.0.0.1:8767/callback` against the registered `:8766` — which flips to
  accepted. The non-loopback half is new, against a non-loopback registration:
  exact string equality accepted, any port difference rejected, and a
  foreign-host rejection the current test lacks, added. Verify with `pytest -q`
  green and unit coverage of every branch (a port-less loopback entry accepting
  an ephemeral port; an explicit-port loopback entry accepting a port-varied
  request, the live fixture's shape; a loopback entry rejecting scheme/host/path
  differences; a non-loopback entry rejecting any port difference; a
  request-shaped loopback URI earning no exception against a non-loopback
  registration), then re-run the authorize probe battery
  against the composed stack — negative control first (the
  `not-registered-anywhere` URI still rejected), the port-varied loopback field
  value now accepted, a non-loopback URI on a varied port still rejected —
  capturing the re-test evidence in `evidence/`; the new evidence row also corrects
  the stale "exact `redirect_uri` matching" criterion in `evidence/group-3.md`'s
  test-summary table (the `tests/test_cimd.py` row).
- [x] 3.12 Make the DCR store's owner-only file mode best-effort per D11: in
  `gateway/store.py`'s `_save()`, the pre-rename `temporary.chmod(0o600)` becomes
  tolerant on its own — an `OSError` from it (a Windows host path bind-mounted into
  the container reaches the store's volume as 9p/DrvFs, where `chmod` raises
  `EPERM`) is logged as a warning naming the store path and the rename proceeds, so
  a registration is never refused for the mode; the write path's own `OSError`
  handling (mkstemp/write/fsync/replace) is unchanged — those failures still refuse
  the registration and leave no temporary file behind. Update the store's unit tests
  to state the tolerance explicitly (a refused mode change proceeds with a logged
  warning naming the path; the saved file holds the registration; no error
  propagates), and align the two texts that state the mode as unconditional: the
  `docker-compose.yml` store-volume comment (the save attempts owner-only mode,
  best-effort) and the DCR section of the gateway configuration reference in
  `docs/` (the mode is enforced only where the volume's filesystem enforces POSIX
  modes; where it does not, the gateway logs a warning naming the path and the
  host/volume owner's boundary carries the exposure). Verify with `pytest -q`
  green, then close the composed-stack gap the defect passed through: with
  `DCR_ENABLED=true` on the committed compose (the `./data:/data` bind mount as
  this host mounts it), re-run the 8.2 registration checks against the composed
  stack — an accepted registration persists (the store file gains exactly one
  record, no temporary file left behind, no secret material), the flat AS metadata
  advertises the registration endpoint, the gateway log carries the mode warning
  naming the path — and re-run the restart-persistence check (8.4's shape) over
  the same mount; capture redacted evidence in `evidence/dcr.md` and record the
  outcome against 8.2's defect note there.

  **Landed:** `_save()`'s `chmod` is wrapped in its own `try/except OSError`, logging a
  warning that names the store path and nothing else, then proceeding with the rename;
  the write path's outer `OSError` handling is unchanged. Three tests in
  `tests/test_store.py` state the tolerance (a refused mode proceeds and persists; a
  refused mode leaves existing records unchanged; a refused rename still refuses). The
  compose comment and the docs' DCR section are aligned. The composed-stack re-run is
  green on the committed bind mount with no override: `201` with a client id, the mode
  warning naming `/data/dcr-registrations.json` in the gateway log, one record in the
  store, no temporary file, no secret material, and the restart-persistence check
  accepted on the same client id with the store file's hash unchanged. `evidence/dcr.md`
  carries the captures; `evidence/finding-dcr-store-mount-chmod.md` records the closure.
  One deployment fact from the run is worth carrying forward: `--force-recreate` builds
  no image, so the first attempt re-ran the pre-fix image and reproduced the original
  failure until `docker compose build` ran first.

## 4. Federation flow and token lifecycle (Stage 2)

- [x] 4.1 Implement the identity-provider leg: redirect to the provider's authorize
  endpoint under the gateway's public PKCE client (no `offline_access`, requesting
  only the client's configured default scopes — a relayed client `scope` can fail the
  whole leg on scopes the client does not carry), the provider callback, and the code
  exchange over the provider's internal base URL; discard the provider's tokens at
  flow end. Verify with respx unit tests asserting the redirect shape (its scope set
  is exactly the client's defaults, with the request's `scope` parameter absent from
  the redirect), the exchange, and that no provider token persists after the flow.
- [x] 4.2 Implement the toolset-settings fetch as the flow's user
  (`GET /v1/toolsets/platform/notion`): the no-access branch fails with a clear page
  before any upstream round-trip, and a signed-in status short-circuits to code
  issuance. Verify with respx unit tests for the 403 branch, the signed-in
  short-circuit, and the settings-projection fields used (challenge present, verifier
  absent).
- [x] 4.3 Implement the upstream leg: the attribution interstitial, the upstream
  authorize redirect built from the toolset's public settings, the upstream callback
  with state round-trip and destroy-on-first-use, and the
  `POST /v1/ops/toolset/signin` call at USER level with the user's identity token and
  the callback URI. Verify with respx unit tests including the replayed/unknown flow
  callback and the exact `/signin` body.
- [x] 4.4 Implement token minting with the claim copy: whole-payload copy minus the
  gateway-owned registry claims, roles re-emitted from the configured source path,
  loud refusal when the path is absent, empty-value pass-through, `aud` = resource +
  marker; and the refresh/revoke grants: resource match, rotation default-on with
  grace, non-sliding absolute expiry, denylist, and the `/dial/revoke` endpoint.
  Verify with unit tests covering each normative scenario of the claim-copy, token,
  and refresh requirements (including the non-sliding expiry and the roles-path
  refusal).
- [x] 4.5 Implement the status endpoint (public auth statuses as the token's user).
  Verify with respx unit tests for signed-in and not-signed-in.
- [x] 4.6 Implement the per-flow audit events (flow id, subject, client id, toolset,
  timestamps, `/signin` result) with no token, code, or key material. Verify with a
  unit test asserting the audit record fields and scanning rendered output for secret
  material.
- [x] 4.7 Land the group's docs: extend the gateway configuration reference with the
  flow, token TTLs, and audit settings. Verify `pytest -q` is green for the whole
  package and the documented TTL names match the settings model.
- [x] 4.8 Fix the interstitial's continuation so the upstream authorization request
  is delivered with every parameter, per D12: `_INTERSTITIAL`/`interstitial_page`
  must not rely on the browser preserving an action URL's query — a `method="get"`
  form submission *replaces* the action's query with its successful controls' entry
  list, so a parameter-bearing action with no controls submits to the bare endpoint —
  so deliver by hidden inputs carrying every parameter with a bare action, or by the
  page continuing itself (a navigation to the built URL), and reconcile the template
  with the page's stated auto-continue behavior (no manual Continue button). Add the
  delivery fail-closed guard: when a required parameter is absent from what the
  browser would receive, the flow fails with the plain-language error page and no
  parameter-less request is sent. Verify with: (a) a regression test that asserts on
  the URL a form submission or navigation PRODUCES — render the page, derive the
  submission URL from the form's actual successful controls (or the navigation
  target) the way a browser does, and assert `response_type`, `client_id`,
  `redirect_uri`, `code_challenge`, `code_challenge_method`, `state`, and the
  advertised `scope` are present on that URL — never on the `action`/`href` attribute
  text, the exact assertion class that stayed green through this defect; (b) a unit
  test for the fail-closed branch; (c) `pytest -q` green; (d) a re-run of the live
  signed-out flow to the interstitial, verifying the URL the browser actually
  navigates to on continuation carries every parameter, with redacted evidence
  captured in `evidence/`. Note: `evidence/group-4.md`'s test-summary row for
  `tests/test_federation.py` (the "the interstitial and its escaping" coverage
  phrase) goes stale on the mechanism detail once this lands; correct it when that
  evidence row is next touched.

  **Landed:** the page continues itself — a `<meta http-equiv="refresh">` navigation to
  the gateway-built URL, with a plain anchor beside it as the fallback for a browser that
  ignores the refresh — so the interstitial carries **no form and no button**, matching its
  own stated auto-continue behavior. The delivery guard reads the **finished URL** (not the
  mapping that built it) for the six required parameters plus `scope` where the toolset
  advertises any, and refuses with the plain-language error page (`502`, `leg="upstream"` in
  the audit trail) rather than delivering an incomplete request. Tests: the attribute-level
  helper is gone; `test_the_upstream_url_is_built_from_cores_public_settings` now derives the
  navigation target the way a browser does, and `test_the_interstitial_delivers_its_request_
  by_navigating_not_by_submitting` asserts the mechanism itself (no form, no button, the two
  delivery routes agreeing), `test_a_toolset_without_advertised_scopes_is_delivered_without_
  a_scope_parameter` covers the conditional-`scope` case (L1), and
  `test_an_incomplete_upstream_request_fails_closed_before_the_page_is_served` plus
  `test_a_present_but_empty_parameter_counts_as_undeliverable` cover the fail-closed branch.
  The live re-run is in `evidence/group-4.md`.

- [x] 4.9 Serve the web-hardening header family on every HTML response, per D13: one
  shared header helper applied to both page-response paths — the interstitial
  (the page rendered by `gateway/flow.py`'s `interstitial_page`, with the
  `HTMLResponse` constructed at `gateway/federation.py`, where the interstitial's
  response is built) and every plain-language error/flow page
  (`gateway/errors.py`: `flow_expired_page`, `gateway_error_page`, `no_access_page`) —
  carrying `Content-Security-Policy: default-src 'none'; base-uri 'none';
  frame-ancestors 'none'` with no source permitting script (the interstitial's inline
  style satisfied per the implementation's choice — nonce, hash, or `'unsafe-inline'`),
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `charset=utf-8` on
  the Content-Type header. The router side adds nothing: HSTS is ruled inapplicable on
  the committed plain-http listener and stays a TLS-terminating deployment's own
  listener concern (D13), so no router task is opened. Verify with a header-assertion
  test per page class — the interstitial and each error page — asserting every header
  and that the CSP admits no script source, `pytest -q` green, and a re-run of the
  live flow to the interstitial capturing the served headers (redacted) in
  `evidence/`. Note: `evidence/group-4.md`'s test-summary rows for the interstitial
  and error-page tests go stale on the added assertions once this lands; correct them
  when that evidence file is next touched (the same standing note 4.8 left).

  **Landed:** `gateway/pages.py` holds the family — `page_headers()`, `PAGE_STYLE` and
  `html_page()`, the single construction path for both page classes. The inline style is
  satisfied **by hash**: `style-src 'sha256-…'` over the shared `PAGE_STYLE` text, which
  both templates substitute through `STYLE_BLOCK`, so the served `<style>` content is
  byte-for-byte what was hashed and the permission cannot go stale beside a template.
  `gateway/federation.py`'s interstitial response and all three `gateway/errors.py` page
  builders now go through `html_page`; the JSON and redirect paths keep their `_NO_STORE`.
  Tests: `tests/conftest.py`'s `assert_hardening_headers` asserts the whole family and
  **recomputes the style hash from the served page's own `<style>` text**, so a page whose
  markup drifted from its policy fails; `test_the_interstitial_carries_the_web_hardening_headers`
  covers the interstitial and `test_every_error_page_carries_the_web_hardening_headers`
  asserts each of the three error pages. Negative controls run: a response built outside
  the builder is rejected, and a tampered stylesheet fails the hash. `pytest -q` **337
  passed, 1 skipped**. The live re-run and the served headers are in
  `evidence/finding-web-hardening-headers.md`; `evidence/group-4.md`'s two stale
  test-summary rows are corrected there.
- [x] 4.10 Wire the audit trail at every pre-allocation refusal site, per the
  refusal-audit requirement: `gateway/audit.py`'s `flow_refused` gets a call site at
  every refusal before a flow is allocated — the `/dial/authorize` validation branches
  (unknown client, unregistered redirect URI, missing or unknown `resource`, the PKCE
  and inference refusals) and its per-source/global limiter 429, the `/dial/token`
  validation failures, the registration-resolution and `/dial/register` refusals (the
  disabled 404, the limiter 429, the body refusals, the cap refusal), the
  `/dial/revoke` form-parameter refusals, the `/dial/{name}/status` refusals (the
  unknown-toolset 404, the missing-token and invalid-token 401s, `invalid_target`),
  and the discovery 404s. The callback pages stay excluded: their refusals answer
  for a flow already allocated and are audited by that flow's own events. Extend
  `flow_refused`'s signature: `flow_refused(reason, *, client_id=None,
  redirect_uri=None, resource=None, toolset=None)` — the discipline splits: the
  reason stays fixed-vocabulary (never a caller value); the facts are
  caller-supplied but land as discrete `_emit` fields, each single-line encoded (a
  newline inside a caller value cannot become a newline in the record), never
  interpolated into free-form text; never a flow id (there is none yet), never
  credential material; each fact length-bounded — truncated at the `_emit`
  boundary to the configured cap, so an oversize caller value cannot land in the
  record in full; and the `rate_limited` branch audits facts-free (the reason
  only) — the limiter bounds work, not log volume. Verify with unit tests: each refusal class produces exactly
  one audit record with the fixed vocabulary and the safe facts (a redirect-URI
  refusal's record names the client id, the redirect URI, and the resource — the
  redirect-uri finding's field class; a limiter 429 or discovery miss carries the
  facts the request offered); an injection attempt through caller-supplied values
  (a redirect URI or client name crafted to carry log content, including embedded
  newlines) writes no free-form content and no extra lines into the record; no
  token, code, key, or verifier appears in any record; a fact longer than the
  configured cap lands truncated, never in full; a limiter 429's record carries
  the reason only and no facts. `pytest -q` green.
- [x] 4.11 Cap the request body on the remaining form endpoints and bound the
  round-2 abuse surfaces, per the abuse-bounds requirement and the design's
  residual record: (a) `/dial/token` and `/dial/revoke` read their forms through
  the same capped-read shape as `/dial/register` — a settings-configured byte
  cap, a chunked read that returns on the first byte past the cap, an over-cap
  body refused — and the DCR per-record maxima are reconciled with the register
  body cap so the per-record caps are jointly reachable within it; (b) the router
  config states `client_max_body_size` explicitly as defense-in-depth, never
  relying on the implicit default. It sits deliberately **above** the gateway's
  per-endpoint form caps (16384 against 8192), which puts two layers in front of
  the public surface rather than one: the router's cap bounds what reaches the
  gateway at all — a larger body is refused there with 413 and never forwarded —
  and a body that fits under it but over an endpoint's own cap is refused by the
  gateway while reading, with that endpoint's RFC 6749 error shape at 400. Both
  refusals are needed and they answer different questions: the router's is a
  bound on the front door's own buffering and carries no OAuth shape, because the
  router does not speak OAuth and answers with a bare 413; the gateway's is a
  bound on the reading endpoint and keeps the surface's error contract, so a form
  the gateway refuses is answered as an OAuth `invalid_request` at 400. A body
  between the two caps is therefore the only class the gateway's own refusal
  sees, which is why both are asserted; (c) a capacity limiter bounds concurrent
  CIMD fetches so an attacker-chosen fetch cannot occupy more than the limiter's
  share of the shared worker pool, keeping capacity for the identity and
  credential legs; (d) the compose gateway service and the router config carry the
  peer-binding comment: the gateway's container port 8091 is never host-published
  — the router is the only door and the only authority for the peer identity.
  Verify with unit tests: an oversize body on each of the three form endpoints is
  refused with no byte past the cap processed; a flood of concurrent CIMD fetches
  is bounded by the capacity limiter while a legitimate leg proceeds;
  `wsl -e docker compose config` shows no host port mapping on the gateway
  service; the router config carries the `client_max_body_size` directive;
  `pytest -q` green.

  **Landed:** `evidence/consolidated-fix-pass.md`, sections S2 and S4 — `capped_body`
  in `gateway/requests.py` shared by all three body-bearing endpoints under
  `GATEWAY_FORM_MAX_BODY_BYTES` (8192) and `DCR_MAX_BODY_BYTES` (8192), the startup
  refusal reconciling the DCR per-record maxima with the registration body cap, the
  router's stated `client_max_body_size 16384`, and the 8091-never-published invariant
  recorded at both halves. Tests: `tests/test_limits.py` (an over-cap body refused at
  each of the three endpoints, plus the at-cap negative control), `tests/test_store.py`
  (the contradictory configuration refused naming both settings, and the defaults
  jointly reachable). Live proof of (d) in the same file: `docker compose config` shows
  no `ports` key on the gateway service while the router publishes `0.0.0.0:8090`. The
  cap layering of (b) is stated there too, in the `router/nginx.conf` entry.

## 5. Front routing (Stage 3)

- [x] 5.1 Write the front-router nginx config: exact AS/discovery locations to the
  gateway; the data path `^/dial/(?<tname>[a-z0-9-]+)/mcp$` to
  `http://core:8080/v1/toolset/$tname/mcp$is_args$args` with `proxy_buffering off`,
  `proxy_intercept_errors on`, `error_page 401 = @mcp_challenge`, and the
  `WWW-Authenticate` header built from the configured `$mcp_origin` (never `$host`);
  everything else to Core. Verify with `nginx -t` inside the built router image.
  **Mechanism deviation, measured:** `proxy_intercept_errors on` + `error_page 401 =
  @mcp_challenge` re-serves the upstream response's headers, so Core's challenge survives
  into the rewritten response and `proxy_hide_header` cannot remove it — the response
  reaches the client with two challenges. The challenge is therefore synthesized by the
  data path's own `add_header` from a status-conditioned `map` plus
  `proxy_hide_header WWW-Authenticate`; the required property (the 401 carries the
  gateway's challenge and none of the upstream's) is met and asserted by the battery.
  See `evidence/group-5.md` D-9.
- [x] 5.2 Run the scripted routing probe battery against the composed router:
  flat AS metadata reachable, per-toolset PRM reachable, data-path 401 rewritten to
  the gateway's challenge, and a GET with `?sessionId=<probe>` visible intact in
  Core's access log. Verify all probes pass; capture the battery output in
  `evidence/` (redacted at capture time).
- [x] 5.3 Land the group's docs: the routing reference (location map, the reserved
  names, the `$mcp_origin` rule) in `docs/`. Verify the documented probe commands run
  as written against the composed stack.

## 6. Deployment configuration and provisioning (sibling instance, config only)

- [x] 6.1 Finalize the sibling's Core env: keep the spike's `dial-mcp-proxy` entry but
  point `jwksUrl` at the running gateway service
  (`http://mcp-signin-gateway:8091/dial/jwks.json`); set
  `aidial.toolsets.security.authorizationServers` to `http://localhost:8090`; put
  `http://localhost:8090/dial/callback/upstream` **first** in
  `allowedRedirectUris` (Core stores the list's *first* entry back as the toolset's
  `auth_settings.redirect_uri`, so order decides which callback the sign-in flow
  redirects to; re-pointing the toolset afterwards needs a delete-and-recreate, not a
  `PUT`); do NOT add `openid` to `scopesSupported`. Apply with
  `wsl -e docker compose up -d --force-recreate core`. Verify: core healthy, a
  Keycloak-issued token still validates (regression), Core's PRM now advertises
  the gateway origin, and `scripts/spike_register_toolset.py --replace` reports the
  stored `redirect_uri` as the gateway's callback.
- [x] 6.2 Write `scripts/provision_keycloak.py`: idempotent creation of the public
  PKCE client `dial-mcp-proxy` (standard flow, S256, no secret, redirect
  `http://localhost:8090/dial/callback/keycloak`, default scopes `profile,email`, the
  roles and `project` mappers cloned from the `dial-sso-desktop-claude` template) via
  the Keycloak Admin API with `KEYCLOAK_ADMIN_USER`/`KEYCLOAK_ADMIN_PASSWORD` from
  `.env` — never hardcoded. Verify by running it twice (second run is a no-op) and
  decoding a token obtained through the client to confirm `sub`, `roles`, `project`,
  `email` claims (redact the capture).
- [x] 6.3 Confirm the `notion` toolset registration established by the spike (1.5)
  is still live — re-run the committed helper `scripts/spike_register_toolset.py` if
  it is not (idempotent: the documented `PUT /v1/toolsets/platform/notion` recipe,
  body limited to `display_name`, `endpoint` (`https://mcp.notion.com/mcp`),
  `transport: HTTP`, and `auth_settings` with `authentication_type: OAUTH` +
  `redirect_uri`). Verify by reading the toolset's public settings back and seeing
  `client_id`, `authorization_endpoint`, `code_challenge`, `code_challenge_method`,
  `scopes_supported` — and no verifier, no client secret — and that a user without
  the toolset's read access receives 403 (not 404) on the same settings read, the
  status the flow's no-access branch (4.2) keys on.
- [x] 6.4 Correct `docs/local-environment.md`: name `scripts/provision_keycloak.py` as
  the promised script; describe Core's settings as env vars in the instance compose
  (not an `aidial.settings.json`); align the documented toolset public-settings read
  with the route the flow is configured to use (`GET /v1/toolsets/platform/notion`;
  the doc's current `GET {core}/openai/toolsets/notion` is the equivalent
  deployment-listing read — both are live Core routes, so this is an alignment, not a
  fix); mark the realm client-registration-policy section as historical PoC-A state
  that this design does not require (harnesses register against the gateway, not
  Keycloak). Verify every command and path in the doc runs as written.
- [x] 6.5 Complete `.env.example` for the full deployment (all gateway settings,
  Keycloak admin placeholders, network name) and add the run instructions to the
  repo's `README.md`. Verify no real value is present and every placeholder is
  consumed by the settings model.

## 7. Static and compose-boot gates

- [x] 7.1 Run the lightweight and static gates on the whole repo: `ruff check`,
  `ruff format --check`, `mypy`, `pytest -q`, `bandit`, `pip-audit` (blocking — remedy
  any reachable vulnerability, including transitive, by a dependency bump), and Trivy
  on the built image (`wsl -e trivy --skip-db-update` if the DB download fails).
  Verify all green or explicitly triaged in `evidence/gates.md` with reasons.
- [x] 7.2 Run the compose-boot gate: `wsl -e docker compose up -d` brings up
  `mcp-signin-router` and `mcp-signin-gateway`, the gateway's `/healthz` answers
  through the router, and the router reaches Core (a plain request through port 8090
  returns Core's response). Verify with a scripted health probe per service; capture
  the probe output in `evidence/`.

## 8. DCR live verification (the config-gated fallback, flag on and off)

The fallback path is proven here, with its own verification and evidence rows —
a DCR failure in this group is a change defect for the defect cycle, NOT a PoC C
criterion and not a design falsification.

- [x] 8.1 Negative control FIRST — with the composed stack from group 7 and DCR off
  (the default): POST a registration body (loopback `redirect_uris`) to
  `/dial/register`. Verify the response is the documented disabled-error (404) and
  the flat AS metadata advertises no registration endpoint; capture redacted
  evidence in `evidence/dcr.md`.
- [x] 8.2 Enable DCR in local `.env` (`DCR_ENABLED=true`), recreate the gateway, and
  confirm the surface is now live: the flat AS metadata advertises the registration
  endpoint; `POST /dial/register` with a body limited to `redirect_uris` (loopback
  URIs) and `client_name` returns a client id; a body without `redirect_uris` is
  refused. Verify both branches and the store file gains exactly one record with no
  secret material; capture redacted evidence in `evidence/dcr.md`. **Defect found
  here:** on the compose file's `./data:/data` bind mount as this host mounts it
  (DrvFs/9p), the store's atomic save fails at `chmod` and *every* registration is
  refused — `evidence/finding-dcr-store-mount-chmod.md`. The checks above ran green
  with the store temporarily on a WSL-native mount; recorded for the defect cycle,
  not fixed in this group. **Resolved in task 3.12:** the fix landed and the checks
  re-ran green on the committed bind mount itself — see `evidence/dcr.md`'s task-3.12
  section.
- [x] 8.3 Complete the authorization flow as that registered client and make a live
  toolset call: `/dial/authorize` with the registered client id, its registered
  redirect URI, PKCE S256, and `resource` (the redirect-URI rules apply — an
  authorization request with an unregistered redirect URI for the same client is
  rejected), the federation flow through to the signed-in state (where the scripted
  client drives the test user's identity-provider login itself, that machine
  credential comes from `.env` with `.env.example` placeholders, mirroring 1.6's
  pattern — never hardcoded), the code exchange at `/dial/token`, and a live
  toolset call through the front door (`/dial/notion/mcp`) with the minted token.
  Verify the tool call succeeds as that user; capture redacted evidence in
  `evidence/dcr.md`. **Blocked, not green:** the redirect-URI control, the
  registered-URI acceptance, discovery, the identity-provider login and the
  gateway's callback all verified; the live tool call did not run, because the test
  user's stored upstream credential had been signed out before this session
  (`/v1/ops/toolset/signout`, Core's log) and completing Notion's consent needs a
  human in a browser — and beyond that, the interstitial defect recorded in
  `evidence/finding-empty-upstream-redirect.md` blocks the leg for every client on
  the current tree. Left unticked deliberately; no pass is inferred.

  **Landed (both blockers cleared).** The interstitial was fixed by task 4.8 (the page
  continues itself by navigation, with the delivery guard) and the owner re-established
  the test user's Notion credential, so the flow's signed-in short-circuit applies. The
  full chain then ran as the **DCR-registered client**: discovery → `/dial/authorize` with
  the stored client id and its registered redirect URI → the Keycloak login → the
  gateway's callback carrying `code`/`iss`/`state` with the state round-tripped →
  `/dial/token` (`200`; `iss=http://localhost:8090`, the test user's `sub`, `roles`,
  `project`) → a **live `tools/list` through `/dial/notion/mcp`** (`200`, 65 tools). The
  registration the flow ran as is the one the store preserved through disable/re-enable —
  its file hash is unchanged before and after. The deployment was returned to the default
  state (`DCR_ENABLED` off, gateway recreated, router restarted, healthy, `/dial/register`
  `404`, store dormant and preserved). Capture: the task-8.3 section of
  `evidence/dcr.md`.
- [x] 8.4 Restart persistence: `wsl -e docker compose restart mcp-signin-gateway`,
  then repeat an authorization request with the same client id and registered
  redirect URI, with no re-registration in between. Verify the request is accepted —
  the registration survived the restart — and the store file is unchanged; capture
  evidence in `evidence/dcr.md`.
- [x] 8.5 Re-disable DCR (unset `DCR_ENABLED`), recreate the gateway, and confirm the
  dormant-store semantics: `POST /dial/register` answers the documented
  disabled-error again, and the store file is preserved unchanged (re-enabling
  restores the registration as it was). Verify both; capture evidence in
  `evidence/dcr.md`.
- [x] 8.6 Record the group's verdict in `evidence/dcr.md`: the negative control
  (8.1), the registration and surface checks (8.2), the completed flow with the live
  toolset call (8.3), restart persistence (8.4), and the re-disable/dormant-store
  check (8.5), each with its evidence row — redacted at capture time. Verify the
  file contains no token, code, key, or secret material.

## 9. PoC C — end-to-end acceptance on a real harness (integration checks only)

- [x] 9.1 Criterion (a) — first use end to end with a real harness (Claude Code):
  `claude mcp add` the front-door path, complete discovery (rewritten 401 → PRM →
  flat AS), CIMD registration (URL-shaped client id, no `/register` call), the
  federation flow (`resource` sent on both legs), and a live `tools/call` through
  `/dial/notion/mcp` authenticated by a gateway-signed, copied-`sub` token. Verify by
  the live tool call succeeding; capture redacted evidence in `evidence/poc-c.md`.
- [x] 9.2 Criterion (b) — silent repeat use and refresh with rotation ON: further tool
  calls with no browser; force access-token expiry and observe refresh-on-401; record
  whether the harness adopts the rotated refresh token. Verify by observation with
  captured evidence (this is a measurement, not a pass/fail of the harness).
- [x] 9.3 Criterion (c) — mid-session upstream-credential removal: sign the toolset
  out through Core's ops API and make the harness's next call. Verify it takes the
  sign-in-again branch (status or re-consent), not a 401 loop, and that the harness
  keeps its gateway token (OR-4); capture evidence.
- [x] 9.4 Criterion (d) — query-string survival on the MCP path: issue a
  streamable-HTTP GET with `?sessionId=<probe>` through the front door. Verify Core
  receives the parameter unchanged (access-log or behavior evidence).
- [x] 9.5 Criterion (e) — coexistence: exercise Core's own toolset path with a
  direct-to-Core client holding a Keycloak-issued token while the gateway front door
  is live. Verify it keeps working unchanged; capture evidence.
- [x] 9.6 Gate verdict: record the per-criterion pass/fail and the refresh/staleness
  measurements for the owner's SLA decision in `evidence/poc-c.md`. Any criterion
  failing is a falsification of the design: halt, reopen the design per the defect
  cycle — do not patch around it. Verify the verdict line exists and names each
  criterion's outcome.
