# Group 3 — the client-facing OAuth surface (Stage 1)

Tasks 3.1–3.9 of `build-mcp-sign-in-gateway-poc`. Records what was built, what was run to
verify it, and the two defects the tests found. Every capture below is redacted at capture
time: no token, code, key, password, or client secret appears in this file.

## Verdict

**Group 3 complete.** The gateway's client-facing surface serves discovery, resolves
clients through the whole priority order, validates authorization requests strictly, issues
and redeems authorization codes, and persists dynamic registrations — with every startup
refusal and every fetch control under test. Gates: all green (below).

## What each task landed

| Task | Deliverable | Where |
|---|---|---|
| 3.1 | Settings and startup validation: OAUTH-only mapping with `route_only`, reserved names, required `ROLES_SOURCE_PATH`, required `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` with the refresh-TTL bound, CIMD bounds, rate limits, flow cap, external origin | `gateway/settings.py` |
| 3.2 | Signing-key loading (RSA-256, derived `kid`, minimum size) and the JWKS endpoint | `gateway/keys.py`, `gateway/routes.py` |
| 3.3 | E1 per-toolset protected-resource documents with the authentication-kind extension and upstream scopes verbatim; E2 flat AS metadata, no scopes of its own, registration endpoint only while DCR is enabled | `gateway/discovery.py`, `gateway/routes.py` |
| 3.4 | CIMD fetch under the full SSRF control set (HTTPS only, origin allowlist, no redirects, private/loopback/link-local refusal with connection pinning, 64 KiB cap, timeouts, TTL + bounded cache, explicit non-default User-Agent) and `redirect_uri` validation against the fetched document | `gateway/cimd.py` |
| 3.5 | `/dial/authorize`: client / redirect-URI / strict-`resource` validation with `invalid_target` and the one-toolset inference flag, PKCE S256 required, the client's `scope` accepted and dropped, 128-bit CSPRNG flow records with TTL; the config-gated DCR endpoint | `gateway/authorize.py`, `gateway/routes.py`, `gateway/state.py` |
| 3.6 | The registration store: one JSON file, atomic save, cap-refuse, corruption startup refusal, dormant flag semantics | `gateway/store.py` |
| 3.7 | `/dial/token`'s authorization-code grant: PKCE, single-use code, short TTL, RFC 9207 `iss` | `gateway/token.py`, `gateway/codes.py` |
| 3.8 | Per-source and global rate limits, the live-flow cap with oldest-first eviction, and the plain-language error page | `gateway/state.py`, `gateway/errors.py` |
| 3.9 | The gateway configuration reference | `docs/gateway-configuration.md` |

## Test coverage, by task

`pytest -q`: **225 passed, 1 skipped**.

| File | Tests | Covers |
|---|---|---|
| `tests/test_settings.py` | 42 | Every startup refusal (non-OAuth entry, reserved name, missing roles source path, refresh TTL > IdP lifespan, placeholder signing key, malformed JSON) and every acceptance; the refusal report carries no settings values |
| `tests/test_app.py` | 17 | Liveness, the factory's refusals, key loading (wrong type, undersized, escaped newlines), JWKS shape, and the no-key-material-in-logs assertion |
| `tests/test_discovery.py` | 16 | Both documents' exact shapes, the shared endpoints, no scopes on the AS metadata, the registration endpoint's presence only while DCR is enabled, 404 for an unmapped name |
| `tests/test_cimd.py` | 48 | Every fetch control as a negative, the positive flow, the explicit User-Agent, address pinning, TTL and size bounds, resolution priority, `redirect_uri` matching — exact string equality with the loopback-port exception (task 3.11) |
| `tests/test_authorize.py` | 24 | Every validation branch, the scope drop, flow allocation and id entropy, the resource rule with and without inference, RFC 9207 `iss` |
| `tests/test_store.py` | 30 | The four durability scenarios, the cap, corruption refusal and its rename-aside recovery, atomicity, the owner-only mode, the record's field set |
| `tests/test_token.py` | 33 | The happy path, every binding mismatch, a wrong verifier, a replayed code, an expired code, a foreign-signed code, an access token presented as a code, the S256 transform pinned against RFC 7636's own vector |
| `tests/test_limits.py` | 24 | Both rate limits driven past, sources counted separately, window recovery, the flow cap and eviction, the replay cache's bound, the error pages (including the web-hardening header family on each of the three, task 4.9) and the audit trail's field set |

One test is skipped on Windows: `test_the_store_file_is_owner_only_where_the_platform_has_posix_modes`.
POSIX permission bits are not implemented there — `chmod` only toggles the read-only flag —
so asserting a mode would be asserting a number the filesystem does not enforce. The store
runs in the Linux container, where the mode is what the write sets.

## Defects found by the tests, and fixed

### D-1 — A resource that was missing at the token endpoint answered `invalid_request`

- **Symptom:** redeeming a code without a `resource` parameter returned
  `error=invalid_request` ("resource is required"), not `invalid_target`.
- **Evidence:** `tests/test_token.py::test_a_missing_resource_on_redemption_is_invalid_target`
  failed with `assert 'invalid_request' == 'invalid_target'`. The requirement is normative:
  the `resource` parameter is required on **both** endpoints and a missing or unknown one
  must be rejected as `invalid_target`.
- **Root cause:** the parameter was passed through the generic "required parameter"
  helper, which raises the `invalid_request` the other missing parameters correctly get.
- **Fix:** the resource check moved ahead of the code decode and raises `invalid_target`
  for absent and mismatched alike — they are one problem, since either way the request does
  not say which toolset the token is for. `gateway/token.py`.

### D-2 — A startup refusal's report dumped the whole settings mapping

- **Symptom:** a validation refusal's error text ended with
  `input_value={... '-----BEGIN PRIVATE KEY-----\n'}`, a truncated repr of the entire
  settings mapping.
- **Evidence:** captured directly during the live startup-refusal probe, with a real
  generated key:
  `input_value={'roles_source_path': 'ro...END PRIVATE KEY-----\n'}`.
- **Root cause:** pydantic includes an input repr in a validation error's report, and this
  model's input is the settings mapping. `SecretStr` masks the *value*, but the repr was
  long enough to expose the masked value's own suffix — which for a PEM is the key
  material's tail — plus every other deployment value beside it. No base64 body line
  leaked, but the boundary and the surrounding mapping did.
- **Fix:** `hide_input_in_errors=True` on the settings model, so no refusal report carries
  the input at all. Each refusal already names the setting it refused, so nothing an
  operator needs was removed. `gateway/settings.py`; pinned by
  `test_a_refusal_report_carries_no_settings_values`.

### D-3 — Two dict settings were JSON-decoded before their own validator ran

- **Symptom:** loading the committed `.env.example` raised
  `SettingsError: error parsing value for field "pre_registered_clients"` for a value that
  was already valid JSON.
- **Evidence:** `Settings(_env_file='.env.example')` raised from pydantic-settings' own
  dotenv source, not from the gateway's validator.
- **Root cause:** pydantic-settings JSON-decodes a complex-typed field itself, before any
  validator sees it. For `PRE_REGISTERED_CLIENTS=` (empty) that decode is a raw parse
  failure naming neither the setting's meaning nor this repository's document shape — so
  the documented "empty means none configured" behaviour never ran, and a malformed value
  refused with a message that does not say which setting it was.
- **Fix:** `NoDecode` on both fields, so pydantic-settings hands the raw string to
  `_parse_json_document`, which accepts empty as "none configured" and refuses anything
  else with a message naming the setting. `gateway/settings.py`; pinned by
  `test_explicit_empty_mapping_is_accepted` and `test_malformed_mapping_json_refuses_startup`.

### D-4 — `GATEWAY_REQUIRE_RESOURCE` was declared, documented, and shipped, but read by nothing

- **Symptom:** the setting appeared in `.env.example`, the compose file, and the
  configuration reference, and was asserted in a settings test — but no module outside
  `settings.py` read it.
- **Evidence:** a sweep of every settings field against the package's other modules:
  `gateway_require_resource` was in the unused list. `grep` for it found only the four
  declaration/shipping sites and the test.
- **Root cause:** the field was carried over in group 2 as a placeholder for a switch the
  requirement does not have. The spec makes `resource` unconditionally required, with the
  one-toolset inference flag as the only escape — so there is no second switch to wire,
  and an operator setting this one to `false` would have seen it silently ignored.
- **Fix:** the setting is removed from the model, `.env.example`, the compose file, the
  reference, and the test. Wiring it instead would have contradicted the normative
  requirement. The reason `resource` is required regardless is now stated where the
  inference flag is declared, so the absence of a switch reads as a decision rather than an
  oversight.

## Gates

Run from `.venv/Scripts` with `PYTHONUTF8=1`.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 70 files already formatted |
| `mypy` (strict) | Success: no issues found in 26 source files |
| `pytest -q` | 225 passed, 1 skipped |
| `bandit -c pyproject.toml -r gateway` | No issues identified (3 B105 findings triaged in place) |
| `pip-audit` | No known vulnerabilities found |
| `openspec validate --changes --strict` | 1 passed, 0 failed |
| `wsl -e docker build` | Image built; the built container serves `/healthz`, both discovery documents, and the JWKS |

`pip-audit` was run twice: the first attempt hit a transient name-resolution failure
against PyPI, and the retry reported no known vulnerabilities. The remedy for a reachable
vulnerability in this repository is a dependency bump, not a triage note, so a scanner run
that could not reach its database is recorded as not-run rather than as green.

Bandit's three findings were all B105 "possible hardcoded password" on values that are
token type names, not credentials: `CODE_TOKEN_TYPE = "code"`, `_ACCESS_TOKEN_TYPE =
"access"`, and the RFC 7591 `token_endpoint_auth_method: "none"`. Each is triaged with a
`# nosec` and a comment stating what the value is, rather than silenced by configuration.

## Live probes

The surface was exercised against a real process (not only the test client), and the
built image was run as a container. Both are recorded here as the behavior observed.

**Live process, discovery and refusals** (`GATEWAY_PUBLIC_ORIGIN=http://localhost:8099`,
a generated key, one mapped toolset):

- `GET /.well-known/oauth-authorization-server` → 200, issuer `http://localhost:8099`,
  shared endpoints, `client_id_metadata_document_supported: true`.
- `GET /.well-known/oauth-protected-resource/dial/notion/mcp` → 200, the derived resource
  URI, the single authorization server, `scopes_supported: ["default"]`,
  `dial_authentication_type: "OAUTH"`.
- `GET /.well-known/oauth-protected-resource/dial/nope/mcp` → 404.
- `GET /dial/jwks.json` → 200, one RSA key, public members only.

**Live process, the flow entry** (DCR enabled, a registered client):

- `POST /dial/register` → 201 with a client id; the store file on disk held exactly that
  client id, read immediately after the response.
- `GET /dial/authorize` with the registered client, its registered redirect URI, PKCE
  S256, and the resource → 200 with a flow id. A `scope=openid profile` parameter was
  present and was dropped.
- `GET /dial/authorize` without a resource → 302 to the client's own redirect URI with
  `error=invalid_target` and `iss=http://localhost:8099`.
- `GET /dial/authorize` with an unregistered redirect URI → 400 `invalid_request`,
  answered directly rather than redirected.
- `GET /dial/authorize` with a URL-shaped client id whose origin is not allowlisted → 400
  `invalid_client`.

**Live startup refusal** (`TOOLSETS={"token":{...}}`, a reserved name): the process exited
with code 1 and the container log carried
`toolset name 'token' is reserved: the front router's authorization-surface location
captures /dial/token/... before the toolset data path, so its MCP traffic could never
reach Core. Reserved names: authorize, token, register, revoke, callback, jwks.json`.

**Built image** (`dial-mcp-gateway:group3`, run with a generated key): `/healthz` answered
`{"status":"ok"}`, both discovery documents and the JWKS answered 200 with the same shapes
as above, under `GATEWAY_PUBLIC_ORIGIN=http://localhost:18099`.

## Deliberate limits of this group

Group 3 is the client-facing surface only. Two things are deliberately not done here, and
each is a later group's task rather than an omission:

- **`/dial/authorize` allocates and reports; it does not redirect to the identity
  provider.** A validated request gets a flow record and a JSON body naming its toolset
  and resource. The redirect that consumes the record — the Keycloak leg, the DIAL
  authorization check, the upstream consent, and the callback that issues a code — is
  group 4's work.
- **`/dial/token` performs the authorization-code grant only.** The refresh and revoke
  grants belong to group 4, and the endpoint answers `unsupported_grant_type` for them
  rather than advertising a grant it cannot perform. The AS metadata advertises both
  grants because the document describes the server a client will talk to, and a client not
  told it may refresh would discard its refresh token and re-run the whole sign-in.