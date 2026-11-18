# Stage 0 spike — Core trusts a gateway-minted JWT

Tasks group 1 of `build-mcp-sign-in-gateway-poc`. Every capture below is redacted at
capture time: no token, code, key, password, or client secret appears in this file
(`.gitignore` blocks `*.jwt`/`*.pem`/`*.key`, so an unredacted capture would silently fail
to commit). Tokens are shown as `<redacted len=N sha256=...>` handles.

## Verdict

**spike passed — proceed**

Core accepts a gateway-minted RS256 JWT and resolves both the identity and that user's
stored upstream credential, while rejecting a mismatched issuer, a missing audience
marker, and an unpublished signing key. The falsification stop did not trigger; the
group 2+ premise — the gateway as an additional identity provider in Core — stands.

## Preconditions, established from committed material

| Step | Instrument | Result |
|---|---|---|
| `notion` toolset registered | `scripts/spike_register_toolset.py` | Reads back `client_id`, `authorization_endpoint`, `redirect_uri`, `code_challenge`, `code_challenge_method: S256`, `scopes_supported: ["default"]`, `dynamically_registered: true`; no verifier, no client secret |
| Test user's upstream credential | `scripts/spike_establish_credential.py` | One browser consent → `POST /v1/ops/toolset/signin` → 200; `user_level_auth_status: SIGNED_IN` |

Both helpers take their machine credentials from `.env` (gitignored) with committed
`.env.example` placeholders, and neither prints a credential.

## Negative controls (run FIRST — all must reject)

| Probe | Token shape | Expected | Observed | Verdict |
|---|---|---|---|---|
| NEG-A mismatched issuer | `iss=http://evil.example:9999`, `aud=[iss, dial-mcp-proxy]`, `kid` published | reject | `GET /v1/user/info` → **401** `Unknown api key` | **rejected as expected** |
| NEG-B missing audience marker | `iss=http://localhost:8090`, `aud=[iss, some-other-service]`, `kid` published | reject | `GET /v1/user/info` → **401** `Unknown api key` | **rejected as expected** |
| NEG-C unpublished signing key | `iss=http://localhost:8090`, `aud=[iss, dial-mcp-proxy]`, `kid=952eff0621862383` (never published) | reject | `GET /v1/user/info` → **401** `Unknown api key` | **rejected as expected** |

The published key for this run was `kid=b12e0ae2e76de03b`; the three controls were minted
and probed against that single published key, so each isolates one variable. All three
rejected before any positive verdict was read: the instrument can fail, so its acceptance
below means something.

## Positive control

| Probe | Expected | Observed | Verdict |
|---|---|---|---|
| `GET /v1/user/info` | identity resolves | **200** — `userId=3a0d60f4-…`, `roles=["admin"]` | **pass** |
| `POST /v1/toolset/notion/mcp` `initialize` | Core resolves the user's upstream credential | **200** — `serverInfo = Notion MCP 1.2.0`, no `WWW-Authenticate` | **pass** |
| `POST /v1/toolset/notion/mcp` `tools/list` | live upstream data through the proxy | **200** — 65 tools, first `["notion-search", "notion-memory-search", "notion-get-tool-access", "notion-fetch", "notion-create-attachment"]` | **pass** |

Token shape for these probes: `iss=http://localhost:8090`,
`aud=["http://localhost:8090", "dial-mcp-proxy"]`, `sub=3a0d60f4-…`, `roles=["admin"]`,
`project="proj-alpha"`, plus the identity token's other claims copied verbatim.

`GET /v1/toolset/notion/tools` is the admin listing endpoint and 403s for ordinary users;
the MCP path above is the check a harness itself performs, and is what these probes use.

## Core env diff applied (sibling instance, config only)

`docker-compose.yml`, Core `environment`; applied with
`wsl -e docker compose up -d --force-recreate core`.

| Variable | Value | Why |
|---|---|---|
| `aidial.identityProviders.keycloak.issuerPattern` | `^https://keycloak:8443/realms/dial$` | With more than one provider Core selects by issuer match, and a provider with no pattern can never match |
| `aidial.identityProviders.dial-mcp-proxy.jwksUrl` | `http://spike-jwks:8099/jwks.json` | The spike's published public key, served from a container on the instance network |
| `aidial.identityProviders.dial-mcp-proxy.issuerPattern` | `^http://localhost:8090$` | Binds the provider to the gateway's public origin |
| `aidial.identityProviders.dial-mcp-proxy.rolePath` | `roles` | Mirrors the Keycloak entry |
| `aidial.identityProviders.dial-mcp-proxy.projectPath` | `project` | Mirrors the Keycloak entry |
| `aidial.identityProviders.dial-mcp-proxy.audience` | `dial-mcp-proxy` | Makes Core verify the marker, so a token minted for another purpose is not valid deployment-wide |
| `aidial.identityProviders.dial-mcp-proxy.loggingKey` / `.loggingSalt` | `email` / `loggingSalt` | The same obfuscated user logging as the Keycloak entry |

Regression control: after the recreate, a Keycloak-issued token still resolves —
`GET /v1/user/info` → 200, `userId=3a0d60f4-…`, `roles=["admin"]`.

The `spike-jwks` container is one-shot and exists only for this spike; it is replaced in
group 6 by the gateway's own JWKS endpoint.

## Environment surprises worth carrying forward

1. **Core's settings route does not enrich auth status.** `GET /v1/toolsets/{bucket}/{name}`
   returns the stored settings with `user_level_auth_status` absent, while
   `GET /openai/toolsets/{name}` returns the same fields plus `global_auth_status` and
   `user_level_auth_status`. A sign-in helper that reads status from the settings route
   reads `None` for a signed-in user. Both routes are live; the listing route is the one
   that answers status.
   **Design ripple landed:** `design.md`'s mi-2 debt-ledger row now splits the two routes
   — settings and creation via `GET`/`PUT /v1/toolsets/{bucket}/{name}`, status via
   `GET /openai/toolsets/{name}` — as measured here. The delta spec pins no route, so no
   spec delta follows.
2. **The realm's clients differ in the claims they carry.** The `admin` role reaches the
   token's `roles` through a *per-client* mapper: `dial-chat` (confidential) carries the
   client-role mapper but no `project` claim, while `dial-cli` carries both `roles` and
   `project`. One credential pair therefore does not serve both jobs — the helpers use a
   separate `.env` setting for each client.
3. **`dial-cli` pins `access.token.lifespan: 60`.** A human consent takes longer than one
   lifespan, so a token minted before the browser step is expired by the time the code
   arrives; the credential helper re-mints immediately before its `signin` call.
4. **`Notion MCP initialize` answered `502 No route` once and `200` on the next call.**
   A transient upstream cold-start, matching the background notes that the first upstream
   call after a sign-in is slow. `tools/list` succeeded on both attempts.

## Non-evidence probe: the synthetic `--simulate` mode

`scripts/spike_establish_credential.py --simulate` sends the toolset's own published
`code_challenge` as a synthetic code to verify the helper's request shape without a human
present. Core answered `400 Authorization server returns error code` — the upstream
rejected the synthetic code, as it must. This confirms the call reaches Core's exchange
and is deliberately **not** used as credential evidence.
## Post-archive field finding (2026-10-23): a transient CIMD fetch failure masquerades as `unknown_client`

**Symptom.** A harness sign-in failed with `invalid_client "this client id is not
registered with the gateway"` (audit reason `unknown_client`, 14:49:05Z) — but the
CIMD fetch works (verified: HTTP 200 from inside the container) and the EXACT same
authorize request answers 302 → Keycloak on immediate re-run. The refusal was a
transient network blip during the metadata fetch.

**Root cause.** The client-resolution path maps a CIMD fetch failure (and any
resolution failure) onto the same `unknown_client` reason — the operator cannot
distinguish "transient, retry" from "this client genuinely does not resolve", and
the gateway does not retry a failed fetch itself.

**Proposed fix (recorded, not implemented — post-PoC).** (a) Distinct audit reasons:
`cimd_fetch_failed` vs `origin_not_allowed` vs `unknown_client`; (b) one in-place
retry of the metadata fetch before refusing; (c) optionally a Retry-After hint on
the transient class. Same diagnosability class as finding-preallocation-refusals.
