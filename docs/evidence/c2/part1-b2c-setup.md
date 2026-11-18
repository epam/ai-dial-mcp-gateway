# Task 7.1 Part 1 — live B2C setup record (2026-11-05)

The composed stack was brought up on the B2C profile and probed for everything that
does not need a login. Every command ran from the `d0a-publication-discipline` worktree
via PowerShell → `wsl -e docker`; no secret value was printed, copied, or moved. The
worktree `.env` had already been switched to the B2C profile before this session
(Keycloak profile backed up at `.env.local-keycloak`).

## Step 1 — Core recreated on the new identity-provider entry

Command (PowerShell, first attempt):

    wsl -e docker compose --project-directory "C:\...\dial\dial-instance" up -d --force-recreate core

Outcome: **failed** — `no such service: core`. The Windows path spelling reached WSL
docker compose, which loaded no project with a `core` service under that spelling.

Command (PowerShell, second attempt — `/mnt/c` spelling):

    wsl -e docker compose --project-directory "<the-instance-folder-as-a-wsl-/mnt/c-path>" up -d --force-recreate core

(The instance folder is this repository's sibling `dial-instance` directory;
the command is recorded with the path elided per the publication-discipline personal-path
rule.)

Outcome: **passed** —

    Container dial-instance-redis-1  Running
    Container dial-instance-core-1   Recreate
    Container dial-instance-core-1   Recreated
    Container dial-instance-core-1   Starting
    Container dial-instance-core-1   Started

The `/mnt/c` spelling is the working one; the `C:\` spelling silently finds no service.
(The worktree guard never refused this step — the recorded constraint did not bite.)

## Step 2 — gateway + router recreated on the B2C .env

Command (PowerShell, from the worktree):

    wsl -e docker compose up -d --build mcp-signin-gateway mcp-signin-router

Outcome: **passed** — the gateway image rebuilt (only the `gateway/` layer and the
dependency install ran; the base layers were cached) and the container was recreated,
started, and reported `Healthy` under compose's own wait. The router was left
`Running` (compose saw no config change for it), so the recorded step was completed
with an explicit recreate:

    wsl -e docker compose up -d --force-recreate mcp-signin-router

Outcome: **passed** — `mcp-signin-router` recreated, started, `Healthy` (its
healthcheck waits on the gateway's, which was healthy).

Health status after both (`wsl -e docker ps --format "{{.Names}}\t{{.Status}}"`):

    d0a-publication-discipline-mcp-signin-router-1   Up About a minute (healthy)
    d0a-publication-discipline-mcp-signin-gateway-1  Up 2 minutes (healthy)
    dial-instance-core-1                    Up 4 minutes (healthy)

## Step 3 — the gateway reads the B2C profile

`docker inspect` of the gateway container's `Config.Env` (secret filtered inside WSL
before any output; the value was never printed):

    IDP_ISSUER=<tenant-issuer>
    IDP_CLIENT_ID=<tenant-client-id>
    IDP_CLIENT_SECRET=<REDACTED — present>
    IDP_BACKCHANNEL_BASE_URL=            (empty — see below)
    IDP_PKCE_ENABLED=true
    IDP_JWKS_URI=                        (empty — discovery-supplied)
    IDP_TOKEN_ENDPOINT=                  (empty — discovery-supplied)
    IDP_AUTHORIZATION_ENDPOINT=          (empty — discovery-supplied)
    IDP_CLIENT_SCOPES=openid,profile
    IDP_DISCOVERY_CACHE_TTL_SECONDS=300
    IDP_SSO_SESSION_MAX_SECONDS=86400

Readings:

- `IDP_ISSUER` is the **tfp spelling** of the B2C tenant — matches the issuer the
  Core `<provider-entry-name>` provider entry pins.
- `IDP_CLIENT_SECRET` is present (shown only as `<REDACTED present>`; the value never
  left the container inspection).
- `IDP_BACKCHANNEL_BASE_URL` is present-but-empty, not absent: the compose file
  interpolates `IDP_BACKCHANNEL_BASE_URL: ${IDP_BACKCHANNEL_BASE_URL:-}` (compose line
  145), and `.env` does not set it, so the container sees the empty string. Empty is
  the "not configured" state, not a misconfiguration.
- The discovery endpoints are empty, consistent with lazy discovery.

Boot log (`wsl -e docker logs` on the gateway container) — clean, and **no startup
discovery fetch**, as the D4 lazy-discovery behavior requires:

    INFO:     Started server process [1]
    INFO:     Waiting for application startup.
    INFO:     Application startup complete.
    INFO:     Uvicorn running on http://0.0.0.0:8091

No discovery errors at boot. A discovery smoke through the front door is not possible
unauthenticated, so the clean-boot log plus the empty discovery-endpoint env is the
boot-time evidence.

## Step 4 — trust-chain probes

### `probe_gateway_trust.py` — ran, all green

Command: `PYTHONUTF8=1 <main checkout venv> python scripts/probe_gateway_trust.py`
(gateway-signed tokens — exercises the JWKS + Core trust path, no B2C login needed).

Outcome — all three controls green, battery verdict green:

1. **Published JWKS through the front door**: `GET
   http://localhost:8090/dial/jwks.json` → `keys=["a119a0a9bee68848"]`, matching the
   kid derived from `GATEWAY_SIGNING_KEY` — *green, the signing key is the published key*.
2. **Negative control** (token signed by an unpublished key): `GET /v1/user/info` →
   HTTP 401 — *red as required, an unpublished signer is refused*.
3. **Positive control** (gateway-signed token, `iss=http://localhost:8090`, `aud`
   `["http://localhost:8090","dial-mcp-proxy"]`): `GET /v1/user/info` → HTTP 200, real
   userId and roles resolved — *green, Core validated the gateway's key through the
   gateway's own JWKS endpoint*.

### `probe_routing.py` — not run; skipped per instruction

Checked first, per the run instruction, and it **does require the Keycloak login
flow**: its token minting (`mint_probe_token` → `fetch_identity_token` in
`scripts/spike_mint_jwt.py`) performs a Keycloak **password grant** against
`KEYCLOAK_ADMIN_URL` with `TEST_USER_NAME` / `TEST_USER_PASSWORD`
(`scripts/spike_env.py` `request_user_token`). The current `.env`'s `TEST_USER_*`
keys are the Keycloak user, not the B2C test user, and the B2C profile is what this
setup is exercising — so the probe was skipped and is handed to the B2C sign-in run
(whose acceptance covers the same routing surface with a real login).

## Step 5 — `probe_end_to_end.py` deliberately not run

The e2e probe drives a login form. The B2C test user has not been supplied by the
owner yet (the current `TEST_USER_*` keys are the Keycloak user), and the B2C login
branch of the e2e probe awaits them. Recorded as pending, not attempted.

## Step 6 — Core healthy, no identityProviders parse errors

`wsl -e docker ps`: `dial-instance-core-1  Up 4 minutes (healthy)`.

`wsl -e docker logs --tail 200 dial-instance-core-1`, filtered for
`identityProvider` / `b2c` / `jwks` / `ERROR` / `WARN`: **no identityProviders parse
errors, no errors at all** — the only warning is a benign micrometer duplicate-gauge
registration on the `/health` route. The boot tail ends clean:

    "Proxy started on 8080" (com.epam.aidial.core.server.AiDial, INFO)

## Ready state for the B2C sign-in run

Green:

- Core recreated on the `<provider-entry-name>` identity-provider entry, healthy, clean logs.
- Gateway rebuilt, recreated, healthy, reading the B2C profile (tfp issuer, client ID,
  secret present, backchannel base URL unset, lazy discovery — no boot-time fetch).
- Router recreated, healthy; front door `localhost:8090` serving the JWKS the trust
  probe consumed.
- Gateway ↔ Core trust chain verified end-to-end without a login (JWKS match,
  unpublished signer refused, gateway-signed token resolves a real identity in Core).

Blocked on the owner before the actual sign-in run:

1. **B2C test user** — not yet supplied; `TEST_USER_*` in `.env` still name the
   Keycloak user. The e2e probe (and the B2C branch of `probe_routing.py`'s token
   source) needs the B2C test user's credentials.
2. **Redirect URI confirmation** — the B2C app registration's redirect URI must list
   the gateway's public origin callback; owner to confirm in the tenant.
