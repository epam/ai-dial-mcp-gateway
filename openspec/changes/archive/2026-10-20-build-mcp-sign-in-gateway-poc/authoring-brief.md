# Authoring brief — build-mcp-sign-in-gateway-poc

**Read this before writing anything.** This brief is the pickup for a fresh author:
verified facts, tensions, and owner decisions — gathered while planning this change, so
they do not have to be rediscovered and do not live only in a conversation transcript
(`PROCESS.md`: no finding lives only in chat scrollback).

## 0. Your authority

**"Authoring" means designing. You have full authority to change the design.** The owner
and orchestrator supply outlines, ideas, and requirements; **you are responsible for the
final shape of the design**. `docs/background/design.md` is the converged starting point
— but where the evidence below supports converging differently, converge differently and
say why. Where this brief sketches a shape, treat it as an input, not a requirement; you
may reject framings with reasons. Repo rules (`CLAUDE.md`, `PROCESS.md`) are not yours to
change: spec-first, gate ladder, never-cut invariants, roles.

## 1. Owner decisions already taken (do not re-open)

1. **One change for the entire PoC** — not one per stage. This supersedes
   `docs/HANDOFF.md` §"Where to start" step 2 (which prescribes a Stage-0-only change);
   record the supersession in `proposal.md`.
2. **The Stage 0 spike is this change's first task block** with an explicit
   **falsification stop** (see §5). Run later by a sonnet subagent — you author, you do
   not execute the spike.
3. **Stack: Python 3.12 + FastAPI** (uvicorn, `pyjwt[crypto]`, httpx, pydantic-settings,
   pytest + respx), matching the repo's toolchain (venv, ruff, mypy, bandit, pip-audit,
   pytest).
4. **Both sign-offs from `design.md` §9 item 8 are granted** (owner rulings): (i) the
   OR-2 deviation — one always-on server-side component; (ii) the nginx 401 rewrite
   *synthesizes* a `WWW-Authenticate` header rather than purely splitting traffic.
   Record them as accepted owner rulings.
5. **The refresh design is yours to choose** (§4 below gives the options and their
   costs).

## 2. Verified facts — Core's claim consumption (source-checked 2026-10-17/18,
local Core `deps-v2`)

### 2.1 What Core reads from a token

`IdentityProvider` (server/src/main/java/com/epam/aidial/core/server/security/) builds
`ExtractedClaims(userId, userRoles, userHash, userClaims, projectUser, userDisplayName)`:

| Consumed | Configured by | Note |
|---|---|---|
| `userId` | `userIdPath` (default `sub`; may be `oid`) | user bucket `Users/{userId}/` (BucketBuilder), per-user credential resolution, `/v1/user/info` |
| `userRoles` | `rolePath` — string **or array** of paths; optional `rolesDelimiter` | DIAL authorization |
| `userHash` | `loggingKey` + `loggingSalt` (SHA-256) | obfuscated user logging |
| `projectUser` | `projectPath` (optional) | project identity, bucket scoping |
| `userDisplayName` | `userDisplayName` (optional) | authors on publications/shares/logs |
| **whole payload** | n/a — `extractUserClaims` returns the entire JWT claim map | forwarded to `ProxyContext.getUserClaims()` → usage logs (`GfLogStore`), analytics (`AnalyticsLogContext`), background-job records |

Verification itself (`verifyJwt`): RSA256 via JWKS by `kid`; **`aud` checked only when
the IdP entry configures `audience`** (`IdentityProvider.java:362-365`); `iss` matched
against `issuerPattern`; standard `exp`. `offlineClient` unset ⇒ the provider cannot
mint DIAL_NATIVE offline credentials.

### 2.2 The local deployment's live values
(`../dial-instance/docker-compose.yml`, Core `environment` — this is the ONLY
live config; there is no `aidial.settings.json`):

```
aidial.identityProviders.keycloak.jwksUrl      = http://keycloak:8900/realms/dial/protocol/openid-connect/certs
aidial.identityProviders.keycloak.rolePath     = roles
aidial.identityProviders.keycloak.projectPath  = project
aidial.identityProviders.keycloak.loggingKey   = email
aidial.identityProviders.keycloak.loggingSalt  = loggingSalt
# issuerPattern: ABSENT    audience: ABSENT
```

- `issuerPattern` is **absent** from the Keycloak entry. With two providers, Core
  selects by issuer match; a provider without a pattern can never match. The spike must
  add it (`design.md` §10.1's "easy to miss, strictly required").
- `audience` is absent ⇒ the `dial-mcp-proxy` audience marker is a *new* enforcement,
  not a mirrored one.
- `core/config.json` has `"toolsets": {}` — the `notion` toolset is registered
  imperatively: `PUT /v1/toolsets/platform/notion` with body limited to
  `{display_name, endpoint: "https://mcp.notion.com/mcp", transport: "HTTP",
  auth_settings: {authentication_type: "OAUTH", redirect_uri: …}}` — the validator
  (`OauthAuthSettingsValidator`) **forbids** `client_id`/`client_secret`/
  `authorization_endpoint`/`token_endpoint`/`scopes_supported` in dynamic-registration
  mode.
- **Trap:** `settings/settings.json` (mounted at `/opt/settings`, used only for
  `gflog.xml`) contains an unused `identityProviders.test` with
  `disableJwtVerification: true` and plaintext secrets. Not the live config; not a model.

### 2.3 The required claim set is larger than the entry's paths

`RuleMatcher.match` (security/RuleMatcher.java:28-38) evaluates authorization rules per
request against **arbitrary claim paths** — `rule.getSource()` is any claim, not just
`roles`. The local admin rule is `{"source": "roles", "function": "EQUAL",
"targets": ["admin"]}` (from `aidial.access.admin.rules`). A deployment may write rules
on other claims; whatever its rules reference must be carried by the minted token or the
rule silently never matches.

### 2.4 Per-call authorization is live — over token claims

`AccessService.lookupPermissions` runs its rule chain per request; its inputs are
`context.getExtractedClaims()` — **the claims the token carried**. The mechanism is
per-call; the *inputs* are as fresh as the token.

## 3. Verified facts — the local environment

- **No front nginx exists.** The instance compose's only nginx
  (`adapter/nginx.conf`, service `dial-upstream-adapter`, `:5010`) is an **egress
  passthrough for model upstreams** — do not repurpose. `DR-0001` reasons about a front
  router as if it pre-exists; here it is **new work** (service + config).
- **Realm** (`keycloak/import/realm-config.json`, partial export — no `clientPolicies`
  or `components`; registration policies live in Keycloak's DB, mutated at runtime):
  `accessTokenLifespan: 86400` (**24 h**), `ssoSessionIdleTimeout: 86400`,
  `sslRequired: none`; realm roles empty (DIAL roles come from
  `keycloak/providers/aidial-keycloak-mappers.jar`); `clientScopes` include
  `profile, email, offline_access` — **`openid` is NOT a Keycloak client scope here**
  (advertising it fails registration wholesale). Users: `dial`/`dial` (attribute
  `project: ["proj-alpha"]`), `user`, `dial-admin`. Closest template for the gateway's
  pre-registered public PKCE client: `dial-sso-desktop-claude` (standard flow only,
  S256, `project` user-attribute→claim mapper, default scopes `profile,email`).
- **Ports.** Gateway origin fixed by `.env.example`:
  `GATEWAY_PUBLIC_ORIGIN=http://localhost:8090`. In use: 8081 Core, 8443/8900 Keycloak
  (issuer is `https://keycloak:8443/realms/dial`; requires Windows hosts entry
  `127.0.0.1 keycloak`), 6600 redis (host-side), 8765 current allowed toolset callback,
  8766 LiteLLM PoB loopback, 3100–3105/8082 chat/admin.
- **Instance repo state is dirty** (modified `docker-compose.yml`,
  `keycloak/import/realm-config.json`, `adapter/nginx.conf`; large untracked scratch
  `.mcp-poc/`, `specs/`, `keycloak/providers/`). **The change must not depend on
  untracked scratch surviving.**
- **Known PoC-A recipes** (from `docs/background/poc-dial-mcp-signin.md`): the
  `/signin` body `{url, credentialsLevel: "USER", authenticationType: "OAUTH", code,
  redirectUri}`; identity is client-independent (tokens from different Keycloak clients
  share the user's `sub`); Cloudflare rejects `Python-urllib` User-Agents (send an
  explicit UA); Node needs `NODE_EXTRA_CA_CERTS` for the local Keycloak cert; the first
  upstream call after sign-in can exceed 60 s.

## 4. Tensions and options (yours to decide)

### 4.1 The refresh staleness question

Per-call authorization runs on token claims (§2.4). The two refresh paths differ:

| Path | What refresh re-reads | Staleness bound |
|---|---|---|
| Harness refreshes at Keycloak (vanilla DIAL) | Keycloak re-mints from current realm state — when a token is re-minted | the realm's `accessTokenLifespan` — **24 h locally** |
| Harness refreshes at the gateway (self-contained refresh token) | the gateway re-emits a frozen snapshot; it holds no Keycloak credential | `refreshTtl` |

Notes: the `8h` in `design.md` §10.3 is an unexplained draft placeholder, and the local
realm's own lifespan is 24 h — the number to beat is the deployment's own token
lifespan. What the gateway adds over vanilla is *unbounded re-minting* within
`refreshTtl`.

**Options (record all; choose one for v1):**

| Option | Refresh token content | Staleness | Cost / residual |
|---|---|---|---|
| 1. Self-contained snapshot | `{sub, roles, project, resource, jti, exp}` | `refreshTtl` | simplest; role revocation lags up to `refreshTtl` |
| 2. s2s claims re-fetch at refresh | `{sub, resource, jti, exp}` | ≈ access TTL (Keycloak parity) | one technical Keycloak client (client-credentials, read-only over all users' roles); one s2s call per refresh |
| 3. Userinfo-mode IdP entry | n/a | ≤ ~1 min (Core caches userinfo 60 s — `USER_INFO_EXP_PERIOD_MS`) | the gateway becomes a claim-resolution dependency of every Core call; fails closed if down |
| 4. 2 + sealed capability token | JWE `{sub, resource, jti, exp}` — no roles | ≈ access TTL | combines 2 with a confidential refresh artifact; sealing alone does not fix staleness |

Whatever you choose: no Keycloak refresh token is ever stored (the gateway's Keycloak
client requests no `offline_access`); the upstream credential's refresh stays entirely
Core's job (`OauthTokenRefreshStrategy`). The harness's refresh dance itself is fixed by
the design (grant at `/dial/token`, `resource` must match, rotation configurable — PoC C
criterion 2 measures whether the harness adopts rotation). **The owner takes the
revocation-SLA decision after PoC C** — your choice ships in v1 and is revisited with
measured evidence.

### 4.2 The claim copy is deployment-specific

`design.md` §10.3 anticipates configurability for roles only (`roles_source_path`).
Every claim in §2.1 varies by deployment (see §2.2's local values; `roles` is not native
Keycloak — it exists locally only via the mappers jar; `userIdPath` may be `oid`;
`loggingKey` may not be `email`). **Tension:** the copy map is an authorization policy
expressed as config — an error yields a role-less token, an unresolvable identity
(invariant 3 breakage), or a rule that never matches, **silently** (cf. review m-6 and
`design.md`'s SR-2 caveat). You decide how it is configured, whether mistakes are caught
at startup or at authorization time, and how broadly to copy given §2.1's whole-payload
telemetry forwarding.

### 4.3 Considered-and-rejected variants (keep on the record)

- **Keycloak token exchange (RFC 8693)** — collapses into the same fork: harness holds
  realm-wide material, or the gateway holds the refresh token and mints its own handles.
- **Hand the Keycloak token through at `/token`** — rejected: harness holds the user's
  realm-wide SSO credential; revocation degenerates to killing the whole SSO session;
  the Keycloak client needs the same mapper/audience setup anyway; reintroduces the
  cross-issuer acceptance class the `dial-mcp-proxy` audience marker kills.
- **Sealed Keycloak tokens (`design.md` alternative B)** — distinct from option 4
  above; B seals *Keycloak* material and distributes it to harnesses.

### 4.4 One asymmetry worth keeping in the honest list

The gateway's signing key is as powerful as Keycloak's (`design.md` §6.2 says so), but
equal *key power* is not equal *issuance policy*: the gateway only mints derived tokens
— after a live Keycloak authentication of that `sub`, after the flow's DIAL-authorization
check, never offline/DIAL_NATIVE credentials. Key custody is the permanent cost
(invariant 7); narrower issuance paths are the mitigation.

## 5. The spike (first task block; sonnet-executed, not by you)

Stage 0 (`ROADMAP.md`): mint an RS256 keypair and a JWT carrying a real user identity
whose claims match §2.2's actual config (`iss`, `sub`, `roles`, `project`, `email`);
register the signer in Core as an additional IdP (`jwksUrl`, `issuerPattern`,
`audience`) **and add the missing `issuerPattern` to the Keycloak entry**; confirm
`GET /v1/user/info` resolves the identity and a toolset MCP call resolves that user's
upstream credential. **Negative controls first** (all must reject): mismatched issuer;
missing `audience` marker; wrong signing key. **Falsification stop:** if Core refuses
the minted JWT, halt and revise the design — not a defect to iterate on. Do not commit
tokens or keys (invariants 5, 6, 7; `.gitignore` already blocks `*.jwt`, `*.pem`,
`*.key` — which also means **evidence must be redacted at capture time** or it will
silently fail to commit).

## 6. The review-finding debt ledger (address each, show where)

`design-review.md` is the design's debt ledger; your `design.md` should show, per
finding, where it is addressed. Numbering trap: `design.md` cites `M-1/M-2/M-3` and
`m-1/m-3/m-4/m-5/m-6/m-10`; the review's own IDs are `MA-1/MA-2/MA-3` and
`mi-1/mi-3/mi-4/mi-5/mi-6/mi-10` (same findings).

| ID | One-line |
|---|---|
| BL-1 | Per-toolset AS issuer/insert-path surface is falsified by measurement; `resource` is the primary disambiguator; one flat issuer, flat AS metadata |
| BL-2 | "Flow not yet PoC'd" is a gate with fixed criteria, not an open question |
| MA-1 | Core never verifies `aud` unless configured — configure `audience: dial-mcp-proxy`; CR-1 downgraded to partially met |
| MA-2 | nginx data path must use `$is_args$args` and a configured external origin (never `$host`) |
| MA-3 | OAUTH-only mapping invariant, enforced at startup (a non-OAUTH mapping = unsatisfiable 401 loop) |
| MA-4 | CIMD is the primary registration path (Claude Code makes no `/register` call); the CIMD fetch is an SSRF surface |
| mi-1 | PoC B's evidentiary reach overstated (scripted probes, not a harness) |
| mi-2 | Toolset-settings path is `/v1/toolsets/{bucket}/{name}` — **half-fixed in design.md; the prose at §4.1 step 4 vs the config sketch must agree, and the recon found `PUT /v1/toolsets/platform/notion` is the real creation call** |
| mi-3 | Flow ids: 128-bit CSPRNG (entropy kills the code-injection chain at E7) |
| mi-4 | E3/E4/E5 are unauthenticated state allocators — rate limits + a hard cap on live flows |
| mi-5 | Keycloak-JWT exposure window = min(flow TTL, the JWT's own `exp`) |
| mi-6 | Roles: name the source path; a naive literal-`roles` copy yields silently role-less tokens |
| mi-7 | FR-3: met for OAUTH toolsets only; non-OAUTH excluded from v1 mapping |
| mi-8 | `resource` check strict by default; lenient only as config fallback |
| mi-9 | The 401 rewrite stretches "splitter ONLY" — sign-off (granted, §1.4) |
| mi-10 | Mirror `loggingKey`/`loggingSalt` on the gateway's IdP entry |

**Open gaps with no OQ number yet:** MA-4's SSRF controls are referenced
(`cimd_allowed_origins`) but never *specified* (HTTPS-only, no redirects to
private/loopback ranges, size cap — decide and specify); DR-0001's
reserved-toolset-name collision in the nginx routing regex (build-time detail — give it
a home); DR-0001's "required amendment if nginx is ever dropped" (FR-3's carrier moving
into the flat AS metadata) is contingent, correctly not open now.

## 7. Environment touchpoints

Create in this repo: the change artifacts; `pyproject.toml` (FastAPI/uvicorn,
`pyjwt[crypto]`, httpx, pydantic-settings, pytest+respx; ruff/mypy/bandit config); the
gateway package (E1–E10, flow store, CIMD resolution, JWKS, audit); `Dockerfile`
(`python:3.12-slim`, non-root); `docker-compose.yml` (service name
`mcp-signin-gateway` per design.md:785); the new front-router nginx config
(`design.md` §4.4 block: `$is_args$args`, `proxy_buffering off`,
`proxy_intercept_errors on`, `error_page 401 = @mcp_challenge`, configured
`$mcp_origin`); the Keycloak provisioning script the docs promise (F-J;
`KEYCLOAK_ADMIN_*` from `.env` — the sibling's scratch script hardcodes `admin`/`admin`,
contrary to repo rules; do not copy it verbatim); `.env.example` additions only;
tests.

Modify in the sibling instance (config, not code): Core env vars — add `issuerPattern`
to the Keycloak entry; add `aidial.identityProviders.dial-mcp-proxy.*` (`jwksUrl`,
`issuerPattern`, `rolePath: roles`, `audience: dial-mcp-proxy`, `loggingKey`/
`loggingSalt` mirroring the Keycloak entry); point
`aidial.toolsets.security.authorizationServers` at the gateway origin; add the gateway's
upstream callback to `allowedRedirectUris`; **do not add `openid` to
`scopesSupported`**; apply with `wsl -e docker compose up -d --force-recreate core`.
Keycloak: one pre-registered public PKCE client `dial-mcp-proxy` (S256, no secret, no
`offline_access`) + a `project` mapper. Also fix: `docs/local-environment.md`'s promise
of a script in `scripts/` (absent — write it or correct the sentence) and its
`aidial.settings.json` description (here: env vars in the instance compose).

**Delegated to you:** the front-router listening port; whether the gateway joins the
instance's compose network or ships its own compose beside it; the delta spec's
capability path (first change in the repo — sets the precedent).

## 8. Mechanics (validated against the openspec CLI v1.14.0)

- Artifact dependency order: `proposal` ← `specs` ← (`design`) ← `tasks`.
- Delta spec: `# Spec Delta` H1; `## Purpose` **required here** (no main spec exists —
  every capability is new; 50+ chars); `## ADDED Requirements` (express the PoC as
  ADDED — MODIFIED/RENAMED block the sync against a nonexistent main spec);
  `### Requirement: <name>` + `#### Scenario: <name>` (exactly four hashes); every
  requirement needs ≥1 scenario; requirement text ≤500 chars; normative SHALL/MUST;
  **spec text carries behavior and its reason — never provenance** (no "the owner", no
  change-folder paths, no "per the review").
- `tasks.md`: `- [ ] N.M <description>` under `## N. <Name>` groups; every task states
  its own verification; every group lands its own tests and docs; the final group is
  integration checks only (PoC C's five criteria live there).
- `release-notes-draft.md`: `### For users` then `### For the team` (both always
  present; if nothing user-visible: `No visible change this release.`).
- Evidence goes in `evidence/` — **redacted at capture time** (see §5's .gitignore trap).
- Validate with `openspec validate --changes --strict` before you finish.
- Artifacts in **English** (`openspec/config.yaml`).
