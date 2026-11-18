# Design

## Context

The converged design is alternative C of `docs/background/design.md`: a small MCP
sign-in gateway beside DIAL Core, registered in Core as an additional identity
provider, behind a front-router nginx that keeps the MCP data path direct to Core and
rewrites 401s into the gateway's own challenge. It was adversarially reviewed
(`docs/background/design-review.md`); this change implements the entire PoC — the
falsifiable spike, the gateway, the routing, the deployment configuration, and the PoC C
acceptance gate — as one change by owner decision.

Verified environment facts that shape every decision below (source-checked 2026-10-17/18
against the local Core `deps-v2` and the sibling instance):

- **Core's claim consumption.** Core reads `userIdPath` (default `sub`), `rolePath`
  (string or array of paths), optional `projectPath`, optional `userDisplayName`, and
  the **whole JWT payload** for telemetry (usage logs, analytics, background jobs).
  Authorization rules (`RuleMatcher`) evaluate **arbitrary claim paths** — the local
  admin rule matches `roles`, but a deployment may write rules on any claim. Whatever
  its rules reference must be in the token or the rule silently never matches.
- **Core's verification.** RSA256 via JWKS by `kid`; `aud` is checked only when the
  provider entry configures `audience`; `iss` is matched against `issuerPattern`; with
  two providers, selection is by issuer match, so **every provider entry needs a
  pattern** — and the local Keycloak entry currently has none.
- **The local deployment's live values** (instance `docker-compose.yml`, Core
  `environment` — there is no `aidial.settings.json`): `rolePath: roles`,
  `projectPath: project`, `loggingKey: email`, `loggingSalt: loggingSalt`, no
  `issuerPattern`, no `audience`; the realm's `accessTokenLifespan` is **24 h**;
  `authorizationServers` currently names Keycloak; `allowedRedirectUris` is one
  loopback callback. The `notion` toolset is registered imperatively via
  `PUT /v1/toolsets/platform/notion` (dynamic-registration mode forbids
  `client_id`/`client_secret`/endpoint/scopes fields in the body).
- **No front nginx exists** — the instance's only nginx is an egress passthrough for
  model upstreams and is not repurposed. The front router is new work: a new service
  plus config.
- The realm's client scopes include `profile`, `email`, `basic`, `offline_access`;
  **`openid` is not a Keycloak client scope here** and must never be advertised. The
  token's `sub` is minted by the realm's `basic` client scope (its `sub` mapper), not
  by `profile` or `email` — a client whose default scopes omit `basic` mints tokens
  with no `sub` at all, and `basic` never appears in the requested scope string. DIAL
  roles are minted by the `aidial-keycloak-mappers.jar` mappers, not realm roles. The
  closest template for the gateway's Keycloak client is `dial-sso-desktop-claude`
  (standard flow, S256, `project` mapper, default scopes `profile,email` — a set
  correct only for a client whose subject nobody reads; this deployment's Core
  authorizes on the subject, so the managed set differs, D9).
- Ports in use: 8081 Core, 8443/8900 Keycloak, 6600 redis, 8765 current toolset
  callback, 8766 LiteLLM loopback, 3100–3105/8082 chat/admin.
  `GATEWAY_PUBLIC_ORIGIN=http://localhost:8090` is fixed by `.env.example`.

Constraints that are not mine to change: no Core code changes (config only on the
sibling); the never-cut list in `ROADMAP.md`; the gate ladder in `PROCESS.md`/`CLAUDE.md`;
`.gitignore` already blocks `*.jwt`, `*.pem`, `*.key`, so evidence must be redacted at
capture time or it will silently fail to commit.

## Goals / Non-Goals

**Goals:**

- Prove the chain end to end: Core trusting a gateway-minted JWT (the falsifiable
  spike), the full gateway behavior, the front routing, and PoC C's five criteria on a
  real harness.
- Keep every footprint except this repo's own code **configuration-only** on the
  sibling instance.
- Resolve every review finding from the debt ledger explicitly (below), and close the
  two open gaps (CIMD SSRF controls; reserved toolset names) by specifying them.
- Keep the gateway a small, single-purpose, internal-logic-only service; no
  harness-specific code anywhere.

**Non-Goals** (beyond the proposal's out-of-scope list, at design level):

- Production key custody (KMS/HSM): the PoC's signing key is a generated RSA key in a
  gitignored path injected via `.env`; the KMS/HSM and `kid`-rotation procedure is
  documented as the production control, not built.
- Freshness beyond the refresh-TTL bound (no per-refresh claim re-fetch from the
  identity provider in v1 — see D3 for why, and what the upgrade path is).
- Redis-backed shared state (single instance; loss semantics are specified).
- Any change to Core's credential model, resolution order, or its own discovery
  surface beyond the env vars listed below.

## Decisions

### D1 — One change, spike first, hard falsification stop

The whole PoC is one change (owner decision, recorded in `proposal.md`), and its first
task group is the Stage 0 spike: mint an RS256 keypair and a JWT carrying a real user's
claims, register the signer in Core as an additional IdP, and confirm Core resolves the
identity and a toolset call resolves that user's upstream credential — negative controls
first (mismatched issuer, missing audience marker, wrong signing key). **If Core
refuses the gateway-minted JWT in the positive control, the spike halts the change:**
that is a falsification of alternative C, and the design is revised before any
implementation begins. It is not a defect to iterate around. The spike is executed by
an implementation subagent; this document only specifies it.

The spike establishes its own preconditions from **committed material only**, so the
falsification gate can never be blocked or improvised on: the `notion` toolset is
registered in Core by a committed helper running the documented recipe
(`PUT /v1/toolsets/platform/notion`, body limited to `display_name`, `endpoint`,
`transport`, and `auth_settings` with `authentication_type` + `redirect_uri`), and the
test user's upstream credential is established by a committed helper running the
documented sign-in recipe (`POST /v1/ops/toolset/signin` with the user's identity
token, the upstream code, and the callback URI at USER level). Both calls carry
credentials, and their sourcing is fixed here: the registration call is admin-gated in
Core (403 unless authorized — locally the test user's `admin` client role reaches the
token's `roles` through the chat client's client-roles mapper, so one credential pair
serves both calls), and the sign-in recipe runs as the test user. Any machine
credential those committed helpers use comes from `.env` (gitignored), with
`.env.example` placeholders (`TEST_USER_NAME`/`TEST_USER_PASSWORD` are already
present) — never hardcoded, the same `.env` pattern the Keycloak provisioning script
follows (D9); a hardcoded password in a committed script is a blocking defect, and no
credential material is printed or committed. Nothing in group 1 depends on the
sibling instance's untracked scratch: the instance contributes only its committed
compose shape (live Core, live Keycloak).

### D2 — Stack and roles

Python 3.12 + FastAPI (uvicorn, `pyjwt[crypto]`, httpx, pydantic-settings,
pytest + respx), matching the repo's toolchain (venv, ruff, mypy, bandit, pip-audit)
— owner decision. Roles per `PROCESS.md`: authoring and review are opus subagents;
spike/implementation/gate runs are sonnet subagents.

### D3 — Refresh: option 1, a self-contained snapshot, with a bounded staleness rule

Per-call authorization runs on the claims the token carries, so the refresh design
sets how stale a revoked role can be. The options and their measured costs:

| Option | Refresh token content | Staleness bound | Cost / residual |
|---|---|---|---|
| **1. Self-contained snapshot (chosen)** | `{sub, roles, project, … copied claims, resource, jti, exp}` | `refreshTtl` | simplest; no new credentials; role revocation lags up to `refreshTtl` |
| 2. s2s claims re-fetch at refresh | `{sub, resource, jti, exp}` | ≈ access TTL | one technical Keycloak client (client-credentials, read over **all** users' roles) held by the gateway; one s2s call per refresh; Keycloak becomes a dependency of every refresh (fails closed when down) |
| 3. Userinfo-mode IdP entry | n/a | ≤ ~1 min (Core caches userinfo 60 s) | the gateway becomes a claim-resolution dependency of **every Core call**; fails closed if down |
| 4. 2 + sealed capability token (JWE) | JWE `{sub, resource, jti, exp}` | ≈ access TTL | all of 2's costs plus sealing; sealing alone does not fix staleness |

**Chosen: option 1.** Reasons:

1. **The staleness bound beats vanilla DIAL locally.** With vanilla DIAL the harness
   refreshes at Keycloak, which re-mints from current realm state only when a token is
   re-minted — bounded by the realm's `accessTokenLifespan`, **24 h locally**. Option 1
   with `refreshTtl = 8 h` (default) bounds role-revocation lag at 8 h — three times
   fresher than the deployment's own vanilla bound. The number to beat is the
   deployment's own token lifespan, not an abstract zero.
2. **The bound holds only if the refresh window is non-sliding.** A rotated refresh
   token that receives a fresh `exp` would make the snapshot live forever. The rotated
   token therefore carries the **original absolute `exp`**, frozen at issuance; the
   staleness bound is then exactly `refreshTtl`. This is specified as normative in the
   delta spec (non-sliding window).
3. **Startup-enforced bound:** `refreshTtl` MUST NOT exceed the deployment IdP's
   access-token lifespan (locally: `8 h ≤ 24 h`), because the gateway must never be
   staler than vanilla. The gateway has no other way to know the IdP's lifespan, so it
   is a required operator setting (`IDP_ACCESS_TOKEN_LIFESPAN_SECONDS`), and startup
   refuses to run when `refreshTtl` exceeds it, naming both values — the bound is
   machine-checked, not a documented hope. What the gateway adds over vanilla is
   *unbounded re-minting within `refreshTtl`* — the harness refreshes forever inside
   the window with no browser, which is exactly the property that makes refresh
   tractable (no third-party rotation semantics).
4. **Options 2–4 buy freshness with new trust.** Each adds a credential or dependency
   the gateway would hold (option 2's technical client can read all users' roles — a
   new realm-wide secret on the component whose whole design goal is to hold no
   post-flow user secrets), or makes the gateway an availability dependency of the
   data path (option 3). Not worth it for v1.

**The revocation-SLA decision is the owner's, after PoC C**, with measured evidence
(criterion b: does the harness adopt rotated refresh tokens at all? how does it behave
near refresh expiry?). If the SLA demands fresher roles, option 2 is the upgrade path
(and option 3 is the ceiling); the design change would be localized to the refresh
grant and the Keycloak provisioning script. Considered-and-rejected variants stay on
the record in `docs/background/design.md` §5.1 (A: session store; B: sealed Keycloak
tokens) and in the authoring brief (Keycloak token exchange; passing the Keycloak
token through `/token`).

### D4 — Claim copy: copy-verbose, verify-loudly

The claim copy is deployment-specific (every consumed claim varies by deployment), and
an explicit **allowlist** copy map is authorization policy expressed as config — a
wrong entry yields a role-less token, an unresolvable identity, or a rule that never
matches, **silently**. Meanwhile Core forwards the **whole payload** to telemetry and
matches rules on **arbitrary claim paths**. The tension resolves in favor of fidelity:

- **Copy the whole identity token payload verbatim, minus a fixed blocklist of
  registry claims the gateway itself owns** (`iss`, `aud`, `exp`, `iat`, `nbf`,
  `jti`, `typ`, `azp`, `nonce`, `at_hash`, `c_hash`, `acr`, `cnf`, `scope`,
  `session_state`, `sid`). Deployment claim paths (`project`, `email`,
  `resource_access`, …) and whole-payload telemetry keep working with **no per-claim
  configuration at all**. The minted token is larger; that is accepted. (The harness
  holding the user's full claim set is no regression: vanilla harnesses hold the
  Keycloak token itself, which carries the same payload.)
  **Caveat — deployment authorization rules MUST NOT key on a blocklisted claim**
  (`scope`, `acr`, or any other name on the list above): gateway tokens never carry
  them, and Core's RuleMatcher may legally key rules on any claim path, so a rule on
  a blocklisted name silently never matches — the exact silent-never-match failure
  the copy-verbose choice exists to prevent. A rule that needs one of those names is
  a deployment configuration error to fix in the rule, never in the gateway; the
  caveat is stated wherever the blocklist is stated (D4 here and the gateway
  configuration reference).
- **Overlay, don't branch:** after the copy, roles are re-emitted as a plain array at
  the claim name Core's gateway provider entry reads (`roles`), read from a
  **required, operator-configured source path in the identity token** (locally:
  `roles`, mirroring Core's Keycloak entry `rolePath`). No default: a silent default is
  exactly the trap. The overlay order (copy first, overlay second) also makes an
  unrelated claim that happens to be named `roles` harmless.
- **Fail loudly where silence is the failure mode:** if the configured roles source
  path is **absent** from the identity token, issuance is refused with an
  operator-facing configuration error — a misconfigured path is a deployment error,
  not user state. If the path **resolves to an empty value**, the user legitimately
  has no roles and the empty array is copied as-is. This is the distinction that
  turns the silent role-less-token failure into a diagnosed one.
- **Startup vs issuance time:** mapping shape, reserved names, and required settings
  are validated at startup (D6); the roles-path resolution can only be checked against
  a live identity token, so it is checked at issuance, loudly.

### D5 — CIMD is the primary registration path, with the SSRF controls specified

Claude Code registers by presenting a URL-shaped client id and making no `/register`
call when the AS metadata advertises `client_id_metadata_document_supported`. CIMD
fetch-and-validate is therefore load-bearing, and the fetch is a server-side request
forgery surface a client steers. Controls (all normative in the delta spec):

- HTTPS only; the client-id URL's origin MUST be on the operator allowlist
  (`cimd_allowed_origins`; default: the known harness metadata origin).
- **No redirects are followed** — a 3xx fails the fetch. A redirect is exactly the
  pivot an SSRF attacker needs; there is no legitimate use here.
- The resolved address (all A/AAAA records) is checked against private, loopback, and
  link-local ranges, and the connection is made to a validated address (pinning the
  connection to the validated IP with Host/SNI preserved, so a rebinding answers to
  the name but cannot redirect the connection).
- Response size capped (64 KiB), JSON content type required, connect/total timeouts
  (5 s / 10 s), responses cached by client-id URL with a TTL and a bounded cache.
- **An explicit, non-default `User-Agent` header** on the fetch. The CIMD origin for the
  flagship harness is fronted by bot protection that rejects library-default agents
  (`python-httpx/x` class) outright; a default-UA fetch would surface as a late,
  misleading registration failure in PoC C rather than at implementation time.
- `redirect_uri` on every subsequent authorization request must match a registered
  entry: exact string equality, except for a registered entry that is a loopback
  redirect URI (`http` scheme; host `localhost`, `127.0.0.1`, or `[::1]`), which
  matches on identical scheme, host, and path with the port ignored on both sides —
  a registered explicit-port entry, a default port included, matches a port-varied
  request too, and only the port is excepted: any query or fragment presence or
  difference is non-matching. The exception is
  measured harness behavior, not loosening: native clients bind an OS-chosen
  ephemeral port at launch and are entitled to present it (RFC 8252 §7.3/§8.4),
  while the client-metadata document registers its loopback callbacks port-less,
  so exact membership refuses every live harness request for its port alone. It is
  keyed on the registered entry, never on the request's value, and extends to no
  `https` entry, no non-loopback host, and no scheme or path difference. DCR stays
  config-gated, default off, with its registration records durable across restarts
  (D11).

### D6 — Mapping safety: OAUTH-only, reserved names, regex order as defense

- **OAUTH-only mapping, enforced at startup, no escape:** a non-OAuth toolset entry
  refuses startup unconditionally — an OAuth challenge in front of a non-OAuth
  credential is an unsatisfiable 401 loop that fails silently at the operator's
  config step. The `route_only` escape the background design sketched (paths served
  through the front door without the challenge rewrite) is dropped: the router is
  static nginx with no view of the mapping, so the promise cannot be kept there. The
  only mechanisms that could keep it are generated per-toolset locations — coupling
  every mapping change to a router regeneration and reload — or moving challenge
  synthesis into the gateway, which puts the gateway on the MCP data path it is
  deliberately absent from. A non-OAuth toolset stays reachable through Core's own
  paths via the router's catch-all, unchanged; a front-door spelling for non-OAuth
  kinds belongs to the API-key wrapper work (open question 3), which brings its own
  routing mechanism.
- **Reserved toolset names, enforced at startup:** the mapping refuses the names whose
  MCP path the front door's gateway-owned routing would capture — `authorize`, `token`,
  `register`, `revoke`, `callback`, `jwks.json` — because the nginx location for the AS
  surface (`/dial/(callback|jwks\.json|authorize|token|register|revoke)(/|$)`) matches
  `/dial/<name>/…` for exactly those names before the data-path regex can, so a toolset
  so named could never have its `/dial/<name>/mcp` traffic routed to Core. The reserved
  set mirrors the router's alternation verbatim, so the guard and the routing stay in
  step when either changes (`jwks.json` is unreachable as a name under the
  `^[a-z0-9-]+$` charset but stays listed for that fidelity). This gives the
  reserved-name collision a normative home instead of a build-time comment. The nginx
  config additionally orders the AS-surface locations before the data-path regex, and
  the data path is anchored (`^/dial/<name>/mcp$`) — belt and braces; the startup check
  is the load-bearing fix.
- Toolset names are `^[a-z0-9-]+$` (the nginx regexes assume this shape).

### D7 — Topology: one public origin on 8090, own compose beside the instance, joined network

- **Front router (`mcp-signin-router`, nginx):** listens on host **:8090** — the fixed
  `GATEWAY_PUBLIC_ORIGIN`. It routes the AS/discovery surface to the gateway, the
  toolset MCP path to Core (`http://core:8080/v1/toolset/<name>/mcp$is_args$args`,
  `proxy_buffering off`), and everything else to Core. A 401 on the data path is
  answered with the gateway's challenge, synthesized in that same location:
  `proxy_hide_header WWW-Authenticate` removes Core's, and an `add_header` whose value
  comes from a `map $status` emits the gateway's on a 401 and nothing on any other
  status, quoting a configured `$mcp_origin`, never `$host`. The background design's
  `error_page 401 = @mcp_challenge` shape is deliberately not the mechanism: measured
  on this nginx image, an intercepted 401 re-serves the upstream response's headers,
  so Core's challenge survives into the rewritten response and `proxy_hide_header`
  has no effect on that path (five configurations measured, all leak). The property —
  every 401 carries the gateway's challenge and nothing of the upstream's — is what
  the spec requires, and the map+hide form is what delivers it.
- **Gateway (`mcp-signin-gateway`):** container-internal **:8091**, never host-published —
  the compose service carries no `ports:` mapping, ever. The router is its only front
  door **and the only authority for the peer identity**: the peer binding that scopes
  the gateway's trust to router-fronted requests holds only while every request that
  reaches 8091 crossed the router. A host-published 8091 admits requests whose peer
  identity the router never established, defeating the binding from outside the
  container — so the port staying unpublished is an invariant of the topology, stated
  by a comment at the compose gateway service and the router config. A `/healthz`
  endpoint serves the compose-boot health probe.
- **Compose placement:** the gateway and router ship in **this repo's own
  `docker-compose.yml`**, joined to the instance's compose network as an external
  network (name from `.env`, default `dial-instance_default` — the instance
  defines no explicit network, so its default network name is the project name).
  The change must not depend on the instance repo's untracked scratch surviving;
  only its committed compose shape (services `core:8080`, `keycloak`) is depended on.
- **Keycloak back-channel:** the gateway talks to Keycloak over its **internal http
  port** (`http://keycloak:8900` — the same port Core's `jwksUrl` already uses),
  avoiding the self-signed-TLS problem entirely for server-to-server calls; the
  browser-facing issuer stays `https://keycloak:8443/realms/dial` with the Windows
  hosts entry. Issuer matching is unaffected (the token's `iss` is the https issuer
  regardless of the port the token endpoint was reached on).

### D8 — Capability path: `mcp-signin`

The repo's first delta spec sets the precedent. Chosen: a single capability,
**`mcp-signin`**, named for the durable behavior (harness sign-in to DIAL MCP
toolsets), not the component or the change. It owns the whole chain — discovery,
registration, federation, tokens, routing, Core-side trust, abuse bounds, invariants,
and the acceptance gate — because from a client's perspective that is one behavior,
and splitting it would scatter one flow's requirements across files whose
implementation is one service plus its routing. Future capabilities (for example an
API-key toolset wrapper) add their own paths. All deltas are ADDED: no main spec
exists, and MODIFIED/RENAMED would block the sync.

### D9 — Keycloak provisioning script, credentials from `.env`

`scripts/provision_keycloak.py` (the script `docs/local-environment.md` promises)
creates the gateway's Keycloak client idempotently through the Keycloak Admin API:
public client `dial-mcp-proxy`, standard flow only, PKCE S256 required, no client
secret, redirect URI `http://localhost:8090/dial/callback/keycloak`, default client
scopes `profile,email,basic` (never `openid` — not a client scope in this realm;
never `offline_access`), and the mapper setup cloned from the
`dial-sso-desktop-claude` template (`project` user-attribute mapper plus the DIAL
roles mapper, so the minted token carries `sub`, `roles`, `project`, `email` under
the names Core's entries read). `basic` is in the managed set because `basic` is
what mints `sub` into the access token — its `sub` mapper, which `profile` and
`email` contribute nothing toward — so without it the identity the whole
copied-`sub` scheme depends on does not exist in the token; and `basic` never
appears in the requested scope string (`include.in.token.scope` off), so the
redirect still asks for `profile email` exactly.

The script **converges** the client's default scopes to exactly that set, removing
whatever the realm's own default-scope list attached on creation (here `web-origins`,
`acr`, `offline_access` and the role-bearing `roles` would otherwise ride along —
`offline_access` putting a refresh token on a flow that must never hold one, `roles`
importing a second, unmapped role source beside the configured DIAL roles mapper;
the wanted `profile`, `email`, `basic` are kept either way).
Convergence is designed behavior, not an implementation nicety: a client created
through the Admin API inherits the realm's default-scope list, so an
attach-only script leaves the client carrying the realm's set plus its own, not
the designed set. The script also verifies the minted claims by driving a real
flow (`--verify-claims`): the token must carry a present, non-empty `sub`, `roles`
and `project` — every claim Core's entries read — or provisioning fails loudly. A
client that cannot mint the identity the chain authorizes with is a deployment
error, and the one-time provisioning check catches it before any user flow is
affected.

Admin credentials come from
`KEYCLOAK_ADMIN_USER`/`KEYCLOAK_ADMIN_PASSWORD` in `.env` — the sibling's scratch
script hardcodes `admin`/`admin` and is **not** copied verbatim, per repo rules.

The realm's client-registration policy changes described in
`docs/local-environment.md` are **historical PoC-A state**: this design's harnesses
register against the gateway (CIMD/pre-registered), never against Keycloak, so no
realm security policy is touched (SR-6). The doc's sentence is corrected accordingly
in the tasks.

### D10 — Scope handling: the client's `scope` never reaches the identity-provider leg

A harness may send `scope` on `/dial/authorize` (OAuth clients echo the scopes the
protected-resource document advertised). That parameter MUST NOT be relayed onto the
Keycloak redirect: the redirect requests exactly the gateway's pre-registered client's
default scopes (locally `profile,email,basic` — of which only `profile email` appears
in the requested scope string, because `basic` contributes its `sub` mapper without
entering it), because a scope the client does not carry —
or that is not a client scope in the realm at all, as `openid` is here — fails the
whole authorization leg with an opaque error. The gateway therefore accepts and drops
the `scope` parameter rather than validating it (rejecting it would break clients
that faithfully echo advertised upstream scopes, which are the well-behaved ones).

Scope advertising is split the same way: the per-toolset protected-resource document
carries the toolset's upstream `scopes_supported` verbatim (they belong to the upstream
leg, whose authorize URL is built from the toolset's *public settings*, not from the
harness's parameters), while the flat AS metadata advertises no scopes of its own —
the gateway enforces no scopes, so advertising any would be an invitation to echo them
back. The identity-provider leg's scope set lives in the gateway's client
configuration (D9), not in any client-supplied parameter.

### D11 — DCR registration records: one JSON file in a mounted volume

DCR registrations are the only gateway state that both outlives a restart **and** is
cached by clients indefinitely, so they are the only state made durable in v1 —
deliberately with the simplest mechanism that survives a restart: **one JSON file in
a mounted volume**, no database, no lock manager, no schema.

**Mechanism:**

- **One JSON file** at `DCR_STORE_PATH` (container default
  `/data/dcr-registrations.json`), a bind-mounted volume on the gateway's compose
  service. A flat JSON object mapping client id → record, the record limited to
  `client_id`, `redirect_uris`, `client_name`, `created_at` — nothing else (all
  clients are public; no secret is ever stored, by the registration requirement).
- **Load at startup, write-through on registration.** The store backs the in-memory
  registration map; a successful registration is persisted **before** the response
  is returned, atomically: write a temporary file in the same directory, `os.replace`
  it over the store. A crash mid-write can leave a temporary file, never a
  half-written store. The save also attempts an owner-only file mode — **best-effort
  hardening, never a guarantee**: a volume on a filesystem without POSIX permission
  changes (a Windows host path bind-mounted into the container reaches it as the
  9p/DrvFs filesystem, where `chmod` fails with `EPERM` and every file carries the
  mount's fixed modes) is tolerated — the mode failure is logged as a warning naming
  the store path, the rename proceeds, and a registration is never refused for it.
  Where the volume's filesystem does enforce modes, the owner-only mode lands as
  attempted.
- **Corruption fails closed and loudly.** An unreadable or unparseable store at
  startup refuses to start, with an operator-facing error naming the path. Recovery
  is one command — rename the corrupt file aside and restart — and the operator
  has thereby acknowledged the loss. This is the same "fail loudly where silence is
  the failure mode" rule as the roles-path refusal (D4): silently starting empty
  would invalidate every registered client id without a trace, the exact failure
  class the flow-loss answer exists to avoid.
- **Tampering is trusted to the same boundary as the signing key.** The store's
  integrity is the host/volume owner's responsibility — the same trust boundary and
  the same class of material as the signing key, which host-level write access can
  likewise rewrite — so no tamper mechanism is added at this bar, and a well-formed
  tampered store is recovered by the corrupt-store path: rename the file aside,
  restart, harnesses re-register. The owner-only mode sits **inside** that boundary
  as hardening subordinate to it, which is why it is best-effort: on a mount without
  POSIX modes the store file is as readable as that mount makes every file in the
  volume — the host/volume owner's exposure to rule — and it holds no secret to
  expose (client ids, redirect URIs, a display name, a timestamp; every client is
  public PKCE). The **bind mount stays**, for the reason it was chosen at first: the
  store is plainly on the host, corrupt-store recovery is one command by path — the
  remedy the startup error itself states — and a lost store is a visible missing
  file. A Docker named volume would buy mode enforcement by trading that
  operator-visible shape away, for hardening the boundary already carries — and the
  save would still assume a filesystem any future non-POSIX deployment can
  withhold, so the tolerance lives in the save, not in the deployment.
- **Bounded.** A configured cap on stored registrations
  (`DCR_MAX_REGISTRATIONS`, default 1024); at the cap, the registration endpoint
  refuses new registrations with a plain-language error naming the cap, and existing
  registrations are untouched — evicting an oldest registration would invalidate a
  possibly live client, which is the dropped-store loss again but silent. The cap
  bounds the file at write time; there is **no expiry** — a registration's lifetime
  is the client's own choice, and an expired registration would recreate the
  harness-held-cached-id problem the store exists to prevent.
- **Flag semantics.** `DCR_ENABLED` gates the whole DCR path, resolution included:
  off (the default), the registration endpoint answers the documented
  disabled-error (404) and the AS metadata advertises no registration endpoint, and
  DCR client ids do not resolve. The store is preserved but dormant — re-enabling
  restores every registration as it was. The resolution priority stays
  pre-registered → CIMD → DCR.
- **What enabling DCR accepts.** Enabling DCR accepts open registration and
  registrant-supplied display attribution: the interstitial's `client_name` for a
  DCR client is registrant-controlled, and no allowlist bounds a DCR registration's
  redirect URIs. The exposure is bounded by the flag's default off, the
  public-endpoint abuse bounds, the live identity-provider login and DIAL
  authorization check every token still requires, and codes and tokens only ever
  reaching the registrant's own registered redirect URIs.

**Loss semantics (plain language, in the spirit of the flow-loss answer):** if the
store is lost, deleted, or reset, every DCR-registered client id stops resolving. A
harness holding a cached client id gets the unregistered-client rejection on its
next authorization request — not an opaque failure — and then does what it did the
first time: re-registers and continues. No human action is required; the loss costs
one re-registration round-trip per DCR harness and nothing else: issued access and
refresh tokens are self-contained JWTs that never consult the store, and the other
registration paths have no gateway-side registration state to lose (CIMD's source
of truth is the client's own metadata document at its URL; pre-registered clients
are operator configuration, inherently durable).

**State inventory interaction — why only the DCR records are durable:**

| State | Store (v1) | Why durable / not |
|---|---|---|
| DCR registration records | one JSON file in a mounted volume | unbounded lifetime, cached indefinitely by harnesses; loss breaks *future* flows, silently — the one state whose loss is neither self-evident nor self-healing without a round-trip |
| Flow records | in memory | 10-min TTL, mid-flight browser state; loss is the already-specified plain-language error page and a one-command retry — durability buys nothing for a state whose whole life is minutes |
| Authorization-code replay cache | in memory | 5-min single-use codes; loss is bounded by the code TTL and the PKCE binding (already specified and accepted) |
| Refresh denylist | in memory | loss is bounded by `refreshTtl` (≤ 8 h, never staler than vanilla), accepted on record |
| Issued tokens | nowhere | self-contained JWTs — restarts and scaling do not touch them |

The documented HA step (Redis) covers the in-memory maps; the DCR store moves with
them when that step is taken.

### D12 — The interstitial delivers the upstream request; it never relies on the browser preserving a URL

The upstream authorization request is specified as **what the upstream endpoint
receives** — never as what a rendered page contains — and the interstitial is its
delivery mechanism, so the page's continuation MUST NOT depend on a browser
preserving an action URL's query string. An HTML form with `method="get"` does not
preserve it: the submission **replaces** the action URL's query with the query built
from the form's successful controls, so a form whose action carries the parameters and
whose body carries no controls submits to the bare endpoint — every parameter
silently lost, including the flow id as `state`, so the callback round-trip the
credential depends on could never happen. The loss occurs inside the browser, after
the gateway's response is complete: the page's own text is correct, no server-side
seam can see the loss, and the failure surfaces only as the upstream's
`invalid_request` answer rather than anything the gateway renders. That is also why
an attribute-level test — one that asserts on the rendered `action` text — is
structurally blind to this class: the whole question is what a submission or
navigation *produces*, which is what the regression guard must assert on.

**Acceptable mechanisms (the implementation pass chooses):**

- **Hidden inputs carrying every parameter, with a bare action** — the interstitial
  stays a form and the entry list is the parameters themselves; or
- **The page continues itself** — a navigation to the built URL (an anchor, or a
  script/meta refresh), no form at all.

The page's own stated behavior is auto-continue — an attribution notice is a step
the user cannot act on, and stopping there for a manual button turns it into a second
consent the user has to give — so whichever mechanism lands, the template must match
that stated behavior: the page continues itself rather than waiting on a button.
The rejected mechanism, on record: a parameter-bearing `action` URL on a
`method="get"` form whose body carries no successful controls — the shape whose
delivery relies on the browser *appending* to the action's query rather than
replacing it, and it appends nothing.

**Fail-closed:** where the request cannot be delivered with every required parameter,
the flow fails with the plain-language error page and no parameter-less request is
sent. The settings-read refusal already guards the incomplete-projection case before
the URL is built; the delivery guard covers the step after it — the request the
browser would actually receive.

### D13 — One hardening header family on every HTML response, each directive earned by a page-class reason

The gateway serves exactly two classes of HTML page — the interstitial and the
plain-language error/flow pages — and every response of both classes carries one
shared header family. One helper, not per-page headers, because the family is a
property of the page classes, not of any one page: a per-page spelling is one omission
away from one page class silently drifting out of the family.

The family, each directive earning its place by what these pages specifically are:

- **`Content-Security-Policy: default-src 'none'` (+ `base-uri 'none'`)** — XSS depth.
  The interstitial renders registrant-supplied text (a DCR client's `client_name`) and
  every error page renders flow context; escaping is the active layer, and a `default-src
  'none'` policy with no source permitting script is the second layer if escaping ever
  regresses. The interstitial is script-free by its own mechanism (D12: meta-refresh +
  anchor, no script), so the policy needs no script source at all. Its inline style is
  the one non-default thing the page needs: the implementation may satisfy it with a
  nonce, a hash, or `'unsafe-inline'` — style injection is not an execution primitive,
  and the choice is traded there rather than pinned here. `base-uri 'none'` because no
  page needs a base URL and an injected `<base>` would relocate every relative URL.
- **`frame-ancestors 'none'` + `X-Frame-Options: DENY`** — an auto-continuing page
  advances an OAuth flow. Framed by an attacker's page, the interstitial's
  meta-refresh advances the upstream authorization leg inside a victim's browser with
  the victim's identity-provider session; framing a flow page can do the same to a
  retry. The legacy header rides along for the browsers that ignore the directive.
- **`Referrer-Policy: no-referrer`** — the sharpest one. The interstitial renders at
  the identity provider's callback (`/dial/callback/keycloak`), whose URL carries the
  provider's authorization **code** in its query — exchanged server-side before the
  page renders — plus the flow id as `state`, and its own behavior is to navigate
  onward to the upstream authorize endpoint. A default `Referer` on that navigation
  carries the callback URL — the provider-issued code and the flow state — to the
  upstream page and its third-party scripts: a cross-party leak (one party's issued
  code and flow state delivered to a different party's page), so nothing bounds it;
  `no-referrer` closes the class for one line, on the interstitial and the error
  pages alike, because error pages reflect user-controlled context and the same
  navigation out of them costs nothing to close.
- **`Cache-Control: no-store`** — a cached interstitial or flow page replayed is a
  stale-flow resubmission. The JSON and redirect responses already carry `no-store`
  (`gateway/errors.py`); the HTML pages join the same rule.
- **`X-Content-Type-Options: nosniff`** + explicit **`charset=utf-8`** on the
  `Content-Type` header — the pages carry `<meta charset>` already, but the header is
  what is read before the body is parsed; the meta tag is the fallback, not the
  carrier.

**Deliberately not pinned:**

- **HSTS / TLS.** TLS termination belongs to the router/deployment layer, not to the
  gateway's page responses — the gateway never sees the client's scheme behind the
  router. The committed router config adds **no** HSTS: its listener is plain http on
  8090 (the fixed `GATEWAY_PUBLIC_ORIGIN`, `http://localhost:8090`), and HSTS is
  defined for, and honored by browsers only on, TLS responses — an
  `add_header Strict-Transport-Security` there would be inert noise. A deployment that
  terminates TLS in front of the router adds HSTS at its own TLS listener; that is
  where the routing's design leaves it (D7's layer), stated here so the deployment
  layer knows it owns it.
- **Cookies.** The gateway serves none, so there is no cookie surface to pin
  (no `Secure`/`HttpOnly`/prefix rules to state).
- **JSON API responses.** The RFC 6749 JSON and redirect error responses already carry
  `no-store`; extending the referrer family to JSON responses is a separate, smaller
  question, not pinned by this family.

The normative home is the delta spec's HTML-response hardening requirement; the
implementation (the shared helper on both page-response paths, and a header-assertion
test per page class) is the next pass.

### Security impact analysis (against the never-cut list)

This change has **material security impact** — a new public AS surface and a new
IdP-equivalent signing key — so the security review gate on the implementation diff
runs at full depth; there is no "no security impact" claim to falsify.

| # | Invariant | Ruling |
|---|---|---|
| 1 | Upstream credential never leaves Core | **Preserved.** The gateway transits only the upstream *authorization code* — single-use, PKCE-bound to Core's verifier, useless to anyone else. No upstream access/refresh token ever transits or is stored by the gateway or any harness. No token passthrough: the front path authenticates to Core with gateway-minted tokens only. |
| 2 | Upstream PKCE verifier never leaves Core | **Preserved.** The gateway builds the upstream authorize URL from the toolset's *public* settings (`code_challenge`, never the verifier — Core nulls it on every public projection). No new exposure path exists. |
| 3 | Per-user credential isolation | **Preserved.** The credential API call is made with the live user's identity token at USER level; Core stamps and resolves per `sub` as today. The code-injection chain at the upstream callback (a guessed flow id pairing an attacker's code with a victim) is killed by 128-bit CSPRNG flow ids, state round-trip, and destroy-on-first-use — a kill-list that covers guessing, not interception; the interception variant is disclosed below. |
| 4 | DIAL authorization on every call | **Preserved, with a disclosed bound.** Every toolset call via the front door is validated and authorized by Core. The claims authorization runs on are a gateway-asserted snapshot at most `refreshTtl` old (see D3) — bounded fresher-than-vanilla locally, an accepted trade recorded in the risks. The flow additionally checks toolset read access *before* any upstream round-trip. |
| 5 | No credential in logs, argv, or errors | **Preserved.** Audit events carry flow id, subject, client, toolset, timestamps, and results — never tokens, codes, or keys. Error pages are plain-language and fail closed. Evidence is redacted at capture time (`.gitignore` blocks `*.jwt`/`*.pem`/`*.key`). The browser-side channel of the same invariant is closed by the response-header family (D13): no `Referer` leaves a page rendered at the identity provider's callback URL (which carries the provider-issued code, already exchanged server-side, and the flow state) toward the upstream's page and scripts, and no cached replay of a flow page exists. |
| 6 | No hardcoded credentials in the repo | **Preserved.** `.env.example` placeholders only; the Keycloak admin credentials and the signing key come from `.env`/injected material; `pip-audit`/bandit gates run on the diff. |
| 7 | Signing key as IdP-grade material | **Preserved.** Generated RSA key, gitignored, injected via environment, never logged; `kid` published in the JWKS; rotation procedure documented (publish new `kid` → wait Core's 10-minute JWKS cache → retire). The honest asymmetry is recorded below in risks: equal key power, narrower issuance policy. |

**Memory zeroization — an acknowledged residual, not a new class.** Secret material in
process memory — the signing key and the in-flight identity token — lives there for the
process lifetime: CPython has no reliable wipe-on-demand (immutable `str`/`bytes`,
unreachable copies held inside the JWT libraries, allocator/GC behavior, traceback
retention), which is the same managed-runtime reality as Java/Go/.NET, not a
Python-specific gap. The residual exposure is therefore the host-read/memory-dump class
the change's trust-boundary rulings already name — signing-key custody (never-cut 7)
and the DCR store's host/volume boundary (D11) — not a new class. It is bounded by the
never-store rules (no token at rest anywhere; the identity token serves the sign-in
flow's one decision step and one action — "may this user sign in, and are they signed
in?", then the credential call — and is dropped once the action is spent) and by the
TTLs (10-minute access tokens; the in-flight identity token
bounded by min(flow TTL, the provider's own `exp`)). The control that actually removes
key material from process memory is never materializing it: a KMS/HSM sign-interface
(`key_source: kms`, the stated production direction), where the process holds a key
reference, not a key.

**The token-use rule is stated in purposes, not counts.** The identity token serves
exactly the sign-in flow — its decision step and its credential call — and never
anything else. The presentation count is a property of the deployment's Core, not of
the flow: where the settings route enriches its answer with the per-caller statuses,
the decision step is one presentation (plus the credential call); where it does not,
the step needs the listing-route fallback, so the token is presented three times in
total — one more internal-network presentation to Core, within the same flow TTL and
for the same purpose, than an enriching build. That delta is the disclosed cost of
tolerating both Core builds; pinning the latest Core collapses the step back to one
presentation and is recorded as the post-PoC simplification (open question 7).

**The audit trail covers the whole request lifecycle, refusals before allocation
included.** The trail is the operator's record of every sign-in request the gateway
answers, not only of the flows that allocate one. A request refused *before* a flow
exists — an unknown client, a redirect-URI mismatch, a missing or unknown `resource`,
a token-endpoint validation failure, a `/dial/revoke` form refusal, a
`/dial/{name}/status` refusal, a limiter 429, a discovery miss — is exactly the "my
harness cannot connect / gets rejected" entry point the operator troubleshoots from,
and a silent refusal class forces the diagnosis to be reproduced with external
probes, the field shape the redirect-uri finding demonstrated. Every pre-allocation
refusal therefore lands on the trail with a fixed-vocabulary reason and the
non-credential facts the request offered (client id, redirect URI, resource,
toolset) — sufficient to diagnose, and inside never-cut 5's discipline: no token,
code, key, or verifier, and no free-form caller input, so a caller cannot write
content into the log. The delta spec pins the class as a requirement; the call-site
wiring is the implementation task.

**The E7 chain's interception variant — a disclosed residual, controlled at the
transport layer.** The defense trio (128-bit flow ids, state round-trip,
destroy-on-first-use) kills *guessing* a flow id; it does not address an attacker who
*intercepts* the victim's identity-provider callback URL off the wire. That URL
carries the provider's authorization code and the flow id as `state`, so an attacker
who captures it can deliver it to the gateway ahead of the victim's browser, pass the
flow lookup on a live flow, and complete the upstream consent in their own browser —
Core then stores the *attacker's* upstream credential under the *victim's* `sub`, and
the victim's toolset traffic executes against the attacker's workspace. The control
is transport security on the public origin: a TLS-fronted origin gives the interceptor
nothing to capture. The committed deployment runs the front door on plain http (D13
leaves TLS and HSTS to the deployment layer's own TLS listener), so the residual is
**disclosed, not mitigated here**: TLS-front the public origin before any
real-world use, and a deployment that runs the front door on plain http accepts this
variant. No delta-spec scenario pins it — the residual is a property of the
deployment's transport, not of gateway behavior, and a spec row cannot turn a
deployment property into one; this disclosure and the risk entry below are its home.

**The shared worker pool is a bounded shared resource — a flood-queue residual,
disclosed.** Every leg runs on one bounded shared worker pool, so a sustained flood of
slow-leg requests queues legitimate legs behind the attacker's queue. The event loop
itself stays responsive (slow work is offloaded off it), and the one slow leg an
unauthenticated caller steers is the CIMD fetch — its target is caller-chosen — so a
capacity limiter on the CIMD fetch bounds an attacker-chosen fetch's pool occupancy:
an attacker cannot hold more than the limiter's share of workers with fetches they
steer, and the identity and credential legs keep capacity. What remains is queue-wait
behind attacker-shaped slow requests within the rate limits — inherent to any bounded
shared resource, accepted on record here and bounded by the public-endpoint abuse
limits.

### Owner rulings recorded (sign-offs granted)

Both sign-offs the converged design called for are **granted** by the owner and are
recorded here as rulings, not open questions:

1. **The OR-2 deviation** — one additional always-on server-side component (the
   gateway), plus the front-router config on infrastructure of the class any
   deployment already runs in front of Core. Accepted.
2. **The nginx 401 synthesis** — a `map $status`-driven `add_header WWW-Authenticate`
   plus `proxy_hide_header` in the data-path location makes the router synthesize the
   gateway's challenge rather than purely split traffic. Accepted; no config-only
   alternative fixes the F-1 misdirection. (The `error_page 401` spelling first
   sketched was replaced after measurement — an intercepted 401 re-serves the
   upstream's headers, so it cannot deliver the property; see D7.)

The keep-nginx decision (`docs/background/decisions/DR-0001-keep-nginx.md`) stands on
these rulings; its "required amendment if nginx is ever dropped" (moving the
authentication-kind extension into the flat AS metadata) stays contingent and is
correctly not opened now.

### Review-finding debt ledger — per-finding resolution

| Finding | Resolution (where it lives) |
|---|---|
| **BL-1** per-toolset AS surface falsified; `resource` primary | Delta spec: one flat AS document + strict, required `resource` at authorization and token endpoints (`invalid_target`); `infer_resource_single_toolset` as the only escape. No per-toolset issuers anywhere. |
| **BL-2** "not yet PoC'd" must be a gate | Delta spec's final requirement fixes the five criteria; tasks group 9 runs them; failure is falsification, not a note. (DCR coverage stays out of the gate on purpose: it is proven by tasks group 8 with its own evidence — a DCR failure is a change defect, not a design falsification.) |
| **MA-1** `aud` never verified unless configured | Core env: `audience: dial-mcp-proxy` on the gateway's provider entry (normative in the delta spec); tokens mint `aud = [resource, marker]`; CR-1 downgraded to partially met — marker-level binding only, honestly recorded in risks. |
| **MA-2** query strings dropped; `$host` drops the port | Delta spec (challenge + query-string scenarios); nginx block uses `$is_args$args` and a configured `$mcp_origin`; PoC C criterion (d) measures survival. |
| **MA-3** non-OAuth mapping → unsatisfiable 401 loop | OAUTH-only mapping, startup-enforced, no escape (D6, normative in the delta spec); the background design's `route_only` escape is dropped because static routing cannot keep its promise. |
| **MA-4** CIMD is the real path; the fetch is SSRF | CIMD primary with the full control set (D5, normative in the delta spec); DCR demoted to config-gated legacy. |
| **mi-1** PoC B's reach overstated | No PoC B evidence is cited as harness proof anywhere in these artifacts; the flat shape is re-justified on the harness capture; PoC C (a) is the only real-harness proof. |
| **mi-2** toolset path prose/config disagree; creation call | Settings and creation use `GET`/`PUT /v1/toolsets/{bucket}/{name}` (`platform/notion` locally — the recon-verified creation call); the **status read is a separate route**, `GET /openai/toolsets/{name}`, because the settings route's answer carries the per-caller statuses only on some Core builds (measured in the Stage 0 spike, finding 1; Core at HEAD enriches the settings route). The flow keeps the statuses the settings answer carries and asks the listing route only when that answer omits them — decided by the answer's content, never by an error, so one route serves both wherever Core enriches it. `docs/local-environment.md` corrected in the tasks. |
| **mi-3** flow-id entropy | 128-bit CSPRNG flow ids, normative (the code-injection chain at E7). |
| **mi-4** unauthenticated state allocation | Rate limits per source and global, hard cap with oldest-first eviction, plain-language pages (normative). |
| **mi-5** Keycloak JWT exposure window | Stated as min(flow TTL, the token's own `exp`) in the delta spec; flow TTL bounds retention, not the token's life. |
| **mi-6** roles source path | D4: required, no default, read at the configured source path, re-emitted as a plain array; loud refusal when absent. |
| **mi-7** FR-3 scope cut hidden | OAUTH-only v1 mapping is explicit in the proposal's out-of-scope and the spec's mapping-safety requirement. |
| **mi-8** lenient `resource` default contradicted | Strict by default, `invalid_target`; one-toolset inference as explicit config only. |
| **mi-9** the 401 rewrite stretches "splitter ONLY" | Owner ruling 2, recorded above. |
| **mi-10** `loggingKey`/`loggingSalt` parity | Core env mirrors `loggingKey: email` / `loggingSalt` on the gateway's provider entry; normative scenario (gateway-leg logins appear in obfuscated user logging). |

**Open gaps closed here:** the CIMD SSRF controls are specified (D5) instead of
referenced; the reserved-toolset-name collision has a normative home (D6) instead of a
build-time comment; the mi-2 prose/config disagreement is resolved and the doc
corrections are tasked.

### Requirement traceability (delta spec → problem statement)

| Delta requirement | Traces to |
|---|---|
| Toolset MCP path answers with the gateway's own challenge | FR-8, OR-3 (partial, disclosed trade), CR-1 |
| Discovery documents describe one flat AS server | FR-3, CR-1, CR-3 |
| Client registration (pre-registered / CIMD / gated DCR) | CR-2, SR-5, SR-6 |
| DCR registration records are durable across restarts | CR-2 (the DCR leg must keep working after a restart), SR-6 (registration stays against the gateway, never Keycloak) |
| Authorization requests require a valid resource | FR-2, CR-1, I4 |
| Federation flow through Core's credential API | FR-1, FR-6, SR-1, SR-2, SR-4, I3, I5, never-cut 1–3 |
| Upstream authorization request arrives complete | FR-1, SR-1, I3, never-cut 1–3 (the upstream leg's delivery; a dropped request never reaches the consent it exists for) |
| HTML responses carry the web-hardening header family | SR-1, SR-4, never-cut 5 (the callback URL a page renders at carries the identity provider's code and the flow state, and the Referer would carry both cross-party to the upstream's page; the Referer and cache channels are closed at the response) |
| Issued tokens are gateway-signed and audience-marked | SR-2, SR-3, CR-1, I4 |
| Claim copy preserves deployment claim paths | SR-2, I4 (the staleness caveat lives in refresh) |
| Refresh and revocation stay local | FR-5 (silent repeat), I4 bound, never-cut 4 |
| Sign-in status queryable | FR-4, OR-3 |
| Public endpoints bounded | SR-3 (no cross-user effect), operational robustness |
| Refusals before flow allocation are audited | OR-3 (failure modes diagnosable), never-cut 5 (the record's facts are non-credential by construction; no free-form caller input) |
| Toolset mapping safe to configure | FR-3 (v1 scope), OR-1 |
| Core trusts gateway tokens via a dedicated entry | OR-1, I4, never-cut 4 |
| Credential-model invariants preserved | SR-1..SR-6, I1–I5, never-cut 1–7 |
| End-to-end acceptance on a real harness | FR-1, FR-5, FR-8, OR-4, CR-3 (the gated rows) |

## Risks / Trade-offs

- [Role staleness ≤ `refreshTtl` (8 h default vs 24 h vanilla locally)] → bounded,
  non-sliding, fresher than the deployment's own bound, and startup-enforced against
  the configured IdP access-token lifespan; the owner's post-PoC-C SLA decision can
  move to option 2 without touching anything but the refresh grant and provisioning.
- [The signing key is as powerful as the IdP's — mint-any-`sub`, any-roles] → equal
  *key power*, narrower *issuance policy*: tokens are minted only after a live
  identity-provider authentication of that `sub` and the flow's DIAL authorization
  check, never offline (no `offlineClient` on the provider entry), 10-minute access
  TTLs, `kid` rotation within Core's 10-minute JWKS cache. Key custody is the
  permanent cost (never-cut 7); the residual is honestly the smaller audit budget of
  a new service — the reason the gateway must stay small.
- [A leaked gateway token is valid deployment-wide for its `sub` until its short `exp`
  — marker-level audience binding only] → recorded as a partial CR-1; the structural
  fix (per-issuer path/audience scoping in Core) is a future Core-side ask, explicitly
  not a dependency.
- [Single instance; in-flight flows lost on restart] → loss semantics specified
  (plain-language error page, one-command retry); issued tokens and refresh survive
  (self-contained JWTs); DCR registration records survive too (one JSON file in a
  mounted volume, D11) — only in-flight state is lost; Redis is the documented HA
  step.
- [The assembly is unproven until PoC C] → that is what the final gate is; every
  ingredient is spike-, source-, capture-, or PoC-verified, and the criteria are fixed
  in advance.
- [nginx config fragility (query strings, `$host`, regex order)] → reserved names
  enforced at startup, anchored regexes, configured origin, and a scripted routing
  probe battery before the harness run.
- [CIMD is a young draft; other harnesses may not send `resource`] → DCR retained
  behind a config flag; one-toolset inference as the escape; both revisited only with
  a named harness's measured failure.
- [The E7 code-injection chain's interception variant survives the gateway's own
  defenses; transport security is the control] → disclosed in the security impact
  analysis: an interceptor of the victim's identity-provider callback URL completes
  the flow in their own browser and Core stores the attacker's upstream credential
  under the victim's `sub`. The committed plain-http front door (D13 defers TLS to
  the deployment layer) accepts it; TLS-front the public origin before any
  real-world use.
- [The shared worker pool is a bounded shared resource — a sustained flood of
  slow-leg requests queues legitimate legs behind the attacker's queue] → the loop
  stays responsive (slow work is offloaded off it), and a capacity limiter on the
  CIMD fetch bounds the one attacker-chosen slow leg's pool occupancy; the residual
  queue-wait is disclosed in the security impact analysis and accepted for the
  single-instance PoC.

## Migration Plan

Implementation order (one change, staged by task group): spike → scaffolding → gateway
skeleton → federation → front routing → deployment configuration → static/compose-boot
gates → DCR live verification → PoC C. Each group's tasks carry their own verification; the gate ladder
(`CLAUDE.md`) runs before any group is done.

Deployment (local): build the gateway image; run `scripts/provision_keycloak.py`;
apply the sibling's Core env changes with
`wsl -e docker compose up -d --force-recreate core`; register the `notion` toolset via
`PUT /v1/toolsets/platform/notion`; bring up this repo's compose (router + gateway) on
the instance network; health-probe both; run the routing probe battery; then PoC C.

Rollback (all additive, no data migration): bring this repo's compose down; revert the
sibling's Core env entries (remove the `dial-mcp-proxy` entry, restore
`authorizationServers` and `allowedRedirectUris`, optionally remove the Keycloak
entry's `issuerPattern`); delete the Keycloak client (or leave it — it grants
nothing by itself). The DCR store file on its host volume (only present if DCR was
enabled) can be left or deleted — it grants nothing by itself. Stored upstream
credentials, the toolset registration, and user data are untouched by the rollback.

## Open Questions

1. **HA / multi-instance** — Redis-backed flow/code/denylist/registration stores when
   required; loss semantics are already specified; no behavior change implied.
2. **Keycloak RP-initiated logout** — wiring flow completion to OIDC end-session so
   "sign out" also ends the SSO session; v1 logout is local discard + revocation.
3. **API-key toolset wrapper UX** — the same flow shape with a key-paste step;
   excluded from v1 mapping, unchanged in scope. A front-door spelling for
   non-OAuth toolsets (serving their MCP path without the OAuth challenge) belongs
   to this work, which brings its own routing mechanism — generated per-toolset
   locations or a route table — decided then; v1 refuses non-OAuth entries outright
   (D6).
4. **Per-issuer path/audience scoping in Core** — the structural fix for the
   deployment-wide token validity; a worthwhile future Core config feature, explicitly
   not a dependency of this change.
5. **Post-PoC-C refresh/SLA decision (owner)** — with criterion (b)'s measured
   rotation behavior and the staleness numbers in D3, the owner picks the revocation
   SLA; option 2 is the prepared upgrade if 8 h is too stale.
6. **Other harnesses' `resource` conformance** — measured only for Claude Code; the
   one-toolset inference flag exists; revisit only on a named harness's failure.
7. **Pinning the latest Core post-PoC** — Core at HEAD enriches the settings route
   with the per-caller statuses, so a deployment running it collapses the flow's
   decision step to one token presentation. The PoC tolerates both builds
   (content-decided fallback); pinning latest and dropping the tolerance is a
   post-PoC simplification, recorded here rather than silently assumed.
