# Local DIAL environment

How to reach the local DIAL instance this PoC runs against, what the deployment has to be
configured with, and which script applies each part. **No credential in this file is
real** — local values go in `.env` (gitignored), from `.env.example`.

## The instance

The development instance lives in the sibling folder `../<local-instance>/`
(a local-only git repository with no remote) and is started with:

```
wsl -e docker compose up -d
```

It runs the full DIAL stack; this PoC needs only **core**, **keycloak** and **redis** of
it. The gateway and its front router are a separate compose project in this repository,
joined to the instance's network as an external network — see the repository `README.md`.

## Endpoints (local values, from `.env`)

| Service | URL | Used for |
|---|---|---|
| DIAL Core | `http://localhost:8081` | The toolset MCP endpoint and the credential API |
| Gateway front door | `http://localhost:8090` | The origin a harness talks to: discovery, sign-in, and the MCP path |
| Keycloak | `https://keycloak:8443` (realm `dial`) | User authentication; the realm's well-known documents |
| Keycloak (admin) | `http://localhost:8900` | Realm administration, and the port `scripts/provision_keycloak.py` uses |

`127.0.0.1 keycloak` must be in the Windows hosts file — the realm's issuer is
`https://keycloak:8443/realms/dial`, and a mismatched issuer is a hard failure (clients
reject an unexpected issuer by specification).

The gateway's federation profile for this local shape goes in the same `.env` (the
shipped `.env.example` carries the placeholder shape only — the gateway is
provider-neutral, so no provider's address is baked into its defaults):

```
IDP_ISSUER=https://keycloak:8443/realms/dial
IDP_BACKCHANNEL_BASE_URL=http://keycloak:8900
```

The back-channel override points the gateway's server-to-server calls at the instance's
internal plain-http port — scheme and host swapped, the realm's path kept — so they
sidestep the self-signed certificate entirely; the browser-facing redirect and issuer
matching stay on the issuer above.

### An external provider's profile (the sketch)

The same settings carry an external provider's profile, in the deployment's
own real values — the gateway is provider-neutral and names a provider class, never a
product; nothing below is a value to copy:

- `IDP_ISSUER` — the provider's issuer for the **one sign-in journey this deployment
  federates**, pinned exactly. For a provider whose issuers vary across its sign-in
  journeys, that is one journey's issuer, and the provider must be configured for
  journey-distinct issuance (one `iss` per journey) — with that absent, every sign-in
  fails at issuer verification.
- `IDP_CLIENT_ID` / `IDP_CLIENT_SECRET` — the client registered in the provider's own
  admin console: a **confidential** client, its secret required at startup in both
  positions of `IDP_PKCE_ENABLED` (the secret authenticates every identity-leg token
  request; the toggle governs only the PKCE challenge).
- `IDP_CLIENT_SCOPES` — the client's own scopes, with `openid` where the provider
  requires it to issue an identity token (the local realm above forbids it; an external
  provider commonly requires it). Never `offline_access`.
- `ROLES_SOURCE_PATH` — the claim path the provider's tokens carry roles at.
- `IDP_SSO_SESSION_MAX_SECONDS` — the provider's own refresh-token window for a client
  of this shape.

A provider reachable at one TLS origin for both browser and server-to-server calls
needs no `IDP_BACKCHANNEL_BASE_URL`. The full settings reference, the endpoint source
modes (discovery or the directly configured trio), and the startup refusals are in
[`gateway-configuration.md`](gateway-configuration.md).

## Toolset

A toolset named `notion`, pointing at the public Notion MCP server
(`https://mcp.notion.com/mcp`), is registered in Core. It must be created through Core's
API (`PUT /v1/toolsets/platform/{name}`) — a toolset declared in `config.json` is **not**
dynamically registered against the upstream, and its OAuth settings are never populated.
`scripts/spike_register_toolset.py` performs the registration and is idempotent.

Two facts about that script's re-registration path are worth knowing before using it:

- Core does **not** store the `redirect_uri` the request body carries. It registers the
  deployment's `allowedRedirectUris` with the upstream and stores the **first** entry back
  (see point 1 above), so the list's order is what decides the stored value. The gateway
  no longer reads that stored value on any leg — it derives its own upstream callback
  from configuration — so the ordering no longer decides whether the gateway's own
  consent works; the script still reports and checks the stored value as deployment
  hygiene, because a reader that remains elsewhere still depends on it.
- A `PUT` over an **existing** toolset cannot move that stored value: with the
  idempotency header it answers `412` ("Resource already exists"), and without it `400`,
  demanding the explicit OAuth fields the dynamic-registration mode forbids. Moving it
  means re-registering — `--replace` deletes the toolset first so the upstream
  registration step re-runs. Both cases are covered by the finding
  `openspec/changes/build-mcp-sign-in-gateway-poc/evidence/finding-toolset-redirect-uri.md`.

```
PYTHONUTF8=1 python scripts/spike_register_toolset.py --replace
```

The script reports the stored settings and fails if the stored `redirect_uri` is not the
gateway's callback.

Its public OAuth settings are readable on the one live Core route the sign-in flow
reads:

```
GET {core}/openai/toolsets/notion   # the listing read: the stored settings, plus the per-caller auth statuses
```

It returns `auth_settings` with `client_id`, `authorization_endpoint`, `redirect_uri`,
`code_challenge`, `code_challenge_method` and `scopes_supported`, enriched with the
caller's `user_level_auth_status` and `global_auth_status`. **The PKCE
`code_verifier` and the `client_secret` are never exposed** — they are generated and held
inside Core, which is why only Core can exchange an upstream authorization code.

This listing route is also the sign-in flow's availability oracle: its authorization is
Core's deployment resolution of the toolset name against the caller's roles — the same
decision the MCP data path makes of every call — so it answers 200 exactly when the user
could call the toolset, 403 when that decision refuses them, and 404 for a name it does
not know. The flow reads it once and decides everything on that one answer.

## App (an application with an MCP endpoint)

DIAL applications that expose an MCP endpoint are sign-in-able through the gateway's
second front-door path shape, `{GATEWAY_PUBLIC_ORIGIN}/apps/{name}/mcp`. Unlike a toolset,
an app carries **no upstream credential** — an `Application` in Core has no authentication
settings — so an app sign-in takes no consent screen and no credential call: the flow is
the identity leg, the app read as the user, and the kind-driven short-circuit.

Because this repository's local environment ships no application resource of its own
(Core's static `config.json` lists none, and the `notion` entry above is a **toolset**),
the app acceptance needs a fixture, and it is two pieces:

- **A minimal MCP-speaking upstream service** in this repository's `docker-compose.yml`,
  joined to the instance network, with no external credential. It is a **test fixture**, so
  it is gated behind the Compose `acceptance` profile — a plain `wsl -e docker compose up -d`
  starts only the gateway and its router, and the fixture is brought up explicitly with
  `wsl -e docker compose --profile acceptance up -d mcp-app-fixture`. Core reaches it by
  service name at `http://mcp-app-fixture:9000/mcp`, and the registration script's `endpoint`
  equals that URL — it registers the app `skills-demo` via
  `PUT /v1/applications/platform/skills-demo`. The fixture carries no stored credential on
  the app's upstream leg by design — Core's app MCP injector sends the application id and
  optional header config only — which is what keeps the acceptance hermetic.
- **`scripts/spike_register_app.py`**, the sibling of `scripts/spike_register_toolset.py`:
  it registers the application resource in Core (the documented apps recipe — a `PUT`
  carrying an `mcp` block whose `endpoint` is the fixture's URL), admin-gated exactly as the
  toolset script is, and **idempotent** — a repeat write is reported as idempotent success,
  and `--replace` deletes the app first so the write re-runs.

```
PYTHONUTF8=1 python scripts/spike_register_app.py
PYTHONUTF8=1 python scripts/spike_register_app.py --replace   # delete first, then register
```

A registered app resolves in Core on `GET {core}/openai/applications/{id}`, whose answer
must carry the `mcp` block Core's apps MCP proxy requires (an application whose `mcp` block
is null is refused). The acceptance run then points a harness at the app's front-door path,
`{GATEWAY_PUBLIC_ORIGIN}/apps/{name}/mcp`, where `{name}` is the app the script registered.
Core serves that MCP path at `/v1/deployments/{id}/mcp` behind the same unauthenticated
401-challenge tier as the toolset path — the router's apps location is what a harness
actually lands on.

## Keycloak realm state

The gateway's own Keycloak client is created by **`scripts/provision_keycloak.py`** — the
script this repository ships for the job. It is idempotent; run it twice and the second
run changes nothing. It registers the confidential client `dial-mcp-proxy` (standard
flow only, S256, `publicClient: false`, redirect
`http://localhost:8090/dial/callback/idp`, default scopes `profile`/`email`, plus the
`sub`, `project` and `roles` mappers the flow needs) through the realm's Admin API, taking
its administrative credential from `KEYCLOAK_ADMIN_USER`/`KEYCLOAK_ADMIN_PASSWORD` in
`.env`:

```
PYTHONUTF8=1 python scripts/provision_keycloak.py
PYTHONUTF8=1 python scripts/provision_keycloak.py --verify-claims   # also runs a real flow
```

The local profile's bring-up includes the client secret: the helper converges the
client's secret to the profile's `IDP_CLIENT_SECRET`, generating a value and writing it
to the local `.env` where the profile carries none (a value the profile supplies is
kept), and it never prints the secret. A compose boot against the profile therefore
carries the secret the realm expects, whichever way `IDP_PKCE_ENABLED` is set.

The realm's own client-registration policies — the **Trusted Hosts** list and the removal
of the **"Consent Required"** and **"Full Scope Disabled"** policies — are **historical
PoC-A state** and are **not required by this design**. Those policies existed so a harness
could register *itself against Keycloak*; here a harness registers against the **gateway**
(a client-id metadata document, or a registration the operator did out of band), and
Keycloak is reached only by the gateway's own pre-registered client. No realm security
policy is touched.

The one realm fact that still matters is the scopes: a scope that is not a client scope in
this realm cannot be requested, and `openid` is **not** one here — requesting it fails the
whole authorization leg rather than being ignored.

## Core configuration this repository requires

Both groups of changes are Core **environment variables** in the instance's
`docker-compose.yml` — there is no `aidial.settings.json` in this deployment. Apply them
with `wsl -e docker compose up -d --force-recreate core` (run in the instance folder):

1. **Advertise this gateway as the authorization server** for toolsets:
   `aidial.toolsets.security.authorizationServers` → the gateway's public origin
   (`http://localhost:8090`). The gateway is the authorization server a harness can
   complete a sign-in against; Keycloak stays the identity provider behind it.

   `aidial.toolsets.security.allowedRedirectUris` is the **shared registry of the three
   callbacks** a deployment composes — the gateway's, DIAL Chat's, and DIAL Admin's —
   and Core validates the `redirect_uri` the flow presents against it at exchange time,
   whatever the toolset's stored field says. Carry all three, in this order:

   1. **The gateway's own upstream callback, first** —
      `http://localhost:8090/dial/callback/upstream`, spelled from the deployment's
      `{GATEWAY_PUBLIC_ORIGIN}` (the callback is derived from configuration, never
      itself a setting, so this is its one spelling).
   2. **DIAL Chat's** — `{chat-origin}/auth/toolset-signin`.
   3. **DIAL Admin's** — `{admin-origin}/toolset-signin`.

   **Why the gateway's entry is first.** Core registers *every* allowlist entry with
   the upstream and then stores the **first entry of the upstream's registration
   response** back as the toolset's `auth_settings.redirect_uri`. A conforming
   dynamic-registration server echoes the registered list in order, so the allowlist's
   first entry is what that stored field becomes for a newly-registered or repaired
   toolset. While any component still reads the stored field — this gateway before the
   code that stops reading it is deployed, or any other deployment component that still
   reads it — a registration whose stored field is another component's callback breaks
   that reader, so the gateway's entry stays first until no such reader remains. Once
   the gateway stops reading the stored field, DIAL Chat's editor saves of the field
   are harmless to every party; the ordering still costs nothing to keep and is what a
   repaired or newly-registered toolset's stored field becomes.

   **Then repair every dynamically-registered toolset.** Dynamic registration ran once,
   at each toolset's creation, against the allowlist as it stood then; a toolset
   registered before all three callbacks were added carries only the callbacks the list
   carried at its creation. Re-run the registration against the current list:

   ```
   POST {core}/v1/ops/toolset/{bucket}/{path}/repair
   ```

   The repair re-runs the upstream registration so the upstream registers all three
   callbacks. Its consequence is stated rather than discovered: the toolset gets a **new
   upstream client id and its stored credentials are cleared**, so each of that
   toolset's users re-consents once.

   **A statically-registered upstream client is not reachable by the repair route.** A
   toolset whose upstream client was registered by hand in Core's own configuration —
   not through dynamic registration — needs the gateway's callback added to that
   client's redirect URIs **by hand at the upstream provider's own console**. The repair
   route re-runs dynamic registration and cannot touch a client Core did not register.
2. **Trust the gateway's tokens**: an `aidial.identityProviders.dial-mcp-proxy.*` entry —
   `jwksUrl` pointing at the **gateway's own** JWKS endpoint
   (`http://mcp-signin-gateway:8091/dial/jwks.json`), an `issuerPattern` matching the
   gateway's public origin, `rolePath`/`projectPath`, and an `audience` marker so a token
   minted for another purpose is not valid everywhere. The deployment's primary Keycloak
   entry carries an `issuerPattern` too: with more than one provider, Core selects by
   issuer match, and an entry with no pattern can never match.

Verify the trust with `PYTHONUTF8=1 python scripts/probe_gateway_trust.py`, which runs a
negative control (a token signed by a key the gateway does not publish must be refused)
before its positive one (a gateway-signed token must resolve a real identity).