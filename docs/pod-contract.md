# The pod contract

The production deployment unit is **one pod**: the front router and the gateway as sibling
containers on a shared localhost, deployed and rolled as one unit. This document is that
pod's **contract** — the requirements the assembly must preserve, stated by the component
that owns the behavior. The Helm/pod assembly itself is the deployment's to write; this
repository delivers the contract it is assembled against.

The contract states two kinds of thing, and keeps them apart on purpose:

- **Requirements** — what the component needs to work and to stay on its stated trust
  basis. These are not preferences: an assembly that relaxes one is a contract violation,
  priced the same way a published gateway port or a dropped store volume is priced.
- **Options** — where two ways to meet a requirement both work, both are stated, neither is
  preferred. The deployment chooses the how in its own managed cluster and cloud, and the
  boundary price of each choice is the deployment's to own.

The contract passes DevOps review with **explicit confirmation**; silence is not
acceptance. That confirmation is this deliverable's acceptance, recorded in the change's
evidence.

## Scope

This document states the pod's shape: the image, the environment surface it reads, the
router's configuration file, the volume mounts, the security context, the ports and
probes, and the assumptions the assembly preserves (sibling localhost, single replica,
port non-publication). It does not contain manifests, and it names no storage class,
secret manager, or other product: where a requirement can only be met by a property, the
property is named and the mechanism is the deployment's.

The local composed stack in this repository is the contract's **executable stand-in**:
the router service joins the gateway's network namespace, which is `docker compose`'s
spelling of the pod's shared localhost. Every acceptance this component carries — the
probe battery, the restart survival, the rotation drill — runs against that stack in the
production image's shape, so the shape is exercised, not merely stated.

---

## 1. The image

The gateway runs the image this repository builds from its `Dockerfile`.

| Property | Value | Why it is a requirement |
|---|---|---|
| Base | `python:3.12-alpine` | Fewer pre-installed OS packages than a Debian base: a smaller scanned surface, which is what clears the base's OS-package debt. The compiled dependencies resolve to `musllinux` wheels, so the runtime image needs no compiler. |
| User | fixed uid **10001**, gid **10001**, non-root | The DCR store's file ownership is stated against this uid (see [volume mounts](#4-volume-mounts)); a rebuild must not change who owns the store. |
| Ports | exactly one container-internal port (**8091**) | Unreachable from the host and from outside networks, and name-routable on the deployment's own instance network — [section 6](#6-ports-and-probes) states both halves; the router is its only front door. |
| Baked secret | **none** | No secret-class value is ever baked into the image. Secret material enters at run time only (see [secret delivery](#9-secret-delivery)). |
| Scanner record | no HIGH-or-above OS-package finding | The static gate's OS-package scanner reports no HIGH-or-above finding against the image; the recorded Debian-base OS-package debt is cleared by the base swap. |
| Runtime extras | no toolchain, no installer | pip is removed from both the venv and the base's site-packages; no compiler is present. Nothing in the runtime image is imported at run time beyond the application and its pinned dependencies. |

The `ENTRYPOINT` runs the application module (`python -m gateway`) so that configuration
validation happens in the gateway's own process and its errors land in the container log
rather than in an argument-parsing traceback.

## 2. The classified environment surface

The gateway reads its configuration from environment variables. The table below classifies
**every environment variable the container reads**, derived from the settings model rather
than from the example file alone. A value the gateway does not read never needs to enter
the container: the local `.env` is shared with host-run helpers, and passing the whole file
through (an `env_file` include) would hand the container values it has no use for.

Class meanings:

- **required** — no default; the container refuses to start without it.
- **optional** — absence is legal and the **Default** column's value applies; the
  **Notes** column states where a default is topology-bound.
- **secret** — secret-class material or a locator for it. Never baked, never in the
  repository, never logged; delivered at run time.
- **dev-only** — read only for the local composed stand-in's layout; it has no meaning in a
  managed cluster.

The **Default** column is the settings model's own default for the field, verbatim: the
value that applies when the variable is absent. A *required* row has no such value, so its
cell states the refusal; a *secret* row's cell states the unset/empty state it starts in
(the two keyset documents show the empty shape their JSON starts from); a *dev-only* row's
cell states its local-stack value.

| Group | Variable | Class | Default | Notes |
|---|---|---|---|---|
| Topology | `GATEWAY_PUBLIC_ORIGIN` | optional | `http://localhost:8090` | The gateway's public origin (issuer of minted tokens; base of every discovery document). Must equal the origin the router publishes. The default is a localhost spelling, so every real deployment sets it. |
| Topology | `GATEWAY_INTERNAL_PORT` | optional | `8091` | The container-internal port uvicorn binds. Never published. |
| Topology | `DIAL_COMPOSE_NETWORK` | dev-only | `dial-instance_default` | Names the DIAL instance's compose network for the local composed stack. In a managed cluster the network is the cluster's, and this setting has no role. |
| Core | `DIAL_CORE_BASE_URL` | optional | `http://core:8080` | Core, as the gateway reaches it from inside its network. The default is the local compose topology's name; a deployment whose Core is reachable at another address sets this — the gateway cannot function without a reachable Core. |
| Core | `ROLES_SOURCE_PATH` | required | — (absence refuses startup) | The claim path roles are read from. A silent default yields a role-less token Core refuses with no diagnosable reason. |
| Core | `ROLES_CLAIM_NAME` | optional | `roles` | The claim name the roles array is re-emitted under (the name Core's provider entry reads). |
| Identity provider | `IDP_ISSUER` | optional | `https://idp.example.com/` | The browser-facing issuer, pinned exactly. The default names the RFC 2606 reserved domain, so a deployment that forgets it fails loudly at the identity leg rather than pointing at a live-looking host. |
| Identity provider | `IDP_BACKCHANNEL_BASE_URL` | optional | *(unset — the issuer's own origin)* | Origin override for server-to-server calls; unset means the issuer's own origin. |
| Identity provider | `IDP_DISCOVERY_CACHE_TTL_SECONDS` | optional | `300` | Reuse bound for a fetched discovery document. |
| Identity provider | `IDP_AUTHORIZATION_ENDPOINT` | optional | *(unset — discovery is the endpoint source)* | Direct endpoint trio member; all three or none. |
| Identity provider | `IDP_TOKEN_ENDPOINT` | optional | *(unset — discovery is the endpoint source)* | Direct endpoint trio member; all three or none. |
| Identity provider | `IDP_JWKS_URI` | optional | *(unset — discovery is the endpoint source)* | Direct endpoint trio member; all three or none. |
| Identity provider | `IDP_PKCE_ENABLED` | optional | `true` | Whether the identity leg's redirect carries a PKCE challenge. |
| Identity provider | `IDP_CLIENT_ID` | optional | `dial-mcp-proxy` | The gateway's registered client id. |
| Identity provider | `IDP_CLIENT_SCOPES` | optional | `profile,email` | The scopes the redirect requests, and only them. |
| Identity provider | `GATEWAY_OUTBOUND_TIMEOUT_SECONDS` | optional | `30.0` | Outbound call timeout. |
| Lifetimes | `GATEWAY_ACCESS_TOKEN_TTL_SECONDS` | optional | `600` | Access-token life. |
| Lifetimes | `GATEWAY_CODE_TTL_SECONDS` | optional | `300` | Authorization-code life. |
| Lifetimes | `GATEWAY_FLOW_TTL_SECONDS` | optional | `600` | In-flight flow record life. |
| Lifetimes | `GATEWAY_REFRESH_TTL_SECONDS` | optional | `28800` | Refresh window (absolute, non-sliding). Must not exceed the declared provider session bound. |
| Lifetimes | `IDP_SSO_SESSION_MAX_SECONDS` | required | — (absence refuses startup) | The operator's declared bound on the provider's session token window. |
| Lifetimes | `GATEWAY_ROTATE_REFRESH_TOKENS` | optional | `true` | Refresh rotation toggle. |
| Lifetimes | `GATEWAY_ROTATION_GRACE_SECONDS` | optional | `60` | Grace window for a request that raced a rotation. |
| Lifetimes | `GATEWAY_INFER_RESOURCE_SINGLE_TOOLSET` | optional | `false` | Single-toolset resource inference escape hatch. |
| Registration | `GATEWAY_AUDIENCE_MARKER` | optional | `dial-mcp-proxy` | The marker Core's provider entry verifies. |
| Registration | `TOOLSETS` | optional | `{}` | Operator restriction on served toolsets, as JSON. |
| Registration | `APPS` | optional | `{}` | Operator restriction on served apps, as JSON. |
| Registration | `PRE_REGISTERED_CLIENTS` | optional | `{}` | Operator-supplied clients, as JSON. |
| Registration | `GATEWAY_CIMD_ALLOWED_ORIGINS` | optional | `https://claude.ai` | Origins allowed to host a client-metadata document. |
| Registration | `GATEWAY_CIMD_USER_AGENT` | optional | `dial-mcp-gateway/0.1 (+mcp-signin)` | `User-Agent` the metadata fetch carries (load-bearing for the fetch's target). |
| Registration | `GATEWAY_CIMD_CONNECT_TIMEOUT_SECONDS` | optional | `5.0` | Metadata fetch connect timeout. |
| Registration | `GATEWAY_CIMD_TOTAL_TIMEOUT_SECONDS` | optional | `10.0` | Metadata fetch total timeout. |
| Registration | `GATEWAY_CIMD_MAX_DOCUMENT_BYTES` | optional | `65536` | Metadata document size cap. |
| Registration | `GATEWAY_CIMD_CACHE_TTL_SECONDS` | optional | `300` | Metadata cache TTL. |
| Registration | `GATEWAY_CIMD_CACHE_MAX_ENTRIES` | optional | `256` | Metadata cache bound. |
| Abuse bounds | `GATEWAY_FLOWS_MAX_LIVE` | optional | `10000` | Hard cap on live flow records. |
| Abuse bounds | `GATEWAY_RATE_PER_SOURCE_PER_MINUTE` | optional | `30` | Per-source request bound (source read from the router's forwarded address). |
| Abuse bounds | `GATEWAY_RATE_GLOBAL_PER_MINUTE` | optional | `600` | Global request bound. |
| Abuse bounds | `GATEWAY_APPROVED_CLIENTS_MAX` | optional | `10000` | Cap on the in-memory approved-client registry. |
| Abuse bounds | `GATEWAY_FORM_MAX_BODY_BYTES` | optional | `16384` | Form-body byte cap at the token and revocation endpoints. |
| Abuse bounds | `GATEWAY_CIMD_MAX_CONCURRENT_FETCHES` | optional | `8` | Concurrent metadata fetches on the shared worker pool. |
| Audit | `AUDIT_FACT_MAX_LENGTH` | optional | `256` | Longest caller-supplied fact in an audit record. |
| DCR | `DCR_ENABLED` | optional | `false` | Gates the dynamic client registration path. |
| DCR | `DCR_STORE_PATH` | optional | `/data/dcr-registrations.json` | The store file's path on the mounted volume. |
| DCR | `DCR_MAX_REGISTRATIONS` | optional | `1024` | Cap on stored registrations. |
| DCR | `DCR_MAX_BODY_BYTES` | optional | `8192` | Registration body cap (the governing bound). |
| DCR | `DCR_MAX_REDIRECT_URIS` | optional | `8` | Redirect URIs per registration. |
| DCR | `DCR_MAX_REDIRECT_URI_LENGTH` | optional | `512` | Length of one redirect URI. |
| DCR | `DCR_MAX_CLIENT_NAME_LENGTH` | optional | `256` | Length of a client name. |
| Custody | `GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES` | optional | `4096` | Largest provider session refresh token carried (coupled with the form-body cap). |
| Secrets | `GATEWAY_SIGNING_KEY` | secret | *(unset)* | The singular signing-key spelling: one active `env`-sourced key, no retention (the no-rotation shape). **One of this and `GATEWAY_SIGNING_KEYS` is required.** Never baked, never committed, never logged. |
| Secrets | `GATEWAY_SIGNING_KEYS` | secret | `{}` (empty document — no keyset) | The structured signing keyset, as JSON (structure only — each entry's material sits in its own variable or file, named by the entry's `ref`). Carries `source` (`env` or `file`), `ref`, and `role` (`active` or `retained`). Mutually exclusive with the singular spelling. |
| Secrets | `GATEWAY_CUSTODY_KEYS` | secret | `{}` (empty document — refuses startup) | The dedicated custody key that seals the provider's session token. **Required.** A JSON object of key-id → key, in two spellings (see below). Each key is 32 bytes in base64. |
| Secrets | `IDP_CLIENT_SECRET` | secret | *(unset)* | The identity-provider client's secret, environment-variable spelling. **One of this and `IDP_CLIENT_SECRET_FILE` is required.** |
| Secrets | `IDP_CLIENT_SECRET_FILE` | secret | *(unset)* | The identity-provider client's secret, file spelling: the path of a read-only-mounted file carrying the value. Optional beside the environment spelling. |

**Counts:** 55 variables the container reads — **2 required**, **47 optional**, **5
secret**, **1 dev-only**.

### The keyset-ref variables

The two keyset settings are **structure, not material**: each structured entry names where
its material comes from, and the material itself is read from the entry's own locator at
startup. So two further kinds of variable and path exist at run time, and both are
secret-class:

- an **`env`-sourced keyset entry** reads an environment variable whose name the entry's
  `ref` carries — an operator-chosen variable, injected with the key material, never the
  same name as any setting above;
- a **`file`-sourced keyset entry** reads a file at the path the entry's `ref` carries, on
  a read-only mount.

Both are read once at startup. A read that fails refuses startup naming the entry id and
the locator (the variable's name, or the file's path), never the material or the file's
content.

### The custody key's two spellings

`GATEWAY_CUSTODY_KEYS` accepts one spelling per document, and the two cannot be mixed.

- **Flat** — `key-id → base64 key` for exactly one key: one active `env`-sourced entry, no
  retention. The pre-keyset shape, kept so no existing deployment's configuration changes
  to gain the keyset seam.
- **Structured** — `key-id → {source, ref, role}`, the same entry schema as the signing
  keyset: one active entry plus any number of retained entries.

Retention requires the structured spelling. A document mixing the two is refused at
startup, naming the keyset: the flat shape cannot carry retention, and one spelling per
document is what keeps the compat shape from silently coexisting with it. The same
relationship holds for the signing key: `GATEWAY_SIGNING_KEY` (singular, no rotation) and
`GATEWAY_SIGNING_KEYS` (structured) are mutually exclusive, and configuring both refuses
startup naming both.

## The minimal configuration

[Section 2](#2-the-classified-environment-surface) is the **reference** — what every setting
does. This section is the **setup guide** — the short list DevOps actually configure to make
a real deployment work, so the surface does not become fifty-five questions asked one at a
time. Everything not named here holds at its **Default**-column value from that table.

### The minimal set — what a real deployment MUST set

```
# The gateway's minimal configuration. Replace every <> with the deployment's own value.
DIAL_CORE_BASE_URL=https://<core-address-in-cluster>
GATEWAY_PUBLIC_ORIGIN=https://<gateway-public-origin>
IDP_ISSUER=https://<idp-issuer>/
IDP_CLIENT_ID=<registered-idp-client-id>
IDP_CLIENT_SECRET=<idp-client-secret>            # or the file spelling on the next line
# IDP_CLIENT_SECRET_FILE=/run/secrets/<idp-client-secret-file>
IDP_CLIENT_SCOPES=<scopes-whose-token-carries-the-roles-claim>
ROLES_SOURCE_PATH=<claim-path-holding-roles>
IDP_SSO_SESSION_MAX_SECONDS=<provider-session-window-seconds>
GATEWAY_SIGNING_KEY=<rsa-private-key-pem>        # or the structured keyset below
# GATEWAY_SIGNING_KEYS={"<entry-id>":{"source":"env","ref":"<variable>","role":"active"}}
GATEWAY_CUSTODY_KEYS={"<key-id>":"<base64-32-byte-key>"}
DCR_ENABLED=<true-where-harnesses-register-dynamically>
```

| Variable | What it is |
|---|---|
| `DIAL_CORE_BASE_URL` | Core's in-cluster base URL, as the gateway reaches it: the flow's listing read and its credential call are made against it. |
| `GATEWAY_PUBLIC_ORIGIN` | The origin the router/ingress publishes — the issuer of every token the gateway mints and the base of every discovery document. It MUST equal the origin the harnesses see. |
| `IDP_ISSUER` | The identity provider's browser-facing issuer, pinned exactly: the `iss` every identity token must carry, and the anchor the discovery document is validated against. |
| `IDP_CLIENT_ID` | The id of the gateway's registered **confidential** client at the provider. |
| `IDP_CLIENT_SECRET` *(or `IDP_CLIENT_SECRET_FILE`)* | The confidential client's secret, in exactly one of its two spellings — the environment variable, or the path of a read-only mounted file (the shape a mounted Secret takes). |
| `IDP_CLIENT_SCOPES` | The scopes the identity leg requests, the only scopes either leg requests. The minted token carries the claims the provider delivers for them, so the set MUST be the one that makes the provider's token carry the claims the gateway re-emits — the roles claim at `ROLES_SOURCE_PATH` among them. The default (`profile,email`) is the local realm's shape, not a universal one; a token without the roles claim refuses at the claims step, naming the fix. |
| `ROLES_SOURCE_PATH` | The claim path the user's roles are read from in the identity token. No default: a wrong path yields a role-less token Core refuses with nothing in the logs to say why. |
| `IDP_SSO_SESSION_MAX_SECONDS` | The operator's declared bound, in seconds, on how long the provider keeps its session-bound refresh token usable. No default; the refresh window is checked against it at startup. |
| `GATEWAY_SIGNING_KEY` *(or `GATEWAY_SIGNING_KEYS`)* | The token signing material: an unencrypted RSA private key in PEM form, at least 2048 bits — or the structured keyset, where rotation is wanted. |
| `GATEWAY_CUSTODY_KEYS` | The dedicated 32-byte key that seals the provider's session refresh token into every gateway refresh token. |
| `DCR_ENABLED` | Dynamic client registration's switch. The default is off, and a deployment serving harnesses that register dynamically (the DCR path) sets it to true. |

**Eleven settings; this and nothing else is the working minimum.** With these set, every
other setting in [section 2](#2-the-classified-environment-surface) holds at its
Default-column value, and the flow runs end to end.

**Six of the eleven are optional in the model's sense and required in practice.** Each of
`DIAL_CORE_BASE_URL`, `GATEWAY_PUBLIC_ORIGIN`, `IDP_ISSUER`, `IDP_CLIENT_ID`,
`IDP_CLIENT_SCOPES`, and `DCR_ENABLED` carries a default — so section 2's class column
marks it *optional*, and that is the model's sense, correctly stated. They are required in
practice because every one of those defaults is a shape a real deployment re-judges: the
Core URL's default is the local compose topology's service name, the public origin's is a
localhost spelling, the issuer's is the RFC 2606 reserved domain, the client id's is the
repository's example client, the scope set's is the local realm's shape, and the
registration toggle's is off. A deployment that leaves any of them at its default does not
reach a real Core, a real harness, a real provider, or the claims the gateway re-emits, so
all six belong in the set that is actually configured. This is the reconciliation the two
lists need: section 2 states the model's classes; this section states the deployment's
minimum.

**The two generated secrets are generated, never invented.** [The secrets
reference](gateway-configuration.md#secrets) documents both settings and is the one source
of truth for them — it carries the custody key's generation, and it states the signing
key's shape (an unencrypted RSA private key in PEM form, at least 2048 bits). The recipes
are linked here, not copied.

### The commonly-adjusted tier — settings a deployment touches when its shape differs from the defaults'

Each of these holds its default for a deployment whose shape matches the default's
assumption, and is set only when the condition named is the deployment's.

| Variable | When a deployment sets it |
|---|---|
| `IDP_PKCE_ENABLED` | Turned **off** only for a provider that cannot support PKCE; on (the default) is the stronger position. |
| `IDP_AUTHORIZATION_ENDPOINT`, `IDP_TOKEN_ENDPOINT`, `IDP_JWKS_URI` | The direct endpoint trio — all three or none — where the provider's discovery document is unavailable, nonstandard, or served at a spelling the issuer-appended fetch does not reach. |
| `IDP_BACKCHANNEL_BASE_URL` | Where the provider's browser-facing origin is impractical for server-to-server calls — a self-signed certificate, or an internal plain-http port; a single-origin provider leaves it unset. |
| `GATEWAY_CIMD_ALLOWED_ORIGINS` | Set to the origins whose client-metadata documents this deployment admits. |
| `GATEWAY_AUDIENCE_MARKER` | Must equal the `audience` of Core's provider entry, where that entry verifies a marker other than the default. |
| `GATEWAY_SIGNING_KEYS`, or the structured `GATEWAY_CUSTODY_KEYS` spelling | Where key rotation is wanted: the singular `GATEWAY_SIGNING_KEY` and the flat `GATEWAY_CUSTODY_KEYS` are the no-rotation compat shapes. |

`DIAL_COMPOSE_NETWORK` is deliberately **absent** from this tier: it is *dev-only* — it
names the local composed stack's network and has no role in a managed cluster (see
[section 2](#2-the-classified-environment-surface)).

### The rest

The remaining settings — token lifetimes, the discovery cache TTL, the outbound timeout,
the metadata-fetch bounds, the abuse bounds, the DCR record bounds, and the audit cap —
hold their defaults as written; [section 2](#2-the-classified-environment-surface) is the
reference for what each one does, and a deployment changes one only when its default does
not fit the deployment's shape.

**Outside the environment surface — the Core-side onboarding a real deployment MUST apply.**
Core must be configured to trust this gateway's tokens, to advertise it as the toolsets'
authorization server, and to admit its callback; that is Core-side configuration, not a
gateway setting. Two settings groups, both stated here in the deployment's `<>`-placeholder
form (properties only — no real hostnames, instance names, tenant or issuer values), and
both mirroring the local instance's spelling in [the local
environment](local-environment.md#core-configuration-this-repository-requires).

**(a) The gateway joined as an identity-provider entry** —
`aidial.identityProviders.dial-mcp-proxy.*`. Each member's rule:

| Member | Rule |
|---|---|
| `jwksUrl` | The gateway's JWKS endpoint, reachable **from Core inside the cluster** at the gateway's instance-network name and container-internal port (`<gateway-service-name>:8091/dial/jwks.json`). This is the reachability half of [section 6](#6-ports-and-probes)'s port rule: Core fetches this URL, so the port is name-routable on the deployment's instance network — while staying unpublished to hosts and the outside (the same section's other half). |
| `issuerPattern` | The deployment's `GATEWAY_PUBLIC_ORIGIN`, pinned as a **full-match** regex. It must equal the origin the gateway mints its tokens with as `iss`. |
| `rolePath` | The claim path the gateway mints roles at — the gateway's `ROLES_CLAIM_NAME` (`roles` by default). It must match what the gateway re-emits, or every rule on roles silently never matches. |
| `projectPath` | The claim path the gateway carries the project attribution at, matching what the gateway mints. |
| `audience` | Equal to the gateway's `GATEWAY_AUDIENCE_MARKER` (`dial-mcp-proxy` by default). Core verifies this marker on every token the gateway mints; the resource audience the gateway also sets is its own addressing discipline, not a Core-side check. |
| `loggingKey` / `loggingSalt` | Mirroring the deployment's **primary** provider entry, so gateway-issued traffic is attributed and redacted the same way as primary-provider traffic. |

**(b) The toolsets security group** — `aidial.toolsets.security.*`:

- `authorizationServers` — an entry carrying the gateway's public origin
  (`<gateway-public-origin>`). The gateway is the authorization server a harness can
  complete a sign-in against; the identity provider stays the provider behind it.
- `allowedRedirectUris` — the three-callback list, **with the gateway's own upstream
  callback first**. The three callbacks, their order, why the order is load-bearing
  (Core stores the first entry of the upstream's registration response as the toolset's
  stored `redirect_uri`), and the repair-and-hand-registration procedure are stated once
  in [the local environment's runbook](local-environment.md#core-configuration-this-repository-requires);
  this contract carries the deployment's obligation to apply it, not a second copy of its
  prose. The gateway's callback is spelled `<gateway-public-origin>/dial/callback/upstream`.

**The multi-provider rule.** In a deployment whose Core has **more than one**
identity-provider entry, **every** entry needs an `issuerPattern`, the **primary** one
included. Core selects a provider by issuer match, and an entry with no pattern can never
be selected once any other entry defines one — so a primary entry left pattern-less is
silently unreachable, and the gateway's own entry (which must carry its pattern) does not
change that fact. An entry's pattern is also part of what keeps the two issuers
non-overlapping: a gateway entry's pattern that matched the primary's issuer would let
either accept the other's tokens.

## 3. The router configuration

The router container runs **this repository's committed `router/nginx.conf`**, mounted
read-only. Front routing is this component's behavior, not deployment folklore: the file
that decides which paths reach the gateway and which reach Core is versioned here, and an
assembly that substitutes its own is a contract violation.

The file states the property the assembly depends on: the router is the **sole front
door** and the **sole authority for the forwarded client address** the gateway's
per-source rate limit counts against. The router sets the forwarded address itself, from
the peer it accepted the connection from, so a client cannot choose it while its traffic
passes through the router. That property holds only if nothing reaches the gateway except
through the router — which is what the port requirement in [section 6](#6-ports-and-probes)
preserves.

The committed conf also **closes the `/.well-known/` namespace**: every path under it that
no discovery location serves is answered by the router with a fixed JSON `404` (body
`{"detail":"Not Found"}`, `application/json`, and the header
`X-Content-Type-Options: nosniff`) and is never forwarded to Core. A deployment that fronts
the gateway with any configuration other than this one must reproduce the closure — its body,
type, and discriminator header — together with the raw-spelling checks that keep a
dot-segment or percent-encoded spelling from reaching Core, and the raw-gated forward of
Core's own two protected-resource templates, the only `/.well-known/` paths that stay with
Core. Without them a discovery path falls through to Core's authentication refusal, which a
discovering client reads as "discovery needs a credential" and abandons the server. The
reasoning is in [`routing.md`](routing.md#the-closed-well-known-namespace).

The router's upstream for the gateway is **sibling localhost** (`127.0.0.1:8091`), not a
service name: the router and the gateway share one network namespace, so the address the
router dials is the gateway's own listener inside the pod (see
[section 8](#8-assumptions)).

## 4. Volume mounts

### 4.1 The DCR registration store (a named MUST)

The pod carries the dynamic-client-registration store's mount:

| Property | Value |
|---|---|
| Requirement | **MUST** be present and read-write |
| Path | The path `DCR_STORE_PATH` names (the store file's configured path) |
| Backing | A cloud-backed persistent-volume storage class — see [4.2](#42-the-stores-governance-and-storage-class) |
| Claim | The pod's **one** mounted state, read-write |
| Ownership | The volume must let uid 10001 write the store file (see [section 5](#5-security-context)) |

Registrations are the only gateway state that both outlives a restart and is cached by
clients indefinitely, so they are the only state made durable. Each accepted registration
is written before the response is returned, atomically (a temporary file in the same
directory, then a rename over the store). A pod assembled without this mount satisfies the
durability requirement's *code* while losing its *substance*: the path exists, but it is
ephemeral, and every restart silently invalidates every registered client. That is the
wound the mount requirement exists to prevent, and the restart-survival acceptance makes it
fail a gate.

The **consent/attribution registry** is deliberately **excluded** from durable state: it is
process memory, and a restart re-prompts every user once per client. This is by design and
fail-safe (a lost approval re-prompts, never skips), and the conditions under which durable
consents would be reconsidered are recorded separately and none has changed.

### 4.2 The store's governance and storage class

Three statements, each a requirement:

1. **The store's backing MUST be a cloud-backed persistent-volume storage class.** Stated
   by its properties: the data must **survive node loss**, and must rest in a
   **tenant-governable resource** the deployment administers. Node-local ephemeral storage
   never satisfies this. Which class, mechanism, or product meets those properties is the
   deployment's choice — named here as a requirement, not as a product.

2. **Backup and export are deployment-owned, and the component's shape makes them cheap.**
   The store is a **single human-readable JSON file written by atomic replace**, so a
   point-in-time copy of the file is a consistent export — no gateway cooperation and no
   new API. The choice of copy mechanism and destination is the deployment's.

3. **The store's no-secret-content rule is load-bearing.** The store holds registrations —
   client ids, redirect URIs, a display name, a timestamp; every client is public PKCE. It
   **MUST NOT** gain secret-class content without re-opening its boundary analysis. That
   property is what makes the external governance reader class (storage-layer RBAC holders,
   backup destinations reading a point-in-time copy) cheap to admit: a reader of the store
   holds registrations, never credential material. The same logic carries the **future
   wrapped-CEK file** — the sealed custody key, ciphertext by design — which is named here
   as the store volume's **future second resident**; it is ciphertext and needs no custody
   key to read, so the reader class survives its arrival.

### 4.3 Read-only mounts for file-sourced secrets

Every file-sourced secret is mounted **read-only**:

- each `file`-sourced keyset entry's key file, at the path its `ref` names;
- the identity-provider client secret under its `IDP_CLIENT_SECRET_FILE` spelling, at the
  path that setting names.

The store's read-write mount and the secret files' read-only mounts are separate mount
classes, and the assembly preserves the difference. A writable key mount is a tamper path,
not a convenience: the material-loaded-at-startup discipline assumes the file cannot change
under it.

## 5. Security context

The pod's containers run under this security context. These are controls the image and its
mounts assume, not deployment preferences — an assembly that relaxes any of them is a
contract violation priced the same way a published gateway port is priced.

| Control | Value | Why |
|---|---|---|
| `runAsNonRoot` | `true`, with `runAsUser` / `runAsGroup` **10001** on the gateway container | The DCR store's file ownership depends on that uid; the image's fixed user is 10001. |
| `fsGroup` | **10001** on the store's volume | So the mount's ownership lets uid 10001 write it. A world-writable mount is the tamper path the assembly must refuse. |
| `allowPrivilegeEscalation` | `false` | No process in the pod needs to gain privilege. |
| Capabilities | **all dropped** | Viable because nothing in the pod binds a privileged port: both the router's public port and the gateway's container-internal port are unprivileged. That is the assumption that keeps the drop total, and it is stated where it lives (see [section 6](#6-ports-and-probes)). |
| Root filesystem | **read-only**, with `emptyDir` mounts for the router's temp and log paths | The gateway writes nothing but the DCR store, whose own volume the read-only root does not touch. The router needs writable temp and log paths, which the `emptyDir` mounts provide. |
| seccomp | the **runtime-default** profile | No syscall set is widened. |

## 6. Ports and probes

| Element | Value | Statement |
|---|---|---|
| Public port | **8090** on the router | The pod's single public entry, at the cluster-ingress TLS boundary. |
| Gateway port | **8091**, container-internal | Unpublished outside the pod's namespace. See the precise statement below. |
| Liveness probe | `/healthz` | Through the router for the paired health, and container-internally for the gateway's own process. The probe answers whether the process is up, never Core's or the identity provider's health. |

**The port non-publication statement, both halves together.** The gateway's port is
unreachable from the host and from outside networks, **and** it is name-routable on the
deployment's own instance network (`mcp-signin-gateway:8091`). Both must hold:

- **Unreachable from the host and from outside networks** — the gateway's port is never
  published to the host and never exposed on the pod's external interface. This is what
  makes the router's forwarded client address trustworthy: a caller that could reach the
  gateway directly would carry whatever address it chose, and the per-source rate limit
  would be a bound the caller sets.
- **Name-routable on the deployment's instance network** — Core fetches the gateway's
  JWKS at that name and port, so the gateway must be reachable there. This is required, not
  a leak: the port is published only to the deployment's own trust domain, never to the
  host or the outside.

The sibling-localhost assumption covers the **router → gateway hop only** (the router dials
`127.0.0.1:8091` inside the shared namespace). It does not touch the instance-network
fact: these are two statements about the same port from two directions, and both are true
at once. A deployment that widened the network face — publishing the port, or exposing it
on the pod's external interface — is the mis-assembly the threat model prices.

## 7. Deployment diagram

Renderer-independent: plain text, readable in any diff, no image dependencies and no
toolchain.

```
   the harness (MCP client)
            |
            |  the pod's single public port
            v
     cluster ingress  (TLS terminates here)
            |
            v
 +---------------------------------------------------------------+
 |  POD  -- the unit of scheduling, rollout, and recreation       |
 |                                                                |
 |   +--------------------------+     +----------------------+    |
 |   | router container         |     | gateway container    |    |
 |   |  nginx                   |     |  uid/gid 10001       |    |
 |   |  conf mounted read-only  |     |  one internal port   |    |
 |   |  listens 8090 (public)   |     |  8091 unpublished    |    |
 |   +--------------------------+     +----------------------+    |
 |        ^        |                        ^        |            |
 |        |        | 127.0.0.1:8091         |        |            |
 |        |        | (sibling localhost,    |        |            |
 |        |        |  router->gateway only) |        |            |
 |        |        +------------------------+        |            |
 |        |        [ shared pod network namespace ]   |            |
 |        |                                          |            |
 |   mounts:                                         |            |
 |     /data  (store volume, READ-WRITE)  <----------+            |
 |       |- dcr-registrations.json   (registered clients,         |
 |       |                            no secret content)          |
 |       `- <wrapped-CEK file>   . . . future second resident     |
 |                                   (ciphertext by design)       |
 |     <key paths>  (read-only)  <-- one per file-sourced secret  |
 +---------------------------------------------------------------+
        |                                   ^
        | MCP data path                     | JWKS fetch by name
        | (bypasses the gateway,            | (deployment instance
        |  router -> Core)                  |  network)
        v                                   |
   DIAL Core  - - - - - - - - - - - - -     |
        |                                   |
        | back-channel legs                 |
        v                                   |
   Identity provider                        |
                                            |
                                  +---------+----------+
                                  |  gateway's keyset  |
                                  |  sources           |
                                  +---------+----------+
                                            ^
                                            | (run time only)
                       +--------------------+---------------------+
                       |  external secret store (deployment's)    |
                       |  -> cluster Secret objects               |
                       |  -> env vars  OR  read-only mounted files |
                       +------------------------------------------+

  assumptions, drawn where they live:
    (a) sibling localhost   -- router dials the gateway at 127.0.0.1:8091;
                               the hop never leaves the pod namespace.
    (b) single replica       -- one pod; flow state and the approved-client
                               registry are in-memory (see section 8).
    (c) port non-publication -- 8091 unreachable from host/outside,
                               name-routable on the instance network (section 6).
    (d) security context     -- non-root uid/gid 10001, fsGroup 10001 on the
                               store volume, no privilege escalation, all
                               capabilities dropped, read-only root (section 5).

  reserved: a future keyset entry with source "kms" . . . . . . . . . . . . - - ->
            (a dashed future arrival: the schema carries the value today and
             refuses it at startup naming the gap; the interface is not built)
```

Two paths are worth naming for their shape rather than their detail:

- The **MCP data path bypasses the gateway entirely** — the router sends it straight to
  Core. The gateway is on the authorization surface (sign-in), not on the data path.
- The **secret path** is drawn as a shape, not a product: an external secret store the
  deployment owns feeds the cluster's Secret objects, which reach the process as
  environment variables or as read-only mounted files. Which store, and which of the two
  deliveries, is the deployment's choice (see [section 9](#9-secret-delivery)).

## 8. Assumptions

### 8.1 Sibling localhost

The router reaches the gateway at **sibling localhost** (`127.0.0.1:8091`) because the two
containers share one network namespace. This is what makes the router the sole authority
for the forwarded client address, and it is the mechanism that narrows the router→gateway
hop to the pod's own loopback — a network peer outside the namespace cannot reach it at
all. The leg stays plain HTTP, which is the same accepting class as loopback anywhere: the
traffic never leaves the pod's namespace.

### 8.2 Port non-publication

See [section 6](#6-ports-and-probes) for the two halves together: unreachable from the host
and from outside networks, and name-routable on the deployment's instance network by
design.

### 8.3 Single replica

The pod is **not horizontally scalable**, and HA remains deferred. Flow state and the
approved-client registry are in-memory. The loss semantics are fail-safe and already fixed:

- a restart forgets every approval, so the next sign-in for each client re-shows the
  decision page — a re-prompt, never a skip;
- in-flight flows are lost, so their browsers receive the expired-session page and re-run
  the sign-in;
- pending entries (an unredeemed authorization code and the credential it would carry) are
  bounded by the code's own short TTL and are lost, so an unredeemed code issued before the
  restart fails its grant closed.

An operator who scales the pod horizontally gets split in-memory state — callbacks landing
on the other replica's expired-flow page, approvals forgotten per replica. That fails safe
but confuses, so this single-replica statement is what makes such a failure diagnosable as
a **contract violation** rather than a gateway defect.

### 8.4 The local composed stand-in, and its operation

The composed stack in this repository stands in for the pod so every acceptance runs
without a cluster. It carries one operational note the pod does not:

> **Operate the composed stand-in at unit granularity.** Recreate the whole unit —
> `docker compose up -d --force-recreate`, or `down` followed by `up`, or `up -d --build`.
> Do **not** restart a single service under compose (`docker compose restart <service>`).

The reason is a **compose-specific trap with no pod equivalent**: a single-service
`restart` recreates one container's network namespace while the other container stays bound
to the namespace it joined at its own start, so the pair's shared namespace is **split** —
the router's upstream then reaches an empty loopback and stays unhealthy until the unit is
recreated. In a real pod this cannot arise: the pod is the unit of scheduling and
recreation, so a container restart within a pod keeps the pod's shared network namespace.
The stand-in is therefore faithful to the **pod's** pairing atomicity under unit-level
operations, and the unit-granularity rule is what makes it exercise that atomicity rather
than a compose artifact.

## 9. Secret delivery

This section states the **requirements** (what the component needs) and the **options**
(how those needs can be met), with no preference between the options.

**Requirements.**

- Secret material enters at **run time only**. It is never baked into the image, never
  committed to the repository, and never passed as a process argument.
- Each secret is delivered by **exactly one spelling**. Configuring both spellings of one
  secret refuses startup, naming both settings — a secret with two possible values has no
  single value.
- Every **file-sourced** secret is delivered on a **read-only mount**. Its file is read
  once at startup; an unreadable or blank file refuses startup loudly, naming the **path**
  and never the content.
- The store volume's ownership must let uid 10001 write it (see [section 5](#5-security-context)).
- No secret value, fingerprint, or file content reaches any log line or error message.
  Startup refusals name entries by their configured ids and their locators only.

**Options.** Each secret accepts two spellings, and both are supported:

| Secret | Spelling 1 | Spelling 2 |
|---|---|---|
| The signing key | the singular environment variable (`GATEWAY_SIGNING_KEY`), or a structured keyset entry with `source: env` | a structured keyset entry with `source: file`, reading a PEM on a read-only mount |
| The custody key | a `GATEWAY_CUSTODY_KEYS` entry with `source: env` | a `GATEWAY_CUSTODY_KEYS` entry with `source: file`, reading a key file on a read-only mount |
| The identity-provider client secret | `IDP_CLIENT_SECRET`, an environment variable | `IDP_CLIENT_SECRET_FILE`, a read-only mounted file |

The two spellings are **equivalent to the gateway**: whichever delivers a secret, its
presentation and its never-logged discipline are identical. The deployment chooses the
delivery its cluster and cloud manage, and the boundary price of each spelling is the
deployment's to own. A keyset entry carrying the reserved source `kms` is refused at
startup, naming the gap: the schema carries the value so a future KMS-sourced entry is a
rotation rather than a redesign, but the interface it names is not built, and a
configuration that believed otherwise must be corrected rather than honored.