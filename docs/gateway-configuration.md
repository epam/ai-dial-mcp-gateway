# Gateway configuration reference

Everything the gateway reads is an environment variable, and every one of them is listed
in `.env.example` with a placeholder. There is no configuration file and no mount to
own: the same `.env` that `docker compose` reads also serves the service, so there is one
place to look and one way to pass a value in.

Copy the example, fill in the local values, and set `GATEWAY_SIGNING_KEY`:

```bash
cp .env.example .env
```

`.env` is gitignored. **No credential, token, or key is ever committed**, and the gateway
never prints one — the signing key and the identity-provider client secret are typed as
secret values, so a settings object cannot be logged, serialized, or dumped in a
traceback with the value attached.

## Startup refusals

The gateway refuses to start rather than serving a surface that is silently broken. Each
refusal names the setting or the entry at fault, and each is machine-checked here instead
of being a documented hope:

| Refusal | Why it is a refusal |
|---|---|
| `IDP_SSO_SESSION_MAX_SECONDS` missing | The carried session refresh token's window is checked against it; a guessed bound makes the startup check meaningless. |
| `ROLES_SOURCE_PATH` missing | A silent default yields a role-less token, which Core answers as a 403 with nothing in the logs to say why. |
| `GATEWAY_REFRESH_TTL_SECONDS` > `IDP_SSO_SESSION_MAX_SECONDS` | The carried session refresh token must remain usable at every refresh in the window, and the declared session bound is how long the identity provider keeps it. The error names both values, and states that the check is an operator assertion about provider session policy — a shorter window is the correct configuration where the provider's policy is short, not a degraded one. |
| `GATEWAY_SIGNING_KEY` missing, unreadable, not RSA, or smaller than 2048 bits | The gateway cannot mint a token, and the symptom would otherwise appear at a harness rather than here. |
| `GATEWAY_SIGNING_KEY` still the example's placeholder | The value in `.env.example` is a real string; a deployment that never replaced it would sign tokens with a key published in this repository. |
| A `TOOLSETS` key outside the resource-path grammar | A resource path is what the front router routes; a configured entry the grammar could never route is refused, naming the entry and the rule (a segment outside the decoded rules, a reserved first segment, a trailing dot, a dot or empty segment, or an over-length or over-depth path). Enforced for configured restriction entries; the same guard runs at request time for dynamic paths. |
| A reserved first segment in a `TOOLSETS` key (below) | The router's authorization-surface location captures `/dial/{segment}/…` at the first segment, so such a key's MCP traffic could never reach Core. The rule is first-segment only, `/dial/`-scoped: a reserved name deeper in a path (`toolsets/public/token`) is legal. Enforced for configured restriction entries; the same guard runs at request time for dynamic paths. |
| `GATEWAY_INFER_RESOURCE_SINGLE_TOOLSET` enabled without `TOOLSETS` configured with exactly one entry | With a dynamic served set there is no "the one toolset" to infer, and inferring silently is how a token ends up addressed to a toolset the client never named. The error names the setting and what it requires. |
| A `TOOLSETS` entry still carrying the removed `authentication_type` member | The member no longer means anything — the kind a flow acts on is Core's, read per flow — so the mapping's schema forbids unknown members and refuses the field by name. This is the migration: the one breaking operator change fails loudly at parse. |
| An `APPS` key outside the resource-path grammar | An app path is what the router's apps map routes, and the map is static; a configured entry the grammar could never route is refused, naming the entry and the rule. Enforced for configured restriction entries; the same guard runs at request time for dynamic paths. Unlike a toolset path, an app path has **no** reserved-first-segment refusal — the reserved names are all `/dial/`-scoped, and nothing the gateway owns is served under the apps namespace's first segment. |
| An `APPS` entry carrying any member other than the name | An app has no authentication kind to declare and no scopes to echo (no upstream leg exists for an app resource), so an entry declaring anything else — `scopes_supported`, a kind, any field — is refused at parse, by field name. |
| A `TOOLSETS`, `APPS`, or `PRE_REGISTERED_CLIENTS` value that is not a JSON object | The value is parsed as one; a malformed document would otherwise be a mapping with nothing in it. |
| A `PRE_REGISTERED_CLIENTS` entry whose `redirect_uris` carry a non-loopback plain-`http` URI | Pre-registration is a redirect-URI admission site like the registration surfaces, so a configured plain-`http` collector refuses startup, naming the entry — see [the admission rule](#the-redirect-uri-admission-rule-all-four-sites). |
| `GATEWAY_CUSTODY_KEYS` unset or empty, or a document mixing the flat and structured spellings, or a keyset with no active entry or more than one active entry | Without a key the gateway could mint nothing it can later decrypt; two live *sealing* keys would let a transplanted envelope header reach a second key, breaking the single-active-keyset invariant that closes AES-GCM's missing key commitment today. Retained entries are not sealing keys — they decrypt only — so a structured keyset may carry them beside the one active entry; a document mixing the two spellings has no single reading. |
| A `GATEWAY_CUSTODY_KEYS` entry whose key is not exactly 32 bytes (or is not base64) | AES-GCM follows the key's length, so a 16- or 24-byte key would silently run AES-128 or AES-192 for the key's whole life and falsify the pinned-algorithm claim. |
| `GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES` too large for `GATEWAY_FORM_MAX_BODY_BYTES` | The two bounds are coupled: a refresh request carries the grown refresh token in its form body, so a provider-token bound past the cap's headroom makes sign-ins succeed while every refresh fails over-cap. The error names both settings. |
| Neither `IDP_CLIENT_SECRET` nor `IDP_CLIENT_SECRET_FILE` configured (or a blank environment value) | The gateway's identity-provider client is a **confidential client**: its secret authenticates the code exchange and the refresh grant on every identity-leg token request, in both positions of `IDP_PKCE_ENABLED`, so no deployment runs without one. The refusal names the setting; see [the no-PKCE mode](#the-no-pkce-mode-and-what-it-costs) and [the secret's two spellings](#the-idp-client-secrets-two-spellings). |
| Both `IDP_CLIENT_SECRET` and `IDP_CLIENT_SECRET_FILE` configured | A secret with two possible values has no single value, so it is delivered by exactly one spelling. The refusal names both settings — the same mixing refusal the keyset seam's settings carry. |
| A `GATEWAY_SIGNING_KEY` and a `GATEWAY_SIGNING_KEYS` both configured | The singular setting is the no-rotation shape and the structured setting is the keyset shape; the gateway would otherwise have two candidate active keys and no honest way to choose. The refusal names both. |
| A partial direct endpoint trio | `IDP_AUTHORIZATION_ENDPOINT`, `IDP_TOKEN_ENDPOINT`, and `IDP_JWKS_URI` are all-or-nothing: some set and some missing would give the identity leg two endpoint sources whose disagreement is undetectable. The refusal names the configured and the missing members. |
| A direct endpoint value that is not a well-formed absolute URL | A value with no scheme or no host cannot be addressed as an endpoint at all; the refusal names the setting. |
| A direct endpoint over plain http with no back-channel base owning its origin | The code, the carried session refresh token, and the client secret never ride a plain leg the operator has not explicitly owned by pointing `IDP_BACKCHANNEL_BASE_URL` at that origin. |
| `IDP_ISSUER` over plain http with no back-channel base | The configured issuer is the identity anchor in either endpoint mode — the pin's comparison value always, the discovery fetch's target in discovery mode — and the override's plain-leg ownership reaches the endpoints the leg calls, never the anchor itself. |
| The DCR registration store unreadable or unparseable | See [the store](#dynamic-client-registration-and-its-store). |

### Reserved toolset names

`authorize`, `token`, `register`, `revoke`, `callback`, `consent`, `jwks.json`.

The list mirrors the front router's authorization-surface alternation verbatim, so the
startup guard and the routing stay in step when either changes. The rule is a
**first-segment** rule and `/dial/`-scoped: it is applied to the first segment of a
resource path only — a reserved name deeper in a path (`toolsets/public/token`) passes,
because the authorization-surface capture is a first-segment match. `jwks.json` is listed
for fidelity to the router's alternation; it is refused only as a first segment (the
decoded segment rules do not refuse an internal dot — only a trailing one).

## Topology

| Setting | Default | What it is |
|---|---|---|
| `GATEWAY_PUBLIC_ORIGIN` | `http://localhost:8090` | The gateway's public origin: the issuer of every token it mints and the base URL of every discovery document. Fixed by the front router's published port. |
| `GATEWAY_INTERNAL_PORT` | `8091` | The port the container binds. Never published to the host — the router is the gateway's only front door. |
| `DIAL_COMPOSE_NETWORK` | `dial-instance_default` | The DIAL instance's compose network, joined as external. |
| `DIAL_CORE_BASE_URL` | `http://core:8080` | Core, as the gateway reaches it from inside the compose network. |

## Discovery and the operator restrictions

`TOOLSETS` is an **optional operator restriction** on the served set, a JSON object keyed
by the client-facing toolset **resource path** (a bare name like `notion`, or
`toolsets/{bucket}/{folders…}/{name}` for a stored toolset):

```json
{"notion":{"scopes_supported":["default"]}}
```

| Member | Meaning |
|---|---|
| `scopes_supported` | The toolset's upstream scopes, as Core publishes them. Echoed verbatim on the toolset's protected-resource document where the toolset is pinned here; they belong to the upstream leg, whose authorize URL is built from the toolset's public settings. |

An entry declares **no authentication kind**: the `authentication_type` member is removed.
The kind a flow acts on is Core's, read per flow at the flow's authenticated listing read, so an
operator-declared kind would be a second and staler source of that fact. A mapping
document that still carries the member is refused at parse, by name.

Two modes:

- **Unset (or empty)** — the gateway serves every toolset whose path passes the
  request-time path guard. Existence is decided post-authentication, at the flow's listing
  read, not on any unauthenticated surface.
- **Set** — only its entries are served. Each configured entry is validated at startup for
  the path-grammar refusals (a segment outside the decoded rules, a reserved first
  segment, a trailing dot, a dot or empty segment, an over-length or over-depth path),
  because the front router's map grammar is static and none can be repaired at request
  time for a path the operator pinned.

The toolset's **resource URI is derived**, not configured:
`{GATEWAY_PUBLIC_ORIGIN}/dial/{path}/mcp`, where `{path}` is the canonical encoding of the
resource path. That one spelling is what the router routes, what the protected-resource
document advertises, and what an authorization request's `resource` parameter must equal —
three places that would otherwise drift apart.

### The apps restriction, and the second namespace

`APPS` is a **second, independent operator restriction** — the apps namespace's twin of
`TOOLSETS`, the same JSON-in-environment shape, unset-means-dynamic, set-means-only-its-
entries. It is separate rather than shared because an app and a toolset may legitimately
share a name: they are disjoint registries in Core, so one shared restriction would admit
or deny both names together, an operator decision the deployment never made (a deployment
pinning three toolsets would silently unpublish every app). Inference
(`GATEWAY_INFER_RESOURCE_SINGLE_TOOLSET`) stays toolset-only and never consults `APPS`.

An `APPS` entry declares **nothing but the name**. There is no kind to declare (an
application carries no authentication settings at all — it is credential-free by
construction) and no scopes to declare (no upstream leg exists for an app resource to send
scopes on). A mapping document whose entry carries any other member — `scopes_supported`,
an authentication kind, anything — is **refused at parse**, by field name.

Configured entries are validated at startup for the path-grammar refusals (a segment
outside the decoded rules, a trailing dot, a dot or empty segment, an over-length or
over-depth path), each refusing the container's start with an operator-facing message
naming the entry, because the router's apps map grammar is static configuration with no
view of what Core serves. There is **no reserved-first-segment refusal** for an app path —
the reserved names are `/dial/`-scoped authorization-surface segments, and nothing the
gateway owns is served under the apps namespace's first segment.

The app's **resource URI is derived**, exactly as a toolset's is:
`{GATEWAY_PUBLIC_ORIGIN}/apps/{path}/mcp`, the canonical encoding of the resource path. The
`/apps/` prefix is disjoint from every `/dial/` alternation, so the two derivations resolve
both ways unambiguously — a toolset URI never names an app and vice versa.

### Apps with MCP endpoints are sign-in-able, credential-free

DIAL applications expose MCP endpoints of their own (Core serves them at
`/v1/deployments/{id}/mcp` behind the same unauthenticated 401-challenge tier as the toolset
path). Point a harness at `{GATEWAY_PUBLIC_ORIGIN}/apps/{name}/mcp` and the sign-in works
the way a toolset sign-in does — with one structural difference: **an app resource is
credential-free by construction**, so the flow needs no credential and takes no consent.
The stages are the identity leg, the app read as the user (`GET /openai/applications/{id}`,
which is the DIAL authorization check and the apps namespace's existence refusal in one
read), and then the **kind-driven short-circuit** — no signed-in check, no kind branch, no
credential call, no upstream round-trip, ever, for this kind. The harness's code is minted
with one audit record (`credential_free_short_circuit`) naming the resource kind. Obtaining
a gateway token for an app therefore needs **no sign-in credential and no consent screen**:
the user authenticates once at the identity provider, DIAL authorization is enforced on the
app read, and the token is issued.

The apps **protected-resource document** is served per app at
`/.well-known/oauth-protected-resource/apps/{name}/mcp`, from the resource's own path like
the toolset document, for every guard-passing name — phantom and real alike, zero Core calls
(the mirror property, extended to the second namespace). Its `scopes_supported` is **always
empty** (no upstream leg exists for an app resource to send scopes on — echoing the
restriction's scopes would advertise parameters no leg can use), and it carries no
authentication-kind extension (an app has no kind to echo).

The front router gains the **apps location** beside the toolset one — a prefix location
`~ ^/apps/` whose Core target comes from a `$request_uri` map (`$apps_target`), exactly
the toolset location's shape re-derived: the same segment grammar, the same byte-faithful
forwarding, the same `/mcp`-suffix match domain — with query-string pass-through
(`$is_args$args`), buffering off, `proxy_hide_header WWW-Authenticate` plus a second
`$status`-keyed map synthesizing a challenge quoting the app's **own** metadata path from
the map's `$aseg` capture — and the apps metadata route
(`~ ^/\.well-known/oauth-protected-resource/apps/`) through to the gateway. The full map
mechanism is in [`routing.md`](routing.md).

### The path guard at request time

One shared predicate — the decoded per-segment rules, the reserved first segment, and the
optional restriction — is applied at every site a resource path is resolved: the
protected-resource document, the authorization request's `resource`, and the refresh
grant's resource. Decoded, per segment: non-empty and not `.`/`..`; no forbidden
character (`{`, `}`, `"`, or any control ≤ U+001F — Core's own resource-name set); no
trailing dot (a front-door ruling mirroring Core's creation-side constraint). The whole
decoded path is capped at 900 UTF-8 bytes (Core's own path-size bound) and at
`RESOURCE_PATH_MAX_SEGMENTS` segments. A segment whose percent-escapes do not decode as
strict UTF-8 is refused with the same reason class. A guard failure answers the surface's
existing shape (404 at discovery, `invalid_target` at the authorization and token
endpoints) and records a fixed-vocabulary reason: `invalid_resource_path`,
`reserved_path_segment`, or `restricted_toolset`. At the token endpoint those reason
tokens reach the record through the closed refusal table, keyed by error code plus
refusal class, so a refusal never lands on an uncommitted token.

The guard's verdict is over the **canonical** form: an offered path is canonicalized
(segmentation precedes decoding; each segment strictly-UTF-8 decoded and re-encoded —
unreserved characters raw, everything else `%XX` uppercase hex) and the restriction's
membership is decided canonical-vs-canonical, so two spellings of one resource are one
resource — one flow record, one token audience, one restriction verdict.

The **reserved-name rule is a first-segment rule** and `/dial/`-scoped only: the router's
authorization-surface location captures `/dial/{segment}/…` at the first segment, and a
stored resource's first segment is its type segment (`toolsets`, `applications`), so a
reserved name appearing deeper (`toolsets/public/token`) is a legal, routable path.

A **second guard** covers the apps namespace, the mirror of this one beside it: the same
decoded per-segment rules, the `APPS` restriction in place of the toolset restriction, and
— the one difference — **no reserved-name check**, because nothing the gateway owns is
served under the apps namespace's first segment (the reserved names are all `/dial/`-scoped).
It is applied at the same sites for an app path (the apps protected-resource document,
the apps-shaped `resource`, the refresh grant's resource), answers with the same surface
shapes and the same kind of fixed-vocabulary reason (`invalid_resource_path`,
`restricted_app`), and shares its rules with the router's apps map grammar so the guard
and the routing stay in step (the two are a stated division of labor — the map is a
routability filter over the wire form, this guard the authority over the decoded form;
[`routing.md`](routing.md) states the one asymmetric class this leaves).

### Discovery is registry-independent (the mirror property)

The gateway's unauthenticated discovery tier brings nothing Core's own does not. Core's MCP
path answers an unauthenticated call — for a toolset that exists or one that does not —
with 401 and a challenge naming the protected-resource document, because its auth check
precedes any registry lookup; Core's own protected-resource route answers any well-formed
name with a registry-independent echo document. So **any guard-passing, restriction-admitted
name is served its protected-resource document, phantom and real alike**, with **no Core
call at all** and no Core credential of the gateway's own — for an app name exactly as for a
toolset name (Core serves the apps tier from the same `toolsets.security` configuration that
serves the toolset tier; there is no apps-specific security configuration). Existence is
decided at the same moment on both sides of the front door — post-authentication, at the
flow's per-user read, which is the namespace's existence refusal (the toolset listing read
for a toolset, the app read for an app). Discovery's availability is
therefore the gateway's own: a document is still served while Core is down. What would let
the gateway refuse phantoms at the door is a Core-side change (a registry-bound
protected-resource route), not something built here.

The gateway serves two discovery documents. The **authorization-server metadata** is one
flat document at the host root for a single path-less issuer (the public origin), shared
by every resource — toolset and app alike; it advertises both the code and refresh grants,
S256, token-endpoint authentication `none`, and client-id-metadata-document support, and it
advertises **no scopes of its own** — the gateway enforces none, and a client faithfully
echoes what it is advertised, so an advertised scope comes back on the identity-provider
leg where it may fail. Each served resource gets its own **protected-resource document** —
at `/.well-known/oauth-protected-resource/dial/{path}/mcp` for a toolset, at
`/.well-known/oauth-protected-resource/apps/{path}/mcp` for an app (`{path}` read from the
**raw request path**, so the document echoes the caller's own spelling) — carrying its
path-derived resource URI and the single authorization server, plus its upstream scopes
where the restriction pins the toolset (an app's document carries no scopes at all, always).
The **authentication-kind extension is omitted** on both: under dynamic serving this
surface has no kind source that would not mean a Core call, and an app has no kind to echo.

The authorization-server metadata also answers, byte for byte, at the other locations a
discovering client may try for this issuer: the OpenID Connect location
(`/.well-known/openid-configuration`) and the path-insertion form of both
(`/.well-known/oauth-authorization-server/{suffix}` and
`/.well-known/openid-configuration/{suffix}`). Three rules keep these aliases honest.

- **The issuer never echoes the suffix.** `issuer` is the public origin at every alias. The
  gateway has one issuer, the one every token and every RFC 9207 `iss` carries; a document
  naming a suffixed issuer would assert an identity no token has. A strict client then
  discards the document, because its `issuer` differs from the one the client derived, and a
  lenient client gets working endpoints. Neither is told anything false. The suffix is never
  read, logged, or reflected.
- **No OpenID Provider members.** The OpenID Connect location serves the OAuth document as
  it stands: no `subject_types_supported`, no `id_token_signing_alg_values_supported`, no
  `userinfo_endpoint`, and no scope list at all. The gateway is not an OpenID Provider, and
  advertising one would make a relying party expect an ID token that never arrives. A
  strict OpenID Connect relying party refuses the document, which is the right outcome.
- **The method posture is the canonical path's.** Only `GET` is served; every other method is
  the framework's `405` with `Allow: GET`, and no alias serves an `Access-Control-*` header.

Every other `/.well-known/` path the front door does not serve is answered by the router
with a fixed JSON `404` and is never forwarded to Core (see
[`routing.md`](routing.md#the-closed-well-known-namespace)). The root
`/.well-known/oauth-protected-resource` is deliberately not served: one root document can
name only one resource, and the gateway's tokens are bound to each resource's own URI.

## Client registration

Clients resolve in a fixed priority order:

1. **Pre-registered** — an operator's own list in `PRE_REGISTERED_CLIENTS`, a JSON object
   keyed by client id with `redirect_uris` and an optional `client_name`. No fetch, no
   registration call.
2. **Client ID Metadata Document** — a URL-shaped client id. The gateway fetches the
   document and treats its `redirect_uris` as the registration. This is the path a
   CIMD-capable harness takes, and it is why the AS metadata advertises the support flag.
3. **Dynamic client registration** — only while `DCR_ENABLED` is true. See below.

| Setting | Default | What it is |
|---|---|---|
| `GATEWAY_CIMD_ALLOWED_ORIGINS` | `https://claude.ai` | Comma-separated origins allowed to host a client-metadata document. An empty value allows none. |
| `GATEWAY_CIMD_USER_AGENT` | `dial-mcp-gateway/0.1 (+mcp-signin)` | The `User-Agent` the fetch carries. **Load-bearing**: the flagship harness's metadata origin is fronted by bot protection that rejects library-default agents outright, which would surface as a late, misleading registration failure. |
| `GATEWAY_CIMD_CONNECT_TIMEOUT_SECONDS` | `5` | Connect timeout for the fetch. |
| `GATEWAY_CIMD_TOTAL_TIMEOUT_SECONDS` | `10` | Total timeout for the fetch. |
| `GATEWAY_CIMD_MAX_DOCUMENT_BYTES` | `65536` | The response-size cap, enforced while reading rather than after. |
| `GATEWAY_CIMD_CACHE_TTL_SECONDS` | `300` | How long a fetched document is cached, so a client's own edit takes effect within one TTL. |
| `GATEWAY_CIMD_CACHE_MAX_ENTRIES` | `256` | The cache's bound, so client ids cannot grow the gateway's memory without limit. |

The fetch is a server-side request forgery surface a client steers, so its controls are
part of the contract rather than hardening:

- **HTTPS only**, and the origin must be on the allowlist.
- **No redirects.** A 3xx fails the fetch: a redirect is the pivot an attacker needs, and
  there is no legitimate use for one here.
- **Private, loopback, and link-local addresses are refused**, on every resolved address
  rather than the first. The connection is then made **to the validated address** with the
  host name preserved in the `Host` header and in the TLS SNI extension — so a name that
  answers publicly for the check and privately for the connection gains nothing, while
  certificate verification still names the client's own host.
- The body is capped, the content type must be `application/json`, and the document must
  declare the URL it is served from.
- Responses are cached with a TTL and a size bound.

### The redirect-URI admission rule (all four sites)

**A registered redirect URI MUST be `https`, or `http` on a loopback host** (`localhost`,
`127.0.0.1`, `[::1]`, any port) — the RFC 8252 §7.3 loopback shape a native app's
ephemeral-port listener needs. A plain-`http` redirect on a real host is the collector the
authorization response — the code and the echoed `state` — would cross in cleartext; the
rule closes RFC 9700 §2.6's MUST NOT and the MCP authorization specification's own
redirect-URI MUST in one clause, and it is an **admission** rule, enforced where a redirect
URI enters the system so every later use inherits it. It is enforced at **four sites**:

| Site | Refusal |
|---|---|
| The DCR registration body (`DCR_MAX_REDIRECT_URI_LENGTH`'s sibling check) | The registration is refused with a plain-language error naming the rule; no record is stored, and the value never reaches the exact-match validation. |
| The CIMD document's `redirect_uris` | A document listing a non-loopback plain-`http` entry is refused **whole** — no authorization request resolves against it. |
| Pre-registered `PRE_REGISTERED_CLIENTS` | A configured entry carrying one **refuses startup**, naming the entry — the operator's configuration is an admission site, not a bypass. |
| The durable store's **load path** | A stored record carrying one refuses startup, naming the record — a record admitted before the rule landed, or planted on the volume, otherwise stays usable because client resolution reads the store without re-checking. Recovery is the corrupt-store discipline's own: rename the store aside or remove the record, and the affected harnesses re-register. |

Loopback `http` stays admitted everywhere: the ecosystem's own example documents list
loopback `http` redirect URIs, and non-loopback `http` is already non-conforming for every
client the ecosystem defines — so **no conforming fielded harness's registration changes
behavior**.

## Dynamic client registration and its store

DCR is the config-gated fallback for harnesses that can neither present a metadata
document nor be pre-registered. It is **off by default**, and while off the endpoint
answers the documented disabled-error (404) and no registration endpoint appears in the
AS metadata — a client is never steered onto a path that cannot register anything.

| Setting | Default | What it is |
|---|---|---|
| `DCR_ENABLED` | `false` | Gates the entire DCR path, resolution included. |
| `DCR_STORE_PATH` | `/data/dcr-registrations.json` | The store file, on the compose bind mount. |
| `DCR_MAX_REGISTRATIONS` | `1024` | The cap on stored registrations. |
| `DCR_MAX_BODY_BYTES` | `8192` | The cap on a registration request body, applied while it is read. The **governing** bound: the per-record maxima below must be jointly reachable inside it. |
| `DCR_MAX_REDIRECT_URIS` | `8` | How many redirect URIs one registration may list. |
| `DCR_MAX_REDIRECT_URI_LENGTH` | `512` | How long one registered redirect URI may be. |
| `DCR_MAX_CLIENT_NAME_LENGTH` | `256` | How long a registered `client_name` may be. |

The endpoint is unauthenticated and accepts a body, so it is bounded in two dimensions:
`DCR_MAX_BODY_BYTES` bounds what is **read** (the cap is applied as the bytes arrive, so an
oversized body never allocates the memory it was meant to bound), and the three per-record
limits bound what is **stored** (`DCR_MAX_REGISTRATIONS` bounds how many records there are;
these bound how large each one may be). An ordinary registration is a few hundred bytes and
well inside every one of them.

**The two kinds of bound have to agree, and startup enforces it.** The per-record maxima
apply to a request that the body cap must be able to carry, so the largest registration the
maxima permit — every redirect URI at its maximum length, plus a client name at its maximum,
plus the JSON around them — must fit inside `DCR_MAX_BODY_BYTES`. A configuration where it
does not is refused at startup with a message naming both settings, because the alternative
is silent: the endpoint would refuse as oversized exactly the registrations its own
configuration advertises, and an operator who raised a per-record maximum expecting larger
clients would see no error and no effect. Raising a per-record bound therefore means raising
the body cap alongside it. The defaults satisfy the relationship comfortably.

Registrations are the only gateway state that both outlives a restart and is cached by
clients indefinitely, so they are the only state made durable — as **one JSON file in a
mounted volume**. No database, no lock manager, no schema.

### The volume mount

The store lives at `DCR_STORE_PATH` on a **bind mount** (`./data:/data` in the compose
file) rather than a named volume, so the file is plainly on the host: an operator
recovering from a corrupt store renames it aside by path, and a lost store is visible as a
missing file rather than hidden inside a Docker-managed volume.

The save attempts an **owner-only file mode (0600), best-effort, never a registration
failure**. Where the mounted filesystem implements POSIX permission changes the file ends
up readable only by the image's uid, and the host directory must be writable by that uid
(10001). Where it does not — a Windows host path reaches the container as the 9p/DrvFs
filesystem, where `chmod` is refused with `EPERM` — the gateway logs a warning naming the
store path and the save proceeds: a filesystem that cannot carry a mode cannot carry it
for any file, so the mode is unenforceable there in principle rather than a gap in the
gateway. On such a mount the store's protection is the **volume owner's boundary** — the
mounted volume and the node it rests on — and the store holds no secret at all (client ids,
redirect URIs, a display name, a timestamp; every client is public PKCE). The property the
mount is chosen for is the operator-visible path, not the mode.

**The store's boundary and a key's boundary are not the same one.** Under the pod shape
they diverge, and the earlier statement that they were identical no longer holds. The
store's protection is the **mounted volume and the node**: the store is read-write, and its
integrity is the volume owner's. A key's protection is its **injection path**: the
environment-variable surface (the pod spec, a Secret, `/proc` environ) or the read-only
key-file mount on the node. The two are equivalent only where they still share a volume
class — a `file`-sourced key sitting on the same volume class as the store rests on the
same boundary the store does; the equivalence is dropped everywhere it is not true. The
future custody envelope is the planned step that moves the custody key's at-rest boundary
to a KMS wrap, but this statement is written to be true **before** that lands: today, every
key's boundary is its injection path.

### Durability

Each accepted registration is written **before the response is returned**, so a client
that caches the id it just received never holds an id the store does not know. The write
is atomic — a temporary file in the same directory, then a rename over the store — so a
crash can leave a temporary file behind, never a half-written store. Atomicity is this
mount's guarantee on every filesystem the volume could be mounted from; the file mode is
the best-effort extra described above.

### Corruption refuses startup

An **unreadable or unparseable store refuses startup**, with an error naming the path.
Starting empty instead would invalidate every registered client id without a trace, and
the operator would learn about it from a harness rather than from the gateway.

**Recovery is one command:** rename the corrupt file aside and restart.

```bash
mv data/dcr-registrations.json data/dcr-registrations.json.corrupt
wsl -e docker compose restart mcp-signin-gateway
```

The rename is also the operator's acknowledgment that the old contents are gone; harnesses
re-register on their next sign-in.

### The cap

At `DCR_MAX_REGISTRATIONS`, new registrations are refused with a plain-language error
naming the cap, and **existing registrations are untouched**. Evicting the oldest would
invalidate a possibly live client — the same loss as a dropped store, but silent. There is
**no registration expiry**: a registration's lifetime is the client's own choice, and an
expired one would recreate the harness-holds-a-cached-id problem the store exists to
prevent.

### Loss semantics, in plain language

If the store is lost, deleted, or reset:

- every DCR-registered client id stops resolving;
- a harness holding a cached client id gets an **unregistered-client** refusal on its next
  authorization request — not an opaque failure;
- it then does what it did the first time: **re-registers and continues**.

No human action is required. The loss costs one re-registration round-trip per DCR
harness and nothing else: issued access and refresh tokens are self-contained JWTs that
never consult the store, and the other registration paths have no gateway-side
registration state to lose (a CIMD document's source of truth is the client's own URL;
pre-registered clients are operator configuration, inherently durable).

### Dormant, not deleted

While `DCR_ENABLED` is off the store is **preserved but dormant**: the endpoint answers
the disabled-error, DCR client ids do not resolve, and re-enabling restores every
registration exactly as it was.

## Abuse bounds

Unauthenticated endpoints that allocate state are bounded. Each bound resets on a fixed
one-minute window, and the per-source map is itself bounded, since an unbounded map keyed
by a caller-supplied value is the same exhaustion problem in a different place.

| Setting | Default | What it is |
|---|---|---|
| `GATEWAY_RATE_PER_SOURCE_PER_MINUTE` | `30` | What one source address may ask for. The address comes from the router's forwarded header, falling back to the socket peer. |
| `GATEWAY_RATE_GLOBAL_PER_MINUTE` | `600` | What the endpoint as a whole accepts. |
| `GATEWAY_FLOWS_MAX_LIVE` | `10000` | The hard cap on live flow records. Past it the **oldest are evicted**, and their browsers receive the ordinary expired-session page — an outcome a user can act on. |
| `GATEWAY_FORM_MAX_BODY_BYTES` | `16384` | The byte cap on a form body at the token and revocation endpoints, applied while the body is read. Raised from 8192 because a refresh request carries the grown refresh token — which carries the custody envelope — in its body; the shared cap means `/dial/revoke`'s read bound rises with it. Coupled with `GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES`. |
| `GATEWAY_CIMD_MAX_CONCURRENT_FETCHES` | `8` | How many client-metadata fetches may run on the shared worker pool at once. |
| `AUDIT_FACT_MAX_LENGTH` | `256` | The longest a caller-supplied fact may be in an audit record. |

### Body caps on the unauthenticated endpoints

Three endpoints here take a body and none of them authenticates its caller:
`/dial/register` (`DCR_MAX_BODY_BYTES`), `/dial/token` and `/dial/revoke`
(`GATEWAY_FORM_MAX_BODY_BYTES`). Each applies its cap **while it reads**, not after — a cap
enforced after the whole body was allocated has already allocated the memory it exists to
bound, so the read is chunked and stops at the first byte past the limit. An over-cap body
is refused whole rather than parsed in part: a form whose meaning depends on which
parameters survived truncation has no meaning to validate.

The front router states its own `client_max_body_size` explicitly rather than relying on
nginx's implicit 1 MB default, so the public bound is a value in the configuration instead
of a library default nobody chose. It sits above the gateway's per-endpoint caps, which are
what actually apply to each surface.

### The shared worker pool, and the CIMD fetch's share of it

Every outbound leg runs on one bounded shared worker pool, so a sustained flood of slow
requests queues legitimate work behind the flooder's. The event loop itself stays responsive
— that is what the offload buys — and the one slow leg an unauthenticated caller steers is
the client-metadata fetch, because its target is the caller's choice. `GATEWAY_CIMD_MAX_CONCURRENT_FETCHES`
caps how many of those may run at once, so an attacker cannot occupy more than that share of
the pool and the flow's identity and credential legs keep capacity beside them. What remains
is queue waiting behind attacker-shaped slow requests within the rate limits above — the
inherent residual of any bounded shared resource, and accepted on record for the
single-instance PoC.

This control holds only while the pool is reached through the front router:
`mcp-signin-gateway` is container-internal and carries **no host-port mapping**, so 8091 is
never published. That is also what makes `X-Real-IP` trustworthy for the per-source limit —
a request delivered to 8091 directly never crossed the router and carries whatever headers
its sender chose. `docker-compose.yml` and `router/nginx.conf` both state the invariant at
the place it would be broken.

A browser that lands on a callback with an unknown, expired, or evicted flow receives a
plain-language HTML page saying the sign-in session expired and to start the sign-in again
from the harness. The page never names a flow id or a record's state: the operator gets
the specifics from the gateway's own log.

### The authorization-server surface is back-channel only

**No endpoint of the authorization-server surface serves any `Access-Control-*` header** —
the browser-facing routes (`/dial/authorize`, the callbacks, the consent route) and the
back-channel endpoints (`/dial/token`, `/dial/revoke`, the discovery documents, the
registration endpoint) alike — and **no preflight is handled**: an `OPTIONS` request against
`/dial/token` (or any other endpoint) receives the framework's own 405 for a method no route
serves. This is a stated rule, not an implementation accident: an operator integrating a web
frontend against this gateway finds the refusal stated here rather than discovering it as a
bug.

**A browser frontend is not a supported client shape.** The clients are harness processes
that exchange codes and tokens on their own loopback redirects and back channels; a
cross-origin browser page can neither read a token response nor drive the authorize
surface's redirects, and the surface is built for exactly that shape. RFC 9700 §2.6 permits
CORS at the token endpoint (a MAY, never a requirement) and forbids it at the authorization
endpoint; **the gateway declines the MAY, surface-wide**. The posture is pinned by a test —
no response from any AS-surface endpoint carries an `Access-Control-*` header — so one future
`add_middleware(CORSMiddleware)` line, added for some unrelated convenience, fails the suite
rather than silently opening the token endpoint to browser origins.

## The federation flow

A validated authorization request is answered with a redirect to the identity provider, and
the flow then runs three browser legs and one back-channel call:

1. **The identity provider.** The redirect carries the flow id as the provider's
   `state`, and — in the default PKCE mode; see [the no-PKCE mode](#the-no-pkce-mode-and-what-it-costs) —
   the gateway's own S256 challenge. The redirect requests **exactly the gateway client's
   configured default scopes** (`IDP_CLIENT_SCOPES`) — a client's own `scope`
   parameter is accepted at `/dial/authorize` and never relayed, because a scope the
   gateway's client does not carry fails the whole leg.
2. **The callback and the DIAL authorization check.** The code is exchanged over the
   provider's back-channel base (`IDP_BACKCHANNEL_BASE_URL` when the deployment sets the
   override — locally plain http with no self-signed TLS; the issuer's own origin
   otherwise), and the identity token is verified against the provider's published keys
   before anything is read from it. The toolset's public settings are then read **as that user**:
   Core answers 403 when the user cannot read the toolset, which is the authorization check
   and happens before any upstream round-trip.
3. **The upstream consent.** The browser passes a display-only attribution interstitial —
   the upstream consent names Core's client, so this page is what tells the user which
   harness and which toolset they are approving — and is sent to the upstream's authorize
   endpoint built from the toolset's *public* settings: Core's client id, Core's published
   challenge, **the gateway's own derived upstream callback**
   (`{GATEWAY_PUBLIC_ORIGIN}/dial/callback/upstream`), and the flow id as `state`. The
   verifier stays in Core. The callback is derived, never read from the toolset's stored
   `auth_settings.redirect_uri` — that field is a value Core stores from its allowlist's
   first entry at registration time and other components overwrite at will, so a flow that
   read it would send the browser to a callback no flow record exists for. The callback
   must nonetheless be present in Core's `allowedRedirectUris`, and every
   dynamically-registered toolset must be repaired afterwards, so the upstream registers
   it — the migration runbook in [the local environment](local-environment.md) is the
   procedure, and [the deployment contract](pod-contract.md) states the deployment-facing
   configuration it rides on.

   The page **continues itself** (a meta refresh, with a plain link beside it for a
   browser that ignores one): it is an attribution notice, not a prompt, and a manual
   button would turn it into a second consent the user has to give. It carries no form,
   and that is load-bearing rather than cosmetic — a `method="get"` form submission
   *replaces* its action URL's query with the query built from the form's own successful
   controls, so a form whose parameters lived in the action and whose body carried no
   controls would submit to the bare endpoint with every parameter, including the flow id
   as `state`, silently dropped inside the browser. The gateway guards the request before
   serving the page: a required parameter missing from the URL it built — a `scope` only
   where the toolset advertises scopes — fails the flow with the plain-language error page
   rather than delivering an incomplete request the upstream could only reject.
4. **The upstream callback.** The `state` must round-trip the flow id; the flow record is
   then **destroyed before the credential call is made**, so a replayed callback finds no
   flow and a guessed flow id injects nothing. The credential call is
   `POST /v1/ops/toolset/signin` at **USER level** with the user's identity token, which is
   what makes Core stamp the stored credential with that user's `sub`.

The identity token serves the sign-in flow and nothing else: its one decision step —
"may this user sign in to this toolset, and are they already signed in?" — and its one
action, the credential call, after which it is dropped. The decision step is **one
read** — the deployment-listing route, which carries the settings projection and the
per-caller statuses in the same answer — so the token is presented at most twice across
the flow: never for anything else, and never beyond the flow's TTL. No `offline_access`
is ever requested, so no beyond-session
grant is acquired; the ordinary, **session-bound** refresh token the provider issues at the
exchange is captured and carried for the refresh window (see [Custody](#custody-the-identity-providers-session-refresh-token)).

If the user already holds a stored upstream credential for the toolset — at **user level**
or **global level** — the flow short-circuits: no interstitial, no upstream consent,
straight to code issuance, **whatever the toolset's authentication kind**. That is what
makes a repeat sign-in one silent login.

The stages after the listing read are a **routing decision**:

- **The signed-in check** short-circuits the upstream stage when Core reports the caller
  signed in at user level, or the toolset signed in at global level. A status that is
  absent, unreadable, or `FAILED` is not signed in, and the check fails closed into the kind
  branch — no token is minted on an unreadable status. The app-level status is not read:
  an app-level credential is not a sign-in for a user's flow.
- **The kind branch**, only when no credential is stored. An `OAUTH` toolset runs the
  upstream consent leg as above (its OAuth settings — client id, endpoints, challenge,
  callback — are required on this branch and only this branch). Any other kind, **or an
  unreadable kind**, is refused with a plain-language page saying the toolset's credential
  is configured directly in DIAL and cannot be established by a consent flow: fail-closed,
  no upstream round-trip, audited `non_oauth_toolset`. The refusal loops benignly like any
  auth error — each cycle costs one identity-leg exchange and changes nothing — until an
  administrator stores the credential out of band, after which the same flow
  short-circuits.

**Use, not establish (the delegation, stated).** The flow never *establishes* a credential
at GLOBAL level — the credential call stays `credentialsLevel: USER` on every establishing
path. When the short-circuit uses a global credential an operator stored, the flow *uses*
it: Core injects it on the data path, the access is the same the same user already holds
through Core's own paths with a primary-provider token, and the minted token carries only
that user's own claims.

A name Core does not know is refused at the listing read — a plain-language page, audited
`unknown_toolset` — and that is the **toolset namespace's existence refusal**: discovery
answered the name a document by the mirror property (above), so existence is decided
post-authentication. The app flow's read is the apps namespace's existence refusal the same
way (a name Core does not know raises `unknown_app`), so the system has one existence
refusal per resource kind, both post-authentication, and no unauthenticated tier on either
side of the front door carries an existence oracle in either namespace.

### The consent/attribution checkpoint (operator notes)

On the **first** sign-in a given client makes for a given user, the flow stops at a
**decision page** before any token is minted, on all three mint paths (the app kind's
zero-page short-circuit, the toolset stored-credential short-circuit, and the toolset
consent branch). The page names the resolved client (its registered `client_name` where one
exists, presented as a name — a registrant supplies it — with the client id beside it, which
is the verifiable identifier), the addressed resource, and the registered `redirect_uri` the
code will be delivered to. It carries two buttons — approve and deny — in a plain form, shows
no scope list (the surface accepts and drops the client's `scope`), and does not
auto-continue. The user's own act is the point: a crafted authorization link can drive a live
identity-provider session silently, so the decision that names the client is the gateway's
own.

The approvals live in an in-memory registry keyed per `(subject, client_id)`, and its
semantics are the ones an operator should expect:

- **A restart re-prompts every user once per client.** The registry is process memory (no
  persistence, no cookie — the decision rides the flow id, which is server-side), so a
  gateway restart forgets every approval and the next sign-in for each client shows the page
  again. This is by design and fail-safe: a lost approval re-prompts, it never skips.
- **Cap pressure evicts the oldest approvals first.** `GATEWAY_APPROVED_CLIENTS_MAX` bounds
  the registry absolutely; when it is reached the oldest entries are dropped, and those users
  re-approve once. Growth is bounded upstream by the flow store's own limits — the only write
  path is an approve click on a live, identity-completed flow.
- **There is no operator bypass.** No configured or pre-registered client id skips the page:
  the client-facing surface carries no client authentication, so a crafted link could wear any
  configured id with an attacker's own redirect, and an auto-trust keyed on the id would make
  that link the one shape that skips the page while naming a name the user trusts. The honest
  zero-page path for a trusted harness is the user's own one approval.
- **The CIMD allowlist remains the naming control it always was.** `GATEWAY_CIMD_ALLOWED_ORIGINS`
  bounds which origins may name a client; the checkpoint is the *attribution* control that
  sits beside it — the two are complementary, not alternatives.

The first attribution is audited (`attribution_required` when the page renders,
`attribution_approved` or `attribution_refused` at the action) under the trail's usual
discipline, with non-credential facts only.

### The app flow

An app resource (a DIAL application with an MCP endpoint) is served through the second path
shape, `{GATEWAY_PUBLIC_ORIGIN}/apps/{name}/mcp`, and its flow is a strict subset of the
toolset flow's stages:

1. **The identity leg** — unchanged machinery, kind-agnostic by construction.
2. **The app read as the user** — `GET /openai/applications/{id}` with the live user's
   identity token, in the listing read's position. This one read is the DIAL authorization
   check and the apps namespace's existence refusal: a **403** is the no-access page, a
   **404** is the plain-language existence refusal audited `unknown_app`, and an
   unreachable or unreadable answer fails closed as a deployment fault and never as an
   existence answer.
3. **The kind-driven short-circuit — unconditional for this kind.** No signed-in check runs
   (an app has no per-app status members to read), no kind branch runs (no consent could
   establish anything for a resource that needs no credential), and no credential call and
   no upstream round-trip ever run. The flow mints the harness's code directly, the tokens
   the same shape a toolset sign-in issues, the audience naming the app's resource, and
   writes one audit record (`credential_free_short_circuit`) naming the resource kind.

The reason this is not a new mechanism: C1's general rule — *the upstream stage runs only
when the credential is missing AND the kind makes it establishable by consent* — already
decides it, because for an app the second conjunct is false **by construction** (an
`Application` in Core carries no authentication settings and no consent leg). The token
endpoint's resource match and the refresh grant's resource match resolve the app shape
through the same shared derivation, so an app resource is refused on a toolset token's
refresh and vice versa.

| Setting | Default | What it is |
|---|---|---|
| `IDP_CLIENT_ID` | `dial-mcp-proxy` | The gateway's identity-provider client. The local realm's is created by `scripts/provision_keycloak.py`; an external provider's is registered in that provider's own admin console, by whoever owns the deployment. |
| `IDP_CLIENT_SECRET` | *(empty)* | **Required** (in one of its two spellings). The gateway's client is a confidential client, and the secret authenticates every identity-leg token request — the code exchange and the refresh grant — in both positions of `IDP_PKCE_ENABLED`; startup refuses without it. The committed placeholder stays empty: a deployment fills the value in its own `.env`. Delivered by exactly one spelling — this environment variable, or the file spelling `IDP_CLIENT_SECRET_FILE` — see [the secret's two spellings](#the-idp-client-secrets-two-spellings). |
| `IDP_CLIENT_SCOPES` | `profile,email` | The scopes the identity-provider redirect requests, and the only ones. They must be client scopes the configured client carries at the provider. Never `offline_access`. Whether `openid` belongs here is a per-provider fact: the local realm's client scopes do not include it (requesting it fails the whole leg), while an external provider commonly requires it to issue an identity token at all — set the profile the provider requires. |
| `IDP_ISSUER` | `https://idp.example.com/` | The browser-facing issuer, pinned exactly: the `iss` a token carries whichever port the token endpoint was reached on, and the anchor the discovery document and every identity token are validated against. The placeholder default names the RFC 2606 reserved domain — set the deployment's real issuer in `.env`. For a provider whose issuers vary across its sign-in journeys, this is **the one sign-in journey's issuer** this deployment federates (see [the endpoint source](#the-identity-legs-endpoint-source) and [the profiles](#configuration-profiles)). |
| `IDP_BACKCHANNEL_BASE_URL` | *(unset)* | The back channel for the server-to-server calls: an origin override whose scheme/host replace the issuer's, the provider's path kept. Unset, the calls go to the issuer's own origin. Its origin is a trust claim — see [the override warning](#the-back-channel-override-is-a-trust-claim). |
| `IDP_DISCOVERY_CACHE_TTL_SECONDS` | `300` | How long a fetched discovery document is reused before the next identity leg fetches it again — the documented bound on how long a provider's endpoint change goes unnoticed. No effect where the direct endpoint trio is configured: that mode fetches nothing. |
| `IDP_PKCE_ENABLED` | `true` | Whether the identity leg's redirect carries a PKCE challenge. Off only for a provider that cannot support PKCE — see [the no-PKCE mode](#the-no-pkce-mode-and-what-it-costs). |
| `IDP_AUTHORIZATION_ENDPOINT` / `IDP_TOKEN_ENDPOINT` / `IDP_JWKS_URI` | *(unset)* | The optional direct endpoint trio — all three or none; where the full set is configured, no discovery fetch is attempted. See [the endpoint source](#the-identity-legs-endpoint-source). |
| `DIAL_CORE_BASE_URL` | `http://core:8080` | Core, as the gateway reaches it. |
| `GATEWAY_OUTBOUND_TIMEOUT_SECONDS` | `30` | How long an outbound call to Core or the identity provider may take. Generous because Core's credential call reaches the upstream before it answers. |

The two callback paths are **derived, not configured**: `/dial/callback/idp` and
`/dial/callback/upstream`. The front router routes them by name and the identity-provider
client is registered against the first, so a setting for them would let one of the three
places that must agree drift. The upstream callback is also the value Core validates at
exchange time against `aidial.toolsets.security.allowedRedirectUris`: it **must be present
in that allowlist**, and every dynamically-registered toolset must be repaired so the
upstream registers it — the migration runbook is in
[the local environment](local-environment.md), and [the deployment
contract](pod-contract.md) states the deployment-facing configuration it rides on.

### The identity leg's endpoint source

The identity leg uses three endpoints: the **authorization endpoint** its browser
redirect names, the **token endpoint** the code exchange and the refresh grant post to,
and the **key-set URI** the provider's identity tokens are verified against. They come
from **one source, chosen by configuration and never by a runtime event** — whichever
source is configured serves the whole leg, and no endpoint is ever built from the
issuer's spelling by provider-specific URL arithmetic:

- **Discovery — the default.** The provider's OpenID Connect discovery document is
  fetched at `{IDP_ISSUER}/.well-known/openid-configuration` — the well-known path is
  joined to the issuer with exactly one separator, so an issuer spelling that ends in a
  slash works as configured — and its three members are the leg's endpoints. Nothing is
  fetched at startup — the container boots, and the health probe passes, with the
  provider unreachable — and the validated document is cached per process for
  `IDP_DISCOVERY_CACHE_TTL_SECONDS` (default 300 seconds): a cold start or an expired
  entry costs at most one fetch per window, and a provider's endpoint change propagates
  within that TTL. A document that cannot be fetched, parsed, or validated fails the
  leg closed with an operator-facing error and no fallback: the first sign-in after a
  cold start needs the provider reachable, and already-minted tokens never do. The
  failure is remembered for the same window — sign-ins during a provider outage are
  refused again from the record, at most one fetch attempt per window, and the first
  sign-in after the window retries the provider.
- **The directly configured trio.** Where the operator sets all three of
  `IDP_AUTHORIZATION_ENDPOINT`, `IDP_TOKEN_ENDPOINT`, and `IDP_JWKS_URI`, no discovery
  fetch is attempted at all — not fetched and ignored, skipped — and the configured
  endpoints serve the redirect, the exchange, the refresh grant, and the key-set fetch.
  The set is **all-or-nothing**: a partial set refuses startup, naming what is
  configured and what is missing, because a leg whose endpoints come from two sources
  has two spellings of the identity leg.

**When to configure the trio instead of discovery.** For a provider whose discovery
document is unavailable, nonstandard, or served at a spelling the issuer-appended fetch
does not reach — providers whose issuers vary across their sign-in journeys are often
in this class, their metadata tied to a path shape the fetch does not hit. Where that
is the deployment's shape, configure the three endpoints at the provider's own
documented spellings and keep `IDP_ISSUER` as the pinning anchor.

**The mode's trade is the operator's, stated rather than hidden.** In discovery mode a
provider's endpoint change propagates within the cache TTL; in direct mode nothing
propagates it — a provider that moves an endpoint fails every leg against the stale
value with the operator-facing error until the setting is updated. Keeping the
endpoints current is the operator's responsibility in this mode.

**The setting names are shared vocabulary.** `IDP_AUTHORIZATION_ENDPOINT`,
`IDP_TOKEN_ENDPOINT`, and `IDP_JWKS_URI` are the OpenID Connect discovery document's own
member names — the same members and the same explicit-endpoint concepts
(`authorizationEndpoint`/`tokenEndpoint`) a DIAL Core deployment spells for a
statically registered upstream client — so the values move between a discovery
document, Core's configuration, and these settings without translation.

**Validation, in both modes.** A discovery document is validated, not trusted: its
`issuer` member must equal `IDP_ISSUER` exactly, every endpoint the leg would use from
it must share the configured issuer's origin or the back-channel override's, plain http
is refused without the override, redirects are not followed, and the response is
size-capped — a document failing any of these is refused whole, never used partially.
A directly configured endpoint is validated at startup instead: each must be a
well-formed absolute URL, and HTTPS unless it shares the override's origin. One rule
deliberately differs between the modes: a configured endpoint is **not** required to
share the issuer's origin. The document is a provider-asserted input and is bounded
hard; the trio is operator input at the same trust level as `IDP_ISSUER` itself, and a
provider whose token endpoint lives on a separate host from its issuer is a legitimate
shape the direct mode exists to absorb.

### The back-channel override is a trust claim

`IDP_BACKCHANNEL_BASE_URL` re-addresses the server-to-server calls — the discovery
fetch, the token exchange, the refresh grant, the key-set fetch — to its origin, the
provider's own path kept (scheme and host swapped, nothing else). The browser-facing
redirect and issuer matching stay pinned to `IDP_ISSUER` whichever base a call used.

> **The override's origin is a trust claim exactly as wide as its hostname.** An
> endpoint the discovery document names is accepted on any origin the override covers,
> so an override pointed at a host that serves more than the identity provider widens
> where credential-bearing calls — the code, the carried session refresh token, and in
> the no-PKCE mode the client secret — can be steered. Point it at an origin that
> serves only the identity provider.

A provider reachable at one TLS origin for both browser and server-to-server calls —
the common external shape — configures no override at all.

### Configuration profiles

**The local development realm.** The local instance's browser-facing origin is https
with a self-signed certificate, so its profile sets the override to the instance's
internal plain-http port and keeps the realm's own browser-facing issuer —
`IDP_ISSUER=https://keycloak:8443/realms/dial`,
`IDP_BACKCHANNEL_BASE_URL=http://keycloak:8900` (see
[the local environment](local-environment.md)). Its scopes exclude `openid`: it is not
a client scope in this realm, and requesting it fails the whole authorization leg
rather than being ignored.

**An external provider.** A single-origin external provider over TLS sets `IDP_ISSUER`
and no override. For a provider whose issuers **vary across its sign-in journeys**, the
configured issuer is the one sign-in journey's issuer this deployment federates;
`ROLES_SOURCE_PATH` names the claim path the provider's tokens carry roles at;
`openid` joins `IDP_CLIENT_SCOPES` where the provider requires it to issue an identity
token; and `IDP_SSO_SESSION_MAX_SECONDS` is set to the provider's refresh-token window
for a client of this shape.

**Operator prerequisite for a varying-issuer provider: journey-distinct issuance.**
Another journey's token is refused *as a different issuer* only where the provider
issues **journey-distinct issuers** — one `iss` per sign-in journey. Where that is a
provider-side setting, it **must be enabled** in the provider's configuration before
this deployment's sign-ins can work at all: with it absent, every journey's tokens
share one issuer, every sign-in fails at issuer verification (the configured
journey-issuer never matches the shared value), and the only diagnosis a
from-documentation operator has is this prerequisite — the gateway cannot repair a
provider-side configuration from its side of the leg.

### The no-PKCE mode, and what it costs

`IDP_PKCE_ENABLED` (default `true`) decides whether the identity leg's redirect carries
a PKCE challenge. Turn it off **only** for a provider that cannot support PKCE: the
redirect then carries no challenge, and the exchange presents no verifier — the client
secret alone authenticates the token requests, exactly as it does in the default mode.
The gateway's client is a **confidential client** either way: its secret authenticates
every identity-leg token request in both positions of the toggle, and startup refuses to
run without one, naming the setting.

What the mode gives up is the challenge, and the trade is priced, not hidden. The
challenge is what makes an intercepted identity-leg code unexchangable by whoever read
it off the callback URL; in the no-PKCE mode that binding is gone and the client
authentication is the only remaining bar — an interceptor holding both the code and the
secret can spend the code, and on a plain-http front door the code is readable on the
wire, so the mode accepts a strictly weaker position than the default's. That is a price
worth paying only for a provider that cannot do PKCE at all, never for convenience.
The mode is the identity leg's alone: the gateway's own client-facing surface keeps
requiring PKCE from harness clients whichever way this is set.

### The Core routes the flow reads, and why

| Read | Route | Why |
|---|---|---|
| The toolset's listing read | `GET /openai/toolsets/{resource-path}` | The flow's **one** toolset read, made with the live user's identity token, serving all three of the decision step's purposes: it is the **availability oracle** (its authorization is Core's deployment resolution of the resource against the caller's roles — the same decision the MCP data path authorizes every call with, so a 403 here is what the data path would decide of this user, and a non-admin user is admitted to a public toolset exactly as the data path admits them); it carries the public settings the upstream leg is built from — `client_id`, `authorization_endpoint`, `code_challenge`, `code_challenge_method`, `scopes_supported`; and it carries the per-caller `user_level_auth_status`/`global_auth_status` that decides the short-circuit. The route is addressed by the resource path — the same id Core's own routes carry — and the projection's `redirect_uri` member is present but **not read**: the upstream callback is the gateway's derived one, so the stored field is no longer an input to any leg. The verifier and the client secret are absent by construction: the listing projection has no fields that could carry them. |
| The app (the app flow's read) | `GET /openai/applications/{resource-path}` | The single-app read, made with the live user's identity token: it enforces DIAL authorization on the app (403 when the user has no access) and answers the apps namespace's existence refusal (404 for an unknown app). It parses nothing beyond existence and readability — the per-service statuses the route may enrich are not read, and no upstream leg exists for an app resource, so there is no settings projection to build. Addressed by the resource path, the same id Core's own responses carry. |

The toolset flow makes **one** read and decides everything on its answer: the
deployment-listing route's authorization *is* the flow's DIAL authorization check, the
same answer's `auth_settings` projection is what the consent branch builds its URL
from, and the same answer's per-caller statuses are what the signed-in check reads. A
status that is absent or unreadable is not signed in — the flow fails closed into the
kind branch, and no second read is ever made: the route asked again could only repeat
its answer. The app flow's read is a single read by construction: with no status
members to decide a short-circuit on, there is nothing more for a second read to
answer.

**The read's refusal shapes, and who each one is for.** The two reads answer their
refusals through one shared mapping, and the codes are two classes with different
remedies, never one:

- **403 — access denied.** The caller's own lack of access: the deployment resolution
  refuses them, the same decision the MCP data path would make of the same call. The
  user sees the no-access page — ask your DIAL administrator to grant access, then
  start the sign-in again. No upstream round-trip happens.
- **404 — not registered.** Core does not know the offered name. The user sees the
  not-registered page, and the audit record carries the fixed-vocabulary reason
  (`unknown_toolset` / `unknown_app`).
- **401 — a trust fault, never an access denial.** Core could not validate the
  sign-in's identity token. This is an authentication failure, not an authorization
  verdict: nothing is wrong with the user's access, and no grant of access fixes it.
  The user sees the operator-facing fault page saying the sign-in cannot proceed and
  an administrator must check Core's trust configuration for the identity provider —
  the gateway never shows them the no-access page. The **operator's checklist** for
  this shape: Core's provider entry for the identity provider — its issuer pattern
  (it must match the issuer the gateway's `IDP_ISSUER` names), its key set (the JWKS
  the entry fetches), its audience (the `aud` the identity token carries, e.g.
  `dial-mcp-proxy`), or the reachability of that key set (an entry whose JWKS URL
  Core cannot fetch fails every sign-in the same way). A 401 burst across users is a
  trust-configuration or reachability event, never an access-change event. Core logs
  no record of its 401s — its auth filter refuses before any controller sees the call
  — so the gateway's audit record (the fixed-vocabulary trust-fault reason on the
  `authorization` leg) is the only diagnosable trace the failure has.
- **Anything else (unreachable, unreadable, 5xx) — a deployment fault.** The user
  sees the operator-facing fault page; the flow is re-run after the cause is fixed.

The trust fault, the no-access refusal, and the not-registered refusal all end the
flow: its record is destroyed and the identity material it held is dropped, so a
re-played callback lands on the expired page. Neither the trust-fault page nor its
audit record names any user-identifying value — no token, claim, or caller value
reaches either; the page text is fixed vocabulary chosen by the gateway.


## Tokens, PKCE, and the resource rule

| Setting | Default | What it is |
|---|---|---|
| `GATEWAY_ACCESS_TOKEN_TTL_SECONDS` | `600` | The access token's life, short by design: it bounds how long a leaked token is usable. |
| `GATEWAY_CODE_TTL_SECONDS` | `300` | The authorization code's life, and the replay cache's claim window. |
| `GATEWAY_FLOW_TTL_SECONDS` | `600` | The in-flight flow record's life. |
| `GATEWAY_REFRESH_TTL_SECONDS` | `28800` | The refresh window: the absolute bound on how long a gateway refresh token lives, and therefore on how long the provider session refresh token it carries stays usable. Must not exceed `IDP_SSO_SESSION_MAX_SECONDS`. |
| `IDP_SSO_SESSION_MAX_SECONDS` | *(required)* | The operator's declared bound on how long the identity provider keeps its session-bound refresh token usable — on Keycloak the realm's SSO Session Max; for an external customer-identity provider, the refresh-token window the provider gives a client of this registration shape (the confidential client the gateway registers as). An **assertion about provider session policy**, not a fact the gateway can learn; the failure it cannot catch (a policy shorter than declared) surfaces at runtime as an `idp_session_ended` burst. |
| `GATEWAY_ROTATE_REFRESH_TOKENS` | `true` | Rotation on by default; the rotated token keeps the original absolute expiry, so rotation cannot extend the window. **Turning it off is valid only on a provider that does not rotate its refresh token per grant** — see the warning below. |
| `GATEWAY_ROTATION_GRACE_SECONDS` | `60` | Lets a request that raced a rotation still use the token it holds. |
| `GATEWAY_INFER_RESOURCE_SINGLE_TOOLSET` | `false` | The escape hatch for a deployment that can never serve more than one toolset. Off, because inferring silently addresses a token to a toolset the client never named. |
| `GATEWAY_AUDIENCE_MARKER` | `dial-mcp-proxy` | The marker Core's provider entry verifies. |
| `ROLES_SOURCE_PATH` | *(required)* | The claim path roles are read from in the identity token. Locally `roles`. |
| `ROLES_CLAIM_NAME` | `roles` | The claim name the roles array is re-emitted under — the name Core's provider entry reads. |

PKCE S256 is mandatory on every authorization request a harness client sends this
gateway, and `plain` is **refused rather
than implemented** — it would put the verifier itself on the wire, which is the property
PKCE exists to establish. (This is the client-facing surface's requirement, unchanged by
the identity leg's own no-PKCE mode above.)

The RFC 8707 `resource` parameter is **required** on both the authorization and the token
endpoint, and a missing or mismatched one is `invalid_target`. One flat authorization
server serves every resource — toolset and app alike — so the resource is the only signal
naming which one a request is for; its URI shape names the kind (`/dial/{name}/mcp` a
toolset, `/apps/{name}/mcp` an app), and the two derivations are disjoint by prefix, so no
resource can be reinterpreted across kinds. A default would address the issued token to a
resource the client never named. The single escape is
`GATEWAY_INFER_RESOURCE_SINGLE_TOOLSET`, which is inert unless exactly one toolset is
mapped and never resolves to an app.

**What the `aud` carries, and what Core actually verifies.** The minted access token's
`aud` carries the addressed resource's URI — the toolset's or the app's — plus the marker
(`GATEWAY_AUDIENCE_MARKER`); the refresh token's `aud` carries the addressed resource's URI
alone (the token-type separation, unchanged and load-bearing for both kinds). But the
resource audience is the **gateway's own addressing discipline**, enforced at the gateway's
own resource checks (the token endpoint's resource match, the refresh grant's resource
match): **Core verifies the marker only** — its identity-provider entry applies the single
configured `audience` string to every presented token, and **no per-resource audience match
exists on either of Core's MCP data paths**. The practical consequence is disclosed rather
than hidden: a user's app-resource token is Core-acceptable on a toolset path and vice
versa (the marker is present either way), within that user's own authorization and under
Core's per-call DIAL authorization. The structural fix — Core-side per-issuer
path/audience scoping — is a Core-side ask, not built here.

A client's `scope` parameter is **accepted and dropped**. The identity-provider leg
requests exactly the gateway's own pre-registered client's default scopes; relaying a
client's scopes there would fail the whole leg on any scope that client does not carry,
including scopes that are not client scopes in the realm at all. Rejecting the parameter
instead would break the clients that faithfully echo the upstream scopes they were
advertised, which are exactly the well-behaved ones.

### The claim copy

A minted token carries the identity token's **whole payload verbatim, minus a fixed
blocklist of registry claims the gateway itself owns** — `iss`, `aud`, `exp`, `iat`, `nbf`,
`jti`, `typ`, `azp`, `nonce`, `at_hash`, `c_hash`, `acr`, `auth_time`, `cnf`, `scope`,
`session_state`, `sid`. Each of those describes the *identity provider's* token, and
carrying any of them into a token this gateway signs would state something false about the
new token or collide with a field the new token must set itself. `acr` and `auth_time` are
the authentication-context pair: they state the *provider's* authentication event, and the
gateway — an OAuth 2.x server, not an OIDC provider — never sees the provider's ID token and
holds no authentication-time or assurance fact of its own. A minted token's recency is its
own `iat`/`exp`, which the mint sets itself.

**Authorization rules in Core's configuration MUST NOT key on a blocklisted claim**
(`scope`, `acr`, or any other name on the list above). Gateway tokens never carry them,
while Core's rule matcher may legally key rules on any claim path — so a rule on a
blocklisted name silently never matches for every gateway-issued token, a 403 with
nothing anywhere to say why. A rule that needs one of those names is a deployment
configuration error, and the fix is in the rule, never in the gateway.

Everything else is copied under its own name, so every deployment claim path Core's
authorization rules or telemetry may reference keeps working with **no per-claim
configuration**. An allowlist copy would be authorization policy expressed as configuration
whose failure mode is silent, which is the trade the whole-payload copy refuses.

**Roles are overlaid, not copied.** After the copy, roles are re-emitted as a plain array
under `ROLES_CLAIM_NAME`, read from `ROLES_SOURCE_PATH`. The path may be nested
(`resource_access.dial-cli.roles`). The two failure modes are deliberately different:

| The path… | What happens | Why |
|---|---|---|
| is **absent** from the identity token | Issuance is **refused** with an operator-facing configuration error naming the path | A wrong path yields a token whose roles Core cannot match, and the symptom is a 403 the user cannot act on and the operator cannot diagnose — the silent role-less token |
| resolves to an **empty** value (`[]`, `""`, `null`) | The empty array is copied as-is | The user legitimately has no roles; that is user state, not a deployment error |

A single-valued string claim becomes a one-element array, because Core's `rolePath`
accepts either and this gateway emits the array.

### Refresh, rotation, and revocation

A refresh **re-reads the user's current claims** from the identity provider. The gateway
presents the provider's session-bound refresh token — carried, encrypted, in the gateway's
own refresh token — to the provider's token endpoint (RFC 6749 §6, the refresh grant), and
the minted access token's claims are the verified fresh token's, through the same copy and
overlay rules as issuance. So a claim change at the provider reaches minted tokens within
the access TTL, and an identity-provider session revocation ends the gateway's refresh
capability at the next refresh attempt. The upstream is never contacted on a refresh.

The gateway's refresh token carries **no claim snapshot**: its one non-binding payload member
is the encrypted custody claim (below). That makes a frozen-snapshot fallback structurally
impossible — a claims-read failure refuses the refresh (`invalid_grant`) with no data to fall
back to. The three failure classes audit apart on the trail through the closed refusal table,
so an operator can distinguish a session end (`idp_session_ended`) from a provider outage or
misconfiguration (`claims_read_failed`) from the gateway's own custody fault
(`custody_decrypt_failed`).

Rotation is on by default, and **the rotated token keeps the original absolute expiry**.
A rotation that granted a fresh window would extend the carried window, so it is deliberately
non-sliding and `GATEWAY_REFRESH_TTL_SECONDS` bounds it exactly. A chain of refreshes keeps
the same absolute expiry at every step. Where the provider rotates its own refresh token per
grant, the replacement carries the provider's **latest** token (latest-wins), re-encrypted
under the current custody key.

The grace window (`GATEWAY_ROTATION_GRACE_SECONDS`) exists for a client that raced the
rotation and lost: it gets a working access token and the replacement it already holds,
both bounded by the same original expiry. A token past its grace window is `invalid_grant`,
which is what makes rotation meaningful rather than decorative.

> **Warning: `GATEWAY_ROTATE_REFRESH_TOKENS=false` on a rotating provider ends sessions at
> the second refresh.** Where the provider rotates its refresh token per grant, turning
> gateway rotation off makes the carried credential effectively single-use: the first refresh
> consumes the provider's token, the un-rotated gateway token keeps presenting the same stale
> blob, and every refresh after the first fails at the provider (`idp_session_ended`). The
> setting is valid only on a provider that does **not** rotate per grant, where the same blob
> stays usable for the whole window. The gateway cannot know the provider's rotation policy at
> startup, so this is warned about, not refused.

A refresh request that presents `client_id` must present the one the token was minted for
(RFC 6749 §6); a mismatch is `invalid_grant`. The parameter is optional — a client that
sends none is served, and the fresh tokens carry the token's own `client_id` — but nothing
else at this grant binds the request to that client, so the check is what makes the
binding real when the parameter is sent.

**A replayed authorization code revokes the refresh token it first bought** (RFC 9700
§4.2.4). A code is single-use and a second redemption is refused as ever; the refusal now
also denylists the refresh token the first redemption minted, so a stolen code's token
family dies at that token's next presentation. The connection rides the existing replay
memo — the code grant records the minted refresh token's id against the code's own id — and
the revocation is one call into the same denylist `/dial/revoke` uses, so nothing new is
stored. Two bounds are disclosed rather than implied: the **access token** the first
redemption minted stays live until its own short TTL (bearer and unrevocable by design, the
bound the recommendation tolerates), and a **refresh token already rotated** before the
replay was detected survives (rotation mints a fresh id, and no code-to-successor mapping
exists — that window is bounded by the replay detection's timing and the non-sliding
absolute expiry).

`POST /dial/revoke` (RFC 7009) denylists a refresh token's id until the moment the token
itself would expire, so the denylist is self-bounding: it can hold at most one entry per
live refresh token. Its answer follows the RFC in both directions: a request that names no
`token` is `invalid_request` (§2.1 makes the parameter required, and such a request is
malformed rather than probing anything), while a request that names one — whether or not
this gateway issued it, whether or not it is live, and whether it is an access token rather
than a refresh token — is answered with the same **empty 200** (§2.2). The uniformity is
the whole point: a body, or any difference in one, would make this endpoint an oracle for
whether a token a caller holds is real, which is the question an attacker holding a stolen
token is asking. Access tokens are not revocable: they are bearer strings this service does
not track, and they die within their own short lifetime. The endpoint is advertised as
`revocation_endpoint` in the AS metadata.

### Custody: the identity provider's session refresh token

The provider's session-bound refresh token is carried for the refresh window as an
**encrypted claim inside the gateway's own refresh token** — never the access token, never
the authorization code, never any other client-visible artifact, in plaintext or as
ciphertext. `offline_access` is never requested: what is carried is the ordinary refresh
token the code exchange issues, a rotating handle to the user's live session, not a
beyond-session grant. There is no long-lived per-session store; between flow end and the code
grant the token transits a server-side pending entry keyed by the authorization code's id,
bounded by that code's short TTL.

The envelope is **AES-256-GCM** (`version | key-id | nonce | ciphertext‖tag`, base64url), with
the algorithm and the key and nonce lengths pinned in code constants — never read from the
envelope. The envelope embeds its own `sub` and `exp`, both checked at the seam before any
use: a blob moved between two users' tokens refuses, and an expired envelope refuses.

| Setting | Default | What it is |
|---|---|---|
| `GATEWAY_CUSTODY_KEYS` | *(required)* | The custody keyset: the dedicated key(s) that seal the provider refresh token. Two spellings, one per document — the flat spelling (`key-id → base64 key`, exactly one active entry, no retention) or the structured entry schema with roles. Each key is 32 bytes in base64. See [Secrets](#secrets). |
| `GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES` | `4096` | The largest provider refresh token the gateway will carry; an over-bound token fails the flow **at sign-in** with an operator-facing error naming the bound. Coupled with `GATEWAY_FORM_MAX_BODY_BYTES`. |

**Generating the key.**

```bash
openssl rand -base64 32
# then, quoting the JSON so compose passes it whole:
GATEWAY_CUSTODY_KEYS='{"k-2026-11":"<paste the base64>"}'
```

The key is separate from `GATEWAY_SIGNING_KEY` (this one decrypts, it never signs) and is
treated as secret material: never committed, never logged.

**Enable the identity provider's rotation reuse detection (recommended).** At each refresh
the gateway presents the provider's session refresh token once on the internal leg, so a
peer able to read that leg would hold a mintable credential. Where the internal legs are
plain HTTP — the local development shape — the provider's rotation reuse detection is the
control that contains a lifted string: the gateway's own next refresh races the thief, and
the first replay revokes the whole chain (the user re-signs in, and the event is loud as
`idp_session_ended`). On Keycloak this is the realm's `revokeRefreshToken` (off in the
image default); the provisioning script sets it on the realm it owns. It is **recommended,
not required**: deployments that run TLS'd internal legs to the identity provider — the
production shape — are bounded by the transport, and the detection is then
defense-in-depth.

**Rotation is an overlap, and the hard cut is the operator's explicit act.** A superseded
custody key may be `retained` for the drain window beside the active one: sealing is always
under the **active** key, decryption accepts the active **or** a retained key with the
envelope's key-id selecting the entry, and each presenting session re-seals its replacement
under the active key — so a routine rotation that logs out no one is what the overlap
delivers. Its bound is the refresh token's non-sliding absolute expiry (the same window the
old hard cut's re-sign-in wave had, read from the other side). The **hard cut survives as
the explicit act**: remove the retained entry at any moment and every outstanding refresh
token carrying a claim sealed under it refuses fail-closed at its next presentation, in this
requirement's custody refusal class. Use the cut when a key compromise is suspected — the
one moment the old key must stop working — and the overlap for routine hygiene. See
[Key rotation](#key-rotation) for both procedures.

The overlap requires the **structured** custody spelling (the flat shape cannot carry
retention); the flat spelling is one active entry with no retention, so an existing
deployment's `.env` needs no change to gain the seam.

**The size bound and the body cap are coupled and must move together.** A refresh request
carries the grown refresh token — which carries the envelope — in its form body, so the body
cap must stay at or above the bound plus the envelope's expansion and the JWT overhead.
Raising `GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES` past `GATEWAY_FORM_MAX_BODY_BYTES`'s
headroom makes sign-ins succeed while every refresh fails over-cap, hours later and far from
its cause; the startup check refuses that combination, naming both settings.

### The flow's audit trail

One JSON line per event on the `gateway.audit` logger: `flow_allocated`, `flow_refused`,
`upstream_callback`, `signin_result`, `code_issued`, `token_issued`, `token_refreshed`,
`token_revoked`, `client_registered`, `flow_branch_refused`, and `flow_leg_failed`. Every
record from a flow's own events carries the flow id, the client id, the resource, and — once
the flow knows the user — the subject. `flow_refused` is the one record outside that shape:
it answers a request refused before any flow exists, so it carries no flow id.
`signin_result` carries one of three fixed outcomes (`accepted`, `access_refused`,
`failed`), chosen by the gateway rather than taken from Core's response text.
`flow_branch_refused` records the flow's routing-branch refusals — the impossible-branch
refusal (`non_oauth_toolset`) and the unknown-name refusal at the listing read
(`unknown_toolset`) — with the same identifiers as the flow's other events.

`flow_refused` covers every refusal that occurs **before** a flow is allocated — the
`/dial/authorize` validation refusals (unknown client, unregistered redirect URI, missing
or unknown `resource`, the name guard's charset/reserved/restriction refusals, a PKCE or
inference refusal), the token-endpoint validation failures, the registration-resolution and
`/dial/register` refusals, the `/dial/revoke` form and missing-token refusals, and the
discovery guard refusals (either namespace's route) — so the trail
answers the operator's most common question ("my harness cannot connect / gets rejected")
from the log instead of a reproduction. Its record carries the refusal's fixed-vocabulary
reason and the non-credential facts the request offered: the client id, the redirect URI,
the resource, and the resource **name** the request named. The name fact is kind-neutral
rather than `toolset`, because a refusal under either namespace records the name the
request offered; where the site serves exactly one kind the record also carries
`resource_kind` (`toolset` or `app`), so the namespace is named explicitly rather than
implied by a field name. Those fields are present and null when a refusal recorded none,
so the record's shape is one shape.

The flow's own events carry the resource the flow serves — a toolset or an app — through a
single `resource` fact (the audit vocabulary the change to two resource kinds renames from
`toolset`), and the app flow adds two fixed-vocabulary reasons of its own: `unknown_app`
(the app read's existence refusal) and `credential_free_short_circuit` (the kind-driven
short-circuit, naming the resource kind).

**A limiter's 429 is recorded facts-free** — the reason and nothing else. The limiter bounds
how much work a caller may make, not how much log; a refusal that arrives at the rate being
bounded must not carry fields whose size the caller chooses, or the bound would cover the
work and not the trail.

**The facts are length-bounded** to `AUDIT_FACT_MAX_LENGTH` (default 256 characters), applied
where the record is emitted rather than at each call site. The facts are the request's own
values and their length is the caller's choice, so without the bound an unauthenticated
request naming a megabyte-long client id would land in the log in full and the trail would
be an amplification path the caller sizes. An over-long fact is **truncated**, not dropped:
its prefix is what identifies the client or URI the refusal was about. The bound names the
fact fields specifically — the reason, the event name, and every other field in a record come
from this gateway's own vocabulary and are never cut, so the log's vocabulary stays groupable
and alertable whatever cap is configured.

**No record ever carries a token, a code, a key, a verifier, or a password.** The trail
answers *who did what*; every value that would answer *with what* is exactly the material
this gateway must not retain. No free-form caller input reaches a record either — the
reason comes from the gateway's own fixed vocabulary, so a caller cannot write content
into the log. The sink is standard output, which is where a container's log
collector already reads.

## Secrets

The signing key and the custody key are each a **keyset**: one or more entries, each
carrying a **source** (`env` — the material in an injected environment variable — or
`file` — a PEM or key on a read-only mount; both implemented) and a **role** (exactly one
entry `active`, any number `retained`). The keyset setting to configure depends on what the
deployment needs:

| Setting | What it is |
|---|---|
| `GATEWAY_SIGNING_KEY` | The token signing key: an unencrypted RSA private key in PEM form, at least 2048 bits. **IdP-grade**: whoever holds it can mint any identity Core will trust. This is the **no-rotation shape** — one active `env`-sourced entry, no retained entries — so a deployment that never rotates needs no keyset JSON. Generate it, set it in `.env`, never commit it, never log it. |
| `GATEWAY_SIGNING_KEYS` | The **structured** signing keyset, as a JSON object keyed by entry-id: `{"<id>":{"source":"env"\|"file","ref":"<env var name \| file path>","role":"active"\|"retained"}}`. The multiply-entry shape a rotation uses. Structure only — each entry's material sits in its own variable or file, named by its `ref`, so the document itself carries no secret. Mutually exclusive with the singular `GATEWAY_SIGNING_KEY`: configuring both refuses startup naming both. |
| `GATEWAY_CUSTODY_KEYS` | The dedicated AES-256 key that seals the identity provider's session refresh token into every gateway refresh token. **Required**, and separate from the signing key (this one decrypts, it never signs). Two spellings, one per document (see below). Each key is 32 bytes in base64. |
| `IDP_CLIENT_ID` | The gateway's identity-provider client, registered **confidential** at the provider — the client whose secret `IDP_CLIENT_SECRET` carries. |
| `IDP_CLIENT_SECRET` | The identity-provider client's secret, delivered as an environment variable. Load-bearing always: the gateway's client is a confidential client, and the secret authenticates the code exchange and the refresh grant on every identity-leg token request, in both positions of `IDP_PKCE_ENABLED`; startup refuses to run without it (in one of its two spellings). The value is never logged, never echoed in an error, and never delivered to any client. |
| `IDP_CLIENT_SECRET_FILE` | The same secret delivered as a **read-only mounted file**: the path that carries it. Optional beside `IDP_CLIENT_SECRET`; see [the secret's two spellings](#the-idp-client-secrets-two-spellings). |

The `ref` indirection is what keeps a keyset document non-secret: a rotation adds one
environment variable or one mounted file per new entry, rather than re-quoting a growing
JSON blob of key material. The document is ids, sources, refs, and roles only.

**Both keysets share one entry schema and one validation discipline.** At startup each
keyset refuses: an empty keyset; a keyset with no active entry; more than one active entry;
an entry that is not a loadable, well-formed key of the right shape (RSA ≥ 2048 bits for
signing, exactly 32 bytes for custody); two entries whose material derives the same `kid`
(the `kid` is a truncated hash over the public material, so a shared `kid` is either the
same key configured twice or a collision — the refusal stands either way, because one `kid`
must name exactly one entry); an unreadable or unparseable `file` source, naming the path;
and an entry carrying the reserved source `kms`, naming the gap (the KMS sign-interface is
not built — a configuration that named it would otherwise believe it held KMS protection it
does not have). No key material, fingerprint, or file content reaches any error or log
line: entries are named by their configured ids and their locators only.

**The custody key's two spellings.** `GATEWAY_CUSTODY_KEYS` accepts one spelling per
document:

- **Flat** — `{"<key-id>": "<base64 key>"}` for exactly one key: one active `env`-sourced
  entry, no retention. The pre-keyset shape, kept so no existing deployment's `.env`
  changes to gain the keyset seam.
- **Structured** — the same entry schema as `GATEWAY_SIGNING_KEYS`: one active entry plus
  any number of retained entries. Retention requires this spelling — an operator who wants
  an overlap rotation says so in the schema.

A document mixing the two is refused at startup, naming the keyset: the flat shape cannot
carry retention, and one spelling per document is what keeps the compat shape from
silently coexisting with it.

An environment variable cannot always carry real newlines, so the signing key accepts the
escaped form (`\n`), which is what a secret store or a compose interpolation produces.

### Key rotation

The `kid` is a hash of the public key, so two keys cannot present the same one. Rotation
is **staged on the signing side**, because a freshly minted token must never carry a `kid`
Core's key cache does not yet hold — a key that starts signing the moment it becomes active
mints tokens Core refuses until its cache turns, a refusal window a routine rotation must
not create. The rule that closes it: **a key about to become active must have its `kid`
published — present in the keyset, hence in the JWKS — for at least the deployment's Core
JWKS-cache window before it signs.** A `retained` entry is exactly "published, not
signing," which is what pre-publication needs.

**The compose environment list.** A structured entry's `ref` names where its material
comes from: an environment variable (`source: env`) or a file path (`source: file`). The
shipped `docker-compose.yml` forwards a fixed allowlist of environment variables, so an
`env` entry whose `ref` names a variable the list does not carry requires that variable to
be added to the compose environment list before the rotation edit below takes effect —
for the signing keyset and the custody keyset alike. A `file` entry's `ref` names a
mounted path instead, and asks only for the corresponding read-only mount.

**Routine overlap rotation (signing key):**

1. **Add** the new key as a `retained` entry — published in the JWKS, not signing.
2. **Wait** the declared Core JWKS-cache window. The default is 10 minutes on the local
   instance (see [the declared cache bound](#the-declared-core-jwks-cache-bound)); the wait
   is the deployment's Core JWKS-cache TTL.
3. **Promote** the new key to `active` and demote the old key to `retained`. Two restarts,
   zero refusal windows.
4. **Drain**: old-key tokens keep verifying through the window, bounded by the refresh
   token's non-sliding absolute expiry (the longest-lived token the gateway mints).
5. **Remove** the old `retained` entry once the drain completes. Removal is the closing
   step of the routine rotation — a retained entry left in place keeps a superseded key
   hot.

**Emergency cut (signing or custody key):** remove a `retained` entry at **any** moment of
the window. On the signing side, tokens signed under it are refused at their next
gateway-side presentation, and Core stops accepting them within its JWKS-cache window plus
the access TTL. On the custody side, outstanding refresh tokens carrying claims sealed
under it refuse at their next presentation in the custody refusal class. This is the
operator's explicit lever, not the routine outcome.

**Routine rotation is no longer a mass signout.** On both keys, a superseded key may be
retained for the drain window beside the active one, so outstanding tokens keep working
through a routine rotation. On the custody side specifically, each presenting session
decrypts its claim under the retained key-id and re-seals the replacement under the
**active** key — the overlap is self-shortening, and an operator who never presents a
session again leaves only inert ciphertext that dies with its token.

> **The retained-key windows are the priced cost of routine rotation.** A superseded
> signing key kept `retained` keeps its `kid` published, so a stolen superseded key stays
> able to mint Core-acceptable tokens for up to the whole drain window; a stolen superseded
> custody key stays able to decrypt for the same window. Both are reconciled by the
> **immediate cut** above: remove the retained entry and the window closes at once. Keep the
> window as short as the drain needs.

#### The declared Core JWKS-cache bound

The pre-publish wait is bounded by how long Core caches the gateway's JWKS. The local
instance's observed value is **10 minutes**, and that is the number the staged procedure
states as the deployment's default. Core's configurability of that cache is **an open
verification**: a deployment whose Core caches longer than declared keeps the residual —
a token minted under a `kid` the cache does not hold is refused at Core until the cache
turns. Until the bound is verified against the deployment's own Core configuration, state
it as the deployment declares it and observe the rotation's waits; the drill's recorded
waits bound it in practice.

### The IdP client secret's two spellings

The identity-provider client's secret is delivered by exactly **one** of two spellings,
both supported, no preference between them:

| Spelling | Setting | Shape |
|---|---|---|
| Environment variable | `IDP_CLIENT_SECRET` | The secret injected as an environment variable. |
| Read-only mounted file | `IDP_CLIENT_SECRET_FILE` | The **path** of a read-only-mounted file carrying the secret — the shape a mounted Secret file takes. |

Configuring **both** refuses startup with an error naming both settings — a secret with two
possible values has no single value. Configuring **neither** is the missing-secret refusal
(the gateway's client is confidential and cannot run without one). The file spelling is
read once at startup; an unreadable or blank file refuses startup loudly, naming the path
and never the content.

The two spellings are **equivalent to the gateway**: whichever delivers it, the secret's
presentation, its never-logged discipline, and its token-leg-only audience are the same.
The deployment chooses the delivery its cluster manages — an environment variable, or a
mounted Secret file — and the boundary each spelling rests on is the deployment's to own.

## Provisioning the identity-provider client

`scripts/provision_keycloak.py` creates the client `IDP_CLIENT_ID` names, through the
realm's Admin API, taking its administrative credential from `KEYCLOAK_ADMIN_USER` and
`KEYCLOAK_ADMIN_PASSWORD` in `.env` (never hardcoded). It is **idempotent**: a re-run
either reports that the client already matches or converges the fields that drifted.

What it creates, and why each part follows from the flow:

| Property | Value | Why |
|---|---|---|
| Type | Confidential client, standard flow only | The gateway's client is a confidential client: its secret authenticates every identity-leg token request, so the realm's client must expect one (`publicClient: false`). No password or client-credentials grant is enabled. |
| PKCE | `S256` required | An intercepted callback code is not redeemable without the verifier, which stays on the gateway's flow record. |
| Redirect URI | `http://localhost:8090/dial/callback/idp` | The path the front router routes and the flow builds; the three must agree, so it is derived from the public origin rather than chosen per deployment. |
| Default scopes | `profile`, `email`, `basic` | `profile`/`email` are the scopes the redirect requests. `basic` carries the `sub` mapper — the subject Core authorizes with — and is attached as a default scope without being requested. Scopes the realm attaches on its own (notably `offline_access`) are **removed**, so the client's carried set is the designed one. |
| `project` mapper | user attribute → `project` | Core's provider entry reads the project attribution from this claim. |
| Roles mapper | client roles of the DIAL chat client → `roles` | Core's `rolePath` reads roles from this claim, and the DIAL `admin` role is granted as a client role of that client in this realm. |

Nothing here prints a credential: the admin token is shown as a redacted handle, and the
client secret is never printed — the helper converges the client's secret to the local
profile's `IDP_CLIENT_SECRET`, generating a value and writing it to the local `.env`
where the profile carries none. `--verify-claims` additionally completes a real
authorization-code flow against the client — driving the realm's own login form — and
reports the claims it minted, which is the check that the mappers are wired to the right
source rather than merely present.

## Origin of the local values

`docs/local-environment.md` describes the local DIAL instance these defaults are written
against. The defaults in `.env.example` are the local ones — the realm's 24 h access-token
lifespan, the `notion` toolset, the loopback callback — so a differently configured
deployment changes `.env`, not code.
