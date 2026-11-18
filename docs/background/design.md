# Harness integration with DIAL MCP toolsets — design

Status: **design for review — converged after adversarial review; implementation is
gated on PoC C (§9, item 2)**. Companion to
[`problem-statement.md`](problem-statement.md) (requirements §3, invariants §2.4,
findings §4), <!-- The May 2026 toolset authentication design is not copied here: it is
     stale and private. Anything it described that still matters is either
     implemented in DIAL Core (cite the source) or stated in this repo. -->
(the DIAL Core implementation, May 2026), [`poc-dial-mcp-signin.md`](poc-dial-mcp-signin.md)
(PoC A), [`poc-litellm-comparison.md`](poc-litellm-comparison.md) (PoC B) and
[`design-review.md`](design-review.md) (the review this revision converges with).

**Evidence marking.** Every non-obvious claim is tagged:

- **[PoC A]** / **[PoC B]** — empirically observed in the respective PoC. PoC B's
  client-side observations are from scripted probes, not a harness (see m-1 in the
  review); tagged precisely below.
- **[Capture]** — observed in the 2026-10-17 Claude Code protocol capture (decoy AS
  pointed at from Core's `toolsets.security.authorizationServers`): Claude Code sends
  the RFC 8707 `resource` parameter on both `/authorize` and `/token` with the
  per-toolset value Core publishes; it registers via a Client ID Metadata Document
  (`client_id = https://claude.ai/oauth/claude-code-client-metadata`, no `/register`
  call) when the AS advertises `client_id_metadata_document_supported: true`; and it
  fetches the **flat** `/.well-known/oauth-authorization-server` for the issuer —
  never a per-toolset path.
- **[Core source]** — read in `dial-core/ai-dial-core` @ `development`, 2026-10-17
  (verified independently by the review).
- **[Spec]** — required by the MCP authorization spec rev 2026-07-28 or the cited RFC;
  not independently exercised.
- **[Assumed]** — not verified; an explicit assumption this design depends on.

---

## 1. Design overview

### 1.1 The chosen architecture

A small **MCP sign-in gateway** ("the proxy") is deployed next to DIAL Core, behind the
existing front router (nginx). It is an OAuth2 **authorization server** for the
harness-facing leg, and a **federation orchestrator** for the two DIAL legs. It is
*not* on the MCP data path: the router forwards toolset MCP traffic directly to Core,
exactly as the human's correction 2 requires.

The token chain is the one the human sketched — *proxy → dial → upstream, never two
tokens in one call* — realized as:

```
   harness                       front router (nginx)                 DIAL Core                 upstream MCP
                                      │                                (credential holder)        (e.g. Notion)
     Leg 2': OAuth2 vs. the proxy     │                                │                          │
   ┌──────────────────────────────────┼────────────────────────────────┼──────────────────────────┼─────────┐
   │ 1. MCP call, no token ──────────►│ 401 → proxy's challenge        │                          │         │
   │ 2. discovery: PRM + flat AS meta►│ ◄─ served by the proxy         │                          │         │
   │ 3. GET /dial/authorize ─────────►│ ──► proxy: federate            │                          │         │
   │        (resource=<per-toolset>)  │                                │                          │         │
   │        browser: Keycloak login (proxy's client, PKCE) ──────────────────────► Keycloak        │         │
   │        browser: upstream consent (Core's client, Core's PKCE challenge) ───────────────────────────────►│
   │ 4. proxy calls POST /v1/ops/toolset/signin (Keycloak JWT + upstream code) ───► stores per sub │         │
   │ 5. code → proxy /token → PROXY-SIGNED JWT (sub copied from Keycloak)         │                          │         │
   └──────────────────────────────────┼────────────────────────────────┼──────────────────────────┼─────────┘
                                      │                                │                          │
   data path (every MCP call):        │  Authorization: Bearer <proxy JWT>                       │         │
   harness ──────────────────────────►│ ──── straight to Core ──────► validate (proxy = extra IdP)          │
                                      │                                │  resolve per-sub cred ───► Notion token
```

The decisive move is **alternative C** from the problem brief: the proxy's signing key
is registered in Core as an **additional identity provider** — a static-settings
change only, no Core code. This is possible because Core already supports multiple
JWT identity providers selected by `issuerPattern` and verified against a per-provider
JWKS **[Core source: `AccessTokenValidator`, `IdentityProvider`; independently
confirmed by the review]**. Because the proxy copies the user's real Keycloak `sub`
(and roles) into the tokens it mints, every per-user mechanism in Core — credential
stamping, per-user resolution, authorization — works unchanged. And because the
proxy's tokens are validated by Core itself, the router can send MCP traffic straight
to Core with no per-request proxy hop.

**The discovery shape is fixed by observed harness behavior, not by choice.** The
capture shows Claude Code resolves the authorization server to the **flat**
`/.well-known/oauth-authorization-server` document and never a per-toolset insert-path,
and registers via CIMD rather than DCR **[Capture]**. The proxy is therefore **one
flat AS for all toolsets** (issuer = the public origin), and the RFC 8707 `resource`
parameter — which the capture proves is sent on both `/authorize` and `/token` with
the per-toolset value — is the **primary disambiguator** (§3, §4.1). An earlier draft
of this design used per-toolset AS issuers and paths; that variant is withdrawn on
this evidence (it is also unreachable via Core's own metadata, which publishes one
global `authorization_servers` list **[Core source: `WellKnownResourceMetadataService`]**).

Why an external component at all: Core relays the *upstream's* 401 when no credential
is stored (finding F-1) and Leg 1 is a private API (F-5). Without a Core code change,
something in front of Core must own the client-facing authorization surface. That
something is the proxy. This is the DIAL Core implementation's own "worst case" item — *"implement
custom AS for DIAL MCP toolsets, redirecting to the real IdPs"* — externalized so that
Core stays untouched.

Relation to the prior author's options (problem statement §5.3): this is **O-3
externalized** (O-3's client-facing surface, but hosted in a satellite component
instead of Core, because Core code changes are off the table). O-2 (capability
descriptor in Core) is not needed for proxy-fronted clients — the proxy owns the
metadata they see — but remains useful for direct-to-Core clients and is not blocked by
this design. O-1 (helper skill) remains a useful stopgap and its `signin.py` semantics
are exactly what the proxy automates server-side.

### 1.2 What the proxy is NOT

- It is not a reverse proxy for MCP traffic — it never sees MCP payloads.
- It is not a credential store — it holds no upstream tokens, no Keycloak refresh
  tokens beyond an in-flight sign-in (see §5), and has no database.
- It is not a change to the credential model — invariants I1–I5 all hold (§6.4, §7).

---

## 2. Components

| Component | Owns | Notes |
|---|---|---|
| **Front router (nginx)** | Path splitting; mapping client-facing paths to Core paths; 401 interception on the toolset MCP path; TLS; SSE pass-through | Almost pure configuration — the human's correction 2. One deliberate exception: the 401 rewrite *synthesizes* a `WWW-Authenticate` header (4 lines of stock config, no logic — §4.4). That stretches "split traffic ONLY", and there is no config-only alternative that fixes F-1; it is flagged for the owner's sign-off together with OR-2 (OQ-8). |
| **MCP sign-in gateway** (new, small stateful service) | The OAuth2 AS surface for harnesses (`/dial/authorize`, `/dial/token`, discovery documents, optional `/dial/register`); the federation flow (Keycloak leg + upstream leg); calling `POST /v1/ops/toolset/signin`; minting and signing its own JWTs; JWKS endpoint; flow-state store; audit log | One signing keypair (RSA, `kid`-rotatable). State: in-flight flow records (10 min TTL), code replay cache, refresh denylist. No database required for v1 (§5.3). |
| **DIAL Core** (unchanged code) | Everything it does today: JWT validation (now including the proxy's issuer), authorization, per-user upstream credential storage and refresh, MCP proxying | Static-settings changes only (§10.1). |
| **Keycloak** (or the deployment's IdP) | User authentication; issues the user's real DIAL JWT during federation | Gets one pre-registered public PKCE client for the proxy. No DCR, no policy changes (neutralizes F-4 for this flow). |

### 2.1 What each component never sees

- The harness never sees: the Keycloak token, the upstream token, the PKCE verifiers.
- The proxy never sees: the upstream access/refresh tokens, the upstream PKCE
  verifier (only the public `code_challenge` from the toolset's public settings
  **[Core source: `ResourceAuthSettings.redactSecrets()` nulls `codeVerifier` on every
  public projection; the pair is generated and persisted server-side in
  `ResourceAuthSettingsService`, regenerated only on challenge-method change or
  re-registration]**).
- Core never sees: the harness's OAuth client secrets (there are none — public PKCE
  clients), the proxy's private key.

---

## 3. Endpoints

Client-facing origin is one public host, `https://dial.example.org` below. Toolset
`{name}` maps to a Core deployment via a proxy config table (v1: identical names, so
`/dial/notion` → Core toolset `notion`).

**Mapping invariant (v1): the table is OAUTH-only.** The proxy must refuse at startup
to map a toolset whose public `auth_settings.authentication_type` is not `OAUTH`
(or, with `route_only: true`, serve its paths without the challenge rewrite). Without
this, an operator who maps an `API_KEY` toolset creates a silent, unsatisfiable loop:
the harness gets the OAuth challenge, completes it, and every MCP call still 401s —
rewritten, forever. That is exactly the "looks configured, is broken" class PoC A
§8.2(4) criticizes in Core. Non-OAUTH kinds remain OQ-7.

**Disambiguation.** One flat AS serves all toolsets; the **`resource` parameter
(RFC 8707) is the primary and required toolset signal at E3/E4** — the capture proves
Claude Code sends it, on both endpoints, with the per-toolset value **[Capture]**, and
the MCP spec requires it of conformant clients **[Spec]**. A missing or unknown
`resource` is an OAuth `invalid_target` error (RFC 8707). The single escape hatch is
config: `infer_resource_single_toolset: true` lets a one-toolset deployment serve
clients that do not send it. The per-toolset PRM path (E1) corroborates — the proxy
cross-checks `resource` against it — but no longer carries the disambiguation alone.

### 3.1 Served by the proxy (routed to it by nginx)

| # | Method & path | Purpose |
|---|---|---|
| E1 | `GET /.well-known/oauth-protected-resource/dial/{name}/mcp` | RFC 9728 PRM, per toolset. Returns `{resource: "https://dial.example.org/dial/{name}/mcp", authorization_servers: ["https://dial.example.org"], scopes_supported: [...], dial_authentication_type: "OAUTH"}`. The last field is a DIAL extension on the proxy's *own* document (FR-3; harnesses ignore unknown members). |
| E2 | `GET /.well-known/oauth-authorization-server` | RFC 8414 AS metadata, **flat, host-root** — the URL the capture shows Claude Code fetching for a path-less issuer **[Capture]**; PoC B observed LiteLLM serving the same gateway-level flat shape (via scripted probes) **[PoC B]**. One document, one issuer, all toolsets. `{issuer: "https://dial.example.org", authorization_endpoint: "https://dial.example.org/dial/authorize", token_endpoint: "https://dial.example.org/dial/token", grant_types_supported: ["authorization_code","refresh_token"], code_challenge_methods_supported: ["S256"], token_endpoint_auth_methods_supported: ["none"], client_id_metadata_document_supported: true, scopes_supported}`. The CIMD flag is what steers Claude Code away from DCR **[Capture]**. |
| E3 | `GET /dial/authorize` | Federation entry (§4.1). Shared across toolsets; `resource` (required) selects the toolset. Redirects the browser: Keycloak → (interstitial) → upstream AS → E7 → harness `redirect_uri`. |
| E4 | `POST /dial/token` | `authorization_code` (PKCE + `resource` required — primary disambiguator) and `refresh_token` grants. On refresh, `resource` must match the one the refresh token was minted for. |
| E5 | `POST /dial/register` | Legacy DCR (RFC 7591). **Config-gated, default OFF.** The capture shows the flagship harness does not need it (CIMD when advertised) **[Capture]**, the spec deprecates it **[Spec]**, and PoC A observed harness DCR only when no CIMD was offered **[PoC A]**. The flag stays for field stragglers; enabling it changes nothing else. |
| E6 | `GET /dial/callback/keycloak` | Keycloak redirect target for the proxy's own client (`redirect_uri=https://dial.example.org/dial/callback/keycloak`). |
| E7 | `GET /dial/callback/upstream` | Upstream redirect target for Core's upstream client. Must be in Core's `allowedRedirectUris` **[Core source: `AiDial.getAllowedRedirectUris` reads `aidial.toolsets.security.allowedRedirectUris`; PoC A exercised the allowlist mechanism with a loopback URI]**. Completes the flow: calls `/v1/ops/toolset/signin`, then redirects to the harness with the proxy's code. |
| E8 | `GET /dial/jwks.json` | The proxy's JWKS. Consumed by Core (configured as the IdP's `jwksUrl` — internal or public URL). |
| E9 | `GET /dial/{name}/status` | With `Authorization: Bearer <proxy JWT>`: returns the toolset's public `auth_settings` statuses (`user_level_auth_status`, `global_auth_status`) fetched from Core as that user (FR-4, without a tool call). |
| E10 | `POST /dial/revoke` | RFC 7009 revocation of the proxy's refresh tokens (denylist by `jti` until `exp`). SHOULD, not required by any harness today. |

### 3.2 Routed by nginx, not touched by the proxy

| Path | Routed to | Notes |
|---|---|---|
| `POST/GET /dial/{name}/mcp` | Core `/v1/toolset/{name}/mcp` | The data path. `proxy_buffering off` for SSE; query strings must survive (`$is_args$args`, §4.4 — MCP streamable-HTTP GETs carry `?sessionId=…`); `proxy_intercept_errors on` + `error_page 401` → proxy's challenge (§4.4). |
| everything else | Core as today | Chat, ops APIs, other deployments unaffected. |

Core's *own* discovery surface (`/.well-known/oauth-protected-resource/v1/toolset/...`
advertising Keycloak **[PoC A; Core source: `WellKnownResourceMetadataService` — one
global `authorizationServers` list, disabled when unset]**) keeps working for
direct-to-Core clients. The two surfaces coexist; proxy-fronted clients only ever see
E1/E2 because the 401 they receive is rewritten (§4.4). Coexistence is a PoC C
criterion (e) — it must be *shown*, not assumed.

---

## 4. Flows

### 4.1 First use (toolset `notion`, harness = any MCP+OAuth2 client)

Registration step (client registration priority per CR-2 **[Spec]**):

- **R.** The harness registers a client with the *proxy*: (1) a pre-registered
  `client_id` listed in proxy config (operator pre-registers known harnesses); else
  (2) **CIMD** — the harness sends `client_id` as a URL (Claude Code sends
  `https://claude.ai/oauth/claude-code-client-metadata`, no `/register` call, when E2
  advertises `client_id_metadata_document_supported: true` **[Capture]**); the proxy
  fetches the client's metadata document from an allowlisted origin, caches it, and
  validates `redirect_uri` against its `redirect_uris`; else (3) DCR at E5 — only if
  the operator enabled it (default off, §3.1 E5). All clients are treated as **public
  PKCE clients** — the proxy stores no client secrets. The proxy has no realm
  policies to fight, which removes the F-4 failure class entirely for harnesses (they
  never register against Keycloak).

Authorization (Leg 2′ — harness ↔ proxy):

1. Harness calls `/dial/notion/mcp` with no token → Core 401 → nginx rewrites to the
   proxy's challenge (§4.4) → harness follows `resource_metadata` → E1 → E2 (flat,
   **[Capture]**).
2. Harness opens `GET /dial/authorize?response_type=code&client_id=…&redirect_uri=<loopback>&state=…&code_challenge=…&code_challenge_method=S256&resource=https://dial.example.org/dial/notion/mcp`.
   The proxy validates `client_id` (per step R), `redirect_uri` against the
   registration, and `resource` — **required**: it must resolve to a mapped toolset's
   resource identifier, else `invalid_target` (RFC 8707). It creates a **flow record**
   (id = **128-bit CSPRNG value** — same entropy class as an authorization code; see
   §5.3 for why this is load-bearing; TTL 10 min) holding the harness's parameters
   and the resolved toolset. It redirects (302) the browser to Keycloak's `/authorize`
   with the **proxy's pre-registered public PKCE client**, `redirect_uri=E6`,
   `state=<flow id>`.
3. Keycloak authenticates the user — an SSO session makes this silent; first time (or
   after SSO expiry) it is one login. Keycloak returns the browser to E6 with a code;
   the proxy exchanges it (PKCE) for the user's **real DIAL JWT** (`sub`, roles).
   **[PoC A: identity is client-independent — tokens from different Keycloak clients
   share the user's `sub`; this is what makes the copied-`sub` scheme sound.]**
4. The proxy fetches the toolset's public settings from Core **as that user** — the
   configured toolset URL, `GET /v1/toolsets/{bucket}/{name}`
   (**[Core source: `RouteTemplate` RESOURCE route; PoC A used
   `PUT /v1/toolsets/platform/notion` for the same resource]**) → `auth_settings`:
   `client_id`, `authorization_endpoint`, `scopes_supported`, `code_challenge`,
   `code_challenge_method`, `user_level_auth_status` **[Core source: `ToolSetData`
   includes the public `ResourceAuthSettingsData`; PoC A read exactly these fields]**.
   A 403 here fails the flow with a clear "no access to this toolset" page — DIAL
   authorization is enforced *before* any upstream round-trip (I4).
   If `user_level_auth_status = SIGNED_IN`, the flow skips to step 7 (repeat use).
5. The proxy renders a **minimal attribution interstitial** (auto-continue, §6.1) and
   redirects the browser to the **upstream** `/authorize` with **Core's** upstream
   `client_id`, Core's public `code_challenge`, `redirect_uri=E7`, `state=<flow id>`
   — the same URL PoC A's helper built from public settings **[PoC A]**.
6. The user approves the upstream consent (the one irreducible consent). The upstream
   returns the browser to E7 with the code. The proxy requires the upstream `state`
   to round-trip the flow id, looks up the flow, and calls
   `POST /v1/ops/toolset/signin` with `Authorization: Bearer <user's Keycloak JWT>`
   and body `{url: <toolset resource url>, credentialsLevel: "USER",
   authenticationType: "OAUTH", code: <upstream code>, redirectUri: E7}`.
   **[PoC A: this exact call proven; Core source: `ResourceCredentialsController` —
   read access required, USER level, stamped with the caller's `sub`.]** Core — the
   only holder of the PKCE verifier — exchanges and stores the upstream tokens per
   user. The flow record is destroyed on first use at E7; the proxy discards the
   Keycloak tokens at flow end (§5.2).
7. The proxy mints an authorization **code** (self-contained signed JWT embedding
   harness `client_id`, `redirect_uri`, `code_challenge`, toolset, `sub`, roles, `exp`
   5 min, `jti`) and redirects the browser to the harness's `redirect_uri` with
   `code`, `state` (echoed), and `iss` (RFC 9207 **[Spec]** — mix-up mitigation).
8. The harness exchanges at E4 with its `code_verifier`. The proxy verifies PKCE
   (S256), `redirect_uri`, `client_id`, `resource`, signature, expiry, and single-use
   (jti replay cache), then issues:
   - `access_token`: proxy-signed JWT, `iss=https://dial.example.org` (the flat
     issuer), `sub` copied from the Keycloak JWT and `roles` **read from the Keycloak
     JWT at the Keycloak IdP entry's configured `rolePath`** (e.g.
     `resource_access.<client>.roles` — copying a literal `roles` claim Keycloak
     never mints would silently yield role-less tokens and 403s), re-emitted as a
     plain `roles` array; `aud` = the resource
     (`https://dial.example.org/dial/notion/mcp`) **plus the marker
     `dial-mcp-proxy`** (enforced by Core config — §10.1, review M-1); `exp` = now +
     10 min, `jti`.
   - `refresh_token`: proxy-signed JWT, `typ=refresh`, same `sub`/`roles`, the
     original `resource`, `exp` = now + 8 h (configurable), distinct `jti`.
9. The harness calls `/dial/notion/mcp` with the proxy JWT → nginx → Core → validated
   via the `dial-mcp-proxy` identity provider (issuer pattern + RSA256 via E8's JWKS
   + the `dial-mcp-proxy` audience marker **[Core source: `IdentityProvider.verifyJwt`
   — RSA256 via JWKS; audience checked only when configured, which §10.1 now does]**)
   → DIAL authorization → per-`sub` upstream credential resolved and injected
   upstream. **[PoC A: this data path proven with a Keycloak JWT; the only new
   elements are the issuer and the audience marker of the JWT.]**

Interactive cost: one Keycloak login (first time only; SSO thereafter) + one upstream
consent per toolset (FR-6). Everything else is HTTP.

### 4.2 Repeat use

- MCP calls: bearer proxy JWT → Core → upstream credential injected. Silent, no
  browser (FR-5, same terminal state PoC A verified; gated on PoC C criterion b).
- New toolset added to the same harness: 401 → E1 → E2 → E3 (with the new toolset's
  `resource`) → Keycloak (SSO-silent) → upstream consent for that toolset → tokens.
  No re-entry of DIAL identity (FR-6).
- Upstream token expiry: **Core refreshes it** using the stored upstream refresh token
  — `OauthTokenRefreshStrategy`/`TokenService` **[Core source]**; no consent, no
  proxy involvement (FR-7). (An *expired upstream refresh token* still ends in
  re-consent — inherent to OAuth, not a design gap.)

### 4.3 Refresh (harness's proxy token) and mid-session expiry

- Access token expires (10 min) → Core 401 → nginx rewrites → harness uses
  `grant_type=refresh_token` at E4 — with `resource`, which the harness sends on
  token requests too **[Capture]**; it must match the refresh token's original
  resource. The proxy verifies the refresh JWT (signature, typ, exp, not
  denylisted) and mints a fresh access token (and rotates the refresh token by
  default, with a short grace window; rotation is configurable — OQ-1; whether the
  harness adopts rotated refresh tokens is PoC C criterion b).
- **No Keycloak and no upstream interaction happens on refresh.** The refresh token
  is purely proxy-local state; this is the property that makes refresh tractable
  (§5.1) and answers the human's "mind refresh".
- Mid-session expiry of the *upstream* credential beyond Core's ability to refresh:
  the MCP call returns the upstream's 401 relayed by Core → nginx rewrites → harness
  re-runs the flow → the proxy reads `user_level_auth_status`; if `SIGNED_IN` it
  reports "upstream rejected the stored credential — sign-out and sign-in again"
  (OR-3), otherwise it re-runs steps 5–7. That this terminates in the sign-in-again
  branch and not a loop is PoC C criterion c.
- Mid-session expiry of the *Keycloak SSO session*: irrelevant to the data path and
  to refresh; it only matters for the *next* first-use flow of a new toolset, where
  the user logs in again. **[Design choice, §5.2 — this is where C departs from the
  human's "store the Keycloak token" sketch.]**

### 4.4 The challenge rewrite (fixing F-1 without touching Core)

nginx, on the toolset data path:

```
set $mcp_origin "https://dial.example.org";    # configured external origin — NOT $host,
                                              # which drops the port behind TLS on a
                                              # non-default port (review M-2)
location ~ ^/dial/(?<tname>[a-z0-9-]+)/mcp$ {
    # variables in proxy_pass suppress nginx's automatic query-string append —
    # $is_args$args is REQUIRED, or MCP streamable-HTTP GETs lose ?sessionId=…
    # (review M-2; PoC C criterion d)
    proxy_pass http://core:8080/v1/toolset/$tname/mcp$is_args$args;
    proxy_buffering off;                       # SSE / streamable HTTP
    proxy_intercept_errors on;
    error_page 401 = @mcp_challenge;
}
location @mcp_challenge {
    add_header WWW-Authenticate
        'Bearer resource_metadata="$mcp_origin/.well-known/oauth-protected-resource/dial/$tname/mcp"' always;
    return 401;
}
```

This converts *every* 401 Core emits on the toolset path — "no token", "invalid
token", and the F-1 case "authenticated but no upstream credential" (where Core
relays the *upstream's* `WWW-Authenticate` **[PoC A]**) — into the proxy's own
challenge. This is the behavior PoC B observed in LiteLLM (its own challenge when no
upstream credential exists — captured raw responses) implemented as router config
instead of code. Consequence for OR-3: the three failure states are no longer
distinguishable from the 401 alone; they are distinguished *inside the flow* (step 4
reads status; §4.3 shows the "upstream rejected us" branch) and via E9. Accepted
trade, revisited in §7.

### 4.5 Sign-out

- **Toolset sign-out** (upstream credential removed — operator action or Chat):
  harness's next call → rewritten 401 → flow re-run → one upstream consent (often
  suppressed — the upstream remembers Core's client). The harness's proxy token
  survives: its DIAL session is never invalidated by upstream credential state
  (OR-4; F-3's coupling is broken because the rewritten challenge points at the
  proxy, not at an AS the harness would fail against and discard its token). Gated
  on PoC C criterion c.
- **Harness logout / token discard** (`claude mcp logout`): local deletion only —
  bearer tokens, nothing to revoke server-side (optionally E10).
- **User-wide revocation**: rotate the proxy's signing key (publish new `kid` in E8,
  wait out Core's JWKS cache — positive cache 10 min by default **[Core source:
  `IdentityProvider.positiveCacheExpirationMs`]** — drop the old `kid`). All proxy
  tokens die within minutes (§6.3).
- **Keycloak session logout**: not wired in v1 (no RP-initiated logout); see OQ-6.

---

## 5. Token and state design

### 5.1 The alternatives (the question the human posed, answered)

The question: *why not store the Keycloak tokens server-side (A), or seal them inside
the proxy's own token (B), and use real Keycloak tokens on the data path — so Core
needs to know nothing about proxy tokens?* Both work. Neither is chosen. The third
option (C) — the proxy issues JWTs carrying the user's real `sub` and registers in
Core as an additional identity provider — wins on the human's own criteria:

| | **A — session store** | **B — sealed tokens** | **C — proxy as Core IdP** *(chosen)* |
|---|---|---|---|
| Data path | proxy on it (swap per request) | proxy on it (unwrap per request) | **router → Core directly** (correction 2, literally) |
| What Core must learn | nothing | nothing | one IdP entry (static settings, config-only — **[Core source: verified it exists; independently confirmed by the review]**, restart required) |
| Post-flow secrets the proxy/harness hold | Keycloak access+refresh per session (server-side, plaintext to the proxy) | Keycloak access+refresh sealed inside every token the *harness* stores | **none** — Keycloak tokens are used during the flow and discarded |
| Refresh | proxy must refresh Keycloak tokens server-side; Keycloak refresh rotation vs a store is manageable but is third-party-coupled state | rotation only happens at `/token`; requires the invariant *outer exp < inner exp* or a stale sealed refresh token breaks the next refresh; header grows by the sealed JWTs (~1–2 KB) | **proxy-local**: refresh tokens are the proxy's own JWTs; no third-party rotation semantics to honor at all |
| Restart / scale | sessions lost → harness re-OAuth (SSO-silent, but a browser round-trip); scale needs a shared store | sessions survive; stateless | **flows in flight are lost (bounded, §5.3); issued tokens survive; refresh survives; horizontal scale is trivial** |
| Trust concentration | signing key gates proxy admission; per-user refresh tokens are the prize | same, plus harvested sealed tokens become decryptable if the key leaks | signing key can assert **any** `sub` — the largest blast radius of the three (§6.2), mitigated but not removed |
| Consistency with "never share the Keycloak token" (correction 3) | holds (server-side) | the harness *carries* the Keycloak tokens, encrypted — defensible, but the bytes leave the proxy | **holds absolutely** — the harness never holds any Keycloak material |

**Choice: C.** Reasons, in order of weight:

1. It is the only option that satisfies correction 2 literally — the stateful
   component never touches the data path.
2. Refresh (the human's flagged concern) degenerates to proxy-local JWT re-issuance:
   no third-party token rotation, no TTL coupling, no secret retention. A and B both
   spend their complexity budget exactly there.
3. It holds zero user secrets after a flow completes. A caches per-user refresh
   tokens; B distributes them (encrypted) to every harness.
4. The Core config surface it needs verifiably exists **[Core source]**.

Rejected despite the sketch: the human's sketch stored the Keycloak token (memory or
sealed) precisely so the *data path* could use real Keycloak tokens. That is A/B.
The rejection reason is not that they cannot work — they can — but that they buy
"Core knows nothing new" at the price of putting the proxy on the data path and
making refresh third-party-coupled, both of which the human's own corrections 2 and
"mind refresh" argue against. C buys the same "Core code knows nothing new" (config
only) without either price.

Fallback: if an operator refuses to touch even Core's static settings, **A** is the
fallback (proxy on the data path, no Core config); B is not recommended (all of B's
costs, plus key-leak retroactively exposes every distributed sealed token).

### 5.2 Token lifecycle (chosen alternative, in full)

| Phase | What happens |
|---|---|
| **Issuance** | At E4, after PKCE + `resource` verification. `sub` is copied from the Keycloak JWT; `roles` are read at the **Keycloak IdP entry's configured `rolePath`** and re-emitted as a plain `roles` array (the proxy entry's `rolePath: "roles"` — review m-6: naming the source path prevents a silent role-less-token downgrade). The Keycloak access token is used exactly twice — toolset settings fetch (step 4) and `/v1/ops/toolset/signin` (step 6) — then **discarded**. No Keycloak refresh token is ever requested or stored (the proxy's Keycloak client requests no `offline_access`). |
| **Expiry** | access 10 min (config `proxy.token.accessTtl`), refresh 8 h (`proxy.token.refreshTtl`). Refresh re-mints access and rotates refresh. After refresh `exp`, the harness gets `invalid_grant` and re-runs the flow (Keycloak SSO usually silent). |
| **Refresh** | §4.3. Proxy-only; no Keycloak, no upstream. Roles are a **snapshot** frozen at issuance and carried in the refresh token — role changes take effect at the next *flow*, not at refresh. Bounded by `refreshTtl`; same staleness class as any offline token. |
| **Revocation** | Per-token: E10 (denylist `jti` until `exp`). Per-user: rotate key (all users) or wait out `refreshTtl` after denylisting their refresh tokens — access tokens die within 10 min regardless. There is **no per-user selective kill of live access tokens** without key rotation — the same limitation every non-introspected JWT IdP has (Core does not introspect Keycloak's tokens either **[Core source: `AccessTokenValidator` does signature/issuer/audience verification only]**). |
| **Logout** | §4.5. |
| **Mid-session expiry** | §4.3. |
| **Key material** | RSA-256 only (Core's verifier is `Algorithm.RSA256` **[Core source]**), `kid` in E8, private key in KMS/HSM if available; rotation procedure: publish new `kid` → wait Core's JWKS cache TTL (10 min default) → retire old. |

### 5.3 State: where it lives, and what its loss means

The PoC B lesson: LiteLLM binds OAuth state to a browser cookie with a short TTL, and
losing it fails opaquely. This design carries state **server-side in the proxy**,
keyed by a flow id in the `state` parameter sent to *both* Keycloak and the
upstream — never in a browser cookie.

**Flow ids are 128-bit CSPRNG values, and the entropy is load-bearing** (review m-3).
The attack it kills: an attacker who *guesses an in-flight flow id* hits E7 with
their **own** upstream authorization code (obtainable — the toolset's
`code_challenge` is public and the consent is the attacker's own). Without the
entropy requirement the proxy would call `/signin` with the **victim's** Keycloak JWT
and the **attacker's** code, and Core would store the attacker's upstream credential
under the victim's `sub` — the victim's toolset traffic would then execute against
the attacker's workspace, an exfiltration channel for every query and tool argument.
Defenses: unguessable ids (2⁻¹²⁸ per guess), the upstream `state` must round-trip the
id, and the flow record is destroyed on first use at E7.

| State | Store | TTL | On loss |
|---|---|---|---|
| Flow records (harness OAuth params, Keycloak JWT mid-flow) | in-memory map, 128-bit flow id = key | 10 min | In-flight sign-ins die. The browser lands on E6/E7 with an unknown flow and gets a **plain-language HTML error** ("sign-in session expired — re-run the sign-in from your harness"), not an opaque failure. Retry is one command. This is the deliberate answer to the LiteLLM lesson. |
| Authorization-code replay cache (`jti`) | in-memory | 5 min | A code could be replayed within its TTL — still PKCE-bound to the original client's verifier, `redirect_uri` and `client_id`, so replay by anyone else fails anyway. Bounded, accepted. |
| Refresh denylist | in-memory | until `exp` | Revoked refresh tokens resurrect until their own `exp` (≤ 8 h). Bounded by short `refreshTtl`; acceptable for v1; Redis if not. |
| Issued tokens | **nowhere** (self-contained JWTs) | — | Restarts and horizontal scaling do not affect them. |

**Resource exhaustion (review m-4):** E3 (and E5, if enabled) are unauthenticated
browser endpoints that allocate flow/registration records. They are rate-limited per
IP and globally, and a hard cap bounds live flow records — the oldest are evicted and
their browsers receive the same plain-language error page. Bounded memory, no silent
degradation.

v1 is a single proxy instance; if HA is required, the maps move to Redis — behavior
on loss is already defined above.

---

## 6. Security analysis

### 6.1 Consent attribution (the problem the human raised)

On the upstream consent screen the user approves **Core's** registered client (DIAL),
not their harness; the harness is invisible to the upstream AS. Mitigations, honest
about their limits:

1. **Client naming.** Core's upstream client is named at registration (e.g. "DIAL
   (dial.example.org)") — operator config, one-time. The proxy's Keycloak client is
   named recognizably (e.g. "DIAL MCP Sign-In Service"). The user always sees *which
   organization* they are granting.
2. **The interstitial.** Between the Keycloak leg and the upstream consent, the proxy
   renders an auto-continuing page: *"You are connecting toolset 'notion' for client
   'Claude Code' (registered as …) through DIAL. Continue to Notion."* The proxy
   knows the harness client (step 2) and the toolset (from `resource`); where the
   registration carries a real `client_name` (CIMD/pre-registered), it prefers that
   over the bare `client_id`. This is attribution the upstream AS cannot provide; it
   is display-only (not a cryptographic guarantee).
3. **Audit (SR-4).** The proxy logs per flow: flow id, `sub`, harness `client_id` +
   `redirect_uri`, toolset, timestamps, upstream code receipt, `/signin` result.
   Core's `/signin` independently records the acting user. The chain is attributable
   end-to-end.
4. **Mix-up / `state`.** Each leg carries its own anti-mix-up state: harness ↔ proxy
   (`state` echoed, plus `iss` in the authorization response **[Spec: RFC 9207,
   required by MCP 2026-07-28]**), proxy ↔ Keycloak (its own `state` + PKCE pair),
   proxy ↔ upstream (flow id + Core's challenge). Three independent PKCE pairs; no
   verifier crosses a trust boundary.

### 6.2 Trust concentration — the honest statement

In C, **the proxy's signing key is exactly as powerful as Keycloak's signing key**:
whoever holds it can mint a DIAL identity for *any* `sub` with *any roles, including
admin* — not only users who ever used the proxy. That is the price of C, and it is
strictly larger than A/B's (where the key only admits traffic to the proxy, and the
per-user secrets expire naturally). What bounds it:

- The key is a Tier-0 secret operated like one: KMS/HSM-held, `kid` rotation
  procedure, network-restricted E8, no `offlineClient` configured on the IdP entry
  **[Core source: `offlineClient` is optional per provider; with it unset, the proxy
  issuer can never mint DIAL_NATIVE offline credentials — confirmed by the review]**.
- Access tokens are 10-minute; a stolen key is detectable and revocable on the
  rotation timescale (JWKS cache: ≤ 10 min **[Core source]**).
- **Audience marker (review M-1):** `"audience": "dial-mcp-proxy"` on the IdP entry
  makes Core *reject* any proxy-issuer token without the marker. This structurally
  binds every accepted proxy token to proxy issuance and eliminates the accidental
  cross-issuer acceptance class. It does **not** shrink key-compromise blast radius
  (an attacker holding the key mints the marker too) and it is **not** per-toolset
  binding: a leaked proxy token remains valid on every Core endpoint for its `sub`.
  With the flat shared AS, per-toolset audience enforcement via per-toolset IdP
  entries is *not available as a hardening option* — it would require per-toolset
  issuers, which the capture shows this harness class cannot discover **[Capture]**.
  The only per-toolset binding in the chain is therefore the proxy's own
  `resource` check at E3/E4 plus the `aud` it mints (advisory downstream). The
  structural fix is a Core-side ask (per-issuer path/audience scoping, OQ-4).
- The blast radius excludes upstream credentials: those stay encrypted in Core per
  user (I1); key compromise yields *use* of other users' toolset access via the MCP
  endpoint, not *theft* of their upstream tokens.
- The difference from Keycloak is operational maturity, not kind: Core already
  accepts non-introspected bearer JWTs from Keycloak. The proxy is new, smaller code
  with a smaller audit budget — that, not the mechanism, is the residual risk, and
  it is the reason the proxy must stay a small, single-purpose, internal-logic-only
  service.

### 6.3 Revocation summary

| Revoke what | Mechanism | Latency |
|---|---|---|
| one harness session | E10 + refresh `exp` | access ≤ 10 min |
| one user's proxy access | denylist their refresh `jti`s | ≤ 10 min (access TTL) |
| all proxy access | key rotation (`kid` add → retire) | ≤ 10 min (Core JWKS cache) |
| a toolset credential | existing `/v1/ops/toolset/signout` (unchanged) | immediate (Core) |
| the user's DIAL identity at the source | Keycloak session revocation — affects future *flows*, not live proxy tokens (role snapshot can outlive it by ≤ `refreshTtl`, §6.5 I4) | n/a (noted, OQ-6) |

### 6.4 What an attacker gains by compromising each component

| Component compromised | Attacker gains |
|---|---|
| harness (or its token store) | that one user's proxy tokens → that user's toolset access (and, per §6.2, every Core endpoint for that `sub`) until expiry. No other user, no upstream tokens (SR-3). |
| proxy (key + process) | mint-any-`sub`/any-role tokens (§6.2); **one in-flight user's Keycloak JWT, valid until that JWT's own `exp`** — the flow TTL (10 min) bounds *retention*, not the token's life (review m-5); audit log. Not: upstream tokens, PKCE verifiers, stored credentials. |
| Core | everything it holds today (unchanged by this design). |
| Keycloak | what it holds today; additionally the ability to authenticate federation flows (but the proxy still gates issuance). |
| nginx | challenge rewrite (phishing surface: could point clients at a hostile AS) and data-path tampering — same class as any front-router compromise today. |

### 6.5 Invariants re-checked

- **I1** upstream token in Core only — the proxy transits only the *code*;
  single-use, PKCE-bound, useless without Core's verifier.
- **I2** verifier never leaves Core — the proxy uses only the public
  `code_challenge` **[Core source: `redactSecrets()`; confirmed by the review]**.
- **I3** credential levels unchanged — the proxy signs in at USER level only; GLOBAL
  requires admin and stays an operator action (see §8, not-solved list).
- **I4** DIAL authorization applies on every call — data-path validation and toolset
  access control in Core, plus the flow's step-4 read-access check. **Caveat,
  disclosed:** the roles the authorization runs on are a proxy-asserted snapshot up
  to `refreshTtl` (8 h) old — a revoked user's toolset access can outlive their
  Keycloak session by hours. Inherent to C (A/B share the class), bounded by config.
- **I5** `POST /v1/ops/toolset/signin` reused verbatim **[Core source: request
  schema `ResourceSignInRequest{url, credentialsLevel, authenticationType, code,
  apiKey, redirectUri, offlineUsageConsent}`]** — the proxy is a new *caller*, which
  the API was always meant to have. It is a facade *in front of* the unified API,
  not a replacement — `API_KEY` and `DIAL_NATIVE` keep their home.

---

## 7. Requirement traceability

Rows marked **gated on PoC C** are design-level claims whose evidence is the gated
experiment of §9 item 2 — they are conditional until it passes.

| Req | How satisfied | Status |
|---|---|---|
| FR-1 | stock harness + browser consents only; no Chat anywhere in §4.1 | met — **gated on PoC C (a)** |
| FR-2 | `claude mcp add` + the harness's own OAuth; browser only where consent is irreducible | met |
| FR-3 | E1's `dial_authentication_type` extension (proxy owns the document) + the challenge always naming the proxy | **met for OAUTH toolsets; non-OAUTH kinds are excluded from the v1 mapping (§3 invariant) and remain OQ-7** |
| FR-4 | E9 (`/dial/{name}/status` with proxy JWT) + step-4 status display in the flow | met |
| FR-5 | data path identical to PoC A's verified silent path | met — **gated on PoC C (b)** |
| FR-6 | one consent per leg per toolset; SSO for the DIAL leg; refresh needs no browser | met |
| FR-7 | upstream refresh is Core's **[Core source]** (expired upstream refresh tokens still end in re-consent — inherent) | met |
| FR-8 | nginx 401 rewrite (§4.4) — the proxy's own challenge, the behavior PoC B observed in LiteLLM's raw responses | met — **gated on PoC C (a)/(d)** |
| SR-1 | only the code transits; tokens never leave Core (I1/I2) | met |
| SR-2 | credential stamped with the Keycloak-authenticated `sub`; per-user resolution unchanged **[PoC A]**. C-caveat: binding transitively relies on the proxy copying `sub` faithfully — the §6.2 trade, disclosed | met |
| SR-3 | proxy tokens are per-session bearer tokens bound to one `sub`; loss affects one user, nothing upstream | met |
| SR-4 | §6.1 (naming, interstitial, audit chain) | met (interstitial is display-level; noted) |
| SR-5 | identity via OAuth only; no API keys to harnesses | met |
| SR-6 | the proxy pre-registers once in Keycloak; harnesses register against the *proxy* (CIMD/pre-registered, no realm policies involved) — F-4 neutralized | met |
| OR-1 | Core static settings + toolset config + nginx config only | met (settings change needs a Core restart — static settings are not hot-reloaded) |
| OR-2 | **deviates, knowingly**: the design adds one always-on server-side component. The requirement's letter (aimed at the *local shim*) cannot be satisfied by any gateway-shaped answer, including the human's own sketch. Spirit preserved: nothing per-user, nothing client-side, deployed inside the deployment's trust zone beside the router | **deviation — accepted, documented; sign-off required (OQ-8)** |
| OR-3 | three states distinguished inside the flow and via E9, not by the 401 alone (§4.4 trade) | partially met (accepted trade) |
| OR-4 | proxy token lifecycle fully independent of upstream credential state | met — **gated on PoC C (c)** |
| CR-1 | RFC 9207 `iss` in responses and the token-passthrough prohibition fully honored (Core strips caller `Authorization` upstream, `forwardAuthToken=false` default **[PoC A/Core source]**); RFC 8707 audience binding enforced **only at the `dial-mcp-proxy` marker level** (config-only, review M-1) | **partially met — marker enforced config-only; per-toolset audience is not enforceable in this shape (§6.2) without a Core change (OQ-4); a leaked proxy token is valid deployment-wide for its `sub`** |
| CR-2 | registration priority pre-registered → CIMD **[Capture: Claude Code takes the CIMD path]** → DCR retained config-gated, default off (spec-deprecated; PoC A observed harness DCR only when CIMD was not advertised) | met |
| CR-3 | no harness-specific code anywhere; harness sees only MCP + OAuth2. Evidence: the capture shows the flagship harness speaking standard discovery/registration **[Capture]**; PoC B's probes walked a mature gateway's equivalent standard surface **[PoC B, scripted — not a harness]**; the full proxy chain is PoC C (a) | met — **gated on PoC C (a)** |

---

## 8. Amendments to the DIAL Core implementation (May 2026)

1. **UC-2 / UC-12 are implemented by an external AS, not by Core.** The authN design's
   implementation plan item 5 ("as a worst case — implement custom AS for DIAL MCP
   toolsets, redirecting to the real IdPs") is hereby promoted from worst case to the
   chosen mechanism, and relocated outside Core to keep Core code frozen.
2. **The Keycloak-DCR conclusion is amended.** "If DIAL owner wants standard MCP
   authentication, they have to deploy KeyCloak [with DCR]" (F-6) no longer holds for
   proxy-fronted clients: harnesses register against the proxy — via CIMD or
   pre-registration, neither of which touches the IdP. The deployment's IdP needs
   only one pre-registered public PKCE client for the proxy. Direct-to-Core clients
   still need the IdP's DCR story — the amendment is scoped to the proxy-fronted
   path.
3. **"Can Credentials Manager live without UX" is answered concretely**: the proxy is
   the headless Credentials Manager *frontend* — its interstitial + flow pages are
   the minimum UX, rendered by the satellite, not by Chat.
4. **Identity-provider model extension**: a second JWT issuer whose tokens are minted
   only after live Keycloak authentication of the same `sub` (federated token
   translation). The authN design assumed tokens arrive directly from trusted IdPs;
   this adds a *derived* issuer with an explicitly larger key-compromise blast radius
   (§6.2).
5. **Scenario 3's redirect target**: `auth_settings.redirect_uri` / the allowlist
   gains `https://<host>/dial/callback/upstream` alongside `{chat-host}` targets.
6. **Not amended**: credential levels and resolution, storage, encryption, consent
   for apps — untouched.

---

## 9. Open questions and the implementation gate

1. **Refresh-token rotation vs harnesses.** The proxy rotates refresh tokens by
   default; OAuth 2.1 expects clients to adopt rotated tokens, but MCP harness
   behavior is uneven. Ship rotation behind a config flag; PoC C criterion (b)
   observes what Claude Code does with a rotated refresh token. **[Assumed until
   then]**
2. **PoC C — the implementation gate (not an open question).** The assembled
   federation chain has never been run end-to-end; every *ingredient* is verified
   (Core config surfaces, `/signin`, the challenge, LiteLLM's surface, the capture's
   discovery/registration behavior), the *assembly* is not. **Implementation is
   gated on a real-harness run passing ALL of:**
   - **(a) First use, real harness (Claude Code), not curl:** rewritten 401 → E1 →
     flat E2 → registration (CIMD: `client_id` URL, no `/register` call) → E3 with
     `resource` → Keycloak → interstitial → upstream consent → E7 → `/signin` → E4
     → live `tools/call` through `/dial/{name}/mcp` authenticated by a
     proxy-signed, copied-`sub` JWT.
   - **(b) Silent repeat use and refresh-on-401 with rotation ON** (does the harness
     adopt the rotated refresh token?), no browser.
   - **(c) Mid-session upstream-credential removal** (sign-out via the ops API)
     produces the §4.3 "sign-out and sign-in again" branch, not a 401 loop.
   - **(d) Query strings survive the nginx data-path rewrite** — a streamable-HTTP
     GET with `?sessionId=…` reaches Core intact.
   - **(e) Coexistence:** a direct-to-Core Keycloak client (PoC A's Leg 2) keeps
     working unchanged while the proxy front door is live.

   Failure of any criterion is a falsification of this design and triggers revision,
   not a note about "unexpected harness behaviour". Until PoC C passes, the status
   stays "for review" and §7's gated rows stay conditional. The PoC A rig
   (`dial-instance`) is the intended environment.
3. **Multi-instance HA** — single instance v1; Redis-backed maps if required (loss
   semantics already defined, §5.3).
4. **Per-issuer path/audience scoping in Core** (restrict the proxy issuer — or its
   audiences — to toolset endpoints) — the structural fix for §6.2's residual and
   CR-1's per-toolset gap; a worthwhile future Core config feature; explicitly *not*
   a dependency.
5. **CIMD maturity** — the draft is young, but the capture shows it is how Claude
   Code actually registers **[Capture]**; the proxy validates redirect URIs from the
   fetched document and allowlists fetch origins. Remaining risk is draft churn and
   other harnesses' adoption; DCR stays available behind the config flag.
6. **Keycloak RP-initiated logout** — wiring the flow's completion to OIDC
   end-session so "sign out" also ends the SSO session; deferred (v1 logout is local
   + revoke).
7. **API_KEY toolsets** — the same wrapper could work (the interstitial becomes a
   key-paste form; `/signin` carries `apiKey` instead of `code` — the unified API
   already supports it **[Core source]**), but they are excluded from the v1 mapping
   by the §3 invariant; the open question is the UX shape.
8. **Owner sign-offs (two, explicit)** — (i) the OR-2 deviation: one always-on
   server-side component; (ii) correction-2 tension: the nginx 401 rewrite
   *synthesizes* a challenge header rather than purely splitting traffic (§2, §4.4;
   no config-only alternative fixes F-1). Both need the deployment owner's
   acceptance before build.
9. **GLOBAL-level sign-in for toolset owners** requires admin roles on the calling
   token; the proxy flow covers USER level only. Owners keep using the ops API/Chat.
10. **`resource` conformance beyond Claude Code.** With the shared flat AS, the
    `resource` parameter is *structurally required* at E3/E4 (no lenient mode is
    possible — there is no path signal to fall back to). The capture proves Claude
    Code conforms **[Capture]** and the spec requires it **[Spec]**; the residual
    risk is other harnesses. The single escape hatch is
    `infer_resource_single_toolset: true` for one-toolset deployments. PoC C (a)
    is the first systematic measurement; revisit only if a named harness fails it.

---

## 10. Deployment and configuration

### 10.1 DIAL Core (static settings — `aidial.settings.json`, restart required)

**Strictly required** for the design to function:

```jsonc
{
  "identityProviders": {
    "keycloak": {                          // existing entry — one REQUIRED addition:
      "issuerPattern": "^https://keycloak:8443/realms/dial$",   // REQUIRED in multi-IdP mode
      "jwksUrl": "https://keycloak:8443/realms/dial/protocol/openid-connect/certs",
      "rolePath": "<existing role path>",  // unchanged — the proxy copies roles FROM here (§5.2)
      "audience": "<existing value>",      // unchanged, if set
      // m-10: mirror loggingKey/loggingSalt here if the Keycloak entry sets them,
      // or proxy-leg logins vanish from obfuscated user logging
    },
    "dial-mcp-proxy": {                    // NEW — alternative C's whole Core footprint
      "jwksUrl": "https://<internal-or-public>/dial/jwks.json",
      "issuerPattern": "^https://dial\\.example\\.org$",   // the proxy's single, flat issuer
      "rolePath": "roles",                 // the proxy re-emits roles as a plain array
      "audience": "dial-mcp-proxy"         // REQUIRED (review M-1) — Core rejects proxy-issuer
                                           // tokens without this marker; config-only enforcement
    }
  },
  "toolsets": {
    "security": {
      "allowedRedirectUris": [
        "https://dial.example.org/dial/callback/upstream"   // NEW — for the /signin call
      ]
      // resourceHost / resourceSchema / authorizationServers / scopesSupported:
      // unchanged — Core's own discovery surface keeps serving direct clients
    }
  }
}
```

Two notes. (1) The `issuerPattern` addition on the *existing* Keycloak entry is easy
to miss and is **strictly required**: with more than one provider, Core selects the
provider by issuer match, so every JWT provider must carry a pattern
**[Core source: `AccessTokenValidator.extractClaimsFromJwt` loops `idp.match(jwt)`;
without a pattern a provider can never match]**. (2) The proxy's `issuerPattern`
must not overlap any other provider's pattern on the same origin — if Keycloak were
ever served from `https://dial.example.org`, the two patterns would be ambiguous;
keep the proxy issuer on the public origin and Keycloak on its own.

The review's optional hardening of *per-toolset IdP entries* (one entry per
high-value toolset with its own audience) is **not adopted**: it requires
per-toolset issuers, which the capture shows this harness class cannot discover
**[Capture]**, and it conflicts with dynamic toolset creation (static settings,
restart per toolset). The honest residual — a leaked proxy token is valid
deployment-wide for its `sub` — is stated in §6.2/CR-1; the structural fix is OQ-4.

Dynamic config (`aidial.config.json`): nothing new — existing OAUTH toolsets as-is.

### 10.2 Keycloak

One pre-registered **public PKCE client** `dial-mcp-proxy`: redirect URI
`https://dial.example.org/dial/callback/keycloak`, PKCE S256 required, no client
secret, default client scope that mints DIAL roles + audience into the access token
(the same mapper setup the DIAL Core implementation's Keycloak section describes for DCR
clients). No `offline_access`. No registration-policy changes (SR-6).

### 10.3 The proxy service

```yaml
external_origin: https://dial.example.org     # M-2: configured origin — used in the nginx
                                             # challenge too; never derived from $host
issuer: https://dial.example.org              # flat, path-less — RFC 8414 flat well-known
jwks: { key_source: kms|file, kid: 2026-10 }
core: { base_url: http://core:8080, toolset_url_template: "/v1/toolsets/{bucket}/{name}" }
keycloak:
  issuer: https://keycloak:8443/realms/dial
  client_id: dial-mcp-proxy          # public, PKCE; no secret
  redirect_uri: https://dial.example.org/dial/callback/keycloak
  roles_source_path: null            # null = read the Keycloak IdP entry's rolePath; see §5.2
toolsets:                            # client-facing name -> core resource; OAUTH-only (§3)
  notion: { url: "toolsets/platform/notion", authentication_type: OAUTH }   # startup-checked
token: { access_ttl: 10m, refresh_ttl: 8h, code_ttl: 5m, flow_ttl: 10m,
         rotate_refresh: true, resource_required: true,
         infer_resource_single_toolset: false }    # the one-toolset escape hatch (§9 item 10)
registration: { pre_registered: [...], cimd_allowed_origins: ["https://claude.ai"],
                dcr_enabled: false }               # default OFF (§3.1 E5)
limits: { flows_max_live: 10_000, rate_per_ip: 30/min, rate_global: 600/min }   # m-4
audit: { sink: stdout|otel }
```

At startup the proxy fetches each mapped toolset's public `auth_settings` (with a
service identity or anonymously if the deployment allows) and **refuses to start**
on a non-OAUTH mapping unless that entry is marked `route_only: true` (paths served,
challenge rewrite disabled for them) — the §3 invariant, enforced rather than
documented (review M-3).

### 10.4 nginx

```
# AS + discovery surface -> proxy
location = /.well-known/oauth-authorization-server   { proxy_pass http://mcp-signin-gateway; }
                                             # the FLAT AS metadata [Capture]; Core serves
                                             # nothing at this path today
location ~ ^/\.well-known/oauth-protected-resource/dial/ { proxy_pass http://mcp-signin-gateway; }
location ~ ^/dial/(callback|jwks\.json|authorize|token|register|revoke)(/|$) { proxy_pass http://mcp-signin-gateway; }
location ~ ^/dial/(?<tname>[a-z0-9-]+)/status$      { proxy_pass http://mcp-signin-gateway; }

# data path -> Core, direct (correction 2), with the F-1 fix — full block in §4.4
# (includes $is_args$args and the $mcp_origin challenge header, review M-2)

# everything else -> Core, unchanged
```

### 10.5 Effort estimate

Proxy service: ~10 endpoints, one crypto dependency (JWT/JWKS), three in-memory
stores, no database — roughly 2–3 engineer-weeks to implement plus hardening (its
own threat model, given §6.2). nginx + Core settings + Keycloak client: days. The
blocking item is the PoC C gate (§9 item 2), not implementation size.

---

## Appendix — what is deliberately NOT solved (honesty list)

- **OR-2's letter** — one always-on component is added (§7); requires sign-off, as
  does the nginx challenge synthesis (OQ-8, both).
- **Per-toolset audience enforcement** — a leaked proxy token is valid on every Core
  endpoint for its `sub` (marker-level binding only, §6.2/CR-1); structural fix is a
  Core-side ask (OQ-4).
- **Per-user live-access-token revocation** without key rotation — impossible without
  Core-side introspection; bounded by the 10-minute access TTL.
- **Role staleness** within a refresh window (8 h max, snapshot semantics — §6.5 I4).
- **GLOBAL / app-level credential establishment from the harness** — admin-gated in
  Core, stays an operator action.
- **Non-OAUTH toolsets** — excluded from the v1 mapping by the §3 invariant
  (enforced at proxy startup); the API_KEY wrapper remains OQ-7.
- **Upstream consent shows Core's client, not the harness** — mitigated by naming +
  interstitial (display-level, §6.1); no cryptographic attribution exists at an
  upstream AS for downstream clients, in any architecture.
- **The proxy flow itself is unproven end-to-end** — every ingredient is PoC-,
  source-, or capture-verified; the assembled chain is the PoC C gate (§9 item 2),
  and §7's gated rows are conditional until it passes.
- **Harness behavioral assumptions** (A1–A3 plus): the harness refreshes on 401,
  re-runs discovery/authorize on a challenge, stores tokens per MCP server, and
  sends the `resource` parameter. Claude Code is evidenced for discovery/
  registration/`resource` **[Capture]** and for the Keycloak-shaped OAuth walk
  **[PoC A]**; the proxy-shaped walk is PoC C; other harnesses are expected, not
  tested.

---

*Imported into this repository from the DIAL design archive on 2026-10-17. This copy is the **living** version of this document; the archive copy is a frozen historical record and is not updated. References to the May 2026 toolset authentication design have been replaced with references to the DIAL Core source, because that document predates the MCP specification revision that deprecated Dynamic Client Registration.*
