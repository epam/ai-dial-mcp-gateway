# Spec Delta

## Purpose

Lets a harness user sign in to an OAuth-protected DIAL MCP toolset and use it with no DIAL Chat in the deployment: the gateway owns the client-facing OAuth surface, runs the upstream consent through Core's unified credential API, and mints the tokens Core trusts.

## ADDED Requirements

### Requirement: Toolset MCP path answers with the gateway's own challenge

Every 401 on the front-door toolset MCP path — no token, invalid token, or a valid token with no stored upstream credential — MUST be answered with the gateway's own challenge: 401 plus `WWW-Authenticate` naming the gateway's protected-resource metadata for that toolset. The upstream's challenge MUST never reach the client, because no client can complete it. Query parameters MUST survive the front-door routing, because streamable-HTTP sessions resume through them.

#### Scenario: No token
- **WHEN** a client calls the toolset MCP path with no Authorization header
- **THEN** the response is 401 with a `WWW-Authenticate` header whose `resource_metadata` names the gateway's protected-resource metadata for that toolset

#### Scenario: Valid token but no stored upstream credential
- **WHEN** a client calls the toolset MCP path with a valid gateway token for a user with no stored upstream credential
- **THEN** the response is 401 with the gateway's own challenge, not the upstream's challenge

#### Scenario: Query string survives routing
- **WHEN** a client sends `GET /dial/<name>/mcp?sessionId=<id>` through the front door
- **THEN** the request reaching Core carries the `sessionId` parameter unchanged

### Requirement: Discovery documents describe one flat authorization server

The gateway MUST serve one RFC 8414 AS metadata document at the host root for a single path-less issuer — the public origin — and one RFC 9728 protected-resource document per mapped toolset. The AS metadata MUST advertise both grants, S256, token-endpoint auth method `none`, and client-ID-metadata-document support, so CIMD-capable clients register with no registration call. Each protected-resource document MUST name the single AS issuer and the toolset's authentication kind.

#### Scenario: Flat AS metadata fetch
- **WHEN** a client fetches `GET /.well-known/oauth-authorization-server` on the public origin
- **THEN** the document's issuer is the public origin and its authorization and token endpoints are shared by all toolsets

#### Scenario: Per-toolset protected-resource fetch
- **WHEN** a client fetches the protected-resource document for a mapped toolset
- **THEN** the document returns the toolset's resource URI, the single AS issuer, and the authentication-kind extension naming OAUTH

#### Scenario: Unmapped toolset
- **WHEN** a client fetches the protected-resource document for a name absent from the mapping
- **THEN** the response is 404

### Requirement: Client registration resolves pre-registered, CIMD, then gated DCR clients

Clients are resolved in priority order: pre-registered client id (operator config); a Client ID Metadata Document at a URL-shaped client id; Dynamic Client Registration only if enabled (default off). The CIMD fetch is server-side request forgery surface and MUST be bounded: HTTPS only, allowlisted origins, no redirects, private/loopback/link-local addresses refused, size capped, cached. All clients are public PKCE; no secret is stored; `redirect_uri` MUST be validated against the registration.

#### Scenario: CIMD registration without a registration call
- **WHEN** a client presents a URL-shaped client id whose document is served by an allowlisted HTTPS origin
- **THEN** the gateway fetches and caches the document, and later authorization requests are accepted only for redirect URIs that match an entry of the document's `redirect_uris` under the redirect-URI matching rule

#### Scenario: CIMD fetch refused
- **WHEN** the client-id URL is not HTTPS, its origin is not allowlisted, it redirects, or it resolves to a private, loopback, or link-local address
- **THEN** the fetch is refused and the authorization request fails

#### Scenario: Unregistered redirect URI
- **WHEN** an authorization request carries a redirect URI that no entry of the client's resolved registration matches under the redirect-URI matching rule
- **THEN** the request is rejected

#### Scenario: DCR off by default
- **WHEN** DCR is not explicitly enabled and a client POSTs to the registration endpoint
- **THEN** the response is the documented disabled-error (404), and the AS metadata advertises no registration endpoint

### Requirement: Loopback redirect URIs match ignoring the port

A registered redirect URI that is loopback — `http` scheme with host `localhost`, `127.0.0.1`, or `[::1]` — MUST match a request redirect URI with identical scheme, host, and path, the port ignored on both sides (RFC 8252 §7.3). Only the port is excepted: any query or fragment presence or difference is non-matching. Every other registered URI MUST match on exact string equality only. The exception is keyed on the registered entry, never the request's value.

#### Scenario: Loopback port variation accepted
- **WHEN** the client's registration lists a port-less loopback redirect URI (`http` scheme, loopback host) and an authorization request presents that URI with an ephemeral port
- **THEN** the redirect URI matches the registration and the request proceeds

#### Scenario: Explicit-port loopback entry matches port variation
- **WHEN** the client's registration lists a loopback redirect URI with an explicit port, a default port included, and an authorization request presents that URI with a different port
- **THEN** the redirect URI matches the registration and the request proceeds

#### Scenario: Non-loopback port difference rejected
- **WHEN** the client's registration lists a non-loopback redirect URI and an authorization request presents it with a different port
- **THEN** the redirect URI is rejected — the exception is keyed on the registered entry, so a request cannot earn it by self-declaring loopback

#### Scenario: Loopback scheme, host, or path difference rejected
- **WHEN** the client's registration lists a loopback redirect URI and an authorization request presents a URI that differs in scheme, host, or path
- **THEN** the redirect URI is rejected with the port ignored

### Requirement: DCR registration records are durable across restarts

Dynamic Client Registration records MUST survive a gateway restart: each registration is written atomically to one JSON file in a mounted volume, loaded at startup. An unreadable or corrupt store MUST refuse startup with an operator-facing error naming the path — a silent drop invalidates every registered client without a trace. Stored registrations MUST be capped; at the cap, new ones are refused with a plain-language error. The registration endpoint is advertised only while DCR is enabled.

#### Scenario: Registration persists across restart
- **WHEN** a client registers via the registration endpoint and the gateway process restarts
- **THEN** the registration is loaded at startup, and an authorization request from that client id with a registered redirect URI is accepted with no re-registration

#### Scenario: Registration persisted before the response
- **WHEN** a registration is accepted at the registration endpoint
- **THEN** the record is written to the store before the response is returned, so a restart immediately after registration never loses a client id the client has already cached

#### Scenario: Store dormant while DCR is disabled, restored on re-enable
- **WHEN** DCR is disabled while registrations are stored, and later re-enabled
- **THEN** the store is preserved unchanged while disabled, and every stored registration resolves again on re-enable with no re-registration

#### Scenario: Corrupt store refuses startup
- **WHEN** the store file is unreadable or unparseable at startup
- **THEN** the gateway refuses to start with an operator-facing error naming the path; recovery renames the file aside, after which harnesses re-register on their next sign-in

#### Scenario: Lost store self-heals via re-registration
- **WHEN** the store is lost or reset while a harness holds a cached registered client id
- **THEN** the harness's next authorization request is rejected as unregistered, the harness re-registers and proceeds, and issued tokens keep working because they are self-contained

#### Scenario: Registration cap reached
- **WHEN** stored registrations reach the configured cap and a new registration arrives
- **THEN** the new registration is refused with a plain-language error naming the cap, and existing registrations are untouched

### Requirement: Authorization requests require a valid resource and allocate protected flow state

The RFC 8707 `resource` parameter MUST be the required toolset disambiguator on both the authorization and token endpoints: a missing or unknown resource MUST be rejected as `invalid_target`; the only escape is an explicit one-toolset operator setting. A valid request MUST create a flow record keyed by a 128-bit CSPRNG id with a bounded TTL — a guessable id lets an attacker pair their own upstream code with a victim's session. Flow state lives server-side; the browser carries only the flow id.

#### Scenario: Missing resource
- **WHEN** an authorization request omits the resource parameter and no one-toolset inference is enabled
- **THEN** the response is an OAuth error with code `invalid_target`

#### Scenario: Unknown resource
- **WHEN** the resource parameter names no mapped toolset's resource URI
- **THEN** the response is an OAuth error with code `invalid_target`

#### Scenario: Valid request allocates a flow
- **WHEN** a registered client sends a valid authorization request with PKCE and a known resource
- **THEN** the browser is redirected to the identity provider's authorization endpoint under the gateway's public PKCE client, and the flow record is keyed by an unguessable id

#### Scenario: One-toolset inference
- **WHEN** the operator enables resource inference and exactly one toolset is mapped
- **THEN** an authorization request without a resource parameter is accepted for that toolset

### Requirement: The federation flow establishes the upstream credential through Core

The flow MUST authenticate the user under the gateway's public PKCE client, requesting only its client's default scopes; a client's `scope` parameter is never relayed — a relayed scope can fail the leg. DIAL authorization is enforced by fetching the toolset settings as that user before any upstream round-trip; the upstream code goes to Core's credential API at USER level. The flow record MUST be destroyed on first use at the upstream callback; the provider's tokens are discarded at flow end.

#### Scenario: DIAL authorization denied
- **WHEN** the authenticated user cannot read the toolset's settings
- **THEN** the flow fails with a clear no-access page and no upstream round-trip happens

#### Scenario: Client scope never reaches the identity provider
- **WHEN** an authorization request carries a `scope` parameter naming scopes the gateway's identity-provider client does not carry
- **THEN** the identity-provider redirect requests only the gateway client's default scopes, and the leg completes

#### Scenario: Upstream consent completes
- **WHEN** the user approves the upstream consent
- **THEN** the gateway calls the credential API with the user's identity token, the upstream code, and the upstream callback URI at USER level, and Core stores the credential for that user

#### Scenario: Flow record destroyed on first use
- **WHEN** the upstream callback has been processed
- **THEN** the flow record is deleted, and a second callback with the same flow id receives a plain-language error page

#### Scenario: Guessed flow id injects nothing
- **WHEN** an attacker arrives at the upstream callback with their own upstream code and a flow id they guessed rather than received
- **THEN** the flow lookup fails and no credential is established for any user

### Requirement: The upstream authorization request arrives complete

The upstream authorization request MUST reach the upstream authorization endpoint carrying `response_type=code`, the registered `client_id`, the toolset's public `code_challenge` and `code_challenge_method`, the upstream `redirect_uri`, the flow id as `state`, and the toolset's advertised scopes. Delivery is normative as what the endpoint receives, not what the page contains: a mechanism whose browser step can drop parameters MUST NOT be used, and an undeliverable request MUST fail closed.

#### Scenario: Continuation delivers every parameter
- **WHEN** the user continues from the interstitial
- **THEN** the URL the browser navigates to carries `response_type=code`, the registered `client_id`, the toolset's public `code_challenge` and `code_challenge_method`, the upstream `redirect_uri`, the flow id as `state`, and the toolset's advertised scopes

#### Scenario: Undeliverable request fails closed
- **WHEN** the upstream authorization request cannot be delivered with every required parameter present
- **THEN** the flow fails with the plain-language error page and no parameter-less request reaches the upstream endpoint

### Requirement: HTML responses carry the web-hardening header family

Every HTML response the gateway serves — the interstitial and every plain-language error or flow page — MUST carry `Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'` with script execution excluded (the interstitial is script-free; inline style may use a nonce, hash, or `'unsafe-inline'`), `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Type naming `charset=utf-8`.

#### Scenario: The interstitial carries the hardening headers
- **WHEN** the interstitial is served
- **THEN** its response carries the Content-Security-Policy with no source permitting script, `base-uri 'none'`, `frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Type naming `charset=utf-8`

#### Scenario: An error or flow page carries them
- **WHEN** any plain-language error or flow page is served
- **THEN** its response carries the same header set

### Requirement: Issued tokens are gateway-signed and audience-marked

The gateway MUST mint RS256 JWTs whose issuer is the public origin and whose `sub` is copied from the identity token of the live-authenticated user. The audience MUST contain the toolset's resource and the marker configured on the gateway's identity-provider entry in Core, so a token that lacks the marker is rejected. Access tokens MUST be short-lived; refresh tokens carry `typ=refresh`. The authorization code MUST be single-use, PKCE-bound, short-lived, with replay rejected.

#### Scenario: Code exchange issues tokens
- **WHEN** the harness exchanges its authorization code with the correct PKCE verifier and resource
- **THEN** an access token and a refresh token are issued, both signed by the gateway and carrying the user's `sub`

#### Scenario: Token carries the marker audience
- **WHEN** an issued access token is validated by Core
- **THEN** its audience contains both the toolset's resource and the configured marker, and Core accepts it through the gateway's identity-provider entry

#### Scenario: Code replay rejected
- **WHEN** the same authorization code is presented twice
- **THEN** the second exchange is rejected

### Requirement: Claim copy preserves deployment claim paths

Minted tokens MUST carry the identity token's claims verbatim except the registry claims the gateway owns, so deployment claim paths and telemetry work without per-claim config. Roles MUST additionally be read at a required, operator-configured source path and re-emitted as a plain array where Core's provider entry reads them. Issuance MUST fail loudly when that path is absent from the identity token — a silent role-less token produces undiagnosable 403s; an empty value is legitimate user state.

#### Scenario: Claims copied verbatim
- **WHEN** a token is minted from an identity token carrying deployment claims such as roles, project, or email
- **THEN** the minted token carries those claims under the same names, plus the re-emitted roles array

#### Scenario: Roles source path absent
- **WHEN** the configured roles source path is absent from the identity token
- **THEN** issuance is refused with an operator-facing configuration error, and no token is minted

#### Scenario: Roles present but empty
- **WHEN** the configured roles source path resolves to an empty array
- **THEN** the minted token carries an empty roles array

### Requirement: Refresh and revocation stay local to the gateway

Refreshing MUST NOT contact the identity provider or the upstream: the refresh token carries a frozen claim snapshot and MUST match its issuance resource. Rotation MUST be default-on with a short grace window, and the rotated token MUST keep the original absolute expiry (non-sliding), bounding staleness by the refresh TTL, which MUST NOT exceed the identity provider's access-token lifespan — both are operator settings, validated at startup. Revocation denylists refresh-token ids until expiry.

#### Scenario: Silent refresh
- **WHEN** the access token expires and the harness refreshes with the correct resource
- **THEN** a fresh access token is issued with no browser interaction and no identity-provider or upstream call

#### Scenario: Resource mismatch on refresh
- **WHEN** a refresh request carries a resource different from the one the refresh token was minted for
- **THEN** the response is `invalid_grant`

#### Scenario: Non-sliding refresh window
- **WHEN** a refresh token is rotated near the end of its life
- **THEN** the replacement carries the original absolute expiry, not a renewed window

#### Scenario: Refresh TTL exceeds the provider lifespan
- **WHEN** the configured refresh TTL exceeds the configured identity-provider access-token lifespan
- **THEN** the gateway refuses to start with an operator-facing error naming both values

#### Scenario: Revoked refresh token
- **WHEN** a revoked refresh-token id is presented
- **THEN** the response is `invalid_grant`

#### Scenario: Expired refresh token
- **WHEN** a refresh token's absolute expiry has passed
- **THEN** the harness receives `invalid_grant` and must re-run the sign-in flow

### Requirement: Sign-in status is queryable without a tool call

With a gateway access token, a client MUST be able to query a mapped toolset's public authentication statuses as that user, distinguishing signed-in from not-signed-in, so the failure states of the toolset MCP path are diagnosable outside the 401.

#### Scenario: Signed in
- **WHEN** the user holds a stored upstream credential for the toolset and queries status with a gateway token
- **THEN** the response reports signed-in at user level

#### Scenario: Not signed in
- **WHEN** the user holds no stored upstream credential and queries status with a gateway token
- **THEN** the response reports not signed-in at user level

### Requirement: Public endpoints are bounded against abuse

Unauthenticated endpoints that allocate state MUST be rate-limited per source and globally; live flow records MUST be capped with oldest-first eviction. Every unauthenticated body-bearing endpoint MUST cap the request body in bytes at reading; over-cap is refused. Expired, evicted, and unknown flows MUST land on a plain-language re-run page, never an opaque failure. The mid-flow identity token is exposed at most min(flow TTL, its own expiry) — the TTL bounds retention, not the token's life.

#### Scenario: Flooding rate-limited
- **WHEN** authorization requests arrive from one source beyond the configured per-source limit, or overall beyond the global limit
- **THEN** excess requests are rejected without allocating flow records

#### Scenario: Flow cap eviction
- **WHEN** live flow records reach the configured cap
- **THEN** the oldest records are evicted and their browsers receive the plain-language error page

#### Scenario: Plain-language error page
- **WHEN** a browser lands on a gateway callback with an unknown or expired flow
- **THEN** it receives an HTML page in plain language saying the sign-in session expired and to re-run the sign-in from the harness

#### Scenario: Oversize request body refused
- **WHEN** an unauthenticated body-bearing endpoint — `/dial/register`, `/dial/token`, or `/dial/revoke` — receives a request body over the configured byte cap
- **THEN** the body is refused at reading, and no byte past the cap is processed

### Requirement: Refusals before flow allocation are audited

Every refusal before a flow is allocated — `/dial/authorize` validation refusals, client resolution, `/dial/register`, `/dial/token`, `/dial/revoke` form refusals, `/dial/{name}/status`, discovery misses, and rate-limit 429s — MUST be recorded with a fixed-vocabulary reason and the non-credential facts (client id, redirect URI, resource, toolset), each fact truncated to the configured cap; a 429 record MUST carry the reason only; no credential or free-form caller input may reach the record.

#### Scenario: Pre-allocation refusal audited
- **WHEN** an authorization request is refused before any flow is allocated — an unknown client, an unregistered redirect URI, or a missing or unknown `resource`
- **THEN** exactly one audit record is written, carrying the refusal's fixed-vocabulary reason and the request's client id, redirect URI, and resource

#### Scenario: Injection attempt writes no free-form content
- **WHEN** a refused request carries values crafted to place content into the audit record
- **THEN** the record carries only the fixed vocabulary and the safe request facts — no free-form caller input reaches it

#### Scenario: Oversize fact lands truncated
- **WHEN** a refused request offers a fact longer than the configured cap
- **THEN** the record carries that fact truncated to the cap, never the full value

#### Scenario: Rate-limited refusal is recorded facts-free
- **WHEN** a request is refused by the volume limiter and answered 429
- **THEN** its record carries the fixed-vocabulary reason only, and no caller-supplied facts

### Requirement: The toolset mapping is safe to configure

The mapping MUST list OAuth toolsets only: a non-OAuth toolset MUST be refused at startup, because an OAuth challenge in front of a non-OAuth credential is an unsatisfiable 401 loop the static router cannot exempt an entry from. Toolset names MUST be refused at startup when the router's authorization-surface location would capture their MCP path first — the reserved names `authorize`, `token`, `register`, `revoke`, `callback`, `jwks.json` — because their MCP traffic could then never reach Core.

#### Scenario: Non-OAuth mapping refused
- **WHEN** the mapping lists a toolset whose public authentication type is not OAUTH
- **THEN** the gateway refuses to start with an operator-facing error naming the entry

#### Scenario: Reserved name refused
- **WHEN** the mapping lists a toolset named like a reserved front-door path segment
- **THEN** the gateway refuses to start with an operator-facing error naming the reserved names

### Requirement: Core trusts gateway tokens through a dedicated identity-provider entry

Core MUST be configured with the gateway as an additional identity provider: a JWKS URL, an issuer pattern matching the public origin, a role path, the audience marker, and the same obfuscated-logging key and salt as the deployment's primary provider entry. Every provider entry MUST carry an issuer pattern in a multi-provider Core, because provider selection is by issuer match. Core's own discovery surface and direct identity-provider clients keep working alongside the gateway front door.

#### Scenario: Token without the marker rejected
- **WHEN** Core receives a gateway-issuer token whose audience lacks the configured marker
- **THEN** Core rejects it

#### Scenario: Primary-provider tokens keep validating
- **WHEN** a client presents a token from the deployment's primary identity provider after the gateway entry is added
- **THEN** Core still resolves its identity, because every provider entry carries an issuer pattern

#### Scenario: Gateway-leg logins appear in obfuscated user logging
- **WHEN** a user signs in through the gateway and calls Core with a gateway-minted token
- **THEN** Core's obfuscated user logging resolves the same user hash as primary-provider logins, because the logging key and salt are mirrored

#### Scenario: Direct-to-Core client coexists
- **WHEN** a client holding a primary-provider token calls Core's own toolset path while the gateway front door is live
- **THEN** the call succeeds unchanged

### Requirement: Credential-model security invariants are preserved

Upstream access and refresh tokens MUST never be delivered to or stored by any client or the gateway; only the single-use, PKCE-bound upstream code transits. Credential establishment MUST be at USER level. DIAL authorization MUST apply on every toolset call, including with gateway-minted tokens. No credential, token, key, or password may appear in logs, command lines, errors, or the repository; failures fail closed. The signing key is IdP-grade: never committed, never logged, rotatable.

#### Scenario: Data path resolves only the token user's credential
- **WHEN** a toolset call arrives with a gateway-minted token for a user
- **THEN** Core resolves and injects that user's stored upstream credential only, and no other user's credential is reachable

#### Scenario: GLOBAL-level establishment refused
- **WHEN** the federation flow attempts to establish a credential at GLOBAL level
- **THEN** it is refused; GLOBAL stays an operator action

#### Scenario: No secrets in logs and errors
- **WHEN** the gateway logs a flow or renders an error page
- **THEN** the output carries no token, code, key, or password material, and identifiers are flow ids and subjects only

#### Scenario: Public toolset settings expose no verifier
- **WHEN** the gateway reads a toolset's public settings during a flow
- **THEN** the public projection carries the code challenge but no code verifier or client secret

### Requirement: End-to-end acceptance on a real harness gates completion

Before this change is done, the assembled chain MUST pass five criteria on a real harness: (a) first use end to end via CIMD and `resource`; (b) silent repeat use and refresh with rotation on; (c) mid-session upstream-credential removal takes the sign-in-again branch, not a 401 loop, and the harness keeps its token; (d) query strings survive the front routing; (e) a direct-to-Core client coexists. Failure of any criterion falsifies the design and MUST reopen it, not be patched around.

#### Scenario: First use end to end
- **WHEN** a real harness is pointed at the front-door toolset path with no prior sign-in
- **THEN** it completes discovery, CIMD registration, the federation flow, and token exchange, and a live tool call through the front door succeeds with a gateway-signed, copied-sub token

#### Scenario: Silent repeat use and refresh with rotation
- **WHEN** the signed-in harness makes further tool calls and its access token expires
- **THEN** repeat calls are silent with no browser, and refresh-on-401 with rotation on is observed and recorded, including whether the harness adopts the rotated token

#### Scenario: Mid-session upstream removal
- **WHEN** the stored upstream credential is removed mid-session through the ops API
- **THEN** the harness's next call leads to the sign-in-again branch, not a 401 loop, and the harness keeps its gateway token

#### Scenario: Query strings survive the front routing
- **WHEN** a streamable-HTTP GET with a session parameter crosses the front door
- **THEN** Core receives the parameter unchanged

#### Scenario: Direct-to-Core coexistence
- **WHEN** a direct-to-Core client with a primary-provider token exercises Core's own toolset path while the front door is live
- **THEN** it keeps working unchanged
