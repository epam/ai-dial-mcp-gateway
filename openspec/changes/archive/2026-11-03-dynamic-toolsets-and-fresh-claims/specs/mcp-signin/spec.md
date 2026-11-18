# Spec Delta

## MODIFIED Requirements

### Requirement: Discovery documents describe one flat authorization server

The gateway MUST serve one RFC 8414 AS metadata document at the host root for a single path-less issuer — the public origin — and one RFC 9728 protected-resource document per served toolset. A toolset is served when its name passes the request-time name guard (routed-path charset, reserved front-door names) and is not excluded by the operator restriction when one is configured — and nothing else decides it on this surface: the document is served for every guard-passing, restriction-admitted name, whether or not Core's registry holds it. The gateway's unauthenticated discovery tier is registry-independent by design, mirroring Core's own: Core's MCP path answers an unauthenticated call — for a toolset that exists or one that does not — with 401 and a challenge naming the protected-resource document, because the auth check precedes any registry lookup (a fact of the enabled route — Core's `toolsets.security.authorizationServers` configuration is what serves it; unset, the 401 carries no challenge, and a challenge-less 401 is no existence oracle either), and Core's own unauthenticated protected-resource route answers any well-formed name with a static document built from configuration with the requested path echoed as `resource` (likewise a fact of the enabled route — the same configuration; unset, the route answers 404, which is no existence oracle either, and the gateway serves its own document regardless); no unauthenticated tier on either side of the front door carries an existence oracle, in either configuration. The mirror property is normative: the gateway's tier brings nothing Core's own does not — the same 401-challenge on the data path, the same echo-document at discovery, and existence decided at the same moment, post-authentication, at the flow's per-user settings read (whose refusal for a name Core does not know is the federation requirement's unknown-toolset scenario, the system's only existence refusal). Discovery therefore makes no Core call at all: no consult, no service credential, no cache, and no Core-unavailable failure shape — the protected-resource document costs the gateway one static document, and its availability is the gateway's own. The AS metadata MUST advertise both grants, S256, token-endpoint auth method `none`, and client-ID-metadata-document support, so CIMD-capable clients register with no registration call; it is a static document and consults nothing. Each protected-resource document MUST name the single AS issuer; its `scopes_supported` echoes the operator restriction's entry where the toolset is pinned there and is empty otherwise; its authentication-kind extension is omitted — under dynamic serving this surface has no authentication-kind source (the mapping's kind declaration is deleted, and the kind a flow acts on is Core's, read per flow at the authenticated settings read). The members are informational, and the scopes the upstream leg sends come from the toolset's Core settings; a client's faithfully echoed `scope` parameter is already accepted and dropped at the authorization endpoint, so an omitted member costs nothing on any leg.

#### Scenario: Flat AS metadata fetch
- **WHEN** a client fetches `GET /.well-known/oauth-authorization-server` on the public origin
- **THEN** the document's issuer is the public origin and its authorization and token endpoints are shared by all toolsets

#### Scenario: Per-toolset protected-resource fetch
- **WHEN** a client fetches the protected-resource document for a served toolset
- **THEN** the document returns the toolset's resource URI and the single AS issuer, with the authentication-kind extension omitted and `scopes_supported` echoing the operator restriction's entry where the toolset is pinned there and empty otherwise

#### Scenario: Unmapped toolset
- **WHEN** a client fetches the protected-resource document for a name the configured operator restriction excludes
- **THEN** the response is 404

#### Scenario: Dynamic toolset served without local configuration
- **WHEN** no operator restriction is configured and a client fetches the protected-resource document for a name that passes the request-time name guard
- **THEN** the document is served with the name-derived resource URI and the single AS issuer, with no gateway-side toolset configuration involved and no Core call made — whether Core's registry holds the name is not decided on this surface (the mirror property: the unauthenticated tier is registry-independent, and existence is decided post-authentication at the flow's settings read)

#### Scenario: Guard-failing name refused at discovery
- **WHEN** a client fetches the protected-resource document for a reserved front-door name or a name outside the routed-path charset
- **THEN** the response is 404, and one audit record carries the fixed-vocabulary reason with the offered name as a truncated non-credential fact

### Requirement: Authorization requests require a valid resource and allocate protected flow state

The RFC 8707 `resource` parameter MUST be the required toolset disambiguator on both the authorization and token endpoints: a missing resource, a resource whose toolset name fails the request-time name guard, or a resource that is not the resource URI of a toolset name the guard and the operator restriction (when one is configured) admit MUST be rejected as `invalid_target`. What this endpoint decides is the name's shape and its place in the operator restriction; whether a guard-passing, admitted name is actually served by Core is not decided here — no Core call is designed at this endpoint, and in dynamic mode a phantom name's resource URI is shape-identical to a served toolset's — so existence is decided one leg deeper, at the flow's per-user settings read, whose refusal for a name Core does not know is the flow requirement's unknown-toolset scenario (a plain-language page, no upstream round-trip). The only escape is an explicit one-toolset operator setting, which applies only while the operator restriction is configured with exactly one entry. A valid request MUST create a flow record keyed by a 128-bit CSPRNG id with a bounded TTL — a guessable id lets an attacker pair their own upstream code with a victim's session. Flow state lives server-side; the browser carries only the flow id.

*Scenario amendment, declared:* the retained "Unknown resource" scenario is re-scoped by this change — from the main spec's "names no mapped toolset's resource URI" to the resource-URI check the endpoint actually performs in dynamic mode against the request-time name guard and the operator restriction — because existence is undecidable at this endpoint without a Core call no surface at this stage is specified to make; the backstop that decides it (the flow's per-user settings read) keeps its own scenario in the flow requirement. No Core call is added to this endpoint.

#### Scenario: Missing resource
- **WHEN** an authorization request omits the resource parameter and no one-toolset inference is enabled
- **THEN** the response is an OAuth error with code `invalid_target`

#### Scenario: Unknown resource
- **WHEN** the resource parameter is not the resource URI of a toolset name the request-time name guard and the operator restriction, when one is configured, admit
- **THEN** the response is an OAuth error with code `invalid_target` — the endpoint has decided the name's shape and its place in the restriction; a guard-passing admitted name that Core does not know is refused later, at the flow's settings read, under that surface's own scenario

#### Scenario: Valid request allocates a flow
- **WHEN** a registered client sends a valid authorization request with PKCE and a known resource
- **THEN** the browser is redirected to the identity provider's authorization endpoint under the gateway's public PKCE client, and the flow record is keyed by an unguessable id

#### Scenario: One-toolset inference
- **WHEN** the operator enables resource inference and the operator restriction is configured with exactly one entry
- **THEN** an authorization request without a resource parameter is accepted for that toolset

#### Scenario: Guard-failing resource refused
- **WHEN** the resource parameter names a toolset name that fails the request-time name guard — a reserved front-door name or a name outside the routed-path charset
- **THEN** the response is an OAuth error with code `invalid_target`, and one audit record carries the fixed-vocabulary reason with the offered resource as a truncated non-credential fact

### Requirement: The federation flow establishes the upstream credential through Core

The flow MUST authenticate the user under the gateway's public PKCE client, requesting only its client's default scopes; a client's `scope` parameter is never relayed — a relayed scope can fail the leg. This identity leg runs for every served toolset regardless of authentication kind: it establishes who is signing in, never what kind of credential the toolset uses. DIAL authorization is enforced by fetching the toolset settings as that user before any upstream round-trip; the upstream code goes to Core's credential API at USER level. The settings read itself fails closed on a Core answer that is unreachable or unreadable — the flow fails with the operator-facing fault page, a deployment fault and never an existence answer, rendered as a page distinct from the not-registered page the unknown-toolset scenario carries — and a projection whose authentication-kind value is absent or unusable falls into the impossible branch the same way a non-OAuth kind does: no unreadable answer is ever taken for a not-registered name, and no unreadable kind for a consentable one. That same settings read carries the toolset's public authentication type and the caller's per-toolset statuses, and the flow's stages after it are, in order: **the signed-in check** — when Core reports the caller signed in at user level, or the toolset signed in at global level, the upstream stage is skipped entirely and the flow finishes by minting the harness's code, regardless of authentication kind, because a stored credential already exists and no consent could add anything; a status that is absent, unreadable, or FAILED is not signed in, and the check fails closed into the kind branch; then **the kind branch** — the upstream consent stage runs only when no credential is stored and the toolset's kind makes one establishable by consent: an OAUTH toolset continues through the upstream consent exactly as designed (its public OAuth settings — client id, endpoints, challenge, callback — are required on this branch and only this branch), and a toolset of any other kind is refused with a plain-language page saying its credential is configured directly in DIAL and cannot be established by a consent flow — audited, fail-closed, no upstream round-trip; the refusal loops benignly, like any auth error, until an administrator stores the credential out of band, after which the same flow short-circuits. The flow never establishes a credential at GLOBAL level — the credential call stays at USER level on every path that establishes one — and it never reads or transits any stored upstream credential on any path, the short-circuit included: Core injects the stored credential on the data path, and a GLOBAL credential the short-circuit uses is one an operator configured — the flow uses it, it does not establish it, which is the same access that user already holds through Core's own paths with a primary-provider token. The flow record MUST be destroyed on first use at the upstream callback. The identity provider's session-bound refresh token — issued with the code exchange, with `offline_access` never requested, so no offline grant is ever acquired — is carried for the refresh window as an encrypted claim in the gateway's own refresh token: encrypted at the code grant under the gateway's dedicated custody key, decrypted at every refresh grant, re-encrypted into each rotated refresh token. The plaintext never travels in any client-visible artifact, and the encrypted claim rides the refresh token only — never the access token, never the authorization code. Between flow end and the code grant the token transits a server-side pending entry keyed by the authorization code's id; the provider's access token is discarded at flow end. A code exchange that issues no refresh token MUST fail the flow at sign-in with an operator-facing error naming the deployment prerequisite — the refresh claims re-read requires it, and failing at sign-in is loud and per flow where failing at the first refresh would be hours late. A provider refresh token larger than the configured custody size bound MUST fail the flow the same way, for the same reason: the carrier it must fit inside is a refresh token handed to a harness token store the gateway does not control. The custody size bound and the token-endpoint request-body cap are coupled operator settings and MUST move together: the cap MUST stay at or above the bound plus the envelope's expansion and the JWT overhead (cap ≥ bound + envelope expansion + JWT overhead), so every refresh body the bound lets a sign-in issue passes the cap — a bound raised past the cap's headroom would recreate by configuration the exact far-from-its-cause failure the loud sign-in refusal exists to prevent: sign-ins succeeding while every refresh fails over-cap.

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

#### Scenario: Non-OAuth toolset refused on the impossible branch
- **WHEN** the caller is not signed in at either level and the toolset's public authentication type is not OAUTH
- **THEN** the flow fails with a plain-language page saying the toolset's credential is configured directly in DIAL and cannot be established by a consent flow, no upstream round-trip happens, and one audit record carries the fixed-vocabulary reason naming the toolset

#### Scenario: Already signed in short-circuits the consent
- **WHEN** the caller holds a stored user-level credential for the toolset and runs the sign-in
- **THEN** the flow completes with no upstream round-trip and no consent screen, and the issued tokens are the same shape a consented flow issues

#### Scenario: A global credential serves every user without consent
- **WHEN** an operator has stored a GLOBAL-level credential for the toolset and any authorized user runs the sign-in, whatever the toolset's authentication kind
- **THEN** the signed-in check short-circuits the upstream stage, the flow establishes no credential itself, and the minted token carries that user's own claims only — using the stored global credential is the access the operator granted, not a new one

#### Scenario: The signed-in check fails closed
- **WHEN** the settings answer carries no readable status at either level, or a FAILED status
- **THEN** the flow does not short-circuit: an OAUTH toolset continues to the upstream consent leg, and a toolset of any other kind is refused on the impossible branch — no token is minted on an unreadable status

#### Scenario: Unknown toolset refused at the flow's settings read
- **WHEN** the authenticated user's toolset settings read returns no toolset — Core does not know the offered name
- **THEN** the flow fails with a plain-language page, no upstream round-trip happens, and one audit record carries the fixed-vocabulary reason (`unknown_toolset`) naming the toolset — and this read is the system's only existence refusal: the unauthenticated discovery tier is registry-independent on both sides of the front door (the mirror property), so a phantom name's discovery document cost the harness one browser round-trip and this refusal is where the name is learned to be unserved; no flow state survives the refusal and no upstream leg can start from it

#### Scenario: The provider's session refresh token is carried past the flow for the refresh window
- **WHEN** a flow completes and tokens are issued
- **THEN** the provider's session refresh token is carried encrypted inside the issued refresh token under the refresh-window bound, no offline grant was ever requested, and the provider's access token is discarded at flow end

#### Scenario: Provider issues no refresh token
- **WHEN** the identity provider's code exchange returns no refresh token for the gateway's client
- **THEN** the flow fails at sign-in with an operator-facing error naming the deployment prerequisite, and no tokens are issued

#### Scenario: Provider refresh token over the custody size bound refused at sign-in
- **WHEN** the identity provider's code exchange returns a refresh token larger than the configured custody size bound
- **THEN** the flow fails at sign-in with an operator-facing error naming the bound, and no tokens are issued — the same loudness as the no-refresh-token refusal, at the same point in the flow

### Requirement: Issued tokens are gateway-signed and audience-marked

The gateway MUST mint RS256 JWTs whose issuer is the public origin and whose `sub` is the live-authenticated user's subject — established at issuance by the verified identity token, and at refresh by the fresh verified provider token whose subject MUST equal the gateway refresh token's own subject, so a minted token never carries a subject the identity provider did not just (re-)assert. The audience MUST contain the toolset's resource and the marker configured on the gateway's identity-provider entry in Core, so a token that lacks the marker is rejected. The refresh token's `aud` MUST carry the toolset's resource alone — the marker MUST NOT be included — so the refresh token is never a token Core's identity-provider entry accepts: the marker is what makes a gateway-issued token a Core-acceptable access token, and its absence on the refresh token is the token-type separation, load-bearing, not incidental. The separation is doubled under the custody design: the refresh token carries no copied claims at all — no roles claim — so even absent the marker check it authorizes nothing at Core's role-path matching. Access tokens MUST be short-lived; refresh tokens carry `typ=refresh`. The authorization code MUST be single-use, PKCE-bound, short-lived, with replay rejected.

#### Scenario: Code exchange issues tokens
- **WHEN** the harness exchanges its authorization code with the correct PKCE verifier and resource
- **THEN** an access token and a refresh token are issued, both signed by the gateway and carrying the user's `sub`

#### Scenario: Token carries the marker audience
- **WHEN** an issued access token is validated by Core
- **THEN** its audience contains both the toolset's resource and the configured marker, and Core accepts it through the gateway's identity-provider entry

#### Scenario: The refresh token is not a Core-acceptable token
- **WHEN** a gateway-issued refresh token is presented to Core's token validation shape — the signature, issuer, and audience-marker check Core's identity-provider entry applies to a presented token
- **THEN** the audience check refuses it, because the refresh token's `aud` is the toolset's resource alone with no marker — and the gateway's mint is pinned to that separation: the marker present on every access token, absent on every refresh token

#### Scenario: Code replay rejected
- **WHEN** the same authorization code is presented twice
- **THEN** the second exchange is rejected

### Requirement: Claim copy preserves deployment claim paths

Minted tokens MUST carry the verified provider token's claims verbatim except the registry claims the gateway owns, so deployment claim paths and telemetry work without per-claim config. The claim source is one vocabulary at both sites: the token the code exchange returns at issuance, and the fresh token the identity provider's refresh grant returns at refresh — read through the same verification path at both (the provider's published keys, the pinned issuer). Roles MUST additionally be read at a required, operator-configured source path and re-emitted as a plain array where Core's provider entry reads them. Issuance MUST fail loudly when that path is absent from the provider token — a silent role-less token produces undiagnosable 403s; an empty value is legitimate user state.

#### Scenario: Claims copied verbatim
- **WHEN** a token is minted from an identity token carrying deployment claims such as roles, project, or email
- **THEN** the minted token carries those claims under the same names, plus the re-emitted roles array

#### Scenario: Roles source path absent
- **WHEN** the configured roles source path is absent from the identity token
- **THEN** issuance is refused with an operator-facing configuration error, and no token is minted

#### Scenario: Roles present but empty
- **WHEN** the configured roles source path resolves to an empty array
- **THEN** the minted token carries an empty roles array

#### Scenario: Roles source path absent at refresh
- **WHEN** the configured roles source path is absent from the fresh token the refresh grant returns
- **THEN** the refresh is refused with `invalid_grant` and no token is minted — the same loudness as issuance, at the refresh site

### Requirement: Public endpoints are bounded against abuse

Unauthenticated endpoints that allocate state MUST be rate-limited per source and globally; live flow records MUST be capped with oldest-first eviction. Every unauthenticated body-bearing endpoint MUST cap the request body in bytes at reading; over-cap is refused. Expired, evicted, and unknown flows MUST land on a plain-language re-run page, never an opaque failure. The identity provider's session refresh token, while carried, is bounded by the refresh token's original absolute expiry, and its plaintext is presented exactly one refresh-grant call per gateway refresh — purposes named, not counted; the bounds govern the gateway's carrying of it, never the credential's usability, which is the provider's own session policy. The token's plaintext is never delivered to any client and never written to any log; the encrypted claim is delivered inside the refresh token by design and is unusable without the custody key. The identity access token's retention is unchanged by this design: it is exposed at most min(flow TTL, its own expiry) — the TTL bounds the gateway's retention, not the token's life — as before. The protected-resource discovery endpoint MUST join the same per-source and global rate limiter as every other unauthenticated surface, so its guard refusals — each of which writes an audit record — cannot be written faster than the requests that carry them: without the limiter, an unauthenticated caller looping guard-failing names would grow the operator's log at whatever rate it chose. Over the limit the endpoint MUST be answered with the limiter's 429 and MUST write no record at all, so the bound holds at the limit itself.

#### Scenario: Flooding rate-limited
- **WHEN** authorization requests arrive from one source beyond the configured per-source limit, or overall beyond the global limit
- **THEN** excess requests are rejected without allocating flow records

#### Scenario: Over-limit discovery requests are refused without a record
- **WHEN** protected-resource discovery requests arrive from one source beyond the configured per-source limit, or overall beyond the global limit
- **THEN** excess requests are answered with the limiter's 429 and write no audit record — the guard-refusal record volume is capped by the same limit as the request rate, and a refused request adds nothing to the trail

#### Scenario: Flow cap eviction
- **WHEN** live flow records reach the configured cap
- **THEN** the oldest records are evicted and their browsers receive the plain-language error page

#### Scenario: Plain-language error page
- **WHEN** a browser lands on a gateway callback with an unknown or expired flow
- **THEN** it receives an HTML page in plain language saying the sign-in session expired and to re-run the sign-in from the harness

#### Scenario: Oversize request body refused
- **WHEN** an unauthenticated body-bearing endpoint — `/dial/register`, `/dial/token`, or `/dial/revoke` — receives a request body over the configured byte cap
- **THEN** the body is refused at reading, and no byte past the cap is processed

### Requirement: Sign-in status is queryable without a tool call

With a gateway access token, a client MUST be able to query a served toolset's public authentication statuses as that user, distinguishing signed-in from not signed-in, so the failure states of the toolset MCP path are diagnosable outside the 401. The `signed_in` boolean answers the question a harness actually asks — will my next call work without a sign-in flow — and therefore reports signed-in when either level is: a stored user-level credential for this caller, or a stored global credential for the toolset; the raw per-level statuses are returned alongside it unchanged, so the two ways of being signed-in stay distinguishable.

#### Scenario: Signed in
- **WHEN** the user holds a stored upstream credential for the toolset and queries status with a gateway token
- **THEN** the response reports signed-in at user level

#### Scenario: Not signed in
- **WHEN** the user holds no stored upstream credential and queries status with a gateway token
- **THEN** the response reports not signed-in at user level

#### Scenario: Signed in through a global credential
- **WHEN** the toolset has a stored GLOBAL-level credential and the caller holds no user-level credential
- **THEN** the response reports the global status as signed-in and the boolean as signed-in, because the caller's next data-path call succeeds through the global credential

## REMOVED Requirements

### Requirement: The toolset mapping is safe to configure

**Reason:** The requirement's opening normative sentence — "The mapping MUST list OAuth toolsets only: a non-OAuth toolset MUST be refused at startup" — is exactly what the owner's ruling 1 deletes: under the re-taken flow a non-OAuth toolset is a valid entry, served through the signed-in short-circuit when Core holds a credential (user or global level) and refused on the impossible branch otherwise, so an operator-declared kind would be a second, staler source of a fact Core answers per flow. A requirement whose first sentence no longer holds is worse than none — the same rule that drove the refresh requirement's REMOVED+ADDED rewrite.

**Migration:** The replacement requirement, "The toolset mapping is an optional operator restriction", carries the retained scenarios byte-identically — "Reserved name refused" and "Name outside the routed charset refused" — and the behaviors the removed requirement also carried for the dynamic mode (the unset mapping, the inference contradiction). One scenario is dropped deliberately, declared here: "Non-OAuth mapping refused" — the startup refusal it pinned is deleted together with the mapping's `authentication_type` member, and its replacement behavior is carried by the new "Non-OAuth entry accepted" scenario. Every conformance row written against the removed requirement maps onto the replacement unchanged except the dropped one, whose row is retired with the behavior.

### Requirement: Refresh and revocation stay local to the gateway

**Reason:** The requirement's normative core — refreshing contacts neither the identity provider nor the upstream — is exactly what this change alters: every refresh now performs one identity-provider call, the refresh grant whose fresh verified token the mint reads, collapsing role staleness to the access TTL and propagating identity-provider session revocation to the gateway's refresh capability at the next refresh attempt. A requirement whose title and first sentence no longer hold is worse than none. The behaviors it also carried (rotation, the non-sliding window, the startup refresh-TTL bound, the resource match, the revocation denylist) are unchanged and move whole into the replacement requirement.

**Migration:** The replacement requirement, "Refresh re-reads current claims from the identity provider", carries the unchanged scenarios byte-identically — non-sliding window, revoked and expired refresh tokens. Three scenarios are amended, each a declared semantics-carrying amendment: Silent refresh now names the identity-provider read it performs. Resource mismatch on refresh is corrected from `invalid_grant` to `invalid_target`: the code and its test already answer `invalid_target` (`gateway/token.py:359-362`, `tests/test_tokens.py:447-457`), matching the code grant's resource-mismatch analogue (`gateway/token.py:289-291`), so the removed requirement's scenario was wrong against the verified behavior and this rewrite is the reconciliation. Refresh TTL exceeds the provider lifespan is re-derived onto the renamed operator-declared identity-provider session bound (`IDP_SSO_SESSION_MAX_SECONDS`), because under the refresh-grant mechanism the provider's access-token lifespan no longer bounds anything the gateway does — the grant mints fresh access tokens. New scenarios cover the claim change, the claims-read failure, the session-ended refusal, the subject mismatch, and the custody-claim refusal. Every conformance row written against the removed requirement maps onto the replacement unchanged except those three.

## ADDED Requirements

### Requirement: The toolset mapping is an optional operator restriction

The mapping is an optional operator restriction: unset, the gateway serves every platform toolset whose name passes the request-time name guard; set, only its entries are served. Configured entries keep the startup refusals that protect static routing — a reserved front-door name and a name outside the routed-path charset each refuse the container's start with an operator-facing error naming the entry — because the front router's locations are static configuration with no view of what Core serves, so neither can be repaired at request time for a name the operator pinned. The OAuth-only declaration check is removed with its reason: a restriction entry declares no authentication kind at all (the `authentication_type` member is removed from the mapping's schema — the kind a flow acts on is Core's, read per flow), and a non-OAuth toolset is a valid entry, because the flow now serves it through the signed-in short-circuit when a credential is stored and refuses it on the impossible branch otherwise. Resource inference MUST refuse to start when it is enabled without a restriction configured with exactly one entry: with a dynamic served set there is no "the one toolset" to infer, and inferring silently is how a token ends up addressed to a toolset the client never named.

#### Scenario: Reserved name refused
- **WHEN** the mapping lists a toolset named like a reserved front-door path segment
- **THEN** the gateway refuses to start with an operator-facing error naming the reserved names

#### Scenario: Name outside the routed charset refused
- **WHEN** the mapping lists a toolset whose name carries a character outside `[a-z0-9-]` — an upper-case letter, underscore, space, slash, or dot
- **THEN** the gateway refuses to start with an operator-facing error naming the charset, so a name the router's locations could never route fails at configuration time, not in operation

#### Scenario: Non-OAuth entry accepted
- **WHEN** the restriction lists a toolset whose Core authentication type is not OAUTH
- **THEN** the entry is accepted: its kind is Core's to answer per flow, and the flow serves it through the short-circuit when a credential is stored — the entry carries no kind declaration of its own

#### Scenario: Removed mapping member refused at parse
- **WHEN** an operator's mapping document still carries the removed `authentication_type` member
- **THEN** the gateway refuses to start with an operator-facing error naming the field — the mapping's schema forbids unknown members, so the one breaking operator change fails loudly at parse rather than the removed kind declaration being silently ignored

#### Scenario: Unset mapping serves dynamically
- **WHEN** no mapping is configured
- **THEN** the gateway starts, and toolsets are served whose names pass the request-time name guard — the documents are registry-independent (the mirror property), and the toolsets a harness can actually use are the ones Core's registry holds, learned at the flow's authenticated settings read

#### Scenario: Inference without a single-entry restriction refused
- **WHEN** resource inference is enabled and no restriction is configured, or the configured restriction does not have exactly one entry
- **THEN** the gateway refuses to start with an operator-facing error naming the setting and what it requires

### Requirement: Refresh re-reads current claims from the identity provider

Refreshing MUST re-read the user's current claims before minting: the gateway presents the identity provider's session-bound refresh token — carried, encrypted, in the gateway's own refresh token — to the provider's token endpoint (RFC 6749 §6, the refresh grant), and the minted access token's claims are the verified fresh token's, under the same copy and overlay rules as issuance and through the same verification path (the provider's published keys, the pinned issuer). The mechanism carries two deployment requirements, each failing loudly where unmet: the identity provider MUST issue refresh tokens to the gateway's client at the code exchange (a provider that does not fails every sign-in with an operator-facing error naming the prerequisite), and the provider's session-bound refresh token MUST remain usable across the refresh window under the provider's session policy — an operator prerequisite stated by the startup bound below, never silently assumed. The fresh token's `sub` MUST equal the refresh token's subject, or no token is minted; its parsing is bounded and fails closed. The gateway's refresh token MUST NOT carry a claim snapshot — the verified fresh read is the mint's only claim input, so a frozen-snapshot fallback has no data to serve and MUST NOT be reintroduced; the token's one non-binding payload member is the encrypted custody claim, which is ciphertext, never a mint input. Any failure of the read — the provider unreachable, the provider refusing the grant, the answer unusable, a subject mismatch, the roles source path absent, or the carried credential absent or undecryptable — MUST refuse the refresh with `invalid_grant`, and the refusal MUST be audited with a fixed-vocabulary reason distinct from every other `invalid_grant` refusal: a session-ended reason keyed on the provider's `invalid_grant` refusal specifically (RFC 6749 §6's session-gone code — the session is gone: revoked, expired by session policy, or consumed by a lost rotation), a claims-read reason for every other failure of the read, other provider 4xx refusals included (`invalid_client` from a misconfigured client secret or `invalid_request` from a gateway bug say nothing about the session), and a custody reason of its own for the decrypt-side failures — the claim absent, tampered, encrypted under an unknown key-id or version, expired as an envelope, or bound to another subject — so a provider outage, a session-policy break, a misconfiguration burst, and a custody-key or rotation fault are each distinguishable on the audit trail from mass token revocation. An identity-provider session revocation therefore ends the gateway's refresh capability at the next refresh attempt — the carried session refresh token dies with the session. Refreshing MUST NOT contact the upstream. Rotation MUST be default-on with a short grace window, and the rotated token MUST keep the original absolute expiry (non-sliding); where the provider rotates its own refresh token, the carried credential MUST track the latest, re-encrypted into each rotated gateway refresh token. The refresh TTL MUST NOT exceed the operator-declared identity-provider session bound — operator settings, validated at startup, because the carried session refresh token must remain usable at every refresh in the window; the declared value is an operator assertion about the provider's session policy, and where that policy is short, the short window is the correct configuration. Revocation denylists refresh-token ids until expiry. A refresh MUST match its issuance resource.

#### Scenario: Silent refresh
- **WHEN** the access token expires and the harness refreshes with the correct resource
- **THEN** a fresh access token is issued with no browser interaction and no upstream call, its claims read from the fresh verified token the identity provider's refresh grant returned

#### Scenario: Resource mismatch on refresh
- **WHEN** a refresh request carries a resource different from the one the refresh token was minted for
- **THEN** the response is `invalid_target`

#### Scenario: Non-sliding refresh window
- **WHEN** a refresh token is rotated near the end of its life
- **THEN** the replacement carries the original absolute expiry, not a renewed window

#### Scenario: Refresh TTL exceeds the declared identity-provider session bound
- **WHEN** the configured refresh TTL exceeds the operator-declared identity-provider session bound
- **THEN** the gateway refuses to start with an operator-facing error naming both values

#### Scenario: Revoked refresh token
- **WHEN** a revoked refresh-token id is presented
- **THEN** the response is `invalid_grant`

#### Scenario: Expired refresh token
- **WHEN** a refresh token's absolute expiry has passed
- **THEN** the harness receives `invalid_grant` and must re-run the sign-in flow

#### Scenario: Claim change reflected within the access TTL
- **WHEN** the user's roles change at the identity provider and the harness refreshes after the change
- **THEN** the minted access token carries the changed roles, so a role revoked at the provider is gone from minted tokens within the access TTL

#### Scenario: Claims-read failure refuses the refresh
- **WHEN** the identity provider cannot be reached at a refresh, or its answer cannot be verified, or the roles source path is absent from the fresh token, or it refuses the grant with an error other than `invalid_grant`
- **THEN** the refresh is refused with `invalid_grant` and the harness must re-run the sign-in flow — no stale-snapshot token is minted, and one audit record carries the fixed-vocabulary claims-read reason, distinct from an ordinary `invalid_grant` refusal

#### Scenario: Identity-provider session revocation ends the refresh capability
- **WHEN** the user's identity-provider session is revoked or expires under the provider's session policy, and the harness refreshes afterwards
- **THEN** the provider refuses the grant with `invalid_grant`, the refresh is refused with `invalid_grant`, the carried session refresh token is dead with the session, and one audit record carries the fixed-vocabulary session-ended reason, distinct from an ordinary `invalid_grant` refusal

#### Scenario: Fresh-token subject mismatch refuses the refresh
- **WHEN** the fresh token the refresh grant returns carries a `sub` different from the refresh token's subject
- **THEN** the refresh is refused with `invalid_grant` and no token is minted

#### Scenario: Custody claim absent or undecryptable refuses the refresh
- **WHEN** a presented refresh token's custody claim is absent, tampered, encrypted under an unknown key-id or version, expired as an envelope, or embeds a subject different from the refresh token's own
- **THEN** the refresh is refused with `invalid_grant`, no plaintext is decrypted to any output, and one audit record carries the fixed-vocabulary custody reason, distinct from the claims-read and session-ended reasons — a custody-key or rotation fault never reads as a provider event

### Requirement: Toolset names are guarded at request time

Every toolset name the gateway resolves — the protected-resource document's path, the authorization request's `resource`, the status endpoint's path, and the refresh grant's resource — MUST pass one guard before it names a served toolset: the routed-path charset (lower-case letters, digits, and hyphen, `[a-z0-9-]`) and the reserved front-door names (`authorize`, `token`, `register`, `revoke`, `callback`, `jwks.json`), because the router's locations are written against exactly that shape and a name outside it has no location that routes it. When an operator restriction is configured, a name it excludes MUST fail the same way. Guard failures fail closed with the response shape the surface already answers — 404 at the protected-resource document and the status endpoint, `invalid_target` at the authorization and token endpoints — and each refusal lands on the audit trail with a fixed-vocabulary reason and the offered name as a truncated non-credential fact, never free-form caller input.

#### Scenario: Reserved name refused at discovery
- **WHEN** a client fetches the protected-resource document for a reserved front-door name
- **THEN** the response is 404 and one audit record carries the fixed-vocabulary reason with the offered name

#### Scenario: Charset violation refused at the authorization endpoint
- **WHEN** an authorization request's `resource` names a toolset name carrying a character outside `[a-z0-9-]`
- **THEN** the response is an OAuth error with code `invalid_target`, and one audit record carries the fixed-vocabulary reason

#### Scenario: Restriction-excluded name refused like an unknown one
- **WHEN** an operator restriction is configured and a request names a toolset outside it
- **THEN** the refusal is the same one an unknown toolset name receives on that surface, and the audit record distinguishes only by its fixed-vocabulary reason

#### Scenario: A valid dynamic name resolves with no local configuration
- **WHEN** no operator restriction is configured and a discovery or authorization request names a charset-valid, non-reserved toolset name
- **THEN** the name is served on that surface exactly as a configured one is, with no gateway-side toolset configuration involved — whether Core's registry holds the name is never decided on an unauthenticated surface (the discovery tier is registry-independent by the mirror property) and is decided by the flow's authenticated settings read, never by local configuration

### Requirement: The identity provider's session refresh token is carried encrypted in the gateway's refresh token

The identity provider's session-bound refresh token MUST be carried for the refresh window as an encrypted claim inside the gateway's own refresh token, and `offline_access` MUST NOT be requested on any leg — no offline (beyond-session) grant is ever acquired; what is carried is a rotating handle to the user's live identity-provider session, and the gateway's refresh capability ends when that session ends. There is no long-lived per-session server-side store. The carrier is the refresh token only: the encrypted claim MUST NOT appear in the access token — which rides the Authorization header of every MCP data-path call and is not even reliably presented at a refresh — nor in the authorization code or any other client-visible artifact. The envelope is pinned: AES-256-GCM under a 256-bit key with a 96-bit random nonce, laid out as version | key-id | nonce | ciphertext‖tag, base64url-encoded; the algorithm and the lengths are code constants, never read from the envelope, and an envelope whose version or key-id is unknown fails closed. The envelope embeds its own `sub` and `exp`, and both are checked at the custody seam before any use: the embedded `sub` MUST equal the refresh token's signed subject — a blob swapped between users' tokens refuses — and an expired envelope refuses. The key is a dedicated 256-bit symmetric key in its own settings slot, separated from the signing key, identified by key-id; the keyset's startup validation refuses an empty keyset, a multi-active keyset, and any key that is not exactly 32 bytes — AES-GCM's algorithm follows the key's length, so a shorter key would silently run AES-128 or AES-192 and falsify the pinned algorithm; its rotation is a hard cut — a superseded key is never retained to accept, so every outstanding refresh token fails closed at its next presentation after a rotation, a wave bounded by the refresh token's non-sliding absolute expiry. Between flow end and the code grant the token lives in a pending entry keyed by the authorization code's id — created when the code is minted at flow end, on both flow paths, bounded by the code's own short TTL, consumed when the code grant issues a refresh token, and dropped when the code expires unredeemed; the token MUST NOT be carried in the authorization code's payload or any other client-visible artifact, in plaintext or as ciphertext, because the code is a signed-but-unencrypted JWT whose payload anyone holding the code string can read, and this token is mintable credential material. At the code grant the provider token is encrypted into the issued refresh token; at every refresh the grant decrypts it, presents it to the provider, and re-encrypts the provider's latest token — latest-wins across the provider's own rotations — into the newly rotated refresh token; a grace-window presentation of a pre-rotation token carries its own stale blob and fails at the provider where the provider rotates per grant. The token's plaintext MUST NOT be logged and MUST NOT be delivered to any client; the ciphertext is delivered inside the refresh token by design and is unusable without the custody key. The identity provider's access token is not retained past the flow: it serves the flow's decision step and credential call and is discarded at flow end. A restart loses nothing the harness does not bring back: the encrypted claim returns with the presented refresh token, so refresh capability survives restarts and rollouts, and already-minted access and refresh tokens keep working until their own expiries because they are self-contained — while the minutes-bounded pending entries are lost, so an unredeemed code issued before the restart fails its grant the same fail-closed way.

#### Scenario: The carried credential ends with the refresh session
- **WHEN** a refresh token expires or is revoked
- **THEN** the gateway never presents its carried credential again — expiry refuses the token, and revocation refuses by id before the claim is ever touched — and the ciphertext that persists in the harness's store is inert without the custody key and dies with the provider's session

#### Scenario: The hand-off never crosses the client
- **WHEN** a flow completes and the authorization code is issued to the harness
- **THEN** the code's payload carries no identity-provider credential of any kind, plaintext or ciphertext, and the provider's session refresh token exists only in the server-side pending entry keyed by the code's id until the code grant consumes it

#### Scenario: The carrier is the refresh token only
- **WHEN** the code grant issues tokens
- **THEN** the encrypted custody claim appears in the refresh token and in no other issued artifact — not the access token, not the authorization code

#### Scenario: Rotation carries the custody, in both directions
- **WHEN** a refresh rotates and the replacement token is issued, and the provider's refresh grant returned a new refresh token of its own
- **THEN** the replacement carries the provider's latest refresh token re-encrypted under the current custody key, and the replaced token's blob is not accepted outside the grace window

#### Scenario: A grace-window presentation carries its own stale blob
- **WHEN** a client presents a pre-rotation refresh token inside the grace window, and the provider rotates its refresh token per grant
- **THEN** the presentation fails at the provider — the token's own carried blob is stale, each token is self-consistent, and the failure lands in the session-ended refusal class

#### Scenario: Custody-key rotation is a hard cut
- **WHEN** the custody key is rotated and outstanding refresh tokens carrying claims encrypted under the superseded key are presented
- **THEN** each refuses fail-closed with the custody reason at its next presentation, and the re-sign-in wave is bounded by the refresh token's original absolute expiry

#### Scenario: The plaintext is never logged or delivered; the ciphertext never logged
- **WHEN** the gateway carries the provider's session refresh token
- **THEN** no log record or stored file carries the plaintext, no client response carries the plaintext, the ciphertext never reaches a log record, and the ciphertext appears only inside the refresh token delivered to its presenting client

#### Scenario: No offline grant is ever requested
- **WHEN** the gateway's client requests its scopes on the identity-provider leg
- **THEN** `offline_access` is never among them, and no offline token is ever issued to the flow

#### Scenario: Restart survives the custody, not the pending entries
- **WHEN** the gateway restarts with refresh sessions live
- **THEN** already-issued refresh tokens keep refreshing — the encrypted claim returns with the presented token — already-minted access tokens keep working, and an unredeemed authorization code issued before the restart fails its grant fail-closed
