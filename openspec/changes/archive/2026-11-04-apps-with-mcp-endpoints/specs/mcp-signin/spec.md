# Spec Delta

## ADDED Requirements

### Requirement: App MCP resources are served through the apps front-door path

App resources are served at their own front-door path shape, `/apps/{name}/mcp`, proxied to Core's deployments MCP path, because the kind lives in the path: one flat authorization server serves two resource kinds, and the path shape is what keeps a toolset and an app that share a name from ever colliding — the toolset registry and the apps registry are disjoint namespaces in Core, and the front door routes by kind, not by registry lookup. Every 401 on the apps MCP path — no token, or an invalid or expired token — MUST be answered with the gateway's own challenge: 401 plus `WWW-Authenticate` naming the gateway's protected-resource document for that app, at `/.well-known/oauth-protected-resource/apps/{name}/mcp`; the challenge Core synthesizes MUST never reach the client, for the same reason as the toolset path: it names a document whose resource vocabulary the client cannot act on through the front door. The refusal shapes beyond the 401 keep their own answers, and neither carries the challenge: an access denial — a valid token whose user cannot pass Core's per-call authorization — is answered by Core's own 403, and an unknown app by a 404, both crossing the router untouched because the challenge synthesis fires on 401 only; neither is a sign-in cause, and a harness reads each directly off the failed call. Query parameters MUST survive the apps routing, because streamable-HTTP sessions resume through them identically on this path.

Every app name the gateway resolves — the apps protected-resource document's path, the authorization request's `resource` when it names the apps shape, and the refresh grant's resource — MUST pass the app name guard: the routed-path charset (`[a-z0-9-]+`, the same shape the router's apps location is written against) and the apps operator restriction when one is configured. The toolset guard's reserved front-door names do not apply to app names, because nothing the gateway owns is served under the apps namespace's name segment — the reserved names are `/dial/`-scoped authorization-surface segments, and an app name can never capture them. An app name carrying a slash — a bucket-scoped app id — fails the charset and is refused: the front door serves the deployment-registry apps, the same routing-charset rationale as toolsets.

The gateway's apps discovery tier mirrors Core's own, extended from the toolset namespace: Core serves the apps MCP path's unauthenticated 401 challenge and the apps protected-resource route from the same `toolsets.security.authorizationServers` configuration that serves the toolset tier — there is no apps-specific security configuration — and both are registry-independent (the auth check precedes any registry lookup; the metadata document is built from configuration with the requested path echoed as `resource`; unset, the 401 carries no challenge and the route answers 404, neither an existence oracle, and the gateway serves its own document regardless). The mirror property is therefore normative in both namespaces: the gateway's apps tier is served for every guard-passing, restriction-admitted name, phantom and real alike, makes no Core call at all, and existence is decided post-authentication, at the flow's app read. Each apps document MUST name the app's resource URI and the single AS issuer; its `scopes_supported` is always empty — no upstream leg exists for an app resource to send scopes on — and no authentication-kind extension appears, because an app carries no authentication kind. The apps protected-resource route joins the same per-source and global rate limiter as every other unauthenticated surface, and over-limit requests write no record.

#### Scenario: No token on the apps path
- **WHEN** a client calls the apps MCP path with no Authorization header
- **THEN** the response is 401 with a `WWW-Authenticate` header whose `resource_metadata` names the gateway's apps protected-resource document for that app, and none of Core's own challenge reaches the client

#### Scenario: Query string survives the apps routing
- **WHEN** a client sends `GET /apps/<name>/mcp?sessionId=<id>` through the front door
- **THEN** the request reaching Core's deployments MCP path carries the `sessionId` parameter unchanged

#### Scenario: Per-app protected-resource fetch
- **WHEN** a client fetches the protected-resource document for a served app
- **THEN** the document returns the app's resource URI and the single AS issuer, with `scopes_supported` empty and no authentication-kind extension

#### Scenario: Dynamic app served without local configuration
- **WHEN** no apps restriction is configured and a client fetches the protected-resource document for an app name that passes the app name guard
- **THEN** the document is served with the name-derived resource URI and the single AS issuer, with no gateway-side app configuration involved and no Core call made — whether Core's registry holds the name is not decided on this surface (the mirror property, apps namespace: the unauthenticated tier is registry-independent, and existence is decided post-authentication at the flow's app read)

#### Scenario: Guard-failing app name refused at discovery
- **WHEN** a client fetches the protected-resource document for an app name outside the routed-path charset
- **THEN** the response is 404, and one audit record carries the fixed-vocabulary reason with the offered name as a truncated non-credential fact

#### Scenario: Restriction-excluded app refused
- **WHEN** an apps restriction is configured and a client fetches the protected-resource document for a name it excludes
- **THEN** the response is 404 — the same shape an unknown app name receives on this surface, the audit record distinguishing only by its fixed-vocabulary reason

### Requirement: App resources complete the sign-in flow credential-free

An app resource is credential-free by construction — it carries no authentication kind and no per-app sign-in status in Core, and its MCP data path runs on the caller's own identity, authorized per call — so the sign-in flow for this resource kind is the identity leg, the DIAL authorization read, and the mint, and nothing else. The flow MUST authenticate the user under the gateway's public PKCE client exactly as for a toolset (the identity leg is kind-agnostic by construction and stays so). DIAL authorization is enforced by reading the app as that user — the single-app read `GET /openai/applications/{id}` — before any token is minted: Core answers 403 when the user cannot read the app, and the flow fails with the same no-access page a toolset refusal earns, no round-trip beyond the read; a 404 is the apps namespace's existence refusal — a plain-language page saying the app is not registered in DIAL Core, one audit record with a fixed-vocabulary reason naming the app, no flow state surviving the refusal; and an unreachable or unreadable answer fails closed as a deployment fault on the operator-facing fault page, never taken for an existence answer — the same three-shape discipline the toolset settings read carries. The existence refusals are the flow's authenticated reads, one per resource kind; no unauthenticated tier on either side of the front door carries an existence oracle in either namespace.

After the read, the kind-driven short-circuit runs unconditionally for this kind: no signed-in check runs, because no per-app status members exist to read; no kind branch runs, because no consent could establish anything for a resource that needs no credential; no credential call and no upstream round-trip of any kind ever run. The flow mints the harness's code directly, and the minted tokens are the same shape a toolset sign-in issues — the audience names the app's resource. The general rule the flow's routing decision already carries decides this without a new mechanism: the upstream stage runs only when the credential is missing AND the kind makes it establishable by consent, and for the app kind the second conjunct is false by construction — where a non-OAuth toolset's missing credential blocks its data path and earns the impossible-branch refusal, an app's data path runs on the caller's own identity, so there is nothing missing to refuse. One audit record MUST show the kind-driven short-circuit: a fixed-vocabulary reason naming the resource kind, with the flow's non-credential facts.

#### Scenario: App sign-in completes with no consent and no credential call
- **WHEN** a harness runs the sign-in flow for an app resource — discovery, registration, the authorization request naming the app's resource URI — and the user can read the app
- **THEN** the flow completes with no consent screen, no credential call, and no upstream round-trip of any kind, and the issued tokens carry the user's `sub` with the app's resource as their audience

#### Scenario: Unknown app refused at the flow's app read
- **WHEN** the authenticated user's app read returns no app — Core does not know the offered name
- **THEN** the flow fails with a plain-language page, no round-trip beyond the read happens, and one audit record carries the fixed-vocabulary reason (`unknown_app`) naming the app — the apps namespace's existence refusal, decided post-authentication exactly where the toolset namespace's is; no flow state survives the refusal

#### Scenario: App authorization denied
- **WHEN** the authenticated user cannot read the app
- **THEN** the flow fails with the clear no-access page and no token is minted

#### Scenario: Unreachable Core is a deployment fault, never an existence answer
- **WHEN** the app read cannot be completed — Core unreachable, or the answer unreadable
- **THEN** the flow fails closed with the operator-facing fault page, distinct from the not-registered page, and the offered name is never learned to be unserved from a failure

#### Scenario: Repeat app sign-in is silent
- **WHEN** the same user runs the app sign-in again while holding valid tokens
- **THEN** the flow completes the same way — no consent, no credential call — and the issued tokens are the same shape the first flow issued

### Requirement: The apps restriction is an optional operator restriction

The apps restriction is the apps namespace's own optional operator restriction, separate from the toolset restriction because the two registries are disjoint namespaces in Core: a name can exist as both a toolset and an app, and a shared restriction would admit or deny both together — an operator decision the deployment never asked for. Unset, the gateway MUST serve every app whose name passes the app name guard; set, it MUST serve only the restriction's entries. Configured entries MUST keep the startup refusal that protects static routing — a name outside the routed-path charset refuses the container's start with an operator-facing error naming the entry — because the router's apps location is static configuration with no view of what Core serves, exactly as for toolsets. An entry MUST declare nothing but the name: no authentication kind exists on an app to declare, and no scopes are declared because no leg ever sends scopes for an app resource — the apps protected-resource document's `scopes_supported` is empty whether or not the app is pinned. Resource inference MUST NOT consult the apps restriction: an app resource is always named explicitly by its resource URI, and with two namespaces served by one authorization server there is no unnamed resource a missing `resource` parameter could honestly be resolved to.

#### Scenario: App name outside the routed charset refused
- **WHEN** the apps restriction lists a name carrying a character outside `[a-z0-9-]`
- **THEN** the gateway refuses to start with an operator-facing error naming the entry and the charset, so a name the router's apps location could never route fails at configuration time, not in operation

#### Scenario: Unset apps restriction serves dynamically
- **WHEN** no apps restriction is configured
- **THEN** the gateway starts, and app resources are served whose names pass the app name guard — the documents are registry-independent (the mirror property), and the apps a harness can actually use are the ones Core's registry holds, learned at the flow's authenticated app read

#### Scenario: Restriction-excluded app refused like an unknown one
- **WHEN** an apps restriction is configured and a request names an app outside it
- **THEN** the refusal is the same one an unknown app name receives on that surface, and the audit record distinguishes only by its fixed-vocabulary reason

### Requirement: App-resource acceptance on a real harness gates completion

Before this change is done, the apps chain MUST pass on a real harness: (a) first use end to end — discovery at the apps protected-resource document, registration, the authorization request with `resource` naming the app's resource URI, the flow, and a live app tool call through the apps front-door path with a gateway-signed token; (b) the flow completes with no consent screen and no credential call, and the audit trail shows the kind-driven short-circuit; (c) query strings survive the apps front routing on a streamable-HTTP session; (d) the toolset flow is unchanged — a toolset sign-in completes exactly as it did before the apps surface existed. Failure of any criterion falsifies the design and MUST reopen it, not be patched around.

#### Scenario: App first use end to end
- **WHEN** a real harness is pointed at the apps front-door path for an app it can read, with no prior sign-in
- **THEN** it completes discovery, registration, the credential-free flow, and token exchange, and a live tool call through the apps front door succeeds with a gateway-signed, copied-sub token

#### Scenario: The audit trail shows the kind-driven short-circuit
- **WHEN** the acceptance flow completes and the audit trail is read
- **THEN** the flow's records show the app read's outcome and the kind-driven short-circuit — a fixed-vocabulary reason naming the resource kind — with no consent-leg event and no credential-call event on the trail for that flow

#### Scenario: Query strings survive the apps front routing
- **WHEN** a streamable-HTTP GET with a session parameter crosses the apps front door
- **THEN** Core receives the parameter unchanged

#### Scenario: The toolset flow is unchanged
- **WHEN** a toolset sign-in runs after the apps surface is live
- **THEN** it completes exactly as before — the routing decision, the consent or short-circuit path, and the issued tokens are unchanged for toolset resources

## MODIFIED Requirements

### Requirement: Authorization requests require a valid resource and allocate protected flow state

The RFC 8707 `resource` parameter MUST be the required resource disambiguator on both the authorization and token endpoints: a missing resource, a resource whose name fails the request-time guard of its kind, or a resource that is not the resource URI of a name the guard and the operator restriction of its kind (when one is configured) admit MUST be rejected as `invalid_target`. The resource URI's path shape names the resource kind — `{public-origin}/dial/{name}/mcp` a toolset, `{public-origin}/apps/{name}/mcp` an app — because one flat authorization server serves both kinds, and the resource is the only thing that says which resource, and which kind, a request is for. The toolset guard is the routed-path charset, the reserved front-door names, and the toolset restriction; the app guard is the routed-path charset and the apps restriction — the reserved names do not apply, because nothing the gateway owns is served under the apps namespace's name segment. What this endpoint decides is the name's shape and its place in its kind's restriction; whether a guard-passing, admitted name is actually served by Core is not decided here — no Core call is designed at this endpoint, and in dynamic mode a phantom name's resource URI is shape-identical to a served resource's, in either namespace — so existence is decided one leg deeper, at the flow's authenticated read of the named kind, whose refusal for a name Core does not know is the flow requirement's unknown-toolset scenario or the app-resource requirement's unknown-app scenario, the existence refusals, one per resource kind. The only escape is an explicit one-toolset operator setting, which applies only while the toolset restriction is configured with exactly one entry and never consults the apps restriction. A valid request MUST create a flow record keyed by a 128-bit CSPRNG id with a bounded TTL — a guessable id lets an attacker pair their own upstream code with a victim's session. Flow state lives server-side; the browser carries only the flow id.

*Scenario amendments, declared:* three retained scenarios are re-worded by this change, each named here. "Unknown resource" is re-scoped — from the main spec's toolset-only resource-URI check to the two-shape check the endpoint performs against the request-time guard and the restriction of the resource's kind — because existence is undecidable at this endpoint without a Core call no surface at this stage is specified to make; the backstops that decide it (the flow's per-user settings read for toolsets, the app read for apps) keep their own scenarios in their own requirements. "One-toolset inference" gains its kind scoping — the WHEN names the toolset restriction where the main spec said "the operator restriction", and the THEN gains that inference never consults the apps restriction and never resolves a request to an app — because a second restriction now exists and the inference's dependency is specifically the toolset one. "Guard-failing resource refused" is re-worded for the two-shape guard — the WHEN names the request-time guard of the resource's kind where the main spec named the toolset guard only. No Core call is added to this endpoint.

#### Scenario: Missing resource
- **WHEN** an authorization request omits the resource parameter and no one-toolset inference is enabled
- **THEN** the response is an OAuth error with code `invalid_target`

#### Scenario: Unknown resource
- **WHEN** the resource parameter is not the resource URI of a name the request-time guard and the restriction of its kind, when one is configured, admit
- **THEN** the response is an OAuth error with code `invalid_target` — the endpoint has decided the name's shape, its kind, and its place in that kind's restriction; a guard-passing admitted name that Core does not know is refused later, at the flow's authenticated read of that kind, under that surface's own scenario

#### Scenario: Valid request allocates a flow
- **WHEN** a registered client sends a valid authorization request with PKCE and a known resource
- **THEN** the browser is redirected to the identity provider's authorization endpoint under the gateway's public PKCE client, and the flow record is keyed by an unguessable id

#### Scenario: App resource accepted
- **WHEN** a registered client sends a valid authorization request whose `resource` is an app resource URI naming a guard-passing, restriction-admitted app name
- **THEN** the request is accepted and the flow is allocated for that app resource, and the flow's later stages are the app-resource requirement's — the identity leg, the app read, the kind-driven short-circuit

#### Scenario: One-toolset inference
- **WHEN** the operator enables resource inference and the toolset restriction is configured with exactly one entry
- **THEN** an authorization request without a resource parameter is accepted for that toolset — inference never consults the apps restriction, and never resolves a request to an app

#### Scenario: Guard-failing resource refused
- **WHEN** the resource parameter names a resource name that fails the request-time guard of its kind — a reserved front-door name or a name outside the routed-path charset on the toolset shape, or a name outside the routed-path charset on the apps shape
- **THEN** the response is an OAuth error with code `invalid_target`, and one audit record carries the fixed-vocabulary reason with the offered resource as a truncated non-credential fact

### Requirement: The federation flow establishes the upstream credential through Core

The flow MUST authenticate the user under the gateway's public PKCE client, requesting only its client's default scopes; a client's `scope` parameter is never relayed — a relayed scope can fail the leg. This identity leg runs for every served toolset regardless of authentication kind: it establishes who is signing in, never what kind of credential the toolset uses. DIAL authorization is enforced by fetching the toolset settings as that user before any upstream round-trip; the upstream code goes to Core's credential API at USER level. The settings read itself fails closed on a Core answer that is unreachable or unreadable — the flow fails with the operator-facing fault page, a deployment fault and never an existence answer, rendered as a page distinct from the not-registered page the unknown-toolset scenario carries — and a projection whose authentication-kind value is absent or unusable falls into the impossible branch the same way a non-OAuth kind does: no unreadable answer is ever taken for a not-registered name, and no unreadable kind for a consentable one. That same settings read carries the toolset's public authentication type and the caller's per-toolset statuses, and the flow's stages after it are, in order: **the signed-in check** — when Core reports the caller signed in at user level, or the toolset signed in at global level, the upstream stage is skipped entirely and the flow finishes by minting the harness's code, regardless of authentication kind, because a stored credential already exists and no consent could add anything; a status that is absent, unreadable, or FAILED is not signed in, and the check fails closed into the kind branch; then **the kind branch** — the upstream consent stage runs only when no credential is stored and the toolset's kind makes one establishable by consent: an OAUTH toolset continues through the upstream consent exactly as designed (its public OAuth settings — client id, endpoints, challenge, callback — are required on this branch and only this branch), and a toolset of any other kind is refused with a plain-language page saying its credential is configured directly in DIAL and cannot be established by a consent flow — audited, fail-closed, no upstream round-trip; the refusal loops benignly, like any auth error, until an administrator stores the credential out of band, after which the same flow short-circuits. The flow never establishes a credential at GLOBAL level — the credential call stays at USER level on every path that establishes one — and it never reads or transits any stored upstream credential on any path, the short-circuit included: Core injects the stored credential on the data path, and a GLOBAL credential the short-circuit uses is one an operator configured — the flow uses it, it does not establish it, which is the same access that user already holds through Core's own paths with a primary-provider token. The flow record MUST be destroyed on first use at the upstream callback. The identity provider's session-bound refresh token — issued with the code exchange, with `offline_access` never requested, so no offline grant is ever acquired — is carried for the refresh window as an encrypted claim in the gateway's own refresh token: encrypted at the code grant under the gateway's dedicated custody key, decrypted at every refresh grant, re-encrypted into each rotated refresh token. The plaintext never travels in any client-visible artifact, and the encrypted claim rides the refresh token only — never the access token, never the authorization code. Between flow end and the code grant the token transits a server-side pending entry keyed by the authorization code's id; the provider's access token is discarded at flow end. A code exchange that issues no refresh token MUST fail the flow at sign-in with an operator-facing error naming the deployment prerequisite — the refresh claims re-read requires it, and failing at sign-in is loud and per flow where failing at the first refresh would be hours late. A provider refresh token larger than the configured custody size bound MUST fail the flow the same way, for the same reason: the carrier it must fit inside is a refresh token handed to a harness token store the gateway does not control. The custody size bound and the token-endpoint request-body cap are coupled operator settings and MUST move together: the cap MUST stay at or above the bound plus the envelope's expansion and the JWT overhead (cap ≥ bound + envelope expansion + JWT overhead), so every refresh body the bound lets a sign-in issue passes the cap — a bound raised past the cap's headroom would recreate by configuration the exact far-from-its-cause failure the loud sign-in refusal exists to prevent: sign-ins succeeding while every refresh fails over-cap.

*Scenario amendment, declared:* the retained "Unknown toolset refused at the flow's settings read" scenario is re-worded by this change in two places, both declared here — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" (with the app read named as the app namespace's), and the mirror-property parenthetical gains "in both namespaces" ("on both sides of the front door" becomes "on both sides of the front door in both namespaces") — because the apps surface adds the app read as the apps namespace's existence refusal and extends the mirror property to the second namespace; the property the phrase carried is unchanged and now stated per kind: the existence refusals are the flow's authenticated reads, one per resource kind, and no unauthenticated tier on either side of the front door carries an existence oracle in either namespace. Everything else in this requirement is unchanged and governs toolset resources; the app flow is the app-resource requirement's own.

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
- **THEN** the flow fails with a plain-language page, no upstream round-trip happens, and one audit record carries the fixed-vocabulary reason (`unknown_toolset`) naming the toolset — and this read is the toolset namespace's existence refusal (the app namespace's is the app read, the app-resource requirement's scenario): the unauthenticated discovery tier is registry-independent on both sides of the front door in both namespaces (the mirror property), so a phantom name's discovery document cost the harness one browser round-trip and this refusal is where the name is learned to be unserved; no flow state survives the refusal and no upstream leg can start from it

#### Scenario: The provider's session refresh token is carried past the flow for the refresh window
- **WHEN** a flow completes and tokens are issued
- **THEN** the provider's session refresh token is carried encrypted inside the issued refresh token under the refresh-window bound, no offline grant was ever requested, and the provider's access token is discarded at flow end

#### Scenario: Provider issues no refresh token
- **WHEN** the identity provider's code exchange returns no refresh token for the gateway's client
- **THEN** the flow fails at sign-in with an operator-facing error naming the deployment prerequisite, and no tokens are issued

#### Scenario: Provider refresh token over the custody size bound refused at sign-in
- **WHEN** the identity provider's code exchange returns a refresh token larger than the configured custody size bound
- **THEN** the flow fails at sign-in with an operator-facing error naming the bound, and no tokens are issued — the same loudness as the no-refresh-token refusal, at the same point in the flow

### Requirement: Discovery documents describe one flat authorization server

The gateway MUST serve one RFC 8414 AS metadata document at the host root for a single path-less issuer — the public origin — and one RFC 9728 protected-resource document per served toolset. A toolset is served when its name passes the request-time name guard (routed-path charset, reserved front-door names) and is not excluded by the operator restriction when one is configured — and nothing else decides it on this surface: the document is served for every guard-passing, restriction-admitted name, whether or not Core's registry holds it. The gateway's unauthenticated discovery tier is registry-independent by design, mirroring Core's own: Core's MCP path answers an unauthenticated call — for a toolset that exists or one that does not — with 401 and a challenge naming the protected-resource document, because the auth check precedes any registry lookup (a fact of the enabled route — Core's `toolsets.security.authorizationServers` configuration is what serves it; unset, the 401 carries no challenge, and a challenge-less 401 is no existence oracle either), and Core's own unauthenticated protected-resource route answers any well-formed name with a static document built from configuration with the requested path echoed as `resource` (likewise a fact of the enabled route — the same configuration; unset, the route answers 404, which is no existence oracle either, and the gateway serves its own document regardless); no unauthenticated tier on either side of the front door carries an existence oracle, in either configuration. The mirror property is normative: the gateway's tier brings nothing Core's own does not — the same 401-challenge on the data path, the same echo-document at discovery, and existence decided at the same moment, post-authentication, at the flow's per-user settings read (whose refusal for a name Core does not know is the federation requirement's unknown-toolset scenario, the toolset namespace's existence refusal). Discovery therefore makes no Core call at all: no consult, no service credential, no cache, and no Core-unavailable failure shape — the protected-resource document costs the gateway one static document, and its availability is the gateway's own. The AS metadata MUST advertise both grants, S256, token-endpoint auth method `none`, and client-ID-metadata-document support, so CIMD-capable clients register with no registration call; it is a static document and consults nothing. Each protected-resource document MUST name the single AS issuer; its `scopes_supported` echoes the operator restriction's entry where the toolset is pinned there and is empty otherwise; its authentication-kind extension is omitted — under dynamic serving this surface has no authentication-kind source (the mapping's kind declaration is deleted, and the kind a flow acts on is Core's, read per flow at the authenticated settings read). The members are informational, and the scopes the upstream leg sends come from the toolset's Core settings; a client's faithfully echoed `scope` parameter is already accepted and dropped at the authorization endpoint, so an omitted member costs nothing on any leg.

*Amendment, declared:* the requirement's text is amended by this change in one clause only — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" — because a second existence refusal exists once the app read does (the app-resource requirement's unknown-app scenario), so the sentence must state the property per namespace to stay true after the sync; the retained scenarios are unchanged and carried verbatim.

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

### Requirement: Issued tokens are gateway-signed and audience-marked

The gateway MUST mint RS256 JWTs whose issuer is the public origin and whose `sub` is the live-authenticated user's subject — established at issuance by the verified identity token, and at refresh by the fresh verified provider token whose subject MUST equal the gateway refresh token's own subject, so a minted token never carries a subject the identity provider did not just (re-)assert. The audience MUST contain the addressed resource's URI — the toolset's or the app's — and the marker configured on the gateway's identity-provider entry in Core, so a token that lacks the marker is rejected. The marker is what Core's provider entry verifies: Core's identity-provider check is the single configured audience, and no per-resource audience match exists on Core's MCP paths, toolset or app — so the resource audience is the gateway's own addressing discipline, enforced at the gateway's resource checks (the authorization and token endpoints' resource match, the refresh grant's resource match), and the spec claims no Core-side per-resource scoping. The refresh token's `aud` MUST carry the addressed resource's URI alone — the marker MUST NOT be included — so the refresh token is never a token Core's identity-provider entry accepts: the marker is what makes a gateway-issued token a Core-acceptable access token, and its absence on the refresh token is the token-type separation, load-bearing, not incidental. The separation is doubled under the custody design: the refresh token carries no copied claims at all — no roles claim — so even absent the marker check it authorizes nothing at Core's role-path matching. Access tokens MUST be short-lived; refresh tokens carry `typ=refresh`. The authorization code MUST be single-use, PKCE-bound, short-lived, with replay rejected.

*Scenario amendments, declared:* the requirement's audience wording is re-worded by this change — "the toolset's resource" becomes "the addressed resource's URI — the toolset's or the app's" — and gains the Core-side enforcement statement, because the app surface makes the wording's implied claim (that Core enforces the resource audience) checkable against the Core source, and the check falsifies it: Core verifies the marker only. The retained "Token carries the marker audience" and "The refresh token is not a Core-acceptable token" scenarios carry the same resource wording ("the toolset's resource" becomes "the addressed resource's URI"); "Token carries the marker audience" additionally gains a closing clause — "the marker being the member Core's check reads" — restating the verified Core fact the requirement text now carries, and "The refresh token is not a Core-acceptable token" is otherwise unchanged; one scenario is added for the app resource.

#### Scenario: Code exchange issues tokens
- **WHEN** the harness exchanges its authorization code with the correct PKCE verifier and resource
- **THEN** an access token and a refresh token are issued, both signed by the gateway and carrying the user's `sub`

#### Scenario: Token carries the marker audience
- **WHEN** an issued access token is validated by Core
- **THEN** its audience contains both the addressed resource's URI and the configured marker, and Core accepts it through the gateway's identity-provider entry — the marker being the member Core's check reads

#### Scenario: An app-resource token carries the app resource and the marker
- **WHEN** a flow for an app resource issues tokens
- **THEN** the access token's audience contains the app's resource URI and the marker, and the refresh token's audience carries the app's resource URI alone — the same separation, the same shape, the resource being the app's

#### Scenario: The refresh token is not a Core-acceptable token
- **WHEN** a gateway-issued refresh token is presented to Core's token validation shape — the signature, issuer, and audience-marker check Core's identity-provider entry applies to a presented token
- **THEN** the audience check refuses it, because the refresh token's `aud` is the addressed resource's URI alone with no marker — and the gateway's mint is pinned to that separation: the marker present on every access token, absent on every refresh token

#### Scenario: Code replay rejected
- **WHEN** the same authorization code is presented twice
- **THEN** the second exchange is rejected

### Requirement: Toolset names are guarded at request time

Every toolset name the gateway resolves — the protected-resource document's path, the authorization request's `resource`, and the refresh grant's resource — MUST pass one guard before it names a served toolset: the routed-path charset (lower-case letters, digits, and hyphen, `[a-z0-9-]`) and the reserved front-door names (`authorize`, `token`, `register`, `revoke`, `callback`, `jwks.json`), because the router's locations are written against exactly that shape and a name outside it has no location that routes it. This guard governs toolset-shaped resources: where a listed surface serves both kinds — the authorization request's `resource` and the refresh grant's resource — the resource's kind decides which guard applies, and the apps shape passes the app guard of the app-resource requirement, never this one. When an operator restriction is configured, a name it excludes MUST fail the same way. Guard failures fail closed with the response shape the surface already answers — 404 at the protected-resource document, `invalid_target` at the authorization and token endpoints — and each refusal lands on the audit trail with a fixed-vocabulary reason and the offered name as a truncated non-credential fact, never free-form caller input.

*Amendments, declared:* the requirement is scoped by this change to toolset-shaped resources — one sentence added, the kind-decides-the-guard rule — because the authorization request's `resource` and the refresh grant's resource resolve two kinds under two guards once the apps surface exists, while this requirement's guard, its reserved names, and its refusal shapes are the toolset namespace's own; and the surface list drops "the status endpoint's path" (with its refusal-shapes twin, "and the status endpoint" leaving the 404 enumeration) because the status endpoint is removed from the gateway entirely, both namespaces — the REMOVED entry below. The retained scenarios are unchanged.

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

### Requirement: The toolset mapping is an optional operator restriction

The mapping is an optional operator restriction: unset, the gateway serves every platform toolset whose name passes the request-time name guard; set, only its entries are served. Configured entries keep the startup refusals that protect static routing — a reserved front-door name and a name outside the routed-path charset each refuse the container's start with an operator-facing error naming the entry — because the front router's locations are static configuration with no view of what Core serves, so neither can be repaired at request time for a name the operator pinned. The OAuth-only declaration check is removed with its reason: a restriction entry declares no authentication kind at all (the `authentication_type` member is removed from the mapping's schema — the kind a flow acts on is Core's, read per flow), and a non-OAuth toolset is a valid entry, because the flow now serves it through the signed-in short-circuit when a credential is stored and refuses it on the impossible branch otherwise. The apps restriction is a separate restriction of the same shape for the apps namespace, and the two never consult each other. Resource inference MUST refuse to start when it is enabled without the toolset restriction configured with exactly one entry: with a dynamic served set there is no "the one toolset" to infer, and inferring silently is how a token ends up addressed to a toolset the client never named — and inference never consults the apps restriction, because a second namespace served by the same authorization server makes an unnamed resource even less inferable than one.

*Scenario amendment, declared:* the retained "Inference without a single-entry restriction refused" scenario's WHEN clause is re-worded by this change — "no restriction is configured, or the configured restriction" becomes "no toolset restriction is configured, or the configured toolset restriction" — because a second restriction now exists and the inference's startup dependency is specifically the toolset one; the requirement text gains the sentences that the apps restriction is a separate restriction of the same shape and that the two never consult each other. No other scenario changes.

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
- **WHEN** resource inference is enabled and no toolset restriction is configured, or the configured toolset restriction does not have exactly one entry
- **THEN** the gateway refuses to start with an operator-facing error naming the setting and what it requires

#### Scenario: Inference never resolves to an app
- **WHEN** resource inference is enabled with its single-entry toolset restriction and an apps restriction is also configured, or not
- **THEN** an authorization request without a resource parameter is still resolved only to that toolset — never to an app, however many apps are served

### Requirement: Public endpoints are bounded against abuse

Unauthenticated endpoints that allocate state MUST be rate-limited per source and globally; live flow records MUST be capped with oldest-first eviction. Every unauthenticated body-bearing endpoint MUST cap the request body in bytes at reading; over-cap is refused. Expired, evicted, and unknown flows MUST land on a plain-language re-run page, never an opaque failure. The identity provider's session refresh token, while carried, is bounded by the refresh token's original absolute expiry, and its plaintext is presented exactly one refresh-grant call per gateway refresh — purposes named, not counted; the bounds govern the gateway's carrying of it, never the credential's usability, which is the provider's own session policy. The token's plaintext is never delivered to any client and never written to any log; the encrypted claim is delivered inside the refresh token by design and is unusable without the custody key. The identity access token's retention is unchanged by this design: it is exposed at most min(flow TTL, its own expiry) — the TTL bounds the gateway's retention, not the token's life — as before. Each protected-resource discovery endpoint — the toolset route and the apps route — MUST join the same per-source and global rate limiter as every other unauthenticated surface, so its guard refusals — each of which writes an audit record — cannot be written faster than the requests that carry them: without the limiter, an unauthenticated caller looping guard-failing names would grow the operator's log at whatever rate it chose. Over the limit either endpoint MUST be answered with the limiter's 429 and MUST write no record at all, so the bound holds at the limit itself.

*Scenario amendments, declared:* the limiter clause is re-worded by this change — "The protected-resource discovery endpoint" becomes "Each protected-resource discovery endpoint — the toolset route and the apps route" — because the apps surface adds a second discovery route of the same class; and the retained "Over-limit discovery requests" scenario's WHEN is re-worded to name both routes ("— on the toolset route or the apps route —" inserted) so the scenario governs the class explicitly. No other scenario changes.

#### Scenario: Flooding rate-limited
- **WHEN** authorization requests arrive from one source beyond the configured per-source limit, or overall beyond the global limit
- **THEN** excess requests are rejected without allocating flow records

#### Scenario: Over-limit discovery requests are refused without a record
- **WHEN** protected-resource discovery requests — on the toolset route or the apps route — arrive from one source beyond the configured per-source limit, or overall beyond the global limit
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

### Requirement: Refusals before flow allocation are audited

Every refusal before a flow is allocated — `/dial/authorize` validation refusals, client resolution, `/dial/register`, `/dial/token`, `/dial/revoke` form refusals, discovery misses, and rate-limit 429s — MUST be recorded with a fixed-vocabulary reason and the non-credential facts (client id, redirect URI, resource, toolset), each fact truncated to the configured cap; a 429 record MUST carry the reason only; no credential or free-form caller input may reach the record.

*Amendment, declared:* the refusal enumeration drops `/dial/{name}/status` — the status endpoint's refusals leave the audited set because the status endpoint itself leaves the gateway, both namespaces (the REMOVED entry below); the status-only refusal reason tokens retire with the endpoint, and every reason token a remaining surface uses stays. The retained scenarios are unchanged and carried verbatim.

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

### Requirement: Flows are audited through their lifecycle

Every allocated flow MUST record its lifecycle events — allocation (carrying the resource kind the flow serves, toolset or app, as a non-credential fact), the upstream callback, the credential call's fixed-vocabulary result, code issuance, and leg failures with the failing leg's name — under the same discipline pre-allocation refusals are audited with: fixed vocabulary, the non-credential facts (flow id, subject, client id, resource), each caller-supplied fact truncated to the configured cap. For an app resource the trail MUST show the kind-driven short-circuit: the app read's fixed-vocabulary result and a short-circuit record with a fixed-vocabulary reason naming the resource kind, so the trail answers that the flow minted with no upstream stage because the resource kind is credential-free — and carries no consent-leg or credential-call event, because none ran. No token, code, key, or free-form caller input may reach a flow record.

*Scenario amendments, declared:* the lifecycle-events list is extended by this change — the allocation record gains the resource kind the flow serves, the app flow's events (the app read's result, the kind-driven short-circuit) are named, and the facts vocabulary's "toolset" becomes "resource" (a flow is now addressed to a toolset or an app) — because the apps surface adds a second flow shape whose decisive event is the short-circuit itself; the retained "A completed flow's chain is attributable end to end" scenario's THEN carries the same vocabulary re-wording ("the toolset" becomes "the resource") and is otherwise unchanged.

#### Scenario: A completed flow's chain is attributable end to end
- **WHEN** a flow completes from allocation to code issuance
- **THEN** the trail carries its lifecycle events under one flow id, each carrying the client id and the resource, and — once the flow knows the user — the subject, so the sign-in is attributable to the acting user

#### Scenario: A refused or failed leg is recorded with its outcome
- **WHEN** the credential call is refused, or a flow leg fails
- **THEN** the trail records the fixed-vocabulary result or the leg failure with the leg's name — never the counterparty's own response text

#### Scenario: The kind-driven short-circuit is recorded
- **WHEN** a flow for an app resource completes
- **THEN** the trail carries the app read's fixed-vocabulary result and the short-circuit record naming the resource kind — and no consent-leg or credential-call event exists for that flow, because none ran

#### Scenario: A credential-shaped value never reaches a flow record
- **WHEN** a flow event is recorded after the flow handled credentials — the identity token, the upstream code, the issued code — or a caller offered a credential-shaped value
- **THEN** the record carries identifiers and outcomes only: no token, code, key, or free-form caller input is written

## REMOVED Requirements

### Requirement: Sign-in status is queryable without a tool call

**Reason:** The requirement's normative sentence — "With a gateway access token, a client MUST be able to query a served toolset's public authentication statuses as that user, distinguishing signed-in from not signed-in" — names exactly the surface the owner's ruling (2026-11-03, at the review pause) deletes from the gateway, both namespaces: the sign-in status API is dropped, not scoped. The reasoning that motivated this change's original no-app-status decision extends to the one namespace the endpoint actually served: for apps there is no stored state for a status question to read, and for toolsets the 401 shapes already answer the harness's question where the harness meets it — the toolset MCP path answers 401 with the gateway's own challenge on no token, an invalid or expired token, and a valid token with no stored upstream credential, and those are exactly the causes the sign-in flow resolves, so the answer the endpoint sold for one authenticated Core read is bought for one failed call the challenge requirement already governs. The price is recorded rather than hidden: operators lose the per-user sign-in probe, and the diagnostic path that remains is the 401 challenge shapes plus the audit trail. A requirement whose only subject is a surface the gateway no longer serves is worse than none.

**Migration:** The requirement is removed whole, and its scenarios — "Signed in", "Not signed in", "Signed in through a global credential" — die with it; every conformance row written against them is retired with the behavior, and no replacement requirement exists (the question the endpoint answered is answered by the data path's own 401 shapes, governed by the toolset-path challenge requirement). No cross-reference is orphaned: the toolset-guard requirement's surface list drops the status endpoint's path, the pre-allocation audit requirement's refusal enumeration drops `/dial/{name}/status`, the status-only refusal reason tokens (`missing_token`, `invalid_token`) retire with the endpoint while every token a remaining surface uses stays, the router's status location and its routing-doc row are removed with their probe rows, and the threat model's T1-15 (the status-enumeration threat) is retired by this change's threat-model task with its cross-references reconciled.
