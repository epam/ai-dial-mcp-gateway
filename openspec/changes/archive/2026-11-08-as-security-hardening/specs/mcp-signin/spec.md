# Spec Delta

## MODIFIED Requirements

### Requirement: Discovery documents describe one flat authorization server

The gateway MUST serve one RFC 8414 AS metadata document at the host root for a single path-less issuer — the public origin — and one RFC 9728 protected-resource document per served toolset. A toolset is served when its name passes the request-time name guard (routed-path charset, reserved front-door names) and is not excluded by the operator restriction when one is configured — and nothing else decides it on this surface: the document is served for every guard-passing, restriction-admitted name, whether or not Core's registry holds it. The gateway's unauthenticated discovery tier is registry-independent by design, mirroring Core's own: Core's MCP path answers an unauthenticated call — for a toolset that exists or one that does not — with 401 and a challenge naming the protected-resource document, because the auth check precedes any registry lookup (a fact of the enabled route — Core's `toolsets.security.authorizationServers` configuration is what serves it; unset, the 401 carries no challenge, and a challenge-less 401 is no existence oracle either), and Core's own unauthenticated protected-resource route answers any well-formed name with a static document built from configuration with the requested path echoed as `resource` (likewise a fact of the enabled route — the same configuration; unset, the route answers 404, which is no existence oracle either, and the gateway serves its own document regardless); no unauthenticated tier on either side of the front door carries an existence oracle, in either configuration. The mirror property is normative: the gateway's tier brings nothing Core's own does not — the same 401-challenge on the data path, the same echo-document at discovery, and existence decided at the same moment, post-authentication, at the flow's per-user listing read (whose refusal for a name Core does not know is the federation requirement's unknown-toolset scenario, the toolset namespace's existence refusal). Discovery therefore makes no Core call at all: no consult, no service credential, no cache, and no Core-unavailable failure shape — the protected-resource document costs the gateway one static document, and its availability is the gateway's own. The AS metadata MUST advertise both grants, S256, token-endpoint auth method `none`, and client-ID-metadata-document support, so CIMD-capable clients register with no registration call; it is a static document and consults nothing. The AS metadata MUST also carry `authorization_response_iss_parameter_supported` with the value `true` (RFC 9207's support member): the advertisement matches the emission — the gateway emits `iss` on every authorization response, success and redirected error alike (the authorization-responses requirement's own discipline), the sibling SHOULD it already satisfies ahead of the MCP `2026-07-28` revision's upgrade path — and the discovery document's member set is fixed, so the member's presence is normative, not incidental. Each protected-resource document MUST name the single AS issuer; its `scopes_supported` echoes the operator restriction's entry where the toolset is pinned there and is empty otherwise; its authentication-kind extension is omitted — under dynamic serving this surface has no authentication-kind source (the mapping's kind declaration is deleted, and the kind a flow acts on is Core's, read per flow at the authenticated listing read). The members are informational, and the scopes the upstream leg sends come from the toolset's Core settings; a client's faithfully echoed `scope` parameter is already accepted and dropped at the authorization endpoint, so an omitted member costs nothing on any leg.

*Amendment, declared (retained):* the requirement's text is amended in one clause only — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" — because a second existence refusal exists once the app read does (the app-resource requirement's unknown-app scenario), so the sentence must state the property per namespace to stay true after the sync; the retained scenarios are unchanged and carried verbatim.

*Amendment, declared (retained — the availability read's re-pinning):* three mentions change — the mirror-property sentence's "at the flow's per-user settings read" becomes "at the flow's per-user listing read", the authentication-kind sentence's "read per flow at the authenticated settings read" becomes "read per flow at the authenticated listing read", and the dynamic-toolset scenario's mirror-property parenthetical follows — because the flow's existence decision moves with the availability oracle to the deployment-listing read (the federation-flow requirement's declared amendment): the settings read the main spec named is authorized by the caller's admin role, a decision the data path never makes, so the flow's authenticated read of the toolset is now the listing read. The mirror property itself is unchanged: existence is still decided post-authentication, at the flow's one authenticated read of the toolset, never on any unauthenticated tier. No scenario's WHEN or THEN changes beyond the parenthetical's named read.

*Amendment, declared:* the requirement's AS-metadata clause gains the `authorization_response_iss_parameter_supported: true` member — RFC 9207's support advertisement, matching the `iss` emission the gateway already makes on every authorization response (the sibling SHOULD satisfied ahead of the MCP `2026-07-28` revision's upgrade path) — because the discovery document's member set is fixed, so the member's presence is a normative advertisement, not an incidental one. One scenario is added; the retained scenarios are unchanged and carried verbatim.

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
- **THEN** the document is served with the name-derived resource URI and the single AS issuer, with no gateway-side toolset configuration involved and no Core call made — whether Core's registry holds the name is not decided on this surface (the mirror property: the unauthenticated tier is registry-independent, and existence is decided post-authentication at the flow's listing read)

#### Scenario: Guard-failing name refused at discovery
- **WHEN** a client fetches the protected-resource document for a reserved front-door name or a name outside the routed-path charset
- **THEN** the response is 404, and one audit record carries the fixed-vocabulary reason with the offered name as a truncated non-credential fact

#### Scenario: The AS metadata advertises iss-parameter support
- **WHEN** the AS metadata document is served
- **THEN** it carries `authorization_response_iss_parameter_supported` with the value `true` — the advertisement matching the `iss` emission every authorization response already carries

### Requirement: Client registration resolves pre-registered, CIMD, then gated DCR clients

Clients are resolved in priority order: pre-registered client id (operator config); a Client ID Metadata Document at a URL-shaped client id; Dynamic Client Registration only if enabled (default off). The CIMD fetch is server-side request forgery surface and MUST be bounded: HTTPS only, allowlisted origins, no redirects, private/loopback/link-local addresses refused, size capped, cached. All clients are public PKCE; no secret is stored; `redirect_uri` MUST be validated against the registration. The registration response document MUST conform to RFC 7591 §3.2.1 (member names and JSON types) in every member it emits, excepting `client_name`, which is emitted as JSON `null` when the registration request carried no client name; `client_id_issued_at`, when present, MUST be a JSON number of seconds since 1970-01-01T00:00:00Z derived from the registration record's stored creation instant.

One admission rule governs every registration and resolution path — the DCR registration endpoint, the CIMD document's `redirect_uris`, and pre-registered operator config alike (RFC 9700 §2.6's MUST NOT and the MCP authorization specification's own redirect-URI MUST, dual-sourced, one rule closing both): a redirect URI MUST be `https`, or `http` on a loopback host — `localhost`, `127.0.0.1`, `[::1]`, any port, the RFC 8252 §7.3 shape the port-ignoring match requirement's exception already knows. A non-loopback plain-`http` redirect URI — an `http` collector the code would cross in cleartext — MUST be refused at each site: a DCR registration request carrying one is refused with a plain-language error naming the rule and no record is stored, a CIMD document carrying one in its `redirect_uris` is refused as a registration (no authorization request ever resolves against it), and a pre-registered configuration entry carrying one refuses the gateway's startup with an operator-facing error naming the entry. The rule is an admission rule, upstream of the exact-match validation, so a value the rule refuses never reaches the matching. Loopback `http` stays admitted: the ecosystem's own example documents list loopback `http` redirect URIs, and non-loopback `http` is already non-conforming for the conforming population, so no fielded harness's registration changes.

*Amendment, declared:* the requirement gains the redirect-URI admission rule — `https`, or `http` on a loopback host (RFC 8252 §7.3's shape, any loopback port), refused at the DCR registration endpoint, in the CIMD document validation, and at startup for pre-registered configuration — because a non-loopback plain-`http` redirect URI is registerable at every resolution path as built, and neither normative source's refusal (RFC 9700 §2.6's MUST NOT; the MCP authorization specification's redirect-URI MUST, verbatim in both revisions) was priced anywhere. The durable DCR store's load path is the rule's fourth site, carried by the DCR-durability requirement's own amendment. Four scenarios are added; the retained scenarios are unchanged and carried verbatim.

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

#### Scenario: Registration response issued-at is an epoch number
- **WHEN** a client POSTs a registration with DCR enabled and the registration is accepted
- **THEN** the response document conforms to RFC 7591 §3.2.1 in every member it emits (`client_name` excepted as `null` when the request carried no name), and `client_id_issued_at` is a JSON number equal to the stored registration record's creation instant in seconds since 1970-01-01T00:00:00Z

#### Scenario: Re-registration answers the stored instant
- **WHEN** a registration arrives for a client id already in the store and the existing record is returned
- **THEN** the response's `client_id_issued_at` is the JSON number of that record's stored creation instant, not a freshly sampled time

#### Scenario: An http collector URI is refused at DCR registration
- **WHEN** DCR is enabled and a registration request carries a `redirect_uris` entry that is plain `http` on a non-loopback host
- **THEN** the registration is refused with a plain-language error naming the rule, no record is stored, and the entry never reaches the exact-match validation — the admission rule is upstream of the matching

#### Scenario: An http redirect URI in a CIMD document is refused
- **WHEN** a URL-shaped client id's fetched document lists a non-loopback plain-`http` entry in its `redirect_uris`
- **THEN** the document is refused as a registration and no authorization request resolves against it — the scheme rule governs the CIMD path's validation, not the fetch alone

#### Scenario: A pre-registered http redirect URI refuses startup
- **WHEN** the operator's pre-registered client configuration carries a non-loopback plain-`http` redirect URI
- **THEN** the gateway refuses to start with an operator-facing error naming the entry — the operator's own configuration is an admission site like the registration surfaces, not a bypass of the rule

#### Scenario: Loopback http remains admitted
- **WHEN** a registration — DCR, CIMD, or pre-registered — carries an `http` redirect URI on a loopback host (`localhost`, `127.0.0.1`, `[::1]`), at any port
- **THEN** the URI is admitted exactly as before the rule — the RFC 8252 loopback exception, the port-ignoring match requirement's own shape, and the ecosystem's own example documents' practice

### Requirement: DCR registration records are durable across restarts

Dynamic Client Registration records MUST survive a gateway restart: each registration is written atomically to one JSON file in a mounted volume, loaded at startup. An unreadable or corrupt store MUST refuse startup with an operator-facing error naming the path — a silent drop invalidates every registered client without a trace. Stored registrations MUST be capped; at the cap, new ones are refused with a plain-language error. The registration endpoint is advertised only while DCR is enabled. The store's load path is the redirect-URI admission rule's fourth site (the client-registration requirement's): a stored record whose redirect URIs carry a non-loopback plain-`http` URI MUST be refused at load — a record admitted before the rule landed, or planted on the volume, otherwise stays usable, because client resolution reads the store without re-checking. The refusal is the corrupt-store discipline's own shape: the gateway refuses to start with an operator-facing error naming the record, and recovery is the same — the store renamed aside or the record removed, after which the affected harnesses re-register.

*Amendment, declared:* the requirement gains the load-path validation clause — a stored record carrying a non-loopback plain-`http` redirect URI refuses the gateway's startup, named, in the corrupt-store discipline's own shape — because client resolution reads the store without re-checking, so the admission rule without a load-side leg would leave pre-rule and planted records usable after the rule lands; load-time refusal is the stated fail mode (the safe default: a refused record is never admitted to resolution, never silently kept). One scenario is added; the retained scenarios are unchanged and carried verbatim.

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

#### Scenario: A stored non-loopback http redirect URI refuses startup at load
- **WHEN** the DCR store contains a record whose redirect URIs carry a non-loopback plain-`http` URI — a record admitted before the admission rule landed, or planted on the volume
- **THEN** the gateway refuses to start with an operator-facing error naming the record, the record never resolves, and recovery is the corrupt-store discipline's own — the store renamed aside or the record removed, the affected harnesses re-registering on their next sign-in

### Requirement: Authorization requests require a valid resource and allocate protected flow state

The RFC 8707 `resource` parameter MUST be the required resource disambiguator on both the authorization and token endpoints: a missing resource, a resource whose name fails the request-time guard of its kind, or a resource that is not the resource URI of a name the guard and the operator restriction of its kind (when one is configured) admit MUST be rejected as `invalid_target`. The resource URI's path shape names the resource kind — `{public-origin}/dial/{name}/mcp` a toolset, `{public-origin}/apps/{name}/mcp` an app — because one flat authorization server serves both kinds, and the resource is the only thing that says which resource, and which kind, a request is for. The toolset guard is the routed-path charset, the reserved front-door names, and the toolset restriction; the app guard is the routed-path charset and the apps restriction — the reserved names do not apply, because nothing the gateway owns is served under the apps namespace's name segment. What this endpoint decides is the name's shape and its place in its kind's restriction; whether a guard-passing, admitted name is actually served by Core is not decided here — no Core call is designed at this endpoint, and in dynamic mode a phantom name's resource URI is shape-identical to a served resource's, in either namespace — so existence is decided one leg deeper, at the flow's authenticated read of the named kind, whose refusal for a name Core does not know is the flow requirement's unknown-toolset scenario or the app-resource requirement's unknown-app scenario, the existence refusals, one per resource kind. The only escape is an explicit one-toolset operator setting, which applies only while the toolset restriction is configured with exactly one entry and never consults the apps restriction. A valid request MUST create a flow record keyed by a 128-bit CSPRNG id with a bounded TTL — a guessable id lets an attacker pair their own upstream code with a victim's session. Flow state lives server-side; the browser carries only the flow id.

The client's `state` is OPTIONAL, and its handling is a stated rule: a request carrying one MUST have it stored on the flow record at allocation and echoed back **unchanged** on the final redirect; a request carrying none is tolerated — nothing is echoed — because the CSRF-binding work `state` does for a client is already done by things this surface requires: PKCE S256 is mandatory, the `resource` is required and validated, codes are single-use and short-lived, and the flow id — an unguessable server-side binding — round-trips every browser leg (RFC 9700 §2.1's accepted carrier), and the ecosystem's client contract makes `state` a SHOULD, not a MUST, so refusing it would break conforming clients for zero security gain. One bound lands with the rule: a `state` over **2048 bytes** MUST be refused as `invalid_request` with the fixed-vocabulary reason `oversized_state`, on the flow-record allocation path, before the record exists — every other caller-chosen length on this surface is bounded, and the `state` is caller-chosen text stored on an in-memory record and echoed on a redirect, so its length is bounded with them. The refusal is a pre-allocation refusal and lands on that discipline's audited enumeration.

*Scenario amendment, declared (retained):* the retained "Valid request allocates a flow" scenario is re-worded by this change — "the gateway's public PKCE client" becomes "the gateway's identity-provider client" — because the identity leg's client is a confidential client whose PKCE challenge the identity-leg requirements' toggle governs (the challenge rides on top of the client authentication), so the scenario must name the leg's client without pinning the toggle's position. No other scenario changes; the retained scenario-amendments record below stays part of the requirement's text as it stands in the main spec, its three re-worded scenarios carried unchanged by this change.

*Scenario amendments, declared (retained):* three retained scenarios are re-worded by this change, each named here. "Unknown resource" is re-scoped — from the main spec's toolset-only resource-URI check to the two-shape check the endpoint performs against the request-time guard and the restriction of the resource's kind — because existence is undecidable at this endpoint without a Core call no surface at this stage is specified to make; the backstops that decide it (the flow's per-user listing read for toolsets, the app read for apps) keep their own scenarios in their own requirements. "One-toolset inference" gains its kind scoping — the WHEN names the toolset restriction where the main spec said "the operator restriction", and the THEN gains that inference never consults the apps restriction and never resolves a request to an app — because a second restriction now exists and the inference's dependency is specifically the toolset one. "Guard-failing resource refused" is re-worded for the two-shape guard — the WHEN names the request-time guard of the resource's kind where the main spec named the toolset guard only. The parenthetical's toolset backstop is re-pinned by the availability-read amendment — "the flow's per-user settings read" becomes "the flow's per-user listing read" (the federation-flow requirement's declared amendment) — so the backstop this note names is the read the flow now makes. No Core call is added to this endpoint.

*Amendment, declared:* the requirement gains the `state` rule — OPTIONAL, stored on the flow record at allocation, echoed unchanged on the final redirect when present, absent tolerated with nothing echoed, and over 2048 bytes refused `invalid_request` with the fixed-vocabulary reason `oversized_state` before the record exists — because the main spec never stated the rule the implementation carries (an absent `state` tolerated, the response echoing nothing), and the one caller-chosen length on the allocation path that was unbounded is bounded with it; the refusal joins the pre-allocation audit discipline's existing enumeration, so that requirement needs no amendment of its own. No other parameter handling changes — the endpoint reads exactly the parameters it read before this change. Three scenarios are added; the retained scenarios are unchanged and carried verbatim.

#### Scenario: Missing resource
- **WHEN** an authorization request omits the resource parameter and no one-toolset inference is enabled
- **THEN** the response is an OAuth error with code `invalid_target`

#### Scenario: Unknown resource
- **WHEN** the resource parameter is not the resource URI of a name the request-time guard and the restriction of its kind, when one is configured, admit
- **THEN** the response is an OAuth error with code `invalid_target` — the endpoint has decided the name's shape, its kind, and its place in that kind's restriction; a guard-passing admitted name that Core does not know is refused later, at the flow's authenticated read of that kind, under that surface's own scenario

#### Scenario: Valid request allocates a flow
- **WHEN** a registered client sends a valid authorization request with PKCE and a known resource
- **THEN** the browser is redirected to the identity provider's authorization endpoint under the gateway's identity-provider client, and the flow record is keyed by an unguessable id

#### Scenario: App resource accepted
- **WHEN** a registered client sends a valid authorization request whose `resource` is an app resource URI naming a guard-passing, restriction-admitted app name
- **THEN** the request is accepted and the flow is allocated for that app resource, and the flow's later stages are the app-resource requirement's — the identity leg, the app read, the kind-driven short-circuit

#### Scenario: One-toolset inference
- **WHEN** the operator enables resource inference and the toolset restriction is configured with exactly one entry
- **THEN** an authorization request without a resource parameter is accepted for that toolset — inference never consults the apps restriction, and never resolves a request to an app

#### Scenario: Guard-failing resource refused
- **WHEN** the resource parameter names a resource name that fails the request-time guard of its kind — a reserved front-door name or a name outside the routed-path charset on the toolset shape, or a name outside the routed-path charset on the apps shape
- **THEN** the response is an OAuth error with code `invalid_target`, and one audit record carries the fixed-vocabulary reason with the offered resource as a truncated non-credential fact

#### Scenario: Absent state tolerated with nothing echoed
- **WHEN** a registered client sends a valid authorization request carrying no `state` parameter
- **THEN** the request is accepted and the flow is allocated exactly as a state-carrying one's, and the final redirect carries no `state` parameter — nothing is echoed for a state that was never offered

#### Scenario: State echoed unchanged
- **WHEN** a valid authorization request carries a `state` parameter
- **THEN** the value is stored on the flow record at allocation and echoed back unchanged on the final redirect — the gateway never modifies, filters, or extends a client's `state`

#### Scenario: Oversized state refused
- **WHEN** an authorization request carries a `state` parameter over 2048 bytes
- **THEN** the response is an OAuth error with code `invalid_request`, no flow record is allocated, and one audit record carries the fixed-vocabulary reason (`oversized_state`) — the bound lands on the allocation path, before the record exists

### Requirement: The federation flow establishes the upstream credential through Core

The flow MUST authenticate the user under the gateway's identity-provider client — a confidential client whose code exchange and refresh grant authenticate with the configured client secret in both positions of the leg's PKCE toggle, the challenge riding on top where the toggle enables it — requesting only its client's default scopes; a client's `scope` parameter is never relayed — a relayed scope can fail the leg. This identity leg runs for every served toolset regardless of authentication kind: it establishes who is signing in, never what kind of credential the toolset uses. DIAL authorization is enforced by the deployment-listing read of the toolset as that user — `GET /openai/toolsets/{name}`, the read whose authorization decision is the MCP data path's own, because both are Core's deployment resolution of the name against the caller's roles, so the flow's availability oracle and the data path's per-call check are one decision, never two that can disagree — before any upstream round-trip; the upstream code goes to Core's credential API at USER level. The read's two refusal codes are two classes with different remedies, never one: a **403 is access denied** — the caller's own lack of access, the deployment resolution's refusal of them, answered with the no-access page and no upstream round-trip — and a **401 is a trust fault**: Core could not validate the sign-in's identity token, an authentication failure whose remedy is the operator's — Core's provider entry for the identity provider (its issuer, its key set, its audience) or the reachability of that key set — never the user's access; the flow fails closed on it with the operator-facing fault page saying the sign-in cannot proceed and an administrator must check the trust configuration, the flow consumed like any other refusal and no credential retained — the record's identity token is the very material Core could not validate — and neither the page nor the audit record names any user-identifying value: an authentication failure is never shown or recorded as an authorization verdict. The listing read itself fails closed on a Core answer that is unreachable or unreadable — the flow fails with the operator-facing fault page, a deployment fault and never an existence answer, rendered as a page distinct from the not-registered page the unknown-toolset scenario carries — and a projection whose authentication-kind value is absent or unusable falls into the impossible branch the same way a non-OAuth kind does: no unreadable answer is ever taken for a not-registered name, and no unreadable kind for a consentable one. That same listing read carries the toolset's public authentication type, the public authentication settings the upstream consent leg builds its URL from, and the caller's per-toolset statuses, and the flow's stages after it are, in order: **the signed-in check** — when Core reports the caller signed in at user level, or the toolset signed in at global level, the upstream stage is skipped entirely and the flow finishes by minting the harness's code, regardless of authentication kind, because a stored credential already exists and no consent could add anything; a status that is absent, unreadable, or FAILED is not signed in, and the check fails closed into the kind branch; then **the kind branch** — the upstream consent stage runs only when no credential is stored and the toolset's kind makes one establishable by consent: an OAUTH toolset continues through the upstream consent exactly as designed (its public OAuth settings — client id, endpoints, challenge, callback — are required on this branch and only this branch), and a toolset of any other kind is refused with a plain-language page saying its credential is configured directly in DIAL and cannot be established by a consent flow — audited, fail-closed, no upstream round-trip; the refusal loops benignly, like any auth error, until an administrator stores the credential out of band, after which the same flow short-circuits. The flow never establishes a credential at GLOBAL level — the credential call stays at USER level on every path that establishes one — and it never reads or transits any stored upstream credential on any path, the short-circuit included: Core injects the stored credential on the data path, and a GLOBAL credential the short-circuit uses is one an operator configured — the flow uses it, it does not establish it, which is the same access that user already holds through Core's own paths with a primary-provider token. The flow record MUST be destroyed on first use at the upstream callback. The identity provider's session-bound refresh token — issued with the code exchange, with `offline_access` never requested, so no offline grant is ever acquired — is carried for the refresh window as an encrypted claim in the gateway's own refresh token: encrypted at the code grant under the gateway's dedicated custody key, decrypted at every refresh grant, re-encrypted into each rotated refresh token. The plaintext never travels in any client-visible artifact, and the encrypted claim rides the refresh token only — never the access token, never the authorization code. Between flow end and the code grant the token transits a server-side pending entry keyed by the authorization code's id; the provider's access token is discarded at flow end. A code exchange that issues no refresh token MUST fail the flow at sign-in with an operator-facing error naming the deployment prerequisite — the refresh claims re-read requires it, and failing at sign-in is loud and per flow where failing at the first refresh would be hours late. A provider refresh token larger than the configured custody size bound MUST fail the flow the same way, for the same reason: the carrier it must fit inside is a refresh token handed to a harness token store the gateway does not control. The custody size bound and the token-endpoint request-body cap are coupled operator settings and MUST move together: the cap MUST stay at or above the bound plus the envelope's expansion and the JWT overhead (cap ≥ bound + envelope expansion + JWT overhead), so every refresh body the bound lets a sign-in issue passes the cap — a bound raised past the cap's headroom would recreate by configuration the exact far-from-its-cause failure the loud sign-in refusal exists to prevent: sign-ins succeeding while every refresh fails over-cap.

The consent/attribution checkpoint gates the mint on first attribution, after the identity leg and before every mint this requirement's paths issue: once the listing read has run and the flow record carries the resolved client (`client_id`, `client_name`, `redirect_uri`) and the addressed resource, the approved-client registry is consulted on both toolset mint paths — the stored-credential short-circuit consults it before the mint itself, an approved (subject, client) passing through with the flow unchanged and an unapproved one rendering the decision page where the short-circuit minted silently before; the consent branch's checkpoint rides the interstitial's existing position, after the read and before the upstream redirect — on first attribution the interstitial's display-only auto-continue is replaced by the decision page for that one presentation, and once the client is approved the flow keeps the display interstitial verbatim, the notice and the decision being different jobs and only the first attribution lacking the decision. No mint path on the toolset kind completes without passing the registry check. The consent branch's continuation — the upstream authorization URL the branch builds — MUST be stored on the flow record at the decision point, the same discipline the upstream redirect URI already follows, because the approve action continues the flow from the record alone; the identity-leg outcomes the approve action needs are record-resident already — the claim snapshot, the client facts, and the provider's session refresh token. The checkpoint's page, action, and registry are the checkpoint requirement's own.

*Amendments, declared (retained):* four clauses change. The opening "the gateway's public PKCE client" becomes "the gateway's identity-provider client — a confidential client whose code exchange and refresh grant authenticate with the configured client secret in both positions of the leg's PKCE toggle, the challenge riding on top where the toggle enables it" — because the identity leg's client shape is the confidential-client requirement's to state, and this requirement must name the leg without pinning the toggle's position; the endpoints the leg uses are the endpoint-source requirements' — the discovery requirement's in discovery mode, the direct-configuration requirement's where the operator configures the endpoint trio — and no clause of this requirement names a provider-specific endpoint spelling. The authorization-bearing read is re-pinned: "fetching the toolset settings as that user" becomes "the deployment-listing read of the toolset as that user — `GET /openai/toolsets/{name}`, the read whose authorization decision is the MCP data path's own", and every "settings read" and "settings answer" mention in this requirement's text and scenarios becomes the listing read's — because the read this requirement previously named (the bucket-based toolset settings read) is authorized by the caller's admin role, a decision the data path never makes, and refused non-admin users toolsets the data path serves — the false denial the live B2C run exposed (the first non-admin identity through the flow); the listing read and the data path share the one authorization decision (Core's deployment resolution), and the read still carries the public authentication type, the public authentication settings the consent branch builds from, and the per-caller statuses. The refusal semantics keep their named shapes and gain the code-level split: a refusal of the authorized caller is the no-access page, a name Core does not know is the unknown-toolset scenario, an unreachable or unreadable answer is the fault page — and the read's two refusal codes are split by this change's trust-fault amendment (D16, authoring round 7): a 403 keeps the access-denied class, while a 401 — which the main spec's denial scenario never named as a code and the implementation folded into the same access-denied refusal — is declared its own trust-fault class, an authentication failure with an operator's remedy, never an authorization verdict, carried by the requirement text above, the re-worded "DIAL authorization denied" scenario (its WHEN names the 403), and the new trust-fault scenario. The retained "Client scope never reaches the identity provider" scenario carries its wording unchanged. Everything else is unchanged and carried whole; the retained scenario-amendment record below stays part of the requirement's text as it stands in the main spec.

*Scenario amendment, declared (retained):* the retained "Unknown toolset refused at the flow's settings read" scenario is re-worded by this change, in two places, both declared here — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" (with the app read named as the app namespace's), and the mirror-property parenthetical gains "in both namespaces" ("on both sides of the front door" becomes "on both sides of the front door in both namespaces") — because the apps surface adds the app read as the apps namespace's existence refusal and extends the mirror property to the second namespace; the property the phrase carried is unchanged and now stated per kind: the existence refusals are the flow's authenticated reads, one per resource kind, and no unauthenticated tier on either side of the front door carries an existence oracle in either namespace. The same scenario's surface is re-pinned by the availability-read amendment: its WHEN's "toolset settings read" becomes the listing read's, because the flow's existence decision moves with the availability oracle to the deployment-listing read (the requirement's declared amendment above) — the refusal's semantics are unchanged, a 404 from Core's deployment resolution for a name it does not know, on the surface the flow now reads. The scenario's title is retained verbatim as its stable identifier (the delta discipline matches scenarios by header against the main spec, so a renamed header would read as a dropped scenario); the title's "settings read" phrase is the identifier's historical spelling, and the body — the normative content — names the surface precisely. Everything else in this requirement is unchanged and governs toolset resources; the app flow is the app-resource requirement's own.

*Amendment, declared:* the requirement gains the checkpoint paragraph — the approved-client registry consulted after the identity leg and before the mint on both toolset mint paths (the stored-credential short-circuit consulting it before the mint itself; the consent branch's checkpoint riding the interstitial's existing position, its display-only auto-continue replaced by the decision page for the first-attribution presentation alone), the consent branch's continuation-storage rule (the built upstream authorization URL stored on the flow record, because the approve action continues from the record alone), and the no-mint-path-without-the-check statement — because the consent/attribution decision gates every mint this requirement issues, and the page, the action, and the registry are the checkpoint requirement's own normative home. Two retained scenarios are re-worded: "Already signed in short-circuits the consent" and "A global credential serves every user without consent" each gain the approved-client condition in their WHEN — the checkpoint gates the mint on first attribution regardless of credential level, so the silent short-circuit is the approved client's, and the first-attribution shapes are the new scenarios' own. Everything else is unchanged and carried whole.

#### Scenario: DIAL authorization denied
- **WHEN** the flow's listing read answers 403 for the authenticated user — Core's deployment resolution denies them, the same decision the data path would make of the same call
- **THEN** the flow fails with a clear no-access page and no upstream round-trip happens

#### Scenario: A token Core cannot validate is a trust fault, not an access denial
- **WHEN** the flow's listing read answers 401 — Core cannot validate the sign-in's identity token: its provider entry's key-set fetch failing, or an issuer or audience mismatch at that entry
- **THEN** the flow fails closed with the operator-facing fault page saying the sign-in cannot proceed and an administrator must check Core's trust configuration for the identity provider, the flow is consumed like any refusal with no credential retained, and one audit record carries the fixed-vocabulary trust-fault reason — a page and a record that name no user-identifying value, distinct from the no-access page a 403 earns and from the not-registered page a 404 earns

#### Scenario: A public toolset serves every user the data path serves
- **WHEN** a non-admin authenticated user runs the sign-in for a toolset with no user-roles restriction — a public toolset, the case the live run exposed as the false denial
- **THEN** the listing read admits them and the flow proceeds exactly as any authorized caller's — the flow's availability decision is the data path's own, so no admin role is ever asked of a user the data path would serve

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
- **WHEN** the caller holds a stored user-level credential for the toolset and runs the sign-in, and the client is approved for that user
- **THEN** the flow completes with no upstream round-trip and no consent screen, and the issued tokens are the same shape a consented flow issues

#### Scenario: A global credential serves every user without consent
- **WHEN** an operator has stored a GLOBAL-level credential for the toolset and any authorized user runs the sign-in, whatever the toolset's authentication kind, for a client approved for that user
- **THEN** the signed-in check short-circuits the upstream stage, the flow establishes no credential itself, and the minted token carries that user's own claims only — using the stored global credential is the access the operator granted, not a new one

#### Scenario: The signed-in check fails closed
- **WHEN** the listing answer carries no readable status at either level, or a FAILED status
- **THEN** the flow does not short-circuit: an OAUTH toolset continues to the upstream consent leg, and a toolset of any other kind is refused on the impossible branch — no token is minted on an unreadable status

#### Scenario: Unknown toolset refused at the flow's settings read
- **WHEN** the authenticated user's listing read of the toolset returns no toolset — Core does not know the offered name
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

#### Scenario: First attribution on the stored-credential short-circuit renders the decision page
- **WHEN** the caller holds a stored user-level credential for the toolset and runs the sign-in, and the (subject, client) is not in the approved-client registry
- **THEN** the registry is consulted after the identity leg and before the mint, the decision page is rendered and no mint runs, one audit record carries the fixed-vocabulary reason (`attribution_required`), and the flow waits for the user's act — the page, the action, and the registry are the checkpoint requirement's

#### Scenario: An approved client passes the short-circuit untouched
- **WHEN** the same user runs the same sign-in again and the client is in the approved-client registry
- **THEN** the registry check passes with no page rendered and the flow runs exactly its pre-checkpoint shape — the short-circuit mints as it always did, zero pages, zero clicks

#### Scenario: First attribution on the consent branch replaces the display interstitial once
- **WHEN** the toolset consent branch runs for a client the user has not approved
- **THEN** the decision page is served in the interstitial's position in place of the display interstitial for that one presentation — no auto-continue — and on approve the flow continues from the record's stored continuation and serves the display interstitial as today before the upstream redirect; every later attribution for that (subject, client) serves the display interstitial verbatim with no decision page

### Requirement: App resources complete the sign-in flow credential-free

An app resource is credential-free by construction — it carries no authentication kind and no per-app sign-in status in Core, and its MCP data path runs on the caller's own identity, authorized per call — so the sign-in flow for this resource kind is the identity leg, the DIAL authorization read, and the mint, and nothing else. The flow MUST authenticate the user under the gateway's identity-provider client exactly as for a toolset (the identity leg is kind-agnostic by construction and stays so). DIAL authorization is enforced by reading the app as that user — the single-app read `GET /openai/applications/{id}` — before any token is minted: Core answers 403 when the user cannot read the app, and the flow fails with the same no-access page a toolset refusal earns, no round-trip beyond the read; a 404 is the apps namespace's existence refusal — a plain-language page saying the app is not registered in DIAL Core, one audit record with a fixed-vocabulary reason naming the app, no flow state surviving the refusal; a 401 — Core cannot validate the sign-in's identity token — is the trust fault the toolset listing read's 401 is (the federation-flow requirement's trust-fault scenario): the operator-facing fault page, the flow consumed, never an access denial, both reads sharing the gateway's one answer-to-refusal mapping; and an unreachable or unreadable answer fails closed as a deployment fault on the operator-facing fault page, never taken for an existence answer — the same four-shape discipline the toolset listing read carries (denial, existence refusal, trust fault, deployment fault). The existence refusals are the flow's authenticated reads, one per resource kind; no unauthenticated tier on either side of the front door carries an existence oracle in either namespace.

After the read, the kind-driven short-circuit runs unconditionally for this kind: no signed-in check runs, because no per-app status members exist to read; no kind branch runs, because no consent could establish anything for a resource that needs no credential; no credential call and no upstream round-trip of any kind ever run. The flow mints the harness's code directly, and the minted tokens are the same shape a toolset sign-in issues — the audience names the app's resource. The general rule the flow's routing decision already carries decides this without a new mechanism: the upstream stage runs only when the credential is missing AND the kind makes it establishable by consent, and for the app kind the second conjunct is false by construction — where a non-OAuth toolset's missing credential blocks its data path and earns the impossible-branch refusal, an app's data path runs on the caller's own identity, so there is nothing missing to refuse. One audit record MUST show the kind-driven short-circuit: a fixed-vocabulary reason naming the resource kind, with the flow's non-credential facts.

The consent/attribution checkpoint gates the mint on first attribution for this kind too, and it composes with the credential-free identity: the decision page is a user's decision, not a credential — it adds no credential call, no upstream round-trip, and no per-app status read. After the app read and before the mint, the approved-client registry is consulted (the checkpoint requirement's): an approved (subject, client) mints exactly as the short-circuit always has — no page of any kind — and an unapproved one renders the decision page where nothing rendered before; no code is minted until the user's act. The kind-driven short-circuit stays unconditional in everything it owns: the checkpoint adds the one user-visible act the zero-page shape lacked, never a credential stage.

*Amendment, declared (retained):* three clauses change — "the gateway's public PKCE client" becomes "the gateway's identity-provider client" — because the identity leg's client is a confidential client whose PKCE challenge the identity-leg requirements' toggle governs, and the app flow shares that leg exactly as the toolset flow does; the closing comparison's "the toolset settings read" becomes "the toolset listing read" — the availability-read amendment (the federation-flow requirement's declared amendment) — so the discipline the app read is compared to is the read the toolset flow now makes; and the refusal enumeration gains the 401 trust-fault clause with the closing comparison's "three-shape discipline" becoming the four-shape one — because the listing read's 401/403 split (the federation-flow requirement's declared trust-fault amendment, D16) is the app read's too: both reads share the gateway's one answer-to-refusal mapping, so a 401 from the app read is the same trust fault, never an access denial. One retained scenario is re-worded: "App authorization denied" gains the 403 in its WHEN (the code the refusal is), aligning the scenario with the split. No other scenario changes.

*Amendment, declared:* the requirement gains the checkpoint paragraph — the approved-client registry consulted after the app read and before the mint, an approved (subject, client) minting exactly as the short-circuit always has and an unapproved one rendering the decision page where nothing rendered before — because the app kind's zero-page short-circuit is the sharpest silent-mint variant the checkpoint exists to close, and the decision composes with the kind's identity: a user's decision, not a credential, so nothing the credential-free rule forbids is added. Two retained scenarios are re-worded: "App sign-in completes with no consent and no credential call" and "Repeat app sign-in is silent" each gain the approved-client condition in their WHEN — the zero-page silent completion is the approved client's, and the first-attribution shape is the new scenario's own — and "Repeat app sign-in is silent"'s THEN gains "no page of any kind" beside no consent and no credential call, the zero-click property the checkpoint preserves for approved clients. One scenario is added.

#### Scenario: App sign-in completes with no consent and no credential call
- **WHEN** a harness runs the sign-in flow for an app resource — discovery, registration, the authorization request naming the app's resource URI — and the user can read the app, and the client is approved for that user
- **THEN** the flow completes with no consent screen, no credential call, and no upstream round-trip of any kind, and the issued tokens carry the user's `sub` with the app's resource as their audience

#### Scenario: Unknown app refused at the flow's app read
- **WHEN** the authenticated user's app read returns no app — Core does not know the offered name
- **THEN** the flow fails with a plain-language page, no round-trip beyond the read happens, and one audit record carries the fixed-vocabulary reason (`unknown_app`) naming the app — the apps namespace's existence refusal, decided post-authentication exactly where the toolset namespace's is; no flow state survives the refusal

#### Scenario: App authorization denied
- **WHEN** the app read answers 403 for the authenticated user — the user cannot read the app
- **THEN** the flow fails with the clear no-access page and no token is minted

#### Scenario: Unreachable Core is a deployment fault, never an existence answer
- **WHEN** the app read cannot be completed — Core unreachable, or the answer unreadable
- **THEN** the flow fails closed with the operator-facing fault page, distinct from the not-registered page, and the offered name is never learned to be unserved from a failure

#### Scenario: Repeat app sign-in is silent
- **WHEN** the same user runs the app sign-in again while holding valid tokens, for a client in the approved-client registry
- **THEN** the flow completes the same way — no consent, no credential call, no page of any kind — and the issued tokens are the same shape the first flow issued

#### Scenario: First attribution on the app kind's zero-page short-circuit renders the decision page
- **WHEN** a harness runs the sign-in for an app resource the user can read, and the (subject, client) is not in the approved-client registry
- **THEN** the decision page is rendered where nothing rendered before — no code is minted, and no credential call and no upstream round-trip run — one audit record carries the fixed-vocabulary reason (`attribution_required`), and the page names the resolved client, the app resource, and the registered `redirect_uri` (the checkpoint requirement's)

### Requirement: HTML responses carry the web-hardening header family

Every HTML response the gateway serves — the interstitial, the decision page, and every plain-language error or flow page — MUST carry `Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` with script execution excluded (the pages are script-free; inline style may use a nonce, hash, or `'unsafe-inline'`), `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Type naming `charset=utf-8`. The `form-action 'self'` directive is stated family-wide: the decision page carries the one form the page surface has, and a directive confining form submission to the gateway's own origin closes the retargeting shape — injected markup that rewrote the form's action would submit to nowhere but the gateway — at the cost of one clause on a policy every page already carries. The decision page is a page class through the one shared builder like its siblings, so the family is inherited by construction and every interpolated value passes the existing escape discipline; and it MUST NOT auto-continue — no `meta refresh`, no navigation of its own — because the decision is the one page on the surface whose whole job is the user's act.

*Amendment, declared:* three changes. The page-class enumeration gains the decision page (a new page class through the one shared builder — this change's checkpoint), because the family's by-construction inheritance is the page's header control. The CSP gains `form-action 'self'`, stated family-wide — the decision page carries the one form the page surface has, and the directive is stated on the policy every page carries rather than per-page, so no page class can drift off it. The requirement gains the no-auto-continue rule for the decision page — the whole difference between it and the display interstitial it replaces on first attribution. The two retained scenarios' THENs gain the directive with the family, and the interstitial's script-free parenthetical is re-worded to the pages' ("the interstitial is script-free" becomes "the pages are script-free") because the decision page is script-free too. One scenario is added for the decision page.

#### Scenario: The interstitial carries the hardening headers
- **WHEN** the interstitial is served
- **THEN** its response carries the Content-Security-Policy with no source permitting script, `base-uri 'none'`, `frame-ancestors 'none'`, `form-action 'self'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Type naming `charset=utf-8`

#### Scenario: An error or flow page carries them
- **WHEN** any plain-language error or flow page is served
- **THEN** its response carries the same header set

#### Scenario: The decision page carries the family and does not auto-continue
- **WHEN** the decision page is served
- **THEN** its response carries the same header set with `form-action 'self'` on the Content-Security-Policy, its markup is script-free with no `meta refresh` and nothing that navigates itself, and every interpolated value — the client name, the client id, the resource name, the redirect URI — passes the escape discipline

### Requirement: Issued tokens are gateway-signed and audience-marked

The gateway MUST mint RS256 JWTs whose issuer is the public origin and whose `sub` is the live-authenticated user's subject — established at issuance by the verified identity token, and at refresh by the fresh verified provider token whose subject MUST equal the gateway refresh token's own subject, so a minted token never carries a subject the identity provider did not just (re-)assert. The audience MUST contain the addressed resource's URI — the toolset's or the app's — and the marker configured on the gateway's identity-provider entry in Core, so a token that lacks the marker is rejected. The marker is what Core's provider entry verifies: Core's identity-provider check is the single configured audience, and no per-resource audience match exists on Core's MCP paths, toolset or app — so the resource audience is the gateway's own addressing discipline, enforced at the gateway's resource checks (the authorization and token endpoints' resource match, the refresh grant's resource match), and the spec claims no Core-side per-resource scoping. The refresh token's `aud` MUST carry the addressed resource's URI alone — the marker MUST NOT be included — so the refresh token is never a token Core's identity-provider entry accepts: the marker is what makes a gateway-issued token a Core-acceptable access token, and its absence on the refresh token is the token-type separation, load-bearing, not incidental. The separation is doubled under the custody design: the refresh token carries no copied claims at all — no roles claim — so even absent the marker check it authorizes nothing at Core's role-path matching. Access tokens MUST be short-lived; refresh tokens carry `typ=refresh`. The authorization code MUST be single-use, PKCE-bound, short-lived, with replay rejected — and a detected replay MUST denylist the refresh token the first redemption minted (RFC 9700 §4.2.4): the code grant records the code's id against the refresh token it issues, bounded by the refresh window, and the replay refusal denylists that refresh token by id, so the replayed flow's token family dies at the token's next presentation. Two bounds are disclosed in the rule, stated rather than left silent: the access token the first redemption minted stays live until its own short TTL — bearer and unrevocable by design, the standing bound the SHOULD tolerates — and a refresh token that has already rotated before the replay is detected survives (rotation mints a fresh id, and no code-to-successor mapping exists), that window bounded by the replay detection's timing and the non-sliding absolute expiry.

*Scenario amendments, declared (retained):* the requirement's audience wording is re-worded by this change — "the toolset's resource" becomes "the addressed resource's URI — the toolset's or the app's" — and gains the Core-side enforcement statement, because the app surface makes the wording's implied claim (that Core enforces the resource audience) checkable against the Core source, and the check falsifies it: Core verifies the marker only. The retained "Token carries the marker audience" and "The refresh token is not a Core-acceptable token" scenarios carry the same resource wording ("the toolset's resource" becomes "the addressed resource's URI"); "Token carries the marker audience" additionally gains a closing clause — "the marker being the member Core's check reads" — restating the verified Core fact the requirement text now carries, and "The refresh token is not a Core-acceptable token" is otherwise unchanged; one scenario is added for the app resource.

*Amendment, declared:* the requirement's code clause gains the revoke-on-double-redemption rule — the code grant recording the code's id against the refresh token it issues (bounded by the refresh window) and the replay refusal denylisting that refresh token by id — because RFC 9700 §4.2.4's SHOULD was violated and unpriced as built: the replayed redemption was refused, but the refresh token the first redemption minted stayed live, and nothing connected the code's id to the tokens it bought. The clause states its two disclosed bounds as bounds, not silent gaps: the first redemption's access token ages out under its own short TTL (the SHOULD's tolerated shape), and a refresh token already rotated before the replay is detected survives (no code-to-successor mapping exists), that window bounded by detection timing and the non-sliding absolute expiry. One scenario is added; the retained scenarios are unchanged and carried verbatim.

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

#### Scenario: A replayed code kills the refresh token it bought
- **WHEN** the same authorization code is redeemed a second time after the first redemption minted tokens
- **THEN** the replay is refused as before, the refresh token the first redemption minted is denylisted — its later presentation is refused `invalid_grant` — and the first redemption's only still-live artifact is the access token, under its own short TTL

### Requirement: Claim copy preserves deployment claim paths

Minted tokens MUST carry the verified provider token's claims verbatim except the registry claims the gateway owns, so deployment claim paths and telemetry work without per-claim config. The claim source is one vocabulary at both sites: the token the code exchange returns at issuance, and the fresh token the identity provider's refresh grant returns at refresh — read through the same verification path at both (the provider's published keys, the pinned issuer). Roles MUST additionally be read at a required, operator-configured source path and re-emitted as a plain array where Core's provider entry reads them. Issuance MUST fail loudly when that path is absent from the provider token — a silent role-less token produces undiagnosable 403s; an empty value is legitimate user state. The registry claims the copy rule strips are named by the rule's own honesty: `acr` is stripped, and `auth_time` joins it — a provider that mints its authentication-time claim into its access token MUST NOT have it copied verbatim into a gateway token, where it would state the provider's authentication event as a fact of the gateway's own token. The gateway never sees the provider's ID token and holds no authentication-time fact of its own to state; a minted token's recency facts are its own `iat` and `exp` — the mint's, never the provider's authentication event.

*Amendment, declared:* the requirement gains the registry strip's naming — `acr`, and `auth_time` joining it — because the copy rule's strip list is normative to the claim paths the requirement exists to preserve, and a provider-minted `auth_time` copied verbatim would carry the provider's authentication event into a gateway token as if it were the gateway's own fact, the same false-claim class `acr`'s strip exists for; the mint's recency facts stay its own `iat`/`exp`, the honest limit of what the gateway knows. One scenario is added; the retained scenarios are unchanged and carried verbatim.

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

#### Scenario: The provider's `auth_time` is never copied
- **WHEN** a provider mints an `auth_time` claim into its access token, and the gateway mints from that token at issuance or refresh
- **THEN** the minted token carries no `auth_time` claim — it is stripped with the registry claims — and the token's recency facts remain its own `iat` and `exp`, the mint's own times, never the provider's authentication event

### Requirement: Public endpoints are bounded against abuse

Unauthenticated endpoints that allocate state MUST be rate-limited per source and globally; live flow records MUST be capped with oldest-first eviction. Every unauthenticated body-bearing endpoint MUST cap the request body in bytes at reading; over-cap is refused. Expired, evicted, and unknown flows MUST land on a plain-language re-run page, never an opaque failure. The identity provider's session refresh token, while carried, is bounded by the refresh token's original absolute expiry, and its plaintext is presented exactly one refresh-grant call per gateway refresh — purposes named, not counted; the bounds govern the gateway's carrying of it, never the credential's usability, which is the provider's own session policy. The token's plaintext is never delivered to any client and never written to any log; the encrypted claim is delivered inside the refresh token by design and is unusable without the custody key. The identity access token's retention is unchanged by this design: it is exposed at most min(flow TTL, its own expiry) — the TTL bounds the gateway's retention, not the token's life — as before. Each protected-resource discovery endpoint — the toolset route and the apps route — MUST join the same per-source and global rate limiter as every other unauthenticated surface, so its guard refusals — each of which writes an audit record — cannot be written faster than the requests that carry them: without the limiter, an unauthenticated caller looping guard-failing names would grow the operator's log at whatever rate it chose. Over the limit either endpoint MUST be answered with the limiter's 429 and MUST write no record at all, so the bound holds at the limit itself.

The authorization-server surface is back-channel only toward browsers, as a rule and not an implementation accident: no endpoint on the surface serves any `Access-Control-*` header — the browser-facing routes (`/dial/authorize`, the callbacks, the consent route) and the back-channel endpoints (`/dial/token`, `/dial/revoke`, the discovery documents, the registration endpoint) alike — no preflight is handled (an `OPTIONS` preflight against `/dial/token` receives the framework's 405), and a browser frontend is not a supported client shape: the clients are harness processes exchanging codes and tokens on their own loopback redirects and back channels, and a cross-origin browser page can neither read a token response nor drive the authorize surface's redirects. RFC 9700 §2.6 permits CORS at the token endpoint as a MAY and forbids it at the authorization endpoint; the gateway declines the MAY, surface-wide, and this spec says so.

*Scenario amendments, declared (retained):* the limiter clause is re-worded by this change — "The protected-resource discovery endpoint" becomes "Each protected-resource discovery endpoint — the toolset route and the apps route" — because the apps surface adds a second discovery route of the same class; and the retained "Over-limit discovery requests" scenario's WHEN is re-worded to name both routes ("— on the toolset route or the apps route —" inserted) so the scenario governs the class explicitly. No other scenario changes.

*Amendment, declared:* the requirement gains the CORS/back-channel posture paragraph — no `Access-Control-*` header on any endpoint of the authorization-server surface, browser-facing or back-channel, no preflight handling, and a browser frontend not a supported client shape — because the posture is today true by omission (no CORS middleware exists anywhere) and this change makes it a rule a future middleware line cannot silently undo; the paragraph's home is this requirement because the main spec carries no requirement titled for the token grant itself, and this requirement governs the unauthenticated AS endpoint set the posture spans — the design's token-grant phrase resolves here. No behavior change backs the statement: the code already is the posture, and the change is the rule and its machine-checkable pin (the pin itself is repo material, the header-assertion test battery's). One scenario is added; the retained scenarios are unchanged and carried verbatim.

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

#### Scenario: No CORS headers on any AS-surface response
- **WHEN** a request crosses any endpoint of the authorization-server surface — `/dial/authorize`, the callbacks, the consent route, `/dial/token`, `/dial/revoke`, the discovery documents, the registration endpoint — an `OPTIONS` preflight against `/dial/token` included
- **THEN** the response carries no `Access-Control-*` header, and the preflight receives the framework's 405 with no preflight handling — a browser frontend is not a supported client shape, the surface's clients being harness processes on their own loopback redirects and back channels

### Requirement: Flows are audited through their lifecycle

Every allocated flow MUST record its lifecycle events — allocation (carrying the resource kind the flow serves, toolset or app, as a non-credential fact), the upstream callback, the credential call's fixed-vocabulary result, code issuance, and leg failures with the failing leg's name — under the same discipline pre-allocation refusals are audited with: fixed vocabulary, the non-credential facts (flow id, subject, client id, resource), each caller-supplied fact truncated to the configured cap. The attribution events the consent/attribution checkpoint adds are lifecycle events of this same enumeration: `attribution_required` when the decision page renders, `attribution_approved` when the approve action records and continues, and `attribution_refused` when the deny action consumes the flow — each recorded under this requirement's discipline, with non-credential facts only (client id, client name, redirect URI, resource, kind), the events' semantics the checkpoint requirement's own. For an app resource the trail MUST show the kind-driven short-circuit: the app read's fixed-vocabulary result and a short-circuit record with a fixed-vocabulary reason naming the resource kind, so the trail answers that the flow minted with no upstream stage because the resource kind is credential-free — and carries no consent-leg or credential-call event, because none ran. No token, code, key, or free-form caller input may reach a flow record.

*Scenario amendments, declared (retained):* the lifecycle-events list is extended by this change — the allocation record gains the resource kind the flow serves, the app flow's events (the app read's result, the kind-driven short-circuit) are named, and the facts vocabulary's "toolset" becomes "resource" (a flow is now addressed to a toolset or an app) — because the apps surface adds a second flow shape whose decisive event is the short-circuit itself; the retained "A completed flow's chain is attributable end to end" scenario's THEN carries the same vocabulary re-wording ("the toolset" becomes "the resource") and is otherwise unchanged.

*Amendment, declared:* the requirement gains the attribution-events clause — `attribution_required`, `attribution_approved`, and `attribution_refused` named as lifecycle events of the enumeration, recorded under this requirement's discipline with the checkpoint requirement carrying their semantics — because the enumeration is event-based and closed, and the three events a flow's trail now carries between the identity leg and the mint would otherwise leave two requirements describing one trail with different event sets; the pre-allocation-refusals requirement needs no twin amendment because its enumeration is class-based ("`/dial/authorize` validation refusals" already admits the `oversized_state` refusal). One scenario is added; the retained scenarios are unchanged and carried verbatim.

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

#### Scenario: The attribution events are recorded in sequence
- **WHEN** a first-attribution flow renders the decision page and the user acts — approves or denies
- **THEN** the trail carries `attribution_required` for the page's rendering and `attribution_approved` or `attribution_refused` for the act, under the same flow id and the same discipline as the flow's other lifecycle events — so an attribution a crafted link induced is distinguishable on the trail from one the user's own harness run began

## ADDED Requirements

### Requirement: The consent/attribution checkpoint gates every mint on first attribution

No mint completes without a user-visible act attributing the flow to the client about to be served, on the first attribution of that client to that user. The bound is the drive-by shape: a crafted authorization link can drive a victim's live identity-provider session through the identity leg silently — the gateway relays nothing client-identifying into it — so the decision point that names the client MUST be the gateway's own. The decision point sits after the identity leg completes — the provider's subject verified, the DIAL authorization read run, the flow record carrying the resolved client (`client_id`, `client_name`, `redirect_uri`) and the addressed resource — and before the mint, on all three mint paths: the app kind's zero-page short-circuit, the toolset stored-credential short-circuit, and the toolset consent branch (the two flow requirements' amendments carry the insertion on their paths). At that position the approved-client registry is consulted: an approved attribution passes through with the flow unchanged — zero pages on the short-circuits, the display interstitial verbatim on the consent branch — and an unapproved attribution renders the decision page, and no mint runs until the user's act. The harness's programmatic surface is unchanged: the authorization request still redirects to the identity provider, the callbacks still land, and the final redirect still carries the code, `iss`, and the echoed `state` to the registered redirect; what changes is one response in the browser's sequence, on first attribution only.

The decision page names, each with its honesty rule: the resolved client — the registration's `client_name` where one exists, presented as a name, not a verified fact (the name is registrant-supplied through CIMD or DCR), with the client id beside it always, because it is the verifiable identifier; the addressed resource — the resource kind and the served name, in the pages' plain vocabulary; and the registered `redirect_uri` the code will be delivered to — the one fact a victim can check against expectation and the one a false name cannot forge, because the redirect is the registration's own validated value. No scope list is shown: the client-facing surface accepts and drops the `scope` parameter, and presenting scopes the flow does not act on would be theater. The page is built through the one shared builder, so the web-hardening header family with `form-action 'self'` is inherited by construction, and every interpolated value passes the existing escape discipline — the `client_name` registrant-supplied and the resource name caller-path-derived, both hostile text in an HTML context. The page is script-free, carries two buttons — approve and deny — in a plain form, and MUST NOT auto-continue (no `meta refresh`): the decision must not navigate itself.

The form posts to `POST /dial/consent` carrying the flow id and the chosen action, and nothing else; the page's other facts are re-derived from the flow record at the action, never round-tripped through the browser. The binding is the flow id itself — 128-bit CSPRNG, server-side record, TTL-bounded, the same binding both callbacks ride; the gateway sets no cookies and holds no ambient browser authority of any kind, so a cross-site POST carries nothing the gateway trusts beyond its own parameters, and the flow id is secret from a link-crafter by construction (it crosses only the victim's browser, on the provider redirect and the callback). The route joins the shared limiter and answers no CORS headers (the abuse requirement's posture).

Approve records the attribution in the approved-client registry, keyed to the flow's own verified subject, audits it with the fixed-vocabulary reason `attribution_approved`, and continues the flow to the stage the decision point deferred: the mint for both short-circuits, the record's stored continuation for the consent branch — after which the display interstitial is served as today. The approve action is single-use-per-flow: a re-presented approve, or a POST against a flow already advanced, lands on the expired-flow page and allocates nothing — one approval cannot mint twice. Deny consumes the flow — record destroyed, identity material dropped, plain-language page, fixed-vocabulary audit reason `attribution_refused` — and no OAuth error is redirected to any target: the decision page is the response, browser-facing refusals are pages, and the harness's pending authorization waits and times out on its own. An approve or deny naming no live flow lands on the expired-flow page and allocates nothing, like every other flow-id-resolved route. Every attribution event is audited in the fixed vocabulary — `attribution_required` when the page renders, `attribution_approved` and `attribution_refused` at the action — under the trail's existing discipline, with non-credential facts only (client id, client name, redirect URI, resource, kind).

No operator bypass exists: no configured or pre-registered client id buys a skip of the decision page — the client-facing surface carries no client authentication by design, so a crafted link can wear any configured client id with an attacker's own redirect, and an auto-trust keyed on the id would make that link the one shape that skips the page while naming a name the user trusts. The honest zero-page path for a trusted harness is the user's own one approval.

#### Scenario: First attribution renders the decision page and no mint runs
- **WHEN** the identity leg has completed on any of the three mint paths and the (subject, client) is not in the approved-client registry
- **THEN** the decision page is rendered, no mint runs, and one audit record carries the fixed-vocabulary reason (`attribution_required`) — the flow waits for the user's act

#### Scenario: The decision page names the client, the resource, and the redirect destination
- **WHEN** the decision page is rendered for a flow
- **THEN** it names the registration's `client_name` as a name, not a verified fact, with the client id beside it, the addressed resource's kind and served name, and the registered `redirect_uri` the code will be delivered to — and no scope list, the surface's `scope` parameter being accepted and dropped

#### Scenario: Approve records the attribution and continues the flow
- **WHEN** the user approves on the decision page
- **THEN** the attribution is recorded in the approved-client registry keyed to the flow's own verified subject, one audit record carries `attribution_approved`, and the flow continues to the deferred stage — the mint on both short-circuits, the stored continuation and then the display interstitial on the consent branch

#### Scenario: Deny consumes the flow with no code issued
- **WHEN** the user denies on the decision page
- **THEN** the flow record is destroyed, a plain-language page is served, no code is minted and no OAuth error is redirected to any target, and one audit record carries `attribution_refused`

#### Scenario: A replayed or foreign POST advances nothing
- **WHEN** an approve POST is replayed against a flow already advanced, or an approve or deny POST names no live flow — an unknown, expired, or consumed flow id, or one the poster guessed
- **THEN** the response is the expired-flow page, no state is allocated or advanced, and nothing is written to the approved-client registry

#### Scenario: The action carries only the flow id and the decision
- **WHEN** the approve or deny POST arrives at the consent route
- **THEN** it is read for exactly the flow id and the chosen action — every fact the continuation needs is re-derived from the flow record, never round-tripped through the browser

#### Scenario: No operator bypass for a pre-registered client
- **WHEN** a deployment carries configured pre-registered clients and a first-attribution sign-in runs for one of them
- **THEN** the decision page is served exactly as for any other client — no configured or pre-registered client id buys a skip, the surface having no client authentication to key an auto-trust on

### Requirement: The approved-client registry is keyed per subject and client and fails safe on loss

The registry the checkpoint consults MUST be keyed per (subject, client_id): the decision the page carries is "may this client act for me" — an attribution of the client, named on a resource — so an approval covers the client for that user, and the DIAL authorization read still gates every resource separately; the page and the approval's audit record name the resource the approval was granted on. The registry MUST be written only by the approve action, which resolves a live flow whose identity leg completed: there is no other write path, so entry creation is downstream of every bound the flow store already enforces (rate limits, flow cap, TTL), and the entries an attacker can write are keyed to their own verified subject — no other user's approvals are reachable.

Custody MUST be process memory, single instance: an approval is durable for the process's life (no TTL) under a hard cap with oldest-first eviction. Loss MUST fail safe in both directions — a restart forgets approvals (every user re-approves every client once) and eviction under cap pressure forgets the oldest first — and loss of an approval MUST re-prompt, never skip the decision page. The registry MUST NOT persist to any host volume, and the decision MUST NOT be carried in any cookie. Entries MUST be (subject, client id) pairs — non-credential facts; nothing secret and no caller-supplied free text is stored: the keys are the provider-verified `sub` and the resolved client id.

#### Scenario: An approved attribution is consulted and passes through
- **WHEN** a sign-in runs for a (subject, client_id) the registry holds
- **THEN** the registry check passes with no page rendered and the flow runs exactly its pre-checkpoint shape — the short-circuits mint with zero pages, the consent branch serves its display interstitial verbatim

#### Scenario: The approval is the client's, not one resource's
- **WHEN** the same user signs in through the same client for a different resource than the one the approval was granted on
- **THEN** no decision page renders — the approval keyed (subject, client_id) covers the client — and the new resource's own DIAL authorization read still gates the flow as ever

#### Scenario: Registry loss re-prompts, never bypasses
- **WHEN** the process restarts, or the cap evicts the oldest entries under pressure
- **THEN** the affected users' next sign-ins render the decision page again — a lost approval is a re-prompt, never a skip, and no minting path exists that treats a lost approval as granted

#### Scenario: The registry has one write path
- **WHEN** any caller attempts to create a registry entry other than an approve action on a live, identity-completed flow
- **THEN** no entry is created — every entry costs a full sign-in under the flow store's existing bounds, and entries are keyed to the signer's own verified subject
