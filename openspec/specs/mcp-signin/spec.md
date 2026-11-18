# mcp-signin Specification

## Purpose
Lets a harness user sign in to an OAuth-protected DIAL MCP toolset and use it with no DIAL Chat in the deployment: the gateway owns the client-facing OAuth surface, runs the upstream consent through Core's unified credential API, and mints the tokens Core trusts.

## Requirements

### Requirement: Toolset MCP path answers with the gateway's own challenge

Every 401 on the front-door toolset MCP path — no token, invalid token, or a valid token with no stored upstream credential — MUST be answered with the gateway's own challenge: 401 plus `WWW-Authenticate` naming the gateway's protected-resource metadata for that toolset, and the challenge MUST quote the resource path in the caller's own spelling, encoded characters included, so a client that follows it fetches the document for the exact path it called. The upstream's challenge MUST never reach the client, because no client can complete it. Query parameters MUST survive the front-door routing, because streamable-HTTP sessions resume through them.

*Amendment, declared:* the requirement gains the challenge-spelling clause — the challenge quotes the caller's own spelling of the resource path — because the front door's addressing vocabulary is now the resource path (the addressing-vocabulary requirement), whose wire form is percent-encoded and whose router capture is the raw request URI; the synthesized header is built from that same capture, so the quoted path is the called path by construction. Two scenarios are added; the retained scenarios are unchanged and carried verbatim (the query-string scenario's `<name>` becomes `<path>`, the shape it always named).

#### Scenario: No token

- **WHEN** a client calls the toolset MCP path with no Authorization header
- **THEN** the response is 401 with a `WWW-Authenticate` header whose `resource_metadata` names the gateway's protected-resource metadata for that toolset

#### Scenario: Valid token but no stored upstream credential

- **WHEN** a client calls the toolset MCP path with a valid gateway token for a user with no stored upstream credential
- **THEN** the response is 401 with the gateway's own challenge, not the upstream's challenge

#### Scenario: Query string survives routing

- **WHEN** a client sends `GET /dial/<path>/mcp?sessionId=<id>` through the front door
- **THEN** the request reaching Core carries the `sessionId` parameter unchanged

#### Scenario: A multi-segment resource path is routed and challenged

- **WHEN** a client calls `/dial/toolsets/public/<name>/mcp` — a stored toolset's full resource path — with no token
- **THEN** the 401 challenge names `/.well-known/oauth-protected-resource/dial/toolsets/public/<name>/mcp`, the same multi-segment path, and the request is proxied to Core's `/v1/toolset/toolsets/public/<name>/mcp` when authenticated

#### Scenario: An encoded segment's challenge quotes the caller's spelling

- **WHEN** a client calls the toolset MCP path with a percent-encoded segment (`/dial/toolsets/public/<a%20b>/mcp`) and is answered 401
- **THEN** the challenge's metadata URL carries the encoded segment exactly as the client sent it — the router builds the header from the raw capture, never from a decoded re-encoding, so the client can fetch the document it is pointed at

### Requirement: Discovery documents describe one flat authorization server

The gateway MUST serve one RFC 8414 AS metadata document at the host root for a single path-less issuer — the public origin — and one RFC 9728 protected-resource document per served toolset. A toolset is served when its **resource path** passes the request-time path guard (the decoded segment rules, the first-segment reserved names, the byte and depth caps) and is not excluded by the operator restriction when one is configured — and nothing else decides it on this surface: the document is served for every guard-passing, restriction-admitted path, whether or not Core's registry holds it. The gateway's unauthenticated discovery tier is registry-independent by design, mirroring Core's own: Core's MCP path answers an unauthenticated call — for a toolset that exists or one that does not — with 401 and a challenge naming the protected-resource document, because the auth check precedes any registry lookup (a fact of the enabled route — Core's `toolsets.security.authorizationServers` configuration is what serves it; unset, the 401 carries no challenge, and a challenge-less 401 is no existence oracle either), and Core's own unauthenticated protected-resource route answers any well-formed path with a static document built from configuration with the requested path echoed as `resource` (likewise a fact of the enabled route — the same configuration; unset, the route answers 404, which is no existence oracle either, and the gateway serves its own document regardless); no unauthenticated tier on either side of the front door carries an existence oracle, in either configuration. The mirror property is normative: the gateway's tier brings nothing Core's own does not — the same 401-challenge on the data path, the same echo-document at discovery, and existence decided at the same moment, post-authentication, at the flow's per-user listing read (whose refusal for a path Core does not know is the federation requirement's unknown-toolset scenario, the toolset namespace's existence refusal). Discovery therefore makes no Core call at all: no consult, no service credential, no cache, and no Core-unavailable failure shape — the protected-resource document costs the gateway one static document, and its availability is the gateway's own. The AS metadata MUST advertise both grants, S256, token-endpoint auth method `none`, and client-ID-metadata-document support, so CIMD-capable clients register with no registration call; it is a static document and consults nothing. The AS metadata MUST also carry `authorization_response_iss_parameter_supported` with the value `true` (RFC 9207's support member): the advertisement matches the emission — the gateway emits `iss` on every authorization response, success and redirected error alike (the authorization-responses requirement's own discipline), the sibling SHOULD it already satisfies ahead of the MCP `2026-07-28` revision's upgrade path — and the discovery document's member set is fixed, so the member's presence is normative, not incidental. Each protected-resource document MUST name the single AS issuer; its `resource` member echoes the offered spelling of the resource path — Core's own protected-resource route echoes the requested path, and the mirror property carries the echo rule to the gateway's tier, so the document an offered spelling fetches names that spelling's resource, which is the identity RFC 9728 requires of it; for a canonical spelling the echo and the derivation are the same string; its `scopes_supported` echoes the operator restriction's entry where the toolset is pinned there and is empty otherwise; its authentication-kind extension is omitted — under dynamic serving this surface has no authentication-kind source (the mapping's kind declaration is deleted, and the kind a flow acts on is Core's, read per flow at the authenticated listing read). The members are informational, and the scopes the upstream leg sends come from the toolset's Core settings; a client's faithfully echoed `scope` parameter is already accepted and dropped at the authorization endpoint, so an omitted member costs nothing on any leg.

*Amendment, declared (retained):* the requirement's text is amended in one clause only — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" — because a second existence refusal exists once the app read does (the app-resource requirement's unknown-app scenario), so the sentence must state the property per namespace to stay true after the sync; the retained scenarios are unchanged and carried verbatim.

*Amendment, declared (retained — the availability read's re-pinning):* three mentions change — the mirror-property sentence's "at the flow's per-user settings read" becomes "at the flow's per-user listing read", the authentication-kind sentence's "read per flow at the authenticated settings read" becomes "read per flow at the authenticated listing read", and the dynamic-toolset scenario's mirror-property parenthetical follows — because the flow's existence decision moves with the availability oracle to the deployment-listing read (the federation-flow requirement's declared amendment): the settings read the main spec named is authorized by the caller's admin role, a decision the data path never makes, so the flow's authenticated read of the toolset is now the listing read. The mirror property itself is unchanged: existence is still decided post-authentication, at the flow's one authenticated read of the toolset, never on any unauthenticated tier. No scenario's WHEN or THEN changes beyond the parenthetical's named read.

*Amendment, declared:* the requirement's AS-metadata clause gains the `authorization_response_iss_parameter_supported: true` member — RFC 9207's support advertisement, matching the `iss` emission the gateway already makes on every authorization response (the sibling SHOULD satisfied ahead of the MCP `2026-07-28` revision's upgrade path) — because the discovery document's member set is fixed, so the member's presence is a normative advertisement, not an incidental one. One scenario is added; the retained scenarios are unchanged and carried verbatim.

*Amendments, declared (this change):* two clauses change. The served-set sentence is re-based — "a name that passes the request-time name guard (routed-path charset, reserved front-door names)" becomes "its resource path passes the request-time path guard (the decoded segment rules, the first-segment reserved names, the byte and depth caps)" — because the addressing vocabulary is now the resource path and the guard with it (the two ADDED requirements), and the mirror-property parentheticals' vocabulary follows ("for a path Core does not know", "any well-formed path"). The document's `resource` member rule is stated — the echo-offered rule with its reason (Core's own echo document; the RFC 9728 per-spelling identity) — replacing the implied name-derived derivation, which for canonical spellings is identical behavior and for non-canonical spellings is the only rule that keeps the document's identity true for the spelling that fetched it. One retained scenario is re-worded ("Guard-failing name refused at discovery", its title retained as the stable identifier) and two are added (the multi-segment document, the encoded-spelling echo). Two further retained scenarios are re-worded to the path vocabulary, their titles retained as stable identifiers — a wording re-pin, no behavior change: "Unmapped toolset" (its WHEN's "a resource path the configured operator restriction excludes" where it said "a name"), and "Dynamic toolset served without local configuration" (its WHEN's "a resource path that passes the request-time path guard" and its THEN's "path-derived resource URI" where they said a name under the name guard and the "name-derived" derivation). The remaining retained scenarios are unchanged and carried verbatim; the main spec's retained amendment records stay part of the requirement's text as they stand.

#### Scenario: Flat AS metadata fetch

- **WHEN** a client fetches `GET /.well-known/oauth-authorization-server` on the public origin
- **THEN** the document's issuer is the public origin and its authorization and token endpoints are shared by all toolsets

#### Scenario: Per-toolset protected-resource fetch

- **WHEN** a client fetches the protected-resource document for a served toolset
- **THEN** the document returns the toolset's resource URI and the single AS issuer, with the authentication-kind extension omitted and `scopes_supported` echoing the operator restriction's entry where the toolset is pinned there and empty otherwise

#### Scenario: A multi-segment resource path is served its document

- **WHEN** a client fetches the protected-resource document at `/.well-known/oauth-protected-resource/dial/toolsets/public/<name>/mcp`
- **THEN** the document is served, its `resource` naming that path's resource URI, with no Core call made and no gateway-side toolset configuration involved — the mirror property carried to the resource-path vocabulary

#### Scenario: An encoded spelling's document echoes the spelling

- **WHEN** a client fetches the protected-resource document at an encoded spelling of a guard-passing resource path (`…/dial/<a%20b>/mcp`)
- **THEN** the document is served and its `resource` member carries the offered spelling — the echo rule — while the flow, the token audience, and the restriction's verdict treat it as the one canonical resource it is

#### Scenario: Unmapped toolset

- **WHEN** a client fetches the protected-resource document for a resource path the configured operator restriction excludes
- **THEN** the response is 404

#### Scenario: Dynamic toolset served without local configuration

- **WHEN** no operator restriction is configured and a client fetches the protected-resource document for a resource path that passes the request-time path guard
- **THEN** the document is served with the path-derived resource URI and the single AS issuer, with no gateway-side toolset configuration involved and no Core call made — whether Core's registry holds the path is not decided on this surface (the mirror property: the unauthenticated tier is registry-independent, and existence is decided post-authentication at the flow's listing read)

#### Scenario: Guard-failing name refused at discovery

- **WHEN** a client fetches the protected-resource document for a reserved first segment, a segment outside the decoded rules, or an over-length or over-depth path
- **THEN** the response is 404, and one audit record carries the fixed-vocabulary reason with the offered path as a truncated non-credential fact

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

The RFC 8707 `resource` parameter MUST be the required resource disambiguator on both the authorization and token endpoints: a missing resource, a resource whose path fails the request-time path guard of its kind, or a resource that is not the resource URI of a path the guard and the operator restriction of its kind (when one is configured) admit MUST be rejected as `invalid_target`. The resource URI's path shape names the resource kind — `{public-origin}/dial/{path}/mcp` a toolset, `{public-origin}/apps/{path}/mcp` an app, the path one or more segments in the canonical or an accepted equivalent spelling — because one flat authorization server serves both kinds, and the resource is the only thing that says which resource, and which kind, a request is for. The toolset path guard is the decoded segment rules, the first-segment reserved front-door names, and the toolset restriction; the app path guard is the decoded segment rules and the apps restriction — the reserved names do not apply, because nothing the gateway owns is served under the apps namespace's first segment. An accepted spelling is canonicalized at resolution: the flow record, the token audience, and the refresh match carry the canonical form, so two spellings of one resource are one resource. What this endpoint decides is the path's shape and its place in its kind's restriction; whether a guard-passing, admitted path is actually served by Core is not decided here — no Core call is designed at this endpoint, and in dynamic mode a phantom path's resource URI is shape-identical to a served resource's, in either namespace — so existence is decided one leg deeper, at the flow's authenticated read of the named kind, whose refusal for a path Core does not know is the flow requirement's unknown-toolset scenario or the app-resource requirement's unknown-app scenario, the existence refusals, one per resource kind. The only escape is an explicit one-toolset operator setting, which applies only while the toolset restriction is configured with exactly one entry and never consults the apps restriction. A valid request MUST create a flow record keyed by a 128-bit CSPRNG id with a bounded TTL — a guessable id lets an attacker pair their own upstream code with a victim's session. Flow state lives server-side; the browser carries only the flow id.

The client's `state` is OPTIONAL, and its handling is a stated rule: a request carrying one MUST have it stored on the flow record at allocation and echoed back **unchanged** on the final redirect; a request carrying none is tolerated — nothing is echoed — because the CSRF-binding work `state` does for a client is already done by things this surface requires: PKCE S256 is mandatory, the `resource` is required and validated, codes are single-use and short-lived, and the flow id — an unguessable server-side binding — round-trips every browser leg (RFC 9700 §2.1's accepted carrier), and the ecosystem's client contract makes `state` a SHOULD, not a MUST, so refusing it would break conforming clients for zero security gain. One bound lands with the rule: a `state` over **2048 bytes** MUST be refused as `invalid_request` with the fixed-vocabulary reason `oversized_state`, on the flow-record allocation path, before the record exists — every other caller-chosen length on this surface is bounded, and the `state` is caller-chosen text stored on an in-memory record and echoed on a redirect, so its length is bounded with them. The refusal is a pre-allocation refusal and lands on that discipline's audited enumeration.

*Scenario amendment, declared (retained):* the retained "Valid request allocates a flow" scenario is re-worded by this change — "the gateway's public PKCE client" becomes "the gateway's identity-provider client" — because the identity leg's client is a confidential client whose PKCE challenge the identity-leg requirements' toggle governs (the challenge rides on top of the client authentication), so the scenario must name the leg's client without pinning the toggle's position. No other scenario changes; the retained scenario-amendments record below stays part of the requirement's text as it stands in the main spec, its three re-worded scenarios carried unchanged by this change.

*Scenario amendments, declared (retained):* three retained scenarios are re-worded by this change, each named here. "Unknown resource" is re-scoped — from the main spec's toolset-only resource-URI check to the two-shape check the endpoint performs against the request-time guard and the restriction of the resource's kind — because existence is undecidable at this endpoint without a Core call no surface at this stage is specified to make; the backstops that decide it (the flow's per-user listing read for toolsets, the app read for apps) keep their own scenarios in their own requirements. "One-toolset inference" gains its kind scoping — the WHEN names the toolset restriction where the main spec said "the operator restriction", and the THEN gains that inference never consults the apps restriction and never resolves a request to an app — because a second restriction now exists and the inference's dependency is specifically the toolset one. "Guard-failing resource refused" is re-worded for the two-shape guard — the WHEN names the request-time guard of the resource's kind where the main spec named the toolset guard only. The parenthetical's toolset backstop is re-pinned by the availability-read amendment — "the flow's per-user settings read" becomes "the flow's per-user listing read" (the federation-flow requirement's declared amendment) — so the backstop this note names is the read the flow now makes. No Core call is added to this endpoint.

*Amendment, declared:* the requirement gains the `state` rule — OPTIONAL, stored on the flow record at allocation, echoed unchanged on the final redirect when present, absent tolerated with nothing echoed, and over 2048 bytes refused `invalid_request` with the fixed-vocabulary reason `oversized_state` before the record exists — because the main spec never stated the rule the implementation carries (an absent `state` tolerated, the response echoing nothing), and the one caller-chosen length on the allocation path that was unbounded is bounded with it; the refusal joins the pre-allocation audit discipline's existing enumeration, so that requirement needs no amendment of its own. No other parameter handling changes — the endpoint reads exactly the parameters it read before this change. Three scenarios are added; the retained scenarios are unchanged and carried verbatim.

*Amendments, declared (this change):* the served-set sentence is re-based — "a resource whose name fails the request-time guard of its kind" becomes "a resource whose path fails the request-time path guard of its kind"; the path-shape sentence's `{name}` becomes `{path}` with the spelling rule stated; the guard sentence is re-based from "the routed-path charset, the reserved front-door names, and the toolset restriction / the routed-path charset and the apps restriction" to the path guard's decoded rules with the first-segment reserved scoping; and the canonicalization sentence is added — all because the addressing vocabulary is the resource path (the two ADDED requirements). Two retained scenarios are re-worded from name to path (their titles retained as stable identifiers), the retained "App resource accepted" scenario is re-worded with them — its WHEN's "guard-passing, restriction-admitted app path" where it said "app name", a wording re-pin, no behavior change — and one is added (a stored toolset's path accepted). The remaining retained scenarios are unchanged and carried verbatim; the main spec's retained scenario-amendment records stay part of the requirement's text as they stand.

#### Scenario: Missing resource

- **WHEN** an authorization request omits the resource parameter and no one-toolset inference is enabled
- **THEN** the response is an OAuth error with code `invalid_target`

#### Scenario: Unknown resource

- **WHEN** the resource parameter is not the resource URI of a path the request-time path guard and the restriction of its kind, when one is configured, admit
- **THEN** the response is an OAuth error with code `invalid_target` — the endpoint has decided the path's shape, its kind, and its place in that kind's restriction; a guard-passing admitted path that Core does not know is refused later, at the flow's authenticated read of that kind, under that surface's own scenario

#### Scenario: Valid request allocates a flow

- **WHEN** a registered client sends a valid authorization request with PKCE and a known resource
- **THEN** the browser is redirected to the identity provider's authorization endpoint under the gateway's identity-provider client, and the flow record is keyed by an unguessable id

#### Scenario: A stored toolset's path is accepted as a resource

- **WHEN** a registered client sends a valid authorization request whose `resource` is `{public-origin}/dial/toolsets/public/<name>/mcp` — a stored toolset's resource path, guard-passing and restriction-admitted
- **THEN** the request is accepted, the flow record carries the resource's canonical identity, and the flow's later stages address the listing read by the same path

#### Scenario: App resource accepted

- **WHEN** a registered client sends a valid authorization request whose `resource` is an app resource URI naming a guard-passing, restriction-admitted app path
- **THEN** the request is accepted and the flow is allocated for that app resource, and the flow's later stages are the app-resource requirement's — the identity leg, the app read, the kind-driven short-circuit

#### Scenario: One-toolset inference

- **WHEN** the operator enables resource inference and the toolset restriction is configured with exactly one entry
- **THEN** an authorization request without a resource parameter is accepted for that toolset — inference never consults the apps restriction, and never resolves a request to an app

#### Scenario: Guard-failing resource refused

- **WHEN** the resource parameter names a resource path that fails the request-time path guard of its kind — a reserved first segment or a segment outside the decoded rules on the toolset shape, or a segment outside the decoded rules on the apps shape
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

The flow MUST authenticate the user under the gateway's identity-provider client — a confidential client whose code exchange and refresh grant authenticate with the configured client secret in both positions of the leg's PKCE toggle, the challenge riding on top where the toggle enables it — requesting only its client's default scopes; a client's `scope` parameter is never relayed — a relayed scope can fail the leg. This identity leg runs for every served toolset regardless of authentication kind: it establishes who is signing in, never what kind of credential the toolset uses. DIAL authorization is enforced by the deployment-listing read of the toolset as that user — `GET /openai/toolsets/{resource-path}`, the resource path being the same id Core's own routes and responses carry, addressed in the canonical encoding — the read whose authorization decision is the MCP data path's own, because both are Core's deployment resolution of the id against the caller's roles, so the flow's availability oracle and the data path's per-call check are one decision, never two that can disagree — before any upstream round-trip; the upstream code goes to Core's credential API at USER level, with the call's `url` member carrying the decoded resource path and its `redirectUri` member carrying the gateway's derived upstream callback (the upstream-authorization-request requirement's value — never the stored registration field). The read's two refusal codes are two classes with different remedies, never one: a **403 is access denied** — the caller's own lack of access, the deployment resolution's refusal of them, answered with the no-access page and no upstream round-trip — and a **401 is a trust fault**: Core could not validate the sign-in's identity token, an authentication failure whose remedy is the operator's — Core's provider entry for the identity provider (its issuer, its key set, its audience) or the reachability of that key set — never the user's access; the flow fails closed on it with the operator-facing fault page saying the sign-in cannot proceed and an administrator must check the trust configuration, the flow consumed like any other refusal and no credential retained — the record's identity token is the very material Core could not validate — and neither the page nor the audit record names any user-identifying value: an authentication failure is never shown or recorded as an authorization verdict. The listing read itself fails closed on a Core answer that is unreachable or unreadable — the flow fails with the operator-facing fault page, a deployment fault and never an existence answer, rendered as a page distinct from the not-registered page the unknown-toolset scenario carries — and a projection whose authentication-kind value is absent or unusable falls into the impossible branch the same way a non-OAuth kind does: no unreadable answer is ever taken for a not-registered name, and no unreadable kind for a consentable one. That same listing read carries the toolset's public authentication type, the public authentication settings the upstream consent leg builds its URL from — the callback excepted, which the gateway derives and the stored field never supplies — and the caller's per-toolset statuses, and the flow's stages after it are, in order: **the signed-in check** — when Core reports the caller signed in at user level, or the toolset signed in at global level, the upstream stage is skipped entirely and the flow finishes by minting the harness's code, regardless of authentication kind, because a stored credential already exists and no consent could add anything; a status that is absent, unreadable, or FAILED is not signed in, and the check fails closed into the kind branch; then **the kind branch** — the upstream consent stage runs only when no credential is stored and the toolset's kind makes one establishable by consent: an OAUTH toolset continues through the upstream consent exactly as designed (its public OAuth settings — client id, endpoints, challenge — are required on this branch and only this branch; the callback is the gateway's derived one, never the projection's), and a toolset of any other kind is refused with a plain-language page saying its credential is configured directly in DIAL and cannot be established by a consent flow — audited, fail-closed, no upstream round-trip; the refusal loops benignly, like any auth error, until an administrator stores the credential out of band, after which the same flow short-circuits. The flow never establishes a credential at GLOBAL level — the credential call stays at USER level on every path that establishes one — and it never reads or transits any stored upstream credential on any path, the short-circuit included: Core injects the stored credential on the data path, and a GLOBAL credential the short-circuit uses is one an operator configured — the flow uses it, it does not establish it, which is the same access that user already holds through Core's own paths with a primary-provider token. The flow record MUST be destroyed on first use at the upstream callback. The identity provider's session-bound refresh token — issued with the code exchange, with `offline_access` never requested, so no offline grant is ever acquired — is carried for the refresh window as an encrypted claim in the gateway's own refresh token: encrypted at the code grant under the gateway's dedicated custody key, decrypted at every refresh grant, re-encrypted into each rotated refresh token. The plaintext never travels in any client-visible artifact, and the encrypted claim rides the refresh token only — never the access token, never the authorization code. Between flow end and the code grant the token transits a server-side pending entry keyed by the authorization code's id; the provider's access token is discarded at flow end. A code exchange that issues no refresh token MUST fail the flow at sign-in with an operator-facing error naming the deployment prerequisite — the refresh claims re-read requires it, and failing at sign-in is loud and per flow where failing at the first refresh would be hours late. A provider refresh token larger than the configured custody size bound MUST fail the flow the same way, for the same reason: the carrier it must fit inside is a refresh token handed to a harness token store the gateway does not control. The custody size bound and the token-endpoint request-body cap are coupled operator settings and MUST move together: the cap MUST stay at or above the bound plus the envelope's expansion and the JWT overhead (cap ≥ bound + envelope expansion + JWT overhead), so every refresh body the bound lets a sign-in issue passes the cap — a bound raised past the cap's headroom would recreate by configuration the exact far-from-its-cause failure the loud sign-in refusal exists to prevent: sign-ins succeeding while every refresh fails over-cap.

The consent/attribution checkpoint gates the mint on first attribution, after the identity leg and before every mint this requirement's paths issue: once the listing read has run and the flow record carries the resolved client (`client_id`, `client_name`, `redirect_uri`) and the addressed resource, the approved-client registry is consulted on both toolset mint paths — the stored-credential short-circuit consults it before the mint itself, an approved (subject, client) passing through with the flow unchanged and an unapproved one rendering the decision page where the short-circuit minted silently before; the consent branch's checkpoint rides the interstitial's existing position, after the read and before the upstream redirect — on first attribution the interstitial's display-only auto-continue is replaced by the decision page for that one presentation, and once the client is approved the flow keeps the display interstitial verbatim, the notice and the decision being different jobs and only the first attribution lacking the decision. No mint path on the toolset kind completes without passing the registry check. The consent branch's continuation — the upstream authorization URL the branch builds — MUST be stored on the flow record at the decision point, the same discipline the derived upstream redirect URI already follows, because the approve action continues the flow from the record alone; the identity-leg outcomes the approve action needs are record-resident already — the claim snapshot, the client facts, and the provider's session refresh token. The checkpoint's page, action, and registry are the checkpoint requirement's own.

**The deployment prerequisite this flow's consent branch names.** Core MUST carry the gateway's derived upstream callback in its configured `allowedRedirectUris` — Core's exchange-time validation accepts the presented `redirectUri` only from that list (or as the stored field's equal, which this flow no longer relies on) — and each dynamically-registered toolset MUST have Core's repair API re-run after the allowlist carries all the deployment's callbacks, because DCR registers the list once, at creation time. The prerequisite is Core configuration with an operator owner; the configuration reference and the local-environment runbook carry the procedure and its ordering (the gateway's callback first while any stored-field reader remains), and a consent that fails it fails closed at Core's exchange — an operator-facing, per-flow visible failure, never a mis-delivery.

*Amendments, declared (retained):* four clauses change. The opening "the gateway's public PKCE client" becomes "the gateway's identity-provider client — a confidential client whose code exchange and refresh grant authenticate with the configured client secret in both positions of the leg's PKCE toggle, the challenge riding on top where the toggle enables it" — because the identity leg's client shape is the confidential-client requirement's to state, and this requirement must name the leg without pinning the toggle's position; the endpoints the leg uses are the endpoint-source requirements' — the discovery requirement's in discovery mode, the direct-configuration requirement's where the operator configures the endpoint trio — and no clause of this requirement names a provider-specific endpoint spelling. The authorization-bearing read is re-pinned: "fetching the toolset settings as that user" becomes "the deployment-listing read of the toolset as that user — `GET /openai/toolsets/{name}`, the read whose authorization decision is the MCP data path's own", and every "settings read" and "settings answer" mention in this requirement's text and scenarios becomes the listing read's — because the read this requirement previously named (the bucket-based toolset settings read) is authorized by the caller's admin role, a decision the data path never makes, and refused non-admin users toolsets the data path serves — the false denial the live B2C run exposed (the first non-admin identity through the flow); the listing read and the data path share the one authorization decision (Core's deployment resolution), and the read still carries the public authentication type, the public authentication settings the consent branch builds from, and the per-caller statuses. The refusal semantics keep their named shapes and gain the code-level split: a refusal of the authorized caller is the no-access page, a name Core does not know is the unknown-toolset scenario, an unreachable or unreadable answer is the fault page — and the read's two refusal codes are split by this change's trust-fault amendment (D16, authoring round 7): a 403 keeps the access-denied class, while a 401 — which the main spec's denial scenario never named as a code and the implementation folded into the same access-denied refusal — is declared its own trust-fault class, an authentication failure with an operator's remedy, never an authorization verdict, carried by the requirement text above, the re-worded "DIAL authorization denied" scenario (its WHEN names the 403), and the new trust-fault scenario. The retained "Client scope never reaches the identity provider" scenario carries its wording unchanged. Everything else is unchanged and carried whole; the retained scenario-amendment record below stays part of the requirement's text as it stands in the main spec.

*Scenario amendment, declared (retained):* the retained "Unknown toolset refused at the flow's settings read" scenario is re-worded by this change, in two places, both declared here — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" (with the app read named as the app namespace's), and the mirror-property parenthetical gains "in both namespaces" ("on both sides of the front door" becomes "on both sides of the front door in both namespaces") — because the apps surface adds the app read as the apps namespace's existence refusal and extends the mirror property to the second namespace; the property the phrase carried is unchanged and now stated per kind: the existence refusals are the flow's authenticated reads, one per resource kind, and no unauthenticated tier on either side of the front door carries an existence oracle in either namespace. The same scenario's surface is re-pinned by the availability-read amendment: its WHEN's "toolset settings read" becomes the listing read's, because the flow's existence decision moves with the availability oracle to the deployment-listing read (the requirement's declared amendment above) — the refusal's semantics are unchanged, a 404 from Core's deployment resolution for a name it does not know, on the surface the flow now reads. The scenario's title is retained verbatim as its stable identifier (the delta discipline matches scenarios by header against the main spec, so a renamed header would read as a dropped scenario); the title's "settings read" phrase is the identifier's historical spelling, and the body — the normative content — names the surface precisely. Everything else in this requirement is unchanged and governs toolset resources; the app flow is the app-resource requirement's own.

*Amendment, declared:* the requirement gains the checkpoint paragraph — the approved-client registry consulted after the identity leg and before the mint on both toolset mint paths (the stored-credential short-circuit consulting it before the mint itself; the consent branch's checkpoint riding the interstitial's existing position, its display-only auto-continue replaced by the decision page for the first-attribution presentation alone), the consent branch's continuation-storage rule (the built upstream authorization URL stored on the flow record, because the approve action continues from the record alone), and the no-mint-path-without-the-check statement — because the consent/attribution decision gates every mint this requirement issues, and the page, the action, and the registry are the checkpoint requirement's own normative home. Two retained scenarios are re-worded: "Already signed in short-circuits the consent" and "A global credential serves every user without consent" each gain the approved-client condition in their WHEN — the checkpoint gates the mint on first attribution regardless of credential level, so the silent short-circuit is the approved client's, and the first-attribution shapes are the new scenarios' own. Everything else is unchanged and carried whole.

*Amendments, declared (this change):* three clauses change. The listing read is re-addressed — "`GET /openai/toolsets/{name}`" becomes "`GET /openai/toolsets/{resource-path}`, the resource path being the same id Core's own routes and responses carry, addressed in the canonical encoding" — because the front door's addressing vocabulary is now the resource path (the addressing-vocabulary requirement), and the listing route resolves it through the same deployment resolution the data path uses (verified against the Core source and live: a stored toolset at `toolsets/public/{name}` answers this read with its id echoed verbatim). The consent leg's inputs are split — the settings sentence gains "the callback excepted, which the gateway derives and the stored field never supplies", the OAuth-fields parenthetical drops `redirect_uri` from the projection-sourced list, and the credential call's members are named (`url` the decoded resource path, `redirectUri` the derived callback) — because the stored field is a value other editors change at will and the fix removes it from every leg (the upstream-authorization-request requirement's own amendment carries the parameter side). The deployment-prerequisite paragraph is added, stating the allowlist and repair requirements with their owner, because a consent branch that derives its callback needs its deployment prerequisite stated where the flow's contract lives, not only in the runbook. The retained "Upstream consent completes" scenario is re-worded to name the derived callback and the decoded path; the retained "Unknown toolset refused at the flow's settings read" scenario's WHEN is re-pinned from "listing read of the toolset" to "listing read of the toolset by its resource path" — the read's spelling follows the id; the refusal's semantics are unchanged. No other scenario changes; the retained amendment records the main spec carries stay part of the requirement's text as they stand.

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
- **THEN** the gateway calls the credential API with the user's identity token, the upstream code, and the gateway's derived upstream callback URI at USER level, the call's `url` member naming the flow's resource by its decoded path, and Core stores the credential for that user

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

- **WHEN** the authenticated user's listing read of the toolset by its resource path returns no toolset — Core does not know the offered path
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

### Requirement: The consent/attribution checkpoint gates every mint on first attribution

No mint completes without a user-visible act attributing the flow to the client about to be served, on the first attribution of that client to that user. The bound is the drive-by shape: a crafted authorization link can drive a victim's live identity-provider session through the identity leg silently — the gateway relays nothing client-identifying into it — so the decision point that names the client MUST be the gateway's own. The decision point sits after the identity leg completes — the provider's subject verified, the DIAL authorization read run, the flow record carrying the resolved client (`client_id`, `client_name`, `redirect_uri`) and the addressed resource — and before the mint, on all three mint paths: the app kind's zero-page short-circuit, the toolset stored-credential short-circuit, and the toolset consent branch (the two flow requirements' amendments carry the insertion on their paths). At that position the approved-client registry is consulted: an approved attribution passes through with the flow unchanged — zero pages on the short-circuits, the display interstitial verbatim on the consent branch — and an unapproved attribution renders the decision page, and no mint runs until the user's act. The harness's programmatic surface is unchanged: the authorization request still redirects to the identity provider, the callbacks still land, and the final redirect still carries the code, `iss`, and the echoed `state` to the registered redirect; what changes is one response in the browser's sequence, on first attribution only.

The decision page names, each with its honesty rule: the resolved client — the registration's `client_name` where one exists, presented as a name, not a verified fact (the name is registrant-supplied through CIMD or DCR), with the client id beside it always, because it is the verifiable identifier; the addressed resource — the resource kind and the served path, in the pages' plain vocabulary; and the registered `redirect_uri` the code will be delivered to — the one fact a victim can check against expectation and the one a false name cannot forge, because the redirect is the registration's own validated value. No scope list is shown: the client-facing surface accepts and drops the `scope` parameter, and presenting scopes the flow does not act on would be theater. The page is built through the one shared builder, so the web-hardening header family with `form-action 'self'` is inherited by construction, and every interpolated value passes the existing escape discipline — the `client_name` registrant-supplied and the resource path caller-derived, both hostile text in an HTML context. The page is script-free, carries two buttons — approve and deny — in a plain form, and MUST NOT auto-continue (no `meta refresh`): the decision must not navigate itself.

The form posts to `POST /dial/consent` carrying the flow id and the chosen action, and nothing else; the page's other facts are re-derived from the flow record at the action, never round-tripped through the browser. The binding is the flow id itself — 128-bit CSPRNG, server-side record, TTL-bounded, the same binding both callbacks ride; the gateway sets no cookies and holds no ambient browser authority of any kind, so a cross-site POST carries nothing the gateway trusts beyond its own parameters, and the flow id is secret from a link-crafter by construction (it crosses only the victim's browser, on the provider redirect and the callback). The route joins the shared limiter and answers no CORS headers (the abuse requirement's posture).

Approve records the attribution in the approved-client registry, keyed to the flow's own verified subject, audits it with the fixed-vocabulary reason `attribution_approved`, and continues the flow to the stage the decision point deferred: the mint for both short-circuits, the record's stored continuation for the consent branch — after which the display interstitial is served as today. The approve action is single-use-per-flow: a re-presented approve, or a POST against a flow already advanced, lands on the expired-flow page and allocates nothing — one approval cannot mint twice. Deny consumes the flow — record destroyed, identity material dropped, plain-language page, fixed-vocabulary audit reason `attribution_refused` — and no OAuth error is redirected to any target: the decision page is the response, browser-facing refusals are pages, and the harness's pending authorization waits and times out on its own. An approve or deny naming no live flow lands on the expired-flow page and allocates nothing, like every other flow-id-resolved route. Every attribution event is audited in the fixed vocabulary — `attribution_required` when the page renders, `attribution_approved` and `attribution_refused` at the action — under the trail's existing discipline, with non-credential facts only (client id, client name, redirect URI, resource, kind).

No operator bypass exists: no configured or pre-registered client id buys a skip of the decision page — the client-facing surface carries no client authentication by design, so a crafted link can wear any configured client id with an attacker's own redirect, and an auto-trust keyed on the id would make that link the one shape that skips the page while naming a name the user trusts. The honest zero-page path for a trusted harness is the user's own one approval.

*Amendment, declared (this change):* a wording re-pin, no behavior change: the decision page's resource naming follows the resource-path vocabulary (the addressing-vocabulary requirement) — "the resource kind and the served name" becomes "the resource kind and the served path", the escape-discipline sentence's "the resource name caller-path-derived" becomes "the resource path caller-derived", and the page-naming scenario's "kind and served name" becomes "kind and served path" — because the page interpolates the resource's path, whose decoded form the path guard has already refused the markup-breaking characters of. The requirement is otherwise unchanged and carried verbatim; the re-pin is declared so the main spec's vocabulary stays one vocabulary after this change's sync.

#### Scenario: First attribution renders the decision page and no mint runs

- **WHEN** the identity leg has completed on any of the three mint paths and the (subject, client) is not in the approved-client registry
- **THEN** the decision page is rendered, no mint runs, and one audit record carries the fixed-vocabulary reason (`attribution_required`) — the flow waits for the user's act

#### Scenario: The decision page names the client, the resource, and the redirect destination

- **WHEN** the decision page is rendered for a flow
- **THEN** it names the registration's `client_name` as a name, not a verified fact, with the client id beside it, the addressed resource's kind and served path, and the registered `redirect_uri` the code will be delivered to — and no scope list, the surface's `scope` parameter being accepted and dropped

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

### Requirement: The upstream authorization request arrives complete

The upstream authorization request MUST reach the upstream authorization endpoint carrying `response_type=code`, the registered `client_id`, the toolset's public `code_challenge` and `code_challenge_method`, **the gateway's own upstream callback URI, derived from the public origin and the fixed callback path** (`{public-origin}/dial/callback/upstream`), the flow id as `state`, and the toolset's advertised scopes. The callback is derived, never read: the toolset's stored `auth_settings.redirect_uri` — a value Core stores from its allowlist's first entry at registration time and other components (DIAL Chat's editor among them) overwrite with their own callbacks — MUST NOT be an input to this request or to any other leg. Delivery is normative as what the endpoint receives, not what the page contains: a mechanism whose browser step can drop parameters MUST NOT be used, and an undeliverable request MUST fail closed.

*Amendment, declared:* the parameter list's "the upstream `redirect_uri`" becomes "the gateway's own upstream callback URI, derived from the public origin and the fixed callback path", and the never-read clause is added — because the stored field is a value other editors of the toolset change at will (a UX-saved toolset carries the Chat editor's callback), so a flow that reads it sends the user's browser to a page no flow record exists for; the derived callback is the same discipline the gateway's two sibling callbacks already follow, and Core's exchange-time validation accepts a presented `redirect_uri` that is in its configured `allowedRedirectUris` regardless of the stored field. The operator prerequisite this fix names — the gateway's callback present in Core's allowlist, and each dynamically-registered toolset repaired afterwards — is the federation flow requirement's and the configuration reference's to state. The retained scenario is re-worded to name the derived callback; one scenario is added. Everything else is unchanged.

#### Scenario: Continuation delivers every parameter

- **WHEN** the user continues from the interstitial
- **THEN** the URL the browser navigates to carries `response_type=code`, the registered `client_id`, the toolset's public `code_challenge` and `code_challenge_method`, the gateway's derived upstream callback URI, the flow id as `state`, and the toolset's advertised scopes

#### Scenario: A stored field pointing elsewhere never steers the consent

- **WHEN** the toolset's stored `auth_settings.redirect_uri` is another component's callback — a UX-saved toolset carrying the Chat editor's — and the consent branch builds the upstream request
- **THEN** the request still carries the gateway's derived upstream callback, the stored value is not read on any leg, and the consent's code returns to the gateway's callback where the flow record lives

#### Scenario: Undeliverable request fails closed

- **WHEN** the upstream authorization request cannot be delivered with every required parameter present
- **THEN** the flow fails with the plain-language error page and no parameter-less request reaches the upstream endpoint

### Requirement: HTML responses carry the web-hardening header family

Every HTML response the gateway serves — the interstitial, the decision page, and every plain-language error or flow page — MUST carry `Content-Security-Policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` with script execution excluded (the pages are script-free; inline style may use a nonce, hash, or `'unsafe-inline'`), `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Type naming `charset=utf-8`. The `form-action 'self'` directive is stated family-wide: the decision page carries the one form the page surface has, and a directive confining form submission to the gateway's own origin closes the retargeting shape — injected markup that rewrote the form's action would submit to nowhere but the gateway — at the cost of one clause on a policy every page already carries. The decision page is a page class through the one shared builder like its siblings, so the family is inherited by construction and every interpolated value passes the existing escape discipline; and it MUST NOT auto-continue — no `meta refresh`, no navigation of its own — because the decision is the one page on the surface whose whole job is the user's act.

*Amendment, declared:* three changes. The page-class enumeration gains the decision page (a new page class through the one shared builder — this change's checkpoint), because the family's by-construction inheritance is the page's header control. The CSP gains `form-action 'self'`, stated family-wide — the decision page carries the one form the page surface has, and the directive is stated on the policy every page carries rather than per-page, so no page class can drift off it. The requirement gains the no-auto-continue rule for the decision page — the whole difference between it and the display interstitial it replaces on first attribution. The two retained scenarios' THENs gain the directive with the family, and the interstitial's script-free parenthetical is re-worded to the pages' ("the interstitial is script-free" becomes "the pages are script-free") because the decision page is script-free too. One scenario is added for the decision page.

*Amendment, declared (this change):* a wording re-pin, no behavior change: the decision-page scenario's interpolated-value enumeration follows the resource-path vocabulary (the addressing-vocabulary requirement) — "the resource name" becomes "the resource path" — so the escape-discipline assertion names the interpolant the pages actually carry. The requirement is otherwise unchanged and carried verbatim, its earlier amendment record included.

#### Scenario: The interstitial carries the hardening headers

- **WHEN** the interstitial is served
- **THEN** its response carries the Content-Security-Policy with no source permitting script, `base-uri 'none'`, `frame-ancestors 'none'`, `form-action 'self'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and a Content-Type naming `charset=utf-8`

#### Scenario: An error or flow page carries them

- **WHEN** any plain-language error or flow page is served
- **THEN** its response carries the same header set

#### Scenario: The decision page carries the family and does not auto-continue

- **WHEN** the decision page is served
- **THEN** its response carries the same header set with `form-action 'self'` on the Content-Security-Policy, its markup is script-free with no `meta refresh` and nothing that navigates itself, and every interpolated value — the client name, the client id, the resource path, the redirect URI — passes the escape discipline

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

Unauthenticated endpoints that allocate state MUST be rate-limited per source and globally; live flow records MUST be capped with oldest-first eviction. Every unauthenticated body-bearing endpoint MUST cap the request body in bytes at reading; over-cap is refused. Expired, evicted, and unknown flows MUST land on a plain-language re-run page, never an opaque failure. Every resource path the guard resolves — on the discovery routes, the authorization endpoint, and the token endpoints' resource parameters — MUST be bounded before any work proportional to it: the decoded path MUST NOT exceed 900 UTF-8 bytes and its segment count MUST NOT exceed the configured cap, and an over-bound path is refused with the surface's fail-closed shape and a fixed-vocabulary reason — the bounds make each admitted request's cost constant, whatever the path's length or depth. The identity provider's session refresh token, while carried, is bounded by the refresh token's original absolute expiry, and its plaintext is presented exactly one refresh-grant call per gateway refresh — purposes named, not counted; the bounds govern the gateway's carrying of it, never the credential's usability, which is the provider's own session policy. The token's plaintext is never delivered to any client and never written to any log; the encrypted claim is delivered inside the refresh token by design and is unusable without the custody key. The identity access token's retention is unchanged by this design: it is exposed at most min(flow TTL, its own expiry) — the TTL bounds the gateway's retention, not the token's life — as before. Each protected-resource discovery endpoint — the toolset route and the apps route — MUST join the same per-source and global rate limiter as every other unauthenticated surface, so its guard refusals — each of which writes an audit record — cannot be written faster than the requests that carry them: without the limiter, an unauthenticated caller looping guard-failing paths would grow the operator's log at whatever rate it chose. Over the limit either endpoint MUST be answered with the limiter's 429 and MUST write no record at all, so the bound holds at the limit itself.

The authorization-server surface is back-channel only toward browsers, as a rule and not an implementation accident: no endpoint on the surface serves any `Access-Control-*` header — the browser-facing routes (`/dial/authorize`, the callbacks, the consent route) and the back-channel endpoints (`/dial/token`, `/dial/revoke`, the discovery documents, the registration endpoint) alike — no preflight is handled (an `OPTIONS` preflight against `/dial/token` receives the framework's 405), and a browser frontend is not a supported client shape: the clients are harness processes exchanging codes and tokens on their own loopback redirects and back channels, and a cross-origin browser page can neither read a token response nor drive the authorize surface's redirects. RFC 9700 §2.6 permits CORS at the token endpoint as a MAY and forbids it at the authorization endpoint; the gateway declines the MAY, surface-wide, and this spec says so.

*Scenario amendments, declared (retained):* the limiter clause is re-worded by this change — "The protected-resource discovery endpoint" becomes "Each protected-resource discovery endpoint — the toolset route and the apps route" — because the apps surface adds a second discovery route of the same class; and the retained "Over-limit discovery requests" scenario's WHEN is re-worded to name both routes ("— on the toolset route or the apps route —" inserted) so the scenario governs the class explicitly. No other scenario changes.

*Amendment, declared:* the requirement gains the CORS/back-channel posture paragraph — no `Access-Control-*` header on any endpoint of the authorization-server surface, browser-facing or back-channel, no preflight handling, and a browser frontend not a supported client shape — because the posture is today true by omission (no CORS middleware exists anywhere) and this change makes it a rule a future middleware line cannot silently undo; the paragraph's home is this requirement because the main spec carries no requirement titled for the token grant itself, and this requirement governs the unauthenticated AS endpoint set the posture spans — the design's token-grant phrase resolves here. No behavior change backs the statement: the code already is the posture, and the change is the rule and its machine-checkable pin (the pin itself is repo material, the header-assertion test battery's). One scenario is added; the retained scenarios are unchanged and carried verbatim.

*Amendment, declared (this change):* the path-bounds sentence is added — every resource path the guard resolves is bounded (900 decoded UTF-8 bytes, the configured segment-count cap) and refused before any work proportional to it — because the resource-path vocabulary admits arbitrarily long and deep caller-chosen inputs where the one-segment name vocabulary bounded them by construction, and the bound belongs with the surface's other stated bounds rather than only in the path-guard requirement. One body clause is re-pinned with it — the rate-limit paragraph's "an unauthenticated caller looping guard-failing paths" where the one-segment vocabulary said "looping guard-failing names", a wording re-pin, no behavior change. One scenario is added; the retained scenarios are unchanged and carried verbatim; the main spec's retained amendment records stay part of the requirement's text as they stand.

#### Scenario: Flooding rate-limited

- **WHEN** authorization requests arrive from one source beyond the configured per-source limit, or overall beyond the global limit
- **THEN** excess requests are rejected without allocating flow records

#### Scenario: Over-limit discovery requests are refused without a record

- **WHEN** protected-resource discovery requests — on the toolset route or the apps route — arrive from one source beyond the configured per-source limit, or overall beyond the global limit
- **THEN** excess requests are answered with the limiter's 429 and write no audit record — the guard-refusal record volume is capped by the same limit as the request rate, and a refused request adds nothing to the trail

#### Scenario: An over-bound resource path is refused before proportional work

- **WHEN** a discovery or authorization request offers a resource path over 900 decoded UTF-8 bytes or over the configured segment-count cap
- **THEN** the path is refused with the surface's fail-closed shape and a fixed-vocabulary reason, before any document build, Core call, or flow allocation — an over-bound path costs the same as any refused request, never more

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

### Requirement: Refusals before flow allocation are audited

Every refusal before a flow is allocated — `/dial/authorize` validation refusals, client resolution, `/dial/register`, `/dial/token`, `/dial/revoke` form refusals, discovery misses, and rate-limit 429s — MUST be recorded with a fixed-vocabulary reason and the non-credential facts (client id, redirect URI, resource, toolset), each fact truncated to the configured cap; a 429 record MUST carry the reason only; no credential or free-form caller input may reach the record. The path guard's refusal classes join the fixed vocabulary with their own reason tokens — a forbidden or trailing-dot character, a dot or empty segment, an over-length or over-depth path, and a reserved first segment are each distinguishable on the trail from a restriction exclusion — and the offered resource path is recorded as the truncated `resource` fact, the same truncation discipline every caller-supplied fact already passes.

*Amendment, declared:* the refusal enumeration drops `/dial/{name}/status` — the status endpoint's refusals leave the audited set because the status endpoint itself leaves the gateway, both namespaces (the REMOVED entry below); the status-only refusal reason tokens retire with the endpoint, and every reason token a remaining surface uses stays. The retained scenarios are unchanged and carried verbatim.

*Amendment, declared (this change):* the path-guard reason tokens are added to the fixed vocabulary and the path fact's truncation is stated — because the path guard (the ADDED requirement) introduces refusal classes the trail must distinguish, and the resource fact's value is now a path whose length the caller chooses. The retained scenarios are unchanged and carried verbatim (the pre-allocation scenario's enumeration gains "or guard-refused"); the main spec's retained amendment records stay part of the requirement's text as they stand.

#### Scenario: Pre-allocation refusal audited

- **WHEN** an authorization request is refused before any flow is allocated — an unknown client, an unregistered redirect URI, or a missing, unknown, or guard-refused `resource`
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

### Requirement: Authorization responses identify their issuer

Every authorization response returned to the client — the success redirect carrying the code and every error redirected to a validated client redirect URI — MUST carry the `iss` parameter (RFC 9207) equal to the gateway's issuer: the public origin, the same value the authorization-server metadata document advertises. The flat single-issuer design makes the parameter necessary: a client that talks to several authorization servers tells which one answered by `iss` alone.

#### Scenario: Success redirect carries the issuer
- **WHEN** a valid authorization request completes and the browser is redirected back to the harness with the code
- **THEN** the redirect carries `iss` equal to the gateway's issuer, alongside the code and the echoed `state`

#### Scenario: Redirected error carries the issuer
- **WHEN** an authorization request fails after the client and its redirect URI are validated, and the error is redirected to the client
- **THEN** the redirect carries `iss` equal to the gateway's issuer, alongside the error and the echoed `state`

#### Scenario: A harness matches `iss` against the AS metadata document
- **WHEN** a harness that talks to several authorization servers receives the gateway's authorization response and reads its `iss`
- **THEN** the value matches the issuer of the authorization-server metadata document the harness discovered, so the response is attributable to this authorization server and not to another

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

### Requirement: Inbound tokens are verified with pinned algorithm and key selection

Inbound JWT verification MUST pin the algorithm and the key selection, so a token's header can select neither. The gateway's own tokens — codes, access tokens, refresh tokens — are verified against the gateway's own signing keyset under the pinned algorithm, with the issuer checked: the token's `kid` selects the entry — the active key or a retained key — and a token whose `kid` names no entry of the keyset is refused as not issued by this gateway, so the `kid` is a selector within the keyset, never a source of key material and never a fetch. The identity provider's tokens are verified under a pinned algorithm and the configured issuer, with the `kid` resolved only in that provider's own published key set — the key set the provider's discovery document names — origin-bound, like every discovered endpoint — or, where the operator configures the endpoints directly, the key-set URL the operator configures; key material embedded in a token header is never used. A token whose header carries no `kid` resolves to the provider's first published RSA signing key — the behavior the implementation has, stated so a from-spec reimplementation cannot silently refuse such tokens; with a single-key key set the resolution is unambiguous, and across rotation its failure mode is fail-closed (a mismatched resolution fails verification, never accepts a forgery kid-resolution would refuse). The issuer check is exact-string against the configured issuer: a provider whose issuers vary across its sign-in journeys — the issuer embedding the journey that issued the token — has the one federated journey's issuer configured, and a token whose issuer differs in any way — another journey's issuer of the same provider included — MUST be refused as not issued by the configured provider.

*Amendment, declared (retained):* the requirement gains the endpoint-source key-set resolution clause ("the key set the provider's discovery document names — origin-bound, like every discovered endpoint — or, where the operator configures the endpoints directly, the key-set URL the operator configures"; the origin-bound qualifier belongs to the discovery alternative only — the operator-configured key-set URL is operator input at the issuer setting's own trust level, not a discovered endpoint) and the varying-issuer pinning sentence with its scenario — because the key set's location is the leg's one configured source's to name (the discovery document's in discovery mode, the operator's in direct mode), and issuers that vary across a provider's sign-in journeys are the shape that sentence covers. The refusal is gateway-side by construction: the pin is exact-string against the configured issuer, and no token and no discovery document can widen it; whether another journey's tokens carry a distinct issuer at all is provider-configuration — the provider must issue journey-distinct issuers for its journeys to be distinguishable by the pin (an operator prerequisite the change's configuration reference states, not a property this spec grants). The pinned-algorithm and no-kid rules are unchanged.

*Amendment, declared:* the requirement's own-tokens clause is re-worded — "verified against the gateway's own signing key under that key's pinned algorithm" becomes "verified against the gateway's own signing keyset under the pinned algorithm", with the `kid`-selects-within-the-keyset rule and the unknown-`kid` refusal — because the single-key shape becomes a keyset with active and retained entries (the signing-keyset requirement, this change), and own-token verification must accept the retained entries through the drain window while remaining pinned (the algorithm stays pinned; the `kid` selects within a startup-fixed keyset, never fetches). One retained scenario is re-worded — "Embedded key refused": "checks the signature against the pinned key only" becomes "checks the signature against the pinned key set's selected entry only, never header-carried material" — because the pin is now a keyset on the gateway's own side, the same re-wording the own-tokens clause carries; the scenario's property is unchanged, whichever side pinned the key material. Two scenarios are added; the remaining retained scenarios are unchanged and carried verbatim.

#### Scenario: Algorithm confusion refused

- **WHEN** a presented token carries an algorithm other than the pinned one — `alg: none` included
- **THEN** verification refuses it; the algorithm is never taken from the token

#### Scenario: Embedded key refused

- **WHEN** a token's header carries its own key material — an embedded `jwk` or `x5c`
- **THEN** verification ignores it, checks the signature against the pinned key set's selected entry only, never header-carried material, and refuses the token

#### Scenario: `kid` outside the provider's key set refused

- **WHEN** an identity token's `kid` names a key absent from the issuing provider's own published key set
- **THEN** the lookup fails and the token is refused as not issued by that provider

#### Scenario: Key set resolved from the leg's one endpoint source

- **WHEN** the identity provider's tokens are verified
- **THEN** the key set they are resolved against is the one the leg's configured source names — the discovery document's in discovery mode, the same source the token and authorization endpoints come from; the operator-configured key-set URL in direct mode — never a URL built by provider-specific arithmetic

#### Scenario: A token from another journey's issuer refused

- **WHEN** the identity provider's issuers vary by sign-in journey, and a token arrives whose `iss` names any issuer other than the configured one — another journey of the same provider included
- **THEN** verification refuses it: the configured issuer is the one this deployment federates, and no other journey's token is accepted by it

#### Scenario: A retained-key token verifies through the drain window

- **WHEN** a gateway-issued token signed under a key demoted to retained is presented while the entry is still in the keyset
- **THEN** verification accepts it — the `kid` selects the retained entry, the algorithm is the entry's pinned one, the issuer check unchanged — the drain window's whole point

#### Scenario: An unknown `kid` on an own token is refused

- **WHEN** a token presented as the gateway's own carries a `kid` that names no entry of the gateway's keyset — a removed retained key's `kid` included
- **THEN** verification refuses it as not issued by this gateway — the `kid` selects within the startup-fixed keyset and nothing else

### Requirement: The toolset mapping is an optional operator restriction

The mapping is an optional operator restriction: unset, the gateway serves every toolset whose **resource path** passes the request-time path guard; set, only its entries are served. Entries are resource paths — a bare config-entity name or a stored toolset's full path (`toolsets/{bucket}/{folders…}/{name}`) — and restriction membership is decided on the canonical form, so no spelling of a restricted-out resource can enter by encoding. Configured entries keep the startup refusals that protect static routing — a reserved first segment, a segment outside the decoded rules, a trailing dot, a dot or empty segment, an over-length or over-depth path each refuse the container's start with an operator-facing error naming the entry and the rule it broke — because the front router's locations are static configuration with no view of what Core serves, so neither can be repaired at request time for a path the operator pinned. A restriction entry declares no authentication kind at all (the retained rule: the kind a flow acts on is Core's, read per flow), and a non-OAuth toolset is a valid entry, because the flow serves it through the signed-in short-circuit when a credential is stored and refuses it on the impossible branch otherwise. The apps restriction is a separate restriction of the same shape for the apps namespace, and the two never consult each other. Resource inference MUST refuse to start when it is enabled without the toolset restriction configured with exactly one entry: with a dynamic served set there is no "the one toolset" to infer, and inferring silently is how a token ends up addressed to a toolset the client never named — and inference never consults the apps restriction, because a second namespace served by the same authorization server makes an unnamed resource even less inferable than one.

*Scenario amendment, declared (retained):* the retained "Inference without a single-entry restriction refused" scenario's WHEN clause is re-worded — "no restriction is configured, or the configured restriction" becomes "no toolset restriction is configured, or the configured toolset restriction" — because a second restriction now exists and the inference's startup dependency is specifically the toolset one; the requirement text gains the sentences that the apps restriction is a separate restriction of the same shape and that the two never consult each other. No other scenario changes.

*Scenario amendment, declared (the availability read's re-pinning):* the retained "Unset mapping serves dynamically" scenario's THEN is re-pinned — "learned at the flow's authenticated settings read" becomes "learned at the flow's authenticated listing read" — because the flow's existence decision moves with the availability oracle to the deployment-listing read (the federation-flow requirement's declared amendment); the scenario's property is unchanged: the registry a harness can actually use is Core's, learned post-authentication at the flow's one authenticated read of the toolset. No other scenario changes.

*Amendments, declared (this change):* the served-set sentence is re-based from names to resource paths; the entries sentence and the canonical-membership rule are added; and the startup-refusal sentence is re-based — "a reserved front-door name and a name outside the routed-path charset" becomes the path guard's refusal classes (a reserved first segment; a segment outside the decoded rules; a trailing dot; a dot or empty segment; an over-length or over-depth path) — because the restriction's entries follow the addressing vocabulary (the two ADDED requirements) and the startup guard is the request-time guard's twin at configuration time. Two retained scenarios are re-worded (their titles retained as stable identifiers), the retained "Unset mapping serves dynamically" scenario is re-worded with them — its THEN's "toolsets are served whose resource paths pass the request-time path guard" where it said "whose names pass the request-time name guard", a wording re-pin, no behavior change — and one is added (a stored toolset's path as an entry). The remaining retained scenarios are unchanged and carried verbatim; the main spec's retained amendment records stay part of the requirement's text as they stand.

#### Scenario: Reserved name refused

- **WHEN** the mapping lists a toolset path whose FIRST segment is a reserved front-door name — `/dial/{token}/…` would be captured by the authorization-surface location
- **THEN** the gateway refuses to start with an operator-facing error naming the reserved names — and a reserved name appearing only in a later segment (`toolsets/public/token`) is NOT refused: the capture is a first-segment match, and no stored path's first segment can collide with it

#### Scenario: Name outside the routed charset refused

- **WHEN** the mapping lists a toolset path with a segment outside the decoded rules — a forbidden character (`{`, `}`, `"`, a control), a trailing dot, a `.`/`..` segment, or an over-length or over-depth path
- **THEN** the gateway refuses to start with an operator-facing error naming the entry and the rule, so a path the router's grammar could never route fails at configuration time, not in operation

#### Scenario: A stored toolset's path is a valid entry

- **WHEN** the mapping lists `toolsets/public/<name>` — a stored toolset's full resource path, guard-passing
- **THEN** the entry is accepted, and requests naming that path, in any accepted spelling, are served while every other path is refused with the restriction's refusal — the exact-membership semantics names always had, carried to paths

#### Scenario: Non-OAuth entry accepted

- **WHEN** the restriction lists a toolset whose Core authentication type is not OAUTH
- **THEN** the entry is accepted: its kind is Core's to answer per flow, and the flow serves it through the short-circuit when a credential is stored — the entry carries no kind declaration of its own

#### Scenario: Removed mapping member refused at parse

- **WHEN** an operator's mapping document still carries the removed `authentication_type` member
- **THEN** the gateway refuses to start with an operator-facing error naming the field — the mapping's schema forbids unknown members, so the one breaking operator change fails loudly at parse rather than the removed kind declaration being silently ignored

#### Scenario: Unset mapping serves dynamically

- **WHEN** no mapping is configured
- **THEN** the gateway starts, and toolsets are served whose resource paths pass the request-time path guard — the documents are registry-independent (the mirror property), and the toolsets a harness can actually use are the ones Core's registry holds, learned at the flow's authenticated listing read

#### Scenario: Inference without a single-entry restriction refused

- **WHEN** resource inference is enabled and no toolset restriction is configured, or the configured toolset restriction does not have exactly one entry
- **THEN** the gateway refuses to start with an operator-facing error naming the setting and what it requires

#### Scenario: Inference never resolves to an app

- **WHEN** resource inference is enabled with its single-entry toolset restriction and an apps restriction is also configured, or not
- **THEN** an authorization request without a resource parameter is still resolved only to that toolset — never to an app, however many apps are served

### Requirement: Refresh re-reads current claims from the identity provider

Refreshing MUST re-read the user's current claims before minting: the gateway presents the identity provider's session-bound refresh token — carried, encrypted, in the gateway's own refresh token — to the provider's discovered or directly configured token endpoint (RFC 6749 §6, the refresh grant) — the same endpoint the code exchange uses, one spelling of the identity leg — and the minted access token's claims are the verified fresh token's, under the same copy and overlay rules as issuance and through the same verification path (the provider's published keys, the pinned issuer). The mechanism carries two deployment requirements, each failing loudly where unmet: the identity provider MUST issue refresh tokens to the gateway's client at the code exchange (a provider that does not fails every sign-in with an operator-facing error naming the prerequisite), and the provider's session-bound refresh token MUST remain usable across the refresh window under the provider's session policy — an operator prerequisite stated by the startup bound below, never silently assumed. The fresh token's `sub` MUST equal the refresh token's subject, or no token is minted; its parsing is bounded and fails closed. The gateway's refresh token MUST NOT carry a claim snapshot — the verified fresh read is the mint's only claim input, so a frozen-snapshot fallback has no data to serve and MUST NOT be reintroduced; the token's one non-binding payload member is the encrypted custody claim, which is ciphertext, never a mint input. Any failure of the read — the provider unreachable, the provider refusing the grant, the answer unusable, a subject mismatch, the roles source path absent, or the carried credential absent or undecryptable — MUST refuse the refresh with `invalid_grant`, and the refusal MUST be audited with a fixed-vocabulary reason distinct from every other `invalid_grant` refusal: a session-ended reason keyed on the provider's `invalid_grant` refusal specifically (RFC 6749 §6's session-gone code — the session is gone: revoked, expired by session policy, or consumed by a lost rotation), a claims-read reason for every other failure of the read, other provider 4xx refusals included (`invalid_client` from a misconfigured client secret or `invalid_request` from a gateway bug say nothing about the session), and a custody reason of its own for the decrypt-side failures — the claim absent, tampered, encrypted under an unknown key-id or version, expired as an envelope, or bound to another subject — so a provider outage, a session-policy break, a misconfiguration burst, and a custody-key or rotation fault are each distinguishable on the audit trail from mass token revocation. An identity-provider session revocation therefore ends the gateway's refresh capability at the next refresh attempt — the carried session refresh token dies with the session. Refreshing MUST NOT contact the upstream. Rotation MUST be default-on with a short grace window, and the rotated token MUST keep the original absolute expiry (non-sliding); where the provider rotates its own refresh token, the carried credential MUST track the latest, re-encrypted into each rotated gateway refresh token. The refresh TTL MUST NOT exceed the operator-declared identity-provider session bound — operator settings, validated at startup, because the carried session refresh token must remain usable at every refresh in the window; the declared value is an operator assertion about the provider's session policy, and where that policy is short, the short window is the correct configuration. Revocation denylists refresh-token ids until expiry. A refresh MUST match its issuance resource.

*Amendment, declared:* one clause changes — "to the provider's token endpoint" becomes "to the provider's discovered or directly configured token endpoint (RFC 6749 §6, the refresh grant) — the same endpoint the code exchange uses, one spelling of the identity leg" — because the endpoints now come from the leg's one configured source (the discovery document in discovery mode, the operator's endpoint trio in direct mode), and the refresh grant and the code exchange addressing different endpoints would be two spellings of the identity leg. No scenario changes.

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

### Requirement: Resource paths are the front door's addressing vocabulary

The front door's resource name segment is a **resource path**: one or more path segments, each percent-encoded as needed, whose decoded form is Core's deployment id — a bare name for a config entity (`notion`), `toolsets/{bucket}/{folders…}/{name}` for a stored toolset, `applications/{bucket}/{folders…}/{name}` for a stored app. The routed shapes are `/dial/{path}/mcp` → Core's `/v1/toolset/{path}/mcp` and `/apps/{path}/mcp` → Core's `/v1/deployments/{path}/mcp`, and the path is the one string every Core surface keys on — the MCP route's greedy capture, the deployment listing route's id, the app read's id, and the credential API's toolset url — so the front door forwards the identifier rather than mapping it. The forwarding MUST be byte-faithful: the router MUST NOT decode the path before proxying, so a request the front door forwards is byte-identical to the request the client would have sent to Core's own port, and Core's answer through the front door is Core's answer, always. The router's capture MUST be a grammar, not a wildcard: a raw request URI whose segments do not conform to the path grammar's wire form (each segment unreserved characters or percent-escapes, no empty segment, no whole-segment `.` or `..`, no trailing dot, and the `/mcp` suffix present) MUST be refused by the router with 404 and never forwarded. The capture's match domain is the **whole raw request URI**: the grammar is anchored at both ends, admits an optional `?query` tail after `/mcp`, and admits nothing after `/mcp` but that query — so a query-bearing request (a streamable-HTTP session resume, `…/mcp?sessionId=<id>`) matches and routes with its query forwarded raw and intact, and a path tail after `/mcp` (`/dial/{path}/mcp/extra`) is refused 404 and never forwarded onto the data-path prefix.

One **canonical encoding** is derived per resource path — unreserved characters raw, every other character `%XX` with uppercase hex over UTF-8 — and the derivation's order is pinned — segmentation precedes decoding: the path is split on raw `/` into segments, and each segment is then strictly-UTF-8 decoded, guard-validated, and re-encoded, so a decode-then-split order — which would merge a `%2F`-escaped segment boundary and a raw `/` onto one canonical identity, the merge direction T-EP1-b prices — is excluded. The derivation's decode step is pinned: percent-escapes decode as **strict UTF-8**, an invalid, over-long, or surrogate (CESU-8-style) sequence refused with the guard's fixed reason — never lossily replaced, which would merge distinct wire spellings onto one replacement-character identity, the aliasing merge direction — and `+` is a literal character in path position, never a space. The canonical resource URI (`{public-origin}/dial/{path}/mcp`, `{public-origin}/apps/{path}/mcp`) is the resource's identity: the flow record, the token audience, the refresh grant's resource match, and the operator restriction's membership check all use the canonical form, so two spellings of one resource are one resource and never two. A guard-passing, restriction-admitted spelling that differs from canonical is accepted on the authorization and token endpoints and canonicalized for identity; the protected-resource document's `resource` member echoes the offered spelling, mirroring Core's own protected-resource route, which echoes the requested path — the document an offered spelling fetches names that spelling's resource, which is the identity RFC 9728 requires of it.

**The matrix this vocabulary serves, with its rulings stated.** Stored toolsets and apps in public, platform, and user buckets are addressed by their full resource paths; a user bucket's segment is a Base58 ciphertext of `Users/{sub}` that no client computes and every client receives verbatim from Core's own responses, so a harness that learned a resource from Core presents its exact path through the front door, and per-caller isolation is unchanged in kind — Core decrypts the segment and applies the same per-caller access chain on the front-door data path and the flow's listing read that it applies on its own port; the ciphertext was client-visible data before this requirement existed, and the front door adds no disclosure. Folder-nested paths are served mechanically, exactly as Core's own greedy resolution routes serve them. Toolset names Core accepts (`[A-Za-z0-9-_]` at Core HEAD) and application names Core accepts (`[A-Za-z0-9._%:-]`) are served in their canonical encodings. What the front door refuses is refused by ruling, each stated: segments carrying Core's forbidden characters (`{`, `}`, `"`, control characters ≤ U+001F) — Core's own resolution-time rule, refused as parity, never as a cut; trailing dots — a front-door ruling, stated as one: it mirrors Core's creation-side constraint (Core's write and upload routes refuse trailing-dot names) and is deliberately stricter than Core's resolution, which resolves a trailing-dot name that already exists on the blob store, so it is offered to the owner pause as a ruling, never claimed as parity; a `%2F` inside a segment — the only reachable wire spelling of a decoded `/` within a segment — forwarded byte-faithfully for Core to answer as it answers on its own port (Core's resolution refuses a decoded `/` inside a filename, so the answer is Core's own refusal — same-answer behavior, not a gateway cut); and raw, unencoded non-ASCII or unsafe characters in the request-target — a wire-spelling refusal, never a resource refusal, since every such name is servable in its encoded canonical form.

#### Scenario: A stored toolset in the public bucket is served end to end

- **WHEN** a toolset is stored in Core at `toolsets/public/{name}` and a harness points at `/dial/toolsets/public/{name}/mcp` through the front door
- **THEN** the unauthenticated call is answered 401 with the gateway's challenge naming the protected-resource document for that path, discovery serves the document, the flow's listing read `GET /openai/toolsets/toolsets/public/{name}` resolves the toolset, and a live tool call through the front door succeeds — the path is the one identifier on every leg

#### Scenario: A user-bucket resource is addressed by its verbatim path

- **WHEN** a harness holds a user-bucket resource path Core's own listing handed it (`toolsets/{ciphertext}/{name}`) and points at `/dial/toolsets/{ciphertext}/{name}/mcp`
- **THEN** the front door routes it exactly as it routes any stored path, Core applies the caller's per-call access decision on the data path, and the flow's listing read applies the same decision before any mint — another user's ciphertext is refused 403 for a caller without access, and the owner's own passes

#### Scenario: An encoded segment is forwarded byte-faithfully

- **WHEN** a client calls `/dial/toolsets/public/{a%20b}/mcp` — a toolset name containing a space, percent-encoded — through the front door
- **THEN** the request Core receives carries `a%20b` byte-identically (never a decoded space, never a re-encoded variant), Core's answer crosses the router untouched, and the 401 challenge quotes the client's own spelling of the metadata path

#### Scenario: A dot-segment or empty-segment path is refused by the router

- **WHEN** a client sends `/dial/{a/../b}/mcp` or `/dial/{toolsets//public/x}/mcp` with the dot-segments or empty segment in the raw request URI
- **THEN** the router answers 404 without forwarding — the grammar refuses whole-segment `.`/`..` and empty segments, so nginx's own normalization can never re-key a path the gateway validated against a different shape

#### Scenario: A path tail after `/mcp` is refused by the router

- **WHEN** a client sends `/dial/{toolsets/public/x}/mcp/extra` or `/apps/{applications/public/x}/mcp/extra` — a conforming resource path followed by a path tail after the `/mcp` suffix — in the raw request URI
- **THEN** the router answers 404 without forwarding — the grammar's match domain is the whole raw request URI with nothing after `/mcp` but the optional query, so the capture cannot alias a longer path onto the data-path prefix

#### Scenario: An over-encoded spelling canonicalizes to one identity

- **WHEN** a client offers a `resource` parameter spelled with a non-canonical escape (`%78` where the canonical form carries `x`) for a guard-passing, restriction-admitted path
- **THEN** the request is accepted, the flow record, the token audience, and the restriction's verdict all carry the canonical form — the same identity the plain spelling produces — and the discovery document fetched at the offered spelling echoes the offered spelling as its `resource`

#### Scenario: An invalid UTF-8 escape sequence is refused, never lossily decoded

- **WHEN** a resource path offers a segment whose percent-escapes decode to an invalid, over-long, or surrogate UTF-8 sequence (`%FF`, `%C0%AF`, `%ED%A0%80`)
- **THEN** the path is refused with the guard's fixed-vocabulary reason on every surface that resolves it — distinct wire spellings never merge onto one replacement-character identity — and a `+` inside a segment is carried as the literal character, never decoded as a space

#### Scenario: An app name with the wider charset is served

- **WHEN** an application is stored in Core at `applications/public/{MyApp.v2}` — a name with uppercase and a dot, Core's application-name rule — and a harness points at `/apps/applications/public/{MyApp.v2}/mcp`
- **THEN** the app resource is served through the apps front-door path exactly as a bare-named app is, the document and the flow addressing it by its canonical encoding, and nothing in the gateway re-implements Core's per-type name rules

### Requirement: Resource paths are guarded at request time

Every resource path the gateway resolves — the protected-resource document's path, the authorization request's `resource`, and the refresh grant's resource — MUST pass one path guard before it names a served resource, and the guard operates on the **decoded** path, never the wire spelling. Per segment: the segment MUST be non-empty and MUST NOT be `.` or `..`; it MUST NOT contain `{`, `}`, `"`, or any character ≤ U+001F — Core's own forbidden set for resource names, and exactly the characters that break the challenge header's quoting and the HTML pages' escaping; and it MUST NOT end with a dot — a front-door ruling: it mirrors Core's creation-side constraint (Core's write and upload routes refuse trailing-dot names) and is deliberately stricter than Core's resolution, which resolves a trailing-dot name that already exists — declared as a ruling, never claimed as Core parity. The whole decoded path MUST NOT exceed 900 UTF-8 bytes — the value of Core's own path-size bound, adopted deliberately with its semantics stated: Core's 900-byte bound applies to the resource's absolute storage path (bucket location plus relative path), not the resource URL, so the same number capping the decoded resource path — longer by its type segment — is deliberately stricter at the 890–900-byte edge, an acknowledged edge cut chosen so the front door never advertises a path Core must refuse for length — and MUST NOT exceed the configured segment-count cap, the gateway's own stated anti-abuse bound (no Core depth limit exists; the front door states one rather than inheriting none). In the `/dial/` namespace the FIRST segment MUST NOT be a reserved front-door name (`authorize`, `token`, `register`, `revoke`, `callback`, `consent`, `jwks.json`) — the router's authorization-surface location captures `/dial/{segment}/…` at the first segment only, and a stored resource's first segment is its type segment, so the re-scoping closes no reachable resource; the `/apps/` namespace carries no reserved names, because nothing the gateway owns is served under the apps namespace's first segment. When an operator restriction is configured, a path it excludes MUST fail the same way. Guard failures fail closed with the response shape the surface already answers — 404 at the protected-resource document, `invalid_target` at the authorization and token endpoints — and each refusal lands on the audit trail with a fixed-vocabulary reason and the offered path as a truncated non-credential fact, never free-form caller input. The guard's verdict is over the canonical form: a path is admitted or refused as the resource it is, whatever spelling arrived.

This requirement replaces the toolset name guard (the REMOVED entry below) and carries its refusal discipline forward unchanged in kind — one reason per refusal class, fixed vocabulary, truncation, fail-closed shapes — with the charset class re-based from a one-segment `[a-z0-9-]+` to the decoded per-segment rules above. The router's wire-form grammar (the addressing-vocabulary requirement) and this guard are a stated division of labor, not two encodings of one rule: the map is a **routability filter over the wire form** — it admits every `%XX`-escaped spelling, whatever the escapes decode to — and this guard is the **authority over the decoded form**. One class is therefore asymmetric by design and documented here: a wire-conforming spelling whose decoded content the guard refuses (an encoded forbidden character such as `%7B`, an escaped trailing dot such as `%2e`, an over-length or over-depth path) is forwarded on the data path by the router and refused at discovery and at the authorization and token endpoints by the guard — the router-synthesized 401 challenge for such a call names a document the gateway answers 404, a dead end by design, and the outcome is same-answer-as-Core: Core refuses these names at resolution too. The routing probe battery asserts this asymmetry explicitly — rows asserting the forwarded-and-refused class on both sides — rather than an agreement between the grammars that does not exist.

#### Scenario: A forbidden character in any segment is refused

- **WHEN** a resource path offers a segment whose decoded form contains `{`, `}`, `"`, or a control character — offered raw or percent-encoded (`%7B`, `%22`, `%01`)
- **THEN** the refusal is the surface's fail-closed shape (404 at discovery, `invalid_target` at the authorization endpoint) and one audit record carries the fixed-vocabulary reason with the offered path truncated — the decoded check is what refuses it, so the encoding cannot smuggle it past

#### Scenario: A trailing dot in any segment is refused

- **WHEN** a resource path offers a segment ending in a dot, at any depth
- **THEN** the path fails the guard with the same refusal shape and reason class as a forbidden character — a front-door ruling that mirrors Core's creation-side constraint and is deliberately stricter than Core's resolution, declared as a ruling rather than claimed as parity

#### Scenario: A reserved first segment is refused; a reserved name deeper in the path is not

- **WHEN** a resource path's first segment in the `/dial/` namespace is `token`, `authorize`, or any other reserved front-door name
- **THEN** the path fails the guard — the authorization-surface location captures that traffic before any data path; and **WHEN** the same name appears as a non-first segment (`toolsets/public/token`), the path passes the reserved-name rule, because the authorization-surface capture is a first-segment match and no stored resource's first segment can collide with it

#### Scenario: An over-length or over-depth path is refused before work proportional to it

- **WHEN** a resource path's decoded form exceeds 900 UTF-8 bytes, or its segment count exceeds the configured cap
- **THEN** the path is refused with the guard's refusal shape and a fixed-vocabulary reason, before any Core call, document build, or flow allocation — the caps make each admitted request's cost constant

#### Scenario: A valid multi-segment path resolves with no local configuration

- **WHEN** no operator restriction is configured and a discovery or authorization request names a guard-passing multi-segment resource path
- **THEN** the path is served on that surface exactly as a configured one is, with no gateway-side toolset configuration involved — whether Core's registry holds the path is never decided on an unauthenticated surface (the discovery tier is registry-independent by the mirror property) and is decided by the flow's authenticated listing read or app read, never by local configuration

#### Scenario: A wire-conforming spelling the guard refuses is forwarded on the data path and refused at discovery — the stated asymmetry

- **WHEN** a client calls `/dial/{a%7Bb}/mcp` on the MCP data path — the wire form conforms to the router's grammar, the decoded content carries the forbidden `{` — and then fetches the protected-resource document for the same spelling
- **THEN** the router forwards the data-path call byte-faithfully (the map is the routability filter over the wire form) and Core answers it as it answers on its own port, while the discovery document for that spelling is refused 404 and the authorization endpoint refuses the resource `invalid_target` (the guard is the authority over the decoded form) — the challenge's dead end at the 404 document is the documented outcome, same-answer-as-Core: no real resource is served or protected differently on either side

### Requirement: The identity provider's session refresh token is carried encrypted in the gateway's refresh token

The identity provider's session-bound refresh token MUST be carried for the refresh window as an encrypted claim inside the gateway's own refresh token, and `offline_access` MUST NOT be requested on any leg — no offline (beyond-session) grant is ever acquired; what is carried is a rotating handle to the user's live identity-provider session, and the gateway's refresh capability ends when that session ends. There is no long-lived per-session server-side store. The carrier is the refresh token only: the encrypted claim MUST NOT appear in the access token — which rides the Authorization header of every MCP data-path call and is not even reliably presented at a refresh — nor in the authorization code or any other client-visible artifact. The envelope is pinned: AES-256-GCM under a 256-bit key with a 96-bit random nonce, laid out as version | key-id | nonce | ciphertext‖tag, base64url-encoded; the algorithm and the lengths are code constants, never read from the envelope, and an envelope whose version or key-id is unknown fails closed. The envelope embeds its own `sub` and `exp`, and both are checked at the custody seam before any use: the embedded `sub` MUST equal the refresh token's signed subject — a blob swapped between users' tokens refuses — and an expired envelope refuses. The key is a dedicated 256-bit symmetric key, separated from the signing key, identified by key-id; the keyset's startup validation refuses an empty keyset, a keyset with no active entry, a multi-active keyset, and any key that is not exactly 32 bytes — AES-GCM's algorithm follows the key's length, so a shorter key would silently run AES-128 or AES-192 and falsify the pinned algorithm. Each keyset entry carries a source — `env` or `file` implemented, `kms` a reserved value refused at startup with an operator-facing error naming the gap — and the keyset MAY hold retained keys beside the one active key: sealing is always under the active key, and decryption accepts the active or a retained key, the envelope's key-id selecting the entry, with the header still bound into the AEAD's associated data so a header transplanted between envelopes fails the tag under whichever key it names. A superseded key retained for the drain window — bounded by the refresh token's non-sliding absolute expiry — keeps every outstanding refresh token working through a routine rotation, and each such refresh re-seals the carried credential under the active key in the replacement token; removing the retained entry is the immediate cut, the operator's explicit emergency path rather than the routine outcome, and its refusal is this requirement's own custody refusal class. Between flow end and the code grant the token lives in a pending entry keyed by the authorization code's id — created when the code is minted at flow end, on both flow paths, bounded by the code's own short TTL, consumed when the code grant issues a refresh token, and dropped when the code expires unredeemed; the token MUST NOT be carried in the authorization code's payload or any other client-visible artifact, in plaintext or as ciphertext, because the code is a signed-but-unencrypted JWT whose payload anyone holding the code string can read, and this token is mintable credential material. At the code grant the provider token is encrypted into the issued refresh token; at every refresh the grant decrypts it, presents it to the provider, and re-encrypts the provider's latest token — latest-wins across the provider's own rotations — into the newly rotated refresh token; a grace-window presentation of a pre-rotation token carries its own stale blob and fails at the provider where the provider rotates per grant. The token's plaintext MUST NOT be logged and MUST NOT be delivered to any client; the ciphertext is delivered inside the refresh token by design and is unusable without the custody key. The identity provider's access token is not retained past the flow: it serves the flow's decision step and credential call and is discarded at flow end. A restart loses nothing the harness does not bring back: the encrypted claim returns with the presented refresh token, so refresh capability survives restarts and rollouts, and already-minted access and refresh tokens keep working until their own expiries because they are self-contained — while the minutes-bounded pending entries are lost, so an unredeemed code issued before the restart fails its grant the same fail-closed way.

*Amendment, declared:* the requirement's keyset clause is re-worded — the hard cut becomes the overlap semantics. "Its rotation is a hard cut — a superseded key is never retained to accept, so every outstanding refresh token fails closed at its next presentation after a rotation, a wave bounded by the refresh token's non-sliding absolute expiry" becomes the per-entry-source sentence and the retained-keys sentence (seal under the active key; decrypt with active-or-retained, the envelope's key-id selecting; the drain window bounded by the non-sliding absolute expiry; removal of a retained entry as the immediate cut) — because routine rotation was specified to cost the same as a compromised-key response, which trains operators not to rotate, and the rulings fix the overlap semantics for both keysets. The startup-validation clause gains the no-active refusal and the per-entry source with its reserved-`kms` refusal. One retained scenario is re-scoped — "Custody-key rotation is a hard cut" keeps its name and moves its subject from routine rotation (no longer a cut) to the cut itself: the superseded key's removal, immediate or mid-drain, which is the same fail-closed shape the scenario always carried, now the operator's explicit path rather than the routine outcome — because routine rotation is a drain under the overlap semantics, and the scenario's name must keep naming something true. One retained scenario gains a clause ("Rotation carries the custody, in both directions" names the active key as the sealing key across a rotation). Four scenarios are added (the retained-key decrypt with active-key seal, the `kms` refusal, the flat compat spelling, the no-active refusal). The retained scenarios are otherwise unchanged and carried verbatim.

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
- **THEN** the replacement carries the provider's latest refresh token re-encrypted under the current active custody key — the active key alone sealing, whichever key decrypted — and the replaced token's blob is not accepted outside the grace window

#### Scenario: A grace-window presentation carries its own stale blob

- **WHEN** a client presents a pre-rotation refresh token inside the grace window, and the provider rotates its refresh token per grant
- **THEN** the presentation fails at the provider — the token's own carried blob is stale, each token is self-consistent, and the failure lands in the session-ended refusal class

#### Scenario: Custody-key rotation is a hard cut

- **WHEN** a custody-key rotation is completed as a cut — the superseded key removed from the keyset rather than retained, at the rotation itself or mid-drain — and outstanding refresh tokens carrying claims sealed under it are presented
- **THEN** each refuses fail-closed with the custody reason at its next presentation, and the re-sign-in wave is bounded by the refresh token's original absolute expiry — the cut is the operator's explicit act under the overlap semantics, never the routine rotation's outcome

#### Scenario: A retained envelope decrypts and the active key seals

- **WHEN** a refresh token's custody claim carries a retained key's key-id and the refresh grant runs
- **THEN** the claim decrypts under that retained key while the replacement envelope is sealed under the active key alone — decryption may look back through the drain window, sealing never does

#### Scenario: A kms-sourced custody entry refuses startup naming the gap

- **WHEN** a custody keyset entry carries the reserved source `kms`
- **THEN** the gateway refuses to start with an operator-facing error naming the gap — the KMS envelope interface is not built — never a silent ignore and never a fallback

#### Scenario: The flat single-key spelling remains the compat shape

- **WHEN** the custody keyset is configured in the pre-keyset flat spelling — key-id to base64 key, no source or role members
- **THEN** it is accepted as exactly one active `env`-sourced entry with no retained entries; a document mixing the flat and structured spellings refuses startup with an operator-facing error naming the keyset

#### Scenario: A custody keyset with no active entry refuses startup

- **WHEN** a structured custody keyset holds only retained entries
- **THEN** the gateway refuses to start with an operator-facing error naming the keyset — exactly one key seals

#### Scenario: The plaintext is never logged or delivered; the ciphertext never logged

- **WHEN** the gateway carries the provider's session refresh token
- **THEN** no log record or stored file carries the plaintext, no client response carries the plaintext, the ciphertext never reaches a log record, and the ciphertext appears only inside the refresh token delivered to its presenting client

#### Scenario: No offline grant is ever requested

- **WHEN** the gateway's client requests its scopes on the identity-provider leg
- **THEN** `offline_access` is never among them, and no offline token is ever issued to the flow

#### Scenario: Restart survives the custody, not the pending entries

- **WHEN** the gateway restarts with refresh sessions live
- **THEN** already-issued refresh tokens keep refreshing — the encrypted claim returns with the presented token — already-minted access tokens keep working, and an unredeemed authorization code issued before the restart fails its grant fail-closed

### Requirement: App MCP resources are served through the apps front-door path

App resources are served at their own front-door path shape, `/apps/{path}/mcp`, proxied to Core's deployments MCP path, because the kind lives in the path: one flat authorization server serves two resource kinds, and the path shape is what keeps a toolset and an app that share a name from ever colliding — the toolset registry and the apps registry are disjoint namespaces in Core, and the front door routes by kind, not by registry lookup. The path is the resource path (the addressing-vocabulary requirement): a bare name for a config-entity app, `applications/{bucket}/{folders…}/{name}` for a stored app, forwarded byte-faithfully to Core's `/v1/deployments/{path}/mcp`. Every 401 on the apps MCP path — no token, or an invalid or expired token — MUST be answered with the gateway's own challenge: 401 plus `WWW-Authenticate` naming the gateway's protected-resource document for that app, at `/.well-known/oauth-protected-resource/apps/{path}/mcp`, quoting the caller's own spelling; the challenge Core synthesizes MUST never reach the client, for the same reason as the toolset path: it names a document whose resource vocabulary the client cannot act on through the front door. The refusal shapes beyond the 401 keep their own answers, and neither carries the challenge: an access denial — a valid token whose user cannot pass Core's per-call authorization — is answered by Core's own 403, and an unknown app by a 404, both crossing the router untouched because the challenge synthesis fires on 401 only; neither is a sign-in cause, and a harness reads each directly off the failed call. Query parameters MUST survive the apps routing, because streamable-HTTP sessions resume through them identically on this path.

Every app resource path the gateway resolves — the apps protected-resource document's path, the authorization request's `resource` when it names the apps shape, and the refresh grant's resource — MUST pass the app path guard: the decoded segment rules (the path-guard requirement's, both namespaces sharing them) and the apps operator restriction when one is configured. The toolset guard's reserved front-door names do not apply to app paths, because nothing the gateway owns is served under the apps namespace's first segment — the reserved names are `/dial/`-scoped authorization-surface segments, and an app path's first segment can never capture them. An app path that Core addresses as a bucket-scoped resource — `applications/{bucket}/{name}`, the stored-app shape — passes the guard and is routed exactly as a bare-named app: the pre-change refusal of "an app name carrying a slash" is reversed by this change, because under the resource-path vocabulary the slash is a path separator, not a charset violation, and the stored-app shape is part of the matrix the front door must serve.

The gateway's apps discovery tier mirrors Core's own, extended from the toolset namespace: Core serves the apps MCP path's unauthenticated 401 challenge and the apps protected-resource route from the same `toolsets.security.authorizationServers` configuration that serves the toolset tier — there is no apps-specific security configuration — and both are registry-independent (the auth check precedes any registry lookup; the metadata document is built from configuration with the requested path echoed as `resource`; unset, the 401 carries no challenge and the route answers 404, neither an existence oracle, and the gateway serves its own document regardless). The mirror property is therefore normative in both namespaces: the gateway's apps tier is served for every guard-passing, restriction-admitted path, phantom and real alike, makes no Core call at all, and existence is decided post-authentication, at the flow's app read. Each apps document MUST name the app's resource URI and the single AS issuer; its `resource` member echoes the offered spelling of the app path — the toolset namespace's echo rule carried to the twin, for the mirror-property reason: Core's own document is built from the request path (`WellKnownResourceMetadataService.resolveResource`), so the document an offered spelling fetches names that spelling's resource, and for a canonical spelling the echo and the derivation are the same string; its `scopes_supported` is always empty — no upstream leg exists for an app resource to send scopes on — and no authentication-kind extension appears, because an app carries no authentication kind. The apps protected-resource route joins the same per-source and global rate limiter as every other unauthenticated surface, and over-limit requests write no record.

*Amendments, declared (this change):* the path shape is re-based from `/apps/{name}/mcp` to `/apps/{path}/mcp` with the resource-path vocabulary and byte-faithful forwarding; the challenge gains the caller's-spelling rule (the toolset path's own amendment, carried to the twin); the document paragraph gains the echo-offered `resource` rule (the toolset namespace's own, carried to the twin, for the same mirror-property reason — Core's own document is built from the request path); the app name guard paragraph becomes the app path guard (the shared decoded rules); and the bucket-scoped refusal sentence is explicitly REVERSED — "an app name carrying a slash — a bucket-scoped app id — fails the charset and is refused" was true of the one-segment vocabulary and is false under the resource-path vocabulary, the stored-app shape being a matrix cell this change serves — the reversal is declared, not silent. One scenario is added (the stored-app path); the retained scenarios are re-worded from name to path where the wording named the shape, their titles retained as stable identifiers; the main spec's retained amendment records stay part of the requirement's text as they stand.

#### Scenario: No token on the apps path

- **WHEN** a client calls the apps MCP path with no Authorization header
- **THEN** the response is 401 with a `WWW-Authenticate` header whose `resource_metadata` names the gateway's apps protected-resource document for that app, and none of Core's own challenge reaches the client

#### Scenario: A stored app's path is routed and served

- **WHEN** a client calls `/apps/applications/public/<name>/mcp` — a stored app's full resource path — through the front door
- **THEN** the request is proxied byte-faithfully to Core's `/v1/deployments/applications/public/<name>/mcp`, an unauthenticated call is answered 401 with the gateway's challenge naming that path's document, and an authenticated call is answered by Core's own per-call authorization — the stored-app shape served, not refused

#### Scenario: Query string survives the apps routing

- **WHEN** a client sends `GET /apps/<path>/mcp?sessionId=<id>` through the front door
- **THEN** the request reaching Core's deployments MCP path carries the `sessionId` parameter unchanged

#### Scenario: Per-app protected-resource fetch

- **WHEN** a client fetches the protected-resource document for a served app
- **THEN** the document returns the app's resource URI — echoing the offered spelling — and the single AS issuer, with `scopes_supported` empty and no authentication-kind extension

#### Scenario: Dynamic app served without local configuration

- **WHEN** no apps restriction is configured and a client fetches the protected-resource document for an app path that passes the app path guard
- **THEN** the document is served with the path-derived resource URI and the single AS issuer, with no gateway-side app configuration involved and no Core call made — whether Core's registry holds the path is not decided on this surface (the mirror property, apps namespace: the unauthenticated tier is registry-independent, and existence is decided post-authentication at the flow's app read)

#### Scenario: Guard-failing app name refused at discovery

- **WHEN** a client fetches the protected-resource document for an app path with a segment outside the decoded rules, or an over-length or over-depth path
- **THEN** the response is 404, and one audit record carries the fixed-vocabulary reason with the offered path as a truncated non-credential fact

#### Scenario: Restriction-excluded app refused

- **WHEN** an apps restriction is configured and a client fetches the protected-resource document for a path it excludes
- **THEN** the response is 404 — the same shape an unknown app path receives on this surface, the audit record distinguishing only by its fixed-vocabulary reason

### Requirement: App resources complete the sign-in flow credential-free

An app resource is credential-free by construction — it carries no authentication kind and no per-app sign-in status in Core, and its MCP data path runs on the caller's own identity, authorized per call — so the sign-in flow for this resource kind is the identity leg, the DIAL authorization read, and the mint, and nothing else. The flow MUST authenticate the user under the gateway's identity-provider client exactly as for a toolset (the identity leg is kind-agnostic by construction and stays so). DIAL authorization is enforced by reading the app as that user — the single-app read `GET /openai/applications/{resource-path}`, the path being the same id Core's own routes and responses carry, addressed in the canonical encoding — before any token is minted: Core answers 403 when the user cannot read the app, and the flow fails with the same no-access page a toolset refusal earns, no round-trip beyond the read; a 404 is the apps namespace's existence refusal — a plain-language page saying the app is not registered in DIAL Core, one audit record with a fixed-vocabulary reason naming the app, no flow state surviving the refusal; a 401 — Core cannot validate the sign-in's identity token — is the trust fault the toolset listing read's 401 is (the federation-flow requirement's trust-fault scenario): the operator-facing fault page, the flow consumed, never an access denial, both reads sharing the gateway's one answer-to-refusal mapping; and an unreachable or unreadable answer fails closed as a deployment fault on the operator-facing fault page, never taken for an existence answer — the same four-shape discipline the toolset listing read carries (denial, existence refusal, trust fault, deployment fault). The existence refusals are the flow's authenticated reads, one per resource kind; no unauthenticated tier on either side of the front door carries an existence oracle in either namespace.

After the read, the kind-driven short-circuit runs unconditionally for this kind: no signed-in check runs, because no per-app status members exist to read; no kind branch runs, because no consent could establish anything for a resource that needs no credential; no credential call and no upstream round-trip of any kind ever run. The flow mints the harness's code directly, and the minted tokens are the same shape a toolset sign-in issues — the audience names the app's resource. The general rule the flow's routing decision already carries decides this without a new mechanism: the upstream stage runs only when the credential is missing AND the kind makes it establishable by consent, and for the app kind the second conjunct is false by construction — where a non-OAuth toolset's missing credential blocks its data path and earns the impossible-branch refusal, an app's data path runs on the caller's own identity, so there is nothing missing to refuse. One audit record MUST show the kind-driven short-circuit: a fixed-vocabulary reason naming the resource kind, with the flow's non-credential facts.

The consent/attribution checkpoint gates the mint on first attribution for this kind too, and it composes with the credential-free identity: the decision page is a user's decision, not a credential — it adds no credential call, no upstream round-trip, and no per-app status read. After the app read and before the mint, the approved-client registry is consulted (the checkpoint requirement's): an approved (subject, client) mints exactly as the short-circuit always has — no page of any kind — and an unapproved one renders the decision page where nothing rendered before; no code is minted until the user's act. The kind-driven short-circuit stays unconditional in everything it owns: the checkpoint adds the one user-visible act the zero-page shape lacked, never a credential stage.

*Amendment, declared (retained):* three clauses change — "the gateway's public PKCE client" becomes "the gateway's identity-provider client" — because the identity leg's client is a confidential client whose PKCE challenge the identity-leg requirements' toggle governs, and the app flow shares that leg exactly as the toolset flow does; the closing comparison's "the toolset settings read" becomes "the toolset listing read" — the availability-read amendment (the federation-flow requirement's declared amendment) — so the discipline the app read is compared to is the read the toolset flow now makes; and the refusal enumeration gains the 401 trust-fault clause with the closing comparison's "three-shape discipline" becoming the four-shape one — because the listing read's 401/403 split (the federation-flow requirement's declared trust-fault amendment, D16) is the app read's too: both reads share the gateway's one answer-to-refusal mapping, so a 401 from the app read is the same trust fault, never an access denial. One retained scenario is re-worded: "App authorization denied" gains the 403 in its WHEN (the code the refusal is), aligning the scenario with the split. No other scenario changes.

*Amendment, declared:* the requirement gains the checkpoint paragraph — the approved-client registry consulted after the app read and before the mint, an approved (subject, client) minting exactly as the short-circuit always has and an unapproved one rendering the decision page where nothing rendered before — because the app kind's zero-page short-circuit is the sharpest silent-mint variant the checkpoint exists to close, and the decision composes with the kind's identity: a user's decision, not a credential, so nothing the credential-free rule forbids is added. Two retained scenarios are re-worded: "App sign-in completes with no consent and no credential call" and "Repeat app sign-in is silent" each gain the approved-client condition in their WHEN — the zero-page silent completion is the approved client's, and the first-attribution shape is the new scenario's own — and "Repeat app sign-in is silent"'s THEN gains "no page of any kind" beside no consent and no credential call, the zero-click property the checkpoint preserves for approved clients. One scenario is added.

*Amendment, declared (this change):* the app read is re-addressed — "`GET /openai/applications/{id}`" becomes "`GET /openai/applications/{resource-path}`, the path being the same id Core's own routes and responses carry, addressed in the canonical encoding" — the apps twin of the federation flow's listing-read re-addressing, for the same reason (the addressing-vocabulary requirement): the read resolves the same deployment id the data path resolves, whatever the path's segment count. One scenario is added (a stored app's path completing the flow); the retained "Unknown app refused at the flow's app read" scenario's WHEN is re-pinned from "the offered name" to "the offered path"; the retained "Unreachable Core is a deployment fault, never an existence answer" scenario's THEN is re-pinned with it — "the offered path is never learned to be unserved from a failure" where it said "the offered name", a wording re-pin, no behavior change; no other scenario changes; the main spec's retained amendment records stay part of the requirement's text as they stand.

#### Scenario: App sign-in completes with no consent and no credential call

- **WHEN** a harness runs the sign-in flow for an app resource — discovery, registration, the authorization request naming the app's resource URI — and the user can read the app, and the client is approved for that user
- **THEN** the flow completes with no consent screen, no credential call, and no upstream round-trip of any kind, and the issued tokens carry the user's `sub` with the app's resource as their audience

#### Scenario: A stored app's path completes the flow

- **WHEN** a harness runs the sign-in flow for a stored app addressed by its full resource path (`{origin}/apps/applications/public/<name>/mcp`) and the user can read the app
- **THEN** the app read resolves the path exactly as a bare-named app's read resolves its name, and the flow completes with the same shape — the stored-app cell served end to end

#### Scenario: Unknown app refused at the flow's app read

- **WHEN** the authenticated user's app read returns no app — Core does not know the offered path
- **THEN** the flow fails with a plain-language page, no round-trip beyond the read happens, and one audit record carries the fixed-vocabulary reason (`unknown_app`) naming the app — the apps namespace's existence refusal, decided post-authentication exactly where the toolset namespace's is; no flow state survives the refusal

#### Scenario: App authorization denied

- **WHEN** the app read answers 403 for the authenticated user — the user cannot read the app
- **THEN** the flow fails with the clear no-access page and no token is minted

#### Scenario: Unreachable Core is a deployment fault, never an existence answer

- **WHEN** the app read cannot be completed — Core unreachable, or the answer unreadable
- **THEN** the flow fails closed with the operator-facing fault page, distinct from the not-registered page, and the offered path is never learned to be unserved from a failure

#### Scenario: Repeat app sign-in is silent

- **WHEN** the same user runs the app sign-in again while holding valid tokens, for a client in the approved-client registry
- **THEN** the flow completes the same way — no consent, no credential call, no page of any kind — and the issued tokens are the same shape the first flow issued

#### Scenario: First attribution on the app kind's zero-page short-circuit renders the decision page

- **WHEN** a harness runs the sign-in for an app resource the user can read, and the (subject, client) is not in the approved-client registry
- **THEN** the decision page is rendered where nothing rendered before — no code is minted, and no credential call and no upstream round-trip run — one audit record carries the fixed-vocabulary reason (`attribution_required`), and the page names the resolved client, the app resource, and the registered `redirect_uri` (the checkpoint requirement's)

### Requirement: The apps restriction is an optional operator restriction

The apps restriction is the apps namespace's own optional operator restriction, separate from the toolset restriction because the two registries are disjoint namespaces in Core: a path can exist as both a toolset and an app, and a shared restriction would admit or deny both together — an operator decision the deployment never asked for. Unset, the gateway MUST serve every app whose resource path passes the app path guard; set, it MUST serve only the restriction's entries, decided on the canonical form. Entries are resource paths — a bare config-entity app name or a stored app's full path (`applications/{bucket}/{folders…}/{name}`). Configured entries MUST keep the startup refusal that protects static routing — a segment outside the decoded rules, a trailing dot, a dot or empty segment, an over-length or over-depth path each refuses the container's start with an operator-facing error naming the entry — because the router's apps location is static configuration with no view of what Core serves, exactly as for toolsets. An entry MUST declare nothing but the path: no authentication kind exists on an app to declare, and no scopes are declared because no leg ever sends scopes for an app resource — the apps protected-resource document's `scopes_supported` is empty whether or not the app is pinned. Resource inference MUST NOT consult the apps restriction: an app resource is always named explicitly by its resource URI, and with two namespaces served by one authorization server there is no unnamed resource a missing `resource` parameter could honestly be resolved to.

*Amendment, declared (this change):* the served-set and startup-refusal sentences are re-based from names to resource paths (the addressing-vocabulary and path-guard requirements), the entries sentence gains the stored-app shape, and the canonical-membership rule is added — the apps twin of the toolset restriction's re-basing, for the same reasons. The retained scenarios are re-worded from name to path, their titles retained as stable identifiers.

#### Scenario: App name outside the routed charset refused

- **WHEN** the apps restriction lists a path with a segment outside the decoded rules — a forbidden character, a trailing dot, a `.`/`..` segment, or an over-length or over-depth path
- **THEN** the gateway refuses to start with an operator-facing error naming the entry and the rule, so a path the router's apps location could never route fails at configuration time, not in operation

#### Scenario: Unset apps restriction serves dynamically

- **WHEN** no apps restriction is configured
- **THEN** the gateway starts, and app resources are served whose paths pass the app path guard — the documents are registry-independent (the mirror property), and the apps a harness can actually use are the ones Core's registry holds, learned at the flow's authenticated app read

#### Scenario: Restriction-excluded app refused like an unknown one

- **WHEN** an apps restriction is configured and a request names an app path outside it
- **THEN** the refusal is the same one an unknown app path receives on that surface, and the audit record distinguishes only by its fixed-vocabulary reason

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

### Requirement: The identity provider's endpoints are read from standard OIDC discovery

Where no directly-configured endpoint set is present — the default; the direct-configuration requirement defines the alternative — the gateway MUST read the identity provider's authorization, token, and key-set endpoints from the provider's OpenID Connect discovery document, fetched from the configured issuer — the issuer with `/.well-known/openid-configuration` appended, the discovery spelling the target providers serve — and from nowhere else in that mode: no endpoint the identity leg uses may be built by provider-specific URL arithmetic, and the one alternative source is the operator-configured endpoint set, which replaces discovery whole, never member-by-member. The code exchange, the refresh grant, and key-set resolution MUST use the discovered endpoints — one spelling of the identity leg at issuance and at refresh alike. The discovery fetch rides the existing outbound discipline: the configured timeout, redirects not followed, and the response size capped. A discovery answer that cannot be fetched, parsed, or validated fails the leg closed with an operator-facing error naming the provider — there is no fallback endpoint construction to fall back to, and no fallback to the configured-set mode either: the mode is chosen by configuration, never by a runtime failure. The validated document MUST be cached per process for a configured TTL, so a cold start or an expired cache costs at most one fetch per window, and an endpoint change at the provider propagates within the TTL. Where an operator configures a back-channel base, the discovery fetch and the token and key-set calls are addressed to it — scheme and host swapped, path kept — while the browser-facing authorization redirect keeps the discovered document's authorization endpoint untouched, and issuer matching stays pinned to the configured issuer whichever base a call used.

#### Scenario: Discovered endpoints used by every leg
- **WHEN** the identity leg runs in discovery mode — no endpoint set directly configured — through the authorization redirect, the code exchange, the refresh grant, the key-set fetch
- **THEN** every endpoint it uses is the discovery document's, the same document for all four, and no endpoint is derived from the issuer by a provider-specific suffix

#### Scenario: Unreachable provider fails the leg closed
- **WHEN** the discovery document cannot be fetched when the identity leg needs it — the provider unreachable, the answer not JSON, or the document over the size cap
- **THEN** the leg fails with an operator-facing error naming the provider, no tokens are minted, and no endpoint is constructed as a fallback

#### Scenario: The cache bounds staleness and cost
- **WHEN** the discovery document has been fetched and validated within the configured TTL
- **THEN** the identity legs use the cached endpoints with no new fetch, and the first leg after the TTL's expiry is the one that re-fetches — the TTL is the documented bound on how long a provider's endpoint change goes unnoticed

#### Scenario: The back-channel override serves the server-to-server calls only
- **WHEN** an operator configures a back-channel base for a provider whose browser-facing origin is impractical for server-to-server calls, and a sign-in runs
- **THEN** the discovery fetch, the code exchange, the refresh grant, and the key-set fetch are addressed to the override's origin with the discovered path, the browser-facing authorization redirect carries the discovered document's authorization endpoint unchanged, and the identity token's issuer check still matches the configured issuer exactly

#### Scenario: One hostname, no override
- **WHEN** the provider is reachable for both browser and server-to-server calls at one HTTPS origin — the common external-provider shape — and no back-channel base is configured
- **THEN** every endpoint of the leg, browser-facing and back-channel alike, is the discovered document's, addressed to the configured issuer's origin

### Requirement: A directly configured endpoint set replaces discovery whole

An operator MAY configure the identity provider's three endpoints directly — the authorization endpoint, the token endpoint, and the key-set URL — as an explicit alternative to discovery, for a provider whose discovery document is unavailable, nonstandard, or served at a spelling the discovery fetch does not reach. The set is all-or-nothing: the gateway MUST refuse to start on a partial set, naming the configured and the missing members, because a leg whose endpoints come from two sources has two spellings of the identity leg. Where the full set is configured, the discovery fetch MUST NOT be attempted at all — not fetched and ignored, skipped — and the three configured endpoints MUST serve the authorization redirect, the code exchange, the refresh grant, and the key-set fetch: exactly one endpoint source per leg, knowable from the configuration alone and never from runtime events — a discovery failure in another deployment's mode never selects this one, and no runtime failure selects between the two. Every configured endpoint MUST be a well-formed absolute URL and MUST be HTTPS unless it shares the configured back-channel base's origin — the override is the operator's explicit ownership of a plain leg, the same discipline discovery mode applies. The back-channel override applies to the configured endpoints exactly as to discovered ones: the token and key-set legs are re-addressed to the override's origin with the path kept, and the browser-facing authorization endpoint stays untouched. Issuer pinning is unaffected by the mode: the identity token's issuer check stays exact-string against the configured issuer, and no endpoint the operator configures widens it. The mode's trade is the operator's, stated rather than mitigated: a provider's endpoint change propagates within the cache TTL in discovery mode and not at all here — a moved endpoint fails the leg closed with the fixed-vocabulary operator-facing error, and keeping the endpoints current is the operator's responsibility.

#### Scenario: The full endpoint set skips discovery entirely
- **WHEN** all three endpoints are directly configured and a sign-in runs
- **THEN** no discovery document is fetched, and the authorization redirect, the code exchange, the refresh grant, and the key-set fetch all use the configured endpoints — one source for all four legs

#### Scenario: A partial endpoint set refuses startup
- **WHEN** one or two of the three endpoints are directly configured
- **THEN** the gateway refuses to start with an operator-facing error naming the configured and the missing members — a partial set would give the leg two endpoint sources

#### Scenario: A malformed or non-absolute configured endpoint refuses startup
- **WHEN** a directly configured endpoint value is not a well-formed absolute URL — a relative path, a scheme-less or otherwise malformed value
- **THEN** the gateway refuses to start with an operator-facing error naming the setting — a value that cannot be addressed as a URL cannot serve as the leg's endpoint

#### Scenario: Plain-http configured endpoint refused without the override
- **WHEN** a directly configured endpoint is plain `http` and shares the origin of no configured back-channel base
- **THEN** the gateway refuses to start with an operator-facing error naming the setting — the code, the carried refresh token, and the client secret never ride a plain leg the operator has not explicitly owned

#### Scenario: The override re-addresses the configured server-to-server legs only
- **WHEN** the full endpoint set is configured together with a back-channel base, and a sign-in runs
- **THEN** the token and key-set calls are addressed to the override's origin with the configured path kept, the browser-facing authorization redirect carries the configured authorization endpoint unchanged, and the identity token's issuer check still matches the configured issuer exactly

#### Scenario: A stale configured endpoint fails the leg closed
- **WHEN** the provider moves an endpoint the operator has not updated, and a leg addresses it
- **THEN** the leg fails with the operator-facing fixed-vocabulary error, no tokens are minted, and no endpoint is constructed as a fallback — keeping the configured endpoints current is the operator's responsibility, stated by this mode's trade

### Requirement: Discovery documents are validated against the configured issuer

The discovery document steers outbound calls that carry credential material — the code, the carried session refresh token, and the client secret (presented on every token request, in both positions of the leg's PKCE toggle) — so it is trusted only within bounds stated as refusals: the document's `issuer` member MUST equal the configured issuer exactly, and every endpoint the gateway uses from it — authorization, token, key set — MUST share the origin of the configured issuer, or of the configured back-channel base where one is set; a document that fails either check MUST be refused whole, never used partially, and the refusal is an operator-facing leg failure. The fetch MUST refuse plain `http` except through an explicitly configured back-channel base, and MUST NOT follow redirects — a redirected discovery fetch is a redirected credential-bearing call in waiting.

#### Scenario: Document issuer mismatch refused
- **WHEN** the fetched discovery document's `issuer` member differs from the configured issuer
- **THEN** the document is refused whole and the identity leg fails with an operator-facing error — no endpoint from it is used

#### Scenario: Out-of-origin endpoint refused
- **WHEN** the discovery document advertises an authorization, token, or key-set endpoint whose origin is neither the configured issuer's nor the configured back-channel base's
- **THEN** the document is refused whole — no endpoint the document names can steer the gateway's credential-bearing calls to another origin

#### Scenario: Plain-http issuer refused without the override
- **WHEN** the configured issuer is plain `http` and no back-channel base is configured
- **THEN** the gateway refuses to start with an operator-facing error naming the setting, whichever endpoint source is configured — the configured issuer is the identity anchor in both modes (the discovery fetch's target and the document's validation target in discovery mode, the exact pin's comparison value in either), and the plain-leg ownership the back-channel override grants reaches the endpoints the leg calls, never the anchor itself

### Requirement: The identity-provider client is confidential; the PKCE toggle governs the challenge only

The gateway's identity-provider client is a confidential client: the code exchange and the refresh grant MUST authenticate the client with the configured client secret on every identity-leg token request, in both positions of the leg's PKCE toggle — the modes are client secret plus PKCE, or client secret alone, and never PKCE alone. The gateway MUST refuse to start without a configured client secret in either position of the toggle, naming the setting: the secret is the client's authentication, not a mode-conditional compensating control, so no deployment runs without one. The configured client secret is delivered by exactly one of two spellings, both supported: the injected environment variable (`IDP_CLIENT_SECRET`) or a file at a configured path (`IDP_CLIENT_SECRET_FILE`, a read-only mount — the shape a mounted Secret file takes). Configuring both refuses startup with an operator-facing error naming both settings — exactly one spelling per secret, the same mixing refusal the keyset seam's settings carry; configuring neither is the missing-secret refusal above. A spelling is configured only by a real value, and the blank-equals-unset rule governs the forwarded **setting** values — the environment value, or the file-path setting: a **blank** environment value or file-path setting — empty or whitespace-only — is **unset**, so a deployment that fronts every setting explicitly never counts a blank-forwarded spelling as configured, and the both-configured refusal fires only when both spellings carry real values. The rule reads the setting values alone and never the file's content: a blank file at a real configured path stays the loud refusal below, not an unset spelling. A file source is read once at startup, and an unreadable or blank file refuses startup loudly, naming the path and never the content — the file loader's discipline, the keyset seam's `file` source carried to the one secret that sits outside the keysets. The two spellings are equivalent to the gateway: whichever delivers it, the secret's presentation, its never-logged discipline, and its token-leg-only audience are the ones this requirement states, and the boundary each spelling rests on is the deployment's to own. The toggle (`IDP_PKCE_ENABLED`, default on) governs only whether the S256 challenge rides on top of the client authentication: on (the default), the identity leg's authorization redirect carries an S256 `code_challenge` and the code exchange presents the verifier — the binding that protects the leg's code while it crosses the browser, composed with the client authentication; off, for a provider that cannot support PKCE, the redirect carries no challenge and the exchange presents no verifier — the client secret alone authenticates the leg's token requests. The secret is presented on the token leg only, to the leg's one endpoint source, and is never logged, never echoed in an error, never rendered on any page, and never delivered to any client, whatever the toggle's position and whichever spelling delivers it. The toggle changes nothing else: the client-facing AS surface keeps requiring PKCE from harness clients on every authorization request, the upstream leg's verifier stays Core's and untouched, and `offline_access` is never requested on any leg.

*Amendment, declared:* the requirement gains the secret's delivery clause (the owner-pause amendment round) — the two spellings (`IDP_CLIENT_SECRET` by environment variable, `IDP_CLIENT_SECRET_FILE` by read-only mounted file), exactly one configured per secret with the both-configured refusal naming both settings (the keyset seam's mixing-refusal style), and the read-once-at-startup file discipline with its loud refusal naming the path and never the content — because the pod's secret delivery needs the file spelling (the mounted-Secret shape) beside the environment variable, and the refusal styles the keyset seam already fixed are the ones this one secret outside the keysets carries. The closing never-logged sentence gains "whichever spelling delivers it" (and its scenario's WHEN the same phrase); the delivery clause states no preference between the spellings — the component requires run-time delivery and accepts both spellings, the deployment chooses between them, and the boundary price of each is the deployment's. A follow-up amendment (the rotation drill's stopped-in-play round, `docs/evidence/c3/rotation-drill.md`) adds the blank-equals-unset sentence — a blank environment value or file-path setting is unset, the rule governing the forwarded setting values and never the file's content at a real path, the both-configured refusal firing only on two real values — and its scenario (a blank file-path spelling unset while the environment spelling carries the real secret). Four scenarios are added in all across the amendment rounds (the file spelling accepted, the both-configured refusal, the unreadable-file refusal, the blank file-path spelling unset); the retained scenarios are otherwise unchanged and carried verbatim.

#### Scenario: A missing client secret refuses startup in either toggle position

- **WHEN** the operator starts the gateway with no client secret configured — or a blank one — whatever the position of the identity leg's PKCE toggle
- **THEN** the gateway refuses to start with an operator-facing error naming the setting — the secret is the client's authentication on every token request, in both modes, so no deployment runs without one

#### Scenario: The challenge-off mode runs as a secret-authenticated client without PKCE

- **WHEN** the operator disables PKCE on the identity-provider leg for a provider that cannot support it, and a sign-in runs
- **THEN** the identity-leg authorization redirect carries no `code_challenge`, the code exchange presents no verifier, and the code exchange and the refresh grant authenticate with the client secret — every other leg behaves exactly as the challenge-on mode's

#### Scenario: The default mode presents the client secret under the challenge

- **WHEN** PKCE is enabled on the identity-provider leg (the default) and a sign-in or a refresh runs
- **THEN** the authorization redirect carries the S256 `code_challenge`, the code exchange presents the verifier, and the code exchange and the refresh grant authenticate with the client secret — client authentication and PKCE together, both bindings on, in the default mode as in the challenge-off one

#### Scenario: The client-facing surface still requires PKCE

- **WHEN** a harness sends the gateway's own authorization endpoint a request without a `code_challenge`, whatever the identity-leg toggle's position
- **THEN** the gateway refuses it — the challenge-off mode is the identity leg's alone, and the client-facing AS surface's PKCE requirement is unchanged

#### Scenario: The client secret never reaches an output

- **WHEN** the gateway logs, audits, or renders an error on the identity leg, in either toggle position and whichever spelling delivers the secret
- **THEN** no record, page, or message carries the client secret — a provider refusal naming the client is recorded by its fixed-vocabulary class, never by the credential it refused

#### Scenario: The file-delivered secret authenticates exactly as the environment-delivered one

- **WHEN** the client secret is configured by the file spelling alone — `IDP_CLIENT_SECRET_FILE` naming a readable file on a read-only mount — and a sign-in or a refresh runs
- **THEN** the secret loads once at startup and authenticates every identity-leg token request exactly as the environment-variable spelling would — the two spellings are equivalent to the gateway, whichever the deployment chooses

#### Scenario: Both delivery spellings configured refuses startup naming both

- **WHEN** both `IDP_CLIENT_SECRET` and `IDP_CLIENT_SECRET_FILE` are configured
- **THEN** the gateway refuses to start with an operator-facing error naming both settings — exactly one spelling per secret, the same mixing refusal the keyset seam's settings carry

#### Scenario: An unreadable secret file refuses startup naming the path

- **WHEN** the file spelling is configured and the path is unreadable or the file blank
- **THEN** the gateway refuses to start with an operator-facing error naming the path and never the content — the file loader's discipline, the keyset seam's `file` source carried to the one secret that sits outside the keysets

#### Scenario: A blank file-path spelling is unset on the composition path

- **WHEN** the file-path setting arrives blank — empty or whitespace-only — while the environment spelling carries a real secret, on a deployment that fronts every setting explicitly so an absent value arrives as an empty string
- **THEN** the file spelling counts as unset and the gateway starts on the environment-delivered secret — the both-configured refusal fires only when both spellings carry real values, and the loader is never sent to a blank path

### Requirement: The deployment unit is a single pod defined by a versioned contract

The production deployment unit is **one pod**: the front router and the gateway as
sibling containers on a shared localhost, deployed and rolled as one unit. This
repository delivers the pod's **contract**, not its manifests — the Helm/pod assembly
is DevOps-owned — and the contract is a versioned document in this repository that
MUST state: the production image; the classified env-var surface; the nginx
configuration as the versioned mountable file the router container runs read-only
(front routing is this spec's behavior, not deployment folklore); the volume mounts;
the ports and probes; the pod's required security context; a deployment diagram of
the assembly (renderer-independent, readable as plain text); the sibling-localhost
assumption; and the single-replica assumption. The contract MUST pass DevOps review
before this change is done, and the
review's evidence is **explicit confirmation** — silence is not acceptance.

The production image MUST run as a fixed non-root uid (the DCR store's file ownership
depends on it), expose exactly one container-internal port (the gateway's, never
published — unreachable from the host and from outside networks, name-routable on the
deployment's own instance network, where Core fetches the JWKS), bake no secret-class
value (never-cut 6), and carry no
HIGH-or-above OS-package finding in the static gate's scanner — the recorded
Debian-slim Trivy debt is cleared by this change, by the base swap the design decides.
The classified env-var surface MUST classify every environment variable the container
reads into required / optional / secret / dev-only, as a committed table; secret-class
values are injected at run time (environment variable or mounted key file), never in
the image, never in the repository.

The router container MUST run this repository's committed nginx configuration
read-only, with the gateway upstream addressed at sibling localhost — the router is
the sole front door and the sole peer-identity authority, and the gateway's port MUST
NOT be reachable from the host or from outside the deployment's network: the pod
boundary keeps it off the host and the pod's external interface, and the deployment's
own instance network is the one network that reaches it by design — the trust domain
where Core fetches the gateway's JWKS by name, the port's named legitimate use (the
property the non-published container port carries in the composed shape). The pod's
volume mounts MUST carry the DCR
registration store's mount (read-write, at the configured store path — the pod's one
mounted state; the consent registry's in-memory custody is deliberately excluded, per
the approved-client registry requirement's own record), and, where file-sourced keyset
entries are configured, their read-only key-file mounts. The store's backing MUST be a
cloud-backed persistent-volume storage class — the requirement stated by its
properties: the data survives node loss and rests in a tenant-governable resource the
deployment administers — never node-local ephemeral storage; which storage class,
mechanism, or product satisfies those properties is the deployment's choice, named by
the contract as a requirement, not as a product. Backup and export are
deployment-owned, and the component's own shape is what makes them cheap: the store is
a single human-readable JSON file written by atomic replace, so a point-in-time copy
of the file is a consistent export — no gateway cooperation and no new API; the choice
of copy mechanism and destination is the deployment's. The store's no-secret-content
rule is load-bearing and MUST be stated as such: the store MUST NOT gain secret-class
content without re-opening its boundary analysis — the property is what makes the
external governance reader class (storage-layer RBAC holders, backup destinations)
cheap to admit, and the same logic carries the future wrapped-CEK file, which is
ciphertext by design and is named in the contract as the store volume's future second
resident. The pod's probes MUST be
liveness probes against `/healthz` — through the router and container-internally —
matching the endpoint's own contract (the probe answers whether the process is up,
never Core's or the identity provider's health).

The pod's security context MUST preserve the controls the image and its mounts
assume: `runAsNonRoot: true` with the image's fixed uid and gid (`runAsUser`/
`runAsGroup` 10001 — the DCR store's file ownership depends on that uid);
`fsGroup: 10001` on the store's volume, so the mount's ownership lets uid 10001 write
it — a world-writable mount is the tamper path the assembly must refuse;
`allowPrivilegeEscalation: false`; all Linux capabilities dropped — viable because
nothing in the pod binds a privileged port (the router's public port and the
gateway's container-internal port are both unprivileged, and that is the assumption
that keeps the drop total, stated where it lives); a read-only root filesystem, with
`emptyDir` mounts for the router's temp and log paths — the gateway writes nothing
but the DCR store, whose own volume the read-only root does not touch; and the
runtime-default seccomp profile. These are requirements the assembly MUST preserve,
not deployment preferences: a pod spec that relaxes any of them is a contract
violation priced at the pod-mis-assembly threat (the design's DT-EP6-1), the same
class that prices a published gateway port or a dropped store volume.

The single-replica assumption MUST be stated in the contract: flow state and the
approved-client registry are in-memory, so the pod is not horizontally scalable and
HA remains deferred — the loss semantics are the ones the spec already fixes
(fail-safe re-prompt and re-run, never a bypass). The local composed stack stands in
for the pod for every acceptance this change carries: it MUST run the production
image in the pod shape — the router and gateway sharing one network namespace, the
gateway's port unpublished — and the probe battery, the DCR-restart survival, and the
rotation drill all run against that stack.

#### Scenario: The probe battery passes against the pod-shaped stack

- **WHEN** the composed stack runs the production image with the router and the gateway sharing one network namespace, and the probe battery runs
- **THEN** every probe passes against the single public port — the front-door routing, the challenge synthesis on both data paths, and the query-string survival — with the gateway's container port unreachable from the host and from outside networks, its reach limited to the pod's shared namespace and the deployment's own instance network, where Core fetches the JWKS

#### Scenario: The DCR store survives a pod restart on its named mount

- **WHEN** a client registers via the registration endpoint on the pod-shaped stack, the pod-shaped deployment unit restarts, and the client presents its cached client id
- **THEN** the registration is loaded from the mounted store and the authorization request is accepted with no re-registration — the contract's volume-mount section is what makes the durability requirement's mount a named MUST rather than an omission the pod shape can lose

#### Scenario: No secret-class value in the image

- **WHEN** the production image is inspected or scanned for secret material
- **THEN** it carries no secret-class value from the classified env-var surface — secret material enters only by run-time injection, environment variable or mounted key file

#### Scenario: The image clears the scanner gate

- **WHEN** the static gate's OS-package scanner runs against the production image
- **THEN** no HIGH-or-above finding remains — the recorded Debian-slim debt is cleared by the base swap, and the finding is recorded in the change's evidence

#### Scenario: The single-replica assumption is stated

- **WHEN** the contract document is read
- **THEN** it states that flow state and the approved-client registry are in-memory, that the pod is not horizontally scalable, and that HA stays deferred — and a restart's loss semantics are the spec's fixed fail-safe shapes (approvals re-prompt, flows re-run, pending entries lost bounded)

#### Scenario: The security context's controls are stated as the assembly's requirements

- **WHEN** the contract document is read and the pod assembly is reviewed against it
- **THEN** it states `runAsNonRoot` with the fixed uid/gid 10001 on the gateway container (the DCR store's file ownership depends on it), `fsGroup` 10001 on the store's volume (a world-writable mount is the tamper path to refuse), no privilege escalation, all capabilities dropped on the strength of the stated no-privileged-port assumption, read-only root filesystems with `emptyDir` for the router's temp and log paths, and the runtime-default seccomp profile — and an assembly that relaxes any of them is a contract violation priced at the pod-mis-assembly threat, not a deployment preference

#### Scenario: The store's storage class and export story are stated

- **WHEN** the contract's volume-mount section is read
- **THEN** it states the cloud-backed persistent-volume requirement by its properties — the data survives node loss and rests in a tenant-governable resource, never node-local ephemeral storage, with the satisfying class and mechanism the deployment's choice — the deployment-owned export property (a single human-readable JSON file written by atomic replace, so a point-in-time copy is a consistent export, no gateway cooperation, no new API), and the no-secret-content rule as load-bearing, with the future wrapped-CEK file named as the store volume's future second resident

#### Scenario: DevOps review passes with explicit confirmation

- **WHEN** the contract is presented to the DevOps owners for review
- **THEN** completion of this change requires their explicit confirmation recorded in the change's evidence — the contract passing review is the deliverable's acceptance, and silence is not acceptance

### Requirement: The signing key is a keyset with per-entry sources and active and retained roles

The gateway's signing material is a **keyset**: one or more RSA private-key entries,
each carrying a **source** — `env` (the material in an injected environment variable)
or `file` (a PEM at a configured path on a read-only mount), both implemented — and a
**role**, exactly one entry `active` and any number `retained`. `kms` is a reserved
source value: an entry carrying it MUST be refused at startup with an operator-facing
error naming the gap (the KMS sign-interface is not built), never silently ignored and
never fallen back — the schema carries the field so a future KMS-sourced entry is a
rotation, not a redesign, and source-heterogeneous keysets (a retained `env` entry
beside an active `file` entry) are valid from day one.

The keyset's startup validation MUST refuse: an empty keyset; a keyset with no active
entry; a keyset with more than one active entry; an entry that is not a readable,
unencrypted RSA private key of at least the minimum key size; two entries whose
material derives the same `kid` (the `kid` is derived from the key material itself —
a truncated hash over the public numbers — so a shared `kid` is either the same key
configured twice, under one name or two, or a collision between two distinct keys in
the truncated hash; the refusal stands either way, because one `kid` must name
exactly one entry); and, for a `file`-sourced entry, an unreadable or unparseable file,
naming the path. No key material, no fingerprint, and no file content reaches any
startup error or log line — the errors name entries by their configured ids and paths
only.

The signing material's two spellings — the singular setting and the structured keyset
setting — are mutually exclusive, and a spelling is configured only by a real value: a
**blank** value of the singular setting, empty or whitespace-only, is **unset**. The
composition path — a deployment that fronts every setting explicitly, so an absent
value arrives as an empty string — never counts as configuring the singular by its
forwarding alone; the both-configured refusal fires only when the singular carries a
real value beside a structured keyset.

The gateway MUST sign with the **active** entry only; every minted token carries the
active entry's `kid`. The JWKS document MUST publish the public half of **every**
entry — active and retained alike — with the active entry first, so a verifier that
resolves a `kid`-less token to the first published key selects the key that signs.
The gateway's own-token verification accepts the active or a retained entry (the
inbound-tokens requirement's amendment), and the retained entries exist for the drain
window: bounded by the refresh token's non-sliding absolute expiry, the longest-lived
token the gateway mints. An operator MAY remove a retained entry at any time;
removal is the **immediate cut** — tokens signed under it are refused at their next
gateway-side presentation, and Core stops accepting them within its JWKS-cache window
plus the access TTL.

Routine rotation MUST pre-publish: a key that is about to become active MUST have its
`kid` published — present in the keyset, hence in the JWKS — for at least the
deployment's Core JWKS-cache window before it signs, so no minted token ever carries a
`kid` a verifier's cache may not hold. The rotation procedure is therefore staged:
add the new key as a retained entry (published, not signing), wait out the cache
window, then promote it to active and demote the old key to retained; the drain
completes when the last old-key token expires, after which the old entry is removed.

*Amendment, declared:* the requirement gains the blank-equals-unset rule (a blank —
empty or whitespace-only — singular value is unset; the composition path's explicit
forwarding of every setting never configures the spelling; the exclusivity refusal
fires only on a real value) and its scenario — added after the rotation drill stopped
in play on the composed stack, the structured spelling unreachable through the
documented procedure because the always-forwarded blank singular counted as configured
(`docs/evidence/c3/rotation-drill.md`).

#### Scenario: Overlap rotation keeps every outstanding token working

- **WHEN** the active signing key is rotated through the staged procedure — the new key added as retained and published, the cache window waited out, the new key promoted to active with the old key demoted to retained
- **THEN** tokens minted before the rotation verify and refresh through the drain window, tokens minted after carry the new `kid`, and the JWKS document carries both `kid`s throughout, the active entry first

#### Scenario: A new key is pre-published before it signs

- **WHEN** a rotation runs
- **THEN** between the new `kid`'s first publication in the JWKS and the first token signed under it, at least the deployment's Core JWKS-cache window elapses — no token is ever minted under a `kid` that has not been published for that window

#### Scenario: Removing a retained entry is the immediate cut

- **WHEN** a retained entry is removed while tokens signed under it are still within their own expiries, and such a token is presented
- **THEN** the gateway refuses it at verification, and Core refuses it within its JWKS-cache window plus the access TTL — the emergency path, available at any moment of the drain window

#### Scenario: A kms-sourced entry refuses startup naming the gap

- **WHEN** a keyset entry carries the reserved source `kms`
- **THEN** the gateway refuses to start with an operator-facing error naming the gap — the KMS sign-interface is not built — never a silent ignore and never a fallback to another source

#### Scenario: Zero or multiple active entries refuse startup

- **WHEN** a signing keyset is configured with no active entry, or with more than one
- **THEN** the gateway refuses to start with an operator-facing error naming the keyset and the violation — exactly one entry signs

#### Scenario: A file-sourced entry loads from its configured path

- **WHEN** a keyset entry names a `file` source and the file holds a readable, unencrypted RSA private key of at least the minimum size
- **THEN** the entry loads at startup and behaves as any other entry of its role; an unreadable or unparseable file refuses startup with an operator-facing error naming the path and never the content

#### Scenario: A source-heterogeneous keyset is valid

- **WHEN** a keyset holds a retained `env`-sourced entry beside an active `file`-sourced entry
- **THEN** the keyset is accepted — the source is per-entry, so the later migration to a KMS-sourced active key is a rotation beside retained injected keys, not a redesign

#### Scenario: Duplicate derived kids refuse startup

- **WHEN** two keyset entries hold material that derives the same `kid`
- **THEN** the gateway refuses to start with an operator-facing error naming both entries — one `kid` naming two entries, whether the same key under two names or two distinct keys colliding in the truncated hash, is a keyset that miscounts its own keys, and the refusal closes both shapes

#### Scenario: The single-key spelling remains the no-rotation shape

- **WHEN** the gateway is configured with the singular signing-key setting alone — the pre-keyset shape — and no keyset setting
- **THEN** it starts and signs exactly as before: one active `env`-sourced entry, no retained entries; the two settings configured simultaneously refuses startup with an operator-facing error naming both

#### Scenario: A blank singular spelling is unset on the composition path

- **WHEN** the singular setting arrives blank — empty or whitespace-only — while the structured keyset setting carries a document, on a deployment that fronts every setting explicitly so an absent value arrives as an empty string
- **THEN** the singular counts as unset and the gateway starts on the structured keyset — the both-configured refusal fires only when the singular carries a real value

### Requirement: A live rotation drill gates the keyset semantics' completion

Before this change is done, a live rotation MUST be performed on the composed stack in
the production-image, pod-shaped configuration, for **each keyset** — the signing
keyset and the custody keyset — with captured evidence, and the drill's instrument
MUST be proven able to fail first: a negative control (a deliberately wrong
expectation, such as asserting an old-`kid` token still verifies after the retained
entry is removed) runs before any verdict from the drill is trusted. The rotation
procedures and their bounds are the keyset requirements' own; the drill is their live
proof and the recorded rehearsal of the future env→KMS migration (AWS asymmetric keys
cannot be imported — a new `kid` is inherent to that migration; Azure import can
preserve it — the same overlap procedure carries both).

The signing leg of the drill MUST show, with evidence: tokens obtained under the old
key before rotation; the staged rotation run (pre-publish, cache window waited out —
the wait itself observed or bounded in the evidence — promotion); old-key access
tokens accepted at Core and old-key refresh tokens refreshing successfully through
the drain window, each rotated refresh token minted under the new `kid`; new sign-ins
minting new-`kid` tokens accepted at Core throughout; and, after the drain bound, the
retained entry removed and old-key tokens refused. The custody leg MUST show: refresh
sessions live across a custody-key rotation with the old key retained — each
presentation decrypting under the retained key-id and each replacement envelope
sealed under the new active key-id — and the emergency cut rehearsed: a retained
custody key removed mid-window, its outstanding refresh tokens refusing at next
presentation with the custody refusal class.

The captured evidence MUST carry public facts and fixed vocabularies only — `kid`s,
key-ids, JWKS snapshots, audit records, probe verdicts — never key material, never
token strings, never envelope contents.

#### Scenario: The drill's rotation window passes with evidence

- **WHEN** the drill runs the staged rotation of each keyset on the live stack and the evidence is read
- **THEN** it shows old tokens draining gracefully, refresh sessions surviving and re-sealing under the new keys, new tokens accepted throughout, and no refusal attributable to the rotation itself — the Core JWKS-cache window respected and observed in the evidence

#### Scenario: The negative control runs first and fails

- **WHEN** the drill's instrument is proven before the rotation verdicts are trusted
- **THEN** a deliberately wrong expectation (an old-`kid` token asserted to verify after its retained entry is removed) is run first and fails — the instrument can fail, so its pass is a verdict

#### Scenario: The emergency cut is rehearsed mid-window

- **WHEN** the drill removes a retained entry while tokens it signed or sealed are still within their expiries
- **THEN** the evidence shows the immediate refusal — signing-key tokens refused at verification and at Core within the cache window, custody-carried refresh tokens refused at next presentation in the custody refusal class — the routine drain and the emergency cut are both proven, not one presumed from the other
