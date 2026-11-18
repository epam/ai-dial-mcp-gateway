# Spec Delta

## ADDED Requirements

### Requirement: The front door's well-known namespace is closed

The front door MUST answer every request whose normalized path — the path the router selects a location by: percent-decoded, dot-segments resolved, slashes merged — is `/.well-known` or lies under `/.well-known/`, and that no served discovery location serves, with 404, the fixed body `{"detail":"Not Found"}` as `application/json`, and the fixed header `X-Content-Type-Options: nosniff`, from the router, and MUST NOT forward it to Core or to the gateway. A served location's path ends where its pattern ends — at a `/` or at the end of the path, never before a decoded trailing line break — so `/.well-known/oauth-authorization-serverX`, `/.well-known/openid-configuration.json`, and a Core template path with a trailing `/` are closed. The served set is exactly three location families: the authorization-server metadata and its aliases (the discovery requirement's alias set), forwarded to the gateway; each toolset's and each app's protected-resource document (`/.well-known/oauth-protected-resource/dial/…`, `/.well-known/oauth-protected-resource/apps/…`), forwarded to the gateway; and Core's own two protected-resource route templates (`/.well-known/oauth-protected-resource/v1/toolset/{id}/mcp` and `/.well-known/oauth-protected-resource/v1/deployments/{id}/mcp`, each `{id}` one or more segments), forwarded to Core unchanged. Everything else under `/.well-known/` is closed, the root `/.well-known/oauth-protected-resource` included: the gateway serves no root protected-resource document, because one root document can name only one resource and the front door serves many, each bound by its own resource URI.

The namespace is closed rather than forwarded because Core answers an unauthenticated request on any path outside its public routes with its auth filter's 401, and a 401 on a discovery path reads to a discovering client as "authenticate before discovering" — a dead end no client can satisfy. A 404 is the answer the discovery orders of RFC 8414, RFC 9728, and the MCP authorization specification expect for an absent document, and it lets a client move to its next discovery step. Core serves nothing under `/.well-known/` but its two protected-resource templates, so the closure takes no working Core path away.

The namespace is closed on the raw spelling too. The router selects a location by the normalized path but forwards the raw request URI — the bytes the client sent, never decoded — and Core matches its templates on that raw path, so a crafted spelling could otherwise select one location and deliver a different path upstream. The front door MUST forward a request to Core's protected-resource templates only when its raw request URI is itself one of the two templates — the template path, then nothing but an optional query; a request whose normalized path matches a template while its raw spelling does not — a dot-segment or percent-encoded spelling, or a percent-encoded trailing line break — receives the closure's 404. The front door MUST NOT forward to Core any other request whose raw path is spelled in the namespace — whose first segment, after any empty or `.` segments and with percent-escapes read as the characters they encode, is `.well-known` — wherever its normalized path leads: such a request, which would otherwise reach Core through the catch-all, receives the closure's 404. A raw namespace spelling whose normalized path selects a gateway location is forwarded to the gateway, whose own routes answer it — the document, or the gateway's own 404 — and one whose normalized path selects a data-path location is refused there by the data path's raw-URI grammar; neither receives Core's answer.

The closure MUST NOT shadow a served location. In the router it is a plain prefix location, which nginx uses only after every regex location has failed to match and which the exact authorization-server location precedes; it is never a `^~` prefix, which would suppress the regex locations the protected-resource documents and the aliases are served by. The 404 is answered for every method, on any request the server-level bounds admit — a body over the router's body cap or an over-long request line is refused by those bounds first; its body is the fixed literal and never reflects any part of the request; it carries the fixed `X-Content-Type-Options: nosniff` header, added on the 404 itself, which keeps a browser from sniffing the body as anything but JSON and tells the router's closure apart from the gateway's own 404 of the same body; it carries no `Access-Control-*` header and no `WWW-Authenticate` header; and a `HEAD` request receives the status and headers without the body. The body and type are the gateway's own unrouted-404 shape, so within the `/.well-known/` namespace a discovering client sees one 404 body whichever of the router and the gateway refuses. The closure lives in the committed router configuration the pod runs, and a deployment that fronts the gateway with any other configuration MUST reproduce it.

#### Scenario: The root protected-resource path is refused by the router

- **WHEN** a client sends `GET /.well-known/oauth-protected-resource` to the front door
- **THEN** the router answers 404 with the body `{"detail":"Not Found"}` as `application/json`, the `X-Content-Type-Options: nosniff` header, no `WWW-Authenticate` header, and no trace of Core's answer (no Core trace header, no Core 401 body) — the request is never forwarded

#### Scenario: An unserved well-known path is refused by the router

- **WHEN** a client sends `GET` to `/.well-known/unknown`, `/.well-known/`, or `/.well-known` through the front door
- **THEN** each is answered by the router's 404 with the fixed JSON body and the `X-Content-Type-Options: nosniff` header, and none reaches Core or the gateway

#### Scenario: Every method on a closed path is the router's 404

- **WHEN** a client sends `POST`, `OPTIONS`, or `HEAD` to a closed `/.well-known/` path through the front door
- **THEN** the answer is the router's 404 with no `Access-Control-*` header — the `HEAD` answer without the body — and an `OPTIONS` preflight receives no preflight handling

#### Scenario: The served discovery locations keep precedence over the closure

- **WHEN** a client fetches `/.well-known/oauth-authorization-server`, a toolset's `/.well-known/oauth-protected-resource/dial/<path>/mcp`, or an app's `/.well-known/oauth-protected-resource/apps/<path>/mcp` through the front door
- **THEN** each is served by the gateway exactly as before the closure existed — the closure is used only after every served location has failed to match

#### Scenario: Core's own protected-resource route still reaches Core

- **WHEN** a client fetches `/.well-known/oauth-protected-resource/v1/toolset/<id>/mcp` or `/.well-known/oauth-protected-resource/v1/deployments/<id>/mcp` through the front door, spelled as the template is
- **THEN** the request is forwarded to Core unchanged and the answer is Core's — the same status and document shape Core answers for the same path on its own port

#### Scenario: A shape off Core's templates is closed

- **WHEN** a client sends `GET /.well-known/oauth-protected-resource/v1/toolset/<id>/tools` or `GET /.well-known/oauth-protected-resource/v1/other` through the front door
- **THEN** the router answers its 404 — only the two templates Core serves are forwarded, and every other shape under Core's prefix is closed like any other unserved path

#### Scenario: A served location's end edge is closed

- **WHEN** a client sends `GET` to `/.well-known/oauth-authorization-serverX`, `/.well-known/openid-configuration.json`, or `/.well-known/oauth-protected-resource/v1/toolset/<id>/mcp/` through the front door
- **THEN** each is answered by the router's 404 with the fixed JSON body and the `X-Content-Type-Options: nosniff` header — none is an alias path or a Core template, so none is forwarded

#### Scenario: A raw spelling that normalizes onto Core's template is closed

- **WHEN** a client sends, with its path transmitted verbatim, `GET /.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/<id>/mcp`, the same path with its dot segments percent-encoded, or `GET /.well-known/oauth-protected-resource/v1/toolset/<id>/mcp%0A`
- **THEN** each is answered by the router's 404 with the `X-Content-Type-Options: nosniff` header and no Core trace header — its normalized path matches Core's template but its raw spelling does not, so it is never forwarded to Core

#### Scenario: A raw namespace spelling that normalizes out of the namespace does not reach Core

- **WHEN** a client sends, with its path transmitted verbatim, `GET /.well-known/unknown/../../v1/<path>`, or the same path with its dot segments or its `.well-known` dot percent-encoded
- **THEN** the answer is the router's 404 with the `X-Content-Type-Options: nosniff` header and no Core trace header — the normalized path selects the catch-all, and the catch-all forwards no raw namespace spelling to Core

## MODIFIED Requirements

### Requirement: Discovery documents describe one flat authorization server

The gateway MUST serve one RFC 8414 AS metadata document at the host root for a single path-less issuer — the public origin — and one RFC 9728 protected-resource document per served toolset. A toolset is served when its **resource path** passes the request-time path guard (the decoded segment rules, the first-segment reserved names, the byte and depth caps) and is not excluded by the operator restriction when one is configured — and nothing else decides it on this surface: the document is served for every guard-passing, restriction-admitted path, whether or not Core's registry holds it. The gateway's unauthenticated discovery tier is registry-independent by design, mirroring Core's own: Core's MCP path answers an unauthenticated call — for a toolset that exists or one that does not — with 401 and a challenge naming the protected-resource document, because the auth check precedes any registry lookup (a fact of the enabled route — Core's `toolsets.security.authorizationServers` configuration is what serves it; unset, the 401 carries no challenge, and a challenge-less 401 is no existence oracle either), and Core's own unauthenticated protected-resource route answers any well-formed path with a static document built from configuration with the requested path echoed as `resource` (likewise a fact of the enabled route — the same configuration; unset, the route answers 404, which is no existence oracle either, and the gateway serves its own document regardless); no unauthenticated tier on either side of the front door carries an existence oracle, in either configuration. The mirror property is normative: the gateway's tier brings nothing Core's own does not — the same 401-challenge on the data path, the same echo-document at discovery, and existence decided at the same moment, post-authentication, at the flow's per-user listing read (whose refusal for a path Core does not know is the federation requirement's unknown-toolset scenario, the toolset namespace's existence refusal). Discovery therefore makes no Core call at all: no consult, no service credential, no cache, and no Core-unavailable failure shape — the protected-resource document costs the gateway one static document, and its availability is the gateway's own. The AS metadata MUST advertise both grants, S256, token-endpoint auth method `none`, and client-ID-metadata-document support, so CIMD-capable clients register with no registration call; it is a static document and consults nothing. The AS metadata MUST also carry `authorization_response_iss_parameter_supported` with the value `true` (RFC 9207's support member): the advertisement matches the emission — the gateway emits `iss` on every authorization response, success and redirected error alike (the authorization-responses requirement's own discipline), the sibling SHOULD it already satisfies ahead of the MCP `2026-07-28` revision's upgrade path — and the discovery document's member set is fixed, so the member's presence is normative, not incidental. Each protected-resource document MUST name the single AS issuer; its `resource` member echoes the offered spelling of the resource path — Core's own protected-resource route echoes the requested path, and the mirror property carries the echo rule to the gateway's tier, so the document an offered spelling fetches names that spelling's resource, which is the identity RFC 9728 requires of it; for a canonical spelling the echo and the derivation are the same string; its `scopes_supported` echoes the operator restriction's entry where the toolset is pinned there and is empty otherwise; its authentication-kind extension is omitted — under dynamic serving this surface has no authentication-kind source (the mapping's kind declaration is deleted, and the kind a flow acts on is Core's, read per flow at the authenticated listing read). The members are informational, and the scopes the upstream leg sends come from the toolset's Core settings; a client's faithfully echoed `scope` parameter is already accepted and dropped at the authorization endpoint, so an omitted member costs nothing on any leg.

The AS metadata document MUST also be served, byte-identical, at three alias locations: `/.well-known/openid-configuration` — the OpenID Connect Discovery location, which the MCP authorization specification requires a client to try for a path-less issuer — and the path-insertion forms `/.well-known/oauth-authorization-server/{suffix}` and `/.well-known/openid-configuration/{suffix}` for any suffix, the empty suffix included. The path-insertion forms are served because a discovering client may derive the issuer from the resource URL rather than from the protected-resource document and probe the form RFC 8414 §3 and the MCP specification give for an issuer with a path. Every alias answers the one document the canonical location answers, from the same builder: its `issuer` is the public origin always and MUST NOT echo the requested suffix. The gateway has exactly one issuer — the `iss` its tokens carry and the RFC 9207 `iss` its authorization responses carry — and a document claiming a suffixed issuer would assert a second identity no token carries. So a strict RFC 8414 client discards a path-insertion answer as §3.3 requires, a lenient client receives the working endpoints, and neither is told anything false. The document served at the OpenID Connect location is the RFC 8414 document as it stands: no OpenID Provider member is added — no `subject_types_supported`, no `id_token_signing_alg_values_supported`, no `userinfo_endpoint`, no `openid` scope — because the gateway is an OAuth authorization server and not an OpenID Provider: it issues no ID token and serves no userinfo, and the member set is the advertisement of what the gateway emits. RFC 8414 §5 lets the `openid-configuration` suffix carry general OAuth 2.0 metadata; an OpenID Connect relying party that requires the OpenID Provider members refuses the document and cannot complete an OpenID Connect sign-in against the gateway, which is the correct outcome for a server that is not one. `code_challenge_methods_supported` is present at every alias, which is the member the MCP specification requires a client to verify in any authorization-server metadata before proceeding, whichever location served it. The aliases are `GET`-only exactly as the canonical location is — every other method, `HEAD` included, is answered with the framework's 405 — and no alias serves an `Access-Control-*` header: the aliases are discovery documents, which the back-channel posture of the public-endpoints requirement already names. An alias costs what the canonical location costs: one static document, no Core call, no audit record.


*Amendment, declared (retained):* the requirement's text is amended in one clause only — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" — because a second existence refusal exists once the app read does (the app-resource requirement's unknown-app scenario), so the sentence must state the property per namespace to stay true after the sync; the retained scenarios are unchanged and carried verbatim.

*Amendment, declared (retained — the availability read's re-pinning):* three mentions change — the mirror-property sentence's "at the flow's per-user settings read" becomes "at the flow's per-user listing read", the authentication-kind sentence's "read per flow at the authenticated settings read" becomes "read per flow at the authenticated listing read", and the dynamic-toolset scenario's mirror-property parenthetical follows — because the flow's existence decision moves with the availability oracle to the deployment-listing read (the federation-flow requirement's declared amendment): the settings read the main spec named is authorized by the caller's admin role, a decision the data path never makes, so the flow's authenticated read of the toolset is now the listing read. The mirror property itself is unchanged: existence is still decided post-authentication, at the flow's one authenticated read of the toolset, never on any unauthenticated tier. No scenario's WHEN or THEN changes beyond the parenthetical's named read.

*Amendment, declared:* the requirement's AS-metadata clause gains the `authorization_response_iss_parameter_supported: true` member — RFC 9207's support advertisement, matching the `iss` emission the gateway already makes on every authorization response (the sibling SHOULD satisfied ahead of the MCP `2026-07-28` revision's upgrade path) — because the discovery document's member set is fixed, so the member's presence is a normative advertisement, not an incidental one. One scenario is added; the retained scenarios are unchanged and carried verbatim.

*Amendments, declared (retained — the resource-path re-basing):* two clauses change. The served-set sentence is re-based — "a name that passes the request-time name guard (routed-path charset, reserved front-door names)" becomes "its resource path passes the request-time path guard (the decoded segment rules, the first-segment reserved names, the byte and depth caps)" — because the addressing vocabulary is now the resource path and the guard with it (the two ADDED requirements), and the mirror-property parentheticals' vocabulary follows ("for a path Core does not know", "any well-formed path"). The document's `resource` member rule is stated — the echo-offered rule with its reason (Core's own echo document; the RFC 9728 per-spelling identity) — replacing the implied name-derived derivation, which for canonical spellings is identical behavior and for non-canonical spellings is the only rule that keeps the document's identity true for the spelling that fetched it. One retained scenario is re-worded ("Guard-failing name refused at discovery", its title retained as the stable identifier) and two are added (the multi-segment document, the encoded-spelling echo). Two further retained scenarios are re-worded to the path vocabulary, their titles retained as stable identifiers — a wording re-pin, no behavior change: "Unmapped toolset" (its WHEN's "a resource path the configured operator restriction excludes" where it said "a name"), and "Dynamic toolset served without local configuration" (its WHEN's "a resource path that passes the request-time path guard" and its THEN's "path-derived resource URI" where they said a name under the name guard and the "name-derived" derivation). The remaining retained scenarios are unchanged and carried verbatim; the main spec's retained amendment records stay part of the requirement's text as they stand.

*Amendment, declared (this change):* the requirement gains the alias paragraph — the AS metadata served byte-identical at `/.well-known/openid-configuration` and at both path-insertion forms, the issuer never echoing a suffix, no OpenID Provider member added, and the aliases' method and CORS behavior the canonical location's — because a discovering client may try the OpenID Connect location or a path-insertion form, and before this amendment those paths fell through the front door to Core's 401, which ends a client's discovery. The previous record's label changes from "(this change)" to "(retained — the resource-path re-basing)" so that each label names the change it belongs to; that record's text is unchanged. Four scenarios are added; the retained scenarios are unchanged and carried verbatim; the main spec's retained amendment records stay part of the requirement's text as they stand.


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

#### Scenario: The OpenID Connect location serves the AS metadata

- **WHEN** a client fetches `GET /.well-known/openid-configuration` on the public origin
- **THEN** the response is 200 with a body byte-identical to the body `GET /.well-known/oauth-authorization-server` answers — the issuer the public origin, `code_challenge_methods_supported` carrying `S256`, `client_id_metadata_document_supported` true

#### Scenario: A path-insertion alias serves the document with the path-less issuer

- **WHEN** a client fetches `GET /.well-known/oauth-authorization-server/apps/<path>/mcp` or `GET /.well-known/openid-configuration/apps/<path>/mcp` — or either form with any other suffix, the empty suffix included
- **THEN** the response is 200 with the same bytes as the canonical document, and its `issuer` is the public origin, never the origin joined with the suffix

#### Scenario: No OpenID Provider member appears at any alias

- **WHEN** the document is served at any alias location
- **THEN** it carries no `subject_types_supported`, no `id_token_signing_alg_values_supported`, no `userinfo_endpoint`, and no `scopes_supported` naming `openid` — the member set is the canonical document's, unchanged

#### Scenario: A non-GET method at an alias is the framework's 405

- **WHEN** a client sends `HEAD`, `OPTIONS`, or `POST` to `/.well-known/openid-configuration` or to a path-insertion alias
- **THEN** the response is the framework's 405 naming `GET` as the allowed method — the canonical location's behavior — and it carries no `Access-Control-*` header

### Requirement: Core trusts gateway tokens through a dedicated identity-provider entry

Core MUST be configured with the gateway as an additional identity provider: a JWKS URL, an issuer pattern matching the public origin, a role path, the audience marker, and the same obfuscated-logging key and salt as the deployment's primary provider entry. Every provider entry MUST carry an issuer pattern in a multi-provider Core, because provider selection is by issuer match. Core's own discovery surface — its two unauthenticated protected-resource routes, `/.well-known/oauth-protected-resource/v1/toolset/{id}/mcp` and `/.well-known/oauth-protected-resource/v1/deployments/{id}/mcp`, the only paths Core serves under `/.well-known/` — and direct identity-provider clients keep working alongside the gateway front door. Through the front door those two routes MUST be forwarded to Core unchanged when the raw request path spells them, as Core itself matches them on the raw path, because Core's own MCP-path challenge quotes them on the request's own host when Core's resource host is unset, so a direct-to-Core client using the front door's host is pointed back at this front door for its document.

*Amendment, declared (this change):* the coexistence sentence names Core's own discovery surface precisely — "Core's own discovery surface" becomes "Core's own discovery surface — its two unauthenticated protected-resource routes, … the only paths Core serves under `/.well-known/` —", with the front-door forwarding of those two routes on their raw spelling and its reason stated — because the front door now closes its `/.well-known/` namespace (the well-known-namespace requirement), and a closure written against an unnamed surface could not be checked for taking a working Core path away. One scenario is added; the retained scenarios are unchanged and carried verbatim.

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

#### Scenario: Core's protected-resource route answers through the front door
- **WHEN** a direct-to-Core client follows a challenge Core issued on the front door's host to `/.well-known/oauth-protected-resource/v1/toolset/<id>/mcp` — or the deployments twin — through the front door
- **THEN** the request reaches Core unchanged and receives Core's own document, exactly as on Core's own port — the well-known closure does not cover Core's two protected-resource routes
