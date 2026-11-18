# Spec Delta

## ADDED Requirements

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

## MODIFIED Requirements

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

### Requirement: The federation flow establishes the upstream credential through Core

The flow MUST authenticate the user under the gateway's identity-provider client — a confidential client whose code exchange and refresh grant authenticate with the configured client secret in both positions of the leg's PKCE toggle, the challenge riding on top where the toggle enables it — requesting only its client's default scopes; a client's `scope` parameter is never relayed — a relayed scope can fail the leg. This identity leg runs for every served toolset regardless of authentication kind: it establishes who is signing in, never what kind of credential the toolset uses. DIAL authorization is enforced by the deployment-listing read of the toolset as that user — `GET /openai/toolsets/{resource-path}`, the resource path being the same id Core's own routes and responses carry, addressed in the canonical encoding — the read whose authorization decision is the MCP data path's own, because both are Core's deployment resolution of the id against the caller's roles, so the flow's availability oracle and the data path's per-call check are one decision, never two that can disagree — before any upstream round-trip; the upstream code goes to Core's credential API at USER level, with the call's `url` member carrying the decoded resource path and its `redirectUri` member carrying the gateway's derived upstream callback (the upstream-authorization-request requirement's value — never the stored registration field). The read's two refusal codes are two classes with different remedies, never one: a **403 is access denied** — the caller's own lack of access, the deployment resolution's refusal of them, answered with the no-access page and no upstream round-trip — and a **401 is a trust fault**: Core could not validate the sign-in's identity token, an authentication failure whose remedy is the operator's — Core's provider entry for the identity provider (its issuer, its key set, its audience) or the reachability of that key set — never the user's access; the flow fails closed on it with the operator-facing fault page saying the sign-in cannot proceed and an administrator must check the trust configuration, the flow consumed like any other refusal and no credential retained — the record's identity token is the very material Core could not validate — and neither the page nor the audit record names any user-identifying value: an authentication failure is never shown or recorded as an authorization verdict. The listing read itself fails closed on a Core answer that is unreachable or unreadable — the flow fails with the operator-facing fault page, a deployment fault and never an existence answer, rendered as a page distinct from the not-registered page the unknown-toolset scenario carries — and a projection whose authentication-kind value is absent or unusable falls into the impossible branch the same way a non-OAuth kind does: no unreadable answer is ever taken for a not-registered name, and no unreadable kind for a consentable one. That same listing read carries the toolset's public authentication type, the public authentication settings the upstream consent leg builds its URL from — the callback excepted, which the gateway derives and the stored field never supplies — and the caller's per-toolset statuses, and the flow's stages after it are, in order: **the signed-in check** — when Core reports the caller signed in at user level, or the toolset signed in at global level, the upstream stage is skipped entirely and the flow finishes by minting the harness's code, regardless of authentication kind, because a stored credential already exists and no consent could add anything; a status that is absent, unreadable, or FAILED is not signed in, and the check fails closed into the kind branch; then **the kind branch** — the upstream consent stage runs only when no credential is stored and the toolset's kind makes one establishable by consent: an OAUTH toolset continues through the upstream consent exactly as designed (its public OAuth settings — client id, endpoints, challenge — are required on this branch and only this branch; the callback is the gateway's derived one, never the projection's), and a toolset of any other kind is refused with a plain-language page saying its credential is configured directly in DIAL and cannot be established by a consent flow — audited, fail-closed, no upstream round-trip; the refusal loops benignly, like any auth error, until an administrator stores the credential out of band, after which the same flow short-circuits. The flow never establishes a credential at GLOBAL level — the credential call stays at USER level on every path that establishes one — and it never reads or transits any stored upstream credential on any path, the short-circuit included: Core injects the stored credential on the data path, and a GLOBAL credential the short-circuit uses is one an operator configured — the flow uses it, it does not establish it, which is the same access that user already holds through Core's own paths with a primary-provider token. The flow record MUST be destroyed on first use at the upstream callback. The identity provider's session-bound refresh token — issued with the code exchange, with `offline_access` never requested, so no offline grant is ever acquired — is carried for the refresh window as an encrypted claim in the gateway's own refresh token: encrypted at the code grant under the gateway's dedicated custody key, decrypted at every refresh grant, re-encrypted into each rotated refresh token. The plaintext never travels in any client-visible artifact, and the encrypted claim rides the refresh token only — never the access token, never the authorization code. Between flow end and the code grant the token transits a server-side pending entry keyed by the authorization code's id; the provider's access token is discarded at flow end. A code exchange that issues no refresh token MUST fail the flow at sign-in with an operator-facing error naming the deployment prerequisite — the refresh claims re-read requires it, and failing at sign-in is loud and per flow where failing at the first refresh would be hours late. A provider refresh token larger than the configured custody size bound MUST fail the flow the same way, for the same reason: the carrier it must fit inside is a refresh token handed to a harness token store the gateway does not control. The custody size bound and the token-endpoint request-body cap are coupled operator settings and MUST move together: the cap MUST stay at or above the bound plus the envelope's expansion and the JWT overhead (cap ≥ bound + envelope expansion + JWT overhead), so every refresh body the bound lets a sign-in issue passes the cap — a bound raised past the cap's headroom would recreate by configuration the exact far-from-its-cause failure the loud sign-in refusal exists to prevent: sign-ins succeeding while every refresh fails over-cap.

The consent/attribution checkpoint gates the mint on first attribution, after the identity leg and before every mint this requirement's paths issue: once the listing read has run and the flow record carries the resolved client (`client_id`, `client_name`, `redirect_uri`) and the addressed resource, the approved-client registry is consulted on both toolset mint paths — the stored-credential short-circuit consults it before the mint itself, an approved (subject, client) passing through with the flow unchanged and an unapproved one rendering the decision page where the short-circuit minted silently before; the consent branch's checkpoint rides the interstitial's existing position, after the read and before the upstream redirect — on first attribution the interstitial's display-only auto-continue is replaced by the decision page for that one presentation, and once the client is approved the flow keeps the display interstitial verbatim, the notice and the decision being different jobs and only the first attribution lacking the decision. No mint path on the toolset kind completes without passing the registry check. The consent branch's continuation — the upstream authorization URL the branch builds — MUST be stored on the flow record at the decision point, the same discipline the derived upstream redirect URI already follows, because the approve action continues the flow from the record alone; the identity-leg outcomes the approve action needs are record-resident already — the claim snapshot, the client facts, and the provider's session refresh token. The checkpoint's page, action, and registry are the checkpoint requirement's own.

**The deployment prerequisite this flow's consent branch names.** Core MUST carry the gateway's derived upstream callback in its configured `allowedRedirectUris` — Core's exchange-time validation accepts the presented `redirectUri` only from that list (or as the stored field's equal, which this flow no longer relies on) — and each dynamically-registered toolset MUST have Core's repair API re-run after the allowlist carries all the deployment's callbacks, because DCR registers the list once, at creation time. The prerequisite is Core configuration with an operator owner; the configuration reference and the local-environment runbook carry the procedure and its ordering (the gateway's callback first while any stored-field reader remains), and a consent that fails it fails closed at Core's exchange — an operator-facing, per-flow visible failure, never a mis-delivery.

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

### Requirement: Authorization requests require a valid resource and allocate protected flow state

The RFC 8707 `resource` parameter MUST be the required resource disambiguator on both the authorization and token endpoints: a missing resource, a resource whose path fails the request-time path guard of its kind, or a resource that is not the resource URI of a path the guard and the operator restriction of its kind (when one is configured) admit MUST be rejected as `invalid_target`. The resource URI's path shape names the resource kind — `{public-origin}/dial/{path}/mcp` a toolset, `{public-origin}/apps/{path}/mcp` an app, the path one or more segments in the canonical or an accepted equivalent spelling — because one flat authorization server serves both kinds, and the resource is the only thing that says which resource, and which kind, a request is for. The toolset path guard is the decoded segment rules, the first-segment reserved front-door names, and the toolset restriction; the app path guard is the decoded segment rules and the apps restriction — the reserved names do not apply, because nothing the gateway owns is served under the apps namespace's first segment. An accepted spelling is canonicalized at resolution: the flow record, the token audience, and the refresh match carry the canonical form, so two spellings of one resource are one resource. What this endpoint decides is the path's shape and its place in its kind's restriction; whether a guard-passing, admitted path is actually served by Core is not decided here — no Core call is designed at this endpoint, and in dynamic mode a phantom path's resource URI is shape-identical to a served resource's, in either namespace — so existence is decided one leg deeper, at the flow's authenticated read of the named kind, whose refusal for a path Core does not know is the flow requirement's unknown-toolset scenario or the app-resource requirement's unknown-app scenario, the existence refusals, one per resource kind. The only escape is an explicit one-toolset operator setting, which applies only while the toolset restriction is configured with exactly one entry and never consults the apps restriction. A valid request MUST create a flow record keyed by a 128-bit CSPRNG id with a bounded TTL — a guessable id lets an attacker pair their own upstream code with a victim's session. Flow state lives server-side; the browser carries only the flow id.

The client's `state` is OPTIONAL, and its handling is a stated rule: a request carrying one MUST have it stored on the flow record at allocation and echoed back **unchanged** on the final redirect; a request carrying none is tolerated — nothing is echoed — because the CSRF-binding work `state` does for a client is already done by things this surface requires: PKCE S256 is mandatory, the `resource` is required and validated, codes are single-use and short-lived, and the flow id — an unguessable server-side binding — round-trips every browser leg (RFC 9700 §2.1's accepted carrier), and the ecosystem's client contract makes `state` a SHOULD, not a MUST, so refusing it would break conforming clients for zero security gain. One bound lands with the rule: a `state` over **2048 bytes** MUST be refused as `invalid_request` with the fixed-vocabulary reason `oversized_state`, on the flow-record allocation path, before the record exists — every other caller-chosen length on this surface is bounded, and the `state` is caller-chosen text stored on an in-memory record and echoed on a redirect, so its length is bounded with them. The refusal is a pre-allocation refusal and lands on that discipline's audited enumeration.

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

### Requirement: The toolset mapping is an optional operator restriction

The mapping is an optional operator restriction: unset, the gateway serves every toolset whose **resource path** passes the request-time path guard; set, only its entries are served. Entries are resource paths — a bare config-entity name or a stored toolset's full path (`toolsets/{bucket}/{folders…}/{name}`) — and restriction membership is decided on the canonical form, so no spelling of a restricted-out resource can enter by encoding. Configured entries keep the startup refusals that protect static routing — a reserved first segment, a segment outside the decoded rules, a trailing dot, a dot or empty segment, an over-length or over-depth path each refuse the container's start with an operator-facing error naming the entry and the rule it broke — because the front router's locations are static configuration with no view of what Core serves, so neither can be repaired at request time for a path the operator pinned. A restriction entry declares no authentication kind at all (the retained rule: the kind a flow acts on is Core's, read per flow), and a non-OAuth toolset is a valid entry, because the flow serves it through the signed-in short-circuit when a credential is stored and refuses it on the impossible branch otherwise. The apps restriction is a separate restriction of the same shape for the apps namespace, and the two never consult each other. Resource inference MUST refuse to start when it is enabled without the toolset restriction configured with exactly one entry: with a dynamic served set there is no "the one toolset" to infer, and inferring silently is how a token ends up addressed to a toolset the client never named — and inference never consults the apps restriction, because a second namespace served by the same authorization server makes an unnamed resource even less inferable than one.

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

### Requirement: Public endpoints are bounded against abuse

Unauthenticated endpoints that allocate state MUST be rate-limited per source and globally; live flow records MUST be capped with oldest-first eviction. Every unauthenticated body-bearing endpoint MUST cap the request body in bytes at reading; over-cap is refused. Expired, evicted, and unknown flows MUST land on a plain-language re-run page, never an opaque failure. Every resource path the guard resolves — on the discovery routes, the authorization endpoint, and the token endpoints' resource parameters — MUST be bounded before any work proportional to it: the decoded path MUST NOT exceed 900 UTF-8 bytes and its segment count MUST NOT exceed the configured cap, and an over-bound path is refused with the surface's fail-closed shape and a fixed-vocabulary reason — the bounds make each admitted request's cost constant, whatever the path's length or depth. The identity provider's session refresh token, while carried, is bounded by the refresh token's original absolute expiry, and its plaintext is presented exactly one refresh-grant call per gateway refresh — purposes named, not counted; the bounds govern the gateway's carrying of it, never the credential's usability, which is the provider's own session policy. The token's plaintext is never delivered to any client and never written to any log; the encrypted claim is delivered inside the refresh token by design and is unusable without the custody key. The identity access token's retention is unchanged by this design: it is exposed at most min(flow TTL, its own expiry) — the TTL bounds the gateway's retention, not the token's life — as before. Each protected-resource discovery endpoint — the toolset route and the apps route — MUST join the same per-source and global rate limiter as every other unauthenticated surface, so its guard refusals — each of which writes an audit record — cannot be written faster than the requests that carry them: without the limiter, an unauthenticated caller looping guard-failing paths would grow the operator's log at whatever rate it chose. Over the limit either endpoint MUST be answered with the limiter's 429 and MUST write no record at all, so the bound holds at the limit itself.

The authorization-server surface is back-channel only toward browsers, as a rule and not an implementation accident: no endpoint on the surface serves any `Access-Control-*` header — the browser-facing routes (`/dial/authorize`, the callbacks, the consent route) and the back-channel endpoints (`/dial/token`, `/dial/revoke`, the discovery documents, the registration endpoint) alike — no preflight is handled (an `OPTIONS` preflight against `/dial/token` receives the framework's 405), and a browser frontend is not a supported client shape: the clients are harness processes exchanging codes and tokens on their own loopback redirects and back channels, and a cross-origin browser page can neither read a token response nor drive the authorize surface's redirects. RFC 9700 §2.6 permits CORS at the token endpoint as a MAY and forbids it at the authorization endpoint; the gateway declines the MAY, surface-wide, and this spec says so.

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

## REMOVED Requirements

### Requirement: Toolset names are guarded at request time

**Removed because its subject changes, not because the discipline does.** The requirement guarded a one-segment `[a-z0-9-]+` name; the front door's addressing vocabulary is now the resource path (the addressing-vocabulary requirement), and the guard it needs is the path guard — per-segment decoded rules, the first-segment reserved-name scoping, the byte and depth caps — which the ADDED "Resource paths are guarded at request time" requirement carries, with this requirement's refusal discipline (fixed vocabulary, truncation, fail-closed shapes, the restriction's same-refusal rule) inherited verbatim in kind. The removal and the addition are one rename, declared here rather than left to a header mismatch the delta discipline would misread as a dropped guard.
