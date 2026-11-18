# Spec Delta

## MODIFIED Requirements

### Requirement: Authorization requests require a valid resource and allocate protected flow state

The RFC 8707 `resource` parameter MUST be the required resource disambiguator on both the authorization and token endpoints: a missing resource, a resource whose name fails the request-time guard of its kind, or a resource that is not the resource URI of a name the guard and the operator restriction of its kind (when one is configured) admit MUST be rejected as `invalid_target`. The resource URI's path shape names the resource kind — `{public-origin}/dial/{name}/mcp` a toolset, `{public-origin}/apps/{name}/mcp` an app — because one flat authorization server serves both kinds, and the resource is the only thing that says which resource, and which kind, a request is for. The toolset guard is the routed-path charset, the reserved front-door names, and the toolset restriction; the app guard is the routed-path charset and the apps restriction — the reserved names do not apply, because nothing the gateway owns is served under the apps namespace's name segment. What this endpoint decides is the name's shape and its place in its kind's restriction; whether a guard-passing, admitted name is actually served by Core is not decided here — no Core call is designed at this endpoint, and in dynamic mode a phantom name's resource URI is shape-identical to a served resource's, in either namespace — so existence is decided one leg deeper, at the flow's authenticated read of the named kind, whose refusal for a name Core does not know is the flow requirement's unknown-toolset scenario or the app-resource requirement's unknown-app scenario, the existence refusals, one per resource kind. The only escape is an explicit one-toolset operator setting, which applies only while the toolset restriction is configured with exactly one entry and never consults the apps restriction. A valid request MUST create a flow record keyed by a 128-bit CSPRNG id with a bounded TTL — a guessable id lets an attacker pair their own upstream code with a victim's session. Flow state lives server-side; the browser carries only the flow id.

*Scenario amendment, declared:* the retained "Valid request allocates a flow" scenario is re-worded by this change — "the gateway's public PKCE client" becomes "the gateway's identity-provider client" — because the identity leg's client is a confidential client whose PKCE challenge the identity-leg requirements' toggle governs (the challenge rides on top of the client authentication), so the scenario must name the leg's client without pinning the toggle's position. No other scenario changes; the retained scenario-amendments record below stays part of the requirement's text as it stands in the main spec, its three re-worded scenarios carried unchanged by this change.

*Scenario amendments, declared (retained):* three retained scenarios are re-worded by this change, each named here. "Unknown resource" is re-scoped — from the main spec's toolset-only resource-URI check to the two-shape check the endpoint performs against the request-time guard and the restriction of the resource's kind — because existence is undecidable at this endpoint without a Core call no surface at this stage is specified to make; the backstops that decide it (the flow's per-user listing read for toolsets, the app read for apps) keep their own scenarios in their own requirements. "One-toolset inference" gains its kind scoping — the WHEN names the toolset restriction where the main spec said "the operator restriction", and the THEN gains that inference never consults the apps restriction and never resolves a request to an app — because a second restriction now exists and the inference's dependency is specifically the toolset one. "Guard-failing resource refused" is re-worded for the two-shape guard — the WHEN names the request-time guard of the resource's kind where the main spec named the toolset guard only. The parenthetical's toolset backstop is re-pinned by the availability-read amendment — "the flow's per-user settings read" becomes "the flow's per-user listing read" (the federation-flow requirement's declared amendment) — so the backstop this note names is the read the flow now makes. No Core call is added to this endpoint.

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

### Requirement: The federation flow establishes the upstream credential through Core

The flow MUST authenticate the user under the gateway's identity-provider client — a confidential client whose code exchange and refresh grant authenticate with the configured client secret in both positions of the leg's PKCE toggle, the challenge riding on top where the toggle enables it — requesting only its client's default scopes; a client's `scope` parameter is never relayed — a relayed scope can fail the leg. This identity leg runs for every served toolset regardless of authentication kind: it establishes who is signing in, never what kind of credential the toolset uses. DIAL authorization is enforced by the deployment-listing read of the toolset as that user — `GET /openai/toolsets/{name}`, the read whose authorization decision is the MCP data path's own, because both are Core's deployment resolution of the name against the caller's roles, so the flow's availability oracle and the data path's per-call check are one decision, never two that can disagree — before any upstream round-trip; the upstream code goes to Core's credential API at USER level. The read's two refusal codes are two classes with different remedies, never one: a **403 is access denied** — the caller's own lack of access, the deployment resolution's refusal of them, answered with the no-access page and no upstream round-trip — and a **401 is a trust fault**: Core could not validate the sign-in's identity token, an authentication failure whose remedy is the operator's — Core's provider entry for the identity provider (its issuer, its key set, its audience) or the reachability of that key set — never the user's access; the flow fails closed on it with the operator-facing fault page saying the sign-in cannot proceed and an administrator must check the trust configuration, the flow consumed like any other refusal and no credential retained — the record's identity token is the very material Core could not validate — and neither the page nor the audit record names any user-identifying value: an authentication failure is never shown or recorded as an authorization verdict. The listing read itself fails closed on a Core answer that is unreachable or unreadable — the flow fails with the operator-facing fault page, a deployment fault and never an existence answer, rendered as a page distinct from the not-registered page the unknown-toolset scenario carries — and a projection whose authentication-kind value is absent or unusable falls into the impossible branch the same way a non-OAuth kind does: no unreadable answer is ever taken for a not-registered name, and no unreadable kind for a consentable one. That same listing read carries the toolset's public authentication type, the public authentication settings the upstream consent leg builds its URL from, and the caller's per-toolset statuses, and the flow's stages after it are, in order: **the signed-in check** — when Core reports the caller signed in at user level, or the toolset signed in at global level, the upstream stage is skipped entirely and the flow finishes by minting the harness's code, regardless of authentication kind, because a stored credential already exists and no consent could add anything; a status that is absent, unreadable, or FAILED is not signed in, and the check fails closed into the kind branch; then **the kind branch** — the upstream consent stage runs only when no credential is stored and the toolset's kind makes one establishable by consent: an OAUTH toolset continues through the upstream consent exactly as designed (its public OAuth settings — client id, endpoints, challenge, callback — are required on this branch and only this branch), and a toolset of any other kind is refused with a plain-language page saying its credential is configured directly in DIAL and cannot be established by a consent flow — audited, fail-closed, no upstream round-trip; the refusal loops benignly, like any auth error, until an administrator stores the credential out of band, after which the same flow short-circuits. The flow never establishes a credential at GLOBAL level — the credential call stays at USER level on every path that establishes one — and it never reads or transits any stored upstream credential on any path, the short-circuit included: Core injects the stored credential on the data path, and a GLOBAL credential the short-circuit uses is one an operator configured — the flow uses it, it does not establish it, which is the same access that user already holds through Core's own paths with a primary-provider token. The flow record MUST be destroyed on first use at the upstream callback. The identity provider's session-bound refresh token — issued with the code exchange, with `offline_access` never requested, so no offline grant is ever acquired — is carried for the refresh window as an encrypted claim in the gateway's own refresh token: encrypted at the code grant under the gateway's dedicated custody key, decrypted at every refresh grant, re-encrypted into each rotated refresh token. The plaintext never travels in any client-visible artifact, and the encrypted claim rides the refresh token only — never the access token, never the authorization code. Between flow end and the code grant the token transits a server-side pending entry keyed by the authorization code's id; the provider's access token is discarded at flow end. A code exchange that issues no refresh token MUST fail the flow at sign-in with an operator-facing error naming the deployment prerequisite — the refresh claims re-read requires it, and failing at sign-in is loud and per flow where failing at the first refresh would be hours late. A provider refresh token larger than the configured custody size bound MUST fail the flow the same way, for the same reason: the carrier it must fit inside is a refresh token handed to a harness token store the gateway does not control. The custody size bound and the token-endpoint request-body cap are coupled operator settings and MUST move together: the cap MUST stay at or above the bound plus the envelope's expansion and the JWT overhead (cap ≥ bound + envelope expansion + JWT overhead), so every refresh body the bound lets a sign-in issue passes the cap — a bound raised past the cap's headroom would recreate by configuration the exact far-from-its-cause failure the loud sign-in refusal exists to prevent: sign-ins succeeding while every refresh fails over-cap.

*Amendments, declared:* four clauses change. The opening "the gateway's public PKCE client" becomes "the gateway's identity-provider client — a confidential client whose code exchange and refresh grant authenticate with the configured client secret in both positions of the leg's PKCE toggle, the challenge riding on top where the toggle enables it" — because the identity leg's client shape is the confidential-client requirement's to state, and this requirement must name the leg without pinning the toggle's position; the endpoints the leg uses are the endpoint-source requirements' — the discovery requirement's in discovery mode, the direct-configuration requirement's where the operator configures the endpoint trio — and no clause of this requirement names a provider-specific endpoint spelling. The authorization-bearing read is re-pinned: "fetching the toolset settings as that user" becomes "the deployment-listing read of the toolset as that user — `GET /openai/toolsets/{name}`, the read whose authorization decision is the MCP data path's own", and every "settings read" and "settings answer" mention in this requirement's text and scenarios becomes the listing read's — because the read this requirement previously named (the bucket-based toolset settings read) is authorized by the caller's admin role, a decision the data path never makes, and refused non-admin users toolsets the data path serves — the false denial the live B2C run exposed (the first non-admin identity through the flow); the listing read and the data path share the one authorization decision (Core's deployment resolution), and the read still carries the public authentication type, the public authentication settings the consent branch builds from, and the per-caller statuses. The refusal semantics keep their named shapes and gain the code-level split: a refusal of the authorized caller is the no-access page, a name Core does not know is the unknown-toolset scenario, an unreachable or unreadable answer is the fault page — and the read's two refusal codes are split by this change's trust-fault amendment (D16, authoring round 7): a 403 keeps the access-denied class, while a 401 — which the main spec's denial scenario never named as a code and the implementation folded into the same access-denied refusal — is declared its own trust-fault class, an authentication failure with an operator's remedy, never an authorization verdict, carried by the requirement text above, the re-worded "DIAL authorization denied" scenario (its WHEN names the 403), and the new trust-fault scenario. The retained "Client scope never reaches the identity provider" scenario carries its wording unchanged. Everything else is unchanged and carried whole; the retained scenario-amendment record below stays part of the requirement's text as it stands in the main spec.

*Scenario amendment, declared (retained):* the retained "Unknown toolset refused at the flow's settings read" scenario is re-worded by this change, in two places, both declared here — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" (with the app read named as the app namespace's), and the mirror-property parenthetical gains "in both namespaces" ("on both sides of the front door" becomes "on both sides of the front door in both namespaces") — because the apps surface adds the app read as the apps namespace's existence refusal and extends the mirror property to the second namespace; the property the phrase carried is unchanged and now stated per kind: the existence refusals are the flow's authenticated reads, one per resource kind, and no unauthenticated tier on either side of the front door carries an existence oracle in either namespace. The same scenario's surface is re-pinned by the availability-read amendment: its WHEN's "toolset settings read" becomes the listing read's, because the flow's existence decision moves with the availability oracle to the deployment-listing read (the requirement's declared amendment above) — the refusal's semantics are unchanged, a 404 from Core's deployment resolution for a name it does not know, on the surface the flow now reads. The scenario's title is retained verbatim as its stable identifier (the delta discipline matches scenarios by header against the main spec, so a renamed header would read as a dropped scenario); the title's "settings read" phrase is the identifier's historical spelling, and the body — the normative content — names the surface precisely. Everything else in this requirement is unchanged and governs toolset resources; the app flow is the app-resource requirement's own.

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
- **WHEN** the caller holds a stored user-level credential for the toolset and runs the sign-in
- **THEN** the flow completes with no upstream round-trip and no consent screen, and the issued tokens are the same shape a consented flow issues

#### Scenario: A global credential serves every user without consent
- **WHEN** an operator has stored a GLOBAL-level credential for the toolset and any authorized user runs the sign-in, whatever the toolset's authentication kind
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

### Requirement: App resources complete the sign-in flow credential-free

An app resource is credential-free by construction — it carries no authentication kind and no per-app sign-in status in Core, and its MCP data path runs on the caller's own identity, authorized per call — so the sign-in flow for this resource kind is the identity leg, the DIAL authorization read, and the mint, and nothing else. The flow MUST authenticate the user under the gateway's identity-provider client exactly as for a toolset (the identity leg is kind-agnostic by construction and stays so). DIAL authorization is enforced by reading the app as that user — the single-app read `GET /openai/applications/{id}` — before any token is minted: Core answers 403 when the user cannot read the app, and the flow fails with the same no-access page a toolset refusal earns, no round-trip beyond the read; a 404 is the apps namespace's existence refusal — a plain-language page saying the app is not registered in DIAL Core, one audit record with a fixed-vocabulary reason naming the app, no flow state surviving the refusal; a 401 — Core cannot validate the sign-in's identity token — is the trust fault the toolset listing read's 401 is (the federation-flow requirement's trust-fault scenario): the operator-facing fault page, the flow consumed, never an access denial, both reads sharing the gateway's one answer-to-refusal mapping; and an unreachable or unreadable answer fails closed as a deployment fault on the operator-facing fault page, never taken for an existence answer — the same four-shape discipline the toolset listing read carries (denial, existence refusal, trust fault, deployment fault). The existence refusals are the flow's authenticated reads, one per resource kind; no unauthenticated tier on either side of the front door carries an existence oracle in either namespace.

After the read, the kind-driven short-circuit runs unconditionally for this kind: no signed-in check runs, because no per-app status members exist to read; no kind branch runs, because no consent could establish anything for a resource that needs no credential; no credential call and no upstream round-trip of any kind ever run. The flow mints the harness's code directly, and the minted tokens are the same shape a toolset sign-in issues — the audience names the app's resource. The general rule the flow's routing decision already carries decides this without a new mechanism: the upstream stage runs only when the credential is missing AND the kind makes it establishable by consent, and for the app kind the second conjunct is false by construction — where a non-OAuth toolset's missing credential blocks its data path and earns the impossible-branch refusal, an app's data path runs on the caller's own identity, so there is nothing missing to refuse. One audit record MUST show the kind-driven short-circuit: a fixed-vocabulary reason naming the resource kind, with the flow's non-credential facts.

*Amendment, declared:* three clauses change — "the gateway's public PKCE client" becomes "the gateway's identity-provider client" — because the identity leg's client is a confidential client whose PKCE challenge the identity-leg requirements' toggle governs, and the app flow shares that leg exactly as the toolset flow does; the closing comparison's "the toolset settings read" becomes "the toolset listing read" — the availability-read amendment (the federation-flow requirement's declared amendment) — so the discipline the app read is compared to is the read the toolset flow now makes; and the refusal enumeration gains the 401 trust-fault clause with the closing comparison's "three-shape discipline" becoming the four-shape one — because the listing read's 401/403 split (the federation-flow requirement's declared trust-fault amendment, D16) is the app read's too: both reads share the gateway's one answer-to-refusal mapping, so a 401 from the app read is the same trust fault, never an access denial. One retained scenario is re-worded: "App authorization denied" gains the 403 in its WHEN (the code the refusal is), aligning the scenario with the split. No other scenario changes.

#### Scenario: App sign-in completes with no consent and no credential call
- **WHEN** a harness runs the sign-in flow for an app resource — discovery, registration, the authorization request naming the app's resource URI — and the user can read the app
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
- **WHEN** the same user runs the app sign-in again while holding valid tokens
- **THEN** the flow completes the same way — no consent, no credential call — and the issued tokens are the same shape the first flow issued

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

### Requirement: Inbound tokens are verified with pinned algorithm and key selection

Inbound JWT verification MUST pin the algorithm and the key selection, so a token's header can select neither. The gateway's own tokens — codes, access tokens, refresh tokens — are verified against the gateway's own signing key under that key's pinned algorithm, with the issuer checked. The identity provider's tokens are verified under a pinned algorithm and the configured issuer, with the `kid` resolved only in that provider's own published key set — the key set the provider's discovery document names — origin-bound, like every discovered endpoint — or, where the operator configures the endpoints directly, the key-set URL the operator configures; key material embedded in a token header is never used. A token whose header carries no `kid` resolves to the provider's first published RSA signing key — the behavior the implementation has, stated so a from-spec reimplementation cannot silently refuse such tokens; with a single-key key set the resolution is unambiguous, and across rotation its failure mode is fail-closed (a mismatched resolution fails verification, never accepts a forgery kid-resolution would refuse). The issuer check is exact-string against the configured issuer: a provider whose issuers vary across its sign-in journeys — the issuer embedding the journey that issued the token — has the one federated journey's issuer configured, and a token whose issuer differs in any way — another journey's issuer of the same provider included — MUST be refused as not issued by the configured provider.

*Amendment, declared:* the requirement gains the endpoint-source key-set resolution clause ("the key set the provider's discovery document names — origin-bound, like every discovered endpoint — or, where the operator configures the endpoints directly, the key-set URL the operator configures"; the origin-bound qualifier belongs to the discovery alternative only — the operator-configured key-set URL is operator input at the issuer setting's own trust level, not a discovered endpoint) and the varying-issuer pinning sentence with its scenario — because the key set's location is the leg's one configured source's to name (the discovery document's in discovery mode, the operator's in direct mode), and issuers that vary across a provider's sign-in journeys are the shape that sentence covers. The refusal is gateway-side by construction: the pin is exact-string against the configured issuer, and no token and no discovery document can widen it; whether another journey's tokens carry a distinct issuer at all is provider-configuration — the provider must issue journey-distinct issuers for its journeys to be distinguishable by the pin (an operator prerequisite the change's configuration reference states, not a property this spec grants). The pinned-algorithm and no-kid rules are unchanged.

#### Scenario: Algorithm confusion refused
- **WHEN** a presented token carries an algorithm other than the pinned one — `alg: none` included
- **THEN** verification refuses it; the algorithm is never taken from the token

#### Scenario: Embedded key refused
- **WHEN** a token's header carries its own key material — an embedded `jwk` or `x5c`
- **THEN** verification ignores it, checks the signature against the pinned key only, and refuses the token

#### Scenario: `kid` outside the provider's key set refused
- **WHEN** an identity token's `kid` names a key absent from the issuing provider's own published key set
- **THEN** the lookup fails and the token is refused as not issued by that provider

#### Scenario: Key set resolved from the leg's one endpoint source
- **WHEN** the identity provider's tokens are verified
- **THEN** the key set they are resolved against is the one the leg's configured source names — the discovery document's in discovery mode, the same source the token and authorization endpoints come from; the operator-configured key-set URL in direct mode — never a URL built by provider-specific arithmetic

#### Scenario: A token from another journey's issuer refused
- **WHEN** the identity provider's issuers vary by sign-in journey, and a token arrives whose `iss` names any issuer other than the configured one — another journey of the same provider included
- **THEN** verification refuses it: the configured issuer is the one this deployment federates, and no other journey's token is accepted by it

### Requirement: Discovery documents describe one flat authorization server

The gateway MUST serve one RFC 8414 AS metadata document at the host root for a single path-less issuer — the public origin — and one RFC 9728 protected-resource document per served toolset. A toolset is served when its name passes the request-time name guard (routed-path charset, reserved front-door names) and is not excluded by the operator restriction when one is configured — and nothing else decides it on this surface: the document is served for every guard-passing, restriction-admitted name, whether or not Core's registry holds it. The gateway's unauthenticated discovery tier is registry-independent by design, mirroring Core's own: Core's MCP path answers an unauthenticated call — for a toolset that exists or one that does not — with 401 and a challenge naming the protected-resource document, because the auth check precedes any registry lookup (a fact of the enabled route — Core's `toolsets.security.authorizationServers` configuration is what serves it; unset, the 401 carries no challenge, and a challenge-less 401 is no existence oracle either), and Core's own unauthenticated protected-resource route answers any well-formed name with a static document built from configuration with the requested path echoed as `resource` (likewise a fact of the enabled route — the same configuration; unset, the route answers 404, which is no existence oracle either, and the gateway serves its own document regardless); no unauthenticated tier on either side of the front door carries an existence oracle, in either configuration. The mirror property is normative: the gateway's tier brings nothing Core's own does not — the same 401-challenge on the data path, the same echo-document at discovery, and existence decided at the same moment, post-authentication, at the flow's per-user listing read (whose refusal for a name Core does not know is the federation requirement's unknown-toolset scenario, the toolset namespace's existence refusal). Discovery therefore makes no Core call at all: no consult, no service credential, no cache, and no Core-unavailable failure shape — the protected-resource document costs the gateway one static document, and its availability is the gateway's own. The AS metadata MUST advertise both grants, S256, token-endpoint auth method `none`, and client-ID-metadata-document support, so CIMD-capable clients register with no registration call; it is a static document and consults nothing. Each protected-resource document MUST name the single AS issuer; its `scopes_supported` echoes the operator restriction's entry where the toolset is pinned there and is empty otherwise; its authentication-kind extension is omitted — under dynamic serving this surface has no authentication-kind source (the mapping's kind declaration is deleted, and the kind a flow acts on is Core's, read per flow at the authenticated listing read). The members are informational, and the scopes the upstream leg sends come from the toolset's Core settings; a client's faithfully echoed `scope` parameter is already accepted and dropped at the authorization endpoint, so an omitted member costs nothing on any leg.

*Amendment, declared (retained):* the requirement's text is amended in one clause only — "the system's only existence refusal" becomes "the toolset namespace's existence refusal" — because a second existence refusal exists once the app read does (the app-resource requirement's unknown-app scenario), so the sentence must state the property per namespace to stay true after the sync; the retained scenarios are unchanged and carried verbatim.

*Amendment, declared (the availability read's re-pinning):* three mentions change — the mirror-property sentence's "at the flow's per-user settings read" becomes "at the flow's per-user listing read", the authentication-kind sentence's "read per flow at the authenticated settings read" becomes "read per flow at the authenticated listing read", and the dynamic-toolset scenario's mirror-property parenthetical follows — because the flow's existence decision moves with the availability oracle to the deployment-listing read (the federation-flow requirement's declared amendment): the settings read the main spec named is authorized by the caller's admin role, a decision the data path never makes, so the flow's authenticated read of the toolset is now the listing read. The mirror property itself is unchanged: existence is still decided post-authentication, at the flow's one authenticated read of the toolset, never on any unauthenticated tier. No scenario's WHEN or THEN changes beyond the parenthetical's named read.

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

### Requirement: The toolset mapping is an optional operator restriction

The mapping is an optional operator restriction: unset, the gateway serves every platform toolset whose name passes the request-time name guard; set, only its entries are served. Configured entries keep the startup refusals that protect static routing — a reserved front-door name and a name outside the routed-path charset each refuse the container's start with an operator-facing error naming the entry — because the front router's locations are static configuration with no view of what Core serves, so neither can be repaired at request time for a name the operator pinned. The OAuth-only declaration check is removed with its reason: a restriction entry declares no authentication kind at all (the `authentication_type` member is removed from the mapping's schema — the kind a flow acts on is Core's, read per flow), and a non-OAuth toolset is a valid entry, because the flow now serves it through the signed-in short-circuit when a credential is stored and refuses it on the impossible branch otherwise. The apps restriction is a separate restriction of the same shape for the apps namespace, and the two never consult each other. Resource inference MUST refuse to start when it is enabled without the toolset restriction configured with exactly one entry: with a dynamic served set there is no "the one toolset" to infer, and inferring silently is how a token ends up addressed to a toolset the client never named — and inference never consults the apps restriction, because a second namespace served by the same authorization server makes an unnamed resource even less inferable than one.

*Scenario amendment, declared (retained):* the retained "Inference without a single-entry restriction refused" scenario's WHEN clause is re-worded — "no restriction is configured, or the configured restriction" becomes "no toolset restriction is configured, or the configured toolset restriction" — because a second restriction now exists and the inference's startup dependency is specifically the toolset one; the requirement text gains the sentences that the apps restriction is a separate restriction of the same shape and that the two never consult each other. No other scenario changes.

*Scenario amendment, declared (the availability read's re-pinning):* the retained "Unset mapping serves dynamically" scenario's THEN is re-pinned — "learned at the flow's authenticated settings read" becomes "learned at the flow's authenticated listing read" — because the flow's existence decision moves with the availability oracle to the deployment-listing read (the federation-flow requirement's declared amendment); the scenario's property is unchanged: the registry a harness can actually use is Core's, learned post-authentication at the flow's one authenticated read of the toolset. No other scenario changes.

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
- **THEN** the gateway starts, and toolsets are served whose names pass the request-time name guard — the documents are registry-independent (the mirror property), and the toolsets a harness can actually use are the ones Core's registry holds, learned at the flow's authenticated listing read

#### Scenario: Inference without a single-entry restriction refused
- **WHEN** resource inference is enabled and no toolset restriction is configured, or the configured toolset restriction does not have exactly one entry
- **THEN** the gateway refuses to start with an operator-facing error naming the setting and what it requires

#### Scenario: Inference never resolves to an app
- **WHEN** resource inference is enabled with its single-entry toolset restriction and an apps restriction is also configured, or not
- **THEN** an authorization request without a resource parameter is still resolved only to that toolset — never to an app, however many apps are served

### Requirement: Toolset names are guarded at request time

Every toolset name the gateway resolves — the protected-resource document's path, the authorization request's `resource`, and the refresh grant's resource — MUST pass one guard before it names a served toolset: the routed-path charset (lower-case letters, digits, and hyphen, `[a-z0-9-]`) and the reserved front-door names (`authorize`, `token`, `register`, `revoke`, `callback`, `jwks.json`), because the router's locations are written against exactly that shape and a name outside it has no location that routes it. This guard governs toolset-shaped resources: where a listed surface serves both kinds — the authorization request's `resource` and the refresh grant's resource — the resource's kind decides which guard applies, and the apps shape passes the app guard of the app-resource requirement, never this one. When an operator restriction is configured, a name it excludes MUST fail the same way. Guard failures fail closed with the response shape the surface already answers — 404 at the protected-resource document, `invalid_target` at the authorization and token endpoints — and each refusal lands on the audit trail with a fixed-vocabulary reason and the offered name as a truncated non-credential fact, never free-form caller input.

*Amendments, declared (retained):* the requirement is scoped to toolset-shaped resources — one sentence added, the kind-decides-the-guard rule — because the authorization request's `resource` and the refresh grant's resource resolve two kinds under two guards once the apps surface exists, while this requirement's guard, its reserved names, and its refusal shapes are the toolset namespace's own; and the surface list drops "the status endpoint's path" (with its refusal-shapes twin, "and the status endpoint" leaving the 404 enumeration) because the status endpoint is removed from the gateway entirely, both namespaces. The retained scenarios are unchanged.

*Scenario amendment, declared (the availability read's re-pinning):* the retained "A valid dynamic name resolves with no local configuration" scenario's THEN is re-pinned — "is decided by the flow's authenticated settings read" becomes "is decided by the flow's authenticated listing read" — because the flow's existence decision moves with the availability oracle to the deployment-listing read (the federation-flow requirement's declared amendment); the scenario's property is unchanged: existence is decided by the flow's one authenticated read of the toolset, never by local configuration and never on an unauthenticated surface. No other scenario changes.

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
- **THEN** the name is served on that surface exactly as a configured one is, with no gateway-side toolset configuration involved — whether Core's registry holds the name is never decided on an unauthenticated surface (the discovery tier is registry-independent by the mirror property) and is decided by the flow's authenticated listing read, never by local configuration

## ADDED Requirements

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

The gateway's identity-provider client is a confidential client: the code exchange and the refresh grant MUST authenticate the client with the configured client secret on every identity-leg token request, in both positions of the leg's PKCE toggle — the modes are client secret plus PKCE, or client secret alone, and never PKCE alone. The gateway MUST refuse to start without a configured client secret in either position of the toggle, naming the setting: the secret is the client's authentication, not a mode-conditional compensating control, so no deployment runs without one. The toggle (`IDP_PKCE_ENABLED`, default on) governs only whether the S256 challenge rides on top of the client authentication: on (the default), the identity leg's authorization redirect carries an S256 `code_challenge` and the code exchange presents the verifier — the binding that protects the leg's code while it crosses the browser, composed with the client authentication; off, for a provider that cannot support PKCE, the redirect carries no challenge and the exchange presents no verifier — the client secret alone authenticates the leg's token requests. The secret is presented on the token leg only, to the leg's one endpoint source, and is never logged, never echoed in an error, never rendered on any page, and never delivered to any client, whatever the toggle's position. The toggle changes nothing else: the client-facing AS surface keeps requiring PKCE from harness clients on every authorization request, the upstream leg's verifier stays Core's and untouched, and `offline_access` is never requested on any leg.

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
- **WHEN** the gateway logs, audits, or renders an error on the identity leg, in either toggle position
- **THEN** no record, page, or message carries the client secret — a provider refusal naming the client is recorded by its fixed-vocabulary class, never by the credential it refused
