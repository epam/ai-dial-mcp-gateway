# Proposal

## Why

Two production defects of the field-proven shape, both already priced in the standing
threat model and both fixed in outcome by the production roadmap (P3 and P2):

1. **A toolset added to Core requires a gateway reconfigure.** The served set is the
   `TOOLSETS` environment mapping, validated at startup — so every new platform OAUTH
   toolset is a `.env` edit plus a container restart, on a service whose whole point is
   to front the deployment's toolsets without touching them. The mapping's three
   startup refusals (non-OAuth kind, reserved name, charset) exist to keep
   configuration safe, not to be the source of truth for what exists; Core already is
   that source, and the flow already reads it — at the authenticated settings read,
   where existence is decided (the unauthenticated discovery tier, the gateway's and
   Core's alike, is registry-independent by design).
2. **Claims are frozen at issuance for the refresh token's whole life.** A role revoked
   at the identity provider keeps its privileges in minted tokens for up to
   `refreshTtl` (8 h locally) — the disclosed residual RES-6, the bound on never-cut
   invariant 4, and the threat-model row T1-16. The staleness collapses to the access
   TTL (identity-provider parity) only if a refresh re-reads current claims instead of
   re-issuing a frozen snapshot.

Both are contained edits on existing surfaces — no new endpoint, grant type, or trust
boundary — which is why they share one security impact analysis, one review cycle, and
one owner pause.

## What Changes

**P3 — dynamic MCPs (the served set follows Core; re-taken on the owner's two
rulings, 2026-10-31, with the discovery half re-taken once more on the owner's
final correction — issued after empirical testing).**

- The required `TOOLSETS` mapping becomes an **optional operator restriction**: unset
  means the gateway serves every platform toolset that passes the name guard; set means
  only the named
  entries are served (a deployment may still pin the served set). Startup keeps the
  two *routing* refusals for configured entries (charset, reserved names) and gains
  one refusal: resource inference enabled without a configured single-entry
  restriction. The **OAuth-only declaration check is deleted, with the mapping's
  `authentication_type` member** — under the re-taken flow a non-OAuth toolset is a
  valid entry, served through the short-circuit when Core holds a credential and
  refused on the impossible branch otherwise; the kind a flow acts on is Core's,
  read per flow.
- The **routed-path charset and reserved-name checks move to request time** as one
  guard every toolset name passes — at the protected-resource document, at
  authorization-request resource resolution, at the status endpoint, and at refresh —
  reusing the same constants the router's locations are written against. A name that
  fails fails closed with the same response shapes a harness sees today, and its
  refusal lands on the audit trail with a fixed-vocabulary reason.
- The **kind check becomes the upstream stage's routing decision inside the flow**
  (ruling 1): the identity leg runs for every served toolset regardless of kind; the
  flow's own Core settings read then carries the toolset's authentication type and
  the caller's per-toolset statuses, and **before any upstream leg the gateway
  checks whether Core already holds a stored credential — user-level OR
  global-level**. If one exists, the flow **short-circuits**: the upstream stage is
  skipped and the harness's code is minted, consentless, whatever the kind — the
  same access that user already holds through Core's own paths (the flow *uses* a
  global credential; it never *establishes* one — the credential call stays at USER
  level). Only when no credential is stored does the kind decide: OAUTH runs the
  consent leg as designed; any other kind is refused with a loud, plain-language
  page — its credential is configured directly in DIAL and cannot be established by
  a consent flow — audited, fail-closed, and looping benignly until an administrator
  stores the credential out of band. An unreadable status or kind fails closed into
  the same branch.
- **Discovery mirrors Core's registry-independent unauthenticated tier — guard-only
  (ruling 2 issued, worked, priced, then reversed by the final correction).** Every
  protected-resource fetch is answered for any guard-passing name, phantom and real
  alike, from the gateway's own static document — **zero Core calls, no service
  credential, no cache, no Core-down failure shape**. The empirical test that settled
  it: Core's MCP path answers an unauthenticated call — phantom toolset or real —
  with `401` and a challenge naming the protected-resource document (the auth check
  precedes any registry lookup, so the unauthenticated tier has no existence
  oracle), and Core's own protected-resource route answers any well-formed name
  with a registry-independent echo document (verified in the Core source and live).
  A door-consult would therefore have needed a standing service API key in Core —
  the one credential class the owner's principle bars: **no DIAL API key is ever
  involved; the gateway's only Core credentials are the user's own per-flow
  token**. The mirror property is normative — same 401-challenge, same
  echo-document, existence decided at the same moment, post-authentication, at the
  flow's settings read (the system's only existence refusal) — so the gateway's
  unauthenticated tier brings nothing Core's own does not, and discovery's
  availability is the gateway's own. What would let the gateway refuse phantoms at
  the door is recorded as a **Core-side ask** (a registry-bound protected-resource
  route or an unauthenticated existence route — the gateway flips when Core
  provides one), not built here. The consult era's artifacts (the service key, the
  amplifier threat, the availability-coupling residual, the cache question) are
  deleted with their design.

**P2 — fresh claims at refresh (the s2s re-fetch upgrade).**

- At every refresh grant the gateway **presents the identity provider's own
  session-bound refresh token to the provider's token endpoint** (RFC 6749 §6, the
  refresh grant) and mints from the verified token the grant returns — a
  frozen-snapshot fallback is not merely forbidden but made structurally impossible:
  the gateway's refresh token no longer carries a claim snapshot at all, so the
  verified fresh read is the mint's only claim input. This is the mechanism's second
  taking (design.md D1): the first (a userinfo re-read backed by a retained identity
  access token) was overruled by the owner on three verified objections — userinfo is
  RECOMMENDED, not guaranteed; its claim set is provider-filtered (fixed on Entra,
  custom-policy-only on B2C); and the retained access token dies on the provider's
  clock far inside the refresh window (5 minutes on a default Keycloak, 60–90 minutes
  fixed on Entra). The refresh grant is the one back-channel surface that survives all
  three: the token endpoint is the OIDC Discovery REQUIRED member, the grant is core
  RFC 6749, and the credential is issued for exactly this purpose, on the provider's
  own session clock. **Universality is restored — stated as dependencies, not as a
  slogan:** the mechanism is universal among providers that (1) issue refresh tokens
  to the gateway's public PKCE client at the code exchange (RFC 6749 permits an AS to
  decline; Keycloak and Entra both issue them — a provider that does not fails
  **loudly at sign-in**, per flow, as a named deployment prerequisite), (2) return a
  token from the grant whose claims the flow can verify — the same carrier and
  verification path the sign-in's exchange read already uses, so **no new claim-source
  deployment requirement appears at all** (the prior mechanism's userinfo claim-set
  prerequisite, and its owner question, are discharged), and (3) keep the
  session-bound refresh token usable across the refresh window under the provider's
  session policy (Keycloak: SSO Session Max, default 10 h — refresh use refreshes
  the idle timer but not the Max; Entra: ~24 h sliding for public clients, versus 90
  days with `offline_access`) — an operator prerequisite, asserted at startup and
  verified live for the local realm by the provisioning check.
- **One claim vocabulary, unchanged from today:** the token the flow reads at the
  exchange is exactly the token the refresh grant reads — the same verification path
  (the provider's published keys, the pinned issuer), with the additional binding that
  the fresh token's `sub` MUST equal the gateway's own refresh-token subject, so no
  provider answer can mint for another user.
- The provider's **session-bound refresh token is carried, encrypted, inside the
  gateway's own refresh token** — an AES-256-GCM envelope
  (`version | key-id | nonce | ciphertext‖tag`, pinned in code constants) under a
  dedicated, key-id-versioned 256-bit custody key separated from the signing key:
  encrypted at the code grant, decrypted at every refresh, re-encrypted into each
  rotated refresh token (the provider's latest token, latest-wins across its own
  rotations). The carrier is the refresh token only — **never the access token**
  (which rides every MCP call's Authorization header and is not even reliably
  presented at a refresh), never the authorization code. The long-lived
  per-session in-memory store of the prior taking is **deleted** (the owner's
  ruling on the custody opinion, `evidence/custody-opinion-v3.md`); what survives
  server-side is the minutes-bounded pending hand-off entry keyed by the
  authorization code's id — honestly stated: no long-lived per-session store, not
  "no store at all". The plaintext is never logged and never delivered to any
  client; the ciphertext is delivered in the refresh token by design and is
  unusable without the key. Three size controls land with it: a configured
  provider-token size bound refused loudly at sign-in, a raised and re-priced
  token-endpoint body cap, and a **live round-trip of the grown refresh token
  through both field harnesses' token stores (Claude Code and Cursor) as an
  implementation gate, not a follow-up**. The custody key's rotation is a hard
  cut (a superseded key decrypts nothing; the drill joins C3's T3).
  **`offline_access` is never requested** — the recorded
  no-`offline_access` provisioning ruling (M13) is amended deliberately, with the
  trade priced on the record: no offline (beyond-session) grant is acquired; what is
  carried is a rotating handle to the user's live IdP session. What the amendment buys is
  a strict improvement over both prior shapes: the gateway's refresh capability **ends
  when the user's IdP session ends**, and **IdP-side session revocation propagates to
  the gateway at the next refresh attempt** — a revoked user's refresh refuses
  (`invalid_grant`, audited with the distinct `idp_session_ended` token) instead of
  working for the rest of the window. What it costs is disclosed as its own
  re-shaped residual (RES-21, four parts): the carried material is **mintable** and
  rides the client-held token as ciphertext — inert without the key, but a
  recorded-token archive plus a later key leak can replay the IdP identity until
  the session dies, time-decoupled — with the
  compromise tables re-priced (design.md D3/D5, §7).
- `_require_refresh_window_within_provider_lifespan` is **re-derived, not deleted**:
  the access-token lifespan no longer bounds anything (the grant mints fresh access
  tokens), so the setting is renamed and re-meaninged (`IDP_SSO_SESSION_MAX_SECONDS`
  — the operator's declared bound on the IdP's session-bound refresh-token
  usability), the arithmetic and the loud refusal stay, the message states honestly
  that it is an operator assertion about provider session policy, and the runtime
  break fails loud as the `idp_session_ended` burst on the audit trail
  (design.md D6).

**Not in scope (the next change's, not this one's):** apps with MCP endpoints as
credential-free sign-in-able resources — and that scope is now **smaller**, because
ruling 1 unifies C1.5's planned mechanism into this change's general rule (the
upstream stage runs only when the credential is missing AND the kind makes it
establishable by consent; a DIAL_NATIVE resource has no consent leg ever, so its
flow is the identity leg plus the signed-in short-circuit, all built here): what
remains C1.5's is the apps resource surface itself (routes, discovery documents,
the router's apps MCP path) and the unsigned DIAL_NATIVE case, on machinery this
change delivers — its own change and SIA still.

## Capabilities

### New Capabilities

(none — both items modify the existing sign-in capability's requirements)

### Modified Capabilities

- `mcp-signin`:
  - MODIFIED — discovery documents (the protected-resource document is served for
    every *served* toolset, not every *mapped* one — and served for any
    guard-passing name, phantom and real alike, mirroring Core's own
    registry-independent unauthenticated tier: zero Core calls, no kind echo, no
    service credential, existence decided post-authentication at the flow's
    settings read);
  - MODIFIED — authorization requests (resource resolution by the request-time name
    guard and restriction; the one-toolset inference condition re-derived);
  - MODIFIED — the federation flow (the kind check becomes the upstream stage's
    routing decision: a stored credential at user OR global level short-circuits
    the consent for any kind — the flow uses a global credential, never establishes
    one — and only a missing credential plus a non-OAuth kind is refused, loudly,
    on the impossible branch; the provider's session refresh token carried
    encrypted in the gateway's own
    refresh token instead of discarded at flow end; a loud sign-in refusal where the
    provider issues no refresh token, and where its refresh token exceeds the
    configured custody size bound);
  - MODIFIED — issued tokens (the `sub` authority at refresh: the fresh verified
    provider token, cross-checked against the gateway's own signed subject);
  - MODIFIED — claim copy (the claim source at refresh is the fresh verified provider
    token — the same carrier and verification path as issuance; the refresh token
    carries no claim snapshot);
  - REMOVED + ADDED — the refresh requirement (its title claim, "stay local", no
    longer holds; the replacement carries every unchanged scenario verbatim —
    rotation, non-sliding window, the startup refresh-TTL bound, revocation — plus
    the refresh-grant claims re-read and its fail-closed semantics);
  - MODIFIED — abuse bounds (the carried provider credential's purposes and bounds;
    the raised, re-priced token-endpoint body cap — the discovery surfaces need no
    amendment of their own, the protected-resource document making no outbound
    call);
  - MODIFIED — sign-in status (served toolsets; the `signed_in` boolean reports
    either level, with a global-credential scenario);
  - REMOVED + ADDED — the toolset mapping requirement (its opening "MUST list
    OAuth toolsets only" sentence no longer holds; the replacement, "The
    toolset mapping is an optional operator restriction", carries the retained
    scenarios byte-identically — reserved name, charset — plus the unset
    mapping, the inference contradiction, and a non-OAuth entry *accepted*; the
    "Non-OAuth mapping refused" scenario is dropped deliberately with the
    startup refusal it pinned);
  - ADDED — toolset names guarded at request time;
  - ADDED — the identity provider's session refresh token carried encrypted in the
    gateway's refresh token.

## Impact

- **Code**: `gateway/settings.py` (the mapping becomes optional; the name-guard
  constants move to a request-time guard; the refresh-window validator re-derived and
  the setting renamed; the custody-key and size-bound settings; the raised body
  cap), `gateway/discovery.py` and `gateway/routes.py` (dynamic
  protected-resource documents behind the request-time guard — registry-independent,
  zero Core calls), `gateway/authorize.py` (request-time resolution),
  `gateway/status.py`, `gateway/core.py` (the authentication kind and level
  statuses read),
  `gateway/flow.py` and `gateway/federation.py` (the signed-in short-circuit at
  user or global level, the kind branch, the impossible-branch refusal; the pending hand-off entry; the
  no-refresh-token and over-size sign-in refusals), `gateway/idp.py` (the
  refresh-grant client; the exchange's capture of the provider refresh token), a
  small custody module (the pinned AES-256-GCM envelope, the key-id versioned
  keyset, the pending entry) beside the existing in-memory state,
  `gateway/tokens.py` and `gateway/token.py` (the snapshot-free refresh token
  carrying the encrypted custody claim; the refresh grant's decrypt–grant–re-encrypt
  mint), `scripts/provision_keycloak.py`
  (the live session-policy and refresh-behavior checks), `.env.example`,
  `README.md`, `docs/gateway-configuration.md`, and the test files covering them.
- **Operational**: `TOOLSETS` may be unset; a deployment that pins keeps its
  routing validation, and its entries no longer declare an authentication kind
  (an old mapping carrying the removed member is refused loudly at parse).
  Discovery depends on nothing but the gateway — no Core call, no service key, no
  new deployment prerequisite — so a Core outage leaves discovery serving
  documents while the Core-down failure shapes live where they already do (the
  sign-in flow's settings read and the data path). A phantom name is answered at
  discovery exactly as Core answers it (a document), and refused at the sign-in
  flow's settings read with a plain-language page — the system's only existence
  refusal.
  An operator-stored GLOBAL credential makes the toolset consentlessly
  sign-in-able for every ACL-permitted user — Core's own credential semantics,
  stated as use-not-establish. Refresh now performs one outbound identity-provider call (the refresh
  grant); a provider-side outage, a session policy shorter than the declared bound,
  or a provider that declines refresh tokens surfaces as refused refreshes (the user
  re-runs the sign-in) rather than as silently stale tokens — the refusals carry
  distinct audit tokens (`custody_decrypt_failed` vs `claims_read_failed` vs
  `idp_session_ended`) so a custody fault, a provider outage, and a session-policy
  break are distinguishable on the trail. **A gateway restart or rollout no longer
  costs a re-sign-in wave** — refresh capability survives, because the encrypted
  custody claim returns with the presented refresh token. `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS`
  is replaced by `IDP_SSO_SESSION_MAX_SECONDS`; a deployment must set it to the
  provider's real session-bound refresh lifetime, and where that policy is short, the
  short refresh window is the correct configuration, not a degraded one. The refresh
  token grows by the encrypted claim; the deployment's harness token stores must
  tolerate it (verified live for both field harnesses before the change is done).
- **Security**: the security impact analysis runs in full (per-change shape — delta
  threats at the touched entry points); it re-prices RES-6 (the staleness bound
  shrinks from the refresh window to the access TTL) and RES-2/RES-3 (the custody
  and token-use rules: a dedicated custody key beside the signing key, and the
  provider credential's plaintext presented once per refresh), adds RES-20 (the
  availability trade of the mandatory read) and **RES-21 (the mintable-custody
  residual of the M13 amendment, re-shaped in four parts for the encrypted chain —
  the at-rest ciphertext in harness stores, the time-decoupled key-plus-archive
  conjunction, the stolen-token-survives-restart regression, and the unchanged
  process-compromise floor)**, extends the internal-leg class to the refresh-grant
  call, records the IdP-session-revocation propagation as a gain with the revocation
  summary's re-priced row, and re-prices the compromise tables. The P3 re-taking
  adds its own priced set, as corrected by the final ruling: the three new
  flow-era threat rows (the short-circuit's widened mint surface, the
  global-credential mis-use, the forged signed-in answer), the stated GLOBAL
  delegation in invariant 3's wording (use vs establish), and the enumerable-set
  widening re-priced against the mirror property (the set names nothing Core's own
  unauthenticated tier does not name) — with **no new secret and no new outbound
  leg**: the consult era's service key, amplifier threat, availability-coupling
  residual, and cache question are deleted with the consult (no DIAL API key is
  ever involved), and what would let the gateway refuse phantoms at the door is
  the Core-side ask, not a gateway-held credential. The threat-model
  updates are part of this change's tasks, not a follow-up.
- **Client credential**: where the deployment's provider requires client
  authentication at the token endpoint, the existing client-secret setting covers it
  (the same setting the code exchange already uses); the requirement that this secret
  move under the deployment's secret management is recorded here and lands in the
  later secret-management scope.
