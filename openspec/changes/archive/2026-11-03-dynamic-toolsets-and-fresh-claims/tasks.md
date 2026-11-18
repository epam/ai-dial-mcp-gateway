# Tasks

Completion state: the implementation is **complete and gated**. Sections 1, 2, 4 and 5
are implemented and verified (evidence: `evidence/gates.md`, `evidence/live-runs.md`,
`evidence/security-review-gate.md`, `evidence/general-review-gate.md`); sections 3.1 and
3.2 ran live on the composed stack (`evidence/live-runs.md`). **Task 3.3** — the Claude
Code (CIMD) + Cursor (DCR) harness token-store round-trip gate — **PASSED**, owner-driven
2026-11-02 (`evidence/live-runs.md` §H): both harnesses completed sign-in → refresh →
gateway restart → refresh with the grown token intact, so no harness store refused it and
the custody shape stands. The only remaining item before the archive is **the commit
itself (5.6)**, which follows. The authoring history below is retained for the record.

Authoring note (historical): this change was specified first, every box starting
unchecked, and the implementation pass ran against this list after the independent
review and the owner pause. Section 2 (P2) is the re-taken mechanism: the
userinfo-based tasks of the first taking are superseded by the owner's ruling
(design.md D1); the tasks below specify the refresh-grant mechanism. Custody is
re-taken a second time (v3, the owner's ruling on
`evidence/custody-opinion-v3.md`): the in-memory retention store of the second
taking is deleted — the provider's session refresh token rides the gateway's own
refresh token as an encrypted custody claim (design.md D3); tasks 2.1–2.3 and
3.1/3.3 below specify that shape. Section 1 (P3) is re-taken a second time on the
owner's two rulings after the three review rounds (2026-10-31) — and its discovery
half re-taken once more on the owner's final correction, issued after empirical
testing (2026-10-31): the kind check is
the upstream stage's routing decision inside the flow — a stored credential at
user OR global level short-circuits the consent for any kind, and only a missing
credential plus a non-OAuth kind is refused (design.md D11/D12) — and discovery
serves every guard-passing name, mirroring Core's registry-independent
unauthenticated tier by design (zero Core calls, no service key; existence is
decided post-authentication at the flow's settings read — design.md D8, re-taken:
no DIAL API key is ever involved, and the consult, its service key, its
concurrency bound, and its threats are deleted); the startup
OAuth-declaration refusal is deleted with the mapping's `authentication_type`
member (design.md D7). The P2 tasks (section 2) and the custody tasks are
untouched by that re-taking.

## 1. P3 — dynamic toolsets

- [x] 1.1 Make the mapping an optional restriction in `gateway/settings.py`: an
  unset/empty `TOOLSETS` is valid and means "serve every platform toolset that
  passes the request-time guard" (existence being decided post-authentication,
  at the flow's settings read — D8's mirror property). Keep `_validate_mapping`
  for *configured* entries byte-for-byte in behavior for the two routing
  refusals (charset, reserved names each refuse startup naming the entry), and
  **remove the OAuth-declaration refusal together with the
  `authentication_type` member of `ToolsetMapping`** (design.md D7 — the
  ruling-1 re-taking: a non-OAuth toolset is a valid entry, served through the
  short-circuit when Core holds a credential and refused on the impossible
  branch otherwise; the kind a flow acts on is Core's, read per flow, so an
  operator-declared kind would be a second, staler source of that fact). A
  mapping document that still carries the removed member is refused loudly at
  parse by the schema (`extra="forbid"` names the field) — that refusal is the
  migration, and task 1.5's operator row names it. Add the startup refusal for
  `gateway_infer_resource_single_toolset` enabled without a restriction
  configured with exactly one entry, with an operator-facing message naming
  the setting and what it requires. Re-derive the docstrings: the mapping is a
  restriction, not the served-set source. Verify: the existing
  `tests/test_settings.py` mapping rows still pass unchanged for the two
  retained refusals; the OAuth-declaration rows are updated to assert the new
  behavior (the entry is accepted; the field is refused); new rows cover the
  unset mapping, the inference contradiction, and each refusal's
  operator-facing message.
- [x] 1.2 Introduce the request-time name guard as one shared predicate
  (`charset` + reserved names, reusing `RESERVED_TOOLSET_NAMES` and the
  `_TOOLSET_NAME` pattern, plus the restriction check when configured) and apply
  it at every toolset-name resolution site: the protected-resource document route
  (`gateway/routes.py`), the authorization request's resource resolution
  (`gateway/authorize.py` — replacing the mapping lookup; the resource URI's path
  segment names the toolset), the status endpoint (`gateway/status.py`), and the
  refresh grant's resource-to-name resolution (`gateway/token.py` — the refresh
  grant's implementation site; `gateway/tokens.py` is the mint/verify module and
  handles no requests). Guard
  failures answer the surface's existing shape (404 at discovery/status,
  `invalid_target` at the authorization and token endpoints — the code grant's
  resource-mismatch analogue answers `invalid_target` today, `gateway/token.py:289-291`)
  and audit a fixed-vocabulary reason (`reserved_toolset_name`,
  `invalid_toolset_name`, `restricted_toolset`) with the offered name as a
  truncated fact. At the token endpoint the reason must reach the record through
  the closed `_REFUSAL_REASONS` table's discipline (`gateway/token.py:96-126`):
  extend the closed vocabulary with the guard's reason tokens on the
  `invalid_target` refusal class — the table's keying widens from the error code
  alone to error code plus named refusal class where a class must be
  distinguishable, every new token committed in the table, so the closed-table
  property holds (a refusal always lands on a token from the table; an unmapped
  class raises in tests rather than logging an unrecognized token). No refusal
  bypasses the table with a direct `flow_refused` call. Verify: unit rows for
  each site and each reason; a row asserting a harness-visible response shape
  identical to the unknown-name refusal on the same surface, the token endpoint
  included; a row asserting each new refusal class lands on its committed token
  from the closed table.
- [x] 1.3 Discovery serves the guard-passing name (`gateway/routes.py`,
  `gateway/discovery.py`; design.md D8 re-taken — guard-only, the mirror
  property): replace the protected-resource route's mapping-membership check
  with the request-time guard (charset + reserved names, task 1.2's predicate)
  plus the optional restriction — any guard-passing, restriction-admitted name
  is served its document, **phantom and real alike**, with no Core call of any
  kind. No consult client is added to `CoreClient`; no service-key slot, no
  consult concurrency bound, no cache, and no discovery-side 503 exist. The
  document's shape follows design.md D9: the name-derived resource URI, the
  single AS issuer, `scopes_supported` echoing the restriction entry's where
  the name is pinned there and empty otherwise, and the authentication-kind
  extension omitted for every document (the discovery surface has no kind
  source under dynamic serving — the kind is Core's, read per flow). The
  mirror property is the normative justification and is stated in the route's
  docstring: Core's MCP path 401s an unauthenticated call, phantom or real
  alike, with the challenge naming the protected-resource document (the auth
  check precedes any registry lookup — no unauthenticated existence oracle),
  Core's own PRM route answers any well-formed name with a registry-independent
  echo document (verified in the Core source and live), and the router's
  challenge synthesis already points a challenged harness at this route — the
  gateway's tier brings nothing Core's own does not. The flat AS metadata
  document consults nothing and is untouched. Verify: unit rows for the
  guard-passing serve in dynamic mode (no `TOOLSETS` configured — a name Core
  does not know is served its document, and a negative control proves no Core
  call is made on this path), the restriction-excluded 404, the guard
  refusals (reserved name, charset violation) with their fixed-vocabulary
  audit records, a row asserting the kind extension is absent from every
  served document, and a row asserting scopes echo the restriction entry
  where pinned and are empty otherwise.
- [x] 1.4 Re-take the flow's stages to the routing decision (`gateway/core.py`,
  `gateway/flow.py`, `gateway/federation.py`; design.md D11/D12). In
  `gateway/core.py`: `read_toolset_settings` reads `auth_settings.authentication_type`
  into the settings object and **stops refusing a projection whose OAuth fields
  are absent** — a non-OAuth toolset's projection is readable; the OAuth-fields
  completeness refusal ("re-register the toolset") moves to the consent branch,
  the only branch that builds a URL from them (`upstream_authorization`'s
  delivery guard remains the last line). `ToolsetStatus.signed_in` becomes
  **user-level OR global-level SIGNED_IN** (both members are already read; the
  vocabulary is SIGNED_IN / SIGNED_OUT / FAILED — an absent, unreadable, or
  FAILED status is not signed in). Core's answer also carries a third member,
  `app_level_auth_status`: the check reads the user and global members only —
  an app-level status is not a sign-in for this flow, and a toolset whose only
  stored credential is APP_LEVEL fails closed into the kind branch (an operator
  storing an APP_LEVEL credential for a non-OAUTH toolset gets the
  impossible-branch refusal). In `gateway/federation.py` /
  `gateway/flow.py`, the identity-leg completion's order becomes: exchange →
  the settings-and-status read (DIAL authorization, kind and statuses carried)
  → **the signed-in check**: `signed_in` short-circuits to `_finish`
  (mint the code, the pending custody entry created on both paths per task
  2.2), regardless of kind → **the kind branch**: OAUTH builds the upstream
  authorization as today; any other kind refuses with the plain-language page
  ("this toolset's credential is configured directly in DIAL and cannot be
  established by a consent flow; ask your DIAL administrator"), the audited
  `non_oauth_toolset` reason, and no upstream round-trip. An unusable or absent
  kind value fails closed the same way as a non-OAuth kind (an unreadable kind
  cannot be establishable). The credential call is unchanged and stays
  `credentialsLevel: USER` on every establishing path — the use-vs-establish
  rule is asserted by a test, not just stated. Verify: federation rows for the
  user-level short-circuit (no upstream leg, no consent screen, tokens issued),
  the global-level short-circuit for a non-OAuth toolset (the delegation row:
  no credential call, no upstream leg, tokens issued), the impossible-branch
  refusal (page text, audit record, no upstream leg), the fail-closed status
  shapes (absent, non-string, FAILED each falling through), a row asserting an
  app-level-only status does not short-circuit (the third member is read by
  nothing), and negative
  controls proving the upstream authorize URL is never built on the
  short-circuit and refusal paths and that no path reads or transits a stored
  upstream credential.
- [x] 1.5 Update the operator-facing material: `.env.example` (the `TOOLSETS`
  block becomes the optional restriction with both modes stated and **no
  `authentication_type` member** — a row naming the removal and the loud
  parse-refusal an old mapping earns; no other new setting — the consult era's
  `dial_core_api_key` and `gateway_discovery_max_concurrent_consults` slots are
  deleted with the consult and must not appear), `README.md`'s quickstart,
  and `docs/gateway-configuration.md`'s mapping and discovery sections (the
  refusal table's rows move to their new homes: startup for the two configured
  -entry routing refusals, request time for the guard, the flow for the kind
  branch and the unknown-name refusal at the settings read; the discovery
  section gains the mirror property — any guard-passing name is served its
  document, phantom and real alike, zero Core calls, no service key, the kind
  extension omitted — and the global-credential
  short-circuit's semantics, stated as use-not-establish). No real instance
  or issuer values (the standing publication discipline). Verify: the committed
  examples are valid JSON in both modes, no operator-facing document still
  names the removed `authentication_type` member, and none names a
  discovery-side service key, consult, or Core-unavailable 503.
- [x] 1.6 Reconcile `docs/production-roadmap.md`'s lines this change has made
  stale, in this change's completion pass, so the tracker does not drift against
  the change that altered its facts: P3's accepts line ("non-OAUTH and unknown
  names fail closed as today" — under ruling 1 a non-OAuth toolset with a stored
  credential is *served* through the short-circuit, and the unknown name's
  fail-closed refusal lives at the flow's authenticated settings read, discovery
  having answered it a document by the mirror property — the behavior stands,
  its home and its vocabulary changed) and the C1.5 entry
  ("adds a new resource kind and a short-circuit branch to the flow" — the
  branch machinery is built by this change, which unifies C1.5's planned
  mechanism into the general rule; what remains C1.5's is the apps resource
  surface and the unsigned DIAL_NATIVE case, as the proposal declares). The
  rulings are the owner's and supersede the tracker's older acceptance
  phrasing; this task re-states the two lines to match what actually lands.
  Verify: both lines re-state the landed behavior; no roadmap line still
  claims the pre-ruling P3 acceptance or the pre-unification C1.5 scope.

## 2. P2 — fresh claims at refresh (the refresh-grant mechanism)

- [x] 2.1 Add the refresh-grant client to `gateway/idp.py` and capture the
  provider's refresh token at the exchange: `exchange_code` reads
  `refresh_token` from the token-endpoint response into `Identity` (a new
  field) — and the captured token is checked against the configured
  provider-token size bound (`gateway_custody_provider_token_max_bytes`,
  default 4096): an over-bound token fails the flow **at sign-in** with an
  operator-facing error naming the bound, the same refusal class as the
  no-refresh-token failure (design.md D3/A5 — the carrier the token must fit
  inside is a refresh token handed to a harness token store the gateway does
  not control; fail at sign-in, never hours later at refresh) — and a new
  `refresh_identity(provider refresh token)` performs RFC 6749
  §6 against the same token-endpoint URL the exchange uses (the internal base
  URL and realm derivation that already exist — one spelling, no new URL
  construction), posting `grant_type=refresh_token`, `client_id`, and the
  optional client secret from the existing setting, with the configured outbound
  timeout, `follow_redirects=False`, and bounded response parsing (size cap, JSON
  object required, fixed refusal text safe to show and log — the exception type,
  never a provider message). The URL never comes from any request. The response
  handling distinguishes: a provider refusal carrying the OAuth error
  `invalid_grant` (RFC 6749 §6's session-gone code — the session is gone:
  revoked, expired by session policy, or consumed by a lost rotation) from every
  other failure (transport, 5xx, non-JSON, oversize, no token, and any other
  provider 4xx — `invalid_client` from a misconfigured client secret or
  `invalid_request` from a gateway bug say nothing about the session) — the two
  refusal classes the refresh grant audits differently, keyed on the error code
  so a misconfiguration burst never reads as mass revocation. The fresh token is
  returned *unverified* to the caller together with the response's new
  `refresh_token` when present (latest-wins, task 2.2), and verification runs
  through the existing `_verified_claims` path so issuance and refresh share one
  vocabulary and one verification path (design.md D2). Verify: unit rows for the
  happy path (token + optional new refresh token), each refusal class (unreachable,
  provider `invalid_grant`, provider `invalid_client`, 5xx, non-JSON, oversize, no
  access token), and that no
  request field can steer the URL; a row proving the exchange captures the
  refresh token, that an over-bound capture refuses the flow at sign-in with
  the operator-facing error, and that `Identity` never logs it (plaintext or
  ciphertext).
- [x] 2.2 Build the custody module (v3 — design.md D3) and the pending
  hand-off entry beside the existing in-memory state (`gateway/state.py` or a
  sibling). **The envelope, pinned in code constants:** AES-256-GCM via
  `cryptography`'s `AESGCM` (already a dependency through `pyjwt[crypto]`;
  PyJWT is sign-only — no JWE — so a signed-but-readable claim is the
  code-payload mistake restated), a 256-bit key, a 96-bit CSPRNG nonce, layout
  `version | key-id | nonce | ciphertext‖tag`, base64url; the algorithm and
  lengths are constants, never envelope-selected (the M20 lesson applied to our
  own encryption); the envelope embeds `sub` (the refresh token's signed
  subject) and its own `exp`, both checked at the custody seam before any use —
  an embedded `sub` that differs from the carrying token's, an expired
  envelope, an unknown version, or an unknown key-id refuses closed. **The
  key:** a dedicated 256-bit symmetric key in a new settings slot
  (`gateway_custody_keys`, a key-id → key mapping with exactly one active
  entry; startup refuses an empty or multi-active keyset, and any key that is
  not exactly 32 bytes — AES-GCM's algorithm follows the key's length, so a
  16- or 24-byte key would silently run AES-128/192 for the key's lifetime and
  falsify the pinned-algorithm claim; the signing key's own minimum-size load
  check, `gateway/keys.py:63-68` refusing a key under 2048 bits at load, is
  the pattern), separated from the
  signing key, custody following `gateway/keys.py`'s `SigningKey` discipline —
  never logged, never in `repr`; **rotation is a hard cut** — replacing the
  active entry removes the superseded key entirely, so every outstanding blob
  refuses at its next presentation (design.md D3/A3; the drill joins C3's T3;
  the wrapped-DEK-over-per-refresh-KMS-call preference at C3 is recorded as
  input there). **The pending hand-off seam:** at `_finish`
  (the flow end, on both flow paths — the consented flow and the
  already-signed-in short-circuit — where the gateway refresh token does
  not yet exist and the flow record never reaches the code grant: destroyed on
  the consented path before `_finish` runs, TTL-bounded and credential-free on the
  short-circuit, where `_finish` clears the record's identity access token and its
  provider session refresh token so only the claim snapshot outlives the flow's use of
  them), the provider's session refresh
  token lands in a **server-side pending entry keyed by the authorization code's
  `jti`**, bounded by the code's own short TTL and dropped when the code expires
  unredeemed; the code grant consumes the entry and encrypts the token into the
  issued refresh token's custody claim. The provider refresh token MUST NOT be
  carried in the authorization code's payload or any other client-visible
  artifact, in plaintext or as ciphertext — the code is a signed-but-unencrypted
  JWT whose payload anyone holding the string can read, and this token is
  mintable credential material, so embedding it there would
  deliver a mintable IdP credential to the client (never-cut 5); the transit is
  server state only. The pending entries are memory-only — a restart drops
  them, and an unredeemed pre-restart code fails its grant fail closed — while
  the custody itself survives the restart (the claim returns with the token).
  The plaintext exists in the process only inside the encrypt/decrypt call and
  the grant's outbound presentation; never logged, never delivered. Raise
  `gateway_form_max_body_bytes` 8192 → 16384 (the refresh request carries the
  grown refresh token in its form body; the raise is re-priced in the SIA, and
  the shared cap means `/dial/revoke`'s read bound rises with it — stated in
  `.env.example` and `docs/gateway-configuration.md`, not slipped in). The two
  bounds are coupled and must move together — the refresh body must stay under
  the cap for every size the bound admits (cap ≥ bound + envelope expansion +
  JWT overhead); raising `gateway_custody_provider_token_max_bytes` past the
  cap's headroom makes sign-ins succeed and every refresh fail over-cap, the
  exact far-from-its-cause failure the loud sign-in refusal exists to prevent,
  recreated by configuration. Verify:
  lifecycle rows for pending-entry create/consume/drop-on-non-redemption;
  keyset startup rows (an empty keyset, a multi-active keyset, and a
  wrong-length key — 16 and 24 bytes — each refusing at startup);
  envelope round-trip rows (encrypt→decrypt; tampered tag refuses;
  wrong-key refuses; unknown version/key-id refuses; expired envelope refuses;
  `sub`-swapped blob between two users' tokens refuses; nonce uniqueness across
  many encryptions); a row decoding an issued authorization code's
  payload and asserting it carries no identity-provider credential of any kind,
  plaintext or ciphertext; a row asserting the custody claim appears in the
  refresh token and in no other issued artifact (not the access token); rows
  proving no client response or log record carries the plaintext and no log
  record carries the ciphertext; a
  restart-semantics row (pending entries empty after restart; a pre-restart
  refresh token still refreshes — the claim returned with it; minted tokens
  still verify); and a hard-cut rotation row (a blob under a superseded key
  refuses with the custody reason).
- [x] 2.3 Rewrite the refresh grant in `gateway/token.py` / `gateway/tokens.py`
  to the new mechanism, and drop the claim snapshot from the refresh token:
  `mint_refresh_token` carries only the session bindings (`sub`, `aud`,
  `typ`, `jti`, `iat`, `exp`, `client_id`, `resource`) plus the encrypted
  custody claim — the gateway refresh
  token carries no claim snapshot at all, so the frozen-snapshot fallback has no
  data to serve (design.md D4 makes the prohibition structural; the custody
  claim is ciphertext, never a mint input). The refresh mint's `aud` is pinned
  to `[resource]` alone — the audience marker MUST NOT be included (the access
  mint carries it, `gateway/tokens.py:202`; the refresh mint does not,
  `gateway/tokens.py:232`): the marker is what makes a gateway-issued token a
  Core-acceptable access token, so its absence is the token-type separation —
  the refresh token is never a token Core's identity-provider entry accepts,
  and with no copied claims aboard it authorizes nothing at Core's role-path
  matching even absent the marker check (design.md D4; the delta spec's
  issued-tokens requirement carries the pin normatively). In the grant,
  after the existing validation ladder (signature, type, denylist, resource,
  client), decrypt the custody claim through task 2.2's seam checks — absent
  (a token minted before this change), tampered, unknown version/key-id,
  expired, or `sub`-mismatched refuses `invalid_grant` on the custody class —
  and
  run the provider refresh grant (task 2.1). Verify the fresh token through
  `_verified_claims`, require its `sub` to equal the gateway refresh token's
  `sub`, run the copy/overlay (`copied_claims` + the roles overlay) on the fresh
  claims, mint the new access token from them, and rotate the gateway refresh
  token as today (original absolute expiry, grace window), re-encrypting the
  provider's **latest** refresh token (latest-wins from the grant response,
  task 2.1) into the replacement's custody claim. Every failure refuses `invalid_grant`
  with no fallback; the three refusal classes audit with distinct fixed-vocabulary
  tokens through the same closed-table extension task 1.2 specifies (the
  `invalid_grant` refusal class gains three named subclass tokens):
  `custody_decrypt_failed` (the claim absent, tampered, under an unknown
  key-id or version, expired, or `sub`-mismatched — the gateway's own custody
  fault, never a provider event), `claims_read_failed` (unreachable, unusable answer, subject mismatch, roles
  path absent, and any provider 4xx other than `invalid_grant`
  — a misconfigured client secret's `invalid_client` burst lands here, not on the
  session-ended token) and `idp_session_ended` (the provider refused the grant
  with `invalid_grant` — RFC 6749 §6's session-gone code) — so a custody fault,
  a provider
  outage, a session-policy break, and mass local
  revocation are four distinguishable bursts on the trail (the detective
  control DT-EP1-4/6/8 cat. 8 and DT-EP4-1 cat. 8 price). The code grant keeps its
  claim snapshot (the code's own short TTL is its freshness bound, as today).
  Verify: rows for the sub mismatch, the roles path absent from the fresh token,
  each provider refusal class, each custody refusal class (absent, tampered,
  wrong key, unknown version, expired envelope, `sub`-swapped), a negative control
  asserting the refresh grant has no code path that mints without a completed
  read (and that the refresh token payload carries no copied claims — the
  custody claim is its only non-binding member), rows pinning the mint pair in
  `tests/test_tokens.py` — the minted refresh token's `aud` is exactly
  `[resource]` with no marker while the access token's `aud` carries it — and a
  negative-control row presenting a minted refresh token through the same
  validation shape Core applies (signature, issuer, audience-marker check) and
  asserting the audience refusal, and audit
  rows asserting each refusal class lands on its committed token from the closed
  table, that the four `invalid_grant` bursts are mutually distinguishable, and
  that a non-`invalid_grant` provider 4xx (`invalid_client`) audits as
  `claims_read_failed`, never `idp_session_ended`, and never
  `custody_decrypt_failed`.
- [x] 2.4 Re-derive the startup validator and rename its setting
  (`gateway/settings.py`, `.env.example`, `docker-compose.yml`,
  `docs/gateway-configuration.md`, `README.md`):
  `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` is replaced by
  `IDP_SSO_SESSION_MAX_SECONDS` — the operator's declared bound on how long the
  identity provider keeps its session-bound refresh token usable (on Keycloak,
  the realm's SSO Session Max; on Entra, the public-client refresh-token bound).
  The check keeps its mechanics (`gateway_refresh_ttl_seconds` MUST NOT exceed
  it, refusal naming both values) and gains an honestly re-derived docstring,
  refusal message, and `.env.example` comment: the value is an **operator
  assertion about the provider's session policy** (a green check is arithmetic,
  not provider truth), the failure it cannot catch is named (a session policy
  shorter than declared — its runtime shape is the `idp_session_ended` burst),
  and the guidance is carried: where the provider's session policy is short, the
  short window is the correct configuration, not a degraded one. The old
  staleness rationale ("the gateway never staler than the deployment's vanilla
  bound") and the old setting name are removed — a validator whose meaning no
  longer matches its name is worse than none (design.md D6). The rename
  propagates into the operator-facing reference, whose rows carry both the old
  name and the superseded staleness rationale: `docs/gateway-configuration.md`
  (the missing-setting refusal row, the refresh-window refusal row, the settings
  table, and the refresh/rotation prose) and `README.md`'s required-settings
  sentences. Both get the same re-derived operator-facing text discipline
  `.env.example` gets — the new name and its operator-assertion semantics, the
  local-realm guidance for where the SSO Session Max value comes from, and the
  retired staleness rationale removed — so an operator upgrading by the doc is
  never told to set a variable that no longer exists while the required new one
  is unnamed. The same operator-material pass carries the custody-era settings
  and procedures the change adds, in the same files: `gateway_custody_keys`
  (how to generate a 32-byte key, the key-id → key mapping's shape, and that a
  rotation is a **hard cut that logs out every live refresh session** — the
  re-sign-in wave bounded by the refresh token's non-sliding absolute expiry,
  the cost the operator schedules the rotation around), `gateway_custody_
  provider_token_max_bytes` (its coupling to `gateway_form_max_body_bytes`:
  the two bounds must move together — raising the bound past the cap's
  headroom makes sign-ins succeed and every refresh fail over-cap), and the
  rotation-off warning (design.md D3/A8): with `GATEWAY_ROTATE_REFRESH_TOKENS=
  false` on a provider that rotates its refresh token per grant, the carried
  credential is effectively single-use — the first refresh consumes it and
  every refresh after fails at the provider (`idp_session_ended`) — so the
  setting is valid only on providers that do not rotate per grant. Verify: the
  existing startup-refusal test row is updated to the renamed setting and the
  re-derived message — the row exists to pin the operator-facing text, not to
  freeze the superseded one; the refusal condition and the named values are
  unchanged in mechanics; and the operator reference carries the custody-key
  generation/mapping/rotation-wave rows, the size-bound-to-body-cap coupling
  row, and the rotation-off warning row.
- [x] 2.5 Extend `scripts/provision_keycloak.py` with the driven checks the
  mechanism's provider facts need (idempotent, driven against the live realm):
  (a) the gateway client's code exchange issues a session-bound refresh token
  (and the requested scopes never include `offline_access` — the M13 line holds,
  now as the amended D5 ruling); (b) the refresh grant against that token
  returns a fresh verifiable token carrying the roles path and the per-user
  attribution claims, through the same verification the flow performs; (c) a
  second refresh using a superseded (rotated-out) provider refresh token is
  refused — the provider's rotation reuse detection, which the provisioning
  **enables** by setting `revokeRefreshToken=true` on the realm it owns (the
  live run found Keycloak's image default is off; the setting is the
  theft-containment control for this dev shape's plain-http internal leg,
  defense-in-depth where TLS'd legs are the production bound), so the reuse arm
  is driven against a realm that actually revokes the chain — and the session's
  refresh token dies when the session is revoked, driven on its **own** fresh
  session so the reuse check's chain revocation cannot make it pass
  incidentally: the revocation-propagation fact the acceptance depends on,
  verified rather than assumed; (d) the realm's actual SSO Session Idle/Max
  values are read through the Admin API and checked against the configured
  `GATEWAY_REFRESH_TTL_SECONDS` — the machine-checked version of the operator
  assertion task 2.4 states — with a refusal or warning naming all three values
  when the window does not fit; (e) a refresh on a normal cadence survives past
  the realm's SSO Session Idle — the machine-checked version of the
  idle-refresh-on-use fact the local 8 h window rests on (design.md D1
  dependency 3: under a normal refresh cadence the operative cap is SSO Session
  Max, not Idle). The realm's own Idle (86400s, equal to Max) can be neither
  waited out nor, at Idle == Max, made to distinguish renewal from the Max cap,
  so the check **temporarily lowers Idle to a short value, drives the cadence,
  and restores the original in a finally-path** (the mutation and its restore
  logged; a failed restore reported loudly) — a realm whose idle timer is not
  refreshed by grant use would kill every session at the idle bound and make the
  window a fiction, so the fact is verified, not inferred.
  Verify: the driven checks run green against the
  composed stack; the negative control (a realm session policy shorter than the
  window) shows the loud `idp_session_ended` refusal shape at refresh.
- [x] 2.6 Correct the refresh resource-mismatch error code via this change's
  replacement requirement: the main spec's "Resource mismatch on refresh"
  scenario expects `invalid_grant`
  (`openspec/specs/mcp-signin/spec.md`) while the code and its test answer
  `invalid_target` (`gateway/token.py:359-362`,
  `tests/test_tokens.py:447-457`), matching the code grant's resource-mismatch
  analogue (`gateway/token.py:289-291`). The REMOVED+ADDED rewrite of the
  refresh requirement is the reconciliation vehicle: the ADDED requirement's
  scenario already carries the corrected `invalid_target` text, and the
  migration note records the amendment. No code change — the code is the
  verified behavior. Verify: after the spec sync, the main spec's scenario
  reads `invalid_target`; a conformance row asserts the code's answer.

## 3. Acceptance — live runs (the two outcomes, on the composed stack)

- [x] 3.1 P2 live run: with a harness signed in and refreshing, change the test
  user's roles in the identity provider mid-session and refresh — the minted
  access token carries the changed roles within the access TTL. Then revoke the
  user's identity-provider session and refresh — the provider refuses the grant,
  the refresh is refused (`invalid_grant`, fail closed, audited
  `idp_session_ended`), and the re-run sign-in re-establishes. Then, with the
  gateway restarted mid-session, refresh — **the refresh succeeds** (the
  encrypted custody claim returned with the presented refresh token — v3's
  restart gain), while an unredeemed authorization code issued before the
  restart fails its grant fail closed (its pending entry is gone).
  Capture the evidence (the before/after decoded tokens, the audit trail's
  records) in `evidence/`. **Ran live 2026-11-01 — evidence `evidence/live-runs.md`
  §B (the three arms); the pre-restart-code arm was re-driven live against the
  fixed image, §G.**
- [x] 3.2 P3 live run: with no `TOOLSETS` configured, add a new platform OAUTH
  toolset to Core (ops API) and complete a full harness sign-in for it with no
  gateway reconfigure and no restart — the flow's settings read picks it up
  (discovery's document was always name-derived and needed no refresh). Then
  the refusal set, each with its specified shape and audited reason: an
  unknown name — its discovery document is served (the mirror property), and
  the flow's settings read refuses it with the plain-language page, the
  system's only existence refusal; a non-OAuth toolset with a stored
  GLOBAL-level credential — a full consentless sign-in through the
  short-circuit; the same toolset with the credential removed — the
  impossible-branch refusal page naming the cause, and the loop ending
  out-of-band when the credential is stored again; and, with Core stopped, a
  discovery fetch — the document is still served (discovery depends on nothing
  but the gateway), while the flow's settings read fails closed as today —
  the availability split the mirror property buys, re-verified once Core
  returns. Capture the evidence (the audit trail's records per refusal class,
  the decoded tokens for the short-circuit) in `evidence/`. **Ran live
  2026-11-01 — evidence `evidence/live-runs.md` §C.**
- [x] 3.3 The harness token-store round-trip gate (design.md D3/A5 — an
  implementation gate on the adoption, not a follow-up): with the grown
  refresh token (carrying the encrypted custody claim), complete a real
  sign-in → refresh cycle in **both** field-proven harnesses — Claude Code
  (CIMD) and Cursor (DCR) — then restart the gateway and refresh again in
  each, proving the stored, grown token survives the harness's token store
  across a full cycle. Any store with a hard item-size limit the configured
  bound cannot dodge is a named deployment prerequisite surfaced at sign-in
  (the size-bound refusal), and a hard limit that no bound can dodge is the
  one finding that legitimately forces the custody shape back to the owner —
  which is why this is a gate. Capture the evidence (the harness, the decoded
  refresh token's size, the completed cycles) in `evidence/`. **PASS, owner-driven
  2026-11-02: both harnesses completed sign-in → refresh → gateway restart →
  refresh with the grown token intact; no store refused it, so the custody shape
  stands — evidence `evidence/live-runs.md` §H.**

## 4. Threat-model updates (part of this change, per the standing rule)

- [x] 4.1 Apply the design's §7 threat-model delta to `docs/threat-model.md`:
  rewrite T1-16's disposition and RES-6's record (the bound shrinks to the
  access TTL), restate invariant 4's bound, re-price T4-2/RES-2 (the custody
  rule, v3: the process's persistent secrets are the signing key **and the
  dedicated custody key**; the provider credential's plaintext exists only
  transiently during each refresh grant — no per-session store; the
  never-store wording gains the encrypted custody claim as a named, bounded
  exception), re-derive T5-1/RES-3 (the token-use rule's purposes — the
  identity access token's unchanged flow purposes; the provider session
  refresh token's plaintext presented once per gateway refresh at the
  provider's token endpoint, its ciphertext delivered once per rotation
  inside the refresh token to its presenting client), extend RES-19/T5-2 to
  the refresh-grant leg with the forged-claims gain stated
  (any-claims-for-an-existing-`sub`) and the sniffing gain named (the
  decrypted provider session refresh token presented on the leg), record
  T1-15's widened enumerable set, re-price RES-10
  (the OAUTH-only enforcement is no longer startup-with-no-escape: startup keeps
  it for configured restriction entries, the flow's settings read carries it
  for dynamic names), narrow RES-15's restart loss semantics to a gain
  (refresh capability **survives** restarts — the encrypted custody claim
  returns with the presented token; what is still lost is the pending
  hand-off entries, the replay cache, and the denylist; the stolen-token-
  survives-restart regression is recorded with the gain), amend T6-2's
  control 4 (the request-time guard does the dynamic-name
  work the startup check no longer covers), record T1-7's widened cost (each
  refresh spends one outbound identity-provider call plus one constant-time
  AES-GCM decryption of the custody claim — the latter microsecond-scale and
  priced for completeness), add the two new residual
  register entries — RES-20 (the accepted availability-for-fidelity trade of
  the mandatory claims read) and **RES-21 (the mintable-custody residual of
  the D5 amendment, re-shaped in four parts for the encrypted chain: the
  at-rest ciphertext in harness token stores, the time-decoupled
  recorded-token-plus-custody-key-leak conjunction, the
  stolen-token-survives-restart regression, and the unchanged
  process-compromise floor — with the bounding controls: session-bound
  no-offline grant (the SSO Session Idle/Max pair as the session clock), the
  provider's rotation reuse detection **where enabled** (the containment
  control for the credential-on-the-wire exposure of plain-internal-leg
  deployments — the local dev shape's provisioning sets it; deployments with
  TLS'd internal legs, the production shape, are bounded by the transport and
  the detection is defense-in-depth there — the owner's layering, 2026-11-01),
  IdP-revocation kill, the hard-cut
  custody key, plaintext-never-logged-or-delivered, what it does NOT grant
  (per-user and session-bound, not scope) — and the re-open trigger)**,
  amend M13 per D5 (never `offline_access`; the session-bound refresh token
  carried encrypted inside the gateway's own refresh token instead of
  discarded, the plaintext never leaving the process — deliberate, the trade
  priced as RES-21), amend M9 (the refresh token carries no claim snapshot —
  its one non-binding member is the encrypted custody claim; the refresh
  mint's claim input is the verified fresh read) and M10 (the startup-bounds
  row: the restriction-entry refusal, the moved halves, the re-derived
  session-bound refresh window), add the revocation-summary table to the model
  (carried from `background/design.md` §6.3) with the re-priced row —
  identity-provider session revocation now propagates to the gateway's refresh
  capability at the next refresh attempt (`idp_session_ended`), with minted
  access tokens bounded by the access TTL — add the new grouped-mitigation row
  (the refresh-grant re-read, the snapshot-free fail-closed refresh, and the
  custody envelope with its carrier discipline and pinned crypto,
  spec-placed), re-price the compromise table's
  gateway-process row (the custody key — which with a recorded-token archive
  replays each archived user's IdP identity until that session dies, and alone
  mints nothing — plus the transient plaintext of only the presenting
  sessions and the minutes-bounded pending entries; no whole-store harvest) and its internal-compose-network row
  (the sniffing gain gains the decrypted provider session refresh token read
  off the refresh-grant leg — the most powerful credential the flow ever puts
  on the wire),
  amend RES-4's bounding text (the refresh grant joins the attacker-steered
  slow legs — one outbound call per refresh holding a worker-thread slot for
  the outbound timeout; the "one attacker-steered slow leg" wording no longer
  names the whole set), amend RES-16's bounding text (startup reserved-name
  enforcement covers configured restriction entries; the request-time guard
  does the dynamic-name work), update §1's system-as-it-stands paragraph (the
  refresh tokens' role-snapshot semantics sentence — the snapshot is deleted,
  claims are re-read fresh at every refresh, and the token carries the
  encrypted custody claim; the startup-check sentence —
  renamed onto `IDP_SSO_SESSION_MAX_SECONDS` as an operator assertion about
  session policy; the state inventory — the minutes-bounded pending custody
  entries join the in-memory state, the process's persistent secrets are the
  signing key and the custody key, and no long-lived per-session store
  exists), add two rows to §4's asset inventory (the dedicated custody key —
  high/high/low, process memory, the `.env` slot, KMS at C3, the signing
  key's custody class; and the encrypted custody claim at rest in harness
  token stores — inert without the key, dying with the provider session),
  resolve OQ-1 into
  the resolved record
  with its source (`gateway/status.py:111-122`) and date, land the change's
  own new threats as model rows with their §13 dispositions — **T1-17** (EP1,
  E4 refresh: refresh cadence keeps the IdP session alive, [mis-use] —
  accepted, RES-22), **T1-18** (EP1, E4 refresh: crafted custody blob —
  mitigated by the new grouped-mitigation row), **T1-19** (EP1, the issued
  refresh token at rest in the harness's token store: grown token overflows a
  harness token store — mitigated to its bound, the ungated stores accepted as
  RES-23), and **T4-8** (EP4, process memory: custody-key compromise and
  transient plaintext — mitigated to its bound, the time-decoupled conjunction
  and process-compromise floor accepted as RES-21 parts ii/iv, the
  managed-runtime memory floor as RES-2) — add the two register entries those
  dispositions cite (**RES-22**: the SSO-session keepalive, three-part record,
  OQ-G's ruling cross-referenced — accepted as priced, 2026-11-01, design.md
  §8; **RES-23**: the ungated harness token stores,
  three-part record, the task 3.3 gate finding as its re-open trigger), amend
  the three descriptive locations whose enumerations the custody key
  falsifies (§5's TB4 — its memory list gains the custody key, the transient
  provider-refresh-token plaintext, and the minutes-bounded pending entries;
  §2's sensitive-asset sentence — gains the custody key; §7's EP4 description
  — gains the custody key and the custody seam), and refresh the at-a-glance
  counts (the register gains RES-20 through RES-23 — 23 residual records; the
  threat tables gain four rows — 59 threats, EP1 19 and EP4 8; the asset
  inventory gains the custody-key and at-rest-ciphertext rows — 17 assets; the
  grouped mitigation list gains the new row — 21 grouped mitigations; the
  revocation-summary table is new). **The flow-era (second P3 re-taking, as
  corrected by the owner's final ruling) additions, in the same edit pass**
  (design.md §7's flow-era bullets are the
  authoritative wording; the consult era's own additions — T1-20, T5-8, T4-9,
  RES-24, the Core-service-API-key asset row, M22, the service-key extensions
  to the descriptive locations and the compromise table — are deleted with the
  consult and land nowhere): re-shape **RES-10** a second time (the non-OAUTH
  exclusion as a class is gone — the startup OAuth-declaration refusal deleted
  with the mapping's `authentication_type` member; a non-OAuth toolset is
  served through the short-circuit when Core holds a credential; the residual
  that remains is the impossible-branch refusal loop, benign and ended
  out-of-band); amend **M10** again (the OAUTH-only mapping refusal removed,
  not re-scoped; the restriction-entry refusals that remain are reserved-name
  and charset; the flow's kind branch named as the moved half); amend
  **T1-15** with the mirror-property bound (the widened enumerable set is
  every guard-passing name — the same registry-independent shape Core's own
  unauthenticated discovery tier serves; no existence oracle exists below
  authentication); amend **T5-3's model row** with the existence edge (the
  per-user settings read is now the system's only existence decision — a
  forged not-found there is the merged consult threat's denial shape, same
  leg, same trust, same disposition); amend **§11's invariant-3 row** with the
  use-vs-establish distinction —
  re-derived against the row's actual text, which carries no level wording
  today ("Credentials are stamped and resolved per `sub` unchanged…"), so the
  GLOBAL-use sentence is added, not a level sentence re-worded (the flow never
  establishes at GLOBAL level; it uses an operator-stored one,
  and the access is the same through Core's own paths); re-shape **RES-9** and
  amend **T5-4's §8 row, §9 control 4, and §13 disposition** with the same
  distinction (the falsified "the flow signs in at USER level only; GLOBAL
  stays an operator action" wording's actual homes — what stays an operator
  action is GLOBAL-level *establishment*; GLOBAL-level *use* through the
  short-circuit is the stated delegation, priced as DT-EP1-12, and T5-4's
  "preserved by absence" disposition is re-derived to preserved by the
  establishment-side refusal with the delegation stated); amend **T1-4's §8
  row and §13 disposition** with OQ-1's resolution (E9 enforces the resource
  binding, `gateway/status.py:111-122` — the open-question and "stays open"
  wordings are replaced in the same edit that resolves OQ-1 in §14, so the
  model never carries OQ-1 as resolved while T1-4 stays blocked on it); amend
  **T6-7's §8 row and §9 controls 6 and 7** with the startup/guard split
  (startup charset enforcement covers configured restriction entries; the
  request-time guard covers dynamic names — the same split as T6-2's control
  4 and RES-16, with control 7's "checked once at startup" N/A reasoning
  re-derived for the guard's request-time volume); and amend **§6 attacker
  2's** "walking statuses across the mapping (T1-15)" to the dynamic-mode
  enumerable set (the platform bucket of guard-passing names the mirror
  property serves); land the three new
  threat rows with their §13 dispositions — **T1-21** (EP1, the short-circuit's
  mint-without-consent surface for non-OAUTH kinds; mitigated — the stage
  order, the per-user DIAL authorization check, use-vs-establish, no
  credential read or transit), **T1-22** (EP1, [mis-use], the global-credential
  delegation; accepted as design, the delegation stated), and **T5-7** (EP5,
  the forged signed-in answer; mitigated to the internal-leg bound — RES-19's
  class extended, no new residual); add §7's **EP1 description** (the
  guard-decided dynamic discovery tier, registry-independent by the mirror
  property, and the flow's short-circuit) and re-derive its **EP5 description**
  (the flow's kind-and-signed-in decisions on the per-user read — no discovery
  leg exists to describe); amend §1's anchor paragraph's
  P3 sentences (the served set follows the request-time guard and the optional
  restriction — discovery mirrors Core's registry-independent unauthenticated
  tier, existence decided post-authentication at the flow's settings read; the
  kind check is the upstream stage's branch; the state inventory's persistent
  secrets are the signing key and the custody key); add the grouped-mitigation
  row **M23** (the flow's routing decision — G2); and land the final
  at-a-glance counts, counted from the actual delta (the
  register gains RES-20 through RES-23 — 23 residual records; the threat
  tables gain seven rows — 62 threats, EP1 21, EP4 8, EP5 7; the asset
  inventory gains two rows — 17 assets; the grouped mitigation list gains
  M21 and M23 — 22 grouped mitigations; the revocation-summary table is new).
  Verify: each edited entry cites its
  delta-spec requirement; the explicit edit list above governs — the entries and
  sections it names are exactly what changes: T1-16, RES-6, invariant 4's row,
  T4-2/RES-2, T5-1/RES-3, RES-19/T5-2, T1-15, RES-10, RES-15, RES-4, RES-16,
  T6-2, T1-7, OQ-1 (resolved), M13 (amended per D5), M9, M10, §1's
  system-as-it-stands paragraph, §4's asset inventory, the compromise table's
  gateway-process and internal-compose-network rows, the new threat rows
  T1-17, T1-18, T1-19, and T4-8 with their §13 dispositions, the new register
  entries RES-22 and RES-23, §5's TB4, §2's sensitive-asset sentence, §7's
  EP4 description, and the new RES-20, RES-21 (its bounding list re-worded to
  the owner's reuse-detection layering — the detection where enabled is the
  plain-internal-leg deployments' containment control; TLS'd legs, the
  production shape, are transport-bounded and the detection is defense-in-depth
  there; 2026-11-01), and revocation-summary table
  — **plus the flow-era set**: §11's invariant-3 row, RES-9 re-shaped, T5-4's
  §8 row, §9 control 4, and §13 disposition, T1-4's §8 row and §13
  disposition, T6-7's §8 row and §9 controls 6 and 7, T5-3's row (the
  existence edge), §6's attacker-2
  enumeration, the new threat rows
  T1-21, T1-22, and T5-7 with their §13 dispositions, §7's EP1
  and EP5 descriptions, and the new grouped-mitigation row M23 —
  **plus the token-type-separation pin** (the owner's ruling after the four
  review rounds, 2026-10-31): **T1-4's §9 control 5**, whose "the
  `aud = [resource, marker]` the gateway mints (spec)" wording is amended to
  name the access token's mint as the one it describes, with the refresh
  token's `aud` stated as the resource alone — the marker never included, the
  pin that keeps the refresh token from ever being a token Core's
  identity-provider entry accepts (the delta spec's issued-tokens requirement
  carries the pin normatively; design.md §7's T1-4 bullet is the authoritative
  wording). Any other model location whose current text this
  change falsifies is a defect in this list, not a protected fact: it is added
  to the list (through this change's artifacts) and edited, never left stale.

## 5. Gates

- [x] 5.1 Static gates green on the diff: `ruff check`, `ruff format --check`,
  `mypy`, `bandit`, `pip-audit` (blocking), Trivy (`--skip-db-update` if the DB
  is stale). Capture outputs in `evidence/`. **Green; outputs in
  `evidence/gates.md`.**
- [x] 5.2 The compose-boot gate: `docker compose up` with a health probe for
  every service. **Green — `evidence/gates.md`.**
- [x] 5.3 The change's conformance rows green: every new and amended scenario in
  the delta spec exercised (the guard at each site; the discovery outcomes —
  a guard-passing name served its document with no Core call (a name Core
  does not know included — the mirror property), the restriction-excluded and
  guard-failing 404s; the signed-in short-circuit at user and
  global level including the non-OAUTH-kind delegation row; the
  impossible-branch refusal and the fail-closed status shapes at the flow; the
  unknown-name refusal at the flow's settings read — the system's only
  existence refusal; the no-refresh-token and
  over-size sign-in refusals, the
  refresh-grant claims re-read and its failure classes including the
  session-ended refusal, the subject mismatch, and the custody-claim refusal,
  the snapshot-free refresh token, the refresh-token-not-Core-acceptable
  separation row (the no-marker `aud` on the refresh mint and its negative
  control), the custody envelope's round-trip and
  refusal rows (tamper, wrong key, unknown version, expired envelope,
  `sub`-swap) with its hand-off seam, carrier discipline, latest-wins
  re-encryption, and hard-cut rotation, the restart-survives-custody row, the
  no-offline-grant negative, the restriction modes), plus the retained rows
  unchanged except the three amendments the migration note declares (silent
  refresh; the resource-mismatch error-code correction, which asserts the
  code's verified `invalid_target`; the refresh-TTL bound's re-derivation onto
  the renamed session-bound setting) — and the harness token-store round-trip
  gate of task 3.3 green in both field harnesses before the change is done.
  **68/68 conformance rows green; evidence `evidence/gates.md`.** The task-3.3
  clause above is now **green** too — the gate PASSED owner-driven 2026-11-02
  (`evidence/live-runs.md` §H), both harnesses round-tripping the grown token.
- [x] 5.4 The security review gate on the diff — an independent reviewer
  subagent against this change's SIA and the updated threat model, at the depth
  the SIA's medium impact level sets, with falsifying any no-impact claim in
  scope. Findings addressed before the general review. **Ran;
  `evidence/security-review-gate.md`.**
- [x] 5.5 The independent review gate on the diff. **Ran — PASS AFTER FIXES;
  `evidence/general-review-gate.md`.**
- [ ] 5.6 Commit locally after all gates pass; push only then. No force-push.
  **All gates green; the commit follows (the orchestrator commits after this pass).**
- [x] 5.7 Correct `gateway/tokens.py`'s module docstring — the flagged
  Core-logging overstatement's task home (design.md §8; flagged by the round-3
  review, assigned by the owner's ruling): the logging half is restated to the
  verified wording (Core
  hashes one key claim by default — `loggingKey`/`loggingSalt` with
  obfuscation on; claim values reach logs only via the operator's opt-in
  `analytics.claimsAllowlist` or the DEBUG-level login line), and the
  authorization-paths half ("matches authorization rules on arbitrary claim
  paths") stands unchanged. The correction is assigned: this change's diff
  (ruling, 2026-11-01) — the implementation pass lands it, not a separate
  repo-docs change; the task slot exists so the flag cannot fall silent.
  Verify: the docstring carries the verified wording, and no live repo
  location carries the overstated phrasing.
- [x] 5.8 The mechanical completeness sweep of `docs/threat-model.md` before this
  change's completion — the gate the edit list earned the hard way (the
  dominant defect of three consecutive review rounds was "the edit list misses
  locations": R2-M1, R3-M1, R4-M1, R4-M2): a grep sweep of the model for every
  phrase-class this change invalidates, run against `docs/threat-model.md` as
  it stands after task 4.1's edit pass. The phrase-classes: the pre-v3 store
  wording (any long-lived per-session store, retention store, `jti`-keyed
  retention); the frozen/role claim snapshot and the snapshot-minted refresh
  token; the userinfo mechanism; startup-only enforcement of the mapping's
  checks (charset, reserved names, OAuth declaration "at startup on every
  mapping entry" where the request-time guard now shares the work, including
  T6-7's "checked once at startup"); OQ-1 carried as open anywhere (T1-4's row
  and disposition included) while §14 resolves it; "the flow signs in at USER
  level only" / GLOBAL-stays-an-operator-action wording without the
  use-vs-establish distinction (RES-9, T5-4's row, grid, and disposition
  included); the userinfo-era claim-source prerequisite; the unqualified
  `aud = [resource, marker]` mint wording (a statement of the gateway's mint
  shape that does not name the access token as its subject — T1-4's §9
  control 5 included, amended by the token-type-separation pin); the
  consult-era discovery vocabulary anywhere it might have landed in the model
  (a discovery consult, a Core service API key, a consult concurrency bound,
  a discovery-side 503 or phantom-refused-at-discovery wording — deleted with
  the consult before any model row was written, so any hit is a stale leak of
  the ruling-2 era); and the
  pre-change
  at-a-glance counts (55 threats, 19 residual records, 15 assets, 20 grouped
  mitigations), the intermediate custody-era counts (59 threats, 23
  residual records, 17 assets, 21 grouped mitigations), and the consult-era
  intermediate counts (65 threats, 24 residual records, 18 assets, 23 grouped
  mitigations). Each hit either
  matches an explicit §7/task-4.1 list entry (an intentionally retained or
  re-shaped statement) or is a defect in the list — added through this
  change's artifacts and edited, never left stale. The list stops being
  trusted on its own; this sweep is the gate. Verify: the sweep runs with
  zero stale hits — every hit in each phrase-class is either a location the
  list explicitly names as edited or a defect found and fixed before
  completion — and the result (the sweep's command list and its zero-stale
  -hits output) is captured in `evidence/`. **Green (zero stale hits); the
  command list and output are in `evidence/gates.md` §5.8.**

## 6. Release notes

- [x] 6.1 Finalize `release-notes-draft.md` in the two-audience format, matching
  what actually landed (user-visible: dynamic toolsets, fresher claims,
  identity-provider session revocation taking effect at the next refresh, the
  fail-closed refresh during provider outages, refresh surviving gateway
  restarts and rollouts, the optional `TOOLSETS`, consentless sign-in for
  toolsets whose credential is already stored (yours or your administrator's),
  unknown names answered at discovery exactly as Core answers them and refused
  at the sign-in flow's settings read, discovery independent of Core (no new
  deployment prerequisite, no service key, documents served through a Core
  outage);
  team:
  the mechanism re-taking and its owner ruling with the three verified
  objections, the custody re-taking and its owner ruling (v3, the encrypted
  claim; `evidence/custody-opinion-v3.md`), the refresh-grant mechanism and its
  three stated universality dependencies, the M13 amendment with the priced
  mintable-custody residual re-shaped in four parts (RES-21), the
  snapshot-free refresh token, the token-type-separation pin (the refresh
  token's no-marker audience, never Core-acceptable), the custody envelope with its carrier
  discipline, pinned crypto, dedicated key, hard-cut rotation, size bound,
  raised cap, and both-harness round-trip gate, the re-derived
  session-bound validator and the renamed setting, the SSO-keepalive
  consequence, the revocation-summary re-priced row, the P3 owner rulings
  with the final correction and the pushback trail (the GLOBAL use-vs-establish
  delegation stated; the consult era's pricing and its deletion — no DIAL API
  key ever involved, the mirror property, the Core-side ask), and the
  threat-model updates). **Draft complete and reconciled to what landed (the
  stale reuse-detection bound re-worded to the ruled layering); finalization
  accompanies the commit after task 3.3.**
