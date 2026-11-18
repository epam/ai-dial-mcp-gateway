# Release notes — dynamic-toolsets-and-fresh-claims (draft)

### For users

- **A toolset added to DIAL Core is sign-in-able immediately — no gateway
  reconfiguration, no restart.** Every platform toolset Core holds is served —
  a new one works at its next sign-in, with nothing to reconfigure; the
  `TOOLSETS` setting is still there for deployments that
  want to pin the served set, and a pinned deployment keeps its routing
  validation (pinned entries no longer declare an authentication kind — an old
  mapping carrying the removed member is refused loudly at startup with the
  field named). A name that does not exist in Core is answered at discovery
  exactly as Core itself answers it — a document, because no unauthenticated
  surface on either side of the front door knows existence — and the sign-in
  flow's settings read refuses it with a plain-language page saying the toolset
  is not registered in DIAL Core: one round-trip later, with nothing upstream
  started.
- **If your toolset's credential is already stored in DIAL, sign-in is now
  consentless.** When Core already holds a credential for the toolset — one you
  stored earlier, or one your administrator configured for everyone — the
  sign-in completes with no approval screen, whatever kind of credential the
  toolset uses. A toolset whose credential is configured directly in DIAL and
  has none stored refuses with a page saying exactly that: no consent flow can
  establish it, and your administrator is the one who can.
- **Role changes take effect within minutes, not hours.** A role granted or
  revoked at your identity provider now reaches your gateway-issued tokens at
  the next refresh — within the access token's lifetime — instead of living on
  for the whole refresh window. **Signing out of your identity provider (or an
  administrator revoking your session) now ends the gateway's refresh ability at
  your next refresh too**: the next refresh is refused and you re-run the sign-in
  from your tool; your existing access tokens keep working until they expire.
  If your identity provider is unreachable when a refresh is due, the refresh is
  likewise refused and you re-run the sign-in once the provider is back. No
  stale token is ever silently issued.
- **Your refresh session now survives gateway restarts and upgrades.** The
  credential the gateway needs to re-read your claims travels inside your own
  refresh token, encrypted under a gateway-only key — so a gateway restart (or
  a deployment rollout) no longer ends your refresh session; the next refresh
  just works. Your refresh token is larger than before; it has been verified
  live against the token stores of both field-proven harnesses (Claude Code
  and Cursor).
- **No new deployment-side requirement for discovery, and one less dependency
  than the earlier draft promised.** The gateway holds no standing credential in
  Core of its own — its only Core credentials are the signed-in user's own
  per-flow token — and discovery makes no Core call at all: no service API key
  to issue, and documents keep being served through a Core outage (the
  Core-down failure shapes live where they already did — the sign-in flow's
  settings read and the data path). A phantom name's discovery document costs
  the gateway one static document, exactly what the same probe against Core's
  own discovery tier costs Core.
- **One deployment-side note** for whoever administers the identity provider:
  the provider must issue refresh tokens to the gateway's sign-in client (the
  default on Keycloak and Entra — a provider that does not fails loudly at
  sign-in, not silently later), and the provider's session policy must keep
  refresh tokens usable for as long as your refresh window. Where that policy is
  short (Keycloak's SSO Session Max defaults to 10 hours; Entra's public-client
  refresh tokens live about 24 hours), set the gateway's refresh window to
  match — a short window is the correct configuration there, not a degraded
  one. The `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` setting is replaced by
  `IDP_SSO_SESSION_MAX_SECONDS`, which declares that bound.
- **No action needed otherwise.** Existing pinned mappings keep their routing
  validation (remove the `authentication_type` member from their entries — the
  one breaking change in the mapping's shape); existing tokens keep validating. One transitional note: refresh
  sessions live at the moment of upgrading end at their next refresh (the
  refresh token's shape changed) — those users simply re-run the sign-in once.

### For the team

- **P2's mechanism is the identity provider's refresh grant, re-taken on the
  owner's ruling.** The first design (a userinfo re-read backed by a retained
  identity access token) was overruled on three objections an independent
  evaluation verified: userinfo is RECOMMENDED, not guaranteed; its claim set is
  provider-filtered (fixed on Entra, custom-policy-only on B2C); and the
  retained access token dies on the provider's clock far inside the refresh
  window (5 minutes on a default Keycloak). The adopted mechanism: at every
  refresh the gateway presents the provider's own session-bound refresh token
  at the provider's token endpoint (RFC 6749 §6) and mints from the verified
  token the grant returns — the token endpoint is the OIDC Discovery REQUIRED
  member, the grant is core OAuth, and the credential is issued for exactly
  this purpose.
- **Universality is restored, stated as dependencies, not as a slogan.** The
  mechanism is universal among providers that (1) issue refresh tokens to the
  gateway's public PKCE client at the code exchange — a provider that does not
  fails loudly at sign-in as a named deployment prerequisite; (2) return a
  token whose claims the flow can verify — the *same carrier and verification
  path the sign-in already uses*, so no new claim-source requirement appears
  (the userinfo claim-set prerequisite and its owner question are discharged);
  and (3) keep the session-bound refresh token usable across the window under
  the provider's session policy — Keycloak's SSO Session Max (refresh use
  refreshes the idle timer but not the Max), Entra's ~24 h public-client bound.
  Dependency (3) is an operator prerequisite asserted at startup and verified
  live for the local realm by the provisioning script.
- **One claim vocabulary, unchanged from today:** the token the code exchange
  returns is exactly the token the refresh grant reads, verified the same way,
  with the fresh token's `sub` required to equal the gateway refresh token's
  subject — no provider answer can mint for another user. The frozen-snapshot
  fallback is not merely forbidden but structurally impossible: the gateway's
  refresh token no longer carries a claim snapshot at all, so the verified
  fresh read is the mint's only claim input. One conformance pin landed with
  it (behavior the verified mint already has, now normative): the refresh
  token's audience stays the resource alone — the access token's audience
  marker is never included, so the refresh token is never a token Core's
  identity-provider entry accepts; pinned by a mint-pair test and a
  negative-control row presenting the refresh token through Core's validation
  shape.
- **Custody is re-taken a second time on the owner's ruling: the provider's
  session refresh token rides the gateway's own refresh token, encrypted (v3).**
  The prior taking (an in-memory, `jti`-keyed retention store) was twice
  reviewed clean and then overruled on an independent custody opinion
  (`evidence/custody-opinion-v3.md`): the store concentrates every live
  session's mintable credential in one memory read, makes every C3 pod rollout
  a mass re-sign-in, and defers the same crypto work to a later home with more
  surface around it. The adopted shape: an AES-256-GCM envelope
  (`version | key-id | nonce | ciphertext‖tag`, pinned in code constants)
  under a dedicated, key-id-versioned 256-bit custody key separated from the
  signing key — encrypted at the code grant, decrypted at every refresh,
  re-encrypted into each rotated refresh token (the provider's latest,
  latest-wins). The carrier is the refresh token only, never the access token
  (which rides every MCP call and is not even reliably presented at refresh) —
  a rule that stands on the refresh-grant facts alone; the claim that Core
  forwards the whole access-token payload to usage logs turned out false on
  verification against the Core source (Core hashes one key claim by default
  and writes claim values only via the operator's opt-in allowlist), so it is
  a supporting note, not a leg — and `gateway/tokens.py`'s docstring that
  overstates it is corrected by this change's implementation pass (tasks.md
  5.7; assigned to this change's diff by the owner's ruling, 2026-11-01). No long-lived per-session store exists; the minutes-bounded pending
  entry keyed by the code's id survives (never the code's payload, which is
  base64-readable by anyone holding the code string — and this token is
  mintable credential material). The custody key rotates by hard cut (a
  superseded key decrypts nothing; the drill joins C3's T3). A restart now
  loses nothing the harness does not bring back — refresh capability survives
  — with one recorded regression: stolen refresh tokens survive restarts too
  (bounded by the non-sliding expiry and the IdP session clock). Three size
  controls land with the envelope: a provider-token size bound refused loudly
  at sign-in, a raised and re-priced token-endpoint body cap, and a live
  round-trip of the grown token through both field harnesses' stores as an
  implementation gate. The identity access token itself is **not** retained
  past the flow.
- **The no-`offline_access` provisioning ruling is amended deliberately, with
  the trade priced on the record.** `offline_access` is still never requested —
  no offline (beyond-session) grant is ever acquired. What changes: the
  session-bound refresh token the code exchange already issues (and the flow
  discarded, unused) is carried, encrypted, inside the gateway's own refresh
  token instead. What the amendment buys:
  the gateway's refresh capability ends with the user's IdP session, and
  IdP-side session revocation propagates to the gateway at the next refresh —
  a strict improvement over both the snapshot design and the overruled design.
  What it costs — the carried material is **mintable** and rides the
  client-held token as ciphertext — is disclosed as its own re-shaped residual
  (RES-21, four parts: the at-rest ciphertext in harness stores, inert without
  the key; the time-decoupled recorded-token-plus-key-leak conjunction,
  bounded by the IdP session clock, with TLS on the internal legs as the
  production bound against the credential on the wire and the provider's
  rotation reuse detection recommended as defense-in-depth (set by this
  repository's local provisioning, never the provider's image default);
  the stolen-token-survives-restart regression; and the unchanged
  process-compromise floor — a compromise now yields the key plus only the
  presenting sessions, never a whole-store harvest) with the compromise tables
  re-priced; it grants no
  upstream credential and no other user's identity — the bound is per-user and
  session-bound, not scope (the minted token carries the user's role claims
  regardless of OAuth scope).
- **The refresh grant's fail-closed semantics are normative, with four
  distinguishable audit bursts.** Any read failure refuses with `invalid_grant`,
  audited `custody_decrypt_failed` (the claim absent, tampered, under an
  unknown key or version, expired, or bound to another subject — the
  gateway's own custody fault), `claims_read_failed` (unreachable, unusable answer, subject mismatch,
  roles path absent, or a provider 4xx other than
  `invalid_grant` — a misconfigured client secret reads as the misconfiguration
  it is, not as mass revocation), or `idp_session_ended` (the provider
  refused the grant with `invalid_grant` — the session is gone), so a custody
  fault, a provider
  outage, a
  session-policy break, and mass local revocation read differently on the
  trail. The refresh-grant cadence also refreshes the IdP session's idle timer
  — a harness's scheduled refreshes keep the user's SSO session alive up to the
  provider's SSO Session Max (disclosed as RES-22; accepted as priced by the
  owner's ruling, 2026-11-01 — design.md §8 OQ-G).
- **The startup refresh-TTL validator is re-derived, not deleted**, and its
  setting renamed: `IDP_SSO_SESSION_MAX_SECONDS` is the operator's declared
  bound on the IdP's session-bound refresh-token usability; the check keeps its
  arithmetic and loud refusal, and its message states honestly that it is an
  assertion about provider session policy — a green check is arithmetic, not
  provider truth, and the runtime break fails loud as the `idp_session_ended`
  burst. The local realm's real session values are checked live by the
  provisioning script.
- **P3 is re-taken on two owner rulings, with the second reversed by a final
  correction issued after empirical testing — the whole trail on the record.**
  Ruling 1 (stands): the kind check is no longer a precondition — the flow
  authenticates
  for any kind, checks Core for an already-stored credential (user OR global
  level) before any upstream leg, short-circuits the consent when one exists,
  and only a missing credential plus a non-OAuth kind refuses (the impossible
  branch: the credential is configured directly in DIAL; the loop ends
  out-of-band when an administrator stores it). The GLOBAL delegation is stated
  as use-vs-establish — the flow never establishes at GLOBAL level, it uses an
  operator-stored credential, and the access is the same the user already holds
  through Core's own paths. Ruling 2 (consult Core at discovery, refuse phantoms
  at the door) was issued, worked, and priced as a first-class threat set — and
  then reversed by the owner's final correction, because the empirical test
  settled the two facts it turned on: Core's MCP path answers an unauthenticated
  call, **phantom toolset or real alike**, with 401 and a challenge (the auth
  check precedes any registry lookup — no unauthenticated existence oracle), and
  Core's own protected-resource route answers any well-formed name with a
  registry-independent echo document (verified in the Core source and live). A
  consult could therefore only stand on a standing service API key in Core —
  and **no DIAL API key is ever involved**: the gateway holds no user-like
  standing credentials in Core; its only Core credentials are the user's own
  per-flow token. Discovery reverts to guard-only and **mirrors Core's
  registry-independent unauthenticated tier by design** — same 401-challenge,
  same echo-document, existence decided at the same moment, post-authentication,
  at the flow's settings read — with the consult era's artifacts deleted
  (service key, amplifier threat, availability-coupling residual, cache
  question). What would let the gateway do better is a **Core-side ask**, not
  this change: a registry-bound protected-resource route or an unauthenticated
  existence route would let the gateway refuse phantoms at the door, keyless —
  the gateway flips when Core provides one.
  The
  startup OAuth-declaration refusal is deleted with the mapping's
  `authentication_type` member; the name guard and restriction check move to
  request time at every name-resolution site; and the C1.5 apps-as-MCP feature
  is unified into the same general rule (the upstream stage runs only when the
  credential is missing AND the kind makes it establishable), shrinking C1.5's
  later scope to the apps resource surface and the unsigned DIAL_NATIVE case.
- **The threat model is updated by this change** (per the standing rule):
  T1-16's disposition and RES-6's bound shrink to the access TTL; RES-2/RES-3
  are re-priced for the custody key and the token-use rule; RES-19's
  internal-leg acceptance extends to the refresh-grant leg; T1-15's enumerable
  set widens in dynamic mode; RES-10 is re-priced for the moved
  kind check and RES-15 is narrowed to a restart *gain* (refresh capability
  survives; the stolen-token regression recorded); T6-2 and T1-7's rows
  are amended for the request-time guard and the refresh grant's new outbound
  call and decryption; four new residuals land — RES-20 (the availability-for-fidelity trade of
  the mandatory read), RES-21 (the mintable custody of the M13 amendment,
  re-shaped in four parts), RES-22 (the SSO-session keepalive, OQ-G — accepted
  as priced, 2026-11-01), and
  RES-23 (the ungated harness token stores) — and four new threat rows carry
  the change's own custody-era threats into the model's tables and
  dispositions (the keepalive mis-use, the crafted custody blob, the
  harness-store overflow, and the custody-key compromise); the asset inventory gains the custody-key and
  at-rest-ciphertext rows;
  M13 is amended per the priced trade; M9/M10 are amended; the revocation
  summary enters the model with identity-provider session revocation now
  propagating to the gateway's refresh capability at the next refresh; OQ-1 is
  resolved against the code; the compromise table's gateway-process and
  internal-network rows are re-priced; a new grouped mitigation row (the
  custody envelope) is placed in the spec; and the flow era adds its own set —
  three new threat rows (the short-circuit's widened mint surface, the
  global-credential mis-use, the forged signed-in answer), the forged-settings
  row's existence edge (the settings read is now the system's only existence
  decision), invariant 3's use-vs-establish wording, and the grouped-mitigation
  row M23 — the counts land at 62 threats (EP1 21, EP4 8, EP5 7), 23 residual
  records, 17 assets, and 22 grouped mitigations.
- **The owner's pause rulings (2026-11-01) are on the record** (design.md §8):
  the fail-closed refresh stands — a refresh that cannot be verified fresh is
  refused, with no stale-snapshot fallback (structurally: the refresh token
  carries no claim snapshot); the SSO-session keepalive effect is accepted as
  priced, with RES-22 as the disclosure; and gateway-side revocation is ruled
  local-only — `/dial/revoke` ends the gateway's own session (its tokens and
  the denylist entries) only, not the user's identity-provider session and not
  the upstream credentials stored in Core, which remain until their own
  lifecycle ends them. The three carried defaults are confirmed as rulings
  too: rotation-off is warned in the operator material, not refused at
  startup; the envelope's version and key-id are bound into the AEAD
  associated data, with the single-active-keyset invariant as today's
  key-commitment bound; and the hard-cut custody-key rotation wave is the
  accepted operator cost, scheduled around the refresh window's absolute
  expiry. The `gateway/tokens.py` docstring correction is assigned to this
  change's diff (tasks.md 5.7). No owner-ruling slot remains open. (The
  consult era's cache question is gone with the consult; the Core-side ask — a
  registry-bound PRM or an unauthenticated existence route that would let the
  gateway refuse phantoms at the door, keyless — stays parked in design.md §8
  as a suggestion to the Core team, not an owner ruling slot. Retention
  persistence (OQ-B) is discharged by the v3 re-taking — there is no store to
  persist; the custody key's long-term home is C3's own scope.)
