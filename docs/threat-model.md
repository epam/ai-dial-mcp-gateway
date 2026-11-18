# Threat model — the MCP sign-in gateway (baseline)

**What this document is.** The baseline threat model of the MCP sign-in gateway as the
system stands today — the local development shape: a plain-http front door on
`http://localhost:8090`, a file-based signing key injected from `.env`, one gateway
instance, in-memory flow state, one JSON-file DCR store (feature off by default). It is
the standing record every later security impact analysis starts from and updates: new
threats, changed dispositions, and re-judged residuals land in the affected entries
directly. Its structure and content are fixed by [`docs/security-analysis.md`](security-analysis.md)
(§4, the full threat model's shape) and the vendored operator instructions
([`background/instructions/threat-modeling.md`](background/instructions/threat-modeling.md),
reproduced exactly — taxonomy, control categories, and their order). This baseline is
the reconciliation of D2's two independent fresh runs (the double-run; comparison
record: [`evidence/d2/comparison.md`](evidence/d2/comparison.md)) — union minus error:
every threat, residual, control, or mis-use case either run found is here unless the
comparison's do-not-adopt list or a substantive error ruled it out. One row was added
after the reconciliation on the owner's sanity-test input — T1-16, the stale-claims
mis-use threat, with RES-6's cross-reference corrected to point at it
([`evidence/d2/owner-sanity-test-1.md`](evidence/d2/owner-sanity-test-1.md)). The
disclosed-residual register was assembled first, per the method, and is placed early
(§3, before assets and threats) so dispositions cite backward to the already-priced
residual they land on; it is assembled from the archived PoC change's `design.md`
(whole — its decision sections included), the change's evidence folder (the PoC C
acceptance-gate outcome), and [`background/design.md`](background/design.md) (§6.5's
role-staleness caveat; the Appendix's honesty list).

**The model at a glance.** 18 assets (§4); 9 trust boundaries (§5); 8 attacker classes
(§6); 7 attack-surface entry points (§7) — the design-review §5.1 six plus the as-built
EP7 — unchanged, the front-door change and the discovery-aliases change re-grade
existing surfaces; **110 threats** (§8: EP1 37, EP2 6, EP3 14, EP4 15, EP5 16, EP6 18,
EP7 4 — the front-door-addressing change's twelve delta rows and the discovery-aliases
change's seven landed in place); 25 residual
records (§3) — 24 disclosed open residuals plus RES-18, closed by the recorded
acceptance-gate outcome (the change adds no new residual; RES-7 and RES-16 are
re-judged, not added); invariant rulings 4 Preserved + 3 with a disclosed bound
(§11); **44 grouped mitigations** (§12 — M37–M42 are the front-door change's, M43–M45
the discovery-aliases change's); the
revocation-summary table (§10) is new.

**Scope boundary.** Dispositions are judged **as the system stands today**. The
production-shape re-judgement (TLS-fronted origin, KMS-held key, high availability,
real users) is a later workstream and is out of scope here: residuals below carry
today's disposition and, where the method requires it, the fact that re-opens them —
never a promise that the later workstream resolves them.

**Vocabulary.** Repo terms per `docs/security-analysis.md` §1: a threat knowingly not
mitigated is a **disclosed residual** with a three-part acceptance record; a
**disposition** is mitigated (implementation and owner named) or accepted; an
**attack-surface entry point** is the itemized unit a threat table is written per.

---

## 1. The system as it stands

A small OAuth2 authorization server ("the gateway", FastAPI / Python 3.12 / uvicorn,
container-internal `:8091`, never host-published) beside DIAL Core, behind a front
router (nginx, `mcp-signin-router`, host `:8090`, plain http,
`GATEWAY_PUBLIC_ORIGIN=http://localhost:8090`). Both ship in this repo's own
`docker-compose.yml`, joined to the instance's compose network as an external network;
the instance contributes Core (`core:8080`) and Keycloak (browser-facing
`https://keycloak:8443/realms/dial`, internal back-channel `http://keycloak:8900`).

The token chain: harness → front router → Core for MCP data (the gateway is *not* on
the data path); a 401 on the data path is answered with the gateway's challenge,
synthesized in the router location (`map $status` + `proxy_hide_header`). The sign-in
flow federates Keycloak (user authentication, the gateway's pre-registered confidential client — the 2026-11-05 ruling's shape: client secret on every token request, the PKCE challenge on top where enabled) and the upstream AS (Core's client, Core's public `code_challenge`), then calls
`POST /v1/ops/toolset/signin` with the live user's Keycloak JWT, and mints the
gateway's own JWTs — `sub` copied from Keycloak, roles read at the configured source
path, the access token's `aud = [resource, dial-mcp-proxy]` (the refresh token's `aud`
is the resource alone — the marker never included) — which Core accepts through a dedicated
identity-provider entry (`issuerPattern`, `audience: dial-mcp-proxy`, RSA256 via the
gateway's JWKS at `/dial/jwks.json`).

State as built: flow records (128-bit CSPRNG flow id, 10-min TTL), authorization-code
replay cache (`jti`, 5-min), refresh denylist (until `exp`), and the minutes-bounded
pending custody entries (one per completed-but-unredeemed flow, keyed by the
authorization code's id, dropped on expiry or restart) — all in memory, one instance;
DCR registration records in one JSON file on a bind-mounted volume (`DCR_ENABLED` off
by default). The process holds two persistent secrets: the signing key — a generated
RSA key in a gitignored path injected via `.env`, not KMS — and the dedicated custody
key, a 256-bit symmetric key in its own `.env` slot; there is no long-lived per-session
store. Keycloak admin credentials live in `.env`. Access tokens live 10 minutes; refresh
tokens 8 hours, non-sliding, carrying no claim snapshot — claims are re-read fresh from
the identity provider at every refresh, and the token carries the encrypted custody
claim (the provider's session refresh token, ciphertext unreadable without the custody
key) — startup-checked as `IDP_SSO_SESSION_MAX_SECONDS`, an operator assertion about the
provider's session policy; an in-flight identity token, once lifted, is live up to the
realm's own `accessTokenLifespan` regardless of the flow TTL that bounds the gateway's
*retention* of it. The served set spans two resource kinds — toolsets, and DIAL
applications with MCP endpoints. The served toolset set follows the request-time name
guard and the optional operator restriction: discovery answers every guard-passing name
— phantom and real alike — mirroring Core's own registry-independent unauthenticated
tier (no Core call, no gateway-held Core credential), and existence is decided
post-authentication, at the flow's per-user listing read. The apps kind is served
beside it through a second front-door path (`/apps/{name}/mcp`, proxied to Core's
deployments MCP path), with its own optional operator restriction and its own discovery
tier mirroring Core's own registry-independent apps tier — the same Core configuration
serving both namespaces, existence decided the same way, post-authentication, at the
flow's per-user app read. The app path introduces no new trust boundary, credential, or
grant type: it rides the existing public front door and the existing internal leg to the
configured Core. The flow's kind check is the upstream stage's routing decision: a
stored credential at user or global level short-circuits the consent for any kind, and
only a missing credential plus a non-OAuth kind is refused, on the impossible branch.
For the app kind the short-circuit is unconditional — no per-app status members exist to
read and no consent could establish anything, so the flow mints after the identity leg
and the app read, with no consent screen, no credential call, and no upstream round-trip
of any kind. Registration priority: pre-registered → CIMD (fetch-and-validate with the full
SSRF control set) → DCR (config-gated, default off).

## 2. Impact level, with reasons

**High.** The system holds an IdP-equivalent signing key — whoever holds it can mint a
DIAL identity for any `sub` with any roles, including admin, valid on every Core
endpoint (`background/design.md` §6.2) — and runs a public authorization-server surface
whose integrity the per-user upstream credential store depends on (the E7 callback
chain decides *whose* credential is stored under *which* `sub`). Sensitive assets in
play: the signing key, the dedicated custody key, live identity tokens, bearer tokens,
per-user upstream credentials (integrity), and toolset MCP traffic. Exposure today is moderated by the
local shape (localhost front door, single user, no real users) but the transport is
plain http and the key is file-based — both disclosed residuals below, not mitigations.

## 3. The disclosed-residual register

Every threat knowingly not mitigated, each with the three-part acceptance record
(`docs/security-analysis.md` §1): (a) the accepting condition, (b) the compensating or
bounding control where one exists, (c) what change or deployment fact re-opens it.
Assembled as the baseline run's first step and placed before assets and threats, per
the method: the register is the anchor the threat tables' dispositions (§13) cite
backward to. Twenty-four entries are disclosed open residuals; RES-18 is closed by the
recorded acceptance-gate outcome.

- **RES-1 — The E7 code-injection chain's interception variant** (T3-2; T3-3's
  exploitable remainder). (a) The committed deployment runs the front door on plain
  http; the defense trio kills guessing, not interception, and a deployment that runs
  the front door on plain http accepts the variant. (b) Transport security on the
  public origin — TLS-fronting — is the named control, deployment-owned, not built
  today; the flow TTL and destroy-on-first-use shrink the window without closing it.
  (c) A TLS-fronted deployment (which closes it) or any real-world use of the
  plain-http front door (which must not happen before then).
- **RES-2 — Memory zeroization** (T4-2). (a) CPython has no reliable wipe-on-demand —
  the managed-runtime reality shared with Java/Go/.NET; the process's two persistent
  secrets, the signing key and the dedicated custody key, live in process memory for
  the process lifetime, and each refresh grant's decrypted provider session refresh
  token exists in the process for the duration of that grant only. (b) The never-store
  rules (no post-flow user secrets; the identity token serves the flow's decision step
  and credential call, then is dropped) and the TTLs (10-minute access; in-flight token
  bounded by min(flow TTL, the provider's own `exp` — 24 h in this realm)); the
  never-store wording's one named exception is the encrypted custody claim, which is
  delivered by design inside the refresh token — ciphertext, never a plaintext — and is
  unusable without the custody key, so no plaintext user credential is stored anywhere.
  (c) Amended to be honest under both end states: **env/file injection is a supported
  end state**, a reasoned disclosed residual — CPython has no reliable wipe-on-demand,
  the process holds the active key material for the process lifetime, and injection
  moves *where the key is read from*, not *whether the process holds it* — so the
  re-open trigger is no longer the KMS sign-interface alone. The **KMS sign-interface
  is optional and may be abandoned**: its arrival would narrow this residual's *signing*
  half (the key never materializes in the process) while the **custody** half stays —
  the CEK is unwrapped at startup and held, the custody envelope the firm planned step.
  The record states all three shapes (injection-as-end-state, optional signing KMS,
  firm custody KMS) instead of promising the one; re-opened by a threat model requiring
  memory hygiene, or by either KMS half landing.
- **RES-3 — The token-use rule in presentations, not counts** (T5-1 exposure breadth).
  (a) The identity token is presented at most twice per flow — the listing read (the
  flow's one decision-step read) and, where the flow establishes a credential, the
  credential call. The two-read fallback that could have added a third presentation is
  deleted: the availability re-pinning made the decision step's two routes one URL, so
  the listing read is the only read the step can make, and the token's purposes never
  widen. The provider session refresh token adds purposes of its own:
  its **plaintext** is presented exactly once per gateway refresh, to the provider's
  token endpoint, while it is carried, and its **ciphertext** is delivered exactly once
  per rotation, inside the refresh token, to the client presenting it — the artifact's
  own bound is the provider's session policy (it dies with the session). (b) Same flow
  TTL, same purposes, internal-network presentations only for the plaintext; the
  ciphertext's client delivery is by design. (c) A second decision-step Core read
  reintroduced — the deleted fallback's return would add the third presentation.
- **RES-4 — The shared worker pool's flood queue** (T1-7, T2-2, T3-10). (a) Every leg
  runs on one bounded shared worker pool; a sustained flood of slow-leg requests within
  the rate limits queues legitimate legs. The refresh grant is one more
  attacker-steered slow leg: each refresh spends one outbound identity-provider call,
  each holding a worker-thread slot for up to the outbound timeout. (b) The event loop
  stays responsive (slow work offloaded), the public-endpoint abuse limits bound the
  refresh flood's arrival (one outbound call per admitted request), the CIMD capacity
  limiter bounds the CIMD fetch's pool share, and the public-endpoint abuse limits bound
  arrival generally — so the "one attacker-steered slow leg" wording no longer names the
  whole set; the set is the CIMD fetch and the refresh grant. (c)
  Sustained-abuse evidence demanding per-leg pools or admission control, or the
  multi-instance HA step.
- **RES-5 — The DCR store's host/volume boundary, and what enabling DCR accepts**
  (T4-3-adjacent, T1-11, T7-1–T7-3). (a) The store's integrity is trusted to the same
  boundary as the signing key (host-level write can rewrite both); the owner-only file
  mode is best-effort and fails on non-POSIX mounts — on a Windows host path
  bind-mounted into the container (9p/DrvFs), `chmod` fails and every file carries the
  mount's fixed modes; with the flag on, open registration and registrant-supplied
  attribution are accepted. (b) The store holds no secret (public clients; ids, URIs,
  a name, a timestamp); corruption fails closed and loudly; the registration cap
  bounds it; the flag is default off, and every token still requires the live IdP
  login and DIAL authorization. **Re-stated for the pod (DT-EP7-1):** the store's
  integrity is the **mounted volume and the node** — its boundary is the volume, not
  the signing key's (the trust-boundary statement `docs/gateway-configuration.md`
  carries), a key's boundary being its own injection path; the mount is the pod's one
  read-write state mount, backed by a cloud-backed persistent-volume storage class
  stated by its properties (survives node loss, tenant-governable), its ownership the
  fsGroup/uid-10001 controls the contract's security-context section states, and its
  no-secret-content property load-bearing (an external governance reader — storage-layer
  RBAC holders, backup destinations — holds registrations, never credential material, so
  the reader class is cheap to admit). (c) A deployment whose volume readers are
  untrusted, or enabling DCR in the production shape, or a store mount assembled outside
  the contract's stated class/ownership.
- **RES-6 — Role staleness within the access TTL** (T1-16 bounding, invariant 4's
  bound). (a) Authorization runs on gateway-asserted claims re-read at the last
  refresh; a role changed at the identity provider reaches minted tokens within the
  access TTL, and an already-minted access token carries its claims to its own expiry
  (≤ the access TTL) — the staleness window is no longer the whole `refreshTtl`. (b)
  The refresh grant re-reads the current claims from the identity provider's fresh
  token at every refresh, the refresh semantics are fail-closed (no snapshot fallback
  exists to serve), the window is non-sliding (the rotated token carries the original
  absolute `exp`), the access TTL is 10 minutes, and the next flow re-authenticates
  live. (c) The owner's revocation-SLA decision at the new baseline — the residual
  interval is now the time between refreshes plus each minted token's own life.
- **RES-7 — Marker-level audience binding only** (T1-3, T1-12). (a) A leaked gateway
  token is valid on every Core endpoint for its `sub` until `exp` — **across both
  resource kinds' paths** (widened by this change): a token minted for one resource kind
  is Core-acceptable on the other kind's data path, because per-toolset
  (per-resource) audience enforcement is unavailable in the flat-AS shape and Core's
  identity-provider entry checks the marker only (verified: no per-resource audience
  match exists on either MCP path, toolset or app). **The resource URI is longer now** —
  a multi-segment path rather than a single-segment name — **but the bound is the same**:
  the token still carries the resource plus the marker in `aud`, and Core still verifies
  the marker only, so the wider address changes what the URI names, not what Core checks.
  (b) The `dial-mcp-proxy` marker (Core config)
  structurally binds every accepted token to gateway issuance; the strict `resource`
  check at E3/E4; the refresh-time resource match; the gateway's own resource checks
  (which refuse a cross-shape presentation at the gateway's own surfaces); the
  10-minute access TTL. **The record's named structural remedy — DPoP (RFC 9449),
  deferred with a two-sided precondition (D6, owner-accepted record-wording
  2026-11-07).** Sender-constraining is the structural fix for this residual's class
  (the bearer token: stolen-token replay T1-3, marker-level audience binding RES-7,
  no per-user kill of live access tokens RES-8). The verdict is **deferred, not
  adopted and not refused**, on a precondition with two sides, the **resource-server
  half decisive and unchanged**: (i) the **client side** — the contract still mandates
  Bearer presentation, and DPoP is unadopted in it. The MCP authorization
  specification's "Access Token Usage" section mandates `Authorization: Bearer` on
  every request, and DPoP appears nowhere in the authorization specification or the
  security best practices — re-verified against the `2025-06-18`, `2025-11-25`, and
  current `2026-07-28` texts, each fetched in full by the re-judge walk. What has
  moved: the official **TypeScript SDK carries opt-in DPoP client support** (RFC 9449 /
  SEP-1932, merged via PR #2629 — `OAuthClientProvider.dpop()`, tokens the AS issued as
  Bearer still presented as Bearer); the **Python SDK does not** (its conformance
  expected-failures file: "the SDK's OAuth client does not implement DPoP proofs"); and
  an **experimental DPoP profile for MCP exists** (unadopted, on an unmerged branch).
  Unverified: whether the two field-proven flagship harnesses enable DPoP — the SDK's
  support is opt-in at the provider level, so SDK capability is not harness enablement.
  (ii) the **resource-server side** — the validator of gateway tokens is **Core**,
  whose identity-provider entry validates **bearer-style with no RFC 9449 proof
  validation**; sender-constraining binds at the point of *use*, so an AS-side-only DPoP
  adoption is incoherent (the constraint would be void exactly where it must hold).
  DPoP adoption reopens when **both** sides move — the contract requiring or permitting
  sender-constraining **and** the flagship harnesses verifiably presenting RFC 9449
  proofs (verified harness evidence, **not SDK changelog entries**), and Core validating
  DPoP-bound tokens (the `cnf` claim and the per-request proof — the decisive half,
  the E1 line's natural scope in `docs/production-roadmap.md` §Evolution). The
  recommendation the RFC makes *mandatory* for this client shape is already held:
  §2.2.2/§4.14.2 require public-client refresh tokens sender-constrained **or** protected
  by rotation, and the rotation + denylist-by-`jti` (M9) is the second alternative, in
  place and spec-pinned. (c) Core-side per-issuer path/audience
  scoping (the structural fix, a future Core ask, recorded §8), or harness discovery of
  per-toolset issuers; the DPoP precondition above reopens the sender-constraining
  disposition when both sides move.
- **RES-8 — No per-user kill of live access tokens** (T1-3 bounding). (a)
  Non-introspected JWTs cannot be revoked individually — the same limitation every
  JWT identity provider has. (b) 10-minute access TTL; refresh-token
  denylist by `jti` (a user's refresh dies at the next refresh attempt); key rotation
  kills all tokens within the JWKS cache TTL. **The class's named structural remedy —
  DPoP (RFC 9449) — is recorded with RES-7's** (the same bearer class, the same
  two-sided precondition, D6): sender-constraining would bind a live access token to its
  holder's key, so DPoP adoption also reopens this residual's per-user-kill gap on the
  access-token side; the deferral stands on the unchanged resource-server half (Core
  validates bearer-style). (c) A revocation SLA demanding faster
  per-user kills (Core-side introspection), or the DPoP precondition above.
- **RES-9 — GLOBAL credential establishment not reachable from the flow** (T5-4).
  (a) The flow *establishes* at USER level only; GLOBAL-level establishment stays an
  operator action (admin-gated in Core). GLOBAL-level *use* is reached through the
  signed-in short-circuit when an operator has stored a GLOBAL credential: that is the
  operator-configured delegation, not an escalation the flow performs — the flow never
  reads or transits the stored credential and the credential call stays at USER level on
  every establishing path. (b) Not a risk acceptance but a scope boundary on record; the
  ops API path is unchanged and admin-gated, and the same user already holds the same
  access through Core's own paths. (c) An owner decision to build a toolset-owner UX.
- **RES-10 — The impossible-branch refusal loop for a credential-less non-OAuth toolset**
  (the flow's kind branch). (a) A non-OAuth toolset with no stored credential refuses
  every flow with a plain-language page naming the cause — the loop is benign
  (rate-limited, one identity-leg exchange per cycle, no retry the user performs changes
  the outcome) and ends out-of-band when an administrator stores the credential (a
  user-level key through Core's own paths, or a GLOBAL-level key through the ops API),
  after which the same flow short-circuits. The non-OAuth exclusion as a class is gone:
  a non-OAuth toolset with a stored credential is *served* through the signed-in
  short-circuit. (b) The refusal is fail-closed, plain-language, and audited
  (`non_oauth_toolset`); the startup OAuth-declaration refusal was deleted with the
  mapping's `authentication_type` member (a non-OAuth toolset is a valid entry under
  dynamic serving); non-OAuth toolsets stay reachable through Core's own paths via the
  router's catch-all. (c) The internal-leg forgery variant (DT-EP5-3), or the API-key
  wrapper workstream.
- **RES-11 — Consent attribution is display-level** (T1-11, T1-14, T3-4 family;
  re-priced for the decision page, DT-EP3-3). (a) The upstream consent screen shows
  Core's registered client, not the harness; no architecture gives an upstream AS
  cryptographic attribution of a downstream client's downstream client. **Re-priced one
  notch wider by this change:** where the residual was an information-honesty bound —
  a false `client_name` misinforms — the decision page raises the stake, because a
  false name there *harvests an approval* (the registrant collects a user trust it did
  not earn at the flow's one decision point). The stake rises; the acceptance is kept,
  because the naming surface is the registration's (CIMD/DCR), outside the gateway's
  boundary to verify, and the gateway's job on that page is to present, not to
  adjudicate. (b) Recognizable client naming (operator config), the interstitial naming
  both harness and toolset (preferring a real CIMD client name), the end-to-end audit
  chain (per-flow records + Core's independent `/signin` record keyed by `sub`), and —
  the compensating control this change adds — the decision page's **verifiable-facts
  rule**: the client id and the registered `redirect_uri` shown beside the name, the
  two facts a registrant cannot falsify to the page's advantage (the redirect is the
  registration's own validated value, and a collector URL reads as one). (c) An upstream
  AS offering downstream-client attribution, or a future client-authentication or
  verified-naming mechanism on the registration surface (the re-open trigger unchanged).
- **RES-12 — The plain-http front door** (T1-1, T1-2, T3-9, T6-5). (a) The local
  development shape runs the public origin on plain http (`http://localhost:8090`);
  TLS and HSTS belong to the deployment layer's TLS listener by design. (b) The local
  shape's bounds: localhost binding, a single-user development deployment, no real
  users; token TTLs bound what a sniffer harvests; PKCE bounds what callback
  interception yields (the exploitable remainder is RES-1). (c) Any real-world use;
  a TLS-fronted deployment (which is the stated precondition for it).
- **RES-13 — File-based signing-key custody** (T4-1, T4-4, T4-6; DT-EP4-4). (a) The
  key's custody is its **injection path — env or file injection the first-class end
  state**; the KMS/HSM sign-interface is optional and may be abandoned (RES-2's
  amendment), not a promised direction. Two spellings share the class with no
  preference between them: the material in an injected environment variable, or a PEM
  on a **read-only mount** (the pod's key-file mounts, or the IdP client secret under
  its `IDP_CLIENT_SECRET_FILE` spelling — the same boundary price, a new location,
  priced at DT-EP4-4). (b) IdP-grade discipline at this bar: never committed, never
  logged, `kid`-published, rotatable — now **proven by rehearsal** (the drill) rather
  than documented-only, with the retained-entry window the priced addition
  (DT-EP4-2); the injection-path boundary (the env-var surface, the node, the mount)
  is the trust. (c) A threat model requiring memory hygiene, a widening of who can
  read the host or the mounts, or either KMS half landing (the optional signing
  interface, the firm custody envelope).
- **RES-14 — The new-AS trust concentration and audit budget** (T4-1 family). (a) The
  gateway's key is as powerful as the identity provider's — the price of the chosen architecture —
  carried by a new, small-code service with a smaller audit budget. (b) Equal key
  power, narrower issuance policy (tokens minted only after a live IdP authentication
  of that `sub` plus the DIAL authorization check; no `offlineClient`; 10-minute
  TTLs); the service stays small, single-purpose, internal-logic-only. (c) Growth of
  the gateway's code or role beyond that bar.
- **RES-15 — Single instance and in-memory state loss** (restart semantics; T5-6's
  crash tail). (a) One gateway instance; the flow records, the minutes-bounded pending
  custody entries, the code-replay cache, and the refresh denylist are in memory and
  lost on restart. (b) Loss semantics specified, narrowed to a gain: refresh capability
  now *survives* restarts and rollouts — the encrypted custody claim returns with the
  presented refresh token, so a restart costs no re-sign-in wave; issued tokens keep
  working (self-contained JWTs); what is still lost is the pending hand-off entries (an
  unredeemed pre-restart code fails its grant, fail closed), the replay cache
  (PKCE-covered), and the denylist (bounded by `refreshTtl`). One regression is recorded
  alongside the gain: a *stolen* refresh token also survives restarts (RES-21's part
  iii), bounded by the non-sliding absolute expiry and the provider's session clock.
  (c) **Extended to the pod's single-replica statement:** the pod contract states the
  assumption — flow state and the approved-client registry are in-memory, so the pod is
  not horizontally scalable and HA stays deferred; the loss semantics are the spec's
  fixed fail-safe shapes (approvals re-prompt, flows re-run, pending entries lost
  bounded). The mis-assembly shape is priced (DT-EP6-1): an operator who scales the pod
  horizontally gets split in-memory state, which fails safe but confuses — the contract's
  statement is what makes the failure diagnosable as a contract violation rather than a
  gateway defect. Re-opened by the HA requirement (the documented Redis step).
- **RES-16 — nginx config fragility** (T6-2, T6-3, DT-EP6-3). (a) The routing's correctness
   (query strings, origin quoting, regex order, and now the path grammar) is config-carried
   and measured, not machine-checked end to end. **(a) widened honestly by this change:**
   the segment grammar **joins the fragile set** — it is a second implementation of the path
   rules beside the gateway's guard, and a drift between the two is the T-EP6-a threat. (b)
   Startup reserved-name and decoded-rule enforcement covers the *configured* operator
   restriction entries; for dynamic paths the request-time path guard does the work;
   anchored maps, the `/mcp`-suffix match domain, the configured origin, and the
   request-line buffer bound carry the router's half, and — the compensating control named
   for the new grammar — the **lockstep probe battery** asserts the shapes both sides admit
   and refuse as identical and the documented asymmetry as the asymmetry it is, negative
   controls first. (c) Any
   router config change, **any change to the path grammar or the data-path map**, or
   dropping nginx (the documented amendment: the
   authentication-kind extension moves into the flat AS metadata). **Re-judged by the
   discovery-aliases change:** (a) gains the `/.well-known/` locations' precedence — the
   closure's plain-prefix form (never `^~`) and the Core protected-resource location's
   end-anchoring and raw-URI template gate, and the catch-all's raw namespace-spelling check — in the fragile set, with the well-known probe rows (M45) named as its
   compensating control; (c) gains "any change to the `/.well-known/` locations, or a
   Core release adding a `/.well-known/` route".
- **RES-17 — CIMD draft churn and harness `resource` conformance beyond the flagship**
  (T2 family, discovery; T2-5's allowlist curation). (a) CIMD is a young draft; the
  flat AS makes `resource` structurally required, and other harnesses are expected,
  not tested. (b) DCR retained behind a config flag; the one-toolset
  `infer_resource_single_toolset` escape; the origin allowlist is the operator's
  trust decision; revisit only on a named harness's measured failure. (c) A named
  harness's measured failure.
- **RES-18 — The assembled chain's evidence status** (system-level) — **closed by the
  recorded outcome.** (a) Every ingredient was spike-, source-, capture-, or
  PoC-verified; the assembled chain's end-to-end proof was the acceptance gate, whose
  outcome was not determinable from the baseline runs' allowed inputs (both runs' gap
  lists — the method's fix has since allowlisted the record). (b) The ingredients'
  evidence; the falsification-stop rule (a failed criterion reopens the design, never
  a patch-around). (c) Discharged: the gate's recorded outcome is green — all five
  criteria (a)–(e) CLOSED on the archived change's evidence (`poc-c-runbook.md`'s
  scoreboard, field runs 1–5) — so this residual is closed, not disclosed. It re-opens
  only if the acceptance evidence is later falsified.
- **RES-19 — Internal plain-http server-to-server legs** (T5-1, T5-2, T5-8, T4-4).
  (a) The gateway presents the live identity token to Core over `http://core:8080`,
  talks to the identity provider over its internal http port, and Core fetches the JWKS over an
  internal URL — all unencrypted inside the compose network. The identity-provider legs carry
  the gateway's **inbound identity-verification chain**, not just data: both the
  token exchange and the JWKS fetch are gateway-outbound calls on the provider's
  back-channel (`http://keycloak:8900` in the local shape), so a compose-network peer in a MITM position can serve a
  forged id_token plus the matching hostile JWKS and make the gateway mint a token
  for any `sub` with any roles, including admin — the signing-key blast radius
  (`background/design.md` §6.2) reached from a network-peer position (TB3, attacker
  7) rather than the host (TB5), with no victim required. The acceptance therefore
  rests on the compose network's membership trust as a **load-bearing assumption for
  identity verification itself**, not only for the confidentiality of the data path.
  (b) The private-bridge network placement (only the deployment's own services are
  peers) is the bound — and it is the *only* bound for the forgery chain: the
  router's port non-publication does not bound these legs, because they are
  gateway-outbound and never cross the router. The token-use rule bounds presentation
  count; PKCE bounds what a `/signin` interception yields (it does not bound the
  forgery chain — the attacker drives their own flow, so no victim's code is
  involved). Re-priced 2026-10-29 with the blast radius stated: the acceptance
  **holds at today's shape** on the private-bridge bound — reaching the position
  requires already being inside the deployment's own compose network, whose members
  are all the deployment's own services — but it is now accepted knowingly against
  mint-any-identity, not merely token capture. The change re-prices the record again,
  adding the refresh-grant leg: the forgery gain at refresh is any-claims-for-an-
  existing-`sub` (the `sub` cross-check binds the subject, so it is strictly narrower
  than the exchange chain's mint-any-sub), and the sniffing gain now includes the
  **decrypted provider session refresh token** the grant presents on the internal
  plain-http leg once per gateway refresh — the most powerful credential the flow ever
  puts on the wire, renewable by use on providers with sliding session semantics. (c) The production shape (K8s, C3's
  pod) changes the network assumption — a cluster's pod-to-pod exposure is not a
  private bridge of the deployment's own services — so D3 must re-judge this residual
  there; at today's shape, any widening of the internal network's membership
  re-opens it.

  **Extended by this change** (the class's one more member, not a new residual): the
  app read (`GET /openai/applications/{id}`, T5-8) rides the same internal leg from the
  configured Core, authenticated by the user's own identity token, and carries the apps
  namespace's existence and authorization decisions. A forged answer on it — a forged
  200 for a phantom app, or a forged 403/404 — has the same acceptance and the same
  bound as the toolset listing read's forged answer (T5-7): it cannot mint for another
  user, and a phantom app's data path answers only an error. The residual's compensating
  controls and re-open trigger are unchanged by this leg; it is one more Core answer on
  the same trusted leg.

  **Re-priced again by the generalized identity leg** (the class's shape widened, not a
  new residual): the identity-provider back-channel legs — the discovery fetch, the
  exchange, the refresh grant, the key-set fetch — are members of this residual in
  every shape the leg takes. In the local shape they are the plain-http Keycloak legs
  described above, unchanged in acceptance. In an override deployment the operator's
  explicit plain-http claim now carries the **client secret** as well — on every
  token request, in both positions of the leg's PKCE toggle (the confidential-client
  ruling, 2026-11-05; the earlier no-PKCE-only conditioning is superseded) — a wider
  exposure than the refresh token alone: an internal-leg peer that could read the
  session refresh token can now read the client secret too, and the widened
  exposure is stated here, inside the override's own trust claim. In the external-TLS
  shape the identity-provider legs are the residual's narrowing case —
  transport-protected to the provider's origin like any HTTPS client, with the same
  acceptance: an attacker who defeats transport validation on the issuer's own origin
  was already able to impersonate the provider's endpoints directly. The compensating
  controls and re-open triggers are otherwise unchanged; the challenge-off mode's
  own interception residue is priced separately (RES-24).
- **RES-20 — The availability-for-fidelity trade of the mandatory claims read** (T1-6's
  accepted remainder; DT-EP1-6). (a) The claim read at refresh is mandatory and
  fail-closed, so an identity-provider outage refuses every refresh, and the recovery
  (re-sign-in) needs the same provider — a full sign-in outage for the provider's
  downtime, where the snapshot design would have kept serving. (b) Already-minted access
  tokens keep working to their own expiry; the provider's own timeout bounds each call;
  and the burst of `claims_read_failed` audit records is the detective signal, distinct
  from every other `invalid_grant` refusal. (c) A future owner ruling for a bounded
  stale-claim fallback (OQ-A ruled fail-closed, 2026-11-01 — the change's design §8) or
  an availability requirement that cannot accept re-sign-in during provider downtime.
- **RES-21 — The mintable-custody residual, in four parts** (T4-8; DT-EP4-1; the D5
  amendment's priced trade). (a) The provider's session refresh token is carried as
  encrypted mintable material inside the gateway's refresh token, in four priced parts:
  **(i) encrypted mintable material at rest in harness token stores** — every issued
  refresh token carries the ciphertext; it is inert without the custody key and adds
  nothing to an attacker who controls the machine it sits on (that attacker already
  holds the refresh token itself, which mints the same user identity through the front
  door); **(ii) the time-decoupled conjunction** — a recorded token plus a later
  custody-key leak lets the attacker decrypt the archive and replay each archived user's
  provider identity for as long as the provider's session policy allows, the two halves
  collectible in different incidents. **Re-priced by this change for the retention
  window (DT-EP4-3):** where the hard cut killed a superseded key's decrypt ability at
  rotation, a superseded key **retained** through the drain window stays able to decrypt
  — the conjunction's window and the archive's window are no longer disjoint at the
  rotation boundary, bounded by the same operator-declared drain bound and the immediate
  cut (remove the entry, outstanding blobs refuse at next presentation), with each
  presenting session re-sealing under the active key to shrink the retained-key-bearing
  population; **(iii) the recorded regression** — a stolen
  refresh token survives restarts under this design, where the store design's restart
  killed stolen tokens' refresh capability with everyone else's; **(iv) the
  process-compromise floor, unchanged in kind and reduced in blast** — a process
  compromise yields the custody key plus the plaintext of only the sessions presenting
  during the window, never a whole-store harvest. (b) The bounding controls: the grant
  is session-bound with `offline_access` never requested (no 30/90-day offline
  capability; the provider's session policy is the clock — the explicit SSO Session
  Idle/Max pair on the local development Keycloak instance), the provider's rotation reuse detection **where enabled**
  is the containment control for the credential-on-the-wire exposure of
  plain-internal-leg deployments (the gateway's own next refresh races a lifted string
  and the first replay revokes the chain for both — the local dev shape's provisioning
  sets it, and it is not Keycloak's image default), while deployments with **TLS'd
  internal legs — the production shape — are bounded by the transport itself**, the
  detection there defense-in-depth rather than the bound, IdP-side session revocation
  kills the credential at its next use, the plaintext
  is never logged and never leaves the process or reaches any client, the carried window
  is bounded by the refresh token's non-sliding absolute expiry and the startup
  lattice's operator-declared session bound, the custody key is rotatable with the
  overlap semantics (seal under the active key, decrypt with active-or-retained through
  the declared drain window; the superseded key's removal — immediate or mid-drain — is
  the cut, and the drill rehearses it), and the size bound plus the two-harness round-trip
  gate bound the carrier's own failure mode. It grants no upstream (toolset) credential
  and no other user's identity — the bound is per-user and session-bound, not scope: the
  minted provider token carries the user's full DIAL role set (Core authorizes on the
  role claims embedded in the token, which the realm's mappers place there regardless of
  OAuth scope; the client's `profile,email` scopes bound nothing DIAL-relevant). (c) A
  custody shape that holds no provider refresh material at all, a provider whose
  session-bound refresh tokens outlive any operator-acceptable session policy, a harness
  token store with a hard size limit the bound cannot dodge (the live round-trip gate
  exists to find this before adoption), or the C3 KMS landing choosing a
  per-refresh-call shape that re-couples availability (the wrapped-DEK preference is the
  guard).
- **RES-22 — The SSO-session keepalive** (T1-17; DT-EP1-7's accepted remainder). (a)
  The gateway's refresh cadence refreshes the identity-provider session's idle timer, so
  a harness refreshing on its own schedule keeps the user's SSO session alive after all
  browser activity has ended, up to the provider's SSO Session Max — the user's "walking
  away" no longer ends their identity session on the idle timescale. (b) Bounding
  controls: the provider's SSO Session Max (an absolute, non-sliding cap), the gateway's
  own non-sliding refresh window, the startup lattice's operator-declared session bound
  (`IDP_SSO_SESSION_MAX_SECONDS`), and explicit revocation still propagating at the next
  refresh. (c) A future owner ruling for a tighter bound (OQ-G ruled accepted-as-priced,
  2026-11-01 — the change's design §8; the refused variant was a provider-specific
  introspection of session state).
- **RES-23 — The ungated harness token stores** (T1-19; DT-EP1-9's accepted remainder).
  (a) Every harness token store beyond the two field-proven ones (Claude Code/CIMD and
  Cursor/DCR) is unverified, and a store with a hard item-size limit below the grown
  refresh token breaks the session silently, far from its cause — the user's
  availability, not the gateway's. (b) Bounding controls: the provider-token size bound
  refused loudly at sign-in, the raised and re-priced token-endpoint body cap, and the
  live two-harness round-trip gate before adoption. (c) A named harness store with a
  hard limit the configured bound cannot dodge — the one result that legitimately forces
  the custody shape back to the owner (the change's task 3.3 gate finding) — or an owner
  ruling for a smaller default carrier.
- **RES-24 — The challenge-off mode's interception residue** (T5-11). (a) With the
  PKCE challenge disabled on the identity leg — an explicit operator opt-in for a
  provider that cannot support it — the binding that made an intercepted identity-leg
  code unexchangable by its interceptor is gone, and on a plain-http front door an
  on-path attacker reads the
  code (and the callback URL) off the wire; the client secret is the only remaining bar
  to spending it, a strictly weaker position than challenge+secret against a
  secret-holder. (b) The control is inherent, not mode-conditional: the gateway is a
  confidential client at the identity provider (the owner's ruling, 2026-11-05) — the
  exchange and the refresh grant authenticate with the configured secret in **both**
  toggle positions, so the interceptor never holds what the exchange requires,
  whichever way the toggle is set — the intercepted code is spent by the gateway first
  or refused as `invalid_client` (the burst reads on the audit trail as the
  claims-read refusal class); the startup refusal guarantees the secret's presence in
  every deployment, and the client-facing
  authorization surface keeps requiring PKCE from harness clients regardless of the
  identity leg's toggle. (c) A TLS-fronted public origin — which closes the
  interception
  vector, re-opening the acceptance for re-judgement (RES-1's own trigger) — or the
  mode's retirement.
- **RES-25 — The localhost-warning deferral** (the current MCP revision's CIMD-security
  display SHOULD; B-4, owner-ruled 2026-11-07). (a) The accepting condition: the MCP
  authorization specification's current revision SHOULDs "additional warnings for
  `localhost`-only redirect URIs," and none exists as built or in the delta — but the
  attack the warning mitigates (the section's own localhost-impersonation shape: a
  hostile party pairing the *legitimate* client's metadata URL with its own loopback
  port, the port exception letting it match) **requires code execution on the victim's
  host to harvest the code**, and that position is the attacker model's **class 3**
  (the second workstation user or workstation malware — reads the harness's token
  store, the browser, or the loopback redirect) and **class 4** (the malicious or
  compromised harness), where the attacker already holds strictly cheaper attacks —
  T1-3's stolen-token replay pricing (the harness token store is on that host) and
  RES-21 part i's own statement that a control adds nothing to an attacker who controls
  the machine it sits on. A warning mitigating an attack whose precondition already
  grants bigger prizes buys no realized gain, so the owner ruled it **deferred with
  reasoning**. (The grounding is on the model's own rows — attacker classes 3/4, T1-3,
  RES-21 part i — because no residual carries a "local-compromise floor" acceptance; an
  earlier draft attributed one to RES-23, whose record is the ungated harness token
  stores' availability bound, and the attribution is corrected here rather than
  carried.) (b) The compensating bound: the decision page displays the **full
  registered `redirect_uri`, port included**, on first attribution (the checkpoint
  requirement's page-content rule), so the one presentation that carries a decision
  names the local destination for what it is — the drive-by shape is bounded by the
  display, the local-execution shape by the priced classes above (a warning adds
  nothing to what that attacker already holds); this display also **discharges the
  current revision's redirect-hostname-display MUST** with room to spare, said here and
  not left implicit. (c) The re-open trigger: a **client population where loopback is
  anomalous** — deployments whose harness clients register non-loopback redirects as
  the norm, making a loopback presentation a signal worth a warning. The deferral is
  priced, not forgotten: the roadmap's closing re-judge (D3) sees it here.

## 4. Assets and footprints

| # | Asset | C | I | A | Footprints in the system |
|---|---|---|---|---|---|
| A1 | Gateway signing key (RSA private) | high | high | low | Host file (gitignored, `.env`-injected); gateway process memory (lifetime of the process); public counterpart at `/dial/jwks.json` (E8) |
| A2 | In-flight user identity token (the user's identity-provider JWT, presented to Core) | high | high | low | Gateway process memory for ≤ flow TTL; the wire to Core (internal plain http, at most two presentations — the listing read and the credential call); never logged |
| A3 | Gateway-issued access tokens (10-min JWTs, bearer) | med | med | low | Harness token store; the wire (plain http `:8090` — token responses and every MCP call's `Authorization` header); Core's validation path |
| A4 | Gateway-issued refresh tokens (8-h non-sliding JWTs, bearer; the session bindings plus the encrypted custody claim — no claim snapshot) | med-high | med | low | Harness token store; the wire; the in-memory denylist; carries the encrypted custody claim (A17) |
| A5 | Authorization codes and flow ids (the identity-provider code, upstream code, gateway code, 128-bit flow id) | med | med | low | Browser callback URLs (E6/E7, plain http); the final redirect to the harness `redirect_uri`; gateway memory (flow record, and the minutes-bounded pending custody entry keyed by the code's id); the `/signin` body over the internal network |
| A6 | Per-user upstream credentials (stored in Core, encrypted, per `sub`) | high | high | med | Core's credential store only; their *integrity* (which credential lands under which `sub`) is decided by the E7 chain |
| A7 | Toolset MCP traffic (user queries, tool arguments, results) | high | high | med | Harness ↔ router ↔ Core (plain http today); Core ↔ upstream |
| A8 | User authentication material (the identity provider's credentials and SSO session) | high | high | low | The identity provider; the user's browser; the IdP leg's login page (the phishing target of a rewritten challenge) |
| A9 | Audit trail (per-flow and per-refusal records) | low | high | med | stdout/otel sink; log storage (deployment-owned) |
| A10 | DCR registration records (client ids, redirect URIs, names) | low | med | med | One JSON file on a host bind-mounted volume; gateway memory |
| A11 | Core identity-provider and toolset-security configuration (`issuerPattern` per provider, `audience: dial-mcp-proxy`, `allowedRedirectUris`, toolset `auth_settings`) | low | high | med | Core environment/configuration on the instance (deployment-owned) |
| A12 | Local development identity instance's admin and test-user credentials (the local dev shape is a Keycloak deployment) | high | high | low | Host `.env` file (gitignored) |
| A13 | Routing and challenge integrity (nginx config; the 401 rewrite) | low | high | med | Router config committed in this repo; the running router container |
| A14 | Gateway availability (the sign-in surface; the data path does not depend on it) | low | low | med | The gateway process; the shared worker pool |
| A15 | Upstream PKCE verifier (Core's, per toolset) | high | — | — | Core only; nulled on every public projection of toolset settings (never-cut 2) — no footprint outside Core |
| A16 | Dedicated custody key (256-bit symmetric, key-id-versioned) | high | high | low | Gateway process memory for the process lifetime; the `.env` slot at rest; KMS at C3 — the signing key's own custody class (never logged, `repr`-clean, hard-cut rotatable) |
| A17 | Encrypted custody claim at rest in harness token stores (the ciphertext of the user's provider session refresh token) | med-high | med | low | Rides every issued refresh token in the harness token store and on the wire; inert without the custody key (A16); dies with the provider session |
| A18 | The identity-provider client secret (the IdP-leg client's authenticator, presented on every token request in both toggle positions) | high | low | low | The `.env` slot at rest; gateway process memory in every deployment; the token-endpoint leg in presentation on every exchange and refresh grant — the IdP-leg client's blast radius only (no gateway mint, no Core access, no upstream credential); the no-secret deployment exposure class is removed by the 2026-11-05 ruling (startup refuses without it in both toggle positions) |

CIA marks: C = confidentiality, I = integrity, A = availability; "—" = not a
first-order property for that asset (A15 — the verifier is secret material whose
custody and integrity are Core's own, unchanged by this design).

## 5. Trust boundaries

- **TB1 — The user workstation / internet.** The harness, the browser, the loopback
  redirect servers. Anyone here is untrusted; every request arriving at the front door
  starts from this boundary. In today's shape the front door is
  `http://localhost:8090` on a development workstation: reachable by any process on
  that workstation and by whatever the host's firewall admits.
- **TB2 — The public front door.** The router's `:8090` listener, plain http — the
  crossing point between TB1 and the deployment. TLS is absent here today (a property
  of the deployment's transport; see RES-12).
- **TB3 — The deployment-internal compose network.** Gateway, router, Core, redis;
  joined as an external network — and, in the local shape, the Keycloak instance as
  the identity provider's compose-network peer. Members are semi-trusted toward each
  other; the internal legs are plain http (`http://core:8080`; the local IdP's
  `http://keycloak:8900`). The boundary statement does not assume that shape: in the
  external-provider configuration the identity provider is not a network member — the
  back-channel legs (the discovery fetch or the directly-configured endpoints, the
  exchange, the refresh grant, the key-set fetch) egress from this network to the
  provider's TLS origin, or to the operator-configured back-channel override's origin
  where one is owned; the IdP is either a peer inside this boundary or a provider
  beyond it, and which endpoint source the legs carry does not change where the
  boundary lies.
- **TB4 — The gateway process/container.** Its memory (the signing key, the dedicated
  custody key, the transient plaintext of the provider session refresh token during each
  refresh grant, the minutes-bounded pending hand-off entries, the in-flight identity
  token, flow records, caches) and its filesystem, including the DCR store mount.
- **TB5 — The host.** The machine running Docker: `.env` (Keycloak admin and test-user
  credentials), the signing-key file's injection path, the DCR store bind mount, the
  Docker daemon. The host/volume owner lives here — the boundary the signing key and
  the DCR store are trusted to (`background/design.md` §6.4 class).
- **TB6 — Core's interior.** The credential holder: per-user upstream tokens, PKCE
  verifiers. Trusted; unchanged by this design.
- **TB7 — The identity provider's interior.** The IdP: user credentials, sessions, its
  signing key. Trusted — in either shape the identity leg takes: the local
  development instance (a Keycloak deployment, a compose-network peer) or an external
  provider beyond the network. The trust is exactly the pinned issuer plus its
  published key set; what a compromised provider inside this boundary gains is priced
  in §10's external-identity-provider row.
- **TB8 — The upstream.** The toolset's AS and API: a third party holding Core's
  registered client. Trusted to authenticate its own users and honor its own consent;
  not trusted to attribute downstream clients (RES-11).
- **TB9 — The operator / deployment-owner boundary.** Core's configuration (the IdP
  entries, the audience marker, `issuerPattern` on every provider,
  `allowedRedirectUris`), the toolset mapping, key rotation, the DCR flag, the audit
  sink. High-privileged and legitimate — and the boundary the deployment administrator
  (§6's attacker 6) and the operator mis-use rows (T1-11, T1-14, T4-6) live behind.

## 6. Attacker inventory

Per the vendored instruction's Step 1 — including legitimate and high-privileged
users, not only outsiders:

1. **An anonymous external party** — anything that can reach the workstation's
   published `:8090` or a process on the workstation itself: probing the public AS
   surface, sniffing or manipulating plain-http traffic, intercepting browser
   redirects. In today's shape, a co-located process on the development host is the
   realistic resident of this class.
2. **A legitimate business user / harness operator** — any DIAL user who can run a
   harness and complete the flow exactly as permitted. Mis-use surfaces: replaying
   their own token across toolsets and resource kinds (T1-12), occupying flow records and
   workers within
   the rate limits (T1-6, T2-2), registrant-supplied attribution when DCR is enabled
   (T1-11), wearing a pre-registered client's label (T1-14), and walking discovery
   across the platform bucket of guard-passing names — toolset names and, with this
   change, app names (the dynamic-mode enumerable set the mirror property serves in each
   namespace, the mapping being an optional restriction now — T1-24).
3. **A second workstation user / workstation malware** — on a shared or compromised
   machine: reads the harness's token store, the browser, or the loopback redirect.
4. **A malicious or compromised harness (OAuth client)** — registers legitimately,
   then attacks the AS surface: SSRF-steered CIMD fetches, open-redirect attempts,
   resource exhaustion, token replay.
5. **The host operator / technical support** — legitimate, high-privileged access to
   TB5: can read `.env`, the signing key's injection path, and the DCR store, and can
   rewrite both (T4-6, T4-3). Trusted by design; the trust is disclosed, not proven.
6. **The deployment administrator** — owns Core's configuration (A11) and the
   identity provider: can add identity providers, change `issuerPattern`/`audience`,
   alter `allowedRedirectUris`, administer the provider's realms or tenants and its
   client registrations. Configuration errors here defeat the
   token-trust chain without any code-level attack.
7. **A compromised sibling container on the compose network** — a peer in TB3 that
   turns hostile: sniffs or manipulates the internal plain-http legs (T5-1, T5-2).
8. **The upstream operator** — a third party: sees Core's client on consent, never the
   harness; holds the toolset data — the beneficiary of the E7 code-injection chain's
   exfiltration channel (T3-1, T3-2): a victim's queries and tool arguments execute
   against the attacker's workspace. Not an attacker on this system by assumption;
   named because consent attribution cannot be enforced against it (RES-11).

## 7. Attack-surface entry points

The itemized inventory (`background/design-review.md` §5.1), carried to the system as
it stands — the design review's six entry points **plus the as-built EP7** the running
system adds (the DCR store on its host volume; the baseline extends the §5.1
inventory to the system as built, per the method — the entry-point count is not fixed
at six). Seven entry points; each gets a threat table (§8).

- **EP1 — The gateway's public OAuth and discovery endpoints** behind the plain-http
  front door: E1 per-toolset PRM, the apps PRM route (per-app), E2 flat AS metadata (served at its
  canonical path and at three aliases — the OpenID Connect location and the two
  path-insertion forms — one document, one issuer), E3
  `/dial/authorize`, the `/dial/consent` decision action, E4 `/dial/token`, E10 `/dial/revoke`, and E5
  `/dial/register` (config-gated, default off). The discovery tier is guard-decided and
  registry-independent by the mirror property (any guard-passing name is served its
  document — toolset or app, phantom and real alike, with no Core call), and the flow's
  short-circuit — the one path that mints without an upstream leg — is on this entry
  point's surface (the flow's code issuance at E4): the toolset stored-credential
  short-circuit, and the app kind's unconditional credential-free short-circuit beside it.
- **EP2 — The CIMD fetch**: a server-side fetch of a client-supplied URL, load-bearing
  for registration.
- **EP3 — The browser callbacks E6/E7 and the gateway's HTML pages** (the
  auto-continue interstitial, the consent decision page, and the plain-language
  error/flow pages).
- **EP4 — The signing key and the dedicated custody key**: the host files, the
  gateway's process memory (the two keys, and the identity-provider client secret,
  load-bearing in every deployment), the mint path at E4, the custody decrypt/re-encrypt seam at
  every refresh, and the public JWKS at E8.
- **EP5 — The gateway's server-to-server calls into Core** (the toolset listing read —
  the deployment-listing route `GET /openai/toolsets/{name}`, the one read that carries
  the flow's availability decision, the settings projection, and the per-caller
  statuses — the app read, `POST /v1/ops/toolset/signin`) and the identity-provider
  back-channel — the
  discovery fetch or the operator's directly-configured endpoints, the exchange, the
  refresh grant, the key-set fetch — carrying the live user's identity token, where
  the flow's kind-and-signed-in decisions ride the per-user listing read (and, for
  the app kind, the per-user app read). The listing read's authorization is the MCP
  data path's own — both are Core's deployment resolution of the name against the
  caller's roles — so the flow's availability oracle and the data path's per-call
  check are one decision, never two that can disagree; the bucket-based admin-role
  route the flow read before answered a question the data path never asks and refused
  non-admin users public toolsets the data path serves — the false-denial defect the
  live B2C run exposed, removed by the re-pinning, not priced here. The back-channel leg has two shapes — the
  internal plain-http override (the local shape) and the external internet TLS
  provider (the tested shape) — and two endpoint sources — the provider's discovery
  document, or the operator's directly-configured endpoint trio. (No discovery leg
  exists here: the deleted consult means discovery makes no
  Core call.)
- **EP6 — The front router nginx**: the public `:8090` listener — challenge synthesis,
  path routing, the MCP data-path proxying, and the closed `/.well-known/` namespace (the
  router's fixed JSON `404` for every unserved well-known path, below every served
  location, with Core's two protected-resource templates forwarded to Core on their raw
  spelling only).
- **EP7 — The DCR store on its host volume**: one JSON file, parsed at startup,
  written on registration (atomic replace), present only if DCR is enabled (default
  off).

## 8. Threat tables

Structure per the vendored instruction, exactly: attack surface entry point for the
component, attack type category (leaf-level, full path), attack type name, target
sensitive footprint of the asset, what is being compromised, attack type description.
Flow and logic flaws classify under Use Control Misconfiguration with the leaf chosen
by what the attacker gains and the flaw named in the description
(`docs/security-analysis.md` §5.4). Mis-use cases are marked **[mis-use]**.

### EP1 — public OAuth and discovery endpoints

This entry point's surface now carries the consent/attribution checkpoint's action
(`POST /dial/consent` on the browser-facing side) and the redirect-URI scheme admission
rule at the registration and resolution sites. Neither is a new entry point: the
consent action is one more route on the same unauthenticated AS surface, bound to the
flow id its siblings ride, and the admission rule is a validation clause at the
registration sites the surface already has. Its delta rows land below beside the
surface's own.

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP1 (E4, and MCP calls via :8090) | Interception → Eavesdropping | Token harvesting off the wire | A3, A4 on the plain-http front door | C | The token-endpoint responses and every `Authorization: Bearer` header cross `:8090` in cleartext; a party that can read that traffic holds a replayable bearer identity for that `sub`. |
| EP1 (the 401 challenge; E4) | Interception → Spoofing of the target (Man in the middle) | Challenge and response manipulation | A8, A3, A5 | C, I | A network-level man in the middle rewrites the challenge's `resource_metadata` to a hostile AS and phishes the user's identity-provider credentials at the proxy leg, or substitutes token responses at E4. Requires the plain-http transport (RES-12) or a router compromise (T6-1). |
| EP1 (E4 refresh; the data path) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Stolen-token replay | A3/A4 in the harness token store or on the wire | C, I | A token stolen from the harness store (or sniffed, T1-1) is replayed by another party: refresh at E4 and toolset calls as that `sub`. Cross-toolset replay included — a token minted for one toolset's resource is valid on every Core endpoint for its `sub` until `exp` (marker-level audience binding only, RES-7). |
| EP1 (E3/E4) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Toolset / leg confusion (OAuth mix-up) | A6 per-`sub` credential binding | I | Mix-up flaw: a code or token issued under one toolset's `resource` is exchanged or used under another's — attempting to bind the wrong toolset's credential or consent to a user. Bounded by the strict, required `resource` check at E3 and E4 and the refresh-time resource match; the token endpoint's resource match is what enforces the presented token's resource binding (the presented token's audience must contain the addressed resource, else `invalid_target`), and the same match governs the app shape under its own guard. |
| EP1 (E3) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Open redirect via `redirect_uri` | A5 (the gateway's code) on the final redirect | I | Open-redirect flaw: a `redirect_uri` outside the registration delivers the authorization code (and echoes state) to an attacker-controlled endpoint. Bounded by registration-bound exact-match validation with the loopback port rule keyed on the registered entry. |
| EP1 (E3; E5 when enabled) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Unauthenticated state allocation | A14 (flow records; DCR records) | A | An unauthenticated caller opens `/dial/authorize` (or registers, when DCR is on) in a loop, allocating flow/registration records until memory or the cap is hit. |
| EP1 (E4, E10) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Token-endpoint flood | A14 (shared worker pool) | A | A flood of token/refresh/revoke requests within the rate limits queues legitimate legs behind the attacker's requests on the bounded shared worker pool (RES-4). |
| EP1 (E3/E4/E10) | Use Control Misconfiguration → Denial of Service → Crashing | Malformed request crafting | A14 | A | Malformed JWTs, PKCE parameters, JSON bodies, or oversized fields crafted to break parsing or validation paths. |
| EP1 (all) | Injection | Log injection into the audit trail | A9 | I | Caller-controlled request fields (client id, redirect URI, resource, toolset) smuggled into the audit trail as free-form content, forging or corrupting the operator's record. |
| EP1 (HTML error pages) | Injection | Reflected content execution | A5, A8 in the user's browser | I | Flow context or registrant text reflected unescaped into an HTML error page executes in the user's browser mid-flow (XSS), hijacking the flow continuation. |
| EP1 (E5, when enabled) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Registrant attribution impersonation **[mis-use]** | A9, consent attribution on the interstitial | I | A legitimate DCR registration (the feature used exactly as permitted) supplies a `client_name` impersonating another organization; the interstitial then displays false attribution. Accepted with the flag's default off (RES-5). |
| EP1 (data path) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Own-token cross-toolset replay **[mis-use]** | A3, A6 | Access (own scope) | A legitimate user's token minted for one resource is used, by that same user, against their other proxied resources — within their own authorization, but outside the per-resource binding the flow implies (RES-7). Widened **cross-kind** by this change: a token minted for one kind's resource is Core-acceptable on the other kind's data path — an app-resource token against a toolset, or a toolset token against an app — because Core's provider entry checks the marker only (verified: no per-resource audience match exists on either MCP path); the gateway's own resource checks refuse the cross-shape presentation at the token and refresh endpoints, but Core's data paths carry no such check to widen. |
| EP1 (E4) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | AS mix-up at the token endpoint | A3 (a gateway token minted on a foreign issuer's artifact) | I, C | A code minted by a different authorization server is presented at E4 (the cross-AS mix-up axis — T1-4 is the per-toolset axis); if accepted, the attacker's AS becomes the unseen issuer behind a gateway token. Collapsed by the single-issuer flat-AS shape and the self-contained code's embedded bindings (`client_id`, `redirect_uri`, `code_challenge`), all enforced at redemption. |
| EP1 (E3) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Pre-registered client impersonation **[mis-use]** | A9, consent attribution on the interstitial | I | A legitimate user's local process presents a known pre-registered `client_id` (e.g. the flagship harness's) with its own loopback redirect; the interstitial and the audit then attribute the flow to the named harness. No client authentication exists by design (public PKCE clients) — reachable in the default shape; the reward is false attribution, not anyone else's access, and the audit chain attributes to the acting user regardless of the label worn (RES-11). |
| EP1 (E4 refresh; the data path) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Stale-claims access token used after role revocation/downgrade **[mis-use]** | A6 per-`sub` credential binding; A3's claim set — the authorization decision's data | I (claim fidelity), Access beyond current authorization | Claim-staleness flaw (a logic/flow flaw, named in the description per the classification convention; the leaf follows the attacker's gain — access beyond current authorization): an already-minted access token carries its claims to its own expiry, so a user whose roles were revoked or downgraded at the IdP keeps toolset access only until that token expires — at most the access TTL. The mint at refresh re-reads the current claims from the identity provider's fresh token, so a revoked role is gone from minted tokens within the access TTL; there is no snapshot to outlive the window. Core's per-call DIAL authorization still runs, on those claims (the residual interval is RES-6). Primary actor: the legitimate business user presenting their own still-valid token — the flow used exactly as permitted. Secondary: the token thief — a stolen token retains its claims up to its own expiry, compounding RES-7/RES-8. |
| EP1 (E4 refresh) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Refresh cadence keeps the IdP session alive **[mis-use]** | A8 (the user's SSO session); A3 | I (session lifetime), Access | Session-lifetime flaw: presenting the session-bound refresh token refreshes the identity provider's session idle timer, so a harness refreshing on its own schedule keeps the user's SSO session alive after all browser activity has ended — the gateway becomes a session keepalive its user never chose, and the user's "walking away" no longer ends their identity session on the idle timescale. Bounded by the provider's SSO Session Max (an absolute, non-sliding cap — the local development instance's default is 10 h), the gateway's own non-sliding refresh window, and the fact that explicit revocation still propagates immediately at the next refresh. Accepted as disclosed — RES-22. |
| EP1 (E4 refresh) | Injection | Crafted custody blob | The custody claim's envelope and the custody seam (the decrypt-and-check path) | I (custody integrity), C | The presented refresh token's custody claim is attacker-controllable ciphertext: a caller who holds or crafts a refresh token can substitute, truncate, or splice the blob, hoping the decrypt path leaks state, accepts a foreign plaintext, or serves an oracle. Bounded by construction: AES-256-GCM is an AEAD with no padding (no padding-oracle class), the tag check fails closed on any tamper, the version/key-id are looked up in a fixed keyset with the algorithm pinned in code constants (the M20 lesson applied to our own encryption — nothing envelope-selected), the nonce is gateway-chosen at encryption and never attacker-supplied, and the seam's `sub`/`exp` checks refuse misplaced or stale blobs. The refusal class is audited with its own fixed-vocabulary reason (`custody_decrypt_failed`). Mitigated — M21. |
| EP1 (the issued refresh token, in the harness's token store) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Grown refresh token overflows a harness token store | A4 (the refresh token); the user's refresh capability | A | Dependency-capacity flaw: the custody claim grows the refresh token into the multi-KB class, and harness token stores are not governed by any RFC size guarantee — the store class that hurts is real (OS keychain/credential-manager stores carry hard item-size limits; the Windows Credential Manager's 2560-byte blob bound is canonical). A token too large for its harness's store breaks the session silently, far from its cause — the user's availability, not the gateway's. Bounded by the provider-token size bound refused loudly at sign-in (the failure lands at the one moment its cause is diagnosable), the re-priced body cap, and the live two-harness round-trip gate before adoption; the accepted remainder is every harness store beyond the two field-proven ones — RES-23. |
| EP1 (the flow, the signed-in short-circuit) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mint-without-consent surface widens to non-OAUTH kinds | A3's claim set; the toolset resource's token audience (A4); the establishment path's integrity | I (authorization fidelity), Access (bounded) | The mint machinery — unchanged in itself — is newly reachable for toolsets of every kind, on a path where no upstream consent and no credential establishment ever ran: where the signed-in check passes (honestly, or by the forged answer priced at T5-7), the flow mints a gateway token addressed to the toolset's resource without the consent leg. The bounds are the stage order and the credential model: the DIAL authorization check (the per-user listing read) still runs before the short-circuit; the mint's `sub` is the identity-leg user's own; the short-circuit never reads or transits any upstream credential (Core injects the stored one on the data path — never-cut 1); and where the status answer was honest, a stored credential exists, so the mint is exactly the repeat-sign-in case the flow already had. Where the answer was forged (no stored credential), the minted token yields 401s on the data path — a misleading token and a diagnosable loop, not access. Mitigated — M23. |
| EP1 (the flow, a GLOBAL credential) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Global credential silently widens the served surface **[mis-use]** | The toolset's upstream access (through the global credential); every ACL-permitted user's token audience | I (the consent's absence), Access (as configured) | An administrator's ordinary ops action — storing a GLOBAL-level credential for a toolset through Core's own API — silently changes gateway behavior for every user: each ACL-permitted user's next sign-in short-circuits with no consent screen, and the toolset becomes harness-able through the gateway front door. A legitimate privileged act, used exactly as permitted, rewarded with a behavior change the gateway never separately approved. Bounded and accepted as design: the administrator's configuration IS the authorization decision, in Core's own credential model — the same semantics the deployment already runs when the same admin stores a global key for a model or an application; the access is not new (the same user reaches the same toolset through Core's own paths with a primary-provider token); the minted token carries only that user's claims and dies at the access TTL; and Core's per-call authorization runs on every call. The gateway states the delegation (the flow *uses* a global credential, it never *establishes* one) and records the short-circuit on the audit trail, not re-approving Core's own configuration decisions. Accepted as design — M23. |
| EP1 (the apps PRM route) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Apps-namespace discovery enumeration **[mis-use]** | The deployment's app inventory (public discovery) | C | The mirror property's price in the second namespace: with no apps restriction configured, the enumerable set on the gateway's unauthenticated apps discovery route is every guard-passing app name. It names nothing the deployment's unauthenticated tier did not already name — Core's own apps tier is likewise registry-independent (the same `toolsets.security` configuration serves it; a phantom app fetch against Core's metadata route earns the echo document), so existence is decided one leg deeper, post-authentication, on both sides of the front door. A row of its own, not an amendment of the retired status-enumeration row (T1-15): its surface is an **unauthenticated discovery route** — the mirror property's class — never an authenticated read. Bounded: the apps restriction option pins the set back where an operator wants to, and the route stays inside the shared limiter. Accepted as design — the inventory disclosure is inherent to serving dynamically in the second namespace (the restriction and the mirror property bound it). |
| EP1 (the app short-circuit mint) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mint-without-consent is unconditional for the app kind | A3's claim set; the app resource's token audience (A4); the establishment path's integrity | I (authorization fidelity), Access (bounded) | The mint machinery — unchanged in itself — is reachable for a whole resource kind on a path where no upstream consent and no credential establishment could ever run, by construction: for an app resource the flow mints after the identity leg and the app read, full stop. The whole-namespace extension of T1-21's class, with the structural difference stated: no stored-credential predicate exists at all. The bounds are the stage order and the identity model: the DIAL authorization check (the per-user app read, refused on 403) runs before the mint on every path; the mint's `sub` is the identity-leg user's own, provider-asserted; the minted token carries only that user's claims; Core's per-call authorization runs on every apps data-path call; and the access TTL is short. There is no forged-status variant to price — the app short-circuit consumes no status at all (T5-7's app-side counterpart does not exist; the app read's forgery is T5-8). Mitigated — M25. |
| EP1 (the flow's authorization entry point, `/dial/authorize`) — **T1-25, re-priced in place (DT-EP1-4)** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Drive-by client hijacks the flow via the app path's zero-page short-circuit | A3 (a minted bearer token naming the victim's `sub`); A4 (the refresh token the same redemption yields); A8 (the victim's live IdP session); A10 (the attacker's own DCR registration) | I, Access | A client registered through CIMD on an operator-allowlisted origin — its `redirect_uris` pointing at a collector the attacker controls — crafts an `/dial/authorize` link and induces a victim with a live IdP session to click it. The identity leg completes silently: the gateway relays nothing client-identifying into the IdP leg, so the IdP cannot name the harness client to the user. **This change widens exactly that surface**: the app kind's unconditional short-circuit completes the flow with **zero user-visible pages of any kind** — no consent screen, no interstitial, nothing naming the client the mint is about to serve — a variant that would not exist without this change, and the row's subject by the method's own letter; the toolset flow's stored-credential short-circuit, pre-existing, is the same class's other member, named for context. The code lands on the attacker's registered redirect, and the attacker redeems it with their own verifier, holding a gateway token **as the victim** (the refresh token with it, custody ciphertext included — inert without the custody key, bounded by the session lattice). PKCE, `state`, and single-use codes bound the interception class, not this one — the attacker holds every binding legitimately. The standing control is CIMD allowlist curation (the naming control, **M7**'s origin-allowlist surface — the control set the CIMD fetch's SSRF discipline lives in), and the standard remedy is a consent/attribution checkpoint naming the resolved client and resource. **Disposition: mitigated — M31** (this change's consent/attribution checkpoint, the deferred-to-mitigated flip the roadmap item C2.5 — AS security hardening — carried as its seed). The mitigation: the checkpoint sits **after the identity leg and before every mint, on all three mint paths** (the app kind's zero-page short-circuit, the toolset stored-credential short-circuit, and the toolset consent branch), consulting a per-(subject, client) approved-client registry and prompting only on the **first** attribution of that client to that user — so the drive-by shape meets a gateway-owned decision page where nothing rendered before, and the mint does not run without the user's act. What the mitigation does **not** claim, stated honestly: the **on-path shape** (an attacker with wire access reading the flow id off the callback and racing the victim's click) keeps **RES-12/RES-1**'s existing acceptance — that attacker already reads A3/A4 directly off the wire (T1-1, a strictly cheaper attack than racing a decision), so the checkpoint changes nothing about what that attacker holds, and the drive-by shape is the checkpoint's declared scope; the **mis-named-registration shape** (a legitimate registration naming another organization's product) is priced at **DT-EP3-3**'s re-priced display-level bound (RES-11), the naming controls staying where they were (M7's allowlist curation; the DCR flag's default-off, RES-5). |
| EP1 (`POST /dial/consent`) — **DT-EP1-1** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Forged approval advances an unattributed flow | A3/A4 (the mint the approval unleashes — a code and tokens delivered to the flow's registered redirect); A8 (the victim's session the flow rides) | I, Access | The attacker seeks the one thing the mint now requires: an approval recorded for a flow whose attribution the victim never made. Two shapes. **Cross-site POST:** the forger posts the approve action from a hostile page — but the gateway sets no cookies and holds no ambient browser authority, so the POST carries nothing the gateway trusts beyond its own parameters, and the flow id it must name is 128-bit CSPRNG, server-side-held, never visible to a link-crafter (it crosses only the victim's browser, on the provider redirect and the callback — the same binding M1's state round-trip gives both callbacks); a forged POST without a live flow id lands on the expired-flow page and allocates nothing. **On-path race:** an attacker reading the wire (the plain-http front door, RES-12) sees the callback URL carry the flow id and races the victim's click — bounded by the existing transport residual's own acceptance: that attacker already reads A3/A4 directly off the wire (T1-1, a strictly cheaper attack than racing a decision). The approve action's single-use-per-flow rule (D3) bounds a replayed approval to one mint, and a replayed POST against an advanced flow lands on the expired-flow page. Mitigated — the flow-id binding as the control, with the on-path race priced at RES-12's existing acceptance. |
| EP1 (`POST /dial/consent`; the registry) — **DT-EP1-2** | Use Control Misconfiguration → Denial of Service → Resource Consumption | Approval-registry flooding | A14 (the registry's memory; the process) | A | An unauthenticated caller tries to grow the registry directly. There is no direct write path: the only write is the approve action, which resolves a live flow whose identity leg completed — so every entry costs a full sign-in under the flow store's existing bounds (rate limits, flow cap, TTL — M6), and the registry's own hard cap with oldest-first eviction bounds the store against the slowest *legitimate* growth there is (real users approving real clients); eviction re-prompts (fail-safe), never bypasses. An attacker completing real sign-ins as themselves to grow the registry spends their own sign-ins for entries keyed to their own subject — no other user's path is affected. Mitigated — the cap-and-eviction control. |
| EP1 (the registration admission sites — the DCR body check, the CIMD document check, the pre-registered settings, the DCR store load) — **DT-EP1-5** | Interception → Eavesdropping | Non-loopback `http` redirect delivers the authorization response over a cleartext leg | A5 (the gateway's code, and the echoed client `state`) on the redirect leg to the registered target; A8 (the session the flow rides) | C | The B-1/B-3 grounding: no admission path validates a redirect URI's scheme as built, so a non-loopback plain-`http` collector registers and passes the exact-match rule untouched — and the authorization response (the code and the echoed `state`) is delivered to it over a cleartext leg any on-path party reads. The read alone does not mint: the code is PKCE-bound to the client's verifier (M2), so an on-path reader without the verifier holds an unusable string — but the leg is the front door's own transport class (RES-12) extended one hop past it to a target the rule can refuse, and the chain closes where the reader also holds the verifier (a compromised-client shape — the attacker model's class 4, with T1-3's stolen-token pricing) or where the registrant is the drive-by attacker and the cleartext collector is the exfiltration channel riding a registration the contract already forbids. Closed by D11's admission rule (M32) — `https` or loopback-`http` only, at all four admission sites, so no such registration exists to deliver to; **no new residual**: the on-path class keeps RES-12's existing acceptance, and the loopback exception keeps the fielded harness population's own local-listener shape. |
| EP1 (the code grant's replay handling) — **DT-EP1-6** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Replayed code refused but its token family survives | A4 (the refresh token the first redemption minted); A3's session continuity | I, Access (beyond detection) | RFC 9700 §4.2.4's own scenario: a stolen code redeemed twice — one redemption succeeds, the other is the detection. As built the detection is answered (the replay cache refuses the replay) but consequence-free: the refresh token the first redemption minted stays live to its own expiry, so a thief's session outlives the moment its theft was observed. The shapes: the thief must hold the verifier too (PKCE — a compromised client or leaked pair, the attacker model's classes 3/4 with T1-3's pricing), or be the drive-by attacker whose own registration mints legitimately (T1-25's shape, for whom this is one more containment beside the checkpoint); the legitimate client losing the race to a thief is already alerted by the refusal. Closed by D12 (M33): the replay memo's `code_id → refresh_jti` field plus one `TokenDenylist.revoke` call at the detected replay — the thief's refresh capability dies at the observation, refusing at its next presentation through the denylist consult every refresh grant already makes. **Two partials disclosed as the clause's bound:** the access token ages out unrevoked (M9's standing TTL bound, which the SHOULD tolerates), and an already-rotated refresh successor survives (no code_id→successor map — bounded by the detection's timing and the non-sliding absolute expiry; the chain-tracking memo is the recorded extension, not built). Mitigated to the clause's stated bound — M33. |
| EP1 (E8, the JWKS; E4 verification) — **DT-EP1-10** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Crafted JWT steering verification across the keyset | A3/A4's verification basis (which key verifies what) | I | T4-7's class, extended to the keyset: a crafted token's header tries to steer verification — a `kid` naming another entry, embedded `jwk`/`x5c` material, an `alg` confusion. The pinned-algorithm requirement's controls carry unchanged and per-entry: the algorithm is pinned (all entries RS256 — the keyset adds no algorithm), embedded header material is ignored, and the `kid` **selects within the startup-fixed keyset** — an unknown `kid` (including a removed retained entry's, the immediate cut's own verification-side effect) refuses as not issued by this gateway. The provider leg's resolution rules are untouched (its own key set, its own pin). Mitigated — the existing M20 discipline, re-stated per-entry by this change's amendment (M34); no new residual. |
| EP1 (E4, the mint during a rotation window) — **DT-EP1-11** | Use Control Misconfiguration → Denial of Service → Resource Consumption | Rotation-window verification gap at Core | A3's usability at Core (freshly minted tokens 401ing until the cache turns) | A | The availability shape the pre-publish rule exists to close: without it, every token minted in the first Core-JWKS-cache-window after a key activation 401s at Core — a rotation-visible refusal burst, and (mis-used) a rotation scheduled at the wrong moment degrades every new session for the window. Mitigated by the pre-publish rule (the new `kid` published ≥ the cache window before it signs — a spec'd scenario), rehearsed by the drill's "no refusal attributable to the rotation" verdict (M34, M36); the residual is the operator's declared cache bound being wrong (a Core-side cache TTL longer than declared), which the drill's observed wait bounds and the change's open question records. |
| EP1 (the discovery routes and `/dial/authorize`'s resource resolution) — **DT-EP1-12** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Encoding-aliasing restriction evasion | A6 (the operator restriction's admission decision); the flow record's resource identity | I | A caller offers a non-canonical spelling of a restricted path (`%78` for `x`, an over-encoded UTF-8 sequence) hoping the restriction's membership check sees a different string than the flow later serves, admitting a resource the operator excluded. Closed by the canonical encoding (M37): the restriction's membership is decided canonical-vs-canonical, so every accepted spelling of one resource meets one verdict. Mitigated — M37. |
| EP1 (the discovery routes and `/dial/authorize`) — **DT-EP1-13** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Resource-identity confusion across spellings | The token audience / the refresh grant's resource match (the resource identity) | I | Two spellings of one resource (`a%2Fb` with the `%2F` decoded and merged, mixed-case hex escapes) resolve to different flow records or different audiences on different surfaces, letting a token minted for one spelling be presented as another resource — an MCP mix-up variant. Closed by the canonical identity (M37) and the segmentation-precedes-decoding order it pins. Mitigated — M37. |
| EP1 (the discovery routes' document build) — **DT-EP1-14** | Injection | Header and page injection via encoded forbidden characters | The 401 challenge header's value (router-synthesized, quoted); the HTML pages' interpolated content | I | A resource path carrying `%22`/`%7D`/`%01` decodes to `"`, `}`, or a control character — breaking the challenge header's quoting or the pages' structure if the guard checked the encoded form instead of the decoded one. Closed by the decoded forbidden-set refusal (the guard refuses `{`, `}`, `"`, and any character ≤ U+001F after decoding, never the encoded form), plus the router's challenge built only from its own fixed template and a grammar-conforming capture. Mitigated — M38; the page-interpolation half rides the existing T3-4/DT-EP3-1 escaping class, proven for path-shaped inputs (task 3.6). |
| EP1 (the discovery routes, unauthenticated) — **DT-EP1-15** | Use Control Misconfiguration → Denial of Service → Resource Consumption | Path-shape flood | A9 (the audit trail's volume); A14 (the guard's CPU per request) | A | An unauthenticated caller loops long, deep, guard-failing paths — each writing an audit record and costing guard CPU — at a rate the limiter admits but the per-request cost amplifies. Bounded by the byte cap (≤ 900 decoded UTF-8 bytes) and the segment-count cap (`RESOURCE_PATH_MAX_SEGMENTS`, default 32), which bound every guard input before work proportional to it, and by the existing per-source and global limiter (M6/M9). Mitigated to its bound — M39. |
| EP1 (`/dial/authorize`'s `resource` parameter) [mis-use] — **DT-EP1-16** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Foreign-bucket path as a resource | A6 (the flow's listing read); the mint | I | A signed-in user names another user's bucket path (a ciphertext they obtained legitimately, e.g. from a shared listing) as the `resource`, seeking a token minted over a resource the data path would refuse them. Mitigated to Core's standing control — the mis-use shape of never-cut 3, now reachable by path: the bucket segment is client-visible data Core itself hands out, and isolation is Core's `hasReadAccess` chain on the listing read (a 403 refuses the flow before any upstream round-trip and before any mint) — the same decision the data path makes per call. The instrument's user-bucket row asserts the refusal live. Mitigated — never-cut 3 preserved; no new residual. |
| EP1 (E2's path-insertion aliases) — **DT-EP1-17** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Suffixed-issuer mix-up at the path-insertion aliases | The issuer identity the RFC 9207 `iss` check binds to (A3/A5's mix-up defense) | I | Mix-up flaw: an alias at `/.well-known/oauth-authorization-server/{suffix}` that echoed the suffix as its `issuer` would assert an issuer identity (`{origin}{suffix}`) no token or authorization response carries — a client keying its per-AS state by issuer would see one server as many, and its RFC 9207 check would fail against the emitted `iss` or be pushed off. Closed by construction: every alias answers the canonical document from the one builder, `issuer` the public origin always (M43). |
| EP1 (E2 at the OpenID Connect location) [mis-use] — **DT-EP1-18** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | OpenID Connect relying party mis-binds the gateway as an OpenID Provider | A3 (a gateway access token presented as an identity assertion) | I | "OAuth for authentication" flaw: a lenient relying party discovers the gateway at `openid-configuration`, treats it as an OpenID Provider, and — with no ID token — accepts a gateway access token (or its `sub`) as proof the user signed in to it; a token minted for another client or resource then logs its presenter in as that user. Bounded: the document advertises no OpenID Provider member, so a conforming relying party refuses the provider (M43); the access token's audience is `[resource, dial-mcp-proxy]` (M9), so the misuse also needs a relying party that skips audience validation. Newly reachable, but bounded: an OpenID Connect–only relying party never fetches `oauth-authorization-server`, so the OpenID Connect location newly exposes the gateway to this class; the misuse needs a relying party that an operator configured to trust the gateway as an OpenID Provider, that skips ID-token validation (no ID token is ever issued), and that skips audience validation (M9) — three conformance failures in a component outside this deployment. |
| EP1 (E2's alias family, unauthenticated) — **DT-EP1-19** | Use Control Misconfiguration → Denial of Service → Resource Consumption | Alias-family request flood | A14 (the gateway's worker pool) | A | Three more unauthenticated paths serve the metadata document, two with an arbitrary suffix; a caller floods them, varying the suffix to defeat any cache in front. Bounded to the canonical route's cost — one static document, no Core call, no record, no state (M43) — with the suffix length bounded by the router's stated request-line buffer (M15) and the rate by the router-level bounds (T6-6). |

### EP2 — the CIMD fetch

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP2 | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Server-side request forgery | A11, internal services on TB3 (core:8080, keycloak:8900, link-local metadata) | C, Access | SSRF flaw: the client-supplied client-id URL steers the gateway's fetch at internal addresses — reading internal responses or probing the internal network through the gateway. |
| EP2 | Use Control Misconfiguration → Denial of Service → Resource Consumption | Slow-fetch pool holding | A14 (shared worker pool) | A | The one unauthenticated caller-steered slow leg: fetches aimed at slow or stalling targets hold worker-pool capacity; bounded by the CIMD capacity limiter, with the residual queue-wait disclosed (RES-4). |
| EP2 | Injection | Fetched-document content injection | A5/A9 attribution on the interstitial; the CIMD cache | I | Fields from the fetched metadata document (notably `client_name`) rendered into the interstitial, or a poisoned cached document, inject content into the attribution display or the flow. |
| EP2 | Use Control Misconfiguration → Denial of Service → Crashing | Malformed metadata document | A14 | A | An oversized, non-JSON, or structurally hostile document crafted to break the fetch/parse path. |
| EP2 (registration resolution) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Attacker-chosen redirect URIs via CIMD | A5 (the harness-leg code) | C | An allowlisted origin the attacker controls (or compromises) serves a metadata document whose `redirect_uris` point at the attacker, making their URIs "registered" — on this path the fetched document *is* the registration, so T1-5's registration-bound validation bounds to what the attacker published. Bounded by allowlist curation (RES-17's revisit rule) and, for the cleartext-delivery shape, by the redirect-URI scheme admission rule (the client-registration requirement's amendment, M32): a document carrying a non-loopback plain-`http` entry is refused whole, so the attacker's collector must be `https` or loopback — the admission-class threat itself is tabled once at EP1 (DT-EP1-5), the rule's home. |
| EP2 (the fetch's connection) | Interception → Spoofing of the target (Man in the middle) | DNS rebinding / fetch MITM | A11 (the fetched document's content) | I | Between validation and connection the resolved address could change (rebinding), or an on-path attacker impersonates the origin, so the document validated is not the document served. Killed by connection pinning to the validated address with Host/SNI preserved, plus the no-redirects rule (M7). |

### EP3 — browser callbacks E6/E7 and the HTML pages

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP3 (E7) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | E7 code-injection chain — guessing variant | A6 (credential binding per `sub`); A7 (victim's toolset traffic) | C, I | A guessed flow id presented at E7 with the attacker's *own* upstream code makes the gateway call `/signin` with the victim's identity-provider JWT and the attacker's code: Core stores the attacker's upstream credential under the victim's `sub`, and the victim's queries and tool arguments execute against the attacker's workspace — an exfiltration channel. Killed by 128-bit CSPRNG flow ids, the upstream `state` round-trip, and destroy-on-first-use. |
| EP3 (E7) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | E7 code-injection chain — interception variant | A6; A7 | C, I | The same chain, entered by *intercepting* the victim's identity-provider callback URL off the wire (it carries the provider's code and the flow id as `state`): the attacker delivers it to the gateway ahead of the victim's browser, passes the flow lookup, and completes the upstream consent in their own browser. The defense trio kills guessing, not interception; the control is transport security, absent today (RES-1). |
| EP3 (E6/E7 URLs) | Interception → Eavesdropping | Callback-URL interception | A5 (codes, flow id) in the callback URLs | C | The E6/E7 callback URLs carry the identity-provider code, the upstream code, and the flow id across the plain-http front door. Each code alone is PKCE-bound (to the gateway's and to Core's verifier respectively) and useless to the interceptor; the exploitable remainder is the identity-token path — the interception variant above. |
| EP3 (interstitial, error pages) | Injection | Attribution/context injection | A5, A8 in the user's browser | I | Registrant-supplied text or flow context rendered unescaped on the interstitial or an error page executes in the user's browser and hijacks the auto-continue that advances the flow. |
| EP3 (interstitial) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Framed flow advancement (UI redressing) | A8 (the victim's IdP session), A5 | I, Access | The attacker frames the auto-continuing interstitial in a victim's browser: its meta-refresh advances the upstream authorization leg inside the attacker's page with the victim's identity-provider session — a consent the victim never saw. |
| EP3 (interstitial navigation) | Interception → Eavesdropping | Referer leakage of the callback URL | A5 (code + flow state) to the upstream's page and scripts | C | The interstitial renders at the identity provider's callback URL and navigates onward to the upstream's authorize endpoint; a default `Referer` on that navigation hands the provider-issued code and the flow state to the upstream's page and its third-party scripts — a cross-party leak. |
| EP3 (E6/E7) | Use Control Misconfiguration → Denial of Service → Crashing | Crafted callback parameters | A14 | A | Crafted `state`/`code`/error parameters against the callback handlers, aiming at lookup or parse failures. |
| EP3 (any flow page, replayed) | Use Control Misconfiguration → Denial of Service → Crashing | Cached-page stale resubmission | A5 (a stale flow's parameters) | I, A | A cached interstitial or flow page replayed after its flow died resubmits a stale flow's parameters, desynchronizing or flooding the flow path. |
| EP3 (the interstitial, plain http) | Interception → Spoofing of the target (Man in the middle) | On-path rewrite of the auto-continue | A5, A8 (the upstream authorization request the browser receives) | I | With no TLS on the front door, an on-path attacker rewrites the interstitial's continuation target — the delivered upstream request (which carries Core's client, the public challenge, the flow id) — redirecting the consent leg to an attacker-controlled AS. The control is TLS on the public origin, unplaced today (RES-12). |
| EP3 (E6/E7) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Callback flood | A14 (flow lookup; the shared worker pool) | A | A loop of garbage callbacks spends lookups and pool occupancy on the public surface — the callbacks' share of the unauthenticated-flood class, distinct from T1-6 because no record is allocated (the lookup fails). Bounded by the public-endpoint abuse limits; unknown-flow callbacks resolve to nothing (M12). |
| EP3 (the decision page) — **DT-EP3-1** | Injection | Attribution/context injection into the decision page | A5 (the flow's continuation); A8 (the victim's session); the approval decision itself | I | Registrant-supplied text (`client_name` via CIMD or DCR) or caller-path-derived text (the resource name) rendered unescaped on the decision page executes in the victim's browser at the flow's most credential-adjacent URL (the provider's code is on the page's own URL) — an XSS here forges the approval click, strictly worse than the interstitial's equivalent (T2-3/T3-4's class) because the forged click is a *decision*, not a notice. Bounded by the same construction the interstitial already carries: the escape on every interpolated value, the page built through the one shared builder so the CSP family (`default-src 'none'`, script excluded) is inherited by construction, and — new for this page — **`form-action 'self'`** confining the form's submission to the gateway's own origin (D3). The decision page joins the header-assertion tests, so the family cannot drift off it. Mitigated — M8's family (with `form-action 'self'`) through the one builder. |
| EP3 (the decision page) — **DT-EP3-2** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Framed approval (UI redressing) | A8 (the victim's session); the approval decision | I, Access | The attacker frames the decision page in a victim's browser and harvests a click — the framed click approves the attribution, the T3-5 class (framed flow advancement) relocated onto a decision. Killed by the same pair the interstitial carries: `frame-ancestors 'none'` + `X-Frame-Options: DENY`, inherited from the family by construction (M8), and asserted by the same test battery. The auto-continue dimension of the T3-5 class is *absent here by design*: the decision page does not navigate itself (no `meta refresh` — D3), so a frame buys one click at most, against a page that renders nothing clickable outside the two buttons. Mitigated — M8's framing pair, with the no-auto-continue rule removing the T3-5 auto-advance dimension. |
| EP3 (the decision page, registration naming) — **DT-EP3-3** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | False attribution on a decision page **[mis-use]** | A8; the approval decision; A9 (the attribution record) | I | The T1-11/EP1 family (registrant attribution impersonation) with raised stakes: pre-change a false `client_name` misinforms (display-level, RES-11's acceptance); on a decision page a false name *harvests an approval* — a legitimate registration (the feature used exactly as permitted) naming another organization's product collects user trust the registrant did not earn. Bounded but not eliminated, honestly: the page presents the name as a name, not a verified fact (the interstitial's existing discipline), beside the **client id** and the **registered `redirect_uri`** — the two facts the registrant cannot falsify to the page's advantage (the redirect is the registration's own validated value; a collector URL reads as one). **Disposition: accepted at RES-11's display-level bound, re-priced for the decision context — the page's verifiable-facts rule (the control above) is the compensating bound;** the naming controls stay M7's allowlist curation and the DCR flag's default-off (RES-5). |

| EP3 (the upstream consent leg) [mis-use: operator] — **DT-EP3-4** | Use Control Misconfiguration → Denial of Service → Resource Consumption | Allowlist migration gap | A14 (every consent flow's completability) | A | An operator applies the allowlist change or the repair procedure partially — the gateway's callback absent from `aidial.toolsets.security.allowedRedirectUris`, or the dynamically-registered toolsets unrepaired so the upstream never registered the callback — so the consent's code returns to a callback the upstream does not have registered, or the exchange fails at Core's allowlist check: a silent-for-the-operator outage whose failure shape is far from its cause. Fail-closed by Core (an unlisted `redirect_uri` fails the exchange; the worst case is unavailability, never a mis-delivery). Mitigated — the three-callback runbook states the procedure and its ordering, with its per-toolset consent probe as the detective step (M40). |

### EP4 — the signing key (the identity-provider client secret joins the custody class, load-bearing in every deployment)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP4 (host file) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Signing-key theft from the host | A1 (the private key); every identity on the deployment | C, I | The key is a file on the host (`.env`-injected) today: whoever reads it mints tokens for any `sub` with any roles, including admin, valid on every Core endpoint — the key-compromise blast radius (`background/design.md` §6.2): *use* of other users' toolset access, never *theft* of their upstream tokens. Custody is the host/volume boundary (RES-13). **Re-stated for the keyset:** the signing material is a keyset with per-entry sources — `env` (an injected environment variable) or `file` (a PEM on a read-only mount), both implemented, `kms` a reserved value refused — and active/retained roles, so the key's custody is the *injection path* (the env-var surface, or the read-only key-file mount on the pod's mounts), and a `file`-sourced entry's material rests where the mount does. The thief class is unchanged; the file source's at-rest footprint is priced at DT-EP4-4 (inside RES-13's class), the retained window the keyset adds at DT-EP4-2. |
| EP4 (process memory) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Key read out of a memory dump | A1, A2 in process memory | C, I | The key and the in-flight identity token live in managed-runtime memory for the process lifetime; a process dump or host-level read extracts them. The identity token's post-lift life is the sharper half — the realm's `accessTokenLifespan` is 24 h, so a lifted token authenticates as that user for up to a day after the flow that justified it is gone. No reliable wipe-on-demand exists (RES-2). |
| EP4 (host file, mint path) | Injection | Key or mint-path tampering | A1, the token-minting path | I | Host-level write access replaces the key material or the injection path with attacker-chosen material — the same boundary the DCR store is trusted to; a well-formed substitution mints attacker identities under the deployment's own issuer. |
| EP4 (E8 as consumed by Core) | Interception → Spoofing of the target (Man in the middle) | JWKS trust-path manipulation | A11 (the IdP entry's `jwksUrl`), the Core↔E8 path | I | Controlling what JWKS Core fetches — by configuring `jwksUrl` elsewhere, or by standing between Core and E8 — controls which keys Core accepts as the gateway's, and therefore controls identity acceptance. The path is internal plain http today (RES-19). |
| EP4 (E8, `/healthz`) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Unauthenticated endpoint floods | A14 | A | Floods of the public JWKS or health endpoints. Trivial, read-only, cacheable surfaces. |
| EP4 (TB5 access, used as permitted) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Host-operator key exfiltration **[mis-use]** | A1, A10, A12 | C | The host operator / technical support uses legitimate host access exactly as granted to read or copy the signing key, the DCR store, or `.env`. Trusted by design; the trust is the disclosed host boundary, not a control. |
| EP4 (E4/E10 verification) | Injection | Crafted JWT against verification | A3/A4 (the gateway's token-acceptance decision) | I | Attacker-crafted JWT headers — algorithm confusion, embedded-`jwk`/`x5c` headers, `kid` values steering key lookup — are the injection route into the verifier: persuading the library to verify with attacker-chosen key material. The gain is control of the token-acceptance decision (an integrity compromise), not a crash — that is T1-8. Killed by pinned-algorithm verification with the gateway's own key passed directly, so header material never selects key material (M20). |
| EP4 (process memory) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Custody-key compromise and transient plaintext | The dedicated 256-bit custody key (a second persistent secret in the signing key's custody class); the transient plaintext of the presenting sessions' provider refresh tokens; the encrypted claim at rest in harness token stores (A4/A17) | C, I | The process holds one custody key and, during each refresh grant, the decrypted provider refresh token of only the session presenting at that moment — never a per-session store, so a same-window compromise reads the key plus the presenting sessions' plaintext and the minutes-bounded pending hand-off entries (one per completed-but-unredeemed flow), not every live session's credential at once. The genuinely new capability is the **time-decoupled conjunction**: an attacker who archives refresh tokens (each carrying the ciphertext, by design) in one incident and compromises the custody key in a later one can decrypt the archive and replay each archived user's provider identity — tokens DIAL itself accepts on its own endpoints — for as long as the provider's session policy allows each session to live. Bounded by the IdP session clock (SSO Session Max; Entra's ~24 h public-client bound — the archive dies with the sessions) and, **where enabled**, the provider's rotation reuse detection (the gateway's own next refresh races a lifted string and the chain is revoked for both — the containment control for the credential-on-the-wire exposure of plain-internal-leg deployments; deployments with TLS'd internal legs are bounded by the transport, the detection defense-in-depth there); strictly harder to assemble than a same-window whole-store read, and the honest shape of the price (RES-21, part ii). The key alone grants no upstream credential and no other user's identity; the mint-any-identity blast radius remains the signing key's own, unchanged. Mitigated to its bound — M21; the time-decoupled conjunction and the process-compromise floor accepted as RES-21 (parts ii/iv), the managed-runtime memory floor as RES-2. |
| EP4 (process memory; the `.env` slot) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Client-secret compromise | The identity-provider client secret (A18 — the third persistent secret in the signing key's custody class, load-bearing in every deployment: always on the token leg's wire, always in process memory, per the 2026-11-05 ruling); the host `.env` at rest | C, I | The secret's holder can authenticate the gateway's identity-leg client to the provider — exchange codes, run refresh grants for tokens they hold — but can mint nothing at the gateway (no signing key, no custody key) and reach no upstream credential; in the challenge-on mode a leaked secret alone still cannot spend an intercepted code (the exchange also requires the gateway-held verifier), so the challenge remains a real second binding there — but the secret is no longer optional anywhere: the ruling removes the no-secret deployment exposure class the prior public-client design permitted (recorded as removed-by-ruling). At rest the secret is a `.env` entry (the committed placeholder empty — the never-cut-6 pattern, delivered as an environment variable from the deployment's `.env`, never argv, never a gateway-read file); in process it is a `SecretStr` with no `repr` — the same custody class as the existing client-secret slot it renames, unconditionally load-bearing, which is why its asset row (A18) is in the table. The KMS/secret-management move is the recorded C3 scope. Mitigated to its blast radius — M28; the `.env`-class custody accepted. **The file spelling (the owner-pause amendment):** the secret MAY be delivered by environment variable (`IDP_CLIENT_SECRET`) or by a read-only mounted file (`IDP_CLIENT_SECRET_FILE`) — both supported, exactly one configured, the both-configured case refusing startup naming both settings — and the file spelling's at-rest footprint is DT-EP4-4's class exactly (same boundary price, new location); the secret's presentation and never-logged discipline are the ones this row states, whichever spelling delivers it. |
| EP4 (the retained signing key, at rest or in memory) — **DT-EP4-2** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Retained signing key extends the stolen-key mint window | A1 (the superseded private key); every identity on the deployment (the mint it forges) | C, I | The priced cost of routine rotation: pre-change a stolen signing key's mints die at the rotation — the old `kid` vanishes from the JWKS and Core refuses within its cache; post-change a superseded key **retained** for the drain window keeps its `kid` published, so the thief's mints verify at Core for up to the whole window (default: the refresh TTL) instead of ≤ cache + access TTL. The thief is the same attacker T4-1/RES-13 already price (host/injection-path read); the change extends *how long the stolen material stays useful*, not who can steal it. Bounded by: the window is operator-declared and ends at the drain bound (the refresh token's non-sliding absolute expiry); the **immediate cut** is available at any moment (remove the entry — the JWKS drops the `kid`, Core refuses within cache + access TTL, the gateway refuses at next verification); and the drill rehearses the cut so the response is proven, not documented. Accepted as the priced trade of "routine rotation must stop being a mass signout" — the disclosed-residual register re-prices it at RES-13 and RES-21; mitigated to its bound — M34, M36. |
| EP4 (the retained custody key, at rest or in memory) — **DT-EP4-3** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Retained custody key extends the decrypt window | A2 (the superseded custody key); the carried provider session refresh tokens of outstanding refresh sessions | C (the blobs' contents), I (the provider identities they authenticate as) | The custody twin of the row above, with its own blast radius (RES-21 part ii's conjunction): a stolen retained custody key, with a recorded archive of refresh tokens, decrypts their carried provider session refresh tokens and replays each user's provider identity until that provider session dies — pre-change the hard cut killed the decrypt ability at rotation; post-change it lives for the drain window. The conjunction is unchanged (the key alone mints nothing; the token archive alone is inert ciphertext); the change extends the window in which the conjunction can be assembled. Bounded by: the same operator-declared window and immediate cut (remove the entry — outstanding blobs refuse at next presentation, the custody refusal class); the envelope's subject binding (a decrypted blob is bound to its signed subject, so the replay is per-user, never cross-user); and the self-shortening overlap (every presenting session re-seals under the active key, shrinking the retained-key-bearing blob population at each refresh). Accepted as the priced twin of the row above; mitigated to its bound — M34, M36; re-prices RES-21 part ii. |
| EP4 (a `file`-sourced key or secret, its read-only mount) — **DT-EP4-4** | Information Disclosure → Information Disclosure at Rest | Key or secret file read off its mount | A1/A2 (the entry's material at rest, before the process loads it); A18 (the IdP client secret, the one secret outside the keysets, under its `IDP_CLIENT_SECRET_FILE` spelling) | C | The new at-rest footprint: file-sourced material — a keyset entry's key, or the IdP client secret under its file spelling — rests on a mount where the injection-path boundary, not the gateway, governs readability. Whoever reads the mount holds the material, the same holder class the env-var surface prices (the pod spec, the node, `/proc` environ); the file adds the volume/node reader for that entry. Not a new boundary — the same host/pod class RES-13 and RES-5 price — but a new *location* the contract must name so the operator knows where the boundary sits; the IdP secret's file spelling is this row's class exactly (same boundary price, new location — the amendment that added it extended this row rather than adding one). Bounded by: the contract's read-only-mount statements for every file-sourced secret (a K8s Secret mount's default ownership is the cluster's, stated); the startup discipline (load once, never log, refuse loudly on an unreadable path); and the mount's read-only-ness stated as an assumption the assembly preserves (a writable key mount is a tamper path priced at DT-EP6-1). Mitigated to the injection-path boundary's existing price (RES-13's class, re-stated for the new location) — M34, M35; no new residual. |
| EP4 (the keyset document, at parse) — **DT-EP4-5** | Injection | Forged or malformed keyset document | A1/A2's loading path (the process's key selection); the startup refusal path | I | A keyset document is operator-supplied JSON parsed at startup inside the trust boundary being configured — the settings-injection class the model already prices (T5-3's family), with the new surface being the entry schema. A malformed document refuses startup loudly (the existing validators extended per-entry); a *forged* document means the injection path is already compromised, which is the boundary's own price, not the parser's. Bounded by: per-entry validation with named refusals (zero-active, multi-active, duplicate derived `kid`, unreadable file, reserved `kms`), no material in any error, and the derived-`kid` duplicate check — the one check that makes the document's claims about *how many keys it holds* checkable rather than trusted. Mitigated — M34. |
| EP4 (the retained-entry lifecycle, operator behavior) — **DT-EP4-6** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Indefinite retention **[mis-use]** | A1/A2 (the retained entries' windows, kept open) | C, I | The mis-use of the retention mechanism: an operator who rotates routinely but never removes retained entries accumulates a growing set of hot superseded keys — each one a live stolen-key window (the two rows above), and the keyset's memory/at-rest footprint grows with them. Nothing forces removal; the drain bound is declarative. Bounded by: the operator reference's procedure stating removal as the rotation's closing step (the drill's own final leg removes the entry — the rehearsed procedure includes the cleanup); the startup validation refusing duplicate derived kids (the accumulation stays honest about its size); and D3's one-keyset-one-JWKS rule keeping the published set exactly as large as the configured one — an operator reading the JWKS sees every retained `kid` the deployment is carrying. Accepted as operator discipline, stated in the contract and the reference; re-opened by an automated-rotation future (which would carry its own removal scheduler). |
| EP4 (the `kms` reserved value, at startup) — **DT-EP4-7** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Silent source fallback **[mis-use, falsified by design]** | A1/A2's sourcing (the entry's claimed protection) | I (the operator's security model) | The falsification target the fail-closed refusal exists to kill: a deployment configuring `source: kms` today believes it holds KMS-protected key material; a gateway that silently ignored the value (or fell back to env) would let that belief run a process whose key is actually env-injected — a security *model* compromise, not a key compromise, and exactly the failure the ruling's "cleanly rejected, naming the gap" forbids. Mitigated by construction: the startup refusal names the gap and the implemented sources; the reserved value is schema-carried so the future real `kms` is additive, never a reinterpretation of the refusal — M34. |

### EP5 — server-to-server calls into Core and the identity-provider back-channel

The back-channel leg's two shapes: the internal plain-http override (the local shape —
a compose-network peer) and the external internet TLS provider (the tested shape); and
its two endpoint sources: the provider's discovery document, or the operator's
directly-configured endpoint trio (which replaces discovery whole — the direct mode
carries no provider-asserted input and no fetch).

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP5 (gateway → Core) | Interception → Eavesdropping | Identity-token sniffing on the internal leg | A2 on `http://core:8080` | C | The live user's identity-provider JWT is presented to Core over internal plain http (at most two presentations per flow — the listing read and, where the flow establishes a credential, the credential call). A hostile peer on the compose network reads it and holds that user's DIAL identity until the JWT's own `exp` — up to the provider's own access-token lifespan (24 h on the local development realm); the flow TTL bounds the gateway's *retention*, not the token's life. The mis-use half: the gateway itself over-presenting beyond the flow's decision step and credential call — bounded by the token-use rule (RES-3), a purposes rule, not an enforced count. |
| EP5 (gateway ↔ Core / ↔ identity provider) | Interception → Spoofing of the target (Man in the middle) | Internal-leg man in the middle | A2, A5 (the `/signin` body), A11 (toolset listing answers), A3 (on the forgery chain) | C, I (worst case: mint-any-`sub`/any-role issuance) | A network-level attacker impersonates Core or the identity provider to the gateway: capturing the identity token and the upstream code, or forging the toolset listing answer so the upstream consent leg is redirected to an attacker's AS. The sharper gain is on the identity-provider legs: the token exchange and the JWKS fetch both ride the provider's back-channel — locally `http://keycloak:8900`, gateway-outbound, plain http — so a MITM peer answers the exchange with a forged id_token and the JWKS fetch with the matching hostile keys — `iss` matches (attacker-chosen), the signature verifies against the attacker's own key set, roles are read from the forged token — and the gateway mints a token for **any `sub` with any roles, including admin**: the signing-key blast radius (`background/design.md` §6.2) reached from a compose-network peer position (TB3, attacker 7) instead of the host (TB5), with no victim required — the attacker drives their own flow. The refresh-grant leg joins the class: a MITM peer on the plain-http token-endpoint leg serves an attacker-chosen token response (plus the matching hostile JWKS) and the gateway mints it — any claims for that `sub`, the gain narrowed to any-claims-for-an-existing-`sub` by the mandatory `sub` cross-check (the forgery cannot mint for another user — the refresh token's `sub` is the gateway's own signed claim), and the same leg exposes the **decrypted provider session refresh token** the grant presents once per gateway refresh — the most powerful credential the flow ever puts on the wire, renewable by use on providers with sliding session semantics. The internal legs are plain http (RES-19, re-priced with both gains stated). |
| EP5 (settings → URLs/pages) | Injection | Settings-field content injection | A5 (the built upstream authorize URL), A8 | I | Toolset public-settings fields (endpoint, `code_challenge`, scopes) are built into the upstream authorize URL and the interstitial. The source is Core's operator-owned configuration, not a caller — the guard is strict URL building and loud failure on malformed values, not input trust. The read now also carries the toolset's authentication kind and the caller's per-caller statuses, and it is the **toolset namespace's** existence decision (discovery answers phantom names a document by the mirror property; the app read is the apps namespace's existence decision the same way): a forged not-found on this leg is a denial of one servable toolset's flow — the same shape, the same leg, and the same internal-leg trust as the forged kind — named here rather than left to inference. |
| EP5 (`/signin`) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | GLOBAL-level escalation attempt | A6 at GLOBAL level | Access | Attempting to establish a GLOBAL/app-level credential through the flow. The flow never *establishes* at GLOBAL level — it signs in at USER level on every establishing path, and the credential call stays at USER level; GLOBAL-level establishment is admin-gated in Core and stays an operator action. A GLOBAL credential's *use* through the signed-in short-circuit is the operator-configured delegation, not an escalation the flow performs: the flow reads no stored credential and the access is the same the same user already holds through Core's own paths (RES-9). |
| EP5 (dependency on Core / the identity provider) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Upstream-dependency stalls | A14 (flow records held by stalled legs) | A | Core or identity-provider unavailability stalls in-flight legs; the gateway fails closed and the flow TTL (10 min) bounds the records held. |
| EP5 (upstream/Core/identity-provider responses) | Use Control Misconfiguration → Denial of Service → Crashing | Hostile upstream response | A14 | A | Error bodies, malformed JSON, and unexpected statuses from Core, the identity provider, or the upstream AS reach the gateway's parsers mid-flow; an unhandled shape crashes the single instance (RES-15). Bounded by schema-validated, size-capped response parsing and the per-call timeouts. |
| EP5 (gateway → Core, the per-user app read) | Interception → Spoofing of the target (Man in the middle) | Forged app answer steers the flow | A11 (Core's app registry as the flow reads it); A14 (the user's time) | I, A | The app read carries the apps namespace's existence decision and the authorization decision on one internal leg, and a compose-network peer in a MITM position can forge either: a forged 404 or 403 denies a servable app's sign-in (a denial of one flow, self-inflicted by whoever controls the leg); a forged 200 for a phantom app mints a gateway token addressed to a resource that does not exist — a misleading token whose data-path calls yield 404/401 at Core, not access. The trust basis is the existing one — the internal leg from the configured Core, authenticated by the user's own identity token — the same trust that already carries the toolset listing read's projection the flow builds URLs from (a peer who can forge the app read can already forge the entire toolset projection, T5-7's acceptance class, RES-19). No answer this leg returns can make a phantom app's data path answer anything but an error. Mitigated to the internal-leg bound — RES-19's class, extended to one more leg. |
| EP5 (gateway → Core, the per-user listing read) | Interception → Spoofing of the target (Man in the middle) | Forged signed-in answer mints without an upstream leg | A3's claim set; the toolset resource's token audience (A4); the establishment path's integrity | I, Access (bounded) | The signed-in check's trust basis, priced: a compose-network peer in a MITM position on the per-user listing read forges a SIGNED_IN status (user or global) for a toolset whose credential is not stored, and the flow short-circuits — a gateway token minted with no consent leg and no credential establishment. What makes the answer trustworthy is nothing the gateway can verify independently: it is the internal leg from the configured Core, authenticated by the user's own identity token — the same trust that already carries the settings the flow builds its URLs from, so a peer who can forge the status can already forge the entire projection and the credential call's endpoints (the existing forged-settings chain, RES-19's acceptance). The gain is bounded by everything else the flow checks: the mint's `sub` is the identity-leg user's own (no cross-user minting); the DIAL authorization read still ran as that user; and the minted token without a stored credential yields 401s on the data path — the upstream is never reached, so the forgery buys a misleading token and a diagnosable loop, not toolset access. Same boundary and same acceptance class as the forged-settings threat — the internal-leg residual, extended to one more member of the same Core answer, the listing route its latest member; no new residual is opened. The read's own authorization is the data path's deployment resolution, so the false-denial defect the prior admin-role availability read carried — refusing non-admin users toolsets the data path serves — is removed by the re-pinning, not accepted here. The read's refusals are four distinguishable classes on the page and the audit trail — no-access (403), unknown-toolset (404), the **trust fault** (401: Core could not validate the sign-in's identity token — an authentication failure whose remedy is the operator's check of Core's provider entry for the identity provider, its issuer pattern, key set, or audience, or that key set's reachability), and the deployment fault (unreachable or unreadable) — where the prior mapping collapsed the 401 into the no-access class; the wrong-class diagnosability defect the second live B2C run exposed — a trust fault rendered and audited as an access denial, undiagnosable because Core logs no record of its 401s — is **removed by this change's refusal-class split**. The forged-answer residue keeps the acceptance unchanged: a forged 401 costs one flow, the same as a forged 404. Mitigated to the internal-leg bound — RES-19's class. |
| EP5 (the discovery fetch) | Interception → Spoofing of the target (Man in the middle) | Forged discovery document steers credential-bearing calls | The discovery document and the endpoints it names; the code, the carried session refresh token, and the client secret that ride the calls it steers; A3's claim set | C, I (worst case: mint-any-`sub` via a hostile key set) | A network-level attacker between the gateway and the provider (DNS poisoning, on-path MITM, a hostile resolver) serves a discovery document whose `token_endpoint`/`jwks_uri` point at the attacker, so the next exchange delivers the code — and the client secret, presented on every token request in both toggle positions (the 2026-11-05 ruling) — to the attacker's endpoint, and the matching hostile key set verifies the forged token the attacker returns: the mint-any-`sub` chain of the internal-leg MITM threat (T5-2), relocated from the compose network to wherever the discovery fetch is answered. Bounded by the validation the document is trusted only within (M26): the document's `issuer` must equal the configured issuer exactly (a document claiming the right issuer while naming wrong-origin endpoints is refused whole), every used endpoint must share the configured issuer's or the override's origin (an off-origin `token_endpoint` is refused — the document cannot steer calls anywhere its own issuer does not live), plain http is refused without the explicit override, redirects are not followed, and the response is size-capped. What remains is the TLS-bounded residue every HTTPS client carries: an attacker who defeats transport validation on the issuer's own origin was already able to impersonate the provider's token endpoint directly, with or without discovery — the RES-19 acceptance's external-TLS narrowing case. Mitigated — M26. Absent in direct mode, which carries no provider-asserted input — no document, nothing to forge. |
| EP5 (the discovery fetch) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Discovery-fetch amplification off the public surface | A14 (the shared worker pool); the provider's discovery endpoint | A | The `/dial/authorize` surface is unauthenticated and an identity-leg redirect needs the discovered authorization endpoint, so an unauthenticated caller could try to spend discovery fetches. Bounded by the cache (M27): at most one fetch per TTL per process however many requests arrive — a validated document serves its window, and a failed or refused fetch is recorded for the same window and served from it without re-fetching, so the bound holds while the provider is unreachable or its document refused as well — and the request rate itself is bounded by the limiter the authorize surface already joins — the fetch rate is min(rate limit, 1/TTL) in the success regime and in the failed one alike — and the identity legs' own fetches are the legitimate ones the cache already serves. Mitigated — M27. Absent in direct mode, which fetches nothing. |
| EP5 (the exchange and refresh grant, challenge-off mode) | Interception → Eavesdropping / Spoofing of the caller's identity | Intercepted identity-leg code exchanged by the interceptor | A5 (the identity-leg code on the callback URL); the client secret; A3's claim set | C, I (the mint's `sub`) | With the PKCE challenge disabled on the identity leg — an explicit operator opt-in for a provider that cannot support it — the binding that made an intercepted identity-leg code unexchangable by its interceptor is gone — the callback-URL interception class (T3-3/RES-1, the class both callbacks share; the identity-leg callback is E6, the upstream's is E7), now on the identity leg's own code. The control is inherent, not mode-conditional: the gateway is a confidential client at the provider (the 2026-11-05 ruling), so the exchange requires the client secret in both toggle positions — the interceptor does not hold it, and the intercepted code is spent by the gateway first or refused as `invalid_client` whichever way the toggle is set. The residue: on a plain-http front door an on-path attacker reads the code (and the callback URL), and the secret is the only remaining bar — a strictly weaker position than challenge+secret against a secret-holder. The mode stays an explicit operator opt-in (the toggle default-on); the secret's presence is guaranteed in every mode by the startup refusal. Accepted — RES-24; re-opened by TLS-fronting the public origin or the mode's retirement. |
| EP5 (verified claims, varying-issuer providers) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Another journey's token accepted by a relaxed issuer match | A3's claim set (the `sub` and roles the mint copies); the configured issuer's authority | I, Access | A provider whose issuers vary by sign-in journey mints each journey's tokens under that journey's issuer; a "helpful" implementation matching the issuer by prefix, tenant, or templated pattern would accept another journey's token — a token whose claims were minted under a different journey's claim configuration, possibly looser roles wiring — and mint a gateway token from it. Refused gateway-side by construction (M29): the issuer check is exact-string against the configured issuer (the one federated sign-in journey's), and the discovery document's `issuer` is validated against the same value, so no document and no token can widen the pin. The distinguishability precondition is provider configuration, not construction: a sibling journey's token is refused *as a different issuer* only where the provider issues journey-distinct issuers — the operator prerequisite the configuration reference states; where the provider shares one issuer across its journeys, the sibling's token carries the configured `iss` and no issuer check, exact or relaxed, can distinguish it — the deployment must enable the provider-side journey-distinct issuance where that is a provider setting, which is why it is carried as a stated prerequisite rather than priced as a mitigation. Mitigated — M29. |
| EP5 (the identity leg, direct endpoint configuration) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mistyped or swapped endpoint in the direct configuration **[mis-use]** | The code, the carried session refresh token, and the client secret that ride the mis-addressed calls; A3's claim set | C, I | In the direct-configuration mode the operator's three endpoint URLs steer every credential-bearing call, and a mistyped or swapped value — a wrong host, a stale copy-paste, a value that reaches the setting by accident — delivers the leg's credential material to a host the operator did not mean. There is no provider-asserted input in this mode, so the forged-document chain (T5-9) cannot exist — no document, nothing to forge — and no fetch exists to amplify (T5-10's class absent with it); what steers the calls is operator input at the same trust level as the configured issuer itself, which already anchors everything the leg trusts. Bounded (M30): HTTPS (no plain leg without the override's explicit ownership), the all-or-nothing startup validation that refuses partial or malformed sets loudly, and the fixed-vocabulary operator-facing leg failures a wrong host produces at first use — a credential-bearing call to a wrong origin is a deployment misconfiguration in the same accepted class as the override's own trust claim (RES-19's operator-claim acceptance). Accepted as the operator's explicit trust claim, bounded by M30. |
| EP5 (the identity leg, direct endpoint configuration) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Stale directly-configured endpoint after a provider change | A14 (the sign-in surface's availability) | A | The provider moves an endpoint; in discovery mode the change propagates within the cache TTL (M27), but in direct mode nothing propagates it — every leg against the moved endpoint fails with the fixed-vocabulary operator-facing error until the operator updates the setting. The failure shape is the existing fail-closed leg failure, and the residue is the mode's priced, documented trade: the operator owns endpoint freshness, stated in the configuration reference and the direct-configuration requirement itself, so the staleness bound is a named operator responsibility rather than an undisclosed window. Mitigated to its bound (fail-closed, no fallback construction — M30); the staleness accepted as the mode's documented trade. |
| EP5 (the listing read / app read URL build) — **DT-EP5-4** | Injection | URL structure injection into the Core read | A11 (the Core route the flow's authorization decision rides on) | I | A caller-derived path concatenated raw into the read URL could steer the request off `/openai/toolsets/…` into another Core route (path confusion inside Core) via dot-segments, empty segments, or encoded separators. Closed by construction: the read URL is built only as `fixed-prefix + canonical-encoding` — the path is guard-validated and canonically re-encoded before the URL is built, never concatenated raw from a caller substring (the grammar refuses dot-segments and empty segments, the steering shapes). Mitigated — M37. |
| EP5 (the credential call's body) — **DT-EP5-5** | Injection | JSON structure injection via the `url` member | A6 (the credential call's target resource) | I | The decoded resource path is caller-derived and now longer and richer than a name; a malformed decode or an unencoded member could alter the JSON body's structure and name a different toolset than the flow's resource. Closed by construction: the body is JSON-encoded by the existing client (a decoded string with quotes or braces cannot break structure — and the guard refuses `{}"` anyway), and the member carries the decoded form of the guard-validated path; unit rows assert a path with every legal punctuation survives the round-trip byte-identical. Mitigated — M37/M38. |

### EP6 — the front router nginx

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP6 (the 401 rewrite; the config) | Interception → Spoofing of the target (Man in the middle) | Challenge redirection to a hostile AS | A8 (user credentials at the proxy leg), A5 | C, I | A compromised or misconfigured router points the challenge's `resource_metadata` at a hostile AS: the harness is phished into it, and the user's identity-provider credentials are entered on the attacker's page; the router can also tamper the data path. The rewrite's integrity is part of the authentication protocol (it is why the challenge-synthesis form delivers *only* the gateway's challenge). |
| EP6 (the routing map) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Path-capture misrouting | A13; the AS/data-path split | Access, A | A resource path whose FIRST segment is a reserved AS name (`authorize`, `token`, `callback`, …), or a map the guard's surfaces resolve differently, captures another surface's traffic: MCP traffic hits the gateway, or AS traffic hits Core. Bounded by the startup reserved-name check mirroring the router's alternation (now a first-segment rule), the authorization-surface locations ordered before the data-path prefix locations, and the raw-URI map's end-anchored whole-request-URI match domain (the `/mcp` suffix required, nothing after it but the optional query — M39). No regex is parameterized by any name: the router's half is the static `map $request_uri` segment grammar and the gateway's half is the decoded path guard (M38). The class names the **apps map** beside the toolset one: its own end-anchored `map $request_uri` grammar over the disjoint `/apps/` prefix (no interaction with any `/dial/` alternation) bounds app-path capture the same way, the app guard mirroring the same decoded per-segment rules. |
| EP6 (the data-path locations) | Use Control Misconfiguration → Denial of Service → Crashing | Query-string loss | A7 (streamable-HTTP sessions, `?sessionId=…`) | A | nginx's automatic query-string behavior on variable `proxy_pass` drops `?sessionId=…` on MCP GETs, breaking every streamable session — an availability break of the data path, invisible to the gateway. Bounded by the explicit `$is_args$args` pass-through (a measured router behavior), carried over verbatim to the apps location so a streamable session on the apps path resumes identically. |
| EP6 (the apps map and location) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Apps routing, challenge synthesis, and query pass-through | A13 (routing and challenge integrity); A7 on the apps path | I, A | The apps prefix location `~ ^/apps/` proxies to Core's deployments MCP path on the target the `map $request_uri` `$apps_target` yields, and carries the toolset location's whole discipline re-derived: the end-anchored whole-request-URI segment grammar over the raw URI (`…/mcp` required, nothing after `/mcp` but the optional query — the map yields the empty string and the location's `if` refuses 404 on any non-match, so nothing is forwarded), the disjoint `/apps/` prefix (no interaction with any `/dial/` alternation), the `$is_args$args` query survival, and the `proxy_hide_header` + second-`$status`-keyed-map challenge quoting the **app's** own metadata path. A map the guard's app surface resolves differently (a name shape the map routes and the guard refuses, or vice versa), a toolset-shaped challenge on an apps path (or a capture-variable mix-up between the two maps), or a dropped query string each breaks one surface invisibly to the gateway: `/apps/…` traffic hitting the gateway or gateway-owned paths hitting Core; a strict client's sign-in that cannot complete because the challenge names a mismatched resource; every streamable session on the apps path broken. Mitigated — M24 (the disjoint `/apps/` prefix, the shared decoded per-segment rules, the second capture-keyed map, `$is_args$args`, M39); the routing probe battery's apps rows assert each in a gate. |
| EP6 (the gateway's `:8091`) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Router bypass via the container port | A13 (the peer binding) | Access | A request reaching the gateway's container-internal `:8091` directly — never crossing the router — carries a peer identity the router never established, defeating the binding that scopes the gateway's trust to router-fronted requests. The port is never host-published; that is an invariant of the topology, not a request-time check. **Re-stated for the pod:** the gateway's port is unreachable from the host and from outside networks, and it is name-routable on the deployment's own instance network (`mcp-signin-gateway:8091`), where Core fetches the gateway's JWKS — that network is the deployment's own trust domain, required reachability rather than a leak. So a request from outside the pod that the router never accepted cannot reach the port; the non-publication invariant is restated as the pod-contract assumption (the router and gateway sharing one namespace, the gateway's port unpublished and never exposed on the pod's external interface), exercised locally by the namespace-shared composed stack (M16, M35); a pod spec that publishes the gateway port or exposes it on the pod's external interface breaks the per-source rate limit's trust basis — the mis-assembly shape DT-EP6-1 prices. |
| EP6 (the pod assembly, from the contract) — **DT-EP6-1** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Pod mis-assembly breaks the stated assumptions | A13 (the peer binding, the routing, the mounts); A1/A2's injection paths; the DCR store's durability | Access, C, A | The threat the pod contract exists to bound: DevOps assemble the pod from the contract, and the assembly can silently lose what the composed shape carries — the gateway port exposed past the pod (the peer-identity authority broken, T6-4's class relocated: a request that never crossed the router carries a caller-chosen peer identity, and the per-source rate limit becomes a bound the caller sets); the DCR volume dropped (every restart silently invalidates every registered client — the named requirement's own wound) or its backing downgraded to node-local ephemeral storage (the durability requirement satisfied in code, lost in substance — the storage-class requirement's own wound); the conf mounted writable or replaced (T6-1's router-tamper class); the key-file mounts omitted or mis-permissioned (the `file`-source entries refuse startup — loud, not silent); the security context relaxed — a root-running or privilege-escalating container, a capability kept, a writable root filesystem, a world-writable store mount (the fsGroup/uid-10001 ownership the store's integrity leans on refused) — each one a stated control dropped, the same class as the port and the volume; the pod scaled horizontally (split in-memory state — callbacks landing on the other replica's expired-flow page, approvals forgotten per replica — fails safe but confuses; the contract's single-replica statement is what makes the failure diagnosable as a contract violation rather than a gateway defect). Deployment-owned surfaces; the controls are this repo's to *state* and DevOps' to *preserve*: the contract's explicit assumption statements — the security-context section's controls among them (runAsNonRoot with the fixed uid/gid 10001 the store's ownership depends on, fsGroup 10001 on the store's volume, no privilege escalation, all capabilities dropped on the stated no-privileged-port assumption, read-only root with `emptyDir` for the router's temp/log paths, runtime-default seccomp) — the startup refusals that make omission loud where the gateway can see it (key files, store path), the probe battery and restart-survival acceptance that make the composed stand-in prove the shape, and the DevOps review's explicit confirmation — the acceptance evidence the requirement names. Accepted as the deployment boundary's standing price (the compromise table's host row, re-shaped for the pod), with the contract as the named control (M35) and the review as its gate. |
| EP6 (the router↔gateway leg, now pod-localhost) — **DT-EP6-2** | Interception → Eavesdropping | Cleartext on the sibling leg | A3/A5 (the proxied AS traffic between router and gateway) | C | Narrowing, tabled for the walk's honesty: the router→gateway hop ran on the compose network (a sniffable plain-http leg for any network peer, RES-19's class); under the shared namespace it is loopback inside the pod — a network peer can no longer reach it at all. The leg stays plain http (no TLS within the pod — the traffic never leaves the pod's network namespace), which is the same accepting class as loopback everywhere; the *peer population* shrinks from "the compose network" to "the pod's own containers and the node." Mitigated by construction (the namespace sharing is the compose stand-in's own mechanism, M16, M35); the node remains the boundary the compromise table prices. |
| EP6 (the data path) | Interception → Eavesdropping | MCP traffic in cleartext | A7 through the plain-http front door | C | Toolset queries, tool arguments, and results cross `:8090` unencrypted; a party that can read that traffic reads the business data (RES-12). |
| EP6 (the listener) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Router-level floods | A13, A14 | A | Connection floods / slow-client attacks against nginx itself — the standard front-router exposure; the gateway's rate limits bound what reaches it. Streamable-HTTP GETs and SSE hold connections open (`proxy_buffering off` is required by the served protocol), so a fleet of slow clients exhausts the router's connection table and Core's upstream slots — the router is a shared bottleneck no gateway-side limiter bounds; nginx's `proxy_read_timeout` and worker/connection caps are the deployment's tuning. |
| EP6 (config generation from the mapping) | Injection | Toolset-name injection into nginx config | A13 (the router's routing decisions) | I | Toolset names flow into nginx regexes; a name carrying regex metacharacters could alter matching (config injection). The decoded path grammar is enforced at startup on every *configured* restriction entry, and the request-time path guard covers dynamic paths — no metacharacter survives to any regex in either mode (M10). **Re-stated for this change:** the data-path maps contain **no operator-supplied names at all** — the grammar is static configuration and no name ever enters it (the paths are matched, never interpolated into the config), so the injection class stays empty here (M38). |
| EP6 (the data-path map — the new capture) — **DT-EP6-3** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Grammar drift between the map and the guard | A13 (the routing decision — what reaches Core's `/v1/toolset/` prefix) | I | The nginx grammar (a routability filter over the wire form) and the gateway guard (the authority over the decoded form) are asymmetric by design on one documented class — a wire-conforming spelling whose decoded content the guard refuses is forwarded on the data path and refused at discovery/authorize, its challenge dead-ending at a 404 document (same-answer-as-Core). The threat is a divergence *beyond* that stated class: a shape the map routes differently than the guard's surfaces resolve, or a new undocumented asymmetry, which yields a challenge whose metadata document is served for a different identity than the path routes. Mitigated — the division of labor is stated once (the addressing-vocabulary and path-guard requirements), and the **lockstep probe battery** asserts the documented behavior on both sides — the shapes both admit, both refuse, and the asymmetry class itself — negative controls first (M39, M41). |
| EP6 (the data-path map regex) — **DT-EP6-4** | Use Control Misconfiguration → Denial of Service → Resource Consumption | Regex backtracking on crafted paths | A14 (the router's worker CPU) | A | The segment grammar nests quantifiers over overlapping-looking classes; a crafted long non-matching URI could drive catastrophic backtracking, stalling router workers. Bounded by construction: the unreserved class excludes `%`, so the `%XX` alternative is unambiguous and no overlapping alternates exist; brace quantifiers are avoided (nginx rejects them here — the doubled classes stand in); the `large_client_header_buffers 4 8k` bound (stated explicitly in the conf) caps the input length upstream of the regex; and the pathological-URI probe row asserts a fast refusal. Mitigated — M39. |
| EP6 (the refusal `if` and the prefix locations) — **DT-EP6-5** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Prefix-capture leakage beyond the data path | A13 (the boundary between the authorization-surface locations and the data path) | I | The data-path locations widen from anchored single-segment regexes to bare prefix matches (`^/dial/`, `^/apps/`); a crafted path the authorization-surface alternation does not catch but the prefix location does could route MCP-shaped traffic to the gateway or authorization-shaped traffic to Core. Bounded by: the authorization-surface locations remain listed **before** the data-path locations; the map's grammar requires the `/mcp` suffix with nothing after it but the optional query (the match domain is the whole raw request URI), so a prefix-matched path without the suffix — or with a path tail after it — is refused by the `if` with 404; the reserved-first-segment rule keeps the authorization-surface names unreachable as resource paths; and the guard refuses dot-segments so a collapsed path and its uncollapsed spelling cannot disagree. Mitigated — M38/M39; probe rows assert each (`/dial/authorize/x/mcp` reaches the gateway not Core; a dot-segment path under `/dial/` is refused; a post-`/mcp` tail is refused 404). |
| EP6 (the raw forwarding itself) — **DT-EP6-6** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Byte-faithful forwarding of refused shapes (`%2F`) | A11 (Core's request-target) | I | The front door forwards raw bytes including spellings Core itself refuses (an encoded slash inside a segment); the design intends same-answer-as-Core behavior, but if Core's container decoded `%2F` differently than Core's own port front line expects, the front door would become a decoder-bypass oracle against Core. Bounded: the forwarded bytes are exactly what the client sent and exactly what Core's own port would receive — the front door adds no decode step, so it adds no decode discrepancy; Core's auth filter applies to the forwarded request as to any; a `%2F` inside a segment is forwarded raw for Core to answer, same-answer behavior. Asserted by a live probe row (the byte-fidelity rows and the `%2F` row), and the open question records the one cell that could falsify the principle (Core's container answering `%2F` differently through the front door than on its own port). Mitigated to the same-answer claim — M41; re-opened if the probe's `%2F` row diverges. |
| EP6 (the closed-namespace location) — **DT-EP6-7** | Use Control Misconfiguration → Denial of Service → Crashing | Closure shadows the served discovery locations | A13 (the routing decision for every discovery path); every sign-in's discovery step | A | A closure written as a `^~` prefix, or as a regex placed before the protected-resource regexes, answers `404` for every toolset and app protected-resource document and the aliases — every sign-in dead-ends at discovery while the data path still challenges toward those documents. The mis-use shape: a maintainer re-ordering the locations or adding `^~`. Mitigated by the plain-prefix form (nginx uses a plain prefix only when no regex matches; the spec forbids `^~`) and probe rows that fail on any shadowing (M44, M45). |
| EP6 (the Core protected-resource location and the closure) — **DT-EP6-8** | Use Control Misconfiguration → Denial of Service → Crashing | Closure severs Core's own discovery surface | Core's protected-resource routes through the front door (direct-to-Core clients' discovery) | A | A closure covering Core's two templates (`…/v1/toolset/{id}/mcp`, `…/v1/deployments/{id}/mcp`) would `404` the document Core's own challenge points a direct-to-Core client at on this host, breaking the Core-coexistence requirement; a Core release adding a `/.well-known/` route would be swallowed the same way. Mitigated by the end-anchored Core location (M44) and the same-answer-as-Core-direct probe row (M45); the Core-source record names its commit, and a Core release adding a well-known route re-opens it. |
| EP6 (the new locations' match-versus-forward split) — **DT-EP6-9** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Normalized match, raw forward on the new locations | A13 (which upstream and handler a crafted URI reaches) | I | nginx selects a location on the normalized URI (percent-decoded, dot-segments resolved, slashes merged), and a URI-less `proxy_pass` forwards the raw request URI, so one raw URI can select a location while delivering a different raw path upstream. Two directions: (i) a raw spelling normalizes **into** a location it does not literally match — into the Core protected-resource location (`/.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/<t>/mcp`), where Core, matching its templates on the raw path, answers its auth filter's `401` on a namespace path, or into the alias location; a decoded trailing `%0A` before a PCRE `$` is the same shape; (ii) a raw namespace spelling normalizes **out of** the namespace into the catch-all (`/.well-known/unknown/../../v1/x` → `/v1/x`) and reaches Core with a raw `/.well-known/…` path. The attacker hopes to reach a handler a location was not meant to expose, or to get Core's answer on a URL the closure claims. Mitigated by raw-URI checks (M44, the M39 discipline): the Core location forwards only when `$request_uri` itself matches one of Core's two templates, and the catch-all refuses any raw path spelled in the namespace (its leading segment, after any empty or `.` segments, with the separators spelled `/` or `%2F` and percent-escapes read as the characters they encode), each refusal handed to the closure's `404`. Two stated limits, both by the definition and both as the catch-all always behaved: a raw URI whose first segment is outside the namespace (e.g. `/x/../.well-known/…`) is not a namespace spelling and is forwarded raw, and dot segments or `#`/`%23` inside a template's `{id}` are forwarded as Core's own raw template accepts them; the alias regex ends `(/\|\z)`, so a decoded trailing line break does not select it. Behind the gateway locations a raw path reaches only handlers the existing gateway locations already reach by the same mechanism (DT-EP6-5's class): the static alias handler, the guarded protected-resource handlers (M38 refuses dot and empty segments), or the framework 404. Measured in both directions, encoded-dot variants and `%0A` included, by verbatim-path probe rows (M45). |
| EP6 (the router's closed `404`) — **DT-EP6-10** | Injection | Reflected content in the router's 404 | The `404` response's body and headers as a client or browser renders them | I | A `404` echoing the requested path (as nginx's default error page and many framework pages do) would carry attacker-chosen content to whatever renders it. Closed by construction: the body is the fixed literal `{"detail":"Not Found"}` with no variable, typed `application/json`, and no header carries request content (M44); a probe row asserts the exact body across distinct paths (M45). |

### EP7 — the DCR store on its host volume

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP7 (the store file) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Tampered store → redirect-URI substitution | A5 (future harness-leg codes), A10 | C | Host-level write rewrites a registration's `redirect_uris` to the attacker's, making future codes deliverable to them — the code-capture path entered through the volume rather than the endpoint. The store is trusted to the same host/volume boundary as the signing key; the use-path is bounded by redirect validation against what the store says — which the tamper controls (RES-5). |
| EP7 (the store file at startup) | Use Control Misconfiguration → Denial of Service → Crashing | Corrupt store → startup refusal | A14 | A | An attacker (or accident) with host write corrupts the store; startup refuses to run — the corruption path is fail-closed, so the attacker with host access trades nothing for a clean stop of the service. Availability loss bounded by the one-command recovery (rename the file aside, restart). |
| EP7 (the store file at parse) | Injection | Hostile JSON content | A14 (the gateway process at startup) | I, A | Well-formed hostile content in the store (attacker-shaped records) is loaded and trusted; unparseable content fails closed (the row above). The boundary ruling (RES-5) is the defense — inside it, the parse is of owner-trusted material, bounded by the fixed record schema. |
| EP7 (the store's mount, in the pod assembly) — **DT-EP7-1** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Omitted or mis-mounted store volume | A10 (the registered clients); A5 (future codes deliverable to registrations the store carries) | I, A | The named requirement's threat, stated where it lives: a pod assembled without the store's mounted volume satisfies the durability requirement's *code* (the path exists) while losing its *substance* (the path is ephemeral) — every restart invalidates every registered client silently, the exact wound the roadmap's owner-catch recorded. Bounded by: the contract's volume-mount section naming the mount as a MUST (the deliverable DevOps review accepts against — M35); the restart-survival acceptance running on the pod-shaped stack (a registered client's cached id keeps working across a restart — the omission cannot survive the acceptance); and the existing corrupt-store and load-path refusals (an empty-but-present store self-heals via re-registration, the spec'd behavior). The store's own host/volume boundary is unchanged from RES-5's price — the same readers, the same no-secret content; the change re-states it for the pod and makes its omission visible. The governance statements extend the row without a new threat: the cloud-backed persistent-volume requirement (the data survives node loss, rests in a tenant-governable resource — never node-local ephemeral storage) is the durability requirement's own substance, and the external governance reader class it admits — storage-layer RBAC holders, backup destinations reading a point-in-time copy, which the store's atomic-replace single-file shape makes a consistent export with no gateway cooperation — is a **bounded reader extension of the same boundary**: the store's no-secret-content property is the control that makes those readers cheap to admit (a reader of the store holds registrations, never credential material), and the property is stated load-bearing — the store MUST NOT gain secret-class content without re-opening this boundary analysis. The future wrapped-CEK file is the volume's named future second resident, ciphertext by design — the same logic, stated now so the reader class survives its arrival. Mitigated — M35. |

## 9. Mitigations, per threat, in the fixed control-category order

Working paper per the method (`docs/security-analysis.md` §5.5); the reviewed result is
the grouped list (§12). Every category appears for every threat; "not applicable"
names the threat-specific property that defeats the category. Homes: **spec** = the
`mcp-signin` capability spec (gateway-owned behavior, normative); **Core config** = the
instance's Core settings (deployment owner); **deployment** = the deployment owner's
surface; **repo** = committed material in this repository; **upstream** = the upstream
operator. Every "Placed — spec" home was verified against the current synced spec
(`openspec/specs/mcp-signin/spec.md`) in the D2 reconciliation; the four elements that
reconciliation found repo-only — M9's RFC 9207 `iss`, M11's per-flow records, M20's
verification hygiene, and M10's toolset-name charset (then a one-segment
`^[a-z0-9-]+$`, **re-based by this change** onto the decoded per-segment path rules —
the fourth missed by that verification and caught by the review round) — are placed
**spec** as of
2026-10-30 (the `pin-implemented-security-behaviors` change, archived); the elements
left un-pinned by owner decision (the CIMD fetch's content-type/timeouts/User-Agent, and
the outbound timeouts and bounded response parsing) remain **repo** — see §12's
placement notes.

### T1-1 Token harvesting off the wire
1. Reduce Attack Surface — the front door is one origin, one port; the AS surface is
   the minimum the harness class can discover (spec; repo). Does not remove the wire.
2. Isolation — not applicable: the vector is traffic on the public leg, which no
   network isolation control can close; the front door exists to receive it.
3. Authentication — not applicable: the harvested artifact *is* the authenticator
   (a bearer token); no second factor exists on the data path by design.
4. Authorization — bounding: 10-minute access TTL and the 8-hour non-sliding refresh
   bound replay; refresh rotation + denylist-by-`jti` kills rotated-token replay
   (spec). Accepted remainder: within the TTLs (RES-7, RES-12).
5. Data Protection — **the control**: TLS-front the public origin, so the tokens never
   cross in cleartext. Home: deployment (the transport layer owns TLS); today unplaced
   — accepted (RES-12).
6. Anti-Injection — not applicable: nothing is injected; the artifact is read.
7. Anti-DoS — not applicable: a passive read consumes no gateway resource.
8. Detective controls — bounding: the audit trail's fixed-vocabulary token-endpoint
   records make replay-grant patterns visible to the operator (spec); no anomaly
   detection is built.

### T1-2 Challenge / response manipulation (MITM)
1. Reduce Attack Surface — the challenge names one configured origin (never `$host`),
   and the synthesized form removes every upstream header from a 401 (repo, router
   config) — the MITM's raw material on the challenge is reduced, not removed.
2. Isolation — not applicable: the attack rides the public client leg, which must
   remain public.
3. Authentication — the user's identity-provider login is the falsification point: a hostile AS
   cannot mint a token Core accepts (the identity provider and the gateway are the only accepted
   issuers; Core config). Bounding, not defeating: credentials are phished *before*
   issuance.
4. Authorization — not applicable: the flaw precedes any authorization decision.
5. Data Protection — **the control**: TLS-front the public origin; a TLS-fronted
   origin gives the interceptor nothing to rewrite. Home: deployment; today unplaced
   (RES-12).
6. Anti-Injection — not applicable: the manipulation is of routing/metadata, not
   executable content in the gateway.
7. Anti-DoS — not applicable: the manipulation rewrites one flow's challenge and responses in transit; the attack's cost is the MITM position, not any gateway resource.
8. Detective controls — the audit trail records the per-flow authorization-server use;
   a phished user surfaces as a flow that never reached the gateway (operator-visible
   gap). Bounding (spec).

### T1-3 Stolen-token replay
1. Reduce Attack Surface — tokens are minted only after a live IdP authentication of
   that `sub` and the flow's DIAL authorization check; never offline (spec; Core
   config: no `offlineClient`).
2. Isolation — not applicable: the replayed token crosses exactly the boundaries it is
   entitled to cross.
3. Authentication — the token *is* the authentication; PKCE binds issuance to the
   legitimate client's verifier, so the thief never holds a code (spec).
4. Authorization — every replayed call still runs DIAL authorization in Core for that
   `sub` (Core config; never-cut 4): the thief gets the victim's own access, nothing
   wider.
5. Data Protection — short TTLs are the bounding control: 10-minute access, 8-hour
   non-sliding refresh, rotation with denylist (spec). Per-user live-token kill is
   impossible without key rotation (RES-8).
6. Anti-Injection — not applicable: nothing is injected — the thief presents a well-formed stolen token verbatim.
7. Anti-DoS — not applicable: a replay is one authenticated request per stolen token; the flood shape is T1-7's, already bounded.
8. Detective controls — the audit trail's token-endpoint and refusal records (spec)
   surface refresh patterns an operator can read; no anomaly detection is built.

### T1-4 Toolset / leg confusion (mix-up)
1. Reduce Attack Surface — one flat AS for all toolsets *with* `resource` as the
   required disambiguator: there is no lenient mode and no path signal to confuse
   (spec).
2. Isolation — not applicable: all toolsets share one issuer by harness-discovery
   constraint; no isolation boundary exists between them.
3. Authentication — not applicable: the actors are all authenticated; the flaw is
   binding, not identity.
4. Authorization — **the control**: strict, required `resource` at E3 and E4
   (`invalid_target` otherwise), the refresh-token resource match, and the pre-consent
   toolset read-access check (spec). The one-toolset inference is explicit config
   only.
5. Data Protection — the access token's `aud = [resource, marker]` the gateway mints
   (spec) and the `dial-mcp-proxy` audience marker Core enforces (Core config) bind every
   accepted token to gateway issuance; the refresh token's `aud` is the resource alone —
   the marker never included — the token-type separation that keeps the refresh token
   from ever being a token Core's identity-provider entry accepts (spec). Per-toolset
   enforcement downstream is absent (RES-7).
6. Anti-Injection — not applicable: no executable content is involved.
7. Anti-DoS — not applicable: the mix-up is a single confused exchange per flow; the confusion rides one request's own parameters, never volume.
8. Detective controls — every flow's resource/toolset pair lands on the audit trail
   (spec); mismatches are refusal records.

### T1-5 Open redirect via redirect_uri
1. Reduce Attack Surface — no DCR by default: registration is pre-registered or CIMD,
   both of which carry a redirect-URI set the gateway did not accept blind (spec).
2. Isolation — not applicable: the redirect target is the harness's own endpoint on
   the user's machine.
3. Authentication — the code is PKCE-bound to the legitimate client's verifier: a
   redirected code is unusable at E4 by the attacker (spec).
4. Authorization — **the control**: `redirect_uri` validated against the registration
   on every request — exact string equality, with the loopback port exception keyed on
   the registered entry only (spec).
5. Data Protection — codes are 5-minute, single-use, self-contained JWTs (spec):
   even a delivered code expires fast.
6. Anti-Injection — not applicable: the misdelivered artifact is a PKCE-bound code, not content — nothing from the gateway executes at the attacker's endpoint.
7. Anti-DoS — not applicable: each open-redirect attempt is one request that dies at redirect validation; nothing is held or consumed.
8. Detective controls — redirect-URI mismatches are pre-allocation refusals on the
   audit trail with the offered facts (spec).

### T1-6 Unauthenticated state allocation
1. Reduce Attack Surface — no endpoint allocates state without first validating the
   client, the redirect URI, and the resource (spec): allocation requires passing
   registration checks.
2. Isolation — flow records are in-process memory keyed by unguessable ids; no shared
   store exists to poison (spec).
3. Authentication — not applicable as a gate: `/authorize` is a browser endpoint that
   cannot authenticate before the IdP leg; the allocation happens before
   authentication by OAuth's nature — the bound is the cap, not identity.
4. Authorization — not applicable: same reason; no user identity exists yet at
   allocation.
5. Data Protection — flow records carry no secret that survives the flow; the
   identity token is dropped when the action is spent (spec; never-cut 1–3).
6. Anti-Injection — not applicable: the flood presents well-formed requests — the weapon is allocation volume, not content smuggled anywhere.
7. Anti-DoS — **the control**: per-source and global rate limits, a hard cap on live
   flow records with oldest-first eviction and a plain-language error page (spec). The
   class's caller-chosen-length member now carries the `state` bound too: this change
   refuses a `state` over 2048 bytes as `invalid_request` with the fixed-vocabulary
   reason `oversized_state`, on the allocation path before the record exists (the
   authorization-requests requirement's amendment, D8), so the flow-record memory and
   the final redirect's size are bounded against a caller who would grow them — the
   DT-EP1-3 narrowing, landed as this grid's bounding note rather than a row of its own.
8. Detective controls — limiter 429s and evictions land on the audit trail as
   pre-allocation refusals (spec), the `oversized_state` refusal joining that
   enumeration with the class, never the value (spec).

### T1-7 Token-endpoint flood
1. Reduce Attack Surface — E4 serves exactly two grant types; nothing else allocates
   (spec).
2. Isolation — the token endpoint shares the bounded worker pool with the flow legs;
   the CIMD capacity limiter keeps the CIMD fetch from owning the pool (spec) —
   bounding, not removing. The refresh grant joins the attacker-steered slow legs: each
   refresh spends one outbound identity-provider call, holding a worker-thread slot for
   up to the outbound timeout (the RES-4 class, widened).
3. Authentication — not applicable: the flood is of requests that fail validation;
   requiring authentication first would not reduce the request rate.
4. Authorization — not applicable: the flooded requests fail validation before any principal exists; there is no identity whose authorization could bound them.
5. Data Protection — not applicable: a refused flood request discloses and stores nothing; it is rejected at the door.
6. Anti-Injection — not applicable: the flood is of syntactically valid requests; malformed crafting is T1-8's class, bounded there.
7. Anti-DoS — **the control**: the public-endpoint abuse limits (per-source, global)
   bound the flood, and each admitted refresh's per-request cost is one outbound call
   plus one constant-time AES-GCM decryption of the custody claim (microsecond-scale,
   priced for completeness); the residual queue-wait within the limits is disclosed
   (RES-4).
8. Detective controls — the audit trail records limiter refusals (spec).

### T1-8 Malformed request crafting
1. Reduce Attack Surface — strict schemas: two grant types, required parameters,
   typed validation before any processing (spec).
2. Isolation — not applicable: the crash would occur inside the single gateway
   process; no isolation boundary exists within it (single instance by design).
3. Authentication — not applicable: the malformed input fails before identity
   matters.
4. Authorization — not applicable: malformed input dies in typed validation before any identity or resource reaches an authorization decision.
5. Data Protection — error responses are plain-language and fail closed; no state or
   secret is echoed back (spec; never-cut 5).
6. Anti-Injection — **the control** in this class's breadth: every request field is
   parsed by explicit validators (typed models), never evaluated; JSON content types
   enforced on the CIMD leg (spec). The crafted-JWT confusion half of the class is
   M20's (T4-7).
7. Anti-DoS — bounding: the abuse limits cap how fast malformed requests arrive
   (spec).
8. Detective controls — token-endpoint validation failures are refusal records on the
   audit trail (spec).

### T1-9 Log injection into the audit trail
1. Reduce Attack Surface — the audit trail records a fixed event vocabulary, not raw
   requests (spec).
2. Isolation — not applicable: the trail is a sink, not a component the caller
   reaches through a boundary.
3. Authentication — not applicable: the vector is content, not identity.
4. Authorization — not applicable: the vector is content in a record, not a request; no authorization decision consumes what the log carries.
5. Data Protection — **the control**: refusal records carry only the non-credential
   facts the request offered (client id, redirect URI, resource, toolset) with
   fixed-vocabulary reasons — no free-form caller input reaches the log, so a caller
   cannot write content into it (spec; never-cut 5).
6. Anti-Injection — the same property stated as injection defense: structure-only
   logging defeats smuggling by construction (spec).
7. Anti-DoS — bounding: the abuse limits cap log volume from a single source (spec).
8. Detective controls — the trail *is* the detective control; its own integrity is
   the deployment-owned sink's responsibility (deployment).

### T1-10 Reflected content execution (error pages)
1. Reduce Attack Surface — the gateway serves exactly two classes of HTML page; one
   shared helper applies the family to both, so no page class drifts out (spec).
2. Isolation — not applicable: the page renders in the user's own browser mid-flow;
   no gateway boundary separates them.
3. Authentication — not applicable: the script executes in the user's browser on an already-rendered page; no gateway authentication step consumes the reflected value.
4. Authorization — not applicable: execution precedes any further authorization.
5. Data Protection — not applicable: the content is display text, not stored secret
   material.
6. Anti-Injection — **the control**: escaping of every reflected value, plus
   `Content-Security-Policy: default-src 'none'` (+ `base-uri 'none'`) as the second
   layer if escaping regresses; the pages are script-free by mechanism (spec).
7. Anti-DoS — not applicable: a reflected page is one transient response; nothing on the gateway is held or consumed.
8. Detective controls — not applicable: a successful XSS leaves no gateway-side
   record distinguishable from a normal flow; the page-class header-assertion tests
   are the regression guard (repo).

### T1-11 Registrant attribution impersonation [mis-use]
1. Reduce Attack Surface — DCR is config-gated, default off; with it off the
   registration endpoint answers a disabled-error and DCR ids do not resolve (spec).
2. Isolation — not applicable: the abuse is of a display the feature legitimately
   produces.
3. Authentication — the registrant is authenticated by registration itself; the abuse
   is post-registration content.
4. Authorization — not applicable: nothing is accessed; attribution text is abused.
5. Data Protection — not applicable: the abused material is a displayed name on a transient page; no stored or transmitted secret is at stake.
6. Anti-Injection — the name is rendered escaped under the CSP family (spec): the
   abuse is *deception*, not code execution — escaping does not reach it.
7. Anti-DoS — the DCR store cap bounds registrations (spec).
8. Detective controls — the audit trail records the registration and its facts; the
   interstitial's displayed name is attributable end-to-end via the flow record
   (spec). **Disposition: accepted with the flag off (RES-5).**

### T1-12 Own-token cross-toolset replay [mis-use]
1. Reduce Attack Surface — one flat AS makes per-toolset issuers unavailable (the
   harness class cannot discover them); the surface cannot shrink further
   (`background/design.md` §6.2).
2. Isolation — not applicable: the replayed call crosses only the boundaries the user's own token is entitled to cross; no boundary separates a user from their own toolsets.
3. Authentication — the user is the legitimate holder; no authentication is bypassed.
4. Authorization — Core still authorizes every call for that `sub` on that toolset
   (Core config; never-cut 4): the replay never exceeds the user's own access.
5. Data Protection — the 10-minute access TTL bounds the window (spec).
6. Anti-Injection — not applicable: the token is the user's own, well-formed mint; nothing is injected.
7. Anti-DoS — not applicable: the mis-use is one legitimate call per request; the volume shape is T1-7's, already bounded.
8. Detective controls — toolset-qualified flows and calls are on the audit trail
   (spec). **Disposition: accepted (RES-7) — same user, own access, low severity,
   stated.**

### T1-13 AS mix-up at the token endpoint
1. Reduce Attack Surface — one flat AS, one issuer, one token endpoint: there is no
   second issuer whose code could be presented, collapsing the mix-up space (spec).
2. Isolation — not applicable: the flaw is a cross-issuer protocol confusion, and no
   in-process boundary separates issuers the deployment does not have.
3. Authentication — not applicable: no caller identity exists on the harness leg
   (public PKCE clients by design); there is no principal to authenticate beyond the
   code's own validity.
4. Authorization — **the control**: the code embeds the harness `client_id`,
   `redirect_uri`, and `code_challenge` it was minted for, and E4 enforces all three
   plus the `resource` match; a foreign AS's artifact fails the signature first
   (spec).
5. Data Protection — RFC 9207 `iss` in the authorization response lets the harness
   itself detect the wrong-AS case; `state` echo binds the response to the request
   (spec — the requirement placed 2026-10-30 by the `pin-implemented-security-behaviors`
   change; see M9).
6. Anti-Injection — not applicable: no attacker content is executed; the vector is a
   legitimate-shaped token from the wrong source.
7. Anti-DoS — not applicable: a single wrong-issuer code is one failed validation; no
   resource is consumed that T1-7's limits do not already bound.
8. Detective controls — token-endpoint validation failures are refusal records on the
   audit trail (spec).

### T1-14 Pre-registered client impersonation [mis-use]
1. Reduce Attack Surface — the pre-registered list is operator configuration, so the
   impersonatable set is exactly what the operator names — one entry per harness the
   deployment actually serves (deployment config; owner: the deployment
   administrator).
2. Isolation — not applicable: the mis-use happens at the attribution layer, in the
   browser and the log; no runtime boundary separates two clients that are, by
   design, indistinguishable (public PKCE, no secrets).
3. Authentication — not applicable: client authentication is the thing this design
   deliberately does not have — the served harness class registers without secrets;
   adding a shared secret would re-create the realm-policy failure class the design
   removes.
4. Authorization — the impersonator is still themselves at every layer that
   authorizes: the identity leg authenticates *them*, DIAL authorization runs on
   *their* identity, the credential stamps *their* `sub`. The reward is a false
   label, not another user's access (Core config; never-cut 4).
5. Data Protection — not applicable: no data is disclosed; the compromise is the
   integrity of an attribution label.
6. Anti-Injection — not applicable: the label is a string the attacker selects from
   the operator's list; nothing executes.
7. Anti-DoS — not applicable: a single mis-attributed flow costs one flow record,
   inside T1-6's bounds.
8. Detective controls — the audit trail is the countermeasure: flow id, `sub`,
   presented `client_id` + `redirect_uri`, toolset, results — a mis-attributed flow is
   attributable end-to-end to the *acting user* regardless of the label worn (spec —
   the per-flow lifecycle records, placed 2026-10-30 by the
   `pin-implemented-security-behaviors` change; see M11). **Disposition: accepted
   (RES-11) — attribution is display-level; the audit chain is the guarantee that
   survives.**

### T1-16 Stale-claims access token used after role revocation/downgrade [mis-use]
1. Reduce Attack Surface — the TTL knobs bound how long stale claims stay live:
   short-lived access tokens, the non-sliding refresh window (the rotated token
   keeps its original absolute `exp`), and a `refreshTtl` that never exceeds the
   operator-declared identity-provider session bound — validated at startup (spec pins
   the lattice; the concrete numbers — 10-minute access, 8-hour refresh locally — are
   the deployment's operator settings within the spec's bounds).
2. Isolation — not applicable: the claims ride inside a legitimately minted
   token across exactly the path it is entitled to cross; no isolation placement
   closes a fidelity flaw.
3. Authentication — the next flow re-authenticates live, and every refresh re-reads
   the claims fresh: tokens' claims are the identity provider's current truth at the
   last read, never a snapshot (spec), so staleness never outlives the minted token's
   own expiry.
4. Authorization — **the control**: the refresh grant re-reads the current claims from
   the identity provider's fresh token, so a role changed at the provider reaches
   minted tokens within the access TTL; Core's per-call DIAL authorization on every
   toolset call for that `sub` (Core config; never-cut 4) runs on those claims, and an
   already-minted token carries them only to its own expiry (≤ access TTL) — that
   residual interval *is* RES-6; the revocation-latency paths shorten it: the refresh
   `jti` denylist kills a revoked user's refresh at the next refresh attempt (spec),
   and key rotation kills all tokens within Core's JWKS cache TTL (repo — the rotation
   procedure).
5. Data Protection — not applicable: no secret material is disclosed or tampered;
   the compromised property is the fidelity of the authorization decision's data,
   which category 4's bound carries.
6. Anti-Injection — not applicable: nothing is injected; the claims were
   legitimately minted and merely age.
7. Anti-DoS — not applicable: the mis-use presents one still-valid token per call; the harm is claim age, not load — no volume or holding shape exists.
8. Detective controls — the audit trail's per-flow records make each flow's
   issuance attributable to the acting user, and a claims-read refusal is auditable
   with the fixed-vocabulary `claims_read_failed` reason (spec — the
   per-flow lifecycle records, placed 2026-10-30 by the
   `pin-implemented-security-behaviors` change; see M11's placement note).
   **Disposition: mitigated to the access-TTL bound — the claims re-read with rotation
   and denylist; the residual interval is the time between refreshes plus each minted
   token's own life, recorded as RES-6.**

### T2-1 Server-side request forgery (CIMD)
1. Reduce Attack Surface — registration prefers pre-registered clients and CIMD; the
   fetch is the only client-steered egress (spec).
2. Isolation — **the core control set** (spec): HTTPS only; the client-id URL's
   origin on the operator allowlist; **no redirects followed** (a 3xx fails the
   fetch); all resolved A/AAAA records checked against private/loopback/link-local
   ranges and the connection pinned to a validated address with Host/SNI preserved.
3. Authentication — not applicable: the fetch's target is not an authenticated
   gateway-internal service; internal services authenticate callers by network
   position, which the IP validation preserves.
4. Authorization — the allowlist is the authorization of fetch targets (spec):
   no unlisted origin is fetched, ever.
5. Data Protection — response size cap (64 KiB) and TTL-bounded cache (spec); JSON
   content type required and connect/total timeouts (repo — the spec pins neither,
   see M7's placement note).
6. Anti-Injection — fetched fields are data, rendered escaped under the CSP family;
   never executed (spec).
7. Anti-DoS — timeouts and the cache bound repeated fetches (cache: spec; timeouts:
   repo, M7's placement note); the capacity limiter bounds pool occupancy (spec).
8. Detective controls — registration events and fetch refusals are audit records
   (spec).

### T2-2 Slow-fetch pool holding
1. Reduce Attack Surface — only the CIMD fetch is attacker-steered among the slow
   legs; identity and credential legs target operator-configured endpoints (spec).
2. Isolation — slow work is offloaded off the event loop; the loop stays responsive
   (spec).
3. Authentication — not applicable: the flood is of permitted unauthenticated
   registration traffic.
4. Authorization — not applicable: the attacker is a permitted registrant steering the fetch exactly as allowed; no authorization decision exists on the path to widen.
5. Data Protection — not applicable: the held resource is worker capacity; a stalled fetch discloses nothing.
6. Anti-Injection — not applicable: the weapon is connection time on well-formed fetches, not content.
7. Anti-DoS — **the control**: the CIMD capacity limiter bounds attacker-chosen
   fetches' pool share, keeping identity/credential legs capacity; rate limits bound
   arrival (spec). Residual queue-wait accepted (RES-4).
8. Detective controls — limiter refusals on the audit trail (spec).

### T2-3 Fetched-document content injection
1. Reduce Attack Surface — the origin allowlist bounds which parties' documents are
   ever fetched (spec).
2. Isolation — the cache is in-process, keyed by client-id URL, TTL-bounded (spec):
   poisoning requires the allowlisted origin itself to change.
3. Authentication — not applicable: the document is public by nature.
4. Authorization — not applicable: rendering a fetched field on the interstitial precedes any authorization decision; the injected content is display, not a request.
5. Data Protection — not applicable (public content).
6. Anti-Injection — **the control**: fetched fields rendered escaped under the CSP
   family; the interstitial is script-free by mechanism (spec).
7. Anti-DoS — size cap (spec) and timeouts (repo — see M7's placement note).
8. Detective controls — registration records name the client-id URL (spec).

### T2-4 Malformed metadata document
1. Reduce Attack Surface — one document shape is accepted; anything else fails the
   fetch (spec).
2. Isolation — not applicable: parsing happens in-process.
3. Authentication — not applicable: the document arrives from an origin the allowlist already admitted over HTTPS; there is no further credential on this leg to check.
4. Authorization — not applicable: the parse fails before anything the document carries could authorize an action.
5. Data Protection — not applicable: the document is public content; the harm is a crash of the parse path, not disclosure.
6. Anti-Injection — **the control**: strict schema validation and size cap — the
   document is never executed or passed through (size cap: spec; schema validation
   and the JSON content-type requirement: repo — see M7's placement note).
7. Anti-DoS — timeouts and size cap bound the parse cost (size cap: spec; the
   connect/total timeouts: repo — re-placed 2026-10-30; the spec pins no timeout value).
8. Detective controls — fetch/parse failures are registration refusals on the trail
   (spec).

### T2-5 Attacker-chosen redirect URIs via CIMD
1. Reduce Attack Surface — the allowlist bounds which origins can contribute URIs at
   all (spec; the allowlist is operator config).
2. Isolation — not applicable: the document's URIs are data consumed at validation
   time; no isolation boundary separates "URIs the document offered" from "URIs the
   operator allowed" except the allowlist itself, which is categories 1/4's control.
3. Authentication — not applicable: the CIMD model has no client secret to
   authenticate the document's owner; the origin allowlist is the substitute trust
   decision and is already spent.
4. Authorization — **the control**: every presented `redirect_uri` must match the
   fetched document's `redirect_uris` (exact, loopback-port exception keyed on the
   registered entry); the attacker's gain is therefore bounded to URIs the
   *allowlisted origin* published (spec).
5. Data Protection — HTTPS-only fetch means the document the URIs came from is the
   origin's actual document, not a tampered copy in transit (spec).
6. Anti-Injection — not applicable: URIs are matched, never executed or rendered
   unescaped (render-side is T1-10's layer).
7. Anti-DoS — not applicable: a single document's URIs cost nothing to validate;
   volume is T2-2/T2-4's shape.
8. Detective controls — the fetched document's origin and the redirect validation
   results are audited per flow (spec). Residual: an attacker controlling an
   allowlisted origin (or the flagship harness's metadata host) publishes hostile
   URIs — bounded by allowlist curation; **accepted with RES-17's
   revisit-on-named-failure rule (the allowlist is the operator's trust decision).**

### T2-6 DNS rebinding / fetch MITM
1. Reduce Attack Surface — no redirects followed removes the redirect pivot entirely
   (spec).
2. Isolation — not applicable: the attack is between the gateway and one external
   origin; no in-system boundary is crossed.
3. Authentication — TLS (HTTPS-only) authenticates the origin server — the control
   against the on-path half (spec).
4. Authorization — **the control**: the connection is made to the *validated* address
   with Host/SNI preserved: a rebinding answer to the name cannot redirect the
   connection — validation and connection are pinned together (spec — the
   private/loopback/link-local refusal; the pinning mechanics are its implementation).
5. Data Protection — not applicable: the document's confidentiality is not the issue;
   its integrity is, which categories 3/4's controls carry.
6. Anti-Injection — not applicable: no code executes; the document is data.
7. Anti-DoS — the connect/total timeouts bound a stalled rebinding attempt (repo —
   see M7's placement note).
8. Detective controls — fetch refusals are registration refusals on the trail (spec).

### T3-1 E7 code-injection chain — guessing variant
1. Reduce Attack Surface — the flow record is destroyed on first use at E7; the
   record's whole life is minutes (spec).
2. Isolation — flow records are in-process, keyed by the flow id; there is no
   enumeration surface (spec).
3. Authentication — the chain requires the victim's identity-provider JWT, which the gateway
   holds only mid-flow: the attacker cannot present it, only ride a live flow
   (bounding).
4. Authorization — **the control's teeth**: the upstream `state` must round-trip the
   flow id, and the `/signin` call carries the live user's identity — the binding the
   attacker must defeat (spec).
5. Data Protection — **the control**: 128-bit CSPRNG flow ids (2⁻¹²⁸ per guess) —
   the entropy is load-bearing (spec; `background/design.md` §5.3).
6. Anti-Injection — the chain *is* an injection of the attacker's code into the
   victim's credential binding; the id entropy + state round-trip + destroy-on-use
   defeat it (spec).
7. Anti-DoS — the flow cap bounds live targets for guessing (spec).
8. Detective controls — flow destruction, callback receipts, and `/signin` results
   are per-flow audit records (spec — the per-flow lifecycle records, placed
   2026-10-30; see M11's placement note).

### T3-2 E7 code-injection chain — interception variant
1. Reduce Attack Surface — the callback URL carries only the code and the flow id;
   no token crosses the browser leg (spec).
2. Isolation — not applicable: the interception is of the user's browser traffic on
   the public leg; no gateway boundary is crossed differently.
3. Authentication — PKCE does not defeat this variant: the attacker *delivers* the
   victim's legitimate code and completes their own upstream consent; both legs'
   PKCE pairs are satisfied by the parties themselves.
4. Authorization — the flow lookup passes on a live flow (the state round-trips by
   construction); authorization is defeated, not bypassable further.
5. Data Protection — **the control**: transport security on the public origin — a
   TLS-fronted origin gives the interceptor nothing to capture. Home: deployment;
   **today unplaced — accepted (RES-1)**.
6. Anti-Injection — the destroy-on-first-use bound shrinks the window (the attacker
   must beat the victim's browser); it does not close the variant.
7. Anti-DoS — not applicable: the interception races one live flow's callback; no volume is involved.
8. Detective controls — the `/signin` result and flow destruction are recorded; a
   victim whose flow completed in another browser is not distinguishable today
   (the audit records bound, not detect, this).

### T3-3 Callback-URL interception (codes)
1. Reduce Attack Surface — codes live seconds-to-minutes and are single-use (spec).
2. Isolation — not applicable: browser-leg traffic.
3. Authentication — **the control**: each code is PKCE-bound to its verifier (the
   gateway's for the identity leg, Core's for the upstream leg) — an intercepted code
   cannot be exchanged by the interceptor (spec; never-cut 2).
4. Authorization — not applicable beyond the exchange failure.
5. Data Protection — the exploitable remainder (identity-token path) is the
   interception variant (RES-1): TLS on the public origin, deployment-owned.
6. Anti-Injection — not applicable: the interception reads a URL off the wire; nothing enters any component.
7. Anti-DoS — not applicable: a passive read of browser-leg traffic consumes no gateway resource.
8. Detective controls — code-receipt and flow-destruction records (spec — the
   per-flow lifecycle records, placed 2026-10-30; see M11's placement note).

### T3-4 Attribution/context injection (interstitial and error pages)
1. Reduce Attack Surface — two page classes, one shared helper (spec).
2. Isolation — not applicable: user's browser.
3. Authentication — not applicable: the injected content executes in the browser after the IdP leg; no authentication step consumes it.
4. Authorization — not applicable: the script hijacks the auto-continue — a display action; no authorization decision reads the injected content.
5. Data Protection — not applicable: the content is display text on a transient page, not stored secret material.
6. Anti-Injection — **the control**: escaping + `default-src 'none'` CSP; the page
   continues itself by meta-refresh/anchor, no script (spec).
   **Widened by this change:** the interpolated resource is now a multi-segment,
   percent-encoded **path** rather than a single-segment name — new interpolant material.
   The guard's decoded forbidden-set refusal removes the markup-breaking characters before
   interpolation, and the shared builder's escape discipline is asserted for path-shaped,
   percent-encoded inputs (decoding to markup-shaped bytes, `%3C%61%3B…`) by unit rows over
   every interpolation point (task 3.6) — the discipline asserted, not assumed.
7. Anti-DoS — not applicable: one rendered page per flow; nothing is held or consumed.
8. Detective controls — per-page-class header-assertion tests are the regression
   guard (repo).

### T3-5 Framed flow advancement (UI redressing)
1. Reduce Attack Surface — the page auto-continues in seconds; the frame window is
   small but real.
2. Isolation — not applicable: the framing happens on an attacker page outside any
   gateway boundary.
3. Authentication — not applicable: the framing rides the victim's already-established IdP session; no credential is presented that a check could catch.
4. Authorization — the framed consent advances with the victim's IdP session: the
   consent integrity control is the header below, not an authorization check.
5. Data Protection — not applicable: nothing is read or stored; the gain is an unseen consent, an action whose bound is the header in category 6.
6. Anti-Injection — not applicable (no content is injected into the gateway).
7. Anti-DoS — not applicable: one framed page in the victim's browser; the gateway spends nothing.
8. Detective controls — not applicable browser-side; the flow's completion is
   audited (spec — the per-flow lifecycle records, placed 2026-10-30; see M11's
   placement note).
   **The control**: `frame-ancestors 'none'` + `X-Frame-Options: DENY` on every HTML
   response (spec).

### T3-6 Referer leakage of the callback URL
1. Reduce Attack Surface — the callback URL carries only already-exchanged material
   (the code is exchanged server-side before the page renders) plus the flow id
   (spec).
2. Isolation — not applicable: the leak channel is the browser's header on
   third-party navigation.
3. Authentication — not applicable: the leak is a browser header to a third-party page; no gateway authentication material crosses.
4. Authorization — not applicable: the leaked code is read, not presented for authorization — and it is single-use, spent server-side before the page renders.
5. Data Protection — **the control**: `Referrer-Policy: no-referrer` on both page
   classes — nothing bounds the cross-party leak otherwise, one line closes the class
   (spec).
6. Anti-Injection — not applicable: nothing is injected; the browser emits a header on navigation.
7. Anti-DoS — not applicable: the leak rides one navigation; no volume exists.
8. Detective controls — not applicable (the leak leaves no server-side trace).

### T3-7 Crafted callback parameters
1. Reduce Attack Surface — callbacks accept a fixed parameter set (spec).
2. Isolation — an unknown flow resolves to nothing: no state is allocated on
   callback misses (spec).
3. Authentication — not applicable: the callback precedes any gateway-held identity
   for unknown flows.
4. Authorization — not applicable: crafted parameters die at flow lookup — unknown flows resolve to nothing, before any identity exists to authorize.
5. Data Protection — the failure answer is the plain-language error page, fail
   closed, no state echoed (spec; never-cut 5).
6. Anti-Injection — parameters are parsed by validators, rendered escaped (spec).
7. Anti-DoS — bounding: callbacks of unknown flows cost one lookup; abuse limits
   bound arrival (spec).
8. Detective controls — callback misses are auditable flow events (spec).

### T3-8 Cached-page stale resubmission
1. Reduce Attack Surface — pages are transient by nature (auto-continue; short-lived
   flows).
2. Isolation — not applicable: the replay is from a browser/proxy cache outside the
   gateway.
3. Authentication — not applicable: the resubmission replays a dead flow's spent parameters; no credential is involved in a lookup that fails.
4. Authorization — a resubmitted stale flow fails the flow lookup — authorization of
   the *dead* flow is refused by destroy-on-first-use and TTL (spec).
5. Data Protection — not applicable: no secret rides a stale page — the flow's material is spent and the pages are display.
6. Anti-Injection — not applicable: the resubmitted parameters are the flow's own well-formed values; staleness, not content, is the flaw.
7. Anti-DoS — bounding: stale submissions die at one lookup (spec).
8. Detective controls — not needed beyond the lookup refusal.
   **The control**: `Cache-Control: no-store` on both page classes (spec).

### T3-9 On-path rewrite of the auto-continue
1. Reduce Attack Surface — not applicable: the rewrite targets the page the
   deployment serves over the transport it chose; no endpoint withdrawal helps.
2. Isolation — not applicable: transport-level attack, the same shape as T1-2.
3. Authentication — TLS would authenticate the origin to the browser — the control,
   not in place today (deployment).
4. Authorization — not applicable: the attacker serves content; no request to
   authorize.
5. Data Protection — the delivered upstream request's integrity is what TLS would
   carry; in its absence the upstream leg's own TLS (the upstream AS's HTTPS)
   protects only the leg's second half — the first half (the interstitial to the
   rewritten target) is exposed. Partial, honest. **Today unplaced — accepted
   (RES-12).**
6. Anti-Injection — not applicable: the rewrite is content substitution at the
   transport, not executable content inside a component.
7. Anti-DoS — not applicable: serving rewritten pages consumes the attacker's
   resources.
8. Detective controls — a rewritten continuation lands the flow at an AS the gateway
   never named; the flow then fails loudly at the callback (unknown flow or refused
   state), which the audit trail records. Partial (spec).

### T3-10 Callback flood
1. Reduce Attack Surface — callbacks that fail lookup allocate nothing; the handlers
   are lookup-first (spec).
2. Isolation — not applicable: the flood is against one handler path on one instance;
   the pool-bound shape is the isolation that exists.
3. Authentication — not applicable: unauthenticated browser endpoints by protocol
   (the same stage property as T1-6).
4. Authorization — not applicable: no principal exists on a garbage callback.
5. Data Protection — not applicable: no data is touched on failed lookups.
6. Anti-Injection — not applicable: volume attack on validated inputs.
7. Anti-DoS — **the control**: the public-endpoint abuse limits cover E6/E7 with the
   rest (spec).
8. Detective controls — unknown-flow callback hits are auditable flow events (spec).

### T4-1 Signing-key theft from the host
1. Reduce Attack Surface — the key is never committed (gitignore blocks
   `*.pem`/`*.key`; repo), never logged (never-cut 5/7), and exists in exactly one
   injection path. Re-stated for the keyset: the material is a keyset entry with a
   per-entry source — `env` (injected) or `file` (a PEM on a read-only mount), both
   implemented, `kms` refused — so the injection path is the env-var surface or the
   key-file mount, and the material's at-rest location is where the mount is
   (DT-EP4-4).
2. Isolation — the host/volume boundary *is* the isolation: the file's readers are
   the host's readers. On the local bind mounts, POSIX modes are best-effort (the
   Windows-mount class the DCR store documents); the contract's read-only key-file
   mounts are the assumption the assembly preserves; no stronger boundary exists at
   this bar.
3. Authentication — stolen key material *is* the authenticator of a full IdP: nothing
   downstream challenges it except the audience marker, which the thief mints too.
4. Authorization — bounding only: minted tokens still run DIAL authorization for
   their asserted `sub` — but the thief asserts any `sub`, so this bounds nothing
   that matters.
5. Data Protection — **the stated control**: IdP-grade custody — KMS/HSM-held key
   where the process holds a reference, not a key; `kid` rotation within Core's
   10-minute JWKS cache. Home: deployment (the KMS signing sign-interface is optional
   and may be abandoned — RES-2's amendment; the key's custody is its injection path,
   the supported end state, RES-13). **Today: env/file injection custody accepted
   (RES-13); the retained-entry window the priced addition (DT-EP4-2, M34).**
6. Anti-Injection — not applicable: the vector is file read, not content injection.
7. Anti-DoS — not applicable: the theft is a file read; the service keeps running.
8. Detective controls — bounding: 10-minute access TTLs make a stolen key detectable
   and revocable on the rotation timescale (rotation procedure, repo docs); no
   anomalous-issuance detection is built.

### T4-2 Key read out of a memory dump
1. Reduce Attack Surface — the gateway holds no post-flow user secrets at all: the
   identity access token is spent and dropped; the process's persistent secrets are the
   signing key and the dedicated custody key, and each refresh grant's decrypted
   provider session refresh token exists in the process only for that grant's duration
   — there is no per-session store to sweep (spec).
2. Isolation — process isolation is the container's; a host-level read crosses it by
   definition — the host boundary is the trust (TB5).
3. Authentication — not applicable (the dump yields the authenticator itself).
4. Authorization — not applicable: the dump yields the authenticator itself; there is no decision below it that an authorization control could guard.
5. Data Protection — **the control that removes the class**: never materializing the
   keys (KMS sign interface for the signing key, KMS at C3 for the custody key —
   deployment, production direction). Within a managed runtime there is no reliable
   wipe-on-demand (CPython immutable strings, library copies, GC); **accepted (RES-2)**
   — the identity access token's post-lift life (the realm's 24 h) is the upstream-owned
   half of the same acceptance, and the custody key's compromise is priced separately
   as RES-21.
6. Anti-Injection — not applicable: the dump is a read of process memory; nothing is injected into anything.
7. Anti-DoS — not applicable: a passive read of a dump consumes no service resource.
8. Detective controls — not applicable to a passive dump.

### T4-3 Key or mint-path tampering (host write)
1. Reduce Attack Surface — one key, one mint path, one injection mechanism (repo).
2. Isolation — the tamper requires host-level write: the same boundary as the key
   itself. No in-repo control can stand below the host boundary.
3. Authentication — not applicable (the tamper *creates* authenticators).
4. Authorization — not applicable: the substituted material mints tokens that pass every downstream check by construction; no decision point remains to guard.
5. Data Protection — **the control is the boundary**: host-write access is the
   signing-key trust boundary; the DCR store is trusted to the same boundary
   explicitly. Accepted at this bar (RES-5, RES-13).
6. Anti-Injection — the tamper is material substitution, not code injection into a
   running parse path; no input validation reaches it.
7. Anti-DoS — not applicable: the substitution leaves the service running — the tamper mints, it does not deny.
8. Detective controls — `kid` rotation and JWKS publication make an unexpected key
   visible to an operator comparing published kids; no automatic check is built.

### T4-4 JWKS trust-path manipulation
1. Reduce Attack Surface — Core fetches exactly one configured `jwksUrl`; the
   gateway publishes exactly one JWKS document (Core config; spec).
2. Isolation — the Core↔E8 path should stay on the internal network (deployment:
   compose-network placement; the internal URL is the stated form).
3. Authentication — Core's fetch of the JWKS is itself unauthenticated: the
   document's integrity rides the path's integrity — TLS or network isolation
   (deployment). Internal plain http today (RES-19).
4. Authorization — not applicable: the manipulation is of key material upstream of every authorization decision; no request is being authorized.
5. Data Protection — `issuerPattern` per provider and the `audience: dial-mcp-proxy`
   marker (Core config) mean a substituted key still must present the deployment's
   exact issuer and mint the marker — the substitution is *this deployment's*
   compromise, not a cross-issuer confusion.
6. Anti-Injection — not applicable: the vector is key substitution on a path or in config, not executable content in a component.
7. Anti-DoS — bounding: JWKS responses are cacheable and cheap (spec).
8. Detective controls — the published `kid` set is operator-comparable across
   rotations (repo docs).

### T4-5 Unauthenticated endpoint floods (E8, /healthz)
1. Reduce Attack Surface — two read-only endpoints, one document each (spec).
2. Isolation — not applicable: both endpoints are deliberately public documents; there is nothing to place behind a boundary.
3. Authentication — deliberately absent: the JWKS is public material by function.
4. Authorization — not applicable: the documents are public by function; there is no per-caller authorization to enforce on them.
5. Data Protection — not applicable (public document).
6. Anti-Injection — not applicable: the responses are static, cacheable documents; no caller input reaches their content.
7. Anti-DoS — **the control**: the public-endpoint abuse limits; cacheability of the
   JWKS (spec).
8. Detective controls — limiter refusals on the trail (spec).

### T4-6 Host-operator key exfiltration [mis-use]
1. Reduce Attack Surface — the operator's legitimate surface is the host; the key's
   exposure to it is the minimum a file-based custody permits.
2. Isolation — none exists against the host operator by definition; the host is the
   trust boundary (TB5).
3. Authentication — not applicable (legitimate privileged access).
4. Authorization — not applicable (host access is not authorized by the gateway).
5. Data Protection — KMS custody would remove the operator's direct key access
   (deployment, production direction). **Today: accepted (RES-13).**
6. Anti-Injection — not applicable: the operator reads material; nothing is injected.
7. Anti-DoS — not applicable: an exfiltration is a read; the service keeps serving.
8. Detective controls — none in-repo; host-level audit is the deployment's
   (deployment).

### T4-7 Crafted JWT against verification
1. Reduce Attack Surface — the gateway verifies JWTs at exactly two endpoints (E4,
   E10) and mints at one; the verification surface is enumerated, not ambient
   (spec's endpoint set).
2. Isolation — not applicable: the crafted token enters the verifier by design;
   isolation would mean not verifying, which is not an option for an AS.
3. Authentication — not applicable: the *attack* targets the authentication
   mechanism itself; category 6 is where key-material selection is pinned.
4. Authorization — not applicable: authorization consumes a *verified* token; the
   flaw is upstream of it.
5. Data Protection — not applicable: no data is disclosed by a verification attempt.
6. Anti-Injection — **the control**: pinned algorithm (RSA256 — the signing key's own
   algorithm, passed to the verifier with the key directly, so an embedded-`jwk`/`x5c`
   header or `kid` steering never selects key material; the provider leg's `kid`
   looked up only in the provider's own JWKS), a maintained verification library
   (`pyjwt[crypto]`), and the dependency-audit gates on every diff (spec — the
   verification-hygiene requirement placed 2026-10-30 by the
   `pin-implemented-security-behaviors` change, covering the pinned algorithm and key
   selection; the implementation and the gate ladder are the repo half — M20).
7. Anti-DoS — malformed tokens are rejected by parsing limits before signature work
   (T1-8's class); verification volume is T1-7's limits (spec).
8. Detective controls — verification failures are refusal records with fixed
   vocabulary (spec).

### T5-1 Identity-token sniffing on the internal leg
1. Reduce Attack Surface — the token-use rule: the identity token serves exactly the
   flow's decision step and credential call — at most two presentations, never
   anything else (spec; RES-3 for the count's shape — the listing read and the
   credential call, the two-read fallback deleted). The provider session
   refresh token adds purposes of its own: its plaintext is presented once per gateway
   refresh at the provider's token endpoint, and its ciphertext is delivered once per
   rotation inside the refresh token to its presenting client (spec).
2. Isolation — the compose network is a private bridge whose members are the
   deployment's own services; the presentations never leave it (deployment; repo
   compose).
3. Authentication — not applicable: the sniffed artifact authenticates its holder.
4. Authorization — a sniffed token still runs DIAL authorization for its `sub` in
   Core (Core config) — the thief gets that user's identity, not more.
5. Data Protection — **the control**: TLS on the internal legs where the deployment
   demands it. Home: deployment; internal plain http today — **accepted (RES-19)**;
   the token's 24 h post-lift life is the realm's own, upstream-owned.
6. Anti-Injection — not applicable: the read is of wire traffic; no content enters the gateway.
7. Anti-DoS — not applicable: a passive sniff spends no gateway resource.
8. Detective controls — the token is never logged (never-cut 5); its use is
   attributable per flow (spec — the per-flow lifecycle records, placed 2026-10-30)
   — a stolen token's later use at Core is *not* gateway-visible.

### T5-2 Internal-leg man in the middle
1. Reduce Attack Surface — the gateway calls operator-configured endpoints only
   (Core base URL, the configured identity-provider issuer); no caller steers them (spec).
2. Isolation — the compose-network boundary (deployment) is the isolation: a peer
   must first be on the network.
3. Authentication — the upstream code is PKCE-bound to Core's verifier: a MITM
   capturing the `/signin` body holds a code they cannot spend (never-cut 2). The
   identity-verification chain itself is exposed on the identity-provider legs: the token
   exchange and the JWKS fetch both ride the provider's back-channel (locally
   `http://keycloak:8900`), so a MITM peer can
   serve a forged id_token *and* the matching hostile JWKS — the gateway verifies the
   forgery against the forger's keys and mints for any `sub` with any roles,
   including admin (the signing-key blast radius from a network-peer position, no
   victim required). PKCE does not reach this gain, and verifying against the
   provider's own JWKS is no answer to it: the verification is only as trustworthy as the channel
   the JWKS arrived over — the same channel the MITM controls (RES-19's re-priced
   acceptance).
4. Authorization — a forged listing answer can at worst misdirect the consent leg:
   the consent still completes against whatever AS the forged endpoint names, and the
   resulting code still lands at E7 for the real flow — the damage is consent
   misdirection, bounded by the source being operator-configured. The listing read
   also carries the kind and the per-caller statuses; a forged answer
   there steers the flow's re-taken branch (T5-3's sibling, DT-EP5-3's shape) and can
   forge the existence decision (a not-found denies one servable toolset's flow).
5. Data Protection — **the control**: TLS on the internal legs. Home: deployment;
   internal plain http today — **accepted (RES-19, re-priced 2026-10-29 with the
   mint-any-identity blast radius stated: the private-bridge membership is the
   load-bearing bound for identity verification itself, and the router's port
   non-publication does not bound these legs — they are gateway-outbound and never
   cross the router)**.
6. Anti-Injection — settings fields are built into URLs by strict construction;
   malformed values fail loudly (spec).
7. Anti-DoS — connect/total timeouts on gateway-issued calls (repo — the configured
   outbound timeout; re-placed 2026-10-30: the spec pins no timeout value).
8. Detective controls — the listing read's refusals and `/signin` results are audited
   (spec — the per-flow lifecycle records, placed 2026-10-30; see M11's placement
   note).

### T5-3 Settings-field content injection
1. Reduce Attack Surface — the settings source is Core's operator-owned
   configuration, not any caller (Core config).
2. Isolation — not applicable: the fields flow inside the trusted internal leg.
3. Authentication — not applicable: the settings arrive from Core on the trusted internal leg; there is no caller credential on this path to check.
4. Authorization — the pre-consent read-access check means the user is entitled to
   the toolset before any upstream leg runs (spec). The read is now the **toolset
   namespace's** existence decision (discovery answers phantom names a document by the
   mirror property; the app read is the apps namespace's existence decision the same
   way, on the same internal leg and likewise post-authentication), so a forged
   not-found on this leg denies one servable toolset's flow —
   the same shape and the same internal-leg trust as the forged kind.
5. Data Protection — not applicable (public projection by construction — Core nulls
   the verifier; never-cut 2).
6. Anti-Injection — **the control**: strict URL building, loud refusal on malformed
   or incomplete projections, and the delivery guard that the upstream request
   arrives complete or the flow fails closed (spec). **Narrowed by this change:** the
   projection's `redirect_uri` member leaves the flow's inputs entirely — the upstream
   callback is now derived from configuration (`{GATEWAY_PUBLIC_ORIGIN}{UPSTREAM_CALLBACK_PATH}`),
   so an editor of the toolset (a UX save overwriting the stored field) can no longer
   steer the consent's destination through this leg; the members still read (client id,
   endpoints, challenge, scopes) keep this threat's shape and this control.
7. Anti-DoS — not applicable: one listing read per flow; malformed values fail loudly and immediately, holding nothing.
8. Detective controls — the listing read's refusals on the trail (spec).
   **Disposition: mitigated (strict URL building, loud refusal — M10's bounding); the
   threat's row narrows — the `redirect_uri` member is out of the flow's inputs (the
   derived-callback mitigation, M42); the existence edge is per-namespace — the
   per-user listing read is the toolset namespace's existence decision and the app read
   the apps namespace's, both post-authentication on the same internal leg; a forged
   not-found is the one denial of one flow — the same leg and trust as the internal-leg
   residual (RES-19).**

### T5-4 GLOBAL-level escalation attempt
1. Reduce Attack Surface — the flow *establishes* no GLOBAL credential at all: the
   credential call stays at USER level on every establishing path; what a GLOBAL
   credential's *use* reaches is the operator-stored credential, through the signed-in
   short-circuit, not an escalation the flow performs (spec).
2. Isolation — not applicable: the flow never establishes at GLOBAL level — the
   capability is absent on the establishing paths, not segregated; a stored global
   credential is *used*, and Core injects it on the data path.
3. Authentication — GLOBAL requires admin roles on the calling token in Core (Core
   config) — an admin mis-using the ops API directly is Core's own surface, unchanged.
4. Authorization — **the control**: the flow never *establishes* a credential at GLOBAL
   level (the credential call stays at USER level on every establishing path) and never
   reads or transits the stored credential; a GLOBAL credential's *use* through the
   short-circuit is the operator-configured delegation — the same access the same user
   already holds through Core's own paths — not an escalation. Core stamps and resolves
   per `sub` (spec; never-cut 3). **Disposition: preserved by the establishment-side
   refusal with the delegation stated — RES-9.**
5. Data Protection — not applicable: no secret material is involved; the flow never
   touches a GLOBAL credential on its establishing paths, and a used one stays inside
   Core.
6. Anti-Injection — not applicable: nothing is injected; the flow performs no GLOBAL
   establishment to refuse.
7. Anti-DoS — not applicable: one refused request; nothing is consumed.
8. Detective controls — `/signin` calls record the acting user and level (Core's own
   record; spec).

### T5-5 Upstream-dependency stalls
1. Reduce Attack Surface — flows touch Core and the identity provider only within the flow TTL
   (spec).
2. Isolation — not applicable: the dependency is genuine and required.
3. Authentication — not applicable: the stall is a dependency being unavailable; no credential is involved in waiting.
4. Authorization — not applicable: nothing is being authorized while a leg waits — the flow fails closed at its TTL.
5. Data Protection — not applicable: the stall holds flow records, not secrets; waiting opens no disclosure path.
6. Anti-Injection — not applicable: the weapon is unavailability, not content.
7. Anti-DoS — **the control**: flow TTL bounds held records; the failure is
   fail-closed with the plain-language page (spec).
8. Detective controls — stalled/failed legs are flow records on the trail (spec —
   the per-flow lifecycle records, placed 2026-10-30; see M11's placement note).

### T5-6 Hostile upstream response
1. Reduce Attack Surface — the gateway talks to a fixed set of peers (Core,
   the identity provider, the toolset's configured endpoints) and validates response shapes before
   consuming them (repo — the shape validation lives in the outbound clients;
   re-placed 2026-10-30: the spec pins no response-shape requirement, so the earlier
   "(spec)" citation was false).
2. Isolation — offloaded to the worker pool, off the event loop (repo — the
   threadpool-offload pattern).
3. Authentication — not applicable: the peer's response arrives on an already-trusted
   channel; there is no per-response credential.
4. Authorization — not applicable: a malformed answer authorizes nothing — the flow
   fails before any credential action.
5. Data Protection — not applicable: availability compromise; fail-closed paths emit
   no credential material (spec; never-cut 5).
6. Anti-Injection — **the control**: bounded response parsing (schema-validated,
   size-capped bodies) so hostile shapes never execute or corrupt state (repo —
   re-placed 2026-10-30; the spec pins no parsing requirement).
7. Anti-DoS — timeouts on every gateway-issued call bound a stalling peer (repo —
   the configured outbound timeout; the spec pins no timeout value).
   Crash residual: a crash-loop is a full outage until restart — **accepted with
   RES-15** (single instance).
8. Detective controls — upstream failures are flow records on the trail (spec —
   the per-flow lifecycle records, placed 2026-10-30; see M11's placement note).

### T6-1 Challenge redirection to a hostile AS (router compromise/misconfig)
1. Reduce Attack Surface — the router is stock nginx with a small committed config;
   the synthesis form (`map $status` + `proxy_hide_header`) guarantees a 401 carries
   the gateway's challenge and nothing of the upstream's (repo).
2. Isolation — the router is a dedicated container with one job and no secrets; the
   gateway's `:8091` is unreachable except through it (repo compose — the peer
   binding).
3. Authentication — a hostile AS cannot produce a token Core accepts (two configured
   issuers only; Core config) — the router compromise yields phishing capability, not
   token forgery.
4. Authorization — not applicable: the compromise precedes authorization decisions.
5. Data Protection — the challenge quotes a configured origin, never `$host` (repo) —
   no header-injection material in the synthesized value.
6. Anti-Injection — not applicable (config integrity, not content injection).
7. Anti-DoS — not applicable: the compromised router serves requests; it denies the gateway no resource.
8. Detective controls — the routing probe battery before harness runs (repo) and the
   committed-config diff review are the guards; runtime router-tamper detection is
   none. **Disposition: same class as any front-router compromise — accepted with the
   router's custody (deployment host), the synthesis form committed here (repo).**

### T6-2 Path-capture misrouting
1. Reduce Attack Surface — resource paths are checked per decoded segment against the
   path grammar (spec — the decoded per-segment rules, re-based by this change from
   the one-segment `[a-z0-9-]+` charset placed 2026-10-30 by the
   `pin-implemented-security-behaviors` change, M10); the reserved set mirrors the
   router's alternation verbatim (spec). The class extends to the second namespace:
   **app paths carry the same decoded per-segment rules** (the grammar the router's
   apps map mirrors). **Re-priced by this change:** the
   data-path capture is no longer a location regex over a single-segment name at all —
   it is a `map $request_uri` carrying the path grammar (the addressing-vocabulary
   requirement), so the row's subject changes from the location regex to the map
   grammar. The map's grammar refuses whole-segment `.`/`..`, empty segments, and
   trailing dots; the location is a bare prefix behind the authorization-surface
   locations; the reserved-name rule is a **first-segment** rule on the guard side,
   mirroring the first-segment capture of the authorization surface. Two regexes
   (toolset and apps maps) and the guard now carry the rules in lockstep, asserted by
   the lockstep probe battery.
2. Isolation — not applicable: one router, one config.
3. Authentication — not applicable: routing is path-based; no credential is presented or checked on the misdirected traffic.
4. Authorization — **the control**: the startup reserved-name check (first segment)
   covers the *configured* operator restriction entries (toolset entries; an app entry
   has no reserved-name check to run — nothing gateway-owned lives under the apps
   segment); for dynamic paths the request-time path guard refuses the collision before
   the router ever serves it (the check moved with the served set, it was not lost); the
   AS-surface locations are ordered before the data-path locations, and the map's
   match domain requires the `/mcp` suffix with nothing after it but the optional query
   (repo — the conf and the guard).
5. Data Protection — not applicable: the misroute moves traffic between surfaces; no stored secret material is at stake.
6. Anti-Injection — not applicable (routing, not content).
7. Anti-DoS — not applicable: the misroute mishandles individual requests; the volume shape is T6-6's class.
8. Detective controls — the startup refusal for configured entries and the guard's
   request-time refusal are both loud and named (spec); the lockstep probe battery
   exercises the split for both path shapes and promises the documented map/guard
   asymmetry as the asymmetry it is (repo — the instrument's rows).

### T6-3 Query-string loss on the data path
1. Reduce Attack Surface — two data-path locations now (the toolset and the apps path),
   each with one explicit pass-through form carrying the toolset location's
   `$is_args$args` verbatim (repo).
2. Isolation — not applicable: one router, one config — there is no second component to isolate the data-path locations from.
3. Authentication — not applicable: the loss is of a URL parameter at proxying; no credential is involved.
4. Authorization — not applicable: the session id is protocol state, not an authorization input at the router — Core's per-call authorization is unchanged.
5. Data Protection — not applicable: the dropped parameter is protocol session state, not secret material the gateway holds.
6. Anti-Injection — not applicable: nothing is injected — a parameter is dropped, not added.
7. Anti-DoS — not applicable (this is correctness-driven availability).
8. Detective controls — the routing probe battery asserts query-string survival
   on both the toolset and the apps path
   (repo). **The control**: `$is_args$args` on each variable `proxy_pass` (repo) —
   nginx's automatic append is suppressed by variables, so the explicit form is
   required; the apps location carries the toolset location's form re-derived.

### T6-4 Router bypass via the container port
1. Reduce Attack Surface — the gateway's `:8091` is container-internal; the compose
   service carries no `ports:` mapping, ever — stated as an invariant of the topology
   at the compose service and router config (repo).
2. Isolation — **the control**: the router is the only front door and the only
   authority for the peer identity; network placement does the isolation (repo
   compose; deployment).
3. Authentication — not applicable: the binding is positional, not a credential.
4. Authorization — requests that never crossed the router carry no router-established
   peer identity; the binding scopes the gateway's trust to router-fronted requests
   (repo).
5. Data Protection — not applicable: the bypass changes which door fronts the request, not what is stored; the wire exposure is T1-1's class.
6. Anti-Injection — not applicable: nothing is injected; the flaw is the door used, not content delivered.
7. Anti-DoS — not applicable: one request per bypass; the flood shape is T6-6's.
8. Detective controls — the compose-file comment and config review are the guard;
   no runtime check is built.

### T6-5 MCP traffic in cleartext
1. Reduce Attack Surface — the router adds nothing to the payload; it proxies
   byte-for-byte with `proxy_buffering off` (repo).
2. Isolation — not applicable: the traffic is public-leg by definition.
3. Authentication — the traffic is authenticated by the bearer token *in* the
   cleartext — which is the separate harvest threat (T1-1).
4. Authorization — not applicable: the read is of traffic already authorized; no decision is subverted.
5. Data Protection — **the control**: TLS-front the public origin. Home: deployment;
   today unplaced — **accepted (RES-12)**.
6. Anti-Injection — not applicable: a passive read; no content enters any component.
7. Anti-DoS — not applicable: passive reading consumes no resource.
8. Detective controls — not applicable to passive reads.

### T6-6 Router-level floods
1. Reduce Attack Surface — one listener, one config, standard nginx exposure (repo).
2. Isolation — the router fronts and bounds what reaches the gateway and Core
   (repo).
3. Authentication — not applicable to connection-level floods.
4. Authorization — not applicable: connection floods carry no identity; there is no principal to authorize.
5. Data Protection — not applicable: the flood holds connections; no secret is disclosed by holding them.
6. Anti-Injection — not applicable: the weapon is connection count and time, not content.
7. Anti-DoS — **the control split**: the gateway's own abuse limits bound what
   reaches the gateway (spec); nginx's connection handling — the `proxy_read_timeout`
   and worker/connection caps the slow-client/SSE shape demands — is the deployment's
   router tuning (deployment).
8. Detective controls — limiter refusals on the gateway trail (spec); router access
   logs are the deployment's (deployment).

### T6-7 Toolset-name injection into nginx config
1. Reduce Attack Surface — resource paths never reach nginx config as free text: the
   data-path maps and the authorization-surface regexes are static in the committed
   config, and the maps match paths against the segment grammar, never interpolating a
   name into the config (spec — the grammar is the addressing-vocabulary and path-guard
   requirements, re-based by this change from the one-segment `[a-z0-9-]+` charset placed
   2026-10-30 by the `pin-implemented-security-behaviors` change; the conf and the
   guard are the committed config and repo half — M10's placement note, M38/M39).
2. Isolation — not applicable: the injection target would be the config file itself;
   no runtime boundary separates config from names because names never enter config
   generation.
3. Authentication — not applicable: config text, not a request.
4. Authorization — not applicable: the injected name alters routing, not any authorization decision.
5. Data Protection — not applicable: no secret material is at stake; the target is the routing config's integrity.
6. Anti-Injection — **the control**: the decoded path grammar enforced at startup on
   every *configured* restriction entry, and at request time by the path guard for
   dynamic paths — no metacharacter survives to any regex in either mode (spec — the
   grammar is the addressing-vocabulary and path-guard requirements;
   `gateway/settings.py`'s guard is the repo half, see M10/M38). **Re-stated by this
   change:** no path segment is configured into the router's maps — the maps' grammar is
   static and matches paths, never interpolating them — so the injection class stays
   empty at the router (DT-EP6-3).
7. Anti-DoS — the path is checked once at startup against the grammar for configured
   entries; for dynamic paths the guard checks it at request time, where its refusal
   volume is bounded by the rate limits and the byte/segment caps (DT-EP1-15) and its
   records are fixed-vocabulary — the guard holds nothing and allocates nothing.
8. Detective controls — the startup validation refusal is loud and names the
   offending entry for configured entries; the guard's request-time refusals carry
   fixed-vocabulary reasons with the truncated offered path for dynamic paths (both
   the reserved-segment and shape refusals are spec; see M10's placement note).

### T7-1 Tampered store → redirect-URI substitution
1. Reduce Attack Surface — the store exists only if DCR is enabled (default off);
   with it off there is no file to tamper (spec).
2. Isolation — the volume is host material trusted to the same boundary as the
   signing key; inside that boundary no further isolation is claimed (deployment —
   the host/volume owner).
3. Authentication — not applicable: the file is read at startup by the process,
   entitled to read it; there is no counterparty to authenticate.
4. Authorization — no mechanism authorizes store writes beyond the boundary — the
   residual's accepting condition (same class as the signing key, which host write
   can likewise rewrite). Not applicable *inside* the boundary; the boundary is the
   control. **Disposition: accepted (RES-5).**
5. Data Protection — the record shape is fixed (a small field set, no secret), so
   what a tamper can *plant* is bounded to redirect URIs and names — nothing
   confidential to protect (spec).
6. Anti-Injection — the parse is schema-bounded (T7-3); the *use* of planted records
   is authorization-bounded at T1-5's redirect validation against what the store says
   — which the tamper controls; honest: partial, and the partial is RES-5's
   acceptance. **Narrowed by this change:** the redirect-URI scheme admission rule's
   load-time validation (M32) refuses a stored record whose redirect URIs carry a
   non-loopback plain-`http` URI at load, so a record planted on the volume can no
   longer keep a cleartext collector URI usable — the narrowing reaches the tamper's
   redirect-URI *substitution* reach (the planted value must also pass the scheme rule),
   inside RES-5's boundary, not a widening of it.
7. Anti-DoS — not applicable: a tamper is a write, not a volume attack.
8. Detective controls — the audit trail records registrations as they happen; a
   tampered store's records diverge from the trail (registrations the trail never
   saw) — attributable after the fact (spec — the per-flow lifecycle records, placed
   2026-10-30; see M11's placement note).

### T7-2 Corrupt store → startup refusal
1. Reduce Attack Surface — the write path is atomic (temporary file + `os.replace`),
   so the gateway's own writes cannot half-write the store; only out-of-band host
   writes can corrupt (spec).
2. Isolation — not applicable: the failure is the gateway process's own startup, by
   design fail-closed.
3. Authentication — not applicable: a startup read of a local file.
4. Authorization — not applicable: the corruption stops the service before any request exists to authorize.
5. Data Protection — not applicable: availability, not data.
6. Anti-Injection — an unparseable store is *rejected*, not repaired or interpreted —
   no content executes from a corrupt file (spec).
7. Anti-DoS — the honest shape: an attacker with host write can stop the service by
   corruption — but host write is already game-over for T4-1/T7-1; the one-command
   recovery (rename the file aside, restart) is the operator's bound (deployment).
   **Disposition: accepted with RES-5's boundary.**
8. Detective controls — the startup error is loud and names the path (spec).

### T7-3 Hostile JSON content
1. Reduce Attack Surface — the store's record schema is fixed; anything else in the
   file is refused at parse (spec).
2. Isolation — not applicable: a trusted-boundary file parsed by the process that
   owns it.
3. Authentication — not applicable: the file is host-boundary material read at startup by the process that owns it; no counterparty exists to authenticate.
4. Authorization — planted records are *used* only through T1-5's redirect
   validation — the tamper's reach, per T7-1. Partial by acceptance.
5. Data Protection — no secret in scope. Not applicable.
6. Anti-Injection — **the control**: bounded parse (size, depth, schema) of the file
   at startup (spec).
7. Anti-DoS — the cap bounds the file's size at write time (spec).
8. Detective controls — startup parse failures are loud (spec).

## 10. Compromise points

What an attacker gains by compromising each component — the current shape carried
forward (`background/design.md` §6.4, `background/design-review.md` §5.5), with the
as-built rows the local shape adds.

| Compromised component | Attacker gains | Note |
|---|---|---|
| Harness (or its token store) | That one user's gateway tokens → that user's toolset and app access (and every Core endpoint for that `sub`) until expiry; replayable against the user's other proxied resources — toolsets and apps — until `exp`; the refresh token's encrypted custody claim at rest (inert without the custody key — A17) | No other user; no upstream tokens (never-cut 1) |
| Gateway process (keys + process) | Mint-any-`sub`/any-role tokens — the signing-key blast radius: *use* of any user's toolset or app access via the MCP endpoints, never *theft* of upstream tokens; the **dedicated custody key**, which alone mints nothing but with a recorded-token archive replays each archived user's provider identity until that user's provider session dies (the time-decoupled conjunction — RES-21, part ii, **re-priced for the retained-key window, DT-EP4-3**); the **transient plaintext of only the sessions presenting during the compromise window** and the minutes-bounded pending hand-off entries — there is no per-session store to sweep; one in-flight user's identity-provider JWT until that JWT's own `exp` — up to 24 h on the local development realm (its `accessTokenLifespan`); the audit trail; the flow state; write access to the DCR store | Upstream tokens and PKCE verifiers never present; flow TTL bounds the JWT's *retention*, not its life; the custody key cannot reach another user's identity beyond the archived tokens it can decrypt (RES-21, RES-2). The process holds **all keyset entries** — the active key plus every retained one — so the compromise widens with the retained set until the entries are removed (DT-EP4-2/DT-EP4-6) |
| Gateway signing key only | As the process row, remotely, until rotation ≤ Core's JWKS cache (10 min) + access TTL (10 min); **while a superseded key is retained, until the drain window closes or the entry is removed** — the retained-key window the keyset adds (DT-EP4-2), where the thief's mints verify at Core for up to the whole window instead of ≤ cache + access TTL | The KMS sign-interface is the optional stated control and may be abandoned (RES-2); today the key's custody is its injection path — env or read-only file (RES-13). The audience marker does not shrink this radius — an attacker holding the key mints the marker too; no `offlineClient` on the IdP entry (the gateway issuer can never mint offline credentials) |
| Front router (nginx) | Challenge phishing — point `resource_metadata` at a hostile AS; data-path tampering; cleartext read of all MCP traffic and tokens | Same class as any front-router compromise; the synthesis form and config are committed here, the running container's custody is the deployment host's |
| Host (as built: `.env`, key injection paths, DCR store bind mount, Docker) | The signing key and the custody key (read or replace); Keycloak admin and test-user credentials; DCR registration records (read/rewrite); container control — which subsumes every gateway compromise | The host/volume boundary the keys and the DCR store are trusted to; no in-repo control stands below it (RES-13, RES-5). **Re-shaped for the pod:** the boundary is the **node, the mounted volumes, and the injection paths** — the store's volume (its integrity the volume owner's, its class and ownership the contract's statements), the read-only key-file mounts (`file`-sourced entries and the IdP client secret's `IDP_CLIENT_SECRET_FILE` alike), and the env-var surface (the pod spec, the Secret, `/proc` environ); a key's boundary is its injection path, the store's is its volume (DT-EP4-4, DT-EP6-1, DT-EP7-1) |
| Internal compose network (a hostile peer) | Sniff the identity-token presentations and the `/signin` bodies (plain http internal); sniff the **decrypted provider session refresh token** the refresh grant presents once per gateway refresh — the most powerful credential the flow ever puts on the wire (DT-EP5-2's price), for as long as the provider's session policy allows; MITM the gateway↔Core and gateway↔identity-provider legs — worst case forge the gateway's inbound identity verification (the token exchange and the JWKS fetch both ride `http://keycloak:8900`) and cause mint-any-`sub`/any-role issuance, or forge the refresh grant's answer for any-claims-for-an-existing-`sub` (narrower — the `sub` cross-check holds); reach the gateway's `:8091` directly if container-network policy permits | Bounded by the private-bridge placement — for the forgery chain this membership is the load-bearing bound, since the legs are gateway-outbound and the router's port non-publication does not reach them; internal TLS is the deployment's (RES-19, re-priced) |
| DCR store (host volume) | Registration rewrite → redirect-URI substitution (T7-1) — future code capture; no secret material in the store | Same host/volume boundary as the signing key (RES-5); only present if DCR is enabled |
| DIAL Core | Everything it holds today — per-user upstream credentials, verifiers, authorization; Core serves the apps MCP path to gateway-minted tokens exactly as it serves the toolset path (per-call DIAL authorization on both) | Unchanged by this design |
| The identity provider — the local development instance (a Keycloak deployment) | What it holds today, plus the ability to authenticate federation flows (the gateway still gates issuance) | Unchanged |
| The identity provider — external (beyond the compose network, the external-TLS shape) | Mint any-`sub` tokens under the pinned issuer and publish the matching key set, which the gateway's exact pin then accepts — the mint chain from the provider position (T5-2's peer gain relocated beyond the compose network, TB7's trust restated for the internet shape) | **Accepted with reasoning:** the pinned issuer plus its published key set *is* the trust — the provider is the trust anchor by design, and the gateway distinguishes a compromised provider from an honest one in no way, exactly as it cannot distinguish a compromised Core (the Core row's own acceptance); no gateway-side control can bound a party whose assertions the pin exists to trust |
| Upstream AS / toolset operator | The toolset's own data; consent shown to Core's client | Cannot attribute or authenticate the downstream harness (RES-11 is inherent) |
| Browser / user session | Phished consents (T1-2, T3-9), framed auto-continues (T3-5), false attribution read off the interstitial (T1-11, T1-14) | Display-level bound (RES-11) |

### Revocation summary

Carried from `background/design.md` §6.3, with the row this change re-prices stated.

| Revoke what | Mechanism | Latency |
|---|---|---|
| one harness session | E10 + refresh `exp` | access ≤ 10 min |
| one user's proxy access | denylist their refresh `jti`s | ≤ 10 min (access TTL) |
| all proxy access | **emergency only:** the immediate cut — remove the retained keyset entry (`kid` dropped from the JWKS) | ≤ 10 min (Core JWKS cache) + access TTL. **Routine rotation is no longer a revocation mechanism** — under the overlap semantics a routine rotation *drains* (the old key demoted to retained, outstanding tokens kept working through the drain window, each presenting session re-sealing under the active key), so it revokes nothing; the cut — removing the retained entry at any moment, `kid` dropped from the JWKS and the entry from the keyset — is the operator's explicit emergency path, and that is the old row's latency, kept as the emergency path |
| a toolset credential | existing `/v1/ops/toolset/signout` (unchanged) | immediate (Core) |
| the user's DIAL identity at the source | identity-provider session revocation propagates to the gateway's refresh capability at the next refresh attempt — the carried session refresh token dies with the session; the refusal is audited `idp_session_ended` | minted access tokens live at most the access TTL (replaced the snapshot design's "affects future flows, not live proxy tokens") |

## 11. Invariant ruling table

One row per never-cut invariant (`ROADMAP.md`), ruled as the system stands today.

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | **Preserved** | The gateway transits only the upstream authorization code — single-use, PKCE-bound to Core's verifier, useless to anyone else; no upstream token is stored or relayed anywhere; the data path authenticates to Core with gateway-minted tokens only, never a caller's token relayed upstream |
| 2 | The upstream PKCE verifier never leaves Core | **Preserved** | The upstream authorize URL is built from the toolset's public projection (`code_challenge`; Core nulls the verifier on every public read); no new exposure path exists |
| 3 | Per-user credential isolation | **Preserved with a disclosed bound** | Credentials are stamped and resolved per `sub` unchanged; the E7 chain's guessing variant is killed (128-bit ids, state round-trip, destroy-on-first-use); the custody envelope's embedded `sub` is checked at the seam against the refresh token's signed subject, so a blob swapped between users' tokens refuses; the provider-side `sub` cross-check binds every mint — issuance and refresh — to a subject the provider just asserted. The flow never *establishes* a credential at GLOBAL level (the credential call stays USER-level on every establishing path); it *uses* one an operator stored, through the signed-in short-circuit, and the access is the same the same user already holds through Core's own paths. **Ruled explicitly by this change:** a user-bucket resource path (the Base58 ciphertext of `Users/{sub}`) is now front-door-addressable by anyone holding the string — but the string was always client-visible data Core itself hands out, and isolation was never the segment's secrecy: it is Core's `hasReadAccess` chain, applied identically on the data path (per call) and the flow's listing read (per flow), so another user's ciphertext is refused 403 and the owner's own bucket passes (DT-EP1-16). The bound is the interception variant under the plain-http front door — disclosed, not mitigated today (RES-1) |
| 4 | DIAL authorization applies to every toolset call | **Preserved with a disclosed bound — the bound shrinks** | Every call through the front door is validated and authorized by Core, and the flow's per-user listing read (the DIAL authorization check) runs before any upstream stage on every path, the short-circuit included — the read is the deployment-listing route, whose authorization is the data path's own deployment resolution, so the pre-check and the per-call enforcement are one decision and the false denial the prior admin-role availability read carried (refusing non-admin users public toolsets the data path serves) is removed; claims are now as fresh as the last refresh — a provider-side change reaches minted tokens within the access TTL, and an already-minted access token carries its claims only to its own expiry (≤ access TTL) — so the bound is no longer the whole `refreshTtl` but the interval between refreshes plus each token's own life (RES-6) |
| 5 | No credential in logs, argv, or error messages | **Preserved** | Audit events carry flow id, subject, client, toolset, timestamps, results — never tokens, codes, or keys; refusal records are fixed-vocabulary with non-credential facts only; error pages are plain-language and fail closed; the browser-side channel (Referer, cache) is closed by the response-header family. **Extended by this change:** the keyset startup errors name entries by configured id and path, never material, fingerprint, or file content — the existing loader discipline carried per-entry to the new surfaces (the keyset entries, the file sources, the IdP client secret's `IDP_CLIENT_SECRET_FILE` source); the drill's evidence rule is spec'd (kids, key-ids, verdicts, audit records, JWKS snapshots only — never token strings or key material) |
| 6 | No hardcoded credentials in the repository | **Preserved** | `.env.example` placeholders only; the signing key, Keycloak admin credentials, and test-user credentials come from `.env`/injected material; the static gates (bandit, pip-audit) run on every diff |
| 7 | The gateway's signing key is treated as IdP-grade secret material | **Preserved with a disclosed bound** | Never committed (gitignore), never logged, `kid`-published; rotatable — **now proven by rehearsal** (the change's drill) instead of documented-only. The disclosed bound moves: the key's custody is its **injection path** (an injected env var, or a read-only key-file mount on the pod's mounts) rather than the host `.env` alone, and the retained-entry window is the priced addition (RES-13 re-worded, RES-2's amendment, DT-EP4-2); managed-runtime memory residency stands (RES-2) |

## 12. The grouped final mitigation list

The reviewed result: the per-threat proposals grouped, each mitigation associated with
the threats it addresses. **Placed** = normative in this repo (the `mcp-signin`
capability spec, or committed repo material); **named** = where it lives, with its
owner. Every "Placed — spec" home below was verified against the current synced
spec (`openspec/specs/mcp-signin/spec.md`) in the D2 reconciliation; the four
elements that reconciliation found repo-only (M9, M11, M20, and M10's toolset-name
charset — the fourth missed by that verification and caught by the review round) are
now **Placed — spec**, pinned 2026-10-30 by the `pin-implemented-security-behaviors`
change (archived); the elements left un-pinned by owner decision (M7's content-type,
timeouts, and User-Agent; the outbound timeouts and bounded response parsing) remain
**repo**.

| # | Mitigation | Home and owner | Addresses |
|---|---|---|---|
| M1 | 128-bit CSPRNG flow ids, upstream `state` round-trip of the flow id, destroy-on-first-use at E7 | **Placed** — spec (gateway behavior) | T3-1, T3-8 (bounding) |
| M2 | PKCE everywhere: three independent S256 pairs (harness↔gateway, gateway↔identity provider, Core↔upstream); no verifier crosses a boundary | **Placed** — spec; the Core↔upstream pair is Core's (never-cut 2) | T1-3, T1-5, T1-13 (bounding), T3-2 (bounding), T3-3, T5-2 (bounding) |
| M3 | `redirect_uri` validated against the registration on every request — exact match, loopback port exception keyed on the registered entry only | **Placed** — spec | T1-5, T2-5, T3-2 (bounding), T7-1 (use-path) |
| M4 | Strict, required `resource` at E3 and E4 (`invalid_target` otherwise); refresh-time resource match; the one-toolset inference as explicit config only | **Placed** — spec | T1-4, T1-12 (bounding) |
| M5 | Pre-consent DIAL authorization: toolset read-access check before any upstream round-trip; USER-level-only credential establishment | **Placed** — spec | T1-4, T5-4 |
| M6 | Public-endpoint abuse bounds: per-source and global rate limits, hard cap on live flow records with oldest-first eviction, plain-language bounded error pages | **Placed** — spec. Extended: the apps protected-resource route joins the shared per-source and global limiter, with over-limit requests writing no record; and the caller-chosen-length member gains the **`state` bound** — a `state` over 2048 bytes refused `invalid_request` with the fixed-vocabulary reason `oversized_state`, before the record exists (DT-EP1-3's narrowing, the authorization-requests requirement's amendment, D8) | T1-6 (with the `oversized_state` bound), T1-7, T1-8 (bounding), T2-2 (bounding), T3-7 (bounding), T3-10, T4-5, T6-6 (gateway side), T1-24 (bounding), DT-EP1-3 (the narrowing) |
| M7 | CIMD SSRF control set: HTTPS only, operator origin allowlist, no redirects followed, all-record IP-range validation with connection pinning (Host/SNI preserved), size cap, JSON content type, timeouts, TTL cache, explicit User-Agent | **Placed** — spec (the bound set the requirement MUSTs: HTTPS-only, allowlisted origins, no redirects, private/loopback/link-local refused, size cap, cache); the finer mechanics are **repo** (implementation + tests) — the all-record checks and connection pinning implement the spec's address-refusal MUST, while the JSON content type, connect/total timeouts, and explicit User-Agent are their own controls the spec does not pin (tightened 2026-10-29: the earlier note called all of them an implementation shape of the spec's MUSTs, which is true only of the address-refusal mechanics; whether the unpinned ones join the candidate spec changes is an owner call) | T2-1, T2-3 (bounding), T2-4, T2-5 (bounding), T2-6 |
| M8 | HTML hardening family on every page class via one shared helper: CSP `default-src 'none'` + `base-uri 'none'`, `frame-ancestors 'none'` + `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` + explicit charset; escaping of all reflected values; script-free pages. Extended by this change: the CSP gains **`form-action 'self'`** (stated family-wide on the policy every page carries, so no page class can drift off it) and the page-class enumeration gains the **decision page**, which inherits the family by construction through the one builder and joins the header-assertion tests; the decision page carries no auto-continue (no `meta refresh`) | **Placed** — spec (the header family, the `form-action 'self'` directive, the script-exclusion property, and the decision page's no-auto-continue rule; the escaping mechanism is its repo implementation) | T1-10, T2-3, T3-4, T3-5, T3-6, T3-8; DT-EP3-1, DT-EP3-2; carries DT-EP1-4's data-protection half and the page-content controls |
| M9 | Token design: 10-minute access TTL, 8-hour non-sliding refresh (original absolute `exp` frozen at issuance) carrying no claim snapshot — its one non-binding payload member is the encrypted custody claim (ciphertext, never a mint input), so the refresh mint's claim input is the verified fresh read; the access token's `aud = [resource, dial-mcp-proxy]` while the refresh token's `aud` is the resource alone (the marker never included — the token-type separation); RFC 9207 `iss` in authorization responses; 5-minute single-use codes with `jti` replay cache; refresh rotation with denylist-by-`jti` | **Placed** — spec (the lattice: short-lived access, non-sliding startup-bounded refresh, single-use PKCE-bound codes, rotation + denylist, audience marking and the snapshot-free refresh token; the concrete TTL numbers are the deployment's operator settings within the spec's bounds); the **RFC 9207 `iss` parameter placed 2026-10-30** — the spec now carries it (the `pin-implemented-security-behaviors` change, archived) | T1-1 (bounding), T1-3, T1-5 (bounding), T1-12, T1-13, T1-16 (bounding — the TTL lattice and rotation + denylist), RES-6/7/8's bounds |
| M10 | Startup-enforced bounds: `refreshTtl` ≤ the operator-declared identity-provider session bound (`IDP_SSO_SESSION_MAX_SECONDS`); reserved first segments mirroring the router's alternation for *configured* restriction entries (the OAuth-only mapping declaration is removed — a non-OAuth toolset is a valid entry); the decoded per-segment path rules (Core's forbidden set, a trailing-dot ruling, `.`/`..`/empty-segment refusal, the 900-byte decoded-path cap and the segment-count cap); loud refusal on corrupt DCR store and absent roles source path. The request-time path guard and the flow's kind branch are the moved halves (dynamic paths and the kind decision). Extended: the request-time path guard reaches the apps namespace with the same decoded per-segment rules the router's apps map mirrors (no reserved-segment check there — nothing gateway-owned lives under the apps first segment) | **Placed** — spec (the startup refusals and the request-time guard); the **decoded per-segment rules** placed by the `pin-implemented-security-behaviors` change as a one-segment `[a-z0-9-]+` charset and **re-based by this change** onto the path grammar (the addressing-vocabulary and path-guard requirements); the refresh-window bound re-derived onto the renamed session-bound setting; the apps-namespace extension is this change's delta spec, the rules repo | T1-8 (bounding), T5-3 (bounding), T6-2, T6-7, T1-16 (bounding — the startup-bounded refresh lattice), T1-23 (the app path guard), T1-24 (bounding), RES-6's bound |
| M11 | Audit trail over the whole request lifecycle: fixed-vocabulary refusal records with non-credential facts (client id, redirect URI, resource, toolset) — no free-form caller input, no tokens/codes/keys; per-flow records (flow id, `sub`, client, resource, timestamps, results) | **Placed** — spec (the refusal records; **the per-flow lifecycle records placed 2026-10-30** — the spec now carries them via the `pin-implemented-security-behaviors` change, archived); the resource-kind fact and the app flow's records are this change's delta spec | T1-9, T1-11 (detective), T1-14 (detective), T1-16 (detective — the per-flow records), T1-6/7/8, T2-*, T3-1/7, T3-10, T5-5 (detective), T5-6, T5-8 (detective), T7-1 (detective) |
| M12 | Fail-closed plain-language error pages; unknown-flow callbacks resolve to nothing and allocate nothing | **Placed** — spec | T1-8, T3-7, T3-10, T5-5, T5-6 |
| M13 | Keycloak provisioning convergence: confidential client (client secret, per the 2026-11-05 ruling — the secret required in both toggle positions of the leg's PKCE setting) with PKCE S256 on top, exactly the managed default scopes (never `offline_access`; no second role source), claims verified by a driven flow; admin credentials from `.env`. Amended: `offline_access` is still never requested and no offline grant is ever acquired, but the session-bound refresh token the exchange issues is carried — encrypted under the gateway's dedicated custody key, inside the gateway's own refresh token — for the refresh window instead of discarded; the plaintext never leaves the gateway process; the trade is priced as RES-21 | **Placed** — repo (provisioning script) | T1-1 (bounding — no offline refresh token ever minted for the flow), RES-14 (bounding), RES-21 (the priced trade) |
| M14 | Core identity-provider entry for the gateway: `issuerPattern` on every provider (the gateway's flat issuer, non-overlapping), `audience: dial-mcp-proxy`, `rolePath: roles`, `loggingKey`/`loggingSalt` parity; `allowedRedirectUris` gains the E7 callback | **Named** — Core configuration, owner: the deployment administrator (the required values are pinned normatively in the repo's spec) | T1-4, T4-4, T6-1 (bounding — only two accepted issuers) |
| M15 | The router: challenge synthesis by `map $status` + `proxy_hide_header` (a 401 carries the gateway's challenge and nothing of the upstream's), configured `$mcp_origin` (never `$host`), `$is_args$args` query survival, the end-anchored `map $request_uri` data-path grammars, the ordered authorization-surface regexes before the data-path prefix locations, the stated `large_client_header_buffers` bound | **Placed** — repo (committed router config in this repo's compose) | T1-2 (reduced material), T6-1, T6-2, T6-3, T6-7 (the static committed config); the well-known locations' precedence with M44 (DT-EP6-7, DT-EP6-8) |
| M16 | Topology: the gateway's `:8091` never host-published (the router is the sole front door and peer-identity authority); the gateway and router in this repo's compose joined to the instance's network as an external network | **Placed** — repo (compose + router config, stated as a topology invariant) | T6-4, T5-1 (bounding) |
| M17 | Signing-key discipline at the as-built bar: generated RSA key, gitignored (repo rule), injected, never logged, `kid` published at E8, rotation procedure (publish new `kid` → wait Core's JWKS cache TTL → retire). **Amended by this change — the KMS split:** the **signing sign-interface is optional and may be abandoned** (the KMS-held key where the process holds a reference, not a key), while the **custody envelope is the firm planned post-go-live step** (a deployment-wide CEK, KMS-wrapped, the wrapped blob on the mounted volume, unwrapped at startup). Both keysets configured simultaneously (an injected signing key beside a KMS-wrapped custody CEK) MUST be supported when the custody envelope lands — the per-entry seam (M34) already is. The key's custody is its injection path meanwhile (RES-13) | **Placed** (discipline) — repo rules + spec; **the signing KMS/HSM sign-interface is Named (optional)** — deployment, owner: the deployment owner (may be abandoned); the **custody envelope is Named (firm planned)** — deployment, owner: the deployment owner (post-go-live) | T4-1 (bounding), T4-2 (bounding), T4-4 (bounding), RES-13's record |
| M18 | TLS on the public origin (and HSTS at the TLS listener; TLS on internal legs where the deployment demands it) | **Named** — deployment, owner: the deployment owner; today unplaced — the accepting residuals are RES-1, RES-12, RES-19 | T1-1, T1-2, T3-2, T3-9, T6-5, T5-1, T5-2, T4-4 |
| M19 | Static gates on every diff (ruff, mypy, bandit, pip-audit — blocking) and the per-page-class header-assertion tests; the routing probe battery before harness runs | **Placed** — repo (gate ladder) | T1-10 (regression guard), T2-4, T6-2, T6-3, RES-16's bound |
| M20 | JWT verification hygiene: pinned RSA256 verification (the signing key's own algorithm, the key passed directly so embedded-`jwk`/`x5c` headers and `kid` steering never select key material; the provider leg's `kid` looked up only in the provider's own JWKS), maintained verification library (`pyjwt[crypto]`), bandit/pip-audit on every diff | **Placed** — spec as of 2026-10-30 (the verification-hygiene requirement — pinned algorithm and key selection, the `kid`-less fallback stated — now exists via the `pin-implemented-security-behaviors` change, archived; the implementation and the gate ladder remain the repo half) | T4-7, T1-8 (bounding) |
| M21 | The custody envelope and the snapshot-free refresh: the provider's *current* session refresh token (latest-wins across its rotations) carried as an AES-256-GCM claim (`version | key-id | nonce | ciphertext‖tag`, pinned constants, key-id from a fixed keyset, embedded `sub`/`exp` checked at the seam) inside the gateway's own refresh token only — never the access token, never the authorization code; under a dedicated 256-bit custody key separated from the signing key; **amended by this change — the overlap semantics replace the hard cut:** the key is a keyset with per-entry sources and active/retained roles, sealing **always under the active key**, decryption accepting the active or a retained key (the envelope's key-id selecting the entry, the header still bound into the AEAD's associated data per entry so a transplanted header fails the tag under whichever key it names), and a superseded key retained for the drain window (bounded by the refresh token's non-sliding absolute expiry) keeping every outstanding refresh token working through a routine rotation — each such refresh decrypting under the retained key-id and re-sealing under the active one; **removing the retained entry is the immediate cut**, the operator's explicit emergency path rather than the routine outcome, its refusal this requirement's own custody refusal class (DT-EP4-3); the flat compat spelling (key-id → base64 key, no source or role) remains exactly one active `env`-sourced entry; the plaintext never logged and never delivered to any client (the ciphertext is, by design); the transit from flow end to code grant is the minutes-bounded pending entry keyed by the code's id; a configured provider-token size bound refused loudly at sign-in; the form-body cap raised and re-priced; the grown token's round trip through both field harnesses' stores gated before adoption; the refresh-grant claims re-read and the fail-closed refresh semantics (the `custody_decrypt_failed`/`claims_read_failed`/`idp_session_ended` classes through the closed reason table); no `offline_access` ever requested — the capability acquired is session-bound by construction | **Placed** — spec (the envelope, carrier, key, refresh re-read, refusal classes, bound, and refusal); the cap value and the key slot are repo settings; the harness round-trip gate is repo | T1-17 (bounding — the session clock), T1-18, T1-19, T4-8, T5-1 (bounding), T5-2 (the artifact bound), T1-16 (the fresh read), T1-7 (the per-request cost), **DT-EP4-3** (the custody half of the retained-key windows) |
| M23 | The flow's routing decision on its own listing read — the signed-in check (user OR global level, unreadable/FAILED fails closed into the kind branch) short-circuits the upstream stage for any kind; the kind branch runs the consent leg only for OAUTH and refuses the impossible branch (any other kind, no stored credential) with a plain-language audited page; the use-vs-establish rule is normative (the credential call stays USER-level; the short-circuit never reads or transits any upstream credential; a global credential is used, never established); the listing read's refusal classes are four distinguishable shapes on page and trail — no-access (403) / unknown-toolset (404) / trust fault (401, Core could not validate the sign-in's identity token — the operator-facing fault page, fixed vocabulary) / deployment fault — the 401 never answered or audited as an access denial | **Placed** — spec | T1-21, T1-22 (bounding), T5-7, T5-4 (the establishment-side refusal) |
| M24 | The apps front-door surface — the `/apps/{path}/mcp` path shape with its own prefix-anchored resource-URI derivation (disjoint from the toolset's by construction); the app path guard (the decoded per-segment rules + the apps restriction, no reserved segments, with the reason); the apps protected-resource document (static, path-derived, always-empty `scopes_supported`, no kind extension, zero Core calls — the mirror property extended to the second namespace); the apps discovery route inside the shared limiter with the no-record-over-limit rule; the router's `/apps/` prefix location driven by the `map $request_uri` `$apps_target` grammar (whole-request-URI match domain, the `if` refusing 404, query pass-through, no buffering) and its second challenge map quoting the app's own metadata path | **Placed** — delta spec (the path shape, guard, document, limiter clause, challenge and query scenarios); the router config and the probe rows are repo | T6-8, T1-24 (bounding), T6-2 (the apps map/location), T6-3 (the apps path) |
| M25 | The app flow's stage order — the identity leg, then the per-user app read (403 no-access / 404 the apps existence refusal audited as `unknown_app` / 401 the trust fault — the same class the listing read's split carries, both reads sharing the gateway's one answer-to-refusal mapping, never an access denial / unreachable-or-unreadable the operator-facing fault page, never an existence answer), then the unconditional kind-driven short-circuit minting the code with one fixed-vocabulary audit record (`credential_free_short_circuit`) naming the resource kind — decided by C1's general rule, no new mechanism; the corrected audience wording (the marker is what Core verifies; the resource audience is the gateway's addressing discipline) | **Placed** — delta spec (the app-resource requirement, the flow requirement's declared existence-refusal amendment, the token requirement's declared enforcement amendment) | T1-23, T5-8 (the residency of the app read and the gate before the mint), T1-12 (bounding — the gateway-side resource checks) |
| M26 | Discovery-document validation: the document's `issuer` member equal to the configured issuer exactly and every used endpoint (authorization, token, key set) sharing the configured issuer's or the back-channel override's origin; plain `http` refused without the explicit override; redirects not followed; the response size-capped; a document failing any check refused whole, never used partially | **Placed** — spec (the discovery-validation requirement) | T5-9; bounds the override deployments' widened RES-19 record (credential-bearing calls go only to origins the operator configured) |
| M27 | The discovery cache: lazy first use, at most one fetch per TTL per process whoever triggered the need — a failed or refused fetch recorded for the same window and served from it (the negative half, which keeps the one-fetch bound in the provider-unreachable and document-refused regime), a success ending the record — an endpoint change at the provider propagating within the TTL; the fetch riding the existing outbound discipline (timeout, no redirects, size cap) | **Placed** — spec (the discovery requirement); the failure record is implementation | T5-10; T5-5's discovery widening (bounding) |
| M28 | The confidential-client rule (the 2026-11-05 ruling): the client secret required at startup in both positions of the leg's PKCE toggle (a missing or blank secret refuses startup naming the setting) and the exchange and the refresh grant authenticating with it in both — client authentication plus PKCE in the default mode, the secret alone in the challenge-off mode, never PKCE alone; the toggle governing the challenge/verifier only; the client-facing authorization surface keeps requiring PKCE from harness clients; the secret never logged, never echoed in an error, never delivered to any client | **Placed** — spec (the confidential-client requirement) | T5-11 (the inherent control; the residue **RES-24**), T4-9 (the blast-radius bound), DT-EP4-1's detective half (the existing refusal vocabulary) |
| M29 | Exact issuer pinning with the varying-issuer scenario: the issuer check is exact-string against the configured issuer at issuance and refresh, another journey's issuer of the same provider refused, and a discovery document advertising a different issuer refused whole — no token and no document can widen the pin | **Placed** — spec (the verification amendment) | T5-12 |
| M30 | Direct-mode startup validation with fail-closed staleness: the all-or-nothing endpoint trio refusing startup on a partial set (naming the configured and the missing members) and on a malformed or non-absolute value; every configured endpoint a well-formed absolute URL, HTTPS unless it shares the back-channel override's origin; no discovery fetch attempted where the full set is configured; a wrong or stale endpoint failing the leg closed with the fixed-vocabulary operator-facing error and no fallback construction. The operator reference states the mode's trade (the operator owns endpoint freshness) and the override's origin-as-trust-claim warning (repo) | **Placed** — spec (the direct-configuration requirement); the operator reference's statements are repo | T5-13, T5-14; in direct mode removes T5-9's and T5-10's attack classes entirely (no provider-asserted input, no fetch) |
| M31 | The consent/attribution checkpoint: the per-(subject, client_id) approval registry consulted after the identity leg and before **every** mint, on all three mint paths (the app kind's zero-page short-circuit, the toolset stored-credential short-circuit, the toolset consent branch); the decision page naming the resolved client (name, client id), the addressed resource, and the registered `redirect_uri`; the `POST /dial/consent` action bound to the flow id, single-use-per-flow, consuming on deny, recording-and-continuing on approve; the three fixed-vocabulary audit events (`attribution_required`/`attribution_approved`/`attribution_refused`). The registry's in-memory bound stated: **single instance, process memory, no TTL, a hard cap with oldest-first eviction** — a restart forgets approvals (every user re-approves every client once) and eviction forgets the oldest first, both fail-safe (re-prompt, never bypass), the **RES-15 acceptance class extended to one more in-memory store**, named; entries are (subject, client id) pairs, non-credential facts, with one write path (the approve action on a live, identity-completed flow). The checkpoint's dwell effect on the two short-circuit paths, stated: a flow parked at the decision point carries the provider's session refresh token on its record for the user's decision time — previously ~0 (the short-circuits minted immediately) — bounded by the flow TTL (600s; the recorded flow cap's lifetime), fail-safe at identity expiry, dropped immediately on deny; the consent branch always had human-decision dwell (the upstream consent screen), so the short-circuits join a priced class rather than create one | **Placed** — spec: the ADDED **"The consent/attribution checkpoint gates every mint on first attribution"** requirement (its `First attribution renders the decision page and no mint runs`, `The decision page names the client, the resource, and the redirect destination`, `Approve records the attribution and continues the flow`, `Deny consumes the flow with no code issued`, `A replayed or foreign POST advances nothing`, `The action carries only the flow id and the decision`, and `No operator bypass for a pre-registered client` scenarios) and the ADDED **"The approved-client registry is keyed per subject and client and fails safe on loss"** requirement (its `An approved attribution is consulted and passes through`, `The approval is the client's, not one resource's`, `Registry loss re-prompts, never bypasses`, and `The registry has one write path` scenarios); the insertion on the three mint paths carried by the **federation-flow** requirement's amendments (the `First attribution on the stored-credential short-circuit renders the decision page`, `An approved client passes the short-circuit untouched`, and `First attribution on the consent branch replaces the display interstitial once` scenarios) and the **app-resource** requirement's amendment (the `First attribution on the app kind's zero-page short-circuit renders the decision page` scenario); the three audit events carried by the **flows-are-audited-through-their-lifecycle** requirement's amendment (the `The attribution events are recorded in sequence` scenario). The router alternation's `consent` segment and the probe rows are repo | **T1-25's drive-by shape — the deferred-to-mitigated flip** (the EP1 table row and DT-EP1-4); DT-EP1-1 (the forged-approval control), DT-EP1-2 (the flooding bound), DT-EP1-4; bounds DT-EP3-3 (the page's verifiable-facts rule) |
| M32 | The redirect-URI scheme admission rule: a registered redirect URI MUST be `https`, or `http` on a loopback host (`localhost`, `127.0.0.1`, `[::1]`, any port — the RFC 8252 §7.3 shape the port-ignoring match already knows), enforced at **four** admission sites — the DCR registration body check, the CIMD document validation (a document carrying a non-loopback `http` entry refused whole), a startup refusal for pre-registered configuration (naming the entry), and the durable DCR store's **load-time validation** (a stored non-conforming record refused loudly at load, naming the record, in the corrupt-store discipline's shape). Loopback `http` is excepted, so no conforming fielded harness's registration changes behavior. The load site's planted-record shape is T7-1's existing price — the load-time refusal narrows that row's reach, noted there | **Placed** — spec: the **"Client registration resolves pre-registered, CIMD, then gated DCR clients"** requirement's amendment (its `An http collector URI is refused at DCR registration`, `An http redirect URI in a CIMD document is refused`, `A pre-registered http redirect URI refuses startup`, and `Loopback http remains admitted` scenarios) and the **"DCR registration records are durable across restarts"** requirement's load-path clause (the `A stored non-loopback http redirect URI refuses startup at load` scenario, the fourth site); the pre-registered refusal rides the startup-bounds family (M10); the DCR body check and the CIMD validation implementations are repo | DT-EP1-5 (discharges RFC 9700 §2.6's MUST NOT and the MCP authorization specification's redirect-URI MUST — B-1/B-3, owner-accepted 2026-11-07, D11); narrows T7-1's reach (the load-site clause) |
| M33 | The redemption-replay revocation: on the detected replay of an authorization code, the code grant denylists the refresh token the first redemption minted — the replay memo gains a `code_id → refresh_jti` field (bounded by the code's own short TTL; no replay is detectable after the code expires), and the replay refusal's path makes one `TokenDenylist.revoke` call (the same call `/dial/revoke` makes), on the existing in-memory self-expiring stores — no new surface, route, page, or unbounded state. **Two partials stated as the clause's bound:** the access token the first redemption minted ages out unrevoked (bearer, short TTL — M9's standing bound, which the SHOULD tolerates), and an already-rotated refresh successor survives (no code_id→successor map exists — bounded by the replay detection's timing and the non-sliding absolute expiry). The rotation-chain-tracking memo is the **recorded known extension, not built** | **Placed** — spec: the **"Issued tokens are gateway-signed and audience-marked"** requirement's code-clause amendment (the `A replayed code kills the refresh token it bought` scenario — the delta lands the rule in that requirement's own code clause, not the public-endpoints requirement) | DT-EP1-6 (discharges RFC 9700 §4.2.4's SHOULD — B-2, owner-accepted 2026-11-07, D12) |
| M34 | The keyset semantics, the per-entry sources, and the pre-publish rule: both keysets share one entry schema (`source`/`ref`/`role`) with `env`/`file` implemented and `kms` a reserved value refused at startup naming the gap; exactly one active entry, any number retained, sign/seal under the active key only, verify/decrypt with the active or a retained entry (`kid`/key-id selecting within the startup-fixed set), unknown `kid` refused; the JWKS publishing every entry's public half with the active entry first; the duplicate-derived-`kid` refusal; the per-entry named startup refusals (zero-active, multi-active, unreadable/unparseable file naming the path never the content, reserved `kms`); the **pre-publish rule** (a key about to become active has its `kid` published for at least the deployment's Core JWKS-cache window before it signs — the staged add-as-retained → wait → promote procedure with no third role); the compat spellings (the singular signing setting; the flat custody document, one spelling per document — mixing refuses); retained entries bounded by the refresh token's non-sliding absolute expiry, removal the immediate cut; the **IdP client secret's two spellings** (`IDP_CLIENT_SECRET` env, `IDP_CLIENT_SECRET_FILE` read-only mounted file) with the both-configured refusal naming both settings, the read-once file loader, and the unreadable/blank refusal naming the path never the content — the same seam/discipline carried to the one secret outside the keysets. No key material, fingerprint, or file content reaches any error or log line (invariant 5) | **Placed** — spec: the **"The signing key is a keyset with per-entry sources and active and retained roles"** requirement (all its scenarios) and the **custody requirement's keyset amendment**; the **identity-leg confidential-client requirement's delivery clause** (the file spelling and its refusals); the keyset documents are repo settings | DT-EP4-2 (bounding), DT-EP4-3 (bounding), DT-EP4-4 (the sources), DT-EP4-5, DT-EP4-7, DT-EP1-10, DT-EP1-11 (the pre-publish rule); re-prices RES-13, RES-21 part ii |
| M35 | The pod contract as a versioned repo document (the requirement plus the committed `docs/pod-contract.md`): the image facts (non-root fixed uid/gid 10001, one container-internal port, no baked secret, the scanner gate), the classified env-var surface, the nginx conf as the versioned mountable file with the sibling-localhost upstream, the volume mounts (the DCR store's as a named MUST with its cloud-backed storage-class requirement, deployment-owned atomic-replace export story, and load-bearing no-secret-content rule; read-only mounts for every file-sourced secret — the keyset entries' key files and the IdP client secret's `IDP_CLIENT_SECRET_FILE` alike), the ports and probes, the **security-context section** (runAsNonRoot/uid-gid 10001, fsGroup 10001 on the store's volume, no privilege escalation, all capabilities dropped on the stated no-privileged-port assumption, read-only root with `emptyDir` for the router's temp/log paths, runtime-default seccomp), the **store's governance/storage-class statements** (the cloud-backed persistent-volume requirement by its properties, the deployment-owned export story, the load-bearing no-secret rule with the future wrapped-CEK file named as the volume's future second resident), the **renderer-independent deployment diagram**, and the single-replica assumption — accepted by DevOps review with explicit confirmation (silence is not acceptance), executed locally by the namespace-shared composed stack. The secret-delivery statements are requirements-and-options only, stated neutrally: run-time-only delivery, two spellings per secret (environment variable or read-only mounted file, both supported, exactly one configured), no preference between them — the deployment chooses, the boundary price is the deployment's | **Placed** — spec: the **"The deployment unit is a single pod defined by a versioned contract"** requirement (all its scenarios); repo: `docs/pod-contract.md` (task 5.1/5.2) | DT-EP6-1, DT-EP7-1, DT-EP6-2's mechanism; carries DT-EP4-4's mount statements (the identity-leg requirement's delivery clause carrying the IdP secret's file spelling and its refusals); re-prices RES-5, RES-15; DT-EP6-1's restatement — the committed conf carries the well-known closure (M44) |
| M36 | The migration drill as the standing evidence control: the live rotation of **each keyset** on the pod-shaped production-image stack with captured evidence, the **negative control first** (a deliberately wrong expectation — an old-`kid` token asserted to verify after its retained entry is removed — run and failed before any verdict is trusted), the signing leg (old-key access tokens accepted at Core, old-key refresh tokens refreshing and minting under the new `kid`, new sign-ins accepted throughout, the cache wait observed or bounded, the post-drain removal's refusals) and the custody leg (live sessions decrypting under the retained key-id and re-sealing under the active one across the rotation, the removed-key mid-window presentations refusing in the custody refusal class); the evidence-hygiene rule spec'd (kids, key-ids, JWKS snapshots, audit records, probe verdicts only — no key material, no token strings, no envelope contents) | **Placed** — spec: the **"A live rotation drill gates the keyset semantics' completion"** requirement (all its scenarios); repo: the scripted legs under `scripts/` and the evidence in `docs/evidence/c3/` (group 6) | DT-EP1-11's proof, DT-EP4-6's procedure-includes-removal, DT-EP4-2's and DT-EP4-3's cut-is-proven; validates the drill's custody extension (P3) |
| M37 | The resource-path identity rule: one **canonical encoding** per resource path (unreserved raw, everything else `%XX` uppercase hex over UTF-8), derived by segmentation-precedes-decoding with strict-UTF-8 decode and `+`-literal (`gateway/settings.py`'s `canonical_path`), the flow record / token audience / refresh match / restriction membership all keyed on the canonical form; the Core reads addressed by the canonical encoding (fixed prefix + canonical path, never a raw caller substring); the credential call's `url` member carrying the decoded path (JSON-encoded) | **Placed** — delta spec: the **"Resource paths are the front door's addressing vocabulary"** requirement (the canonical-encoding clause and its scenarios) and the **federation-flow** requirement's read-spelling amendment | DT-EP1-12, DT-EP1-13 (canonical identity), DT-EP5-4 (the URL build), DT-EP5-5 (the body member); bounds RES-7's widened address |
| M38 | The decoded path-shape refusal: per decoded segment the guard refuses `{`, `}`, `"`, any character ≤ U+001F (Core's forbidden set), a trailing dot (a front-door ruling), and `.`/`..`/empty segments; the reserved-first-segment rule (`/dial/` namespace only); each refusal a fixed-vocabulary reason on the audit trail with the offered path truncated. The router's challenge is built only from its own fixed template plus a grammar-conforming capture, so the forbidden characters never reach the header's quoting; the HTML pages' shared escape discipline is proven for path-shaped percent-encoded inputs (task 3.6), widening T3-4/T3-5's existing escaping class | **Placed** — delta spec: the **"Resource paths are guarded at request time"** requirement (all its scenarios); the routing grammar's static config is repo (`router/nginx.conf`) | DT-EP1-14 (the decoded check), DT-EP5-5 (the `{}"` refusal); T3-4/T3-5 (the page-interpolation widening); T6-7's re-statement (no name enters the config) |
| M39 | The raw-URI map with the segment grammar: one `map $request_uri` per kind (the raw, never-decoded URI) whose pattern is the wire-form grammar (unreserved-or-`%XX` per segment, unambiguous alternates, doubled classes for the brace-quantifier parse), end-anchored with an optional `?query` tail and nothing else after `/mcp` (the whole-raw-request-URI match domain); a bare prefix location with `if ($target = "") { return 404; }` and `proxy_pass http://core$target$is_args$args`; the stated `large_client_header_buffers 4 8k` bound; the byte and segment caps on the gateway side. Byte-faithful forwarding | **Placed** — repo: `router/nginx.conf` (the committed config) and `gateway/settings.py` (the caps); the behavior is asserted by the probe battery (M41) and the delta spec's addressing scenarios | DT-EP1-15 (the caps bound the flood), DT-EP6-3 (the lockstep surface), DT-EP6-4 (backtracking), DT-EP6-5 (the prefix capture); T6-2, T6-3 (re-priced), RES-16's widened bound |
| M40 | The three-callback allowlist runbook: `aidial.toolsets.security.allowedRedirectUris` carries the gateway's callback **first**, then Chat's and Admin's, with the ordering's reason stated (Core stores the first entry of the upstream's DCR response as the toolset's stored `redirect_uri`; a conforming DCR server echoes the registered list in order); the **repair** procedure per dynamically-registered toolset (`POST /v1/ops/toolset/{bucket}/{path}/repair`, with its consequence stated — new client id, credentials cleared, one re-consent); the hand registration of the gateway callback at statically-registered upstream clients; the deployment obligation stated in the pod contract | **Named** — Core configuration, owner: the deployment administrator; repo: `docs/local-environment.md` (the runbook), `docs/gateway-configuration.md`, and `docs/pod-contract.md` (the deployment obligation) | DT-EP3-4 (the allowlist-gap mis-use); the operational home of the derived-callback prerequisite (M42) |
| M41 | The lockstep probe battery, negative controls first: the shapes both sides admit and both refuse asserted identical across the router's map and the gateway's guard surfaces (`scripts/probe_front_door_paths.py` + the extended `scripts/probe_routing.py`), the **documented asymmetry** asserted as the asymmetry it is (a wire-conforming guard-refused spelling forwarded on the data path, its challenge dead-ending at 404 — same-answer-as-Core), the byte-fidelity rows (`%20`, `%3F`, `%25`, non-ASCII, `%2F` forwarded verbatim), the match-domain rows (a query-bearing request routed, a post-`/mcp` tail refused), the user-bucket ciphertext shape, and the pathological-URI row | **Placed** — repo: the scripts (the change's failing-first instrument); the assertions are the delta spec's scenarios | DT-EP6-3, DT-EP6-4, DT-EP6-5, DT-EP6-6 (the recurring detector), DT-EP1-12/13/14/15 (the guard rows), RES-16's compensating control |
| M42 | The derived upstream callback: the consent branch's authorize URL and the credential call's `redirectUri` carry `{GATEWAY_PUBLIC_ORIGIN}{UPSTREAM_CALLBACK_PATH}`, computed from configuration; the stored `auth_settings.redirect_uri` member is no longer read on any leg, so no editor of the toolset can steer the consent's destination | **Placed** — delta spec: the **"The upstream authorization request arrives complete"** requirement (the never-read clause and its scenarios) and the federation-flow requirement's `url`/`redirectUri` clause | T5-3 (the row narrows — the member leaves the flow's inputs); the derived-callback mitigation the T-EP3-a threat records |
| M43 | The AS-metadata alias set: the canonical handler and the one `authorization_server_metadata()` builder registered on `/.well-known/openid-configuration` and the two path-insertion forms (`/.well-known/oauth-authorization-server/{suffix}`, `/.well-known/openid-configuration/{suffix}`), byte-identical bodies; `issuer` the public origin always, never the suffix; no OpenID Provider member (`subject_types_supported`, `id_token_signing_alg_values_supported`, `userinfo_endpoint`, an `openid` scope — none added); `GET`-only with the framework's `405` on every other method; no `Access-Control-*`; the canonical route's cost (no Core call, no record, no state) | **Placed** — delta spec: the discovery requirement's alias paragraph and its four scenarios; unit rows pin the byte-identity, the issuer, the absent members, and the methods | DT-EP1-17, DT-EP1-18 (bounding), DT-EP1-19 (bounding) |
| M44 | The closed well-known namespace: the router's plain-prefix `location /.well-known/` and exact `location = /.well-known` answering `404` with the fixed literal `{"detail":"Not Found"}` as `application/json` and the fixed discriminator header `X-Content-Type-Options: nosniff` (added `always`), for every method on any request the server-level bounds admit — no CORS header, no challenge header, never forwarded — consulted only after every regex location (never `^~`); the alias-family regex to the gateway, ending `(/\|\z)`; Core's two protected-resource templates forwarded to Core by an end-anchored location (`^/\.well-known/oauth-protected-resource/v1/(toolset\|deployments)/.+/mcp$`) gated on a raw-URI map (`$core_prm_raw` over `$request_uri`, the M39 discipline), so only a raw URI that is itself one of Core's templates is forwarded and every other spelling is handed to the closure; the catch-all's raw-URI check (`$wk_raw_spelling`) handing any raw path spelled in the namespace (separators `/` or `%2F`, percent-escapes read as the characters they encode) to the closure instead of Core; the closure carried in the committed conf the pod runs, which any other fronting must reproduce | **Placed** — delta spec: the well-known-namespace requirement and the Core-coexistence amendment; repo: `router/nginx.conf` | DT-EP6-7, DT-EP6-8, DT-EP6-9, DT-EP6-10; DT-EP6-1's restatement |
| M45 | The well-known probe rows, controls first: the Core control (Core's own `401` and trace header on its own port) and the gateway control (the gateway's own `404` through the front door, the discriminator header absent) before any front-door verdict, the failing-first run against the pre-change stack, the alias byte-identity and issuer rows, the closure rows (root PRM, unknown paths, every method, the exact body and the discriminator header), the precedence rows (the served discovery documents unchanged), the Core same-answer row, the off-template rows, the boundary rows (the alias regex's and the Core template's end edges), the normalization rows in both directions with encoded-dot variants and `%0A` (sent by a verbatim-path client), and the path-appended rows (the data path's refusal, never Core's answer) | **Placed** — repo (`scripts/probe_routing.py`, the gate ladder M19 runs) | DT-EP6-7, DT-EP6-8, DT-EP6-9, DT-EP6-10, DT-EP1-17 (detective) |

Threats with no mitigation are the accepted residuals of §3 — every one traces to at
least one table row above, and every residual's record carries its three parts.

## 13. Dispositions

Every threat of §8, mapped to its verdict — the form the security review gate reads in
one pass; the per-threat grids (§9) carry the same dispositions inline.

| Threat | Disposition |
|---|---|
| T1-1 | Mitigated to its bound (M9's TTL lattice, rotation + denylist); the cleartext wire accepted — **RES-12**; cross-toolset validity accepted — **RES-7** |
| T1-2 | Mitigated to its bound (M15's synthesis form, M14's two-issuer rule); the plain-http transport remainder accepted — **RES-12** |
| T1-3 | Mitigated to its bound (M2/M4/M9); marker-level audience binding accepted — **RES-7**; no per-user kill — **RES-8** |
| T1-4 | Mitigated (M4/M5; M9's token-type separation — the refresh token's no-marker `aud`); the token endpoint's resource match is what enforces the presented token's resource binding (`invalid_target` if the presented audience lacks the addressed resource), and it governs the app shape under the app guard the same way |
| T1-5 | Mitigated (M3) |
| T1-6 | Mitigated (M6) |
| T1-7 | Mitigated to its bound (M6; each admitted refresh spends one outbound call plus one constant-time custody decrypt); the queue-wait within the limits accepted — **RES-4** |
| T1-8 | Mitigated (M12's validators; M20 bounds the crafted-JWT half) |
| T1-9 | Mitigated (M11) |
| T1-10 | Mitigated (M8) |
| T1-11 | Accepted — **RES-5** (flag default off; attribution display-level) |
| T1-12 | Accepted — **RES-7** (same user, own access, stated); widened cross-kind by this change — a token minted for one resource kind is Core-acceptable on the other kind's data path (the marker is checked, not the resource), the same class one axis wider |
| T1-13 | Mitigated (single flat issuer; M4's embedded-bindings enforcement; M9's RFC 9207 `iss`) |
| T1-14 | Accepted — **RES-11** (the audit chain attributes to the acting user; no other user's access is reachable) |
| T1-16 | Mitigated to the access-TTL bound (M21's claims re-read with M9's TTL lattice and rotation + denylist, M10's startup-bounded refresh, M11's per-flow records; Core's per-call DIAL authorization on the current claims); the interval between refreshes plus each minted token's own life accepted — **RES-6** |
| T1-17 | Accepted — **RES-22** (the SSO-session keepalive, bounded by SSO Session Max and the non-sliding window; ruled accepted-as-priced by the owner, 2026-11-01) |
| T1-18 | Mitigated (M21 — the AEAD tag, the pinned constants and fixed keyset, the seam's `sub`/`exp` checks, the `custody_decrypt_failed` detective class) |
| T1-19 | Mitigated to its bound (M21 — the size bound, the re-priced cap, the two-harness round-trip gate); the ungated harness stores accepted — **RES-23** |
| T1-21 | Mitigated (M23 — the stage order, the per-user DIAL authorization check on every path, the use-vs-establish rule, no credential read or transit); the forged-answer variant bounded by the internal-leg trust — T5-7 |
| T1-22 | Accepted as design (M23's routing decision — Core's own credential semantics, the delegation stated as use-vs-establish, the same access through Core's own paths) |
| T1-23 | Mitigated (M25 — the stage order: the identity leg and the per-user app read before every mint; the mint's `sub` is the identity leg's own; the short-circuit itself is audited as `credential_free_short_circuit`) |
| T1-24 | Accepted as design — the apps-namespace inventory disclosure is inherent to serving discovery dynamically in the second namespace, bounded by the apps restriction option and the mirror property (the widened set names nothing Core's own apps tier does not name); the route stays inside the shared limiter (M6/M24) |
| T1-25 | **Mitigated (M31)** — the consent/attribution checkpoint, the deferred-to-mitigated flip this change lands: the drive-by shape meets the gateway-owned decision page on first attribution (after the identity leg, before every mint, on all three paths; the per-(subject, client) registry; prompting only on first attribution), so the mint does not run without the user's act. The **standing control is CIMD allowlist curation — M7's control set** (the CIMD fetch's SSRF discipline and origin allowlist, the curation surface), *not* M24's apps front-door surface (corrected here: the earlier row cited M24's CIMD allowlist, a cross-reference defect — the apps surface is M24, the allowlist is M7's). The on-path shape keeps **RES-12/RES-1**'s existing acceptance (that attacker holds strictly cheaper attacks — T1-1); the mis-named-registration shape is **DT-EP3-3**'s re-priced display-level bound (**RES-11**) |
| T2-1 | Mitigated (M7) |
| T2-2 | Mitigated to its bound (M7's capacity limiter, M6); the residual queue-wait accepted — **RES-4** |
| T2-3 | Mitigated (M7/M8) |
| T2-4 | Mitigated (M7/M12) |
| T2-5 | Mitigated to its bound (M3/M7 — URIs bounded to what the allowlisted origin published); allowlist curation accepted with **RES-17**'s revisit rule |
| T2-6 | Mitigated (M7 — pinning, no redirects, HTTPS-only) |
| T3-1 | Mitigated (M1/M2) |
| T3-2 | Accepted — **RES-1** (TLS named, deployment-owned, unplaced today) |
| T3-3 | Mitigated (M2 — each code PKCE-bound); the exploitable remainder is the interception variant — **RES-1** |
| T3-4 | Mitigated (M8; **widened by this change** — the interpolated resource is a multi-segment path now, with the guard's decoded refusal (M38) and the escape discipline asserted for path-shaped inputs, task 3.6) |
| T3-5 | Mitigated (M8's `frame-ancestors`/`X-Frame-Options`) |
| T3-6 | Mitigated (M8's `Referrer-Policy`) |
| T3-7 | Mitigated (M6/M12) |
| T3-8 | Mitigated (M8's `no-store`) |
| T3-9 | Accepted — **RES-12** (the transport class; M18 named, unplaced) |
| T3-10 | Mitigated (M6/M12 — lookup-first, abuse limits) |
| T4-1 | Accepted — **RES-13** (bounding: never-commit discipline, rotation reach, re-stated for the keyset — the injection path is the custody, env or read-only file; DT-EP4-2's retained window and DT-EP4-4's file footprint are the priced additions) (M34, M35) |
| T4-2 | Accepted — **RES-2** (bounding: never-store rules — the encrypted custody claim the one named exception, ciphertext never plaintext — TTLs, and the absence of any per-session store; the identity access token's 24 h post-lift life is the realm's, upstream-owned) |
| T4-3 | Accepted — **RES-5 / RES-13** (the host-write boundary the key and the store share) |
| T4-4 | Mitigated to its bound (M14's `issuerPattern` + marker); the internal plain-http path accepted — **RES-19** |
| T4-5 | Mitigated (M6) |
| T4-6 | Accepted — **RES-13** (the host-operator trust is disclosed, not proven) |
| T4-7 | Mitigated (M20) |
| T4-8 | Mitigated to its bound (M21's envelope and key discipline, the session-bound grant, the overlap semantics — seal under the active key, decrypt active-or-retained, the retained entry's removal the cut); the time-decoupled conjunction and the process-compromise floor accepted — **RES-21 (parts ii and iv)**, part ii re-priced for the retention window (DT-EP4-3); the managed-runtime memory floor — **RES-2** |
| T4-9 | Mitigated to its blast radius (M28 — the secret authenticates the identity-leg client only: no gateway mint, no Core access, no upstream credential; load-bearing in every deployment per the 2026-11-05 ruling, and in the challenge-on mode a leaked secret alone still cannot spend an intercepted code — the verifier is the second binding); the `.env`-class custody accepted, the KMS/secret-management move the recorded C3 scope |
| T5-1 | Mitigated to the flow's purposes (the token-use rule — **RES-3**); the post-lift life accepted — **RES-19** (wire) / **RES-2** (memory); the 24 h lifespan is upstream-owned |
| T5-2 | Accepted — **RES-19** (bounding: PKCE — a captured `/signin` body holds a code the MITM cannot spend; re-priced with the refresh-grant leg's any-claims-for-an-existing-`sub` forgery gain and the decrypted provider session refresh token's sniffing gain stated) |
| T5-3 | Mitigated (strict URL building, loud refusal — M10's bounding); **narrowed by this change — the `redirect_uri` member leaves the flow's inputs (M42, the derived-callback mitigation), so an editor of the toolset can no longer steer the consent's destination through this leg**; the existence edge is per-namespace — the per-user listing read is the toolset namespace's existence decision and the app read the apps namespace's, both post-authentication on the same internal leg; a forged not-found is the one denial of one flow — the same leg and trust as the internal-leg residual (**RES-19**) |
| T5-4 | Preserved by the establishment-side refusal with the delegation stated — **RES-9** (the flow never *establishes* at GLOBAL level; a GLOBAL credential's *use* through the short-circuit is the operator-configured delegation, not an escalation) |
| T5-5 | Mitigated (flow TTL bounds held records; fail-closed) |
| T5-6 | Mitigated (bounded parsing, timeouts); the crash-loop tail accepted — **RES-15** |
| T5-7 | Mitigated to the internal-leg bound (the RES-19 acceptance class, extended to one more member of the same Core answer — the listing route, the re-pinned availability oracle, whose authorization is the data path's own, so the false-denial defect the prior admin-role availability read carried is removed by the re-pinning rather than accepted; the mint's `sub` is the identity leg's, and no stored credential means the data path 401s); the wrong-class diagnosability defect the second live run exposed — a trust fault (Core's 401) rendered and audited as an access denial, undiagnosable because Core logs no record of its 401s — is **removed by this change's refusal-class split**; the forged-answer residue's acceptance unchanged — a forged 401 costs one flow, the same as a forged 404 |
| T5-8 | Mitigated to the internal-leg bound (M25 — the app read's stage position and the gate before the mint; the forged 200 yields a misleading token whose data-path calls fail at Core, not access); the forged-answer remainder is **RES-19**'s acceptance class, extended to one more leg; the app read's 401 rides the listing read's trust-fault class — both reads share the gateway's one answer-to-refusal mapping, so an authentication failure is never an access denial on either |
| T5-9 | Mitigated (M26 — refuse-whole discovery validation: issuer equality, origin-bound endpoints, HTTPS without the override, no redirects, size cap); the TLS-bounded residue accepted as **RES-19**'s external-TLS narrowing case — the same acceptance any HTTPS client carries; the class absent in direct mode (no provider-asserted input) |
| T5-10 | Mitigated (M27 — the TTL cache bounds fetches to one per window per process, in the success regime and in the failed one alike (a failed or refused fetch is recorded for the same window and served from it without re-fetching), and the authorize surface's limiter bounds arrival, so the fetch rate is min(rate limit, 1/TTL) either way); absent in direct mode, which fetches nothing |
| T5-11 | Accepted — **RES-24** (the challenge-off mode's priced residue: the client secret is the only bar to an intercepted code on a plain-http front door — client authentication is on in every mode, the 2026-11-05 ruling's shape, so the residue is the missing challenge binding, not a missing secret; re-opened by TLS-fronting the public origin or the mode's retirement) |
| T5-12 | Mitigated (M29 — exact-string issuer pinning at issuance and refresh; no token and no discovery document can widen the pin); the distinguishability precondition is the provider's journey-distinct-issuance configuration — the operator prerequisite the configuration reference states, not a property the gateway grants |
| T5-13 | Accepted as the operator's explicit trust claim — operator input at the configured issuer's own trust level (the RES-19 override-claim class), bounded by M30's startup validation (all-or-nothing, well-formed absolute URLs, HTTPS without the override) and the fail-closed first-use failure; no provider-asserted input exists in the mode, so the forged-document and fetch-amplification classes are absent |
| T5-14 | Mitigated to its bound (M30 — the fail-closed fixed-vocabulary leg failure, no fallback construction); the staleness accepted as the direct mode's priced, documented trade — the operator owns endpoint freshness |
| T6-1 | Accepted as the standing front-router class — bounded by the committed synthesis form (M15, repo) and config review |
| T6-2 | Mitigated (M10/M15/M39; **re-priced by this change against the new map mechanism** — the row's subject changes from the location regex to the `$request_uri` map grammar; the reserved-name rule is now a first-segment rule, the match domain requires the `/mcp` suffix, the data-path locations are bare prefixes behind the authorization-surface locations, and the lockstep probe battery asserts the map/guard split for both path shapes) |
| T6-3 | Mitigated (M15; the apps data-path location carries the toolset location's `$is_args$args` verbatim) |
| T6-4 | Mitigated (M16's topology invariant, re-stated for the pod — the gateway's port unreachable from the host and from outside networks, name-routable on the deployment's own instance network by design, the mis-assembly shape priced at DT-EP6-1; M35) |
| T6-5 | Accepted — **RES-12** |
| T6-6 | Mitigated to its bound (M6 on the gateway side; nginx's connection/timeout tuning is the deployment's) |
| T6-7 | Mitigated (M10's decoded per-segment rules for configured entries + the request-time path guard for dynamic paths + M15's static committed config — no path ever enters the config as free text) |
| T6-8 | Mitigated (M24 — the disjoint `/apps/` prefix, the shared decoded per-segment rules, the second capture-keyed challenge map quoting the app's own metadata path, `$is_args$args`, M39; the routing probe battery's apps rows assert each) |
| T7-1 | Accepted — **RES-5** (the use-path is bounded by M3 against what the store says — which the tamper controls; re-stated for the pod: the store's boundary is its volume and the node, its ownership the contract's fsGroup/uid-10001 controls, its no-secret property load-bearing — M35, DT-EP7-1) |
| T7-2 | Mitigated (fail-closed startup refusal, atomic writes, one-command recovery); the host-write precondition is **RES-5**'s acceptance |
| T7-3 | Mitigated (bounded schema parse; inside the boundary ruling — **RES-5**) |
| DT-EP1-1 | Mitigated — the flow-id binding is the control (128-bit CSPRNG, server-side record, single-use-per-flow; the route answers exactly the flow id and the action); the on-path race keeps **RES-12**'s existing acceptance (a strictly cheaper attack exists — T1-1) (M31) |
| DT-EP1-2 | Mitigated — the approval registry's hard cap with oldest-first eviction, one write path (the approve action on a live identity-completed flow), and the flow store's existing bounds as the per-entry cost (M6/M31); the RES-15 acceptance class extended to one more in-memory store |
| DT-EP1-3 | **No new row** — the existing unauthenticated-allocation class's own member (T1-6's flow-record memory), narrowed by the 2048-byte `state` bound rather than newly enabled; the bound's home is T1-6's grid (D8) |
| DT-EP1-4 | Mitigated (M31) — **in-place: the EP1 table row's deferred disposition flips to mitigated**, not a new row — T1-25's drive-by shape, the deferred-to-mitigated flip; the on-path shape **RES-12/RES-1**, the mis-named shape **DT-EP3-3**/**RES-11** |
| DT-EP1-5 | Mitigated (M32) — the redirect-URI scheme admission rule at the four sites closes the cleartext-delivery class; **no new residual** (the on-path class keeps **RES-12**'s acceptance, the loopback exception keeps the fielded population's shape) |
| DT-EP1-6 | Mitigated to the clause's stated bound (M33) — the replay revocation denylists the minted refresh token at the detected replay; the two partials (the access token's TTL bound, the rotated-successor window) stated as the bound the clause buys |
| DT-EP3-1 | Mitigated (M8's family with `form-action 'self'`, through the one shared builder; the header-assertion tests extend to the page class) |
| DT-EP3-2 | Mitigated (M8's `frame-ancestors`/`X-Frame-Options` pair; the no-auto-continue rule removes the T3-5 auto-advance dimension) |
| DT-EP3-3 | Accepted — the **RES-11** display-level bound, re-priced for the decision context; the page's verifiable-facts rule (client id and registered `redirect_uri` beside the name) is the compensating control; the naming controls stay **M7**'s allowlist curation and the DCR flag's default-off (**RES-5**) |
| DT-EP3-4 | Mitigated (M40) — the three-callback runbook states the allowlist procedure, its ordering and its reason, the per-toolset repair, and the statically-registered hand registration; the failure is fail-closed by Core (unavailability, never a mis-delivery), and the runbook's per-toolset consent probe is the detective step |
| DT-EP4-2 | Mitigated to its bound (M34, M36) — the retained signing key's window is operator-declared, bounded by the drain window, and removable at any moment (the immediate cut, proven by the drill); accepted as the priced trade of routine rotation — **RES-13**, **RES-21** |
| DT-EP4-3 | Mitigated to its bound (M34, M36) — the retained custody key's decrypt window is the same declared window and cut, with the envelope's subject binding and the self-shortening re-seal; **re-prices RES-21 part ii** |
| DT-EP4-4 | Mitigated to the injection-path boundary's existing price (M34, M35) — a file-sourced key or secret's at-rest footprint is a new *location* inside RES-13's class (the IdP client secret's `IDP_CLIENT_SECRET_FILE` spelling included — same price, new location); the read-only mounts and load-once discipline are the controls; **no new residual** |
| DT-EP4-5 | Mitigated (M34) — per-entry validation with named refusals, no material in any error, and the duplicate-derived-`kid` check making the document's key count checkable |
| DT-EP4-6 | Accepted as operator discipline (M34's JWKS inventory, M35's contract and reference, M36's drill) — a growing retained set is visible in the JWKS; re-opened by an automated-rotation future |
| DT-EP4-7 | Mitigated by construction (M34) — the reserved `kms` value is refused naming the gap; the falsification target so the review can check the refusal fires |
| DT-EP1-10 | Mitigated — M20's discipline re-stated per-entry (algorithm pinned, embedded header material ignored, the `kid` selecting within the startup-fixed keyset, unknown `kid` refused); **no new residual** (M34) |
| DT-EP1-11 | Mitigated (M34, M36) — the pre-publish rule closes the rotation-window verification gap; the residual is a wrongly declared cache bound, recorded as the change's open question (§14's JWKS-cache TTL note) |
| DT-EP6-1 | Mitigated to the deployment boundary's standing price (M35) — the pod contract is the named control, the DevOps review its gate; the compromise table's host row is re-shaped, not removed; **restated by the discovery-aliases change:** a fronting that is not the committed conf also loses the well-known closure — availability-only for discovery-probing clients (the pre-change fall-through to Core's `401` returns); the pod contract's router section names the closure as part of the conf |
| DT-EP6-2 | Mitigated by construction (M35) — a strict narrowing of RES-19's class (the sibling leg loopback-only within the pod's namespace); the node remains the priced boundary |
| DT-EP7-1 | Mitigated (M35) — the contract's mount section names the store's volume as a MUST with its cloud-backed storage-class requirement, export story, and load-bearing no-secret rule; the restart-survival acceptance makes the omission fail the gate; **RES-5**'s boundary price unchanged |
| DT-EP1-12 | Mitigated (M37) — the restriction membership is decided canonical-vs-canonical, so every accepted spelling of one resource meets one verdict |
| DT-EP1-13 | Mitigated (M37) — one canonical identity per resource across the flow record, token audience, refresh match, and restriction check; segmentation-precedes-decoding pins the merge direction |
| DT-EP1-14 | Mitigated (M38) — the decoded forbidden-set refusal (`{`, `}`, `"`, ≤ U+001F) removes the header/page-breaking characters before any interpolation; the router's challenge is a fixed template plus a grammar-conforming capture |
| DT-EP1-15 | Mitigated to its bound (M39) — the byte cap (≤ 900 decoded UTF-8 bytes) and the segment cap (`RESOURCE_PATH_MAX_SEGMENTS`, default 32) bound every guard input before work proportional to it; the existing limiter bounds the rate; the trail's volume is bounded by the same limit |
| DT-EP1-16 | Mitigated to Core's standing control — a foreign-bucket path is legitimately addressable, and Core's per-caller access chain refuses it 403 at the listing read before any mint (same-answer-as-Core); the ciphertext was client-visible data before this change; **no new residual** (never-cut 3 preserved) |
| DT-EP5-4 | Mitigated (M37) — the read URL is built only as `fixed-prefix + canonical-encoding`; the guard refuses the dot-segment and empty-segment steering shapes and the canonical re-encoding normalizes every escape before the URL is built |
| DT-EP5-5 | Mitigated (M37/M38) — the `url` member carries the decoded, guard-validated path, JSON-encoded by the existing client; unit rows assert a path with every legal punctuation survives the round-trip byte-identical |
| DT-EP6-3 | Mitigated (M39, M41) — the division of labor is stated once and the lockstep probe battery asserts the documented behavior on both sides (the shapes both admit, both refuse, and the asymmetry class itself), negative controls first |
| DT-EP6-4 | Mitigated (M39) — the grammar's alternates are unambiguous (the unreserved class excludes `%`), brace quantifiers are avoided, the `large_client_header_buffers 4 8k` bound caps the input, and the pathological-URI probe row asserts a fast refusal |
| DT-EP6-5 | Mitigated (M38/M39) — the authorization-surface locations precede the data-path locations, the map requires the `/mcp` suffix with nothing after it but the query, the reserved-first-segment rule keeps the AS names unreachable as resource paths, and the guard refuses dot-segments; probe rows assert each |
| DT-EP6-6 | Mitigated to the same-answer claim (M41) — the front door adds no decode step, so it adds no decode discrepancy; a live probe row asserts the `%2F` forwarding, and the open question records the one cell that could falsify the principle |
| DT-EP1-17 | Mitigated (M43) — every alias answers the canonical document from the one builder; the issuer never echoes the suffix, so no second issuer identity exists |
| DT-EP1-18 | Mitigated to the relying party's own conformance (M43, M9) — no OpenID Provider member is advertised, so a conforming relying party refuses the provider; the class is newly reachable through the OpenID Connect location, and bounded there: the misuse needs a relying party operator-configured to trust the gateway as an OpenID Provider that skips both ID-token validation and audience validation (M9), three conformance failures outside this deployment; **no new residual** on that reasoning (RES-7 is the bounding record) |
| DT-EP1-19 | Mitigated to the canonical route's bound (M43, M15, T6-6) — constant cost, no record, no Core call; the suffix length bounded by the request-line buffer; the aliases deliberately not on the limiter, which bounds state and record volume they do not have |
| DT-EP6-7 | Mitigated (M44, M45) — the plain-prefix closure is consulted only after every regex location; `^~` is forbidden by the spec; the precedence rows fail on any shadowing |
| DT-EP6-8 | Mitigated (M44, M45) — Core's two templates forwarded end-anchored; the same-answer-as-Core-direct row; re-opened by a Core release adding a `/.well-known/` route |
| DT-EP6-9 | Mitigated (M44, M38, M45) — both directions closed by raw-URI checks: the Core location forwards only a raw URI that is itself one of Core's templates, and the catch-all hands any raw namespace spelling to the closure's `404`; behind the gateway locations no new handler is reachable (DT-EP6-5's class); the verbatim-path normalization rows measure both directions, encoded-dot variants, and `%0A` |
| DT-EP6-10 | Mitigated by construction (M44, M45) — a fixed literal body with no variable, `application/json`, no request content in any header |

## 14. Open questions

What the analysis could not resolve, phrased for the reviews (§6), never left
implicit — the section's contract (`docs/security-analysis.md` §5.8) is the
*unresolved* set; a question answered by a later input moves to the resolved record
below, with its source and date, so it cannot be re-litigated from silence. The
original OQ numbering is kept (the resolved entries retain their ids).

**Open.**

- **OQ-4 — Per-issuer path/audience scoping in Core** — the structural fix for RES-7
  and RES-8's class: a worthwhile future Core configuration feature, explicitly not
  a dependency of this system.
- **OQ-5 — The audit sink's operational shape** (stdout vs. otel) in the local
  deployment — never-cut 5's discipline is designed in; the running sink's own
  custody is the deployment's.
- **OQ-6 — The mint-path watch.** T4-1/T4-6's honest gap: nothing in today's shape
  detects anomalous minting or key-file reads. Is a mint-rate metric (or the KMS
  move) worth scheduling, or does the rotation-reach bound suffice for the local
  shape's lifetime?
- **OQ-7 — DCR's enabled state on record.** EP7's threats are conditional on the
  flag; if DCR has never been enabled in the committed deployment, EP7 is dormant
  surface — worth one line of state on record.
- **OQ-8 — Core's JWKS-cache TTL as an operator-declared fact** (DT-EP1-11, DT-EP4-2,
  DT-EP4-3). The pre-publish wait and the retained window's Core-side closure are
  bounded by Core's JWKS-cache TTL; the local instance's observed 10 minutes is the
  default the configuration reference states, but Core's configurability of that cache
  is unverified. Implementation verifies against the Core source and the reference
  states the verified value; a deployment whose Core caches longer than declared keeps
  DT-EP1-11's residual open — the drill's observed wait bounds it in practice.
- **OQ-9 — The discovery document's echo rule** (DT-EP1-12/13, the addressing-vocabulary
  requirement). The design **echoes the offered spelling** as the protected-resource
  document's `resource` (Core's own mirror), so every spelling a client can be challenged
  with is served a document naming that spelling. The stricter alternative — refuse
  non-canonical spellings outright, one document per resource — would cost encoder-strict
  clients (lowercase hex, over-encoding) for no security gain the canonical identity does
  not already provide (DT-EP1-13). Open for the review's RFC 9728 identity argument and
  the owner's preference.
- **OQ-10 — The segment-count cap's value** (DT-EP1-15). The design states a cap without
  blessing a number; the implementation picks `RESOURCE_PATH_MAX_SEGMENTS` (default 32).
  No Core depth limit exists, so the front door states one. Owner sign-off on the number
  is cheap now and expensive after clients depend on deep paths.
- **OQ-11 — The `%2F` same-answer claim** (DT-EP6-6). The byte-faithfulness principle
  rests on Core's container refusing an encoded slash inside a segment exactly as Core's
  own port front line does. The instrument's `%2F` row verifies it live, once, at
  implementation. If Core answers differently through the front door than on its own port,
  the design's byte-faithfulness principle is falsified at that cell and DT-EP6-6 reopens.
- **OQ-12 — Whether Chat and Admin need a matching change** to stop overwriting the
  toolset's stored `redirect_uri`. Cosmetic once this change lands (the gateway no longer
  reads the field, M42); a cross-repo report, not this repo's change.
- **OQ-13 — The root protected-resource document** (M44's one deliberate `404` on a
  known discovery path; the discovery-aliases change's OQ-1). The front door answers the root
  `/.well-known/oauth-protected-resource` with the closure's `404`: one root document
  names one resource, and naming the origin breaks the per-resource RFC 8707 binding
  unless the audience rule widens. If a discovery-probing harness (ChatGPT first) still
  fails with the aliases deployed, a root document needs a design of its own and a full
  SIA; the live reconnect is the deciding evidence.
**Resolved during the baseline — kept on record, resolved-with-source and dated.**

- **OQ-1 — Does E9 enforce the presented token's resource binding? Resolved
  2026-11-01; source: the code** (`gateway/status.py:111-122`). The status endpoint
  enforces the per-toolset resource binding: it decodes the presented gateway token and
  requires the token's audience to contain the toolset's resource URI
  (`runtime.settings.toolset_resource_uri(name)`), else it answers `invalid_target` —
  the same resource rule the token endpoint enforces, applied to a read. So E9 binds the
  token to its own toolset, consistent with E3/E4; T1-4's grid and disposition carry the
  resolved statement, and the question is no longer open.
- **OQ-2 — The acceptance gate's recorded outcome. Resolved 2026-10-29; source: the
  archived change's evidence folder** (`poc-c-runbook.md`'s scoreboard, on the run's
  allowlist since the method fix). The gate PASSED — all five criteria (a)–(e)
  closed on field runs 1–5. RES-18 is closed on it; no §8 disposition flips.
- **OQ-3 — The current spec's continued coverage of every gateway-owned mitigation.
  Resolved 2026-10-29 by the D2 reconciliation's placement verification against
  `openspec/specs/mcp-signin/spec.md`, corrected the same day by the review round, and
  closed 2026-10-30 by the `pin-implemented-security-behaviors` change (archived).**
  Every "Placed — spec" entry in §12 was checked against the spec. Four elements were
  found implemented and tested in the repo but absent from the spec (M9's RFC 9207
  `iss`, M11's per-flow lifecycle records, M20's verification hygiene with the
  `kid`-less fallback stated, and M10's toolset-name charset — then a one-segment
  `^[a-z0-9-]+$`, **re-based by this change** onto the decoded per-segment path rules —
  the fourth missed by the verification itself and caught by the review); all four are now
  spec-pinned, and their §12 placements read "Placed — spec". The two elements left
  un-pinned by owner decision (the CIMD fetch's content-type/timeouts/User-Agent; the
  outbound timeouts and bounded response parsing) remain repo controls and are cited
  as "(repo)" in their grids.
- **OQ-14 — Core's challenge through the catch-all quotes `$host` without the port.
  Resolved 2026-11-16; source: the owner's ruling at the discovery-aliases change's
  review pause, recorded in that change's design.** Accepted, no change: the router
  keeps forwarding `Host: $host`. In a non-default-port shape (the local `:8090`)
  Core's own challenge for a direct-to-Core client crossing the catch-all therefore
  names a URL the front door does not serve; a TLS deployment on the default port is
  unaffected, and no gateway flow depends on Core's challenge. If the question is ever
  revisited, the preferred remedy is configuring Core's
  `toolsets.security.resourceHost` per deployment (an operator-set value) over
  forwarding the client-supplied `Host` with its port (`$http_host`).

## 15. The RFC 9700 conformance ledger

**What this section is.** The standing record of the RFC 9700 re-judge — the change's
first acceptance row's artifact, from the walk this change carries. The walk covers
every MUST, MUST NOT, SHOULD, SHOULD NOT, and RECOMMENDED of RFC 9700 §2 (the
operational recommendations) and §4 (the attack mitigations), plus the security-posture
MAYs; beside it, the OIDC items the roadmap's scope names and the MCP authorization
specification's own security considerations — **98 rows**, scored against the gateway's
client-facing authorization-server surface **as built** and re-walked against the
current MCP protocol revision (`2026-07-28`). The per-row verdicts are the walk's
report (this change's re-judge, its method D10); the bucket structure below is the
report's Part 6 partition, fully reconciled against the owner's rulings (2026-11-07).
The roadmap's closing re-judge (D3) inherits this ledger — it cites these rows, and
every residual the walk surfaced is priced here rather than forgotten.

**The vocabulary** — the four values, plus the carried N/A:

- **already satisfied** — the control exists as built; the row names where (the
  M-number, or the code/spec site the walk cited).
- **landed by this change** — nothing as built satisfied it; a requirement in this
  change's delta spec (with its implementing task, groups 3–5) satisfies it, or the
  change states the rule.
- **deferred with a named home** — knowingly not satisfied, on record with its priced
  home (an RES-number and the roadmap's closing re-judge).
- **accepted with reasoning** — violated or partial, already priced on record (an
  RES-number or a named owner-ruled condition); the price is the acceptance.
- **N/A** — not scoreable against this surface, with the boundary reasoning that makes
  the N/A honest.

**The partition — disjoint buckets whose counts sum.** **55 already satisfied as built
/ 13 landed by this change / 3 deferred with a named home / 6 accepted with reasoning
/ 22 not applicable** — **99 verdicts over 98 rows**: one row, the Part 4
communication-security MUST, carries two MUSTs (all endpoints over HTTPS; all redirect
URIs `localhost` or HTTPS) and is split across two buckets, the one declared exception.
Nothing is undecided: the five rows the walk left open — B-1 (the redirect-URI scheme
MUST NOT), B-2 (revoke-on-double-redemption), B-3 (the MCP redirect-URI twin of B-1),
B-5 (the `iss` advertisement) — joined **landed by this change** (B-1+B-3 → M32, B-2 →
M33, B-5 → M9's `iss` rows plus the member), and B-4 (the localhost-warning SHOULD)
joined **deferred** as **RES-25**.

| Bucket | Count | The rows |
|---|---|---|
| Already satisfied as built | 55 | the rows verdicted *already satisfied* in the four tables below |
| Landed by this change | 13 | §2.6's CORS-posture row (D9); §2.6's redirect-URI MUST NOT (B-1 → M32); the MCP redirect-URI MUST (B-3 → M32, the split row's landed half); §4.2.4's revoke-on-double-redemption SHOULD (B-2 → M33); §4.11.2's three rows (the DCR-phishing precautions, the authenticate-before-redirect reading, the trust/inform pair); the MCP open-redirection row (its two statement-shaped halves: the `state` rule, the trust/inform twin); the MCP confused-deputy MUST; the MCP best-practices confused-deputy mitigation details; the OIDC `auth_time` strip; the MCP redirect-hostname-display MUST; the MCP `iss`-advertisement MUST (B-5 → M9's member) |
| Deferred with a named home | 3 | §2.2.1 and its §4.10 twin (the sender-constraining SHOULD — D6's two-sided precondition); the MCP localhost-warning SHOULD (B-4 → **RES-25**, D13) |
| Accepted with reasoning | 6 | §2.3 (RES-7/OQ-4); §2.5 (M28/RES-24); §2.6's TLS row (RES-12/RES-19); §4.13's proxy-link row (RES-19); the MCP token-handling row (RES-7/OQ-4); the MCP communication-security endpoints half (RES-12) |
| Not applicable | 22 | the rows verdicted *N/A* below, each with its boundary reasoning |

### RFC 9700 §2 — the operational recommendations (27 rows)

| Ref | Verdict | Where the satisfaction or the price lives |
|---|---|---|
| §2.1 MUST — exact-string redirect comparison, loopback port exception | already satisfied | M3; the loopback-match requirement; `gateway/cimd.py`'s exact-match with the port exception keyed on the registered entry |
| §2.1 MUST NOT — open redirectors, either side | already satisfied | in-place refusals until the redirect target is validated (`gateway/authorize.py`); the gateway-as-client's one configured callback |
| §2.1 MUST — CSRF prevention via PKCE, `nonce`, or one-time `state` | already satisfied | M1/M2; the flow id as `state`, single-use |
| §2.1 MUST + SHOULD + MAY — mix-up defense (`iss`, or distinct redirect URIs) | already satisfied | M9's RFC 9207 `iss`; the gateway-as-client's single-issuer exact pin (M29) |
| §2.1 MUST — no credential forwarding on redirect | already satisfied | the redirect carries only `code`/`iss`/`state`; the custody-carrier discipline (M21) |
| §2.1.1 MUST — clients prevent code injection/misuse | already satisfied | M2 — the challenge is required and embedded in the code's bindings |
| §2.1.1 MUST — public clients use PKCE | already satisfied | M2/M9; `token_endpoint_auth_method: none` advertised |
| §2.1.1 RECOMMENDED — confidential clients also use PKCE | already satisfied | the confidential-client rule (M28); PKCE S256 on top of the secret by default |
| §2.1.1 MAY — `nonce` + ID Token alternative | N/A | no ID-token leg exists on either surface (D7's ruling) |
| §2.1.1 MUST — challenge transaction-specific, bound to client and user agent | already satisfied | M2; the code's bindings pin `client_id`, `redirect_uri`, `resource` |
| §2.1.1 SHOULD — S256 challenge method | already satisfied | S256 the only method accepted; `plain` refused, not implemented |
| §2.1.1 MUST — the AS supports PKCE | already satisfied | M2; `code_challenge_methods_supported: ["S256"]` advertised |
| §2.1.1 MUST — the AS enforces correct verifier usage | already satisfied | the challenge is in the signed bindings; the verifier is checked on every redemption |
| §2.1.1 MUST — PKCE downgrade mitigation | already satisfied | structural — a challenge-less code cannot exist (allocation refuses it) |
| §2.1.1 MUST + RECOMMENDED — detect PKCE support; publish the method list | already satisfied | `code_challenge_methods_supported` present beside the mandatory challenge |
| §2.1.2 SHOULD NOT / SHOULD — no implicit grant; `code` only | already satisfied | `response_type=code` the only value; `response_types_supported: ["code"]` |
| §2.2.1 SHOULD — sender-constrain access tokens (mTLS, DPoP) | **deferred** | D6's two-sided precondition (client side + Core-side RFC 9449 validation); the residual priced at RES-7/RES-8; home: the roadmap's closing re-judge (D3) |
| §2.2.2 MUST — public-client refresh tokens sender-constrained **or** rotated | already satisfied | M9 — rotation with replay detection (the held alternative branch) |
| §2.3 SHOULD + MUST + MAY — privilege minimization, audience restriction | **accepted** | AS side placed (M4/M9); RS side (Core) priced — RES-7 / OQ-4 |
| §2.4 MUST NOT — ROPC grant | already satisfied | the grant dispatch knows exactly `authorization_code` and `refresh_token` |
| §2.5 SHOULD + RECOMMENDED — client authentication; asymmetric where feasible | **accepted** | the client-facing surface is public by contract (the checkpoint is the control — D1/M31); the identity leg's secret is symmetric — M28 / RES-24 |
| §2.6 RECOMMENDED — publish RFC 8414 metadata | already satisfied | the flat single-issuer discovery document |
| §2.6 SHOULD NOT — client-influenced `client_id` where namespaces could confuse | already satisfied | the RS reads `sub` (provider-verified), never client input; no `client_id` in the access token |
| §2.6 RECOMMENDED — end-to-end TLS (BCP 195) | **accepted** | the plain-http front door (RES-12, M18 named and deployment-owned) and the internal plain-http legs (RES-19) |
| §2.6 MUST NOT — `http` redirect URIs, except native loopback (RFC 8252 §7.3) | **landed** | **B-1 → M32** — the redirect-URI scheme admission rule at the four admission sites (the client-registration requirement's amendment and the DCR-store load-path clause) |
| §2.6 MUST (per §4.17) — in-browser response techniques verify initiator/receiver | N/A | no in-browser channel exists; the pages are script-free server-rendered navigations |
| §2.6 MAY + MUST NOT — CORS permitted at token/metadata/registration, not at authorize | **landed** | D9 — the posture stated as a rule with the machine-checkable no-`Access-Control-*` pin (the public-endpoints requirement's amendment) |

### RFC 9700 §3 and §4 — the attack mitigations (40 rows)

| Ref | Verdict | Where the satisfaction or the price lives |
|---|---|---|
| §3 MUST — account for all attacker types in the deployment | already satisfied | §6's attacker inventory and §8's per-entry-point threat tables (this document) |
| §4.1.3 MUST — request and registered redirect URIs equal by exact match | already satisfied | M3; the same control as §2.1 |
| §4.1.3 MUST — variable ports allowed for native `localhost` redirects | already satisfied | the loopback-port exception, keyed on the registered entry |
| §4.1.3 MUST NOT — web servers hosting redirect URIs expose no open redirectors | already satisfied | the gateway hosts no client redirect targets; its error surfaces never redirect to an unvalidated target |
| §4.1.3 MAY — prevent fragment reattachment | N/A | no fragment-bearing authorization responses exist (codes are delivered, not tokens) |
| §4.1.3 SHOULD — clients use the code response type | already satisfied | enforced of every client (the same control as §2.1.2) |
| §4.1.3 MAY — trust the redirect URI where the request's integrity is verified (JAR/PAR) | N/A | no request-object mechanism exists, so the trusted precondition never holds |
| §4.2.4 SHOULD NOT — no third-party resources/links on pages or the authorize endpoint | already satisfied | M8 — script-free pages with an inline stylesheet pinned by hash |
| §4.2.4 MUST — invalidate authorization codes after first use | already satisfied | the replay cache claims the code's `jti` at acceptance; short-lived codes (M9) |
| §4.2.4 SHOULD — on double redemption, revoke all tokens issued from that code | **landed** | **B-2 → M33** — the replay memo's `code_id → refresh_jti` field plus one denylist call (the issued-tokens requirement's code-clause amendment), two partials disclosed as the clause's bound |
| §4.2.4 SHOULD (clients) — invalidate `state` after first use | N/A | client-side duty; the AS-side twin is the delta's `state` rule (row §4.11.2/MCP open-redirection) |
| §4.3.2 MUST NOT — clients pass access tokens in URI query parameters | already satisfied | tokens exist only in no-store JSON bodies; no surface-built URL carries a token |
| §4.4.2 / §4.4.2.1 MUST (clients) — mix-up prevention, `iss` evaluation | already satisfied | the AS supplies `iss` on every response matching the metadata issuer; M29's single-issuer pin (same control as §2.1) |
| §4.4.2.2 MUST/SHOULD (clients) — distinct-redirect-URI fallback | N/A | the preferred `iss` defense is in place, so the fallback's precondition never arises |
| §4.5.3.2 MUST (OIDC clients) — validate `nonce` in the ID Token | N/A | no ID-token leg; `nonce` is in the registry blocklist (the no-ID-token boundary) |
| §4.6 (informational) — access-token injection; `at_hash`/`nonce`; sender-constraining | N/A | no ID-token leg (so no `at_hash`); the sender-constraining half is the §2.2.1 row's priced deferral |
| §4.7.1 MUST (clients) — confirm AS PKCE support before relying on it | N/A | client-side duty; the AS makes the detection unavoidable (mandatory challenge, member advertised) |
| §4.7.1 MUST + RECOMMENDED (AS) — provide a way to detect PKCE support | already satisfied | the same control as §2.1.1 (member advertised + mandatory challenge) |
| §4.8.2 MUST — PKCE downgrade mitigation | already satisfied | structural (the same control as §2.1.1) |
| §4.9.3 SHOULD/SHOULD/MUST (RS) — sender-constrained, audience-restricted tokens; secrets at rest | N/A | the RS of gateway tokens is Core (the boundary: the token's validator is Core); the price is on record — RES-7 / OQ-4 |
| §4.10 SHOULD — AS ensures tokens sender-constrained and audience-restricted | **deferred** | its twin of §2.2.1 — D6's precondition; the audience half placed AS-side, marker-only RS-side (RES-7) |
| §4.11.1 MUST NOT (clients) — no open redirectors | already satisfied | the gateway-as-client's one configured callback; the page host serves no forwarding URL |
| §4.11.2 MUST (RFC 6749) — no auto-redirect on invalid `client_id`/`redirect_uri` | already satisfied | every refusal before validation is answered in place |
| §4.11.2 MUST — precautions against dynamic-registration phishing | **landed** | the checkpoint (M31; the ADDED checkpoint requirement's `First attribution renders the decision page and no mint runs` scenario); layered on DCR's default-off (RES-5) and the CIMD origin allowlist (M7) |
| §4.11.2 MUST — always authenticate the user before redirecting | **landed** | the identity leg precedes every mint; the checkpoint removes the zero-page short-circuits' reach beyond the silent-auth exception |
| §4.11.2 SHOULD + MAY — auto-redirect only where the redirect URI is trusted | **landed** | the decision page is the inform-the-user option (D1/D2); RFC 9700 §4.11.2 is the design's standards anchor |
| §4.12 MUST NOT + SHOULD — no HTTP 307 for credential-bearing requests; 303 preferred | N/A | only 302s answering GETs exist; the method-preserving credential-POST redirect shape is never produced |
| §4.13 MUST — the reverse proxy sanitizes security-relevant headers | already satisfied | the rate-limit source reads the router-appended value, never the client's claim; the committed router config (M15) |
| §4.13 MUST — the proxy-to-app link is protected against eavesdropping/injection/replay | **accepted** | the internal legs are plain http at the local shape — RES-19 (M16 the topology invariant; M18 named for the production direction) |
| §4.14.2 MUST — decide via risk assessment whether to issue refresh tokens | already satisfied | refresh tokens are session-bound by construction; the trade is the designed answer (M9/M21) |
| §4.14.2 MUST — issued refresh tokens bound to the consented scope and resource servers | already satisfied | the refresh token carries `resource` and `client_id` as signed bindings; no scopes granted (the honest empty set) |
| §4.14.2 MUST — public clients: sender-constrained or rotation with replay detection | already satisfied | M9 — rotation + denylist (the same control as §2.2.2) |
| §4.14.2 MUST (implementation note) — grant integrity where encoded in the token value | already satisfied | all token kinds are self-signed JWTs verified under a pinned algorithm/issuer (M20) |
| §4.14.2 MAY — auto-revoke refresh tokens on security events | already satisfied | IdP session revocation ends the gateway's refresh at the next attempt; `/dial/revoke` denylists by id |
| §4.14.2 SHOULD — refresh tokens expire after client inactivity | already satisfied | satisfied in substance by a different mechanism — the non-sliding absolute expiry plus provider-session death |
| §4.15.1 SHOULD NOT + MUST — no client-influenced `client_id` in a shared namespace | already satisfied | verified non-confusable (the same control as §2.6's `client_id` row) |
| §4.16 MUST + SHOULD — clickjacking prevention and CSP level 2+ | already satisfied | M8's family on every page (`frame-ancestors 'none'` + `X-Frame-Options: DENY` + full CSP), extended to the decision page with `form-action 'self'` |
| §4.16 SHOULD — let administrators configure/clients register frameable origins | N/A | no framing consumer exists; `frame-ancestors 'none'` satisfies the MUST more strictly than the SHOULD's mechanism |
| §4.16 SHOULD — combine CSP with other countermeasures | already satisfied | the legacy `X-Frame-Options: DENY` rides beside the CSP on every page |
| §4.17.2 MUST/MUST NOT — in-browser messaging: exact origin match, never `*` | N/A | no postMessage or in-browser messaging exists (the pages are script-free) |

### The OIDC beside-set — the roadmap's named scope (5 rows)

| Ref | Verdict | Where the satisfaction or the price lives |
|---|---|---|
| `max_age` (OIDC Core §3.1.2.1) | N/A | no ID-token leg; not accepted by the surface and not relayed to the provider (D7), so a from-spec reimplementation does not add it |
| `prompt` (`login`/`none`, OIDC Core §3.1.2.1) | N/A | no ID-token leg; the one silent-auth risk this surface has is T1-25's drive-by, bounded by the checkpoint (M31) |
| `auth_time` (OIDC Core §2 claim) | **landed** | the delta's claim-copy amendment strips `auth_time` beside `acr` (the claim-copy requirement's amendment, task 4.2) — a gateway token never states the provider's authentication event as its own |
| `nonce` (OIDC Core §3.1.2.1/§11.3) | N/A | no ID-token leg; the copy-side hygiene already held (`nonce` in the registry blocklist) |
| The ID-token boundary generally | N/A | the client-facing surface mints no ID tokens; the provider's ID token never reaches the gateway (the verified artifact is the provider's access token) |

### The MCP authorization specification and security best practices (26 rows)

Scored against the current `2026-07-28` revision.

| Ref | Verdict | Where the satisfaction or the price lives |
|---|---|---|
| Overview (MUST) — implement OAuth 2.1 with appropriate security measures | already satisfied | code + refresh only, PKCE mandatory, no implicit, no ROPC (the §2 rows are the measures this MUST points to) |
| Discovery (MUST) — provide a discovery mechanism | already satisfied | the flat single-issuer RFC 8414 document; the document's `issuer` is the public origin |
| Protected resource metadata (MUST) — RFC 9728 with `authorization_servers`, 401 challenges | already satisfied | the per-toolset and per-app PRM documents; the challenge synthesis through the router (M15) |
| Client ID Metadata Documents (SHOULD, with AS-side MUSTs) | already satisfied | advertised (`client_id_metadata_document_supported: true`); the URL-shaped fetch under the full SSRF control set (M7); exact `client_id`-matches-URL, redirect validation against the document, structure validation, TTL/size cache, origin allowlist |
| Dynamic registration (MAY, deprecated in `2026-07-28`) | already satisfied | implemented and config-gated **default-off**, CIMD the preferred rung — the registry's own migration shape; the deprecation is a forward-looking fact (RES-5 prices the flag) |
| Resource parameter (MUST, clients) — send `resource` | already satisfied | the AS-side twin is stricter than the client MUST — `resource` required at both endpoints and at refresh (M4) |
| Access token usage (MUST/MUST NOT, clients) — Bearer, never in the URI | already satisfied | issued tokens are Bearer, exist only in no-store JSON bodies; the load-bearing half of D6's client-side precondition |
| Token handling (MUST, servers) — validate tokens and their audience | **accepted** | the MCP server of this deployment is Core; its audience check is the marker — RES-7 / OQ-4 |
| Token theft (SHOULD + MUST) — short-lived access tokens; rotate public-client refresh tokens | already satisfied | M9's short access TTL; rotation default-on with denylist |
| Refresh tokens guidance (SHOULD NOT) — no `offline_access` on the RS side | already satisfied | PRM `scopes_supported` empty or operator-pinned; `offline_access` never requested (M13); no scopes granted |
| Communication security (MUST) — all endpoints over HTTPS; all redirect URIs `localhost` or HTTPS | **accepted** for the endpoints half (RES-12/M18) **+ landed** for the redirect-URI half | **B-3 → M32** — the same unpriced gap as B-1, one change closes both sources; the row is the one declared split (two MUSTs, two buckets) |
| Authorization code protection (MUST, clients) — PKCE S256, verify via metadata | already satisfied | enforced of every client; `code_challenge_methods_supported` present and non-empty |
| Authorization response validation — `iss` emission (SHOULD) | already satisfied | `iss` rides every authorization response, success and redirected error alike (M9; the "Authorization responses identify their issuer" requirement) |
| Authorization response validation — `iss` advertisement (MUST) | **landed** | **B-5 → M9's member** — `authorization_response_iss_parameter_supported: true` in the AS metadata (the discovery requirement's amendment, task 5.3), a pure trueness fix; no new threat row or M-number |
| Open redirection (MUST/MUST NOT/SHOULD) | **landed** | exact validation held (M3); the delta lands the two statement-shaped halves — the `state` rule (D8) and the trust/inform pair (the checkpoint, D1/D2) |
| CIMD security: redirect-hostname display (MUST) | **landed** | the decision page names the registered `redirect_uri` in full — hostname **and** port, more than the MUST's letter (the checkpoint requirement's naming scenario); the two disclosed bounds (first-attribution-only rendering; the localhost-impersonation hostname cannot catch) stated with it |
| CIMD security: localhost warnings (SHOULD) | **deferred** | **B-4 → RES-25** (D13) — the attack the warning mitigates requires local code execution (attacker classes 3/4, priced at T1-3/RES-21(i)); the compensating bound is the decision page's full-`redirect_uri` display; the re-open trigger is a population where loopback is anomalous |
| Confused deputy (MUST) — per-client consent before forwarding | **landed** | the checkpoint's per-(subject, client) registry checked before every mint on all three paths (M31; the ADDED checkpoint and registry requirements); the two declared deviations (no scope list; the checkpoint after the identity leg) are in the design |
| Confused-deputy mitigation details (MUST) — consent storage, page content, CSRF, framing, cookies | **landed** | the delta's checkpoint against each member: server-side registry (D4); the page naming client/resource/redirect; CSRF-bound by the flow id; frame-locked; no auto-continue; the scopes member the one declared deviation |
| Token passthrough (MUST NOT) | already satisfied | the gateway is the AS, not a pass-through: no client token travels upstream (invariants 1/2) |
| SSRF (client guidance + AS-facing subsection) | already satisfied | the CIMD fetch exceeds the guidance (M7): HTTPS-only, origin-allowlisted, redirect-refusing, all-record IP-range-checked with pinning, size-capped, timed, cached |
| State handle hijacking (MUST/SHOULD) | N/A | the gateway is the AS; the MCP-server handle duties are Core's on the data path |
| OAuth authorization URL validation (client-side MUSTs) | N/A | client-side; the gateway's own leg exceeds the analogous bar (M26/M30) |
| Scope minimization (guidance) | N/A | the gateway grants no scopes (`"scope": ""`); its PRM documents echo only operator-pinned entries or nothing |
| Local MCP server compromise / stdio security (client-side) | N/A | harness-side duties; the gateway serves no local servers and no stdio transport |
| Local Server Security tutorial (new page) | N/A | informational for a server-side AS; every recommendation addresses the local-server operator or the client, none an OAuth AS |

**The closing note the roadmap's D3 owes.** Every row that is not *already satisfied*
names its home in the table above: the 13 *landed* rows name their delta requirement
and, where a mitigation number carries them, the M-number (B-5's `iss` advertisement is
a trueness member on M9's existing behavior and carries none of its own); the 3
*deferred* rows name their RES-number (RES-25 for B-4) or the D6 precondition that
re-opens them; the 6 *accepted* rows name their RES-number. The closing
re-judge (D3) therefore finds every residual here priced rather than forgotten — it
inherits this ledger as the record of what the walk satisfied, landed, deferred, and
accepted, and re-judges the priced rows against the production shape when it runs.
