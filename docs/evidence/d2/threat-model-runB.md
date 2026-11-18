# MCP sign-in gateway — baseline threat model (D2, run B)

**What this is.** The D2 baseline threat model of the MCP sign-in gateway as the system
stands today, authored per the standing method (`docs/security-analysis.md`) in its
full-threat-model run shape. This copy is the comparison artifact of the D2 double-run;
the working deliverable is `docs/threat-model.md`. Dispositions are judged **on the
local development shape** — plain-http front door, file-based key custody, single
instance, no real users — with each disclosed residual at its current accepted state.
The production-shape re-judgement is a later workstream and is out of scope here; where
the method requires it, the re-open condition is stated, never the production verdict.

**Input basis.** Only the full-threat-model run's allowlist: the standing method, the
vendored attack-type taxonomy and control categories, `ROADMAP.md`'s never-cut list,
`docs/background/design.md` (§6 and the Appendix), `docs/background/design-review.md`
(§5.1's itemized attack surface), and the archived PoC change's `design.md` (its
security impact analysis and risks sections). Where this run needed more than those
documents gave, the point is recorded in the companion gap list
(`docs/evidence/d2/gap-list-runB.md`), not worked around.

**Placement vocabulary.** A mitigation's home is one of: **gateway spec** (behavior the
gateway owns, specified as requirements in the `mcp-signin` capability's spec), **Core
configuration** (the deployment's Core identity-provider and toolset settings), **the
deployment** (compose shape, network, host, transport), **this repo's committed
configuration** (the nginx front router), or **an upstream** (Core, Keycloak, or a
harness, each with its owner). Gateway-owned mitigations are normative in the gateway
spec; the spec's text itself is outside this run's allowlist, so placements cite the
archived change's design, where each requirement is stated as normative — the
verification gap is on the gap list.

---

## 1. The system as it stands

**Business description.** A harness (an MCP client such as Claude Code) that wants to
use a DIAL MCP toolset (an upstream OAuth-protected server, e.g. Notion) signs in
through a small gateway beside DIAL Core instead of Chat. The gateway is an OAuth2
authorization server for the harness-facing leg and a federation orchestrator for the
two DIAL legs: it challenges unauthenticated toolset traffic (via the front router's
401 rewrite), walks the user through the deployment IdP (Keycloak) and the upstream's
consent, deposits the upstream credential in Core through Core's own
`POST /v1/ops/toolset/signin` at USER level, and mints its own short-lived JWTs that
carry the user's real `sub` and roles. Core trusts those JWTs through a dedicated
identity-provider entry (`dial-mcp-proxy`, RSA256 via the gateway's JWKS, audience
marker `dial-mcp-proxy`), so the MCP data path runs harness → router → Core directly;
the gateway is never on it. The upstream access and refresh tokens never leave Core;
the upstream PKCE verifier never leaves Core; the harness never holds any Keycloak
material.

**Implementation shape.** One flat authorization server for all toolsets: the RFC 8707
`resource` parameter is the primary and required per-toolset discriminator at
authorization and token endpoints (`invalid_target` otherwise; a one-toolset inference
flag is the only escape). Registration priority: pre-registered client ids → CIMD
(fetch and validate the client's metadata document from an allowlisted origin) → DCR
(config-gated, default off). All clients are public PKCE clients; the gateway stores no
client secrets. Claim copy is copy-verbose: the whole identity-token payload verbatim
minus a fixed blocklist of registry claims the gateway owns, with roles overlaid from a
required, operator-configured source path and re-emitted as a plain array; loud refusal
when the path is absent. Refresh is a self-contained snapshot with a non-sliding
window: the rotated refresh token carries the original absolute `exp`, and startup
refuses to run when `refreshTtl` exceeds the configured IdP access-token lifespan.
Python 3.12 + FastAPI (uvicorn, `pyjwt[crypto]`, httpx, pydantic-settings); one bounded
shared worker pool with slow work offloaded off the event loop.

**Today's deployment shape (the shape dispositions are judged on).** Single instance,
no HA. Public origin `http://localhost:8090` — plain http on the development host,
fixed by `.env.example`; TLS and HSTS belong to the deployment layer's own TLS listener
and none exists. The gateway listens container-internally on :8091 and is never
host-published; the router is its only front door and the only authority for the peer
identity. Back-channels run over the instance compose network's internal plain http:
`http://core:8080` and `http://keycloak:8900`. The signing key is a generated RSA
keypair in a gitignored path injected via `.env` — file-based custody; KMS/HSM is the
documented production direction, not built. DCR registration records, if DCR is
enabled (default off), live in one JSON file on a bind-mounted host volume with
best-effort owner-only file mode. In-memory state: flow records (10-min TTL, 128-bit
CSPRNG ids), code replay cache (5 min), refresh denylist (until `exp`); issued tokens
are self-contained JWTs stored nowhere. TTLs: access 10 min, refresh 8 h (non-sliding,
startup-enforced against the realm's 24 h access-token lifespan), code 5 min, flow
10 min. Public-endpoint abuse bounds: per-IP and global rate limits, a hard cap on
live flow records with oldest-first eviction, a DCR registration cap (1024). The
realm's `accessTokenLifespan` is 24 h — an in-flight identity token, once lifted, is
live up to that long regardless of the flow TTL that bounds the gateway's *retention*
of it. The PoC change that built all of this is archived, so its acceptance gate is
closed; the allowed inputs carry no record of the gate's outcome (gap list).

---

## 2. Impact level

**High.** Reasons: the system operates an IdP-equivalent signing key whose compromise
mints any `sub` with any roles, including admin — the largest blast radius in the
design's own comparison of alternatives; it exposes a new public authorization-server
surface reachable without authentication; and it brokers the deposit of upstream
credentials into Core, so a logic flaw in the federation flow misdirects other users'
toolset traffic. The sensitive assets involved (the signing key, in-flight identity
tokens, upstream credential establishment) are directly exposed to confidentiality and
integrity attacks at the public boundary, and the unauthenticated endpoints are exposed
to availability attacks. There is no "no impact" claim anywhere in this model for a
reviewer to falsify; the security review gate on any change to this system runs at
full depth.

---

## 3. The disclosed-residual register (assembled first)

Assembled as the run's first step from the locations the allowlist names: the archived
PoC change's design (its security impact analysis and risks sections) and
`docs/background/design.md` (§6.5's role-staleness caveat, the Appendix's honesty
list). Every residual found there enters the model with its three-part acceptance
record: (a) the accepting condition, (b) the compensating or bounding control, (c) the
change or deployment fact that re-opens it. Each entry also names the threats in §8
that land on it.

**REG-1 — the public origin is plain http.** All bearer tokens, authorization codes,
flow ids, and browser legs cross `http://localhost:8090` in the clear.
(a) Accepting condition: the local development shape — a single instance bound to the
development host, no real users, no exposure beyond that host; TLS termination is the
deployment layer's own listener and none is deployed.
(b) Bounding control: none at the transport layer in this shape; the application-level
leak channels a page can open (Referer, cache replay) are closed by the response-header
family (REG-10's sibling controls, §8 T3.3), and the harness-leg artifacts a capture
yields are themselves short-lived and PKCE-bound.
(c) Re-open: any exposure of the origin beyond the development host, or any real-world
use — TLS-front the public origin first. Covers T1.11, T1.12, T3.2, T3.4, T6.2.

**REG-2 — the E7 callback-interception variant.** The defense trio against the
code-injection chain (128-bit flow ids, state round-trip, destroy-on-first-use) kills
*guessing* a flow id; an attacker who *intercepts* the victim's identity-provider
callback URL off the wire delivers it to the gateway ahead of the victim's browser,
completes the upstream consent in their own browser, and Core stores the attacker's
upstream credential under the victim's `sub` — the victim's toolset traffic then
executes against the attacker's workspace.
(a) Accepting condition: the committed deployment's plain-http front door (REG-1); the
variant is a property of the transport, not of gateway behavior, so no gateway-spec
requirement can pin it.
(b) Bounding control: TLS-fronting the public origin — an interceptor of a TLS-fronted
callback has nothing to capture; inside this shape the residual stands unmitigated.
(c) Re-open: a TLS-fronted deployment makes the bounding control real and re-judges
this entry. Covers T3.2.

**REG-3 — no memory zeroization.** The signing key and the in-flight identity token
live in process memory for the process lifetime; CPython has no reliable wipe-on-demand
(immutable strings, library-held copies, allocator/GC behavior, traceback retention) —
the same managed-runtime reality as Java/Go/.NET.
(a) Accepting condition: the exposure class is host-read/memory-dump, the same class
the trust-boundary rulings already name for key custody and the DCR store's volume; no
Python-process control changes that.
(b) Bounding control: the never-store rules (no token at rest anywhere; the identity
token serves the flow's decision step and credential call, then is dropped), and the
TTLs — 10-minute access tokens, identity-token retention bounded by
min(flow TTL, the token's own `exp`).
(c) Re-open: the KMS/HSM sign-interface (`key_source: kms`, the stated production
direction), where the process holds a key reference, not a key. Covers T4.2, T4.1's
memory half, T5.1.

**REG-4 — the token-use rule is stated in purposes, not counts.** The identity token
serves exactly the sign-in flow — its decision step and its credential call; on Core
builds that do not enrich the settings route with per-caller statuses, the decision
step falls back to the listing route, so the token is presented three times — one more
internal-network presentation, within the same flow TTL and the same purpose, than an
enriching build.
(a) Accepting condition: the change tolerated both Core builds rather than pinning one.
(b) Bounding control: same flow, same purpose, internal network only, TTL-bounded.
(c) Re-open: pinning the latest Core (the recorded post-PoC simplification) collapses
the step back to one presentation. Covers T5.1's mis-use half.

**REG-5 — the shared worker pool is a bounded shared resource.** A sustained flood of
slow-leg requests within the rate limits queues legitimate legs behind the attacker's
queue. The event loop stays responsive (slow work is offloaded), and the one
unauthenticated attacker-steered slow leg — the CIMD fetch — is bounded by a capacity
limiter, so identity and credential legs keep capacity.
(a) Accepting condition: any bounded shared resource has this property; the
single-instance local shape accepts the residual queue-wait.
(b) Bounding control: the CIMD capacity limiter, the public-endpoint abuse limits
(§8 T1.5), worker-pool boundedness.
(c) Re-open: a multi-user deployment, or a sustained-flood incident — the HA/Redis
step revisits it. Covers T2.2.

**REG-6 — the DCR store's host/volume boundary.** The store's integrity is the
host/volume owner's responsibility — the same trust boundary and the same class of
material as the signing key, which host-level write access can likewise rewrite. The
owner-only file mode is best-effort: on a Windows host path bind-mounted into the
container (9p/DrvFs), `chmod` fails and every file carries the mount's fixed modes.
(a) Accepting condition: the store holds no secret (client ids, redirect URIs, a
display name, a timestamp; every client is public PKCE), and the boundary is the same
one that already guards the signing key.
(b) Bounding control: write-before-respond atomic replace (`os.replace`), corruption
fails closed and loudly at startup, a registration cap, DCR default-off.
(c) Re-open: a deployment where the volume is shared beyond the host owner, or the
HA step that moves the store to Redis with the other state. Covers T7.1, T7.2, T7.3.

**REG-7 — role staleness within a refresh window.** The claims DIAL authorization runs
on are a gateway-asserted snapshot at most `refreshTtl` (8 h default) old; a revoked
user's toolset access can outlive their Keycloak session by hours.
(a) Accepting condition: the self-contained-snapshot refresh was chosen with this
bound priced in — 8 h is three times fresher than the deployment's own vanilla bound
(the realm's 24 h access-token lifespan); options that buy freshness buy new trust
(a realm-wide technical client) or an availability dependency on the data path.
(b) Bounding control: the non-sliding window (the rotated refresh token carries the
original absolute `exp`) and the startup-enforced `refreshTtl ≤ IdP access-token
lifespan` check — machine-checked, not documented.
(c) Re-open: the owner's post-PoC refresh/SLA decision (the claims-re-fetch upgrade
path), or a deployment whose IdP lifespan is shorter than `refreshTtl`. Covers the
I4 bound in §10; no §8 threat lands on it directly (every authorization-relevant row
assumes the snapshot).

**REG-8 — a leaked gateway token is valid deployment-wide for its `sub`.** Binding is
marker-level only (`audience: dial-mcp-proxy` on the Core IdP entry); per-toolset
audience enforcement is not available in the flat single-issuer shape, because
harnesses discover the flat well-known and cannot reach per-toolset issuers.
(a) Accepting condition: the flat AS shape is fixed by measured harness discovery
behavior, not by choice; per-toolset IdP entries conflict with dynamic toolsets and
restart-on-settings-change.
(b) Bounding control: the audience marker (eliminates accidental cross-issuer
acceptance), the strict `resource` check at authorization and token endpoints (the
only per-toolset gate in the chain), and the 10-minute access TTL.
(c) Re-open: Core-side per-issuer path/audience scoping — a future Core configuration
feature, explicitly not a dependency. Covers T1.3.

**REG-9 — no per-user kill of live access tokens without key rotation.** Inherent to
non-introspected JWTs; Core does not introspect Keycloak's tokens either.
(a) Accepting condition: the class is the deployment's existing reality, not a new one.
(b) Bounding control: 10-minute access TTL; refresh denylist by `jti` until `exp`;
key rotation kills everything within the JWKS-cache window (≤ 10 min).
(c) Re-open: Core-side introspection, if it ever exists. Covers T1.4's tail.

**REG-10 — upstream consent attribution is display-only.** The upstream consent screen
shows Core's client, not the harness; no architecture gives an upstream AS
cryptographic attribution of its downstream clients' downstream clients.
(a) Accepting condition: inherent to OAuth federation; the one irreducible consent
belongs to Core's client because Core holds the verifier.
(b) Bounding control: recognizable client naming, the attribution interstitial (which
prefers a real `client_name` from CIMD metadata), and the end-to-end audit chain
(gateway flow log + Core's independent `/signin` record keyed by `sub`).
(c) Re-open: none known — no change or deployment fact fixes this; it is permanent.
Covers T1.10's attribution half, T3.7's context.

**REG-11 — non-OAUTH toolsets are excluded from the mapping, and GLOBAL-level
credential establishment stays an operator action.** A non-OAuth toolset entry refuses
startup unconditionally (an OAuth challenge in front of a non-OAuth credential is an
unsatisfiable 401 loop); GLOBAL sign-in is admin-gated in Core and not offered by the
flow.
(a) Accepting condition: v1 scope, enforced rather than documented; the
`route_only` escape was dropped because static routing cannot keep its promise.
(b) Bounding control: the startup refusal is loud; non-OAuth toolsets stay reachable
through Core's own paths via the router's catch-all.
(c) Re-open: the API-key toolset wrapper work, which brings its own routing mechanism
and UX. Covers no §8 threat (excluded surface), recorded for completeness.

**REG-12 — harness behavioral assumptions beyond the flagship.** Discovery shape,
CIMD registration, `resource` sending, and refresh-rotation adoption are measured for
Claude Code; other harnesses are expected, not tested.
(a) Accepting condition: the flagship harness is the one the deployment serves first;
revisit-on-named-failure is the rule, not silent tolerance.
(b) Bounding control: DCR retained behind a config flag, the one-toolset
`infer_resource_single_toolset` escape, the strict-`resource` default.
(c) Re-open: a named harness's measured failure. Covers no §8 threat directly; bounds
T1.1's and T1.2's residual reach.

**REG-13 — single instance, in-memory state, no HA.** Flow records, the code replay
cache, and the refresh denylist are in-memory; a restart loses in-flight flows (bounded:
plain-language error, one-command retry), can replay codes within their 5-minute TTL
(bounded: PKCE-bound to the original client's verifier, `redirect_uri`, `client_id`),
and resurrects revoked refresh tokens until their own `exp` (bounded: ≤ 8 h). Issued
tokens and DCR records survive (self-contained JWTs; the durable store).
(a) Accepting condition: the local single-instance shape; loss semantics are specified,
not accidental.
(b) Bounding control: the TTLs and PKCE bindings above; the plain-language error page.
(c) Re-open: the HA requirement — the documented Redis step. Covers T1.4's cache-loss
half.

**REG-14 — internal back-channels over plain http on the instance network.** The
gateway's calls to Core (`http://core:8080`) and Keycloak (`http://keycloak:8900`)
carry the in-flight identity token and the credential call with no transport
protection.
(a) Accepting condition: the compose network is operator-controlled and single-host in
this shape; the same network already carries Core's own `jwksUrl` fetch over http.
(b) Bounding control: network isolation of the compose network (external network join
is operator-configured); the gateway talks to services by name, never by
client-supplied address.
(c) Re-open: a multi-host deployment, or any untrusted tenant on the instance network.
Covers T5.2, T5.3.

---

## 4. Sensitive assets, sensitivity, footprints

| Asset | C | I | A | Footprints in the system |
|---|---|---|---|---|
| Gateway signing key (RSA private) | critical | — | — | Gateway process memory (REG-3); the gitignored key file injected via `.env` on the development host; the public half at the JWKS endpoint. Theft mints any `sub`, any roles, including admin. |
| Upstream access/refresh tokens (per user) | high | high | low | Core's encrypted per-user credential store only — never in the gateway, a harness, or transit. |
| Upstream PKCE verifier | high | — | — | Core only; nulled on every public projection of toolset settings. |
| In-flight identity token (Keycloak JWT, real DIAL identity) | high | — | — | Gateway flow-record memory during a flow (retention ≤ min(10-min flow TTL, the token's own `exp` — up to 24 h in this realm)); the internal http back-channels when presented (REG-4, REG-14). |
| Gateway access token | high | high | low | The harness's token store; the wire (plain http today, REG-1); Core's validator. 10-min TTL; valid deployment-wide for its `sub` (REG-8). |
| Gateway refresh token | high | high | low | The harness's token store; the wire. 8-h non-sliding window; carries the role snapshot (REG-7). |
| Harness-leg authorization code (self-contained JWT) | medium | — | — | The browser redirect to the harness `redirect_uri`; the wire. 5-min TTL, single-use, PKCE-bound. |
| Keycloak authorization code (for the gateway's client) | low | — | — | The E6 callback URL; PKCE-bound to the gateway's own verifier. |
| Flow record / flow id | — | high | low | Gateway memory; the `state` parameter on both federation legs and the callback URLs. Guessability is the integrity property (128-bit CSPRNG). |
| DCR registration store | — | medium | medium | One JSON file on the bind-mounted host volume; gateway memory behind it. Holds no secret. |
| Audit trail | — | high | medium | stdout/otel sink; the operator's record. Integrity = attributable chain (SR-4); no credential facts by construction. |
| Attribution on the interstitial | — | medium | — | The browser page between the legs (display-only, REG-10). |
| Toolset mapping / routing configuration | — | high | high | Gateway config (OAUTH-only, reserved names, startup-enforced); the committed nginx config; Core env (IdP entries, `allowedRedirectUris`). |
| `.env` on the development host | critical | — | — | Signing key, Keycloak admin credentials, test-user credentials. Host-read boundary. |

CIA marks: C = confidentiality, I = integrity, A = availability; "—" = not a
first-order property for that asset. The compromise-point tables (§9) state what an
attacker actually gains per component.

## 5. Trust boundaries

Attack vectors start from a trust boundary or another component; the boundaries,
who lives there, and what they can reach:

- **The public internet / development-host perimeter.** Everything that can reach
  `http://localhost:8090`. In today's shape this is the development host itself and
  whatever it exposes — co-located processes, and the LAN if the port is reachable.
  This is the boundary the plain-http residual (REG-1) lives on.
- **The browser / user session.** The user's browser holds the Keycloak SSO session
  and walks both federation legs. Legitimate business users and their actions
  (consents) live here; phishing and framing target it.
- **The harness boundary.** The harness's machine and token store. Legitimate
  business users live here; a harness is a bearer-token holder with no client secret.
- **The gateway container.** The gateway process, its memory (key, in-flight identity
  token, flow state), :8091 never host-published — the router is the only front door
  and the only authority for the peer identity. The operator lives around it.
- **The instance compose network.** Gateway ↔ Core ↔ Keycloak over internal plain
  http (REG-14). Operator-controlled; joined as an external network.
- **Core's credential boundary.** Upstream tokens, verifiers, per-user credential
  store — Core's, unchanged by this design.
- **The host / volume boundary.** The development host: `.env` (key, admin
  credentials), the DCR store volume, process memory via host read (REG-3, REG-6).
  Technical support and administrators live here.
- **The operator / deployment-owner boundary.** Core configuration (IdP entries,
  audience marker, `issuerPattern` on every provider, `allowedRedirectUris`), the
  mapping table, key rotation, the DCR flag, the audit sink. High-privileged,
  legitimate — and the source of the mis-use cases below.

## 6. Attacker inventory

Per the vendored instruction's Step 1 — potential attackers including legitimate
business users and high-privileged users:

1. **A network attacker against the front door** — on-path or off-path, able to reach
   `http://localhost:8090`: eavesdrops tokens and codes, impersonates the AS,
   intercepts callback URLs (REG-1, REG-2). In today's shape, a co-located process on
   the development host is the realistic resident of this class.
2. **A malicious harness user (legitimate business user)** — holds a valid DIAL
   identity and uses the surface exactly as permitted: floods public endpoints,
   registers attacker-shaped clients (DCR if enabled), enumerates statuses (T1.13),
   steers the CIMD fetch (T2.1–T2.3), impersonates a pre-registered client id for
   attribution (T1.10).
3. **A user attacking another user** — cross-user: guesses or intercepts a flow id to
   pair their upstream code with the victim's identity (T3.1, T3.2), captures codes
   via redirect-URI abuse (T1.1, T2.4).
4. **Technical support / an administrator (high-privileged)** — host access (key file,
   DCR store, memory), Core configuration, the mapping, the audit log, key rotation:
   can exfiltrate the key (T4.4), rewrite registrations (T7.1), silently weaken Core
   entries, or read the audit trail. Mis-use of permitted action, not hacking.
5. **The upstream toolset operator (semi-trusted party)** — controls the workspace a
   victim's toolset traffic executes against; is the beneficiary of the E7
   code-injection chain's exfiltration channel (T3.1, T3.2).
6. **A compromised sibling component** — nginx (challenge synthesis, data path),
   Core (everything it holds), Keycloak (authentication of federation flows): attack
   vectors that start from another component, enumerated at AEP6 and in §9.
7. **A tenant on the instance network** — anything else joined to the compose network:
   eavesdrops or spoofs the internal http back-channels (T5.2, T5.3, REG-14).

---

## 7. Attack surface — entry points

The itemized inventory (design-review §5.1's six), carried forward to the system as
it stands, with the implemented system's addition — the DCR store as a file-system
surface:

- **AEP1 — the public OAuth/AS surface on the front door**: the per-toolset
  protected-resource documents (E1), the flat AS metadata (E2), `/dial/authorize`
  (E3), `/dial/token` (E4), `/dial/register` (E5, config-gated DCR, default off),
  `/dial/{name}/status` (E9), `/dial/revoke` (E10), `/healthz`. All reachable
  unauthenticated through `http://localhost:8090`.
- **AEP2 — the CIMD fetch**: the gateway's server-side fetch of a client-supplied
  metadata-document URL — an SSRF surface a client steers.
- **AEP3 — the browser callbacks E6/E7 and the pages they render**: the Keycloak and
  upstream redirect targets, the attribution interstitial, the plain-language error
  pages.
- **AEP4 — the signing key and token minting**: key material in process memory and in
  the `.env`-injected file; minting at E4; verification at E4/E9/E10; the public half
  at the JWKS endpoint (E8).
- **AEP5 — the server-to-server calls into Core and Keycloak**: the toolset-settings
  fetch, the status listing fallback, `POST /v1/ops/toolset/signin`, the Keycloak
  token exchange — all over the instance network's internal plain http.
- **AEP6 — the nginx front router**: the 401 challenge synthesis (map + hide), the
  data-path proxying (`$is_args$args`, `proxy_buffering off`), location ordering and
  the reserved-name alternation.
- **AEP7 — the DCR store on its host volume**: one JSON file, parsed at startup,
  written on registration (only present if DCR is enabled).

## 8. Threat tables, per entry point

Structure per the vendored instruction, exactly. Classification convention: flow and
logic flaws (confused deputy, SSRF, mix-up) classify under Use Control Misconfiguration;
the leaf is what the attacker gains (identity → Spoofing of caller's identity, access →
Bypass Authorization), and the flaw is named in the description.

### AEP1 — the public OAuth/AS surface

| # | Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | C/I/A | Description |
|---|---|---|---|---|---|---|
| T1.1 | E3/E4, registration resolution | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Redirect-URI abuse for code capture | Harness-leg authorization code | C | The attacker registers or presents a `redirect_uri` they control (a DCR-registered URI if DCR is enabled; a loopback variant exploiting the port exception; a URI inside a fetched CIMD document — see T2.4) so the authorization code is delivered to them. Confused-deputy shape: the gateway is persuaded to address the code to the wrong party. The code stays PKCE-bound to the legitimate client's verifier, so the gain is real only where the attacker also controls the client side of the leg. |
| T1.2 | E4 | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | AS mix-up at the token endpoint | Gateway access token | I/C | A code minted by a different authorization server is presented at E4 (OAuth mix-up); if accepted, the attacker's AS becomes the unseen issuer behind a gateway token. |
| T1.3 | Any Core endpoint via a captured gateway token | Use Control Misconfiguration / Elevation of Privilege / Bypass Authorization | Cross-toolset, deployment-wide token replay | Gateway access token; every Core endpoint for that `sub` | C | A token minted for one toolset is replayed against every other toolset and every Core endpoint until its `exp` — binding is marker-level only (REG-8). Same user's own access, widened scope; the door it opens is every non-toolset Core surface. |
| T1.4 | E4 refresh grant | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Stolen refresh token replay | Gateway refresh token; minted access tokens | C | A lifted refresh token mints access tokens until its absolute `exp` (≤ 8 h). Rotation narrows the window; the in-memory denylist bounds revocation, and its loss on restart resurrects revoked tokens until `exp` (REG-13, REG-9). |
| T1.5 | E3 (and E5 if enabled) | Use Control Misconfiguration / Denial of Service / Resource Consumption | Flow-record flooding | Flow records; gateway memory | A | Unauthenticated browser endpoints allocate a flow record per hit; a trivial loop exhausts memory. |
| T1.6 | E4 | Use Control Misconfiguration / Denial of Service / Resource Consumption | Verification flood | CPU (RSA verification), worker pool | A | A loop of token-endpoint requests spends signature-verification CPU and pool occupancy without ever completing a flow. |
| T1.7 | E4/E9/E10, all parsers | Use Control Misconfiguration / Denial of Service / Crashing | Crafted request breaks the gateway | Gateway process | A | Malformed JWTs, oversized or hostile-encoded parameters, degenerate JSON — any input that reaches a parser or verifier unvalidated can crash the single instance (no HA, REG-13). |
| T1.8 | E3/E5 → interstitial rendering | Injection | Registrant-supplied text as XSS | The browser page at the callback; the flow it advances | I/C | A DCR registrant's `client_name` (or reflected flow context) is rendered into the interstitial; unescaped, it executes in the page that auto-continues an OAuth flow. Injection in the broad sense: attacker content becomes executable in a component. |
| T1.9 | E5 (if DCR enabled) | Use Control Misconfiguration / Denial of Service / Resource Consumption | DCR registration flood | DCR store (file and memory) | A | Open registration fills the store toward its cap and the volume's capacity; the endpoint is unauthenticated when the flag is on. |
| T1.10 | E3 | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Pre-registered client impersonation (mis-use) | Attribution on the interstitial; the audit trail | I | A legitimate user's local process presents a known pre-registered `client_id` (e.g. the flagship harness's) with its own loopback redirect; the interstitial and the audit then attribute the flow to the named harness. No client authentication exists by design (public PKCE clients) — the mis-use is rewarded with false attribution, not with anyone else's access. |
| T1.11 | The front door (all AEP1 endpoints) | Interception / Eavesdropping | Cleartext tokens and codes on the wire | Gateway tokens, codes, flow ids | C | Everything AEP1 exchanges crosses `http://localhost:8090` in the clear (REG-1); a co-located process or on-path observer reads bearer tokens as they are used. |
| T1.12 | The front door | Interception / Spoofing of the target (Man in the middle) | On-path AS impersonation | The harness's OAuth state; the PKCE verifier at E4 | C/I | With no TLS, an on-path attacker answers discovery and token requests in the gateway's name — serving a fake AS metadata document, harvesting the code plus `code_verifier` at a fake E4, and minting the tokens the harness then trusts. |
| T1.13 | E9 | Use Control Misconfiguration / Elevation of Privilege / Bypass Authorization | Status enumeration (mis-use) | Toolset sign-in statuses | C | A legitimate user walks `/dial/{name}/status` across every mapped toolset, probing the deployment's toolset inventory and per-user sign-in states beyond any need their own work states — using the endpoint exactly as permitted. Bounded: the statuses returned are the caller's own, and every refusal and hit is audited. |

### AEP2 — the CIMD fetch

| # | Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | C/I/A | Description |
|---|---|---|---|---|---|---|
| T2.1 | The fetch itself | Use Control Misconfiguration / Elevation of Privilege / Bypass Authorization | SSRF via the client-id URL | The instance network; Core/Keycloak internal endpoints; any link-local metadata service | C | The client-id URL is attacker-steered; the gateway is persuaded to fetch an internal address it can reach and its callers cannot (SSRF named; leaf = the internal access gained). The response is validated as a metadata document, so the direct read-back is bounded — the reach itself is the compromise. |
| T2.2 | The fetch's pool occupancy | Use Control Misconfiguration / Denial of Service / Resource Consumption | Slow-fetch flood | The shared worker pool | A | Slow fetches to attacker-chosen targets hold pool occupancy within the rate limits, queueing legitimate legs (REG-5). The capacity limiter bounds the attacker's share; the residual queue-wait stands. |
| T2.3 | The fetched document | Use Control Misconfiguration / Denial of Service / Crashing | Hostile metadata document | Gateway process | A | A hostile origin serves pathological content — maximal JSON nesting, oversized bodies, wrong content types — to break the parser or exhaust memory. |
| T2.4 | Registration resolution | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Attacker-chosen redirect URIs via CIMD | Harness-leg authorization code | C | An allowlisted origin the attacker controls (or compromises) serves a metadata document whose `redirect_uris` point at the attacker, making their URIs "registered" — the CIMD half of T1.1's capture path. |
| T2.5 | The fetch's connection | Interception / Spoofing of the target (Man in the middle) | DNS rebinding / fetch MITM | The metadata document's content | I | Between validation and connection the resolved address could change (rebinding), or an on-path attacker impersonates the origin, so the document validated is not the document served. |

### AEP3 — the browser callbacks E6/E7 and their pages

| # | Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | C/I/A | Description |
|---|---|---|---|---|---|---|
| T3.1 | E7 | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Flow-id guessing → code-injection chain | Per-user upstream credential binding in Core | I/C | An attacker who guesses an in-flight flow id hits E7 with their own upstream code (obtainable — the toolset's `code_challenge` is public and the consent is their own); the gateway would call `/signin` with the victim's identity token and the attacker's code, storing the attacker's upstream credential under the victim's `sub` — the victim's toolset traffic then executes against the attacker's workspace, an exfiltration channel for every query and tool argument. Killed by 128-bit CSPRNG flow ids, the state round-trip, and destroy-on-first-use. |
| T3.2 | E6/E7 off the wire | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | E7 callback-interception variant | Per-user upstream credential binding in Core | I/C | The same chain, entered by intercepting the victim's identity-provider callback URL off the wire (it carries the provider's code and the flow id as `state`) and delivering it ahead of the victim's browser. The guessing defenses do not address interception; the control is transport security — disclosed residual REG-2. |
| T3.3 | The interstitial's onward navigation | Interception / Eavesdropping | Cross-party Referer leak | Keycloak authorization code; flow id | C | The interstitial renders at the E6 callback URL, whose query carries the provider's code and the flow state, and navigates onward to the upstream's page and its third-party scripts; a default `Referer` delivers one party's issued code and flow state to a different party's page. |
| T3.4 | The interstitial (plain http) | Interception / Spoofing of the target (Man in the middle) | On-path rewrite of the auto-continue | The upstream authorization request the browser receives | I | With no TLS on the front door, an on-path attacker rewrites the interstitial's continuation target — the delivered upstream request (which carries Core's client, the public challenge, the flow id) — redirecting the consent leg to an attacker-controlled AS. |
| T3.5 | E6/E7 error pages | Injection | Reflected flow context as XSS | The browser page; the flow it would advance | I/C | Error pages render user-controlled context (client ids, resources, flow references); unescaped reflection executes in the page. Same class as T1.8, different entry. |
| T3.6 | E6/E7 parameters | Use Control Misconfiguration / Denial of Service / Crashing | Crafted callback parameters | Gateway process | A | Oversized or malformed `code`/`state`/error parameters hit the callback handlers' parsers; the single instance dies (REG-13). |
| T3.7 | The interstitial framed | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Framing the auto-continue | The victim's browser session; the federated flow | I | An attacker frames the auto-continuing page in a victim's browser: the interstitial's meta-refresh advances the upstream authorization leg — with the victim's identity-provider session — inside a context the attacker controls. The gain is driving the victim's own flow to completion for the attacker's benefit; framing is the named flaw. |
| T3.8 | E6/E7 | Use Control Misconfiguration / Denial of Service / Resource Consumption | Callback flood | Flow lookup; worker pool | A | A loop of garbage callbacks spends lookups and pool occupancy on the public surface — the callbacks' share of T1.5's class, distinct because no record is allocated (the lookup fails). |

### AEP4 — the signing key and token minting

| # | Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | C/I/A | Description |
|---|---|---|---|---|---|---|
| T4.1 | The key file on the host | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Key-file theft | The signing key; every Core identity | C/I | Today's custody is file-based: a generated RSA key in a gitignored path injected via `.env`. Host read is key compromise: whoever holds the file mints any `sub` with any roles, including admin — remotely valid until rotation (≤ JWKS cache 10 min + access TTL). The never-committed/never-logged discipline bounds the repo, not the host. |
| T4.2 | Gateway process memory | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Memory dump during a flow | The signing key; one in-flight identity token (live up to the realm's 24 h) | C/I | A memory-dump attacker gets the key (REG-3) and one user's full DIAL identity — the flow TTL (10 min) bounds the gateway's *retention*, not the token's life. The dump is host-read class; the identity token's 24 h realm lifespan makes its post-lift life the sharper half. |
| T4.3 | E4/E9/E10 verification | Injection | Crafted JWT against verification | Gateway's token acceptance decision | I | Attacker-crafted JWT headers — algorithm confusion, embedded-`jwk` headers, `kid` values steering key lookup — are the injection route into the verifier: persuading the library to verify with attacker-chosen key material. The leaf is code-execution-equivalent control of the accept decision, not a crash (that is T1.7). |
| T4.4 | Host / operator action | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Insider key exfiltration (mis-use) | The signing key | C/I | Technical support or an administrator — entitled to host access for legitimate operations — copies the key file or dumps memory; nothing in today's shape marks, detects, or bounds that use of permitted access. Bounded by rotation reach (≤ 10 min + TTL after detection) and the audit trail's absence of any legitimate reason to move the file. |

### AEP5 — the server-to-server calls into Core and Keycloak

| # | Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | C/I/A | Description |
|---|---|---|---|---|---|---|
| T5.1 | The internal presentations of the identity token | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Lifted identity-token replay; use beyond the flow | The user's DIAL identity (live up to 24 h) | C/I | The identity token presented to Core (two or three times per the token-use rule, REG-4) is a full DIAL identity on the internal network; lifted from memory (T4.2) or the wire (T5.2), it authenticates as the user to any Core endpoint until its own `exp` — hours after the flow that justified it is gone. The mis-use half: the gateway itself presenting it beyond the flow's decision step and credential call. |
| T5.2 | The internal http back-channels | Interception / Eavesdropping | Cleartext identity token on the instance network | In-flight identity token; the `/signin` call | C | The gateway's calls to `core:8080` and `keycloak:8900` carry the user's identity token in the clear on the compose network (REG-14); an instance-network eavesdropper collects live DIAL identities. |
| T5.3 | The internal back-channels | Interception / Spoofing of the target (Man in the middle) | Rogue Core/Keycloak on the network | The flow's decisions; the identity token's exchange | C/I | Without TLS or mutual authentication on the back-channels, a rogue service on the compose network answers in Core's or Keycloak's name. A spoofed identity-token exchange is bounded by JWKS verification (the token must still verify against Keycloak's keys), so the realistic gains are a spoofed *settings* or *status* answer steering the flow toward an attacker-chosen upstream leg, and capture of the gateway's outbound calls; the named flaw is network-level impersonation of a trusted peer. |
| T5.4 | Upstream/Core/Keycloak responses | Use Control Misconfiguration / Denial of Service / Crashing | Hostile upstream response | Gateway process | A | Error bodies, malformed JSON, and unexpected statuses from Core, Keycloak, or the upstream AS reach the gateway's parsers mid-flow; an unhandled shape crashes the single instance. |

### AEP6 — the nginx front router

| # | Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | C/I/A | Description |
|---|---|---|---|---|---|---|
| T6.1 | The router's config / the challenge synthesis | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Challenge-header tampering → credential phishing | The harness's OAuth trust in the AS the challenge names | C/I | A compromised or misconfigured router points `resource_metadata` at a hostile AS and phishes credentials at the proxy leg; the router also fronts the data path, so tampering there is protocol-level, not just forwarding. Router integrity is part of the auth protocol after the challenge-synthesis design — same class as any front-router compromise today, now load-bearing. |
| T6.2 | The :8090 listener | Interception / Spoofing of the target (Man in the middle) | Plain-http front door | Everything the front door carries | C/I | The router's listener is plain http with no HSTS (correctly: HSTS is inert on non-TLS) — the transport half of REG-1: on-path impersonation of the entire public surface, the router included. |
| T6.3 | The data path through the router | Use Control Misconfiguration / Denial of Service / Resource Consumption | Slow-client / SSE exhaustion | Router connection table; Core upstream slots | A | Streamable-HTTP GETs and SSE hold connections open (`proxy_buffering off`); a fleet of slow clients exhausts the router's connection table and Core's upstream slots — the router is a shared bottleneck no gateway-side limiter bounds. |
| T6.4 | Location ordering / the reserved-name alternation | Use Control Misconfiguration / Elevation of Privilege / Bypass Authorization | Reserved-name path capture | The AS surface vs. a toolset's MCP path | I/A | A toolset named `token` (or any reserved name) makes the AS-surface location capture `/dial/token/mcp` before the data-path regex — the toolset becomes unreachable, or (worse, in a mis-ordered config) AS traffic is captured by the data path. Startup refusal of reserved names and ordered, anchored locations are the defense. |
| T6.5 | Config generation from the mapping | Injection | Toolset-name injection into nginx config | The router's routing decisions | I | Toolset names flow into nginx regexes; a name carrying regex metacharacters could alter matching (config injection). The `^[a-z0-9-]+$` charset and startup enforcement close it. |

### AEP7 — the DCR store on its host volume

| # | Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | C/I/A | Description |
|---|---|---|---|---|---|---|
| T7.1 | The store file | Use Control Misconfiguration / Elevation of Privilege / Spoofing of caller's identity | Tampered store → redirect-URI substitution | Harness-leg authorization code | C | Host-level write rewrites a registration's `redirect_uris` to the attacker's, making future codes deliverable to them — T1.1's capture path entered through the volume rather than the endpoint. Trusted to the same boundary as the signing key (REG-6). |
| T7.2 | The store file at startup | Use Control Misconfiguration / Denial of Service / Crashing | Corrupt store → startup refusal | Gateway availability | A | An attacker (or accident) with host write corrupts the store; startup refuses to run — the corruption path is fail-closed, so the attacker with host access trades nothing for a clean stop of the service. Availability loss bounded by the one-command recovery. |
| T7.3 | The store file at parse | Injection | Hostile JSON content | Gateway process at startup | I/A | Well-formed hostile content in the store (attacker-shaped records) is loaded and trusted; unparseable content fails closed (T7.2). The boundary ruling (REG-6) is the defense — inside it, the parse is of owner-trusted material. |

---

## 9. Compromise-point tables

What an attacker gains by compromising each component, carried forward to the system
as it stands (the key-compromise blast radius included):

| Component compromised | Attacker gains | Notes in today's shape |
|---|---|---|
| Harness (or its token store) | That one user's gateway tokens → that user's toolset access **and every Core endpoint for that `sub`** until expiry (access ≤ 10 min; refresh ≤ 8 h; cross-toolset replay until `exp`, REG-8). No other user; no upstream tokens. | The tokens crossed plain http to get there (REG-1). |
| Gateway process | Mint-any-`sub`/any-role tokens; **one in-flight user's identity token, live until that token's own `exp` — up to 24 h in this realm** (the 10-min flow TTL bounds retention, not life); the audit log; write access to the DCR store; the signing key in memory. Not: upstream tokens, PKCE verifiers, stored credentials. | Memory zeroization does not exist (REG-3). |
| Gateway signing key alone (file or memory) | Remote mint-any-`sub`/any-role tokens — the blast radius equals Keycloak's signing key, minus operational maturity — until rotation (≤ JWKS cache 10 min + access TTL 10 min). Excludes upstream credentials: key compromise yields *use* of other users' toolset access, not *theft* of their upstream tokens. | Today's custody is the `.env`-injected file: host read is key compromise (T4.1); the audience marker does not shrink this radius — an attacker holding the key mints the marker too. |
| DCR store (host volume) | Registration rewrite → redirect-URI substitution (T7.1) — future code capture. No secret material in the store. | Same boundary as the signing key (REG-6); only present if DCR is enabled. |
| nginx front router | Challenge phishing (point `resource_metadata` at a hostile AS — T6.1) and data-path tampering; the whole public surface impersonated. | The challenge synthesis makes router integrity part of the auth protocol; plain http already concedes the transport (REG-1). |
| DIAL Core | Everything it holds today: per-user upstream credentials, the verifiers, authorization itself. | Unchanged by this design. |
| Keycloak | What it holds today, plus the ability to authenticate federation flows — the gateway still gates issuance, and the identity token still must verify against Keycloak's keys. | Unchanged. |
| The development host | `.env` (signing key, Keycloak admin credentials, test-user credentials), the DCR store volume, gateway process memory via host read. | The local shape's root boundary — everything above it in this table is reachable from here (REG-3, REG-6, T4.1, T4.4). |
| The browser / user session | Phished consents, framed auto-continues, false attribution read off the interstitial. | Display-level bound (REG-10). |

**Key-compromise blast radius, stated once, plainly:** the signing key is exactly as
powerful as Keycloak's — any `sub`, any roles, including admin, valid on every Core
endpoint. What bounds it in today's shape: 10-minute access TTLs; `kid` rotation
within Core's 10-minute JWKS cache; no `offlineClient` on the IdP entry (the gateway
issuer can never mint DIAL_NATIVE offline credentials); tokens minted only after a
live identity-provider authentication and the flow's DIAL authorization check. What
does not bound it: the audience marker (config-only, minted by the key holder too);
per-toolset scoping (not available in the flat shape — REG-8). What is honestly left:
a new, small-code authorization server with a smaller audit budget than the IdP it
equals — the reason the gateway must stay small and single-purpose.

## 10. Invariant ruling table (the never-cut list)

One row per invariant, all seven, ruled on the system as it stands:

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | **Preserved** | The gateway transits only the upstream authorization *code* — single-use, PKCE-bound to Core's verifier, useless to anyone else; no upstream access/refresh token transits or is stored by the gateway or any harness; the front path authenticates to Core with gateway-minted tokens only, never a caller's token relayed upstream. |
| 2 | The upstream PKCE verifier never leaves Core | **Preserved** | The upstream authorize URL is built from the toolset's *public* settings — the `code_challenge`, never the verifier; Core nulls the verifier on every public projection of the settings. No new exposure path exists. |
| 3 | Per-user credential isolation | **Preserved** | The credential call is made with the live user's identity token at USER level; Core stamps and resolves per `sub` as today. The code-injection chain at the upstream callback is killed against *guessing* (128-bit CSPRNG flow ids, state round-trip, destroy-on-first-use); the *interception* variant is disclosed residual REG-2, controlled at the transport layer. |
| 4 | DIAL authorization applies to every toolset call | **Preserved with a disclosed bound** | Every toolset call via the front door is validated and authorized by Core; the flow checks toolset read access before any upstream round-trip. The bound: the claims authorization runs on are a gateway-asserted snapshot at most `refreshTtl` (8 h) old — REG-7, non-sliding, startup-enforced against the realm's 24 h lifespan, fresher than the deployment's own vanilla bound. |
| 5 | No credential in logs, argv, or error messages | **Preserved** | Audit events carry flow id, subject, client, toolset, timestamps, results — never tokens, codes, keys, or verifiers; pre-allocation refusals are audited with fixed vocabulary and non-credential facts only, so a caller cannot write content into the log; error pages are plain-language and fail closed; evidence is redacted at capture time. The browser-side channel of the same invariant is closed by the response-header family: no `Referer` leaves a page rendered at the identity provider's callback URL (T3.3), no cached replay of a flow page. |
| 6 | No hardcoded credentials in the repository | **Preserved** | `.env.example` placeholders only; the signing key, the Keycloak admin credentials, and the test-user credentials come from gitignored `.env` material; the static gates (bandit, pip-audit) run on every diff. |
| 7 | The gateway's signing key is treated as IdP-grade secret material | **Preserved with a disclosed bound** | Never committed, never logged, `kid`-rotatable within Core's JWKS cache window. The bound, in today's shape: custody is *file-based* — a generated RSA key injected via `.env` on the host — not the KMS/HSM sign-interface that is the documented production direction; and process memory holds the key un-zeroized (REG-3). The bound is the local development shape's accepted state, re-opened by the KMS move. |

---

## 11. Mitigations per threat — the control-category grid

Every category appears for every threat, in the vendored order; "not applicable"
names the threat-specific property that defeats the category. Placement vocabulary
per the header: gateway spec / Core configuration / this repo's committed
configuration / the deployment / an upstream. The grid is working paper; the
reviewed result is the grouped list (§12).

### AEP1 — the public OAuth/AS surface

**T1.1 — redirect-URI abuse for code capture**
1. Reduce Attack Surface — registration is bounded to three paths (pre-registered,
   CIMD from allowlisted origins, DCR behind a default-off flag), so the set of
   registrable URIs is as small as the deployment allows. *Gateway spec; owner:
   gateway.*
2. Isolation — not applicable: the code is a self-contained single-use artifact bound
   to one client's verifier; there is no shared component inside the gateway whose
   isolation would contain its capture.
3. Authentication — the client's proof-of-possession is PKCE itself: the code is
   useless at E4 without the legitimate client's verifier, so what authenticates the
   redeemer is the verifier, not a secret. *Gateway spec; owner: gateway.*
4. Authorization — `redirect_uri` exact-match against the registration, with the
   loopback port exception keyed on the registered entry only (never on the
   request's value, no query or fragment tolerated); `resource` required and
   validated. *Gateway spec; owner: gateway.*
5. Data Protection — codes are 5-minute single-use JWTs (jti replay cache); a
   captured code ages out fast. *Gateway spec; owner: gateway.*
6. Anti-Injection — not applicable: the vector is parameter substitution on a
   redirect target, not delivery of executable content; nothing on this path
   executes attacker input.
7. Anti-DoS — not applicable: a forged redirect costs one validation and allocates
   nothing; the resource-consuming form of this surface is T1.5/T1.9, not capture.
8. Detective — every pre-allocation refusal (redirect-URI mismatch, unknown client)
   lands on the audit trail with fixed vocabulary and the non-credential facts
   offered. *Gateway spec; owner: gateway.*

**T1.2 — AS mix-up at the token endpoint**
1. Reduce Attack Surface — one flat AS, one issuer, one token endpoint: there is no
   second issuer whose code could be presented, collapsing the mix-up space. *Gateway
   spec + the design's flat-AS decision; owner: gateway.*
2. Isolation — not applicable: the flaw is a cross-*protocol* confusion between
   issuers, and no in-process boundary separates issuers the deployment does not
   have.
3. Authentication — not applicable: no caller identity exists on the harness leg
   (public PKCE clients by design); there is no principal to authenticate beyond the
   code's own validity.
4. Authorization — the code embeds the harness `client_id`, `redirect_uri`, and
   `code_challenge` it was minted for, and E4 enforces all three plus `resource`
   match; a foreign AS's artifact fails the signature first. *Gateway spec; owner:
   gateway.*
5. Data Protection — RFC 9207 `iss` in the authorization response lets the harness
   itself detect the wrong-AS case; `state` echo binds the response to the request.
   *Gateway spec; owner: gateway.*
6. Anti-Injection — not applicable: no attacker content is executed; the vector is a
   legitimate-shaped token from the wrong source.
7. Anti-DoS — not applicable: a single wrong-issuer code is one failed validation;
   no resource is consumed that the limiter for T1.6 does not already bound.
8. Detective — token-endpoint validation failures are audited pre-allocation.
   *Gateway spec; owner: gateway.*

**T1.3 — cross-toolset, deployment-wide token replay**
1. Reduce Attack Surface — not applicable in this shape: shrinking the surface means
   per-toolset issuers, which measured harness discovery behavior makes unreachable
   — the residual's accepting condition (REG-8).
2. Isolation — not applicable: the replay happens *outside* the gateway, at Core;
   no boundary the gateway draws contains a token already in a harness's store.
3. Authentication — the token's bearer nature is the threat; adding client
   authentication on the data path would change the MCP client contract the system
   exists to serve. Not applicable without breaking the served class.
4. Authorization — Core applies DIAL authorization on every call with the token's
   `sub` and roles: the replay gains *that user's own* access, deployment-wide —
   widening scope, not crossing users. *Core, owner: upstream (unchanged behavior).*
5. Data Protection — the 10-minute access TTL is the binding bound: the window of
   deployment-wide validity is short by construction. *Gateway spec (TTLs); owner:
   gateway.*
6. Anti-Injection — not applicable: the attacker presents a legitimate token; no
   content is injected.
7. Anti-DoS — not applicable: a replayed token spends one validation at Core, which
   is the traffic Core exists to take.
8. Detective — Core's own request telemetry sees the token's use across endpoints;
   the gateway's audit sees issuance. Anomalous cross-endpoint use is Core-side
   telemetry, not a gateway signal. *Upstream (Core); owner: deployment operator.*
   Disposition: **accepted — REG-8** (the structural fix is a Core-side ask,
   explicitly not a dependency).

**T1.4 — stolen refresh token replay**
1. Reduce Attack Surface — refresh tokens are minted only on the authorization-code
   grant, never handed out anywhere else. *Gateway spec; owner: gateway.*
2. Isolation — not applicable: the token lives in the harness's store, outside every
   boundary the gateway or deployment draws.
3. Authentication — not applicable: a refresh token *is* the credential; there is no
   second factor a public client could present (proof-of-possession would change the
   served harness class).
4. Authorization — E10 revocation (denylist by `jti` until `exp`) lets the owner
   kill a lifted token's refresh line; the denylist's in-memory loss is bounded by
   `refreshTtl` (REG-13). *Gateway spec; owner: gateway.*
5. Data Protection — the non-sliding absolute `exp` (≤ 8 h, startup-enforced ≤ the
   IdP's own lifespan) bounds the replay window structurally; rotation by default
   narrows it to the grace window. *Gateway spec; owner: gateway.*
6. Anti-Injection — not applicable: the artifact is a legitimately-signed token; no
   content is injected.
7. Anti-DoS — not applicable: each replay is one verification; volume is T1.6's
   shape.
8. Detective — rotated-token reuse outside the grace window is a detectable event at
   E4 (the old `jti` reappearing); the audit trail records refresh failures.
   *Gateway spec; owner: gateway.* Residual tail: **accepted — REG-9, REG-13.**

**T1.5 — flow-record flooding**
1. Reduce Attack Surface — only E3 (and gated E5) allocate records; every other
   public endpoint is stateless, so the allocating surface is two locations.
   *Gateway spec; owner: gateway.*
2. Isolation — flow records are a bounded, TTL-scoped in-memory map, structurally
   separated from the credential path; nothing durable is allocated. *Gateway spec;
   owner: gateway.*
3. Authentication — not applicable: E3 is an unauthenticated browser endpoint by
   protocol (the user has not authenticated anywhere yet); requiring auth here
   dead-ends the flow it exists to start.
4. Authorization — not applicable: there is no principal yet — the same
   protocol-stage property as category 3.
5. Data Protection — not applicable: the flooded resource is memory, not sensitive
   data; the records hold no credential until the Keycloak leg returns (and the
   identity token's retention is TTL-bounded).
6. Anti-Injection — not applicable: the flood is a volume attack; the attacker's
   parameters are validated inputs, not executable content.
7. Anti-DoS — the whole control set: per-source and global rate limits, a hard cap
   on live flow records, oldest-first eviction with the plain-language error page
   (bounded memory, no silent degradation). *Gateway spec; owner: gateway.*
8. Detective — limiter hits and evictions are auditable events (the 429 class is on
   the pre-allocation audit trail). *Gateway spec; owner: gateway.*

**T1.6 — verification flood**
1. Reduce Attack Surface — E4 does exactly two verifications per request (the
   presented artifact, the PKCE hash); no other public endpoint verifies signatures.
   *Gateway spec; owner: gateway.*
2. Isolation — verification runs on the worker pool, off the event loop, so the
   loop's responsiveness (and every other endpoint) survives the flood. *Gateway
   spec (pool design); owner: gateway.*
3. Authentication — not applicable: the flood is *of* authentication work;
   authenticating the caller first would require the client secret the public-PKCE
   design deliberately does not have.
4. Authorization — not applicable: an unauthenticated request has nothing to
   authorize; authorization would only add work to the flooded path.
5. Data Protection — not applicable: no data is exposed or altered; the resource is
   CPU.
6. Anti-Injection — not applicable: malformed inputs are the crash class (T1.7);
   well-formed floods consume CPU, which no input filter distinguishes from
   legitimate load.
7. Anti-DoS — the token endpoint joins the same rate limits as E3; per-source
   bounding makes the flood cost the attacker more than the pool. *Gateway spec;
   owner: gateway.*
8. Detective — rate-limit counters and token-endpoint failure rates are the
   operator's signal. *Gateway spec (audit/metrics); owner: gateway.*

**T1.7 — crafted request breaks the gateway**
1. Reduce Attack Surface — every endpoint validates its inputs before parsing
   (parameter presence, shape, size); nothing parses unvalidated bytes. *Gateway
   spec; owner: gateway.*
2. Isolation — the single instance is the whole service (REG-13): in today's shape
   there is no second instance to isolate the crash into. Not applicable *in this
   shape* — the HA step is the re-open.
3. Authentication — not applicable: a crash payload is malformed before any
   credential is examined; authentication cannot precede parsing the request itself.
4. Authorization — not applicable: same ordering property — the request must parse
   before any principal exists to authorize.
5. Data Protection — not applicable: the compromise is process availability, not
   data; crash handlers fail closed and emit no credential material.
6. Anti-Injection — malformed-input rejection *is* this category's contribution:
   strict content types, size caps, and bounded parse depth on every public parser
   (JWTs included, overlapping T4.3). *Gateway spec; owner: gateway.*
7. Anti-DoS — the crash-per-request form is bounded by the same rate limits as
   T1.5/T1.6: repeated crashes cost the attacker the limiter, one crash costs
   availability once. *Gateway spec; owner: gateway.* Residual: a crash-loop is a
   full outage until restart — **accepted with REG-13** (single instance).
8. Detective — startup and crash logs are the operator's detection; the compose-boot
   health probe is the machine check. *The deployment (health probe); owner:
   deployment operator.*

**T1.8 — registrant-supplied text as XSS**
1. Reduce Attack Surface — DCR (the registrant-controlled path) is config-gated,
   default off; with it off, no registrant text exists. *Gateway spec; owner:
   gateway + operator (the flag).*
2. Isolation — the rendered pages carry no privileges to isolate: the interstitial
   and error pages are static HTML with no script source at all. *Gateway spec; owner:
   gateway.*
3. Authentication — not applicable: the page renders mid-flow for a browser; the
   rendered content does not gate anything the attacker could authenticate into.
4. Authorization — not applicable: display content; the flow's authorization steps
   (settings read, DIAL check) do not consume the rendered text.
5. Data Protection — `Cache-Control: no-store` on every HTML response keeps a
   poisoned page from being replayed from cache. *Gateway spec (header family);
   owner: gateway.*
6. Anti-Injection — the active layer: HTML escaping of every rendered value; the
   second layer: `Content-Security-Policy: default-src 'none'` + `base-uri 'none'`
   on both page classes, so escaping regressions do not become execution.
   *Gateway spec; owner: gateway.*
7. Anti-DoS — not applicable: the input is one short string; its resource cost is a
   render, already inside T1.5's limits.
8. Detective — the audit trail records the registration (or refusal) whose
   `client_name` later rendered; the chain from a poisoned render back to its
   registrant is attributable. *Gateway spec; owner: gateway.*

**T1.9 — DCR registration flood**
1. Reduce Attack Surface — DCR default-off removes the endpoint and the
   advertisement entirely until an operator opts in. *Gateway spec; owner: operator
   (flag).*
2. Isolation — registrations live in their own bounded store, separate from flow
   state and tokens; the store's fill does not touch the credential path. *Gateway
   spec; owner: gateway.*
3. Authentication — not applicable: open registration is what DCR *is*; the
   accepting condition for enabling it is stated with the flag (registrant-controlled
   attribution accepted).
4. Authorization — the cap authorizes the store's shape, not a principal: at
   `DCR_MAX_REGISTRATIONS` the endpoint refuses new registrations with a
   plain-language error and never evicts (eviction would silently invalidate a live
   client). *Gateway spec; owner: gateway.*
5. Data Protection — not applicable: the store holds no secret (public clients
   only); nothing confidential is being filled.
6. Anti-Injection — registration fields are validated (URIs, names, sizes) and the
   stored record is a fixed four-field shape; render-side escaping is T1.8's layer.
   *Gateway spec; owner: gateway.*
7. Anti-DoS — the endpoint joins the public rate limits; the cap bounds the file.
   *Gateway spec; owner: gateway.*
8. Detective — registrations and cap refusals are audited. *Gateway spec; owner:
   gateway.*

**T1.10 — pre-registered client impersonation (mis-use)**
1. Reduce Attack Surface — the pre-registered list is operator configuration, so the
   impersonatable set is exactly what the operator names — one entry per harness the
   deployment actually serves. *The deployment (config); owner: operator.*
2. Isolation — not applicable: the mis-use happens at the attribution layer, in the
   browser and the log; no runtime boundary separates two clients that are, by
   design, indistinguishable (public PKCE, no secrets).
3. Authentication — not applicable: client authentication is the thing this design
   deliberately does not have — the served harness class registers without secrets;
   adding a shared secret would re-create the realm-policy failure class the design
   removes.
4. Authorization — the impersonator is still themselves at every layer that
   authorizes: the Keycloak leg authenticates *them*, DIAL authorization runs on
   *their* identity, the credential stamps *their* `sub`. The reward is a false
   label, not another user's access — the authorization layers make it so.
   *Upstream (Keycloak, Core); owner: upstream.*
5. Data Protection — not applicable: no data is disclosed; the compromise is the
   integrity of an attribution label.
6. Anti-Injection — not applicable: the label is a string the attacker selects from
   the operator's list; nothing executes.
7. Anti-DoS — not applicable: a single mis-attributed flow costs one flow record,
   inside T1.5's bounds.
8. Detective — the audit trail is the countermeasure: flow id, `sub`, presented
   `client_id` + `redirect_uri`, toolset, results — a mis-attributed flow is
   attributable end-to-end to the *acting user* regardless of the label worn.
   *Gateway spec; owner: gateway.* Disposition: **accepted — REG-10** (attribution
   is display-level by architecture; the audit chain is the guarantee that survives).

**T1.11 — cleartext tokens and codes on the wire**
1. Reduce Attack Surface — not applicable: the surface is the deployment's transport
   choice, not an endpoint the gateway can decline to expose.
2. Isolation — not applicable: eavesdropping crosses no process boundary; the
   boundary that would contain it (TLS) is the transport itself.
3. Authentication — not applicable: the attack reads traffic; no authentication of
   the parties exists without the transport that is missing.
4. Authorization — not applicable: no request is forged; legitimate requests are
   merely read.
5. Data Protection — the control, and it is the deployment's: TLS-front the public
   origin — the bounding control named in REG-1, **not in place in today's shape**.
   *The deployment; owner: deployment operator.* Application-level leak channels are
   closed regardless (no-referrer, no-store — T3.3's family).
6. Anti-Injection — not applicable: nothing is executed; the compromise is
   confidentiality in transit.
7. Anti-DoS — not applicable: reading traffic consumes none of the system's
   resources.
8. Detective — nothing in today's shape detects a sniffer; detection of the
   *consequences* (replayed artifacts) is T1.4's and T3.1's detective rows.
   Disposition: **accepted — REG-1.**

**T1.12 — on-path AS impersonation**
1. Reduce Attack Surface — not applicable: the impersonator answers the same URLs
   the deployment publishes; no endpoint can be withdrawn without withdrawing the
   service.
2. Isolation — not applicable: same transport-shape property as T1.11.
3. Authentication — the one control that defeats on-path impersonation is
   transport-level peer authentication — TLS server certificates; **not in place in
   today's shape** (REG-1). *The deployment; owner: deployment operator.*
4. Authorization — not applicable: the attacker serves, not requests; there is no
   request of theirs to authorize.
5. Data Protection — PKCE is the in-protocol backstop: a fake E4 harvests the
   `code_verifier`, but the *real* code's redemption at the real E4 races the
   attacker and the stolen code is single-use — the attacker must complete the whole
   exchange in the gateway's name, which TLS absent makes possible and PKCE alone
   does not prevent. Honest rating: partial. *Gateway spec (PKCE everywhere); owner:
   gateway.* Disposition: **accepted — REG-1** (the complete control is TLS).
6. Anti-Injection — not applicable: no code executes in the gateway; the harness is
   the component deceived, by protocol responses, not injected content.
7. Anti-DoS — not applicable: the attack serves traffic rather than consuming the
   system's.
8. Detective — a successful impersonation is visible only downstream (the gateway's
   own audit never sees the exchanged token); nothing in today's shape detects it.
   Disposition: **accepted — REG-1.**

**T1.13 — status enumeration (mis-use)**
1. Reduce Attack Surface — E9 serves only mapped toolsets and only the caller's own
   statuses; the enumerable set is the mapping, which is public by design (the
   challenge advertises it). *Gateway spec; owner: gateway.*
2. Isolation — not applicable: the probe reads the attacker's own data through a
   legitimate endpoint; no cross-user boundary is crossed to isolate.
3. Authentication — E9 requires a valid gateway token; anonymous probing is already
   refused. *Gateway spec; owner: gateway.*
4. Authorization — the statuses returned are resolved *as that user* at Core, so a
   user without access to a toolset gets the no-access status, not the toolset's
   state; the probe cannot exceed the prober's own authorization. *Upstream (Core,
   as-that-user resolution); owner: upstream.*
5. Data Protection — not applicable: the data returned is the caller's own state;
   the disclosure the mis-use seeks (the deployment's inventory) is public in the
   discovery documents by design.
6. Anti-Injection — not applicable: fixed-shape responses; nothing of the caller's
   is rendered or executed.
7. Anti-DoS — E9 joins the public rate limits. *Gateway spec; owner: gateway.*
8. Detective — every E9 request and refusal is audited with the toolset named — the
   enumeration pattern itself is the detectable signature. *Gateway spec; owner:
   gateway.* Disposition: mitigated to the display of the caller's own state; the
   inventory leak is inherent to public discovery — accepted as design.

### AEP2 — the CIMD fetch

**T2.1 — SSRF via the client-id URL**
1. Reduce Attack Surface — the fetch fires only for URL-shaped client ids on the
   operator's origin allowlist (default: the known harness metadata origin); every
   other client id never triggers a fetch. *Gateway spec; owner: gateway + operator
   (allowlist).*
2. Isolation — the fetch runs from the gateway container on the instance network;
   the deployment's network shape bounds which internal addresses are even
   reachable. *The deployment (network isolation); owner: deployment operator.*
3. Authentication — not applicable: the attacker never authenticates to the gateway
   to steer the fetch — the client id *is* the steering input on an endpoint that
   must accept unauthenticated clients by protocol.
4. Authorization — the origin allowlist is the authorization of fetch targets, and
   the resolved-address check (all A/AAAA records against private, loopback, and
   link-local ranges) is the authorization of connections. *Gateway spec; owner:
   gateway.*
5. Data Protection — HTTPS only, so the fetch cannot be read; no redirects followed
   (a 3xx fails — the pivot an SSRF attacker needs), connection pinned to the
   validated address with Host/SNI preserved (rebinding answers to the name but
   cannot redirect the connection). *Gateway spec; owner: gateway.*
6. Anti-Injection — not applicable: the fetched document is data, never executed;
   the closest executable-content risk is T2.3's parser crash, a different threat.
7. Anti-DoS — size cap 64 KiB, JSON content type required, connect/total timeouts
   5 s/10 s, bounded cache with TTL, and the capacity limiter (T2.2's control).
   *Gateway spec; owner: gateway.*
8. Detective — fetch attempts, allowlist refusals, and validation failures are
   audited pre-allocation. *Gateway spec; owner: gateway.*

**T2.2 — slow-fetch flood**
1. Reduce Attack Surface — the capacity limiter caps concurrent attacker-steered
   fetches, so the attacker's share of the pool is bounded by configuration, not by
   their patience. *Gateway spec; owner: gateway.*
2. Isolation — slow work is offloaded off the event loop; identity and credential
   legs keep reserved capacity. *Gateway spec (pool design); owner: gateway.*
3. Authentication — not applicable: the CIMD path is unauthenticated by protocol
   (pre-flow), the same stage property as T1.5.
4. Authorization — not applicable: the flood is of *capacity*, not of a protected
   action; the fetch itself is already authorization-bounded by T2.1's controls.
5. Data Protection — not applicable: the resource is worker occupancy; no data is
   exposed.
6. Anti-Injection — not applicable: volume attack; the attacker's URL is validated
   input.
7. Anti-DoS — the timeouts (5 s connect / 10 s total) bound each fetch's life; the
   rate limits bound frequency; the limiter bounds concurrency. *Gateway spec;
   owner: gateway.* Residual queue-wait: **accepted — REG-5.**
8. Detective — limiter and timeout counters on the audit/metrics surface.
   *Gateway spec; owner: gateway.*

**T2.3 — hostile metadata document**
1. Reduce Attack Surface — 64 KiB size cap and required JSON content type exclude
   the pathological body shapes before parsing. *Gateway spec; owner: gateway.*
2. Isolation — the parse runs on the worker pool, not the event loop. *Gateway
   spec; owner: gateway.*
3. Authentication — not applicable: the document arrives from a fetched origin; the
   origin allowlist (T2.1) is the trust decision, and no further principal exists.
4. Authorization — not applicable: parsing a document authorizes nothing; the
   *use* of its contents is authorized at T1.1's redirect validation.
5. Data Protection — not applicable: the compromise is process availability; the
   document holds no data of the system's.
6. Anti-Injection — bounded parse depth and strict schema (the metadata document's
   shape is fixed by the draft); nothing beyond the schema is retained.
   *Gateway spec; owner: gateway.*
7. Anti-DoS — the timeouts and cache bound repeated hostile fetches of the same
   client id. *Gateway spec; owner: gateway.*
8. Detective — parse failures are audited with the origin named. *Gateway spec;
   owner: gateway.*

**T2.4 — attacker-chosen redirect URIs via CIMD**
1. Reduce Attack Surface — the allowlist bounds which origins can contribute URIs at
   all. *Gateway spec; owner: gateway + operator.*
2. Isolation — not applicable: the document's URIs are data consumed at validation
   time; no isolation boundary separates "URIs the document offered" from "URIs the
   operator allowed" except the allowlist itself, which is category 1/4's control.
3. Authentication — not applicable: the CIMD model has no client secret to
   authenticate the document's owner; the origin allowlist is the substitute trust
   decision and is already spent.
4. Authorization — every presented `redirect_uri` must match the fetched document's
   `redirect_uris` (exact, loopback-port-exception keyed on the registered entry);
   the attacker's gain is therefore bounded to URIs the *allowlisted origin*
   published. *Gateway spec; owner: gateway.*
5. Data Protection — HTTPS-only fetch means the document the URIs came from is the
   origin's actual document, not a tampered copy in transit. *Gateway spec; owner:
   gateway.*
6. Anti-Injection — not applicable: URIs are matched, never executed or rendered
   unescaped (render-side is T1.8's layer).
7. Anti-DoS — not applicable: a single document's URIs cost nothing to validate;
   volume is T2.2/T2.3's shape.
8. Detective — the fetched document's origin and the redirect validation results
   are audited per flow. *Gateway spec; owner: gateway.* Residual: an attacker
   controlling an allowlisted origin (or the flagship harness's metadata host)
   publishes hostile URIs — bounded by allowlist curation; **accepted with REG-12's
   revisit-on-named-failure rule** (the allowlist is the operator's trust decision).

**T2.5 — DNS rebinding / fetch MITM**
1. Reduce Attack Surface — no redirects followed removes the redirect pivot
   entirely. *Gateway spec; owner: gateway.*
2. Isolation — not applicable: the attack is between the gateway and one external
   origin; no in-system boundary is crossed.
3. Authentication — TLS (HTTPS-only) authenticates the origin server — the control
   against the on-path half. *Gateway spec; owner: gateway.*
4. Authorization — the connection is made to the *validated* address with
   Host/SNI preserved: a rebinding answer to the name cannot redirect the
   connection — validation and connection are pinned together. *Gateway spec;
   owner: gateway.*
5. Data Protection — not applicable: the document's confidentiality is not the
   issue; its integrity is, which category 3/4's controls carry.
6. Anti-Injection — not applicable: no code executes; the document is data.
7. Anti-DoS — the timeouts bound a stalled rebinding attempt. *Gateway spec; owner:
   gateway.*
8. Detective — validation-vs-connection mismatches and fetch failures are audited.
   *Gateway spec; owner: gateway.*

### AEP3 — the browser callbacks E6/E7 and their pages

**T3.1 — flow-id guessing → code-injection chain**
1. Reduce Attack Surface — flow records exist for 10 minutes and are destroyed on
   first use at E7: the guessable window is minutes wide and each id is single-use.
   *Gateway spec; owner: gateway.*
2. Isolation — flow records are an in-memory map keyed by the flow id, unreachable
   except through E6/E7 lookup; there is no enumeration surface. *Gateway spec;
   owner: gateway.*
3. Authentication — not applicable: E7 is a browser callback the *user's* browser
   lands on; the protocol has no client credential to check here — the flow id's
   unguessability *is* the authentication of the callback's right to complete the
   flow.
4. Authorization — the upstream `state` must round-trip the flow id, and the flow
   record's identity token (the victim's) is what authorizes the `/signin` call —
   the chain's defense is that a guessed id without the record's contents cannot
   drive the credential call. *Gateway spec; owner: gateway.*
5. Data Protection — the flow id is 128-bit CSPRNG — the entropy is load-bearing
   (2⁻¹²⁸ per guess) and is specified as an entropy requirement, not an
   implementation accident. *Gateway spec; owner: gateway.*
6. Anti-Injection — not applicable: the attacker's *code* is a legitimate upstream
   artifact; the flaw is pairing, which categories 3–5's defenses kill, not content
   validation.
7. Anti-DoS — the callback rate limits bound guess loops (T3.8's class); each guess
   is one failed lookup. *Gateway spec; owner: gateway.*
8. Detective — E7 hits on unknown or destroyed flows are audited pre-allocation;
   a guess campaign is a visible pattern. *Gateway spec; owner: gateway.*

**T3.2 — E7 callback-interception variant**
1. Reduce Attack Surface — not applicable: the interceptor copies the victim's
   legitimate callback URL; there is no endpoint or parameter to withdraw.
2. Isolation — not applicable: the attack happens on the wire and in the
   attacker's browser; no in-system boundary is crossed before E7.
3. Authentication — not applicable: the intercepted artifacts are the victim's
   own, delivered intact; they authenticate as designed.
4. Authorization — the flow's own checks pass, because the attacker presents the
   genuine flow id; authorization cannot distinguish the delivering browser.
5. Data Protection — the control is transport confidentiality: TLS-front the public
   origin and the interceptor has nothing to capture. **Not in place in today's
   shape.** *The deployment; owner: deployment operator.* Disposition: **accepted —
   REG-2** (the model residual; re-opened by a TLS-fronted deployment).
6. Anti-Injection — not applicable: no content is injected; the artifacts are
   genuine.
7. Anti-DoS — not applicable: a single intercepted flow consumes one record.
8. Detective — the flow's audit trail records the `/signin` result under the
   victim's `sub` — the *consequence* is attributable after the fact, which is
   detection of the effect, not of the interception. *Gateway spec; owner: gateway.*

**T3.3 — cross-party Referer leak**
1. Reduce Attack Surface — the interstitial is the only page that renders at the
   callback URL and navigates onward; its existence is required for attribution, so
   the page cannot be withdrawn — but the leak channel is closed at the response.
2. Isolation — not applicable: the leak crosses parties via the browser's own
   Referer machinery; no system boundary is involved.
3. Authentication — not applicable: the leak rides legitimate navigation by the
   legitimate user.
4. Authorization — not applicable: the upstream page receives the Referer by
   browser default; no request of the system's is authorized or refused.
5. Data Protection — `Referrer-Policy: no-referrer` on the interstitial and the
   error pages — one line closing the whole cross-party channel (the provider's
   code and flow state never leave as Referer). *Gateway spec (header family);
   owner: gateway.*
6. Anti-Injection — not applicable: nothing executes; the compromise is disclosure
   by navigation metadata.
7. Anti-DoS — not applicable: no resource is consumed.
8. Detective — not applicable in practice: a Referer leak happens in third-party
   logs the system cannot see; the header's presence is asserted by a per-page-class
   header test instead. *Gateway spec (test); owner: gateway.*

**T3.4 — on-path rewrite of the auto-continue**
1. Reduce Attack Surface — not applicable: the rewrite targets the page the
   deployment serves over the transport it chose; no endpoint withdrawal helps.
2. Isolation — not applicable: transport-level attack, same shape as T1.12.
3. Authentication — TLS would authenticate the origin to the browser — the
   control, **not in place today**. *The deployment; owner: deployment operator.*
4. Authorization — not applicable: the attacker serves content; no request to
   authorize.
5. Data Protection — the delivered upstream request's integrity is what TLS
   would carry; in its absence the upstream leg's own TLS (the upstream AS's HTTPS)
   protects only the leg's second half — the first half (the interstitial to the
   rewritten target) is exposed. Partial, honest. Disposition: **accepted — REG-1.**
6. Anti-Injection — not applicable: the rewrite is content substitution at the
   transport, not executable content inside a component.
7. Anti-DoS — not applicable: serving rewritten pages consumes the attacker's
   resources.
8. Detective — a rewritten continuation lands the flow at an AS the gateway never
   named; the flow then fails loudly at the callback (unknown flow or refused
   state), which the audit trail records. Partial. *Gateway spec; owner: gateway.*

**T3.5 — reflected flow context as XSS**
1. Reduce Attack Surface — error pages render only the fixed-vocabulary facts the
   gateway itself selected (the pre-allocation audit's fact set), not raw caller
   input. *Gateway spec; owner: gateway.*
2. Isolation — the pages are script-free static HTML; there is no in-page state to
   isolate. *Gateway spec; owner: gateway.*
3. Authentication — not applicable: the page renders for an unauthenticated
   browser at a failure point; no credential exists to check.
4. Authorization — not applicable: display-only content at a flow's end.
5. Data Protection — `no-store` keeps error pages out of cache. *Gateway spec;
   owner: gateway.*
6. Anti-Injection — escaping of every rendered value plus the CSP second layer
   (`default-src 'none'`, `base-uri 'none'`) — same two-layer set as T1.8.
   *Gateway spec; owner: gateway.*
7. Anti-DoS — not applicable: one render per failed flow, inside the callback
   limits.
8. Detective — the refusal that produced the page is audited with the same facts
   the page shows. *Gateway spec; owner: gateway.*

**T3.6 — crafted callback parameters**
1. Reduce Attack Surface — E6/E7 validate parameter presence, shape, and size
   before any parsing or flow lookup. *Gateway spec; owner: gateway.*
2. Isolation — not applicable in today's shape (single instance, REG-13): the
   crash is the whole service; the HA step is the re-open.
3. Authentication — not applicable: parsing precedes any principal; a malformed
   `state` never becomes one.
4. Authorization — not applicable: same ordering property.
5. Data Protection — not applicable: availability compromise; crash handlers emit
   no credential material.
6. Anti-Injection — strict input validation on every callback parameter is this
   category's form here (bounded lengths, expected character sets for ids and
   codes). *Gateway spec; owner: gateway.*
7. Anti-DoS — callbacks join the public rate limits. *Gateway spec; owner:
   gateway.* Crash-loop residual: **accepted with REG-13.**
8. Detective — crash/startup logs and the health probe. *The deployment; owner:
   deployment operator.*

**T3.7 — framing the auto-continue**
1. Reduce Attack Surface — the interstitial auto-continues (meta-refresh + anchor,
   no script, no user action to wait for), which removes the dwell time a
   button-waiting page would give a framer. *Gateway spec; owner: gateway.*
2. Isolation — `frame-ancestors 'none'` + `X-Frame-Options: DENY` on both page
   classes: the browser refuses to render the page inside any frame — the
   isolation boundary is drawn by the response, in the browser. *Gateway spec
   (header family); owner: gateway.*
3. Authentication — not applicable: the frame carries the victim's own legitimate
   session; there is nothing unauthenticated to reject.
4. Authorization — not applicable: the flow advanced is the victim's own,
   legitimately authorized; the flaw is *who* benefits, which no authorization
   check can read.
5. Data Protection — not applicable: no data disclosure; the compromise is
   control of a navigation.
6. Anti-Injection — not applicable: no content is injected; the attacker's page
   frames, it does not modify.
7. Anti-DoS — not applicable: a framed attempt consumes one request.
8. Detective — a framed interstitial still completes a flow that appears in the
   audit trail under the victim's `sub` with the harness parameters — the effect
   is attributable after the fact. *Gateway spec; owner: gateway.*

**T3.8 — callback flood**
1. Reduce Attack Surface — callbacks that fail lookup allocate nothing; the
   handlers are lookup-first. *Gateway spec; owner: gateway.*
2. Isolation — not applicable: the flood is against one handler path on one
   instance; the pool-bound shape is the isolation that exists.
3. Authentication — not applicable: unauthenticated browser endpoints by protocol
   (same stage property as T1.5).
4. Authorization — not applicable: no principal exists on a garbage callback.
5. Data Protection — not applicable: no data is touched on failed lookups.
6. Anti-Injection — not applicable: volume attack on validated inputs.
7. Anti-DoS — the public-endpoint rate limits cover E6/E7 with the rest.
   *Gateway spec; owner: gateway.*
8. Detective — unknown-flow callback hits are audited pre-allocation; the pattern
   is the signal. *Gateway spec; owner: gateway.*

### AEP4 — the signing key and token minting

**T4.1 — key-file theft**
1. Reduce Attack Surface — the key exists in exactly two places (process memory,
   the gitignored file) and nowhere else: no store, no log, no argv, no committed
   artifact; `.gitignore` blocks the key file extensions outright. *Repo rules +
   gateway spec; owner: repo/gateway.*
2. Isolation — the file lives on the development host, readable by the host's
   boundary (its user); the container never publishes a key-serving endpoint beyond
   the *public* JWKS half. The boundary that matters is the host's own — the
   deployment's to own. *The deployment; owner: deployment operator.*
3. Authentication — not applicable: a stolen file needs no authentication — that
   is what theft means; authentication controls the *use* of the key, which is
   category 4/5's territory.
4. Authorization — the key itself authorizes (it is the signing authority);
   there is no higher authorization to check its use against. Not applicable
   without a KMS: the sign-interface (`key_source: kms`) is exactly an
   authorization wrapper around key use — **the production control, not built in
   today's shape**. *The deployment (future KMS); owner: deployment operator.*
5. Data Protection — file-based custody at the IdP-grade bar means: never
   committed, never logged, rotatable; the *placement* discipline is the data
   protection, and it holds. What does not hold today: KMS/HSM custody and memory
   zeroization (REG-3). *Gateway spec (discipline) + deployment (custody); owners:
   gateway / deployment operator.* Disposition: **accepted with the never-cut 7
   bound** (file-based custody in the local shape; re-opened by the KMS move).
6. Anti-Injection — not applicable: theft copies material; nothing is injected or
   executed.
7. Anti-DoS — not applicable: availability is untouched by copying a file.
8. Detective — key rotation is the *response*; detection of the theft itself has
   no in-shape control (a copied file leaves no trace); what is detectable is
   anomalous minting, and nothing in today's shape watches the mint path — an
   honest gap, bounded by rotation reach (≤ 10 min + TTL after *detection*).
   Disposition: **accepted — REG-3's class, with rotation as the standing remedy.**

**T4.2 — memory dump during a flow**
1. Reduce Attack Surface — the never-store rules keep the process memory as small
   as it can be: no token at rest, the identity token only mid-flow, dropped once
   its action is spent. *Gateway spec; owner: gateway.*
2. Isolation — the gateway container is one boundary; within it, memory is one
   space — no in-process isolation defeats a dump. Not applicable beyond the
   container wall.
3. Authentication — not applicable: the dump reads artifacts that need no
   authentication to be replayed elsewhere (the identity token authenticates *as
   the user* wherever presented).
4. Authorization — the dumped identity token's presentations at Core are
   authorized by Core exactly as the user's — which is the threat, not a defense;
   no in-shape control bounds the token's post-lift life.
5. Data Protection — retention bounded by min(flow TTL 10 min, the token's own
   `exp`); the access TTL (10 min) bounds anything the *key* mints. The residual
   is the 24 h realm lifespan of a lifted identity token — honest, unbounded by
   anything the gateway controls. *Gateway spec (TTLs) + upstream (realm lifespan);
   owners: gateway / deployment operator.* Disposition: **accepted — REG-3.**
6. Anti-Injection — not applicable: the dump is a read.
7. Anti-DoS — not applicable: no availability impact.
8. Detective — nothing detects a memory dump in today's shape; the audit trail
   bounds the *flow* that was in flight. Disposition: **accepted — REG-3.**

**T4.3 — crafted JWT against verification**
1. Reduce Attack Surface — the gateway verifies JWTs at exactly three endpoints
   (E4, E9, E10) and mints at one; the verification surface is enumerated, not
   ambient. *Gateway spec; owner: gateway.*
2. Isolation — not applicable: the crafted token enters the verifier by design;
   isolation would mean not verifying, which is not an option for an AS.
3. Authentication — not applicable: the *attack* targets the authentication
   mechanism itself; category 6 is where key-material selection is pinned.
4. Authorization — not applicable: authorization consumes a *verified* token;
   the flaw is upstream of it.
5. Data Protection — not applicable: no data is disclosed by a verification
   attempt.
6. Anti-Injection — the controls: pinned algorithm set (RSA256 only, per Core's
   own verifier), `kid` lookup restricted to the gateway's own keys (embedded-`jwk`
   and `x5c` headers never select key material), a maintained verification library
   (`pyjwt[crypto]`) with the dependency-audit gates on every diff. *Gateway spec +
   repo gates; owner: gateway.*
7. Anti-DoS — malformed tokens are rejected by parsing limits before signature
   work (T1.7's class); verification volume is T1.6's limits. *Gateway spec; owner:
   gateway.*
8. Detective — verification failures are audited pre-allocation with fixed
   vocabulary. *Gateway spec; owner: gateway.*

**T4.4 — insider key exfiltration (mis-use)**
1. Reduce Attack Surface — the key file has exactly one legitimate consumer (the
   gateway process at startup); every other touch is already outside legitimate
   use, which makes the operational rule crisp. *The deployment; owner: deployment
   operator.*
2. Isolation — not applicable: the insider's entitlement *is* host access;
   isolation inside the host against its administrator is not a control this shape
   can draw.
3. Authentication — not applicable: the action (reading a file on a host one
   administers) authenticates nowhere.
4. Authorization — as with T4.1: without KMS there is no authorization wrapper
   around key use; the sign-interface is the structural fix, not built. *The
   deployment (future KMS); owner: deployment operator.*
5. Data Protection — the never-committed/never-logged discipline makes the *repo*
   clean, but the host file is within the admin's legitimate reach — data
   protection bounds the artifact's copies, not the admin's eyes. Partial. *Repo
   rules; owner: repo.* Disposition: **accepted — the never-cut 7 bound** (same
   entry as T4.1: file-based custody, host-trusted operator).
6. Anti-Injection — not applicable: a copy operation, not content.
7. Anti-DoS — not applicable.
8. Detective — the honest statement: nothing in today's shape marks or detects a
   key-file read by an entitled operator; rotation bounds the *effect* after
   detection, and detection rests on the operator's own process. Disposition:
   **accepted with the never-cut 7 bound.**

### AEP5 — the server-to-server calls into Core and Keycloak

**T5.1 — lifted identity-token replay; use beyond the flow**
1. Reduce Attack Surface — the token is *retained* only mid-flow and presented only
   at the two (or three, per the token-use rule) specified calls; every presentation
   is on the internal network. The rule is stated in purposes, not counts (REG-4).
   *Gateway spec; owner: gateway.*
2. Isolation — the token crosses only the gateway↔Core boundary on the compose
   network; the deployment's network shape is the isolation. *The deployment;
   owner: deployment operator.*
3. Authentication — the token *is* the authentication; what bounds its misuse is
   that Core authorizes per presentation as today — the same exposure vanilla DIAL
   has for every token it accepts. Not a new class. *Upstream (Core); owner:
   upstream.*
4. Authorization — each presentation authorizes exactly the call it makes (settings
   read, status listing, `/signin` at USER level); a replayed presentation gains the
   user's own access — the 24 h post-lift life is the unbounded half.
   *Upstream (Core); owner: upstream.*
5. Data Protection — no `offline_access` is ever requested (the gateway's Keycloak
   client requests no refresh token), so the artifact's life is the realm's
   access-token lifespan and nothing extends it. *Gateway spec (client scopes) +
   upstream (realm lifespan 24 h); owners: gateway / deployment operator.*
   Disposition: retained-life bounded by design; post-lift life **accepted — REG-3/
   REG-14's class** (host-read or network-read is the precondition).
6. Anti-Injection — not applicable: the artifact is genuine and legitimately
   signed; nothing is injected.
7. Anti-DoS — not applicable: a replay consumes one Core call.
8. Detective — the flow's audit trail records the presentations' purposes (the
   settings read, the `/signin` result); a presentation outside a flow would be a
   Core-side anomaly, not a gateway signal. Partial. *Upstream (Core telemetry);
   owner: deployment operator.*

**T5.2 — cleartext identity token on the instance network**
1. Reduce Attack Surface — the back-channels are exactly two service-name
   destinations; no client-supplied address is ever called (that surface is the
   CIMD fetch, T2.1's). *Gateway spec; owner: gateway.*
2. Isolation — the compose network is operator-controlled and joined as an
   external network by configuration; the tenants of that network are the
   deployment's choice. *The deployment; owner: deployment operator.*
3. Authentication — not applicable to the eavesdropper: reading traffic
   authenticates no one and is authenticated by no one.
4. Authorization — not applicable: no forged request.
5. Data Protection — TLS on the back-channels is the control — **not in place
   today** (REG-14); the accepting condition is the operator-controlled
   single-host network. *The deployment; owner: deployment operator.* Disposition:
   **accepted — REG-14.**
6. Anti-Injection — not applicable: a read, not content.
7. Anti-DoS — not applicable.
8. Detective — a lifted token's use appears in Core telemetry under the user's
   identity; the lift itself is invisible. Disposition: **accepted — REG-14.**

**T5.3 — rogue Core/Keycloak on the network**
1. Reduce Attack Surface — service-name destinations only, no redirects followed,
   addresses resolved by the deployment's DNS: the reachable set is the compose
   network's own services. *Gateway spec + deployment; owners: gateway / deployment
   operator.*
2. Isolation — the network join is configuration; an untrusted tenant on the
   compose network is a deployment defect this control surfaces. *The deployment;
   owner: deployment operator.*
3. Authentication — partial: the identity-token exchange verifies the returned
   token against Keycloak's JWKS (a rogue Keycloak cannot mint an acceptable
   token); the *settings* and *status* answers have no such verification — the
   honest gap the description names. *Upstream (JWKS verification); owner: upstream.*
4. Authorization — the flow's DIAL-authorization check consumes the settings
   answer only for status display and leg routing; the credential call itself is
   authorized by the genuine token. Bounded. *Upstream (Core); owner: upstream.*
5. Data Protection — not applicable beyond T5.2's transport entry: the rogue
   peer's gain is steering and capture, which REG-14's acceptance covers.
   Disposition: **accepted — REG-14.**
6. Anti-Injection — not applicable: the rogue serves responses, not executable
   content.
7. Anti-DoS — a rogue peer refusing answers fails the flow loudly (T5.4's
   fail-closed); no additional control needed.
8. Detective — settings-answer anomalies (unknown fields, refused statuses) are
   audited per flow. *Gateway spec; owner: gateway.*

**T5.4 — hostile upstream response**
1. Reduce Attack Surface — the gateway talks to a fixed set of peers (Core,
   Keycloak, the toolset's configured endpoints) and validates response shapes
   before consuming them. *Gateway spec; owner: gateway.*
2. Isolation — offloaded to the worker pool, off the event loop. *Gateway spec;
   owner: gateway.*
3. Authentication — not applicable: the peer's response arrives on an
   already-trusted channel; there is no per-response credential.
4. Authorization — not applicable: a malformed answer authorizes nothing — the
   flow fails before any credential action.
5. Data Protection — not applicable: availability compromise; fail-closed paths
   emit no credential material.
6. Anti-Injection — bounded response parsing (schema-validated, size-capped
   bodies) so hostile shapes never execute or corrupt state. *Gateway spec; owner:
   gateway.*
7. Anti-DoS — timeouts on every upstream call bound a stalling peer.
   *Gateway spec; owner: gateway.* Crash residual: **accepted with REG-13** (single
   instance).
8. Detective — upstream failures are audited per flow with the peer and reason
   named. *Gateway spec; owner: gateway.*

### AEP6 — the nginx front router

**T6.1 — challenge-header tampering → credential phishing**
1. Reduce Attack Surface — the synthesized challenge quotes a *configured*
   `$mcp_origin`, never a request-derived value, so the advertised origin is not
   caller-influenceable. *This repo's committed configuration; owner: repo.*
2. Isolation — the router is a dedicated container whose only privilege is
   routing; its compromise is the deployment's to bound (config and image
   integrity). *The deployment; owner: deployment operator.*
3. Authentication — not applicable: the router forwards and synthesizes; it
   authenticates nothing (by design — the AS does).
4. Authorization — not applicable: the router authorizes no request; the
   phishing harm is done at the harness's trust in the challenge, upstream of any
   authorization.
5. Data Protection — the `proxy_hide_header` + `map $status` form delivers the
   property that a 401 carries the gateway's challenge and *nothing of the
   upstream's* — the measured form; the `error_page` shape leaked Core's header on
   this path and was replaced for exactly this reason. *This repo's committed
   configuration; owner: repo.*
6. Anti-Injection — not applicable: config-level tampering, not content injected
   into a component.
7. Anti-DoS — not applicable: the tampering serves traffic; availability is
   untouched.
8. Detective — the committed router config is in the repo, so any change to the
   challenge synthesis is a reviewable diff — the detective control is the repo's
   review gates on that diff. *The repo; owner: repo.* Disposition: router
   compromise is the deployment's standing front-router exposure, load-bearing now
   (the challenge synthesis is part of the auth protocol) — **accepted as the
   same class as any front-router compromise today**, bounded by config review.

**T6.2 — plain-http front door (router listener)**
1. Reduce Attack Surface — not applicable: the listener is the service.
2. Isolation — not applicable: transport shape, as T1.11/T1.12.
3. Authentication — TLS server authentication, **not in place today**; HSTS is
   correctly absent (inert on non-TLS) and belongs to the future TLS listener.
   *The deployment; owner: deployment operator.*
4. Authorization — not applicable.
5. Data Protection — TLS-fronting the origin; the deployment layer's own
   listener. **Not in place today.** *The deployment; owner: deployment operator.*
   Disposition: **accepted — REG-1.**
6. Anti-Injection — not applicable.
7. Anti-DoS — not applicable.
8. Detective — not applicable (the sibling rows T1.11/T1.12 carry the honest
   nothing). Disposition: **accepted — REG-1.**

**T6.3 — slow-client / SSE exhaustion at the router**
1. Reduce Attack Surface — `proxy_buffering off` is required by SSE/streamable
   HTTP (the served protocol), so the held-connection surface cannot be withdrawn;
   honest: not applicable.
2. Isolation — the router's connection table is nginx's own, bounded by worker
   configuration, separate from the gateway's pool. *This repo's committed
   configuration (nginx tuning); owner: repo / deployment operator.*
3. Authentication — not applicable: slow clients hold connections open before
   any authentication matters; authentication would not close an open socket.
4. Authorization — not applicable: no request is made to authorize.
5. Data Protection — not applicable: availability attack.
6. Anti-Injection — not applicable.
7. Anti-DoS — nginx-level connection/timeouts tuning (`proxy_read_timeout`,
   worker/connection limits) bounds slow-client holding; the values are the
   deployment's knobs. *This repo's committed configuration + deployment; owner:
   deployment operator.* Residual: a determined slow-client fleet can still exhaust
   the front — **accepted for the local shape** (no external exposure worth
   defending beyond the host).
8. Detective — router access/error logs show the connection saturation pattern.
   *The deployment (nginx logs); owner: deployment operator.*

**T6.4 — reserved-name path capture**
1. Reduce Attack Surface — the startup check refuses the reserved names
   (`authorize`, `token`, `register`, `revoke`, `callback`, `jwks.json`) outright,
   mirroring the router's alternation verbatim so guard and routing stay in step.
   *Gateway spec; owner: gateway.*
2. Isolation — the AS-surface locations are ordered before the data-path regex
   and the data path is anchored (`^/dial/<name>/mcp$`) — belt and braces at the
   routing layer. *This repo's committed configuration; owner: repo.*
3. Authentication — not applicable: the capture misroutes before any
   authentication could matter.
4. Authorization — the misrouting bypasses the intended endpoint's checks (the
   AS surface instead of the data path, or vice versa) — the leaf; the defense is
   the routing discipline of categories 1–2, not an authorization rule.
5. Data Protection — not applicable: routing, not data.
6. Anti-Injection — the `^[a-z0-9-]+$` name charset keeps regex metacharacters
   out of the paths the locations match (overlaps T6.5). *Gateway spec; owner:
   gateway.*
7. Anti-DoS — not applicable: a single misrouted toolset is an outage of that
   toolset's path, not a resource attack — and it cannot exist with the startup
   check green.
8. Detective — a misconfigured mapping refuses at startup, loudly, naming the
   collision — the fail-loud rule as detection. *Gateway spec; owner: gateway.*

**T6.5 — toolset-name injection into nginx config**
1. Reduce Attack Surface — toolset names never reach nginx config as free text:
   the regexes are static in the committed config, parameterized only by the
   charset-validated name. *This repo's committed configuration + gateway spec;
   owner: repo / gateway.*
2. Isolation — not applicable: the injection target would be the config file
   itself; no runtime boundary separates config from names because names never
   enter config generation.
3. Authentication — not applicable: config text, not a request.
4. Authorization — not applicable.
5. Data Protection — not applicable.
6. Anti-Injection — the control: `^[a-z0-9-]+$` enforced at startup on every
   mapping entry — no metacharacter survives to any regex. *Gateway spec; owner:
   gateway.*
7. Anti-DoS — not applicable.
8. Detective — the startup validation refusal is loud and names the offending
   entry. *Gateway spec; owner: gateway.*

### AEP7 — the DCR store on its host volume

**T7.1 — tampered store → redirect-URI substitution**
1. Reduce Attack Surface — the store exists only if DCR is enabled (default off);
   with it off there is no file to tamper. *Gateway spec; owner: operator (flag).*
2. Isolation — the volume is host material trusted to the same boundary as the
   signing key; inside that boundary no further isolation is claimed (REG-6's
   ruling). *The deployment; owner: deployment operator (host/volume owner).*
3. Authentication — not applicable: the file is read at startup by the process,
   entitled to read it; there is no counterparty to authenticate.
4. Authorization — no mechanism authorizes store writes beyond the boundary —
   the residual's accepting condition (same class as the signing key, which host
   write can likewise rewrite). Not applicable *inside* the boundary; the boundary
   is the control. Disposition: **accepted — REG-6.**
5. Data Protection — the record shape is fixed (four fields, no secret), so what
   a tamper can *plant* is bounded to redirect URIs and names — nothing
   confidential to protect. *Gateway spec; owner: gateway.*
6. Anti-Injection — the parse is schema-bounded (T7.3); the *use* of planted
   records is authorization-bounded at T1.1's redirect validation against what the
   store says — which the tamper controls; honest: partial, and the partial is
   REG-6's acceptance.
7. Anti-DoS — not applicable: a tamper is a write, not a volume attack.
8. Detective — the audit trail records registrations as they happen; a tampered
   store's records diverge from the trail (registrations the trail never saw) —
   attributable after the fact. *Gateway spec; owner: gateway.*

**T7.2 — corrupt store → startup refusal**
1. Reduce Attack Surface — the write path is atomic (temporary file +
   `os.replace`), so the gateway's own writes cannot half-write the store; only
   out-of-band host writes can corrupt. *Gateway spec; owner: gateway.*
2. Isolation — not applicable: the failure is the gateway process's own startup,
   by design fail-closed.
3. Authentication — not applicable: a startup read of a local file.
4. Authorization — not applicable.
5. Data Protection — not applicable: availability, not data.
6. Anti-Injection — an unparseable store is *rejected*, not repaired or
   interpreted — no content executes from a corrupt file. *Gateway spec; owner:
   gateway.*
7. Anti-DoS — the honest shape: an attacker with host write can stop the service
   by corruption — but host write is already game-over for T4.1/T7.1; the
   one-command recovery (rename aside, restart) is the operator's bound.
   *The deployment; owner: deployment operator.* Disposition: **accepted — REG-6's
   boundary.**
8. Detective — the startup error is loud and names the path. *Gateway spec;
   owner: gateway.*

**T7.3 — hostile JSON content**
1. Reduce Attack Surface — the store's schema is four fixed fields; anything
   else in the file is refused at parse. *Gateway spec; owner: gateway.*
2. Isolation — not applicable: a trusted-boundary file parsed by the process
   that owns it.
3. Authentication — not applicable.
4. Authorization — planted records are *used* only through T1.1's redirect
   validation — the tamper's reach, per T7.1. Partial by acceptance.
5. Data Protection — no secret in scope. Not applicable.
6. Anti-Injection — bounded parse (size, depth, schema) of the file at startup.
   *Gateway spec; owner: gateway.*
7. Anti-DoS — the cap bounds the file's size at write time. *Gateway spec;
   owner: gateway.*
8. Detective — startup parse failures are loud. *Gateway spec; owner: gateway.*

---

## 12. The grouped final mitigation list (the reviewed result)

The per-threat proposals reviewed and grouped: one mitigation often addresses several
threats. Each entry carries its placement and owner, and — honestly — whether it is
in place in today's shape or is the named control for an accepted residual.

- **M1 — TLS fronting of the public origin.** Transport confidentiality and peer
  authentication for everything the front door carries. *The deployment; owner:
  deployment operator. Not in place today (REG-1's accepting condition); required
  before any real-world use.* Addresses: T1.11, T1.12, T3.2 (REG-2's bounding
  control), T3.4, T6.2.
- **M2 — 128-bit CSPRNG flow ids, state round-trip, destroy-on-first-use.** The
  kill-list for the code-injection chain's guessing form. *Gateway spec; owner:
  gateway. In place.* Addresses: T3.1.
- **M3 — strict, required `resource` validation (`invalid_target`), flat single-AS
  discovery.** The only per-toolset gate in the chain, and the mix-up collapse.
  *Gateway spec; owner: gateway. In place.* Addresses: T1.2, T1.3 (partially — with
  M5), T1.13's routing scope.
- **M4 — redirect-URI exact-match with the keyed loopback port exception.**
  *Gateway spec; owner: gateway. In place.* Addresses: T1.1, T2.4, T7.1's use-path.
- **M5 — PKCE S256 on every leg, RFC 9207 `iss`, `state` echo.** Three independent
  PKCE pairs; no verifier crosses a trust boundary. *Gateway spec; owner: gateway.
  In place.* Addresses: T1.1, T1.2, T1.4 (partially), T1.12 (partial backstop).
- **M6 — the `dial-mcp-proxy` audience marker on the Core IdP entry.**
  *Core configuration; owner: deployment operator. In place.* Eliminates accidental
  cross-issuer acceptance; does not shrink key-compromise blast radius. Addresses:
  T1.3 (to its marker-level bound — residual REG-8).
- **M7 — `issuerPattern` on every JWT provider entry (including the existing
  Keycloak one).** *Core configuration; owner: deployment operator. In place.*
  Addresses: the issuer-selection misconfiguration class behind T1.3/T4.3.
- **M8 — the TTL lattice: 10-min access, 5-min single-use code, non-sliding 8-h
  refresh, startup-enforced `refreshTtl ≤ IdP access-token lifespan`, 10-min flow.**
  *Gateway spec; owner: gateway. In place.* Addresses: T1.3, T1.4, T3.1's window,
  T4.2's key-mint half, REG-7's bound.
- **M9 — refresh rotation by default + `jti` denylist (E10).** *Gateway spec;
  owner: gateway. In place (denylist loss bounded — REG-13).* Addresses: T1.4.
- **M10 — public-endpoint abuse limits: per-source and global rate limits, hard
  live-flow cap with oldest-first eviction, DCR cap, plain-language error pages.**
  *Gateway spec; owner: gateway. In place.* Addresses: T1.5, T1.6, T1.7 (cost
  side), T1.9, T3.6, T3.8, T2.2 (frequency side).
- **M11 — the CIMD SSRF control set: HTTPS-only, origin allowlist, no redirects,
  all-record private/loopback/link-local validation with connection pinning, 64 KiB
  cap, JSON content type, 5 s/10 s timeouts, bounded cache, explicit User-Agent,
  capacity limiter.** *Gateway spec; owner: gateway (allowlist: operator). In
  place.* Addresses: T2.1, T2.2, T2.3, T2.5.
- **M12 — the HTML hardening family on both page classes: CSP `default-src 'none'`
  + `base-uri 'none'`, `frame-ancestors 'none'` + `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `nosniff` + explicit
  charset.** *Gateway spec; owner: gateway. In place.* Addresses: T1.8 (second
  layer), T3.3, T3.5 (second layer), T3.7.
- **M13 — output escaping plus fixed-vocabulary, non-credential audit facts.**
  *Gateway spec; owner: gateway. In place.* Addresses: T1.8, T3.5, and never-cut 5.
- **M14 — the audit trail covering the whole request lifecycle, pre-allocation
  refusals included.** *Gateway spec; owner: gateway. In place.* Addresses: the
  detective halves of T1.1, T1.5, T1.10, T1.13, T2.1, T3.1, T3.8, T7.1; SR-4's
  chain.
- **M15 — signing-key discipline: never committed, never logged, never in argv;
  generated RSA in a gitignored `.env`-injected path; `kid` rotation within the
  JWKS-cache window; no `offlineClient` on the IdP entry.** *Gateway spec + repo
  rules + Core configuration; owners: gateway / repo / deployment operator. In
  place at the file-based bound (never-cut 7); KMS/HSM is the re-open.* Addresses:
  T4.1, T4.4 (effect-bounding), T4.2 (mint half).
- **M16 — mapping safety: OAUTH-only startup refusal, reserved-name startup
  refusal, `^[a-z0-9-]+$` charset, anchored and ordered router locations.**
  *Gateway spec + this repo's committed configuration; owners: gateway / repo. In
  place.* Addresses: T6.4, T6.5, REG-11's enforcement.
- **M17 — router challenge synthesis in the measured form (`proxy_hide_header` +
  `map $status`), configured `$mcp_origin` (never `$host`), `$is_args$args` on the
  data path.** *This repo's committed configuration; owner: repo. In place.*
  Addresses: T6.1's config-integrity surface, the query-string survival class.
- **M18 — fail-closed, fail-loud everywhere: corrupt store refuses startup,
  absent roles path refuses issuance, unknown flows get plain-language pages, no
  parameter-less request is ever delivered.** *Gateway spec; owner: gateway. In
  place.* Addresses: T1.7's failure mode, T5.4, T7.2, T7.3, T6.4's detection.
- **M19 — JWT verification hygiene: pinned RSA256, own-keys-only `kid` lookup,
  maintained library, bandit/pip-audit on every diff.** *Gateway spec + repo gates;
  owner: gateway / repo. In place.* Addresses: T4.3.
- **M20 — network isolation of the instance compose network; service-name-only
  back-channels; gateway :8091 never host-published.** *The deployment; owner:
  deployment operator. In place at the single-host shape (REG-14's accepting
  condition).* Addresses: T2.1's reach, T5.2, T5.3.

## 13. Dispositions

| Threat | Disposition |
|---|---|
| T1.1, T1.2, T1.4, T1.5, T1.6, T1.7, T1.8, T1.9, T2.1, T2.3, T2.5, T3.1, T3.3, T3.5, T3.6, T3.8, T4.3, T5.4, T6.4, T6.5, T7.2, T7.3 | **Mitigated** — M2–M5, M8–M14, M16, M18, M19 as mapped in §11; crash-loop and cache-loss tails accepted with REG-13. |
| T1.3 | **Mitigated to its bound** (M3+M5+M6+M8); residual **REG-8**. |
| T1.10 | **Accepted — REG-10** (audit chain M14 is the surviving guarantee; no other user's access is reachable). |
| T1.11, T1.12, T3.4, T6.2 | **Accepted — REG-1** (control M1 named, owned, not in place in today's shape). |
| T1.13 | **Mitigated** (as-that-user resolution + M14); the inventory disclosure is inherent to public discovery — accepted as design. |
| T2.2 | **Mitigated to its bound** (M11's limiter); residual queue-wait **REG-5**. |
| T2.4 | **Mitigated to its bound** (M4+M11); allowlist-curation residual accepted with **REG-12**'s revisit rule. |
| T3.2 | **Accepted — REG-2** (control M1 named; re-opened by a TLS-fronted deployment). |
| T3.7 | **Mitigated** (M12); effect-attribution after the fact via M14. |
| T4.1, T4.4 | **Accepted at the never-cut 7 bound** (M15's discipline in place; file-based custody and entitled-host read are the local shape's accepted state; KMS is the re-open). |
| T4.2 | **Accepted — REG-3** (M1's TTL lattice bounds the mint half; the identity token's post-lift life is the realm's 24 h, upstream-owned). |
| T5.1 | **Mitigated to the flow's purposes** (never-store rules, no `offline_access`); post-lift life accepted — **REG-3/REG-14** class. |
| T5.2, T5.3 | **Accepted — REG-14** (control: network isolation M20 in place at single-host; TLS on back-channels named, not in place). |
| T6.1 | **Accepted as the standing front-router class** (M17 delivers the challenge property; config diffs are reviewable — the repo's gates). |
| T6.3 | **Mitigated to nginx tuning** (connection/timeouts); residual slow-client exhaustion accepted for the local shape. |
| T7.1 | **Accepted — REG-6** (M4 bounds the use-path; the boundary is the host/volume owner's). |

## 14. Open questions

For the reviews (the loop's independent review and owner pause), phrased as
questions, never left implicit:

1. **The PoC C outcome record.** The archived change's design still describes the
   assembled chain as unproven until PoC C; the change's archived state implies the
   gate closed. Where does the closure record live, and do any §8 dispositions above
   need to flip on it? (Gap list, MAJOR.)
2. **Spec placement verification.** Every "gateway spec" placement in §11–§12 cites
   the archived change's normative statements; the current spec text was not on this
   run's allowlist. The grouped list's in-place claims should be verified against the
   spec once, mechanically. (Gap list, MAJOR.)
3. **The refresh/SLA decision.** REG-7's re-open is the owner's post-PoC-C SLA
   decision; the allowed inputs do not record whether it was taken. If 8 h is now
   too stale for the deployment's intent, the claims-re-fetch upgrade path is the
   prepared change.
4. **The mint-path watch.** T4.1/T4.4's honest gap: nothing detects anomalous
   minting or key-file reads. Is a mint-rate metric (or KMS move) worth scheduling,
   or does the rotation-reach bound suffice for the local shape's lifetime?
5. **DCR's enabled state.** The store-backed threats (AEP7) are conditional on the
   flag; if DCR has never been enabled in the committed deployment, AEP7 is dormant
   surface — worth one line of state on record.

---
