# Design review — harness integration with DIAL MCP toolsets

Reviewer: architecture + security, adversarial pass. Date: 2026-10-17.
Scope: **review only** — the findings below are inputs for the author; no design file
was modified by the reviewer.

Reviewed: [`design.md`](design.md) @ "design for review", against
[`problem-statement.md`](problem-statement.md) (§3 requirements, §2.4 invariants,
§4 findings), <!-- The May 2026 toolset authentication design is not copied here: it is
     stale and private. Anything it described that still matters is either
     implemented in DIAL Core (cite the source) or stated in this repo. -->
[`ideas.scratchpad.md`](ideas.scratchpad.md), [`poc-dial-mcp-signin.md`](poc-dial-mcp-signin.md),
[`poc-litellm-comparison.md`](poc-litellm-comparison.md), Core's source
(`dial-core/ai-dial-core` @ `development`, 2026-10-17), and a **harness-behaviour
capture run 2026-10-17** (Claude Code against a decoy AS wired into Core's
`toolsets.security.authorizationServers`) — cited below as **[Capture]** and treated
as measured evidence.

Core source files read in full for this review:
`WellKnownResourceMetadataService.java`, `RouteTemplate.java`, `IdentityProvider.java`,
`AccessTokenValidator.java`, `AiDial.java` (config wiring), `McpAuthorizationChallengeProvider.java`,
`ResourceAuthSettings.java`, `ResourceCredentialsController.java`; existence of
`TokenService` / `OauthTokenRefreshStrategy` confirmed in the `credentials` module.

---

## 1. Verdict

The design is **architecturally sound in its load-bearing structure and mostly
implementable as written — but its client-facing discovery surface, as specified, is
falsified by measurement for the one harness that matters most, and that is a
blocker.** Everything I could test against Core's source checked out: the
config-only second identity provider, issuer-pattern matching (including the
easy-to-miss requirement to add `issuerPattern` to the existing Keycloak entry),
RSA256/JWKS verification and its 10-minute cache, `allowedRedirectUris`, the
`rolePath`/`sub` claim requirements, the `/v1/ops/toolset/signin` route and schema,
and the PKCE verifier never leaving Core. Alternative C is a defensible resolution of
the human's sketch — it honours corrections 2 and 3 literally and degenerates
refresh to proxy-local state — and the design is unusually honest about its limits
(OR-2, role staleness, trust concentration). However, **[Capture]** shows that Claude
Code (a) resolves AS metadata at the **flat, host-level**
`/.well-known/oauth-authorization-server` and never at a per-toolset insert-style
path, and (b) registers via **CIMD**, not DCR, making no `/register` call at all when
CIMD is advertised. The design's per-toolset AS issuer/path (E2, `iss =
https://dial.example.org/dial/{name}`) is therefore not the surface this harness
walks — under the design's own nginx split, Claude Code's flat metadata fetch would
be routed to Core, not the proxy, and discovery dead-ends. The same capture supplies
the fix: Claude Code **sends the RFC 8707 `resource` parameter, with the per-toolset
value, on both `/authorize` and `/token`** — so a **single-issuer, flat-metadata AS
with `resource` as the primary per-toolset discriminator** is not the fallback but
the correct primary design, requiring no Core change. With that restructure, plus the
audience-enforcement config, the nginx query-string fix, the OAUTH-only mapping
invariant, and a gated PoC C (criteria in §7), the design will be defensible.

---

## 2. Findings

### BLOCKER

**BL-1 — The per-toolset AS issuer/insert-path surface (E2) is falsified by measurement; `resource` must be the primary disambiguation signal.**
Attaches to: §3.1 E2 ("RFC 8414 AS metadata for issuer `https://dial.example.org/dial/{name}`
(insert-style path — the same shape PoC B proved a stock client walks [PoC B])"),
§4.1 step 8 (`iss=https://dial.example.org/dial/notion`), §10.1 (`issuerPattern:
^https://dial\.example\.org/dial/[a-z0-9-]+$`), §10.4 (nginx well-known split).
Evidence: **[Capture]** — during `claude mcp login` against Core's own PRM (decoy AS
in `authorizationServers`), Claude Code fetched the **flat**
`/.well-known/oauth-authorization-server` for the issuer, twice, and **never a
per-toolset path**; it did send `resource` with the per-toolset value
(`http://localhost:8081/v1/toolset/notion/mcp`) on **both** `/authorize` and `/token`.
Why it breaks the design: (a) with a per-toolset issuer containing a path, the
harness's actual metadata fetch lands at the host-root flat well-known — which under
§10.4's split (`^/\.well-known/oauth-(protected-resource|authorization-server)/dial/`
→ proxy, everything else → Core) is routed **to Core**, so the harness never sees the
proxy's AS document and discovery dead-ends; (b) the design's own cross-check framing
("the proxy cross-checks `resource` against the path-derived toolset") inverts the
roles — `resource` is the only per-toolset signal this harness actually carries
end-to-end, so it must be the *primary* discriminator, not a corroborating check;
(c) the PoC B tag on E2 was already weak (curl probes, no real harness — see mi-1)
and is now contradicted for the primary harness.
Required change (author): restructure the AS surface to **one issuer at the origin
root** (e.g. `https://dial.example.org`) with **flat AS metadata at
`/.well-known/oauth-authorization-server`** routed to the proxy by an exact nginx
location — which is also the RFC 8414-correct location for a path-less issuer, so
Claude Code's measured behaviour and spec-correct clients agree. A single AS metadata
document advertises a single `authorization_endpoint`/`token_endpoint`, so E3/E4
become name-agnostic (`/dial/authorize`, `/dial/token`) dispatching on `resource`;
E1 (per-toolset PRM) is unaffected — each PRM names the one AS issuer; per-toolset
well-known aliases may remain for spec-literal clients but are not the load-bearing
path. The Core IdP `issuerPattern` collapses to the single issuer
(`^https://dial\.example\.org$`). Per-toolset binding then rests on the proxy's
`resource` validation at `/authorize` and `/token` — which **[Capture]** proves
Claude Code exercises on both endpoints — so that check must be **strict by default**
(see mi-8). No Core change is needed for any of this (see §6).

**BL-2 — "The proxy flow is not yet PoC'd end-to-end" is a gate, not an open question.**
Attaches to: §9 OQ-2, and every traceability row marked "met" that rests on the
unproven chain (FR-1, FR-5, FR-8, OR-4, CR-3).
Why: the design's honesty list concedes that every *ingredient* is verified but the
*assembly* is not; several "met" rows in §7 are design-level claims, not evidenced
ones. A design can condition on an experiment only if the experiment's pass/fail
criteria are fixed in advance. **[Capture]** has already pre-answered two ingredients
for Claude Code (resource sent on both legs; CIMD registration), which makes the
remaining gap sharper, not smaller: the *assembled* proxy chain is now the only
unknown.
Required change (author): promote OQ-2 to a gate with fixed acceptance criteria —
(a) a real harness (Claude Code) completes first use against the *restructured*
surface (BL-1): rewritten 401 → E1 → flat AS metadata → CIMD registration →
`/dial/authorize` (with `resource`) → Keycloak → interstitial → upstream consent →
E7 → `/signin` → `/dial/token` → live tool call via `/dial/{name}/mcp` with a
**proxy-signed, copied-`sub`** JWT; (b) silent repeat use and refresh-on-401 with no
browser, including observation of what Claude Code does with a rotated refresh
token; (c) mid-session upstream-credential removal produces the §4.3 "sign-out and
sign-in again" branch, not a loop, and does not discard the harness's proxy token
(OR-4); (d) query strings survive the nginx data-path rewrite (MA-2); (e) a
direct-to-Core Keycloak client keeps working unchanged while the proxy front door is
live. Until PoC C passes, the design's status stays "for review" and §7's dependent
rows are conditional.

### MAJOR

**MA-1 — CR-1 is not met as stated: Core never verifies `aud` on the proxy's tokens; a token minted for one toolset is valid on every endpoint of the deployment.**
Attaches to: §7 CR-1 row ("`resource` + `aud` binding … met"), §4.1 step 8, §10.1
(the `dial-mcp-proxy` IdP entry with `"audience"` deliberately omitted).
Why: `IdentityProvider.verifyJwt` applies an audience check **only if the provider
entry configures one** — `IdentityProvider.java:362-365`:
`if (audience != null) verification.withAudience(audience)`. The design omits it, so
the per-toolset `aud` it mints is decorative: Core accepts any correctly-signed token
whose `iss` matches the proxy pattern on **any** route — chat completions, ops APIs,
every toolset. CR-1 says "audience-bound tokens (RFC 8707)" and the table marks it
"met" with only a parenthetical. Note this is aggravated by BL-1: with a single
issuer, the `iss` claim carries no per-toolset information at all, so nothing
Core-side distinguishes a `notion` token from a `github` token.
Required change (author): configure `"audience": "dial-mcp-proxy"` on the proxy IdP
entry. auth0's `withAudience` requires the token's `aud` to contain the value, so
this is a real, config-only enforcement of the marker the proxy already mints —
every proxy-issuer token becomes structurally audience-bound. Honest limits: it is
not per-toolset binding (achievable config-only only via one IdP entry per toolset
with distinct `issuerPattern` + `audience`, which conflicts with dynamic toolsets —
optional hardening for high-value toolsets, not v1); and after BL-1 the proxy's
strict `resource` check at `/authorize`+`/token` is the *only* per-toolset binding in
the chain, which is one more reason it must be strict by default. Downgrade the CR-1
row to "partially met".

**MA-2 — The nginx data-path sample config drops query strings, and `$host` can drop the port.**
Attaches to: §4.4 and §10.4 — `proxy_pass http://core:8080/v1/toolset/$tname/mcp;`
and `resource_metadata="https://$host/..."`.
Why: when `proxy_pass` contains variables, nginx uses the constructed URI as-is and
does **not** append the original query string (the remedy is `$is_args$args`). MCP
streamable-HTTP servers use query parameters on GET (session resumption,
`?sessionId=…`); silently stripping them breaks reconnect semantics for exactly the
clients this design exists to serve. Separately, `$host` is the Host header without
the port — behind TLS termination on a non-default port the advertised
`resource_metadata` origin will not match the origin the harness used, and after
BL-1 the strict `resource` check would then reject legitimate requests.
Required change (author): `proxy_pass http://core:8080/v1/toolset/$tname/mcp$is_args$args;`
and a configured external origin for the challenge header instead of `$host`. Add to
PoC C criteria (d).

**MA-3 — Nothing prevents mapping a non-OAUTH toolset into the proxy, which yields an unsatisfiable auth loop.**
Attaches to: §3 ("Toolset `{name}` maps to a Core deployment via a proxy/router
config table"), §4.1 (the flow assumes an upstream OAuth consent), OQ-7.
Why: the nginx 401 rewrite fires for **every** toolset routed under `/dial/`. If an
operator lists an `API_KEY`/`DIAL_NATIVE` toolset, a harness gets the proxy's OAuth
challenge, completes Leg 2′, and every MCP call still 401s (the OAuth flow can never
establish that credential) — rewritten 401, forever. It fails silently at the
operator's config step: the same "looks configured, is broken" class PoC A §8.2
item 4 criticizes in Core.
Required change (author): state a v1 config invariant — the mapping table lists
OAUTH toolsets only — and enforce it at proxy startup (refuse a toolset whose public
`auth_settings.authentication_type` ≠ `OAUTH`, or route it without the challenge
rewrite). API_KEY support stays OQ-7.

**MA-4 — Registration is specified around DCR; the measured path for Claude Code is CIMD, with no `/register` call — the proxy must actually implement CIMD fetch-and-validate.**
Attaches to: §3.1 E5 ("Legacy DCR … kept for older clients"), §4.1 step R (priority
pre-registered → CIMD → DCR, CIMD tagged **[Spec]**), §7 CR-2, SR-6 ("harnesses DCR
against the proxy").
Why: **[Capture]** — with `client_id_metadata_document_supported: true` advertised,
Claude Code registered via CIMD (`client_id =
https://claude.ai/oauth/claude-code-client-metadata`, a URL) and made **no** call to
any `/register` endpoint. So for the primary harness E5 is never exercised; the
load-bearing step is the proxy **fetching and validating the client's metadata
document** from the `client_id` URL. The design currently treats CIMD as a
spec-labeled middle option and DCR as the evidenced one ("[PoC A: harnesses still
DCR]") — that PoC A observation is now superseded for Claude Code whenever CIMD is
advertised (PoC A's DCR happened because Core's Keycloak surface does not advertise
CIMD). The design's priority order (CR-2) is confirmed correct; its implementation
emphasis is not.
Required change (author): make CIMD the primary registration path in the
implementation plan (fetch the document at the `client_id` URL over HTTPS, validate
`redirect_uris` against what the client later presents, no secrets stored), keep E5
DCR for clients that need it, and add the security note: the CIMD fetch is
server-side request forgery surface — restrict to HTTPS, no redirects to
private/loopback ranges, origin allowlist (the §10.3 `cimd_allowed_origins` key
exists but is never specified as an SSRF control). Update SR-6/CR-2 rows: "harnesses
register against the proxy" via CIMD **[Capture]** — the F-4 neutralization argument
is unchanged and still holds.

### MINOR

**mi-1 — PoC B's evidentiary reach was overstated, and BL-1 has now contradicted it.**
Attaches to: §3.1 E2 and §7 CR-3 ("PoC B evidence that this endpoint shape works for
stock clients").
Why: PoC B walked LiteLLM's chain with curl probes; no harness was pointed at
LiteLLM, and the consent was never clicked. "A stock client walks" was an inference —
and **[Capture]** now shows the primary stock client does *not* walk the insert-style
per-toolset AS path. Required change: re-tag E2/CR-3 to what was observed; the
real-harness proof is PoC C criterion (a).

**mi-2 — §4.1 step 4 names a Core path that does not do what the step needs.**
Attaches to: step 4 — "`GET /v1/toolset/notion`".
Why: `/v1/toolset/{id}` (without `/mcp`, `/tools`) is not a toolset-settings GET
route; toolsets are resources addressed as `/v1/toolsets/{bucket}/{name}`
(`RouteTemplate.java:94`, RESOURCE route; PoC A used `PUT /v1/toolsets/platform/notion`).
§10.3's `toolset_url_template` has it right; the prose has it wrong. Required change:
step 4 fetches the configured toolset URL.

**mi-3 — Flow-id entropy is unspecified; a guessable id enables a code-injection chain at E7.**
Attaches to: §4.1 step 2 ("opaque id"), §5.3.
Why: an attacker who guesses an in-flight flow id can hit E7 with *their own* upstream
code (obtainable — the toolset's `code_challenge` is public and the consent is the
attacker's own). The proxy would call `/signin` with the **victim's** Keycloak JWT
and the attacker's code; Core stores the attacker's upstream credential under the
victim's `sub`, and the victim's subsequent toolset traffic executes against the
attacker's workspace — their queries and tool arguments land where the attacker can
read them. The only thing that kills this chain is unguessable flow ids.
Required change: flow ids are 128-bit random (same entropy class as authorization
codes); state it.

**mi-4 — E3/E4/E5 are unauthenticated endpoints that allocate unbounded in-memory state.**
Attaches to: §5.3, §3.1.
Why: `GET /dial/authorize` creates a flow record per hit; a trivial loop exhausts
proxy memory; same for DCR/CIMD-handling records. Required change: per-IP and global
rate limits, a hard cap on live flow records (oldest evicted with the plain-language
error page).

**mi-5 — "≤ 10 min of Keycloak JWTs" misstates the exposure window.**
Attaches to: §6.4 proxy row.
Why: the flow-record TTL bounds how long the proxy *holds* the JWT, not how long the
JWT *lives*. A memory-dump attacker gets a full DIAL identity valid for the Keycloak
token's own `exp` (typically minutes to an hour in production realms). Required
change: state the bound as min(flow TTL, JWT `exp`); §10.2's no-`offline_access` is
already the right control.

**mi-6 — "roles copied from the Keycloak JWT" needs the source path named.**
Attaches to: §4.1 step 8, §5.2, §10.1 (`rolePath: "roles"`).
Why: the Keycloak JWT carries roles at the *Keycloak entry's* configured `rolePath`
(e.g. `resource_access.<client>.roles` / `realm_access.roles`); the proxy must read
that path and re-emit at its own `roles` claim. A naive copy of a literal `roles`
claim Keycloak never mints yields role-less tokens and silent 403s. Required change:
one sentence naming the source path.

**mi-7 — FR-3's "met" hides the v1 scope cut.**
Attaches to: §7 FR-3 row.
Why: FR-3 asks *which kind* a toolset needs — OAUTH, API key, … The proxy fronts
OAUTH toolsets only in v1 (MA-3); `dial_authentication_type` will never say "API_KEY"
in practice. Required change: row becomes "met for OAUTH toolsets; non-OAUTH kinds
excluded from the v1 mapping (MA-3), remain OQ-7".

**mi-8 — OQ-10's lenient `resource` default is now contradicted by measurement.**
Attaches to: §9 OQ-10 ("lenient default until harness conformance is measured
[Assumed]"), §4.1 step 2 / E4 (resource as cross-check).
Why: the conformance measurement exists — **[Capture]**: Claude Code sends `resource`
on both `/authorize` and `/token` with the per-toolset value. After BL-1, the strict
resource check is the only per-toolset binding in the chain; lenient-by-default makes
the primary discriminator advisory. Required change: strict by default, lenient as a
config fallback for other harnesses (revisit if PoC C shows a harness that omits
`resource`).

**mi-9 — The 401 rewrite stretches "nginx as a traffic splitter ONLY" (human constraint 2).**
Attaches to: §2 (Front router row: "No proxying logic beyond `proxy_pass`"), §4.4,
§10.4.
Why: `error_page 401` + `add_header` makes nginx *synthesize* an authorization
challenge — protocol behaviour, not forwarding. It is four lines of stock config,
there is no config-only alternative that fixes F-1, and BL-1's restructure does not
remove it — but the human said "ONLY", so it needs explicit sign-off alongside OR-2's.
Required change: extend OQ-8 to cover both sign-offs; amend the §2 row.

**mi-10 — `loggingKey`/`loggingSalt` parity on the proxy IdP entry (operational).**
Attaches to: §10.1. Why: if the deployment's Keycloak entry sets `loggingKey`
(obfuscated user logging — `IdentityProvider.java:196-201`), the proxy entry should
mirror it or proxy-leg logins disappear from user logging. One-line note.

---

## 3. Requirement traceability audit

Design's §7 table re-audited against problem-statement §3:

| Req | Audit result |
|---|---|
| FR-1 | Correct, **conditional on PoC C** (BL-2). Design admits it; the row should say so. |
| FR-2 | Correct. `claude mcp add` + harness-native OAuth; browser only for consent. |
| FR-3 | **Overstated** (mi-7): OAUTH-only in v1; non-OAUTH kinds excluded by MA-3. |
| FR-4 | Correct (E9 + flow step 4). |
| FR-5 | Correct, conditional on PoC C criterion (b). |
| FR-6 | Correct (SSO for the DIAL leg; one upstream consent per toolset). |
| FR-7 | Substantiated: `credentials` module `TokenService` + `OauthTokenRefreshStrategy` exist. Refresh of an *expired upstream refresh token* still ends in re-consent — inherent, not a design gap. |
| FR-8 | Mechanism (nginx rewrite) is sound and targets the behaviour PoC B observed in LiteLLM; **[Capture]** confirms Claude Code follows `authorization_servers` from the PRM, so the rewritten challenge will be followed too. Conditional on PoC C. |
| SR-1 | Substantiated (I1/I2 verified — §4 below). |
| SR-2 | Substantiated with the C-caveat: binding now transitively relies on the proxy copying `sub` faithfully — the §6.2 trade, correctly disclosed. |
| SR-3 | Correct. |
| SR-4 | Correct; display-level limit of the interstitial disclosed. |
| SR-5 | Correct. |
| SR-6 | Correct conclusion, wrong emphasis (MA-4): registration moves to the proxy — via **CIMD [Capture]**, not DCR; the F-4 neutralization argument is unchanged. |
| OR-1 | Correct; restart-on-settings-change noted. Total config surface is fully listed in §10. |
| OR-2 | Documented deviation, needs sign-off (OQ-8 + mi-9). Not silent. |
| OR-3 | "Partially met (accepted trade)" is honest; the in-flow disambiguation only helps if the harness re-runs the flow on 401 — evidenced for Claude Code [PoC A]. Keep. |
| OR-4 | Correct; conditional on PoC C criterion (c). |
| CR-1 | **Overstated** (MA-1): audience binding was not enforced before and is not enforced by the design as written; the marker fix is config-only and must be specified. "Issuer validation (RFC 9207)" (`iss` in responses) is correct. |
| CR-2 | Priority order confirmed — and now **measured** for Claude Code via CIMD [Capture] (MA-4). Row should cite CIMD as the evidenced path, DCR as legacy. |
| CR-3 | Correct at design level only; PoC B tag overstated (mi-1) and the per-toolset AS shape is falsified (BL-1); real-harness proof is PoC C criterion (a). |

**Silently unmet requirements:** none found — the weak rows (FR-3, CR-1, CR-2
emphasis) were *mislabeled*, not hidden. The authN-design consistency check passes:
§8's amendments are correctly scoped (worst-case item 5 promoted and externalized;
Keycloak-DCR conclusion amended only for the proxy-fronted path — and MA-4's capture
strengthens that amendment, since the proxy-fronted path needs no DCR at all for
CIMD-capable harnesses; direct-to-Core clients keep the old story), and no amendment
touches the credential model, which the DIAL Core implementation's own analysis says must not
move.

---

## 4. Invariant audit (I1–I5)

- **I1 — upstream token stored in Core only, never in the harness.** Holds. The proxy
  transits only the upstream *code*; Core exchanges it (sole holder of the verifier)
  and stores per `sub`. `forwardAuthToken=false` default untouched; the harness holds
  only proxy-signed JWTs. **Verified in source + PoC A.**
- **I2 — the upstream PKCE verifier never leaves Core.** Holds, verified:
  `ResourceAuthSettings.redactSecrets()` nulls `codeVerifier` (and `clientSecret`) on
  every public projection (`ResourceAuthSettings.java:116-126`), and PoC A read the
  toolset's public settings — `code_challenge` present, verifier absent. The proxy
  builds the upstream authorize URL from public settings exactly as PoC A's helper did.
- **I3 — credential levels and resolution order unchanged.** Holds. The proxy signs in
  at USER level only (`ResourceCredentialsController` gates GLOBAL behind admin —
  `if (credentialsLevel.equals(CredentialsLevel.GLOBAL))` at lines 159/170);
  resolution order in Core untouched; GLOBAL stays an operator action (OQ-9).
- **I4 — DIAL authorization applies on every toolset call.** Holds mechanically: the
  data path validates the proxy JWT in Core and applies toolset access control; the
  flow's step-4 read check enforces access before any upstream round-trip. **Caveat
  the design discloses and §5 quantifies:** the roles authorization runs on are a
  proxy-asserted snapshot up to `refreshTtl` (8 h) old — a revoked user's toolset
  access can outlive their Keycloak session by hours. Inherent to C (A/B share the
  class), bounded by config.
- **I5 — one unified credential API, reused verbatim.** Holds, verified:
  `RouteTemplate.TOOL_SET_CREDENTIALS` (`^/v1/ops/toolset/(signin|signout)`,
  `RouteTemplate.java:266-269`) and the request schema
  (`ResourceSignInRequest{url, credentialsLevel, authenticationType, code, apiKey,
  redirectUri, offlineUsageConsent}`, with `validateAuthType` enforcing the
  type match, `ResourceCredentialsController.java:186-190`). The proxy is a new
  *caller* of an API designed for exactly that. The authN design's "do not replace
  `/signin` with hosted `/authorize`" (PoC A §8.2.1) is respected: the proxy's OAuth
  surface is a facade *in front of* `/signin` — API_KEY and DIAL_NATIVE keep their
  home.

---

## 5. Security review

### 5.1 Threat model for the new component (the proxy)

New attack surface, itemized:

1. **Public OAuth endpoints** (PRM/AS metadata, `/authorize`, `/token`, `/register`,
   `/status`, `/revoke`) — standard AS surface. Risks: open redirect (mitigated:
   `redirect_uri` validated against registration), registration spam (mi-4),
   flow-record flooding (mi-4), `state`/mix-up (three independent PKCE pairs + RFC
   9207 `iss` — sound), code replay (self-contained JWT code, PKCE-bound, jti cache —
   sound; in-memory cache loss is bounded and PKCE-covered, as §5.3 argues).
2. **CIMD fetch (new, load-bearing after MA-4)** — the proxy fetches a client
   metadata document from a client-supplied URL: classic SSRF surface. Controls:
   HTTPS-only, no redirects into private/loopback/link-local ranges, origin allowlist,
   response size cap, cached with TTL.
3. **Browser callbacks E6/E7** — the code-injection chain (mi-3) killed by 128-bit
   flow ids; E6 carries Keycloak's code for the proxy's client (PKCE-bound to the
   proxy — an intercepted code is useless without the proxy's verifier).
4. **The signing key** — see trust concentration below.
5. **Server-to-server calls into Core** — the proxy holds a live Keycloak JWT for ≤
   one flow (mi-5 exposure window) and makes two GETs + `/signin`. Compromise of the
   proxy process during a flow yields one user's DIAL identity until that JWT's `exp`.
6. **nginx rewrite** — a compromised router can point `resource_metadata` at a
   hostile AS and phish credentials at the *proxy* leg; same class as any front-router
   compromise today (the design says so; agreed). Note BL-1 increases reliance on
   this rewrite being correct — its integrity is now part of the auth protocol.

### 5.2 Consent attribution (human constraint 6)

The design's answer — client naming + auto-continue interstitial + end-to-end audit —
is the honest maximum: **no architecture gives an upstream AS cryptographic
attribution of its downstream client's downstream client**; the upstream consent must
be Core's client because Core holds the verifier (I2). The interstitial is the only
place both identities (harness client + toolset) are simultaneously known, and the
design correctly labels it display-only. Two refinements: (a) for CIMD clients the
proxy knows a real client name from the fetched metadata document — prefer it over a
bare `client_id` (and note the CIMD client is identifiable as an *organization*,
e.g. "Anthropic Claude Code", which is better attribution than DCR ever gave);
(b) the audit chain (proxy flow log + Core's independent `/signin` record keyed by
`sub`) is genuinely attributable end-to-end and satisfies SR-4.

### 5.3 Trust concentration (§6.2 audited)

§6.2's statement is correct and unusually frank: the proxy's key is as powerful as
Keycloak's — it can mint any `sub` **with any roles, including admin**, and (before
MA-1's fix) valid on every Core endpoint. MA-1's `audience: "dial-mcp-proxy"` marker
does not shrink key-compromise blast radius (an attacker holding the key mints the
marker too) but makes every proxy-issuer token structurally audience-bound (RFC 8707)
and eliminates accidental cross-issuer acceptance. After BL-1, per-toolset binding
exists **only** in the proxy's own strict `resource` check — a token stolen from one
toolset's harness session is replayable against another toolset until its 10-minute
`exp` (same user, their own access — low severity, but it should be stated). The
remaining mitigations — KMS/HSM, `kid` rotation ≤ JWKS cache
(`IdentityProvider.java:149`, positive cache 10 min default), 10-minute access TTL,
no `offlineClient` on the IdP entry (`IdentityProvider.java:108-110, 212` — verified
optional and correctly omitted, so the proxy issuer can never mint DIAL_NATIVE
offline credentials) — are the right set. Per-issuer path scoping (OQ-4) remains the
real fix and correctly stays a future ask. Residual risk is exactly what §6.2 says:
a new, small-code AS with a small audit budget, equivalent in kind to Keycloak — the
price of C, priced honestly.

### 5.4 Revocation and token lifecycle

- No per-user kill of *live* access tokens without key rotation — inherent to
  non-introspected JWTs, same as Keycloak today (`AccessTokenValidator` does
  signature/issuer/audience only — verified). Bounded by the 10-minute access TTL.
- Refresh rotation default-on with grace window, config-off (OQ-1) — right call; the
  grace window weakens replay detection, so denylist-until-`exp` + 8-h `refreshTtl`
  remain the backstop. PoC C criterion (b) must observe Claude Code's handling of a
  rotated refresh token.
- Key rotation procedure (publish new `kid` → wait cache TTL → retire) is correct per
  `IdentityProvider` caching.
- The role-snapshot staleness (§4, I4) is the one revocation path with an 8-hour
  tail; a shorter `refreshTtl` is the available knob.

### 5.5 Compromise points (extends §6.4)

| Compromised | Attacker gains | Note |
|---|---|---|
| harness / token store | that user's toolset access until ≤10 min (access) / ≤8 h (refresh); replayable against the user's *other* proxied toolsets until exp (§5.3) | unchanged in kind |
| proxy process | mint-any-`sub`/any-role tokens (§6.2); **one in-flight user's Keycloak JWT until that JWT's own `exp`** (mi-5); audit log | upstream tokens and verifiers never present |
| proxy **signing key only** | as above, remotely, until rotation ≤ cache TTL + access TTL | KMS/HSM is the control |
| Core | everything it holds today | unchanged by this design |
| Keycloak | what it holds today + ability to authenticate federation flows (proxy still gates issuance) | unchanged |
| nginx | challenge phishing (mi-9); tampering on the data path | same class as today's router; load-bearing after BL-1 |

---

## 6. Core-source verification — the per-toolset-AS question

**Question:** can a client discover a per-toolset issuer/AS path without a Core code
change, given Core's PRM advertises one global `authorization_servers` list?

**Answer: a per-toolset AS must NOT be attempted at all — not in Core (impossible
without a code change) and not in the proxy (falsified by measurement for Claude
Code). The correct design is a single proxy AS with flat metadata, and the RFC 8707
`resource` parameter as the PRIMARY per-toolset signal — which [Capture] proves
Claude Code sends, with the per-toolset value, on both `/authorize` and `/token`. No
Core change is needed.**

Evidence, in three parts:

1. **Core's `authorization_servers` is one global configured value — a per-toolset AS
   in Core's own metadata is impossible without a code change.**
   `WellKnownResourceMetadataService.java:44` — `authorizationServers =
   getStrOrList(security, "authorizationServers", null)`, read once from
   `toolsets.security.authorizationServers` at construction; `:124` —
   `metadata.setAuthorizationServers(authorizationServers)`, the same list for every
   request; `:169-171` — the whole surface is disabled when the list is unset.
   Per-toolset PRM *routes* exist (`RouteTemplate.java:363-366`,
   `TOOL_SET_PROXY_METADATA`) but every such document carries the identical global
   list. Wiring confirmed at `AiDial.java:344` (`new
   WellKnownResourceMetadataService(settings("toolsets"))`) and `AiDial.java:212`
   (`new AccessTokenValidator(settings("identityProviders"), …)`).
2. **The design's workaround (per-toolset issuer + insert-style E2, following
   LiteLLM) is not how the primary harness behaves — measured.** **[Capture]**:
   during `claude mcp login`, Claude Code fetched the **flat**
   `/.well-known/oauth-authorization-server` for the issuer, twice, and never a
   per-toolset path; it followed `authorization_servers` from the PRM (so the
   nginx-rewrite → proxy-PRM leg of the design's chain *is* walked), and it sent
   `resource` with the per-toolset value on both `/authorize` and `/token`. Under the
   design's §10.4 split, the flat fetch routes to Core and the chain dead-ends (BL-1).
   The fix — single path-less issuer at the origin root + flat metadata at the
   host-level well-known — is simultaneously the RFC 8414-correct location for a
   path-less issuer, so spec-literal clients and Claude Code converge on the same
   URL.
3. **The residual Core-side gap is audience *enforcement*, also fixable
   config-only.** With a single issuer, `iss` carries no per-toolset information;
   Core-side binding is only what the IdP entry configures. `IdentityProvider.java:
   362-365` — audience checked only when configured → MA-1's marker. Per-toolset
   enforcement at Core would need one IdP entry per toolset or a code change;
   neither is required, because the proxy's strict `resource` check (BL-1, mi-8) is
   the per-toolset gate and is measured-exercised by Claude Code.

**Second verification — is the second identity provider genuinely config-only? Yes,
verified; no constraint breaks with a second provider:**

- `AccessTokenValidator.java:58-69` — every key of the `identityProviders` settings
  object becomes an `IdentityProvider`; nothing else needed.
- Multi-IdP selection: `AccessTokenValidator.java:90-95` (single provider: issuer not
  consulted) vs `:115-122` (`extractClaimsFromJwt` loops `idp.match(jwt)`); matching
  is `IdentityProvider.matchesIssuer` (`IdentityProvider.java:519-521`) —
  `issuerPattern != null && issuer != null && pattern.matcher(issuer).matches()`.
  **Without a pattern a provider can never match in multi-IdP mode — the design's
  "issuerPattern on the existing Keycloak entry is strictly required" (§10.1) is
  correct and easy to miss.**
- JWKS: per-provider `jwksUrl` via `UrlJwkProvider` (`AccessTokenValidator.java:59-64`,
  `IdentityProvider.java:161-163`); a jwksUrl-only provider is valid
  (`IdentityProvider.java:153-159` — jwksUrl xor userInfoEndpoint). RSA256 only
  (`:362`); audience only if configured (`:363-365`); positive JWKS cache 10 min
  default (`:149`).
- Required claims: `rolePath` mandatory (`IdentityProvider.java:176`,
  `requireNonNull` — the design sets `rolePath: "roles"`); `userIdPath` defaults to
  `sub` (`:216`); `projectPath` optional (`:193`); `loggingKey` optional but
  pair-locked with `loggingSalt` (`:196-201`) — mi-10.
- **No constraint breaks with a second provider.** API keys travel a separate path
  (ApiKeyStore); issuer matching is per-JWT; JWKS is per-provider; and
  `resolveOfflineClientByIssuer` (`AccessTokenValidator.java:195-211`) returns null
  for the proxy entry's (unconfigured) `offlineClient` — DIAL_NATIVE offline
  credentials can never be minted through the proxy issuer, exactly as §6.2 requires.
  The only behavioural flip is the single→multi provider code-path change, fully
  covered by the required `issuerPattern` addition.

Other design claims spot-checked in source: `AiDial.getAllowedRedirectUris` reads
`toolsets.security.allowedRedirectUris` (`AiDial.java:524-531`); `/signin` route and
GLOBAL-gating in `ResourceCredentialsController` (above); `redactSecrets` clears
`codeVerifier` (`ResourceAuthSettings.java:116-126`); `TokenService` /
`OauthTokenRefreshStrategy` exist in the `credentials` module (FR-7).

---

## 7. What MUST change before this design can be final

1. **Restructure the AS surface per BL-1**: single path-less issuer at the origin
   root, flat `/.well-known/oauth-authorization-server` routed to the proxy by an
   exact nginx location, name-agnostic `/dial/authorize` + `/dial/token` dispatching
   on `resource`; `resource` becomes the **primary** per-toolset discriminator,
   **strict by default** (mi-8, measured support); Core `issuerPattern` collapses to
   the single issuer.
2. **Make CIMD the primary registration path** (MA-4): fetch-and-validate the client
   metadata document (SSRF controls: HTTPS-only, no private-range redirects, origin
   allowlist, size cap); E5 DCR demoted to legacy; re-tag SR-6/CR-2.
3. **Add `"audience": "dial-mcp-proxy"` to the proxy IdP entry** and downgrade the
   CR-1 row (MA-1); optional per-toolset IdP entries as hardening for high-value
   toolsets.
4. **Fix the nginx data-path config** (`$is_args$args`; configured external origin
   for the challenge header) and verify query-string survival (MA-2).
5. **State and enforce the OAUTH-only mapping invariant** for v1 (MA-3).
6. **Run PoC C and gate final status on its criteria** (BL-2; criteria in §2 — the
   capture has pre-answered resource-sending and CIMD for Claude Code, so the
   remaining unknowns are exactly the assembled chain, refresh behaviour, mid-session
   expiry, query strings, and coexistence).
7. Obtain the two sign-offs the design itself calls for, now explicitly including the
   nginx challenge-synthesis (OR-2 deviation + constraint-2 tension — mi-9).
8. Specify 128-bit flow ids, rate limits on the public endpoints, and the mi-5/mi-6
   accuracy fixes.

Nothing in the above requires a Core code change; items 1–5 and 8 are configuration
and proxy-implementation changes, item 6 is a defined experiment, item 7 is process.

---

*Imported into this repository from the DIAL design archive on 2026-10-17. This copy is the **living** version of this document; the archive copy is a frozen historical record and is not updated. References to the May 2026 toolset authentication design have been replaced with references to the DIAL Core source, because that document predates the MCP specification revision that deprecated Dynamic Client Registration.*
