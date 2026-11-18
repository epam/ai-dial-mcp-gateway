# RFC 9700 re-judge — the authorization-server surface walked (pre-decision input)

Date: 2026-11-06. Corrected twice: 2026-11-07 after the independent review
(`evidence/rejudge-report-review.md` — 0 blocking / 2 should-fix / 3 notes: the Part 6
partition, the remedy completeness notes), and again 2026-11-07 after the owner's
source-currency catch — **the current MCP protocol revision is `2026-07-28`** (stated by
`modelcontextprotocol.io/specification/versioning`), not `2025-11-25` as this report and
the review had both assumed; Part 4 is re-walked against the restructured `2026-07-28`
surface (four new rows, one new finding — B-5), every load-bearing statement re-verified
verbatim on the current pages, and each B-finding's basis status recorded.
Status: **an input for the owner's scope ruling**, not a scope decision —
every (b)-class row below is priced for the owner to accept, defer, or refuse; nothing in
this report changes the change's artifacts.

## Method

The walk covers every MUST, MUST NOT, SHOULD, SHOULD NOT, and RECOMMENDED of RFC 9700
§2 (the operational recommendations) and §4 (the attack mitigations), plus the
security-posture-bearing MAYs (§2.6's CORS permission among them), walked against the
gateway's client-facing authorization-server surface **as built** (the code in this
worktree), both resource kinds, both mint paths and the consent branch, the
client-facing endpoints (`/dial/authorize`, the callbacks, `/dial/token`, `/dial/revoke`,
discovery, registration) and the identity leg behind them. Beside it: the OIDC items the
roadmap's scope names (the step-up parameter set `max_age`/`prompt`/`auth_time`, the
nonce/ID-token boundary) and the MCP authorization specification's security
considerations including the confused-deputy per-client-consent MUST. Sources verified
this pass: RFC 9700 (rfc-editor.org, fetched in full across two page reads), the MCP
authorization specification and security best practices (modelcontextprotocol.io — the
current `2026-07-28` revision per `/specification/versioning`, all six restructured
authorization and security pages fetched in full and scored in Part 4, with the
`2025-06-18` and `2025-11-25` texts fetched alongside for continuity on the items the
revisions carry unchanged), and the gateway's own code and threat model.

Verdict vocabulary — one class per row, with one honesty marker inside (a):

- **(a) SATISFIED** — no new scope; the control exists, named where (code site,
  M-number, spec requirement, or the pending delta that lands it).
- **(a) PRICED** — no new scope; the recommendation is violated or only partially held,
  and the violation is *already priced* in the model (an RES-number, a deferral with a
  named precondition). These are counted and listed separately in the summary, because
  "already priced" is not "satisfied" and the owner reads them differently.
- **(b) ADDS SCOPE** — nothing as built or pending satisfies it and no price is on
  record; the smallest satisfying change is described and sized SMALL (an amendment or a
  bound, near test-only), MEDIUM (a requirement amendment plus implementation plus
  tests), or LARGE (a new surface or mechanism).
- **(c) N/A** — not scoreable against this surface, with the boundary reasoning that
  makes the N/A honest.

Rows that duplicate a §2 row's subject at §4 (the redirect-matching pair, the PKCE
downgrade pair) are kept — the walk is per-recommendation — but cross-referenced rather
than re-argued.

## Summary — the owner's decision surface

**98 rows walked** (RFC 9700 §2: 27; §3 and §4: 40; the OIDC beside-set: 5; the MCP
authorization specification and security best practices: 26, scored against the current
`2026-07-28` revision).

| Relevance class | Count |
|---|---|
| (a) SATISFIED — control exists, no new scope | 64 |
| (a) PRICED — violated or partial, already priced on record | 8 |
| (b) ADDS SCOPE — unpriced gap, the owner's call | **5 rows, 4 distinct findings** |
| (c) N/A — boundary reasoning stated | 22 |

One row — the MCP communication-security row, which carries two MUSTs — is split across
two verdicts (PRICED for the endpoints half, ADDS SCOPE for the redirect-URI half), so
the four class counts sum to 99 over 98 rows.

**The (b)-class list — every row that would add to the delta scope, with its size:**

| # | Source | The gap | Smallest satisfying change | Size |
|---|---|---|---|---|
| B-1 | RFC 9700 §2.6 MUST NOT (dual-sourced: the MCP authorization spec's own "All redirect URIs **MUST** be either `localhost` or use HTTPS" — **verbatim on the current `2026-07-28` revision** (`security-considerations.md`, Communication Security), re-verified word-for-word; basis STRENGTHENED, not merely intact) | A **non-loopback plain-`http` redirect URI is registerable and usable** at every one of the three client-resolution paths — DCR validates `redirect_uris` for type/count/length only (`gateway/routes.py:336-357`), the CIMD document's `redirect_uris` are accepted with no scheme check (`gateway/cimd.py:307-317`), and pre-registered `redirect_uris` carry no scheme validation (`gateway/settings.py:169-175`) — so an `http://` collector URI passes the exact-match rule untouched (`gateway/cimd.py:573-599`). Unpriced anywhere: no spec rule, no RES row, no test | One admission rule, enforced at **four** sites: a registered redirect URI MUST be `https` or a loopback `http` URI (the RFC 8252 §7.3 shape `_loopback_target` already knows, `gateway/cimd.py:529-570`) — a refusal clause in the DCR body check, the CIMD document validation, a startup refusal for pre-registered config, and **load-time validation of the durable DCR store** (or an explicit boundary ruling that pre-rule records are the pre-publication cleanup backlog's, not the rule's): records admitted before the rule lands — or planted per the store's own threat row, T7-1's class — otherwise keep their non-loopback `http` URIs usable after the rule lands, because client resolution reads the store without re-checking; the exposure is bounded by DCR's default-off (RES-5) and the host/volume boundary, but the rule's scope sentence must name it. Plus a sentence in the client-registration requirement; tests. Loopback `http` is excepted, so no fielded harness UX changes | **MEDIUM** (a rule + implementation at four sites + tests; mechanically small, but it is a behavior change on live registration surfaces, not a statement) |
| B-2 | RFC 9700 §4.2.4 SHOULD (the AS *SHOULD revoke all tokens issued previously based on that code* on double redemption) | A replayed authorization code is refused by the replay cache (`gateway/token.py:452-458`) — but the tokens minted from the first redemption **stay live**: no revocation of the refresh token a replayed code once bought. Unpriced: not in the annex, not in an RES row | On the replay refusal, denylist the refresh token issued from that code: the code grant remembers `code_id → refresh_jti` for the refresh window (the replay cache's own store family, TTL-bounded), and the refusal path calls the existing denylist (`gateway/token.py:581-582`); one clause in the token-grant side of the public-endpoints requirement; tests. **Two disclosed partials, so the spec clause states the bound it actually buys:** (1) the access token stays unrevocable by design (bearer, short TTL — M9's standing bound), which the RFC's SHOULD tolerates; (2) a refresh token that has already **rotated** before the replay is detected survives — rotation mints a fresh `jti` (`gateway/token.py:702-716`) and no code_id→successor mapping exists, so denylisting the original `jti` leaves the live successor untouched; closing that half means the memo tracks the rotation chain (or the clause accepts the window, bounded by the replay detection's timing and the non-sliding absolute expiry) | **SMALL** (an amendment + a bounded memo + one denylist call; no new surface, route, or page — the rotation-chain tracking, if wanted, is the same memo's one extension) |
| B-3 | The MCP authorization spec's redirect-URI MUST (same finding as B-1, its second normative source) | Same as B-1 | Same as B-1 — one change closes both sources | **MEDIUM** (with B-1) |
| B-4 | The MCP authorization spec's CIMD security section, current `2026-07-28` revision (`security-considerations.md`, Localhost Redirect URI Risks — **verbatim**, and reinforced by the best-practices tutorial's dedicated "Localhost Redirect URI Impersonation" section, which names these countermeasures as "expected of authorization servers") (SHOULD): "Authorization servers **SHOULD** display additional warnings for `localhost`-only redirect URIs" | No localhost-specific warning exists as built or in the pending delta, and no residual prices this exact shape — the softest of the five (b) rows. The honest boundary note for the owner: the shape the warning mitigates (the section's own localhost-impersonation attack — a hostile party pairing the *legitimate* client's metadata URL with its own loopback port, the port exception letting it match) requires code execution on the victim's host to harvest the code, which already sits inside the accepted local-compromise floor (RES-23's class — an attacker with local code execution holds strictly cheaper attacks, the same pricing logic DT-EP1-1 applies to the on-path attacker); the delta's first-attribution display of the full `redirect_uri` (port included) bounds the drive-by shape | One sentence on the decision page when the flow's registered redirect is loopback (naming that the destination is a local address on the user's own machine), riding the checkpoint requirement's page-content amendment the delta already carries; one test | **SMALL** (a page-content clause on a page the delta already builds; the owner may equally rule it deferred-with-reasoning on the boundary note above — it is priced here so that ruling is a recorded decision, not a silence) |
| B-5 | The MCP authorization spec's **Authorization Response Validation** section, new in the current `2026-07-28` revision (`authorization/index.md`; also the driver of the new **Mix-Up Attacks** sections in `security-considerations.md` and the tutorial) (MUST): "Authorization servers that include the `iss` parameter **MUST** advertise this by setting `authorization_response_iss_parameter_supported` to `true` in their metadata" (RFC 9207 §2.3) — beside the AS-facing SHOULD "MCP authorization servers **SHOULD** include the `iss` parameter in authorization responses, including error responses", with the stated intent to upgrade that SHOULD to MUST in a future revision | The SHOULD half is satisfied as built: `iss` rides every authorization response, success and redirected error alike (M9; `gateway/flow.py:454-466`; `gateway/authorize.py:162-168`; the "Authorization responses identify their issuer" requirement). The MUST half is **violated and unpriced as built**: the AS metadata document carries no `authorization_response_iss_parameter_supported` member (`gateway/discovery.py:56-76` — issuer, endpoints, jwks, revocation, grants, response types, auth methods, challenge methods, the CIMD flag, the registration endpoint; no RFC 9207 member) — a conforming 2026-07-28 client that records the issuer and checks the metadata is told nothing about `iss` emission, and the revision's mix-up machinery explicitly depends on honest servers advertising it. Unpriced: no spec rule, no test, and the design's D8/D10 records do not mention the member | One metadata member — `"authorization_response_iss_parameter_supported": true` in the AS metadata document (`gateway/discovery.py:56-76`) — plus one sentence in the discovery requirement's advertisement clause (the requirement already enumerates the advertised members; this joins them) and one metadata-assertion test. No behavior change anywhere else: the emission itself already happens on every response | **SMALL** (one member, one clause, one test — the smallest of the five; a pure trueness fix, making the metadata state what the code already does) |

**The (a) PRICED rows — the 8 rows by name, so the tally is checkable** (violated or
partial today, no new scope because the price is on record; listed so "no new scope" is
not read as "green"): **§2.2.1** and its **§4.10** twin — the sender-constraining SHOULD
(D6's deferral, two-sided precondition — see Part 5 for a new fact that narrows its
client-side leg); **§2.3** — AS-side audience restriction placed, RS-side refusal
Core's to enforce (RES-7; OQ-4 names the Core-side fix; §4.9.3's own row is *not* one of
the 8 — it is (c) N/A with the price already on record, the RS boundary being the reason);
**§2.5** — asymmetric client authentication on the identity leg (M28/RES-24, symmetric
secret, owner-ruled); **§2.6** — end-to-end TLS (RES-12 the plain-http front door, M18
named and deployment-owned; RES-19 the internal plain-http legs); **§4.13's proxy-link
half** (RES-19's class); **Part 4's token-handling row** — the MCP spec's RS-side
audience validation MUST (RES-7/OQ-4, Core's duty); **Part 4's communication-security
row's endpoints half** — "all AS endpoints MUST be served over HTTPS" (RES-12).

**The headline finding, stated plainly:** B-1 is a violated MUST NOT (two normative
sources, both verbatim on the current `2026-07-28` revision) that the design's D10 annex
did not surface and no residual prices — the report's most important result. B-2 is a
violated SHOULD, likewise unpriced (RFC 9700-sourced; untouched by the MCP revision
history). Both are small against the change's existing weight, and both are
admission/replay-path rules, not new surfaces. B-4 (surfaced by the revision re-walks)
is soft: a SHOULD whose attack precondition sits inside an already-accepted class —
priced so the owner's ruling on it is a recorded decision either way. B-5 (new in the
`2026-07-28` restructuring) is a trueness gap: the code emits `iss` everywhere and the
metadata never says so — the smallest fix in the list.

## Part 1 — RFC 9700 §2, the operational recommendations

### §2.1 Protecting redirect-based flows

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.1 (MUST) | The AS compares client redirection URIs against pre-registered ones by exact string matching, excepting variable ports for native-app loopback redirects | Exact string equality with exactly one exception — the loopback-port rule keyed on the **registered** entry, never the request's (`gateway/cimd.py:573-599`, `_loopback_target` at `:529-570`); the main spec's "Loopback redirect URIs match ignoring the port" requirement; M3 | **(a) SATISFIED** |
| §2.1 (MUST NOT) | Neither clients nor authorization servers expose open redirectors | AS side: every refusal is answered **in place** until the client and its redirect URI are validated (`gateway/authorize.py:158-168`; the unregistered-redirect refusal at `:226-234` carries no `redirect_uri` and is never redirected); redirected errors go only to the validated registration. Gateway-as-client side: its redirect target is the one configured callback (`gateway/idp.py:305-309`), never caller-influenced | **(a) SATISFIED** |
| §2.1 (MUST) | Clients prevent CSRF in the authorization flow via PKCE, the OIDC `nonce`, or one-time-use `state` bound to the user agent | The gateway as OAuth client (identity leg): PKCE S256 by default plus the flow id as `state` — 128-bit CSPRNG, server-side record, round-tripped and single-use (M1/M2; `gateway/flow.py:149-167`). The gateway as AS: PKCE S256 is mandatory of every client (`gateway/authorize.py:236-242`), which RFC 9700 §2.1 names a sufficient carrier; the pending delta's `state` rule (D8) states the tolerance and the reasoning | **(a) SATISFIED** |
| §2.1 (MUST + SHOULD + MAY) | Clients interacting with multiple ASs deploy a mix-up defense — `iss` per RFC 9207 preferred, distinct redirect URIs as fallback | The gateway emits `iss` (RFC 9207) on every authorization response, success and redirected error alike (`gateway/flow.py:454-466`; the spec's "Authorization responses identify their issuer" requirement; M9). Gateway-as-client: one configured IdP per process with exact-string issuer pinning (M29) — the single-AS shape the defense exists for, held by the pin rather than by per-request bookkeeping | **(a) SATISFIED** |
| §2.1 (MUST) | An AS redirecting requests that may contain user credentials avoids accidentally forwarding those credentials | The AS's redirects carry only `code`, `iss`, and the echoed `state` (`gateway/flow.py:462-466`); redirected errors carry `error`/`description`/`state`/`iss` and nothing the request offered beyond them; no token, secret, or provider artifact ever rides a redirect (the custody carrier discipline, M21) | **(a) SATISFIED** |

### §2.1.1 Authorization code grant

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.1.1 (MUST, clients) | Clients prevent code injection and misuse via the listed mechanisms | The enforced mechanism is PKCE: the challenge is required at allocation and embedded in the code's bindings, and the redemption validates the verifier against it (`gateway/authorize.py:236-242`; `gateway/codes.py:106-147`; `gateway/token.py:437-444`) | **(a) SATISFIED** |
| §2.1.1 (MUST) | Public clients use PKCE | Every client on the client-facing surface is public, and PKCE is mandatory of all of them — a challenge-less request never allocates a flow (`gateway/authorize.py:236-242`; the AS metadata advertises `token_endpoint_auth_method: none`, `gateway/discovery.py:68`) | **(a) SATISFIED** |
| §2.1.1 (RECOMMENDED) | Confidential clients also use PKCE | The one confidential client the gateway operates (the identity leg) carries PKCE S256 by default, the toggle governing only whether the challenge rides on top of the client secret (the confidential-client requirement; `gateway/idp.py:311-341`) | **(a) SATISFIED** |
| §2.1.1 (MAY) | Confidential OIDC clients may use `nonce` + ID Token instead | No ID-token leg exists on either surface the gateway operates; the alternative mechanism is not scoreable here | **(c) N/A** — the no-ID-token boundary (D7's ruling) |
| §2.1.1 (MUST) | The PKCE challenge (or nonce) is transaction-specific and bound to the client and user agent | The verifier is generated per flow, stored only on the server-side flow record, and never crosses a boundary; only its challenge travels (`gateway/flow.py:149-167`); the code's bindings pin `client_id`, `redirect_uri`, `resource` beside the challenge (`gateway/codes.py:136-145`) | **(a) SATISFIED** |
| §2.1.1 (SHOULD) | Clients use a challenge method that does not expose the verifier in the authorization request (S256 today) | S256 is the only method accepted at allocation (`gateway/authorize.py:236-242`) and the only one the redemption verifies — `plain` is refused, not implemented (`gateway/codes.py:93-103`) | **(a) SATISFIED** |
| §2.1.1 (MUST) | The AS supports PKCE | Enforced and advertised: mandatory challenge at allocation, `code_challenge_methods_supported: ["S256"]` in the AS metadata (`gateway/discovery.py:69`) | **(a) SATISFIED** |
| §2.1.1 (MUST) | Where a valid `code_challenge` was sent, the AS enforces correct `code_verifier` usage at the token endpoint | The challenge is embedded in the code's signed bindings and the verifier is checked against it on every redemption (`gateway/token.py:437-444`) | **(a) SATISFIED** |
| §2.1.1 (MUST) | The AS mitigates PKCE downgrade — a `code_verifier` presented where no `code_challenge` was sent is rejected | Structural: a code cannot exist without a challenge (allocation refuses the challenge-less request), and the grant requires the verifier of *every* redemption (`gateway/token.py:400-407`) — there is no challenge-less code to downgrade into, so the rejection the RFC demands has no input to fire on. This is the annex's "downgrade guard structural" claim, **verified** | **(a) SATISFIED** |
| §2.1.1 (MUST + RECOMMENDED) | The AS provides a way to detect PKCE support; publishing `code_challenge_methods_supported` in AS metadata is recommended | Both: the metadata member is present (`gateway/discovery.py:69`) and the mandatory challenge itself is loud | **(a) SATISFIED** |

### §2.1.2 Implicit grant

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.1.2 (SHOULD NOT / SHOULD) | Clients do not use the implicit grant or any response type issuing tokens in the authorization response; they use `code` | `response_type=code` is the only value accepted (`gateway/authorize.py:214-219`); `response_types_supported: ["code"]` (`gateway/discovery.py:65`); tokens are issued only at the token endpoint | **(a) SATISFIED** |

### §2.2 Token replay prevention

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.2.1 (SHOULD) | ASs and RSs sender-constrain access tokens (mTLS per RFC 8705, DPoP per RFC 9449) | Not implemented, **deferred with a named two-sided precondition** (D6): the MCP authorization specification mandates Bearer presentation (verified again this pass — see Part 5) and the resource server of gateway tokens is **Core**, whose identity-provider entry validates bearer-style with no RFC 9449 proof validation — the constraint would be void exactly where it must hold. The residual it would remedy stays priced (T1-3, RES-7, RES-8; short access TTL M9 the standing bound). **New fact in Part 5: the client-side precondition is closer than the design recorded** | **(a) PRICED** |
| §2.2.2 (MUST) | Public clients' refresh tokens are sender-constrained **or** protected by rotation | Rotation with replay detection is the held alternative: default-on rotation keeping the original absolute expiry, denylist-by-`jti` with a short grace window (M9; `gateway/token.py:679-726`, `:581-582`) | **(a) SATISFIED** |

### §2.3 Access token privilege restriction

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.3 (SHOULD + MUST + MAY) | Token privileges are minimized; access tokens are audience-restricted to the intended resource server, which MUST refuse mismatched audiences; `scope`/`resource` may signal the target | AS side placed: `resource` is the required disambiguator at both endpoints and at refresh (M4; `gateway/authorize.py:311-373`; `gateway/token.py:412-414, 433-435, 588-590`), the access token's `aud` is `[resource, marker]` and the refresh token's is the resource alone (`gateway/tokens.py:220, 261`), and no scopes are granted at all (`"scope": ""`, `gateway/token.py:329` — the honest empty set). RS side is **not the gateway's**: Core's check is marker-only (RES-7; T1-12's cross-kind widening; OQ-4 names the Core-side per-issuer path/audience scoping as the future fix) | **(a) PRICED** — AS-side satisfied, RS-side priced at RES-7/OQ-4 |

### §2.4 Resource owner password credentials grant

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.4 (MUST NOT) | The ROPC grant is not used | The grant dispatch knows exactly `authorization_code` and `refresh_token`; anything else is `unsupported_grant_type` (`gateway/token.py:269-279`) | **(a) SATISFIED** |

### §2.5 Client authentication

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.5 (SHOULD + RECOMMENDED) | The AS enforces client authentication where issuance/registration and confidentiality are feasible; asymmetric client authentication (mTLS, private-key JWT) is recommended | Two legs, two verdicts. **Client-facing surface:** no client authentication by design — the client population is public native harness clients (the MCP ecosystem contract itself: `token_endpoint_auth_method: none`), so the feasibility condition fails, and the consent/attribution checkpoint is the control the design interposes instead (D1, D5's refused operator bypass). **Identity leg:** client authentication is on in every mode — the confidential-client rule (M28) — but the secret is **symmetric**, so the RECOMMENDED is violated and priced (M28/RES-24, T4-9's bounded blast radius, owner-ruled) | **(a) PRICED** — the annex's claim verified on both legs |

### §2.6 Other recommendations

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §2.6 (RECOMMENDED) | The AS publishes RFC 8414 AS metadata; clients configure from it | The flat single-issuer document at the well-known path (`gateway/discovery.py:44-76`; the discovery requirement) | **(a) SATISFIED** |
| §2.6 (SHOULD NOT, conditions of §4.15.1) | The AS does not let clients influence their `client_id` where a namespace shared with resource-owner identifiers could cause confusion | Verified non-confusable: DCR ids are gateway-generated (`new_client_id`), CIMD ids are URL-shaped, pre-registered ids are operator-chosen; the access token carries no `client_id` at all, and the identifier Core reads as the resource owner is the provider-verified `sub` (copied from the provider's token, never from client input) — no claim the RS reads as identity is client-influenceable (see also the §4.15.1 row) | **(a) SATISFIED** |
| §2.6 (RECOMMENDED) | End-to-end TLS per BCP 195 between client and resource server | Violated as built and priced: the plain-http front door (RES-12, M18 named and deployment-owned) and the internal plain-http legs (RES-19) | **(a) PRICED** |
| §2.6 (MUST NOT) | The AS does not allow `http` redirection URIs, except native clients using loopback per RFC 8252 §7.3 | **Violated and unpriced — finding B-1.** No registration path validates the scheme of a redirect URI: DCR checks type/count/length only (`gateway/routes.py:336-357`), the CIMD document's `redirect_uris` are accepted as-is (`gateway/cimd.py:307-317`), and pre-registered `redirect_uris` have no scheme validation (`gateway/settings.py:169-175`). A non-loopback `http://` URI therefore registers and passes the exact-match rule (`gateway/cimd.py:588`), and the code lands on it over a cleartext leg. The same gap is the MCP authorization spec's own MUST (row B-3 in Part 4) | **(b) ADDS SCOPE — B-1, MEDIUM** |
| §2.6 (MUST, per §4.17) | Authorization responses delivered via in-browser techniques (postMessage) strictly verify initiator and receiver | No in-browser response mechanism exists: the pages are script-free server-rendered navigations (`gateway/pages.py`), and no postMessage surface is served anywhere | **(c) N/A** — no in-browser communication channel to score |
| §2.6 (MAY + MUST NOT) | CORS MAY be supported at the token/metadata/registration endpoints for browser-based clients; MUST NOT at the authorization endpoint | No CORS middleware exists anywhere (`gateway/app.py:58-84` builds the app with none), so no endpoint serves `Access-Control-*` — today an implementation accident, which the pending delta (D9) turns into a rule with a pinning test (the no-CORS scenario in the delta's public-endpoints amendment). Declining the MAY is conformant | **(a) SATISFIED** — the posture as built, the rule landed by the pending delta |

## Part 2 — RFC 9700 §3 and §4, the attack mitigations

### §3 Updated attacker model

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §3 (MUST) | Implementers take into account all attacker types present in the deployment's environment, not only the enumerated ones | The threat model's attacker inventory (§6) and per-entry-point threat tables (§8) are exactly this exercise, maintained as a living document with residuals and re-open triggers | **(a) SATISFIED** |

### §4.1 Insufficient redirection URI validation

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.1.3 (MUST) | The AS ensures the request and registered redirection URIs are equal by exact string match | Same control as the §2.1 row — `gateway/cimd.py:573-599`, M3, the loopback-match requirement | **(a) SATISFIED** (cross-ref §2.1) |
| §4.1.3 (MUST) | For native apps using `localhost`, the AS allows variable port numbers | The loopback-port exception, keyed on the registered entry, scheme/host/path/query/fragment all still compared (`gateway/cimd.py:529-599`) | **(a) SATISFIED** |
| §4.1.3 (MUST NOT) | Web servers hosting redirection URIs do not expose open redirectors | The gateway hosts no client redirect targets; its own error surfaces never redirect to an unvalidated target (the §2.1 open-redirector row) | **(a) SATISFIED** (cross-ref §2.1) |
| §4.1.3 (MAY) | Servers MAY prevent fragment reattachment by appending an arbitrary fragment to Location headers | An optional hardening; the surface's redirects carry codes (not fragment-bearing tokens) to loopback listeners, and no redirect URI the surface serves carries a fragment — the attack shape the MAY addresses (fragment-reattachment on an implicit-style response) does not exist here | **(c) N/A** — no fragment-bearing authorization responses exist |
| §4.1.3 (SHOULD) | Clients use the authorization code response type | Enforced of every client (`gateway/authorize.py:214-219`) | **(a) SATISFIED** (cross-ref §2.1.2) |
| §4.1.3 (MAY) | Where the request's origin and integrity are verified (RFC 9101/9126 request objects), the AS MAY trust the redirection URI without further checks | No request-object (JAR/PAR) mechanism exists on the surface, so the trusted precondition never holds — and the surface does not need the exception: the registration match is the check | **(c) N/A** |

### §4.2 Credential leakage via Referer headers

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.2.4 (SHOULD NOT) | Client response pages and the authorization endpoint include no third-party resources or links to external sites | Every page is script-free with an inline stylesheet pinned by hash — no third-party resource of any kind loads on any page (`gateway/pages.py:64-108`; M8) | **(a) SATISFIED** |
| §4.2.4 (MUST) | The AS invalidates authorization codes after their first use | The replay cache claims the code's `jti` at the moment of acceptance — no window between verified and used (`gateway/token.py:452-458`); codes are short-lived (M9's 5-minute lattice) | **(a) SATISFIED** |
| §4.2.4 (SHOULD) | On double redemption, the AS revokes all tokens previously issued based on that code | **Violated and unpriced — finding B-2.** The replayed redemption is refused, but the refresh token the first redemption minted stays live; nothing connects the code's id to the tokens it bought, and no residual prices the gap | **(b) ADDS SCOPE — B-2, SMALL** |
| §4.2.4 (SHOULD, clients) | The `state` value is invalidated by the client after first use | A client-side duty; the gateway's own binding (the flow id) is single-use by destroy-on-first-use, and the client's `state` is echoed unchanged — its lifecycle is the harness's | **(c) N/A** — client-side duty; the AS-side twin is the delta's `state` rule (D8) |

### §4.3 Credential leakage via browser history

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.3.2 (MUST NOT) | Clients pass access tokens in URI query parameters | Never: tokens exist only in token-endpoint JSON bodies served `no-store` (`gateway/token.py:321-332, 894`); no URL the surface builds carries a token (the code is the only credential in a URL, and it is single-use, PKCE-bound, short-lived) | **(a) SATISFIED** |

### §4.4 Mix-up attacks

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.4.2/§4.4.2.1 (MUST, clients) | Clients prevent mix-ups: store the issuer per request, compare the received `iss`, abort on mismatch, evaluate `iss` per RFC 9207 | Client duties — the gateway supplies everything the defense needs (`iss` on every response matching the metadata issuer, one flat AS), and its own client leg holds the single-issuer exact pin (M29). Same control set as the §2.1 mix-up row | **(a) SATISFIED** (cross-ref §2.1) |
| §4.4.2.2 (MUST/SHOULD, clients) | The distinct-redirect-URI defense, used only when the `iss` options are unavailable | The preferred `iss` defense is in place, so the fallback's precondition never arises | **(c) N/A** |

### §4.5 Authorization code injection

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.5.3.2 (MUST, OIDC clients) | Clients validate the `nonce` in the ID Token from the token endpoint and disregard all tokens until the check succeeds | No ID-token leg exists on the client-facing surface — the gateway mints access and refresh tokens only, and `nonce` is in the registry blocklist (`gateway/tokens.py:64-83`) — so the OIDC mechanism has nothing to score against | **(c) N/A** — the no-ID-token boundary (D7); the OAuth twin of this defense is PKCE, which is mandatory |

### §4.6 Access token injection

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.6 (no keywords; informational) | Pure OAuth cannot detect access-token injection; OIDC's `at_hash`/`nonce` mitigate; sender-constraining remains necessary | No ID-token leg (so `at_hash` machinery is absent by the same boundary as §4.5), and the sender-constraining half is the §2.2.1 row's priced deferral (D6) — nothing new to add to that record | **(c) N/A** — cross-ref §2.2.1 |

### §4.7 Cross-site request forgery

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.7.1 (MUST, clients) | Clients confirm the AS supports PKCE before relying on it for CSRF protection; otherwise use `state`/`nonce`; protect integrity-sensitive `state` | Client duties — the AS makes the detection unavoidable (mandatory challenge, `code_challenge_methods_supported` advertised) | **(c) N/A** — client-side duty |
| §4.7.1 (MUST + RECOMMENDED, AS) | The AS provides a way to detect PKCE support; metadata publication recommended | Same control as the §2.1.1 row — `gateway/discovery.py:69` and the mandatory challenge | **(a) SATISFIED** (cross-ref §2.1.1) |

### §4.8 PKCE downgrade attack

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.8.2 (MUST) | The AS mitigates the downgrade — no `code_verifier` accepted where no `code_challenge` was sent | Structural, verified: allocation refuses the challenge-less request (`gateway/authorize.py:236-242`), so no code without a challenge can exist, and the grant requires the verifier unconditionally (`gateway/token.py:400-407`) | **(a) SATISFIED** (cross-ref §2.1.1; the annex's claim verified) |

### §4.9 Access token leakage at the resource server

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.9.3 (SHOULD/SHOULD/MUST, RS) | The RS uses sender-constrained and audience-restricted tokens and treats tokens as secrets in storage | The resource server of gateway tokens is **Core**, not the gateway — the RS-side duties are Core's, and their absence is the priced RES-7/OQ-4 record; the AS-side halves are the §2.2.1 and §2.3 rows | **(c) N/A** for the gateway-as-AS (boundary: the token's validator is Core), with the price already on record |

### §4.10 Misuse of stolen access tokens

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.10 (SHOULD) | The AS ensures access tokens are sender-constrained and audience-restricted | The same two priced halves: sender-constraining deferred on the two-sided precondition (D6), audience restriction placed AS-side and marker-only RS-side (RES-7); the standing bound is M9's short access TTL plus Core's per-call DIAL authorization | **(a) PRICED** (cross-ref §2.2.1, §2.3) |

### §4.11 Open redirection

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.11.1 (MUST NOT, clients) | Clients do not expose open redirectors | The gateway-as-client's only redirect target is its configured callback (`gateway/idp.py:305-309`); as a page host it serves no URL that forwards to a caller-supplied target | **(a) SATISFIED** (cross-ref §2.1) |
| §4.11.2 (MUST, RFC 6749) | The AS does not auto-redirect the user agent on an invalid `client_id`/`redirect_uri` combination | Every refusal before validation is answered in place (`gateway/authorize.py:158-168`); the `AuthorizeError.redirect_uri` field is the mechanism — set only after the registration match passes (`:226-234`, `:236-242`) | **(a) SATISFIED** — the annex's claim verified |
| §4.11.2 (MUST) | The AS takes precautions against the dynamic-registration phishing attacks enumerated there | The pending delta's checkpoint is the named precaution (the decision page naming client, resource, and the registered `redirect_uri` on first attribution), layered on DCR's default-off (RES-5) and the CIMD origin allowlist (M7); the MCP best-practices confused-deputy MUST — the same attack, stated normatively for this architecture — is discharged by the same checkpoint (Part 4) | **(a) SATISFIED** — landed by the pending delta |
| §4.11.2 (MUST) | The AS always authenticates the user first, and prompts for credentials when needed, before redirecting — silent authentication (`prompt=none`) excepted | Federated by construction: the redirect the AS issues goes **to the authentication** (the IdP's authorization endpoint), which prompts per its own session policy; no code is issued, and no redirect to a *client* target happens, before the identity leg's verified subject exists. The zero-page short-circuits were the shape that leaned on the silent-authentication exception beyond its intent, and the checkpoint removes exactly that reach — the annex's framing, **verified** | **(a) SATISFIED** — the delegation reading plus the pending delta |
| §4.11.2 (SHOULD + MAY) | The AS auto-redirects only where it trusts the redirection URI; where it does not, it MAY inform the user and rely on the user's decision | The checkpoint is this option, built: trust in a CIMD-resolved redirect is origin-level at best (the attack's precondition lives inside an allowlisted origin), so the inform-the-user page is the honest answer on first attribution (D1/D2; RFC 9700 §4.11.2 is the design's own standards anchor, and the MCP authorization spec carries the same SHOULD/MAY pair — verified in Part 4) | **(a) SATISFIED** — landed by the pending delta |

### §4.12 307 redirects

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.12 (MUST NOT + SHOULD) | The AS does not use HTTP 307 for redirects of requests that may contain user credentials; 303 preferred where redirection is used for such requests | The annex's adjacent item, **ruled N/A**: the surface issues only 302, and only in answer to GET navigations (`gateway/authorize.py:186`; `gateway/federation.py:396`; `gateway/errors.py:89` — no 307 or 303 anywhere), so the precondition — redirecting a credential-bearing *request* with a method-preserving status — never occurs. A 302 answering a GET cannot re-POST a credential | **(c) N/A** — the annex's disposition verified and confirmed |

### §4.13 TLS-terminating reverse proxies

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.13 (MUST) | The reverse proxy sanitizes inbound requests so security-relevant header values cannot be forged (e.g. `X-Forwarded-For`) | The proxy-trust discipline is implemented and reasoned at the seam the gateway owns: the rate-limit source reads `X-Real-IP` or the **last** `X-Forwarded-For` entry — the router's own appended value, not the client's claim — and the value is never trusted for authorization (`gateway/errors.py:221-239`); the committed router config derives those headers from `$remote_addr` (M15) | **(a) SATISFIED** |
| §4.13 (MUST) | The proxy-to-application-server link is protected against eavesdropping, injection, and replay, with entity authenticity | As built locally, the router-to-gateway and internal legs are plain http on the instance network — violated and priced as RES-19's class (M16's topology invariant the standing bound; M18 named for the TLS-fronted production direction) | **(a) PRICED** |

### §4.14 Refresh token protection

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.14.2 (MUST) | The AS decides via risk assessment whether to issue refresh tokens to a given client | The decision is made and on record, not defaulted: refresh tokens are session-bound by construction (the carried provider session token dies with the session — `idp_session_ended`), rotation + denylist is default-on, and the whole lattice is the designed trade (M9/M21, the token-lattice requirements) — every client gets one *because* the session bound is the risk answer | **(a) SATISFIED** |
| §4.14.2 (MUST) | Issued refresh tokens are bound to the consented scope and resource servers | The refresh token carries its `resource` and `client_id` as signed bindings, and every refresh must name the same resource (`gateway/token.py:588-590`) and the same client (`:623-627`); no scopes are granted, so the scope binding is vacuously exact (`"scope": ""`) | **(a) SATISFIED** |
| §4.14.2 (MUST) | For public clients: sender-constrained refresh tokens OR rotation with replay detection | Rotation with replay detection — the same control as the §2.2.2 row (M9; `gateway/token.py:679-726`) | **(a) SATISFIED** (cross-ref §2.2.2) |
| §4.14.2 (MUST, implementation note) | Where the grant is encoded in the token value, integrity is ensured (e.g. signatures) | All three token kinds are self-signed JWTs verified under the pinned algorithm and issuer (`gateway/tokens.py:310-343`; M20) — the grant is never readable without the signature check | **(a) SATISFIED** |
| §4.14.2 (MAY) | The AS MAY auto-revoke refresh tokens on security events (password change, logout) | Held by a different mechanism: an IdP session revocation ends the gateway's refresh capability at the next attempt (the carried session token dies with the session, `gateway/token.py:649-667`), and `/dial/revoke` denylists by id (`:760-825`) | **(a) SATISFIED** |
| §4.14.2 (SHOULD) | Refresh tokens expire after a period of client inactivity | The annex's adjacent item, **ruled satisfied in substance by a different mechanism**: the window is non-sliding with the original absolute expiry frozen at issuance (`gateway/tokens.py:274-281`), startup-bounded by the operator-declared IdP session bound (M10), and disuse ends it at the provider — an unused token past the window, or past the session it rode, refuses `invalid_grant`. The concern's substance (a bounded refresh life that ends with disuse) is met; the mechanism is absolute expiry plus session death, not an inactivity timer | **(a) SATISFIED** |

### §4.15 Client impersonating resource owner

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.15.1 (SHOULD NOT + MUST) | ASs do not let clients influence their `client_id` (or other claims) where a namespace shared with resource-owner identifiers exists; where unavoidable, the RS is given a way to distinguish | Verified non-confusable: the identifier the RS (Core) reads as the resource owner is `sub`, copied from the provider's verified token — never client input; the access token carries no `client_id`; refresh tokens (which do carry one) are not Core-acceptable by the marker separation; and no `sub` value can be registered as a client id that would then flow into a token claim the RS reads as identity | **(a) SATISFIED** (cross-ref §2.6) |

### §4.16 Clickjacking

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.16 (MUST + SHOULD) | The AS prevents clickjacking (X-Frame-Options/frame-busting per RFC 6819), and additionally uses CSP level 2 or greater | Both, on every HTML response by the one builder: `frame-ancestors 'none'` + `X-Frame-Options: DENY` beside a full CSP (M8; `gateway/pages.py:91-118`; the web-hardening requirement), extended by the delta to the decision page with `form-action 'self'` and no auto-continue | **(a) SATISFIED** |
| §4.16 (SHOULD) | ASs let administrators configure (or clients register) the origins allowed to frame them | The recommendation presupposes a legitimate framing consumer for the AS's pages; none exists on this surface (the pages are flow moments, not embeddable widgets), and the pages' policy is deliberately `frame-ancestors 'none'` — stricter than the configurable-origins shape the SHOULD envisions. Allowing configuration would *widen* a control the surface wants total | **(c) N/A** — no framing consumer exists; refusing all framing satisfies the MUST more strictly than the SHOULD's mechanism |
| §4.16 (SHOULD) | CSP is combined with other countermeasures unless legacy user agents are unsupported | Combined by construction: the legacy `X-Frame-Options: DENY` header rides beside the CSP on every page (`gateway/pages.py:105-106`) | **(a) SATISFIED** |

### §4.17 Attacks on in-browser communication flows

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| §4.17.2 (MUST/MUST NOT) | Exact-string matching of receiver origins; postMessage only to trusted explicit origins, never `*`; clients prevent injection at the receiver; §2.1's protections applied to in-browser flows | No postMessage or any in-browser messaging exists — the pages are script-free (`gateway/pages.py`), responses are navigations and JSON, and the §2.1 protections already cover the navigation flows the surface actually serves | **(c) N/A** — no in-browser communication channel exists (cross-ref §2.6) |


## Part 3 — The OIDC beside-set (the roadmap's named scope)

The roadmap's C2.5 scope names the step-up parameter set and the nonce/ID-token boundary.
The boundary that governs all of them: the gateway's client-facing AS is an **OAuth 2.x
server, not an OIDC provider** — no ID tokens, no `nonce`, no `openid` semantics toward
harness clients (`gateway/token.py` mints access and refresh tokens only), and the gateway
never sees the provider's ID token either (its verified artifact is the provider's *access*
token, per the federation-flow and refresh requirements). D7's ruling is verified against
the code on every point below.

| Item | What it demands (OIDC Core) | The gateway as built | Verdict |
|---|---|---|---|
| `max_age` (OIDC Core §3.1.2.1) | An OIDC RP sends `max_age` to demand authentication recency; the OP re-authenticates or returns `auth_time` for the client to check | The authorize surface reads exactly `response_type`, `client_id`, `redirect_uri`, `resource`, `state`, and the PKCE pair (`gateway/authorize.py:112-143`) — `max_age` is unrecognized and ignored, and acting on it per OIDC's own contract would require the ID-token leg (answering with `auth_time`) the surface deliberately lacks. The identity leg relays nothing client-derived (`gateway/idp.py:311-341` — verified: the redirect carries the gateway client's own facts only), so a client's `max_age` can never reach the provider. Half-accepting it — relaying without being able to answer — would advertise a guarantee the surface cannot make (D7's reasoning, verified) | **(c) N/A** — no ID-token leg; non-acceptance stated by D7 so a from-spec reimplementation does not "helpfully" add it |
| `prompt` (`login`/`none`, OIDC Core §3.1.2.1) | `prompt=login` forces re-authentication; `prompt=none` forbids interaction and errors where silent auth is impossible | Not accepted on the client surface (same parameter set as above); the identity leg never relays a `prompt` on any flow (`gateway/idp.py:311-341`). The silent-authentication shape that *does* touch this surface — a live provider session driven silently — is exactly T1-25's drive-by, and the checkpoint (not a step-up parameter) is the control that bounds it. The operator-policy step-up (`prompt=login` relayed on every sign-in) is recorded-not-built with its precondition (OQ-4) | **(c) N/A** — no ID-token leg; the one silent-auth risk this surface has is the checkpoint's, bounded by the pending delta |
| `auth_time` (OIDC Core §2 claim) | The ID-token claim answering `max_age`, stating when the user last authenticated at the OP | **A real as-built gap, landed by the pending delta:** the mint's copy rule is verbatim-minus-registry and `REGISTRY_CLAIMS` strips `acr` but **not** `auth_time` (`gateway/tokens.py:64-83`) — a provider that minted `auth_time` into its access token would have it copied verbatim into a gateway token, stating the *provider's* authentication event as a fact of the gateway's own token (the same false-claim class `acr`'s strip exists for). The delta's claim-copy amendment lands the strip with its scenario; the mint's own recency facts stay its `iat`/`exp` (`gateway/tokens.py:216-225`), the honest limit of what the gateway knows | **(a) SATISFIED** — by the pending delta (the as-built gap is real and correctly priced by D7's analysis) |
| `nonce` (OIDC Core §3.1.2.1/§11.3) | The RP sends `nonce`; the OP returns it in the ID token; the RP verifies to bind the flow to its request | No ID-token leg to carry or answer a `nonce`; on the copy side, `nonce` is already in `REGISTRY_CLAIMS` (`gateway/tokens.py:64-83`), so a provider token carrying one cannot leak it into a gateway token — the boundary holds in both directions | **(c) N/A** — the no-ID-token boundary; the copy-side hygiene already held |
| The ID-token boundary generally | All OIDC ID-token machinery (signature validation per OP metadata, `at_hash`/`c_hash`, `iss`/`aud` ID-token checks) | The client-facing surface has no ID tokens to protect or to misuse; the provider's own ID token never reaches the gateway (the leg's verified artifact is the provider's access token, verified under the pinned algorithm and key set — the inbound-verification requirement). Scoring OIDC ID-token machinery against this surface would be scoring a mechanism its architecture deliberately excludes | **(c) N/A** — the boundary D7's refusal rests on, verified against the code |

## Part 4 — The MCP authorization specification and security best practices

The ecosystem's contract the surface exists to satisfy. **Scored against the current
`2026-07-28` revision** — current per `modelcontextprotocol.io/specification/versioning`
("The current protocol version is 2026-07-28"), the revision the earlier correction pass
of this report wrongly took to be `2025-11-25` (a source-currency defect the owner
caught; the design's Context and the review record share it — see the note at the end of
this part). The revision restructured the authorization surface into six pages, all
fetched in full and scored here: the authorization index, authorization-server-discovery,
client-registration, and security-considerations specification pages, plus the
security-best-practices and local-server-security tutorial pages; the `2025-06-18` and
`2025-11-25` texts were fetched alongside for continuity on the items the revisions
carry unchanged, and every load-bearing statement the report's verdicts rest on was
re-verified **verbatim** on the current pages (the per-row citations name the page).

**What the `2026-07-28` restructuring changes, and how this part handles it:** dynamic
client registration stays MAY and is now formally **deprecated** — registry entry,
migration path CIMD, earliest removal the first revision released on or after
2027-07-28 (the DCR row carries it); RFC 9207 `iss` becomes normative machinery — the
AS SHOULD emit `iss` on every authorization response including errors, and **MUST
advertise `authorization_response_iss_parameter_supported`** where it does (two new
rows; the advertisement MUST is finding **B-5**); the Refresh Tokens guidance adds an
RS-facing SHOULD NOT on `offline_access` (a new row); the best-practices tutorial's
session-hijacking section is replaced by **State Handle Hijacking** (MCP is stateless
at 2026-07-28 — the row is re-scored) and gains an explicit AS-facing SSRF subsection
("SSRF Against Authorization Servers" — folded into the SSRF row); and the new
local-server-security tutorial is scored in its own row. Everything else the report's
MCP verdicts rest on — the redirect-URI MUST (B-1/B-3), the Bearer mandate and DPoP
silence (D6), the confused-deputy per-client-consent MUST and the full consent-UI
requirements (D1/D3), the client-registration priority order, the CIMD statements, the
token-theft and open-redirection and token-handling statements — is **verbatim on the
current pages**, re-verified word-for-word; no existing verdict changed on the
current text.

**Stated rather than dropped — the current revision's material that adds no rows:** the
two OPTIONAL authorization extensions in the `modelcontextprotocol/ext-auth` repository
are out of scope for this surface and named for the record — `oauth-client-credentials`
(serves non-user clients; this surface's clients are user-facing public PKCE clients)
and `enterprise-managed-authorization` (governs organization-managed AS/RS trust; not
this deployment's shape); both are stable at `2026-07-28`, neither is adopted, and
neither imposes anything on an AS that does not opt in. The protocol-version
negotiation machinery (`_meta` protocolVersion, the `MCP-Protocol-Version` header,
`server/discover`) lives on the MCP data path between client and MCP server — Core's,
behind the router — and carries no duty on the OAuth surface this gateway owns; the
deprecated-features registry's only entry touching this surface is DCR's (the row
carries it), and its "new implementations SHOULD NOT adopt / existing SHOULD migrate"
posture is exactly the gateway's default-off, CIMD-first shape. The client-side
registration-binding MUSTs (credentials keyed to the AS issuer, re-registration on AS
change) and the DCR `application_type` MUSTs are harness duties — the gateway is the
one flat issuer its harnesses talk to, and its DCR is plain RFC 7591, not OIDC
registration, so the OIDC constraint machinery does not bind it.

### The authorization specification

| Ref (2026-07-28 page) | Demands | The gateway as built | Verdict |
|---|---|---|---|
| Overview (MUST, `authorization/index.md`) | ASs implement OAuth 2.1 with appropriate security measures for confidential and public clients (the standards list now names RFC 6750 beside OAuth 2.1, RFC 8414/7591/8707/9728/9207, the CIMD draft, and OIDC discovery/registration) | OAuth 2.1's shape held: code + refresh only, PKCE mandatory, no implicit, no ROPC (the §2 rows of Part 1 are the "security measures" walk this MUST points to, and RFC 9700 is the document the best-practices tutorial names for it) | **(a) SATISFIED** |
| Discovery (MUST, `index.md` + `authorization-server-discovery.md`) | ASs provide at least one discovery mechanism — RFC 8414 AS metadata (or OIDC discovery, the revision's alternative); MCP clients use it and validate the document's `issuer` against the well-known URL's origin | The flat single-issuer RFC 8414 document (`gateway/discovery.py:44-76`; the discovery requirement) — the at-least-one disjunction is satisfied by the RFC 8414 half, the document's `issuer` is the public origin the well-known URL is built from (the client-side identity check passes by construction), and the gateway serves no OIDC discovery variant to owe the OIDC-only metadata MUST | **(a) SATISFIED** |
| Protected resource metadata (MUST, `authorization-server-discovery.md`) | MCP servers implement RFC 9728 with `authorization_servers`, and answer 401 with `WWW-Authenticate` naming the resource metadata URL (or serve the well-known alternative) | The per-toolset and per-app protected-resource documents, served at the well-known resource path, and the challenge synthesis through the router (M15; the toolset-path and apps-path requirements; the challenge never lets Core's own through) — both discovery mechanisms the page offers | **(a) SATISFIED** |
| Client ID Metadata Documents (SHOULD, `client-registration.md`; with AS-side implementation MUSTs) | ASs and clients support CIMD per the draft; an AS supporting it SHOULD fetch URL-shaped client ids, MUST validate the document's `client_id` matches the URL exactly, MUST validate redirect URIs against the document, MUST validate the document's structure, SHOULD cache, and SHOULD follow the draft's §6 security considerations — and MAY apply domain-based trust policies | Satisfied as built, member by member, verbatim-unchanged across all three revisions: the capability is advertised (`client_id_metadata_document_supported: true`, `gateway/discovery.py:72`), URL-shaped ids are fetched under the full SSRF control set (M7; `gateway/cimd.py:134-271` — the tutorial's new "SSRF Against Authorization Servers" subsection applies those mitigations to exactly this fetch), the `client_id`-matches-URL check is exact (`gateway/cimd.py:299-305`), redirect URIs are validated against the document's entries (`gateway/cimd.py:573-599`), the document's structure and required fields are validated (`:307-317`), fetches are TTL- and size-cached (`:334-443`), and the operator origin allowlist is a domain-based trust policy in the MAY's own shape | **(a) SATISFIED** |
| Dynamic registration (MAY, `client-registration.md` — **deprecated**; SHOULD in `2025-06-18`, MAY from `2025-11-25`) | ASs and clients MAY support RFC 7591 DCR — deprecated in `2026-07-28` (registry entry, PR #2858: migration path Client ID Metadata Documents, earliest removal the first revision released on or after 2027-07-28; "new implementations SHOULD NOT adopt it, and existing implementations SHOULD migrate") | Implemented and config-gated **default-off**, with CIMD the preferred rung and pre-registration the operator rung (`gateway/routes.py:179-255`; the resolution order `gateway/authorize.py:263-298`) — the MAY is satisfied outright, and the default-off, CIMD-first posture is precisely the registry's migration shape: the gateway's DCR exists for harnesses that cannot do CIMD, which is the deprecation's own stated backwards-compatibility purpose (RES-5 prices the flag). The current revision's client registration priority (pre-registered → CIMD → DCR → prompt the user) is the gateway's own resolution order exactly, verified member-for-member | **(a) SATISFIED** — with the deprecation recorded as the forward-looking fact it is: the flag's retirement is an operator-timed future change, not this one's scope |
| Resource parameter (MUST, clients, `index.md`) | MCP clients send `resource` (RFC 8707) in authorization and token requests, always | The AS-side twin is what this walk can score, and it is stricter than the client MUST: `resource` is *required* at both endpoints and at refresh, `invalid_target` otherwise (M4; `gateway/authorize.py:311-373`; `gateway/token.py:412-414, 588-590`) — verbatim-unchanged across all three revisions | **(a) SATISFIED** |
| Access token usage (MUST/MUST NOT, clients, `index.md`) | `Authorization: Bearer` on every request; tokens never in the URI query string | The issued tokens are Bearer (`gateway/token.py:324`) and exist only in JSON bodies served no-store; the harness's presentation duty is its own, and the tokens the gateway hands it are shaped for exactly that duty — verbatim-unchanged, and the load-bearing half of D6's client-side precondition (see Part 5) | **(a) SATISFIED** |
| Token handling (MUST, servers, `index.md` + `security-considerations.md`) | The MCP server validates tokens and their audience (RFC 8707 §2) | The MCP server of this deployment is **Core** behind the router; its audience check is the configured marker (M14) — per-resource audience validation does not exist on Core's MCP paths, which is the priced RES-7 record (T1-12's cross-kind widening; OQ-4 names the Core-side fix). The gateway's own addressing discipline is placed and spec-honest about what Core enforces — verbatim-unchanged | **(a) PRICED** — Core's duty, priced at RES-7/OQ-4 |
| Token theft (SHOULD + MUST, `security-considerations.md`) | ASs issue short-lived access tokens; for public clients, ASs rotate refresh tokens (OAuth 2.1 §4.3.1) | Short access TTL in the M9 lattice; rotation default-on with denylist and the original absolute expiry (`gateway/token.py:679-726`) — verbatim-unchanged | **(a) SATISFIED** |
| Refresh tokens guidance (SHOULD NOT, RS-side; `index.md` — new in `2026-07-28`) | MCP servers (protected resources) SHOULD NOT include `offline_access` in `WWW-Authenticate` scope or Protected Resource Metadata `scopes_supported` — refresh tokens are not a resource requirement; the client-side MUSTs in the same section (confidentiality, `grant_types` metadata) are harness duties | Satisfied: the gateway's protected-resource documents carry `scopes_supported` empty or echoing the toolset restriction's operator-curated entry (`gateway/discovery.py:92-98, 115-124`), `offline_access` is never requested on any leg (M13 — the custody design's own rule), and the AS grants no scopes at all (`"scope": ""`) — the member the SHOULD NOT guards never carries the value it guards against | **(a) SATISFIED** |
| Communication security (MUST, `security-considerations.md`) | All AS endpoints over HTTPS; all redirect URIs `localhost` or HTTPS | Endpoints: violated as built and priced — the plain-http front door, RES-12/M18 (the local deployment's accepted transport residual). Redirect URIs: **the same unpriced gap as B-1** — no registration path enforces the scheme, so a non-loopback `http://` redirect registers and is served; this MUST is **verbatim on the current `2026-07-28` page** ("All redirect URIs **MUST** be either `localhost` or use HTTPS", re-verified word-for-word, unchanged in all three revisions), so the finding's basis is the current contract's, not an old text's. One change closes both sources (RFC 9700 §2.6 and this MUST) | **(a) PRICED** for the endpoints (RES-12) + **(b) ADDS SCOPE — B-3/B-1, MEDIUM** for the redirect URIs |
| Authorization code protection (MUST, clients, `security-considerations.md`) | MCP clients implement PKCE (OAuth 2.1 §7.5.2) with S256 when technically capable, and MUST verify PKCE support via AS metadata before proceeding — refusing where `code_challenge_methods_supported` is absent | Enforced of every client at allocation and redemption — the AS holds the pair's harder half (mandatory S256, embedded bindings, verifier check), and the member the client's verification MUST reads is present and non-empty (`gateway/discovery.py:69`) — the client-side verification duties are the harness's and cannot fail against this AS | **(a) SATISFIED** |
| Authorization response validation — `iss` emission (SHOULD, `index.md` — new in `2026-07-28`; the driver of the new Mix-Up Attacks sections in `security-considerations.md` and the best-practices tutorial) | MCP authorization servers SHOULD include the `iss` parameter (RFC 9207) in authorization responses, **including error responses**, with the stated intent to upgrade the SHOULD to MUST in a future revision | Satisfied as built, ahead of the stated upgrade: `iss` rides every authorization response the surface produces — the success redirect and every error redirected to a validated client redirect (`gateway/flow.py:454-466`; `gateway/authorize.py:162-168`; the "Authorization responses identify their issuer" requirement; M9, pinned 2026-10-30) — which is also RFC 9700 §2.1's own countermeasure, scored in Part 1 | **(a) SATISFIED** |
| Authorization response validation — `iss` advertisement (MUST, `index.md` — new in `2026-07-28`) | Authorization servers that include the `iss` parameter MUST advertise it by setting `authorization_response_iss_parameter_supported` to `true` in their metadata (RFC 9207 §2.3) | **Violated and unpriced as built — finding B-5** (the summary's (b)-class list): the gateway includes `iss` on every response but its AS metadata document carries no `authorization_response_iss_parameter_supported` member (`gateway/discovery.py:56-76`), so a conforming `2026-07-28` client that checks the metadata is told nothing about the emission — and the revision's mix-up machinery explicitly depends on honest servers advertising it. The remedy, the size, and the fact that the emission half already holds are priced in the B-5 row | **(b) ADDS SCOPE — B-5, SMALL** |
| Open redirection (MUST/MUST NOT/SHOULD, `security-considerations.md`) | Clients use registered redirect URIs; ASs validate exact redirect URIs against pre-registered values; clients SHOULD use and verify `state`; ASs MUST take precautions against redirecting to untrusted URIs, SHOULD auto-redirect only where they trust the URI, and MAY inform the user | Exact validation held (M3); the `state` tolerance is the delta's stated rule (D8 — the ecosystem's own SHOULD, not MUST, is why tolerating is conformant); the precautions/trust/inform triple is the pending delta's checkpoint (§4.11.2's twin) — all verbatim-unchanged across the revisions | **(a) SATISFIED** — the delta lands the two statement-shaped halves |
| CIMD security: redirect-hostname display (MUST, `security-considerations.md` — Localhost Redirect URI Risks) | "Authorization servers **MUST** clearly display the redirect URI hostname during authorization" | **Discharged by the pending delta, and said so explicitly:** the decision page names the registered `redirect_uri` in full — hostname *and* port, more than the MUST's letter — beside the client name and client id (the checkpoint requirement's naming scenario; the `redirect_uri` is the registration's own validated value). Two disclosed bounds, stated rather than folded away: (1) the page renders on **first attribution** — on approved repeat attributions no page exists at all (D5's deliberately-preserved zero-click), so the MUST's letter read as "every authorization" is met on the presentations that carry a decision and knowingly not on the zero-click repeats the confused-deputy MUST itself licenses through the approved-client registry; (2) the one attack hostname display cannot catch — the section's own localhost impersonation, where the attacker's redirect shares the legitimate registration's hostname and differs only in port — is exactly what the localhost-warning SHOULD (the next row) addresses. Verbatim-unchanged across the revisions, and reinforced on the current one by the tutorial's dedicated Localhost Redirect URI Impersonation section | **(a) SATISFIED** — landed by the pending delta, with both bounds disclosed |
| CIMD security: localhost warnings (SHOULD, `security-considerations.md` — Localhost Redirect URI Risks) | "Authorization servers **SHOULD** display additional warnings for `localhost`-only redirect URIs" | **Violated and unpriced — finding B-4** (the summary's (b)-class list): no localhost-specific warning exists as built or in the delta, and no residual prices this exact shape; the row's full boundary reasoning (the local-compromise precondition, RES-23's floor, the first-attribution display's bound) and the smallest satisfying change are priced there. Verbatim on the current page, reinforced by the tutorial's section naming these countermeasures "expected of authorization servers" | **(b) ADDS SCOPE — B-4, SMALL** |
| Confused deputy (MUST, `security-considerations.md`) | MCP proxy servers using static client IDs MUST obtain user consent for each dynamically registered client before forwarding to third-party authorization servers | **The architecture match is verified member-for-member** (static client at the IdP, dynamic registration of harnesses via CIMD/DCR, a live provider session standing in for the consent cookie), and the pending delta discharges the MUST: the per-(subject, client) approved-client registry checked before every mint on all three paths, the decision page naming the resolved client and the registered `redirect_uri`, the three audit events. **Two declared deviations, both verified as declared and reasoned, not accidental:** (1) no scope list on the page — the toolset consent branch's scopes are shown on the upstream AS's own consent screen the approve action continues to, and the short-circuits have no third-party scopes to show (D3); (2) the checkpoint sits *after* the identity leg, not before the third-party flow as the best-practices diagram draws it — the per-user registry cannot be consulted before the user is known, and D2's placement covers every mint path the earlier position would miss (both short-circuits never touch the third-party flow at all). Verbatim-unchanged across the revisions | **(a) SATISFIED** — landed by the pending delta, with the two deviations declared in the design and confirmed honest here |

### The security best practices document (`tutorials/security/security_best_practices.md`)

| Ref | Demands | The gateway as built | Verdict |
|---|---|---|---|
| Confused-deputy mitigation details (MUST) | Per-client consent storage (approved `client_id` per user, checked before forwarding); the consent page identifies the client by name, shows scopes and the registered `redirect_uri`, carries CSRF protection, prevents iframing; consent cookies `__Host-`-prefixed and set only after approval; exact `redirect_uri` matching; `state` generated securely, stored server-side only after approval, validated at the callback, single-use, short-lived | The delta's checkpoint against each member: the registry is server-side per (subject, client) (D4); the page names client name + client id + resource + `redirect_uri`, is CSRF-bound by the flow id (no cookies exist at all, so the `__Host-` cookie rules are satisfied vacuously and the no-cookie-before-approval rule by construction — the record exists from allocation but *authorizes nothing* until the act), frame-locked by the header family, and does not auto-continue; exact matching is M3; the `state`-as-flow-id binding is 128-bit CSPRNG, server-side, single-use (destroy on first use), TTL-bounded. The scopes member is the one declared deviation (above) — the whole section verbatim-unchanged on the current tutorial page | **(a) SATISFIED** — the delta, with the declared deviation |
| Token passthrough (MUST NOT) | MCP servers accept no tokens not issued for them and never pass tokens through to downstream APIs | The gateway is the AS, not a pass-through: the client's token is the gateway's own mint, the upstream credential is established per-user through Core's credential API, and no client token ever travels upstream (invariants 1/2; the credential-model requirement) — verbatim-unchanged | **(a) SATISFIED** |
| SSRF (client-side guidance, plus a new AS-facing subsection) | MCP clients fetching OAuth-related URLs consider SSRF (HTTPS enforcement, private-range blocking, redirect validation, DNS pinning) — and, new in `2026-07-28`, "SSRF Against Authorization Servers": the same mitigations "apply equally to authorization servers fetching client metadata documents" | The gateway's one fetch-what-a-caller-names surface exceeds the guidance, and the new AS-facing subsection names exactly the control set it already carries: the CIMD fetch is HTTPS-only, origin-allowlisted, redirect-refusing, all-record IP-range-checked with connection pinning, size-capped, timed, cached, and capacity-limited (M7; `gateway/cimd.py:134-271`) — the tutorial caught up to the gateway, not the reverse | **(a) SATISFIED** |
| State handle hijacking (MUST/SHOULD — replaces the pre-`2026-07-28` session-hijacking section; MCP is stateless at this revision, no protocol sessions) | MCP servers MUST verify all inbound requests, MUST NOT treat possession of a state handle as authentication, SHOULD use secure non-deterministic handles, and SHOULD bind handles server-side to the authenticated user (the old session-ID material moved to the `2025-11-25` page) | The MCP-server role is Core's behind the router; the gateway adds no session or handle layer — every gateway-surface request is validated on its own credential or binding, and the flow id (the closest thing to a handle the gateway mints) is a single-use TTL-bounded binding that *authorizes nothing* until the user's act — a shape the MUST NOT's own rule is satisfied by ahead of the check | **(c) N/A** — the gateway is the AS; the data path's handle duties are Core's |
| OAuth authorization URL validation (client-side MUSTs) | MCP clients validate authorization URLs (reject dangerous schemes, no shell opening, CSP) | A harness-side duty; the gateway's own outbound twin is held — every endpoint the identity leg calls is discovery-validated or operator-configured, origin-bound, HTTPS-or-override, redirect-refusing (M26/M30) | **(c) N/A** — client-side; the gateway's own leg exceeds the analogous bar |
| Scope minimization (guidance) | Progressive least-privilege scopes; minimal initial sets; precise challenges | The gateway has no scope surface to minimize: it grants no scopes at all (`"scope": ""` — the honest empty set), and its protected-resource documents echo only the operator-restriction-pinned entries or nothing (`gateway/discovery.py:92-98, 115-124`) | **(c) N/A** — no scopes are granted or advertised beyond the operator's own curation |
| Local MCP server compromise / stdio security (client-side) | One-click local-server consent, command display, sandboxing | Harness-side duties; the gateway serves no local servers and no stdio transport | **(c) N/A** |
| Local Server Security tutorial (new page, `tutorials/security/local-server-security.md`) | Practical defaults for running MCP servers on one's own machine — provenance, version pinning, tool-definition distrust, process isolation, per-server credentials, filesystem and egress limits, fleet management; references SEP-1024 (client consent requirements for local installs) | Scored honestly: the page's entire audience is users, IT administrators, and harness hosts — the threat model is *your machine*, an ordinary child process with the user's privileges; every recommendation addresses the local-server operator or the client, and none addresses an OAuth authorization server. The one tangential touch — "prefer the remote version where one exists", a server that runs no code on the user's machine and uses the protocol's authorization flow — describes the deployment shape this gateway exists to serve, not a duty on it | **(c) N/A** — informational for a server-side AS; no AS-facing duty exists on the page |

**The note this part owes the owner (recorded, not acted on):** the design's Context
cites the MCP security best practices document's "current revision `2025-11-25`", and
this report's first correction pass repeated that reading — the versioning page states
the current revision is `2026-07-28`. The design and delta files are outside this
report's edit scope; the stale citation is reported to the coordinator for the owner's
next authoring pass. No D-decision and no delta-spec citation is falsified by the
current text: every statement the design rests on (the Bearer mandate and DPoP silence
behind D6, the confused-deputy MUST and consent-UI requirements behind D1/D3, the
client `state` SHOULD behind D8, the CIMD statements behind the registration surface)
is verbatim on the current pages — the one substantive delta between the revisions on
this surface is the `iss` machinery, and its AS-facing halves are scored above (one
satisfied as built, one priced as B-5).



## Part 5 — OQ-5 closed: the harness ecosystem's DPoP support, re-verified with sources

The authoring session could not re-verify this (the web-search facility was unavailable).
This pass had the web tools available with one exception: **WebSearch was refused
(`search_unauthorized`)**, so the verification ran through direct page fetches and GitHub
code search (`gh search code` / `gh api` on public repositories) — which reached primary
sources the search facility would only have summarized.

**What was verified, and where it rests:**

1. **The MCP authorization specification still mandates Bearer and still does not mention
   DPoP — verified in the `2025-06-18` and `2025-11-25` texts and re-verified on the
   current `2026-07-28` revision's pages, each fetched in full this pass**: "MCP client
   **MUST** use the Authorization request header field …
   `Authorization: Bearer <access-token>`" (`index.md`, Access Token Usage — verbatim),
   and DPoP appears nowhere in any of the three texts or the best-practices tutorial.
   The design's Context claim on this point **stands, re-verified against the current
   revision**.
2. **The MCP security best practices document does not mention DPoP** — fetched in full;
   no occurrence. Also re-verified.
3. **NEW FACT — the client-side precondition has moved since the design was authored.**
   The official MCP **TypeScript SDK has landed opt-in DPoP client support** (RFC 9449 /
   SEP-1932): `modelcontextprotocol/typescript-sdk`, `packages/client/src/client/dpop.ts`
   and the `OAuthClientProvider.dpop()` opt-in, merged via PR #2629 (its changelog: "Add
   DPoP (RFC 9449 / SEP-1932) sender-constrained access token support to the client";
   tokens the AS issued as Bearer are still presented as Bearer, and DPoP-bound tokens are
   presented as `Authorization: DPoP` with a per-request proof). The **Python SDK has
   not**: its conformance expected-failures file states "the SDK's OAuth client does not
   implement DPoP proofs", with the feature on its roadmap. And an **experimental DPoP
   profile for MCP exists** in `modelcontextprotocol/ext-auth`
   (`specification/experimental/dpop.mdx`, on the unmerged branch
   `paulc/sep3392-4-dpop-experimental`): an OPTIONAL extension requiring, when supported,
   `dpop_signing_alg_values_supported` in AS metadata and RFC 9449 proof validation at
   the resource server — not adopted into the specification at any revision, the
   current `2026-07-28` text included.
4. **What could not be verified:** whether the two field-proven flagship harnesses (the
   CLI and IDE shapes) actually enable DPoP. Their public documentation was not reachable
   this session (the vendor doc pages returned 404/redirect-dead-ends), and the TS SDK's
   support is opt-in at the provider level — a harness built on the SDK must affirmatively
   implement `dpop()`, so SDK support does not imply harness enablement.

**The effect on D6's verdict: none; the effect on D6's record: one narrowing.** The
deferral stands on the two-sided precondition, whose **resource-server half is decisive
and unchanged**: the resource server of gateway tokens is Core, whose identity-provider
entry validates bearer-style with no RFC 9449 proof validation — an AS-side-only DPoP
adoption remains incoherent regardless of any client's capability. But the design's
statement that the client side "cannot bind today" is now stale at the margin: the
reference SDK can bind (opt-in), and an extension specifying the metadata exists in
experimental draft. The recommendation this report adds to the owner's decision surface
(not as scope, as a record-keeping fact): when D6's threat-model entry lands, its
precondition's client-side leg should be worded against today's state — "the extension is
experimental and unadopted; the flagship harnesses' enablement is unverified; the
reference TypeScript SDK carries opt-in support" — rather than "nowhere in the
ecosystem", so the re-open trigger fires on the right evidence when the RS side (the E1
line) moves. The OQ-5 gap itself is **closed**: the disposition now rests on verified
primary sources, not on unavailability.

## Part 6 — The D10 annex, verified: agreements, completions, and the four misses

The design's annex (end of D10) lists clearly-held, clearly-violated, and adjacent items
as inputs for this walk to verify rather than inherit. Every claim was re-derived from
the code and sources above.

**Annex claims verified as stated (no disagreement):**

- *Clearly held* — PKCE mandatory with S256 the only method and the downgrade guard
  structural (verified: `gateway/authorize.py:236-242`, `gateway/token.py:400-407,
  437-444`, `gateway/codes.py:93-103`); exact-match redirect validation with the
  loopback-port exception keyed on the registered entry (M3; `gateway/cimd.py:573-599`);
  resource indicators and audience restriction AS-side (M4/M9); rotation + denylist for
  public-client refresh tokens, which is §2.2.2's held alternative branch (M9;
  `gateway/token.py:679-726`); AS metadata (the flat document); single-use short-lived
  codes (the replay cache and the 5-minute lattice); RFC 9207 `iss` on authorization
  responses (`gateway/flow.py:454-466`, the spec requirement); the clickjacking controls
  on the page surface (M8, §4.16); errors answered in place until the redirect target is
  validated (§4.11.2's guard); no implicit, no ROPC. **All verified.**
- *Clearly violated and already priced* — all-endpoints-HTTPS (RES-12, M18 named and
  deployment-owned); the sender-constraining SHOULD (D6's deferral with its precondition,
  now narrowed per Part 5 but standing); asymmetric client authentication on the identity
  leg (§2.5's RECOMMENDED — the leg's secret is symmetric, M28's owner ruling, blast
  radius bounded at T4-9). **All verified as priced, none unpriced.**
- *Adjacent, ruled by this walk* — §4.12's redirect-status guidance: **ruled N/A**
  (only 302s answering GETs exist; the method-preserving credential-POST redirect shape
  is never produced). §4.14.2's inactivity-expiry SHOULD: **ruled satisfied in substance
  by a different mechanism** (the non-sliding absolute expiry, startup-bounded by the
  operator-declared session bound, with provider-session death ending disused refresh —
  the concern's substance met, the mechanism honestly different). Both annex
  dispositions confirmed.

**The annex's four misses — this report's findings, stated as findings:**

1. **RFC 9700 §2.6's redirect-URI scheme MUST NOT (and the MCP authorization spec's own
   redirect-URI MUST) is violated and unpriced** — finding B-1/B-3, Part 1 and Part 4.
   The annex's "clearly violated" list names the transport leg of §2.6 (all-endpoints
   HTTPS) but not its redirect-URI leg; no residual, spec rule, or test prices it. A
   non-loopback plain-`http` redirect URI is registerable today at every resolution path.
   **Basis on the current `2026-07-28` revision: verbatim, both sources — strengthened,
   not weakened.**
2. **RFC 9700 §4.2.4's revoke-on-double-redemption SHOULD is violated and unpriced** —
   finding B-2, Part 2. The annex does not surface it and neither does the model.
   **Basis: RFC 9700-sourced, untouched by the MCP revision history — unchanged.**
3. **The MCP authorization spec's localhost-warning SHOULD is violated and unpriced** —
   finding B-4, Part 4. The annex did not walk the revision's CIMD-security display
   statements; nothing prices the missing warning, though the boundary note in B-4's
   row gives the owner honest ground to rule it deferred rather than built.
   **Basis on `2026-07-28`: verbatim, reinforced by the tutorial's dedicated
   Localhost Redirect URI Impersonation section.**
4. **The `2026-07-28` revision's `authorization_response_iss_parameter_supported`
   advertisement MUST is violated and unpriced** — finding B-5, Part 4: the gateway
   emits `iss` on every response and its metadata never says so. This miss is
   attributable to the source-currency defect the owner caught — the annex, the review,
   and this report's first correction all anchored on `2025-11-25` as "current" — and
   it is the one *substantive* AS-facing delta the restructuring added to this surface.
   **Basis: new in the current revision; the SHOULD it sits beside is satisfied as
   built.**

None of the four falsifies a design claim (the annex is inputs, not verdicts, by its
own words); all are exactly the class of row the re-judge exists to surface, and all
are priced above for the owner's call.

**One record-keeping disagreement with the design's text (not its verdict):** D6's
Context states the ecosystem's client side "cannot bind today" and that DPoP appears
nowhere but in the two verified documents — the documents part is re-verified true, the
ecosystem part is now stale at the margin (Part 5, item 3). The deferral verdict is
untouched; the wording of the record that lands in the threat model should carry the
current state.

**The verdict table this report owes D10's method, in its vocabulary — a partition of
the 98 rows, each row in exactly one bucket (the communication-security row's two
MUSTs split its two halves across two buckets, the one declared exception):**

- ***Already satisfied, as built* — 55 rows:** every (a) SATISFIED row that exists in
  the code or the synced spec today (Parts 1–4), including the CIMD SHOULD row, the DCR
  MAY row, the current revision's `iss`-emission SHOULD, and its refresh-tokens
  `offline_access` SHOULD NOT.
- ***Landed by this change* — 9 rows:** the §2.6 CORS-posture row (D9's rule and pin),
  §4.11.2's three rows (the dynamic-registration precautions, the
  authenticate-before-redirect reading, the trust/inform pair), the confused-deputy
  MUST and its best-practices mitigation details, the Part 4 open-redirection row's two
  statement-shaped halves (the `state` rule, the trust/inform twin — its exact-match
  half is as built), the Part 3 `auth_time` strip, and the Part 4 redirect-hostname
  display MUST. All are in the pending delta.
- ***Deferred with a named roadmap home* — 2 rows:** §2.2.1 and its §4.10 twin, the
  sender-constraining SHOULD (D6, precondition recorded and narrowed by Part 5). If the
  owner **declines** B-1/B-2/B-3/B-4/B-5, those five rows join this bucket and must be
  priced as residuals rather than left unrecorded — the summary prices them precisely
  so that either ruling lands cleanly.
- ***Accepted with reasoning* — 6 rows:** §2.3 (RS-side audience refusal is Core's,
  RES-7/OQ-4), §2.5 (the symmetric identity-leg secret, M28/RES-24), §2.6's TLS row
  (RES-12/RES-19), §4.13's proxy-link half (RES-19), Part 4's token-handling row
  (RES-7/OQ-4), and Part 4's communication-security row's endpoints half (RES-12).
- ***Not applicable* — 22 rows:** the (c) rows, each with its boundary reasoning.
- ***The owner's call, undecided* — 5 rows:** B-1, B-2, B-3, B-4, B-5.

The buckets sum: 55 + 9 + 2 + 6 + 22 + 5 = 99 verdicts over 98 rows, the difference
being the one declared split row — the same reconciliation the summary table carries.
The ledger that lands in `docs/threat-model.md` (D10's landing home) should carry the
per-row verdicts from Parts 1–4 and this mapping, with the undecided five resolved by
the owner's ruling into either *landed by this change* or *deferred with a named home*.


