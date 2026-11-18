# Proposal

## Why

The gateway is now the deployment's client-facing authorization server for two resource
kinds — and that surface has never been judged whole against the OAuth 2.0 Security Best
Current Practice. It was built requirement by requirement, each control placed for a named
threat, and the parts hold; but nobody has walked RFC 9700's recommendations down the AS
as built and said of each one: landed, deferred with a home, or accepted with reasoning.
The production roadmap fixes this stage (the owner-approved iteration plan, 2026-10-29)
as exactly that pass — **C2.5, AS security hardening (RFC 9700 alignment)** — and the
walk has one known open wound waiting at its start.

That wound is **T1-25**, the consent/attribution gap, recorded in the threat model as
deferred to this change with a named roadmap home — not accepted as a residual, not
mitigated where it was found. A client registered through CIMD on an operator-allowlisted
origin can craft an `/dial/authorize` link and induce a victim with a live IdP session to
click it: the identity leg completes silently (the gateway relays nothing
client-identifying into it, so the IdP cannot name the harness client to the user), the
code lands on the attacker's registered redirect, and the attacker redeems it with their
own verifier — holding a gateway token **as the victim**. The app kind's zero-page
short-circuit is the sharpest variant: the flow completes with no user-visible page of
any kind, so no surface ever names the client the mint is about to serve; the toolset
flow's stored-credential short-circuit is the same class's other member. PKCE, `state`,
and single-use codes bound the *interception* class, not this one — the attacker holds
every binding legitimately. The standing control is CIMD allowlist curation, an
operator-side discipline; the standard remedy is a consent page naming the resolved
client and the resource, a decision point the gateway itself owns.

Around that seed, the pass carries the rest of the roadmap's scope: sender-constrained
tokens (DPoP, RFC 9449) as the structural remedy for the bearer-token residual,
step-up/re-authentication, `state` strictness, and the CORS/back-channel posture
statement. The stage sits **after C2** (the `IDP_*` rename churned the IdP leg this pass
hardens, and the consent-page acceptance needs the local compose stack) and **before C3
and D3**, so the closing re-judge judges the final shape.

## What Changes

This change is a hardening pass whose normative shape the roadmap fixes: **every scope
item is dispositioned by the change itself — landed, deferred with a named home, or
accepted with reasoning** — and its acceptance carries as its first two rows the
checklist re-judge and the consent-page decision. Both rows now have their answers: the
re-judge is walked — 98 rows, every verdict grounded in a named code fact, spec
requirement, or model row (`evidence/rfc9700-rejudge-report.md`, its falsification
review `evidence/rejudge-report-review.md` holding the findings) — and the owner has
ruled on its five undecided findings (2026-11-07): B-1+B-3, B-2, and B-5 accepted as
scope, B-4 deferred with reasoning. The mechanisms are design.md's (D1–D10, and
D11–D14 for the accepted findings, landing in parallel); what follows is the scope as
decided.

- **The RFC 9700 checklist re-judge — walked; the ledger lands.** Every recommendation
  of RFC 9700, plus the OIDC and MCP authorization beside-sets, walked against the
  gateway's AS surface as built — both resource kinds, the client-facing endpoints
  (`/dial/authorize`, `/dial/token`, `/dial/revoke`, discovery, registration) and the
  identity leg behind them — each row verdicted in the four-value vocabulary and
  grounded in a named fact; the undecided five went to the owner and came back ruled
  (2026-11-07). What remains is the landing: the conformance-ledger section in
  `docs/threat-model.md` built from the report (its Part 6 partition the ledger's
  structure), the report's borderline rows re-verified against the built code, and the
  ruled dispositions recorded — the re-judge stays a first-class acceptance row, not a
  side artifact.
- **The redirect-URI scheme admission rule (B-1+B-3, owner-accepted 2026-11-07).** The
  walk's headline finding: a non-loopback plain-`http` redirect URI is registerable and
  usable at every client-resolution path today — a violated MUST NOT under two
  normative sources (RFC 9700 §2.6 and the MCP authorization specification's own
  redirect-URI MUST) that no residual priced. The rule: a registered redirect URI MUST
  be `https` or a loopback `http` URI (the RFC 8252 §7.3 shape the loopback-port
  exception already knows), enforced at all four admission sites — the DCR body check,
  the CIMD document's `redirect_uris` validation, a startup refusal for pre-registered
  configuration, and load-time validation of the durable DCR store, so records
  admitted before the rule (or planted inside the host/volume boundary) cannot keep a
  non-conforming URI usable. Loopback `http` is excepted, so no conforming fielded
  harness's UX changes.
- **Revoke-on-double-redemption (B-2, owner-accepted 2026-11-07).** A replayed
  authorization code is refused today, but the refresh token its first redemption
  minted stays live — RFC 9700 §4.2.4's revoke-on-replay SHOULD, unpriced until the
  walk. The remedy rides existing machinery only: the replay memo carries the minted
  refresh token's `jti`, and the detected replay's refusal path makes one call to the
  existing token denylist — no new surface, route, or page. The spec clause states the
  bound it actually buys, both partials disclosed: the already-minted access token
  stays unrevocable by design (bearer, short TTL), and a refresh token that has
  already rotated before the replay is detected survives (no code-to-successor mapping
  exists), the window bounded by the replay detection's timing and the non-sliding
  absolute expiry.
- **The localhost-redirect warning (B-4) — deferred with reasoning, no behavior change
  (owner ruling 2026-11-07).** The MCP authorization specification's current revision
  SHOULDs an additional warning for localhost-only redirect URIs; the attack shape it
  mitigates requires code execution on the victim's host — inside the accepted
  local-compromise floor — and the checkpoint's first-attribution page already
  displays the full redirect URI, port included, bounding the drive-by shape. The
  deferral's residual record lands in the threat model; nothing is built.
- **The `iss` advertisement member (B-5, owner-accepted 2026-11-07).** The current MCP
  revision (2026-07-28) MUSTs that an AS including the `iss` parameter advertise it:
  the discovery document's AS metadata gains
  `authorization_response_iss_parameter_supported: true`, making the existing emission
  (every authorization response, success and redirected error alike) discoverable in
  the metadata — a pure trueness fix: one member, one clause, one test, no behavior
  change anywhere else.
- **The consent/attribution checkpoint — BUILT (design.md D1–D5).** A gateway-owned
  decision point in the sign-in flow: a page naming the resolved client and the
  addressed resource, its approval recorded in a per-(subject, client) registry —
  asked once, never asked again — inserted after the identity leg and before every
  mint, on all three mint paths (the toolset flow's consent and stored-credential
  short-circuit paths and the app kind's zero-page short-circuit alike). T1-25 moves
  from deferred to mitigated; the standing control (CIMD allowlist curation) stays
  what it always was — the naming control — and the checkpoint becomes the
  attribution control.
- **Sender-constrained tokens (DPoP, RFC 9449) — deferred, with a named two-sided
  precondition (design.md D6).** The evaluation is done. The decisive ground is the
  resource-server side: the MCP authorization specification mandates Bearer
  presentation, and the resource server of gateway tokens is Core, whose
  identity-provider entry validates bearer-style with no RFC 9449 proof validation —
  the constraint would be void exactly where it must hold. The deferral's record
  carries the current ecosystem state the walk's re-verification found (an opt-in
  client-side implementation now exists — the client-side leg closer than first
  recorded; the verdict stands on the unchanged resource-server ground).
- **Step-up / re-authentication — not accepted on the client surface, nothing relayed
  (design.md D7).** The authorize surface accepts none of `max_age`/`prompt`, the
  identity leg relays nothing, and the mint's recency facts stay its own `iat`/`exp` —
  the no-ID-token-leg boundary stated rather than an OIDC mechanism scored against a
  non-OIDC surface. One hygiene rule lands with the verdict: a provider's `auth_time`
  claim is never copied verbatim into a gateway token (the same false-claim class
  `acr`'s strip exists for).
- **`state` strictness made explicit (design.md D8).** Today an authorization request
  with no client `state` is tolerated and the response echoes nothing; the spec never
  says so. The rule, decided: an absent `state` tolerated (refusing it would break
  clients that never send one; the CSRF-binding rides the flow id's own round-trip), a
  carried `state` echoed back unchanged, and an oversized value refused before a flow
  is allocated — stated in the authorization-requests requirement.
- **The CORS/back-channel posture statement (design.md D9).** The token endpoint is
  same-origin/back-channel only: no CORS headers are served on any AS-surface
  endpoint, and a browser frontend is not a supported client shape — the clients are
  harness processes exchanging codes and tokens on their own loopback redirects and
  back channels. Stated normatively in the spec and the operator reference, and pinned
  by a machine-checkable test, so the posture is a rule rather than an implementation
  accident — one future middleware line cannot silently open the surface.
- **Docs and ledger sync.** The threat model's T1-25 row flips from deferred to
  mitigated, its cross-reference corrected (the standing control it cites is the CIMD
  allowlist on M7's control set, not M24's apps surface); the conformance ledger lands
  from the report; the B-4 deferral's residual record and the DPoP precondition's
  current-state wording land with it; and any mitigation the change places is recorded
  as placed — a mitigation that exists only in prose is not landed.

The scope seed was the roadmap's list; the walk surfaced exactly the adjacent findings
the discipline exists for — B-1 through B-5 — and each is dispositioned by the owner's
ruling: three accepted into scope (B-1+B-3 as one change, B-2 and B-5 beside them),
one deferred with reasoning. None silently dropped.

## Capabilities

### New Capabilities

(none — the client-facing authorization-server surface is the existing sign-in
capability's; every requirement this change touches or adds lives in `mcp-signin`)

### Modified Capabilities

- `mcp-signin`: the AS-surface requirements change, each by a decided disposition —
  the checkpoint and its registry land as ADDED requirements (the consent/attribution
  checkpoint gating every mint on first attribution; the approved-client registry it
  consults, keyed per subject and client, failing safe on loss), and the
  owner-accepted findings land as amendments across the delta's registration,
  durability, and issued-tokens requirements (the
  redirect-URI scheme admission rule — `https` or loopback `http` only, all four
  admission sites; the revoke-on-double-redemption clause with its two disclosed
  partials; the discovery document's `iss`-advertisement member); the **authorization-requests** requirement gains the `state` rule
  (tolerated when absent, echoed unchanged when present, an oversized value refused);
  the **federation-flow** and **app-resource** requirements gain the checkpoint's
  decision point and first-attribution scenarios on all three mint paths; the
  **header-family** requirement gains `form-action 'self'` family-wide and the
  decision page's no-auto-continue rule; the **claim-copy** requirement gains the
  `auth_time` strip; the **public-endpoints** requirement ("Public endpoints are
  bounded against abuse") gains the CORS/back-channel posture with its pin; the
  **discovery** requirement gains the `authorization_response_iss_parameter_supported`
  advertisement member (B-5); and the **abuse/audit** requirements extend to the
  attribution events, under the same fixed-vocabulary discipline. Every requirement
  the re-judge leaves satisfied or priced stays verbatim — this change amends what its
  verdicts moved, and nothing else.

## Impact

Surfaces are named at file depth; the mechanisms are design.md's.

- `gateway/authorize.py` — the `/dial/authorize` entry: the `state` rule's bound (an
  oversized `state` refused before a flow is allocated) and the flow record's state
  storage, on both resource kinds' requests.
- `gateway/flow.py`, `gateway/federation.py` — the flow's stage order: the checkpoint
  inserted after the identity leg and before every mint on all three mint paths (the
  toolset consent and stored-credential short-circuit paths and the app kind's
  unconditional short-circuit), the consent branch's continuation stored on the flow
  record, and the new `POST /dial/consent` action on the browser-facing surface.
- `gateway/pages.py` — the decision page as a new page class through the one shared
  builder, inheriting the web-hardening header family (which gains `form-action
  'self'` family-wide) by construction; the registrant-supplied `client_name` it
  renders joins the interstitial's escaping discipline.
- `gateway/state.py` — the approved-client registry in the flow store's own class
  pattern, and the replay memo's `jti` field on the replay cache's entry (the minted
  refresh token's id, for the replay-revocation call).
- `gateway/token.py` — the detected replay's refusal path gains one call to the
  existing token denylist (B-2); the token endpoint's no-CORS posture stays pinned by
  the test battery.
- `gateway/tokens.py` — the `auth_time` claim joins the registry-claims strip (beside
  `acr`).
- `gateway/discovery.py` — the AS metadata document's fixed payload gains
  `authorization_response_iss_parameter_supported: true` (B-5): the trueness member
  advertising what the authorize flow already emits on every response.
- `gateway/routes.py`, `gateway/cimd.py`, `gateway/store.py` — the redirect-URI scheme
  admission rule at its sites: the DCR body check, the CIMD document's `redirect_uris`
  validation, and the durable DCR store's load-time validation.
- `gateway/settings.py` — the startup refusal for pre-registered `redirect_uris` that
  fail the admission rule (the settings validators' own pattern), the registry cap
  setting, and the `state` bound.
- `gateway/audit.py` — the attribution events' fixed-vocabulary reasons
  (`attribution_required`/`attribution_approved`/`attribution_refused`) and the
  oversized-state refusal's reason.
- `router/nginx.conf`, `scripts/probe_routing.py` — the `consent` segment joins the
  AS-surface alternation, with the routing probe battery's new rows.
- `docs/threat-model.md` — T1-25's flip to mitigated with the corrected M7
  cross-reference, the conformance ledger landed from the report, the B-4 deferral's
  residual record, the DPoP precondition's current-state wording, and any mitigation
  placed or residual accepted by this change, landed before implementation.
- `docs/gateway-configuration.md` — the operator-facing posture statements (the token
  endpoint's back-channel-only rule, the checkpoint's operator notes, the admission
  rule's pre-registered startup refusal), and `docs/production-roadmap.md`'s C2.5 row
  closing as its acceptance rows pass.
- `tests/` and the compose stack — unit coverage for every landed rule (the per-site
  admission tests, the replay-revokes-family test with its disclosed-partials
  assertions, the `state` bound, the CORS pin, the checkpoint and registry scenarios),
  and the checkpoint's live acceptance on the local compose stack (the same stack
  C2's acceptance used).
- No change to Core, its credential API, or the custody design.
