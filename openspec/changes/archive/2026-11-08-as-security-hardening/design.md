# Design

## Context

The gateway is the deployment's client-facing authorization server for two resource
kinds, and that surface has never been judged whole against the OAuth 2.0 Security Best
Current Practice. This change is that pass — **C2.5, AS security hardening (RFC 9700
alignment)** — and it opens on a wound the threat model has been carrying since C1.5
widened it: **T1-25**, the consent/attribution gap, recorded as *deferred to this
change* with a named roadmap home — not accepted as a residual, not mitigated where it
was found (`docs/threat-model.md:658`, the EP1 row; the disposition at
`docs/threat-model.md:1937`). A client registered through CIMD on an
operator-allowlisted origin can craft an `/dial/authorize` link and induce a victim
with a live IdP session to click it: the identity leg completes silently (the gateway
relays nothing client-identifying into it — `gateway/idp.py:311-341` builds the
provider redirect from the gateway's own client facts alone), the code lands on the
attacker's registered redirect, and the attacker redeems it with their own verifier —
a gateway token held **as the victim**. The app kind's zero-page short-circuit is the
sharpest variant — `gateway/federation.py:149-154` mints directly off the identity
leg with **no user-visible page of any kind** — and the toolset stored-credential
short-circuit (`gateway/federation.py:191-194`) is the same class's other member.
PKCE, `state`, and single-use codes bound the *interception* class, not this one: the
attacker holds every binding legitimately.

The flow's one existing page — the attribution interstitial (`gateway/flow.py:469-572`)
— is display-only and auto-continues in one second; it sits only on the toolset
consent branch and is skipped entirely by both short-circuits. Both short-circuits
mint through `_finish` (`gateway/federation.py:368-398`), which needs only the claim
snapshot the record already carries. The page surface itself is one builder
(`gateway/pages.py:91-118`) that stamps the web-hardening header family on every HTML
response by construction, and the interstitial already renders a registrant-supplied
`client_name` under the escaping discipline at `gateway/flow.py:505-518` — the
checkpoint this change decides on inherits both.

Around that seed, the roadmap's scope (`docs/production-roadmap.md`
§"C2.5 — AS security hardening"): sender-constrained tokens (DPoP, RFC 9449),
step-up/re-authentication, `state` strictness, the CORS/back-channel posture, and the
RFC 9700 checklist re-judge as the change's first acceptance row. What exists today,
grounded: the authorize entry parses exactly `response_type`, `client_id`,
`redirect_uri`, `resource`, `state`, and the PKCE pair — an absent `state` is
tolerated (`gateway/authorize.py:116-118`) and the response echoes it only when
present (`gateway/flow.py:462-466`); the spec never states the rule. The mint carries
no authentication-recency fact — `mint_access_token` sets `iss`/`aud`/`typ`/`jti`/
`iat`/`exp` and the copied claims (`gateway/tokens.py:202-226`) — and
`REGISTRY_CLAIMS` strips `acr` but not `auth_time` (`gateway/tokens.py:64-83`), so a
provider that minted `auth_time` into its access token would have it copied verbatim
into a gateway token. No CORS middleware is installed anywhere
(`gateway/app.py:58-66` builds the app with none), so no endpoint serves CORS headers
— a posture that is today an implementation accident, not a rule.

Two research facts anchor the decisions and are stated here because every later
section cites them. **First, the MCP ecosystem's own security guidance mandates the
consent checkpoint for exactly this architecture.** The MCP Security Best Practices
document (modelcontextprotocol.io, specification `2025-06-18` basic/
security_best_practices; re-verified verbatim on the current `2026-07-28`
revision) carries a *Confused Deputy
Problem* section whose attack flow is T1-25 member-for-member — a proxy server with a
static client ID at a third-party authorization server, dynamic registration of MCP
clients, a consent cookie that skips the third-party's screen, a crafted link with a
dynamically registered client and a malicious `redirect_uri`, and a code delivered to
the attacker — and its mitigation is normative: *MCP proxy servers **MUST** implement
per-client consent*, a proxy-owned consent page shown **before** the third-party
authorization flow, with a per-user registry of approved `client_id` values checked
before the flow forwards, a page that clearly identifies the requesting client,
displays the API and the registered `redirect_uri`, carries CSRF protection, and
prevents iframing. The gateway **is** that architecture: it is an MCP proxy fronting
DIAL (the third party is the identity provider; the consent cookie is the victim's
live IdP session; the dynamically registered clients are the harnesses). The same
document's authorization specification mandates `Authorization: Bearer` on every MCP
request (OAuth 2.1 §5.1.1) and names DPoP **nowhere** — neither in the authorization
specification nor in the security best practices. **Second, RFC 9700's own text**
(verified against rfc-editor.org this pass): §2.2.1 makes sender-constraining
(mTLS, DPoP) a SHOULD; §2.2.2/§4.14.2 require public-client refresh tokens to be
sender-constrained **or** use rotation (the gateway already holds the rotation half —
M9's rotation + denylist-by-`jti`); §4.11.2 requires the AS to authenticate the user
before redirecting (with the silent-authentication exception) and states the
checkpoint's own standards anchor — the AS *SHOULD only automatically redirect the
user agent if it trusts the redirection URI*, and where it does not, it *MAY inform
the user and rely on the user to make the correct decision*; §2.6 permits (never
requires) CORS at the token endpoint and forbids it at the authorization endpoint.

One known defect rides this change's docs task: T1-25's disposition row cites "M24's
CIMD allowlist" as the curation surface, but M24 is the apps front-door surface
(`docs/threat-model.md:1897`); the CIMD origin allowlist belongs to M7's control set
(`docs/threat-model.md:1881`). The threat-model delta (§7 below) corrects the
cross-reference.

The RFC 9700 re-judge this change carries as its first acceptance row **has run**
(2026-11-06, corrected twice on 2026-11-07 — once after its own review round,
once for the source-currency catch that fixed the current MCP revision to
`2026-07-28` and re-walked Part 4 against it): **98 rows walked** in
`evidence/rfc9700-rejudge-report.md`, its every item falsification-checked by
`evidence/rejudge-report-review.md`, and **the owner ruled on its five decision
rows the same day (2026-11-07)** — B-1+B-3, B-2, and B-5 accepted (decisions
D11, D12, D14), B-4 deferred with reasoning (D13), D6's record-wording accepted
(folded into D6). The decisions below carry the rulings folded in; D10 records
the walk's status, its annex's honest correction, and what remains for the tasks.

Publication discipline holds throughout: no real issuer, tenant, or org values, no
internal hostnames, no personal paths — `<>` placeholders where prose must name such
a thing. This is a planning artifact; nothing outside the change folder is touched by
the authoring pass.

## Goals / Non-Goals

**Goals:**

- **The consent/attribution checkpoint built** (D1–D5): a gateway-owned decision
  point naming the resolved client and the addressed resource, placed after the
  identity leg and before every mint, on all three mint paths — the toolset consent
  branch, the toolset stored-credential short-circuit, and the app kind's
  unconditional zero-page short-circuit — so no mint completes without a
  user-visible act attributing the flow to the client about to be served, on the
  *first* attribution of a client to that user; repeat attributions stay zero-click.
- **T1-25's disposition moved from deferred to mitigated**, with the mitigation
  landed in the delta spec (a mitigation that exists only in prose is not landed)
  and the threat model updated before implementation — including the M24→M7
  cross-reference correction.
- **DPoP evaluated, not promised** (D6): the bearer-token residual's structural
  remedy dispositioned against the actual client contract and the actual
  resource-server side, with the named precondition recorded if deferred.
- **Step-up dispositioned** (D7): what the authorize surface accepts, what the
  identity leg relays, what the mint records — decided and stated, never implicit in
  provider defaults.
- **`state` strictness explicit** (D8): tolerated or refused, with the reasoning,
  written into the authorization-requests requirement.
- **The CORS/back-channel posture a rule, not an accident** (D9): stated
  normatively and pinned by a test.
- **The RFC 9700 re-judge: method fixed (D10), walked, and owner-ruled
  (2026-11-07)** — the walk's findings folded in: the redirect-URI scheme
  admission rule at four sites (D11), revoke-on-double-redemption on the
  existing stores (D12), the localhost-warning deferral with reasoning (D13),
  the `iss` advertisement member (D14), and the ledger landed from the walk's
  report with its fully-reconciled partition.
- Every mitigation the gateway owns landed in the delta spec; every refusal the new
  surface adds audited in the fixed vocabulary.

**Non-Goals:**

- No new grant type, no new trust boundary, no new secret material, no change to
  Core, its credential API, the custody design, or the token lattice (TTLs,
  rotation, denylist, audience marking all unchanged).
- No client authentication added to the client-facing surface — the harnesses stay
  public PKCE clients; the checkpoint is the user's decision, not a client
  credential (the operator-bypass option is refused in D5 for exactly this reason).
- No ID-token leg, no `nonce`, no openid-scope semantics on the client-facing
  surface — the gateway remains an OAuth 2.x authorization server toward harnesses;
  this boundary is what D7's step-up refusal rests on.
- No per-toolset consent modeling, no scope presentation, no approval expiry
  workflow, no registration-management surface — the one decision the page carries
  is "may this client act for me here", and the registry's shape follows it (D4).
- No change to the CIMD/DCR registration surfaces' **controls** — the fetch
  discipline, the DCR flag's default, the resolution priority — which stay
  M7's and the flag's; the surfaces themselves gain exactly the redirect-URI
  scheme admission rule (D11, owner-accepted: a validation clause at the four
  admission sites, amending the client-registration and DCR-durability
  requirements) and the page's naming of their resolved facts — nothing else.
- No DPoP implementation, no mTLS client authentication on the client-facing
  surface — both only as evaluated dispositions (D6).
- No live run against the external tested provider in this pass beyond what the
  checkpoint's harness acceptance needs (the local compose stack is the acceptance
  environment; owner-dependent rows say so).

## Decisions

### D1 — The consent/attribution checkpoint is BUILT

The verdict the roadmap carries as open is decided: **built**. The reasoning is
three-legged, and each leg is a fact on record rather than a preference.

**The ecosystem mandates it for this architecture.** The MCP Security Best Practices
document's confused-deputy section (Context) describes T1-25 member-for-member and
its mitigation is a MUST: *MCP proxy servers MUST implement per-client consent* —
a proxy-owned consent page before the third-party authorization flow, with a
per-user approved-client registry checked before the flow forwards. The gateway is
that architecture precisely: static client at the identity provider, dynamic client
registration of harnesses (CIMD/DCR), and a live provider session standing in for
the consent cookie. Refusing the checkpoint would mean running a proxy shape the
ecosystem's own security guidance names as the vulnerable configuration, with the
vulnerability already priced in this repo's own threat model.

**The standards text licenses exactly this page.** RFC 9700 §4.11.2: the
authorization server SHOULD only automatically redirect the user agent if it trusts
the redirection URI, and where it does not, it MAY inform the user and rely on the
user to make the correct decision. The gateway's trust in a CIMD-resolved
redirect is origin-level at best — the operator allowlists an *origin*, and the
attacker's registration lives inside an allowlisted origin by the attack's own
precondition — so "trusts the redirection URI" does not hold for exactly the flows
the checkpoint exists for, and the inform-the-user option is the honest answer. The
zero-page short-circuits are the silent-authentication shape §4.11.2 names as the
exception; this change removes the gateway's silent mints from that exception's
unintended reach.

**The refusal's price is the wound itself.** T1-25 is not a theoretical row: a
victim with a live IdP session clicks one link and an attacker holds a bearer token
as that victim, refresh capability included (bounded by the session lattice and the
custody ciphertext's inertness without the custody key, but the access token alone
is enough for its TTL). The standing control — CIMD allowlist curation, M7's
surface — is an operator-side discipline that cannot distinguish a hostile
registration on an allowlisted origin from a benign one, and it is the *only*
control standing between the link and the mint today. Refusing the checkpoint
accepts that a one-click user decision is too expensive to interpose on a flow that
ends in a bearer credential, which is a price this design refuses to record as
reasonable when the decision is needed once per (user, client) — not per sign-in.

What bounds the attack is stated precisely, because it is also what the page must
be: the page is the user's decision point on the **first attribution of a flow to a
client they have not approved** — and the zero-page short-circuit is precisely the
path that skips every user-visible page, which is why the checkpoint's position
(D2) covers the short-circuits first and the consent branch's display interstitial
becomes the decision page's vehicle on first attribution. The refused shape, for
the record: T1-25 would have moved from "deferred" to "accepted with reasoning",
with the reasoning priced as "CIMD allowlist curation is argued to bound
registration abuse, and the drive-by mint class is accepted" — a residual whose
bounding control is an allowlist the attack's own precondition operates inside.
That is not an acceptance this design can defend; the checkpoint is built.

### D2 — Stage position: after the identity leg, before every mint, on all three mint paths

The decision point sits at the one place in the flow where both facts it needs
exist and no later stage can bypass it: **after `complete_identity_leg`** — the
provider's subject is verified, the DIAL authorization read has run, and the flow
record carries the resolved client (`client_id`, `client_name`,
`redirect_uri`) and the addressed resource (`resource`, `resource_kind`,
`toolset`) — **and before `_finish`** (`gateway/federation.py:368-398`), the one
function every mint path funnels through. Concretely, across
`_run_identity_leg` (`gateway/federation.py:115-176`) — the app short-circuit
and the consent branch's page position — and `_toolset_after_read`
(`gateway/federation.py:179-207`) — the stored-credential short-circuit:

- **The app kind's zero-page short-circuit** (`gateway/federation.py:149-154`):
  today `AppLegResult` mints immediately; under this change the registry is
  consulted first, and an unapproved (subject, client) renders the decision page
  where nothing rendered before; an approved one mints exactly as today.
- **The toolset stored-credential short-circuit**
  (`gateway/federation.py:191-194`): same insertion — the registry check runs
  before `_finish`; approved passes through untouched, unapproved gets the page.
- **The toolset consent branch**: the checkpoint rides the interstitial's existing
  position (after the read, before the upstream redirect). On first attribution
  the interstitial's display-only auto-continue is *replaced* by the decision page
  for that one presentation; once the client is approved, the flow keeps today's
  display interstitial verbatim — the notice and the decision are different jobs,
  and only the first attribution lacks the decision.

Placement alternatives, rejected with reasons. **Before the identity leg (at
`/dial/authorize`)** — the MCP best-practices diagram's own position — fails on a
fact of this gateway's flow: the per-user registry cannot be consulted there,
because the user is not yet known; the authorize entry is unauthenticated and the
subject arrives only with the provider's verified token. A page at the entry would
have to prompt *every* request (breaking zero-click for every repeat sign-in) or
key approvals on something other than the user (which is not a per-user registry
at all). **After the mint, as a first-use gate on the data path** — refuses
nothing the attack needs: the code and tokens are already issued and redeemable;
a first-use gate is a second authorization surface, not a decision point in the
flow. **On the consent branch only** — leaves both short-circuits as silent mints,
which is exactly the sharpest variant the threat row names.

One mechanical note the implementer needs (grounded, not prescriptive): the
consent branch's continuation target — the upstream authorization URL built by
`upstream_authorization` from the `ToolsetLegResult` — is transient today (only
`upstream_redirect_uri` is kept on the record, `gateway/flow.py:259`); the
decision point must store the built continuation on the record (the same
discipline `upstream_redirect_uri` already follows), because the approve action
(D3) continues the flow from the record alone. The identity-leg outcomes the
approve action needs are all record-resident already: the claim snapshot, the
client facts, and the provider's session refresh token (held until `_finish`
moves it to the pending hand-off entry) — the mint needs none of the identity
token itself, which the read paths may already have discarded
(`gateway/flow.py:247, 261-265`).

### D3 — The page and the approve action: what it names, how it is bound, how it is served

**What the page names.** Three facts, each with its honesty rule: the **resolved
client** — the registration's `client_name` where one exists (preferred, as the
interstitial already prefers it, `gateway/flow.py:495`), presented *as a name, not
a verified fact* (the interstitial's own discipline — the name is
registrant-supplied through CIMD or DCR); the **client id** beside it, always,
because it is the verifiable identifier; and the **addressed resource** — the
resource kind and name (`toolset`/`app` and the served name), stated in the same
plain vocabulary the pages already use. The MCP best-practices consent-UI
requirements add one fact this design adopts: the **registered `redirect_uri` the
code will be delivered to**, shown on the page — for the drive-by shape it is the
one fact a victim can check against expectation (an attacker's collector versus a
loopback listener), and it is the fact the false-name mis-use (DT-EP3-3 below)
cannot forge, because the redirect is the registration's own validated value. No
scope list is shown — a **declared deviation** from one member of the consent-UI
requirements the page otherwise adopts (the best-practices text has the
MCP-level page MUST "display the specific third-party API scopes being
requested"), and the recorded reason is *where those scopes are shown*, which
differs by path: on the toolset consent branch the flow does act on third-party
scopes — the upstream authorization request it relays carries the toolset's
advertised scopes (`gateway/flow.py:305-316`) — and the screen the user sees
them on is the upstream AS's own consent page, delivered by the very request
the approve action continues to, immediately after the decision; on both
short-circuit paths no third-party authorization request exists at all, so
there are no third-party scopes being requested to display. The client-facing
`scope` parameter is a separate fact and stays undisplayed for its own reason:
the gateway accepts and drops it (`gateway/authorize.py:14-19`) — the flow
never acts on it. The deviation is declared here so the re-judge walk (D10,
which covers the MCP security considerations) prices it as a chosen deviation
with its where-the-scopes-are-shown answer, not an accidental omission.

**Escaping and the header family.** The page is a new page class through the one
shared builder (`html_page`, `gateway/pages.py:111-118`), so the web-hardening
family — CSP `default-src 'none'` + `base-uri 'none'`, `frame-ancestors 'none'` +
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control:
no-store`, `nosniff`, explicit charset — is inherited by construction, and the
header-assertion tests extend to it mechanically. Every interpolated value passes
through the interstitial's existing escape (`gateway/flow.py:505-518`); the
`client_name` is registrant-supplied and the resource name is
caller-path-derived, and both are treated as hostile text in an HTML context. The
family gains one directive for this page class, stated family-wide (no other page
carries a form): **`form-action 'self'`** — the decision page carries the one
form the page surface has, and a directive that confines form submission to the
gateway's own origin closes the retargeting shape (an injected markup that
rewrote the form's action would submit to nowhere but the gateway) at the cost of
one clause on a policy every page already carries. The page is script-free like
its siblings: two buttons (approve / deny) in a plain form, no `meta refresh`
(the decision must *not* auto-continue — that is the whole difference between
this page and the interstitial it replaces for first attribution).

**The action and its binding.** The form posts to a new browser-facing route,
`POST /dial/consent`, carrying the flow id and the chosen action — nothing else;
the page's other facts are re-derived from the record at the action, never
round-tripped through the browser. The binding is the flow id itself: 128-bit
CSPRNG, server-side record, TTL-bounded (`gateway/state.py:160-216`) — the same
binding both callbacks already ride. The CSRF analysis is structural, and it is
why no token beyond the flow id is needed: the gateway **sets no cookies and has
no ambient browser authority of any kind**, so the classic cross-site POST (a
forger relying on credentials the browser attaches automatically) has nothing to
attach; and the flow id is *secret from the forger by construction* — the
attacker who crafted the `/dial/authorize` link never sees it, because it is
generated server-side and travels only in the 302 to the identity provider and
back on the provider's callback URL, both of which cross the victim's browser,
not the attacker's. A forger can only name a flow id they hold, and holding one
means either wire access (priced: that attacker is bounded by RES-12/RES-1, for
whom strictly cheaper attacks — reading `A3`/`A4` off the wire directly, T1-1 —
already exist) or being the party the decision belongs to. The MCP
best-practices' state/cookie discipline ("the consent cookie or session
containing the state value MUST NOT be set until after the user has approved")
is satisfied trivially and by construction: there is no cookie, and the
server-side state (the flow record) exists from allocation but *authorizes
nothing* until the user's action — the record's identity material is inert
without a mint, and the mint is what the decision gates.

**Semantics of the two actions.** *Deny* consumes the flow — the same
`_consume_refused_flow` discipline the read refusals carry
(`gateway/federation.py:251-264`): record destroyed, identity material dropped,
plain-language page, fixed-vocabulary audit reason (`attribution_refused`).
*Approve* records the attribution (D4), audits it
(`attribution_approved`), and continues the flow to the stage D2's position
deferred: `_finish` for both short-circuits, the stored continuation (the
upstream authorization URL) for the consent branch — which then serves the
display interstitial as today, so the consent branch's first-attribution sequence
is decision page → approve → display notice → upstream, and every later
attribution is notice → upstream unchanged. The approve action is
**single-use-per-flow**: the record carries the attribution decision, and a
re-presented approve (or a POST against a flow already advanced) lands on the
expired-flow page — the destroy-on-first-use discipline the callbacks carry,
applied to the decision point, so one approval cannot mint twice. An approve or
deny naming no live flow lands on the expired-flow page and allocates nothing,
like every other flow-id-resolved route (`gateway/federation.py:354-365`). The
route joins the shared limiter (the callbacks' own pattern,
`gateway/federation.py:100-101`) and answers no CORS headers (D9's posture is
surface-wide). The router's AS-surface alternation
(`router/nginx.conf:131-134`) gains the `consent` segment — one locked step with
the routing probe battery, the same lockstep D7 of the C2 change used for the
callback rotation; a half-routed deployment fails the probe, not a user.

### D4 — The per-user approval registry: in-memory, per (subject, client), hard-capped, fail-safe on loss

The registry the MCP best practices require — approved `client_id` values per
user — is a new store in `gateway/state.py`'s family: keyed **(subject,
client_id)**, consulted at D2's position, written only by the approve action.
Every shaping choice follows one direction: **loss of an approval must re-prompt,
never skip the page.**

- **Keying.** Per (subject, client), not per (subject, client, resource): the
  decision the page carries is "may this client act for me" — an attribution of
  the *client*, named on a resource — and the MCP best practices' own registry
  shape is per client. A per-resource keying would re-prompt per toolset for a
  trust decision the user has already made, buying prompt fatigue that degrades
  the one control this change exists to add. The page and the audit record name
  the resource the approval was granted on; a per-resource scoping is recorded
  as the open question it is (OQ-2) rather than built. The key has no issuer
  dimension, and that is safe by a stated chain, not by accident: `sub` values
  are not globally unique across issuers, but this deployment federates exactly
  one configured identity provider per process (the C2 ruling's one-provider
  exact pin), and a provider change requires a restart — which empties the
  in-memory registry — so no cross-issuer `sub` collision can ever be
  consulted. That safety is the in-memory custody's own, which is why the
  persistent-registry extension (OQ-1) carries the condition it carries.
- **Custody: process memory, single instance.** The flow store's own class
  (`gateway/state.py:160` — "a TTL and a hard cap that evicts oldest-first") is
  the pattern: no TTL (an approval is durable for the process's life), a hard
  cap with oldest-first eviction. The disclosed bound is honest about both
  directions: a restart forgets approvals (every user re-approves every client
  once — fail-safe, the same in-memory semantics the flow store and RES-15's
  single-instance record already carry), and eviction under cap pressure
  forgets the oldest first (re-prompt, never bypass). Persistence to a host
  volume is deliberately **not** built: a durable approval store is a new
  on-disk, tamper-surface-bearing asset (the DCR store's EP7 threat class, T7's
  rows) whose gain is one fewer click per restart — a bad trade at this stage,
  recorded as the extension it would be (OQ-1). No cookie carries the decision:
  the `__Host-` prefix the best-practices text requires is `Secure`-bound, and
  the plain-http front door (RES-12) cannot carry it — the cookie route is
  closed by the deployment's own transport residual, stated rather than worked
  around.
- **Allocation bound.** Entries cannot be allocated by an unauthenticated
  caller: the only write path is the approve action, which resolves a live flow
  whose identity leg completed — so entry creation is downstream of every bound
  the flow store already enforces (rate limits, flow cap, TTL). The cap bounds
  the registry's memory against the slowest legitimate growth there is (real
  users approving real clients); there is no flood path that does not first
  complete real sign-ins.

### D5 — Harness UX and the live acceptance: one click once, zero-click ever after, no operator bypass

**What a harness experiences.** The harness's programmatic surface is unchanged:
`/dial/authorize` still 302s to the identity provider, the callback still lands on
the gateway, and the final redirect still carries code + `iss` + the echoed
`state` to the harness's registered redirect. What changes is *one response in
the browser's sequence*: on first attribution, where the app-kind and
stored-credential flows today redirect straight back to the harness (and the
consent branch shows its one-second notice), the browser instead renders the
decision page. The harness itself is never consulted, never errors, and never
knows — it is waiting on its loopback listener either way, and the user who
clicked the harness's own sign-in link is the user the page addresses. **Silent
re-auth is preserved where it is legitimate**: a repeat sign-in to an approved
client hits the registry and runs exactly today's flow, zero pages on the
short-circuits; the harness-driven re-authentication loop (token expiry →
re-run) stays zero-click for every client the user has approved. The one-click
cost falls exactly once per (user, client), at the moment the attribution is
first claimed — which is the moment the attack would have ridden. First-ever
sign-in for every existing user of every existing harness gains one click; the
design records that cost and pays it deliberately.

**The refusal path's UX.** A denied flow dies in the browser with a plain page;
the harness's pending authorization waits and times out on its own, the same
death a user's closed tab produces today. No OAuth error reaches the harness
(there is no request to redirect an error to — the decision page is the
response), which matches the flow's existing refusal discipline: browser-facing
refusals are pages, never redirects to a target the client did not offer
(`gateway/federation.py:81-87`).

**No operator-policy bypass, refused with the reasoning.** The tempting shape —
an operator setting marking configured clients (the `pre_registered_clients`
block, `gateway/settings.py:393`) as pre-approved, so the flagship harnesses
never see the page — is refused. The reason is a priced mis-use in the model
already: T1-14 (pre-registered client impersonation, `docs/threat-model.md:649`)
— the client-facing surface has **no client authentication by design** (public
PKCE clients), so a crafted link can *wear* a pre-registered `client_id` with the
attacker's own loopback redirect, and an auto-trust keyed on the id would make
that link the one shape that skips the page while naming a name the user trusts.
The only safe bypass is one keyed on an authenticated client, and no such
authentication exists on this surface. The page's content is the partial answer
to the same mis-use: it shows the `redirect_uri` beside the trusted name, and a
victim who checks the one line the attacker cannot forge is not fooled by the
name — but the *design* answer is that no configured id buys a skip. An operator
who wants zero pages for a trusted harness gets it the honest way: the user
approves it once.

**The live acceptance (both harnesses, the local compose stack).** The
proposal's acceptance row: a built checkpoint proven on a real harness. Concretely,
on the same compose stack C2's acceptance used, with both field-proven harness
shapes — the flagship CLI harness via CIMD and the IDE harness via DCR: (a) a
first sign-in renders the decision page naming the resolved client, the
resource, and the redirect destination, and the approve click completes the flow
to the harness (the toolset consent branch completing through the upstream, the
stored-credential and app-kind short-circuits minting directly); (b) an
immediately repeated sign-in for the same (user, client) completes with zero
pages on the short-circuit paths — the zero-click property the harness UX
depends on, proven rather than asserted; (c) a denied flow consumes with the
refusal page and no code issued, and the harness's re-run after denial renders
the page again (the registry was not written); (d) the audit trail carries the
new fixed-vocabulary events in sequence (`attribution_required` →
`attribution_approved`/`attribution_refused` → the existing
`code_issued`/`credential_free_short_circuit` records). These rows are
owner-dependent in the C2 sense only where a real account is needed; the
compose-stack harnesses run them directly.

### D6 — DPoP (RFC 9449): deferred, with a named two-sided precondition

Evaluated against the actual client contract, the actual resource-server side,
and RFC 9449's own scope — and the verdict is **deferred with a named
precondition**, not adopted and not refused.

**The client side: the contract still forbids the presentation, and the ecosystem
has begun to move.** The MCP authorization specification — the contract every
conforming harness implements — still mandates the bearer presentation itself:
MCP clients **MUST** use `Authorization: Bearer` on every request (OAuth 2.1
§5.1.1, adopted normatively by the spec's "Access Token Usage" section), and
DPoP appears **nowhere** in the authorization specification or the security
best practices — re-verified against the `2025-06-18` text, the `2025-11-25`
revision, and the current `2026-07-28` revision, each fetched in full, by the
re-judge walk
(`evidence/rfc9700-rejudge-report.md` Part 5, its every item verified against
primary sources by `evidence/rejudge-report-review.md`). What has moved since
this design was authored: the official **TypeScript SDK has landed opt-in DPoP
client support** (RFC 9449 / SEP-1932, merged via PR #2629 —
`OAuthClientProvider.dpop()`, with tokens the AS issued as Bearer still
presented as Bearer and DPoP-bound tokens presented as `Authorization: DPoP`
with a per-request proof); the **Python SDK has not** (its conformance
expected-failures file: "the SDK's OAuth client does not implement DPoP
proofs"); and an **experimental DPoP profile for MCP exists**
(`modelcontextprotocol/ext-auth`'s experimental draft — unadopted, requiring
`dpop_signing_alg_values_supported` in AS metadata and RS-side proof validation
when supported). Unverified: whether the two field-proven flagship harnesses
enable DPoP — the TS SDK's support is opt-in at the provider level, so SDK
capability does not imply harness enablement, and their public documentation
was not reachable this pass. Sender-constraining minted tokens while the
contract mandates bearer presentation still buys zero realized gain (an adopted
DPoP mint would make every token unusable by every conforming harness — the
client base breaks), and an *optional* DPoP (mint `cnf` only when a client
presents proofs) implements a code path no verified client exercises: RFC
9449's own §6 carries real attack surface (proof replay windows, `jti`
tracking, key handling) that would be carried for a client population of zero
verified members.

**The resource-server side is not the gateway's to change.** The gateway token's
validator is **Core** — the MCP data path authenticates on Core's
identity-provider entry, and sender-constraining binds tokens at the point of
*use*, not the point of mint: DPoP adoption requires RFC 9449 proof validation
on every resource-server request, and Core has no such validation. Even a
DPoP-capable harness's token would be accepted bearer-style at Core or rejected
whole — either way the constraint is void exactly where it must hold. This is
the decisive structural fact: DPoP is not a decision this authorization server
can make alone, and an AS-side-only adoption is incoherent.

**What RFC 9700 actually demands, and what already holds.** §2.2.1's
sender-constraining is a SHOULD — the disposition is a deferral, not an
unpriced violation: the structural remedy is real and named, and the residual it
would remedy (the bearer class: stolen-token replay T1-3, marker-level audience
binding RES-7, no per-user kill of live access tokens RES-8) stays priced
exactly as the model prices it today — short access TTL (M9's lattice) and
Core's per-call DIAL authorization are the standing bounds, and the theft
channels (the plain-http wire, the harness stores) are RES-12/RES-23's own
records. The recommendation the RFC makes *mandatory* for this client shape is
already held: §2.2.2/§4.14.2 require public-client refresh tokens to be
sender-constrained **or** protected by rotation — the gateway's rotation +
denylist-by-`jti` (M9) is the second alternative, in place and spec-pinned.

**The named precondition, and the home.** DPoP adoption reopens when **both**
sides move: (a) the client side — the contract moves (a revision or adopted
extension requiring or permitting sender-constraining; today's candidate is the
experimental profile, unadopted) **and** the flagship harnesses verifiably
present RFC 9449 proofs — the TS SDK's opt-in support existing is capability,
not enablement, so the trigger fires on verified harness evidence, not on SDK
changelog entries; and (b) the resource-server side — Core's
token-validation path validates DPoP-bound tokens (the `cnf` claim and the
per-request proof) — the decisive half, unchanged by the client-side movement.
The natural home for (b) is the E1 line (the Core merge —
`docs/production-roadmap.md` §Evolution), where the resource-server
implementation is in this repo's family's own hands; the deferral is recorded in
the threat model as the bearer residual's named structural remedy with this
precondition (§7 below), so the roadmap's closing re-judge (its D3 stage —
distinct from this document's decision numbering) finds it priced rather than
forgotten. **Record-wording (owner-accepted, 2026-11-07):** the threat-model
entry's client-side leg is worded against today's state — the extension is
experimental and unadopted; the flagship harnesses' enablement is unverified;
the reference TypeScript SDK carries opt-in support — never "nowhere in the
ecosystem", so the re-open trigger fires on the right evidence when the RS side
(the E1 line) moves. The gateway-side prerequisite that *would* be this change's to build
(the mint's `cnf` emission, the proof validation at `/dial/token` and
`/dial/revoke`, the `jti` replay cache) is recorded in this decision as the
known shape, not built.

### D7 — Step-up / re-authentication: not accepted on the client surface, nothing relayed, the mint's recency facts stated — with one landed hygiene rule

Grounded in what the surface is: the gateway's client-facing AS is an **OAuth 2.x
server, not an OIDC provider** — no ID tokens, no `nonce`, no `openid` semantics
toward harness clients (`gateway/token.py` mints access and refresh tokens only,
and `nonce` is already in `REGISTRY_CLAIMS`, `gateway/tokens.py:64-83`).
`max_age`, `prompt=login`, and `auth_time` are OIDC *request and ID-token*
mechanisms (OIDC Core §3.1.2.1 and §2): `max_age` and `prompt` are authorization-
request parameters an OIDC relying party sends, and `auth_time` is the ID-token
claim that answers them. The gateway has neither leg toward clients, and no
fielded harness sends these parameters (they are not MCP-authorization-spec
parameters; the harnesses send `resource`, PKCE, `state` — exactly what
`gateway/authorize.py:112-118` reads).

**The authorize surface: does not accept them.** Unrecognized parameters are
ignored (today's behavior, the same class as `scope`'s accepted-and-dropped); the
surface does not act on `max_age` or `prompt`, and this decision is the recorded
reasoning so a from-spec reimplementation does not "helpfully" add them: acting
on them per OIDC's own contract would require an ID-token leg (returning
`auth_time`, honoring `prompt` semantics) that the gateway deliberately does not
have, and half-accepting them — relaying without being able to answer — would
advertise a guarantee the surface cannot make. No spec rule is added beyond the
non-acceptance being *stated* in this design and reflected in the re-judge's
verdict table (the authorization-requests requirement gains no new parameter
handling; it stays exactly as D8 amends it).

**The identity leg: relays nothing.** `authorization_url`
(`gateway/idp.py:311-341`) sends the gateway client's own facts and nothing
client-derived — no `max_age`, no `prompt`, on any flow. The provider's own
session policy (its SSO idle/max windows, `IDP_SSO_SESSION_MAX_SECONDS`'s
declared bound) governs authentication recency, unchanged. An **operator-policy
step-up** — a setting relaying a fixed `prompt=login` or `max_age` to the
provider on every sign-in — is *recorded, not built*: it is a real capability
with a real price (every sign-in becomes interactive, including every
short-circuit; provider support for the parameters is not universal across the
tested family's flavors), no deployment has asked for it, and the checkpoint
(D1) already bounds the attack a step-up would redundantly address (the
stale-session ride: the attacker's link can drive a live session, but it now
meets a decision page regardless of the session's age). Its precondition, if a
deployment ever wants it: a provider that honors the parameters and an owner
ruling that the interactivity price is wanted; it lands as its own small change
riding the identity-leg requirement. The standard OIDC surface C2 generalized to
defines the parameters; the classic tested flavor's support for them is not a
documented standard surface (its journeys are self-contained) — a fact that
moots only because the verdict is non-relay.

**The mint: records what it actually knows.** A minted access token carries its
own `iat`/`exp` (`gateway/tokens.py:216-225`) — the mint's recency, not the
provider's authentication recency, and that is the honest limit: the leg's
verified artifact is the provider's *access* token, which carries no
`auth_time`; the gateway never sees the provider's ID token, so it has no
authentication-time fact to record, and inventing one would be a false claim in
a signed artifact. **One hygiene rule lands from this analysis:** `auth_time`
joins `REGISTRY_CLAIMS` — today the copy is verbatim-minus-registry
(`gateway/tokens.py:132-154`), `acr` is already stripped for exactly this
reason, and a provider that minted `auth_time` into its access token would have
it copied verbatim into a gateway token, where it would state the *provider's*
authentication event as if it were a fact of the gateway's token — the same
false-claim class `acr`'s strip exists for. The delta spec's claim-copy
requirement gains the registry addition; the copied-claims test extends with it.

### D8 — `state`: tolerated when absent, echoed unchanged when present, bounded — stated as a rule

The rule, landed in the authorization-requests requirement: a client's `state`
is OPTIONAL — stored on the flow record at allocation
(`gateway/authorize.py:245-260`), echoed back **unchanged** on the final redirect
when present (`gateway/flow.py:462-466`), and simply absent from the response
when the request carried none (`gateway/authorize.py:116-118` — today's behavior,
now a stated rule rather than an unstated accident).

**Why tolerated rather than refused.** The CSRF-binding work `state` does for a
client is, on this surface, already done by things the gateway *requires*: PKCE
S256 is mandatory (the code is unexchangable by any party that did not hold the
verifier), the `resource` is required and validated, codes are single-use and
short-lived, and the flow id — an unguessable server-side binding — round-trips
every browser leg. RFC 9700 §2.1 accepts exactly this: clients MUST prevent CSRF
via PKCE, the OIDC `nonce`, *or* one-time-use CSRF tokens in `state` — PKCE is a
sufficient carrier, and §4.7.1 requires only that a client relying on PKCE
verify the AS supports it (the gateway's AS metadata and the mandatory challenge
do that loudly). The MCP authorization spec makes client `state` use a SHOULD,
not a MUST — a conforming client may legitimately never send one, and refusing
it would break conforming clients for zero security gain: the state the *gateway*
would be defending is its own flow binding, which the flow id already carries.
The refusing shape is recorded for honesty: it would buy strictness theater — a
400 for a class of clients the ecosystem permits — at the price of the client
base.

**One landed addition: the length bound.** The `state` is caller-chosen text
stored on an in-memory record and echoed on a redirect — its length is the
caller's choice, and every other caller-chosen length on this surface is bounded
(the audit facts at `gateway/audit.py:36-49`, the body cap at the token
endpoint). The rule: a `state` over **2048 bytes** is refused as `invalid_request`
with a fixed-vocabulary reason (`oversized_state`) — no fielded harness's state
is within an order of magnitude of it (OAuth libraries emit tens of bytes), and
the refusal bounds the record and the echo against a caller who would grow them.
The bound rides the flow-record allocation path, before the record exists.

### D9 — The CORS/back-channel posture: stated normatively, pinned by a test

The posture, as a rule: **the authorization-server surface serves no CORS
headers on any endpoint** — the browser-facing routes (`/dial/authorize`, the
callbacks, the consent route) and the back-channel endpoints (`/dial/token`,
`/dial/revoke`, discovery, registration) alike — and **a browser frontend is not
a supported client shape**: the clients are harness processes exchanging codes
and tokens on their own loopback redirects and back channels, and a
cross-origin browser page can neither read a token response nor drive the
authorize surface's redirects. Today this is true by omission — no CORS
middleware is installed anywhere (`gateway/app.py:58-66` builds the app with
none, and the surface adds none per-route) — which is an implementation
accident: one future `add_middleware(CORSMiddleware)` line, added for some
unrelated convenience, would silently open the token endpoint to browser
origins. The change makes the accident a rule in both directions of artifact:

- **Normatively**, in the delta spec's public-endpoints requirement ("Public
  endpoints are bounded against abuse"): the token (and
  revoke) endpoints are back-channel only — no `Access-Control-*` headers are
  served, no preflight is handled (an `OPTIONS` preflight against `/dial/token`
  receives the framework's 405), and a browser frontend is not a supported
  client. This is conformant with RFC 9700 §2.6, which *permits* CORS at the
  token endpoint (a MAY, never a requirement) and forbids it at the
  authorization endpoint — the gateway declines the MAY, surface-wide, and the
  spec says so.
- **As a pin**, in the repo's test battery: a test asserts that no response from
  the AS surface — token, revoke, authorize, the consent route, the discovery
  documents — carries any `Access-Control-*` header, so the posture cannot drift
  silently; the assertion joins the existing header-assertion family's
  discipline (M19's per-page-class tests are the pattern).
- **In the operator reference** (`docs/gateway-configuration.md`): one posture
  paragraph, so an operator integrating a web frontend against the gateway finds
  the refusal stated where they look, not discovered as a bug.

No behavior change backs the statement — the code already is the posture; the
change is the rule and the pin.

### D10 — The RFC 9700 re-judge: its method fixed here, its walk carried by the tasks

The design fixes HOW the re-judge runs. **Status (2026-11-07): the walk has
run** — before the owner pause, per the review ladder's order — producing
`evidence/rfc9700-rejudge-report.md` (the report corrected twice that day: once
after its own review round, once for the source-currency catch — the current
MCP protocol revision is `2026-07-28`, not the `2025-11-25` the report and this
design had both assumed; Part 4 was re-walked against the restructured
`2026-07-28` surface, adding four rows and one new finding, **98 rows walked**
in all) and that review's verdict,
`evidence/rejudge-report-review.md`: *trustworthy as the owner's decision input
as-is*, its findings folded into the corrected report. **The owner ruled on the
(b)-class rows the same day (2026-11-07): B-1+B-3 ACCEPTED (D11), B-2 ACCEPTED
(D12), B-4 DEFERRED with reasoning (D13), B-5 ACCEPTED (D14 — the
`2026-07-28` re-walk's finding), and D6's record-wording ACCEPTED (folded into
D6 above).** What remains for the tasks is no longer the walk itself: group
5's task becomes **landing the ledger** — the per-row verdicts and Part 6's
partition into `docs/threat-model.md`'s conformance-ledger section — and
**verifying the borderline rows against the built code**, because
implementation moves the satisfied-by-pending-delta rows to as-built and the
landing re-checks each against the diff, not against the report's reading of
the pre-change code.

- **The checklist source.** RFC 9700, whole: every MUST, MUST NOT, SHOULD,
  SHOULD NOT, and RECOMMENDED of its §2 (the operational recommendations) and §4
  (the attack mitigations), plus the MAYs that carry security posture (§2.6's
  CORS permission among them) — walked against the gateway's AS surface as
  built, both resource kinds, the client-facing endpoints (`/dial/authorize`,
  `/dial/token`, `/dial/revoke`, discovery, registration) and the identity leg
  behind them. Beside it, the OIDC recommendations the roadmap's scope names —
  the step-up parameter set (`max_age`, `prompt`, `auth_time`, D7's ruling) and
  the nonce/ID-token boundary — where the verdict records the no-ID-token-leg
  boundary rather than scoring an OIDC mechanism against a non-OIDC surface. And
  the MCP authorization specification's own security considerations (the
  ecosystem's contract the surface exists to satisfy), including the
  confused-deputy MUST D1 discharges.
- **The disposition vocabulary** — the proposal's own four, so the verdicts and
  the acceptance rows read as one: **already satisfied (named where)** / **landed
  by this change** / **deferred with a named roadmap home** / **accepted with
  reasoning (a priced residual)**. Adjacent findings the walk surfaces join the
  same discipline — dispositioned, never silently dropped.
- **Where verdicts land.** `docs/threat-model.md` gains a conformance-ledger
  section: one row per recommendation, its verdict, and where the satisfaction
  or the price lives (the M-number, the RES-number, the delta-spec requirement,
  or the roadmap home). The ledger is the re-judge acceptance row's artifact and
  the thing every later change and the roadmap's closing re-judge (D3) cite.

**The annex this design owes the task — clearly-held and clearly-violated items
my reading surfaced, as inputs for the walk to verify, not verdicts it inherits.**
Clearly already held: PKCE mandatory with S256 the only method, and the downgrade
guard structural (the challenge is embedded in the code's bindings and the
redemption validates the verifier against it — a verifier with no challenge
cannot exist, since allocation refuses the challenge-less request); exact-match
redirect validation with the loopback-port exception keyed on the registered
entry (M3); resource indicators and audience restriction (M4/M9); rotation +
denylist for public-client refresh tokens (M9 — §2.2.2's alternative branch);
AS metadata (the flat AS document); single-use short-lived codes; RFC 9207 `iss`
on authorization responses; the clickjacking controls on the page surface
(M8 — §4.16); errors answered in place until the redirect target is validated
(§4.11.2's open-redirector guard); no implicit, no ROPC (the two grants are code
and refresh). Clearly violated and already priced: all-endpoints-HTTPS (the
plain-http front door — RES-12, M18 named and deployment-owned); the
sender-constraining SHOULD (D6's deferral, precondition recorded); asymmetric
client authentication on the IdP leg (§2.5's RECOMMENDED — the leg's client
secret is symmetric, M28's owner ruling, blast radius bounded and accepted).
Adjacent, for the walk to rule: §4.12's redirect-status guidance (the gateway's
redirects are 302 answers to GETs; no 307 is issued anywhere, and the concern —
method-preserving redirects of credential-bearing requests — is a shape the
surface never produces); §4.14.2's "refresh tokens SHOULD expire if the client
has been inactive" (the gateway's refresh window is non-sliding and
absolute-expiry-bounded — M9 — which meets the concern's substance by a
different mechanism; the walk states which verdict that earns).

**The annex's correction, recorded honestly (the walk found the annex
incomplete).** The annex above was authored as inputs for the walk, and the
walk — its coverage, citations, and verdicts re-verified item by item by
`evidence/rejudge-report-review.md` — found it missed two findings and one
current-revision row: **B-1/B-3** (RFC 9700 §2.6's redirect-URI scheme
MUST NOT, and the MCP authorization specification's own redirect-URI MUST —
the annex's violated list named §2.6's transport leg but not its redirect-URI
leg) and **B-2** (RFC 9700 §4.2.4's revoke-on-double-redemption SHOULD —
nothing anywhere priced it), plus **B-4** (the MCP spec's localhost-warning
SHOULD — verbatim on the current `2026-07-28` revision, whose dedicated
Localhost Redirect URI Impersonation section reinforces it; a row the annex
could not have walked: the revision's CIMD-security display statements postdate
its sources). None of the annex's own
claims was falsified — every held, violated, and adjacent item was confirmed —
but the misses are exactly the class of row the walk exists to surface, and the
annex's claim to have named the "clearly-violated" set was wrong by two
findings. **The corrected record:** the report and its review are the walk's
artifact and the authoritative disposition source; the annex above stands as
the inputs it was, not as a verdict table. **Part 6's partition — as the
re-walked report states it, against the current `2026-07-28` revision —
replaces the annex as the disposition source for the threat-model conformance
ledger**: pre-ruling, 55 already satisfied as built / 9 landed by this change /
2 deferred with a named home / 6 accepted with reasoning / 22 not applicable /
5 the owner's call — 99 verdicts over 98 rows (the communication-security
row's two MUSTs split across two buckets, the one declared exception). The
five undecided rows are B-1, B-2, B-3, B-4, B-5 — and **all five are now
ruled** (2026-11-07): B-1, B-2, B-3, and B-5 join *landed by this change*
(D11, D12, D14 — the bucket grows to 13 rows), B-4 joins *deferred with a
named home* (D13 — 3 rows), leaving the final, fully-reconciled partition
**55 / 13 / 3 / 6 / 22 — nothing undecided**, still 99 over 98. (The
reconciliation, stated so the arithmetic is checkable: the earlier four-row
ruling and the B-5 ruling both fold into the re-walked partition; a partition
that moves only B-5 and leaves the other four "undecided" would contradict
D11–D13, which this document already carries.)

### D11 — The redirect-URI scheme admission rule (B-1+B-3, owner-ACCEPTED 2026-11-07)

The re-judge's headline finding, now the owner's ruling: **a registered
redirect URI MUST be `https`, or `http` on a loopback target** — the RFC 8252
§7.3 loopback shape the exact-match validator already knows
(`_loopback_target`, `gateway/cimd.py:529-570`). The finding it closes is real
and was unpriced anywhere: no registration path validates the scheme today —
DCR checks type/count/length only (`gateway/routes.py:336-357`), the CIMD
document's `redirect_uris` are accepted string-only
(`gateway/cimd.py:307-317`), pre-registered `redirect_uris` are a bare
`list[str]` with no validator (`gateway/settings.py:169-175`), and the
exact-match rule passes a registered `http://` URI untouched
(`gateway/cimd.py:588`) — so a non-loopback plain-`http` collector registers
and is served, and the authorization response (code and echoed `state`) is
delivered to it over a cleartext leg.

**The dual normative sourcing, verbatim-stable.** RFC 9700 §2.6 MUST NOT (no
`http` redirect URIs except native loopback clients) and the MCP authorization
specification's own Communication Security MUST — "All redirect URIs MUST be
either `localhost` or use HTTPS" — verified verbatim-unchanged across the
`2025-06-18` text, the `2025-11-25` revision, and the current `2026-07-28`
revision, so the rule's basis is
the current contract's, not the old text's. One change closes both sources.

**The four enforcement sites.** The rule is an *admission* rule — enforced
where a redirect URI enters the system, so every later use (the exact-match
validation, the authorize redirect, the code delivery) inherits it: (1) the
**DCR registration body check** (`gateway/routes.py:336-357`) — a refusal
clause naming the class; (2) the **CIMD document validation**
(`gateway/cimd.py:307-317`) — a document whose `redirect_uris` carry a
non-loopback `http` entry is refused whole, the same refuse-whole discipline
the discovery validation uses; (3) the **pre-registered settings** — a startup
refusal for configured `redirect_uris` violating the rule (the loud-refusal
family `gateway/settings.py` already uses for the IdP endpoint trio and the
issuer); and (4) the **durable DCR store's load path** — load-time validation
of stored records, because records admitted before the rule lands (or planted
per the store's own threat row, T7-1's class) would otherwise keep their
non-loopback `http` URIs usable after the rule lands: client resolution reads
the store without re-checking. The fourth site is the review's finding 3,
folded in by the ruling; the alternative it offered (a boundary ruling that
pre-rule records are the pre-publication cleanup backlog's) was not taken —
load-time validation is the complete answer, and a stored invalid record
refused loudly at load is diagnosable in a way a silently-served one is not.
The scope sentence names the boundary the review named: the exposure is
bounded by DCR's default-off (RES-5) and the host/volume boundary, and the
load-time refusal is the rule's own reach into that boundary, not a widening
of it.

**Harness compatibility, grounded.** Loopback `http` is excepted because the
fielded population lives there: the harnesses are native processes on loopback
listeners, the MCP authorization specification's own example CIMD document
lists loopback `http` redirect URIs, and non-loopback `http` is already
non-conforming for every client the ecosystem defines — so **no conforming
fielded harness's registration changes behavior**; the rule refuses exactly
the registrations the contract already forbids. The spec home: the
client-registration requirement gains the admission rule with its four-site
scenario set; the pre-registered startup refusal rides the
startup-enforced-bounds family. Mitigation number **M32** (§6 below).

### D12 — Revoke-on-double-redemption (B-2, owner-ACCEPTED 2026-11-07)

RFC 9700 §4.2.4 SHOULD: on a double redemption of an authorization code, the AS
revokes all tokens previously issued based on that code. As built, the replayed
redemption is refused by the replay cache (`gateway/token.py:452-458`) — but the
tokens the first redemption minted **stay live**: nothing connects the code's id
to the tokens it bought. The owner accepted the remedy, and the remedy is
deliberately the smallest one that satisfies the SHOULD:

- **The mechanism, on existing stores.** The replay claim-once memo
  (`runtime.replay.claim`, `gateway/token.py:452-458` — the code grant's
  claim-once check) **gains the minted refresh `jti` as a field**: at first
  redemption, the code grant records `code_id → refresh_jti`, held for the
  **code's own TTL** — the natural and sufficient bound, stated as such:
  every store family the memo can ride (the replay cache's own,
  `gateway/state.py`) is minutes-bounded to the code's life, and no replay
  can be *detected* after the code expires (the expiry refusal path never
  consults the memo); the revocation itself persists regardless — the
  denylist entry lives to the token's own `exp`, which is the retention that
  matters. On the
  detected replay — the refusal path where `claim` fails — the grant makes
  **one call** into the existing `TokenDenylist`
  (`gateway/state.py:360-396`): `revoke(refresh_jti, expires_at=…)`, the same
  call `/dial/revoke` makes. Both stores are in-memory and self-expiring — the
  denylist holds an entry only as long as the token it names could still be
  presented, and the memo only for its window — so the mechanism adds no new
  surface, route, page, or unbounded state.
- **Why the denial is immediate and certain.** The denylist is already
  consulted at every refresh grant (`gateway/token.py:581-582`), so the revoked
  `jti` refuses at its next presentation with the existing
  `invalid_grant`/rotation-detection vocabulary — no new refusal class, no new
  audit token beyond the replay refusal that already fires.

**The two disclosed partials, stated in the spec clause so it claims the bound
it actually buys.** (1) **The access token ages out unrevoked** — bearer,
short TTL (M9's standing bound), which the RFC's own SHOULD tolerates (its
letter says "all tokens", its scenario is the refresh family; the honest
clause says the refresh token is revoked and the access token is bounded by
its TTL). (2) **An already-rotated refresh token survives** — rotation mints a
fresh `jti` (`gateway/token.py:702-716`) and no code_id→successor mapping
exists, so denylisting the original leaves the live successor untouched; the
window is bounded by the replay detection's timing (the memo is consulted only
while it lives) and by the non-sliding absolute expiry (the successor's window
is the original token's own, never extended). Closing that half means the memo
tracks the rotation chain — the memo's one extension, recorded here as the
known shape, not built.

**Why SMALL, and what the threat actually is.** The replay window is minutes —
the code TTL is 5 minutes in the M9 lattice, and the double redemption the RFC
describes happens inside it; and the replay attacker is the **code-thief, not
the legitimate client** — the RFC's own scenario is a thief redeeming a stolen
code (the second redemption, whichever loses the race, is the detection). The
revocation turns the detection into a consequence: the thief's refresh
capability dies at the moment the theft is observed, instead of surviving to
the token's own expiry. Spec home: the **issued-tokens requirement's code
clause** ("Issued tokens are gateway-signed and audience-marked" — the
requirement whose code clause, "The authorization code MUST be single-use,
PKCE-bound, short-lived, with replay rejected," is the clause the rule
extends; the delta's declared amendment and its replay-revocation scenario
land in that block — not the public-endpoints requirement the CORS posture
lives in, the home an earlier draft of this decision named), with the
two partials stated as the clause's bound. Mitigation number **M33** (§6
below).

### D13 — The localhost-warning SHOULD (B-4): deferred with reasoning (owner ruling 2026-11-07)

The current MCP revision's CIMD security section: "Authorization servers
SHOULD display additional warnings for `localhost`-only redirect URIs." No
localhost-specific warning exists as built or in the pending delta, and no
residual priced the shape — the softest of the five (b)-class rows (B-5, the
trueness gap, is smaller but is no warning's rival), and the
owner ruled it **deferred with reasoning**, on grounds this decision records
verbatim in substance:

- **The attack the warning mitigates already sits inside the attacker model's
  priced classes.** The section's own localhost-impersonation attack — a
  hostile party pairing the *legitimate* client's metadata URL with its own
  loopback port, the port exception letting it match — requires code execution
  on the victim's host to harvest the code, and that position is the attacker
  model's **class 3** (the second workstation user or workstation malware —
  reads the harness's token store, the browser, or the loopback redirect) and
  **class 4** (the malicious or compromised harness): an attacker there holds
  strictly cheaper attacks — T1-3's stolen-token replay pricing (the harness
  token store is on that host) and RES-21 part i's own statement that a
  control adds nothing to an attacker who controls the machine it sits on —
  the same pricing logic DT-EP1-1 applies to the on-path attacker. A warning
  that mitigates an attack whose precondition already grants bigger prizes
  buys no realized gain. (Grounded on the model's own rows — classes 3/4,
  T1-3, RES-21(i) — because no residual in the model carries a
  "local-compromise floor" acceptance; an earlier draft of this reasoning
  attributed one to RES-23, whose record is the ungated harness token stores'
  availability bound, and the attribution is corrected here rather than
  carried into RES-25.)
- **The compensating bound exists.** The decision page displays the **full
  registered `redirect_uri` — port included** — on first attribution (D3's
  page-content rule, which also discharges the current revision's
  redirect-hostname-display MUST with room to spare), so the one presentation
  that carries a decision names the local destination for what it is; the
  drive-by shape is bounded by the display, and the local-execution shape is
  bounded by the same priced classes (the attacker model's 3/4 — a warning
  adds nothing to what that attacker already holds).
- **The re-open condition, named.** A **client population where loopback is
  anomalous** — deployments whose harness clients register non-loopback
  redirects as the norm, making a loopback presentation a signal worth a
  warning — re-opens the deferral. The deferral lands in the four-value
  vocabulary as **deferred with a named home**: the home is the threat-model
  residual (RES-25, §7 below) with this reasoning and the re-open trigger, and
  the roadmap's closing re-judge (D3) sees it there — priced, not forgotten.

### D14 — The `iss` advertisement (B-5, owner-ACCEPTED 2026-11-07; the `2026-07-28` revision)

The current MCP revision's Authorization Response Validation section — new in
the `2026-07-28` restructuring, and the driver of the revision's new Mix-Up
Attacks sections — makes RFC 9207 normative machinery: the AS SHOULD include
the `iss` parameter in authorization responses, error responses included
(with the stated intent to upgrade that SHOULD to MUST in a future revision),
and **MUST advertise the emission where it does**:
`authorization_response_iss_parameter_supported: true` in the AS metadata
(RFC 9207 §2.3). The re-judge's B-5 row: the SHOULD half is **satisfied as
built** — `iss` rides every authorization response, success and redirected
error alike (M9's placed record; `gateway/flow.py:454-466`,
`gateway/authorize.py:162-168`; the "Authorization responses identify their
issuer" requirement) — and the MUST half was **violated and unpriced**: the
AS metadata document carries no such member (`gateway/discovery.py:56-76`).

**The ruling: accepted — a pure trueness fix.** One metadata member
(`"authorization_response_iss_parameter_supported": true` in the discovery
document), one clause in the discovery requirement's advertisement enumeration
(the requirement already enumerates the advertised members; this joins them —
the delta spec's discovery amendment, landed in this same change), one
metadata-assertion test. No behavior change anywhere else: the emission
itself already happens on every response.

**Why the advertisement is normative, not cosmetic.** The metadata member set
is the discovery document's fixed contract: a conforming client reads the
AS's capabilities from that document and nowhere else, so an unadvertised
behavior is invisible to exactly the clients that would rely on it. The
revision's mix-up defense depends on honest servers advertising the member —
a client that records the issuer per request and checks the metadata is told
nothing about `iss` emission today, so the protection the gateway already
provides cannot be discovered, relied on, or checked. Advertising it makes an
existing protection part of the contract, which is the whole of what the
MUST asks.

**Why trivial, and the SIA's no-new-threat note.** No flow, state, route, or
page changes; the member states what the code already does. The SIA records
**no new threat row and no new mitigation number** (§6/§7 below): the member
narrows nothing (nothing that was served is refused) and adds nothing
attackable (a boolean served in the same shape as the document's neighboring
members, under the discovery surface's existing validation and the
metadata-assertion tests); it makes an existing protection *discoverable*,
which is a trueness gain, not an exposure.

## Security impact analysis

Per `docs/security-analysis.md` §4, this change is a **change on existing surfaces
that adds one route**: it inserts a gateway-owned decision point into the flow's
existing stages, adds the `POST /dial/consent` browser route and the decision page
class on surfaces that already exist (EP1's AS surface, EP3's page surface), and
adds one in-memory store (the approval registry, the flow store's own class). The
owner-ruled re-judge additions (D11, D12 — the scheme admission rule and the
replay revocation) add no route, page, or store at all: validation clauses at
existing admission sites, one field and one call on existing stores. It
adds no trust boundary, no grant type, and no secret material, so the touched
entry points carry delta tables (not complete re-enumeration), and the one new
route is enumerated completely within them.

### 1. Change description

*Business:* no mint completes without a user-visible act attributing the flow to
the client about to be served, on the first attribution of that client to that
user — the consent/attribution checkpoint (D1–D5), bounding T1-25. The AS
surface's outstanding standards questions are dispositioned: DPoP deferred with a
named two-sided precondition (D6); step-up not accepted on the client surface,
nothing relayed, the mint's recency facts stated, `auth_time` joined to the
registry blocklist (D7); `state` tolerance stated as a rule with a length bound
(D8); the CORS/back-channel posture stated normatively and pinned by a test (D9);
and the RFC 9700 re-judge walked, owner-ruled (2026-11-07), and folded in (D10's
correction): the redirect-URI scheme admission rule enforced at four sites
(D11), revoke-on-double-redemption on the existing replay memo and denylist
(D12), the localhost-warning SHOULD deferred with reasoning (D13), and the
`iss` advertisement — the `2026-07-28` revision's metadata member the
emission already satisfies (D14).

*Implementation shape:* a registry check at the one point every mint path
traverses — after `complete_identity_leg`, before `_finish`
(`gateway/federation.py:115-176, 368-398`) — consulting a per-(subject,
client_id) in-memory approval registry (hard cap, oldest-first eviction, the flow
store's class, `gateway/state.py:160-216`); an unapproved attribution renders a
new decision page through the one shared builder (so the web-hardening family,
plus a family-wide `form-action 'self'`, is inherited by construction), naming
the resolved client (registrant `client_name` presented as a name beside the
client id), the addressed resource, and the registered `redirect_uri`, all under
the interstitial's escape (`gateway/flow.py:505-518`); the page's form posts the
flow id and the chosen action to `POST /dial/consent` (a new browser-facing
route joining the shared limiter, resolving a live flow or landing on the
expired-flow page, consuming on deny, recording-and-continuing on approve,
single-use-per-flow); the router's AS-surface alternation gains the `consent`
segment in one lockstep with the probe battery; three fixed-vocabulary audit
events (`attribution_required`, `attribution_approved`,
`attribution_refused`) join the trail; the authorize entry gains the
`oversized_state` refusal (2048-byte bound) and nothing else — the tolerated
absent state becomes a stated rule; `REGISTRY_CLAIMS` gains `auth_time`; the
token-grant posture lands in the public-endpoints requirement's amendment ("Public
endpoints are bounded against abuse") with a pinning test
asserting no `Access-Control-*` header on any AS-surface response; the
registration surfaces gain the **redirect-URI scheme admission rule** at four
sites — the DCR body check, the CIMD document validation, the pre-registered
startup refusal, and the durable DCR store's load-time validation (D11) — and
the code grant gains the **replay-revocation mechanism**: the replay memo's
`code_id → refresh_jti` field and one `TokenDenylist.revoke` call on the
detected replay, both on existing in-memory, self-expiring stores (D12); the
threat model gains the RFC 9700 conformance ledger (landed from the walk's
report and its fully-reconciled partition), T1-25's new disposition, the M24→M7
cross-reference correction, and RES-25 (B-4's priced deferral). No change to
the identity leg's requests, the token lattice's TTLs or rotation semantics, the
custody design, or Core.

### 2. Impact level, with reasons

**Medium.** The sensitive assets involved are the mint's integrity (A3/A4 —
tokens issued to a client the user never attributed, exactly T1-25's stake) and
the user's provider session (A8, the attack's vehicle), and the change's
direction on both is *narrowing*: a control is interposed where none existed.
What keeps the level above low is the added exposure the control itself brings:
one new unauthenticated browser-facing route (the approve action — a POST that
advances flows and writes registry state), one new page class rendering
registrant-supplied text at the flow's most credential-adjacent moment (the
provider's code is on the page's own URL), and one new in-memory store consulted
on every mint — each a surface the review must falsify, none a trust boundary,
grant type, or credential. No new secret material exists anywhere in the change;
the DPoP, step-up, state, and CORS dispositions are statements about existing
surfaces (two of them pure documentation-and-test). The level sets the security
review gate's depth: a full-depth review of the new route, the page, and the
registry mechanics, with the falsification pass focused on the claim that the
checkpoint's own surfaces (DT-EP1-1, DT-EP3-1 through DT-EP3-3 below) are bounded
as designed.

**Re-checked after the owner-ruled additions (D11–D14): Medium stands.** The
additions' direction on exposure is *narrowing only* — the admission rule
refuses a whole class of redirect URIs at the boundary (a
reduce-attack-surface change on live registration surfaces, which is exactly
why its size was MEDIUM as implementation work while its security direction
is strictly a narrowing), and the replay revocation turns an existing refusal
into a revocation with no new surface, route, page, or unbounded state. What
the additions bring for the review to falsify is behavior change on the three
live admission paths (a stored DCR record now refused at load; a CIMD document
refused whole; a pre-registered startup refusal) — refusal behavior, on
existing surfaces, with no credential at stake in the refusal itself. The
level's reasoning above is otherwise unchanged, and the falsification focus
gains the two new mitigations' rows (DT-EP1-5, DT-EP1-6 below).

### 3. Invariant ruling table

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | **Preserved** | The upstream stage, the credential call, and the USER-level stamp are untouched; the checkpoint sits before the mint on the toolset consent branch's *upstream-ward* side only in position (it gates the flow, never the credential call's shape), and the short-circuits never read or transit a credential, unchanged |
| 2 | The upstream PKCE verifier never leaves Core | **Preserved** | The verifier is Core's, nulled on every public projection, untouched on every path; the checkpoint adds a browser page and a POST route, neither of which projects any upstream field — the page renders the *gateway's* flow facts only |
| 3 | Per-user credential isolation | **Preserved** | The approval registry is keyed (subject, client_id) — a per-user record by construction; the provider-side `sub` cross-checks at issuance and refresh are untouched; and the preservation is strengthened within the ruling: T1-25's cross-user mint (a token as the *victim* for the *attacker's* client) is exactly the isolation violation the checkpoint removes, on the drive-by shape |
| 4 | DIAL authorization applies to every toolset call | **Preserved** | The listing/app read and Core's per-call authorization are unchanged in existence and enforcement; the checkpoint is an *additional* gate before the mint, not a substitute for either — a user who approves a client still passes the DIAL authorization read, and a user who fails it never reaches a page (the read refusal consumes the flow first, `gateway/federation.py:210-248`) |
| 5 | No credential in logs, argv, or error messages | **Preserved, with the new surfaces named** | The decision page and its audit events carry non-credential facts only (client id, client name, redirect URI, resource, kind — the same fact class the trail already bounds at `gateway/audit.py:43-49`); the approve POST's parameters are the flow id and a fixed action token; no token, code, key, or secret reaches the page, the route, or the record it writes; the `oversized_state` refusal names the class, never the value |
| 6 | No hardcoded credentials in the repository | **Preserved** | No new setting, no new secret material, no committed value — the registry is runtime state, the page is committed markup with no secrets, the tests carry fixtures only |
| 7 | The signing key is IdP-grade secret material | **Preserved** | Key custody, publication, and rotation are untouched; the mint's inputs are unchanged (the checkpoint decides *whether* the mint runs, never what it signs); `REGISTRY_CLAIMS` gains `auth_time` — a copy-rule narrowing inside the mint, nothing about the key |

### 4. Delta threat tables, per touched entry point

EP5 (the server-to-server legs) and EP4 (the keys) are untouched — no delta
tables. EP6 (the router) gains one alternation segment under the existing
locked-routing discipline — no new behavior, no table. EP2 (the CIMD fetch) is
touched by D11's scheme check on the fetched document's `redirect_uris` (a
document carrying a non-loopback `http` entry refused whole — a validation
clause, no fetch-behavior change); the admission-class threat it serves is
tabled once, at EP1, with the other admission sites (DT-EP1-5) — no separate
EP2 row. The remaining two admission sites carry no tables of their own, their
homes declared here: the **pre-registered-settings check** is operator
configuration validated at startup — inside the trust boundary being
configured, its mis-use shape priced inside DT-EP1-5's row — and the **DCR
store's load path** is EP7's host/volume territory, where the planted-record
shape is T7-1's existing price (the load-time refusal narrows that row's
reach, noted with M32 in §7). EP1 and EP3 carry the change. Mis-use cases are
marked **[mis-use]**.

#### EP1 — the AS surface, the new consent route and the mint paths

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP1 (`POST /dial/consent`) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Forged approval advances an unattributed flow | A3/A4 (the mint the approval unleashes — a code and tokens delivered to the flow's registered redirect); A8 (the victim's session the flow rides) | I, Access | The attacker seeks the one thing the mint now requires: an approval recorded for a flow whose attribution the victim never made. Two shapes. **Cross-site POST:** the forger posts the approve action from a hostile page — but the gateway sets no cookies and holds no ambient browser authority, so the POST carries nothing the gateway trusts beyond its own parameters, and the flow id it must name is 128-bit CSPRNG, server-side-held, and never visible to a link-crafter (it crosses only the victim's browser, on the provider redirect and callback — the same binding M1's state round-trip gives both callbacks); a forged POST without a live flow id lands on the expired-flow page and allocates nothing. **On-path race:** an attacker reading the wire (the plain-http front door, RES-12) sees the provider callback URL carry the flow id and races the victim's click — bounded by the existing transport residual's own acceptance: that attacker already reads A3/A4 directly off the wire (T1-1, a strictly cheaper attack than racing a decision), so the checkpoint changes nothing about what that attacker holds — the checkpoint's declared scope is the drive-by shape (the link crafter with no wire access), which is T1-25's shape, and the on-path class keeps its existing price and re-open trigger (TLS-fronting, M18). The approve action's single-use-per-flow rule (D3) bounds a replayed approval to one mint, and a replayed POST against an advanced flow lands on the expired-flow page. |
| EP1 (`POST /dial/consent`; the registry) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Approval-registry flooding | A14 (the registry's memory; the process) | A | An unauthenticated caller tries to grow the registry directly. There is no direct write path: the only write is the approve action, which resolves a live flow whose identity leg completed — so every entry costs a full sign-in under the flow store's existing bounds (rate limits, flow cap, TTL — M6), and the registry's own hard cap with oldest-first eviction bounds the store against the slowest *legitimate* growth there is (real users approving real clients); eviction re-prompts (fail-safe), never bypasses. An attacker completing real sign-ins as themselves to grow the registry spends their own sign-ins for entries keyed to their own subject — no other user's approvals are writable; the cap's eviction is global with oldest-first ordering, so flood (or organic growth) can force another user's next sign-in to re-prompt once (fail-safe: a re-prompt, never a bypass). |
| EP1 (`/dial/authorize`) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Oversized `state` growth | A14 (the flow record's memory; the final redirect's size) | A | Pre-change, a caller-chosen `state` of any length is stored on an in-memory record and echoed on the redirect (`gateway/authorize.py:116-118`, `gateway/flow.py:462-466`) — the one caller-chosen length on the allocation path not bounded (the audit facts and the token body are). The 2048-byte refusal (D8) closes it; the delta is a narrowing, tabled so the walk's narrowing is visible, with the residual stated: a state at or under the bound is stored and echoed as before — bounded, not refused. |
| EP1 (the mint, both short-circuits — the checkpoint's absence exploited) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Drive-by client hijacks the flow via a zero-page short-circuit | A3 (a minted bearer token naming the victim's `sub`); A4; A8; A10 (the attacker's registration) | I, Access | T1-25 itself, re-priced: pre-change this row is the model's open deferred wound; post-change the drive-by shape meets the decision page on first attribution and the mint does not run without the user's act (D1, D2) — the row's disposition flips from deferred to mitigated (M31, §7). What the mitigation does *not* claim: the on-path shape (above), and the mis-named-registration shape (DT-EP3-3) — a page can be fooled by a name but not by the redirect URI it also shows. |
| EP1 (the registration admission sites — the DCR body check, the CIMD document check, the pre-registered settings, the DCR store load) | Interception → Eavesdropping | Non-loopback `http` redirect delivers the authorization response over a cleartext leg | A5 (the gateway's code, and the echoed client `state`) on the redirect leg to the registered target; A8 (the session the flow rides) | C | The B-1/B-3 grounding: no admission path validates a redirect URI's scheme as built (`gateway/routes.py:336-357`, `gateway/cimd.py:307-317`, `gateway/settings.py:169-175`), so a non-loopback plain-`http` collector registers and passes the exact-match rule untouched (`gateway/cimd.py:588`) — and the authorization response (the code and the echoed `state`) is delivered to it over a cleartext leg any on-path party reads. The read alone does not mint: the code is PKCE-bound to the client's verifier (M2), so an on-path reader without the verifier holds an unusable string — but the leg is the front door's own transport class (RES-12) extended one hop past it to a target the rule can refuse, and the chain closes where the reader also holds the verifier (a compromised-client shape — the attacker model's class 4, with T1-3's stolen-token pricing) or where the registrant is the drive-by attacker and the cleartext collector is the exfiltration channel riding a registration the contract already forbids. Closed by D11's admission rule (M32) — https or loopback-`http` only, at all four admission sites, so no such registration exists to deliver to; no new residual: the on-path class keeps RES-12's existing acceptance, and the loopback exception keeps the fielded harness population's own local-listener shape. |
| EP1 (E4, the code grant's replay handling) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Replayed code refused but its token family survives | A4 (the refresh token the first redemption minted); A3's session continuity | I, Access (beyond detection) | RFC 9700 §4.2.4's own scenario: a stolen code redeemed twice — one redemption succeeds, the other is the detection. As built the detection is answered (`gateway/token.py:452-458` refuses the replay) but consequence-free: the refresh token the first redemption minted stays live to its own expiry, so a thief's session outlives the moment its theft was observed. The shapes: the thief must hold the verifier too (PKCE — a compromised client or leaked pair, the attacker model's classes 3/4 with T1-3's pricing), or be the drive-by attacker whose own registration mints legitimately (T1-25's shape, for whom this is one more containment beside the checkpoint); the legitimate client losing the race to a thief is already alerted by the refusal. Closed by D12 (M33): the replay memo's `code_id → refresh_jti` field plus one `TokenDenylist.revoke` call at the detected replay — the thief's refresh capability dies at the observation, refusing at its next presentation through the denylist consult every refresh grant already makes (`gateway/token.py:581-582`). Two partials disclosed as the clause's bound: the access token ages out unrevoked (M9's standing TTL bound, which the SHOULD tolerates), and an already-rotated refresh successor survives (no code_id→successor map — bounded by the detection's timing and the non-sliding absolute expiry; the chain-tracking memo is the recorded extension). |

#### EP3 — the browser page surface, the new decision page

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP3 (the decision page) | Injection | Attribution/context injection into the decision page | A5 (the flow's continuation); A8 (the victim's session); the approval decision itself | I | Registrant-supplied text (`client_name` via CIMD or DCR) or caller-path-derived text (the resource name) rendered unescaped on the decision page executes in the victim's browser at the flow's most credential-adjacent URL (the provider's code is on the page's own URL) — an XSS here forges the approval click, which is strictly worse than the interstitial's equivalent (T2-3/T3-4's class) because the forged click is a *decision*, not a notice. Bounded by the same construction the interstitial already carries: the escape (`gateway/flow.py:505-518`) on every interpolated value, the page built through the one shared builder so the CSP family (default-src 'none', script excluded) is inherited by construction, and — new for this page — `form-action 'self'` confining the form's submission to the gateway's own origin (D3). The decision page joins the header-assertion tests, so the family cannot drift off it. |
| EP3 (the decision page) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Framed approval (UI redressing) | A8 (the victim's session); the approval decision | I, Access | The attacker frames the decision page in a victim's browser and harvests a click — the framed click approves the attribution, the T3-5 class (framed flow advancement) relocated onto a decision. Killed by the same pair the interstitial carries: `frame-ancestors 'none'` + `X-Frame-Options: DENY`, inherited from the family by construction (M8), and asserted by the same test battery. The auto-continue dimension of the T3-5 class is *absent here by design*: the decision page does not navigate itself (no `meta refresh` — D3), so a frame buys one click at most, against a page that renders nothing clickable outside the two buttons. |
| EP3 (the decision page, registration naming) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | False attribution on a decision page **[mis-use]** | A8; the approval decision; A9 (the attribution record) | I | The T1-11/EP1 family (registrant attribution impersonation) with raised stakes: pre-change a false `client_name` misinforms (display-level, RES-11's acceptance); on a decision page a false name *harvests an approval* — a legitimate registration (the feature used exactly as permitted) naming another organization's product collects user trust the registrant did not earn. Bounded but not eliminated, honestly: the page presents the name as a name, not a verified fact (the interstitial's existing discipline), beside the **client id** and the **registered `redirect_uri`** — the two facts the registrant cannot falsify to the page's advantage (the redirect is the registration's own validated value; a collector URL reads as one). The residual is the display-level bound RES-11 already carries, re-priced for the decision context in §7; the naming controls stay where they are (CIMD allowlist curation, M7; the DCR flag's default-off, RES-5). |

### 5. Mitigations per threat, in the fixed control-category order

Homes: **spec** = this change's delta spec (gateway-owned, normative); **repo** =
committed material; **deployment** = named with its owner. Every category appears
for every threat.

**DT-EP1-1 Forged approval advances an unattributed flow**
1. Reduce Attack Surface — the route answers exactly two actions and carries
   exactly two parameters (the flow id, the action token); nothing else is read
   from the request, and no route on the surface accepts an approval by any other
   spelling (spec).
2. Isolation — the approval state and the flow state are separate stores; the
   registry write happens only after the flow resolves and the identity leg's
   subject exists, so no unauthenticated path reaches the registry (spec).
3. Authentication — not applicable, because the route is deliberately
   unauthenticated like its callback siblings: the flow id *is* the authenticator
   of the request (128-bit CSPRNG, server-side record, TTL-bounded — the M1
   binding), and adding a cookie or session layer would create the ambient
   authority the CSRF shape feeds on where none exists today.
4. Authorization — **the control**: the approve action advances only a live flow
   whose identity leg completed, records the attribution keyed to that flow's own
   verified subject, and is single-use-per-flow — a replayed or foreign POST
   advances nothing (spec).
5. Data Protection — the action's parameters are non-credential (flow id, fixed
   action token); no token, code, or secret is read, stored, or echoed by the
   route; responses are the family's no-store pages and redirects (spec).
6. Anti-Injection — the action token is compared against a fixed vocabulary, the
   flow id against the store's keys; no request value reaches a URL, a page
   template, or a log un-escaped and un-bounded (spec; repo — the existing
   disciplines).
7. Anti-DoS — the route joins the shared limiter (the callbacks' pattern), and a
   POST naming no live flow allocates nothing — lookup-first, like every
   flow-id-resolved route (spec).
8. Detective controls — the three fixed-vocabulary events
   (`attribution_required`/`attribution_approved`/`attribution_refused`) make an
   approval burst, an approval for a client no harness flow should be attributing,
   and a refusal pattern distinguishable on the trail (spec).

**DT-EP1-2 Approval-registry flooding**
1. Reduce Attack Surface — one write path (the approve action on a live,
   identity-completed flow); no unauthenticated write exists (spec).
2. Isolation — the registry is process memory, the flow store's class, with no
   disk, no cookie, and no external exposure of its contents (repo).
3. Authentication — not applicable, because the flood shape has no credential to
   check: the bound is upstream (a completed sign-in per entry), not at the write.
4. Authorization — not applicable, because the entries an attacker can write are
   keyed to their own verified subject; no other user's approvals are reachable.
5. Data Protection — the registry's entries are (subject, client id) pairs —
   non-credential facts; nothing secret is stored (spec).
6. Anti-Injection — keys are the provider-verified `sub` and the resolved
   client id — both already bounded values from trusted sources; no
   caller-supplied free text is stored (spec).
7. Anti-DoS — **the control**: the hard cap with oldest-first eviction bounds
   memory absolutely, the entry cost is a full rate-limited sign-in, and eviction
   fails safe — a re-prompt, never a bypass (spec).
8. Detective controls — the `attribution_required` events make registry growth
   visible on the trail as what it is (real approvals), and an approve burst reads
   as one (spec).

**DT-EP1-3 Oversized `state` growth**
1. Reduce Attack Surface — the bound is 2048 bytes, two orders above any fielded
   harness's state; the refusal lands before the record exists (spec).
2. Isolation — not applicable: the value is stored server-side on the flow record
   regardless of size; there is no second boundary to draw.
3. Authentication — not applicable: the `state` is the client's own echo token,
   never an authenticator on this surface.
4. Authorization — not applicable: the `state` authorizes nothing at the gateway;
   its whole role is the client's own round-trip.
5. Data Protection — the stored state is echoed unchanged and never logged (the
   trail records the refusal's class, not the value) (spec).
6. Anti-Injection — the state is echoed via `urlencode` and never rendered into
   markup; the bound caps the echo's size with it (spec; repo — the existing
   redirect builder).
7. Anti-DoS — **the control**: the bound caps per-record memory and the final
   redirect's size against a caller who would grow them (spec).
8. Detective controls — the refusal is audited as `oversized_state`, so a client
   hitting it is diagnosable from the trail (spec).

**DT-EP1-4 Drive-by client hijacks the flow via a zero-page short-circuit
(T1-25, re-priced)**
1. Reduce Attack Surface — the silent mints are gone: no mint path exists that
   does not pass the registry check, on either resource kind, short-circuit or
   consent branch (spec — the checkpoint requirement).
2. Isolation — the decision is a gateway-owned page served on the gateway's own
   origin at the flow's own URL; no third-party surface (provider or upstream) is
   trusted to carry the attribution (spec).
3. Authentication — the decision addresses the party that holds the flow id —
   the user whose browser the provider's callback landed in, the one party the
   link crafter cannot be (spec; the M1 binding).
4. Authorization — **the control**: the mint runs only after the user's act, on
   first attribution, per (subject, client) — the attacker's registration earns
   no mint without a click from the victim; DIAL authorization and Core's
   per-call enforcement stand unchanged behind it (spec).
5. Data Protection — the decision page names non-credential facts only; the
   provider's code is on the page's URL, and the family's `Referrer-Policy:
   no-referrer` + `no-store` (M8, inherited) close the page's own leak channels
   (spec; unchanged).
6. Anti-Injection — the page's facts are escaped and CSP-bound (DT-EP3-1's
   controls, inherited by construction) (spec).
7. Anti-DoS — not applicable: the page adds one response to a flow the rate
   limiter already admitted; the decision adds no amplifiable work.
8. Detective controls — every attribution is on the trail
   (`attribution_required` → decision), so a victim who was prompted by a link
   they did not start leaves the record an operator can read (spec).
   **Disposition: the drive-by shape moves from deferred to mitigated (M31); the
   on-path shape keeps RES-12/RES-1's existing price (DT-EP1-1's analysis); the
   mis-named-registration shape is priced at DT-EP3-3.**

**DT-EP3-1 Attribution/context injection into the decision page**
1. Reduce Attack Surface — the page interpolates a fixed set of values, every one
   through the existing escape; no page on the surface interpolates anything else
   (spec).
2. Isolation — the page is script-free and CSP-bound to no script source; the
   form submits to the gateway's own origin only (`form-action 'self'`) (spec).
3. Authentication — not applicable: the threat is content, not a caller; the
   page's authority (advancing the flow) is the flow id's, unchanged.
4. Authorization — a forged click approves the flow the page belongs to and
   nothing else; the single-use rule bounds even a forged approval to one mint of
   one already-identity-verified flow (spec).
5. Data Protection — `Referrer-Policy: no-referrer` and `Cache-Control:
   no-store` on the page (M8, inherited) keep the flow's URL-borne material off
   third-party referents and caches (spec; unchanged).
6. Anti-Injection — **the control**: the escape on every value, the CSP family
   with script excluded, and the header-assertion test extending to the new page
   class — the same triple the interstitial carries (M8), inherited through the
   one builder (spec; repo — the tests).
7. Anti-DoS — not applicable: the injection targets the victim's browser, not
   the gateway's capacity.
8. Detective controls — not applicable, because a successful XSS leaves no
   gateway-side anomaly to detect (the approval it forges *is* trail-visible as
   an approval); the control is the prevention triple above.

**DT-EP3-2 Framed approval (UI redressing)**
1. Reduce Attack Surface — the page does not auto-continue (no `meta refresh`),
   so a frame cannot advance the flow without a click inside the frame (spec).
2. Isolation — `frame-ancestors 'none'` + `X-Frame-Options: DENY`, the family's
   pair (M8), inherited by construction and asserted by the tests (spec; repo).
3. Authentication — not applicable: the framing site holds no gateway credential;
   there is nothing to authenticate the frame with.
4. Authorization — a harvested click approves only the framed flow — the flow-id
   binding again; the frame cannot address a flow it does not hold (spec).
5. Data Protection — not applicable: the frame reads nothing the page does not
   render.
6. Anti-Injection — not applicable: the threat is framing, not content.
7. Anti-DoS — not applicable.
8. Detective controls — not applicable: framing leaves no gateway-side trace;
   the CSP pair is the control, and the header-assertion tests are its pin.

**DT-EP3-3 False attribution on a decision page [mis-use]**
1. Reduce Attack Surface — the page shows the client id and the registered
   `redirect_uri` beside the name — the two facts a registrant cannot falsify to
   the page's advantage (spec — the page-content requirement).
2. Isolation — not applicable: the naming surface is the registration's
   (CIMD/DCR), outside the gateway's boundary to verify; the page's job is to
   present, not to adjudicate.
3. Authentication — not applicable: the registrant is legitimate by the
   mis-use's own definition; no credential is attacked.
4. Authorization — not applicable: the approval grants the client nothing the
   user's own DIAL authorization does not already gate.
5. Data Protection — not applicable: no secret is at stake; the stake is the
   decision's honesty.
6. Anti-Injection — the name is escaped and presented as a name (the
   interstitial's discipline, inherited); no markup rides it (spec).
7. Anti-DoS — not applicable.
8. Detective controls — the approval record carries the client id (the
   verifiable fact), so a misleading-name approval is identifiable on the trail
   after the fact (spec).
   **Disposition: accepted at RES-11's display-level bound, re-priced for the
   decision context — the page's verifiable-facts rule (the control above) is the
   compensating bound; the naming controls stay M7's allowlist curation and the
   DCR flag's default-off (RES-5).**

**DT-EP1-5 Non-loopback `http` redirect delivers the authorization response over
a cleartext leg**
1. Reduce Attack Surface — **the control**: the admission rule refuses the
   whole non-loopback-`http` class at every entry point (the four sites), so
   the cleartext delivery target cannot exist to be registered (spec — the
   client-registration requirement's amendment).
2. Isolation — the loopback exception confines plain-`http` delivery to the
   client's own host (the RFC 8252 §7.3 native-client shape), where the leg is
   the host's own, not a network hop (spec).
3. Authentication — not applicable: the threat is the delivery leg's
   transport, not a caller's identity; no credential check bears on it.
4. Authorization — not applicable: redemption is already gated by PKCE and the
   code's embedded bindings; the rule governs where the code may be
   *delivered*, never who may redeem it.
5. Data Protection — the redirect carries only code, `iss`, and the echoed
   `state` (unchanged); under the rule, never over a cleartext non-loopback
   leg (spec — unchanged, restated).
6. Anti-Injection — not applicable: the URI is compared, not executed; the
   scheme check is a string-shape check on a registration-validated value.
7. Anti-DoS — not applicable: the refusal clauses are constant-time checks on
   existing validation paths and allocate no state.
8. Detective controls — every refusal site is loud and fixed-vocabulary: the
   DCR body refusal, the refused-whole document, the startup refusal naming
   the setting, the load-time refusal naming the record — each diagnosable as
   the rule firing, not a silent skip (spec).

**DT-EP1-6 Replayed code refused but its token family survives**
1. Reduce Attack Surface — **the control's shape**: the revocation removes the
   surviving-refresh payoff from the replay shape — a detected replay now
   costs the thief the session the code bought (spec — the issued-tokens
   requirement's code clause).
2. Isolation — the memo and the denylist are existing in-memory,
   self-expiring stores; the mechanism is one field and one call, no new state
   class (repo).
3. Authentication — not applicable: the detection is the existing claim-once
   check; the revocation verifies no credential.
4. Authorization — **the control**: the denylist is consulted at every refresh
   grant (`gateway/token.py:581-582`), so the revoked `jti` refuses at its
   next presentation through the existing `invalid_grant` path — now reachable
   from the replay detection (spec).
5. Data Protection — the memo holds gateway-minted identifiers only (`code_id`,
   `refresh_jti` — the trail's own fact class), TTL-bounded to the refresh
   window, never logged as credential material (spec).
6. Anti-Injection — not applicable: both values are gateway-minted identifiers
   compared against store keys; no caller-supplied value enters the mechanism.
7. Anti-DoS — not applicable: one constant-time store write on an
   already-refused request; both stores self-expire.
8. Detective controls — the replay refusal is already audited (the existing
   `invalid_grant` record); the revocation reads downstream as the revoked
   token's next refusal — the pair on the trail is detected-theft-then-kill
   (spec).

### 6. The grouped mitigation list

The reviewed result — one mitigation to the threats it addresses:

1. **The consent/attribution checkpoint (spec — the checkpoint requirement:
   federation-flow and app-resource amendments):** the per-(subject, client_id)
   approval registry consulted after the identity leg and before every mint, on
   all three mint paths; the decision page naming the resolved client (name,
   client id), the addressed resource, and the registered `redirect_uri`; the
   `POST /dial/consent` action bound to the flow id, single-use-per-flow,
   consuming on deny, recording-and-continuing on approve; the registry in
   process memory with a hard cap and oldest-first eviction (fail-safe on
   loss); the three fixed-vocabulary audit events. Addresses DT-EP1-1,
   DT-EP1-2, DT-EP1-4 (T1-25's drive-by shape — the deferred-to-mitigated flip);
   bounds DT-EP3-3.
2. **The page inherits the web-hardening family, plus `form-action 'self'`
   (spec — the header-family requirement's amendment):** the one builder stamps
   the family on the decision page by construction, the new directive confines
   its form to the gateway's origin, and the header-assertion tests extend to
   the page class. Addresses DT-EP3-1, DT-EP3-2; carries DT-EP1-4's
   data-protection half.
3. **The `state` rule with its bound (spec — the authorization-requests
   requirement's amendment):** state OPTIONAL, stored, echoed unchanged when
   present, absent tolerated and nothing echoed, over 2048 bytes refused
   `invalid_request` (`oversized_state`). Addresses DT-EP1-3; states the CSRF
   reasoning (PKCE + flow-id round-trip as the binding, RFC 9700 §2.1's
   accepted carrier).
4. **The CORS/back-channel posture as a rule with a pin (spec — the public-endpoints
   requirement's amendment, "Public
   endpoints are bounded against abuse"; repo — the no-`Access-Control-*` assertion test and
   the operator-reference paragraph):** no CORS headers on any AS-surface
   endpoint, no preflight handling, a browser frontend not a supported client
   shape. Addresses the posture-drift risk the SIA's surface scope names; makes
   D9's statement machine-checkable.
5. **The `auth_time` registry addition (spec — the claim-copy requirement's
   amendment):** the provider's authentication-time claim, where a provider
   mints one into its access token, is stripped by the copy rule alongside
   `acr` — a gateway token never carries the provider's authentication event as
   its own. Addresses the copy-rule gap D7's analysis found (a narrowing inside
   the mint; no tabled threat — it closes one).
6. **The RFC 9700 conformance ledger (repo — `docs/threat-model.md`'s new
   section, landed from the re-walked report and its review under D10's
   method, with the fully-reconciled partition 55/13/3/6/22 — nothing
   undecided, 99 verdicts over 98 rows):** one row per
   recommendation, verdict in the four-value vocabulary, satisfaction or price
   named; the landing task verifies the borderline rows against the built
   code. Addresses the roadmap's first acceptance row; carries the re-judge of
   every residual D3 will inherit.
7. **The redirect-URI scheme admission rule (spec — the client-registration
   requirement's amendment, the startup-bounds family, and the store-load
   validation):** a registered redirect URI MUST be `https` or a loopback
   `http` URI, enforced at the four admission sites — the DCR body check, the
   CIMD document validation (refused whole), the pre-registered startup
   refusal, and the durable DCR store's load-time validation; loopback
   excepted for the native-client population, so no conforming fielded
   harness's registration changes behavior. Addresses DT-EP1-5; discharges
   RFC 9700 §2.6's MUST NOT and the MCP authorization specification's
   redirect-URI MUST (B-1/B-3, owner-accepted 2026-11-07, D11) — **M32**.
8. **The redemption-replay revocation (spec — the issued-tokens
   requirement's code clause):** the replay memo's
   `code_id → refresh_jti` field and one `TokenDenylist.revoke` call at the
   detected replay, on the existing in-memory self-expiring stores, with the
   two partials (the access token's TTL bound; the rotated-successor window)
   stated as the clause's bound. Addresses DT-EP1-6; discharges RFC 9700
   §4.2.4's SHOULD (B-2, owner-accepted 2026-11-07, D12) — **M33**.

*Beside the numbered mitigations:* D14's `iss` advertisement carries **no
M-number and no threat row** — it is a trueness member on an existing,
spec-pinned behavior (M9's `iss` rows), landed by the discovery requirement's
amendment (the delta's discovery clause and its metadata-assertion test); it
makes an existing protection discoverable, which no threat row prices and no
mitigation number should double-count.

### 7. The threat-model delta

The entries `docs/threat-model.md` gains or changes — landed by this change's
implementation, before the change is done (the standing order):

- **T1-25's disposition flips: deferred → mitigated (M31).** The EP1 threat-table
  row (`docs/threat-model.md:658`) gains its mitigation statement — the
  checkpoint's position (after the identity leg, before every mint, all three
  paths), the per-(subject, client) registry, the first-attribution-only
  prompting — and its scope statement, priced honestly: the drive-by shape is
  bounded; the on-path shape keeps RES-12/RES-1's existing acceptance (an
  attacker with wire access holds strictly cheaper attacks — T1-1); the
  mis-named-registration shape is DT-EP3-3's re-priced display-level bound. The
  dispositions-table row (`docs/threat-model.md:1937`) rewrites accordingly —
  and **corrects the known cross-reference defect**: the standing control it
  cites is CIMD allowlist curation, whose surface is **M7's** control set
  (`docs/threat-model.md:1881`), not M24's (the apps front-door surface,
  `docs/threat-model.md:1897`); the corrected row names M7.
- **M31 joins the grouped mitigation list** (the grouped list above, item 1),
  Placed — spec (the checkpoint requirement and its flow amendments), with the
  registry's in-memory bound stated in its own record: single instance, restart
  forgets (re-prompt, fail-safe), hard cap with oldest-first eviction — the
  RES-15 acceptance class extended to one more in-memory store, named; the
  short-circuit dwell effect stated there too — a flow parked at the decision
  point carries the provider's session refresh token on its record for the
  user's decision time (previously ~0 on the short-circuits), bounded by the
  flow TTL, dropped on deny — the consent branch's priced human-decision dwell
  class gaining two members, not a new class.
- **M32 and M33 join with it** (the grouped list above, items 7 and 8; the
  owner-ruled re-judge findings, 2026-11-07): **M32** the redirect-URI scheme
  admission rule — Placed — spec (the client-registration requirement's
  amendment, the startup-bounds family, the store-load validation), its
  four-site scope and the loopback exception stated in its record — the
  store-load site's planted-record shape being T7-1's existing price, that
  row's bounding note gaining the load-time refusal; **M33** the
  redemption-replay revocation — Placed — spec (the issued-tokens
  requirement's code clause), its two partials stated as the clause's
  bound and the rotation-chain memo recorded as the known extension, not built.
- **New threat rows:** the forged-approval threat (DT-EP1-1) lands in EP1's
  table with the flow-id binding as its control and the on-path race priced at
  RES-12's existing acceptance; the registry-flooding row (DT-EP1-2) with the
  cap-and-eviction control; the decision-page rows (DT-EP3-1/2/3) land in EP3's
  table, DT-EP3-3 marked mis-use and accepted at RES-11's re-priced bound; the
  cleartext-redirect-delivery row (DT-EP1-5) lands in EP1's table with M32 as
  its control and no new residual (the on-path class keeps RES-12's acceptance;
  the loopback exception keeps the fielded population's shape); the
  token-family-survival row (DT-EP1-6) with M33 as its control and its two
  partials as the stated bound; and
  **DT-EP1-3 (oversized `state` growth) lands as no new row** — it is the
  existing unauthenticated-allocation class's own member (the flow-record
  memory family the model's EP1 allocation-abuse row already carries), narrowed
  by the 2048-byte bound rather than newly enabled by this change; its
  mitigation lives in the delta spec's authorization-requests amendment, and
  the existing row's bounding note gains the state bound's mention.
- **RES-25 lands — the localhost-warning deferral (B-4, owner-ruled 2026-11-07,
  D13):** a new disclosed residual with its three-part record — (a) the
  accepting condition: the attack the warning mitigates (the current MCP
  revision's own localhost-impersonation shape) requires local code execution
  on the victim's host — the attacker model's classes 3/4, where T1-3's
  stolen-token pricing and RES-21 part i's machine-control statement give the
  attacker strictly cheaper attacks (the grounding rows D13 names; no residual
  carries a "local-compromise floor" acceptance, so none is cited); (b) the
  compensating bound: the decision page's display of the full registered
  `redirect_uri`, port included, on first attribution (which also discharges
  the revision's redirect-hostname-display MUST); (c) the re-open trigger: a
  client population where loopback is anomalous — and the roadmap's closing
  re-judge (D3) sees it there.
- **RES-11 re-prices, one notch wider:** display-level attribution was an
  information honesty bound; on a decision page a false name harvests an
  approval. The re-priced record keeps the acceptance (the naming surface is the
  registration's, outside the gateway's boundary) and names the compensating
  control the checkpoint adds — the page's verifiable-facts rule (client id and
  registered redirect beside the name) — with the re-open trigger unchanged
  (a future client-authentication or verified-naming mechanism on the
  registration surface).
- **The bearer-token residual's record gains its named structural remedy with
  the two-sided precondition (D6):** RES-7/RES-8's class keeps its price; the
  record names DPoP (RFC 9449) as the structural remedy, deferred on the
  precondition — the client side and the resource-server side (Core validating
  DPoP-bound tokens; the E1 line's natural scope) — so the roadmap's closing
  re-judge (D3) finds it priced, not forgotten. The client-side leg carries the
  **owner-accepted record-wording** (2026-11-07, folded into D6): worded against
  today's state — the extension is experimental and unadopted; the flagship
  harnesses' enablement is unverified; the reference TypeScript SDK carries
  opt-in support — never "nowhere in the ecosystem", so the re-open trigger
  fires on verified harness evidence, not on SDK changelog entries.
- **The RFC 9700 conformance ledger section lands** (D10's method) — the
  change's first acceptance row's artifact — **from the re-walked report
  (`evidence/rfc9700-rejudge-report.md`, 98 rows against the current
  `2026-07-28` revision) and its falsification review, with the
  fully-reconciled partition 55/13/3/6/22 — nothing undecided, 99 verdicts
  over 98 rows** (D10's correction names it the disposition source, replacing
  the annex); the landing task verifies the borderline rows against the built
  code.
- **D14's `iss` advertisement lands with no threat row and no M-number** —
  the discovery requirement's amendment carries it (§6's note beside the
  numbered mitigations); the ledger's row for the `2026-07-28` advertisement
  MUST reads *landed by this change*, its satisfaction named (M9's `iss` rows
  plus the member).
- **The M24→M7 cross-reference correction** (above) is this change's docs task
  and lands with the disposition flip, in the same edit.
- **No residual is closed by this change** except T1-25's deferred status (a
  mitigation, not a residual closure — the row was never an accepted residual);
  RES-11 widens one notch with its compensating control named; **one residual
  is added: RES-25** (B-4's priced deferral, D13 — added, not widened from an
  existing record: the shape was unpriced before the walk surfaced it); nothing
  else moves. The roadmap's closing re-judge (D3) of every residual against the
  production shape is
  untouched by this delta's scope.

### 8. Open questions

- **OQ-1 — The approval registry's persistence.** In-memory by design (D4), so a
  restart re-prompts every user for every client once. If restart frequency
  (deploy cadence, RES-15's single-instance semantics) makes that painful, the
  durable registry is its own change with its own SIA (an EP7-class host-volume
  asset with T7-class tamper rows) — and that change must carry one condition
  the in-memory registry holds for free: durability would outlive the restart
  that today empties the keying's single-issuer safety (D4), so a
  `(sub, client)` entry from an old issuer could survive a provider migration
  and pass the check for a different user under the new one; the durable
  registry's own change re-keys by issuer or clears on provider migration.
  Answerable after the first deployment's
  experience; no spec change needed to reopen it.
- **OQ-2 — Per-resource scoping of approvals.** The registry keys (subject,
  client_id) — the attribution of a *client* (D4's ruling). A per-resource keying
  would re-prompt per toolset for the same trust decision. Reopenable if a
  deployment presents a shape where one client is trusted for one resource and
  actively hostile for another (the DIAL authorization read still gates every
  resource, so the exposure is attribution granularity, not access); the delta
  spec's registry clause is written so the key can widen without touching the
  page or the action.
- **OQ-3 — The re-judge's per-recommendation verdicts. Resolved 2026-11-06/07;
  source: the walk itself** (`evidence/rfc9700-rejudge-report.md` — 98 rows
  walked after the twice-applied corrections, the second the `2026-07-28`
  source-currency re-walk; `evidence/rejudge-report-review.md`) and the
  owner's rulings (2026-11-07): B-1+B-3, B-2, and B-5 accepted (D11, D12,
  D14), B-4 deferred with reasoning (D13). The authoritative verdict table
  exists — the report's Parts 1–4 and its Part 6 partition, fully reconciled
  to 55/13/3/6/22 with nothing undecided — and what remains is the landing
  task's (the ledger into the threat model, the borderline rows verified
  against the built code; D10's status note). The annex's incompleteness is
  recorded at D10's correction, not silently: the walk found what the annex
  missed.
- **OQ-4 — The operator-policy step-up setting** (D7's recorded-not-built
  extension): its precondition is a provider honoring `max_age`/`prompt` and an
  owner ruling that full interactivity is wanted. Kept open as the record the
  deferral needs; building it is a small future change, not this one's scope.
- **OQ-5 — The strict gap list. Resolved 2026-11-07; source: the walk's Part 5,
  every item verified against primary sources by the review.** The harness
  ecosystem's DPoP support beyond the two field-proven harnesses is now
  verified to today's state: the reference TypeScript SDK carries opt-in DPoP
  client support (RFC 9449 / SEP-1932, PR #2629); the Python SDK does not; an
  experimental, unadopted DPoP profile for MCP exists; the flagship harnesses'
  enablement remains unverified (opt-in at the provider level — capability is
  not enablement). The deferral stands on the decisive, unchanged
  resource-server half (Core validates bearer-style), and D6's record carries
  the owner-accepted current-state wording. The gap is closed: the disposition
  rests on verified primary sources, not on the authoring session's
  unavailability.

## Risks / Trade-offs

- [First-attribution friction for every existing user] → one click once per
  (user, client), at the moment the attribution is first claimed; repeat
  sign-ins stay zero-click (D5) — the price is paid deliberately and is the
  MCP best-practices MUST's own shape.
- [The decision page is the flow's most attackable page yet] → it inherits the
  interstitial's escape and the family's CSP by construction, adds
  `form-action 'self'`, joins the header-assertion tests, and carries no
  auto-continue (D3, DT-EP3-1/2) — the controls are inherited, not invented for
  the page, which is what "by construction" is worth.
- [The checkpoint does not bound the on-path attacker] → stated, not hidden:
  that attacker keeps RES-12/RES-1's price and holds strictly cheaper attacks
  (T1-1); the checkpoint's declared scope is the drive-by shape, T1-25's own
  shape (DT-EP1-1).
- [A false `client_name` can harvest an approval] → RES-11 re-priced with the
  page's verifiable-facts rule as the compensating bound (client id and
  registered redirect beside the name); the naming surface stays the
  registration's (DT-EP3-3).
- [The registry forgets on restart] → fail-safe by construction (re-prompt,
  never bypass); the persistence trade is recorded as OQ-1, not built blind.
- [No operator bypass for trusted harnesses] → refused for the priced reason
  (T1-14: a pre-registered id is wearable by any crafted link on a surface with
  no client authentication — D5); the honest zero-page path for a trusted
  harness is the user's one approval.
- [DPoP deferral leaves the bearer residual standing] → the residual keeps its
  price and gains its named structural remedy with a two-sided precondition
  (D6); the refresh-token half of RFC 9700's mandate already holds (rotation +
  denylist, M9).
- [The `state` tolerance could be read as laxity] → it is the RFC 9700-accepted
  carrier (PKCE) plus the flow-id round-trip, stated as a rule with reasoning
  and a bound (D8) — strictness theater (refusing conforming stateless clients)
  was considered and rejected on record.
- [The re-judge could drift into a paperwork walk] → its verdicts land in the
  threat model's ledger, every verdict names where the satisfaction or price
  lives, and adjacent findings join the disposition discipline (D10) — the
  ledger is the thing D3 cites, not a side artifact.
- [The admission rule is a behavior change on live registration surfaces] →
  priced and ruled (B-1/B-3, owner-accepted): the refused class is exactly the
  registrations both normative sources already forbid, the loopback exception
  holds every conforming fielded harness, and the one migration-visible
  consequence — a stored pre-rule DCR record refused loudly at load — is the
  rule's scope made visible, with re-registration as the remedy (D11).
- [The replay revocation is partial in two dimensions] → both stated as the
  clause's bound, not folded away: the access token ages out (M9's TTL, which
  the SHOULD tolerates) and a rotated successor survives the original's
  denylisting (bounded by the detection's timing and the non-sliding absolute
  expiry; the chain-tracking memo is the recorded extension) (D12).
- [The localhost warning is deferred, not built] → deferred with the owner's
  reasoning on record (RES-25): the attack's precondition sits inside the
  attacker model's priced local-compromise classes (3/4, with T1-3's and
  RES-21 part i's pricing), the decision page's full-redirect display is the
  compensating bound, and the re-open condition — a client population where
  loopback is anomalous — is named (D13).

## Migration Plan

1. Land the delta spec and the threat-model updates first (the standing order: a
   mitigation that exists only in prose is not landed) — the checkpoint
   requirement and its flow amendments, the state rule, the CORS posture
   statement, the `auth_time` registry addition, T1-25's flip with the M24→M7
   correction, RES-25, and the conformance ledger landed from the walk's report
   with its fully-reconciled partition (the borderline rows verified against the
   built code before the change is done).
2. One lockstep implementation task: the registry (state.py's family), the
   checkpoint insertion in `_run_identity_leg`/`_toolset_after_read`, the
   decision page through the builder with `form-action 'self'` family-wide, the
   `POST /dial/consent` route with the limiter join and the three audit events,
   the router alternation's `consent` segment with the probe battery's new rows,
   the `oversized_state` refusal, the `auth_time` strip, and the no-CORS pinning
   test; beside it, the owner-ruled set — the admission rule at its four sites
   (the DCR body check, the CIMD document validation, the pre-registered
   startup refusal, the DCR store's load-time validation, with the startup and
   load refusals covered by their own tests), the replay memo's
   `code_id → refresh_jti` field with the denylist call at the detected replay,
   and the discovery document's `authorization_response_iss_parameter_supported`
   member with its metadata-assertion test —
   no intermediate commit leaves the flow half-gated (a checkpoint whose
   route is unrouted is a flow that dead-ends at the page).
3. Existing users: the first sign-in after upgrade renders the decision page
   once per (user, client); no migration exists for approvals (the registry
   starts empty by design). A deployment whose durable DCR store carries
   pre-rule records with non-loopback `http` redirect URIs learns it loudly:
   the load-time validation refuses the record at startup, and the operator's
   remedy is re-registration over `https` or loopback — the refusal is the
   rule's own scope sentence made visible, not a data-loss event (the record is
   refused, not rewritten). In-flight flows at the upgrade instant are unaffected
   (their records predate the gate) or land on the expired page as ever,
   TTL-bounded.
4. Rollback is the lockstep in reverse; the registry's loss on rollback is the
   restart semantics (re-prompt). Issued tokens, the custody design, and the
   token lattice are untouched by the rollback; the registration stores keep
   their records, the load-time rule's refusal leaving with the rollback —
   the gate's removal restores the pre-change flow exactly.
5. The harness acceptance (D5's rows, both harness shapes, the compose stack)
   runs as the change's live gate; the ledger lands from the walk's report and
   the borderline rows are verified against the built code before the change
   closes; the owner review pause carries the dispositions (D1–D14) and the
   SIA's rulings, with the 2026-11-07 ruling already folded in.

## Open Questions (deferrable)

OQ-1 through OQ-5 above are the deferrable set: OQ-1/OQ-2 reopen on deployment
experience without touching the specs' shape; OQ-3 and OQ-5 are resolved on
record (the walk ran and the owner ruled; the landing and the borderline-row
verification are implementation tasks, not open questions); OQ-4 is the
recorded extension's standing precondition. None of them blocks the
checkpoint's implementation or the delta spec's landing.
