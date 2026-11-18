# Independent mechanism opinion — 1 (the P2 half of C1)

Evaluator: independent design evaluator, not the change's author, not the round-1
reviewer. No candidate solutions or recommendations were shared by anyone; the design
space below is derived from the material and the specifications. Read-only except this
file. Scope: **P2 only** — the mechanism that re-reads the user's claims at every
gateway-token refresh (design.md D1/D2/D3/D5, delta spec's ADDED refresh requirement and
MODIFIED claim-copy requirement). P3 (dynamic toolsets) is out of scope here.

Sources read: the change's five artifacts
(`proposal.md`, `design.md`, `specs/mcp-signin/spec.md`, `tasks.md`,
`release-notes-draft.md`), `evidence/review-round-1.md`, the main spec
(`openspec/specs/mcp-signin/spec.md`), `gateway/settings.py` (the
`_require_refresh_window_within_provider_lifespan` validator, lines 433–451),
`scripts/provision_keycloak.py` (the gateway client's mappers, lines 252–284),
`.env.example`, `docker-compose.yml`, `ROADMAP.md` (never-cut list),
`docs/production-roadmap.md` (P2/C1/C2), `docs/gateway-configuration.md`,
`docs/threat-model.md` (RES-6, T1-16, T4-2/RES-2, M13). Specification facts from the
OIDC/OAuth specifications; provider-behavior facts from the vendors' documentation as
named — the same class of not-repo-verifiable inputs D1 itself records and hands to the
owner (the design's own strict-gap-list discipline, third bullet).

---

## 1. The three objections, verified

### O1 — "userinfo does not exist for a lot of IdPs"

**Verdict: partially correct — right on the standard, overstated on the facts.**

What the specification actually says: in OIDC Discovery 1.0 §3, `userinfo_endpoint`
is a metadata member with **RECOMMENDED** status, not REQUIRED. A conformant OP may
omit it and still conform; an AS that is plain OAuth 2.0 (RFC 8414 metadata only) has
no userinfo concept at all — RFC 8414 §2 defines no claims endpoint. So "the endpoint
is discoverable from the issuer" does not mean "guaranteed by the issuer." On this
point the owner is exactly right, and — to the design's credit — the design says so
itself: D1's "honest boundary" paragraph states RECOMMENDED-not-REQUIRED with the
consequence (a conformant OP may omit it), and the delta spec's ADDED requirement
carries the dependency in the normative text.

What the facts say: among OIDC OPs the gateway could plausibly front, omission is
uncommon. Keycloak, Entra (AAD), Okta, Auth0, Ping, ForgeRock, Google all expose a
userinfo endpoint. The notable conditional cases are Azure AD B2C (endpoint exists
only when the flow uses custom policies with per-policy claim wiring) and
non-OIDC OAuth 2.0 servers — and the latter are out of scope for a different reason:
this gateway's identity leg is OIDC by construction (the identity token is the
authentication proof and the `sub` authority, `design.md` D2; the spec's issued-tokens
requirement), so the relevant population is OIDC OPs, where the endpoint is
near-universal but not guaranteed. "A lot of IdPs" overstates; "not guaranteed by the
standard, and conditional at named providers" is the accurate form.

Deployment consequence where it bites: an OP that omits the endpoint fails D2 at
**sign-in**, loudly, per user — fail-closed, not a runtime surprise. No silent
failure mode exists for this objection under the specified design.

### O2 — "userinfo does not necessarily return the needed claims from the access_token"

**Verdict: correct — and it is a general property of every standard claim surface,
not a userinfo-specific defect. The design concedes it; the round-1 review surfaced
it (M1); it is priced as OQ-F.**

Where providers actually place authorization-relevant claims: wherever the IdP
administrator or the vendor decides. OIDC Core §5.3.2 makes the userinfo response's
claim set a function of **the scopes granted and the OP's release policy** — the
endpoint is scope-filtered and policy-filtered by design, and the OIDC Core `claims`
parameter (§5.4) that could request specific claims is OPTIONAL for the OP. Keycloak
exposes this concretely: every protocol mapper has four independent toggles
(`access.token.claim`, `id.token.claim`, `userinfo.token.claim`,
`introspection.token.claim`), so the same role claim can be in the access token only,
the ID token only, userinfo only, or all four — it is realm configuration, and a
default Keycloak mapper set puts client roles in the **access token** without
necessarily exposing them at userinfo. Entra is the categorical case the design
records: the userinfo endpoint returns a fixed, non-customizable claim set
("You can't add to or customize the information returned by the UserInfo endpoint" —
learn.microsoft.com/en-us/entra/identity-platform/userinfo), so roles and custom
claims never appear there, and Entra places app roles in the **access token only** —
not in the ID token either. Azure AD B2C exposes userinfo only through custom
policies with per-policy claim wiring.

Can the gateway's `ROLES_SOURCE_PATH` claim set be assumed present at userinfo? No.
It is present exactly where the deployment wired it: the local realm works because
`scripts/provision_keycloak.py:252-284` sets `userinfo.token.claim: true` on both
the roles and the project mappers — a provisioning fact this repo controls, not a
property of the mechanism. A differently-administered Keycloak (mappers wired to the
access token only) fails D2 at sign-in, loudly. Entra and B2C-without-custom-policies
fail it categorically — no operator setting can repair it, which is the round-1
review's M1 and the design's OQ-F, both landed in the artifacts before this opinion.

One point the owner's objection does *not* establish: that this is a new defect
introduced by the userinfo choice. The **current** design reads deployment claims
from the **identity token** (main spec's claim-copy requirement: "Minted tokens MUST
carry the identity token's claims verbatim … Roles MUST additionally be read at a
required, operator-configured source path … absent from the identity token" —
`openspec/specs/mcp-signin/spec.md:200-202`), and the ID token's claim set is
governed by the same provider election: Entra's ID token carries no roles either, and
Keycloak's ID-token claim set is the same mapper toggles. The change moves the
deployment requirement from "claims reachable in the ID token for the client's
scopes" to "claims reachable in userinfo for the client's scopes" — on a
self-administered IdP these are one checkbox apart; on Entra both fail. The
objection is correct against universality, but it indicts the *category* (any single
fixed standard claim surface), not the userinfo member specifically.

### O3 — "the access_token gets expired quickly. The gateway's refresh token is
supposed to live definitely longer"

**Verdict: correct, and decisive against typical IdP defaults. This is the objection
the design's own text half-acknowledges (D5) without spelling out its operational
consequence.**

The design's own validator (D5, `gateway/settings.py:433-451`): the startup check
survives with a re-derived meaning — `refreshTtl` MUST NOT exceed the identity
provider's access-token lifespan, "because the retained identity token must outlive
the refresh window for the claims re-read to be possible at every refresh." The
design thereby concedes the structural fact behind the objection: **the mechanism's
claims read dies at the retained token's `exp`, and the validator exists precisely
because that expiry is typically far inside the refresh window.**

The deployment's configured numbers: `GATEWAY_REFRESH_TTL_SECONDS=28800` (8 h) and
`IDP_ACCESS_TOKEN_LIFESPAN_SECONDS=86400` (24 h) — `.env.example:94-101`,
`docker-compose.yml:64-71`. The check passes locally because the local realm's
`accessTokenLifespan` was deliberately set to 24 h (`docs/gateway-configuration.md`
"Origin of the local values": the local DIAL instance's realm; threat-model.md:73-74).
That 24 h is a provisioning artifact of the one IdP this repo administers, not a
typical value.

Typical values (vendor-documented behavior, from my knowledge — the same input class
as D1's Entra records):

- **Keycloak's default access-token lifespan is 5 minutes** (Server Administration
  Guide, Realm Settings → Tokens). The local realm's 24 h is a 288× deliberate
  override.
- **Microsoft Entra access tokens live a variable 60–90 minutes** (~75 min average;
  learn.microsoft.com/en-us/entra/identity-platform/access-tokens), and the
  configurable-token-lifetimes policy was retired for access tokens in 2021 — an
  operator **cannot** raise it to 8 h.

What actually happens at the first refresh after the retained token's expiry, under
the design's own D4 (fail-closed, no fallback): the gateway presents the expired
identity token at userinfo; the IdP refuses it (401); D4 refuses the refresh with
`invalid_grant`, audited `claims_read_failed`; the harness's 401→refresh path fails;
the user must re-run the sign-in flow, which mints a fresh IdP access token and a
fresh 8 h refresh window. So on an unreconfigured provider the **effective refresh
session equals the IdP access-token lifespan, not `refreshTtl`**:

- Keycloak defaults (5 min AT, 600 s gateway access TTL): the **first** refresh —
  at ~10 minutes — already presents an expired token. The mechanism delivers **zero**
  successful refreshes; every session is sign-in → 10 min → forced re-sign-in. (The
  D5 validator refuses this configuration at startup *if the operator declares 300
  honestly* — so the failure mode is a startup refusal, not a silent loop.)
- Entra (~75 min AT): ~7 successful refreshes, then a forced re-sign-in roughly
  every 75 minutes — the 8 h window is a fiction, and the operator cannot fix it by
  configuration because the lifetime is not theirs to set.
- Local realm (24 h AT): works as designed for the full 8 h — the one case where
  the acceptance task 3.1's live run can pass, and the only one whose IdP this repo
  controls.

A trap the artifacts do not currently name: the validator compares **two
operator-declared numbers**, not the provider's actual behavior. An operator who
copies `.env.example` (86400 pre-filled, "locally … 24 h" in the comment) against a
default Keycloak passes startup and then fails every refresh after 5 minutes — the
validator's input is an assertion, and on providers with variable, undocumented
lifetimes (Entra's 60–90 min) a green startup check predicts nothing. The delta
spec's "Refresh TTL exceeds the provider lifespan" scenario checks arithmetic, not
truth.

**Summary of the three verdicts:** O1 partially correct (standard: right; "a lot":
overstated). O2 correct (and already conceded/priced by the design as OQ-F). O3
correct and decisive (the design's own D5 concedes the structure; typical IdP
lifespans make the 8 h window conditional on a deliberate, IdP-side lifespan
override that managed providers do not offer). None of the three is mistaken.

---

## 2. Viability judgment

**For which deployments the mechanism works.** All three of these preconditions must
hold, and they are satisfiable exactly on **self-administered, configurable OIDC
providers**:

1. The issuer exposes userinfo (near-universal among OIDC OPs; RECOMMENDED, so not
   guaranteed; conditional at B2C without custom policies).
2. The deployment's claims — `ROLES_SOURCE_PATH` and whatever else it consumes — are
   present in the userinfo response for the gateway client's scopes (one mapper
   checkbox on Keycloak/Okta/Auth0; categorically false on Entra; per-policy wiring
   on B2C).
3. The IdP's access-token lifespan ≥ the refresh window (operator-raisable on
   self-hosted IdPs — the local realm's 24 h proves it; impossible on Entra, where
   60–90 min is fixed).

**For which it fails, and how loudly.** An OP without userinfo, or a provider whose
userinfo cannot carry the claims, fails at **sign-in for every user** — loudly, per
flow, by D2's single-vocabulary design; no silent mode exists. A provider whose AT
lifespan is shorter than the window fails at **the first refresh past that lifespan**
— loudly (`invalid_grant`, distinct audit token), converting the refresh session into
an IdP-lifespan-bounded session; or at **startup** if the operator declares the
lifespan honestly and the D5 check refuses the combination. Every failure mode is
fail-closed; none is silent. The honest characterization is: **the mechanism never
lies, but on un-reconfigured or managed providers it says "no" so often that the
8-hour refresh window stops existing.**

**Against the design's own constraint set:**

- *Fresh claims at refresh (the acceptance):* achieved where the preconditions hold —
  by test and by the live run locally (task 3.1 is achievable). The staleness bound
  genuinely collapses from the window to the refresh interval.
- *Universality (the owner's binding constraint, `docs/production-roadmap.md` C1:
  "must ride the OIDC standard and be universal — the identity provider is not known
  upfront … no solution may assume a provider-specific surface, endpoint shape, or
  claims vocabulary"):* **not met as stated.** The mechanism makes no
  provider-specific *code* assumption — every surface it touches is a standard OIDC
  member — but it makes three provider *behavior* assumptions, and the binding
  constraint's premise ("the IdP is not known upfront") is precisely about behavior
  you may not assume. The design concedes this in D1's honest boundary and OQ-F;
  my verdict is that the concession is honest but the word "universal" is then
  doing no work: a mechanism whose preconditions exclude the largest managed IdP
  (Entra) and the roadmap's own named tested case for C2 (B2C as shipped) is
  **deployment-conditional**, and P2's deliverable should be stated that way.
- *The never-cut list (`ROADMAP.md`):* preserved. Invariants 1, 2, 6, 7 untouched.
  Invariant 3 is strengthened (the userinfo `sub` cross-check binds the mint to the
  gateway's own signed subject). Invariant 4's bound shrinks — the change's purpose.
  Invariant 5 is preserved by the retention store's never-logged/never-delivered
  discipline, with the round-1 M5 finding (the hand-off seam) now specified as a
  server-side pending entry, never the code payload. The never-store/token-custody
  discipline is widened exactly once (D3), memory-only, bounded — the SIA prices it
  (DT-EP4-1, DT-EP5-1/2, RES-2/RES-3/RES-19 re-priced).
- *The recorded rulings:* the no-`offline_access` provisioning convergence
  (threat-model M13 — the token-harvest bounding control for T1-1; enforced in
  `provision_keycloak.py` and `docs/gateway-configuration.md:334,558`) is preserved —
  D1 rejected the provider refresh-token leg partly on exactly this ground. The
  token-use rule (RES-3/T5-1) is widened by D2's issuance read — the round-1 M2
  finding, now landed in the delta spec's purposes sentence.

**One custody observation the SIA under-states.** Under precondition 3 (AT lifespan ≥
window — the only configuration in which the mechanism works for the full window),
the retained token is not "min(refreshTtl, its own exp)" in any meaningful limiting
sense — the validator forces the two to converge, so the store holds a **full-window,
live, Core-accepted DIAL bearer identity** per active session (this is the same class
of token the credential call presents at USER level). DT-EP4-1 prices this correctly
(minutes → up to 8 h), but the operator-facing material does not say that adopting
the mechanism at an 8 h window *requires deliberately extending the IdP's own
bearer-token lifespan to ≥ 8 h* — an IdP-side security-posture change whose cost
lands on the IdP, not on this gateway. That requirement should be stated where
`GATEWAY_REFRESH_TTL_SECONDS` is documented.

---

## 3. The derived design space

**The hard constraint, stated precisely.** At a back-channel refresh there is no
browser and no user interaction. The gateway holds exactly: its own signing key, the
presented (gateway-signed) refresh token, and whatever it chose to retain from the
sign-in flow. Any freshness mechanism is therefore: *present some retained credential
to some IdP surface and read an answer whose claims the IdP computed recently*. The
design space is enumerable by (retained credential × IdP surface), and it is small.

**Candidate A — retained IdP access token → userinfo (the design's D1).**
Surface: OIDC userinfo (Discovery RECOMMENDED member). Custody: a presentation-only
bearer token, retained for the window, memory-only — the minimum custody of any
candidate that re-reads anything, and no new credential class (the flow already
holds and verifies this token). Survives O1: partially (endpoint not guaranteed).
O2: partially (claim set is provider configuration; false on Entra). O3: **no** —
structurally bounded by the IdP's AT lifespan; works for the full window only where
the operator raised that lifespan. Standard: yes. Freshness: claims as fresh as the
IdP's userinfo computation — genuinely current, not session-frozen.

**Candidate B — retained IdP refresh token → token endpoint (the `offline_access`
leg).** Surface: the token endpoint (Discovery **REQUIRED** member) + the RFC 6749 §6
refresh grant — the most universally implemented mechanism in OAuth, and the only
back-channel surface that is both guaranteed present and long-lived. Custody: a
**mintable** credential — strictly larger blast radius than A: it renews itself past
AT expiry, on some providers past any window the gateway believes in (Entra
public-client refresh tokens live ~24 h and slide on use; Keycloak offline tokens
30 days+), so "bounded by the refresh token's absolute expiry" becomes a gateway
self-restraint, not a property of the artifact. It also reverses the recorded
no-`offline_access` convergence (M13), adds provider rotation-state tracking, and
depends on the provider *granting* offline access to the gateway's public PKCE
client — a policy dependency, not a standard guarantee. Survives O1: **yes**. O2:
**partially** — the fresh ID token's claim set is the same provider election A
suffers (Entra's ID token carries no roles either); the fresh *access* token does
carry roles on Entra, but reading claims out of an IdP access token is outside any
specification (no guarantee it is a JWT the client may decode — opaque ATs exist and
are the roadmap P4's own named case). O3: **yes** — the only candidate that survives
it. Standard: yes. D1's rejection of B is sound on custody grounds; my addition is
that B is also the *only* O3-surviving back-channel candidate, which is why the
custody price is the real trade, not a detail.

**Candidate C — retained IdP access token → introspection (RFC 7662).** Surface: not
a Discovery/RFC 8414 metadata member — the URL is a provider-specific surface, an
immediate failure of the binding constraint (D1's ground, verified: RFC 8414 §2
defines no such member). It also requires client authentication the gateway's public
PKCE client lacks, returns token metadata more often than user claims (RFC 7662
leaves claim content to the provider; Keycloak's introspection claim set is the same
mapper toggles — the local script sets `introspection.token.claim: true`, which says
"configurable," not "guaranteed"), and it still needs the retained AT, so it **fails
O3 exactly as A does** while paying A's full retention cost for less universality.
Rejected; D1's reasoning holds.

**Candidate D — a technical/read-only IdP client querying user claims (the roadmap
P2's own parenthetical hint, `docs/production-roadmap.md:31-32`).** Surface: none
standard. OIDC has no per-user claims-query endpoint for a client-credentials
client — userinfo requires a *user* token, introspection is token-targeted, and the
per-user surfaces that remain are provider admin APIs (Keycloak Admin REST, MS
Graph), which are provider-specific (fails the binding constraint at the first test)
and carry **tenant-wide** credentials — a process compromise or network peer gains
all users' claims, orders of magnitude beyond A's per-session tokens. O3: survives.
O1/O2: fails. Non-starter; worth stating so the owner sees why the roadmap's own
hint was abandoned — read against the specifications, it has no standard leg.

**Candidate E — shrink the TTLs, keep the frozen snapshot (status quo with smaller
numbers).** Surface: none — nothing is re-read. Custody: zero. Freshness: the bound
stays the window, whatever its width; fails P2's acceptance by definition. This is
also, note, what candidate A *degenerates to* on an Entra-shaped provider under O3+D5
— a ≤90-minute window — except that A at least makes the claims fresh *within* that
shortened window, which E does not. Listed as the floor, not a contender.

**Candidate F — freshness via the front channel: abolish/shorten the long refresh
window and lean on re-authorization.** Surface: the authorization endpoint
(Discovery **REQUIRED** member) with `prompt=none` (OIDC Core §3.1.2.1) — the
strictly most universal surface in the entire space. Custody: **zero** — no retained
IdP credential at all, strictly narrower than even today's design (nothing survives
the flow but the gateway's own tokens); D3's widening would be deleted, not widened.
Claims: read from the fresh ID token at each re-authorization — the *same*
vocabulary as today's issuance, so no new claim-source deployment requirement (O2's
userinfo half disappears; the ID-token half stays, as it does today). Survives O1
(yes), O2 (as well as anything), O3 (yes — the IdP SSO session, not the AT, is the
clock, and SSO sessions outlive access tokens: Keycloak SSO max 10 h default, Entra
sessions longer still). The price: **it is not a back-channel mechanism.** The token
endpoint cannot open a browser (RFC 6749 token responses are JSON; a harness's
401→re-authorize path is what triggers the front channel), so "silent refresh, no
user interaction" holds only while the IdP SSO session lives; when it lapses, the
user re-authenticates in the browser. It also changes the harness-visible contract
(401→browser at a cadence, instead of a silent token swap for 8 h) and breaks the
spec's own acceptance criterion (b) "silent repeat use and refresh" for windows
longer than the SSO session. Listed honestly: this is the zero-custody,
max-universality corner of the space, and it is excluded by the assignment's own
hard constraint (no browser at refresh) — but it is the shape the *system already
falls back to* at every fail-closed refresh under D4, and it is what the mechanism
effectively becomes on Entra-shaped providers anyway (~75-minute sessions, browser
re-run at each lapse, possibly invisible behind the SSO cookie).

**Candidate G — push-based freshness (the IdP notifies the gateway on claim
change).** No standard exists for claim-change notification: OIDC back-channel
logout signals session end, not role change; RFC 7009 revocation is token-targeted
and caller-initiated; SCIM/Graph push are provider-specific. Non-starter.

**Hybrids (OQ-F's options ii/iii — per-deployment claim source, userinfo-at-refresh /
id_token-at-issuance):** not new mechanisms — A with a configuration switch. Option
(iii) reintroduces the two-vocabulary silent-vanish drift D2 exists to reject
(a claim in the ID token but not userinfo works at sign-in and vanishes hours later);
option (ii) preserves deployment universality at the price of one config item and is
the honest container for the Entra-shaped case *if* the owner accepts that "fresh
claims" there means "fresh ID-token claims" — which on Entra still does not include
roles. The owner's ruling slot, as designed.

**The space's verdict: the constraint set is jointly unsatisfiable.** At a pure
back-channel refresh on standard surfaces:

- The only surface that is *guaranteed* to exist and *outlives* the access token is
  the IdP refresh grant (B) — and it is barred by the repo's recorded custody ruling
  and still does not fix claim placement (O2) on managed providers.
- The minimum-custody standard read (A) carries three provider-behavior
  dependencies (O1/O2/O3), at least one of which (O3) is a structural property of
  OAuth lifespans, not a wiring mistake.
- The zero-custody universal option (F) uses the front channel — barred by "no
  browser at refresh."
- Everything else (C, D, G) is non-standard or admin-credential-bearing.

**No mechanism delivers fresh claims at an unauthenticated back-channel refresh,
universally, on standard OIDC surfaces, within the repo's custody rulings.** This is
not a gap in the author's search — the design space is genuinely exhausted; the
constraints, taken jointly, contradict. Something must give.

---

## 4. Recommendation

**Keep D1's userinfo re-read as the mechanism; give up the universality constraint —
restate P2's deliverable as deployment-conditional, and surface the O3 arithmetic to
the operator.** With the trade made explicit:

1. **The mechanism choice is right for the constraint that should survive.** Among
   back-channel candidates, A is the only one that adds no mintable credential, no
   new credential class, no provider-specific surface, and no policy dependency —
   and the repo's rulings (M13's no-`offline_access` convergence as the token-harvest
   bounding control; the never-store discipline widened only once) were recorded to
   block exactly B's custody shape. Reversing them to buy O3-survivability would be
   the wrong trade: it converts a per-session presentation-only token into a
   renewable credential whose theft outlives every bound the gateway can enforce,
   and it still does not deliver roles on Entra (O2). A is the minimum-custody
   honest read; its costs are all *loud* failures, and every one of its failure
   modes fails closed. On self-administered IdPs — the population this repo's local
   deployment, and every Keycloak/Okta/Auth0-style adopter, belongs to — all three
   preconditions are one provisioning script away, and the freshness gain (window →
   interval) is real, testable, and survives at any window length.

2. **The universality constraint is the one that must give, and it should give
   explicitly, not by quiet redefinition.** The design already concedes the facts
   (D1's honest boundary, OQ-F); what remains is to stop calling the mechanism
   universal and start calling it what it is: **conditional on three deployment
   preconditions, verified loudly at sign-in (preconditions 1–2) and asserted at
   startup (precondition 3)**. P2's acceptance text should say: fresh claims within
   the access TTL *on deployments whose IdP satisfies the preconditions*; providers
   that cannot (Entra's fixed userinfo and fixed 60–90-minute tokens; B2C without
   custom policies) get their answer from C2's per-provider federation or from OQ-F's
   option (ii), and that is an owner decision recorded now, not a silent breakage
   discovered at a customer. This is OQ-F's option (i) with the wording fixed — the
   one place this opinion disagrees with the artifacts as they stand is that
   `proposal.md`'s "Its universality is one of claim-source reachability" and the
   release notes' "universal among providers whose userinfo can carry the claims"
   still smuggle the word back in; drop it. "Conditional" is honest; "universal
   among those where it works" is a tautology.

3. **State the O3 arithmetic where the operator sets the window.** The mechanism at
   an 8 h window requires the IdP to issue access tokens ≥ 8 h — an IdP-side posture
   change that extends the life of a Core-accepted DIAL bearer identity by two
   orders of magnitude against Keycloak's default (5 min → 8+ h), and that managed
   providers do not offer at all. The honest guidance, currently absent from
   `.env.example` and `docs/gateway-configuration.md`: *set
   `GATEWAY_REFRESH_TTL_SECONDS` to the IdP's true access-token lifespan; the
   freshness gain does not require a long window — the window is a session-comfort
   knob, and where the IdP's tokens are short, the short window is the correct
   configuration, not a degraded one.* The D5 validator should also be described as
   checking an operator *assertion*, with the failure it cannot catch named (a
   declared lifespan the provider does not honor — Entra's variable 60–90 min, a
   realm someone else reconfigured) so the green check is not mistaken for a
   provider fact.

**Blast-radius delta, stated against D3's existing widening.** D3 as specified
retains, per active refresh session, one presentation-only IdP access token for
min(refreshTtl, its own exp) — and under the only working configuration (precondition
3) that is a **full-window live DIAL bearer identity** in process memory: minutes
become up to 8 h; one to three presentations per flow become that plus one per
refresh; the internal-leg exposure class extends to the userinfo call (RES-19's
class, gain bounded to any-claims-for-an-existing-`sub` by the cross-check). That is
the price of P2, and it is priced. The rejected alternative B would have held, for
the same window, a **mintable, self-renewing** credential — renewable past the
gateway's own absolute cap on providers with sliding semantics, a strictly larger
blast radius per stolen byte, plus the reversal of M13 and rotation-state tracking:
the delta from A to B is the step from "a copy of a credential that dies on the
provider's clock" to "a credential that mints new credentials," and that step is
what this recommendation declines to take. Candidate F would have taken the delta
*negative* — no retained IdP credential at all, D3's widening deleted — and that is
the corner worth remembering at C2/P4: if a future owner values zero custody over
silent long sessions, F is the standard-surface shape that buys it, at the price of
the browser cadence and the "silent refresh" acceptance criterion.

**If the owner instead rules that universality must not give:** then P2 as scoped
cannot land, and the constraint that gives should be the back-channel one — B (the
`offline_access` leg) is the only O3-surviving back-channel candidate, and choosing
it means re-opening M13's no-`offline_access` convergence and re-pricing the
retention store from presentation-only to mintable; or F, which gives up "no user
interaction" instead of custody. Both are worse trades than a conditional A in this
repo's threat model, which is why this opinion does not recommend either — but they
are the honest alternatives, and the owner should see them named.

**Bottom line:** the owner's three objections are respectively partially correct,
correct (already conceded as OQ-F), and correct-and-decisive (acknowledged
structurally by D5, its operational consequence under-stated). The mechanism is not
universal and cannot be made universal at a back-channel refresh on standard
surfaces — no candidate can, and the design's search of the space was sound. It is
the right minimum-custody mechanism for a deployment whose IdP it can configure, it
fails loudly everywhere it fails, and it should ship with the word "universal"
removed, the three preconditions stated as deployment requirements, and the
window-vs-lifespan arithmetic stated where the operator sets the window. The
constraint that gives is universality; freshness, fail-closed semantics, custody
discipline, and the never-cut list all stand.
