# Design

## Context

The identity leg is the one part of the gateway still welded to a single provider's URL
grammar. `gateway/idp.py` builds the provider's three endpoints by string arithmetic —
`_AUTHORIZE_SUFFIX`/`_TOKEN_SUFFIX`/`_CERTS_SUFFIX` (`/protocol/openid-connect/…`)
joined onto the configured issuer, with `realm_of()` carving the realm name out of the
issuer's path and `_token_url()`/`_fetch_key_set()` rebuilding both back-channel URLs
from `keycloak_internal_base_url` (`gateway/idp.py:51-54, 157-165, 347-357, 475-495`).
`gateway/settings.py` carries a Keycloak issuer default and a `-- Keycloak --` section;
`gateway/federation.py` spells the callback route `/dial/callback/keycloak` and audits
the leg under the name `keycloak`; `.env.example`, `docker-compose.yml`, two operator
docs, the provisioning helper, the probes, and eight test files carry the
`KEYCLOAK_*` vocabulary — and four surfaces outside those lists spell the old name
in prose: a comment in `gateway/app.py` ("Reachability of Core or Keycloak is
measured by the flow paths"), the UTC-formatter docstring in
`gateway/__main__.py` ("correlates these stamps against Core's and Keycloak's" —
the audit-stamp correlation, mechanism vocabulary), `pyproject.toml`'s description
comment ("Core, Keycloak, or upstream MCP server"), and `docs/routing.md`'s
end-to-end sketch ("the gateway's Keycloak client"); all four join the rename
surface. Deliberately out of
the rename's scope, stated once here: the PoC-era and historical records —
`docs/HANDOFF.md`, `docs/demo-slide.html`, `docs/hosting-options.html`, and
`docs/background/*` — keep their old-vocabulary spellings; they describe the system
as it stood, not as this change builds it. C1's fresh-claims mechanism already rides this leg —
`refresh_identity` posts the refresh grant to "the *same* token-endpoint URL the
exchange uses — one spelling and no new URL construction" (`gateway/idp.py:270-299`) —
so the generalization must preserve that one-spelling property rather than grow a
second: whatever the exchange addresses, the refresh grant addresses, and both come
from the discovery document this change introduces.

The tested case is a Microsoft Entra customer-identity tenant — this paragraph and
D9 are the change's tested-case record, the one zone in the design where the tested
family's product vocabulary lives (D14 states the boundary). The relevant provider
facts, verified against Microsoft's public documentation this pass — except the two
classic-B2C discovery facts marked **live-run-to-verify** in the first bullet, which
the docs do not state and which must not be presented as verified:

- **Classic Azure AD B2C** puts the policy (user flow) in the path:
  `https://<tenant-name>.b2clogin.com/<tenant-name>.onmicrosoft.com/<policy-name>/oauth2/v2.0/authorize|token`;
  its default issuer is `https://<domain>/{tenant GUID}/v2.0/`, and the
  OIDC-Discovery-compliant issuer value is **per-policy**:
  `https://<domain>/tfp/{tenant GUID}/{Policy ID}/v2.0/` — **verified**: the tfp
  value is a per-policy token-compatibility setting ("Issuer (iss) claim"), **off by
  default**; a tenant on the default issues every policy's tokens under the
  tenant-wide issuer. Also verified: each policy serves its own metadata document,
  at
  `https://<tenant>.b2clogin.com/<tenant>.onmicrosoft.com/{policy}/v2.0/.well-known/openid-configuration`,
  and its own key set at `…/{policy}/discovery/v2.0/keys`. **Not stated by the public
  docs, and therefore live-run-to-verify, not verified (D9):** (a) that the
  well-known document is also served at the **tfp-issuer-appended** path this design
  fetches — `{https://<domain>/tfp/{tenant GUID}/{policy}/v2.0/}/.well-known/openid-configuration`
  — the documented metadata URL is spelled on the `<tenant>.onmicrosoft.com` path, a
  different shape; and (b) that the policy's discovery document's `issuer` member
  equals the tfp issuer — D3's first control refuses the document whole unless it
  does. Both facts are carried in D9's live-run list, the tasks' live-run row, and
  OQ-A.
- B2C refresh tokens are opaque and a new one is returned at every redemption (per-grant
  rotation — the latest-wins custody design already tracks it). Under the round-5
  ruling (D5) the gateway's registration at the tenant is the **confidential (web)
  shape**, not the SPA/PKCE shape the public docs state their 24-hour refresh-token
  fact for; for the confidential shape the refresh-token lifetime is 14 days by
  default with configurable sliding windows, and **that the web registration
  receives session refresh tokens at the code exchange without `offline_access`** —
  which this gateway never requests — is **live-run-to-verify, not verified**: the
  tested provider is expected to issue refresh tokens by default for its web
  registrations too, and the run verifies it (D9, OQ-B, the tasks' live-run row).
- Azure AD B2C is no longer sold to new customers (since 2025-05-01);
  **Microsoft Entra External ID** is the successor CIAM, whose authority is
  `https://<tenant>.ciamlogin.com/<tenant-id>/` with the v2.0 per-tenant issuer
  `https://<tenant>.ciamlogin.com/<tenant-id>/v2.0/` — one issuer, no policy segment,
  standard suffix discovery. **The flavor is decided (OQ-A, owner round 4): the
  owner's tenant is the classic B2C flavor**, and the live acceptance run
  (owner-dependent task row) targets it — its per-policy issuer shape and the two
  live-run-to-verify discovery facts above. The successor is the **untested
  alternative**, kept in this record for context, not as a verified shape: a future
  deployment of it is a configuration profile, not a code change, because both
  flavors are discovery-from-the-issuer with exact issuer pinning — the decision
  changes the tested literal, never the mechanism, and no Class A surface changes
  its neutral wording because of it (D14).
- Entra's *workforce* multitenant discovery serves a templated issuer
  (`https://login.microsoftonline.com/{tenantid}/v2.0`) — explicitly out of scope:
  this gateway federates **one** provider, exact-pinned (D6).

The owner's round-2 questions (recorded with their grounding in
`evidence/owner-round-2.md`) brought in a comparison this design now carries as
context: how DIAL itself configures identity providers, verified against fresh code —
Core's own IdP-login leg (`server/.../security/IdentityProvider.java`, the
`identityProviders` settings block) is **direct-configuration only**: per named
provider, a `jwksUrl` or a `userInfoEndpoint` (never discovery), with an
`issuerPattern` **regex** routing tokens to providers (`AccessTokenValidator`), and
per-provider claim paths (`rolePath`, `loggingKey`, the offline client's explicit
`authorizationEndpoint`/`tokenEndpoint`); Core's upstream OAuth clients
(`config/.../ResourceAuthSettings.java`) take explicit
`authorization_endpoint`/`token_endpoint` under static registration; the chat's
server-side auth (`apps/chat-api`) configures issuer + client id + secret + scopes
and lets openid-client discovery resolve the endpoints **at startup** (discovery
failure is a boot failure), validating the issuer against the **discovered** canonical
issuer. Both mental models already exist in the family; D11 and D12 decide what the
gateway adopts from each, and D13 states the client secret's delivery.

Two facts from C1's record are inherited as constraints: the mechanism's
provider-agnosticism premise ("no solution may assume a provider-specific surface,
endpoint shape, or claims vocabulary; whatever the flow reads must be discoverable
from the issuer" — the roadmap's P2 binding constraint, satisfied here by
construction), and OQ-F's discharge note that the userinfo provider facts (userinfo is
RECOMMENDED not REQUIRED in OIDC Discovery; its claim set is scope- and policy-filtered
— fixed on Entra, custom-policy-only on B2C) "stay on record as inputs to C2's B2C
planning". They price D10's recorded-not-built extension.

The roles mechanism needs no change and that is a design claim to verify, not assume:
`roles_source_path` is an operator-configured claim path resolved against whatever the
verified token carries (`gateway/tokens.py:157-204`), and B2C "user flows and custom
policies" emit operator-chosen claims into the token — the B2C deployment sets
`ROLES_SOURCE_PATH` to its own claim spelling and the mechanism works with zero code
change. The `<tenant>`/`<policy>` placeholders in this change's working artifacts
(this Context, D9, the live-run task rows) follow the publication discipline; real
values arrive from the owner for the live run. The normative delta spec, the release
notes, and every implementation-facing surface carry none of the tested family's
product vocabulary — the boundary D14 states.

## Goals / Non-Goals

**Goals:**

- The identity leg addresses **any** OIDC provider through its standard discovery
  document — endpoints, and nothing provider-specific, in the code; the code exchange,
  the refresh grant, and key-set resolution share the discovered endpoints (one
  spelling of the IdP leg, C1's mechanism folded in).
- The tested case configured end-to-end with placeholders: the external
  customer-identity family's classic-flavor tenant (the journey-varying issuer
  shape — Context and D9; the successor's per-tenant shape is the untested
  alternative), custom
  claims through the existing `ROLES_SOURCE_PATH` mechanism, no code change for the
  claim wiring.
- A confidential client on every identity-leg token request — the secret required at
  startup in both toggle positions, PKCE's challenge riding on top where the provider
  supports it — that absorbs a provider's PKCE incapacity by turning the challenge
  off while the client authentication stays on (D5, the owner's round-5 ruling).
- The `KEYCLOAK_*` → `IDP_*` rename and the callback-route rotation carried through
  every surface that spells them, with the rename's migration cost stated.
- The threat model's IdP-leg entries updated by this change, before implementation
  (the standing rule): the generalized back-channel boundary, the discovery-document
  trust threat, the client-secret custody, the challenge-off mode's acceptance.
- The flow's availability decision is the data path's own decision: the toolset read
  the flow authorizes through becomes the deployment-listing read (D15, the live-run
  finding's fix), whose authorization is Core's deployment resolution — the same call
  the MCP data path authorizes through — so no user is refused a toolset the data path
  would serve, and no user is admitted to one it would refuse.
- The read's refusal classes are honest to what Core's answer means: a 403 is the
  caller's own lack of access, and a 401 — Core could not validate the sign-in's
  identity token — is an operator-facing trust fault with its own fixed page and audit
  reason, never an access denial (D16, the second live-run finding's fix), so an
  authentication failure is never shown or recorded as an authorization verdict.
- Every mitigation the gateway owns landed in the delta spec, not in this prose.

**Non-Goals:**

- No userinfo-federation mode for opaque-token providers — recorded (D10), not built.
- No operator-doc row aligning Core's `issuerPattern` with the gateway's configured
  issuer — **refused by the owner** (round 4): exact issuer match stays as long as
  possible, and the `issuerPattern` mechanism can be adopted later, by a future
  change, if a real deployment needs it. The gateway pins the exact issuer (D6);
  whether a Core deployment of the same provider routes its own tokens by pattern is
  the operator's Core-side deployment concern, outside this change's surface, and
  task 5.1 gains no row for it. The refusal is the same posture as D6's templating
  rejection: a pattern, wherever it matches, weakens the exact pin.
- No multitenant issuer templating (`{tenantid}`), no issuer allowlists, no
  multi-provider federation: one configured provider, exactly pinned.
- No change to the client-facing AS surface (discovery documents, `/dial/authorize`,
  PKCE-required, CIMD/DCR, `/dial/token`, `/dial/revoke`), the upstream leg, the
  credential call, the custody design, or the router's locations — the `callback`
  alternation (`router/nginx.conf:134`) already routes the new callback spelling.
- No new settings mechanism: the renamed settings ride the same `.env`/`.env.example`
  pattern; the KMS/secret-management move is C3's scope, recorded as its input.
- No live run against the tested provider in this pass — the owner supplies the
  tenant; the task row is owner-dependent and says so.

## Decisions

### D1 — Standard OIDC discovery from the issuer, suffix spelling, one IdP leg

The provider's endpoints come from the issuer's OpenID Connect discovery document,
fetched at `{issuer}/.well-known/openid-configuration` — the **suffix-appended**
spelling, not RFC 8414's host-inserted one, because every provider this gateway
targets serves or is expected to serve that spelling: the local instance does; the
tested family's flavors do or are expected to, with one open fact — whether the
classic flavor's per-journey-issuer-appended path this decision fetches also serves
the document is a live-run fact, not a documented one (Context, D9); and the
host-inserted form is the OAuth 2.0 authorization-server variant that OIDC providers
are not required to serve alongside it. The alternative
— keeping per-provider suffix tables and adding a table for the tested family — was
rejected as the status quo's second instance: N providers, N tables, and the new
table still wrong the day that vendor moves a segment. Discovery is the OIDC Core mechanism the roadmap
names, and it is the only one whose answer is guaranteed current against a live
provider's own spelling.

One spelling of the leg is preserved by construction: the discovered
`authorization_endpoint` builds the browser redirect, the discovered `token_endpoint`
serves both the code exchange and `refresh_identity`'s refresh grant, and the
discovered `jwks_uri` serves key-set resolution. `realm_of()`, the three suffix
constants, and `_token_url()`'s arithmetic are deleted; there is no fallback endpoint
construction anywhere, so an unreachable or invalid discovery answer fails the leg
closed at the point of use with the operator-facing error class the IdP failures
already use. This lands as the delta spec's first ADDED requirement. D11 (owner
round 2) adds the operator-configured endpoint set as an explicit **alternative
source**; the no-fallback property this decision states is about runtime
construction — no arithmetic, no fallback-on-failure — and D11's alternative is
chosen at configuration time, never at runtime, so the property stands.

### D2 — The back-channel split survives as an optional origin override

The internal-base setting exists for one real reason: the local Keycloak instance's
browser-facing origin (`https`, self-signed certificate) is impractical for the
gateway's server-to-server calls, which sidestep it over the plain-http internal port
— and the same document is served on both ports at the same path. Under
generalization this becomes an explicit, optional **back-channel base**
(`IDP_BACKCHANNEL_BASE_URL`): when set, the discovery fetch and the token/key-set
calls are addressed to the override's origin with the **discovered path kept** —
scheme and host swapped, nothing else — while the browser-facing authorization
redirect keeps the discovered `authorization_endpoint` untouched and issuer matching
stays pinned to the configured issuer, whichever base a call used.

The alternatives were rejected for stated reasons: configuring two complete endpoint
sets (browser-facing and back-channel) doubles the operator's spelling surface and
re-creates the drift problem discovery exists to remove; deriving the back-channel
endpoints by path mirroring without discovery would be a second, hidden arithmetic.
A provider with one hostname — the single-origin external-provider shape —
configures only `IDP_ISSUER` and leaves the override unset, which is the default. The path-preserving
swap is what keeps the override honest: it can only re-address the provider's own
paths, never invent one.

### D3 — The discovery document is validated, not trusted

The document steers outbound calls that carry credential material — the code, the
carried session-bound refresh token, and the client secret — so a
hostile or misfetched document is an integrity threat to the leg, priced in the SIA
(EP5). The controls, landed as the delta spec's second ADDED requirement: the
document's `issuer` member MUST equal the configured issuer exactly (the strong pin —
a document claiming another authority is refused whole); every used endpoint MUST
share the origin of the configured issuer, or of the configured back-channel base
where one is set (the SSRF-shaped bound — no endpoint the document names can steer
credential-bearing calls to another origin, the same discipline the CIMD fetch
applies to its URLs); plain `http` is refused without the explicit override (the
override is the operator owning the plain leg, the existing RES-19 acceptance);
redirects are not followed; the response is size-capped and parsed under the
existing bounded-parsing discipline.

### D4 — Lazy first-use fetch, per-process cache, bounded TTL; no startup fetch

The document is fetched when the identity leg first needs it and cached per process
for a configurable TTL (default 300 s, `IDP_DISCOVERY_CACHE_TTL_SECONDS`). The
alternatives, rejected: **startup fetch** would make the container's boot and the
compose-boot gate depend on the IdP's availability — for an internet IdP that is an
availability coupling the deployment cannot order (compose `depends_on` cannot wait on
an external internet provider), and it would fail the boot for a provider outage that every already-minted
token survives anyway; **no cache** would spend one discovery fetch per flow on the
public endpoints' rate limits. The lazy shape's honest costs: a cold start's first
sign-in fails closed if the provider is unreachable (the existing operator-facing leg
failure, unchanged in kind), and a provider's endpoint change goes unnoticed for at
most the TTL — a documented bound, and the JWKS leg already re-fetches on a
`kid` miss, so signing-key rotation is not TTL-bound.

### D5 — The gateway is a confidential client at the identity provider; the PKCE toggle governs the challenge only (amended by the owner's round-5 ruling)

**The ruling (owner round 5, issued during the live-run setup; recorded with its
reasoning and the per-artifact semantic diff in `docs/evidence/c2/authoring-round-5.md`):**
the gateway is NOT a public client to the identity provider — it is a private
(confidential) client. The modes are "client secret + PKCE" or "simply client
secret" — never "just PKCE". The design omission the ruling corrects is the gateway
operating as a public client at all; the provider-registration bypass the old
public-client shape forced at the tested tenant (the public-client-flows toggle the
owner had to enable there — D9 records the concrete registration shape) was the
wrong answer to that omission, not a mode to keep. The reasoning, as the ruling
carries it: the gateway is a **first-party client** of the deployment it serves, not
an untrusted third-party application; it already holds higher-grade secrets than a
client secret (the signing key, the custody key), so requiring one adds no new
custody class; and the RFC 9700-aligned shape for a confidential client is
**client authentication plus PKCE** — the challenge composed on top of the secret,
never a public client whose only binding is the challenge.

The amended semantics, as the design now stands (the prior D5 — the
conditional-secret design with its no-PKCE-only startup refusal and its
default-mode-never-presents converse — is superseded; the semantic diff is in the
round-5 evidence):

- **The client secret is required at startup, in both toggle positions.** A missing
  or blank `IDP_CLIENT_SECRET` refuses startup with an operator-facing error naming
  the setting, whether `IDP_PKCE_ENABLED` is on or off — no deployment of this
  gateway runs without one, so the "no-secret deployment" exposure class the prior
  design permitted no longer exists (removed by the ruling, recorded in the SIA and
  the threat model).
- **The exchange and the refresh grant authenticate the client with the secret on
  every identity-leg token request, in both modes.** The secret rides the token leg
  only — TLS-protected to the discovered or directly-configured token endpoint,
  never any other leg, never a log, a page, or an error message.
- **`IDP_PKCE_ENABLED` (default `true`) governs only whether the S256
  challenge/verifier rides on top of the client authentication.** On: the
  identity-leg authorization redirect carries the challenge and the exchange
  presents the verifier — client authentication and PKCE together, the RFC 9700
  shape. Off, for a provider that cannot support PKCE: the redirect carries no
  challenge and the exchange presents no verifier — the client secret alone
  authenticates, RFC 6749's original confidential-client model.

The precise interaction with never-cut 2 — the **upstream** PKCE verifier never
leaves Core — is unaffected by the amendment and re-verified this round: that
verifier is Core's, per toolset, nulled on every public projection, untouched by
this change on every path (the code as built confirms it; task 4.3's check, and the
round-5 evidence records the re-verification). What the toggle varies is the
**gateway's own** PKCE on the **IdP leg only** — the binding that protects the
IdP-leg code while it crosses the browser and the plain-http front door. The
client-facing AS surface is unchanged: harness clients still MUST send PKCE to
`/dial/authorize`, the AS metadata still advertises S256, and the delta spec
carries the scenario that pins this. The challenge-off mode's residual (an
intercepted IdP-leg code is exchangable only by a party that also holds the secret,
on a front door that is plain http today) is priced in the SIA and disclosed in the
threat-model delta — the T3-3/RES-1 interception class (the shared callback-URL
class; the identity-leg callback is E6, the upstream's is E7) — with the client
authentication now an **inherent** control (it is on in every mode), not a
mode-conditional compensating one; what the toggle drops is the challenge binding
alone.

### D6 — Varying-issuer providers: exact pinning, one provider, no templating

The configured issuer is the one issuer this deployment federates — for a provider
whose issuers vary across its sign-in journeys, the one federated journey's. The
tested family's two flavors spell that issuer differently (the classic flavor's
journey-scoped form and the successor's per-tenant form — Context, D9); the owner's
tenant is the classic flavor (OQ-A decided), so the configured literal is the
journey-scoped one — but which spelling a deployment configures decides only the
literal, never the mechanism. What
is by construction is **gateway-side**: the issuer check is exact-string against the
configured issuer, so any token whose `iss` differs in any way — a sibling journey's
included — is refused, and no discovery document can widen the pin (D3 validates the
document's `issuer` against the same value). What is **provider-configuration**, not
construction: whether a sibling journey's tokens arrive with a different `iss` at all
— that requires the provider to issue journey-distinct issuers, which in the tested
family is an opt-in per-journey token-compatibility setting, off by default
(verified, Context); under the family-wide default issuer, sibling journeys' tokens
share one `iss` and the pin cannot distinguish them — the operator prerequisite task
5.1 states in provider-neutral terms and the live run verifies against the family's
concrete setting (D9). The verification requirement's issuer check stays
exact-string; the delta spec adds the scenario that names the other-journey refusal
so a from-spec reimplementation cannot "helpfully" fuzzy-match.
Rejected: supporting the tested vendor's `{tenantid}` templated issuer form (a
multi-provider feature — this deployment federates one provider, and a templated
match would weaken the pin to a pattern); deriving the issuer from the discovery
document instead of configuring it (the configured issuer is the trust anchor the
document is validated **against** — D3's first check — so it must come from the
operator, not from the thing being checked).

### D7 — The callback route rotates to `/dial/callback/idp`

The identity-leg callback route rotates `/dial/callback/keycloak` →
`/dial/callback/idp`, and the audit leg's fixed-vocabulary name rotates with it
(`leg="keycloak"` → `leg="idp"`). The router needs no change: its authorization-surface
alternation matches on the `callback` segment
(`location ~ ^/dial/(callback|jwks\.json|authorize|token|register|revoke)(/|$)`),
which both spellings share — verified against `router/nginx.conf:131-134`. The route
constant, the identity-provider client's registered redirect URI (written by the
provisioning helper), the probes that drive the callback, and the docs rotate in one
lockstep task; a half-rotated deployment is a sign-in that never returns, which is
why the tasks make it atomic. The migration cost is disclosed: in-flight flows at the
upgrade instant reference the old route in their IdP-leg redirect, which the router's
alternation still forwards to the gateway — and the gateway answers it with its plain
404, because no handler resolves the old route. No handler serves it, no flow state is
touched by the answer, and no credential is at stake; the affected flows are already
interrupted ones whose window is bounded by the flow TTL (10 minutes), so the
flow-state property the prose must state holds — the old route lands on nothing, not
on a different page. Core is unaffected (the IdP callback is not in
Core's allowlists; only the upstream callback is Core's).

### D8 — The rename's boundary: the gateway's IdP vocabulary vs the local dev instance's own plumbing

The gateway-consumed settings rename to the provider-neutral vocabulary:
`IDP_ISSUER`, `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET`, `IDP_CLIENT_SCOPES`, plus the new
`IDP_BACKCHANNEL_BASE_URL`, `IDP_PKCE_ENABLED`, `IDP_DISCOVERY_CACHE_TTL_SECONDS`, and
the directly-configured endpoint trio of D11 (`IDP_AUTHORIZATION_ENDPOINT`,
`IDP_TOKEN_ENDPOINT`, `IDP_JWKS_URI`);
the settings model's section header, the compose file's gateway environment block,
`.env.example`'s IdP section, both operator docs, and the README follow. The
**helper-scoped** settings — `KEYCLOAK_ADMIN_URL`/`ADMIN_USER`/`ADMIN_PASSWORD`,
`KEYCLOAK_TOKEN_CLIENT_ID`/`SECRET`, `KEYCLOAK_IDENTITY_CLIENT_ID`/`SECRET` — keep
their names. The reason is an honesty claim, not a convenience one:
`scripts/provision_keycloak.py` drives a **Keycloak Admin REST API** — it can
provision only Keycloak, and those settings describe that local instance's own admin
and test-user machinery, not the gateway's IdP abstraction. Renaming them to `IDP_*`
would advertise a generality the helper does not have; the local environment remains
a Keycloak deployment, and its helper keeps its honest name (`provision_keycloak.py`
stays, and the file's own name says what it provisions). The tested external tenant
is configured against the gateway's `IDP_*` settings directly — no provisioning
helper exists or is needed for it (its client registration is created in the
provider's own admin portal by its owner). This split is a decision of record,
**confirmed by the owner** (OQ-D decided, round 4): the helper-scoped settings keep
their names. The owner's principle, on record verbatim: **the gateway itself is
generic, but examples and tests can and should be IdP-specific.** The principle
reaches past the settings block, and the artifacts already agree with it: the
provisioning helper keeps its Keycloak Admin REST API vocabulary end to end, and the
probe scripts' Keycloak-specific fixtures — the login-flow driving against the local
development instance — stay as they are, because the local deployment is a Keycloak
deployment and its examples and tests may say so. The ruling is the same position
D14 states for the tested case's vocabulary, and the two read as one: the gateway's
own surfaces are provider-neutral because the gateway is generic; the working
artifacts may be IdP-specific where they record a specific instance's own facts —
D8 applies that to the local deployment's artifacts, D14 to the tested case's
record, and neither ruling narrows the other.

**The deployment-shaped defaults are retired, not renamed.** The rename touches the
exact lines the roadmap §D0b exposure list names — "the internal instance name
across `.env.example`, `docker-compose.yml`, `gateway/settings.py`'s default" — so
this change retires those exposures instead of carrying them forward under a new
name: `idp_issuer`'s default becomes a provider-neutral placeholder
(`https://idp.example.com/`, the RFC 2606 reserved domain — it names no real
provider, so a forgotten setting fails loudly at the discovery fetch rather than
silently pointing at a live-looking host), `docker-compose.yml`'s `IDP_ISSUER` line
loses its Keycloak-realm fallback, and `IDP_BACKCHANNEL_BASE_URL` in compose becomes
the explicit override's example — `IDP_BACKCHANNEL_BASE_URL: ${IDP_BACKCHANNEL_BASE_URL:-}`,
unset by default, which is what D2's "optional, unset by default" claim already
required the file to say (today's hardcoded `http://keycloak:8900` contradicts it).
The local profile's real values move to the local deployment's `.env` (gitignored)
and are documented in `docs/local-environment.md` — a local-deployment fact, D8's
own boundary; `.env.example`'s IdP section shows the placeholder shape only. The
compose-boot gate is unaffected: D4's lazy first-use fetch means the gateway boots
and probes green without a reachable issuer, and the local probe runs (task 2.4)
against the `.env`-supplied values. Task 2.6 carries this ruling; D0b's list shrinks
by the items this change retires.

### D9 — The tested case: the standard surface both flavors of the tested family share, placeholders everywhere

This decision is the change's tested-case record — with the Context paragraph, the
one zone in the design where the tested family's product vocabulary lives (D14
states the boundary); every mechanism it records is stated provider-neutrally in D6
and the delta spec. The design targets what classic B2C and External ID share — discovery from the
configured issuer, exact issuer pinning, JWT access tokens verified against the
discovered key set, opaque rotating session refresh tokens (which the latest-wins
custody already tracks), operator-configured scopes (`openid` is required by
Entra/B2C to obtain an OIDC token where the local realm's guidance forbids adding it
— a per-provider deployment fact the operator reference now states per provider), and
operator-configured roles claim path. The owner's tenant is the **classic flavor**
(OQ-A decided, round 4): the live run verifies its issuer literal — the
journey-scoped (tfp) spelling — and its facts below, and the successor flavor is the
**untested alternative**, its per-tenant shape kept in the Context record as
context, not as a verified shape; the mechanism is one. Four provider facts the live run must verify are stated as such in the tasks: that the chosen client registration shape — under the
round-5 ruling (D5) a **confidential (web) client** on the authorization-code flow,
authenticating every token request with its secret, with the PKCE challenge on top
where the tenant supports it, redirect URI at the gateway's public origin, and **no
public-client-flows bypass at the registration** (the toggle the old public-client
shape forced there is never used; the client is registered confidentially, secret
issued by the provider) — receives session refresh tokens at the code exchange
**without** `offline_access` — live-run-to-verify for the web shape (the tested
provider is expected to issue refresh tokens by default for its web registrations
too — Context, OQ-B; the public docs' "always have a refresh token lifetime of 24
hours" fact is the SPA/PKCE shape's, no longer this gateway's shape), with the
already-spec'd loud no-refresh-token sign-in refusal as the
failure shape if it does not hold (the successor flavor's answer is the untested
alternative's open fact); that `IDP_SSO_SESSION_MAX_SECONDS` is set to
the tenant's actual refresh-token window (the confidential shape's 14-day default
with configurable sliding windows — the run records the tenant's actual value),
the
C1-landed startup assertion; that b2clogin serves the well-known document at the
**tfp-issuer-appended** path D1 fetches — the docs state the metadata URL on the
`<tenant>.onmicrosoft.com` path, a different spelling, and say nothing about the
`/tfp/…` form (Context, OQ-A); and that the policy's discovery document's `issuer`
member equals the tfp issuer — D3's first control refuses the document whole unless
it does, and the prerequisite is the policy's per-policy "Issuer (iss) claim" setting
(task 5.1's operator row states the generic journey-distinct-issuance prerequisite;
without the setting, a tfp-configured deployment fails every sign-in at issuer
verification, diagnosable only from that stated prerequisite and this record). All prose in
this change's working artifacts carries
`<tenant>`/`<policy>` placeholders — no real issuer values, per the publication
discipline; the normative and implementation-facing surfaces carry none of the
family's product vocabulary at all (D14).

### D10 — Recorded, not built: opaque-token IdPs via a userinfo-federation mode

The open extension: an identity provider whose access tokens are opaque (or
claim-less) cannot serve the claim-copy mechanism, which reads and verifies a JWT. A
userinfo-federation mode — present the carried session refresh token, receive the
opaque access token, read the claims from the userinfo endpoint — is the only
standards-based option for that provider class, and it is deliberately **not built
here**. The recorded facts that gate it, from C1's overruled-mechanism record:
userinfo is RECOMMENDED, not REQUIRED, in OIDC Discovery (a provider may not have
one); its claim set is scope- and provider-configuration-filtered — fixed on one
flavor of the tested family, reachable only through custom journeys on the other
(Context) — so the claims the gateway must read (notably the roles path) are not
guaranteed reachable; and a claims-from-userinfo design moves the trust basis from a
signature-verified token to TLS-plus-issuer on a second endpoint, which changes the
verification requirement's shape and would need its own SIA. The extension is
recorded in this design (this decision) as the deferred direction it already is in
the roadmap's P4 line; nothing in this change's specs or code anticipates it beyond
what the discovery requirement already provides (the discovery document names the
userinfo endpoint when the provider has one; the gateway simply does not call it
yet).

### D11 — Direct endpoint configuration: an explicit alternative source, never a fallback (owner round 2, question 1)

The owner asks whether the gateway can allow direct configuration of the main IdP
parameters ("two URLs, scopes etc") in addition to discovery, because discovery is
not always working and direct configuration sometimes resolves compatibility
problems. Two observations shape the answer. First, most of what the owner names is
already direct configuration: the client id, the client secret, the scopes, and the
roles claim path are operator settings today and stay so — discovery only ever owned
the three endpoint URLs. Second, the compatibility claim is real, and this change
itself carries an instance of it: D9's first live-run-to-verify fact is whether the
tested family's classic flavor serves the well-known document at the
per-journey-issuer-appended path D1 fetches, and if it does not, the design as D1
alone stood had **no answer for that flavor**
(D3 refuses the unfetchable document; D1 constructed no fallback). Direct
configuration is the remedy for exactly that provider class, so it is **adopted** —
as an explicit alternative source, never a fallback.

**The shape.** Three settings: `IDP_AUTHORIZATION_ENDPOINT`, `IDP_TOKEN_ENDPOINT`,
`IDP_JWKS_URI` — the OIDC discovery member names and Core's
`authorizationEndpoint`/`tokenEndpoint` concepts, so the vocabulary is one a support
engineer already reads elsewhere in the family (D12). The set is all-or-nothing: a
partial set refuses startup, naming what is set and what is missing. Where the full
set is configured, the discovery fetch is **not attempted at all** — not
fetched-and-ignored, skipped — and the three configured endpoints serve the browser
redirect, the code exchange, the refresh grant, and the key-set fetch. One spelling
of the leg is preserved exactly as C1's inheritance constraint requires: at any
moment the leg has exactly one endpoint source, knowable from the configuration
alone, never from runtime events. Where the set is absent (the default), discovery
per D1–D4 applies unchanged.

**Rejected shapes, with reasons.** Per-member override (discovery with individual
endpoints overridden) would give the leg two sources whose disagreement is
undetectable — the drift problem discovery exists to remove, recreated — and breaks
the one-spelling property at the boundary between members. Runtime fallback on
discovery failure would make the effective source depend on the provider's
availability: a provider outage would silently become a configuration change, and
the leg's fail-closed discipline (D4's cold-start refusal, the fixed-vocabulary
operator-facing failures) exists to make provider faults visible, not maskable.

**Validation, at startup.** Each of the three is a well-formed absolute URL and MUST
be HTTPS unless it shares the configured back-channel base's origin — the override
is the operator's explicit plain-leg ownership, the same discipline discovery mode
applies to the fetch and the document's endpoints. Deliberately **not** carried over
from D3: the origin-bound-to-issuer rule. D3's bound exists to constrain a
provider-**asserted** document — an input from outside the trust boundary; in direct
mode there is no provider-asserted input at all, the operator's URLs are the
deployment's own trust claim (the same trust level as `IDP_ISSUER` itself), and a
same-origin rule would refuse the legitimate split-origin providers that are part of
the compatibility class direct mode exists to absorb (a provider whose token
endpoint lives on a separate host from its issuer). The HTTPS-or-override rule stays
because it is not about trust anchors but about never carrying the code, the carried
refresh token, or the client secret over a plain leg the operator has not explicitly
owned. One rule crosses the mode boundary: the configured issuer's scheme is
validated at startup in both modes — a plain-http issuer refuses startup whether
discovery would fetch it or the direct trio serves the legs — because the configured
issuer is the identity anchor either way (the exact pin's comparison value in both
modes, the discovery fetch's target and the document's validation target in
discovery mode), and the plain-leg ownership the override grants reaches the
endpoints the leg calls, never the anchor itself; one rule, one refusal, no
mode-specific plain anchor.

**Mechanics carried over unchanged.** The back-channel override applies to the
configured endpoints exactly as to discovered ones: the token and key-set legs are
re-addressed to the override's origin with the path kept, and the browser-facing
authorization endpoint stays untouched. Issuer pinning is unaffected: the inbound
token's `iss` check stays exact-string against `IDP_ISSUER` (D6), in direct mode as
in discovery mode, and nothing the operator configures widens it.

**The mode's priced trade, stated rather than mitigated.** In discovery mode a
provider's endpoint change propagates within the cache TTL (D4); in direct mode
nothing propagates it — a moved endpoint surfaces as a leg failure with the
fixed-vocabulary operator-facing error, and keeping the endpoints current is the
operator's responsibility, stated in the operator reference (task 5.1). The security
posture: the forged-document threat (DT-EP5-1) cannot exist in direct mode — there
is no provider-asserted input to forge; what replaces it is the
operator-misconfiguration class (DT-EP5-8: a mistyped or stale endpoint), priced in
the SIA, bounded by HTTPS, by the operator being inside the trust boundary, and by
the loud fixed-vocabulary failures a wrong endpoint produces at first use.

This decision amends the P4 outcome line ("reading the provider's endpoints and
capabilities from standard OIDC discovery") per the owner's round-2 ruling recorded
in `evidence/owner-round-2.md`; the roadmap's wording follows at archive time. OQ-A's
worst case is answered by it: if the per-journey-path discovery fact fails for the
classic flavor, the operator configures the three endpoints at that flavor's
documented spellings and keeps the journey issuer for pinning (OQ-A records the
concrete spellings).

### D12 — Alignment with how DIAL itself configures identity providers: partial, and mostly already held (owner round 2, question 2)

Grounded in fresh code — Core at `6dae044afb008e99cdd044ae1dcb97385c4fbefc`
(branch `development`, fast-forwarded this pass), the chat's `apps/chat-api` at
`e09fc75b34faa06b128ad0899a2835876ac5ce40` (`origin/development` as fetched; the
chat checkout is dirty and was not pulled — `evidence/owner-round-2.md` records the
fetch attempts and the dirty-state rule). The family configures IdPs in **both**
mental models, so "make it similar" needed the comparison first; the facts are in
the Context paragraph above and the evidence file. Core itself carries both
models — direct for its IdP-login leg and static upstream registrations,
discovered for its upstream DCR clients, whose `credentials` module at `6dae044`
builds `.well-known` URLs in both the RFC 8414 and the OIDC spellings and fetches
a five-spelling runtime fallback set off the resource endpoint to feed
registration — the exact fallback mechanism D1/D11 refuse for the gateway's IdP
leg, whose answer to the same spelling-compatibility problem is D11's
configuration-time alternative (one source per leg, chosen by configuration,
never by which well-known spelling answered). The decision, item by item:

**Adopted.** (a) The direct-mode settings of D11 use the endpoint vocabulary the
family already shares — `IDP_AUTHORIZATION_ENDPOINT`/`IDP_TOKEN_ENDPOINT`/
`IDP_JWKS_URI` match the OIDC discovery member names and Core's
`authorizationEndpoint`/`tokenEndpoint` concepts (Core's static OAuth resource
registration requires exactly the first two, explicitly), so a support engineer
moving between Core's static clients, a discovery document, and the gateway's direct
mode reads one vocabulary. (b) The issuer/client-id/secret/scopes vocabulary is
already aligned with both shapes — the chat's `issuer`/`clientId`/`clientSecret`/
`scope` and Core's `clientId`/`clientSecret` map member-for-member onto
`IDP_ISSUER`/`IDP_CLIENT_ID`/`IDP_CLIENT_SECRET`/`IDP_CLIENT_SCOPES`; recorded here
so the coherence is a checked fact, not an accident. (c) The gateway's **discovery
mode is the chat's mental model** — one issuer spelling in, discovery resolves the
endpoints, client credentials and the roles-claim field as settings — so the support
team's chat-side instincts transfer to the gateway's default mode as-is.

**Refused, with reasons.** (a) Core's `issuerPattern` regex: it is a multi-provider
**routing** feature (one Core fronts N providers; the regex picks), and adopting it
would weaken the gateway's exact pin (D6, DT-EP5-5) to a pattern — the same
weakening D6 already rejected in the tested vendor's `{tenantid}` templating; the gateway
federates one provider, and the pin is a security decision, not a convenience. (b)
The chat's startup discovery with boot-coupling: D4's lazy first-use is deliberate —
the compose-boot gate must not depend on an internet IdP's availability, and the
chat's own README documents the cost of the opposite choice (a private-CA
misconfiguration means the application does not boot). (c) The chat's
canonical-issuer-from-discovery: the gateway pins the **configured** issuer and
validates the document against it (D3/D6) — strictly stronger, the document cannot
redefine the trust anchor. (d) Core's `userInfoEndpoint` leg for opaque tokens:
already this change's recorded-not-built D10; Core's own sample settings show the
shape exists in the family where a deployment needs it. (e) The chat's per-provider
flavor templates (per-flavor default scopes): the gateway is
one-provider-per-deployment and provider-neutral, and the chat's defaults include
`offline_access` — a scope the gateway must never request (the custody design's own
rule); importing flavor defaults would import scope decisions that are wrong for
this leg.

**Noted for the deployment workstream, not this change:** the chat's private-CA
mechanism (a mounted CA bundle plus an environment variable) is the family's answer
to self-signed-TLS providers; the gateway's C2 answer to that class is the
back-channel override for the local shape, and a private-CA need in the tested
external-TLS shape is a packaging fact (C3/P5's pod), not an IdP-leg setting.

Verdict: **partial alignment, and most of it was already in the design** — the
discovery mode matches the chat, the direct mode (D11) matches Core's
explicit-endpoint spelling, and the one behavior a support engineer must not expect
to transfer (regex issuer matching) is refused with the security reason on record.

### D13 — The client secret's delivery: the environment slot in C2; variants are C3's (owner round 2, question 3)

What the design already answers: the secret's home is the `IDP_CLIENT_SECRET`
setting (`SecretStr`, never logged, never in `repr` — DT-EP4-1's controls); under
the round-5 ruling (D5) it is **required at startup in both toggle positions** (a
missing or blank secret refuses startup naming the setting, whichever way
`IDP_PKCE_ENABLED` is set) and is **presented on every identity-leg token request**
— the exchange and the refresh grant alike, in both modes, TLS-protected on the
token leg and never any other leg; its committed shape is the `.env.example` placeholder with an
empty value (never-cut 6 — the committed file carries no real secret; the running
deployment's `.env` supplies it); and its move under deployment secret management is C3's recorded
scope (the production roadmap's P1 — "the client secrets out of env files" —
packaged with the pod's secret injection in C3 = P5+P1+T3). What was not stated
anywhere is the delivery **mechanism** between "the setting exists" and "the process
holds it" — this decision states it: in C2 the secret is delivered as an
**environment variable** to the gateway process, sourced from the deployment's
`.env` (compose) or the deployment environment — the same delivery every other
secret the gateway holds uses today (the signing key, the custody key), one delivery
pattern for the whole secret class, never argv, never a file the gateway reads.
**No file-mounted variant is added in C2:** a mounted-file source would be a second
delivery mechanism with its own reading, permission, and rotation code and its own
SIA coverage, built now and re-designed immediately by C3's P1 (the roadmap's own
packaging rationale: "secrets out of env files *is* the pod's secret injection"), for
zero security gain in the compose deployment C2 targets; where a deployment wants
file-based or orchestrated injection before C3, the deployment feeds the environment
variable from its own secret material (compose `env_file`, a K8s secret's env
injection) without the gateway knowing the difference. The answer lands where a
reader looks: this decision, the operator-reference task row (5.1 gains the delivery
statement), and the `.env.example` IdP section's comment that task 2.3 carries.

### D14 — The vocabulary boundary: provider classes in the normative and implementation-facing surfaces; the concrete tested provider only in the change's working artifacts (owner round 3)

The owner's round-3 ruling: the exact-match issuer principle (D6) stands, and the
tested provider's product vocabulary — "policies" and its kin — leaves the spec and
the implementation. The tested provider is an example of the class the mechanism
covers, and the artifacts that tell a reader what to build or operate speak of
classes and mechanisms, never of the product. This decision fixes where each kind of
vocabulary may live, as a stated rule the sweep is checkable against.

**Class A — provider-neutral surfaces: zero product vocabulary.** The delta spec,
all of it (requirement text, scenarios, amendment notes); the release-notes draft
(both audiences); and every implementation-facing artifact and prescription —
settings names, code identifiers, route spellings, error text, and the
operator-facing documentation content the tasks prescribe (`docs/gateway-configuration.md`,
`docs/local-environment.md`, `README.md`). These name provider classes and
mechanisms only. The class vocabulary this change coins, used consistently from here
on: a **varying-issuer provider** (issuers that vary across the provider's sign-in
journeys or tenants); a **sign-in journey** (the provider-side configuration path
that issues tokens — the neutral term for what the tested family calls a policy or
user flow); the **one federated journey's issuer** (what D6 pins); and
**journey-distinct issuance** (the provider-side property that makes the pin
distinguish journeys). Generic provider vocabulary stays generic: "session policy"
was never the product concept and remains as it was.

**Class B — working artifacts: the tested provider may be named, for its own facts
only.** The design's tested-case record (the Context paragraph and D9), the open
questions that track live-run facts (OQ-A, OQ-B, OQ-E), the tasks' live-run rows (7.1,
7.2), the evidence records, and the proposal's tested-case identification (its
mechanism bullets stay Class A). These may name the concrete family, its flavors,
its URL grammar, and its portal settings, because they record operational facts
about the tested deployment that generic wording cannot state without losing their
content — which issuer spelling the owner's tenant uses, whether the family's
discovery serves a given path, which portal property must be enabled. Mechanism
statements inside Class B zones still use Class A vocabulary: D9 records what the
family shares, and the mechanism it shares is stated once, neutrally, in D6 and the
delta spec.

**The OQ-D agreement, stated so the two rulings read as one position.** The owner's
round-4 ruling on OQ-D — the helper-scoped `KEYCLOAK_*` settings keep their names,
on the principle that the gateway itself is generic but examples and tests can and
should be IdP-specific (D8, confirmed) — is the same spirit this boundary states:
Class A surfaces are provider-neutral because the gateway is generic; Class B
working artifacts may name the concrete provider for their own facts. D8 applies the
principle to the local deployment's artifacts (the provisioning helper, its
settings, the probes' local-instance fixtures); D14 applies it to the tested case's
record. Checked against each other this round: no artifact conflicts with the
principle — the provisioning helper keeps its Keycloak Admin REST vocabulary, the
probe scripts' Keycloak-specific fixtures stay, and the operator-doc prescriptions
(5.1/5.2) stay class-vocabulary-only, which the principle requires of the gateway's
own surfaces and permits of its examples.

**The design's mechanism sections: Class A vocabulary plus family anaphora, never
product names.** The sections of this design outside the Class B record zones — the
Goals, the Non-Goals, the decisions other than the record (D1–D8, D10–D13), the SIA,
the Risks, and the Migration Plan — state their mechanisms in Class A vocabulary and
may refer to the tested case by **family anaphora** ("the tested family", "either
flavor", "the classic flavor", "the successor", "that vendor", "the tested external
tenant/provider", "the tested deployment/shape"), each mention resolving through the
Context/D9 record it points at or sits beside; the sections that carry it today are
Goals, Non-Goals, D1, D6, D8, D10–D12, the SIA, and the Migration Plan's
provider-configuration step. They never name the family, its flavors, its URL
grammar, or its product concepts — the anaphor is a pointer into the record, not
vocabulary a reader must already hold. One term is ruled explicitly so the sweep's
pattern list and its dispositions agree: **"customer-identity"** (and its compound
"the external customer-identity family") is the generic CIAM category — external
providers whose user population is the deployment's customers — not any vendor's
product vocabulary; it sits on the sweep's pattern list deliberately, so every hit
is dispositioned against this ruling rather than passing as a presumed non-hit.

**Where the provider-specific operator facts live now.** The operator reference
(task 5.1) states the prerequisite in provider-neutral terms — a varying-issuer
provider must be configured for journey-distinct issuance, or its journeys' tokens
share one `iss` no issuer check can distinguish — because that is the honest content
for every provider of the class, and the operator of the tested family finds the
concrete property name ("Issuer (iss) claim", off by default) in the D9 record and
the live-run row (task 7.1 verifies with it enabled and records the portal path).
F3's diagnosability rationale survives intact: an operator of any varying-issuer
provider who sees every sign-in fail at issuer verification finds the stated
prerequisite in the reference, and the tested family's operator reaches the concrete
setting through the record this change ships.

**The check.** A grep of the Class A surfaces for the product vocabulary — the
family's names, its flavor names, its URL segments (`tfp`, the login hosts), and its
product concept words (policy/user flow as the sign-in-journey concept) — returns
nothing; every remaining hit in the change folder sits inside an enumerated Class B
zone, is family anaphora in a design mechanism section (the intermediate tier stated
above), is a quotative mention of the working artifacts' `<tenant>`/`<policy>`
placeholder tokens — task 6.1's gate row names them to state what those artifacts
carry, using no product concept — or is a D8-scoped local-deployment fact (the
local development instance's own name — a different boundary, decided before this
one, now owner-confirmed, and the same position this one states: the OQ-D
agreement above). The round-3 evidence note records the sweep and every hit's
disposition.

**The implementation-surface half of the check is the change's own gate,
machine-checked.** The family's names over the Class A implementation surfaces —
`gateway/`, the tests, `pyproject.toml`, `.env.example`, `docker-compose.yml`,
`README.md`, and the two operator docs — return nothing once task 2.7's
neutralizations land, and that grep is the machine check behind this decision's
Class A claim: the gate row (task 6.1) re-runs it, so the claim cannot be false
with every stated gate green. That gate is **distinct from the D8-scoped
local-deployment allowances**: D8 licenses the local development instance's own
name where a surface records the local deployment's own facts (the provisioning
helper's vocabulary, the probes' and tests' local-instance fixtures, the operator
docs' local-instance reading guidance) — it never licenses the tested family's
names on an implementation surface. The pre-existing family-name mentions on
those surfaces (the session-bound comments' provider comparisons in
`gateway/settings.py` and `.env.example`, the README's tested-case clause and
roadmap-item tail, the operator reference's session-bound row) are content this
change sweeps because it owns the surface — neutralized by task 2.7 into
provider-class wording, not deleted history. The historical records the Context
excludes keep their spellings outside both the gate and the allowances.

### D15 — The flow's availability oracle is the deployment-listing read (the live-run finding's fix)

**The finding (diagnosed, recorded at `docs/evidence/c2/availability-read-diagnosis.md`).** The live B2C run put the first non-admin identity through the flow and exposed a false denial: a user whose token carries no admin role completed the identity leg and was then refused a toolset the MCP data path serves. The flow's availability read was `GET /v1/toolsets/platform/{name}` — Core's admin-only config-resource route (the caller's admin role is the whole decision; the toolset's `user_roles` and publicness play no part) — while the data path `/v1/toolset/{name}/mcp` authorizes through `findDeployment` → `RoleBasedEntity.hasAccess(userRoles)` (a public toolset serves any authenticated caller). The two routes share no authorization logic, so the flow's "may this user sign in?" and the data path's "may this user call?" could disagree — and for every non-admin user on every platform-resident toolset they did, unconditionally on the entity: no `user_roles` value the toolset could carry would change the 403. The mismatch is structural, not tunable: the toolset lives in the `platform` bucket because that is where the platform admin API creates it, and the `public` bucket route would 404 for it.

**The decision (the diagnosis's Option A, adopted).** The flow's availability oracle becomes `GET /openai/toolsets/{name}` — the deployment-listing route. Its authorization is the data path's own by construction: `ToolSetController.getToolSet` resolves the toolset through the same `DeploymentService.findDeployment` the MCP proxy controller uses (`ToolSetController.java:68` vs `McpProxyController.java:120`), so the listing read answers 200 exactly when the data path's authorization — the deployment resolution of the name against the caller's roles — would admit the caller, 403 when that decision would refuse them, and 404 for a name it does not know; the data path additionally runs consent and rate-limit gates the listing read does not run, so the verified property is that resolution-and-roles decision — what the availability pre-check needs, and all it can claim: the pre-check grants nothing, and Core re-authorizes on every data-path call. The bucket-based platform settings read stops deciding availability, and the `TOOLSET_BUCKET` setting is retired with it — no read the flow makes addresses a bucket any more. The rejected alternatives, with the diagnosis's reasons: Option B (keep the platform read, gate it with a pre-flight listing call) would require the settings read to run on a service credential, dropping the per-user DIAL-authorization enforcement the read exists to provide — a security-relevant weakening; Option C (create user-callable toolsets in the `public` bucket, an operator workaround) changes administration practice and leaves the defect latent for platform-resident toolsets. Only Option A makes the flow's availability decision *be* the data path's decision.

**The field-parity verification (fresh, against Core at `6dae044`).** The question: does the listing route's projection carry everything the flow consumes from the settings read it replaces? The flow's `ToolsetSettings` (`gateway/core.py`) reads, from the answer's `auth_settings` member: `authentication_type`, `client_id`, `authorization_endpoint`, `code_challenge`, `code_challenge_method`, `redirect_uri`, `scopes_supported`, and — for the signed-in check — `user_level_auth_status` and `global_auth_status`. The listing route projects `auth_settings` through `ResourceAuthSettingsData.toData` (`server/.../data/ToolSetData.java:68`, `server/.../data/ResourceAuthSettingsData.java:21-32`), and the projection carries every consumed member under the same wire spellings: `authentication_type`, `client_id`, `authorization_endpoint`, `resource`, `redirect_uri`, `code_challenge`, `code_challenge_method`, `api_key_header`, `global_auth_status`, `app_level_auth_status`, `user_level_auth_status`, `scopes_supported`, `dynamically_registered` (both routes serialize snake_case; both are `NON_NULL`). **Parity is complete: the flow loses nothing it reads.** The members the platform settings read carries that the listing projection does not are `token_endpoint`, `token_endpoint_auth_method` (never read by the flow), and the secret members — `client_secret`, `code_verifier`, `client_secret_hint` — which the platform route redacts for every non-admin caller anyway (`ConfigResourceController.redactSecretFields`) and which the listing projection has no fields to carry at all: never-cut 2's public-projection property ("the upstream PKCE verifier never leaves Core") becomes structural on this route — there is no code path that could project them. The per-caller statuses the signed-in check reads are enriched on the listing route on every answer (`ResourceAuthStatusEnricher.enrichToolSet`, `ToolSetController.java:70-71`), exactly as the platform route enriches (`ConfigResourceController.java:1129-1138`).

**The semantic notes — what the flow reads differently, and the three shape changes that are all alignments with the data path.** (1) A toolset whose stored blob carries no `auth_settings` block at all: the platform route answered 200 without the member (the gateway's "carries no authentication settings" refusal — a deployment fault); the listing route cannot project it and answers 500 (`ToolSetData.toData` dereferences the block) — the gateway's unreachable-or-unreadable branch, the same operator-facing fault page, fail-closed in both shapes and never an existence answer. (2) A toolset whose stored blob is invalid: the platform route answered 200 with `status=invalid` (the gateway read it as a fault); the listing route answers 404, because an invalid entity never enters the merged config — which is exactly what the data path resolves from, so its 404 is the data path's own answer, not a new false refusal. (3) Resource-sourced toolsets (created in a user's or the public bucket, not the platform one): the platform read 404'd them — a false "not registered" for toolsets the data path serves; the listing route resolves them through the same resource-descriptor path the data path does (`DeploymentService.findDeployment`'s resource branch). In every case the listing read's answer is the answer the data path's own resolution would give.

**The shape decision — one read, and the status read is deleted, not merged.** The flow's toolset read becomes one request serving all three of its purposes: availability (the authorization decision), the settings projection the consent branch builds from, and the per-caller statuses the signed-in check reads. The existing two-call fallback (`read_toolset_for_flow`: where the first answer carries no statuses, ask the status route) collapses — its two routes are now the same URL, so the fallback could only re-ask the route that just answered, and `read_toolset_status` is deleted rather than merged. The fail-closed discipline the fallback served survives as the absence rule it always carried: a listing answer with no readable status at either level is not signed in, and the flow fails closed into the kind branch — on a Core build whose listing route does not enrich the statuses, no short-circuit ever fires (an OAUTH toolset re-runs its consent, the benign loop the impossible-branch refusal already rides; a non-OAuth toolset is refused as ever). That is the priced trade of the one-read shape, stated rather than mitigated.

The delta spec carries the re-pinning as declared amendments: the federation-flow requirement's authorization-bearing clause, its "DIAL authorization denied" and unknown-toolset scenarios (the latter's title retained verbatim as the scenario's stable identifier — the delta discipline matches scenarios by header against the main spec and has no scenario-level rename — with its body, the normative content, naming the listing read), the new public-toolset scenario (the regression this defect demands, pinned so a from-spec reimplementation cannot reintroduce the admin-role question), and the existence-decision mentions in the discovery, toolset-mapping, and name-guard requirements. The SIA below re-prices the read; the threat model's "per-user settings read" mechanism vocabulary re-pins with it (§7, task 8.1).

### D16 — The listing read's 401 is a trust fault, not an access denial (the second live-run finding's fix)

**The finding (live-run evidence: `docs/evidence/c2/part1-b2c-setup.md` and the run's audit trail).** `gateway/core.py`'s `_read_json` maps Core's **401 and 403 to the same access-denied error** — one refusal class for two answers that mean different things. The live B2C-backed sign-in run (the stack the Part 1 setup record brought up) put a signed-in user's flow through the listing read with an identity token Core could not validate — Core's own JWKS fetch of the provider's keys rides the same flaky network the discovery leg rides, and an audience or claims mismatch at Core's provider entry fails the same way — and Core answered **401**. The flow raised the access-denied refusal, and the user was shown the no-access page: "You do not have access to this toolset… Ask your DIAL administrator to grant it" — an authorization verdict for an **authentication** failure. The audit trail carries the same wrong class: the authorization leg's failure record with the access-denied message, nothing distinguishing a trust fault. Core logs no record of its 401s (the auth filter refuses before any controller sees the call), so without a gateway-side split the failure is undiagnosable — the operator is sent hunting an access problem that does not exist, and the user is told to ask for access they may already hold.

**The decision.** The two codes become two classes with different remedies. **403 keeps the access-denied class** — it is the deployment resolution's refusal of this caller, the data path's own decision, and the no-access page with its "ask your DIAL administrator" remedy is the honest answer to it. **401 raises a new trust-fault class** — an operator-facing `CoreError` subclass, distinct from the access-denied class — whose fixed page tells the user the sign-in cannot proceed and an administrator must check the trust configuration. The reasoning is that authentication is not authorization, and the two answers have two audiences whose actions differ: the *user's* remedy for a 403 is access granted, then a re-run; for a 401 the user can do nothing but report — the page says so instead of sending them to ask for access. The *operator's* diagnostic differs with the class: a 401 means Core's provider entry for the identity provider — its issuer pattern, its key set, its audience — or the reachability of that key set; a 401 burst across users is a trust-configuration or reachability event, never an access-change event, and the audit trail is where the two are told apart (Core's own logs cannot do it). The refusal is fail-closed and consumes the flow like the other refusals, no credential retained — the record's identity access token and the provider's session refresh token are the very material Core could not validate, so retaining them serves no re-run. The new class names nothing user-identifying: fixed vocabulary, no token or claim value — the same discipline every other refusal page carries, and never-cut 5's class.

**The scope of the split, and the adjacent site it does not reach.** The split lands in `_read_json`, the one answer-to-refusal mapping both resource kinds' reads share, so the app read's 401 lands on the same trust-fault class (the app-resource requirement's refusal enumeration is aligned with it). The credential call's own response handling (`gateway/flow.py`'s 401/403 branch on the USER-level credential API answer) also maps both codes to the toolset access-denied refusal today; it is **not** split by this decision — that call answers a different question (the credential establishment, not the sign-in's identity), its 401 semantics at Core's credential API are not evidenced by this run, and a split there is its own finding to make against its own live evidence. Recorded here so the implementer does not silently widen or silently ignore it.

**The SIA assessment.** The new fault page's information content is fixed vocabulary only — the sign-in cannot proceed, an administrator must check the trust configuration — with no token, claim, caller, or provider value on the page or in its audit record (never-cut 5's class; the delta spec's new scenario pins the no-user-identifying-value property). The threat rows affected: **DT-EP5-9's forged-answer residue gains nothing** — a forged 401 denies one flow exactly as a forged 404 does, and the split changes what the denial is *called*, never what it costs; what changes is the **detective control** (§5's item 8: four distinguishable refusal shapes on the trail — no-access, unknown-toolset, trust fault, deployment fault — where the prior mapping collapsed the 401 into the no-access class) and one **removed defect**: the wrong-class page and record — a trust fault rendered and audited as an access denial — is a diagnosability defect (the operator misdirected, the user misinformed), recorded as removed in the threat-model delta (§7). No mitigation weakens: the split adds a class on an already-priced read, moves no boundary, adds no entry point, and the impact level stays as the discovery shape set it (§2's D16 note). The delta spec carries the split as a declared trust-fault amendment: the federation-flow requirement's refusal-class clause, the "DIAL authorization denied" scenario's WHEN naming the 403, the new trust-fault scenario, and the app-resource requirement's refusal enumeration (the four-shape discipline).

## Security impact analysis

Per `docs/security-analysis.md` §4, this change **adds a surface**: the identity leg
generalizes from one internal, plain-http, compose-network provider to any OIDC
provider — including, in the tested deployment, an **external internet provider over
TLS** — and the confidential-client mode makes secret material load-bearing on that
leg. So the touched entry points are enumerated completely, and the asset and
trust-boundary updates ride the threat-model delta (§7 below).

### 1. Change description

*Business:* the gateway fronts any OIDC identity provider whose MCP incompliances it
absorbs, instead of one provider's URL grammar. Endpoints and capabilities are read
from the provider's standard discovery document at the configured issuer — or, where
the operator explicitly configures the provider's three endpoints directly (D11, the
owner's round-2 compatibility ask), from that configured set with discovery skipped
entirely; a varying-issuer provider is pinned exactly (the configured issuer is the
one federated sign-in journey's, and a token from any other issuer, another journey
of the same provider included, is refused); a provider that
cannot support PKCE is absorbed by turning the leg's challenge off while the client
authentication stays on — the gateway is a confidential client at the identity
provider on every token request, the secret required at startup in both toggle
positions (D5, the owner's round-5 ruling); the configuration vocabulary is provider-neutral (`IDP_*`) and
the identity-leg callback route is provider-neutral (`/dial/callback/idp`). The
tested case is the external customer-identity family's classic-flavor tenant (the
successor flavor is the untested alternative — Context, D9, OQ-A decided),
configured with placeholders; the live acceptance run is owner-dependent. The live
run's first non-admin identity exposed a false denial in the flow's availability
read — an admin-only Core route deciding a question the data path answers by role —
and this change fixes it: the availability oracle becomes the deployment-listing
read, the route whose authorization is the data path's own deployment resolution
(D15). The same live run also exposed the read's refusal-class conflation — Core's
401 (it could not validate the sign-in's identity token) and 403 (the caller's lack
of access) answered as one access-denied class, page and audit record alike — and
this change splits them: the 401 becomes an operator-facing trust fault with its own
fixed page and fixed-vocabulary audit reason, never an access denial (D16).

*Implementation shape:* a discovery document client in the identity leg — fetched at
`{IDP_ISSUER}/.well-known/openid-configuration` (or through `IDP_BACKCHANNEL_BASE_URL`
when set, which re-addresses the fetch and the token/key-set calls while leaving the
browser-facing authorization endpoint and the issuer pin untouched), validated
(issuer equality; every used endpoint origin-bound to the configured issuer or the
back-channel base; HTTPS without the override; no redirects; size-capped), cached per
process for `IDP_DISCOVERY_CACHE_TTL_SECONDS`, and used by the code exchange, the
refresh grant, and key-set resolution — one spelling of the identity leg; the realm
arithmetic and endpoint-suffix constants are deleted with no fallback. Where the
operator configures the all-or-nothing endpoint trio (`IDP_AUTHORIZATION_ENDPOINT`,
`IDP_TOKEN_ENDPOINT`, `IDP_JWKS_URI`), the discovery fetch is not attempted and the
trio serves every leg, validated at startup (well-formed absolute URLs; HTTPS unless
the endpoint shares the override's origin; a partial set refuses startup). The
gateway authenticates as a confidential client on every identity-leg token request:
`IDP_CLIENT_SECRET` is required at startup (a missing or blank secret refuses
startup naming the setting, in both toggle positions), and the exchange and the
refresh grant present it in both modes; `IDP_PKCE_ENABLED` (default true) governs
only whether the S256 challenge/verifier rides on top — off, the IdP-leg redirect
carries no challenge, for a provider that cannot support PKCE. The secret is
delivered as an environment variable from the deployment's `.env`, the same delivery
the signing and custody keys use (D13). The `KEYCLOAK_*`→`IDP_*` rename and the
callback-route rotation are carried through settings, compose, `.env.example`, the
provisioning helper's gateway-facing writes, the probes, the docs, and the tests in
one lockstep change. The flow's toolset read re-points from
`GET /v1/toolsets/{bucket}/{name}` to `GET /openai/toolsets/{name}` (D15): one read
serving availability, the settings projection the consent branch builds from, and
the per-caller statuses; the separate status read, the two-call fallback, and the
`TOOLSET_BUCKET` setting are retired. The read's refusal classes split (D16):
`_read_json` raises the new trust-fault `CoreError` class on UNAUTHORIZED — fixed
vocabulary, nothing user-identifying — while FORBIDDEN keeps the access-denied
class; the flow renders the trust-fault page, consumes the flow like a refusal with
no credential retained, and audits the fixed-vocabulary reason.

### 2. Impact level, with reasons

**High.** The identity-provider trust boundary changes shape: the back-channel leg —
which today crosses the semi-trusted compose network to a co-located, plain-http
provider — becomes, in the tested deployment, an outbound **internet** leg to a
third-party provider over TLS, carrying the code, the carried session refresh token,
and the client secret — presented on every token request in every deployment (the
confidential-client shape the owner's round-5 ruling fixes, D5). New secret material
becomes load-bearing, and by the ruling it is load-bearing **unconditionally**: the
client secret, a process-held persistent credential in the signing key's and custody
key's class, is on the token leg's wire and in process memory in both toggle
positions — the ruling removes the no-secret deployment class the prior design
permitted (the public-client mode), a widening of an already-priced class to every
deployment, not a new class. A new integrity-critical
input enters the leg: the discovery document, whose advertised endpoints steer every
credential-bearing outbound call — an integrity surface the URL arithmetic never had
(the endpoints were operator-configured constants; now they are provider-asserted and
validated). The claim-source chain gains a link: what Core authorizes on now flows
through discovery → key set → verified token. No new public endpoint, no new grant
type on the client-facing surface, and no change to the upstream credential model.
The direct endpoint-configuration mode (D11) does not raise the level — it removes
the provider-asserted input in that mode (there is no document to forge) and adds
only operator-trusted input at the trust level `IDP_ISSUER` already holds — but its
misconfiguration and staleness residue is priced (DT-EP5-8), so the level and the
review depth stay as the discovery shape set them. The level sets the security
review gate's depth — full depth. **The availability-read re-pinning (D15) does not
move the level:** it changes which Core route one existing read addresses — the same
internal leg, the same live-user identity token, the same trust — and adds no entry
point, no grant type, and no new integrity input; its whole effect on the exposure
surface is the re-pricing stated in §4 (an availability-correctness alignment on an
already-priced read), so the level and the review depth stay as the discovery shape
set them. **The refusal-class split (D16) does not move the level either:** it adds a
page class and an audit reason on the same already-priced read — no new entry point,
no grant type, and no new integrity input — and its whole effect on the exposure
surface is the detective-control gain and the removed diagnosability defect stated
in §4/§5, so the level and the review depth stay as the discovery shape set them.

### 3. Invariant ruling table

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | **Preserved** | The upstream leg, the credential call, and the USER-level stamp are untouched; the change is entirely on the identity-provider leg and its configuration vocabulary |
| 2 | The upstream PKCE verifier never leaves Core | **Preserved, with the boundary stated precisely** | The upstream verifier is Core's, per toolset, nulled on every public projection, untouched on every path. What the PKCE toggle varies is the **gateway's own** PKCE on the **identity leg** — a different binding on a different leg; since the round-5 ruling (D5) the client secret is that leg's **inherent** control, presented on every token request in both toggle positions and required at startup either way. The client-facing AS surface keeps requiring PKCE from harness clients; the delta spec pins that with its own scenario |
| 3 | Per-user credential isolation | **Preserved** | The `sub` cross-checks (issuance and refresh against the provider's just-asserted subject; the custody seam's embedded `sub`) are unchanged; exact issuer pinning (D6) strengthens identity provenance — a sibling journey's token is refused wherever the provider issues journey-distinct issuers (a provider-side setting, task 5.1's stated prerequisite), so no cross-journey subject confusion can mint in that configuration |
| 4 | DIAL authorization applies to every toolset call | **Preserved, with the pre-check aligned (D15)** | The per-user read before any upstream stage and Core's per-call authorization are unchanged in existence and enforcement; the read is re-pinned to the deployment-listing route, whose authorization is the same deployment resolution the data path authorizes through, so the flow's pre-check and the per-call enforcement are now one decision instead of two that could disagree (the disagreement was the live run's false denial — removed, not mitigated). The claim source's integrity now rides discovery → key set → verified token, bounded by D3's validation (origin-bound endpoints, issuer equality) — or, in direct mode (D11), configured endpoints → key set → verified token, bounded by D11's startup validation and the unchanged exact issuer pin — and the existing pinned-algorithm verification — priced as DT-EP5-1 (discovery mode) and DT-EP5-8 (direct mode); the refusal-class split (D16) keeps the pre-check's verdicts honest — an authentication failure (Core's 401) is never answered or audited as an authorization verdict |
| 5 | No credential in logs, argv, or error messages | **Preserved, with the new member named** | The client secret joins the never-logged set (SecretStr, no `repr`, refusal messages name the setting class, never the value) — the delta spec's scenario pins it; the discovery document carries no credential material and its refusals are fixed-vocabulary; the direct-mode settings carry no credential material and their startup refusals name the setting classes only; the trust-fault page (D16) is fixed vocabulary too — no token, claim, or caller value reaches the page or its audit record, and the delta spec's new scenario pins that |
| 6 | No hardcoded credentials in the repository | **Preserved** | `IDP_CLIENT_SECRET` stays a committed `.env.example` placeholder with an empty value, delivered as an environment variable from the deployment's `.env` (D13 — the same delivery the signing and custody keys use, never argv, never a gateway-read file); the move under deployment secret management is C3's recorded scope |
| 7 | The signing key is IdP-grade secret material | **Preserved** | Key custody, publication, and rotation are untouched; the discovery change touches only where the **provider's** keys are fetched from (its own discovered `jwks_uri`, origin-bound) |

### 4. Delta threat tables, per touched entry point

EP1 (the client-facing OAuth/discovery endpoints) is touched in vocabulary only — the
route constant and the audit leg name rotate; no request-handling behavior changes on
that surface, so it carries no delta table. EP6 (the router) is untouched — the
alternation already matches the new callback spelling (verified), so it carries no
delta table. Mis-use cases are marked **[mis-use]**.

#### EP5 — the server-to-server identity leg (generalized: the discovery fetch or the directly-configured endpoints, the exchange, the refresh grant, the key-set fetch)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP5 (the discovery fetch) | Interception → Spoofing of the target (Man in the middle) | Forged discovery document steers credential-bearing calls | The discovery document and the endpoints it names; the code, the carried session refresh token, and the client secret that ride the calls it steers; A3's claim set | C, I (worst case: mint-any-`sub` via a hostile key set) | A network-level attacker between the gateway and the provider (DNS poisoning, on-path MITM, a hostile resolver) serves a discovery document whose `token_endpoint`/`jwks_uri` point at the attacker, so the next exchange delivers the code — and the client secret, presented on every token request in both modes (D5) — to the attacker's endpoint, and the matching hostile key set verifies the forged token the attacker returns: the mint-any-`sub` chain of the existing internal-leg MITM threat (T5-2), relocated from the compose network to wherever the discovery fetch is answered. Bounded by D3's validation, which is designed against exactly this document: the document's `issuer` must equal the configured issuer exactly (a document claiming the right issuer while naming wrong-origin endpoints is refused whole), every used endpoint must share the configured issuer's or the override's origin (an off-origin `token_endpoint` is refused — the document cannot steer calls anywhere its own issuer does not live), plain http is refused without the explicit override, redirects are not followed, and the response is size-capped. What remains is the TLS-bounded residue every HTTPS client carries: an attacker who defeats transport validation on the issuer's own origin was already able to impersonate the provider's token endpoint directly, with or without discovery — the existing RES-19 acceptance, restated for the internet leg. |
| EP5 (the discovery fetch) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Discovery-fetch amplification off the public surface | A14 (the shared worker pool); the provider's discovery endpoint | A | The `/dial/authorize` surface is unauthenticated and an identity-leg redirect needs the discovered authorization endpoint, so an unauthenticated caller could try to spend discovery fetches. Bounded by the cache: at most one fetch per TTL per process however many requests arrive — a validated document serves its window, and a failed or refused fetch is recorded for the same window and served from it without re-fetching, so the bound holds while the provider is unreachable or its document refused as well — and the request rate itself is bounded by the limiter the authorize surface already joins — the fetch rate is min(rate limit, 1/TTL) in the success regime and in the failed one alike — and the identity legs' own fetches are the legitimate ones the cache already serves. |
| EP5 (the exchange and refresh grant, challenge-off mode) | Interception → Eavesdropping / Spoofing of the caller's identity | Intercepted identity-leg code exchanged by the interceptor | A5 (the identity-leg code on the callback URL); the client secret; A3's claim set | C, I (the mint's `sub`) | With the leg's PKCE challenge disabled — an explicit operator opt-in for a provider that cannot support it — the binding that made an intercepted IdP-leg code unexchangable by its interceptor is gone — the callback-URL interception class (T3-3/RES-1, the class both callbacks share; the identity-leg callback is E6, the upstream's is E7), now on the identity leg's own code. The control is inherent, not mode-conditional: the gateway is a confidential client at the provider (the round-5 ruling, D5), so the exchange requires the client secret in **both** toggle positions — the interceptor does not hold it, and the intercepted code is spent by the gateway first or refused as `invalid_client` whichever way the toggle is set. The residue: on a plain-http front door an on-path attacker reads the code (and the callback URL), and the secret is the only remaining bar — a strictly weaker position than challenge+secret against a secret-holder. The mode stays an explicit operator opt-in (the toggle is default-on); the secret's presence is guaranteed in every mode by the startup refusal, disclosed in the threat-model delta, and re-opened by TLS-fronting the public origin (RES-1's own re-open trigger). |
| EP5 (the token endpoint, both modes) | Interception → Eavesdropping | Client secret presented on every token call | The client secret (a persistent process credential, the signing key's class); the token-endpoint leg | C | Every exchange and refresh grant presents the client secret to the discovered or directly-configured token endpoint — in both toggle positions, in every deployment (the round-5 ruling's shape, D5) — over TLS to the origin-bound provider (D3), or over the operator-owned plain override where one is configured (the RES-19 internal-leg acceptance, now carrying a secret on every token request: an internal-leg peer that could read the refresh token can read the client secret too). The secret's blast radius is bounded by design: it authenticates only the gateway's IdP-leg client (no upstream credential, no Core access, no mint capability), and its exposure does not widen what a refresh-token reader could already do. Priced as the override deployment's widened RES-19 record. |
| EP5 (verified claims, varying-issuer providers) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Another journey's token accepted by a relaxed issuer match | A3's claim set (the `sub` and roles the mint copies); the configured issuer's authority | I, Access | A provider whose issuers vary by sign-in journey mints each journey's tokens under that journey's issuer; a "helpful" implementation matching the issuer by prefix, tenant, or templated pattern would accept another journey's token — a token whose claims were minted under a different journey's claim configuration, possibly looser roles wiring — and mint a gateway token from it. Refused
**gateway-side** by construction: the issuer check is exact-string against the
configured issuer (the one federated journey's, D6), the delta spec's scenario names the
refusal, and the discovery document's `issuer` is validated against the same value
(D3), so no document and no token can widen the pin. The distinguishability
precondition is provider-configuration, not construction: a sibling journey's token is
refused *as a different issuer* only where the provider issues journey-distinct
issuers — in the tested family an opt-in per-journey token setting (off by default,
Context), the operator prerequisite task 5.1 states; under the family-wide default
the sibling's token shares the configured `iss` and no issuer check, exact or
relaxed, can distinguish it — the deployment must enable the provider-side setting,
which is why it is carried as a stated prerequisite rather than priced as a
mitigation. |
| EP5 (the identity leg, availability) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Provider outage becomes a sign-in outage, discovery included | A14 (the sign-in surface's availability) | A | The identity leg already fails closed on provider unavailability; discovery adds one more provider dependency to the same leg, cached (D4) so the failure shape is unchanged in kind — the operator-facing fault page, already-minted tokens unaffected. The cold-start note is stated: the first sign-in after a cold cache needs the provider reachable, where before it needed only the token endpoint — a wider provider dependency by exactly the discovery endpoint, bounded by the TTL cache thereafter. |
| EP5 (the identity leg, operator misconfiguration) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mis-scoped discovery acceptance **[mis-use]** | A3's claim set; the origin bound of D3 | I | A legitimate operator configures the back-channel override sloppily — an override whose origin is broader than the provider's own (a shared internal host serving more than the IdP) — and the origin bound then admits endpoints on that host that are not the provider's, widening where credential-bearing calls may be steered by a document. The bound is exactly as wide as the operator's override claim: this is the same class as the existing plain-http override acceptance (RES-19), stated in the operator reference as the override's own trust claim, and re-judged in the threat-model delta's reworded TB3/TB7 entries. |
| EP5 (the identity leg, direct mode) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mistyped or swapped endpoint in the direct configuration **[mis-use]** | The code, the carried session refresh token, and the client secret that ride the mis-addressed calls; A3's claim set | C, I | In direct mode (D11) the operator's three endpoint URLs steer every credential-bearing call, and a mistyped or swapped value — a wrong host, a stale copy-paste, a value that reaches the setting by accident — delivers the leg's credential material to a host the operator did not mean. There is no provider-asserted input in this mode, so the forged-document chain of DT-EP5-1 cannot exist — no document, nothing to forge; what steers the calls is operator input at the same trust level as `IDP_ISSUER` itself, which already anchors everything the leg trusts. Bounded by: HTTPS (no plain leg without the override's explicit ownership), the all-or-nothing startup validation that refuses partial or malformed sets loudly, and the fixed-vocabulary operator-facing leg failures a wrong host produces at first use — a credential-bearing call to a wrong origin is a deployment misconfiguration in the same accepted class as DT-EP5-7's override claim, not a forgeable input. |
| EP5 (the identity leg, direct mode) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Stale directly-configured endpoint after a provider change | A14 (the sign-in surface's availability) | A | The provider moves an endpoint; in discovery mode the change propagates within the cache TTL (D4), but in direct mode nothing propagates it — every leg against the moved endpoint fails with the fixed-vocabulary operator-facing error until the operator updates the setting. The failure shape is the existing fail-closed leg failure (the DT-EP5-6 class), and the residue is the mode's priced, documented trade: the operator owns endpoint freshness, stated in the operator reference (task 5.1) and in the direct-configuration requirement itself, so the staleness bound is a named operator responsibility rather than an undisclosed window. |

#### EP5 — the flow's Core read (re-pinned by D15: the availability oracle moves to the deployment-listing route)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP5 (the flow's Core read — the listing read, `GET /openai/toolsets/{name}`) | Interception → Spoofing of the target (Man in the middle) | Forged listing answer steers the flow | The flow's availability, existence, and settings decisions; the signed-in statuses the short-circuit reads; A14 (one user's flow, the user's time) | I, A (bounded) | **The re-pricing statement first, because it is the row's substance: the read's authorization becomes the data path's own.** The prior read (`GET /v1/toolsets/platform/{name}`) was authorized by the caller's admin role — a decision the data path never makes — so it was simultaneously *wider* than the data path on one axis (an admin passed availability for a role-restricted toolset the data path would refuse them) and *narrower* on another (a non-admin was refused a public toolset the data path serves — the live run's false denial, a denial-of-service defect the model had not priced). The listing read resolves the toolset through the same `findDeployment` the MCP data path authorizes through, so the flow's decision now *equals* the data path's on every axis — never exceeding it, never refusing what it serves; both the false denial and the admin-axis disagreement are removed, not mitigated. The read remains a pre-check, not the enforcement: Core re-authorizes on every data-path call, unchanged. The forged-answer residue is unchanged in kind: the listing read rides the same internal leg, with the same live-user identity token to the same configured Core, as the platform read did — a peer who could forge the old answer can forge the new one (T5-7's acceptance class, RES-19), and the bounds T5-7 already states carry over whole: a forged SIGNED_IN status mints a misleading token whose data-path calls yield 401s, not access; a forged 200 for a phantom toolset steers one flow to an error; a forged 404 denies one flow — and a forged 401 denies one flow the same way: the refusal-class split (D16) changes what the denial is *called* (the trust-fault class, distinct on page and trail from the no-access class a forged 403 earns), never what it costs — one flow, the forged-answer class unchanged. One narrowing is structural: the listing projection has no fields for the verifier or the client secret at all, so never-cut 2's public-projection property holds by construction on this route. |

#### EP4 — the signing key (process memory and host files; the IdP-leg client secret joins the class, load-bearing in every deployment)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP4 (process memory; the `.env` slot) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Client-secret compromise | The IdP-leg client secret (the third persistent secret in the signing key's class, load-bearing in every deployment since the round-5 ruling — always on the token leg's wire, always in process memory); the host `.env` at rest | C, I | The secret's holder can authenticate the gateway's IdP-leg client to the provider — exchange codes, run refresh grants for tokens it holds — but can mint nothing at the gateway (no signing key, no custody key) and reach no upstream credential; in the challenge-on mode a leaked secret alone still cannot spend an intercepted code (the exchange also requires the gateway-held verifier), so the challenge remains a real second binding there — but the secret is no longer optional anywhere: the ruling removes the no-secret deployment exposure class the prior public-client design permitted (recorded as removed-by-ruling in the threat model). At rest the secret is a `.env` entry (never-cut 6's pattern, committed placeholder empty); in process it is a `SecretStr` with no `repr` — the same custody class as the existing client-secret slot it renames, unconditionally load-bearing now, which is why its asset row is added to the threat model (§7) and its KMS/secret-management move is recorded as C3's input. |

### 5. Mitigations per threat, in the fixed control-category order

Homes: **spec** = this change's delta spec (gateway-owned, normative); **repo** =
committed material; **Core config** / **deployment** = named with their owners.

**DT-EP5-1 Forged discovery document steers credential-bearing calls**
1. Reduce Attack Surface — the discovery document is the one provider-asserted input;
   only its `issuer`, `authorization_endpoint`, `token_endpoint`, and `jwks_uri` are
   read, and nothing else from it reaches a URL builder (spec).
2. Isolation — the back-channel override is the one origin the document's endpoints
   may name besides the issuer's own; both bounds are operator-configured constants,
   never document-supplied (spec).
3. Authentication — the fetch is TLS-validated HTTPS to the configured issuer (plain
   http refused without the explicit override), redirects not followed (spec).
4. Authorization — **the control**: the document's `issuer` must equal the configured
   issuer exactly and every used endpoint must share the configured origin — a
   document that fails either is refused whole, so no document the gateway accepts can
   steer a credential-bearing call to an origin the operator did not configure (spec).
5. Data Protection — the response is size-capped and schema-checked; no credential
   material is sent on the discovery fetch itself (spec; repo — the existing
   bounded-parsing discipline).
6. Anti-Injection — bounded parsing of a fixed-shape JSON document; endpoint strings
   are used as URLs and never interpolated into any executable or config context
   (repo).
7. Anti-DoS — the response cap bounds what a hostile document server can make the
   gateway buffer (spec); the fetch runs on the worker pool off the event loop (repo).
8. Detective controls — a refused document is an operator-facing leg failure with a
   fixed-vocabulary reason; the audit leg-failure record exists unchanged (spec).

**DT-EP5-2 Discovery-fetch amplification off the public surface**
1. Reduce Attack Surface — the cache bounds fetches to at most one per TTL per
   process, whoever triggered the need; a failed or refused fetch is recorded for the
   same window and served from it without re-fetching (the negative half of the
   cache), so the one-fetch bound holds while the provider is unreachable or its
   document refused as well, and a success ends the record (code).
2. Isolation — not applicable: the fetch is gateway-originated to a configured
   origin; there is no caller-steered target to isolate (the CIMD fetch's SSRF shape
   is absent because the discovery URL is never caller-supplied).
3. Authentication — not applicable: the flood is of public authorize requests; the
   fetch target is fixed by configuration.
4. Authorization — not applicable: a refused or accepted authorize request authorizes
   nothing at the provider.
5. Data Protection — not applicable: no secret rides the discovery fetch.
6. Anti-Injection — not applicable beyond DT-EP5-1's parsing bound.
7. Anti-DoS — **the control**: the public-surface rate limiter the authorize endpoint
   already joins bounds the request rate, and the cache bounds the fetch rate below
   it — min(limiter, 1/TTL), in the success regime and in the failed one alike (the
   existing limiter; the cache and its failure record).
8. Detective controls — limiter 429 records exist unchanged (spec).

**DT-EP5-3 Intercepted identity-leg code in the challenge-off mode**
1. Reduce Attack Surface — the challenge-off mode is opt-in and default-off (the
   toggle's default keeps the challenge); the startup refusal guarantees the secret's
   presence in every mode, so no deployment runs without the control (spec).
2. Isolation — not applicable: the code crosses the browser and the front door by
   protocol; no boundary placement changes that.
3. Authentication — **the control, inherent since the round-5 ruling**: the exchange
   and refresh grant authenticate the client with the configured secret in **both**
   toggle positions, so the interceptor cannot spend the code it read whichever way
   the toggle is set (spec); the challenge stays the default second binding and is
   dropped only on this leg.
4. Authorization — the mint's `sub` is still the provider-asserted subject of the
   exchanged token; no token is minted for a subject the provider did not assert
   (spec — unchanged).
5. Data Protection — the code is short-lived and single-use at the provider; the
   secret is never logged (spec).
6. Anti-Injection — not applicable: the threat is interception, not injection.
7. Anti-DoS — not applicable: the interception costs the gateway nothing.
8. Detective controls — an `invalid_client` burst at the provider reads on the audit
   trail as the claims-read refusal class (spec — the existing refusal vocabulary).
   **Disposition: the residue (secret-holder on a plain-http front door) is accepted
   as the mode's priced cost, disclosed as the challenge-off residual in the threat-model
   delta, re-opened by TLS-fronting the public origin.**

**DT-EP5-4 Client secret on the wire in every deployment**
1. Reduce Attack Surface — the secret is presented only to the discovered or
   directly-configured, origin-bound token endpoint, never any other leg (spec —
   D3's bound is this mitigation).
2. Isolation — not applicable: the presentation is the protocol's client
   authentication; there is no second channel.
3. Authentication — the secret is the authenticator itself (spec).
4. Authorization — not applicable: the secret authenticates, it does not authorize.
5. Data Protection — **the control**: TLS to the configured origin in the default
   shape; where the operator's plain-http override carries it, that is the override's
   disclosed trust claim, recorded in the operator reference and the re-priced RES-19
   (spec — the plain-http refusal without the override; repo — the operator
   reference's override warning).
6. Anti-Injection — not applicable.
7. Anti-DoS — not applicable.
8. Detective controls — a misconfigured secret fails loudly as the provider's
   `invalid_client`, audited in the claims-read class, never read as mass revocation
   (spec — the existing C1 ruling's keying). **Disposition: accepted with the override
   deployment's widened RES-19 record; the KMS/secret-management move is C3's.**

**DT-EP5-5 Another journey's token accepted by a relaxed issuer match**
1. Reduce Attack Surface — one provider, one configured issuer; no issuer list, no
   pattern (spec — the configured-issuer pin).
2. Isolation — not applicable: the pin is a string comparison, not a boundary.
3. Authentication — **the control**: exact-string issuer verification at issuance and
   refresh, the sibling journey's issuer failing it wherever the provider issues
   journey-distinct issuers — the provider-side setting, the row's stated precondition
   (spec — the added scenario).
4. Authorization — the mint's claims come only from the verified token of the pinned
   issuer (spec — unchanged copy rule).
5. Data Protection — not applicable: no secret is at stake; the compromised property
   is issuer authority.
6. Anti-Injection — not applicable: the threat is a relaxed match, not a payload.
7. Anti-DoS — not applicable.
8. Detective controls — an issuer-mismatch refusal is the existing leg-failure
   record; a deployment misconfigured the other way (family-wide issuer configured,
   journey-issuer tokens arriving) fails every sign-in loudly and diagnosably (spec).

**DT-EP5-6 Provider outage becomes a sign-in outage, discovery included**
1. Reduce Attack Surface — the cache bounds the discovery dependency to one fetch per
   TTL; the token-endpoint dependency is the leg's existing one (spec).
2. Isolation — not applicable: the dependency is genuine and required by the
   generalization's goal.
3–4. Authentication / Authorization — not applicable: unavailability, not a
   credential or permission failure.
5. Data Protection — not applicable.
6. Anti-Injection — not applicable.
7. Anti-DoS — **the control**: the failure fails closed with the operator-facing
   fault page; already-minted tokens and the local revocation denylist keep working;
   the cold-start widening (one more provider endpoint needed at first use) is stated
   in the cache scenario (spec).
8. Detective controls — the leg-failure audit record with the failing leg's name
   (spec — unchanged, the name now provider-neutral).

**DT-EP5-7 Mis-scoped discovery acceptance [mis-use]**
1. Reduce Attack Surface — the override is optional and unset by default; the
   single-origin external-provider shape needs none (spec).
2. Isolation — the override is a single origin constant; the bound is exactly as
   wide as the operator's claim, and the operator reference says so (repo).
3–4. Authentication / Authorization — not applicable: the operator is inside the
   trust boundary being configured; the control is the claim's explicitness.
5. Data Protection — not applicable.
6. Anti-Injection — not applicable.
7. Anti-DoS — not applicable.
8. Detective controls — an endpoint refused as out-of-origin names the setting class
   in its fixed-vocabulary reason, so a mis-scoped override surfaces at its first
   sign-in, diagnosably (spec). **Disposition: accepted as the operator's explicit
   trust claim, the RES-19 class, reworded in the threat-model delta.**

**DT-EP5-8 Mistyped or stale directly-configured endpoint (direct mode) [mis-use]**
1. Reduce Attack Surface — direct mode is opt-in and default-off (discovery is the
   mode); the setting trio is all-or-nothing, so no mixed-source leg exists (spec).
2. Isolation — the back-channel override remains the one plain-leg ownership: a
   plain-http configured endpoint is refused unless it shares the override's origin
   (spec).
3. Authentication — the leg's authenticators (the client secret on every token
   request, with PKCE's challenge on top where the toggle enables it) are unchanged
   by the mode; the endpoints are addressing, not
   authentication (spec — D5's client-authentication shape is orthogonal to the endpoint source).
4. Authorization — the mint's claims come only from the verified token of the pinned
   issuer; the configured endpoints never widen the exact-string pin (spec — D6,
   unchanged in direct mode).
5. Data Protection — HTTPS enforced on every configured endpoint except an
   override-owned plain leg, so the code, the carried refresh token, and the client
   secret never ride an unowned plain leg (spec).
6. Anti-Injection — the three settings are used as URLs and never interpolated into
   any executable or config context (repo).
7. Anti-DoS — not applicable beyond the leg's existing bounds: no discovery fetch
   exists in direct mode, so DT-EP5-2's amplification class is absent entirely; the
   staleness residue fails closed through the leg's existing bounds (spec).
8. Detective controls — a wrong or stale endpoint fails the leg closed at first use
   with the fixed-vocabulary operator-facing error; the audit leg-failure record
   exists unchanged (spec).
   **Disposition: the mistyping residue is accepted as the operator's explicit trust
   claim (the DT-EP5-7 class — operator input at the issuer setting's own trust
   level); the staleness residue is accepted as the mode's priced, documented trade
   (the operator owns endpoint freshness).**

**DT-EP5-9 Forged listing answer steers the flow (the re-pinned availability read)**
1. Reduce Attack Surface — the flow's toolset read is one request on one route
   (the listing read), the same route the statuses and the settings projection come
   from; no second Core route is addressed on the toolset flow's decision step
   (spec — the federation-flow requirement's re-pinned read).
2. Isolation — not applicable: the read is gateway-originated to the configured Core;
   the leg and its trust are the pre-existing internal leg (T5-7's).
3. Authentication — the read carries the live user's verified identity token, as the
   platform read did; the leg's trust basis is unchanged (spec — unchanged).
4. Authorization — **the control, and the change's substance**: the read's
   authorization is the data path's own deployment resolution, so a forged answer is
   the only way the flow's decision could exceed the data path's — and the
   per-call enforcement on the data path is unchanged and independent of it (spec —
   the re-pinned requirement and its scenarios).
5. Data Protection — the projection the flow consumes structurally carries no
   verifier and no client secret (the listing projection type has no such fields);
   no credential material is read, stored, or logged from the answer (spec —
   unchanged; the structural note is D15's parity record).
6. Anti-Injection — the answer's fields are read as bounded strings by fixed field
   names; the existing bounded-parsing discipline carries (repo — unchanged).
7. Anti-DoS — not applicable: one read per flow, the same count the two-call shape
   bounded (spec — D15's one-read shape).
8. Detective controls — the read's refusals land on the audit trail with their
   fixed-vocabulary reasons, **four shapes distinguished — no-access (the 403),
   unknown-toolset (the 404), the trust fault (the 401, D16), and the deployment
   fault (unreachable or unreadable) — where the prior mapping collapsed the 401
   into the no-access class** (spec — the new trust-fault scenario and the
   re-worded denial scenario). A refusal's class is the operator's diagnostic, and
   the trail is where a 401 burst is told apart from an access-change event —
   Core's own logs carry no record of its 401s, so the gateway's record is the only
   diagnosable trace the failure has.
   **Disposition: the forged-answer residue is accepted at the internal-leg bound —
   T5-7's class, RES-19, one member of the same Core answer relocated to the listing
   route; the false-denial defect class (an availability oracle disagreeing with the
   data path) is removed by the re-pinning and is recorded as removed in the
   threat-model delta; the wrong-class defect (a trust fault rendered and recorded
   as an access denial — D16's finding, a diagnosability defect) is likewise removed
   and recorded as removed.**

**DT-EP4-1 Client-secret compromise**
1. Reduce Attack Surface — the secret is load-bearing in every deployment (required
   at startup, presented on every token request, both toggle positions — the
   round-5 ruling's shape), and the no-secret deployment exposure class the prior
   public-client design permitted is removed by the ruling; in the challenge-on mode
   a leaked secret alone still cannot spend an intercepted code (the verifier is the
   second binding), so the challenge keeps a real narrowing there (spec — the
   confidential-client requirement's structure).
2. Isolation — the secret's home is the `.env` slot and the `SecretStr` field, the
   existing custody class of the slot it renames (repo).
3. Authentication — the secret is the IdP-leg client's authenticator; it
   authenticates nothing at the gateway, Core, or any upstream (spec — the leg's
   shape).
4. Authorization — **the control, by blast radius**: the secret's holder can drive
   the provider's client (exchange a code they intercepted, refresh a token they
   hold) but can mint no gateway token, reach no upstream credential, and read no
   other user's identity (spec — the unchanged mint and custody invariants).
5. Data Protection — never logged, never in `repr`, no `repr`-bearing dataclass field
   (spec — the no-output scenario; repo — `SecretStr`).
6. Anti-Injection — not applicable.
7. Anti-DoS — not applicable.
8. Detective controls — provider-side anomaly visibility is the provider's own; the
   gateway's trail carries the refusal classes the secret's misuse produces
   (spec — unchanged). **Disposition: accepted at the `.env`-class custody of the
   never-cut-6 pattern; the secret-management move is C3's recorded scope.**

### 6. The grouped mitigation list

The reviewed result, one mitigation to the threats it addresses:

1. **Discovery validation (spec — the validation requirement):** issuer-equality and
   origin-bound endpoints, HTTPS without the explicit override, no redirects, size
   cap, refuse-whole semantics. Addresses DT-EP5-1, DT-EP5-7; bounds DT-EP5-4.
2. **The discovery cache with its TTL (spec — the discovery requirement):** at most
   one fetch per TTL per process, staleness bounded and documented; a failed or
   refused fetch recorded for the same window and served from it, so the bound holds
   in the provider-unreachable and document-refused regime too. Addresses
   DT-EP5-2, DT-EP5-6.
3. **The confidential-client rule (spec — the confidential-client requirement):** the
   client secret required at startup in both toggle positions and presented on the
   exchange and refresh grant in both, the PKCE toggle governing the
   challenge/verifier only (default-on), the client-facing surface's
   PKCE unchanged and pinned by its own scenario. Addresses DT-EP5-3, DT-EP5-4,
   DT-EP4-1.
4. **Exact issuer pinning with the varying-issuer scenario (spec — the verification
   amendment):** exact-string match against the configured issuer, other journeys'
   tokens refused. Addresses DT-EP5-5.
5. **Fail-closed leg semantics with fixed-vocabulary audit (spec — unchanged,
   restated for the discovered endpoints):** every discovery or leg failure is an
   operator-facing fault, audited by leg name and reason class. Addresses
   DT-EP5-6, DT-EP5-7, DT-EP4-1's detective half.
6. **Operator reference for the override and the mode (repo):** the override's origin
   is a trust claim as wide as its hostname; the challenge-off mode trades the
   challenge binding away while the client authentication stays on, and the secret is
   required whichever way the toggle is set — stated per provider. Addresses
   DT-EP5-7, DT-EP5-3's
   disclosed residue.
7. **Direct-mode startup validation with fail-closed staleness (spec — the
   direct-configuration requirement):** the all-or-nothing endpoint trio with its
   startup refusal on a partial set, well-formed-absolute-URL and
   HTTPS-or-override-owner checks, no discovery fetch attempted in the mode, and a
   wrong or stale endpoint failing the leg closed with a fixed-vocabulary
   operator-facing error. Addresses DT-EP5-8; and in direct mode removes
   DT-EP5-1's and DT-EP5-2's attack classes entirely (no provider-asserted input, no
   fetch) — a mode-conditional narrowing recorded as such.
8. **The availability oracle as the data path's own decision (spec — the
   federation-flow requirement's re-pinned read and its scenarios, D15):** the
   flow's toolset read is the deployment-listing read, authorized by the same
   deployment resolution the MCP data path uses, with the refusal shapes
   distinguished — no-access / unknown-toolset / trust fault / deployment fault, the
   401 split from the 403 by D16 — and the public-toolset scenario pinning the
   non-admin pass. Addresses DT-EP5-9; removes the false-denial defect class the
   prior read carried and the wrong-class diagnosability defect the second live run
   exposed.

### 7. The threat-model delta

The entries `docs/threat-model.md` gains or changes — landed by this change's
implementation (task group 5), before the change is done:

- **EP5's title and framing generalize** — "server-to-server calls into Core and the
  Keycloak back-channel" becomes "…and the identity-provider back-channel (discovery
  or the directly-configured endpoints, exchange, refresh grant, key set)"; the leg's
  shape note states the two configurations it now has: the internal plain-http
  override (the local shape) and the external internet TLS provider (the tested
  shape), and the two endpoint sources it can carry — the discovery document's, or
  the operator's directly-configured trio (D11). TB3/TB7 reword to match —
  the IdP is either a compose-network peer or an external provider beyond it, and the
  boundary statement must not assume the local shape or either endpoint source.
- **New threats in EP5's table:** the forged-discovery-document steering threat
  (DT-EP5-1, mitigated by the validation requirement, residue the TLS-bounded
  RES-19 class restated for the internet leg — and absent entirely in direct mode,
  which carries no provider-asserted input); the other-journey issuer confusion
  (DT-EP5-5, mitigated by exact pinning); the challenge-off interception variant
  (DT-EP5-3, accepted as the mode's priced residue — its control inherent since the
  round-5 ruling: client authentication is on in every mode — re-open trigger:
  TLS-fronting the public origin or the mode's retirement); the discovery-fetch amplification
  (DT-EP5-2, mitigated by the cache — absent in direct mode, which fetches nothing);
  and the direct-mode operator-input rows (DT-EP5-8: the mistyped-or-swapped-endpoint
  mis-use of DT-EP5-7's family, and the stale-endpoint availability residue — the
  mode's priced, documented trade).
- **EP4 gains the client-secret row** (DT-EP4-1) and the asset table gains **A18 —
  the identity-provider client secret** (high C, low I, low A; footprints: the
  `.env` slot at rest, process memory in every deployment, the token-endpoint leg in
  presentation on every token request — both toggle positions, per the round-5
  ruling; blast radius the IdP-leg client only). The exposure class the prior
  public-client design permitted — a deployment with no client secret at all — is
  **removed by the ruling** and recorded as such in the model: no deployment of this
  gateway starts without the secret.
- **RES-19 (the internal-leg residual) is re-priced:** the plain-http override
  deployments now carry the client secret on that leg on every token request, in
  both toggle positions — a wider exposure than the refresh token alone, and no
  longer mode-conditional — stated in the residual's bounding control;
  the external-TLS IdP shape is the residual's narrowing case for the discovery,
  exchange, refresh, and key-set calls, with the same acceptance as any HTTPS client.
- **Asset rows reworded provider-neutral:** A2 ("the user's real Keycloak/DIAL JWT" →
  the user's identity-provider JWT), A8 (Keycloak credentials and SSO session → the
  identity provider's), A12 (Keycloak admin/test credentials → the local development
  identity instance's — kept, because the local dev shape is still a Keycloak
  deployment per D8); the attacker inventory's "deployment administrator … and
  Keycloak" wording follows.
- **The rewording's scoping rule, stated so the sweep is checkable:** facts about the
  *local deployment* — the compose service, the dev realm, the provisioning helper's
  targets — legitimately stay Keycloak-named (D8's boundary; the model's §1
  as-it-stands description of the local shape included); *mechanism* vocabulary — the
  federation leg, its tokens and codes, its trust boundary, its key set — must go
  provider-neutral, because after this change the system has no Keycloak-spelled leg
  for those rows to describe. Beyond the entries enumerated above, the
  mechanism-level spellings this rule reaches: A5's code inventory ("Keycloak code"
  → the identity-provider code), the EP3 callback-URL row ("the E6/E7 callback URLs
  carry the Keycloak code"), T3-3's mitigation prose ("the gateway's for the
  Keycloak leg"), T5-2's mitigation prose ("verifying against Keycloak's published
  keys", "the Keycloak legs"), M2's pair list ("gateway↔Keycloak" →
  gateway↔identity provider), and the §10 compose-network row's "gateway↔Core/Keycloak
  legs". The check is a grep: after the edit, every `Keycloak` hit in
  `docs/threat-model.md` must be either a local-deployment fact (D8's boundary) or
  reworded — no mechanism-level hit survives.
- **§10's compromise-point tables update with the boundary change** — the method's
  adds-a-surface requirement (`docs/security-analysis.md` §4: where a trust boundary
  or credential changes, the asset/footprint **and compromise-point tables** are
  updated with it), and this change adds both an external-internet provider shape and
  load-bearing secret material. The Keycloak component row rewords to the two IdP
  shapes: the local development instance (a compose-network component — what it holds
  today, plus the ability to authenticate federation flows, the gateway still gating
  issuance) and, in a new row, the **external identity provider**: a compromised
  external IdP mints any-`sub` tokens under the pinned issuer and publishes the
  matching key set, which the gateway's exact pin then accepts — the mint-any-`sub`
  chain from the provider position, TB7's trust restated for the internet shape
  (T5-2's peer gain relocated beyond the compose network). **Accepted with
  reasoning:** the pinned issuer plus its published key set *is* the trust — the
  provider is the trust anchor by design, and the gateway distinguishes a compromised
  provider from an honest one in no way, exactly as it cannot distinguish a
  compromised Core today (the Core row's own acceptance); no gateway-side control can
  bound a party whose assertions the pin exists to trust.
- **The availability read re-pins, and its mechanism vocabulary re-pins with it
  (D15, task 8.1 — landed by this change's implementation before the code delta, the
  standing order):** the flow's toolset read becomes the deployment-listing read,
  and the model's "per-user settings read" wording names a read the flow no longer
  makes — the rewording reaches every mechanism-level mention: §3's flow sketch
  ("existence is decided post-authentication, at the flow's per-user settings
  read"), EP5's title and shape note ("toolset settings read … the flow's
  kind-and-signed-in decisions ride the per-user settings read"), the
  mint-without-consent row's bounding ("the DIAL authorization check (the per-user
  settings read)"), the forged signed-in answer row ("the per-user settings read"),
  the forged app answer row's comparison ("the same trust that already carries the
  toolset settings"), the app-read RES entry's "toolset settings read's forged
  answer (T5-7)" comparison, M23's routing-decision row ("on its own settings
  read"), the never-cut table's row 4 ("the flow's per-user settings read"), T5-3's
  disposition ("the per-user settings read is the toolset namespace's existence
  decision"), and the settings-field mitigation block's "one settings read per
  flow" — each becomes the listing read's wording, the mechanism unchanged. Two
  substantive records ride the rewording: T5-7's class gains the listing route as
  one more member of the same Core answer (RES-19's acceptance unchanged), and the
  **false-denial defect the live run exposed — an availability oracle authorized by
  the caller's admin role, refusing non-admin users toolsets the data path serves —
  is recorded as removed by this change**, with the listing read's
  authorization-equals-the-data-path property stated in EP5's shape note. The
  check is the §7 scoping rule's own: after the edit, no mechanism-level "settings
  read" hit survives in the model (the D8-scoped local-deployment facts are
  untouched by this rewording — none of them name the toolset read).
- **The listing read's refusal classes split (D16, task 9.1 — landed by this
  change's implementation before the code delta, the standing order):** the model's
  listing-read row (T5-7's class) gains the fourth refusal shape — the trust-fault
  class (a 401: Core could not validate the sign-in's identity token), distinct on
  the page and the audit trail from the no-access, unknown-toolset, and
  deployment-fault shapes — and the **wrong-class diagnosability defect the second
  live run exposed — a trust fault rendered and recorded as an access denial,
  undiagnosable because Core logs no record of its 401s — is recorded as removed by
  this change**. No residual widens and none narrows: the forged-answer residue
  keeps T5-7's acceptance unchanged (a forged 401 costs one flow, the same as a
  forged 404 — the split names the class, it does not price a new one).
- **No residual is closed by this change** and none is widened except RES-19's
  override case (the client secret on the plain leg in every deployment now) and the
  challenge-off residue; the no-secret deployment exposure class is **removed by the
  round-5 ruling** — a narrowing, not a widening; the false-denial defect class is
  **removed by the availability re-pinning (D15)** and the wrong-class
  diagnosability defect by **the refusal-class split (D16)** — likewise narrowings;
  D3's re-judge of every residual against the production shape is untouched by this
  delta's scope.

### 8. Open questions

- **OQ-A — decided (owner round 4): the owner's tenant is the classic B2C flavor.**
  The flavor half of the question is closed: the live run (task 7.1) targets the
  tested family's classic flavor — the per-policy (tfp) issuer shape, the
  per-journey-issuer-appended discovery path, the confidential (web) registration's
  refresh-token issuance (live-run-to-verify, OQ-B) —
  and it is two-part (owner round 4): the controlled acceptance on the local
  compose stack, then the real-world acceptance against the owner's existing
  B2C-configured DIAL deployment and its real app — the same chain in both parts,
  with the `IDP_*` federation profile identical between them and the environments'
  Core and public origins the recorded per-environment delta (task 7.1 states the
  operative criterion in full). What
  remains live-run-to-verify is the two classic discovery facts the public docs do
  not state (Context, D9, task 7.1): that b2clogin serves the well-known document at
  the tfp-issuer-appended path D1 fetches, and that the policy's discovery document's
  `issuer` member equals the tfp issuer (the per-policy "Issuer (iss) claim" setting
  enabled — the operator prerequisite task 5.1 states). The successor flavor
  (External ID) becomes the **untested alternative** — its per-tenant issuer shape
  and standard-suffix discovery stay in the Context/D9 record as context, stated as
  untested, not deleted: a future deployment of that flavor is a configuration
  profile, not a code change. The decision changed no mechanism and no Class A
  surface (D14): it is a Class B working-artifact fact about which literal the live
  run verifies. The recorded remedy stands unchanged: if the tfp-path fact fails,
  direct mode (D11) is the configuration answer — the operator configures the three
  endpoints at the documented `<tenant>.onmicrosoft.com/{policy}` spellings, and the
  issuer stays the tfp form for pinning — and the live run records which endpoint
  source the tenant used. Resolved as to the flavor; the two discovery facts resolve
  at the owner-dependent live run.
- **OQ-B — does the chosen client registration shape receive session refresh tokens
  at the code exchange without `offline_access`?** Under the round-5 ruling (D5) the
  chosen shape is the **confidential (web) registration**, and for that shape the
  question is **live-run-to-verify**: the public docs state the SPA/PKCE shape's
  24-hour refresh-token fact, not the web shape's issuance, and the tested provider
  is expected to issue refresh tokens by default for its web registrations too — the
  run verifies it against the actual tenant (Context, D9, task 7.1); the successor
  flavor's answer is the untested alternative's open fact. The failure shape is
  already spec'd (the loud no-refresh-token sign-in refusal), so a negative answer is
  a configuration change at the provider, not a design change. Resolved by the live
  run.
- **OQ-C — the MCP conformance suite's availability** as the acceptance certificate
  (the roadmap's conditional acceptance row): the tasks carry it as conditional — run
  it when a suite exists, record its absence otherwise.
- **OQ-D — decided (owner round 4): the helper-scoped `KEYCLOAK_*` settings keep
  their names.** The owner confirmed D8's split on the principle, recorded verbatim
  there: the gateway itself is generic, but examples and tests can and should be
  IdP-specific. No artifact change was needed — the design already carried the
  split, the provisioning helper already keeps its Keycloak Admin REST vocabulary,
  and the probes' local-instance fixtures already stay; the confirmation removes the
  uniformity option and closes the question. The ruling's agreement with D14 (the
  same position, two applications) is stated in both decisions.
- **OQ-E — the discovery TTL's default (300 s):** a tunable, not a design fork; the
  live B2C run may show Microsoft's discovery endpoint is slow enough to prefer a
  longer default. Answerable at implementation without reopening this design.

## Risks / Trade-offs

- [The discovery document is a new provider-asserted integrity input] → validated
  against the configured issuer (issuer equality, origin-bound endpoints, HTTPS, no
  redirects) and refused whole on any failure — a document the gateway accepts cannot
  steer a call anywhere the operator did not configure (D3, delta spec).
- [The challenge-off mode drops the identity leg's code binding on a plain-http
  front door] → the challenge is default-on, the client secret is required and
  presented in every mode (the control is inherent, not mode-conditional — D5, the
  round-5 ruling), the residue disclosed in the threat model with TLS-fronting as
  its re-open trigger (D5, SIA DT-EP5-3).
- [The rename is breaking for every existing local deployment] → the migration is one
  lockstep task (settings + compose + route + provisioning + probes + docs), the
  compose-boot gate catches a half-renamed stack, and in-flight flows land on the
  benign expired-flow page bounded by the flow TTL (D7, Migration Plan).
- [Discovery adds a provider dependency to sign-in availability] → cached (one fetch
  per TTL), the failure shape is the existing operator-facing fault, and
  already-minted tokens are unaffected (D4, SIA DT-EP5-6).
- [An internet IdP widens the outage and latency surface of the identity leg] → the
  existing generous outbound timeout and fail-closed semantics carry it; this is the
  price of the generalization, stated rather than mitigated away.
- [Exact issuer pinning refuses tokens a "smarter" matcher would accept] → that
  refusal is the point (D6); the operator configures the one federated journey's
  issuer, and other journeys' tokens are not this deployment's users.
- [Direct mode's endpoints go stale silently when the provider moves them] → the
  trade is the mode's price, stated rather than mitigated: discovery stays the
  default, the operator reference names endpoint freshness as the direct-mode
  operator's responsibility, and a moved endpoint fails the leg closed at first use
  with the fixed-vocabulary operator-facing error (D11, SIA DT-EP5-8).
- [Direct mode removes the forged-document class but adds operator-input trust] →
  the operator is inside the trust boundary at the issuer setting's own level,
  HTTPS-or-override is enforced at startup, and a partial or malformed set refuses
  startup loudly (D11, SIA DT-EP5-8) — the residue is the DT-EP5-7 mis-use class,
  accepted on record.
- [A Core build whose listing route does not enrich the per-caller statuses never
  short-circuits] → the one-read shape's priced trade: the status read is deleted
  because its route is the same URL the listing read uses, so the absence rule the
  two-call design fell back with is the whole discipline — an absent status is not
  signed in, the flow fails closed into the kind branch, and an OAUTH toolset re-runs
  its consent (the benign loop) while a non-OAuth toolset is refused as ever (D15).
- [The trust-fault page tells the user to stop, where a blind retry might have healed
  a transient key-set fetch failure] → priced and stated: the retry a consumed flow
  forecloses is one sign-in re-run — a fresh flow mints a fresh identity token, so
  nothing of the failed flow is reused — while the wrong-class page it replaces sent
  the operator hunting an access problem that does not exist and the user asking for
  access they may already hold; the diagnosability gain is the trade's point (D16).

## Migration Plan

1. Land the delta spec and threat-model updates first (the standing order: a
   mitigation that exists only in prose is not landed).
2. One lockstep implementation task rotates the vocabulary and the route:
   `gateway/settings.py` + `gateway/idp.py` + `gateway/federation.py` (rename +
   discovery + the confidential-client mode), `.env.example`, `docker-compose.yml`, the provisioning
   helper's gateway-facing writes (the new redirect URI registration),
   `scripts/probe_*.py`, both operator docs, README, and the tests — no intermediate
   commit leaves the stack half-spelled.
3. A local deployment migrates by rewriting its `.env`: `KEYCLOAK_ISSUER` →
   `IDP_ISSUER` (and the other gateway-consumed settings), setting `IDP_CLIENT_SECRET`
   (required at startup in both toggle positions — D5, the round-5 ruling; the
   provisioning helper registers the client confidentially and the secret it issues
   is the value), leaving the helper-scoped `KEYCLOAK_*` entries untouched (D8);
   re-run `provision_keycloak.py` to re-register the
   client's redirect URI at the new `/dial/callback/idp` spelling; restart. The
   compose-boot gate verifies the stack; the routing probe battery verifies the new
   route.
4. In-flight sign-ins at the upgrade instant fail benignly (expired-flow page,
  flow-TTL-bounded); users re-run the sign-in from the harness.
5. Rollback is the same lockstep in reverse; no data migration exists (no store, no
   token shape, no custody change). Issued tokens are unaffected by the rename — the
   issuer is the gateway's public origin, unchanged.
6. The tested external provider's configuration (placeholders now, real values at
   the live run)
   is additive: a second `.env` profile against the `IDP_*` settings, no code change.
7. The direct endpoint configuration (D11) is additive and optional: a deployment
   whose provider's discovery is unavailable or served at a spelling the gateway's
   fetch does not reach configures the endpoint trio instead — no route, no
   vocabulary, and no custody impact; a deployment that had nothing configured
   beyond the rename keeps discovery mode by doing nothing.
8. The availability re-pinning (D15) is breaking for configuration in one setting
   only: `TOOLSET_BUCKET` is removed, because no read the flow makes addresses a
   bucket any more. A deployment carrying the setting (the default `platform` or any
   other value) simply drops the line — the stale value is ignored, never validated,
   and no migration step exists beyond deleting it; the flow's behavior change is
   the fix itself (non-admin users pass availability for the toolsets the data path
   serves them). The operator reference and `.env.example` lose the setting in the
   same lockstep task as the code (task 8.2).

## Open Questions (deferrable)

OQ-A's flavor half and OQ-D are decided (owner round 4 — classic flavor; the
helper-scoped settings keep their names); OQ-A's two discovery facts and
OQ-B/OQ-E above are deferrable to the live run and the implementation pass
without changing the specs or this design; OQ-C is the roadmap's own conditional row.
