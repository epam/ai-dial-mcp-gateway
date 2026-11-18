# Owner round 2 — three questions, author decisions (2026-11-04)

Author: the design author (this pass), evaluating the owner's three pause questions on
the design's merits. Each outcome below was a live option — "revise" and "refuse with
reasoning" both were — and the decision taken is recorded with its grounding. No
mechanism of D1–D10 was reopened except where a decision below says so (D11 amends
D1's scope by adding an alternative source; the D1–D10 mechanisms themselves stand).

## Question 1 — direct configuration alongside discovery

**The owner's ask:** allow direct configuration of the main IdP parameters ("two URLs,
scopes etc") in addition to discovery, because discovery is not always working and
direct configuration sometimes resolves compatibility problems.

**Decision: adopted, as an explicit alternative source — never a fallback (design.md
D11).** Two findings drove it. First, the ask is smaller than it sounds: the client
id, the client secret, the scopes, and the roles claim path are already direct
operator settings; discovery only ever owned the three endpoint URLs. Second, the
compatibility premise is real and the change itself carries an instance of it: D9's
first live-run-to-verify fact (b2clogin serving the well-known document at the
tfp-issuer-appended path) could fail, and D1-with-no-alternative then had no answer
for classic B2C at all. The shape: `IDP_AUTHORIZATION_ENDPOINT` /
`IDP_TOKEN_ENDPOINT` / `IDP_JWKS_URI`, all-or-nothing (a partial set refuses
startup); where the full set is configured, discovery is skipped entirely (not
attempted, not fetched-and-ignored) and the trio serves all four legs — one spelling
of the IdP leg preserved (C1's inheritance constraint). Per-member override and
runtime fallback-on-discovery-failure were rejected with reasons (D11): mixing
sources recreates the drift discovery exists to remove; runtime fallback makes the
effective source depend on provider availability and masks provider faults the
fail-closed design exists to surface. Validation: well-formed absolute URLs, HTTPS
unless the endpoint shares the back-channel override's origin; D3's
origin-bound-to-issuer rule is deliberately not carried over (it constrains
provider-asserted documents; direct-mode input is operator-asserted at the issuer
setting's own trust level, and a same-origin rule would refuse legitimate
split-origin providers). Issuer pinning, the back-channel override mechanics, and the
no-PKCE mode are unchanged. The SIA gains DT-EP5-8 (mistyped-or-swapped endpoint
[mis-use]; stale endpoint after a provider change); the forged-document
(DT-EP5-1) and fetch-amplification (DT-EP5-2) classes are absent in direct mode —
recorded as a mode-conditional narrowing. The P4 outcome line is amended by this
ruling (roadmap wording follows at archive time); OQ-A's worst case now has a
recorded remedy.

## Question 2 — compare with how DIAL itself configures IdPs

**The owner's ask:** review how IdPs are configured in DIAL Chat and Core, fresh, and
decide whether making the gateway's configuration similar would unify the support
team's mental model.

**Decision: partial alignment — and most of it was already in the design (design.md
D12).** The family configures IdPs in both mental models, verified against fresh
code:

- **Core (ai-dial-core, branch `development`, fast-forwarded this pass from
  `0cd885f37ac334e83daf99722647bb2b24f92f71` to
  `6dae044afb008e99cdd044ae1dcb97385c4fbefc`, 2026-11-03):** the IdP-login leg is
  direct-configuration only — `IdentityProvider`
  (`server/src/main/java/com/epam/aidial/core/server/security/IdentityProvider.java`)
  reads per named provider (`identityProviders` in `sample/aidial.settings.json`) a
  `jwksUrl` or a `userInfoEndpoint` (exactly one, or `disableJwtVerification`), an
  `issuerPattern` **regex**, `rolePath`(s)/`rolesDelimiter`, `projectPath`,
  `audience`, logging fields, and an `offlineClient` with explicit
  `authorizationEndpoint`/`tokenEndpoint` — no OIDC discovery anywhere on that
  leg; `AccessTokenValidator` (same package) routes a token to its provider by
  regex issuer match, with a userinfo fallback for opaque tokens. Core's upstream
  OAuth clients (`config/src/main/java/com/epam/aidial/core/config/ResourceAuthSettings.java`,
  `credentials/.../validation/OauthAuthSettingsValidator.java`) carry both
  endpoint-source modes: static registration is direct — it requires `client_id`
  + `client_secret` + `authorization_endpoint` + `token_endpoint`; dynamic
  registration (DCR) forbids all four and is **discovered** — the `credentials`
  module at this SHA
  (`credentials/.../util/ResourceEndpointUtil.java`,
  `credentials/.../service/metadata/ProtectedResourceMetadataService.java`,
  `AuthorizationServerMetadataService.java`) builds `.well-known` URLs in both
  the RFC 8414 host-inserted and the OIDC suffix-appended spellings, fetches a
  five-spelling fallback set off the resource endpoint until one validates
  (resource → protected-resource metadata → authorization-server metadata), and
  feeds dynamic client registration, whose response supplies the client's
  endpoints. So Core itself carries both mental models — direct for its
  IdP-login leg and static upstream registrations, discovery-with-runtime-fallback
  for upstream DCR — which makes D12's both-models verdict more true, not less;
  the multi-spelling runtime fallback that upstream path uses is exactly the
  mechanism D1/D11 refuse for the gateway's IdP leg, where the same
  spelling-compatibility problem is answered at configuration time instead (D11's
  direct trio, one source per leg chosen by configuration, never by a runtime
  fetch's success).
- **Chat (ai-dial-chat, `apps/chat-api`):** discovery-based — grounded at
  `e09fc75b34faa06b128ad0899a2835876ac5ce40` (`origin/development` as fetched,
  2026-10-08; see the checkout-state note below):
  `apps/chat-api/src/auth/providers/provider.types.ts` (`ProviderConfig`: `issuer`,
  `clientId`, `clientSecret` — required, confidential clients — `scope`,
  `rolesClaim`, `adminRoles`, `postLogoutRedirectUri`; no endpoint fields) and
  `provider-builders.ts` (per-provider env vars: `AUTH_<PROVIDER>_CLIENT_ID` enables
  the provider, `_SECRET` required, `_HOST` bare-host-or-URL becomes the issuer,
  `_SCOPE` with per-flavor defaults — most of which include `offline_access`);
  openid-client discovery runs **at startup** (the README states discovery failure
  means the application does not boot), and the issuer is validated against the
  **discovered** canonical issuer (so an internal discovery URL may return the
  external canonical issuer); private-CA trust is a mounted CA bundle env var.

**Checkout-state note (the round's authorization limits, applied):** the Core
checkout was fast-forwarded to the fetch's tip (the checkout's own unrelated local
SIA/security working files were verified untouched by the incoming diff's file list
and were left as they were). The chat checkout is on branch `development` with a
modified working file (`apps/chat/src/utils/auth/auth-callbacks.ts`) — dirty, so per
the round's scope limits it was **not pulled**; two `git fetch` attempts failed with
connection resets, and the freshest locally available remote tip is
`e09fc75b34faa06b128ad0899a2835876ac5ce40` (2026-10-08), whose objects are present —
all chat grounding is committed content at that SHA (read via `git show`; no working
files touched). The chat checkout's own working-tree HEAD (2025-08-29) is stale and
was not used as grounding.

**What was adopted:** the direct-mode setting names (D11's trio) ride the vocabulary
the family already shares — the OIDC discovery member names and Core's
`authorizationEndpoint`/`tokenEndpoint` concepts; the
issuer/client-id/secret/scopes vocabulary was already aligned with both shapes and
is now recorded as a checked fact; and the gateway's discovery mode already **is**
the chat's mental model (issuer in, discovery resolves endpoints, credentials and
roles-claim as settings), so chat-side support instincts transfer to the gateway's
default mode as-is. **What was refused, with reasons (D12):** Core's `issuerPattern`
regex (a multi-provider routing feature; adopting it would weaken the exact pin of
D6/DT-EP5-5 the same way D6 already rejected `{tenantid}` templating); the chat's
startup discovery with boot-coupling (D4's lazy choice is deliberate; the chat's own
README documents the boot-failure cost); the chat's canonical-issuer-from-discovery
(the gateway pins the configured issuer and validates the document against it —
stronger); Core's `userInfoEndpoint` leg (already this change's recorded-not-built
D10); the chat's per-flavor scope defaults (most include `offline_access`, which the
gateway must never request). Noted for the deployment workstream, not this change:
the chat's mounted-CA-bundle mechanism for private-CA providers (a C3/P5 packaging
fact).

## Question 3 — client_secret delivery

**The owner's ask:** how will the client secret be delivered when required, and
should C2 add a delivery variant (e.g. reading the secret from a mounted file)?

**Decision: no new variant in C2 — the delivery is the environment slot, stated
where a reader looks (design.md D13).** The design already answered the surrounding
questions: the secret's home is `IDP_CLIENT_SECRET` (`SecretStr`, never logged,
never in `repr`), it is required at startup in no-PKCE mode (D5's refusal names both
settings), it is never presented in the default PKCE mode (the delta's converse
scenario), its committed shape is the `.env.example` empty placeholder (never-cut 6),
and its move under deployment secret management is C3's recorded scope (the
production roadmap's P1, packaged with the pod's secret injection in C3 = P5+P1+T3).
The missing piece was the delivery mechanism itself, now stated: an **environment
variable** sourced from the deployment's `.env` (compose) or deployment environment —
the same delivery the signing and custody keys use, one pattern for the whole secret
class, never argv, never a gateway-read file. A mounted-file variant was refused for
C2: a second delivery mechanism with its own reading/permission/rotation code and
SIA coverage, built now and immediately re-designed by C3's P1 ("secrets out of env
files *is* the pod's secret injection" — the roadmap's own packaging rationale), for
zero security gain in the compose deployment C2 targets; a deployment wanting
file-based injection before C3 feeds the variable from its own secret material
(compose `env_file`, K8s secret env injection) without the gateway knowing. Recorded
in D13, the task 5.1 operator row, and the `.env.example` comment task 2.3 carries.

## Artifacts changed this round

- `design.md` — Context gains the DIAL-family configuration grounding; D1 gains the
  D11 cross-reference; D8's settings list gains the endpoint trio; new D11, D12,
  D13; SIA §1 (change description), §2 (impact-level note), §3 (invariant rows 4–6),
  §4 (EP5 heading + two new direct-mode rows), §5 (new DT-EP5-8), §6 (grouped list
  item 7), §7 (threat-model delta: two endpoint sources, six EP5 rows), §8 (OQ-A's
  recorded remedy); Risks gains two direct-mode rows; Migration Plan gains the
  additive-direct-mode step.
- `specs/mcp-signin/spec.md` — the discovery requirement is mode-conditioned (the
  direct set replaces discovery whole, never member-by-member; no runtime fallback);
  a new ADDED requirement "A directly configured endpoint set replaces discovery
  whole" with five scenarios; the refresh and verification requirements' amendments
  and normative clauses re-worded from "discovered" to the leg's one configured
  source; the key-set scenario renamed accordingly; the validation requirement's
  plain-http scenario stated mode-independent.
- `tasks.md` — 1.1 (six EP5 rows, two endpoint sources); new 3.4 (direct-mode
  implementation + tests); 5.1 (direct-mode guidance, family-alignment note,
  client-secret delivery statement); 7.1 (the tfp-path failure remedy and the
  endpoint-source record).
- `proposal.md` — Why carries the round-2 ruling; What Changes gains the
  direct-configuration bullet (with the delivery statement); Modified Capabilities
  names the new requirement; Impact's `gateway/idp.py`, `gateway/settings.py`, and
  `tests/` rows carry the direct mode.
- `release-notes-draft.md` — both audiences gain the direct-mode and delivery
  statements, and the team note gains the DIAL-family alignment verdict.

## Validation this round

- `openspec validate generalized-idp-federation` — **valid** (exit 0).
- `python scripts/check_publication_leaks.py` — **PASS** (200 tracked files
  scanned; 3 findings, all pre-existing and waived, 0 unwaived).
