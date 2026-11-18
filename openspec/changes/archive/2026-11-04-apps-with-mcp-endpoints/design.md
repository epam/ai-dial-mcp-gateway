# Design

## Context

The production roadmap's C1.5 item (`docs/production-roadmap.md` §"The iteration,
packaged and ordered") restores the dropped N1: DIAL applications with MCP endpoints
as sign-in-able resources. C1's P3 half built the general rule this change needs —
the flow's routing decision (the signed-in check, the short-circuit, the kind
branch, the impossible-branch refusal, all on the per-user settings read) — so what
remains is the apps resource *surface* (the front-door path, the discovery
documents, the router's apps MCP location) and the app-resource semantics, verified
against the current Core source (the verification records live in `evidence/`,
file:line cited throughout this design).

The verified facts that shape everything below:

- Core serves an app's MCP endpoint at `/v1/deployments/{id}/mcp` (RouteTemplate
  `APPLICATION_MCP_PROXY`) and its protected-resource metadata at
  `/.well-known/oauth-protected-resource/v1/deployments/{id}/mcp`
  (`APPLICATION_MCP_PROXY_METADATA`) — **not** at an `/openai/<app>/mcp` shape; the
  pre-verification assumption of an `/openai` path is falsified.
- The unauthenticated 401 + `WWW-Authenticate: Bearer resource_metadata=…` challenge
  covers the apps MCP path identically with the toolset path, and the gate for both
  — challenge and metadata route alike — is the global
  `toolsets.security.authorizationServers` configuration, served from the
  `toolsets` settings block: there is no `apps.security.*` (Proxy's MCP-path check
  matches both patterns; `WellKnownResourceMetadataService` is built from
  `settings("toolsets")`; unset, the 401 carries no challenge and the metadata
  route answers 404 — neither an existence oracle).
- Applications carry **no authentication kind and no per-app sign-in status**:
  `AuthenticationType` lives on `ResourceAuthSettings`, which `SecuredResource`
  carries and `Application extends Deployment` does not — an app's inline
  `external_services[]` entries carry auth settings of their own, and the app read
  enriches per-user statuses **per external service only**.
- The ops credential API cannot serve apps: `/v1/ops/toolset/signin` requires the
  deployment to be a `SecuredResource`, and an `Application` is not one — apps are
  credential-free **by construction** for the gateway.
- `DIAL_NATIVE` is external-services-only in function (sign-in explicitly rejected
  for it on the external-service surface) — the owner's standing 2026-11-03
  correction; no design here assumes it for apps or toolsets.
- Core's identity-provider entry verifies the **single configured `audience` — the
  marker — and nothing else**: no per-resource audience match exists on either MCP
  data path (`IdentityProvider.verifyJwt` → `verification.withAudience(audience)`).
  The gateway's per-resource audience is its own addressing discipline, not a
  Core-enforced check — the spec wording is corrected to match this (D6).

## Goals / Non-Goals

**Goals:**

- A harness pointed at an app's MCP endpoint completes a sign-in through the front
  door and calls the app with a gateway-signed token — with no consent screen, no
  credential call, and no upstream round-trip of any kind, because the resource kind
  is credential-free by construction.
- The audit trail answers that the flow minted through the kind-driven
  short-circuit (the charter's acceptance: the records show it).
- The apps discovery tier mirrors Core's own apps tier exactly as the toolset tier
  mirrors Core's toolset tier: registry-independent, zero Core calls, existence
  decided post-authentication at the flow's app read — the mirror property,
  extended to the second namespace.
- The toolset flow is unchanged (the routing decision, the consent and
  short-circuit paths, the issued tokens) — the app path is added beside it, not
  folded into it beyond the shared resource resolution.
- The threat model's affected entries are updated by this change, not after it.

**Non-Goals:**

- No `DIAL_NATIVE` support of any kind (the owner's standing correction — Core's
  function is external-services-only; toolsets may support it in the future, and no
  design here may assume it).
- No app external-services credential surface: the gateway's app flow never reads
  per-service statuses and never calls `/v1/ops/external-service/*` — that surface
  is DIAL Chat's flow. The app read is used for exactly two answers: can this user
  read this app, and does this app exist.
- No status surface at all, either namespace (D4 — the owner's ruling at the review
  pause, superseding the no-app-status decision this change first authored: the
  existing toolset status endpoint is deleted, not scoped, and no apps analogue is
  added).
- No path-grammar unification: the `/dial/` (toolsets) and `/apps/` (apps) prefixes
  stay as authored — the owner's ruling at the review pause; unification (one prefix
  per concern, retiring the reserved-name class) is recorded as a deferred item in
  the roadmap's "Deferred — to later iterations" table, naturally landing with E1
  (the Core merge) or as its own change with a migration window.
- No change to the router's toolset location, the challenge map's toolset entry, or
  the toolset flow's built rule beyond the shared resource resolution.
- No Core-side work: the asks a registry-bound protected-resource route and
  per-resource audience enforcement are recorded (§8), not built here — the
  gateway's design stands on what Core serves today, verified.

## Decisions

**D1 — The front-door path shape: `/apps/{name}/mcp`, a second path shape beside
the toolset `/dial/{name}/mcp`, proxying to Core's `/v1/deployments/{id}/mcp`.**

The kind lives in the path, and that single property decides most of what follows:
a toolset and an app that share a name never collide (the registries are disjoint
namespaces in Core; the front door routes by kind, not by registry lookup); the
resource-URI derivation is unambiguous in both directions; and the router's new
location has no interaction with any `/dial/` alternation.

The alternatives, and why each loses:

- *`/dial/{name}/mcp` shared, kind resolved by a Core lookup* — rejected: it needs
  an unauthenticated existence/registry decision at the door (the consult class C1
  deleted, for the same reason: it would need the one credential class the owner's
  principle bars), and a toolset and an app sharing a name would be
  indistinguishable on the front door.
- *`/dial/app/{name}/mcp` (a kind segment under `/dial`)* — rejected: it makes
  `app` a reserved toolset name (refusing a toolset actually named `app`, and
  growing the reserved list every time a second kind appears), and it puts the
  apps namespace under the toolset namespace's guard surface — two namespaces
  sharing one name segment's collision space is exactly what a distinct prefix
  avoids.
- *`/openai/<app>/mcp` (the pre-verification assumption)* — falsified by the Core
  source: Core's app MCP path is `/v1/deployments/{id}/mcp`, and the front door is
  the gateway's own namespace anyway — but the path is named here because it was
  the working assumption before verification, and the correction is part of this
  change's record (`evidence/` fact 1).

App names pass their own guard: the routed-path charset `[a-z0-9-]+` (the shape the
router's apps location is written against) and the apps restriction when one is
configured (D5). The toolset guard's reserved front-door names do not apply:
nothing the gateway owns is served under the apps namespace's name segment — the
reserved names are `/dial/`-scoped authorization-surface segments (`/dial/authorize`,
`/dial/token`, …), and an app name occupying `/apps/{name}/…` can never capture
them. An app name carrying a slash — a bucket-scoped app id — fails the charset:
the front door serves the deployment-registry apps, the same routing-charset
rationale as toolsets, stated rather than left to inference.

**D2 — Resource disambiguation and the DIAL authorization read for apps.**

The `resource` parameter distinguishes the kind by its URI's shape —
`{public-origin}/dial/{name}/mcp` a toolset, `{public-origin}/apps/{name}/mcp` an
app — because one flat authorization server serves both kinds and the resource URI
is the one spelling every surface already shares. The prefix-anchored inverse
derivation the toolset resolution uses (`toolset_name_from_resource`) gains an
apps twin, and the two derivations are disjoint by prefix: a toolset resource URI
never resolves as an app name and vice versa, so no request can be reinterpreted
across kinds between surfaces.

The app flow's DIAL authorization read is the single-app read,
`GET /openai/applications/{id}`, made with the live user's verified identity token
— the same trust basis and the same position in the flow as the toolset settings
read. Verified against the Core source, it answers the three shapes the flow needs
distinguished (`DeploymentService.findDeployment` → `selectDeployment` with the
deployment's own access check; `ApplicationController`'s 404 for an unknown app):

- **403** — the user cannot read the app: the flow fails with the same no-access
  page a toolset refusal earns; DIAL authorization is enforced before any mint.
- **404** — Core does not know the name: the apps namespace's existence refusal —
  a plain-language page, one fixed-vocabulary audit record (`unknown_app`), no
  flow state surviving. The main spec's "the system's only existence refusal"
  wording becomes per-namespace by declared amendment, in both places the phrase
  lives (the federation requirement's unknown-toolset scenario and the discovery
  requirement's mirror-property sentence): the existence refusals are
  the flow's authenticated reads, one per resource kind (the toolset settings
  read; the app read), and no unauthenticated tier on either side of the front
  door carries an existence oracle in either namespace — the mirror property
  (D8) is what keeps that sentence true for apps exactly as C1 kept it true for
  toolsets.
- **Unreachable or unreadable** — the flow fails closed on the operator-facing
  fault page, a deployment fault and never an existence answer — the same
  three-shape discipline the toolset settings read carries, restated so the app
  read inherits it rather than inventing a variant.

*Why not the toolset settings route shape (`/v1/applications/{bucket}/{name}`)?*
The single-app read is the route Core enriches per caller, and the flow needs no
bucket plumbing for a registry-resolved id; the bucket-scoped resource route is
what `findDeployment` falls back to for bucket-resolved ids, and those ids carry a
slash and never pass the guard (D1). *Why not read the per-service statuses the
route enriches?* Out of scope by charter — the external-services credential
surface is DIAL Chat's; the gateway's app flow reads nothing from the answer
beyond existence and readability.

**D3 — The app flow: the unconditional kind-driven short-circuit, decided by C1's
general rule — not a new mechanism.**

The flow's stages for an app resource: (1) the identity leg, unchanged machinery —
it is kind-agnostic by construction and stays so; (2) the app read as the user
(D2) — the DIAL authorization check and the existence refusal in one read; (3) the
kind-driven short-circuit, **unconditional for this kind**: no signed-in check
runs, because no per-app status members exist to read (verified: the app read
enriches statuses per external service only, and the flow does not read them); no
kind branch runs, because no consent could establish anything for a resource that
needs no credential; no credential call and no upstream round-trip of any kind
ever run. The flow mints the harness's code directly, and the minted tokens are
the same shape a toolset sign-in issues, the audience naming the app's resource.

The justification is that this is not a new branch at all: C1's general rule —
*the upstream stage runs only when the credential is missing AND the kind makes it
establishable by consent* — already decides it, because for the app kind the
second conjunct is false **by construction** (there is no kind and no consent leg
on Core's surface to establish anything with). What distinguishes the app kind
from a non-OAuth toolset — and why the impossible-branch refusal must NOT be
reached for apps — is the first conjunct's meaning: a non-OAuth toolset's data
path is *blocked* by its missing credential (the refusal's page says so), while an
app's data path runs on the caller's own identity, authorized per call, so there
is nothing missing to refuse. The delta spec states this in the app-resource
requirement rather than amending the toolset flow requirement's branch text — the
toolset requirement keeps its scenarios byte-identical except the declared
existence-refusal amendment (D2).

One audit record carries the short-circuit: a fixed-vocabulary reason
(`credential_free_short_circuit`) naming the resource kind, with the flow's
non-credential facts. This is the charter's acceptance row — the trail must answer
*that* the flow minted with no upstream stage, and *why* (the kind), not merely
that a code was issued.

*The alternative — routing apps through the toolset flow's status machinery with a
synthesized "always signed in" answer — rejected:* it would fabricate a status
Core never answers, put the mint behind a predicate that pretends to read state,
and complicate the audit story (a short-circuit indistinguishable from a stored
credential). The honest shape is that there is nothing to check, stated as
nothing to check.

**D4 — The sign-in status surface is dropped — both namespaces (the owner's ruling
at the review pause, superseding the no-app-status decision this change first
authored).**

The owner ruled the status endpoint out of the gateway's surface entirely: the
toolset endpoint `/dial/{name}/status` is deleted, no apps analogue is added, and
the delta spec's first-authored shape — scoping the status requirement to toolset
resources — is superseded by a REMOVED entry. The ruling extends the reasoning
that motivated the original decision rather than contradicting it, on two legs:

- *For apps, the original leg, unchanged:* the status question — "will my next
  call work without a sign-in flow" — never depends on stored state for a
  credential-free resource. The 401s the gateway's own tokens shape — no token,
  an invalid or expired token — are causes the sign-in flow resolves, which is
  the exact loop the challenge exists to drive; an authorization denial (a
  revoked role, a removed access grant) surfaces as Core's own 403, and an
  unknown app as a 404, both crossing the router without the challenge — the
  synthesis fires on 401 only — statuses a harness reads directly off the failed
  call. The one 401 no sign-in can resolve is the app's own upstream MCP
  endpoint refusing a call: no stored credential is attached on the app MCP leg,
  so the app's endpoint answers for itself, and the router's rewrite points a
  harness at the gateway's sign-in for it — the same benign loop the toolset
  path's upstream-401 rewrite produces, bounded the same way (one session,
  looping, until the app's endpoint accepts the call or the operator intervenes).
- *For toolsets, the new leg:* the 401 shapes already answer the harness's
  question there too. The toolset MCP path answers 401 with the gateway's own
  challenge on no token, an invalid or expired token, and a valid token with no
  stored upstream credential — and the third shape is the "not signed in" answer
  the endpoint sold, delivered by the data path itself, while the first two are
  the causes the sign-in flow resolves. The answer the endpoint provided for one
  authenticated Core read is therefore bought for one failed call the challenge
  requirement already governs — the same round-trip, on a surface that exists
  anyway.

The operational cost is recorded rather than hidden: operators lose the per-user
sign-in probe — the one machine-readable "is this user signed in to this toolset"
answer. The diagnostic path that remains: the 401 challenge shapes on the data
path (which distinguish the token-shape causes the flow resolves), and the audit
trail (every flow's short-circuit or consent leg is recorded, so the signed-in
state a probe asked for is answerable from the records of the flows that ran).

The alternatives, and why each loses:

- *A `/apps/{name}/status` analogue* — rejected: it would answer from the
  presented token (whose validity the 401 already told the caller) plus a Core app
  read as the user (a new authenticated Core-facing surface whose only yield is a
  fact the next MCP call answers for free). It adds a surface to avoid reading a
  401.
- *Answering a fixed `signed_in: true`* — rejected twice over: it is a status
  Core never asserts (fabricated state, the D3 alternative's defect), and it
  answers "signed in" to a caller that may hold no token at all — the word would
  mean nothing.
- *Keeping the toolset endpoint and scoping it (the delta's first-authored
  shape)* — rejected by the ruling itself: a surface kept for the one namespace
  where the 401 shapes answer its question is a surface without a question, and
  the enumeration walk it retained (T1-15's mis-use) bought nothing the
  challenge does not already say.

The landing: the delta spec REMOVES the status requirement — the entry carries the
requirement's normative sentence and the removal reason, and its scenarios die
with it; the toolset-guard requirement's surface list and the pre-allocation
audit requirement's refusal enumeration drop the status path; the status-only
audit reason tokens (`missing_token`, `invalid_token`) retire with the endpoint
while every token a remaining surface uses stays; the router's status location
and its routing-doc row are removed; and the threat model's T1-15 is retired with
its cross-references reconciled (§7). The probe battery gains the row that makes
the removal observable: a status path under either namespace falls through to
Core, whose auth filter precedes any routing and answers an unauthenticated
request with Core's own 401 — the same fact of the enabled route the mirror
property names — carrying no gateway challenge; a 404 is what an authenticated
request would meet. The charter was silent on a
status surface; the decision of record is the owner's ruling, and this design
carries its reasoning.

**D5 — A second optional operator restriction (`APPS`), one per namespace; resource
inference stays toolset-only.**

One restriction per kind, not one shared: the toolset restriction (`TOOLSETS`)
governs toolsets, a new apps restriction (`APPS`) governs apps, and neither
consults the other. The reason is the same registry disjointness that decided D1 —
a name can exist as both a toolset and an app, and a shared restriction would
admit or deny both together, an operator decision the deployment never asked for;
worse, a deployment pinning three toolsets would silently unpublish every app.

The apps restriction copies the toolset restriction's semantics, not its schema:
unset means serve every guard-passing app name (dynamic, existence decided
post-authentication at the app read — the mirror property); set means only its
entries; and configured entries keep the startup routing refusal — a name outside
`[a-z0-9-]+` refuses the container's start with an operator-facing error naming
the entry, because the router's apps location is static configuration with no view
of what Core serves. An entry declares **nothing but the name**: no
`authentication_type` (an app has none — the toolset mapping's kind declaration
was deleted by C1 for exactly this class of reason), and no `scopes_supported`
(no leg ever sends scopes for an app resource — the apps document's member is
empty whether or not the app is pinned, so an entry-level scopes echo would be a
field nothing reads).

Resource inference (`gateway_infer_resource_single_toolset`) stays toolset-only,
unchanged in mechanism: its startup requirement is re-worded to name *the toolset
restriction* explicitly (a declared amendment — "a restriction" is ambiguous the
day a second one exists), and inference never consults the apps restriction. With
two namespaces served by one authorization server there is even less "the one
resource" an unnamed request could honestly be resolved to; the delta spec's
"Inference never resolves to an app" scenario pins the boundary.

**D6 — Token audience for app resources: the same shape, and the spec's enforcement
wording corrected to the verified Core fact.**

The mint is unchanged in shape: the access token's `aud` carries the addressed
resource's URI — now the app's, at `{public-origin}/apps/{name}/mcp` — plus the
marker; the refresh token's `aud` carries the addressed resource's URI alone (the
token-type separation, load-bearing as before). The code's bindings carry the app
resource, so the token endpoint's resource match and the refresh grant's resource
match govern apps exactly as they govern toolsets.

What changes is the spec's *claim about enforcement*, corrected by verification:
Core's identity-provider entry applies a single configured `audience` — the marker
— to every presented token (`IdentityProvider.verifyJwt`:
`verification.withAudience(audience)`), and **no per-resource audience match
exists on Core's MCP data paths, toolset or app**. The main spec's existing
wording ("The audience MUST contain the toolset's resource and the marker … so a
token that lacks the marker is rejected") never quite claimed Core-side resource
enforcement, but it implied a check the app surface makes checkable — and the
check falsifies the implication. The delta spec's amendment states it exactly: the
marker is what Core verifies; the resource audience is the gateway's own
addressing discipline, enforced at the gateway's resource checks, and the spec
claims no Core-side per-resource scoping.

The consequence is priced rather than hidden: a user's app-resource token is
Core-acceptable on a toolset path and vice versa (the marker is present either
way), within that user's own authorization and under Core's per-call DIAL
authorization. That is the disclosed marker-level-binding residual (RES-7 /
threat row T1-12) widened **cross-kind** — the same class, one axis wider, bounded
identically (own-scope mis-use, per-call authorization, the short access TTL); the
SIA's delta table prices it (DT-EP1-A4) and §7 amends the model's rows. The
structural fix stays what it always was — Core-side per-issuer path/audience
scoping — and is recorded as a Core-side ask (§8), not built here.

**D7 — The router's apps location: one static location, a second challenge map, and
the guard coordination the toolset location already carries.**

The router gains three pieces, each the apps twin of a discipline the toolset
location already holds:

- **The apps metadata route** — `location ~
  ^/\.well-known/oauth-protected-resource/apps/ { proxy_pass http://gateway; }`,
  beside the toolset one, so a challenged harness's document fetch reaches the
  gateway's apps document. Ordering against the toolset regex is irrelevant (the
  prefixes are disjoint), and both precede the catch-all by nginx's regex-first
  matching — the same property the existing locations rest on.
- **The apps MCP location** — `location ~ ^/apps/(?<aname>[a-z0-9-]+)/mcp$`
  proxying to `http://core/v1/deployments/$aname/mcp$is_args$args`. Every element
  is the toolset location's, carried over with the path re-derived:
  `$is_args$args` because variables in `proxy_pass` make nginx drop the query
  string (the measured behavior — a streamable session's `?sessionId=` would
  never reach Core without it); buffering off on both directions because
  streamable answers are long-lived streams; and the charset-anchored regex
  because the gateway's app name guard is written against exactly this shape —
  the guard and the routing cannot disagree, the property the toolset guard's
  shared constants already hold.
- **The challenge rewrite** — `proxy_hide_header WWW-Authenticate` plus a
  synthesized header from a **second map** keyed on the same `$status`, quoting
  the app resource's own metadata path:
  `Bearer resource_metadata="$mcp_origin/.well-known/oauth-protected-resource/apps/$aname/mcp"`.
  A second map rather than one parameterized map because the header value differs
  by capture variable (`$tname` vs `$aname`), and a map's value is a fixed
  template per variable. Both halves of the discipline are required, for the
  toolset location's own reason: without the hide, Core's challenge reaches the
  client beside the gateway's; without the synthesized header, the 401 carries no
  challenge a harness can act on. Core's own challenge names its metadata route,
  whose `authorization_servers` come from Core's `toolsets.security`
  configuration — what that lists is a deployment fact, and the rewrite is what
  makes the front door's answer independent of it: the harness is always pointed
  at the authorization server that can actually complete the sign-in, whichever
  AS the Core-side configuration names.

Guard coordination: the gateway's startup charset validation for *configured* apps
restriction entries (D5) is the static-routing refusal that keeps a pinned name
routable; the request-time app name guard covers dynamic names; both reuse the
same `[a-z0-9-]+` shape the location's regex is written against. The router's
comments carry the apps location's reasons beside the toolset ones, so the file
states why each element exists for both paths.

**D8 — The apps discovery document and the mirror property, extended to the second
namespace.**

The gateway serves one RFC 9728 document per served app at
`/.well-known/oauth-protected-resource/apps/{name}/mcp` — served from the
resource's own path, like the toolset document, so a client following a challenge
lands on the document describing exactly the resource it was challenged for. The
document is built from configuration and the requested path alone: the
name-derived app resource URI, the single AS issuer, `scopes_supported` **always
empty** (no upstream leg exists for an app resource to send scopes on — echoing
the restriction's scopes, as the toolset document does where pinned, would
advertise parameters no leg can use), and no authentication-kind extension (an
app has no kind to echo).

The mirror property is normative here exactly as C1 made it normative for
toolsets, and it extends rather than re-derives: Core serves the apps MCP path's
unauthenticated 401 challenge and the apps metadata route from the **same**
`toolsets.security.authorizationServers` configuration that serves the toolset
tier (verified — there is no apps-specific security configuration), and both are
registry-independent (the auth check precedes any registry lookup; the metadata
document echoes the requested path as `resource`; unset, the 401 carries no
challenge and the route answers 404, neither an existence oracle, and the gateway
serves its own document regardless). So the gateway's apps tier — served for
every guard-passing, restriction-admitted name, phantom and real alike, zero Core
calls — brings nothing Core's own apps tier does not: same challenge class, same
echo-document, existence decided at the same moment, post-authentication, at the
flow's app read. The `isMcpResourcePath` check covering both patterns is the
factual hinge, and it is verified in `evidence/` (fact 2): a phantom app and a
real app are indistinguishable below authentication on Core's own surface, so the
gateway's tier cannot honestly be more deciduous than that, and is not.

## Security impact analysis

Per the standing method (`docs/security-analysis.md`, the `security-analysis`
skill). Shape judgment, stated: this is a change on **existing surface classes** —
each new route is an instance of one (a static protected-resource document behind
the guard and limiter; a proxied MCP data path with the challenge rewrite; an
authenticated per-user Core read) — with no new trust boundary, no new credential
or secret material, and no new grant type, so the tables below enumerate the
**delta threats** at the touched entry points; untouched surfaces are covered by
the invariant ruling table, not re-enumerated.

### 1. Change description

*Business:* DIAL applications with MCP endpoints become sign-in-able resources
through the gateway's front door — a second path shape (`/apps/{name}/mcp`)
proxied to Core's deployments MCP path, a matching protected-resource document
mirroring Core's own registry-independent apps tier (the mirror property, extended
to the second namespace), and a sign-in flow that is the identity leg, the app
read as the user (DIAL authorization and the apps namespace's existence refusal),
and an unconditional kind-driven short-circuit — no consent screen, no credential
call, no upstream round-trip, ever, for this resource kind — with the audit trail
showing the short-circuit. A second optional operator restriction (`APPS`) pins
the served app set where a deployment wants to; resource inference stays
toolset-only. The sign-in status API is dropped entirely, both namespaces (the
owner's ruling at the review pause): the endpoint, its route, and its router
location are deleted — an authenticated public surface (E9) leaves the inventory
rather than a new one joining it — and the diagnostic path that remains is the
401 challenge shapes plus the audit trail.

*Implementation shape:* the resource URI's path shape names the kind
(`/dial/{name}/mcp` toolset, `/apps/{name}/mcp` app), resolved by prefix-anchored
inverse derivations that are disjoint by construction; the app name guard is the
routed-path charset plus the apps restriction (no reserved names — nothing
gateway-owned lives under the apps name segment); the apps protected-resource
document is static, name-derived, always empty `scopes_supported`, no kind
extension, zero Core calls; the app read is `GET /openai/applications/{id}` with
the live user's token, failing closed into the three distinguishable shapes (403
no-access page, 404 plain-language existence refusal audited as `unknown_app`,
unreachable/unreadable operator-facing fault page); the short-circuit mints the
code directly and writes one fixed-vocabulary audit record
(`credential_free_short_circuit`) naming the resource kind; the mint's audience
carries the app's resource and the marker (refresh: the app's resource alone) —
and the spec's enforcement wording is corrected to the verified Core fact that
Core checks the marker only, with the cross-kind consequence priced (RES-7
widened); the router gains the apps location (`proxy_pass` to
`/v1/deployments/{id}/mcp`, query pass-through, no buffering, hide + synthesize
challenge from a second map quoting the app's own metadata path) and the apps
metadata route; the apps discovery route joins the shared limiter with the
no-record-over-limit rule; and the status surface's removal deletes
`gateway/status.py` with its route registration (the Core status read the flow's
signed-in check uses stays, in `gateway/core.py`), retires the status-only audit
reason tokens (`missing_token`, `invalid_token`), and removes the router's status
location with its routing-doc row.

### 2. Impact level, with reasons

**Medium.** No new trust boundary, credential, or grant type is introduced: the
process's secret set is unchanged (the signing key and the custody key), the new
routes ride the existing public front door and the existing internal leg to the
configured Core, and the mint uses the existing machinery. What elevates the level
is the reach of what is added: a **new public path shape and a new unauthenticated
discovery route** (surface-class instances, but surface that did not exist); a
**new authenticated Core read** whose answer carries the apps namespace's
existence and authorization decisions; a **mint path that is consentless by
construction for a whole resource kind** — not the C1 shape (consentless where a
stored credential exists) but consentless always, which widens the
mint-without-consent surface class to an entire namespace; and a **widening of the
marker-level audience-binding residual (RES-7) cross-kind**, now a verified Core
fact rather than an implication. The level sets the security review gate's depth,
not whether this analysis runs.

### 3. Invariant ruling table

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | **Preserved — vacuously strengthened for the app kind** | The app flow never establishes, reads, or transits any upstream credential, because none exists: no credential call of any kind runs on any app path, and the app read returns the app document, never credential material. The toolset paths are untouched |
| 2 | The upstream PKCE verifier never leaves Core | **Preserved** | No app path reads a projection that could carry a verifier; the app read is not the toolset settings projection, and no OAuth fields are read from it |
| 3 | Per-user credential isolation | **Preserved** | No credential exists to isolate for apps; the minted token carries only the identity-leg user's own verified claims, and Core resolves per-call identity from the token's `sub` |
| 4 | DIAL authorization applies to every toolset call | **Preserved, and the invariant's reach extends to app calls** | The app read enforces DIAL authorization as the user before any mint (403 refuses the flow); Core's per-call authorization — the deployment access check on the app — runs on every apps MCP call with a gateway token, exactly as it runs on every toolset call, whichever front door the call came through |
| 5 | No credential in logs, argv, or error messages | **Preserved** | No credential material is introduced anywhere on the app path; every new refusal (`unknown_app`, the guard tokens, the short-circuit record) is fixed-vocabulary with non-credential facts, truncated per the existing cap, and the app read's failures never echo Core's response text |
| 6 | No hardcoded credentials in the repository | **Preserved** | No new credential: the apps restriction is non-secret configuration through the existing `.env` mechanism with a committed placeholder |
| 7 | The signing key is IdP-grade secret material | **Preserved** | Key custody, publication, and rotation are untouched; the app path mints with the same key under the same discipline |

### 4. Delta threat tables, per touched entry point

Structure per the vendored instruction. Mis-use cases are marked **[mis-use]**;
flow/logic flaws classify under Use Control Misconfiguration with the leaf chosen
by the attacker's gain. Touched entry points: **EP1** (the public OAuth and
discovery endpoints — the apps PRM route, app resource resolution, the app
short-circuit mint), **EP5** (the server-to-server legs — the app read), and
**EP6** (the front router — the apps location). EP1 also *loses* a surface: E9
(the status endpoint) is deleted by this change, and a removal carries no delta
threat table — it introduces no threat; its ledger effect is T1-15's retirement
(§7). EP3 (the browser pages) is
touched — the app flow renders the no-access, unknown-app, and fault pages — but
carries no delta table: the pages are fixed text rendered through the shared
hardening helper, adding no threat shape beyond the refusal records EP1 prices
(the C1 precedent for the same class). EP2 and EP4 are untouched.

#### EP1 — the apps discovery route, app resource resolution, and the app short-circuit mint

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP1 (the apps PRM route) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Apps-route name smuggling | A13 (routing and challenge integrity); the AS/data-path split | I, Access | An app name the request-time app guard judges differently than the router's apps location would — a charset edge the guard's pattern and the location's regex disagree on — serves an app whose MCP path can never route, or routes a name the guard refuses. The guard must be the same constants the router's apps regex mirrors, or the startup check's guarantee is lost rather than moved — the toolset guard's property, restated for the second namespace. |
| EP1 (the apps PRM route) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Apps-inventory enumeration widens **[mis-use]** | The deployment's app inventory (public discovery) | C | With no apps restriction configured, the enumerable set is every name that passes the app guard — the mirror property's price, second namespace: Core's own apps tier is likewise registry-independent (the same `toolsets.security` configuration serves it; a phantom app fetch against Core's metadata route earns the echo document), so the widened set names nothing the deployment's unauthenticated tier did not already name. A legitimate user can walk discovery across the apps namespace, probing the deployment's app inventory beyond any need their own work states; the existence answer lives one leg deeper, post-authentication, on both sides of the front door. |
| EP1 (the apps PRM route) | Injection | App refusal-record volume amplification | A9 (the audit trail) | A (log volume), I | The app guard's refusals are unauthenticated and each writes an audit record; a loop of crafted guard-failing app names writes records at the request rate. The content is fixed-vocabulary with truncated facts (not attacker-written) — only the volume is attacker-influenced, and the volume is capped by the shared limiter the apps route joins, with the no-record-over-limit rule; the document itself costs one static serve (no Core call). |
| EP1 (the app short-circuit mint) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mint-without-consent is unconditional for the app kind | A3's claim set; the app resource's token audience (A4); the establishment path's integrity | I (authorization fidelity), Access (bounded) | The mint machinery — unchanged in itself — is reachable for a whole resource kind on a path where no upstream consent and no credential establishment could ever run, by construction: for an app resource the flow mints after the identity leg and the app read, full stop. The bounds are the stage order and the identity model: the DIAL authorization check (the per-user app read, refused on 403) runs before the mint on every path; the mint's `sub` is the identity-leg user's own, provider-asserted; the minted token carries only that user's claims; Core's per-call authorization runs on every apps data-path call; and the access TTL is short. There is no forged-status variant to price here — the short-circuit consumes no status at all (the C1 shape's forged-answer threat, T5-7, has no app-side counterpart; the app read's forgery is DT-EP5-A1). |
| EP1 (the issued token, cross-kind) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Own-token cross-kind replay **[mis-use]** | A3, A6 | Access (own scope) | A legitimate user's token minted for one resource kind is Core-acceptable on the other kind's path — an app-resource token used against a toolset, or a toolset token against an app — because Core's identity-provider entry verifies the marker only (verified: no per-resource audience match exists on either MCP path). Within the caller's own authorization and under per-call DIAL authorization, but outside the per-resource binding the flow implies — RES-7/T1-12's class, widened cross-kind by this change, disclosed rather than mitigated away (the structural remedies are named below). |
| EP1 (the flow's authorization entry point, `/dial/authorize`) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller | Drive-by client hijacks the flow via the app path's zero-page short-circuit | A3 (a minted bearer token naming the victim's `sub`); A4 (the refresh token the same redemption yields); A8 (the victim's live IdP session); A10 (the attacker's own DCR registration) | I, Access | A client registered through CIMD on an operator-allowlisted origin — its `redirect_uris` pointing at a collector the attacker controls — crafts an `/dial/authorize` link and induces a victim with a live IdP session to click it. The identity leg completes silently: the gateway relays nothing client-identifying into the IdP leg, so the IdP cannot name the harness client to the user. **This change widens exactly that surface**: the app kind's unconditional short-circuit completes the flow with **zero user-visible pages of any kind** — no consent screen, no interstitial, nothing naming the client the mint is about to serve — a variant that would not exist without this change, and the row's subject by the method's own letter (enumerate the new threats the change brings); the toolset flow's stored-credential short-circuit, pre-existing, is the same class's other member, named here for context. The code lands on the attacker's registered redirect; the attacker redeems it with their own verifier and holds a gateway token **as the victim** (the refresh token with it, custody ciphertext included — inert without the custody key, bounded by the session lattice). PKCE, `state`, and single-use codes bound the interception class, not this one — the attacker holds every binding legitimately. The standing control is CIMD allowlist curation; the standard remedy is a consent/attribution checkpoint naming the resolved client and resource. |

#### EP5 — the server-to-server legs (the app read)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP5 (gateway → Core, the per-user app read) | Interception → Spoofing of the target (Man in the middle) | Forged app answer steers the flow | A11 (Core's app registry as the flow reads it); A14 (the user's time) | I, A | The app read carries the apps namespace's existence decision and the authorization decision on one internal leg, and a compose-network peer in a MITM position can forge either: a forged 404 denies a servable app's sign-in (a denial of one flow, self-inflicted by whoever controls the leg); a forged 200 for a phantom app mints a gateway token addressed to a resource that does not exist — a misleading token whose data-path calls yield 404/401 at Core, not access; a forged 403 denies one flow. The trust basis is the existing one — the internal leg from the configured Core, authenticated by the user's own identity token — the same trust that already carries the toolset settings the flow builds URLs from (a peer who can forge the app read can already forge the entire toolset projection, T5-7's acceptance class, RES-19). No answer this leg returns can make a phantom app's data path answer anything but an error. |

#### EP6 — the front router nginx (the apps location and its challenge synthesis)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP6 (the apps location's regexes) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Apps path-capture misrouting | A13; the AS/data-path split | Access, A | A mis-ordered or unanchored apps regex, or a name shape the location matches that the guard refuses (or vice versa), captures another surface's traffic or serves an app whose path can never route: `/apps/…` traffic hitting the gateway, or gateway-owned paths hitting Core. Bounded by the anchored `^/apps/(?<aname>[a-z0-9-]+)/mcp$` shape, the disjoint `/apps` prefix (no interaction with any `/dial/` alternation), and the guard's shared constants — the same triple the toolset locations rest on. |
| EP6 (the apps location's challenge rewrite) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mismatched challenge points the harness at a document it cannot act on | A13 (the challenge's integrity); the sign-in surface's availability | I, A | The synthesized apps challenge must quote the **app's** metadata path; a toolset-shaped challenge on an apps path (or a capture-variable mix-up between the two maps) names a document whose `resource` differs from the challenged resource, so a strict client's sign-in cannot complete — an availability break of the apps sign-in, invisible to the gateway. Bounded by the second map being keyed on the same location's own capture variable, and by the routing probe battery asserting the challenge's metadata path per path shape. |
| EP6 (the apps location's proxy_pass) | Use Control Misconfiguration → Denial of Service → Crashing | Apps query-string loss | A7 (streamable-HTTP sessions on the apps path, `?sessionId=…`) | A | nginx's automatic query-string behavior on variable `proxy_pass` drops `?sessionId=…` on apps MCP GETs exactly as on toolset GETs — a measured nginx behavior, not a hypothetical; without `$is_args$args` every streamable session on the apps path breaks, invisibly to the gateway. Bounded by carrying the toolset location's explicit pass-through over verbatim. |

### 5. Mitigations per threat, in the fixed control-category order

Homes: **spec** = this change's delta spec (gateway-owned, normative); **repo** =
committed material; **Core config** / **deployment** = named with their owners.

**DT-EP1-A1 Apps-route name smuggling**
1. Reduce Attack Surface — the app guard applies at every app-name resolution site
   (the apps PRM path, the apps-shaped `resource`, the refresh grant's resource);
   no site resolves an app name without it (spec).
2. Isolation — not applicable: the guard is a shared predicate between the gateway
   and the router's config; there is no runtime boundary between two components
   that must agree, only the shared constant.
3. Authentication — not applicable: the guarded value is a path segment on
   unauthenticated discovery; no credential exists to check at this stage.
4. Authorization — **the control**: the app guard reuses the exact
   `[a-z0-9-]+` shape the router's apps location regex mirrors, so the
   request-time check and the routing cannot disagree; a name failing it is
   refused before it names anything (spec).
5. Data Protection — not applicable: no stored or transmitted secret is at stake;
   the compromise is routing integrity, carried by category 4.
6. Anti-Injection — the charset refusal is the injection bound: no metacharacter
   survives to the location's regex (spec).
7. Anti-DoS — the guard is a constant-time string check before any allocation;
   nothing is held (spec — the refusal paths allocate nothing).
8. Detective controls — every app-guard refusal is an audit record with a
   fixed-vocabulary reason and the truncated name (spec).

**DT-EP1-A2 Apps-inventory enumeration widens [mis-use]**
1. Reduce Attack Surface — the apps restriction, where configured, pins the
   enumerable app set exactly as the toolset restriction pins the toolset set;
   the widening applies only to deployments that choose the dynamic mode (spec).
2. Isolation — not applicable: the probe reads public discovery documents; no
   cross-user boundary exists to isolate behind.
3. Authentication — not applicable: discovery is public by design on both sides
   of the front door; identity is not the lever.
4. Authorization — not applicable: the document names a challenge and nothing
   else; there is no per-user data on this surface to exceed.
5. Data Protection — not applicable: the disclosed inventory is public by design
   in the discovery documents.
6. Anti-Injection — not applicable: fixed-shape responses; nothing of the
   caller's is rendered or executed.
7. Anti-DoS — the apps route stays inside the public-endpoint abuse limits it
   joins (spec).
8. Detective controls — every discovery refusal is audited with the app named;
   the enumeration pattern is the detectable signature (spec — unchanged
   discipline). **Disposition: the inventory disclosure is inherent to serving
   dynamically in the second namespace — accepted as design, bounded by the
   restriction option and the mirror property extended (the widened set names
   nothing Core's own apps tier does not name).**

**DT-EP1-A3 App refusal-record volume amplification**
1. Reduce Attack Surface — the app guard's refusals share the discovery surface
   that already exists; no new endpoint beyond the apps route the surface needs
   (spec).
2. Isolation — not applicable: the audit sink is a log stream, not a component
   behind a boundary the caller crosses differently.
3. Authentication — not applicable: the volume arrives on an unauthenticated
   surface by protocol.
4. Authorization — not applicable: a refused request authorizes nothing.
5. Data Protection — **the control**: records carry fixed-vocabulary reasons and
   facts truncated to the configured cap — a caller grows no record beyond the
   cap, so content and per-record size are bounded by construction (spec — the
   existing refusal discipline, unchanged).
6. Anti-Injection — structure-only JSON records with no free-form caller input
   (spec — unchanged).
7. Anti-DoS — **the volume bound**: the apps route joins the same per-source and
   global rate limiter every unauthenticated surface uses, and over-limit
   requests write no record, so the record rate is capped at the limit itself
   (spec — the abuse-bounds amendment).
8. Detective controls — the trail itself; limiter 429s are recorded facts-free,
   so a volume attack is visible without being amplified (spec — unchanged).

**DT-EP1-A4 Mint-without-consent is unconditional for the app kind**
1. Reduce Attack Surface — the short-circuit is reachable only behind the
   identity leg and the app read, in that order; no surface mints an app token
   without both (spec — the stage order).
2. Isolation — not applicable: the mint is one function inside the process; the
   unconditional reach is a kind property, not a new component or boundary.
3. Authentication — **the control, first half**: the identity leg still
   authenticates the user under the gateway's PKCE client on every app flow; the
   minted token's `sub` is the live-authenticated user's, never anything the
   app read asserted (spec).
4. Authorization — **the control, second half**: the per-user app read (refused
   on 403) runs before the mint on every path — DIAL authorization is decided
   before any token exists — and Core's per-call authorization runs on every
   apps data-path call with the minted token, so the mint removes a consent
   screen that could never exist, never an authorization check (spec).
5. Data Protection — not applicable: no secret is disclosed or transited; the
   app flow touches no credential material at all (never-cut 1, vacuously).
6. Anti-Injection — not applicable: the attacker-controllable input at this
   stage is the app read answer's integrity, which is DT-EP5-A1's threat; the
   mint's other inputs are the flow's own verified state.
7. Anti-DoS — not applicable: the app flow mints *less* than any toolset flow
   (no interstitial, no upstream leg); its resource shape is a subset of the
   flow that already exists, inside the same limits.
8. Detective controls — the kind-driven short-circuit is itself an audit record
   (`credential_free_short_circuit`, the resource kind named), so a burst of
   app mints is answerable from the trail as what it is (spec).

**DT-EP1-A5 Own-token cross-kind replay [mis-use]**
1. Reduce Attack Surface — the gateway's own resource checks (the token and
   refresh endpoints' resource match) refuse a token presented against the other
   resource than it was minted for at every gateway surface that asks; the
   widening is Core-side, where no per-resource check exists to widen (spec —
   the corrected enforcement wording states exactly this division).
2. Isolation — not applicable: the replay is the same user presenting their own
   token to the same Core through the same data path; no boundary separates the
   kinds on Core's side — that is the residual's content.
3. Authentication — the replayed token authenticates its own legitimate holder;
   that is the mis-use's shape — identity is correct, the addressing is loose.
4. Authorization — **the bound**: every replayed call still passes Core's
   per-call DIAL authorization on the destination path — a user reaches only
   what they are already authorized to reach, on either kind's path; the minted
   claims are the user's own, bounded by the access TTL (Core config —
   unchanged; the residual's compensating control).
5. Data Protection — not applicable: no secret is disclosed; the compromised
   property is the token's addressing, carried by category 4.
6. Anti-Injection — not applicable: nothing is injected; the harness uses its
   token exactly as permitted.
7. Anti-DoS — not applicable: the mis-use grants access within authorization;
   it consumes nothing.
8. Detective controls — the mint's resource and the data path's resource are
   both on the trails (the gateway's per-flow records; Core's own request
   logging), so a cross-kind pattern is answerable from the two trails together
   (spec — the existing records). **Disposition: accepted as the widened form of
   RES-7 (T1-12) — the same class, one axis wider, bounded identically; the
   structural fix is the Core-side ask (per-issuer path/audience scoping),
   recorded §8, not built here.**

**DT-EP1-A6 Drive-by client hijacks the flow via the app path's zero-page
short-circuit (no gateway-owned consent page)**
1. Reduce Attack Surface — client registration is CIMD-only on
   operator-allowlisted origins: an attacker's registration requires a presence
   on an origin the operator allowlisted — the standing curation control
   (repo — the CIMD origin allowlist, and the operator's curation discipline
   behind it).
2. Isolation — not applicable: every leg is protocol-correct and every binding
   is the attacker's own; no component boundary the gateway can police separates
   the attacker's client from the mint.
3. Authentication — both authentications are genuine (the victim at the IdP,
   the attacker's client at the token endpoint); the defect is structural — no
   user-facing decision point attributes the mint to the client that will hold
   it. The standard remedy (a consent/attribution page naming the resolved
   client and resource) is deferred with its home named, not absent by
   overlook.
4. Authorization — the bounds that hold: the token carries only the victim's
   own claims (never a third party's), Core's per-call DIAL authorization
   governs every use, and the access TTL is short — the attacker's gain is the
   victim's own scope, misattributed to the attacker's client, never access the
   victim lacks.
5. Data Protection — no secret is disclosed beyond the tokens the design hands
   the code-holder by definition; the refresh token's custody ciphertext is
   inert without the custody key, and its refresh window is bounded by the
   provider session bound (M21's lattice).
6. Anti-Injection — not applicable: nothing is injected; the attacker uses the
   protocol exactly as designed.
7. Anti-DoS — not applicable: one flow per attack; the volume class is T1-7's,
   already bounded.
8. Detective controls — the flow's per-flow records name the client id and the
   resource, so a pattern of one client minting across many users' flows is
   answerable from the trail (spec — the existing records; attribution
   display-level, RES-5's class). **Disposition: remediation deferred to
   C2.5 — AS security hardening (RFC 9700 alignment)**, the roadmap change the
   deferral is recorded in (the consent/attribution checkpoint is its first
   scope seed); the standing control is CIMD allowlist curation; the deferral
   is recorded in the roadmap (the docs task) and the threat model (T1-25),
   not shipped as a mitigation here.

**DT-EP5-A1 Forged app answer steers the flow**
1. Reduce Attack Surface — the app read exists once per flow, on the same leg
   and in the same position as the toolset settings read; no second
   app-existence surface is created anywhere (spec).
2. Isolation — the read arrives on the trusted internal leg from the configured
   Core; the boundary is the existing one the settings read already trusts
   (deployment — unchanged).
3. Authentication — not applicable: the forged answer impersonates Core's
   configured position, not a credential the gateway could check independently;
   the user's own token authenticated the request, not the answer.
4. Authorization — **the bound**: the forged answer cannot mint for another
   user (the `sub` is the identity leg's, provider-asserted); a forged 200 for
   a phantom app yields a token whose data-path calls fail at Core (no upstream
   is reached — a misleading token and a diagnosable loop, not access); and the
   forged 403/404 shapes deny one flow, self-inflicted by whoever controls the
   leg (spec — the three-shape discipline).
5. Data Protection — not applicable: no secret is at stake; the compromised
   property is decision integrity on a trusted leg.
6. Anti-Injection — strict read discipline: an unreachable or unreadable answer
   fails closed as a deployment fault, never as an existence answer; no Core
   response text reaches a page or a record (spec; repo — the existing
   strict-read discipline, extended to the app read).
7. Anti-DoS — not applicable: the forged answer serves or denies one flow; the
   loop it can produce is bounded by one session and the rate limits.
8. Detective controls — the app read's refusals are audited with fixed
   vocabulary (`unknown_app` and the leg-failure tokens), so a forgery pattern
   reads as failed flows on the trail (spec). **Disposition: bounded by the
   internal-leg trust — the same acceptance class as the toolset settings
   read's forged-answer threats (RES-19's residual, extended to one more leg);
   no new residual is opened.**

**DT-EP6-A1 Apps path-capture misrouting**
1. Reduce Attack Surface — the `/apps` prefix is disjoint from every `/dial`
   alternation and from Core's own route shapes, so the new location can capture
   nothing that existed (repo — the router config).
2. Isolation — the apps location proxies to Core's deployments MCP path and only
   it; the gateway's surfaces remain reachable only through their own locations
   (repo — the location's anchored shape).
3. Authentication — not applicable: the misrouting threat is routing integrity,
   not identity; the data path's own auth runs behind Core whichever location
   served it.
4. Authorization — **the control**: the anchored regex
   `^/apps/(?<aname>[a-z0-9-]+)/mcp$` matches exactly the shape the app guard
   admits, and the guard reuses the same constants — routing and guard cannot
   disagree (repo; spec — the guard requirement).
5. Data Protection — not applicable: no secret is at stake; the compromised
   property is traffic distribution, carried by category 4.
6. Anti-Injection — the charset bound again: no metacharacter survives the name
   capture into the `proxy_pass` variable (repo — the anchored charset capture).
7. Anti-DoS — a misrouted shape fails at the location (404 at Core) rather than
   looping; no state is held (repo).
8. Detective controls — the routing probe battery asserts each path shape's
   destination and refusal (repo — the probes' apps rows).

**DT-EP6-A2 Mismatched challenge points the harness at a document it cannot act on**
1. Reduce Attack Surface — exactly two challenge maps exist, each keyed on its
   own location's capture variable, each quoting its own path shape's metadata
   path; no parameterized single map exists to misconfigure across shapes
   (repo).
2. Isolation — not applicable: both maps live in one static config; there is no
   runtime boundary, only the config's own correctness.
3. Authentication — not applicable: the challenge precedes authentication by
   design; its integrity is the issue, not a credential's.
4. Authorization — not applicable: the challenge names a document, not a
   principal; the sign-in it steers toward enforces authorization itself.
5. Data Protection — not applicable: no secret is disclosed; the header's
   correctness is the whole of the threat.
6. Anti-Injection — the challenge value is a fixed template over the router's
   own origin setting and capture variable; no caller input reaches it (repo).
7. Anti-DoS — the wrong-challenge failure is an availability break of one
   sign-in, bounded by one session; the probe battery catches it before
   deployment (repo — the probes' challenge rows).
8. Detective controls — the routing probes assert the challenge's metadata path
   per path shape, so a mismatch is a gate failure, not a field incident (repo).

**DT-EP6-A3 Apps query-string loss**
1. Reduce Attack Surface — not applicable without refusing the apps path: the
   location must exist, and its `proxy_pass` must carry the captured name.
2. Isolation — not applicable: the loss is nginx's own proxying behavior inside
   one config.
3. Authentication — not applicable: the query string carries session
   resumption, not identity.
4. Authorization — not applicable: no authorization decision reads the query
   string at the router.
5. Data Protection — not applicable: no secret is at stake; the lost parameter
   is a session handle.
6. Anti-Injection — not applicable: the pass-through changes nothing about what
   is forwarded.
7. Anti-DoS — **the control**: the explicit `$is_args$args` on the apps
   `proxy_pass` — the measured nginx behavior (variables in `proxy_pass` drop
   the automatic query append) carried over verbatim from the toolset location —
   keeps every streamable session on the apps path resumable (repo; spec — the
   query-survival scenario).
8. Detective controls — the routing probes assert the query string arrives at
   Core on the apps path (repo — the probes' apps row).

### 6. The grouped mitigation list

| # | Mitigation | Home and owner | Addresses |
|---|---|---|---|
| M24 | The apps front-door surface — the `/apps/{name}/mcp` path shape with its own prefix-anchored resource-URI derivation (disjoint from the toolset's by construction); the app name guard (the routed-path charset + the apps restriction, no reserved names, with the reason); the apps protected-resource document (static, name-derived, always-empty `scopes_supported`, no kind extension, zero Core calls — the mirror property extended to the second namespace); the apps discovery route inside the shared limiter with the no-record-over-limit rule; the router's apps location (anchored regex, query pass-through, no buffering) and its second challenge map quoting the app's own metadata path | **Placed** — delta spec (the path shape, guard, document, limiter clause, challenge and query scenarios); the router config and the probe rows are repo | DT-EP1-A1, DT-EP1-A2 (bounding), DT-EP1-A3, DT-EP6-A1, DT-EP6-A2, DT-EP6-A3 |
| M25 | The app flow's stage order — the identity leg, then the per-user app read (403 no-access / 404 the apps existence refusal audited as `unknown_app` / unreachable-or-unreadable the operator-facing fault page, never an existence answer), then the unconditional kind-driven short-circuit minting the code with one fixed-vocabulary audit record (`credential_free_short_circuit`) naming the resource kind — decided by C1's general rule, no new mechanism; the corrected audience wording (the marker is what Core verifies; the resource audience is the gateway's addressing discipline) | **Placed** — delta spec (the app-resource requirement, the flow requirement's declared existence-refusal amendment, the token requirement's declared enforcement amendment) | DT-EP1-A4, DT-EP5-A1, DT-EP1-A5 (bounding — the gateway-side resource checks) |
| M10 (extended) | The request-time name guard — extended to the apps namespace with the same shared constants the router's apps location mirrors | **Placed** — delta spec; the constants are repo | DT-EP1-A1, DT-EP6-A1 |
| M6 (extended) | The public-endpoint abuse limits — the apps protected-resource route joins the shared per-source and global limiter; over-limit requests write no record | **Placed** — delta spec (the abuse-bounds amendment) | DT-EP1-A3 |

Accepted remainders: DT-EP1-A2's apps-inventory disclosure (inherent to dynamic
serving in the second namespace, bounded by the restriction option and the mirror
property extended); DT-EP1-A5's cross-kind replay (the widened RES-7 — the
structural fix is the Core-side ask, §8); DT-EP5-A1's forged-app-read remainder
inside the internal-leg boundary (RES-19's class, extended to one more leg).
DT-EP1-A6's drive-by class carries no mitigation this change ships: its standing
control is CIMD allowlist curation, and its remediation — the
consent/attribution checkpoint — is deferred to C2.5, recorded in the roadmap
(the item this change's docs task inserts) and the threat model (T1-25), not
accepted as a residual. No new residual record is opened by this change.

### 7. The threat-model delta

`docs/threat-model.md` entries this change adds or changes (landed by this
change's tasks, not a follow-up):

- **T1-12 / RES-7 (new row wording)** — widened cross-kind: a leaked or
  legitimate gateway token is valid on every Core endpoint for its `sub` *across
  both resource kinds' paths* (verified: Core's provider entry checks the marker
  only; no per-resource audience match exists on either MCP path); the
  compensating controls unchanged (per-call DIAL authorization, the short access
  TTL, the marker binding to gateway issuance) plus the gateway's own resource
  checks at its own surfaces; the re-open trigger gains the Core-side
  per-issuer-path/audience-scoping ask as the named structural fix.
- **T1-24 (new)** — apps-namespace discovery enumeration: the enumerable set on
  the unauthenticated apps discovery route is every guard-passing app name in
  dynamic mode, the same registry-independent shape Core's own apps tier serves
  (the same `toolsets.security` configuration), bounded by the apps restriction
  option and the mirror property extended. A row of its own: its surface is an
  unauthenticated discovery route — the mirror property's class — never an
  authenticated read (the status-endpoint enumeration row T1-15 is retired by
  this same change, below, its surface deleted with the status endpoint).
- **T1-15 (retired)** — the status-enumeration threat: its surface — the
  authenticated status read, E9 — is deleted with the status endpoint (the
  owner's ruling; D4). The threat row and its disposition row are removed, and
  the retirement is stated with its cross-references reconciled rather than
  orphaned: E9 leaves the entry-point inventory, and the two
  verification-surface enumerations that name it are re-counted — the EP4
  `E4/E9/E10 verification` row's label becomes `E4/E10`, and T4-7's grid
  ("verifies JWTs at exactly three endpoints (E4, E9, E10)") becomes two
  (E4/E10), each enumeration counting what the process actually verifies, and
  the status read is gone; the rows citing `gateway/status.py` (the EP1
  toolset/leg-confusion row's resource-binding citation, and T1-4's
  disposition) are re-worded to the surfaces that remain (the token endpoint's
  resource match); T1-15 leaves the M6, M11, and M23 Addresses lists; and the
  attacker inventory's business-user bullet drops the status walk. The resolved
  OQ-1 record — the dated historical note that E9 enforced the resource
  binding, citing `gateway/status.py:111-122` — keeps its original wording: it
  records a question resolved before the endpoint's removal, so the
  retirement's repo-wide grep treats its citation as a known, accepted
  remaining reference rather than a cross-reference to reconcile. The accepted
  inventory disclosure that row carried closes with the surface — a
  retirement, not a new residual.
- **T1-23 (new)** — mint-without-consent is unconditional for the app kind (the
  whole-namespace extension of T1-21's class, with the structural difference
  stated: no stored-credential predicate exists at all); disposition:
  mitigated (M25 — the stage order: the identity leg and the per-user app read
  before every mint; the mint's `sub` is the identity leg's own; the
  short-circuit is itself audited).
- **T1-25 (new)** — the drive-by/malicious-client hijack of the flow **via the
  app path's zero-page short-circuit**, the surface this change widens: a
  client registered through CIMD on an operator-allowlisted origin —
  `redirect_uris` pointing at its collector —
  induces a victim with a live IdP session through `/dial/authorize`; the IdP
  leg completes silently (nothing client-identifying is relayed into it, so
  the IdP cannot name the harness client to the user); and the app kind's
  unconditional short-circuit — **zero user-visible pages of any kind, a
  variant that would not exist without this change** — completes the flow
  with no gateway-owned decision point (the toolset flow's stored-credential
  short-circuit, pre-existing, is the same class's other member, named for
  context); the code lands on the attacker's registered redirect, and
  the attacker redeems it with their own verifier, holding a gateway token
  **as the victim**. PKCE, `state`, and single-use codes bound the
  interception class, not this one — the attacker holds every binding
  legitimately; the standing control is CIMD allowlist curation. Disposition:
  **remediation deferred to C2.5 — AS security hardening (RFC 9700
  alignment)**, the roadmap item this change's docs task records (the
  consent/attribution checkpoint naming the resolved client and resource is
  its first scope seed) — a disposition stating where the fix lands and who
  owns it, per the method's own rule; the row and its disposition row land
  with the threat-model task, cross-referenced to the roadmap item.
- **T5-8 (new)** — the forged app-read answer (existence and authorization on
  one new internal leg; the forged-200 gain is a misleading token, not access);
  disposition: mitigated to the internal-leg bound (RES-19's acceptance class,
  extended; T5-7's sibling).
- **T5-3 (amended)** — the row's existence-edge wording ("the per-user settings
  read is the system's only existence decision") is re-worded per namespace: the
  per-user settings read is the toolset namespace's existence decision and the
  app read the apps namespace's, both post-authentication on the same internal
  leg — the sentence as written is false once the app read exists. Both the
  §8 threat row and its disposition row carry the re-wording.
- **T6-8 (new)** — the apps location's routing, challenge synthesis, and query
  pass-through; disposition: mitigated (M24 — the anchored disjoint prefix, the
  shared guard constants, the second capture-keyed map, `$is_args$args`, the
  probe battery's apps rows).
- **T6-2 / T6-3 (amended)** — the nginx config-fragility rows name the apps
  location beside the toolset one (two more regexes and one more map whose
  correctness the probe battery and the guard's shared constants carry).
- **M10 / M6 (amended)** — the guard's and the limiter's rows extended to the
  apps namespace and the apps route; **M24/M25 added** to the grouped list
  (§6 above).
- **EP1's entry-point description (amended)** — the discovery tier's guard-decided,
  registry-independent description extends to the apps route; the flow's
  consentless-mint clause gains the app kind's unconditional form.
- **The attacker inventory (§6, item 2) (amended)** — the business user's
  mis-use surfaces gain walking discovery across the apps namespace (the new
  T1-24).
- **§1 (the system as it stands) and §10 (compromise points) (amended, declared)**
  — two further ledger sites this change's surface widening reaches, owed under
  the standing rule (every change updates the threat model's affected entries)
  because the gateway now serves apps as a second resource kind: §1's system
  description gains the apps kind beside the toolset set (the apps front door —
  the `/apps/{name}/mcp` path proxied to Core's deployments MCP path — the
  guard-decided, registry-independent apps discovery tier, and the app flow's
  unconditional credential-free short-circuit: no consent screen, no credential
  call, no upstream round-trip, ever; no new trust boundary, credential, or grant
  type — the app path rides the existing public front door and the existing
  internal leg to the configured Core); §10's compromise-point rows whose text
  names a served surface class extend to the second kind (the Core row states Core
  serves the apps MCP path to gateway-minted tokens exactly as it serves the
  toolset path; the rows naming toolset access name app access beside it; the
  Keycloak row — whose text names no served surface — is unchanged). Neither site
  was named in this list before; the omission is declared here rather than left to
  the implementer's judgment.
- **No new residual records**: the accepted remainders land inside existing
  records (RES-7 widened; RES-19's class extended) and the apps-inventory
  disclosure lands as the new T1-24's stated disposition (inherent to dynamic
  serving in the second namespace, bounded by the restriction option and the
  mirror property), per §6's accepted-remainder list; T1-15's retirement closes
  a formerly accepted disclosure rather than opening one (its surface is gone),
  so the residual ledger shrinks by one accepted item; and T1-25, though a new
  threat row, opens no residual record either — its disposition is a
  remediation deferred to C2.5 with the standing control (CIMD allowlist
  curation) and the deferred remedy both named in the row: an open item with a
  named roadmap home, not an acceptance.

### 8. Open questions and the strict gap list

**Open questions — none ruling-worthy.** The design decisions the charter left
open are all decided above (D1–D8) with alternatives and reasons; what remains
open is implementation-level naming (the `APPS` setting's exact environment
spelling, the audit tokens' final strings — `unknown_app`,
`credential_free_short_circuit`, `invalid_app_name`, `restricted_app` — which are
repo-level constants behind the spec's fixed-vocabulary requirement), none of
which changes the specs, the approach, or the task breakdown.

**Questions for the owner — the SIA shape judgment: RULED 2026-11-04; the
tables stand.** One method-conformance judgment was recorded for a ruling rather
than settled here. The security impact analysis above prices this change as a
change on **existing surface classes** — each new route (the apps
protected-resource route, the apps MCP location, the app read) is treated as an
instance of a class the threat model already enumerates, so the analysis carries
delta threat tables at the touched entry points rather than a complete
leaf-level enumeration of a new entry point. The standing method's
proportional-enumeration rule (`docs/security-analysis.md`) has a second shape
that triggers on a change that **adds a surface** — a new endpoint or trust
boundary, or new secret material the process holds — and this change does add
new endpoints (a new public path shape and a new unauthenticated discovery
route) while adding no new trust boundary, credential, or grant type. Whether a
class-instance route counts as an existing surface for that rule, or whether
every new route demands the complete new-entry-point enumeration (with the
asset/footprint and compromise-point tables updated with it), decides whether
the SIA's tables stand as written or need widening.

**The owner's ruling (2026-11-04): the tables stand** — the SIA's shape judgment
is accepted. The reason: no new trust boundary, credential, or grant type
exists; every new threat row lands in a class the model already enumerates; and
the security review gate at medium depth ran against exactly these tables and
held them. The ruling sets the precedent for future changes: a new endpoint
that is an instance of an analyzed surface class is priced with delta rows, not
a fresh chapter.

**Core-side asks, recorded — the OQ-4 pattern (suggestions to the Core team,
explicitly not dependencies of this system, not built here):**

- **Per-issuer path/audience scoping** — the structural fix for RES-7, now priced
  cross-kind: a provider entry able to scope accepted tokens to a resource or
  path shape would make the gateway's resource audience a Core-enforced check
  rather than a gateway-side discipline. The gateway flips its spec wording back
  the day Core enforces one.
- **A registry-bound protected-resource route** — the C1 ask, unchanged, now
  doubly relevant: with two namespaces served guard-only, a registry-bound route
  (or an unauthenticated existence route) for either namespace would let the
  gateway refuse phantoms at the door, keyless, and the mirror property would
  tighten to "same challenge, same document, same existence answer."

**Strict gap list (per the method's conformance rule):**

- *None (closed this pass)* — the Core facts this design rests on were verified
  against the local authoritative public source checkout this pass, with
  file:line evidence recorded in `evidence/core-app-mcp-verification.md`: the
  apps MCP path and its route wiring; the apps metadata route and its shared
  `toolsets.security` gate; the app model's lack of authentication settings and
  per-app statuses; the ops credential API's `SecuredResource` requirement (apps
  unreachable through it); `DIAL_NATIVE`'s external-services-only function; the
  identity-provider entry's marker-only audience check (the fact that falsified
  the spec's implied per-resource enforcement, D6); and the app read's
  access/404 semantics (`findDeployment`'s registry lookup with the deployment's
  own access check).
- *Minor* — what a given deployment's Core `toolsets.security.authorizationServers`
  lists (the gateway's origin, an upstream, nothing) is a deployment fact not in
  this repository; the design does not depend on it (the router's challenge
  rewrite makes the front door's answer independent of it, D7), the operator
  reference states the requirement, and the acceptance run verifies the live
  shape.
- *Minor* — whether a deployment's Core build enriches the single-app read with
  per-service statuses is a deployment fact; the flow reads neither member, so no
  gap opens (recorded so a reviewer does not re-open it as one).
- *Minor* — the live acceptance run (a real app served through the front door,
  exercised by a real harness) is the gate that proves the composed behavior; the
  unit and probe tiers verify the gateway-side and router-side behavior first,
  but the end-to-end claim rests on the run's evidence, per the acceptance
  requirement.

## Risks / Trade-offs

- **The app mint is consentless by construction — the change's central price.**
  For a whole resource kind, the gateway mints tokens with no consent leg and no
  credential establishment, ever. Bounded by the stage order (the live identity
  leg and the per-user app read precede every mint), the token's own claims
  (only the signing user's), Core's per-call authorization on every data-path
  call, and the short access TTL; priced as T1-23 with no residual opened
  (DT-EP1-A4).
- **The audience residual widens cross-kind.** A user's app token works on
  toolset paths and vice versa, within their own authorization — RES-7's class,
  one axis wider, now a verified fact rather than an implication. Disclosed
  (DT-EP1-A5); the structural fix stays a Core-side ask.
- **The apps inventory is enumerable in dynamic mode** — every guard-passing app
  name, the mirror property's price in the second namespace, bounded by the
  restriction option and the fact that the set names nothing Core's own
  unauthenticated tier does not name (DT-EP1-A2, the new T1-24).
- **The router carries a second location and a second challenge map** — the
  nginx config-fragility class (RES-16's) grows by one location and one map;
  bounded by the disjoint prefix, the shared guard constants, and the probe
  battery's apps rows (DT-EP6-A1/A2, T6-8).
- **Bucket-scoped app ids are excluded, honestly.** The front door serves the
  deployment-registry apps; an app id with a slash fails the routed-path charset
  and is refused by the guard. The same limitation toolsets carry, stated rather
  than hidden; widening the charset would re-open every routing-regex and guard
  question this design closes.
- **The phantom app's lesson arrives one leg later** — its discovery document
  costs the harness one browser round-trip and one identity-leg exchange before
  the app read refuses it; the same lesson the same probe against Core's own
  tier would teach, the mirror property's shape in both namespaces.
- **Operators lose the per-user sign-in probe** — the status drop's recorded
  price (the owner's ruling; D4): the one machine-readable per-user signed-in
  answer is gone with the endpoint, and the diagnostic path that remains is the
  data path's 401 challenge shapes plus the audit trail. Stated rather than
  hidden; the rollback restores the endpoint with the rest of the diff.

## Migration Plan

- **Rollout** is additive except one removal: the new paths (`/apps/{name}/mcp`,
  the apps protected-resource route) appear beside the existing ones, and the one
  existing surface that changes behavior is the status path — with the router's
  status location removed, `/dial/{name}/status` falls through to Core, whose
  auth filter precedes any routing and answers an unauthenticated request with
  Core's own 401 (no gateway challenge) — a 404 is what an authenticated request
  would meet — so the router and the gateway must deploy together for the
  location's removal and the endpoint's deletion to land atomically (the
  compose-boot gate). Then verify with the probe battery and the acceptance run.
- **Configuration**: `APPS` is optional; a deployment that wants the pinned set
  adds it to `.env` (charset-validated at startup — the one new startup
  refusal); a deployment that wants dynamic serving adds nothing.
- **Rollback**: revert the router locations and the gateway routes; the apps
  paths stop being served, and the status endpoint returns with them (the
  rollback restores both halves of the diff) — no data migration, no token
  migration (already-minted app tokens die at their own expiries, and no store
  holds app-specific state beyond them).
- **Spec sync**: nine requirements are MODIFIED and one is REMOVED. MODIFIED:
  the discovery requirement (the mirror-property sentence's existence-refusal
  clause becomes per-namespace), the authorization-requests requirement (the
  two-shape resource resolution, with its three retained scenario re-wordings
  declared), the federation-flow requirement (the declared existence-refusal
  amendment to the unknown-toolset scenario), the issued-tokens requirement (the
  audience and Core-side enforcement wording, with its two retained scenario
  re-wordings declared), the toolset-guard requirement (the
  kind-decides-the-guard scoping, plus the surface list's status-endpoint drop
  with its refusal-shapes twin — both declared), the toolset-mapping requirement
  (the inference wording names the toolset restriction; the apps restriction
  named as separate), the abuse-bounds requirement (the limiter clause covers
  both discovery routes), the flow-lifecycle-audit requirement (the
  resource-kind fact and the app flow's events), and the
  pre-allocation-audit requirement (the refusal enumeration drops the status
  path — declared). REMOVED: the sign-in-status requirement ("Sign-in status is
  queryable without a tool call") — its scenarios die with it, and the REMOVED
  entry, not a MODIFIED rewrite, is what deletes it at sync. These are the only
  main-spec changes; all retained scenarios are byte-identical except where the
  declared amendment notes name them, so the sync is reviewable line by line.
