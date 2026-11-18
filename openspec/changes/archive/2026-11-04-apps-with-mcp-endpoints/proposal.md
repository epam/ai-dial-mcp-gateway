# Proposal

## Why

DIAL applications expose MCP endpoints of their own — Core serves them at
`/v1/deployments/{id}/mcp` behind the same unauthenticated 401-challenge tier as the
toolset MCP path — and a harness pointed at one cannot complete a sign-in: the
gateway's front door serves only the toolset path shape, so the challenge a harness
receives describes an authorization server whose resource vocabulary has no spelling
for an app. This is the restored N1 (`docs/production-roadmap.md` §C1.5), dropped by
the PoC's minimization audit and now the iteration's next change. The general rule
the app flow needs — the upstream stage runs only when the credential is missing AND
the kind makes it establishable by consent — was built by C1's P3 half (the flow's
routing decision on its per-user settings read), so this change's scope is the apps
resource *surface* (routes, discovery documents, the router's apps MCP path — a new
path shape C1 does not touch) and the app-resource semantics, verified against the
current Core source with the owner's 2026-11-03 correction standing: `DIAL_NATIVE` is
external-services-only — no design here may assume it for apps or toolsets, and
applications carry no authentication kind and no per-app sign-in status at all.

An app resource is credential-free **by construction** (an `Application` in Core
carries no authentication settings; its MCP data path runs on the caller's own
identity, authorized per call), so the app flow is: identity leg → DIAL authorization
(the app read as the user) → the kind-driven short-circuit — **no consent screen, no
credential call, no upstream round-trip, ever**, for this resource kind.

## What Changes

- **A second front-door path shape for app resources: `/apps/{name}/mcp`.** The kind
  lives in the path, so the toolset registry and the apps registry never collide (a
  toolset and an app may share a name) and the resource URI derivation is unambiguous.
  The router gains one static location proxying to Core's
  `/v1/deployments/{id}/mcp` with the same discipline as the toolset location —
  query-string pass-through, no buffering, `proxy_hide_header` + a synthesized
  challenge quoting the app resource's own metadata path — plus the apps
  protected-resource route through to the gateway.
- **App discovery documents, mirroring Core's apps tier.** The gateway serves one RFC
  9728 document per served app at `/.well-known/oauth-protected-resource/apps/{name}/mcp`
  — served for every guard-passing name, phantom and real alike, zero Core calls, the
  mirror property extended to the apps namespace (Core serves the apps 401-challenge
  and the apps metadata route from the same `toolsets.security` configuration that
  serves the toolset tier; both are registry-independent). The document's
  `scopes_supported` is always empty — no upstream leg exists for an app resource to
  send scopes on — and it carries no authentication-kind extension, because an app
  has no authentication kind.
- **The app flow, unified onto C1's general rule.** The `resource` parameter's URI
  shape names the kind; the authorization and token endpoints resolve both shapes
  under their own guards. The app flow's stages: the identity leg (unchanged
  machinery), then the app read as the user (`GET /openai/applications/{id}` — 403 is
  the no-access page, 404 is the apps namespace's existence refusal with a
  plain-language page, an unreachable or unreadable answer fails closed as a
  deployment fault and never as an existence answer), then the kind-driven
  short-circuit: unconditional for this kind — no signed-in check runs (no per-app
  status members exist), no kind branch runs (no consent could establish anything),
  and the harness's code is minted with one audit record showing the kind-driven
  short-circuit.
- **A second optional operator restriction (`APPS`).** Unset, every guard-passing app
  name is served; set, only its entries. Configured entries are charset-validated at
  startup (the routing refusal, same reason as toolsets — the router's locations are
  static). Entries declare nothing but the name: no kind (there is none) and no
  scopes (no leg sends any). Resource inference stays toolset-only and never consults
  the apps restriction — with two namespaces there is even less "the one resource"
  to infer.
- **Token audience for app resources: same shape, wording corrected to the verified
  Core fact.** `aud` carries the app's resource and the marker; the refresh token
  carries the app's resource alone (the token-type separation unchanged). Verified
  against the Core source: Core's identity-provider entry checks the single
  configured `audience` — the marker — and **no per-resource audience match exists on
  either MCP data path**; the resource audience is the gateway's own addressing
  discipline, enforced at the gateway's resource checks. The consequence is priced:
  an app-resource token is Core-acceptable on a toolset path and vice versa, within
  the caller's own authorization — the disclosed marker-level-binding residual
  (RES-7), widened cross-kind.
- **The sign-in status API is dropped entirely — both namespaces (the owner's ruling
  at the review pause).** The status requirement is REMOVED, not scoped: the
  `/dial/{name}/status` endpoint, its route, its router location, and its threat row
  (T1-15) all go, and no apps analogue ever existed. The reasoning that motivated the
  original no-app-status decision extends to the namespace the endpoint served: there
  is no stored state for apps to answer a status question with, and for toolsets the
  401 shapes already answer the harness's question — no token, an invalid or expired
  token, and a valid token with no stored credential each earn the gateway's challenge
  on the data path, and those are exactly the causes the sign-in flow resolves. The
  operational cost is recorded honestly: operators lose the per-user sign-in probe;
  the 401 challenge shapes and the audit trail remain the diagnostic path.
- **The spec's existence-refusal wording generalized.** The flow's settings read
  keeps its scenario; the "system's only existence refusal" phrasing becomes
  per-namespace — the existence refusals are the flow's authenticated reads, one per
  resource kind, and no unauthenticated tier on either side of the front door
  carries an existence oracle in either namespace. The phrase is amended in both
  places it lives — the federation requirement's unknown-toolset scenario and the
  discovery requirement's mirror-property sentence — each a declared amendment.

**Not in scope (the recorded boundary):** `DIAL_NATIVE` anything (external-services
only in Core's function — the owner's standing correction); the app external-services
credential surface (`/v1/ops/external-service/*`, the consent endpoint — DIAL Chat's
flow, not the gateway's; the gateway's app flow never reads per-service statuses);
**path-grammar unification** — the `/dial/` vs `/apps/` prefix asymmetry stays as
authored (the owner's ruling at the review pause); one prefix per concern would retire
the reserved-name class, and that unification is recorded as a deferred item (the
roadmap's "Deferred — to later iterations" table gains the row by this change's docs
task), naturally landing with E1 (the Core merge) or as its own change with a
migration window for already-registered clients; **the AS security-hardening
pass (C2.5 — RFC 9700 alignment)** — the consent/attribution checkpoint for
the drive-by threat the SIA prices (the new threat row T1-25: a
CIMD-registered client on an allowlisted origin can drive a victim's live IdP
session through the app path's zero-page short-circuit — a variant that would
not exist without this change — and redeem the code as the victim) is
remediated there, not here: the deferral is recorded in the roadmap's
iteration ordering (the item this change's docs task inserts, positioned
after C2 and before C3, its scope seed carrying the further hardening items),
and the threat row's disposition names the item; E1/E3/E4 evolutions; any change to
the toolset flow's built rule beyond what unifying the resource resolution
requires; the Core-side asks (a registry-bound protected-resource route,
per-resource audience enforcement) — recorded, not built here.

## Capabilities

### New Capabilities

(none — the change extends the existing sign-in capability to a second resource kind)

### Modified Capabilities

- `mcp-signin`:
  - ADDED — app MCP resources are served through the apps front-door path (the path
    shape, the challenge discipline, the query-string survival, the app name guard,
    the mirror property extended to the apps namespace, the app protected-resource
    document);
  - ADDED — app resources complete the sign-in flow credential-free (the app read as
    the DIAL authorization and existence check; the unconditional kind-driven
    short-circuit; its audit record);
  - ADDED — the apps restriction is an optional operator restriction (per-namespace
    restrictions; inference stays toolset-only);
  - ADDED — app-resource acceptance on a real harness gates completion;
  - MODIFIED — authorization requests (the `resource` parameter resolves two path
    shapes, each under its own guard; the inference clause re-derived);
  - MODIFIED — the federation flow (a declared amendment to the existence-refusal
    wording: one existence refusal per resource kind, both post-authentication);
  - MODIFIED — discovery documents (a declared one-clause amendment to the
    mirror-property sentence's existence-refusal wording — the same per-namespace
    generalization, in the second place the phrase lives);
  - MODIFIED — issued tokens (the audience carries the addressed resource's URI —
    toolset or app — and the marker, with the Core-side enforcement stated as
    verified: the marker is what Core checks);
  - REMOVED — sign-in status is queryable without a tool call (the status API leaves
    the gateway's surface entirely, both namespaces — the owner's ruling; the 401
    challenge shapes and the audit trail remain the diagnostic path, and the
    operational cost — the per-user sign-in probe — is recorded);
  - MODIFIED — toolset names are guarded at request time (scoped to
    toolset-shaped resources: where a listed surface serves both kinds, the
    resource's kind decides which guard applies — the apps shape passes the app
    guard of the app-resource requirement; the surface list drops the status
    endpoint's path, the surface being gone);
  - MODIFIED — the toolset mapping requirement (the inference wording names the
    toolset restriction explicitly now that two restrictions exist);
  - MODIFIED — pre-allocation refusal auditing (the refusal enumeration drops the
    status path — the surface is gone; the status-only reason tokens retire with
    it);
  - MODIFIED — abuse bounds (each protected-resource discovery endpoint — toolset
    route and apps route — joins the limiter, with the no-record-over-limit rule);
  - MODIFIED — flow lifecycle audit (the app flow's events: the app read's outcome
    and the kind-driven short-circuit).

## Impact

- **Code**: `gateway/settings.py` (the apps restriction; the app name guard and the
  app resource-URI derivation, beside the toolset ones), `gateway/discovery.py` and
  `gateway/routes.py` (the apps protected-resource route and document, behind the
  limiter), `gateway/authorize.py` (resource resolution across both shapes),
  `gateway/core.py` (the app read client), `gateway/federation.py` and
  `gateway/flow.py` (the app branch of the routing decision — the read, the
  unconditional short-circuit, the audit event; the decision itself lives in the
  federation callback's routing logic), `gateway/audit.py` (the allocation
  record's resource-kind fact, the facts vocabulary's `toolset` becoming
  `resource` across the emit sites, the closed reason vocabulary's new app
  tokens, the status-only tokens' retirement), `gateway/token.py` (the token and
  refresh endpoints' resource resolution across
  both shapes), `gateway/status.py` (deleted, with its route registration
  in `gateway/app.py` — the status surface's removal, both namespaces; the Core
  status read the flow's signed-in check uses stays, in `gateway/core.py`),
  `router/nginx.conf` (the apps location, its challenge map, the apps metadata
  route, and the status location's removal), `.env.example`,
  `docs/gateway-configuration.md`, `docs/routing.md` (the status row's removal),
  `docs/production-roadmap.md` (the deferred path-grammar-unification row),
  `docker-compose.yml` (a minimal MCP-speaking app test fixture service, joined to
  the instance network — test fixture, no production behavior), and
  `scripts/spike_register_app.py` (the registration script for the fixture app,
  the sibling of `scripts/spike_register_toolset.py` — test fixture, no
  production behavior); the test files covering them (the status tests
  deleted with the surface).
- **Operational**: a new public path shape (`/apps/{name}/mcp`) and a new
  protected-resource route appear on the front door, and one existing path stops
  being served: `/dial/{name}/status` is gone — with the router's status location
  removed, the path falls through to Core, whose auth filter precedes any routing
  and answers an unauthenticated request with Core's own 401 (no gateway
  challenge; a 404 is what an authenticated request would meet), so the router
  and gateway must deploy together for the removal to land atomically. The
  per-user sign-in probe operators had there is gone with it; the diagnostic path
  that remains is the data path's 401 challenge shapes and the audit trail.
  `APPS` is optional (unset =
  every guard-passing app name is served, existence decided post-authentication at
  the app read — the mirror property, apps namespace). Core's
  `toolsets.security.authorizationServers` configuration — the one that already
  serves the toolset tier — is what serves the apps 401-challenge and metadata route
  on Core's side; a deployment that has it set for toolsets needs nothing new, and a
  deployment without it has a challenge-less 401 on Core's side that is no existence
  oracle either (the gateway serves its own document regardless). App names with
  slashes (bucket-scoped app ids) fail the routed-path charset and are refused by
  the guard — the front door serves the deployment-registry apps, the same
  routing-charset rationale as toolsets.
- **Security**: the security impact analysis runs in full (impact level **medium**;
  the shape is a change on existing surface classes — each new route is an instance
  of one: a static protected-resource document behind the guard and limiter, a
  proxied MCP data path with the challenge rewrite, an authenticated per-user Core
  read — with no new trust boundary, credential, or grant type). It prices the
  unconditional short-circuit mint for a whole resource kind (bounded by the
  identity leg, the per-user app read, the token's own claims, Core's per-call
  authorization, the short access TTL), the apps-namespace inventory widening
  (bounded by the mirror property and the restriction option), the forged-app-read
  variant (the internal-leg trust class), the router's new location (charset
  coordination, challenge-synthesis correctness), the cross-kind widening of
  the marker-level audience-binding residual (RES-7), and the
  drive-by/malicious-client hijack via the app path's zero-page
  short-circuit (the new threat row T1-25 — a
  CIMD-registered client on an allowlisted origin driving a victim's live IdP
  session through the flow and redeeming the code as the victim; a variant
  that would not exist without this change, bounded by the standing CIMD
  allowlist curation, remediation deferred to C2.5 — AS security hardening
  (RFC 9700 alignment), the roadmap item this change records). The threat-model
  updates are part of this change's tasks, not a follow-up.
