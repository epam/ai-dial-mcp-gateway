# Core-source verification — apps with MCP endpoints (C1.5 authoring pass)

Verification pass of 2026-11-03, run against the local authoritative public source
checkout (`dial/dial-core/ai-dial-core`, read-only) while authoring the
`apps-with-mcp-endpoints` change. Every fact the change's design rests on is
recorded here with its evidence (file:line as read this pass). The pre-verification
working assumption — an `/openai/<app>/mcp` app MCP path — is recorded as
**falsified** (fact 1) because correcting it is part of this change's record.

## Fact 1 — The app MCP path is `/v1/deployments/{id}/mcp`; the toolset path is `/v1/toolset/{id}/mcp` (singular "toolset")

- `server/src/main/java/com/epam/aidial/core/server/data/RouteTemplate.java:391-394`
  — `APPLICATION_MCP_PROXY("^/v1/deployments/(?<id>.+?)/mcp$", "/v1/deployments/{id}/mcp")`.
- Same file, lines 387-390 — `TOOL_SET_MCP_PROXY("^/v1/toolset/(?<id>.+?)/mcp$", …)`
  (singular `toolset`, not `toolsets`).
- `server/src/main/java/com/epam/aidial/core/server/controller/ControllerSelector.java:312-315`
  — the GET route wiring: `APPLICATION_MCP_PROXY` → `ApplicationMcpProxyController`
  with the captured id; `TOOL_SET_MCP_PROXY` → `ToolSetMcpProxyController`
  (lines 304-307).
- The `/openai/<app>/mcp` assumption is falsified: no such route template exists;
  `/openai/applications` is the app listing/read surface, not an MCP path.

## Fact 2 — Core's protected-resource tier for app MCP is served from the `toolsets.security` configuration; there is no `apps.security.*`

- `RouteTemplate.java:403-406` — `APPLICATION_MCP_PROXY_METADATA("^/\\.well-known/oauth-protected-resource/v1/deployments/(?<id>.+?)/mcp$", …)`:
  Core's own metadata route for app MCP, beside `TOOL_SET_PROXY_METADATA`
  (lines 399-402).
- `server/src/main/java/com/epam/aidial/core/server/Proxy.java:347-363`
  (authorizeRequest) — with no API key and no Authorization header, a GET/POST on
  an MCP resource path is answered 401 with `WWW-Authenticate: Bearer
  resource_metadata="<path>"` from `resourceMetadataService.resolveResourceMetadataPath`;
  `Proxy.java:501-503` — `isMcpResourcePath` matches **both**
  `TOOLSET_PROXY_PATTERN` and `APPLICATION_MCP_PROXY_PATTERN`, so the apps path
  gets the identical challenge.
- `server/src/main/java/com/epam/aidial/core/server/service/WellKnownResourceMetadataService.java:38-46`
  — the service is constructed from the `toolsets` settings block
  (`security.authorizationServers`, `security.resourceSchema`, `security.resourceHost`,
  `security.scopesSupported`); `resolveResourceMetadataPath` returns empty when
  disabled (lines 92-95; `isDisabled()`, lines 169-171), and the challenge then
  carries no header (Proxy builds `Map.of()`).
- `WellKnownResourceMetadataService.java:92-103` — the metadata path is built as
  `resourceSchema + "://" + host + "/.well-known/oauth-protected-resource" + <the
  request's own path>` — a registry-independent echo of the requested path.
- `server/src/main/java/com/epam/aidial/core/server/controller/WellKnownResourceMetadataController.java:22-44`
  — an empty resolution answers 404 (lines 25-29); a resolved one serves the
  document built from configuration.
- `server/src/main/java/com/epam/aidial/core/server/AiDial.java:393` —
  `new WellKnownResourceMetadataService(settings("toolsets"))`: the one service
  instance serves both namespaces' metadata routes from the `toolsets`
  configuration. No `apps.security` setting is read anywhere (grep of the server
  source finds none).
- Consequence for the design: Core's apps unauthenticated tier is
  registry-independent exactly as its toolset tier is, gated by the same
  configuration; unset, the 401 carries no challenge and the metadata route
  answers 404 — neither shape an existence oracle. The gateway's apps discovery
  tier mirrors it (the mirror property, extended).

## Fact 3 — Applications carry no authentication kind and no per-app sign-in status

- `config/src/main/java/com/epam/aidial/core/config/Application.java:24` —
  `public class Application extends Deployment` (not `SecuredResource`); its
  `externalServices` map (lines 42-44) is where per-service auth settings live.
- `config/src/main/java/com/epam/aidial/core/config/SecuredResource.java:14-15` —
  `authSettings` (`ResourceAuthSettings`) is carried by `SecuredResource`
  (toolsets and other secured resources), which `Application` does not extend.
- `config/src/main/java/com/epam/aidial/core/config/ResourceAuthSettings.java:38-41`
  — `AuthenticationType` (OAUTH / API_KEY / NONE / DIAL_NATIVE) lives on
  `ResourceAuthSettings`.
- `server/src/main/java/com/epam/aidial/core/server/controller/ApplicationController.java:102-126`
  — the single-app GET (`/openai/applications/{id}`): 404
  (`ResourceNotFoundException`) for an unknown app (lines 104-106); the per-user
  enrichment at
  lines 117-119 (`ResourceAuthStatusEnricher.enrichApplication`) is applied to
  `data.getExternalServices()` — **per external service only**; no per-app status
  member exists.
- Consequence: an app is credential-free by construction for the gateway; the
  flow's signed-in check and kind branch have nothing to read, and the design
  states the short-circuit as unconditional (design.md D3).

## Fact 4 — The ops credential API cannot serve apps

- `server/src/main/java/com/epam/aidial/core/server/controller/ResourceCredentialsController.java:83-99`
  (signIn) — the deployment must be `instanceof SecuredResource` to reach the
  credential path; otherwise `ResourceNotFoundException`. `Application` is not a
  `SecuredResource` (fact 3), so `/v1/ops/toolset/signin` cannot store anything
  for an app. Apps have their own external-service credential surface
  (`/v1/ops/external-service/…`), which the gateway's flow does not use.

## Fact 5 — `DIAL_NATIVE` is external-services-only in function (the owner's 2026-11-03 correction, verified)

- `server/src/main/java/com/epam/aidial/core/server/controller/ExternalServiceCredentialsController.java:552-558`
  (`rejectDialNative`) — sign-in/sign-out is explicitly rejected for
  `DIAL_NATIVE` services ("users manage offline access via the
  offline-credentials endpoints, and an administrator manages consent
  separately"); the consent endpoint is per external service
  (`/v1/applications/{appId}/external-services/{id}/consent`).
- No design in this change assumes `DIAL_NATIVE` for apps or toolsets.

## Fact 6 — Core's identity-provider entry verifies the marker only; no per-resource audience match exists on either MCP path

- `server/src/main/java/com/epam/aidial/core/server/security/IdentityProvider.java:342-357`
  (verifyJwt) — the verification is `JWT.require(RSA256(jwk))` plus, where an
  `audience` is configured, `verification.withAudience(audience)` (line 351) — the
  provider entry's **single configured audience string** (the marker;
  `IdentityProvider.java:204` reads it from settings). No resource, path, or
  per-deployment audience participates in token validation anywhere in the
  source (grep: `withAudience` appears once).
- Consequence for the design: the gateway's per-resource audience is its own
  addressing discipline (enforced at the gateway's resource checks), not a
  Core-enforced check — the spec wording is corrected to state exactly this
  (design.md D6, the delta spec's token requirement amendment), and the
  cross-kind replay consequence is priced (RES-7 widened; DT-EP1-A5).

## Fact 7 — The single-app read enforces DIAL authorization and answers 404 for unknown apps

- `server/src/main/java/com/epam/aidial/core/server/service/DeploymentService.java:63-78`
  (findDeployment) — the registry lookup (`selectDeployment`) applies the
  deployment's own access check (`hasAccess(userRoles)` → forbidden on failure);
  non-registry ids fall through to bucket-scoped resource descriptors
  (application/toolset services), whose ids carry slashes.
- `ApplicationController.java:104-106` — the unknown-app 404.
- Consequence: `GET /openai/applications/{id}` is the app flow's DIAL
  authorization read, with the three distinguishable shapes the design relies on
  (403 no-access / 404 unknown / unreachable-unreadable deployment fault);
  bucket-scoped ids never pass the gateway's routed-path charset, so the front
  door serves the deployment-registry apps (design.md D1/D2).

## Fact 8 — On the apps MCP path, an access denial answers 403 and an unknown app 404; the 401 class is token-shape only

- `server/src/main/java/com/epam/aidial/core/server/controller/McpProxyController.java:477-485`
  (handleError) — `PermissionDeniedException` → **403** (lines 479-481);
  `ResourceNotFoundException` → **404** (lines 484-485). The 403 originates in
  the deployment access check:
  `DeploymentService.java:66-67` → `throwForbiddenDeploymentError` →
  `PermissionDeniedException` (lines 141-142).
- `Proxy.java:347-363` (authorizeRequest, fact 2) — the unauthenticated 401 is
  raised before any deployment resolution, so it carries no per-call
  authorization outcome; with a presented token, a failed per-call check is the
  403 above, never a 401.
- Consequence: the apps-path 401s the gateway's own tokens shape are the
  token-shape causes (no token, invalid or expired token) the sign-in flow
  resolves; an access denial surfaces as the data path's own 403 and an unknown
  app as a 404, neither a sign-in cause (the delta spec's apps front-door
  requirement states exactly this division).

## Fact 9 — No stored credential is attached on the app MCP upstream leg

- `server/src/main/java/com/epam/aidial/core/server/util/McpUpstreamAuthInjector.java:60-74`
  (the `Application` overload) — the outgoing app MCP request carries the
  application id header, an optional per-request DIAL key, and config delivery
  via header; no `AuthorizationHeaderProvider` call is made, unlike the `ToolSet`
  overload (lines 43-54), which resolves `ResourceAuthSettings` and attaches a
  stored credential's authorization header.
- Consequence: an app whose own upstream MCP endpoint demands authentication
  answers for itself — its 401 reaches the caller through the apps location,
  where the challenge synthesis fires on 401 and points the harness at the
  gateway's sign-in, a loop no gateway flow can resolve (no credential exists to
  establish). The same benign-loop class as the toolset path's upstream-401
  rewrite; stated as the one-clause caveat in the status requirement's scoping
  and D4.
