# Core's own `/.well-known/` surface — what the closure must not take away

The Core-coexistence requirement says Core's own discovery surface keeps working
alongside the front door. Closing the front door's `/.well-known/` namespace is safe only
if the closure takes no working Core path away. This record states, from DIAL Core's
source, exactly what Core serves under `/.well-known/` and what it answers everywhere else.

**Source.** DIAL Core (`https://github.com/epam/ai-dial-core`), commit `e49f6c4b`
(2026-10-08), read at the paths named below. Facts are about that commit; a later Core
release that adds a `/.well-known/` route re-opens this record (design.md, D5).

## What Core serves under `/.well-known/`

Exactly two route templates, both `GET`, both unauthenticated:

| Route template (`RouteTemplate`) | Pattern | Handler |
|---|---|---|
| `TOOL_SET_PROXY_METADATA` | `^/\.well-known/oauth-protected-resource/v1/toolset/(?<id>.+?)/mcp$` | `WellKnownResourceMetadataController` |
| `APPLICATION_MCP_PROXY_METADATA` | `^/\.well-known/oauth-protected-resource/v1/deployments/(?<id>.+?)/mcp$` | `WellKnownResourceMetadataController` |

`server/src/main/java/com/epam/aidial/core/server/data/RouteTemplate.java` declares the
two templates; `Proxy.java`'s `handleRequest` dispatches a `GET` whose raw path matches
either one (`isMcpResourceMetadataPath(request.path())`) to the controller **before** the
authorization step, so these are the only `/.well-known/` paths Core answers without a
credential.

The document (`WellKnownResourceMetadataService`) is built from configuration and the
request: `resource` is the request path with the `/.well-known/oauth-protected-resource`
prefix removed, on `resourceSchema://resourceHost` — `resourceHost` defaults to the
**request authority** when `toolsets.security.resourceHost` is unset. With
`toolsets.security.authorizationServers` unset, the service is disabled and the route
answers `404`.

**Why this matters through the front door.** Core's own MCP-path challenge quotes
`resourceSchema://{resourceHost or request authority}/.well-known/oauth-protected-resource{path}`.
A client that reaches Core's own MCP path through the front door's catch-all
(`<gateway-origin>/v1/toolset/<id>/mcp`, which the router forwards to Core unchanged) is
therefore pointed, when `resourceHost` is unset, at
`<gateway-origin>/.well-known/oauth-protected-resource/v1/toolset/<id>/mcp` — a path on
this front door. That path reaches Core today through the catch-all, and it must keep
reaching Core after the closure. This is the one legitimate Core `/.well-known/` path
through the front door.

## What Core answers on every other `/.well-known/` path

`Proxy.java`'s `handleRequest`, in order: CORS headers on every response
(`Access-Control-Allow-Origin: *`); any `OPTIONS` answered `200` with no
authentication; methods outside the allowed set answered `405`; `GET /health` and
`GET /version` answered without authentication; the two metadata templates above;
then **the authorization step** — a request with neither an API key nor an
`Authorization` header is refused `401` with the plain-text body
`At least API-KEY or Authorization header must be provided`. No other route under
`/.well-known/` exists in `RouteTemplate`, so even an authenticated request on another
`/.well-known/` path finds no handler.

The source grep that establishes "no other route": every occurrence of `well-known` in
Core's `server/src/main` is in `RouteTemplate.java` (the two templates) and
`WellKnownResourceMetadataService.java` (the service's own constant and doc comments).

## Consequence for this change

- Every `/.well-known/` path the closure answers `404` was answered by Core's `401`
  (unauthenticated) or by no handler (authenticated) — no working Core path is taken
  away, **except** the two metadata templates, which the change forwards to Core
  unchanged (design.md, D5).
- Core's `OPTIONS 200` and `Access-Control-Allow-Origin: *` on those paths disappear
  through the front door. Nothing depends on them: Core's own two metadata routes keep
  their CORS behavior (they are still Core's answer), and the gateway's discovery surface
  serves no CORS header by its stated posture (the public-endpoints requirement).
- Core's `/health` and `/version` are outside `/.well-known/` and are untouched.
