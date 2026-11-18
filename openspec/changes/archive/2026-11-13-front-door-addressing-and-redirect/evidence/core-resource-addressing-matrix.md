# Core's resource-addressing matrix — verified cell by cell

Sources: the ai-dial-core source at HEAD 894328d6 (checkout
`dial/dial-core/ai-dial-core`), and live probes against the dev instance's Core
(port 8081, 2026-11-13; probe resources created for the verification were deleted
afterwards — the instance's toolset registry holds only its pre-existing `notion`
entry). Live-probe facts are marked **[live]**; source facts carry the file. The
design targets Core HEAD; where the live instance's build differs, both facts are
recorded.

## The routes and their grammars

| Route (RouteTemplate) | Pattern (HEAD 894328d6) | Serves |
|---|---|---|
| `TOOL_SET_MCP_PROXY` | `^/v1/toolset/(?<id>.+?)/mcp$` | ToolSets only — `ApplicationMcpProxyController` type-checks the toolset MCP route; the deployments route serves Applications with an `mcp` block only |
| `APPLICATION_MCP_PROXY` | `^/v1/deployments/(?<id>.+?)/mcp$` | Applications with an `mcp` block |
| `TOOL_SET` (listing) | `^/+openai/toolsets/(?<id>.+?)$` | Deployment resolution by dual lookup — the read the gateway's flow uses |
| `APPLICATION` (listing) | `^/+openai/applications/(?<id>.+?)$` | The app read |
| Config CRUD | `^/v1/(conversations|prompts|applications|toolsets)/(?<bucket>[a-zA-Z0-9]+)/(?<path>.*)$` | Stored toolsets/apps — PUT/DELETE validate the whole `path` against one-segment patterns (no folders at creation) |
| `TOOL_SET_REPAIR` | `^/v1/ops/toolset/(?<bucket>[a-zA-Z0-9]+)/(?<path>.+)/repair$` | The DCR repair API — path multi-segment (folders supported) |

Dual lookup (`DeploymentService.findDeployment`): leg a — the config registry by bare
name (`selectDeployment`), then `hasAccess` by roles; leg b —
`toResourceDescriptor`: `UrlUtil.encodePath(resourceUrl)` →
`ResourceDescriptorFactory.fromAnyUrl` (parses `{typeSegment}/{bucket}/{folders}/{name}`,
decrypts the bucket ciphertext) → `hasReadAccess` (owner's own bucket always passes;
admin/global-reader/auto-shared/per-request/publication/sharing/public rules
otherwise) → the stored ToolSet or Application. Failure legs: parse failure → 404
"Unknown deployment: {url}"; access refusal → 403 "Forbidden deployment: {url}".

## The cells

| Cell | Addressing shape | Verified how | Front door today | Front door after |
|---|---|---|---|---|
| Config-entity toolset | `/v1/toolset/{name}/mcp`, listing `{name}` | Source (leg a) + **[live]** `/openai/toolsets/notion` → 200 | Served | Served, unchanged |
| Config-entity app | `/v1/deployments/{name}/mcp` | Source (leg a; the C1.5/C2 stacks exercise it live) | Served | Served, unchanged |
| Stored toolset, `public` bucket | `toolsets/public/{name}` | Source (leg b) + **[live]**: created `toolsets/public/probets-v2` (PUT 200); listing `GET /openai/toolsets/toolsets/public/probets-v2` → **200**, `id` echoed `toolsets/public/probets-v2`; MCP route `/v1/toolset/toolsets/public/probets-v2/mcp` resolves (distinguishable from the bogus-path 404) | Refused (multi-segment) | **Served** |
| Stored toolset, `platform` bucket | `toolsets/platform/{name}` | **[live]**: PUT 200; listing full-URL shape → **403 "Forbidden deployment"** — an *access* refusal (the platform bucket is not public; `getAdminAccess` grants admins only public/review buckets, `AccessService.java:219-226`), not a routing miss; bucket-first shape → 404 "Unknown deployment" (parse failure — no type segment) | Refused | **Served**; a non-privileged caller's 403 is Core's access rule, inherited |
| Stored toolset, user bucket | `toolsets/{base58-ciphertext}/{name}` | Source: `EncryptionService`/`Base58` — ciphertext of `Users/{sub}`, alphanumeric, per-caller; clients receive it verbatim in `id`/`name` (ToolSetService, ToolSetData, DeploymentData); `GET /v1/bucket` (`BucketController`) hands the caller its own encrypted bucket, and a user token's `PUT /v1/toolsets/{ciphertext}/{name}` writes into the caller's own bucket — verified at implementation by a **live row in 8.1** (the change's instrument: a user-created toolset addressed through the front door by the Core-handed path, the isolation refusal asserted for a second caller) | Refused | **Served** — the harness presents the verbatim path; isolation is Core's `hasReadAccess` chain, applied per caller on the data path and the flow's listing read alike |
| Stored app, any bucket | `applications/{bucket}/{name}` | Source (same routes, deployments prefix; the C1.5 fixture app exercises the bare shape live) | Refused | **Served** — `/apps/applications/.../mcp` → `/v1/deployments/applications/.../mcp` |
| Folders (nested paths) | `toolsets/{bucket}/{folder…}/{name}` | Source: every resolution route is greedy multi-segment; **[live]**: the CRUD API refuses folder paths at creation — PUT `/v1/toolsets/platform/probe-front-door/probets-v2` → 400 "Invalid entity name segment" (the whole `path` validated as one segment) — so such resources arise only via other creation paths (publication, moves, blob writes); the repair route takes folder paths | Unroutable | Served mechanically — the front door carries whatever Core resolves; no cell closed by us |
| Toolset names `^[A-Za-z0-9-_]+$` | one segment | Source: `ConfigPostProcessor.RESOURCE_KEY_PATTERN = ^[A-Za-z0-9-_]+$` (config keys and stored names alike, `isValidToolSetKey`); **[live]**: the older build enforces `[a-z0-9-_]` (its refusal message) — HEAD widened to uppercase | Underscore refused by `[a-z0-9-]+` — **a today-broken, Core-servable cell** | Served |
| App names `^[A-Za-z0-9._%:-]+$` | one segment | Source: `ConfigResourceController.ENTITY_NAME_PATTERN` (applications stay on it; toolsets add the key check) — dots, colons, uppercase, percent | Refused | Served, encoded per the canonical form (dot and colon are unreserved/pchar-raw) |
| Segments with `{`, `}`, `"`, controls ≤ U+001F | — | Source: Core's resource-name forbidden set (`isValidFilename`: `INVALID_FILE_NAME_CHARS` is `/ { } "` plus ≤ U+001F — a decoded `/` inside a segment is reachable on the wire only as `%2F`, the row below) | Refused (charset) | Refused — Core's own rule, parity |
| Trailing dot in any segment | — | Source: Core's trailing-dot rule is creation-side only — `isValidResourcePath` is called from the write/upload controllers (`ResourceController`, `UploadFileController`), never on the resolution routes; a trailing-dot name that exists on the blob store resolves on Core's own port | Refused (charset) | Refused — a front-door ruling: mirrors Core's creation-side constraint, deliberately stricter than Core's resolution |
| `%2F` inside a segment | raw-forwarded | Design intent: same-answer-as-Core (byte-faithful); **[live]** nginx forwards `%2F` raw (see the nginx probe); Core's answer to it is the container's — verified once at implementation (the probe row) | n/a | Forwarded; Core answers |
| Raw unencoded non-ASCII / unsafe chars in the request-target | — | **[live]**: the map's wire grammar admits only unreserved + `%XX`, so raw shapes are refused by the router | Refused (charset) | Refused — a wire-spelling refusal; the same name is servable in its canonical encoded form |

## The listing-read grammar, pinned

The listing route's `{id}` and the MCP route's `{id}` are the **same string**: the
full resource URL for stored resources (type segment included — `toolsets/…`,
`applications/…`), the bare name for config entities. **[live]** confirmation: the
bucket-first spelling (`platform/probets-v2`, no type segment) is a parse failure at
`fromAnyUrl` → 404 "Unknown deployment: platform/probets-v2"; the full-URL spelling
(`toolsets/public/probets-v2`) resolves → 200. So the gateway's flow reads a
front-door path `/dial/{path}/mcp` as `GET /openai/toolsets/{path}` verbatim — no
transformation, one identifier everywhere. The credential call's `url` member carries
the **decoded** path (the form Core's `id` fields carry); its live verification for a
stored-toolset consent lands with this change's instrument (the tasks' failing-first
probe), since it needs a full consent round-trip.

## Operational facts recorded for the runbook

- `allowedRedirectUris`: Core registers every entry with the upstream at DCR time and
  stores the first entry of the upstream's DCR **response** as
  `auth_settings.redirect_uri`
  (`clientRegistrationResponse.getRedirectUris().getFirst()` — a conforming DCR
  server echoes the registered list in order, so the allowlist's first entry is the
  response's first); exchange-time validation accepts a presented `redirectUri`
  from the list or equal to the stored field (source:
  `DynamicResourceRegistrationStrategy.collectRedirectUris`,
  `TokenService.resolveRedirectUri`).
- The repair API re-runs DCR with the current list: new client_id, stored credentials
  cleared, `dynamicallyRegistered == true` required (source: `ToolSetRepairService`;
  `TOOL_SET_REPAIR` route above).
- The instance's Core build is older than HEAD 894328d6 in at least one visible rule
  (the toolset-key charset message) — the design targets HEAD and records the delta.
