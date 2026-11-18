# Finding F2 — the front door can only address a fraction of the resources Core can serve

## Symptom

A harness pointed at a stored toolset (`toolsets/public/{name}`), a bucket-scoped app
(`applications/{bucket}/{name}`), or any resource whose name carries an underscore,
dot, uppercase letter, or colon, cannot use the gateway's front door at all: the
router has no location for the path, and the gateway's name guard refuses the name on
every authorization surface. The same resources work fine against Core's own port.

## Evidence

- The router's data-path locations capture single-segment `[a-z0-9-]+` names
  (`router/nginx.conf`, the toolset and apps MCP locations); the gateway's guard is
  the same shape (`gateway/settings.py`, `_TOOLSET_NAME = re.compile(r"^[a-z0-9-]+$")`,
  shared by both namespaces' guards).
- Core's actual MCP routes are greedy multi-segment captures
  (`RouteTemplate.TOOL_SET_MCP_PROXY` `^/v1/toolset/(?<id>.+?)/mcp$`,
  `APPLICATION_MCP_PROXY` `^/v1/deployments/(?<id>.+?)/mcp$`, HEAD 894328d6), resolved
  by `DeploymentService.findDeployment`'s dual lookup: leg a, the config registry by
  bare name; leg b, `ResourceDescriptorFactory.fromAnyUrl` over the full resource URL
  (type segment, bucket, folders, name), with `AccessService.hasReadAccess` deciding
  per caller.
- The deployment-listing route is the same greedy shape
  (`TOOL_SET` `^/+openai/toolsets/(?<id>.+?)$`) and resolves through the same dual
  lookup — verified live against the dev instance (2026-11-13, probe records in
  `core-resource-addressing-matrix.md`): a toolset created at
  `toolsets/public/probets-v2` answers `GET /openai/toolsets/toolsets/public/probets-v2`
  with 200 and its id echoed verbatim, while the bare-name shape
  (`/openai/toolsets/platform/probets-v2`) answers 404 "Unknown deployment" and the
  MCP route `/v1/toolset/toolsets/public/probets-v2/mcp` resolves (403/404
  distinguishable from the bogus-path 404 by an authenticated call).
- User buckets are addressed by a Base58 ciphertext of `Users/{sub}`
  (`EncryptionService`, `Base58`) — alphanumeric, single-segment, per-caller,
  decryptable only with Core's secret; clients obtain it verbatim from Core's own
  `id`/`name` responses and never compute it.
- Core's name rules are wider than the front door's: toolset keys
  `^[A-Za-z0-9-_]+$` at HEAD (`ConfigPostProcessor.RESOURCE_KEY_PATTERN` — underscore
  allowed, uppercase allowed; the live instance's older build enforces `[a-z0-9-_]`),
  application names `^[A-Za-z0-9._%:-]+$`
  (`ConfigResourceController.ENTITY_NAME_PATTERN`). Concretely: an app named
  `QuickApp.v2` or a toolset named `my_toolset` is Core-servable and
  front-door-refused today.
- Resolution-time constraints (the rules the front door participates in): forbidden
  characters per segment — `/ { } "` and controls ≤ U+001F (`isValidFilename`; a
  decoded `/` inside a segment is reachable on the wire only as `%2F`) — and a
  path-size bound of 900 UTF-8 bytes on the resource's **absolute storage path**
  (bucket location plus relative path, `ResourceDescriptorFactory`), not on the
  resource URL; no depth limit on the resolution routes. The trailing-dot rule is
  **creation-side only** — `isValidResourcePath` is called from the write and upload
  controllers, never on the resolution routes, so a trailing-dot name that exists on
  the blob store resolves on Core's own port; the front door's trailing-dot refusal
  is therefore its own ruling, deliberately stricter than Core's resolution (design
  D4). Creation-time constraints are narrower (see the matrix file) — the toolset
  CRUD API refuses folder paths at creation entirely (whole-path single-segment
  validation, `ConfigResourceController.handle`), while every resolution route
  accepts them mechanically.
- Core has no `__version` logic anywhere — versioned names are a client-side
  convention baked into the stored name; every resource has one literal URL.

## Root cause

The front door was designed against a one-segment, lowercase-charset name model that
matches only the config-entity cell of Core's actual addressing matrix. Everything
else Core serves — bucket-scoped stored resources, folder-nested paths, wide-charset
names — has no front-door spelling. The router's capture and the gateway's guard were
kept deliberately in lockstep (`[a-z0-9-]+` in both), so the limitation is symmetric
and total, not an accidental gap on one side.

## Proposed fix

Pass-through resource paths (design.md D2–D6): the front door's name segment becomes
the resource path — the exact string Core's own routes and responses key on — routed
by a byte-faithful raw-URI map (design.md D3, the mechanism probed in
`nginx-mechanism-probe.md`) and guarded by a decoded per-segment path grammar whose
rules mirror Core's own (design.md D4), with the reserved names re-scoped to the first
segment (D5) and the flow's Core reads re-addressed by the same path (D6). The MCP
data path stays gateway-free. The matrix, cell by cell with its verification, is
`core-resource-addressing-matrix.md`.
