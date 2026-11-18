# C2 live-run finding — the availability read denies a user the data path would admit

Date: 2026-11-05. Diagnosis only; no code or spec changed.
Sources: Core read fresh at commit `6dae044` (`development`),
`<the-sibling-core-checkout>` (READ-ONLY; the personal path elided per the
publication-discipline personal-path rule).
Gateway read in this worktree.

## Correction (2026-11-06, owner's catch)

The original diagnosis misattributed its "live" evidence: the Core log line it cited —
a 403 on `GET /v1/toolsets/platform/notion` for `user.id bba154f1-…` — was produced by
the DIAGNOSIS AGENT'S OWN control call (a minted non-admin Keycloak test user whose
`sub` is exactly `bba154f1-…`), not by the owner's B2C attempt. Core's log carries
**no** 403 for the B2C identity (`sub <tenant-user-sub-dir>`) anywhere in the window. The corrected
history: **every** B2C denial in the live run was Core answering **401** — it could not
validate the B2C access token (the audience mismatch: Core's pin spelled the scope URI,
the token's `aud` is the bare client id) — which `_read_json`'s 401/403 conflation
disguised as the access-denied page. The single root cause of the observed denials was
the audience mismatch; the conflation made it undiagnosable.

What survives of the routing decision (D15) is the STRUCTURAL fact from Core's source,
independent of log evidence: the platform-bucket settings route authorizes by
`AdminRoleAuthorizationService` (admin role only) while the MCP data path authorizes by
the deployment's `user_roles` — so the flow's availability decision, if it stayed on the
platform route, would falsely deny a federated non-admin user **after** the trust fix
unblocked the 401. The switch to the listing route remains necessary for that reason;
its evidentiary basis is corrected to the source-level fact.

## Symptom

Live B2C run: a user whose identity token carries `roles=["<tenant-role>"]` (no admin role)
completed the B2C identity leg; the gateway's availability read then returned 403 and the flow
served the refusal page ("You do not have access to this toolset"). The toolset ("notion") is
GLOBAL-scope, created through Core's platform admin API with no `user_roles` restriction — under
DIAL semantics a public toolset should be callable by any authenticated user, and Core's own MCP
data path does admit this user.

(The symptom record above is kept as written but re-read under the correction: the "403"
in the observed denial was the gateway's own conflation of Core's 401; the page class,
not Core's authorization decision, is what the symptom text reports.)

## What the gateway does today

- Availability = `GET /v1/toolsets/{toolset_bucket}/{name}` with the user's identity token
  (`gateway/core.py:306-310`); `toolset_bucket` defaults to and is deployed as `platform`
  (`gateway/settings.py:224`, `docker-compose.yml:133`, `.env.example:19`).
  A 403 (or 401) raises the access-denied refusal (`gateway/core.py:288-289`).
- Status = `GET /openai/toolsets/{name}` (`gateway/core.py:312-313`) — the deployment-listing
  route.

## Evidence — the route the gateway uses is an admin-only surface

1. **Routing.** `/v1/toolsets/{bucket}/{name}` with `bucket = "platform"` does NOT reach the
   user Resource API. `RouteTemplate.PLATFORM_APP_TOOLSET_RESOURCE` matches
   `^/v1/(applications|toolsets)/(?<bucket>platform)/(?<path>.*)$`
   (`server/src/main/java/com/epam/aidial/core/server/data/RouteTemplate.java:106-109`) and is
   registered before the generic `RESOURCE` route so it wins the match
   (`server/.../controller/ControllerSelector.java:80-90`), dispatching to
   `ConfigResourceController` (`ControllerSelector.java:83`, `:727-740`).

2. **Authorization.** `ConfigResourceController.handle()` checks
   `EntityBucketBinding.isAllowed(entityType, bucket)` then
   `authorizationService.isAuthorized(...)`, answering 403 `"Forbidden"` on failure
   (`server/.../controller/ConfigResourceController.java:1016-1032`). The wired implementation is
   `AdminRoleAuthorizationService`
   (`server/.../security/AdminRoleAuthorizationService.java:20-32`):
   - `bucket == "platform"` → `accessService.hasExplicitAdminAccess(context)` — **admin role
     only**; the entity's `user_roles`, its publicness, and any resource-level ACL play no part.
   - `bucket == "public"` → any authenticated caller on reads.
   - else → bucket-owner check.

3. **`hasExplicitAdminAccess` is fail-closed**
   (`server/.../security/AccessService.java:532-534`): `adminRulesConfigured &&
   hasAdminAccess(context)`; `hasAdminAccess` matches the caller's claims against the configured
   `access.admin.rules` (`AccessService.java:515-518`). A B2C user carrying only
   `<tenant-role>` does not match an admin rule → 403.

4. **Platform-created toolsets live in the `platform` bucket.** `EntityBucketBinding`
   allows toolsets in `{public, platform}` with `PLATFORM_BUCKET = "platform"`
   (`server/.../security/EntityBucketBinding.java:21,29`); the platform admin API writes them
   through the same controller's PUT delegation
   (`ConfigResourceController.java:1066-1077,1454+`). On startup the `MergedConfigStore` scan
   folds platform-bucket toolset blobs into the merged `Config`'s toolsets map, keyed by short
   name (`server/.../config/MergedConfigStore.java:1225,1247`; keying convention at `:86`).

So the gateway's read is `GET /v1/toolsets/platform/notion` as the end user: the record is
found, but the route answers 403 because the user is not an admin — **independently of the
toolset's own `user_roles`**, which are empty and would admit everyone.

## Evidence — the MCP data path admits the same user

The data path `/v1/toolset/{name}/mcp` (`RouteTemplate.TOOL_SET_MCP_PROXY`,
`RouteTemplate.java:387-390`) is served by `ToolSetMcpProxyController` → `McpProxyController.handle()`
(`server/.../controller/McpProxyController.java:113-138`). Its checks, in order:

- authentication (upstream of the controller; an unauthenticated call gets Core's 401 challenge —
  the fact the gateway's discovery requirement already relies on);
- the `useAllowedTools=false` admin gate (`McpProxyController.java:117-119`), which the normal
  call never triggers;
- `deploymentService.findDeployment(context, deploymentId)` (`McpProxyController.java:120`) —
  `DeploymentService.findDeployment` resolves a config-sourced deployment via
  `config.selectDeployment(id)` and checks **`deployment.hasAccess(context.getUserRoles())`**
  (`server/.../service/DeploymentService.java:63-70`); resource-based toolsets fall through to
  `accessService.hasReadAccess` (`DeploymentService.java:71-78`, `:119-139`);
- consent (`:121`) and rate limit (`:124`) — deployment-scoped, not role gates.

`RoleBasedEntity.hasAccess` (`config/src/main/java/com/epam/aidial/core/config/RoleBasedEntity.java:24-33`):
`user_roles == null` → **allow everyone**; non-empty → any intersection with the caller's roles.
For the admin-created "notion" toolset with no `user_roles`, the B2C user is authorized. For a
platform toolset the merged config (see 4 above) is exactly what `selectDeployment` consults.

**The data path and the platform settings read share no authorization logic**: the data path
checks the toolset's `user_roles` against the caller's roles; the platform settings read checks
only the caller's admin role.

## Evidence — the listing route

`GET /openai/toolsets/{name}` (`RouteTemplate.TOOL_SET`, `RouteTemplate.java:371-374`) →
`ToolSetController.getToolSet` (`server/.../controller/ToolSetController.java:66-79`) → the very
same `deploymentService.findDeployment` call. For the B2C user and this toolset it answers **200**,
with the toolset's `auth_settings` projected in the response body
(`ToolSetData.toData`, `server/.../data/ToolSetData.java:68`) plus the per-caller auth-status
enrichment (`ToolSetController.java:70-71`). This is the route the gateway already uses for the
status read — in the live run it was never reached, because the availability read 403'd first.

## Semantics comparison

| Route | What it checks | B2C user (`roles=["<tenant-role>"]`), admin-created toolset, no `user_roles` |
|---|---|---|
| `GET /v1/toolsets/platform/{name}` — gateway's availability read | caller's admin role only (`AdminRoleAuthorizationService.java:23-25`) — entity ACLs ignored | **403 Forbidden** → gateway refuses access |
| `POST /v1/toolset/{name}/mcp` — the data path | auth + `findDeployment`: the toolset's `user_roles` vs caller's roles (`DeploymentService.java:63-70`, `RoleBasedEntity.java:24-33`) | **authorized** (would proxy) |
| `GET /openai/toolsets/{name}` — listing route | the same `findDeployment` call (`ToolSetController.java:68`) | **200** with `auth_settings` |
| `GET /v1/toolsets/public/{name}` | user-resource permission rules (`AccessControlBaseController.java:32-46` → `AccessService` public rules) | irrelevant — a platform toolset does not exist in the `public/` bucket (404, not a fix) |

## Root cause

**CONFIRMED.** The gateway uses a read stricter than the data path — strictly stricter, in a way
that is wrong for the platform bucket: `GET /v1/toolsets/platform/{name}` answers the caller's
*admin role* (`AdminRoleAuthorizationService.java:23-25`), while the MCP data path answers the
toolset's own `user_roles` (`DeploymentService.java:66` + `RoleBasedEntity.java:24-33`). A
non-admin user is 403'd at availability for a toolset the data path would serve. The 403 is
unconditional on the entity: no `user_roles` value the toolset could carry would change it.

The mismatch is structural, not tunable: `toolset_bucket` cannot be pointed at a bucket whose
read semantics match the data path, because the toolset actually lives in `platform/` (that is
where the platform admin API creates it), and the *public* bucket route would 404 for it.

## Proposed fix options

**Option A (recommended): make the deployment-listing route the availability oracle.**
Decide availability with `GET /openai/toolsets/{name}` — the one read whose authorization
semantics are identical to the data path's by construction (both are `findDeployment`;
`ToolSetController.java:68` vs `McpProxyController.java:120`), and which 200s exactly when the
user could call the toolset. It also carries the `auth_settings` projection (`ToolSetData.java:68`),
so the flow's settings/status reads can collapse onto it (field parity to be verified in the
change's design: the platform route's redacted settings vs the listing route's
`ResourceAuthSettingsData`). `toolset_bucket` becomes obsolete for the availability decision.
- Spec impact (`openspec/specs/mcp-signin/spec.md`):
  - Requirement **"The federation flow establishes the upstream credential through Core"**
    (line 156): the sentence "DIAL authorization is enforced by fetching the toolset settings as
    that user before any upstream round-trip" and the surrounding text naming "this same settings
    read" would need amending to name the listing read as the authorization-bearing read.
  - Scenario **"DIAL authorization denied"** (lines 162-164): "WHEN the authenticated user cannot
    read the toolset's settings" must be re-based on the listing read's refusal.
  - Scenario **"Unknown toolset refused at the flow's settings read"** (lines 198-200): the
    existence refusal is pinned to "the flow's settings read"; it must be re-pinned to the
    listing read (the existence-refusal semantics are unchanged — a 404 from `findDeployment` —
    but the surface named is the settings read).
  - Requirement **"Discovery documents describe one flat authorization server"** (line 26) and
    the "Dynamic toolset served without local configuration" scenario (line 44): the mirror-property
    sentence pins "existence is decided post-authentication, at the flow's per-user settings
    read" — must be re-pinned to the listing read.

**Option B: keep the platform settings read, add the listing route as a pre-flight availability
gate.** The flow first confirms the user can call the toolset via the listing route, then reads
platform settings (as the user; admins only get past it — non-admins' settings read would still
403). Workable only if the settings read happens with a gateway service credential instead of the
user's token — which would drop the per-user DIAL-authorization enforcement the settings read
exists to provide ("DIAL authorization is enforced by fetching the toolset settings as that
user"), a security-relevant weakening that would need its own SIA and is NOT recommended as a
shortcut.

**Option C: correct at the operator layer (no code change): create user-callable toolsets in the
`public/` bucket instead of `platform/`.** `GET /v1/toolsets/public/{name}` admits any
authenticated reader (`AdminRoleAuthorizationService.java:26-30`) — but this changes platform
administration practice (blob location, admin tooling) and does not fix the semantics mismatch
for platform-resident toolsets; at best a documented workaround, not the fix.

Option A is the only option that makes the gateway's availability decision *be* the data path's
decision; B weakens the per-user check; C is a workaround that leaves the defect latent.
