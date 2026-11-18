# Tasks

Authoring note: this change is specified first, every box starting unchecked; the
implementation pass runs against this list after the independent review and the
owner pause (the owner's two rulings of 2026-11-03 are folded in — the status
surface's removal and the kept path-grammar asymmetry). The task order is the
dependency order: the status surface's removal comes first (a pure deletion, no
dependency on anything else this change builds), then the settings and guard
constants (every later site reuses them), then the discovery surface, the flow,
the token endpoints, the router, the docs and threat model, and the gates. The
audit vocabulary's new tokens (`invalid_app_name`, `restricted_app`,
`unknown_app`, `credential_free_short_circuit`) are committed constants in the
closed reason tables wherever they land — no refusal bypasses its table with a
direct `flow_refused` call — and the status-only tokens (`missing_token`,
`invalid_token`) retire with the endpoint they served, after the implementation
pass greps that no other emit site uses them.

## 1. The status surface's removal, and the settings and app name guard

- [x] 1.1 Delete the sign-in status surface — both namespaces (the owner's ruling
  at the review pause; the delta's REMOVED entry, design.md D4): remove
  `gateway/status.py` and its router registration in `gateway/app.py`; the Core
  status read the flow's signed-in check uses stays in `gateway/core.py`
  (`read_toolset_status` — only the endpoint surface goes); retire the
  status-only audit reason tokens (`missing_token`, `invalid_token`) from the
  closed reason table after grepping every audit emit site for them (the shared
  tokens — `rate_limited`, the guard tokens, `invalid_target` — stay); delete
  the status endpoint's tests. Verify: unit rows asserting the route is gone (a
  request to `/dial/{name}/status` reaches no gateway handler), the retired
  tokens absent from the reason table, the flow's signed-in check unchanged
  (regression rows — the settings read's status fallback still runs), and every
  remaining audit emit site byte-identical in behavior.
- [x] 1.2 Add the apps restriction and the app name guard to `gateway/settings.py`
  (design.md D1/D5): a new optional `apps` setting of the same
  JSON-in-environment shape as `toolsets` whose entries carry nothing but the name
  (the model forbids every other member, so an entry carrying scopes or a kind is
  refused loudly at parse naming the field); the app guard
  `app_guard_refusal(name)` mirroring `toolset_guard_refusal` — the same
  `_TOOLSET_NAME` charset pattern, the apps restriction in place of the toolset
  restriction, and **no reserved-name check**, with the docstring stating the
  reason (nothing the gateway owns is served under the apps namespace's name
  segment; the reserved names are `/dial/`-scoped). Add the startup routing
  refusal for *configured* apps entries (charset violation → refuse the start,
  operator-facing message naming the entry and the charset). Re-word the inference
  validator to name **the toolset restriction** explicitly (a declared amendment —
  "a restriction" is ambiguous with two present) and state that inference never
  consults the apps restriction. Verify: unit rows for the app guard's each
  refusal class and its pass; the charset startup refusal's operator-facing
  message; the parse refusal for an entry carrying an unknown member; the
  inference re-wording against both restrictions configured and against only one.
- [x] 1.3 Add the app resource-URI derivations beside the toolset ones
  (`gateway/settings.py`, design.md D1/D2): `app_resource_uri(name)` →
  `{public-origin}/apps/{name}/mcp`, and the prefix-anchored inverse
  `resource_kind_and_name(resource)` resolving a resource URI to `(kind, name)` —
  `/dial/`-prefixed to toolset, `/apps/`-prefixed to app, `None` otherwise — with
  both derivations disjoint by prefix so no URI resolves both ways. Keep
  `toolset_resource_uri`/`toolset_name_from_resource` delegating to the shared
  resolution so the toolset spelling stays one code path, not two. Verify: unit
  rows asserting the disjointness both ways (a toolset URI never resolves as an
  app name and vice versa), the anchored refusals (trailing slash, extra segment,
  empty name), and byte-identical behavior for every existing toolset derivation
  row.

## 2. The apps discovery surface

- [x] 2.1 Add the apps protected-resource document and route
  (`gateway/discovery.py`, `gateway/routes.py`; design.md D8): the document
  (`resource` = the app resource URI, `authorization_servers` = the single
  gateway origin, `scopes_supported` always empty with the reason in the
  docstring, no kind extension) and the route at
  `/.well-known/oauth-protected-resource/apps/{name}/mcp`, joining the shared
  per-source and global limiter **before** the guard (an over-limit request
  writes no record at all), answering the guard's refusals with the surface's 404
  shape and one fixed-vocabulary audit record carrying the truncated name, and
  serving every guard-passing name with **zero Core calls** — the mirror property
  extended, stated in the route's docstring with the Core facts it rests on (the
  apps tier is served from the same `toolsets.security` configuration; the auth
  check precedes any registry lookup; the metadata document echoes the requested
  path). Verify: unit rows for the guard-passing serve in dynamic mode with a
  negative control proving no Core call is made on this path, the
  restriction-excluded 404, each guard refusal's fixed-vocabulary record, the
  always-empty scopes member, and the over-limit 429 writing no record.

## 3. The app flow

- [x] 3.1 Add the app read client (`gateway/core.py`; design.md D2):
  `read_app_for_flow(app, identity_token)` → `GET {core}/openai/applications/{id}`
  with the live user's token, carrying the three distinguishable failure shapes —
  403 raises the access-denied error (the same no-access page class the toolset
  read earns), 404 raises a new `AppUnknownError` (the apps namespace's existence
  refusal), and unreachable/unreadable raises the deployment-fault `CoreError`,
  never an existence answer. The read parses nothing beyond existence and
  readability — the per-service statuses the route may enrich are not read (out
  of scope; the docstring says so). Verify: unit rows for each of the three
  shapes with a mocked Core, including that no Core response text reaches any
  error message or record.
- [x] 3.2 Add the app branch of the flow's routing decision, and extend the
  audit trail to the second resource kind (`gateway/federation.py` — the routing
  decision itself lives in `_run_identity_leg`, so the app branch hooks it
  there — with `gateway/flow.py`, `gateway/authorize.py`, and the flow record in
  `gateway/state.py`; `gateway/audit.py`; design.md D3 and the lifecycle
  requirement's declared amendment): the flow record carries the resource kind
  (derived once from the resource URI at allocation, never re-derived per
  site); the identity leg is unchanged; after the exchange, an app-kind flow
  runs the app read in the settings read's
  position (the DIAL authorization check) and then the **unconditional
  kind-driven short-circuit** — no signed-in check, no kind branch, no credential
  call, no upstream round-trip — minting the code with one fixed-vocabulary audit
  record (`credential_free_short_circuit`) naming the resource kind. The
  toolset-kind flow's stages are untouched. The authorization endpoint's
  `_resolve_toolset` generalizes to resource resolution across both shapes
  (task 1.3's shared derivation), each shape under its own guard, with the
  inference path still resolving only through the toolset restriction. The
  audit trail's changes land in `gateway/audit.py`: the allocation record gains
  the resource kind the flow serves, the facts vocabulary's `toolset` fact
  becomes `resource` across the audit emit sites (a flow is now addressed to a
  toolset or an app), and the closed reason vocabulary gains the new app tokens
  (`unknown_app`, `credential_free_short_circuit`) — no refusal bypasses the
  table with a direct free-form call. Verify: unit rows for the app flow's
  full path (no consent-leg or credential-call event
  exists on the trail — asserted negatively), the three app-read failure shapes'
  pages and audit records, the short-circuit record's vocabulary and facts, the
  allocation record's resource-kind fact and the renamed fact field on every
  emit site, the toolset flow's unchanged stage order (regression rows), and
  the inference never resolving to an app.

## 4. The token endpoints and the audience

- [x] 4.1 Generalize resource resolution and the audience across both kinds
  (`gateway/token.py`; design.md D6): the token endpoint's
  code-grant and refresh-grant resource checks resolve both shapes through the
  shared derivation (task 1.3), the app guard covering app-shaped resources at
  the refresh site exactly as the toolset guard covers toolset-shaped ones (the
  guard tokens reaching the record through the closed reason table's named-class
  extension, as C1's task 1.2 established); the mint's `aud` carries the
  addressed resource's URI — toolset or app — plus the marker, and the refresh
  token's `aud` carries the addressed resource's URI alone (the separation
  pinned for both kinds). The code bindings carry the app resource for app-kind
  flows. Verify: unit rows for an app-kind code grant and refresh (the audience
  members asserted), the refresh resource match across shapes (an app resource
  refused on a toolset token's refresh and vice versa), and the retained
  toolset rows byte-identical in behavior.

## 5. The router

- [x] 5.1 Add the apps location, its challenge map, and the apps metadata route,
  and remove the status location (`router/nginx.conf`, `docs/routing.md`;
  design.md D7 and D4): add `location ~
  ^/\.well-known/oauth-protected-resource/apps/` → the gateway; `location ~
  ^/apps/(?<aname>[a-z0-9-]+)/mcp$` →
  `proxy_pass http://core/v1/deployments/$aname/mcp$is_args$args;` with
  `proxy_buffering off` / `proxy_request_buffering off`,
  `proxy_hide_header WWW-Authenticate`, and a second `$status`-keyed map
  synthesizing `Bearer
  resource_metadata="$mcp_origin/.well-known/oauth-protected-resource/apps/$aname/mcp"`
  — each element carrying the toolset location's reason in its comment, restated
  for the apps path (the disjoint prefix, the capture-keyed map, the measured
  query-loss behavior); and remove the status location
  (`location ~ ^/dial/[a-z0-9-]+/status$`, with its comment) and the status row
  from `docs/routing.md`'s location map — the status surface's removal, both
  namespaces (the owner's ruling; D4). Verify: the routing probe battery gains
  apps rows — an unauthenticated apps MCP call answered 401 with the gateway's
  challenge naming the **apps** metadata path and none of Core's; the query
  string arriving at Core's deployments path unchanged; the apps metadata route
  served by the gateway; a status path under either namespace
  (`GET /dial/<name>/status` and `GET /apps/<name>/status`) falling through to
  Core, whose auth filter precedes any routing and answers an unauthenticated
  call with Core's own 401 — the same fact of the enabled route the mirror
  property names — with no gateway challenge (a 404 is what an authenticated
  request would meet) — the status drop made
  checkable; and the toolset rows unchanged (regression).

## 6. Documentation and the threat model

- [x] 6.1 Update the operator reference, `.env.example`, the local-environment
  reference, and the roadmap (`docs/gateway-configuration.md`, `.env.example`,
  `docs/local-environment.md`, `docs/production-roadmap.md`): the app test fixture
  (task 7.2a — the compose service and `scripts/spike_register_app.py`, its usage, and
  the registered app the acceptance run points at) joins the toolset the local
  environment already documents; the apps path shape and its challenge; the
  `APPS` restriction (optional; entries are names only; the charset startup
  refusal); the app flow's shape (no consent, no credential call); the app read
  row in the Core-calls table; the corrected audience statement (the marker is
  what Core's provider entry verifies — no per-resource match exists on Core's
  MCP paths — the resource audience being the gateway's own addressing
  discipline); the removal of the status endpoint's section and every status
  mention in the guard description (the surface is gone — the diagnostic path
  that remains is the 401 challenge shapes and the audit trail); and, in
  `docs/production-roadmap.md`'s "Deferred — to later iterations" table, the
  deferred path-grammar-unification row (the `/dial/` vs `/apps/` prefix
  asymmetry kept as authored — one prefix per concern would retire the
  reserved-name class; naturally landing with E1, the Core merge, or as its own
  change with a migration window) — behavior and reason wording, the deferred
  table being the decision-record register for it. And, in the same roadmap's
  iteration ordering ("The iteration, packaged and ordered"), insert the new
  item **C2.5 — AS security hardening (RFC 9700 alignment)** between C2 and C3
  — in the ordering block and as its own prose paragraph, with the section's
  framing sentence re-counted (the iteration becomes five grouped OpenSpec
  changes, not three — the count covering C1, C1.5, C2, C2.5, and C3; the
  sentence being re-counted has itself been stale since C1.5's addition, so
  the implementer corrects the stale count rather than merely updating it):
  an AS-specific security-hardening pass against the
  OAuth 2.0 Security Best Current Practice (RFC 9700) plus the OIDC
  recommendations, every scope item dispositioned by that change itself
  (landed, deferred, or accepted with reasoning) — the scope seed: (1) the
  consent/attribution checkpoint (the team's finding: a client registered
  through CIMD on an allowlisted origin can drive a victim's live IdP session
  through `/dial/authorize` with no gateway-owned decision point anywhere —
  the app kind's zero-page short-circuit the sharpest variant — and redeem the
  code as the victim; PKCE/state/single-use bound the interception class, not
  this one; the standing control is CIMD allowlist curation, the standard
  remedy a consent page naming the resolved client and resource); (2)
  sender-constrained tokens (DPoP, RFC 9449) evaluated as the structural
  remedy for the bearer-token residual (the harness ecosystem's DPoP support
  is the open question — evaluate, don't promise); (3) step-up /
  re-authentication (`max_age`, `prompt=login`, `auth_time`); (4) `state`
  strictness (absent client `state` refused or tolerated — made explicit);
  (5) the CORS/back-channel posture statement (the token endpoint is
  same-origin/back-channel only; a browser frontend is not a supported client
  shape). The item's acceptance carries as its first two rows the RFC 9700
  checklist re-judge (every recommendation dispositioned against the gateway
  as built) and the consent-page decision (built, or refused with reasoning).
  The positioning rationale is stated in the item: after C2 because the
  consent-page acceptance needs the local compose stack (the same reasoning
  that orders C2 before C3) and because C2's `KEYCLOAK_*` → `IDP_*` rename
  churns the IdP leg the hardening touches; before C3 so that both C2.5 and
  C3 land before D3 and the closing re-judge judges the final shape. Verify:
  the documented
  commands and settings run as written against the composed stack; no
  status-**endpoint** reference survives in the operator reference — the
  dropped endpoint's own section gone and the status mention dropped from the
  guard description (the task body's sites), not every occurrence of "status":
  the flow's Core status read (`read_toolset_status`, documented in the
  Core-calls and status-check material) legitimately stays; the deferred row
  present; the C2.5 item present in the iteration ordering between C2 and C3,
  in the ordering block and the prose, with the scope seed, the
  first-two-rows acceptance, and the positioning rationale as authored above;
  and the T1-25 threat row's disposition (design.md §7) names C2.5 as the
  remediation's home.
- [x] 6.2 Land the threat-model delta (`docs/threat-model.md`; design.md §7 — the
  standing rule, this change's own task, not a follow-up): amend T1-12/RES-7
  (widened cross-kind, the verified marker-only enforcement, the Core-side ask
  as the named structural fix), T5-3 (the existence-edge wording becomes
  per-namespace — the per-user settings read is the toolset namespace's
  existence decision, the app read the apps namespace's, both
  post-authentication — in both the §8 threat row and its disposition row),
  the EP1 entry-point description, T6-2/T6-3
  (the apps location and map), M10/M6 (extended), and the attacker inventory's
  business-user row; add the new rows T1-23 (the unconditional app mint —
  mitigated), T1-24 (apps-namespace discovery enumeration on the unauthenticated
  apps route — a row of its own: its surface is an unauthenticated discovery
  route, the mirror property's class, never an authenticated read), T5-8 (the
  forged app read — the internal-leg bound), T6-8 (the apps location —
  mitigated), **T1-25** (the drive-by/malicious-client hijack of the flow
  **via the app path's zero-page short-circuit**, the surface this change
  widens — a CIMD-registered client on an allowlisted origin driving
  a victim's live IdP session through `/dial/authorize`, the IdP leg
  completing silently with nothing client-identifying relayed into it, the
  app kind's unconditional short-circuit completing the flow with zero
  user-visible pages (the toolset stored-credential short-circuit, the
  class's pre-existing other member, named for context), the code redeemed on
  the attacker's registered redirect with their own verifier, a gateway token
  held as the victim; PKCE, `state`, and single-use codes bound the
  interception class, not this one; the standing control is CIMD allowlist
  curation; disposition: remediation
  deferred to **C2.5 — AS security hardening (RFC 9700 alignment)**, the
  roadmap item this change's docs task records — the threat row and its
  disposition row, cross-referenced to the roadmap item; the next free EP1 id,
  T1-23/T1-24 being this change's own), and M24/M25 to the grouped list; **retire T1-15** (the
  status-enumeration threat — its surface, the authenticated status read E9, is
  deleted with the status endpoint, the owner's ruling; D4): the threat row and
  its disposition row are removed, E9 leaves the entry-point inventory and the
  two verification-surface enumerations that name it are re-counted to match
  (the EP4 `E4/E9/E10 verification` row's label becomes `E4/E10`; T4-7's grid —
  "verifies JWTs at exactly three endpoints (E4, E9, E10)" — becomes
  two, E4/E10, counting only what the process still verifies), the rows
  citing `gateway/status.py` (the EP1 toolset/leg-confusion row's
  resource-binding citation, and T1-4's disposition) are re-worded to the
  surfaces that remain (the token endpoint's resource match), T1-15 leaves the
  M6, M11, and M23 Addresses lists, and the attacker inventory's business-user
  bullet drops the status walk — the retirement stated, no cross-reference
  orphaned; the resolved OQ-1 record (the dated note that E9 enforced the
  resource binding, citing `gateway/status.py:111-122`) keeps its original
  wording — a historical record of a question resolved before the endpoint's
  removal is not re-worded, and the retirement's grep treats its citation as a
  known, accepted remaining reference rather than a dangling one; confirm no new
  residual record is opened (the accepted remainders
  land inside existing records — RES-7 widened, RES-19 extended — and the
  apps-inventory disclosure as T1-24's stated disposition; T1-15's retirement
  closes a formerly accepted disclosure rather than opening one). Verify: the
  at-a-glance counts re-counted from the actual delta (threats, grouped
  mitigations — the retirement included); every new ID resolves; no dangling
  reference to a deleted or renamed row — a repo-wide grep for "T1-15", "E9",
  and `gateway/status.py` returns only the retirement's own statements, the
  re-counted EP4/T4-7 surfaces, and the OQ-1 record's dated citation (the
  allowed remainder); the T5-3 re-wording present in both the threat row and
  its disposition row; and the T1-25 row and its disposition row present with
  the drive-by scenario, the widened-surface statement (the row's subject is
  the app path's zero-page short-circuit — a variant that would not exist
  without this change — with the toolset stored-credential short-circuit
  named as the class's pre-existing other member), the standing control (CIMD
  allowlist curation), and the C2.5 cross-reference (the disposition names
  the roadmap item).

## 7. Gates and the live acceptance run

- [x] 7.1 Run the lightweight gates (`PROCESS.md` step 5): `ruff check`,
  `ruff format --check`, `mypy`, `pytest -q`, then `bandit`, `pip-audit`, and
  Trivy, with findings triaged. Verify: all green with every finding triaged or
  fixed.
- [x] 7.2 Run the compose-boot gate (`PROCESS.md` step 6): `docker compose up`
  brings the stack up and the health probe passes for every service. Verify: the
  probe output captured in this change's `evidence/`.
- [x] 7.2a Add the app test fixture. Before provisioning it, probe the live Core for
  a pre-existing MCP app the acceptance could use directly — the Skills MCP demo app
  (an MCP app outside this repo, registered into Core's bucket storage **via the API**,
  which is why Core's static `config.json` lists no applications) — with one
  authenticated `GET /openai/applications/{bucket}/{name}`: if it is still registered
  and its declaration carries the `mcp` block Core's apps MCP proxy requires, it may
  serve the acceptance run below as a verified-real app, the fixture then the fallback;
  the fixture is this task's primary deliverable either way (self-sufficiency is the
  owner's stated preference; the probe only avoids duplicate work). The fixture
  (a precondition of the run below; no app resource exists in this repo's local
  environment — its Compose stack and Core's static `config.json` — or in the tasks —
  the Notion toolset is a toolset, and Core's `ApplicationMcpProxyController` refuses an
  application whose `mcp` block is null, so the acceptance run has nothing to point at
  until this lands): (a) a minimal
  MCP-speaking upstream service in `docker-compose.yml` — the reference MCP test server
  image, or an equivalent minimal local fixture — joined to the instance network, no
  external credential, reachable by Core by service name (`http://<service>:<port>/mcp`).
  It is a **test fixture**, not a production service, so it is gated behind the Compose
  `acceptance` profile: a plain `docker compose up -d` starts only the gateway and its
  router, and the fixture comes up with `docker compose --profile acceptance up -d
  mcp-app-fixture` (the command the acceptance run and the compose-boot gate's per-service
  probe use); the app's upstream leg attaches no stored credential (the injector sends the
  app id and optional header config only), so a keyless fixture keeps the acceptance
  hermetic;
  (b) a registration script `scripts/spike_register_app.py`, the sibling of
  `scripts/spike_register_toolset.py` — idempotent, admin-gated exactly as the toolset
  script is, creating the application resource in Core (`PUT /v1/applications/{bucket}/{name}`
  or the documented apps recipe) with an `mcp` block whose `endpoint` is the fixture's
  URL, safe to re-run (a repeat write is reported as idempotent success, `--replace`
  deletes first); (c) the acceptance run below pointed at the app resource this script
  registers, through the apps front door. Verify: the fixture answers an MCP
  initialize/handshake from inside the compose network (a negative control first — the
  call fails before the fixture is up); the registration script re-runs without error and
  the app resolves in Core (`GET /openai/applications/{id}` shows the `mcp` block); and
  deleting and re-registering the app works.
- [x] 7.3 Run the app-resource acceptance on a real harness (the delta spec's
  acceptance requirement; the charter's acceptance; the app resource the fixture task
  7.2a registers): (a) first use end to end —
  discovery at the apps protected-resource document, registration, the
  authorization request with `resource` naming the app's resource URI, the flow,
  and a live app tool call through the apps front door with a gateway-signed
  token; (b) the flow completes with no consent screen and no credential call,
  and the audit trail shows the kind-driven short-circuit; (c) a streamable
  session's query string survives the apps front routing; (d) a toolset sign-in
  completes unchanged. Verify: the run's evidence — captures of the challenge,
  the document, the flow's audit records (the short-circuit record present; no
  consent or credential event), the successful tool call, and the unchanged
  toolset flow — captured in this change's `evidence/`, per the probe-fail-first
  rule with the negative controls run before the verdicts.
- [x] 7.3a Fix Finding 1 from the live-acceptance run (the defect cycle; no spec
  change — the spec already demands the behavior): `gateway/federation.py`'s
  `_core_read_refusal` rendered the refusal page and wrote the audit record but
  never consumed the flow record, so a refused read left the record — and the
  identity access token and provider refresh token it still held — re-presentable,
  and a re-presented flow id re-ran the leg instead of landing on the expired page
  (the live run's measured `unknown_app` survivorship). Add
  `_consume_refused_flow` (destroy the record; drop the identity token and the
  provider refresh token) and call it on every refusal branch — both existence
  refusals and the 403 no-access refusal, fixed under the same custody rule (a
  refusal must not extend the identity token's retention past the flow TTL); the
  fault branch (unreachable/unreadable Core) does not consume state (the user
  re-runs it, and the three-shape discipline is preserved). The audit ordering is
  unchanged. Verify (probe-fail-first): the four new unit tests in
  `tests/test_federation.py` fail against the unpatched code and pass after the
  fix — each asserts the store no longer resolves the id, the record holds no
  identity credential, re-presenting the id yields the expired page with the
  provider exchange not re-run (a counted mock), and the refusal record still
  landed; and `pytest -q`, `ruff check`, LF-normalized `ruff format --check`, and
  `mypy` all green. **Landed — evidence `evidence/review-1-findings-and-dispositions.md`
  Round 11; resolution appended to `evidence/acceptance-live.md` Finding 1.**
- [x] 7.4 Run the security review gate and the review gate on the diff
  (`PROCESS.md` step 8): an independent reviewer subagent against this change's
  SIA (design.md §"Security impact analysis") and the threat model — its depth
  set by the SIA's medium impact level — then the general diff review. Verify:
  both gates' outcome records in this change's `evidence/`.
- [x] 7.5 Commit locally after the change's gates pass; push only after the
  owner's go. Verify: the commit on the worktree branch, nothing pushed.
