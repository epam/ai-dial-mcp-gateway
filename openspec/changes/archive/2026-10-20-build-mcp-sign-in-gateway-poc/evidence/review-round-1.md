# Review round 1 — findings and resolutions

Reviewer: independent opus subagent, fresh pass, briefed from this folder only.
Verdict: **needs-changes** (0 BLOCKER, 1 MAJOR, 6 MINOR).
`openspec validate --changes --strict` green at review time.

## Findings

### MAJOR-1 — Spike's positive control depends on state no task establishes
- **Attaches to:** tasks.md group 1 / design.md D1.
- **Finding:** Task 1.5's positive control ("toolset MCP call as that user, with an
  upstream credential established by the PoC A rig") depends on: (a) the PoC A rig,
  which lives only in the sibling instance's **untracked** scratch
  (`../dial-instance/.mcp-poc/`) — the change's own Context forbids depending
  on it surviving; (b) the `notion` toolset being live in Core — but registration is
  task 6.3, five groups later, and neither `core/config.json` nor its PoC-era backup
  declares it (`"toolsets": {}`). The falsification gate for the entire change can be
  blocked or silently improvised on.
- **Required fix:** a group-1 precondition task establishing the spike's preconditions
  from **committed** material — register `notion` via the documented
  `PUT /v1/toolsets/platform/notion` recipe and establish the user credential via the
  documented `POST /v1/ops/toolset/signin` recipe (e.g. a committed spike helper), or
  minimally an explicit task that runs the rig, records that it did, and captures the
  rig's provenance in `evidence/spike.md`.
- **Resolution:** Fixed as required (committed-material route chosen; rig reference
  removed entirely). tasks.md group 1 restructured: new 1.5 registers the `notion`
  toolset via a committed helper (`scripts/spike_register_toolset.py`, the documented
  `PUT /v1/toolsets/platform/notion` recipe, verified by reading the public settings
  back); new 1.6 establishes the test user's upstream credential via a committed
  helper (`scripts/spike_establish_credential.py`, the documented
  `POST /v1/ops/toolset/signin` recipe, verified by `user_level_auth_status:
  SIGNED_IN`); the positive control is renumbered 1.7 and reworded to depend on 1.5/1.6
  (PoC A rig reference deleted); 1.9 records the preconditions and the helpers that
  established them. design.md D1 gained the committed-material preconditions paragraph.
  No reference to `../dial-instance/.mcp-poc/` remains anywhere in the
  artifacts.

### MINOR-1 — Reserved-name justification wrong for 3 of 9 names; design and spec disagree
- **Attaches to:** design.md D6; delta spec reserved-name requirement.
- **Finding:** D6 reserves `authorize, token, register, revoke, callback, status,
  jwks.json, signin, signout` "because the nginx AS-surface location would otherwise
  capture `/dial/<name>/mcp`" — but `signin`, `signout`, `status` are not in that
  regex and create no routing ambiguity. The spec's list (seven names) omits
  `signin`/`signout` — the two artifacts disagree.
- **Required fix:** trim the reserved set to the colliding names
  (`authorize, token, register, revoke, callback, jwks.json`) or correct the
  justification (defense-in-depth beyond the regex) and align the spec's list with D6's.
- **Resolution:** Fixed by trimming (option 1). design.md D6 now reserves exactly the
  six names the router's AS-surface alternation matches — `authorize`, `token`,
  `register`, `revoke`, `callback`, `jwks.json` — with the justification corrected to
  the true mechanism: the alternation captures `/dial/<name>/…` for exactly those
  names before the data-path regex can, so such a toolset's MCP traffic could never
  reach Core. `status`, `signin`, `signout` are dropped (checked against the routing
  sketch in `docs/background/design.md` §10.4: the status route is
  `^/dial/<name>/status$`, which cannot collide with `^/dial/<name>/mcp$`; no
  `/dial/signin`/`/dial/signout` endpoint exists on any surface). The list mirrors the
  alternation verbatim so the guard and the routing evolve together (`jwks.json` is
  unreachable under the `^[a-z0-9-]+$` name charset but stays listed for that
  fidelity). The delta spec's mapping-safety requirement now carries the same
  six-name list — design and spec agree.

### MINOR-2 — `refreshTtl` ≤ IdP access-token lifespan MUST is unverifiable
- **Attaches to:** delta spec (Refresh requirement); design.md D3; tasks.md 3.1.
- **Finding:** The spec states the MUST; design states it as a "Config rule"; but the
  gateway has no configured knowledge of the IdP's lifespan, task 3.1's startup
  validation does not include it, and no scenario covers a violation. As written it
  cannot be verified.
- **Required fix:** give it a testable home — e.g. a required operator setting for the
  IdP access-token lifespan, validated against `refreshTtl` at startup with a refusal
  scenario — or downgrade to a documented operator constraint with its verification
  stated in tasks.
- **Resolution:** Fixed with the startup-validation mechanism. A required operator
  setting `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` (the gateway has no other way to know
  the IdP's lifespan), validated against `refreshTtl` at startup with refusal naming
  both values. Homes: delta spec — refresh requirement reworked ("both are operator
  settings, validated at startup") plus a new scenario "Refresh TTL exceeds the
  provider lifespan"; design D3 point 3 is now the startup-enforced bound (no longer
  a free-floating "Config rule"); tasks 2.2 (the placeholder), 3.1 (the validation
  and its refusal unit test); release-notes draft records the enforcement.

### MINOR-3 — Task 6.4 mislabels a valid Core route as a defect
- **Attaches to:** tasks.md 6.4; design's local-environment corrections.
- **Finding:** "Fix the toolset public-settings read to `GET /v1/toolsets/platform/notion`"
  — but the doc's current `GET {core}/openai/toolsets/notion` is a real, working Core
  route (`RouteTemplate.TOOL_SET`; `ToolSetController.java:51`; `ToolSetData.java:68`
  puts `auth_settings` in the response). The review's mi-2 was about the old design
  prose naming `GET /v1/toolset/notion` (singular, bucketless), not about
  `local-environment.md`.
- **Required fix:** reword 6.4 to "align the documented settings-read with the flow's
  configured path" (both routes valid); verify the 403 semantics of
  `GET /v1/toolsets/platform/notion` for a no-access user (task 4.2's no-access branch
  depends on 403, not 404).
- **Resolution:** Fixed both halves. 6.4 reworded to an alignment ("the doc's current
  `GET {core}/openai/toolsets/notion` is the equivalent deployment-listing read — both
  are live Core routes, so this is an alignment, not a fix"; re-verified in source:
  `RouteTemplate.TOOL_SET` `^/+openai/toolsets/(?<id>.+?)$` and
  `PLATFORM_APP_TOOLSET_RESOURCE` `^/v1/toolsets/platform/(?<path>.*)$` are both live).
  The 403 semantics are now verified live: task 6.3's verification adds "a user
  without the toolset's read access receives 403 (not 404) on the same settings read,
  the status the flow's no-access branch (4.2) keys on."

### MINOR-4 — Scope handling between harness token request and Keycloak leg unspecified
- **Attaches to:** design.md D4/D7; delta spec flow requirement; tasks.
- **Finding:** The AS metadata's `scopes_supported` and how `/dial/authorize` maps or
  filters an incoming `scope` onto the Keycloak redirect are decided nowhere. The brief
  flags that `openid` is not a client scope in this realm and scope mistakes fail
  registration wholesale; a harness sending `scope=openid …` passed through could fail
  the Keycloak leg.
- **Required fix:** one decision line (e.g. the AS advertises its own minimal scopes
  and the gateway ignores the harness's `scope` on the Keycloak redirect, requesting
  only its client's defaults) in D4/D7 or the delta spec, with a task verification.
- **Resolution:** Fixed with a dedicated decision. New design D10: the client's
  `scope` parameter is accepted and dropped at `/dial/authorize` (never relayed — a
  scope the gateway's Keycloak client does not carry, or that is not a client scope
  in the realm at all, as `openid` is here, fails the whole leg); the Keycloak
  redirect requests exactly the pre-registered client's default scopes (locally
  `profile,email`); scope advertising is split — per-toolset PRMs carry the toolset's
  upstream `scopes_supported` verbatim (upstream leg only, whose authorize URL is
  built from the toolset's public settings, not client parameters), and the flat AS
  metadata advertises no scopes of its own (the gateway enforces none, and advertised
  scopes are echoed back by clients). Normative home: delta spec federation
  requirement ("a client's `scope` parameter is never relayed") + new scenario
  "Client scope never reaches the identity provider". Task verification: 3.3 (E1/E2
  shapes), 3.5 (scope drop), 4.1 (respx test asserting the provider redirect carries
  exactly the client's default scopes and no relayed `scope`).

### MINOR-5 — CIMD fetch's User-Agent unspecified (Cloudflare)
- **Attaches to:** design.md D5; tasks.md 3.4.
- **Finding:** The CIMD fetch for Claude Code targets `https://claude.ai/...`
  (Cloudflare-fronted) and is made server-side (httpx default UA `python-httpx/x`);
  the brief's own environment facts document Cloudflare rejecting Python default
  User-Agents. D5's otherwise-complete control set omits it; PoC C criterion (a)
  would trip over it late.
- **Required fix:** one line in D5 / task 3.4 requiring an explicit, non-default
  User-Agent on the CIMD fetch.
- **Resolution:** Fixed in both places. design D5's control set gains the bullet (the
  CIMD origin's bot protection rejects library-default agents — `python-httpx/x`
  class — so a default-UA fetch would surface as a late, misleading registration
  failure in PoC C); task 3.4 adds the explicit non-default User-Agent to the SSRF
  control set and a respx unit test asserting the fetch carries it.

### MINOR-6 — tasks group 2 lands tests but no docs
- **Attaches to:** tasks.md group 2.
- **Finding:** The brief's mechanics require every group to land its own tests and
  docs; group 2's closest artifact is `.env.example` additions (configuration, not
  docs).
- **Required fix:** add a short docs task to group 2 (e.g. README run/toolchain
  section or a brief `docs/` note) or fold `.env.example` explicitly into the group's
  documentation deliverable.
- **Resolution:** Fixed with a docs task. New task 2.5 lands the group's docs: the
  repo README's development section (venv creation, tooling from `.venv/Scripts`,
  the static gate commands, and the `.env`-from-`.env.example` step), with
  `.env.example` explicitly folded into that documentation deliverable; verification:
  the documented commands run as written.

## Confirmed-correct highlights (reviewer's spot-checks)

Core claim consumption paths; audience-verification conditionality (MA-1 premise);
provider selection by `issuerPattern` (missing on the Keycloak entry — real, tasked);
JWKS 10-min / userinfo 60-s caches; `offlineClient` optional; instance live values
verbatim; realm facts (24 h lifespan, no `openid` scope, `dial-sso-desktop-claude`
template with `project` mapper); toolset API shapes (validator-forbidden fields,
`redactSecrets()` nulling `codeVerifier`/`clientSecret`); topology feasibility
(default network `dial-instance_default`, ports 8090/8091 free, singular
`toolset` data path vs plural settings path); repo hygiene; full debt ledger
(BL-1/2, MA-1..4, mi-1..10) resolved concretely; never-cut invariants analyzed with
source-verifiable rulings; spec format green; cross-artifact consistency; HANDOFF
supersession recorded.
