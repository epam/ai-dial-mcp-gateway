# DR-0001 — Keep nginx; do not drop the front router

Status: **Accepted** (2026-10-17)
Deciders: the human owner, design author (agent), reviewer (agent)
Supersedes: nothing
Related: `problem-statement.md` §3 (FR-8, OR-2, OR-3, OR-4, CR-3), §4 (F-1, F-3), `design.md` §2, §4.4, §9

## Context

The design (`design.md`) proposes an **MCP sign-in gateway** beside DIAL Core, with
**nginx** in front of both on one public origin:

- nginx routes OAuth/AS traffic (`/.well-known/*`, `/dial/authorize`, `/dial/token`,
  `/dial/callback/*`, `/dial/jwks.json`) to the gateway, and everything else — including
  the toolset MCP path `/dial/{name}/mcp` — straight to **Core**.
- The gateway is an OAuth2 authorization server for harnesses: flat host-root AS metadata,
  CIMD-first client registration, the federation choreography (Keycloak → upstream
  consent → `POST /v1/ops/toolset/signin`), and it mints the JWTs harnesses use.
- Core accepts those JWTs because the gateway is registered as an **additional identity
  provider** (`issuerPattern` + `jwksUrl`) — config only, no Core code change.
- nginx also carries one job beyond routing: on the toolset MCP path it intercepts 401s
  (`proxy_intercept_errors on` + `error_page 401`) and **replaces the challenge** with the
  gateway's own.

That last job is the reason this record exists.

### Where nginx came from

nginx entered the original human sketch for **one** reason: the human believed the
authorization server had to be **per-toolset**, because Core's
`toolsets.security.authorizationServers` is a single global value and the AS must know
which toolset it is calling `/signin` for. A per-toolset AS would need path-based
splitting, which Core cannot do.

That reason is now **gone**. The AS disambiguates the toolset from the RFC 8707
`resource` parameter — which the MCP spec requires conformant clients to send on **both**
the authorization and token requests, and which was **measured** being sent with the
per-toolset value by Claude Code on both endpoints (the decoy-AS capture). One AS can
therefore serve every toolset.

## Decision considered

**Drop nginx.** If the AS no longer needs path splitting, it can live on its own origin,
Core's PRM advertises it, and MCP traffic reaches Core directly. One new always-on
component instead of two.

The argument, step by step:

1. Core's 401 on the toolset MCP path carries `resource_metadata` pointing at **Core's
   own** per-toolset PRM (PoC A).
2. Core's PRM `authorization_servers` is a config value — point it at the gateway
   (config-only).
3. Discovery chain: 401 → Core's PRM → gateway AS → gateway `/authorize` (federation) →
   gateway `/token` → harness calls **Core directly** with the gateway's JWT.
4. Core validates that JWT because the gateway is an additional identity provider.
5. So the gateway is never on the data path, and no router is needed to split AS from MCP
   traffic — they are on different origins.

Proposed recovery for the case nginx otherwise handles: re-run the skill, which reads
`user_level_auth_status` and re-runs the upstream consent.

## Analysis

Both the design author and the reviewer attacked this proposal **independently** — the
reviewer was not shown the author's objections. They converged on the same verdict.

### Verdict: rejected — not safe as proposed

> The human is right that resource-disambiguation retired nginx's **original** job
> (per-toolset AS splitting) — but nginx's job **moved**; the 401 rewrite is now the only
> config-only fix to an observed MUST-level failure mode, and this proposal removes it to
> save four lines of config on infrastructure that already exists.
> — reviewer

### Points both raised independently

**1. FR-8 becomes unmet by construction (MUST).**
There are two different 401s. The *no-token* one is Core's own challenge and is fine. The
*valid-token-but-no-upstream-credential* one is different: Core injects nothing, relays
the **upstream's** 401 verbatim, and it points at the upstream's IdP — which no harness
can complete, because only Core holds the upstream PKCE verifier. nginx was the only
config-only lever that rewrote it; the proxy never sees data-path responses, and Core's
relay behaviour is code, not config. Removing nginx leaves no fix that respects correction
1 (no Core code changes).

**2. The proposed recovery is circular.**
"Re-run the skill" is O-1 — the per-harness helper this design exists to retire. It is a
CR-3 regression, and it re-couples harness state (OR-4). Worse, the skill repairs the
*credential*, but the observed damage is to the harness's *session*: the harness discards
its own valid DIAL token on the unactionable 401 (F-3, observed). So the user loses both
legs, and recovery is potentially four manual steps (`mcp remove`, re-add, `login`, skill)
that an unassisted user could not be expected to discover. This fires on **routine**
credential lifecycle events — operator sign-out, upstream credential lapse — not rare
faults.

**3. The global repoint is a cutover, not an addition.**
`authorizationServers` is one value for every toolset and every client. No coexistence, no
per-toolset choice, no parallel run. Non-OAUTH toolsets would be advertised to an OAuth AS
that cannot serve them — the M-3 "silent unsatisfiable 401 loop", now with **global**
blast radius instead of being scoped to operator-mapped toolsets and enforced at proxy
startup.

### Point the reviewer raised that the author rated lower

With nginx gone, the harness reads **Core's** PRM, which the gateway cannot extend — so
FR-3's carrier (`dial_authentication_type`) disappears from the surface clients actually
walk. The reviewer rated this fatal-as-stated but **cheap to amend**: move the extension
into the gateway's *flat* AS metadata as a `resource` → authentication-type map. Recorded
as a required amendment if this decision is ever revisited.

### What the proposal got right (both acknowledged)

- The no-nginx discovery chain is **better evidenced** than the nginx one: the decoy
  capture ran in exactly that shape, and Claude Code walked 401 → Core's PRM → flat AS
  metadata → CIMD → `resource` on both endpoints. The nginx chain's *rewritten* challenge
  has never been exercised by anything.
- The `resource` identifier becomes Core's true resource-server URI rather than a
  `/dial/{name}/mcp` alias — more RFC 8707-correct.
- The nginx data-path block was the design's most fragile configuration (query strings,
  `$host`, SSE buffering).
- The "nginx stretches *splitter ONLY*" tension (OQ-8) disappears entirely.
- `resource` conformance beyond Claude Code is **not** a differentiator: the converged
  design requires it in both topologies, so it was not counted against this proposal.

### Cost-benefit correction (both)

The claimed "two components become one" is **largely illusory**. In any production
deployment Core already sits behind TLS/ingress, so nginx-the-process pre-exists and the
converged design added *configuration* to it. Net-new always-on components are **one** in
both topologies. Dropping nginx removes its *auth role* — the 401 synthesis, the OQ-8
sign-off, and the M-2-class config bugs — which is a real benefit, but it is being
purchased with the two fatal objections above.

## Outcome

**Keep nginx.** The design is unchanged.

Accepted residuals (already documented in `design.md`): the gateway is an always-on
component (OR-2 deviation, sign-off required); nginx challenge synthesis is a disclosed
stretch of "splitter ONLY" (OQ-8, sign-off required).

## Conditions for revisiting

If any of the following change, this decision should be re-opened:

1. **A requirements re-scope, signed off by the human**: FR-8 and OR-4 explicitly
   downgraded, with the observed token-discard/stuck-state behaviour recorded as an
   accepted shipped property and the traceability table updated to say so.
2. **A Core change to F-1** — Core recognizing "no credential stored" and answering with
   its own challenge. This is the *proper* fix and would remove nginx's last load-bearing
   role.
3. **The experiment below returns a favourable result** — which calibrates the recovery
   cost, though it does not by itself make the misdirection conformant.

### The experiment that would inform a revisit

Repoint `toolsets.security.authorizationServers` at a decoy proxy AS; get a live harness
fully authenticated with the toolset credential live; then remove the upstream credential
mid-session via the ops sign-out API; and capture the harness's complete state machine:

- does it follow the upstream's pointer?
- what does it store against Core's endpoint if it completes the upstream's OAuth?
- does it discard the proxy token?
- does it reach a stuck needs-auth state, or self-correct through re-discovery?

Several runs. Secondary measurements: AS-selection behaviour with a dual-listed
`authorization_servers` (Keycloak + gateway), and a full CIMD first-use against the
gateway origin.

**Caveat:** even the most favourable outcome does not make the misdirection conformant —
the experiment calibrates the *recovery cost*, it does not fix the requirement.

## What this decision does not close

- **F-1 remains open** as a defect. The proper fix is Core-side (challenge ownership) and
  is tracked in `problem-statement.md` §5.2 / `design.md` §9.
- **PoC C** remains the implementation gate; nginx's query-string survival criterion moves
  to the existing ingress.
- The **reserved-toolset-name collision** in the nginx routing regex remains an
  implementation detail to fix at build time.
