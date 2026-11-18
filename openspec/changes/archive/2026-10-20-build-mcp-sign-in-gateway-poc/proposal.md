# Proposal

## Why

A Chat-less DIAL deployment cannot establish the upstream credential an OAuth-protected
MCP toolset needs: the only designed sign-in surface is DIAL Chat, and a harness user is
blocked with an unactionable 401 that points at an IdP no client can complete
(`docs/background/problem-statement.md` §1.2, findings F-1/F-5). The converged,
adversarially reviewed design (`docs/background/design.md`, alternative C) fixes this
with a small MCP sign-in gateway registered in Core as an additional identity provider,
behind a front router that keeps MCP traffic on a direct path to Core. This change
implements the entire proof of concept and gates its completion on the PoC C acceptance
run against a real harness.

## What Changes

- **One OpenSpec change for the entire PoC** — from the Stage 0 spike through the PoC C
  acceptance gate. This supersedes the "write the change for Stage 0" instruction in
  `docs/HANDOFF.md` ("Where to start", step 2): the ROADMAP stages remain the
  implementation order, as this change's task groups.
- **A new `mcp-signin` capability**: an OAuth2 authorization server (the MCP sign-in
  gateway, a new small stateful service) owning the client-facing surface — flat AS
  metadata and per-toolset protected-resource documents, CIMD-first client registration
  (the gated DCR fallback's registration records are durable across restarts — one
  JSON file in a mounted volume, no database in v1), the federation flow
  (identity-provider leg → DIAL authorization check → upstream
  consent → Core's existing `POST /v1/ops/toolset/signin`), gateway-minted RS256 JWTs
  carrying the user's real identity, refresh/revocation, a status endpoint, and an audit
  trail.
- **A new front-router nginx** in front of one public origin: AS/discovery paths → the
  gateway; the toolset MCP path → Core directly, with the 401 challenge rewrite that
  replaces the upstream's challenge with the gateway's own.
- **Sibling instance changes, configuration only** (`../dial-instance/`):
  Core env vars (a new `dial-mcp-proxy` identity-provider entry including the audience
  marker; `issuerPattern` added to the existing Keycloak entry; `authorizationServers`
  repointed at the gateway origin; the upstream callback allowlisted), one pre-registered
  public PKCE Keycloak client plus mappers, and the `notion` toolset registered through
  Core's API.
- **No DIAL Core code changes; no DIAL Chat dependency; no harness-specific code.**

**Owner decisions carried into this change (recorded, not re-opened):**

1. One change for the entire PoC, not one per stage (supersedes `docs/HANDOFF.md` step 2).
2. The Stage 0 spike is this change's first task block, with an explicit falsification
   stop; it is executed later by an implementation subagent, not by the author.
3. Stack: Python 3.12 + FastAPI (uvicorn, `pyjwt[crypto]`, httpx, pydantic-settings,
   pytest + respx), matching the repo's toolchain.
4. Both design sign-offs are granted as owner rulings: (i) the OR-2 deviation — one
   always-on server-side component; (ii) the nginx 401 rewrite synthesizes a
   `WWW-Authenticate` header rather than purely splitting traffic.
5. The refresh design is the author's choice, made in `design.md` (option 1, a
   self-contained snapshot, with a bounded staleness rule).

**Out of scope for this change:**

- Non-OAuth toolset kinds (`API_KEY`, `DIAL_NATIVE`, `NONE`) in the gateway mapping —
  excluded from v1 and refused at startup; the API-key wrapper shape stays an open
  question.
- DIAL Core code changes of any kind (the Core footprint is env-var configuration).
- Keycloak realm security-policy changes (harnesses never register against Keycloak;
  the only Keycloak addition is one pre-registered public PKCE client and its mappers).
- GLOBAL-level credential establishment from a harness (admin-gated in Core; stays an
  operator action).
- Multi-instance HA (single gateway instance; loss semantics are specified; Redis-backed
  state is a documented future step).
- Keycloak RP-initiated logout wiring (v1 logout is local token discard + revocation).
- Per-toolset audience enforcement in Core (per-issuer path/audience scoping is a future
  Core-side ask; the v1 binding is the audience marker plus the gateway's strict
  `resource` check).
- DIAL Chat UX, and any harness-specific integration code.

## Capabilities

### New Capabilities

- `mcp-signin`: harness sign-in to OAuth-protected DIAL MCP toolsets — discovery
  documents, client registration (pre-registered / CIMD / gated DCR with durable,
  file-backed registration records), the federation
  flow through Core's unified credential API, gateway token issuance, refresh and
  revocation, front-door routing and the challenge rewrite, Core-side trust
  configuration, abuse bounds on the public surface, preservation of the credential
  model's security invariants, and the end-to-end acceptance gate.

### Modified Capabilities

None — this is the repository's first change; no main specs exist under
`openspec/specs/` yet.

## Impact

- **New code in this repo**: a `gateway/` package (Python 3.12 + FastAPI), `Dockerfile`
  (non-root), `docker-compose.yml` (services `mcp-signin-gateway` and
  `mcp-signin-router`, joined to the instance's compose network),
  `scripts/provision_keycloak.py` (admin credentials from `.env`, never hardcoded),
  `pyproject.toml` with the repo gate toolchain (ruff, mypy, bandit, pip-audit, pytest),
  tests, and `.env.example` additions. A mounted volume holds the durable DCR
  registration store (one JSON file — deliberately no database in v1; its loss means
  one re-registration round-trip per DCR harness). No credential, token, or key is
  ever committed.
- **Sibling instance (config only)**: Core `environment` additions and changes (applied
  with `wsl -e docker compose up -d --force-recreate core`), one Keycloak client, and
  toolset registration via `PUT /v1/toolsets/platform/notion`. One behavior change to
  note: `aidial.toolsets.security.authorizationServers` is repointed from Keycloak to the
  gateway origin, so Core's own protected-resource metadata advertises the gateway as
  the authorization server; Keycloak-issued tokens keep validating unchanged
  (coexistence is a PoC C criterion).
- **Docs**: corrections to `docs/local-environment.md` (the promised provisioning
  script, the Core-settings description — env vars in the instance compose, not an
  `aidial.settings.json` — and the toolset-settings path).
- **Security surface**: one new public AS surface and one new IdP-equivalent signing key
  (never-cut invariant 7). The change has material security impact; the full analysis
  and rulings against the never-cut list are in this change's `design.md`, and the
  security review gate runs at full depth on the implementation diff.
