<h1 align="center">
    AI DIAL MCP Gateway
</h1>
<p align="center">
    <a href="https://dialx.ai/">
        <img src="https://dialx.ai/logo/dialx_logo.svg" alt="About DIALX">
    </a>
</p>
<h4 align="center">
    <a href="https://discord.gg/ukzj9U9tEe">
        <img src="https://img.shields.io/static/v1?label=DIALX%20Community%20on&message=Discord&color=blue&logo=Discord&style=flat-square" alt="Discord">
    </a>
</h4>

An **MCP sign-in gateway** for DIAL, plus the proof that it works.

DIAL's MCP toolsets hold their *upstream* credential (say, a Notion token) inside DIAL
Core, scoped per user — the harness never sees it. That model is required by the MCP
authorization specification, but it has historically left one gap: the only designed way
to establish that upstream credential was through DIAL Chat, and in a deployment where
DIAL Core is used purely as an LLM/MCP proxy, Chat may not be installed at all. Harness
users (Claude Code, Codex, Copilot, custom agents) were stuck.

This repository implements the fix: a small **OAuth2 authorization server** that harnesses
authenticate against, which performs the upstream sign-in on the user's behalf and then
mints the token the harness uses. It is **not on the MCP data path** — MCP traffic reaches
DIAL Core directly, and Core resolves the user's upstream credential from the identity in
the token.

**The gateway's role is wider than toolset sign-in.** As the harness-facing authorization
server it also absorbs the deployment IdP's MCP incompliances — an IdP that supports no
CIMD or DCR, or exposes quirky scopes and claims, never reaches the harness: the gateway
represents a perfectly MCP-compliant AS for the whole harness ecosystem. That role now
covers: any platform toolset served without per-toolset configuration (dynamic toolsets),
federation to any OIDC identity provider (an external customer-identity provider is the
tested case), and DIAL's "apps with MCP endpoints" as sign-in-able, credential-free
resources.

## Status

**The capability is field-proven, and the production-preparation iteration is nearly
complete.** The build and its first follow-on change are archived:
`build-mcp-sign-in-gateway-poc` closed all five acceptance criteria on real harnesses
(Claude Code via CIMD, Cursor via DCR) with the audit trail and Core's logs
corroborating every step, and `fix-dcr-response-conformance` fixed the RFC 7591
response conformance Cursor exposed. The capability spec is
[`openspec/specs/mcp-signin/spec.md`](openspec/specs/mcp-signin/spec.md).

**The production-preparation stages have landed**, each an archived change with live
evidence: dynamic platform toolsets and up-to-date claims at refresh, generalized OIDC
federation to any identity provider, apps with MCP endpoints as credential-free
sign-in-able resources, authorization-server hardening against the RFC 9700
recommendations, and the production deployment shape — the single nginx-plus-gateway pod,
both signing and custody keysets with env/file key sources (a KMS sign-interface reserved
as an optional extension), and no secret material in env files. The scope, the order, and
the deferred items are in [`docs/production-roadmap.md`](docs/production-roadmap.md).

**The one remaining stage is the closing security re-judge (D3):** every disclosed
residual, re-judged in the production shape, with the verdicts written into
[`docs/threat-model.md`](docs/threat-model.md).

Read [`docs/HANDOFF.md`](docs/HANDOFF.md) first. Then
[`docs/production-roadmap.md`](docs/production-roadmap.md) — the iteration's scope.

## Layout

| Path | What |
|---|---|
| [`docs/HANDOFF.md`](docs/HANDOFF.md) | **Start here** — what this is, current state, where to begin |
| [`docs/gateway-configuration.md`](docs/gateway-configuration.md) | Every gateway setting, the startup refusals, and the DCR store's loss semantics |
| [`docs/routing.md`](docs/routing.md) | The front router: the location map, the 401 challenge rewrite, and the probe battery |
| [`docs/local-environment.md`](docs/local-environment.md) | The local DIAL instance, endpoints and configuration |
| [`docs/background/`](docs/background/) | The design, its independent review, the requirements, and the PoC evidence |
| [`docs/background/decisions/`](docs/background/decisions/) | Decision records |
| [`docs/production-roadmap.md`](docs/production-roadmap.md) | The next iteration's scope (P1–P6), the deferred items, and the evolution list |
| [`docs/demo-slide.html`](docs/demo-slide.html) | The demo one-slider: problem, architecture, features |
| [`docs/hosting-options.html`](docs/hosting-options.html) | Hosting the sign-in flow: separate service / Core / Keycloak extension / Chat |
| [`PROCESS.md`](PROCESS.md) | The defect-fight cycle — how work is run |
| [`ROADMAP.md`](ROADMAP.md) | Stages and the never-cut security invariants |
| `gateway/` | The gateway service — the OAuth2 authorization server |
| `router/` | The front router's nginx configuration |
| `.env.example` | Every setting, with placeholders; copy to `.env` to run anything |
| `openspec/` | Normative specs and the change record |

## Development

### Setup

The service targets **Python 3.12**. Create the virtualenv and install the package with
its development extras:

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
```

On Windows the executables live in `.venv/Scripts`; every command below is written that
way. On Linux or macOS substitute `.venv/bin`.

### Configuration

Nothing runs without a `.env`: `Settings` refuses to construct when a required setting
is absent, and `IDP_SSO_SESSION_MAX_SECONDS` deliberately has no default. Copy the
committed example and fill in the local values:

```bash
cp .env.example .env
```

`.env.example` documents every setting and carries **placeholders only**. `.env` is
gitignored and is the only place a real value belongs — no credential, token, or key is
ever committed, and nothing prints one.

Two settings are required and have no default: `IDP_SSO_SESSION_MAX_SECONDS` (the
operator's declared bound on the identity provider's session policy, checked against the
refresh window) and `ROLES_SOURCE_PATH` (a silent default would produce a role-less token).
`GATEWAY_CUSTODY_KEYS` is also required: it carries the dedicated key that seals the
identity provider's session refresh token into the gateway's own refresh token (generate one
with `openssl rand -base64 32`). `GATEWAY_SIGNING_KEY` must be a real generated key — the
example's placeholder is refused at startup, because a deployment that never replaced it
would sign tokens with a key published in this repository.

The toolset restriction and the pre-registered client list are JSON documents in
`TOOLSETS` and `PRE_REGISTERED_CLIENTS`:

```bash
# Serve every guard-passing toolset (dynamic mode):
TOOLSETS=
# Or pin an explicit served set (each entry is validated at startup):
TOOLSETS='{"notion":{"scopes_supported":["default"]}}'
PRE_REGISTERED_CLIENTS='{"a-harness":{"redirect_uris":["http://127.0.0.1:8766/callback"]}}'
```

Both are quoted so compose interpolates them as single values. `TOOLSETS` unset means the
gateway serves every platform toolset whose name passes the request-time name guard — a
toolset added to Core is sign-in-able with no reconfigure and no restart, and existence is
decided post-authentication at the flow's settings read. A configured entry that a startup
check refuses — a name outside `[a-z0-9-]+` or a reserved name — fails the container's
start with a message naming it. A restriction entry declares no authentication kind: the
kind a flow acts on is Core's, read per flow. A mapping document still carrying the old
`authentication_type` member is refused at parse, by name.

The **identity-provider federation profile** is the `IDP_*` settings block: the OIDC
provider the gateway federates, its issuer pinned exactly (`IDP_ISSUER`), its client and
its client secret (`IDP_CLIENT_ID`, `IDP_CLIENT_SECRET` — the secret required at startup
in both positions of the leg's PKCE toggle: the gateway's client is a confidential
client), and its scopes — with
the provider's endpoints read from standard OIDC discovery by default, or configured
directly as an all-or-nothing trio (`IDP_AUTHORIZATION_ENDPOINT`, `IDP_TOKEN_ENDPOINT`,
`IDP_JWKS_URI`) for a provider whose discovery document does not serve the fetch's
spelling. The committed example carries the provider-neutral placeholder
(`https://idp.example.com/`); a deployment's real values go in `.env`. An external
provider's configuration sketch is in
[`docs/local-environment.md`](docs/local-environment.md), the full reference in
[`docs/gateway-configuration.md`](docs/gateway-configuration.md).

**[`docs/gateway-configuration.md`](docs/gateway-configuration.md) is the full
reference**: every setting, every startup refusal with its reason, the CIMD fetch's
controls, and the DCR store's corruption recovery and loss semantics.

### Running locally

```bash
PYTHONUTF8=1 .venv/Scripts/python -m gateway
```

`PYTHONUTF8=1` matters on Windows: the console is cp1252 and the local instance's error
bodies are not, so a default run crashes while printing one.

The service binds the container-internal port (`GATEWAY_INTERNAL_PORT`, default 8091)
and answers `GET /healthz`. In a deployment the front router publishes the public origin
and is the gateway's only front door; running the container directly is a development
convenience.

The composed stack (gateway plus router) is:

```bash
wsl -e docker compose up -d
```

Docker runs in WSL2 here, not Docker Desktop, so the command is run through `wsl -e`.
Compose joins the DIAL instance's network as external; the network name comes from
`DIAL_COMPOSE_NETWORK`.

### Deploying beside an instance

The stack is a second compose project beside a running DIAL instance, so the order is:
the instance first, then its two configuration edits, then the gateway's client, then
this repository's stack.

```bash
# 1. The instance (its own folder), then apply its Core configuration —
#    see docs/local-environment.md for the two environment changes.
wsl -e docker compose up -d
wsl -e docker compose up -d --force-recreate core

# 2. The gateway's client in the local realm (this repository). Idempotent: run it again
#    and the second run is a no-op. --verify-claims additionally walks a real flow and
#    reports the claims the client mints. The client is registered against the
#    identity-leg callback, http://localhost:8090/dial/callback/idp — the path the front
#    router routes and the flow builds.
PYTHONUTF8=1 .venv/Scripts/python scripts/provision_keycloak.py --verify-claims

# 3. This repository's stack: the gateway and its front router on the public origin.
wsl -e docker compose up -d
```

The three carry-forward settings that make the gateway's token match what Core's provider
entry verifies — `IDP_CLIENT_SCOPES`, `ROLES_CLAIM_NAME`,
`GATEWAY_OUTBOUND_TIMEOUT_SECONDS` — are named in `docker-compose.yml` with the rest of
the gateway's environment.

Then verify the deployment, in this order — the negative controls run inside each probe,
before its positive claim:

```bash
# Core trusts the gateway's own key, through the gateway's JWKS endpoint.
PYTHONUTF8=1 .venv/Scripts/python scripts/probe_gateway_trust.py

# The front router: routing map, the 401 challenge rewrite, query-string survival.
PYTHONUTF8=1 .venv/Scripts/python scripts/probe_routing.py

# The whole chain end to end: authorize -> provider login -> callback -> token -> a live
# tool call through the front door. Needs GATEWAY_E2E_CLIENT_ID in .env, naming a client
# the gateway resolves whose redirect_uris include http://127.0.0.1:8767/callback.
PYTHONUTF8=1 .venv/Scripts/python scripts/probe_end_to_end.py
```

A gateway container that is recreated gets a new address on the compose network, while
nginx resolves its upstream once at start — so restart the router after recreating the
gateway:

```bash
wsl -e docker compose up -d --force-recreate
```

### Static gates

Run these before considering any change done. The first three are the cheap tier and
should be run on every edit:

```bash
PYTHONUTF8=1 .venv/Scripts/python -m ruff check .
PYTHONUTF8=1 .venv/Scripts/python -m ruff format --check .
PYTHONUTF8=1 .venv/Scripts/python -m mypy
PYTHONUTF8=1 .venv/Scripts/python -m pytest -q
```

`ruff format` (without `--check`) rewrites the files; `ruff check --fix` applies the
autofixes it can. The formatter and the linter are configured in `pyproject.toml`, so
their line width and rule set travel with the repository rather than with whichever
tool version happens to be installed.

The security scanners run on the same tree:

```bash
PYTHONUTF8=1 .venv/Scripts/python -m bandit -c pyproject.toml -r gateway
PYTHONUTF8=1 .venv/Scripts/python -m pip_audit
```

`pip-audit` is **blocking**: a reachable vulnerability, including a transitive one,
blocks the release, and the remedy is a dependency bump rather than a triage note. Trivy
scans the built image and lives in WSL:

```bash
wsl -e trivy image --skip-db-update dial-mcp-gateway:local
```

Use `--skip-db-update` only when the vulnerability-database download fails and the
cached database is recent.

## Outbound references

Authoritative public references: the DIAL Core source and documentation
(https://github.com/epam/ai-dial-core, https://docs.dialx.ai), the MCP specification
(https://modelcontextprotocol.io), and IETF RFCs.
