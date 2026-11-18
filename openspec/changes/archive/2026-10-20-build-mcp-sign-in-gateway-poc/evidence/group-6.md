# Group 6 — deployment configuration and provisioning

Tasks 3.10 and 6.1–6.5 of `build-mcp-sign-in-gateway-poc`. Records what each task landed,
what was run to verify it, the three defects this group found and fixed, and the live
end-to-end result. Every capture below is redacted at capture time: no token, code, key,
password, or client secret appears in this file (`.gitignore` blocks `*.jwt`/`*.pem`/
`*.key`/`.secrets/`, so an unredacted capture would silently fail to commit).

## Verdict

**Group 6 complete.** The gateway's Keycloak client exists and is provisioned by a
committed, idempotent script; this repository's compose names every setting the model
reads, including the three carried forward from group 4; the sibling Core entry now points
at the **gateway's own** JWKS endpoint instead of the spike container, and the spike
container is gone; and the whole chain runs live — a client walked discovery,
`/dial/authorize`, the realm's login, the gateway's callback and `/dial/token` through the
front door, and then made a real tool call with the token it received. `route_only` is
removed and its removal is pinned by tests.

## What each task landed

| Task | Deliverable | Where |
|---|---|---|
| 3.10 | `route_only` removed: the field, `Settings.is_route_only`, the validator's escape branch, and its refusal message; the escape-acceptance test became a refusal test (with and without the field, on a non-OAuth and an OAuth entry); `.env.example` and the `README.md` startup-check sentence aligned | `gateway/settings.py`, `tests/test_settings.py`, `.env.example`, `README.md` |
| 6.1 | The sibling's Core env: `jwksUrl` → `http://mcp-signin-gateway:8091/dial/jwks.json`, `authorizationServers` → `http://localhost:8090`, the gateway's upstream callback appended to `allowedRedirectUris`; `spike-jwks` removed | sibling `docker-compose.yml` (config only; no commit there) |
| 6.2 | `scripts/provision_keycloak.py`: idempotent creation and convergence of the public PKCE client `dial-mcp-proxy`, admin credential from `.env`, plus `--verify-claims` which runs a real flow and reports the minted claims | `scripts/provision_keycloak.py` |
| 6.3 | The `notion` registration re-confirmed live, with the flow's no-access branch (403) measured on the same read | no code; measured |
| 6.4 | `docs/local-environment.md` corrected: the promised script named, Core described as env vars (no `aidial.settings.json`), the toolset settings read aligned to the route the flow uses, the realm registration-policy section marked historical | `docs/local-environment.md` |
| 6.5 | `.env.example` completed for the full deployment (admin placeholders, the smoke's client id, the pre-registered-clients note) and the run instructions added to `README.md`; a provisioning section added to the configuration reference | `.env.example`, `README.md`, `docs/gateway-configuration.md` |

Two new probes landed with the tasks because the deployment fact they check had no
instrument:

| Script | What it proves |
|---|---|
| `scripts/probe_gateway_trust.py` | Core trusts the **gateway's own key**, fetched from the **gateway's JWKS endpoint**: the published `kid` equals the configured key's derived `kid`, while a token signed by an unpublished key is refused 401 (negative control first) and a gateway-signed token resolves a real identity (positive control). |
| `scripts/probe_end_to_end.py` | The whole sign-in, live, through the front door, ending in a real tool call with the token the flow minted. |

## 3.10 — `route_only` removed

The escape is gone: a non-OAuth entry refuses startup unconditionally, and the mapping is
closed to the field, so an operator who sets it learns at startup rather than believing a
setting is in effect. Both branches are pinned:

| Test | Assertion |
|---|---|
| `test_non_oauth_toolset_refuses_startup` | A non-OAuth entry refuses, naming the entry and its type. |
| `test_non_oauth_toolset_refuses_startup_with_an_unknown_escape_field` | The same entry **with** `route_only: true` still refuses, and the message names the unknown field. |
| `test_oauth_toolset_refuses_startup_with_an_unknown_escape_field` | An otherwise-accepted OAuth entry carrying the field is refused too — the field is gone from the model, not ignored. |

Verified live in the built image:

```
route_only in ToolsetMapping fields: False
is_route_only on Settings: False
```

## 6.2 — the provisioning script

`PYTHONUTF8=1 python scripts/provision_keycloak.py`, run three times:

```
admin login -> <redacted len=750 sha256=47907de2ece3>
client 'dial-mcp-proxy' created (id=86a95006-…)
default client scopes: profile, email, basic (the client's whole carried set)
redirect URI:          http://localhost:8090/dial/callback/keycloak
  publicClient                 = true
  standardFlowEnabled          = true
  implicitFlowEnabled          = false
  directAccessGrantsEnabled    = false
  serviceAccountsEnabled       = false
  redirectUris                 = ["http://localhost:8090/dial/callback/keycloak"]
  attributes                   = {"pkce.code.challenge.method": "S256", …}
  mapper 'project claim (the per-user attribution)' -> project (oidc-usermodel-attribute-mapper)
  mapper 'DIAL roles' -> roles (oidc-usermodel-client-role-mapper)

second run was a no-op: the client is already the desired shape
```

Runs 2 and 3 both reported `already matches; nothing changed`, so the operation is
idempotent. The admin credential came from `.env`; nothing hardcoded, and the capture
carries no secret (a public client has none).

### The claims the client mints, measured

`--verify-claims` completes a real authorization-code flow against the client — reading
the realm's own login form's action URL and submitting the test user's `.env`-sourced
credential, with no browser:

```
=== token minted through the provisioned client (no token shown) ===
  access token = <redacted len=1082 sha256=da2932da3468>
  iss       = "https://keycloak:8443/realms/dial"
  sub       = "3a0d60f4-fad0-4164-8903-20e5adf408c3"
  roles     = ["admin"]
  project   = "proj-alpha"
  email     = "dial@example.com"
  scope     = email profile
  refresh   = present
OK: every claim Core's provider entry reads is present and non-empty
```

`scope` carries neither `openid` nor `offline_access`, which is the designed set.

## Defects found, and fixed

### D-11 — the realm's default scopes put `offline_access` on the client

- **Symptom:** the first provisioned client carried `offline_access` as a default scope,
  and the code exchange returned a refresh token for a flow that must never hold one.
- **Evidence:** the admin API's own read of the created client:
  `default-client-scopes ['web-origins', 'acr', 'offline_access', 'roles', 'profile',
  'basic', 'email']` — five scopes the script never attached.
- **Root cause:** a client created through the Admin API inherits the **realm's** default
  scope list, which here includes `offline_access`. The script added the two scopes it
  wanted and left the rest alone, so the client's carried scopes were the realm's set plus
  the script's, not the designed set.
- **Fix:** the script now **converges** the client's default scopes to exactly its set,
  removing the ones the realm attached on its own and reporting each change
  (`+name`/`-name`). `scripts/provision_keycloak.py`; the measured result is the
  `scope = email profile` line above.

### D-12 — the client's default scopes omitted `basic`, so the token had no `sub`

- **Symptom:** with `offline_access` removed, the token obtained through the client had
  `roles`, `project` and `email` — but **no `sub`**. A token without a subject is one Core
  cannot authorize, so the whole chain would have been dead on arrival. The gateway's
  client, as originally specified (default scopes `profile,email`, mirroring the
  `dial-sso-desktop-claude` template), could never mint a usable token.
- **Evidence:** the same `--verify-claims` run reported `sub = null` and refused; a control
  run with the template client `dial-sso-desktop-claude` and the identical flow reproduced
  `sub = None`, which localized the cause to the scope set rather than to this client.
  Adding the realm's `basic` client scope and re-running produced
  `sub = "3a0d60f4-…"`.
- **Root cause:** `sub` is contributed by the realm's `basic` client scope (its `sub`
  mapper), not by `profile` or `email`. The template client's two-scope default set is
  correct *for a client whose subject nobody reads*; here the subject **is** the thing Core
  authorizes with. Following the template literally produced a token shape the deployment
  cannot use.
- **Fix:** `basic` is part of the managed default-scope set. `basic` has
  `include.in.token.scope` off, so it contributes its mapper without appearing in the
  requested scope string — the redirect still asks for `profile email` exactly.
  `scripts/provision_keycloak.py`; pinned by `--verify-claims`, which now requires `sub`,
  `roles` and `project` to be present and non-empty and fails otherwise.

### D-13 — `fullScopeAllowed: false` made the realm refuse the code exchange

- **Symptom:** the exchange answered
  `{"error":"not_allowed","error_description":"Offline tokens not allowed for the user or
  client"}` — an error about offline tokens for a client that requests no offline scope.
- **Evidence:** the client's own configuration at the time (`fullScopeAllowed: false`,
  default scopes `profile,email`) against the same request with the field flipped
  (`true`), which succeeded on the next run with no other change.
- **Root cause:** in this realm, a client with `fullScopeAllowed: false` and no
  `offline_access` scope granted is refused an offline-token request at the exchange — and
  the realm's error names the scope rather than the client setting, which is the misleading
  text `docs/local-environment.md` already recorded from PoC A. The client was written with
  the field off to keep its token narrow.
- **Fix:** `fullScopeAllowed: true`, as the template client has it. It buys nothing here:
  the client's default scopes are `profile`/`email`/`basic` only, so the role-bearing
  `roles` client scope is absent and no extra role collection enters the token either way —
  the same measured `roles = ["admin"]` from the one mapper the script configures.
  `scripts/provision_keycloak.py`, with the reason stated at the field.

## 6.1 — the JWKS repoint, and its evidence

Applied to the sibling instance (config only; nothing committed there):

| Variable | Was | Now |
|---|---|---|
| `aidial.identityProviders.dial-mcp-proxy.jwksUrl` | `http://spike-jwks:8099/jwks.json` | `http://mcp-signin-gateway:8091/dial/jwks.json` |
| `aidial.toolsets.security.authorizationServers` | `https://keycloak:8443/realms/dial` | `http://localhost:8090` |
| `aidial.toolsets.security.allowedRedirectUris` | `["http://localhost:8765/callback"]` | `[…, "http://localhost:8090/dial/callback/upstream"]` |

`scopesSupported` was left unchanged (no `openid` added). Applied with
`wsl -e docker compose up -d --force-recreate core` after
`wsl -e docker stop spike-jwks && wsl -e docker rm spike-jwks`.

### Core reaches the gateway's endpoint

```
$ wsl -e docker exec dial-instance-core-1 sh -c "wget -qO- http://mcp-signin-gateway:8091/dial/jwks.json"
{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"a119a0a9bee68848","n":"mtZZrB5UuIMaK04mjD1SHFlBtFWUJNnT5Yl6Q-…","e":"AQAB"}]}
```

### The trust probe (negative control first)

`PYTHONUTF8=1 python scripts/probe_gateway_trust.py`:

```
=== the published JWKS (through the front door) ===
  GET http://localhost:8090/dial/jwks.json -> keys=["a119a0a9bee68848"]
  derived from GATEWAY_SIGNING_KEY -> kid=a119a0a9bee68848
  verdict: green — the signing key is the published key

=== negative control: a token signed by an unpublished key ===
  token     <redacted len=1170 sha256=632320fbbfb6>  kid=0f338f9739a9116c
  GET /v1/user/info -> HTTP 401
  verdict: red as required — an unpublished signer is refused

=== positive control: a token signed with the gateway's key ===
  token     <redacted len=1170 sha256=242d104ea2c6>  kid=a119a0a9bee68848
  iss       "http://localhost:8090"
  aud       ["http://localhost:8090", "dial-mcp-proxy"]
  sub       "3a0d60f4-fad0-4164-8903-20e5adf408c3"
  GET /v1/user/info -> HTTP 200
  userId    3a0d60f4-fad0-4164-8903-20e5adf408c3
  roles     ["admin"]
```

### The spike's retired key is refused

The Stage 0 spike's own keypair is still on disk; a token signed with it under its old
published `kid` no longer resolves, so the repoint left no trusted predecessor:

```
spike-key token (kid=b12e0ae2e76de03b) -> HTTP 401 Unknown api key
verdict: rejected as required
```

### Regression: a Keycloak token still validates, and Core's PRM names the gateway

```
GET http://localhost:8081/.well-known/oauth-protected-resource/v1/toolset/notion/mcp -> 200
  {"resource":"http://localhost:8081/v1/toolset/notion/mcp","authorization_servers":["http://localhost:8090"],…}

keycloak token GET http://localhost:8081/v1/user/info -> 200
  {"roles":["admin"],"userId":"3a0d60f4-fad0-4164-8903-20e5adf408c3",…}
```

### The routing battery, re-run on the deployed arrangement

The query-string probe mints its own token, and its mint followed the trust anchor: it now
signs with the **gateway's configured key** rather than the spike's generated one, because
Core's provider entry no longer points at the spike. With that, all six probes pass:

```
=== battery verdict ===
  pass      negative control — Core's own challenge
  pass      query string survives the routing
  pass      flat AS metadata through the router
  pass      per-toolset PRM through the router
  pass      data-path 401 rewritten to the gateway's challenge
  pass      gateway paths reachable through the front door

all 6 probes passed
```

Before the mint was repointed, probe 2 failed with "Core's log carried no request line
containing `<marker>`" — the same signature group 5's D-10 recorded. The probe's own note
("an unauthenticated call never reaches the point where Core records the URI") is what
identified it as an authentication failure rather than a routing one, so no route was
changed on that evidence.

## 6.3 — the toolset registration, and the 403 branch

`GET /v1/toolsets/platform/notion` as the test user: `200`, `auth_settings` carrying
`client_id`, `authorization_endpoint`, `redirect_uri`, `code_challenge`,
`code_challenge_method: S256`, `scopes_supported: ["default"]`,
`dynamically_registered: true`, and **no** `code_verifier` and **no** `client_secret`.

The flow's no-access branch was measured on the same read, with a gateway-signed token for
a different realm user and no roles:

| Token | `/v1/toolsets/platform/notion` | `/v1/user/info` |
|---|---|---|
| `dial` (roles `["admin"]`) | 200 | 200 |
| another user's `sub`, `roles: ["admin"]` | 200 | 200 |
| another user's `sub`, `roles: []` | **403 Forbidden** | 200 |

The 403 (not 404) is what the flow's no-access branch keys on, and it is the status the
read produces for an authenticated user without the toolset's read access.

## The live end-to-end sign-in (the deployment check)

`PYTHONUTF8=1 python scripts/probe_end_to_end.py`, against the composed stack:

```
=== step 1: discovery through the front door ===
  resource  http://localhost:8090/dial/notion/mcp
  servers   ["http://localhost:8090"]
=== step 2: /dial/authorize through the front door ===
  status    302 -> keycloak:8443
  client    dial-mcp-proxy
  scope     profile email
=== step 3: the identity provider's login form ===
  credentials submitted -> HTTP 302
  hop 2: HTTP 302
  hop 3: reached the client redirect URI
=== step 4: the gateway's callback ===
  params    ['code', 'iss', 'state']
  state     round-tripped
  code      <redacted len=1206 sha256=4f5e7bb7bcde>
=== step 5: /dial/token ===
  status    200
  access    <redacted len=977 sha256=6f0138efb46e>
    iss      "http://localhost:8090"
    sub      "3a0d60f4-fad0-4164-8903-20e5adf408c3"
    aud      ["http://localhost:8090/dial/notion/mcp", "dial-mcp-proxy"]
    roles    ["admin"]
    project  "proj-alpha"
  refresh   present
=== step 6: a live tool call through the front door (/dial/notion/mcp) ===
  status    200
  tools     65
  first     ["notion-search", "notion-memory-search", "notion-get-tool-access"]
```

The probe drives the realm's login form itself — reading the form's action URL out of the
rendered page and replaying the session cookies, accumulating every `Set-Cookie` rather
than the last one — which is what keeps the whole smoke browser-free and repeatable. A
failure to accumulate the cookies reads as an expired session rather than as a missing
cookie; the probe's first version had exactly that bug, and it is fixed rather than worked
around because the next person to run it would hit the same wall.

This is **not** PoC C: group 9 runs the five acceptance criteria on a real harness (CIMD
registration, silent repeat use, mid-session credential removal, query-string survival,
coexistence). What this proves is the deployment fact group 6 owns — the provisioned
client, the repointed JWKS, the composed stack, and the routing — with the chain's own
steps rather than a harness driving them.

## Composition checks

| Check | Result |
|---|---|
| `wsl -e docker compose config` | parses |
| `wsl -e docker compose up -d --build` | gateway built; both services started |
| `mcp-signin-gateway` health | `healthy` |
| `mcp-signin-router` health | `healthy` |
| `GET /healthz` through the router (port 8090) | `200 {"status":"ok"}` |
| `GET /healthz` in the gateway container (8091) | `{"status":"ok"}` |
| Every settings-model field named in `docker-compose.yml` | yes — 43 of 43, checked mechanically |
| `spike-jwks` container | removed |

**One operational fact worth recording.** Recreating the gateway gives it a new address on
the compose network, while nginx resolves its upstream once at start — so the router
answers 502 until it is restarted too. Measured here (a `/healthz` 502 immediately after a
gateway-only recreate, cleared by restarting the router) and documented in the repository
`README.md`, because the failure looks like a broken gateway and is not one.

## Gates

Run from `.venv/Scripts` with `PYTHONUTF8=1`.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 90 files already formatted |
| `mypy` (strict) | Success: no issues found in 35 source files |
| `pytest -q` | **321 passed, 1 skipped** |
| `bandit -c pyproject.toml -r gateway` | No issues identified |
| `pip-audit` | No known vulnerabilities found |
| `wsl -e docker compose config` | parses |
| compose-boot health probes | both services `healthy`; `/healthz` 200 through the router |
| `probe_gateway_trust.py` | negative control refused, positive control green |
| `probe_routing.py` | all 6 probes passed |
| `probe_end_to_end.py` | live tool call succeeded |

The skipped test is the same Windows one groups 3–5 recorded: POSIX permission bits are
not implemented there, so the DCR store's owner-only mode is asserted in the Linux
container where it is enforced.

The one new test count over group 5 is `test_oauth_toolset_refuses_startup_with_an_unknown_escape_field`;
the escape-acceptance test became a refusal test rather than being deleted, so the behavior
is pinned on both entry kinds.

### Trivy on the built image

156 findings, all in the Debian 13.7 **base image's** own packages: 17 HIGH, 24 MEDIUM, 28
LOW, 2 UNKNOWN, across 87 OS packages (`util-linux`/`bsdutils`, `ncurses`, `systemd`,
`perl-base`, `libc6`, `zlib1g`, …). **Every one has no fixed version available**, so the
remedy the repository rule names — a dependency bump — does not exist for any of them yet.
The Python package layer reports zero. None is introduced by this group's change, which
touches gateway configuration validation, documentation, and probe scripts. Triage remains
group 7's task (its checklist names the same gate); recorded here so the number and its
composition are not re-derived from a fresh scan.

### Bandit on `scripts/`

The gate's scope is `gateway`. Run over `scripts/` as a check, bandit reports five
low/medium-confidence findings, all pre-existing in files this group did not introduce its
findings in: `subprocess` use in `probe_routing.py` (a fixed `wsl -e docker` argv, no shell)
and `urlopen` scheme auditing in `spike_env.py`/`probe_routing.py` (configured local
endpoints). The three new scripts add none.

## Deliberate limits of this group

- **The live flow used a pre-registered client** (`GATEWAY_E2E_CLIENT_ID` in `.env`,
  registered in `PRE_REGISTERED_CLIENTS` with the probe's loopback callback). The CIMD path
  is exercised by unit tests and is criterion (a) of group 9, which runs it against a real
  harness.
- **The harness-facing measurements are group 9's.** This group measured flow-shaped calls
  (`tools/list`), not a harness's own discovery/refresh behavior.
- **The sibling instance is configured, never committed.** Its git status still shows the
  pre-existing dirty state (modified `docker-compose.yml`, `keycloak/import/realm-config.json`,
  `adapter/nginx.conf`, and untracked scratch). This group's edits are in the tracked
  `docker-compose.yml` and were left uncommitted there, per the repository rule.

## Design ripple (authoring pass, 2026-10-19)

D-12 (and D-11's leakage) are design-level corrections, not implementation details, so
the background design's letter is superseded where it still named the client's scope set
as `profile,email` — the set cloned from the `dial-sso-desktop-claude` template, which
mints a token with **no `sub`** on this realm and would have been dead on arrival. What
changed, where:

- **`design.md` context** — the realm-facts bullet now lists `basic` among the realm's
  client scopes and states the provenance: the token's `sub` is minted by the realm's
  `basic` client scope (its `sub` mapper), not by `profile` or `email`, and `basic` never
  appears in the requested scope string. The template client is named as correct only
  for a client whose subject nobody reads; this deployment's Core authorizes on the
  subject, so the managed set differs (D9).
- **`design.md` D9** — the managed default-scope set is now `profile,email,basic`
  (never `openid`, never `offline_access`), with the reason stated: `basic` is what
  mints `sub` into the access token, so without it the identity the whole copied-`sub`
  scheme depends on does not exist in the token. D9 now also states the **convergence
  behavior as designed provisioning**: the script converges the client's default scopes
  to exactly the managed set, removing the realm's own default-scope leakage
  (`web-origins`, `acr`, `offline_access`, the role-bearing `roles`) — an Admin-API
  client inherits the realm's list, so attach-only leaves the realm's set plus the
  script's, not the designed set. And D9 states the claims verification
  (`--verify-claims`) as designed behavior: the provisioned client must mint a present,
  non-empty `sub`, `roles` and `project` through a real flow, or provisioning fails
  loudly — a deployment error caught before any user flow.
- **`design.md` D10** — the redirect's requested scope string is restated against the
  managed set: the client's default scopes are `profile,email,basic`, of which only
  `profile email` appears in the requested scope string, because `basic` contributes
  its `sub` mapper without entering it.

**Spec-ripple ruling: none — the delta spec is unchanged, deliberately.** Reasons:

1. No spec requirement or scenario names the client's scope set. The federation-flow
   requirement says "requesting only its client's default scopes" and its scenario says
   "the gateway client's default scopes" — deployment-agnostic wording, exactly right,
   because the set is realm configuration that varies by deployment. Pinning
   `profile,email,basic` there would freeze one local realm's scope names into a
   capability spec.
2. The token's identity-claim presence **is already normative**: the issued-tokens
   requirement states the minted token's `sub` is copied from the identity token of the
   live-authenticated user, and the code-exchange scenario pins "carrying the user's
   `sub`". What D-12 exposed is a *deployment*-configuration failure (a mis-scoped
   realm client), not a gateway behavior gap.
3. The author's sub-presence verification is ruled **not normative in the spec**, for
   altitude reasons. The provisioning script and its `--verify-claims` check are
   deployment tooling — outside the capability spec's boundary (the spec governs the
   gateway's client-facing behavior) — and are instead stated as designed behavior in
   D9, where deployment provisioning lives.
   **Correction (review of this ripple):** the original draft of this reason rejected
   the issuance-time refusal with two claims that are both false — (a) that a missing
   `sub` is caught once at provisioning before any user flow, and (b) that making it
   normative would put the spec ahead of the implementation. In fact the gateway
   **already refuses per-flow, loudly**: `gateway/idp.py` raises an identity-provider
   error ("the identity token carries no subject") at the exchange leg, before any
   gateway token is minted — a mis-scoped deployment fails at every user flow, and no
   sub-less gateway token can ever be minted. D-12 itself shows the failure class is
   *correct IdP output from a mis-scoped client* — the same deployment-configuration
   class as the roles path, not a one-time-provisioning class. And a normative
   scenario would document existing behavior, not require a source change. The
   no-ripple conclusion therefore stands on reasons 1 and 2 alone (nothing pins a
   scope set; sub-presence is already normative via the issued-tokens requirement and
   the code-exchange scenario's "carrying the user's `sub`"); reason 3 is altitude
   only — whether to also pin the per-flow refusal with its own scenario is a
   formatting choice for the author, not a gap: the defense-in-depth (provisioning
   check + per-flow refusal) exists and is disclosed here and in `gateway/idp.py`'s
   docstring.

`openspec validate --changes --strict` passes after the edits.
