# PoC: driving DIAL MCP-toolset sign-in from an external harness

> **Historical evidence — read as a record, not as guidance.**
>
> This document records what was measured at the time. It is **not** current guidance,
> and parts of it describe approaches that were **later retracted** — notably PoC A's
> discussion of using a DIAL API key for the sign-in call, which was rejected; the
> credential used is a user's DIAL token, obtained through the harness.
>
> The authoritative documents are [`design.md`](design.md) (the converged, reviewed
> design), [`problem-statement.md`](problem-statement.md) (the requirements and the
> findings, F-1…F-8), and [`decisions/`](decisions/) (decision records). Read this file
> for the underlying measurements and how they were obtained — not for the design.

Status: **PoC A proven locally** (Notion upstream). PoC B (LiteLLM) not yet run.
Environment: `dial-instance` (Core `deps-v2`, Keycloak 26.7.2), artifacts in <local-instance>/.mcp-poc/

> **Where the artefacts live.** The probe scripts referenced below (`<local-instance>/.mcp-poc/*.py`)
> are the local PoC rig for the `dial-instance` development instance and
> are **not** part of this repository. The sign-in skill itself *is* shipped here,
> at [`gateway/`](../gateway/) -- `skill/signin.py` plus the runbook `skill/SKILL.md`.

## 1. The problem

DIAL MCP toolsets proxy a remote MCP server and hold its upstream credentials. Today the
upstream sign-in is performed **from DIAL Chat**: a human clicks through the upstream IdP
there, DIAL stores the token, and later MCP calls get it attached automatically.

Users' complaint is narrow: they must go to Chat at all. The goal is to let the harness
they are already in (Claude Code, Codex, Copilot) trigger that sign-in itself, so first use
costs one browser consent from where the user already is, and later use is silent.

## 2. Shape of the fix: two legs, two different jobs

```
  Leg 1  (NEW)                      Leg 2  (existing)
  harness ──▶ DIAL ──▶ upstream MCP      harness ──▶ DIAL's MCP endpoint
  exchange the upstream code             ordinary MCP-over-OAuth
```

| Leg | Between | Mechanism | Core feature that carries it |
|---|---|---|---|
| 1 | DIAL → upstream MCP | Toolset `auth_settings: OAUTH`; Core holds the PKCE verifier, exchanges the code, stores the token per user | `POST /v1/ops/toolset/signin` |
| 2 | harness → DIAL | Core is an OAuth2 **Resource Server**; Keycloak is the advertised AS; a Keycloak JWT *is* a DIAL JWT | RFC 9728 metadata + `WWW-Authenticate` |

**Both are existing Core features, switched off by configuration.** No Core change was
needed. The operator-visible switches:

```yaml
aidial.toolsets.security.resourceHost: localhost:8081          # builds the resource id
aidial.toolsets.security.resourceSchema: http
aidial.toolsets.security.authorizationServers: https://keycloak:8443/realms/dial
aidial.toolsets.security.scopesSupported: '["openid","offline_access"]'
aidial.toolsets.security.allowedRedirectUris: '["http://localhost:8765/callback"]'
```

`authorizationServers` is the gate: while it is unset, `WellKnownResourceMetadataService`
disables itself, the metadata endpoint 404s, and no `WWW-Authenticate` is emitted — so no
MCP client even offers to authenticate.

### The invariant this work preserves

DIAL's MCP toolset is a **credential-holding proxy**, not a byte forwarder. That single
decision explains the rest of the design:

> The upstream credential lives in Core, scoped per user. The client holds only a DIAL
> token.

Every existing path preserves it. Today upstream credentials arrive one of two ways:
pre-signed-in through Chat, or an app that hit a 401 asking Chat — over the client
channel — to surface a sign-in button to the human. In both, Core ends up holding the
upstream token and the client never does.

Two facts from Core show this is deliberate, not incidental:

```java
// Deployment.java: forwardAuthToken defaults to FALSE
// McpProxyController.handleProxyRequest:
if (!deployment.isForwardAuthToken()) {
    excludeHeaders.add(HttpHeaders.AUTHORIZATION, "whatever");   // client token stripped
}
```

So Core actively removes the caller's `Authorization` before calling upstream unless an
operator opts in. DIAL is choosing *"the client does not hold the upstream token."*

**What this work adds is the transport, not the invariant.** The harness performs the
consent and hands Core the **authorization code**; Core still mints and stores the
upstream token (`POST /v1/ops/toolset/signin`). Nothing upstream-credential-shaped
reaches the client. The novelty is that a chat-less client can now establish the upstream
credential at all — previously that required Chat.

### Why this cannot be done by a "standard MCP client"

This is the argument for why the flow must call a DIAL-private endpoint rather than follow
the MCP authorization spec end to end.

1. `/v1/ops/toolset/signin` is a DIAL-private operation. It takes an authorization `code`
   plus a DIAL user JWT. No spec-following MCP client discovers or invokes it.
2. The PKCE `code_verifier` is generated server-side and deliberately never exposed
   (`ResourceAuthSettingsData` omits it), so **no client can exchange the code itself** —
   only Core can.
3. The standard MCP authorization flow terminates with the client holding the **upstream**
   access token. That is the model the spec assumes, and much of it — audience binding,
   the confused-deputy rules, the explicit prohibition on **Token Passthrough** — exists
   precisely because the client ends up holding a token for a resource it is not the
   audience of.

For a proxy like DIAL, (3) is not merely unnecessary, it is undesirable: it would leave
the client holding two live credentials — DIAL's and the upstream's — and put a token in
the client that a DIAL token already adequately gates. DIAL has removed the legitimate
job that requirement existed to serve.

The symmetry with the industry is worth noting: **OAuth token exchange (RFC 8693)** —
LiteLLM calls the same shape `oauth_delegate` — is the established way to express
"the client authenticates to me, and I hold the credential for the downstream service."
The MCP spec had not standardised that as a first-class flow at the time of writing, so
DIAL implements it as a private API. That is a real cost — a per-DIAL integration like
`signin.py` — and it is a deliberate trade against the token never leaving Core.

**Summary of the trade:**

| | Standard MCP OAuth | DIAL's model |
|---|---|---|
| Where the upstream token lives | the client | Core, per user |
| Client integration | generic, spec-driven | DIAL-specific (`signin.py`, or Chat) |
| Client holds how many credentials | 2 (its own + upstream) | 1 (DIAL only) |
| Token passthrough | client-held, spec forbids passing it on | not applicable — never leaves Core |
| Per-user isolation | client's responsibility | Core's, verified in §3 |

### The identity rule (the part that silently breaks)

`/v1/ops/toolset/signin` stamps the stored token with the caller JWT's `sub`
(`SecuredResourceService.signIn` → `ProxyContext.getInitiatorId()`). Core later honours
that record only for the same `sub` (`ResourceCredentialsService`). So Leg 1 must be
authenticated with a **DIAL/Keycloak user JWT for the same user who will call the
toolset** — not a DIAL API key. An API key has no `sub`; the record would be stamped with
the key's project and never match, producing a permanent "not signed in".

Verified: the identity is **client-independent** — tokens minted by different Keycloak
clients for one user share the same `sub` (`dial-chat` and `dial-cli` both yielded
`3a0d60f4-…`). Leg 1 and Leg 2 need not use the same client.

## 3. What was proven (PoC A)

Recorded end-to-end against a real Notion workspace.

**Metadata and challenge** — before the config change both were absent, which is the
baseline that shows the config is what enables them:

```
before:  GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp -> 404
         POST /v1/toolset/notion/mcp (no auth) -> 401, NO WWW-Authenticate
after:   -> 200 {"resource":"http://localhost:8081/v1/toolset/notion/mcp",
                 "authorization_servers":["https://keycloak:8443/realms/dial"], ...}
         -> 401 + WWW-Authenticate: Bearer resource_metadata="http://localhost:8081/…"
```

**Dynamic client registration against Notion.** `PUT /v1/toolsets/platform/notion` with
only `authentication_type: OAUTH` + `redirect_uri` made Core discover Notion's PRM/AS
metadata and register itself:

```json
"auth_settings": { "client_id": "Ohk3BbaVnj3lemIy",
                   "authorization_endpoint": "https://mcp.notion.com/authorize",
                   "scopes_supported": ["default"],
                   "dynamically_registered": true,
                   "user_level_auth_status": "SIGNED_OUT" }
```

Note for implementers: in dynamic-registration mode `redirect_uri` is the **only**
permitted `auth_settings` field. `OauthAuthSettingsValidator` forbids `client_id`,
`client_secret`, `authorization_endpoint`, `token_endpoint` and `scopes_supported` —
Core discovers them. Declaring them returns
`400 Field 'TOKEN_ENDPOINT' is forbidden for OAUTH authentication.`

**Sign-in and live data.** The helper built the upstream `/authorize` URL from the
toolset's *public* settings, caught the loopback callback, and handed the code to Core:

```
POST /v1/ops/toolset/signin -> 200 true
status now: user_level=SIGNED_IN global=SIGNED_OUT
GET tools -> 200 {"tools":[{"name":"notion-search", ...
```

Then through Core's MCP proxy, authenticated with the DIAL JWT:

```
initialize  -> Notion MCP 1.2.0, protocol 2025-06-18
tools/list  -> 57 tools
tools/call notion-search -> live workspace data
```

**Per-user isolation** (the assertion that guards the identity rule — what an
API-key-authenticated sign-in would fail):

```
user 'dial'  sub=3a0d60f4-…  user_level=SIGNED_IN   -> 57 tools
user 'user'  sub=d82a91b9-…  user_level=SIGNED_OUT  -> no access
```

**Silent re-run** — a second run of the helper prints `already SIGNED_IN` and opens no
browser. That is the UX win: the complaint is about a *repeated* manual step.

## 4. Findings worth carrying forward

### 4.1 A chat-less client has no way to learn it must sign in upstream

When the caller is authenticated to DIAL but has **no stored upstream credential**, Core
injects no header and relays Notion's response verbatim, including Notion's
`WWW-Authenticate`:

```
no Authorization header    -> 401 + resource_metadata="http://localhost:8081/…"   (DIAL's)
valid JWT, no stored creds -> 401 + resource_metadata="https://mcp.notion.com/…"  (Notion's)
```

This is **consistent with the design, not a defect in it.** DIAL's designed answer to
"no upstream credential" is to surface it to the human through Chat:

| Caller | Designed behaviour when the upstream credential is missing |
|---|---|
| DIAL Chat | asks for `user_level_auth_status` up front and renders a sign-in button |
| A DIAL app | is not a full MCP authN client; it holds a per-request key, calls the toolset, and on 401 sends `toolset/signin` to Chat over the client channel — Chat owns the human interaction |
| An external MCP client | **no designed channel at all** |

The third row is the gap. A raw MCP client has no Chat to escalate to, so it receives a
challenge pointing at the *upstream* authorization server — which it can never satisfy,
because only Core holds the PKCE verifier. It will either loop against the wrong IdP or
fail confusingly. The relayed upstream 401 is therefore the design working as designed
for an audience it was not designed for; what is missing is a way to tell a chat-less
client *"sign in upstream first, and here is where."*

**This is why `signin.py` is necessary rather than a convenience** — it is the missing
channel, implemented client-side. Given the framing in §2, that is the correct place for
it in the short term: extending RFC 9728 is not something a PoC can do unilaterally.

**What a Core-side fix could look like** (a follow-up, not done here):

- Recognise "no credential stored" as distinct from "upstream rejected us", and answer the
  former with **DIAL's own** challenge or a sign-in hint rather than relaying the
  upstream's.
- Advertise *what kind of sign-in* the toolset needs and where to start it. RFC 9728 has no
  field for this — `authorization_servers` names token *issuers*, and the standard flow
  would end with the client holding the upstream token, which §2 explains DIAL deliberately
  avoids. A client also cannot infer from metadata whether the toolset wants an OAuth code
  or an `API_KEY` paste. So this needs an additive **capability descriptor**, not a change
  to the sign-in API.

Note that this is explicitly *not* an argument for replacing `/v1/ops/toolset/signin` with
a hosted authorization-code endpoint — see §8.2.1 for why that would be regressive.

Either way the gap is about **discovery**, and `signin.py` is the client-side stopgap for
it until Core advertises the capability.

### 4.2 Upstream bot protection can look like an auth failure

`mcp.notion.com` is fronted by Cloudflare, which bans some client User-Agents outright
(`error 1010`), and **Core relays the caller's User-Agent upstream**. Measured through
Core's proxy:

```
User-Agent: Python-urllib/3.13  -> 403  (Cloudflare 1010)
User-Agent: dial-mcp-poc/1.0    -> 200
User-Agent: curl/8.5.0          -> 200
```

A probe using a default library UA gets a 403 that looks exactly like an auth bug. The
helpers always send an explicit User-Agent. Bursts also trigger it — space out probes.

### 4.3 Node does not read the Windows trust store

Keycloak's dev certificate is self-signed (`keycloak/certs/keycloak.crt`, `CN=keycloak`).
Python accepts it on this machine; **Node does not**:

```
python + STRICT TLS -> 200
node   + STRICT TLS -> ERROR DEPTH_ZERO_SELF_SIGNED_CERT
node   + NODE_EXTRA_CA_CERTS=keycloak.crt -> 200
```

Since Claude Code is Node, Leg 2 fails on the AS metadata fetch unless
`NODE_EXTRA_CA_CERTS` points at that certificate. The correct fix is to trust the cert,
never to disable verification.

### 4.4 Keycloak DCR works, but four policies must be cleared first

The realm publishes a `registration_endpoint`, and harness-side DCR **does work** — but
four separate client-registration policies each produce a *different* misleading error.
This is the single most time-consuming part of the PoC, so it is worth recording precisely.
Each was isolated empirically, not inferred:

| Policy | Forced state | Symptom |
|---|---|---|
| `trusted-hosts` | rejects unlisted callers | `"Host not trusted"` / `"URI doesn't match"` |
| `allowed-client-templates` | rejects non-default scopes | `"Not permitted to use specified clientScope"` |
| `consent-required` | `consentRequired=true` | `"Client requires user consent"` |
| `scope` ("Full Scope Disabled") | `fullScopeAllowed=false` | **`"Offline tokens not allowed for the user or client"`** |

Four findings that cost real time and generalise beyond this PoC:

1. **`trusted-hosts` needs two different things**, and the second is easy to miss: (a) the
   address the AS sees the request coming *from*, and (b) the host of the client's
   `redirect_uri`. Behind Docker the caller address is the bridge **gateway** —
   `172.19.0.1` here — **not** `127.0.0.1`. With only the gateway listed the error becomes
   `"URI doesn't match"`. Keycloak also refuses to disable both Trusted Hosts sub-checks
   at once: *"At least one of hosts verification or client URIs validation must be
   enabled"*. A sibling keycloak realm-configuration repo (`<internal-realm-config>`) uses
   the same shape for production, listing its trusted network egress points and its
   cluster ingress address as trusted hosts, with `client-uris-must-match: "false"`.
2. **`openid` is not a Keycloak client scope.** Core echoes
   `toolsets.security.scopesSupported` verbatim into the MCP client's registration
   request — PRM `scopes_supported` is not a hint, it *is* the registration payload — so
   advertising `openid` fails the entire registration with an opaque scope error. This was
   a bug in our own Phase 0 config (`["openid","offline_access"]`), fixed to
   `["profile","email","offline_access"]`. **Every advertised scope must exist as a client
   scope on the realm.**
3. **`fullScopeAllowed=false` blocks offline tokens**, and it fires even when the
   requested scope is only `openid` — so it looks like a scope problem and is not. The dev
   repo reached the same conclusion and documents the remedy as a comment:
   `#manually remove "Full Scope Disabled" policy for anonymous clients registrations`.
   We do it programmatically in `<local-instance>/.mcp-poc/kc_enable_dcr.py`.
4. **The harness caches its client registration.** Fixing the realm does **not** repair an
   already-registered client — the harness keeps reusing it and keeps failing with the old
   error. `claude mcp remove <name>` (which clears stored credentials *and* the
   registration) then re-add is required. This is why a fixed realm can still appear
   broken.

A correct DCR client now comes out as `consentRequired=false`, `fullScopeAllowed=true`,
with `offline_access` among its **default** client scopes.

Documented fallback if registration still cannot be made to work: pre-register a public
PKCE client with loopback redirects and pass `--client-id` with a fixed `--callback-port`
— the MCP spec lists pre-registration as the first-choice mechanism anyway. Worth noting
in comparison that LiteLLM ships a `dcr_bridge` flag precisely because OAuth-only clients
(Claude Code, Cursor, Claude Desktop) hit this class of problem.

The local realm also contains `dial-sso-cli-claude-code` and `dial-sso-desktop-claude` —
public, PKCE S256, wildcard loopback redirects, correctly refusing password grants. Avoid
`dial-cli` for real use: it pins `access.token.lifespan: 60`.

### 4.5 Two smaller traps found while building the demo

**`GET /v1/toolset/{id}/tools` is an admin endpoint, not the MCP path.** It returns
`403 "Only admin is allowed to view all tools for static toolsets"` for an ordinary user
token. A verification step using it reports failure *after a successful sign-in*, which is
actively misleading. The correct check is `POST /v1/toolset/{id}/mcp` with
`tools/list` — what the harness itself calls.

**The first upstream call after a sign-in is slow.** Measured through Core: the first
`initialize` exceeded 60s once, then settled at 0.6–0.9s for every subsequent call. A
harness health probe with a short timeout (Claude Code allows 5s) will therefore report
`Failed to connect — Version negotiation probe timed out` even though the toolset is
correctly signed in. Warm the connection before relying on it; re-running the health check
once the upstream session exists clears the false negative.

## 5. The end-user scenario (validated end to end)

This is the flow a real user performs. It was **run and verified** on Claude Code, not
reasoned about — see §6 for exactly what that means.

```bash
# 1. register DIAL's toolset as an MCP server  (no DIAL key, no config edits)
claude mcp add --transport http notion-poc http://localhost:8081/v1/toolset/notion/mcp

# 2. Leg 2 -- authenticate to DIAL.  Claude Code self-registers with Keycloak (DCR),
#    runs PKCE, and stores a DIAL token.  Normally silent: an existing Keycloak SSO
#    session means no prompt at all.
claude mcp login notion-poc

# 3. Leg 1 -- the upstream sign-in, which previously required opening DIAL Chat.
#    ONE browser approval (the upstream consent); the code goes to Core.
python signin.py --toolset notion

# 4. invoke a Notion tool from the harness -> live workspace data
```

Observed result: `user_level=SIGNED_IN`, **57 tools** via `/v1/toolset/notion/mcp`, and
`claude mcp list` reporting `✔ Connected`.

**Two browser interactions total — one per leg, each a distinct consent:** the user's DIAL
identity, then the upstream grant.

### 5.1 The harness's DIAL token is reused — do not authenticate twice

An important simplification found while building the demo. `/v1/ops/toolset/signin` needs
a DIAL user JWT, and it is tempting to run a second Keycloak flow inside the helper to get
one. **That is redundant work.** Leg 2 already obtained exactly that token and the harness
stored it:

```
~/.claude/.credentials.json → mcpOAuth["notion-poc|…"]
  issuer = https://keycloak:8443/realms/dial
  sub    = 3a0d60f4-fad0-4164-8903-20e5adf408c3   ← byte-identical to the JWT used in §3
  scope  = offline_access email profile
```

Same user identity, different route. `signin.py` now resolves the token in this order:
explicit `--jwt` → **harness credential store** → cached token → fresh Keycloak flow. The
last entry keeps the helper harness-agnostic (Codex/Copilot have no such store); the
harness-store step is the Claude-Code optimisation and removes a whole consent round-trip.

This also makes the architecture cleaner to describe: **one identity, established once at
the harness and reused for both legs**, rather than the same human authenticating twice.

### 5.2 Reuse from other harnesses

Leg 1 is identical everywhere (`signin.py`, stdlib only, public DIAL APIs); only Leg 2
varies.

| Harness | Leg 2 mechanism | Limits |
|---|---|---|
| Claude Code | `claude mcp add --transport http <n> {core}/v1/toolset/<id>/mcp`, then `claude mcp login <n>`; RFC 9728 → 8414 → DCR → PKCE | **Validated.** Needs an interactive TTY — headless `claude -p` / Agent SDK cannot run OAuth, so sign in first. Needs `NODE_EXTRA_CA_CERTS` for a self-signed AS cert. Only harness whose stored token the helper reuses directly. |
| Claude Desktop | Same discovery chain via `mcpServers` config | No CLI login equivalent; driven from the app UI. |
| Cursor | MCP config + built-in callback | Its callback URI must be in `allowedRedirectUris`. |
| VS Code / Copilot | Harness MCP config | If only static headers are supported, pass a JWT with `-H "Authorization: Bearer …"`. Works, but cannot refresh and expires with the token lifespan. |
| Custom agent | Call `/v1/toolset/<id>/mcp` directly | Keep `signin.py` for Leg 1; falls through to the Keycloak flow for the token. |

**Validated for: Claude Code only.** The other rows are expected, not tested — do not
present them as proven.

## 6. What was NOT proven

- **The other harnesses in §5.2.** Only Claude Code was exercised. Claude Desktop, Cursor,
  VS Code/Copilot and custom agents are expected-not-tested.
- **PoC B (LiteLLM).** Covered separately in `mcp-toolset-signin-poc-b.md`.
- **`--level GLOBAL` from a harness token.** A DCR-registered harness client carries no
  `roles` claim, and GLOBAL sign-in requires admin, so this needs a role mapper on the DCR
  client. USER level is what was validated.
- **Zero-interaction first use.** Consent is interactive by definition, so first use costs
  one human approval. Removing even that would require the upstream to support
  non-interactive authorization (device authorization, or a service credential), not
  client-side cleverness. Note this is about the *upstream* leg only — it does not imply a
  change to Core's sign-in API (§8.2.1).
- **Production posture.** This environment uses an HTTP resource identifier, a
  self-signed Keycloak certificate, and `disableJwtVerification` neighbours. None of that
  should be carried forward.

## 7. Reproducing

```bash
# 0. add the toolsets.security.* keys to the core service, then:
wsl -e docker compose up -d --force-recreate core

# 1. verify metadata + challenge flipped from 404/bare-401 to 200/challenge
python <local-instance>/.mcp-poc/leg2_discovery.py

# 2. create the toolset (must be PUT: DCR runs only on creation, not from config.json)
python <local-instance>/.mcp-poc/create_toolset.py

# 3. enable Keycloak DCR so the harness can register itself (see 4.4).
#    Clears the trusted-hosts and Full-Scope-Disabled/Consent policies; idempotent.
python <local-instance>/.mcp-poc/kc_enable_dcr.py

# 4. Leg 1: sign in to the upstream -- opens ONE browser consent.
#    No --jwt-file: the token is reused from the harness store (see 5.1).
python skill/signin.py --toolset notion     # source: skill/signin.py in this folder

# 5. prove live data flows through the proxy
python <local-instance>/.mcp-poc/e2e_leg1.py

# 6. prove per-user isolation
python <local-instance>/.mcp-poc/user_isolation_check.py
```

Helpers in `<local-instance>/.mcp-poc/`: `kc_probe.py`, `kc_clients.py`, `kc_enable_dcr.py`,
`core_jwt_check.py`, `create_toolset.py`, `signin.py`, `mcp_probe.py`, `e2e_leg1.py`,
`leg2_discovery.py`, `leg2_keycloak_probe.py`, `user_isolation_check.py`,
`identity_check.py`.

**Demo checklist** (things that produce misleading failures if not done):

- **Warm the connection first.** The first upstream call after a sign-in can exceed the
  harness's 5s health-probe timeout (§4.5), reporting a false "Failed to connect".
- **If the toolset is `SIGNED_OUT`, step 4 is required before invoking any tool**, or the
  call returns the upstream's 401.
- **Verifying with `/v1/toolset/{id}/tools` gives a misleading 403** — that is the admin
  listing endpoint; use the MCP path (§4.5).
- **After changing Keycloak registration policies, `claude mcp remove` then re-add** —
  the harness caches its client registration (§4.4).

## 8. Is DIAL's design right — and is it overcomplicated?

The question this PoC exists to answer. Stated as a thesis, then measured.

### 8.1 The thesis

> The standard MCP-client model does not properly support the **MCP proxy** approach,
> unless the proxy is a shallow byte forwarder — which Core is not.

This holds, and §2 gives the mechanism: the standard flow's terminal state is the client
holding the upstream token, which is precisely what a credential-holding proxy must avoid.
A "shallow forwarder" would pass the client's token through and have no opinion about
credentials at all. Core has an opinion: it holds them, per user, and strips the client's
`Authorization` by default.

So the two designs are not competing implementations of one thing; they are answers to
different questions.

| | Shallow MCP proxy | DIAL toolset | LiteLLM gateway |
|---|---|---|---|
| Held state | none | credentials per user | credentials per user, keyed by `user_id` |
| Upstream token held by | the client | Core | LiteLLM |
| Client needs per-service integration | no | yes (Chat, or `signin.py`) | depends on `auth_type` |

LiteLLM is the strongest counter-example to "standard clients can't do proxies", and it is
worth being precise about why: **it does not rely on the standard client flow either.**
Its closest analogue to DIAL's model is `oauth_delegate` / `true_passthrough` — token
exchange and passthrough, not RFC-authorization-code-terminating-at-the-client. Its
`dcr_bridge` flag exists specifically so OAuth-only clients can be admitted. That is the
same "the standard client can't express this, so the gateway bridges it" move DIAL makes
with `/v1/ops/toolset/signin`. Two implementations, one conclusion.

### 8.2 Is DIAL's design overcomplicated?

Honest split — some of it is inherent, some of it is not.

**Inherent (the proxy model requires it):**

- Holding the upstream token server-side, per user, with refresh. Nothing simpler achieves
  the isolation property verified in §3.
- A private sign-in op taking a `code` + DIAL JWT. Given the verifier must stay in Core,
  *some* Core-mediated exchange is unavoidable.
- DIAL acting as an OAuth2 Resource Server for its own endpoint (Leg 2) — the client must
  authenticate to DIAL somehow, and reusing the existing IdP is the cheap option.

**Genuinely more complex than necessary — the real criticism:**

1. **No standard discovery affordance for the non-code flows.** `/v1/ops/toolset/signin`
   is deliberately unified across credential types, and that is right — see 8.2.1. But
   there is no standard way for a client to *discover* which flow a toolset needs. A
   standards-following MCP client can complete an authorization-code flow from Core's
   metadata; for `API_KEY`, `NONE` or `DIAL_NATIVE` it has no IETF-specified signal
   ("prompt the human for a key", "consent required"), because the MCP authorization spec
   models OAuth only. The missing piece is a **capability descriptor**: sign-in required,
   which `authentication_type`, which entry point. That is additive, not a rewrite.
2. **Three credential levels (USER / APPLICATION / GLOBAL) where toolsets use two.** The
   resolution order — exact `sub` match, then GLOBAL — is a source of the confusing
   "authenticated but no upstream access" state in §4.1. The `APPLICATION` level is for
   external services, not toolsets.
3. **Identity coupling to `getInitiatorId()`.** `sub` for JWTs but *project* for API keys
   means the same concept silently differs by credential type, and an API-key caller can
   never resolve a USER record. That is a footgun (see the identity rule in §2), not a
   feature.
4. **Configuration gates.** `authorizationServers` disabling the entire metadata surface
   is defensible, but it means a toolset can look correctly configured and still not offer
   any client-side auth path.

#### 8.2.1 Why `/signin` must NOT be replaced by a hosted `/authorize` + `/token`

An earlier draft of this document argued for replacing `/v1/ops/toolset/signin` with a
DIAL-hosted authorization-code flow, on the grounds that a standard client could then
complete it without per-DIAL integration. **That recommendation was wrong**, and the
reason is worth recording because it is a natural mistake to make.

The endpoint is not an OAuth endpoint. It is the unified credential-establishment API, and
`authenticationType` discriminates the flow:

```java
private String url;
private CredentialsLevel credentialsLevel;
private AuthenticationType authenticationType;  // the discriminator
private String code;          // OAUTH
private String apiKey;        // API_KEY
private String redirectUri;   // OAUTH
private boolean offlineUsageConsent;
```

with four supported types — `OAUTH`, `API_KEY`, `NONE`, `DIAL_NATIVE` — each with its own
integrity check (`AuthSettingsValidatorFactory`), and `SecuredResourceService.signIn`
branching accordingly: `API_KEY` gets format validation, an upstream `initialize`/`tools/list`
probe, and an idempotency skip; `OAUTH` runs the code exchange. `DIAL_NATIVE` — the target
*is* DIAL, the caller acts as the user via that user's offline credentials with separate
admin approval — lives alongside at `/v1/ops/external-service/*` and
`/v1/user/offline-credentials`.

A hosted `/authorize` + `/token` covers **only `OAUTH`**. It would orphan `API_KEY`, which
has no authorization-code leg at all (the human pastes a key), and `DIAL_NATIVE`'s consent
path. That is regression, not simplification.

**This strengthens §2's argument rather than weakening it.** Forwarding the `code` to Core
is not only what keeps the upstream token out of the client — it is what lets **one**
credential API serve flows that have no authorization code whatsoever. A hosted
code-exchange endpoint would have forced one API for `OAUTH`, a second for `API_KEY`, and
a third for `DIAL_NATIVE` consent. The private, unified op is *unifying*: a deliberate
choice, not inherited complexity. What it lacks is discoverability for non-OAuth flows
(item 1 above), and that is the narrow, additive fix worth making.

**Verdict:** the *model* is right and not overcomplicated — holding credentials server-side
per user is the correct architecture for a proxy, and the industry's own token-exchange
patterns agree. The *ergonomics* have real rough edges (items 1-4), but none of them is
"replace the sign-in API". The right ask is a discovery/capability descriptor so a
chat-less client can learn what kind of sign-in a toolset needs and where to start it.

### 8.3 What would falsify this

Worth stating so the conclusion is not unfalsifiable:

- If a standard MCP client could be made to hand a code to Core and accept a DIAL token in
  exchange — with no DIAL-specific code — the thesis would weaken.
- If upstream consent could be avoided entirely (it cannot; it is interactive by
  definition), the whole two-leg structure would collapse.
- PoC B (LiteLLM) is the direct empirical test. If LiteLLM demonstrates the model with
  standard clients and no per-client integration, that is evidence for "DIAL could too",
  not evidence against DIAL's model.

## 9. Follow-ups

1. Run PoC B (LiteLLM) and document the comparison. *(delegated; see
   `mcp-toolset-signin-poc-b.md` once complete)*
2. Close the chat-less discovery gap (4.1). The scoped ask is an additive **capability
   descriptor** — sign-in required, which `authentication_type`, which entry point — so a
   standard client can learn what kind of sign-in a toolset needs. Explicitly *not* a
   replacement of `/v1/ops/toolset/signin` (§8.2.1).
3. Decide the DCR story for production: fix the Keycloak policies, or standardise on a
   pre-registered client plus `--callback-port`.
4. Only then consider Core-side work for headless first use and bake the recipe into the
   launcher/CLI.
---

*Imported into this repository from the DIAL design archive on 2026-10-17. This copy is the **living** version of this document; the archive copy is a frozen historical record and is not updated. References to the May 2026 toolset authentication design have been replaced with references to the DIAL Core source, because that document predates the MCP specification revision that deprecated Dynamic Client Registration.*
