# PoC B: LiteLLM's MCP gateway as the comparison point for DIAL toolset sign-in

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

Status: **PoC B partially proven** — LiteLLM runs locally, its discovery/DCR/authorize surface is
captured raw, and the passthrough contrast is measured. The interactive upstream consent was
prepared and surfaced but **not click-through by a human**, so the token-exchange step and
per-user token storage are documented from the schema and docs, not observed end-to-end.
Environment: `dial-instance` (PoC A frozen and verified intact). Artifacts in <local-instance>/.mcp-poc/litellm/.

> **Where the artefacts live.** The probe scripts referenced below (`<local-instance>/.mcp-poc/*.py`)
> are the local PoC rig for the `dial-instance` development instance and
> are **not** part of this repository. The sign-in skill itself *is* shipped here,
> at [`gateway/`](../gateway/) -- `skill/signin.py` plus the runbook `skill/SKILL.md`.

Reframing note: DIAL's sign-in API is **not an OAuth endpoint**. It is a unified
credential-establishment API discriminated by `authentication_type` across four types
(`OAUTH`, `API_KEY`, `NONE`, `DIAL_NATIVE`) — `code` for OAUTH, `apiKey` for API_KEY — with a
sibling DIAL_NATIVE consent path at `/v1/ops/external-service/*` and
`/v1/user/offline-credentials`. DIAL is therefore not "OAuth with a private endpoint"; it is a
private, multi-mode credential API. That distinction is what makes the contrast below sharp:
LiteLLM's equivalent operation is wrapped in **standard** OAuth endpoints, DIAL's is not.

## 1. Status — exactly how far this got, and what is untested

**Proven by direct observation (raw responses in §3 and §5):**

- LiteLLM proxy (v1.105.1) running locally on `:4000` with the same Notion MCP upstream as
  PoC A, and a second instance on `:4001` for the passthrough comparison.
- The full **client-facing discovery chain**: unauthenticated call → `WWW-Authenticate`
  challenge → RFC 9728 protected-resource metadata → RFC 8414 authorization-server metadata →
  RFC 7591 dynamic client registration → `/{server}/authorize` → 307 redirect to Notion's
  consent. A stock client can walk every step; nothing DIAL-specific is needed.
- DCR genuinely proxied upstream (Notion returned a 16-char `client_id`, and the subsequent
  authorize URL carries that same id to `mcp.notion.com`).
- The `/token` endpoint exists and validates (`400 invalid_grant` on a bogus code).
- `true_passthrough` vs `oauth_delegate` behaviour, including which challenge each emits when
  no upstream credential is present (the Q2 question).
- The per-user credential storage schema LiteLLM ships (`LiteLLM_MCPUserCredentials`).

**Prepared but NOT proven (needs the human click):**

- The upstream **consent** and the subsequent `/token` exchange completing, and an upstream
  token actually landing in `LiteLLM_MCPUserCredentials` under a `user_id`.
- **Silent repeat use** (refresh, no browser) — not observed.
- Whether a stored token survives a proxy restart, and how it is keyed when a token exists.
- The `dcr_bridge` flag (not enabled in this run — its behaviour is doc-only here).
- The second `true_passthrough` instance's 200s prove **forwarding** to Notion, but the Notion
  response was a protocol error (`-32602 Invalid request parameters`) because the token was
  bogus; that still proves the request reached Notion with the client's own token.

Loopback note: the interactive probe (`probe_oauth_leg.py --interactive`) serves the loopback
callback on `http://localhost:8766/callback`. During this run three consent URLs were surfaced and
none was clicked; the listener and both proxies were subsequently reaped by the host's low-memory
reaper, so **nothing is running now**. §6 gives the restart recipe and the exact human step.

## 2. Setup — what was actually run, and corrections to the drafts

### Correction 1 — the image pull never succeeded; the proxy ran natively instead

`ghcr.io/berriai/litellm:main-stable` and the Docker Hub mirror `litellm/litellm:main-stable`
both **failed repeatedly** on this network with `read: connection reset by peer` partway through
a large layer. I also found (and killed) **two concurrent pulls of the same image** running at
once — exactly the corruption the brief warned about; after that, only single pulls were issued.
The GHCR host was intermittently unreachable (`curl -sI https://ghcr.io/v2/` → `000`), while
Docker Hub answered. The retry loops cached completed layers but never converged.

Because a working gateway was required and the image was the only blocker, I installed LiteLLM
into a local venv on the Windows host and ran the proxy directly:

```bash
cd <local-instance>/.mcp-poc/litellm
python -m venv .venv
.venv/Scripts/python -m pip install "litellm[proxy]"     # v1.105.1
# One Windows startup fix, otherwise the banner crashes on the cp1252 console:
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
.venv/Scripts/litellm --config config.yaml --port 4000 --host 127.0.0.1
```

This is LiteLLM's own supported "run from source / pip" deployment path, not a substitute
implementation, so the observed endpoints are authoritative for the product. The
`docker-compose.yml` draft was **not** used for the recorded runs; it is retained and corrected
for anyone who retries it on a network where the pull works.

### Correction 2 — `config.yaml`: `transport: http` and an explicit User-Agent were added

Two changes to the draft:

- `transport: http` — added explicitly. Config-file entries default to `http`, so this is
  belt-and-braces, but the management-API models default to `sse`, so pinning it removes doubt.
- `static_headers: {User-Agent: dial-poc-b/1.0}` — added for the PoC A Cloudflare gotcha: Notion
  sits behind Cloudflare, which 403s (`error 1010`) some client User-Agents. Sending an explicit
  UA upstream is the same mitigation the DIAL helpers use.

The draft's core choice — `auth_type: oauth2` **without** `client_id`/`client_secret` so LiteLLM
performs its own upstream DCR — is correct, and it is what produced the working DCR in §3.
`oauth2_flow: authorization_code` is mandatory (LiteLLM refuses to start otherwise), as assumed.

### Correction 3 — `docker-compose.yml`: `PROXY_BASE_URL` was missing

Added `PROXY_BASE_URL=http://localhost:4000`. LiteLLM uses this origin to build its own callback
URL (`<origin>/callback`) and the issuer in discovery documents; without it the proxy guesses from
the request. The draft's `MCP_TRUSTED_REDIRECT_ORIGINS=http://localhost` was kept but is
defensive: the docs state loopback `http://localhost` callbacks are accepted on **any** port by
default, and registration worked in this run regardless. (Docs also note origin entries are
HTTPS-only; a loopback http entry is the documented exception.) `DATABASE_URL` is genuinely
required — see Correction 4.

### Correction 4 — LiteLLM without a database does not work for MCP auth

Without `DATABASE_URL`, the unauthenticated MCP endpoints returned
`500 {"error":"MCP request failed","details":"No module named 'prisma'"}`, and once `prisma` was
installed but no DB was connected, an admitted request returned `400 {"detail":"No connected db."}`.
Getting the DB path working needed, beyond `DATABASE_URL`:

- the Python `prisma` package (not pulled in by `litellm[proxy]` alone in this env),
- `prisma migrate deploy` (LiteLLM ran the 195 migrations itself on startup), **and**
- `prisma generate` for the Python client. That last step failed two ways: `spawn prisma-client-py
  ENOENT` (fix: put the venv `Scripts` dir on `PATH`) and an engine download that reset on this
  network (fix: point `PRISMA_QUERY_ENGINE_LIBRARY` at the locally-installed
  `query_engine-windows.dll.node` and set `PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1`).

Postgres ran as a container on `:5433` (`wsl -e docker run ... postgres:16-alpine`), separate
from the DIAL stack. This is the operational cost LiteLLM imposes for per-user MCP tokens;
DIAL holds its toolset credentials in Core with no such adjacent database.

## 3. The discovery surface LiteLLM exposes (raw responses)

All from `curl -sD-` against `:4000`, `auth_type: oauth2`, `oauth2_flow: authorization_code`,
no `client_id`/`client_secret`.

**Unauthenticated MCP call → challenge (RFC 9728 pointer):**

```
POST /mcp            -> 401
  WWW-Authenticate: Bearer resource_metadata="http://localhost:4000/.well-known/oauth-protected-resource/mcp"
POST /notion/mcp     -> 401
  WWW-Authenticate: Bearer resource_metadata="http://localhost:4000/.well-known/oauth-protected-resource/notion/mcp"
```

**Gateway admits the key but has no upstream token → LiteLLM's *own* AS is advertised:**

```
POST /notion/mcp  (x-litellm-api-key: Bearer <litellm-master-key>, no upstream token)  -> 401
  WWW-Authenticate: Bearer authorization_uri="http://localhost:4000/.well-known/oauth-authorization-server/notion"
  body: {"detail":"Unauthorized"}
```

This is the mirror image of PoC A's finding 4.1. DIAL relays *Notion's* challenge in this state
(pointing the client at an IdP it cannot complete); LiteLLM emits *its own* challenge, pointing
the client at an AS the client *can* complete.

**Protected-resource metadata (RFC 9728):**

```
GET /.well-known/oauth-protected-resource           -> 200
  {"resource":"http://localhost:4000","authorization_servers":["http://localhost:4000/mcp"],"scopes_supported":[]}
GET /.well-known/oauth-protected-resource/mcp       -> 200
  {"authorization_servers":["http://localhost:4000/mcp"],"resource":"http://localhost:4000/mcp","scopes_supported":[]}
GET /.well-known/oauth-protected-resource/notion/mcp -> 200
  {"authorization_servers":["http://localhost:4000/mcp"],"resource":"http://localhost:4000/notion/mcp","scopes_supported":["default"]}
GET /notion/.well-known/oauth-protected-resource    -> 404
```

**Authorization-server metadata (RFC 8414) — per-server is the real one:**

```
GET /.well-known/oauth-authorization-server            -> 200   (gateway-level)
  {"issuer":"http://localhost:4000",
   "authorization_endpoint":"http://localhost:4000/v1/mcp/oauth/authorize",
   "token_endpoint":"http://localhost:4000/v1/mcp/oauth/token",
   "response_types_supported":["code"],"grant_types_supported":["authorization_code"],
   "code_challenge_methods_supported":["S256"]}

GET /.well-known/oauth-authorization-server/notion     -> 200   (per-server)
  {"issuer":"http://localhost:4000/notion",
   "authorization_endpoint":"http://localhost:4000/notion/authorize",
   "token_endpoint":"http://localhost:4000/notion/token",
   "response_types_supported":["code"],"scopes_supported":["default"],
   "grant_types_supported":["authorization_code","refresh_token"],
   "code_challenge_methods_supported":["S256"],
   "token_endpoint_auth_methods_supported":["client_secret_post"],
   "registration_endpoint":"http://localhost:4000/notion/register"}

GET /notion/.well-known/oauth-authorization-server      -> 404
```

Note the per-server document carries `refresh_token` in `grant_types_supported` — the hint that
repeat use is meant to be silent.

**Dynamic client registration (RFC 7591) — proxied to Notion, no gateway key needed:**

```
POST /notion/register
  {"redirect_uris":["http://localhost:8766/callback"],"client_name":"dial-poc-b harness",
   "grant_types":["authorization_code"],"response_types":["code"],
   "token_endpoint_auth_method":"none"}
-> 200
  {"client_id":"6TvLIAIEdjxOwtUh","redirect_uris":["http://localhost:8766/callback"],
   "client_name":"dial-poc-b harness","grant_types":["authorization_code"],
   "response_types":["code"],"token_endpoint_auth_method":"none","client_id_issued_at":1792067046}
```

The `client_id` is a Notion-minted 16-char identifier, i.e. LiteLLM forwarded the registration
upstream rather than inventing a local client.

**Authorize → upstream consent (the decisive step for Q1):**

```
GET /notion/authorize?response_type=code&client_id=NkaArF4MBeMQ4WoQ
   &redirect_uri=http%3A%2F%2Flocalhost%3A8766%2Fcallback
   &state=...&code_challenge=...&code_challenge_method=S256
-> 307 Temporary Redirect
  Location: https://mcp.notion.com/authorize?client_id=NkaArF4MBeMQ4WoQ
            &redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Fcallback
            &state=...&response_type=code&scope=default
            &code_challenge=...&code_challenge_method=S256
```

The single most important line in this document is the `redirect_uri` inside that Location:
Notion will send the code to **LiteLLM's** `/callback`, not to the client's
`http://localhost:8766/callback`. LiteLLM holds the state cookie, receives the code, and only
then relays back to the client. That is why a stock client needs no LiteLLM-specific code — and
it is also why the architecture differs subtly from DIAL (see §5).

**Token endpoint exists and validates:**

```
POST /notion/token  (grant_type=authorization_code, code=bogus-code, ...)
-> 400 {"error":"invalid_grant","error_description":"Invalid authorization code format"}
```

**Aggregate `/mcp`** (gateway-level endpoint, admitted with the key but no upstream token):

```
POST /mcp  (x-litellm-api-key)  -> 200
  {"jsonrpc":"2.0","id":2,"result":{
     "_meta":{"litellm.ai/server_outcomes":{"notion":{"status":"auth_required","http_status":401}}},
     "tools":[]}}
```

So the aggregate view degrades gracefully: it tells the caller which server needs auth rather
than failing the whole call.

## 4. The comparison table

| Dimension | DIAL MCP toolset | LiteLLM MCP gateway |
|---|---|---|
| Where consent happens | Human opens the upstream `/authorize` URL (built from the toolset's **public** `auth_settings`), approves, callback delivers `code` to the **harness's** loopback; harness hands `code` to Core | Human opens the upstream `/authorize` URL (LiteLLM's 307 to Notion), approves, Notion redirects to **LiteLLM's** `/callback`; LiteLLM relays to the client's registered `redirect_uri` |
| Interactive steps, first use | **1 browser consent.** Plus a DIAL-specific step: the client must call `POST /v1/ops/toolset/signin` with the code — a **private** API no generic MCP client can produce | **1 browser consent.** No extra step: discovery → `register` → `authorize` → `token` are all standard OAuth endpoints a generic client already speaks |
| Repeat use silent? | Yes — re-running `signin.py` prints `already SIGNED_IN`, no browser (PoC A, observed) | **Expected** yes (`refresh_token` advertised), **not observed** — consent was not completed |
| Upstream token storage | Inside Core, keyed by the caller JWT's `sub` (per-user; an API key has no `sub` and silently breaks it) | `LiteLLM_MCPUserCredentials(id, user_id, server_id, credential_b64, …)` — per-user, keyed by the calling key's `user_id`; needs a Postgres |
| Scoping | **Per user (`sub`), strictly** — verified in PoC A across two users | **Per key's `user_id`** (schema + docs; not observed with a real token). M2M (`client_credentials`) is the shared/global alternative |
| Discovery: protected-resource metadata | `GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp` → **200** `{"resource":"…/v1/toolset/notion/mcp","authorization_servers":["https://keycloak:8443/realms/dial"],"scopes_supported":["openid","offline_access"]}` | `GET /.well-known/oauth-protected-resource/notion/mcp` → **200** `{"authorization_servers":["http://localhost:4000/mcp"],"resource":"http://localhost:4000/notion/mcp","scopes_supported":["default"]}` |
| Discovery: AS metadata | Points at **Keycloak** (`https://keycloak:8443/realms/dial`), which the harness completes for Leg 2 | `GET /.well-known/oauth-authorization-server/notion` → **200**, `authorization_endpoint=/notion/authorize`, `token_endpoint=/notion/token`, `registration_endpoint=/notion/register` — **LiteLLM itself is the AS** |
| DCR | Notion DCR is real and Core does it **server-side** (client_id `Ohk3BbaVnj3lemIy`, `dynamically_registered: true`); Keycloak advertises DCR but its policies block browser-free registration, so harness-side DCR does not work | `POST /notion/register` → **200**, LiteLLM **forwards to Notion** (client_id `6TvLIAIEdjxOwtUh`), no gateway key required. `dcr_bridge` exists for OAuth-only clients |
| Per-server endpoints | Core: `/v1/toolset/notion/mcp` (resource). The **sign-in** op is `/v1/ops/toolset/signin` — private | `/notion/register`, `/notion/authorize`, `/notion/token`, `/notion/mcp` — all standard |
| Which combination maps to DIAL's two-leg model | Leg 1 = `POST /v1/ops/toolset/signin` (verifier lives only in Core). Leg 2 = Core as RFC 9728 resource server | Closest analogue to DIAL Leg 1 = **`auth_type: oauth2` + `oauth2_flow: authorization_code`** (gateway mediates and stores per user). `oauth_delegate` admits the caller then forwards a *separate* upstream bearer — the closest analogue to a gateway-holds-credential model with admission, but **not** a workaround for the oauth2 flow |
| Headless / zero-interaction | Not possible from the client: consent is interactive; would need Core-side work (DIAL-hosted `/authorize` + `/token` + DCR bridge, or device authorization) | Also not possible: consent is interactive. Would need device authorization (RFC 8628) or a pre-provisioned token; `dcr_bridge` does not remove the click, it removes the client's need for DCR |
| Debuggability | Upstream 401s relayed verbatim with the **upstream's** challenge (`resource_metadata="https://mcp.notion.com/…"`) — misleads a standards-following client into the wrong IdP (PoC A §4.1) | `x-litellm-mcp-debug: true` → masked `x-mcp-debug-inbound-auth`, `x-mcp-debug-oauth2-token`, `x-mcp-debug-auth-resolution`, `x-mcp-debug-outbound-url`, `x-mcp-debug-server-auth-type`. Emitted **only after gateway admission**; a leak shows as `SAME_AS_LITELLM_KEY` |

## 5. Genuine architectural differences, not a feature list

**(a) Standard OAuth facade vs private credential API.** This is the material difference and the
answer to Q1. LiteLLM's delegation is not "OAuth with a private endpoint" any more than DIAL's
sign-in is "OAuth at all" — it is the opposite: LiteLLM wraps the *whole* delegation in the
endpoints an MCP client already implements (`/.well-known/oauth-protected-resource`,
`/.well-known/oauth-authorization-server/{server}`, `POST /{server}/register`, `GET
/{server}/authorize`, `POST /{server}/token`). A stock client needs no LiteLLM-specific code:
it discovers, registers, redirects the user, and exchanges the code through calls it makes
anyway. DIAL's equivalent operation, `POST /v1/ops/toolset/signin`, is private, and the PKCE
`code_verifier` is generated inside Core and never exposed — so a generic client **cannot**
complete DIAL's Leg 1 no matter how standards-compliant it is. PoC A had to ship a helper; PoC B
does not. Same delegation architecture, opposite client-integration cost.

**(b) Who holds the code, and where the verifier lives.** In DIAL, the client builds the
`/authorize` URL from the toolset's *public* settings (which include `code_challenge` but not the
verifier), the callback comes to the **harness's** loopback, and the client can only hand the raw
`code` to Core — Core does the exchange because it alone has the verifier. In LiteLLM, the
`/authorize` redirect points Notion at **LiteLLM's own `/callback`**, LiteLLM receives the code,
and *it* performs the exchange; the client's `redirect_uri` is where LiteLLM then relays the
result. So LiteLLM's gateway is genuinely in the middle of the token exchange, whereas DIAL's Core
is the *only* possible exchanger while the code still transits the client. Both keep the verifier
server-side; they differ in whether the code ever reaches the client's own loopback.

**(c) The challenge-ownership inversion (the sharpest COW).** PoC A's finding 4.1 was that when
DIAL has no stored credential, Core relays **Notion's** `WWW-Authenticate` — pointing a
standards-following client at an IdP it can never complete. LiteLLM does the opposite: with the
gateway key present and no upstream token, it emits **its own** challenge
(`authorization_uri="…/.well-known/oauth-authorization-server/notion"`). That is the correct
behaviour and it is exactly the fix PoC A proposed upstream for DIAL. The comparison therefore
*validates* PoC A's design gap rather than merely describing it.

**(d) Passthrough is a different mechanism, not a workaround (Q2).** `true_passthrough` and
`oauth_delegate` were measured on a second proxy (`:4001`), both pointed at the same Notion
upstream:

- `true_passthrough`, **no credentials** → `401` whose `WWW-Authenticate` is
  **Notion's own**: `resource_metadata="https://mcp.notion.com/.well-known/oauth-protected-resource/mcp"`.
  `GET /.well-known/oauth-protected-resource/notion_pt/mcp` returns **Notion's** PRM verbatim.
  Its `/{server}/authorize` is not even an AS (`"MCP server 'notion_del' is not an OAuth
  authorization server"`). With a token supplied in `Authorization`, LiteLLM returns `200` and
  `x-mcp-debug-outbound-url: https://mcp.notion.com/mcp` — the client's token went straight to
  Notion.
- `oauth_delegate`, **gateway key only** → `401` whose `WWW-Authenticate` is **LiteLLM's own**
  (`resource_metadata="http://localhost:4001/.well-known/oauth-protected-resource/notion_del/mcp"`).
  With gateway key **and** a separate `Authorization`, LiteLLM admits the caller and forwards
  `Authorization` upstream (`200`, outbound url = Notion), never forwarding the gateway key.

So passthrough is architecturally distinct from delegation: it is "the client already solved the
upstream OAuth; the gateway is a transparent pipe." **Yes, passthrough requires the client to have
obtained the upstream token itself** — and therefore it does not remove DIAL's edge at all, it
*relocates* it: the client still has to run Notion's OAuth, only now with no gateway help. The
difference from DIAL's `forwardAuthToken` is the direction of the token: DIAL forwards the caller's
**DIAL** JWT upstream (which only works if the upstream is DIAL-aware), whereas LiteLLM's
`true_passthrough` forwards the client's **upstream** token by design. They look alike and are not
the same mechanism.

**(e) Credential rendezvous requires an adjacent database.** DIAL's per-`sub` credential store is
part of Core. LiteLLM's per-user MCP credentials are a separate Postgres that the operator must
provision, and without it the MCP auth path simply does not function (observed: `No connected db`).
That is a real deployment difference, not a feature-list entry.

## 6. What a human must still do, and whether any step is avoidable

Exactly one interactive step is required, for both products: **approving the upstream consent in a
browser.** No design change removes consent — it is the user authorizing access to their own
workspace by definition. What each product *can* change is the number of steps around it, and that
is where they diverge: DIAL needs a DIAL-specific callback-to-Core call after the consent; LiteLLM
needs nothing beyond the consent, because the surrounding calls are standard OAuth.

**Important — the consent window is NOT currently open.** Three consent URLs were generated during
this run and all three went unclicked; the listener processes were then reaped by the host's
low-memory reaper, so the proxies (`:4000`, `:4001`) and the loopback callback are **down**. The
earlier URLs are dead (their listeners no longer exist) and are deliberately not reproduced here,
so you do not try to use one.

**The exact human step for PoC B**, once the stack is back up: start the interactive probe and open
the URL it prints.

```bash
cd <local-instance>/.mcp-poc/litellm
# 1. proxy (Postgres container litellm-pg on :5433 must be running; see §2)
.venv/Scripts/litellm --config config.yaml --port 4000 --host 127.0.0.1   # PYTHONUTF8=1, DATABASE_URL, PROXY_BASE_URL set
# 2. probe: registers a client, prints its own consent URL, serves the loopback callback,
#    then runs the /token exchange and a tools/list automatically once you approve
.venv/Scripts/python -u probe_oauth_leg.py --interactive
```

Open the printed `https://mcp.notion.com/authorize?...` URL and approve access to Notion. After
approval, Notion returns the browser to `http://localhost:4000/callback` (LiteLLM's own callback,
per §3) and LiteLLM relays to the waiting probe. Each run registers a fresh client and prints a
fresh URL, and the window times out after 30 minutes per run; re-running is cheap and idempotent.

**Avoidability:** zero-interaction first use is **not** achievable in either system as configured.
For DIAL it would need Core-side work (a DIAL-hosted `/authorize` + `/token` + DCR bridge, or
device authorization). For LiteLLM it would likewise need device authorization or a
pre-provisioned token — `dcr_bridge` does **not** remove the click; it removes the client's need
to do its own DCR. Repeat use, by contrast, is intended to be silent in both.

## 7. Corrections to the staged drafts (summary)

1. **`config.yaml`** — added `transport: http` and `static_headers.User-Agent` (Cloudflare). The
   `auth_type: oauth2` + `oauth2_flow: authorization_code` choice without client credentials is
   correct and produced working upstream DCR.
2. **`docker-compose.yml`** — added `PROXY_BASE_URL=http://localhost:4000` (was missing; it drives
   LiteLLM's callback and discovery issuer). `MCP_TRUSTED_REDIRECT_ORIGINS=http://localhost` kept
   but unnecessary for loopback. `DATABASE_URL` is required in practice.
3. **Deployment** — the compose file was not exercised: the container image could not be pulled on
   this network, so LiteLLM ran natively from a venv. The recorded endpoints are the product's own.
4. **Verification gap** — the upstream consent was surfaced, not completed, so token storage,
   refresh, and restart-persistence are documented from schema/docs and marked unverified.

## 8. Safety / integrity of PoC A

- PoC A artifacts untouched; `<local-instance>/.mcp-poc/` files other than `litellm/` unmodified.
- DIAL instance unmodified; no `docker compose down`; all 12 `dial-instance-*` containers
  still up.
- Notion toolset **not** signed out — verified mid-run and at the end:
  `user_level_auth_status = SIGNED_IN`, `client_id = Ohk3BbaVnj3lemIy`, unchanged from PoC A.
- Nothing committed to git.
- TLS verification was **not** disabled anywhere. The only relaxation was
  `PRISMA_ENGINES_CHECKSUM_IGNORE_MISSING=1`, which concerns Prisma's **local engine checksum
  lookup**, not TLS verification of any connection.
- One credential hygiene note: `~/.docker/config.json` in WSL contains the user's Docker Hub
  registry token in cleartext. It was read incidentally while diagnosing the pull and is not
  reproduced here; the user may want to be aware of it.
---

*Imported into this repository from the DIAL design archive on 2026-10-17. This copy is the **living** version of this document; the archive copy is a frozen historical record and is not updated. References to the May 2026 toolset authentication design have been replaced with references to the DIAL Core source, because that document predates the MCP specification revision that deprecated Dynamic Client Registration.*
