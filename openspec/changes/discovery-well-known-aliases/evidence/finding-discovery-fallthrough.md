# Finding — discovery paths fall through the front door to Core

The finding record for this change (`PROCESS.md` step 1): symptom, evidence, root cause,
proposed fix. Hostnames are recorded as `<gateway-origin>` and the app as `<app>`; the
publication discipline forbids the real values in tracked files.

## Symptom

A ChatGPT MCP connector pointed at `<gateway-origin>/apps/<app>/mcp` reports that it
"couldn't discover OAuth settings". The gateway's audit trail carries no registration
and no authorization request from ChatGPT, so the failure happens during discovery,
before any request reaches the gateway's OAuth endpoints.

## Evidence

Live `curl` probes against the deployed dev gateway, 2026-11-16, unauthenticated.

**What works** — the MCP authorization discovery chain as the MCP specification
(2025-11-25, Authorization) requires it:

| Request | Response |
|---|---|
| `POST /apps/<app>/mcp` | `401`, `WWW-Authenticate: Bearer resource_metadata="<gateway-origin>/.well-known/oauth-protected-resource/apps/<app>/mcp"` |
| `GET /.well-known/oauth-protected-resource/apps/<app>/mcp` | `200`, the app's RFC 9728 document |
| `GET /.well-known/oauth-authorization-server` | `200`, the RFC 8414 document: `code_challenge_methods_supported: ["S256"]`, `client_id_metadata_document_supported: true`, `registration_endpoint` present |
| `POST /dial/register` | `201` |

**What falls through** — each answered by DIAL Core, not by the router or the gateway:

| Request | Response |
|---|---|
| `GET /.well-known/openid-configuration` | `401`, `text/plain`, body `At least API-KEY or Authorization header must be provided` |
| `GET /.well-known/oauth-protected-resource` (root) | the same `401` from Core |
| `GET /.well-known/oauth-authorization-server/<path>` | the same `401` from Core |
| `GET /.well-known/openid-configuration/<path>` | the same `401` from Core |

Each fall-through response carries `X-Dial-Trace-Id`, Core's own trace header, which is
the evidence that Core answered. The router's catch-all `location /` forwards every
path no other location matches to Core, and Core's request pipeline answers an
unauthenticated request on any path outside its handful of public routes with its auth
filter's `401` (the Core surface record beside this file has the source facts).

The path-appended forms (`/apps/<app>/mcp/.well-known/oauth-protected-resource` and the
like) already get the router's own `404`: the apps data-path map requires `/mcp` as the
final path segment, so a tail after it is refused without forwarding.

## Root cause — inferred, not log-confirmed

The OpenAI Apps SDK authentication guide
(`https://developers.openai.com/apps-sdk/build/auth`) names the root
`/.well-known/oauth-protected-resource` as the protected-resource metadata location, and
names both `/.well-known/oauth-authorization-server` and
`/.well-known/openid-configuration` as authorization-server metadata locations without
stating an order. Community reports say ChatGPT probes the root protected-resource
document even when the `401` carries `resource_metadata`. A client that probes those
paths and receives Core's `401` instead of a document or a `404` reads the server as
requiring authentication for its own discovery, which no client can satisfy — and ends
discovery.

**The cause is inferred.** No request log confirms which paths ChatGPT requested:

- The gateway runs uvicorn with `access_log=False` by design: request lines on the
  authorization surface carry codes and tokens, and the gateway's own audit trail
  records flows and subjects instead.
- The router runs `access_log off` for the same reason (`router/nginx.conf`).
- Core's logs were checked as the candidate witness and failed as one. **Negative
  control:** the prober's own unauthenticated requests to the same fall-through paths,
  made at a known time, do not appear in Core's logs either — Core does not log
  unauthenticated `401` refusals at the configured level. Core's logs therefore cannot
  confirm or refute ChatGPT's requests, and their silence is not evidence.

So the defect this change fixes — discovery paths answered by Core's `401` — is
observed. Its sufficiency as the cause of the ChatGPT symptom is not, and the live
re-test with ChatGPT after deployment is the confirmation (tasks.md, the re-test group).
If ChatGPT still fails with the fix deployed, the open question on the root
protected-resource document (design.md, OQ-1) opens the next iteration.

## Proposed fix (the scope approved for this change)

1. Serve the authorization-server metadata at `/.well-known/openid-configuration`.
2. Serve the same document at `/.well-known/oauth-authorization-server/<path>` and
   `/.well-known/openid-configuration/<path>` — the issuer has no path, so one document
   covers every variant.
3. Answer every other `/.well-known/` path on the front door with a JSON `404` and
   never forward it to Core — the root `/.well-known/oauth-protected-resource`
   included — without shadowing the exact authorization-server metadata location or the
   `/dial/` and `/apps/` protected-resource locations.

**Out of scope, recorded only:** serving a root protected-resource document (one root
document can name only one resource; naming the origin breaks RFC 8707 resource binding
— design.md OQ-1); and the registration response's `grant_types` omitting
`refresh_token` (a separate observation — design.md, "Noted, not addressed").

## Noted while probing

- `POST /dial/register` answers `201` with `"grant_types": ["authorization_code"]`
  (`gateway/routes.py`), while the authorization-server metadata advertises
  `grant_types_supported: ["authorization_code", "refresh_token"]`. A client that honors
  its registration's `grant_types` strictly may not attempt the refresh grant. Not this
  change's defect and not addressed by it; recorded so it is not lost.
