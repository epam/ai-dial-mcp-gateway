# ChatGPT can't discover OAuth settings on the gateway

**Status:** addressed by the OpenSpec change `openspec/changes/discovery-well-known-aliases/`,
pending the live re-test (row W11).

## Symptom

A ChatGPT connector pointed at `<gateway-origin>/apps/<app>/mcp` fails with "couldn't
discover OAuth settings." The gateway audit log has no registration or authorization
request from ChatGPT, so the failure happens during discovery.

## What works

The MCP authorization discovery chain responds as the MCP specification requires:

| Request                                                    | Response                                                     |
| ---------------------------------------------------------- | ------------------------------------------------------------ |
| `POST /apps/<app>/mcp` without a token                     | `401`, `WWW-Authenticate` with `resource_metadata`           |
| `GET /.well-known/oauth-protected-resource/apps/<app>/mcp` | `200`, protected resource metadata                           |
| `GET /.well-known/oauth-authorization-server`              | `200`, `S256`, `client_id_metadata_document_supported: true` |
| `POST /dial/register`                                      | `201`                                                        |

## Cause

The router forwards every path it doesn't match to DIAL Core. Core answers unauthenticated
requests with `401` and a plain-text body, not `404`. The following discovery paths fall
through to Core:

| Request                                              | Response        |
| ---------------------------------------------------- | --------------- |
| `GET /.well-known/openid-configuration`              | `401` from Core |
| `GET /.well-known/oauth-protected-resource`          | `401` from Core |
| `GET /.well-known/oauth-authorization-server/<path>` | `401` from Core |
| `GET /.well-known/openid-configuration/<path>`       | `401` from Core |

ChatGPT probes the root protected resource metadata and `openid-configuration`, not only
the URL in `resource_metadata`. A `401` on those paths ends its discovery. This cause is
inferred from the OpenAI Apps SDK documentation and community reports; no request log
confirms it, because the gateway and router access logs are off and Core doesn't log
unauthenticated `401` responses.

## Fix

**Superseded by `openspec/changes/discovery-well-known-aliases/`.** The change shipped a
different design from the proposal below: the gateway serves the aliases, not the router.
The gateway answers `/.well-known/openid-configuration` and both path-insertion forms with
the same document as `/.well-known/oauth-authorization-server`. The router closes the rest
of `/.well-known/` with a JSON `404`, so an unknown discovery path no longer reaches Core.
Core's own protected resource templates still reach Core, through a location that forwards
only a raw URI that matches them exactly. Read the change's `design.md` for the reasons.

The original proposal follows for the record.

Make these changes in `router/nginx.conf`:

1. Serve the authorization server metadata at `/.well-known/openid-configuration`.
2. Serve the same document at `/.well-known/oauth-authorization-server/<path>` and
   `/.well-known/openid-configuration/<path>`. The issuer has no path, so one document
   covers every variant.
3. Answer every other `/.well-known/` path with a JSON `404`. Don't forward it to Core.
   Place this location after the existing protected resource metadata locations.

Items 1–3 alias public metadata and grant no new authority. They need an OpenSpec change
to `openspec/specs/mcp-signin/spec.md` with a low-impact security impact analysis.

## Open question

The root `/.well-known/oauth-protected-resource` can name only one resource, and the
gateway serves many. If ChatGPT still fails after the fix, the root document needs a
design decision, because naming the origin as the resource breaks RFC 8707 resource
binding. That decision needs a full security impact analysis.

## Verify

After the deployment, run the following checks:

```bash
G=<gateway-origin>
curl -s "$G/.well-known/openid-configuration" | jq .client_id_metadata_document_supported  # true
curl -s -o /dev/null -w '%{http_code}\n' "$G/.well-known/oauth-authorization-server/apps/<app>/mcp"  # 200
curl -s -o /dev/null -w '%{http_code}\n' "$G/.well-known/oauth-protected-resource"  # 404
curl -s -o /dev/null -w '%{http_code}\n' "$G/.well-known/unknown"  # 404
```

Then reconnect ChatGPT and confirm that the gateway audit log records a `client_registered`
or authorization event.
