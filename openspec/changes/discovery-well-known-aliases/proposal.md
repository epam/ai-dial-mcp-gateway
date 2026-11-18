# Proposal

## Why

A ChatGPT MCP connector pointed at the gateway's `/apps/<app>/mcp` fails with
"couldn't discover OAuth settings", and the gateway's audit trail shows it never reached
registration or authorization. The MCP discovery chain itself works — the `401`
challenge, the per-resource protected-resource document, the flat authorization-server
metadata, and registration all answer correctly. What fails is everything *around* that
chain: four well-known paths a discovering client may probe —
`/.well-known/openid-configuration`, the root `/.well-known/oauth-protected-resource`,
and the path-insertion forms `/.well-known/oauth-authorization-server/<path>` and
`/.well-known/openid-configuration/<path>` — match no router location, fall through the
catch-all to DIAL Core, and are answered by Core's auth filter with a plain-text `401`.
A discovery document that answers "authenticate first" is a dead end no client can
satisfy.

The MCP specification (2025-11-25) requires clients to try both RFC 8414 and OpenID
Connect discovery, and the OpenAI Apps SDK guide names `openid-configuration` and the
root protected-resource path as locations ChatGPT reads. The finding record
(`evidence/finding-discovery-fallthrough.md`) states the evidence and its limit: the
fall-through is observed; that it is what stops ChatGPT is inferred, because no request
log can confirm which paths ChatGPT requested (the gateway's and the router's access logs
are off by design, and Core does not log unauthenticated refusals — the negative control
showed the prober's own requests absent from Core's logs too).

## What Changes

- **The authorization-server metadata is served at its OpenID Connect location too.**
  `GET /.well-known/openid-configuration` answers the gateway's RFC 8414 document,
  byte-identical to `/.well-known/oauth-authorization-server`. No OpenID Provider member
  is added: the gateway issues no ID tokens and has no userinfo endpoint, and the
  document's member set stays the advertisement of what the gateway emits.
- **The path-insertion forms answer the same document.**
  `GET /.well-known/oauth-authorization-server/<suffix>` and
  `GET /.well-known/openid-configuration/<suffix>`, for any suffix, answer the same
  bytes. The issuer is the path-less public origin in every response — never an echo of
  the suffix — so a strict RFC 8414 client discards it (§3.3) and a lenient one gets
  working endpoints; no second issuer identity is ever asserted.
- **The gateway serves the aliases itself**, from the one builder and the one handler the
  canonical route already uses; the router forwards the alias family to the gateway. One
  source of truth for the body; the alias behavior is unit-testable without the stack.
- **The front door's `/.well-known/` namespace is closed.** The router answers every
  `/.well-known/` path that no discovery location serves with `404` and the body
  `{"detail":"Not Found"}` as `application/json` — the gateway's own 404 shape — plus a
  fixed `X-Content-Type-Options: nosniff` header that tells the router's answer from the
  gateway's, and never forwards it to Core. The root
  `/.well-known/oauth-protected-resource` is one of those paths. The closure is a plain
  prefix location, so the exact authorization-server location and the `/dial/` and
  `/apps/` protected-resource regex locations keep precedence. Because nginx selects a
  location by the normalized path but forwards the raw one, the closure is also enforced
  on the raw spelling: raw-URI checks keep a dot-segment or percent-encoded spelling from
  reaching Core in either direction.
- **Core's own protected-resource routes keep reaching Core.** Core serves exactly two
  unauthenticated `/.well-known/` templates (`…/v1/toolset/{id}/mcp`,
  `…/v1/deployments/{id}/mcp`), and Core's own challenge can point a direct-to-Core
  client at them on this host. A dedicated router location forwards exactly those shapes,
  spelled literally in the raw request, to Core unchanged; every other `/.well-known/` path was Core's `401` and becomes the
  router's `404`, so the closure takes no working Core path away
  (`evidence/core-well-known-surface.md`).
- **The routing probe battery gains the rows that prove each behavior**, negative
  controls first — Core-direct on its own port, and the gateway's own `404` through the
  front door, so a front-door `404` is provably the router's and neither Core's nor the
  gateway's. The normalization rows send their paths verbatim.

**Not in scope (the recorded boundary):** serving a root protected-resource document —
one root document names one resource, and naming the origin as the resource breaks the
per-resource RFC 8707 binding the gateway's tokens carry; it is an open question with its
own future SIA (design.md OQ-1). The registration response's `grant_types` omitting
`refresh_token` — a separate observation, noted and not addressed (design.md). The
path-appended forms (`/apps/<app>/mcp/.well-known/…`), which the data path already
refuses without reaching Core. Any change to Core.

## Capabilities

### New Capabilities

(none — the change extends the existing sign-in capability)

### Modified Capabilities

- `mcp-signin`:
  - ADDED — the front door's well-known namespace is closed (the router's `404` for every
    unserved `/.well-known/` path, its body and type, its precedence below the discovery
    locations, and the forwarding of Core's two protected-resource templates);
  - MODIFIED — discovery documents describe one flat authorization server (the AS
    metadata's alias set: the OpenID Connect location and both path-insertion forms,
    byte-identical, the issuer never echoing a suffix, no OpenID Provider member);
  - MODIFIED — Core trusts gateway tokens through a dedicated identity-provider entry
    (Core's own discovery surface named precisely — its two protected-resource templates —
    with a scenario proving they still reach Core through the front door).

## Impact

- **Code**: `gateway/routes.py` (the alias paths registered on the canonical handler),
  `gateway/discovery.py` (the alias path constants beside `AUTHORIZATION_SERVER_PATH`),
  `router/nginx.conf` (the alias-family location, the raw-gated Core protected-resource
  location, the closed-namespace locations, and the catch-all's raw namespace-spelling
  check), `scripts/probe_routing.py` (the new rows and their
  control), `tests/test_app.py` and `tests/test_discovery.py` (the alias pins; the CORS
  pin's path list), `docs/routing.md` (the location map and the probe table),
  `docs/gateway-configuration.md` (the discovery section's alias set),
  `docs/pod-contract.md` (the router section: the closure is part of the committed conf
  the pod runs), and `docs/threat-model.md` (the SIA's delta).
- **Operational**: no setting is added or changed; the router and the gateway deploy
  together (the router forwards the alias family to routes the gateway must have). A
  deployment that fronts the gateway with anything other than the committed router conf
  loses the closure, and must reproduce it — the pod contract says so.
- **Security**: the security impact analysis runs in full (impact level **low** — the
  aliases publish an already-public static document; the closure narrows what reaches
  Core; no endpoint that issues, accepts, or stores a credential is added or changed; no
  trust boundary, grant type, or secret material). It prices the issuer-identity question
  at the path-insertion aliases, an OpenID Connect relying party mis-binding the gateway
  as an OpenID Provider, the router's location-precedence failure modes (shadowing the
  protected-resource locations; severing Core's own discovery surface), and the
  normalized-match-versus-raw-forward class on the new locations. The threat-model
  updates are part of this change's tasks.
