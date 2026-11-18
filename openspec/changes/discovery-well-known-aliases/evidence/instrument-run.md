# Instrument run — the well-known row group

The probe battery's well-known group (`scripts/probe_routing.py --group wellknown`), run
at the stages the process names. Hostnames are the composed stack's local ones; no
credential appears. Every row goes out through `http.client` with the raw path on the
request line, and each prints it.

## Environment of these runs (read this first)

The composed stack's DIAL Core and Keycloak come from a sibling instance repository that
is not present on the implementation host. The runs below therefore used the repository's
own compose project (gateway and router, built from this tree) beside a **local stand-in
for Core**: a small throwaway process that models only what the routing rows observe,
from `core-well-known-surface.md` — `Access-Control-Allow-Origin: *` on every answer,
`OPTIONS` answered `200`, the two protected-resource templates answered on the **raw**
path, and the authentication filter's plain-text `401` carrying a trace header
(`X-Dial-Trace-Id`) on everything else. It lives outside the repository. What this
establishes and what it does not:

- It establishes everything that is a property of the router and the gateway: which
  location answers, what is forwarded raw, and what the closure answers. The rows
  discriminate on Core's trace header, which the stand-in sets as Core does.
- It does not establish the behavior of the real Core process: that the two templates
  match exactly as the source record says, that Core's `401` has exactly this shape, or
  anything the existing token-bearing rows measure (the two query-string rows, which need a
  minted identity token and Core's request log, were not run). The owner-run live re-test
  (W11) and a run against the real instance stand behind those.

## W0b — the failing-first run, against the pre-change stack

Router and gateway exactly as committed before this change (no alias route, no
closure). Expected by the design: W0, W0c, W7, W13, and W10 cells f and g pass; W1, W2, W4,
W5, W8, W10 cells a-e, and W12 fail with Core's answer. W6, not named in that list, is
expected to pass because the three documents it re-runs are served today.

**Measured: the pattern is exactly the expected one.** Every failing row failed with
Core's `401` (or its `OPTIONS 200`) and Core's trace header; no row differed from the
expectation, so no finding was opened.

| Row | Expected pre-change | Measured |
|---|---|---|
| W0 | pass (control) | pass |
| W0c | pass (control) | pass |
| W1 | fail | FAIL (Core 401, trace present) |
| W2 | fail | FAIL (Core 401 on all six paths) |
| W4 | fail | FAIL (Core 401 on all four paths, CORS header present) |
| W5 | fail | FAIL (Core 401 for POST and HEAD, Core OPTIONS 200) |
| W6 | pass | pass |
| W7 | pass | pass |
| W8 | fail | FAIL (Core 401) |
| W10 a | fail | FAIL (Core 401, not the document) |
| W10 b, c, d, e | fail | FAIL (Core 401, every variant) |
| W10 f | pass | pass (gateway 404, no trace) |
| W10 g | pass | pass (data path 404, HTML, no trace) |
| W12 | fail | FAIL (Core 401 on all three paths) |
| W13 | pass | pass (data-path 404, HTML, no trace) |

Output of the run, with the long per-cell failure detail elided:

```text
[1/19] negative control — Core's own challenge
  request   GET http://localhost:8081/v1/toolset/notion/mcp  (direct to Core, outside the router)
  status    401
  challenge 'Bearer resource_metadata="http://localhost:8081/.well-known/oauth-protected-resource/v1/toolset/notion/mcp"'
  verdict   control red — Core's own challenge names its own metadata

[2/19] W0 negative control — Core's own answer on a discovery path
  request   GET /.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  (direct to Core, outside the router)
  record    Core's answer carries X-Content-Type-Options: False
  verdict   control red — Core's 401 is plain text with its trace header

[3/19] W0c negative control — the gateway's own 404
  request   GET /.well-known/oauth-protected-resource/dial/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff absent
  verdict   control red — the gateway's 404 carries no discriminator header

[4/19] W1 openid-configuration serves the canonical document
  request   GET /.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[5/19] W2 path-insertion aliases serve the canonical document
  request   GET /.well-known/oauth-authorization-server/apps/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-authorization-server/dial/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-authorization-server/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration/apps/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration/dial/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[6/19] W4 unserved well-known paths are the router's 404
  request   GET /.well-known/oauth-protected-resource HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[7/19] W5 closure is method-blind, no CORS
  request   POST /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   OPTIONS /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type text/plain  core-trace PRESENT  nosniff absent
  request   HEAD /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[8/19] W6 precedence: AS, toolset, and app documents still served
  request   GET http://localhost:8090/.well-known/oauth-authorization-server
  status    200
  issuer    http://localhost:8090
  authorization_endpoint   http://localhost:8090/dial/authorize
  token_endpoint           http://localhost:8090/dial/token
  jwks_uri                 http://localhost:8090/dial/jwks.json
  verdict   green — the flat metadata is served, on the public origin
  request   GET http://localhost:8090/.well-known/oauth-protected-resource/dial/notion/mcp
  status    200
  resource  http://localhost:8090/dial/notion/mcp
  servers   ['http://localhost:8090']
  kind      absent
  verdict   green — the toolset's metadata is served on the public origin
  request   GET http://localhost:8090/.well-known/oauth-protected-resource/apps/skills-demo/mcp
  status    200
  resource  http://localhost:8090/apps/skills-demo/mcp
  scopes    []
  verdict   green — the app's metadata is served on the public origin

[9/19] W7 Core's templates through the front door equal Core direct
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  (second request: Core direct, outside the router)
  request   GET /.well-known/oauth-protected-resource/v1/deployments/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-protected-resource/v1/deployments/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  (second request: Core direct, outside the router)
  verdict   green — Core's templates through the front door equal Core direct

[10/19] W8 off-template shapes under Core's prefix are closed
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/tools HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-protected-resource/v1/other HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[11/19] W10a normalization: into the alias location, the document
  request   GET /.well-known/openid-configuration/x/../y HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[12/19] W10b normalization: out of the alias location, the closure
  request   GET /.well-known/openid-configuration/../unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[13/19] W10c normalization: into the Core location from outside its raw spelling, the closure
  request   GET /.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration/%2e%2e/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration/%2E%2E/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration/..%2Foauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[14/19] W10d normalization: out of the namespace into the catch-all, the closure
  request   GET /.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/unknown/%2e%2e/%2e%2e/v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /%2Ewell-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET //.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /./.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[15/19] W10e normalization: decoded trailing line break, the closure
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp%0A HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration%0A HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[16/19] W10f normalization: into a gateway location, the gateway's answer (recorded)
  request   GET /.well-known/x/../../dial/token HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff absent
  recorded  the gateway's answer: status 404
  verdict   green — the raw spelling never reaches Core

[17/19] W10g normalization: into a data-path location, the data path's refusal (recorded)
  request   GET /.well-known/x/../../apps/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  recorded  the data-path's answer: status 404
  verdict   green — the raw spelling never reaches Core

[18/19] W12 served locations' end edges are closed
  request   GET /.well-known/oauth-authorization-serverX HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/openid-configuration.json HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAILED    (cell detail elided; each request's answer is the line above it)

[19/19] W13 path-appended forms are the data path's refusal
  request   GET /apps/skills-demo/mcp/.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  request   GET /apps/skills-demo/mcp/.well-known/oauth-protected-resource HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  request   GET /dial/notion/mcp/.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  request   GET /dial/notion/mcp/.well-known/oauth-protected-resource HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  verdict   green — path-appended forms are the router's refusal, not Core's

=== battery verdict ===
  pass      negative control — Core's own challenge
  pass      W0 negative control — Core's own answer on a discovery path
  pass      W0c negative control — the gateway's own 404
  FAIL      W1 openid-configuration serves the canonical document
  FAIL      W2 path-insertion aliases serve the canonical document
  FAIL      W4 unserved well-known paths are the router's 404
  FAIL      W5 closure is method-blind, no CORS
  pass      W6 precedence: AS, toolset, and app documents still served
  pass      W7 Core's templates through the front door equal Core direct
  FAIL      W8 off-template shapes under Core's prefix are closed
  FAIL      W10a normalization: into the alias location, the document
  FAIL      W10b normalization: out of the alias location, the closure
  FAIL      W10c normalization: into the Core location from outside its raw spelling, the closure
  FAIL      W10d normalization: out of the namespace into the catch-all, the closure
  FAIL      W10e normalization: decoded trailing line break, the closure
  pass      W10f normalization: into a gateway location, the gateway's answer (recorded)
  pass      W10g normalization: into a data-path location, the data path's refusal (recorded)
  FAIL      W12 served locations' end edges are closed
  pass      W13 path-appended forms are the data path's refusal

11 of 19 probes failed
```

## Regex and mechanism details, verified on the router's image

`nginx -t` inside the router container (`nginx:1.27-alpine`, nginx 1.27.5) is clean with
the full configuration, so every new regex compiles as written. Each unverified detail
worked as designed, so there is **no deviation from the design's router shape**:

- **`\z` in a location regex.** `location ~ ^/\.well-known/(oauth-authorization-server|openid-configuration)(/|\z)`
  compiles and behaves as an end anchor. Mutating it to `$` makes W10e fail (see the
  one-off mutation table below), which shows the anchor is load-bearing and that `$` does
  match before a decoded trailing line break, as the design says.
- **`$)` in a map key.** The `$wk_raw_spelling` pattern ends `(?:/|%2[Ff]|\?|$)`. nginx
  does not interpolate a variable in a map key, and the `$` is the PCRE anchor; W10d passes
  on every spelling and fails when the check is disabled.
- **The lookahead.** `(?=/)` in the prefix loop compiles (nginx's PCRE accepts it) and the
  merged-slash and `.`-segment spellings (`//.well-known/...`, `/./.well-known/...`) are
  refused.
- **nginx's treatment of `%2e%2e`.** nginx normalizes `%2e%2e`, `%2E%2E`, and `..%2F` to a
  parent segment when it selects a location, exactly as for a literal `..`, and forwards
  the raw bytes. The W10c cells show the normalized selection of the Core location and the
  gate's refusal on the raw spelling; W10d's `%2e%2e/%2e%2e` cell and the `%2Ewell-known`
  cell show the same on the catch-all. No cell was refused `400` by nginx itself.

## Re-test after the implementation (`--group wellknown`)

Router and gateway rebuilt from this tree, beside the same Core stand-in. Every row
passes on the first run; the controls pass first.

```text
[1/19] negative control — Core's own challenge
  request   GET http://localhost:8081/v1/toolset/notion/mcp  (direct to Core, outside the router)
  status    401
  challenge 'Bearer resource_metadata="http://localhost:8081/.well-known/oauth-protected-resource/v1/toolset/notion/mcp"'
  verdict   control red — Core's own challenge names its own metadata

[2/19] W0 negative control — Core's own answer on a discovery path
  request   GET /.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  (direct to Core, outside the router)
  record    Core's answer carries X-Content-Type-Options: False
  verdict   control red — Core's 401 is plain text with its trace header

[3/19] W0c negative control — the gateway's own 404
  request   GET /.well-known/oauth-protected-resource/dial/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff absent
  verdict   control red — the gateway's 404 carries no discriminator header

[4/19] W1 openid-configuration serves the canonical document
  request   GET /.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  verdict   green — the OpenID Connect location serves the canonical document

[5/19] W2 path-insertion aliases serve the canonical document
  request   GET /.well-known/oauth-authorization-server/apps/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  request   GET /.well-known/oauth-authorization-server/dial/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  request   GET /.well-known/oauth-authorization-server/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  request   GET /.well-known/openid-configuration/apps/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  request   GET /.well-known/openid-configuration/dial/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  request   GET /.well-known/openid-configuration/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  verdict   green — every path-insertion form serves the canonical document

[6/19] W4 unserved well-known paths are the router's 404
  request   GET /.well-known/oauth-protected-resource HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — every unserved well-known path is the router's 404

[7/19] W5 closure is method-blind, no CORS
  request   POST /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   OPTIONS /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   HEAD /.well-known/unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — POST, OPTIONS, HEAD get the router's 404, no CORS header

[8/19] W6 precedence: AS, toolset, and app documents still served
  request   GET http://localhost:8090/.well-known/oauth-authorization-server
  status    200
  issuer    http://localhost:8090
  authorization_endpoint   http://localhost:8090/dial/authorize
  token_endpoint           http://localhost:8090/dial/token
  jwks_uri                 http://localhost:8090/dial/jwks.json
  verdict   green — the flat metadata is served, on the public origin
  request   GET http://localhost:8090/.well-known/oauth-protected-resource/dial/notion/mcp
  status    200
  resource  http://localhost:8090/dial/notion/mcp
  servers   ['http://localhost:8090']
  kind      absent
  verdict   green — the toolset's metadata is served on the public origin
  request   GET http://localhost:8090/.well-known/oauth-protected-resource/apps/skills-demo/mcp
  status    200
  resource  http://localhost:8090/apps/skills-demo/mcp
  scopes    []
  verdict   green — the app's metadata is served on the public origin

[9/19] W7 Core's templates through the front door equal Core direct
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  (second request: Core direct, outside the router)
  request   GET /.well-known/oauth-protected-resource/v1/deployments/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  request   GET /.well-known/oauth-protected-resource/v1/deployments/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8081)
  answer    status 200  type application/json  core-trace PRESENT  nosniff absent
  (second request: Core direct, outside the router)
  verdict   green — Core's templates through the front door equal Core direct

[10/19] W8 off-template shapes under Core's prefix are closed
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/tools HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/oauth-protected-resource/v1/other HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — off-template shapes under Core's prefix are the router's 404

[11/19] W10a normalization: into the alias location, the document
  request   GET /.well-known/openid-configuration/x/../y HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 200  type application/json  core-trace absent  nosniff absent
  verdict   green — the raw spelling never reaches Core

[12/19] W10b normalization: out of the alias location, the closure
  request   GET /.well-known/openid-configuration/../unknown HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — the raw spelling never reaches Core

[13/19] W10c normalization: into the Core location from outside its raw spelling, the closure
  request   GET /.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/openid-configuration/%2e%2e/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/openid-configuration/%2E%2E/oauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/openid-configuration/..%2Foauth-protected-resource/v1/toolset/notion/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — the raw spelling never reaches Core

[14/19] W10d normalization: out of the namespace into the catch-all, the closure
  request   GET /.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/unknown/%2e%2e/%2e%2e/v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /%2Ewell-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET //.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /./.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — the raw spelling never reaches Core

[15/19] W10e normalization: decoded trailing line break, the closure
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp%0A HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/openid-configuration%0A HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — the raw spelling never reaches Core

[16/19] W10f normalization: into a gateway location, the gateway's answer (recorded)
  request   GET /.well-known/x/../../dial/token HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff absent
  recorded  the gateway's answer: status 404
  verdict   green — the raw spelling never reaches Core

[17/19] W10g normalization: into a data-path location, the data path's refusal (recorded)
  request   GET /.well-known/x/../../apps/skills-demo/mcp HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  recorded  the data-path's answer: status 404
  verdict   green — the raw spelling never reaches Core

[18/19] W12 served locations' end edges are closed
  request   GET /.well-known/oauth-authorization-serverX HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/openid-configuration.json HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /.well-known/oauth-protected-resource/v1/toolset/notion/mcp/ HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  verdict   green — the served locations' end edges are the router's 404

[19/19] W13 path-appended forms are the data path's refusal
  request   GET /apps/skills-demo/mcp/.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  request   GET /apps/skills-demo/mcp/.well-known/oauth-protected-resource HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  request   GET /dial/notion/mcp/.well-known/openid-configuration HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  request   GET /dial/notion/mcp/.well-known/oauth-protected-resource HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type text/html  core-trace absent  nosniff absent
  verdict   green — path-appended forms are the router's refusal, not Core's
=== battery verdict ===
  pass      negative control — Core's own challenge
  pass      W0 negative control — Core's own answer on a discovery path
  pass      W0c negative control — the gateway's own 404
  pass      W1 openid-configuration serves the canonical document
  pass      W2 path-insertion aliases serve the canonical document
  pass      W4 unserved well-known paths are the router's 404
  pass      W5 closure is method-blind, no CORS
  pass      W6 precedence: AS, toolset, and app documents still served
  pass      W7 Core's templates through the front door equal Core direct
  pass      W8 off-template shapes under Core's prefix are closed
  pass      W10a normalization: into the alias location, the document
  pass      W10b normalization: out of the alias location, the closure
  pass      W10c normalization: into the Core location from outside its raw spelling, the closure
  pass      W10d normalization: out of the namespace into the catch-all, the closure
  pass      W10e normalization: decoded trailing line break, the closure
  pass      W10f normalization: into a gateway location, the gateway's answer (recorded)
  pass      W10g normalization: into a data-path location, the data path's refusal (recorded)
  pass      W12 served locations' end edges are closed
  pass      W13 path-appended forms are the data path's refusal

all 19 probes passed
```

## The one-off mutation runs (negative controls for the detectors)

Each mutation was applied to a restored conf, the router reloaded, the group run, and the
conf restored byte for byte (its checksum was compared against the intended state after the
last mutation, and the final run on the restored conf passed all 19 rows). **None of these
mutations is committed.**

**The precedence detector (the `^~` run).** The closure rewritten as
`location ^~ /.well-known/`. The gateway control W0c fails first, because the shadowed
gateway location now answers the closure's `404` (the closure's header is present), and a
failed control stops the battery, so W6 was then run on its own against the mutated conf:

```text
request   GET http://localhost:8090/.well-known/oauth-authorization-server
  status    200
  issuer    http://localhost:8090
  authorization_endpoint   http://localhost:8090/dial/authorize
  token_endpoint           http://localhost:8090/dial/token
  jwks_uri                 http://localhost:8090/dial/jwks.json
  verdict   green — the flat metadata is served, on the public origin
  request   GET http://localhost:8090/.well-known/oauth-protected-resource/dial/notion/mcp
  status    404
W6 RESULT: FAIL -> the protected-resource document answered 404
```

The exact AS location still answers (an exact match, which `^~` does not affect) and the
toolset document gets the closure's `404`, so W6 fails as designed. On the restored conf,
W6 alone:

```text
W6 RESULT: pass
```

**The raw-URI guards and the end anchor (extra negative controls).**

| Mutation | Rows that fail; the rest pass |
|---|---|
| the catch-all's check disabled (`if ($wk_raw_spelling = "x")`) | W10d |
| the Core location's gate disabled (`if ($core_prm_raw = "x")`) | W10c, W10e |
| the alias regex's `\z` replaced by `$` | W10e |
| the closure written as `^~` | W0c (control) stops the battery; W6 fails when run alone |

Each guard is therefore detected by a row that fails without it.

## Security-gate fix round — SF-1, failing first

The security review (`security-review.md`) found that the catch-all's `$wk_raw_spelling`
check accepted only a literal `/` as the separator before `.well-known`, so a leading
`%2F` slipped through. The detector comes first: two cells were added to W10(d) in
`scripts/probe_routing.py` (`/%2F.well-known/unknown/../../v1/x` and
`/%2E%2F.well-known/unknown/../../v1/x`).

Environment: the same shape as the runs above (this repository's compose project, built
from the tree, beside a throwaway local stand-in for Core outside the repository; the
stand-in sets Core's trace header and answers its plain-text `401`).

**Against the conf as it stood before the fix** (the two new cells only; the other five
W10(d) cells and every other row passed):

```text
  request   GET /%2F.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  request   GET /%2E%2F.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 401  type text/plain  core-trace PRESENT  nosniff absent
  FAIL      W10d normalization: out of the namespace into the catch-all, the closure
1 of 19 probes failed
```

**The fix.** `$wk_raw_spelling`'s pattern became
`^/(?:(?:\.|%2[Ee])?(?:/|%2[Ff]))*(?:\.|%2[Ee])(?:w|%77)…(?:/|%2[Ff]|\?|$)`: each prefix
iteration is an optional dot then a separator spelled `/` or `%2F`. `nginx -t` on
`nginx:1.27-alpine`: syntax ok, test successful.

**After the fix:**

```text
  request   GET /%2F.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  request   GET /%2E%2F.well-known/unknown/../../v1/x HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  pass      W10d normalization: out of the namespace into the catch-all, the closure
all 19 probes passed
```

Also sent by hand after the fix (status, then whether the answer was the closure's
`nosniff` or Core's trace header): `/.%2F.well-known/unknown/../../v1/x`,
`/%2f.well-known/unknown/../../v1/x`, and `/%2F%2F.well-known/unknown/../../v1/x` all got
the closure's `404`. The non-namespace controls `/v1/x`, `/v1/.well-known/x`,
`/x/.well-known`, `/.wellknown/x`, `/.%2Fwell-known/x`, and `/x/../.well-known/unknown/../../v1/x`
still reached Core (`401` with its trace header), as the definition requires.

The full `--no-token` battery on the fixed conf: all 29 probes passed (2 skipped: the
token-bearing query-string rows).

## General-review fix round - strengthened checks, failing first

The general review (`general-review.md`) found two probe assertions weaker than their
scenarios. W7 compared only the status (SF-B). W10 cells (f) and (g) did not fail when the
router's closure answered in place of the gateway or the data path (SF-C). Both were
strengthened, and each is shown failing under a deliberate mutation. Also changed in the
probe: W5's `OPTIONS` is a real preflight (`Origin` and `Access-Control-Request-Method`);
the W10 closure cells require the router's `404` (the `400` allowance is gone, since no
cell steps above the root); the token-row skip list and the row names share two constants;
and W7's banner prints before the Core-direct request.

Environment: the same shape as the runs above (this repository's compose project, built
from the tree, beside a throwaway local stand-in for Core outside the repository). No
mutation is committed.

**SF-C: a router answer on the W10(f) path.** One location added to the router conf,
`location = /dial/token`, answering the closure's `404` with the discriminator header. The
conf was reloaded and the group run:

```text
[16/19] W10f normalization: into a gateway location, the gateway's answer (recorded)
  request   GET /.well-known/x/../../dial/token HTTP/1.1   (verbatim, to http://localhost:8090)
  answer    status 404  type application/json  core-trace absent  nosniff present
  FAILED    W10f: GET /.well-known/x/../../dial/token: the router's closure answered; the request belongs to the gateway
1 of 19 probes failed
```

The same location retargeted to `/apps/<app>/mcp` fails W10(g) with "the request belongs to
the data-path"; every other row passed in both runs. The conf was then restored from a
byte copy, and its checksum matched the intended state.

**SF-B: a front-door answer that differs from Core's own.** The stand-in was changed to
alter its answer only for requests that did not arrive on Core's own port, so the
front-door and direct answers differ:

| Mutation | W7 result |
|---|---|
| content type `text/plain` via the front door | FAIL: "content type 'text/plain' via the front door, 'application/json' direct" |
| `bearer_methods_supported` member dropped via the front door | FAIL: "members [...] via the front door, [... 'bearer_methods_supported' ...] direct" |
| `resource` ending in `/v1/other/mcp` | FAIL: "resource ... does not end with '/v1/toolset/notion/mcp'" |

Every other row passed in each run. With the unmodified stand-in restored, the group
passed all 19 rows.

**After the fix round, on a clean boot:** `probe_routing.py --group wellknown` passed all
19 probes, and `probe_routing.py --no-token` passed all 29 (2 skipped).
