# Front routing reference

The front router is an nginx in this repository's compose (`mcp-signin-router`, config at
[`router/nginx.conf`](../router/nginx.conf)) and the single public origin harnesses see. It
exists because the public surface has two owners: the gateway owns the authorization
surface, and Core owns the MCP data path and its own API. One origin in front of both is
what makes a harness's view look like one server.

Everything below is the map, the one place the router does more than split traffic, and
the checks that keep the two in step.

## The location map

Order matters: nginx evaluates regex locations in the order they appear, so every
`location` below is listed in its configured order.

| Location | Goes to | Why |
|---|---|---|
| `= /healthz` | the gateway | The composed stack's health probe measures the link the router depends on, not just its own process. |
| `= /.well-known/oauth-authorization-server` | the gateway | The flat RFC 8414 document. One exact path, and Core serves nothing there. |
| `~ ^/\.well-known/(oauth-authorization-server\|openid-configuration)(/\|\z)` | the gateway | The same document at every other location a discovering client may try for this issuer: the OpenID Connect location and the path-insertion form of both. The gateway answers all of them from the one builder. The end anchor is `\z`, not `$`: PCRE's `$` also matches before a decoded trailing line break. |
| `~ ^/\.well-known/oauth-protected-resource/dial/` | the gateway | Each toolset's RFC 9728 document, served from the resource's own path so a client following a challenge lands on the document for the resource it was challenged for. |
| `~ ^/\.well-known/oauth-protected-resource/apps/` | the gateway | Each app's RFC 9728 document, the apps twin of the toolset route. The `/apps/` prefix is disjoint from every `/dial/` alternation, so ordering against the toolset regex is irrelevant. |
| `~ ^/\.well-known/oauth-protected-resource/v1/(toolset\|deployments)/.+/mcp$` | Core, only when `$core_prm_raw` is set (`proxy_pass http://core`) | Core's own two protected-resource templates, the only `/.well-known/` paths Core serves. Core's own challenge can point a direct-to-Core client back at this host for them. End-anchored at `/mcp` because those two templates are all Core serves there. The regex nominates on the normalized path; the raw-URI map decides, and a request that is not literally one of the templates goes to the closure. A Core release that adds a `/.well-known/` route re-opens this location. |
| `= /.well-known` and `/.well-known/` (a plain prefix) | the router's closed `404` | The closed namespace: every `/.well-known/` path no location above serves. A prefix location, used only when no regex matches; never `^~`. See the section below. |
| `~ ^/dial/(callback\|consent\|jwks\.json\|authorize\|token\|register\|revoke)(/\|$)` | the gateway | The OAuth endpoints the gateway owns, plus the JWKS Core verifies minted tokens against, the two flow callbacks, and the consent action the decision page posts to. |
| `~ ^/dial/` | Core, via the `$dial_target` map (`http://core$dial_target$is_args$args`) | The toolset MCP data path, direct to Core — the gateway is deliberately not on it. The location is a **prefix** match, but the **map**, not the location regex, decides routability: `$dial_target` carries the segment grammar and the `/mcp`-suffix match domain over the raw request URI, and is empty for any request the grammar does not match, which the `if ($dial_target = "") { return 404; }` refuses without forwarding. |
| `~ ^/apps/` | Core, via the `$apps_target` map (`http://core$apps_target$is_args$args`) | The apps MCP data path, proxied to Core's deployments MCP path. The same prefix-location-behind-a-map shape, its own grammar and match domain. The kind lives in the path, so a toolset and an app that share a name never collide. |
| `/` | Core, unless the raw path is spelled in the `/.well-known` namespace (`$wk_raw_spelling`), which goes to the closure | Everything else, unchanged: Core's own API and its own toolset routes keep working for clients that never involve the gateway. The one thing it refuses is a raw path whose leading segment is `.well-known` in some spelling, which normalizes out of the namespace but would still be forwarded under that name. |

Three properties of the map are load-bearing and easy to lose:

- **The authorization-surface locations precede the data-path locations.** A toolset whose
  first path segment is a reserved name (`authorize`, `token`, `consent`, …) would
  otherwise have its `/dial/authorize/…` matched by the data-path prefix location — but the
  authorization-surface location matches first, so its traffic could never reach Core. The
  gateway refuses to start with such a first segment mapped. The reserved-name rule is a
  **first-segment** rule only: a stored resource's first segment is its type segment
  (`toolsets`, `applications`), so a reserved name *deeper* in a path
  (`/dial/toolsets/public/token/mcp`) is a legal, routable resource path, and the data-path
  location routes it. The apps namespace has no reserved names — nothing the gateway owns
  is served under an `/apps/{segment}/…` path.
- **The data-path routes are decided by a raw-URI map, not by the location regex.** The
  location is now a bare prefix (`^/dial/`, `^/apps/`) because a decoded location capture
  corrupts the names this change exists to serve (below). The map carries the grammar and
  the `/mcp` match domain, and the location's `if` refuses what the map does not match.
- **The map's match domain is the whole raw request URI.** The grammar is anchored at both
  ends and admits nothing after `/mcp` but an optional `?query` tail, so a query-bearing
  session-resume request (`…/mcp?sessionId=<id>`) matches and a post-`/mcp` path tail
  (`…/mcp/extra`) does not — the capture cannot alias a longer path onto the data path.

The status location (`~ ^/dial/[a-z0-9-]+/status$`) is **removed**: the sign-in status
surface leaves the gateway entirely, both namespaces, so the path is no longer served by
any gateway handler. With the data-path locations now bare prefixes (`~ ^/dial/`,
`~ ^/apps/`) whose routability a raw-URI map decides, a non-MCP path under either prefix —
`/dial/{name}/status`, `/apps/{name}/status` — does not match the map's grammar (which
requires the `/mcp` suffix), so the location's `if ($dial_target = "") { return 404; }`
refuses it with a bare 404 and never forwards it. The router and the gateway must deploy
together for the removal to land atomically.

### Reserved toolset names

`authorize`, `token`, `register`, `revoke`, `callback`, `consent`, `jwks.json`.

The list mirrors the authorization-surface alternation above verbatim, so the startup
guard and the routing stay in step when either changes. `jwks.json` is listed for that
fidelity although the segment grammar's decoded rules refuse its dot.

### The raw-URI map, and why decoded capture cannot be the mechanism

The data path forwards **raw bytes**, and the mechanism is one `map` per kind keyed on
`$request_uri` — the raw, never-decoded request URI:

```nginx
map $request_uri $dial_target {
    default "";
    "~^/dial/(?<tseg>(?:[A-Za-z0-9_~.-]|%[0-9A-Fa-f][0-9A-Fa-f])*(?:[A-Za-z0-9_~-]|%[0-9A-Fa-f][0-9A-Fa-f])(?:/(?:[A-Za-z0-9_~.-]|%[0-9A-Fa-f][0-9A-Fa-f])*(?:[A-Za-z0-9_~-]|%[0-9A-Fa-f][0-9A-Fa-f]))*)/mcp(\?.*)?$" /v1/toolset/$tseg/mcp;
}

location ~ ^/dial/ {
    if ($dial_target = "") {
        return 404;
    }
    proxy_pass http://core$dial_target$is_args$args;
    # ... buffering off, proxy_hide_header + add_header (below)
}
```

The apps map and location are the twin, over the `/apps/` prefix and Core's
`/v1/deployments/` path with its own `$aseg` capture.

**Why not a decoded location capture.** nginx matches `location` regexes against its
**normalized, decoded** URI, and a variable `proxy_pass` does not re-escape a captured
value. Both were measured on the router's image
(`openspec/changes/archive/2026-11-13-front-door-addressing-and-redirect/evidence/nginx-mechanism-probe.md`,
run against `nginx:1.27-alpine`): a permissive decoded multi-segment capture answers a
request for a name with a space (`…/a%20b/mcp`) with **400 from nginx itself**, forwards
`%3F` and `%23` as literal `?` and `#` in the request-target where any conforming server
re-splits path from query, forwards `%25` as a raw `%` (an invalid escape at Core's door),
forwards non-ASCII as raw undelimited bytes, and **merges `%2F` onto a real `/`**, splitting
one segment into two. Decoded capture is not a lossy mechanism; it is a defect generator,
and it breaks exactly the matrix cells (names with spaces, `?`, `#`, `%`, non-ASCII,
multi-segment paths) the front door exists to serve. Keying the map on the raw URI and
forwarding the raw captured bytes makes forwarding **byte-faithful**: the request Core
receives is byte-identical to the one the client sent, and Core's answer through the front
door is Core's answer (measured: `%20`, `%2F`, `%3F`, `%23`, `%25`, `%C3%A9`, multi-segment
and leading-dot paths all forwarded verbatim).

**The grammar is a grammar, not a wildcard.** Each segment is unreserved characters
(`[A-Za-z0-9._~-]`) or percent-escapes (`%[0-9A-Fa-f][0-9A-Fa-f]`) — the unreserved class
**excludes** `%`, so the `%XX` alternative is unambiguous and no overlapping alternates
exist, which is the ReDoS discipline. A segment ends in a non-dot atom, so a trailing dot
is refused; a whole-segment `.`/`..` and an empty segment cannot match. Brace quantifiers
(`{n}`) are avoided because nginx's parser rejects them here, so the doubled character
classes stand in. The pathological-URI probe row asserts a fast refusal, and the
`large_client_header_buffers 4 8k` bound (stated explicitly in the server block) caps the
input length upstream of the regex. On a match the map yields the Core target built from
the raw captured bytes; on no match it yields the empty string, and the location's
documented-safe `if ($target = "") { return 404; }` refuses the request without forwarding.

**The division of labor with the gateway's guard.** The map and the gateway's path guard
are a stated division, not two encodings of one rule. The map is a **routability filter
over the wire form**: it admits every `%XX`-escaped spelling, whatever the escapes decode
to. The gateway's guard (`gateway/settings.py`) is the **authority over the decoded form**:
it decodes each offered segment (strict UTF-8), refuses `{`, `}`, `"`, control characters,
trailing dots, `.`/`..`/empty segments, and over-length or over-depth paths, and applies the
reserved-first-segment rule. One class is therefore asymmetric by design and documented as
such: a wire-conforming spelling whose decoded content the guard refuses (an encoded
forbidden character `%7B`, an escaped trailing dot `%2e`, an over-length path) is forwarded
on the data path by the router and refused at discovery and the authorization/token
endpoints by the guard. The router-synthesized 401 challenge for such a call names a
document the gateway answers 404 — a dead end by design — and the outcome is
same-answer-as-Core: Core refuses these names at resolution too. The lockstep probes assert
this asymmetry itself, never an agreement that does not exist.

### The caller's-spelling challenge rule

The map's named capture (`$tseg`, `$aseg`) is visible to the challenge map's value
template — a map regex's captures become variables — so **one capture feeds both the Core
target and the challenge**, and the two cannot disagree about which path was called. The
challenge therefore quotes the client's **own spelling**, encoded characters included: a
client challenged for `/dial/toolsets/public/challenge%20me/mcp` is pointed at the metadata
document for exactly that encoded spelling (measured through the stacked maps in the
probe). The target map and the challenge map are both keyed as they are because the
challenge's value differs by capture variable (`$tseg` against `$aseg`) and a map's value
is a fixed template per variable, so one map could not quote both metadata paths.

### Query strings, and why `$is_args$args` is required

A `proxy_pass` containing a variable suppresses nginx's own query-string append, so
`$is_args$args` is not cosmetic: a streamable-HTTP session resumes with
`?sessionId=<id>`, and without it the parameter would never reach Core. The probe battery
below asserts on the URI Core recorded receiving, which is the only place the loss is
visible — a proxy that dropped the parameter would still return the response Core produced
without it.

## The closed well-known namespace

The router answers every `/.well-known/` path that no discovery location serves with a
fixed JSON `404` (`{"detail":"Not Found"}`, `application/json`) and never forwards it.
Left to fall through to Core, such a path gets Core's authentication filter's `401`, which a
discovering client reads as "discovery itself needs a credential" and abandons the server.
The answer is the gateway's own unrouted-`404` shape, so under this namespace a client sees
one `404` body whichever side refuses; elsewhere the data path's refusal is nginx's default
HTML page. The closure answers every method, because `return` runs before any handler: a
`POST` body is never read, and an `OPTIONS` preflight gets the `404` with no CORS header.

- **Precedence.** The closure is two plain prefix locations (`= /.well-known` and
  `/.well-known/`), which nginx uses only when no regex location matches. Every served
  discovery location is a regex or an exact location, so none can be shadowed and the order
  of the regexes cannot move the closure in front of one. **Never write it as `^~`:** that
  skips regex matching for every path under the prefix and would answer `404` for the
  toolset and app documents and the aliases. The probe battery's row W6 fails on that
  mutation (it was run once, as a one-off negative control, and the conf restored).
- **The discriminator header.** nginx drops the upstream's `Server` and `Date` headers, so
  through the front door the router's `404` and the gateway's own `404` would otherwise be
  byte-identical. The closure carries `X-Content-Type-Options: nosniff`, which the gateway's
  JSON answers never carry. It is `always` because nginx otherwise attaches `add_header` to
  `2xx` and `3xx` answers only. The probe rows read the header to tell the router's `404`
  from the gateway's.
- **The raw-URI checks.** nginx selects a location on the normalized URI but forwards the
  raw one, so a raw spelling can select a location and deliver another path upstream. Two
  checks close that on the raw `$request_uri`, each handing a refusal to the closure by an
  internal redirect (`rewrite ^ /.well-known/ last;`), so the answer is defined once.
  `$core_prm_raw` gates the Core location: it forwards only a raw URI that is itself one of
  Core's two templates, so a spelling that merely normalizes onto a template (dot segments,
  an encoded character in `toolset`, a decoded trailing line break) never reaches Core.
  `$wk_raw_spelling` guards the catch-all: a raw path whose leading segment is `.well-known`
  in any spelling nginx's normalization maps onto it (merged slashes, `.` segments, `%2F` as a
  separator, a percent-encoded character in the name) is answered by the closure rather than forwarded
  to Core. The check is a prefix test, so a legitimate Core path that merely contains the
  string is untouched, and a raw path whose first segment is outside the namespace (for
  example `/x/../.well-known/…`) is forwarded raw by definition.
- **The one forwarded Core exception.** Core serves exactly two unauthenticated
  `/.well-known/` templates (`oauth-protected-resource/v1/toolset/<id>/mcp` and
  `.../v1/deployments/<id>/mcp`), and the closure forwards exactly those, on their raw
  spelling. The exception depends on Core's route set: a DIAL Core release that adds a
  `/.well-known/` route re-opens it.
- **Out of scope.** The path-appended forms (`/apps/<app>/mcp/.well-known/...`) are outside
  the namespace; the data-path location refuses them with its own `404`, never Core's
  answer (row W13 pins that).

## The 401 challenge, and the `$mcp_origin` rule

Every 401 on the toolset MCP path is answered with the **gateway's** challenge, and Core's
own `WWW-Authenticate` never reaches the client. Core answers such a call by relaying the
*upstream* authorization server's challenge — the one Core itself received for a user
whose credential it has not stored — and no harness can complete a sign-in against it; a
harness that tried would fail and discard its token. The gateway's protected-resource
document describes the authorization server that *can* complete the sign-in, so that is
what a client must see.

The mechanism is `proxy_hide_header WWW-Authenticate` plus an `add_header` whose value
comes from a `map $status`, so the gateway's challenge is emitted on a 401 and on nothing
else. Each data path has its own map, quoting its own resource's metadata path from the
**data-path map's named capture** (`$tseg` / `$aseg` — the client's own spelling, per the
caller's-spelling rule above):

```nginx
map $status $mcp_challenge {
    default "";
    401     'Bearer resource_metadata="$mcp_origin/.well-known/oauth-protected-resource/dial/$tseg/mcp"';
}

map $status $apps_mcp_challenge {
    default "";
    401     'Bearer resource_metadata="$mcp_origin/.well-known/oauth-protected-resource/apps/$aseg/mcp"';
}

location ~ ^/dial/ {
    if ($dial_target = "") { return 404; }
    proxy_pass http://core$dial_target$is_args$args;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_hide_header WWW-Authenticate;
    add_header WWW-Authenticate $mcp_challenge always;
}

location ~ ^/apps/ {
    if ($apps_target = "") { return 404; }
    proxy_pass http://core$apps_target$is_args$args;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_hide_header WWW-Authenticate;
    add_header WWW-Authenticate $apps_mcp_challenge always;
}
```

**The capture is the data-path map's, not the location's.** `$tseg` and `$aseg` are the
named captures of the `$request_uri` maps (a map regex's captures become variables), so
the challenge quotes the exact raw path the map routed — the same value that built the Core
target, which is why the two cannot disagree. A grammar-refused request never reaches the
challenge: the `if` answers 404 with no header (the challenge map's default is empty and
nginx omits empty-valued headers), so the challenge fires on 401 only.

**A second map for the apps path, not one parameterized map.** The header value differs by
capture variable (`$tseg` against `$aseg`), and a map's value is a fixed template per
variable — so one map could not quote both metadata paths. Each map is keyed on the same
`$status` and reads its own path's capture, so an apps 401 always names the **apps**
document and a toolset 401 the toolset's; a mismatch would point a strict client at a
document whose `resource` differs from the challenged resource, and its sign-in could not
complete.

**Both halves are required.** Without the hide, Core's challenge reaches the client beside
the gateway's, and a client that reads the first — or the list — sees one it cannot
complete. Without the synthesized header, the 401 carries no challenge at all and a client
cannot tell where to authenticate.

**`$mcp_origin` is a configured origin, never `$host`.** `$host` drops the port, so behind
TLS on a non-default port — or on plain http on 8090, as locally — a client that followed
the challenge would fetch metadata from a URL this router does not serve. The configured
value must equal the gateway's `GATEWAY_PUBLIC_ORIGIN`: the router publishes that origin,
the gateway mints its tokens with it as `iss`, and every discovery document in it is
spelled with it.

**Why not `error_page 401 = @location`.** The obvious spelling — `proxy_intercept_errors
on` with `error_page 401 = @mcp_challenge` — does not satisfy the property. Measured on
this nginx image, an intercepted 401 re-serves the upstream response's headers, so Core's
challenge survives into the rewritten response and `proxy_hide_header` has no effect on
it; the client receives two challenges. The named-location form cannot hide the upstream's
header, so it cannot be the mechanism. The property is the requirement — one challenge,
the gateway's — and the `map` form is what delivers it.

## Public-origin byte cap

The server block states `client_max_body_size 16384` explicitly. nginx otherwise applies
its own implicit 1 MB default, which would be the real bound on the public surface while
appearing in no configuration — a value nobody chose and nobody can find. The three
unauthenticated body-bearing endpoints the gateway owns (`/dial/register`, `/dial/token`,
`/dial/revoke`) each cap their own body at 8192 bytes while reading it, so this is the
defense-in-depth bound in front of them, and a request over it is refused by the router
with 413 and never forwarded. It is deliberately larger than the endpoints' caps, so the
two are separate layers: this one bounds what reaches the gateway at all, and a body under
it that is over an endpoint's own cap is refused by the gateway while reading, with that
endpoint's OAuth error shape at 400. Sizing the two the same would give up that error
contract for every oversize form, because the router's 413 carries no OAuth shape. The MCP
data path shares the bound rather than being exempt:
one value every request has is easier to reason about than one per location, and an MCP
JSON-RPC call is far inside it.

## The peer identity, and why 8091 is never published

`X-Real-IP` is this router's own statement about the peer it accepted the connection from
(`$remote_addr`), which is what makes it trustworthy: a client cannot set it, because a
client's traffic reaches the gateway only by crossing this router. The gateway reads that
header to key its per-source rate limit.

That property **depends on the gateway's container port 8091 never being published to a
host**. A request delivered to 8091 directly never crossed this location and carries
whatever `X-Real-IP` its sender chose, so the per-source limit would become a bound the
caller sets. `docker-compose.yml` states the invariant at the gateway service, where the
mapping would be added; this file states it here, where the header's trust is established.
The two are halves of one control.

## Probe battery

[`scripts/probe_routing.py`](../scripts/probe_routing.py) runs against the composed stack
and asserts the map, the challenge, and the query-string survival. Run it with the stack
up:

```bash
wsl -e docker compose up -d
PYTHONUTF8=1 .venv/Scripts/python scripts/probe_routing.py
```

Its probes, in order:

| # | Probe | Assertion |
|---|---|---|
| 1 | **Negative control** — the same toolset URL on Core directly (port 8081, outside the router) | Core's own challenge names Core's protected-resource host. Without this, a rewritten 401 that happened to quote the gateway's origin could be Core's own answer, and the rewrite probe would pass for the wrong reason. |
| 2 | Query string survives the routing | A POST and a GET carrying `?sessionId=<probe>` both appear in Core's own log with the parameter intact. |
| 3 | Flat AS metadata | Served through the front door, its issuer and every endpoint on the public origin. |
| 4 | Per-toolset protected-resource document | Served through the front door, naming the toolset's resource and the single authorization server. |
| 5 | Data-path 401 rewrite | The response carries **exactly one** `WWW-Authenticate`, quoting the gateway's metadata, and no trace of Core's host. |
| 6 | Gateway paths reachable | `/dial/authorize` and `/dial/token` answer as the gateway (an OAuth error document) rather than as Core (404). |

The well-known group runs after the controls, and two more negative controls open it. Every
row goes out through `http.client` with the raw path on the request line, because the usual
client libraries normalize dot segments out of a URL; each row prints the request it sent.
`--group wellknown` runs only the controls and this group (no token needed). `--no-token`
runs every row except the two query-string rows, which need a minted token and Core's
request log.

| # | Probe | Assertion |
|---|---|---|
| W0 | **Negative control (Core)** - `GET /.well-known/openid-configuration` on Core directly | Core's `401`, `text/plain`, with its trace header: the discriminator against Core every later row uses. |
| W0c | **Negative control (gateway)** - `GET /.well-known/oauth-protected-resource/dial/x` through the front door | The gateway's own `404` with no `X-Content-Type-Options` header: the discriminator against the gateway. |
| W1 | `GET /.well-known/openid-configuration` | `200`, byte-identical to the canonical document. |
| W2 | Both path-insertion families, an apps path, a toolset path, and the empty suffix | `200`, byte-identical, `issuer` the public origin. |
| W3 | No OpenID Provider member at any alias | Unit row (`tests/test_discovery.py`). |
| W4 | The root `/.well-known/oauth-protected-resource`, `/.well-known/unknown`, `/.well-known/`, `/.well-known` | The router's `404`, JSON, with the discriminator header, no Core trace header, no `WWW-Authenticate`. |
| W5 | `POST`, `OPTIONS` (sent as a CORS preflight), `HEAD` on a closed path | The router's `404` with the discriminator header and no `Access-Control-*`; `HEAD` has no body. |
| W6 | Precedence: the exact AS location, a toolset document, an app document | Served by the gateway, unchanged. |
| W7 | Core's two protected-resource templates | Same status and content type as Core direct, with Core's trace header; on `200`, the same JSON member names and a `resource` ending in the requested path. |
| W8 | Off-template shapes under Core's prefix (`.../tools`, `.../v1/other`) | The router's `404`. |
| W9 | `HEAD`, `OPTIONS`, `POST` on each alias | Unit row: `405` with `Allow: GET`, no `Access-Control-*`. |
| W10 a-g | Raw spellings that normalize across a namespace edge, both directions, `%2e%2e` and `..%2F` variants, encoded-name, merged-slash and `.`-segment spellings, and a decoded trailing line break | a: the document; b-e: the router's `404`; f: the gateway's answer, recorded; g: the data path's refusal, recorded. No cell reaches Core, and a router closure answer on f or g fails the cell. |
| W12 | `...authorization-serverX`, `openid-configuration.json`, the Core template with a trailing slash | The router's `404`. |
| W13 | `/apps/<app>/mcp/.well-known/...` and the `/dial/` twins | The data path's `404`; never Core's answer. |

The battery's apps rows (added for the apps surface):

| # | Probe | Assertion |
|---|---|---|
| 7 | Apps data-path 401 rewrite | An unauthenticated call on `/apps/<name>/mcp` answers 401 carrying the gateway's challenge naming the **apps** metadata path (`…/apps/<name>/mcp`) and none of Core's. |
| 8 | Apps query string survives | A streamable-HTTP GET with `?sessionId=<id>` on the apps path reaches Core's deployments MCP path with the parameter intact. |
| 9 | Apps metadata route | `/.well-known/oauth-protected-resource/apps/<name>/mcp` is served by the gateway. |
| 10 | Status path refused | `GET /dial/<name>/status` and `GET /apps/<name>/status` do not match the data-path map's grammar (the `/mcp` suffix is required), so the router's `if` refuses them with a bare 404 and no gateway challenge — the status removal made checkable, and the shape the prefix locations produce. |
| 11 | Lockstep: the map and the guard | The three row groups of the division of labor: the shapes both surfaces admit (a stored path, a user-bucket alphanumeric segment — a 401 challenge on the data path, a 200 document at discovery), the shapes both refuse (dot-segments, an empty segment, a trailing dot, a reserved first segment — 404 on both), and the documented asymmetry (an encoded forbidden character `%7B`, an escaped trailing dot `%2e` — forwarded on the data path with a 401 challenge, refused 404 at discovery). |
| 12 | Lockstep: the apps map/guard division | The apps twin: an admitted stored-app path (a 401 challenge on the data path, a 200 document at discovery) and a dot-segment shape refused 404 on both surfaces. |

Probe 5 needs a token Core accepts, so probe 2 **mints one** the way the Stage 0 spike
does, rather than reading a token file: those live ten minutes, and a stale token is not a
routing failure. Core accepts a gateway-shaped token because its `dial-mcp-proxy` provider
entry already points at the spike's JWKS; group 6 repoints that entry at the gateway's own
`/dial/jwks.json`.

The battery exits non-zero on any failure, and the control failing stops it — a later
probe's acceptance means nothing without it.

## What is not yet covered

- **A non-OAuth toolset is a served toolset, and the front-door routing is kind-agnostic.**
  The front door is static nginx: its challenge synthesis is unconditional and lives in the
  data-path location for each kind, so it does not know a toolset's kind and does not need
  to. A non-OAuth toolset's MCP path routes to Core like any other; the *flow* is where the
  kind matters — a toolset whose credential Core already holds (at user or global level)
  short-circuits the upstream stage for any kind, and a toolset with no stored credential and
  a non-OAuth kind is refused on the impossible branch with a plain-language page. So there
  is no per-entry routing exemption to make: the router needs no view of the toolset set, and
  today it has none.
- **Discovery is registry-independent, mirroring Core's own unauthenticated tier, in both
  namespaces.** A protected-resource document is served for every guard-passing resource
  path — phantom and real alike, toolset or app — because Core's own unauthenticated discovery tier
  is likewise registry-independent (its auth check precedes any registry lookup, so a phantom
  and a real resource are indistinguishable below authentication). Existence is decided
  post-authentication, at the flow's per-user read of the named kind — the toolset listing
  read or the app read — one existence refusal per namespace; the harness's lesson about a
  path Core does not hold arrives one leg later, exactly where the same probe against Core's
  own tier would have taught it.
- **The live end-to-end sign-in through the front door** needs the gateway's
  pre-registered identity-provider client, which group 6 provisions.
