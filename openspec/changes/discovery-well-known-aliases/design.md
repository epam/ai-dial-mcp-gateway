# Design — discovery well-known aliases and the closed namespace

This design rests on the evidence in this change's `evidence/` folder:
`finding-discovery-fallthrough.md` (the finding record: symptom, evidence, the inferred
root cause and its negative control, the approved fix), `core-well-known-surface.md`
(what DIAL Core serves under `/.well-known/`, from its source), and
`gateway-method-baseline.md` (the gateway app's method and 404 behavior on the discovery
surface, measured), and `review-round-1.md` (the first independent review's findings,
verbatim; their dispositions are the last section of the decisions of record). Nothing
below cites chat scrollback.

## The shape of the fix

Two moves carry the whole change:

1. **The authorization-server metadata answers at every location a discovering client
   may try for this issuer** (D1–D3): the OpenID Connect location and both path-insertion
   forms, byte-identical to the canonical document, served by the gateway from the one
   builder it already has.
2. **The front door stops letting discovery paths fall through to Core** (D4–D5): every
   `/.well-known/` path no discovery location serves gets the router's JSON `404`, and
   the only Core paths under `/.well-known/` — Core's two protected-resource templates —
   are forwarded to Core by a location of their own. Because nginx selects a location by
   the normalized path but forwards the raw one, the closure is also enforced on the raw
   spelling, by raw-URI checks at the two locations that forward to Core (D9).

Everything else is consequence: the method and CORS behavior (D6), what stays out of
scope (D7), and the instrument and conformance rows (D8).

## Decisions of record

### D1 — The gateway serves the alias family; the router forwards it

The gateway registers its existing authorization-server-metadata handler on three more
paths — `/.well-known/openid-configuration`,
`/.well-known/oauth-authorization-server/{suffix:path}`, and
`/.well-known/openid-configuration/{suffix:path}` — so every alias answers from
`authorization_server_metadata(settings)`, the one builder the canonical route uses. The
router gains one regex location,
`~ ^/\.well-known/(oauth-authorization-server|openid-configuration)(/|\z)`, which forwards
the family to the gateway unchanged. The end anchor is `\z`, not `$`: PCRE's `$` also
matches before a final line break, so `$` would select this location for a decoded
`…/openid-configuration%0A`, which is not an alias path (D9). The existing exact location
`= /.well-known/oauth-authorization-server` stays: nginx checks exact locations first,
so the canonical path is unaffected, and the existing probe row for it keeps its meaning.

**Why the gateway and not the router.** The router's job is to split traffic: the
authorization surface belongs to the gateway, and the router's one synthesized response
is the data path's challenge. A document route belongs where the document is built. The
gateway serving the aliases also makes them unit-testable with the suite's own client, so
the byte-identity property is pinned without a composed stack. The direct gateway port is
unreachable from outside the pod (`docs/pod-contract.md` §8.2, port non-publication), so "what the gateway app
answers" matters for tests and for the router's forwarding — and the answer is the same
document on every alias path.

**Alternatives weighed and rejected.**

- *A router rewrite onto the canonical path* (`rewrite ^ /.well-known/oauth-authorization-server break;`
  in the alias location). It would remove the raw-versus-normalized class on this
  location (DT-EP6-9) and need no gateway change. Rejected because the alias behavior
  would then exist only in nginx configuration, where no unit test can pin it, and a
  fronting other than the committed conf would silently lose it. DT-EP6-9 is bounded
  without it (§SIA.6).
- *A static JSON file served by nginx.* Rejected: two sources of truth for one document,
  and the document varies with configuration (`registration_endpoint` is present only
  while DCR is enabled).
- *`proxy_pass http://gateway$uri`* (forward the normalized path). Rejected: `$uri` is
  decoded, and a variable `proxy_pass` does not re-escape it — the measured defect class
  that made the data path move to a raw-URI map. The alias handler ignores the suffix,
  so the raw forward costs nothing.

### D2 — Every alias answers the canonical document; the issuer never echoes the suffix

The body at every alias is byte-identical to the canonical document. In particular,
`issuer` is the public origin in every response, including the path-insertion forms,
where RFC 8414 §3 (with §3.1's request form) would associate the path with an issuer of
`{origin}{suffix}`.

**Why.** The gateway has one issuer: the `iss` of every token it mints and the RFC 9207
`iss` on every authorization response. A document that echoed the suffix as its issuer
would assert an issuer identity no token carries. A client running RFC 9207's mix-up
check would then compare the response's `iss` (the origin) with the metadata's issuer
(the suffixed string), and either fail every sign-in or be pushed to disable the check.
RFC 8414 §3.3 says a client MUST NOT use a document whose `issuer` differs from the
issuer it derived. So the truthful document gives each client class the right outcome:
a strict client discards it and moves on, and a lenient client — one that probes a
path-insertion form because it derived the issuer from the resource URL — receives
working endpoints. Neither is told anything false.

**Why serve the path-insertion forms at all.** RFC 8414 §3 and the MCP specification
give these forms for an issuer with a path, and the gateway's issuer has none — so a
client that follows the protected-resource document's `authorization_servers` never
needs them. They are reached by a client that misreads the resource URL as an issuer
URL — taking `<origin>/apps/<app>/mcp` for an issuer with the path `/apps/<app>/mcp` —
and then applies the path-issuer discovery order to it. This is not the earlier MCP
authorization revision's model: that revision discarded the path and probed the root
forms. No client in this change's evidence is observed to probe the path-insertion forms;
the finding's probe set includes them because they are on the standards' list, and
today they get Core's `401`, which ends discovery for any client that does probe them. A
`404` would let a strict client move on; a `200` additionally lets a lenient client
succeed. The `200` costs one static document and asserts nothing false (D2's issuer
rule), so it was chosen over a `404` (ruled at the owner pause; "Owner rulings" below).

### D3 — The OpenID Connect location serves the RFC 8414 document as it stands

`/.well-known/openid-configuration` answers the RFC 8414 document with no OpenID
Provider member added: no `subject_types_supported`, no
`id_token_signing_alg_values_supported`, no `userinfo_endpoint`, and no `openid` in any
scope list (the document has no `scopes_supported` at all).

**Sources checked.**

- RFC 8414 §2: only `issuer` and `response_types_supported` are unconditionally
  REQUIRED; `authorization_endpoint` and `token_endpoint` are conditionally required.
  The gateway's document carries all four.
- RFC 8414 §5 (Compatibility Notes): the `openid-configuration` suffix, and the
  `op_policy_uri` and `op_tos_uri` names, are OpenID-derived, but this specification
  uses them for general OAuth 2.0 features. Serving OAuth AS metadata at the OpenID
  Connect suffix is therefore within RFC 8414's own reading.
- OpenID Connect Discovery 1.0 §3: REQUIRED members are `issuer`,
  `authorization_endpoint`, `token_endpoint` (unless only the implicit flow is used),
  `jwks_uri`, `response_types_supported`, `subject_types_supported`, and
  `id_token_signing_alg_values_supported`. The gateway's document lacks the last two.
  §4.3: the returned `issuer` must equal the issuer URL used for the lookup — true at
  `/.well-known/openid-configuration` for the path-less issuer.
- The MCP authorization specification (2025-11-25): an MCP authorization server MUST
  provide at least one of RFC 8414 or OpenID Connect Discovery, and MCP clients MUST
  support both and try them in a fixed order — for a path-less issuer,
  `oauth-authorization-server` first, then `openid-configuration`. In any
  authorization-server metadata, whichever location served it, a client MUST verify
  that `code_challenge_methods_supported` is present and refuse to proceed otherwise.
  The gateway's document carries it at every location.

**What a strict OpenID Connect relying party does.** It validates the document against
OpenID Connect Discovery §3, finds `subject_types_supported` and
`id_token_signing_alg_values_supported` missing, and refuses the provider. It cannot
complete an OpenID Connect sign-in against the gateway — which is right, because the
gateway is not an OpenID Provider. That client got Core's `401` before this change, so
nothing it could do before is lost.

**Why not add the OpenID Provider members.** Adding them would advertise behavior the
gateway does not have: a relying party told
`id_token_signing_alg_values_supported: ["RS256"]` requests `scope=openid` and expects
an ID token that never arrives, or it accepts the access token in the ID token's place
(DT-EP1-18 prices that misuse). The discovery requirement already treats the member set
as normative advertisement — the RFC 9207 member was added *because* the emission
exists. A false advertisement breaks that rule.

### D4 — The front door's `/.well-known/` namespace is closed, below every served location

The router gains a plain prefix location, `location /.well-known/`, plus an exact
`location = /.well-known`. Both answer `return 404 '{"detail":"Not Found"}';` with
`default_type application/json` and `add_header X-Content-Type-Options nosniff always;`,
and neither forwards anything. The two blocks are the only place the closure's answer is
defined: the raw-URI checks (D9) hand a refused request to the closure by an internal
redirect rather than repeating the answer. The root
`/.well-known/oauth-protected-resource` falls into the closure, because no served
location matches it.

**Precedence — verified against nginx's documented matching order.** nginx checks exact
(`=`) locations first, then finds the longest matching prefix location, then evaluates
regex locations in configuration order and uses the first regex that matches. It falls
back to the remembered prefix only when no regex matches — unless that prefix is marked
`^~`, which skips the regex step entirely. So:

- `= /.well-known/oauth-authorization-server` wins outright (exact).
- The alias-family regex (D1), the `/dial/` and `/apps/` protected-resource regexes, and
  the Core protected-resource regex (D5) all win over the plain `/.well-known/` prefix,
  because each is a regex that matches.
- Only a `/.well-known/` path that matches none of them reaches the closure.
- A `^~ /.well-known/` would be the longest prefix for every such path and would suppress
  every regex location — shadowing all discovery. The spec forbids it, and DT-EP6-7
  prices it.

The closure is order-independent by construction: it is a prefix location, not a
regex, so no edit to the regex order can move it in front of a served location.

**Body and type.** `{"detail":"Not Found"}` as `application/json` is the gateway's own
unrouted-404 shape (`evidence/gateway-method-baseline.md`), so within the `/.well-known/`
namespace a discovering client sees one 404 body whichever of the router and the
gateway refuses. The claim is scoped to the namespace: elsewhere on the front door the
data path's refusal (`return 404;` in the `/dial/` and `/apps/` locations) is nginx's
default HTML page, which this change does not touch (D7). The body is a fixed literal
with no variable, so no part of the request can appear in it (DT-EP6-10).

**The discriminator header.** nginx drops the upstream's `Server` and `Date` headers by
default, so through the front door the router's `404` and the gateway's own `404` are
otherwise byte-identical, and an instrument could not tell a closure mis-written as a
gateway forward from the real one. The closure therefore carries one fixed header the
gateway's JSON answers never carry: `X-Content-Type-Options: nosniff` (the gateway sets
it on its HTML pages only). It is constant, reflects nothing, and is useful in its own
right: it keeps a browser from sniffing the body as anything but JSON. It is added
`always`, because without `always` nginx's `add_header` applies only to `2xx` and `3xx`
answers and would be absent from the `404` it exists to mark. Probe row W0c is its
negative control: a path the gateway answers with its own `404` through the front door,
showing the header absent.

**Every method.** nginx's `return` answers in the rewrite phase, before any content
handler, for every method — on any request the server-level bounds admit. A body over
`client_max_body_size` (16384) is refused `413`, and an over-long request line `414` or
`400`, before any location answers. A `HEAD` gets the status and headers without the body. An
`OPTIONS` preflight gets the `404` with no `Access-Control-*` header, which is the
back-channel posture. A `POST` body is never read or forwarded.

**What the closure takes away.** Every path it answers was answered before by Core's
auth filter (`401`) or by no Core handler at all (`evidence/core-well-known-surface.md`),
except Core's two protected-resource templates, which D5 forwards. Core's `OPTIONS 200`
and `Access-Control-Allow-Origin: *` on those paths also go away through the front door.
Nothing depends on them: a well-known path Core does not serve has no CORS use.

### D5 — Core's two protected-resource templates are forwarded to Core, and only those

One router location forwards Core's own discovery surface unchanged:
`location ~ ^/\.well-known/oauth-protected-resource/v1/(toolset|deployments)/.+/mcp$`,
which forwards with `proxy_pass http://core;` only when the raw-URI gate
`$core_prm_raw` (D9) says the raw request URI is itself one of Core's templates. The
location regex selects candidates on the normalized path; the gate, on the raw URI,
decides — the same division of labor as the data-path locations and their maps. No
streaming directives: Core's metadata route answers one JSON document.

The Core location forwards every method, as the catch-all already did for these
paths: Core's templates are `GET`-only, so a non-`GET` request gets Core's own answer
(its authentication filter's `401`, or its `OPTIONS` answer with Core's CORS header) on
a `/.well-known/` path. That is no new exposure, and no `limit_except` is added: its
`deny` would answer `403` rather than the closure's body, and the method-blind closure
(D6) is the one place a refusal is defined.

**Why this location is needed.** Core serves exactly two unauthenticated `/.well-known/`
templates (`evidence/core-well-known-surface.md`). When Core's
`toolsets.security.resourceHost` is unset, Core builds its own MCP-path challenge from the
request authority. A direct-to-Core client that reaches Core's MCP path through the
front door's catch-all (`<gateway-origin>/v1/toolset/<id>/mcp`) is therefore pointed back
at `<gateway-origin>/.well-known/oauth-protected-resource/v1/toolset/<id>/mcp` on this
front door. That path reaches Core today through the catch-all. The Core-coexistence
requirement says Core's discovery surface keeps working, so the closure must not take it.

**Why the location is narrow (end-anchored at `/mcp`).** Core's templates are
`(?<id>.+?)/mcp$`. A shape under Core's prefix that is not one of them (`…/v1/toolset/<id>/tools`,
`…/v1/other`) reached Core's auth filter's `401` before this change. It now reaches the
closure's `404`, exactly as any unserved discovery path does. Forwarding only what Core
serves keeps the closure honest at its one exception.

**Re-open trigger.** A DIAL Core release that adds a `/.well-known/` route. The Core
surface record states the commit it was read at. A Core upgrade that adds a route
reached through this front door re-opens D5, and the routing doc's location map names
the dependency.

**Observed and not addressed (an existing behavior).** The router forwards
`Host: $host`, which drops the port. In the local shape (front door on `:8090`, plain
http) Core's challenge for a direct-to-Core client through the catch-all therefore quotes
`{resourceSchema}://localhost/…` — no port, and `https` by Core's default schema. That
challenge does not resolve back to this front door. A TLS deployment on the default port
is unaffected. This is an existing property of the catch-all, unchanged by this change.
It was raised as OQ-3 and ruled at the owner pause: accepted, no change ("Owner rulings"
below).

### D6 — Methods and CORS: the aliases behave as the canonical route; the closure is method-blind

The aliases inherit the canonical route's method behavior by being registered on the same
handler: `GET` answers `200`, and every other method — `HEAD`, `OPTIONS`, and `POST`
included — gets the framework's `405` with `Allow: GET` (measured on the canonical
route; `evidence/gateway-method-baseline.md`). No alias serves an `Access-Control-*`
header. The public-endpoints requirement's back-channel posture already names "the
discovery documents", and the aliases are discovery documents, so that requirement's text
needs no change. Its machine pin — the CORS-header test's path list — gains the alias
paths so the posture stays pinned per path. The router's closed `404` is method-blind
(D4) and carries no CORS header either.

**Why not add `HEAD` to the aliases.** `HEAD` support on the canonical route is a separate
behavior change on an existing surface, and the parity rule ("an alias behaves as the
canonical location") is simpler to check than a per-path method set. No client in the
evidence uses `HEAD` for discovery.

### D7 — What stays out: the root protected-resource document, the path-appended forms, the DCR `grant_types`

**The root `/.well-known/oauth-protected-resource` is closed (`404`), not served.**
RFC 9728 lets a resource with no path serve its document at the root. The front door
serves many resources, each identified by its own resource URI, and the gateway's tokens
carry that URI in their audience (RFC 8707). A root document must name exactly one
`resource`. Naming the origin would make a token minted for the origin acceptable as the
audience of nothing the data path serves, or would need an audience rule that accepts
the origin for every resource — which removes the per-resource binding. The MCP
specification's fallback to the root applies only when the `401` carries no
`resource_metadata`, and the gateway's `401` always carries it. So a conforming client
never needs the root, and a `404` there is a correct answer that lets a probing client
move on. Whether ChatGPT needs more than a `404` is OQ-1. Its answer is the live
re-test, and a root-document design would need its own full SIA.

**The path-appended forms are out of scope, and already never reach Core.** A client
that appends the well-known suffix to the resource URL instead of inserting it —
`/apps/<app>/mcp/.well-known/openid-configuration`,
`/apps/<app>/mcp/.well-known/oauth-protected-resource`, and the `/dial/` twins — is
outside the `/.well-known/` namespace this change closes. Those paths select the `/apps/`
or `/dial/` data-path location, whose raw-URI map requires `/mcp` as the final segment,
so the router refuses them with the data path's bare `return 404;` — nginx's default HTML
404 page, not the closure's JSON and not Core's `401` (the finding record measured the
same). That page is the data path's existing refusal shape, unchanged here. Probe row
W13 asserts the forms are the router's refusal and never Core's answer, so a later
data-path change cannot quietly start forwarding them.

**Noted, not addressed.** The registration response carries
`"grant_types": ["authorization_code"]` (`gateway/routes.py`), while the authorization
metadata advertises both grants. A client that honors its registration's `grant_types`
strictly may not attempt the refresh grant. That is a separate finding, recorded in the
finding record and here so it is not lost. It is not this change's defect, and this
change does not touch registration.

### D8 — The instrument and the conformance rows

The instrument is `scripts/probe_routing.py`, extended with a well-known row group. Its
first two rows are negative controls. W0 calls a discovery path on Core's own port,
outside the router, and shows what Core's answer looks like — `401`, `text/plain`,
Core's trace header — so a front-door `404` is provably not Core's. W0c calls, through
the front door, a path the gateway answers with its own `404`, and shows that answer
without the discriminator header — so a front-door `404` carrying the header is provably
the router's and not the gateway's (D4). The battery's existing control (Core's own
challenge) stays first overall. The new group's controls run first within its group,
and a failed control stops the battery.

**A verbatim-path client.** The normalization rows (W10) send paths with dot segments
and percent-escapes that a client library may rewrite before sending: `httpx` and
`requests` normalize dot segments out of a URL, which would turn a probe of the raw
spelling into a probe of the normalized one and pass for the wrong reason. Every
well-known row is therefore sent with `http.client` directly, which puts the given path
on the request line unchanged, and each normalization row prints the request line it
sent, so the run shows that the raw spelling reached the router.

| Row | What it proves | Instrument |
|---|---|---|
| W0 | **Negative control (Core).** Core-direct `GET /.well-known/openid-configuration` (Core's own port) answers Core's `401` with Core's trace header and plain-text body — the discriminator against Core every later row relies on; the row also records whether Core's answer carries `X-Content-Type-Options` | probe battery, the group's first row |
| W0c | **Negative control (gateway).** Front-door `GET /.well-known/oauth-protected-resource/dial/x` — the gateway's protected-resource location, no `/mcp` suffix — answers the gateway's own `404`, body `{"detail":"Not Found"}`, `application/json`, **no** `X-Content-Type-Options` header, no Core trace header — the discriminator against the gateway | probe battery, the group's second row |
| W0b | **Failing-first.** Rows W1, W2, W4, W5, W8, W12, and W10's cells a–e (each reaches Core today) run against the pre-change stack, and each fails (Core's `401`, or its `OPTIONS 200`, where the row expects a document or the router's `404`); W0, W0c, W7, W13, and W10's gateway and data-path cells (f, g) pass, because those answers do not change; the run is recorded before the fix lands | probe battery, `evidence/instrument-run.md` |
| W1 | `GET /.well-known/openid-configuration` → `200`, body byte-identical to the canonical document | unit (`tests/test_discovery.py` / `tests/test_app.py`) + probe |
| W2 | `GET /.well-known/oauth-authorization-server/<suffix>` and `GET /.well-known/openid-configuration/<suffix>` — an apps path, a toolset path, the empty suffix — → `200`, byte-identical, `issuer` the public origin | unit + probe |
| W3 | No OpenID Provider member at any alias (`subject_types_supported`, `id_token_signing_alg_values_supported`, `userinfo_endpoint` absent; no `scopes_supported`) | unit |
| W4 | `GET` the root `/.well-known/oauth-protected-resource`, `/.well-known/unknown`, `/.well-known/`, and `/.well-known` → `404`, body `{"detail":"Not Found"}`, `application/json`, `X-Content-Type-Options: nosniff`, no Core trace header, no `WWW-Authenticate` | probe |
| W5 | `POST`, `OPTIONS`, and `HEAD` on a closed path → `404`, `X-Content-Type-Options: nosniff`, no `Access-Control-*`; `HEAD` has no body | probe |
| W6 | Precedence: the exact AS location, a toolset document, and an app document are served by the gateway, unchanged (the routing doc's existing probe rows 3, 4, and 9 re-run green beside the closure) | probe |
| W7 | Core's protected-resource templates through the front door give the same answer as Core-direct, for `…/v1/toolset/<toolset>/mcp` and `…/v1/deployments/<app>/mcp`: same status and content type, and Core's trace header present; on `200`, the same JSON member names and a `resource` ending in the requested path | probe |
| W8 | Off-template shapes under Core's prefix (`…/v1/toolset/<toolset>/tools`, `…/v1/other`) → the router's `404` with `X-Content-Type-Options: nosniff` | probe |
| W9 | `HEAD`, `OPTIONS`, and `POST` on each alias → `405`, `Allow: GET`, no `Access-Control-*` (the CORS pin's path list extended) | unit |
| W10 | **Normalization, both directions, verbatim paths.** (a) Into the alias location: `/.well-known/openid-configuration/x/../y` → the document (the gateway's answer, no discriminator header). (b) Out of the alias location into the closure: `/.well-known/openid-configuration/../unknown` → the router's `404`. (c) Into the Core location from outside its raw spelling: `/.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/<toolset>/mcp`, and the same with `%2e%2e`, `%2E%2E`, and `..%2F` for the dot segment → the router's `404`. (d) Out of the namespace into the catch-all: `/.well-known/unknown/../../v1/x`, `/.well-known/unknown/%2e%2e/%2e%2e/v1/x`, `/%2Ewell-known/unknown/../../v1/x`, `//.well-known/unknown/../../v1/x`, `/./.well-known/unknown/../../v1/x`, `/%2F.well-known/unknown/../../v1/x`, and `/%2E%2F.well-known/unknown/../../v1/x` → the router's `404`. (e) The decoded trailing line break: `…/v1/toolset/<toolset>/mcp%0A` and `/.well-known/openid-configuration%0A` → the router's `404`. (f) A raw namespace spelling normalizing into a gateway location (`/.well-known/x/../../dial/token`) → the gateway's answer, recorded. (g) One normalizing into a data-path location (`/.well-known/x/../../apps/<app>/mcp`) → the data path's refusal, recorded. Every cell: no Core trace header. Cells (b)–(e) also: `X-Content-Type-Options: nosniff`. Cells (f) and (g) also fail when the router's `nosniff` header is present (a closure answer means the request went to the wrong side). Every closure cell requires the router's `404`; no cell steps above the root, so a `400` is a failure | probe (verbatim-path client) |
| W11 | **Live re-test on the dev deployment.** The finding's verify commands (`openid-configuration` → `client_id_metadata_document_supported: true`; a path-insertion alias → `200`; the root PRM → `404`; an unknown well-known path → `404`), then the ChatGPT connector reconnected and the gateway's audit trail checked for a `client_registered` or an authorization record | live, owner-run (the ChatGPT reconnect), recorded in `evidence/` |
| W12 | **Boundaries.** The served locations' end edges: `/.well-known/oauth-authorization-serverX` and `/.well-known/openid-configuration.json` (the alias regex's `(/\|\z)` edge) and `…/v1/toolset/<toolset>/mcp/` (the Core template's end edge, trailing slash) → each the router's `404` with `X-Content-Type-Options: nosniff` | probe |
| W13 | **Path-appended forms (out of scope, pinned).** `/apps/<app>/mcp/.well-known/openid-configuration` and `/apps/<app>/mcp/.well-known/oauth-protected-resource` → `404` from the router's data-path refusal; no Core trace header, no `WWW-Authenticate` (D7) | probe |

**The precedence detector's own negative control (one-off).** After the router locations
land, the closure is once temporarily rewritten as `location ^~ /.well-known/`, the
router reloaded, and W6 run: it must fail (the exact AS location still answers, the
toolset and app documents get the closure's `404`). The conf is then restored, W6 re-run
green, and both runs recorded in `evidence/instrument-run.md`. The mutation is never
committed; it shows that W6 detects the shadowing DT-EP6-7 prices.

W11 is the re-test that confirms the inferred root cause. If ChatGPT still fails with
W1–W10, W12, and W13 green, the fix is correct but not sufficient for the symptom, and
OQ-1 opens the next iteration (`PROCESS.md` step 9) — not a re-litigation of this change.

### D9 — The raw spelling: both normalization directions are closed by raw-URI checks

nginx selects a location on the normalized URI — percent-decoded, dot-segments resolved,
slashes merged — but a `proxy_pass` with no URI forwards the raw request URI, the bytes
the client sent. Core matches its two templates on that raw path. So a raw URI can
select one location and deliver a different path upstream, in two directions:

- **Into the Core location.** Raw
  `/.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/x/mcp`
  normalizes onto the Core location's regex and would be forwarded raw. Core's raw
  template does not match it, so Core's auth-filter `401` and its trace header would come
  back on a path the closure claims. A decoded trailing `%0A` is the same shape: PCRE's
  `$` matches before a final line break, so `…/mcp%0A` would select the location too.
- **Out of the namespace into the catch-all.** Raw `/.well-known/unknown/../../v1/x`
  normalizes to `/v1/x`, selects `location /`, and reaches Core with a raw
  `/.well-known/…` path — Core's `401` on a `/.well-known/` URL.

Neither is a security break — the catch-all already forwards any raw URI to Core, so
nothing reachable is new — but each makes the delta spec's MUST ("never forwarded to
Core") false as written. The spec's MUST stays absolute, and the router enforces it on
the raw URI, by the repository's existing discipline for this class: a `map` keyed on
`$request_uri`, the raw never-decoded URI (M39; the data-path maps, DT-EP6-5).

**The shape.** Two maps beside the data-path maps, and one check at each of the two
locations that forward to Core:

The snippet is abridged; `router/nginx.conf` is normative.

```nginx
# Core's two protected-resource templates, matched on the raw request URI as Core
# itself matches them: the template path, then nothing but an optional query.
map $request_uri $core_prm_raw {
    default "";
    "~^/\.well-known/oauth-protected-resource/v1/(?:toolset|deployments)/[^?]+/mcp(?:\?.*)?$" 1;
}

# A raw path spelled in the `/.well-known` namespace: after any empty or `.` segments
# (each separator spelled `/` or `%2F`, the dot possibly percent-encoded), a first segment
# that is `.well-known` with any of its characters percent-encoded (the dot included),
# ended by `/`, an encoded `/`, the query, or the end of the URI.
map $request_uri $wk_raw_spelling {
    default "";
    "~^/(?:(?:\.|%2[Ee])?(?:/|%2[Ff]))*(?:\.|%2[Ee])(?:w|%77)(?:e|%65)(?:l|%6[Cc])(?:l|%6[Cc])(?:-|%2[Dd])(?:k|%6[Bb])(?:n|%6[Ee])(?:o|%6[Ff])(?:w|%77)(?:n|%6[Ee])(?:/|%2[Ff]|\?|$)" 1;
}

location ~ ^/\.well-known/oauth-protected-resource/v1/(toolset|deployments)/.+/mcp$ {
    if ($core_prm_raw = "") {
        rewrite ^ /.well-known/ last;
    }
    proxy_pass http://core;
}

location / {
    if ($wk_raw_spelling != "") {
        rewrite ^ /.well-known/ last;
    }
    proxy_pass http://core;
    # ... the catch-all's existing streaming directives, unchanged
}
```

**Why this shape.**

- **The Core gate is the template, raw.** `[^?]+` mirrors Core's own `(?<id>.+?)` over
  the path: Core's `request.path()` excludes the query, so the gate allows exactly what
  Core's template matches, then an optional query. A raw URI that passes the gate is one
  Core would answer as its own template on its own port, so W7's same-answer property
  holds for everything forwarded. A spelling that only normalizes onto the template —
  dot segments before or across the `toolset` prefix, an encoded `t` in `toolset`, a
  decoded trailing line break — fails the gate. On the raw URI `%0A` is three literal
  characters, not a line break, so `$` cannot match early. Dot segments and `#`/`%23`
  inside `{id}` do pass the gate: `[^?]+` admits them, as Core's own raw `(?<id>.+?)`
  does, and every forwarded raw URI still ends `/mcp` before the first `?`, so it is a
  path Core's unauthenticated metadata route answers as its own template. That is
  consistent with D5, and those requests were forwarded before this change too. The cost is that an encoded spelling of Core's template that Core
  itself might accept is closed. No discovering client spells a template it was handed
  in a challenge any way but literally.
- **The catch-all check is a raw-prefix test, not a substring test.** It refuses only a
  raw path whose leading segment is `.well-known` in some spelling. It covers the
  spellings nginx's normalization maps onto that segment: merged slashes (`//`), `.`
  segments (`/./`), and a percent-encoded character anywhere in the name, the dot
  included (`%2E`); nginx decodes `%2F` as a slash, so it counts as a separator before
  the name (`/%2F.well-known/…`, `/%2E%2F.well-known/…`) and as the segment's end after
  it. A substring test (`.well-known` anywhere in the path) would
  refuse legitimate Core paths that happen to contain the string, such as a file name
  under Core's own API. A raw path whose first segment is something else and that only
  passes through `.well-known` by dot segments (`/x/../.well-known/…/../../v1/y`) is,
  by the spec's definition, not a namespace spelling. If it normalizes into the
  namespace, a well-known location answers it, and the Core location's gate refuses it
  as above. If it normalizes outside, Core answers it as the path it normalizes to, as
  before this change.
- **Both regexes are linear.** The prefix loop `(?:(?:\.|%2[Ee])?(?:/|%2[Ff]))*` is an
  optional dot followed by a mandatory separator per iteration, so a wrong guess
  backtracks at most one token and there is no ambiguous backtracking. `[^?]+/mcp` backtracks at most once
  per character. The stated `large_client_header_buffers 4 8k` bounds the input to both
  (DT-EP6-4's discipline). Each map is evaluated only where its variable is read: the
  catch-all's check costs one anchored regex that fails at the second character for any
  path not starting `/.`, `/%`, or `//`.
- **The refusal is an internal redirect to the closure, not a second `return`.**
  `rewrite ^ /.well-known/ last;` re-runs location selection with the normalized path
  `/.well-known/`, which only the closure's prefix location matches. So the refused
  request gets the closure's own answer: its status, body, type, and discriminator
  header, defined once. A `return 404 '…'` inside the `if` would need its own
  `default_type`, which nginx does not allow inside `if`, and its own `add_header`,
  which would also be a second copy of the answer to drift. `rewrite … last` and
  `return` are the two directives nginx documents as safe inside `if` in a location.
  The redirect cannot loop, because the closure does not rewrite.
- **The checks sit only where Core is reached.** The Core location and the catch-all are
  the only locations that forward to Core with the raw URI. The data-path locations
  forward to Core only through their own raw-URI maps, which require a raw `/dial/` or
  `/apps/` prefix, so a raw namespace spelling that normalizes onto them is refused by
  their existing `return 404;`. The gateway locations forward raw URIs to the gateway,
  whose routes answer them: the document, or the gateway's own `404` (DT-EP6-9's
  gateway half, bounded by M38 and measured by W10 (f)). The gateway is the component
  the router meant to reach there, so no raw check is added on those locations.
- **Rejected: qualifying the spec instead.** The alternative was to state the MUST over
  normalized paths only and price the raw directions as a bounded exception. It was
  rejected because the raw-URI map is the repository's settled answer to exactly this
  class, it costs two short maps, and an absolute MUST is checkable by the probe rows,
  while a qualified one would have needed its own list of exceptions to test.

### Owner rulings (`PROCESS.md` step 3c)

Recorded 2026-11-16, at the owner pause after review round 1.

- **OQ-2 — ruled: the path-insertion forms answer `200` with the same document, as
  designed** (D2). The `404` alternative is not taken.
- **OQ-3 / threat-model OQ-14 — ruled: the router's `Host: $host` forwarding stays as is
  in this change.** Accepted, no change. The threat model closes OQ-14 with that
  disposition. If the question is ever revisited, the preferred remedy is configuring
  Core's `toolsets.security.resourceHost` per deployment — an operator-set value — over
  forwarding the client-supplied `Host` with its port. The review recorded this
  preference in its note on the question.
- **3c — ruled: go for implementation, 2026-11-16, no further changes requested;
  artifact re-review waived — the diff security gate covers the round-2 router
  additions.**

### Review round 1 — dispositions

The findings are recorded verbatim in `evidence/review-round-1.md`. Each one's
disposition follows.

| Finding | Disposition |
|---|---|
| S1 — router and gateway 404s indistinguishable | Addressed. The closure carries `X-Content-Type-Options: nosniff`, added `always` (D4). The header is pinned in the ADDED requirement and its scenarios and in M44. W0c is the gateway-side negative control, and W4, W5, W8, W10, and W12 assert the header (D8). |
| S2 — normalized match, raw forward, both directions | Addressed by option (a): the raw-URI gate `$core_prm_raw` on the Core location, and the raw namespace-spelling check `$wk_raw_spelling` on the catch-all, each refusal an internal redirect to the closure (D9). The alias regex ends `(/\|\z)` (D1). The spec's MUST stays absolute and is restated over the normalized path plus the raw spelling. DT-EP6-9 prices both directions. W10 covers both directions, the encoded-dot variants, and `%0A`, with a verbatim-path client (D8; tasks 1.2). |
| S3 — D2 misattributes path-insertion probing | Addressed. D2 now bases the reason on a client that misreads the resource URL as an issuer URL. It states that the earlier MCP revision probed root forms, and that no client in the evidence is observed to probe the path-insertion forms. The spec wording is unchanged, as the review allowed. |
| S4 — DT-EP1-18 "pre-existed" is inaccurate | Addressed. The class is newly reachable through the OpenID Connect location and bounded by three relying-party failures: operator-configured trust in the gateway as an OpenID Provider, skipped ID-token validation, and skipped audience validation (M9). "No new residual" is kept on that reasoning (§SIA.6; the threat model's row and disposition). |
| S5 — "one 404 shape" overclaimed; path-appended forms | Addressed. The sentence is scoped to the `/.well-known/` namespace in the spec and D4. D7 records the path-appended forms as out of scope, with their current answer (the data path's HTML `404`, never Core's). W13 pins them. |
| S6 — boundary rows missing | Addressed. W12 covers `oauth-authorization-serverX`, `openid-configuration.json`, and the Core template with a trailing slash. A spec scenario states the end edges. |
| N1 — RFC 8414 §3 not §3.1 | Addressed in the spec ("§3") and D2 ("§3, with §3.1's request form"). |
| N2 — the PKCE-member check applies to any AS metadata | Addressed in the spec's alias paragraph and D3. |
| N3 — "every method" holds only within the server-level bounds | Addressed in the spec ("on any request the server-level bounds admit"), D4, and M44. |
| N4 — "three locations" is four blocks | Addressed in §SIA.1 and §SIA.2: four location blocks, two maps, and one check on the catch-all. |
| N5 — the port-reachability reference | Addressed: `docs/pod-contract.md` §8.2 (D1). |
| N6 — the streaming sentence | Addressed (D5). |
| N7 — the catch-all comment | Addressed (tasks 3.4). |
| N8 — git writes | Addressed: tasks 6.6 states that the user runs every git write and agents never commit or push. |
| N9 — a mutation run for W6 | Taken: the one-off `^~` mutation run (D8; tasks 3.7). |
| N10 — untracked pod-named log dumps | Outside this change; not addressed here. |

### Security gate — dispositions

The findings are recorded verbatim in `evidence/security-review.md`. Verdict: pass with
fixes; no blocking finding; the impact level of Low is confirmed.

| Finding | Disposition |
|---|---|
| SF-1 — the catch-all's raw namespace check missed `%2F` as a leading separator | Fixed. `$wk_raw_spelling`'s prefix loop accepts `/` or `%2F` as each separator (D9). W10(d) gained `/%2F.well-known/unknown/../../v1/x` and `/%2E%2F.well-known/unknown/../../v1/x`; both failed against the previous conf and pass with the fix (`evidence/instrument-run.md`). DT-EP6-9, M44, D9, and the routing doc were reworded to match. No spec change: the spec's definition already reads percent-escapes as the characters they encode. |
| N-1 — the Core gate's comment overstated what "dot segments do not match" covers | Fixed. The conf comment and D9 now say that dot segments before or across the prefix do not match, while dot segments and `#`/`%23` inside `{id}` are forwarded as-is, consistent with D5 because Core's own raw template accepts them. |
| N-2 — the Core location forwards every method | Recorded in D5: no new exposure, the catch-all did the same; no `limit_except`. |
| N-3 — version disclosure (`server_tokens`) on the closure's `404` | Not changed. Already disclosed on every nginx-generated answer; `server_tokens off;` is deferred to a later change. |
| N-4 — the "first segment is something else" carve-out | Fixed. One sentence in DT-EP6-9 (threat model and D9) and in the routing doc: such a raw URI is not a namespace spelling by definition and is forwarded raw. |

### General review - dispositions

The findings are recorded verbatim in `evidence/general-review.md`. Verdict: pass with
fixes; no blocking finding. No spec change.

| Finding | Disposition |
|---|---|
| SF-A - the battery ran against a Core stand-in, but 6.3 and 6.4 were ticked unqualified | Fixed. Tasks 6.3 and 6.4 carry the stand-in caveat inline. Task 6.5b (owner-run, unticked) runs the full probe with no flags against the real instance, as a precondition to archive beside W11. |
| SF-B - W7 compared only the status | Fixed. W7 also compares the content type and, on `200`, the JSON member names and the `resource` path suffix. Shown failing under a wrong-content-type stand-in (`evidence/instrument-run.md`). |
| SF-C - W10 (f) and (g) did not detect a closure answer | Fixed. Both cells fail when the router's `nosniff` header is present. Shown failing under a router `404` on the (f) path. |
| SF-D - the bug doc still prescribed the router-only fix | Fixed. The bug doc has a status line pointing to this change, and its Fix section is marked superseded with a summary of what shipped. |
| N-A - `state` used before it was defined | Fixed. The definition moved above the rows. |
| N-B - `TOKEN_ROWS` matched display names typed twice | Fixed. Two shared name constants name the rows in `main()` and in `TOKEN_ROWS`. |
| N-C - `allow_bad_request` covered every closure cell | Fixed. The parameter is gone: no cell steps above the root, so every closure cell requires the `404`. |
| N-D - W5's `OPTIONS` was not a preflight | Fixed. It carries `Origin` and `Access-Control-Request-Method`. |
| N-E - the D9 snippet comment drifted from the conf | Fixed. The comment is synced and the snippet is labelled abridged, with the conf normative. |
| N-F - `--no-token` undocumented in the routing doc | Fixed. One sentence added. |
| N-G - the unrelated `probe_end_to_end.py` touch | Recorded in `evidence/gate-run.md` as a formatter-only change. |
| N-H - W7's banner printed after both requests | Fixed. It prints before the Core-direct request. |
| N-I - no unit row for the alias's cost statement | Fixed. `test_an_alias_makes_no_core_call_and_writes_no_audit_record` runs every alias under a recorder with a live-capture control and asserts no Core call and no audit record. |

## Security impact analysis

Authored with the `security-analysis` skill against `docs/security-analysis.md`. The
taxonomy and the control categories are the vendored operator's, verbatim in
`docs/background/instructions/threat-modeling.md`.

### 1. Change description

**Business.** Discovery-driven harnesses — the ChatGPT connector first — find the
gateway's OAuth settings at every location the MCP and OpenID Connect discovery orders
name. A discovery path the gateway does not serve answers a plain `404` instead of
Core's authentication refusal.

**Implementation shape.** The gateway registers its existing metadata handler on three
alias paths (D1–D3). The router gains four location blocks: the alias family to the
gateway (D1), Core's two protected-resource templates to Core (D5), and the closed
`/.well-known/` namespace — `= /.well-known` and `/.well-known/` — answering a fixed
JSON `404` with a fixed discriminator header (D4). It also gains two raw-URI maps, the
Core-template gate and the namespace-spelling test, read by a check in the Core location
and one added to the existing catch-all (D9). The change adds no endpoint that issues,
accepts, or stores a credential. It adds no grant type, trust boundary, secret material,
Core call, or audit record kind.

### 2. Surface scope — the shape and the touched entry points

This is a **change on existing surfaces**. The aliases are three more paths serving an
existing static document on EP1's discovery tier; they serve nothing the canonical path
does not. The router locations are routing changes on EP6. Delta threats are
enumerated per touched entry point. Untouched surfaces are covered by the invariant
table, not re-enumerated.

- **EP1** — the public OAuth and discovery endpoints: E2, the flat AS metadata, gains
  three alias paths, one of them at the OpenID Connect location.
- **EP6** — the front router nginx: four new location blocks, two maps, and one check
  added to the catch-all. Two of the blocks are load-bearing for precedence (the closure
  must not shadow; the Core location must not be shadowed), and the two raw-URI checks
  are load-bearing for the closure's raw spelling (D9).

### 3. Impact level, with reasons

**Low.** The sensitive assets near this change are the issuer identity that the mix-up
defense binds to (A3/A5 through RFC 9207's `iss`), and the routing decisions that keep
discovery reachable and Core's discovery surface intact (A13). The aliases publish a
document that is already public and static at the canonical path, so they expose no new
information. The closure narrows what reaches Core, the Core location forwards a
strict subset of what the catch-all forwarded before, and the raw-URI checks only refuse:
they add no forward and narrow what reaches Core further. No credential, token, code, key,
or user datum is newly read, carried, or stored. "No impact" would understate it: a
precedence mistake in the router is an availability break of every sign-in at discovery
(DT-EP6-7), the OpenID Connect location invites a client class the gateway does not
serve (DT-EP1-18), and an issuer that echoed the suffix would break the mix-up defense's
identity (DT-EP1-17). Round 2 re-checked the level after the review: the raw-URI
checks and the discriminator header add no forward, no credential surface, and no new
threat row, so the level stays **Low**. The security review gate runs at low depth — a
focused pass against this SIA and the threat model, which should try to falsify
DT-EP6-9's claim that both normalization directions are closed (D9), and D5's claim
that only Core's literal templates reach Core.

### 4. Invariant ruling table — the never-cut list

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | Preserved | No leg that carries or establishes an upstream credential is touched. The aliases serve a static document, and the Core location forwards an unauthenticated metadata request that carries no credential and that the catch-all forwarded before. |
| 2 | The upstream PKCE verifier never leaves Core | Preserved | Untouched. No flow, no Core call, and no consent leg changes. |
| 3 | Per-user credential isolation | Preserved | No per-user surface is touched. Every new answer is the same for every caller, and no answer depends on any user. |
| 4 | DIAL authorization applies to every toolset call | Preserved | The data path is untouched (`/dial/` and `/apps/` locations unchanged). The closure applies only under `/.well-known/`, which carries no toolset call. The catch-all's raw check only refuses a raw namespace spelling; it never forwards, so it cannot route a call around Core's authorization. |
| 5 | No credential in logs, argv, or error messages | Preserved | The router's `404` is a fixed literal with no request content. The aliases write no record. No new log line exists, and the router's access log stays off. |
| 6 | No hardcoded credentials in the repository | Preserved | No secret material is added. The router conf gains literal paths, a literal body, a literal header, and two path-grammar maps, and `.env.example` is unchanged. |
| 7 | The signing key is IdP-grade secret material | Preserved | Untouched. The aliases name the same `jwks_uri` the canonical document names, and no key handling changes. |

### 5. Threat tables — per touched entry point, the delta threats

#### EP1 — the public OAuth and discovery endpoints

| Attack surface entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| E2's path-insertion aliases — **DT-EP1-17** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Suffixed-issuer mix-up at the path-insertion aliases | The issuer identity the RFC 9207 `iss` check binds to (A3/A5's mix-up defense) | I | Mix-up flaw: an alias answering at `/.well-known/oauth-authorization-server/{suffix}` that echoed the suffix as its `issuer` would assert an issuer identity (`{origin}{suffix}`) that no token or authorization response carries. A client keying its per-authorization-server state by issuer would then treat one server as many. Its RFC 9207 check would compare the emitted `iss` (the origin) with a suffixed issuer and fail, or a lenient client would be pushed to disable the check — which reopens the mix-up class the check closes. An attacker who controls how a victim client derives the issuer gains a confusable second identity for the gateway. |
| E2 at the OpenID Connect location [mis-use] — **DT-EP1-18** | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | OpenID Connect relying party mis-binds the gateway as an OpenID Provider | A3 (a gateway access token presented as an identity assertion) | I | "OAuth for authentication" flaw: a relying party discovers the gateway at `openid-configuration` and leniently treats it as an OpenID Provider. With no ID token, it accepts a gateway access token — or the `sub` inside it — as proof that the user signed in to the relying party. A party holding a token minted for another client or resource (its own, legitimately obtained, or one replayed) presents it there and is logged in as that user. The client uses the new location exactly as published, and the gateway's own behavior is correct throughout. |
| E2's alias family (unauthenticated) — **DT-EP1-19** | Use Control Misconfiguration → Denial of Service → Resource Consumption | Alias-family request flood | A14 (the gateway's worker pool) | A | Three more unauthenticated paths serve the metadata document, and two of them take an arbitrary suffix. A caller floods them, or varies the suffix to defeat any cache in front, to hold gateway workers that legitimate legs share. |

#### EP6 — the front router nginx

| Attack surface entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| The closed-namespace location — **DT-EP6-7** | Use Control Misconfiguration → Denial of Service → Crashing | Closure shadows the served discovery locations | A13 (the routing decision for every discovery path); every sign-in's discovery step | A | A closure written as a `^~` prefix, or as a regex placed before the protected-resource regexes, answers `404` for every toolset and app protected-resource document and for the aliases. Every sign-in then dead-ends at discovery while the data path still answers its challenge naming those documents. The mis-use shape is a maintainer "tidying" the location order or adding `^~` for speed: the configuration is used as permitted, and the outcome is a front-door-wide availability break. |
| The Core protected-resource location and the closure — **DT-EP6-8** | Use Control Misconfiguration → Denial of Service → Crashing | Closure severs Core's own discovery surface | Core's protected-resource routes through the front door (direct-to-Core clients' discovery) | A | If the closure covered Core's two templates, a direct-to-Core client that Core's own challenge pointed at this host would get `404` for its document and could not authorize. That breaks the Core-coexistence requirement. The same break follows from a Core release that adds a `/.well-known/` route the closure then swallows. |
| The new locations' match-versus-forward split — **DT-EP6-9** | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Normalized match, raw forward on the new locations | A13 (which upstream and which handler a crafted URI reaches) | I | nginx selects a location on the normalized URI (decoded, dot-segments resolved, slashes merged). A `proxy_pass` without a URI forwards the client's raw request URI, and Core matches its templates on that raw path. Two directions follow. (i) A raw URI crafted to normalize **into** the alias location or the Core location delivers a different raw path to the gateway or to Core than the location's pattern describes; at the Core location, Core's raw template does not match and its auth-filter `401` comes back on a closed path, and a decoded trailing `%0A` before PCRE's `$` is the same shape. (ii) A raw namespace spelling crafted to normalize **out of** the namespace (`/.well-known/unknown/../../v1/x` → `/v1/x`) selects the catch-all and reaches Core with a raw `/.well-known/…` path. The attacker hopes to reach a handler a location was not meant to expose — another gateway route behind the alias location, a Core route behind the Core location — or to get Core's answer on a URL the closure claims. |
| The router's closed `404` — **DT-EP6-10** | Injection | Reflected content in the router's 404 | The `404` response's body and headers as a client or browser renders them | I | A `404` that echoed the requested path — as nginx's default error page and many framework 404 pages do — would carry attacker-chosen content to whatever renders it: markup in a browser, or confusing text in a client's diagnostics. |

### 6. Mitigations, per threat, in the fixed control-category order

**DT-EP1-17 (suffixed-issuer mix-up at the path-insertion aliases).**
1. Reduce Attack Surface — the aliases have no per-suffix variant. Every alias answers
   from the one builder, so no suffix-dependent document exists to be wrong (delta spec:
   the discovery requirement's alias paragraph).
2. Isolation — not applicable: the issuer is one value built by one function in one
   process. There is no second compartment whose separation would keep the identity
   single; the property is the value's, not a boundary's.
3. Authentication — not applicable: the threat is a false identity *assertion* in a
   public document, not a forged caller. No credential check is in the path of an
   unauthenticated metadata fetch.
4. Authorization — not applicable: the document grants nothing, and the mix-up's harm
   lands at the client's own check, which the gateway does not run.
5. Data Protection — the issuer MUST NOT echo the suffix. It is the public origin in
   every response, the same string the tokens' `iss` and RFC 9207's `iss` carry (delta
   spec).
6. Anti-Injection — the suffix never enters the response: the handler does not read it.
   A unit row asserts byte-identity across suffixes carrying `%22`, `<`, and a long
   segment (tasks: the alias unit rows).
7. Anti-DoS — not applicable to the mix-up: the identity question costs one request.
   The flood shape is DT-EP1-19.
8. Detective — unit rows W2 (issuer equals origin at every alias) and probe row W2
   through the front door; the RFC 9207 `iss` emission's existing tests stay the check
   that the emitted value matches.

**DT-EP1-18 (OpenID Connect relying party mis-binds the gateway as an OpenID Provider)
[mis-use].**
1. Reduce Attack Surface — the document advertises no OpenID Provider capability: no
   `subject_types_supported`, no `id_token_signing_alg_values_supported`, no
   `userinfo_endpoint`, no `openid` scope (delta spec). A conforming relying party
   refuses the provider at discovery.
2. Isolation — not applicable: the misuse happens inside the relying party's own trust
   decision, a component outside this deployment that no boundary drawn here can
   separate.
3. Authentication — bounding: a gateway access token's audience is
   `[resource, dial-mcp-proxy]` (M9). A relying party that validated the audience —
   which OAuth requires of any resource server — would refuse a token not minted for it.
   The misuse needs a relying party that skips audience validation too.
4. Authorization — not applicable: the gateway's own authorization decisions are
   unchanged and correct. The harm is the relying party granting a session the gateway
   never authorized it to grant.
5. Data Protection — not applicable: no confidential material is newly exposed. The
   token the misuse replays is one the presenter already holds.
6. Anti-Injection — not applicable: no input crosses into an interpreter. The misuse is
   a semantic misreading of a valid token.
7. Anti-DoS — not applicable: the misuse is one successful impersonation per replayed
   token. Volume is not its axis.
8. Detective — not available on the gateway side: the misuse completes at the relying
   party with no gateway request beyond an ordinary discovery fetch, which writes no
   record by design. Disposition: mitigated to the relying party's own conformance.
   The class is newly reachable: an OpenID Connect–only relying party never fetches
   `/.well-known/oauth-authorization-server`, so before this change it never found the
   gateway, and the OpenID Connect location now lets it. The exposure is bounded by
   three independent failures in that relying party, all outside this deployment: an
   operator must have configured it to trust the gateway as an OpenID Provider, it
   must skip ID-token validation (the gateway never issues an ID token), and it must
   skip audience validation (M9). On that reasoning no new residual is opened, and
   RES-7's marker-level audience binding is the bounding record.

**DT-EP1-19 (alias-family request flood).**
1. Reduce Attack Surface — the aliases cost what the canonical route costs: one static
   document built from configuration, no Core call, no record, and no state (delta
   spec: the alias paragraph's cost sentence).
2. Isolation — not applicable: the aliases share the gateway's worker pool with every
   route by the single-process design. Separating them would need a second process for
   one static document.
3. Authentication — not applicable: discovery is unauthenticated by necessity. A client
   discovers the server before it has a client identity.
4. Authorization — not applicable: there is no principal to authorize on a public
   metadata fetch.
5. Data Protection — not applicable: the document is public, so a flood reads nothing
   that is not published.
6. Anti-Injection — not applicable: the suffix is not read, so no suffix content reaches
   any parser.
7. Anti-DoS — the router's stated `large_client_header_buffers 4 8k` bounds the suffix
   length. The router-level connection bounds (T6-6, the deployment's tuning) bound the
   rate that reaches the gateway. The aliases do not join the per-source limiter, for
   the canonical route's reason: the limiter bounds state allocation and audit-record
   volume, and the aliases have neither, so a limiter on them would only make discovery
   refusable by volume.
8. Detective — not applicable at the gateway: the aliases write no record by design,
   matching the canonical route. Flood detection is the router's and the platform's
   (T6-6).

**DT-EP6-7 (closure shadows the served discovery locations).**
1. Reduce Attack Surface — the closure is a plain prefix location, which nginx uses only
   when no regex matches. No regex edit can put it in front of a served location (delta
   spec: the well-known-namespace requirement, which forbids `^~` and states the
   precedence).
2. Isolation — not applicable: the closure and the served locations are one nginx
   server block's location table. The control is their ordering semantics, not a
   separation between them.
3. Authentication — not applicable: the failure is a routing decision on
   unauthenticated discovery paths, and no credential takes part in it.
4. Authorization — not applicable: shadowing denies nothing on authority grounds. It
   answers the wrong component, an availability failure.
5. Data Protection — not applicable: no data is exposed. A shadowed request receives the
   fixed `404`.
6. Anti-Injection — not applicable: the locations are static configuration, and no
   request content alters which location matches beyond the path itself.
7. Anti-DoS — this is an availability threat, and its control is the precedence rule
   plus the probe rows that fail on any shadowing (W6, with W1, W2 and W7 as served-path
   witnesses).
8. Detective — probe rows W6 and W7 run before harness runs (M19's gate ladder). A
   one-off mutation run — the closure rewritten as `^~`, W6 failing, then restored —
   shows the detector detects the shadowing (D8). The routing doc's location map names
   the closure's precedence and the `^~` prohibition beside the configured order (repo).

**DT-EP6-8 (closure severs Core's own discovery surface).**
1. Reduce Attack Surface — exactly Core's two templates are forwarded, end-anchored at
   `/mcp` and only on their raw spelling (`$core_prm_raw`, D9), so the exception is no
   wider than Core's own surface (delta spec: the
   well-known-namespace requirement, with the Core-coexistence amendment naming the
   surface).
2. Isolation — not applicable: the Core location and the closure live in one location
   table. The control is the regex-before-prefix precedence, the same semantics
   DT-EP6-7 relies on.
3. Authentication — not applicable: Core's metadata routes are unauthenticated by
   Core's design, and the forward adds no credential and removes none.
4. Authorization — not applicable: Core's answer on its own routes is Core's, and the
   location does not alter it.
5. Data Protection — not applicable: the document Core serves is public configuration.
6. Anti-Injection — not applicable: the request is forwarded raw and unchanged, and
   Core's own template match decides (DT-EP6-9 prices the match-versus-forward split).
7. Anti-DoS — this is an availability threat, and its control is the forward location
   itself plus probe row W7, same-answer as Core-direct.
8. Detective — probe row W7 (front door equals Core-direct). The Core surface record
   names the Core commit it was read at, and its re-open trigger is a Core release
   adding a `/.well-known/` route. The routing doc names the dependency at the location
   (repo).

**DT-EP6-9 (normalized match, raw forward on the new locations).**
1. Reduce Attack Surface — both directions are closed on the raw URI, the claim the
   security review gate should try to falsify (D9). (i) *Into a location.* The Core
   location forwards only when `$core_prm_raw` — a map over `$request_uri` — finds the
   raw URI to be one of Core's two templates, so a spelling that only normalizes onto
   the template (dot segments, percent-encoded characters, a decoded trailing `%0A`)
   gets the closure's `404` and never reaches Core. The alias location ends `(/|\z)`,
   so a decoded trailing line break does not select it. (ii) *Out of the namespace.*
   The catch-all's `$wk_raw_spelling` check hands any raw path whose leading segment is
   `.well-known` in some spelling (merged slashes, `.` segments, `%2F` as a separator,
   percent-encoded characters) to the closure, so a namespace spelling that normalizes
   to `/v1/…` never reaches Core. By the definition, a raw URI whose first segment is
   outside the namespace (for example `/x/../.well-known/…`) is not a namespace
   spelling and is forwarded raw, as the catch-all always did; Core matches on the raw
   path, so it never treats such a path as a `/.well-known/` route. (iii) *Behind the gateway locations*, a raw path reaches only gateway
   handlers the existing gateway locations already reach by the same raw-forward
   mechanism: the alias handler (a static document), the protected-resource handlers
   (the path guard refuses dot-segment and empty-segment paths — the decoded rules), or
   the framework `404`. No gateway route serves content keyed on a raw dot-segment
   path. That half is DT-EP6-5's existing class, bounded as before.
2. Isolation — not applicable: the split is inherent to nginx's location model on every
   location that forwards without a URI, the existing gateway locations included
   (DT-EP6-5's class). No compartment can be drawn between matching and forwarding
   inside one nginx. The raw-URI checks restore agreement at the two Core-bound
   locations instead.
3. Authentication — not applicable: every handler reachable this way is unauthenticated
   by design and serves only public or refusal answers.
4. Authorization — not applicable: no handler behind either location makes an
   authorization decision on the forwarded path. The guard's refusals and the raw-URI
   checks' refusals are validity-shaped and fail closed.
5. Data Protection — not applicable: no reachable handler serves non-public data.
6. Anti-Injection — the raw-URI maps are the M39 discipline applied to this surface:
   anchored patterns over the raw, never-decoded URI, unambiguous alternates, and a
   prefix loop with one path through each iteration, bounded by the stated
   `large_client_header_buffers 4 8k` (DT-EP6-4's discipline). The alias handler
   ignores the suffix. The guard on the protected-resource handlers is the authority
   over the decoded form (M38), and refuses `.`, `..`, and empty segments.
7. Anti-DoS — not applicable beyond DT-EP1-19 and DT-EP1-15's existing bounds: a
   crafted path costs the same constant work as any other request to the handler it
   reaches, and each raw check is one anchored regex over a bounded input.
8. Detective — probe row W10, sent by a verbatim-path client that prints its request
   line, asserts both directions: (a) into the alias location, the gateway's answer;
   (b) out of it into the closure, the router's `404`; (c) into the Core location,
   with `%2e%2e`, `%2E%2E`, and `..%2F` variants, the router's `404`; (d) out of the
   namespace into the catch-all, with the encoded-dot, encoded-name, merged-slash, and
   `.`-segment variants, the router's `404`; (e) the `%0A` edge at both the Core
   template and the alias, the router's `404`; (f) and (g) into a gateway location and
   a data-path location, the gateway's answer and the data path's refusal, recorded.
   No cell carries Core's trace header. The closure cells carry the discriminator
   header, so a refusal that came from the gateway instead fails the row.

**DT-EP6-10 (reflected content in the router's 404).**
1. Reduce Attack Surface — the `404` body is a fixed literal, `{"detail":"Not Found"}`,
   written in the conf with no variable (delta spec: "never reflects any part of the
   request"). There is nothing to reflect into.
2. Isolation — not applicable: the response is generated in nginx's rewrite phase with
   no upstream. No compartment carries request content into it.
3. Authentication — not applicable: the `404` is a public refusal that authenticates
   no one.
4. Authorization — not applicable: there is no decision beyond "closed".
5. Data Protection — not applicable: the body carries no data.
6. Anti-Injection — the body is constant and the type is `application/json`, a type
   browsers do not render as markup, and the fixed `X-Content-Type-Options: nosniff`
   keeps a browser from sniffing it as anything else. No header carries request
   content: the one header the conf adds is that constant.
7. Anti-DoS — not applicable: a constant response costs the least of any answer the
   router gives. The volume shape is T6-6's.
8. Detective — probe rows W4 and W12 assert the exact body, type, and discriminator
   header for several distinct request paths, so a body that varied with the path
   fails the row.

### 7. The grouped mitigation list (the analysis's result)

1. **M43 — The AS-metadata alias set** (delta spec: the discovery requirement's alias
   paragraph and its four scenarios). The one builder and the one handler on three alias
   paths; the issuer always the public origin, never the suffix; no OpenID Provider
   member; `GET`-only with the framework's `405`; no CORS header; the canonical route's
   cost (no Core call, no record). Addresses DT-EP1-17, DT-EP1-18, and DT-EP1-19
   (bounding). Gateway-owned.
2. **M44 — The closed well-known namespace** (delta spec: the well-known-namespace
   requirement; the Core-coexistence amendment; `router/nginx.conf`). The plain-prefix
   closure below every served location, never `^~`; the fixed JSON `404` literal and
   the fixed `X-Content-Type-Options: nosniff` header (added `always`) for every method
   on any request the server-level bounds admit, with no CORS and no challenge header;
   the alias regex ending `(/|\z)`; Core's two protected-resource templates forwarded
   end-anchored and gated on the raw-URI map `$core_prm_raw`; the catch-all's raw-URI
   check `$wk_raw_spelling`, handing any raw namespace spelling to the closure; the
   closure carried in the committed conf the pod runs, which any other fronting must
   reproduce. Addresses DT-EP6-7, DT-EP6-8,
   DT-EP6-9, and DT-EP6-10. Router-owned (repo), spec-pinned.
3. **M45 — The well-known probe rows, controls first** (`scripts/probe_routing.py`;
   rows W0, W0c, W1–W10, W12, and W13, plus the failing-first run W0b and the one-off
   `^~` mutation run; the normalization rows sent by a verbatim-path client). Addresses
   DT-EP6-7, DT-EP6-8, DT-EP6-9, DT-EP6-10, and DT-EP1-17 as the recurring detector.
   Repo-owned.
4. **Existing controls this change leans on, unchanged:** M9 (the access token's
   audience — bounds DT-EP1-18), M15 (the router's stated
   `large_client_header_buffers` — bounds DT-EP1-19), M19 (the gate ladder that runs
   the battery), M35 (the pod contract — the committed conf is the closure's home;
   DT-EP6-1's mis-assembly shape now includes losing it), M38 (the decoded guard —
   bounds DT-EP6-9's gateway half), M39 (the raw-URI map discipline the two new maps
   follow — DT-EP6-9's Core half), and the router-level flood tuning (T6-6).

No threat is left without a mitigation. None is accepted as a new residual: DT-EP1-18's
remaining exposure is the relying party's own conformance, bounded by RES-7's existing
record.

### 8. Threat-model delta (the entries `docs/threat-model.md` gains or changes)

- **New rows:** EP1 — DT-EP1-17, DT-EP1-18, DT-EP1-19. EP6 — DT-EP6-7, DT-EP6-8,
  DT-EP6-9, DT-EP6-10. The entry-point inventory's EP1 bullet names E2's alias paths,
  and the EP6 bullet names the well-known closure.
- **New grouped mitigations:** M43, M44, M45 (§12), with M15's and M35's rows gaining a
  cross-reference to M44.
- **New dispositions:** the seven rows (§13).
- **Restated disposition:** DT-EP6-1 (pod mis-assembly) — a fronting that is not the
  committed conf loses the closure. The consequence is availability-only for
  discovery-probing clients: the pre-change fall-through returns. The pod contract's
  router section states the closure as part of the conf.
- **Re-judged residual:** RES-16 (nginx config fragility) — part (a) gains the
  well-known locations' precedence (the closure's plain-prefix form and the Core
  location's anchoring) and the two raw-URI checks in the fragile set, with probe rows
  W4–W8, W10, and W12 named as its compensating control. Part (c)'s re-open trigger gains "any change to the
  `/.well-known/` locations, or a Core release adding a `/.well-known/` route".
- **New open question:** OQ-13 (the root protected-resource document — OQ-1 below).
  OQ-14 (the `$host`-without-port challenge through the catch-all — OQ-3 below) lands
  in the resolved record, ruled accepted with no change (the owner rulings above).
- **Round 2 re-landing:** the DT-EP1-18 row and disposition (newly reachable, bounded),
  the DT-EP6-9 row and disposition (both directions, raw-URI checks), M44 and M45, RES-16
  (a), and the EP6 bullet are updated in place. No row is added or removed, so the
  counts below stand.
- **Counts:** threats 103 → 110 (EP1 34 → 37, EP6 14 → 18); grouped mitigations
  41 → 44.

### 9. Open questions, and the strict gap list

**Open question (carried past the owner pause):**

1. **OQ-1 — The root protected-resource document** (threat model OQ-13). If ChatGPT
   still fails discovery after this change (row W11), the root
   `/.well-known/oauth-protected-resource` may need a document, not a `404`. One root
   document names one resource. Naming the origin breaks the per-resource RFC 8707
   binding unless the audience rule widens. Any design needs a full SIA of its own, and
   this change answers `404` there deliberately.
**Resolved at the owner pause (3c)** — kept here so neither is re-opened from silence:

2. **OQ-2 — The path-insertion forms answer `200` rather than `404`** (D2). Ruled: `200`
   with the same document, as designed.
3. **OQ-3 — Core's challenge through the catch-all quotes `$host` without the port**
   (D5's observation; threat model OQ-14). Ruled: accepted, no change in this change;
   the threat model closes OQ-14 with that disposition. If it is ever revisited,
   operator-configured Core `toolsets.security.resourceHost` is the preferred remedy.

**Strict gap list** (where the skill's input allowlist did not suffice):

- *Minor*: Core's `/.well-known/` surface (D5) is a fact of DIAL Core's source, outside
  this repository. It was read from Core's public source and recorded in
  `evidence/core-well-known-surface.md` with its commit, so the analysis can be re-run
  from the change folder.
- *Minor*: the ChatGPT discovery behavior is a fact of a third-party client, known only
  from OpenAI's published guide and community reports. The finding record states the
  inference and its negative control. Row W11 is the live confirmation, and its result
  lands in `evidence/`.
- *Minor*: nginx's location-matching order (D4) is a fact of nginx's documentation, not
  of this repository. The probe rows measure it on the router's own image rather than
  trusting the documentation alone.

No Blocking gap.

## Flagged, not fixed (existing material this change found inconsistent)

- **Amendment labels go stale on sync.** Several main-spec requirements carry
  "*Amendment(s), declared (this change):*" records that belong to the
  front-door-addressing change, so after the next sync "this change" names the wrong
  change. This delta relabels only the one record inside the requirement it modifies
  ("(retained — the resource-path re-basing)", declared in its amendment). A
  repo-wide convention — relabel on sync, or label by change name — is the owner's call.
- **`scripts/probe_routing.py`'s module docstring, item 11**, says a status path "falls
  to the catch-all and is answered by Core's own 401". The function's docstring and
  `docs/routing.md` row 10 say the router's map refuses it with a bare `404`, which is
  what the current conf does. The module docstring is stale. This change's probe edit
  is the natural place to correct it (tasks 3.6).
- **`docs/routing.md` cites `openspec/changes/2026-11-13-front-door-addressing-and-redirect/evidence/…`**,
  a path that now lives under `openspec/changes/archive/`. The link is stale. Corrected
  with this change's routing-doc edit (tasks 4.1).
