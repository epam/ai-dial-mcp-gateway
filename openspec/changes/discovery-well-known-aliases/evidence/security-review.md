# Security review gate — discovery well-known aliases

The security review gate (`PROCESS.md` step 8) on the working-tree diff of this change.
The reviewer is independent of the spec author and the implementer. The SIA records the
impact level as **Low**, so this is a focused pass that tries to falsify the SIA's claims:
D5's "only Core's literal templates reach Core", D9's and DT-EP6-9's "both normalization
directions are closed", and the shadowing, reflection, and CORS claims.

## Method

- Read the diff, `design.md` (D1–D9 and §SIA.1–9), the delta spec, the evidence records,
  and the threat-model rows DT-EP1-17..19, DT-EP6-7..10, and M43–M45.
- **Measured on the router's own image.** The committed `router/nginx.conf` ran unmodified
  in a throwaway `nginx:1.27-alpine` container (nginx 1.27.5). Two echo stand-ins sat
  beside it: `core:8080` returned `CORE uri=$request_uri host=$host` with an `X-Core`
  marker, and a sibling-localhost `127.0.0.1:8091` returned `GW uri=$request_uri` with an
  `X-GW` marker. Each stand-in echoes the raw URI it received, so every row below shows
  which location nginx selected and the exact bytes it forwarded. Requests went out with
  `curl --request-target`, which puts the target on the request line verbatim. The scratch
  files lived outside the repository, and the containers and network were removed
  afterwards.
- Ran `pytest tests/test_discovery.py tests/test_app.py`: 69 passed.
- Read the gateway route table (`gateway/app.py`, `routes.py`, `authorize.py`,
  `federation.py`, `token.py`) to check whether a raw forward through a gateway location
  can reach a route the router does not expose.

## Findings

### BLOCKING

None.

### SHOULD-FIX

**SF-1 — The catch-all's raw namespace check misses `%2F` as a leading separator. The
"out of the namespace" direction is not closed as the spec's MUST states it.**

- **Where:** `router/nginx.conf:149-152` (the `$wk_raw_spelling` map). The claim is
  repeated in `docs/threat-model.md:928` (DT-EP6-9: "the catch-all refuses any raw path
  spelled in the namespace"), in M44 (`docs/threat-model.md:2158`), in design D9, and in
  `docs/routing.md:188`.
- **The spec text it falsifies:** "MUST NOT forward to Core any other request whose raw
  path is spelled in the namespace — whose first segment, after any empty or `.` segments
  and **with percent-escapes read as the characters they encode**, is `.well-known`".
  `%2F` read as the character it encodes is `/`, so `/%2F.well-known/…` has an empty
  segment followed by `.well-known`. nginx also treats a decoded `%2F` as a separator when
  it normalizes, as D9 itself states for the `%2F` after the name.
- **Reproducer (measured):**

  | Raw request line | Observed |
  |---|---|
  | `GET /%2F.well-known/unknown/../../v1/x HTTP/1.1` | `200` from the Core stand-in; Core received `uri=/%2F.well-known/unknown/../../v1/x`. No closure. |
  | `GET /%2f.well-known/unknown/../../v1/x` | Same: forwarded to Core raw. |
  | `GET /%2E%2F.well-known/unknown/../../v1/x` | Same. |
  | `GET /.%2F.well-known/unknown/../../v1/x` | Same. |
  | `GET /%2F%2F.well-known/unknown/../../v1/x` | Same. |
  | `GET //.well-known/unknown/../../v1/x` (control) | The closure's `404` with `nosniff`. |

  Each request normalizes to `/v1/x`, selects `location /`, and fails the map, because
  the map's prefix loop `(?:/(?:\.|%2[Ee])?(?=/))*/` accepts only a literal `/` as the
  separator. Against the real Core, each answers Core's auth-filter `401` on a raw
  `/.well-known/` URL. That is the exact outcome D9 says the check prevents.
- **Security impact:** None beyond what existed before the change. The catch-all already
  forwards any raw URI to Core, Core's own authorization applies, and no legitimate client
  sends this spelling. The finding is SHOULD-FIX, not BLOCKING, for that reason. It is
  still a false MUST and a false "closed" claim in the SIA and the threat model, and the
  review gate exists to catch exactly that.
- **Fix (verified on the same image):** treat `%2F` as a separator inside the prefix loop:

  ```nginx
  "~^/(?:(?:\.|%2[Ee])?(?:/|%2[Ff]))*(?:\.|%2[Ee])(?:w|%77)(?:e|%65)(?:l|%6[Cc])(?:l|%6[Cc])(?:-|%2[Dd])(?:k|%6[Bb])(?:n|%6[Ee])(?:o|%6[Ff])(?:w|%77)(?:n|%6[Ee])(?:/|%2[Ff]|\?|$)" 1;
  ```

  With this map, all five rows above get the closure's `404` with `nosniff`. The existing
  spellings (`/.well-known/…`, `//`, `/./`, `/%2Ewell-known`) are still refused. Non-namespace
  paths (`/v1/x`, `/v1/.well-known/x`, `/x/.well-known`, `/.wellknown/x`, `/.%2Fwell-known/x`)
  and the served locations (the Core template, `openid-configuration`) are unaffected. The
  pattern stays linear: each loop iteration is an optional dot followed by a mandatory
  separator, so a wrong guess backtracks at most one token. `/` plus 1300 copies of
  `%2E%2F` answered in 2 ms, and `/` plus 2600 copies of `%2F` in 3 ms. Update the map's
  comment ("after any empty or `.` segments, either separator spelled `/` or `%2F`").
- **Detector:** add `/%2F.well-known/unknown/../../v1/x` and
  `/%2E%2F.well-known/unknown/../../v1/x` to W10 cell (d) (`scripts/probe_routing.py:1280-1286`).
  Mutation reasoning: on the committed conf these cells fail (measured above: Core's
  answer, no `nosniff`), and with the fix they pass. That is the negative control the cell
  needs.

### NIT

**N-1 — The Core gate's comment and D9 overstate what "dot segments do not match" covers.**
`router/nginx.conf:132-133` and design D9 (around `design.md:415`) say that a spelling with
dot segments does not match `$core_prm_raw`. That holds only for dot segments outside
`{id}`. Inside `{id}`, `[^?]+` admits them, and so does Core's own raw `(?<id>.+?)`.

Measured: `GET /.well-known/oauth-protected-resource/v1/toolset/a/../b/mcp`,
`…/toolset/a/%2e%2e/b/mcp`, `…/toolset/x/mcp%23/y/mcp`, and
`…/toolset/x/mcp#/../../../../../v1/admin/mcp` are all forwarded to Core raw. This is
*consistent* with D5's actual invariant: each raw path matches Core's template on Core's
raw `request.path()` (the path up to the first `?`), so Core's unauthenticated metadata
controller answers it, and no other Core handler can. It was also forwarded before the
change, through the catch-all.

Fix: reword the comment to "a spelling that normalizes onto the template from outside it —
dot segments before or across `{id}`'s prefix, an encoded character in `toolset`, a
decoded trailing line break — does not match; dot segments inside `{id}` do, as they do in
Core's own template".

**N-2 — The Core location forwards every method.** `POST`, `OPTIONS`, and `DELETE` on
`/.well-known/oauth-protected-resource/v1/toolset/x/mcp` reach Core (measured). Core's
templates are `GET`-only, so the real Core answers `POST` with its auth-filter `401` and
`OPTIONS` with `200` and `Access-Control-Allow-Origin: *`, on a `/.well-known/` path.

This is not new exposure: the catch-all forwarded the same requests before, and the CORS
header is Core's posture on Core's own route. It is a small gap against the change's goal
of not leaving Core's `401` on a discovery path. The cheap remedy is `limit_except GET {
deny all; }`, but `deny` answers `403` and not the closure's body. Alternatively, record
in D5 that non-`GET` methods on the two templates stay Core's answer. A design note is
enough.

**N-3 — Version disclosure on the new 404.** The closure's `404` carries
`Server: nginx/1.27.5`, measured. That fact was already disclosed on every nginx-generated
answer (the data path's `404`, the `413`), so nothing is new. `server_tokens off;` at the
`http` level is a one-line hardening for a later change. It matters a little more while
the base image carries known CVEs (see the Trivy section).

**N-4 — The carve-out for "first segment is something else" deserves one sentence in
DT-EP6-9.** `GET /x/../.well-known/unknown/../../v1/x` and
`GET /v1/x/..%2F..%2F.well-known/y/../../v1/z` reach Core raw (measured). This is by the
spec's own definition: they are not namespace spellings. The threat-model row's phrase
"both directions closed" reads as broader than the definition. Add "by the spec's
definition of a namespace spelling (the leading segment); a raw path that only passes
through `.well-known` via dot segments is forwarded as the catch-all always did". This
note is harmless as long as Core matches on the raw path and so never treats such a path
as a `/.well-known/` route.

## Claims checked and upheld

1. **Into the Core location (D5).** Every raw spelling that normalizes onto the template
   from outside it was refused with the closure's `404` and `nosniff`. Measured cases:
   `/.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/x/mcp`,
   `…/v1/toolset/a/../../../../../v1/toolset/b/mcp`, `…%2F..%2F…`, `…/mcp%0A`, `…/mcp;a`,
   `…/mcp/`, `…/mcp/..%2Fmcp`, and `…/mcp#frag`. `%00` and a dot segment above the root
   are nginx's `400`. Every forwarded raw URI ends `/mcp` before the first `?`, starts with
   Core's literal template prefix, and contains no `?` before that point. So it is matched
   by Core's raw template, and only Core's unauthenticated metadata controller can answer
   it.
2. **Out of the namespace (D9).** Literal `.well-known`, `%2E`- and `%2e`-encoded names,
   `%2F` after the name, `//`, `/./`, and absolute-form targets
   (`GET http://evil.example/.well-known/unknown/../../v1/x`) were all refused. The only
   gap is SF-1. Backslash, `;`, and upper-case spellings reach Core, but they are not
   namespace paths on Linux nginx, which is case-sensitive and does not treat `\` as a
   separator.
3. **No shadowing (DT-EP6-7, DT-EP6-8).** The exact AS location, the alias family, the
   `/dial/` and `/apps/` PRM documents, and Core's template all reached the intended
   upstream with the closure in place. The closure blocks are plain prefixes, and the
   `rewrite ^ /.well-known/ last` target is matched by no regex location, so the internal
   redirect always lands in the closure and cannot loop. The authorization-surface
   location `^/dial/(callback|…)`, the data paths, and `/healthz` lie outside
   `/.well-known/` and are unaffected. The new raw checks sit only in the Core location
   and in `location /`.
4. **No second issuer, no reflection (DT-EP1-17, DT-EP6-10).** The alias handler ignores
   the suffix and builds from `runtime.settings` alone (`gateway/routes.py:74-88`). The
   unit rows assert byte identity across seven suffix shapes, with DCR both off and on.
   The router's body is a literal. A `%0D%0A`-carrying target produced no injected header,
   because no `add_header` or `rewrite` interpolates request content. Absolute-form targets
   change `$host`. The gateway documents never read it. The `Host` forwarded to Core is the
   existing OQ-14 behavior, ruled accepted, and is not widened here.
5. **CORS and `if` (D6).** The closure answers `POST`, `OPTIONS` (with a preflight
   `Origin`), `DELETE`, and `HEAD` with `404`, `nosniff`, and no `Access-Control-*` header.
   `HEAD` has no body. Both `if` blocks contain only `rewrite … last`, one of the two
   directives nginx documents as safe inside `if` in a location. The data-path `if`s are
   unchanged.
6. **Gateway alias routes (D1).** `{suffix:path}` exists only under the two AS prefixes, so
   it cannot match a PRM path, and it does not bypass the resource guard. Every gateway
   route is already exposed by a router location, so a raw forward through the alias
   location reaches nothing the router hides. One change in outcome: through the gateway
   location, a raw `GET /.well-known/openid-configuration/../../dial/token` now gets the
   public AS document instead of the gateway's `404`, and a `POST` to it gets `405`.
   Neither touches token handling. The W10(f) cell records the gateway's answer and
   accepts this.
7. **Threat-model rows.** DT-EP1-17, DT-EP1-18, DT-EP1-19, DT-EP6-7, DT-EP6-8, and DT-EP6-10
   are accurate, and their mitigations are implemented and tested. DT-EP6-9 and M44 are
   accurate except for the SF-1 overclaim and the N-4 wording.
8. **Never-cut invariants 1–7.** Preserved. No credential path, log line, secret, or
   data-path routing changed. The catch-all's check only refuses.
9. **Detectors.** The mutation table's reasoning holds:
   - Disabling the catch-all check reopens exactly W10(d).
   - Disabling the Core gate reopens W10(c) and W10(e). nginx's normalized `$` matches
     before the decoded LF, so the location is selected, and only the gate refuses.
   - Replacing `\z` with `$` reopens the alias cell of W10(e).
   - Under `^~`, W0c and W6 fail.

   The unit rows would fail if the handler echoed the suffix (byte identity), added an
   OpenID Provider member, or registered a non-`GET` method. The gap: no cell exercised a
   `%2F` prefix, which is why SF-1 went unseen.

## Trivy (the base image's 70 HIGH and CRITICAL findings)

This change makes none of them more reachable:

- It adds no module, library, or directive class the router did not already use.
  `map` over `$request_uri` with PCRE2, `if` plus `rewrite`, and `return` all ran on
  attacker-controlled URIs before (the data-path maps and their `return 404`).
- The new PCRE2 patterns are fixed at startup. Only the subject string is
  attacker-supplied, and it is bounded by `large_client_header_buffers 4 8k`. The PCRE2
  issues in this class concern crafted patterns, not crafted subjects.
- `libxml2`, `libxslt`, `libpng`, `tiff`, `curl`, and the other flagged packages are not
  on the request path of this configuration. `curl` serves only the container healthcheck.

The remedy remains the base-image bump that `gate-run.md` already flags.

## Stand-in caveat

The Core side of these measurements is an echo stand-in. That is sufficient for every
claim about which location nginx selects and what it forwards, which is the subject of
this review. Two claims rest on the Core-source record (`core-well-known-surface.md`), not
on a measurement: that Core matches its templates on the raw `request.path()`, and that
Core treats `#` as an ordinary path character. The owner-run W11 against the real
deployment, with SF-1's two new cells added, closes that gap.

## Verdict

**PASS WITH FIXES.** Apply SF-1 (the one-line map change and two W10(d) cells) and correct
the DT-EP6-9, M44, and routing-doc wording to match. The NITs are optional. No blocking
security defect was found. The impact level of Low is confirmed.
