# The router-mechanism probe — measured on the router's nginx image

Run 2026-11-13 against `nginx:1.27-alpine` (the image family the router runs), a
scratch compose stack (an nginx plus a Python echo server that logs the raw request
line it receives), outside the repository tree. The probe stack was torn down after
the run; the records below are the captured results. Every verdict was produced by a
request actually sent; nothing is inferred from documentation.

## Part 1 — the naive decoded capture is a defect generator (the rejected mechanism)

Config: a permissive multi-segment location
`location ~ ^/dial/(?<tname>[^/]+(?:/[^/]+)*)/mcp$` with
`proxy_pass http://echo/v1/toolset/$tname/mcp$is_args$args;`.

| Request (raw) | nginx answer | What the upstream received |
|---|---|---|
| `/dial/notion/mcp` | 200 | `/v1/toolset/notion/mcp` |
| `/dial/toolsets/public/a%20b/mcp` | **400 (nginx itself)** | — |
| `/dial/a%2Fb/mcp` | 200 | `/v1/toolset/a/b/mcp` — the `%2F` **decodes to a real slash** and splits the segment |
| `/dial/toolsets/public/a%3Fb/mcp` | 200 | `/v1/toolset/toolsets/public/a?b/mcp` — a literal `?` inside the proxied request-target; any conforming server re-splits path/query there |
| `/dial/toolsets/public/a%23b/mcp` | 200 | `…/a#b/mcp` — a literal `#` in the target |
| `/dial/toolsets/public/100%25/mcp` | 200 | `…/100%/mcp` — a raw `%`, an invalid escape at the upstream's door |
| `/dial/toolsets/public/%C3%A9tape/mcp` | 200 | the raw UTF-8 bytes, undelimited, in the target |

Conclusion: nginx matches locations against the **normalized, decoded** URI and a
variable `proxy_pass` passes captured values **without re-escaping**. A decoded
capture cannot faithfully carry percent-encoded names — it 400s some (space),
corrupts others (`?`, `#`, `%`), and aliases the rest (`%2F` vs `/`). Any design that
widens the location regex but keeps decoded capture breaks exactly the matrix cells
the change exists to serve.

## Part 2 — the raw-URI map: byte-faithful, refused shapes refused (the chosen mechanism)

Config: a `map` keyed on `$request_uri` (the raw, never-decoded request URI) carrying
the segment grammar, producing the Core target from the raw capture; a prefix
location `~ ^/dial/` with `if ($dial_target = "") { return 404; }` and
`proxy_pass http://echo$dial_target$is_args$args;`; the challenge map of the
production shape quoting the same capture. The segment grammar (raw form): each
segment allows an optional single leading dot, dots in the middle, and percent
escapes, and refuses whole-segment `.`/`..`, trailing dots, and empty segments;
escapes are `%[0-9A-Fa-f][0-9A-Fa-f]` (the doubled class avoids nginx's
brace-quantifier parse failure — an implementation fact the tasks carry). The
pattern's match domain is the **whole raw request URI**: it is anchored at both ends
with an optional query tail after `/mcp` — `^/dial/(GRAMMAR)/mcp(\?.*)?$` — so
nothing after `/mcp` but the query can match; Part 3's query row
(`…/mcp?sessionId=abc%2F1` forwarded with the parameter intact) is the tail in
action. The post-`/mcp` path-tail refusal was not exercised by this run; it is the
instrument's match-domain row (the tasks' probe battery), recorded here so the
grammar as stated is the grammar the tasks implement and the battery asserts.

| Request (raw, `--path-as-is` where it matters) | nginx answer | Upstream received (verbatim) |
|---|---|---|
| `/dial/notion/mcp` | 200 | `/v1/toolset/notion/mcp` |
| `/dial/toolsets/public/a%20b/mcp` | 200 | `/v1/toolset/toolsets/public/a%20b/mcp` — **byte-identical** |
| `/dial/a%2Fb/mcp` | 200 | `/v1/toolset/a%2Fb/mcp` — the raw `%2F` forwarded; Core answers as it answers on its own port |
| `/dial/toolsets/public/a%3Fb/mcp` | 200 | `…/a%3Fb/mcp` — no corruption |
| `/dial/toolsets/public/a%23b/mcp` | 200 | `…/a%23b/mcp` |
| `/dial/toolsets/public/100%25/mcp` | 200 | `…/100%25/mcp` |
| `/dial/toolsets/public/%C3%A9tape/mcp` | 200 | `…/%C3%A9tape/mcp` |
| `/dial/toolsets/public/deep/folder/path/x/mcp` | 200 | `…/deep/folder/path/x/mcp` — multi-segment |
| `/dial/toolsets/public/.hidden/mcp` | 200 | `…/.hidden/mcp` — leading dot allowed |
| `/dial/toolsets/public/upperCase_X.Y/mcp` | 200 | `…/upperCase_X.Y/mcp` |
| `/dial/a/../b/mcp` | **404** | — dot-segment refused by the grammar (verified with `--path-as-is`; without it curl itself collapses the path — a client-side normalization to remember when writing probes) |
| `/dial/a/./b/mcp` | **404** | — |
| `/dial/../etc/passwd/mcp` | **404** | — |
| `/dial/toolsets//public/x/mcp` | **404** | — empty segment refused (nginx's merge_slashes collapses it for *matching*, but the map sees the raw URI and refuses) |
| `/dial/toolsets/public/trailing./mcp` | **404** | — trailing dot refused |
| `/dial/toolsets/public/a%2e%2e/b/mcp` | 200 | `…/a%2e%2e/b/mcp` — escaped dots forwarded raw; Core judges the decoded `a..` by its own trailing-dot rule |

## Part 3 — the challenge synthesis works through the stacked maps

With the echo server answering 401 on a trigger name, `proxy_hide_header
WWW-Authenticate` + `add_header` from a `$status` map quoting the target map's named
capture:

- `/dial/challenge-me/mcp` → 401, header:
  `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/dial/challenge-me/mcp"`
- `/dial/toolsets/public/challenge-me/mcp` → 401, header quotes the **multi-segment**
  path correctly.
- `/dial/toolsets/public/challenge%20me/mcp` → 401, header quotes
  `…/dial/toolsets/public/challenge%20me/mcp` — the **encoded** spelling, the
  client's own.
- The query string rides raw: `…/mcp?sessionId=abc%2F1` reached the upstream with the
  parameter intact, `%2F` included.
- A grammar-refused 404 carries **no** challenge header (the challenge map's default
  is empty and nginx omits empty-valued headers) — the challenge fires on 401 only,
  the production property.

## What this fixes, mechanically, and what it costs

The named capture of the target map is visible to the challenge map's value template,
so one capture feeds both the Core target and the challenge — the two cannot disagree
about which path was called. The cost, stated: the grammar is a second implementation
of the path rules beside the gateway's guard (the drift risk priced as T-EP6-a,
bounded by the lockstep probes), the `if` is the documented-safe `return` form, and
the regex must avoid nginx's brace-quantifier parsing (doubled classes) and
catastrophic backtracking (the request-line buffer bound; the pathological-URI probe
row).
