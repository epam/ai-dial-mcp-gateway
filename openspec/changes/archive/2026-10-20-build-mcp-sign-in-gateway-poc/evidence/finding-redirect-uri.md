# Finding — a CIMD client's loopback `redirect_uri` is rejected for its port alone

**Status:** fixed and verified — the matcher is changed, the test split landed, and the
live battery re-ran green (see "Fix verified" at the end of this file). Originally
reproduced from the field failure against the live composed stack; captured values below.

**Symptom.** A real Claude Code harness run against the front door twice (owner, live).
Discovery and client resolution succeeded — the harness reached `/dial/authorize` with the
CIMD client id it read from E2's `client_id_metadata_document_supported`, so the document
was fetched and cached. The browser then landed on the gateway's own JSON refusal:

```
HTTP 400
{"error":"invalid_request","error_description":"redirect_uri is not one this client registered"}
```

The exact authorize URL the browser addressed (decoded):

| parameter | value |
|---|---|
| `client_id` | `https://claude.ai/oauth/claude-code-client-metadata` |
| `redirect_uri` | `http://localhost:45002/callback` |
| `code_challenge_method` | `S256` (`code_challenge` present) |
| `scope` | `default` (the harness echoing the PRM's `scopes_supported`; dropped by D10, not the failure) |
| `resource` | `http://localhost:8090/dial/notion/mcp` (the correct per-toolset value) |
| `state` | present |

`45002` is an **ephemeral** port the harness obtained from the OS at request time, not a
value any registration could have pinned.

## Evidence

### 1. The client-metadata document, fetched live

`GET https://claude.ai/oauth/claude-code-client-metadata` (2026-10-19, `HTTP 200`,
`content-type: application/json`), body verbatim:

```json
{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}
```

Member-by-member against the request — **both entries are loopback, both are port-less**:

| document `redirect_uris` entry | vs. harness's `http://localhost:45002/callback` |
|---|---|
| `http://localhost/callback` | scheme `http` ✓, host `localhost` ✓, path `/callback` ✓, **port absent vs `45002` ✗** |
| `http://127.0.0.1/callback` | scheme ✓, host `localhost` vs `127.0.0.1` ✗, path ✓, port ✗ |

So the harness's URI is the document's **first** entry with a dynamic port added. The
port is the **only** difference against an entry the document does list — scheme, host
and path are byte-identical. It is not a case of the document omitting loopback entirely
(it lists nothing but loopback), and it is not a stale or failed fetch (the document is
served by the allowlisted origin; the cache is not implicated — see §3).

### 2. The failing comparison, isolated by probe

Probe: `scripts`-style script at a temp path (not committed), driving the live front door
at `http://localhost:8090` with abridged replayed parameters, recording status and body.
The gateway's source for the string is
`gateway/authorize.py:178` → `redirect_uri_allowed()` in `gateway/cimd.py:424`, which is
`return redirect_uri in client.redirect_uris` — **exact tuple membership**, no
normalization (the docstring says so deliberately).

`/dial/authorize`, `client_id` = the CIMD URL:

| # | `redirect_uri` sent | status | verdict |
|---|---|---|---|
| **N** | `http://127.0.0.1:9999/not-registered-anywhere` | 400 | **REJECTED — the negative control; the probe can fail** |
| C1 | `http://localhost/callback` (document entry, verbatim) | **302** | ACCEPTED |
| C2 | `http://localhost:80/callback` (explicit default port) | 400 | REJECTED |
| **C3** | **`http://localhost:45002/callback` (the field value)** | **400** | **REJECTED — reproduced** |
| C4 | `http://localhost:45002/notcallback` (path differs too) | 400 | REJECTED (A/B of port-vs-path: confirmed in §4) |
| C5 | `https://localhost/callback` (scheme differs) | 400 | REJECTED |
| C6 | `http://127.0.0.1:45002/callback` (second entry + dynamic port) | 400 | REJECTED |
| C7 | `http://127.0.0.1/callback` (document entry, verbatim) | **302** | ACCEPTED |
| C8 | `http://0.0.0.0/callback` | 400 | REJECTED |
| C9 | `http://[::1]:45002/callback` | 400 | REJECTED |
| C10 | `http://localhost/callback/` (trailing slash) | 400 | REJECTED |

The **negative control ran first and failed as it must** (case N), so the probe is a
proven instrument before any red verdict is read. C1 and C7 are the positive controls:
the *same* client, *same* endpoint, *same* request shape, accepted the instant the URI is
the document's own port-less text.

Statuses only; no credential appears in this record (a `code_challenge` and a `state` are
non-secret by construction and are not reproduced here; the redirect `Location` on the 302
rows points at Keycloak and carries the gateway's own PKCE challenge and flow state, not a
token).

### 3. The CIMD cache is not implicated

A stale/failed fetch would have surfaced as `invalid_client` at `_resolve_client`
(`gateway/cimd.py` raises `CimdError`, `authorize.py` maps it to `invalid_client`, message
"this client id is not registered with the gateway"). The observed error is
`invalid_request` from `authorize.py:181-183`, which is reached **only after** the client
resolved with a non-empty `redirect_uris` tuple. Cases C1/C7 returning 302 prove the
document and its entries are the ones fetched live above, from the same cache entry the
failing request used (`gateway_cimd_cache_ttl_seconds` default 300 — all cases ran inside
one TTL window).

### 4. A/B isolating port from path

C3 vs C1 differs in the port and nothing else → reject. C4 differs in the path as well →
also reject. The point is that **no accepted case carries a port at all**, and every
rejected case either adds a port to a port-less entry, changes scheme, changes host, or
changes the path. The predicate under test is therefore exact string equality, and the
port is precisely what the harness cannot fix on its side.

### 5. The behavior the standards require

- **RFC 8252 §7.3** (OAuth 2.0 for Native Apps), verbatim: the loopback URI is
  *"...constructed with the loopback IP literal and whatever port the client is listening
  on"*, and **"The authorization server MUST allow any port to be specified at the time of
  the request for loopback IP redirect URIs"**.
- **RFC 8252 §8.4**, verbatim: **"the exception is loopback redirects, where an exact match
  is required except for the port URI component."**
- **MCP authorization (2025-06-18)** requires exact redirect-URI validation
  (*"Authorization servers MUST validate exact redirect URIs against pre-registered
  values"*) and, in the same document, **"All redirect URIs MUST be either `localhost` or
  use HTTPS"** — i.e. loopback callbacks are the spec's own expected client shape, and the
  MCP spec delegates the loopback-port rule to the OAuth base it cites.
- **CIMD draft §4.2** requires exact string comparison of the redirect URI against the
  registered values, and carries **no** loopback/port carve-out of its own. So a CIMD-only
  reading supports the shipped exact match; the carve-out arrives from the native-app
  layer the harness actually is. This tension is the authoring question, not a bug in the
  draft.

Claude Code is a native app serving a loopback callback on an OS-chosen ephemeral port
(documented behavior — the sibling instance's own PoC notes record the same class and the
`--callback-port` escape hatch, `docs/background/poc-dial-mcp-signin.md` §4).

## Root cause

`gateway.cimd.redirect_uri_allowed` implements **exact string equality** against the
fetched document's `redirect_uris`. The document registers its loopback callbacks
**without a port** (`http://localhost/callback`, `http://127.0.0.1/callback`), while
RFC 8252 §7.3/§8.4 entitles the client to present the **same** loopback URI with whatever
ephemeral port it obtained, and to have the AS match it ignoring the port. The two
port-less entries and the harness's `http://localhost:45002/callback` are therefore not
string-equal, the membership test at `gateway/cimd.py:431` returns `False`, and
`authorize.py:178-183` refuses with `invalid_request`.

The failure is **not** a misconfiguration and **not** a document mismatch: the client's
registration is correct, the harness's URI is correct, and the gateway applies a stricter
rule than the one that governs the client class it is serving. The build's own tests
encode the strict rule as the intent (`tests/test_cimd.py:568`,
`test_redirect_uri_matching_is_exact`, asserts a differing port is rejected), so the code
matches its tests and both diverge from the loopback rule — this is a specification gap
surfacing in play, not an implementation slip against a written rule.

## Proposed fix (author's decision, not implementation improvisation)

**A loopback-port-variation exception in the matcher.** When the *registered* entry is a
loopback URI — `http` scheme and host one of `127.0.0.1`, `[::1]`, or `localhost` — compare
the URI ignoring the **port** and require exact equality of scheme, host and path. Both
spellings belong in scope: §7.3's carve-out is written for the loopback **IP literal**, and
§8.3 says the `localhost` form *"function similarly to loopback IP redirects described in
Section 7.3"* (`localhost` is only *NOT RECOMMENDED*, not out of scope) — and the document
below registers `localhost`, so a literals-only rule would not fix this failure. The rule:

- Port-less entry `http://localhost/callback` matches `http://localhost:<any>/callback`.
- Scheme, host and path stay exact — no case folding, no trailing-slash folding, no host
  aliasing (`localhost` ⇔ `127.0.0.1` must **not** be folded together unless the author
  rules otherwise; the harness presents the host it registered).
- The exception applies **only** when the registered entry is loopback-`http`. Any
  non-loopback or `https` entry keeps today's exact string equality unchanged.

**Security note (must accompany the fix).** Loopback-port matching must not weaken the
binding for anything else, and the argument is that it cannot:

- The registered host and path are still exact, so a stolen registration cannot be turned
  into a redirect to a different host or path; widening the port on a loopback URI keeps
  the code's destination on the **user's own machine**, which is the property the carve-out
  rests on.
- The exception is keyed on the **registered** (server-side, fetched) entry, never on the
  request's value — a hostile request cannot self-declare as loopback to earn the
  relaxation unless the client's own document already registered a loopback URI, which is
  already a user-local redirect target.
- It must not extend to `https` on a loopback host, to private/link-local/`0.0.0.0`, or to
  non-loopback hosts, and never to scheme or path.
- The negative control (case N, a foreign URI) must still be rejected after the fix; the
  re-test's first row is that control, then C3 (now 302), then a non-loopback URI on a
  varied port (still 400).

**Alternatives considered and why they are not the fix:** (a) adding
`--callback-port` on the harness side is a per-harness workaround that leaves the AS
non-conformant and un-usable by un-configurable clients — the sibling PoC already
documents it as a fallback, not a remedy; (b) relaxing to prefix/substring matching is the
normalization `gateway/cimd.py`'s own docstring rejects and would open scheme/host/path
slack.

## Spec ripple — yes, an authoring ripple is required

The delta spec pins the rule but stages it loosely:

- `openspec/changes/build-mcp-sign-in-gateway-poc/specs/mcp-signin/spec.md:43` —
  *"`redirect_uri` MUST be validated against the registration"*.
- The **Unregistered redirect URI** scenario (same file) — *"WHEN an authorization request
  carries a redirect URI absent from the client's resolved registration THEN the request is
  rejected"*.

Neither states *how* the match is performed, so a reader cannot tell from the spec whether
exact string equality or the RFC 8252 loopback rule is intended — and the shipped code
chose the stricter one. Per `PROCESS.md`'s "Unspecified behavior is spec'd first", the
loopback-port rule must be **stated in the delta spec before the matcher changes**: a
requirement line (or a scenario) naming the exception and its bounds — loopback-`http`
registered entry, port ignored, scheme/host/path exact, non-loopback unchanged. That is an
authoring pass (opus) plus the independent review and the owner pause, not a code edit.

The design's `D5` bullet (`design.md:224-225`, *"`redirect_uri` ... must appear in the
fetched document's `redirect_uris`"*) reads as exact membership and should be restated to
carry the exception explicitly, in the same pass, for the same reason the spec line is
being written.

The build's evidence table therefore also carries a stale assumption:
`evidence/group-3.md` row 3.4 and its `tests/test_cimd.py` line both describe
"exact `redirect_uri` matching" as the criterion met, and `test_redirect_uri_matching_is_exact`
asserts a differing port is rejected — that test will need to be **split** (the non-loopback
half stays; the loopback half inverts), which is an implementation-task ripple for the
change's `tasks.md`.

## Negative control / instrument record

- Probe run against the live composed stack (`ai-dial-mcp-gateway-mcp-signin-router-1` on
  `:8090`, `...-gateway-1` healthy).
- **Negative control first:** case N (a foreign loopback URI on a port no document lists)
  → 400. Passed as required — the probe rejects, so an ACCEPTED reading is meaningful.
- Positive controls: C1 and C7 → 302.
- The field value: C3 → 400, byte-identical error string to the owner's browser capture.
- Probe scripts were written to a temp directory outside the repo and are not committed;
  the harness's own `state`/`code_challenge` from the owner's capture were not replayed
  (the probe generated its own). Gateway container logs carried no authorize records (the
  audit trail is per-flow and this refusal is pre-allocation), so the evidence is
  HTTP-level, reproduced, not log-derived.
- **Repo state restored / unperturbed:** `git status --short` is empty. The probe created
  no registrations (CIMD path, no `/register` call) and the only gateway side effects are
  CIMD cache entries and short-TTL flow records from the two 302 controls, both expiring on
  their own (`gateway_cimd_cache_ttl_seconds` 300, `gateway_flow_ttl_seconds` 600).
- No token, code, or secret appears in this record.

## Spec ripple (authoring pass)

The authoring ripple identified above is landed; the matcher's code fix is left for the
next (implementation) pass. What changed, where:

- **`specs/mcp-signin/spec.md`** — the matching rule is now normative. A new ADDED
  requirement, "Loopback redirect URIs match ignoring the port", states it: for a
  registered entry that is a loopback redirect URI (`http` scheme; host `localhost`,
  `127.0.0.1`, or `[::1]`), a request redirect URI matches on identical scheme, host,
  and path with any port (RFC 8252 §7.3); every other registered URI matches on exact
  string equality only; the exception is keyed on the registered entry, never on the
  request's value, and extends to no `https` entry, no non-loopback host, and no
  scheme or path difference. Three scenarios: loopback port variation accepted
  (registered port-less loopback entry, request with an ephemeral port), non-loopback
  port difference rejected (with the keyed-on-registered-entry bound stated), and
  loopback scheme/host/path difference rejected. The existing "Unregistered redirect
  URI" scenario was reworded to "matches no entry … under the redirect-URI matching
  rule" so the two requirements cannot be read as disagreeing. The rule lives in its
  own requirement rather than appended to the registration requirement because that
  requirement's text is already at the 500-char bound.
- **`design.md` D5** — the exact-membership bullet is replaced by the
  loopback-variation rule with the measured reason (native clients bind an ephemeral
  port per launch; the document registers its loopback callbacks port-less, so exact
  membership refuses every live harness request for its port alone) and the same
  bounds (keyed on the registered entry; no `https`, no non-loopback host, no
  scheme/path extension). The DCR tail of the bullet is unchanged.
- **`tasks.md`** — task 3.11 added (group 3, unchecked): the matcher fix in
  `gateway/cimd.py`, the `test_redirect_uri_matching_is_exact` split (the non-loopback
  exact-match half stays; the loopback half inverts to accept port variation and
  still reject scheme/host/path changes and non-loopback port differences), the
  authorize probe battery re-run (negative control first — the
  `not-registered-anywhere` URI still rejected; the port-varied loopback field value
  now accepted; a non-loopback URI on a varied port still rejected), and the re-test
  evidence whose row corrects `evidence/group-3.md` row 3.4's stale "exact
  `redirect_uri` matching" criterion.

**Left for the next pass:** the matcher change in `gateway/cimd.py`, the test split,
and the re-test evidence. No source code was touched in this pass; nothing was
committed.
## Ripple review (fresh reviewer pass) — needs-changes, five authoring-accuracy fixes

The rule is sound and RFC-faithful (verified against RFC 8252 §7.3/§8.3/§8.4 fetched
live); all five findings are within the same authoring pass:

- **F1 (MAJOR)** — `specs/mcp-signin/spec.md` ~line 47, scenario "CIMD registration
  without a registration call": "accepted only for redirect URIs the document lists"
  contradicts the new rule (a port-varied loopback URI is accepted but not listed).
  Reword to the matching-rule phrasing.
- **F2 (MAJOR)** — the exception's boundary on a registered loopback entry WITH an
  explicit port is unpinned (Scenario 1's WHEN narrows to port-less entries; the live
  fixture `http://127.0.0.1:8766/callback` is a loopback entry with a port). Fix:
  state the port is ignored on both sides, or add an explicit-port scenario (also
  settles the `:80` default-port case).
- **F3 (MAJOR)** — task 3.11's split inventory misdescribes
  `test_redirect_uri_matching_is_exact`: there is no foreign-host rejection in it;
  the path/case/trailing-slash asserts run against the LOOPBACK registration (they
  stay, in the loopback half); the assert that must INVERT is the port-only loopback
  difference (`:8767` vs `:8766`) — unnamed in the task. An implementer following it
  literally could keep that assert and key the exception on port-less entries only.
  Fix the parenthetical; name the inverting assert; add a foreign-host case to the
  non-loopback half.
- **F4 (MINOR)** — query/fragment components unpinned by "identical scheme, host, and
  path": add a clause — only the port is excepted; any query/fragment presence or
  difference is non-matching (consistent with the docstring's query-folding
  rejection).
- **F5 (MINOR)** — the stale "exact redirect_uri matching" wording is in
  `evidence/group-3.md`'s test-summary table (tests/test_cimd.py row), not row 3.4
  (whose wording is fine). Point the correction at the right row.

## F1–F5 fixes applied (authoring pass)

All five findings fixed in the authoring artifacts; no source code touched; nothing
committed. What changed, where:

- **F1** — `specs/mcp-signin/spec.md`, scenario "CIMD registration without a
  registration call": the THEN is reworded from "accepted only for redirect URIs the
  document lists" to the matching-rule phrasing — "accepted only for redirect URIs
  that match an entry of the document's `redirect_uris` under the redirect-URI
  matching rule" — so it no longer contradicts the loopback requirement.
- **F2** — `specs/mcp-signin/spec.md`: the loopback requirement's text now states the
  port is ignored **on both sides** (a registered explicit-port entry, a default port
  included, matches a request with any port), and a new scenario "Explicit-port
  loopback entry matches port variation" pins the case — a registered explicit-port
  loopback entry, default port included, matches a request with a different port —
  settling the `:80` default-port case and the live fixture's shape
  (`http://127.0.0.1:8766/callback`). `design.md` D5 and `tasks.md` 3.11 carry the
  same both-sides statement. The requirement text stays at 461 chars (the dropped
  "extends to no `https`, non-loopback, scheme, or path difference" tail is carried
  by the "Every other registered URI MUST match on exact string equality only"
  sentence and the two rejection scenarios).
- **F3** — `tasks.md` 3.11's split inventory is corrected against the actual asserts
  of `test_redirect_uri_matching_is_exact`: the test's registration is itself a
  loopback entry with an explicit port (`http://127.0.0.1:8766/callback`), so its
  path, case, and trailing-slash rejections stay in the **loopback** half; the
  inverting assert is named — the port-only loopback difference
  (`http://127.0.0.1:8767/callback` vs the registered `:8766`), which flips to
  accepted; the non-loopback half is new, against a non-loopback registration, and
  gains the foreign-host case the current test lacks. The verify list gains the
  explicit-port loopback entry branch.
- **F4** — the loopback requirement's text, `design.md` D5, and `tasks.md` 3.11 each
  gain the clause: only the port is excepted; any query or fragment presence or
  difference is non-matching.
- **F5** — `tasks.md` 3.11's evidence sentence now points the correction at
  `evidence/group-3.md`'s test-summary table (the `tests/test_cimd.py` row, whose
  "exact `redirect_uri` matching" wording is stale), not row 3.4 (whose wording is
  accurate).

## Fix verified (implementation pass, task 3.11)

The matcher is fixed, the test split landed, and the battery was re-run against the live
composed stack. No credential material appears below: the probe generated its own PKCE
pair and state, and only statuses and the `Location` host of an accepted redirect are
recorded.

### The matcher change

`gateway/cimd.py` — `redirect_uri_allowed` keeps exact string equality as its first test,
and adds one exception keyed on the **registered** entry:

- A new module-level constant `_LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}`
  and a helper `_loopback_target(uri)` that returns the URI's comparable components
  `(scheme, host, path, query, fragment)` when it is a loopback `http` URI, and `None`
  otherwise. Only scheme and host are read in normalized form (RFC 3986 §3.1/§3.2.2 make
  neither case-sensitive, and `urlsplit` is what normalizes them); path, query and
  fragment are the raw text, so dropping or folding either stays non-matching. A URI
  carrying credentials, an unparseable URI, a non-`http` scheme, and any host outside the
  set all return `None`.
- `redirect_uri_allowed` returns exact membership first; when that fails, it computes the
  **request's** target and asks whether **any registered entry's** target equals it. A
  non-loopback registered entry yields `None` there and can never equal the request's, so
  the exception never applies to a registration that named a real host — a hostile request
  cannot self-declare its way into it. `https` on a loopback host is not `http`, so it
  gets nothing either.
- The docstring is restated to carry the rule and its boundary, and to say plainly that
  the exception is a carve-out the base specification does not have rather than a
  normalization — the case/trailing-slash/query foldings the docstring rejects remain
  rejected.

### The test split

`tests/test_cimd.py` — `test_redirect_uri_matching_is_exact` is replaced by seven tests,
with a small `client_with(*redirect_uris)` helper:

| Test | What it pins |
|---|---|
| `test_a_loopback_entry_ignores_only_the_port` | The split's loopback half: the registered `:8766` loopback entry accepts the `:8767` port-only difference (the **inverted** assert), and still rejects path/case/trailing-slash/scheme/host/query/fragment differences |
| `test_a_port_less_loopback_entry_matches_an_ephemeral_port` | The live document's shape: `http://localhost/callback` accepts `:45002` and `:80`; host is not aliased to `127.0.0.1`; `https` earns nothing; scheme/host case is insensitive per RFC 3986 §3.1/§3.2.2 while a case-folded **path** is not |
| `test_an_explicit_port_loopback_entry_matches_a_port_less_request` | The port is ignored on both sides (`:80` entry vs a bare request) |
| `test_a_loopback_entry_covers_the_ipv6_loopback_literal` | `[::1]` is the third loopback host |
| `test_non_loopback_redirect_uri_matching_is_exact` | The new non-loopback half: exact equality accepted, any port difference (incl. the `:443` default) rejected, foreign host rejected, scheme/case/trailing-slash rejected |
| `test_a_loopback_request_earns_no_exception_against_a_non_loopback_registration` | The keying bound: a request-shaped loopback URI matches nothing against a non-loopback registration |
| `test_the_loopback_exception_applies_to_the_entry_that_matches` | A mixed registration is matched entry by entry |
| `test_a_uri_that_cannot_be_parsed_is_not_a_loopback_target` | A malformed URI falls through to exact equality, which it fails |

`tests/test_cimd.py`: 48 passed. Whole suite: 328 passed, 1 skipped.

### The live re-test, against the composed stack

`mcp-signin-gateway` and `mcp-signin-router` up and healthy, the router on `:8090`. The
battery ran 18 cases, **negative control first**, and every case matched its expectation.
The two clients it drives: the CIMD document `https://claude.ai/oauth/claude-code-client-metadata`
(the field failure's own client), the pre-registered `group6-smoke` (`http://127.0.0.1:8767/callback`,
the live fixture shape), and a temporarily added non-loopback pre-registered client
(`https://app.example/callback`) so the non-loopback branch is measured live rather than
only in unit tests. The gateway was recreated with the temporary entry and recreated again
with the committed `.env` afterwards.

| # | `client_id` | `redirect_uri` sent | status | verdict |
|---|---|---|---|---|
| **N** | CIMD | `http://127.0.0.1:9999/not-registered-anywhere` | **400** | **REJECTED — the negative control; the probe can fail** |
| C1 | CIMD | `http://localhost/callback` (document entry, verbatim) | **302** | ACCEPTED |
| **C3** | CIMD | **`http://localhost:45002/callback` (the field value)** | **302** | **ACCEPTED — the reported failure is fixed** |
| C2 | CIMD | `http://localhost:80/callback` (explicit default port) | **302** | ACCEPTED |
| C7 | CIMD | `http://127.0.0.1/callback` (second entry, verbatim) | **302** | ACCEPTED |
| C6 | CIMD | `http://127.0.0.1:45002/callback` (second entry + dynamic port) | **302** | ACCEPTED |
| C5 | CIMD | `https://localhost/callback` (scheme differs) | 400 | REJECTED (unchanged) |
| C4 | CIMD | `http://localhost:45002/notcallback` (path differs too) | 400 | REJECTED (unchanged) |
| C10 | CIMD | `http://localhost/callback/` (trailing slash) | 400 | REJECTED (unchanged) |
| C8 | CIMD | `http://0.0.0.0/callback` | 400 | REJECTED (unchanged) |
| C9 | CIMD | `http://[::1]:45002/callback` (no such registered entry) | 400 | REJECTED (unchanged) |
| P1 | pre-registered | `http://127.0.0.1:8768/callback` (port varied) | **302** | ACCEPTED — the explicit-port loopback entry |
| P2 | pre-registered | `http://127.0.0.1:8767/callback` (verbatim) | 302 | ACCEPTED |
| P3 | pre-registered | `http://localhost:8768/callback` (host differs) | 400 | REJECTED |
| P4 | pre-registered | `http://127.0.0.1:8768/other` (path differs) | 400 | REJECTED |
| L1 | non-loopback | `https://app.example/callback` (verbatim) | 302 | ACCEPTED |
| **L2** | non-loopback | **`https://app.example:8443/callback` (varied port)** | **400** | **REJECTED — exact equality still governs** |
| L3 | non-loopback | `http://localhost:45002/callback` (request self-declares loopback) | 400 | REJECTED — no exception earned |

Every accepted 302 answered `Location: https://keycloak:8443/realms/dial/protocol/openid-connect/auth`,
the identity-provider leg beginning: the request was accepted, not merely tolerated. Every
rejection is `400 invalid_request` with the same body as the field capture. The rows that
change against the finding's §2 table are exactly the port-only ones (C2, C3, C6, P1);
every other row's status is unchanged, which is the property the fix had to preserve.

The pre-existing routing battery (`scripts/probe_routing.py`) was re-run against the same
composed stack afterwards: **all 6 probes passed**, so the matcher change regressed
nothing on the routing surface.

The probe script was written to a temp directory outside the repo and is not committed,
as the finding's §1 did. `git status --short` shows only the four files this task changes.
No gateway state was left behind: CIMD cache entries and short-TTL flow records expire on
their own, and the temporary pre-registered client was removed from `.env` and the
gateway recreated from the committed configuration.

### The stale criterion corrected

`evidence/group-3.md`'s test-summary table, the `tests/test_cimd.py` row: "exact
`redirect_uri` matching" is replaced by "`redirect_uri` matching — exact, with the
loopback-port exception", with the test count updated (41 → 48) and the coverage text
naming the rule. The `test_redirect_uri_matching_is_exact` name was replaced by the seven
tests above, so the row's wording was stale twice over.
