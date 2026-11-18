# The security review gate — `generalized-idp-federation` (C2)

The independent security review of the change's full diff (`8c6dbe5^..HEAD`, 33 files),
run at the depth the change's SIA sets (**High** — full depth, every changed file against
the SIA, the delta spec, and `docs/threat-model.md` as this change updates it). The
reviewer is independent of the authoring and implementation passes; the method is
falsification — every mitigation claim was attacked, not confirmed, and the findings
below are the claims that broke plus the defects found while trying.

**Verdict: pass-with-findings.** No fail-open defect was found on any leg. One
mitigation claim is falsified by the implementation (SRG-1) and must be resolved before
push — the repo's own rule that a mitigation which exists only in prose is not landed
cuts both ways: prose that claims more than the code does is equally unlanded. One
fail-closed correctness defect (SRG-2) breaks the change's own tested-case issuer class
and must be fixed before the live run. The rest are triaged.

Re-verification run during the review: `tests/test_idp.py` + `tests/test_settings.py`
against this worktree — **122 passed**; the D14 machine sweep (the tested family's
names over the Class A implementation surfaces) — **clean**; `grep -i keycloak
gateway/` — **clean**; `grep KEYCLOAK docker-compose.yml` — **0 hits** (the gateway
container receives no helper-scoped setting).

## Findings

### SRG-1 — The discovery size cap is checked after the whole body is buffered; the SIA's Anti-DoS claim ("bounds what a hostile document server can make the gateway buffer") is false as implemented

- **Severity:** medium — a mitigation claim the diff must satisfy, falsified; required
  before push (minimum: the SIA/spec wording states the true bound; preferred: the
  streaming cap, below).
- **Where:** `gateway/idp.py:697-719` (`_fetch_discovery_document`: `httpx.get(...)` —
  non-streaming — then `len(response.content) > _DISCOVERY_MAX_BYTES`); the same shape
  at `gateway/idp.py:533` (`_post_refresh`).
- **Evidence:** `httpx.get` with default `stream=False` reads the entire response body
  into memory before the cap is applied, so the cap bounds what the gateway *parses*,
  not what it *buffers* — a hostile or misbehaving answer can grow the buffer without
  bound inside the outbound timeout window. The SIA's DT-EP5-1 mitigation 7 states
  "the response cap bounds what a hostile document server can make the gateway buffer
  (spec)"; mitigation 5 cites "the existing bounded-parsing discipline". That existing
  discipline is not this shape: the CIMD leg (`gateway/cimd.py:215,274-286`) reads its
  document under `client.stream(...)` with `_read_capped` refusing the moment the limit
  is crossed — a read-time cap. The discovery fetch deviates from the very precedent
  its mitigation cites, and the implementation's own honesty about it exists only in
  `_post_refresh`'s docstring (`gateway/idp.py:497-503`: "bounds what the gateway
  *parses*, not what it holds") — the discovery fetch carries no such caveat and the
  SIA carries the stronger, false claim. M26 and the delta spec's "the response size
  capped" are worded loosely enough to survive either behavior, which is itself the
  problem: the spec's placed claim does not distinguish buffered-then-capped from
  capped-while-read.
- **Bounding facts, stated so the severity is honest:** the attacker must control the
  provider's own origin (the trust anchor — a compromised provider) or hold an on-path
  position on an operator-owned plain-http override leg (the RES-19 class, where the
  same attacker can already serve the exchange an uncapped hostile answer —
  `_post_token` carries no cap at all); the cache lock serializes fetches to one at a
  time per process; the TTL bounds the rate to one fetch per window; the outbound
  timeout (30 s default) bounds each fetch's duration. The practical gain is a
  transient memory spike, once per TTL, from a position that already holds stronger
  attacks. The finding is the claim/code mismatch, not a new attack class.
- **Required disposition:** before push — either land the read-time cap (stream the
  discovery fetch and refuse past `_DISCOVERY_MAX_BYTES` while reading, the
  `gateway/cimd.py` `_read_capped` shape), or amend the SIA's DT-EP5-1 mitigations 5
  and 7 and the delta spec's cap wording to state the true bound (the cap bounds
  parsing; buffering is bounded by the outbound timeout and the one-fetch-at-a-time
  serialization, not by the cap). The streaming cap is preferred: it is the change's
  own cited precedent, and it is small.

### SRG-2 — One-sided trailing-slash normalization breaks the exact issuer pin for issuers whose canonical form ends with `/` — the tested family's per-journey issuer class included

- **Severity:** medium — fail-closed (no bypass, no leak), but it makes D3's
  issuer-equality mitigation unusable for the exact provider class the change targets,
  and it converts OQ-A's second live-run fact into an uninterpretable result. Must be
  fixed before the live run; recommended before push.
- **Where:** `gateway/settings.py:1046-1071` (`_require_scheme` ends with
  `value.rstrip("/")` and applies to `idp_issuer`); `gateway/idp.py:749`
  (`document.get("issuer") != settings.idp_issuer` — compared against the stripped
  value); `gateway/idp.py:601-612` (`jwt.decode(..., issuer=self.issuer)` — the same
  stripped value).
- **Evidence:** the operator's configured issuer is silently stripped of every trailing
  slash before the model sees it, while the two comparisons that pin the trust anchor
  run against the provider's *unnormalized* strings — the discovery document's `issuer`
  member and the token's `iss` claim. A provider whose canonical issuer ends with `/`
  can therefore never be federated: the document is refused whole at issuer equality
  and, in direct mode (no document), every token fails verification. The change's own
  tested-case record spells that issuer with the trailing slash —
  `https://<domain>/tfp/{tenant GUID}/{Policy ID}/v2.0/` (the classic-flavor
  per-journey form the design's Context and D9 carry as the configured literal) — so
  the tested deployment as designed would fail every sign-in at discovery validation,
  and OQ-A's live-run fact (b) ("the policy's discovery document's `issuer` member
  equals the tfp issuer") can never be cleanly verified: the mismatch fires on the
  slash before the fact is tested. No test covers the case — the fixtures build both
  the document's issuer and the token's `iss` from the already-stripped
  `settings.idp_issuer` (`tests/conftest.py:114`, `tests/conftest.py:130` region), so
  the suite cannot see the asymmetry. The strip is inherited (the pre-change
  `keycloak_issuer` had it, for path-joining), but the equality checks that consume the
  stripped value are new in this change, which is what makes the inherited quirk newly
  consequential.
- **Required disposition:** fix before the owner-dependent live run, and recommended
  before push since the fix is what makes the change's own acceptance run meaningful:
  either stop stripping `idp_issuer` (and join the well-known path explicitly against
  both spellings), or compare and verify against a spelling-preserving value so the
  operator's configured literal is the exact pin the spec names. Add one test with a
  trailing-slash document issuer and token `iss`.

### SRG-3 — `httpx.InvalidURL` escapes the leg's fixed-vocabulary failure path as an unhandled 500

- **Severity:** low — failure-shape and diagnosability, not exposure; triaged.
- **Where:** `gateway/idp.py:704` (`except httpx.HTTPError` — `httpx.InvalidURL` is not
  an `HTTPError`; its MRO is `(InvalidURL, Exception, BaseException, object)`,
  verified against the project venv); `gateway/settings.py:1066-1071` (the
  `_require_scheme` validator accepts any value containing `"://"`, so a malformed
  issuer or back-channel base — a space in the host, a bad port, a non-ASCII host that
  fails IDNA — passes startup); `gateway/authorize.py:176-183` (catches only
  `IdentityProviderError`).
- **Evidence:** a configured issuer that passes the `"://"` substring check but that
  httpx refuses to parse makes the first discovery fetch raise `InvalidURL`, which no
  handler translates — the browser gets a bare 500 and the operator a traceback,
  where the discovery requirement specifies "a discovery answer that cannot be
  fetched... fails the leg closed with an operator-facing error naming the provider".
  The direct endpoint trio gets a real urlsplit well-formedness check at startup
  (`gateway/settings.py:807-814`); `idp_issuer` and `idp_backchannel_base_url` — the
  two settings the whole discovery mode hangs off — get only the substring check, an
  inconsistency inside this same diff. No credential reaches any output (the exception
  text is a URL the operator configured; the traceback carries source lines, not
  locals), so this is not a leak — it is the fixed-vocabulary discipline missing one
  of its own failure shapes.
- **Required disposition:** triaged — give `idp_issuer` and
  `idp_backchannel_base_url` the same urlsplit well-formedness startup refusal the
  direct trio carries (preferred, symmetric with the trio), or catch the URL-parse
  error class in the fetch helpers and translate it into the leg's fixed vocabulary.

### SRG-4 — A mechanism-level "Keycloak" survives in the compose healthcheck comment

- **Severity:** low — vocabulary-boundary consistency; triaged, optional.
- **Where:** `docker-compose.yml:246` ("would misreport a working gateway as down if it
  depended on Core or Keycloak").
- **Evidence:** the same sentence was neutralized in `gateway/app.py` ("Core or the
  identity provider") by this change's rename sweep, and the four prose surfaces the
  design's Context enumerates (app.py, `__main__.py`, pyproject.toml, routing.md) all
  rotated — this one, the same class of mechanism statement (dependency liveness, not
  a local-deployment fact), did not. D8 arguably licenses it (in this compose file the
  IdP is the local Keycloak instance), and the D14 machine gate greps the tested
  *external* family's names, not "Keycloak", so the gate cannot catch it — which is
  exactly why it needs an explicit disposition rather than silence.
- **Required disposition:** triaged — either neutralize for consistency with the
  app.py twin, or record it as a D8-licensed local-deployment fact so the next sweep
  has a ruling to cite.

### SRG-5 — D7's migration prose overstates the old route's landing page

- **Severity:** informational — documentation accuracy; triaged.
- **Where:** the change's `design.md` D7 ("in-flight flows... land on the plain-language
  expired-flow page") versus `gateway/federation.py:62-63` (only `/dial/callback/idp`
  and `/dial/callback/upstream` are routes) and `router/nginx.conf:134` (the `callback`
  alternation still forwards the old spelling to the gateway).
- **Evidence:** an in-flight flow's provider-side redirect returns to the registered
  old route, which the router forwards and the gateway answers with its default 404 —
  not the plain-language expired-flow page. Every security property holds (no handler
  serves the old route, no flow state is touched, no credential is at stake, the
  window is flow-TTL-bounded and benign), so this is a prose inaccuracy in the
  disclosed migration cost, nothing more.
- **Required disposition:** triaged — correct the sentence (or note the 404) in the
  change's design/evidence record at archive time.

## What was attacked and held

Recorded so the disposition trail shows the falsification attempts that failed, not
only the ones that broke:

- **Discovery validation, origin binding** (`gateway/idp.py:121-124,757-799`): the
  comparison is a `(scheme, netloc)` tuple, lowercased, against the issuer's origin and
  (where set) the override's — every URL trick tried produces a *different* netloc and
  is refused: userinfo (`https://issuer@evil/`), trailing-dot hosts, IDN homoglyphs,
  any port (the port is part of the netloc, so a same-host-different-port endpoint is
  refused), subdomain suffixes (`issuer.evil.com`), backslash and whitespace forms
  (netloc mismatch or empty, both refused), and `urlsplit`'s scheme lowercasing closes
  the `HTTPS://`/`http` case games. Empty netloc and non-string members are refused;
  the issuer-equality check runs first, on raw strings, before any endpoint is read.
  Refuse-whole semantics hold: no `Endpoints` is constructed on any failure path, the
  cache is never filled from a refused document, and a failed re-fetch leaves the old
  entry unserved (the freshness check gates it).
- **Redirects and proxies:** `follow_redirects=False` and `trust_env=False` on every
  outbound call the diff touches (discovery, token, refresh, key set).
- **The back-channel swap and TLS downgrades** (`gateway/idp.py:127-139,671-683`): no
  document value can choose the scheme the swap writes — the override is an operator
  constant; the only downgrades on any path are the operator's own override (the
  disclosed RES-19 shape) and a plain-http *configured issuer*, which startup refuses
  without the override (`gateway/settings.py:826-850`). The browser-facing
  authorization endpoint is never re-addressed, on either endpoint source.
- **The direct mode** (`gateway/settings.py:756-824`, `gateway/idp.py:426-445`):
  all-or-nothing holds through the blank-is-unset validator (a blank or
  whitespace-only member reads as unset and a partial set refuses startup naming both
  sides); well-formed absolute URL and HTTPS-unless-the-override's-own-origin are
  checked at startup; the full trio skips discovery entirely (asserted at
  `call_count == 0`, `tests/test_idp.py:655-700`); the issuer pin is the same
  exact-string check in both modes.
- **The no-PKCE mode's secret** (`gateway/idp.py:473-492`): POST-body authentication,
  `SecretStr`, no `repr`; the startup refusal treats `None`, blank, and
  whitespace-only as unset (`gateway/settings.py:852-878`), and the runtime
  presentation guard re-checks the same condition so a blank delivery cannot be
  presented as a secret. The default mode's never-present claim is pinned at the byte
  level — `tests/test_idp.py:927-1014` asserts each request's raw body equals an
  expected body, covering the exchange *and* the refresh grant, with the secret's
  bytes asserted absent from the bodies and the redirect; `tests/test_idp.py:1046-1125`
  sweeps logs (chained-exception text included), audit records, error pages, and
  response headers for the secret's bytes with the secret planted and provably on the
  wire. No new error text interpolates document or token values — the interpolations
  are status codes, exception *type* names, and fixed member-name constants.
- **The rename and the route rotation:** `gateway/` carries no Keycloak vocabulary; the
  gateway container's compose environment carries zero `KEYCLOAK_*` entries (the
  realm-admin credential never enters the container); the settings↔`.env.example`
  completeness is machine-checked both directions and passing; no handler serves the
  old callback route; the router alternation matches the new spelling; the audit leg
  name rotated with the route (`leg="idp"`, `gateway/federation.py:159`).
- **The never-cut invariants:** the upstream verifier is Core's and untouched on every
  path (the verifier the no-PKCE mode drops is the gateway's own, on the IdP leg only,
  and the client-facing surface still refuses a harness request without a challenge —
  tested at `tests/test_idp.py:1017-1043`); the per-user settings read still gates
  every mint, and the discovery/direct legs sit before it without touching it; no
  credential reaches any log, argv, or error the diff adds; the committed secret
  placeholders are empty and the compose defaults are empty strings; the signing and
  custody key handling is untouched.
- **New failure shapes:** `begin_identity_leg`'s async conversion catches
  `IdentityProviderError` at `/dial/authorize` and renders the leg's own page
  (`gateway/authorize.py:176-183`); a failed first leg leaves the flow record to its
  TTL holding only the verifier (no credential yet), and the discovery-failure
  amplification is bounded by the cache (one fetch per TTL per process) and the
  authorize surface's limiter, as DT-EP5-2 states — the thread-occupancy shape at a
  cold start (waiting worker threads serialized on the cache lock for the duration of
  one fetch) is the same class every slow outbound leg already carries.
- **The threat-model deltas:** T5-9..T5-14 exist with dispositions that match the
  built behavior; M26-M30 point at the delta spec's real requirements (discovery
  validation, discovery/cache, confidential-client, issuer pinning,
  direct-configuration — all present in `specs/mcp-signin/spec.md`); RES-24 is added
  with the re-open trigger; RES-19 is re-priced with the no-PKCE secret named; A18 is
  in the asset table; the §10 external-IdP row is added with its stated acceptance;
  EP5's title and TB3/TB7 are reworded to the two-shape boundary.
- **D14's vocabulary boundary:** the machine sweep over the Class A implementation
  surfaces (`gateway/`, tests, pyproject.toml, `.env.example`, docker-compose.yml,
  README, both operator docs, routing.md) for the tested family's names, flavors, URL
  segments, and product concepts returns nothing; the remaining Keycloak spellings on
  those surfaces are the D8-licensed helper-scoped settings and local-deployment facts
  (save SRG-4's one sentence).

## Disposition summary

| id | severity | must fix before push? | must fix before live run? |
|---|---|---|---|
| SRG-1 | medium | yes — wording minimum, streaming cap preferred | wording suffices if not fixed as code |
| SRG-2 | medium | recommended | yes |
| SRG-3 | low | no (triaged) | recommended |
| SRG-4 | low | no (triaged) | no |
| SRG-5 | informational | no (triaged) | no |

## Security-gate dispositions (the fix round)

All five findings dispositioned; the three code findings landed as code (SRG-1 as the
preferred streaming-cap disposition, not the wording minimum). The fix round is
uncommitted, on the same worktree the review ran against.

### SRG-1 — resolved: the streaming cap landed (the preferred disposition)

The discovery fetch (`gateway/idp.py`, `_fetch_discovery_document`) now streams the
response and enforces `_DISCOVERY_MAX_BYTES` **while reading**, in the shape of
`gateway/cimd.py`'s `_read_capped` — the repo's own cited precedent. A shared
`_read_capped(response, limit)` helper reads the body chunk by chunk and refuses the
moment the running total crosses the limit (`_OversizeError`, translated at the call
site into the leg's fixed-vocabulary refusal), so a document whose body exceeds the cap
is refused whole and the connection is abandoned past the cap: the cap now bounds what a
hostile document server can make the gateway **buffer**, not merely what it parses, and
the SIA's DT-EP5-1 mitigation 7 claim is true as implemented. The delta spec's and D3's
"response size capped" wording needed no amendment — the code landed the stronger
reading.

The refresh grant (`_post_refresh`) — the finding's second site of the same shape — was
streamed under the same read-time cap (`_RESPONSE_MAX_BYTES`) and returns the capped
buffer in the response shape its shared document readers take. Its docstring's
parse-bound caveat ("bounds what the gateway *parses*, not what it holds") was removed:
it described the old shape and is no longer true. `_post_token` remains uncapped — the
finding's stated bounding fact about the trusted internal leg, unchanged by this round.

New test: `test_an_oversized_discovery_document_is_refused_while_being_read`
(`tests/test_idp.py`) — the provider answers a ~4 MB body in 4 KiB chunks; the test
counts the chunks the gateway actually pulled and asserts the refusal came within one
chunk of the 64 KiB cap and that the answer's tail was never read. A buffered-then-capped
fetch fails this test on the counter: it would have drained the whole answer before
checking. (A bounded answer is used rather than an endless one so the old shape fails
instead of hanging.)

### SRG-2 — resolved: the issuer is pinned at its configured spelling, verbatim

`gateway/settings.py` no longer strips trailing slashes from `idp_issuer`: the issuer
left the shared `_require_scheme` validator and carries its own
(`_require_scheme_on_the_issuer`), which checks the scheme and returns the value
unchanged — the configured spelling **is** the pin, and both comparisons that consume it
(the discovery document's `issuer` equality check at `gateway/idp.py`, and
`jwt.decode(issuer=...)` at verification) run against it verbatim. The one place the
issuer is used as an address — the well-known join at the fetch — adds the separator
explicitly (`issuer.rstrip('/') + '/.well-known/openid-configuration'`) and rewrites
nothing: a canonical issuer ending in `/` (the classic-flavor per-journey tfp form the
change targets) now federates. The back-channel origin derivation is unaffected by a
trailing slash in the issuer's path (it reads the netloc only), and the allowed-origins
set for document validation is built from the same verbatim value.

The exact-string property is pinned cuttings both ways:

- `test_a_trailing_slash_issuer_is_federated_at_its_exact_spelling`
  (`tests/test_idp.py`) — a configured issuer ending in `/`, a document carrying the
  same exact spelling, and a token whose `iss` carries it: discovery validates, the
  exchange verifies, and the flow completes (the fetch went to the single-separator
  joined URL, one fetch, cached).
- `test_a_discovery_document_issuer_missing_only_the_slash_is_refused` — a document
  differing from the configured value only by the trailing slash is refused whole
  ("names another issuer").
- `test_a_token_issuer_missing_only_the_slash_is_refused` — a token whose `iss`
  differs only by the trailing slash fails verification; the sign-in fails closed.
- `test_the_issuer_is_pinned_at_its_configured_spelling` (`tests/test_settings.py`) —
  the model keeps the configured spelling verbatim.
- `test_the_federation_defaults_name_no_provider` updated: the shipped default
  (`https://idp.example.com/`) is likewise kept verbatim — the pin rule, not a new
  default.

`tests/conftest.py`'s two fixture builders (`discovery_url_of`,
`discovery_document_of`) now join the issuer's path with exactly one separator, the same
construction the client performs, so the fixtures match the fetch for trailing-slash
issuers and are byte-identical to before for every issuer without one. The task-2 and
task-3 implementation records' "trailing slash stripped" wording describes the pre-fix
behavior and is superseded by this disposition (they are round records, left as
written).

### SRG-3 — resolved: the two settings got the trio's well-formedness check, and the parse-error class is caught at the fetch

`gateway/settings.py` gained `_require_wellformed_issuer_and_backchannel_base` (model
validator, before the plain-http-issuer check): `idp_issuer` and
`idp_backchannel_base_url` must parse as absolute http(s) URLs with a host — the direct
endpoint trio's own check, at `urlsplit`'s shape — or startup refuses naming the
setting. A value that passes it and that the HTTP client itself still cannot address (a
malformed port) is caught at the fetches: every outbound call site on the leg
(`_fetch_discovery_document`, `_post_token`, `_post_refresh`, `_fetch_key_set`) catches
`httpx.InvalidURL` beside `httpx.HTTPError` — it is not an `HTTPError` subclass, which
is how it escaped as a 500 — and translates it into the leg's fixed-vocabulary failure
with the exception *type* name, like every other transport refusal.

New tests: `test_a_malformed_issuer_or_backchannel_base_refuses_startup_naming_the_member`
(`tests/test_settings.py`, three parametrized cases — an empty host on either setting,
and a scheme no HTTP client speaks on the issuer) and
`test_an_unaddressable_issuer_fails_the_leg_with_the_fixed_vocabulary`
(`tests/test_idp.py` — the unparseable-URL class raised at the fetch is answered with
the leg's 502 error page naming the cause, not a 500).

### SRG-4 — resolved by neutralizing (dispositioned, my call recorded)

The compose healthcheck comment's "Core or Keycloak" is now "Core or the identity
provider" (`docker-compose.yml`, one line) — the same sentence shape the rename sweep
already neutralized in its `gateway/app.py` twin. D8 would arguably have licensed the
original (in this compose file the IdP is the local instance), but the sentence is a
mechanism statement about what the probe does not depend on, not a local-instance fact,
and consistency with the twin is cheaper than carrying a D8 ruling for one sentence. The
neutralized spelling is the disposition of record for the next sweep.

### SRG-5 — resolved: D7's migration prose corrected to the mechanism

The change's `design.md` D7 now states what actually happens: an in-flight flow's
provider-side return to the old route is forwarded by the router's alternation and
answered with the gateway's plain 404 — no handler resolves the old route, no flow state
is touched, and no credential is at stake; the cost stays bounded by the flow TTL and
benign. The flow-state property the disclosure needs (nothing serves the old route)
holds and is now stated as what holds, replacing the inaccurate "expired-flow page"
claim.

### Gate outputs (the fix round)

- `ruff check .` — all checks passed.
- `ruff format --check` on the five touched Python files — formatted (no changes).
- `pytest -q` (full suite) — **610 passed, 1 skipped**; `tests/test_idp.py` +
  `tests/test_settings.py` — **131 passed** (the review's re-verification baseline was
  122; +9 new tests, listed above).
- Leak check (`scripts/check_publication_leaks.py`) — **PASS** (213 files scanned; 3
  waived findings, all pre-existing waivers; 0 unwaived).
- `bandit -r gateway/` — **no issues identified** (nothing new to triage; the 9
  nosec-disabled findings are the pre-existing pinned ones).
- `grep -i keycloak gateway/` — clean (the D14 sweep's property, re-checked after the
  fix round).

Touched: `gateway/idp.py`, `gateway/settings.py`, `docker-compose.yml` (SRG-4 line),
`tests/test_idp.py`, `tests/test_settings.py`, `tests/conftest.py`,
`openspec/changes/generalized-idp-federation/design.md` (SRG-5 wording), and this
evidence file. Not committed — the change's gates re-run before push.
