# The consolidated fix pass — security round 2 (S1–S4) and general review round 1 (F-1…F-5)

The eight findings of `security-review-round-2.md` and `general-review-round-1.md`, one
pass. Their spec/design clauses landed first (`d6231f4`); this records the implementation,
the tests, the live proofs, and the gate tier. Every capture is redacted at capture time:
no token, code, key, password, or client secret appears in this file.

## Verdict

**All eight findings are fixed and verified.** One is fixed by falsifying its premise
instead (the "dead" `# nosec`), and one produced a defect the finding did not name (the
audit bound applied to every string would have truncated the fixed vocabulary — caught by
the test that made the cap small enough to see it). Gates: green, with the full suite at
**376 passing** (363 at the start of this pass), the composed stack rebuilt and healthy,
and all four probe batteries green on the rebuilt stack.

## S1 (MAJOR) — every caller-supplied fact is length-bounded at the emit

`gateway/audit.py`:

- `AuditTrail` takes a `fact_max_length`, fed from the new `AUDIT_FACT_MAX_LENGTH` setting
  (default 256). `Runtime.build` passes it, so the bound is configuration.
- `_emit` walks the record through `_bounded(key, value, limit)`.
- `_bounded` is scoped to `_CALLER_FACT_FIELDS` — `client_id`, `redirect_uri`, `resource`,
  `toolset` — rather than to every string.
- The `rate_limited` branch of `/dial/authorize` and `/dial/{name}/status` now records the
  reason only: no caller facts.

**The scoping is the defect the test found.** Bounding every string is the obvious reading
of "length-bound every caller-supplied fact", and it destroys the record's meaning at a
small cap: `reason` and `event` are this gateway's own fixed vocabulary, and truncating
them turns `unknown_client` into `unknown_`. That surfaces as a log an operator cannot group
or alert on — and it is invisible at the default cap, because the vocabulary is shorter than
256 characters. `tests/test_audit.py::test_the_bound_is_the_configured_cap_not_a_fixed_length`
is the instrument: it sets the cap to 8, so a fact truncates while `reason` and `event` are
asserted whole. **A bound applied to every string fails that test**, which is the
falsification.

Tests (`tests/test_audit.py`):

| Test | What it pins |
|---|---|
| `test_an_over_long_fact_lands_truncated` | a 40×-cap client id lands at exactly the cap, and the full value appears nowhere in the log |
| `test_the_bound_is_the_configured_cap_not_a_fixed_length` | the cap is the setting's value, and the vocabulary survives it |
| `test_a_trail_built_without_settings_is_bounded_too` | a bare `AuditTrail()` is bounded by the default, so the one construction path that reads no settings omits no bound |
| `test_a_limiter_refusal_on_authorize_is_recorded` | rewritten: the 429 record carries the reason and every caller fact is `None`, while the request carried all four |

## S2 (MAJOR) — the form endpoints' byte cap, the router's stated cap, and the DCR maxima

- `gateway/requests.py` (new): `capped_body`, the chunked read that returns on the first
  byte past the limit. `routes.py`'s private `_capped_body` is gone; all three body-bearing
  endpoints share this one.
- `gateway/token.py`: `_form_parameters` takes the settings and reads through `capped_body`
  under the new `GATEWAY_FORM_MAX_BODY_BYTES` (default 8192). Both `/dial/token` and
  `/dial/revoke` go through it, and an over-cap body is refused whole rather than parsed in
  part — a form whose meaning depends on which parameters survived truncation has none.
- `gateway/routes.py`: the module docstring's "the one unauthenticated endpoint that
  accepts a body" is corrected — three endpoints take a body, and each caps it.
- `router/nginx.conf`: `client_max_body_size 16384;` stated in the server block, above the
  gateway's per-endpoint caps and below nginx's implicit 1 MB default.
- The DCR per-record maxima are **reconciled with the body cap and enforced at startup**:
  `Settings._require_registration_bounds_to_fit_the_body_cap` refuses a configuration whose
  maxima could not fit inside `DCR_MAX_BODY_BYTES`, naming both settings. The defaults moved
  to `8` redirect URIs and `512` characters so the relationship holds out of the box
  (4352 value bytes + 512 scaffolding inside an 8192 cap).

The reconciliation is a startup refusal rather than a note because the failure is silent:
the endpoint would refuse as oversized exactly the registrations its own configuration
advertises, and an operator raising a per-record maximum would see no error and no effect.
Fixing it by sizing the defaults alone would leave the next operator to rediscover it.

Tests: `tests/test_limits.py` — an over-cap body on each form endpoint (400,
`invalid_request`, "larger than"), and a body at the cap still processed (the negative
control: without it the refusals would pass on an endpoint that refused everything).
`tests/test_store.py` — a contradictory configuration refused naming both settings, and the
defaults asserted jointly reachable (the control: a guard that refused everything would pass
the first test and break every deployment).

## S3 (MINOR) — the CIMD fetch's share of the shared worker pool

`gateway/cimd.py`: `ClientMetadataCache` owns an `anyio.CapacityLimiter` sized by the new
`GATEWAY_CIMD_MAX_CONCURRENT_FETCHES` (default 8), and `resolve_async` runs the offloaded
fetch inside it. A `max_concurrent_fetches` property exposes the configured size.

Tests (`tests/test_concurrency.py`): `test_concurrent_metadata_fetches_are_bounded_by_the_capacity_limiter`
drives three distinct client ids at three slow origins at once and observes the peak number
inside the outbound call under a lock; it must never exceed one.
`test_the_overlap_instrument_detects_an_unbounded_burst` is its control — the same
instrument with the limiter widened must observe the overlap, so the ceiling means
something. `test_the_fetch_limiter_is_sized_by_its_setting` pins the setting. Distinct
client ids matter (one id would measure the cache instead of the limiter), which is what the
first attempt got wrong.

## S4 (MINOR) — the 8091-never-published dependency, stated at both halves

- `docker-compose.yml`, at the gateway service: the port is container-internal and carries
  no `ports:` mapping, ever — with the reason (a host-published 8091 would admit requests
  the router never touched, carrying a caller-chosen `X-Real-IP`, making the per-source
  limit a bound the caller sets).
- `router/nginx.conf`, at the shared proxy settings: the same invariant from the other side,
  where the header's trust is established.
- `docs/routing.md` gains both sections (the byte cap and the peer identity).

Live proof: `docker compose config --format json` shows **no `ports` key on the gateway
service**, and `docker compose ps` reports the gateway as `8091/tcp` with no host binding
while the router is `0.0.0.0:8090->8090/tcp`. Both containers healthy.

## F-1 (MAJOR) — the group-4 checklist

Tasks 4.1–4.7 and 4.10 are ticked. Their evidence trails are `evidence/group-4.md` (4.1–4.7)
and `evidence/security-review-fixes.md` (4.10, "Task 4.10 — pre-allocation refusals are
audited"), both already in the change folder.

## F-3 (MINOR) — `/dial/revoke` answers an empty 200

`gateway/token.py`: the route returns `Response(status_code=200, headers=_NO_STORE)` —
no body at all, per RFC 7009 §2.2. The docstring, `docs/gateway-configuration.md`'s
revocation section, and the tests were updated to the actual shape.

Tests (`tests/test_tokens.py`): `test_revoking_an_unknown_token_answers_the_same_way` now
asserts on the **bytes** rather than on JSON equality — a body of any shape is a place a
difference could be reported, and a body that happened to match today could stop matching
without the status changing. `test_a_revoked_refresh_token_is_refused` and
`test_an_access_token_cannot_be_revoked` assert the empty body on the success and
not-revocable paths too, so the uniform shape is pinned in all three cases.

## F-4 (MINOR) — the required `token` parameter, and the refresh's `client_id`

**(a) Implemented.** `/dial/revoke` with no `token` is now `invalid_request` with an audit
record under the new fixed reason `missing_revocation_token`. The distinction from the
uniform 200 is the point: it reports the shape of the request, not the state of any token,
so it is not the oracle F-3 closed.

**(b) Implemented, not deviated.** `_refresh_grant` verifies a presented `client_id`
against the token's own and refuses a mismatch as `invalid_grant` (RFC 6749 §6). The
parameter stays optional — a client that sends none is served, and the fresh tokens carry
the token's own `client_id` — because nothing else at this grant binds the request to that
client, which is exactly why the check is real when the parameter is sent.

Tests (`tests/test_tokens.py`): `test_revoking_nothing_at_all_is_a_malformed_request`
asserts the error document *and* the audit record's reason, with a well-formed form carrying
another parameter so the refusal under test is the missing `token` and not the request's
shape. `test_a_refresh_naming_another_client_is_refused` and
`test_a_refresh_naming_its_own_client_is_served` are the pair — the second is the control,
since the first could otherwise pass on a grant that refused every `client_id`.

## F-5 (MINOR) — the status prose

`README.md`'s Status paragraph and `docs/HANDOFF.md`'s status section both state the actual
state: every implementation group landed with its gates green, and the five acceptance
criteria waiting on the owner's run against a real harness. HANDOFF's "Where to start"
section was rewritten too — it still told a fresh reader to write the Stage 0 change and
implement the spike, which is two completed stages behind where the repository is. Behavior
and reason only, no provenance.

## F-2's remaining note — falsified, not fixed

The general review called `gateway/routes.py`'s `# nosec B105` "dead". **Measured: it is
load-bearing.** Removing it makes bandit report `B105 hardcoded_password_string` on
`"token_endpoint_auth_method": "none"` and the bandit gate exits non-zero. The suppression
is restored, and the triage comment above it still states why the value is not a credential
(the RFC 7591 method name).

## Gates

| Gate | Command | Result |
|---|---|---|
| Lint | `python -m ruff check .` | All checks passed |
| Format | `python -m ruff format --check .` | 108 files already formatted |
| Types | `python -m mypy` (strict) | Success: no issues found in 38 source files |
| Tests | `python -m pytest -q` | **376 passed, 1 skipped**, 1 warning (was 363) |
| Bandit | `python -m bandit -c pyproject.toml -r gateway` | No issues identified |
| pip-audit (**BLOCKING**) | `python -m pip_audit` | No known vulnerabilities found |
| Trivy | `trivy image --skip-db-update dial-mcp-gateway:local` | `Total: 156 (UNKNOWN: 2, LOW: 57, MEDIUM: 53, HIGH: 44, CRITICAL: 0)` — **identical to the baseline triaged in `gates.md`**, all in the Debian 13.7 base image, none in the Python layer; this diff adds none. The DB-refresh caveat recorded there still stands. |
| Compose build | `docker compose build` | `mcp-signin-gateway Built` (run **before** recreate — the group-3 lesson) |
| Compose boot | `docker compose up -d --force-recreate` | gateway and router both `(healthy)` |
| Liveness | `probe_liveness.py --slow-client-id https://httpbin.org/delay/5` | PASS — control worst 0.0940 s, `/healthz` **200 in 0.0310 s** during a 7.59 s held-open fetch. Run against a temporary compose override pointing the allowlist at the slow origin; the override was removed and the stack recreated from the committed configuration (allowlist verified back at `https://claude.ai`). |
| Routing | `probe_routing.py` | all 6 probes passed |
| Trust | `probe_gateway_trust.py` | green — JWKS `kid` matches, unpublished signer refused, gateway-signed token resolves a real identity |
| End to end | `probe_end_to_end.py` | green — full chain, 65 tools via `/dial/notion/mcp` |

### Live proofs of the new behavior

Against the composed stack through the front door (`http://localhost:8090`):

```
S2  POST /dial/token  with a 10 KB form body
    400  {"error":"invalid_request","error_description":"the request body is larger
          than the 8192 bytes this gateway accepts"}
S2  POST /dial/token  with a 20 KB form body
    413  413 Request Entity Too Large   (refused by the router before the gateway)
F-3 POST /dial/revoke with an unissued token
    200  len(body)=0  body=b''
F-4 POST /dial/revoke with no token
    400  {"error":"invalid_request","error_description":"the `token` parameter is
          required: it names the refresh token to revoke"}
S4  docker compose config --format json
    services.mcp-signin-gateway -> 'ports' key absent
S2  the DCR joint-reachability guard, in the image's own settings model
    REFUSED: the registration bounds are jointly unreachable within
    dcr_max_body_bytes (4096): dcr_max_redirect_uris (64) ...
```

## Open items carried forward

- **Trivy's vulnerability database is stale** (cached DB `UpdatedAt 2026-09-27`, 22 days old;
  the download fails from both mirrors). Unchanged by this pass, already recorded in
  `gates.md`; the remedy is a network condition or a newer base image, not a code change.
- **`probe_liveness.py` needs a slow allowlisted origin** and takes it as an argument, so it
  is not part of the default battery and its run needs a configuration override that must be
  removed afterwards. Recorded here so the next reader does not mistake the missing run for
  a gap.
- **The five acceptance criteria remain the owner's run.** Nothing in this pass could
  substitute for them: they need a provisioned instance and a real harness.

## Deliberate limits of this pass

- **The audit bound is applied at the emit, not at each call site.** A call site that had to
  remember to bound its own values would eventually not, and these surfaces are
  unauthenticated. The cost is that every record passes through the same small function,
  which is what the truncation tests measure.
- **The capacity limiter bounds a caller's share, not the pool.** Queue waiting behind
  attacker-shaped slow requests within the rate limits remains, and is disclosed in the
  design's residual record; a limiter cannot remove it without refusing legitimate traffic.
- **`GATEWAY_CIMD_MAX_CONCURRENT_FETCHES` is a judgement, not a measurement.** Eight of a
  default forty-worker pool leaves the flow's own legs ample capacity while still allowing
  ordinary concurrent resolution; it is a setting precisely because the right number depends
  on the deployment's traffic.
