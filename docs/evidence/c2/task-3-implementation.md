# Task group 3 — the discovery client, the endpoint sources, and the pinning tests (tasks 3.1–3.4)

Change: `generalized-idp-federation` (C2). Scope of this record: the discovery document
client, the deletion of the realm arithmetic, the refresh grant and key-set legs
re-pointed at the resolved endpoints, the varying-issuer pinning tests, and the direct
endpoint-configuration mode. No commit made.

## The endpoint-resolution layer's shape

Both modes meet at one source: `IdentityProviderClient._resolved_endpoints()`
(`gateway/idp.py`), which returns the leg's three endpoints as a frozen `Endpoints`
record (`authorization_endpoint`, `token_endpoint`, `jwks_uri`) from exactly one of two
configurations, never a mix:

* **Direct mode** — `_configured_endpoints()` returns the operator's trio when it is set.
  All-or-nothing is enforced at startup by the settings model, so the client's check only
  separates "no member set" (discovery mode) from the full trio; where the trio is set,
  **no discovery fetch is attempted at all** — the cache is never consulted and the fetch
  function is never called.
* **Discovery mode** — `_discovered_endpoints()` serves the cached, validated document's
  endpoints, or fetches and validates on a cold/expired cache. The cache is per client
  (the runtime builds one client per process), checked and filled under a lock so
  concurrent legs share one fetch, and fresh for `idp_discovery_cache_ttl_seconds`
  (default 300). The clock is a module-level `_monotonic_now()` so a test can move it.

After either source resolves, `_with_backchannel_applied()` applies the one mapping both
modes share: the authorization endpoint — browser-facing — is kept at its source's own
spelling, and the token endpoint and `jwks_uri` go through `backchannel_addressed()`,
the override's scheme/host swapped with the source's path (and query) kept. This
replaces group 2's lockstep helper `backchannel_base_url()` wholesale.

Async shape: `authorization_url()` is now `async` and resolves the endpoint set before
building the redirect — direct mode and a fresh cache answer without a thread hop; a
stale cache fetches on a worker thread (`anyio.to_thread.run_sync`), like every outbound
call the leg makes. The exchange and the refresh grant resolve inside their existing
worker-thread calls (`_post_token`/`_post_refresh`); the key-set leg resolves inside
`_key_set_response()`, also on the worker thread. The event loop never waits on the
provider.

## Task 3.1 — the discovery document client

Fetch at `{idp_issuer}/.well-known/openid-configuration` — the suffix-appended OIDC
spelling — through the back-channel base when configured (scheme/host swapped, path
kept). The fetch rides the outbound discipline: the configured
`gateway_outbound_timeout_seconds`, `follow_redirects=False`, `trust_env=False`, and the
body capped at 65,536 bytes (`_DISCOVERY_MAX_BYTES`), checked before parsing.

Validation (`_validated_endpoints`), per the delta spec, refusing the document **whole**
at any failure, all as 502-class `IdentityProviderError` (the provider answered unusably
— an operator fault, not a declined sign-in), fixed-vocabulary text that never echoes the
document's own values (they are a third party's strings):

- the document's `issuer` equals the configured issuer **exactly** (string equality);
- each of `authorization_endpoint`/`token_endpoint`/`jwks_uri` is present, a
  well-formed absolute URL (scheme + host), and its origin is the configured issuer's or
  the configured back-channel base's;
- each is HTTPS unless its origin is the back-channel base's own — the override is the
  operator's explicit ownership of a plain leg, and nothing else is.

Any fetch/parse/validate failure fails the leg **closed** with the operator-facing leg
error; there is no fallback endpoint construction anywhere, and no runtime failure can
switch modes. All four legs — the browser-facing authorize redirect, the exchange, the
refresh grant, the key-set fetch — consume the one resolved set.

**Deleted-arithmetic inventory** (no fallback construction survives):

- `realm_of()` — the realm-from-issuer parser, gone;
- `_AUTHORIZE_SUFFIX` (`/protocol/openid-connect/auth`), `_TOKEN_SUFFIX`
  (`/protocol/openid-connect/token`), `_CERTS_SUFFIX` (`/protocol/openid-connect/certs`)
  — the three provider-specific suffix constants, gone;
- `_token_url()` and its base+realm+suffix construction — gone; the exchange and the
  refresh grant both address `self._resolved_endpoints().token_endpoint`, the same
  resolved URL, and `_fetch_key_set(settings, jwks_url)` takes the resolved URL rather
  than building one. A grep over `gateway/`, `tests/`, and `scripts/` returns no
  remaining reference to any deleted name.

New tests: `tests/test_idp.py` (12 tests) — every row task 3.1 enumerates:

- discovered endpoints used by all four legs from one fetch, asserted on the requests
  the gateway actually made, with the negative control that no URL carries the local
  instance's provider-specific suffix (`test_the_discovered_endpoints_serve_all_four_legs_from_one_fetch`);
- issuer-mismatch document refused whole, no endpoint from it addressed
  (`test_a_discovery_document_advertising_another_issuer_is_refused_whole`);
- out-of-origin endpoint refused whole, the steered-to origin never contacted
  (`test_an_out_of_origin_discovered_endpoint_is_refused_whole`);
- plain-http issuer refused without the override — at startup, per the delta spec's
  scenario, in `tests/test_settings.py::test_a_plain_http_issuer_is_refused_without_the_override`
  (with the negative control `test_a_plain_http_issuer_is_accepted_when_the_override_owns_the_origin`);
- unreachable provider fails the leg closed, the only outbound call the attempted fetch
  (`test_an_unreachable_provider_fails_the_leg_closed_with_no_fallback`);
- cache honored within the TTL and re-fetched after it, the clock moved rather than
  waited on (`test_the_cache_is_honored_within_the_ttl_and_refetched_after`);
- the back-channel override re-addresses the fetch/exchange/refresh/key-set calls to its
  origin with the discovered paths kept while the browser redirect keeps the discovered
  authorization endpoint (`test_the_back_channel_override_readdresses_the_server_calls_only`).

The provider under test in this file is deliberately *not* local-instance-shaped — its
endpoints are spelled independently of its issuer's path — so an arithmetic construction
would produce URLs nothing serves and every test would fail loudly rather than pass on a
coincidental match.

## Task 3.2 — the refresh grant and the key set at the resolved endpoints

`refresh_identity` posts to the same `token_endpoint` the exchange uses (one resolved
set, no per-call construction), and the fresh token's verification resolves the key set
from the same set's `jwks_uri` with origin-bound validation at discovery time. No
production code beyond `gateway/idp.py` changed for this: `gateway/token.py`'s
`_fresh_claims` already routes every `IdentityProviderError` (a discovery failure at
refresh included) into the claims-read refusal class.

**The existing battery is unchanged.** `git diff` over `tests/test_tokens.py`,
`tests/test_federation.py`, `tests/test_audit.py`, and `tests/test_custody.py` is empty
— zero edits to any refresh-grant test (session-ended vs claims-read vs custody refusal
classes, the sub cross-check, latest-wins rotation, non-sliding rotation, grace-window
behavior). They pass against the discovered-endpoint fixtures exactly as they stood:
the only fixture change is `tests/conftest.py`'s new discovery mock —
`discovery_url_of(settings)`/`discovery_document_of(settings)` serve the local realm's
discovery document (its endpoints advertise the same `REALM_*` URLs the tests already
mocked) from a router inside `make_client`, tried after any router the calling test
entered (respx walks its routers in registration order, and unmatched requests fall
through), so no test file had to add a route for it. The normative expectation — no
existing test changes beyond fixture URL spellings — holds with the stronger outcome:
no existing test file's *assertions* changed at all; the only edits to an existing test
file are four one-line `mock_discovery_on(router, settings)` additions in
`tests/test_concurrency.py`, whose four tests build their app and router by hand rather
than through `make_client` and whose successful authorize now needs the discovery fetch
served. No test there asserted anything about the identity leg.

## Task 3.3 — the varying-issuer pinning tests

Three tests, all in `tests/test_idp.py`:

- a token whose `iss` names the sibling journey's issuer of the same provider (same
  host, different journey path segment) is refused at the exchange —
  `test_a_token_from_another_journeys_issuer_is_refused_at_sign_in`;
- the same token returned by the refresh grant is refused at the refresh site with
  `invalid_grant`, audited as `claims_read_failed`, not `idp_session_ended` —
  `test_a_token_from_another_journeys_issuer_is_refused_at_refresh`;
- a discovery document advertising a different issuer than configured is refused whole
  (the task 3.1 test above covers this row for the document side).

The pin itself needed no code change — `verified_claims` passes the configured issuer to
`jwt.decode`'s exact-string issuer check — which is the point: the tests pin the
behavior so a from-spec reimplementation cannot fuzzy-match.

## Task 3.4 — the directly configured endpoint mode

`gateway/settings.py`:

- the trio `idp_authorization_endpoint`/`idp_token_endpoint`/`idp_jwks_uri`
  (`str | None = None`); a blank environment value is unset (the compose pass-explicitly
  shape), and each joins the scheme validator (trailing slash stripped, schemeless
  refused);
- `_validate_direct_endpoint_set` refuses startup on: a **partial set** (naming the
  configured and the missing members, all three names always listed), a member that is
  **not a well-formed absolute URL** (no scheme or no host, naming the member), and a
  **plain-http member** that shares no configured back-channel base's origin (naming the
  member and the remedy). Deliberately absent per design D11: no origin binding to the
  issuer — the trio is operator input at the issuer setting's own trust level, and the
  split-origin provider is the shape the mode exists to absorb;
- `_require_https_issuer_without_the_override` refuses a plain-http configured issuer
  with no back-channel base — in both modes, the anchor's one rule (this is the delta
  spec's plain-http-issuer scenario, which task 3.1's test row also names; task 4.1's
  row lists the same refusal — it is landed here, and 4.1's remaining scope is the
  `IDP_PKCE_ENABLED` settings and their refusals).

`gateway/idp.py`: the full trio serves all four legs with **no fetch attempted at all**
(armed-route test: zero calls); the override's scheme/host swap applies to the token and
key-set legs with the authorization endpoint untouched (shared `_with_backchannel_applied`
mapping); issuer pinning is unchanged (the exact-string check reads the configured
issuer, whatever the endpoint source); a stale endpoint fails the leg closed with the
fixed-vocabulary error and no fallback — the armed discovery route stays at zero calls.

New tests — `tests/test_settings.py` (10): the three partial-set pairings (parametrized,
each refusal naming all three members), malformed/relative/scheme-less member values
refusing startup naming the member, plain-http member refused without the override,
plain-http member accepted on the override's own origin, plain-http issuer refused and
the owned-origin negative control, blank-trio-is-unset, and the both-modes pass case
with the shipped 300-second cache window. `tests/test_idp.py` (runtime behaviors): the
full trio skips discovery entirely and serves all four legs
(`test_the_full_trio_serves_all_four_legs_and_skips_discovery_entirely`), the override
re-addresses the configured server-to-server calls only
(`test_the_override_readdresses_the_configured_server_to_server_calls_only`), a stale
configured endpoint fails the leg closed with no fallback
(`test_a_stale_configured_endpoint_fails_the_leg_closed`), and the varying-issuer
refusal holds in direct mode
(`test_the_varying_issuer_refusal_holds_in_direct_mode`).

## Deviations from the stated file scope

Each is mechanical, forced by a task row, and minimal:

1. **`gateway/flow.py`, `gateway/authorize.py`** — the authorize redirect is one of the
   four legs task 3.1 names, so `begin_identity_leg` is now `async` (awaiting the
   endpoint resolution, whose first use fetches on a worker thread) and `authorize`
   awaits it, catching `IdentityProviderError` to serve the leg's operator-facing page.
   Without the catch, an unreachable or invalid discovery document at the first leg
   would surface as a bare 500 instead of the operator-facing error the spec requires.
   No other line of either file changed.
2. **`.env.example`** — the direct endpoint trio's entries moved from commented-out to
   active empty lines (the settings model now reads them, and the example-completeness
   test `test_every_settings_field_is_named_in_the_example` requires every field named),
   plus the new `IDP_DISCOVERY_CACHE_TTL_SECONDS=300` with the mode's-trade note. Task
   2.3 pre-staged the trio as commented-out lines exactly for this landing.

## Gates

- `ruff check .` — "All checks passed!" (whole tree).
- `ruff format --check` on all touched files — "8 files already formatted" (after a
  formatting pass normalized the working copies).
- `pytest -q` — **593 passed, 1 skipped** (baseline before this group: 571 passed,
  1 skipped — +22: 12 in `tests/test_idp.py`, 10 in `tests/test_settings.py`).
- `bandit -r -c pyproject.toml gateway` — "No issues identified." (exit 0; nothing to
  triage).
- Leak check `python scripts/check_publication_leaks.py` — **PASS** (exit 0): the same
  3 pre-existing waived findings, no new exposure.
- `mypy` (strict, configured; not this group's gate list but run for the record): the
  single pre-existing error in the untouched `tests/test_leak_check.py` (its import of
  the `scripts/check_publication_leaks` module); no error in any file this group
  touched.
- Vocabulary boundary re-check on the touched files: the D14 family-name grep and the
  task 2.5 renamed-spelling grep both return zero hits in the files this group touched;
  the `Keycloak` mentions that remain in `.env.example` are the D8-scoped local-instance
  plumbing that group 2 landed, untouched here.
- The compose-boot gate and pip-audit/Trivy are task 6.x's rows, not this group's.
