# Tasks 4.1/4.2 re-executed — the confidential client in every deployment (2026-11-05)

Implementer's record for the re-opened tasks 4.1/4.2, executed against the revised
semantics of the owner's round-5 ruling (`docs/evidence/c2/authoring-round-5.md`,
design.md D5, and the delta spec's requirement "The identity-provider client is
confidential; the PKCE toggle governs the challenge only"). The prior implementation of
these tasks (`docs/evidence/c2/task-4-implementation.md`) built the superseded
public-client semantics; where that record says "never presents in the default mode" it
describes code this round removed.

## The semantic diff, code side

**`gateway/settings.py`**

- `idp_client_secret` is now `SecretStr` with **no default** — a value absent altogether
  is the model's own required-field refusal, which names the setting.
- The old `_require_client_secret_in_no_pkce_mode` validator is replaced by an
  unconditional `_require_client_secret`: it refuses a **blank** value (compose passes
  every setting explicitly, so an unset deployment value arrives as an empty string —
  the blank-counts-as-unset behavior is kept so an explicit blank hits the refusal, not a
  false pass). The refusal names `idp_client_secret` alone; the old message's
  naming-both-settings no-PKCE framing is gone with the mode.
- The `idp_pkce_enabled` field comment re-stated: the toggle governs the challenge only;
  the client-facing surface's PKCE requirement is unchanged. The `idp_client_secret`
  field comment states the both-positions requirement and the every-token-request
  presentation.

**`gateway/idp.py`**

- `_client_authentication()` returns the secret's form-credential on **every** call — the
  `idp_pkce_enabled` branch and the blank-secret guard inside it are removed. The secret
  rides the exchange and the refresh grant in both toggle positions, in the POST body;
  the startup refusal guarantees it exists and is not blank.
- `authorization_url()` and `_post_token()`'s verifier branch keep the toggle governing
  the challenge alone: `code_challenge`/`code_challenge_method` on the redirect and
  `code_verifier` on the exchange only when the toggle is on.
- Module docstring's mode paragraph, `authorization_url`/`refresh_identity`/
  `_post_token` docstrings, and the verifier-branch comment re-worded to the
  confidential-client semantics. The "never presents on any leg" property is gone; its
  inverse is pinned by test (below).

**`scripts/provision_keycloak.py`** — the local realm's client registers
**confidentially** (`publicClient: False`; the old "public client with PKCE" bullet and
its rationale replaced). The client's secret is part of the converged shape: the helper
converges the realm's client to the profile's `IDP_CLIENT_SECRET` where `.env` carries
one, and where it does not, generates a value, always updates the client to it, and
writes it back to the local profile's `.env` as `IDP_CLIENT_SECRET` (existing line
replaced in place, missing line appended, other lines untouched; the secret is never
printed). The helper's own verification flows (`obtain_session_document`,
`refresh_once`) present the secret from the profile on their token requests, as the
gateway does. This helper has **not been run against a live realm this round** — the
provisioning run and the end-to-end probe re-run are the orchestrator's, on its schedule.

**`.env.example`** — the `IDP_CLIENT_SECRET` comment states the requirement (required at
startup in both toggle positions; presented on every identity-leg token request; the
committed placeholder stays empty per never-cut 6 / D13). The `IDP_PKCE_ENABLED` comment
states the challenge-only governance and that the secret is required either way.

## The tests, per pin

**`tests/test_settings.py`** — the old no-PKCE-mode refusal section (4 tests) replaced by
the required-secret section:

- `test_a_missing_client_secret_refuses_startup_in_either_toggle_position` — parametrized
  over both toggle positions; built on the bare model with no secret; asserts the
  refusal names `idp_client_secret`.
- `test_a_blank_client_secret_counts_as_unset_and_refuses_startup` — parametrized over
  both positions; a blank `SecretStr` refuses, naming the setting.
- `test_a_configured_client_secret_starts_in_either_toggle_position` — the pass cases,
  both positions.
- `test_pkce_is_enabled_by_default` — the toggle's default.
- The pre-existing required-field tests (session bound, custody keyset, roles path) and
  the federation-defaults test now supply a secret so each isolates its own refusal;
  `test_defaults_are_inert` drops the `idp_client_secret is None` assertion (the field
  has no inert default any more) and keeps the rest; the hermeticity test's temp `.env`
  carries an `IDP_CLIENT_SECRET` line and its file-off control supplies one directly.

**`tests/test_idp.py`**

- `test_the_challenge_off_redirect_carries_no_challenge_and_the_token_requests_authenticate_with_the_secret`
  (renamed from the no-PKCE test): redirect without `code_challenge`/
  `code_challenge_method`, the other parameters present; the exchange carries
  `client_secret` and no `code_verifier`; the refresh grant carries `client_secret` —
  asserted on the captured request bodies.
- `test_the_default_mode_presents_the_client_secret_under_the_challenge` (inverts the
  old never-presents pin): the byte-level pin. Each raw request body must equal an
  expected body spelled in the test — `urlencode` over the leg's own member order, the
  `client_secret` member where the client authentication is appended (the exchange's
  last member, after the verifier; the refresh grant's last, after the client id) —
  asserted by raw-byte equality (`bodies[i] == expected.encode()`), so a missing secret
  member, an extra one, a reorder, or a re-encoding fails. The redirect is pinned the
  same way with the challenge parameters on.
- `test_a_harness_authorization_request_without_pkce_is_still_refused_in_the_challenge_off_mode`
  (renamed): the client-facing refusal holds under the identity-leg toggle off.
- `test_the_client_secret_appears_only_in_the_token_request_bodies` (the
  never-emitted sweep, widened): parametrized over **both toggle positions**; the secret
  is planted, and the run exercises both outcomes — a sign-in that succeeds end to end
  (refresh grant included) and an exchange the provider refuses with `invalid_client`.
  The **plant proof** comes first: the captured token-request bodies must contain
  `client_secret=<value>`, so the sweep cannot pass vacuously on a secret nothing used.
  The sweep then asserts the value appears in **nothing else** the gateway emitted: every
  log record at DEBUG and above (the audit trail included, exception texts included),
  the three responses to the harness (the redeemed, refreshed, and refused bodies), and
  their headers. The refused exchange's page names the fixed-vocabulary class, not the
  credential.

**`tests/test_tokens.py`** — `test_the_refresh_grant_authenticates_with_the_client_secret`
(the re-pointed refresh test, inverted again): with a secret planted, the captured
refresh grant's form carries `client_secret=<value>` beside the grant type and the
provider refresh token.

**`tests/test_authorize.py`** — **untouched**, and its client-facing PKCE-required pin
(`test_a_missing_code_challenge_is_redirected_to_the_client`, plus the `plain`-method
refusal) passes unchanged in the full suite: the challenge-off mode remains the identity
leg's alone.

## Never-cut 2's boundary, re-checked on this round's diff

The diff touches `gateway/settings.py` (the secret requirement and the toggle's comment),
`gateway/idp.py` (`_client_authentication`, the docstrings), the mode tests, the
provisioning helper, and `.env.example`. No diff reaches the upstream authorize
construction or the credential call: `gateway/federation.py` is untouched, the upstream
leg's verifier stays Core's, and the client-facing surface's PKCE requirement is pinned
unchanged. The toggle varies the gateway's own PKCE on the identity leg only.

## Gates (this round's diff)

- `ruff check .` — **all checks passed** (exit 0).
- `ruff format --check` on the touched files — **7 files already formatted** (the
  touched files plus `tests/conftest.py`; see deviations).
- `pytest -q` — **619 passed, 1 skipped** (exit 0), full suite green. The count moved
  with the re-pointed pins (the both-positions refusals and the sweep are parametrized
  over the toggle positions); the suite's other files pass with only the fixture-level
  secret-supply knock-on recorded below.
- `bandit -r -c pyproject.toml gateway/ scripts/` — 12 findings (8 Low, 4 Medium), **all
  pre-existing and in untouched `scripts/` files** (the leak checker's subprocess/word-list
  findings and the probes'/spike helper's `urlopen`/`subprocess` findings — the triaged
  baseline of the earlier gate rounds); a bandit run over the touched files alone
  (`gateway/` + `scripts/provision_keycloak.py`) returns **zero findings** (exit 0).
- `python scripts/check_publication_leaks.py` — **PASS** (219 tracked files; 3 findings,
  all pre-existing and waived; 0 unwaived).

## Deviations from the round's file list

The round's instruction was to touch `gateway/settings.py`, `gateway/idp.py`,
`scripts/provision_keycloak.py`, `.env.example`, the named test files, and the evidence
file. Three further files were touched, each a **minimal fixture-level knock-on** of the
now-required secret, changing no assertion and no test's subject:

- `tests/conftest.py` — `make_settings` supplies the local profile's client secret
  (`IDP_CLIENT_SECRET` constant beside the local issuer/back-channel constants). Without
  it, every settings object the suite builds would refuse at startup, and no test outside
  the named files could pass untouched.
- `tests/test_app.py` — the two tests that build `Settings` directly supply the secret.
- `tests/test_audit.py` — the uvicorn-arguments test supplies the secret through the
  environment it builds.

Not touched, per the file list, though task 4.1's full text names them: the local
`.env`/`docs/local-environment.md` documentation of `IDP_CLIENT_SECRET`, and
`docker-compose.yml`'s environment wiring. Those are the local-deployment knock-on the
orchestrator lands with the compose/probe round — the running container still holds the
old image, and the compose-boot gate re-runs there. Task 4.1/4.2's tick marks in
`tasks.md` are likewise left for the round that closes them.

Nothing is committed.
