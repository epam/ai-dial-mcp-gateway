# Task group 4 — the confidential-client / no-PKCE mode (tasks 4.1–4.3)

Change: `generalized-idp-federation` (C2). Scope of this record: the `IDP_PKCE_ENABLED`
setting and its startup refusal, the mode's two sides in `gateway/idp.py` (no challenge
plus secret-authenticated token requests when disabled; the secret never presented when
enabled — the default), and the never-cut 2 boundary inspection. No commit made.

## Task 4.1 — the setting and its startup refusal

`gateway/settings.py`:

- `idp_pkce_enabled: bool = True`, in the identity-provider section beside the client
  settings, with the mode's shape in the field comment (the challenge is what makes an
  intercepted identity-leg code unexchangable; the mode is the identity leg's alone; the
  client-facing AS surface keeps requiring PKCE whichever way it is set);
- `_require_client_secret_in_no_pkce_mode` (model validator): when `idp_pkce_enabled` is
  false and `idp_client_secret` is unset — a `None` **or a blank value counts as unset**,
  because the compose file passes every setting explicitly and an unset deployment secret
  arrives as an empty string — startup refuses with a message naming **both settings**
  (`idp_pkce_enabled` and `idp_client_secret`) and stating the reason: the mode drops the
  challenge binding, and the client secret is the compensating control that authenticates
  the exchange and the refresh grant in its place. The plain-http-issuer refusal this row
  also lists is group 3's `_require_https_issuer_without_the_override`, already landed
  and already covered (see the task-3 record);
- the `idp_client_secret` field comment now states its no-PKCE-mode role (required
  there, the compensating control) beside its existing "empty for a public PKCE client"
  reading.

Coverage in `tests/test_settings.py` (4 new tests): the refusal naming both settings
(`test_no_pkce_mode_without_a_secret_refuses_startup_naming_both_settings`), the blank-
secret-is-unset edge (`test_a_blank_secret_in_no_pkce_mode_counts_as_unset`), the
negative control — the mode with a configured secret starts
(`test_no_pkce_mode_with_a_secret_starts`) — and the default mode's pass cases: PKCE on
by default, and a configured secret changes neither the default nor the startup
(`test_pkce_is_enabled_by_default_with_or_without_a_secret`).

## Task 4.2 — the mode in the identity leg

All of it in `gateway/idp.py` (the flow's caller is untouched — the mode is the client's
configuration, not the caller's):

- **When disabled** — `authorization_url()` omits `code_challenge` and
  `code_challenge_method` from the redirect query (the caller still derives a challenge;
  the leg's mode decides whether the redirect carries it, so one call shape serves both
  modes). `_post_token()` presents `code_verifier` only in the default mode (no
  challenge was issued, so there is none to present) and both `_post_token()` and
  `_post_refresh()` authenticate the client from the new `_client_authentication()`
  helper: the secret in the POST body — the form-credential spelling the client's token
  requests already use, matching the helper-registered client's confidential shape an
  operator registers for this mode (the local provisioning helper's client stays the
  public-PKCE shape, which is the default mode's). Everything else — endpoints,
  verification, custody, error vocabulary — is byte-for-byte the other mode's paths.
- **When enabled (the default)** — `_client_authentication()` returns an empty mapping:
  the opportunistic send whenever a secret was set (the old
  `if secret is not None and secret.get_secret_value(): form["client_secret"] = …` in
  both `_post_token` and `_post_refresh`) is **removed**. The secret's presentation is
  the no-PKCE mode's compensating control, never an add-on to a leg whose PKCE binding
  already protects it — the delta spec's default-mode scenario pins this as the converse,
  so the default-mode requests are now a fixed shape the mode cannot widen.

New tests, `tests/test_idp.py` (section "the confidential-client / no-PKCE mode"), one
per scenario row:

- **No-PKCE mode runs as a confidential client** —
  `test_the_no_pkce_redirect_carries_no_challenge_and_the_exchange_authenticates_with_the_secret`:
  asserted on the leg's actual requests. The redirect query carries `response_type`,
  `client_id`, `redirect_uri`, `scope`, `state` and neither challenge parameter; the
  exchange's captured POST body carries `grant_type=authorization_code`,
  `client_secret=<the secret>`, and no `code_verifier`; the refresh grant's captured
  body carries `grant_type=refresh_token` and the secret.
- **The default mode never presents the client secret (byte-identical scenario)** —
  `test_the_default_mode_is_byte_identical_except_that_a_configured_secret_is_never_presented`:
  the gateway runs with a client secret configured and PKCE at its default, through the
  full chain (redirect → exchange → refresh), and three assertions compare **raw
  bytes**. The redirect's full URL must equal the pre-change query — the expected string
  is spelled in the test with the pre-change member order (`response_type`, `client_id`,
  `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`), the
  challenge derived from the flow record's own verifier. The exchange's and the refresh
  grant's captured request bodies must each equal an expected body spelled in the
  pre-change leg's own member order (`grant_type`, `code`, `redirect_uri`, `client_id`,
  `code_verifier`; `grant_type`, `refresh_token`, `client_id`) — the form the leg sent
  before this change, minus the `client_secret` member the old opportunistic send
  appended. Any added member, any reorder, any re-encoding fails the equality; and the
  secret's bytes are asserted absent from all three. This is a real test, not prose: the
  expected bodies are constructed in the test, not read from the implementation.
- **The client-facing surface still requires PKCE** —
  `test_a_harness_authorization_request_without_pkce_is_still_refused_in_no_pkce_mode`:
  a harness request without a `code_challenge` is refused (redirected to the client with
  `error=invalid_request`) on a gateway configured in the no-PKCE mode — the mode is the
  identity leg's alone. The default-mode pin of the same refusal is the pre-existing
  `tests/test_authorize.py::test_a_missing_code_challenge_is_redirected_to_the_client`,
  confirmed present and passing, unchanged.
- **The client secret never reaches an output** —
  `test_no_log_audit_or_error_page_carries_the_client_secret`: the secret is planted
  (distinctive value) and **both outcomes run** — a sign-in that succeeds end to end
  (exchange and refresh both authenticate with the secret) and an exchange the provider
  refuses with `invalid_client`. The test first proves the plant is real (the secret's
  `client_secret=` pair is in the captured token-request bodies — the sweep cannot pass
  vacuously on a secret nothing used), then sweeps every emitted record: every log
  record's message and exception text at DEBUG and above (the `gateway.audit` audit
  trail included), the refused exchange's error page, the successful token responses,
  and every response header. Nothing carries the secret; the provider refusal surfaces
  by its fixed-vocabulary class ("the identity provider refused the code exchange
  (400)"), never by the credential it refused.

One pre-existing test pinned the superseded behavior and was re-pointed at the new one:
`tests/test_tokens.py::test_the_refresh_grant_never_presents_the_client_secret_in_the_default_mode`
(was `test_the_refresh_grant_uses_the_configured_client_secret_when_present`, which
asserted the opportunistic send on the refresh grant — exactly the behavior the delta
spec's converse scenario removes). It now plants a secret, runs the refresh grant, and
asserts no `client_secret` member and no secret bytes in the captured request.

## Task 4.3 — the never-cut 2 boundary, as built

Inspection of the change's full diff (from the pre-change tree at `89775ad` to this
working tree) against the upstream leg and Core's verifier:

- **`gateway/core.py`: zero diff** — Core's client, its reads, and everything Core's
  credential call rides on are untouched by the whole change.
- **`gateway/flow.py`: one hunk pair only**, both in `begin_identity_leg` (the identity
  leg's redirect; group 3's async change). Not one diff line reaches:
  - `upstream_authorization()` (flow.py:268) — the upstream authorize construction from
    the toolset's public settings, including the required-parameter delivery guard whose
    `UPSTREAM_REQUIRED_PARAMETERS` still lists the upstream `code_challenge`/
    `code_challenge_method`;
  - `complete_upstream_leg()` (flow.py:331) and `_post_credential_signin()` (flow.py:358)
    — the credential call, still posting `credentialsLevel: "USER"` with the user's
    identity token.
- The mode's variations all live behind `IdentityProviderClient`'s own methods
  (`authorization_url`, `_post_token`, `_post_refresh`, `_client_authentication`) — none
  of them a caller of the upstream leg. The upstream verifier is Core's, per toolset,
  nulled on every public projection, untouched on every path: preserved, not adapted.
- The client-facing AS surface: `gateway/authorize.py`'s PKCE requirement
  (S256-only, `unacceptable_code_challenge`) is untouched by group 4 — its whole diff in
  this change is group 2's rename plus group 3's await of the async redirect — and the
  no-PKCE-mode refusal test above runs it with the mode off and gets the same refusal.

## Deviations from the stated file scope

1. **`.env.example`** — the new `IDP_PKCE_ENABLED=true` line with its mode/trade comment,
   placed in the IdP section. Mechanical and forced: the settings model now reads the
   field, and the example-completeness test
   (`tests/test_settings.py::test_every_settings_field_is_named_in_the_example`) requires
   every field the model reads to be named in the example — the same forcing function as
   the task-3 record's `.env.example` deviation. The placeholder is the boolean default,
   no real value.
2. **`tests/test_tokens.py`** — the re-pointed test described above; the file is a test
   file where a scenario test lives (the converse the delta spec pins), and the old test
   pinned behavior task 4.2 exists to remove.

## Gates

- `ruff check .` — "All checks passed!" (whole tree).
- `ruff format --check` on the touched files (`gateway/settings.py`, `gateway/idp.py`,
  `tests/test_settings.py`, `tests/test_idp.py`, `tests/test_tokens.py`) — all formatted.
- `pytest -q` — **601 passed, 1 skipped** (before this group: 593 passed, 1 skipped;
  +8: 4 in `tests/test_settings.py`, 4 in `tests/test_idp.py`; the `test_tokens.py` test
  replaced 1-for-1). One unrelated flake in `tests/test_custody.py` on the first full
  run passed on re-run and in two further full-suite runs; no change this group made
  touches the custody envelope.
- `bandit -r gateway` — exit 0, no findings (nothing to triage). Two throwaway `nosec`/
  `noqa` annotations were added and removed while landing the `S256` constant; the final
  state carries none, and the only remaining nosec warnings are the pre-existing ones in
  `routes.py`/`tokens.py`.
- Leak check `python scripts/check_publication_leaks.py` — **PASS** (exit 0): the same 3
  pre-existing waived findings, no new exposure.
- Vocabulary boundary re-check on the touched surfaces: the D14 family-name grep
  (`entra|b2c|azure|microsoft|tfp|b2clogin|ciamlogin|onmicrosoft|external id|statgpt`
  over `gateway/`, `tests/`, `pyproject.toml`, `.env.example`, `docker-compose.yml`,
  `README.md`, `docs/gateway-configuration.md`, `docs/local-environment.md`) returns
  zero hits.
- The compose-boot gate, pip-audit/Trivy, and the review gates are task 6.x's rows, not
  this group's.
