# D5 amendment delta review — the confidential client on every identity-leg token request (2026-11-05)

Focused re-review (the review gates' amendment pass) of commit `ccc0284` against
`a4f2d72` — the owner's round-5 ruling re-implemented: the gateway is a confidential
client at the identity provider, the client secret required at startup in both positions
of `IDP_PKCE_ENABLED` and presented on every identity-leg token request, the toggle
governing only the challenge/verifier. Scope: exactly `git diff a4f2d72..ccc0284`
(the authoring revision, the code re-implementation, the tests, the threat-model
re-pricing). No fixes made; nothing outside this file touched.

## Findings

| id | severity | evidence | disposition |
|---|---|---|---|
| D5-R1 | **major** | `docs/gateway-configuration.md` — the operator reference was **not touched by the amendment** and still teaches the superseded semantics at live sites: line 42 (the refusal table's `IDP_PKCE_ENABLED=false` with no `IDP_CLIENT_SECRET` row — "the refusal names both settings", the old no-PKCE-only refusal, which the new `_require_client_secret` replaced with a both-positions refusal naming the setting alone); line 534 (`IDP_CLIENT_SECRET` "(empty) … Empty for a public PKCE client" — it is now required); lines 660–677 (the "no-PKCE mode" section, including verbatim "in the default mode a configured secret is never presented on any leg — the challenge binding already protects the code, so presenting the secret too would double the credential's exposure for no gain" — the exact property the ruling inverted); line 966 ("load-bearing only in the no-PKCE mode … empty for a public PKCE client"); lines 988/996 (the provisioning table: "Public client, standard flow only … a public client has no secret to print" — `scripts/provision_keycloak.py` now registers `publicClient: False` and writes a secret to the local `.env`). Compounding: `openspec/changes/generalized-idp-federation/tasks.md` 5.1 is marked `[x]` with round-5-amended text ("the challenge-off mode's priced trade … the secret, required at startup in both toggle positions"; "IDP_CLIENT_SECRET is required at startup in both toggle positions") that the file does not satisfy, and no open task row carries the operator-reference update — the re-implementation evidence (`docs/evidence/c2/task-4-reimplementation.md`, "Deviations") defers only `docs/local-environment.md`, `docker-compose.yml`, and the 4.1/4.2 tick marks; the operator reference and README are named in no deferral. | Fix before push: re-word `docs/gateway-configuration.md` to the confidential-client semantics (or explicitly re-open 5.1 the way 4.1/4.2 were re-opened, recording the deferral). An operator following the reference as it stands would configure no secret in the default mode and hit a startup refusal the doc says cannot happen. |
| D5-R2 | minor | `README.md:126` — "(`IDP_CLIENT_ID`, `IDP_CLIENT_SECRET` for a confidential client)" still implies the secret is conditional; under the ruling it is unconditionally required. README is one of the "both operator docs" the release-notes draft names as carrying the change lockstep. | Fix with D5-R1's doc round. |
| D5-R3 | low | Stale "public client" class reference inside files the amendment itself touched: `gateway/settings.py:326` and `.env.example:151` — "the refresh-token window the provider gives a public client's tokens" (the `IDP_SSO_SESSION_MAX_SECONDS` guidance). The gateway's identity-provider client is now confidential; the window fact an operator reads off an external provider is the confidential/web registration's (design.md D9 re-worded exactly this fact for the tested provider). Wording-only; no behavior claim about the secret's presentation. | Fix with D5-R1's doc round (both lines are in that round's blast radius). |
| D5-R4 | info (accepted deferral, already recorded) | `docs/local-environment.md:58-60` ("public with PKCE by default; a secret only where the client is confidential (the no-PKCE mode …)") and `docker-compose.yml:151` ("a mode that then requires IDP_CLIENT_SECRET") still carry the old semantics, and `docker-compose.yml:147` passes `IDP_CLIENT_SECRET: ${IDP_CLIENT_SECRET:-}` — the documented local bring-up will refuse at startup until the orchestrator's compose/probe round lands the local `.env` knock-on. This deferral is explicit in `docs/evidence/c2/task-4-reimplementation.md`'s deviations section; the compose-boot gate re-runs there. | Tracked by the orchestrator round; not a new finding. The compose-boot gate for the amendment is not yet green by record. |
| D5-R5 | info (observation, no action) | The challenge-off redirect test (`tests/test_idp.py::test_the_challenge_off_redirect_carries_no_challenge_and_the_token_requests_authenticate_with_the_secret`) asserts member presence/absence on the redirect rather than byte-pinning the full query; the challenge-on test byte-pins the shared `authorization_url` construction exactly, and `_client_authentication()` is not reachable from `authorization_url` (single usage site, below), so no toggle-conditional redirect regression is constructible without code the challenge-on pin would catch. | No action. |

## The inversion, verified complete where the amendment reached

`git grep` at `ccc0284` for the old property's wording ("never presents/never
presented", "public client", "no client credential", "opportunistic"), outside
`docs/evidence/` and `openspec/changes/archive/`:

- **Code** — `gateway/idp.py` and `gateway/settings.py`: no old-property hit; the
  module docstring, `_client_authentication`, the validator (`_require_client_secret`,
  replacing `_require_client_secret_in_no_pkce_mode`), and every field comment state
  the new property. `gateway/discovery.py:66`'s "public client sends no client
  authentication" is the **client-facing AS surface** (`token_endpoint_auth_methods_supported:
  ["none"]` for harness clients) — a different, correct surface the ruling does not
  touch. (D5-R3's two stale lines are the only code/env hits, dispositioned above.)
- **Tests** — the old pins are inverted, not merely deleted:
  `test_the_default_mode_presents_the_client_secret_under_the_challenge` (the
  byte-level pin, below), `test_the_refresh_grant_authenticates_with_the_client_secret`
  (`tests/test_tokens.py`, inverted again), the sweep renamed and widened to both
  toggle positions. No test asserts the secret's absence anywhere.
- **Delta spec** — the requirement is re-titled "The identity-provider client is
  confidential; the PKCE toggle governs the challenge only" with all five scenarios
  re-worded; the discovery requirement's credential-material clause updated; the
  three "public PKCE client" sites covered by declared amendments. The **main spec**
  (`openspec/specs/mcp-signin/spec.md:142/158/628`) still reads "the gateway's public
  PKCE client" — correct per the OpenSpec workflow: it is the pre-change spec, and the
  delta's declared amendments re-word exactly those sites at sync/archive time.
- **Design** — D5 re-written as the ruling (the prior D5 recorded as superseded, the
  semantic diff in `docs/evidence/c2/authoring-round-5.md`); D13, D9, the SIA's
  DT-EP5-3/DT-EP5-4/DT-EP4-1, and the never-cut table's rows 2 and 5 all state the new
  property.
- **Threat model** — no old-property hit outside historical records; see the
  re-pricing check below.
- **Historical records, marked as such** — `docs/evidence/c2/task-4-implementation.md`,
  `task-5-implementation.md`, `review-round-1.md`, `owner-round-2.md`,
  `general-review-gate.md`, and `openspec/changes/generalized-idp-federation/evidence/*`
  carry the old property as records of prior rounds; `task-4-reimplementation.md`
  explicitly states "where that record says 'never presents in the default mode' it
  describes code this round removed". `docs/background/design-review.md` is a
  historical background document. All acceptable.

The **operator documentation** is the one live surface where the inversion is
incomplete — D5-R1/D5-R2/D5-R4 above.

## The new pins, verified sound

- **Byte-level both-token-requests pin.**
  `test_the_default_mode_presents_the_client_secret_under_the_challenge` asserts
  raw-byte equality (`bodies[0] == expected_exchange.encode()`,
  `bodies[1] == expected_refresh.encode()`) against expected bodies spelled in the
  leg's own member order — `client_secret` last on both (after the verifier on the
  exchange, after the client id on the grant), matching the built form exactly
  (`_post_token`: base form → `code_verifier` if toggle-on → `form.update(
  _client_authentication())`; `_post_refresh`: base form → the update). A missing
  member, an extra one, a reorder, or a re-encoding fails the equality. The redirect
  is pinned the same way with the challenge parameters on and no secret in the query.
- **Sweep plant-proof non-vacuous.**
  `test_the_client_secret_appears_only_in_the_token_request_bodies` (parametrized over
  both toggle positions) proves the plant first — `any("client_secret=" + CLIENT_SECRET
  in body)` over the captured token-request bodies — before sweeping every log record
  at DEBUG (the audit trail and exception texts included), the three harness-facing
  response bodies, and their headers. The refused exchange's page is asserted to name
  the fixed-vocabulary class ("the identity provider refused the code exchange (400)").
- **Missing/blank refusal in both positions.**
  `test_a_missing_client_secret_refuses_startup_in_either_toggle_position` (the
  model's required-field refusal — `idp_client_secret: SecretStr` with no default)
  and `test_a_blank_client_secret_counts_as_unset_and_refuses_startup` (a blank
  `SecretStr` refused by the validator, so compose's explicit-empty-string delivery
  cannot silently pass), both parametrized `[True, False]`, both asserting the refusal
  names `idp_client_secret`; negative controls pass in both positions.
- **Client-facing PKCE pin unchanged and passing.**
  `tests/test_authorize.py` untouched by the diff and green in the full suite; the
  challenge-off variant asserts the `invalid_request` redirect at `/dial/authorize`
  without a challenge.

## Security posture of the new shape

- **The secret travels only on the token leg.** One usage site in the code:
  `_client_authentication()` (gateway/idp.py:562-563), consumed only by `_post_token`
  and `_post_refresh` — both POSTs to the resolved token endpoint. No GET, no redirect,
  no URL carries it: `authorization_url` builds its query from fixed members only, and
  the challenge-on byte pin proves the redirect secret-free. The probes handle no
  secret at all (the browser leg is the human's; the gateway does the exchange).
- **Fixed-vocabulary errors interpolate no secret.** The startup refusal names the
  setting only; the leg refusals are the pre-existing fixed classes, pinned by the
  sweep.
- **Never-cut 2 holds.** No diff reaches `gateway/federation.py` or the upstream
  authorize construction/credential call; the upstream verifier stays Core's, per
  task-4-reimplementation's re-check, which this review re-confirmed on the diff stat.
- **Never-cut 5 holds.** The DEBUG-level sweep covers logs/audit/response bodies and
  headers; no argv surface exists; `scripts/provision_keycloak.py` writes the generated
  secret to the local `.env` and never prints it (the admin token stays a redacted
  handle).
- **Re-pricing matches the built behavior.** A18: "presented on every token request in
  both toggle positions … the no-secret deployment exposure class is removed by the
  2026-11-05 ruling". EP4's title/row: "load-bearing in every deployment" — always on
  the token leg's wire, always in process memory, with the challenge-on mode's leaked-
  secret-alone-cannot-spend-an-intercepted-code narrowing honestly retained. RES-24:
  "the control is inherent, not mode-conditional … in both toggle positions", the
  residue re-named as the missing challenge binding, not a missing secret. RES-19: the
  override deployment's plain-http claim "carries the client secret as well — on every
  token request, in both positions of the leg's PKCE toggle", with the earlier
  no-PKCE-only conditioning marked superseded. M28 and the DT rows re-worded to the
  same shape. All consistent with the code as built.

## The D9 fact re-wording (task 7.1)

Verified. design.md's Context now states the confidential (web) registration shape,
the 14-day default window for it, and — the load-bearing part — that the web
registration receiving session refresh tokens at the code exchange without
`offline_access` is **"live-run-to-verify, not verified"**, with the expectation
("the tested provider is expected to issue refresh tokens by default for its web
registrations too") carried as OQ-B (design.md:1264) and the tasks' 7.1 row re-worded
to "the run verifies". The old 24-hour SPA/PKCE fact is correctly re-attributed to
the shape the gateway no longer uses. Not presented as verified.

## Gates (re-run for this review, on the worktree at ccc0284)

- `ruff check .` — **all checks passed** (exit 0).
- `pytest -q` — **619 passed, 1 skipped** (exit 0), full suite.
- `python scripts/check_publication_leaks.py` — **PASS** (221 tracked files; 3
  findings, all pre-existing and waived; 0 unwaived).

## Verdict

**Findings** — the amendment's core (code, tests, delta spec, design, threat model)
is sound and fully inverted, and all three gates pass, but the inversion is incomplete
on the live operator surface: `docs/gateway-configuration.md` still teaches the
superseded property at six sites with task 5.1 ticked against text the file does not
satisfy (D5-R1, major), `README.md` still implies the secret is conditional (D5-R2),
and two amendment-touched lines still reference the public-client window class
(D5-R3). Fix D5-R1–R3 (or record their deferral as explicitly as the local-env/compose
knock-on was recorded) before push; D5-R4 is the already-recorded orchestrator
deferral, and D5-R5 needs no action.

## Dispositions (the fix round, 2026-11-05)

| id | disposition | what changed |
|---|---|---|
| D5-R1 | **Fixed.** `docs/gateway-configuration.md` re-worded to the confidential-client semantics at the six named sites plus two same-class lines the review's sweep missed in the same file. Line 42's refusal-table row is now the unconditional missing/blank-secret refusal naming `idp_client_secret` alone; line 534's `IDP_CLIENT_SECRET` row states **required** (presented on every identity-leg token request, both toggle positions; the committed placeholder stays empty); the no-PKCE section carries the new property — the secret authenticates every identity-leg token request in both positions, the challenge is what the toggle drops, dropping it is for a PKCE-incapable provider only, with the interception trade stated and the old "never presented on any leg / double the exposure" sentence removed; the Secrets table's `IDP_CLIENT_ID`/`IDP_CLIENT_SECRET` rows state the confidential registration and the always-load-bearing secret; the provisioning table's Type row is "Confidential client, standard flow only" (`publicClient: false`) and the closing paragraph states the helper converges/writes the secret and never prints it. The two missed same-class lines: the `IDP_CLIENT_ID` row (965, "a public PKCE client … no secret exists for it") and the `IDP_SSO_SESSION_MAX_SECONDS` row (706, the D5-R3 window-class wording). Tasks 4.1/4.2 ticked as re-executed-and-satisfied; 5.1's tick now matches the file (the challenge-off priced trade and the both-positions-required delivery statement it demands are in the reference as re-worded). | `docs/gateway-configuration.md`, `openspec/changes/generalized-idp-federation/tasks.md` |
| D5-R2 | **Fixed.** `README.md:126`'s conditional dropped: the profile paragraph now states the secret is required at startup in both toggle positions — the gateway's client is a confidential client. | `README.md` |
| D5-R3 | **Fixed, plus two same-class hits in files already touched.** `gateway/settings.py`'s `idp_sso_session_max_seconds` comment and `.env.example`'s `IDP_SSO_SESSION_MAX_SECONDS` comment now read "the refresh-token window the provider gives a client of this registration shape (the confidential client the gateway registers as)". The sweep for this round also found the same stale class at `gateway/settings.py:294` (`idp_client_id` — "No secret exists for a public client, so this is not secret material") and `.env.example:42` (`IDP_CLIENT_ID` — "Public (PKCE, no secret) … holds no client credential"), each contradicting its own file's confidential-client statement; both re-worded to the confidential-client semantics. The remaining "public client" mentions in the tree are the client-facing AS surface (harness clients) and historical/background records — correct as the review ruled. | `gateway/settings.py`, `.env.example` |
| D5-R4 | **Landed this round; the amendment's compose-boot gate now green by record.** `docker-compose.yml`'s identity-provider comment block re-worded (the client id names the confidential client the helper registers, its secret converging to the local profile's `IDP_CLIENT_SECRET`; the mode-settings comment states the secret is required either way and the toggle governs the challenge only — the old "a mode that then requires IDP_CLIENT_SECRET" line removed). `docs/local-environment.md`: the external-provider sketch's client row states the confidential registration and the both-positions-required secret; the provisioning section states the helper registers `publicClient: false` and that the local profile's bring-up includes the secret — the helper generates and writes `IDP_CLIENT_SECRET` to the local `.env` where the profile carries none, keeps a profile-supplied value, and never prints it. **The boot verification:** rebuilt and recreated the gateway from this worktree (`wsl -e docker compose up -d --build mcp-signin-gateway`, PowerShell). The container came up **healthy** (the compose healthcheck's probe passing). The container's env was inspected without printing any value: `IDP_CLIENT_SECRET` present (40 characters), `IDP_PKCE_ENABLED=false` — the boot verified the **worktree `.env`'s live B2C profile** (the challenge-off position, the B2C tfp issuer), which is the profile the live run needs; the secret-present fact is position-independent by the new validator, and the challenge-on position's startup refusal is covered by the parametrized settings tests. | `docker-compose.yml`, `docs/local-environment.md` |
| D5-R5 | No action, unchanged (observation only). | — |

### The fix round's gates

Re-run after the fixes, from the worktree (the main checkout's venv):

- `ruff check .` — **all checks passed** (exit 0); `ruff format --check gateway/settings.py` — **1 file already formatted**.
- `pytest -q` — **619 passed, 1 skipped** (exit 0), full suite.
- `python scripts/check_publication_leaks.py` — **PASS** (221 tracked files; 3 findings, all pre-existing and waived; 0 unwaived).
- The compose-boot gate — **healthy**, against the B2C profile recorded under D5-R4 above.

Nothing committed; the fix round leaves its changes uncommitted in the worktree for the
orchestrator's gates and push.
