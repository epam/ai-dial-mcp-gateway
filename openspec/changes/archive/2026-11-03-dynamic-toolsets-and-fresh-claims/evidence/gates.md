# Gate run — tasks 5.1, 5.2, 5.3, 5.8 (+ `openspec validate --strict`)

The gate-run pass for `dynamic-toolsets-and-fresh-claims`: the static gates (5.1), the
compose-boot gate (5.2), the conformance sweep (5.3), and the mechanical threat-model
sweep (5.8). No commits. All commands run on the Windows host from `.venv/Scripts`
(Trivy and Docker via WSL). Toolchain: Python 3.12.13, ruff 0.17.1, mypy 2.4.0,
bandit 1.9, Trivy 0.71.2.

## 5.1 Static gates

| Gate | Command | Result |
|---|---|---|
| ruff check | `ruff check` | **green** — "All checks passed!" |
| ruff format | `ruff format --check` | **green** — "156 files already formatted" |
| mypy | `mypy` (project config: `files = ["gateway","tests"]`) | **green** — "Success: no issues found in 40 source files" |
| bandit | `bandit -c pyproject.toml -r gateway` | **green** — "No issues identified." (5757 LOC; 9 `#nosec B105` suppressions, all triaged prose — see below) |
| pip-audit | `pip-audit` | **FINDING — remedied** (see below) |
| pytest | `pytest -q` | **green** — "497 passed, 1 skipped, 1 warning in 102.90s" |
| Trivy (image) | `trivy image --severity HIGH,CRITICAL dial-mcp-gateway:local` | **green at CRITICAL; 44 HIGH, all OS-package, no fix available** (see below) |

### mypy scope note

A bare `mypy .` reports **27 errors in 10 files, all under `scripts/`**. These are
**out of scope and not a finding**: `pyproject.toml` sets `files = ["gateway","tests"]`
with the comment that the one-off spike instruments under `scripts/` are interactive
helpers, not shipped code. The configured gate (`mypy` with no path) is green. The
`scripts/` files are untouched by a defect; the errors are pre-existing and excluded
by design.

### bandit `#nosec B105` suppressions (9)

All 9 are the RFC 7591/RFC 6749 method-name vocabulary, not credentials:
`gateway/routes.py` (6) — `token_endpoint_auth_method: "none"` and the grant-type strings
in the DCR response; `gateway/tokens.py` (3) — `ACCESS_TOKEN_TYPE`/`REFRESH_TOKEN_TYPE`
and `CUSTODY_CLAIM_MEMBER` ("custody"), a claim *name*, not a value. Bandit reports
"nosec encountered (B105), but no failed test on file" — i.e. the suppressions currently
mask nothing, which is the safe direction. Triaged: retained (they document intent).

### pip-audit — BLOCKING finding, remedied

First run (blocking):

```
Found 2 known vulnerabilities in 1 package
Name    Version   ID              Fix Versions
certifi 2026.7.22 PYSEC-2026-4320 2026.10.18
```

**Advisory** (`GHSA-6q48-6c7w-9gw2` / PYSEC-2026-4320): certifi < 2026.10.18 bundles the
`emSign ECC Root CA - G3` root; eight chained eMudhra intermediates have compromised
keys. An on-path attacker holding one can issue valid-looking certificates for any
hostname, intercepting TLS from clients that trust the bundle. Fixed in 2026.10.19+
(2026.10.18 removed all emSign roots; 2026.10.19 restored the unaffected ones).

**Reachability — reachable.** `certifi` is pulled by `httpx` (and `requests`) and is the
CA bundle for the gateway's outbound TLS legs — the identity provider's token/JWKS calls
and Core's credential API. It is not merely vendored; it is the trust root for traffic
the gateway makes. This is a genuine, reachable finding, not a triage candidate.

**Remedy applied (dependency bump).** `certifi` bumped in the local venv to 2026.10.23
(`python -m pip install --upgrade "certifi>=2026.10.19"`); pip-audit re-run:

```
No known vulnerabilities found
Name             Skip Reason
dial-mcp-gateway Dependency not found on PyPI and could not be audited (0.1.0)
```

(the skip is the un-published project itself, expected). **The built image already
carries the fixed version** — Trivy's METADATA scan of `dial-mcp-gateway:local` reports
`certifi-2026.10.23`. So the image is clean; the finding was confined to the stale local
venv, and the fix is the same version the image already resolves.

> **Action for the implementation pass (not a gate-run edit):** the dependency is
> unpinned (`pyjwt[crypto]>=2.15`, `httpx>=0.28`), so a fresh `pip install .` resolves
> certifi from the index and already picks the fixed version — but the finding belongs in
> the change's record. No `pyproject.toml` change is strictly required (no upper bound
> forced the stale version); a lower-bound floor (`certifi>=2026.10.19`) would make the
> fix belt-and-braces. Flagging for the owner; not applied here (no gate-run edits).

### Trivy on the built image

Image built with `wsl -e docker build -t dial-mcp-gateway:local .` (builder installs from
the index; the runtime image strips pip). **DB freshness: refreshed this run** —
`wsl -e trivy image --download-db-only` succeeded; DB `UpdatedAt 2026-11-01 07:08 UTC`
(today). No `--skip-db-update` needed.

```
Report Summary
dial-mcp-gateway:local (debian 13.7)   debian     44   -
...every python-pkg METADATA row: 0 vulnerabilities...
```

- **CRITICAL: 0.**
- **HIGH: 44**, all in the **Debian 13.7 base image OS packages** (not the app, not a
  Python dependency). Packages: `util-linux`/`bsdutils`/`libmount1`/`libblkid1`/
  `libsmartcols1`/`libuuid1`/`liblastlog2-2`/`login`/`mount` (CVE-2026-76642, -78408,
  -78409, -78410 — 4 CVEs × their mirrors), `ncurses-*`/`libtinfo6` (CVE-2025-69720),
  `libsystemd0`/`libudev1` (CVE-2026-16742), `libacl1` (CVE-2026-54369),
  `perl-base` (CVE-2026-9538, status `fix_deferred`).
- **Fix availability: 0 of 44 carry a `FixedVersion`** (43 `affected`, 1 `fix_deferred`)
  — Debian has published no fixed revision in the `python:3.12-slim` (trixie) archive.
  Triage: **unremedied upstream, accepted as base-image residual**. The remedies
  (a newer `python:3.12-slim` base digest, or a distroless base) are base-image bumps
  outside this change's scope; the gateway runs as a non-root user with a read-only
  filesystem and the affected packages (`mount`/`util-linux` helpers, `systemd` libs,
  `ncurses`, `perl-base`) are not on the gateway's execution path. No requirement is
  cut. Recorded as an accepted base-image residual; no reachable dependency vulnerability.
- **Python packages: 0 findings** — every `opt/venv/.../METADATA` row reports 0,
  including `certifi-2026.10.23`, `cryptography-50.0.2`, `pyjwt-2.15.1`, `starlette`,
  `fastapi`, `httpx`. **No secret findings.**

## 5.2 Compose-boot gate

Docker daemon started in WSL (`dockerd`); the sibling `dial-instance` stack
already up. `wsl -e docker compose up -d --build` rebuilt the gateway and recreated both
services (`--force-recreate` used to avoid the gateway-only-recreate router 502 quirk).

```
NAME                                       STATUS
ai-dial-mcp-gateway-mcp-signin-gateway-1   Up (healthy)
ai-dial-mcp-gateway-mcp-signin-router-1    Up (healthy)
```

Probes (all green):

| Probe | Command | Output |
|---|---|---|
| Gateway health through the front door (router 8090) | `curl http://localhost:8090/healthz` | `HTTP 200` / `{"status":"ok"}` |
| Gateway health in-container (8091) | `docker exec ... python -c urllib... /healthz` | `{"status":"ok"}` |
| Router serving (AS metadata through the front door) | `curl .../.well-known/oauth-authorization-server` | `HTTP 200` |
| Router serving Core (front door → Core) | `curl http://localhost:8090/health` | `HTTP 200` |
| Joined network resolves (Core from gateway container) | `docker exec ... /health` at `http://core:8080` | `core /health HTTP 200` |
| Joined network DNS (Keycloak) | `socket.gethostbyname("keycloak")` | `172.19.0.3` |
| Network membership | `docker inspect ... Networks` | `dial-instance_default` |

**Note — local `.env` was stale and updated to boot** (gitignored, not a diff). The
committed `.env.example`/compose defaults carry the new settings, but the local `.env`
still named `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` and carried no `GATEWAY_CUSTODY_KEYS`, so
startup refused (empty keyset). Updated locally: renamed to `IDP_SSO_SESSION_MAX_SECONDS`,
dropped `authentication_type` from the `TOOLSETS` entry, added
`GATEWAY_CUSTODY_KEYS={"k-local-1":"<generated-32-byte-b64>"}`,
`GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES=4096`, `GATEWAY_FORM_MAX_BODY_BYTES=16384`. This
is expected migration friction for an operator upgrading by the doc — the change's task
1.5/2.4 rows cover it.

## 5.3 Conformance sweep

The delta spec has **68 scenarios** (MODIFIED: discovery 5, authorization 5, federation
13, issued-tokens 4, claim-copy 4, bounds 4, status 3; ADDED: mapping 6, refresh 11,
name-guard 4, custody-carrier 9). Below, each delta scenario → its proving test row(s).

### MODIFIED requirements

| # | Scenario | Proving row(s) | Verdict |
|---|---|---|---|
| 1 | Flat AS metadata fetch | `test_discovery.py::test_flat_metadata_is_served_at_the_host_root`, `::...names_the_public_origin_as_its_only_issuer`, `::...endpoints_are_shared_by_every_toolset` | green |
| 2 | Per-toolset protected-resource fetch | `test_discovery.py::test_protected_resource_document_names_the_toolset_resource`, `::...names_the_single_authorization_server`, `::...carries_no_authentication_kind`, `::...echoes_the_upstream_scopes_verbatim`, `::test_a_pinned_toolset_with_no_scopes_publishes_an_empty_list` | green |
| 3 | Unmapped toolset | `test_discovery.py::test_a_restriction_excluded_name_is_not_found`, `::test_unserved_toolset_document_is_not_found` | green |
| 4 | Dynamic toolset served without local configuration | `test_discovery.py::test_a_guard_passing_name_is_served_in_dynamic_mode_with_no_core_call` | green |
| 5 | Guard-failing name refused at discovery | `test_discovery.py::test_a_reserved_name_is_refused_at_discovery`, `::test_a_charset_violating_name_is_refused_at_discovery` | green |
| 6 | Missing resource | `test_authorize.py::test_a_missing_resource_is_invalid_target`, `::test_an_empty_resource_is_treated_as_absent`, `::test_inference_off_by_default_refuses_a_missing_resource` | green |
| 7 | Unknown resource | `test_authorize.py::test_an_unknown_resource_is_invalid_target`, `::test_a_resource_with_a_trailing_slash_is_not_the_same_resource` | green |
| 8 | Valid request allocates a flow | `test_authorize.py::test_a_valid_request_redirects_to_the_identity_provider`, `::test_the_flow_id_is_a_128_bit_random_value`, `::test_a_valid_request_allocates_exactly_one_live_flow` | green |
| 9 | One-toolset inference | `test_authorize.py::test_one_toolset_inference_accepts_a_request_with_no_resource`; `test_settings.py::test_inference_with_a_single_entry_restriction_starts` | green |
| 10 | Guard-failing resource refused | `test_authorize.py::test_a_charset_violating_resource_name_is_invalid_target`, `::test_a_reserved_resource_name_is_invalid_target` | green |
| 11 | DIAL authorization denied | `test_federation.py::test_a_refused_settings_read_fails_before_any_upstream_round_trip` | green |
| 12 | Client scope never reaches the identity provider | `test_federation.py::test_the_redirect_requests_only_the_clients_default_scopes`; `test_authorize.py::test_the_redirect_requests_only_the_clients_own_scopes` | green |
| 13 | Upstream consent completes | `test_federation.py::test_the_signin_body_is_the_documented_one` (asserts `credentialsLevel: USER`), `::test_the_upstream_url_is_built_from_cores_public_settings` | green |
| 14 | Flow record destroyed on first use | `test_federation.py::test_a_replayed_upstream_callback_is_refused`, `::test_the_flow_holds_no_credential_after_it_completes` | green |
| 15 | Guessed flow id injects nothing | `test_federation.py::test_an_unknown_flow_id_at_the_upstream_callback_injects_nothing` | green |
| 16 | Non-OAuth toolset refused on the impossible branch | `test_federation.py::test_a_non_oauth_toolset_with_no_credential_is_refused_on_the_impossible_branch` | green |
| 17 | Already signed in short-circuits the consent | `test_federation.py::test_a_user_level_credential_short_circuits_with_no_upstream_leg`, `::test_a_signed_in_user_short_circuits_to_code_issuance` | green |
| 18 | A global credential serves every user without consent | `test_federation.py::test_a_global_credential_short_circuits_a_non_oauth_toolset` | green |
| 19 | The signed-in check fails closed | `test_federation.py::test_an_unreadable_or_failed_status_does_not_short_circuit`, `::test_an_app_level_only_status_does_not_short_circuit` | green |
| 20 | Unknown toolset refused at the flow's settings read | `test_federation.py::test_an_unknown_toolset_is_refused_at_the_settings_read` | green |
| 21 | Provider's session refresh token carried past the flow | `test_custody.py::test_the_custody_claim_appears_only_in_the_refresh_token`, `::test_the_code_payload_carries_no_identity_provider_credential`; `test_federation.py::test_no_offline_access_is_requested_at_the_exchange`, `::test_the_identity_token_is_used_for_the_core_reads_and_dropped` | green |
| 22 | Provider issues no refresh token | `test_federation.py::test_an_exchange_with_no_refresh_token_refuses_at_sign_in` | green |
| 23 | Provider refresh token over the custody size bound refused at sign-in | `test_federation.py::test_a_refresh_token_over_the_custody_bound_refuses_at_sign_in` | green |
| 24 | Code exchange issues tokens | `test_token.py::test_a_valid_code_exchanges_for_an_access_token`, `::test_the_access_token_is_signed_by_the_gateway_and_names_the_subject` | green |
| 25 | Token carries the marker audience | `test_tokens.py::test_the_access_token_carries_the_resource_and_the_marker`, `::test_the_marker_is_configurable` | green |
| 26 | The refresh token is not a Core-acceptable token | `test_tokens.py::test_the_refresh_token_is_not_a_core_acceptable_token`, `::test_the_refresh_token_audience_is_the_resource_alone`, `::test_the_refresh_token_carries_no_claim_snapshot` | green |
| 27 | Code replay rejected | `test_token.py::test_a_replayed_code_is_refused` | green |
| 28 | Claims copied verbatim | `test_tokens.py::test_the_copy_preserves_every_claim_under_its_own_name` | green |
| 29 | Roles source path absent | `test_tokens.py::test_an_absent_roles_path_refuses_issuance_loudly`, `::test_the_roles_path_refusal_is_an_operator_facing_one` | green |
| 30 | Roles present but empty | `test_tokens.py::test_an_empty_roles_value_is_copied_as_an_empty_array` | green |
| 31 | Roles source path absent at refresh | `test_tokens.py::test_a_roles_path_absent_from_the_fresh_token_refuses_the_refresh` | green |
| 32 | Flooding rate-limited | `test_limits.py::test_requests_past_the_per_source_limit_are_rejected`, `::test_the_global_limit_bounds_the_endpoint_overall` | green |
| 33 | Flow cap eviction | `test_limits.py::test_the_flow_cap_evicts_the_oldest_records` | green |
| 34 | Plain-language error page | `test_limits.py::test_an_error_page_is_plain_language`, `::test_the_error_page_shape_is_fixed` | green |
| 35 | Oversize request body refused | `test_limits.py::test_an_oversized_token_request_body_is_refused`, `::test_an_oversized_revocation_body_is_refused` | green |
| 36 | Signed in | `test_tokens.py::test_the_status_endpoint_reports_a_signed_in_user` | green |
| 37 | Not signed in | `test_tokens.py::test_the_status_endpoint_reports_a_user_who_is_not_signed_in` | green |
| **38** | **Signed in through a global credential** | **none** — see Defect 1 | **RED** |

### ADDED requirements

| # | Scenario | Proving row(s) | Verdict |
|---|---|---|---|
| 39 | Reserved name refused | `test_settings.py::test_reserved_toolset_name_refuses_startup`, `::test_reserved_names_are_refused_as_reserved_down_to_the_listed_set` | green |
| 40 | Name outside the routed charset refused | `test_settings.py::test_toolset_name_outside_the_routed_charset_refuses_startup` | green |
| 41 | Non-OAuth entry accepted | `test_settings.py::test_non_oauth_entry_is_accepted` | green |
| 42 | Removed mapping member refused at parse | `test_settings.py::test_the_removed_authentication_type_member_is_refused_at_parse` | green |
| 43 | Unset mapping serves dynamically | `test_settings.py::test_explicit_empty_mapping_is_accepted`; `test_discovery.py::test_a_guard_passing_name_is_served_in_dynamic_mode_with_no_core_call` | green |
| 44 | Inference without a single-entry restriction refused | `test_settings.py::test_inference_without_a_single_entry_restriction_refuses_startup`; `test_authorize.py::test_one_toolset_inference_with_two_toolsets_refuses_startup` | green |
| 45 | Silent refresh | `test_tokens.py::test_a_silent_refresh_returns_a_fresh_access_token`, `::test_a_refresh_re_reads_the_claims_from_the_provider` | green |
| 46 | Resource mismatch on refresh | `test_tokens.py::test_a_resource_mismatch_on_refresh_is_invalid_target` | green |
| 47 | Non-sliding refresh window | `test_tokens.py::test_a_rotated_refresh_token_keeps_the_original_absolute_expiry`, `::test_every_rotation_keeps_the_same_absolute_expiry` | green |
| 48 | Refresh TTL exceeds the declared session bound | `test_tokens.py::test_the_refresh_window_may_not_exceed_the_declared_session_bound`, `::test_the_refusal_names_both_values`; `test_settings.py::test_refresh_ttl_longer_than_the_declared_session_bound_refuses_startup` | green |
| 49 | Revoked refresh token | `test_tokens.py::test_a_revoked_refresh_token_is_refused`, `::test_revocation_survives_rotation_grace` | green |
| 50 | Expired refresh token | `test_tokens.py::test_an_expired_refresh_token_is_invalid_grant` | green |
| 51 | Claim change reflected within the access TTL | `test_tokens.py::test_a_refresh_re_reads_the_claims_from_the_provider` | green |
| 52 | Claims-read failure refuses the refresh | `test_tokens.py::test_an_unreachable_provider_audits_the_claims_read_token`, `::test_an_unusable_provider_answer_audits_the_claims_read_token`, `::test_a_provider_invalid_client_refusal_audits_the_claims_read_token`, `::test_an_unverifiable_fresh_token_audits_the_claims_read_token` | green |
| 53 | IdP session revocation ends the refresh capability | `test_tokens.py::test_a_provider_session_ended_refusal_audits_the_session_token` | green |
| 54 | Fresh-token subject mismatch refuses the refresh | `test_tokens.py::test_a_fresh_token_subject_mismatch_refuses_the_refresh` | green |
| 55 | Custody claim absent or undecryptable refuses the refresh | `test_tokens.py::test_the_custody_claim_absent_refuses_the_refresh`, `::test_a_tampered_custody_claim_refuses_the_refresh`, `::test_a_custody_claim_under_another_key_refuses_the_refresh`, `::test_a_custody_claim_sealed_for_another_subject_refuses_the_refresh`, `::test_an_expired_custody_envelope_refuses_the_refresh` | green |
| 56 | Reserved name refused at discovery | `test_discovery.py::test_a_reserved_name_is_refused_at_discovery` | green |
| 57 | Charset violation refused at the authorization endpoint | `test_authorize.py::test_a_charset_violating_resource_name_is_invalid_target` | green |
| 58 | Restriction-excluded name refused like an unknown one | `test_discovery.py::test_a_restriction_excluded_name_is_not_found`; `test_tokens.py::test_a_guard_refused_name_on_a_refresh_is_invalid_target`, `::test_each_guard_refusal_class_lands_on_its_committed_token`, `::test_the_guard_refusal_response_shape_matches_the_resource_mismatch`; `test_audit.py::test_a_restriction_excluded_name_is_recorded_with_its_own_reason` | green |
| 59 | A valid dynamic name resolves with no local configuration | `test_authorize.py::test_a_dynamic_name_passes_the_guard_with_no_restriction`; `test_discovery.py::test_a_guard_passing_name_is_served_in_dynamic_mode_with_no_core_call` | green |
| 60 | The carried credential ends with the refresh session | `test_tokens.py::test_a_revoked_refresh_token_is_refused` + `::test_an_expired_refresh_token_is_invalid_grant` (see note) | green (by inference) |
| 61 | The hand-off never crosses the client | `test_custody.py::test_the_code_payload_carries_no_identity_provider_credential`, `::test_the_pending_entry_is_consumed_at_the_code_grant` | green |
| 62 | The carrier is the refresh token only | `test_custody.py::test_the_custody_claim_appears_only_in_the_refresh_token` | green |
| 63 | Rotation carries the custody, in both directions | `test_tokens.py::test_the_replacement_carries_the_providers_latest_refresh_token`, `::test_a_refresh_with_no_new_provider_token_keeps_the_carried_one`, `::test_a_rotated_token_is_refused_after_its_grace_window` | green |
| **64** | **A grace-window presentation carries its own stale blob** | **none** — see Defect 2 | **RED** |
| 65 | Custody-key rotation is a hard cut | `test_custody.py::test_a_blob_under_a_superseded_key_refuses_with_the_custody_reason`; `test_tokens.py::test_a_custody_claim_under_another_key_refuses_the_refresh` | green |
| 66 | The plaintext is never logged or delivered; the ciphertext never logged | `test_custody.py::test_the_plaintext_never_reaches_a_client_response_or_a_log`; `test_tokens.py::test_the_custody_ciphertext_never_reaches_a_log_record` | green |
| 67 | No offline grant is ever requested | `test_federation.py::test_no_offline_access_is_requested_at_the_exchange` | green |
| 68 | Restart survives the custody, not the pending entries | `test_custody.py::test_a_restart_loses_pending_entries_but_not_the_custody` | green |

**Shape: 66 green / 2 RED (candidate defects) / 0 pending-live among the delta's own
scenarios.**

Scenario 60 note: the `stack()` fixture's default provider mock returns a valid fresh
token, so if the revoked/expired refresh had reached the provider it would have succeeded;
the asserted `invalid_grant` therefore proves the provider leg was never reached, and the
carried credential never presented. Adequately proven. Flagged as weaker than an explicit
"no outbound call" negative control, but not a defect.

### Pending live runs (NOT this pass's scope — task 5.3's live-only list)

These are task-level verifications, not delta-spec scenarios, and require the composed
stack plus a real harness/idP:

- Task 2.5(a)–(e) — the driven Keycloak provisioning checks (idempotent, live realm).
- Task 3.1 — P2 live run (mid-session role change, session revocation, restart).
- Task 3.2 — P3 live run (dynamic toolset add, refusal set, Core-down discovery).
- Task 3.3 — the harness token-store round-trip gate (Claude Code CIMD + Cursor DCR).

## Defects found

**Defect 1 — scenario 38 "Signed in through a global credential" has no proving row.**
The status requirement's new scenario asserts the `/status` response reports the global
status as signed-in and `signed_in: true` when only a GLOBAL credential exists. The only
two status-body tests vary `user_level_auth_status` and hardcode
`global_auth_status: "SIGNED_OUT"` (`test_tokens.py::status_response`, lines 1481–1517);
no test feeds `global_auth_status: "SIGNED_IN"` to `/status` and asserts the body. The
behavior is implemented (`ToolsetStatus.signed_in` returns true if either level is
`SIGNED_IN`, `gateway/core.py:194`; `gateway/status.py:78-82` returns both levels and the
boolean) and the *flow* short-circuit on a global credential is proven
(`test_federation.py::test_a_global_credential_short_circuits_a_non_oauth_toolset`), but
the **status-endpoint** variant of the scenario is unexercised. A test row is owed.

**Defect 2 — scenario 64 "A grace-window presentation carries its own stale blob" has no
proving row.** The scenario requires: within the rotation grace window, a pre-rotation
token is presented, the provider rotates per grant, so the token's own carried blob is
stale and the provider rejects it — landing in the `idp_session_ended` class. The
grace-window tests (`test_tokens.py::test_a_rotated_token_inside_its_grace_window_still_works`,
lines 1181–1196) present the original token inside the window and assert **success**
against the default provider mock (which accepts anything); no test drives a provider
that rejects a rotated-out blob, and no test asserts the `idp_session_ended` reason for
this path. The design's grace-window blob staleness is documented
(`gateway/token.py::_apply_rotation` docstring, lines 651–662) but not exercised. A test
row is owed.

Both are reported, not faked. Neither is a never-cut invariant; both are missing
conformance rows on scenarios the delta spec declares.

### Defects remedied

Both rows are now written and green; no code defect was found — the implementation on both
paths already matched the scenario text.

- **Defect 1 (scenario 38)** — `tests/test_tokens.py::test_the_status_endpoint_reports_a_signed_in_toolset_through_a_global_credential`.
  The status helper now varies both levels (`global_status` parameter, default
  `SIGNED_OUT`); the new row feeds `user_level_auth_status: "SIGNED_OUT"` with
  `global_auth_status: "SIGNED_IN"` and asserts `signed_in is True` with both raw levels
  returned unchanged — the either-level rule (`gateway/core.py:194`, `gateway/status.py:78-82`).
- **Defect 2 (scenario 64)** — `tests/test_tokens.py::test_a_grace_window_presentation_carries_its_own_stale_blob`.
  A rotating provider (mocked by presented token) refuses the superseded provider token with
  `invalid_grant`; the pre-rotation gateway token is presented inside its grace window and
  still carries its own stale blob, so the presentation fails at the provider and the audit
  trail carries `idp_session_ended` (`gateway/token.py::_fresh_claims`, the `session_ended`
  branch). Matches the scenario's THEN text.

Scenario 38 → green; scenario 64 → green. Conformance is now 68 green / 0 RED.

## 5.8 Mechanical threat-model sweep

Run against `docs/threat-model.md` as landed (task 4.1's edit pass). Command list and
results:

| Phrase-class | Pattern | Hits | Verdict |
|---|---|---|---|
| pre-v3 store wording | `per-session store\|retention store\|keyed retention` | 4 (lines 593, 1284, 1712, 1836) | all the **negated** new wording ("never a per-session store", "there is no per-session store to sweep"); list entries — not stale |
| frozen / role snapshot | `frozen\|role-snapshot\|snapshot-minted` | 1 (line 1773, M9) | "carrying no claim snapshot … the snapshot-free refresh token"; list entry — not stale |
| userinfo mechanism | `userinfo\|claim source\|claim-source\|claim reachab` | 0 | never landed — no hit |
| startup-only enforcement | `startup on every mapping entry\|checked once at startup\|at startup on every` | 3 (617, 1631, 1636) | each carries the new **configured-entry-only** split ("*configured* restriction entry"; "for configured entries"; T6-7's control 7 re-derived); list entries — not stale |
| OQ-1 as open | `stays open\|open question` | 1 (1861) | the single hit is the §14 "Open questions" heading; OQ-1 sits in the resolved record (line ~1888) with source `gateway/status.py:111-122`, dated 2026-11-01; T1-4's row/disposition carry the resolved statement — not stale |
| USER-only / GLOBAL-operator without use-vs-establish | `USER level only\|GLOBAL/app-level sign-in\|stays an operator action\|signs in at USER` | 2 (200, 602) | both carry the use-vs-establish form (RES-9; the EP5 row: "*establishes* at USER level only … GLOBAL-level *establishment* stays an operator action"); list entries — not stale |
| unqualified `aud = [resource, marker]` mint | `aud = \[` | 3 (64, 716, 1773) | each names the **access token's** mint as the subject and states the refresh token's no-marker `aud`; amended by the token-type-separation pin — not stale |
| consult-era discovery vocabulary | `consult\|service key\|service-key\|dial_core_api_key\|concurrency bound\|503\|OQ-I\|RES-24\|M22` | 1 (513) | line 513 is the deletion's own record ("No discovery leg exists here: the deleted consult means discovery makes no…") — not a stale leak |
| pre/intermediate counts | `55 threat\|19 residual\|15 assets\|20 grouped\|59 threat\|23 residual\|17 assets\|21 grouped\|65 threat\|24 residual\|18 assets\|23 grouped` | 2 (27, 29) | both are the new at-a-glance line ("17 assets", "62 threats … 23 residual"); no retired literal count appears anywhere — not stale |

**Result: zero stale hits.** Every hit in each phrase-class is a location the task-4.1
list names as edited (an intentionally retained or re-shaped statement) or the deletion's
own record; no out-of-list defect was found that required a stop.

## openspec validate

```
$ openspec validate --all --strict
✓ change/dynamic-toolsets-and-fresh-claims
✓ spec/mcp-signin
  ℹ [INFO] requirements[2]: Requirement text is very long (>500 characters)…
  ℹ [INFO] requirements[15]: Requirement text is very long (>500 characters)…
  ℹ [INFO] requirements[21]: Requirement text is very long (>500 characters)…
Totals: 2 passed, 0 failed (2 items)
```

**VALIDATION IS GREEN (--strict; 0 failures).** Note: **three** INFO advisories, not two.
All three are length advisories on the **main spec** (`openspec/specs/mcp-signin/spec.md`),
which is **untouched on this diff** (no `M` entry for it in `git status`):

- `requirements[2]` — "Client registration resolves pre-registered, CIMD, then gated DCR
  clients" (893 chars).
- `requirements[15]` — "The toolset mapping is safe to configure" (851 chars) — this is
  the requirement the delta **REMOVES**; when the change is synced/archived, its advisory
  goes with it, which is why a count of "two" was expected downstream.
- `requirements[21]` — "Inbound tokens are verified with pinned algorithm and key
  selection" (928 chars).

All three are pre-existing and introduced by no part of this change.

## Summary

| Gate | Result |
|---|---|
| 5.1 static (ruff ×2, mypy, bandit, pytest) | **green** |
| 5.1 pip-audit | **blocking finding, remedied** (certifi bump; image already fixed) |
| 5.1 Trivy image | **0 CRITICAL; 44 HIGH base-image OS, 0 fixable — accepted residual** |
| 5.2 compose boot | **green** (both services healthy; front-door, router, and joined-network probes pass) |
| 5.3 conformance | **66 green / 2 RED** — Defects 1 and 2 (unproven scenarios 38, 64) |
| 5.8 threat-model sweep | **zero stale hits** |
| openspec validate --strict | **green** (3 INFO advisories, all pre-existing, main spec unmodified) |

**Blocking for the change's completion:** the two missing conformance rows (Defects 1,
2). The pip-audit finding is remedied; the Trivy base-image HIGHs are an accepted,
unremediable-upstream residual. Live runs (2.5, 3.1–3.3) remain pending and are outside
this pass.
