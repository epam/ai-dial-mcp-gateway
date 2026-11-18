# Task 8.3 — the conformance-row walk (all 92 scenarios of the delta spec)

Change: `as-security-hardening` (C2.5). Branch `worktree-c2p5-as-security-hardening`,
HEAD `c1806582d215a6e26ac001adf108b98e25566408`.

Scope: every scenario of the delta spec
(`openspec/changes/as-security-hardening/specs/mcp-signin/spec.md`) — **92 scenarios**
(1 + 3 + 3 + 4 + 11 + 1 + 7 + 4 + 5 + 6 + 3 + 1 + 6 + 5 + 6 + 5 + 7 + 4 — the ADDED
requirements' 11 scenarios plus the MODIFIED requirements' 81) — walked against the test
that covers it.

Method: the spec's scenarios were enumerated (`grep '^#### Scenario:'` → 92 headers); the
full test inventory was collected (`pytest --collect-only -q` → 676 test ids); each
scenario was mapped to its covering test(s) by reading the test bodies and their
docstrings, which name the scenario they implement. Every row below names a real test
id; the full suite ran green in task 8.2 (**675 passed, 1 skipped**, the 1 skip being the
standing unrelated one), so **every named test passes**. No row is uncovered — **no
FINDING from this walk.**

Legend: the "→" separates the scenario from its covering test(s); test ids are
`file::name`, file paths relative to the repo root.

## MODIFIED: Discovery documents describe one flat authorization server

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 1 | Flat AS metadata fetch | tests/test_discovery.py::test_flat_metadata_is_served_at_the_host_root; ::test_flat_metadata_names_the_public_origin_as_its_only_issuer; ::test_flat_metadata_endpoints_are_shared_by_every_toolset | PASS |
| 2 | Per-toolset protected-resource fetch | tests/test_discovery.py::test_protected_resource_document_names_the_toolset_resource; ::test_protected_resource_document_carries_no_authentication_kind; ::test_protected_resource_document_echoes_the_upstream_scopes_verbatim | PASS |
| 3 | Unmapped toolset | tests/test_discovery.py::test_a_restriction_excluded_name_is_not_found | PASS |
| 4 | Dynamic toolset served without local configuration | tests/test_discovery.py::test_a_guard_passing_name_is_served_in_dynamic_mode_with_no_core_call | PASS |
| 5 | Guard-failing name refused at discovery | tests/test_discovery.py::test_a_reserved_name_is_refused_at_discovery[token]; ::[authorize]; ::test_a_charset_violating_name_is_refused_at_discovery; tests/test_audit.py::test_a_discovery_guard_refusal_is_recorded | PASS |
| 6 | The AS metadata advertises iss-parameter support | tests/test_discovery.py::test_flat_metadata_advertises_iss_parameter_support | PASS |

## MODIFIED: Client registration resolves pre-registered, CIMD, then gated DCR clients

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 7 | CIMD registration without a registration call | tests/test_cimd.py::test_a_document_resolves_a_client; ::test_a_cached_document_is_not_fetched_twice | PASS |
| 8 | CIMD fetch refused | tests/test_cimd.py::test_an_http_client_id_is_refused; ::test_a_non_allowlisted_origin_is_refused; ::test_a_redirect_is_refused; ::test_a_private_loopback_or_link_local_resolution_is_refused[...] | PASS |
| 9 | Unregistered redirect URI | tests/test_authorize.py::test_an_unregistered_redirect_uri_is_refused_directly; tests/test_store.py::test_an_authorization_request_validates_the_redirect_uri_against_the_stored_record | PASS |
| 10 | DCR off by default | tests/test_store.py::test_registration_is_disabled_by_default; tests/test_discovery.py::test_flat_metadata_advertises_no_registration_endpoint_while_dcr_is_off | PASS |
| 11 | Registration response issued-at is an epoch number | tests/test_store.py::test_the_registration_response_answers_an_epoch_number_for_the_stored_instant | PASS |
| 12 | Re-registration answers the stored instant | tests/test_store.py::test_re_registering_an_existing_client_id_answers_its_stored_instant_as_a_number; ::test_the_idempotent_branch_answers_the_stored_instant_as_a_number | PASS |
| 13 | An http collector URI is refused at DCR registration | tests/test_store.py::test_a_non_loopback_http_redirect_uri_is_refused_at_dcr_registration | PASS |
| 14 | An http redirect URI in a CIMD document is refused | tests/test_cimd.py::test_a_non_loopback_http_redirect_uri_refuses_the_whole_document | PASS |
| 15 | A pre-registered http redirect URI refuses startup | tests/test_settings.py::test_a_pre_registered_http_redirect_uri_refuses_startup_naming_the_entry | PASS |
| 16 | Loopback http remains admitted | tests/test_cimd.py::test_a_loopback_http_redirect_uri_is_admitted_in_a_document; tests/test_store.py::test_a_loopback_http_redirect_uri_is_admitted_at_dcr_registration; tests/test_settings.py::test_pre_registered_loopback_and_https_redirect_uris_are_admitted | PASS |

## MODIFIED: DCR registration records are durable across restarts

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 17 | Registration persists across restart | tests/test_store.py::test_a_registration_survives_a_restart | PASS |
| 18 | Registration persisted before the response | tests/test_store.py::test_a_registration_is_persisted_before_the_response | PASS |
| 19 | Store dormant while DCR is disabled, restored on re-enable | tests/test_store.py::test_a_registration_is_inert_while_dcr_is_disabled; ::test_re_enabling_restores_a_dormant_registration | PASS |
| 20 | Corrupt store refuses startup | tests/test_store.py::test_a_corrupt_store_refuses_startup_naming_the_path; ::test_a_store_holding_something_other_than_an_object_refuses_startup; ::test_recovery_from_a_corrupt_store_is_rename_aside_and_restart | PASS |
| 21 | Lost store self-heals via re-registration | tests/test_store.py::test_a_lost_store_self_heals_through_re_registration | PASS |
| 22 | Registration cap reached | tests/test_store.py::test_reaching_the_cap_refuses_new_registrations; ::test_the_cap_leaves_existing_registrations_untouched | PASS |
| 23 | A stored non-loopback http redirect URI refuses startup at load | tests/test_store.py::test_a_stored_non_loopback_http_redirect_uri_refuses_startup_at_load | PASS |

## MODIFIED: Authorization requests require a valid resource and allocate protected flow state

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 24 | Missing resource | tests/test_authorize.py::test_a_missing_resource_is_invalid_target; ::test_inference_off_by_default_refuses_a_missing_resource | PASS |
| 25 | Unknown resource | tests/test_authorize.py::test_an_unknown_resource_is_invalid_target | PASS |
| 26 | Valid request allocates a flow | tests/test_authorize.py::test_a_valid_request_redirects_to_the_identity_provider; ::test_the_flow_id_is_a_128_bit_random_value; ::test_a_valid_request_allocates_exactly_one_live_flow | PASS |
| 27 | App resource accepted | tests/test_federation.py::test_an_app_resource_request_allocates_a_flow_of_the_app_kind | PASS |
| 28 | One-toolset inference | tests/test_authorize.py::test_one_toolset_inference_accepts_a_request_with_no_resource | PASS |
| 29 | Guard-failing resource refused | tests/test_authorize.py::test_a_charset_violating_resource_name_is_invalid_target; ::test_a_reserved_resource_name_is_invalid_target[authorize]; ::[token]; tests/test_audit.py (resource-refusal record via ::test_a_redirect_uri_refusal_names_the_client_the_uri_and_the_resource) | PASS |
| 30 | Absent state tolerated with nothing echoed | tests/test_authorize.py::test_an_absent_state_is_tolerated; tests/test_federation.py::test_a_flow_started_without_state_completes_with_none_echoed | PASS |
| 31 | State echoed unchanged | tests/test_authorize.py::test_a_carried_state_is_stored_at_allocation_and_echoed_unchanged | PASS |
| 32 | Oversized state refused | tests/test_authorize.py::test_an_oversized_state_is_refused_before_a_record_exists | PASS |

## MODIFIED: The federation flow establishes the upstream credential through Core

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 33 | DIAL authorization denied | tests/test_federation.py::test_a_non_admin_user_is_refused_where_the_data_path_refuses_them; ::test_a_refused_settings_read_fails_before_any_upstream_round_trip | PASS |
| 34 | A token Core cannot validate is a trust fault, not an access denial | tests/test_federation.py::test_a_trust_fault_listing_answer_is_not_an_access_denial; ::test_the_trust_fault_page_names_no_user_identifying_value; ::test_a_trust_fault_refusal_consumes_the_flow | PASS |
| 35 | A public toolset serves every user the data path serves | tests/test_federation.py::test_a_non_admin_user_is_admitted_to_a_public_toolset; ::test_the_admin_axis_agrees_with_the_data_path_both_ways | PASS |
| 36 | Client scope never reaches the identity provider | tests/test_federation.py::test_the_redirect_requests_only_the_clients_default_scopes; tests/test_authorize.py::test_the_redirect_requests_only_the_clients_own_scopes | PASS |
| 37 | Upstream consent completes | tests/test_federation.py::test_the_signin_body_is_the_documented_one | PASS |
| 38 | Flow record destroyed on first use | tests/test_federation.py::test_the_upstream_state_round_trips_the_flow_id (record consumed); ::test_a_replayed_upstream_callback_is_refused | PASS |
| 39 | Guessed flow id injects nothing | tests/test_federation.py::test_an_unknown_flow_id_at_the_upstream_callback_injects_nothing | PASS |
| 40 | Non-OAuth toolset refused on the impossible branch | tests/test_federation.py::test_a_non_oauth_toolset_with_no_credential_is_refused_on_the_impossible_branch | PASS |
| 41 | Already signed in short-circuits the consent | tests/test_federation.py::test_a_user_level_credential_short_circuits_with_no_upstream_leg; ::test_a_signed_in_user_short_circuits_to_code_issuance | PASS |
| 42 | A global credential serves every user without consent | tests/test_federation.py::test_a_global_credential_short_circuits_a_non_oauth_toolset | PASS |
| 43 | The signed-in check fails closed | tests/test_federation.py::test_an_unreadable_or_failed_status_does_not_short_circuit[...]; ::test_an_app_level_only_status_does_not_short_circuit | PASS |
| 44 | Unknown toolset refused at the flow's settings read | tests/test_federation.py::test_an_unknown_toolset_is_refused_at_the_settings_read; ::test_an_unknown_toolset_refusal_leaves_no_flow_state | PASS |
| 45 | The provider's session refresh token is carried past the flow for the refresh window | tests/test_federation.py::test_the_exchange_captures_the_provider_refresh_token; tests/test_custody.py::test_the_custody_claim_appears_only_in_the_refresh_token | PASS |
| 46 | Provider issues no refresh token | tests/test_federation.py::test_an_exchange_with_no_refresh_token_refuses_at_sign_in | PASS |
| 47 | Provider refresh token over the custody size bound refused at sign-in | tests/test_federation.py::test_a_refresh_token_over_the_custody_bound_refuses_at_sign_in | PASS |
| 48 | First attribution on the stored-credential short-circuit renders the decision page | tests/test_federation.py::test_first_attribution_on_the_short_circuit_renders_the_decision_page | PASS |
| 49 | An approved client passes the short-circuit untouched | tests/test_federation.py::test_a_repeat_sign_in_for_an_approved_client_is_silent | PASS |
| 50 | First attribution on the consent branch replaces the display interstitial once | tests/test_federation.py::test_first_attribution_on_the_consent_branch_replaces_the_interstitial_once; ::test_the_consent_branch_stores_the_continuation_on_the_record | PASS |

## MODIFIED: App resources complete the sign-in flow credential-free

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 51 | App sign-in completes with no consent and no credential call | tests/test_federation.py::test_an_app_sign_in_completes_with_no_consent_and_no_credential_call | PASS |
| 52 | Unknown app refused at the flow's app read | tests/test_federation.py::test_an_unknown_app_is_refused_at_the_flow_read; ::test_an_unknown_app_refusal_leaves_no_flow_state | PASS |
| 53 | App authorization denied | tests/test_federation.py::test_a_refused_app_read_fails_with_the_no_access_page; ::test_a_refused_app_read_leaves_no_flow_state | PASS |
| 54 | Unreachable Core is a deployment fault, never an existence answer | tests/test_federation.py::test_an_unreachable_app_read_is_a_deployment_fault_never_an_existence_answer | PASS |
| 55 | Repeat app sign-in is silent | tests/test_federation.py::test_an_approval_does_not_render_a_page_for_a_second_resource (approved client's app sign-in mints, no page) | PASS |
| 56 | First attribution on the app kind's zero-page short-circuit renders the decision page | tests/test_federation.py::test_first_attribution_on_the_app_kind_renders_the_page_where_nothing_rendered | PASS |

## MODIFIED: HTML responses carry the web-hardening header family

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 57 | The interstitial carries the hardening headers | tests/test_federation.py::test_the_interstitial_carries_the_web_hardening_headers | PASS |
| 58 | An error or flow page carries them | tests/test_limits.py::test_every_error_page_carries_the_web_hardening_headers | PASS |
| 59 | The decision page carries the family and does not auto-continue | tests/test_federation.py::test_the_decision_page_carries_the_family_and_does_not_auto_continue; ::test_the_decision_page_escapes_a_hostile_client_name | PASS |

## MODIFIED: Issued tokens are gateway-signed and audience-marked

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 60 | Code exchange issues tokens | tests/test_token.py::test_a_valid_code_exchanges_for_an_access_token; ::test_the_access_token_is_signed_by_the_gateway_and_names_the_subject | PASS |
| 61 | Token carries the marker audience | tests/test_tokens.py::test_the_access_token_carries_the_resource_and_the_marker; ::test_the_marker_is_configurable | PASS |
| 62 | An app-resource token carries the app resource and the marker | tests/test_tokens.py::test_an_app_kind_code_grant_carries_the_app_resource_and_the_marker | PASS |
| 63 | The refresh token is not a Core-acceptable token | tests/test_tokens.py::test_the_refresh_token_is_not_a_core_acceptable_token; ::test_the_refresh_token_audience_is_the_resource_alone | PASS |
| 64 | Code replay rejected | tests/test_token.py::test_a_replayed_code_is_refused | PASS |
| 65 | A replayed code kills the refresh token it bought | tests/test_tokens.py::test_a_replayed_code_revokes_the_refresh_token_it_first_bought | PASS |

## MODIFIED: Claim copy preserves deployment claim paths

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 66 | Claims copied verbatim | tests/test_tokens.py::test_the_copy_preserves_every_claim_under_its_own_name; ::test_the_roles_overlay_re_emits_roles_at_the_configured_name | PASS |
| 67 | Roles source path absent | tests/test_tokens.py::test_an_absent_roles_path_refuses_issuance_loudly; ::test_the_roles_path_refusal_is_an_operator_facing_one | PASS |
| 68 | Roles present but empty | tests/test_tokens.py::test_an_empty_roles_value_is_copied_as_an_empty_array | PASS |
| 69 | Roles source path absent at refresh | tests/test_tokens.py::test_a_roles_path_absent_from_the_fresh_token_refuses_the_refresh | PASS |
| 70 | The provider's `auth_time` is never copied | tests/test_tokens.py::test_the_providers_auth_time_is_never_copied | PASS |

## MODIFIED: Public endpoints are bounded against abuse

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 71 | Flooding rate-limited | tests/test_limits.py::test_requests_past_the_per_source_limit_are_rejected; ::test_a_rejected_request_allocates_no_flow; ::test_the_global_limit_bounds_the_endpoint_overall | PASS |
| 72 | Over-limit discovery requests are refused without a record | tests/test_limits.py::test_a_burst_of_discovery_refusals_is_limited_and_writes_nothing; tests/test_discovery.py::test_a_burst_of_app_discovery_refusals_is_limited_and_writes_nothing | PASS |
| 73 | Flow cap eviction | tests/test_limits.py::test_the_flow_cap_evicts_the_oldest_records; ::test_an_evicted_flow_is_gone_from_the_store | PASS |
| 74 | Plain-language error page | tests/test_limits.py::test_an_error_page_is_plain_language; ::test_the_error_page_shape_is_fixed | PASS |
| 75 | Oversize request body refused | tests/test_limits.py::test_an_oversized_token_request_body_is_refused; ::test_an_oversized_revocation_body_is_refused; tests/test_store.py::test_an_oversized_registration_body_is_refused | PASS |
| 76 | No CORS headers on any AS-surface response | tests/test_app.py::test_no_as_surface_endpoint_serves_a_cors_header; ::test_an_options_preflight_at_the_token_endpoint_is_the_frameworks_405; tests/test_federation.py::test_the_consent_route_answers_no_cors_headers | PASS |

## MODIFIED: Flows are audited through their lifecycle

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 77 | A completed flow's chain is attributable end to end | tests/test_audit.py::test_the_flow_emits_its_whole_story_with_identifiers | PASS |
| 78 | A refused or failed leg is recorded with its outcome | tests/test_audit.py::test_a_refused_credential_call_is_recorded_as_a_refusal; ::test_a_flow_refusal_is_recorded_with_this_gateways_own_text | PASS |
| 79 | The kind-driven short-circuit is recorded | tests/test_federation.py::test_the_app_kind_approve_path_keeps_the_short_circuit_record; ::test_an_app_sign_in_completes_with_no_consent_and_no_credential_call | PASS |
| 80 | A credential-shaped value never reaches a flow record | tests/test_audit.py::test_no_credential_material_reaches_any_record; ::test_no_credential_material_reaches_a_refusal_record; ::test_the_verifier_is_never_written | PASS |
| 81 | The attribution events are recorded in sequence | tests/test_federation.py::test_approve_records_the_attribution_and_mints_on_the_short_circuit (asserts required < approved < code_issued) | PASS |

## ADDED: The consent/attribution checkpoint gates every mint on first attribution

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 82 | First attribution renders the decision page and no mint runs | tests/test_federation.py::test_first_attribution_on_the_short_circuit_renders_the_decision_page | PASS |
| 83 | The decision page names the client, the resource, and the redirect destination | tests/test_federation.py::test_the_decision_page_names_the_client_resource_and_redirect | PASS |
| 84 | Approve records the attribution and continues the flow | tests/test_federation.py::test_approve_records_the_attribution_and_mints_on_the_short_circuit | PASS |
| 85 | Deny consumes the flow with no code issued | tests/test_federation.py::test_deny_consumes_the_flow_with_no_code_issued | PASS |
| 86 | A replayed or foreign POST advances nothing | tests/test_federation.py::test_a_replayed_approve_advances_nothing; ::test_a_foreign_post_against_no_live_flow_lands_on_the_expired_page | PASS |
| 87 | The action carries only the flow id and the decision | tests/test_federation.py::test_the_action_carries_only_the_flow_id_and_the_decision; ::test_a_malformed_consent_body_is_refused | PASS |
| 88 | No operator bypass for a pre-registered client | tests/test_federation.py::test_no_operator_bypass_for_a_pre_registered_client | PASS |

## ADDED: The approved-client registry is keyed per subject and client and fails safe on loss

| # | Scenario | Covering test(s) | Pass/Fail |
|---|---|---|---|
| 89 | An approved attribution is consulted and passes through | tests/test_limits.py::test_an_approved_pair_is_consulted_and_passes; tests/test_federation.py::test_a_repeat_sign_in_for_an_approved_client_is_silent | PASS |
| 90 | The approval is the client's, not one resource's | tests/test_limits.py::test_an_approval_covers_the_client_across_resources; tests/test_federation.py::test_an_approval_covers_the_client_across_resources; ::test_an_approval_does_not_render_a_page_for_a_second_resource | PASS |
| 91 | Registry loss re-prompts, never bypasses | tests/test_limits.py::test_the_registry_cap_evicts_the_oldest_approval; tests/test_federation.py::test_registry_loss_re_prompts_never_bypasses | PASS |
| 92 | The registry has one write path | tests/test_federation.py::test_a_replayed_approve_advances_nothing; ::test_a_foreign_post_against_no_live_flow_lands_on_the_expired_page; tests/test_limits.py::test_an_empty_subject_is_never_recorded | PASS |

## Walk verdict

**All 92 scenarios are covered by a real, passing test.** 92 of 92 rows green; **no row
is uncovered, so this walk raises no FINDING.** (The suite's 675 passed / 1 skipped in
task 8.2 is the pass basis; the 1 skip is the standing unrelated one, not any row here.)

Notes for honesty:

- Rows 29, 74, and 87 name two/three tests because the scenario's THEN spans a response
  shape and an audit record, or a shape and a malformed-input refusal; each cited test is
  real and passing.
- Row 38 cites `test_the_upstream_state_round_trips_the_flow_id`, which asserts the record
  is consumed by the callback (the "destroyed on first use" clause) alongside the replay
  refusal.
- Rows 55 and 89 look similar: 55 is the app kind's silent repeat (mapped to the
  approved-client app sign-in that mints with no page); 89 is the registry-check contract
  proper (both the unit-level `is_approved` hit and the flow-level zero-click sign-in).
- The mapping is by reading test bodies and their docstrings (which name the scenario they
  implement); the spec carries no machine-readable scenario tags, so the walk is a
  hand-verified reading, recorded here row by row for the reviewers to re-check.
