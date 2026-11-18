# Task 7.3 — the conformance map (all 50 scenarios of the delta spec)

Change: `one-pod-and-keysets` (C3). Branch `worktree-c3-one-pod-and-keysets`, HEAD
`42f4f02`, changed scope is the diff `3383173..42f4f02` against `origin/master` `846017d`.

Scope: every scenario of the delta spec
(`openspec/changes/one-pod-and-keysets/specs/mcp-signin/spec.md`) — **50 scenarios**
(8 + 10 + 3 ADDED = 21; 13 + 7 + 9 MODIFIED = 29) — mapped to its verification home: a
unit test (`tests/file.py::name`), a probe (`scripts/…`), or an evidence record
(`docs/evidence/c3/…`, section).

Method: the spec's scenario headers were enumerated (`grep '^#### Scenario:'` → 50); the
test inventory was read (`grep '^def test_' tests/*.py`); each scenario was mapped to the
test(s) whose body and docstring name it, or to the probe/evidence run recorded for it.
Every named test exists (each was resolved against the tree); the full suite ran green in
task 7.1 (**708 passed, 1 skipped**, the standing unrelated skip), and again after this
map's four flagged rows gained their tests (**712 passed, 1 skipped**). Several scenarios are
**evidence-gated by design** (the pod-contract statements, the scanner row, the DevOps
review, the drill), per tasks.md's own note — those map to a record, not a test.

Legend: **U** = unit test, **P** = probe script, **E** = evidence record. Test ids are
`tests/file.py::name`.

## ADDED: The deployment unit is a single pod defined by a versioned contract (8)

| # | Scenario | Home | Evidence |
|---|---|---|---|
| 1 | The probe battery passes against the pod-shaped stack | P + E | `scripts/probe_routing.py` (11/11 green, re-run 2026-11-09 against the current stack); `docs/evidence/c3/pod-shape-probes.md` §"Task 4.3"; boundary assertion (8090 reachable, 8091 unreachable) re-confirmed on the current stack |
| 2 | The DCR store survives a pod restart on its named mount | P + E | `scripts/probe_dcr.py --expect enabled --register` then `--authorize-expect accepted` after a unit restart; `docs/evidence/c3/pod-shape-probes.md` §"Task 4.4" |
| 3 | No secret-class value in the image | E | `docs/evidence/c3/pod-shape-probes.md` §"Task 4.2" (compat spellings run-time only); `docs/evidence/c3/image-alpine-build.md` §"Task 3.2" (no baked secret; Trivy image secret scan clean — all rows `-`) |
| 4 | The image clears the scanner gate | E | `docs/evidence/c3/image-alpine-build.md` §"Task 3.3" (Alpine OS-package row 0 HIGH/CRITICAL; 44-HIGH Debian debt cleared); re-confirmed fresh: `trivy image --severity HIGH,CRITICAL` → 0 on `dial-mcp-gateway:c3` |
| 5 | The single-replica assumption is stated | E | `docs/pod-contract.md` §8.3 "Single replica" (in-memory flow state + registry; not horizontally scalable; fail-safe loss semantics) |
| 6 | The security context's controls are stated as the assembly's requirements | E | `docs/pod-contract.md` §5 "Security context" (runAsNonRoot + uid/gid 10001, fsGroup 10001, no privilege escalation, capabilities dropped, read-only root + emptyDir, runtime-default seccomp) |
| 7 | The store's storage class and export story are stated | E | `docs/pod-contract.md` §4.2 "The store's governance and storage class" (cloud-backed class by properties, deployment-owned export, wrapped-CEK future resident) |
| 8 | DevOps review passes with explicit confirmation | E | **PENDING — task 7.6** (the review record does not yet exist; it closes with explicit confirmation, not silence) |

## ADDED: The signing key is a keyset with per-entry sources and active and retained roles (10)

| # | Scenario | Home | Evidence |
|---|---|---|---|
| 9 | Overlap rotation keeps every outstanding token working | E | `docs/evidence/c3/rotation-drill.md` §"Task 6.3" (S0–S3: old tokens drain onto the new kid; both kids in JWKS throughout) |
| 10 | A new key is pre-published before it signs | E | `docs/evidence/c3/rotation-drill.md` §"Task 6.3" (S1 pre-publish; S1b cache wait observed 615 s ≥ 600 s; S2 pre-promotion acceptance) |
| 11 | Removing a retained entry is the immediate cut | E + U | `docs/evidence/c3/rotation-drill.md` §"Task 6.3" S4; `tests/test_keyset.py::test_a_retained_key_token_verifies_and_a_removed_kid_refuses` |
| 12 | A kms-sourced entry refuses startup naming the gap | U | `tests/test_keyset.py::test_a_kms_sourced_signing_entry_refuses_startup_naming_the_gap` |
| 13 | Zero or multiple active entries refuse startup | U | `tests/test_keyset.py::test_a_zero_active_signing_keyset_refuses_startup`; `::test_a_multi_active_signing_keyset_refuses_startup` |
| 14 | A file-sourced entry loads from its configured path | U | `tests/test_keyset.py::test_a_file_sourced_signing_entry_loads_and_refuses_a_missing_path` |
| 15 | A source-heterogeneous keyset is valid | U | `tests/test_keyset.py::test_a_source_heterogeneous_keyset_is_valid` |
| 16 | Duplicate derived kids refuse startup | U | `tests/test_keyset.py::test_two_entries_deriving_the_same_kid_refuse_startup` |
| 17 | The single-key spelling remains the no-rotation shape | U | `tests/test_keyset.py::test_the_singular_spelling_constructs_the_same_one_active_keyset`; `::test_both_signing_spellings_configured_refuse_startup` |
| 18 | A blank singular spelling is unset on the composition path | U | `tests/test_keyset.py::test_a_blank_singular_signing_key_beside_a_keyset_is_accepted`; `::test_a_whitespace_singular_signing_key_beside_a_keyset_is_accepted`; `::test_a_blank_structured_keyset_beside_a_real_singular_is_accepted` |

## ADDED: A live rotation drill gates the keyset semantics' completion (3)

| # | Scenario | Home | Evidence |
|---|---|---|---|
| 19 | The drill's rotation window passes with evidence | E | `docs/evidence/c3/rotation-drill.md` §"Task 6.3" (all five signing verdicts true; cache wait observed) |
| 20 | The negative control runs first and fails | E | `docs/evidence/c3/rotation-drill.md` §"Task 6.2" (`control_failed_as_required: true`) |
| 21 | The emergency cut is rehearsed mid-window | E | `docs/evidence/c3/rotation-drill.md` §"Task 6.3" S4 (signing cut) and §"Task 6.4" C2 (custody cut, `custody_decrypt_failed`) |

## MODIFIED: The IdP session refresh token is carried encrypted (13)

| # | Scenario | Home | Evidence |
|---|---|---|---|
| 22 | The carried credential ends with the refresh session | U | `tests/test_tokens.py::test_an_expired_refresh_token_is_invalid_grant`; `::test_a_revoked_refresh_token_is_refused` (revocation by id, claim untouched) |
| 23 | The hand-off never crosses the client | U | `tests/test_custody.py::test_the_code_payload_carries_no_identity_provider_credential`; `::test_the_pending_entry_is_created_consumed_and_dropped` |
| 24 | The carrier is the refresh token only | U | `tests/test_custody.py::test_the_custody_claim_appears_only_in_the_refresh_token` |
| 25 | Rotation carries the custody, in both directions | U | `tests/test_tokens.py::test_the_replacement_carries_the_providers_latest_refresh_token`; `tests/test_keyset.py::test_custody_seals_under_the_active_key_and_opens_by_the_envelope_key_id` |
| 26 | A grace-window presentation carries its own stale blob | U | `tests/test_tokens.py::test_a_grace_window_presentation_carries_its_own_stale_blob` |
| 27 | Custody-key rotation is a hard cut | U + E | `tests/test_tokens.py::test_a_custody_claim_under_another_key_refuses_the_refresh`; `tests/test_keyset.py::test_a_removed_retained_key_id_refuses_before_any_decrypt`; `docs/evidence/c3/rotation-drill.md` §"Task 6.4" C2 |
| 28 | A retained envelope decrypts and the active key seals | U + E | `tests/test_keyset.py::test_custody_seals_under_the_active_key_and_opens_by_the_envelope_key_id`; `docs/evidence/c3/rotation-drill.md` §"Task 6.4" C1 |
| 29 | A kms-sourced custody entry refuses startup naming the gap | U | `tests/test_keyset.py::test_a_kms_sourced_custody_entry_refuses_startup_naming_the_gap` |
| 30 | The flat single-key spelling remains the compat shape | U | `tests/test_keyset.py::test_the_flat_custody_spelling_is_one_active_env_entry`; `::test_the_flat_spelling_behaves_as_its_structured_one_active_equivalent`; `::test_a_mixed_custody_document_refuses_startup` |
| 31 | A custody keyset with no active entry refuses startup | U | `tests/test_keyset.py::test_a_structured_custody_keyset_with_no_active_entry_refuses_startup` |
| 32 | The plaintext is never logged or delivered; the ciphertext never logged | U | `tests/test_custody.py::test_the_plaintext_never_reaches_a_client_response_or_a_log`; `tests/test_tokens.py::test_the_custody_ciphertext_never_reaches_a_log_record` |
| 33 | No offline grant is ever requested | U | `tests/test_federation.py::test_no_offline_access_is_requested_at_the_exchange` |
| 34 | Restart survives the custody, not the pending entries | U | `tests/test_custody.py::test_a_restart_loses_pending_entries_but_not_the_custody`; `::test_an_unredeemed_code_drops_its_pending_entry`; `::test_the_pending_entry_is_consumed_at_the_code_grant` |

## MODIFIED: Inbound tokens are verified with pinned algorithm and key selection (7)

| # | Scenario | Home | Evidence |
|---|---|---|---|
| 35 | Algorithm confusion refused | U | `tests/test_idp.py::test_an_alg_none_token_is_refused_by_the_pinned_algorithm` — a hand-assembled `alg: none` token (PyJWT is not asked to mint it; the header a hostile issuer sends is built directly) is refused at the exchange by the pinned algorithm, the header's choice never consulted. **RESOLVED (was GAP)** |
| 36 | Embedded key refused | U | `tests/test_idp.py::test_an_embedded_jwk_in_the_header_is_ignored_and_the_token_refused` — a token signed by a key foreign to the provider's published set and carrying that key as a header `jwk` is refused: the embedded material is never consulted, the signature checked against the published key only. **RESOLVED (was GAP)** |
| 37 | `kid` outside the provider's key set refused | U | `tests/test_idp.py::test_a_provider_token_kid_absent_from_the_published_set_is_refused` — a token whose `kid` names no key of the published set is refused by the lookup itself (the refusal reads "no signing key matching"), the literal `_signing_key`-lookup branch, distinct from a signature mismatch. **RESOLVED (was WEAK)** |
| 38 | Key set resolved from the leg's one endpoint source | U | `tests/test_idp.py::test_the_discovered_endpoints_serve_all_four_legs_from_one_fetch` (discovery); `::test_the_full_trio_serves_all_four_legs_and_skips_discovery_entirely` (direct) |
| 39 | A token from another journey's issuer refused | U | `tests/test_idp.py::test_a_token_from_another_journeys_issuer_is_refused_at_sign_in`; `::test_a_token_from_another_journeys_issuer_is_refused_at_refresh`; `::test_the_varying_issuer_refusal_holds_in_direct_mode` |
| 40 | A retained-key token verifies through the drain window | U | `tests/test_keyset.py::test_a_retained_key_token_verifies_and_a_removed_kid_refuses` (first half) |
| 41 | An unknown `kid` on an own token is refused | U | `tests/test_keyset.py::test_a_retained_key_token_verifies_and_a_removed_kid_refuses` (second half: `pytest.raises(match="not issued by this gateway")`); `tests/test_token.py::test_a_code_signed_by_another_key_is_refused` |

## MODIFIED: The IdP client is confidential; the PKCE toggle governs the challenge only (9)

| # | Scenario | Home | Evidence |
|---|---|---|---|
| 42 | A missing client secret refuses startup in either toggle position | U | `tests/test_settings.py::test_a_missing_client_secret_refuses_startup_in_either_toggle_position`; `::test_a_blank_client_secret_counts_as_unset_and_refuses_startup`; `::test_the_missing_secret_refusal_is_unchanged_under_the_file_spellings_absence` |
| 43 | The challenge-off mode runs as a secret-authenticated client without PKCE | U | `tests/test_idp.py::test_the_challenge_off_redirect_carries_no_challenge_and_the_token_requests_authenticate_with_the_secret` |
| 44 | The default mode presents the client secret under the challenge | U | `tests/test_idp.py::test_the_default_mode_presents_the_client_secret_under_the_challenge` |
| 45 | The client-facing surface still requires PKCE | U | `tests/test_idp.py::test_a_harness_authorization_request_without_pkce_is_still_refused_in_the_challenge_off_mode` |
| 46 | The client secret never reaches an output | U | `tests/test_idp.py::test_the_client_secret_appears_only_in_the_token_request_bodies` (sweeps logs, pages, responses in both toggle positions) |
| 47 | The file-delivered secret authenticates exactly as the environment-delivered one | U | `tests/test_settings.py::test_the_file_spelling_delivers_the_secret_equivalently` |
| 48 | Both delivery spellings configured refuses startup naming both | U | `tests/test_settings.py::test_both_secret_spellings_configured_refuse_startup_naming_both` |
| 49 | An unreadable secret file refuses startup naming the path | U | `tests/test_settings.py::test_an_unreadable_secret_file_refuses_startup_naming_the_path`; `::test_a_blank_secret_file_refuses_startup_naming_the_path` |
| 50 | A blank file-path spelling is unset on the composition path | U | `tests/test_settings.py::test_a_blank_secret_file_path_beside_a_real_env_secret_is_accepted` — a blank (`""`) or whitespace-only `idp_client_secret_file` beside a real `idp_client_secret` is read as unset, so the environment spelling is authoritative and the loader is never sent to a blank path. E (adjacent): the drill's controlled matrix (`docs/evidence/c3/rotation-drill.md` Part 1). **RESOLVED (was WEAK)** |

## Row counts by home

- **Unit test (U):** 35 rows (some rows cite more than one test).
- **Probe (P):** 2 rows (the two pod-stack runs; each also carries an evidence record).
- **Evidence record (E):** 11 rows gated wholly on a record (the pod-contract statements,
  the image rows, the drill rows, the DevOps review).
- **Unmapped:** 0 rows have no home at all.

## Flags — scenarios whose home is absent or weak (gaps, not papered over)

**All four flags are RESOLVED.** The four flagged rows (35, 36, 37, 50) now each carry a
direct pytest home, added in this change; the flag text is retained below with its
resolution so the trail is readable.

1. **Scenario 35 "Algorithm confusion refused" — RESOLVED.** Was no pytest home (the only
   evidence a manual probe in an **archived** change's review record, not a live test). Now
   `tests/test_idp.py::test_an_alg_none_token_is_refused_by_the_pinned_algorithm`: the token
   is assembled by hand (`alg: none`), because PyJWT refuses to mint it through its
   high-level API, and the exchange refuses it by the pinned algorithm.
2. **Scenario 36 "Embedded key refused" — RESOLVED.** Was no pytest home. Now
   `tests/test_idp.py::test_an_embedded_jwk_in_the_header_is_ignored_and_the_token_refused`:
   a token signed by a key foreign to the published set, carrying that key as a header
   `jwk`, is refused — proving the embedded material is never consulted.
3. **Scenario 37 "`kid` outside the provider's key set refused" — RESOLVED.** Was a weak
   home (the nearest test exercised the signature-mismatch branch, not the `kid`-absent
   lookup). Now `tests/test_idp.py::test_a_provider_token_kid_absent_from_the_published_set_is_refused`:
   a real-key-signed token whose `kid` names no published key hits the literal
   `gateway/idp.py::_signing_key` lookup-failure branch ("no signing key matching").
4. **Scenario 50 "A blank file-path spelling is unset on the composition path" — RESOLVED.**
   Was in-process-only via the drill's matrix and the code. Now
   `tests/test_settings.py::test_a_blank_secret_file_path_beside_a_real_env_secret_is_accepted`,
   the direct sibling of the signing pair's `test_a_blank_structured_keyset_beside_a_real_singular_is_accepted`.

## Map verdict

**All 50 scenarios have a home**: 35 unit-tier, 2 probe-tier, 11 evidence-tier, with
overlap where a scenario is both. **No scenario is entirely unmapped, and no row carries a
flag**: the four rows that did (35, 36 — no pytest home; 37, 50 — weak homes) each gained a
direct pytest home in this change, closing the gaps.