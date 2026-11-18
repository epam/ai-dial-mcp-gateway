# Tasks

Verification-shaped by design: this change alters no code, so every task is a check —
that each delta's behavior exists and is proven, that the gates that apply to a
spec-only diff pass, and that the conformance rows hold once synced. No task writes
code or tests.

## 1. Verify-first re-walk (per delta — the review's own map)

- [ ] 1.1 Delta 1 (RFC 9207 `iss`): confirm each scenario's grounding —
  `gateway/flow.py`'s `harness_redirect` (the success redirect's `iss`), and
  `gateway/errors.py`'s `redirect_error` (the error path's `iss`), both set to the
  public origin; the tests `tests/test_federation.py::test_the_harness_code_round_trips_state_and_issuer`
  and `tests/test_authorize.py::test_a_redirected_error_carries_the_issuer_for_mix_up_defense`;
  and that the main spec still carries no `iss` requirement outside this delta
  (grep `openspec/specs/mcp-signin/spec.md` for `iss`/`9207` — the only hits must be
  this change's synced lines, post-sync). The third scenario (a harness matches
  `iss` against the AS metadata document) rests on no single named test: it is
  grounded in the conjunction of the success-redirect test above and the main
  spec's pinned AS-metadata issuer ("Flat AS metadata fetch" — both values derive
  from the one `gateway_public_origin` setting), disclosed as such in `design.md`
  §D2. Verify: every scenario in the delta matches observed, tested behavior or a
  recorded conjunction, per the mapping in `design.md` §D2.
- [ ] 1.2 Delta 2 (per-flow lifecycle audit): confirm the emitters and their wiring
  (`gateway/audit.py`; `gateway/authorize.py`, `gateway/federation.py`,
  `gateway/token.py`, `gateway/routes.py` call sites) and the grounding tests —
  `tests/test_audit.py::test_the_flow_emits_its_whole_story_with_identifiers`,
  `::test_a_refused_credential_call_is_recorded_as_a_refusal`,
  `::test_no_credential_material_reaches_any_record`,
  `tests/test_federation.py::test_no_credential_material_reaches_the_audit_trail`;
  and that the existing refusal-audit requirement is untouched by the delta.
  Verify: the three delta scenarios match the tested behavior, and the refusal
  requirement's text is byte-identical to the main spec's.
- [ ] 1.3 Delta 3 (JWT verification hygiene): confirm the call shapes —
  `gateway/tokens.py`'s `decode_own_token` (the signing key's own algorithm, the
  key passed directly, the issuer checked) and `gateway/idp.py`'s
  `_verified_claims`/`_signing_key` (pinned RS256, configured issuer, `kid` resolved
  only in the provider's own JWKS); re-run the empirical probe from the repo venv
  for the two library-semantics scenarios (an `alg: none` token and a header-embedded
  `jwk` token, both refused under the exact decode call shape); and confirm the
  foreign-key/unpublished-key tests (`tests/test_token.py::test_a_code_signed_by_another_key_is_refused`,
  `tests/test_tokens.py::test_a_foreign_signed_refresh_token_is_refused`,
  `::test_a_foreign_signed_token_is_refused_on_the_status_endpoint`,
  `tests/test_federation.py::test_the_exchange_verifies_the_identity_token_against_the_providers_keys`,
  `::test_a_token_from_another_issuer_is_refused`). Verify: each scenario rests on a
  named test or on the empirically re-probed pinned call shape.
- [ ] 1.4 Delta 4 (toolset-name charset): confirm the charset and the routing agree —
  `gateway/settings.py`'s `_TOOLSET_NAME` (`^[a-z0-9-]+$`) against the router's
  static locations (`router/nginx.conf`'s `^/dial/[a-z0-9-]+/status$` and
  `^/dial/(?<tname>[a-z0-9-]+)/mcp$`); and the refusal tests
  (`tests/test_settings.py::test_toolset_name_outside_the_routed_charset_refuses_startup`
  and its parametrized names, `::test_the_unreachable_reserved_name_is_refused_by_the_charset_guard`,
  `::test_reserved_name_refusal_is_case_sensitive_but_charset_is_enforced_first`).
  Verify: the MODIFIED requirement carries the existing block whole (the two existing
  scenarios byte-identical) with only the charset sentence and scenario added.

## 2. The gate ladder, as it applies to a spec-only diff

- [ ] 2.1 Diff-boundary check (the spec-only analogue of the static gates): the
  working tree's change is confined to `openspec/changes/pin-implemented-security-behaviors/**`
  — no code, test, configuration, `docs/`, or main-spec file is touched, so the
  static gates' last green run over the code stands unchanged. Verify:
  `git status --porcelain` and `git diff --stat` name only files under the change
  folder (the `docs/threat-model.md` edit re-placing the timeout/bounded-parsing
  grid cells, noted at session start, was never this change's: it landed as its own
  docs commit `4254a1f` — "docs(threat-model): re-place the timeout/bounded-parsing
  grid cells to repo" — pushed to `origin/master`, so the committed tree already
  carries it and this change's diff stays spec-artifacts-only).
- [ ] 2.2 Change validation: `openspec validate pin-implemented-security-behaviors
  --strict` passes — the delta parses, every scenario uses exactly four hashtags,
  every requirement has at least one scenario, the MODIFIED header matches the main
  spec's requirement name exactly, and the zero-delta rule is satisfied (four
  deltas). Verify: the command exits clean.
- [ ] 2.3 Security review gate (focused depth): an independent reviewer subagent —
  not this authoring pass — reviews the diff against this change's SIA
  (`design.md` §"Security impact analysis") and the threat model, with the job of
  *falsifying* the no-impact claim: that no pinned line changes behavior, that the
  verify-first evidence is accurate, and that nothing the owner excluded has
  crept in. Verify: the reviewer's report is captured in the change folder and its
  findings, if any, are resolved before the review gate.
- [ ] 2.4 Independent review gate: a second independent reviewer subagent reviews
  the full artifact set (proposal, delta spec, design, tasks, release notes) for
  coherence with the repo's conventions and the main spec's format. Verify: the
  review's findings are resolved or answered in the artifacts.
- [ ] 2.5 Owner pause: the complete package goes to the owner; nothing is committed
  or pushed before the owner's go, per the mandate. Verify: the owner's decision is
  on record in the change folder before any commit.

## 3. Conformance and follow-through

- [ ] 3.1 Conformance-row check (post-sync): after the delta lands in the main spec
  (sync or archive), walk every scenario against the mapping in `design.md` —
  each maps to one of the three recorded categories: a named existing test, the
  pinned-call library semantics with the recorded empirical probe, or (the `iss`
  metadata-match scenario) the recorded conjunction of the `iss`-equals-origin test
  and the main spec's pinned AS-metadata issuer; no scenario is unprovable against
  the current code. Verify: the walk finds no scenario outside the three categories
  (nine named tests, two library-semantics, one conjunction — twelve total), and
  the main spec's other requirements are untouched by the sync. _2026-10-30: pending
  evidence record._
- [x] 3.2 Threat-model follow-through (owner-approved; the standing rule, not part
  of this diff). _Completed late, 2026-10-30 in the follow-up commit. The first pass
  (the `docs/threat-model.md` edit landed with the spec sync) flipped the four §12
  M-row homes but left the grid notes and the §9/§12 preambles un-changed, which the
  retro-review (`evidence/retro-review-orchestrator-edits.md` R1) found left the
  model self-contradictory. The follow-up re-places every stale citation — the §9
  preamble, T1-13, T4-7, T6-2, T6-7 (its Reduce-Attack-Surface, Anti-Injection, and
  detective cells), the seven per-flow-records cells, and the §12 preamble — to the
  spec home, and reconciles T2-4's Anti-DoS "(spec)" timeouts cell to repo per R2.
  The task's own grep now finds none of the four stale flags._ Deliverables: flip
  the placement-note homes in `docs/threat-model.md` — M9's
  RFC 9207 `iss`, M10's `[a-z0-9-]+` charset, M11's per-flow lifecycle records,
  M20's verification-hygiene set — from "repo — flagged: candidate spec change" to
  "Placed — spec", and drop the matching "the spec carries no … requirement" notes
  in the T4-7, T6-2, and T6-7 grids. Dispositions are unchanged; only the homes
  move. Verify: a grep for "candidate spec change" finds none of the four stale
  flags, and each flipped note names its spec requirement.

## 4. Release notes

- [ ] 4.1 Finalize `release-notes-draft.md` in the two-audience format — the
  user-facing section states no visible change this release; the team-facing
  section records what got pinned, why, and the verify-first basis. Verify: both
  sections present, no credential or live-deployment detail beyond what the
  change's artifacts already carry. _2026-10-30: pending evidence record._
