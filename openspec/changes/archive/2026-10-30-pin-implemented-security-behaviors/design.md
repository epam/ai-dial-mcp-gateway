# Design

## Context

The implementation is ahead of the spec on four security behaviors. Each is real,
tested, and mandated — by the threat model's rulings (M9, M10, M11, M20's placement
notes each say "repo — **flagged**: candidate spec change") and, for the first two, by
the consent-attribution design (`background/design.md` §6.1: control 3 the audit chain,
control 4 the RFC 9207 `iss` required by MCP 2026-07-28). See `proposal.md` — Why, for
the owner's verify-first mandate; this design's job is to show the verification, choose
the delta shapes, and carry the security impact analysis.

This is a **spec-only change**: the delta spec is the mechanism, the main spec is never
edited directly, no code or test is touched, and `docs/threat-model.md` is not edited
here (its placement-note flips are the standing rule's follow-through at completion,
owner-approved — see the threat-model delta below).

## Verify-first evidence (per delta)

The mandate's binding rule: for each delta, establish that the implemented behavior is
(a) real, (b) correct, and (c) mandated, before writing the spec line. Each delta below
carries its grounding; **no delta was stopped on** — all four passed.

### Delta 1 — RFC 9207 `iss` in authorization responses

- **Real.** The success redirect builds `params = {"code": code, "iss":
  settings.gateway_public_origin}` (`gateway/flow.py`, `harness_redirect`, line 381)
  and is wired at the upstream callback (`gateway/federation.py:258`). The error
  redirect carries the same parameter (`gateway/errors.py`, `redirect_error`,
  lines 79-83: `iss` in the params mapping, echoed on the error path deliberately).
  The value is the public origin — the same string the AS metadata document
  advertises as its issuer (`gateway/settings.py`, `gateway_public_origin`).
- **Correct.** The value is derived from the one setting the discovery document,
  every minted token's `iss`, and the resource URIs are all derived from — one
  spelling, so the parameter always matches the metadata a harness holds. Tested on
  both paths: success (`tests/test_federation.py:920-932`,
  `test_the_harness_code_round_trips_state_and_issuer` — `params["iss"] == [ORIGIN]`
  alongside the echoed `state` and the code) and redirected error
  (`tests/test_authorize.py:319-327`,
  `test_a_redirected_error_carries_the_issuer_for_mix_up_defense`).
- **Mandated.** Threat model M9's placement note (the RFC 9207 `iss` parameter is
  "repo — implemented and tested, and the current spec carries no `iss` requirement
  (**flagged**: candidate spec change)"), with M9's address list naming T1-12/T1-13
  and T1-13's Data Protection row carrying the wrong-AS defense — the mix-up class
  T1-4/T1-13 belongs to (T1-4's own grid is addressed by M4/M5 and does not cite
  `iss`); `background/design.md` §6.1 control 4 names it "required by MCP 2026-07-28".
  A grep of the main spec confirms zero `iss`/9207 mentions today.

### Delta 2 — Per-flow lifecycle audit records

- **Real.** `gateway/audit.py` carries the lifecycle emitters — `flow_allocated`,
  `upstream_callback`, `signin_result` (fixed-vocabulary result), `code_issued`,
  `flow_leg_failed` (leg name + the gateway's own reason text), plus
  `token_issued`/`token_refreshed`/`token_revoked`/`client_registered` — and they are
  wired at every site: `gateway/authorize.py:164`, `gateway/federation.py:118-258`
  (leg failures, callback, signin result, code issuance),
  `gateway/token.py:210/430/498`, `gateway/routes.py:158`.
- **Correct.** The discipline the spec already pins for refusals holds for the
  lifecycle records by construction: the emit boundary bounds caller-supplied facts
  (`_bounded`, `_CALLER_FACT_FIELDS`), the reason/result vocabularies are the
  gateway's own, and no emitter has a parameter for a credential. Proven by tests:
  the whole-story test (`tests/test_audit.py:204-241`,
  `test_the_flow_emits_its_whole_story_with_identifiers` — the event sequence is
  exactly `[flow_allocated, upstream_callback, signin_result, code_issued]`, every
  record carries flow id / client id / toolset, and the post-identity records carry
  the subject); the refused-credential-call outcome
  (`tests/test_audit.py:244-286`); the credential-free measurements
  (`tests/test_audit.py:289+`, `test_no_credential_material_reaches_any_record`;
  `tests/test_federation.py:951-982` — each mints values that genuinely exist during
  the run and asserts their absence from the populated log); and the structural
  field-set controls (`tests/test_limits.py:690`, `:734` — each asserts every
  emitted record's fields fall inside an allowed set, with a negative control that
  the log is populated rather than empty).
- **Mandated.** Threat model M11's placement note ("repo (the per-flow lifecycle
  records — implemented and PoC-evidenced; the spec pins refusals only, **flagged**:
  candidate spec change)"); T1-16's Detective entry names the per-flow records as
  what makes each flow's issuance attributable to the acting user;
  `background/design.md` §6.1 control 3 (the consent-attribution audit chain: "The
  chain is attributable end-to-end"); the archived PoC design's control statement
  ("The audit trail covers the whole request lifecycle, refusals before allocation
  included") pinned only the refusal class as spec.

### Delta 3 — JWT verification hygiene

- **Real.** The gateway's own tokens are verified in `gateway/tokens.py`
  (`decode_own_token`, lines 286-294): `jwt.decode(token, signing_key.public_key(),
  algorithms=[signing_key.algorithm], issuer=issuer, …)` — the key is passed
  directly and the algorithm is the signing key's own, so a token header selects
  neither. The provider leg pins `_SIGNING_ALGORITHM = "RS256"`
  (`gateway/idp.py:47`) and decodes under it with the configured issuer
  (`gateway/idp.py:255-264`); the `kid` is resolved only in that provider's own
  fetched JWKS (`gateway/idp.py:273-312`), with a refusal — "the token was not
  issued by this provider" — when no published key matches.
- **Real — one implemented nuance the delta does not pin (disclosed, not smuggled
  in).** The `kid` resolution carries a fallback for a token whose header has no
  `kid` at all: the lookup does not refuse, it resolves to the first RSA signing
  key in the provider's JWKS and accepts the token if that key verifies it
  (`gateway/idp.py:296` — the `kid` comparison is skipped for an empty `kid`). With
  this deployment's IdP the path is dead: Keycloak signs every token type the realm
  issues — the flow's id_token included — under the realm's single active key and
  carries that key's `kid` in the JOSE header; verified live 2026-10-30 against the
  running Keycloak 26.7.2 in this deployment's `dial` realm, whose freshly minted
  token's header is exactly `alg`/`typ`/`kid` — so only a hand-crafted token that
  strips the header's `kid` can reach the fallback. The direction of the omission
  matters: a reimplementation working from the delta spec alone would *refuse*
  kid-less tokens — a silent behavior change in exactly the drift direction this
  change exists to close. Pinning the fallback is a one-clause delta edit —
  recommended below as an owner-pause decision, not made here; the delta spec is
  frozen in this pass.
- **Correct.** Three grounds. (1) The existing tests prove key pinning end to end: a
  code signed by another key is refused (`tests/test_token.py:376-384`), a
  foreign-signed refresh token is refused (`tests/test_tokens.py:568`), a
  foreign-signed token is refused on the status endpoint (`tests/test_tokens.py:893`),
  and the identity token is verified against the provider's *published* keys — a
  token signed by a key the provider does not publish is refused
  (`tests/test_federation.py:290-317`,
  `test_the_exchange_verifies_the_identity_token_against_the_providers_keys`) as is a
  foreign-issuer token (`tests/test_federation.py:320-338`). (2) The two scenarios
  with no dedicated unit row — `alg: none`, embedded `jwk`/`x5c` — were verified
  empirically against the repo's own venv under the exact decode call shape the
  implementation uses: an `alg: none` token is refused (`InvalidAlgorithmError`,
  the pinned-algorithm allowlist) and a token whose header carries its own `jwk` is
  refused on signature (`InvalidSignatureError` — the header's key material is never
  consulted; the passed key is the only key). (3) The call shape is the
  library-documented safe form (key passed directly, `algorithms` pinned), and the
  dependency-audit gates cover the library itself.
- **Mandated.** Threat model T4-7's grid names this the control and flags the gap
  ("the spec pins RS256 *minting* but carries no verification-hygiene requirement:
  flagged for a spec change — M20"); M20's placement note repeats the flag; the
  disposition "T4-7 | Mitigated (M20)" rests on a repo-owned control the spec does
  not carry.

### Delta 4 — The toolset-name charset

- **Real.** `gateway/settings.py:40` (`_TOOLSET_NAME = re.compile(r"^[a-z0-9-]+$")`),
  enforced first in the startup mapping validator (`_validate_mapping`) with a loud
  operator-facing message naming the charset.
- **Correct — and the assumption it protects is verifiable.** The router's static
  locations are written against exactly this shape: `location ~
  ^/dial/[a-z0-9-]+/status$` and `location ~ ^/dial/(?<tname>[a-z0-9-]+)/mcp$`
  (`router/nginx.conf`), so a name outside the charset has no location that matches
  it at all. Tested: `tests/test_settings.py:185-193` (parametrized over `Notion`,
  `notion_mcp`, `notion mcp`, `notion/mcp`, `""` — each refuses startup with
  "charset" in the error), plus `:159-168` (the dot in `jwks.json` is refused by the
  charset guard, pinned deliberately) and `:171-182` (the charset refusal fires
  before the reserved-name one). One nuance verified, not a defect: the reserved
  list carries `jwks.json`, which the charset makes unreachable as a name — kept
  for fidelity with the router's alternation, and the test suite pins that
  relationship on purpose.
- **Mandated.** Threat model M10's placement note, re-placed 2026-10-29 after the
  review round found the spec claim false: "the delta must pin the charset toolset
  names are validated against at startup, the shape the router's static regexes
  assume, so a relaxed code check cannot silently diverge from the routing"; T6-2's
  surface-reduction row and T6-7's control row both cite the charset, each noting
  "the spec carries no charset requirement".

## Goals / Non-Goals

**Goals:**

- Pin the four behaviors as spec requirements whose scenarios map onto the existing
  tests and the pinned-call library semantics — so the main spec, once synced, says
  what the system already does, and a future change that relaxes any of them fails a
  conformance row instead of silently diverging.
- Record the verification honestly, including what each scenario rests on (an
  existing test, or the pinned call's library-guaranteed semantics).

**Non-Goals:**

- No code, test, or configuration change; no behavior change of any kind.
- No edit to the main spec directly, to `docs/threat-model.md`, or to the method
  files (the threat-model placement-note flips are tracked as the completion
  follow-through, below).
- No spec text for the owner-excluded controls: the CIMD fetch's JSON content type,
  timeouts, and User-Agent; outbound-call timeouts and bounded response parsing
  beyond what the spec already pins. They stay repo controls per M7's note.

## Decisions

### D1 — Three ADDED requirements, one MODIFIED

- **`iss`** gets a new requirement rather than a sentence inside "Authorization
  requests require a valid resource and allocate protected flow state": that
  requirement is entirely about *request* validation and flow allocation, and the
  `iss` line is about *responses* — appending it would blur a requirement whose name
  and scenarios are request-shaped. The new requirement is tightly scoped to the
  response parameter and carries the metadata-match scenario the mandate named.
- **Per-flow audit** likewise gets a new requirement ("Flows are audited through
  their lifecycle") rather than extending "Refusals before flow allocation are
  audited": that requirement's name and text pin the pre-allocation class
  specifically, and the lifecycle class is a different population (allocated flows)
  under the same discipline. The new requirement states the shared discipline rather
  than duplicating it, and its scenarios are the two the mandate named (end-to-end
  attribution; credential-shaped values never reaching a record) plus the
  refused/failed-leg outcome that the whole-story test pins.
- **JWT verification hygiene** is new requirement territory by definition — the spec
  pins minting only today; nothing exists to modify.
- **The charset** is a MODIFIED of "The toolset mapping is safe to configure": the
  requirement already pins two startup mapping refusals and the charset is the third
  of the same kind, in the same place, for the same reason class (a mapping entry
  the router cannot serve). The full amended text is carried, existing scenarios
  untouched, one scenario added.

### D2 — Scenario-to-evidence honesty

Every scenario in the delta maps to evidence, and the mapping is recorded here
rather than left implicit: **nine of the twelve** scenarios rest directly on named
existing tests (cited above). Three do not, and each is disclosed with its actual
grounding. The `alg: none` and embedded-key scenarios rest on the pinned decode
call's library-guaranteed semantics, verified empirically against the repo's own
venv under that exact call shape, with the surrounding key-pinning behavior covered
by the named foreign-key tests. The metadata-match scenario ("A harness matches `iss`
against the AS metadata document") rests on the *conjunction* of two pinned
behaviors rather than on any single named test: the success-redirect test asserting
`iss` equals the public origin (`tests/test_federation.py:920-932`), and the main
spec's existing "Flat AS metadata fetch" scenario pinning the metadata document's
issuer as that same public origin (`gateway/discovery.py:57-59` builds it from the
one `gateway_public_origin` setting both derive from). No test asserts the match end
to end; per the repo's rule — a scenario without a test path is a conformance row
that can lie — it is recorded here as such, and a dedicated row is a code-side
follow-up alongside the two library-semantics shapes (open question below). The
conformance task in `tasks.md` makes the reviewer re-walk this mapping, and no
scenario falls outside the three recorded categories.

### D3 — Verify-first as the change's own gate

The mandate's rule is operationalized as the first task in `tasks.md` and the
evidence section above: implementation and tests read before any spec text, each
delta's mandate traced to its threat-model entry, and the one empirical probe (the
JWT shapes) run against the repo's own dependency set rather than asserted from
memory. A delta that had failed any of (a) real, (b) correct, (c) mandated would
have been stopped on and reported — none was.

## Risks / Trade-offs

- [The spec pins a behavior that should instead be fixed] → The verify-first pass
  above, re-walked by the independent review gate and the owner pause; every delta
  cites its code, its tests, and its threat-model mandate.
- [Pinned scenarios drift from the code after this change] → The scenarios become
  conformance rows once synced; the gate ladder's row check catches divergence at
  the next change that touches these paths.
- [Scenario-to-test asymmetry: three scenarios rest outside a named test row — the
  two JWT scenarios on library semantics, the `iss` metadata-match scenario on the
  conjunction of two pinned behaviors] → Disclosed here and in `tasks.md`; the
  empirical probe and the foreign-key tests bound the first gap, the two conjuncts
  (the `iss`-equals-origin test; the main spec's pinned AS-metadata issuer) bound the
  second; a dedicated-row follow-up is recorded as an open question, deliberately not
  smuggled into this spec-only change.
- The MODIFIED requirement's description exceeds the 500-character hint because
  MODIFIED deltas carry the existing block whole, never trimmed to fit — the
  retained text is untouched and the charset sentence is appended (the same trade
  the archived `fix-dcr-response-conformance` change recorded).

## Security impact analysis (per `docs/security-analysis.md`, per-change shape)

**1. Change description.** A spec-only delta: four requirements added or amended in
the `mcp-signin` capability, pinning security behaviors the implementation already
has (RFC 9207 `iss`; per-flow lifecycle audit records; pinned-algorithm/pinned-key
JWT verification; the startup toolset-name charset). No executable path, no
configuration, no data, no protocol element changes. The implementation shape is the
existing code, cited per delta above.

**2. Impact level — No impact, with reasons.** The diff is markdown under
`openspec/`; it adds no endpoint, grant, trust boundary, credential, or data flow,
and touches no sensitive asset (the never-cut assets A1-A14 are all runtime or
at-rest material this diff cannot reach). The spec-pinning *changes what future
changes must preserve* — that is its purpose — but the change itself exposes nothing.
This "no impact" level is exactly the claim the security review gate runs to
*falsify* (repo gate 4, focused depth); the analysis below is what that pass reads.

**3. Invariant ruling table** (one row per never-cut invariant, `ROADMAP.md`):

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | Preserved | No runtime change; the pinned behaviors do not touch the credential path. |
| 2 | The upstream PKCE verifier never leaves Core | Preserved | Same — no code or protocol change. |
| 3 | Per-user credential isolation | Preserved | No change to any authorization or resolution behavior. |
| 4 | DIAL authorization on every toolset call | Preserved | No change; the audit requirement pins *records* of flows, not any authorization decision. |
| 5 | No credential in logs, argv, or errors | Preserved — strengthened | The per-flow audit requirement pins the credential-free record discipline for the lifecycle class, extending the invariant's spec coverage from refusals to allocated flows. |
| 6 | No hardcoded credentials in the repository | Preserved | The diff adds prose only; no value of any kind is added. |
| 7 | The signing key is IdP-grade secret material | Preserved — strengthened | The verification-hygiene requirement pins the algorithm/key-selection discipline that protects the token-acceptance decision the key underwrites. |

**4. Threat tables, per touched entry point.** The change touches no runtime
attack-surface entry point — no request path, no parsing, no storage. The one
surface it does touch is the repository's normative specification (the delta spec
itself, and the main spec at sync time), which future changes and reviews treat as
trusted input. That surface is enumerated here rather than skipped:

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| The normative spec (this delta; the main spec at sync) | Injection → (by gain: integrity of the trusted record) Manipulation of trusted configuration | Spec mis-pinning | The spec as the input every future change's conformance rows and reviews read | I | A requirement pinning behavior that is buggy, incidental, or unmandated is written as normative: future changes preserve a defect because the spec says to. Not a runtime attack — an integrity flaw in the record the process trusts. |
| The normative spec (post-sync) | Use Control Misconfiguration → (by gain: integrity) Manipulation of trusted configuration | Spec/implementation drift | The spec-implementation correspondence | I | After pinning, a code change relaxes the behavior and the spec silently goes stale — the exact gap this change closes, re-opened from the other side. |

No mis-use cases: no legitimate-user behavior is altered, so no permitted use can be
rewarded differently than today.

**5. Mitigations per threat, in the control-category order.**

*Threat: Spec mis-pinning.*

1. Reduce Attack Surface — four deltas only, each threat-model-flagged; the
   owner-excluded controls stay out (delta spec; owner: this change's review).
2. Isolation — not applicable: the spec is one document the whole process reads;
   no boundary separates a pinned line from its readers, and none should.
3. Authentication — not applicable: the threat is a wrong trusted record, not an
   untrusted author; authorship is fixed by the repo's workflow.
4. Authorization — not applicable: no principal's access changes; the spec grants
   nothing at runtime.
5. Data Protection — not applicable: no sensitive data is stored or moved by a
   markdown diff.
6. Anti-Injection — **the control**: the verify-first rule — each delta grounded in
   cited code, cited tests, and a cited threat-model mandate before the spec line
   was written (delta spec + this document's evidence section; owner: this change's
   author, falsified-or-confirmed by the review gates).
7. Anti-DoS — not applicable: the threat is a single wrong line's slow effect, not
   volume; no rate shape exists.
8. Detective controls — the independent review gate and the owner pause read the
   evidence mapping; the conformance-row check at every later change re-tests the
   pinned scenarios against the code (repo gate ladder).

*Threat: Spec/implementation drift.*

1. Reduce Attack Surface — the scenarios are written against existing tests and
   pinned library semantics, so drift is detectable from day one (delta spec).
2. Isolation — not applicable: drift is a correspondence property between two
   artifacts; no isolation boundary can hold it.
3. Authentication — not applicable: no actor is authenticated against a spec.
4. Authorization — not applicable: same.
5. Data Protection — not applicable: no data at stake.
6. Anti-Injection — the scenarios' WHEN/THEN shape is the falsifiable form: a
   drifted behavior fails a row rather than reinterpreting prose (delta spec).
7. Anti-DoS — not applicable: no volume shape.
8. Detective controls — **the control**: once synced, the scenarios are conformance
   rows in the gate ladder; any later change touching these paths re-proves them
   (repo gate ladder; owner: every future change).

**6. Grouped mitigation list.**

| Mitigation | Home and owner | Addresses |
|---|---|---|
| Verify-first evidence per delta (cited code, tests, mandate; one empirical probe) authored before the spec lines | **Placed** — this change's `design.md` (the evidence section above); enforced by the review gates and the owner pause | Spec mis-pinning |
| Scenarios written as test-mapped WHEN/THEN rows, mapping recorded (tests vs pinned-call library semantics) | **Placed** — the delta spec + this document; the conformance-row check enforces it from sync on | Spec mis-pinning, drift |
| The standing gate ladder's conformance-row check on every later change | **Placed** — repo (gate ladder) | Drift |

**7. Threat-model delta.** None in this diff. At the change's completion (owner
pause passed), the standing rule applies: M9's, M10's, M11's, and M20's placement
notes flip their homes from "repo — flagged: candidate spec change" to "Placed —
spec" for the pinned elements (the RFC 9207 `iss`; the `[a-z0-9-]+` charset; the
per-flow lifecycle records; the verification-hygiene set), and T4-7's/T6-2's/T6-7's
grids stop noting "the spec carries no … requirement". Dispositions themselves are
unchanged — every one of these threats was already ruled Mitigated; only the
control's home moves. That edit is a tracked task, not part of this diff.

**8. Open questions.**

- **Dedicated negative rows for the two library-semantics JWT scenarios.** The
  `alg: none` and embedded-key refusals are pinned by the call shape and verified
  empirically, but the suite has no unit row that mints such a token and asserts
  the refusal (the `kid`-absent shape likewise). Whether to add them is a code-side
  call for a later change; it does not change this delta's requirements, scenarios,
  or tasks, and the current foreign-key and unpublished-key rows already prove the
  key-pinning behavior around them.
- **Pinning the `kid`-less fallback in the delta spec (owner-pause recommendation,
  not decided here).** The implemented provider leg accepts a token whose header
  carries no `kid` by resolving to the first RSA signing key in the provider's JWKS
  (`gateway/idp.py:296`) — dead-path-only with this deployment's Keycloak (every
  realm token carries `kid`; verified live 2026-10-30, see Delta 3's evidence
  above), but a real behavior the delta spec neither states nor forbids, so a
  from-spec reimplementation would silently refuse such tokens — the
  silent-behavior-change direction. Recommendation for the owner pause: add one
  clause to the verification-hygiene requirement naming the fallback (a token whose
  header carries no `kid` resolves to the provider's first published RSA signing
  key), so the spec says what the code does. Not done in this pass — the delta spec
  is frozen here and the decision is the owner's.

## Migration Plan

None. The change is additive prose; sync (`openspec sync specs` or archive) lands
the four requirements in the main spec, and nothing else moves. Rollback is deleting
the change folder before sync.
