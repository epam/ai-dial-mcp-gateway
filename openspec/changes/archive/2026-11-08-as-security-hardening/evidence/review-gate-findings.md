# Gate 8.5 — the general review gate's findings

Change: `as-security-hardening` (C2.5). Review object: `git diff f19dcfb..HEAD`, the full
implementation. Reviewer: the independent general-review subagent (gate 8.5, after the
security gate's PASS — `security-gate-findings.md`; a different lens from rounds 1–2,
which reviewed the planning artifacts).

Method: the delta spec walked requirement by requirement against the actual hunks (not
the intent); the implementation stress-tested for the subtle-bug classes the gate brief
names (continuation staleness, memo/mint ordering, eviction order, state echo, refuse-whole
semantics, load-refusal loudness, partial state on error paths); the new tests read for
behavior-vs-implementation and tautology; the docs and threat-model ledger checked against
the code and the spec's scenario headers; the full suite run fresh on this tree.

## Findings

### 1. SHOULD-FIX — a pre-existing flaky test can falsify the suite's green signal (~1 run in 21)

- **Location:** `tests/test_custody.py:97-107`
  (`test_the_envelope_layout_is_version_key_id_nonce_ciphertext`) — unchanged by this
  diff (this change touches the file only at `_run_flow`'s pre-approve seed).
- **Problem:** the test seals a one-byte provider token (`"t"`) and asserts
  `b"t" not in raw[header + key_id : header + key_id + NONCE_BYTES]` — i.e. that the
  **random 12-byte nonce** contains no `0x74` byte. That fails by pure chance with
  probability `1-(255/256)^12 ≈ 4.6%`. My fresh full-suite run on this tree hit it:
  **674 passed, 1 failed (this test), 1 skipped**; eight immediate re-runs of the test
  passed 8/8. The change's own gate evidence (`docs/evidence/c2p5/gate-conformance-walk.md`,
  task 8.2) records "675 passed, 1 skipped" — a run that got lucky, not a reproducible
  green. A byte of the nonce is not "the provider token appearing in the clear bytes";
  the assertion's semantics are wrong, not the envelope.
- **Impact on this change:** none behaviorally — the test is pre-existing and unrelated
  to the checkpoint, the admission rule, the state rule, or the replay revocation. But a
  gate tier whose green is a coin flip every ~20 runs is a gate that will one day block
  an unrelated change for a spurious reason.
- **Suggested direction:** assert against the **ciphertext** region (the bytes after the
  nonce — deterministic, and the region the claim is actually about), or assert that the
  full clear region does not decode to the token (the round-trip test at line 90 already
  proves decrypt is required). One line; land it with this change or as an immediate
  follow-up before the next suite-dependent gate.

### 2. SHOULD-FIX — `_single_string`'s docstring states a repeated-parameter refusal the endpoint does not perform

- **Location:** `gateway/authorize.py:103-115` (`_single_string`) and its call sites at
  `gateway/authorize.py:125-127, 152-158`; contrast `gateway/token.py`'s form read
  (repeated parameters refused — proven by `tests/test_token.py:268`).
- **Problem:** the docstring says "A repeated OAuth parameter is ambiguous — two
  different parsers can read two different values from it — **so it is refused rather
  than resolved by picking one**." The endpoint resolves, never refuses: Starlette's
  `QueryParams.get` is last-wins for duplicated keys (verified directly:
  `QueryParams([('state','a'),('state','b')]).get('state') == 'b'`), and no test asserts
  refusal at `/dial/authorize`. Every authorize parameter — `client_id`,
  `redirect_uri`, `resource`, `response_type`, the PKCE pair — is read that way, and the
  new `state` read (line 134) joins the same posture. The security gate's note 3 saw the
  `state` half of this; the sharper half is that the file's own stated discipline is
  false today, for every parameter, and the new state comment ("its handling is a stated
  rule") leans on the same convention.
- **Security weight:** low — last-wins is deterministic within one implementation, the
  ambiguity can only harm the client that sent it, and the security gate judged the
  `state` instance a note. But a docstring that names a security rationale ("two parsers
  can read two values") for a discipline the code does not enforce is a standing trap for
  the next reader.
- **Suggested direction:** either enforce what the docstring claims — a
  repeated-parameter refusal for the authorize parameter set as a whole, the token
  endpoint's own `_form_parameters` shape — or correct the docstring to state the
  last-wins resolution honestly. The docstring fix is the minimum; the enforcement can be
  its own small change (the security gate's suggested direction, seconded here).

### 3. NOTE — the admission rule is scheme-deep only: `https` with no authority is admitted

- **Location:** `gateway/redirect_uris.py:76-93` (`scheme_admission_refusal`);
  `gateway/settings.py:177` (`PreRegisteredClient.redirect_uris` is `list[str]`, no
  shape check).
- **Problem:** the check reads only `parts.scheme == "https"`; a URI with no authority
  (`https:`, `https:/x`) passes at every admission site. Harmless as built — there is no
  cleartext leg, no host to attack, and the registration's own code delivery goes
  nowhere — but the rule's one-sentence promise ("a redirect URI must be `https`, or
  `http` on a loopback host") is true of the scheme alone, not of the URI shape.
- **Suggested direction:** nothing now; if the rule is ever revisited, one clause
  requiring an authority (a non-empty host) on the `https` arm closes it.

### 4. NOTE — refreshing the decision page re-runs the identity leg and fails loudly (pre-existing class, more likely here)

- **Location:** `gateway/federation.py:119-141` (`idp_callback`) — the decision page is
  served at the idp-callback URL, and the route does not consume the flow before the
  exchange.
- **Problem:** a browser refresh of the decision page re-GETs the idp callback, the
  already-used provider code is re-exchanged, and the user sees the identity-error page —
  while the parked record stays live and the approve POST still works (the identity-error
  path does not consume the record). The interstitial had exactly this shape; the
  decision page is simply the one page a user sits on long enough to refresh. No state
  corruption, no bypass — the flow either completes via the POST or expires by TTL.
- **Suggested direction:** none required; a `awaiting_attribution` short-circuit at the
  top of `idp_callback` (re-render the parked page without re-exchanging) would be the
  polish if anyone ever reports the UX.

### 5. NOTE — one registry test is tautological; the real property is covered elsewhere

- **Location:** `tests/test_limits.py::test_an_approval_covers_the_client_across_resources`
  (the `ApprovedClientRegistry` unit test).
- **Problem:** the registry API has no resource axis, so "a second resource's flow
  consults the same pair" collapses to calling `is_approved` with the same arguments the
  first test already used — it cannot fail for any reason the first test does not. The
  docstring narrates a resource dimension the test never exercises. The behavioral
  property is genuinely covered, twice, in `tests/test_federation.py`
  (`test_an_approval_covers_the_client_across_resources` — refusal still gates the new
  resource — and `test_an_approval_does_not_render_a_page_for_a_second_resource`).
- **Suggested direction:** delete the limits-level test or re-point its docstring at
  what it actually checks (that the key type carries no third member).

### 6. NOTE — the oversize-body scenario's route enumeration predates the consent route

- **Location:** the delta spec's retained "Oversize request body refused" scenario
  (`openspec/changes/as-security-hardening/specs/mcp-signin/spec.md`) — its WHEN names
  `/dial/register`, `/dial/token`, `/dial/revoke`.
- **Problem:** `POST /dial/consent` is a fourth unauthenticated body-bearing endpoint.
  It is covered — the requirement's text is general ("Every unauthenticated body-bearing
  endpoint MUST cap the request body in bytes at reading"), the implementation reads
  under `capped_body` (`gateway/federation.py:510`), and the limiter test bounds the
  route — but the scenario's enumeration was not extended, so a reader walking scenarios
  alone would miss the fourth route.
- **Suggested direction:** one line in the scenario's WHEN at the next amendment of that
  requirement (the CORS amendment beside it already names the consent route in its own
  scenario's enumeration).

### 7. NOTE — the state echo is value-faithful, not wire-byte-faithful (recorded so the claim's meaning is exact)

- **Location:** `gateway/authorize.py:134-136` (store the decoded parameter) and
  `gateway/flow.py:454-466` (`harness_redirect` re-encodes via `urlencode`).
- **Problem:** none, concretely — the stored value is the decoded `state` and the echo
  re-encodes it, so a client whose original percent-encoding differed from `urlencode`'s
  choice (e.g. `%7E` sent, `~` echoed) sees different raw bytes but the identical decoded
  value. OAuth clients correlate on the decoded value; the tests assert exactly that
  (`test_a_carried_state_is_stored_at_allocation_and_echoed_unchanged` stores an awkward
  value with `+?&=#` characters; the end-to-end round-trip test parses and compares).
  Recorded because the spec's "echoed back unchanged" is worth pinning as value-level
  fidelity — a wire-byte-level reading is not achievable without storing the raw encoded
  parameter, and nothing conforming needs it.
- **Suggested direction:** none.

## What was verified, and what could not be broken

**Spec conformance, requirement by requirement.** All 92 scenario headers walked against
the code: the checkpoint's gate is inserted at the spec's exact position on all three
mint paths — the app kind (after the app read in `complete_identity_leg`, before the
mint, `federation.py:178-189`), the stored-credential short-circuit (after the listing
read's signed-in check, before `_finish`, `federation.py:250-259`), and the consent
branch (after the read and the upstream build, in the interstitial's position,
`federation.py:197-209`) — and no mint path reaches `_finish` without either passing the
registry check or the approve action. The decision page carries exactly the three named
facts plus the two-field form, no scope list, no auto-continue, through the one shared
builder (`html_page`), with `form-action 'self'` family-wide and every interpolation
escaped (the hostile-name test proves the escape). The approve/deny handlers match the
spec's shapes: single-use via the check-then-clear of `awaiting_attribution` (atomic in
the event loop — no await between the lookup and the clear), deny consuming the record
and dropping identity material with `attribution_refused` audited, approve recording
`(subject, client_id)` and continuing from the record's stored continuation. The
registry's custody matches the ADDED requirement: process memory, no TTL, hard cap
(`gt=0` in settings — the zero-cap `StopIteration` shape is unreachable), oldest-first
eviction by insertion order with idempotent re-approve not moving age, one write path,
empty subject never recorded (and unreachable anyway — `idp.py:381` refuses a token with
no `sub` at the leg, verified).

**The subtle-bug classes, attacked:**

- *Continuation storage:* the upstream authorization URL is stored only on the
  first-attribution consent branch, the one path whose approve needs it; staleness is
  bounded by the flow's own TTL (600s), the same dwell the interstitial always had, and
  the threat model prices the dwell (M31). The approve action re-serves the interstitial
  from the record alone; nothing is round-tripped but the flow id and the action.
- *Memo/mint ordering:* the code grant mints **first** and records the token id **after**
  (`token.py:307-328`) — a failed mint leaves no memo entry, and a recorded id always
  names a token that exists. The replay claim sits **after** PKCE verification
  (`token.py:449-475`), so a wrong-verifier replay neither burns the code nor triggers
  the revocation — only a fully valid second redemption is the RFC's detection, and an
  attacker without the verifier cannot weaponize the denylist as a DoS. The memo's
  stored expiry is wall-clock and the denylist prunes on wall-clock (`state.py:514`) —
  no monotonic/epoch clock mix.
- *Eviction ordering:* `ApprovedClientRegistry` is insertion-ordered with an early return
  on an existing key — insertion order is approve order, and the re-approve test pins it.
  `ReplayCache._bought` is popped everywhere `_claimed` is (prune and cap eviction).
- *The parked-flow races (the ones I could not break):* the upstream callback does not
  check `awaiting_attribution`, so I tried to complete a parked flow around the user's
  act. App flows are structurally immune (`upstream_redirect_uri` is never set for them
  → the expired page). Stored-credential short-circuit flows discard the identity token
  at the listing read (`flow.py:264`), so a raced upstream callback hits
  `complete_upstream_leg`'s "lost the identity" refusal — no credential call, no mint.
  The consent branch parked at the decision page does hold the identity token, but
  completing it requires the flow id — 128-bit CSPRNG crossing only the victim's
  browser — so the shape that remains is the on-path race the threat model already
  prices at RES-12/DT-EP1-1 (that attacker reads the tokens off the wire directly). A
  post-mint record cannot mint twice: `_finish` discards the identity token, and the
  claims-only retention until TTL is pre-existing and priced.
- *Refuse-whole and load-refusal shapes:* the CIMD admission check raises inside the
  `redirect_uris` loop before any `ResolvedClient` exists — refused whole, matching the
  other document validations. The store's load refusal raises `ConfigurationError` from
  `RegistrationStore.__init__` — startup fails loudly, naming the record, proven by the
  planted-record test. A planted record with a non-list or non-string `redirect_uris`
  cannot admit anything: the resolution path filters to `()` (`authorize.py:318-324`),
  so every exact and loopback match fails.
- *Partial state on error paths:* the consent route clears the flag before acting; an
  issuance failure inside `_finish` leaves the flag clear, so a re-POST lands on the
  expired page and nothing re-mints; the identity-leg failure classes keep their
  consume-on-refusal / retain-on-fault split, now stated once in `_leg_failure`.

**The stated rules:** the 2048-byte state bound is checked first in `_validated_flow` —
before client resolution, answered directly (no redirect target exists yet), audited
`oversized_state`, at-the-bound admitted (both tested). `auth_time` joins `acr` in
`REGISTRY_CLAIMS`, stripped at both claim-source sites, with the recency assertions in
the test. The CORS posture is pinned by a real battery (every surface endpoint, plus the
OPTIONS-405) and the conftest's `'self'` check is precise (count==1, on `form-action`
only). The `iss` advertisement matches the emission. The admission rule's four sites
read one copy (`redirect_uris.py`, a leaf module — the import-cycle claim verified
against `settings.py`'s import).

**Test quality:** the new tests assert behavior (statuses, headers, page text, redirect
targets, audit event sequences, registry state), not implementation details; the
disclosed-partials assertions (task 5.2) are real — the replay test proves the original
refresh token dies at its next presentation, the rotated successor still refreshes, and
the first access token's `exp` is future and TTL-bounded. The pre-approve seeding in
`a_gateway`/`an_app_gateway` is honest test scaffolding, documented as such. The one
tautology found is finding 5.

**Docs and ledger consistency:** `gateway-configuration.md`'s new sections match the
code (the four-site table, the checkpoint operator notes, the registry semantics, the
revocation clause with its two disclosed bounds); the reserved-names list and the router
alternation both gained `consent` and stay verbatim-mirrored; `.env.example` documents
`GATEWAY_APPROVED_CLIENTS_MAX` with the fail-safe story. The threat-model ledger's
landed rows cite scenario headers that exist in the delta spec (checked name by name
against the 92 headers), and M31/M32/M33's "Placed" columns name the implementing
scenarios accurately. Comment quality holds the repo's bar: behavior and reason, no
provenance.

**The suite, run fresh:** 674 passed / 1 failed / 1 skipped — the failure is finding 1's
flake, pre-existing and unrelated (8/8 pass on re-run; the change's own evidence records
the lucky 675/1 run). Everything this change touched passes.

## Verdict

**PASS.** No blocking findings. Two should-fix findings, neither a defect in what this
change builds: finding 1 is a pre-existing flaky assertion that makes the suite's green
non-reproducible (~4.6% per run) and should be closed before the next suite-dependent
gate; finding 2 is a docstring claiming a repeated-parameter refusal the authorize
endpoint has never performed — pre-existing, but the new `state` rule inherits the
posture, so the false claim should be corrected (or the discipline enforced) rather than
carried forward. The five notes are hygiene and record-keeping. The implementation
matches the delta spec as written on every requirement walked; every subtle-bug class in
the gate brief was attacked and held; the tests assert behavior and can fail; the docs
and the ledger tell the truth about the code.
