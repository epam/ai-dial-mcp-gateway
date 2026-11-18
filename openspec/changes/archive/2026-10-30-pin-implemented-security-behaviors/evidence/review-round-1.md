# Independent review — round 1 (PROCESS.md step 3b)

Reviewer: independent review pass (not the authoring pass). Scope: the full artifact
set (`proposal.md`, delta `specs/mcp-signin/spec.md`, `design.md`, `tasks.md`,
`release-notes-draft.md`) verified against the implementation, the tests, the main
spec, the threat model, and `docs/security-analysis.md`. `openspec validate
pin-implemented-security-behaviors --strict` run by this reviewer: **clean**. The
cited tests were run (not just read): all pass. The empirical JWT probe was re-run
against the repo venv (pyjwt 2.15.1): both claims reproduce.

## Findings

### F1 — MAJOR — the scenario-to-evidence record miscounts and leaves one test-path-less scenario undisclosed

`design.md` §D2 (lines 186-195) claims "**ten of the eleven scenarios rest directly
on named existing tests**", disclosing only the `alg: none` and embedded-`jwk`
scenarios as library-semantics. The delta spec carries **twelve** scenario blocks
(3 + 3 + 3 in the ADDED requirements, 3 in the MODIFIED block). Counting what rests
on a named existing test: `iss` success, `iss` error, whole-story, refused/failed
leg, credential-free, `kid`-absent, non-OAuth, reserved-name, charset — **nine**,
not ten; and no reading of "eleven" matches any enumeration. Worse, a **third**
scenario with no dedicated test row is not disclosed at all: delta spec lines 17-19,
"A harness matches `iss` against the AS metadata document". It is grounded in fact
(`tests/test_federation.py:920-932` asserts `iss == ORIGIN`;
`gateway/discovery.py:57-59` builds the AS metadata `issuer` from the same
`gateway_public_origin` setting) — but it rests on the *conjunction* of two pinned
behaviors, not on a named test, and the change's own rule (`design.md` §D2: "the
mapping is recorded here rather than left implicit") is violated for it. Per the
repo's rule — a scenario without a test path is a conformance row that can lie —
task 3.1's walk (lines 83-88, "each maps to a named existing test or to the
pinned-call library semantics") would find this scenario outside both recorded
categories.

**Failure scenario:** at task 3.1 the conformance walk hits the metadata-match
scenario, finds no recorded grounding for it, and either silently passes it (the
row lies) or stalls the walk on a gap the artifacts should have closed.

**Fix (wording only; no delta change):** correct §D2 to the real count, and add the
metadata-match scenario to the disclosed list with its actual grounding (the
conjunction of `iss == ORIGIN` and the AS-metadata issuer scenario already pinned in
the main spec). Mirror the same clause in task 1.1 and task 3.1.

### F2 — MINOR — the `iss` delta cites T1-4, which the threat model does not support

`proposal.md` line 29 and `release-notes-draft.md` line 16 cite
"T1-4/T1-12/T1-13"; `design.md` line 44 says "T1-4 is the mix-up threat the
parameter defends". In `docs/threat-model.md`, the RFC 9207 `iss` defense lives in
**T1-13's** Data Protection row (line 723) and M9's row (line 1554) addresses
T1-12/T1-13 — not T1-4. T1-4's own grid (lines 556-574) never mentions `iss`, and
its disposition cites M4/M5. The load-bearing citations (M9, T1-13) are accurate;
T1-4 is thematic padding that a future reader will fail to trace. Fix: drop T1-4
from the three artifacts or rephrase as "the mix-up class T1-4/T1-13 belongs to".

### F3 — MINOR — the provider leg's kid-less fallback is unpinned, and silence here is the drift risk

Delta spec lines 39 and 49-51 pin `kid` resolution only for a `kid` that is
*present*. The code (`gateway/idp.py:296`, `if kid and document.get("kid") != kid`)
falls back to the **first RSA signing key in the provider's JWKS** when the token
header carries no `kid` at all — an accepted, not refused, token. The delta neither
states nor forbids this, so the sync does not mis-pin — but a future re-implementer
working from the spec text alone could refuse kid-less tokens, a silent behavior
change in exactly the drift direction this change exists to close. Fix: either add
one clause naming the fallback, or record it in `design.md`'s open questions beside
the dedicated-row question. Not a blocker: the pinned scenario (kid *names* an
absent key → refused) is accurate to `idp.py:308-312`.

### F4 — MINOR — Delta 2's evidence section overstates two test_limits rows

`design.md` lines 66-70 say the credential-free measurements
"(`tests/test_limits.py:690`, `:734`) — each asserts the values genuinely existed
during the run and are absent from the populated log". Those two rows are
**structural** field-set controls (records' keys ⊆ an allowed set, with a
negative control that the log is populated); the value-existence-and-absence
instrument is `test_audit.py:289+` and `test_federation.py:951-982`. Both
groundings are valid; the sentence ascribes the wrong one to the test_limits rows.

### F5 — MINOR — the orphan `docs/threat-model.md` working-tree edit needs a tracked home before this change commits

The working tree carries an uncommitted `docs/threat-model.md` edit re-placing
T5-5/T5-6's timeout and parsing controls from "(spec)" to "repo" (dated 2026-10-30)
— the falsification of citations this change's out-of-scope rationale brushes
against. Task 2.1 discloses it ("not this change's and is not staged with it"),
which is honest, but it currently belongs to no change folder, and this change
asserts "no edit to `docs/threat-model.md`" as a non-goal. Verified: it does not
touch M9/M10/M11/M20 or the T4-7/T6-2/T6-7 grids, so it cannot collide with task
3.2's flips. Fix: give it an owner-approved home (its own change folder or a ruling
on record) before this change's commit, so the "spec-only diff" claim stays true of
what is actually committed.

## Focused falsification of the SIA's "No impact" claim — claim survives

Run per CLAUDE.md gate 4's duty, at focused depth:

- **Does any delta text change what an implementer would build?** Walked every
  requirement against the code. Delta 1: the only client-facing redirects are
  `harness_redirect` (`gateway/federation.py:257-258`) and `redirect_error`
  (`gateway/authorize.py:156-162`); the one other `RedirectResponse`
  (`gateway/authorize.py:170`) goes to the identity provider, not the client, so
  "every authorization response returned to the client" is exactly the population
  the code covers, no more. Both `iss` sources and the AS metadata `issuer` derive
  from the single `gateway_public_origin` setting — the metadata-match scenario
  holds. Delta 2: the requirement's event list, discipline sentence, and fact fields
  match `gateway/audit.py` emitters, `_CALLER_FACT_FIELDS`, and `_bounded` exactly;
  wiring verified at `authorize.py:164`, `federation.py:118-258`,
  `token.py:210/430/498`, `routes.py:158`. Delta 3: matches
  `tokens.py:286-294` and `idp.py:47/255-264/273-312` (one nuance → F3). Delta 4:
  matches `settings.py:40` and `_validate_mapping` (charset-first order, message
  naming the charset) and `router/nginx.conf`'s two regexes character-for-character.
  **No delta line demands behavior the code does not have.**
- **Empirical claims re-tested:** the probe run against the repo's own venv
  reproduces both — `alg: none` refused with `InvalidAlgorithmError`; a token whose
  header embeds the very `jwk` that signed it refused with `InvalidSignatureError`
  (the embedded key was the signing key, so refusal proves the header key is never
  consulted). A fourth falsifier (HS256 confusion) could not even be minted: pyjwt
  2.15.1 refuses an asymmetric PEM as an HMAC secret at encode time; moot given the
  algorithm-allowlist refusal.
- **Out-of-scope smuggling:** none. The delta contains no CIMD content-type,
  timeout, User-Agent, or response-parsing text; the four deltas are the whole
  delta (`openspec validate --strict` clean, four deltas).
- **SIA shape:** conforms to `docs/security-analysis.md` §5 — all eight steps
  present; the invariant ruling table's seven rows match `ROADMAP.md`'s never-cut
  list one-for-one; threat tables carry the vendored columns; mitigations in
  category order with threat-specific N/A reasons; grouped list; threat-model delta
  deferred per the standing rule; open questions present. The two doc-surface
  threats (spec mis-pinning, spec/implementation drift) are the right enumeration
  for a spec-only diff, and the SIA's own text correctly invites this falsification.

**Verdict: the "No impact" claim stands.** The only drift-direction residue found is
F3's unstated fallback — an omission, not a mis-pin.

## The test-debt question — explicit answer

**Acceptable as disclosed, with one correction.** The `alg: none` and embedded-`jwk`
scenarios are acceptably grounded: the re-runnable probe (re-run and reproduced by
this reviewer), the foreign-key/unpublished-key/foreign-issuer tests
(`test_token.py:376`, `test_tokens.py:568/893`, `test_federation.py:290/320` — all
run, all green), and pyjwt's documented semantics for the pinned call shape; the
dedicated-unit-row follow-up is correctly a code-side open question, not this
change's. The `iss`-metadata-match scenario is equally acceptable *in substance* but
is **not** disclosed as test-path-less, and the recorded count is wrong (F1). The
delta spec itself needs no change; `design.md` §D2 and tasks 1.1/3.1 must say so
explicitly, per the repo's own rule.

## Clean areas (verified, one line each)

- Delta 1 vs code and tests: exact — `flow.py:381`, `errors.py:79-83`,
  `authorize.py:156/161`; both cited tests exist, assert the claim, and pass.
- Delta 2 vs code and tests: exact — emitters, wiring, and discipline match; the
  three cited audit tests and `test_federation.py:951` exist and pass.
- Delta 3 vs code and tests: exact at both call sites; all five cited tests exist
  and pass; the empirical probe reproduces.
- Delta 4 vs code, router, and tests: exact — charset, startup order (charset
  before reserved), error text, `nginx.conf` regexes, and the `jwks.json` fidelity
  nuance; all cited tests exist and pass (including the parametrized five).
- MODIFIED block fidelity: retained prose is a byte-identical prefix and both
  existing scenarios are byte-identical (verified mechanically, not by eye); only
  the charset sentence and one scenario are appended.
- Main-spec staleness confirmed: no `iss`/RFC 9207/charset requirement exists today;
  the sync target is real, and the direction is spec-behind-implementation, as the
  mandate requires.
- Delta format: conforms to the main spec's conventions (MUST keywords, `####
  Scenario:` blocks, WHEN/THEN shape); `openspec validate --strict` clean.
- Mandate citations: M9/M10/M11/M20 placement notes and the T4-7/T6-2/T6-7/T1-13/
  T1-16 grids verified as quoted (T1-4 excepted — F2); `background/design.md` §6.1
  controls 3 and 4 verified.
- Task 3.2's deferral of the M9/M10/M11/M20 placement flips out of this diff is
  consistent across proposal, design, tasks, and release notes, and the uncommitted
  threat-model edit does not overlap the entries it will flip.
- Cross-artifact consistency: all five artifacts agree on scope (four deltas, three
  ADDED + one MODIFIED), the out-of-scope list, the spec-only claim, and the
  verification story.

## Overall verdict

**LAND AFTER FINDINGS.** No blocker; the delta spec itself is accurate to the
implementation on all four behaviors and needs no change. F1 (a wording/evidence
correction in `design.md` §D2 plus tasks 1.1/3.1) should be resolved before the
owner pause, because the verify-first evidence record is this change's central
deliverable and its arithmetic is presently wrong. F2-F5 are minor and can be
folded into the same pass or answered on record at the owner pause.
