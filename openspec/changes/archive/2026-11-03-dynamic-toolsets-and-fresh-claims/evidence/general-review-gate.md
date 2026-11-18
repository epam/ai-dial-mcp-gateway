# General review gate — `dynamic-toolsets-and-fresh-claims`

Reviewer: independent general-review subagent (PROCESS.md step 5.5 / CLAUDE.md gate 5).
Scope: the full uncommitted diff vs HEAD (`gateway/**`, `tests/**`, `scripts/**`,
`.env.example`, `docker-compose.yml`, `README.md`, `docs/*`, the change folder's artifacts),
reviewed against the delta spec (the contract), `design.md` (D1–D12), CLAUDE.md's
code/comment standards, and the pre-change modules for register. The security review gate
(`evidence/security-review-gate.md`) was read **last**, after this review's judgment was
formed; its findings are spot-checked only where the correctness walk touched them.

The suite was re-run by this reviewer on the current tree: **502 passed, 1 skipped**
(`.venv/Scripts/python.exe -m pytest tests/ -q`), matching the security gate's post-fix run.

## Findings

### G1 — MAJOR (gate, not code) — task 3.3, the two-harness token-store round-trip, is still undischarged, and no deferral ruling is recorded

`tasks.md` 3.3 (unchecked); `evidence/live-runs.md:348` ("PENDING — owner-driven (not this
pass)"); `evidence/security-review-gate.md` F2 and its fix record ("F2 remains open"). The
design prices this as an implementation gate, not a follow-up (design.md D3/A5: "the live
round trip through both field harnesses' token stores … as an implementation **gate**, not a
follow-up"; G5; DT-EP1-9 cat 7), and task 5.3 requires it "green in both field harnesses
before the change is done". It has not run, and the owner ruling the security gate named as
the alternative discharge ("record an owner ruling deferring it, in the change folder") does
not exist in the change folder — the fix record's "deferred by design" is not a recorded
ruling. The size bound, the raised cap, and the startup coupling check are all in place and
verified; the residual is the undriven gate itself. The change cannot be declared done, or
pushed, until the round-trip runs in both harnesses (Claude Code/CIMD and Cursor/DCR) or a
dated owner ruling deferring it lands in this folder.

### G2 — MAJOR (evidence drift) — live-runs.md Finding 2 reports an open spec-vs-code divergence that the tree has since closed, with no decision record and no live re-run

`evidence/live-runs.md:194-218` (Finding 2), `:341` (verdict row "FINDING — spec vs code
diverge"), `:439-441` ("it remains open for the owner / design pass"). The live run found
the pre-restart unredeemed code's grant **succeeding** (a custody-less refresh token minted,
failing one step later at its first refresh) against the spec's "fails its grant fail-closed".
The current tree implements the spec-first behavior: `gateway/token.py:330-363`
(`_sealed_custody_claim` refuses the grant when the pending entry is absent, under the
custody refusal class), and `tests/test_custody.py:492-585` now redeems the orphan code after
the restart and asserts the `invalid_grant` / `custody_decrypt_failed` refusal (the security
gate confirms the fix and re-ran the row green). But the evidence file still presents the
divergence as **open**, its verdict table still shows the run as a FINDING against the
current code, no artifact records who took the spec-first decision the live pass explicitly
left to "the owner / design pass", and the fixed behavior has never been re-driven on the
composed stack (unit coverage only). The evidence must be reconciled to the implemented
behavior with the decision recorded, and 3.1(3)'s pre-restart-code arm re-run live against
the fixed image.

### G3 — MAJOR — the release-notes draft still carries the pre-ruling reuse-detection bound

`release-notes-draft.md:151-152`: the time-decoupled conjunction is described as "bounded by
the IdP session clock and the provider's rotation reuse detection" — the wording that
predates the owner's reuse-detection layering ruling (design.md §8, 2026-11-01). The ruling's
layering — detection **set locally** by the provisioning (containment for the dev shape's
plain-http internal leg), TLS'd internal legs as the production bound with detection only
*recommended* as defense-in-depth — landed in `design.md` (D3/A8, §7 RES-21, the EP4 cell),
`docs/threat-model.md:349,598`, and `docs/gateway-configuration.md:606-612`, but the release
notes carry none of it: a grep of the draft finds no other occurrence of "reuse detection",
"revokeRefreshToken", or "TLS", so the stale clause is the draft's only statement of the
bound. As written it tells both audiences that production rests on a Keycloak setting that
is **off in the image default** — exactly the falsified fact the ruling re-worded everywhere
else. One-clause fix; task 6.1's "matching what actually landed" requires it before
finalization.

### G4 — MAJOR (comment discipline) — five comments carry provenance, not behavior

The repo's rule is hard: comments carry behavior and its reason, never provenance — no
ruling references, no change-folder paths, no process artifacts. Five new comments violate
it:

- `scripts/provision_keycloak.py:778` — "the local window rests on it (design.md D1
  dependency 3)". A change-folder citation that dangles the moment the change is archived
  (the path moves to `openspec/changes/archive/…`). The fact's reason is already stated in
  the same docstring; the citation adds nothing but provenance.
- `tests/test_settings.py:760` — section header "the operator material (task 1.5)".
- `tests/test_settings.py:862` — section header "the custody-era operator material (task
  2.4)".
- `tests/test_settings.py:836-838` — "matches what landed, not the pre-ruling acceptance …
  The ruling-era behavior: …". The docstring should state the asserted behavior; the
  ruling chronology is process artifact.

All five are one-line edits. In a change whose D0 discipline is the public repo it is
becoming, these are the exact class the rule exists to keep out.

### G5 — MINOR — stale vocabulary: "mapped" survives in the status route's docstring

`gateway/status.py:33` — "A **mapped** toolset's public authentication statuses". The
change's own declared re-wording is mapped→served (the delta spec's status requirement, the
design's byte-identity list); every other surface was re-worded. One word.

### G6 — MINOR — the absent/unusable authentication-kind edge is implemented but unexercised

The federation requirement's text states "a projection whose authentication-kind value is
absent or unusable falls into the impossible branch the same way a non-OAuth kind does".
Implemented structurally (`gateway/core.py` `is_oauth`: `(self.authentication_type or
"".upper() == "OAUTH"` → None/"" is not OAuth → impossible branch), and the nearest rows
cover the neighbors (`test_federation.py:1374` a non-OAuth kind; `:1529` a non-OAuth
projection not refused at the settings read), but no row feeds an absent/non-string
`authentication_type` and asserts the impossible-branch refusal. The edge is
requirement-text, not a named scenario, so the 68-row sweep could not miss it — a row is
owed anyway.

### G7 — MINOR — the `.env.example` custody-key example models a wrong shape

`.env.example:261` — `GATEWAY_CUSTODY_KEYS={"k-2026-11":{"<paste>"}}`. The value must be a
string; as written the example nests an object (`{"<paste>"}` is not valid JSON at all). An
operator pasting by the shape earns the loud parse refusal, but the one committed example of
the mapping's shape should be the right shape: `{"k-2026-11":"<paste>"}`.

### G8 — MINOR — design.md D10's `unknown_toolset` "status endpoint" home does not match the implementation

design.md D10: "`unknown_toolset` keeps its existing home at the flow's settings read **and
the status endpoint**". In the tree it lives at the flow only
(`gateway/federation.py:158-160`); the status endpoint's refusals are the guard's tokens
(`gateway/status.py:54-61`), and a Core 404 there writes no record at all
(`gateway/status.py:68-73` answers the CoreError directly). The delta spec — the contract —
requires no status-side `unknown_toolset` record post-change, so this is design-text drift,
not a code defect; the practical reachability of that Core-404 path is near nil (a phantom
name has no token addressed to it, so the audience check refuses first). Reconcile D10's
sentence or accept the drift knowingly.

### G9 — MINOR — `tasks.md`'s state contradicts the tree

Every checkbox is unchecked and the authoring note (tasks.md:3-4) still says "this change is
specified, not yet built". The implementation is complete, gated (5.1/5.2/5.3/5.8 green,
security gate run), and live-run (2.5, 3.1, 3.2). The file must be reconciled at completion
— the archive step will otherwise archive a tasks file that claims the work never happened.

### G10 — MINOR (pre-existing, named for the next pass) — the non-discovery 429s still write a `rate_limited` record per refused request

`gateway/routes.py`'s new docstring argues exactly why discovery's over-limit answer writes
nothing: the limiter does not count refused requests, so a record per refusal leaves the
record volume attacker-chosen. `/dial/token`, `/dial/revoke`, `/dial/{name}/status`, and the
callbacks still write one `rate_limited` record each (`gateway/token.py:236`,
`gateway/status.py:47`, `gateway/federation.py:84,173`). Pre-existing behavior, spec'd as
"unchanged" for those sites, and out of this change's scope — but the reasoning the F1 fix
landed now cuts against them; worth a priced line in the next hardening pass.

### Trivial

- `docker-compose.yml:56` — "requestng" typo (also noted by the security gate; still
  present).
- `docs/routing.md` — the file now ends without a trailing newline.

## Spot-audit of the conformance sweep (claimed 68/68)

The sweep's mapping (`evidence/gates.md` §5.3) was checked row-by-row for ~15 rows against
the actual tests; every cited row exists and asserts the spec's THEN, not merely that code
runs:

| Scenario | Row(s) | Verdict |
|---|---|---|
| 4 — dynamic serve, no Core call | `test_discovery.py:232` (respx `call_count == 0` — a measured negative control) | holds |
| 5 / 56 — guard-failing name at discovery | `test_discovery.py:273,285` (404) + `test_limits.py:284` (the record and its cap) | holds |
| Over-limit discovery writes no record | `test_limits.py:284` (`test_a_burst_of_discovery_refusals_is_limited_and_writes_nothing`) | holds |
| 16 — impossible branch | `test_federation.py:1374` (page text, no upstream URL, no interstitial, `non_oauth_toolset` record) | holds |
| 17 — user-level short-circuit | `test_federation.py:584,1311` + `:1502` (negative control: the advertised upstream endpoint never appears) | holds |
| 18 — global credential delegation | `test_federation.py:1342` (asserts **no signin route was ever called** — use-not-establish proven by negative control, as task 1.4 demands) | holds |
| 19 — signed-in check fails closed | `test_federation.py:1423` (absent / non-string / FAILED, each falls through) + `:1445` (app-level-only does not short-circuit) | holds |
| 20 — unknown toolset at the settings read | `test_federation.py:1473` (404 page, `unknown_toolset` record, no upstream) | holds |
| 22 / 23 — no-refresh-token and over-bound at sign-in | `test_federation.py:456,477` | holds |
| 26 — refresh token not Core-acceptable | `test_tokens.py:687,702` (the mint pair pinned: `aud == [resource]` vs `[resource, marker]`; the negative control presents the refresh token through Core's own signature/issuer/marker shape and asserts `InvalidAudienceError`) | holds |
| 52 / 53 / 54 / 55 — the four refusal classes | `test_tokens.py:874-1121` (each class lands on its committed token; `invalid_client` audits `claims_read_failed`, never `idp_session_ended`) + `:1122` (mutual distinguishability) | holds |
| 64 — grace-window stale blob | `test_tokens.py:1262` (the remedied Defect 2; verified present and green) | holds |
| 38 — status through a global credential | `test_tokens.py:1624` (the remedied Defect 1; verified present and green) | holds |
| 42 / 43 / 44 — mapping refusals and modes | `test_settings.py:378,392,467,551` (non-OAuth entry accepted; removed member refused at parse naming the field; unset mapping accepted; inference contradiction refused) | holds |

Scenario 60's "by inference" note in gates.md is honest and the inference is sound (the
default provider mock would succeed, so the asserted `invalid_grant` proves the leg was
never reached). No row was found pinned to an implementation detail that a legitimate
refactor would break; the deliberate pins (the mint-pair `aud`, the closed reason table's
committed tokens) are spec-normative facts, not incidental ones. Gap found beyond the
sweep's scope: G6 above.

## Correctness walk (verified clean, one line each)

- **Flow stage order (D11)** — exchange → per-user settings read (403-checking, kind and
  statuses carried) → signed-in check (user OR global `SIGNED_IN`, short-circuit to
  `_finish` for any kind) → kind branch (OAUTH consent / impossible branch): exactly the
  spec's order, in `gateway/flow.py:181-234` and `gateway/federation.py:99-146`; the
  OAuth-fields completeness refusal moved to the only URL builder
  (`gateway/flow.py:263-270`) as specified.
- **The guard's four sites (G1)** — one shared predicate
  (`gateway/settings.py:484-503`) applied at the protected-resource document
  (`routes.py:95`), the authorization request (`authorize.py:321`), the status path
  (`status.py:54`), and the refresh grant's resource (`token.py:596-604`); the response
  shapes match each surface's existing refusal (404 / `invalid_target`), and the reasons
  reach the trail through the closed tables.
- **The refresh grant's ladder** — rate limit → body cap → signature/type → denylist →
  resource match → name guard → subject → client, and only then decrypt and the outbound
  grant: no failing request spends a decrypt or an outbound call
  (`gateway/token.py:557-629`).
- **The custody seam** — version/key-id/length checks cheapest-first, the AEAD tag before
  any JSON, embedded `sub` and `exp` checked at the seam, header bound into the AAD,
  pinned constants, single `CustodyError` class (`gateway/custody.py`); envelope size
  arithmetic coupled to the body cap at startup (`settings.py:635-666`).
- **Fail-closed paths** — every failure of the read refuses `invalid_grant` with no
  fallback; the refresh token's payload is bindings plus ciphertext only
  (`gateway/tokens.py:229-271`); the absent pending entry refuses the **code grant**
  (spec-first, per G2); latest-wins re-encryption; rotation keeps the original absolute
  expiry; the grace window does not restart on replay.
- **The security gate's fixes, verified in place** — F1 (discovery limiter, checked before
  the guard, silent 429, spec scenario added), F3 (`custody` stripped in both copy paths
  `tokens.py:148-152,301-307`, row `test_tokens.py:425`), F4 (`_finish` clears
  `identity_refresh_token` after the hand-off, `federation.py:290`; docstrings re-derived;
  row `test_federation.py:504`), F5/F6 (docstrings now state the actual behavior).
- **Comment quality of `gateway/**`** — behavior and reason throughout; the `#nosec B105`
  suppressions are triaged in place with the reason stated (RFC vocabulary names, not
  credentials); no dead code or leftover scaffolding found in the walk.
- **Operational surfaces** — `.env.example`, `docker-compose.yml`, `README.md`, and
  `docs/gateway-configuration.md` are coherent with `settings.py`: the renamed
  `IDP_SSO_SESSION_MAX_SECONDS` propagates everywhere (grep clean for the retired name in
  operator material, asserted by `test_settings.py:865`); both restriction modes stated;
  the custody block, the size-bound/cap coupling, and the rotation-off warning all present
  and asserted by rows; the committed examples are valid JSON in both modes.
- **Threat model** — the anchor paragraph, the new rows (T1-17/18/19/21/22, T4-8, T5-7),
  RES-20–23, M21/M23, and the re-worded layering are present; my independent greps for the
  stale phrase-classes (retired setting name, role-snapshot refresh semantics, consult
  vocabulary, pre-change counts) agree with the 5.8 sweep's zero-stale result; the
  `accessTokenLifespan` mentions that remain are the identity token's own provider fact,
  not the retired gateway setting.
- **tasks.md verify-rows vs the suite** — every verify-row named requirement I checked has
  a real, asserting row (the mapping modes, the guard sites and reasons, the short-circuit
  negative controls including use-not-establish, the custody lifecycle/rotation/restart
  rows, the mint-pair pin, the refusal-class rows); task 1.6's roadmap re-statements are in
  the tree (landed with commit 4429c1f) and pinned by `test_settings.py:835,850`; task 5.7's
  `gateway/tokens.py` docstring correction is landed with the verified opt-in-logging
  wording.
- **Live-run evidence (2.5, 3.1, 3.2)** — the driven checks and the P2/P3 acceptance runs
  are real drives with redacted handles, findings reported rather than papered over, and
  the 2.5(c)/(e) findings closed by the ruling with re-runs; the one open item beyond G1/G2
  is none — 3.2's consent-branch stop is the designed OAUTH behavior, honestly marked.

## Verdict

**PASS AFTER FIXES.** The implementation is correct against the delta spec — the stage
order, the guard, the ladder, the seam, and every fail-closed path match the contract, the
suite is green (502 passed), the conformance sweep's 68/68 claim checks out under
spot-audit, and the security gate's fixes are verifiably in place. No BLOCKER; no code
correctness defect found. Before commit: G3 and G4 (one-sitting text edits), G2 (reconcile
the evidence and re-drive 3.1(3)'s pre-restart arm against the fixed image), G5/G7 and the
trivials (one-line edits), G6 (one test row). Before the change is **done**: G1 — the
two-harness round-trip gate runs, or a dated owner ruling deferring it lands in this
folder; and G9 — tasks.md reconciled at completion. G8 and G10 are recorded judgements for
the owner, not edits this gate insists on.
