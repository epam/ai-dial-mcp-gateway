# Independent review — round 2 (the folded layer: the 2026-11-07 rulings, D11–D14, and coherence after the fold)

Reviewer: the round-2 independent reviewer (a fresh subagent, not the author, distinct
from the round-1 reviewer). Scope: **the delta since round 1** — the owner's 2026-11-07
rulings folded in (B-1+B-3, B-2, B-5 accepted; B-4 deferred with reasoning; D6's
record-wording accepted), the new decisions D11–D14, the SIA's new rows and mitigations
(M32/M33, DT-EP1-5/6, RES-25, the impact re-check), the three new delta blocks (client
registration, DCR durability, issued tokens) plus the B-5 discovery amendment, the
re-walked RFC 9700 re-judge report and its falsification review, and cross-artifact
coherence after the fold. Round 1's findings and their dispositions
(`evidence/review-1-findings-and-dispositions.md`) were read and are not re-litigated
here. Method: falsification — nothing was fixed, no artifact outside this file was
touched.

Inputs read in full: the four change artifacts; the round-1 findings and dispositions;
`evidence/rfc9700-rejudge-report.md` (588 lines, both corrections) and
`evidence/rejudge-report-review.md`; `docs/threat-model.md` (the T1-25 row and its
dispositions entry, the M-register through M30, the grouped mitigation list, the RES
register — RES-1/5/11/12/15/21/23/24 read in full — the attacker model, the EP1/EP3
tables); `docs/security-analysis.md` (the threat-table and mitigation-order format);
the authoritative baselines — the pre-sync spec (`git show
4519c93^:openspec/specs/mcp-signin/spec.md`) for the three new blocks (the archived C2
delta did not touch client registration, DCR durability, or issued tokens; verified
against its block list) and the archived C2 delta's discovery block for the B-5
amendment; the gateway code the new decisions cite (`gateway/routes.py`,
`gateway/cimd.py`, `gateway/settings.py`, `gateway/store.py`, `gateway/token.py`,
`gateway/state.py` — the cited ranges). External, fetched live:
`modelcontextprotocol.io/specification/versioning` (the current-revision claim), the
`2026-07-28` authorization index and authorization security-considerations pages (the
redirect-URI MUST, the localhost-warning SHOULD, the redirect-hostname-display MUST,
the `iss` emission SHOULD and advertisement MUST, the Bearer mandate, the
refresh-tokens SHOULD NOT), and the `2026-07-28` deprecated-features registry (the DCR
deprecation row). `openspec validate --type strict` was run (only the two known ERRORs
— the corrupted on-disk spec's authreq and lifecycle parse artifacts — stand; the three
new blocks validate clean). The publication leak check was run (PASS, 0 unwaived
findings, none in the change folder).

## What held under falsification (the findings below start from a verified floor)

- **The three new delta blocks are mechanically complete against their baselines.**
  Client registration: the pre-sync text is carried whole (paragraph 1 verbatim), the
  admission rule arrives as a new paragraph with a declared amendment naming its three
  sites and explicitly delegating the fourth to the DCR-durability block, all 6
  baseline scenarios carried verbatim, 4 added (10 total — the declared count). DCR
  durability: baseline carried whole, the load-path clause declared, 6 retained + 1
  added (7). Issued tokens: the pre-sync text (including the C1.5-era retained
  scenario-amendments note, correctly marked retained) carried whole, the code clause
  extended by the declared B-2 amendment, 5 retained + 1 added (6). Discovery: the C2
  archived block's text and both retained amendment notes carried, the B-5 member
  declared as a third amendment, 5 retained verbatim + 1 added (6). Scenario counts
  reconcile with the declared amendments; the delta totals 11 MODIFIED + 2 ADDED, 92
  scenarios, as the fold claims. `openspec validate` confirms no new validation
  error beyond the two known corrupted-spec artifacts.
- **The report's currency claims are true on the current pages, verbatim.** The
  versioning page states "The **current** protocol version is 2026-07-28". The
  `2026-07-28` authorization security-considerations page carries, word-for-word:
  "All redirect URIs **MUST** be either `localhost` or use HTTPS" (Communication
  Security, beside "All authorization server endpoints **MUST** be served over
  HTTPS"); "**SHOULD** display additional warnings for `localhost`-only redirect
  URIs" and "**MUST** clearly display the redirect URI hostname during authorization"
  (Localhost Redirect URI Risks). The authorization index carries, word-for-word: the
  `iss`-emission SHOULD "including error responses", the advertisement MUST
  ("**MUST** advertise this by setting `authorization_response_iss_parameter_supported`
  to `true` in their metadata", RFC 9207 §2.3), the stated intent to upgrade the SHOULD
  to MUST, and the `Authorization: Bearer` mandate with DPoP absent from the page. The
  deprecated-features registry's DCR row matches the report exactly (PR #2858,
  deprecated in `2026-07-28`, migration path Client ID Metadata Documents, earliest
  removal "First revision released on or after 2027-07-28"). B-1/B-3, B-4, and B-5's
  normative bases are the current contract's, not an old text's.
- **The code facts the new decisions rest on are real.** The DCR body check validates
  type/count/length only (`gateway/routes.py:336-357`, `_redirect_uris_refusal` — no
  scheme clause); the CIMD document's `redirect_uris` are accepted string-only
  (`gateway/cimd.py:307-317`); pre-registered `redirect_uris` are a bare `list[str]`
  (`gateway/settings.py:169-175`); the store's load path (`gateway/store.py:70-116`)
  validates file shape and record shape and never re-checks redirect URIs, so
  "client resolution reads the store without re-checking" is true and the
  load-time-refusal site is genuinely missing as built; the replay refusal is
  claim-once with no consequence (`gateway/token.py:452-458`,
  `runtime.replay.claim`); the denylist exists with `revoke` in `/dial/revoke`'s own
  shape and is consulted at every refresh grant (`gateway/state.py:360-396`,
  `gateway/token.py:581-582`). The falsification review's B-1/B-2 verification holds
  on this worktree's code.
- **The fold itself is real and complete in its verdict layer.** The rejudge review's
  five findings are all folded into the corrected report: the Part 6 buckets are now
  disjoint and sum (55+9+2+6+22+5 = 99 over 98, the one declared split — the
  communication-security row's two MUSTs); the source-currency catch produced the
  `2026-07-28` re-walk with the two CIMD display statements scored (the
  hostname-display MUST discharged by the pending delta with both bounds disclosed;
  the localhost-warning SHOULD as B-4); B-1's row names the fourth site; B-2's row
  discloses the rotation-successor partial; the priced list names its 8 rows. The
  owner's ruling is recorded consistently in D10 (with the checkable reconciliation of
  the four-row and B-5 rulings into the re-walked partition), §7, OQ-3, the proposal,
  and the tasks — the final partition 55/13/3/6/22 = 99 is stated identically in all
  of them. No "2025-11-25 as current" framing survives in the artifacts (the design's
  Context carries the corrected citation; the remaining mentions are honest
  historical records of the catch), and no still-open conditional framing remains.
- **The SIA's new material conforms to the method.** DT-EP1-5 ("Interception →
  Eavesdropping") and DT-EP1-6 ("Use Control Misconfiguration → Elevation of
  Privilege → Bypass Authorization") use established leaf categories of the vendored
  taxonomy (both appear verbatim in the standing model's tables; DT-EP1-6's leaf
  follows the attacker's gain per the method's convention), with honest footprints
  and compromised-dimension values; M32 and M33 are tabled in §5 with all eight
  control categories in the fixed order, "not applicable" rows carrying
  threat-specific reasons; the impact-level re-check (Medium stands) is reasoned —
  the additions narrow exposure, and what they bring for review is refusal behavior
  on existing surfaces; the invariant table is untouched, correctly (no folded
  mechanism touches an invariant's subject).
- **The new decisions' soundness holds where I tried to break them.** D11's
  load-time-refusal fail mode is the corrupt-store discipline's own shape (the
  existing requirement already refuses startup over an unparseable store rather than
  silently dropping clients; a skipped-and-logged record would be exactly the silent
  partial drop that discipline exists to refuse), the planted-record shape adds no
  capability its host-boundary attacker (T7-1's class) does not already hold
  (corrupting the store achieves the same outage), and the migration consequence is
  stated honestly (a pre-rule record refuses startup loudly; the remedy — rename
  aside or remove the record, re-register — is named; the design does not call it
  anything but a visible behavior change). D12's two partials are stated as the
  clause's bound in the delta itself (the scenario asserts the bound, not a wider
  implication), the eviction-shaped escape (a flooded memo cap evicting the entry
  before the replay) is covered by the disclosed detection-timing bound, and the
  RFC's own scenario (the thief, not the legitimate client, detected by the race) is
  characterized correctly. D14's no-new-threat claim is reasoned and right: a fixed
  boolean member on an existing static, validated, test-pinned document narrows
  nothing and adds nothing attackable; the §6 note beside the numbered mitigations
  is the correct treatment (no M-number double-count). D13's deferral *logic* (an
  attacker with local code execution holds strictly cheaper attacks than the
  localhost-impersonation harvest) is sound — the citation grounding it is finding 5
  below.
- **Publication discipline holds in the new text.** The leak check passes with zero
  unwaived findings; the new sections cite public sources, RFC numbers, and
  repo-relative paths only; the TS-SDK/PR facts are public GitHub material.

## Findings

### Should-fix

1. **[should-fix] The folded layer's threat-model delta has no landing task — DT-EP1-5,
   DT-EP1-6, M32, and M33 appear nowhere in `tasks.md`.** Location:
   `openspec/changes/as-security-hardening/tasks.md` — task 2.1 (the threat-model
   delta task, which enumerates its rows: the forged-approval and registry-flooding
   rows, the three decision-page rows — stopping at the round-1 set), task 2.2 (the
   §6-anchored re-read checklist names §6's items 1–6 of 8), task 6.1 (its
   consistency check names T1-25's flip, RES-11's re-price, the DPoP record), task
   8.4 (its falsification-focus list names the five checkpoint threats). Problem:
   design §7 explicitly lands the cleartext-redirect-delivery row (DT-EP1-5) and the
   token-family-survival row (DT-EP1-6) in the model's EP1 table, and M32/M33 into
   the grouped mitigation list ("M32 and M33 join with it", §7's third bullet), and
   SIA §2 says the security-review falsification focus "gains the two new
   mitigations' rows (DT-EP1-5, DT-EP1-6 below)" — but no task carries any of it
   (grep-verified: zero occurrences of DT-EP1-5, DT-EP1-6, M32, M33 in tasks.md). An
   implementer following the task list literally lands the model without the two rows
   and the two mitigation records, leaving the SIA's §7 delta half-landed and the
   conformance ledger (group 6) citing M32/M33 records that do not exist in the
   model — against the standing order the tasks themselves invoke ("a mitigation
   that exists only in prose is not landed"). The proposal's catch-all ("any
   mitigation the change places is recorded as placed") does not repair an
   enumeration the implementer reads as complete. Suggested direction: extend task
   2.1 with the two EP1 rows (their controls and disclosed bounds per SIA §4/§5) and
   the M32/M33 grouped-list joins; add §6's items 7–8 to task 2.2's checklist; add
   the rows to task 6.1's consistency verification and task 8.4's falsification
   focus.
2. **[should-fix] B-2's spec home is misnamed in the design — the delta lands it
   elsewhere.** Location: `design.md` D12's closing ("Spec home: the public-endpoints
   requirement's token-grant clause (the same requirement the CORS posture landed
   in…)"), SIA §6 item 8 ("spec — the public-endpoints requirement's token-grant
   clause"), and DT-EP1-6's mitigation 1 ("spec — the token-grant clause").
   Problem: the delta's actual landing is the **issued-tokens** requirement
   ("Issued tokens are gateway-signed and audience-marked") — its declared amendment
   says "the requirement's code clause gains the revoke-on-double-redemption rule",
   and the new scenario ("A replayed code kills the refresh token it bought") sits in
   that block; the public-endpoints requirement's amendment carries only the CORS
   posture. The code clause the rule extends ("The authorization code MUST be
   single-use, PKCE-bound, short-lived, with replay rejected") lives in the
   issued-tokens requirement, so the delta's choice is the right one — the design
   followed the report's remedy sketch (which named the public-endpoints home
   pre-ruling) and was not updated when the delta landed the clause where the code
   clause actually is. This is round-1 F6's exact class (spec home named wrong,
   fixed "in all three places" then). Suggested direction: re-name the home in D12,
   §6 item 8, and DT-EP1-6's mitigation-1 parenthetical as the issued-tokens
   requirement's code clause.
3. **[should-fix] SIA §6 item 6 carries a stale, arithmetically wrong partition.**
   Location: `design.md:1404` — "with the post-ruling partition 53/12/3/6/21".
   Problem: 53+12+3+6+21 = 95, not 99 over 98; the post-ruling partition is
   55/13/3/6/22 (D10's reconciliation, §7's ledger bullet, and OQ-3 all state it
   identically, and the report's Part 6 pre-ruling buckets verify against it). The
   stale figure is the pre-re-walk 94-row-era partition; left as-is, the conformance
   ledger's structure description (which task 6.1 builds from "the report's Part 6
   partition") carries a contradictory count in the SIA's own mitigation record.
   Suggested direction: one replacement — 55/13/3/6/22, 99 verdicts over 98 rows.
4. **[should-fix] The design's Non-Goals deny a change the fold makes: "No change to
   the CIMD/DCR registration surfaces beyond naming their resolved facts on the
   page."** Location: `design.md` Non-Goals, sixth bullet. Problem: D11 (owner-ACCEPTED)
   adds the redirect-URI scheme admission rule **at the DCR registration body check,
   the CIMD document validation, the pre-registered settings, and the DCR store's
   load path** — a validation clause on exactly those surfaces — and the delta
   amends the client-registration and DCR-durability requirements accordingly. The
   Non-Goals list was not revisited when the ruling folded in, so the design's own
   scope boundary now contradicts one of its owner-accepted decisions; a reader
   taking Non-Goals as the contract (as the owner's final pause does) would rule
   B-1's implementation out of scope. The bullet's evident intent — the registration
   *controls* (the fetch discipline, the DCR flag, the priority order) stay M7's and
   the flag's — is not what the sentence says. Suggested direction: scope the bullet
   to the registration controls ("no change to the CIMD/DCR registration surfaces'
   controls — the fetch discipline, the flag's default, the resolution priority —
   beyond the redirect-URI admission rule (D11) and naming their resolved facts on
   the page"), or drop the bullet.
5. **[should-fix] D13's deferral grounds cite a residual that does not carry the
   acceptance attributed to it — the "RES-23 local-compromise floor" chain.**
   Location: `design.md` D13 ("local code execution is **RES-23's accepted
   local-compromise floor**: an attacker with it holds strictly cheaper attacks (the
   harness token store is on that host)"), echoed in tasks 6.3 ("inside the accepted
   local-compromise floor — RES-23's pricing class"), SIA DT-EP1-5 ("a
   compromised-client shape, RES-23's class") and DT-EP1-6 ("a compromised client or
   leaked pair, RES-23's class"). Problem: RES-23 as recorded
   (`docs/threat-model.md:427-433`) is "the ungated harness token stores" — an
   **availability** residual accepting that stores beyond the two field-proven ones
   are unverified and may break on the grown token's size; its record says nothing
   about local code execution, and no record anywhere in the model carries a
   "local-compromise floor" acceptance (grep-verified: no "local compromise"/"local
   code execution" occurrence in `docs/threat-model.md`). The deferral's *reasoning*
   is supportable on rows that do exist — the attacker model's class 3 ("a second
   workstation user / workstation malware — on a shared or compromised machine:
   reads the harness's token store, the browser, or the loopback redirect"), class 4
   (the malicious or compromised harness), T1-3's stolen-token replay pricing, and
   RES-21(i)'s machine-control statement ("adds nothing to an attacker who controls
   the machine it sits on") — but as written, RES-25 will land (task 6.3) grounded
   on a citation a reader of the model cannot verify, the same defect class the
   M24→M7 correction exists to fix. Suggested direction: re-ground the chain on the
   rows that carry it (attacker-model classes 3/4, T1-3's pricing, RES-21 part i),
   or declare in §7's delta a widening of RES-23's record to name the
   local-compromise acceptance explicitly — a declared model change, not a silent
   re-read of an existing residual.
6. **[should-fix] Stale D-ranges after the fold: "D1–D13" where the decision set is
   D1–D14.** Location: `design.md` Migration Plan item 5 ("the owner review pause
   carries the dispositions (D1–D13)"); `tasks.md` task 8.5 ("coherence with the
   design's decisions D1–D13"). Problem: D14 (the `iss` advertisement, an
   owner-ACCEPTED finding with its own delta amendment and task 5.3) postdates both
   sentences; as tasked, the general review gate's charter omits the decision behind
   one of the change's accepted findings. Suggested direction: D1–D14 in both.

### Notes

7. **[note] The replay memo's retention bound is stated as "the refresh window" while
   every store family it can ride is minutes-bounded by the code's life.** Location:
   `design.md` D12 ("records `code_id → refresh_jti`, held for the refresh window
   (the replay cache's own store family, TTL-bounded)"); the delta's issued-tokens
   clause ("records the code's id against the refresh token it issues, bounded by
   the refresh window"). Both candidate stores (`ReplayCache`, `PendingCustodyStore`,
   `gateway/state.py`) are TTL-bounded to the code's short life, and no replay can
   be *detected* after the code expires (an expired code is refused on the
   expiry path, which never consults the memo) — so the code TTL is the natural and
   sufficient bound, and "the refresh window" over-states retention (the revocation
   itself persists correctly regardless: the denylist entry lives to the token's own
   `exp`). Not a soundness defect — the disclosed detection-timing bound covers the
   eviction/expiry shapes — but the task-5.2 test could pin either reading, and the
   clause should name the bound the implementation will actually carry (the code
   TTL), or name the longer TTL as a deliberate choice.
8. **[note] The falsification review file still opens with the superseded
   "current 2025-11-25 revision" premise, unmarked in its own text.** Location:
   `evidence/rejudge-report-review.md` header ("the current 2025-11-25 revision")
   and its 91-row counts. The corrected report's header records honestly that "this
   report and the review had both assumed" 2025-11-25, so the record is discoverable
   — but a reader who opens the review file first reads a wrong currency claim with
   no in-file marker (the round-1 pattern — the reviewer's record unedited plus a
   dispositions companion — would keep the evidence folder self-consistent). A dated
   one-line correction note at the top of the review file, or a short dispositions
   companion recording the re-walk's effect on each of its five findings, would
   close it.
9. **[note] The proposal's Modified-Capabilities phrase "the two owner-accepted
   findings land as the delta's two further requirements" misdescribes the landing.**
   Location: `proposal.md` Modified Capabilities. B-1's rule spans **two** MODIFIED
   blocks (the client-registration requirement and the DCR-durability requirement —
   the fourth site), and B-2's clause lands in a third (the issued-tokens
   requirement); immediately after a sentence about ADDED requirements, "two further
   requirements" reads as two more ADDED blocks and undercounts the blocks. The
   substance is right elsewhere in the proposal (the B-1 bullet names all four
   sites); naming the three requirements here would keep the capability summary
   exact.
10. **[note] SIA §4's touched-entry-point preamble declares the EP2→EP1 consolidation
    but is silent on the settings and store-load sites' entry-point homes.**
    Location: `design.md` SIA §4 preamble. The CIMD document check's tabling at EP1
    is declared ("no separate EP2 row"); the pre-registered-settings check (operator
    configuration, validated at startup) and the DCR store's load path (the
    host/volume boundary, where the planted-record threat T7-1 lives — EP7's
    territory) get no equivalent sentence, though DT-EP1-5's entry-point cell names
    all four sites transparently. One clause naming those homes (and T7-1's row as
    the planted shape's existing price) would make the table's placement fully
    declared rather than implicit.

## Verdict

**0 blocking, 6 should-fix, 4 notes.** The folded layer is substantively sound: the
three new delta blocks are mechanically complete against their authoritative
baselines with declared amendments and honest bounds; the re-walked report's
load-bearing currency claims are verbatim-true on the current `2026-07-28` pages
(five spot-checks, including the DCR deprecation registry row); the code facts under
B-1/B-2/B-5 are real in this worktree; the partition arithmetic reconciles to 99
over 98 with the one declared split everywhere it is stated; the SIA's new rows and
mitigations conform to the standing method; and D11–D14's mechanisms, fail modes,
and disclosed partials survived the attempts to break them. Every finding above is a
fold-seam defect — a task list, a spec-home name, a stale count, an un-revisited
Non-Goal, a mis-grounded citation, a stale range — each mechanically fixable without
moving any decision or any spec text. **Ready for the owner's final pause once the
six should-fixes land** (findings 1–6; the notes may land with them or be
dispositioned). None of them falsifies a design claim, a delta requirement, or a
ruled disposition; finding 1 is the one that matters most, because without it the
standing order's own rule — a mitigation that exists only in prose is not landed —
would be violated by the change's own task list.
