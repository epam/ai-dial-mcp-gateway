# Review round 1 — findings and dispositions

The independent review pass (a reviewer subagent, distinct from every authoring
subagent) ran over the four planning artifacts after the final delta re-validation.
Findings file: `evidence/review-1-findings.md` (the reviewer's own record, unedited
here). This file records what was done about each finding before the owner review
pause. Verdict: 0 blocking, 3 should-fix, 6 notes; the reviewer held the package's
load-bearing claims as falsification-checked (the three mint paths' exhaustiveness in
code, the flow-id binding's secrecy from the link-crafter, the no-cookie CSRF shape,
the registry's unauthenticated-write-path absence, the live-verified external facts
behind D1/D6/D8/D9, the delta's mechanical completeness against its authoritative
baselines, the SIA's conformance to the standing method).

## Should-fix

- **F1 — tasks group 1's corruption inventory incomplete; self-contradictory target
  count.** Two whole requirements are absent outright from the corrupted main spec
  ("End-to-end acceptance on a real harness gates completion"; "App MCP resources are
  served through the apps front-door path"), and task 1.1 carried a stale "32" while
  the preamble and task 1.2 said 31. **Disposition: FIXED.** Both requirements named in
  the group 1 preamble and in task 1.1's reconstruction criteria (restored verbatim
  from the pre-sync source); the count is 31 consistently (27 pre-sync line-start
  headers + the C2 delta's 4 ADDED), with the sources governing over the number.
- **F2 — the delta did not amend "Flows are audited through their lifecycle" for the
  three new attribution events,** whose closed event enumeration would contradict the
  ADDED checkpoint requirement after the archive sync. **Disposition: FIXED.** A
  MODIFIED block for the lifecycle requirement joins the delta (baseline: the pre-sync
  spec — the C2 delta did not touch it), extending the enumeration by declared
  amendment with the three events under the checkpoint requirement's exact names
  (`attribution_required`, `attribution_approved`, `attribution_refused`), all 4
  baseline scenarios carried verbatim, one new scenario exercising the new events'
  trail. The amendment note also records why the pre-allocation-refusals requirement
  needs no twin amendment (class-based vs event-based enumeration).
- **F3 — D3's no-scope-list reasoning was false on the toolset consent branch** (the
  flow relays the toolset's advertised scopes to the upstream AS, so "scopes the flow
  does not act on" does not hold there), while D1 leans on the MCP consent-UI MUST
  that explicitly includes displaying the requested scopes. **Disposition: FIXED
  (reasoning corrected, decision unchanged, deviation declared).** The consent-branch
  fact is stated with its code citation; the omission is recorded as a declared
  deviation from that MUST member, grounded in the upstream AS's own consent screen
  displaying the scopes on the very request the approve action continues to, and in
  the short-circuit paths requesting no third-party authorization at all; the
  deviation is flagged for D10's re-judge walk to price.

## Notes

- **F4 — an undeclared THEN change in "Repeat app sign-in is silent."**
  **Disposition: FIXED** — the change is declared in the block's amendment note (the
  wording kept); the author re-audited every re-worded retained scenario for undeclared
  drift; none remains.
- **F5 — the stored-credential short-circuit's insertion function named wrong** (D2
  and task 3.5 said `_run_identity_leg`; the function is `_toolset_after_read`).
  **Disposition: FIXED in both places** — design D2 now names both functions with
  citations (the app short-circuit and consent-branch page position in
  `_run_identity_leg`; the stored-credential short-circuit in `_toolset_after_read`),
  matching the migration plan; task 3.5 corrected.
- **F6 — the CORS posture's spec home was named "the token-grant requirements" in the
  proposal and design, while the delta lands it in "Public endpoints are bounded
  against abuse."** **Disposition: FIXED in all three places** — the proposal, design
  D9, and design SIA §6's mitigation 4 now name the public-endpoints requirement.
- **F7 — invariant 3's ruling "Preserved, and strengthened" is outside the method's
  ruling values.** **Disposition: FIXED** — restated as **Preserved**, with the
  strengthening stated inside the reason column.
- **F8 — SIA §7 silent on DT-EP1-3's threat-model landing.** **Disposition: FIXED** —
  stated: no new row; a member of the existing unauthenticated-allocation class's
  memory family, narrowed by the 2048-byte bound, with the existing row's bounding note
  gaining the bound's mention.
- **F9 — D4's single-issuer keying safety rests on an unstated restart-clears
  argument.** **Disposition: FIXED** — the chain stated (no issuer dimension in the
  key; `sub` not globally unique across issuers; safety from the one-provider exact
  pin plus the restart that empties the in-memory registry), and OQ-1 now carries the
  condition a durable registry must satisfy (re-key by issuer or clear on provider
  migration). The author's own pass also corrected a stale OQ-2→OQ-1 cross-reference
  in D4's custody bullet.

## The two standing `openspec validate` ERRORs

Both are parse artifacts of the corrupted on-disk main spec, verified finding by
finding by the delta's author: every "omitted" scenario name belongs to a foreign
requirement (the authreq block welded to the federation-flow header at line 150; the
lifecycle block welded at line 441) or to an on-disk duplicate, and the "adds" are the
delta's genuinely-new scenarios plus baseline scenarios the welds destroyed on disk.
Both errors clear when tasks group 1 (the main-spec repair — the change's declared
precondition) restores the clean post-C2-sync spec. The delta is mechanically complete
against its authoritative baselines: the archived C2 delta's blocks for the eight
C2-modified requirements, the pre-sync spec (`4519c93^`) for the rest.
