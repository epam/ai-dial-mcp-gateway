# D2 baseline threat model — strict gap list (run A)

**What this file is.** The strict gap list of run A (the first of two independent
fresh runs) of the D2 baseline threat-model authoring, per
[`docs/security-analysis.md`](../../../security-analysis.md) §7 and the
`security-analysis` skill's step 10: every point where the run's allowed inputs did
not suffice, severity-tagged (Blocking / Major / Minor), plus meta-commentary on where
the method was hard to follow. Nothing was read outside the allowlist to work around
a gap; where a gap forced a judgment, the judgment is named below.

## Gaps

- **[MAJOR] G-1 — The current capability spec is outside the full-run allowlist, but
  step 7 requires verifying placement in it.** The skill's step 7 and
  `docs/security-analysis.md` §3.3 require that a gateway-owned mitigation's
  requirement "actually be in the delta spec, not only in this analysis". The
  full-threat-model allowlist names neither `openspec/specs/mcp-signin` (the synced
  capability spec) nor the archived change's delta specs — only the archived
  `design.md`'s SIA and Risks sections. Run A therefore placed every gateway-owned
  mitigation by citing the spec as the normative home, with the archived change's
  requirement-traceability table as the only allowed evidence that the requirements
  exist there; it could not verify the *current* spec still carries each one. A
  reviewer running the security review gate against the threat model alone cannot
  confirm the placements either. **Fix:** add the synced capability spec (and, for
  future baselines/re-judges, whatever spec paths exist then) to the full-run
  allowlist in `docs/security-analysis.md` §7 and in the skill's input list.

- **[MAJOR] G-2 — No as-built source for "the system as it stands today".** The
  baseline's dispositions are judged on the local development shape (plain-http front
  door on `http://localhost:8090`, file-based `.env`-injected signing key, single
  instance, in-memory state, JSON-file DCR store, internal plain-http legs, ports
  8090/8091/8080/8900). `background/design.md` describes the converged
  production-intent design, not the as-built deployment; the as-built facts are
  recoverable only from the archived change's decision sections (D2, D5–D7, D9, D11,
  D13 — see G-3) and from the run brief itself. The allowlist's two named sections of
  the archived `design.md` do not contain them. A full re-judge (D3) hits this harder
  (it must judge the production shape). **Fix:** name an as-built source in the
  full-run allowlist — the synced spec plus the committed compose/env/router
  material, or a deployment-shape document.

- **[MAJOR] G-3 — The named sections define their substance by reference to decision
  sections of the same file that the allowlist does not name.** The PoC `design.md`'s
  SIA and Risks sections state their residuals and controls through citations to
  D3 (refresh snapshot), D5 (CIMD SSRF controls), D6 (mapping safety), D7 (topology,
  ports, plain http), D9 (provisioning), D11 (DCR store), D12 (interstitial
  delivery), D13 (header family, TLS deferral). Reading only the two named sections
  leaves the residual register's accepting conditions and bounding controls
  unreadable. Run A read the cited decisions as part of the named sections (a
  citation is how a section states its content) and also the file's Context/Goals for
  the change description the SIA opens with. This is a defensible reading, not an
  allowlisted one — and run B may draw the line differently, which is exactly the
  reproducibility risk §7's comparison step exists to catch. **Fix:** name the whole
  archived `design.md`, or name the decision sections explicitly, in the full-run
  allowlist.

- **[MAJOR] G-4 — The acceptance gate's (PoC C's) recorded outcome is not in the
  allowlist.** `background/design.md`'s Appendix carries "the proxy flow itself is
  unproven end-to-end … §7's gated rows are conditional until it passes", and the
  archived design's Risks carry the same. Whether the gate subsequently passed is
  determinable from no allowed input. Run A recorded the residual (RES-18) with the
  outcome as its re-open condition rather than assuming either way. Session memory
  (auto-memory, outside the allowlist's "no prior-session context" rule) suggests the
  gate passed — which would close RES-18 — but the model cannot cite it. **Fix:** the
  full-run allowlist needs an allowed source for the implementation gate's outcome
  (the archived change's evidence folder, or the closing record), or the baseline
  must be re-run against it.

- **[MINOR] G-5 — The brief's scope boundary cites a non-allowlisted document.** The
  brief defines the D2/D3 boundary by reference to `docs/production-roadmap.md`'s
  D1/D2/D3 paragraphs, which the skill's allowlist excludes; the brief itself
  instructs treating its bullet as the statement of the boundary. Run A followed the
  brief's boundary without reading the file. The boundary a threat-model run judges
  against should live inside the run's allowed inputs, not only in the brief that
  launches it. **Fix:** either add `docs/production-roadmap.md`'s D-paragraphs to the
  full-run allowlist or restate the boundary in `docs/security-analysis.md`.

- **[MINOR] G-6 — The attack-surface inventory's granularity is ambiguous.**
  `background/design-review.md` §5.1 item 1 bundles seven-plus public endpoints into
  one entry point ("Public OAuth endpoints"), while the vendored TM instruction asks
  for "a separate table of Threats for each attack surface entry point" and
  `docs/security-analysis.md` §1 fixes the inventory at "six entry points today". Run
  A kept the six-item inventory as the unit and enumerated endpoint-level threats
  inside each table (noting E5's default-off state). If the reviewed shape wants
  per-endpoint tables, the inventory itself must be itemized finer — a method-doc
  decision, not a run judgment.

- **[MINOR] G-7 — The taxonomy has no leaf for host-file secret reads, configuration
  tampering, or information-disclosure-at-rest.** The vendored taxonomy's seven leaves
  force such vectors into Eavesdropping (a stretch: nothing is "flowing"),
  Spoofing-of-caller's-identity (chosen by what the attacker gains — the rule
  `docs/security-analysis.md` §5.4 states only for flow/logic flaws), or Injection
  (material substitution). Run A classified key theft and memory dumps as Spoofing of
  caller's identity (gains-based) and host-level tampering as Injection (substitution
  of executable/key material), and names the stretch in the tables. The gains-based
  rule should be stated as a general classification convention, not only for
  Use-Control flaws.

- **[MINOR] G-8 — E9's resource binding is not determinable from the allowed
  inputs** (open question 1 in the threat model): the endpoint inventory in
  `design-review.md` §5.1 lists `/status` among the public endpoints without stating
  whether it enforces the presented token's `resource`. Recorded as an open question
  for the reviews rather than resolved.

- **[MINOR] G-9 — `docs/threat-model.md` did not exist before this run.** Expected
  for the baseline (the per-change run's clause is "once it exists"); recorded for
  completeness. From the baseline on, the per-change allowlist's threat-model clause
  is live.

- **[MINOR] G-10 — Exact numeric limits are not as-built-verifiable.** The rate
  limits, caps, and TTL *classes* are normative in the allowed sources; their exact
  configured values in the running deployment are not in the allowlist (only
  `background/design.md` §10.3's illustrative production-intent config carries
  numbers). Run A stated the controls without pinning numbers.

## Meta-commentary — where the method was hard to follow

- **The per-threat eight-category grid at baseline scale is the heaviest part of the
  method, and the skill itself calls the grid "working paper" against the grouped
  list's "reviewed result".** At ~35 threats × 8 categories the grid dominates the
  document, and most cells are bounding or not-applicable statements that repeat
  across threats of the same shape. The method should state explicitly whether the
  *baseline document* must carry the full grid (run A wrote it in full, per the
  brief's "mitigations for every threat considered from every control category") or
  whether the baseline may carry the grouped list plus the deltas from it. Left
  implicit, two independent runs will diverge in volume even with identical threat
  sets — noise for the §7 reproducibility comparison.
- **The register-first step and the document's reading order pull against each
  other.** The skill assembles the disclosed-residual register first (its content is
  an *input* to threat enumeration — several threats exist only because a residual
  bounds them), but the brief's structure places residuals late in the document. Run
  A assembled first and placed the register after the threat tables, with a preamble
  note. The method doc should say which order the *document* carries.
- **"Placed — normative in this repo" was genuinely hard to satisfy without G-1's
  fix.** Placement is the load-bearing distinction of this repo's method (a
  mitigation that exists only in prose "is not landed"), and the full-run allowlist
  contains no document where gateway behavior is normative today except by
  inference. This is the single change that would most improve the next run.
- **The compromise-point tables carry forward cleanly; the attacker inventory does
  not.** §6.4/§5.5 give the current shape in maintained prose, but no allowed input
  lists the attackers for the *local* shape (workstation processes, second users,
  compose-network peers, the host operator) — run A constructed it from the trust
  boundaries and the shape facts. It is the section most likely to diverge between
  runs; a maintained attacker list in the method or the baseline's successors would
  pin it.
