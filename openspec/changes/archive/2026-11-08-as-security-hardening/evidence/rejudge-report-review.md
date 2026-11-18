# Independent review — the RFC 9700 re-judge report

> *Currency note (2026-11-07, later the same day):* this review verified source
> currency against the `2025-11-25` revision as "current"; the actual current
> revision is **`2026-07-28`**. The report was subsequently re-walked against it
> (zero verdict changes; all bases verbatim-stable or strengthened; one new finding,
> B-5). The review's per-finding substance stands; its currency claims are superseded
> by the re-walk recorded in the report's header.

Date: 2026-11-07. Reviewer stance: falsification — an independent pass over the report's
coverage, verdicts, citations, sizes, and internal consistency, run against the RFC text
(rfc-editor.org, fetched in full), the MCP authorization specification and security best
practices (modelcontextprotocol.io, both the 2025-06-18 text the report says it walked and
the then-latest 2025-11-25 revision), the MCP TypeScript/Python SDKs and the ext-auth
repository (primary GitHub sources), the gateway code in this worktree, and the change's
design and threat-model records. Findings only — the report was not edited.

## Findings

1. **[should-fix] Part 6, the four-value disposition mapping — the buckets do not
   partition the 91 rows.** The mapping states "*already satisfied*: 60 rows outright
   plus 8 held-as-priced", then lists "*accepted with reasoning*: the 8 priced rows" as a
   fourth bucket — the same 8 rows assigned to two dispositions. Worse, the
   "*landed by this change*" bucket (§4.11.2's three rows, the confused-deputy MUST and
   its mitigation details, the CORS posture rule, the `state` rule, the `auth_time`
   strip — seven-plus rows) is presented as separate from "already satisfied", yet every
   one of those rows is counted inside the summary's 60 (a) SATISFIED. As written, the
   four buckets overlap and sum past 91. The summary table itself reconciles exactly
   (verified: 27+40+5+19 = 91 rows; 60/8/3/21 = 92 with the declared communication-security
   split), so the defect is confined to Part 6's mapping prose — but D10 names that
   mapping as the thing the conformance ledger in `docs/threat-model.md` carries, so it
   lands in a normative artifact if left as-is. Direction: restate the mapping with
   disjoint buckets whose counts sum — e.g. satisfied-as-built = 60 minus the
   delta-landed subset; landed-by-this-change = that subset (named rows); deferred with a
   named home = the D6 row plus B-1/B-2 if the owner declines them; accepted with
   reasoning = the 8 priced rows, once.

2. **[should-fix] Part 4 / Method — the walk scores the 2025-06-18 MCP authorization
   text while itself naming 2025-11-25 as the current revision, and the current revision
   changes the normative surface.** Verified against both texts: the current revision
   (a) drops dynamic client registration from SHOULD to MAY ("MCP clients and
   authorization servers **MAY** support … RFC 7591 … for backwards compatibility"), so
   the report's "Dynamic registration (SHOULD)" row scores a requirement the current
   revision no longer states; (b) adds Client ID Metadata Documents as a SHOULD for ASs
   and clients — the gateway satisfies it (`client_id_metadata_document_supported: true`,
   `gateway/discovery.py:72`, and the fetch/validate path in `gateway/cimd.py`) but no row
   scores it; and (c) adds AS-facing statements in the CIMD security considerations with
   no row anywhere: "Authorization servers **MUST** clearly display the redirect URI
   hostname during authorization" and "**SHOULD** display additional warnings for
   `localhost`-only redirect URIs". The first is plausibly discharged by the pending
   delta (the decision-page scenario already pins "names the client, the resource, and
   the redirect destination", delta spec), but the walk should say so; the second is
   unscored and unpriced. The redirect-URI MUST behind B-1/B-3 is unchanged and verbatim
   in the current revision ("All redirect URIs **MUST** be either `localhost` or use
   HTTPS" — verified in both texts), so B-1's normative basis is unaffected — if
   anything strengthened — but the owner should not rule on a walk that silently lags
   the ecosystem contract it exists to score. Direction: either re-walk Part 4 against
   the 2025-11-25 text or state the revision choice and its deltas explicitly, and score
   the two CIMD display statements (the hostname-display MUST against the delta's
   decision page; the localhost-warning SHOULD as its own row — satisfied, priced, or
   N/A with reasoning).

3. **[note] B-1's "smallest satisfying change" omits a fourth site — the DCR store's
   load path.** The proposed rule names the three admission sites (DCR body check, CIMD
   document validation, startup refusal for pre-registered config) but not the durable
   DCR store: records admitted before the rule lands (or planted per the store's own
   threat row, T7-1's class) keep their non-loopback `http` redirect URIs usable after
   the rule lands, because client resolution reads the store without scheme validation
   (`gateway/routes.py:223-229` stores what the body check admitted; nothing re-checks
   at load). The exposure is bounded — DCR is default-off (RES-5) and the store sits
   inside the host/volume boundary — but "the smallest satisfying change" should name
   the fourth site (load-time validation, or an explicit boundary ruling that
   pre-rule records are the cleanup backlog's, not the rule's) for the size and the
   scope sentence to be complete.

4. **[note] B-2's remedy is partial in a second dimension the report does not disclose:
   the rotation successor.** The memo binds code_id → the refresh `jti` minted at first
   redemption, and the refusal path denylists that jti. But a refresh token that has
   already rotated before the replay is detected survives: rotation mints a fresh jti
   (`gateway/token.py:702-716`) and no code_id → successor mapping exists, so
   denylisting the original leaves the live rotated token untouched. The access-token
   half of the partial is disclosed honestly (bearer, short TTL, M9's standing bound);
   the rotation-successor half should be stated the same way — or the memo should track
   the chain — so the spec clause the owner accepts states the bound it actually buys.

5. **[note] Summary prose, the priced list's second bullet ("§2.3/§4.9.3-adjacent
   RS-side audience enforcement") reads as if §4.9.3 were among the 8 priced rows.**
   §4.9.3's own row is (c) N/A — boundary: the token's validator is Core — with the
   price already on record. The 8-row tally itself is correct (verified: §2.2.1, §2.3,
   §2.5, §2.6-TLS, §4.10, §4.13's proxy-link, Part 4's token-handling, Part 4's
   communication-endpoints half); only the prose grouping is loose. Direction: name the
   rows, not the topic cluster, in the priced list.

## What was falsified, and held

- **Coverage.** RFC 9700 §2 and §3+§4 were enumerated independently from rfc-editor.org
  (three page reads, the full 142k characters). Every MUST, MUST NOT, SHOULD,
  SHOULD NOT, and RECOMMENDED of §2 and §4, plus the security-posture MAYs, has a row —
  client-side sub-statements are folded into declared, cross-referenced rows (the
  method announces this), and no statement was found without a home. The OIDC beside-set
  is 5/5. Part 4 is complete against the 2025-06-18 text the report declares as its
  source (finding 2 covers the current-revision deltas).
- **B-1 survived falsification.** All four citations verified: DCR checks
  type/count/length only (`gateway/routes.py:336-357`), CIMD `redirect_uris` are accepted
  string-only (`gateway/cimd.py:307-317`), pre-registered `redirect_uris` are a bare
  `list[str]` with no validator (`gateway/settings.py:165-176`; the settings validators
  at `:807-858` govern the IdP endpoint trio and issuer, not redirect URIs), and the
  exact-match rule passes a registered `http://` URI untouched (`gateway/cimd.py:588`).
  A full-repo sweep for scheme validation found none on any registration or resolution
  path — the existing scheme checks govern the CIMD fetch URL itself
  (`gateway/cimd.py:142`), the loopback exception's own shape (`:560`), and the identity
  leg's endpoints/issuer. The dual normative sourcing is verbatim in both RFC 9700 §2.6
  and the MCP spec's Communication Security section (both revisions). The loopback
  exception is keyed on the registered entry exactly as row §2.1 claims
  (`gateway/cimd.py:573-599`).
- **B-2 survived falsification.** `gateway/token.py:452-458` refuses the replayed code
  and revokes nothing; no code_id → issued-token linkage exists anywhere. The remedy's
  citations are real (denylist at `:581-582`, rotation at `:679-726`), and a
  code_id-keyed, minutes-bounded store already exists as the custody hand-off's keying,
  so the "no new surface" sizing claim is grounded. The RFC's SHOULD was verified
  verbatim. The access-token-unrevocable disclosure is accurate — the revoke endpoint
  handles refresh tokens only (`gateway/token.py:760-825`).
- **The 8 priced rows are on record.** RES-5, RES-7, RES-12, RES-19, RES-24, M18, M28,
  T4-9, OQ-4, and D6's deferral all exist and say what the report says they say in
  `docs/threat-model.md` and the change's `design.md`.
- **Sampled satisfied rows (~25, across all four parts) verified against the code.**
  Including: response_type=code only (`gateway/authorize.py:214-219`); PKCE S256
  mandatory at allocation and `plain` refused, not implemented
  (`gateway/authorize.py:236-242`, `gateway/codes.py:93-103`); the structural downgrade
  guard (allocation refuses the challenge-less request, the grant requires the verifier
  unconditionally — `gateway/token.py:400-407`); in-place refusals before redirect
  validation (`gateway/authorize.py:158-168, 226-234`); RFC 9207 `iss` on success and
  redirected error alike (`gateway/flow.py:454-466`, `gateway/authorize.py:162-168`);
  AS metadata members (`gateway/discovery.py:65-69`); grant dispatch knows exactly code
  and refresh (`gateway/token.py:269-279`); tokens only in no-store JSON bodies, Bearer,
  empty scope (`:321-332`); the header family on every page (`gateway/pages.py:91-118`);
  the last-entry XFF read (`gateway/errors.py:221-244`); the non-sliding absolute
  refresh expiry (`gateway/tokens.py:274-281`); the audience shapes (`:220, :261`); the
  CIMD SSRF control set (`gateway/cimd.py:134-271`); the identity leg's fixed callback
  and nothing-relayed authorization URL (`gateway/idp.py:305-341`); the `auth_time`
  as-built gap (`REGISTRY_CLAIMS` strips `acr` and `nonce` but not `auth_time`,
  `gateway/tokens.py:64-83`). The pending-delta claims all have real landing spots in
  the delta spec (state rule scenarios, the no-CORS scenario, the `auth_time` strip
  scenario, the checkpoint and registry requirements, the decision page naming the
  redirect destination), and the "client registration" and "public endpoints"
  requirements B-1/B-2 name as their spec homes exist in the main spec.
- **All 21 N/A rows checked; none dishonest.** No in-browser channel exists (no script,
  postMessage, 307, or 303 anywhere in `gateway/`); the no-ID-token boundary is real on
  both surfaces; the RS of gateway tokens is Core (the priced RES-7/OQ-4 record); no
  scopes are granted or advertised; the client-side duties are the harness's. No N/A
  should be reclassified as a priced violation.
- **Part 5 verified against primary sources, every item.** PR #2629 is merged (Aug 31
  2026) and is opt-in client DPoP per SEP-1932 (`OAuthClientProvider.dpop()`,
  `client/dpop.ts`); the changelog sentence is verbatim what the report quotes ("Add
  DPoP (RFC 9449 / SEP-1932) sender-constrained access token support to the client");
  the Python SDK's conformance expected-failures file says "the SDK's OAuth client does
  not implement DPoP proofs" with the feature on its ROADMAP; the experimental
  `specification/experimental/dpop.mdx` exists on the named ext-auth branch; and the MCP
  authorization specification — both the 2025-06-18 and current 2025-11-25 texts — still
  mandates `Authorization: Bearer` with no DPoP occurrence, as does the best-practices
  document. The proposed record-wording is right, and the deferral verdict stands on the
  unchanged, decisive RS-side ground (Core validates bearer-style, no RFC 9449 proof
  validation).
- **Sizing.** B-1 MEDIUM fits the report's own MEDIUM definition (requirement amendment
  + implementation at multiple sites + tests) and is honestly flagged as a behavior
  change on live surfaces rather than a statement. The loopback exception preserves
  every conforming fielded harness — the MCP spec's own example CIMD document lists
  loopback `http` redirect URIs, and non-loopback `http` is already non-conforming for
  them, so "no fielded harness UX changes" holds for the conforming population. B-2
  SMALL is honest (amendment + bounded memo + one denylist call; the memo's store family
  has an in-codebase precedent).
- **Annex reconciliation.** The D10 annex's held/violated/adjacent lists were re-derived
  from `design.md` and the code — all accurate. The two misses are real (the annex names
  §2.6's transport leg but not its redirect-URI leg; nothing anywhere prices §4.2.4's
  revoke-on-replay), and Part 6 reports them honestly as findings rather than inherited
  verdicts. The D6 record-wording disagreement is correctly scoped: the documents claim
  re-verified true; the ecosystem claim stale at the margin; the verdict untouched.
- **Publication discipline.** The report is clean — no internal hostnames, personal
  paths, or real issuer/tenant/org values; public sources and repo-relative paths only.

## Verdict

**Trustworthy as the owner's decision input as-is.** Both (b)-class findings survived
falsification against the code and the primary normative sources — B-1 is a real,
unpriced, dual-sourced MUST NOT violation at every registration path with no missed
compensating check, and B-2 is a real, unpriced SHOULD violation — and both sizes are
honest. The five findings above do not undercut either finding's factual basis: 1 and 5
are presentation/consistency defects in the record-keeping layer (fix before Part 6's
mapping is carried into the threat-model conformance ledger, and ideally before the
ruling so the ledger is born clean); 2 is a source-currency gap that leaves B-1's own
basis intact while leaving three current-revision statements unscored; 3 and 4 are
completeness notes on the two proposed remedies that should be folded into the
implementation scope if the owner accepts B-1 and B-2. Nothing blocks the ruling.
