# Review pass 1 — findings (one-pod-and-keysets, C3)

Independent review of the authored change artifacts, 2026-11-08, per PROCESS.md step 3b.
Reviewed: proposal.md, specs/mcp-signin/spec.md (delta), design.md (SIA included),
tasks.md, release-notes-draft.md — against CLAUDE.md, PROCESS.md, the "C3 as ruled,
2026-11-08" amendment of docs/production-roadmap.md, docs/security-analysis.md,
openspec/specs/mcp-signin/spec.md, docs/threat-model.md, ROADMAP.md's never-cut list,
and the worktree's code and deployment files (every line-level claim checked, not
spot-checked).

Counts: **0 blocking, 3 should-fix, 4 notes.**

## Should-fix

### SF-1 — The implementation brief omits two files the keyset change necessarily touches

- **Artifact / location:** proposal.md §Impact; tasks.md 2.5–2.6 (and 2.7's test list).
- **Claim:** "Surfaces are named at file depth" — the call sites that read the keysets
  are `gateway/token.py` and `gateway/runtime.py` (task 2.6); task 2.5 names only
  `decode_own_token` in `gateway/tokens.py`.
- **Evidence:** `gateway/codes.py:150-156` — `decode_code` verifies authorization codes
  with its own `jwt.decode` against `signing_key.public_key()`, no `kid` selection, a
  separate verification path from `decode_own_token`. The delta's inbound-tokens
  amendment explicitly covers codes ("The gateway's own tokens — codes, access tokens,
  refresh tokens — are verified against the gateway's own signing keyset … the token's
  `kid` selects the entry"), so a code minted under the old key and redeemed after a
  promotion must verify through the retained entry — `decode_code` must change, and no
  task names it. Likewise `gateway/routes.py:177` serves
  `runtime.signing_key.jwks()` — the single key's document; under the keyset the JWKS
  endpoint must serve every entry's public half, active first (the delta's
  signing-keyset requirement), and no task names `routes.py` either. The drill's named
  signing-leg observations (old-key access tokens at Core, old-key refresh tokens
  refreshing) do not exercise an old-key code redeemed across a promotion, so the miss
  could pass the drill.
- **What would resolve it:** add `gateway/codes.py` (the decode side; `issue_code`'s
  sign path may stay if the active entry is exposed as today's `SigningKey` shape) and
  `gateway/routes.py` (the JWKS endpoint) to the proposal's Impact and to tasks 2.5/2.6
  or a new task; add the old-key-code-across-promotion case to the unit tests (2.7) or
  the drill's signing leg.

### SF-2 — Task 7.7 places the owner review pause after implementation, against PROCESS.md's ordering

- **Artifact / location:** tasks.md group 7, row 7.7.
- **Claim:** "The owner review pause (PROCESS step 3c) with the complete package …
  before any merge" — listed among the acceptance/gate tasks, i.e. after groups 1-6
  (threat model, implementation, image, stack, drill) have run.
- **Evidence:** PROCESS.md step 3 is explicit: after the 3b review's findings are
  addressed, the change "enters an owner review pause (3c) … nothing proceeds without
  the owner's explicit go: no implementation, no packaging, no branch work." The pause
  precedes step 4 (implement), which runs "against the `tasks.md` checklist" — so a
  fresh implementation agent reading this checklist top-down would meet the pause as a
  late, pre-merge gate rather than the precondition it is.
- **What would resolve it:** restate 7.7 as a precondition record (a header note or
  group-0 row: the pause was held before group 1 ran, its go recorded), or move it
  ahead of group 1; keep the merge-is-the-owner's-act statement where it is.

### SF-3 — Delta-threat ID collision with citations already in the live threat model

- **Artifact / location:** design.md §SIA (the threat tables' DT-EP4-1/DT-EP4-2, and
  DT-EP1-1/DT-EP1-2); design.md §7 and tasks.md 1.1 (the threat-model delta).
- **Claim:** The SIA's delta threats are numbered DT-EP4-1 "Retained signing key
  extends the stolen-key mint window" and DT-EP4-2 "Retained custody key extends the
  decrypt window"; §7 writes these IDs into the live model's rows ("a new row for the
  retained-key windows (the signing half — DT-EP4-1) and a re-price of T4-8/RES-21
  part ii for the custody half (DT-EP4-2)").
- **Evidence:** the per-change restart-at-1 numbering convention is pre-existing, but
  the live model already cites those IDs from earlier changes: docs/threat-model.md
  line 423 — "RES-21 … (T4-8; DT-EP4-1; the D5 amendment's priced trade)" is C1's
  custody-key-compromise threat (archive/2026-11-03-dynamic-toolsets-and-fresh-claims
  design.md:1237), and the dispositions table (line 2098) cites DT-EP1-2 for C2.5's
  approval-registry flooding. After this change's sync, RES-21 would carry both C1's
  "DT-EP4-1" and this change's "DT-EP4-2" with no change-scope marker — and task 1.3's
  freshness rule ("the reviewer can reconstruct every delta row's citation from this
  change's design §5–§7") hits exactly that ambiguity.
- **What would resolve it:** scope the IDs where they land in the threat model (e.g.
  "C3 DT-EP4-1/2", or renumber this change's EP4 delta rows to continue the sequence,
  e.g. DT-EP4-8/9), or state the scoping convention in design §7 so task 1.1 lands
  unambiguous citations. (The M34–M36 rows are collision-free — the model's grouped
  list currently ends at M33.)

## Notes

### N-1 — The MODIFIED inbound-tokens requirement drops the prior amendment note without declaring it

- **Artifact / location:** delta spec, MODIFIED "Inbound tokens are verified with
  pinned algorithm and key selection"; main spec line 612.
- **Evidence:** the main spec's requirement carries a prior "*Amendment, declared:*"
  note (the endpoint-source key-set resolution rationale, with the origin-bound
  qualifier's scope). The delta's MODIFIED text carries only its own new amendment
  note; on sync the prior note is lost, while the convention elsewhere in the main
  spec is that prior amendment notes persist (e.g. the toolset-mapping requirement's
  retained notes at lines 638/640). The clause the old note explains is carried
  verbatim, so no behavior is lost — only the rationale record.
- **Resolution (optional):** declare the drop in the new amendment note, or carry the
  prior note marked "(retained)".

### N-2 — The retained "Embedded key refused" scenario's "the pinned key only" reads against the keyset amendment

- **Artifact / location:** delta spec, inbound-tokens scenarios.
- **Evidence:** the scenario is carried verbatim as declared ("the retained scenarios
  are unchanged"), but "checks the signature against the pinned key only" predates the
  keyset: the pinned key is now the `kid`-selected entry of the pinned keyset. The
  requirement text governs and is unambiguous; a reader of scenarios alone could read
  a single pinned key. A future declared one-clause re-pin would close it; not worth
  reopening this change alone.

### N-3 — SIA invariant-table ruling values drift off the method's two allowed values

- **Artifact / location:** design.md §SIA §3 (the invariant ruling table).
- **Evidence:** docs/security-analysis.md §2 fixes the ruling values as "Preserved" or
  "Preserved with a disclosed bound". Row 7 reads "Preserved — and strengthened within
  the ruling" and row 5 "Preserved, with the new surfaces named". The substance is
  conforming (each row's reason states its bound — row 7 names the injection-path
  custody and the retained-entry window), only the labels vary.

### N-4 — The duplicate-derived-kid parenthetical overstates what the mechanism proves

- **Artifact / location:** delta spec, signing-keyset requirement ("this is the
  duplicate-key refusal — the same key configured twice, or one key under two names").
- **Evidence:** the `kid` is a 16-hex-char (64-bit) truncation of a SHA-256 over the
  public numbers (`gateway/keys.py:74`), so two *different* keys can in principle
  derive the same `kid`; the refusal is correct either way (the keyset must not hold
  two entries with one `kid`), but the parenthetical's causal claim ("the same key
  configured twice") is stronger than the truncated hash guarantees.

## What was checked and found true (the falsification record)

- **Code reality — every line-level claim verified TRUE:** `gateway/keys.py:128-150`
  (single injected PEM, `kid` derived from public material, one-key JWKS);
  `gateway/settings.py:505` (one `SecretStr`), `:528/:567-575/:977-1025` (custody dict
  forced to exactly one entry, 32-byte pin, multi-active refusal); `gateway/tokens.py:
  326-359` (`decode_own_token` verifying against `signing_key.public_key()`, no `kid`
  selection); `gateway/custody.py:176-244` with the key-id check at `:203-210`;
  custody call sites in `gateway/token.py` (376/758/795) and the runtime wiring;
  `router/nginx.conf:43-45` (gateway upstream by service name); `docker-compose.yml:
  94-108` (gateway container-internal, never published) and `:229-244` (DCR bind
  mount); `Dockerfile` uid 10001, pip removal, one internal port, `python -m gateway`;
  `docs/gateway-configuration.md:324` ("the same trust boundary as the signing key's")
  and `.env.example:352` ("ROTATION IS A HARD CUT") — both statements the change
  amends exist as claimed.
- **The Alpine precedent (D5/P4) independently re-verified:** the sibling
  `ai-dial-adapter-openai` Dockerfile builds on `python:3.11-alpine` and runs
  `apk upgrade --no-cache libcrypto3 libssl3` in both stages, with `alpine-sdk` in the
  builder only — D5's claims about it are accurate, including the 3.11-vs-3.12 nuance
  it itself records.
- **Ruling deviations (P1–P5), each on its merits:**
  - **P1** (full-window JWKS publication as a priced simplicity choice) — the
    underlying factual claim is true: refresh tokens are never Core-acceptable (no
    marker, `aud` = resource alone — the issued-tokens requirement) and codes are
    gateway-only, so Core verifies access tokens only; the old `kid` is strictly
    needed at Core for ~access-TTL + cache. The rejected sharper design's costs
    (JWKS/keyset divergence class; two operator windows) are real; the lost shorter
    mint-window is priced in DT-EP4-1 with the immediate cut as the control. Sound.
  - **P2** (pre-publish rule) — required by the ruling's own "new tokens accepted
    throughout"; the staged add-as-retained → wait → promote procedure needs no third
    role. Landed normatively (requirement clause + scenario). Sound.
  - **P3** (drill extended to the custody keyset) — the roadmap's own T3 reasoning
    applied to the second key this change rotates; adds coverage, loses nothing.
    Landed in the drill requirement. Sound.
  - **P4** — verified above. **P5** — the concurrence is reasoned, not assumed, and
    both-configured-simultaneously is carried by the per-entry seam. Sound.
- **Delta-spec hygiene:** both MODIFIED headers exist in the main spec (lines 744 and
  608); the ADDED requirements duplicate nothing in the main spec (33 distinct
  requirement headers, no pre-existing pod/keyset/drill requirement); the MODIFIED
  texts diff to exactly the declared amendments and nothing else (word-level diff
  run); custody scenarios: 9 retained (2 amended exactly as declared) + 4 new;
  inbound: 5 retained verbatim + 2 new; nothing welded, nothing silently dropped.
- **The re-scoped "Custody-key rotation is a hard cut" scenario reads honestly:** the
  name keeps naming something true (the cut), the subject moves from routine rotation
  to the removal act, the fail-closed shape and the wave bound are unchanged, and the
  re-scope is declared with its reason in the amendment note — not a smuggled
  redefinition.
- **SIA method conformance:** full structure §5.1–§5.8 present (change description,
  impact level Medium with reasons, 7-row invariant table against the never-cut list,
  per-entry-point delta threat tables EP4/EP1/EP6/EP7 with EP2/EP3/EP5 covered by the
  invariant table per §4, per-threat 8-category mitigation grids with threat-specific
  N/A reasons, grouped mitigation list with threats addressed, threat-model delta,
  open questions, strict gap list). Every gateway-owned mitigation lands in the delta
  spec; non-gateway homes are named with owners. The impact level (Medium) is
  consistent with the analysis and sets the review depth.
- **Threat-model coherence:** every entry §7 claims to amend exists — T4-1, T4-8 (the
  dispositions row), RES-2/5/13/15/21, T6-1/T6-4, EP4/EP6/EP7, the revocation
  summary's "all proxy access" row (line 1947), M17/M21; M34–M36 are free IDs. The
  "10 minutes observed" Core JWKS-cache figure matches the model's recorded
  observation; its unverified status is honestly recorded as OQ-1.
- **Mechanical gates:** `openspec validate one-pod-and-keysets` green; `openspec
  validate --all` green (2 passed, 0 failed — INFO-only length notices, the pre-
  existing style of the whole spec; bare `openspec validate` prints its usage message
  and exits 1, which is the tool's no-args behavior, not a validation failure).
  `python scripts/check_publication_leaks.py` exit 0 (3 findings, all waived in the
  committed baseline; none new). Manual scan of the untracked change-folder files for
  leak classes (personal paths, hostnames, issuer/tenant values, credential-shaped
  literals): clean — "the local instance" and product names only.
- **Internal coherence:** the threat-model delta is task group 1 (the standing
  order); every delta requirement has tasks (the SF-1 gap is file enumeration, not
  requirement coverage); release-notes-draft carries both audience subsections and
  its compatibility sentence is true (the singular and flat spellings are the
  supported compat shapes per the delta's own scenarios); the drill honors
  probe-fail-first (the negative control is a spec'd scenario and task 6.2); the
  DevOps-review acceptance requires explicit confirmation with silence-is-not-
  acceptance, evidence-gated (task 7.6).

## Verdict

The change is sound: the ruling set is implemented faithfully, the two licensed
deviations and three extensions are argued and (independently re-)verified, the SIA is
conforming and honest about its priced widenings, and the delta spec is clean against
a main spec that has been corrupted before — no drift, no welding, no silent drops.

**Proceed to the owner review pause (PROCESS 3c) once SF-1 through SF-3 are addressed**
— all three are authoring-artifact fixes (a file list, a task's placement, citation
scoping); none requires design rework, and none is blocking on its own.
