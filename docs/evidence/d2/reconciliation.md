# D2 reconciliation record — the merged baseline

**What this is.** The record of the reconciliation pass that merged run A's
`docs/threat-model.md` (base) and run B's `docs/evidence/d2/threat-model-runB.md`
into the single canonical `docs/threat-model.md`, executing the directives of
[`comparison.md`](comparison.md) (§4, directives 1–16; §4's do-not-adopt list
binding). The merge ran after the method-fix pass landed E-1..E-7 in
`docs/security-analysis.md` and the skill, so both of directive 16's follow-ups were
live: the one-time placement verification against the now-allowlisted
`openspec/specs/mcp-signin/spec.md`, and the RES-18 re-judge against the
now-allowlisted PoC C outcome record. This pass authored neither baseline and ran
neither comparison; its writes are `docs/threat-model.md` and this file.

## Per-directive disposition

| # | Directive | Disposition | Notes |
|---|---|---|---|
| 1 | Assets: keep A1–A14, add A15 (upstream PKCE verifier), extend A12 with test-user credentials | **Adopted** | A15 carries B's "—" convention for non-first-order CIA cells, with a one-line note under the table; count 15 |
| 2 | Trust boundaries: keep TB1–TB8, add TB9 (operator / deployment-owner) | **Adopted** | TB9 names Core config, the mapping, key rotation, the DCR flag, the audit sink; count 9 |
| 3 | Attackers: keep A's 8, fold B's two phrasings (co-located process into 1; E7-beneficiary into 8) | **Adopted** | Count 8 |
| 4 | Entry points: keep EP1–EP6, add EP7 (DCR store) | **Adopted** | Count 7; "six entry points" phrasing struck from the preamble |
| 5 | Threat tables: add B's 13 rows renumbered (T1-13/14/15, T2-5/6, T3-9/10, T4-7, T5-6, T6-7, T7-1/2/3) | **Adopted** | All 13 carried with B's substance, homes re-expressed in A's vocabulary; count 54 (15/6/10/7/6/7/3) |
| 6 | Keep every A row; fold B's sharper facts (24 h realm lifespan into T4-2/T5-1/§10; SSE/`proxy_read_timeout` into T6-6; T5.1's mis-use half into T5-1) | **Adopted** | Also grounded the 24 h fact once in §1's state paragraph and in RES-2's bound, for consistency |
| 7 | Register: keep RES-1..RES-19, RES-9/10 split; enrich RES-3/6/5 from B | **Adopted** | RES-3 gains the non-enriching-Core-build fallback; RES-6 gains "machine-checked, not documented"; RES-5 gains the 9p/DrvFs `chmod`-failure mechanism. RES-18 additionally re-judged — see below |
| 8 | Invariant table: A's rulings verbatim, 4 Preserved + 3 with bound; do not adopt B's flat invariant-3 | **Adopted** | Table carried verbatim (D-1, A's ruling stands) |
| 9 | Grids: A's grids stand; write the eight-category grid for the 13 added rows from B §11 with A's home vocabulary | **Adopted** | All 13 grids carried over; homes converted; three cells re-placed per the placement verification below (T1-13 cat 5, T4-7 cat 6, and the per-flow detective cells) |
| 10 | Grouped list: keep M1–M19, add M20 (JWT verification hygiene) | **Adopted with change** | M20 added but **re-placed** — see placement verification; also extended the Addresses columns of M2, M3, M6, M7, M9, M10, M12, M15, M18 to cover the added rows |
| 11 | Compromise points: add browser/session and DCR-store rows; carry B's two honesty lines into the key rows | **Adopted** | Both rows added; the marker-does-not-shrink and no-`offlineClient` lines carried into the "Gateway signing key only" row (B carried both there); 24 h folded into the process row |
| 12 | Disposition table: add B §13's consolidated table as a new section after the grouped list | **Adopted** | New §13, all 54 threats, one row each (B grouped rows; one-per-threat is the more checkable form and matches the counts requirement) |
| 13 | Open questions: keep A's five, add B's OQ-4/OQ-5 | **Adopted with change** | A's five kept; B's two added as OQ-6/OQ-7. OQ-2 and OQ-3 are annotated **resolved** — OQ-2 by the PoC C outcome record, OQ-3 by this pass's placement verification (both resolutions are inputs this pass had that the runs did not) |
| 14 | State the counts in the document; §6 preamble says §5.1's six plus as-built EP7; note E-6 in the evidence trail | **Adopted** | "The model at a glance" block in the preamble states every count with its section; preamble rewritten per E-6 (this note is that note) |
| 15 | Do-not-adopt list | **Followed** | No REG-11 merge (RES-9/10 split); no flat invariant-3; no asset coarsening (A7/A8/A14 kept); no M-addresses-unenumerated-class (M20 addresses the enumerated T4-7 and bounds T1-8); register placed **early** (§3, not late) per D-12/E-7 |
| 16 | Sequencing: method edits first; then placement verification; then RES-18 re-judge | **Adopted** | Method edits had landed; both follow-ups executed below |

## Placement verification — every "Placed — spec" claim vs `openspec/specs/mcp-signin/spec.md`

Verified: the grouped list (the reviewed result) entry by entry, plus the spec-citing
cells of the 13 added grids. Repo placements sanity-checked (committed
`docker-compose.yml`, `router/nginx.conf`, `.env.example`,
`scripts/provision_keycloak.py`, and the CLAUDE.md gate ladder all exist).

**Verified against the spec (requirement text present):** M1 (128-bit CSPRNG flow
ids, state round-trip, destroy-on-first-use), M2 (PKCE on every leg, single-use
PKCE-bound codes), M3 (redirect-URI validation + the keyed loopback exception), M4
(required `resource` / `invalid_target` / refresh match / one-toolset escape), M5
(pre-consent read-access check, USER-level only, GLOBAL refused), M6 (per-source and
global limits, flow cap with oldest-first eviction, body caps), M7 (the SSRF bound
set: HTTPS-only, allowlist, no redirects, private/loopback/link-local refused, size
cap, cache), M8 (the full header family and the script-exclusion property), M10 (~~all
five startup refusals~~ — **corrected 2026-10-29, review round 1: only four are spec
text**; the `^[a-z0-9-]+$` toolset-name charset is repo-implemented
(`gateway/settings.py`'s `_TOOLSET_NAME`) with no spec requirement behind it —
re-placed and flagged as the fourth candidate spec change; see the correction note),
M12 (plain-language fail-closed pages, unknown flows land on the
re-run page), M17's spec half (never committed/logged/rotatable; the JWKS surface
named in the reserved list and Core's JWKS URL).

**Failed verification — re-placed to repo and flagged (3):**

1. **M9's RFC 9207 `iss`** — the spec's discovery requirements name RFC 8414/9728
   only; no requirement carries the `iss` authorization-response parameter.
   Implemented (`gateway/flow.py`, `gateway/errors.py`) and tested
   (`tests/test_authorize.py`, `tests/test_federation.py`). Re-placed: repo
   (implementation + tests). **Candidate spec change.**
2. **M11's per-flow lifecycle records** — the spec's only audit requirement is
   "Refusals before flow allocation are audited"; no requirement covers the
   success-path per-flow records (flow_allocated, upstream_callback, signin_result,
   code_issued, token_issued). Implemented (`gateway/audit.py`) and PoC-evidenced
   (`poc-c-runbook.md` runs on exactly those events). The refusal half stays
   spec-placed; the per-flow half re-placed: repo. **Candidate spec change.**
3. **M20's verification hygiene** — the spec pins RS256 *minting* ("MUST mint RS256
   JWTs") but carries no requirement for the verification side (pinned algorithm on
   verification, own-keys-only key selection). Implemented
   (`gateway/tokens.py:decode_own_token` — the key passed directly with
   `algorithms=[signing_key.algorithm]`, so header `jwk`/`x5c`/`kid` cannot select
   material; `gateway/idp.py` — pinned `_SIGNING_ALGORITHM`, `kid` resolved only
   against the provider's own JWKS). Directive 10's "Placed: spec + repo gates" was
   corrected to repo (implementation + gate ladder). **Candidate spec change.**

Per the landing rule, these three are gateway-owned mitigations not landed as spec
requirements — the next OpenSpec change should land them; they are flagged at their
§12 entries and summarized in OQ-3. No placement was silently kept. **Correction
(2026-10-29, review round 1): the preceding sentence was false as written.** M10's
charset was exactly that — a repo placement carried under "Placed — spec" with no spec
text behind it, the same defect class as M9/M11/M20 except undisclosed. It is now
re-placed to repo in the baseline (§12 M10; §9 T6-2 cat 1, T6-7 cats 1/6/8) and
flagged as the fourth candidate spec change. The history stands: the verification
above checked the grouped list's placements and missed this element of M10's list;
see the correction note at the end of this record.

**Nuance notes (verified at requirement level, mechanics are implementation):**
M7's finer mechanics — all-record resolution checks and connection pinning with
Host/SNI genuinely implement the spec's private/loopback/link-local refusal MUST;
the JSON content type, connect/total timeouts, and explicit User-Agent are their own
controls, repo-implemented, pinned nowhere in the spec. **Corrected 2026-10-29
(review round 1, MINOR-2):** this note originally called all of them "the
implementation shape of the spec's refusal/cap/cache MUSTs", which stretched the
claim past what the spec MUSTs — a timeout is its own control, not an implementation
shape of a refusal requirement; the baseline's M7 entry and the T2 grid citations now
carry the split, and whether the unpinned mechanics join the candidate spec changes
is an owner call for the pause. M8's
"escaping of all reflected values" implements the spec's "script execution excluded"
property (the header family itself is fully pinned). M9's concrete TTL numbers
(10 min / 8 h / 5 min) are the deployment's operator settings within the spec's
startup-validated bounds — the spec pins the lattice, not the numbers.

## RES-18 re-judge (directive 16)

The recorded PoC C outcome is determinable now: the archived change's evidence
folder (`poc-c-runbook.md`, final scoreboard) records the acceptance gate **PASSED**
— all five criteria (a)–(e) CLOSED on field runs 1–5. RES-18's own re-open condition
("green closes this residual") therefore discharges: **RES-18 is closed, not
disclosed.** The register keeps the entry (A's numbering and every cross-reference
preserved) with the closure recorded. OQ-2 resolved identically; no §8 disposition
flips (no threat landed on RES-18).

## Final counts as stated in the document

15 assets · 9 trust boundaries · 8 attacker classes · 7 entry points · 55 threats
(EP1 16, EP2 6, EP3 10, EP4 7, EP5 6, EP6 7, EP7 3) · **19 residual records — 18
disclosed open residuals + RES-18 closed by the recorded outcome** · invariant
rulings 4 Preserved + 3 with a disclosed bound · 20 grouped mitigations.

**The one deliberate deviation from the comparison's canonical counts:** the
comparison states "19 disclosed residuals", written before E-3's landing made the
PoC C outcome determinable; directive 16's own re-judge closes RES-18, so the
honest count is 18 open + 1 closed. The register's entry count (19) and A's
numbering are unchanged. If the owner prefers the literal "19 disclosed residuals",
re-opening RES-18 would require falsifying the acceptance evidence, not a count
edit.

## What a reviewer should look at first

1. **The three spec gaps** (M9 `iss`, M11 per-flow records, M20 hygiene) — the
   placement-verification outcome that both runs' gap lists asked for; each is a
   candidate OpenSpec change, and each is flagged in the document itself.
   **(Corrected 2026-10-29: now four — M10's toolset-name charset, added by the fix
   pass after the review round found it silently kept; see the correction note.)**
2. **RES-18's closure** — the one count deviation, per directive 16.
3. **The re-placed M20** — the comparison's directive 10 text said "Placed: spec +
   repo gates"; verification overruled the spec half. Confirm the repo placement is
   accepted as the holding state or a spec change is opened.
4. **The 13 added rows' dispositions in §13** — T1-14 (accepted, RES-11) and T2-5
   (mitigated to bound, RES-17) are the two new accepted-class entries; T7-1
   (accepted, RES-5) is the D-2 substance item.
5. **OQ-2/OQ-3 resolved annotations** — the merged document resolves two of A's five
   open questions with inputs the runs lacked; confirm the resolutions are wanted in
   the baseline rather than a successor change. (Form corrected 2026-10-29 per the
   review: both now live as resolved-with-source, dated entries in §14's resolved
   record, not prose inside the open set.)

## Post-reconciliation owner input applied (2026-10-29)

The owner's sanity test
([`owner-sanity-test-1.md`](owner-sanity-test-1.md)) found two defects in the merged
baseline; both are applied. The stale-claims mis-use threat — previously carried only
as the residual RES-6 — is now an explicit EP1 threat row (T1-16, Use Control
Misconfiguration → Elevation of Privilege → Bypass Authorization, with its
eight-category grid and a §13 disposition: accepted → RES-6, mitigated to its bound),
and run A's RES-6 cross-reference was corrected from T1-4 (the toolset/leg mix-up) to
T1-16. Counts updated to 55 (EP1 16) in the final-counts section above and in the
document's at-a-glance block; the per-directive table's counts (54) record the
reconciliation pass's own output and stand as history.

## Fix-pass corrections applied (review round 1, 2026-10-29)

The independent review ([`review-round-1.md`](review-round-1.md)) returned three
MAJORs and three MINORs; the fix pass addressed all six in
`docs/threat-model.md` and in this record. Nothing outside those two files was
touched; no spec, code, or disposition change was made — the spec deltas below are
flagged for an OpenSpec change, not applied.

- **MAJOR-1 (M10's false spec placement).** The `^[a-z0-9-]+$` toolset-name charset
  is re-placed from "Placed — spec" to **repo** (`gateway/settings.py`'s
  `_TOOLSET_NAME`) at §12 M10's entry, §9's T6-2 cat 1 and T6-7 cats 1/6/8, and
  added to the candidate-spec-change flags alongside M9/M11/M20 — the flag states
  what the delta must pin (the charset toolset names are validated against at
  startup, the shape the router's static regexes assume). §9's and §12's preambles
  now say four elements, not three. The two false statements in this record's
  placement-verification section ("M10 (all five startup refusals)" verified; "No
  placement was silently kept") are corrected in place above, with the history kept.
  Counts unchanged.
- **MAJOR-2 (92 bare N/A cells).** Every bare "not applicable." cell in §9's grids
  now names the threat-specific property that defeats the category; zero bare cells
  remain. No judgment changed — dispositions, controls, and residuals are untouched.
- **MAJOR-3 (the Keycloak back-channel's forgery blast radius).** The mint-any-`sub`/
  any-role gain from a compose-network MITM position (token exchange + JWKS fetch,
  both gateway-outbound on `http://keycloak:8900`, per `gateway/idp.py:208/321` and
  `docker-compose.yml`) is now stated in §8's T5-2 row, §9's T5-2 cat 3 (with the
  anti-circularity stated: verification is only as trustworthy as the channel the
  JWKS arrived over) and cat 5, and §10's internal-network row. RES-19 is re-priced
  on record: **held at today's shape, accepted knowingly** — (a) the compose-network
  membership trust is now named as load-bearing for identity verification itself;
  (b) the private bridge is the bound, and the record notes the router's port
  non-publication does NOT bound these gateway-outbound legs; (c) the production
  shape (K8s, C3's pod) changes the network assumption and D3 must re-judge it.
  Presented at the owner pause as held-with-knowing-acceptance, not escalated.
- **MINOR-1.** T1-16 added to M9, M10, and M11's Addresses columns in §12, and §13's
  T1-16 row now cites the M ids — §12's "every one traces" note is true.
- **MINOR-2.** M7's nuance tightened (§12 M7 home cell, the T2 grid citations, and
  the nuance note above): only the bound set the spec MUSTs is claimed spec; the
  timeouts, JSON content type, and User-Agent are their own repo controls. Whether
  they join the candidate spec changes is an owner call at the pause.
- **MINOR-3.** §14 restructured to the method's resolution contract: the open set
  holds the unresolved questions (ids kept), and OQ-2/OQ-3 moved to a
  resolved-with-source, dated record under §14.

One observation recorded without action (owner call): the fix pass found the same
placement-uncertainty class in two grid citations the review did not flag — T5-2
cat 7 and T5-6 cats 6/7 cite "timeouts on gateway-issued calls" and "bounded
response parsing" as (spec), and no spec text pins either. They were left as-is
pending the owner's placement pass rather than re-placed here, to keep this fix pass
inside the review's findings.
