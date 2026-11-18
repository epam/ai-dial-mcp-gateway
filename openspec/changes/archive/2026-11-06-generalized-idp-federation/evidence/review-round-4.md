# Review round 4 — the owner's pause rulings folded (2026-11-04)

Reviewer: the independent review subagent (PROCESS.md step 3b, round 4). Mandate:
falsify the round-4 fold-in — verify each ruling landed faithfully (OQ-A without a
Class A leak, OQ-D verbatim with its reach, the issuerPattern refusal without
operator-doc content), the task-2.5 latent-conflict fix, the two-part 7.1 row's
executability, the rounds-1–3 dispositions' survival, the splice integrity of the
script-edited 7.1 row, and the gates. No fixes applied; findings and dispositions
requested only.

## What was checked, independently

- **The round-4 diff read whole** (`git diff` vs `dcc1347`: design.md, proposal.md,
  tasks.md — 122 insertions / 52 deletions; authoring-round-4.md new). Every claim
  below is checked against the diff, not the authoring note's description of it.
- **Ruling fidelity, ruling by ruling** (detail below): OQ-A's landing sites
  (Context, Goals, D6, D9, SIA §1, §8 OQ-A/OQ-B, tasks 7.1, proposal Why and
  tested-case bullet) read against the note's record of the owner's words; OQ-D's
  verbatim principle searched across all its landing sites; the refusal's landing
  and its no-operator-doc claim verified by grep.
- **A fresh sweep**: `statgpt` over the whole tracked tree; the family pattern set
  (`b2c|entra|microsoft|azure|tfp|b2clogin|ciamlogin|onmicrosoft|external id|statgpt`,
  case-insensitive) over the change folder minus evidence, and over the delta spec
  and release-notes draft specifically; `issuerpattern` over the change folder.
- **Task 2.5's grep run over the current (pre-change) tree** —
  `git grep -i keycloak -- gateway/ tests/ 'scripts/probe_*.py' pyproject.toml
  docs/routing.md` — and every hit classified against the new expectation's three
  permitted categories; the update scope compared against the verification scope.
- **The tree's Class A surfaces swept for the family's names** (the side of the
  boundary the change-folder sweep does not reach): `git grep -i entra` excluding
  the change folder, the archived change, and the PoC-era records.
- **Regression spot-checks**: tasks 5.1 (F3's prerequisite row and R3-1's re-worded
  direct-mode trigger) confirmed untouched by the diff and present; the delta spec
  confirmed untouched (R2-2/R2-4's clauses therefore mechanically intact); the
  never-cut table confirmed outside every diff hunk; D14's self-check re-evaluated
  against the new paragraphs' hits.
- **Splice/encoding check on tasks.md 7.1**: the row read whole; the diff confirms
  a clean one-line replacement (2 deletions / 2 insertions in the file, rows 2.5
  and 7.1 only); no U+FFFD, no CR, the non-ASCII inventory is exactly `§ — →`, no
  duplicated fragments, the markdown structure intact.
- **Gates re-run** (main checkout venv, `PYTHONUTF8=1`, in the worktree):
  `openspec validate generalized-idp-federation` — **valid** (exit 0);
  `python scripts/check_publication_leaks.py` — **PASS** (204 tracked files
  scanned; 3 findings, all pre-existing and waived — two in
  `docs/evidence/d0a/review-round-1.md`, one in `scripts/import_background.py`;
  0 unwaived). Matches the authoring note's record exactly.

## Ruling fidelity — verified

- **OQ-A (classic flavor).** The decision text is consistent across all nine
  landing sites ("the owner's tenant is the classic flavor", the successor "the
  untested alternative ... a configuration profile, not a code change"), and the
  construction claim survives everywhere ("which spelling a deployment configures
  decides only the literal, never the mechanism"). **No Class A leak**: the delta
  spec and the release-notes draft are untouched by the diff and zero-hit under
  the family pattern set; tasks 5.1/5.2 are untouched; the proposal's two changed
  zones are exactly its two Class B identification zones (the Why's tested-case
  identification and the What-Changes tested-case bullet — the mechanism bullets
  are untouched). Task 7.1's "per-policy (tfp) issuer" now matches the decision
  (the "or per-tenant" alternative correctly removed). OQ-B's re-anchoring is
  faithful: verified for the tested flavor's SPA/PKCE shape, the successor's
  answer named the untested alternative's open fact.
- **OQ-D (helper-scoped KEYCLOAK_*).** The principle is quoted verbatim and
  identically in D8, D14's agreement paragraph, and the §8 OQ-D entry ("the
  gateway itself is generic, but examples and tests can and should be
  IdP-specific"); the reach is stated in D8 ("reaches past the settings block" —
  the helper's Admin REST vocabulary end to end, the probes' local-instance
  fixtures staying); D8+D14-as-one-position is stated in both directions, and the
  deferrable-questions closing note carries the decision. The one artifact change
  the ruling forced (task 2.5's expectation extension) is the conflict fix
  reviewed below.
- **The issuerPattern refusal.** Landed in Non-Goals in the owner's words ("exact
  issuer match stays as long as possible, and the `issuerPattern` mechanism can be
  adopted later, by a future change, if a real deployment needs it"), with the
  posture tied to D6's templating rejection. **No operator-doc content added**:
  `issuerpattern` hits in the change folder are exactly design.md:85 (the
  Context's DIAL-family grounding), :142/:144 (the new Non-Goals bullet itself),
  :554 (D12's refused list), and the historical evidence records — tasks.md has
  zero hits, so 5.1 gained no row.
- **The two-part live run.** All elements of the owner's refinement are present in
  7.1 (Part 1 controlled with the full chain, D9 verifications, refresh leg, and
  the direct-trio remedy; Part 2 real-world with the owner's coordinates and the
  real app; the no-reconfigure-or-record-delta criteria; evidence capture for both
  parts; the Class B confinement of the real names), and echoed in OQ-A and the
  proposal's tested-case bullet. The app's name appears in exactly two places: tasks.md
  7.1 and authoring-round-4.md — both Class B; zero hits in the operator docs, the
  delta spec, the release notes, and every other tracked file.

## The latent-conflict fix (task 2.5) — the keycloak line is right; see R4-2 for the family side

The new expectation permits "the helper-scoped settings, the provisioning helper's
own Keycloak-API vocabulary, and the local-instance fixtures the tests and probes
carry for the local shape (the local Keycloak URLs, realm, and login-flow driving
— the D8 boundary per the owner's OQ-D ruling)". Run over the current tree, the
grep's 190+ hits classify cleanly into: to-be-renamed mechanism vocabulary
(gateway/idp.py, federation.py, settings.py identifiers; the route; the three
named stray prose surfaces), and the categories the post-change state will keep —
the tests' fixture URLs (`https://keycloak:8443/realms/dial`,
`http://keycloak:8900/...` in test_tokens/test_custody/test_federation/
test_audit/test_authorize), the probes' login-flow driving
(probe_end_to_end.py's three-request Keycloak login), the helper-scoped names
(test_settings.py:905-911, test_leak_check.py's `KEYCLOAK_ADMIN_PASSWORD`), and
the leak-check test's fixture lines (task 2.5 lists that file). Every anticipated
post-change survivor maps to a permitted category, and every hit that maps to no
category is a file some task row or the grep's own "every other hit gone" clause
forces to be reworded — the expectation is executable as a net, and it draws the
keycloak line at the right place: local-instance fixtures in, mechanism
vocabulary out. The one inventory miss the run exposed is R4-4 below.

## Regression — rounds 1–3 dispositions hold

- **F3**: task 5.1's operator-prerequisite row is untouched by the round-4 diff
  (tasks.md changes are rows 2.5 and 7.1 only) and carries the round-3 wording
  intact. **R3-1**: the re-worded direct-mode trigger ("journey-distinct-issuance
  providers whose discovery document cannot be relied upon included") is present
  and untouched.
- **R2-2/R2-4**: their clauses live in the delta spec, which round 4 does not
  touch (git status: design.md, proposal.md, tasks.md, one new evidence file) —
  the dispositions hold mechanically.
- **The never-cut table** (§3) is outside every diff hunch — unchanged in
  membership and rulings.
- **D14's self-check in the letter**: the new paragraphs' hits all fit the
  permitted categories — the Non-Goals bullet carries no family vocabulary
  (`issuerPattern` is Core's, not the tested family's); D8's confirmed paragraph
  and D14's OQ-D agreement paragraph carry Keycloak mentions that are D8-scoped
  local-deployment facts (the check's fourth permitted class); the OQ-A entry's
  product names sit in an enumerated Class B zone; Goals/D6/SIA §1 carry only
  permitted family anaphora. The check claim remains true in the letter for the
  change folder. (The tree-level question is R4-2.)
- **Publication discipline**: `<tenant>`/`<policy>` placeholders retained; no real
  hostnames added; the leak check's waived baseline is pre-existing and untouched.

## Findings

### R4-1 — task 7.1's Part 2 pass criterion "no gateway reconfigure between the parts" is not operationalized

- **Severity:** medium (not blocking the fold-in; must be dispositioned before
  task 7.1 executes, because it is the row's pass/fail line).
- **Evidence:** tasks.md 7.1, Part 2: "Part 2's pass criteria are the same chain
  with no gateway reconfigure between the parts — or, where the two environments
  genuinely need different values, record exactly which per-environment
  configuration differs and why (an environment fact, not a gateway change)."
  Three ambiguities, one root cause — the row never fixes what "a gateway
  reconfigure" is: (a) it never says which gateway instance serves Part 2 (Part
  1's stack is the local compose gateway; Part 2 lists "the strict harness, B2C
  as the identity provider, and the owner's real DIAL deployment" — no gateway
  named); (b) pointing a gateway at the real deployment's Core instead of the
  local one plausibly requires changing gateway settings (the Core origin, the
  public origin), which **is** a gateway reconfiguration under the plain reading
  — so the primary criterion may be unsatisfiable as written, with the escape
  hatch the expected path, and the parenthetical "(an environment fact, not a
  gateway change)" redefines coordinate changes as not-gateway-changes in tension
  with that plain reading; (c) "the same chain" is ambiguous about whether the D9
  provider-fact verifications and the refresh leg enumerated in Part 1 carry into
  Part 2 or are Part 1-only. The test-worthy claim — the same `IDP_*` federation
  profile serves both environments, with only environment coordinates differing —
  is derivable but not stated. The same phrase propagates to OQ-A's decided entry
  and the proposal bullet, so a fix lands in all three or the row alone reads as
  the operative one.
- **Disposition requested:** scope the criterion to what it is testing (no change
  to the `IDP_*` federation profile between the parts); name the gateway instance
  per part; name the expected per-environment delta class (environment
  coordinates such as the Core and public origins — recorded per the escape
  hatch); and state whether the D9 verifications and refresh leg are Part 1-only.

### R4-2 — the family-name half of the D8/D14 boundary has live Class A sites in the tree that no task names and no gate checks

- **Severity:** medium (the unfinished half of this round's own conflict check;
  must be dispositioned before task groups 2 and 5 execute).
- **Evidence:** the OQ-D conflict check drew the line for `keycloak` (task 2.5's
  expectation) but the tested family's names on the same surfaces have neither a
  task row nor a gate. `git grep -i entra` over the tree (excluding the change
  folder, the archived change, and the PoC-era records) finds four live Class A
  sites: `gateway/settings.py:260-261` and `:697-698` ("on Keycloak the realm's
  SSO Session Max, on Entra the public-client refresh-token bound" — code
  comments in implementation-facing code), `.env.example:102` ("on Entra, the
  public-client refresh-token bound (~24 h)"), `README.md:23` ("Entra B2C is the
  tested case"), and `docs/gateway-configuration.md:566` (the
  `IDP_SSO_SESSION_MAX_SECONDS` row: "on Keycloak … on Entra …"). None is named
  by any task row: 2.1 renames settings and the section header (not these
  comments); 2.3 rewrites `.env.example`'s IdP section (the comment can be
  carried forward); 5.1's "all of it in provider-neutral vocabulary" arguably
  reaches the gateway-configuration row but names it no more specifically than
  the whole doc; 5.2's provider-neutral instruction is attached to "the
  external-provider configuration sketch", which README:23's opening sentence is
  not. The machine gates are blind to all of it: task 2.5's grep is
  `keycloak`-only (it catches the Keycloak half of the very same
  settings.py sentences but not the Entra half beside it) and its scope excludes
  `.env.example`, README, and the operator docs anyway; task 6.1's stated
  discipline check is `check_publication_leaks.py`, whose rule set (personal
  paths, secret shapes, tracked `.env`) scans no provider names. Post-change,
  D14's Class A claim and 6.1's gate row can both be false with every stated gate
  green.
- **Disposition requested:** the family-name symmetric of the round's own fix —
  either name the four sites in tasks 2.1/2.3/5.1/5.2, or add a family-name
  verification over the tree's Class A surfaces (gateway/, `.env.example`,
  README.md, `docs/gateway-configuration.md`, `docs/local-environment.md`) to the
  2.5/6.1 gate rows, so the line drawn for `keycloak` is drawn for the tested
  family's names on the same surfaces. (The threat model and the production
  roadmap also carry Entra mentions — `docs/threat-model.md:630`,
  `docs/production-roadmap.md:49/212` — but neither file is enumerated Class A by
  D14, and task 1.1's scope is its enumerated rows; noted for the disposition,
  not demanded.)

### R4-3 — task 2.5's verification grep covers a strict subset of the surfaces the rename updates

- **Severity:** low.
- **Evidence:** the grep's scope is `gateway/ tests/ scripts/probe_*.py
  pyproject.toml docs/routing.md`, but the same task updates `README.md`,
  `docs/gateway-configuration.md`, `docs/local-environment.md`, and
  `scripts/spike_*.py`, and task 2.3 updates `.env.example` and
  `docker-compose.yml`. A stale half-renamed spelling in any of those — a dead
  `KEYCLOAK_ISSUER` line in compose's gateway environment (silently ignored by
  the renamed settings model, so the compose-boot gate stays green and the probe
  runs on `.env`-supplied values), a carried-forward old comment in
  `.env.example`, a stale mention in README or the operator docs, a missed spike —
  passes the row's own verification clause. The functional gates catch some of
  this (the probe, the documented bring-up) but not the silently-ignored class.
- **Disposition requested:** extend the verification with a second grep over the
  full update scope for the renamed gateway-consumed setting names (which must be
  zero everywhere post-change), leaving the local-instance-name judgment on the
  remaining `keycloak` prose to the D8 boundary as now.

### R4-4 — the stray-prose inventory misses a fourth surface: gateway/__main__.py

- **Severity:** low (no leak risk — the grep net covers `gateway/` — but the
  inventory claim is false as written).
- **Evidence:** design.md Context claims "three surfaces outside those lists spell
  the old name in prose" (`gateway/app.py`, `pyproject.toml`, `docs/routing.md`),
  and task 2.5's file list carries the same three. The current-tree grep finds a
  fourth: `gateway/__main__.py:57` — "reconstructing a sign-in correlates these
  stamps against Core's and Keycloak's" (the `_UtcFormatter` docstring) — which is
  mechanism vocabulary (the audit stamp correlation, not a local-instance fact),
  named by no task row. Task 2.5's grep would catch it at verification time (its
  scope includes `gateway/`), so the rename cannot silently miss it; the finding
  is the inventory's accuracy.
- **Disposition requested:** add `gateway/__main__.py`'s docstring to the Context
  inventory and 2.5's file list.

### R4-5 — Part 1's "a test MCP toolset or app configured for B2C" is ambiguous about its object and provisioner

- **Severity:** low.
- **Evidence:** tasks.md 7.1, Part 1: "the local compose stack (the local DIAL),
  with a test MCP toolset or app configured for B2C". In this architecture the
  upstream MCP toolset takes no identity-provider configuration (the IdP leg is
  the gateway's; the toolset flow is the upstream leg), so "configured for B2C"
  has no obvious object — a fresh agent scheduling Part 1 must guess whether it
  means a test upstream MCP server the harness stands up and CIMD-registers (the
  chain already includes "CIMD registration"), a DIAL-side app, or something
  pre-registered in the tenant, and who provisions it. The row is owner-dependent
  and the owner supplies details, which bounds the risk.
- **Disposition requested:** one clause saying what the test toolset is and who
  stands it up (e.g., "a test MCP toolset the harness CIMD-registers, plus the
  local DIAL"), so Part 1 is schedulable from the row alone once the tenant values
  arrive.

### R4-6 — authoring-round-4.md's ruling-3 inventory omits the Non-Goals bullet the same round landed

- **Severity:** low (record accuracy only).
- **Evidence:** the note's "Verified:" paragraph claims "the only `issuerPattern`
  mentions in the change folder are D12's comparison and its refused list, the
  Context's DIAL-family grounding, and the historical evidence records" — the
  Non-Goals refusal bullet the same round added (design.md:142-144) is a fourth
  zone the sentence does not list, so the inventory is false as written and a
  future reader greeping `issuerPattern` finds a zone the record does not
  account for.
- **Disposition requested:** amend the sentence to include the Non-Goals bullet.

## Verdict

The fold-in is faithful: all three rulings and the two-part refinement landed
where the note says they landed, in the owner's words where the owner's words
were ruled on record (OQ-D's principle verbatim and identical across its three
sites); OQ-A leaked into no Class A surface (the delta spec and release notes are
untouched and verifiably zero-hit; the proposal's changes are confined to its two
Class B identification zones); the refusal added no operator-doc content
anywhere; the splice-edited 7.1 row is clean (a single coherent line, no
duplicated fragments, no encoding damage); the rounds-1–3 dispositions survive
mechanically (5.1 and the delta spec untouched, the never-cut table unchanged);
D14's self-check holds in the letter for the change folder; and both gates
reproduce green exactly as the authoring note records. The keycloak side of the
2.5 conflict fix draws the line at the right place and is executable as a net.

**Ready for commit, with two findings to disposition before the task groups they
govern execute** (the round-3 precedent): R4-1 before task 7.1 is scheduled (the
owner-dependent row has time), and R4-2 — the unfinished family-name half of this
round's own conflict check — before task groups 2 and 5 execute; R4-3 through
R4-6 are precision fixes that can ride the same disposition pass. Nothing here
re-opens a mechanism decision, and no finding alleges infidelity of the fold-in
itself.

## Dispositions (authoring pass, 2026-11-04)

All six findings accepted and fixed inside the change folder. No mechanism
decision re-opened; nothing outside the change folder touched — the four R4-2
implementation-surface sites are prescribed for neutralization by the new task
row at implementation time, not edited in this authoring pass.

- **R4-1 — accepted, fixed.** Task 7.1's Part 2 rewritten around what the
  criterion actually tests: the **`IDP_*` federation profile** (`IDP_ISSUER`,
  `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET`, `IDP_CLIENT_SCOPES`, and the
  endpoint-source and mode settings, the D11 direct trio included) is identical
  between the parts, unchanged in spelling and value. The Part-2 gateway
  instance is named — a gateway configured against the real deployment's
  coordinates, its Core URL and public origin the expected per-environment
  delta class and the only settings expected to differ from Part 1's stack; a
  coordinate difference is stated not to be a gateway reconfiguration, and a
  federation-profile difference is stated to be a finding to record and
  explain, not a pass. The D9 provider-fact verifications and the refresh leg
  are stated as Part-1 rows: Part 2 repeats the full chain but not the
  verifications, unless a Part-2 behavior puts a fact in question. Propagated
  to all three carrying sites: design.md §8 OQ-A's two-part clause (same
  criterion, pointing at task 7.1 as the operative statement) and proposal.md's
  tested-case bullet. The row is now executable by a fresh agent holding only
  the owner's details.
- **R4-2 — accepted, fixed, three parts.** (a) New **task 2.7** neutralizes the
  family-name sites into provider-class wording: `gateway/settings.py`'s two
  session-bound comments (the "on Entra" halves; the Keycloak halves beside them
  are already swept by 2.5's grep, so both sites end fully neutral),
  `.env.example`'s `IDP_SSO_SESSION_MAX_SECONDS` comment half, `README.md`'s
  tested-case clause plus its roadmap-item line's "on B2C" tail (a sixth
  location this pass's wider family pattern found beyond the review's
  entra-only sweep — named so the row's own grep passes), and
  `docs/gateway-configuration.md`'s session-bound row — pre-existing content
  the change sweeps because it owns the surface, neutralized, not deleted.
  (b) The row's verification is the machine check:
  `grep -riE 'entra|b2c|azure|microsoft|tfp|b2clogin|ciamlogin|onmicrosoft|external id|statgpt'`
  over `gateway/ tests/ pyproject.toml .env.example docker-compose.yml
  README.md docs/gateway-configuration.md docs/local-environment.md` returns
  nothing — so D14's Class A claim and 6.1's gate row cannot be false with
  every stated gate green; task 6.1's row now re-runs this grep and records its
  zero-hit result. (c) design.md D14 gains a closing note — "The
  implementation-surface half of the check is the change's own gate,
  machine-checked" — stating the gate's scope and its distinctness from the
  D8-scoped local-deployment allowances (D8 licenses the local instance's own
  name for local-deployment facts, never the tested family's names on an
  implementation surface). The historical-records exclusion is unchanged and
  stays outside the grep's file list.
- **R4-3 — accepted, fixed.** Task 2.5's verification gains a second grep over
  the full rename surface — `grep -riE
  'keycloak_issuer|keycloak_client|keycloak_internal|keycloak_callback'` across
  `gateway/`, the tests, the three script groups, `pyproject.toml`,
  `README.md`, `.env.example`, `docker-compose.yml`, and the three updated
  docs — which must return nothing, so a silently-ignored stale spelling (a
  dead `KEYCLOAK_ISSUER` line in compose, a carried-forward `.env.example`
  comment, a missed spike) cannot pass. The row states the pattern matches none
  of the helper-scoped `KEYCLOAK_*` names (their fate is D8's, decided) and
  that the local-instance-name judgment on remaining `keycloak` prose stays
  with the first grep's D8 boundary.
- **R4-4 — accepted, fixed.** `gateway/__main__.py`'s UTC-formatter docstring
  added as the fourth stray-prose surface in all three places that carry the
  inventory: design.md Context (three → four, quoted, marked mechanism
  vocabulary), task 2.5's file list, and proposal.md's Impact stray-prose list.
- **R4-5 — accepted, fixed.** Task 7.1 Part 1's "a test MCP toolset or app
  configured for B2C" reworded to what is meant, in one clause: the test
  toolset/app is the resource the harness calls through the front door after
  the B2C-backed sign-in — provisioned by the local provisioning helper as
  today, configured for nothing IdP-side at the toolset itself (the IdP
  configuration lives in the gateway's `IDP_*` profile and the harness's
  client; the toolset's own upstream credential is the separate, unchanged
  upstream leg). The resource-model design is untouched. The authoring note's
  quotation of the owner's words ("configured for B2C") is the owner-input
  record and stands as history.
- **R4-6 — accepted, fixed.** `authoring-round-4.md`'s ruling-3 "Verified:"
  sentence amended to list the Non-Goals refusal bullet among the
  `issuerPattern` zones, with a parenthetical marking the amendment and its
  cause (an accuracy correction to the round's own record, as allowed).
