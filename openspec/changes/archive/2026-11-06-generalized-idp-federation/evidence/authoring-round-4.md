# Authoring round 4 — the owner's pause rulings folded (2026-11-04)

Author: the design author (this pass). This note records the third re-pause's
outcome: the owner ruled on the three open owner items and supplied the live-run
refinement, and this round folded all four into the artifacts. The prior evidence
files (`owner-round-2.md`, `review-round-1.md` through `review-round-3.md`,
`authoring-round-3.md`) are historical records and were not re-worded.

## Ruling 1 — OQ-A decided: classic B2C, not External ID

The owner's tenant is the tested family's **classic flavor**. The decision is a
Class-B working-artifact fact: it records which literal the live run verifies; no
Class A surface changed its neutral wording because of it (D14's boundary kept
exactly — the delta spec and the release-notes draft are untouched by this ruling,
before and after carrying zero family vocabulary). The successor flavor (External
ID) becomes the **untested alternative** everywhere it appears — stated as such,
kept for context, not deleted, because a future deployment of that flavor is a
configuration profile, not a code change, and the record needs its shape to say so.

Where it landed:

- `design.md` Context — the External-ID bullet's closing now records the decision
  (the owner's tenant is the classic flavor; the live acceptance run targets it)
  and marks the successor the untested alternative, kept in the record for context.
- `design.md` Goals — the tested-case bullet names the classic-flavor tenant's
  journey-varying issuer shape, with the successor's per-tenant shape marked the
  untested alternative (family anaphora only — the section is a mechanism section).
- `design.md` D6 — the flavor clause now states the owner's tenant is the classic
  flavor (OQ-A decided), so the configured literal is the journey-scoped one, while
  keeping the construction claim: which spelling a deployment configures decides
  only the literal, never the mechanism.
- `design.md` D9 — the record states the tenant is the classic flavor, the live run
  verifies its issuer literal (the tfp spelling) and its facts, and the successor's
  per-tenant shape is kept as context, not as a verified shape; the SPA/PKCE
  refresh-token fact is re-anchored to the tested tenant's own shape, with the
  successor's answer named the untested alternative's open fact.
- `design.md` SIA §1 — the tested case is the family's classic-flavor tenant (the
  successor the untested alternative).
- `design.md` §8 — OQ-A rewritten as **decided**: the flavor half closed, the two
  classic discovery facts (the tfp-path well-known document; the policy document's
  `issuer` equaling the tfp issuer) remaining live-run-to-verify, the direct-mode
  remedy standing unchanged, and the two-part run structure recorded (below);
  OQ-B re-anchored (verified for the tested flavor's SPA/PKCE shape, the successor
  the untested alternative's open fact); the "Open Questions (deferrable)" closing
  note updated (the flavor half of OQ-A and OQ-D decided; the discovery facts,
  OQ-B, OQ-E still deferrable).
- `tasks.md` 7.1 — the row's target is the classic flavor (see the two-part
  refinement below); the identity leg runs against the tenant's **per-policy (tfp)
  issuer** (the "or per-tenant" alternative removed from the row's chain).
- `proposal.md` — the Why identification and the What-Changes tested-case bullet
  name the classic flavor, with the successor marked the untested alternative
  (both Class B identification zones; the mechanism bullets stay Class A).

Not touched, deliberately: the delta spec, the release-notes draft, and every
operator-doc prescription (tasks 5.1/5.2) — all Class A, all already neutral; the
flavor decision gives them nothing to say.

## Ruling 2 — OQ-D decided: the helper-scoped KEYCLOAK_* settings keep their names

The owner confirmed D8's split. The principle, recorded verbatim in D8: **the
gateway itself is generic, but examples and tests can and should be IdP-specific.**

Where it landed:

- `design.md` D8 — the flag-for-pause closing replaced by the confirmation: the
  owner's principle verbatim, its reach past the settings block (the provisioning
  helper keeps its Keycloak Admin REST vocabulary; the probe scripts'
  Keycloak-specific fixtures — the login-flow driving against the local development
  instance — stay), and the statement that the ruling and D14 are one position.
- `design.md` D14 — a new **OQ-D agreement** paragraph states the two rulings read
  as one: Class A surfaces neutral because the gateway is generic; Class B working
  artifacts IdP-specific for their own facts — D8 applied to the local deployment's
  artifacts, D14 to the tested case's record; the check paragraph's D8 parenthetical
  now notes the boundary is owner-confirmed and the same position.
- `design.md` §8 — OQ-D rewritten as **decided** (no artifact change was needed;
  the confirmation removes the uniformity option); the deferrable closing note
  updated with it.

Conflict check (the ruling's own ask): one latent conflict found and fixed. Task
2.5's grep expectation allowed only "the helper-scoped settings and the provisioning
helper's own Keycloak-API vocabulary" to survive in `gateway/ tests/
scripts/probe_*.py pyproject.toml docs/routing.md` — but the tests' and probes'
local-instance fixtures (the local Keycloak URLs, the realm, the login-flow
driving) are exactly the IdP-specific examples and tests the owner's principle
permits, and the probes' fixtures stay by this ruling. The expectation now permits
"the local-instance fixtures the tests and probes carry for the local shape",
citing the D8 boundary and the owner's OQ-D principle. Everything else already
agreed: the provisioning helper keeps its vocabulary (tasks 2.1/2.4 rename only the
gateway-facing writes), and the operator-doc prescriptions stay class-vocabulary-only.

## Ruling 3 — the Core-issuerPattern-alignment operator row: refused

The owner: leave "exact match" as long as possible; the `issuerPattern` mechanism
can be adopted later if needed. Recorded as a ruled-out extension in `design.md`'s
**Non-Goals** (the home chosen for it, consistent with how the record handles scope
refusals — D6's rejected list carries the templating refusal the same way): the
gateway pins the exact issuer; Core-side pattern alignment remains the operator's
deployment concern **without** a new operator-doc row in this change; a future
change may adopt pattern matching when a real deployment needs it; the refusal is
the same posture as D6's templating rejection and D12's refused item (a) (Core's
regex is a multi-provider routing feature that would weaken the exact pin).

Verified: no alignment row was added to task 5.1 (and none existed to remove); the
only `issuerPattern` mentions in the change folder are D12's comparison and its
refused list, the Context's DIAL-family grounding, the Non-Goals refusal bullet
this round landed, and the historical evidence records. (Sentence amended in the
review-round-4 disposition pass, R4-6: the original omitted the Non-Goals bullet
the same round had landed.)

## The two-part live run (owner input for task 7.1)

The live B2C acceptance run is **two parts**: Part 1 — harness + B2C as IdP + the
local dial (the compose stack) + a test MCP toolset or app configured for B2C;
Part 2 — harness + B2C as IdP + the owner's real dial deployment (already
configured for B2C) + a real MCP app called `<tenant-app>`. The owner provides all
details (tenant values, the real deployment's coordinates).

Where it landed:

- `tasks.md` 7.1 — rewritten as the two-part row. **Part 1 is the controlled
  acceptance** and carries everything the row already specified (the full chain,
  the D9 provider-fact verifications, the refresh leg, the direct-trio remedy if
  the tfp-path fact fails). **Part 2 is the real-world acceptance** against the
  existing B2C-configured DIAL deployment and the `<tenant-app>` app — the same chain
  through the real app, ending in its live tool call. Part 2's pass criteria: the
  same chain with **no gateway reconfigure between the parts** — or, where the
  environments genuinely need different values, record exactly which
  per-environment configuration differs and why (an environment fact, not a
  gateway change). Evidence capture: both parts recorded in the evidence folder,
  Part 2's record capturing the deployment shape it ran against (the real
  deployment's DIAL and app names, its B2C configuration profile, the
  per-environment configuration delta if any).
- `design.md` §8 OQ-A — the decided entry carries the two-part structure in one
  clause (controlled, then real-world; same chain; no reconfigure between parts).
- `proposal.md` tested-case bullet — the live run is named two-part with both
  shapes identified.

Vocabulary boundary kept: the real deployment's and the app's names (`<tenant-app>`) are
Class-B working-artifact facts — they appear only in the enumerated live-run row
(task 7.1) and this evidence note, never in the operator docs or any Class A
surface.

## Second-order coherence edits beyond the four landings

- Task 2.5's grep expectation extension (ruling 2's conflict check — the one
  artifact change the rulings forced).
- OQ-B's re-anchoring and the "Open Questions (deferrable)" summary rewrite
  (ruling 1's knock-ons).
- A wording polish in D9 ("kept in the Context record as context", not "for
  context").

## Validation this round

- `openspec validate generalized-idp-federation` — **valid** (exit 0).
- `python scripts/check_publication_leaks.py` — **PASS** (204 tracked files
  scanned; 3 findings, all pre-existing and waived — two in
  `docs/evidence/d0a/review-round-1.md`, one in `scripts/import_background.py`;
  0 unwaived).
