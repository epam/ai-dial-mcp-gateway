# Authoring round 6 — the availability oracle re-pinned to the deployment-listing read (2026-11-05)

Author: the design author (this pass). This note records the live-run finding in the
flow's availability read, the design decision that fixes it (D15, the diagnosis's
Option A), and the revision of the change's artifacts to the decided semantics. No
implementation code was touched this round: the code delta is the next round's,
executed by implementers against the new task group 8. The prior evidence files are
historical records and were not re-worded.

## The finding

Recorded in full, with the Core-side evidence, at
`docs/evidence/c2/availability-read-diagnosis.md` (same date). The short form: the
live B2C run put the first non-admin identity through the flow — a user whose token
carries `roles=["<tenant-role>"]`, no admin role — and the flow's availability
read returned 403 for a toolset ("notion", GLOBAL-scope, no `user_roles`
restriction) that Core's own MCP data path admits. The read the flow used is
`GET /v1/toolsets/platform/{name}`, whose authorization is the caller's admin role
alone (`AdminRoleAuthorizationService`; the entity's `user_roles` and publicness
play no part), while the data path authorizes through `findDeployment` →
`RoleBasedEntity.hasAccess(userRoles)` — a public toolset serves any authenticated
caller. Two authorization logics, no shared code, a structural (not tunable)
mismatch: the toolset lives in the `platform` bucket because that is where the
platform admin API creates it, and no `user_roles` value could change the 403.

## The decision (design.md D15)

**Option A, adopted: the flow's availability oracle becomes `GET /openai/toolsets/{name}`** — the
deployment-listing route, whose authorization is the data path's own by construction
(`ToolSetController.getToolSet` and the MCP proxy controller both resolve through
`DeploymentService.findDeployment`). The flow's "may this user sign in?" and the
data path's "may this user call?" become one decision, never two that can disagree.
The bucket-based platform settings read stops deciding availability; `TOOLSET_BUCKET`
is retired with it. Options B (pre-flight the listing read, keep the platform read on
a service credential — drops the per-user authorization enforcement the read exists
to provide) and C (an operator workaround creating user-callable toolsets in the
`public/` bucket — changes administration practice, leaves the defect latent) are
rejected with the diagnosis's reasons.

**The shape decision:** one read, and the status read is deleted, not merged. The
listing read serves availability, the settings projection the consent branch builds
from, and the per-caller statuses (enriched on the listing route on every answer);
the old two-call fallback (`read_toolset_for_flow`) asked a second route when the
first answer carried no statuses, and under the re-pinning its two routes are the
same URL — the fallback could only re-ask the route that just answered. The absence
rule survives as the whole discipline: an answer with no readable status at either
level is not signed in, and the flow fails closed into the kind branch (the priced
trade, stated in the design's Risks: on a Core build whose listing route does not
enrich the statuses, no short-circuit ever fires — an OAUTH toolset re-runs its
consent, the benign loop; a non-OAuth toolset is refused as ever).

## The field-parity verification (fresh, against Core at `6dae044`, the same commit the diagnosis read)

The question the diagnosis left open: does the listing route's `auth_settings`
projection carry everything the flow consumes from the platform settings read
(`gateway/core.py`'s `ToolsetSettings` and `read_toolset_settings`)?

**Consumed members** (all read from the answer's `auth_settings`):
`authentication_type`, `client_id`, `authorization_endpoint`, `code_challenge`,
`code_challenge_method`, `redirect_uri`, `scopes_supported`,
`user_level_auth_status`, `global_auth_status`.

**The listing projection** (`ToolSetData.toData`, `server/.../data/ToolSetData.java:68`
→ `ResourceAuthSettingsData.toData`,
`server/.../data/ResourceAuthSettingsData.java:21-32`, snake_case, `NON_NULL`):
`authentication_type`, `client_id`, `authorization_endpoint`, `resource`,
`redirect_uri`, `code_challenge`, `code_challenge_method`, `api_key_header`,
`global_auth_status`, `app_level_auth_status`, `user_level_auth_status`,
`scopes_supported`, `dynamically_registered`.

**Verdict: parity is complete — every consumed member is projected under the same
wire spelling; the flow loses nothing it reads.** The platform read's extra members
are all non-consumed: `token_endpoint` and `token_endpoint_auth_method` (never read
by the flow), and the secret members — `client_secret`, `code_verifier`,
`client_secret_hint` — which the platform route redacts for every non-admin caller
(`ConfigResourceController.redactSecretFields`, lines 2030-2043) and which the
listing projection has no fields to carry at all. That last difference is a
narrowing recorded in the SIA: never-cut 2's public-projection property (the
upstream PKCE verifier never leaves Core) becomes structural on the listing route —
there is no code path that could project it. The per-caller statuses the signed-in
check reads are enriched on the listing route on every answer
(`ResourceAuthStatusEnricher.enrichToolSet`, `ToolSetController.java:70-71`),
exactly as the platform route enriches (`ConfigResourceController.java:1129-1138`).

## The semantic notes — three answer-shape differences, all alignments with the data path

1. **A toolset whose stored blob carries no `auth_settings` block.** The platform
   route answered 200 without the member (the gateway's "carries no authentication
   settings" refusal — a deployment fault); the listing route cannot project it —
   `ToolSetData.toData` dereferences the block — and answers 500. The gateway's
   unreachable-or-unreadable branch takes it: the same operator-facing fault page,
   fail-closed in both shapes, never an existence answer.
2. **A toolset whose stored blob is invalid.** The platform route answered 200 with
   `status=invalid`; the listing route answers 404, because an invalid entity never
   enters the merged config — which is exactly what the data path resolves from, so
   the 404 is the data path's own answer, not a new false refusal.
3. **Resource-sourced toolsets** (created in a user's or the public bucket, not the
   platform one). The platform read 404'd them — a false "not registered" for
   toolsets the data path serves; the listing route resolves them through the same
   resource-descriptor branch of `findDeployment` the data path uses.

In every case the listing read's answer is the answer the data path's own resolution
would give — the property Option A was chosen for, holding beyond the
authorization axis the finding pinned.

## The SIA re-pricing (design.md, SIA §2/§3/§4/§5/§6/§7)

The availability read is a Core-authorization surface, so the change is re-priced:
**the read's authorization becomes exactly the data path's — neither uniformly
stricter nor uniformly narrower than the old read, but aligned.** Relative to the
platform read it is *narrower* on the admin axis (an admin is no longer admitted
past availability for a role-restricted toolset the data path would refuse them)
and *wider* on the non-admin axis (a non-admin is admitted for a public toolset the
data path serves — the finding's fix); on both axes it now equals the data path and
never exceeds it. The read remains a pre-check, not the enforcement — Core
re-authorizes on every data-path call, unchanged — so no confidentiality or
integrity exposure changes; the change is an availability correction (a
denial-of-service defect class removed, recorded as removed in the threat-model
delta). The deny-page semantics are unchanged: 403 the no-access page, 404 the
not-registered page, other or unreadable the fault page. The forged-answer residue
is unchanged in kind — same internal leg, same live-user identity token, same
configured Core; T5-7's acceptance class (RES-19) carries, one member of the same
Core answer relocated. The impact level stays **High** (the discovery shape set it;
this delta adds no entry point, no grant type, no new integrity input), so the
security review gate's depth stays full.

## The per-artifact semantic diff, this round

**specs/mcp-signin/spec.md** — the four rows the diagnosis pinned, plus the
coherence re-pins that follow from them:
- The federation-flow requirement's authorization-bearing clause re-pinned to "the
  deployment-listing read of the toolset as that user — `GET /openai/toolsets/{name}`,
  the read whose authorization decision is the MCP data path's own", with the
  "settings read"/"settings answer" mentions in the requirement text re-worded to
  the listing read; the declared-amendments note gains the third clause.
- The "DIAL authorization denied" scenario's WHEN re-based on the listing read's
  refusal; a new scenario added — "A public toolset serves every user the data path
  serves" (the non-admin/public-toolset pass, the regression pinned normatively).
- The "Unknown toolset refused at the flow's settings read" scenario's WHEN re-pinned
  to the listing read; the scenario's title is retained verbatim as its stable
  identifier — the delta discipline (`openspec validate --strict`) matches scenarios
  by header against the main spec and has no scenario-level rename, so a renamed
  header reads as a dropped scenario; the amendment note declares the retention and
  states that the body — the normative content — names the surface precisely.
- The discovery requirement's mirror-property sentence and authentication-kind
  sentence, and the "Dynamic toolset served without local configuration" scenario's
  parenthetical, re-pinned to the listing read — the requirement added to the delta
  as MODIFIED with a declared amendment.
- Coherence re-pins beyond the diagnosis's four rows, each a declared amendment:
  the authorization-requests requirement's retained note (the toolset backstop
  names the listing read), the app-resources requirement's closing comparison ("the
  same three-shape discipline the toolset listing read carries"), and two
  main-spec scenarios the diagnosis had not listed that name the settings read as
  the existence decider — the toolset-mapping requirement's "Unset mapping serves
  dynamically" and the name-guard requirement's "A valid dynamic name resolves with
  no local configuration" — both requirements added to the delta as MODIFIED so the
  main spec cannot survive the archive naming a surface the flow no longer reads.

**design.md** — D15 added (the finding, the decision, the field-parity
verification, the semantic notes, the shape decision); a Goals bullet; the SIA's §1
business/implementation paragraphs, §2 level statement, §3 invariant row 4
("Preserved, with the pre-check aligned"), a new EP5 delta table and row for the
flow's Core read, a DT-EP5-9 mitigation block, grouped-list item 8, and §7's
threat-model delta bullet (the vocabulary sweep and the removed-defect record); a
Risks line (the one-read shape's priced trade); Migration Plan step 8
(`TOOLSET_BUCKET`'s removal).

**tasks.md** — task group 8 added (8.1 the threat-model re-pin, before
implementation per the standing order; 8.2 the re-implementation with the re-based
and new tests, including the non-admin/public-toolset PASS case and the admin-axis
refusal), unticked; task 7.1's Part 1 and Part 2 gain the live verification of the
fix (a public test toolset and a non-admin federated user in Part 1; a
non-admin-callable toolset in Part 2 where the deployment serves one).

**proposal.md** — a "The flow's availability decision becomes the data path's own"
bullet (with the `TOOLSET_BUCKET` BREAKING note); the Capabilities bullet and the
`gateway/core.py`/`gateway/settings.py`/`.env.example`-and-docs/`tests/`/
`docs/threat-model.md` Impact lines extended.

**release-notes-draft.md** — the users section gains the non-admin fix paragraph
and the setting's removal; the team section gains the finding/fix record with the
parity and re-pricing pointers.

## What this round did NOT do

No implementation code, compose file, `.env.example`, operator doc, probe, test, or
threat-model text was touched — the code and the model land next round against task
group 8 (the model first, per the standing order). No commit was made. The
group-6 gates re-run on that round's diff.

## Validation this round

- `openspec validate generalized-idp-federation --strict` — **valid** (exit 0). One
  iteration was needed: the first run refused the renamed scenario header ("Unknown
  toolset refused at the flow's listing read" read as dropping the main spec's
  "…settings read" scenario — the delta discipline matches scenarios by header and
  has no scenario-level rename), so the title is retained as the identifier and the
  body re-pinned, as the amendment note declares; the second run is the recorded
  pass.
- `python scripts/check_publication_leaks.py` — **PASS** (exit 0; 222 tracked files
  scanned; 3 findings, all pre-existing and waived — two in
  `docs/evidence/d0a/review-round-1.md`, one in `scripts/import_background.py`;
  0 unwaived).

## Addendum — the round-7 disposition pass (2026-11-06)

Review round 7 (`docs/evidence/c2/review-round-7.md`) verified this round's artifacts
against the Core source and returned three actionable findings; all three were
disposed the same day in the artifacts only: task 8.2's operator-doc surface extended
to the two live doc sections still documenting the retired read (R7-1), D15's
"exactly when" sentence tightened to the authorization-scoped property (R7-2), and
the spike scripts' platform-route use dispositioned in the 8.2 sweep (R7-3). No code
was touched and no commit was made; both gates re-ran green after the edits (the
runs are recorded in the review file's disposition section). The full disposition
record lives in `docs/evidence/c2/review-round-7.md`.
