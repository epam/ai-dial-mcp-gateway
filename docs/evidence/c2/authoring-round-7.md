# Authoring round 7 — the listing read's 401/403 split: a trust fault is not an access denial (2026-11-06)

Author: the design author (this pass). This note records the second live-run finding
in the flow's listing read — the refusal-class conflation — the design decision that
fixes it (D16), and the revision of the change's artifacts to the decided semantics.
No implementation code was touched this round: the code delta is task group 9's,
executed by implementers against the new rows. The prior evidence files are
historical records and were not re-worded. (The round-7 *review* of the round-6
artifacts and its dispositions are recorded at `review-round-7.md`; this round is the
authoring round that follows them.)

## The finding (live-run evidence: `part1-b2c-setup.md` and the run's audit trail)

The stack the Part 1 setup record brought up (`docs/evidence/c2/part1-b2c-setup.md` —
Core recreated on the identity-provider entry, the gateway on the B2C profile, the
trust-chain probes green) carried the live sign-in run, and the run put a signed-in
user's flow through the flow's listing read with an identity token Core could not
validate. Core answered **401**. Two causes fit the shape, both Core-side trust
facts: Core's own JWKS fetch of the provider's keys rides the same flaky network the
gateway's discovery leg rides, and an audience or claims mismatch at Core's
identity-provider entry fails the validation the same way.

What the user was shown is the finding: **the no-access page** — "You do not have
access to this toolset… Ask your DIAL administrator to grant it, then start the
sign-in again" — an authorization verdict for an **authentication** failure. The
cause is `gateway/core.py`'s `_read_json`, which maps Core's 401 and 403 to the same
access-denied error:

    if response.status_code in (httpx.codes.FORBIDDEN, httpx.codes.UNAUTHORIZED):
        raise access_denied_error

The audit trail carries the same wrong class: the authorization leg's failure record
with the access-denied message (`_core_read_refusal` → `flow_leg_failed`, leg
`authorization`, the no-access wording as the reason) — nothing on the trail
distinguishes a trust fault from a denial. And Core logs **no record of its 401s**
(its auth filter refuses before any controller sees the call), so without a
gateway-side split the failure is undiagnosable: the operator is sent hunting an
access problem that does not exist, and the user is told to ask for access they may
already hold. The two answers have different remedies — the 403's is access granted
(anyone's access decision), the 401's is Core's trust configuration for the provider
checked (the operator's, and only the operator's) — and one class for both erases
the difference on every surface the failure reaches.

## The decision (design.md D16)

**The two codes become two classes with different remedies.** 403 keeps the
access-denied class — the deployment resolution's refusal of this caller, the data
path's own decision, the no-access page with its "ask your DIAL administrator"
remedy. 401 raises a new **trust-fault class** — an operator-facing `CoreError`
subclass, distinct from the access-denied class — whose fixed page tells the user the
sign-in cannot proceed and an administrator must check the trust configuration.
Fail-closed; the flow is consumed like the other refusals, no credential retained
(the record's identity access token and the provider's session refresh token are the
very material Core could not validate, so retaining them serves no re-run); the class
names nothing user-identifying — fixed vocabulary, no token or claim value.

The reasoning, in full (design.md D16 carries it):

- **Authentication is not authorization.** A 403 from the listing read is the
  deployment resolution's refusal of *this caller* — the data path's own decision.
  A 401 is Core's failure to validate the very token the sign-in established —
  nothing about the user's access is in it. One class for both answers a question
  the 401 never asked.
- **Two audiences, two actions.** The *user's* remedy for a 403 is access granted,
  then a re-run; for a 401 the user can do nothing but report — the page must say so
  instead of sending them to ask for access. The *operator's* diagnostic differs
  with the class: a 401 means Core's provider entry for the identity provider — its
  issuer pattern, its key set, its audience — or the reachability of that key set; a
  401 burst across users is a trust-configuration or reachability event, never an
  access-change event, and the audit trail is where the two are told apart, because
  Core's own logs cannot do it.
- **The adjacent site is named, not silently widened.** The credential call's own
  401/403 branch (`gateway/flow.py`, on the USER-level credential API answer) also
  maps both codes to the access-denied refusal today; it is **not** split by this
  decision — that call answers a different question, its 401 semantics at Core's
  credential API are not evidenced by this run, and a split there is its own finding
  against its own live evidence. D16 records it so the implementer neither silently
  widens nor silently ignores it; task 9.2 carries the same boundary.

## The SIA assessment (design.md, SIA §1/§2/§3/§4/§5/§6/§7)

- **The new fault page's information content:** fixed vocabulary only — the sign-in
  cannot proceed, an administrator must check the trust configuration — with no
  token, claim, caller, or provider value on the page or in its audit record
  (never-cut 5's class; the delta spec's new scenario pins the
  no-user-identifying-value property).
- **The threat rows affected:** DT-EP5-9's forged-answer residue gains nothing — a
  forged 401 denies one flow exactly as a forged 404 does; the split changes what
  the denial is *called*, never what it costs. What changes is the **detective
  control** (§5 item 8: four distinguishable refusal shapes on the trail —
  no-access, unknown-toolset, trust fault, deployment fault — where the prior
  mapping collapsed the 401 into the no-access class) and one **removed defect**:
  the wrong-class page and record — a trust fault rendered and audited as an access
  denial — is a diagnosability defect, recorded as removed in the threat-model delta
  (§7's new bullet, task 9.1).
- **No mitigation changes and the level does not move:** the split adds a class on
  an already-priced read, moves no boundary, adds no entry point — §2 gains the
  explicit "does not move the level" note beside D15's, invariant rows 4 and 5 gain
  the split's statements, §6's grouped item 8 names the four shapes, and the level
  stays High with the review depth full.

## The per-artifact semantic diff, this round

**specs/mcp-signin/spec.md** — the trust-fault amendment, declared in both touched
requirements:
- The federation-flow requirement's text gains the refusal-class clause (403 access
  denied / 401 trust fault, with the operator's remedy named — Core's provider
  entry: issuer, key set, audience, or the key set's reachability — and the
  consumed-flow, no-credential-retained, nothing-user-identifying semantics); the
  declared-amendments note gains the split as its fourth clause.
- The retained "DIAL authorization denied" scenario's WHEN names the 403 (the code
  the refusal is); a new scenario is added — "A token Core cannot validate is a
  trust fault, not an access denial" — with the 401's WHEN and the fault-page,
  consumed-flow, fixed-vocabulary-audit THEN.
- The app-resource requirement's refusal enumeration gains the 401 trust-fault
  clause (both reads share the gateway's one answer-to-refusal mapping), its
  closing comparison becomes the four-shape discipline, its amendment note declares
  the third clause, and the retained "App authorization denied" scenario's WHEN
  names the 403. No other scenario changes; the existence refusals, the impossible
  branch, and the discovery/mapping/guard requirements are untouched — the split
  changes what the read's refusals are *called*, and only there.

**design.md** — D16 added (the finding with the live audit trail, the decision, the
adjacent-site scope, the SIA assessment); a Goals bullet; the SIA's §1
business/implementation paragraphs, §2 level note, §3 invariant rows 4 and 5, §4's
listing-read row (the forged-401 clause), §5's DT-EP5-9 item 8 and disposition, §6's
grouped item 8, and §7's threat-model delta bullet (the fourth refusal shape, the
wrong-class defect recorded as removed) plus the closing no-residual bullet's D16
narrowing; a Risks line (the priced trade: the consumed flow forecloses a blind
retry, which costs one re-run, against the wrong-class page's misdirected operator
hunt).

**tasks.md** — task group 9 added (9.1 the threat-model note, before the code per
the standing order; 9.2 the split itself: `_read_json`'s UNAUTHORIZED→the new
trust-fault class with FORBIDDEN keeping the access-denied class, the flow's page
for the new class in `_core_read_refusal`, the 401→fault and 403→denial tests both
on the listing read, and the operator-docs row — `docs/gateway-configuration.md`'s
"The Core routes the flow reads, and why" section gains the trust-fault shape),
unticked; the group-8 rows' checkbox typo (a stray `]`) repaired in passing — a
formatting fix, no semantic change.

**proposal.md** — a "The read's refusal classes are split by what Core's answer
means" bullet in What Changes; the Capabilities bullet extended with the split (the
denial scenario scoped to the 403, the new trust-fault scenario, the app-flow
enumeration aligned); the `gateway/core.py`, `gateway/federation.py`, `tests/`, and
`docs/threat-model.md` Impact lines extended.

**release-notes-draft.md** — the users section gains the trust-fault fix (the page
now says the deployment must fix it, not the user's access to grant); the team
section gains the finding/fix record with the SIA pointers.

## What this round did NOT do

No implementation code, threat-model text, operator doc, or test was touched — the
model note, the code, the tests, and the operator-doc row land against task group 9
(the model first, per the standing order). The credential call's 401/403 mapping is
deliberately untouched and dispositioned as the adjacent site (D16, task 9.2's
closing clause). No commit was made. The group-6 gates re-run on task group 9's
diff.

## Validation this round

Run after the edits, from the worktree, the main checkout's venv python
(`PYTHONUTF8=1`):

- `openspec validate generalized-idp-federation --strict` — **valid** (exit 0); the
  new scenario header and the re-worded retained headers (matched against the main
  spec) pass the delta discipline unchanged.
- `python scripts/check_publication_leaks.py` — **PASS** (exit 0; 226 tracked files;
  3 findings, all pre-existing and waived — two in `docs/evidence/d0a/review-round-1.md`,
  one in `scripts/import_background.py`; 0 unwaived). This round introduces no
  provider-product vocabulary and no internal hostname; the record above names none
  either.

One gate-keeping action this round had to take, recorded for the caller: the first
leak-check run **failed on two pre-existing unwaived personal-path findings** —
`availability-read-diagnosis.md:5` and `review-round-7.md:8`, both naming the
personal filesystem path of the sibling Core checkout, both committed in `210d3eb`
(the task-8 commit) and untouched by this round's edits. They were repaired with the
same fix the Part 1 record itself received when it was flagged (the `part1-b2c-setup.md`
precedent): the personal path elided to `<the-sibling-core-checkout>` with the
elision noted — a redaction that changes no evidential content, applied so the
blocking gate could be green at all. If the owner prefers a different disposal
(a waiver, a revert of these two lines), the two edits are the only changes this
round made outside the change folder and this evidence file, and they are the first
to undo.
