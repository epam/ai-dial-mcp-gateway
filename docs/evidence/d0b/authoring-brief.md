# D0b authoring brief — the pre-publication cleanup

**What this workstream is.** D0b of the production roadmap
(`docs/production-roadmap.md` §"D0 — publication hygiene"): the cleanup that
precedes the public GitHub move, plus the owner decisions publication needs.
D0a (its record: `docs/evidence/d0a/leak-check-and-discipline.md`) froze the
situation with a standing discipline and a machine check; D0b retires the debt
that discipline left bounded. **D0b gates only the GitHub move, not the
iteration** — C3 has landed (2026-11-10) and the roadmap proceeds regardless;
D3, the closing re-judge of disclosed residuals, is a roadmap stage and is not
a publication blocker either. Like D0a, this is a docs/config workstream: a
direct commit after the review gates, not an OpenSpec change — but the full
security impact analysis still runs (`docs/security-analysis.md`); hygiene does
not skip the analysis.

**The decisions settled with the owner on 2026-11-17 (settled; do not
re-litigate):**

1. **Branch model: the published repository adopts `development` as the default
   branch.** The team's CI preparation (MR !3 on the internal GitLab remote,
   `<>`) delivers workflows that fire on `development` and `release-*`; with
   this decision they merge as-is, no trigger changes. How the current `master`
   maps onto `development` — a rename or a fast-forward — is decided at the
   move (Phase 4), not in this brief.
2. **Commit-history author identity: kept as-is.** Names in commit history are
   normal for a public repository. A rewrite would invalidate the provenance
   and reviewable trail this repository's process treats as evidence. No
   history mutation for identity.
3. **The archived OpenSpec change folders publish, neutralized.** The evidence
   trail is this repository's differentiator; the archive is not dropped and
   not excised from history. Machine detail in evidence files — instance
   names, personal paths — is scrubbed during the cleanup (Phase 2), and then
   everything publishes.
4. **License: Apache-2.0** — the `ai-dial` family license; the CI pull-request
   template already asserts contributions under Apache 2.0. The `LICENSE` file
   itself is a D0b deliverable (Phase 2).

**The plan, phased.** Each phase's action items name their owner per
`PROCESS.md`'s roles split: authoring and review are opus subagents;
implementation and gate runs are sonnet subagents. `PROCESS.md`'s Roles
section has the orchestrator routing artifacts and making the spec-gate
decision — it does not implement and does not review. The owner's standing
rule for this repository extends that: the orchestrator routes, verifies, and
commits, and every fix, any size, runs as a fresh subagent.

## Phase 0 — owner decisions

Recorded above. Nothing to implement; this brief is the record.

## Phase 1 — merge the team's CI-preparation MR

Merge MR !3 (`<>`) as delivered. Its workflows already fire on `development`
and `release-*`; decision 1 means no trigger changes are needed. The merge must
carry one recorded note — in the MR description or the evidence note — so a
future auditor does not rediscover it: **CI's bandit scope is `-r gateway`,
while the local gate runs `bandit -c pyproject.toml -r gateway scripts`.** The
four triaged bandit findings on the leak-check script (B404, B105, B603, B607;
dispositions in `docs/evidence/d0a/leak-check-and-discipline.md`) are consistent
with that narrowing — CI does not scan `scripts/` — but the scope difference is
recorded, not left to be inferred. The MR's templates reference `SECURITY.md`
and Apache-2.0; both land in Phase 2, before publication — fine as long as the
ordering holds (Phase 1 before Phase 2's templates, Phase 2 before Phase 4).

Phase 1 lands nothing itself. The MR's gates — the static tier at minimum,
plus the review pass on the CI diff — are run and recorded by the team's
change per the ladder; the merge act is the owner's (sessions land gated
branches; they never merge).

## Phase 2 — the D0b cleanup change

A single change, on the D0a precedent (direct commit after review gates; full
SIA in its design record). Action items:

- **Establish the D0b evidence note** — `docs/evidence/d0b/cleanup-and-move.md`,
  the D0b record, on the precedent of D0a's
  `docs/evidence/d0a/leak-check-and-discipline.md`. It carries what landed
  and the dispositions, and is the note the later phases append to: Phase 1's
  bandit-scope note (if not carried in the MR description), Phase 3's accepted
  findings, Phase 4's branch-mapping record and the `.gitlab-ci.yml`
  disposition's execution.
- **Fix the personal path in `scripts/import_background.py`** (line 15 — the
  absolute path under the author's profile). Placeholder or config-driven
  input; the waiver exists precisely so this fix is the only edit needed there.
- **Replace the internal instance name** across `.env.example`,
  `docker-compose.yml`, `gateway/settings.py`'s default, the docs, and the
  tracked probe scripts that carry it as a code default —
  `scripts/probe_routing.py:121` and `scripts/probe_front_door_paths.py:99`
  (the `DEFAULT_CORE_CONTAINER` constant) — using `<>` placeholders or neutral
  names, per the convention in `CLAUDE.md`'s publication-discipline section.
  The scripts are named so that a fresh implementer working only the named
  items cannot leave instance names in tracked code while the machine gate
  stays green — the instance-name class is exactly the class the machine
  check does not scan.
- **Decide `.gitlab-ci.yml`'s disposition.** The file is tracked and carries
  internal GitLab project paths — namespace and org values, not URL-shaped,
  so the hostname/URL sweep's named classes may not catch it. The disposition
  — delete at the move, neutralize, or leave as dead config — is decided here
  and recorded in the D0b evidence note; it takes effect at the move.
- **Scrub machine detail from the evidence trail** — `docs/evidence/`,
  `openspec/changes/archive/`, and any merged-but-unarchived change folder
  present at cleanup time (today `openspec/changes/discovery-well-known-aliases/`
  is tracked and unarchived). Decision 3 governs: neutralize, do not excise.
  The scrub includes the synthetic probe quotes in
  `docs/evidence/d0a/review-round-1.md` that the second baseline waiver covers.
- **Land the org-standard metadata files:** `LICENSE` (Apache-2.0),
  `SECURITY.md` (the CI bug template points reporters at it), and whatever
  else the standard requires — `CONTRIBUTING`, `CODE_OF_CONDUCT`, `NOTICE`;
  check what the sibling `ai-dial` components carry and match.
- **Retire both waivers in `scripts/leak-baseline.json`** — the
  `scripts/import_background.py` personal-path waiver and the
  `docs/evidence/d0a/review-round-1.md` personal-path waiver. The gate ends at
  zero findings, zero waivers; an empty waiver list, not a deleted check.
- **An explicit hostname/URL sweep of every tracked file.** The machine check
  deliberately does not scan that class (the D0a concession), so this sweep is
  a named opus review pass over the tracked set — internal hostnames, instance
  names, issuer/tenant values in URL shape — not a glance. Its findings and
  dispositions land in the D0b evidence note.

Gates: the full ladder per `CLAUDE.md` — static gates (leak check green at
zero waivers; bandit, pip-audit, Trivy per their standing invocations; the
publication leak check is the one this change exists to turn fully green), the
compose-boot gate (the change touches `docker-compose.yml` and a
`gateway/settings.py` default, so the composed stack is in scope; once the
compose-network default is neutralized, the local stack boots green only with
the real network name in the local `.env` — gitignored by design, exactly the
`.env.example` pattern — which is the implementer's defined route to a green
gate), the security review gate on the diff against its SIA, then the diff
review gate.

## Phase 3 — the full-history audit

The discipline is prospective-only — from D0a on — so a clean tip proves
nothing about history. An independent opus subagent walks `git log -p` end to
end, looking for: secret shapes, including the lowercase-hex blind spot the
leak check self-reports (a Keycloak client secret is by default lowercase-hex
UUID-shaped and passes the machine check — the boundary is stated in
`docs/evidence/d0a/leak-check-and-discipline.md`); personal paths; internal
hostnames and instance names; real issuer/tenant/org values; tracked-`.env`
episodes since removed from the tip. Findings are either fixed — a history
rewrite, which needs its own owner decision if anything is found — or recorded
as accepted, with the reason, in the D0b evidence note. Nothing publishes until
this pass is done and every finding is dispositioned.

## Phase 4 — the move

**Standing rule: the target repository stays private and receives nothing
until Phases 1–3 are green.** The repository under the `epam` GitHub
organization already exists (confirmed 2026-11-17) and carries only the team's
two-commit family-standard skeleton on its `development` branch — that is the
whole pre-publication state: a private repository with the family base and
nothing more. The
one-way door is the push to a public repository; until that push, nothing is
exposed. If the repository were public already, everything in history would
need to be publishable now — the rule exists to make that condition explicit
rather than accidental. The repository's exact slug is recorded in the D0b
evidence note at the move, not in this brief.

Mechanics only, after Phases 1–3 are green:

- Populate the existing repository: the corpus's birth — a single commit on the
  family-standard skeleton that branch carries, the master tip's tree composed
  with that skeleton per the composition's conflict policy, with
  `.gitlab-ci.yml` retired — lands as a pull request; no internal history
  publishes. The move's first
  steps are populate and configure — creation is already done.
- Set the default branch to `development` (decision 1; the master→development
  mapping — rename or fast-forward — is decided here, and recorded in the D0b
  evidence note).
- Configure the CI configuration the workflows read — secrets
  (`ACTIONS_BOT_TOKEN`, `DEPLOY_HOST`, `DEPLOY_ACCESS_TOKEN`,
  `DEPLOY_TRIGGER_TOKEN`, `DOCKERHUB_LOGIN`, `DOCKERHUB_TOKEN`) and variables
  (`DEPLOY_GITLAB_PROJECT_ID`, `DEPLOY_GITLAB_PROJECT_REF` for the deploy
  workflow; `ACTIONS_BOT_NAME`, `ACTIONS_BOT_EMAIL` for the release
  workflow's publish step) — names, never values; values live only in the CI
  environment. The deploy leg of the first CI run fails without the
  variables. Because the target exists ahead of time, this item and the
  branch protection below can be set up **before** the first push — which is
  what makes a green first CI run on day one possible.
- Branch protection on the default branch.
- First CI run green; templates verified against the landed metadata files.
- Flip the repository to public — the move's concluding act, once the first
  CI run is green and the templates are verified.
- The internal GitLab remote (`<>`) archived or redirected — the working
  remote until the move, read-only after it.

## Standing aside

D3 — the closing re-judge of every disclosed residual into
`docs/threat-model.md` — remains a roadmap stage. The roadmap's own wording
controls: D0b gates only the GitHub move. Residuals accepted at Phase 3 flow
into D3's ledger; they do not hold publication.

## Constraints

- No internal hostname, instance name, tenant value, or personal path appears
  in this brief or in anything D0b adds — `<>` placeholders where prose would
  name one; MR numbers are fine (`MR !3`), URLs are not.
- Prose names no person. "The owner" / "the team" is the accepted register for
  an evidence brief (the D0a precedent's voice); the author's name or anyone
  else's is not.
- The repo comment rule (`CLAUDE.md`) holds for every file D0b touches:
  comments and docs carry behavior and reason, never provenance. The rulings
  live here; the code and specs do not cite them.
- Prose is hand-wrapped at the repo's ruff line-length (88); markdown has no
  enforced gate, but this brief matches the D0a brief's wrapping.
