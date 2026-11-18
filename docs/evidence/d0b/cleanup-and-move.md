# D0b — the cleanup and the move

The D0b record: the pre-publication cleanup change (Phase 2 of the plan in
`docs/evidence/d0b/authoring-brief.md`) and the envelope the later phases append to.
Opened here with the change's design record and its full security impact analysis;
gate results, the hostname/URL sweep's findings and dispositions, Phase 3's accepted
findings, and Phase 4's records (branch mapping, repository slug, the
`.gitlab-ci.yml` disposition's execution) are appended by later rounds. Written to
stand alone on the D0a precedent: a fresh reviewer needs this note, the brief, and the
files named below.

**What the change is.** A docs/config workstream on the D0a precedent — a direct
commit after the review gates, not an OpenSpec change — that retires the bounded
backlog D0a left: the internal instance name and its derived network/container names
out of every tracked file; the personal path out of `scripts/import_background.py`;
real external-provider tenant values out of the C2 evidence; assorted machine detail
(host-local address literals, an internal resolver domain, one person's name) out of
the records; both leak-baseline waivers retired to an empty list; and the
org-standard metadata files (`LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`) landed.
The full security impact analysis runs anyway (`docs/security-analysis.md`) — hygiene
does not skip the analysis.

**A note carried for Phase 1 (so no future auditor re-derives it).** The merged
CI-preparation MR's bandit scope is `-r gateway`, while the local gate runs
`bandit -c pyproject.toml -r gateway scripts`. The four triaged bandit findings on
the leak-check script (B404, B105, B603, B607; dispositions in
`docs/evidence/d0a/leak-check-and-discipline.md`) are consistent with that narrowing —
CI does not scan `scripts/`. The scope difference is recorded here, not inferred.

## The design record

### The neutral-name scheme

The internal instance name and everything compose derives from it (the default
network `<name>_default`, the Core container `<name>-core-1`) are replaced by one
neutral instance name: **`dial-instance`**, giving `dial-instance_default` (network)
and `dial-instance-core-1` (Core container). Why this name: it is DNS-label-safe
(compose network and container names must be), self-descriptive in the docs' own
vocabulary ("the DIAL instance"), carries no person, ownership, or org marker, and
the compose-derived shapes follow from it mechanically, so quoted command/output
pairs in evidence stay coherent after one substitution. A `<>` placeholder is NOT
workable here: the machine check's own charset analysis is the reason — `<` fails the
credential charset, compose cannot interpolate it, and a default that cannot resolve
is a trap, not a default. The neutral name is an example value, exactly the class
`IDP_ISSUER`'s RFC 2606 placeholder already belongs to.

Two substitution registers, applied by file class:

- **Quoted machine output and commands** (evidence records, background PoC records,
  env blocks): mechanical prefix substitution, the internal name → `dial-instance`,
  in every spelling including derived names. The records stay internally coherent
  (a command and its output both change), and become illustrative rather than
  verbatim. The substitution is this change's act and is disclosed once, here — the
  files themselves carry no per-file note (the comment rule: behavior and reason,
  never provenance).
- **Live prose** (instructional docs, and any prose that would name a real tenant or
  host value): `<>` placeholders per `CLAUDE.md`'s publication discipline —
  `<local-instance>` for the local instance folder (the vocabulary the background
  corpus's import-time redaction already established), `<tenant-issuer>`,
  `<tenant-client-id>`, `<tenant-host>`, `<provider-entry-name>` for the
  external-provider values, `<host-address>` and `<internal-domain>` for the two
  one-off literals, `<name>` for the D0a rule-sample profile segments.

### The edit plan, per site

**Code and configuration (the behavioral defaults).**

| Site | Current state's role | Prescribed replacement |
|---|---|---|
| `.env.example:129` | `DIAL_COMPOSE_NETWORK` carries the real local network as its committed default | Value → `dial-instance_default`; the adjacent comment states the default is a neutral example name and the local deployment's real network name lives only in the gitignored `.env` |
| `docker-compose.yml:146` | The gateway service's `${DIAL_COMPOSE_NETWORK:-…}` fallback names the real network | Fallback → `dial-instance_default` |
| `docker-compose.yml:352` | The external network's `name:` fallback, same value | Fallback → `dial-instance_default`; the two spellings in the file must remain identical |
| `gateway/settings.py:368` | `dial_compose_network`'s model default names the real network | Default → `"dial-instance_default"`; the field comment above it stays valid unchanged |
| `scripts/probe_routing.py:121` | `DEFAULT_CORE_CONTAINER` names the instance's real Core container | → `"dial-instance-core-1"`; local runs pass the real name via the existing `--core-container` flag |
| `scripts/probe_front_door_paths.py:99` | `DEFAULT_CORE_CONTAINER`, same role | → `"dial-instance-core-1"`; same flag route (`--core-container`) |

`scripts/probe_front_door_paths.py:100` (`DEFAULT_GATEWAY_CONTAINER`) **stays**: it
derives from this repository's own compose project name, which publishes with the
repository — it is not internal-instance detail. Wiring the container default to read
`.env` instead was considered and rejected: it adds a setting surface to a dev probe
for no gain, since the flag already exists and a wrong default fails loudly
(`docker exec` on a name that does not exist).

**The import script's input (`scripts/import_background.py:14-17`).** The hardcoded
source path — the absolute path under the author's profile — becomes a required
first positional CLI argument (the background archive's harness-integration folder),
with an argparse refusal naming the argument when it is absent. No default, no path
fragments: a default would have to be either the real path (the exposure, back where
it started) or an invented one (a trap). The destination, file list, and rewrite
logic are untouched; the script's behavior for anyone who runs it is unchanged apart
from supplying the input it always had.

**Live docs.**

- `docs/gateway-configuration.md:70` — the `DIAL_COMPOSE_NETWORK` row's default
  column → `dial-instance_default`.
- `docs/pod-contract.md:84` — the topology row's default value →
  `dial-instance_default` (the row's dev-only classification is unchanged by a
  dev default's new spelling).
- `docs/local-environment.md:9` — the sibling folder is named by its real local
  spelling; → the `<local-instance>` placeholder, with the sentence still carrying
  what an operator needs: a local-only git repository with no remote, sibling of this
  repository.

**The instance-name scrub (mechanical substitution, decision 3: neutralize, never
excise).** Every file below carries the internal instance name or a name compose
derives from it; the occurrence counts are the implementer's verification baseline.
Line counts as of 2026-11-17:

| File | Lines |
|---|---|
| `docs/evidence/c2/part1-b2c-setup.md` | 10 |
| `docs/evidence/c2/task-6-gates.md` | 1 |
| `docs/evidence/c2p5/gate-compose-boot.txt` | 2 |
| `docs/evidence/c3/pod-shape-probes.md` | 3 |
| `docs/background/poc-dial-mcp-signin.md` | 2 |
| `docs/background/poc-litellm-comparison.md` | 3 |
| `docs/background/design.md` | 1 |
| `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/authoring-brief.md` | 1 |
| `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/design.md` | 1 |
| `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/proposal.md` | 1 |
| `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/tasks.md` | 1 |
| `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/evidence/review-round-1.md` | 3 |
| `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/evidence/group-6.md` | 1 |
| `openspec/changes/archive/2026-10-20-fix-dcr-response-conformance/evidence/implementation.md` | 1 |
| `openspec/changes/archive/2026-11-03-dynamic-toolsets-and-fresh-claims/evidence/gates.md` | 2 |
| `openspec/changes/archive/2026-11-03-dynamic-toolsets-and-fresh-claims/evidence/live-runs.md` | 1 |
| `openspec/changes/archive/2026-11-04-apps-with-mcp-endpoints/evidence/acceptance-live.md` | 1 |
| `openspec/changes/archive/2026-11-04-apps-with-mcp-endpoints/evidence/gates-implementation.md` | 4 |
| `openspec/changes/archive/2026-11-04-apps-with-mcp-endpoints/evidence/review-1-findings-and-dispositions.md` | 2 |
| `openspec/changes/archive/2026-11-13-front-door-addressing-and-redirect/evidence/instrument-run.md` | 1 |

The merged-but-unarchived `openspec/changes/discovery-well-known-aliases/` was
scanned on 2026-11-17 and carries none of the machine-detail classes — nothing to
scrub there. End state: a full-text grep for the pre-substitution name (read the
token from any scrub-list file before editing it; this record does not repeat it)
returns nothing across the tracked set.

**The tenant scrub (real external-provider values; `<>` placeholders).** Two files:

- `docs/evidence/c2/part1-b2c-setup.md` — the external-provider profile block
  (around lines 64-68) carries the real issuer URL (tenant hostname, tenant GUID,
  policy name in its path) and the provider's client id; the issuer →
  `<tenant-issuer>`, the client id → `<tenant-client-id>`. The provider-entry
  name the local Core configuration uses (around lines 80 and 152) →
  `<provider-entry-name>`.
- `docs/evidence/c2/interactive-probe.md` — the redirect-trace quotes (around lines
  98-105 and 203-210) carry the tenant hostname and the client id inside
  authorize URLs; hostname → `<tenant-host>`, client id → `<tenant-client-id>`.

These two files are where the **issuer/hostname/client-id family** appears as values
(verified 2026-11-17 by class-pattern search over the tracked set). That earlier
search's "only two files" statement covered that family alone and did not extend to
the provider's **app/role-name family** or to **real-tenant subject identifiers** —
both of which the independent hostname/URL sweep later found live (its findings and
their scrub are recorded in the append below). The family's names inside quoted
grep-pattern strings elsewhere are pattern vocabulary, not values, and stay. The
profile block's secret line is already a placeholder and needs nothing.

**Assorted machine detail, one file each.**

- `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/evidence/dcr.md:372`
  — a host-local address literal inside a quoted health-probe result →
  `<host-address>`.
- `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/evidence/gates.md:254`
  — an internal resolver search domain inside a quoted `/etc/resolv.conf` line →
  `<internal-domain>`.
- `docs/background/decisions/DR-0001-keep-nginx.md:4` — a person's name in the
  Deciders line → "the human owner". (Decision 2 keeps names in *commit history*;
  file content is not commit history, and the published decision record needs a
  role, not a person.)
- `.github/workflows/test.yml:172` — a comment's parenthetical names an internal
  sibling project as the reason the Pip analyzer is enabled; drop the parenthetical —
  the stated reason (a pip/hatchling project with a PEP 621 pyproject) carries the
  behavior on its own. Comment-only edit.
- `docs/evidence/d0a/review-round-1.md:63-64` — the F3 finding's probe samples quote
  profile-path shapes with concrete sample name segments; rewrite the samples to the
  `<name>` placeholder spelling (`C:/Users/<name>/…`, the POSIX branch beside it).
  The evidence survives — F3's claim is about the directory segment's case
  tolerance, which the placeholder spelling still shows — and the rule engine no
  longer matches the quotes, which is what retires the file's waiver.

**Keep-rulings (scanned, judged not machine detail; the sweep and the review gates
re-examine them).** The gateway container name constant and its quotes in evidence
(this repository's own compose project name, published with the repository); the
local development realm test user's `sub` UUIDs and the RFC 9700 ledger's synthetic
jti values (random values minted by the local development realm, no correlation
surface to any real identity) — this keep is **scoped to the local development
realm's own fixtures**; real-tenant subject identifiers are not covered by it and
are scrubbed (the sweep's Finding 1, below); the `epam` GitHub-organization
references and `com.epam.*` DIAL Core package paths (public open-source
identifiers); the `skills-demo` demo-app name as a probe default and audit-quote
value (a self-descriptive local fixture name with no correlation surface — the
sweep's borderline keep, recorded below); link-local metadata address literals
(taxonomy constants, not hosts); the `.env`-profile and worktree names quoted in
C2/C2.5 records (this repository's own branches and worktrees).

### The local-`.env` consequence

The real values the neutral defaults displace move to the local gitignored `.env`,
exactly the `.env.example` pattern: `DIAL_COMPOSE_NETWORK=<the real network name>` —
compose reads `.env` for the `${…}` interpolation and the settings model reads it
for the field, so both the network join and the setting stay correct with one line.
Without that line a bare `docker compose up` fails loudly (network not found) —
fail-loud is the designed behavior, the same stance `IDP_ISSUER`'s placeholder
default takes. Probe runs that read Core's logs pass the real container name via
`--core-container`. No real value is written in any tracked file by this change.

### The metadata set

Checked against the sibling published component (read-only reference, 2026-11-17):
it carries `LICENSE` (full Apache-2.0 text), `SECURITY.md`, and `CONTRIBUTING.md`;
no `CODE_OF_CONDUCT`, no `NOTICE`. This repository matches that set — the three,
and neither of the two:

- **`LICENSE`** — the full Apache-2.0 text, copyright holder line matched to the
  family's ("EPAM Systems, Inc."), year 2026 (this repository's first publication
  year). `pyproject.toml` already declares `license = "Apache-2.0"` and the CI
  pull-request template already asserts contributions under Apache 2.0; the file
  makes both true.
- **`SECURITY.md`** — the reporting channel is ruled (owner decision 2026-11-17):
  GitHub private vulnerability reporting. Modeled on the family's wording: do not
  file public issues for vulnerabilities; use the repository's "Report a
  Vulnerability" advisory form; a reply and progress updates follow. The slug it
  names is the one the release workflow already publishes (`ghcr.io/epam/…` carries
  it), with the explicit dependency that Phase 4 verifies the pointer against the
  actual repository before the public flip.
- **`CONTRIBUTING.md`** — a short pointer to the family-wide contributing guide,
  matching the sibling's shape.

### The baseline's end state

Both waivers in `scripts/leak-baseline.json` retire — the
`scripts/import_background.py` personal-path waiver (the fix above removes the
exposure) and the `docs/evidence/d0a/review-round-1.md` personal-path waiver (the
sample rewrite removes the match). End state: `"waivers": []` — an empty list, not a
deleted check; the check script itself is untouched.

**`.gitlab-ci.yml` needs no waiver, and gets none.** Read of
`scripts/check_publication_leaks.py` (2026-11-17): the rule set is exactly
`personal-path`, `secret-shape`, `tracked-env`. The file's internal GitLab project
references — the template include's `project:` key (~line 11) and the deploy
trigger's `project:` key (~line 25), namespace-shaped values naming this repository
inside the internal GitLab — are none of the three classes: not a user-profile path,
not a credential-shaped literal, not a tracked `.env`. The machine check does not
flag the file, so a baseline entry would be a waiver for a finding that does not
exist — and an unused waiver is reported as a note by design. The file's disposition
is therefore held where the class is held: the hostname/URL sweep records it as a
finding, dispositioned by the owner's ruling of 2026-11-17 — keep live and untouched
until the move (the working remote's CI is live config); it is retired or replaced
with the internal remote at Phase 4, and that execution is appended to this note
then.

### The threat-model and delta-spec determination

**No threat-model entry, no delta spec.** Reasons, per `docs/security-analysis.md`:

1. The change removes exposure; it adds no control to any attack-surface entry
   point. The neutral defaults and placeholders land in the code, compose, and
   records they govern — nothing exists only in prose, so there is no mitigation
   left un-landed.
2. No threat disposition changes: no entry point, trust boundary, credential, or
   grant type is touched (the SIA below), so no entry in `docs/threat-model.md`
   moves from mitigated to accepted or back.
3. `docs/threat-model.md` §1 describes the external-network join without naming the
   network ("the instance's compose network as an external network") — verified
   2026-11-17 that the model carries no instance name — so it needs no edit.

The publication discipline itself is a repository-level process control, already
landed where it lives (`CLAUDE.md`, `PROCESS.md`, the check and its baseline); this
change does not re-home any part of it into the threat model, and inventing a
"publication hygiene" surface there would be a mitigation invented where the change
is removal of exposure.

## The security impact analysis

Per `docs/security-analysis.md` (the per-change structure, §5), authored with the
design — the SIA is part of the design, not a report after it.

### 1. Change description

A publication-hygiene change over the tracked set: two default strings in runtime
configuration (`gateway/settings.py`'s `dial_compose_network` default and the two
matching compose fallbacks), one default string in each of two dev probe scripts,
one input change in a one-shot import utility (hardcoded source path → required
argument), `<>`-placeholder and neutral-name substitutions across evidence,
archive, and background records, one comment-only edit in a CI workflow, an empty
waiver baseline, and three new metadata files. No gateway flow code, no endpoint, no
setting consumed by the request path, no dependency, no image.

### 2. Impact level, with reasons

**Low.** None of the system's runtime sensitive assets (the signing key, the custody
key, live identity tokens, bearer tokens, per-user upstream credentials, toolset MCP
traffic) is involved: no code path that holds or moves them is touched. The asset in
play is the **publication corpus** — the repository's content, destined for public
exposure, whose confidentiality this change strictly *reduces* by removing internal
machine detail. The only runtime-adjacent edits are defaults for operator-supplied
topology values (a compose network name, a container name) that were never
gateway-validated and remain operator-supplied; the exposure they carry is
informational (the old default disclosed the local rig's project name), not
behavioral. Low sets the security review gate's depth: a focused pass whose job
includes falsifying the "hygiene-only" claim — its specific falsification duties are
in the gate plan below.

### 3. Invariant ruling table

One row per never-cut invariant (`ROADMAP.md`), ruled explicitly:

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | Preserved | No flow code, no data path, no credential leg is touched |
| 2 | The upstream PKCE verifier never leaves Core | Preserved | Untouched by every edit in this change |
| 3 | Per-user credential isolation | Preserved | No store, resolution, or identity code is touched |
| 4 | DIAL authorization applies to every toolset call | Preserved | The router config, the gateway's authorization paths, and Core's provider entries are untouched |
| 5 | No credential in logs, argv, or error messages | Preserved | The import script's new refusal names the missing argument, never a value; no new logging is introduced anywhere |
| 6 | No hardcoded credentials in the repository | Preserved, and strengthened | The change's whole purpose is removal: real provider identifiers leave the records, no credential-shaped value is added, and every placeholder introduced is a spelling the machine check can never match |
| 7 | The signing key is treated as IdP-grade secret material | Preserved | Key handling, delivery, and rotation are untouched |

### 4. Threat tables — the touched-surface determination

No attack-surface entry point of the system (`docs/threat-model.md` §7's EP1-EP7) is
touched: the change adds and alters no endpoint, no trust boundary, no credential,
no grant type, no request-path setting. Per the method's proportional enumeration
(§4), surfaces the change does not touch are covered by the invariant table above,
not re-enumerated. Two delta shapes were considered and rejected:

- **The default flip as a misconfiguration vector.** A deployment that relied on the
  old default now fails loudly at the compose network join (network not found) —
  fail-loud, not a silent misjoin; the network value was and remains
  operator-supplied, and the gateway performs no validation of it either way. A
  wrong join would require a second DIAL deployment deliberately named the neutral
  example name on the same host — an operator-controlled condition that existed
  identically under the old default with the real instance's name.
- **The scrub as a records-integrity risk.** Neutralizing quoted values could make a
  record claim something the rig did not do. Bounded by the scheme: substitutions
  are value-for-placeholder of the same shape in place, no record's verdicts,
  numbers, or claims change, and the act is disclosed once in this note. Mis-use
  cases: none — no behavior the system rewards is changed.

### 5. Mitigations (grouped final list)

The change's own edits are its mitigations, each landed where it lives:

- **Neutral example defaults** for the compose network and probe container names —
  implemented in `.env.example`, `docker-compose.yml`, `gateway/settings.py`, and the
  two probe scripts; owned by this repository. Addresses the class "internal
  instance name as committed default".
- **Config-driven input** for the import utility's source path — implemented in
  `scripts/import_background.py`. Addresses the class "personal path in tracked
  code"; retires the first waiver.
- **Placeholder-rewrite of rule-engine samples** —
  `docs/evidence/d0a/review-round-1.md`. Addresses the matching class; retires
  the second waiver.
- **The mechanical instance-name substitution and the tenant/misc scrubs** — the
  file lists above; owned by this repository. Addresses the classes "internal
  instance name", "real issuer/tenant values", "host-local literals", "person names"
  in the publication corpus.
- **The empty waiver baseline** — `scripts/leak-baseline.json`; the machine gate's
  end state, not a control in itself.

### 6. Threat-model delta

None. See the determination above (§"The threat-model and delta-spec determination").

### 7. Open questions

- The `.gitlab-ci.yml` disposition executes at Phase 4 under the owner's 2026-11-17
  ruling; until then the file is live internal CI and untouched by this change. The
  review gates confirm this change's diff contains no edit to it.
- `SECURITY.md`'s advisory-form pointer depends on the target repository's slug
  matching the one the release workflow already publishes; Phase 4 verifies before
  the public flip.
- The keep-rulings above (the `sub` UUIDs, the synthetic jti values, the repository
  container-name constant) are the authoring sweep's judgments; the independent
  hostname/URL sweep pass and the security review gate are invited to overturn them,
  and any overturn lands in this note's appended findings.

## The gate plan

The full ladder per `CLAUDE.md`, with this change's specifics. The orchestrator
runs and records the gates; the implementer's checklist carries self-checks only.

1. **Static tier.** `ruff check .` — green. `ruff format --check` on every
   Python file this change touches (the tree-wide format check stays red on CRLF
   checkouts for the documented pre-existing reason; the touched files themselves
   must be LF-clean — the D0a precedent). `mypy` — its configured scope
   (`gateway`, `tests`) includes the settings default change; green at its standing
   baseline. `bandit -c pyproject.toml -r gateway scripts` — the local scope; no
   new finding class is introduced by renames or an argument. `pip-audit` — no
   dependency is touched, so the verdict is unchanged from the standing green; run
   per the standing invocation regardless. Trivy — no image content changes (the
   compose edit changes defaults, not base images); `wsl -e trivy --skip-db-update`
   when the DB download fails and the cache is recent. `pytest -q` — the suite
   stays green; no test touches the renamed defaults as values, and the leak-check
   tests are rule-engine tests that do not read the baseline's contents.
2. **The publication leak check — this change's own gate.**
   `PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python scripts/check_publication_leaks.py`
   from the repo root, with every new file (`LICENSE`, `SECURITY.md`,
   `CONTRIBUTING.md`, and this note) `git add -N`'d so the check sees them before
   commit (the D0a precedent — the check reads the index). **Expected end state,
   stated exactly: `summary: scanned N tracked files; 0 finding(s): 0 waived, 0
   unwaived` / `verdict: PASS`, exit 0, and no `note: unused waiver` lines.** Zero
   findings, zero waivers — the empty-list baseline is what makes "zero waived"
   the honest number rather than an unenforced one.
3. **The compose-boot gate — in scope.** The change touches `docker-compose.yml`
   and a `gateway/settings.py` default, so the composed stack is in scope. Route to
   green: the local gitignored `.env` carries `DIAL_COMPOSE_NETWORK=<the real
   network name>`; then `wsl -e docker compose up -d --build` brings the gateway
   and router up, the health probe passes for every service, and the fixture is
   probed under the `acceptance` profile per the standing procedure. A boot against
   a bare `.env.example` copy must fail loudly at the network join — that is the
   designed behavior, worth one probe to confirm the fail-loud property survived.
4. **The hostname/URL sweep — a named opus pass over the tracked set.** The machine
   check deliberately does not scan this class (the D0a concession), so the sweep is
   a review pass, not a glance: internal hostnames, the internal instance name in
   every spelling, issuer/tenant values in URL shape, host-local address literals,
   internal namespace/project references, person names, profile paths — over
   `git ls-files`, every hit dispositioned. Its findings and dispositions land in
   this note (appended below). The authoring-side sweep that produced the site lists
   above is its input inventory, not its substitute; it runs independently on the
   implemented diff.
5. **The security review gate (opus, independent, before the review gate).** Depth
   Low per the SIA, with the falsification duties named: (a) confirm the two default
   flips change no trust relationship — the network value was and remains
   operator-supplied, and compose fails loudly on a nonexistent network; (b) confirm
   the scrub is complete — the class-greps return nothing and the diffs remove the
   named values without introducing new machine-shaped material; (c) watch the
   machine check's stated blind spot in this diff specifically — lowercase-hex
   identifier material is the exact shape the scrubbed corpus contained, and the
   one class the check cannot see.
6. **The review gate (opus, independent) on the diff** — correctness and scope:
   every edit matches this record's plan, nothing else moved.

Commit locally by the orchestrator after the gates; push only after the change's
gates pass. Phase 3 (the full-history audit) and Phase 4 (the move) follow their own
rounds and append here.

## The implementation checklist

Each item binary (done / not). A sonnet implementer executes item by item; every
edit is named above with file, line, and replacement.

**Code and configuration:**

1. `.env.example:129` — `DIAL_COMPOSE_NETWORK` value → `dial-instance_default`;
   adjacent comment states the neutral-example role and the local-`.env` route.
2. `docker-compose.yml:146` — fallback → `dial-instance_default`.
3. `docker-compose.yml:352` — fallback → `dial-instance_default` (identical to
   item 2's spelling).
4. `gateway/settings.py:368` — default → `"dial-instance_default"`; comment above
   unchanged.
5. `scripts/probe_routing.py:121` — `DEFAULT_CORE_CONTAINER` →
   `"dial-instance-core-1"`.
6. `scripts/probe_front_door_paths.py:99` — `DEFAULT_CORE_CONTAINER` →
   `"dial-instance-core-1"`; line 100 (`DEFAULT_GATEWAY_CONTAINER`) NOT touched.
7. `scripts/import_background.py` — the source path becomes a required first
   positional argument with an argparse refusal naming it; no default, no path
   fragments; the rest of the script unchanged.

**Live docs:**

8. `docs/gateway-configuration.md:70` — default column → `dial-instance_default`.
9. `docs/pod-contract.md:84` — default value → `dial-instance_default`.
10. `docs/local-environment.md:9` — the sibling folder named via the
    `<local-instance>` placeholder; the local-only/no-remote facts kept.

**The scrubs:**

11. The instance-name substitution over the 20-file list above (mechanical prefix
    substitution, all spellings, quoted output and prose alike); verification: a
    full-text grep over the tracked set for the pre-substitution name — the token
    every file in the list still carries, read it there before editing —
    returns nothing.
12. `docs/evidence/c2/part1-b2c-setup.md` — issuer → `<tenant-issuer>`,
    client id → `<tenant-client-id>`, provider-entry name (both occurrences) →
    `<provider-entry-name>`.
13. `docs/evidence/c2/interactive-probe.md` — tenant hostname → `<tenant-host>`
    and client id → `<tenant-client-id>` in both redirect-trace blocks.
14. `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/evidence/dcr.md:372`
    — the address literal → `<host-address>`.
15. `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/evidence/gates.md:254`
    — the resolver search domain → `<internal-domain>`.
16. `docs/background/decisions/DR-0001-keep-nginx.md:4` — the person's name → "the
    human owner".
17. `.github/workflows/test.yml:172` — the internal-project parenthetical dropped;
    the pip/hatchling reason stands alone. Comment-only.
18. `docs/evidence/d0a/review-round-1.md:63-64` — the sample profile-name segments →
    the `<name>` placeholder spelling, both branches of the F3 sample.

**Baseline and metadata:**

19. `scripts/leak-baseline.json` — `"waivers": []` (empty list; the file and the
    check script stay).
20. `LICENSE` — full Apache-2.0 text; holder line matched to the family's, year
    2026.
21. `SECURITY.md` — GitHub private vulnerability reporting (the owner's 2026-11-17
    ruling), modeled on the family's wording; the no-public-issues warning carried.
22. `CONTRIBUTING.md` — short pointer to the family-wide contributing guide.
23. No `CODE_OF_CONDUCT`, no `NOTICE` — the sibling set is the rule.

**Self-checks (the implementer runs these before handing back):**

24. `PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python scripts/check_publication_leaks.py`
    with items 20-22 `git add -N`'d — zero findings, zero waived, zero unwaived,
    PASS, no unused-waiver notes.
25. `ruff check .` green; `ruff format --check` green on every touched Python file.
26. `pytest -q` green at its standing baseline.
27. `git diff --stat` shows no file outside this record's named sites.

**Do-not guardrails:**

- Do not touch `.gitlab-ci.yml` — content or existence. Live internal CI under the
  owner's 2026-11-17 ruling; its disposition executes at Phase 4.
- Do not touch `pyproject.toml`. The release workflow's sed replaces the
  `^version = ` line; nothing in this change needs the file, and any edit near the
  version line risks that shape. No dependency or tooling change is in scope.
- Do not alter behavior beyond the named renames and the import script's input
  change: no new settings, no `.env` wiring in the probes, no logic edits. The
  settings default change must keep the gateway bootable with the local `.env`
  (which sets the real network name), and a bare-example boot must fail loudly at
  the network join, never silently.
- Comments and docs carry behavior and reason, never provenance: no "per D0b", no
  change-folder paths, no ruling citations in any touched file. The rulings live
  here.
- No `<>` placeholder in any code, compose, or `.env.example` default —
  placeholders are for prose and evidence records only; defaults take the neutral
  names.
- Neutralize, never excise (decision 3): no evidence section is deleted; values are
  replaced in shape, in place.
- The baseline only shrinks: no new waiver entries, for any finding, under any
  circumstance — a new exposure in this change would be a violation of the
  discipline, not a baseline use.
- No real value — hostname, instance name, tenant value, path, person's name — is
  written into any file by this change, including this note's later appends.

## Appended by later rounds

*(Gate results and dispositions land here: the static tier's outputs, the leak
check's closing run, the compose-boot record, the hostname/URL sweep's findings and
dispositions, the security review and review gates' verdicts; then Phase 3's
accepted findings and Phase 4's records — branch mapping, repository slug, the
`.gitlab-ci.yml` disposition's execution, the first CI run. Nothing above this line
is rewritten by those appends.)*

### The hostname/URL sweep — findings and dispositions (appended 2026-11-18)

The named opus pass over the tracked set ran on the implemented diff. Three
findings, each a class this change scrubbed — the classes and file lists are the
design record's above. The PASS dispositions, with their reasoning:

**The public upstream's client id — PASS, kept unscrubbed.** Sites:
`docs/background/poc-dial-mcp-signin.md:164`;
`docs/background/poc-litellm-comparison.md:266` (two literals) and `:390`;
`openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/evidence/group-4.md:169`
and `:185`; the same change's `evidence/finding-empty-upstream-redirect.md:46` and
`:82`; and `evidence/finding-toolset-redirect-uri.md:54` — all inside quoted
authorize URLs. The reasoning: a public OAuth upstream's client id is public by
nature — it is embedded in every authorize URL a user of that upstream visits, and
the quoted URLs are the exact evidence those records exist to carry; it is
mixed-case, outside the lowercase-hex blind-spot class the security review gate
checked; and both review gates examined it and passed it. That resolves the
asymmetry with the scrubbed external-provider client id: the scrubbed literal
identified a private tenant's registration, this one a public upstream's published
client. The disposition records the judged default, not a ban on revisiting — the
owner may still order symmetry-scrubbing at the pause.

**Both flagged IP-literal sites — PASS, kept unscrubbed.**
`docs/evidence/c3/pod-shape-probes.md:123-124` (the bridge-gateway address in the
pod-shape reachability rows) and `docs/background/poc-dial-mcp-signin.md:305` (a
network-gateway address inside a quoted diagnostic). The reasoning: both are the
container runtime's default bridge/network-gateway constants — the same address on
any default installation, naming no host of this deployment — and the
reachability rows are the pod-shape record's load-bearing evidence: the router's
published port reachable at the bridge gateway while the gateway's
container-internal port is not. They are topology constants in quoted output, the
class the design record's keep-rulings already names — unlike the scrubbed
one-off host-local literal, which named a specific host.

### The gate results (appended 2026-11-18)

| Gate | Command | Result |
|---|---|---|
| leak check (closing run) | `PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python scripts/check_publication_leaks.py` | exit 0 — scanned 340 tracked files; 0 finding(s): 0 waived, 0 unwaived; verdict PASS; no unused-waiver notes; the baseline is `waivers: []` |
| ruff lint | `ruff check .` | exit 0 — all checks passed |
| ruff format | `ruff format --check` on every touched Python file | exit 0 — formatted (LF); the tree-wide CRLF failure is the documented autocrlf checkout property (`git ls-files --eol` shows `i/lf`; the HEAD content formats clean) |
| mypy | `mypy` | 3 errors, all pre-existing in untouched test files (`test_leak_check` import-not-found, `test_idp.py:1454`, `test_federation.py:409`) — the standing baseline; none from this change |
| bandit | `bandit -c pyproject.toml -r gateway scripts` | 21 findings (15 Low, 6 Medium), all pre-existing triaged classes (B404/B105/B603/B607/B310) in scripts unrelated to this change; the argparse conversion adds none |
| pip-audit / Trivy | — | not applicable: no dependency and no image change — nothing for these gates to examine (the D0a precedent's wording) |
| unit tests | `pytest -q` | exit 0 — 771 passed, 1 skipped (re-run after the test-constant change) |
| compose-boot | the real local `.env` (`DIAL_COMPOSE_NETWORK` set there) | GREEN — negative control first: fail-loud at the absent external network, exit 1, run by the implementer; positive control: the worktree stack booted from the real `.env`, all three services healthy — gateway `:8091 /healthz` 200, router `:8090 /healthz` ok, acceptance fixture `:9000 POST /mcp` 200 — and the front door answers 200; teardown clean; the displaced stack of the discovery-aliases worktree restored healthy |
| hostname/URL sweep | the named opus pass over the tracked set | GREEN — 3 findings, all scrubbed by this change (the classes and file lists in the design record above); the PASS dispositions — the public upstream's client-id class and both flagged IP-literal sites — recorded in the findings section above |
| security review gate | opus, independent; Low depth per the SIA | GREEN — the three falsification duties each ran and failed to falsify: the default flips move no trust boundary (the membership-trust residual RES-19 intact); the scrub is complete, the inverse corruption check clean; no lowercase-hex/UUID-shaped secret survives or was introduced (the client-secret-mode captures were redacted at capture time). Never-cut invariants preserved; 4 benign notes |
| general review gate | opus, independent, on the diff | GREEN — design conformance one-to-one across the 52 touched files; guardrails held; evidence integrity intact; its should-fix (the public upstream client-id disposition, recorded above) and its notes are folded into this record |

Both review gates green. The change stands ready for the owner's pause; the
orchestrator commits after it.

### The hostname/URL sweep — findings and dispositions

An independent pass over `git ls-files` for the classes the machine check does not
scan (internal hostnames, the instance name in every spelling, issuer/tenant values
in URL shape, host-local address literals, internal namespace/project references,
person names, profile paths). It returned **three must-scrub findings**, all now
landed, plus a set of PASS dispositions and one borderline keep.

**Finding 1 — real-tenant user subject identifiers (GUIDs) in the C2 live-run
records.** The federated identities' subject values appeared as values in the C2
Part 1 evidence: full GUIDs in two token-dump records and prefix-ellipsized
fragments in two others, across two distinct subject spellings (the first user's
access-token `sub` form and the second user's directory-`sub` form). Scrubbed to
`<tenant-user-sub>` and `<tenant-user-sub-dir>` respectively, keeping each dump's
surrounding lines and the records' two-identity point coherent. Sites:
`docs/evidence/c2/part1-refresh-leg-live.md` and `part1-run-client-secret-mode.md`
(the full-value dumps); `part1-harness-acceptance.md` and `part1-revocation-live.md`
(the ellipsized fragments); and `docs/evidence/c2/availability-read-diagnosis.md`
(one further ellipsized fragment of the second form, same class, found by this
pass and scrubbed with it). **This overturns the earlier blanket keep-ruling on
`sub` values** — that ruling was correct only for the local development realm's own
fixtures (see the scoped keep-ruling above); real-tenant subject values are
machine-identity detail and are scrubbed.

**Finding 2 — the provider's app/role-name family surviving as values.** The
external provider's product name appeared as a value in two registers: as the
tenant's role name inside `roles` claim dumps and prose across the C2 records, and
as the app/deployment name in the C2 federation change's live-run planning material.
Scrubbed to `<tenant-role>` and `<tenant-app>` (the `<tenant-*>` register). Sites:
the C2 evidence records (`authoring-round-6.md`, `availability-read-diagnosis.md`,
`part1-harness-acceptance.md`, `part1-refresh-leg-live.md`,
`part1-run-client-secret-mode.md`, `part1-run-secret-pkce-mode.md`,
`task-8-implementation.md`); the archived C2 federation change
(`2026-11-06-generalized-idp-federation/evidence/authoring-round-4.md` and its
`tasks.md` row 7.1); the archived change's review record where the name appeared in
prose (not as a grep-pattern); and `tests/test_federation.py`'s non-admin role
fixture constant, replaced with a synthetic fixture-shaped value (`partner-reader`)
so the regression test still exercises the same non-admin path. **Kept** (pattern
vocabulary, not values): the name as one alternative inside the quoted `grep -riE`
pattern strings in the C2 task-2/4/5/6 implementation records and the archived
change's review record and task 2.7 — those quote the sweep pattern itself
(case-insensitively, alongside the provider-family terms), and scrubbing one
alternative would break the record of what was grepped.

**Finding 3 — an internal sibling repo reference and production-infrastructure
facts.** `docs/background/poc-dial-mcp-signin.md` named an internal sibling
Keycloak realm-configuration repository (with its realm-file path) and described
production's keycloak `trusted-hosts` configuration as listing specific
infrastructure (VPN gateways and a managed-kubernetes cluster IP). Neutralized to
a `<internal-realm-config>` placeholder and class descriptions ("its trusted
network egress points and its cluster ingress address"), keeping the paragraph's
technical point — production uses the same trusted-hosts shape with
`client-uris-must-match: "false"`.

**PASS dispositions (judged, not missed).** The host-local address literals flagged
during implementation were dispositioned: `docs/evidence/c3/pod-shape-probes.md`
carries the default-bridge gateway address of the local Docker network (a
container-internal topology fact with no host or identity correlation) — PASS;
`tests/test_cimd.py`'s blocked-address literal is CIMD taxonomy test input (the
SSRF-blocked range the CIMD resolver must refuse), not a host — PASS. Two further
Docker-bridge literals in the records were cleared on the same reasoning.

**Borderline keep.** The local instance's demo-app name (`skills-demo`) survives as
a probe default and an audit-quote value: a self-descriptive fixture name for the
local composed stack, carrying no person, org, or tenant marker and no correlation
surface. Kept; the owner may neutralize it at the pause if the fixture name is
judged to leak intent.

*(Gate results — the static tier, the leak check's closing run, the compose-boot
record, the security review and review gates' verdicts — and the later phases'
records land below as their rounds complete.)*

### Phase 3 — the full-history audit (2026-11-18)

The discipline is prospective-only — from D0a on — so a clean tip proves nothing
about history: an independent opus subagent walked the full history end to end
before anything publishes, per the plan's Phase 3. Every finding below is
dispositioned; nothing publishes past an open finding.

**Scope.** 175 commits; 1032 unique blobs (~30.6 MB); all 22 refs. Method: the full
unique-blob corpus swept by 12 regex classes; all 175 commit messages read;
targeted reads of every pre-scrub file this record names; and a filename sweep for
`.env`-shaped, PEM, and binary blobs. Merge-commit content is subsumed by the
blob-level pass — a merge adds no blob the corpus pass has not already seen.

**Verdict.** **History findings: 12. Zero secrets.** No credential, token, key, JWT
literal, or tracked-`.env` episode exists anywhere in history — the client-secret
captures were redacted at capture time even pre-scrub. The lowercase-hex blind spot
(the local client-secret shape the machine check self-reports) was specifically
covered: the only lowercase-hex UUIDs in all of history are tenant-identity values,
local-realm fixture GUIDs, and one all-zeros fixture. No history rewrite is forced
by the blocking class.

**The machine-detail findings (file/class only, quantified; no values).**

- The internal instance-name family: ~162 blobs, 33 paths, 17 commits — the PoC
  era through the D0b scrub.
- The real-tenant identity family: ~19 blobs across ~10 paths — the tenant
  hostname, its GUIDs, the client id, the policy/journey name, the provider-entry
  and role/app names, and two user-subject GUIDs (the classes the tip's sweep found
  and scrubbed; history carries their pre-scrub originals).
- The internal GitLab hostname: 1 blob — the old README clone URL.
- The `.gitlab-ci.yml` namespace references: every version of the file, the tip
  included (the Phase-4 retirement disposition's subject).
- Internal sibling-project references — the class the tip's sweep neutralized.
- The owner's profile path: 5 blobs, plus the one in-content occurrence of the
  owner's name.
- One host-local address literal; the corporate domain inside a resolv.conf quote;
  and class-level production-infrastructure facts (the trusted-egress and
  cluster-ingress shape the tip's sweep reduced to class descriptions).
- Minor: two stale side refs outside master (never published — push mechanics, not
  content); the D0a brief's synthetic truncated secret-shape illustration
  (illustrative by construction); teammate names in commit authorship only (the
  settled keep — the plan's decision 2).

**The disposition — the owner's ruling (2026-11-18): publication without history,
a fresh root.** The published GitHub repository carries a two-commit
family-standard skeleton (the team's project-configuration base) on its
`development` branch, and the corpus's birth is a single commit on that
skeleton, opened as a pull request. The birth commit's tree is the master tip
composed with that skeleton per the composition's conflict policy — the family
side wins `.github/`, `Makefile`, and `.pre-commit-config.yaml` outright;
`pyproject.toml`, `Dockerfile`, `trivy.yaml`, `README.md`, `LICENSE`,
`SECURITY.md`, and `CONTRIBUTING.md` are reconciled — with `.gitlab-ci.yml`
retired per its Phase-4 disposition; identity is verified by diff against the
master tip. The complete
175-commit history remains the private record on the internal GitLab remote,
archived or redirected at the move. The accepted residuals — the machine-detail
findings above, all of them — flow to D3's ledger per the standing-aside clause.
The rationale, recorded: the tip's own dispositions already rule these classes
unpublishable, so accepting the history as-is was incoherent; between the two
rewrite shapes, the owner chose the fresh root over a value-replacing history
rewrite — the provenance stays private with the history, and the corpus publishes.

**Keep-rulings re-checked against history.** The audit re-checked every tip keep
against the full corpus — all upheld: the public upstream client ids, the
local-realm fixtures, the synthetic RFC 9700 values, the taxonomy IP literals, the
repository's own container-name constant, the fixture app names, and the public
`epam` identifiers. The grep-pattern-vocabulary sites (the sweep-pattern quotes)
remain the only internal-marker occurrences at the tip.
