# Review round 2 — findings and resolutions

Reviewer: independent opus subagent, fresh pass (re-review), briefed from this folder
plus round 1's record. Verdict: **pass** (0 BLOCKER, 0 MAJOR, 2 new MINOR).

## Round-1 resolutions — all verified by the reviewer

| Finding | Verdict |
|---|---|
| MAJOR-1 (spike preconditions) | RESOLVED — group 1 establishes both preconditions from committed helpers (`scripts/spike_register_toolset.py`, `scripts/spike_establish_credential.py`); `.mcp-poc/` dependency gone; positive control 1.7 ordered after 1.5/1.6; falsification stop governs |
| MINOR-1 (reserved names) | RESOLVED — six names, justification factually true against the §10.4 routing sketch; design D6 and spec agree |
| MINOR-2 (TTL bound) | RESOLVED — `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` required setting, startup refusal with unit test, spec scenario, D3, release notes |
| MINOR-3 (6.4) | RESOLVED — alignment not "fix"; both routes verified live in source; 403 semantics verified and checked in 6.3 |
| MINOR-4 (scope) | RESOLVED — D10: client `scope` accepted and dropped, never relayed; Keycloak leg requests exactly the client's defaults; normative in spec with scenario; safe against the `openid` trap |
| MINOR-5 (CIMD UA) | RESOLVED — explicit non-default User-Agent in D5's control set and task 3.4 with a respx test |
| MINOR-6 (group 2 docs) | RESOLVED — task 2.5 (README development section; `.env.example` folded in) |

No regressions: spec format, tasks mechanics, cross-artifact consistency, renumbering
cross-references, never-cut rulings — all intact.

## New findings this round

### MINOR-A — Duplicated paragraph in design.md D3 (edit artifact of the MINOR-2 fix)
- **Finding:** Lines 138–141 and 142–144 repeat the same three lines verbatim
  ("What the gateway adds over vanilla is unbounded re-minting…").
- **Required fix:** delete the duplicate block (keep one copy).
- **Resolution:** RESOLVED — the second verbatim copy of the "What the gateway adds
  over vanilla is *unbounded re-minting within `refreshTtl`*…" block in D3 reason 3
  is deleted; exactly one copy remains.

### MINOR-B — Spike helpers' credential sourcing unspecified (blocking-defect trap)
- **Finding:** The `PUT /v1/toolsets/platform/notion` call in task 1.5 is admin-gated
  in Core (verified: routes to `ConfigResourceController`, 403 unless authorized), so
  the committed helper needs an admin credential — and neither 1.5 nor D1 says where
  it comes from. Task 1.6's flow needs the test user's login (browser-driven or not —
  unstated); 1.5 lacks even the "no credential material printed or committed" guard
  that 1.6 has. This is the exact trap the brief flags (the sibling's scratch script
  hardcodes `admin`/`admin`); the repo rule makes a hardcoded password in a committed
  script a blocking defect.
- **Required fix:** a clause in 1.5 (and D1, plus 1.6 if its flow is not
  browser-driven) stating that any machine credential the helpers use comes from
  `.env` (gitignored) with `.env.example` placeholders — mirroring task 6.2's explicit
  pattern — never hardcoded.
- **Resolution:** RESOLVED — the sourcing rule now appears in all three places.
  D1's preconditions paragraph states the registration call is admin-gated in Core
  (403 unless authorized; locally the test user's `admin` client role reaches the
  token's `roles` through the chat client's client-roles mapper — verified against
  the realm import and the sibling's working `.mcp-poc/core_jwt_check.py` — so one
  credential pair serves both calls) and that any machine credential the committed
  helpers use comes from `.env` (gitignored) with `.env.example` placeholders
  (`TEST_USER_NAME`/`TEST_USER_PASSWORD`, already present), never hardcoded, the
  same `.env` pattern 6.2 follows, with no credential material printed or committed.
  Task 1.5 carries the same clause (admin gate, `.env` sourcing mirroring 6.2) plus
  the "no credential material is printed or committed" guard 1.6 already had; task
  1.6 states that where the helper drives the test user's login itself rather than
  the browser, the credential comes from `.env` with the same placeholders. No
  `.env.example` additions were needed: both placeholder pairs are already present
  (`KEYCLOAK_ADMIN_USER`/`KEYCLOAK_ADMIN_PASSWORD` serve 6.2's Keycloak Admin API).
  The delta spec was untouched (it does not cover the spike helpers).
