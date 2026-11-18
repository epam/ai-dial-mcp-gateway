# The main-spec repair — verification record (tasks 1.1 / 1.2)

Date: 2026-11-07. Executor: the C2.5 apply session (group 1, verify-on-rebase).

## What was verified and how

The repair itself was performed by the C2 session (commit `f19dcfb` on
`fix/main-spec-c2-sync-repair`, reconstructed from the pre-sync parent `4519c93^` and
the archived C2 delta, applied per-block by name) and merged to master by the owner's
explicit authorization. This change's group 1 does not re-perform it; it verifies the
repaired spec is the base this branch builds on.

- **The rebase (task 1.1):** branch `worktree-c2p5-as-security-hardening` rebased onto
  master at `f19dcfb` — clean, no conflicts (the branch never touched the spec file);
  the working tree's `openspec/specs/mcp-signin/spec.md` is the repaired content.
- **The header-inventory assertion (task 1.2):** run over the working-tree spec:
  - line-start `### Requirement:` headers: **31** (27 pre-sync + the C2 delta's 4 ADDED)
  - mid-line `### Requirement:` occurrences: **0** (was 6)
  - duplicated requirement names: **none** (was 2)
  - `#### Scenario:` headers: **160**
  - the two requirements the sync lost outright are present at line start:
    "End-to-end acceptance on a real harness gates completion";
    "App MCP resources are served through the apps front-door path"
- **`openspec validate as-security-hardening`:** **valid** — the two ERRORs the
  planning phase carried (the authreq and lifecycle MODIFIED blocks' parse artifacts of
  the corrupted on-disk spec, per
  `openspec/changes/as-security-hardening/evidence/review-1-findings-and-dispositions.md`)
  are **cleared** by the rebase, exactly as predicted.

## The fallback

Not exercised: the reconstruction recipe recorded in the change's tasks group 1 existed
as the fallback should the repair branch or its merge have stalled. The merge landed
before apply began.
