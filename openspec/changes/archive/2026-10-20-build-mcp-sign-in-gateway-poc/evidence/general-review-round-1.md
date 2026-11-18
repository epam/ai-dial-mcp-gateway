# General review gate — round 1 (diff 16e655a..HEAD)

Reviewer: independent opus subagent (gate 5, PROCESS step 8), full conformance trace
of all 17 requirements to code, correctness pass on the least-reviewed changes (the
F1 offload, limiter placements, caps, refusal audits — verified sound, independently
re-run: 363 tests, gates green, live spot checks), PoC C readiness (nothing material
missing).

## Findings

- **F-1 MAJOR (checklist integrity):** tasks.md group 4's tasks 4.1–4.7 and 4.10 are
  landed and evidenced (commits ecfc15d, b0f624b; evidence/group-4.md;
  security-review-fixes.md) but unticked — the checklist the owner's PoC C run reads
  reports group 4 incomplete. Fix: tick with the evidence trails.
- **F-2 MINOR (overlaps security S2):** `/dial/token` + `/dial/revoke` read uncapped
  bodies; `routes.py`'s docstring ("the one unauthenticated endpoint that accepts a
  body") is false; the DCR per-record caps are jointly unreachable (16×2048 ≈ 33 KB >
  the 8192-byte body cap). Fix: the capped-read shape on the form endpoints; correct
  the docstring; reconcile the maxima.
- **F-3 MINOR:** `/dial/revoke` returns `{"revoked": true|false}` — an oracle — while
  its docstring, the configuration doc, and the tests claim RFC 7009 uniformity. Fix:
  empty 200 per RFC 7009 (or correct all three texts; prefer the RFC).
- **F-4 MINOR (RFC conformance):** (a) `/dial/revoke` without `token` → 200
  `{"revoked": false}`; RFC 7009 §2.1 requires `token` (`invalid_request`) + an audit
  record; (b) the refresh grant ignores a presented `client_id` (RFC 6749 §6: verify
  it) — refuse mismatched, or document the deviation.
- **F-5 MINOR (stale status prose):** README.md's status paragraph ("the gateway
  skeleton is being built") and docs/HANDOFF.md ("implementation not started") are
  flatly false now — HANDOFF is the routed entry point for the next fresh reader.
  Fix: update both to the actual state (groups 1–8 landed; PoC C pending).
- Note: a dead `# noqa: B105` suppression at routes.py:154–156 — cosmetic.

## Dispositions

One consolidated fix pass after the security S1/S2 spec micro-pass lands: F-1 ticks +
F-5 status prose + F-3/F-4 endpoint shapes + F-2 (shared with S2) + S1–S4 (the
security round's own record). The reviewer's own assessment: with F-1 (and F-2)
corrected, the change passes without a further full review round — the remainder is
documentation-level, checkable with the lightweight gates.
