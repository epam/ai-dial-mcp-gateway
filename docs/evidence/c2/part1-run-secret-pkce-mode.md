# Part 1, mode 2 — the secret + PKCE live B2C run: PASS

Date: 2026-11-06. Task 7.1 Part 1, the challenge-on position
(`IDP_PKCE_ENABLED=true` — the default; the D5 ruling's "secret + PKCE",
the RFC 9700 shape for a confidential client). Same probe, same tenant,
same toolset as the mode-1 record (`part1-run-client-secret-mode.md`).

## What this run added to mode 1's proof

- The authorize redirect carried `code_challenge` + `code_challenge_method=S256`
  (visible in the pasted run's URL) — the challenge rides ON TOP of the
  confidential client's authentication; the exchange presented both the
  verifier and the secret.
- The provider accepted both bindings: the token answered 200 and the
  mint carried the same verified shape as mode 1 — the gateway's issuer,
  the toolset audience, `roles: ["<tenant-role>"]`, the session
  refresh token present.
- The live tool call repeated: 200, 77 tools through the front door.

## Task 7.1 Part 1 state after this run

Both D5 positions verified live against the tested tenant:

| mode | challenge | client auth | verdict |
|---|---|---|---|
| challenge off | none | secret | PASS (mode-1 record) |
| challenge on (default) | S256 | secret | PASS (this record) |

## Still open in task 7.1

- The refresh leg's live verification (fresh claims within the access
  TTL; session revocation ending the refresh capability).
- Part 2: the real deployment + the real app.
