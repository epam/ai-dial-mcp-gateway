# Part 1 — the harness-level acceptance: PASS on both harnesses

Date: 2026-11-06. Task 7.1 Part 1, the row's original intent: real
harnesses completing the flow against the tested external tenant.

## What ran

The owner drove **two real harnesses** end to end against the gateway
fronting the B2C-backed toolset:

- **Claude Code** — the CIMD client: the gateway fetched its
  client-metadata document, the client-facing PKCE ran, the browser
  walked the B2C sign-in and the Notion consent, and the tools answered.
- **Cursor** — the DCR client: it registered itself at the gateway's
  DCR endpoint and completed the same chain.

Both harnesses' flows authenticated live tool calls through the front
door as the federated identity (`roles=["<tenant-role>"]`).

## What this adds to the probe-run records

The probe runs (`part1-run-client-secret-mode.md`,
`part1-run-secret-pkce-mode.md`) proved both D5 positions against the
live tenant with the chain instrumented step by step. The harness runs
add the client-facing surface in its real shape: CIMD resolution, DCR
registration, and each harness's own loopback/PKCE handling — the two
client ecosystems the gateway exists to serve — completing against the
B2C-backed deployment with zero harness-side changes.

## The audit trail's verification (added 2026-11-06, after the runs)

The gateway's audit log independently verifies the runs, and adds three
facts the runs' reports alone could not carry:

1. **The full consent leg ran live** — Cursor's first flow: `upstream_callback`
   → `signin_result: accepted` (the Notion credential stored at the user
   level) → `code_issued`.
2. **The short-circuit verified live, across harnesses** — Cursor's second
   run and Claude Code's flow show `code_issued`/`token_issued` with no
   upstream callback: the stored USER-level credential (one identity,
   `subject <tenant-user-sub>` on every event) served both harnesses —
   per-user credential isolation holding across DCR and CIMD clients.
3. **Claude Code resolved by CIMD** — its client id is the
   client-metadata-document URL, as designed.
4. **The fail-closed behavior under a real outage** — two DCR flows died
   on "the identity provider's token endpoint could not be reached
   (ConnectError)" (the WSL/VPN egress flake); the retries succeeded; no
   flow half-completed.
5. One `flow_refused: invalid_grant` for the CIMD client — a stale or
   retried authorize, consumed cleanly.

## Task 7.1 state

- [x] Part 1: the harness-level acceptance — PASS on both harnesses,
      both D5 positions verified by the probe records.
- [ ] The refresh leg + session revocation live (the probe's steps 7-8
      + a portal session deletion) — the row's remaining sub-item.
- [ ] Part 2: the real deployment + the real app — scoping decided
      separately (the remote deployment cannot fetch a local gateway's
      JWKS; options recorded: deploy the gateway at the production
      shape / tunnel / defer to C3).
