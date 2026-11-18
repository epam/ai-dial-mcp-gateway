# Part 1 — the revocation check: PASS

Date: 2026-11-06. Task 7.1's last live sub-item: session revocation
propagating as a clean re-sign-in, never a loop.

## The owner's sequence

1. Use a notion tool (a live harness session) — OK.
2. The B2C portal: **Revoke sessions** on the user
   (the directory id behind the federated identity) — the stored
   credential's refresh token died with the session.
3. Use the tool again: **re-authentication demanded** — the
   sign-in-again branch (the 401-challenge signal), not an error loop.
4. The re-authentication ran under a **different B2C user**: the flow
   asked for the **Notion consent again** (no stored credential for
   that identity — per-user credential isolation, live) → the call
   succeeded.

## What this verified

- The revocation propagates: a provider-side session revocation ends
  the stored credential's refresh capability and surfaces to the
  harness as the sign-in-again branch — the C1-era designed shape.
- Per-user credential isolation live with two distinct federated
  identities: each identity's consent and credential are its own; the
  second user's consent ran from scratch and their call succeeded.

## The audit trail's verification (added 2026-11-06)

The gateway's audit carries every beat:

1. Pre-revocation: `token_refreshed` events for subject `<tenant-user-sub>` —
   the probe's step 7 and the harness's silent refreshes (the
   silent-repeat behavior on the record).
2. The revocation's effect: the next refresh died with
   **`flow_refused: claims_read_failed`** — the sign-in-again branch's
   own vocabulary, loud, flow consumed, no loop.
3. The re-authentication: fresh DCR registrations, two abandoned
   attempts, then the second user's flow: `upstream_callback` →
   `signin_result: accepted` → `code_issued` → `token_issued`, all
   under the NEW identity.

One B2C quirk recorded: the two identities' subjects surface in
different spellings (`<tenant-user-sub>` — the first user's access-token
subject form; `<tenant-user-sub-dir>` — the second user's directory-sub form).
Both are stable per user and both carry through the pinning and minting
untouched; the gateway treats either as the claims' subject verbatim.

## Task 7.1 Part 1: COMPLETE

Both D5 positions, the consent leg, the refresh leg + rotation, the
revocation branch, the isolation behavior — all live-verified against
the tested tenant; both real harnesses (CIMD + DCR) passed. The row's
remaining item is Part 2's scoping decision only.
