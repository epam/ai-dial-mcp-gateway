# Part 1 — the refresh leg's live verification: PASS

Date: 2026-11-06. Task 7.1, the refresh-leg row, run against the tested
tenant (challenge-on position; the stored user credential made the flow
short-circuit — the sign-in half is the earlier records').

## The verdict (the probe's steps 7-8, output tail)

    === step 7: the refresh leg (/dial/token, grant_type=refresh_token) ===
      status    200
      access    was <redacted sha256=f4213dd6d3be>
      access    now <redacted sha256=b322580bb5e2>
        iss      "http://localhost:8090"
        sub      "<tenant-user-sub>"
        roles    ["<tenant-role>"]
      refresh   present
      rotation  the refresh token rotated (a replacement was issued)
    === step 8: a live tool call through the front door ===
      status    200
      tools     77

## What this verified live

1. **The refresh grant against the tested tenant** — the gateway's
   refresh grant used the stored provider session refresh token and
   minted a NEW access token (fingerprints differ).
2. **C1's fresh-claims mechanism on the generalized leg** — the claims
   were RE-READ through the identity leg (the provider answered the
   refresh grant and the roles arrived again): a provider-side role
   revocation now propagates within the access TTL — the P2 mechanism's
   live proof.
3. **The refresh-token rotation policy running live** (a replacement
   issued per the gateway's configured rotation).
4. **The refreshed credential's own live tool call** (200, 77 tools).

## Addendum (2026-11-06): the revocation check's honest shape

A second full-green run re-verified rotation and the claims re-read on a
fresh session — and clarified why the probe CANNOT run the revocation
check: the probe's own sign-in creates a fresh provider session, whose
refresh token is what the refresh grant then uses; revoking the *older*
session is moot by step 7. The check's honest shape is harness-first:
hold a live harness session (use a tool), revoke the user's sessions in
the provider's portal, then exercise the next silent refresh after the
access TTL — the expected outcome is the sign-in-again branch (the
401-challenge, not an error loop), and the stored credential's dead
refresh token makes the consent leg re-run too.

## Task 7.1 state

- [x] Part 1: both D5 positions + the consent leg + the refresh leg —
      all live-verified.
- [ ] The revocation check: revoke the user's sessions at the provider
      (portal "Revoke sessions") → the next refresh takes the
      sign-in-again branch (no loop) — the row's last live sub-item.
- [ ] Part 2: the scoping decision (deploy-at-production / tunnel /
      defer to C3).
