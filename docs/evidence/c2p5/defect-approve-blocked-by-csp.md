# Defect and fix — the approve click was blocked by the decision page's `form-action 'self'`

Date: 2026-11-08. The owner's real-harness run (Cursor / DCR) surfaced a **BLOCKING**
defect: after a deny, a fresh flow's approve never completed — the decision page came
back, and a second click landed on the expired page, so the user could never approve.
This record states the repro, the root cause, the fix, and the re-test.

## The owner's repro (Cursor / DCR, toolset)

1. First run: the decision page rendered → **Deny** → cancelled cleanly (correct).
2. Re-run: the decision page rendered again (correct — the deny wrote no registry entry).
3. **Approve**: the page came **back** (consent requested again) — the harness never got
   its code.
4. **Approve** again: the **expired-flow** page ("the sign-in session has expired or the
   sign-in was started again") — because the first approve had already spent the flow's
   decision. Net effect: after a deny, the user is blocked.

The owner also read the browser's dev tools: "first approve gives the 302 with the
following target, but browser does not go there. it re-renders the consent page again" —
the approve's cross-origin `302` was **observed at the wire but not followed by the
browser**. That was the decisive clue.

## Reproduction

- **Server-side reproduction fails by construction.** The bug is browser-only: a Python
  client follows a 302 regardless of any page policy, so every headless shape (app and
  toolset; deny → fresh approve; approve-twice; repeat) passed and the approve "minted"
  correctly. The scratch driver `security-runs/checkpoint_drive.py` and the fixed
  `scripts/probe_end_to_end.py` both complete the flow headlessly — which is exactly why
  the bug escaped the automated rows.
- **Reproduced in a real browser against the real gateway.** Headless Chrome (CDP
  `Target`/`Runtime`) was driven through the actual flow — authorize → Keycloak login →
  gateway idp callback → decision page → click **Approve** — against the running stack:
  after the click the browser was **still on the decision page**
  (`location.href` unchanged, the consent `<form>` still present).
- **Controlled browser experiment (isolated root cause).** A two-origin test page: origin
  A serves a form whose POST answers `302` to origin B, under the gateway's exact CSP.
  - Under `Content-Security-Policy: … form-action 'self'` → the redirect is **blocked**
    (origin B never sees the request; the browser stays on A).
  - With `form-action` removed → the redirect is **followed** (B records the hit).
  - With `form-action 'self' http://127.0.0.1:8799` (the redirect's origin added) → the
    redirect is followed, i.e. the blocking directive is `form-action`.
  - Answering the POST with a **200 page that navigates by meta refresh** (no 302), under
    the **full** family including `form-action 'self'` → the navigation is followed. This
    is the fix shape.

## Root cause (file:line)

`gateway/federation.py:426` — `POST /dial/consent`, the approve branch. On a short-circuit
path the approve returned `_finish(runtime, record)` (a **302 RedirectResponse** to the
harness's registered `redirect_uri`). That `redirect_uri` is a **different origin** — a
loopback port for a CLI harness, or `https://www.cursor.com/...` for Cursor — and the
response follows the decision page's **form submission**.

The decision page (`gateway/flow.py:_DECISION_PAGE`) is served through `html_page` with
the web-hardening family, whose CSP carries **`form-action 'self'`**
(`gateway/pages.py:page_headers`, stated family-wide per this change's design D3 and the
threat model's M8). Per the CSP spec and browser behavior, **a form submission's redirects
are governed by the form's `form-action`**: a redirect off the gateway's origin is
refused. So the browser received the 302 and refused to follow it, leaving the user on the
decision page — the "consent requested again" symptom. The second click then hit the
already-cleared `awaiting_attribution` flag and landed on the expired page.

The route's own docstring already stated the correct contract — "**Its responses are
pages, never redirects**" (`gateway/federation.py:446`) — but the short-circuit approve
branch violated it. The consent-branch approve was never affected: it returns the display
interstitial, a **page** (meta refresh), which `form-action` does not govern.

## The fix

`gateway/federation.py` + `gateway/flow.py`:

- The approve's deferred **mint** is delivered as a **navigating page**, not a redirect:
  `gateway/flow.py:mint_navigation_page` renders the same meta-refresh + anchor delivery
  the display interstitial already uses (a navigation, which `form-action` does not
  govern). The consent branch's approve was already a page and is unchanged.
- `_finish` was split: `_mint(runtime, record)` returns the destination URL (or the
  issuance-failure page); `_finish` redirects (the **callback** paths' delivery — those
  arrive by a redirect chain, not a form, so a redirect is correct there);
  `_approve` renders `mint_navigation_page(destination)` (the **consent route's**
  delivery).
- The success page carries the same web-hardening family (through `html_page`), so its
  meta-refresh target is escaped and the family cannot be bypassed.

The **deny** path, the **single-use** flag, the registry write, and the audit vocabulary
are untouched.

## Re-test

- **Real browser, real gateway, post-fix** (headless Chrome through the actual flow, with a
  loopback listener on the client's redirect URI): the browser leaves the decision page and
  **lands on the callback with the code** —
  `STILL_ON_DECISION: false`, `LANDED_ON_CALLBACK: true`, `CODE_DELIVERED: true`. Pre-fix
  the same driver showed `STILL_ON_DECISION: true`. **The owner's blocked state is resolved**
  by the fix (a gateway restart/redeploy, then Cursor's flow succeeds).
- **Regression test added** — `tests/test_federation.py::test_an_approve_after_a_deny_mints_the_fresh_flow`:
  deny flow A, then run flow B for the same (subject, client) and approve it; asserts B's
  approve mints (a navigating page carrying a real code), does not re-ask, does not expire,
  writes the registry, and the audit trail carries exactly one `attribution_required` per
  flow plus `attribution_refused` / `attribution_approved` / `code_issued`.
- **Updated tests** — five tests encoded the old redirect delivery (`HTTPStatus.FOUND` +
  `location` header); they now assert the navigating page (`mint_redirect(...)` helper reads
  the meta-refresh target as a browser would). This is the contract correction, not a
  weakening: the route's spec'd delivery is "pages, never redirects".
- **Probe updated** — `scripts/probe_end_to_end.py:complete_checkpoint` now recognizes the
  mint's navigating page (and a `&amp;`-encoded refresh target), so the shipped probe
  passes again: approve → mint page → callback (`code`, `iss`, `state` round-trip) →
  `/dial/token` → live tool call.
- **Full suite** — see the run below (green at branch HEAD `2d72c0f`).

## Evidence files refreshed (this fix)

`live-probe-end-to-end.txt` (approve), `-deny.txt`, `-repeat.txt`,
`-toolset-boundary.txt` — all re-captured under the fixed gateway, redaction discipline
held (no credential; the subject UUID is abbreviated).

## Concurrency note

While this fix was developed, a separate session committed `c180658` (this group's probe
fix) and `2d72c0f` (group 8 gates). Commit `2d72c0f` introduced an unused import
(`NONCE_BYTES`) in `tests/test_custody.py` which `ruff check` flags (`F401`) — **not this
fix's file**; flagged here for the coordinator. This defect fix is left uncommitted in the
working tree.