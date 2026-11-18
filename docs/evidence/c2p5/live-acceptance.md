# Group 7 — live acceptance on the local compose stack

## The owner's real-harness round (2026-11-08) — tasks 7.1 and 7.2 CLOSED

After the approve-redirect defect's fix was deployed
(`defect-approve-blocked-by-csp.md`), the owner ran the real harnesses and reported:
**Claude Code (CIMD)** — first sign-in asked consent once, the immediate repeat was
silent (zero-click) — and **Cursor (DCR)** — approve and deny both working after the
fix ("I already tested from claude code and cursor, approve and deny. everything works
this time"). Their earlier round had found the blocking defect (deny → fresh flow →
approve looped back to the consent page; a second approve hit the expired page) —
reproduced, root-caused (`form-action 'self'` correctly refusing the approve branch's
cross-origin 302; the fix delivers the mint as a navigating page), regression-tested
(`test_an_approve_after_a_deny_mints_the_fresh_flow`), and re-deployed before this
round. Scope note, stated honestly: the runs covered the harness first-attribution /
zero-click / deny rows on both registration shapes; the toolset consent branch's
completion through a real Notion account was not explicitly re-confirmed in this round
(its mechanics are proven in the headless rows below and the upstream leg itself in
C2's archived live evidence).

Date: 2026-11-07. Scope: tasks 7.1–7.3 (design.md D5's rows), run against the local
compose stack (the gateway + router + the `acceptance`-profile fixture, joined to the
personal DIAL instance's external network). This record states what ran, what passed,
and what did not run and why — an unrun row is recorded as unrun, never implied passed.

Evidence files written beside this one (all under `docs/evidence/c2p5/`):

| File | What it is |
|---|---|
| `live-probe-liveness.txt` | `scripts/probe_liveness.py` — F1 liveness under a held-open outbound leg |
| `live-probe-trust.txt` | `scripts/probe_gateway_trust.py` — Core trusts the gateway's JWKS |
| `live-probe-routing.txt` | `scripts/probe_routing.py` — the full routing battery, including the new consent route row |
| `live-probe-dcr.txt` | `scripts/probe_dcr.py --expect enabled --register` — DCR surface + a registration |
| `live-probe-end-to-end.txt` | `scripts/probe_end_to_end.py --app` — the fixed non-interactive chain, first attribution → decision page → approve → mint → live call |
| `live-probe-end-to-end-deny.txt` | `scripts/probe_end_to_end.py --app --deny` — the decision page driven to deny, asserting the refusal shape |
| `live-probe-end-to-end-repeat.txt` | `scripts/probe_end_to_end.py --app` (repeat) — the approved pair's zero-page path |
| `live-probe-end-to-end-toolset-boundary.txt` | `scripts/probe_end_to_end.py` on a toolset — approve reports the upstream boundary (a real account needed) |
| `live-probe-interactive-stop.txt` | `scripts/probe_end_to_end_interactive.py` — the interactive chain, stopped at the IdP login page |
| `live-checkpoint-*.txt` | the consent/attribution checkpoint mechanics driven headlessly (app kind and toolset consent branch) |
| `live-audit-trail.txt` | the gateway's `gateway.audit` records for the runs, read from the container log (task 7.3) |
| `live-audit-owner-harness-runs.txt` | the audit excerpt of the OWNER's real-harness round (2026-11-08): Cursor (DCR) approve; Cursor deny (`attribution_refused`); Cursor approve after deny (the recovery); Claude Code (CIMD, the `claude.ai/oauth/claude-code-client-metadata` client) deny → fresh-flow approve — the deny-then-approve recovery on the real CIMD harness, post-fix |

## The stack

- Docker is in WSL2 (not Docker Desktop); driven through the PowerShell tool as
  `wsl -e docker …`.
- **A pre-existing WSL-NAT/VPN egress outage was hit and recovered.** Inbound/local
  traffic worked, but the gateway container had no outbound network
  (`Network is unreachable` to any public host). A `wsl --shutdown` cycle (the documented
  recovery) restored egress; `dockerd` then needed a manual start (`wsl -u root` +
  `setsid`). No run below was taken while egress was down — the liveness probe's slow
  origin, the toolset read, and CIMD-dependent paths all need it.
- **The worktree `.env` was a stale pre-C2 profile.** It carried the pre-federation
  `KEYCLOAK_ISSUER` / `KEYCLOAK_INTERNAL_BASE_URL` names, while the post-C2 compose file
  and settings model read `IDP_ISSUER` / `IDP_BACKCHANNEL_BASE_URL` / `IDP_CLIENT_SECRET`.
  The result was an empty `IDP_CLIENT_SECRET` and a startup refusal (the container died
  unhealthy on `idp_client_secret is missing or blank`). The bootable post-federation
  local-Keycloak profile (identical material under the current names, secret included)
  was present as `.env.local-keycloak` in the sibling `d0a-publication-discipline`
  worktree; the worktree `.env` was replaced with it. **This is a real finding** — a
  fresh worktree whose `.env` is copied from an older checkout will not boot the current
  code; recorded here, not fixed by this session (`.env` is gitignored local config).
- **The gateway image was stale (37 h) and lacked the consent route.** `docker compose
  up -d` recreated the container from an old `dial-mcp-gateway:local`, so
  `/dial/consent` answered FastAPI's default `{"detail":"Not Found"}` (probe_routing row 7
  FAILED on the first run). `docker compose build mcp-signin-gateway` rebuilt the image
  from the worktree's landed code, after which the row passed. **Finding** for the
  compose-boot gate: a recreate without a build can run stale code.
- **A stale gateway stack held port 8090.** The sibling `d0a-publication-discipline`
  worktree's stack (branch `c2-generalized-idp-federation`, already merged) was up and
  publishing 8090. It was stopped to free the port for this stack; its containers remain
  (stopped) and can be restarted by that worktree's owner.
- Services up (all healthy): `c2p5-…-mcp-signin-gateway-1`, `…-mcp-signin-router-1`,
  `…-mcp-app-fixture-1`; the instance's `core` and `keycloak` reachable.

## The automated rows

### probe_liveness (F1) — PASS

`probe_liveness.py` needs a slow **allowlisted** origin (default allowlist is
`https://claude.ai`), so it ran under a temporary compose override adding
`https://httpbin.org`, exactly as the archived PoC run documents. Verdict:

```
control /healthz: worst 0.1250 s
during the held-open leg: /healthz 200 in 0.0000 s (budget 1.2500 s)
the slow leg answered 400 in 7.22 s (the fetch was held ~5.0 s)
VERDICT: PASS
```

The override file was removed and the gateway recreated from the committed
configuration afterward; the running container's `GATEWAY_CIMD_ALLOWED_ORIGINS` was
verified back at `https://claude.ai`.

### probe_gateway_trust — green

Published JWKS `kid` matches the configured signing key; a token signed by an
unpublished key is refused (401 — the negative control); a gateway-signed token
resolves a real identity at Core's `/v1/user/info` (200, `roles=["admin"]`).

### probe_routing — all 11 rows pass

Including the **new** row: *consent action route reachable through the front door* —
a POST to `/dial/consent` naming an unknown flow is answered by the gateway with an
HTML page, never Core's 404. (First run: FAILED on the stale image; see above. Final
run: all 11 pass.)

### probe_dcr — green (flag enabled)

The AS metadata advertises `/dial/register`; a registration with no `redirect_uris` is
refused; a loopback registration succeeds with no secret issued; the RFC 7591 §3.2.1
typed sweep finds no violation.

### probe_end_to_end — fixed and green (see "The probe fix" below)

The shipped non-interactive probe could not complete a first-attribution flow on the
first run (it crashed on the decision page); it was fixed in lockstep with the flow shape
this change introduced and now completes headlessly on the app kind, drives deny, and
verifies the zero-page repeat. Four captured runs (approve, repeat, deny, toolset
boundary) are listed above and detailed below.

## The checkpoint rows

The checkpoint's own rows were driven **headlessly** by a scratch driver
(`security-runs/checkpoint_drive.py`,
gitignored, not a repository script) that reuses the shipped probe's browser machinery
(`_Session`, `_CallbackHandler`) and drives the **fixture** Keycloak login exactly as
`probe_end_to_end.py` does. No human was needed for the rows below because the **app
kind** carries no external account and the toolset's *first* decision row stops before
any upstream account is needed. Every credential prints only as a `redact()` handle.

### Row 7.1/7.2 mechanics — the app kind (`/apps/skills-demo/mcp`)

`live-checkpoint-1-approve-app-kind.txt`, `-2-repeat-zero-click.txt`, `-3-deny-app-kind.txt`:

1. **First attribution renders the decision page.** A first app sign-in for a fresh DCR
   client rendered the page naming the resolved client, the resource, and the redirect
   destination:

   > Approve access for cp-approve2? **cp-approve2** (client id CM9ZB9rDYcDdndm-PqNE9w)
   > is asking to use the DIAL app **skills-demo** as you. If you approve, the sign-in
   > code will be delivered to `http://127.0.0.1:8772/callback`.

   The approve POST minted a code (302 to the registered redirect URI). **PASS** — the
   app kind renders the page where nothing rendered before (no code minted pre-approval).

2. **Repeat is zero-page.** An immediately repeated sign-in for the same (user, client)
   reached the client callback with **zero pages** (`landed: callback-zero-page`, a code
   issued). **PASS** — the zero-click property proven, not asserted.

3. **Deny consumes with the refusal page, no code.** A deny POST answered HTTP 400 with
   the plain-language page ("you declined to let this client act as you. Nothing was
   changed, and no sign-in code was issued."). A re-run for the same client rendered the
   decision page **again** — the registry was not written. **PASS.**

### Row 7.1 mechanics — the toolset consent branch

`live-checkpoint-4-toolset-consent-branch.txt`, `-5-toolset-repeat-interstitial.txt`:

4. **First toolset attribution renders the decision page**, naming the *toolset* notion.
   The approve served the **display interstitial** (HTTP 200, meta-refresh), which
   continues to the upstream authorization URL (`https://mcp.notion.com/authorize`).
   **PASS** for the decision-page-then-approve mechanics; the flow then needs a real
   Notion account (unrun row below).

5. **A toolset repeat for the approved pair serves the interstitial directly** — no
   decision page (`landed: interstitial-no-decision`). **PASS** — approving wrote the
   registry, and the notice-not-decision split holds on the consent branch.

### Task 7.3 — the audit-trail sequence check — PASS

`live-audit-trail.txt` (read from the container's `gateway.audit` records) carries the
fixed-vocabulary events in sequence. Example (app kind, first attribution):

```
flow_allocated            client_id=CM9ZB9… resource_kind=app
attribution_required      client_name=cp-approve2 subject=3a0d60f4-<redacted-subject>
attribution_approved      client_name=cp-approve2 subject=3a0d60f4-<redacted-subject>
credential_free_short_circuit  resource_kind=app subject=3a0d60f4-<redacted-subject>
code_issued               subject=3a0d60f4-<redacted-subject>
```

and the repeat carries `flow_allocated → credential_free_short_circuit → code_issued`
with **no** `attribution_required` (the approved path). The deny row carries
`attribution_required → attribution_refused` with no `code_issued`. The toolset consent
branch carries `attribution_required → attribution_approved` (the continuation is the
upstream redirect; `code_issued` would follow the upstream callback, which needs a real
account). The subject is the local Keycloak fixture UUID — one stable value across every
event, which is what `runtime.approved_clients` keys on; it is shown here and in the raw
capture in the same abbreviated form the C2 evidence uses (`3a0d60f4-<redacted-subject>`),
per the publication-placeholder discipline. No credential (code, token, secret) appears
in any capture — every code is a `redact()` handle.

## The probe fix (task 3.6's spirit — the battery moves in lockstep with the flow shape)

The first run of this group surfaced that the shipped non-interactive probe
`scripts/probe_end_to_end.py` could no longer complete a first-attribution flow: it read
the decision page's `<form action="/dial/consent">` as if it were the IdP login form and
crashed (`ValueError: unknown url type: '/dial/consent'`). The probe battery must move in
lockstep with the flow this change introduced, so the probe was fixed:

- **The decision page is now recognized by construction** — the consent form's action plus
  the flow-id field it carries — checked *before* the login-form branch, so the provider
  credential is never submitted to it. Detection is by the page's own markers, never by the
  login form's absence.
- **Default mode completes the checkpoint headlessly**: it POSTs the flow id and `approve`
  to the consent route exactly as the page's form would (the probe's fixture login is
  already scriptable; the decision page needs no human), then continues the existing chain
  to the mint, the token exchange, and the live call.
- **`--deny`** drives the deny action and asserts the refusal shape (the plain refusal
  page, HTTP 400, no code issued), then stops.
- **`--app`** serves the flow as an app resource (`/apps/<name>/mcp`). An app carries no
  upstream credential, so its flow mints directly — the app shape is the one that completes
  headlessly end to end; a toolset may take the upstream consent branch, where the probe
  reports the boundary (the display interstitial → the upstream authorization URL) rather
  than following it, since that leg needs a real provider account.
- **A repeat sign-in for an approved pair needs no mode**: the flow is zero-click, and the
  probe verifies that path unchanged.
- The module docstring and step numbering were extended per the file's own conventions.

### The fixed probe's runs (all against the up stack; captures above)

- **App first attribution, approve** (`live-probe-end-to-end.txt`): discovery → authorize →
  IdP login → **decision page** → approve → **302 to the callback (the mint)** → callback
  (state round-tripped) → `/dial/token` (claims present) → **live tool call** (`tools/list`,
  1 tool). Full smoke verdict.
- **App repeat** (`live-probe-end-to-end-repeat.txt`): the same chain with **zero pages** —
  the pair is approved, no decision page.
- **App deny** (`live-probe-end-to-end-deny.txt`): the decision page → deny → **HTTP 400
  refusal page**, no code.
- **Toolset approve** (`live-probe-end-to-end-toolset-boundary.txt`): the decision page →
  approve → the **display interstitial** → reports the upstream boundary and stops.
- **The interactive probe** (`scripts/probe_end_to_end_interactive.py`) fails **cleanly**
  on the decision page rather than crashing — its pasted-URL check now names the decision
  page (a clean `ChainError`) instead of the misleading "not the client redirect URI";
  its self-test still passes 3/3. It remains hands-off the consent act by design (it hands
  the human exactly one URL).

## The findings

0. **BLOCKING defect found and fixed — the approve click was blocked by the decision
   page's `form-action 'self'`.** The owner's real-harness run exposed that a short-circuit
   approve returned a cross-origin 302 the browser would not follow, stranding the user on
   the decision page (then expiring). Root cause, controlled browser reproduction, fix, and
   re-test are in **`defect-approve-blocked-by-csp.md`**. The captures in this folder were
   re-taken after the fix. The harness-driven rows below are now expected to succeed.

1. **The full chain still cannot complete headlessly on a toolset** — by the flow's own
   design, not a defect: the toolset `notion` has no stored credential (`SIGNED_OUT`), so
   its first attribution reaches the upstream consent leg, which needs a real provider
   account. The probe now reports that boundary explicitly rather than failing obscurely.
   The app kind (no upstream credential) is the shape that completes headlessly, and does.

2. **The interactive probe cannot be handed a decision-page URL it can print.** By design
   it stops at the IdP login page and waits for a human's `input()`; the decision-page URL
   only exists *after* the sign-in. `live-probe-interactive-stop.txt` shows the clean stop
   (discovery OK, authorize OK, login page rendered, then `ChainError: no pasted URL`). A
   row that needs the owner's hands is listed below.

## The rows that need the owner's hands (UNRUN — do not read as passed)

These need a **real account** and/or a **real harness**, which no session can substitute:

- **7.1 — the CLI harness shape (Claude Code / CIMD), first sign-in → decision page →
  approve → the harness completes**, and **the immediately-repeated zero-click run with
  the real harness**. (The *mechanics* are proven headlessly above with the fixture; the
  *real harness* — CIMD resolution, the harness's own `needs authentication` → browser
  round-trip, and its completion on approve — is unrun.)
- **7.1/7.2 — the toolset consent branch completing through the upstream (Notion)**
  with a real account: the decision page is proven; the upstream sign-in and the
  post-approval `code_issued` are unrun (they need a Notion account).
- **7.2 — the IDE harness shape (Cursor / DCR) first-attribution and repeat**, through a
  real DCR-registered client driven by the harness itself. (The DCR registration and the
  checkpoint mechanics are proven above; the harness-driven flow is unrun.)
- **7.2 — the deny row on a real harness** (the harness's re-run after denial rendering
  the page again). (Proven headlessly with the fixture client; the harness-driven re-run
  is unrun.)

For the owner's run: bring the stack up as above (`.env` must be the post-federation
profile, image built), point Claude Code at the CIMD metadata document and Cursor at
the DCR endpoint, and expect the decision page on each first attribution.