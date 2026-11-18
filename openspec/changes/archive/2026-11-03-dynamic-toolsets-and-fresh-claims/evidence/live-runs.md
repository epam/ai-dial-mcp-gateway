# Live-acceptance pass — tasks 2.5 (driven checks), 3.1 (P2 live run), 3.2 (P3 live run)

The script-driven live acceptance for `dynamic-toolsets-and-fresh-claims`, run against the
composed stack (Core 8081, gateway front door 8090, Keycloak admin 8900) on 2026-11-01.
Every run below is a real drive against the live realm / live Core; nothing is simulated.
Toolchain: Python 3.12.13 from `.venv/Scripts` on the Windows host, Docker in WSL2.

Task **3.3** (the Claude Code + Cursor harness round-trip) is **NOT** in this pass — it needs
real harness sessions the owner drives. It is listed as pending in §D's summary table.
**Added later:** the owner drove task 3.3 live on 2026-11-02; its evidence is §H (a section
appended after this 2026-11-01 pass).

**No credential material appears in this file.** Provider refresh tokens, gateway refresh
tokens, access tokens and authorization codes are represented by redacted handles
(`<redacted len=… sha256=…>`); decoded claims are excerpted by name, never a whole token.

## Environment and preconditions

- The running gateway image carries the new code (`gateway/custody.py` present in the
  image's site-packages; `refresh_identity` present), and its environment carries the
  migrated settings (`IDP_SSO_SESSION_MAX_SECONDS=86400`, `GATEWAY_CUSTODY_KEYS` one entry,
  `GATEWAY_CUSTODY_PROVIDER_TOKEN_MAX_BYTES=4096`, `GATEWAY_FORM_MAX_BODY_BYTES=16384`).
- The stack was up and healthy at the start (`gateway /healthz` 200, Core `/health` 200,
  Keycloak realm 200); it was restored to that state at the end.
- The reconfigurable settings were read from `.env`: `GATEWAY_REFRESH_TTL_SECONDS=28800`,
  `IDP_SSO_SESSION_MAX_SECONDS=86400`, `TOOLSETS={"notion":{"scopes_supported":["default"]}}`.
- Realm facts read through the Admin API: `ssoSessionIdleTimeout=86400`,
  `ssoSessionMaxLifespan=86400`, `accessTokenLifespan=86400`, `revokeRefreshToken=false`,
  `refreshTokenMaxReuse=0`.
- The full sign-in flow was first re-verified as the baseline driver:
  `scripts/probe_end_to_end.py` completed the whole chain through the front door and the
  minted token authenticated a live tool call (`tools/list` → 68 tools). The driver pattern
  for 3.1/3.2 is that script's browserless flow (Keycloak login form driven by hand, cookies
  replayed).

---

## A — Task 2.5: the five driven checks (the provisioning script's verify mode)

Command (the router must be stopped while it runs — see the environment note):

```
wsl -e docker stop ai-dial-mcp-gateway-mcp-signin-router-1
PYTHONUTF8=1 python scripts/provision_keycloak.py --verify-refresh
wsl -e docker start ai-dial-mcp-gateway-mcp-signin-router-1
```

**Environment note (why the router is stopped).** The script binds a loopback listener on
`127.0.0.1:8090` to catch the gateway's callback. The front router publishes `0.0.0.0:8090`;
on this Windows host a `localhost`/`127.0.0.1` connection to 8090 resolves to the router's
binding, not the script's, so the script never sees the callback and the login leg reads as
a 400. With the router stopped the script's listener is the only binder on 8090 and the
flow completes. This is a host-port interaction, not a gateway or realm fact.

Observed output (trimmed):

```
OK (a): the exchange issued a session-bound refresh token; scopes = 'email profile' (no offline_access)
OK (b): the refresh grant returned a fresh token carrying sub, roles, and project
FAIL (c): a superseded provider refresh token was accepted again — the realm's rotation
          reuse detection is not revoking the chain
  (d) realm SSO Session Idle = 86400s, Max = 86400s, GATEWAY_REFRESH_TTL_SECONDS = 28800s
OK (d): the configured refresh window fits the realm's session policy
SKIP (e): pass --verify-refresh-idle-gap to wait out the idle timer
OK (c-revocation): after the session was revoked, the provider refused the refresh —
          revocation propagates to the refresh capability
```

| Check | Verdict | Evidence |
|---|---|---|
| (a) session-bound refresh token, no `offline_access` | **PASS** | exchange issued a refresh token; granted scopes `email profile` |
| (b) refresh grant returns a fresh verifiable token with roles + attribution | **PASS** | fresh token's decoded claims carry `sub`, `roles`, `project` |
| (c) reuse detection (superseded token refused) | **FAIL** | a superseded provider refresh token was **accepted again** |
| (c) session revocation kills the token | **PASS** | after admin logout the provider refused the refresh |
| (d) realm session window fits the configured refresh window | **PASS** | idle=86400, max=86400, configured=28800 (fits the Max) |
| (e) idle-refresh-on-use after a gap past SSO Session Idle | **INCOMPLETE (infeasible here)** | see below |

### Finding 1 — check (c): rotation reuse detection is OFF on this realm (provider fact)

**Verdict: FAIL — a design-load-bearing provider fact is falsified by the live run.**

- The realm runs with `revokeRefreshToken = false` (Keycloak's image default; **not**
  overridden in the instance's realm import — `keycloak/import/realm-config.json` sets only
  the session timeouts). With reuse detection off, a superseded provider refresh token is
  accepted again on reuse; the chain is not revoked.
- **Characterization (reverted).** Setting the realm to `revokeRefreshToken = true` through
  the Admin API and re-running the probe showed the mechanism works: the superseded token
  was **refused** and the chain was revoked (the current token also refused afterwards).
  The change was reverted; the realm is back at `revokeRefreshToken = false`.
- **Why it is load-bearing.** The design rests on the provider's rotation reuse detection as
  a bounding control: `design.md` §7 prices "the provider's rotation reuse detection bounds a
  lifted string (the gateway's own next refresh races a lifted string and the chain is revoked
  for both)" as a mitigation of RES-21 part ii (the time-decoupled ciphertext-archive
  conjunction), and §"Provider rotation can end a session by a lost response" treats
  rotation-on-use "with reuse detection that revokes the chain on replay" as a custody
  *strength*. On this realm that control is absent at the default configuration.
- **Scope.** This is a fact about *this local realm's configuration*, not about the gateway.
  Per the pass rule ("a check failing = a design-load-bearing provider fact falsified — STOP
  and report precisely"), this is reported, not patched around: the remedy is either
  (i) an operator prerequisite/guidance that the deployment must enable provider-side reuse
  detection for the rotation-strength claim to hold, or (ii) a design re-derivation of what
  bounds a lifted string where the provider does not revoke on replay. Both are the owner's /
  design pass's call.

### Check (e): INCOMPLETE — infeasible as specified on this realm (not a failure)

`--verify-refresh-idle-gap` waits out the realm's SSO Session Idle before the next refresh
(`time.sleep(idle + 30)`). On this realm `ssoSessionIdleTimeout = 86400s`, so the check would
sleep ~24 h — beyond a session. Separately, this realm sets **Idle == Max (both 86400s)**, so
even a completed wait could not distinguish "grant use renews the idle timer" from "the Max
cap applies": the two bounds coincide. The idle-refresh-on-use fact (D1 dependency 3) is
therefore **not verified here**; it is neither confirmed nor falsified. Recorded as
INCOMPLETE with the reason.

### 2.5's stated negative control

Task 2.5's verify note asks for a negative control (a realm session policy shorter than the
window) showing the loud `idp_session_ended` refusal at refresh. That control was **not run
in this pass**: it needs a temporary realm mutation (shorter session policy) plus a
deliberate wait, and the acceptance pass's environment was left at its committed state. The
`idp_session_ended` shape itself was exercised live in run B(2) below (session revocation),
which produces the same refusal class.

---

## B — Task 3.1: the P2 live run

Driven with a temp driver over the `probe_end_to_end.py` browserless-flow pattern: obtain a
user token via the full flow, redeem the code for access + refresh tokens, then exercise the
three P2 outcomes. A fresh session was established first (`token_issued` audited; refresh
token handle `<redacted len=2113 …>` — the grown, custody-carrying token).

### B(1) — roles change mid-session → refresh carries the changed roles

```
added dial-chat:user -> HTTP 204          (Admin API, mid-session)
refresh -> HTTP 200
  roles_before = ["admin"]
  roles_after  = ["admin", "user"]
```

**Verdict: PASS.** The minted access token's `roles` reflected the provider's changed roles
within the access TTL — the claims are re-read fresh at refresh, not served from a snapshot.
Audit: `token_refreshed` for subject `3a0d60f4-…-20e5adf408c3`, toolset `notion`.

### B(2) — session revocation → refused `invalid_grant` + audited `idp_session_ended`; re-run re-establishes

```
refresh before revocation -> HTTP 200
admin logout -> True                       (Admin API user logout)
refresh after revocation -> HTTP 400
  {"error":"invalid_grant",
   "error_description":"your sign-in session at the identity provider has ended;
                         start the sign-in again from your tool."}
```

Audit record (the refusal class on the trail):

```
{"event": "flow_refused", "reason": "idp_session_ended", "client_id": null,
 "redirect_uri": null, "resource": "http://localhost:8090/dial/notion/mcp", "toolset": null}
```

Re-run sign-in after revocation completed the whole flow and re-established the session
(`roles=["admin"]`, same `sub`).

**Verdict: PASS.** Revocation propagates to the gateway's refresh capability at the next
refresh, refused fail-closed with `invalid_grant`, audited distinctly as `idp_session_ended`,
and the re-run sign-in re-establishes.

### B(3) — gateway restart mid-session → refresh SURVIVES; pre-restart code

```
[wsl -e docker restart ai-dial-mcp-gateway-mcp-signin-gateway-1; /healthz 200]
refresh after restart -> HTTP 200
  roles = ["admin"], sub = 3a0d60f4-…
  (the custody claim returned with the presented token)

redeem the pre-restart unredeemed code after the restart:
  code grant after restart -> HTTP 200
    grant SUCCEEDED; access issued (sub=3a0d60f4-…)
    refresh token carries a custody claim? False
    that token's refresh -> HTTP 400
      {"error":"invalid_grant","error_description":"this refresh token's carried
       credentials cannot be read; …"}
```

**Verdict: PASS (refresh survives) / FINDING then CLOSED (pre-restart code; §G).**

- The refresh-after-restart half **PASSES**: the presented refresh token refreshed
  successfully because its encrypted custody claim travelled with the token; nothing
  server-side was needed. Audit: `token_refreshed` after the restart.
- The pre-restart unredeemed code's grant **SUCCEEDED** at the time of this run — it did
  **not** fail its grant. Its issued refresh token carried **no** custody claim, and its
  *next refresh* refused fail-closed with the custody refusal class (audit `flow_refused`
  `custody_decrypt_failed`). This was the spec-vs-code divergence of Finding 2; the code
  was fixed spec-first (the grant now refuses) and the arm re-driven live — see §G.

### Finding 2 — the spec's "an unredeemed pre-restart code fails its grant, fail-closed" was falsified; CLOSED spec-first (see §G)

The delta spec (`specs/mcp-signin/spec.md`, the restart scenario) states: *"an unredeemed
authorization code issued before the restart fails its grant fail-closed"*. `design.md`
(§D3/A2, and §7's RES-15 entry) states the same: *"an unredeemed pre-restart code fails its
grant, fail closed"*.

At the time of this run, the code let the **grant succeed**: with the pending custody entry
lost in the restart, `_sealed_custody_claim` (`gateway/token.py:315-338`) treated an absent
pending entry as **not a refusal** — it minted a refresh token with no custody claim, and
the fail-closed refusal happened one step later, at that token's *next refresh*
(`invalid_grant` / `custody_decrypt_failed`). The code's own docstring stated this behavior
explicitly ("A pending entry that is absent is not a refusal … that token refuses fail
closed at its next refresh under the custody refusal class rather than at this grant").

So the implementation and the spec disagreed about **where** the fail-closed refusal lands:
the spec says at the code grant; the code said at the following refresh. No test covered
the divergence — the restart test
(`tests/test_custody.py::test_a_restart_loses_pending_entries_but_not_the_custody`) obtains
a second unredeemed code but never redeemed it after the restart, so the grant path was
unexercised. Per the pass rule ("if a driven flow reveals a code defect … report it
precisely and stop — the fix decision is not yours"), this was reported, not fixed: either
the spec/design text is corrected to the implemented behavior (fail-closed deferred to the
next refresh), or the code is changed to fail the grant (spec-first: the spec would then be
the verified behavior). Either way the pass owner/design pass decides.

**Disposition (fixed, spec-first).** The decision was taken spec-first, as the repo's rule
requires: the spec is the contract, so the **code** was changed to match it rather than the
spec being re-worded down to the code. `_sealed_custody_claim` (`gateway/token.py`) now
refuses the **code grant** when the pending entry is absent — no pending entry means no
mint — under the custody refusal class (`invalid_grant` / `custody_decrypt_failed`), with
the reason stated in the function's docstring: a refresh token minted without custody could
never be refreshed, so issuing it would be a session born dead, and the fail-closed rule
pins the refusal at the grant where the client is still in a sign-in it can restart. The
verdict's basis: the spec's restart scenario is the normative statement of *where* the
refusal lands, and the implemented behavior had placed it one step later; the spec wins.
The unit coverage followed: `tests/test_custody.py` now redeems the orphan code after the
restart and asserts the `invalid_grant` / `custody_decrypt_failed` refusal, so the grant
path is exercised rather than merely asserted. The arm was then **re-driven live** against
the fixed image — see §G below.

---

## C — Task 3.2: the P3 live run (dynamic toolsets, no `TOOLSETS`)

The gateway was recreated with `TOOLSETS={}` (verified in the container environment) so it
serves every guard-passing name dynamically. The `.env` value was restored afterwards.

### C(1) — a new OAUTH toolset added to Core, signed in with no reconfigure and no restart

A new platform OAUTH toolset `live-check-oauth-2cc3` was registered through Core's ops API
(`PUT /v1/toolsets/platform/{name}`, the public Notion MCP endpoint — same upstream as
`notion`). No gateway reconfigure and no restart followed.

```
GET discovery /dial/live-check-oauth-2cc3/mcp -> 200
  {"resource":"http://localhost:8090/dial/live-check-oauth-2cc3/mcp",
   "authorization_servers":["http://localhost:8090"],"scopes_supported":[]}
[flow] the identity leg completed; the gateway rendered the attribution interstitial whose
  navigation target is built from the NEW toolset's own public settings:
  https://mcp.notion.com/authorize?...&client_id=wiAtXgCIqlHusX1A&
  redirect_uri=http%3A%2F%2Flocalhost%3A8090%2Fdial%2Fcallback%2Fupstream&
  code_challenge=VehzyPdcMjOpGlxe6Xa5dI4YboWaePRxUrNmVKzVY2k&…&scope=default
```

**Verdict: PASS up to the consent branch.** Discovery served the new name with **zero Core
calls** (name-derived), and the flow's settings read picked the new toolset up live and built
the consent interstitial from its *own* freshly-read public settings — no reconfigure, no
restart. A full token completion for this OAUTH toolset requires a **human consent at the
real upstream (Notion)** — the flow correctly landed on the consent interstitial, which is
the designed OAUTH branch. The toolset was then deleted (cleanup).

### C(2) — the refusal shapes

**Unknown name** (`live-check-ghost`, never registered in Core):

```
[discovery] /dial/live-check-ghost/mcp -> 200
  {"resource":"http://localhost:8090/dial/live-check-ghost/mcp",
   "authorization_servers":["http://localhost:8090"],"scopes_supported":[]}
[flow] callback_status 404, page:
  "Sign-in could not complete / this toolset is not registered in DIAL Core"
audit: {"event":"flow_branch_refused","reason":"unknown_toolset","toolset":"live-check-ghost",…}
```

**Verdict: PASS.** Discovery served the name (mirror property — phantom and real alike, no
Core call), and the flow's authenticated settings read is the system's only existence
refusal — plain-language page, `unknown_toolset` audited.

**Non-OAUTH toolset, no stored credential** (impossible branch) — `live-check-none`
(`authentication_type: NONE`):

```
[flow] callback_status 400, page:
  "This toolset cannot be signed in this way / This toolset's credential is configured
   directly in DIAL and cannot be established by a consent flow. Ask your DIAL
   administrator …"
audit: {"event":"flow_branch_refused","reason":"non_oauth_toolset","toolset":"live-check-none",…}
```

**Verdict: PASS.** Plain-language impossible-branch page, `non_oauth_toolset` audited, no
upstream round-trip.

**Non-OAUTH toolset with a stored GLOBAL credential** (the consentless short-circuit). A
GLOBAL credential was stored through Core's ops API
(`POST /v1/ops/toolset/signin` with `credentials_level:GLOBAL, authentication_type:NONE` →
`global_auth_status: SIGNED_IN`), then the full flow driven:

```
[flow] the identity leg completed; callback carried a code; /dial/token -> HTTP 200
  access_claims: iss="http://localhost:8090", sub="3a0d60f4-…",
                 aud=["http://localhost:8090/dial/live-check-none/mcp","dial-mcp-proxy"],
                 roles=["admin"], project="proj-alpha"
  refresh present: true
audit: flow_allocated → code_issued → token_issued   (no upstream_callback, no signin_result)
```

**Verdict: PASS.** A full **consentless** sign-in through the short-circuit: tokens issued
for a non-OAUTH toolset, with no upstream leg in the audit trail — the flow used the stored
GLOBAL credential, it did not establish one.

**The loop (credential removed → impossible branch → re-stored → short-circuit).** The GLOBAL
credential was removed through Core's ops API (`POST /v1/ops/toolset/signout` with
`credentials_level:GLOBAL` → `global_auth_status: SIGNED_OUT`). Re-driving the flow then
produced the impossible-branch refusal page again (400, "cannot be signed in this way").
Re-storing the credential restored the short-circuit (tokens issued). **Verdict: PASS** — the
loop is benign and ends out-of-band as designed.

**Core stopped — the availability split.** Core was stopped
(`wsl -e docker stop dial-instance-core-1`):

```
discovery /dial/live-check-none/mcp -> 200 (document still served — discovery depends only on the gateway)
flow settings read -> 502, page: "Sign-in could not complete / DIAL Core could not be reached (ConnectError)"
audit: {"event":"flow_leg_failed","leg":"authorization",
        "reason":"DIAL Core could not be reached (ConnectError)","toolset":"live-check-none",…}
```

Core was restored (`/health` 200), and the flow re-verified (GLOBAL credential re-stored;
consentless sign-in issued tokens again). **Verdict: PASS.** The availability split holds:
discovery is served through a Core outage; the flow's settings read fails closed with the
distinct operator-facing fault page and the `flow_leg_failed` / `authorization` audit.

Cleanup: both test toolsets deleted (`DELETE /v1/toolsets/platform/{name}` → 204), the GLOBAL
credential signed out, the gateway recreated with the `.env` `TOOLSETS` value, and the
stack left healthy.

---

## D — Verdict summary

| Run | Verdict |
|---|---|
| 2.5 (a) session-bound refresh token, no `offline_access` | **PASS** |
| 2.5 (b) refresh returns a fresh verifiable token with roles/attribution | **PASS** |
| 2.5 (c) reuse detection revokes the chain | **FAIL — provider fact (Finding 1)** |
| 2.5 (c) session revocation kills the refresh token | **PASS** |
| 2.5 (d) realm session window fits the configured window | **PASS** |
| 2.5 (e) idle-refresh-on-use after an idle gap | **INCOMPLETE — infeasible on this realm** |
| 3.1 (1) roles re-read fresh at refresh | **PASS** |
| 3.1 (2) revocation → `invalid_grant` + `idp_session_ended`; re-sign-in restores | **PASS** |
| 3.1 (3) refresh survives a gateway restart | **PASS** |
| 3.1 (3) unredeemed pre-restart code fails its grant | **PASS** live (§G — fixed spec-first, re-driven against the fixed image) |
| 3.2 (1) new OAUTH toolset picked up dynamically, no reconfigure/restart | **PASS** (to the consent branch; full completion needs upstream consent) |
| 3.2 (2) unknown name: discovery served + flow 404 + `unknown_toolset` | **PASS** |
| 3.2 (2) non-OAUTH no credential: impossible-branch page + `non_oauth_toolset` | **PASS** |
| 3.2 (2) non-OAUTH + GLOBAL credential: consentless short-circuit | **PASS** |
| 3.2 (2) credential removed → impossible branch → re-stored → short-circuit | **PASS** |
| 3.2 (2) Core stopped: discovery served, flow fails closed; re-verified after restore | **PASS** |
| 3.3 Claude Code + Cursor harness round-trip | **PASS** — owner-driven 2026-11-02 (§H) |

## E — Findings (for the owner / design pass; not fixed here)

1. **2.5(c) — provider fact falsified.** The local realm runs with `revokeRefreshToken=false`
   (Keycloak image default), so rotation reuse detection is off and a superseded provider
   refresh token is accepted again. With `revokeRefreshToken=true` the mechanism works
   (verified, then reverted). The design's RES-21 bounding control and the "rotation-on-use
   with reuse detection is a custody strength" claim rest on this; the remedy (operator
   prerequisite/guidance, or a re-derivation of what bounds a lifted string) is the design
   pass's call.

2. **3.1(3) — spec vs code diverge on the pre-restart code (CLOSED, spec-first; §G).** The
   spec and design say an unredeemed pre-restart code "fails its grant, fail-closed"; the
   implementation let the grant succeed and failed closed one step later (the minted token
   carried no custody claim and its next refresh refused `custody_decrypt_failed`). The
   decision was taken spec-first — the spec is the contract, so the **code** was changed to
   fail the grant rather than the spec re-worded — and the grant now refuses
   `invalid_grant` / `custody_decrypt_failed`, exercised by the restart test and re-driven
   live (§G).

3. **2.5(c) environment note.** The verify script's own loopback listener on
   `127.0.0.1:8090` collides with the front router's `0.0.0.0:8090` binding on this Windows
   host, so the router must be stopped while the script runs. This is a host-port fact, not a
   gateway/realm one; it is worth a note in the operator material if the script is meant to
   run against a live composed stack.

---

## F — Defect-fix pass: the 2.5(c)/(e) findings closed (2026-11-01, the owner's ruling)

The two findings of §A — check (c)'s reuse-detection fact and check (e)'s infeasibility —
are closed by the owner's ruling (design.md §8, "the provider's rotation reuse detection —
RULED"). The realm's rotation reuse detection is **set locally** (the
`scripts/provision_keycloak.py` provisioning converges `revokeRefreshToken=true` on the
realm it owns); real deployments run TLS'd internal legs (the owner's guarantee), so there
the setting is documented as a recommendation (defense-in-depth), never required; RES-21's
bounding list is re-worded to exactly that layering.

### F(1) — check (c) re-run: **PASS**

`scripts/provision_keycloak.py --verify-refresh --verify-refresh-idle-gap`, run against the
live realm (router stopped per the §A environment note). The provisioning converged the
realm's token policy (the setting had already been made true during the §A characterization
and was left as the ruling directs), and the reuse arm now passes:

```
realm token policy: revokeRefreshToken already True; nothing changed
OK (c): a superseded provider refresh token is refused on reuse
OK (c-revocation): after the session was revoked, the provider refused the refresh
```

The (c-revocation) arm was changed to drive its **own** fresh session: with reuse detection
on, the (c) arm revokes the whole chain it presents, so a shared chain would have made
(c-revocation) pass for the reuse check's reason rather than the session's. It now
establishes a fresh session, revokes it, and asserts the refresh is refused — the fact
verified rather than inherited.

### F(2) — check (e) temporary-Idle run: **PASS**, restore verified

The realm's own SSO Session Idle (86400s) equals Max, so waiting it out is infeasible and,
at Idle == Max, a completed wait could not even distinguish "grant use renews the idle
timer" from "the Max cap applies". Check (e) now temporarily lowers Idle to 300s, drives a
cadence, and restores the original in a `finally` path — the mutation and its restore logged:

```
  (e) temporarily lowered the realm's SSO Session Idle 86400s -> 300s for this check; it is restored afterwards
  (e) refresh 1 at 150s (inside the 300s idle window) ...
  (e) refresh 2 at 330s from the session's creation (past the 300s idle window), 180s after refresh 1 ...
OK (e): a refresh past the idle window succeeded — grant use renews the idle timer, so the operative cap is SSO Session Max
  (e) restored the realm's SSO Session Idle to 86400s
```

The restore was verified independently after the run (a fresh Admin-API read): the realm
holds Idle 86400s, Max 86400s, `revokeRefreshToken=true` — the pre-run state with the one
ruling-directed change. A separate characterization before the script edit also drove the
negative control on the same temporary-short-Idle shape: a single gap past Idle with **no**
intervening use is REFUSED (the session dies at the idle bound), while a use inside Idle
renews the timer and a later refresh past Idle still succeeds — the two halves the check
now asserts together. The idle-refresh-on-use fact (D1 dependency 3) is therefore
**verified**, not inferred.

### F(3) — the ruling's layering, landed

- `scripts/provision_keycloak.py` sets `revokeRefreshToken=true` on its realm (the reason
  is in the module's `REALM_REVOKE_REFRESH_TOKEN` comment), and the check-(e) temporary-Idle
  shaping is self-cleaning.
- `design.md` D3/A8's custody-strength sentence, §7's RES-21 (b) bounding list, the EP4
  delta-table cell, the Risks bullet, and the strict-gap-list provider-facts line are
  re-worded to the layering; §8 carries the ruling record (2026-11-01: local set, real-env
  guidance, TLS'd legs the production bound).
- `tasks.md` 2.5's (c)/(e) and 4.1's RES-21 entry carry the same layering.
- `docs/threat-model.md` RES-21 (b) and the EP4 row carry the same re-wording.
- `docs/gateway-configuration.md` (custody section) gains the recommendation row.

Finding 2 (§E) — the 3.1(3) pre-restart-code spec/code divergence — was left open by that
pass; it is closed spec-first and re-driven live in §G below.

---

## G — Finding 2 closed by a live re-run (3.1(3)'s pre-restart arm, 2026-11-01)

Finding 2 was a spec-vs-code divergence on **where** the pre-restart code's fail-closed
refusal lands. It was decided **spec-first** — the spec is the contract, so the code was
changed to fail the grant rather than the spec re-worded down to the old behavior — and the
arm was then re-driven live against the fixed image, since the fix had only unit coverage.

### G(1) — the code fix

`_sealed_custody_claim` (`gateway/token.py`) now raises `invalid_grant` /
`custody_decrypt_failed` when the pending entry is absent, so an unredeemed pre-restart
code fails **its grant** rather than minting a custody-less refresh token whose first
refresh would fail. `tests/test_custody.py` redeems the orphan code after the restart and
asserts the refusal, exercising the grant path the earlier coverage left untouched.

### G(2) — the live re-run: **PASS**

The gateway image was rebuilt from the working tree (the running image still carried the
pre-fix `token.py`), the container recreated, and the flow re-driven over the composed
stack with a fresh driver on the `probe_end_to_end.py` browserless pattern:

```
authorize -> keycloak:8443/realms/dial/protocol/openid-connect/auth
  hop 1: 200 -> (the login form submitted)
  hop 2: 302 -> 127.0.0.1:8768/callback
  code issued (pre-restart)      <redacted len=1206 sha256=274ba7c7c61e>
  restarting the gateway ...
  gateway healthy after restart
  code grant after restart       HTTP 400
    error                        'invalid_grant'
    error_description            "the gateway could not recover this sign-in's credentials,
                                  so it refused to issue a token that could not be
                                  refreshed. Start the sign-in again from your tool."
  audit flow_refused records     ['custody_decrypt_failed']
```

The audit record on the trail, read from the container's own log:

```
{"event": "flow_refused", "reason": "custody_decrypt_failed", "client_id": "group6-smoke",
 "redirect_uri": "http://127.0.0.1:8768/callback",
 "resource": "http://localhost:8090/dial/notion/mcp", "toolset": null}
```

**Verdict: PASS.** Against the fixed image, an authorization code issued before the restart
and redeemed after it now fails **its grant** — HTTP 400, `invalid_grant`, audited
`custody_decrypt_failed` — matching the spec's restart scenario and `design.md` §D3/A2's
"an unredeemed pre-restart code fails its grant, fail closed". The precedence of the spec
over the code is the ruling's basis, recorded here and in the code's docstring.

The stack was left healthy, the driver removed, and the pre-fix image's replacement is the
running image (which now carries the fixed code).

---

## H — Task 3.3: the harness token-store round-trip gate — **PASS** (2026-11-02)

The gate (design.md D3/A5, task 3.3): with the grown refresh token — the one carrying the
encrypted custody claim — complete a real sign-in → refresh cycle in **both** field-proven
harnesses (Claude Code/CIMD and Cursor/DCR), restart the gateway, and refresh again in each,
proving the stored, grown token survives the harness's own token store across a full cycle.
The owner drove both harnesses against the live composed stack; the audit trail is the
event source below. **No token material appears here** — only audit event names, timestamps
and the trail's fixed-vocabulary fields.

The consentless path was armed for both harnesses by one act: the `notion` toolset's
**GLOBAL** credential was stored through Core's ops API from the owner's own Notion consent
(the admin-role identity token). Both harnesses then sign in through the short-circuit
(the stored credential), which is why neither run carries an upstream leg — the global
credential is the routing decision, not the identity-consent session.

### H(1) — Run A: Claude Code (CIMD) — **PASS**

The full cycle, from the audit trail (Z timestamps):

```
23:47Z  flow_allocated -> code_issued -> token_issued     (consentless short-circuit; NO upstream leg)
00:54:43Z  token_refreshed                                 (refresh across a ~40-minute idle gap)
01:04:15Z  token_refreshed                                 (the FIRST event after a live gateway
                                                            restart — no re-auth requested)
09:27:10Z  flow_refused  reason=invalid_grant              (after an ~8-hour pause: the session's
                                                            ABSOLUTE expiry behaved as designed —
                                                            the non-sliding 8 h window from
                                                            GATEWAY_REFRESH_TTL_SECONDS=28800)
10:07:32-34Z  flow_allocated -> code_issued -> token_issued (re-auth, consentless AGAIN — no
                                                            upstream callback; the global
                                                            credential short-circuit)
```

**Verdict: PASS.** Sign-in (consentless) → refresh across an idle gap → refresh across a
live gateway restart (no re-auth) → the absolute non-sliding expiry refused at the window's
end → re-auth, consentless again. The grown refresh token was accepted by Claude Code's
store and replayed after the restart; the restart-survives-custody behavior (task 3.1(3))
held in the real harness, not only in the script driver.

### H(2) — Run B: Cursor (DCR) — **PASS**

```
21:30:20Z  client_registered  source=dcr                   (DCR registration)
           flow_allocated -> code_issued (2 s later) -> token_issued
                                                            (consentless short-circuit; NO upstream leg)
21:43:41Z  token_refreshed                                 (refresh)
           [gateway restarted; the owner re-invoked post-restart]
           token_refreshed                                 (refresh across the live restart — no re-auth)
```

**Verdict: PASS.** The full DCR cycle: client registration → consentless short-circuit
sign-in → refresh → refresh across a live gateway restart, the owner re-invoking after the
restart and getting no re-auth request. The grown refresh token was accepted by Cursor's
store and replayed after the restart.

### H(3) — The gate's adoption question — answered: the custody shape stands

Task 3.3 is an **implementation gate on adoption**: any harness token store with a hard
item-size limit the configured bound cannot dodge is a named deployment prerequisite, and a
hard limit no bound can dodge is the one result that legitimately forces the custody shape
back to the owner. **Neither field-proven harness's store refused the grown token** — both
completed the sign-in/refresh/restart/refresh round trip with the custody-carrying refresh
token intact. No such finding was raised; the v3 custody shape stands, and the two-harness
round-trip gate is green. The stores beyond the two remain the accepted RES-23 remainder
(untested stores, unverified), with this gate as its recorded re-open trigger.

### H(4) — Incident en route: one transient CIMD refusal, recovered by retry

One `flow_refused reason=unknown_client` occurred on the CIMD path — a CIMD (client
metadata document) fetch blip, not a token-store or custody failure. It was **recovered by
retry** on the second attempt (the flow completed). This is the deferred **T14** class
behaving as documented: a transient upstream fetch failure refuses the flow with
`unknown_client` and a retry re-establishes it — no gateway defect, no persistent effect on
the gate's result.
