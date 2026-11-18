# The interactive end-to-end probe — `scripts/probe_end_to_end_interactive.py`

Change: `generalized-idp-federation` (C2). Scope of this record: the interactive
sign-in probe (the human signs in at the identity provider's own hosted page; the
harness side of the chain stays scripted), its reuse decision, its stopping points, the
dry run against the live B2C-backed gateway, and one finding the dry run surfaced about
the *non-interactive* probe. No commit made. Files touched by this record:
`scripts/probe_end_to_end_interactive.py` and this file — nothing else.

## The reuse decision: import, with one deliberate exception

`scripts/probe_end_to_end.py` imports cleanly: its module level defines only
constants, classes, and functions; `main()` runs under `__main__` alone. The
interactive probe therefore imports the chain machinery wholesale rather than forking
it — `_Session` (the cookie-replaying browser session), `_Run`/`_new_secrets` (the run
configuration and the client's PKCE S256 pair and state), `_resolve_run` (client
resolution: `--client-id`, which may be a CIMD metadata URL the gateway fetches itself
at `/dial/authorize`, or the pre-registered `GATEWAY_E2E_CLIENT_ID`), `probe_discovery`,
`probe_token`, `probe_live_call`, and the `ChainError`/`_safe`/`_step` reporting
helpers. The two probes cannot drift apart in what the token and live-call steps
assert.

**The exception — the authorize step is this probe's own (`authorize_idp_leg`), and the
dry run proved it could not be otherwise.** The shared `probe_authorize` refuses
`openid` in the relayed scope. That check encoded the pre-federation fixture's policy;
against the live B2C-backed gateway it fails on a correct flow, because C2's identity
leg requests the gateway identity client's own default scopes — `openid profile` from
the configured `IDP_CLIENT_SCOPES`, with `openid` mandatory for any OIDC provider —
which the shared probe reports as `authorize: the redirect requested a forbidden scope:
['openid', 'profile']`. The invariant that survives every provider is the spec's other
one, so the interactive step asserts instead: `offline_access` is never requested, and,
where `IDP_CLIENT_SCOPES` is readable from the settings, the relayed scope set equals
it exactly (a scope the operator did not configure fails the probe instead of passing
unexamined). The interactive probe must not edit the probe it imports from, so the
corrected step lives here.

**Finding to route back (not acted on):** `scripts/probe_end_to_end.py` step 2 is now
stale relative to C2's scope semantics — it passes only against a provider profile
whose identity client requests no `openid`. The non-interactive probe will fail the
same way on the B2C profile. Fixing it is that file's owner's call; this record only
establishes the fact.

## The flow's stopping points

1. **Steps 1–2, scripted.** Discovery through the front door, then `/dial/authorize`
   with PKCE (S256) and state, exactly the shared probe's request shape.
2. **The login-page stop (step 3).** Redirects are followed one hop at a time and only
   until an HTML page renders on a host that is **not the gateway's** — that page is
   the provider's hosted login, recognized by construction, not by provider knowledge
   (no provider fact is hardcoded; the B2C page is stopped at the same rule a Keycloak
   or any other hosted page would be). Two things abort the walk before it: a hop that
   lands on the client callback before any sign-in, and a gateway page mid-chain —
   either means the flow short-circuited or faulted without a human ever signing in.
   The probe submits nothing to the login page and prints none of its cookies, headers,
   or body — only the page's host and the URL itself.
3. **The human sign-in (step 4).** The probe prints the login URL in full (it carries
   the flow's state and challenge, no secret — the verifier never leaves the client and
   no code exists yet) and waits on `input()`. Prompts are plain ASCII because the
   Windows console is cp1252. The human signs in; the provider routes through the
   gateway's identity callback and lands the browser on the client's registered
   redirect URI, where nothing is listening — the page fails to load, and the URL from
   the address bar is what the human pastes. An EOF or empty input on stdin is a clean
   `ChainError`, so scripted runs stop loudly at exactly this point.
4. **The pasted URL (step 4's second half).** The origin and path must equal the
   registered redirect URI's — a code delivered anywhere else was not delivered to this
   client — and the **state must round-trip exactly: a mismatch is a failed probe, not
   a warning**. An OAuth error response (`error`/`error_description`) is reported the
   way the shared probe reports one. The code is printed only as a redacted handle
   (`redact()`), the same handle the non-interactive probe prints; the pasted URL is
   never echoed whole.
5. **Steps 5–6, imported unchanged.** The code exchange at `/dial/token` with the
   verifier, the minted token's claim report, and the live `tools/list` through the
   front door (`/dial/<toolset>/mcp`) with the token the flow minted — the shared
   probe's functions, unmodified.

No login credential is read from any file or environment: `TEST_USER_*` is never
touched, and the only secrets in play are none — DCR's flow needs no secret and the
pre-registered E2E client's config is non-secret.

## What the human sees

The terminal shows the login URL with two sentences of instruction: open it, sign in;
after the sign-in the browser is redirected through the gateway and lands on a URL
that fails to load (nothing is listening there) — that is expected; paste it and press
Enter. The provider's own page does whatever the provider renders (SSO, MFA, consent);
the probe is deliberately blind to all of it.

## The dry run (steps 1 through the login-page stop, against the live stack)

The composed stack was up and healthy for the B2C profile (`IDP_ISSUER` is the `tfp`
spelling; gateway and router containers healthy, discovery answering through the front
door). The probe was run with stdin at EOF — the honest dry run for an interactive
tool: everything before the human step runs for real, the input step then stops
loudly. **The login-page stop is reached**: step 2's redirect goes to the B2C tenant,
and step 3 stops on hop 1 at the hosted login page:

    === step 2: /dial/authorize through the front door ===
      status    302 -> <tenant-host>
      client    <tenant-client-id>
      scope     openid profile
    === step 3: the identity provider's login page ===
      hop 1: the login page rendered (<tenant-host>)
    === step 4: the human signs in ===
      open this URL in a browser and sign in:
      https://<tenant-host>/.../oauth2/v2.0/authorize?...
    final URL: login: no pasted URL: stdin closed before the sign-in completed

(The URL above is elided here; the run printed it in full, with no secret in it.) The
stop was driven no further — no human input was given or simulated. **Not yet
exercised live:** the paste-back, the code exchange, and the live call, which need a
human to sign in; the paste-verification logic was exercised with synthetic cases
instead — 6/6 behave (one accept; wrong port, wrong path, wrong origin, mismatched
state, and OAuth-error response each refused, the state mismatch as a hard failure).

## Gates

- `ruff check scripts/probe_end_to_end_interactive.py` — pass (one import-order fix
  applied).
- `ruff format --check` — pass (one reformat applied).
- Leak check on the tree (`scripts/check_publication_leaks.py`) — PASS, 0 unwaived
  findings; the script adds no secret literals.

---

# Addendum: the loopback-capture mode — the paste removed

Scope of this addendum: the same file, `scripts/probe_end_to_end_interactive.py`, grown
a default capture mode so the owner only ever enters credentials at the provider's own
page — the probe drives everything else, including receiving the final redirect. No
commit made. Files touched by this addendum: the probe and this file — nothing else.

## The capture mode's design

**Default is capture; paste is the flagged fallback.** The probe now arms a small local
HTTP listener on the pre-registered client's loopback redirect
(`http://127.0.0.1:8767/callback` — the `PRE_REGISTERED_CLIENTS` entry the non-interactive
probe already points at), **bound before the flow starts**, so a port that cannot be
bound is a configuration fault reported before any request is spent on a flow whose
callback nothing would catch; the failure message points at `--paste`. The listener
stays out of the way of the scripted steps: the probe's own session still walks the
chain hop by hop to the login page, and its walk still refuses a hop that lands on the
client callback before any sign-in — so a flow that short-circuits fails loudly before
the listener could record an unearned code.

**The human step.** The probe prints the login URL and blocks: the human signs in at
the provider's page and follows whatever pages the provider renders (SSO, MFA, consent
— the probe is blind to all of it); the flow's final harness redirect lands on the
loopback, the listener records the path and the query parameters, and answers the
browser with one static page — "Sign-in captured … close this tab and return to the
terminal" — with no injected content and nothing from the request rendered back. Which
pages the human saw first is the provider's business; the listener only cares about the
final landing.

**The wait costs no CPU.** The listener thread blocks on the socket accept
(`serve_forever`); the main thread sleeps on the capture event, waking once a second
only so Ctrl+C stays responsive on Windows, where a single long wait can hold the
interrupt. The wait defaults to 10 minutes (`--wait-minutes` to change), prints a clear
"waiting for the browser to return... (Ctrl+C to abort)" line and a progress note every
30 s, and times out into the probe's normal loud failure — no half-state, the unspent
code simply expires. A `KeyboardInterrupt` during the wait is caught and reported as a
clean abort (exit 130) with the same "rerun for a fresh flow" note.

**The verification is one shared implementation.** The paste path's assertions were
extracted rather than forked: `_verify_callback_params` (state round-trips exactly — a
mismatch is a hard failure, never a warning; an OAuth error response is reported, not
crashed on) and `_report_callback` (parameter list, state line, the code as a redacted
handle) now sit behind both `harvest_callback` (paste: full origin+path check) and
`collect_captured_callback` (capture: the socket's own bind proves the request reached
127.0.0.1 on the client's registered port, so the remaining check is the registered
path). The two capture paths cannot drift in what they assert.

**Self-test.** `--self-test` exercises the whole capture machinery with synthetic
requests — no gateway, no human: the listener is armed exactly as a real run arms it, a
local HTTP client plays the returning browser, and the verification is asked for each
verdict it can give.

## The self-test results (`--self-test`, 3/3)

    params    ['code', 'state']
    state     round-tripped
    code      <redacted len=14 sha256=2769ef6263a8>
    capture   ok (HTTP 200, the static page, code <redacted len=14 sha256=2769ef6263a8>)
    mismatch  refused as a hard failure (callback: the state parameter did not round-trip)
    error     reported, not crashed on (callback: no authorization code: access_denied )
    self-test: 3/3 checks passed on 127.0.0.1:8767

(The handle above is `redact()`'s, over the synthetic string `self-test-code` — no
credential.) The three verdicts: the capture answers the returning browser with HTTP 200
and the static page and hands back the captured code through the shared verification; a
forged state is a hard failure with the same message the paste path raises; an OAuth
error response is reported through the same "no authorization code" channel.

## The dry run (capture mode, live B2C-backed stack, aborted at the human step)

The stack was up and healthy for the B2C profile. The dry run ran capture mode with
`--wait-minutes 1` — everything before the human step runs for real, the wait then
expires on purpose rather than holding a terminal for 10 minutes:

    === step 1: discovery through the front door ===
      resource  http://localhost:8090/dial/notion/mcp
      servers   ["http://localhost:8090"]
    === step 2: /dial/authorize through the front door ===
      status    302 -> <tenant-host>
      client    <tenant-client-id>
      scope     openid profile
    === step 3: the identity provider's login page ===
      hop 1: the login page rendered (<tenant-host>)
    === step 4: the human signs in (the probe listens on the loopback) ===
      open this URL in a browser and sign in:
      https://<tenant-host>/.../oauth2/v2.0/authorize?...
      listening http://127.0.0.1:8767/callback - the flow's final redirect lands here
      waiting for the browser to return... (Ctrl+C to abort; the wait gives up after 1 min)
      ... still waiting (0 min of the wait left; Ctrl+C to abort)
    ChainError: callback: no browser return within 60 s: the sign-in never completed,
    or the browser landed somewhere this listener does not cover

(The URL is elided here; the run printed it in full — it carries the flow's state and
challenge, no secret, and no code exists yet.) **Confirmed live:** the listener armed
before step 1, the login-page stop reached, the capture-mode step 4 printed the URL,
the listening line, and the waiting line with the countdown note. The run then aborted
on its own short wait — the deliberate dry-run abort, which also exercised the timeout
path; no human input was given or simulated. **Not yet exercised live:** a real browser
landing on the loopback with a real code, the exchange, and the live call — they need
the human step, and the capture and verification logic behind them is covered by the
self-test above.

## Gates (this addendum)

- `ruff check scripts/probe_end_to_end_interactive.py` — pass (three `TRY003` findings
  on the self-test's bare `AssertionError`s, resolved by routing them through
  `ChainError("self-test", ...)` like the rest of the file).
- `ruff format --check` — pass (one reformat applied).
- `--self-test` — 3/3, above.
- `pytest -q` — 615 passed, 1 skipped (the probe is not under `tests/`; run once to
  confirm the suite is untouched).
- Leak check (`scripts/check_publication_leaks.py`) — the probe adds **zero** findings,
  but the tree-wide verdict is **FAIL** on one pre-existing unwaived finding this
  addendum did not create: `docs/evidence/c2/part1-b2c-setup.md:20: personal-path`,
  committed in `d9af1b8`. Routing it back to that record's owner; fixing it is outside
  this addendum's two-file scope.

---

# Addendum: the `offline_access` refusal removed from `authorize_idp_leg`

Stale: this step refused a relayed `offline_access` as "the forbidden scope", but the
operator's verified B2C configuration now legitimately includes it for the confidential
client — the refresh-token fact depends on it — so the refusal failed a correct flow.
Changed: the refusal is gone; the invariant kept is the `IDP_CLIENT_SCOPES` equality
check, and `offline_access` is now reported informationally ("relayed offline_access:
yes/no"), never refused — ruff check/format clean, leak check PASS, `--self-test` 3/3.

---

Addendum: `probe_token`'s `project` requirement dropped — the claim is optional by design (Core's projectPath is null-safe; the live provider carries no project attribute), so it is printed when present and noted informationally when absent, `sub` and `roles` staying required. Gates: ruff check clean, format content-clean (tree-wide CRLF checkout artifact aside), leak check PASS 0 unwaived, `--self-test` 3/3.

---

# Addendum: step 7 — the refresh leg (and the refreshed token's second live call)

Scope of this addendum: the same file, `scripts/probe_end_to_end_interactive.py`, grown
two steps — the refresh leg at `/dial/token` (`grant_type=refresh_token`), and a second
live tool call made with the refreshed token. No commit made. Files touched: the
interactive probe, the probe it imports from (the minimal plumbing, below), and this
file — nothing else.

## How the scripted probe handled refresh, and the plumbing this needed

`scripts/probe_end_to_end.py` had **no refresh step** — `probe_token` reported the
minted refresh token's presence ("present"/"absent") and dropped it; no grant of
`grant_type=refresh_token` existed to reuse or extend. The refresh token therefore had
to be plumbed out of the token step, in that file, minimally and behavior-preservingly:
`probe_token` now returns `(access_token, refresh_token | None)` instead of the bare
access token (the scripted probe's `main` unpacks and ignores the refresh token — its
chain is unchanged), and `probe_live_call` gained a keyword `step: int = 6` so a
repeated call can carry a later step number without forking its assertions. The refresh
leg itself lives in the interactive file (`probe_refresh`), as the scripted probe does
not run it; if its owner later adopts one, this is the shape.

## The step's shape

`probe_refresh(session, run, refresh_token, access_token)` POSTs to `/dial/token` with
`grant_type=refresh_token`, the minted gateway refresh token, the client id, and the
`resource` the original flow named — the last two because the gateway's refresh grant
refuses a resource that does not match the one the token was minted for
(`invalid_target`) and a client id that is not the token's own (`invalid_grant`), so
the request has to be the honest one to pass at all. The checks, in order:

1. **HTTP 200.**
2. **A new access token.** Both handles print in the existing `redact()` style
   (`access    was <handle>` / `access    now <handle>`); the refreshed token equal to
   the presented one is a `ChainError` — a refresh that returned the presented token
   would mean nothing was refreshed.
3. **The claims re-read through the identity leg.** The refreshed token's `iss`, `sub`,
   `aud`, `roles` print exactly as the token step prints them, and `sub` and `roles`
   are required as there — the gateway's refresh grant re-reads the claims from the
   live provider rather than re-minting from a snapshot, so roles arriving here is the
   fresh-claims read (C1) exercised end to end; their absence fails with a message
   naming the re-read.
4. **A refresh token present.** Absent is a `ChainError` (the session would be born
   unrefreshable); present, the step reports which policy ran — `rotation  none: the
   same refresh token persists` when the returned token equals the presented one,
   `rotation  the refresh token rotated (a replacement was issued)` otherwise. Neither
   is required: rotation is the deployment's configured setting
   (`gateway_rotate_refresh_tokens`), and both are correct.

Step 8 then repeats the live `tools/list` through the front door with the refreshed
token — the imported `probe_live_call` at `step=8`, the same assertions as step 6. The
second live call is the point: the refreshed credential works through the front door,
not only at the token endpoint.

If the token step minted **no refresh token at all**, the probe stops loudly before
step 7 with a message naming the cause (`offline_access` absent from the identity
client's configuration, or the provider granted no refresh token) — the leg cannot run
on nothing, and a deployment configured per C2 that mints no refresh token is exactly
what the probe exists to catch.

## Gates

- `ruff check` on both probe files — pass.
- `ruff format --check` — the interactive file fully formatted; the shared probe
  content-clean (the tree-wide CRLF checkout artifact: untouched committed probes fail
  `--check` identically; an LF-normalized copy of the file reads "already formatted").
- `--self-test` — 3/3 (imports both probes, exercises the capture machinery; unchanged).
- `scripts/probe_end_to_end.py --help` — runs, confirming the scripted probe survives
  the `probe_token` signature change.
- Leak check (`scripts/check_publication_leaks.py`) — PASS, 0 unwaived findings.

**Not yet exercised live:** the refresh leg and the second live call need a human
sign-in to complete the flow first (the minted refresh token is the leg's input, and
nothing synthetic stands in for it). The request shape and refusals above are read
against the gateway's own refresh-grant validation ladder, not yet against the running
stack; the next interactive run with a human at the provider's page exercises them.

---

# Addendum: the `--signout` mode — deleting the stored per-user credential

Scope of this addendum: the same file, `scripts/probe_end_to_end_interactive.py`, grown
a `--signout` mode: the flow runs exactly as above through the token exchange, then —
instead of the live calls and the refresh leg — the minted access token deletes the
toolset's stored per-user credential through Core's ops sign-out, and the deletion is
verified. No commit made. Files touched by this addendum: the probe and this file —
nothing else.

**Why the mode exists, and why the call goes to Core directly.** A per-user credential
in Core resolves only by its creating identity, and Core exposes no admin surface for
one: the only way to delete it is the holder's own call. The gateway's public surface
relays no sign-out, so the probe presents the flow's minted access token — Core trusts
it as this user through the dial-mcp-proxy trust entry, the same trust that lets it
drive a live tool call — at `POST {DIAL_CORE_URL}/v1/ops/toolset/signout`. This is the
one diagnostic call the probe makes off the gateway: it holds the user's own token, and
a diagnostic tool acting as the user, with their consent at the browser step that
minted it, is its purpose. `DIAL_CORE_URL` comes from `.env` (`http://localhost:8081`
locally); absent, the mode fails with a message saying where the route lives.

**The request shape, read off the gateway's own credential-call construction**
(`complete_upstream_leg` in `gateway/flow.py`, the sign-in body Core demonstrably
accepts): camelCase `url` / `credentialsLevel` / `authenticationType`, with the
`code` and `redirectUri` — the fields only a consent leg carries — dropped. So:

    POST /v1/ops/toolset/signout
    Authorization: Bearer <the flow's minted access token>
    {"url": "<toolset>", "credentialsLevel": "USER", "authenticationType": "OAUTH"}

`url` is the toolset's **registry name** (e.g. `notion`), not a resource URL — the
same value the gateway's sign-in body sends (`flow.toolset`, the resolved namespace
name) and the key Core stores the credential under. `credentialsLevel` is the literal
`USER`, matching the level the credential was stored at. Refusals surface loudly:
400/403/404 raise with the body prefix (`Core refused the sign-out with HTTP …`), and
any other non-200 fails the same way — no silent pass.

**The verdict.** After a 200, the mode re-reads the status the way the flow itself
reads it: `GET {DIAL_CORE_URL}/openai/toolsets/<toolset>` with the same token, and
checks `auth_settings.user_level_auth_status`. The pass verdict is a signed-out value —
`NOT_SIGNED_IN`, or `SIGNED_OUT` as the dynamic-toolsets live run observed Core
spelling it — and `SIGNED_IN` after a 200 sign-out is a hard failure naming the
surviving credential; an unreadable or absent status is also a failure (an unproven
deletion does not pass).

**Not yet exercised live (the positive run).** The mode needs a human browser pass —
one quick trip to the provider's page, often SSO-instant, because the stored credential
short-circuits the upstream consent leg — and none was performed here. Exercised
instead:

- `--self-test` — 3/3 (the mode does not touch the capture machinery; run to confirm
  the file still imports and the listener path is unchanged).
- Negative control against the live stack: `POST /v1/ops/toolset/signout` and
  `GET /openai/toolsets/notion` at Core with a deliberately invalid bearer both answer
  **401 "Unknown api key"** — both routes exist where the mode aims them, and the
  invalid-token refusal is exactly the loud rendering the mode reports. No side
  effects; no credential touched.
- The first live `--signout` run (owner at the browser) is the deletion event itself;
  its transcript belongs in the record of whatever change needs the deletion.

## Gates (this addendum)

- `ruff check scripts/probe_end_to_end_interactive.py` — pass (one PLR0915 on the
  grown `main`, resolved by extracting `_build_parser()`).
- `ruff format --check` — pass.
- `--self-test` — 3/3.
- Leak check (`scripts/check_publication_leaks.py`) — PASS, 0 unwaived findings.
- `--help` — runs; the flag renders in the usage block.
- `pytest -q` — 626 passed, 1 skipped (run once to confirm the suite is untouched).

