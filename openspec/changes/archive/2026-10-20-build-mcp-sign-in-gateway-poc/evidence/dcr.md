# Group 8 — DCR live verification

Tasks 8.1–8.6 of `build-mcp-sign-in-gateway-poc`, the config-gated fallback path proven
live with the flag off and on. Every capture below is redacted at capture time; the
`.gitignore` blocks `*.jwt`/`*.pem`/`*.key` and the scratch `dcr_client.json`, so an
unredacted capture would fail to commit silently. No client secret exists on this path at
all — every client is a public PKCE client and the endpoint issues none.

## Verdict

**Group 8 complete, every task green.** The flag-off surface (8.1), the enabled surface
with registration and its refusal branch (8.2), the authorization flow as the
DCR-registered client through to a **live toolset call** (8.3), restart persistence (8.4),
and the re-disable/dormant-store round trip (8.5) are all **green**.

8.3's final leg was **blocked when this group ran**, on two independent blockers, and the
pass that cleared them is written up at the end of this file (**Task 8.3 — the flow
completed as the DCR-registered client**). In the blocked pass the flow was verified from
the authorization request through the Keycloak login to the upstream interstitial; the
live toolset call was unreachable because the test user's Notion credential had been
signed out (completing Notion's consent needs a human in a browser) and, beyond that, the
interstitial defect recorded in `finding-empty-upstream-redirect.md` blocked the leg for
every client on the then-current tree. Both are resolved: the credential is established
again and the interstitial is fixed (task 4.8). The section below is the group's original
record, kept as it stood; the end-of-file section is what completes 8.3.

**One defect found, since closed** (8.2, `finding-dcr-store-mount-chmod.md`): on the compose file's
`./data:/data` bind mount as this host mounts it, the store's atomic save fails at
`chmod`, so **every** registration is refused. Recorded for the defect cycle, not fixed
in the group's own pass; **closed by task 3.12** (the tolerant `chmod`), whose
composed-stack re-run is further down this file.

## The recreate sequence, and the operational fact it exercises

Every flag change ran the same four steps:

```
# 1. set or unset DCR_ENABLED in .env (gitignored)
# 2. recreate the gateway
wsl -e docker compose up -d --force-recreate mcp-signin-gateway
# 3. restart the router too — a gateway-only recreate gives it a new address while
#    nginx resolved its upstream once at start, so the router 502s until restarted
wsl -e docker compose restart mcp-signin-router
# 4. poll /healthz through 8090 before any probe
curl -s -o /dev/null -w "%{http_code}" http://localhost:8090/healthz
```

Step 3 is not optional, and it was exercised on every one of the five recreates below.
Step 4 gated each probe: no probe ran until `/healthz` answered `200` through the public
origin.

**One more operational fact, measured.** The first enable was attempted against the
compose file as committed, and the store would not write (defect below). Isolating the
feature from the mount defect required a **temporary compose override** — the same
compose file with one line changed, the store mounted from a WSL-native (ext4) path:

```
# /tmp/dcr-verify.override.yml (deleted after the pass; nothing in the repository changed)
services:
  mcp-signin-gateway:
    volumes:
      - /home/<user>/gw-dcr-verify/data:/data
```

Every green capture below was taken with that override in place, and the deployment was
returned to the committed bind mount afterwards. Which mount each capture used is stated
per row.

## Scenario verdict rows

| Spec scenario | Probe (task) | Expected | Observed | Verdict |
|---|---|---|---|---|
| DCR off by default | `probe_dcr.py --expect disabled` (8.1) | `registration_endpoint` absent; POST answers the disabled-error 404 | metadata advertised no endpoint; `404 {"error":"invalid_request", "error_description":"dynamic client registration is not enabled on this gateway; clients register by presenting a client-id metadata document URL, or are pre-registered by the operator"}` | **green** |
| The endpoint is advertised only while enabled | `probe_dcr.py --expect enabled` (8.2) | metadata advertises it; body with `redirect_uris` accepted | `registration_endpoint: http://localhost:8090/dial/register`; `201` with a client id | **green** |
| A registration records only what a public client needs | same (8.2) | id, redirect URIs, name, issued-at; **no secret** | see the response shape below — no `client_secret`, no `registration_access_token` | **green** |
| (refusal branch) a registration without `redirect_uris` | `probe_dcr.py --expect enabled` (8.2) | plain-language refusal | `400 {"error":"invalid_request","error_description":"redirect_uris is required and must list at least one URI; without it no authorization request could be validated for this client"}` | **green** |
| Unregistered redirect URI | `probe_dcr.py --authorize-expect rejected` (8.3, negative control) | rejected, no redirect | `400 {"error":"invalid_request","error_description":"redirect_uri is not one this client registered"}` | **green** |
| A registered redirect URI resolves the DCR client | `probe_dcr.py --authorize-expect accepted` (8.3) | flow starts, redirect to the identity provider | `302 -> keycloak:8443` | **green** |
| Registration persists across restart | `probe_dcr.py --authorize-expect accepted` after `restart` (8.4) | accepted with no re-registration; store unchanged | `302 -> keycloak:8443`; store sha256 byte-identical before and after | **green** |
| Store dormant while disabled, restored on re-enable | `--expect disabled --authorize-expect accepted` (8.5) | rejected while off; accepted again after re-enable | off: `400 {"error":"invalid_client",…}`; after re-enable: `302 -> keycloak:8443` again, store sha256 unchanged throughout | **green** |
| First use end to end as the registered client | `probe_end_to_end.py --client-id <dcr>` (8.3) | live tool call with the minted token | discovery, authorize, Keycloak login, gateway callback and the upstream interstitial all reached; **the live tool call was not reachable** (see below) | **blocked — external precondition**, then **green** once both blockers cleared — see the task-8.3 section at the end of this file |

## 8.1 — the negative control, first

Run against the composed stack as group 7 left it, `DCR_ENABLED` unset:

```
=== the authorization-server metadata (/.well-known/oauth-authorization-server) ===
  registration_endpoint  <absent>
=== POST /dial/register with the flag off ===
  status                 404
  error                  invalid_request
  error_description      dynamic client registration is not enabled on this gateway;
                         clients register by presenting a client-id metadata document
                         URL, or are pre-registered by the operator
  verdict: green — no endpoint advertised, disabled-error answered
```

The same body the enabled branch accepts was posted, so the 404 is attributable to the
flag and not to the request.

## 8.2 — the enabled surface, the refusal branch, and the registration

```
=== the authorization-server metadata ===
  registration_endpoint  http://localhost:8090/dial/register
  verdict: green — the registration endpoint is advertised

=== the refusal branch: POST /dial/register with no redirect_uris ===
  status                 400
  error                  invalid_request
  error_description      redirect_uris is required and must list at least one URI; …

=== the registration: POST /dial/register with a loopback redirect_uri ===
  client_id              <redacted len=22 sha256=07a0e180943b>
  client_name            "group8-dcr-probe"
  redirect_uris          ["http://127.0.0.1:8768/callback"]
  auth method            "none"
  grant_types            ["authorization_code"]
  response_types         ["code"]
  client_id_issued_at    2026-10-19T08:06:36+00:00
  recorded               dcr_client.json (gitignored)
  verdict: green — one registration accepted, no secret issued
```

### The store it wrote

Read inside the container (the host path is mode 600 owned by uid 10001, so the host
account cannot read it — which is the intended shape). The client id is shown as the
same redacted handle the probe prints, per this file's capture rule: it is an identifier
rather than a secret — nothing on this path issues one — but it is also not repository
content, and `.gitignore` blocks the scratch file that holds it for exactly that reason.
The record's *shape* is the evidence here, not the id's value:

```
$ wsl -e docker exec ai-dial-mcp-gateway-mcp-signin-gateway-1 \
    stat -c '%a %U %s bytes' /data/dcr-registrations.json
600 gateway 235 bytes

{
  "<redacted len=22 sha256=07a0e180943b>": {
    "client_id":      "<redacted len=22 sha256=07a0e180943b>",
    "client_name":    "group8-dcr-probe",
    "created_at":     "2026-10-19T08:06:36+00:00",
    "redirect_uris": [
      "http://127.0.0.1:8768/callback"
    ]
  }
}
```

Exactly one record; the four fields the design limits a record to; **no secret field of
any kind**; mode `600`; and `ls -a /data` showed no leftover temporary file from the
save.

## 8.3 — the flow as the DCR-registered client

The negative control ran before the positive claim, with the same client id and a
redirect URI **differing in path, not in port** — a registered loopback entry matches a
port-varied request by design (task 3.11), so a port-only control would have passed for
the wrong reason:

```
=== an authorization request as the registered client ===
  redirect_uri           http://127.0.0.1:8768/not-registered
  status                 400
  body                   {"error":"invalid_request",
                          "error_description":"redirect_uri is not one this client registered"}
  verdict: green — refused, as required for the control
```

Accepted case, on the registered URI:

```
  redirect_uri           http://127.0.0.1:8768/callback
  status                 302
  location host          keycloak:8443
  verdict: green — accepted, the registration resolved
```

### The chain the registered client walked

`PYTHONUTF8=1 python scripts/probe_end_to_end.py --client-id <the DCR client id>
--callback-port 8768`:

```
=== step 1: discovery through the front door ===
  resource  http://localhost:8090/dial/notion/mcp
  servers   ["http://localhost:8090"]
=== step 2: /dial/authorize through the front door ===
  status    302 -> keycloak:8443
  client    dial-mcp-proxy
  scope     profile email
=== step 3: the identity provider's login form ===
  credentials submitted -> HTTP 302
=== step 4: the gateway's callback ===
  -> rendered the attribution interstitial for toolset notion, client group8-dcr-probe
```

Steps 1–3 are green: discovery resolved the front door as the authorization server, the
**DCR-registered client id was accepted**, and the identity-provider leg completed the
Keycloak login. Step 4 reached the gateway's own callback and rendered the upstream
**attribution interstitial** — the boundary of what this probe can drive.

### Why the last leg did not run, and what it is not

The interstitial's continue-URL is Notion's consent page, which is a JavaScript
application: fetched directly it answers `200` with a boot-strap document and no form and
no redirect to drive:

```
upstream authorize -> 200
page text:  Notion !function(){var a=!1;try{a="true"===window.localStorage.getItem(
            "boot:gate:async_load_airgap_in_prod")}catch(e){…}
```

Completing it needs a signed-in Notion account and a human clicking approve. The test
user's stored credential had been **removed before this session** — Core's own log
records the sign-out, which is the environment state this pass inherited and not an
effect of anything run here:

```
2026-10-19T07:58:12Z POST /v1/ops/toolset/signout
  "Deleting resource credentials for resourceId=toolsets/config/notion."
  "… finished. Result: true"          user.id=3a0d60f4-…
```

Re-read after every attempt, the status stayed `user_level_auth_status: SIGNED_OUT`
(73 minutes after the sign-out, and again after each recreate).

This is **not** a DCR failure and not a gateway failure. The gateway's own short-circuit
is working exactly as specified — a user with no stored credential is taken to the
upstream consent, which is the designed path — and this leg is green in
`evidence/group-6.md` for a pre-registered client, on the same host, when the credential
was present. What is missing is the one-time human approval, an external precondition
this session could not supply.

**A second, independent block sits beyond it.** Diagnosed in parallel with this group and
recorded as `evidence/finding-empty-upstream-redirect.md`: the interstitial's
`method="get"` form carries a parameter-bearing `action` but **no successful form
controls**, so the browser replaces the action's query with an empty entry list and
navigates to a bare `…/authorize?`. Even with a human at the keyboard the consent screen
would be reached without its parameters. That defect is live in the tree this group ran
against and is scheduled as task 4.8; it does not change any verdict here — the DCR
surface, the registration, its durability and its dormancy are all independent of the
interstitial — but it is why the flow's last leg is unreachable for **any** client on the
current tree, DCR-registered or pre-registered, with or without a stored credential. Its
own evidence file carries the reproduction, the browser-level controls, and the spec-gate
verdict.

**Not claimed:** a live toolset call as the DCR-registered client. Recorded as blocked,
deliberately, rather than inferred from the pre-registered client's green result: the
claim under test is that a **DCR-registered** client id reaches a live call, and the
difference between the two clients is the thing 8.3 exists to measure.

**Superseded:** both blockers cleared, and the claim above was then measured and is
green — see **Task 8.3 — the flow completed as the DCR-registered client** at the end of
this file. This paragraph describes the state of the blocked pass, not the current
verdict.

## 8.4 — restart persistence

```
store before  sha256  42211e2269b1a629ec11689f04c98ded0a85c1b08d94b6405b99639a531239d1
$ wsl -e docker compose restart mcp-signin-gateway
$ wsl -e docker compose restart mcp-signin-router
$ curl http://localhost:8090/healthz        -> 200
store after   sha256  42211e2269b1a629ec11689f04c98ded0a85c1b08d94b6405b99639a531239d1

=== an authorization request as the registered client ===
  status                 302
  location host          keycloak:8443
  verdict: green — accepted
```

No re-registration between the restart and the request. The store file is **byte-identical**
across the restart, so the registration was loaded from disk rather than recreated.

## 8.5 — the re-disable, and the dormant store

`DCR_ENABLED` removed from `.env`, gateway recreated, router restarted, `/healthz` polled
to `200`. The disabled-error returns and **the store is preserved**:

```
  registration_endpoint  <absent>
  status                 404
  error_description      dynamic client registration is not enabled on this gateway; …
  store sha256           42211e2269b1a629ec11689f04c98ded0a85c1b08d94b6405b99639a531239d1
                         (unchanged), mode 600, 235 bytes
```

The dormant-store semantics were then measured **on the authorization path too**, which
is where dormancy is actually observable — a stored client id must stop resolving while
the flag is off. Two requests with the same client id and URI, expecting opposite
outcomes:

```
--- while disabled, the client's own registered URI: rejected ---
  status                 400
  body                   {"error":"invalid_client",
                          "error_description":"this client id is not registered with the gateway"}
  verdict: green — the store is dormant

--- after re-enabling DCR and recreating ---
  status                 302
  location host          keycloak:8443
  verdict: green — the registration resolved again, no re-registration
  store sha256           42211e2269b1a629ec11689f04c98ded0a85c1b08d94b6405b99639a531239d1
                         (still byte-identical)
```

The store's hash is identical through off → dormant → on, so the round trip changed
nothing on disk. That is the "preserved unchanged while disabled" scenario and its
"resolves again on re-enable" half, both measured.

The deployment was then returned to the committed configuration (see the end state).

## Defect found

| Finding | Where | Class |
|---|---|---|
| The store's atomic save fails at `chmod` on the compose file's Windows-host bind mount, so every registration is refused | `openspec/changes/build-mcp-sign-in-gateway-poc/evidence/finding-dcr-store-mount-chmod.md` | deployment-blocking, spec/def-cycle candidate |

Symptom in one line: with `DCR_ENABLED=true` and the compose file as committed, a
registration the endpoint's validation accepts answers
`400 "the registration could not be written to the gateway's store at /data/dcr-registrations.json"`.
Root cause: `gateway/store.py`'s `_save()` calls `temporary.chmod(0o600)` before
`replace()`, and the `./data:/data` bind mount reaches this deployment's container over
**DrvFs** (9p), where `chmod` returns `EPERM`; the file mode D11 requires cannot be set on
that filesystem at all. It is invisible to the unit suite because those tests run on the
host filesystem, and it survived group 7's compose-boot gate because that gate starts the
stack with `DCR_ENABLED` at its default **off**, so the save path is never entered.

No behavioral fix was applied: the change is outside this group's mechanical scope and
the fix has a spec question in it (whether the owner-only mode is a guarantee or a
best-effort hardening measure), so it goes to the defect cycle with proposed options
recorded in the finding.

## Deliberate limits of this group

- **The live tool call was not run.** Stated above with its reason; not inferred from the
  pre-registered client's green result.
- **The green captures used a verification-only mount.** The feature was isolated from
  the mount defect with a temporary compose override, deleted afterwards. The deployment
  end state uses the committed bind mount exactly as group 6 left it.
- **No harness is involved.** Group 9 owns the five harness-facing acceptance criteria;
  this group measures the DCR surface and the DCR client's flow.
- **The other DCR store scenarios are unit-tier, and stay there.** Persist-before-response,
  corrupt-store startup refusal, lost-store self-heal, and the registration cap are proven
  by group 3.6's tests; group 8's charter is the live surface, and this pass did not
  re-derive them.

## End state

| Item | State |
|---|---|
| `DCR_ENABLED` | unset in `.env` — the default (off) |
| `.well-known/oauth-authorization-server` | advertises no `registration_endpoint` |
| `POST /dial/register` | the documented disabled-error, `404` |
| Store file | **not present on the committed bind mount** — that mount cannot write one (see the defect), so the deployment starts with an empty store, exactly as a first run would |
| `mcp-signin-gateway` | up, healthcheck healthy |
| `mcp-signin-router` | up, healthy; `/healthz` `200` through `http://localhost:8090` |
| Compose file | unmodified; the temporary override deleted |
| Gateway configuration | as group 6 left it |
| `dcr_client.json` | gitignored scratch, present (the registered client id) |

**Observation on the host's port forwarding (not this change's).** Some time after the
last probe, Windows→WSL `localhost` forwarding for **all** ports stopped on this host —
`curl http://localhost:8090/healthz` and `http://localhost:8081/v1/user/info` both failed
to connect from Windows while both answered normally from inside WSL
(`in-wsl 8090: 200`), and the direct WSL address answered from Windows
(`http://<host-address>:8090/healthz -> 200`). Both services reported healthy throughout.
Every capture in this file was taken **before** that, with forwarding working, so no
verdict depends on it, and the end state was re-verified from inside WSL for this reason.
It is recorded because the failure looks identical to a dead stack and is not one. Both
probes take `--origin`, so they run against the WSL address unchanged — the end-state
re-check above was taken that way.
| Repository | no credential, token, or key committed; `git status` clean of this group's artifacts |

## Gates after the pass

Run from `.venv/Scripts` with `PYTHONUTF8=1`. See `evidence/gates.md` for the tier
definitions.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | all files formatted |
| `mypy` (strict) | Success: no issues found |
| `pytest -q` | 328 passed, 1 skipped |
| `bandit -c pyproject.toml -r gateway` | No issues identified |
| `pip-audit` | No known vulnerabilities found |

Nothing was committed.

## Task 3.12 — the composed-stack re-run (the gate gap closed)

The defect cycle for `finding-dcr-store-mount-chmod.md` closes its gate gap here. The 8.2
registration checks above ran **with a temporary ext4 override** — the store on a
WSL-native path — because the committed bind mount could not be written to at all. The
3.12 code fix (the tolerant `chmod` in `gateway/store.py`'s `_save()`) removes that need:
every capture below is taken on the **committed `./data:/data` bind mount as this host
mounts it**, with the compose file unmodified and no override in play.

### The two runs, and why there are two

The first attempt was halted mid-run by the host-wide Windows→WSL localhost forwarding
outage recorded at the end of the group-8 section: `DCR_ENABLED=true` was set and the
containers recreated, but the surface answered only from inside WSL, so no probe ran. The
host then ran `wsl --shutdown` and brought both stacks back; the run resumed against the
restarted stack, forwarding green (`/healthz` `200` from Windows).

**The resumption exposed a deployment fact worth recording.** `docker compose up
--force-recreate` recreates a container from the **existing image** — it does not rebuild
one. The first recreation after the code change therefore ran the *old* image, and the
registration failed with the finding's original error, verbatim:

```
HTTP 400 {"error":"invalid_request",
 "error_description":"the registration could not be written to the gateway's store at
 /data/dcr-registrations.json; no registration was created. An administrator should check
 that the volume is writable."}
```

This was not the defect surviving the fix — it was the fix not being in the running
container (`grep chmod /opt/venv/.../gateway/store.py` inside the container showed the
unguarded line at 178; the source is baked into the image at build time, per the
`Dockerfile`). `docker compose build mcp-signin-gateway` then `up -d --force-recreate`
produced the green run below. Under `--force-recreate` alone, the compose-boot gate is
measuring the previously built image, not the working tree — a fact for whoever runs the
gates next, and the reason the first attempt's result was discarded rather than recorded
as a verdict.

### The live captures (DCR on, committed bind mount, image rebuilt from the working tree)

All commands from the repository root with `PYTHONUTF8=1`, against `http://localhost:8090`
from Windows — forwarding working.

| Check (task 3.12 / 8.2) | Result |
|---|---|
| Flat AS metadata advertises the registration endpoint | **green** — `registration_endpoint: http://localhost:8090/dial/register` at `/.well-known/oauth-authorization-server` |
| The refusal branch (no `redirect_uris`) is still refused | **green** — `400`, `invalid_request`, `redirect_uris is required and must list at least one URI; without it no authorization request could be validated for this client` |
| **`POST /dial/register` on the DrvFs mount succeeds** — the check the defect failed | **green** — `201` with `client_id` (redacted: `len=22 sha256=e828b246a0b0`), `client_name: "group8-dcr-probe"`, `redirect_uris: ["http://127.0.0.1:8768/callback"]`, `token_endpoint_auth_method: "none"`, `grant_types: ["authorization_code"]`, `response_types: ["code"]` |
| No secret issued | **green** — no `client_secret`, no `registration_access_token` in the response |
| **The gateway log carries the mode warning naming the path** | **green** — see the capture below |
| **The store file gains exactly one record** | **green** — `data/dcr-registrations.json`, 235 bytes, one key; no temporary file beside it (the directory holds `.gitkeep` and the store, nothing else) |
| The record holds no secret material | **green** — exactly the four fields: `client_id`, `client_name`, `created_at`, `redirect_uris` |
| **Restart persistence over the same mount** (8.4's shape) | **green** — `--force-recreate mcp-signin-gateway` + `restart mcp-signin-router`, then an authorization request as the same client id with its registered redirect URI: `302` to `keycloak:8443`, no re-registration in between. The store file's SHA-256 is **unchanged** by the restart (`dda2465af05c…`), so the record was read, not rewritten |
| Negative control for the authorization request | **green** — the same client id with a redirect URI it never registered (`/not-registered`) is refused `400`, `redirect_uri is not one this client registered`. A pass above cannot come from a gateway that accepts anything |
| **Return to the default state** | **green** — `DCR_ENABLED` removed from `.env`, gateway recreated, router restarted, both `Up (healthy)`, `/healthz` `200`; metadata advertises **no** `registration_endpoint`; `POST /dial/register` answers the documented disabled-error `404`. The store file is **preserved unchanged** (same hash), so re-enabling restores the registration as it was (8.5's dormant-store semantics) |

The mode warning, as the container logged it on the successful save:

```
the registration store at /data/dcr-registrations.json could not be given its owner-only
file mode ([Errno 1] Operation not permitted:
'/data/dcr-registrations.json._9dbfqqe.tmp'); the save continues and the file keeps the
mode its filesystem assigns. Where the volume enforces POSIX modes the file would be
readable only by its owner; this filesystem does not, so every file on the mount is
equally readable and the store's protection is the host or volume owner's boundary.
```

This is the ruling's shape exactly: the mode failure is named, the save proceeds, and the
registration is not refused. The record's four fields and the client id are absent from
the message — it carries the path and nothing else.

### Verdict

**All green.** The defect that reached group 8 no longer blocks a registration on the
committed bind mount, the store persists and survives a restart on that mount, and the
mode failure is now a logged warning rather than a refusal. **The D-A finding's
live-verification open item is CLOSED.**

### Gates after this pass

Run from `.venv/Scripts` with `PYTHONUTF8=1`.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 98 files already formatted |
| `mypy` (strict) | Success: no issues found in 35 source files |
| `pytest -q` | 335 passed, 1 skipped |
| `bandit -c pyproject.toml -r gateway` | Total issues (all severities): 0 |
| `bandit -c pyproject.toml -r gateway scripts` | 5 findings, all pre-existing in probe/spike instruments (see `gates.md`) |
| `pip-audit` | No known vulnerabilities found |

Nothing was committed.

## Task 8.3 — the flow completed as the DCR-registered client (both blockers cleared)

The 8.3 leg this group left **blocked** is now **green**. Both blockers named at the end
of the group's own section are gone: the interstitial defect is **fixed** (task 4.8 — the
page continues itself by navigation, with the delivery guard), and the test user's stored
Notion credential is **established** again, so the flow's signed-in short-circuit applies
and no upstream consent is needed.

Every capture below is redacted at capture time, against the committed stack with the
compose file unmodified (`./data:/data`, as this host mounts it) and the image rebuilt
from the working tree at `a6e71c7` — `--force-recreate` alone re-runs the previously built
image, the fact task 3.12 recorded.

### The precondition, re-measured first

```
$ PYTHONUTF8=1 python scripts/spike_establish_credential.py
current status:
  user_level_auth_status = SIGNED_IN
  global_auth_status     = SIGNED_OUT
already signed in; the credential precondition is established (silent path)
```

The helper's silent path returned without touching the browser: the user-level credential
is present, which is what makes the signed-in short-circuit in `complete_identity_leg`
reachable. This is the environment state the previous pass lacked.

### Enable DCR, and the dormant registration resolves again

`DCR_ENABLED=true` in `.env`, `docker compose build mcp-signin-gateway`,
`up -d --force-recreate mcp-signin-gateway`, `restart mcp-signin-router`, then `/healthz`
through 8090 (`200` before any probe). The registration written in the 3.12 pass — and
preserved dormant through the group's disable/re-enable round trip — is still the only
record:

```
=== the authorization-server metadata (/.well-known/oauth-authorization-server) ===
  registration_endpoint  http://localhost:8090/dial/register
  verdict: green — the registration endpoint is advertised
=== the refusal branch: POST /dial/register with no redirect_uris ===
  status                 400
  error                  invalid_request
  error_description      redirect_uris is required and must list at least one URI; …
  verdict: green — the registration was refused
=== an authorization request as the registered client ===
  redirect_uri           http://127.0.0.1:8768/callback
  status                 302
  location host          keycloak:8443
  verdict: green — accepted, the registration resolved
```

No re-registration between the enable and the request. The store file's SHA-256 is
`dda2465af05cbbf0dad476f26f4cd57b9b3d04d0ca4557e9270bd2f047b1f0c0` — the same hash this
file recorded for the 3.12 pass — so the client id the flow runs as is the **dormant
registration the store preserved**, not a fresh one. The record was read, not rewritten:

```
$ sha256sum data/dcr-registrations.json     # before and after every probe below
dda2465af05cbbf0dad476f26f4cd57b9b3d04d0ca4557e9270bd2f047b1f0c0  dcr-registrations.json
$ docker exec … ls -a /data
.  ..  .gitkeep  dcr-registrations.json      # one record, no temporary file
```

### The completed chain, as the DCR-registered client

`PYTHONUTF8=1 python scripts/probe_end_to_end.py --client-id <dcr client id, redacted
len=22 sha256=e828b246a0b0> --callback-port 8768` — the client id and the callback port
are the ones the dormant registration holds, so the whole chain runs as **that** client:

```
=== step 1: discovery through the front door ===
  resource  http://localhost:8090/dial/notion/mcp
  servers   ["http://localhost:8090"]
=== step 2: /dial/authorize through the front door ===
  status    302 -> keycloak:8443
  client    dial-mcp-proxy
  scope     profile email
=== step 3: the identity provider's login form ===
  credentials submitted -> HTTP 302
  hop 2: HTTP 302
  hop 3: reached the client redirect URI
=== step 4: the gateway's callback ===
  params    ['code', 'iss', 'state']
  state     round-tripped
  code      <redacted len=1220 sha256=c82d64dd2b59>
=== step 5: /dial/token ===
  status    200
  access    <redacted len=977 sha256=1cf8cc84ca52>
    iss      "http://localhost:8090"
    sub      "3a0d60f4-fad0-4164-8903-20e5adf408c3"
    aud      ["http://localhost:8090/dial/notion/mcp", "dial-mcp-proxy"]
    roles    ["admin"]
    project  "proj-alpha"
  refresh   present
=== step 6: a live tool call through the front door (/dial/notion/mcp) ===
  status    200
  tools     65
  first     ["notion-search", "notion-memory-search", "notion-get-tool-access"]

=== smoke verdict ===
  the sign-in completed through the front door and the token it minted
  authenticated a live tool call: the deployment is wired end to end
```

Note the shape of step 4: the callback arrived with **`code`, `iss` and `state`** and the
state round-tripped. That is the D12 fix working — the interstitial delivered its request
by navigation, so the upstream leg was reached with every parameter and the callback the
flow needed actually came back. In the blocked pass this leg never got past the
interstitial's page.

**This is the claim 8.3 exists to measure, and it is no longer inferred from the
pre-registered client.** The client id presented at `/dial/authorize` is the DCR
registration's — resolved from the gateway's own store, with its registered redirect URI —
and it is that flow which minted the token (`sub` the test user, `roles`, `project`) and
that token which Core accepted for a live `tools/list` (200, 65 tools) through
`/dial/notion/mcp`.

### The return to the default state

`DCR_ENABLED` removed from `.env` (the file restored to the copy taken before this pass),
gateway recreated, router restarted, `/healthz` polled to `200`:

```
  registration_endpoint  <absent>
POST /dial/register     → 404  invalid_request
  error_description      dynamic client registration is not enabled on this gateway;
                         clients register by presenting a client-id metadata document
                         URL, or are pre-registered by the operator
an authorization request as the (now dormant) client:
  400 {"error":"invalid_client",
       "error_description":"this client id is not registered with the gateway"}
  store sha256           dda2465af05cbbf0dad476f26f4cd57b9b3d04d0ca4557e9270bd2f047b1f0c0
                         (unchanged, 235 bytes, one record, no temporary file)
```

`mcp-signin-gateway` and `mcp-signin-router` both `Up (healthy)`; the compose file is
unmodified; the store is dormant and preserved exactly as 8.5 left it.

### Verdict

**Task 8.3 green.** The authorization flow completed as the DCR-registered client through
the signed-in short-circuit, `/dial/token` minted a token for the test user, and that
token authenticated a live toolset call through the front door. **No finding is raised by
this pass.**

### Gates after this pass

Run from `.venv/Scripts` with `PYTHONUTF8=1`. See `evidence/gates.md` for the tier
definitions.

| Gate | Result |
|---|---|
| `ruff check` | All checks passed |
| `ruff format --check` | 102 files already formatted |
| `mypy` (strict) | Success: no issues found in 36 source files |
| `pytest -q` | 337 passed, 1 skipped |
| `bandit -c pyproject.toml -r gateway` | Total issues (all severities): 0 |
| `pip-audit` | No known vulnerabilities found |

Nothing was committed.
