# Evidence — the fix implemented, its negative controls, and the gate ladder

Implementer record for `fix-dcr-response-conformance`. Gate outputs below are the
verbatim results of the commands named; the review gates and the commit are the
orchestrator's, and are not claimed here.

## 1.1 — the conversion at the response site

`gateway/routes.py` gained `_issued_at(record)`, called from the one place the registration
response is assembled, so both branches (new registration, idempotent re-registration)
pass through it. It parses the record's stored `created_at` and returns
`int(datetime.fromisoformat(created_at).timestamp())` — the stored instant, never a second
`datetime.now()`.

`gateway/store.py`'s `created_at` gained a comment naming it the store's at-rest format and
pointing at the response site as the only conversion point. The record's shape and the
write path are untouched (`git diff gateway/store.py` shows five comment lines only).

## 1.2 — regression tests, and the negative controls that prove they can fail

Four tests in `tests/test_store.py`, all in the accepted-registration region:

| test | asserts |
|---|---|
| `test_the_registration_response_answers_an_epoch_number_for_the_stored_instant` | the member is an `int`, not a `bool`, and equals the stored record's `created_at` as epoch seconds |
| `test_the_response_answers_the_stored_instant_and_not_the_time_of_the_request` | the served value is the stored instant and **not** the time of the request |
| `test_the_issued_at_assertion_rejects_the_pre_fix_string` | the suite's own helper refuses the pre-fix ISO-8601 string |
| `test_the_idempotent_branch_answers_the_stored_instant_as_a_number` | the re-registration branch answers the *first* registration's instant, as a number |
| `test_re_registering_an_existing_client_id_answers_its_stored_instant_as_a_number` | the idempotent branch at store level, where it is actually reachable |

**A1 — the idempotent-branch mechanism, stated explicitly.** The branch is **not
wire-reachable**: the route calls `new_client_id()` on every request, so no real request
can re-register an existing id. It is covered two ways, because each covers a different
caller:

- **Route level**: `monkeypatch.setattr(gateway.routes, "new_client_id", lambda: RE_REGISTERED_CLIENT_ID)`
  pins the id the route mints, so the second POST to `/dial/register` is a genuine
  re-registration through the response site — this is what makes the *response site's*
  conversion covered on this branch, which is the property D1 turns on.
- **Store level**: `RegistrationStore.add()` is called twice with the same id, asserting
  the second call returns the existing record with its original `created_at` and redirect
  URIs — the guarantee a future caller inherits.

**The same-instant property is made decisive by pinning the store's clock.**
`created_at` is written with `timespec="seconds"`, so against the real clock a response
that sampled its own `now()` would usually land in the *same second* as the record and pass
by coincidence. The two route-level tests patch `gateway.store.datetime` to a clock pinned
to `2020-01-02T03:04:05Z` (`_PinnedStoreClock`), so the only value satisfying the assertion
is the stored instant.

**Negative control 1 — the pre-fix behaviour.** `gateway/routes.py` temporarily restored to
the pass-through (`record["created_at"]` verbatim):

```
FAILED tests/test_store.py::test_the_registration_response_answers_an_epoch_number_for_the_stored_instant
FAILED tests/test_store.py::test_the_issued_at_assertion_rejects_the_pre_fix_string
FAILED tests/test_store.py::test_the_idempotent_branch_answers_the_stored_instant_as_a_number
3 failed, 1 passed, 42 deselected
```

**Negative control 2 — a plausible wrong fix: a second `now()` at the response site.**
This is the control that matters most, because it is the fix a reader would reach for and
it passes every type assertion. `_issued_at` temporarily returning
`int(datetime.now(UTC).timestamp())`:

```
FAILED tests/test_store.py::test_the_registration_response_answers_an_epoch_number_for_the_stored_instant
FAILED tests/test_store.py::test_the_response_answers_the_stored_instant_and_not_the_time_of_the_request
FAILED tests/test_store.py::test_the_idempotent_branch_answers_the_stored_instant_as_a_number
3 failed, 43 passed, 1 skipped
```

Both controls were reverted; `gateway/routes.py` ends holding
`int(datetime.fromisoformat(created_at).timestamp())`.

## 1.3 — the probe's permanent typed sweep

`scripts/probe_dcr.py`'s `register()` now calls `check_typed_sweep(document)` where it used
to print the member and assert nothing. The sweep checks every RFC 7591 §3.2.1 response
member's JSON type — `client_id` string, `redirect_uris` array of strings, `client_name`
string, `token_endpoint_auth_method` string, `grant_types` and `response_types` arrays of
strings, `client_id_issued_at` a whole JSON number — plus the absence of a required member
and the presence of a member that is no RFC 7591 response member at all. `bool` is refused
at the number member explicitly (`bool` is an `int` in Python). Its negative control is a
hand-built conformant document, checked first; a violation there raises
`control_is_broken`, so a live violation can never be confused with a broken instrument.

**Live, against the composed stack's front door (`http://localhost:8090/dial/register`),
after the fix:**

```
=== the typed sweep: RFC 7591 §3.2.1 response members ===
  negative control       no violation
  client_id              str    <redacted len=22 sha256=fff0c3b3941f>
  client_id_issued_at    int    1792498125
  client_name            str    "group8-dcr-probe"
  grant_types            list   ["authorization_code"]
  redirect_uris          list   ["http://127.0.0.1:8768/callback"]
  response_types         list   ["code"]
  token_endpoint_auth_method str    "none"
  verdict: green — every member carries its RFC 7591 §3.2.1 JSON type
```

**Live, against the pre-fix container (before the rebuild), and against a deliberately
broken build** — the probe fails non-zero in both cases, so the instrument distinguishes:

| build | `client_id_issued_at` line | exit |
|---|---|---|
| pre-fix container | `str    "2026-10-20T12:00:30+00:00"  VIOLATION` | 1 |
| `_issued_at` deliberately returning the string | `str    "2026-10-20T12:19:22+00:00"  VIOLATION` | 1 |
| fixed | `int    1792498125` | 0 |

The failure message names the member and its type, and says why the whole document is lost
client-side: `the response document does not conform to RFC 7591 §3.2.1 — client_id_issued_at:
expected number, got str. A schema-strict client rejects the whole document on a type
mismatch, so the registration is lost client-side even though the gateway answered 201`.

The broken build was reverted and the image rebuilt from the fixed tree.

## 1.4 — the operational prune of the live store

`data/dcr-registrations.json` is the container's live state (bind-mounted at `/data`). Eight
throwaway diagnostic records were removed — the four the finding left (`troubleshoot-*` ×3
with loopback callbacks `8769|8770|8771`, plus the unnamed `J63ZuPU5wFhMkoCb38mPkQ` on
`8772`) and four this session's verification runs added (`group8-dcr-probe` on `8768`, and
the one-off `fix-verify-issued-at`). Kept: the **five Cursor registrations** and the
original **`group8-dcr-probe`** (`gxTIV84luPqhX0dG2BdgJg`) — six records, the intended end
state.

The rewrite is a JSON round-trip with `indent=2, sort_keys=True`, which was verified
byte-identical to the store's own save format before the edit, and the kept records were
asserted byte-identical to their pre-prune text. Verified after a `--force-recreate`:

```
container sees 6 records
  5O_wQNpsvku21MeIki0pDw Cursor
  AkaDRPhBlHM17exhkQiQnw Cursor
  HdvpOItd8DFojtxxj5PQxA Cursor
  fGvtRY2OEKkUzks4Ua37pg Cursor
  gxTIV84luPqhX0dG2BdgJg group8-dcr-probe
  yu0tNpWngBh95nsHM99-vg Cursor
```

The store loads (the gateway would refuse startup on a store it cannot parse), and a kept
Cursor registration still resolves: `GET /dial/authorize` for
`yu0tNpWngBh95nsHM99-vg` with its registered `cursor://` redirect URI answered `302` to the
identity provider. The gateway and router are both `healthy`.

## 1.5 — the gate ladder

Every command run from `.venv/Scripts` with `PYTHONUTF8=1`:

| gate | result |
|---|---|
| `ruff check` | `All checks passed!` |
| `ruff format --check` | `118 files already formatted` |
| `mypy` (strict, `gateway` + `tests`) | `Success: no issues found in 38 source files` |
| `pytest -q` | `387 passed, 1 skipped` (baseline before this change: 382 passed, 1 skipped) |
| `bandit -r gateway` | `Total issues (by severity): High: 0, Medium: 0, Low: 0` |
| `pip-audit` | `No known vulnerabilities found` |
| Trivy (`wsl -e trivy fs --skip-db-update --scanners vuln,secret,misconfig`) | no vulnerabilities and no misconfigurations in repository content |
| compose-boot | `docker compose build` then `up -d --force-recreate`; gateway and router both report `healthy`; `GET /healthz` through the front door answers `{"status":"ok"}` |

**Trivy note.** The first Trivy run scanned `.venv` and died on a traversal deadline over
byte-compiled files (a scan error, not a finding). Re-run with `.venv`, `.git`, and `data`
excluded: no vulnerabilities, no misconfigurations. The secret scanner's two `MEDIUM`
findings are JWT fixtures under `.secrets/spike-token-*.jwt` — untracked
(`.gitignore:25` ignores `.secrets/`) and never committed; they are the spike's own
deliberately-wrong-issuer and unknown-key tokens.

**The two review gates from 1.5 are not performed here.** The security review on the diff
(its job being to falsify the no-security-impact claim) and the independent review are
separate reviewer subagents, and nothing is committed — both are the orchestrator's to run.

## 2.1 — release notes

`release-notes-draft.md` carries both sections. Its user-facing compatibility sentence was
found to state a false inference and was corrected (advisory A2, below).

## The two review advisories

**A1 — the idempotent-branch test mechanism** is stated in §1.2 above and in the tests' own
docstrings: route level by pinning `gateway.routes.new_client_id`, store level by calling
`RegistrationStore.add` twice, and why the branch is not wire-reachable.

**A2 — the compatibility sentence.** `proposal.md`'s Impact section claimed that "a harness
holding a client id from a rejected response can connect immediately". That is not true and
could not be: a rejecting harness discards the **entire** response, client id included (that
is what the Cursor log shows — the failure is document-level), so it never held a usable
client id. The true statement, now in both `proposal.md` and `release-notes-draft.md`: the
defect-era record answers a conformant document as soon as the fix runs, and the recovery
the harness actually sees is that its next registration succeeds and the retry loop ends.

## Live verification — a fresh registration through the front door

```
HTTP 201
client_id_issued_at      1792497971 -> int
raw document (verbatim):
  {"client_id": "5pT1TckHBjMICjH2drX9Ww", "redirect_uris": ["http://127.0.0.1:8791/callback"],
   "client_name": "fix-verify-issued-at", "token_endpoint_auth_method": "none",
   "grant_types": ["authorization_code"], "response_types": ["code"],
   "client_id_issued_at": 1792497971}
stored created_at        '2026-10-20T12:06:11+00:00'
epoch of stored          1792497971
same instant             True
stored is still ISO-8601 True
record fields            ['client_id', 'client_name', 'created_at', 'redirect_uris']
```

The member is a JSON number on the wire and the same instant the store recorded, while the
stored record keeps its ISO-8601 string and its four fields — the Cursor-class reject
(`expected "number", received "string"` at this path) has nothing left to fire on.

Redaction: no token, code, key, or secret appears above. Client ids are shown as their
store keys (identifiers a harness caches, not credentials) or as a redacted handle; the
only value printed in full is the issued-at number, which is a timestamp.
## General review gate (round 1) — needs-changes; both gates' verdicts

Security gate: **pass** — the no-impact claim survived falsification (128-bit
server-minted ids make the guard operator-facing only; no leak; invariants
untouched; three informational notes recorded).

General gate: **needs-changes**:
1. **(medium)** The new blanket RFC 7591 §3.2.1 conformance sentence contradicts
   the deliberately deferred `client_name: null` on the accepted name-less path
   (a present-but-null member fails §3.2.1's string type; the change's own probe
   sweep agrees; the design's "no spec line permits or forbids it" justification
   is undone by the sentence). Fix: reconcile the wording — carve the recorded
   open question into the requirement/scenario text explicitly, or tighten the
   sentence to what is delivered. Fixing the null emission stays out of scope.
2. **(low)** The idempotent-branch route-level test's docstring describes an
   earlier draft (real store clock / straddling seconds) — the code pins the
   store clock and asserts the literal epoch. Align the docstring.
3. Informational (not blocking, recorded): the guard's RegistrationError lands in
   the global 500 handler after persist (corrupted-store-only reachability; a
   future store-level field validation at load closes the class); the probe's
   deny-by-default member message slightly overclaims vs the RFC's optional
   members.

## Resolutions — general review gate, round 1 (author)

1. **(medium) resolved by carving the exception.** The requirement's conformance
   sentence now reads "…in every member it emits, excepting `client_name`, which is
   emitted as JSON `null` when the registration request carried no client name" —
   the epoch-number MUST is untouched and every other member stays under the blanket.
   The type scenario's THEN is aligned with the same exception so neither reads as
   contradicting the other. `design.md`'s open question is corrected: the carve-out
   is the spec line that now touches the emission — it keeps the conformance claim
   honest while judging nothing about whether `null` is the right answer. The
   sibling lines that still claimed "no spec line permits or forbids it"
   (`proposal.md`'s What Changes and Out of scope, `release-notes-draft.md`'s open
   question bullet) are aligned to the carve-out, so no artifact carries the undone
   justification. The null emission itself is unchanged — fixing it stays out of
   scope.
2. **(low) resolved.** The idempotent-branch route-level test's docstring now states
   the actual mechanism: the store's clock is pinned and the served member is
   asserted against the literal `STORED_INSTANT_EPOCH`, so a response-site `now()`
   cannot land on the value — the earlier draft's real-clock/straddling-seconds
   story is gone. No assertion or code line changed.
3. Informational items stand as recorded; no action taken (both name a future
   hardening, not a defect on this diff).

`openspec validate --changes --strict` green after the edits (`change/
fix-dcr-response-conformance` passed, 0 failed). The edited test re-run green
(`pytest -q tests/test_store.py -k idempotent_branch_answers_the_stored_instant`:
1 passed) with `ruff check` and `ruff format --check` clean on the touched file;
docstring-only, no assertion changed. Nothing is committed; the gates above remain
the orchestrator's to close.

## DCR field run (Cursor, 2026-10-20) — the fix verified in the field

The fix's own verification (§1.3, §1.4) ran against a probe and the front door. This
section records the **field** verification: the harness whose strict schema produced the
original finding — Cursor, a DCR-only MCP client — run against the gateway after the fix's
image was live, doing a full registration → authorization → token-exchange → connected-
session cycle with no operator intervention. Nothing was restarted or rebuilt for this run;
the evidence is the trail the running stack already wrote.

The gateway container (`ai-dial-mcp-gateway-mcp-signin-gateway-1`) started `12:22:08Z`,
holding the fixed image. Cursor's run is the `13:00:04Z` – `13:00:12Z` window; Cursor's own
log timestamps are local (UTC+3), so its `16:00:0x` lines are the same events.

### The sequence, as the gateway's audit trail recorded it

`docker logs --timestamps ai-dial-mcp-gateway-mcp-signin-gateway-1` for the window,
`gateway.audit` records verbatim (identical keys collapsed; ids are the store keys a harness
caches, not credentials):

```
13:00:04.885  client_registered  client_id=JJDBg9HTTyNXJT3hV3Hn9w  source=dcr
13:00:07.466  client_registered  client_id=0uMKVR7ymrDDqrOhN4D0KQ  source=dcr
13:00:07.971  flow_allocated     flow_id=bOhLh0Y6PiW4LUXVqE8x1Q  client_id=0uMKVR7ymrDDqrOhN4D0KQ  toolset=notion
13:00:10.209  code_issued        flow_id=bOhLh0Y6PiW4LUXVqE8x1Q  client_id=0uMKVR7ymrDDqrOhN4D0KQ  toolset=notion  subject=<uuid>
13:00:10.507  token_issued       client_id=0uMKVR7ymrDDqrOhN4D0KQ  toolset=notion  subject=<uuid>
```

Reading the chain:

- **Registration is the fix under test, and it fired.** Both `client_registered` records
  carry `source=dcr` — Cursor used Dynamic Client Registration, the surface the finding was
  about. Cursor registered **twice**: the first (`13:00:04`) after its initial 401, then
  Cursor cleared its local OAuth credentials (`MCP OAuth credentials cleared (local
  housekeeping`) and re-registered (`13:00:07`) before completing the flow. Both accepted;
  no refusal between them.
- **The flow ran on the second client id.** `flow_allocated` carries
  `0uMKVR7ymrDDqrOhN4D0KQ` — the client whose registration sat two lines above it — so the
  authorizing client is the one DCR just minted, not a pre-registered or CIMD one.
- **The signed-in short-circuit fired, not the full upstream chain.** `code_issued` follows
  `flow_allocated` directly, with **no `upstream_callback` and no `signin_result` between
  them**: the identity leg found a stored upstream credential for the user, so the flow
  issued its code without a second consent round-trip. That is the intended repeat-sign-in
  path (`gateway/federation.py`, the `result.status.signed_in` branch); a first-use run
  would show `upstream_callback` → `signin_result accepted` → `code_issued` instead.
- **The code was redeemed.** `token_issued` closes the chain ~0.3 s later for the same
  client, toolset, and subject — the harness exchanged its code and the gateway minted the
  access/refresh pair.
- **No `flow_refused` anywhere in the window**, so not one authorization request was
  rejected for an unknown client, an unregistered redirect URI, or a missing/unknown
  `resource`. In particular the `cursor://anysphere.cursor-mcp/oauth/callback` redirect URI
  resolved against the DCR record — the loopback/custom-scheme matching held.
- **The toolset call reached Core and succeeded.** Core's log
  (`dial-instance-core-1`) shows `POST /v1/toolset/notion/mcp` answered **200** at
  `13:00:20`, `13:00:22`, `13:01:58`, `13:01:59`, `13:02:00`, `13:02:02`, MCP-proxied to
  `mcp.notion.com:443` — i.e. the live tool call through the front door, under the gateway-
  minted token, worked. Two transient `502`s sit between registration and the first 200 (one
  `Failed to resolve 'mcp.notion.com'`, one `Connection reset`), both from the upstream
  resolver and both retried successfully — they are Core's own upstream blips, not gateway
  refusals, and a `GET` on the same path returned the expected `405`.

The only other lines in the window are the store's own file-mode `WARNING`s — the bind-
mounted `/data` filesystem does not honor POSIX owner-only modes, so each save logs that the
temporary file keeps the mount's mode and the store's protection is the volume owner's. That
is pre-existing, documented behavior, unrelated to this run, and the saves themselves
succeeded (the registrations above persisted).

### Corroboration from Cursor's side

Cursor's own logs (`%APPDATA%\Cursor\logs\20261019T204549\`) show the defect's signature
present **before** the fix and **absent after** it — the strongest form of corroboration,
since the same client, same config, same toolset is on both sides of the boundary:

```
mcp-server-user-notion-dial-gw.log

13:28:04  [warning] Transient error connecting to streamableHttp server:
            expected "number", code "invalid_type", path ["client_id_issued_at"],
            message "Invalid input: expected number, received string"        <- pre-fix
13:28:41  (same)
13:30:27  (same)
13:31:18  (same)                                                           <- last error
16:00:04  [info] MCP OAuth needsAuth (v2)                                  \
16:00:10  [info] MCP OAuth tokens persisted                                 |  post-fix
16:00:10  [info] MCP OAuth callback exchange completed                      |  (no error)
16:00:21  [info] Successfully connected to streamableHttp server           /
16:00:37  [info] Successfully connected to streamableHttp server
            [V2 FSM] connection:connect_success: conn=connecting,auth=valid -> conn=connected,auth=valid
```

Every `client_id_issued_at` type error is stamped `13:28`–`13:31` local (`10:28Z`–`10:31Z`)
— the pre-fix registrations, the same four whose `created_at` the store shows as
`10:28:04`–`10:31:18Z`. The post-fix run at `16:00` local contains **no** such error: Cursor
went from `needsAuth` to `MCP OAuth tokens persisted`, `MCP OAuth callback exchange
completed`, and a final `connect_success` with `auth=valid`. A schema-strict client cannot
reach `connected` on a document it would reject — so the document it received this time was
conformant. The failure mode the finding named (*"A schema-strict client rejects the whole
document on a type mismatch, so the registration is lost client-side"*, §1.3) has no
occurrence left to fire on.

### The store after the run

`/data/dcr-registrations.json` (bind-mounted; `DCR_MAX_REGISTRATIONS=1024`), read from the
running container:

```
container sees 8 records
  0uMKVR7ymrDDqrOhN4D0KQ Cursor    created_at 2026-10-20T13:00:07+00:00   <- this run
  JJDBg9HTTyNXJT3hV3Hn9w Cursor    created_at 2026-10-20T13:00:04+00:00   <- this run
  5O_wQNpsvku21MeIki0pDw Cursor    created_at 2026-10-20T10:30:19+00:00
  AkaDRPhBlHM17exhkQiQnw Cursor    created_at 2026-10-20T10:30:27+00:00
  HdvpOItd8DFojtxxj5PQxA Cursor    created_at 2026-10-20T10:28:04+00:00
  fGvtRY2OEKkUzks4Ua37pg Cursor    created_at 2026-10-20T10:31:18+00:00
  yu0tNpWngBh95nsHM99-vg Cursor    created_at 2026-10-20T10:28:41+00:00
  gxTIV84luPqhX0dG2BdgJg group8-dcr-probe  created_at 2026-10-19T10:59:31+00:00
```

Eight records: the six kept at the end of §1.4 (five Cursor + the `group8-dcr-probe`), plus
the **two** this field run added (`13:00:04Z`, `13:00:07Z`, both `client_name: "Cursor"`,
both carrying the three real Cursor redirect URIs). Well under the cap. Every record's
`created_at` is still ISO-8601 **at rest** — the fix converted at the response site only, so
the storage format is unchanged and the epoch number exists solely on the wire, exactly as
§1.1 designed.

### Verdict

DCR is **proven in the field on its strictest client**. The finding's trigger — Cursor's
`client_id_issued_at` type check — was met by a registration whose response Cursor accepted,
followed by authorization, code issuance, token issuance, and a live tool call through the
front door that Core proxied to the upstream with `200`. The fix holds not just against the
probe (§1.3, which exercises one crafted document) but against a real third-party client
that had rejected the pre-fix document outright, on the same machine and config, minutes
apart. No regression appears in the window: no refusal, no leg failure, no error on either
side of the boundary.

Redaction: no token, code, verifier, key, or secret appears above. Client ids are the store
keys a harness caches (identifiers, not credentials); the user is carried as `<uuid>` and
the flow id is a 128-bit server-minted identifier. The `GATEWAY_SIGNING_KEY` and every other
env value read during extraction are not reproduced here.
