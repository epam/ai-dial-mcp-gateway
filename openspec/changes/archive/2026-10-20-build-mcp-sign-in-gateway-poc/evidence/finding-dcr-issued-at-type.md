# Finding — the registration response serializes `client_id_issued_at` as an ISO-8601 string, and a strict harness rejects the whole document

**Status:** open — diagnosed only, no code changed. Fix not implemented (deliberate: this
record is the input to the spec gate and the fix pass).

**Location note.** The briefing named
`openspec/changes/build-mcp-sign-in-gateway-poc/evidence/…`, but that change is **archived**
(`3db8a43`, directory `openspec/changes/archive/2026-10-20-build-mcp-sign-in-gateway-poc/`).
`openspec list` reports no active changes. This record therefore landed in the archived
folder's `evidence/`, beside the other finding records (`finding-redirect-uri.md`,
`finding-web-hardening-headers.md`, …), so the folder stays the single place its findings
live. Whether the fix re-opens this change (new spec delta + tasks) or opens a successor
change is the orchestrator's spec-gate call, not a troubleshooting one.

## Symptom

A real-harness attempt against the live composed stack: **Cursor** (a DCR-only harness —
it advertises no CIMD and so takes the gated registration path) registered against the
gateway with DCR enabled. The registration itself **succeeded server-side** — a client id
was issued and persisted, and the gateway answered `201 Created`. Cursor then failed the
connection **client-side**, before any authorization request:

```
Transient error connecting to streamableHttp server: [
  {
    "expected": "number",
    "code": "invalid_type",
    "path": [ "client_id_issued_at" ],
    "message": "Invalid input: expected number, received string"
  }
]
Connection failed: [ … same … ]
```

The error is a zod/`invalid_type` shape — a schema validation of the **registration
response document** — and the path is the response member, so the failure is Cursor
refusing the document the gateway sent, not Cursor failing to reach the gateway.

## Evidence

### 1. Reproduction — the live response, with types per field

Probe (typed sweep, run against the front door `http://localhost:8090/dial/register` through
the router, 2026-10-20). The instrument has a **negative control** that runs first: a
hand-built RFC 7591-conformant response document. It must show **no** violation, or a
failure from the live document would be indistinguishable from a broken instrument.

```
--- negative control: RFC 7591-conformant control document (expect NO violation) ---
  client_id                    str      OK  'abc'
  redirect_uris                list     OK  ['http://127.0.0.1:1/cb']
  client_name                  str      OK  'c'
  token_endpoint_auth_method   str      OK  'none'
  grant_types                  list     OK  ['authorization_code']
  response_types               list     OK  ['code']
  client_id_issued_at          int      OK  1792067046

--- live gateway /dial/register response ---
  client_id                    str      OK  'vdy_ZKXPhoPcmhRbyuGEDw'
  redirect_uris                list     OK  ['http://127.0.0.1:8771/callback']
  client_name                  str      OK  'troubleshoot-dcr-issued-at-type'
  token_endpoint_auth_method   str      OK  'none'
  grant_types                  list     OK  ['authorization_code']
  response_types               list     OK  ['code']
  client_id_issued_at          str      VIOLATION  '2026-10-20T10:38:13+00:00'

negative control violations: NONE -> instrument distinguishes
live violations:             {'client_id_issued_at'}
```

Raw response, as sent (body verbatim, `HTTP/1.1 201 Created`):

```json
{"client_id":"F9Odc0D2oHOH5G9I9KlnTQ","redirect_uris":["http://127.0.0.1:8769/callback"],"client_name":"troubleshoot-dcr-issued-at-type","token_endpoint_auth_method":"none","grant_types":["authorization_code"],"response_types":["code"],"client_id_issued_at":"2026-10-20T10:34:28+00:00"}
```

**The whole-response sweep found exactly one violation.** Every other member matches its
RFC 7591 type: `client_id` string, `redirect_uris` array of strings,
`token_endpoint_auth_method` string (`"none"`), `grant_types` and `response_types` arrays
of strings, `client_name` string. That matters for the fix's blast radius — this is a
one-field defect, not a shape problem across the document.

### 2. Cursor's log — the client-side rejection, and the registration it belongs to

`%APPDATA%\Cursor\logs\20261019T204549\mcp-server-user-notion-dial-gw.log` — the same
`{"expected":"number","code":"invalid_type","path":["client_id_issued_at"]}` block, with
the connection around it:

```
2026-10-20 13:28:04.469 [info] stopped connection: user-notion-dial-gw
2026-10-20 13:28:04.501 [info] connecting streamableHttp for "notion-dial-gw" (user-notion-dial-gw)
2026-10-20 13:28:04.501 [info] [V2 FSM] connection:connect_start: conn=idle,auth=unknown -> conn=connecting,auth=unknown
2026-10-20 13:28:04.553 [warning] MCP HTTP exchange completed
2026-10-20 13:28:04.610 [warning] Transient error connecting to streamableHttp server: [
  { "expected": "number", "code": "invalid_type", "path": [ "client_id_issued_at" ],
    "message": "Invalid input: expected number, received string" }
]
2026-10-20 13:28:04.611 [warning] Connection failed: [ … same … ]
2026-10-20 13:28:04.611 [warning] [V2 FSM] connection:connect_failure: conn=connecting,auth=unknown -> conn=failed,auth=unknown
```

(The identical block repeats 6× across 13:28:04–13:31:18 in this log and mirrors into
`mcpprocess.log`; the same failure class appears in
`window1_wb0/exthost/anysphere.cursor-always-local/Cursor Structured Logs.20261019T204607_e9a90129.log`.)

**Corroboration ties each log failure to a served registration.** The store's
`client_name == "Cursor"` records, matched to the failure timestamps (log timestamps are
local, UTC+3; store `created_at` is UTC):

| store registration (`created_at`, UTC → local) | client_id | Cursor log failure | delta |
|---|---|---|---|
| 10:28:04 → 13:28:04 | `HdvpOItd8DFojtxxj5PQxA` | 13:28:04.610 | +0.6 s |
| 10:28:41 → 13:28:41 | `yu0tNpWngBh95nsHM99-vg` | 13:28:41.971 | +1.0 s |
| 10:30:19 → 13:30:19 | `5O_wQNpsvku21MeIki0pDw` | 13:30:19.094 | +0.1 s |
| 10:30:27 → 13:30:27 | `AkaDRPhBlHM17exhkQiQnw` | 13:30:27.570 | +0.6 s |
| 10:31:18 → 13:31:18 | `fGvtRY2OEKkUzks4Ua37pg` | 13:31:18.413 | +0.4 s |

Five Cursor registrations, five failures, sub-second deltas: the gateway answered `201`
and Cursor failed the **response parse** immediately after each one, then retried. Nothing
between the registration and the failure — the harness never reached `/dial/authorize`.
There is no upstream or credential failure here; the registration leg is the whole story.
Also visible earlier in the same log, the pre-DCR state of the same harness:
`Incompatible auth server: does not support dynamic client registration` (DCR was off then).

Redaction: no token, code, key, or secret appears above. Client ids are shown as handles.
The harness's store entries carry the harness's own three redirect URIs (a custom-scheme
one, `https://www.cursor.com/agents/mcp/oauth/callback`, and a loopback one); the probe's
own throwaway entries carry a loopback callback only.

### 3. The persisted record — the string is at rest, and the response passes it through

`data/dcr-registrations.json` (host side of the container's `/data`), one record with its
types:

```
client_id        str    'vdy_ZKXPhoPcmhRbyuGEDw'
redirect_uris    list   ['http://127.0.0.1:8771/callback']
client_name      str    'troubleshoot-dcr-issued-at-type'
created_at       str    '2026-10-20T10:38:13+00:00'
```

A string at rest is **not** the defect: the store is JSON, nothing reads `created_at` back
for arithmetic, and its shape is an internal detail of this gateway's own file. The defect
is that the same value is forwarded, unconverted, into an RFC 7591 **response**.

## Root cause

In `gateway/store.py`, `RegistrationStore.add` builds the record with:

```python
"created_at": datetime.now(UTC).isoformat(timespec="seconds"),
```

— an **ISO-8601 string** (`"2026-10-20T10:38:13+00:00"`), which is the store's at-rest
form. (`gateway/state.py`'s `created_at: float` is a different, unrelated field — the flow
record's creation time — and is not on this path.)

In `gateway/routes.py` the registration response is assembled field by field, and the
issued-at member is copied straight out of that record with no conversion:

```python
_CLIENT_ID_ISSUED_AT_MEMBER: record["created_at"],
```

(`_CLIENT_ID_ISSUED_AT_MEMBER = "client_id_issued_at"`, the RFC 7591 name.)

So the response carries the store's **internal** serialization of a timestamp where
RFC 7591 §3.2.1 requires a **JSON number of seconds since 1970-01-01T00:00:00Z**. The
number was never computed and never converted anywhere on the path — this is a
pass-through of a storage-format value into a wire-format field, not a `str()` applied at
the wrong moment.

**Why Cursor rejects it.** Cursor validates the registration response against an RFC 7591
schema in which `client_id_issued_at` is `number` (that is a *permissive* client, not a
lax one — RFC 7591's own language is descriptive, "the number of seconds from
1970-01-01T00:00:00Z as measured in UTC", and the RFC states its data-member types "are
defined in terms of their JSON representations"). A JSON string at that path fails the
type check, and the failure is **document-level**: Cursor discards the entire response —
including the perfectly valid `client_id` and `redirect_uris` — so a registration that
succeeded and persisted is, from the harness's side, as if it never happened. That is why
the symptom is "cannot connect at all" rather than "a timestamp is wrong".

## Impact and scope

- **Breaks:** any harness whose registration-response schema types `client_id_issued_at`
  as a number — the Cursor class of strict validators, i.e. exactly the DCR-only clients
  this endpoint exists for. For those, DCR is **100% broken**: every registration is
  refused client-side, forever, with no workaround on the gateway's side other than a fix.
  This is the fallback path in the design (`docs/background/design.md` E5: the flag stays
  for field stragglers), and it is currently non-functional for its target client class.
- **Does not break:** the gateway's own flows. Nothing in this repo reads
  `client_id_issued_at` — the store reads `created_at` only to write it back out, and
  authorization resolves clients from `redirect_uris` (`gateway/authorize.py`,
  `gateway/cimd.py`). The gateway's unit suite, the DCR probe, and PoC C's own criteria
  are all structurally blind to it (see "Why this slipped through").
- **Does not break:** CIMD harnesses. They never call this endpoint; the defect lives
  entirely on the DCR response path.
- **Security:** none. The issued-at value is not a credential, is not used for any
  decision, and no flow depends on it. This is an interop defect, and the fix is
  type-only — no new data is exposed, no validation is relaxed.

## Why this slipped through (the test blind spot)

The accepted-registration test asserts field **presence and values**, never the issued-at
member's **type**:

`tests/test_store.py::test_registration_is_accepted_while_enabled` asserts
`redirect_uris`, `token_endpoint_auth_method`, `grant_types`, and `"client_secret" not in
body` — it never touches `client_id_issued_at`. `scripts/probe_dcr.py` **prints** it
(`print(f"  client_id_issued_at    {document.get('client_id_issued_at')}")`) without
asserting anything about it, so the live probe displays `2026-10-20T…` and reports `green`
— an instrument that shows the value and checks nothing about it. RFC 7591 field-type
conformance had no assertion anywhere, which is why a live PoC-C run and a green battery
coexisted with a totally broken DCR path for the Cursor client class. (`mypy` cannot see
it either: the response is a plain `dict[str, object]` / `Any`.)

## Proposed fix (not implemented)

1. **Emit the member as an int, in epoch seconds, at the response boundary.** The
   response is built in `gateway/routes.py`; the store's record is its own format. Compute
   the number rather than pass the string through — the value must be the *same instant*
   the store recorded, so derive it from the record's timestamp (parse the stored
   ISO-8601 and take `int(dt.timestamp())`), not from a second `datetime.now()`. A second
   `now()` is a silent skew between the stored record and the answered value, and it also
   breaks the re-registration case (below).
   - Note the pass-through is *only* visible on the re-registration path as well:
     `RegistrationStore.add` returns the **existing** record unchanged when the client id
     already exists (by design), so any fix must convert at the response site, not at the
     `add` site — otherwise the idempotent branch would serialize an unconverted record.
2. **Leave the persisted record as it is.** `created_at` stays the ISO-8601 string in
   `data/dcr-registrations.json`: it is at rest, unread, and a store-format change would be
   churn with an on-disk migration question attached. The redaction/shape of the record is
   **unaffected** by the fix — the store holds no secret today and the fix touches no field
   of it. (If anything, the store's `created_at` should gain a comment that it is a storage
   format, not the wire format, so the pass-through is not reintroduced.)
3. **Regression test — assert the TYPE, not merely presence:**
   `assert isinstance(body["client_id_issued_at"], int)` alongside the existing assertions,
   plus (a) the value is within a sane epoch range for "now", and (b) it equals the epoch
   form of the store record's `created_at` (the "same instant" property from step 1, which
   a second `now()` would fail).
4. **Tighten the live probe, because the probe is what should have caught this.**
   `scripts/probe_dcr.py`'s `register()` currently prints the member and asserts nothing
   about it; the fix's pass adds a typed assertion over the **whole** response document
   (every RFC 7591 member present checked against its expected JSON type), so the sweep I
   ran here becomes a permanent instrument rather than a one-off. This is the generalizable
   lesson from the blind spot: `probe_dcr.py` asserts statuses and secret-absence but not
   the document's field types.
5. **Out of scope, noted for the record:** the response omits `client_name` as a member
   when the request carried none (`record.get("client_name")` → `None`) — it emits
   `"client_name": null`, which the live probe confirms. I found no spec line permitting or
   forbidding this, and no harness failure attributable to it (Cursor sends a client name).
   It is a **separate, lower-severity** observation, not part of this finding's fix; I did
   not chase it, and I recommend it be judged on its own if anyone sees a harness send no
   name.

### Spec judgment (this finding's spec gate)

The delta spec's registration requirements say nothing about the response document's
members or their types — the registration requirement
("Client registration resolves pre-registered, CIMD, then gated DCR clients") and the
durability requirement ("DCR registration records are durable across restarts") both speak
to resolution order, fetch bounds, persistence, and the cap, never to the response shape.
RFC 7591 conformance is the **background standard** the endpoint is implemented against
(RFC 7591 is named in the design's E5 row and in the evidence records), so a type
conformance defect is a defect against a standard the spec already adopts, not a change to
specified behavior.

**However, I judge that a Wording touch IS required, and it is worth doing for a reason
beyond this defect.** "The response conforms to RFC 7591" is currently implicit — a reader
of the spec cannot tell whether the shape was deliberately left to the implementation or
simply omitted — and that implicitness is precisely what let a broken field live through a
green suite and a live PoC run. The capability's whole reason for having the DCR path is
interop with clients that validate strictly (that is what "for field stragglers" means), so
the response's conformance is capability-bearing behavior, not an implementation detail.
The recommendation is therefore a **one-line spec addition** in that requirement: the
registration response document MUST conform to RFC 7591 §3.2.1, and `client_id_issued_at`
— when present — MUST be a JSON number of seconds since the epoch (with a scenario
asserting the type). That is a small delta, and it converts an unnamed assumption into a
testable row that the type-regression test binds to.

Because a spec delta is needed, the cycle's spec gate (step 2 → 3) applies: the fix goes
through an OpenSpec change (delta spec + tasks + review + owner pause) **before** any code.
The orchestrator owns that call; this record stops at the diagnosis.

## Reproduction recipe (for the fix pass)

```bash
# 1. typed sweep with its negative control (the instrument above, verbatim)
#    POST http://localhost:8090/dial/register  {"redirect_uris":["http://127.0.0.1:8771/callback"]}
# 2. the store entry it created
cat data/dcr-registrations.json          # created_at is the ISO-8601 string
# 3. Cursor's rejection
grep -n -A6 client_id_issued_at \
  "$APPDATA/Cursor/logs/20261019T204549/mcp-server-user-notion-dial-gw.log"
```

## State left behind (no perturbation)

Diagnosis only — **no code, spec, config, or container was changed**, nothing committed.
DCR remains **enabled** (`DCR_ENABLED=true` in `.env`, the owner's testing configuration):
it was not disabled or touched. The store was **not** cleared and no registration was
removed. The only additions are this agent's own throwaway probe registrations — four of them, all
with a loopback callback (`http://127.0.0.1:8769|8770|8771|8772/callback`; three with
`client_name` `troubleshoot-dcr-issued-at-type` / `troubleshoot-typed-sweep`, one with no
`client_name` from probe 5) — left in place per instruction, so the store went from 6 to 10
records. The five Cursor registrations from the failed attempt and `group8-dcr-probe` are
untouched. The gateway and router containers were already up (both healthy) and were not
recreated.

**One operational note worth carrying to the fix pass:** each probe registration above
consumed one slot of the store cap (1024), and the harness's failure loop will keep
registering on every retry (6 attempts observed in 3 minutes), because a client-side
response rejection never reaches the client's "I already have a client id" state. Every
retry adds a registration. A Cursor-class client left pointed at this gateway therefore
consumes the cap steadily — worth knowing before a fix pass or a demo runs long.
