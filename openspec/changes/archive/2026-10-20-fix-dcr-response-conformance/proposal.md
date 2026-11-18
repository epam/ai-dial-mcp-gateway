# Proposal

## Why

The DCR registration response serializes `client_id_issued_at` as an ISO-8601 string
(the store's at-rest `created_at` format, forwarded verbatim) where RFC 7591 §3.2.1
defines the member as a **JSON number of seconds since 1970-01-01T00:00:00Z**. A strict
harness — the Cursor class, which validates the registration response document against
an RFC 7591 schema — rejects the **entire document** client-side on the type failure:
the registration succeeds and persists server-side, yet the harness discards the
response, never reaches authorization, retries, and registers again on every retry.
For that client class DCR is fully broken — and DCR-only, schema-strict harnesses are
exactly the clients the gated DCR fallback exists for. The failure was observed live:
five registrations answered `201 Created`, each followed within a second by the same
client-side `invalid_type` rejection at `client_id_issued_at`; the harness never
advanced past the registration leg.

The defect is one field, one path: a typed sweep of the whole live response found
exactly one violating member. Nothing else breaks — the gateway's own flows never read
`client_id_issued_at`, CIMD harnesses never call the endpoint, and no credential,
decision, or validation is involved. This is an interop defect against the standard the
endpoint is implemented for, not a behavior change; but the response's conformance was
never written down, which is precisely what let a broken field coexist with a green
suite and a live acceptance run — so the conformance line becomes spec, not just code.

## What Changes

- **One MODIFIED requirement** in `mcp-signin` (the client-registration requirement):
  the registration response document MUST conform to RFC 7591 §3.2.1 (member names and
  JSON types) in every member it emits, excepting the name-less `client_name: null`
  (the open question below), and `client_id_issued_at`, when present, MUST be a JSON
  number of seconds since 1970-01-01T00:00:00Z **derived from the record's stored
  creation instant** — plus type-asserting scenarios (first registration and idempotent
  re-registration) that bind the type and the same-instant property.
- **The fix boundary is the response site only**: the epoch-seconds number is computed
  where the response is assembled, from the record the store already holds. The
  store's at-rest shape is **unchanged** — `created_at` stays the ISO-8601 string in
  the JSON store file; no migration, no format change, existing records unaffected.
- **Regression tests assert the type, not mere presence**: `isinstance(…, int)`, a
  sane-epoch-range check, and equality with the epoch form of the stored record's
  `created_at` (the same-instant property a second `now()` would silently break), on
  both the new-registration and the idempotent re-registration branch.
- **The live probe gains a permanent typed-sweep assertion**: the whole registration
  response document checked member-by-member against its RFC 7591 JSON type (with a
  conformant negative control), so the instrument that displayed the string and
  reported green can no longer miss a type defect.
- **Operational cleanup, stated as such**: the four throwaway diagnostic registrations
  left in the live store are pruned — an operational step on live state, not a code
  change.

**Out of scope:**

- `client_name: null` in the response when the registration request carried no name —
  the requirement's conformance sentence excepts it while judging nothing about it, and
  no harness failure is attributable to it; recorded in the design as an open question,
  judged on its own if a name-less harness ever appears.
- Any store-format change, on-disk migration, or rewrite of existing records.
- CIMD and pre-registered client resolution (untouched), and anything off the DCR
  response path.

## Capabilities

### Modified Capabilities

- `mcp-signin`: the client-registration requirement gains the RFC 7591 §3.2.1
  response-conformance line and type-asserting scenarios. No requirement is added,
  removed, or renamed; every other requirement is untouched.

## Impact

- **One wire field's JSON type, one code path**: `gateway/routes.py`'s registration
  response assembly converts the stored instant to epoch seconds at the boundary;
  `gateway/store.py`'s record shape, file format, and write path are untouched.
- **Compatible with all stored state**: responses convert at read time, so the
  records registered during the defect era answer conformantly with no migration —
  a defect-era record answers a conformant document as soon as the gateway runs the
  fix. The rejecting harness never held a usable client id, though: it discarded the
  whole response, client id included, so the recovery it sees is not "connect with the
  id I have" but "the next registration succeeds and the retry loop ends" — it
  re-registers once more and proceeds from there.
- **Security: no impact claimed** — a type-only conversion of a non-credential,
  non-decision field; no new data exposed, no validation relaxed, no surface added.
  Per the repo's gates, that claim is falsified-or-confirmed by the security review
  on the implementation diff, at focused depth.
- **Instruments**: `scripts/probe_dcr.py`'s typed sweep becomes a permanent assertion;
  the unit suite gains the type/same-instant regression rows.
- **Operational**: the live store keeps its shape; the diagnostic throwaway records
  are pruned by hand as a live-state step; the store cap consumption note (each
  rejected-response retry re-registers, so a Cursor-class client left pointed at the
  gateway consumed cap steadily) is resolved by the fix itself — a conformant response
  ends the retry loop.
