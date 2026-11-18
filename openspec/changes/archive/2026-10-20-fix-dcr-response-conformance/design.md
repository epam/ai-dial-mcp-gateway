# Design

## Context

A field defect on the gated DCR path: the registration response serializes
`client_id_issued_at` as an ISO-8601 string where RFC 7591 §3.2.1 defines the member as
a JSON number of seconds since 1970-01-01T00:00:00Z. Schema-strict harnesses (the
Cursor class) reject the whole response document on the type failure — a registration
that succeeds and persists server-side is, from the harness's side, as if it never
happened, and every retry registers again. A typed sweep of the whole live response
found exactly one violating member, so the blast radius is one field on one path: no
other member, no store change, no flow change, no security change.

The registration response's conformance was implicit in the capability — RFC 7591 is
the standard the endpoint is implemented for — and that implicitness is what let a
broken field coexist with a green suite and a live acceptance run. This change makes
the conformance line spec and binds it to tests and the probe.

## Goals / Non-Goals

**Goals:**

- Every registration response document conforms to RFC 7591 §3.2.1 member names and
  JSON types — asserted, not assumed.
- The answered `client_id_issued_at` is the same instant the store recorded, as an
  epoch-seconds JSON number, on every branch that returns a registration.

**Non-Goals:**

- No change to the store's at-rest format, no on-disk migration, no rewrite of
  existing records.
- No change to client resolution, CIMD handling, or anything off the DCR response path.
- No position on `client_name: null` (the open question below).

## Decisions

### D1 — Convert at the response site, deriving the instant from the stored record

The epoch-seconds number is computed where the response is assembled, by parsing the
record's stored `created_at` and taking its seconds since 1970-01-01T00:00:00Z — never
by a second `datetime.now()`. Two properties force this shape:

1. **Same instant.** The answered value must be the instant the store recorded. A
   second `now()` is a silent skew between the persisted record and the answered
   number — the two disagree by however long the request took, forever.
2. **The idempotent branch.** Re-registration with an existing client id returns the
   existing record unchanged, by design. A conversion at the record-creation site
   would miss that branch entirely and serialize an unconverted record on it — the
   defect would survive the fix for every already-registered client. The response
   site is the one place every record that becomes a response passes through.

The store's `created_at` field keeps a comment marking it as the storage format, not
the wire format, so the pass-through is not reintroduced by a future edit.

### D2 — The store's at-rest format is unchanged

`created_at` stays the ISO-8601 string in the store file. It is at rest, unread for
arithmetic, and an internal detail of the gateway's own file. Changing it would be
churn with an on-disk migration question attached and no behavioral gain — the wire
concern is solved at the wire boundary, where it belongs. Existing records — including
every record registered during the defect era — answer conformantly the moment the
response site converts, with no migration.

### D3 — The typed sweep becomes a permanent probe assertion

`scripts/probe_dcr.py` printed the issued-at member and asserted nothing about it — the
instrument showed the string and reported green; the accepted-registration unit test
asserted presence and values of other members, never the type. The fix binds the typed
sweep into the probe as a permanent assertion: every RFC 7591 member of the response
document checked against its expected JSON type, with a hand-built conformant document
as the negative control that must show no violation. The one-off diagnostic instrument
becomes the standing one; a type defect on this path can no longer coexist with a green
probe run.

### Open question — `client_name: null` when the request carries no name

The registration response emits `"client_name": null` when the registration request
carried no client name. The requirement's conformance sentence now names this emission
as its one exception, so a spec line touching it exists — the carve-out keeps the
conformance claim honest without judging the emission. That judgment stays open:
whether a name-less registration should answer `null`, omit the member, or be rejected
is not decided here, and no harness failure is attributable to it (the observed strict
harness sends a name). It is judged on its own — with its own finding, and its own spec
line if warranted — should a name-less harness ever break against it. The emission
itself is deliberately not changed by this fix.

## Risks / Trade-offs

- **None of substance.** One field's JSON type on one response path; no data, decision,
  validation, or surface change. The security review on the diff runs at focused depth
  to falsify the no-impact claim, per the repo's gates.
- The requirement description exceeds the 500-character hint because MODIFIED deltas
  carry the existing block whole, never trimmed to fit — the retained text is
  untouched and the conformance line is appended.
