# Release notes — fix-dcr-response-conformance (draft)

### For users

- **Strict harnesses can now register against the gateway.** The registration
  response's `client_id_issued_at` is now a JSON number of seconds since
  1970-01-01T00:00:00Z, as RFC 7591 defines it — where it was an ISO-8601 string that
  schema-strict harnesses (the Cursor class) rejected, discarding the whole
  registration response and never advancing past the sign-in's first step. If your
  harness kept failing to connect with a registration-response type error, it now
  completes registration and proceeds to sign-in.
- **No action needed, nothing to re-register.** The fix converts at the response
  boundary; stored registrations keep their shape and their client ids, and a
  registration made before the fix answers a conformant document immediately after
  it. A harness that was rejected had no usable client id to hold — it discarded the
  whole response, id included — so what it sees is the retry loop ending: its next
  registration succeeds and it proceeds to sign-in. That also stopped the loop from
  quietly consuming the registration store's capacity.

### For the team

- **The DCR registration response is now spec-bound to RFC 7591 §3.2.1** (member names
  and JSON types): one modified requirement in `mcp-signin` with type-asserting
  scenarios for both the first registration and the idempotent re-registration branch.
  The conformance line was implicit before — which is how a broken field coexisted with
  a green suite and a live acceptance run.
- **The conversion lives at the response site, derived from the stored record.** The
  answered number is the same instant the store recorded — parsed from the record's
  stored `created_at`, never a second `now()`. The response site is the one place both
  branches pass through: a conversion at record creation would have missed the
  idempotent re-registration branch, which returns the existing record unchanged.
- **The store's at-rest format is unchanged.** `created_at` stays the ISO-8601 string
  in the JSON store file — a storage format, now commented as such; no migration, and
  defect-era records answer conformantly the moment the response converts.
- **The live probe now asserts a typed sweep over the whole response document** (with a
  conformant negative control), closing the instrument blind spot that printed the
  value and checked nothing. The unit suite gains the type and same-instant regression
  rows, including the re-registration branch.
- **One open question recorded, not chased:** the response emits `client_name: null`
  when the registration request carried no name — the requirement's conformance
  sentence carves it out as its one exception while judging nothing about it, and no
  failure is attributable to it; it is judged on its own if a name-less harness ever
  breaks against it.
