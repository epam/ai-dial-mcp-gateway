# Finding — refusals before flow allocation leave no log trace

**Symptom.** A harness rejected at `/dial/authorize` (invalid client, redirect_uri
mismatch, `invalid_target`, unknown toolset) receives its JSON error and nothing is
logged: `gateway/audit.py`'s `flow_refused()` has no call sites. Felt in the field:
the redirect-uri diagnosis (finding-redirect-uri.md) could not begin from the
gateway's logs — the failure had to be reproduced externally with probes. Leg
failures AFTER allocation are audited (`flow_leg_failed`, federation.py); the
pre-allocation class is silent.

**Why it matters.** This is exactly the operator's entry point for "my harness cannot
connect / gets rejected" — the most common troubleshooting shape. Invariant 5 (no
credential in logs) is not in tension: the diagnosable facts of a refusal
(`client_id`, `redirect_uri`, `resource`, toolset name, reason) contain no credential;
the discipline that keeps them safe is the auditor's existing fixed-vocabulary /
single-line rule (a caller cannot write arbitrary content into the log).

**Root cause.** The audit design grew from the flow lifecycle outward; the
pre-allocation refusal paths (authorize validation, discovery 404s, token-endpoint
validation failures) predate the flow record and were never wired to the auditor.

**Proposed fix.** Audit every pre-allocation refusal: `flow_refused(reason, ...)` with
the safe request facts, at the authorize/token/register/discovery refusal points;
fixed-vocabulary reasons; no free-form reflection. A spec ripple is likely needed
(audit/logging behavior for the refusal class is not pinned — the existing audit
requirement covers flow lifecycle events); per spec-first: authoring pass, then the
implementation (call sites + tests: a refusal produces exactly one audit record with
the safe facts and no credential material — the negative control being the
injection attempt).

**Status.** Open — routed to the authoring pass after the in-flight passes (4.9
headers / 3.12 store / toolset-redirect fix) complete, before the final review gates.

## Resolution — the spec-first ripple (authoring pass)

Landed, authoring only (the call sites and tests are the next implementation pass):

- **Delta spec (`specs/mcp-signin/spec.md`)** — new ADDED requirement *"Refusals
  before flow allocation are audited"*: every refusal before a flow is allocated
  (authorize validation, client resolution and registration, token-endpoint
  validation, discovery misses) MUST be audited with a fixed-vocabulary reason and
  the request's non-credential facts (client id, redirect URI, resource, toolset) —
  no credential material, no free-form caller input. Two scenarios: the
  pre-allocation refusal record (the redirect-uri field class) and the injection
  negative control.
- **`design.md`** — the audit trail's design statement now says the trail covers the
  whole request lifecycle, refusals before allocation included, with the
  troubleshootability rationale from this finding; a traceability row
  (OR-3, never-cut 5) is added.
- **`tasks.md`** — task 4.10 opened: wire `flow_refused` at every pre-allocation
  refusal site (authorize/token/register/discovery), with the per-class
  exactly-one-record tests, the injection negative control, and the
  no-credential-anywhere assertion.
- **`docs/gateway-configuration.md`** — the audit-trail section now lists
  `flow_refused` and its safe facts, closing the doc-side staleness that had the
  event absent from the documented vocabulary.

Note: the spec had no audit-trail requirement before this ripple — only the
invariants requirement's "no secrets in logs" scenario touched the trail — so the
refusal class is pinned by this new requirement rather than by extending an
existing one.

**Status after this pass.** Resolved at the spec/design/task level; the
implementation pass (task 4.10) carries the call sites and tests.

## Ripple review (fresh reviewer pass) — needs-changes: one MAJOR, two MINOR

F6/F7 disclosures verified sound and honestly placed (not this finding's scope).

1. **MAJOR — coverage gap.** The requirement's preamble ("Every refusal that occurs
   before a flow is allocated") sweeps more than its enumeration (and task 4.10's
   site list) delivers. Silent sites missed: (a) the 429 limiter refusals at
   `/dial/authorize` and `/dial/register`; (b) `/dial/revoke` form-parameter
   refusals (unauthenticated, no flow ever allocated); (c) `/dial/{name}/status`
   refusals (unknown-toolset 404, the two 401s, invalid_target). Callbacks' unknown/
   expired-flow pages are post-allocation and correctly excluded. Fix: rescope the
   preamble (e.g. "on the unauthenticated sign-in surfaces") or add the three sites
   to the enumeration and task 4.10 — otherwise a literal conformance run fails even
   after 4.10 lands as specified.
2. **MINOR — implementability.** `flow_refused(self, reason)` takes only the reason;
   the spec requires client id / redirect URI / resource / toolset on the record.
   Task 4.10 must name the signature extension — and its subtlety: the
   never-a-caller-value discipline applies to the REASON; the facts ARE
   caller-supplied and must land as discrete `_emit` fields (single-line encoded).
3. **MINOR — doc contradiction.** `docs/gateway-configuration.md`'s audit section
   still opens "Every record carries the flow id, the client id, the toolset…"
   directly above a `flow_refused` paragraph describing a record with no flow id.
   Align.
- **Resolution:** Landed, authoring only (no source changes; the call sites and tests
  remain task 4.10's implementation pass):
  1. **Coverage** — the requirement's preamble now enumerates the full site list
     determinately instead of sweeping: `/dial/authorize` validation **and rate-limit
     refusals**, client resolution and `/dial/register` refusals, `/dial/token`
     validation, **`/dial/revoke` form refusals**, **`/dial/{name}/status`
     refusals**, and discovery misses (489 chars, RFC 2119 kept); the facts clause
     now says "the non-credential facts **the request offered**", so a limiter 429
     or a discovery miss — a request with no client id to carry — is conformant
     rather than indeterminate. The callback pages stay excluded: their refusals
     answer for a flow already allocated and are audited by that flow's own events
     (stated explicitly in task 4.10). Task 4.10's site list is extended to match,
     site by site: the authorize limiter 429, the register refusals (disabled 404,
     limiter 429, body refusals, cap refusal), the revoke form refusals, and the
     status refusals (unknown-toolset 404, the two 401s, `invalid_target`).
  2. **Signature** — task 4.10 now names the extension
     `flow_refused(reason, *, client_id=None, redirect_uri=None, resource=None,
     toolset=None)` and its discipline split: the reason stays fixed-vocabulary
     (never a caller value); the facts are caller-supplied but land as discrete
     `_emit` fields, each single-line encoded — a newline inside a caller value
     cannot become a newline in the record — never interpolated into free-form
     text.
  3. **Doc** — `docs/gateway-configuration.md`'s audit section no longer opens with
     "Every record carries the flow id": the flow-scoped records do, and
     `flow_refused` is named as the one record outside that shape (no flow id,
     pre-allocation); its site list is extended to match the rescoped coverage.
     `design.md`'s audit statement and site list are aligned with the same coverage.
  `openspec validate --changes --strict` green after the edits.
