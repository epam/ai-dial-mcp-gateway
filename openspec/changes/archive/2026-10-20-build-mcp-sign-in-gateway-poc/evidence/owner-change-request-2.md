# Owner change request — 2 (2026-10-18, during implementation)

**Secret-material memory acknowledgment.** The owner asks whether the design handles
secrets in memory as wipeable byte arrays; the honest answer is no, and in pure Python
reliable zeroization is not achievable at the application layer (immutable `str`/`bytes`,
unreachable library-internal copies in PyJWT/`cryptography`, allocator/GC behavior,
traceback retention). The owner wants this added — **the author to fold a short
acknowledgment into the security impact analysis** (design.md), covering:

- secret material (signing key, in-flight identity tokens) lives in process memory for
  the process lifetime; there is no reliable wipe-on-demand in CPython — the same
  reality as any managed runtime, not a Python-specific gap;
- the residual is the **host-read/memory-dump class already named** in this change's
  trust-boundary statements (signing-key custody, DCR-store tamper) — not a new class;
- the exposure is **bounded** by the TTLs (10-min access tokens; min(flow TTL,
  Keycloak `exp`) for the in-flight identity token) and by the never-store rules
  (tokens nowhere at rest; the Keycloak token used twice then dropped);
- the **actual control** that removes key material from process memory is not
  materializing it: a KMS/HSM sign-interface (`key_source: kms` — the design's stated
  production direction), where the process holds a key reference, not a key.

Keep it to the acknowledgment + these four points, in the security impact analysis's
existing style (behavior and reason, no provenance). Add a spec ripple ONLY if the
author judges the exposure needs a normative scenario — the expectation is it does not
(it is a residual disclosure, not new behavior).

## Resolution (2026-10-19, authoring pass)

**What changed, where — both edits in `design.md`:**

- **The zeroization acknowledgment** was folded into the security impact analysis, as a
  prose block ("Memory zeroization — an acknowledged residual, not a new class") after
  the never-cut invariant table, covering the four points: secret material lives in
  process memory for the process lifetime with no reliable CPython wipe-on-demand
  (immutable `str`/`bytes`, unreachable library-internal copies, allocator/GC,
  traceback retention — the same managed-runtime reality as Java/Go/.NET, not a
  Python-specific gap); the residual is the host-read/memory-dump class the
  trust-boundary rulings already name (signing-key custody, DCR-store tamper) — not a
  new class; it is bounded by the TTLs (10-min access tokens, min(flow TTL, provider
  `exp`) for the in-flight identity token) and the never-store rules; and the control
  that actually removes key material from process memory is never materializing it — a
  KMS/HSM sign-interface (`key_source: kms`), a key reference, not a key.
- **The mi-2 debt-ledger row** was updated to the content-decided status read: the flow
  keeps the statuses the settings route's own answer carries and asks
  `GET /openai/toolsets/{name}` only when that answer omits them — decided by the
  answer's content, never by an error, so one route serves both wherever Core enriches
  it (D-7's measured behavior, `evidence/group-4.md`).

**Spec-ripple judgment: none, on both items.** The zeroization item is a residual
disclosure, not new behavior: the delta spec already normatively bounds everything
observable about the exposure (never-store rules, the 10-minute access TTL, the
min(flow TTL, `exp`) bound on the in-flight identity token), and zeroization itself is
not an observable behavior a scenario could pin — the acknowledgment belongs in the
impact analysis, matching the owner's expectation. The D-7 item needs no delta because
the delta spec pins no route for the settings/status read (it requires the settings
fetch as the user before any upstream round-trip and the signed-in short-circuit, not
which Core route answers them) — the orchestrator's spec-gate decision stands.

**Scope note on the "flow step 4" referent:** `design.md` contains no numbered flow
walkthrough; its only prose describing the status read's route was the mi-2 row
(updated above). The flow walkthrough lives in `docs/gateway-configuration.md` (group
4's task 4.7 deliverable), whose "The two Core routes the flow reads, and why both"
subsection still frames the listing route as the status read rather than the
content-decided fallback; `gateway/core.py`'s module docstring likewise predates D-7's
fix, while the same module's read-function docstring already states the decided
behavior. Both are outside this pass's edit scope (design.md only; no source code) and
are flagged for the owner/orchestrator to direct.
