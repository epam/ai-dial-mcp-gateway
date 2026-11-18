# Owner change request — 2026-10-18 (during the owner review pause)

Ruling on the two open items raised at the pause (DCR support for non-CIMD harnesses;
registered-client storage):

1. **DCR default stays OFF.** The owner agrees with the deprecation rationale; the
   config-gated default is unchanged.
2. **DCR MUST be tested in this change.** The fallback is to be proven, not shipped as
   a documented hope — but as **tasks with their own verification + evidence rows**,
   NOT as a sixth PoC C criterion (the five criteria remain the design-falsification
   gate; a DCR test failure is a change defect, not a design falsification). Suggested
   coverage, details to the author: flag enabled locally → register at `/dial/register`
   → complete the authorization flow with the registered client → live toolset call;
   plus the negative: flag OFF → `/dial/register` fails with the documented
   disabled-error.
3. **Simple durable storage for DCR registration records (v1).** The current design
   leaves DCR registration storage unspecified (in-memory implied; a gateway restart
   would invalidate harness-cached client registrations). The owner wants **something
   very simple — no overcomplication, no database**. The author figures out the
   details/mechanism and specifies its loss semantics explicitly (what a restart means
   for harnesses holding cached client ids).

Everything else in the paused package is unchanged and remains pending the same pause's
go.

---

## Resolution — 2026-10-18 (authoring pass, fresh author, per the agent-freshness rule)

All three parts implemented. No owner decision was re-opened: the DCR default stays
OFF, and PoC C's five criteria are unchanged in content (its group was renumbered
8 → 9 to make room for the DCR verification group before it). The review-round
records were not touched.

### 1. Durable DCR registration storage — mechanism chosen

**One JSON file in a mounted volume** (the simplest thing that survives a restart —
no database, no lock manager, no schema): `DCR_STORE_PATH` (container default
`/data/dcr-registrations.json`), bind-mounted on the gateway's compose service; a
flat client-id → record map (`client_id`, `redirect_uris`, `client_name`,
`created_at`; no secret ever stored), loaded at startup, write-through on
registration, saved atomically (temporary file in the same directory + rename,
owner-only file mode — a crash can leave a temp file, never a half-written store).
**Corruption** → startup refusal with an operator-facing error naming the path
(fail loudly, not silently empty — recovery is one command: rename the file aside,
restart, harnesses re-register). **Cap** `DCR_MAX_REGISTRATIONS` (default 1024):
refusal at the cap with existing registrations untouched (eviction would be the
dropped-store loss again, but silent); no expiry. **Flag** `DCR_ENABLED` (default
off) gates the endpoint AND DCR resolution; the store is preserved but dormant while
off — re-enabling restores every registration as it was. **Loss semantics:** a lost
or reset store makes every DCR client id stop resolving; a harness holding a cached
id gets the unregistered-client rejection on its next authorization request, then
re-registers and proceeds — self-healing, one round-trip, no human action; issued
tokens are self-contained and unaffected; CIMD (client-owned document) and
pre-registered clients (operator config) have no gateway-side registration state to
lose. **Why only DCR records are durable:** flow records (10-min TTL,
plain-language error page + one-command retry — durability buys nothing), the code
replay cache (5-min, single-use, PKCE-bounded), and the refresh denylist (bounded
by `refreshTtl`) stay in memory by design; issued tokens live nowhere.

**Homes:**
- `design.md`: new decision **D11** (mechanism, corruption handling, cap, flag
  semantics, loss semantics, state-inventory interaction table); D5 pointer;
  risks bullet (only in-flight state is lost on restart); rollback note (the store
  file can be left or deleted); traceability row (CR-2, SR-6); OQ-1 (the Redis HA
  step now includes the registration store).
- `specs/mcp-signin/spec.md`: new requirement "DCR registration records are durable
  across restarts" (scenarios: registration persists across restart; corrupt store
  refuses startup; lost store self-heals via re-registration; cap reached); the
  "DCR off by default" scenario sharpened to the documented disabled-error (404,
  no advertised registration endpoint).
- `tasks.md`: 2.2 (env placeholders), 2.3 (mounted volume), 3.3 (no registration
  endpoint advertised while DCR is off), 3.5 (disabled-error branch; persist through
  the store before responding; `redirect_uri` validated against the stored record),
  **new 3.6** (store implementation + unit-test verification; old 3.6–3.8
  renumbered 3.7–3.9), 3.9 (docs: store settings, corruption recovery, loss
  semantics).
- `proposal.md`: capability summary ("gated DCR with durable, file-backed
  registration records"), What Changes, Impact (mounted volume, no database, loss
  cost).
- `release-notes-draft.md`: both sections.

### 2. DCR test tasks

New tasks group 8 "DCR live verification (the config-gated fallback, flag on and
off)" — placed after the compose-boot gates (group 7) and before PoC C, with the
group header stating a DCR failure is a change defect, not a design falsification:
8.1 negative control first (flag off → documented disabled-error 404 + no advertised
registration endpoint); 8.2 enable in `.env`, surface + registration checks
(refusal without `redirect_uris`); 8.3 the full authorization flow as the registered
client (redirect-URI rules enforced; machine credentials from `.env` mirroring 1.6's
pattern) through to a **live toolset call** through the front door; 8.4 restart
persistence (no re-registration in between); 8.5 re-disable → disabled-error again
+ store preserved dormant; 8.6 evidence verdict rows in `evidence/dcr.md`, redacted
at capture time. PoC C's group renumbered 8 → 9 with its content untouched;
`design.md`'s BL-2 row updated to "tasks group 9" and annotated with the
DCR-stays-out-of-the-gate rationale. No sixth criterion was added.

### 3. Consistency ripples

All ADDED deltas (the new requirement is an addition; one existing scenario's THEN
sharpened); requirement texts ≤ 500 chars (the new one is 498); no provenance in
spec text; `openspec validate --changes --strict` — **green** (1 passed, 0 failed).
