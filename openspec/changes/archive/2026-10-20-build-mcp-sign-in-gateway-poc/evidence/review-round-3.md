# Review round 3 — findings and resolutions (owner-change-request-1 delta)

Reviewer: independent opus subagent, fresh pass, verified against the files (not the
resolution narrative). Verdict: **pass** (0 BLOCKER, 0 MAJOR, 4 MINOR — consistency
ripples and unacknowledged-exposure namings; none blocking at the repo's bar for a
default-off v1 fallback). `openspec validate --changes --strict` run by the reviewer:
green.

## Owner ruling fidelity — verified by the reviewer

1. DCR default OFF preserved everywhere (spec scenario, D11, tasks 8.1/8.5, release
   notes, `.env`/startup defaults).
2. DCR proven as tasks with their own evidence, NOT a sixth PoC C criterion — final
   requirement still exactly five criteria; group 8 header states a DCR failure is a
   change defect, not a design falsification; BL-2 row updated with the rationale.
3. Storage is genuinely simple v1 (one JSON file, flat map, four fields, no secret,
   atomic save, cap-refuse, no expiry, no locks/schema) — consistent with the
   background design's no-database rationale; the Redis HA step covers the store.

## Findings

### MINOR-1 — Migration Plan omits the new group 8
- design.md `## Migration Plan` names eight stages for nine task groups; the DCR
  live-verification group is missing from the implementation-order line.
- **Fix:** add "→ DCR live verification → PoC C".
- **Resolution:** design.md `## Migration Plan` implementation-order line now reads
  "… deployment configuration → static/compose-boot gates → DCR live verification →
  PoC C." — the line now names all nine task groups.

### MINOR-2 — Store tamper handling silent; the durable file is not in the security impact analysis
- D11 handles *corruption* (loud refusal) but not *tampering*: a well-formed edit
  (redirect_uri injection into an existing record) passes the corrupt-store refusal
  and yields persistent redirect manipulation. Owner-only file mode bounds the
  accidental case, not the malicious one. Host/volume write access is the same trust
  boundary as the injected signing key (also not tamper-protected), so no mechanism is
  required at this bar — but the exposure is unstated.
- **Fix:** one sentence (D11 or the impact analysis) naming the boundary: store
  integrity trusted to the host/volume owner, same class as signing-key material;
  tamper recovery is the corrupt-store path (rename aside, restart, re-register).
- **Resolution:** design.md D11 gains a bullet after the corruption bullet ("Tampering
  is trusted to the same boundary as the signing key"): store integrity is the
  host/volume owner's responsibility — the same trust boundary and the same class of
  material as the signing key, which host-level write access can likewise rewrite —
  so no tamper mechanism is added at this bar, and a well-formed tampered store is
  recovered by the corrupt-store path (rename the file aside, restart, harnesses
  re-register).

### MINOR-3 — DCR registrant-controlled `client_name`/`redirect_uris` spoofing surface unacknowledged
- The interstitial prefers the registration's `client_name`; a DCR registrant controls
  both it and the redirect URIs; no normative bound (allowlist/loopback/https rule)
  on DCR-registered redirect URIs exists. Exposure is bounded (flag default off,
  rate limits, live IdP login + DIAL authorization check, tokens only to the
  registrant's own redirects) but "when DCR is enabled, interstitial attribution is
  registrant-supplied" is acknowledged nowhere.
- **Fix:** an acknowledgment line (D11 or the impact analysis) that enabling DCR
  accepts open registration and registrant-supplied display attribution.
- **Resolution:** design.md D11 gains a bullet after Flag semantics ("What enabling
  DCR accepts"): enabling DCR accepts open registration and registrant-supplied
  display attribution — the interstitial's `client_name` for a DCR client is
  registrant-controlled, and no allowlist bounds a DCR registration's redirect URIs —
  bounded by the flag's default off, the public-endpoint abuse bounds, the live
  identity-provider login and DIAL authorization check every token still requires,
  and codes and tokens only ever reaching the registrant's own registered redirect
  URIs.

### MINOR-4 — Two D11 properties and one scenario have incomplete homes
- (a) persist-before-response: tasked (3.5) but not normative in the spec requirement;
  (b) store-dormant-while-disabled / restored-on-re-enable: stated in D11 and verified
  live (8.5) but no spec scenario covers it; (c) the "Lost store self-heals" scenario
  is normative but never exercised (no unit or live test deletes the store and walks
  rejection → re-registration).
- **Fix:** fold (a)/(b) into the requirement's text or scenarios; add one verification
  clause for (c) (3.6 unit test or a group-8 live check).
- **Resolution:** (a)/(b) are normative as scenarios in the delta spec's DCR
  durability requirement: "Registration persisted before the response" (the record is
  written to the store before the response is returned) and "Store dormant while DCR
  is disabled, restored on re-enable" (preserved unchanged while disabled, every
  registration resolves again on re-enable); the requirement text is unchanged and
  ≤500 chars, all deltas ADDED. (c) is tasked in tasks.md 3.6's verify line: a
  lost-store self-heal unit test — after a registration, delete the store file and
  load a fresh app instance over the missing store, see the cached client id
  rejected as unregistered on its next authorization request, then re-register
  through the endpoint and see acceptance restored (the spec's lost-store
  self-heal scenario).
