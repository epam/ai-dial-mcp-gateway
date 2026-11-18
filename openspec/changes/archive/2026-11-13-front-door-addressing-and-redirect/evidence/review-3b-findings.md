# Independent review 3b — findings record

Reviewer: independent opus pass (fresh agent), 2026-11-13. Scope: the complete change
folder against CLAUDE.md, PROCESS.md, ROADMAP.md, the security-analysis skill, the main
spec (all 1330 lines), docs/routing.md, gateway-configuration.md, local-environment.md,
pod-contract.md, threat-model.md; claims cross-checked against the gateway code,
router/nginx.conf, docker-compose.yml, dial-core @ 894328d6, ai-dial-chat @ e09fc75b3.

**Verdict: not ready for the owner pause as-is.** The evidence base held under every
falsification attempt; B1/B2/S1–S5 are wording-plus-probe-row fixes, not design rework.
Address the Blockings (and S1–S5; notes at the author's discretion), re-review the
amended text, then the package is ready for 3c.

## BLOCKING

### B1 — the raw-URI map's match domain (the query component) is unstated, and both naive implementations break a normative property
- Where: design.md D3 ("anchored to the kind's prefix and `/mcp` suffix"; "the query string rides `$is_args$args` as today"); tasks.md 5.1; delta spec ADDED "Resource paths are the front door's addressing vocabulary" (the wire-form grammar sentence); design SIA T-EP6-c mitigation.
- Problem: `$request_uri` includes the query string. A pattern anchored `$` after `/mcp` never matches `/dial/{path}/mcp?sessionId=<id>` — every streamable-HTTP session-resume request is 404'd, contradicting the retained "Query string survives routing" requirement in both namespaces and PoC criterion (d). An unanchored pattern instead matches `/dial/x/mcp/foo` and forwards it as `/v1/toolset/x/mcp` — path aliasing, violating the delta's own "the router's capture MUST be a grammar, not a wildcard" clause. The correct pattern — `^/dial/(GRAMMAR)/mcp(\?.*)?$`, end-of-URI anchored with an optional query tail and nothing after `/mcp` but the query — is nowhere stated. The probe evidence proves it can work (Part 3: `…/mcp?sessionId=abc%2F1` reaches the upstream with `%2F` intact) but the probe's recorded grammar (Part 2) never mentions the query component.
- Required fix: one clause in the delta spec's addressing requirement (the map's match domain is the whole raw request URI, optional `?query` tail, nothing after `/mcp` but it); the same statement in design D3 and tasks 5.1; the probe's grammar recorded; two probe rows (query-bearing request routes with the parameter intact; a post-`/mcp` path tail refused 404).

### B2 — the "two encodings of one rule / cannot drift" parity claim is falsified by the package's own grammars
- Where: delta spec ADDED "Resource paths are guarded at request time" closing paragraph; design.md D4 ("One grammar, two encodings of it"); SIA T-EP6-a mitigation ("the grammar is stated once … implemented twice against it").
- Problem: the router's wire grammar admits every `%XX` escape, so `/dial/a%7Bb/mcp` (or `%22`, `%01`, over-depth) is grammar-conforming and forwarded on the data path, while the gateway's decoded guard refuses the same resource on every gateway surface. An unauthenticated call gets the router-synthesized challenge naming a document the gateway answers 404. The two grammars are a routability filter (wire form) and an authority (decoded form) with a real, reachable asymmetry class — not two encodings of one rule. Task 8.2's lockstep rows cover only shapes where the two agree; the encoded-forbidden class would fail the row if added, and is absent.
- Security-neutral outcome (Core refuses these names too — the dead-end challenge hurts no real resource) does not save the spec text: the owner pause would approve a stated invariant the design's own grammar pair violates, and the drift detector as tasked cannot detect the drift it claims to.
- Required fix: state the division of labor precisely (map = routability filter over the wire form; guard = authority over the decoded form; a wire-conforming spelling whose decoded content the guard refuses is forwarded on the data path and refused at discovery/authorize; its challenge dead-ends at a 404 document by design — same-answer-as-Core in outcome), and either drop the "two encodings of one rule" sentence or add probe rows asserting the documented asymmetry.

## SHOULD-FIX

### S1 — decoded-`/`-in-segment: two contradictory rulings inside one delta paragraph
- Where: delta spec ADDED addressing requirement, matrix paragraph — "segments carrying Core's forbidden characters (`/`, `{`, `}`, `"`, control ≤ U+001F) and trailing dots … refused as parity" beside "a `%2F` inside a segment — forwarded byte-faithfully for Core to answer".
- Problem: raw `/` is unreachable on the wire (it IS the separator), so `%2F` is the only reachable spelling of a decoded-`/` segment — the adjacent sentences rule the same decoded content oppositely. The operative path-guard's forbidden set omits `/` (coherent: verified Core's `isValidFilename` refuses decoded `/` at resolution, so refusal happens at Core — same-answer behavior).
- Required fix: pick one story — decoded-`/` rides the `%2F` ruling (not guard-refused; forwarded; Core answers); `/` comes out of the "refused as parity" list (or is marked unreachable-raw).

### S2 — the trailing-dot "parity" claim misattributes a creation-time rule as resolution-time
- Where: design.md D4 ("no trailing dot — Core's own rule, at every segment"); the matrix's "Resolution-time constraints" framing (evidence/finding-f2, core-resource-addressing-matrix.md); delta spec ("Core's own trailing-dot rule, refused as parity").
- Problem, verified in Core: `isValidResourcePath` (the trailing-dot refusal) is called only from `ResourceController`/`UploadFileController` (write/upload). Resolution routes (`fromEncoded` → `fromAnyUrl`) check only forbidden chars and the 900-byte bound — a trailing-dot name that exists on the blob store resolves on Core's own port. `ENTITY_NAME_PATTERN` even admits trailing dots for non-toolset entities. So the front-door refusal is deliberately stricter than Core's resolution and contradicts the folders cell's own ruling ("the front door serves whatever Core resolves; no cell is closed by us").
- Required fix: restate honestly — a front-door rule matching Core's creation-side constraints, stricter than Core's resolution, offered to the owner pause as a ruling (or drop it from the guard).

### S3 — the canonical encoder's decode discipline is unpinned; the identity rule has an unstated failure mode
- Where: design.md D4 ("a pure decode-validate-reencode"); tasks 1.2; the delta's canonical-encoding paragraph.
- Problem: nothing states UTF-8 strictness, `unquote` vs `unquote_plus`, or invalid/non-shortest-sequence handling. Python's default `unquote(errors='replace')` maps every invalid byte sequence to U+FFFD, so distinct wire spellings (`%FF`, `%FE`, `%C0%AF`) canonicalize to the SAME identity — aliasing's merge direction (two caller-chosen strings, one resource, one token audience); `unquote_plus` would additionally collapse `+` into a space in path position. U+FFFD itself passes the guard's forbidden set. No unit row in tasks 1.2 covers invalid UTF-8, over-long encodings, or CESU-8 surrogates. (No split-identity exists — decode→validate→re-encode with split-then-decode is order-safe; this is the one hole.)
- Required fix: state the decode rule in the grammar (strict UTF-8; an invalid or non-shortest sequence refused with the guard's fixed reason; `+` literal in path position) and add the unit rows.

### S4 — T-EP3-b's named mitigation has no home task
- Where: design SIA T-EP3-b mitigation 6 ("the shared builder's existing escape discipline, with unit rows extended to path-shaped, percent-encoded inputs decoding to markup-shaped bytes") vs tasks.md — no row names the page-interpolation unit rows (sites: `flow.py` `_DECISION_PAGE`/`_INTERSTITIAL`, `_escape(flow.toolset)` at flow.py:565, note pages at :687-689).
- Required fix: add the row (or fold it into tasks 3.4/3.5 naming the pages).

### S5 — the 900-byte bound's attribution is imprecise, and the adoption is silently stricter than Core's
- Where: design D4 and the delta spec ("the whole decoded path ≤ 900 UTF-8 bytes — Core's whole-resource-URL bound").
- Problem, verified: Core's `MAX_PATH_SIZE = 900` applies to the absolute file path (`bucketLocation + relativePath`, e.g. `public/{name}` — ResourceDescriptorFactory.java:72), not the resource URL (`toolsets/public/{name}`). The front door caps the longer string — stricter by the type segment's length, a small unacknowledged cut at the 890–900-byte edge.
- Required fix: state the adoption as deliberate (or align the semantics); correct the attribution either way.

## NOTES

- **N1** — D7 step 1's rationale: precisely (DynamicResourceRegistrationStrategy.java:100), Core stores the first entry of the upstream's DCR **response**; the ordering argument survives because conforming DCR servers echo the registered list in order. Name the response-echo fact in the runbook.
- **N2** — wording stragglers in the main spec: the checkpoint requirement's "served name" and the HTML-family requirement's decision-page scenario ("the resource name") read stale under the path vocabulary; a declared re-pin (name→path) keeps the next sync from tripping. (The reviewer's full sweep found no other stragglers — all 14 touched requirements' scenarios are accounted for in the delta.)
- **N3** — proposal Impact says "`.env.example` (no new settings …)" while tasks 1.1 adds the segment-count cap (default 32). Reword.
- **N4** — implementability trap: FastAPI path parameters arrive decoded; the echo-offered rule needs the raw spelling (`request.scope["raw_path"]`); no task names it, and routes.py's single-segment captures must become multi-segment.
- **N5** — pre-existing doc lag task 6.2's rewrite should absorb: docs/routing.md's location-map alternation (line 23) and reserved-names list (line 47) omit `consent`, which nginx.conf (line 148) and settings.py carry.
- **N6** — ReDoS discipline: the load-bearing detail — `%` must be EXCLUDED from the raw unreserved class so the `%XX` alternative is unambiguous — is implied, not stated. One clause in tasks 5.1 closes it.

## Claims tried and falsified that HELD (checked, not skipped)

nginx mechanism properties (decoded/normalized location matching, no re-escaping of variable proxy_pass, `$request_uri` raw incl. args, the `if`+`return` documented-safe form, `large_client_header_buffers` default 4×8k — on the exact compose image nginx:1.27-alpine); Core dual lookup (leg a/leg b, 404 "Unknown deployment"/403 "Forbidden deployment" verbatim); per-caller Base58 bucket (AES/CBC + Base58, decrypt-only-with-secret; ciphertext already client-visible); DCR-registers-the-whole-allowlist (DynamicResourceRegistrationStrategy.java:114-121); exchange-time validation accepts any allowlisted presented redirectUri (TokenService.resolveRedirectUri/isAllowedRedirectUri); repair API preconditions; route templates at HEAD 894328d6; creation-time classes (`RESOURCE_KEY_PATTERN ^[A-Za-z0-9-_]+$` at HEAD; live older build noted honestly; `ENTITY_NAME_PATTERN ^[A-Za-z0-9._%:-]+$`) — the pushback on the forbidden-set framing is correct; Core's echo rule (WellKnownResourceMetadataService.resolveResource builds `resource` from the request path); Chat overwrite (authorize-url.ts:8-9, ToolsetApplicationEditor.tsx:162 at e09fc75b3); admin/platform-bucket access (AccessService.java:218-230); F1/F2 diagnoses vs the code (flow.py:259/308/355; settings.py:111, :789-830, :709-752; nginx.conf:156/192); threat-model delta hooks (T5-3, T6-2, T6-7, RES-16, RES-7); publication discipline (change folder clean — placeholders only; blocking-zero); SIA conformance (all seven never-cut invariants ruled; MEDIUM justified); security falsification passes that held (reserved-name first-segment scoping; canonical identity — one hole is S3; user-bucket isolation; prefix-capture leakage; challenge-header quoting; the `%2F` same-answer principle with the live probe row honestly deferred as open question 3); owner mandates (matrix complete cell-by-cell; no Chat/Admin regression path; three-callback runbook; failing-first instrument in tasks 8.1/9.4).
