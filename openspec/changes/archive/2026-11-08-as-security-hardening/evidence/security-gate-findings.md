# Security review gate — findings (gate 8.4)

Reviewer: the independent security-review subagent (gate 8.4), distinct from the
implementer and the author. Review object: the full change diff `git diff f19dcfb..HEAD`
(merge-base = the repaired-master point). Method: falsification of the change's own
security claims (design.md's SIA, the delta spec, and the threat-model delta) against
the built code — every claim below was attacked, not assumed. Code facts were verified
by reading the changed modules and by running an adversarial input battery against the
admission-rule parser (`gateway/redirect_uris.py`) and the publication leak scanner.

## Findings

Three notes, no should-fix, no blocking findings.

### 1. NOTE — DT-EP1-2's "no other user's path is affected" is broader than the mechanism

- **Location:** `openspec/changes/as-security-hardening/design.md`, DT-EP1-2's threat
  table row and mitigation row 4; `gateway/state.py:275-334` (ApprovedClientRegistry).
- **The imprecision:** the row states an attacker flooding the registry "spends their
  own sign-ins for entries keyed to their own subject — no other user's path is
  affected". The registry's cap is **global** across all subjects with oldest-first
  eviction, so entries an attacker writes (or organic growth) *can* evict other users'
  approvals, and an evicted approval forces that user one extra decision-page prompt.
  The security bound itself holds — eviction re-prompts, never bypasses, exactly as the
  same row's fail-safe statement says — so this is a wording precision issue, not a
  defect. The practical cost of the attack shape is high and was verified: each entry
  costs a completed, rate-limited sign-in (30/min per source, 600/min global) with a
  *distinct* registered client (DCR default-off; CIMD origin-allowlisted), and the
  default cap is 10,000 — pushing a specific victim's entry out requires on the order
  of the whole cap in fresh (subject, client) pairs.
- **Evidence:** `ApprovedClientRegistry.approve` evicts
  `next(iter(self._approved))` — the globally oldest entry, whoever owns it;
  `test_limits.py:611` (`test_the_registry_cap_evicts_the_oldest_approval`) pins
  exactly that behavior.
- **Suggested direction:** reword the row to what the mechanism guarantees — "no other
  user's approvals are *writable*; cap eviction can force a re-prompt (fail-safe,
  never a bypass)". No code change.

### 2. NOTE — the checkpoint extends the short-circuit paths' provider-refresh-token dwell on the flow record

- **Location:** `gateway/federation.py:275-313` (`_attribution_gate`),
  `gateway/state.py:126` (`FlowRecord.identity_refresh_token`).
- **The observation:** pre-change, the two short-circuit mint paths (the app kind's
  zero-page short-circuit, the toolset stored-credential short-circuit) called
  `_finish` immediately, which clears `identity_refresh_token` at once. Post-change, a
  first attribution parks the flow at the decision page with the provider's session
  refresh token still on the record, so the record now holds that credential for the
  user's decision time — up to the flow TTL (default 600 s, capped at 3600) where
  before it was near zero on these paths. The consent branch is not a new member of
  this class: pre-change its record already lived through a human-scale decision (the
  upstream consent screen) before the callback consumed it.
- **No stated bound is violated:** retention is TTL-bounded by design
  (`gateway_flow_ttl_seconds`), `FlowStore.get` refuses an expired record (so a late
  approve POST against a TTL'd flow lands on the expired page and mints nothing), the
  deny action drops the material immediately (`_consume_refused_flow`), and the SIA's
  invariant table prices record retention as TTL-bounded. The note records that the
  dwell-time extension on the short-circuits is a consequence the change's documents
  state only implicitly ("TTL-bounded"), not explicitly.
- **Suggested direction:** optionally add one sentence to M31's record naming the
  short-circuit dwell (bounded by the flow TTL, fail-safe on expiry). No code change.

### 3. NOTE — a repeated `state` parameter on `/dial/authorize` is resolved, not refused

- **Location:** `gateway/authorize.py:134` (`state = params.get("state")`), against
  the repeated-parameter discipline the token endpoint carries
  (`gateway/token.py:_form_parameters`).
- **The observation:** `?state=A&state=B` stores and echoes whichever value the query
  parser resolves rather than refusing the ambiguity. This is the authorize surface's
  pre-existing parsing posture (every authorize parameter is read the same way), not
  something this change introduced; the 2048-byte bound and the urlencoded echo apply
  to whichever value is stored, so no injection or bound escape exists; and the
  `state` is the client's own echo token, so the ambiguity can only harm the client
  that sent it — the attacker crafting an authorize link controls the state anyway.
  The change's own claims ("stored and echoed back unchanged") are accurate for every
  single-valued request.
- **Suggested direction:** if the ambiguity is ever tightened, do it for the authorize
  parameter set as a whole (a `_single_string`-style repeated-parameter refusal), not
  as a `state`-only patch. Not this change's scope.

## The claims attacked, and what survived

**Pass 1 — the consent route as the new front door (DT-EP1-1). Survived.**
The route is unauthenticated by design, and the binding is the flow id:
`new_flow_id()` is `secrets.token_urlsafe(16)` — 128-bit CSPRNG, server-side,
TTL-bounded, and never visible to a link-crafter (it crosses only the victim's
browser, on the provider redirect, the callback URL, and the page HTML;
`Referrer-Policy: no-referrer` on every page; the harness redirect carries only code,
`iss`, and the client's own `state` — never the flow id). A cross-site form POST is
deliverable (a simple request, no preflight) but carries nothing the gateway trusts:
grep of the whole gateway package finds zero cookie handling, zero session
middleware, zero CORS middleware — no ambient authority exists anywhere on the
surface. A forged POST without a live flow id lands on the expired page, allocates
nothing, writes nothing (pinned by `test_a_foreign_post_against_no_live_flow_lands_on_the_expired_page`).
The single-use race was attacked directly: from the flow lookup through the
`awaiting_attribution` check-and-clear to the act (registry write, audit,
consume-or-continue), the handler contains **no await**, so two racing POSTs (approve
vs deny, approve vs approve) serialize on the event loop; the loser finds the flag
clear and lands on the expired page. Method/content-type confusion: the route is
POST-only (GET is the framework's 405), the content type must be exactly
`application/x-www-form-urlencoded`, the body is read under `capped_body` (chunked,
refused past the cap), `parse_qsl` does not treat semicolons as separators, a repeated
parameter is refused, the action is compared against the two-token closed vocabulary,
and extra fields are dropped — only the flow id and the action are read, every other
fact re-derived from the record. The route joins the shared limiter (429 page,
`test_the_consent_route_joins_the_limiter`). The on-path race keeps RES-12/RES-1's
existing price, as the SIA states — that attacker already reads tokens off the wire.

**Pass 2 — the decision page as injection/attribution surface (DT-EP3-1/2/3). Survived.**
Every interpolated value (`client_name`, `client_id`, `resource`, `redirect_uri`,
`flow_id`) passes `_escape` (`&`, `<`, `>`, `"`); every attribute context in the
template is double-quoted; the flow id is server-generated URL-safe base64. No
injection vector found. The page is built through the one shared builder, so the
family is inherited by construction: `default-src 'none'` (no script source at all),
style pinned by a hash computed from the served text, `base-uri 'none'`,
`frame-ancestors 'none'` + `X-Frame-Options: DENY`, and the new family-wide
`form-action 'self'`. The form's action is the fixed literal `/dial/consent`; even
hypothetical injected markup could not submit off-origin. The page does not
auto-continue — no `meta refresh`, nothing that navigates (the interstitial's 1-second
refresh is retained by design and disclosed everywhere; the no-auto-continue claim is
decision-page-scoped in the design and the spec, and that scope holds). DT-EP3-3's
compensating bound is present: the registrant-supplied name is presented as a name,
with the client id and the **full registered `redirect_uri`** beside it — the two
facts a registrant cannot falsify to the page's advantage.

**Pass 3 — the registry as escalation surface (DT-EP1-2). Survived, with finding 1.**
Exactly one write path exists (`gateway/federation.py:475`, the approve branch —
package-wide grep confirms no other caller). The subject is derived from the flow
record's provider-verified claim snapshot, never from the request, so a cross-subject
write is structurally impossible: the only entry any POST can create is the one the
flow's own user could create. The empty-subject refusal holds twice — `is_approved("",
client_id)` is False (re-prompt, fail-safe) and `approve("")` writes nothing. The cap
is real and tested (10,000 default; oldest-first eviction; idempotent re-approval
does not refresh age, so an attacker cannot keep their own entries young while
victims' age). Cap-eviction gaming reduces to a re-prompt flood at a cost of one full
rate-limited sign-in per entry with a distinct registered client — finding 1's
wording note is the only thing this pass dented.

**Pass 4 — the admission rule's bypasses (DT-EP1-5 / M32). Survived.**
All four sites are real and on the only paths that reach client resolution: the DCR
body check (`gateway/routes.py:_redirect_uris_refusal`, upstream of
`registrations.add` — the store never receives an unvalidated URI), the CIMD document
validation (`gateway/cimd.py:_document_client`, refused whole; the cache stores only
validated resolutions), the pre-registered startup refusal
(`gateway/settings.py:_require_admissible_redirect_uris`), and the DCR store's
load-time validation (`gateway/store.py:_refuse_inadmissible_record`, corrupt-store
discipline). No fifth path exists: resolution is CIMD-cache → pre-registered → store,
each validated at its own admission moment. The parser was attacked empirically — a
27-case adversarial battery run against `scheme_admission_refusal`/`loopback_target`:
`localhost.evil.com`, `127.0.0.2`, decimal/hex/octal IP forms (`2130706433`, `0x7f.1`,
`0177.0.0.1`), percent-encoded hosts (`loca%6Chost`), null-byte hosts, userinfo spoofs
in both directions (`localhost@evil.com` and `evil.com@localhost` — the latter
refused because userinfo is rejected even toward loopback), trailing-dot localhost,
long-form IPv6, IPv4-in-brackets, schemeless and non-http(s) schemes, and the empty
string are all refused; the only admitted non-https forms are `localhost`,
`127.0.0.1`, and `[::1]` in their case-normalized spellings, any port — none routable
off-host. The rule and the loopback matching now read one copy
(`gateway/redirect_uris.py`, a leaf module), so the sites cannot drift. The refusals
name the offending URI and the rule only — no secret material.

**Pass 5 — the revocation's correctness (DT-EP1-6 / M33). Survived.**
The denylist call is reachable on exactly the replay path: `claim()` failure →
`_revoke_the_tokens_this_code_bought` → `TokenDenylist.revoke`, and every refresh
grant consults the denylist (`_validated_refresh_claim` → `is_revoked`) — the revoked
jti refuses `invalid_grant` at its next presentation. The clocks are consistent per
store (the replay memo's liveness on `time.monotonic()`, the denylist and the
recorded token expiry on wall clock — no cross-clock comparison exists). The
DoS-by-crafted-replay shape was attacked and closed: the replay detection sits
**after** PKCE verification in `_validated_claim`, so an attacker holding only a
stolen code (no verifier) never reaches the revocation — the victim's refresh token
cannot be denylisted without the full code+verifier pair, and whoever holds that pair
is exactly the RFC 9700 §4.2.4 actor the rule exists to answer. Whose code maps to
whose jti: both values are gateway-minted identifiers recorded only by the code grant
— no caller-supplied value enters the mechanism. The memo-cap eviction shape was also
attacked: evicting a claimed entry would require ~100,000 distinct *valid* codes
inside the 300-second code TTL (the cap is 100,000), while the global rate limit
admits at most ~3,000 requests in that window — unreachable; and even a hypothetical
eviction is closed a second time by the consuming custody seam
(`pending_custody.take`), which refuses the second grant fail-closed. Both disclosed
partials (the access token ages out; an already-rotated successor survives) are
exactly what the code does — no more is claimed than is bought.

**Pass 6 — the state bound and echo (DT-EP1-3 / D8). Survived, with finding 3.**
The 2048-byte refusal lands in `_validated_flow`'s first check — before client
resolution, before `flows.create` — so no record exists and no state is allocated
(pinned by `test_an_oversized_state_is_refused_before_a_record_exists`); the refusal
is answered directly, never redirected, so the oversized value is never echoed. The
echo is the stored value urlencoded into the final redirect — decoded byte-identical,
no injection into the redirect (the `urlencode` boundary). The refusal audits the
class (`oversized_state`), never the value. The repeated-parameter ambiguity is
finding 3 — pre-existing posture, no bound escape.

**Pass 7 — the evidence files. Survived.**
The leak scanner passes on tracked files (`PASS`, 3 waived pre-existing findings, 0
unwaived). The c2p5 evidence is untracked, so it was eyeballed and pattern-scanned
independently: no JWT-shaped strings, no bearer tokens, no authorization codes, no
personal paths, no real issuer/tenant/org values; the only hostnames are the local
compose fixture's own (`localhost`, `keycloak:8443` — both present in tracked files
at the merge-base, so no new internal-name exposure), subjects are redacted
(`<redacted-subject>`), and the probe's login credential is sourced from `.env`
(`TEST_USER_NAME`/`TEST_USER_PASSWORD` via `require(env, ...)`) — never argv, never
printed (the capture logs the HTTP status only).

**Pass 8 — the diff's hygiene. Survived.**
No provenance or process-artifact comments in the `gateway/`, `scripts/`, or `router/`
diff (grep for owner/change-folder/stage/designation/date references over the added
lines: zero hits — comments carry behavior and reason). `.env.example` gains one
documented placeholder setting (`GATEWAY_APPROVED_CLIENTS_MAX=10000`), no values. No
real issuer/tenant/hostnames in `docs/gateway-configuration.md`'s additions. No debug
or secret material anywhere in the diff.

**The never-cut invariants. All preserved.** The upstream token and the upstream PKCE
verifier never leave Core (the checkpoint reads and renders only the gateway's own
flow facts — no upstream field reaches the page, the route, or the record it writes).
Per-user credential isolation is strengthened: T1-25's cross-user mint is the
violation the checkpoint removes, and the registry key is the provider-verified
(subject, client) pair. DIAL authorization still runs before the checkpoint on every
path (the read precedes the gate; a refused user never reaches a decision page —
pinned by `test_an_approval_covers_the_client_across_resources`'s 403 branch). No
credential reaches logs, argv, or errors: the three attribution events carry
identifier facts only, and `client_name` was correctly added to the audit trail's
truncated caller-fact fields. No new secret material or hardcoded credentials exist
anywhere in the change. `REGISTRY_CLAIMS` gains `auth_time` — a copy-rule narrowing
inside the mint.

**The checkpoint's placement claims. Survived.** The gate renders on first
attribution on all three mint paths — the app kind's zero-page short-circuit
(`_run_identity_leg`'s AppLegResult branch), the toolset stored-credential
short-circuit (`_toolset_after_read`'s signed-in branch), and the toolset consent
branch (after `upstream_authorization`, with the continuation stored on the record) —
and no mint path bypasses it. No operator bypass exists: the gate consults the
registry alone; no setting, source, or pre-registration key can skip the page (pinned
by the spec's scenario and the code's shape). The router's alternation carries the
`consent` segment in lockstep with the probe battery, and `consent` joined the
reserved toolset names.

**D14's member. Survived.** `authorization_response_iss_parameter_supported: true`
lands in the fixed AS-metadata document — a trueness member, no behavior change.

## Verdict

**PASS.** No blocking findings, no should-fix findings. Three notes (findings 1-3),
each a documentation-precision or record-completeness item with no code change
required. Every security claim in the change's SIA, delta spec, and threat-model
delta was attacked by the passes above and held; the two imprecisions found (findings
1 and 3) are in prose adjacent to claims, not in the claims' mechanisms, and the one
behavioral observation (finding 2) sits inside bounds the change already states.
