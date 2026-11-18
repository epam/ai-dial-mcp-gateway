# Security review gate — `dynamic-toolsets-and-fresh-claims`

Reviewer: independent security-gate subagent (PROCESS.md step 5.4 / CLAUDE.md gate 4).
Scope: the full uncommitted diff vs HEAD (gateway/**, tests/**, scripts/**, .env.example,
docker-compose.yml, router/, docs/, the change folder), read against the change's SIA
(`design.md` §§2–7, impact level **Medium**) and the landed threat model
(`docs/threat-model.md`). Depth: Medium — full attention on the changed surfaces. The
suite was re-run by this reviewer on the current tree: **499 passed, 1 skipped** (the
recorded gate run predates the pre-restart-code fix; the current tree is green with it).

## Findings

### F1 — MAJOR — the priced record-volume bound does not exist at the discovery guard site

`gateway/routes.py:76-99` (`protected_resource`). DT-EP1-3 (design.md §5) prices the
guard-refusal record volume and names its control: "the per-source and global rate limits
cap the record rate the same way they cap the request rate (spec — unchanged)"; the delta
spec (`specs/mcp-signin/spec.md`, the abuse-bounds section) says discovery's "endpoints
are unauthenticated and rate-limited as today". The protected-resource route has **no
limiter call** — neither in this diff nor before it (the pre-change route wrote
`unknown_toolset` records unlimitered for unmapped names; there is no app-level
middleware, and `router/nginx.conf` has no `limit_req`), so "as today" is not a bound —
there is no bound there today.

*Scenario:* an unauthenticated attacker loops
`GET /.well-known/oauth-protected-resource/dial/<guard-failing-name>/mcp` at network
rate; every request writes one `flow_refused` record (~200–350 B, fixed vocabulary, name
truncated to 256) to the container log. No credential, no state, no outbound call — the
gain is exactly the priced one: log-volume growth the operator does not control (at even
1 k rps, ~1 GB/hour), plus the request capacity itself. `/dial/authorize`, `/dial/token`,
and `/dial/{name}/status` share the limiter; this, the fourth guard site, does not.

*Remedy (either, before commit):* add `runtime.limiter.allow(...)` + the 429 shape to the
route (one line; the limits — 30/min per source, 600/min global — cannot break a
harness's one-fetch-per-toolset discovery), or re-price DT-EP1-3 and the spec sentence to
state that the discovery surface is unlimitered by design and accept the volume as
bounded only by content. A prose bound the code does not have is exactly the
"mitigation that exists only in prose" the repo refuses to call landed.

### F2 — MAJOR (gate, not code) — task 3.3, the two-harness token-store round-trip, is still open

`openspec/changes/dynamic-toolsets-and-fresh-claims/tasks.md` (3.3, unchecked);
`evidence/live-runs.md` states it is "NOT in this pass — it needs real harness sessions
the owner drives". G5 and DT-EP1-9 price it as "the live two-harness round-trip gate
before adoption — a gate, not a follow-up": the grown, custody-carrying refresh token
must be proven to survive Claude Code's and Cursor's token stores through a full
sign-in → refresh cycle before this change is adopted. It has not run. Under the repo's
own gate order (commit locally; push only after the change's gates pass), this must be
discharged — or explicitly deferred by an owner ruling recorded in the change folder —
before commit/push. No code change required; the size bound, the re-priced body cap, and
the startup coupling check are all in place (verified below), so the residual is the
undriven gate itself.

### F3 — MINOR — the carrier discipline is write-side only; the copy path can carry a `custody` member

`gateway/tokens.py:132-147` (`copied_claims`) and `:282-293` (`claims_for_tokens`) strip
only `REGISTRY_CLAIMS` / `_CODE_BINDINGS`. A provider answer carrying a member named
`custody` (the forgery class DT-EP5-1 already prices — any claims for an existing `sub`)
would be copied verbatim into the minted **access token** and the **code JWT**, which the
delta spec forbids in the only way this gateway's own code can produce it. Inert in
effect: nothing reads `CUSTODY_CLAIM_MEMBER` off anything but a refresh token (the
refresh grant alone decrypts, behind the type check), so no exploit follows — but the
"refresh token only" property should be structural, not a convention of the mint
functions. *Remedy:* add `CUSTODY_CLAIM_MEMBER` to the stripped set in both functions.
Cheap; recommended before commit, acceptable as a noted residual with a follow-up
spec row.

### F4 — MINOR — the short-circuit leaves the provider refresh token in the flow record until TTL

`gateway/federation.py:117-119` (short-circuit → `_finish`), `_finish` at `:266-286`,
`gateway/state.py:143-150` (`discard_identity_token` drops only the access token), and
`state.py`'s module docstring claiming the short-circuited record is "TTL-bounded and
**identity-free**". It is not: `identity_refresh_token` — the flow's most powerful
credential — stays in the FlowStore until the flow TTL prunes it (and after the discard,
`identity_expired()` no longer accelerates the prune, since it returns `False` when the
access token is `None`). On the consent path the record is destroyed at the upstream
callback; the short-circuit path retains the credential minutes longer than the flow
needs it. Exposure is in-process only, and I traced the replay shapes to ground: a
replayed identity callback cannot re-exchange (PKCE verifier bound), and a replayed
upstream callback fails closed at `complete_upstream_leg`'s missing-identity refusal —
no reachable abuse. But the retention is not what DT-EP4-1 prices (the plaintext exists
in `encrypt`/`decrypt`, once at the grant's outbound presentation, plus the pending
entries) and the docstring is false. *Remedy:* clear `identity_refresh_token` and
destroy the record in `_finish` (the pending entry already holds the hand-off copy).

### F5 — MINOR — the refresh-answer size cap is checked after the body is fully buffered

`gateway/idp.py:301-342` (`_post_refresh`): `len(response.content) > _RESPONSE_MAX_BYTES`
runs after `httpx.post` has buffered the whole response, so the docstring's claim that "a
chunked or lying provider cannot make the gateway hold more than it agreed to" is wrong
in direction — the cap bounds what is *parsed*, not what is *held*. The threat sits on
the trusted internal leg (the same leg and trust the pre-existing exchange
`_post_token` already occupies, with no cap at all), and DT-EP5-1's cat-6 control
("size-capped and schema-checked before any claim is read") is satisfied in the
before-any-claim sense. Noted residual: fix the comment, or read the response streamed
under the cap.

### F6 — MINOR (pre-existing, unchanged by this diff) — the grace-window docstrings disagree with the code

`gateway/state.py:392-402` (`in_rotation_grace`) says a grace-window presentation "gets
an access token and **no replacement**"; `gateway/token.py:673-720` (`_apply_rotation`)
mints a replacement unconditionally (its own docstring — "gets the same treatment" — is
the accurate one). Behavior is identical to HEAD (verified against `git show
HEAD:gateway/token.py`), so it is not this change's defect; with custody, the grace
presentation on a per-grant-rotating provider now fails at the provider with the
`idp_session_ended` class — priced in the spec ("consumed by a lost rotation"). Note
only; reconcile the `state.py` docstring in a docs pass.

Trivial: `docker-compose.yml` comment typo "requestng" (line ~55).

## The never-cut invariants — verdicts

1. **The upstream credential never leaves Core — Preserved.** The short-circuit reads a
   *status* only (`gateway/core.py` `ToolsetStatus`; `gateway/federation.py:117`); the
   one credential call is `complete_upstream_leg` with the literal
   `credentialsLevel: "USER"` (`gateway/flow.py:317-323`); no path in the diff sends any
   other level, and no path reads or transits a stored upstream credential.
2. **The upstream PKCE verifier never leaves Core — Preserved.** The settings projection
   is consumed unchanged (`gateway/core.py:265-309`); the verifier is never a projected
   field; the consent URL is built from Core's public challenge
   (`gateway/flow.py:272-283`).
3. **Per-user credential isolation — Preserved, with the stated use-vs-establish
   delegation.** The custody seam checks the envelope's embedded `sub` against the
   refresh token's signed subject (`gateway/custody.py:230-233`), so a blob swapped
   between users' tokens refuses; the provider-side `sub` cross-check binds every mint —
   issuance (claims from the verified identity token) and refresh
   (`gateway/token.py:659-660`); the global-level short-circuit never establishes at
   GLOBAL (the credential call stays USER-level on every establishing path, verified).
4. **DIAL authorization applies to every toolset call — Preserved.**
   `read_toolset_for_flow` — the 403-refusing per-user read — runs inside
   `complete_identity_leg` on every path, the short-circuit included
   (`gateway/flow.py:221`); the impossible branch and the consent branch both sit behind
   it; Core's per-call authorization on minted tokens is unchanged, and claims are now as
   fresh as the last refresh (no snapshot exists to serve — see 5 below).
5. **No credential in logs, argv, or error messages — Preserved**, with the SIA's
   disclosed M13-style amendment (the *ciphertext* is delivered, by design, inside the
   refresh token). Verified: every new refusal is fixed text with a fixed-vocabulary
   audit token; facts are truncated at the `_emit` boundary (`gateway/audit.py:66-99`);
   `Identity`'s tokens and `FlowRecord.identity_refresh_token` are `repr=False`
   (`gateway/idp.py:148-149`, `gateway/state.py:117`); httpx failures report the
   exception *type* only, never the message; the custody plaintext exists only inside
   `encrypt`/`decrypt` and the grant's outbound presentation; tests assert the plaintext
   and the ciphertext never reach a log record or a client response
   (`tests/test_custody.py`, `tests/test_tokens.py:1440-1483`).
6. **No hardcoded credentials in the repository — Preserved.** `.env.example` carries
   only placeholders (`GATEWAY_CUSTODY_KEYS=` empty, refused at startup by the required-
   keyset validator, `gateway/settings.py:604-611`); the provisioning script takes the
   admin credential from `.env` through the placeholder-refusing `require`, prints only
   sha256 handles (`scripts/spike_env.py:190-203`), and no secret value appears in the
   diff.
7. **The signing key is IdP-grade secret material — Preserved.** Untouched; the custody
   key is a separate, decrypt-only, hard-cut-rotatable key in its own SecretStr slot
   with `repr`-clean custody classes (`gateway/custody.py:254-260`).

## Falsification verdicts on the change's own claims

No "no security impact" claim exists to falsify — the SIA records **Medium** and the
gate ran at that depth. The sub-claims were falsification targets:

- "P3 adds no new process-held secret / no new outbound call on the unauthenticated
  perimeter" — **holds**: no Core service API key remains anywhere in the diff (grep
  clean across `gateway/`, `.env.example`, compose); discovery makes zero Core calls
  (the route builds from configuration alone; asserted by
  `test_discovery.py::test_a_guard_passing_name_is_served_in_dynamic_mode_with_no_core_call`).
- "The guard is the same constants the router's alternation mirrors" — **holds**:
  `RESERVED_TOOLSET_NAMES` ≡ nginx's `callback|jwks\.json|authorize|token|register|revoke`
  (`router/nginx.conf:114`), `_TOOLSET_NAME` ≡ the router's `[a-z0-9-]+` captures
  (`nginx.conf:121,129`); URL-encoding does not open a gap (decoded names re-enter the
  guard; anchored prefix/suffix derivation in `toolset_name_from_resource` refuses
  trailing slashes and extra segments).
- "The record volume is capped by the rate limits the arrival shares" — **falsified at
  one of the four guard sites** (F1).
- "The short-circuited flow record is identity-free" — **falsified** (F4).
- "A lying provider cannot make the gateway hold more than it agreed to" — **falsified
  as stated** (F5; the cap does bound what is parsed).
- The mirror property — **holds**: guard refusals on the unauthenticated surfaces are
  shape-decided only (charset/reserved/restriction), answered identically for known and
  unknown names; existence is decided solely at the authenticated settings read
  (`ToolsetUnknownError`, post-auth, `gateway/federation.py:158-160`).

## Verified clean (one line each)

- **Custody crypto seam** (`gateway/custody.py`): AES-256-GCM; nonce from
  `secrets.token_bytes(12)` at encryption only, never taken from the envelope;
  `version|len|key-id` header fed as AEAD associated data on both seal and open, so a
  transplanted header fails the tag; checks ordered cheapest-first with the tag before
  any JSON is read; one `CustodyError` class, so tamper vs wrong-key vs wrong-subject is
  indistinguishable to the client (fixed descriptions in `gateway/token.py:118-134`);
  the 32-byte length is enforced before any `AESGCM` construction
  (`decode_custody_key`, `CustodyKey.__init__`); `__repr__` carries no material.
- **Keyset startup validation** (`gateway/settings.py:586-633`): empty, multi-active,
  bad id, and wrong-length keys each refuse the container's start.
- **Size-bound/body-cap coupling** (`settings.py:635-666` +
  `custody.envelope_bytes_for_token`): defaults fit (4096-byte token → ~5.7 KB envelope
  + 800 B overhead ≤ 16384 cap); sign-in-side refusal of over-bound and absent provider
  refresh tokens is loud and operator-facing (`gateway/idp.py:581-613`).
- **Carrier discipline, write side**: `mint_access_token` takes no custody claim; the
  code JWT's payload is clean (`gateway/codes.py:120-139`); the pending hand-off entry
  is single-use (`take`) and TTL-bounded by the code's own TTL; an absent entry — the
  orphaned pre-restart code — refuses the grant fail-closed under the custody class
  (`gateway/token.py:330-363`), and the fix is covered by
  `test_custody.py::test_a_restart_loses_pending_entries_but_not_the_custody` (re-run
  green this session).
- **Refresh failure semantics**: `idp_session_ended` is keyed *only* on the provider's
  own `invalid_grant` (`gateway/idp.py:508-535` — a non-`invalid_grant` 4xx such as
  `invalid_client` audibly does *not* read as a session end); custody faults never file
  as provider events and vice versa; the `_REFUSAL_REASONS` table is closed and an
  unmapped key raises (`gateway/token.py:164-219`).
- **Validation ladder order** (`gateway/token.py:557-629`): rate limit → body
  cap/duplicate-parameter refusal → signature and type → denylist → resource match →
  name guard → subject → client — and only then decrypt and the outbound grant: no
  failing request spends a decrypt or an outbound call.
- **No stale-snapshot fallback, structurally**: the refresh token's payload is bindings
  plus the custody ciphertext only (`gateway/tokens.py:250-264`); the refresh mint's
  only claim input is the verified fresh read; rotation keeps the original absolute
  expiry (`rotated_expiry`) and re-encrypts the provider's latest token (latest-wins);
  the grace window does not restart on replay.
- **The short-circuit as an authorization argument**: both `_finish` paths sit behind
  the identity leg (PKCE at the provider) and `read_toolset_for_flow`'s 403-checking
  per-user read; `SIGNED_IN` counts only user/global levels, never app-level, and
  absent/unreadable/FAILED fail closed into the kind branch (`gateway/core.py:186-195`);
  the OAuth-fields completeness refusal lives at the only URL builder
  (`gateway/flow.py:263-270`) with the delivery guard on the built URL.
- **Name guard**: one predicate at all four sites (`gateway/authorize.py:321`,
  `gateway/token.py:596-604`, `gateway/routes.py:95`, `gateway/status.py:54`);
  restriction comparison is exact dict membership; configured entries and the
  inference contradiction are pinned at startup (`settings.py:507-556`).
- **`offline_access`**: never requested — the scope set is configuration-only
  (`gateway/idp.py:183-194`), asserted in compose and the spec.
- **Startup lattice**: `refreshTtl ≤ IDP_SSO_SESSION_MAX_SECONDS` refused at startup with
  the assertion-not-truth caveat stated (`settings.py:558-584`).
- **Provisioning script** (`scripts/provision_keycloak.py`): `revokeRefreshToken`
  convergence is idempotent (read, compare, write only on difference); the
  temporary-Idle mutation is restored in a `finally` with a loud failed-restore message,
  and the restore was independently verified post-run (live-runs F(2)); a hard-crash
  residue (realm left at 300 s Idle) is the accepted, printed remainder of a dev-only
  script; no credential is printed or committed.
- **Docs/plumbing**: `.env.example`, `docker-compose.yml`, and the threat-model delta
  (RES-20/21/22/23, A16/A17, the EP1/EP4/EP5 delta rows, the mirror property) are
  consistent with the implementation; the gateway's internal port stays unpublished.

## Must fix before commit vs noted residuals

**Before commit:** F1 (land the limiter at the discovery guard site, or re-price the
spec and SIA to state the absent bound), F2 (run task 3.3 — the two-harness round-trip
gate — or record an owner ruling deferring it, in the change folder).

**Recommended with F1/F2 (cheap, same sitting):** F3 (strip `custody` in the claim
copy), F4 (drop `identity_refresh_token` and destroy the record at `_finish`).

**Nototed residuals (no action required for this change):** F5 (comment/streaming on the
refresh-answer cap), F6 (pre-existing grace-window docstring contradiction), the
compose comment typo, and the SIA's already-accepted remainders (RES-20 availability
trade, RES-21 custody residual, RES-22 session keepalive, RES-23 ungated harness
stores, DT-EP1-2 inventory disclosure, DT-EP1-12 global-credential delegation).

## Verdict

**PASS AFTER FIXES** — the custody design, the refresh grant, the short-circuit
authorization argument, the name guard, and all seven never-cut invariants are
implemented as priced and verified clean at Medium depth; the two items that must close
before commit are the missing record-volume bound at the discovery guard site (F1) and
the undriven two-harness round-trip gate (F2). No BLOCKER findings; no falsified
no-impact claim survives (the change makes none), and three of its own prose claims were
falsified and are filed above as F1, F4, and F5.

## Fix record

An earlier fix pass stalled and left this evidence file with no fix record at all (no
partial "fixes landed" note was written), and it landed no code or test change (verified:
no `gateway/**` or `tests/**` file was modified by it). The fixes below were made fresh.
F2 remains open — it is the owner-driven two-harness round-trip gate
(task 3.3), deferred by design and not a code fix.

**F1 — fixed, code + spec.** `gateway/routes.py`'s `protected_resource` route now joins the
same `runtime.limiter.allow(errors.client_source(request))` per-source/global limiter the
authorization, token, revocation, and status endpoints use, checked before the name guard.
Over the limit it answers the limiter's 429 (`temporarily_unavailable`) and writes **no**
audit record — the bound holds at the limit, because a record per refused request would
leave the volume unbounded. The delta spec's false "rate-limited as today" parenthetical is
replaced with a clause and a scenario stating the bound; the design's DT-EP1-3 control text,
its EP1 threat-table row, its "what is deleted with the consult" note, and its A2
pending-entry paragraph are re-worded to match. New rows: `tests/test_limits.py`
`test_a_burst_of_discovery_refusals_is_limited_and_writes_nothing` (429 past the limit and
exactly `PER_SOURCE_LIMIT` guard records, none of them `rate_limited`) and the
`protected_resource` entry in `test_the_unauthenticated_routes_are_all_bounded`. Negative
control: both fail with the limiter removed.

**F3 — fixed, code + test.** `CUSTODY_CLAIM_MEMBER` is stripped in both copy paths —
`gateway/tokens.py`'s `copied_claims` and `claims_for_tokens` — so a provider answer carrying
a `custody` member cannot plant one into an access token or a code JWT. New row:
`tests/test_tokens.py` `test_a_provider_answer_carrying_custody_plants_no_claim`, exercising
both functions (a forged refresh answer and a forged code payload). Negative control: the
test's assertions hold only with the strips in place (verified against the pre-fix predicate).

**F4 — fixed, code + docstrings.** `gateway/federation.py`'s `_finish` now clears
`record.identity_refresh_token` after `issue_code_for_flow` has moved the hand-off copy into
the pending entry, so the short-circuit's record holds no credential for its TTL — matching
the state.py docstrings, which were re-derived (the field now says it lives only until
`_finish`; `PendingCustodyStore`'s "identity-free" is corrected to "credential-free"). The
design's A2 paragraph and the task's pending-hand-off text are corrected the same way. New
row: `tests/test_federation.py`
`test_the_short_circuit_finish_clears_both_credentials_from_the_record`. Negative control:
fails with the clear removed.

**F5 — fixed, docstring only.** `gateway/idp.py`'s `_post_refresh` docstring no longer claims
the size cap bounds what the gateway *holds*: it now states plainly that httpx buffers the
body before the cap is checked, so the cap bounds what is *parsed*, and names the trusted
internal leg it shares with the uncapped `_post_token`. No streaming rewrite.

**F6 — fixed, docstring only.** The stale half of the grace-window contradiction is
`gateway/state.py`'s `in_rotation_grace` docstring, which claimed the presentation "gets an
access token and no replacement"; `gateway/token.py`'s `_apply_rotation` mints a replacement
unconditionally, and its own docstring is the accurate one. The `in_rotation_grace` and
`TokenDenylist` docstrings are corrected to the code's actual behavior (same treatment,
window not restarted, replacement keeps the non-sliding expiry).

**Gates re-run on the fixed tree:** full suite **502 passed, 1 skipped**; `ruff check`,
`ruff format --check`, `mypy` (strict), and `bandit` (0 findings) all clean. One pre-existing
`mypy` error in `tests/test_tokens.py` (an untyped `httpx.Response` return in the
grace-window test, not in this pass's regions) was fixed to make the gate green.
