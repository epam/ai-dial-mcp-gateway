# Custody opinion — v3 (encrypted IdP refresh token as a claim in the gateway's own token)

Evaluator: independent design evaluator — not the change's author, not the round-1 or
round-2 reviewer, not the prior mechanism opinion's author. Read-only except this file.
Question put: stress-test v3 (the owner's hint — encrypt the IdP session refresh token
and carry it as a claim in the gateway's own token, dissolving the retention store)
harder than its advocates do; stress-test v2 (the change's specified in-memory store)
equally; then rule — adopt v3, keep v2, or a third shape.

Sources read: the change's five artifacts (`proposal.md`, `design.md`,
`specs/mcp-signin/spec.md`, `tasks.md`, `release-notes-draft.md`),
`evidence/review-round-1.md`, `evidence/review-round-2.md`,
`evidence/independent-mechanism-opinion-1.md`, the main spec
(`openspec/specs/mcp-signin/spec.md`), `docs/threat-model.md` (§1, §3's RES-2/RES-15,
§4's asset inventory, the compromise table), `docs/production-roadmap.md` (the
iteration plan, C3, the deferred-HA table), `docs/background/design.md` §6.3 (the
revocation summary), and the code facts the analysis leans on: `gateway/tokens.py`
(the mint/verify module and the claim-copy rationale), `gateway/token.py` (the refresh
grant and `_REFUSAL_REASONS`'s closed table), `gateway/keys.py` (the signing key's
custody shape), `gateway/state.py` (the in-memory state design), `gateway/settings.py`
(`gateway_form_max_body_bytes`, default **8192**, line 289), `pyproject.toml`
(`pyjwt[crypto]>=2.15`, `httpx`, no JWE library), and `gateway/idp.py`'s
`_verified_claims` path. Specification and vendor-behavior facts from the RFCs and the
vendors' documentation — the same not-repo-verifiable input class the design's own
strict gap list records.

Terminology fixed for this file: **the blob** = the encrypted IdP session refresh
token claim; **the custody key** = the gateway's symmetric key that encrypts/decrypts
it (a new, dedicated key — never the RS256 signing key); **the carrier** = the gateway
token that carries the blob. The orchestrator's judgement (the carrier must be the
refresh token, never the access token) was read as input to critique, and is confirmed
below with an additional reason its advocates have not named.

---

## 1. v3 stress-tested

### 1.1 The carrier question — the orchestrator is right, and the reason is stronger than stated

The refresh token is the right carrier, and the decisive reason is in this repo's own
code rationale, not in OAuth etiquette: `gateway/tokens.py`'s module docstring records
that **Core forwards the whole access-token payload to usage logs** and matches
authorization rules on arbitrary claim paths. A blob in the access token would
therefore (a) land in the deployment's usage logs — encrypted credential material
written to a log sink on every MCP call, directly against never-cut 5's spirit and the
retention requirement's own discipline — and (b) ride the Authorization header of
every MCP data-path call through the router and Core, multiplying the places the
ciphertext is seen and pushing the token toward real header-size limits. The access
token is also optional at refresh time (RFC 6749 §6 keys on the refresh token), so as
a carrier it is not even reliably presented. The refresh token, by contrast, is
presented exactly once per refresh, only to `/dial/token`, only in a form body the
gateway itself caps. **Carrier = refresh token, normatively, with the usage-logs fact
recorded as the reason** — an implementer reading only "it must never ride the data
path" could too easily believe the access token is merely suboptimal rather than
categorically wrong.

### 1.2 Token size — the first real failure mode, and it is concrete

The refresh token today is a small JWT (session bindings only, post-D4). Under v3 it
gains the blob. Arithmetic:

- Keycloak's session refresh token is a signed JWT — typically several hundred bytes
  to ~1.5 KB.
- Entra's public-client refresh token is an opaque string, typically larger — the
  multi-KB class; B2C's per-policy tokens vary further. The design's own universality
  dependencies (D1) commit the gateway to exactly these providers.
- AES-256-GCM adds 12-byte nonce + 16-byte tag + a versioned key-id envelope; base64
  expands by 4/3. A 1 KB provider token becomes a ~1.4 KB claim; a 4 KB one becomes
  ~5.5 KB.

Against that: **`gateway_form_max_body_bytes` defaults to 8192 bytes**
(`gateway/settings.py:289`) and the refresh request carries the whole refresh token in
its form body. An Entra-shaped session can produce a refresh request at or past the
cap — the failure is a refused-over-cap body at the one endpoint the harness cannot
avoid, i.e., a hard session break with a confusing symptom. The cap must be raised
deliberately, and the raise is not free: `/dial/token` is an unauthenticated
body-bearing endpoint whose byte cap is a priced abuse bound (DT-EP1-3's class); the
delta spec's oversize-body scenario and the abuse-bounds requirement both name the
current cap discipline. Raising it to accommodate the blob re-prices that bound and
must be stated in the SIA, not slipped in.

The harder half is the harness side, which the owner's hint does not mention at all:
**the blob lands in every harness's token store**, and the store is not ours. Claude
Code (CIMD) and Cursor (DCR) are the two field-proven harnesses; their token stores
are not governed by any RFC size guarantee, and the store class that hurts is real —
OS keychain/credential-manager-backed stores have hard item-size limits (the Windows
Credential Manager CRED_MAX_CREDENTIAL_BLOB class, 2560 bytes, is the canonical
example). A 5 KB refresh token silently breaks a harness in that class, and the break
appears far from its cause. **Amendment-level conclusion:** a configured provider-token
size bound, refused loudly at the code exchange (the same refusal class as the
no-refresh-token sign-in failure — fail at sign-in, never hours later at refresh),
plus a raised-and-re-priced form cap, plus a live round-trip check against both field
harnesses as a task, before v3 is committed.

### 1.3 Custody-key rotation — the second failure mode, and it is manageable but must be designed now

What a rotation does to outstanding blobs: every refresh token in the field carries
ciphertext under the old key. Options, honestly priced:

1. **Hard cut:** every outstanding refresh fails at its next presentation
   (undecryptable blob → fail-closed refusal). One re-sign-in wave for all live
   sessions — exactly v2's restart semantics, on demand. Honest, loud, and the
   simplest correct policy.
2. **Bounded dual-accept window:** accept old and new key ids for a window ≤ the
   refresh TTL (8 h). Bounded because the token envelope's non-sliding absolute expiry
   bounds the old ciphertext's life anyway — the window can never outlive the tokens
   that carry it. Costs: the old key stays hot for the window (an old-key leak during
   the window still reaches live blobs), and the keyset logic must be versioned and
   tested.

Either is defensible; the design must pick one and write it down, because C3's T3
(rotation drill, already scoped) will exercise it. The structural point in v3's favor:
**rotation's blast is bounded by the non-sliding envelope** — the same
`rotated_expiry` property D4 already normative. And the key's *existence* is not new
cost: v2's own HA future (the Redis offload the owner names) requires at-rest
encryption of mintable user secrets — the same custody-key machinery, arrived at
later, with a store attached. v3 does not add the crypto work; it schedules it now
instead of at the step where it arrives bundled with a new trust boundary.

### 1.4 Revocation interplay — checked on all three axes

- **Gateway-side revocation (denylist by `jti`):** unchanged mechanically — the
  presented token is refused by `jti` before the blob is ever touched. The difference
  is residual, not control: in v2 the revocation also *drops the server-side copy* of
  the IdP credential; in v3 the ciphertext persists wherever the harness stores it.
  That persistence is worthless without the custody key, and the plaintext's own
  usability is still bounded by the provider's session policy and rotation reuse
  detection — the same bound RES-21 already prices for a lifted string. Not a new
  capability for any attacker; recorded as residual wording, not as a control gap.
- **IdP-side session revocation:** unchanged — the grant presents the (decrypted)
  provider token, the provider refuses `invalid_grant`, D4's `idp_session_ended`
  refusal fires. v3 does not touch the propagation gain D5 buys.
- **A revoked-but-recorded gateway refresh token:** the question the task poses
  explicitly. Pre-revocation, a thief who recorded the token holds, under v2, a
  self-contained gateway credential and nothing else — the IdP credential stays
  server-side. Under v3 the same thief also holds the ciphertext, which is useless
  *unless they also hold the custody key*. So the marginal v3 exposure is exactly the
  conjunction: **a recorded token plus a later key leak**, time-decoupled — an
  attacker who archives tokens today and compromises the key next month can decrypt
  the archive and replay the IdP identity for as long as the provider's session
  policy allows (Keycloak SSO Session Max; Entra's ~24 h sliding bound). This is the
  honest new residual, and its bound is the same clock RES-21 already names. v2's
  equivalent (process compromise + store read) requires the attacker to hold the
  material *at the same time*; v3 allows the two halves to be collected in different
  incidents. Against that: v2's same-time window contains **every live session at
  once**; v3's time-decoupled window contains only the tokens the attacker happened
  to record. Concentration vs. archive — the archive is strictly harder to assemble
  and dies with the provider sessions.

### 1.5 The crypto machinery — what the stack actually provides

- **PyJWT provides signature and verification only. There is no JWE support** —
  `jwt.encode` cannot encrypt a payload. Anyone prototyping v3 with "just use
  `jwt.encode(..., algorithm=...)`" is building a signed-but-readable claim, which is
  the authorization-code payload mistake M5/R2-M6 already prohibit, restated.
- **`cryptography` is already a dependency** (the `pyjwt[crypto]` extra installs it)
  and gives `AESGCM` — a 256-bit key, 96-bit random nonce, encrypt/decrypt in two
  calls. This is the minimal path: **no new dependency passes through the pip-audit
  gate**, no JWE library is needed, and the envelope is fully under our control.
- **The implementation must pin, in code constants:** the algorithm (AES-256-GCM),
  the key length, the nonce length, and the envelope layout (`version | key-id |
  nonce | ciphertext‖tag`, base64url). The envelope's key-id selects from a small
  in-process versioned keyset; **no algorithm identifier is ever read from the
  envelope** — the M20 lesson (never let a header select the algorithm) applied to
  our own encryption, exactly as the orchestrator requires. A blob whose version byte
  or key-id is unknown fails closed.
- **Binding:** the envelope embeds `sub` (and its own `exp`); the grant cross-checks
  the envelope's `sub` against the refresh token's signed `sub` before any use — a
  blob swapped between two users' tokens fails closed, the custody-seam analogue of
  D2's provider-side `sub` cross-check. AES-GCM's tag already covers integrity;
  the `sub` check covers *placement*, which the tag cannot see.
- **Key separation and custody:** a dedicated symmetric key in a new settings slot
  (env/file now, the KMS sign-interface at C3 — where a per-refresh KMS call would
  add an availability dependency of the RES-20 class, so a wrapped-DEK envelope
  shape is the better C3 landing; that is C3's decision, recorded here as input).
  The key is never logged, never in `repr` — `gateway/keys.py`'s `SigningKey`
  discipline, duplicated for the symmetric key.

### 1.6 The new residual's honest shape — is "useless without the key" the whole story?

No, but the rest of the story is smaller than v2's. Four parts:

1. **Ciphertext at rest on user machines** — the owner's "encrypted IdP material at
   rest in the harness's token store". The non-obvious fact: this adds *nothing* to
   an attacker who controls the user's machine, because that attacker already holds
   the gateway refresh token itself, which mints the same user identity through the
   front door without any key. The ciphertext matters only to an attacker who has the
   token but not the machine — i.e., only in conjunction with the key. It is a
   distributed, inert copy of mintable material, not a distributed exposure.
2. **The time-decoupled conjunction** (recorded token + later key leak) — §1.4's
   finding; the one genuinely new capability v3 creates. Bounded by the provider's
   session policy and rotation reuse detection; the archive dies with the sessions.
3. **Transient plaintext in process memory** — during a refresh the gateway decrypts
   the blob and holds plaintext for the duration of the outbound grant. A crash-dump
   or memory read in that window yields *that session's* IdP credential — and only
   the sessions presenting during the compromise window, never the ones idle in a
   store. v2's same-window read yields **all of them at once**. This asymmetry is the
   heart of the comparison (§2).
4. **The key itself at rest in the process** — a new high-value secret, but the same
   custody class as the signing key the process already holds (A1), the same
   container boundary, and C3's KMS scope already exists for exactly this class.

### 1.7 What v3 makes worse than v2 — the axes the task names, checked explicitly

- **Restart/availability axis: v3 is strictly better.** v2's restart kills the store
  → every live session's refresh fails closed → mass re-sign-in (RES-15's extended
  semantics, honestly priced as the cost of the single-instance design). v3's restart
  loses nothing the harness does not bring back itself: the blob returns with the
  token, refresh capability survives, and — the operationally decisive version of
  this — **a deployment/upgrade no longer costs a re-sign-in wave for every user**.
  C3 makes this acute: the K8s pod rollout is a restart, so under v2 *every rollout*
  is a mass re-sign-in event, which is exactly the pressure that forces the Redis
  offload early — the path the owner is already uneasy about. One honest regression
  on this axis, recorded: a *stolen* refresh token also survives restarts under v3
  (v2's restart killed stolen tokens' refresh capability with everyone else's). That
  was never a control — the same restart harmed every legitimate user — but it is a
  real delta and belongs in the residual's (c) list.
- **Revocation-propagation axis: unchanged where it matters, one residual shift.**
  IdP-side revocation propagates identically (the grant still runs). Gateway-side
  revocation still refuses by `jti`. The shift: revoked sessions' ciphertext persists
  on the harness side, inert without the key (§1.4). No new usable capability; the
  wording of the retention requirement's "never delivered to any client" must be
  deliberately amended — the *ciphertext* is delivered by design, the plaintext never
  — an M13-style amendment on the record, not a silent overwrite of a normative
  sentence.
- **Rotation-grace semantics — a small, nameable shift.** In v2, a grace-window
  presentation of the pre-rotation gateway token can be answered from the store's
  re-keyed latest entry. In v3 the pre-rotation token carries its own *stale* blob;
  if the provider rotated per grant, that provider token is already consumed and the
  presentation fails at the provider — the same fail-closed lost-rotation class D3
  already accepts, now reached one step earlier. Arguably more honest (each token is
  self-consistent), certainly bounded; one scenario covers it.
- **Complexity axis: v3 is worse, plainly.** A second key slot, keyset versioning, a
  rotation policy, envelope encode/decode with pinned constants, a size bound, a
  raised body cap, and new tests (round-trip, tamper refusal, wrong-key refusal,
  `sub`-swap refusal, size-bound refusal, version/nonce uniqueness). v2's store is a
  dict with three lifecycle rules. The owner's "too big a responsibility" frames the
  store as the burden; the honest accounting is that v3 *moves* the burden — from
  guarding N credentials to guarding one key and getting a few hundred bytes of
  crypto right. That is a better trade (§2) but it is not free, and the M20 lesson
  exists precisely because "a little crypto code" is where confidence goes to die.

### 1.8 What happens to the two-rounds-clean v2 artifacts

Roughly **80% survives untouched; the re-take is bounded and nameable**:

- **Survives as written:** the entire P3 half (D7–D10, tasks 1.x, the guard/kind/
  restriction specs — mechanism-independent); D1 (the refresh-grant mechanism and its
  three dependencies); D2 (one vocabulary, the provider-side `sub` cross-check); D4
  (fail-closed semantics, the snapshot-free refresh token); D5 (the M13 amendment and
  its priced trade); D6 (the re-derived validator). Both review rounds' findings were
  predominantly mechanism-independent (edit-list completeness, the rename's
  propagation, the audit-token distinctions, the migration reconciliation) — their
  work is not wasted.
- **Re-taken:** D3 (the store becomes the custody claim: envelope, key, rotation,
  size bound); the pending hand-off entry **survives but shrinks in role** (§1.9);
  the delta spec's retention requirement (title, the "never delivered" sentence, the
  restart scenario — which flips from a disclosed loss to a disclosed gain); task
  2.2 (rewritten); DT-EP4-1 and DT-EP5-2's shapes; the asset rows (the retained-token
  row becomes the custody-key row plus the user-machine ciphertext row); RES-15
  (narrowed — refresh capability no longer lost on restart); RES-21 (re-shaped per
  §1.6); OQ-B (discharged — there is nothing to persist); the compromise table's
  gateway-process row (whole-store harvest → key + in-flight sessions).
- **Process cost:** `openspec validate --strict` re-run, and **a third independent
  review round** — the change re-opens, and the repo's own gate ladder says so. This
  is the strongest argument for deciding *now*: the change is specified, not built
  ("every box below starts unchecked" — tasks.md's own note). The cheapest moment to
  re-take custody is before implementation; the most expensive is after v2-shaped
  deployments exist.

### 1.9 The claim the owner's hint overstates — there is still one store

"The blob rides the credential the harness already holds … no store exists at all" is
not quite true. The gateway refresh token's `jti` — the retention key — still does
not exist until the code grant at `/dial/token`, minutes after `_finish`, and the
authorization code is a signed-but-unencrypted JWT whose payload is client-readable —
the M5/R2-M6 prohibition stands. So the **pending entry keyed by the authorization
code's `jti`, bounded by the code's TTL, still exists server-side**; what dissolves is
the *long-lived, per-session* store — the part that concentrates the mintable
material, needs Redis at HA, and carries RES-21's central price. The honest v3
sentence is: "no long-lived per-session store; one minutes-bounded pending hand-off
entry per flow, already the design's shape." (The alternative — putting the blob in
the code payload because it is "only ciphertext" — is defensible only on a
ciphertext-tolerance ruling the repo has not made; keeping the pending entry avoids
needing that ruling at all.)

---

## 2. v2 stress-tested (equally)

- **The concentration exposure is real, and the owner's unease is technically
  correct.** The store holds one mintable, rotating provider credential per active
  refresh session — the highest-value credential class the flow ever touches. A
  process compromise (the EP4 row) reads **every live session's IdP credential in one
  memory sweep**: not per-session risk, aggregate risk scaling with concurrent users,
  at exactly the asset class (mintable identity) the compromise table re-prices. The
  host-read/core-dump class gets the same sweep. RES-21 prices the *per-entry* bound
  carefully (per-user, session-bound, latest-wins, dropped at session end) — but the
  *aggregate* is unbounded by construction, and that is the shape the owner is
  reacting to.
- **The KMS step makes it worse, not better.** At C3 the signing key leaves the host
  (`key_source: kms` — the process holds a reference). The store stays in memory —
  the store becomes the process's single highest-value at-rest asset, protected by
  nothing but the container boundary, while the key that could have protected it is
  the one thing that just left. The asymmetry is awkward to defend at D3's re-judge.
- **The clustering future is a strictly harder conversation.** The roadmap defers
  HA/Redis ("AuthN load will be small; the designed loss semantics cover a restart;
  revisit under load") — but under v2 the deferral has a ratchet: every rollout
  (restart) costs a mass re-sign-in, which manufactures the pressure to adopt Redis
  early, and Redis means **mintable user secret material at rest** — a class the
  design's own OQ-B names as "a strictly harder class" belonging to the
  secret-management scope. It needs at-rest encryption (the same custody-key
  machinery v3 needs now), a new trust boundary (Redis), a network leg per refresh
  (a sniffed leg carrying mintable material — DT-EP5-2's class, now to a second
  internal peer), and Redis-side compromise equals a full harvest. Multi-replica
  without Redis fails randomly (any replica without the entry refuses the refresh).
  v2 does not merely fail to solve HA; it **raises the price of HA** and pre-commits
  to the exact store the owner is uncomfortable protecting.
- **What v2 genuinely does better:** zero new crypto code, zero new key slots, zero
  token growth (no body-cap, harness-store, or keychain-limit exposure), the
  ciphertext never touches any client, stolen refresh tokens die with restarts, the
  artifacts are two review rounds clean and `validate --strict` green today, and the
  reviewable surface is a lifecycle spec rather than a crypto spec. These are real,
  and the verdict below pays for them explicitly.

---

## 3. Verdict

**Adopt v3, with the amendments below — decided now, before implementation starts.**

The trade, stated as the blast-radius comparison that decides it:

| Axis | v2 (in-memory store) | v3 (encrypted claim) |
|---|---|---|
| Transient process/host compromise | **All live sessions' mintable credentials in one read** (aggregate, scales with users) | The custody key + only the sessions presenting during the window; a dump yields at most the refreshing session's plaintext |
| Restart / rollout | All refresh capability lost; mass re-sign-in per deploy (C3 makes every rollout one) | Nothing lost; capability returns with the token; one regression: stolen tokens also survive (recorded) |
| The clustering step (owner's stated future) | Forces Redis: mintable material at rest, new trust boundary, new sniffed leg, Redis-compromise = full harvest | Needs only the shared custody key — the same secret-sharing class as the signing key every replica already needs; the jti-keyed store disappears from the HA problem (denylist/replay remain, low-sensitivity) |
| Key material to guard | N mintable credentials (concentrated) + the signing key | One symmetric key (signing-key custody class) + inert ciphertext on user machines |
| New machinery | None | AES-GCM envelope, keyset versioning, rotation policy, size bound, raised body cap, one new settings slot |
| Provider behavior | Identical (the grant is the mechanism in both) | Identical |
| Failure loudness | Fail-closed everywhere (D4) | Fail-closed everywhere (D4 unchanged; the refusal classes carry over, the retention-absent class becomes the undecryptable/absent-blob class) |

The decisive reasoning:

1. **The mechanism is not what moves — only custody does.** D1/D2/D4/D5/D6 — the
   refresh grant, the one-vocabulary read, the fail-closed snapshot-free refresh, the
   M13 amendment, the validator — survive a v3 re-taking intact, and they are where
   both review rounds' scrutiny went. The owner's hint attacks exactly one decision
   (D3), and D3 is the decision whose price (RES-21's concentration, RES-15's
   restart semantics, OQ-B's persistence question) the record itself keeps flagging
   as the uncomfortable part.
2. **The concentration-vs-distribution trade favors distribution at this system's
   threat model.** v2's aggregate exposure (one read = every live user's mintable IdP
   identity) is the textbook concentration risk, and it worsens at both named future
   steps (KMS leaves the key but not the store; Redis adds a boundary and an at-rest
   copy). v3's new exposures are (a) inert ciphertext that adds nothing to an
   attacker who already controls the machine it sits on, and (b) a time-decoupled
   key+archive conjunction bounded by the provider's session clock — the same clock
   RES-21 already prices for v2's lifted string. Neither is unpriced; both are
   strictly narrower than a full-store harvest.
3. **The restart axis alone is close to decisive given the deployment trajectory.**
   A system whose production unit is a K8s pod that rolls (C3) cannot carry a design
   where every roll invalidates every user's refresh — it either accepts recurring
   mass re-sign-ins or reaches for Redis, and the record already says the Redis
   conversation is a "strictly harder class." v3 removes the ratchet.
4. **v2 does not avoid the crypto work; it defers it to a worse home.** The Redis
   future needs at-rest encryption of mintable material — the same custody key, the
   same pinning discipline, plus a store, a boundary, and a network leg. Choosing v2
   chooses to do v3's engineering later with strictly more surface around it.
5. **The moment is the cheapest it will ever be.** Nothing is implemented; no
   v2-shaped deployment exists to migrate (the only migration is the pre-change
   snapshot tokens' existing fail-closed-once semantics, unchanged). The 80/20
   artifact split (§1.8) plus one more review round is the entire switching cost;
   after implementation it becomes a re-architecture with a live-user migration.

The honest price of the verdict, on the record: v3 takes on real crypto engineering
(the M20 class of mistake is a one-line away), grows the harness-visible refresh token
(with a hard dependency on harness token stores we do not control), adds a second key
slot with its own rotation story, and re-opens a change that is two rounds clean. If
the amendments below are not staffed seriously, v2 remains the defensible floor — a
store whose every property is specified, bounded, and already twice reviewed beats a
crypto seam specified casually.

### The amendments (all required; A1–A4 are the load-bearing ones)

- **A1 — Carrier discipline, normative, with the real reason.** The blob rides the
  gateway refresh token only. It MUST NOT appear in the access token (Core forwards
  the whole access-token payload to usage logs — `gateway/tokens.py`'s own rationale —
  so the blob would land in log sinks, and it would ride every MCP call), nor in the
  authorization code or any client-visible artifact other than the refresh token
  itself.
- **A2 — Keep the pending hand-off entry; state the claim honestly.** The
  minutes-bounded, code-`jti`-keyed pending entry survives (the code payload stays
  prohibited — M5/R2-M6). The owner-facing sentence is "no long-lived per-session
  store," not "no store at all."
- **A3 — Dedicated, versioned custody key; rotation policy chosen now.** A 256-bit
  symmetric key in a new settings slot, key-id versioned, separated from the signing
  key; rotation either hard-cut (one re-sign-in wave) or a dual-accept window bounded
  by the refresh TTL — picked and written into the design; the rotation drill joins
  C3's T3. C3 landing preference: wrapped-DEK envelope over a per-refresh KMS call
  (a per-refresh call would re-create RES-20's availability coupling against the KMS).
- **A4 — Crypto pinned in constants.** AES-256-GCM via `cryptography`'s `AESGCM`
  (already present through `pyjwt[crypto]`; PyJWT has no JWE — sign-only); envelope
  `version | key-id | nonce | ciphertext‖tag`, base64url; algorithm and lengths are
  code constants, never envelope-selected (the M20 lesson applied to our own
  encryption); unknown version/key-id fails closed; the envelope embeds `sub` and its
  own `exp`, both checked at the custody seam before use (the `sub` check is the
  placement bound — a blob swapped between users' tokens refuses).
- **A5 — Size bound, raised cap, live harness verification.** Refuse at the code
  exchange — loudly, operator-facing, the no-refresh-token refusal's class — when the
  provider's refresh token exceeds a configured bound; raise
  `gateway_form_max_body_bytes` (8192 today) to fit the worst-case refresh request
  and re-price the unauthenticated-body abuse bound (DT-EP1-3's class) in the SIA;
  a live round-trip task against both field harnesses (Claude Code/CIMD, Cursor/DCR)
  proving the grown refresh token survives their token stores — any store with a
  hard item-size limit (the keychain/credential-manager class) becomes a named
  deployment prerequisite, surfaced at sign-in.
- **A6 — Fail-closed decryption semantics carry D4 forward.** Absent, tampered,
  wrong-key, unknown-version, expired-envelope, or `sub`-mismatched blob = the
  `claims_read_failed` refusal class (the retention-absent class re-named); the blob
  is never logged — never-cut 5's wording extended to credential ciphertext, and the
  retention requirement's "never delivered to any client" amended M13-style to "the
  plaintext is never delivered; the ciphertext is, by design, and is unusable without
  the custody key."
- **A7 — The re-shaped residual (RES-21's successor record), four parts.**
  (a) Per-session mintable material is gone from the process — a transient
  compromise yields the key plus only the presenting sessions. (b) The new
  conjunction: a recorded token plus a later key leak replays the IdP identity for as
  long as the provider's session policy allows, time-decoupled — bounded by SSO
  session policy and the provider's rotation reuse detection. (c) Ciphertext at rest
  on user machines — inert without the key, and adding nothing to an attacker who
  controls the machine (the refresh token already mints the same identity through the
  front door). (d) The recorded regression: stolen refresh tokens survive restarts
  under v3 (v2's restart killed them with everyone else's); bounded by the
  non-sliding absolute expiry and the IdP session clock.
- **A8 — Rotation-grace semantics restated.** Each rotation re-encrypts the
  provider's latest token (latest-wins preserved); a grace-window presentation of a
  pre-rotation token carries its stale blob and fails at the provider where the
  provider rotates per grant — D3's accepted lost-rotation class, reached one step
  earlier; one scenario covers it.
- **A9 — The artifact re-take, scoped and honest.** D1/D2/D4/D5/D6 and the whole P3
  half stand; D3 re-taken; the retention requirement, task 2.2, DT-EP4-1, the asset
  rows, RES-15 (narrowed to a gain), RES-21 (re-shaped per A7), OQ-B (discharged),
  and the compromise table's rows are the edit list; `validate --strict` re-run; a
  third independent review round before the owner pause. The re-open is the price of
  deciding custody correctly before a line of it is built.

**If v3 is declined**, what would have to be true for v2 to stand as more than the
fallback: (i) the deployment stays single-instance indefinitely (no C3 pod rollouts
at cadence, no HA ever) — false on the roadmap's own text; (ii) the crypto seam's
review cost is judged heavier than the store's aggregate exposure — defensible only
with the amendments' scope priced and rejected on the record, not by default; and
(iii) the harness-store size question turns up a hard limit in a field harness that
no bound can dodge — the one finding that would legitimately force v2 back, which is
exactly why A5's live verification is a gate on the adoption, not a follow-up.
