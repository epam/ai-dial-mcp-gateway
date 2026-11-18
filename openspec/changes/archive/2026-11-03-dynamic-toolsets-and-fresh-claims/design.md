# Design

## Context

Two production items of the iteration land here, on surfaces the PoC already proved:

- **P3 — dynamic MCPs.** The served toolset set is the `TOOLSETS` environment mapping,
  validated at startup: a toolset added to Core is not sign-in-able until an operator
  edits `.env` and restarts the container. The mapping's three startup refusals
  (non-OAuth kind, reserved name, charset) keep *configuration* safe; they were never
  needed as the source of truth for *what exists* — Core is, and the flow already
  reads Core's public settings projection per flow, a projection that carries the
  authentication kind. Existence is decided on that same authenticated read, never
  on an unauthenticated one: Core's own discovery tier is registry-independent by
  design (D8's empirical facts), and the gateway's mirrors it. The router needs no per-toolset configuration at all: its
  data-path location is a generic anchored `[a-z0-9-]+` regex and its
  authorization-surface alternation is static, so the mapping was never a routing
  input — only a served-set input.
- **P2 — fresh claims at refresh.** The refresh token freezes the claim snapshot at
  issuance, so a role revoked at the identity provider lives on in minted tokens for
  up to `refreshTtl` (8 h locally) — the disclosed residual RES-6, the bound on
  never-cut invariant 4, and threat-model row T1-16. Collapsing staleness to the
  access TTL requires a refresh that re-reads current claims instead of re-issuing
  the snapshot. The mechanism is this change's to choose, and this is the second
  taking: the first design chose a userinfo re-read backed by the retained identity
  access token, and the owner **overruled it** (2026-10-31) on three objections an
  independent evaluation had verified as the factual baseline
  (`evidence/independent-mechanism-opinion-1.md`): (O1) userinfo does not exist for
  every identity provider — it is RECOMMENDED, not REQUIRED, in OIDC Discovery, and
  plain-OAuth servers have no userinfo concept at all; (O2) userinfo does not
  necessarily return the needed claims — the response is scope- and policy-filtered
  (OIDC Core §5.3.2), fixed and non-customizable on Entra, custom-policy-only on
  B2C; (O3) the retained access token dies on the provider's clock far inside the
  refresh window — 5 minutes on a default Keycloak, 60–90 minutes fixed on Entra —
  so the 8-hour window was a fiction outside the one deliberately reconfigured
  local realm. The owner's direction is binding: the proper mechanism is the IdP's
  own **refresh token** — issued universally and long-lived enough, able to mint
  real tokens that carry the claims with guarantee — and the design's job is to
  answer *where it is stored* and *how it is done properly*. The owner also ruled
  (binding) that the PoC-era principles are revisable where the design misses an
  important piece: the recorded no-`offline_access` provisioning ruling (M13) may be
  changed **deliberately, with the trade priced on the record** — not silently.
  D5 below is that deliberate change.

Both are contained edits on existing surfaces — no new endpoint, grant type, or trust
boundary — which is why they share one security impact analysis. One credential
class does change shape (what the gateway holds of the provider's session refresh
token after the flow), and that change is the SIA's center of gravity. Custody has
now been taken three times. The second taking specified an in-memory,
`jti`-keyed retention store; it survived two review rounds clean, and the owner
overruled it (2026-10-31) on an independent custody opinion's verdict
(`evidence/custody-opinion-v3.md`): the store concentrates every live session's
mintable credential into one memory read, makes every C3 rollout a mass re-sign-in
(the ratchet that forces the Redis offload early), and defers the same crypto
work to a later home with strictly more surface around it. The adopted shape
(**v3**, D3): the provider's session refresh token rides the gateway's own refresh
token as an **encrypted claim** under a dedicated custody key; the long-lived
per-session store is deleted. The mechanism decisions (D1/D2/D4/D5/D6) and the
whole P3 half survive the re-taking intact; the amendments A1–A9 of the custody
opinion are landed as D3/D4/D5's re-taken text and the SIA below.

**The P3 half is re-taken a second time on two owner rulings (2026-10-31) issued after
the three review rounds — and its discovery half re-taken once more on the owner's
final correction (2026-10-31, issued after empirical testing)** — all binding, all
worked below with the arguments the owner's own meta-norm (arguments, not decrees)
obligates:

- **Ruling 1 — the kind check becomes a routing decision inside the flow, not a
  precondition.** The OAUTH-only refusal dies. The flow authenticates the harness for
  ANY toolset kind; then, before any upstream leg, it checks Core for an already-stored
  credential — user level OR global level; if one exists, the flow short-circuits
  (skip the upstream stage, mint, done) regardless of kind; only when no credential
  exists does the kind decide — OAUTH runs the consent leg as designed, any other kind
  gets a loud, plain-language refusal ("this toolset's credential is configured
  directly in DIAL and cannot be established by a consent flow") — fail-closed, but
  only in the genuinely impossible case. D11/D12 are that re-taking; the startup
  OAuth-declaration refusal dies with it (D7).
- **Ruling 2 — discovery consults Core; phantoms are refused immediately — issued,
  worked, priced, and then reversed by the final correction.** The consult's design
  rested on a standing service credential in Core, and the empirical test falsified
  the fact that would have justified its necessity. What the test settled: Core's MCP
  path answers an unauthenticated call — **phantom toolset or real alike** — with
  `401` plus
  `WWW-Authenticate: Bearer resource_metadata="…/oauth-protected-resource/v1/toolset/{name}/mcp"`
  (the auth check precedes any registry lookup, so the unauthenticated tier has **no
  existence oracle**), and Core's own protected-resource route answers an
  unauthenticated fetch for **any** well-formed name with `200` — a document built
  from static configuration plus the requested path echoed as `resource`
  (`WellKnownResourceMetadataService`, no registry lookup; verified in the Core
  source **and** live). A consult would therefore have needed a dedicated Core
  service API key — the one credential class the owner's principle bars: **the
  gateway holds no user-like standing credentials in Core; its only Core credentials
  are the user's own per-flow token.** Discovery reverts to guard-only, mirroring
  Core's own registry-independent unauthenticated tier *by design* (D8 re-taken);
  the consult, its service key, its concurrency bound, its threats, and its cache
  question are deleted with it, and what would let the gateway refuse phantoms at
  the door is recorded as a Core-side ask (§8), not built here.

## Goals / Non-Goals

**Goals:**

- A toolset added to Core is sign-in-able with no gateway reconfigure; discovery
  answers every guard-passing name (charset, reserved names, optional restriction)
  exactly as Core's own unauthenticated discovery tier does — registry-independent,
  zero Core calls, existence decided post-authentication at the flow's settings read
  (the mirror property, D8); a non-OAuth toolset with a stored credential
  (user or global) is sign-in-able through the short-circuit; a non-OAuth toolset with
  no stored credential is refused with a plain-language page that names the actual
  cause; a name Core does not know is refused at the flow's settings read with a
  plain-language page — the system's only existence refusal.
- An identity-provider claim change is reflected in minted tokens within the access
  TTL — by test and by a live run.
- An identity-provider session revocation ends the gateway's refresh capability at
  the next refresh attempt — by test and by a live run (the strict improvement the
  mechanism buys over both the snapshot design and the overruled userinfo design).
- The mechanism is standard and provider-agnostic — core OAuth surfaces only, no
  provider-specific surface, endpoint shape, or claims vocabulary — with its
  availability dependencies stated honestly (D1's three dependencies), none of which
  is a new claim-source requirement the sign-in does not already carry.
- Every new refusal lands on the audit trail under the existing discipline
  (fixed-vocabulary reason, non-credential facts, no free-form caller input).
- The threat model's affected entries are updated by this change, not after it.

**Non-Goals:**

- No apps-as-MCP-resources support in this change — but the ruling-1 re-taking
  **unifies C1.5's planned mechanism into this change's general rule**, so C1.5's
  later scope shrinks (D11 states what that means: the flow's branch machinery — the
  signed-in check, the short-circuit, the kind branch — is built here; what remains
  C1.5's is the apps resource surface itself and the unsigned DIAL_NATIVE case).
- No OIDC-discovery generalization, no `KEYCLOAK_*` rename, no Entra B2C (the
  federation change's). This change adds one identity-provider call — the refresh
  grant — to an endpoint (the token endpoint) the flow already calls, and nothing
  else provider-facing.
- No `offline_access`, ever: no beyond-session grant is requested or accepted (D5).
- No long-lived per-session server-side custody: the provider's session refresh
  token rides the gateway's own refresh token as an encrypted claim (D3); there is
  no retention store to persist or protect. The custody key's long-term home (KMS
  at C3, wrapped-DEK preference) is C3's conversation, recorded there as input.
- No change to the access token's shape: it carries no custody material of any
  kind — the carrier discipline is normative (D3).
- No change to the upstream leg, the credential call, the router's locations, or the
  challenge synthesis.
- No per-toolset audience binding (RES-7 stands; only its sibling RES-6 shrinks).

## Decisions

### P2 — the mechanism

**D1 — The mechanism: the identity provider's refresh grant at every gateway
refresh, reading claims from the fresh token the grant returns.** At each refresh
grant the gateway presents the provider's own refresh token — retained from the
sign-in flow — to the provider's token endpoint (RFC 6749 §6, the refresh grant),
and mints from the verified token the grant returns. The design space, re-taken on
the owner's ruling:

- *The userinfo re-read (the overruled mechanism) — rejected on the ruling.* Its
  three provider-behavior dependencies (O1/O2/O3 above) are recorded facts, not
  misconfigurations: O3 is structural (OAuth lifespans), O2 is categorical on the
  largest managed IdP, and O1 is a RECOMMENDED-not-REQUIRED membership. The prior
  design priced them honestly as deployment preconditions and an owner decision
  (OQ-F); the owner's ruling is that a mechanism whose preconditions exclude named
  providers is not the P2 answer. Everything the userinfo design specified that
  survives the re-taking — the fail-closed refresh semantics, the hand-off seam,
  the validator's re-derivation duty — is carried into
  this design rather than re-invented.
- *Introspection-based resolution (RFC 7662) — rejected, unchanged.* The
  introspection endpoint is not an OIDC Discovery member (RFC 8414 defines no such
  field), so its URL is a provider-specific surface; it also has nothing to
  introspect without retaining a provider token anyway, and it fails O3 exactly as
  userinfo does.
- *The `offline_access` leg — rejected as unnecessary, not only as costly.* The
  owner's direction needs a provider refresh token; the ordinary, session-bound one
  the code exchange already issues is it (D5). Requesting `offline_access` would
  acquire a *beyond-session* grant (Keycloak: 30-day offline tokens; Entra: 90-day)
  — a strictly larger capability than the freshness goal needs, reversing M13
  outright instead of amending it. The amendment (D5) is the priced middle: keep the
  no-`offline_access` line, retain what the provider issues inside it.
- *Shrink the TTLs, keep the snapshot — rejected.* It leaves the residual at its
  priced width (the window, not the interval) and fails the acceptance.

The refresh grant wins on every axis the constraint names: the token endpoint is
the OIDC Discovery **REQUIRED** member every OP exposes; the refresh grant is core
RFC 6749 — the same grant family the flow's own code exchange presupposes the
provider implements; the credential it needs is one the provider issues for exactly
this purpose, on the provider's own session clock; and the claim read rides the very
token the grant returns, so the mechanism's claim-carrier dependency is one the
sign-in's exchange read already carries (D2) — no new claim-source deployment
requirement appears anywhere.

The universality claim, stated as dependencies rather than as a slogan — the
mechanism is universal among providers that satisfy all three, and each failure
mode is loud:

1. **The provider issues refresh tokens to the gateway's public PKCE client on the
   code exchange.** RFC 6749 permits an AS to decline to issue refresh tokens;
   Keycloak and Entra both issue them to public clients (Keycloak: session-bound,
   issued with the code exchange by default; Entra: public clients receive them and
   cannot be configured out). Failure shape: the exchange returns no
   `refresh_token` → the flow refuses **at sign-in**, loudly, per flow, with an
   operator-facing message naming the deployment prerequisite — never a silent
   breakage at the first refresh hours later.
2. **The refresh grant returns a token whose claims the flow can verify.** The
   grant's `access_token` response member is REQUIRED (RFC 6749 §6); whether the
   response also carries an ID token is provider behavior (OIDC Core §12.2's
   response shape), and the mechanism deliberately does not depend on it: the claim
   carrier is the same token-endpoint token the exchange already reads and verifies
   (D2). A provider whose tokens are opaque or claim-less fails **sign-in today**,
   under the existing design — the refresh mechanism adds no dependency of this
   kind.
3. **The session-bound refresh token remains usable across the refresh window under
   the provider's session policy.** Keycloak: the ordinary refresh token is bound to
   the user's SSO session and dies with it; refresh use refreshes the session's
   *idle* timer, so under a normal refresh cadence the operative cap is **SSO
   Session Max** (default 10 h; the local realm's value is a deployment fact task
   2.5 reads live, and the idle-refresh-on-use fact itself is one of task 2.5's
   driven checks — the local 8 h window rests on it, so it is machine-checked, not
   inferred). Entra: public-client refresh tokens live roughly 24 h and slide
   on use (versus 90 days with `offline_access`), and admin session revocation or
   user sign-out kills them. This dependency is an **operator prerequisite, not a
   standard guarantee**: it is asserted at startup (D6), verified live for the local
   realm by the provisioning check, and its runtime break fails loud (D4's
   `idp_session_ended` burst on the audit trail).

**D2 — One claim vocabulary: the same carrier and the same verification path at
issuance and at refresh.** What the flow reads today at the exchange — the
token-endpoint token, verified against the provider's published keys with the
issuer pinned (`_verified_claims`) — is exactly what the refresh grant reads: the
fresh token the grant returns, verified through that same path, with the additional
binding that its `sub` MUST equal the gateway's own refresh-token subject (a claim
the gateway signed itself, so no answer the provider returns can mint for another
user). The prior change's D2 achieved the single vocabulary by *narrowing* the
source to userinfo and paying a new deployment requirement (userinfo claim
reachability — OQ-F, with Entra and B2C categorically unable to satisfy it); this
design achieves the same property by keeping the source *unchanged* — the
deployment has already proven, at sign-in, that it can read and verify this
carrier. The one-vocabulary property is therefore not a new requirement on the
operator at all, and OQ-F is discharged: the userinfo claim-set question (Entra's
fixed userinfo, B2C's custom-policy-only userinfo) no longer gates the mechanism;
those provider facts remain inputs to C2's federation planning, nothing more. The
`sub` cross-check strengthens the mint: a token is never minted at refresh for a
subject the provider did not just re-assert.

**D3 — Custody (v3): the encrypted claim in the gateway's own refresh token.** The
gateway carries exactly one credential per active refresh session: the provider's
**current session-bound refresh token** — a rotating handle, not a snapshot — held
as an encrypted claim (the **custody claim**, below "the blob") inside the
gateway's own refresh token, under a dedicated symmetric **custody key**. There is
no long-lived per-session store; what dissolves is exactly the part of v2 that
concentrated mintable material server-side. The sub-decisions, each an amendment
of the custody opinion landed here:

**The carrier (A1, normative).** The blob rides the gateway refresh token only,
and MUST NOT appear in the access token, the authorization code, or any other
client-visible artifact. The decision stands on two refresh-grant facts alone:
(1) RFC 6749 §6 keys the grant on the refresh token — the access token is not
even reliably presented at the moment the blob is needed; (2) the access token
rides the `Authorization` header of every MCP data-path call through the router
and Core — a carrier there multiplies the places the ciphertext is seen by every
call and pushes the header toward real size limits. A supporting note, verified
this pass against the authoritative public reference (the DIAL Core source):
Core does **not** write the presented token's payload to logs by default. The
analytics row's user identity is the salted SHA-256 hash of the configured
`loggingKey` claim (`loggingSalt`; obfuscation on by default —
`IdentityProvider.java`'s `extractUserHash`); claim values reach the analytics
log only through the operator's opt-in `analytics.claimsAllowlist` (emitted
verbatim and unhashed, `["*"]` collecting every top-level claim — Core's own
README warns), headers only via `analytics.collectHeaders` (default off,
`authorization` on the default blacklist), and a small fixed claim set
(`sub`/`oid`/`email`) at DEBUG level (`claimPathsToLog`, `claimsLogLevel`
defaulting to DEBUG). The access-token carrier is therefore not a *default*
logging exposure — but it remains barred regardless: a deployment that opts into
claims collection would write the ciphertext into a log sink, and
credential-adjacent material does not belong in logs even inert. One honesty
consequence of this verification was recorded for the owner pause and is
resolved by its ruling (§8):
`gateway/tokens.py`'s module docstring states Core "forwards the whole payload
to usage logs" — true only under that opt-in, not by default; its
authorization-paths half ("matches authorization rules on arbitrary claim
paths") is accurate. The docstring is pre-existing repo material and is not
rewritten mid-change; the correction is assigned to this change's
implementation pass (owner ruling, 2026-11-01, §8 — tasks.md, task 5.7), not a
separate repo-docs change. The PoC's own history is the closing note: `background/design.md`
§5.1's alternative B (sealed tokens) was rejected because it sealed *both*
tokens and put the proxy on the data path; v3 seals exactly one claim of exactly
one token, and the data path is untouched.

**The envelope (A4, pinned).** AES-256-GCM via `cryptography`'s `AESGCM` —
already a dependency through `pyjwt[crypto]`; PyJWT provides signature and
verification only (no JWE), so "just `jwt.encode(...)` it" builds a
signed-but-readable claim — the authorization-code payload mistake M5/R2-M6
prohibit, restated for our own encryption. The envelope is
`version | key-id | nonce | ciphertext‖tag`, base64url-encoded; the algorithm,
the key length (256-bit), and the nonce length (96-bit, CSPRNG) are **code
constants, never envelope-selected** — the M20 lesson (never let a header select
the algorithm) applied to our own encryption. An envelope whose version byte or
key-id is unknown fails closed. Two further pins complete the seam. The 96-bit
CSPRNG nonce is random, so NIST SP 800-38D's random-IV bound applies: no more
than 2^32 encryptions under one key, past which the random-nonce collision
probability becomes non-negligible — unreachable at this gateway's mint rate
and reset by each hard-cut rotation, but stated because it is the one fact that
tells a future implementer why re-keying matters without a compromise. And the
clear-text `version` and `key-id` are bound into the AEAD's associated data, so
a header transplanted between envelopes fails the tag: AES-GCM's missing key
commitment is structurally closed today by the single-active-keyset invariant
(an unknown key-id refuses, and there is never a second live key for a swapped
header to reach), and the associated-data binding carries that closure into any
multi-key future — which must re-judge the commitment bound before the keyset
ever holds two active entries. Both the binding and the invariant-as-today's-bound
are confirmed as an owner ruling (2026-11-01, §8). The envelope embeds its own `sub` and `exp`, and
both are checked at the **custody seam** before any use: the embedded `sub` MUST
equal the refresh token's signed subject — the placement bound, the custody
analogue of D2's provider-side `sub` cross-check (AES-GCM's tag covers
integrity; the `sub` check covers *placement*, which the tag cannot see) — and
an expired envelope refuses.

**The key and its rotation (A3 — the policy chosen now).** A dedicated 256-bit
symmetric key in a new settings slot, identified by key-id, separated from the
signing key (never derived from it, never used for signing); its custody follows
`gateway/keys.py`'s `SigningKey` discipline — never logged, never in `repr`. The
256-bit pin is enforced at startup, not aspirational: `cryptography`'s `AESGCM`
constructs for any 16-, 24-, or 32-byte key and the algorithm follows the key's
length, so the keyset's startup validation refuses any key that is not exactly
32 bytes — a shorter key would otherwise run AES-128/192-GCM silently for the
key's lifetime and falsify the pinned-algorithm claim (the M20 lesson's last
hole: the key material is the one remaining thing that can select the
algorithm). The signing key's own minimum-size load check (`gateway/keys.py:63-68`,
refusing a key under 2048 bits at load) is the pattern. The
rotation policy is **hard cut**: a superseded custody key is never retained to
decrypt, so every outstanding refresh token fails closed at its next presentation
after a rotation and its user re-runs the sign-in — one bounded re-sign-in wave,
deliberately chosen over the dual-accept alternative (old and new key-ids
accepted for a window ≤ the refresh TTL). The justification: rotation is a rare,
operator-initiated act undertaken precisely when key compromise is suspected —
the one moment the old key must stop working — and the dual-accept window buys
freedom from the re-sign-in wave at the price of keeping the possibly-compromised
key hot against every live blob for the window. The wave is bounded by
construction: the non-sliding absolute expiry (D4's `rotated_expiry`) caps how
long any outstanding blob lives, so a rotation's blast can never outlive
`refreshTtl` from the rotation instant — the accepted operator cost, confirmed
as an owner ruling (2026-11-01, §8): the operator schedules the rotation around
that absolute expiry. The rotation drill joins C3's T3 (already
scoped for the signing key; the custody key joins it — one drill, two keys). At
C3, where the key's home moves under KMS, the landing preference is a
**wrapped-DEK envelope** over a per-refresh KMS call — a call per refresh would
re-create RES-20's availability coupling against the KMS; recorded here as C3's
input, decided there.

**Size: the bound, the cap, and the harness store (A5).** Three deliberate
controls, because the first real failure mode of v3 is concrete: an Entra-shaped
opaque session refresh token is multi-KB, the envelope and base64 expand it
further, and the resulting refresh token must fit (a) the form body of every
refresh request and (b) the token store of a harness the gateway does not
control. (i) A **configured provider-token size bound**
(`gateway_custody_provider_token_max_bytes`, default 4096) refused **loudly at
sign-in** — the no-refresh-token refusal's class: fail at sign-in, per flow,
operator-facing, never hours later at refresh. (ii) `gateway_form_max_body_bytes`
is raised 8192 → 16384 to fit the worst-case refresh body, and the raise
**re-prices** the unauthenticated-body abuse bound (DT-EP1-3's class) in the SIA
— the shared cap means `/dial/revoke`'s read bound rises with it; stated, not
slipped in. The two bounds are coupled and must move together: the refresh body
must stay under the cap for every size the bound admits (cap ≥ bound + envelope
expansion + JWT overhead), so raising `gateway_custody_provider_token_max_bytes`
past the cap's headroom recreates by configuration the exact failure this
control exists to prevent — sign-ins succeed and every refresh fails over-cap,
hours later and far from its cause. (iii) The harness-side half: the blob lands in every harness's token
store, and the store class that hurts is real — OS keychain/credential-manager
stores carry hard item-size limits (the Windows Credential Manager's 2560-byte
`CRED_MAX_CREDENTIAL_BLOB` class is canonical). A refresh token too large for a
harness's store breaks silently, far from its cause. The round trip through both
field-proven harnesses' stores (Claude Code/CIMD and Cursor/DCR — sign-in,
refresh, gateway restart, refresh again) is therefore an implementation **gate**
(task 3.3), not a follow-up; any store with a hard limit the bound cannot dodge
becomes a named deployment prerequisite surfaced at sign-in.

**The pending hand-off entry (A2) — kept, honestly stated.** The retention
carrier — the refresh token — does not exist until the code grant at `/dial/token`,
minutes after `_finish`, and the flow record never reaches the code grant —
destroyed on the consented path before `_finish` runs, TTL-bounded and credential-free
on the already-signed-in short-circuit (`_finish` clears both the identity access token
and the provider's session refresh token, so only the claim snapshot outlives the flow's
use of them) — so the provider refresh token cannot ride the
flow record to the grant on either path. It transits a **server-side pending
entry keyed by the authorization code's `jti`**: created at `_finish` when the
code is minted (both flow paths — the consented flow and the already-signed-in
short-circuit), bounded by the code's own short TTL, consumed at the code grant
(the provider token encrypted into the issued refresh token), and dropped when
the code expires unredeemed. The owner-facing sentence is the honest one:
**no long-lived per-session store; one minutes-bounded pending hand-off entry per
flow** — a shape the first taking already had. The code payload stays prohibited
for the blob exactly as for the plaintext (M5/R2-M6): the code is a
signed-but-unencrypted JWT whose payload is base64-readable by anyone holding
the code string, and "it is only ciphertext" is defensible solely on a
ciphertext-tolerance ruling this repo has not made; the pending entry avoids
needing that ruling at all. The pending entry is memory-only and lost on restart
(an unredeemed pre-restart code fails its grant, fail closed). The identity
access token itself is **not retained past the flow** — it returns to today's
shape (the flow's decision step and credential call, then discarded at flow end).

**Restart, revocation, and rotation grace (A8 — the semantics that flip).** A
restart — and a C3 rollout, which is a restart — loses nothing the harness does
not bring back: the blob returns with the presented refresh token and refresh
capability survives; v2's RES-15 restart loss narrows to a gain, with one
recorded regression (RES-21's part iii): a *stolen* refresh token also survives
restarts under v3, where v2's restart killed stolen tokens' refresh capability
with everyone else's — never a control, but a real delta, disclosed. Gateway-side
revocation is unchanged mechanically — the denylist refuses by `jti` before the
blob is ever touched, and its scope is ruled local-only (§8 OQ-H, 2026-11-01:
the revoke endpoint ends the gateway's own session only — its tokens and the
denylist entries — neither the user's identity-provider session nor the
upstream credentials stored in Core); the residual difference is that the revoked session's
ciphertext persists wherever the harness stores it, inert without the key and
dying with the provider session. IdP-side session revocation is unchanged — the
grant presents the decrypted token, the provider refuses `invalid_grant`, D4's
`idp_session_ended` fires; the propagation gain D5 buys is untouched by custody.
Rotation grace: each gateway rotation re-encrypts the provider's **latest** token
into the replacement (latest-wins preserved — RFC 6749 §6 makes the response's
`refresh_token` optional; where present it supersedes, where absent the old one
is kept), and a grace-window presentation of a pre-rotation token carries its
own **stale** blob: where the provider rotates per grant, that provider token is
already consumed and the presentation fails at the provider — the accepted
lost-rotation class, reached one step earlier. Arguably more honest (each token
is self-consistent), certainly bounded; one scenario covers it. The one
provider-side failure mode named in the first taking stands: a refresh response
lost in transit after a per-grant provider rotation consumes the carried token —
the session fails closed at the next refresh and the user re-signs-in; the design
accepts this rather than disabling provider rotation, because rotation-on-use
(Keycloak's default) is a custody *strength*, not a defect — its reuse detection,
**where enabled**, revokes the chain when a superseded token is replayed. That
detection is the containment control for the credential-on-the-wire exposure of
plain-internal-leg deployments (this deployment's dev shape, where the provisioning
script sets it); deployments with TLS'd internal legs — the production shape — are
bounded by the transport itself, and the detection is defense-in-depth there (it is
not Keycloak's image default, so a deployment that wants it must enable it).

One configuration interaction is priced rather than refused. With gateway
rotation off (`GATEWAY_ROTATE_REFRESH_TOKENS=false`) on a provider that rotates
its refresh token per grant, the carried credential is single-use in effect:
the first refresh consumes the provider token at the grant, the un-rotated
gateway token keeps presenting the same stale blob, and every refresh after the
first fails at the provider (`idp_session_ended`) — the session ends at the
second refresh. Refusing the combination at startup was considered and rejected
as the larger, less coherent edit: the gateway cannot know the provider's
rotation policy at startup (provider behavior, not configuration — the same
class as D6's un-catchable failure), and the setting is valid on providers that
do not rotate per grant, where the same blob stays usable for the whole window.
The degraded semantics are therefore stated here as the priced cost and carried
into the operator documentation as a warning (task 2.4) — confirmed as an owner
ruling (2026-11-01, §8): warned, not refused at startup.

**D4 — Fail-closed refresh semantics; the fallback is forbidden and then made
structurally impossible.** Every failure of the freshness read refuses the refresh
with `invalid_grant`: the custody claim absent (a pre-change token) or
undecryptable — tampered, under an unknown key or version, an expired envelope,
or a subject mismatch at the custody seam (A6: decryption failures join these
refusal classes with their own audit reason) — the provider unreachable, the
provider refusing the grant, the answer unusable
(no token, unverifiable signature, wrong issuer), a `sub` mismatch, or the roles
source path absent from the fresh token. The tempting alternative — serving the
frozen snapshot when the read fails — is rejected on the same terms as the first
taking (it reintroduces exactly the staleness this change exists to remove,
silently, precisely during provider-side incidents), and this design goes further:
**the gateway's refresh token no longer carries a claim snapshot at all.** The
refresh token's payload is reduced to its session bindings (`sub`, `aud`, `typ`,
`jti`, `iat`, `exp`, `client_id`, `resource`) plus one non-binding member: the
encrypted custody claim (D3) — ciphertext, not claims, and never a mint input;
the mint at refresh has exactly one
claim input — the verified fresh read — so the fallback path does not exist to be
taken under an availability squeeze. The `aud` binding among those session
bindings is pinned as the **token-type separation**: the refresh token's audience
is the resource alone (`gateway/tokens.py:232`) — the audience marker the access
mint carries (`gateway/tokens.py:202`) is never included — because the marker is
what makes a gateway-issued token a Core-acceptable access token (Core's
identity-provider entry rejects every gateway-issuer token lacking it), so its
absence keeps the refresh token from ever being one; and with no copied claims
aboard, the token authorizes nothing at Core's role-path matching even absent
the marker check. The code grant keeps its claim snapshot (the
code's own short TTL is its freshness bound, as today). Three refusal classes are
distinguished on the audit trail, all inside the token endpoint's closed reason
table: `custody_decrypt_failed` (the custody seam failed — the claim absent,
tampered, under an unknown key-id or version, expired, or bound to another
subject; a class of its own so a custody-key mistake or a botched rotation never
reads as a provider outage or as mass revocation), `claims_read_failed` (the read
failed — unreachable, unusable answer, subject mismatch, roles path absent, or
a provider 4xx other than `invalid_grant`) and `idp_session_ended` (the provider
refused the grant with `invalid_grant` — RFC 6749 §6's session-gone code; the
session is gone: revoked, expired by session policy, or consumed by a lost
rotation). The keying is on the
error code, not the status class: `invalid_client` (a misconfigured client secret)
and `invalid_request` (a gateway bug) are 4xx refusals that say nothing about the
session, so they land on `claims_read_failed` — a wrong client secret answering
every refresh with 401 must read as the misconfiguration it is, not as mass
revocation. The distinction is the operator's signal:
a burst of `idp_session_ended` during an incident is the designed
revocation-propagation or a session-policy break (D6's loud failure); a burst of
`claims_read_failed` is an outage or misconfiguration; a burst of
`custody_decrypt_failed` is the gateway's own custody key or rotation — three
diagnoses, three tokens. Migration: refresh tokens
issued before this change carry a snapshot the new grant ignores and no custody
claim — they fail closed once, at their next refresh, on the custody refusal
class, and the user re-signs-in;
the same loss class RES-15 already discloses for restarts.

**D5 — The no-`offline_access` amendment: the recorded principle changed
deliberately, with the trade priced.** M13's convergence — the provisioning never
requests `offline_access`, and the flow mints no provider refresh token, as the
token-harvest bounding control for T1-1 — is amended on the owner's meta-ruling
that PoC-era principles are revisable where the design misses an important piece.
The amended line: **`offline_access` is still never requested, and no offline
(beyond-session) grant is ever acquired — what changes is that the session-bound
refresh token the provider already issues at the code exchange (and which the flow
discards today, unused) is carried, encrypted under the gateway's dedicated custody
key inside the gateway's own refresh token, for the refresh window instead of
being thrown away (D3).** What the amendment buys, stated as gains: (a) the gateway's
refresh capability **ends when the user's IdP session ends** — the gateway cannot
outlive the identity the session represents, on any provider whose refresh tokens
are session-bound; (b) **IdP-side session revocation propagates to the gateway's
refresh capability at the next refresh attempt** — a strict improvement over the
snapshot design (a revoked user kept working for the whole window) and over the
overruled userinfo design (the provider's session state was invisible to the
mechanism); (c) no 30-day or 90-day offline grant exists anywhere in the system —
the capability acquired is a rotating handle to a live session, bounded by the
provider's own session policy. What it costs: the carried material is **mintable**
— and under v3 its encrypted form rides the refresh token itself, delivered to the
client by design (the plaintext never is): a compromised custody key plus a
recorded token archive can mint the user's provider identity tokens until the
provider's session policy ends the session — two halves that may now be collected
in different incidents, time-decoupled. That price is disclosed as its own
residual (the SIA's RES-21, re-shaped in four parts for the encrypted chain) with
the compromise
tables re-priced; it is recorded, not avoided. The honest per-provider boundary:
"session-bound" is exact on Keycloak (the refresh token references the SSO
session); on Entra the default public-client refresh token has no crisp per-session
object — its practical bound is the ~24 h sliding window (versus 90 days with
`offline_access`), and sign-out / admin session revocation kill it. The amended
M13 row is landed by this change's threat-model delta, so the model never carries
the pre-amendment wording as if it were current.

**D6 — The startup validator, re-derived: an operator assertion about session
policy, checked at three layers.** The old check (`refreshTtl` must not exceed the
IdP's access-token lifespan) loses its meaning entirely under the new mechanism —
the refresh grant mints fresh access tokens, so the provider's access-token
lifespan no longer bounds anything the gateway does. The invariant the design
actually needs is: **the carried session refresh token must remain usable at every
refresh in the window** — a property of the provider's session policy (Keycloak's
SSO Session Max; Entra's public-client refresh-token bound), not a number the
gateway can learn or verify at startup. The honest shape, in three layers:

1. **Startup keeps an arithmetic check on an operator-declared bound.** The setting
   is renamed and re-meaninged: `IDP_ACCESS_TOKEN_LIFESPAN_SECONDS` →
   `IDP_SSO_SESSION_MAX_SECONDS` — the operator's declared bound on how long the
   IdP keeps its session-bound refresh token usable. The check keeps its mechanics
   and its loud refusal (`refreshTtl` MUST NOT exceed the declared bound, the
   message naming both values), and the docstring, the refusal message, and the
   `.env.example` comment state what it is: an **assertion about provider session
   policy**, with the failure it cannot catch named (a session policy shorter than
   declared — a green check is arithmetic, not provider truth). The operator
   guidance from the independent evaluation is carried with it: where the
   provider's session policy is short, the short window is the *correct*
   configuration, not a degraded one — the freshness gain does not require a long
   window.
2. **The local realm's real values are verified live** by the provisioning check
   (task 2.5): the script reads the realm's SSO Session Idle/Max through the Admin
   API and refuses or warns when the configured window does not fit — the
   machine-checked version of the assertion for the one IdP this repo administers.
3. **The runtime break fails loud.** When the assumption is false in operation
   (the provider's session policy ends the session inside the window), every
   refresh past that point refuses with `invalid_grant` and the distinct
   `idp_session_ended` audit token — a diagnosable burst on the trail, not a
   silent return to stale tokens (D4 forbids the fallback that would make it
   silent).

A validator that survives only as an assertion is kept deliberately: deleting the
check would leave the window unbounded against the one provider property the
operator *can* know and the deployment *must* match.

### P3 — the served set

**D7 — What stays at startup versus moves to request time (re-taken on ruling 1).**
Startup keeps: the validation of *configured* restriction entries for the two refusals
that protect static routing — the reserved-name and charset refusals (the router's
locations are static and cannot repair either for a name the operator pinned) — and
one new refusal: resource inference enabled without a restriction configured with
exactly one entry. Startup **loses** the OAuth-declaration refusal, and with it the
`authentication_type` member of the mapping's schema: under the re-taken flow a
non-OAuth toolset is a *valid* entry — served through the signed-in short-circuit when
Core holds a credential, refused on the impossible branch otherwise — so an
operator-declared kind would be a second, staler source of a fact Core answers per
flow; a mapping entry carrying the removed member is refused loudly at parse (the
schema forbids unknown members and names the field), which is the honest migration
shape for a declaration that no longer means anything. What moves: the charset and
reserved-name checks become one request-time guard applied at every site a toolset
name is resolved (the protected-resource document, the authorization request's
`resource`, the status path, the refresh grant's resource), reusing the same
constants the router's alternation mirrors; the restriction check moves with them.
Nothing else can move and nothing else must stay: the mapping was never a routing
input (the router's locations are generic), so serving dynamically requires no router
change at all.

**D8 — Discovery mirrors Core's registry-independent unauthenticated tier (re-taken on
the owner's final correction — the consult deleted).** The protected-resource document
is served for a name the guard passes and the restriction (when one is configured)
admits — **whether or not Core's registry holds it**. Discovery makes **zero Core
calls**, holds no Core credential of its own, and its availability is the gateway's
own. The property is stated normatively as a **mirror**: the gateway's unauthenticated
discovery tier brings nothing Core's own does not — same 401-challenge on the data
path, same echo-document at discovery, existence decided at the same moment,
**post-authentication**. The empirical facts that justify it (each verified in the
Core source and the first two live, per the ruling's own test):

- *Core's MCP path, no identity, phantom or real: 401 + challenge.* The data path
  answers an unauthenticated call — for a toolset that exists or one that does not —
  with `401` and `WWW-Authenticate: Bearer
  resource_metadata="…/oauth-protected-resource/v1/toolset/{name}/mcp"`. The auth
  check precedes any registry lookup, so the unauthenticated tier has **no existence
  oracle**: a phantom and a real toolset are indistinguishable below authentication,
  on Core's own surface. (A fact of the enabled route — Core's
  `toolsets.security.authorizationServers` configuration is what serves it; unset,
  the MCP path still answers 401 but with no challenge header, and a challenge-less
  401 is no existence oracle either.)
- *Core's PRM route, unauthenticated, any name: 200.* The well-known
  protected-resource route (`WellKnownResourceMetadataService`) answers a fetch for
  **any** well-formed name with a document built from static configuration plus the
  requested path echoed as `resource` — no registry lookup, live-verified. Core's own
  unauthenticated discovery tier is registry-independent by construction. (Likewise a
  fact of the enabled route — the same `authorizationServers` configuration; unset,
  the controller answers 404, which is no existence oracle either, and the gateway
  serves its own document regardless.)
- *Through the front door, the router's challenge synthesis points the harness at the
  gateway's PRM route* (`router/nginx.conf`'s `WWW-Authenticate` map) — so the
  gateway's document is the one a challenged harness fetches, and today's
  404-for-unmapped answer at that route is the **mapping's** answer, not a system
  property. Deleting the mapping's membership gate removes the 404; nothing behind
  it ever knew existence.

*Why the consult is deleted, reasoned.* The consult era's design (ruling 2) served
the document only for names Core's registry holds, which required an unauthenticated
existence decision — and the empirical facts above show Core offers no
unauthenticated route that can make one: every registry-bound route sits behind
`Proxy.authorizeRequest`, so the consult needed a dedicated standing service
credential in Core (`dial_core_api_key`). That is the one credential class the
owner's principle bars — **the gateway holds no user-like standing credentials in
Core; its only Core credentials are the user's own per-flow token** — and buying it
back would have priced a third process-held secret, a per-request authenticated
registry read behind the unauthenticated perimeter (the amplifier threat), and a
discovery-to-Core availability coupling, all to refuse a phantom one leg earlier
than the flow's settings read already refuses it. With zero Core calls at discovery,
there is nothing to amplify and nothing to couple: the deleted threat (the ruling-2
era's DT-EP1-10) and the deleted residual (its RES-24) die with the consult rather
than being re-priced. The mirror property is the honest shape: an attacker probing
the gateway's discovery surface learns exactly what the same probe against Core's
own unauthenticated tier learns — a document naming a challenge, never an
existence answer — and the enumerable-set widening that dynamic serving does bring
(DT-EP1-2) is priced on its own.

*What is deleted with the consult.* The consult client, the `dial_core_api_key`
settings slot, the `gateway_discovery_max_concurrent_consults` bound, the abuse-bounds
amendment that extended the rate limits to the protected-resource endpoint for the
consult's sake, the discovery-side failure shapes (the 503, the 403-omits-kind
answer), the cache question (OQ-I — no consult means no cache decision), and the
consult's threats (DT-EP1-10, DT-EP5-5, DT-EP4-2 with their grid rows, G9/G10,
M22, RES-24, T1-20/T5-8/T4-9). The 503-shaped "Core unreachable" failure moves to
the flow's settings read, where it already lives today (`gateway/core.py`'s
transport-failure refusal). *Not deleted, and not restored by this deletion:* the
protected-resource endpoint joins the same per-source and global rate limiter every other
unauthenticated surface uses — not for the consult's sake (there is no consult), but as
DT-EP1-3's volume bound: the guard's refusals are audit records, and the limiter is what
caps their rate (the delta spec's abuse-bounds requirement carries the clause and its
scenario). What would let the gateway do better — refuse phantoms
at the door, keyless — is a **Core-side ask**, not this change (§8): the gateway
flips to a door-refusal the day Core provides a registry-bound protected-resource
route or an unauthenticated existence route.

**D9 — The protected-resource document is name-derived and kind-less (re-taken).**
The document's `scopes_supported` echoes the operator restriction's entry where the
toolset is pinned there, exactly as today, and is empty otherwise; the
**authentication-kind extension is omitted for every document**. Under guard-only
serving the discovery surface has no kind source: the mapping's kind declaration is
deleted (D7), and the kind a flow acts on is Core's answer at the flow's
authenticated settings read — echoing it here would mean a Core call, which is
exactly what the final correction deletes. The members are informational; the scopes
the upstream leg actually sends come from the toolset's Core settings either way,
and a client's faithfully echoed `scope` parameter is already accepted and dropped
at the authorization endpoint, so an omitted member costs nothing on any leg. The
document is otherwise exactly today's: the name-derived resource URI and the single
AS issuer, built from configuration and the requested path — the same
registry-independent construction Core's own PRM route uses.

**D10 — The harness-visible refusal shapes, re-taken.** At discovery: a guard-failing
or restriction-excluded name receives the same 404 it receives today; a guard-passing
name receives its document, phantom and real alike (the mirror property — the
phantom's document costs the harness one browser round-trip and one identity-leg
exchange before the flow's settings read refuses it, the same lesson the same probe
against Core's own tier would teach one leg later). There is no discovery 503:
discovery consults nothing, so it has nothing to fail against. At the flow: the
impossible-branch refusal is a plain-language page — "this toolset's credential is
configured directly in DIAL and cannot be established by a consent flow; ask your
DIAL administrator" — audited under the existing `non_oauth_toolset` token, and the
unknown-name refusal at the settings read ("this toolset is not registered in DIAL
Core", today's fixed text) is now the **system's only existence refusal**. A harness
therefore observes one genuinely new error shape (the impossible-branch page) and one
new success (the short-circuit's consentless completion), both self-describing; every
other shape is one today's system already answers. The audit vocabulary gains the
guard's tokens (`reserved_toolset_name` / `invalid_toolset_name` /
`restricted_toolset`) and the flow's `non_oauth_toolset`; `unknown_toolset` keeps its
existing home at the flow's settings read and the status endpoint — fixed vocabulary,
non-credential facts, truncated per the existing cap.

**D11 — Ruling 1: the kind check becomes the upstream stage's routing decision.**
The flow's stages, re-ordered around the owner's two-situations frame (both
situations run the same logic):

1. **The identity leg** (either situation): the browser is redirected to the identity
   provider under the gateway's public PKCE client and the code is exchanged — this
   leg is kind-agnostic by construction and stays so; it establishes *who* is signing
   in, never what kind of credential the toolset uses.
2. **The settings-and-status read as that user** (the DIAL authorization check,
   unchanged in position): Core's public settings projection now also carries the
   toolset's `authentication_type` and the caller's per-toolset statuses — the read
   stops refusing a projection whose OAuth fields are absent, because a non-OAuth
   toolset is now servable; the OAuth-fields completeness refusal moves to the
   consent branch, the only branch that builds a URL from them. A name Core does not
   know still fails here — and this read is now the **system's only existence
   refusal**: discovery answers phantom names a document by the mirror property
   (D8), so existence is decided post-authentication, exactly where Core's own model
   decides it.
3. **The signed-in check, before any upstream leg** (D12): a stored credential at
   user level OR global level short-circuits the upstream stage entirely — mint the
   harness's code, done — regardless of authentication kind.
4. **The kind branch, only when no credential is stored**: OAUTH → the consent leg
   exactly as designed (interstitial, upstream authorize, callback, credential call
   at USER level); any other kind → the impossible-branch refusal (D10's page), no
   upstream round-trip.

*The loop analysis, restated honestly.* The impossible-branch refusal loops benignly,
identically to any auth error: each 401 on the data path drives one flow, the flow
refuses with a page naming the cause, and the cycle repeats at the rate the limiter
bounds — each cycle costs the harness one browser round-trip and the gateway one
identity-provider exchange. No retry the user performs changes the outcome, and the
page says so; the state that ends the loop changes **out of band** — an administrator
stores the credential (a user-level key through Core's own paths, or a GLOBAL-level
key through the ops API), after which the signed-in check passes and the same flow
short-circuits. The old design's loop-prevention argument (an OAuth challenge in
front of a non-OAuth credential is unsatisfiable) is preserved where it was true —
the consent leg still never runs for a kind it cannot satisfy — and narrowed where it
was over-broad: the kind no longer gates the *flow*, only the *upstream stage*.

*The C1.5 unification, stated explicitly.* The general rule this re-taking lands —
**the upstream stage runs only when the credential is missing AND the kind makes it
establishable by consent** — is exactly the rule C1.5 (apps as MCP resources,
Core's DIAL_NATIVE kind: no upstream credential at all, the caller acts as the user
via that user's offline credentials, Core's enricher answering user-level status from
those offline credentials) needs: a DIAL_NATIVE resource has no consent leg ever, so
its flow is the identity leg plus the signed-in check plus the short-circuit, all of
which this change builds. What remains C1.5's own scope, and is now smaller: the apps
resource *surface* (routes, discovery documents, and the router's apps MCP path — a
new path shape this change does not touch) and the semantics of the *unsigned*
DIAL_NATIVE case (a user with no offline credentials — the impossible branch refuses
it under this change's rule; whether C1.5 wants a different answer for that case is
its decision, on machinery this change has already built).

**D12 — Ruling 1's other half: the signed-in check — which Core API, its trust
basis, its failure shape, and the GLOBAL delegation stated.** The check rides the
flow's existing per-user read (`read_toolset_for_flow`): the settings route where
Core's build enriches it with per-caller statuses, the deployment-listing route
otherwise — both authenticated with the *user's own verified identity token*, which
is the trust basis: the answer is Core's, about Core's own credential store, reached
on the internal leg from the configured Core, the same trust that already carries the
settings the flow builds its URLs from (a peer who can forge the status can already
forge the whole projection — DT-EP5-4 prices the one new gain that fact leaves).
Core's answer distinguishes the levels by wire member (`user_level_auth_status`,
`global_auth_status` — verified against Core's `ResourceAuthSettingsData`; the
vocabulary is SIGNED_IN / SIGNED_OUT / FAILED), and the check accepts SIGNED_IN at
**either** member. The answer carries a third member, `app_level_auth_status` (the
APP_LEVEL credential class in Core's model): the check reads the user and global
members only — an app-level status is not a sign-in for this flow, so a toolset
whose only stored credential is APP_LEVEL fails closed into the kind branch like
any not-signed-in answer (an operator storing an APP_LEVEL credential for a
non-OAUTH toolset gets the impossible-branch refusal), a behavior named rather
than left to inference. The failure shape is fail-closed in the specific direction that
matters: a status that is absent, unreadable, or FAILED is *not signed in* — the flow
falls through to the kind branch (an OAUTH toolset gets its consent leg, the safest
path the flow has; any other kind gets the impossible-branch refusal) — so no token
is ever minted on an unreadable status, and the short-circuit requires a positive
answer.

*The GLOBAL delegation, priced and stated (use vs establish — the distinction the
invariant wording must carry).* A GLOBAL-level credential short-circuits the consent
for **every** user whose Core ACL permits the toolset: any authenticated user can
harness the toolset through the gateway, consentless. That is a real delegation and
it is stated, not slipped in: (a) the flow never **establishes** a global credential
— the credential call stays `credentialsLevel: USER` on every establishing path — it
**uses** one that an operator configured, and the main spec's "GLOBAL-level
establishment refused" invariant keeps its exact meaning through that distinction;
(b) the access the delegation grants is not new — the same user, holding a
primary-provider token, already reaches the same toolset through Core's own paths
(the PoC's criterion-5 coexistence), because Core injects the global credential on
the data path whichever front door the call came through; the gateway adds a *front
door*, not access; (c) the minted token carries only that user's own claims, is
bounded by the access TTL, and Core's per-call DIAL authorization runs on it as on
every token. The mis-use shape (an administrator's ordinary ops action silently
changing gateway behavior for every user) is enumerated as DT-EP1-12 and accepted as
design: the administrator's configuration *is* the authorization decision, in Core's
own credential model — the same semantics the deployment already runs when the same
admin stores a global key for a model or an application.

## Security impact analysis

Per the standing method's per-change shape: this is a change on existing surfaces,
so the tables below enumerate the **delta threats** at the touched entry points;
untouched surfaces are covered by the invariant ruling table, not re-enumerated.

### 1. Change description

*Business:* the served toolset set follows Core (an operator restriction instead of
a required mapping; discovery answers every guard-passing name, mirroring Core's own
registry-independent unauthenticated tier — existence is decided post-authentication,
at the flow's settings read; the flow's kind check becomes the upstream stage's
routing decision —
a stored credential, user-level or global, short-circuits the consent for any kind,
and only a missing credential plus a non-OAuth kind is refused, loudly), and a
refresh re-reads the user's current claims — by presenting the identity provider's
own session-bound refresh token (carried, encrypted, in the gateway's own refresh
token — D3) at the provider's
token endpoint and minting from the verified token the grant returns, so a claim
change reaches minted tokens within the access TTL and an IdP session revocation
ends the gateway's refresh capability at the next refresh. *Implementation shape:
the provider's session refresh token (never an offline grant — no `offline_access`
is requested) is carried for the refresh window as an **encrypted claim inside the
gateway's own refresh token** — an AES-256-GCM envelope (`version | key-id |
nonce | ciphertext‖tag`) under a dedicated, key-id-versioned 256-bit custody key,
encrypted at the code grant, decrypted at every refresh, re-encrypted into each
rotated refresh token (latest-wins across the provider's own rotations); the
carrier is the refresh token only, never the access token or the authorization
code; between flow end and the code grant the token transits a server-side
pending entry keyed by the authorization code's `jti` — there is no long-lived
per-session store; a configured provider-token size bound refuses over-sized
tokens loudly at sign-in; the token-endpoint form-body cap is raised and
re-priced; the claim source at refresh is the same token-endpoint carrier and
the same verification path as issuance, with a mandatory `sub` cross-check
against the gateway's own signed subject (and the envelope's embedded `sub`
checked at the custody seam); the gateway's refresh token drops its claim
snapshot (the fallback becomes structurally impossible); the name guard and the
restriction move to a request-time check shared by every name-resolution site;
the flow's settings read carries the authentication kind and the per-caller
statuses, a stored credential at user OR global level short-circuits the upstream
stage for any kind (the credential call stays USER-level — the flow uses a global
credential, it never establishes one), and the kind branch runs the consent leg
only for OAUTH, refusing any other kind on the impossible branch with a
plain-language audited page; discovery serves every guard-passing,
restriction-admitted name its document — phantom and real alike, **mirroring Core's
own registry-independent unauthenticated tier by design** (the same 401-challenge on
the data path, the same echo-document at discovery, existence decided at the same
moment — post-authentication, at the flow's per-user settings read, the system's
only existence refusal): zero Core calls at discovery, no Core credential of the
gateway's own, and discovery's availability is the gateway's own.*

### 2. Impact level, with reasons

**Medium.** Sensitive assets are involved and their custody changes in two
qualitative ways: the gateway's process now holds a **second persistent secret**
— the dedicated custody key, in the signing key's own custody class — beside the
transient plaintext of the presenting sessions' provider refresh tokens (never a
per-session store); and the **refresh token itself grows and is delivered to the
client carrying encrypted mintable material inside**, with a hard dependency on
harness token stores the gateway does not control (the reason the live two-harness
round-trip is an implementation gate, not a follow-up). The unauthenticated
token-endpoint body cap is deliberately raised and re-priced. The P3 re-taking adds
**no new process-held secret** (the final correction deletes the consult era's
Core service API key — the process's secret set stays the signing key and the
custody key; the gateway's only Core credentials are the user's own per-flow token)
and **no new outbound call on the unauthenticated perimeter** (discovery makes zero
Core calls — the consult and its amplifier threat are deleted), plus a mint path
newly reachable for non-OAUTH
kinds (DT-EP1-11). The mint path's
claim source changes (an integrity surface — whatever the verified provider
answer carries is what Core authorizes on). No new trust boundary, public
endpoint, or grant type is introduced: the new identity-provider call (the
refresh grant) rides the existing back-channel boundary to an endpoint the flow
already calls, and the new secret sits inside the
process boundary the signing key already occupies. The level sets the security
review gate's depth, not whether this analysis runs.

### 3. Invariant ruling table

| # | Invariants | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | **Preserved, strengthened in wording** | The upstream leg and the credential call are untouched; the code transit and the USER-level stamp are exactly as before; and the new short-circuit path — the one path that mints without an upstream leg — never reads or transits any stored upstream credential at all: it reads a *status*, and Core injects the stored credential on the data path, whichever level it is stored at |
| 2 | The upstream PKCE verifier never leaves Core | **Preserved** | The settings projection read is unchanged; Core's nulling of the verifier on public reads is what the flow still consumes |
| 3 | Per-user credential isolation | **Preserved with a stated delegation — the global-level use-vs-establish distinction is normative** | The E7 chain is untouched; the custody envelope's embedded `sub` is checked at the seam against the refresh token's signed subject, so a blob swapped between users' tokens refuses; the provider-side `sub` cross-check now binds *every* mint — issuance and refresh — to a subject the provider just asserted. The ruling-1 re-taking adds the stated delegation: the signed-in check short-circuits on a **GLOBAL** credential too, so an operator's global key makes the toolset consentlessly harness-able by every ACL-permitted user — the flow **uses** that credential (Core injects it on the data path) and never **establishes** one at GLOBAL level (the credential call stays USER-level on every establishing path), and the access is the same the same user already holds through Core's own paths; the minted token still carries only that user's claims and Core authorizes it per call |
| 4 | DIAL authorization applies to every toolset call | **Preserved with a disclosed bound — the bound shrinks** | Claims are now as fresh as the last refresh: a provider-side change reaches minted tokens within the access TTL once the harness refreshes; an already-minted access token carries its claims to its own expiry (≤ access TTL); Core's per-call DIAL authorization runs unchanged on those claims; and the flow's own DIAL authorization check — the per-user settings read before any upstream stage — runs on every path, the short-circuit included |
| 5 | No credential in logs, argv, or error messages | **Preserved** | The custody claim's plaintext and ciphertext are never logged, and the provider's refresh answers are never logged; every new refusal uses fixed-vocabulary reasons with non-credential facts, truncated per the existing cap; the retention rule's "never delivered to any client" is amended M13-style — the *plaintext* is never delivered, the *ciphertext* is, by design, and is unusable without the custody key (D3) |
| 6 | No hardcoded credentials in the repository | **Preserved** | No new credential enters the repository: the custody key and the refresh grant's optional client authentication ride the existing `.env` mechanism and committed placeholders (the requirement to move both under the deployment's secret management is recorded, owner: the deployment, C3's scope) |
| 7 | The signing key is IdP-grade secret material | **Preserved** | Key custody, publication, and rotation are untouched |

### 4. Delta threat tables, per touched entry point

Structure per the vendored instruction. Mis-use cases are marked **[mis-use]**;
flow/logic flaws classify under Use Control Misconfiguration with the leaf chosen by
the attacker's gain and the flaw named in the description. EP3 (the browser
callback pages) is touched — the non-OAuth and unknown-name refusals render a new
plain-language page on the identity-leg callback — but carries no delta table: the
page is fixed text rendered through the shared hardening helper, adding no threat
shape beyond the refusal records EP1 already prices.

#### EP1 — the public OAuth and discovery endpoints (toolset resolution; the flow's short-circuit; the refresh grant)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP1 (discovery, E3) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Router-shape name smuggling | A13 (routing and challenge integrity); the AS/data-path split | I, Access | A toolset name that the request-time guard judges differently than the router's locations would — a reserved name served, or a charset edge the guard and the regex disagree on — captures another surface's traffic or serves a toolset whose MCP path can never route. The guard must be the same constants the router's alternation mirrors, or the startup check's guarantee is lost rather than moved. |
| EP1 (discovery, E9) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Served-inventory enumeration widens **[mis-use]** | The deployment's toolset inventory (public discovery); per-user sign-in states | C | With no restriction configured, the enumerable set grows from the operator's pinned list to every name that passes the guard — the mirror property's price, stated plainly: Core's own unauthenticated discovery tier is likewise registry-independent (a phantom fetch against Core's PRM route earns a 200 echo document, verified live), so the widened set names nothing the deployment's unauthenticated tier did not already name; the existence answer lives one leg deeper, post-authentication, on both sides of the front door. Within that set a legitimate user can still walk the status endpoint or discovery across the platform bucket, probing the deployment's inventory beyond any need their own work states. The statuses returned remain the caller's own, and discovery is public by design; what widens is the inventory the public surface names. |
| EP1 (discovery, E3) | Injection | Refusal-record volume amplification | A9 (the audit trail) | A (log volume), I | The guard refusals are unauthenticated and each writes an audit record; a loop of crafted guard-failing names writes records at the request rate, growing the operator's log with caller-chosen names. The record's shape is fixed-vocabulary with truncated facts, so the content is not attacker-written — only the volume is attacker-influenced, and the volume is capped by the per-source and global rate limits the discovery endpoint shares with every other unauthenticated surface (the endpoint joins the limiter; over-limit requests write no record, so the record rate is bounded at the limit itself). Discovery itself costs the gateway one static document per request (the mirror property — no Core call), so a document-flood's resource shape is the surface's existing bounded serve, not a new outbound amplification. |
| EP1 (E4 refresh) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Stale-snapshot fallback | A3's claim set (the authorization decision's data); A6 | I (claim fidelity), Access beyond current authorization | Claim-staleness flaw, reintroduced: if a claims-read failure at refresh were answered from a frozen snapshot, a revoked role would live on in minted tokens for the rest of the window — silently, and precisely during provider-side incidents. The design removes the snapshot from the refresh token outright (D4), so the fallback has no data to serve; the threat is listed because re-adding a snapshot to the refresh token is the implementation's most tempting shortcut under an availability squeeze. |
| EP1 (E4 refresh) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Refresh as an outbound-call amplifier | A14 (the shared worker pool); the identity provider's token endpoint | A | Each refresh now spends a worker-thread slot, one outbound identity-provider call, and one constant-time AES-GCM decryption of the custody claim where it previously spent none; the decryption is microseconds — negligible beside the RSA verification the endpoint already performs — and is priced here only so the per-request cost row is complete. A flood of refresh requests within the rate limits multiplies outbound load against the provider and holds pool capacity — T1-7's shape with a per-request cost it did not have. |
| EP1 (E4 refresh) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Provider outage becomes a refresh outage | A14 (the sign-in surface's availability) | A | Dependency-availability flaw: with the claims read mandatory and fail-closed, an identity-provider outage refuses every refresh; affected users funnel to re-sign-in, which also needs the provider — a full sign-in outage for the provider's downtime, where today's refresh would have kept serving the snapshot. Already-minted access tokens keep working to their own expiry. |
| EP1 (E4 refresh) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Refresh cadence keeps the IdP session alive **[mis-use]** | A8 (the user's SSO session); A3 | I (session lifetime), Access | Session-lifetime flaw: presenting the session-bound refresh token refreshes the IdP session's idle timer, so a harness refreshing on its own schedule keeps the user's SSO session alive after all browser activity has ended — the gateway becomes a session keepalive its user never chose, and the user's "walking away" no longer ends their identity session on the idle timescale. Bounded by the provider's SSO Session Max (an absolute, non-sliding cap — default 10 h on Keycloak), the gateway's own non-sliding refresh window, and the fact that explicit revocation still propagates immediately at the next refresh. |
| EP1 (E4 refresh) | Injection | Crafted custody blob | The custody claim's envelope and the custody seam (the decrypt-and-check path) | I (custody integrity), C | The presented refresh token's custody claim is attacker-controllable ciphertext: a caller who holds or crafts a refresh token can substitute, truncate, or splice the blob, hoping the decrypt path leaks state, accepts a foreign plaintext, or serves an oracle. Bounded by construction: AES-GCM is an AEAD with no padding (no padding-oracle class), the tag check fails closed on any tamper, the version/key-id are looked up in a fixed keyset with the algorithm pinned in code constants (M20 applied to our own encryption — nothing envelope-selected), the nonce is gateway-chosen at encryption and never attacker-supplied, and the seam's `sub`/`exp` checks refuse misplaced or stale blobs. The refusal class is audited with its own fixed-vocabulary reason (`custody_decrypt_failed`). |
| EP1 (the issued refresh token, in the harness's token store) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Grown refresh token overflows a harness token store | A4 (the refresh token); the user's refresh capability | A | Dependency-capacity flaw: the custody claim grows the refresh token into the multi-KB class, and harness token stores are not governed by any RFC size guarantee — the store class that hurts is real (OS keychain/credential-manager stores carry hard item-size limits; the Windows Credential Manager's 2560-byte blob bound is canonical). A token too large for its harness's store breaks the session silently, far from its cause — the user's availability, not the gateway's. Bounded by the provider-token size bound refused loudly at sign-in (the failure lands at the one moment its cause is diagnosable), the re-priced body cap, and the live two-harness round-trip gate (task 3.3) before adoption; the accepted remainder is every harness store beyond the two field-proven ones. |
| EP1 (the flow, the signed-in short-circuit) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Mint-without-consent surface widens to non-OAUTH kinds | A3's claim set; the toolset resource's token audience (A4); the establishment path's integrity | I (authorization fidelity), Access (bounded) | The mint machinery — unchanged in itself — is newly reachable for toolsets of every kind, on a path where no upstream consent and no credential establishment ever ran: where the signed-in check passes (honestly, or by the forged answer priced at DT-EP5-4), the flow mints a gateway token addressed to the toolset's resource without the consent leg. The bounds are the stage order and the credential model: the DIAL authorization check (the per-user settings read) still runs before the short-circuit; the mint's `sub` is the identity-leg user's own; the short-circuit never reads or transits any upstream credential (Core injects the stored one on the data path — never-cut 1); and where the status answer was honest, a stored credential exists, so the mint is exactly the repeat-sign-in case the flow already had. Where the answer was forged (no stored credential), the minted token yields 401s on the data path — a misleading token and a diagnosable loop, not access. |
| EP1 (the flow, a GLOBAL credential) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Global credential silently widens the served surface **[mis-use]** | The toolset's upstream access (through the global credential); every ACL-permitted user's token audience | I (the consent's absence), Access (as configured) | An administrator's ordinary ops action — storing a GLOBAL-level credential for a toolset through Core's own API — silently changes gateway behavior for every user: each ACL-permitted user's next sign-in short-circuits with no consent screen, and the toolset becomes harness-able through the gateway front door. A legitimate privileged act, used exactly as permitted, rewarded with a behavior change the gateway never separately approved. Bounded and accepted as design: the administrator's configuration IS the authorization decision, in Core's own credential model — the same semantics the deployment already runs when the same admin stores a global key for a model or an application; the access is not new (the same user reaches the same toolset through Core's own paths with a primary-provider token — criterion-5 coexistence); the minted token carries only that user's claims and dies at the access TTL; and Core's per-call authorization runs on every call. The gateway's job is to state the delegation (D12's use-vs-establish wording) and record the short-circuit on the audit trail, not to re-approve Core's own configuration decisions. |

#### EP4 — the signing key's process boundary (the custody key; the transient plaintext)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP4 (process memory) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Custody-key compromise and transient plaintext | The dedicated 256-bit custody key (a second persistent secret in the signing key's custody class); the transient plaintext of the presenting sessions' provider refresh tokens; the encrypted claim at rest in harness token stores (A4/A17) | C, I | The process holds one custody key and, during each refresh grant, the decrypted provider refresh token of only the session presenting at that moment — never a per-session store, so a same-window compromise reads the key plus the
presenting sessions' plaintext and the minutes-bounded pending hand-off entries
(one per completed-but-unredeemed flow — category 1's window), not every live
session's credential at once (v2's aggregate exposure, dissolved). The genuinely new capability is the **time-decoupled conjunction**: an attacker who archives refresh tokens (each carrying the ciphertext, by design) in one incident and compromises the custody key in a later one can decrypt the archive and replay each archived user's provider identity — tokens DIAL itself accepts on its own endpoints — for as long as the provider's session policy allows each session to live. Bounded by the IdP session clock (SSO Session Max; Entra's ~24 h public-client bound — the archive dies with the sessions) and, **where enabled**, the provider's rotation reuse detection (the gateway's own next refresh races a lifted string and the chain is revoked for both — the containment control for the credential-on-the-wire exposure of plain-internal-leg deployments; deployments with TLS'd internal legs are bounded by the transport, the detection defense-in-depth there); strictly harder to assemble than a same-window whole-store read, and the honest shape of the price (RES-21, part ii). The key alone grants no upstream credential and no other user's identity; the mint-any-identity blast radius remains the signing key's own, unchanged. |

#### EP5 — the server-to-server legs (the new refresh-grant call; the flow's kind and signed-in decisions)

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP5 (gateway → IdP token endpoint, refresh grant) | Interception → Spoofing of the target (Man in the middle) | Forged refresh answer steers minted claims | A3's claim set (what Core authorizes on); A11 | I | The internal-leg forgery class gains a refresh-time entry: a compose-network peer in a MITM position on the plain-http token-endpoint leg serves an attacker-chosen token response (plus the matching hostile JWKS), and the gateway mints it — any claims for that `sub`. The `sub` cross-check binds the subject (the forgery cannot mint for another user — the refresh token's `sub` is the gateway's own signed claim), so the gain is any-claims-for-an-existing-`sub`, strictly narrower than the existing exchange-time forgery chain's mint-any-sub — and the same boundary and the same acceptance as that chain (RES-19). |
| EP5 (gateway → IdP token endpoint, refresh grant) | Interception → Eavesdropping | Mintable credential presented on the internal leg | The decrypted provider session refresh token, on the internal plain-http wire, once per gateway refresh | C | The token-use rule's exposure widens in kind, not just count: at each refresh the gateway decrypts the custody claim and presents the provider's session refresh token once on the internal plain-http leg — a network peer reading the leg holds a *mintable* credential for that session's user, renewable by use on providers with sliding session semantics, not a token that dies at a fixed `exp`. The custody key itself never leaves the process, and the ciphertext's other presentation is the client-bound `/dial/token` form body — delivered by design, not an internal-leg exposure. Same boundary and same acceptance class as the existing internal-leg exposures (RES-19); the frequency grows with refresh cadence, and the artifact at stake on this leg is the most powerful credential the flow ever presents. |
| EP5 (the flow's kind and signed-in decisions) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Forged settings answer steers the re-taken branch | A11 (Core's toolset configuration as the flow reads it); A14 (the user's time) | I, A | The kind and the per-caller statuses now both come from a runtime Core answer whose integrity is the internal leg's, and they steer the re-taken branch: a forged OAUTH kind for a credential-less non-OAuth toolset sends the flow down a consent leg that can never satisfy it (the old unsatisfiable-loop shape, now per flow and bounded by one session); a forged non-OAUTH kind refuses a servable toolset (a denial of one flow, self-inflicted by whoever controls the leg); a forged status is the sharper sibling, priced as DT-EP5-4. The same leg now also carries the system's **existence decision** (the deleted consult's threat, DT-EP5-5, merged here rather than left dangling): discovery answers phantom names a document by the mirror property (D8), so a forged not-found on this read is the one way a servable toolset's sign-in surface can be denied — the same denial-of-one-flow shape as the forged kind, on the same leg and under the same trust, and its forged-existence sibling (a phantom served past this read) cannot happen: no answer this leg returns can make a phantom's data path answer anything but 401. The forged answer must arrive on the trusted internal leg from the configured Core — the same boundary and the same bounding analysis as the existing forged-settings threat; what changes is that no class of kind misconfiguration is caught before the container starts (the startup declaration is gone, D7) and that the branch, not a precondition, is what the forgery steers. |
| EP5 (gateway → Core, the per-user settings/status read) | Interception → Spoofing of the target (Man in the middle) | Forged signed-in answer mints without an upstream leg | A3's claim set; the toolset resource's token audience (A4); the establishment path's integrity | I, Access (bounded) | The signed-in check's trust basis, priced: a compose-network peer in a MITM position on the per-user settings read forges a SIGNED_IN status (user or global) for a toolset whose credential is not stored, and the flow short-circuits — a gateway token minted with no consent leg and no credential establishment. What makes the answer trustworthy is nothing the gateway can verify independently: it is the internal leg from the configured Core, authenticated by the user's own identity token — the same trust that already carries the settings the flow builds its URLs from, so a peer who can forge the status can already forge the entire projection and the credential call's endpoints (the existing forged-settings chain, RES-19's acceptance). The gain is bounded by everything else the flow checks: the mint's `sub` is the identity-leg user's own (no cross-user minting); the DIAL authorization read still ran as that user; and the minted token without a stored credential yields 401s on the data path — the upstream is never reached, so the forgery buys a misleading token and a diagnosable loop, not toolset access. Same boundary, same acceptance class as DT-EP5-1 (the internal-leg residual, extended to one more member of the same answer). |

### 5. Mitigations per threat, in the fixed control-category order

Homes: **spec** = this change's delta spec (gateway-owned, normative); **repo** =
committed material; **Core config** / **deployment** = named with their owners.

**DT-EP1-1 Router-shape name smuggling**
1. Reduce Attack Surface — the guard applies at every name-resolution site; no site
   resolves a name without it (spec).
2. Isolation — not applicable: the guard is a shared predicate between the gateway
   and the router's config; there is no runtime boundary between two components
   that must agree, only the shared constant.
3. Authentication — not applicable: the guarded value is a path segment on
   unauthenticated discovery; no credential exists to check at this stage.
4. Authorization — **the control**: the guard reuses the exact constants the
   router's alternation mirrors (`[a-z0-9-]+`, the reserved list), so the
   request-time check and the routing cannot disagree; a name failing either is
   refused before it names anything (spec).
5. Data Protection — not applicable: no stored or transmitted secret is at stake;
   the compromise is routing integrity, carried by category 4.
6. Anti-Injection — the charset refusal is itself the injection bound: no
   metacharacter survives to any regex (the property the startup check already
   held, restated at request time) (spec).
7. Anti-DoS — the guard is a constant-time string check before any allocation;
   nothing is held (spec — the refusal paths allocate nothing).
8. Detective controls — every guard refusal is an audit record with a
   fixed-vocabulary reason and the truncated name (spec).

**DT-EP1-2 Served-inventory enumeration widens [mis-use]**
1. Reduce Attack Surface — an operator restriction, where configured, still pins
   the enumerable set exactly as today; the widening applies only to deployments
   that choose the dynamic mode (spec).
2. Isolation — not applicable: the probe reads public discovery documents and the
   caller's own statuses; no cross-user boundary exists to isolate behind.
3. Authentication — E9 requires a valid gateway token; anonymous probing is
   refused (spec — unchanged).
4. Authorization — the statuses returned are resolved as that user at Core; the
   probe cannot exceed the prober's own authorization (Core config — unchanged).
5. Data Protection — not applicable: the disclosed inventory is public by design
   in the discovery documents; the per-user data returned is the caller's own.
6. Anti-Injection — not applicable: fixed-shape responses; nothing of the
   caller's is rendered or executed.
7. Anti-DoS — E9 and discovery stay inside the public-endpoint abuse limits
   (spec — unchanged).
8. Detective controls — every status request and discovery refusal is audited with
   the toolset named; the enumeration pattern is the detectable signature (spec —
   unchanged). **Disposition: the inventory disclosure is inherent to serving
   dynamically — accepted as design, bounded by the restriction option and the
   mirror property (the set names nothing Core's own unauthenticated tier does not
   name).**

**DT-EP1-3 Refusal-record volume amplification**
1. Reduce Attack Surface — the guard refusals share the endpoint surfaces that
   already exist; no new endpoint is added (spec).
2. Isolation — not applicable: the audit sink is a log stream, not a component
   behind a boundary the caller crosses differently.
3. Authentication — not applicable: the volume arrives on unauthenticated
   surfaces by protocol; identity is not the lever.
4. Authorization — not applicable: a refused request authorizes nothing.
5. Data Protection — **the control**: records carry fixed-vocabulary reasons and
   facts truncated to the configured cap — a caller grows no record beyond the
   cap, so the content and per-record size are bounded by construction (spec —
   the existing refusal discipline, unchanged).
6. Anti-Injection — structure-only JSON records with no free-form caller input
   (spec — unchanged).
7. Anti-DoS — **the volume bound**: the per-source and global rate limits cap the
   record rate the same way they cap the request rate (spec — the protected-resource
   discovery endpoint joins the limiter with an amendment of its own: the guard's
   refusals write records, over-limit requests write none, and the bound therefore holds
   at the limit).
8. Detective controls — the trail itself; limiter 429s are recorded facts-free,
   so a volume attack is visible without being amplified (spec — unchanged).

**DT-EP1-4 Stale-snapshot fallback**
1. Reduce Attack Surface — **the control, made structural**: the refresh token
   carries no claim snapshot; the refresh grant's only claim input is the
   verified fresh read, so no code path can mint without one (spec).
2. Isolation — not applicable: the flaw is a data choice inside one function;
   no boundary placement distinguishes the branches.
3. Authentication — the fresh read authenticates by the provider's own refresh
   grant; a provider that refuses it fails the refresh (spec).
4. Authorization — the minted claim set can never be older than the last
   successful read; every read failure refuses the grant (`invalid_grant`)
   (spec).
5. Data Protection — not applicable: no secret is disclosed or tampered; the
   compromised property is claim fidelity, carried by category 1.
6. Anti-Injection — not applicable: nothing is injected; the threat is a
   shortcut, not an attacker payload.
7. Anti-DoS — not applicable: the fallback's harm is stale authorization, not
   load; the availability shape is DT-EP1-6's.
8. Detective controls — a claims-read refusal is an audit record with the
   fixed-vocabulary reason `claims_read_failed`, reaching the record through the
   closed reason table's named-class extension, distinct from every other
   `invalid_grant` refusal (spec); a pattern of them during an incident is the
   operator's signal that freshness failed closed, not silently.

**DT-EP1-5 Refresh as an outbound-call amplifier**
1. Reduce Attack Surface — the refresh grant runs only inside a validated
   refresh request: a request failing signature, denylist, or resource checks
   spends no outbound call, and a presentation without a retained entry spends
   none either (spec — the validation order).
2. Isolation — the call runs on the worker pool off the event loop, like every
   other outbound leg (repo — the existing thread-offload pattern).
3. Authentication — not applicable: the flood is of requests that fail
   validation; requiring authentication first would not reduce the rate.
4. Authorization — not applicable: the flooded requests fail before a principal
   exists beyond the token they present, which is itself the thing being checked.
5. Data Protection — the provider's refresh response is bounded parsing:
   size-capped, schema-checked, never logged (spec — the verification
   requirement; the parse mechanics are repo).
6. Anti-Injection — bounded response parsing so a hostile provider answer never
   executes or corrupts state (repo — the existing outbound-parsing discipline,
   extended to the new leg).
7. Anti-DoS — **the control**: the public-endpoint abuse limits bound the
   refresh request rate, which bounds the outbound call rate one-to-one; the
   outbound timeout bounds each call's duration. Residual queue-wait within the
   limits is the already-disclosed RES-4 class (spec — limits; repo — timeout).
8. Detective controls — limiter refusals and claims-read failures are audit
   records; a refresh flood is visible as 429 patterns (spec).

**DT-EP1-6 Provider outage becomes a refresh outage**
1. Reduce Attack Surface — only the refresh grant depends on the provider;
   already-minted access tokens and the local revocation denylist keep working
   (spec — self-contained tokens).
2. Isolation — not applicable: the dependency is genuine and required by the
   freshness goal; no boundary removes a needed call.
3. Authentication — not applicable: the outage is unavailability, not a
   credential failure.
4. Authorization — not applicable: nothing is being authorized while the
   provider is down; the flow fails closed.
5. Data Protection — not applicable: no disclosure path opens during the
   outage.
6. Anti-Injection — not applicable: the weapon is unavailability, not content.
7. Anti-DoS — **the bounding shape**: the failure is fail-closed with the
   provider's own timeout, access tokens bridge the gap to their expiry, and the
   recovery (re-sign-in) is the same path the user already knows. **Disposition:
   accepted as the priced cost of freshness — an availability-for-fidelity trade,
   recorded in the model's residual register as RES-20 (§7); the alternative that
   avoids it (the snapshot fallback) is DT-EP1-4's rejected flaw.**
8. Detective controls — claims-read refusals land on the trail with the
   fixed-vocabulary reason `claims_read_failed`, distinct from every other
   `invalid_grant` refusal, so a provider outage reads as a burst of them rather
   than as indistinguishable mass revocation (spec).

**DT-EP1-7 Refresh cadence keeps the IdP session alive [mis-use]**
1. Reduce Attack Surface — the gateway mints refresh tokens only at completed
   flows (rate-limited), and its own refresh window is non-sliding: the
   keepalive effect cannot outlive `refreshTtl` from the session's sign-in
   (spec).
2. Isolation — not applicable: the session being extended lives at the
   provider; no gateway-side boundary contains it.
3. Authentication — the extension is driven by presenting a credential the
   harness legitimately holds; the harness is the party whose cadence is
   tolerated, by design (spec — the refresh grant is the permitted use).
4. Authorization — **the bound**: the provider's SSO Session Max is an absolute
   cap the cadence cannot slide (Keycloak: idle refreshes but Max does not
   renew); the operator's declared session bound (D6) must fit the window, so
   the deployment's own configuration states how long this may run (spec — the
   startup lattice; the provider policy is the operator's).
5. Data Protection — not applicable: no secret is disclosed; the compromised
   property is session lifetime, carried by category 4.
6. Anti-Injection — not applicable: nothing is injected; the harness uses the
   grant exactly as permitted.
7. Anti-DoS — not applicable: the cadence is the harness's own refresh rate,
   already bounded by the token endpoint's limits.
8. Detective controls — token-refresh events are audited per session, so the
   refresh cadence of any session is answerable from the trail (spec).
   **Disposition: accepted and disclosed — the session extension is bounded by
   SSO Session Max and the non-sliding window; ruled accepted-as-priced by the
   owner (2026-11-01, §8 OQ-G), with RES-22 as the disclosure.**

**DT-EP1-8 Crafted custody blob**
1. Reduce Attack Surface — the custody claim exists on exactly one token kind
   (the refresh token) and is read at exactly one seam (the refresh grant,
   after the signature, type, denylist, resource, and client checks have all
   passed); no other path decrypts anything (spec).
2. Isolation — not applicable: the crafted input arrives on a public endpoint
   the caller is entitled to call; there is no second component behind a
   boundary the blob crosses before the seam.
3. Authentication — the envelope is only reached behind the gateway's own
   signed refresh token: an attacker without a valid token never reaches the
   decrypt path, and the token's own signature is the outer authentication
   (spec — the validation ladder's order).
4. Authorization — not applicable: the blob names no principal and grants
   nothing; the seam's `sub` check is an integrity/placement bound, carried by
   categories 5 and 6.
5. Data Protection — **the control**: AES-256-GCM is an AEAD — the tag
   authenticates the whole envelope, so any substitution, truncation, or
   splice fails closed with no partial plaintext released; the algorithm, key
   length, and nonce length are code constants and the key-id selects from a
   fixed in-process keyset, so nothing envelope-selected reaches the crypto
   (the M20 lesson applied to our own encryption) (spec).
6. Anti-Injection — no padding exists (AEAD), so there is no padding-oracle
   class to probe; the nonce is gateway-chosen at encryption time and never
   taken from the envelope; an unknown version or key-id refuses before any
   decrypt (spec).
7. Anti-DoS — the decrypt is one constant-time operation on a size-bounded
   claim inside a body-capped request behind the rate limits — a crafted-blob
   flood costs no more than the refresh flood DT-EP1-5 already prices (spec —
   the shared bounds).
8. Detective controls — every custody refusal lands on the trail with the
   fixed-vocabulary reason `custody_decrypt_failed`, distinct from the
   claims-read and session-ended reasons, so a probing pattern is visible and
   diagnosable as custody-side, not provider-side (spec).

**DT-EP1-9 Grown refresh token overflows a harness token store**
1. Reduce Attack Surface — the provider-token size bound
   (`gateway_custody_provider_token_max_bytes`) caps what may be carried at
   all, and it is refused **at sign-in** — the one moment the cause is
   diagnosable — never hours later at the first refresh (spec).
2. Isolation — not applicable: the failing store is a harness-side component
   the gateway cannot isolate anything from; the dependency is the harness's
   own.
3. Authentication — not applicable: the failure is a capacity overflow of a
   legitimate session's token, not an authentication event.
4. Authorization — not applicable: nothing is being authorized; the session's
   user is the party harmed.
5. Data Protection — not applicable: no disclosure path opens; the compromised
   property is the user's refresh availability.
6. Anti-Injection — not applicable: the weapon is size, not content.
7. Anti-DoS — **the bounding shape**: the size bound caps the token by
   construction; the raised and re-priced form cap keeps the refresh request
   deliverable; and the live two-harness round-trip (Claude Code/CIMD and
   Cursor/DCR — task 3.3) proves the grown token survives both field-proven
   stores **before adoption — a gate, not a follow-up**; a harness store with
   a hard item-size limit the bound cannot dodge becomes a named deployment
   prerequisite surfaced at sign-in (spec/repo).
8. Detective controls — the sign-in refusal is audited with the operator
   facing message; a store-side silent break is honestly stated as not
   gateway-visible — the gate exists precisely because the trail cannot be
   (repo — task 3.3's evidence). **Disposition: the two field harnesses are
   gated; every other harness store is the accepted remainder, bounded by the
   size bound's loud refusal.**

**DT-EP1-11 Mint-without-consent surface widens to non-OAUTH kinds**
1. Reduce Attack Surface — the short-circuit requires a positive SIGNED_IN
   answer at user or global level from the per-user settings read; absent,
   unreadable, or FAILED statuses fall through to the kind branch, so no token
   is minted on an unreadable status (spec).
2. Isolation — not applicable: the mint is one function inside the process;
   the widened reach is a predicate change, not a new component or boundary.
3. Authentication — the identity leg still authenticates the user under the
   gateway's PKCE client on every path, the short-circuit included: the minted
   token's `sub` is the live-authenticated user's, never a status answer's
   (spec).
4. Authorization — **the controls**: the DIAL authorization check (the
   per-user settings read, refused on 403) runs before the short-circuit on
   every path, and Core's per-call DIAL authorization runs on the minted token
   at the data path — the short-circuit removes a consent screen, never an
   authorization check (spec).
5. Data Protection — **the credential-model invariant re-checked**: the
   short-circuit never reads or transits any upstream credential — it reads a
   status; Core injects the stored credential on the data path, at either
   level (spec — the use-vs-establish rule).
6. Anti-Injection — not applicable: the attacker-controllable input at this
   stage is the status answer's integrity, which is DT-EP5-4's threat; the
   mint's other inputs are the flow's own verified state.
7. Anti-DoS — not applicable: the short-circuit mints *less* than the consent
   path (no upstream round-trip, no interstitial); its resource shape is a
   subset of the flow that already exists.
8. Detective controls — the short-circuit's code issuance is audited like
   every issuance (per-flow record, subject, client, toolset), so a burst of
   consentless issuances for one toolset is answerable from the trail (spec —
   the existing lifecycle records).

**DT-EP1-12 Global credential silently widens the served surface [mis-use]**
1. Reduce Attack Surface — not applicable without refusing Core's own feature:
   the widening is the global credential's semantics, which the gateway front
   door faithfully reflects; refusing it at the gateway would second-guess the
   operator's own configuration with a second authorization implementation the
   repo's design deliberately does not build.
2. Isolation — not applicable: no boundary inside the deployment separates an
   administrator's Core-side act from the gateway's view of it, and none
   should: the registry is one source of truth.
3. Authentication — every short-circuited mint still requires the live
   identity leg: no token is minted for a user who did not just authenticate
   at the provider (spec).
4. Authorization — **the bound, stated as the delegation**: the administrator's
   global credential IS the authorization decision (Core's own credential
   model — the same semantics as a global key on a model), and the access it
   grants is the same the same user already holds through Core's own paths
   with a primary-provider token; the minted token carries only that user's
   claims and Core authorizes per call (spec — D12's use-vs-establish wording;
   the invariant table's row 3).
5. Data Protection — not applicable: no secret is disclosed; the global
   credential never leaves Core on any gateway path.
6. Anti-Injection — not applicable: the act is a configuration write in Core,
   not a payload toward the gateway.
7. Anti-DoS — not applicable: the mis-use grants access, it consumes nothing.
8. Detective controls — the short-circuit's issuances are audited per flow
   (subject, client, toolset), and Core's own ops API records the global
   credential's storage — the delegation is answerable from the two trails
   together (spec — the existing records; Core config — the ops audit).
   **Disposition: accepted as design — the delegation is Core's own credential
   semantics stated in the gateway's own words (D12), not a gateway-side
   authorization decision.**

**DT-EP4-1 Custody-key compromise and transient plaintext**
1. Reduce Attack Surface — there is no per-session store to harvest: the
   process holds one custody key plus the minutes-bounded pending hand-off
   entries, and the plaintext of only the sessions presenting during a
   compromise window; the capability carried is the provider's *session-bound*
   token (never an offline grant — no `offline_access` is requested, D5), so
   what an archive yields ends with the provider's own session policy (spec).
2. Isolation — the key is process memory inside the container boundary the
   signing key already occupies; no new boundary is created, and none weaker is
   used (repo — the single-instance topology; the container is the boundary).
3. Authentication — not applicable: the threat is possession of the key by a
   process-level attacker; the key is not an authenticator but a decryptor, and
   no credential check stands between a holder of the key and the ciphertext.
4. Authorization — bounding: a decrypted credential still authenticates only
   its session's user — the thief gets that user's provider identity until the
   provider's session ends, never another user's and never an upstream
   (toolset) credential, which exists only inside Core (Core config —
   unchanged; never-cut 1); the envelope's embedded `sub`, checked at the seam,
   is what keeps one session's blob from serving another's token (spec).
5. Data Protection — **the controls**: AES-256-GCM under a dedicated,
   key-id-versioned 256-bit key separated from the signing key; the plaintext
   exists in the process only for the duration of a refresh grant and is never
   logged; the ciphertext is delivered only inside the refresh token to its
   presenting client; the carried window is bounded by the refresh token's
   absolute expiry, machine-checked at startup against the operator's declared
   session bound; rotation is a hard cut, so a superseded key stops decrypting
   everything at once (spec). The remainders — the time-decoupled
   key-plus-archive conjunction, the ciphertext at rest in harness stores, and
   the stolen-token-survives-restart regression — are the disclosed residual
   RES-21 (§7), whose bound is the IdP session clock, TLS on the internal legs
   (the production shape's primary bound), and the provider's rotation reuse
   detection where enabled (the plain-internal-leg deployments' containment
   control).
6. Anti-Injection — not applicable: the envelope is written by the gateway's
   own encryption path; caller input reaches only the decrypt side, where the
   AEAD tag, the pinned constants, and the seam checks refuse everything
   crafted (DT-EP1-8's block).
7. Anti-DoS — not applicable: a key compromise is a read of process memory;
   it consumes no service resource (the crafted-blob flood shape is
   DT-EP1-8/DT-EP1-5's).
8. Detective controls — token issue, refresh, revocation, custody-refusal,
   and session-ended events are audited per session, so which sessions presented
   near a compromise instant is answerable from the trail (spec — the existing
   per-flow records plus the custody refusal class).

**DT-EP5-1 Forged refresh answer steers minted claims**
1. Reduce Attack Surface — the token endpoint URL is derived from the configured
   issuer exactly as the exchange's is, never from any request; no caller steers
   the leg (spec).
2. Isolation — the call stays on the compose network whose members are the
   deployment's own services — the same private-bridge bound the existing
   identity legs rest on (deployment; repo compose).
3. Authentication — the fresh token is verified against the provider's own
   published keys with the issuer pinned, the same verification path as the
   exchange — but the *answer's* integrity rides the channel, not a signature
   the gateway can independently check. This is honestly partial — the channel
   is the control, and it is the one the existing exchange leg already trusts.
4. Authorization — **the bound**: the `sub` cross-check — the fresh token's
   subject must equal the gateway's own signed refresh-token subject, so the
   forgery mints claims only *for an existing session's user*, never for an
   attacker's chosen identity (spec). Role claims from the forgery are the
   accepted remainder, priced against the same boundary as the existing chain.
5. Data Protection — **the named control**: TLS on the internal legs where the
   deployment demands it — deployment-owned, unplaced today; the acceptance is
   the existing internal-leg residual's, extended to the refresh-grant call
   (deployment; the residual record is updated by this change).
6. Anti-Injection — bounded response parsing: the answer is size-capped and
   schema-checked before any claim is read (repo — the existing outbound
   discipline, extended).
7. Anti-DoS — the outbound timeout bounds a stalling peer (repo — the existing
   configured timeout).
8. Detective controls — claims-read failures are audited with fixed vocabulary;
   a forged-answer pattern (claims changing impossibly between refreshes) is not
   automatically detected — stated honestly, no anomaly detection is built.

**DT-EP5-2 Mintable credential presented on the internal leg**
1. Reduce Attack Surface — the token-use rule is restated in purposes: the
   decrypted provider refresh token is presented exactly once per gateway
   refresh, to the provider's token endpoint, and in no other code path; the
   ciphertext's only other presentation is the client-bound refresh-token
   delivery itself (spec).
2. Isolation — the presentations never leave the compose network (deployment;
   repo compose — unchanged).
3. Authentication — not applicable: the presented artifact authenticates its
   holder; that is the exposure being bounded.
4. Authorization — a sniffed credential still authenticates only its session's
   user, and dies with the provider's session — revocation at the provider
   propagates to it at its next use (Core config / provider — the session bound
   is the one control this exposure has that a fixed-expiry token does not).
5. Data Protection — TLS on the internal legs, deployment-owned, unplaced today
   — the existing internal-plain-http acceptance, now covering the
   highest-value credential the flow ever holds (deployment; the residual record
   is updated).
6. Anti-Injection — not applicable: the read is of wire traffic; nothing enters
   the gateway.
7. Anti-DoS — not applicable: a passive read spends no gateway resource.
8. Detective controls — the credential is never logged (never-cut 5); refresh
   and session-ended events are audited so the presentation count per session
   is answerable from the trail (spec).

**DT-EP5-3 Forged settings answer steers the re-taken branch**
1. Reduce Attack Surface — the kind read still exists, once per flow, on the
   same settings read that enforces DIAL authorization; the check became the
   upstream stage's branch condition, it was not dropped (spec).
2. Isolation — the settings read arrives on the trusted internal leg from the
   configured Core; the boundary is the existing one (deployment — unchanged).
3. Authentication — not applicable: the forged answer impersonates Core's
   configured position, not a credential the gateway could check independently.
4. Authorization — **the bound**: the settings source is operator-configured and
   the leg is the deployment's internal network — the same trust that already
   carries the credential call itself; a peer who can forge the kind can already
   forge the endpoints the flow builds (the existing forged-settings analysis,
   unchanged in boundary, extended in one consequence).
5. Data Protection — not applicable: no secret is at stake; the compromised
   property is configuration integrity on a trusted leg.
6. Anti-Injection — strict projection parsing: an answer without a readable
   authentication type fails closed as an unusable projection (repo — the
   existing strict-read discipline).
7. Anti-DoS — not applicable: the forged answer serves a flow, it denies
   nothing; the loop it produces is the user's cost, bounded by one session.
8. Detective controls — a non-OAuth refusal and a settings-read failure are
   audited with fixed vocabulary; the loop a forged kind produces surfaces as a
   failed flow on the trail (spec). **Disposition: bounded by the internal-leg
   trust (the existing class); the residual is the moved check itself — a
   configuration error class no longer caught at startup, priced against the
   dynamic-serving gain.**

**DT-EP5-4 Forged signed-in answer mints without an upstream leg**
1. Reduce Attack Surface — the short-circuit consumes only statuses from the
   per-user settings read the flow already performs; no new leg, no new
   surface, and no unauthenticated discovery-side status exists to confuse it
   with — discovery consults nothing (spec).
2. Isolation — the answer arrives on the trusted internal leg from the
   configured Core; the boundary is the existing one the settings read already
   trusts (deployment — unchanged).
3. Authentication — not applicable: the forged answer impersonates Core's
   configured position on a leg the gateway cannot authenticate against Core;
   the user's own token authenticated the request, not the answer.
4. Authorization — **the bounds**: the forged status cannot mint for another
   user (the `sub` is the identity leg's, provider-asserted); it cannot reach
   the upstream (no stored credential means the data path 401s — the forged
   mint buys a misleading token, not access); and the DIAL authorization read
   it rode already ran as the real user (spec).
5. Data Protection — not applicable: no secret is disclosed or tampered; the
   compromised property is the establishment path's integrity.
6. Anti-Injection — strict projection parsing: an unreadable status is not a
   signed-in status — the check fails closed into the kind branch (repo — the
   existing strict-read discipline, extended to the status members).
7. Anti-DoS — not applicable: the forgery mints, it does not consume; the
   401-loop it produces is bounded by one session and the rate limits.
8. Detective controls — the short-circuit's issuance is audited per flow, and
   the 401 pattern a forged mint produces is visible on Core's side as
   challenge-after-token — no anomaly detection is built, stated honestly
   (spec — the existing records). **Disposition: bounded by the internal-leg
   trust — the same acceptance class as DT-EP5-1 (RES-19's residual, extended
   to one more member of the same Core answer); no new residual is opened.**

### 6. The grouped mitigation list

| # | Mitigation | Home and owner | Addresses |
|---|---|---|---|
| G1 | The request-time name guard — one shared predicate (routed-path charset + reserved names, the same constants the router mirrors) applied at every toolset-name resolution site, with today's response shapes and fixed-vocabulary audit reasons | **Placed** — delta spec (gateway behavior); the shared constants are repo | DT-EP1-1, DT-EP1-2 (bounding), DT-EP1-3 (with G6) |
| G2 | The flow's routing decision on its own settings read — the signed-in check (user OR global level, unreadable/FAILED fails closed into the kind branch) short-circuits the upstream stage for any kind; the kind branch runs the consent leg only for OAUTH and refuses the impossible branch (any other kind, no stored credential) with a plain-language audited page; the use-vs-establish rule is normative (the credential call stays USER-level; the short-circuit never reads or transits any upstream credential; a global credential is used, never established) | **Placed** — delta spec | DT-EP5-3, DT-EP5-4, DT-EP1-11, DT-EP1-12 (bounding) |
| G3 | The verified claims re-read by the provider's refresh grant — the same token-endpoint carrier and verification path as issuance, mandatory `sub` cross-check against the gateway's own signed subject, bounded parsing | **Placed** — delta spec; the parse mechanics are repo | DT-EP1-4, DT-EP5-1 (the subject bound), DT-EP5-2 (the purposes rule) |
| G4 | Fail-closed refresh semantics with a snapshot-free refresh token — every read failure refuses the grant; the distinct audit tokens `custody_decrypt_failed`, `claims_read_failed`, and `idp_session_ended` reach the record through the closed reason table's named-class extension (the session-ended token keyed on the provider's `invalid_grant` specifically — RFC 6749 §6's session-gone code; the custody token its own class, so a key or rotation mistake never reads as a provider event), so a custody fault, a provider outage, a session-policy break, and a misconfiguration burst are each distinguishable from mass token revocation | **Placed** — delta spec | DT-EP1-4, DT-EP1-6 (bounding), DT-EP1-8 (detective), DT-EP4-1 (detective) |
| G5 | The custody envelope — the provider's *current* session refresh token (latest-wins across its rotations) carried as an AES-256-GCM claim (`version | key-id | nonce | ciphertext‖tag`, pinned constants, key-id from a fixed keyset, embedded `sub`/`exp` checked at the seam) inside the gateway's own refresh token only — never the access token, never the authorization code; under a dedicated 256-bit custody key separated from the signing key, rotated by hard cut (the drill joins C3's T3; the wrapped-DEK preference recorded as C3 input); the plaintext never logged and never delivered to any client (the ciphertext is, by design, in the refresh token); the transit from flow end to code grant is the minutes-bounded pending entry keyed by the code's id; a configured provider-token size bound refused loudly at sign-in; the form-body cap raised and re-priced; the grown token's round trip through both field harnesses' stores gated before adoption (task 3.3); no `offline_access` ever requested — the capability acquired is session-bound by construction | **Placed** — delta spec (the envelope, carrier, key, bound, and refusal); the cap value and the key slot are repo settings; the harness round-trip gate is repo (task 3.3's evidence) | DT-EP4-1, DT-EP1-7 (bounding), DT-EP1-8, DT-EP1-9, DT-EP5-2 (the artifact bound) |
| G6 | The carried bounds — public-endpoint abuse limits, fixed-vocabulary refusal records with truncated facts, outbound timeouts, bounded response parsing | **Placed** — spec/repo as today (unchanged placements) | DT-EP1-3, DT-EP1-5, DT-EP1-6 (timeout), DT-EP5-1 (parse) |
| G7 | The re-derived startup lattice — `refreshTtl` ≤ the operator-declared IdP session bound (`IDP_SSO_SESSION_MAX_SECONDS`), an assertion about session policy with the un-catchable failure named, backed by the provisioning script's live realm check | **Placed** — delta spec (the startup refusal row); the live realm check is repo | DT-EP4-1 (the window bound), DT-EP1-7 (the cadence bound) |
| G8 | Internal-leg transport security (TLS where the deployment demands it) — the named control for the refresh-grant leg's integrity and the decrypted provider credential's confidentiality in transit | **Named** — deployment, owner: the deployment owner; unplaced today — the existing internal-leg residual's acceptance, extended to the refresh-grant call | DT-EP5-1, DT-EP5-2 |

Accepted remainders: DT-EP1-2's inventory disclosure (inherent to dynamic serving,
bounded by the restriction option and the mirror property — the widened set names
nothing Core's own unauthenticated tier does not name); DT-EP1-6's availability trade
(the priced cost
of freshness, landed in the model's register as RES-20 — §7); DT-EP1-7's session
keepalive (bounded by SSO Session Max and the non-sliding window; accepted as
priced by the owner's ruling, 2026-11-01 — §8 OQ-G);
DT-EP1-9's harness stores beyond the two gated ones (bounded by the size bound's
loud sign-in refusal); DT-EP4-1's re-shaped custody residual (the D5 trade, landed
as RES-21 in its four-part encrypted-chain shape — §7); DT-EP5-1's forged-claims
remainder inside the internal-leg boundary (RES-19's class, extended); DT-EP5-3's
moved check (the internal-leg trust, one consequence extended — the existence edge
included, the merged consult threat's denial shape);
DT-EP1-12's global-credential delegation (accepted as design — Core's own
credential semantics, stated in D12's use-vs-establish wording).

### 7. The threat-model delta

`docs/threat-model.md` entries this change adds or changes (landed by this change's
tasks, not a follow-up):

- **T1-16** — disposition rewritten: mitigated to the access-TTL bound (the
  claims re-read with rotation + denylist); the staleness window within
  `refreshTtl` is no longer the bound; the residual is the interval between
  refreshes plus each minted token's own life.
- **RES-6** — record rewritten: the bound shrinks from the refresh window to the
  access TTL; the compensating controls are the re-read and the fail-closed
  semantics; the re-open trigger becomes the revocation-SLA decision at its new
  baseline.
- **Invariant 4's row** — the bound restated (claims as fresh as the last
  refresh; in-flight tokens bounded by the access TTL).
- **T4-2 / RES-2** — re-priced to the encrypted-chain custody: the process's
  persistent secrets are the signing key **and the dedicated custody key** (a
  second secret in the same custody class, never logged, `repr`-clean, hard-cut
  rotatable); the transient plaintext of the presenting sessions' provider
  refresh tokens exists only for the duration of each refresh grant — there is
  no per-session store to sweep; the identity access token's retention stays
  the flow TTL, its pre-change shape; the never-store rule's wording gains the
  encrypted custody claim as a named, bounded exception (the plaintext never
  leaves the process; the ciphertext is delivered by design, unusable without
  the key).
- **T5-1 / RES-3** — the token-use rule re-derived: the identity access token's
  purposes are unchanged (the flow's decision step and credential call); the
  provider session refresh token adds purposes of its own — its **plaintext**
  presented exactly once per gateway refresh at the provider's token endpoint
  while carried, and its **ciphertext** delivered exactly once per rotation
  inside the refresh token to the client presenting it — with the artifact's
  own bound (dies with the provider session) named.
- **RES-19 / T5-2** — the internal-leg acceptance extended to the refresh-grant
  call (the forgery gain stated as any-claims-for-an-existing-`sub`, narrower
  than the exchange chain's mint-any-sub; the sniffing gain now includes the
  decrypted provider session refresh token the grant presents on the leg — the
  most powerful credential the flow ever puts on the wire); the
  compromised-row note updated.
- **T1-15** — the enumerable set's widening recorded (dynamic mode), disposition
  unchanged (as-that-user resolution; public-by-design inventory), with the bound
  the mirror property states: the widened set is every guard-passing name, the
  same registry-independent shape Core's own unauthenticated discovery tier
  serves — no existence oracle exists below authentication on either side of
  the front door, and the set names nothing Core's own tier does not name.
- **RES-10** — re-shaped a second time (ruling 1): the non-OAUTH exclusion as a
  class is gone — the startup OAuth-declaration refusal is deleted with the
  mapping's `authentication_type` member, and a non-OAuth toolset is *served*
  through the signed-in short-circuit when Core holds a credential (user or
  global). The residual that remains is the impossible-branch refusal loop: a
  non-OAuth toolset with no stored credential refuses every flow with a
  plain-language page naming the cause; the loop is benign (rate-limited, one
  identity-leg exchange per cycle, no retry changes the outcome) and ends
  out-of-band when an administrator stores the credential, after which the same
  flow short-circuits — the record's (a)/(b)/(c) restated in those terms
  (DT-EP5-3's moved-check analysis carries the internal-leg forgery variant).
- **RES-15** — restart loss semantics **narrowed to a gain**: refresh
  capability now *survives* restarts and rollouts — the encrypted custody claim
  returns with the presented refresh token, so a restart (and every C3 pod
  rollout) costs no re-sign-in wave; what is still lost is the minutes-bounded
  pending hand-off entries (an unredeemed pre-restart code fails its grant,
  fail closed), the replay cache (PKCE-covered), and the denylist (bounded by
  `refreshTtl`), all as recorded; one regression is recorded alongside the
  gain (RES-21's part iii): a *stolen* refresh token survives restarts under
  v3, where the store design's restart killed stolen tokens' refresh
  capability with everyone else's — bounded by the non-sliding absolute expiry
  and the IdP session clock, with explicit revocation still propagating at the
  next refresh.
- **T6-2** — control 4 amended: the startup reserved-name check now covers
  configured restriction entries; for dynamic names the request-time guard
  refuses the collision before the router ever serves it (the check moved with
  the served set, it was not lost).
- **RES-16** — the bounding control's startup half re-scoped to match: "Startup
  reserved-name enforcement" covers *configured* restriction entries; for dynamic
  names the request-time guard does the reserved-name work (the same split as
  T6-2's control 4 — the record no longer names the startup half as if it still
  covered the whole surface).
- **T1-7** — cost row amended: each refresh now spends one outbound
  identity-provider call (the refresh grant) and one constant-time AES-GCM
  decryption of the custody claim — the call the flood did not cost before,
  the decryption a microsecond-scale addition priced for completeness
  (negligible beside the RSA verification the endpoint already performs) —
  and the public-endpoint abuse limits bound both one-to-one with the request
  rate (DT-EP1-5's shape).
- **RES-4** — the slow-leg membership widened: the refresh grant joins the
  attacker-steered slow legs (one outbound identity-provider call per refresh,
  each holding a worker-thread slot for up to the outbound timeout — DT-EP1-5's
  shape, whose residual the design itself lands on RES-4), so the record's
  bounding text — "the CIMD capacity limiter bounds **the one attacker-steered
  slow leg's** pool share" — no longer names the whole set; the text is amended
  to carry both legs, with the public-endpoint abuse limits named as the refresh
  flood's arrival bound (one outbound call per admitted request).
- **RES-20 (register entry)** — the availability-for-fidelity trade of the
  mandatory claims read, landed as a disclosed residual (DT-EP1-6's accepted
  remainder): (a) accepting condition — the claims read is mandatory and
  fail-closed, so an identity-provider outage refuses every refresh, and the
  recovery (re-sign-in) needs the same provider; (b) bounding — already-minted
  access tokens keep working to their own expiry, the provider's own timeout
  bounds each call, and the burst of `claims_read_failed` audit records is the
  detective signal; (c) re-open trigger — a future owner ruling for a bounded
  stale-claim fallback (OQ-A ruled fail-closed, 2026-11-01 — §8) or an
  availability requirement that cannot accept
  re-sign-in during provider downtime.
- **RES-21 (new register entry — the re-shaped residual of the D5 amendment,
  four parts, replacing the store-design's memory-custody record)**:
  (a) accepting condition — the provider's session refresh token is carried
  as encrypted mintable material inside the gateway's refresh token, in four
  priced parts: **(i) encrypted mintable material at rest in harness token
  stores** — every issued refresh token carries the ciphertext; it is inert
  without the custody key, and it adds nothing to an attacker who controls the
  machine it sits on (that attacker already holds the refresh token itself,
  which mints the same user identity through the front door); **(ii) the
  time-decoupled conjunction** — a recorded token plus a later custody-key
  leak lets the attacker decrypt the archive and replay each archived user's
  IdP identity for as long as the provider's session policy allows, with the
  two halves collectible in different incidents; **(iii) the recorded
  regression** — a stolen refresh token survives restarts under v3 (the store
  design's restart killed stolen tokens' refresh capability with everyone
  else's); **(iv) the process-compromise floor, unchanged in kind and reduced
  in blast** — a process compromise yields the custody key plus the plaintext
  of only the sessions presenting during the window, never a whole-store
  harvest; the mint-any-identity radius remains the signing key's own;
  (b) bounding controls — the grant is session-bound with `offline_access`
  never requested (no 30/90-day offline capability; the provider's session
  policy is the clock — the explicit SSO Session Idle/Max pair on Keycloak),
  the provider's rotation reuse detection **where enabled** is the containment
  control for the credential-on-the-wire exposure of plain-internal-leg
  deployments (the gateway's own next refresh races the thief and the first
  replay revokes the chain for both — D3's custody strength; the provisioning
  sets it on the local realm, and it is not Keycloak's image default), while
  deployments with **TLS'd internal legs — the production shape — are bounded
  by the transport itself**, the detection there defense-in-depth rather than
  the bound; IdP-side session revocation kills the
  credential at its next use, the ciphertext is never logged and the
  plaintext never leaves the process or reaches any client, the carried
  window is bounded by the refresh token's non-sliding absolute expiry and
  the startup lattice's operator-declared session bound, the custody key is
  hard-cut rotatable (a superseded key decrypts nothing), and the size bound
  plus the two-harness round-trip gate bound the carrier's own failure mode;
  it grants no upstream (toolset) credential and no other user's identity —
  the bound is per-user and session-bound, not scope: the minted provider
  token carries the user's full DIAL role set (Core authorizes on the role
  claims embedded in the token, which the realm's mappers place there
  regardless of OAuth scope — the client's `profile,email` scopes bound
  nothing DIAL-relevant); (c) re-open trigger — an owner ruling for a custody
  shape that holds no provider refresh material at all (the candidate-F
  front-channel alternative the independent evaluation names), a provider
  whose session-bound refresh tokens outlive any operator-acceptable session
  policy, a harness token store with a hard size limit the bound cannot dodge
  (the task 3.3 gate exists to find this before adoption), or the C3 KMS
  landing choosing a per-refresh-call shape that re-couples availability (the
  wrapped-DEK preference is the guard).
- **New §8/§13 rows — the change's own new threats land in the model's threat
  tables and dispositions, not only in this change's SIA tables** (the next
  change's SIA starts from the model's mapped mitigations, so the custody seam
  must exist there as a threat surface): **T1-17** (EP1, E4 refresh — refresh
  cadence keeps the IdP session alive, marked [mis-use]; the DT-EP1-7 shape),
  disposition **accepted — RES-22**; **T1-18** (EP1, E4 refresh — crafted
  custody blob; the DT-EP1-8 shape), disposition **mitigated (M21 — the AEAD
  tag, the pinned constants and fixed keyset, the seam's `sub`/`exp` checks,
  the `custody_decrypt_failed` detective class)**; **T1-19** (EP1, the issued
  refresh token at rest in the harness's token store — grown refresh token
  overflows a harness token store; the DT-EP1-9 shape), disposition
  **mitigated to its bound (the size bound, the re-priced cap, the two-harness
  round-trip gate); the ungated harness stores accepted — RES-23**; and
  **T4-8** (EP4, process memory — custody-key compromise and transient
  plaintext; the DT-EP4-1 shape), disposition **mitigated to its bound (M21's
  envelope and key discipline, the session-bound grant, the hard-cut key); the
  time-decoupled conjunction and the process-compromise floor accepted —
  RES-21 (parts ii and iv); the managed-runtime memory floor — RES-2**.
- **RES-22 (new register entry)** — the SSO-session keepalive, DT-EP1-7's
  accepted-with-reasoning landed where the method's vocabulary mapping puts a
  disclosure — the register, not a risk paragraph in the change folder:
  (a) accepting condition — the gateway's refresh cadence refreshes the IdP
  session's idle timer, so a harness refreshing on its own schedule keeps the
  user's SSO session alive after all browser activity has ended, up to the
  provider's SSO Session Max — the user's "walking away" no longer ends their
  identity session on the idle timescale; (b) bounding controls — the
  provider's SSO Session Max (an absolute, non-sliding cap), the gateway's own
  non-sliding refresh window, the startup lattice's operator-declared session
  bound (D6), and explicit revocation propagating at the next refresh;
  (c) re-open trigger — a future owner ruling for a tighter bound (OQ-G ruled
  accepted-as-priced, 2026-11-01 — §8).
- **RES-23 (new register entry)** — the ungated harness token stores,
  DT-EP1-9's accepted remainder landed the same way: (a) accepting condition —
  every harness token store beyond the two field-proven ones is unverified,
  and a store with a hard item-size limit below the grown refresh token breaks
  the session silently, far from its cause — the user's availability, not the
  gateway's; (b) bounding controls — the provider-token size bound refused
  loudly at sign-in, the raised and re-priced body cap, and the live
  two-harness round-trip gate before adoption (task 3.3); (c) re-open trigger —
  a named harness store with a hard limit the configured bound cannot dodge
  (the task 3.3 gate finding, the one result that legitimately forces the
  custody shape back to the owner), or an owner ruling for a smaller default
  carrier.
- **Three descriptive locations gain the custody key** — the same amendment
  class as §1's anchor paragraph, whose enumerations the custody era falsifies:
  §5's **TB4** (its memory list gains the custody key, the transient
  provider-refresh-token plaintext, and the minutes-bounded pending hand-off
  entries), §2's **sensitive-asset sentence** (gains the dedicated custody
  key), and §7's **EP4 entry-point description** (gains the custody key and
  the custody seam — the signing key and the dedicated custody key: the host
  files, the gateway's process memory, the mint path at E4, the custody
  decrypt/re-encrypt seam at every refresh, and the public JWKS at E8).
- **M13** — the provisioning-convergence row amended per D5: still never
  `offline_access`; the session-bound refresh token the exchange issues is
  carried — encrypted under the gateway's dedicated custody key, inside the
  gateway's own refresh token — for the refresh window instead of discarded;
  the plaintext never leaves the gateway process — the amendment deliberate,
  the trade priced as RES-21 (the pre-amendment "no provider refresh token
  ever minted for the flow" wording is replaced, not silently dropped).
- **M9** — the token-design row amended: the refresh token carries no claim
  snapshot — its one non-binding payload member is the encrypted custody
  claim; the refresh mint's claim input is the verified fresh read, and the
  fail-closed semantics are normative.
- **M10** — the startup-bounds row amended twice over: the OAUTH-only mapping
  refusal is **removed** (ruling 1 deleted it with the mapping's kind
  declaration — the row's "OAUTH-only mapping with no escape" wording is
  replaced, not re-scoped); the restriction-entry refusals that remain are the
  reserved-name and charset checks; the request-time guard and the flow's kind
  branch are named as the moved halves; the refresh-window bound is re-derived
  onto the operator-declared session bound (unchanged from the P2 re-taking).
- **New row (M21)** — the grouped mitigation (G3/G4/G5: the refresh-grant re-read, the
  snapshot-free fail-closed refresh, the custody envelope with its carrier
  discipline, pinned crypto, keyset, size bound, and raised cap) with its spec
  placement.
- **Revocation summary (new table in the model)** — the revocation summary
  carried in `background/design.md` §6.3 enters the living model, because this
  change re-prices one of its rows: "the user's DIAL identity at the source"
  changes from "Keycloak session revocation affects future flows, not live
  proxy tokens — latency n/a" to "**Keycloak session revocation propagates to
  the gateway's refresh capability at the next refresh attempt** (the retained
  session refresh token dies with the session; the refusal is audited
  `idp_session_ended`); minted access tokens live at most the access TTL" — and
  the table's other rows are carried unchanged.
- **Compromise table** — two rows re-priced. The gateway-process row: the
  **custody key** (with a recorded-token archive, replay each archived user's
  provider identity until that user's provider session dies — the
  time-decoupled conjunction; alone, the key decrypts but mints nothing) plus
  the transient plaintext of only the sessions presenting during the
  compromise window and the minutes-bounded pending hand-off entries — there
  is no per-session store to sweep; the signing
  key's mint-any-identity radius and the in-flight identity access token's
  flow-TTL shape are unchanged. The internal-compose-network row: the
  sniffing gain gains the **decrypted provider session refresh token**,
  presented once per gateway refresh on the refresh-grant leg — the most
  powerful credential the flow ever puts on the wire (DT-EP5-2's price), for
  as long as the provider's session policy allows.
- **§1 "The system as it stands"** — the model's anchor paragraph updated to the
  system this change leaves: the refresh-token sentence drops the role-snapshot
  semantics (the snapshot is deleted — D4; claims are re-read fresh at every
  refresh) and gains the custody claim (the provider's session refresh token,
  carried encrypted under the dedicated custody key — the token is larger, and
  refresh capability now survives restarts), the startup-check sentence is
  renamed and re-meaninged onto `IDP_SSO_SESSION_MAX_SECONDS` (an operator
  assertion about the provider's session policy, D6 — replacing the superseded
  24 h `accessTokenLifespan` check), and the state inventory gains the
  minutes-bounded pending custody entries (in memory, lost on restart —
  RES-15's narrowed semantics) and names the process's persistent secrets as
  the signing key and the custody key (no long-lived per-session store
  exists).
- **§4's asset inventory** — two new asset rows: the **dedicated custody key**
  (high/high/low — process memory for the process lifetime, the `.env` slot
  at rest, KMS at C3; the signing key's custody class) and the **encrypted
  custody claim at rest in harness token stores** (the ciphertext of the
  user's provider session refresh token, riding every issued refresh token —
  inert without the key, dying with the provider session); A4's footprint
  line gains the carried custody claim; A2's own footprint line is unchanged
  (the identity token's retention stays the flow TTL). The at-a-glance count
  becomes 17 assets.
- **OQ-1 resolved** — moves from the open to the resolved record with its source
  and date: the code already enforces the presented token's audience/resource
  binding at E9 (`gateway/status.py:111-122` — the audience must contain the
  toolset's resource, else `invalid_target`); recorded in the same edit that
  widens T1-15.
- **The model-at-a-glance counts** updated accordingly, recomputed from the actual
  delta (the register gains RES-20 through RES-23 — 23 residual records; the threat
  tables gain seven rows — 62 threats: the four custody-era rows T1-17/T1-18/T1-19
  and T4-8, plus the three flow-era rows T1-21 and T1-22 (EP1 — 21) and T5-7
  (EP5 — 7), EP4 gaining T4-8 alone — 8; the asset inventory gains the
  custody-key and at-rest-ciphertext rows — 17
  assets; the grouped mitigation list gains M21 and M23 — 22 grouped
  mitigations; the revocation-summary table is new).
- **New §8/§13 rows, flow era** (the re-taken flow's own threats, landing beside
  the custody-era rows above; the consult era's T1-20/T5-8/T4-9 are deleted with
  the consult — no model row is landed for a deleted design):
  **T1-21** (EP1, the flow's short-circuit — the mint-without-consent surface
  widens to non-OAUTH kinds; the DT-EP1-11 shape), disposition **mitigated
  (the stage order, the per-user DIAL authorization check on every path, the
  use-vs-establish rule, no credential read or transit; the forged-answer
  variant bounded by the internal-leg trust — T5-7)**; **T1-22** (EP1,
  [mis-use] — a global credential silently widens the served surface; the
  DT-EP1-12 shape), disposition **accepted as design (Core's own credential
  semantics, the delegation stated as use-vs-establish, the same access
  through Core's own paths)**; and **T5-7** (EP5, the per-user settings/status
  read — a forged signed-in answer mints without an upstream leg; the
  DT-EP5-4 shape), disposition **mitigated to the internal-leg bound (the
  RES-19 acceptance class, extended to one more member of the same Core
  answer; the mint's `sub` is the identity leg's, and no stored credential
  means the data path 401s)**. The deleted consult's forgery surface is not
  left homeless: the settings read now carries the existence decision too, and
  DT-EP5-3's row absorbs the forged-not-found denial shape (the merged
  DT-EP5-5).
- **T5-3's model row** — the existing forged-settings threat's description gains
  the existence edge the merged DT-EP5-5 brings: the per-user settings read is
  now the system's only existence decision (discovery answers phantom names a
  document by the mirror property), so a forged not-found on that leg — a
  denial of one servable toolset's flow, the same shape and leg as the forged
  kind — is named in the row's description rather than left to inference; the
  boundary, the bounding analysis, and the disposition are unchanged (the
  internal-leg trust, RES-19's class).
- **Invariant 3's model row (§11)** — the wording amendment the GLOBAL delegation
  needs, re-derived against the row's actual text: the row today carries no level
  wording at all ("Credentials are stamped and resolved per `sub` unchanged; the E7
  chain's guessing variant is killed …; the bound is the interception variant under
  the plain-http front door — disclosed, not mitigated today (RES-1)"), so the
  amendment **adds** the GLOBAL-use sentence rather than re-wording a level
  sentence that is not there — the flow never *establishes* a credential at GLOBAL
  level (the credential call stays USER-level on every establishing path); it
  *uses* one an operator stored, through the signed-in short-circuit, and the
  access is the same the same user already holds through Core's own paths
  (DT-EP1-12's delegation, stated rather than slipped in).
- **The GLOBAL use-vs-establish wording's four model homes** (round 4's R4-M1 —
  the falsified text the list previously missed: the pre-ruling statement "the
  flow signs in at USER level only; GLOBAL/app-level sign-in stays an operator
  action" now describes a system in which the flow *uses* a GLOBAL credential on
  every short-circuited mint): **RES-9** (§3 — the record is re-shaped: what stays
  an operator action is GLOBAL-level *establishment*, which the flow never
  performs; GLOBAL-level *use* through the short-circuit is Core's own credential
  semantics, stated as the delegation and priced as DT-EP1-12; the (a)/(b)/(c)
  parts restated in those terms); **T5-4's §8 row** (the escalation-attempt
  description is amended: what the flow refuses by design is *establishing* a
  GLOBAL credential — it signs in at USER level on every establishing path —
  while a GLOBAL credential's *use* is the operator-configured delegation, not an
  escalation); **T5-4's §9 control 4** (the same amendment — the control is the
  establishment-side refusal plus the use-vs-establish distinction, and the
  disposition line is re-derived from "preserved by absence" to preserved by the
  establishment-side refusal with the delegation stated); and **T5-4's §13
  disposition** (restated to match the re-shaped RES-9 — no longer "preserved by
  absence" of any GLOBAL path, since the short-circuit's GLOBAL use is now a
  designed, stated behavior).
- **T1-4's two carried OQ-1 statements** (round 4's R4-M2) — the §8 row's "whether
  E9 enforces the token's resource binding is an open question (OQ-1)" and the
  §13 disposition's "E9's resource binding stays open (OQ-1)" are amended in the
  same edit that resolves OQ-1 in §14: E9's resource binding is enforced
  (`gateway/status.py:111-122` — the presented token's audience must contain the
  toolset's resource, else `invalid_target`), so the open-question clause and the
  "stays open" wording are replaced with the resolved statement — the model
  cannot carry OQ-1 as resolved while T1-4 remains blocked on it.
- **T6-7's §8 row and §9 controls 6 and 7** (round 4's R4-M2) — the charset's
  enforcement point is split, the same amendment T6-2's control 4 and RES-16
  already carry: the row's and control 6's "enforced at startup on every mapping
  entry closes it" becomes startup enforcement for *configured restriction
  entries* plus the request-time guard for dynamic names (a name outside the
  charset never reaches the router's locations on any surface, so no
  metacharacter survives to any regex in either mode), and control 7's
  "checked once at startup … no runtime volume to attack" N/A reasoning is
  re-derived for the guard's request-time volume (bounded, fixed-vocabulary
  refusals, audited per the standing discipline).
- **§6 attacker 2's mis-use enumeration** (round 4's R4-M2, the weaker instance)
  — "walking statuses across the mapping (T1-15)" is amended to the dynamic-mode
  enumerable set: walking statuses across the platform bucket (the guard-passing
  name set the mirror property serves), the mapping being an optional restriction
  now —
  T1-15's own widened-set amendment carried into the attacker-class text that
  names it.
- **The descriptive locations, flow era** — §7's **EP1 description**
  gains the flow's short-circuit and the guard-decided dynamic discovery tier
  (registry-independent by the mirror property — no Core call), while its
  **EP5 description** names the flow's kind-and-signed-in decisions on the
  per-user read (the deleted consult leaves no discovery leg to describe);
  **§1's anchor paragraph**
  gains the P3 sentences the re-taking falsifies: the served set follows the
  request-time guard and the optional restriction (discovery mirrors Core's
  registry-independent unauthenticated tier; existence is decided
  post-authentication at the flow's settings read), the flow's kind check is
  the upstream stage's branch (a stored credential at either level
  short-circuits; a missing credential plus a non-OAuth kind refuses on the
  impossible branch), and the state inventory names the process's persistent
  secrets as the signing key and the custody key (the consult era's third
  secret is deleted before it ever lands in the model). The custody-key
  extensions to §5's TB4, §2's sensitive-asset sentence, and §7's EP4
  description are the custody-era entries above, unchanged by this re-taking.
- **New row (M23)** — beside the custody-era M21: **M23** the flow's
  routing decision (the signed-in short-circuit at user or global level, the
  kind branch, the impossible-branch refusal, the use-vs-establish rule —
  G2), spec-placed. (The consult era's M22 is deleted with the consult — no
  grouped mitigation is landed for a deleted design.)
- **T1-4's §9 control 5** (the token-type-separation pin, the owner's ruling
  after the four review rounds) — the control's "the `aud = [resource, marker]`
  the gateway mints (spec)" wording is amended to name the access token's mint
  as the one it describes: the access token's `aud` is `[resource, marker]`,
  while the refresh token's `aud` is the resource alone, the marker never
  included — the pin (delta spec's issued-tokens requirement, D4's sentence)
  that keeps the refresh token from ever being a token Core's
  identity-provider entry accepts — so the control's "bind every accepted
  token to gateway issuance" statement stays exact against both mints. No
  other model location's text changes: the marker's other homes (RES-7's
  bounding, T4-1's control 3, T4-4's control 5) speak of the marker binding
  accepted tokens, and the refresh token is not a Core-accepted token.

### 8. Open questions, owner rulings, and the strict gap list

**Owner rulings recorded (2026-11-01, at the pre-implementation pause):** the
owner ruled on the parked ruling slots; each ruling is recorded below where its
question stood, with its date. The discharged entries and non-questions keep
their records for the trail.

- **OQ-A — RULED: fail-closed stands (2026-11-01).** A refresh that cannot be
  verified fresh — the provider unreachable, the custody claim unusable, the
  session gone — is refused; there is no stale-snapshot fallback, and under D4
  there structurally cannot be one: the gateway's refresh token carries no
  claim snapshot, so the fallback has no data to serve. The *marked* fallback
  alternative (mint from the last successful read with an explicit stale-claim
  marker the harness could observe) was weighed and refused — it would require
  re-adding retained claim state and trades silent staleness for availability.
  Recorded as a ruling, no longer an open question; RES-20's re-open trigger is
  a future owner ruling, not this one.
- **OQ-B — Retention persistence: discharged by the v3 re-taking, and
  re-framed onto the question that survives it.** The in-memory-vs-persist
  dilemma dissolves: there is no store to persist — refresh capability
  already survives restarts, because the encrypted custody claim returns with
  the presented refresh token. The question that replaces it is the **custody
  key's** long-term home: its KMS landing (with the wrapped-DEK-over-per-
  -refresh-call preference) is C3's own scope, recorded there as input
  (D3/A3); nothing remains for this change's owner pause to rule on custody
  persistence.
- **OQ-C — discharged by the ruling-1 re-taking.** The question dissolves: a
  non-OAuth toolset is now a *served* toolset when Core holds a credential for
  it (the short-circuit), so E9 answering its statuses is correct behavior, not
  a symmetry question — the endpoint serves every served toolset's statuses,
  and the delta spec's status requirement gains the global-credential scenario
  alongside the user-level ones.
- **OQ-D — The refresh grant's client authentication** rides the existing
  `.env` mechanism (the confidential-client setting the exchange already uses,
  where a deployment has one); its move under the deployment's secret management
  is recorded as a requirement for that later scope (with the signing key and
  the other client secrets).
- **OQ-E — E9's per-toolset binding** (the baseline's OQ-1) is not open: the code
  already enforces it — `gateway/status.py:111-122` requires the presented
  token's audience to contain the named toolset's resource and answers
  `invalid_target` otherwise. Task 4.1 resolves OQ-1 in the model's resolved
  record with that source, in the same edit that widens T1-15; no owner ruling
  is needed.
- **OQ-F — discharged by the re-taking.** The userinfo claim-source reachability
  decision (Entra's fixed userinfo; B2C's custom-policy-only userinfo) gated the
  overruled mechanism; the refresh-grant mechanism reads the same carrier the
  sign-in already reads, so no claim-source question remains for this change.
  The provider facts stay on record as inputs to C2's B2C planning (its
  per-policy claim wiring is C2's own concern).
- **OQ-G — RULED: accepted as priced (2026-11-01).** The SSO-session keepalive
  effect (surfaced by this design, DT-EP1-7) stands as disclosed: the gateway's
  refresh cadence refreshes the IdP session's idle timer, so a harness's
  scheduled refreshes keep the user's SSO session alive after browser activity
  ends, up to the provider's SSO Session Max — bounded by SSO Max, the
  non-sliding gateway window, and immediate propagation of explicit revocation.
  RES-22's record (landed by task 4.1) is the disclosure the ruling accepts. No
  tighter bound is built (the refused variant: refusing refreshes once the IdP
  session's idle would have lapsed absent the gateway — a provider-specific
  introspection of session state this design deliberately does not build);
  RES-22's re-open trigger is a future owner ruling, not this one.
- **OQ-H — RULED: local-only (2026-11-01).** The gateway's revoke endpoint ends
  the gateway's own session only — its issued tokens, refused by the denylist
  entries until expiry — and nothing else. It does NOT end the user's
  identity-provider session (no RFC 7009 leg against the IdP is added — that
  would be a new outbound leg and a new scope of behavior for a capability the
  provider already owns directly), and it does NOT touch the upstream
  credentials stored in Core, which remain until their own lifecycle ends them.
  The symmetry variant (gateway-side logout propagating upward, the mirror
  image of the propagation this change buys downward) was weighed and refused.
  A verification pass accompanies the ruling: no design or spec text was found
  implying otherwise — the main spec's "Revocation denylists refresh-token ids
  until expiry", the delta spec's carried revoked-token scenario, and D3/A8's
  revocation wording all state gateway-local semantics — so the ruling records
  the boundary as owner-stated rather than correcting a contradiction.
- **The provider's rotation reuse detection — RULED (2026-11-01): set it locally,
  document it as guidance for real deployments.** The live acceptance run
  (task 2.5, check (c)) falsified the "reuse detection is the default" fact the
  RES-21 bounding text rested on: Keycloak's image default is
  `revokeRefreshToken=false`, so on the local realm a superseded provider refresh
  token was accepted again (the characterization with the setting on proved the
  mechanism, then was reverted). The ruling's layering: **locally, the
  provisioning script configures the realm it owns and sets
  `revokeRefreshToken=true`** — on a plain-http internal leg (this deployment's
  dev shape) rotation reuse detection IS the theft-containment control, the first
  replay kills the chain and the event is loud (`idp_session_ended`); **real
  environments run TLS'd internal legs for Keycloak (guaranteed by the owner)** —
  the sniffing exposure closes there, so the primary production bound is the
  transport itself, and the operator material only *recommends* enabling the
  IdP's rotation reuse detection as defense-in-depth, never requires it. RES-21's
  bounding list is re-worded to exactly this layering, and the same layering is
  carried into the operator reference (`docs/gateway-configuration.md`) and the
  provisioning script's comment rather than the design alone.

**The three carried defaults — all confirmed as owner rulings (2026-11-01):**

1. **Rotation-off is warned, not refused (D3's priced interaction).** With
   `GATEWAY_ROTATE_REFRESH_TOKENS=false` on a provider that rotates its refresh
   token per grant, the carried credential is effectively single-use — the
   session ends at the second refresh; the combination is priced in the design
   and carried into the operator documentation as a warning (task 2.4), not
   refused at startup — the gateway cannot know the provider's rotation policy
   at startup, and the setting is valid on providers that do not rotate per
   grant.
2. **The envelope's `version` and `key-id` are bound into the AEAD associated
   data (D3/A4).** AES-GCM's missing key commitment is structurally closed
   today by the single-active-keyset invariant (an unknown key-id refuses, and
   there is never a second live key for a swapped header to reach); the
   associated-data binding carries that closure into any multi-key future,
   which must re-judge the commitment bound before the keyset ever holds two
   active entries.
3. **The hard-cut custody-key rotation wave is the accepted operator cost
   (D3/A3).** Every live refresh session signs in once after a rotation (a
   superseded key decrypts nothing); the wave is bounded by the refresh
   token's non-sliding absolute expiry, which is what the operator schedules
   the rotation around.

**The section's state after the rulings (2026-11-01):** no owner-ruling slot
remains open. OQ-A, OQ-G, and OQ-H are resolved by today's rulings; the three
carried defaults are confirmed by today's rulings; OQ-B, OQ-C, and OQ-F were
discharged by the re-takings (no store to persist; a non-OAuth toolset with a
stored credential is served; no claim-source question); OQ-D is a recorded
default, not a question (the refresh grant's client authentication rides the
existing `.env` mechanism, its move under the deployment's secret management
recorded as the later scope's requirement); OQ-E was never open (the code
already enforces E9's per-toolset binding; task 4.1 resolves OQ-1 in the
model's resolved record). The one item that stays parked is the **Core-side
ask** below — a suggestion to the Core team, explicitly not a dependency of
this system and not an owner-ruling slot — and the `gateway/tokens.py`
docstring correction is assigned, no longer flagged (task 5.7, this change's
diff).

**A Core-side ask, recorded — the OQ-4 pattern (a suggestion to the Core team,
explicitly not a dependency of this system, not built here):** a **registry-bound
protected-resource route** (the well-known document answered from the registry, so a
phantom name earns a 404) or an **unauthenticated existence route** (any
credential-less route that answers toolset existence) would let the gateway refuse
phantom names at the discovery door, **keyless** — no service credential, no
per-request authenticated registry read, no availability coupling; the gateway's
discovery tier would then carry an existence oracle Core itself endorses, and the
mirror property would tighten to "same challenge, same document, same existence
answer." The gateway flips to a door-refusal the day Core provides either surface —
the flip is a local, contained edit (the guard-passing serve becomes a
guard-plus-existence serve at one route) with its own SIA, priced against the facts
the Core surface actually offers. Until then, the mirror property is the honest
shape: it refuses nothing Core's own unauthenticated tier does not already refuse,
and the phantom's lesson arrives one leg later, at the authenticated settings read
where Core itself decides existence.

**The pushback record — two objections worked into this re-taking, named for the
pause (the owner's meta-norm is arguments, not decrees; both objections were
raised against the rulings as issued and are answered in the artifacts, not
buried):**

1. **The GLOBAL-level nuance on ruling 1.** A global credential short-circuits
   the consent for every ACL-permitted user — a real delegation the design now
   states as **use versus establish** (D12; the invariant table's row 3; the
   model's invariant-3 row amendment in §7): the flow never *establishes* at
   GLOBAL level (the credential call stays USER-level on every establishing
   path) and never reads or transits the stored credential; it *uses* one an
   operator configured, and the access is the same the same user already
   holds through Core's own paths (criterion-5 coexistence). The delegation is
   priced as its own mis-use row (DT-EP1-12, accepted as design with the
   bounds named) rather than left implicit. The status API's level semantics
   were verified, not assumed: Core answers `user_level_auth_status` and
   `global_auth_status` as **separate members** (`ResourceAuthSettingsData`,
   SIGNED_IN / SIGNED_OUT / FAILED), the flow treats SIGNED_IN at *either* as
   sufficient, and an unreadable or FAILED status fails closed into the kind
   branch (D12's failure shape) — so the API does answer the question the
   ruling needs it to, and the design states what happens on every shape it
   can return.
2. **The phantom traffic is new, on ruling 2 — and the final correction resolves
   the objection by deletion, not by caching.** The objection was raised against
   ruling 2 as issued and verified against the Core source: pre-gateway, Core's
   well-known route answered a phantom discovery fetch with a registry-independent
   static document (no registry read), so the consult's per-request *authenticated
   registry read* on attacker-chosen names would have been new traffic of a new
   kind. The consult era priced it as a first-class threat (its DT-EP1-10, with a
   mitigation grid and a RES-24 register entry) and rejected the cache as the
   mitigation with reasons. The owner's final correction — issued after empirical
   testing, binding — resolves the objection at its root: the same verification
   that established "the phantom traffic is new" also established that no
   unauthenticated Core route answers existence, so the consult could only stand
   on a standing service credential in Core, the one credential class the owner's
   principle bars (the gateway's only Core credentials are the user's own
   per-flow token). The consult, its service key, its threats, and its cache
   question are deleted; the enumerable-set widening that dynamic serving does
   bring stays priced (DT-EP1-2, T1-15's amendment) against the mirror property;
   and the door-refusal the consult wanted becomes the Core-side ask (§8), to be
   bought keyless from Core's own surface, not with a gateway-held secret.

**The round-5 reviewer's attack list** (what a fresh falsification pass should
check this re-taking against, with the ground truth to verify it on):

1. **The mirror property's Core facts** — verify D8's empirical claims against the
   Core source and live: the MCP path answers an unauthenticated call, phantom or
   real alike, with `401` plus `WWW-Authenticate` naming
   `…/oauth-protected-resource/v1/toolset/{name}/mcp`, and the auth check precedes
   any registry lookup (`Proxy.authorizeRequest`, the MCP challenge path); the
   well-known protected-resource route serves any well-formed name a
   registry-independent document built from static configuration with the
   requested path echoed as `resource`
   (`WellKnownResourceMetadataController`/`WellKnownResourceMetadataService`); the
   front router's challenge synthesis points a challenged harness at the
   gateway's PRM route (`router/nginx.conf`'s `WWW-Authenticate` map). If any is
   false, the mirror property — and the deletion it justifies — rests on sand.
2. **The deletion's completeness** — the recurring defect class (R2-M1, R3-M1,
   R4-M1), now with a deletion edge: every consult-era artifact must be gone from
   all five change files — the consult client and its route design, the
   `dial_core_api_key` slot and its operator rows, the
   `gateway_discovery_max_concurrent_consults` bound, DT-EP1-10/DT-EP5-5/DT-EP4-2
   and their grids, G9/G10, M22, RES-24, T1-20/T5-8/T4-9, the abuse-bounds
   consult amendment and its rate-limit scenario, the discovery 503 and
   403-omits-kind scenarios, OQ-I, the third-secret wording in the impact level
   and invariant rows 5/6, the service-key asset row, and the 65/24/18/23 counts.
   Grep the five artifacts for the consult vocabulary (consult, service key,
   `dial_core_api_key`, concurrency bound, 503, OQ-I, RES-24, phantom-refused)
   — every surviving hit outside the deletion's own record is a finding.
3. **The settings-read backstop's full weight** — the flow's unknown-toolset
   scenario is now the system's ONLY existence refusal: check the delta spec's
   wording carries that (a phantom name's discovery document, one browser
   round-trip, the identity-leg exchange, then the plain-language refusal — no
   upstream leg, no surviving flow state, one fixed-vocabulary audit record), and
   that the authorization requirement still names the settings read as the
   backstop rather than promising an endpoint-level refusal it cannot make
   (R4-M3's class, one round back).
4. **The stage order as an authorization argument** — unchanged from round 4 and
   still load-bearing: can any path mint a token without (a) the live identity
   leg, (b) the per-user DIAL authorization read, or (c) a positive SIGNED_IN
   answer or a completed consent leg? Check the forged-status path (DT-EP5-4),
   the short-circuit for a non-OAUTH kind with no credential, and now the merged
   existence edge (DT-EP5-3's forged-not-found denial) — the design claims all
   three yield no access or one denied flow; verify against the spec's scenarios.
5. **The use-vs-establish wording against the main spec** — the main spec's
   "GLOBAL-level establishment refused" scenario must survive verbatim in
   meaning: find any delta text that blurs "the flow uses a global credential"
   into "the flow establishes or grants one".
6. **Byte-identity of the retained rows** — every retained scenario byte-identical
   to the main spec except the declared amendments (this re-taking declares: the
   per-toolset fetch's omitted kind extension; the retained scenarios'
   mapped→served/restriction vocabulary re-wording the redesign forces — the
   per-toolset fetch's, the unmapped-toolset's, and the one-toolset-inference
   WHEN clauses, plus the status requirement's mapped→served subject, all
   required because a served name is no longer a mapped one; the
   dynamic-toolset scenario's mirror wording; the mapping requirement's dropped
   OAuth-declaration scenario
   and its replacement; the status requirement's boolean semantics and new global
   scenario; the guard requirement's trailing clause; the abuse-bounds' restored
   original opening with the custody-era declared amendments; the federation
   requirement's stage rewrite and weighted backstop scenario). Any undeclared
   diff is a finding.
7. **The custody half untouched** — this re-taking is the discovery half: D1–D6,
   the custody delta rows (DT-EP1-4–9, DT-EP4-1, DT-EP5-1/2), G3–G8, tasks
   2.x/3.1/3.3, and every custody-era §7 entry must be byte-identical to the
   round-3/4 landings — a regression there is this pass's most likely
   self-inflicted wound.
8. **The audit-vocabulary closure and the counts** — the deleted tokens
   (`core_unavailable`, the discovery-side `unknown_toolset` placement) leave no
   dangling references in spec, tasks, or release notes; the surviving tokens
   (`non_oauth_toolset`, `unknown_toolset` at the settings read and status
   endpoint, the guard's three) reach the record through the fixed-vocabulary
   discipline; and the at-a-glance counts (62 threats — EP1 21, EP4 8, EP5 7;
   23 residual records; 17 assets; 22 grouped mitigations) are counted from the
   actual §7 delta, not inherited from the consult era's arithmetic.

**Surfaced by the custody re-take — pre-pause fixes and flags for the owner
pause (not ruling slots):**

- **The `gateway/tokens.py` docstring correction (the repo-docs task 5.7,
  flagged, not landed).** The carrier decision's original justification
  (carried in `evidence/custody-opinion-v3.md` from this repo's own code
  rationale) stated Core "forwards the whole access-token payload to usage
  logs". Verified this pass against the DIAL Core source: false as a default —
  the analytics row's user identity is the salted SHA-256 of the
  `loggingKey` claim, and claim values reach logs only via the operator's
  opt-in `analytics.claimsAllowlist` (or the DEBUG-level login line). The
  carrier decision itself is unaffected (it stands on the refresh-grant facts
  and the data-path rule — D3), and the design's text now carries the
  verified wording. `gateway/tokens.py`'s module docstring (the copy-verbose
  rationale, line ~6) still carries the overstatement; it is pre-existing
  repo material outside this change's diff, so it is **not rewritten
  mid-change** — the correction (the logging half restated as opt-in; the
  authorization-paths half stands) has its task home (tasks.md, task 5.7) and
  is **assigned to this change's diff** (owner ruling, 2026-11-01, §8): the
  implementation pass lands it, not a separate repo-docs change, so the flag
  cannot fall silent and the correction cannot drift past this change.

**Strict gap list (per the method's conformance rule):**

- *Minor* — the provider-behavior facts D1/D5/D6 rest on (Keycloak: the ordinary
  refresh token is session-bound, dies with the SSO session, refresh use
  refreshes the session idle, SSO Session Max caps absolutely, rotation-on-use is
  the default, and rotation reuse detection is **not** the image default —
  `revokeRefreshToken=false`, verified live and set by the provisioning per the
  owner's ruling, below; Entra: public clients are issued refresh
  tokens, a ~24 h sliding bound applies without `offline_access`, and
  sign-out/admin revocation kills them) come from the vendors' documentation and
  the specifications — the same not-repo-verifiable input class the overruled
  D1 recorded. The driven checks (task 2.5) and the field run (task 3.1) verify
  the local realm's actual behavior rather than inferring it; the Entra facts
  remain vendor-documented behavior handed to C2.
- *Minor* — the local realm's SSO Session Idle/Max values are deployment facts
  not pinned in the repository; the provisioning check reads them from the live
  realm at run time (task 2.5) rather than asserting them here.
- *Minor* — whether a provider returns an ID token from the refresh grant is
  provider behavior (OIDC Core §12.2's response shape); the mechanism
  deliberately does not depend on it (D2's carrier choice), so no gap is open —
  recorded here so a reviewer does not re-open it as one.
- *Minor* — the harness token-store size facts the custody re-take rests on
  (the keychain/credential-manager item-size-limit class, the Windows
  Credential Manager's 2560-byte blob bound; Claude Code's and Cursor's
  actual store behavior) are not repo-verifiable — the same input class as the
  provider facts above; verified live for the two field harnesses by task
  3.3's gate before adoption, never assumed.
- *None (closed this pass)* — the Core logging behavior the carrier decision
  was first justified on ("Core forwards the whole payload to usage logs") was
  verified against the authoritative public source this pass
  (epam/ai-dial-core: `IdentityProvider.java`, `AnalyticsLogContext.java`, the
  README's analytics settings) and found **false as a default** — hashed key
  claim by default, opt-in allowlist for claim values; the design's carrier
  text now carries the verified wording, and the pre-existing
  `gateway/tokens.py` docstring that still overstates it is corrected by this
  change's implementation pass (assigned by the owner's ruling, 2026-11-01 —
  §8; tasks.md, task 5.7).
- *None (closed this pass, the final-correction Core facts)* — the facts the
  re-taken discovery and flow design rest on were verified against the same
  authoritative public source (the local `epam/ai-dial-core` checkout, the input
  class round 3 used for the logging verification), and the two discovery facts
  were additionally verified **live** in the owner's empirical test: Core's MCP
  path answers an unauthenticated call — phantom toolset or real — with `401`
  plus the `WWW-Authenticate` challenge naming
  `…/oauth-protected-resource/v1/toolset/{name}/mcp`, the auth check preceding
  any registry lookup (`Proxy.authorizeRequest` — no unauthenticated existence
  oracle); and `WellKnownResourceMetadataController`/`WellKnownResourceMetadataService`
  serves a registry-independent document for any well-formed name, the requested
  path echoed as `resource`. The flow facts are the round-4-verified set,
  unchanged: the per-caller
  statuses ride `user_level_auth_status`/`global_auth_status` as separate
  members (`ResourceAuthSettingsData`, vocabulary SIGNED_IN / SIGNED_OUT /
  FAILED, the enricher filling both for toolsets); and the kind rides
  `authentication_type` with values OAUTH / API_KEY / NONE / DIAL_NATIVE, DIAL_NATIVE
  answering user-level status from the caller's offline credentials
  (`ResourceAuthStatusEnricher`).
- *Minor* — whether a given deployment's Core build enriches the settings
  route with the per-caller statuses is a deployment fact the flow already
  handles by its one-or-two-read fallback (`read_toolset_for_flow`) — the
  re-taking changes only the predicate (user OR global), not the fallback, so
  no new gap opens; recorded so a reviewer does not re-open it as one.

## Risks / Trade-offs

- **The carried material is mintable — the change's central price, disclosed in
  its v3 shape.** The provider's session refresh token rides the gateway's own
  refresh token as encrypted material: a custody-key compromise paired with a
  recorded-token archive — two incidents, time-decoupled — or an internal-leg
  eavesdropper on a single refresh grant can mint that user's provider identity
  tokens until the provider's session policy ends the session. Bounded by: the
  session-bound, no-offline grant (never `offline_access`), IdP-side revocation
  killing the credential at its next use, TLS on the internal legs (the primary
  production bound — the owner guarantees TLS'd Keycloak legs) with the
  provider's rotation reuse detection — where enabled — as defense-in-depth and
  the containment control for plain-internal-leg deployments, the hard-cut
  custody key, the plaintext
  never leaving the process or reaching any client or log. RES-21 lands the
  four-part acceptance record; the compromise tables are re-priced (D5, §7).
- **The refresh token grows, and its harness store is not ours.** The custody
  claim puts the refresh token in the multi-KB class; a harness token store
  with a hard item-size limit breaks silently, far from its cause. Bounded by
  the provider-token size bound refused loudly at sign-in, the raised and
  re-priced body cap, and the live two-harness round-trip gate before adoption
  (D3/A5, task 3.3) — the accepted remainder is every store beyond the two
  field-proven ones (DT-EP1-9).
- **Stolen refresh tokens survive restarts under v3** — the recorded regression
  (RES-21's part iii): v2's restart killed stolen tokens' refresh capability
  with everyone else's, and that accidental sweep is gone. Bounded by the
  non-sliding absolute expiry and the IdP session clock; explicit revocation
  still propagates at the next refresh.
- **Refresh availability is coupled to identity-provider availability.** The
  fail-closed choice (D4) means a provider outage refuses refreshes; users
  re-sign-in when the provider returns. RES-20; the fail-closed choice is
  confirmed by the owner's ruling (2026-11-01, §8 OQ-A), and the alternative is
  the reintroduced staleness the change exists to remove.
- **The refresh window is now conditional on the IdP's session policy, honestly
  stated.** Where the provider's session policy (SSO Session Max; Entra's ~24 h
  public-client bound) is shorter than the configured window, sessions end at
  the policy's bound with a loud, auditable refusal (`idp_session_ended`) and
  the user re-signs-in — the correct configuration there is the shorter window,
  and the operator guidance says so (D6).
- **Provider rotation can end a session by a lost response.** Where the provider
  rotates its refresh token per grant, a refresh response lost in transit
  consumes the carried token — the session fails closed at the next refresh
  (D3); a grace-window presentation of a pre-rotation token reaches the same
  fail-closed class one step earlier (its own stale blob). Accepted:
  rotation-on-use is a custody strength, and the alternative (disabling it) is
  not the gateway's to choose.
- **The gateway keeps the IdP session alive on refresh cadence** (DT-EP1-7;
  accepted as priced by the owner's ruling, 2026-11-01 — §8 OQ-G, disclosed as
  RES-22): a harness's scheduled refreshes extend the user's SSO session beyond
  browser activity, bounded by SSO Session Max and the non-sliding window.
- **Live refresh sessions fail closed once at deployment.** The refresh token's
  shape changes (no claim snapshot) and pre-change tokens have no retention
  entry: each dies at its next refresh with a re-sign-in — the same loss class
  RES-15 discloses for restarts.
- **Discovery answers phantom names a document — the mirror property, priced.**
  The unauthenticated discovery tier serves every guard-passing name, phantom and
  real alike, exactly as Core's own unauthenticated protected-resource tier does
  (verified in the Core source and live); the harness's existence lesson arrives
  one leg later, at the flow's authenticated settings read — the system's only
  existence refusal — where the same probe against Core's own tier would have
  taught it. The phantom-name document costs the gateway one static document
  (zero Core calls, no service credential — the consult era's third secret,
  amplifier threat, and availability coupling are deleted with the consult), and
  the enumerable-set widening is DT-EP1-2's disclosed price, bounded by the
  restriction option. The door-refusal the consult era wanted is the Core-side
  ask (§8): bought keyless from Core's own surface when Core provides it, not
  with a gateway-held secret.
- **A global credential delegates consentless sign-in to every ACL-permitted
  user — stated, not slipped in.** The short-circuit uses an operator-stored
  GLOBAL credential (use, never establish; the credential call stays
  USER-level); the access is the same the same user already holds through
  Core's own paths, and the minted token carries only that user's claims
  (D12, DT-EP1-12, invariant 3's amended wording).
- **The non-OAuth refusal is now per flow, on the impossible branch only.**
  A non-OAuth toolset with a stored credential is served (the short-circuit);
  one without refuses each flow with a plain-language page naming the cause —
  a benign, rate-limited loop that ends out-of-band when an administrator
  stores the credential. The configuration-time refusal is gone with the
  mapping's kind declaration (D7); the internal-leg trust bounds the
  forged-answer variant (DT-EP5-3/4).
- **The enumerable inventory widens in dynamic mode** to every guard-passing
  name — the mirror property's shape, the same registry-independent set Core's
  own unauthenticated tier serves (no existence oracle below authentication,
  on either side of the front door) — still wider than the operator's pinned
  list; the restriction option pins it back exactly as today.
- **The refresh grant's per-request cost grows** (one outbound call, one
  verification, one more signing) — bounded by the existing abuse limits, which
  now bound outbound call rate one-to-one.
