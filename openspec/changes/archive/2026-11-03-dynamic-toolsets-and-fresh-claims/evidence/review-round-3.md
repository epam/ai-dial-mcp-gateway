# Independent review — round 3 (the v3 re-taking; the crypto seam)

Change: `dynamic-toolsets-and-fresh-claims` as re-taken to **v3** (encrypted custody
embedded in the gateway's own refresh token; the long-lived store deleted). Reviewer: a
fresh independent pass — round 1, round 2, the mechanism opinion, and the custody opinion
were read as history to verify against, not verdicts to inherit. Ground truth re-verified
this pass: `docs/security-analysis.md` (the method), `docs/threat-model.md` (whole — §1,
§3 register, §4 assets, §5 TB4, §7 entry points, §8 tables, §10 compromise table, §11
invariants, §12 mitigations, §13 dispositions, §14 OQs, the at-a-glance counts), the main
spec (`openspec/specs/mcp-signin/spec.md`, scenario-by-scenario against the delta), the
code (`gateway/token.py`, `gateway/tokens.py`, `gateway/idp.py`, `gateway/settings.py`,
`gateway/keys.py`, `gateway/state.py` presence, `gateway/federation.py`, `gateway/flow.py`,
`gateway/status.py:111-122`, `tests/test_tokens.py:447-457`), `.env.example`,
`docker-compose.yml`, `README.md`, `docs/gateway-configuration.md`,
`docs/production-roadmap.md` (C3 = P5+P1+T3, the deferred-HA table), and — for the
carrier-justification verification — **the DIAL Core source itself**
(`dial/dial-core/ai-dial-core`: `IdentityProvider.java`, `AnalyticsSettings.java`,
`AnalyticsLogContext.java`, the bundled `aidial.settings.json`). Read-only except this
file. `openspec validate dynamic-toolsets-and-fresh-claims --strict` run this pass: green.

**Overall verdict: LAND AFTER FINDINGS.** The v3 custody design survives falsification
on every axis that matters, including the crypto seam no prior pass covered: the envelope
is pinned end-to-end (nothing envelope-selected on either the encrypt or the decrypt
path), the carrier discipline is normative and correctly justified, the hard-cut rotation
is justified and its cost stated, the four-burst audit design is coherent, and the
corrected Core-logging wording is **accurate — verified against the Core source, not just
against the design's own record**. Round 2's findings (R2-M1/M2, m1–m6) are all verifiably
landed. What remains is the same defect class round 2 called out in R2-M1 — prices the
SIA states that do not reach the model locations supposed to carry them — plus one genuine
pin gap on the crypto seam (the key length) and a handful of minors. No design decision is
reopened by anything below.

---

## Findings

### BLOCKER

None.

### MAJOR

**R3-M1 — The threat-model delta (§7 / task 4.1) still does not land the change's own
new threats in the model: the session-keepalive mis-use has no model home at all, and
the custody-era threats land neither as §8 rows nor as register entries.**
`design.md` §7 (lines 994–1198), `tasks.md:324-419` (task 4.1's explicit edit list).

- **DT-EP1-7 (refresh cadence keeps the IdP session alive) is accepted with reasoning**
  (`design.md:779-781`: "accepted and disclosed — the session extension is bounded by
  SSO Session Max and the non-sliding window; an owner ruling for a tighter bound is
  OQ-G"). By the repo's own **normative** vocabulary mapping
  (`docs/security-analysis.md` §1: "a threat accepted with reasoning = a disclosed
  residual … **The disclosure's home is the threat model — not a risk paragraph
  alone**"), this is a disclosed residual and must land in §3's register. It lands
  nowhere: not as a register entry (RES-20 is the availability trade, RES-21 is the
  mintable-custody trade — neither carries the keepalive), not as a §8 threat row, not
  in any amended entry. The design's §7 accepted-remainders paragraph
  (`design.md:984-992`) is a risk paragraph in the change folder — exactly the shape
  the vocabulary mapping prohibits as a disclosure's home.
- **The custody-era delta threats land only in the change's SIA tables.** DT-EP1-8
  (crafted custody blob — mitigated), DT-EP1-9 (grown token overflows a harness store —
  remainder accepted), and DT-EP4-1 (custody-key compromise and transient plaintext)
  have no §8 rows, no §13 dispositions, and no register entries of their own. The
  method's order of work is explicit (`docs/security-analysis.md` §3 step 4: "Update the
  threat model. **New threats**, changed dispositions, and re-judged residuals land in
  `docs/threat-model.md`") and the model's own preamble agrees ("new threats … land in
  the affected entries directly", `threat-model.md:7-9`). T4-2/RES-2's re-price carries
  the custody key into the *existing* memory-dump threat, and the new grouped-mitigation
  row carries the controls — but the model's threat tables and dispositions never gain
  the crafted-blob, harness-store, or key-compromise rows themselves, so the next
  change's SIA (which starts from "the threat model's mapped mitigations — the
  per-surface record of what is already deployed against which threat",
  `security-analysis.md` §2) begins from a model that does not know the custody seam
  exists as a threat surface. DT-EP1-9's accepted remainder (every harness store beyond
  the two gated ones) is likewise disclosed only in the change folder; its only model
  trace is half a sentence inside RES-21's re-open trigger.
- **The at-a-glance counts are updated for three of the four things that change.**
  `threat-model.md:27-32` says "20 grouped mitigations (§12)"; the new grouped-mitigation
  row makes 21, and neither §7 (`design.md:1196-1198`) nor task 4.1's count refresh
  (`tasks.md:406-409`) names the mitigation count — the parenthetical enumerates only
  the register, the assets, and the revocation-summary table.
- **Three descriptive locations whose enumerations the custody key falsifies are outside
  the edit list:** §5 TB4 (`threat-model.md:300-303` — "Its memory (signing key,
  in-flight identity token, flow records, caches)" gains the custody key and the
  transient provider-refresh-token plaintext), §2's sensitive-asset sentence
  (`threat-model.md:86-88`), and §7's EP4 entry-point description
  (`threat-model.md:372-374` — "The signing key: the host file, the gateway's process
  memory…"). The §1 anchor paragraph is amended (task 4.1) — these three are the same
  class and were not.

Concrete failure: an implementer executing task 4.1 literally — whose verify clause says
"the entries and sections it names are exactly what changes" — leaves the keepalive
residual homeless and the model without custody threat rows; the security review gate
(5.4) then reads a threat model that does not carry the change's own disclosed prices,
and the first SIA written *after* this change inherits an incomplete standing inventory.
Remedy: add to §7 and task 4.1 — (a) a register entry (or explicit threat row +
disposition) for DT-EP1-7's keepalive, OQ-G cross-referenced; (b) new §8/§13 rows (or
stated register homes) for DT-EP1-8/DT-EP1-9/DT-EP4-1; (c) the grouped-mitigation count
in the at-a-glance refresh; (d) TB4, §2's asset sentence, and §7's EP4 description.

**R3-M2 — The custody key's length is not startup-enforced, so the "AES-256-GCM, pinned
in code constants" claim has a silent downgrade path: `AESGCM` accepts 128- and 192-bit
keys, and the algorithm then follows the key.**
`tasks.md:130-138` (task 2.2: the keyset's specified startup refusals are "an empty or
multi-active keyset" — no wrong-length refusal), `design.md:255-274` (A3), the delta
spec's custody requirement (`specs/mcp-signin/spec.md:269`). `cryptography`'s
`AESGCM(key)` constructs for any key of 16, 24, or 32 bytes: an operator who supplies a
16-byte key in `gateway_custody_keys` gets **AES-128-GCM** with no refusal, and the
envelope's "algorithm … code constants, never envelope-selected" pin is true of the
code and false of the running system — the M20 lesson (never let anything but the code
select the algorithm) is enforced against the *envelope* but not against the *key
material*, which is the other thing that selects the algorithm in an AEAD constructor.
The signing key's own discipline has the analogue check (`gateway/keys.py:63-68` refuses
a key under 2048 bits at load); the custody key's specified checks stop at presence and
keyset shape, and task 2.2's verify rows have no wrong-length-key row. Concrete failure:
a deployment pastes a 128-bit hex string; startup is green; every blob is
AES-128-GCM-encrypted for the key's lifetime, and nothing on the trail or in the audit
ever says so. Remedy: one startup refusal — the custody key must be exactly 32 bytes
(the 256-bit pin made checkable) — plus a verify row refusing a short key at startup.

### MINOR

**R3-m1 — The release notes count "three distinguishable audit bursts" and then name
four.** `release-notes-draft.md:130-145`: "with three distinguishable audit bursts …
so a custody fault, a provider outage, a session-policy break, and mass local revocation
read differently on the trail" — four classes (the fourth being the plain `invalid_grant`
burst the closed table already carries), as the design (`design.md:386-388`), task 2.3
(`tasks.md:207-209`), and the delta spec all correctly state. The same count-slip class
as round 2's m4. Remedy: "four".

**R3-m2 — The size bound and the body cap are coupled, and the coupling is unstated.**
`design.md:276-296` (A5), `tasks.md:159-162`. The arithmetic works at the defaults: a
4096-byte provider token becomes a ~5.7 KB base64url claim, a ~6.3 KB refresh token, a
~6.5 KB form body — comfortable under 16384. But both settings are operator-configurable,
and the refresh body must stay under `gateway_form_max_body_bytes` for *every* size the
bound admits: an operator who raises `gateway_custody_provider_token_max_bytes` past
roughly 10 KB without raising the cap gets sign-ins that succeed and **refreshes that
always fail over-cap** — precisely the "hours later, far from its cause" failure A5
exists to prevent, recreated by configuration. No task or spec sentence states the
invariant (cap ≥ bound + envelope expansion + JWT overhead) or cross-references the two
settings. Remedy: one sentence in the delta spec's custody requirement and in
`.env.example`'s/gateway-configuration.md's bound documentation (folds into m6).

**R3-m3 — The nonce and key-id disciplines are one statement short of complete pinning.**
`design.md:238-252` (A4), `specs/mcp-signin/spec.md:269`, `tasks.md:121-127`. (a) The
96-bit random nonce is pinned and per-encryption (the uniqueness verify row exists), but
the **NIST SP 800-38D random-IV bound** — no more than 2^32 encryptions under one key —
is nowhere stated. At this gateway's mint rate the bound is unreachable, and a hard-cut
rotation resets it, but the spec that pins everything else should say so: the number is
the difference between "random nonce" as an incantation and as a discipline (and it is
the one fact that tells a future implementer why re-keying matters without a compromise).
(b) `version` and `key-id` ride the envelope in the clear and are **not stated to be
bound into the AEAD's associated data**. Today this is structurally closed — the keyset
holds exactly one active entry (task 2.2: startup refuses multi-active) and an unknown
key-id fails closed, so there is no second key for a swapped header to reach, and
AES-GCM's missing key commitment cannot bite — but the design never says that the
single-active invariant *is* the key-commitment bound, and the envelope is explicitly
versioned for a future (dual-accept, KMS) where it would not be. Remedy: bind
`version | key-id` into the associated data (or state the single-active-keyset rationale
as the commitment bound and require it to be re-judged before any multi-key future), and
state the 2^32 bound.

**R3-m4 — The abuse-bounds requirement silently drops a retained sentence.** Main spec
line 258: "The mid-flow identity token is exposed at most min(flow TTL, its own expiry) —
the TTL bounds retention, not the token's life." The delta's replacement
(`specs/mcp-signin/spec.md:135`) says only "The identity access token's retention is
unchanged by this design: the flow TTL, as before" — losing the min(…, exp) bound and
the retention-vs-life distinction, and the drop is not among the declared amendments
(the proposal declares "the carried provider credential's purposes and bounds; the
raised, re-priced token-endpoint body cap"). The sentence's topic is adjacent to the
declared one, which is presumably why it was touched — but the migration discipline is
byte-identity with *declared* amendments, and this one is undeclared and lossy. Remedy:
restore the min(flow TTL, own expiry) wording (it is still true) or declare the
amendment.

**R3-m5 — Refresh-token rotation off is now a broken configuration, and the interaction
is unstated.** Delta spec line 201 keeps "Rotation MUST be default-on with a short grace
window" (a default, not a prohibition — the setting exists today,
`gateway/token.py:402`), while the custody requirement (line 269) re-encrypts the
provider's latest token only "into the newly rotated refresh token". On a
rotation-on-use provider (Keycloak's default — the design's own custody strength), a
grant consumes the carried provider token; with gateway rotation off, the client keeps
presenting the same gateway token carrying the now-consumed blob, and **every refresh
after the first fails at the provider** (`idp_session_ended`) — an availability
foot-gun, fail-closed, but a configuration the operator can legally set today with no
warning anywhere. Remedy: the custody requirement should state the interaction — either
rotation off is refused under this mechanism, or its semantics (the carried credential
becomes single-use; the session ends at the second refresh on per-grant-rotating
providers) are stated as the priced cost.

**R3-m6 — The two new settings and the rotation procedure have no operator-facing
documentation task.** Task 2.2 lands the body-cap raise in `.env.example` and
`docs/gateway-configuration.md` (`tasks.md:159-162`); nothing tasks documentation for
`gateway_custody_keys` itself (how to generate a 32-byte key, what the key-id mapping
looks like, that a rotation is a **hard cut that logs out every live refresh session**,
bounded by the window) or for `gateway_custody_provider_token_max_bytes` (its coupling
to the body cap, m2). The proposal's Impact list names the files generically, but the
tasks carve only the mapping and the rename into them — the same propagation class as
round 2's R2-M2. The rotation wave cost is stated in the design and the delta spec but
never reaches the operator who would perform the rotation. Remedy: extend task 2.2 (or a
2.2b) with the custody-key and size-bound operator documentation, the hard-cut wave cost
included.

**R3-m7 — The EP4 row's summary sentence overstates the transient-plaintext bound by
omitting the pending entries.** `design.md:608`: "a same-window compromise reads the key
plus at most the refreshing session's plaintext" — a compromise during the
sign-in-to-code-grant window also reads the **pending hand-off entries' plaintext**
(minutes-bounded, one per completed-but-unredeemed flow). Category 1 of the same threat's
grid names them (`design.md:847-849`), so the price is disclosed — but the row's
one-sentence summary, which is what the compromise table's re-price and RES-21(iv) echo,
drops them. Remedy: "the key plus the presenting sessions' plaintext and the
minutes-bounded pending entries" in the row (or a parenthetical).

---

## Verdicts on the six attack points

1. **The third audit class — PASS.** The four-burst design is coherent and complete:
   plain `invalid_grant` (denylist/expiry/bad signature — the closed table's existing
   token, verified at `gateway/token.py:96-101`), `custody_decrypt_failed` (absent,
   tampered, unknown key-id/version, expired envelope, `sub`-mismatch),
   `claims_read_failed` (unreachable, unusable, subject mismatch, roles path absent,
   and every provider 4xx other than `invalid_grant` — `invalid_client` lands here, the
   misdiagnosis round 2's m1 existed to prevent), `idp_session_ended` (keyed on the
   provider's `invalid_grant` specifically — RFC 6749 §6's session-gone code, verified
   as the keyed class in task 2.1/2.3 and the delta spec's scenarios). The closed-table
   extension preserves the property I verified in the code (one-directional, keyed,
   unmapped values raise at `gateway/token.py:119-126`): the keying widens to error-code
   plus named class, every token committed, no `flow_refused` bypass, and the verify
   rows assert mutual distinguishability of the four bursts plus the
   `invalid_client`-never-session-ended negative. The divergence from the custody
   opinion's A6 (which prescribed `claims_read_failed` for decrypt failures) is
   **justified on the record**: D4 (`design.md:372-375`) cites A6 and gives the
   operational reason — a custody-key mistake or botched rotation must never read as a
   provider outage or as mass revocation — which is exactly the diagnostic the
   three-token design exists to preserve, and the release-notes count slip (m1) is the
   only defect in the class.
2. **The hard-cut rotation choice — PASS.** The justification is sound and correctly
   framed: rotation is a rare, operator-initiated act undertaken at the
   compromise-suspected moment — the one moment the old key must stop working — and the
   dual-accept alternative keeps the possibly-compromised key hot against every live
   blob for the window (`design.md:258-274`). The mass re-sign-in cost is stated as the
   accepted price in A3, in the delta spec's hard-cut scenario (bounded by the
   non-sliding absolute expiry — the bound is real and correctly derived from D4's
   `rotated_expiry`, verified at `gateway/tokens.py:243-250`), and in RES-21's bounding
   controls. The RES-15/C3 interaction is honest: a rollout is a restart, not a
   rotation — the key is unchanged, so refresh capability survives it (the gain, C3's
   ratchet removed); only a deliberate key rotation costs the wave; and "one drill, two
   keys" is accurate against `docs/production-roadmap.md:84,201-211` (T3 folded into
   C3), with the two keys' different rotation semantics (gradual JWKS-TTL overlap for
   the signing key, hard cut for the custody key) both stated. The one gap is
   operator-facing: nothing tasks the documentation of the wave cost or the rotation
   procedure (m6).
3. **A5's arithmetic — PASS, live-able.** Verified concretely: 4096-byte provider token
   → ~4.2 KB envelope plaintext (embedded `sub`/`exp` included) → ~5.7 KB base64url
   claim → ~6.3 KB refresh token → ~6.5 KB form body, against the 16384 cap — ~2.5×
   headroom at the defaults. Real opaque tokens: the Entra public-client shape (~1–4 KB)
   fits under the default; a B2C custom policy issuing more hits the **configured,
   loudly-refused-at-sign-in** bound — a named deployment prerequisite an operator can
   raise, not a silent wall. Task 3.3 is genuinely adoption-blocking as specified: it is
   an implementation gate wired into task 5.3 ("green in both field harnesses before the
   change is done"), with the undodgeable-hard-limit finding named as the one thing that
   legitimately forces the custody shape back to the owner — the exact escape hatch A5's
   live verification was designed around. The unmentioned remainder is the two settings'
   coupling (m2).
4. **The corrected carrier justification and the flagged docstring — PASS, verified
   against the Core source.** Every fact in the corrected wording
   (`design.md:216-233`) checks against `dial/dial-core/ai-dial-core`:
   `IdentityProvider.java:396-409` — `extractUserHash` is the salted SHA-256 of the
   `loggingKey` claim, with `obfuscateUserEmail` defaulting **true** (line 208);
   `AnalyticsSettings.java` — `claimsAllowlist` is opt-in, `"*"` collects every claim,
   `collectClaims`/`collectHeaders` default **false**; the bundled
   `aidial.settings.json:131` — `authorization` on the default `headersBlacklist`;
   `IdentityProvider.java:218,128-130` — `claimPathsToLog` defaults to
   `sub`/`oid`/`email` at a `claimsLogLevel` defaulting to DEBUG. The overstatement is
   confined to `gateway/tokens.py:6` in live repo material (the archived PoC folder's
   copies are history), it is **flagged, not silently rewritten** (`design.md:1262-1277`,
   the strict gap list, the release notes), and the design's own carrier text carries
   the verified wording — the decision stands on the refresh-grant facts alone, exactly
   as stated. The flag's one weakness: the correction has no task home ("a small
   repo-docs task the owner pause assigns") — see the pause list below.
5. **Byte-identity — PASS with one undeclared drop (m4).** Every retained scenario in
   the delta was compared against the main spec: the REMOVED→ADDED refresh requirement
   carries its six retained scenarios byte-identically except the three declared
   amendments (Silent refresh, Resource mismatch → `invalid_target` — verified against
   `gateway/token.py:359-362` and `tests/test_tokens.py:447-457`, so task 2.6's
   no-code-change reconciliation is right — and the TTL re-derivation); the MODIFIED
   requirements' changes are exactly the declared ones (mapped→served, the inference
   condition, the `sub` authority, the claim source, the retention/custody sentences);
   the migration note now reads "except those three" (round 2's m4 fixed); and every P3
   requirement the change does not touch is absent from the delta. The one defect is
   m4's undeclared drop of the min(flow TTL, own expiry) sentence.
6. **Threat-model delta completeness — FAIL in part (R3-M1).** What §7 *does* name was
   checked entry-by-entry against the model's current text and is consistent and
   non-overstating: T1-16/RES-6/invariant 4 (the shrink to the access TTL is exactly
   what the delta spec guarantees), T4-2/RES-2 (v3 shape: two persistent secrets,
   transient plaintext per grant, the never-store wording's named exception), T5-1/RES-3
   (the purposes sentence, both plaintext and ciphertext presentations), RES-19/T5-2
   (the forgery gain honestly narrowed to any-claims-for-an-existing-`sub`; the sniffing
   gain named), T1-15, RES-10, RES-15 (narrowed to a gain with the pending-entry,
   replay-cache, and denylist losses and the stolen-token regression recorded), T6-2,
   RES-16, T1-7, RES-4, RES-20, RES-21 (four parts, the R2-m2 remedies landed: per-user
   and session-bound **not scope**, the reuse-detection and Idle/Max bounding controls
   present), M13/M9/M10, the revocation-summary table (matches
   `background/design.md` §6.3's row), the compromise table's two rows, §1, §4's two new
   asset rows with A4's footprint gained (15 + 2 = 17 — no store row ever landed, so
   there is nothing to remove), and OQ-1's resolution (verified:
   `gateway/status.py:111-122` enforces the audience/resource binding). Round 2's R2-M1
   locations are all in the list now. The defects are what the list still omits —
   R3-M1's four classes above.

## The crypto seam (this round's own responsibility — no prior pass covered it)

- **Envelope correctness — PASS.** AES-256-GCM with a per-encryption 96-bit CSPRNG
  nonce, gateway-chosen at encryption and never taken from the envelope (DT-EP1-8 cat 6);
  the layout `version | key-id | nonce | ciphertext‖tag` base64url; the embedded
  `sub`/`exp` are inside the plaintext, hence **both encrypted and authenticated**,
  and both are checked at the seam before any use — the `sub` check as the placement
  bound (correctly reasoned: the tag cannot see placement, `design.md:246-252`). The
  two shortfalls are stated as m3: the NIST 2^32 random-nonce bound is unstated, and
  the clear-text `version`/`key-id` are not stated to be bound into the associated
  data. **Key commitment**: AES-GCM's missing key commitment is structurally
  neutralized today by the single-active-keyset invariant + hard cut (an unknown key-id
  refuses; there is never a second live key to confuse with) — sound, but the design
  never says this is *why*, which matters because the envelope is versioned for a
  multi-key future (m3b). The `key-id` is safe to expose: it is lookup metadata, fails
  closed when unknown, and selects nothing cryptographic.
- **Key separation — PASS with R3-M2.** Dedication is stated as a requirement
  ("separated from the signing key (never derived from it, never used for signing)",
  D3/A3 and the delta spec), and the custody discipline otherwise matches the signing
  key's bar: `.env` injection with committed placeholders only (invariant 6), never
  logged, `repr`-clean per `gateway/keys.py`'s `SigningKey` discipline (verified at
  `gateway/keys.py:119-125`), hard-cut rotatable, KMS-wrapped-DEK preference recorded
  as C3 input. The bar is missed in exactly one place: the signing key's minimum-size
  load check has no custody analogue, and without it the AES-256 pin is enforceable
  only by honor (R3-M2 — `AESGCM` follows the key's length).
- **Plaintext lifetime — PASS.** Decrypt-use-drop is specified ("the plaintext exists
  in the process only inside the encrypt/decrypt call and the grant's outbound
  presentation; never logged, never delivered", task 2.2; "for the duration of each
  refresh grant", §7's T4-2/RES-2), never cached, never logged, never delivered to any
  client — consistent with RES-2's re-pricing, which correctly carries the managed-
  runtime floor. The one-sentence overstatement about the pending entries is m7; the
  pending-entry window itself is honestly disclosed (minutes-bounded, one per flow,
  dropped unredeemed, lost on restart fail-closed).
- **The M20 lesson applied — PASS.** The decryption path is as pinned as the encryption
  path: no algorithm identifier exists in the envelope at all; `version` and `key-id`
  are lookup keys into a fixed code-side set, not selectors — an unknown value refuses
  *before* any decrypt (task 2.2, DT-EP1-8 cat 5); the algorithm and lengths are code
  constants on both paths; and the negative rows (tampered tag, wrong key, unknown
  version/key-id, expired envelope, `sub`-swap, nonce uniqueness) exercise every
  refusal. The one M20-shaped hole is R3-M2 — the key material itself is the one
  remaining thing that can select the algorithm.

## History verified, not inherited

Round 2's findings are all confirmed landed in the v3 artifacts: R2-M1's five model
locations are in §7/task 4.1; R2-M2's two operator documents are in task 2.4's file
list (the old name's footprint — `.env.example:95,101`, `docker-compose.yml:68`,
`README.md:82,93`, `docs/gateway-configuration.md:27,29,378-379` — is entirely covered
by it); m1 (`invalid_grant`-keyed session-ended), m2 (per-user-not-scope with reuse
detection and the Idle/Max pair), m3 (task 2.5(e)'s idle-gap driven check), m4 ("except
those three"), m5 (`gateway/token.py` named with the mint/verify module distinguished),
and m6 (both-paths hand-off wording, verified against
`gateway/federation.py:115,170,178` and `gateway/flow.py:210`) are all verifiably
addressed. The custody opinion's amendments A1–A9 all landed (A1 carrier normative in
the spec; A2 pending entry kept with the honest sentence; A3 key + hard cut chosen and
written down; A4 pinned constants; A5 bound + cap + gate; A6 superseded by the better
three-class design, divergence justified; A7 RES-21 four parts; A8 rotation-grace
scenario; A9 the re-take itself). The brief's own claims check out: v3's shape matches
the opinion's verdict and the owner's ruling; the store is deleted with the
minutes-bounded pending entry kept; the body cap and bound are as stated
(`gateway/settings.py:289` verified at 8192 today).

## Clean areas (one line each)

- The carrier decision: refresh-token-only, normative in the spec with both
  refresh-grant facts as the legs, the access token barred by rule and reason, and the
  corrected Core-logging note now a supporting fact rather than a leg.
- The code-payload prohibition: absolute (plaintext or ciphertext), with the
  decode-and-assert test row and the M5/R2-M6 lineage cited.
- The hand-off seam: specified against the code's actual paths (both `_finish` sites,
  the code TTL bound, consume-at-grant, drop-unredeeded, restart fail-closed).
- D2's one-vocabulary claim: verified against the implementation — the exchange reads
  the token-endpoint access token through `_verified_claims` (`gateway/idp.py:193-194`),
  the exact carrier and path the grant will use.
- The snapshot-free refresh token: structural, with the negative control (no mint path
  without a completed read; no copied claims in the payload) specified in task 2.3.
- The startup lattice re-derivation (D6): three honest layers, the un-catchable failure
  named, the short-window-is-correct guidance carried into the operator material task.
- The SIA's conformance to `docs/security-analysis.md` §5: all eight sections in order,
  per-change delta shape, mis-use cases marked, threat-specific N/A reasoning
  throughout, G1–G8 with homes and owners.
- `openspec validate --strict`: green, run this pass; the delta format conforms
  (MODIFIED requirements carry full amended text; scenarios byte-identical except the
  declared amendments).
- The migration story: pre-change tokens fail closed once on the custody class, stated
  consistently across D4, the spec, and the release notes' transitional note.
- No `offline_access` anywhere: the amended M13 line is enforced twice locally (the
  provisioning's scope convergence, task 2.5(a)'s negative).

## What the owner pause must decide

- **OQ-A / OQ-C / OQ-D / OQ-G / OQ-H** — as parked (design §8); OQ-B, OQ-F, and OQ-E
  are discharged/resolve-with-source and nothing remains for the pause in them.
- **Pre-pause fixes to require landed** (authoring completeness, not rulings): R3-M1's
  model homes for the keepalive residual and the custody-era threats (plus the count and
  the three descriptive locations), and R3-M2's key-length startup refusal.
- **Assign the `gateway/tokens.py` docstring correction a home.** It is flagged
  everywhere it should be and rewritten nowhere it should not be — but "a small
  repo-docs task the owner pause assigns" currently has no assignee and no task slot;
  if the pause does not catch it, the overstated claim survives the change that
  falsified it.
- **Ruling slots surfaced by this round:** (1) whether refresh-token rotation off is
  refused under the mechanism or its degraded semantics are accepted and stated (m5);
  (2) whether `version`/`key-id` join the AEAD associated data now or the
  single-active-keyset rationale is recorded as the commitment bound to re-judge before
  any multi-key future (m3b); (3) confirmation that the hard-cut wave (and its
  operator-facing documentation, m6) is the accepted rotation cost.

## Bottom line

**LAND AFTER FINDINGS.** Land R3-M1 and R3-M2 (and m1–m7 alongside) in the change
artifacts before the owner pause. Nothing above reopens a design decision: the v3
custody shape, the refresh-grant mechanism, the hard-cut rotation, the carrier
discipline, the four-burst audit design, and the M13 amendment's priced trade all
survive this round's falsification attempts — including the crypto seam, which is
specified to a bar the custody opinion demanded ("a crypto seam specified casually"
was the stated risk) and misses that bar in exactly one enforceable particular (the key
length) and a handful of statements. The findings' common root is narrower than round
2's: the re-authoring pass landed every price it looked at in the artifacts' own tables,
and left the model's threat-side homes and two settings-coupling sentences unlanded —
the same edit-list class, one iteration later.
