# Task group 1 — the threat-model entries (tasks 1.1 and 1.2)

Change: `generalized-idp-federation` (C2). Scope of this record: task 1.1 (the
`docs/threat-model.md` delta) and task 1.2 (the cross-check against the delta spec).
Only `docs/threat-model.md` and this evidence file were touched. No commit made.

## Task 1.1 — what changed in the threat model, section by section

**Header, "The model at a glance."** Counts updated for the delta: 17→18 assets, 66→73
threats (EP4 8→9, EP5 8→14), 23→24 residual records (23 open + closed RES-18),
24→29 grouped mitigations.

**§1 (the system as it stands).** Unchanged — the as-it-stands description of the local
development shape is a local-deployment record and stays Keycloak-named (the D8
boundary; the local shape is still a Keycloak deployment).

**§3 (the disclosed-residual register).**
- RES-8: "every JWT IdP has here, Keycloak included" → "every JWT identity provider
  has" (mechanism vocabulary, neutralized).
- RES-14: "as powerful as Keycloak's" → "as powerful as the identity provider's".
- RES-19 re-priced, as the task specifies: the body's leg descriptions went
  provider-neutral ("talks to the identity provider over its internal http port", "the
  identity-provider legs carry the gateway's inbound identity-verification chain",
  the local back-channel URL kept as the local shape's address); a closing re-pricing
  paragraph added stating the two shapes — the local plain-http Keycloak legs
  unchanged; the override deployments' widened exposure (the **client secret** now
  rides the operator's plain-http claim in no-PKCE mode, wider than the refresh token
  alone, stated inside the override's own trust claim); the external-TLS shape as the
  residual's narrowing case (transport-protected like any HTTPS client, the same
  acceptance: an attacker who defeats transport validation on the issuer's own origin
  was always able to impersonate the provider directly).
- RES-21: the session-policy parenthetical scoped to "the local development Keycloak
  instance"; the image-default note kept (a local-provisioning fact).
- **RES-24 added** — the no-PKCE mode's interception residue (T5-11): the mode drops
  the binding that made an intercepted identity-leg code unexchangable; the client
  secret is the only remaining bar on a plain-http front door; the compensating
  control (secret authentication, startup refusal, default mode never presents the
  secret, client-facing PKCE unchanged); the re-open trigger (a TLS-fronted public
  origin re-opening the acceptance for re-judgement, or the mode's retirement).

**§4 (assets).**
- A2: "the user's real Keycloak/DIAL JWT" → "the user's identity-provider JWT,
  presented to Core".
- A5: "Keycloak code" → "the identity-provider code".
- A8: "Keycloak credentials and SSO session" → "the identity provider's credentials
  and SSO session"; footprint "Keycloak" → "The identity provider".
- A12: class-framed as the local development identity instance's credentials, the
  local dev shape named a Keycloak deployment (kept per D8).
- **A18 added** — the identity-provider client secret: high C / low I / low A;
  footprints the `.env` slot at rest, process memory in no-PKCE mode, the
  token-endpoint leg in presentation; blast radius the IdP-leg client only.

**§5 (trust boundaries).**
- TB3 reworded to not assume the local shape or either endpoint source: the local
  membership list kept as the local shape's fact (the Keycloak instance as the
  identity provider's compose-network peer), plus the generalized statement — in the
  external-provider configuration the IdP is not a network member; the back-channel
  legs egress to the provider's TLS origin or the operator-configured override's
  origin; the IdP is either a peer inside the boundary or a provider beyond it.
- TB7 retitled "The identity provider's interior": trusted in either shape (the local
  Keycloak development instance or an external provider), the trust exactly the pinned
  issuer plus its published key set, cross-referencing §10's external-IdP row.

**§6 (attacker inventory).** Attacker 6 (the deployment administrator) now owns Core's
configuration "and the identity provider"; realm administration phrased as "the
provider's realms or tenants and its client registrations".

**§7 (entry points).** EP4's entry point adds the identity-provider client secret in
no-PKCE mode to the gateway process memory it names. EP5's entry point generalized:
"the identity-provider back-channel — the discovery fetch or the operator's
directly-configured endpoints, the exchange, the refresh grant, the key-set fetch",
with the two leg shapes (the internal plain-http override / the local shape; the
external internet TLS provider / the tested shape) and the two endpoint sources
(discovery document; the directly-configured trio).

**§8 (threat tables).**
- EP1: the challenge-manipulation row's phishing target and the keepalive row's SSO
  Session Max parenthetical neutralized (the 10 h default re-scoped to the local
  development instance).
- EP3: the E7 guessing-variant row's "victim's Keycloak JWT" → "identity-provider
  JWT"; the callback-URL row's "Keycloak code" → "identity-provider code".
- EP5: section header generalized, with a short preamble stating the two shapes and
  the two endpoint sources (and that direct mode carries no provider-asserted input
  and no fetch). The sniffing row's token naming neutralized (the 24 h lifespan
  re-scoped to the local development realm). The MITM row (T5-2): "impersonates Core
  or the identity provider", "the sharper gain is on the identity-provider legs", the
  local back-channel URL kept as the local spelling. The dependency-stall and
  hostile-response rows' peer lists neutralized. **Six new rows added, model ids
  T5-9 through T5-14:**
  - T5-9 — forged discovery document steers credential-bearing calls: the
    mint-any-`sub` chain relocated to wherever the fetch is answered; bounded by
    refuse-whole validation (M26); residue the TLS-bounded acceptance any HTTPS
    client carries (RES-19's external-TLS narrowing case); absent in direct mode.
  - T5-10 — discovery-fetch amplification off the public surface: bounded by the
    cache and the authorize surface's limiter (M27), fetch rate
    min(rate limit, 1/TTL); absent in direct mode.
  - T5-11 — intercepted identity-leg code exchanged by the interceptor in no-PKCE
    mode: the callback-URL interception class on the identity leg's own code, the
    confidential client the compensating control (M28); accepted — RES-24.
  - T5-12 — another journey's token accepted by a relaxed issuer match: refused
    gateway-side by exact-string pinning (M29); the distinguishability precondition is
    the provider's journey-distinct-issuance configuration, carried as a stated
    operator prerequisite rather than priced as a mitigation.
  - T5-13 — mistyped or swapped directly-configured endpoint **[mis-use]**: operator
    input at the configured issuer's own trust level; no provider-asserted input in
    the mode, so T5-9's and T5-10's classes are absent with it; accepted as the
    operator's explicit trust claim, bounded by M30.
  - T5-14 — stale directly-configured endpoint after a provider change: fail-closed
    with the fixed-vocabulary error (M30); the staleness accepted as the mode's
    priced, documented trade (the operator owns endpoint freshness).
- EP4: section header notes the client secret joining the custody class; **new row
  T4-9** — client-secret compromise: blast radius the IdP-leg client only (no
  gateway mint, no Core access, no upstream credential); the default mode's leaked
  secret buys nothing the PKCE binding does not bar; the `.env`-class custody, the
  never-cut-6 pattern, the KMS/secret-management move the recorded C3 scope.
- EP6: the challenge-redirection row's phishing target neutralized.

**§9 (per-threat grids).** Mechanism-vocabulary neutralized in T1-2 (the falsification
point and the accepted-issuer pair), T1-14 (the identity leg authenticates them),
T3-1 (the victim's identity-provider JWT), T3-3 (the gateway's verifier for the
identity leg), T5-2 (the configured identity-provider issuer; the identity-provider
legs with the local URL kept; verifying against the provider's own JWKS), T5-5 (Core
and the identity provider), T5-6 (the fixed peer set). No new grids — new threats
follow the established delta convention (an §8 row, a §13 disposition, and §12
coverage; the grids remain the baseline runs').

**§10 (compromise points).**
- The gateway-process row's in-flight JWT neutralized (24 h re-scoped to the local
  development realm).
- The compose-network row: "gateway↔Core and gateway↔identity-provider legs"; the
  local back-channel URL kept (the row is inherently the local shape's).
- The single Keycloak component row replaced by the two IdP shapes: the **local
  development instance** (a Keycloak deployment — what it holds plus authenticating
  federation flows, the gateway still gating issuance) and the new **external
  identity provider** row — a compromised external IdP mints any-`sub` under the
  pinned issuer and publishes the matching key set, which the exact pin accepts;
  **accepted with reasoning**: the pinned issuer plus its published key set *is* the
  trust, the provider is the trust anchor by design, and the gateway distinguishes a
  compromised provider from an honest one in no way, exactly as it cannot distinguish
  a compromised Core; no gateway-side control can bound a party whose assertions the
  pin exists to trust.

**§12 (grouped mitigations).** M2's pair list: "gateway↔identity provider". **Five new
rows, M26 through M30**: discovery-document validation (refuse-whole; T5-9; bounds the
widened RES-19 record), the discovery cache (T5-10; T5-5's discovery widening), the
no-PKCE compensating-control rule (T5-11's compensating control — residue RES-24;
T4-9's blast-radius bound), exact issuer pinning with the varying-issuer scenario
(T5-12), and direct-mode startup validation with fail-closed staleness (T5-13, T5-14;
removes T5-9's and T5-10's classes entirely in direct mode). All five **Placed —
spec** (the delta's discovery-validation, discovery, confidential-client,
verification-amendment, and direct-configuration requirements); M30's operator-
reference statements are repo.

**§13 (dispositions).** Seven rows added: T4-9 (mitigated to its blast radius; the
`.env`-class custody accepted), T5-9 (mitigated — M26; the TLS-bounded residue
RES-19's narrowing case; absent in direct mode), T5-10 (mitigated — M27; absent in
direct mode), T5-11 (accepted — RES-24), T5-12 (mitigated — M29; the
provider-configuration precondition stated), T5-13 (accepted as the operator's
explicit trust claim, bounded by M30), T5-14 (mitigated to its bound; the staleness
accepted as the mode's documented trade).

**§11 (invariant rulings).** Unchanged — the table rules the never-cut invariants as
the system stands; the client secret rides never-cut 5/6's existing wording ("Keycloak
admin credentials" there is a local `.env` fact), and this change's own ruling table
is the design's SIA §3.

### Prose convention

The model text carries behavior and reason only — no references to the change folder,
the design's section numbers, or any ruling artifact. Cross-references are to the
model's own ids (RES-*, T*, M*, §) and to standing background docs, as before.

## Task 1.2 — the cross-check against the delta spec

Every gateway-owned mitigation the design's §6 grouped list names was checked against
`openspec/changes/generalized-idp-federation/specs/mcp-signin/spec.md`:

| §6 item | Delta-spec home | Result |
|---|---|---|
| 1. Discovery validation (issuer equality, origin-bound endpoints, HTTPS-without-override, no redirects, size cap, refuse-whole) | The "Discovery documents are validated against the configured issuer" requirement; scenarios: Document issuer mismatch refused; Out-of-origin endpoint refused; Plain-http issuer refused without the override; plus the discovery requirement's fetch discipline (no redirects, size cap) | Present |
| 2. The discovery cache with its TTL | The discovery requirement's cache clause and the "The cache bounds staleness and cost" scenario | Present |
| 3. The no-PKCE compensating-control rule | The confidential-client requirement and all five of its scenarios (startup refusal without the secret; the mode runs as a confidential client; the default mode never presents the secret; the client-facing surface still requires PKCE; the secret never reaches an output) | Present |
| 4. Exact issuer pinning with the varying-issuer scenario | The verification requirement's amendment and the "A token from another journey's issuer refused" scenario; the discovery document's issuer-mismatch scenario pins the document side | Present |
| 5. Fail-closed leg semantics with fixed-vocabulary audit ("unchanged, restated") | The fail-closed half is restated in the delta (the discovery requirement's leg-closed refusal with no fallback construction; the direct-configuration requirement's stale-endpoint scenario); the audit-record half lives unchanged in the main `mcp-signin` spec, which the delta does not modify — correct by the "unchanged" home | Present (no finding) |
| 6. Operator reference for the override and the mode | Repo by design — not a spec mitigation | Not applicable |
| 7. Direct-mode startup validation with fail-closed staleness | The "A directly configured endpoint set replaces discovery whole" requirement: all-or-nothing with the partial-set refusal naming the configured and missing members; the well-formed-absolute-URL refusal; the plain-http-without-override refusal; the no-fetch clause ("MUST NOT be attempted at all") with its skip scenario; the stale-endpoint fail-closed scenario; issuer pinning unaffected | Present |

The task 1.2 enumeration's items — issuer equality, origin-bound endpoints,
HTTPS-without-override refusal, cache TTL, no-PKCE startup refusal, exact issuer
pinning scenario, secret-never-logged scenario, and §6 item 7's four direct-mode
mitigations (all-or-nothing refusal, well-formed-absolute-URL and HTTPS-or-override
checks, no-fetch skip, stale-endpoint fail-closed scenario) — each map to a normative
MUST and a named scenario in the delta.

**Outcome: no findings.** Every gateway-owned mitigation in §6 has a requirement in
the delta; nothing to report back for a spec fix.

## The grep verification

`grep -in keycloak docs/threat-model.md` after the edit — 27 lines remain, each a
D8-scoped local-deployment fact; no mechanism-level hit survives:

- §1 lines (the as-it-stands local shape): the instance's Keycloak contribution with
  its browser-facing and back-channel URLs; the flow federating Keycloak; the live
  user's Keycloak JWT and the `sub` copy; the admin credentials in `.env` — the
  local development shape's own description, explicitly inside D8's allowance.
- RES-19's local back-channel URL (`http://keycloak:8900`) and the re-pricing
  paragraph's "the plain-http Keycloak legs" — scoped to "in the local shape".
- RES-21's SSO Session Idle/Max pair ("on the local development Keycloak instance")
  and the provisioning/image-default note — the local realm's own session and
  provisioning facts.
- A12 (the local development identity instance's credentials — "the local dev shape
  is a Keycloak deployment"), TB3 (the local-shape peer and its URL), TB5 (the local
  admin/test-user credentials in `.env`), TB7 (the local instance named as one of the
  two shapes).
- EP2's SSRF row (the local compose addresses `core:8080` / `keycloak:8900`), the EP5
  MITM row and its grid ("locally `http://keycloak:8900`").
- §10's host row (local admin credentials in `.env`), the compose-network row (the
  local back-channel URL), and the local-instance component row ("the local
  development instance (a Keycloak deployment)").
- §11's invariant 6 (the local admin credentials' `.env` delivery).
- M13 (the provisioning helper — the helper's own Keycloak Admin API scope, D8's
  helper-scoped ruling).

Every hit names the local development deployment, its instance, its URLs, or the
provisioning helper; the federation leg, its tokens and codes, its trust boundary,
and its key set are provider-neutral everywhere.

One numbering note, for the record: the design's SIA numbers its delta threats
DT-EP5-1…8, but the model's prose already cites DT-EP5-2 and DT-EP5-3 from a prior
change's delta (the refresh-token sniffing price and the forged signed-in answer) —
reusing those ids here would make the model's citations ambiguous. The model's own
stable numbering was therefore extended instead (T5-9…T5-14, T4-9), and no new DT-
ids were introduced into the model. The design's internal ids remain readable from
the design; the model needs no second meaning for them.

## Gate outputs

- `python scripts/check_publication_leaks.py` — **PASS** (exit 0): "scanned 206
  tracked files; 3 finding(s): 3 waived, 0 unwaived" — the three waived findings are
  pre-existing (`docs/evidence/d0a/review-round-1.md` ×2, `scripts/import_background.py`);
  no finding originates in this edit.
- `python -m pytest -q` — **570 passed, 1 skipped** (docs-only change; the run
  confirms the tree is still green).
- `openspec validate` — not applicable: no change-folder file was modified by this
  task group.
