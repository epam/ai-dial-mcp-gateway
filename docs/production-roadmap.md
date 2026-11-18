# Production roadmap — the sign-in gateway beyond the PoC

**What this document is.** The working tracker for taking the field-proven gateway to
production and for the capability's evolution after deployment. Items graduate into
OpenSpec changes as they are picked up; this document records the scope, not the
specs. Feeds `ROADMAP.md`'s next iteration.

**Where we are.** The PoC (`build-mcp-sign-in-gateway-poc`, archived) closed all five
acceptance criteria on real harnesses (Claude Code via CIMD, Cursor via DCR);
`fix-dcr-response-conformance` (archived) fixed the RFC 7591 response conformance
Cursor exposed. The full gate ladder ran; both review gates passed. The production
deployment target is a **Kubernetes cluster**; the gateway is not exposed directly
(TLS terminates at the cluster's ingress — infrastructure work, not the gateway's).
The six P-items below are packaged and ordered in the section
"**The iteration, packaged and ordered**" — read it before picking an item up.

---

## The next iteration — minimal scope (owner, 2026-10-28)

Six items, nothing more. The definition of done: P1–P6 + whatever the threat model
(P6) reveals as blocking.

- [ ] **P1. Secret management.** All secret material under the deployment's secret
      management: the signing key (KMS/HSM sign-interface — the process holds a key
      reference, not a key; `key_source: kms`) and the client secrets out of env
      files. *Accepts:* no secret material in env files or process memory beyond the
      disclosed residuals; the memory-zeroization disclosure amended accordingly.
- [ ] **P2. Refresh with up-to-date claims** (the s2s re-fetch upgrade). Today
      claims are frozen at issuance for the refresh token's whole life — a revoked
      role keeps its privileges for hours. A technical read-only IdP client; claims
      re-fetched per refresh; staleness collapses to the access TTL (IdP parity).
      *Accepts:* an IdP claim change is reflected in minted tokens within the
      access TTL, by test and by a live run.
- [ ] **P3. Dynamic MCPs.** Drop the required `TOOLSETS` mapping (an optional
      operator restriction instead): any platform toolset served by name pattern;
      discovery mirrors Core's registry-independent unauthenticated tier (any
      guard-passing name served, phantom and real alike, zero Core calls); the kind
      check is the upstream stage's routing decision inside the flow; reserved-name
      and charset checks at request time. *Accepts:* a toolset added to Core is
      sign-in-able without a gateway reconfigure; a non-OAuth toolset with a stored
      credential (user or global level) is served through the signed-in
      short-circuit, a non-OAuth toolset with none is refused on the impossible
      branch, and an unknown name is refused at the flow's authenticated settings
      read — the system's only existence refusal, discovery having answered it a
      document by the mirror property.
- [ ] **P4. Generalized IdP federation — the compliance shield.** Replace the
      hardcoded Keycloak URL suffixes with standard OIDC discovery from the issuer;
      rename `KEYCLOAK_*` → `IDP_*`; the tested case: **Entra B2C** (per-policy
      issuers, custom claims); the generalization: any OIDC provider whose MCP
      incompliances the gateway absorbs (no CIMD/DCR, quirky scopes/claims,
      optionally no PKCE via a confidential client). Open extension: opaque-token
      IdPs via a userinfo-federation mode. *Accepts:* the gateway fronts a
      non-MCP-compliant IdP (B2C) and a strict harness completes the flow; an MCP
      conformance suite (when available) as the certificate.
- [ ] **P5. One pod: nginx + gateway.** The deployment unit in K8s is a single pod
      running the router and the gateway as sibling containers (shared localhost) —
      K8s manifests/Helm replace the local compose for production. This also
      retires the recorded operational quirk (a gateway-only recreate 502s the
      router until it restarts — same-pod localhost upstreams make the pairing
      atomic under rollout). *Accepts:* the pod deploys/rolls as one unit; the
      probe batteries pass against the pod; the quirk is gone.
- [ ] **P6. The production threat model.** Assemble the distributed material (the
      component threat model, the security analyses, two review rounds' passes)
      into one living document — `docs/threat-model.md` — and re-judge every
      disclosed residual in the production shape (K8s ingress TLS, KMS key, no HA,
      real users). *Accepts:* assets, entry points, trust boundaries, per-threat
      dispositions; anything it reveals as blocking joins this iteration's list;
      each P-item traceable to a threat it addresses.

---

## The iteration, packaged and ordered (owner-approved plan, 2026-10-29)

The six P-items above are executed as **five grouped OpenSpec changes plus four
docs/config workstreams**, in the order below. Each workstream fixes the **outcome** (the
P-item's acceptance text above), the **constraints** the outcome must respect, and the
**files and surfaces** the work touches — it does **not** design the solution. Where the
mechanism is genuinely open, the choice is the change author's, made and justified in that
change's `design.md` and defended at its review gate.

```
D0a GitLab remote + the public-repo discipline (the leak check in the static gate tier)
D0b the pre-publication cleanup — gates only the GitHub move, not the iteration
D1  standing instructions for threat modeling + security impact analysis (skill + docs)
D2  threat-model baseline — docs/threat-model.md, the ledger every change cites
C1  P3 dynamic MCPs + P2 fresh claims at refresh
C1.5 apps with MCP endpoints as sign-in-able resources (the restored N1)
C2  P4 generalized IdP federation (B2C)
C2.5 AS security hardening (RFC 9700 alignment) — the consent/attribution checkpoint and the AS hardening pass
    (LANDED 2026-11-08: the checkpoint + registry live, both harnesses, the owner's
    real-harness round; the RFC 9700 ledger is docs/threat-model.md §15 — 98
    recommendations walked, every one dispositioned; B-1/B-2/B-5 landed, B-4
    deferred as RES-25, DPoP deferred with its two-sided precondition, step-up
    declined)
C3  P5 one K8s pod + P1 KMS sign-interface, secrets out of env, and T3's rotation drill
    (LANDED 2026-11-10: the pod contract — docs/pod-contract.md, the deployment unit's
    versioned document (image, classified env-var surface, nginx conf, mounts,
    ports/probes, security context, deployment diagram, single-replica assumption) —
    plus the pod shape on the composed stack (router and gateway one network namespace,
    port unpublished); the Alpine image clears the 44-HIGH Trivy debt; both keysets
    (signing, custody) carry active+retained entries and the per-entry source seam
    (env/file implemented, kms a reserved value refused at startup naming the gap);
    secrets out of env — the IdP client secret gains the IDP_CLIENT_SECRET_FILE
    spelling beside IDP_CLIENT_SECRET; the DCR durable mount a named contract MUST; the
    migration drill ran live on both keysets, negative control first, both emergency
    cuts rehearsed. The KMS interfaces stay post-go-live: the custody envelope (Core's
    CEK pattern) firm and planned, the signing sign-interface optional and possibly
    abandoned — env/file injection a supported end state. DevOps review of the contract
    (task 7.6) open by design, the documentation-first path — silence is not
    acceptance)
D3  closing re-judge of every disclosed residual into docs/threat-model.md
```

**D0 — publication hygiene, in two phases (not a blocker for the roadmap).** The
repository will eventually be published publicly under the `epam` GitHub organization as
one of the `ai-dial` components. Publication is a one-way door — it exposes the full
history and cannot be recalled — so D0 is split rather than front-loaded:

- **D0a — now: a GitLab repository plus the standing discipline.** The immediate
  requirement is to *not make the situation worse*: a remote (GitLab first; the move to
  GitHub happens when the cleanup is done), a public-repo discipline section in
  `CLAUDE.md` (no new internal hostnames, instance or cluster names, personal paths, or
  real issuer values; secrets never in history, not merely absent from the tip; local
  configuration stays `.env`/`.env.example` placeholders per never-cut 6), and a
  repeatable leak check added to the static gate tier so the discipline is a gate rather
  than a hope. From D0a on, every change adds **no new problematic content**, which is
  what keeps the eventual cleanup bounded instead of growing with the iteration.
- **D0b — later, before the GitHub publication: the cleanup.** The known exposures and
  their dispositions (the internal instance name across `.env.example`,
  `docker-compose.yml`, `gateway/settings.py`'s default and the docs; the absolute
  personal path in `scripts/import_background.py`; the machine detail embedded in the
  archived evidence), plus the owner decisions publication needs: whether the
  commit-history author identity is rewritten, whether the archived change folders
  publish and with what neutralization, and the LICENSE/org-standard metadata files
  (none are present today). **D0b does not gate C1–C3** — the iteration's roadmap
  proceeds; D0b gates only the GitHub move.

**D1 — the standing instructions (owner rulings, 2026-10-29).** The operator supplies the
substance; the repo vendors it and adapts it. Source material: the operator's two
instruction documents (threat modeling; security impact analysis — vendored into this
repo with attribution and a canonical-source pointer, so fresh agents and the published
repo never depend on a sibling path), plus the *method* lessons of the operator's
threat-modeling-framework project (eval-driven validation — a fresh subagent given only
the framework and the case, emitting a strict gap list; reproducibility by independent
double-run) — that project's framework spec and threat library stay out of scope until
they stabilize. Form: a hand-authored `.claude/skills/<name>/SKILL.md` carrying the
operational checklist, a `docs/` document carrying the method and rationale, and short
normative pointers in `CLAUDE.md` and `PROCESS.md` step 8.

The adapted method's core rulings, as the owner stated them:

- **The SIA runs in full on every change.** The instruction documents' two-step depth
  dial (impact level first; full exercise only if medium/high) exists to minimize a
  *security team's* involvement — involvement this repo is trying to avoid needing. Here
  the SIA is ours to run, so it runs every time; there is no "low impact, skip the
  tables" branch. The instruction documents' Step 1 impact evaluation is still performed
  and recorded — its level informs the security review gate's depth, not whether the SIA
  happens.
- **The SIA's essence is keeping the threat model current with every change:** plan the
  change → enumerate the new threats it brings → put the necessary mitigations into the
  delta specs → update the threat model → *then* implement. This is the order, not a
  suggestion; a mitigation that exists only in prose is not landed.
- **The initial threat model (D2) is performed in full**: all attack surfaces and attack
  vectors enumerated, all mitigations mapped. Mitigations must be **feasible and
  realistic**, and their implementation is named: normative in this repo's delta spec
  where the gateway owns the behavior; otherwise the document states *where* it is
  implemented (Core configuration, the deployment, an upstream) and who owns it. A threat
  may alternatively be **accepted with reasoning** — which is exactly this repo's
  "disclosed residual" landing in the threat model.
- **Validation:** the framework's first full application is C1's SIA — the authored
  artifacts are proven by C1 using them, and by a fresh subagent being able to produce a
  conforming analysis from the repo's docs alone (`PROCESS.md` agent-freshness applied to
  D1 itself).

D1 and D2 are documentation, not gateway behavior — they land as direct commits (the
`PROCESS.md`/`ROADMAP.md` precedent), each after an **independent review pass** of the
authored artifacts; they are not OpenSpec changes. The first OpenSpec change the framework
bites is C1.

**D2 — the threat-model baseline, performed in full.** `docs/threat-model.md` assembled
under the D1 method: assets and their footprints (with CIA sensitivity), trust
boundaries, every attack-surface entry point, a threat table per entry point using the
attack-type taxonomy (leaf-level categories, full path), and mitigations mapped for every
threat in the fixed control-category order — feasible and realistic, each named where its
implementation lives (delta spec / Core configuration / deployment / upstream), or
accepted with reasoning as a disclosed residual. Sources: `docs/background/design.md` §6
(consent attribution, trust concentration, the revocation and component-compromise
tables, invariants re-checked), `design-review.md` §5.1's itemized attack surface, the
never-cut list, and the disclosed-residual register. The re-judgement against the
*finished* production shape is D3, not this.

**C1 = P3 + P2.** Both are contained edits on existing surfaces — no new endpoint, grant
type, or trust boundary — which is why they share one security impact analysis, one review
cycle, and one owner pause. **P2's binding constraint:** the claims-refresh mechanism must
ride the OIDC standard and be universal — the identity provider is **not known upfront**
(the same premise P4 rests on), so no solution may assume a provider-specific surface,
endpoint shape, or claims vocabulary; whatever the flow reads must be discoverable from
the issuer. The mechanism itself is deliberately not decided here: evaluating the design
space (a claims/userinfo read at refresh, an introspection/userinfo resolution, or another
standards-based approach) and justifying the choice is the change author's task, the same
way the PoC's refresh decision was its author's. C2 inherits whatever C1 introduces and
must fold it into the generalized discovery path rather than leave two spellings of the
IdP leg behind — one reason C2 follows C1. P2 shrinks a disclosed residual (the role
staleness caveat on invariant I4 in `design.md` §6.5); C1's security impact analysis
records the new disposition, and D3 re-checks it. The
`_require_refresh_window_within_provider_lifespan` validator in `gateway/settings.py`
encodes today's staleness rule and must be re-derived by the change, not deleted.

**C1.5 — apps with MCP endpoints as sign-in-able resources (the restored N1; added
2026-10-30 after the minimization audit found it dropped).** DIAL's "apps with MCP
endpoints" are not toolsets and need no upstream credential: the gateway fronts them
with the same MCP-compliant AS + DIAL authorization, and the flow short-circuits the
upstream stage by kind — always on for this kind. The **general rule** this needs — the
upstream stage runs only when the credential is missing AND the kind makes it
establishable by consent — was **built by C1's P3 half** (the flow's routing decision:
the signed-in check, the short-circuit, the kind branch, the impossible-branch refusal,
all on the per-user settings read), so C1.5's planned mechanism is unified into C1's
general rule. What remains C1.5's own scope is smaller: the apps resource *surface*
(routes, discovery documents, and the router's apps MCP path — a new path shape C1 does
not touch) and the app kinds' semantics — the author verifies them against the **current
Core source** (the checkout at `dial/dial-core/ai-dial-core` is kept fresh for exactly
this; corrected 2026-11-03 per the owner: **`DIAL_NATIVE` is supported only for
external-services for now — not for toolsets and not for apps**; toolsets may support it
in the future, so no C1.5 design may assume it).
*Accepts:* a credential-free app-MCP resource completes the harness flow with no
consent and no credential call; the audit records show the kind-driven short-circuit.

**C2 = P4 alone.** The largest surface — the `KEYCLOAK_*` → `IDP_*` rename reaches
`.env.example`, `docker-compose.yml`, `gateway/settings.py`, `gateway/federation.py`,
`gateway/idp.py`, `scripts/provision_keycloak.py`, `README.md`, two docs, and six test
files — plus the OIDC-discovery generalization and a live Entra B2C integration run, so it
gets its own full-depth review. It runs before C3 because the B2C acceptance run is far
cheaper against the local compose stack than inside a fresh K8s pod.

**C2.5 — AS security hardening (RFC 9700 alignment).** A security-hardening pass over the
authorization-server surface against the OAuth 2.0 Security Best Current Practice (RFC 9700)
plus the OIDC recommendations, every scope item dispositioned by that change itself
(landed, deferred, or accepted with reasoning). The scope seed: (1) **the
consent/attribution checkpoint** — a client registered through CIMD on an operator-
allowlisted origin can drive a victim's live IdP session through `/dial/authorize` with no
gateway-owned decision point anywhere, and redeem the code as the victim; the app kind's
zero-page short-circuit is the sharpest variant, and PKCE/`state`/single-use codes bound the
interception class, not this one, because the attacker holds every binding legitimately. The
standing control is CIMD allowlist curation; the standard remedy is a consent page naming
the resolved client and the resource. (2) **Sender-constrained tokens (DPoP, RFC 9449)**,
evaluated as the structural remedy for the bearer-token residual — the harness ecosystem's
DPoP support is the open question, so this is evaluated, not promised. (3) **Step-up /
re-authentication** (`max_age`, `prompt=login`, `auth_time`). (4) **`state` strictness** —
an absent client `state` refused or tolerated, made explicit. (5) **The CORS/back-channel
posture statement** — the token endpoint is same-origin/back-channel only, and a browser
frontend is not a supported client shape. The item's acceptance carries as its first two
rows the RFC 9700 checklist re-judge (every recommendation dispositioned against the gateway
as built) and the consent-page decision (built, or refused with reasoning).

The positioning: **after C2** because the consent-page acceptance needs the local compose
stack (the same reasoning that orders C2 before C3) and because C2's `KEYCLOAK_*` → `IDP_*`
rename churns the IdP leg the hardening touches; **before C3** so that both C2.5 and C3 land
before D3 and the closing re-judge judges the final shape.

**C3 = P5 + P1 + T3.** One change because they are the same conversation: "secrets out of env
files" *is* the pod's secret injection, and the deployment unit defines the secret slots.
The KMS sign-interface (`key_source: kms` — the process holds a key reference, not a key)
is what makes the memory-zeroization disclosure's own sentence true rather than
aspirational; C3's security impact analysis amends that disclosure and
`docs/gateway-configuration.md`'s statement that the store's protection is the same trust
boundary as the signing key's — an equivalence that changes when the key leaves the host.
**T3 (key rotation rehearsed) is folded here** — restored 2026-10-30 after the
minimization audit found it dropped with no record: rotation is the revocation table's
"all proxy access" path and the containment for the trust-concentration residual, and a
documented-but-never-exercised procedure is an unproven control. C3's acceptance gains
the drill: a live `kid` rotation with captured evidence — old tokens rejected within
Core's JWKS cache window, new tokens accepted throughout.

**The DCR durable mount is C3's named requirement** (added 2026-11-06, the owner's
catch in the C2.5 review pause): the pod's manifests/Helm MUST carry the mounted volume
the DCR registration store writes to (the JSON-file store the main spec's
"durable across restarts" requirement pins), or every pod restart silently invalidates
every registered client — the requirement the compose shape satisfies implicitly and
the pod shape can lose by omission. C3's acceptance covers it: the volume survives a
pod restart, a registered client's cached client id keeps working across it, and the
store path is the pod's one mounted state (the consent registry's in-memory custody
is deliberately excluded — see the C2.5 change's OQ-1 for the conditions under which
durable consents would be reconsidered).

**C3 as ruled, 2026-11-08 (the pre-authoring discussion's rulings; the change's author
owns the final solution within them and argues in the change's design where the plan
looks wrong):**

- **The deployment deliverable is the pod contract, not manifests.** DevOps own the
  Helm/pod assembly (their report); this repo cannot run K8s locally. C3 delivers: the
  image (base swapped to Alpine — the `ai-dial-adapter-*` Python precedent — clearing
  the 44-HIGH Trivy debt), the classified env-var surface (required / optional /
  secret / dev-only), the nginx conf as a versioned mountable file (front routing is
  spec'd gateway behavior, not DevOps folklore), the volume mounts (the DCR durable
  mount above), ports/probes, and the sibling-localhost assumption stated. Acceptance:
  the contract passes DevOps review — their explicit confirmation is the evidence,
  silence is not; the probe battery, the DCR-restart survival, and the drill run on
  the local compose stack in the production-image shape. **Single-replica assumption
  stated in the contract** — flow state and the approved-client registry are
  in-memory; the pod is not horizontally scalable (HA stays deferred).
- **Secret delivery: injected material via env vars is a first-class path, always.**
  `.env` locally; KeyVault/Secrets Manager → K8s Secrets → env in production. "Secrets
  out of env *files*" is what the pod shape delivers; the strict question is only which
  secrets justify a KMS API interface versus injection.
- **The per-entry `source` seam.** Both keysets (signing, custody) carry
  a per-entry source — `env`/`file` implemented in C3, `kms` a cleanly-rejected
  reserved value until it exists. Source-heterogeneous keysets (a retained env key
  beside an active KMS key) are what make the later migration graceful.
- **Active + retained keyset semantics for both keys.** Sign with the active key;
  verify with active-or-retained until the old tokens' TTL drains; the JWKS publishes
  all kids for Core's cache window. Routine rotation stops being a mass signout
  (today's single-key shape invalidates every outstanding refresh token). The
  retention-versus-stolen-old-key-window trade is the SIA's to price; revocation
  remains the immediate cut.
- **T3 upgraded to the migration drill:** the live `kid` rotation rehearses the
  overlap rotation with captured evidence — old tokens drain gracefully, new tokens
  accepted throughout, Core's JWKS cache respected. This drill is also the env→KMS
  migration path on AWS (asymmetric keys cannot be imported; Azure import can
  preserve the `kid`).
- **The KMS split is post-go-live.** The custody envelope — Core's credentials-manager
  pattern adapted: a single deployment-wide CEK (not per-user buckets; custody stays
  stateless), KMS-wrapped, the wrapped blob on the mounted volume, unwrapped at
  startup — is the firm planned step (the pattern is tested in Core; the port gets
  its own change, SIA, and live acceptance). The signing sign-interface (AWS + Azure
  in its first delivery) is **optional and may be abandoned** — env/file injection
  remains a supported end state. Both-configured-simultaneously must be supported
  when it lands. Cost/limits at company scale: sign volume stays inside cloud
  quotas, but the design must be throttle-aware (retries with jitter; a throttled
  mint fails closed) — the future change's SIA item.

**D3 — the closing re-judge.** Every disclosed residual — memory zeroization, the
token-use rule, the E7 callback-interception variant, the worker-pool flood queue, the
store/host-write boundary, and the role-staleness caveat C1 shrank — re-judged in the
production shape (K8s ingress TLS, KMS key, no HA, real users), with the verdicts written
into `docs/threat-model.md`. Anything D3 reveals as blocking joins the iteration's list,
per P6's own acceptance criterion. **Standing rule from here on: every change updates the
threat model's affected entries as part of its own security impact analysis.**

---

## Deferred — to later iterations

| Deferred item | Why it can wait |
|---|---|
| TLS on the public origin (was T1) | Infra work: the gateway sits in a K8s cluster behind an ingress; not exposed directly |
| Base-image hardening (added 2026-11-01, from C1's Trivy gate) | The Debian-slim base carries 44 HIGH OS-package findings, none fixable upstream (trixie archive) and none on the execution path — accepted for now. Remedy: move the image to a clean base — either Alpine or **whatever base the other Python-based ai-dial components use** (alignment preferred; check their Dockerfiles). Natural home: C3, which rebuilds the production image for the K8s pod anyway; if C3 slips, the item goes with it. |
| HA / Redis state (was T5) | AuthN load will be small; the designed loss semantics cover a restart; revisit under load |
| Graceful drain (was T6) | Tied to rolling deploys at scale |
| CI/CD (was T7) | The gate ladder runs manually until the deployment stabilizes |
| Metrics / log shipping / alerting (T8/T9) | The audit trail + logs suffice at current load; add with scale |
| Per-user revocation surface (was T11) | Coherent to defer once P2 lands: the stale-claims window shrinks to the access TTL, so role revocation propagates at the next refresh; revisit with the revocation-SLA decision |
| CIMD transient-failure retry + distinct reasons (was T14) | Checked against the landed threat model (2026-10-30): P6 did **not** pull it in — a transient CIMD failure fails closed with a plain-language page and a one-command user retry, and no threat row requires retry machinery. Stays deferred on that evidence. |
| Store hardening at load + the `client_name: null` decision (was T15) | Host-write-boundary class; recorded |
| Path-grammar unification (the `/dial/` vs `/apps/` asymmetry) | The asymmetry is kept as authored: one prefix per resource concern, which is what keeps the two namespaces' guards, regexes, and resource-URI derivations disjoint by construction. The reserved-name class is **not** retired by keeping the asymmetry: the reserved names exist because the `/dial/` prefix serves both concerns — the authorization surface (`/dial/authorize`, `/dial/token`, …) and the toolset MCP data path (`/dial/{name}/mcp`) — so a toolset named for a gateway-owned endpoint would shadow it. It is **unification** that would retire the class — following the grammar the apps namespace already does, whose name segment covers only its own data path and so carries no reserved names — and that unification needs a migration window for already-registered clients. It naturally lands with E1 (the Core merge), where the front door's spelling is open, or as its own change with that migration window. |
| Production deployment guide (was T16) | Written with the K8s manifests (P5) when the shape settles |

---

## Evolution (post-deployment)

- [ ] **E1. The Core merge — the native sign-in AS in DIAL Core.** The strategic
      destination: one component, Core's own token custody (the extra-IdP machinery
      and the second Tier-0 key retire), the no-credential 401 answered at the
      source, **per-toolset audience binding** possible (closes the biggest
      disclosed residual). The gateway remains: the bridge for older Cores, and the
      executable specification (design, threat model, harness measurements) for the
      implementation. Acceptance per the Core team's own plan.
      **Framework decision criterion (E1-specific):** the Core implementation should
      evaluate *Spring Authorization Server* (or equivalent Java AS primitives) as
      its base, with the federation/containment logic as the extension — the
      "adopt a framework" trade belongs at the Java layer, not in the Python
      gateway. Symmetrically, a decision criterion for the GATEWAY itself: stay
      custom-with-library-primitives (PyJWT/cryptography; no hand-rolled crypto)
      while its AS surface stays single-purpose (auth-code + PKCE + refresh, public
      clients only); the moment the surface grows (new grant types, introspection,
      client-authentication modes), re-evaluate an AS framework — the
      code-vs-config surface trade starts winning there.
- [ ] **E2. The revocation-SLA decision** — re-taken after E1's shape is known
      (native tokens change the refresh calculus); P2 is the interim answer.
- [ ] **E3. API_KEY toolset wrapper** (the recorded OQ-7 UX) and **E4. GLOBAL-level
      sign-in** (OQ-9, admin-gated).
- [ ] **E5. RP-initiated logout** (OQ-6).
- [ ] **E6. Device-authorization flow** (RFC 8628) for headless-first harnesses.
- [ ] **E7. Pin-latest-Core simplification** (drop the dual-API tolerance) — folds
      into E1's planning.
- [ ] **E8. Operator conveniences**: a registration-management admin surface;
      metrics-driven limiter tuning; a toolset client-naming convention (the
      consent screen shows the IdP-registered name — cosmetic, demo-visible).
- [ ] **E9. Revisit the Keycloak-extension option** only if Keycloak is guaranteed
      and the verifier-binding obstacle is solved (narrower future than E1).

---

## Open questions registry

| Question | Where it lives | Decides |
|---|---|---|
| Revocation SLA (stale-claims window) | P2 / E2 | Whether P2's shape is final |
| `client_name: null` — null / omit / refuse | Deferred (T15) / the spec carve-out | The name-less registration's shape |
| DCR store in HA mode | Deferred (T5) | Named volume vs Redis-backed |
| What the production threat model pulls in | P6 | The iteration's final list |
| The E7 interception residual's final wording (restored 2026-10-30) | D3, with C3's TLS decision | The re-judged RES-1 wording once TLS fronts the origin |
