# Design — one pod and keysets (C3)

## Context

The production roadmap fixes this stage as **C3 = P5 + P1 + T3** (the owner-approved
iteration plan, 2026-10-29), with the binding ruling set in the "C3 as ruled,
2026-11-08" amendment of `docs/production-roadmap.md` — the pre-authoring discussion's
rulings, which fix outcomes and constraints and leave the mechanisms to this change's
author. The three items are one conversation: the pod is the deployment unit that
defines the secret slots; "secrets out of env files" is the pod's secret injection;
and rotation is the operation that proves both.

What the change builds on, as verified in this worktree (post-C2.5, `IDP_*` settings):

- The signing key is a single injected PEM today (`gateway/keys.py:128-150`,
  `gateway/settings.py:505`): one `SecretStr`, parsed once at startup, `kid` derived
  from the public key, the JWKS is that one key's public half, and `decode_own_token`
  verifies against `signing_key.public_key()` directly (`gateway/tokens.py:326-359`).
- The custody keyset is already a dict forced to exactly one entry
  (`gateway/settings.py:528, 567-575, 977-1025`): `gateway_custody_keys` as key-id →
  base64 key, the multi-active refusal and the 32-byte pin in place, rotation a hard
  cut by requirement, the envelope's key-id checked against the single key at decrypt
  (`gateway/custody.py:176-244`).
- The deployment shape is two compose services on the instance network: the router
  (nginx, host-published `:8090`, the conf's gateway upstream by service name at
  `router/nginx.conf:43-45`) and the gateway (container-internal `:8091`, never
  published — the peer-identity authority property, `docker-compose.yml:94-108`).
  The image is `python:3.12-slim` with 44 recorded HIGH OS-package findings (the
  deferred table's Trivy debt, natural home C3).
- The DCR store is a bind-mounted JSON file (`docker-compose.yml:229-244`), durable by
  requirement; the approved-client registry and flow state are in-memory by design;
  the fixed uid 10001 is what makes the store's ownership predictable
  (`Dockerfile:26-29`).
- The threat model's rows this change re-prices: RES-2 (memory zeroization — the
  disclosure this change must amend), RES-13 (file-based signing-key custody), RES-15
  (single instance), RES-21 (the mintable-custody residual), RES-5 (the store's
  host/volume boundary), the revocation table's "all proxy access" row, and EP4/EP6/
  EP7's entry-point rows (`docs/threat-model.md` §3, §8, §10, §12).

The KMS adapters themselves are **out of scope** (post-go-live, their own change with
its own SIA and live acceptance); what this change lands is the seam they will plug
into, the semantics that make their arrival a rotation, and the drill that rehearsed
the rotation before any of it exists.

## Goals / Non-Goals

**Goals**

1. The pod contract as a versioned repo document that DevOps review accepts with
   explicit confirmation — image, classified env-var surface, the nginx conf as a
   versioned mountable file, volume mounts (the DCR durable mount a named MUST),
   ports/probes, sibling-localhost, single-replica — with the local composed stack as
   its executable stand-in for every acceptance.
2. The `key_source` seam with per-entry sources on both keysets: `env`/`file`
   implemented, `kms` a cleanly-rejected reserved value; the schema carried from day
   one so source-heterogeneous keysets are valid.
3. Active + retained keyset semantics for both keys: sign/seal with the active entry
   only; verify/decrypt with active-or-retained through the drain window; the JWKS
   publishing every `kid`; routine rotation a drain, revocation the immediate cut.
4. The migration drill (T3, upgraded): live rotation of each keyset on the composed
   stack, captured evidence, negative control first, the emergency cut rehearsed
   beside the routine drain.
5. The disclosure amendments: the memory-zeroization disclosure honest under both end
   states; the configuration reference's signing-key/store trust-boundary statement
   re-stated for the pod shape; the threat model's affected entries updated per the
   standing rule.

**Non-Goals**

- Helm charts, K8s manifests, any live K8s rollout (DevOps-owned; the contract is the
  deliverable).
- TLS/ingress (infrastructure; RES-12/RES-1 unchanged), HA/Redis (deferred; the
  single-replica assumption stated instead), CI/CD.
- The KMS adapters (post-go-live): neither the AWS/Azure signing sign-interface nor
  the custody CEK envelope is built here — both are *named* as the recorded next
  steps, with their shapes fixed in D8 so the future change inherits a decided
  design.
- GCP (not in the first KMS-signing delivery, should it happen).
- Any change to token TTLs, rotation grace, the refresh lattice, the flow, or the
  consent checkpoint — the keyset semantics change *which key* signs and verifies,
  never the token shapes or the flow around them.

## Decisions

### D1 — The pod contract is a repo document; the composed stack is its executable stand-in

The deliverable is the **contract**, not manifests: `docs/pod-contract.md`, a versioned
document this repository owns, stating the image, the classified env-var surface, the
nginx conf as the versioned mountable file, the volume mounts, the ports and probes,
the sibling-localhost assumption, and the single-replica assumption. DevOps own the
Helm/pod assembly; their **explicit confirmation** is the review's evidence — the
acceptance scenario says silence is not acceptance, because a contract "reviewed" by
no reply is a contract nobody read. (The security-context section, the store's
governance/storage-class statements, and the deployment diagram are D10's — added at
the owner-pause amendment round, extending this decision's contract document.)

The local composed stack stands in for the pod so every acceptance runs without K8s:
the router service joins the gateway's network namespace
(`network_mode: "service:mcp-signin-gateway"`), which is compose's spelling of the
pod's shared localhost — the router then reaches the gateway at `127.0.0.1:8091`, the
gateway's port is unreachable outside the shared namespace, and the published public
port moves to the namespace-owning service. This is not a simulation of convenience:
the sibling-localhost assumption, the port non-publication, and the pairing atomicity
(a gateway recreate no longer 502s the router — the recorded operational quirk P5
exists to retire) are all *exercised* by this shape, not merely stated. The probe
battery, the DCR-restart survival, and the drill all run against it, in the
production-image shape (D5).

The contract's volume-mount section carries the stage's named requirement: the DCR
store's mount, read-write, at the configured store path — the pod's one mounted
state. Where file-sourced keyset entries are configured (D2), their read-only
key-file mounts are named beside it. The consent registry's in-memory custody is
deliberately excluded, per the C2.5 change's OQ-1 record — the conditions under which
durable consents would be reconsidered are recorded there and none has changed.

### D2 — The keyset schema: per-entry `source`/`ref`/`role`, with compat spellings and a fail-closed `kms`

Both keysets share one entry schema:

```
<entry-id> : { "source": "env" | "file", "ref": "<env var name | file path>", "role": "active" | "retained" }
```

- **Signing** — a new setting, `GATEWAY_SIGNING_KEYS`, structured-only. The existing
  singular `GATEWAY_SIGNING_KEY` remains the **no-rotation shape**: one active
  `env`-sourced entry, no retained entries — every deployment that never rotates
  needs no keyset JSON, and the two settings configured simultaneously refuses
  startup naming both.
- **Custody** — `GATEWAY_CUSTODY_KEYS` accepts two spellings: the **flat** spelling
  (key-id → base64 key — today's exact shape, meaning one active `env`-sourced entry,
  no retained entries) and the **structured** spelling above. Mixing value kinds in
  one document refuses startup naming the keyset: one spelling per document, so the
  compat shape cannot silently coexist with retention. Retention requires the
  structured spelling — an operator who wants an overlap rotation has to say so in
  the schema, which is the point.
- **`kms` is a reserved value, refused fail-closed**: an entry carrying it refuses
  startup with an operator-facing error naming the gap ("the KMS interface for this
  keyset is not built; `env` and `file` are implemented"). Never a silent ignore,
  never a fallback — a config line that names a source the gateway cannot honor is a
  deployment that believes it has KMS protection it does not have, and the only safe
  answer to that belief is a refusal that corrects it.

The `ref` indirection is the load-bearing choice: the keyset **document is structure,
not secret material** — each entry's material sits in its own environment variable or
its own file, so the document itself classifies non-secret, a rotation adds one
Secret/mount rather than re-quoting a growing JSON blob of key material, and the
future `kms` entry is the same shape with `ref` naming a key reference. The
spec pins the seam (per-entry source, the reserved value, the roles); the field names
are this decision's, repo material.

Startup validation, per keyset: exactly one active entry; no zero-active keyset; a
blank singular value — empty or whitespace-only — is unset (the composition path fronts
every setting explicitly, so an absent value arrives as an empty string), the
both-configured refusal firing only on a real value; every
entry loadable and well-formed (RSA ≥ 2048 bits for signing, exactly 32 bytes for
custody — the existing pins); **duplicate derived `kid` refused** (the `kid` is a truncated hash over the public
material — 16 hex characters — so a shared `kid` is either the same key configured
twice or a collision between two distinct keys in the truncated hash; the refusal
stands either way, because one `kid` must name exactly one entry); a `file` source unreadable or unparseable refuses
startup naming the path, never the content; and no key material, fingerprint, or file
content reaches any error or log line — entries are named by their configured ids and
paths only, the existing discipline carried per-entry.

### D3 — Active + retained signing semantics, and the pre-publish rule the rulings require but do not name

Sign with the active entry only; every minted token carries its `kid`. The JWKS
publishes every entry's public half, **the active entry first** — a verifier that
resolves a `kid`-less token to the first published key selects the key that signs
(Core's own no-`kid` resolution rule, mirrored on the publishing side).
`decode_own_token` selects by the token's `kid` within the startup-fixed keyset,
algorithm pinned per entry, unknown `kid` refused — the pinned-algorithm requirement's
amendment. Retained entries hold private material for the drain window, bounded by
the refresh token's non-sliding absolute expiry (the longest-lived token minted);
removal is the immediate cut.

**The pre-publish rule is this design's one addition to the ruled semantics, and it
is required by the rulings' own acceptance:** "new tokens accepted throughout" is
unachievable without it. Core caches the JWKS; a key that starts signing the moment
it becomes active mints tokens under a `kid` Core's cache may not hold, and every
such token 401s at Core until the cache expires — a rotation-visible refusal window
the drill's "no refusal attributable to the rotation" forbids. The rule: a key that
is about to become active must have its `kid` published — present in the keyset,
hence in the JWKS — for at least the deployment's Core JWKS-cache window before it
signs. The staged procedure falls out with no third role: **add the new key as
`retained`** (published, not signing), **wait out the cache window**, **promote to
`active` and demote the old key to `retained`** — two restarts, zero refusal windows,
and `retained` is exactly "published but not signing," which is what pre-publication
needs. The operator reference states the wait bound as the deployment's Core
JWKS-cache TTL (10 minutes observed on the local instance — an operator-declared
fact, D7's open question).

**Where the author finds the ruling imprecise (recorded per the owner's standing
request):** the ruling's rationale — "the JWKS publishes ALL kids … so Core's
verifier accepts outstanding tokens through the window" — overstates the need. Core
only ever sees **access tokens** (≤ the access TTL); refresh tokens are presented to
the gateway alone, and the gateway verifies them from the keyset, not the JWKS. The
old `kid` is strictly needed at Core for ~access-TTL + cache, not the whole drain
window; publishing it for the full window is a simplicity choice whose cost — a
stolen retained signing key mints Core-acceptable tokens for up to the whole drain
window rather than ~10 minutes — the SIA prices (DT-EP4-2). The sharper design (a
publication window shorter than the private-retention window) is **rejected**: it
would make the JWKS and the keyset disagreeable by construction (a divergence class
the spec would then have to police), and it would give the operator two windows to
get wrong where the emergency lever — remove the retained entry, any moment, JWKS
drops the `kid`, Core refuses within cache + access TTL — already answers the
security case. One keyset, one JWKS, one removal procedure; the window is the priced
cost, the cut is the control.

### D4 — Custody overlap: seal under the active key, decrypt by the envelope's key-id

The custody keyset gains the same roles and sources. **Sealing is always under the
active entry** — every newly encrypted claim, at the code grant and at every refresh
rotation, carries the active key's key-id. **Decryption accepts the active or a
retained entry, the envelope's key-id selecting** — a mechanical, not architectural,
change: today's decrypt checks the carried key-id against the single key
(`gateway/custody.py:203-210`); under the keyset it looks the key-id up in the
entry map and refuses unknown ids exactly as before. The header stays bound into the
AEAD's associated data per entry, so a header transplanted between envelopes fails
the tag under whichever key it names — the existing property, preserved per-entry
rather than per-keyset. The subject and expiry checks at the seam are untouched.

The drain window is the refresh token's own non-sliding absolute expiry — the same
bound the hard cut's re-sign-in wave had, read from the other side: the cut waits for
exactly as long as the wave would have lasted. Each refresh during the window
decrypts under the retained key-id and re-seals under the active one, so the overlap
is self-shortening in practice (every presenting session migrates its blob at its
next refresh); sessions that never present again carry inert ciphertext that dies
with the token. Routine rotation therefore stops being a mass signout, and the
**hard cut survives as the operator's explicit act** — remove the retained entry at
any moment, and its outstanding blobs refuse at next presentation in the custody
refusal class: the re-scoped "Custody-key rotation is a hard cut" scenario's own
shape.

The flat compat spelling (D2) means no existing deployment's `.env` changes to gain
the seam; an overlap rotation is the one operation that requires the structured
spelling, and the operator reference says so in one sentence.

### D5 — The production image: Alpine base swap, the precedent verified

The base swaps `python:3.12-slim` → `python:3.12-alpine`. The ruling's precedent
claim was verified against the sibling `ai-dial-adapter-openai` Dockerfile (read-only;
see the SIA's strict gap list for the allowlist note): it builds on
`python:3.11-alpine` and runs `apk upgrade --no-cache libcrypto3 libssl3` — the
pattern that keeps the Alpine base's crypto libraries current and the scanner gate
green. This image carries that pattern, pins the same minor line the codebase already
targets (3.12), and keeps everything else the slim image earned: the fixed uid/gid
10001 (**load-bearing — the DCR store's ownership and the mounted volume's
permissions are stated against it in the contract**), the venv-copied builder, pip
removed from the runtime image, no `.pyc` writes, the non-root user, one
container-internal port, `ENTRYPOINT ["python", "-m", "gateway"]`.

The two verification risks the ruling names, with their answers:

- **musl wheels.** The dependency set (`pyjwt[crypto]`, `cryptography`,
  `pydantic`/`pydantic-core`, `fastapi`/`uvicorn`/`starlette`, `httpx`) ships
  `musllinux` wheels for CPython 3.12 — `cryptography` and `pydantic-core` (the two
  compiled dependencies) both publish them. Where a wheel is missing at build time
  the precedented fallback is a builder-stage-only `apk add build-base` (the adapter
  precedent's `alpine-sdk`), never a runtime toolchain. The builder stage may carry a
  compiler; the runtime image may not.
- **The compose-boot gate is the functional check.** The WSL-docker compose gate
  (gate 2) boots the pod-shaped stack on the new base and probes every service — a
  musl incompatibility surfaces there, at the gate, not in production. The static
  Trivy gate is the debt-clearing check: no HIGH-or-above OS-package finding remains,
  recorded in the change's evidence (the acceptance scenario's own row).

### D6 — The nginx conf's one substantive edit: the sibling-localhost upstream

`router/nginx.conf` is already the versioned mountable file the ruling asks for —
committed in this repository, mounted read-only in compose. The pod shape changes
**one line of substance**: the gateway upstream re-points from the service name
(`server mcp-signin-gateway:8091`) to sibling localhost (`server 127.0.0.1:8091`) —
the conf's own comment block already states the shared-network-namespace assumption
this makes true in the composed stand-in. Everything else — the challenge maps, the
anchored alternation, the ordering discipline, `$is_args$args`, the body cap, the
`X-Real-IP` statement — is unchanged, because the front routing is the spec's
behavior and this change moves only where the router finds the gateway.

The `X-Real-IP` authority property carries into the pod shape by construction: the
gateway's port is reachable only within the pod's network namespace, so a request the
router never accepted still cannot reach it — the non-publication invariant
(`docker-compose.yml:94-108`) restated for the pod, and the contract states it as the
assumption DevOps assembly must preserve (a pod spec that publishes the gateway port
or exposes it on the pod's external interface breaks the per-source rate limit's
trust basis — the mis-assembly shape DT-EP6-1 prices).

### D7 — The migration drill: scripted legs, negative control first, evidence hygiene

The drill is an acceptance **gate**, not a demo: its scenarios are the delta spec's
ADDED requirement, its evidence lands in `docs/evidence/c3/`, and its instrument is
proven able to fail before any verdict is trusted — the negative control (assert an
old-`kid` token still verifies after its retained entry is removed; it must fail)
runs first, per the repo's probe-fail-first rule.

Signing leg: obtain tokens under the old key; stage the rotation per D3 (add as
retained → wait out the declared Core JWKS-cache window, the wait itself observed or
bounded in the evidence → promote); through the drain — old-key access tokens
accepted at Core, old-key refresh tokens refreshing and minting under the new `kid`,
new sign-ins accepted throughout; after the drain bound, remove the retained entry
and record the refusals. Custody leg: rotate the custody key with the old key
retained, watch live refresh sessions decrypt under the retained key-id and re-seal
under the active one; then rehearse the emergency cut — remove a retained key
mid-window and record the custody-class refusals.

**The author extends the ruling here, and argues it:** the ruling names "a live `kid`
rotation" — signing-key language. The drill is extended to the **custody keyset's
rotation**, because the custody overlap is this change's own new semantics (D4) and
an unexercised procedure is an unproven control — the roadmap's own T3 reasoning,
applied to the second key the change rotates. The drill also doubles as the
env→KMS migration rehearsal exactly as ruled: the staged procedure is the path a
future KMS-sourced active key takes (AWS asymmetric keys cannot be imported — a new
`kid` is inherent; Azure import can preserve it), with the retained env-sourced key
beside it — the source-heterogeneous keyset the schema exists for.

Evidence hygiene is a spec'd rule (the drill requirement's own clause): `kid`s,
key-ids, JWKS snapshots, audit records, probe verdicts — never key material, never
token strings, never envelope contents. The evidence files are committed
(pre-publication discipline: public facts and fixed vocabularies only).

### D8 — The disclosure amendments, and the KMS split recorded as ruled

**The memory-zeroization disclosure (RES-2) amended to be honest under both end
states.** Today's record says the re-open trigger is "the KMS/HSM sign-interface —
which never materializes the key." Under the rulings that sentence is no longer a
plan: env/file injection is a **supported end state** (a reasoned disclosed residual
— CPython has no reliable wipe-on-demand, the process holds the active key material
for the process lifetime, and injection moves where the key is read from, not whether
the process holds it), and the KMS sign-interface is **optional and may be abandoned**
— its arrival would narrow the residual's signing half (the key never materializes in
the process) while the custody half stays (the CEK is unwrapped at startup and held).
The amended record states all three shapes instead of promising the one.

**The configuration reference's trust-boundary statement re-stated for the pod.**
`docs/gateway-configuration.md` says the store's protection is "the same trust
boundary as the signing key's" — true when both were the host's `.env`, and changing
now: under the pod shape the store's boundary is the **mounted volume and the node**
(read-write, its integrity the volume owner's), while a key's boundary is its
**injection path** — the env-var surface (pod spec, Secret, `/proc` environ) or the
read-only key-file mount (the node). The amended statement says exactly that, with
the equivalence kept only where it is still true (a file-sourced key on the same
volume class as the store) and dropped where it is not. The future custody envelope
is named as the firm planned step that moves the custody key's at-rest boundary to
KMS — but the statement is written to be true **before** that lands.

**The KMS split, recorded as ruled, with the author's concurrence and reasoning.**
The signing sign-interface (AWS + Azure in its first delivery) is optional and may be
abandoned; the custody envelope is the firm planned post-go-live step — Core's
credentials-manager pattern adapted: a single deployment-wide CEK (not per-user
buckets; custody stays stateless — the wrapped blob is deployment-wide state, never
per-session state, so the "no long-lived per-session store" property is untouched),
KMS-wrapped, the wrapped blob on the mounted volume, unwrapped at startup. The
author's reasoning for concurring, recorded so the position is examinable rather than
assumed: the signing key's exposure is bounded by rotation and the immediate cut
(the keyset semantics this change lands), so injection is a defensible end state for
it; the custody key's at-rest footprint is the one a KMS wrap genuinely moves — the
key never transits the env-var surface or the pod spec, only the wrapped blob does,
and the blob is useless without the KMS decrypt the startup performs. Both keysets
configured simultaneously (an injected signing key beside a KMS-wrapped custody CEK)
must be supported when it lands — which the per-entry seam (D2) already is.
Throttle-awareness (retries with jitter; a throttled mint fails closed) is recorded
as the future change's SIA item, per the ruling.

### D9 — The single-replica assumption: stated, not fought

The contract states it: flow state and the approved-client registry are in-memory;
the pod is not horizontally scalable; HA stays deferred. The author does not argue
this ruling. The loss semantics are already spec'd fail-safe (approvals re-prompt,
flows re-run, pending entries lost bounded), the alternative (durable consents) has
its recorded reconsideration conditions in the C2.5 change's OQ-1 and none has
changed, and the honest cost — a pod rollout re-prompts every user once per client —
is a UX cost, not a security one. What the contract adds beyond stating it: the
**mis-assembly shape is priced** (DT-EP6-1's scale-out row) — an operator who scales
the pod horizontally gets split in-memory state (callbacks landing on the other
replica's expired-flow page, approvals forgotten per replica), which fails safe but
confuses; the contract's single-replica statement is what makes that failure
diagnosable as a contract violation rather than a gateway defect.

### D10 — The owner-pause amendments, round 2: the security context, the store's governance class, the deployment diagram, and the IdP secret's file spelling

The owner reviewed the package at the PROCESS step-3c pause and requested four
amendments; this decision records how each folds in, and the mid-round correction
that shapes two of them. Everything here extends existing decisions and existing
SIA rows — no new threat row was needed (the owner's amendments are requirements
statements on surfaces the SIA already prices).

**The pod's security context (extends D1, priced into DT-EP6-1's control set).** The
contract gains a security-context section, and the delta's pod-contract requirement
gains the MUST clause and its scenario: `runAsNonRoot` with the image's fixed
uid/gid 10001 (the DCR store's file ownership depends on it — the assumption D5
already carries); `fsGroup` 10001 on the store's volume (a world-writable mount is
the tamper path the assembly must refuse); `allowPrivilegeEscalation: false`;
all capabilities dropped — viable because nothing in the pod binds a privileged
port, stated as the assumption that keeps the drop total (both the router's public
port and the gateway's container-internal port are unprivileged); a read-only root
filesystem with `emptyDir` for the router's temp and log paths (the gateway writes
nothing but the DCR store); and the runtime-default seccomp profile. These are
requirements the assembly preserves, not preferences — the mis-assembly threat
(DT-EP6-1) prices their relaxation exactly as it prices a published gateway port or
a dropped store volume, so the amendment extends that row's control set rather than
adding a row.

**The store's governance and storage-class statements (extends D1 and D8, priced
into DT-EP7-1's row).** The contract's volume-mount section and the delta's
mount clause gain three statements. (a) The store's backing MUST be a cloud-backed
persistent-volume storage class — stated by its properties: the data survives node
loss and rests in a tenant-governable resource — never node-local ephemeral storage.
(b) Backup/export is deployment-owned, and the component's shape makes it cheap: the
store is a single human-readable JSON file written by atomic replace, so a
point-in-time copy is a consistent export — no gateway cooperation, no new API. (c)
The no-secret-content rule is stated as load-bearing: the store MUST NOT gain
secret-class content without re-opening its boundary analysis — the property that
makes the external governance reader class (storage-layer RBAC holders, backup
destinations) cheap to admit; the same logic carries the future wrapped-CEK file
(D8's firm planned step), ciphertext by design, named as the store volume's future
second resident. The SIA prices the reader class as a bounded extension inside
DT-EP7-1's row — the store's no-secret property is the control — not a new threat.

**The deployment diagram (a task, D1's contract document).** The contract gains a
renderer-independent ASCII diagram inside the markdown — no image dependencies, no
toolchain, readable as plain text in any diff. It must show: the pod as one box (the
router container with nginx, the versioned conf mounted read-only, the single public
port at the cluster-ingress TLS boundary; the sibling-localhost leg
`127.0.0.1:8091`; the gateway container, uid 10001, one internal port unpublished);
the mounts (the DCR store's durable volume — the cloud-backed class, the pod's one
state mount, the future wrapped-CEK file named as its future second resident; the
read-only key-file mounts); the secret paths (KeyVault/Secrets Manager → K8s Secrets
→ env vars or mounted files → the signing keyset, the custody keyset, and the IdP
client secret); the neighbors (the harness via ingress; DIAL Core with the MCP data
path drawn bypassing the gateway entirely; the identity provider with its
back-channel legs); the reserved `source: kms` as a dashed future arrival; and the
stated assumptions drawn where they live (sibling-localhost, single-replica, port
non-publication, the security-context controls). Task 5.2 carries it.

**The IdP client secret's file spelling (extends D2's seam to the one secret
outside the keysets, priced into DT-EP4-4's row).** The identity-leg requirement
(the confidential client) gains the delivery clause: the secret MAY be delivered by
environment variable (`IDP_CLIENT_SECRET`) or by file — **`IDP_CLIENT_SECRET_FILE`**,
the exact name — a read-only mount, the shape a mounted Secret file takes; exactly
one of the two configured, both configured refusing startup naming both settings
(the keyset seam's mixing-refusal style, D2); a file source read once at startup,
an unreadable path refused loudly naming the path never the content (the keyset
seam's `file`-source discipline, D2, carried to the one secret outside the keysets).
The name follows the seam's `ref` discipline — the env-var spelling names the value,
the `_FILE` spelling names the path that carries it — and is stated in the delta and
in the `.env.example` task's placeholder. The at-rest footprint is DT-EP4-4's class
(same boundary price, new location), so that row's wording extends to cover it
rather than a row being added. The pod contract's classified env-var surface table
gains the new setting.

**The owner's mid-round correction (recorded as ruled): no preference language, and
requirements named, not products.** The owner corrected the amendment round's first
draft: the contract does not *recommend* a delivery spelling — DevOps know K8s and
choose the how in their managed cluster and cloud; the contract's job is to declare
(a) what the component REQUIRES and (b) HOW it CAN be delivered. Applied: the
contract's secret-delivery content states the requirements only (run-time-only
delivery, never baked, never in the repository; two spellings per secret with
exactly one configured; read-only mounts; the uid-10001/fsGroup ownership
constraints) and the options neutrally — "environment variable or mounted file, both
supported" — with no preference, no "recommended", no default-shape guidance,
anywhere (contract, delta, design, release notes). The component's honest position:
the two spellings are equivalent to the gateway; the boundary price is the
deployment's. The same filter applies to the storage-class statement: the
cloud-backed persistent-volume requirement stays a REQUIREMENT (the component
requires the data to survive node loss and to rest in a tenant-governable resource),
but no specific class, mechanism, or product is named — managed disks, file shares,
CSI drivers, backup tooling, and destinations are DevOps's choice; the contract
names the requirement, not the product.

**Pushback summary** (the owner asked for disagreements explicitly; each is argued in
place): **P1** — the JWKS "all kids" rationale is imprecise, the full-window
publication is a simplicity choice with a priced cost, the sharper split rejected
with reasons (D3); **P2** — pre-publish is absent from the rulings but required by
their own acceptance, made normative (D3); **P3** — the drill is extended to the
custody keyset beyond the ruling's signing-`kid` wording, argued (D7); **P4** — the
Alpine precedent verified against the sibling adapter repo, with the 3.11-vs-3.12
and builder-toolchain nuances recorded (D5, and the SIA's gap list); **P5** — the KMS
split inversion examined and concurred with reasoning, not assumed (D8). No ruling
was found *wrong*; two were found *incomplete* (P2, P3) and one *imprecise in
rationale* (P1), each carried to its consequence rather than silently complied with.

## Security impact analysis

Per `docs/security-analysis.md` §4, this change is a **change on existing surfaces
that alters the system's secret-material handling**: it adds no endpoint, grant type,
or trust boundary, but it changes which key material the process holds and for how
long (active + retained entries), where key material rests before the process holds
it (injected env vars and — new — read-only key files on mounts), how the JWKS
publishes, and the deployment boundary's shape (one pod, sibling localhost). EP4 (the
keys) is therefore enumerated near-completely — it is the change's center; EP1, EP6,
and EP7 carry delta tables for what the change alters on them (the verification and
JWKS surface, the router-as-sibling and the pod assembly, the store's mount). EP2
(the CIMD fetch), EP3 (the pages), and EP5 (the server-to-server legs) are untouched
— no table, covered by the invariant ruling table. Mis-use cases are marked
**[mis-use]**.

### 1. Change description

*Business:* the deployment unit becomes the pod this repository contracts for
(D1, D5, D6, D9); routine key rotation stops being a mass signout for both keys, with
the source seam (`env`/`file`/reserved-`kms`) carried per entry so a future KMS
arrival is a rotation (D2, D3, D4); rotation is proven live, with the emergency cut
rehearsed beside the routine drain (D7); and the standing disclosures are amended to
be honest under both ruled end states (D8).

*Implementation shape:* the signing keyset setting (structured entries, compat
singular) validated at startup — exactly one active, retained entries, duplicate
derived-`kid` refusal, `kms` refused naming the gap, `file` sources loaded once and
loudly on failure (`gateway/settings.py`, `gateway/keys.py`); `decode_own_token`
selecting by `kid` within the keyset (`gateway/tokens.py`) and `decode_code`
verifying codes through the same keyset selection (`gateway/codes.py` — its own
verification path today, no `kid` selection); the JWKS as every
entry's public half, active first (`gateway/keys.py`), served by the JWKS route
(`gateway/routes.py`); the custody keyset's
structured spelling beside the flat one, decrypt by the envelope's key-id across
active-or-retained, seal under the active key only (`gateway/custody.py`,
`gateway/settings.py`, the call sites in `gateway/token.py`, `gateway/runtime.py`);
the image on `python:3.12-alpine` with uid 10001 and the pip-removal discipline
carried (`Dockerfile`); the composed stack in the pod shape via the shared network
namespace, the nginx gateway upstream at `127.0.0.1:8091` (`docker-compose.yml`,
`router/nginx.conf`); the IdP client secret's file spelling — `IDP_CLIENT_SECRET_FILE`,
exactly one of the two spellings configured, the both-configured refusal, the
read-once file loader with its path-naming refusal (`gateway/settings.py`, the
identity-leg requirement's amendment); the contract document (`docs/pod-contract.md`)
with its security-context section (runAsNonRoot/uid-gid 10001, fsGroup 10001 on the
store's volume, no privilege escalation, all capabilities dropped, read-only root
with `emptyDir` for the router's temp/log paths, runtime-default seccomp), the
store's governance/storage-class statements (the cloud-backed persistent-volume
requirement by its properties, the deployment-owned atomic-replace export story, the
load-bearing no-secret-content rule), and the renderer-independent deployment
diagram; the classified
env-var surface and rotation procedures in the configuration reference and
`.env.example`; the disclosure amendments and the threat-model update
(`docs/threat-model.md`); the drill's scripted legs and captured evidence
(`docs/evidence/c3/`, the probe battery's extension). No change to the token
lattice's TTLs, the flow, the consent checkpoint, the custody envelope's layout, or
Core.

### 2. Impact level, with reasons

**Medium.** The sensitive assets involved are the deployment's most sensitive
material — A1 (the signing key, whose holder mints any identity) and A2 (the custody
key, whose holder with a recorded-token archive replays archived users' provider
identity) — and the change's direction on both is **mixed, honestly**: narrowing in
the fail-closed `kms` refusal, the pre-publish rule, the sibling-localhost leg (one
internal network hop removed), and the cleared image debt; **widening** in the
retained-key windows (a stolen superseded signing key stays hot at Core, and a
stolen superseded custody key stays able to decrypt, each for up to the drain
window — the priced cost of routine rotation, DT-EP4-2/DT-EP4-3) and in the new
at-rest footprint of file-sourced keys (DT-EP4-4). What keeps the level at Medium
rather than High: no new endpoint, no new trust boundary, no new grant type, no new
credential — the same two keys under a keyset discipline, inside the same
host/pod-injection boundary the model already prices (RES-13's class), with the
immediate cut preserved as the answer to every widening. The level sets the security
review gate's depth: a full-depth review of the keyset mechanics (the loaders, the
kid selection, the JWKS shape, the seal/decrypt split), the pod-contract statements
against the mis-assembly shapes, and the drill's evidence against its scenarios —
with the falsification pass aimed at exactly the claim that the retained-key windows
are priced and bounded as designed.

### 3. Invariant ruling table

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | **Preserved** | The flow, the credential call, and the data path are untouched; the keyset changes which key signs the gateway's own tokens, never what any leg carries upstream; the custody envelope's carrier and layout are unchanged (the key-id selects the entry; the envelope's shape is byte-identical) |
| 2 | The upstream PKCE verifier never leaves Core | **Preserved** | Nothing on the upstream leg changes; the mint's inputs and outputs are the same claims under a different key when rotated |
| 3 | Per-user credential isolation | **Preserved** | The custody seam's subject check is untouched and per-entry (the envelope's embedded `sub` against the signed subject, whichever entry's key-id the header names — a transplanted header fails the tag under the key it names, so the keyset widens nothing); the mint's `sub` binding is unchanged; the retained custody key decrypts only blobs already bound to their subject |
| 4 | DIAL authorization applies to every toolset call | **Preserved** | The token's claims, Core's per-call authorization, and the flow's reads are unchanged; a rotated key changes the token's `kid`, never its `sub` or claims path; the JWKS's per-`kid` publication changes nothing about which tokens Core accepts beyond which `kid`s it can verify |
| 5 | No credential in logs, argv, or error messages | **Preserved** | Keyset startup errors name entries by configured id and path, never material, fingerprint, or file content — the existing loader discipline carried per-entry, and the new surfaces (the keyset entries, the file sources, the IdP client secret's `IDP_CLIENT_SECRET_FILE` source) are named inside this reason; the drill's evidence rule is spec'd (kids, key-ids, verdicts, audit records, JWKS snapshots only — never token strings or key material); the contract's classified surface states the secret class's never-logged rule for the new file sources |
| 6 | No hardcoded credentials in the repository | **Preserved** | The keyset documents are structure (ids, sources, refs, roles), never material; `.env.example` gains placeholder-shaped examples only; the pod contract names secret classes, never values; the image bakes no secret-class value (a spec'd scenario) |
| 7 | The signing key is IdP-grade secret material | **Preserved with a disclosed bound** | Strengthened within the ruling — never committed, never logged, `kid`-published, **rotatable — now proven by rehearsal** (the drill, this change's own gate) instead of documented-only; the disclosed bound moves: the key's custody is the injection path (env var or read-only key file on the pod's mounts) rather than only the host `.env`, and the retained-entry window is the priced addition (RES-13 re-worded, RES-2's amendment, DT-EP4-2) |

### 4. Delta threat tables, per touched entry point

#### EP4 — the keys: the keyset, the sources, the retained entries

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP4 (the retained signing key, at rest or in memory) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Retained signing key extends the stolen-key mint window | A1 (the superseded private key); every identity on the deployment (the mint it forges) | C, I | The priced cost of routine rotation (D3's honesty): pre-change, a stolen signing key's mints die at the rotation — the old `kid` vanishes from the JWKS and Core refuses within its cache; post-change, a superseded key **retained** for the drain window keeps its `kid` published, so the thief's mints verify at Core for up to the whole window (default: the refresh TTL) instead of ≤ cache + access TTL. The thief is the same attacker RES-13/T4-1 already price (host/injection-path read); the change extends *how long the stolen material stays useful*, not who can steal it. Bounded by: the window is operator-declared and ends at the drain bound; the **immediate cut** is available at any moment (remove the entry — the JWKS drops the `kid`, Core refuses within cache + access TTL, the gateway refuses at next verification); and the drill rehearses the cut so the response is proven, not documented. Accepted as the priced trade of "routine rotation must stop being a mass signout" — the SIA's explicit pricing the ruling demands. |
| EP4 (the retained custody key, at rest or in memory) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Retained custody key extends the decrypt window | A2 (the superseded custody key); the carried provider session refresh tokens of outstanding refresh sessions | C (the blobs' contents), I (the provider identities they authenticate as) | The custody twin of the row above, with its own blast radius (RES-21 part ii's conjunction): a stolen retained custody key, with a recorded archive of refresh tokens, decrypts their carried provider session refresh tokens and replays each user's provider identity until that provider session dies — pre-change the hard cut killed the decrypt ability at rotation; post-change it lives for the drain window. The conjunction is unchanged (the key alone mints nothing; the token archive alone is inert ciphertext); the change extends the window in which the conjunction can be assembled. Bounded by: the same operator-declared window and immediate cut (remove the entry — outstanding blobs refuse at next presentation, the custody refusal class); the envelope's subject binding (a decrypted blob is bound to its signed subject, so the replay is per-user, never cross-user); and the self-shortening overlap (every presenting session re-seals under the active key, shrinking the retained-key-bearing blob population at each refresh). Accepted as the priced twin of the row above. |
| EP4 (a `file`-sourced key or secret, its read-only mount) | Information Disclosure → Information Disclosure at Rest | Key or secret file read off its mount | A1/A2 (the entry's material at rest, before the process loads it); the IdP client secret (the one secret outside the keysets, under its `IDP_CLIENT_SECRET_FILE` spelling) | C | The new at-rest footprint: file-sourced material — a keyset entry's key, or the IdP client secret under its file spelling — rests on a mount where the injection-path boundary — not the gateway — governs readability. Whoever reads the mount holds the material, the same holder class the env-var surface prices (the pod spec, the node, `/proc` environ); the file adds the volume/node reader for that entry. Not a new boundary — the same host/pod class RES-13/RES-5 price — but a new *location* the contract must name so the operator knows where the boundary sits; the IdP secret's file spelling is this row's class exactly (same boundary price, new location — the amendment that added it extended this row rather than adding one). Bounded by: the contract's read-only-mount statements for every file-sourced secret (a K8s Secret mount's default ownership is the cluster's, stated); the startup discipline (load once, never log, refuse loudly on an unreadable path); and the mount's read-only-ness being stated as the assumption the assembly preserves (a writable key mount is a tamper path priced below, EP6's mis-assembly row). |
| EP4 (the keyset document, at parse) | Injection | Forged or malformed keyset document | A1/A2's loading path (the process's key selection); the startup refusal path | I | A keyset document is operator-supplied JSON parsed at startup inside the trust boundary being configured — the settings-injection class the model already prices (T5-3's family), with the new surface being the entry schema. A malformed document refuses startup loudly (the existing validators extended per-entry); a *forged* document means the injection path is already compromised, which is the boundary's own price, not the parser's. Bounded by: per-entry validation with named refusals (zero-active, multi-active, duplicate derived `kid`, unreadable file, reserved `kms`), no material in any error, and the derived-`kid` duplicate check — the one check that makes the document's claims about *how many keys it holds* checkable rather than trusted. |
| EP4 (the retained-entry lifecycle, operator behavior) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Indefinite retention **[mis-use]** | A1/A2 (the retained entries' windows, kept open) | C, I | The mis-use of the retention mechanism: an operator who rotates routinely but never removes retained entries accumulates a growing set of hot superseded keys — each one a live stolen-key window (the two rows above), and the keyset's memory/at-rest footprint grows with them. Nothing forces removal; the drain bound is declarative. Bounded by: the operator reference's procedure stating removal as the rotation's closing step (the drill's own final leg removes the entry — the rehearsed procedure includes the cleanup); the startup validation refusing duplicate derived kids (the accumulation stays honest about its size); and D3's one-keyset-one-JWKS rule keeping the published set exactly as large as the configured one — an operator reading the JWKS sees every retained `kid` the deployment is carrying. The residual is operator discipline, stated in the contract and the reference, re-opened by an automated-rotation future (which would carry its own removal scheduler). |
| EP4 (the `kms` reserved value, at startup) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Silent source fallback **[mis-use, falsified by design]** | A1/A2's sourcing (the entry's claimed protection) | I (the operator's security model) | The falsification target the fail-closed refusal exists to kill: a deployment configuring `source: kms` today believes it holds KMS-protected key material; a gateway that silently ignored the value (or fell back to env) would let that belief run a process whose key is actually env-injected — a security *model* compromise, not a key compromise, and exactly the failure the ruling's "cleanly rejected, naming the gap" forbids. Mitigated by construction: the startup refusal names the gap and the implemented sources; the reserved value is schema-carried so the future real `kms` is additive, never a reinterpretation of the refusal. |

#### EP1 — the AS surface: verification and the JWKS under the keyset

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP1 (E8, the JWKS; E4 verification) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Crafted JWT steering verification across the keyset | A3/A4's verification basis (which key verifies what) | I | T4-7's class, extended to the keyset: a crafted token's header tries to steer verification — a `kid` naming another entry, embedded `jwk`/`x5c` material, an `alg` confusion. The pinned-algorithm requirement's controls carry unchanged and per-entry: the algorithm is pinned (all entries RS256 — the keyset adds no algorithm), embedded header material is ignored, and the `kid` **selects within the startup-fixed keyset** — an unknown `kid` (including a removed retained entry's, the immediate cut's own verification-side effect) refuses as not issued by this gateway. The provider leg's resolution rules are untouched (its own key set, its own pin). Mitigated — the existing M20 discipline, re-stated per-entry by this change's amendment; no new residual. |
| EP1 (E4, the mint during a rotation window) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Rotation-window verification gap at Core | A3's usability at Core (freshly minted tokens 401ing until the cache turns) | A | The availability shape D3's pre-publish rule exists to close: without it, every token minted in the first Core-JWKS-cache-window after a key activation 401s at Core — a rotation-visible refusal burst, and (mis-used) a rotation scheduled at the wrong moment degrades every new session for the window. Mitigated by the pre-publish rule (the new `kid` published ≥ the cache window before it signs — a spec'd scenario), rehearsed by the drill's "no refusal attributable to the rotation" verdict; the residual is the operator's declared cache bound being wrong (a Core-side cache TTL longer than declared), which the drill's observed wait bounds and the open question records. |

#### EP6 — the front router: the pod shape and the assembly it assumes

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP6 (the pod assembly, from the contract) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Pod mis-assembly breaks the stated assumptions | A13 (the peer binding, the routing, the mounts); A1/A2's injection paths; the DCR store's durability | Access, C, A | The threat the pod contract exists to bound: DevOps assemble the pod from the contract, and the assembly can silently lose what the composed shape carries — the gateway port exposed past the pod (the `X-Real-IP` authority broken, T6-4's class relocated: a request that never crossed the router carries a caller-chosen peer identity, and the per-source rate limit becomes a bound the caller sets); the DCR volume dropped (every restart silently invalidates every registered client — the named requirement's own wound) or its backing downgraded to node-local ephemeral storage (the durability requirement satisfied in code, lost in substance — the storage-class requirement's own wound); the conf mounted writable or replaced (T6-1's router-tamper class); the key-file mounts omitted or mis-permissioned (the `file`-source entries refuse startup — loud, not silent); the security context relaxed — a root-running or privilege-escalating container, a capability kept, a writable root filesystem, a world-writable store mount (the fsGroup/uid-10001 ownership the store's integrity leans on refused) — each one a stated control dropped, the same class as the port and the volume; the pod scaled horizontally (D9's split-state confusion). Deployment-owned surfaces; the controls are this repo's to *state* and DevOps' to *preserve*: the contract's explicit assumption statements — the security-context section's controls among them (runAsNonRoot with the fixed uid/gid 10001 the store's ownership depends on, fsGroup 10001 on the store's volume, no privilege escalation, all capabilities dropped on the stated no-privileged-port assumption, read-only root with `emptyDir` for the router's temp/log paths, runtime-default seccomp) — the startup refusals that make omission loud where the gateway can see it (key files, store path), the probe battery and restart-survival acceptance that make the composed stand-in prove the shape, and the DevOps review's explicit confirmation — the acceptance evidence the requirement names. Accepted as the deployment boundary's standing price (the compromise table's host row, re-shaped for the pod), with the contract as the named control and the review as its gate. |
| EP6 (the router↔gateway leg, now pod-localhost) | Interception → Eavesdropping | Cleartext on the sibling leg | A3/A5 (the proxied AS traffic between router and gateway) | C | Narrowing, tabled for the walk's honesty: the router→gateway hop ran on the compose network (a sniffable plain-http leg for any network peer, RES-19's class); under the shared namespace it is loopback inside the pod — a network peer can no longer reach it at all. The leg stays plain http (no TLS within the pod — the traffic never leaves the pod's network namespace), which is the same accepting class as loopback everywhere; the *peer population* shrinks from "the compose network" to "the pod's own containers and the node." Mitigated by construction (the namespace sharing is the compose stand-in's own mechanism); the node remains the boundary the compromise table prices. |

#### EP7 — the DCR store: the pod's one mounted state

| Entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| EP7 (the store's mount, in the pod assembly) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Omitted or mis-mounted store volume | A10 (the registered clients); A5 (future codes deliverable to registrations the store carries) | I, A | The named requirement's threat, stated where it lives: a pod assembled without the store's mounted volume satisfies the durability requirement's *code* (the path exists) while losing its *substance* (the path is ephemeral) — every restart invalidates every registered client silently, the exact wound the roadmap's owner-catch recorded. Bounded by: the contract's volume-mount section naming the mount as a MUST (the deliverable DevOps review accepts against); the restart-survival acceptance running on the pod-shaped stack (a registered client's cached id keeps working across a restart — the omission cannot survive the acceptance); and the existing corrupt-store and load-path refusals (an empty-but-present store self-heals via re-registration, the spec'd behavior). The store's own host/volume boundary is unchanged from RES-5's price — the same readers, the same no-secret content; the change re-states it for the pod and makes its omission visible. The governance statements extend the row without a new threat: the cloud-backed persistent-volume requirement (the data survives node loss, rests in a tenant-governable resource — never node-local ephemeral storage) is the durability requirement's own substance, and the external governance reader class it admits — storage-layer RBAC holders, backup destinations reading a point-in-time copy, which the store's atomic-replace single-file shape makes a consistent export with no gateway cooperation — is a **bounded reader extension of the same boundary**: the store's no-secret-content property is the control that makes those readers cheap to admit (a reader of the store holds registrations, never credential material), and the property is stated load-bearing — the store MUST NOT gain secret-class content without re-opening this boundary analysis. The future wrapped-CEK file (D8's firm planned step) is the volume's named future second resident, ciphertext by design — the same logic, stated now so the reader class survives its arrival. |

### 5. Mitigations per threat, in the fixed control-category order

Homes: **spec** = this change's delta spec (gateway-owned, normative); **repo** =
committed material; **deployment** = named with its owner. Every category appears for
every threat.

**DT-EP4-2 Retained signing key extends the stolen-key mint window**
1. Reduce Attack Surface — the retained set is exactly the configured one, published
   as-is in the JWKS (one keyset, one document — no hidden retained key can exist)
   (spec).
2. Isolation — the retained entry's material sits in the same injection-path
   boundary as the active one's (env var or read-only key file); no new boundary is
   drawn, and none is claimed (spec — the sources; repo — the contract's mount
   statements).
3. Authentication — not applicable, because the threat is stolen *material*, not a
   forged caller: the mint the stolen key produces is correctly signed by a real key,
   and no authentication check at the gateway distinguishes it (the boundary is the
   injection path's, priced at RES-13).
4. Authorization — not applicable, for the same reason: a minted token carries
   whatever claims the thief writes; Core's per-call authorization runs on those
   claims exactly as for honest tokens (the never-cut 4 discipline, unchanged).
5. Data Protection — **the window and the cut**: retention is operator-declared,
   bounded by the drain window (the refresh token's non-sliding absolute expiry),
   and removable at any moment — removal drops the `kid` from the JWKS and the entry
   from the keyset, and Core refuses the thief's mints within its cache window plus
   the access TTL (spec — the keyset requirement's removal clause and scenarios).
6. Anti-Injection — not applicable: the threat holds no injection vector; the
   stolen key signs well-formed tokens by construction.
7. Anti-DoS — not applicable: the threat mints tokens at whatever rate it pleases
   against *Core*, and the gateway is not on that path; the gateway-side surfaces
   the thief could touch keep their existing limits.
8. Detective controls — the JWKS's `kid` set is the operator's live inventory of
   retained keys (readable at any moment), and the drill's evidence discipline keeps
   each rotation's `kid` set on record (spec — the JWKS shape; repo — the drill's
   evidence).
   **Disposition: accepted as the priced trade of routine rotation — the window is
   the cost, the immediate cut is the control, the drill proves the cut.**

**DT-EP4-3 Retained custody key extends the decrypt window**
1. Reduce Attack Surface — retained custody entries exist only in the structured
   spelling (the flat compat shape cannot carry them), so an overlap window is
   always an explicit operator act (spec — the custody amendment's compat scenario).
2. Isolation — the custody key stays separated from the signing key (its own keyset,
   its own entries); the retained entry's boundary is the injection path's, as the
   active one's (spec, unchanged).
3. Authentication — not applicable, because the thief holds *material*, not a
   credential to present: the decrypt happens offline against recorded ciphertext;
   no gateway check is crossed (the conjunction is the archive plus the key, RES-21's
   own price).
4. Authorization — not applicable: the decrypted blob is bound to its signed subject
   (the seam's check — per-entry, unchanged); the replay is per-user at the
   provider, and no gateway authorization leg is involved.
5. Data Protection — **the window and the cut, custody side**: retention bounded by
   the same drain window; removal refuses outstanding blobs at next presentation in
   the custody refusal class; each presenting session re-seals under the active key,
   shrinking the retained-key-bearing population at every refresh (spec — the
   custody amendment's drain and cut scenarios).
6. Anti-Injection — not applicable: the blob's integrity is the AEAD's (the tag
   fails under a transplanted header whichever key it names); there is no
   gateway-facing injection surface.
7. Anti-DoS — not applicable: an offline decrypt costs the gateway nothing.
8. Detective controls — the custody refusal class on the trail distinguishes a
   removed-key presentation from a provider event (the existing closed reason
   table), so the cut's effect is diagnosable as the cut (spec, unchanged —
   re-stated for the removal path).
   **Disposition: accepted as DT-EP4-2's custody twin — the same window, the same
   cut, re-pricing RES-21 part ii.**

**DT-EP4-4 Key or secret file read off its mount**
1. Reduce Attack Surface — file sources are per-entry and optional: a deployment
   that injects everything by env var has no key files at all, and the IdP client
   secret's file spelling is optional the same way — one secret, two spellings,
   exactly one configured (spec — the sources; the identity-leg amendment's
   delivery clause).
2. Isolation — the file mounts are read-only and named in the contract — every
   file-sourced secret's, the keyset entries' and the IdP client secret's alike;
   the store's read-write mount and the secret files' read-only mounts are stated
   as separate mount classes the assembly preserves (repo — the contract; spec —
   the pod-contract requirement's mount clause).
3. Authentication — not applicable, because the reader of a mounted file crosses no
   authentication surface: the mount's permissions are the boundary (the node's, the
   cluster's Secret mount ownership).
4. Authorization — not applicable: file readability is the OS's and the mount's
   decision; the gateway's authorization surfaces are not on this path.
5. Data Protection — the file is read once at startup into the process's custody;
   the startup path never logs content or fingerprint, and an unreadable file
   refuses loudly naming the path (spec — the keyset requirement's file scenarios;
   the identity-leg amendment's file scenarios for the IdP secret's spelling).
6. Anti-Injection — not applicable: the file's *content* is parsed as key material
   and refused on any malformation; a "crafted file" is an unparseable one and fails
   closed.
7. Anti-DoS — not applicable: a startup-time read with no request-driven path.
8. Detective controls — the startup refusal itself is the detective control: an
   unreadable, unparseable, or wrongly-permissioned-by-omission file surfaces as a
   named, loud failure, never a silent downgrade (spec).
   **Disposition: mitigated to the injection-path boundary's existing price
   (RES-13's class, re-stated for the new location); no new residual — the location
   is new, the boundary class is not.**

**DT-EP4-5 Forged or malformed keyset document**
1. Reduce Attack Surface — the document is structure only (ids, sources, refs,
   roles); material never rides it, so the document's compromise surface is the
   loading decision, not the material (spec — the seam; repo — the settings).
2. Isolation — the document is parsed at startup inside the trust boundary being
   configured — operator input at the issuer setting's own trust level, the
   direct-configuration mode's own class (spec-adjacent, repo).
3. Authentication — not applicable: a forged document means the injection path is
   compromised — the boundary's own price; the parser authenticates nothing and
   should not (it would be a false comfort).
4. Authorization — not applicable: the document grants nothing; it selects keys.
5. Data Protection — the per-entry named refusals (zero-active, multi-active,
   duplicate derived `kid`, unreadable file, reserved `kms`) make every loadable
   claim checkable, and no error carries material (spec — the keyset requirement's
   validation scenarios).
6. Anti-Injection — the duplicate-derived-`kid` refusal is the anti-injection row:
   the document cannot hold two entries under one `kid` — the same key claimed
   twice, or a truncated-hash collision between distinct keys — so its `kid` set
   stays an honest count of its entries (spec).
7. Anti-DoS — not applicable: startup parse, bounded size, no request path.
8. Detective controls — every refusal is loud and named; a mis-loaded keyset is a
   container that does not start, which is the most detectable state a gateway has
   (spec).
   **Disposition: mitigated — the existing settings-validation discipline, extended
   per-entry.**

**DT-EP4-6 Indefinite retention [mis-use]**
1. Reduce Attack Surface — the JWKS publishes exactly the configured set: an
   accumulating keyset is visible in one document, not hidden in a drawer (spec —
   the JWKS shape).
2. Isolation — not applicable: the mis-use is operator behavior, not a component
   boundary; no isolation control bounds an operator's own configuration choices.
3. Authentication — not applicable: the operator is legitimate by the mis-use's
   definition.
4. Authorization — not applicable: retention grants no access; it extends windows.
5. Data Protection — the operator reference's rotation procedure states removal as
   the rotation's closing step, and the drill's own final leg removes the entry —
   the rehearsed procedure includes the cleanup (repo — the reference; spec — the
   drill's drain-completion clause).
6. Anti-Injection — not applicable.
7. Anti-DoS — not applicable: a growing keyset costs bytes at startup and one JWK
   per entry in a document; no request path scales with it.
8. Detective controls — the JWKS's `kid` inventory (above) plus the drill evidence's
   per-rotation record make accumulation visible to anyone who looks (spec; repo).
   **Disposition: accepted as operator discipline, stated in two committed places —
   re-opened by an automated-rotation future.**

**DT-EP4-7 Silent source fallback [mis-use, falsified by design]**
1. Reduce Attack Surface — the reserved value is refused, not ignored: there is no
   configured `kms` that reaches a running process (spec — the refusal scenario).
2. Isolation — not applicable: the threat is a wrong belief about sourcing, not a
   component crossing a boundary.
3. Authentication — not applicable: no credential is presented.
4. Authorization — not applicable: no access is gained; the compromise is the
   operator's security model, and the refusal restores it.
5. Data Protection — the refusal's message names the gap and the implemented
   sources, so the operator learns what is and is not protected (spec).
6. Anti-Injection — not applicable.
7. Anti-DoS — not applicable: a startup refusal is the intended stop.
8. Detective controls — the refusal is the detection: a deployment that believed it
   had KMS finds out at the container's first start, in the log, by name (spec).
   **Disposition: mitigated by construction — the falsification target exists so the
   review can check the refusal actually fires.**

**DT-EP1-10 Crafted JWT steering verification across the keyset**
1. Reduce Attack Surface — the keyset adds entries, not algorithms: every entry is
   RS256 ≥ 2048 bits, so no entry widens the algorithm set the pin covers (spec —
   the keyset requirement's parse refusals).
2. Isolation — verification selects within the startup-fixed keyset; no fetch, no
   provider-side lookup, no header-carried material (spec — the inbound-tokens
   amendment).
3. Authentication — **the control's home**: the signature check is the
   authentication, per entry, under the pinned algorithm; an unknown `kid` — a
   removed retained entry's included — never resolves (spec).
4. Authorization — not applicable: verification precedes authorization; the verified
   token's authorization legs are unchanged.
5. Data Protection — not applicable: no secret is at stake in the verification
   selection itself.
6. Anti-Injection — embedded `jwk`/`x5c` ignored (the existing pinned-key rule,
   unchanged); the `kid` is a selector compared against the keyset's ids, never
   executed or fetched (spec, unchanged).
7. Anti-DoS — the keyset's size is startup-fixed and small; the selection is a
   constant-time map lookup (repo).
8. Detective controls — refusals land in the existing fixed-vocabulary trail (the
   `invalid_grant`/token classes, unchanged).
   **Disposition: mitigated — M20's discipline re-stated per-entry; no new residual.**

**DT-EP1-11 Rotation-window verification gap at Core**
1. Reduce Attack Surface — the pre-publish rule means no token is ever minted under
   a `kid` unpublished for at least the cache window (spec — the pre-publish
   scenario).
2. Isolation — not applicable: the gap is a cache-timing fact between two
   cooperating components; no boundary is drawable around it.
3. Authentication — not applicable: the tokens are honestly signed; the failure is
   the verifier's stale cache, not a forged caller.
4. Authorization — not applicable: the refusal is a 401 at Core's validation layer,
   upstream of any authorization decision.
5. Data Protection — not applicable: no material is exposed; the shape is
   availability.
6. Anti-Injection — not applicable.
7. Anti-DoS — **the control's class**: the refusal burst is bounded by the cache
   window and closed by the rule; the drill's verdict ("no refusal attributable to
   the rotation") is the acceptance that proves it (spec — the drill requirement).
8. Detective controls — the drill's evidence records the wait and the verdict; a
   rotation that skipped the wait would show its refusals there (spec; repo — the
   evidence discipline).
   **Disposition: mitigated — the pre-publish rule; the residual is a wrongly
   declared cache bound, recorded as an open question.**

**DT-EP6-1 Pod mis-assembly breaks the stated assumptions**
1. Reduce Attack Surface — the contract's statements are explicit (port
   non-publication, the mounts, the security context, the single replica), so an
   assembly that drops one deviates from a named line, not from an unstated custom
   (repo — the contract; spec — the pod-contract requirement).
2. Isolation — the pod's network namespace is the isolation unit: the gateway's
   port reachable only within it, the sibling leg loopback-only (spec — the
   requirement's sibling-localhost clause; the narrowing row DT-EP6-2); the
   security-context controls are the container-isolation unit — runAsNonRoot with
   the fixed uid/gid 10001, no privilege escalation, all capabilities dropped on
   the stated no-privileged-port assumption, runtime-default seccomp (spec — the
   requirement's security-context clause; repo — the contract's section).
3. Authentication — the peer-identity authority: the router remains the only
   accepted source of the forwarded client address, and the gateway port's
   non-reachability is what makes it so (spec — the requirement's port clause;
   unchanged, re-stated).
4. Authorization — not applicable: the mis-assembly's access gains run through the
   router or the mounts, not through a gateway authorization leg.
5. Data Protection — the store's no-secret content, the secret files' read-only
   mounts, and the ownership controls the store's integrity leans on (fsGroup
   10001 on the store's volume with the uid-10001 writer — a world-writable mount
   refused) are the data-protection halves of the assembly's duties, with the
   read-only root filesystem and the router's `emptyDir` temp/log mounts closing
   the writable-filesystem variant (spec — the mount and security-context clauses;
   repo — the contract).
6. Anti-Injection — the conf is mounted read-only from this repository's versioned
   file — the writable-mount variant of the mis-assembly is stated against (repo —
   the contract).
7. Anti-DoS — not applicable: the mis-assembly's availability shapes (the dropped
   store volume) are priced at DT-EP7-1.
8. Detective controls — the startup refusables (missing key files, unwritable store
   path) make the omissions the gateway can see loud; the probe battery and the
   restart-survival acceptance make the ones it cannot see fail a gate; the DevOps
   review's explicit confirmation is the human detective layer (spec — the
   requirement's scenarios).
   **Disposition: mitigated to the deployment boundary's standing price — the
   contract is the named control, the review its gate; the compromise table's host
   row is re-shaped, not removed.**

**DT-EP6-2 Cleartext on the sibling leg**
1. Reduce Attack Surface — **the narrowing**: the leg's peer population shrinks
   from the compose network to the pod's own containers and the node (the namespace
   sharing is the mechanism — spec — the sibling-localhost clause; repo — compose).
2. Isolation — loopback within the pod's network namespace (same as above; the
   control and the narrowing are one fact).
3. Authentication — not applicable: the leg carries proxied AS traffic whose
   authentication is the tokens' own, end-to-end.
4. Authorization — not applicable.
5. Data Protection — the traffic never leaves the namespace; where the deployment
   demands more, the node's and the pod's own isolation (or a future TLS-on-loopback
   decision, not priced here) is the deployment's (deployment — the node owner).
6. Anti-Injection — not applicable.
7. Anti-DoS — not applicable.
8. Detective controls — not applicable: the leg has no gateway-visible failure mode
   of its own.
   **Disposition: mitigated by construction — a strict narrowing of RES-19's class;
   the node remains the priced boundary.**

**DT-EP7-1 Omitted or mis-mounted store volume**
1. Reduce Attack Surface — the contract's mount section names the volume as a MUST
   with its path and class (read-write, the pod's one state mount, backed by a
   cloud-backed persistent-volume storage class stated by its properties — the
   data survives node loss and rests in a tenant-governable resource, never
   node-local ephemeral storage; the satisfying class and mechanism the
   deployment's choice) (repo — the contract; spec — the requirement's mount
   clause).
2. Isolation — the store's file discipline (atomic replace, owner-only mode
   best-effort, the corrupt-store refusal) is unchanged and carries into the pod
   shape (spec — the durability requirement, unchanged).
3. Authentication — not applicable: the store holds no credential and no
   authentication reads it.
4. Authorization — not applicable: the store's use-path is bounded by the
   redirect-URI validation against what it says (T7-1's existing price).
5. Data Protection — the store's no-secret content, unchanged, and now stated
   load-bearing: the property is what makes the external governance reader class
   (storage-layer RBAC holders, backup destinations reading a point-in-time copy —
   a consistent export by the store's atomic-replace single-file shape, deployment-
   owned, no gateway cooperation) cheap to admit, and the store MUST NOT gain
   secret-class content without re-opening this boundary analysis (spec — the
   requirement's governance clause; repo — the contract).
6. Anti-Injection — the load-path admission rule (the redirect-URI scheme check at
   load) is unchanged — a planted record still refuses startup (spec, unchanged).
7. Anti-DoS — not applicable: the omission is an availability wound, priced here,
   not a flood.
8. Detective controls — **the acceptance**: the restart-survival scenario on the
   pod-shaped stack (a registered client's cached id working across a restart) makes
   the omission fail the gate; the re-registration self-heal bounds the wound if it
   lands anyway (spec — the requirement's scenario).
   **Disposition: mitigated — the named requirement the stage exists to carry;
   RES-5's boundary price unchanged.**

### 6. The grouped mitigation list

The reviewed result — one mitigation to the threats it addresses:

1. **The keyset with per-entry sources and active/retained roles (spec — the
   signing-keyset requirement; the custody requirement's amendment; the
   inbound-tokens requirement's amendment):** exactly one active entry, retained
   entries for the drain window (bounded by the refresh token's non-sliding absolute
   expiry), sign/seal under the active key only, verify/decrypt with the active or a
   retained entry (`kid`/key-id selecting within the startup-fixed set), the JWKS
   publishing every `kid` with the active entry first, the duplicate-derived-`kid`
   refusal, the per-entry named startup refusals (zero-active, multi-active,
   unreadable file, reserved `kms` naming the gap), and the compat spellings (the
   singular signing setting; the flat custody document). Addresses DT-EP4-2
   (bounding), DT-EP4-3 (bounding), DT-EP4-4 (the sources), DT-EP4-5, DT-EP4-7,
   DT-EP1-10.
2. **The pre-publish rotation rule (spec — the keyset requirement's staged
   procedure):** a key about to become active has its `kid` published for at least
   the deployment's Core JWKS-cache window before it signs — the staged
   add-as-retained → wait → promote procedure with no third role. Addresses
   DT-EP1-11; carries the drill's "no refusal attributable to the rotation" verdict.
3. **The immediate cut, preserved and rehearsed (spec — the keyset requirement's
   removal scenario; the custody requirement's re-scoped hard-cut scenario; the
   drill requirement's emergency-cut scenario):** removing a retained entry at any
   moment of the window drops the `kid` from the JWKS (Core refuses within cache +
   access TTL; the gateway at next verification) and refuses outstanding custody
   blobs at next presentation. Addresses DT-EP4-2's and DT-EP4-3's control halves;
   the answer the priced windows get.
4. **The pod contract as a versioned repo document (spec — the pod-contract
   requirement; repo — `docs/pod-contract.md`):** the image facts (non-root fixed
   uid, one container-internal port, no baked secret, the scanner gate), the
   classified env-var surface, the nginx conf as the versioned mountable file with
   the sibling-localhost upstream, the volume mounts (the DCR store's as a named
   MUST with its cloud-backed storage-class requirement, deployment-owned export
   story, and load-bearing no-secret-content rule; read-only mounts for every
   file-sourced secret), the ports and probes, the required security context
   (runAsNonRoot/uid-gid 10001, fsGroup 10001 on the store's volume, no privilege
   escalation, all capabilities dropped, read-only root with `emptyDir` for the
   router's temp/log paths, runtime-default seccomp), the renderer-independent
   deployment diagram, and the single-replica
   assumption — accepted by DevOps review with explicit confirmation, executed
   locally by the namespace-shared composed stack. The secret-delivery statements
   are requirements-and-options only, stated neutrally: run-time-only delivery,
   two spellings per secret (environment variable or read-only mounted file, both
   supported) with exactly one configured, no preference between them — the
   deployment chooses, and the boundary price is the deployment's. Addresses
   DT-EP6-1, DT-EP7-1, DT-EP6-2's mechanism; carries DT-EP4-4's mount statements
   (with the identity-leg requirement's delivery clause carrying the IdP client
   secret's `IDP_CLIENT_SECRET_FILE` spelling and its refusals).
5. **The migration drill as an acceptance gate (spec — the drill requirement; repo —
   the scripted legs and `docs/evidence/c3/`):** each keyset rotated live with
   captured evidence, the negative control first, the drain and the emergency cut
   both rehearsed, the evidence carrying public facts only. Addresses DT-EP1-11's
   proof, DT-EP4-6's procedure-includes-removal, DT-EP4-2/DT-EP4-3's
   cut-is-proven; validates P2's and P3's extensions of the ruling.
6. **The disclosure amendments (repo — `docs/threat-model.md`, `docs/
   gateway-configuration.md`, `.env.example`):** RES-2's both-end-states wording,
   the trust-boundary statement re-stated for the pod, the rotation procedures with
   the declared cache bound, the KMS split recorded with its shapes. Addresses the
   roadmap's disclosure scope; lands the SIA's re-prices where the threat model
   owns them.

### 7. The threat-model delta

The entries `docs/threat-model.md` gains or changes (tasks, landed before the change
closes — the standing rule):

**ID numbering — unique across the live model.** This change's delta-threat IDs
continue the live model's sequences instead of restarting at 1, because the model's
citation surface is cumulative and the per-change restart-at-1 convention has already
produced a collision: RES-21 cites C1's DT-EP4-1 (the D5 amendment's priced trade),
and the dispositions table cites the consent-checkpoint change's DT-EP1-1 through
DT-EP1-7 and DT-EP1-9 — two unscoped same-numbered IDs from different changes would
be exactly the ambiguity task 1.3's freshness rule forbids. The mapping: EP4's rows
are **DT-EP4-2 through DT-EP4-7** (C1 owns DT-EP4-1), EP1's rows are **DT-EP1-10 and
DT-EP1-11** (continuing past DT-EP1-9; the unused DT-EP1-8 hole is not reused), and
EP6's/EP7's rows (DT-EP6-1, DT-EP6-2, DT-EP7-1) are the first of their entry points
in the model, so they stand as numbered. Every citation this change lands in the
model carries these IDs as written — a plain ID that resolves to exactly one design
§5 grid, no change-scope marker needed. Later changes continue the sequences from
wherever the model then stands.

- **EP4's rows re-priced:** T4-1 gains the keyset/injection-path re-statement (the
  sources and the pod's mounts named); a new row for the retained-key windows (the
  signing half — DT-EP4-2) and a re-price of T4-8/RES-21 part ii for the custody
  half (DT-EP4-3); a new row for the file-source at-rest footprint (DT-EP4-4) inside
  RES-13's class, its wording covering the IdP client secret's `IDP_CLIENT_SECRET_FILE`
  spelling — the same boundary price, a new location, no row of its own; the mis-use
  rows (DT-EP4-6, DT-EP4-7) recorded.
- **The revocation summary's "all proxy access" row re-priced:** routine rotation
  (overlap) is **no longer a revocation mechanism** — it drains; the immediate cut
  (retained-entry removal, `kid` dropped from the JWKS) keeps the old row's latency
  (≤ Core's JWKS cache + access TTL) as the *emergency* path. The row's text must
  say both, because the table is what an operator reads under pressure.
- **EP6's rows re-shaped for the pod:** the router-bypass row (T6-4) re-stated for
  the pod (the port reachable only within the namespace; the mis-assembly shape
  DT-EP6-1 beside it, its control set carrying the security-context controls —
  runAsNonRoot/uid-gid 10001, fsGroup 10001 on the store's volume, no privilege
  escalation, all capabilities dropped on the no-privileged-port assumption,
  read-only root with `emptyDir`, runtime-default seccomp); the internal-network
  peer row narrowed by the sibling leg (DT-EP6-2).
- **EP7's rows re-stated for the pod mount** (DT-EP7-1), RES-5's boundary unchanged;
  the governance reader class (storage-layer RBAC holders, backup destinations) is
  a bounded reader extension inside DT-EP7-1's row — the store's no-secret property
  is the control — and the row carries the cloud-backed storage-class requirement
  with the deployment-owned export story.
- **The compromise points:** the host row re-shaped for the pod (the node, the
  mounted volumes, the injection paths); the "Gateway signing key only" row gains
  the retained-key window text; the "Gateway process" row's custody half re-priced.
- **The residuals:** RES-2 re-worded per D8 (both end states); RES-13 re-worded
  (env/file injection the first-class end state, the pod's mounts, KMS optional —
  the IdP client secret's file spelling inside the same class, no preference
  between the spellings); RES-15 extended to the pod's single-replica statement; RES-21 part ii re-priced
  for the retention window; RES-5 re-stated for the pod.
- **The grouped mitigation list gains:** M34 (the keyset semantics and the
  pre-publish rule — this change's delta spec), M35 (the pod contract — the
  requirement plus the repo document, its content including the security-context
  section, the governance/storage-class statements, and the deployment diagram),
  M36 (the drill as the standing evidence
  control), with M17/M21's texts amended for the keyset (the hard-cut wording
  becomes the overlap wording in M21; M17's KMS line becomes the optional/signing,
  firm/custody split).

### 8. Open questions

1. **Core's JWKS-cache TTL as an operator-declared fact.** The pre-publish wait is
   bounded by it; the local instance's observed 10 minutes is the default the
   reference states, but Core's configurability of that cache is unverified in this
   authoring pass. Implementation verifies against the Core source (the checkout the
   C1.5 ruling names) and the reference states the verified value; a deployment
   whose Core caches longer than declared keeps DT-EP1-11's residual open — the
   drill's observed wait bounds it in practice.
2. **Core's `kid` resolution for gateway tokens.** The active-first JWKS ordering is
   written for kid-less verifiers; whether Core's provider entry resolves by `kid`
   or falls back to the first key is verified at implementation against the Core
   source, and the drill's evidence records which behavior the live run exercised.
3. **The DevOps review's logistics** — who reviews, in what forum, on what artifact
   version — is a process fact the owner fixes at the pause; the acceptance scenario
   requires the confirmation to be *recorded*, not to have a named reviewer today.
4. **The custody envelope port's one wording risk:** the wrapped-CEK blob is
   deployment-wide mounted state; the "no long-lived per-session store" property is
   untouched (D8's reasoning), but the *port's* SIA should re-state the property
   against the blob when that change is authored — recorded here so the future
   change inherits the question, not the answer.

**The strict gap list** (per the method's §7): **Minor** — the Alpine precedent
verification (D5) read a sibling repository's Dockerfile (`ai-dial-adapter-openai`),
which the SIA skill's per-change allowlist does not include; the fact is a
design-input per the roadmap's own instruction ("check their Dockerfiles"), cited as
such, and the SIA's own analysis does not depend on it — but the method should
either name sibling-repo verification as an allowed input for roadmap-ruled factual
claims or record such checks as orchestrator-supplied brief facts. No Blocking or
Major gaps: the analysis ran from the allowed inputs.

## Risks / Trade-offs

- **The retained-key windows are the change's honest cost** — a stolen superseded
  signing key stays hot at Core, and a stolen superseded custody key stays able to
  decrypt, each for up to the drain window, where both died at rotation before. The
  trade buys routine rotation that operators will actually run (an operator who
  rotates for hygiene no longer pays the stolen-key-response price) and keeps the
  emergency cut one configuration edit away, rehearsed. The SIA prices both windows
  (DT-EP4-2, DT-EP4-3) and the threat model re-prices the revocation table so the
  operator-facing record says which rotation is which.
- **The pod contract's acceptance depends on a human act** (DevOps explicit
  confirmation) — the one acceptance row this repo cannot gate mechanically. The
  composed stand-in proves everything the stack can prove; the assembly itself is
  trusted to the review, and the spec says silence is not acceptance.
- **The compat spellings are deliberate debt** — two spellings per keyset (singular/
  flat vs structured) kept so no deployment's `.env` churns to gain the seam. The
  cost is one more code path per loader and one "mixing kinds refuses" rule; the
  alternative (forced migration) was rejected as churn without benefit at this stage
  count.
- **The musl-wheel question is verified at the gate, not in this document** — the
  design names the wheel-availability expectation and the precedented builder
  fallback; the compose-boot gate on the new base is the check that counts.

## Migration Plan

1. **Threat-model delta first** (the standing order): §7's entries land in
   `docs/threat-model.md` before the implementation's keyset code merges.
2. **Settings and loaders:** the keyset schemas with their compat spellings and the
   reserved-`kms` refusals land together — every existing deployment's configuration
   keeps working unchanged (the singular and flat spellings are the compat shapes),
   and `openspec validate` plus the settings unit tests carry the refusal matrix.
3. **Verification and publication:** `decode_own_token`'s keyset selection and the
   multi-`kid` JWKS land as one unit with their tests — the two are one behavior
   (which keys verify) seen from two sides.
4. **Image and stack shape:** the Alpine swap, the `network_mode` pod shape, and the
   nginx upstream re-point land together and pass the compose-boot gate and the
   probe battery as one gate run — the base and the shape are separately bisectable
   but gated together.
5. **The drill:** runs on the pod-shaped production-image stack, evidence captured
   per the spec'd hygiene rule; the negative control precedes every verdict.
6. **Docs:** the contract document, the configuration reference's amendments, the
   `.env.example` additions, and the release notes — then the review gates (security
   first), the owner pause, and DevOps review as the closing acceptance.
7. **Rollback:** the compat spellings make the whole change configuration-reversible
   — a deployment that needs the old single-key behavior restores it by configuring
   the singular/flat spelling; the code's keyset support is inert without structured
   configuration.

## Open Questions (deferrable)

- Whether the singular signing setting and the flat custody spelling are eventually
  *retired* (a deprecation change with a migration window) or kept as the permanent
  no-rotation shapes — decided when the KMS adapters' change lands and the real
  configuration population is visible.
- Whether the drill graduates into a standing runbook artifact (a scripted rotation
  procedure an operator executes against production) or stays the change's
  acceptance evidence — the natural home is the production deployment guide the
  deferred table records with the K8s manifests (DevOps-owned).
- The token-lattice interaction with a *future* KMS-sourced active key (mint latency
  under a throttled sign API) is the future change's SIA item, named in D8 — not
  priced here, recorded so it is not lost.
