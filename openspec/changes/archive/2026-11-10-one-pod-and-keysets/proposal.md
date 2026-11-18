# Proposal

## Why

The production deployment target is a Kubernetes cluster, and the deployment unit there
is **one pod** — the front router and the gateway as sibling containers on a shared
localhost. Everything this stage exists to decide is a property of that unit: how the
secret material enters it, what state it carries across a restart, and what happens to
every outstanding token when its keys change. The production roadmap packages exactly
this conversation as **C3 = P5 + P1 + T3** (the owner-approved plan, 2026-10-29; the
binding ruling set is the "C3 as ruled, 2026-11-08" amendment), because the three items
are one decision viewed from three sides: "secrets out of env *files*" *is* the pod's
secret injection, the deployment unit defines the secret slots, and rotation is the one
operation that proves the slots and the unit both work.

Three facts make the change necessary now:

- **The deployment deliverable is decided as a contract, not manifests.** DevOps own the
  Helm/pod assembly; this repository cannot run K8s locally. What this repo owns — and
  what the pod can silently lose by omission — is the contract: the image, the
  classified env-var surface, the nginx conf as a versioned mountable file (front
  routing is spec'd gateway behavior, not DevOps folklore), the volume mounts, the
  ports and probes, the sibling-localhost assumption, and the single-replica
  assumption. The DCR registration store's durable mount is already a named
  requirement of the stage: a pod assembled without the mounted volume silently
  invalidates every registered client at every restart — the requirement the compose
  shape satisfies implicitly and the pod shape can lose by omission.
- **Routine key rotation is currently a mass signout, and that is a defect of the
  single-key shape.** Replacing the signing key invalidates every outstanding refresh
  token at its next presentation; the custody keyset's rotation is a *hard cut by
  specification* — every outstanding refresh token fails closed, a re-sign-in wave
  bounded only by the refresh TTL. An operator who rotates for hygiene pays the same
  price as an operator who rotates because the key was stolen, which trains operators
  not to rotate. The active-plus-retained keyset semantics (sign with the active key,
  verify with active-or-retained until the old tokens' TTL drains, the JWKS publishing
  every `kid`) make routine rotation a drain and keep revocation the immediate cut.
- **A documented-but-never-exercised rotation procedure is an unproven control** — the
  roadmap's own T3 reasoning, restored 2026-10-30. No live `kid` rotation has ever been
  run on this stack. T3 is folded here and upgraded to the **migration drill**: the
  same overlap procedure is the future env→KMS migration path (AWS asymmetric keys
  cannot be imported — a new `kid` is inherent to that migration; Azure import can
  preserve it), so the drill proves the procedure twice over.

The change also carries the two disclosure amendments the roadmap pins to it: the
memory-zeroization disclosure (RES-2) and `docs/gateway-configuration.md`'s statement
that the DCR store's protection is the same trust boundary as the signing key's — an
equivalence that must be re-stated honestly for the pod shape, under **both** end
states the rulings fix (env/file injection as a reasoned disclosed residual; the KMS
sign-interface optional and possibly abandoned for signing; the custody envelope —
Core's credentials-manager pattern adapted — the firm planned post-go-live step).

## What Changes

The rulings fix the outcomes and constraints; the mechanisms are design.md's, argued
there as decisions of record (including where the author finds a ruling imprecise —
the owner asked for that pushback explicitly).

- **The pod contract (ADDED requirement).** A versioned contract document this
  repository owns, reviewed by DevOps as acceptance evidence — **their explicit
  confirmation, silence is not acceptance**: the production image (base swapped to
  Alpine per the `ai-dial-adapter-*` Python precedent, clearing the recorded 44-HIGH
  OS-package Trivy debt; non-root fixed uid; one container-internal port; no
  secret-class value baked), the classified env-var surface (required / optional /
  secret / dev-only, committed as a versioned table), the nginx conf as the versioned
  mountable file the router container runs read-only — with its gateway upstream
  re-pointed to sibling localhost, the volume mounts (the DCR store's mount as the
  pod's one state mount, a named MUST, backed by a cloud-backed persistent-volume
  storage class stated by its properties — the data survives node loss and rests in
  a tenant-governable resource, never node-local ephemeral storage; backup/export
  deployment-owned, cheap by the store's own atomic-replace single-file shape; the
  no-secret-content rule stated load-bearing, the future wrapped-CEK file named as
  the store volume's future second resident; read-only mounts for every
  file-sourced secret), the ports and probes (`/healthz` liveness through the router
  and container-internally; the gateway port unreachable outside the pod), the
  required security context (runAsNonRoot with the image's fixed uid/gid 10001,
  fsGroup 10001 on the store's volume, no privilege escalation, all capabilities
  dropped on the stated no-privileged-port assumption, read-only root filesystem
  with `emptyDir` for the router's temp/log paths, the runtime-default seccomp
  profile), a renderer-independent deployment diagram of the assembly, the
  sibling-localhost assumption, and the **single-replica assumption stated** (flow
  state and the approved-client registry are in-memory; the pod is not horizontally
  scalable; HA stays deferred). The contract's secret-delivery content states
  requirements and options only, with no preference between the spellings — the
  deployment chooses the how in its managed cluster and cloud. The
  probe battery, the DCR-restart survival, and the
  drill all run on the local composed stack **in the production-image shape** — the
  compose `network_mode` standing in for the pod's shared network namespace.
- **The per-entry `source` seam (ADDED requirement).** Both keysets —
  signing and custody — carry a per-entry source: `env` and `file` implemented now,
  `kms` a cleanly-rejected reserved value (fail-closed at startup, an operator-facing
  error naming the gap — never a silent ignore). The schema carries the field from
  day one so source-heterogeneous keysets (a retained env-sourced key beside a future
  active KMS-sourced key) are a rotation, not a redesign.
- **The IdP client secret gains a file spelling (MODIFIED requirement).** The
  confidential client's secret — the one secret outside the keysets — accepts two
  delivery spellings, both supported: the injected environment variable
  (`IDP_CLIENT_SECRET`) or a file at a configured path (`IDP_CLIENT_SECRET_FILE`, a
  read-only mount — the shape a mounted Secret file takes). Exactly one of the two
  is configured: both configured refuses startup naming both settings (the keyset
  seam's mixing-refusal style), neither configured keeps the existing
  missing-secret refusal. A file source is read once at startup, an unreadable path
  refused loudly naming the path never the content. No preference between the
  spellings is stated anywhere — the two are equivalent to the gateway, and the
  boundary each rests on is the deployment's to own.
- **Active + retained keyset semantics for both keys.** Sign with the active key only;
  the JWKS publishes every `kid` (active first, for kid-less verifiers); own-token
  verification accepts active-or-retained, the token's `kid` selecting within the
  keyset; custody decrypts with active-or-retained (the envelope's key-id selecting)
  and seals always under the active key. Routine rotation becomes an overlap drain
  bounded by the refresh token's non-sliding absolute expiry; removing a retained
  entry is the **immediate cut** — the emergency path the old hard cut becomes. The
  rotation procedure gains a normative **pre-publish step** (the new `kid` published
  — present in the keyset, hence in the JWKS — at least Core's JWKS-cache TTL before
  it signs), so no minted token ever carries a `kid` a verifier's cache may not hold;
  the rulings' "new tokens accepted throughout" requires it, and the drill proves it.
  The retention-versus-stolen-old-key window is priced in the SIA (design.md §5): a
  stolen retained signing key mints Core-acceptable tokens, and a stolen retained
  custody key decrypts outstanding blobs, each for up to the drain window — the
  priced cost of routine rotation, with the immediate cut as the answer.
- **T3 — the migration drill (ADDED requirement).** A live rotation of each keyset on
  the composed stack with captured evidence, negative control first: old tokens drain
  gracefully, refresh sessions survive and re-seal under the new key, new tokens are
  accepted throughout, Core's JWKS cache window is respected and observed, and the
  emergency cut (retained-entry removal mid-window) is rehearsed alongside the
  routine drain. The drill is the acceptance gate for the keyset semantics and the
  recorded rehearsal of the env→KMS migration path.
- **Disclosure and configuration-doc amendments.** The memory-zeroization disclosure
  (RES-2) amended to be honest under both end states; the configuration reference's
  signing-key/store trust-boundary equivalence re-stated for the pod shape; the
  threat model's affected entries updated per the standing rule (the retained-key
  windows, the revocation table's re-priced "all proxy access" row, the pod-shaped
  host boundary, the EP4/EP6/EP7 re-prices) — as tasks, before implementation
  completes.

Out of scope (deferred or DevOps-owned, per the rulings): Helm charts and any K8s
manifests; any live K8s rollout; TLS/ingress (infrastructure); HA/Redis; the KMS
adapters themselves (post-go-live, their own change with its own SIA and live
acceptance — the custody envelope's shape is *named* here as the firm planned step,
not built); GCP (not in the first KMS-signing delivery, should it happen).

## Capabilities

### New Capabilities

(none — the pod contract, the keysets, and the drill are the existing sign-in
capability's deployment and key-management behavior; every requirement this change
adds or touches lives in `mcp-signin`)

### Modified Capabilities

- `mcp-signin`: three requirements are ADDED — **the pod contract** (the deployment
  unit's versioned contract: image, classified env-var surface, the nginx conf as a
  mountable versioned file with the sibling-localhost upstream, the volume mounts with
  the DCR durable mount as a named MUST and its cloud-backed storage-class and
  governance statements, the required security context, the deployment diagram,
  ports and probes, the single-replica
  assumption, DevOps review as acceptance evidence); **the signing keyset** (per-entry
  sources with the reserved `kms` refusal, exactly one active entry, retained entries,
  sign-active-only, the JWKS publishing every `kid` active-first, the pre-publish
  rotation procedure, retained-entry removal as the immediate cut, the
  blank-equals-unset rule for the mutually-exclusive spellings (a blank value is
  unset — the composition path's explicit forwarding never configures a spelling —
  so the exclusivity refusals fire only on real values, the IdP client secret's
  delivery pair carrying the same rule), source-heterogeneous
  keysets valid); and **the rotation drill** (the live keyset-rotation acceptance gate
  with captured evidence and its negative control). Three requirements are MODIFIED —
  **the custody requirement** ("The identity provider's session refresh token is
  carried encrypted in the gateway's refresh token": the hard-cut clause becomes the
  overlap semantics — seal under the active key, decrypt with active-or-retained
  selected by the envelope's key-id, the drain window, the immediate cut as the
  explicit emergency path, the per-entry source field with its reserved-`kms`
  refusal), **the inbound-tokens requirement** ("Inbound tokens are verified with
  pinned algorithm and key selection": own-token verification is keyset-based — the
  token's `kid` selecting within the gateway's own keyset, active or retained, an
  unknown `kid` refused — under the pinned algorithm, everything else verbatim; the
  one wording-level touch is the retained "Embedded key refused" scenario's "the
  pinned key only" becoming "the pinned key set's selected entry only", declared in
  the amendment note, and the prior change's amendment note is carried marked
  (retained)), and **the confidential-client requirement** ("The identity-provider
  client is confidential; the PKCE toggle governs the challenge only": the secret's
  delivery clause — two spellings, `IDP_CLIENT_SECRET` by environment variable and
  `IDP_CLIENT_SECRET_FILE` by read-only mounted file, both supported, exactly one
  configured, the both-configured refusal naming both, the read-once file discipline
  with its path-naming refusal; the never-logged sentence extended to "whichever
  spelling delivers it"; three scenarios added; no preference between the spellings
  stated — the deployment chooses). Every other requirement stays verbatim.

## Impact

Surfaces are named at file depth; the mechanisms are design.md's.

- `gateway/settings.py` — the keyset schemas: the signing keyset setting (new) with
  per-entry source/role validation and its compat relationship to the existing
  singular setting; the custody keyset's structured entries beside the flat compat
  spelling; the reserved-`kms` startup refusals; the zero-active and multi-active
  refusals; duplicate-derived-`kid` refusal; and the IdP client secret's file
  spelling (`IDP_CLIENT_SECRET_FILE`) with its exactly-one-of-two refusal and
  read-once file loader.
- `gateway/keys.py` — the keyset: entries as loaded keys with roles, the derived-`kid`
  uniqueness property carried per entry, the JWKS document as every entry's public
  half with the active entry first, sign-through-the-active-entry only, the
  `file`-source loader (read once at startup, refused loudly on an unreadable path,
  never logged).
- `gateway/custody.py` — the keyset seam on the decrypt side: the envelope's key-id
  selects the entry (active or retained); seal always under the active entry; the
  AAD-bound header property preserved per entry (a transplanted header fails the tag
  under the key it names).
- `gateway/tokens.py` — `decode_own_token` verifies against the keyset: the token's
  `kid` selects the entry, unknown `kid` refused, algorithm pinned per entry.
- `gateway/codes.py` — `decode_code` verifies authorization codes against the keyset
  (the code's `kid` selects the entry — the inbound-tokens requirement's own-tokens
  clause names codes, so a code minted under the old key and redeemed after a
  promotion verifies through the retained entry); `issue_code`'s sign path reads the
  active entry and is otherwise unchanged.
- `gateway/token.py`, `gateway/runtime.py`, `gateway/routes.py` — the mint and
  refresh paths read the keysets (the active signing entry; the custody seal/decrypt
  pair); the JWKS route serves the keyset's document — every entry's public half,
  the active entry first — where it served the single key's; no call-site behavior
  beyond the key selection changes.
- `Dockerfile` — the base swap to `python:3.12-alpine` (the
  `ai-dial-adapter-*` precedent: `apk upgrade` of the crypto libraries in the builder;
  musl-wheel availability verified, with the build toolchain fallback named); the
  fixed uid 10001 preserved (the DCR store's ownership depends on it); pip removal
  discipline carried over.
- `docker-compose.yml` — the pod shape locally: the router joining the gateway's
  network namespace (`network_mode: "service:…"`, compose's stand-in for the pod's
  shared localhost), the published port moving with the namespace owner, the
  keyset/compat settings in the environment list, the DCR mount unchanged in
  substance.
- `router/nginx.conf` — the gateway upstream re-pointed from the service name to
  sibling localhost (`127.0.0.1:8091`) — the conf's one substantive edit; the versioned
  mountable file is the same file, and its routing behavior is unchanged.
- `.env.example`, `docs/gateway-configuration.md` — the keyset settings with rotation
  procedures (routine overlap and emergency cut, the pre-publish step and Core's
  JWKS-cache bound), the classified env-var surface table, the IdP client secret's
  two delivery spellings stated neutrally (`IDP_CLIENT_SECRET` and
  `IDP_CLIENT_SECRET_FILE`, both supported, exactly one configured), and the amended
  signing-key/store trust-boundary statement for the pod shape.
- `docs/pod-contract.md` (new) — the contract document itself: the deliverable DevOps
  review accepts against — the image facts, the classified env-var surface (gaining
  `IDP_CLIENT_SECRET_FILE`), the nginx conf as the versioned mountable file, the
  volume mounts with the store's governance/storage-class statements, the
  security-context section, the renderer-independent deployment diagram, the
  ports and probes, and the stated assumptions.
- `docs/threat-model.md` — the standing rule's update: EP4's keyset rows, the
  retained-key window pricing, the revocation table's re-priced row, RES-2/RES-13/
  RES-15/RES-21 re-worded or re-priced, the pod-shaped host boundary in the
  compromise points, the new mitigation rows — landed as tasks before the change
  closes.
- `docs/evidence/c3/` — the drill's captured evidence (kids, verdicts, audit records,
  JWKS snapshots — public facts and fixed vocabularies only; no key material, no
  token strings).
- The test suite — keyset unit coverage (roles, sources, refusals, kid selection,
  JWKS shape), the compat-spelling migrations, and the drill's scripted legs.
