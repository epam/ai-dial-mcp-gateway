# Tasks

## 0. Precondition — the owner review pause (PROCESS step 3c)

- [x] 0.1 The owner review pause with the complete package — proposal, design (the
  SIA and its rulings), tasks, delta specs — presented to the owner, and the owner's
  explicit go recorded in this change's evidence folder. Nothing in groups 1–8 runs
  without it: no implementation, no packaging, no branch work (PROCESS step 3c).
  This row is the checklist's front gate — a fresh implementation agent reading
  top-down meets the pause here, before group 1, not as a late pre-merge gate.
  The pause's amendment round (round 2, `evidence/pause-amendments.md`): the owner
  requested four amendments — the pod security-context section, the store's
  governance/storage-class statements, the deployment diagram, and the IdP client
  secret's file spelling — and corrected the round mid-flight (no preference
  language between delivery spellings; storage requirements named by properties,
  never products). The amendments are folded into this package; the re-presented
  package is what this row gates, and its go is the go for the amended shape.

## 1. Threat-model delta (the standing order — landed before implementation)

Design.md §7 names the entries; a mitigation that exists only in prose is not landed,
so the model's rows move before the code that carries them.

- [x] 1.1 Update `docs/threat-model.md` per design.md §7 — EP4's re-priced rows (the
  retained-key windows as new rows, T4-1's injection-path re-statement, T4-8/RES-21
  part ii's custody-window re-price, the file-source at-rest row inside RES-13's
  class — its wording covering the IdP client secret's `IDP_CLIENT_SECRET_FILE`
  spelling, same class, new location — and the mis-use rows), the revocation summary's "all proxy access" row
  re-priced (routine rotation drains — no longer a revocation; the retained-entry
  removal keeps the old latency as the emergency path), EP6's pod re-shape
  (T6-4 re-stated, the mis-assembly row — its control set carrying the
  security-context controls per the design's DT-EP6-1 — the sibling-leg narrowing),
  EP7's pod re-statement (DT-EP7-1 with the governance reader class as a bounded
  reader extension and the cloud-backed storage-class requirement), the compromise points' host row re-shaped for the pod, and
  the residuals' re-words (RES-2 both end states per D8, RES-13 env/file first-class
  — the IdP secret's file spelling inside the class, no preference between
  spellings — RES-15 the single-replica statement, RES-21 part ii, RES-5 the pod
  mount) — the
  delta rows carry design §7's ID numbering (DT-EP4-2..7, DT-EP1-10/11,
  DT-EP6-1/2, DT-EP7-1), unique across the live model, landed as written
- [x] 1.2 Add the grouped mitigation rows M34 (the keyset semantics and the
  pre-publish rule), M35 (the pod contract — the requirement plus the repo
  document, its content including the security-context section, the
  governance/storage-class statements, and the deployment diagram), M36 (the drill as evidence control),
  and amend M17 (the KMS optional-signing / firm-custody split) and M21 (the overlap
  wording replacing the hard-cut wording) — each home-named per the table's format
- [x] 1.3 Verify the §7 update with a fresh-agent read (the agent-freshness rule):
  the reviewer can reconstruct every delta row's citation from this change's design
  §5–§7 without session context — each ID is unique across the live model under
  §7's numbering, so a citation resolves to exactly one design §5 grid

## 2. The keyset schema and loaders

- [x] 2.1 `gateway/settings.py` — the signing keyset setting (structured entries:
  `source`/`ref`/`role`) with the compat relationship to the singular setting (both
  set refuses startup naming both), the zero-active and multi-active refusals, the
  duplicate-derived-`kid` refusal, the reserved-`kms` refusal naming the gap, and
  the per-entry named error discipline (ids and paths only, never material)
- [x] 2.2 `gateway/settings.py` — the custody keyset's structured spelling beside
  the flat compat spelling, the mixed-document refusal, the structured spelling's
  retained entries, and the no-active refusal carried from the signing rules
- [x] 2.3 `gateway/keys.py` — the signing keyset: entries with roles, the `file`
  source loaded once at startup (an unreadable or unparseable file refuses naming
  the path, never the content), the JWKS as every entry's public half with the
  active entry first, sign-through-the-active-entry only
- [x] 2.4 `gateway/custody.py` + `gateway/settings.py` — the custody keyset seam:
  the envelope's key-id selects the entry at decrypt (active or retained, unknown
  ids refused as before), seal always under the active entry, the AAD-bound header
  property preserved per entry
- [x] 2.5 `gateway/tokens.py`, `gateway/codes.py` — `decode_own_token` and
  `decode_code` verify against the keyset: the token's or code's `kid` selects the
  entry, unknown `kid` refused as not issued by this gateway, algorithm pinned per
  entry — `decode_code`'s verification is its own path today (a `jwt.decode` against
  `signing_key.public_key()`, no `kid` selection), so it moves with the keyset while
  `issue_code`'s sign path keeps today's shape through the active entry
- [x] 2.6 `gateway/runtime.py`, `gateway/token.py`, `gateway/routes.py` — the call
  sites read the keysets (the active signing entry; the custody seal/decrypt pair;
  the JWKS route serves the keyset's document — every entry's public half, active
  first — where it served the single key's); no behavior beyond key selection
  changes
- [x] 2.7 The unit tests — the refusal matrix (zero-active, multi-active, duplicate
  `kid`, reserved `kms`, unreadable file, mixed custody document, both signing
  settings set), the compat spellings' equivalence, the JWKS shape (all kids, active
  first), the retained-key verification and decrypt paths, the seal-under-active
  re-seal at rotation, and the old-key code redeemed across a promotion (a code
  minted under the pre-rotation key verifies through the retained entry —
  `decode_code`'s path; unit-tier because the code's own minutes TTL bounds it far
  below the drain window, which is why the drill's named legs are the access and
  refresh tokens that span the window)
- [x] 2.8 `gateway/settings.py` — the IdP client secret's file spelling
  (`IDP_CLIENT_SECRET_FILE`): the optional setting beside `idp_client_secret`,
  exactly one of the two spellings configured (both set refuses startup naming
  both, the keyset seam's mixing-refusal style; neither set keeps the existing
  missing-secret refusal), the file source read once at startup with an unreadable
  or blank file refusing loudly naming the path and never the content — the
  keyset seam's `file`-source discipline carried to the one secret outside the
  keysets (the identity-leg requirement's amendment scenarios) — plus the unit
  tests: the file spelling accepted and equivalent, the both-configured refusal,
  the unreadable-file refusal, and the missing-secret refusal unchanged under the
  file spelling's absence
- [x] 2.9 `gateway/settings.py` — the signing pair's blank normalization (the defect
  the rotation drill stopped on, `docs/evidence/c3/rotation-drill.md`): a
  field-level validator on the singular setting normalizes a blank value — empty or
  whitespace-only — to unset (to `None`, the `_blank_secret_file_path_is_unset`
  style), never a check-only tweak inside `_validate_signing_keyset` — because only
  the field-level normalization makes the loader's fold read blank as unset too
  (`gateway/keys.py` `_entries_from_settings`'s `singular is not None` branch), so a
  blank singular alone, with no structured keyset, surfaces as the loader's
  neither-configured refusal ("gateway_signing_key is not set…") — the refusal the
  spec's general clause requires, a spelling configured only by a real value —
  instead of a PEM-parse refusal on empty material; the composition path's
  always-forwarded blank never counts as configured and the both-configured refusal
  fires only on a real value — plus the unit matrix: blank singular + structured
  keyset accepted, whitespace singular the same, real singular + structured refused,
  blank singular alone (no structured keyset) refused as neither-configured — the
  "gateway_signing_key is not set" refusal, never the PEM-parse refusal — and real
  singular + blank structured (the always-on compose shape of every compat
  deployment) accepted with the singular honored — and the group-5 doc sentence: the
  rotation procedure in
  `docs/gateway-configuration.md` names the compose env-list step a structured
  entry's `ref` variable implies (the shipped compose forwards a fixed env allowlist,
  so a per-entry `ref` variable joins the list before the documented rotation edit
  starts)

## 3. The production image

- [x] 3.1 `Dockerfile` — the base swap to `python:3.12-alpine` with the adapter
  precedent's `apk upgrade --no-cache libcrypto3 libssl3`, uid/gid 10001 preserved,
  the pip-removal discipline carried, and the builder-stage-only toolchain fallback
  (`apk add build-base`) if a musl wheel is missing at build
- [x] 3.2 Verify the musl-wheel expectation (D5): the build completes on the new
  base with no runtime toolchain; record the wheel availability in the change's
  evidence
- [x] 3.3 The static gate's scanner run against the new image: no HIGH-or-above
  OS-package finding remains (the 44-HIGH Debian debt cleared), the result recorded
  in `docs/evidence/c3/` — the pod-contract requirement's scanner scenario

## 4. The pod shape on the composed stack

- [x] 4.1 `router/nginx.conf` — the one substantive edit: the gateway upstream
  re-pointed to `127.0.0.1:8091` (sibling localhost); the alternation, ordering,
  challenge maps, and query pass-through untouched
- [x] 4.2 `docker-compose.yml` — the pod shape: the router joining the gateway's
  network namespace (`network_mode: "service:mcp-signin-gateway"`), the published
  public port moved to the namespace-owning service, the gateway's port
  unreachable outside the shared namespace (the peer-identity property re-stated in
  the file's comments), the DCR mount unchanged in substance, and the keyset/
  compat settings in the environment list
- [x] 4.3 The compose-boot gate on the pod-shaped stack (gate 2): every service
  healthy, the probe battery green against the single public port (front-door
  routing, challenge synthesis on both data paths, query-string survival), the
  gateway's container port unreachable from outside — the pod-contract
  requirement's probe scenario
- [x] 4.4 The DCR-restart survival on the pod-shaped stack: register, restart the
  deployment unit, present the cached client id, accepted with no re-registration —
  the requirement's named-mount scenario, evidence in `docs/evidence/c3/`
- [x] 4.5 The quirk check: a gateway-only recreate no longer 502s the router (the
  pairing-atomicity acceptance P5 was scoped for), recorded with the probe run

## 5. The pod contract and the configuration surface

- [x] 5.1 `docs/pod-contract.md` (new) — the contract document: the image facts,
  the classified env-var surface (required / optional / secret / dev-only — every
  variable the container reads, from the settings model, one table, gaining
  `IDP_CLIENT_SECRET_FILE` as the optional secret-class spelling beside
  `IDP_CLIENT_SECRET`), the nginx conf
  as the versioned mountable file, the volume mounts (the DCR store's as a named
  MUST, read-write, the pod's one state mount; read-only mounts for every
  file-sourced secret — the keyset entries' key files and the IdP client secret's
  file alike), the store's governance/storage-class statements (the cloud-backed
  persistent-volume requirement stated by its properties — survives node loss,
  tenant-governable, never node-local ephemeral storage, the satisfying class the
  deployment's choice; the deployment-owned export story — a single
  human-readable JSON file written by atomic replace, a point-in-time copy a
  consistent export, no gateway cooperation, no new API; the no-secret-content
  rule stated load-bearing with the future wrapped-CEK file named as the store
  volume's future second resident), the security-context section (runAsNonRoot
  with the image's fixed uid/gid 10001 — the DCR store's file ownership depends
  on it; fsGroup 10001 on the store's volume, a world-writable mount the tamper
  path to refuse; allowPrivilegeEscalation false; all capabilities dropped on the
  stated no-privileged-port assumption; a read-only root filesystem with emptyDir
  for the router's temp/log paths; the runtime-default seccomp profile), the
  secret-delivery statements as requirements and neutral options only — secret
  material enters at run time only, never baked, never in the repository; each
  secret accepts two spellings (injected environment variable, or read-only
  mounted file), both supported, exactly one configured, no preference stated:
  the deployment chooses the how in its managed cluster and cloud, and the
  boundary price of each spelling is the deployment's — the ports and probes, the
  sibling-localhost
  assumption with the port non-publication, and the single-replica assumption with
  its loss semantics
- [x] 5.2 `docs/pod-contract.md` — the deployment diagram (the contract document's
  own section, renderer-independent ASCII inside the markdown — no image
  dependencies, readable as plain text in any diff): the pod as one box (the
  router container: nginx, the versioned conf mounted read-only, the single
  public port at the cluster-ingress TLS boundary; the sibling-localhost leg
  `127.0.0.1:8091`; the gateway container: uid 10001, one internal port,
  unpublished), the mounts (the DCR store's durable volume — the cloud-backed
  class, the pod's one state mount, the future wrapped-CEK file named as its
  future second resident; the read-only key-file mounts), the secret paths
  (KeyVault/Secrets Manager → K8s Secrets → env vars or mounted files → the
  signing keyset, the custody keyset, and the IdP client secret — the diagram
  names the path shape, not a product), the neighbors (the harness via ingress;
  DIAL Core with the MCP data path drawn bypassing the gateway entirely; the
  identity provider with its back-channel legs), the reserved `source: kms` as a
  dashed future arrival, and the stated assumptions drawn where they live
  (sibling-localhost, single-replica, port non-publication, the security-context
  controls)
- [x] 5.3 `docs/gateway-configuration.md` — the keyset settings with both rotation
  procedures (routine overlap: add-as-retained → wait the declared Core
  JWKS-cache window → promote → drain → remove; emergency: remove the retained
  entry at any moment), the pre-publish rule stated, the declared cache bound
  (verified per design §8 OQ-1) — the amended signing-key/store trust-boundary
  statement for the pod shape (design D8: the store's boundary is the volume/node,
  a key's is its injection path, the equivalence kept only where still true) —
  and the IdP client secret's two delivery spellings documented neutrally
  (`IDP_CLIENT_SECRET` by environment variable, `IDP_CLIENT_SECRET_FILE` by
  read-only mounted file, both supported, exactly one configured, the
  both-configured refusal naming both) — and the rotation procedure names the compose
  env-list step a structured entry's `ref` variable implies (the shipped compose
  forwards a fixed env allowlist, so a per-entry `ref` variable joins the list before
  the documented rotation edit starts — the drill's recorded gap, landed with 2.9)
- [x] 5.4 `.env.example` — the keyset settings with placeholder examples, the
  compat spellings' unchanged blocks re-annotated, the rotation-procedure note
  replacing the hard-cut note on the custody block, and the IdP client secret
  block's amendment: the `IDP_CLIENT_SECRET_FILE=` placeholder added (empty, the
  committed placeholder stays empty) and the existing comment's
  "never a file the gateway reads" clause re-worded to the two-spellings
  statement — delivered at run time as an environment variable or from a
  read-only mounted file named by `IDP_CLIENT_SECRET_FILE`, both supported,
  exactly one configured, never argv, never committed — no preference between the
  spellings stated
- [x] 5.5 The memory-zeroization disclosure amendment — RES-2's re-worded record in
  `docs/threat-model.md` (both end states: injection the reasoned disclosed
  residual; KMS optional for signing and possibly abandoned; the custody envelope
  the firm planned step) — landed with group 1 if the same file pass, verified
  against design D8's wording here

## 6. The migration drill (T3, upgraded)

- [x] 6.1 The drill's scripted legs under `scripts/` (the probe battery's
  extension): the signing leg (tokens under the old key → staged rotation per the
  pre-publish rule with the declared cache wait → drain observations → removal) and
  the custody leg (overlap rotation with live refresh sessions → the emergency cut
  mid-window)
- [x] 6.2 The negative control first: the deliberately wrong expectation (an
  old-`kid` token asserted to verify after its retained entry is removed) runs and
  fails before any verdict is trusted — recorded in the evidence
- [x] 6.3 The signing-leg evidence: old-key access tokens accepted at Core through
  the window, old-key refresh tokens refreshing and minting under the new `kid`,
  new sign-ins accepted throughout, the cache wait observed or bounded, the
  post-drain removal's refusals — the drill requirement's rotation-window scenario
- [x] 6.4 The custody-leg evidence: live sessions decrypting under the retained
  key-id and re-sealing under the active one across the rotation; the removed-key
  mid-window presentations refusing in the custody class — the requirement's
  emergency-cut scenario
- [x] 6.5 The evidence-hygiene pass: every captured file carries `kid`s, key-ids,
  JWKS snapshots, audit records, and verdicts only — no key material, no token
  strings, no envelope contents; the pass itself recorded (the requirement's
  evidence clause)
- [x] 6.6 The publication leak check green over the evidence folder (the static
  gate's step, run on the drill's artifacts specifically)

## 7. Acceptance and gates

- [x] 7.1 The lightweight gates then the static gates on the whole diff (ruff,
  ruff format, bandit, pip-audit, Trivy, the publication leak check) — per
  `PROCESS.md` step 5's order
- [x] 7.2 The compose-boot gate on the pod-shaped production-image stack (group 4's
  run, as the gate-tier record)
- [x] 7.3 The change's conformance rows: every delta-spec scenario mapped to a test,
  a probe, or an evidence record (the drill's and the pod contract's scenarios are
  evidence-gated by design)
- [x] 7.4 The security review gate on the diff (an independent reviewer, depth per
  the SIA's Medium level: the keyset mechanics, the pod-contract statements against
  the mis-assembly shapes, the drill's evidence against its scenarios — the
  falsification pass aimed at the retained-key windows' pricing)
- [x] 7.5 The review gate on the diff (an independent reviewer)
- [ ] 7.6 DevOps review of the pod contract: explicit confirmation recorded in
  `docs/evidence/c3/` — silence is not acceptance; this row does not close without
  the record
- [ ] 7.7 The closing record: 0.1's go and the checklist's rows complete, the branch
  committed and pushed — the merge to master is the owner's act (PROCESS.md's final
  rule), never a task on this checklist; the change is done when its gates pass and
  its branch is pushed

## 8. Release notes

- [x] 8.1 Finalize `release-notes-draft.md` with both sections, the user-facing
  compatibility sentence verified true (every existing deployment's configuration
  keeps working: the singular and flat spellings are the compat shapes), and the
  rotation-behavior change stated plainly (routine rotation is no longer a mass
  signout; the hard cut is now the explicit act)
