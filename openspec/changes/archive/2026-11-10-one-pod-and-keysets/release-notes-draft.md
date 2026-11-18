# Release notes — draft (one pod and keysets, C3)

### For users

No visible change for harnesses or sign-in flows: tokens, endpoints, discovery
documents, the consent checkpoint, and every flow behave exactly as before. Two
operator-facing behaviors change, both improvements:

- **Routine key rotation is no longer a mass signout.** Replacing the signing key or
  the custody key previously invalidated every outstanding refresh token at its next
  presentation — every user re-signed-in, a wave bounded only by the refresh TTL.
  Rotation is now an overlap: the superseded key is retained through a drain window
  (bounded by the refresh token's original absolute expiry), old tokens keep working
  and re-seal under the new key, and new tokens are accepted throughout. The hard
  cut still exists as the explicit act — removing the retained entry — and it is the
  right response to a suspected key compromise: the effect is immediate, exactly as
  before.
- **Your existing configuration keeps working unchanged.** The current single-key
  settings are the supported "no-rotation" shapes; the new keyset settings are
  opt-in, for rotation and for file-sourced (mounted) key material.
- **The identity-provider client secret accepts a file spelling.** The secret can
  now be delivered either as an environment variable (`IDP_CLIENT_SECRET`, as
  before) or from a read-only mounted file named by `IDP_CLIENT_SECRET_FILE` —
  both spellings are supported and equivalent to the gateway; configure exactly
  one of the two (configuring both refuses startup naming both settings). No
  preference is stated between them: the deployment chooses the delivery in its
  own cluster, and the boundary each spelling rests on is the deployment's to own.

The deployment unit for production is now defined: one pod (the front router and the
gateway as sibling containers), specified by a contract this repository owns and
DevOps assemble. If you deploy the gateway yourself, read
`docs/pod-contract.md` — the mounted volume for the dynamic-client-registration
store is a named requirement there, and a pod assembled without it silently loses
every registered client at each restart; the store's backing must be cloud-backed
persistent storage (surviving node loss, never node-local ephemeral); the pod's
required security context is stated alongside it; and a deployment diagram shows
the whole assembly, including where every secret enters it.

### For the team

- **The pod contract** (`docs/pod-contract.md`): the image (Alpine base, the
  44-HIGH Trivy debt cleared, uid 10001 preserved), the classified env-var surface,
  the nginx conf as the versioned mountable file with the sibling-localhost
  upstream, the volume mounts (the DCR durable mount a named MUST, its backing a
  cloud-backed persistent-volume storage class stated by its properties — survives
  node loss, tenant-governable, never node-local ephemeral; backup/export
  deployment-owned, cheap by the store's atomic-replace single-file shape; the
  no-secret-content rule stated load-bearing), the required security context
  (runAsNonRoot with uid/gid 10001, fsGroup 10001 on the store's volume, no
  privilege escalation, all capabilities dropped on the stated no-privileged-port
  assumption, read-only root with `emptyDir` for the router's temp/log paths,
  runtime-default seccomp), a renderer-independent deployment diagram,
  ports/probes,
  and the single-replica assumption — accepted by DevOps review with explicit
  confirmation (silence is not acceptance). The contract states requirements and
  delivery options only, with no preference between them — the deployment chooses
  the how in its managed cluster and cloud. The composed stack now runs the pod
  shape via a shared network namespace, so every gate exercises what production
  will run.
- **The per-entry `source` seam**: both keysets carry per-entry sources — `env`/`file`
  implemented, `kms` a reserved value refused at startup naming the gap — so the
  post-go-live KMS work plugs in as a rotation, not a redesign
  (source-heterogeneous keysets are valid from day one). The IdP client secret —
  the one secret outside the keysets — carries the same seam's file discipline:
  `IDP_CLIENT_SECRET_FILE` beside `IDP_CLIENT_SECRET`, exactly one of the two
  configured, the read-once loader refusing loudly on an unreadable path.
- **Active + retained keyset semantics** for both keys: sign/seal under the active
  entry only; verify/decrypt with active-or-retained through the drain window; the
  JWKS publishes every `kid` (active first). The rotation procedure gains a
  normative pre-publish step (the new `kid` published at least Core's JWKS-cache
  window before it signs) — required for "new tokens accepted throughout," which
  the rulings demand. The retained-key windows are priced in the change's SIA
  (design.md §5, DT-EP4-2/DT-EP4-3): a stolen superseded signing key mints
  Core-acceptable tokens, and a stolen superseded custody key decrypts outstanding
  blobs, each for up to the drain window — the priced cost of routine rotation,
  with the immediate cut as the answer.
- **The migration drill (T3, upgraded)**: live rotation of each keyset on the
  composed stack with captured evidence (`docs/evidence/c3/`), negative control
  first, the emergency cut rehearsed beside the routine drain. The drill doubles as
  the env→KMS migration rehearsal (AWS asymmetric keys cannot be imported; Azure
  import can preserve the `kid`).
- **The disclosures amended to be honest under both ruled end states**: the
  memory-zeroization residual (RES-2) now states that env/file injection is a
  supported end state (a reasoned residual — the process holds the key either way)
  and that the KMS sign-interface is optional for signing while the custody
  envelope (Core's credentials-manager pattern adapted: a single deployment-wide
  CEK, KMS-wrapped, the wrapped blob on the mounted volume, unwrapped at startup)
  is the firm planned post-go-live step. The configuration reference's
  signing-key/store trust-boundary equivalence is re-stated for the pod shape.
- **The threat model updated per the standing rule**: the revocation table's "all
  proxy access" row re-priced (routine rotation drains; the retained-entry removal
  is the emergency cut at the old latency), EP4/EP6/EP7 re-priced for the keysets
  and the pod, and the new mitigation rows M34–M36 recorded
  (`docs/threat-model.md`).
