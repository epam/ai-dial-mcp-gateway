# Spec Delta

## ADDED Requirements

### Requirement: The deployment unit is a single pod defined by a versioned contract

The production deployment unit is **one pod**: the front router and the gateway as
sibling containers on a shared localhost, deployed and rolled as one unit. This
repository delivers the pod's **contract**, not its manifests — the Helm/pod assembly
is DevOps-owned — and the contract is a versioned document in this repository that
MUST state: the production image; the classified env-var surface; the nginx
configuration as the versioned mountable file the router container runs read-only
(front routing is this spec's behavior, not deployment folklore); the volume mounts;
the ports and probes; the pod's required security context; a deployment diagram of
the assembly (renderer-independent, readable as plain text); the sibling-localhost
assumption; and the single-replica assumption. The contract MUST pass DevOps review
before this change is done, and the
review's evidence is **explicit confirmation** — silence is not acceptance.

The production image MUST run as a fixed non-root uid (the DCR store's file ownership
depends on it), expose exactly one container-internal port (the gateway's, never
published — unreachable from the host and from outside networks, name-routable on the
deployment's own instance network, where Core fetches the JWKS), bake no secret-class
value (never-cut 6), and carry no
HIGH-or-above OS-package finding in the static gate's scanner — the recorded
Debian-slim Trivy debt is cleared by this change, by the base swap the design decides.
The classified env-var surface MUST classify every environment variable the container
reads into required / optional / secret / dev-only, as a committed table; secret-class
values are injected at run time (environment variable or mounted key file), never in
the image, never in the repository.

The router container MUST run this repository's committed nginx configuration
read-only, with the gateway upstream addressed at sibling localhost — the router is
the sole front door and the sole peer-identity authority, and the gateway's port MUST
NOT be reachable from the host or from outside the deployment's network: the pod
boundary keeps it off the host and the pod's external interface, and the deployment's
own instance network is the one network that reaches it by design — the trust domain
where Core fetches the gateway's JWKS by name, the port's named legitimate use (the
property the non-published container port carries in the composed shape). The pod's
volume mounts MUST carry the DCR
registration store's mount (read-write, at the configured store path — the pod's one
mounted state; the consent registry's in-memory custody is deliberately excluded, per
the approved-client registry requirement's own record), and, where file-sourced keyset
entries are configured, their read-only key-file mounts. The store's backing MUST be a
cloud-backed persistent-volume storage class — the requirement stated by its
properties: the data survives node loss and rests in a tenant-governable resource the
deployment administers — never node-local ephemeral storage; which storage class,
mechanism, or product satisfies those properties is the deployment's choice, named by
the contract as a requirement, not as a product. Backup and export are
deployment-owned, and the component's own shape is what makes them cheap: the store is
a single human-readable JSON file written by atomic replace, so a point-in-time copy
of the file is a consistent export — no gateway cooperation and no new API; the choice
of copy mechanism and destination is the deployment's. The store's no-secret-content
rule is load-bearing and MUST be stated as such: the store MUST NOT gain secret-class
content without re-opening its boundary analysis — the property is what makes the
external governance reader class (storage-layer RBAC holders, backup destinations)
cheap to admit, and the same logic carries the future wrapped-CEK file, which is
ciphertext by design and is named in the contract as the store volume's future second
resident. The pod's probes MUST be
liveness probes against `/healthz` — through the router and container-internally —
matching the endpoint's own contract (the probe answers whether the process is up,
never Core's or the identity provider's health).

The pod's security context MUST preserve the controls the image and its mounts
assume: `runAsNonRoot: true` with the image's fixed uid and gid (`runAsUser`/
`runAsGroup` 10001 — the DCR store's file ownership depends on that uid);
`fsGroup: 10001` on the store's volume, so the mount's ownership lets uid 10001 write
it — a world-writable mount is the tamper path the assembly must refuse;
`allowPrivilegeEscalation: false`; all Linux capabilities dropped — viable because
nothing in the pod binds a privileged port (the router's public port and the
gateway's container-internal port are both unprivileged, and that is the assumption
that keeps the drop total, stated where it lives); a read-only root filesystem, with
`emptyDir` mounts for the router's temp and log paths — the gateway writes nothing
but the DCR store, whose own volume the read-only root does not touch; and the
runtime-default seccomp profile. These are requirements the assembly MUST preserve,
not deployment preferences: a pod spec that relaxes any of them is a contract
violation priced at the pod-mis-assembly threat (the design's DT-EP6-1), the same
class that prices a published gateway port or a dropped store volume.

The single-replica assumption MUST be stated in the contract: flow state and the
approved-client registry are in-memory, so the pod is not horizontally scalable and
HA remains deferred — the loss semantics are the ones the spec already fixes
(fail-safe re-prompt and re-run, never a bypass). The local composed stack stands in
for the pod for every acceptance this change carries: it MUST run the production
image in the pod shape — the router and gateway sharing one network namespace, the
gateway's port unpublished — and the probe battery, the DCR-restart survival, and the
rotation drill all run against that stack.

#### Scenario: The probe battery passes against the pod-shaped stack

- **WHEN** the composed stack runs the production image with the router and the gateway sharing one network namespace, and the probe battery runs
- **THEN** every probe passes against the single public port — the front-door routing, the challenge synthesis on both data paths, and the query-string survival — with the gateway's container port unreachable from the host and from outside networks, its reach limited to the pod's shared namespace and the deployment's own instance network, where Core fetches the JWKS

#### Scenario: The DCR store survives a pod restart on its named mount

- **WHEN** a client registers via the registration endpoint on the pod-shaped stack, the pod-shaped deployment unit restarts, and the client presents its cached client id
- **THEN** the registration is loaded from the mounted store and the authorization request is accepted with no re-registration — the contract's volume-mount section is what makes the durability requirement's mount a named MUST rather than an omission the pod shape can lose

#### Scenario: No secret-class value in the image

- **WHEN** the production image is inspected or scanned for secret material
- **THEN** it carries no secret-class value from the classified env-var surface — secret material enters only by run-time injection, environment variable or mounted key file

#### Scenario: The image clears the scanner gate

- **WHEN** the static gate's OS-package scanner runs against the production image
- **THEN** no HIGH-or-above finding remains — the recorded Debian-slim debt is cleared by the base swap, and the finding is recorded in the change's evidence

#### Scenario: The single-replica assumption is stated

- **WHEN** the contract document is read
- **THEN** it states that flow state and the approved-client registry are in-memory, that the pod is not horizontally scalable, and that HA stays deferred — and a restart's loss semantics are the spec's fixed fail-safe shapes (approvals re-prompt, flows re-run, pending entries lost bounded)

#### Scenario: The security context's controls are stated as the assembly's requirements

- **WHEN** the contract document is read and the pod assembly is reviewed against it
- **THEN** it states `runAsNonRoot` with the fixed uid/gid 10001 on the gateway container (the DCR store's file ownership depends on it), `fsGroup` 10001 on the store's volume (a world-writable mount is the tamper path to refuse), no privilege escalation, all capabilities dropped on the strength of the stated no-privileged-port assumption, read-only root filesystems with `emptyDir` for the router's temp and log paths, and the runtime-default seccomp profile — and an assembly that relaxes any of them is a contract violation priced at the pod-mis-assembly threat, not a deployment preference

#### Scenario: The store's storage class and export story are stated

- **WHEN** the contract's volume-mount section is read
- **THEN** it states the cloud-backed persistent-volume requirement by its properties — the data survives node loss and rests in a tenant-governable resource, never node-local ephemeral storage, with the satisfying class and mechanism the deployment's choice — the deployment-owned export property (a single human-readable JSON file written by atomic replace, so a point-in-time copy is a consistent export, no gateway cooperation, no new API), and the no-secret-content rule as load-bearing, with the future wrapped-CEK file named as the store volume's future second resident

#### Scenario: DevOps review passes with explicit confirmation

- **WHEN** the contract is presented to the DevOps owners for review
- **THEN** completion of this change requires their explicit confirmation recorded in the change's evidence — the contract passing review is the deliverable's acceptance, and silence is not acceptance

### Requirement: The signing key is a keyset with per-entry sources and active and retained roles

The gateway's signing material is a **keyset**: one or more RSA private-key entries,
each carrying a **source** — `env` (the material in an injected environment variable)
or `file` (a PEM at a configured path on a read-only mount), both implemented — and a
**role**, exactly one entry `active` and any number `retained`. `kms` is a reserved
source value: an entry carrying it MUST be refused at startup with an operator-facing
error naming the gap (the KMS sign-interface is not built), never silently ignored and
never fallen back — the schema carries the field so a future KMS-sourced entry is a
rotation, not a redesign, and source-heterogeneous keysets (a retained `env` entry
beside an active `file` entry) are valid from day one.

The keyset's startup validation MUST refuse: an empty keyset; a keyset with no active
entry; a keyset with more than one active entry; an entry that is not a readable,
unencrypted RSA private key of at least the minimum key size; two entries whose
material derives the same `kid` (the `kid` is derived from the key material itself —
a truncated hash over the public numbers — so a shared `kid` is either the same key
configured twice, under one name or two, or a collision between two distinct keys in
the truncated hash; the refusal stands either way, because one `kid` must name
exactly one entry); and, for a `file`-sourced entry, an unreadable or unparseable file,
naming the path. No key material, no fingerprint, and no file content reaches any
startup error or log line — the errors name entries by their configured ids and paths
only.

The signing material's two spellings — the singular setting and the structured keyset
setting — are mutually exclusive, and a spelling is configured only by a real value: a
**blank** value of the singular setting, empty or whitespace-only, is **unset**. The
composition path — a deployment that fronts every setting explicitly, so an absent
value arrives as an empty string — never counts as configuring the singular by its
forwarding alone; the both-configured refusal fires only when the singular carries a
real value beside a structured keyset.

The gateway MUST sign with the **active** entry only; every minted token carries the
active entry's `kid`. The JWKS document MUST publish the public half of **every**
entry — active and retained alike — with the active entry first, so a verifier that
resolves a `kid`-less token to the first published key selects the key that signs.
The gateway's own-token verification accepts the active or a retained entry (the
inbound-tokens requirement's amendment), and the retained entries exist for the drain
window: bounded by the refresh token's non-sliding absolute expiry, the longest-lived
token the gateway mints. An operator MAY remove a retained entry at any time;
removal is the **immediate cut** — tokens signed under it are refused at their next
gateway-side presentation, and Core stops accepting them within its JWKS-cache window
plus the access TTL.

Routine rotation MUST pre-publish: a key that is about to become active MUST have its
`kid` published — present in the keyset, hence in the JWKS — for at least the
deployment's Core JWKS-cache window before it signs, so no minted token ever carries a
`kid` a verifier's cache may not hold. The rotation procedure is therefore staged:
add the new key as a retained entry (published, not signing), wait out the cache
window, then promote it to active and demote the old key to retained; the drain
completes when the last old-key token expires, after which the old entry is removed.

*Amendment, declared:* the requirement gains the blank-equals-unset rule (a blank —
empty or whitespace-only — singular value is unset; the composition path's explicit
forwarding of every setting never configures the spelling; the exclusivity refusal
fires only on a real value) and its scenario — added after the rotation drill stopped
in play on the composed stack, the structured spelling unreachable through the
documented procedure because the always-forwarded blank singular counted as configured
(`docs/evidence/c3/rotation-drill.md`).

#### Scenario: Overlap rotation keeps every outstanding token working

- **WHEN** the active signing key is rotated through the staged procedure — the new key added as retained and published, the cache window waited out, the new key promoted to active with the old key demoted to retained
- **THEN** tokens minted before the rotation verify and refresh through the drain window, tokens minted after carry the new `kid`, and the JWKS document carries both `kid`s throughout, the active entry first

#### Scenario: A new key is pre-published before it signs

- **WHEN** a rotation runs
- **THEN** between the new `kid`'s first publication in the JWKS and the first token signed under it, at least the deployment's Core JWKS-cache window elapses — no token is ever minted under a `kid` that has not been published for that window

#### Scenario: Removing a retained entry is the immediate cut

- **WHEN** a retained entry is removed while tokens signed under it are still within their own expiries, and such a token is presented
- **THEN** the gateway refuses it at verification, and Core refuses it within its JWKS-cache window plus the access TTL — the emergency path, available at any moment of the drain window

#### Scenario: A kms-sourced entry refuses startup naming the gap

- **WHEN** a keyset entry carries the reserved source `kms`
- **THEN** the gateway refuses to start with an operator-facing error naming the gap — the KMS sign-interface is not built — never a silent ignore and never a fallback to another source

#### Scenario: Zero or multiple active entries refuse startup

- **WHEN** a signing keyset is configured with no active entry, or with more than one
- **THEN** the gateway refuses to start with an operator-facing error naming the keyset and the violation — exactly one entry signs

#### Scenario: A file-sourced entry loads from its configured path

- **WHEN** a keyset entry names a `file` source and the file holds a readable, unencrypted RSA private key of at least the minimum size
- **THEN** the entry loads at startup and behaves as any other entry of its role; an unreadable or unparseable file refuses startup with an operator-facing error naming the path and never the content

#### Scenario: A source-heterogeneous keyset is valid

- **WHEN** a keyset holds a retained `env`-sourced entry beside an active `file`-sourced entry
- **THEN** the keyset is accepted — the source is per-entry, so the later migration to a KMS-sourced active key is a rotation beside retained injected keys, not a redesign

#### Scenario: Duplicate derived kids refuse startup

- **WHEN** two keyset entries hold material that derives the same `kid`
- **THEN** the gateway refuses to start with an operator-facing error naming both entries — one `kid` naming two entries, whether the same key under two names or two distinct keys colliding in the truncated hash, is a keyset that miscounts its own keys, and the refusal closes both shapes

#### Scenario: The single-key spelling remains the no-rotation shape

- **WHEN** the gateway is configured with the singular signing-key setting alone — the pre-keyset shape — and no keyset setting
- **THEN** it starts and signs exactly as before: one active `env`-sourced entry, no retained entries; the two settings configured simultaneously refuses startup with an operator-facing error naming both

#### Scenario: A blank singular spelling is unset on the composition path

- **WHEN** the singular setting arrives blank — empty or whitespace-only — while the structured keyset setting carries a document, on a deployment that fronts every setting explicitly so an absent value arrives as an empty string
- **THEN** the singular counts as unset and the gateway starts on the structured keyset — the both-configured refusal fires only when the singular carries a real value

### Requirement: A live rotation drill gates the keyset semantics' completion

Before this change is done, a live rotation MUST be performed on the composed stack in
the production-image, pod-shaped configuration, for **each keyset** — the signing
keyset and the custody keyset — with captured evidence, and the drill's instrument
MUST be proven able to fail first: a negative control (a deliberately wrong
expectation, such as asserting an old-`kid` token still verifies after the retained
entry is removed) runs before any verdict from the drill is trusted. The rotation
procedures and their bounds are the keyset requirements' own; the drill is their live
proof and the recorded rehearsal of the future env→KMS migration (AWS asymmetric keys
cannot be imported — a new `kid` is inherent to that migration; Azure import can
preserve it — the same overlap procedure carries both).

The signing leg of the drill MUST show, with evidence: tokens obtained under the old
key before rotation; the staged rotation run (pre-publish, cache window waited out —
the wait itself observed or bounded in the evidence — promotion); old-key access
tokens accepted at Core and old-key refresh tokens refreshing successfully through
the drain window, each rotated refresh token minted under the new `kid`; new sign-ins
minting new-`kid` tokens accepted at Core throughout; and, after the drain bound, the
retained entry removed and old-key tokens refused. The custody leg MUST show: refresh
sessions live across a custody-key rotation with the old key retained — each
presentation decrypting under the retained key-id and each replacement envelope
sealed under the new active key-id — and the emergency cut rehearsed: a retained
custody key removed mid-window, its outstanding refresh tokens refusing at next
presentation with the custody refusal class.

The captured evidence MUST carry public facts and fixed vocabularies only — `kid`s,
key-ids, JWKS snapshots, audit records, probe verdicts — never key material, never
token strings, never envelope contents.

#### Scenario: The drill's rotation window passes with evidence

- **WHEN** the drill runs the staged rotation of each keyset on the live stack and the evidence is read
- **THEN** it shows old tokens draining gracefully, refresh sessions surviving and re-sealing under the new keys, new tokens accepted throughout, and no refusal attributable to the rotation itself — the Core JWKS-cache window respected and observed in the evidence

#### Scenario: The negative control runs first and fails

- **WHEN** the drill's instrument is proven before the rotation verdicts are trusted
- **THEN** a deliberately wrong expectation (an old-`kid` token asserted to verify after its retained entry is removed) is run first and fails — the instrument can fail, so its pass is a verdict

#### Scenario: The emergency cut is rehearsed mid-window

- **WHEN** the drill removes a retained entry while tokens it signed or sealed are still within their expiries
- **THEN** the evidence shows the immediate refusal — signing-key tokens refused at verification and at Core within the cache window, custody-carried refresh tokens refused at next presentation in the custody refusal class — the routine drain and the emergency cut are both proven, not one presumed from the other

## MODIFIED Requirements

### Requirement: The identity provider's session refresh token is carried encrypted in the gateway's refresh token

The identity provider's session-bound refresh token MUST be carried for the refresh window as an encrypted claim inside the gateway's own refresh token, and `offline_access` MUST NOT be requested on any leg — no offline (beyond-session) grant is ever acquired; what is carried is a rotating handle to the user's live identity-provider session, and the gateway's refresh capability ends when that session ends. There is no long-lived per-session server-side store. The carrier is the refresh token only: the encrypted claim MUST NOT appear in the access token — which rides the Authorization header of every MCP data-path call and is not even reliably presented at a refresh — nor in the authorization code or any other client-visible artifact. The envelope is pinned: AES-256-GCM under a 256-bit key with a 96-bit random nonce, laid out as version | key-id | nonce | ciphertext‖tag, base64url-encoded; the algorithm and the lengths are code constants, never read from the envelope, and an envelope whose version or key-id is unknown fails closed. The envelope embeds its own `sub` and `exp`, and both are checked at the custody seam before any use: the embedded `sub` MUST equal the refresh token's signed subject — a blob swapped between users' tokens refuses — and an expired envelope refuses. The key is a dedicated 256-bit symmetric key, separated from the signing key, identified by key-id; the keyset's startup validation refuses an empty keyset, a keyset with no active entry, a multi-active keyset, and any key that is not exactly 32 bytes — AES-GCM's algorithm follows the key's length, so a shorter key would silently run AES-128 or AES-192 and falsify the pinned algorithm. Each keyset entry carries a source — `env` or `file` implemented, `kms` a reserved value refused at startup with an operator-facing error naming the gap — and the keyset MAY hold retained keys beside the one active key: sealing is always under the active key, and decryption accepts the active or a retained key, the envelope's key-id selecting the entry, with the header still bound into the AEAD's associated data so a header transplanted between envelopes fails the tag under whichever key it names. A superseded key retained for the drain window — bounded by the refresh token's non-sliding absolute expiry — keeps every outstanding refresh token working through a routine rotation, and each such refresh re-seals the carried credential under the active key in the replacement token; removing the retained entry is the immediate cut, the operator's explicit emergency path rather than the routine outcome, and its refusal is this requirement's own custody refusal class. Between flow end and the code grant the token lives in a pending entry keyed by the authorization code's id — created when the code is minted at flow end, on both flow paths, bounded by the code's own short TTL, consumed when the code grant issues a refresh token, and dropped when the code expires unredeemed; the token MUST NOT be carried in the authorization code's payload or any other client-visible artifact, in plaintext or as ciphertext, because the code is a signed-but-unencrypted JWT whose payload anyone holding the code string can read, and this token is mintable credential material. At the code grant the provider token is encrypted into the issued refresh token; at every refresh the grant decrypts it, presents it to the provider, and re-encrypts the provider's latest token — latest-wins across the provider's own rotations — into the newly rotated refresh token; a grace-window presentation of a pre-rotation token carries its own stale blob and fails at the provider where the provider rotates per grant. The token's plaintext MUST NOT be logged and MUST NOT be delivered to any client; the ciphertext is delivered inside the refresh token by design and is unusable without the custody key. The identity provider's access token is not retained past the flow: it serves the flow's decision step and credential call and is discarded at flow end. A restart loses nothing the harness does not bring back: the encrypted claim returns with the presented refresh token, so refresh capability survives restarts and rollouts, and already-minted access and refresh tokens keep working until their own expiries because they are self-contained — while the minutes-bounded pending entries are lost, so an unredeemed code issued before the restart fails its grant the same fail-closed way.

*Amendment, declared:* the requirement's keyset clause is re-worded — the hard cut becomes the overlap semantics. "Its rotation is a hard cut — a superseded key is never retained to accept, so every outstanding refresh token fails closed at its next presentation after a rotation, a wave bounded by the refresh token's non-sliding absolute expiry" becomes the per-entry-source sentence and the retained-keys sentence (seal under the active key; decrypt with active-or-retained, the envelope's key-id selecting; the drain window bounded by the non-sliding absolute expiry; removal of a retained entry as the immediate cut) — because routine rotation was specified to cost the same as a compromised-key response, which trains operators not to rotate, and the rulings fix the overlap semantics for both keysets. The startup-validation clause gains the no-active refusal and the per-entry source with its reserved-`kms` refusal. One retained scenario is re-scoped — "Custody-key rotation is a hard cut" keeps its name and moves its subject from routine rotation (no longer a cut) to the cut itself: the superseded key's removal, immediate or mid-drain, which is the same fail-closed shape the scenario always carried, now the operator's explicit path rather than the routine outcome — because routine rotation is a drain under the overlap semantics, and the scenario's name must keep naming something true. One retained scenario gains a clause ("Rotation carries the custody, in both directions" names the active key as the sealing key across a rotation). Four scenarios are added (the retained-key decrypt with active-key seal, the `kms` refusal, the flat compat spelling, the no-active refusal). The retained scenarios are otherwise unchanged and carried verbatim.

#### Scenario: The carried credential ends with the refresh session

- **WHEN** a refresh token expires or is revoked
- **THEN** the gateway never presents its carried credential again — expiry refuses the token, and revocation refuses by id before the claim is ever touched — and the ciphertext that persists in the harness's store is inert without the custody key and dies with the provider's session

#### Scenario: The hand-off never crosses the client

- **WHEN** a flow completes and the authorization code is issued to the harness
- **THEN** the code's payload carries no identity-provider credential of any kind, plaintext or ciphertext, and the provider's session refresh token exists only in the server-side pending entry keyed by the code's id until the code grant consumes it

#### Scenario: The carrier is the refresh token only

- **WHEN** the code grant issues tokens
- **THEN** the encrypted custody claim appears in the refresh token and in no other issued artifact — not the access token, not the authorization code

#### Scenario: Rotation carries the custody, in both directions

- **WHEN** a refresh rotates and the replacement token is issued, and the provider's refresh grant returned a new refresh token of its own
- **THEN** the replacement carries the provider's latest refresh token re-encrypted under the current active custody key — the active key alone sealing, whichever key decrypted — and the replaced token's blob is not accepted outside the grace window

#### Scenario: A grace-window presentation carries its own stale blob

- **WHEN** a client presents a pre-rotation refresh token inside the grace window, and the provider rotates its refresh token per grant
- **THEN** the presentation fails at the provider — the token's own carried blob is stale, each token is self-consistent, and the failure lands in the session-ended refusal class

#### Scenario: Custody-key rotation is a hard cut

- **WHEN** a custody-key rotation is completed as a cut — the superseded key removed from the keyset rather than retained, at the rotation itself or mid-drain — and outstanding refresh tokens carrying claims sealed under it are presented
- **THEN** each refuses fail-closed with the custody reason at its next presentation, and the re-sign-in wave is bounded by the refresh token's original absolute expiry — the cut is the operator's explicit act under the overlap semantics, never the routine rotation's outcome

#### Scenario: A retained envelope decrypts and the active key seals

- **WHEN** a refresh token's custody claim carries a retained key's key-id and the refresh grant runs
- **THEN** the claim decrypts under that retained key while the replacement envelope is sealed under the active key alone — decryption may look back through the drain window, sealing never does

#### Scenario: A kms-sourced custody entry refuses startup naming the gap

- **WHEN** a custody keyset entry carries the reserved source `kms`
- **THEN** the gateway refuses to start with an operator-facing error naming the gap — the KMS envelope interface is not built — never a silent ignore and never a fallback

#### Scenario: The flat single-key spelling remains the compat shape

- **WHEN** the custody keyset is configured in the pre-keyset flat spelling — key-id to base64 key, no source or role members
- **THEN** it is accepted as exactly one active `env`-sourced entry with no retained entries; a document mixing the flat and structured spellings refuses startup with an operator-facing error naming the keyset

#### Scenario: A custody keyset with no active entry refuses startup

- **WHEN** a structured custody keyset holds only retained entries
- **THEN** the gateway refuses to start with an operator-facing error naming the keyset — exactly one key seals

#### Scenario: The plaintext is never logged or delivered; the ciphertext never logged

- **WHEN** the gateway carries the provider's session refresh token
- **THEN** no log record or stored file carries the plaintext, no client response carries the plaintext, the ciphertext never reaches a log record, and the ciphertext appears only inside the refresh token delivered to its presenting client

#### Scenario: No offline grant is ever requested

- **WHEN** the gateway's client requests its scopes on the identity-provider leg
- **THEN** `offline_access` is never among them, and no offline token is ever issued to the flow

#### Scenario: Restart survives the custody, not the pending entries

- **WHEN** the gateway restarts with refresh sessions live
- **THEN** already-issued refresh tokens keep refreshing — the encrypted claim returns with the presented token — already-minted access tokens keep working, and an unredeemed authorization code issued before the restart fails its grant fail-closed

### Requirement: Inbound tokens are verified with pinned algorithm and key selection

Inbound JWT verification MUST pin the algorithm and the key selection, so a token's header can select neither. The gateway's own tokens — codes, access tokens, refresh tokens — are verified against the gateway's own signing keyset under the pinned algorithm, with the issuer checked: the token's `kid` selects the entry — the active key or a retained key — and a token whose `kid` names no entry of the keyset is refused as not issued by this gateway, so the `kid` is a selector within the keyset, never a source of key material and never a fetch. The identity provider's tokens are verified under a pinned algorithm and the configured issuer, with the `kid` resolved only in that provider's own published key set — the key set the provider's discovery document names — origin-bound, like every discovered endpoint — or, where the operator configures the endpoints directly, the key-set URL the operator configures; key material embedded in a token header is never used. A token whose header carries no `kid` resolves to the provider's first published RSA signing key — the behavior the implementation has, stated so a from-spec reimplementation cannot silently refuse such tokens; with a single-key key set the resolution is unambiguous, and across rotation its failure mode is fail-closed (a mismatched resolution fails verification, never accepts a forgery kid-resolution would refuse). The issuer check is exact-string against the configured issuer: a provider whose issuers vary across its sign-in journeys — the issuer embedding the journey that issued the token — has the one federated journey's issuer configured, and a token whose issuer differs in any way — another journey's issuer of the same provider included — MUST be refused as not issued by the configured provider.

*Amendment, declared (retained):* the requirement gains the endpoint-source key-set resolution clause ("the key set the provider's discovery document names — origin-bound, like every discovered endpoint — or, where the operator configures the endpoints directly, the key-set URL the operator configures"; the origin-bound qualifier belongs to the discovery alternative only — the operator-configured key-set URL is operator input at the issuer setting's own trust level, not a discovered endpoint) and the varying-issuer pinning sentence with its scenario — because the key set's location is the leg's one configured source's to name (the discovery document's in discovery mode, the operator's in direct mode), and issuers that vary across a provider's sign-in journeys are the shape that sentence covers. The refusal is gateway-side by construction: the pin is exact-string against the configured issuer, and no token and no discovery document can widen it; whether another journey's tokens carry a distinct issuer at all is provider-configuration — the provider must issue journey-distinct issuers for its journeys to be distinguishable by the pin (an operator prerequisite the change's configuration reference states, not a property this spec grants). The pinned-algorithm and no-kid rules are unchanged.

*Amendment, declared:* the requirement's own-tokens clause is re-worded — "verified against the gateway's own signing key under that key's pinned algorithm" becomes "verified against the gateway's own signing keyset under the pinned algorithm", with the `kid`-selects-within-the-keyset rule and the unknown-`kid` refusal — because the single-key shape becomes a keyset with active and retained entries (the signing-keyset requirement, this change), and own-token verification must accept the retained entries through the drain window while remaining pinned (the algorithm stays pinned; the `kid` selects within a startup-fixed keyset, never fetches). One retained scenario is re-worded — "Embedded key refused": "checks the signature against the pinned key only" becomes "checks the signature against the pinned key set's selected entry only, never header-carried material" — because the pin is now a keyset on the gateway's own side, the same re-wording the own-tokens clause carries; the scenario's property is unchanged, whichever side pinned the key material. Two scenarios are added; the remaining retained scenarios are unchanged and carried verbatim.

#### Scenario: Algorithm confusion refused

- **WHEN** a presented token carries an algorithm other than the pinned one — `alg: none` included
- **THEN** verification refuses it; the algorithm is never taken from the token

#### Scenario: Embedded key refused

- **WHEN** a token's header carries its own key material — an embedded `jwk` or `x5c`
- **THEN** verification ignores it, checks the signature against the pinned key set's selected entry only, never header-carried material, and refuses the token

#### Scenario: `kid` outside the provider's key set refused

- **WHEN** an identity token's `kid` names a key absent from the issuing provider's own published key set
- **THEN** the lookup fails and the token is refused as not issued by that provider

#### Scenario: Key set resolved from the leg's one endpoint source

- **WHEN** the identity provider's tokens are verified
- **THEN** the key set they are resolved against is the one the leg's configured source names — the discovery document's in discovery mode, the same source the token and authorization endpoints come from; the operator-configured key-set URL in direct mode — never a URL built by provider-specific arithmetic

#### Scenario: A token from another journey's issuer refused

- **WHEN** the identity provider's issuers vary by sign-in journey, and a token arrives whose `iss` names any issuer other than the configured one — another journey of the same provider included
- **THEN** verification refuses it: the configured issuer is the one this deployment federates, and no other journey's token is accepted by it

#### Scenario: A retained-key token verifies through the drain window

- **WHEN** a gateway-issued token signed under a key demoted to retained is presented while the entry is still in the keyset
- **THEN** verification accepts it — the `kid` selects the retained entry, the algorithm is the entry's pinned one, the issuer check unchanged — the drain window's whole point

#### Scenario: An unknown `kid` on an own token is refused

- **WHEN** a token presented as the gateway's own carries a `kid` that names no entry of the gateway's keyset — a removed retained key's `kid` included
- **THEN** verification refuses it as not issued by this gateway — the `kid` selects within the startup-fixed keyset and nothing else

### Requirement: The identity-provider client is confidential; the PKCE toggle governs the challenge only

The gateway's identity-provider client is a confidential client: the code exchange and the refresh grant MUST authenticate the client with the configured client secret on every identity-leg token request, in both positions of the leg's PKCE toggle — the modes are client secret plus PKCE, or client secret alone, and never PKCE alone. The gateway MUST refuse to start without a configured client secret in either position of the toggle, naming the setting: the secret is the client's authentication, not a mode-conditional compensating control, so no deployment runs without one. The configured client secret is delivered by exactly one of two spellings, both supported: the injected environment variable (`IDP_CLIENT_SECRET`) or a file at a configured path (`IDP_CLIENT_SECRET_FILE`, a read-only mount — the shape a mounted Secret file takes). Configuring both refuses startup with an operator-facing error naming both settings — exactly one spelling per secret, the same mixing refusal the keyset seam's settings carry; configuring neither is the missing-secret refusal above. A spelling is configured only by a real value, and the blank-equals-unset rule governs the forwarded **setting** values — the environment value, or the file-path setting: a **blank** environment value or file-path setting — empty or whitespace-only — is **unset**, so a deployment that fronts every setting explicitly never counts a blank-forwarded spelling as configured, and the both-configured refusal fires only when both spellings carry real values. The rule reads the setting values alone and never the file's content: a blank file at a real configured path stays the loud refusal below, not an unset spelling. A file source is read once at startup, and an unreadable or blank file refuses startup loudly, naming the path and never the content — the file loader's discipline, the keyset seam's `file` source carried to the one secret that sits outside the keysets. The two spellings are equivalent to the gateway: whichever delivers it, the secret's presentation, its never-logged discipline, and its token-leg-only audience are the ones this requirement states, and the boundary each spelling rests on is the deployment's to own. The toggle (`IDP_PKCE_ENABLED`, default on) governs only whether the S256 challenge rides on top of the client authentication: on (the default), the identity leg's authorization redirect carries an S256 `code_challenge` and the code exchange presents the verifier — the binding that protects the leg's code while it crosses the browser, composed with the client authentication; off, for a provider that cannot support PKCE, the redirect carries no challenge and the exchange presents no verifier — the client secret alone authenticates the leg's token requests. The secret is presented on the token leg only, to the leg's one endpoint source, and is never logged, never echoed in an error, never rendered on any page, and never delivered to any client, whatever the toggle's position and whichever spelling delivers it. The toggle changes nothing else: the client-facing AS surface keeps requiring PKCE from harness clients on every authorization request, the upstream leg's verifier stays Core's and untouched, and `offline_access` is never requested on any leg.

*Amendment, declared:* the requirement gains the secret's delivery clause (the owner-pause amendment round) — the two spellings (`IDP_CLIENT_SECRET` by environment variable, `IDP_CLIENT_SECRET_FILE` by read-only mounted file), exactly one configured per secret with the both-configured refusal naming both settings (the keyset seam's mixing-refusal style), and the read-once-at-startup file discipline with its loud refusal naming the path and never the content — because the pod's secret delivery needs the file spelling (the mounted-Secret shape) beside the environment variable, and the refusal styles the keyset seam already fixed are the ones this one secret outside the keysets carries. The closing never-logged sentence gains "whichever spelling delivers it" (and its scenario's WHEN the same phrase); the delivery clause states no preference between the spellings — the component requires run-time delivery and accepts both spellings, the deployment chooses between them, and the boundary price of each is the deployment's. A follow-up amendment (the rotation drill's stopped-in-play round, `docs/evidence/c3/rotation-drill.md`) adds the blank-equals-unset sentence — a blank environment value or file-path setting is unset, the rule governing the forwarded setting values and never the file's content at a real path, the both-configured refusal firing only on two real values — and its scenario (a blank file-path spelling unset while the environment spelling carries the real secret). Four scenarios are added in all across the amendment rounds (the file spelling accepted, the both-configured refusal, the unreadable-file refusal, the blank file-path spelling unset); the retained scenarios are otherwise unchanged and carried verbatim.

#### Scenario: A missing client secret refuses startup in either toggle position

- **WHEN** the operator starts the gateway with no client secret configured — or a blank one — whatever the position of the identity leg's PKCE toggle
- **THEN** the gateway refuses to start with an operator-facing error naming the setting — the secret is the client's authentication on every token request, in both modes, so no deployment runs without one

#### Scenario: The challenge-off mode runs as a secret-authenticated client without PKCE

- **WHEN** the operator disables PKCE on the identity-provider leg for a provider that cannot support it, and a sign-in runs
- **THEN** the identity-leg authorization redirect carries no `code_challenge`, the code exchange presents no verifier, and the code exchange and the refresh grant authenticate with the client secret — every other leg behaves exactly as the challenge-on mode's

#### Scenario: The default mode presents the client secret under the challenge

- **WHEN** PKCE is enabled on the identity-provider leg (the default) and a sign-in or a refresh runs
- **THEN** the authorization redirect carries the S256 `code_challenge`, the code exchange presents the verifier, and the code exchange and the refresh grant authenticate with the client secret — client authentication and PKCE together, both bindings on, in the default mode as in the challenge-off one

#### Scenario: The client-facing surface still requires PKCE

- **WHEN** a harness sends the gateway's own authorization endpoint a request without a `code_challenge`, whatever the identity-leg toggle's position
- **THEN** the gateway refuses it — the challenge-off mode is the identity leg's alone, and the client-facing AS surface's PKCE requirement is unchanged

#### Scenario: The client secret never reaches an output

- **WHEN** the gateway logs, audits, or renders an error on the identity leg, in either toggle position and whichever spelling delivers the secret
- **THEN** no record, page, or message carries the client secret — a provider refusal naming the client is recorded by its fixed-vocabulary class, never by the credential it refused

#### Scenario: The file-delivered secret authenticates exactly as the environment-delivered one

- **WHEN** the client secret is configured by the file spelling alone — `IDP_CLIENT_SECRET_FILE` naming a readable file on a read-only mount — and a sign-in or a refresh runs
- **THEN** the secret loads once at startup and authenticates every identity-leg token request exactly as the environment-variable spelling would — the two spellings are equivalent to the gateway, whichever the deployment chooses

#### Scenario: Both delivery spellings configured refuses startup naming both

- **WHEN** both `IDP_CLIENT_SECRET` and `IDP_CLIENT_SECRET_FILE` are configured
- **THEN** the gateway refuses to start with an operator-facing error naming both settings — exactly one spelling per secret, the same mixing refusal the keyset seam's settings carry

#### Scenario: An unreadable secret file refuses startup naming the path

- **WHEN** the file spelling is configured and the path is unreadable or the file blank
- **THEN** the gateway refuses to start with an operator-facing error naming the path and never the content — the file loader's discipline, the keyset seam's `file` source carried to the one secret that sits outside the keysets

#### Scenario: A blank file-path spelling is unset on the composition path

- **WHEN** the file-path setting arrives blank — empty or whitespace-only — while the environment spelling carries a real secret, on a deployment that fronts every setting explicitly so an absent value arrives as an empty string
- **THEN** the file spelling counts as unset and the gateway starts on the environment-delivered secret — the both-configured refusal fires only when both spellings carry real values, and the loader is never sent to a blank path
