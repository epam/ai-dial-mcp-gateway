# Owner-pause amendments — round 2 (PROCESS step 3c)

The owner reviewed the complete package at the pause and requested four amendments;
this record is what the amendment authoring round did with each. The round ran
authoring-only: no implementation, no commits — the package returns to the
re-pause with the amendments folded in, and task 0.1's go gates the amended shape.

## Amendment 1 — the pod contract's security-context section

**What was asked:** the contract (`docs/pod-contract.md`, a task deliverable) gains
a security-context section, and the delta's pod-contract requirement gains a MUST
clause + a scenario stating the assembly's required K8s controls — `runAsNonRoot`
with `runAsUser`/`runAsGroup` 10001 (the image's fixed uid, which the DCR store's
file ownership depends on), `fsGroup` 10001 on the store's volume (a world-writable
mount is the tamper path to refuse), `allowPrivilegeEscalation: false`,
capabilities dropped ALL (viable because nothing in the pod binds a privileged
port — stated as the assumption that keeps it true), `readOnlyRootFilesystem: true`
with `emptyDir` for the router's temp/log paths, `seccompProfile: RuntimeDefault` —
priced into the existing DT-EP6-1 mis-assembly row's control set, not a new threat.

**What changed where:**
- Delta spec (`specs/mcp-signin/spec.md`): the pod-contract ADDED requirement gains
  the security-context paragraph (a MUST clause with all six controls, the
  no-privileged-port assumption stated where it lives, and the
  contract-violation-not-preference framing priced at DT-EP6-1) and the scenario
  "The security context's controls are stated as the assembly's requirements"; the
  requirement's MUST-state enumeration gains "the pod's required security context"
  (and the deployment diagram, amendment 3).
- `design.md`: D10 records the amendment; DT-EP6-1's grid row gains the
  security-context relaxation shapes (root/escalating container, kept capability,
  writable root, world-writable store mount) and the controls in its bounded-by
  set; DT-EP6-1's mitigation list extends categories 1, 2, and 5 with the
  controls; §6 item 4 and §7's EP6 bullet carry the same.
- `tasks.md`: 5.1 gains the security-context section's content; 1.1 and 1.2 carry
  the threat-model-side landing (the mis-assembly row's control set, M35's
  content).
- `proposal.md`: the pod-contract bullet (What Changes), the Modified-Capabilities
  parenthetical, and the Impact line gain the security context.
- `release-notes-draft.md`: both sections state it.

## Amendment 2 — governance / storage-class statements

**What was asked:** the contract's volume-mount section and the delta's
pod-contract requirement gain (a) the DCR store's backing MUST be a cloud-backed
persistent-volume storage class — tenant-governable, surviving node loss — never
node-local ephemeral storage; (b) backup/export as deployment-owned (a single
human-readable JSON file with atomic-replace writes, so a point-in-time copy is a
consistent export — no gateway cooperation, no new API); (c) the no-secret-content
rule stated as load-bearing (the store MUST NOT gain secret-class content without
re-opening its boundary analysis; the property is what makes the external
governance reader class cheap; same logic for the future wrapped-CEK file,
ciphertext by design). SIA coherence: the governance reader class lands as a
bounded reader extension inside DT-EP7-1's row, not a new threat.

**What changed where:**
- Delta spec: the pod-contract requirement's mount clause gains the three
  statements; the scenario "The store's storage class and export story are stated"
  is added.
- `design.md`: D10 records the amendment; DT-EP7-1's grid row gains the
  storage-class requirement, the deployment-owned export story, the bounded
  governance-reader extension (the no-secret property as the control), and the
  wrapped-CEK future resident; DT-EP7-1's mitigation list extends categories 1 and
  5; §6 item 4 and §7's EP7 bullet carry the same.
- `tasks.md`: 5.1 gains the three statements' content; 1.1 carries the
  threat-model-side landing.
- `proposal.md` and `release-notes-draft.md`: stated in the same places as
  amendment 1.

**The owner's mid-round correction, applied here (recorded under amendment 4's
disposition below and in D10):** the cloud-backed persistent-volume requirement
stays a REQUIREMENT, stated by its properties (survives node loss, rests in a
tenant-governable resource); no specific class, mechanism, or product is named —
managed disks, file shares, CSI drivers, backup tooling, and destinations are
DevOps's choice. The contract names the requirement, not the product.

## Amendment 3 — the deployment diagram

**What was asked:** `docs/pod-contract.md` gains a renderer-independent ASCII
diagram inside the markdown — the pod as one box (router: nginx, the versioned conf
read-only, the single public port at the cluster-ingress TLS boundary → sibling
localhost `127.0.0.1:8091` → gateway: uid 10001, one internal unpublished port);
the mounts (the DCR store's durable volume — cloud-backed class, the pod's one
state mount, the future wrapped-CEK file named as the future second resident; the
read-only key-file mounts); the secret paths (KeyVault/Secrets Manager → K8s
Secrets → env vars / mounted files → the signing keyset, the custody keyset, the
IdP client secret); the neighbors (the harness via ingress; DIAL Core with the MCP
data path drawn bypassing the gateway entirely; the identity provider with its
back-channel legs); the reserved `source: kms` as a dashed future arrival; and the
stated assumptions drawn where they live. A task for it.

**What changed where:**
- `tasks.md`: new task 5.2 carries the diagram with its full required content (the
  old 5.2/5.3/5.4 renumbered to 5.3/5.4/5.5); 5.1 names the diagram as contract
  content.
- Delta spec: the requirement's MUST-state enumeration gains "a deployment diagram
  of the assembly (renderer-independent, readable as plain text)" — the diagram is
  spec-gated as contract content, its detail is the task's.
- `design.md`: D10 records the amendment with the content list; D1 points to D10.
- `proposal.md` and `release-notes-draft.md`: stated.

## Amendment 4 — `IDP_CLIENT_SECRET` gains a file spelling

**What was asked:** the identity-leg requirement (the confidential client's
secret) is extended — the secret MAY be delivered by environment variable or by
file (a read-only mount, the K8s default Secret shape), exactly one of the two
configured; both configured refuses startup naming both settings (the keyset
seam's mixing-refusal style); a file source is read once at startup, refused
loudly on an unreadable path naming the path never the content; the exact new
setting name stated in the delta and in `.env.example`'s placeholder; the pod
contract's classified env-var surface table gains the setting; the contract's
guidance states file-mount is the recommended production delivery. SIA coherence:
DT-EP4-4's row extends to cover the IdP client secret's file spelling rather than
a row being added.

**The setting name chosen: `IDP_CLIENT_SECRET_FILE`.** The `_FILE` suffix follows
the keyset seam's `ref` discipline — the base spelling names the value, the `_FILE`
spelling names the path that carries it — and is self-describing against the
existing `IDP_CLIENT_SECRET` (the pattern the wider ecosystem also uses for
mounted-Secret delivery). Stated in the delta's requirement text and amendment
note, in task 2.8 (the settings implementation), in task 5.4 (the `.env.example`
placeholder: `IDP_CLIENT_SECRET_FILE=`), and in task 5.1 (the env-var surface
table's row).

**The owner's mid-round correction — drop all "recommended" language.** The
owner corrected the amendment as first drafted: the contract does not recommend a
delivery spelling — DevOps know K8s and choose the how in their managed cluster
and cloud; the contract declares (a) what the component REQUIRES and (b) HOW it
CAN be delivered. Applied everywhere the round's edits might compare env vs file
favorably: the contract's secret-delivery content (task 5.1) states requirements
only (run-time-only delivery, never baked, never in the repo; two spellings per
secret with exactly one configured; read-only mounts; the uid-10001/fsGroup
ownership constraints) and the options neutrally — "environment variable or
mounted file, both supported" — with no preference, no "recommended", no
default-shape guidance. The delta's delivery clause states the two spellings are
equivalent to the gateway and the boundary price is the deployment's; the design
(D10) and the release notes carry the same neutrality. The component's honest
position, recorded: the two spellings are equivalent to the gateway; the boundary
price is the deployment's.

**What changed where:**
- Delta spec: a new MODIFIED block for "The identity-provider client is
  confidential; the PKCE toggle governs the challenge only" — the delivery clause
  (two spellings, exactly one, the mixing refusal, the read-once file discipline,
  the equivalence statement), a declared amendment note, the five retained
  scenarios carried verbatim (the never-logged scenario's WHEN gaining "whichever
  spelling delivers it", declared in the note), and three added scenarios (the
  file spelling accepted and equivalent; both configured refuses naming both; the
  unreadable file refuses naming the path).
- `design.md`: D10 records the amendment, the name choice, and the correction;
  DT-EP4-4's grid row and mitigation list extend to cover the IdP secret's file
  spelling (same class, new location); §1's implementation shape, §3's invariant
  row 5, §6 item 4, and §7's EP4/residuals bullets carry the same.
- `tasks.md`: new task 2.8 (the settings implementation + unit tests); 5.1 gains
  the env-var-table row and the neutral delivery statements; 5.3 documents the two
  spellings; 5.4 carries the `.env.example` placeholder and the existing comment's
  re-wording (its "never a file the gateway reads" clause becomes the
  two-spellings statement).
- `proposal.md`: a new What-Changes bullet; the Modified-Capabilities paragraph
  (now three requirements MODIFIED); the Impact lines for `gateway/settings.py`,
  `.env.example`/`docs/gateway-configuration.md`, and `docs/pod-contract.md`.
- `release-notes-draft.md`: a user-facing bullet (neutral) and the team-facing
  seam bullet.

**One boundary note, recorded:** the round is authoring-only, so `.env.example`
itself was not edited — the exact name and the placeholder shape are stated in the
delta and in task 5.4's text, which is what implements the file when the pause
lifts. The same holds for every implementation-surface file named above.

## The mechanical gates after the round

- `openspec validate one-pod-and-keysets` — green ("Change 'one-pod-and-keysets'
  is valid"), exit 0.
- `openspec validate --all` — 2 passed, 0 failed (INFO-only requirement-length
  notices, the pre-existing style of the whole spec — the new MODIFIED block's
  length notice is the same class), exit 0.
- `python scripts/check_publication_leaks.py` (PYTHONUTF8=1) — PASS, exit 0: 3
  findings, all waived in the committed baseline, none new. The round's new text
  uses public vocabulary and repo-relative paths only; the secret-delivery content
  names settings and mount shapes, never values.
