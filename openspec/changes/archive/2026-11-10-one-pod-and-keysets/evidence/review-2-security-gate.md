# Review 2 — the security review gate (PROCESS step 8, task 7.4)

Change: `one-pod-and-keysets` (C3). Reviewer: an independent security-review subagent
(not the implementer). Scope: the diff `846017d..7baa971` (origin/master → the change's
HEAD), at the SIA's recorded **Medium** depth — full depth on the keyset mechanics, the
pod-contract statements against the mis-assembly shapes, and the drill's evidence against
its scenarios. The orchestrator-touched stretch inside `6b5ee1c` (ruff triage, the
assert→cast replacement in `settings.py`'s custody-keyset builder, named test constants)
was reviewed as part of the diff with no assumption of prior review.

**Verdict: PASS.** No blocking findings. Two should-fix (one documentation consistency,
one functional edge on a new surface), four notes. The falsification target the SIA names
— that the retained-key windows are priced and bounded as designed — **held** under every
attempt to break it.

## 1. The falsification pass (the SIA's named target, and the escapes attempted)

The primary target: **the retained-key windows are priced and bounded as designed.** Each
attempt below states what was tried and what held.

1. **Can a retained signing entry sign? — NO (held).** Every mint call site
   (`gateway/codes.py:147`, `gateway/tokens.py:236,287`, `gateway/token.py:296,318,560,752`,
   `gateway/flow.py:437`) receives `runtime.signing_key`, the property returning
   `signing_keyset.active` (`gateway/runtime.py:60-66`). `SigningKeyset.active` is
   `_entries[0]` and `load_signing_keyset` partitions active-first from the validated
   entries (`gateway/keys.py:290-292`), so no code path can hand a retained key to a
   signer. Exhaustive grep over `gateway/` found no other holder of keyset entries used
   for minting.
2. **Does every signing consumer read sign-active-only? — YES (held).** Verification and
   the JWKS go through `signing_keyset` (kid-selected; every entry published); minting goes
   through `signing_key` (the active). No consumer bypasses the split.
3. **Can a retained custody key seal? — NO (held).** The only two seal sites
   (`gateway/token.py:376,760`) call `runtime.custody_keyset.encrypt`, which delegates to
   `self._active` alone (`gateway/custody.py:303`). Decrypt alone selects by the
   envelope's key-id across active-or-retained (`gateway/custody.py:314-335`).
4. **Does the kid selection have an escape? — NO (held).** A token with no `kid`, a
   non-string `kid`, or an unreadable header returns `None` and refuses as "not issued by
   this gateway" (`gateway/keys.py:188-202`, incl. the `isinstance(kid, str)` guard); a
   duplicated derived `kid` inside one document refuses at load (`gateway/keys.py:277-285`)
   — covering both the same-key-twice and the truncated-hash-collision cases, since the
   `kid` is a 16-hex-character sha256 over the public numbers; the algorithm is pinned
   per entry (`algorithms=[key.algorithm]`, `gateway/tokens.py:348-356`, `gateway/codes.py`)
   so a token's header selects neither algorithm nor key material. `decode_code` went
   through the same keyset selection (verified in the diff).
5. **Does the JWKS ever omit the active key or publish a removed entry? — NO (held).**
   `jwks()` maps every entry, active first (`gateway/keys.py:204-210`); the keyset is
   startup-fixed, removal is a restart, and the JWKS is exactly the configured set.
   `tests/test_keyset.py:409` pins both the ordering and the public-only member set
   (`{kty, use, alg, kid, n, e}`).
6. **Does the blank→None normalization create a hole? — NO hole found.** A blank or
   whitespace-only singular signing key normalizes to unset so the exclusivity refusal
   fires only on a real value (`gateway/settings.py:1418-1427`; the defect cycle's fix,
   `1b91c64`); a blank file-path spelling normalizes the same way (`:1404-1412`); a blank
   structured document parses to `{}` via the shared JSON validator; and the
   `SecretStr("")` default on `idp_client_secret` is resolved to a non-blank value by
   `_resolve_client_secret` (`:1063-1105`) before any consumer reads it — the only reads
   are the resolver itself and the identity leg's presentation. One residual on the file
   spelling is finding 2 below (whitespace *around* a non-blank value, not blankness).
7. **Can a custody key-id be duplicated to shadow the active key? — unreachable.** The
   `CustodyKeyset` map would let a retained key overwrite an active entry with the same
   key-id, but custody key-ids are the JSON document's own keys — unique by construction —
   so no document can produce the collision. No other construction site exists.
8. **Per-user isolation through the keyset seam (invariant #3) — CONFIRMED.**
   `CustodyKey.decrypt` re-checks the carried key-id against its own (`gateway/custody.py:208-215`),
   binds the clear header into the AEAD's associated data (`:221,251-257`), and checks the
   embedded subject against the signed subject (`:235-238`) — per entry, unchanged. A
   header transplanted between envelopes fails the tag under whichever key it names; the
   retained key decrypts only blobs already bound to their subject.

## 2. The invariant ruling table — all seven verified

| # | Invariant | Verdict | Basis |
|---|---|---|---|
| 1 | Upstream credential never leaves Core | Preserved — confirmed | The custody envelope's carrier and layout are byte-identical (version/length/key-id header + nonce + sealed); only the key-id's *meaning* widened (selects an entry). No leg carries anything new. |
| 2 | Upstream PKCE verifier never leaves Core | Preserved — confirmed | The upstream leg is untouched in the diff. |
| 3 | Per-user credential isolation | Preserved — confirmed | Falsification 8 above: the subject check and AAD binding are per-entry. |
| 4 | DIAL authorization on every toolset call | Preserved — confirmed | Mint paths unchanged except which key signs; claims, `sub`, and Core's per-call authorization untouched. |
| 5 | No credential in logs/argv/errors | Preserved — confirmed | Every new refusal message in `keysets.py`, `keys.py`, `settings.py`, `custody.py`, `tokens.py`, `codes.py` names entry ids, paths, or setting names only — never material, fingerprints, or file content. The drill evidence carries kids/key-ids/statuses/audit reasons only; an independent re-run of the hygiene sweep (`grep -rEn 'BEGIN (RSA )?PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}' docs/evidence/c3/`) found no match, confirming the record's own claim. `scripts/drill_rotation.py` embeds no secrets. |
| 6 | No hardcoded credentials in the repo | Preserved — confirmed | Keyset documents are structure only; `.env.example` gains placeholder-shaped examples only (checked); the pod contract names classes, never values; the publication leak check is recorded green (exit 0, 3 pre-existing waivers, none in the change's artifacts). |
| 7 | The signing key is IdP-grade secret material | Preserved with the disclosed bound — confirmed | Never committed, never logged (all four key classes carry kid/key-id-only `repr`s); `kid`-published; rotatable — and now *proven* by the drill's live legs. The retained-entry window is the priced addition (DT-EP4-2), and the immediate cut is exercised (drill S4, control). |

## 3. The pod contract vs the mis-assembly threats (DT-EP6-1 / DT-EP7-1)

Every control the SIA's rows name appears as a contract requirement or a startup
refusal:

- Port non-publication — §6's two-half statement (host/external unreachability **and**
  instance-network name-routability as the trust domain); the deployment diagram's (c).
- The mounts — §4.1 the DCR store as a named MUST (read-write, one state mount);
  §4.3 read-only mounts for every file-sourced secret, stated as a separate mount class.
- The security context — §5 carries all seven controls (runAsNonRoot/uid-gid 10001,
  fsGroup 10001 on the store volume, no privilege escalation, all capabilities dropped on
  the stated no-privileged-port assumption, read-only root with `emptyDir`, runtime-default
  seccomp).
- The store's governance — §4.2: cloud-backed storage class by properties (no product
  named), deployment-owned atomic-replace export, the load-bearing no-secret-content rule,
  the wrapped-CEK file named as the future second resident.
- The conf — §3: this repository's committed `nginx.conf`, mounted read-only; the
  sibling-localhost upstream stated (§3, §8.1).
- Single replica — §8.3, with the fail-safe loss semantics and the
  diagnosable-as-contract-violation framing.
- No preference language — verified per the owner's correction: the contract's
  secret-delivery section states requirements and neutral options only (§9).
- Startup refusals where the gateway can see the omission: unreadable/blank key files and
  the reserved `kms` refuse loudly (verified in code and tests); the store path refusal is
  pre-existing.

The contract's §6 statement is the accurate one, and the boundary assertion in
`docs/evidence/c3/pod-shape-probes.md` tested exactly both halves — including the "honest
deviation" record of the instance-network reachability, recorded rather than overclaimed.
The should-fix below is that two other prose spots do not meet the contract's own
precision.

## 4. The drill's evidence vs its scenarios

- **The negative control is the anchor and it holds.** It ran first, before any positive
  verdict, and failed as required (`wrong_expectation_holds: false`,
  `control_failed_as_required: true`) — the instrument is proven able to observe a
  removal, so its passes are verdicts.
- **The signing leg's five booleans each have a recorded observable** (JWKS kid sets per
  stage, minted kids, Core statuses, the audited post-cut refusal). The 615 s cache wait
  is arithmetically consistent with the recorded timestamps (S1 pre-publish
  `14:58:23Z` → S1b waited `15:08:38Z`), and it exceeds the declared 600 s window. The
  pre-publish rule's proof is present (new-`kid` tokens accepted at Core immediately
  after promotion — no refusal window); see note 5 on one row's labeling.
- **The custody leg's three booleans each have a recorded observable**: the re-seal
  (presented key-id `k-oldc` → replacement sealed `k-newc`, read from the clear header —
  a public fact), the emergency cut refusing in the **custody** refusal class with the
  audit line distinguishing it from the signing leg's plain `invalid_grant`, and the
  active session surviving. Both the drain and the cut are proven, not one presumed from
  the other.
- **The evidence could not have been produced by a broken instrument**: the control's
  failure is recorded with its own observables, and the legs were re-run end to end with
  the finalized committed instrument (`scripts/drill_rotation.py`), each exiting 0.
- **Hygiene**: independently confirmed (invariant #5 above). The key material lives only
  in gitignored `.secrets/` (blocked by `.gitignore`'s `*.pem`, `*.key`, `.secrets/`).
- **The stopped-in-play record (Part 1)** is preserved and the defect it found
  (blank-singular exclusivity) was fixed through the documented cycle — the fix
  (`1b91c64`) is spec'd first and matches the spec's "blank singular is unset on the
  composition path" scenario; the test matrix (`tests/test_keyset.py:93-183`) pins the
  full blank/whitespace/real-value matrix.

## 5. The threat-model delta (design §7) — landed as written

- **ID uniqueness: confirmed.** The pre-change model (`git show 846017d:docs/threat-model.md`)
  contains **zero** occurrences of `DT-EP4-2..7`, `DT-EP1-10/11`, `DT-EP6-1/2`, or
  `DT-EP7-1`; `DT-EP4-1` remains C1's (cited by RES-21, line 457). Every ID this change
  lands resolves to exactly one design §5 grid row.
- **All eleven delta rows present** in the live model: DT-EP4-2/3 (the retained-key
  windows, accepted-as-priced with the immediate cut and the drill named), DT-EP4-4 (the
  file-source footprint, covering the IdP secret's file spelling), DT-EP4-5 (the keyset
  document), DT-EP4-6/7 (the mis-use rows), DT-EP1-10/11, DT-EP6-1/2, DT-EP7-1 — each
  matching its design §4 wording (spot-compared; the EP4/EP1 rows are verbatim-faithful,
  the EP6/EP7 rows re-shaped as specified).
- **M34/M35/M36 present and cited** in the rows and the grouped mitigation list;
  M17/M21's amended texts carry the keyset wording.
- **The revocation table's "all proxy access" row re-priced** for the overlap-vs-cut
  split; RES-2/RES-13/RES-15/RES-21/RES-5 re-worded per the delta (spot-checked).
- One precision defect in a re-stated row: finding 1 below.

## 6. Findings

### Blocking

None.

### Should-fix

1. **The pod re-statement of the router-bypass row overstates namespace containment.**
   `docs/threat-model.md:878` (T6-4's re-stated row): "the gateway's port is reachable
   only within the pod's shared network namespace, so a request the router never accepted
   cannot reach it." **Falsified by the repository's own records**: the boundary
   assertion's honest-deviation record (`docs/evidence/c3/pod-shape-probes.md`:
   `mcp-signin-gateway:8091 -> REACHABLE` from the instance network, because Core fetches
   the JWKS there and the process binds `0.0.0.0:8091`, `gateway/__main__.py:114`),
   the pod contract's own §6 second half, and the nginx comment in the same file
   (`router/nginx.conf:46-48`). Core's JWKS fetch is exactly a request the router never
   accepted that reaches the port. The accurate two-half statement exists in
   `docs/pod-contract.md` §6; the threat model is the standing operator-facing record and
   should carry the same two halves (host/external unreachability **and**
   instance-network name-routability as the deployment's trust domain), otherwise an
   operator reading only the model under-prices the instance-network trust requirement.
   The same overstated phrasing appears in the compose comment
   (`docker-compose.yml:104-105`: "8091 is reachable on the pod's loopback and nowhere
   else — a container outside the namespace cannot reach it"), internally contradicted by
   the nginx.conf comment mounted from the same file. Not a code defect and not a
   regression — the instance network was the trust domain before this change too — but
   the change's own architecture (the JWKS-fetch fact) makes the new phrasing false where
   the old one was merely incomplete. **Fix: re-word both spots to the contract's §6
   statement.**

2. **The IdP client secret's file spelling stores the file content unstripped.**
   `gateway/settings.py:1088-1092`: the blank check uses `content.strip()`, but the
   stored value is `SecretStr(content)` — surrounding whitespace survives to the wire. A
   trailing newline (the common shape of a mounted-secret file) silently changes the
   presented secret and surfaces as the provider's `invalid_client` at the first sign-in —
   the exact "far from the misconfiguration" failure mode the blank-equals-unset rule
   exists to prevent, on the one new surface this change adds. Contrast: the keyset file
   sources are immune (the PEM parser tolerates whitespace; `decode_custody_key` strips,
   `gateway/custody.py:100`). Not a confidentiality issue (the value is never logged
   either way). **Fix: strip the file content before storing, or document the
   exact-bytes contract for the file spelling in the reference and the contract.**

### Notes

3. **`SigningKeyset.active` relies on constructor ordering** (`gateway/keys.py:176-178`):
   the class does not itself enforce that `_entries[0]` is the active entry; the
   invariant is maintained by `load_signing_keyset`'s partition and the class has no other
   construction site in the gateway. Safe as-is; a constructor-side assertion (or a
   comment naming the invariant) would make it local. The orchestrator's assert→cast
   replacement (`gateway/settings.py:653`) has the same shape and fails loud
   (`AttributeError` on `None`) if the validator guarantee ever breaks — acceptable.

4. **`test_signing_goes_through_the_active_entry_only` is weak**
   (`tests/test_keyset.py:435`): it signs with `loaded.active` and asserts the token's kid
   equals `loaded.active.kid` — near-tautological. The real property (no mint call site
   can reach a retained key) holds structurally, verified by exhaustive grep in
   falsification 1, but the test does not pin it. A stronger form would assert
   `keyset.get(<retained kid>) is not keyset.active` or mint through the routes' actual
   path.

5. **The drill's "S2 pre-publish proof" row label is confusing**: the row records the
   *old*-kid token's continued acceptance after promotion (the drain-side proof), while
   the pre-publish rule's actual proof is the *new*-kid acceptance at S2 (also recorded,
   "Core accepts new"). Both observables exist; only the label could mislead a future
   reader of the evidence.

6. **Live test re-run was not possible in this review session** (worktree isolation
   forbids executing the main checkout's venv binaries; no pytest in the system
   interpreter). The sanity basis is: the conformance map's recorded full-suite runs
   (708 then 712 passed, 1 standing unrelated skip), the implementer's gate records
   (static tier closed at `7baa971`; drill legs exit 0), and this review's direct
   code-level verification of every load-bearing behavior above, against test bodies
   confirmed substantive (real keys, real decodes, real refusals — not vacuous).

## 7. The orchestrator-touched stretch (disclosed)

Reviewed as part of the diff with no prior-review assumption: the `cast(CustodyKey, active)`
replacement (finding 3's twin — fails loud, acceptable), the ruff auto-fixes, and the
named test constants (`CUSTODY_KEY_ID`, `CUSTODY_KEY_B64` — synthetic values only). No
issue found in the touched lines.

## 8. Verdict

**PASS.** The retained-key windows are bounded exactly as the SIA prices them —
sign-active-only and seal-active-only are structural (no code path can violate them), the
kid/key-id selection has no escape, the JWKS is exactly the configured set, the immediate
cut is real and rehearsed, and the invariant table's seven rows are confirmed against the
code. The two should-fix findings are a documentation-consistency defect on the port
containment claim (where the accurate statement already exists in the contract) and a
functional edge on the new file-spelling surface; neither undermines a security claim
this change makes. Both belong in the closing cleanup, not a re-review.

## 9. Closure — the fix pass and the final wording micro-pass

Every finding's disposition, recorded for the archive:

- **Should-fix 1 (the port-containment overstatement)** — landed across two passes. The
  fix pass re-worded the standing records: the threat model's re-stated EP6 `:8091` row
  and the T6-4 disposition row, and both compose comments, now carry the contract's §6
  two-halves statement. The micro-pass aligned the remaining prose to the same truth:
  the pod contract's §1 summary row (previously "reachable only within the pod's
  network namespace") and the delta spec's three port statements — the image
  paragraph's parenthetical, the MUST NOT clause (now "MUST NOT be reachable from the
  host or from outside the deployment's network", with the pod boundary and the
  instance-network trust domain named together and Core's JWKS fetch as the named
  legitimate use), and the probe-battery scenario. The delta spec's wording is the one
  that syncs into the main spec at archive, so it carries the precision most
  load-bearing. The design's own change-internal historical wording (design.md's D6
  paragraph) is left as history by disposition.
- **Should-fix 2 (the file-spelling whitespace)** — fixed in the fix pass: the file
  content is stripped at read before storing (`_resolve_client_secret`), with the
  strip-versus-blank-check distinction commented at the site.
- **Notes 3-4** — accepted as-is on the reviewer's own recorded basis: the active-entry
  ordering invariant is structural (load-time partition, no other construction site),
  and sign-active-only was verified by exhaustive call-site grep; the stronger test
  forms are named in the findings for any future touch of those sites.
- **Note 5 (the S2 row label)** — accepted as-is: both observables the finding
  distinguishes are recorded in the drill's stage table (the old-`kid` drain
  acceptance and the new-`kid` acceptance at S2), and the label is the run's
  historical record.
- **Note 6** — stands as recorded: the code-level verification basis of this review.
