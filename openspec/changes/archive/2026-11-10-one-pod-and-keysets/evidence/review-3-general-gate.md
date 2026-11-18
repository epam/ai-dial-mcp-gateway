# Review 3 — the general gate (PROCESS step 8, task 7.5)

Reviewer: an independent reviewer subagent (not the implementer; not the security-gate
reviewer). Scope: the whole diff `846017d..7baa971` (13 commits, ~7,100 added lines) —
correctness of the keyset code against the change's own design and delta spec, the docs
against reality, the work order's honesty, and the change's coherence. The
orchestrator-touched stretch inside commit 6b5ee1c was reviewed as part of the diff, with
no assumed prior review. Method: design.md and the delta spec read first, the code judged
against them; verification runs executed where a claim could be tested mechanically.

**Verdict: FAIL** — one blocking finding (F1). Everything else the change carries is in
strong shape; the fix is small and local, and the re-run after it can be a focused pass
over F1's diff, not a fresh review.

## Findings

### F1 — BLOCKING: flat custody key material now renders in `repr(Settings)` and `model_dump()`

- Where: `gateway/settings.py:595` (the field `gateway_custody_keys` re-typed from
  `dict[str, SecretStr]` to `dict[str, object]`), `gateway/settings.py:1448-1456`
  (`_coerce_custody_entries` leaves flat-spelling values as plain strings).
- Defect: verified empirically against the worktree — with the flat compat spelling
  configured (the shape every existing deployment uses), the base64 32-byte custody key
  appears verbatim in both `repr(settings)` and `settings.model_dump()`, while the signing
  key and the client secret stay masked. The pre-change `SecretStr` dict typing masked
  these values; this change silently removed that protection while reworking the field,
  and the guard test (`tests/test_settings.py:1246`,
  `test_secret_settings_do_not_render_their_values`) was not extended to custody keys —
  it would fail today if it were.
- Why blocking: the change's SIA invariant table rules invariant 5 ("no credential in
  logs, argv, or error messages") **Preserved**, with the keyset surfaces named in the
  reason. That ruling is falsified for the dump path the repo's own test docstring
  defines as the guarded threat ("a traceback or a debug dump of the configuration").
  The never-cut discipline and the repo's rule that a mitigation that exists only in
  prose is not landed both apply: a landed masking control was silently un-landed. No
  code path in this diff logs the settings object — the exposure is the repr/dump path,
  not a live log line — but the protection existed precisely for that path.
- Fix shape: mask the flat values again (wrap them in `SecretStr` at coercion and unwrap
  in `_custody_entries`, or exclude the field from repr and redact `model_dump`), and
  extend `test_secret_settings_do_not_render_their_values` to cover
  `gateway_custody_keys` in both spellings. See also F8 (adjacent, same surface).

### F2 — SHOULD-FIX: the compose comments overstate the 8091 isolation the stack does not have

- Where: `docker-compose.yml:104-105` ("so 8091 is reachable on the pod's loopback and
  nowhere else — a container outside the namespace cannot reach it") and
  `docker-compose.yml:304-306` ("The gateway's port is therefore reachable only within
  this shared namespace, and no container outside it can open a connection the router
  never accepted").
- Defect: both claims are false for this stack. The gateway — the namespace owner — still
  carries `networks: [instance]` (`docker-compose.yml:292-293`), so its 8091 listener is
  reachable from every instance-network peer exactly as before the change. The repo
  already states this correctly in three other places: `router/nginx.conf:43-52` ("the
  gateway also joins the instance network … so it remains name-routable inside that
  network"), `docs/pod-contract.md` §6 (the two-halves port statement), and the probes
  evidence itself (`docs/evidence/c3/pod-shape-probes.md:138` —
  `mcp-signin-gateway:8091 -> REACHABLE` from the instance network). The compose file —
  the file the comments call "a property of this file" — is now the one place that
  contradicts the others, on a security-relevant property (the basis of the per-source
  rate limit's trust argument).
- Fix shape: reword both comments to the contract's two-halves statement (unreachable
  from the host and outside networks; name-routable on the instance network by design).

### F3 — SHOULD-FIX: provenance in a code comment — the drill script cites the change's task list

- Where: `scripts/drill_rotation.py:3` — "This is the drill's scripted leg set (task
  6.1)."
- Defect: the repo rule is that code comments carry behavior and its reason, never
  provenance — no change-folder references. "task 6.1" is a checklist citation that
  survives as a dangling pointer after the change archives. The script is published repo
  material; the docstring should say what the script is and why, not which checklist row
  birthed it. This is the only provenance hit in the diff's code comments (the gateway/
  tree is clean; the checked sweep found nothing else).

### F4 — SHOULD-FIX: the drill evidence's "driven with `--build` throughout" is not true of the restore leg

- Where: `docs/evidence/c3/rotation-drill.md:236-237` vs `scripts/drill_rotation.py:765`
  — `cmd_restore` recreates with `up -d --force-recreate` and no build, while every other
  leg defaults to building.
- Defect: an evidence record overstating what the instrument did. Defensible in intent
  (restore returns to the pre-drill image), but the record should say what happened, not
  claim a uniformity the script does not have. One-line fix in the evidence text.

### F5 — NOTE: the Part 1 hygiene sweep command, as printed, could not have returned "no match"

- Where: `docs/evidence/c3/rotation-drill.md:173` — the recorded grep pattern carries a
  trailing `|` inside the character-class alternation (`'…eyJ[A-Za-z0-9_-]{20,}|'`), and
  an empty alternative in `grep -E` matches every line. Part 2's sweep (`:333`) records
  the same pattern without the trailing pipe, and that re-run plus the direct
  `scan_file` result are the credible hygiene evidence. Almost certainly a
  transcription typo; a one-line correction keeps the record from carrying a
  self-contradictory command.

### F6 — NOTE: `decode_code`'s unknown-`kid` refusal conflates provenance with type

- Where: `gateway/codes.py:155-157` — an unknown `kid` on a presented code refuses as
  "the presented token is not an authorization code", where `decode_own_token`'s
  analogue (`gateway/tokens.py:343-345`) says "the token was not issued by this
  gateway". Both fail closed inside their fixed vocabularies; the code path's message
  names the wrong reason for the refusal (the token may be a perfectly-shaped code from
  another keyset). Wording-level only.

### F7 — NOTE: the seam is named `key_source` in the proposal and release notes, `source` in everything the operator touches

- Where: `openspec/changes/one-pod-and-keysets/proposal.md:88`,
  `openspec/changes/one-pod-and-keysets/release-notes-draft.md:60` ("the `key_source`
  seam") vs the implemented field `source` (`gateway/keysets.py:32`, the delta spec, the
  contract, `.env.example`, the configuration reference). A reader looking for a
  `key_source` member will not find one. The design's own D2 schema block says `source`,
  so the artifact set is internally consistent except for these two planning-document
  mentions. Harmless at task 8.1's finalization if the release-notes sentence is
  re-worded to the field's real name.

### F8 — NOTE (pre-existing, adjacent to F1): the JSON-document parse refusal echoes the raw value

- Where: `gateway/settings.py:1481` — `_parse_json_document`'s message embeds
  `{value!r}`, so a malformed `GATEWAY_CUSTODY_KEYS` document whose text contains real
  key material would echo that text into the refusal message. `hide_input_in_errors`
  does not reach message text. Pre-existing (this change only added
  `gateway_signing_keys` to the validator's field list, where the document is
  structure-only and the echo is harmless); recorded here because F1's fix should close
  the custody side of it in the same pass.

### F9 — NOTE: the drill's negative-control-first ordering is procedural, not enforced

- The `control` subcommand is registered and documented before `signing`/`custody`
  (`scripts/drill_rotation.py:775-783`), and the evidence records it running and
  failing first (`rotation-drill.md:253-255`) — but no code-level check forces
  control-before-verdict. Acceptable for an operator-run drill whose evidence is the
  record; noted so the acceptance's basis is explicit.

## What was verified clean

- **Compat equivalence (the spec's core compat claims):** the singular signing spelling
  folds into one active `env`-sourced entry with the pre-change message vocabulary and
  the `\n`-unescape preserved (`gateway/keys.py:227-243, 259-263`); the flat custody
  spelling is accepted as exactly one active entry with no retention; every minted token
  carries its key's `kid` (`gateway/keys.py:121-128`), so the new kid-selection refusal
  (`key_for_token`, no-kid → refusal) breaks nothing the gateway itself ever issued; a
  blank singular/structured/file-path value is unset per the declared amendments
  (`gateway/settings.py:1404-1435`), so the always-forwarded compose shape never
  configures a spelling. The release-notes compat sentence ("every existing
  deployment's configuration keeps working") is true of the diff.
- **The keyset mechanics:** exactly-one-active and mixing refusals (`gateway/keysets.py:122-128`,
  `gateway/settings.py:1163-1176`); duplicate-derived-`kid` refusal naming both entries
  (`gateway/keys.py:269-277`); JWKS active-first with stable retained ordering
  (`gateway/keys.py:200-206`); custody seal-active/decrypt-by-envelope-key-id with the
  AAD binding preserved per entry (`gateway/custody.py:268-351`); both decode paths
  pinned per entry with unknown-`kid` refusal; all refusal messages name ids and
  locators, never material (the one echo exception is the pre-existing F8). Empty
  keyset documents refuse loudly on both keysets.
- **The classified env table:** mechanically complete — all 55 settings-model fields
  appear in `docs/pod-contract.md` §2, and the stated counts (2 required, 47 optional,
  5 secret, 1 dev-only) are correct. `.env.example`'s placeholders match the settings
  model.
- **The conformance map:** six rows spot-checked across all six requirement groups
  (pod-contract probe, signing kms refusal, drill rotation window, custody hard cut,
  inbound alg-confusion, client-secret both-spellings refusal) — all six VERIFIED, each
  named test exists and asserts the row's substance (message content where the row says
  "naming", refusal class where it says class), not a weaker proxy.
- **The drill evidence vs the drill script:** leg names, stages, observables, and the
  five verdict booleans match verbatim between `rotation-drill.md` and
  `scripts/drill_rotation.py`; the 615 s cache wait is asserted on measured elapsed
  time, not the argument; the executed procedure matches the operator doc's staged
  steps (`docs/gateway-configuration.md` Key rotation) including the emergency cut; no
  key material, token strings, or envelope contents anywhere in the evidence.
- **The work order's honesty:** every checked box in `tasks.md` has its deliverable in
  the tree (owner-go record, threat-model IDs, code and tests, four evidence files,
  conformance map); 7.4, 7.6, 7.7, and 8.1 are honestly open.
- **The threat-model delta:** the ID numbering lands exactly as design §7 claims
  (DT-EP4-2..7, DT-EP1-10/11, DT-EP6-1/2, DT-EP7-1, M34-M36, unique across the live
  model), and the at-a-glance counts are internally consistent (80+11=91 threats;
  +2 EP1, +6 EP4, +2 EP6, +1 EP7; 32→35 mitigations).
- **The image evidence:** musl-wheel availability proven from pip's own download lines,
  runtime invariants verified in the built image (no pip, no toolchain, no `.pyc`, uid
  10001, imports + RSA keygen under musl), Trivy 0 HIGH/CRITICAL with the counter-check
  (7 HIGH before the `libuuid` extension, 0 after).
- **The probes evidence:** honest on both the boundary (host 8091 unreachable, instance
  network reachable — the two-halves fact) and the restart quirk (a single-service
  `restart` splits the namespace; the contract's §8.4 unit-granularity rule records
  the compose-specific trap).
- **Publication discipline:** `scripts/check_publication_leaks.py` over the worktree —
  PASS, 3 waived baseline findings, 0 unwaived; no personal paths or issuer/tenant
  values added anywhere in the diff (the image evidence abbreviates the build context
  path).
- **Provenance in gateway/ code comments:** clean (the single hit is F3, in the drill
  script).

## Verdict

**FAIL.** F1 is the only finding that blocks: restore the custody material's repr/dump
masking and extend the loggable-settings test to cover it, then re-run this gate as a
focused pass over that diff. F2-F4 are should-fix items small enough to land in the same
pass (two comment rewords, one docstring line, one evidence sentence). The rest of the
change — the keyset semantics, the compat spellings, the drill, the contract, and the
evidence discipline — is verified coherent against its own spec and design.

## Closure — the fix pass and the final wording micro-pass

Every finding's disposition, recorded for the archive:

- **F1 (blocking, custody material in repr/dump)** — fixed in the fix pass: flat
  custody values are wrapped in `SecretStr` at coercion and unwrapped at the one
  resolution seam (`_flat_custody_material`), and the loggable-settings test covers
  `gateway_custody_keys` in both spellings. The focused re-review confirmed the fix.
- **F2 (the compose comments' 8091 overstatement)** — fixed in the fix pass: both
  comments re-worded to the contract's §6 two-halves statement.
- **F3 (provenance in the drill docstring)** — fixed in the fix pass: the task-list
  citation removed.
- **F4 (the `--build` record)** — fixed in the fix pass: the evidence now states the
  restore leg's deliberate no-build recreate instead of claiming uniformity.
- **F5 (the Part-1 sweep command)** — fixed in the fix pass: the corrected pattern
  printed, with the trailing-pipe typo called out as the record's own correction.
- **F6 (`decode_code`'s refusal reason)** — fixed in the fix pass: "the authorization
  code was not issued by this gateway".
- **F7 (the seam's name)** — fixed across two passes: the fix pass re-worded the
  proposal and release-notes mentions to the per-entry `source` seam; the micro-pass
  renamed the roadmap's planning bullet the same way (`docs/production-roadmap.md`:
  "The per-entry `source` seam"), the last `key_source` spelling inside this change's
  diff.
- **F8 (the JSON-parse echo)** — closed with F1's fix in the same pass: the refusal
  names the problem, never the raw value.
- **F9 (control-first is procedural)** — dispositioned in the fix pass by recording the
  fact in the drill evidence itself, next to the control's own record.

The focused re-review left three wording residuals (F7's roadmap site; the port
statements' precision class from the security gate's should-fix 1 — the pod contract's
§1 summary row and the delta spec's port statements); all three are landed in the
micro-pass, aligned to pod-contract §6's two-halves statement — the gateway's port
unreachable from the host and from outside networks, name-routable on the deployment's
own instance network where Core fetches the JWKS, that network being the trust domain.
The design's own change-internal historical wording (design.md's D6 paragraph) is left
as history by disposition.
