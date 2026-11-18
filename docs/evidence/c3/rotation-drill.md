# The migration drill (T3) — the stopped-in-play finding, then the completed drill

Change: `one-pod-and-keysets` (C3), tasks 6.1–6.6. **This record has two parts.** Part 1 is
the stopped-in-play record the first pass wrote: task 6.1's signing leg could not be
configured into the structured spelling through the documented operator procedure on the
composed stack, so the drill stopped at that point rather than accommodating the
discrepancy. The finding opened the defect cycle, the fix landed
(`1b91c64`: the signing pair's blank normalization — a blank `GATEWAY_SIGNING_KEY` is now
read as unset), and **Part 2** records the re-entered drill run to completion: the
instrument built, the negative control proven to fail first, and both keysets' legs passing
with their evidence.

No secrets, tokens, key material, or personal paths appear: hosts are the local
endpoints, keys are named by `kid`/key-id only, values shown are non-secret renderings,
and machine paths are elided.

Environment: the worktree `c3-one-pod-and-keysets`; Docker in WSL2 (`wsl -e docker …`),
compose project `c3-one-pod-and-keysets`, the composed stack on the production Alpine
image (group 3), the pod shape (group 4), currently the **compat** profile (singular
`GATEWAY_SIGNING_KEY`, flat `GATEWAY_CUSTODY_KEYS`) and healthy. Host helpers ran under
the repository venv with `PYTHONUTF8=1` and the repo root on `PYTHONPATH`.

---

# Part 1 — the stopped-in-play finding (preserved)

## The defect — symptom, evidence, expected

**Symptom.** On the composed stack, the documented signing-rotation reconfiguration —
"use `GATEWAY_SIGNING_KEYS` instead" of the singular `GATEWAY_SIGNING_KEY`
(`.env.example`; `docs/gateway-configuration.md`'s rotation procedure) — cannot be
reached through `.env` alone: the gateway refuses to start with
`gateway_signing_key and gateway_signing_keys are both configured`.

**Why.** The shipped `docker-compose.yml` forwards **both** signing settings
unconditionally, each defaulted to blank when the `.env` value is absent:

```
GATEWAY_SIGNING_KEY: ${GATEWAY_SIGNING_KEY:-}
GATEWAY_SIGNING_KEYS: ${GATEWAY_SIGNING_KEYS:-}
```

`docker compose config` shows this resolves the singular to `GATEWAY_SIGNING_KEY: ""`
when the `.env` value is blank. The settings model's exclusivity check is
(`gateway/settings.py`, `_validate_signing_keyset`):

```python
if self.gateway_signing_key is not None and self.gateway_signing_keys:
```

A blank environment value produces `SecretStr("")`, which is **not `None`**, so the
singular counts as *configured* and the model refuses. There is no `.env`-only way to
make the singular *absent*: compose always forwards it, and a blank (or whitespace)
value is treated as configured. So an operator who follows the reference — blank the
singular, set the structured setting — gets a container that refuses to start.

**This diverges from the codebase's own stated convention.** The model repeatedly states
that "the compose file passes every setting explicitly, so an unset value arrives as an
empty string" and normalizes a blank value to *unset* for every other optional/exclusive
setting:

- `_blank_optional_url_is_unset` — the optional URL settings;
- `_blank_secret_file_path_is_unset` — `idp_client_secret_file`;
- `_parse_json_document` — every JSON setting, including `gateway_signing_keys`.

The IdP client secret's two-spelling pair — the **sibling** mutually-exclusive pair this
change added — normalizes blank exactly this way: `_resolve_client_secret` computes
`environment_spelling = bool(self.idp_client_secret.get_secret_value().strip())`, so a
blank environment secret is read as unset and the file spelling is honored. The signing
pair's check omits that normalization, so the same "both spellings passed by compose"
shape is tolerated for the secret and refused for the signing key.

**Evidence (in play, on the live composed stack).**

1. The shipped compose resolves the singular to a blank when unset:
   `docker compose config` → `GATEWAY_SIGNING_KEY: ""`.
2. The documented `.env` edit (singular blanked, structured set) then a unit recreate:
   the gateway container starts, fails its healthcheck, and `docker compose up` exits:
   `dependency failed to start: container …-mcp-signin-gateway-1 is unhealthy`.
3. The container log carries the refusal, in the settings model's own vocabulary:

   ```
   pydantic_core._pydantic_core.ValidationError: 1 validation error for Settings
     Value error, gateway_signing_key and gateway_signing_keys are both configured: the
     singular setting is the no-rotation shape (one active key, no retained entries) and
     the structured setting is the keyset shape. …
   ```

4. Controlled matrix, in-process and isolated from `.env` (the deciding experiment):

   | Case | Setting shape | Result |
   |---|---|---|
   | singular **absent** + structured set | `GATEWAY_SIGNING_KEY` unset | **accepted** (the control — the structured parsing is sound) |
   | singular **blank** + structured set | `GATEWAY_SIGNING_KEY=""` | **refused**: both configured |
   | singular **whitespace** + structured set | `GATEWAY_SIGNING_KEY="   "` | **refused**: both configured |
   | secret env-set + file-blank (the sibling pair) | `IDP_CLIENT_SECRET` set, `IDP_CLIENT_SECRET_FILE=""` | **accepted** (the sibling normalizes blank → unset) |

   Case 1 vs cases 2–3 proves the **blank value**, not the structured parsing, is what
   refuses; the fourth row shows the sibling pair's opposite (correct) behavior.

5. Root-cause confirmation in play: removing the singular from the container environment
   (a gitignored compose override, `GATEWAY_SIGNING_KEY: !reset null` — **not** a
   documented mechanism) lets the identical structured document start, the container goes
   healthy, and the JWKS publishes the structured entry's `kid` alone
   (`5960946c54560b07`). So the code path is sound; only the always-forwarded blank
   singular blocks the documented procedure.

**Expected.** The documented reconfiguration should start: with the singular blanked and
the structured `GATEWAY_SIGNING_KEYS` set, the singular should be read as **unset** (the
same normalization the sibling `idp_client_secret`/`idp_client_secret_file` pair already
applies, and the model's own stated convention for compose-passed blanks), so the
structured keyset is authoritative and the container starts. The refusal should fire only
when the singular carries a **real value** alongside a structured keyset.

**Where the fix belongs.** Gateway code — the signing pair's blank normalization
(`gateway/settings.py`, `_validate_signing_keyset`, mirroring `_resolve_client_secret`'s
`bool(… .strip())` treatment, or a blank-to-`None` field validator on
`gateway_signing_key`). This is **not** the drill's to patch: the drill author stops at
the defect. The finding opens the defect cycle (instrument → diagnose → spec gate → spec
change → implement → gates → re-test).

## A second, lesser surface gap (within the drill's config remit, recorded not accommodated)

The shipped compose forwards an explicit allowlist of environment variables; a structured
keyset entry's `ref` names a variable the operator chooses, which the fixed list does not
carry. The documented custody-rotation edit (structured `GATEWAY_CUSTODY_KEYS` whose
entry's `ref` names a per-entry variable) therefore also fails startup until that variable
is added to the compose env list:

```
gateway.errors.ConfigurationError: keyset entry 'k-oldc' names the environment variable
'CUSTODY_KEY_ROT_OLDC', which is not set. The material must be injected in that variable
```

Unlike the signing defect this is a **configuration** step the drill author is entitled to
perform (the compose env list is a drill-editable surface), so it does not by itself block
the drill — but it is moot while the signing leg is blocked at the code level, and it is
recorded because the documented rotation procedure should name the env-list step a
structured entry implies. The custody keyset itself has no exclusivity partner, so it is
not affected by the blank-singular defect.

## Task status — as the stopped pass left it

The rows below are the first pass's own record, kept as written: it stopped at 6.1 before
a positive leg, so 6.2–6.4 were not reached. **Part 2 supersedes these rows.**

- **6.1 The drill's scripted legs** — **not completed.** The signing leg's required
  reconfiguration (structured spelling) is unreachable through the documented procedure;
  the drill stopped at that point. The instrument scaffolding written during the recon
  lives in gitignored scratch (`.secrets/rotation/`), not committed: it is not a
  deliverable while the leg it drives cannot be configured.
- **6.2 The negative control first** — **not run.** Its purpose is to prove the drill's
  instrument can fail before any verdict is trusted; with the drill stopped before a
  positive leg, there is no verdict to trust and the instrument is unvalidated. Recorded
  as not run rather than run out of sequence.
- **6.3 The signing-leg evidence** — **not produced** (blocked by the defect above).
- **6.4 The custody-leg evidence** — **not produced** (moot while the signing leg is
  blocked).
- **6.5 The evidence-hygiene pass** — applied to this file: see the sweep below.
- **6.6 The publication leak check** — run over the tree including this file: see below.

## Task 6.5 — the evidence-hygiene sweep

This record carries public facts and fixed vocabularies only: `kid`s (`5960946c54560b07`,
`a119a0a9bee68848`), key-ids (`k-oldc`), JWKS `kid` sets, the settings model's refusal
text, and `docker compose`/container-state outcomes. It carries **no** key material, no
token strings, no envelope contents, and no per-entry secret values — the reproduction's
secret values were read from gitignored scratch and are never rendered here.

The sweep run over this file (and the whole evidence folder):

```
grep -rEn 'BEGIN (RSA )?PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}' docs/evidence/c3/rotation-drill.md
```

Result: **no match** — no PEM boundary, no JWT-shaped string (`eyJ…`) anywhere in the
file. The mapping and config edits never printed a secret; the test signing keys and
custody keys live only in the gitignored `.secrets/rotation/` (blocked by `.gitignore`'s
`*.pem`, `*.key`, `.secrets/`).

The Part-1 sweep, as first printed, carried a trailing `|` inside its alternation (an
empty alternative, which `grep -E` matches on every line) and so could not have returned
"no match" as recorded. The command above is the corrected form; Part 2's re-run (below)
is the operative hygiene record, and it carries the corrected pattern.

## Task 6.6 — the publication leak check

```
PYTHONUTF8=1 python scripts/check_publication_leaks.py
summary: scanned 285 tracked files; 3 finding(s): 3 waived, 0 unwaived
verdict: PASS
```

**PASS**, exit 0 — the 3 findings are the pre-existing waivers (two synthetic-sample
quotes in the D0a review record and one known exposure in `import_background.py`), none
in the drill's artifacts. The checker reads only `git ls-files` entries, so this record
(untracked until the orchestrator commits) was additionally scanned with the checker's
own `scan_file` rules directly:

```
scanned docs/evidence/c3/rotation-drill.md: 0 finding(s)
PASS
```

## Verdict

The drill is **stopped in play at task 6.1** by a gateway-code defect: the signing
key's two-spelling exclusivity check does not normalize a blank (compose-forwarded)
environment value to *unset*, unlike its sibling IdP-secret pair and the model's stated
convention, so the documented structured-signing rotation refuses startup on the
composed stack. The drill author does not patch the gateway; the defect opens the defect
cycle. The custody leg's blocker (a per-entry `ref` variable not in the compose env list)
is a lesser configuration step and is recorded, not accommodated.

---

# Part 2 — the completed drill (re-entered after the fix)

The defect was fixed and committed (`1b91c64`: the signing pair's blank normalization — a
blank `GATEWAY_SIGNING_KEY` is read as unset, so the documented structured-keyset
reconfiguration works through `.env` alone). The drill was then re-entered and run to
completion: the instrument built, the negative control proven to fail first, both keysets'
legs passing. The stop condition still governs — a code defect found in play stops the leg
and is reported rather than patched — and none was found.

## Task 6.1 — the instrument

`scripts/drill_rotation.py` is the scripted leg set: `control`, `signing`, `custody`,
`status`, and `restore` subcommands. It reuses the probe battery's own sign-in machinery
(`scripts/probe_end_to_end.py`'s chain) so the drill exercises the real front door. Its
design decisions, each a place the drill could have gone wrong:

- **The operator reconfiguration is `.env` alone plus the compose env-list step.** The
  structured keyset is set and the singular spelling is blanked; the blank-equals-unset
  rule reads the blank as unset, so the structured document is authoritative. A structured
  `env` entry's `ref` names a variable the shipped compose's fixed allowlist does not carry,
  so that variable joins the effective environment list through a **gitignored compose
  override** (`.secrets/rotation/override.yml`) — the drill edits no tracked file, and the
  effective environment the container receives is exactly the tracked list plus the
  override. Compose was driven with `--build` at every leg that reconfigures the stack
  (the signing and custody legs, and each reconfiguration between them); the restore leg's
  recreate is the one exception — it recreates without a build (`up -d --force-recreate`),
  deliberately returning to the tracked image the drill started from. The builds are what
  matters: the first pass's container ran an image built before the fix, and a
  recreate-without-build at a reconfiguration would silently run stale code (the recorded
  lesson).
- **The headless sign-in vehicle is the app flow** (`skills-demo`): an app resource is
  credential-free by construction, so its flow mints directly through the consent
  checkpoint with no upstream consent leg a probe cannot cross. The toolset flow stops at
  the upstream authorization page without a real provider account and cannot complete
  headlessly.
- **Recreate is always the whole deployment unit** (`docker compose up -d --force-recreate
  --build`), never a single-service restart — the recorded trap that splits the shared
  namespace.
- **The observables are public facts only**: `kid`s read from a token's unverified header,
  a custody claim's clear key-id byte, JWKS `kid` sets, Core-acceptance statuses, and the
  gateway's own audit reason. No token string, key material, or envelope content is
  recorded — the transcripts carry `kid`/key-id/status/verdict fields only.

## Task 6.2 — the negative control, run first and failing

The deliberately wrong expectation: an old-`kid` refresh token still verifies after its
retained entry is removed. It was run **before** any positive verdict, and it **failed** as
required — the instrument can observe a removal, so its passes are verdicts.

The control-first ordering is procedural, not script-enforced: `scripts/drill_rotation.py`
registers and documents `control` before `signing`/`custody`, and this record is what
attests it ran and failed first — the script itself does not force control-before-verdict.

| Step | Observable |
|---|---|
| pre-rotation JWKS | `["5960946c54560b07"]` (only the old key) |
| minted tokens | access `kid` `5960946c54560b07`, refresh `kid` `5960946c54560b07`, custody key-id `k-oldc` |
| post-cut JWKS | `["cf4813fbc58ce841"]` (old entry removed) |
| the wrong expectation's probe | refresh → HTTP **400** `invalid_grant` |

The expectation **did not hold** (`wrong_expectation_holds: false`,
`control_failed_as_required: true`). Had the old-kid token still verified, the instrument
would be blind to a removal and every leg's pass would be worthless.

## Task 6.3 — the signing leg (the rotation-window scenario)

Two sessions were minted under the old key, then the staged rotation ran; the held
un-rotated one is presented after the cut (a drained token would have rotated onto the new
kid and would not test the cut). Timestamps are UTC.

| Stage | Observable | Verdict |
|---|---|---|
| S0 pre-rotation | JWKS `["5960946c54560b07"]`; old access/refresh `kid` `5960946c54560b07`; Core accepts old access | 200 accepted |
| S1 pre-publish | JWKS `["5960946c54560b07","cf4813fbc58ce841"]` — the new `kid` published, the old still signing | pass |
| S1b cache wait | waited **615 s** (≥ the declared 600 s window); fresh old-`kid` access minted after the wait, Core accepts it | observed |
| S2 promote | JWKS `["cf4813fbc58ce841","5960946c54560b07"]` (new active first); new tokens `kid` `cf4813fbc58ce841`; Core accepts new | 200 accepted |
| S2 pre-publish proof | the old-`kid` access minted after the wait is **still accepted at Core after promotion** | 200 accepted |
| S3 drain | old-`kid` refresh → HTTP 200; replacement access **and** refresh `kid` `cf4813fbc58ce841`; Core accepts | drained onto the new kid |
| S4 post-cut | JWKS `["cf4813fbc58ce841"]`; the held un-rotated old-`kid` refresh → HTTP **400** `invalid_grant`, audited | refused |

**Verdict — all five true** (`old_tokens_drained`, `new_tokens_accepted`,
`prepublish_respected`, `postcut_old_refused`, `cache_wait_observed`). The pre-publish
rule's proof is S2's pre-promotion acceptance: the old-`kid` access token — whose `kid` had
been published in the JWKS through the whole 615 s wait — is still accepted at Core after
the new key took over signing, so the promotion created no refusal window. The cache wait
is **observed, not merely bounded**: 615 s ≥ the declared 600 s. Timestamps (the finalized
instrument's re-run): S0 mint `2026-11-09T14:56:46Z`, S1 pre-publish `2026-11-09T14:58:23Z`,
S1b waited `2026-11-09T15:08:38Z`.

**Re-verified with the delivered instrument.** All three legs (control, signing, custody)
were re-run end to end against the finalized `scripts/drill_rotation.py` after the lint and
publication-leak cleanups, each exiting 0 with the same verdicts — so the artifact recorded
here is the artifact that ran, not an earlier draft.

## Task 6.4 — the custody leg (the emergency-cut scenario)

Two sessions were minted under the old custody key (`k-oldc`): one is rotated in the
overlap, one is held un-rotated for the cut.

| Stage | Observable | Verdict |
|---|---|---|
| C0 pre-rotation | both sessions' refresh tokens carry custody key-id `k-oldc` | pass |
| C1 overlap rotate | `k-newc` active, `k-oldc` retained; the live session's refresh → HTTP 200, **presented key-id `k-oldc` → re-sealed key-id `k-newc`** | overlap re-seals under active |
| C2 emergency cut | `k-oldc` removed; the held un-rotated `k-oldc`-carried refresh → HTTP **400** `invalid_grant`, audited as **`custody_decrypt_failed`** | refused in the custody class |
| C2 active survives | a fresh session under `k-newc` → refresh HTTP 200, still sealed `k-newc` | active session unaffected |

**Verdict — all three true** (`overlap_reseals_under_active`, `cut_refuses_in_custody_class`,
`active_session_survives`). The audit line confirms the refusal class is the custody one,
distinct from the signing leg's plain `invalid_grant`:

```
{"event": "flow_refused", "reason": "custody_decrypt_failed", "resource":
 "http://localhost:8090/apps/skills-demo/mcp", "client_id": "group6-smoke"}
```

This is the requirement's core claim made live: a routine rotation is a drain that logs no
one out (the overlap decrypts under the retained key and re-seals under the active one),
and the hard cut — removing the retained entry — is the operator's explicit lever that
refuses the outstanding sessions in the custody class. Both are proven, not one presumed
from the other.

## Task 6.5 — the evidence-hygiene pass

The sweep ran over this record and the drill's transcripts. It looks for PEM boundaries
(a private-key block), JWT-shaped strings (`eyJ…`), and — additionally — the custody keys'
base64 material and a PEM modulus fragment, so a leak in any of those forms would be
caught:

```
grep -rEn 'BEGIN (RSA )?PRIVATE KEY|eyJ[A-Za-z0-9_-]{20,}' docs/evidence/c3/rotation-drill.md \
    .secrets/rotation/transcript-*.json      -> no match
grep -rF '<custody-key-base64>'  … (both keys)   -> no match
grep -rF 'MIIEvgIBADANBgkqhkiG9w0B' …            -> no match
```

Result: **no match** in any class. The transcripts carry only `kid`/key-id facts, Core
statuses, refusals, and verdict booleans (`subcommand`, `timestamps`, `*_jwks_kids`,
`access_kid`, `refresh_kid`, `custody_key_id`, `status`, `error`, the five signing and
three custody verdict booleans) — no token string, no key material, no envelope content.
The key material itself lives only in the gitignored `.secrets/` (blocked by `.gitignore`'s
`*.pem`, `*.key`, `.secrets/`).

## Task 6.6 — the publication leak check

```
PYTHONUTF8=1 python scripts/check_publication_leaks.py
summary: scanned 286 tracked files; 3 finding(s): 3 waived, 0 unwaived
verdict: PASS
```

**PASS**, exit 0 — the 3 findings are the pre-existing waivers (two synthetic-sample quotes
in the D0a review record and one known exposure in `import_background.py`), none in the
drill's artifacts. The checker reads only `git ls-files` entries, so this record (untracked
until the orchestrator commits) and `scripts/drill_rotation.py` were additionally scanned
with the checker's own `scan_file` rules directly (see the Part 1 note for the same
approach).

## The stack's final state

After the legs, the drill restored the resting state: `.env` written back to the working
**compat** profile (singular `GATEWAY_SIGNING_KEY`, flat `GATEWAY_CUSTODY_KEYS`), the
gitignored override removed, the deployment unit recreated without it. Confirmed healthy,
with the compat profile's `kid` published:

```
docker compose ps  -> both services Up (healthy)
JWKS               -> ["a119a0a9bee68848"]   (the compat singular key)
```

## Part 2 verdict

The drill **completed**: the typed instrument is proven able to fail (the negative control
failed first), the signing keyset's staged rotation passed with the Core JWKS-cache wait
observed (615 s) and the pre-publish rule's proof recorded, and the custody keyset's overlap
rotation and emergency cut both passed with the cut's refusal landing in the custody class.
No code defect was found in play; the stop condition was not triggered. All artifacts are
credential-free (the hygiene sweep found no match in any class), and the publication leak
check is green.
