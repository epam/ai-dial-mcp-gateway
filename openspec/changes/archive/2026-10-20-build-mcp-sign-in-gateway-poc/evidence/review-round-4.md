# Review round 4 — findings and resolutions (design-reconciliation delta, 30abd61)

Reviewer: independent opus subagent, fresh pass, verified against files and Core source.
Verdict: **needs-changes** (0 BLOCKER, 1 MAJOR, 2 MINOR). All three reconciliations
substantively sound (D-9 mechanism/config/spec agreement exact; route_only removal
clean, no dangling references; token-unit restatement consistent in every artifact it
claims); validate --strict green.

## Findings

### MAJOR-1 — Purposes-not-counts restatement misses two code docstrings
- `gateway/idp.py` ~line 81 (`Identity` docstring) and `gateway/state.py` ~line 75
  (`FlowRecord` docstring) still state "used at most twice — the toolset settings read
  and the credential API call" — false on the non-enriching local build (three
  presentations) and a different unit than the restated rule (design.md, core.py both
  docstrings, docs).
- **Required fix:** same purposes-not-counts restatement in both docstrings (or fold
  into 3.10's alignment sweep as a companion task).
- **Resolution:** fixed directly, not deferred to 3.10. `gateway/idp.py`'s `Identity`
  docstring and `gateway/state.py`'s `FlowRecord` docstring
  (`identity_access_token` bullet) both replaced the "used at most twice — the toolset
  settings read and the credential API call" count with the same purposes unit the
  corrected statements carry: the token serves the flow's one decision step — "may this
  user sign in to this toolset, and are they already signed in?" — and its one action,
  the credential call, and never anything else, with the decision step taking one or two
  presentations depending on whether the deployment's Core enriches its settings route
  with the per-caller statuses. The count is named as a property of the deployment's
  Core, not of the flow, matching `gateway/core.py` (module docstring and
  `read_toolset_for_flow`), `docs/gateway-configuration.md`, and `design.md`. Comment-only;
  no behavior change.

### MINOR-1 — Front-door dead-end for an unmapped/non-OAuth toolset is safe but unstated
- A client calling `/dial/<unmapped>/mcp` gets the gateway's OAuth challenge (the
  rewrite is unconditional), whose PRM then 404s ("unknown toolset"); status read 404s
  too — fail-closed, honestly diagnosable, no loop, no exposure. Stated nowhere.
  (Also corrects the review-request premise: unrewritten Core 401 pass-through is the
  catch-all's behavior for Core's own spellings — stated as accepted and safe.)
- **Required fix:** one sentence in `docs/routing.md`'s "not yet covered" bullet.
- **Resolution:** fixed. `docs/routing.md`'s "What is not yet covered" section gained one
  bullet stating the front-door outcome for a toolset absent from the mapping: the call
  still gets the gateway's OAuth challenge (the rewrite is unconditional), whose
  protected-resource document answers 404 for the unmapped name, as does the status read —
  a fail-closed dead end and the honest "this origin does not serve that resource" answer,
  no loop and no exposure. Both 404 claims verified against the code: `gateway/routes.py`
  `protected_resource` (404 `{"detail": "unknown toolset"}` for an unmapped name) and
  `gateway/status.py`'s public status-read handler `status`, the same (the 404 is raised
  in the handler when the name is absent from the toolset mapping, before the Core-client
  method `read_toolset_status` in `gateway/core.py` is reached).

### MINOR-2 — Interim spec/code divergence until 3.10 lands (tracked, sequenced)
- README/.env.example/settings.py still implement the route_only escape the spec now
  forbids — the disclosed spec-first sequencing; 3.10 lands before the gates.
- **Required fix:** none beyond landing 3.10 as sequenced.
- **Resolution:** confirmed as the remedy, no code change. Task 3.10's sequencing — landing
  before this change's gates — is the accepted remedy for the disclosed interim divergence
  between the spec (which now forbids the `route_only` escape) and README/.env.example/
  `settings.py` (which still implement it). Until 3.10 lands the divergence is disclosed
  and open, not silent; the change's gate run must follow 3.10.

---

# Re-review of the round-4 fixes (fresh reviewer pass)

Verdict: **needs-changes** — the resolutions' substance verified correct (diff scope
exact, comment-only; purposes unit consistent across idp.py/state.py/core.py/design.md/
docs; routing bullet matches code; gates green), but:

## Finding 1 (MAJOR) — a stale count statement escaped in `gateway/flow.py`
- `gateway/flow.py` module docstring (~lines 30–32): "the **identity token is used at
  most twice** — the settings read and the credential call — and dropped as soon as
  both are spent" — the same falsified count rule, missed because the phrase wraps
  across two lines (single-line grep misses it; a multiline pattern
  `at most\s*\n?\s*twice` exposes it). The prior pass's "no remaining live artifact"
  claim is falsified.
- **Fix:** same purposes-not-counts restatement; verification must use a multiline
  grep over the whole `gateway/` package.
- **Resolution:** fixed. `gateway/flow.py`'s module docstring (the second of the two
  properties it names) dropped the "identity token is used at most twice — the settings read
  and the credential call — and dropped as soon as both are spent" count and now carries the
  same purposes unit every corrected statement carries: the token serves the flow's one
  decision step — "may this user sign in to this toolset, and are they already signed in?" —
  and its one action, the credential call, after which the flow discards it; the decision
  step takes one or two presentations depending on whether the deployment's Core enriches
  its settings route with the per-caller statuses, so the use is stated in purposes rather
  than counts, the count being a property of the deployment's Core and not of the flow. The
  provider-refresh-token sentence (no refresh token requested, so none to retain) is kept
  verbatim. Comment-only; no behavior change.

  Verification that no live artifact states a count rule, over the whole package:
  `grep -rPn "at most\s*\n?\s*twice" gateway/` and `grep -rn "at most twice" gateway/`
  return nothing; `grep -rPn "used at most" gateway/ docs/` also returns nothing. The
  multiline form is what the escaped phrasing needed: the phrase wrapped across two lines
  (`at most` at end-of-line, `twice` at the start of the next), which the single-line
  pattern could not see. Residual count-flavored wording remains only in two *internal*
  comments in `gateway/state.py` ("the second of the token's uses would fail" in
  `identity_expired`; "Called as soon as both of the token's uses are spent" in
  `discard_identity_token`) — neither states a numeric count, neither is a live docstring
  rule, and both are consistent with the purposes unit (the decision step followed by the
  one action), so they are outside this finding's scope and were left unchanged.

## Finding 2 (MINOR) — evidence mis-attributes the status-read function
- This file's MINOR-1 resolution cites "gateway/status.py (read_toolset_status the
  same)" — but `read_toolset_status` is a Core-client method in `gateway/core.py`;
  the public status-read handler in `gateway/status.py` is named `status`. The 404
  claim itself is true; only the attribution is wrong.
- **Fix:** correct the attribution in the MINOR-1 resolution text.
- **Resolution:** fixed. The MINOR-1 resolution above now attributes the two 404 claims
  correctly: `gateway/routes.py`'s `protected_resource` for the protected-resource document,
  and `gateway/status.py`'s public status-read handler `status` for the status read — the
  handler that raises the 404 when the path name is absent from the toolset mapping, before
  the Core-client method `read_toolset_status` in `gateway/core.py` is reached. The prior
  text's parenthetical "(read_toolset_status the same)" conflated the handler with the
  Core-client method; the 404 claim itself was true and is unchanged. Comment-only; no code
  change.
