# General review gate — discovery well-known aliases

`PROCESS.md` step 8 (`CLAUDE.md` gate 5). This is an independent reviewer that did not
author, implement, or security-review the change. It reviewed the working-tree diff
(`router/nginx.conf`, `gateway/discovery.py`, `gateway/routes.py`,
`scripts/probe_routing.py`, `scripts/probe_end_to_end.py`, `tests/test_discovery.py`,
`tests/test_app.py`, and the four docs) and the untracked change folder, against the delta
spec, D1–D9, and the main `mcp-signin` spec.

**Verdict: PASS WITH FIXES.** No blocking finding. The implementation matches the delta
spec and D1–D9. Every MUST has a unit row or a probe row. The gateway code is small and
correct, and the nginx changes are well reasoned and commented by behavior. The fixes
below are about evidence fidelity (the real-Core run), two probe assertions that are
weaker than the scenarios they claim, and some small readability and doc-sync issues.

## What was checked and held

- **Re-run by this reviewer:** `pytest -q` passed with 770 passed and 1 skipped, the same
  as the recorded run. The two touched test modules alone gave 69 passed. `ruff check` is
  green. `ruff format --check --config 'format.line-ending = "cr-lf"' .` reports 281
  files formatted. The plain `ruff format --check .` flags 63 files, all from the
  CRLF/LF artifact that `gate-run.md` records; the index is LF. The publication leak check
  exits 0 with 3 waived findings and 0 unwaived.
- **Gateway, D1–D3 and D6.** One handler is stacked on four routes, and the suffix is
  never bound to a parameter, so nothing in the request path can reach the body. The
  routes are `GET` only, and the unit row pins `HEAD`, `OPTIONS`, and `POST` as `405`
  with `Allow: GET`. OpenAPI is disabled (`gateway/app.py:65`), so stacking the routes
  causes no operation-id side effect. The empty suffix (`…/openid-configuration/`) hits
  the `{suffix:path}` route directly, with no slash redirect.
- **Router, D4, D5 and D9.** The closure is two plain prefix locations with no `^~`, and
  the mutation runs prove that W6 and W0c detect a `^~`. Both raw checks hand off with
  `rewrite ^ /.well-known/ last;`, which only the closure's prefix matches, so the
  redirect cannot loop. The `proxy_set_header` directives are server-level, so the new
  Core location forwards the same `Host` and `X-Forwarded-*` as the catch-all. W7's
  "same as direct" therefore holds by construction. `$wk_raw_spelling` covers `//`, `/./`,
  `%2F` and `%2E%2F` separators, and percent-encoded name characters in both hex cases.
  Each guard has a mutation that fails its row (`instrument-run.md`).
- **Coverage.** Every delta-spec scenario maps to a row:
  - closure: W4, W5, W6, W7, W8, W12, and W10 (c, d, e);
  - aliases: W1, W2, W3, and W9 as unit rows, with W1 and W2 also as probe rows;
  - Core coexistence: W7.

  The failing-first run (W0b) and the SF-1 failing-first run are recorded.
- **Docs.** The facts agree across `routing.md`, `gateway-configuration.md`,
  `pod-contract.md`, `threat-model.md`, `design.md` and the release notes. These facts
  are the alias set, the issuer rule, the absence of OpenID Provider members, the body,
  type and discriminator header, the raw checks, the Core exception and its re-open
  trigger, and the counts. The threat-model counts add up: threats go from 103 to 110
  (EP1 from 34 to 37, EP6 from 14 to 18), and grouped mitigations from 41 to 44. The
  stale archive link in `routing.md` is corrected.
- **Provenance.** No code comment, test docstring, or nginx comment cites the owner, the
  review, a finding ID, or a change path. The threat model's OQ-14 entry says "source:
  the owner's ruling …", which matches that file's established convention for resolved
  open questions (for example OQ-2), so it is not flagged.
- **Publication discipline.** The only origins in the change folder, `docs/bugs/`, and
  the diff are `localhost:8090`, `localhost:8081`, `core`, `gateway`, `evil.example`, and
  public documentation hosts. No pod, cluster or registry name, personal path, or tenant
  value appears.
- **Tasks.** 6.5 (W11, owner-run) and 6.6 (the review gates and git writes, left for the
  user) are correctly unticked.
- **Release notes.** They use the two-audience format (`### For users`, then
  `### For the team`) and state the inferred-cause limit honestly.

## BLOCKING

None.

## SHOULD-FIX

**SF-A — The battery ran against a Core stand-in, but tasks 6.3 and 6.4 are ticked as if
it ran against the composed stack.** `tasks.md:178-182`; `evidence/gate-run.md:6-14`;
`evidence/instrument-run.md:8-27`.

`gate-run.md` discloses this honestly. Core in both the compose-boot and the re-test was
a throwaway local stand-in that models `core-well-known-surface.md`, and the two
token-bearing query-string rows were skipped. That makes W0 and W7 partly circular: the
control proves the stand-in behaves as modeled, and W7 compares the router against the
stand-in. The router's and the gateway's behavior is fully established, but D5's "no
working Core path is taken away" and W7's "same as Core direct" are not yet measured
against a real Core process. `CLAUDE.md` gate 2 (a health probe for every service of the
composed stack) is also not met for Core.

Fix:

1. Annotate 6.3 and 6.4 inline. For example: "(run against a Core stand-in: the
   instance repository was not on the host; the 2 query-string rows were skipped — see
   `gate-run.md`)".
2. Add an owner-run, unticked item beside 6.5, or fold it into W11: the full
   `probe_routing.py`, with no flags, against the real composed instance. That run covers
   both controls, every existing row including the two query-string rows, and W7 against
   real Core. Treat it as a precondition to archive, together with W11.

**SF-B — W7 compares only the status, but its scenario requires the same document
shape.** `scripts/probe_routing.py:1203`.

Both scenarios require Core's answer through the front door to equal the answer on Core's
own port. "Core's own protected-resource route still reaches Core" says "the same status
and document shape". "Core's protected-resource route answers through the front door"
says "receives Core's own document". The probe compares the status, checks the trace
header, and checks that the discriminator header is absent. A router that forwarded to
the wrong Core path and got the same status would pass. Byte equality would be wrong here,
because Core builds `resource` from the request authority, which differs between ports.

Fix: also compare the `Content-Type`. When the status is `200`, compare the sorted JSON
member names, and check that the front-door `resource` ends with the requested path minus
the `/.well-known/oauth-protected-resource` prefix.

**SF-C — W10 (f) does not assert what its spec sentence states.**
`scripts/probe_routing.py:1306-1312`.

The spec says a raw namespace spelling whose normalized path selects a gateway location
"is forwarded to the gateway, whose own routes answer it". Cell (f) only asserts that
there is no Core trace header and no `WWW-Authenticate`. If the router's closure answered
instead of the gateway, the cell would still pass. Cell (g) has the same gap for the data
path's refusal.

Fix: in the `gateway` and `data-path` branch, also fail on `response.nosniff`. A closure
answer there means the request went to the wrong side.

**SF-D — The bug doc still prescribes the superseded router-only fix.**
`docs/bugs/chatgpt-oauth-discovery-fallthrough.md:39-49`.

The bug doc's "Fix" says "Make these changes in `router/nginx.conf`" and says to serve
the aliases from the router. The change instead serves them from the gateway (D1), adds
the raw-URI checks (D9), and keeps Core's two templates (D5). A reader who lands on the
bug doc gets a different design than the one that shipped.

Fix: add a status line under the title, for example "**Status:** fixed by the OpenSpec
change `discovery-well-known-aliases` (pending the live re-test W11)". Then either
reword "Fix" to "Proposed fix (superseded — see the change's design)" or replace its
three items with a two-line summary that links to the change. Keep the "Verify" section:
it is W11's command list.

## NIT

**N-A — `state` is used before it is defined.** `scripts/probe_routing.py:1482` vs `:1519`.

The `existing` list's lambda reads `state["challenge"]`, but `state` and
`record_core_challenge` are defined 37 lines later. This works because the lambda runs
late, but it reads like a bug. Fix: move `state = {...}` and `record_core_challenge`
above `existing`.

**N-B — `TOKEN_ROWS` matches rows by their display names.** `scripts/probe_routing.py:1379-1384`.

The row names are duplicated as string literals. If someone renames a row, `--no-token`
stops skipping it, and the row then runs with `token = ""` and fails confusingly. Fix:
put the token requirement on the row itself, for example as a third tuple field or a
`needs_token` set built from shared name constants. At least add a comment that the
strings must match the names in `main()`.

**N-C — `allow_bad_request` covers every closure cell of W10.** `scripts/probe_routing.py:1048`, `:1304-1305`.

A cell that nginx answered with `400` passes cells (b) to (e). No cell produced a `400`
in any recorded run, so a regression from the closure's `404` to `400` would pass
unnoticed. The spec scenarios for (c) to (e) require the closure's `404`. Fix: pass
`allow_bad_request=True` only for paths that are expected to step above the root, or
drop the parameter until such a cell exists.

**N-D — W5's `OPTIONS` is not a preflight.** `scripts/probe_routing.py:1181`.

The scenario says "an `OPTIONS` preflight receives no preflight handling", but the probe
sends a bare `OPTIONS` with no `Origin` and no `Access-Control-Request-Method`. The
closure's `return` makes the result the same, but the row would be faithful to its
scenario if `_check_closure` sent both headers for `OPTIONS`.

**N-E — The design's D9 snippet comment has drifted from the conf.** `design.md:392-395`
vs `router/nginx.conf:142-155`.

The conf's comment for `$wk_raw_spelling` adds "the dot possibly percent-encoded", and
the Core-gate comment was extended (security-review N-1). The design snippet still shows
the shorter text. The regexes themselves are identical. Fix: re-sync the two comments,
or label the snippet "abridged; the conf is normative".

**N-F — `routing.md` documents `--group wellknown` but not `--no-token`.** `docs/routing.md:340`.

Fix: add one sentence. For example: "`--no-token` runs every row except the two
query-string rows, which need a minted token and Core's request log."

**N-G — The `probe_end_to_end.py` change is unrelated to this change.**
`scripts/probe_end_to_end.py:605-607`.

It is a formatter-only wrap, presumably to make `ruff format --check` pass, and it is
harmless. It is not mentioned in the proposal's Impact list or in the task list. Fix:
mention it in `gate-run.md` as a formatter-only touch, so the diff has no unexplained
file.

**N-H — The `[1/N]` banner order in W7 is misleading.** `scripts/probe_routing.py:1202`.

The line "(second request: Core direct, outside the router)" prints after both requests
have already been sent and printed. Fix: print it before the `direct = _send(...)` call.

**N-I — No unit row pins the alias's cost statement.**

The spec says "An alias costs what the canonical location costs: … no Core call, no audit
record". This holds by construction, because the handler is shared. If a pin is wanted,
the byte-identity test could run under `respx` with no routes, which fails on any
outbound call, and assert that the audit capture is empty.

## Summary for the caller

The change can proceed once the SHOULD-FIX items are folded in. The most important one is
SF-A: the real-Core battery run must become an explicit owner-run precondition to
archive, next to W11, and the ticks on 6.3 and 6.4 must carry the stand-in caveat. SF-B
and SF-C are small probe tightenings. SF-D keeps the bug doc from contradicting the
shipped design. None of these requires a spec change.
