# Tasks

The implementation pass runs against this list after the independent review (3b) and
the owner pause (3c). The tasks are in dependency order: the instrument first (it is
probe-fail-first, so it must run and fail against the unfixed stack before any fix
lands), then the gateway aliases, the router locations, the docs, and the gates. The
threat model's delta is landed by the authoring pass itself (group 5), because the
mitigations must exist in the delta spec and the threat model before implementation.

## 1. The instrument — failing-first, control first (design.md D8)

- [x] 1.1 Extend `scripts/probe_routing.py` with a well-known row group. Its first row is
      the **negative control W0**: `GET /.well-known/openid-configuration` on Core's own
      port (the battery's `--core-origin`, outside the router), asserting Core's answer —
      `401`, a `text/plain` body, and Core's trace header (`X-Dial-Trace-Id`) present. The
      control establishes the discriminator every later row uses: a front-door answer that
      carries Core's trace header came from Core. The row also records whether Core's
      answer carries `X-Content-Type-Options`. A failed control stops the battery, as
      the existing control does. Verify: the control passes on the current stack (Core
      answers as recorded in `evidence/finding-discovery-fallthrough.md`).
- [x] 1.1b The group's second row, the **negative control W0c**: front-door
      `GET /.well-known/oauth-protected-resource/dial/x` (the gateway's
      protected-resource location, no `/mcp` suffix), asserting the gateway's own `404` —
      body `{"detail":"Not Found"}`, `application/json`, no Core trace header, and **no**
      `X-Content-Type-Options` header. The control establishes the discriminator against
      the gateway: a front-door `404` carrying the header is the router's closure. A
      failed control stops the battery. Verify: it passes on the current stack.
- [x] 1.2 Add rows W1, W2, W4, W5, W7, W8, W10, W12, and W13 as design.md D8 states
      them, each printing its request, status, content type, and the presence or absence
      of Core's trace header and of `X-Content-Type-Options`. Send every well-known row
      with `http.client` directly (a verbatim-path client): `httpx` and `requests`
      normalize dot segments out of a URL, which would make W10 probe the normalized
      path and pass for the wrong reason. Each W10 cell prints the request line it sent,
      so the run shows the raw spelling reached the router. W1 and W2 compare the alias
      bodies byte-for-byte with the canonical `GET /.well-known/oauth-authorization-server`
      body fetched in the same run. W7
      compares the front-door answer with the Core-direct answer for the same path, using
      the battery's existing toolset and app fixtures (`…/v1/toolset/<toolset>/mcp`,
      `…/v1/deployments/<app>/mcp`). W10 records what the gateway answers for the
      cells that reach it (a, f), so DT-EP6-9's gateway half is measured, and asserts the
      closure's answer, discriminator header included, for the cells that must never
      reach Core (b, c, d, e) — both normalization directions, the `%2e%2e`, `%2E%2E`,
      and `..%2F` variants, the encoded-name, merged-slash, and `.`-segment spellings,
      and the `%0A` edge. Every closure cell requires the router's `404`: no cell steps above the root, so a
      `400` is a failure.
- [x] 1.3 **The failing-first run (W0b).** Run the extended battery against the current,
      unfixed stack and record the run in `evidence/instrument-run.md`: W0 and W0c pass;
      W1, W2, W4, W5, W8, W12, and W10's cells a–e fail, each with Core's answer (its
      `401`, or its `OPTIONS 200`) and Core's trace header where the row expects a
      document or the router's `404`; W7 passes (the catch-all reaches Core today, which
      is the behavior D5 must preserve); W13 and W10's cells f and g pass (their answers
      do not change). Record any row whose pre-change
      outcome differs from this expectation as a finding before proceeding.

## 2. The gateway aliases (`gateway/discovery.py`, `gateway/routes.py`, design.md D1–D3, D6)

- [x] 2.1 Add the alias path constants beside `AUTHORIZATION_SERVER_PATH` in
      `gateway/discovery.py`: the OpenID Connect location
      (`/.well-known/openid-configuration`) and the two path-insertion templates. Each
      constant's comment states the behavior and the reason — the MCP discovery order
      for a path-less issuer, and the issuer never echoing a suffix.
- [x] 2.2 Register the existing `authorization_server` handler's document on the three
      alias paths in `gateway/routes.py`, so every alias answers
      `authorization_server_metadata(runtime.settings)` — one builder and one response
      path. The suffix routes ignore the captured suffix entirely: it is never read,
      logged, or reflected. Keep the routes `GET`-only so every other method is the
      framework's `405`, matching the canonical route.
- [x] 2.3 Unit rows (`tests/test_discovery.py` and `tests/test_app.py`):
      **W1** — `/.well-known/openid-configuration` answers `200` with a body
      byte-identical to the canonical document, with DCR both on and off (the
      `registration_endpoint` member follows the flag at every alias).
      **W2** — both path-insertion forms with an apps suffix, a toolset suffix, a
      multi-segment suffix, the empty suffix (trailing slash), and suffixes carrying
      `%22`, `%3C`, and a long segment all answer byte-identical bodies, and `issuer`
      equals the public origin in each.
      **W3** — no alias carries `subject_types_supported`,
      `id_token_signing_alg_values_supported`, `userinfo_endpoint`, or
      `scopes_supported`.
      **W9** — `HEAD`, `OPTIONS`, and `POST` on each alias answer `405` with `Allow: GET`.
- [x] 2.4 Extend `test_no_as_surface_endpoint_serves_a_cors_header`'s request list with
      the three alias shapes (the OpenID Connect location and one path-insertion form of
      each family), so the back-channel posture stays pinned per path (design.md D6).

## 3. The router (`router/nginx.conf`, design.md D1, D4, D5)

- [x] 3.1 Add the alias-family location
      `location ~ ^/\.well-known/(oauth-authorization-server|openid-configuration)(/|\z) { proxy_pass http://gateway; }`
      directly after the exact `= /.well-known/oauth-authorization-server` location. The
      comment states the behavior (the gateway answers the canonical document at every
      alias), the reason (the discovery orders a client may follow), and why the end
      anchor is `\z` (PCRE's `$` matches before a decoded trailing line break), not
      where the requirement came from.
- [x] 3.2 Add the raw-URI map `$core_prm_raw` beside the data-path maps, exactly as
      design.md D9 gives it, and Core's protected-resource location
      `location ~ ^/\.well-known/oauth-protected-resource/v1/(toolset|deployments)/.+/mcp$`
      after the `/dial/` and `/apps/` protected-resource locations, carrying
      `if ($core_prm_raw = "") { rewrite ^ /.well-known/ last; }` before
      `proxy_pass http://core;`. The comments state why the location exists (Core's own
      challenge can point a direct-to-Core client back at this host), why it is
      end-anchored (only the two templates Core serves), and why the raw gate decides
      (nginx selects on the normalized path, forwards the raw one, and Core matches its
      templates raw).
- [x] 3.3 Add the closure: `location = /.well-known` and `location /.well-known/`, each
      with `default_type application/json;`,
      `add_header X-Content-Type-Options nosniff always;`, and
      `return 404 '{"detail":"Not Found"}';`, placed before the catch-all `location /`.
      The comment states the precedence (a plain prefix, used only when no regex
      matches), the prohibition (never `^~`, which would shadow every discovery regex),
      and why the header is there and why `always` (it tells the router's `404` from
      the gateway's, and without `always` nginx omits it on a `404`).
- [x] 3.3b Add the raw-URI map `$wk_raw_spelling` exactly as design.md D9 gives it, and
      in the catch-all `location /` the check
      `if ($wk_raw_spelling != "") { rewrite ^ /.well-known/ last; }` before its
      `proxy_pass`. The comment states the behavior (a raw path spelled in the
      `/.well-known` namespace is answered by the closure, never forwarded to Core) and
      the reason (a dot-segment spelling can normalize out of the namespace while the
      raw path still names it).
- [x] 3.4 Update the conf's header comment's three-way split so it names the closed
      `/.well-known/` namespace as the router's second synthesized answer beside the
      challenge, and update the catch-all's section comment ("Everything else: Core,
      unchanged") so it names the one thing the catch-all now refuses: a raw path spelled
      in the `/.well-known` namespace.
- [x] 3.5 Verify on the router's image before the full battery: `nginx -t` inside the
      router container (`wsl -e docker compose exec <router-service> nginx -t`) is clean.
      `nginx -t` is also the check that both new map regexes compile as written.
- [x] 3.6 Correct `scripts/probe_routing.py`'s module docstring item 11 (the status path
      is the router's `404`, not Core's `401` — the function docstring and the routing
      doc already say so), and add the well-known group's items to the docstring's list.
- [x] 3.7 **The precedence detector's negative control (one-off, design.md D8).** With the
      router locations landed, temporarily rewrite the closure as
      `location ^~ /.well-known/`, reload the router, and run W6: it must fail. Restore
      the conf, re-run W6 green, and record both runs in `evidence/instrument-run.md`.
      The mutation is never committed.

## 4. The docs

- [x] 4.1 `docs/routing.md`: add the four location blocks to the location map in their
      configured order, each with its reason, and note the catch-all's raw check on its
      row; add a short "the closed well-known namespace" section stating the precedence
      (plain prefix after every regex; never `^~`), the discriminator header, the raw
      checks (the Core-template gate and the catch-all's namespace-spelling refusal, both
      handing a refusal to the closure), and the one forwarded Core exception with its
      re-open trigger (a Core release adding a `/.well-known/` route); add rows W0, W0c,
      W1–W10, W12, and W13 to the probe table. Correct the
      stale evidence link to `openspec/changes/archive/2026-11-13-front-door-addressing-and-redirect/evidence/nginx-mechanism-probe.md`.
- [x] 4.2 `docs/gateway-configuration.md`, the discovery section: name the alias set
      (the OpenID Connect location and the path-insertion forms), the issuer rule, and the
      absence of OpenID Provider members, with the reason for each.
- [x] 4.3 `docs/pod-contract.md` §3 (the router configuration): state that the committed
      conf closes the `/.well-known/` namespace, and that a deployment fronting the
      gateway with any other configuration must reproduce the closure (its body, type,
      and discriminator header), the raw-spelling checks, and the raw-gated Core
      protected-resource forward.

## 5. The threat model (`docs/threat-model.md`, design.md §SIA.8) — landed by the authoring pass

- [x] 5.1 Land the SIA's delta before implementation: rows DT-EP1-17 to DT-EP1-19 and
      DT-EP6-7 to DT-EP6-10 (§8); M43 to M45 (§12); the seven dispositions (§13); the
      DT-EP6-1 restatement; RES-16's re-judgement; OQ-13 and OQ-14 (§14); the entry-point
      bullets (§7); and the header counts.
- [x] 5.1b Land the round-2 re-pricing (design.md, "Review round 1 — dispositions"): the
      DT-EP1-18 row and disposition (newly reachable, bounded); the DT-EP6-9 row and
      disposition (both directions, the raw-URI checks); M44 and M45; RES-16 (a); the EP6
      bullet; OQ-14 moved to the resolved record. No row added, so the counts stand.
- [x] 5.2 At implementation, re-check that every "Placed — delta spec" home named in
      M43 and M44 is still true of the delta spec as reviewed, and that M45's row list
      matches the battery as built.

## 6. The gates (`PROCESS.md`'s ladder, in order)

- [x] 6.1 Lightweight: `ruff check`, `ruff format --check`, and `pytest -q`, including
      the new unit rows of group 2.
- [x] 6.2 Static: `bandit`, `pip-audit`, Trivy (`wsl -e trivy --skip-db-update` if the DB
      is stale), and `PYTHONUTF8=1 .venv/Scripts/python scripts/check_publication_leaks.py`
      (exit 0). Also grep the change's new and edited files for real hostnames and
      personal paths: the leak check scans tracked files only, and evidence files written
      during implementation may not be tracked yet.
- [x] 6.3 Compose-boot: `wsl -e docker compose up` and the health probe per service.
      (Run against a Core stand-in: the instance repository that supplies the real Core
      and Keycloak was not on the host, so Core's health was not probed - see
      `evidence/gate-run.md`.)
- [x] 6.4 The re-test: the same battery first. W0 and W0c stay passing controls; W1,
      W2, W4, W5, W8, W10, and W12 now pass; W6's existing rows, W7, and W13 stay green. Then the full
      battery (every existing row), then the change's conformance rows (the delta spec's
      scenarios). Record the run in `evidence/gate-run.md`.
      (Run against a Core stand-in, with `--no-token`: the two query-string rows were
      skipped, and W0 and W7 measured the stand-in's modeled Core, not a real one. Task
      6.5b closes that gap.)
- [ ] 6.5 (owner-run; left unchecked) The live re-test on the dev deployment (row W11; needs the deployment, so it is
      owner-run): the finding's verify commands against `<gateway-origin>`, then the
      ChatGPT connector reconnected and the gateway's audit trail checked for a
      `client_registered` or an authorization record. Record the outcome in `evidence/`,
      with hostnames as placeholders. If ChatGPT still fails, open OQ-1's iteration
      (`PROCESS.md` step 9) rather than amending this change.
- [x] 6.5b (green on 2026-11-17: the full `scripts/probe_routing.py` passed 31/31 against the
      real composed instance, after the W0/W7 trace-header pin was relaxed per the owner's
      ruling and under a recorded **local origin override** — an uncommitted one-line-edited
      copy of `router/nginx.conf` mounted via an untracked compose override, the deviation and
      its diagnosis recorded in `evidence/real-core-run.md`. The structural fix — a
      configurable router origin — remains routed as a follow-up change. The 2026-11-16 attempt
      and its two findings are in the same evidence file.)
      Run the full `scripts/probe_routing.py` with no flags against the real composed
      instance. That run covers both negative controls, every existing row including the
      two query-string rows, and W7 against a real Core process. Record the outcome in
      `evidence/`, with hostnames as placeholders.
- [ ] 6.6 (the review gates run after the implementation pass, by fresh reviewer subagents; git writes are left for the user) The security review gate on the diff (an independent reviewer subagent, against
      this change's SIA and the updated threat model; low depth, with DT-EP6-9's and D5's
      claims — both normalization directions closed, only Core's literal templates reach
      Core — as its falsification targets), then the general review gate. The user runs
      every git write (commit, push, merge); agents never commit or push. When the gates
      pass, the implementer reports which files changed and stops.
