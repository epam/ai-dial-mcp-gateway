# Tasks

Authoring note: every box starts unchecked; the implementation pass runs against this
list after the independent review (3b) and the owner pause (3c). The order is the
dependency order: the grammar and canonical encoder first (every later site reuses
them), then F1's derived callback (independent of F2, smallest first), then the guard
and the surfaces, the flow's reads, the router, the docs and runbook, the threat
model, the instrument, and the gates. The instrument (task 8) is written **before**
the router and guard land where practical — probe-fail-first: its negative controls
must run and fail against the unfixed stack, then pass against the fixed one, and the
same script is what step 7's re-test re-runs.

## 1. The path grammar and the canonical encoder (`gateway/settings.py`, design.md D4)

- [x] 1.1 Add the resource-path grammar as the settings module's shared constants:
      the decoded per-segment rules (non-empty; not `.`/`..`; no `{`, `}`, `"`, no
      characters ≤ U+001F; no trailing dot), the whole-path byte cap (900 UTF-8
      bytes — the value of Core's own path-size bound, adopted deliberately on the
      decoded resource path, the longer string; design D4), and the segment-count cap (a new stated setting with
      a default of 32, joining the abuse-bounds family). One predicate
      `path_guard_refusal(path)` returning the fixed-vocabulary reason per class —
      the reason tokens (`invalid_resource_path`, `reserved_path_segment`,
      `restricted_toolset`/`restricted_app` retained) join the audit vocabulary's
      closed tables. Verify: unit rows for each refusal class and the pass, including
      a `%22`/`%7B`/`%01` in any segment (offered encoded) refused by the *decoded*
      check, a trailing dot at every depth, `.`/`..` segments, over-length and
      over-depth paths, and a reserved FIRST segment refused while the same name
      deeper in the path passes.
- [x] 1.2 Add the canonical encoder: split the offered resource URI's path on raw `/`
      into segments and decode each segment — segmentation precedes decoding, so a
      `%2F` inside a segment and a raw `/` never merge onto one canonical identity (the
      merge direction T-EP1-b prices) — under a pinned decode discipline — **strict UTF-8** (an invalid, over-long, or CESU-8
      surrogate sequence refused with the guard's fixed reason; never
      `errors='replace'`, which would merge distinct wire spellings onto one U+FFFD
      identity — the aliasing merge direction) and `+` literal in path position
      (`unquote`, never `unquote_plus`) — validate through the grammar, re-encode
      (unreserved raw, everything else `%XX` uppercase hex over UTF-8) — one
      canonical string per resource, with `unquote`/`quote` round-trip unit rows for
      every legal punctuation, non-ASCII, and mixed-case hex input. Verify: `%78` and
      `x` canonicalize identically; lowercase-hex escapes canonicalize to uppercase;
      raw non-ASCII input is refused by the request-target's wire grammar (the
      router's — asserted live by probe row 4), not mirrored gateway-side: the
      gateway's surfaces accept-and-canonicalize a wire-conforming spelling per the
      canonical-identity rule (D4), and only discovery's `raw_path` fallback's
      latin-1 decode yields a harmless phantom identity for a raw non-ASCII byte; an
      invalid UTF-8 sequence (`%FF`), an over-long encoding
      (`%C0%AF`), and a CESU-8 surrogate (`%ED%A0%80`) are each refused with the fixed
      reason, never canonicalized onto a replacement-character identity; a `+` inside
      a segment survives as the literal character, never a space.

## 2. F1 — the derived upstream callback (`gateway/flow.py`, design.md D1)

- [x] 2.1 Replace every use of the listing projection's `redirect_uri`:
      `upstream_authorization()` builds the authorize URL with
      `{GATEWAY_PUBLIC_ORIGIN}{UPSTREAM_CALLBACK_PATH}`, the flow record stores the
      derived value, and the credential call's `redirectUri` carries it. The
      projection's `redirect_uri` member stops being read (drop it from
      `ToolsetSettings`'s required handling — the listing read's parse may keep
      tolerating the member for projection-compatibility, but no leg consumes it).
      Verify: unit rows asserting the authorize URL's `redirect_uri` is the derived
      value when the projection carries a different one (the Chat-saved shape), and
      the credential call body's `redirectUri` likewise; a regression row that no
      code path reads `redirect_uri` off the projection (grep the symbol; only the
      derived constant's uses remain).

## 3. The guard and resource resolution across the surfaces

- [x] 3.1 `gateway/settings.py`: re-base `toolset_resource_uri`/`app_resource_uri` on
      the path (the canonical encoding) and the inverses
      (`resource_kind_and_name` and siblings) on path resolution with
      canonicalization — a `/dial/`-prefixed URI resolves to a toolset path, an
      `/apps/`-prefixed one to an app path, multi-segment accepted, canonicalized at
      resolution. Verify: round-trip unit rows (derive then resolve) for bare names,
      bucket paths, folder paths, and encoded names; two spellings resolve to one
      canonical identity.
- [x] 3.2 Re-base the request-time guards (`toolset_guard_refusal`,
      `app_guard_refusal`) on `path_guard_refusal` with the kind's restriction
      membership decided on the canonical form. Verify: unit rows — a restriction
      entry `toolsets/public/x` admits that path in every accepted spelling and
      refuses every other; the reserved-name refusal fires on the first segment only
      (`/dial/token/…` refused, `toolsets/public/token` passes).
- [x] 3.3 Re-base the startup validators for configured restriction entries on the
      path grammar (a reserved first segment, a segment outside the decoded rules, a
      trailing dot, a dot/empty segment, over-length/over-depth each refuse the start
      naming the entry and the rule). Verify: startup-refusal unit rows per class,
      including a stored-toolset path as a valid entry (`toolsets/public/x` accepted).
- [x] 3.4 `gateway/discovery.py` + `gateway/routes.py`: the protected-resource routes
      resolve the offered path (guard + restriction), serve the document with
      `resource` echoing the offered spelling, behind the existing limiter — reading
      the offered spelling from `request.scope["raw_path"]` (FastAPI delivers path
      parameters decoded, and the echo-offered rule needs the wire form; the
      single-segment path captures become multi-segment). Verify:
      route tests for a multi-segment document, an encoded-spelling echo, a
      guard-refused path 404 with one audit record (reason token + truncated path
      fact), and the over-limit 429 writing no record.
- [x] 3.5 `gateway/authorize.py` + `gateway/token.py`: resource resolution over paths
      with canonicalization (the flow record and token audience carry the canonical
      form; the refresh match is canonical-vs-canonical). Verify: authorization and
      refresh unit rows — a stored-toolset path accepted; a non-canonical spelling
      accepted and canonicalized; a guard-refused path `invalid_target` with the
      audit record; a resource-mismatch refresh still `invalid_target` across
      spellings of two different resources.

- [x] 3.6 The HTML pages' escape discipline, proven for path-shaped interpolants (the
      SIA's T-EP3-b mitigation): unit rows feeding path-shaped, percent-encoded
      inputs that decode to markup-shaped bytes (`%3C%61%3B…`) through every
      interpolation point on the flow's pages — the decision-page and interstitial
      templates and the note-page builders in `gateway/flow.py`
      (`_DECISION_PAGE`/`_INTERSTITIAL`, the `_escape` call sites, the note pages) —
      asserting the rendered output carries no raw markup, the rows running against
      the shared builder so the discipline is asserted, not assumed.

## 4. The flow's Core reads by path (`gateway/core.py`, `gateway/flow.py`, design.md D6)

- [x] 4.1 `listing_url`/`application_url` build the read URL as the fixed route
      prefix plus the canonical encoding of the flow's resource path — never a raw
      caller substring. Verify: unit rows asserting the URL for `toolsets/public/x`,
      an encoded name, and a steering shape never reaching the URL builder (refused
      by the guard first); a row asserting the read URL for a path with `%`-bearing
      segments is correctly re-encoded.
- [x] 4.2 The credential call's `url` member carries the **decoded** resource path;
      the flow record's resource-name field carries the canonical path (decoded form
      for the body, canonical for identity — both from one resolution). Verify: body
      unit rows — a JSON round-trip of a path with every legal punctuation stays
      structurally intact; the decoded and canonical forms are used at their named
      sites only.

## 5. The router (`router/nginx.conf`, design.md D3)

- [x] 5.1 Replace the two data-path locations with the raw-URI map mechanism: one
      `map $request_uri` per kind carrying the segment grammar (raw form:
      unreserved + `%HH` — the unreserved class EXCLUDES `%`, so the `%XX` alternative
      is unambiguous and no overlapping alternates exist, the ReDoS discipline —
      whole-segment `.`/`..` and trailing dots and empty segments refused — doubled
      character classes, no brace quantifiers), yielding
      `/v1/toolset/$tseg/mcp` / `/v1/deployments/$aseg/mcp`; the pattern's match
      domain is the **whole raw request URI** — end-anchored with an optional
      `?query` tail after `/mcp` and nothing after `/mcp` but the query
      (`^/dial/(GRAMMAR)/mcp(\?.*)?$`) — so a query-bearing session-resume request
      matches and a post-`/mcp` path tail does not; prefix locations
      `~ ^/dial/` and `~ ^/apps/` behind the authorization-surface locations, with
      `if ($target = "") { return 404; }`; `proxy_pass http://core$target$is_args$args`;
      the challenge maps re-pointed at the same named captures (the caller's-spelling
      rule). State `large_client_header_buffers` explicitly with the ReDoS rationale.
      Verify: config-load test; the probe battery (task 8) is the behavior gate — no
      router change passes review without it.
- [x] 5.2 Update `docker-compose.yml`'s router service only if the image pin or
      mounts change (none expected); confirm the router and gateway deploy together
      (the grammar and the guard land as one unit).

## 6. The docs and the operator runbook (design.md D7, the owner's mandate 3)

- [x] 6.1 `docs/local-environment.md` + `docs/gateway-configuration.md`: the
      three-callback runbook — `aidial.toolsets.security.allowedRedirectUris` carries
      the gateway's `{gateway-origin}/dial/callback/upstream` FIRST (while any
      stored-field reader remains), then Chat's `{chat-origin}/auth/toolset-signin`
      and Admin's `{admin-origin}/toolset-signin` (placeholders, per the publication
      discipline); the repair procedure per dynamically-registered toolset
      (`POST /v1/ops/toolset/{bucket}/{path}/repair`) with its consequence stated
      (new client id, credentials cleared, one re-consent); the hand registration of
      the gateway callback at statically-registered upstream clients; the ordering
      and its reason — Core stores the first entry of the upstream's DCR **response**
      as the registration's `redirect_uri`, and a conforming DCR server echoes the
      registered list in order, so the allowlist's first entry is what a repaired or
      newly-registered toolset's stored field becomes. The old "must be the first
      entry" guidance is replaced by the three-callback procedure.
- [x] 6.2 `docs/routing.md`: the location map's two data-path rows, the raw-URI map
      mechanism and its byte-faithfulness property (with the measured evidence
      cited), the segment grammar as the shared rule with the guard, the
      caller's-spelling challenge rule, and the reserved-first-segment scoping —
      absorbing the pre-existing lag the rewrite replaces: the current location-map
      alternation and the reserved-names list omit `consent`, which the router's
      configuration and the gateway's settings already carry.
- [x] 6.3 Apply the runbook to the owner's local instance (the owner's act or the
      owner-delegated session act — record which): add all three callbacks with the
      gateway's first, repair the registered toolset(s), verify Chat sign-in and a
      gateway consent both complete. This is the mandate's named migration; its
      evidence lands in this change's `evidence/` folder. **Owner-delegated** (recorded:
      `evidence/instrument-run.md`). The three-callback allowlist landed and Core was
      recreated; the `notion` toolset's stored `redirect_uri` was verified to read the
      gateway's callback (no repair needed). The interactive Chat-sign-in and gateway-
      consent completion legs are the interactive acceptance run's and are deferred, not
      claimed.
- [x] 6.4 `docs/pod-contract.md`: the deployment contract gains the Core-side
      onboarding configuration a real deployment must apply — the doc's "Outside the
      environment surface, one more thing is required" pointer (end of section 2)
      becomes the deployment-facing section itself, placeholders only per the
      publication discipline (no real hostnames, instance names, tenant or issuer
      values). Two settings groups: (a) the gateway joined as an identity provider
      entry (`aidial.identityProviders.dial-mcp-proxy.*`) with each member's rule —
      `jwksUrl` reachable from Core inside the cluster (the instance-network name and
      port; the 8091 port stays unpublished to hosts — the contract's §6 rule, both
      halves), `issuerPattern` equal to the deployment's `GATEWAY_PUBLIC_ORIGIN`
      pinned as a full-match regex, `rolePath`/`projectPath` matching what the
      gateway mints, the `audience` marker equal to `GATEWAY_AUDIENCE_MARKER`, and
      `loggingKey`/`loggingSalt` mirroring the primary provider entry; (b) the
      toolsets security group — the `aidial.toolsets.security.authorizationServers`
      entry (the gateway's public origin) and the three-callback
      `allowedRedirectUris` with the gateway's first (the same runbook facts task
      6.1 carries — cross-reference that task, do not duplicate its prose). The
      section also carries the spec's standing rule: in a multi-provider Core every
      provider entry needs an `issuerPattern`, including the primary one — an entry
      with no pattern can never be selected once another provider defines one. The
      shape of both groups mirrors the local instance's spelling in
      `docs/local-environment.md`'s "Core configuration this repository requires"
      section; the pod contract states it as the deployment's `<>`-placeholder
      form, naming properties, never products or real instances.

## 7. The threat model (`docs/threat-model.md`, design.md §SIA.8)

- [x] 7.1 Land the SIA's delta: the new rows (EP1's encoding-aliasing, identity
      confusion, encoded-forbidden-character injection, path flood, foreign-bucket
      mis-use; EP3's allowlist-gap mis-use; EP5's URL and JSON injection; EP6's
      grammar drift, backtracking, prefix leakage, byte-faithful forwarding), the
      changed dispositions (T5-3 narrowed — the `redirect_uri` member leaves the
      flow's inputs; T6-2 re-priced against the map), and the re-judged RES-16 (the
      grammar joins the fragile set; the lockstep probes named as the compensating
      control; the re-open trigger gains any grammar/map change).

## 8. The instrument — failing-first, with its negative controls (the brief's repeatable probe)

- [x] 8.1 Write `scripts/probe_front_door_paths.py` against the composed stack: a
      fixture toolset stored in Core at `toolsets/public/<probe-name>` (created and
      cleaned up by the script, admin token via the spike harness) plus the existing
      config fixture. Its rows: (1) **negative controls, run first** — assert the
      encoded-name MCP call through the front door is refused by the router (must
      FAIL against the fixed stack — it forwards byte-faithfully), and assert the
      listing read of the stored toolset's full-URL path answers 404 (must FAIL — it
      answers 200); the instrument is proven able to fail before any positive verdict
      is trusted; (2) the stored-toolset chain end to end — 401 challenge naming the
      multi-segment metadata path, discovery document, authorize with the
      resource-URI path, listing read resolution, credential call (needs the runbook
      of 6.1 applied), token exchange, live tool call through the front door;
      (2b) **the user-bucket row** — the same chain for a resource in a caller's own
      user bucket: the probe signs in as a user (a user token via the spike
      harness's `request_user_token`), learns the caller's ciphertext bucket from
      Core's own answer (`GET /v1/bucket` returns the encrypted bucket — Core
      computes it, the probe never does), creates the toolset with
      `PUT /v1/toolsets/{ciphertext}/{name}` (a user token writes into the caller's
      own bucket — Core's `AccessService` own-bucket rule), and takes the full
      resource id (`toolsets/{ciphertext}/{name}`) **verbatim from Core's response**
      — the `id`/`name` field. The ciphertext bucket is per-caller and the probe
      NEVER computes it: a leg that derives the segment instead of copying Core's
      answer is a defect in the row, not a tolerance of it. Asserts through the
      front door: the stored-toolset chain of row (2) — 401 challenge naming the
      user-bucket metadata path, discovery document, listing read resolution, and
      (where the row's harness supports it) the credential/token legs — plus the
      **isolation assertion**: a second user's call on the same front-door path is
      refused by Core's access chain (403 at the listing read / the data path —
      same-answer-as-Core; the second user is a realm user the probe provisions
      through the Keycloak admin API, the same admin access `provision_keycloak.py`
      already uses, because the harness's `.env` carries only the one test user).
      The row's negative-control shape: it fails if the router mangles the
      ciphertext segment or the guard refuses a legal ciphertext spelling
      (alphanumeric, single-segment — wire-conforming and guard-admitted; any
      refusal of it is a defect, never a verdict). Cleanup: the probe deletes the
      user-bucket resource it created (and the second realm user it provisioned,
      so the local realm converges back);
      (3) byte-fidelity rows — `%20`, `%3F`, `%25`, non-ASCII, `%2F` forwarded
      verbatim (asserting the URI Core's log records); (3b) match-domain rows — a
      query-bearing request (`…/mcp?sessionId=<id>`) routes with the parameter
      forwarded raw and intact (the optional `?query` tail matching, `%2F` in the
      value included), and a post-`/mcp` path tail (`/dial/{path}/mcp/extra`) is
      refused 404 and never forwarded; (4) refused-shape rows —
      dot-segments, empty segments, trailing dots, reserved first segments, raw
      non-ASCII; (5) canonicalization rows — a non-canonical spelling resolves to one
      identity (same token audience as the canonical spelling); (6) the pathological
      long/deep URI answers fast (the ReDoS row) and the over-bound path is refused
      with the fixed reason. The same script is what the re-test (PROCESS.md step 7)
      re-runs. **Run green 2026-11-14** (12 rows, controls red as designed;
      `evidence/instrument-run.md`). The credential-call, token-exchange, and
      token-audience-equality legs are the interactive acceptance run's (deferred,
      printed as a boundary).
- [x] 8.2 Extend `scripts/probe_routing.py`'s battery with the lockstep rows — the
      stated division of labor asserted on both sides: the shapes both sides admit
      and the shapes both sides refuse are asserted identical (each shape of 8.1's
      rows (2)–(4), on the router's map and the gateway's guard surfaces alike —
      the user-bucket ciphertext shape of row (2b) included: it is a
      wire-conforming, guard-admitted spelling (alphanumeric, single-segment), so
      the lockstep row asserts both sides agree on admitting the verbatim
      ciphertext Core handed the harness), and the documented asymmetry class is
      asserted as the asymmetry it is — a
      wire-conforming, guard-refused spelling (an encoded forbidden character `%7B`,
      an escaped trailing dot `%2e`, an over-length path) is forwarded by the router
      on the data path and refused by the guard's surfaces, its 401 challenge
      dead-ending at the 404 document, same-answer-as-Core in outcome — plus the
      apps-path twins (a stored-app path routed and challenged). **Run green
      2026-11-14** (13 probes; `evidence/instrument-run.md`). Probe 10's status-path
      assertion was reconciled to the shipped router (the new prefix locations + the
      `/mcp`-suffix map now answer 404, the spec-mandated shape) — the one changed
      pre-existing row, recorded as a finding in the evidence file.

## 9. The gates (PROCESS.md's ladder, in order)

- [x] 9.1 Lightweight: `ruff check`, `ruff format --check` (the CRLF-safe stdin
      method), `pytest -q` — the new unit rows of 1–4 included. **PASS**
      (`evidence/gate-run.md`: `759 passed, 1 skipped`; `ruff check` clean;
      touched-file format clean).
- [x] 9.2 Static: `bandit`, `pip-audit`, Trivy (`wsl -e trivy --skip-db-update` if
      the DB is stale), and `python scripts/check_publication_leaks.py` (exit 0 — the
      runbook's callbacks are placeholders, no real hostnames or tenant values enter
      tracked files). **GREEN after remediation** (`evidence/gate-run.md` round 2: the
      round-1 `opentelemetry-api` floor and Trivy `krb5-libs` parity cleared;
      bandit/pip-audit/Trivy/leak check all PASS).
- [x] 9.3 Compose-boot: `docker compose up` and the health probe per service. **PASS**
      (`evidence/gate-run.md` round 2: both services recreated on the rebuilt image,
      both `(healthy)`; each service's own health probe 200).
- [x] 9.4 The re-test: the same failing probe first (8.1's negative controls now fail
      *because the fix landed*, the positive rows pass), then the full battery
      (8.1 + 8.2 + the existing routing rows), then the change's conformance rows
      (the delta spec's scenarios). **PASS — round 3, as literally invoked**
      (`evidence/gate-run.md`: `probe_front_door_paths.py` 12 rows green / 2 controls
      red as designed, exit 0; `probe_routing.py` 13 probes green, exit 0; the
      conformance accounting recorded).
- [x] 9.5 The security review gate on the diff (an independent reviewer subagent,
      against this change's SIA and the updated threat model), then the general
      review gate. Commit locally; push after the gates pass; the merge to master is
      the owner's act.
      Both gates ran (records: `evidence/security-gate.md` — PASS, SF-1 remediated,
      N-1/N-2 residual minors; `evidence/general-gate.md` — PASS, SF-G1..G4 + the
      notes landed), their remediations verified (762 passed; the battery green
      with the fixture-hygiene fix).
