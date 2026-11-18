# Independent review — round 2 (the owner-round-2 decisions and their artifact integration)

Reviewer: the PROCESS.md step-3b independent reviewer (opus subagent, not the author, not
the round-1 reviewer). Method: falsification — the three round-2 decisions (D11 direct
endpoint configuration, D12 DIAL-family alignment, D13 client-secret delivery) were traced
through every artifact they touch, and every fresh-code fact the round claims was re-checked
against the cited code at the cited revisions. No code was touched; nothing was fixed here.

Inputs read in full: `evidence/owner-round-2.md`, `evidence/review-round-1.md` (with its
dispositions), `proposal.md`, `design.md` (all decisions and the SIA, §1–§8, Risks,
Migration), `specs/mcp-signin/spec.md` (the delta), `tasks.md`,
`release-notes-draft.md`; `openspec/specs/mcp-signin/spec.md` (the main spec, for the
programmatic diff); `ROADMAP.md` (never-cut list); `docs/production-roadmap.md` (P1, the
C3 packaging, the quoted rationale). Fresh-code grounding re-checked read-only: Core at
`6dae044afb008e99cdd044ae1dcb97385c4fbefc` (checkout verified at that SHA, branch
`development`) — `IdentityProvider.java`, `AccessTokenValidator.java`,
`ResourceAuthSettings.java`, `OauthAuthSettingsValidator.java`, and (found by this review)
`ResourceEndpointUtil.java`, `ProtectedResourceMetadataService.java`,
`AuthorizationServerMetadataService.java`; the chat at
`e09fc75b34faa06b128ad0899a2835876ac5ce40` via `git show` (checkout verified dirty on
`development` with the one modified file, exactly as the checkout-state note records) —
`provider.types.ts`, `provider-builders.ts`, the auth README sections. A programmatic
unified diff of every MODIFIED requirement (delta vs main spec) was re-run to catch
undeclared drift after this round's re-wording. Gates re-run this pass:
`openspec validate generalized-idp-federation` (valid, exit 0) and
`python scripts/check_publication_leaks.py` (PASS — 200 tracked files, 3 findings all
pre-existing and waived, 0 unwaived), both matching the round's own record.

## Verdict

The round-2 package is coherent and its decisions are sound: D11's direct mode is
configuration-time-only, all-or-nothing, one endpoint source per leg on all four legs in
both modes, with the rejected shapes (per-member override, runtime fallback) reasoned;
D12's adopted/refused items each survive re-checking against the fresh code; D13's refusal
of the mounted-file variant is reasoned against the roadmap's actual C3 packaging, with the
quotes verified verbatim. The round-1 dispositions (F1–F8) all still hold in the revised
artifacts — the revision touched the same sections without regressing any of them. Five
findings, one medium and four minor: the medium is a factual-completeness defect in the
D12 grounding record (Core's upstream OAuth machinery at the cited SHA contains a
well-known metadata-discovery path the record says does not exist — "no OIDC discovery
anywhere"); the minors are precision gaps in the direct mode's spec/design integration.
R2-1 and R2-2 should be dispositioned before the re-pause; R2-3–R2-5 can ride the same
pass. None of the five re-opens D11–D13's mechanism choices.

## Findings

### R2-1 — the D12 grounding record overstates Core's directness: Core's upstream OAuth clients have a well-known metadata-discovery path at the cited SHA

- **Severity:** medium (grounding-record accuracy; no D12 decision is affected)
- **Evidence:** `evidence/owner-round-2.md` states Core's upstream OAuth clients "are also
  direct" and, summarizing the IdP-login leg, "no OIDC discovery anywhere" — wording that
  invites the Core-wide reading that Core configures OAuth by explicit endpoints only.
  At the cited SHA `6dae044` the `credentials` module carries a discovery machinery for
  upstream resources:
  `credentials/src/main/java/com/epam/aidial/core/credentials/util/ResourceEndpointUtil.java`
  (builds `.well-known/...` URLs in both the RFC 8414 host-inserted form and the OIDC
  suffix-appended form) and
  `credentials/src/main/java/com/epam/aidial/core/credentials/service/metadata/`
  (`ProtectedResourceMetadataService.java`, `AuthorizationServerMetadataService.java`) —
  the latter builds a fallback set of five well-known spellings off the resource endpoint
  (`oauth-authorization-server` and `openid-configuration`, each in two path variants,
  plus the appended form), fetches them sequentially until one validates, and feeds
  dynamic client registration. So in DCR mode Core's upstream client endpoints are
  **discovered** (resource → protected-resource metadata → authorization-server metadata
  → registration), not operator-typed — the static-registration claim ("requires
  `client_id` + `client_secret` + `authorization_endpoint` + `token_endpoint`") is
  verified true, and the DCR field-forbidding is verified true, but "are also direct"
  as a summary of the upstream clients does not hold, and "no OIDC discovery anywhere"
  holds only for the IdP-login leg it grammatically attaches to. `design.md`'s own
  wording is properly scoped ("take explicit `authorization_endpoint`/`token_endpoint`
  under static registration"), so no decision rests on the overstatement — but this
  evidence file is the artifact the owner reads to judge the family's mental models, and
  the true picture is stronger for D12's verdict, not weaker: Core has **both** models
  (direct for static upstream clients and the IdP-login leg; discovery-with-fallback for
  upstream DCR), which makes "both mental models already exist in the family" more true
  than the record states. Notably, Core's upstream discovery tries multiple well-known
  spellings with runtime fallback — the exact mechanism D1/D11 reason against for the
  IdP leg; the record should say the family precedent exists and why the gateway still
  refuses it for this leg (one source per leg, chosen at configuration time — D11's
  alternative is the configuration-time answer to the same compatibility problem).
- **Disposition requested:** in `evidence/owner-round-2.md`, scope "no OIDC discovery
  anywhere" to the IdP-login leg and replace "are also direct" for the upstream clients
  with the two-mode truth (static = direct; DCR = discovered from the resource's
  well-known metadata, endpoints from the registration response); add one sentence to
  `design.md` D12 (or the Context paragraph) recording the upstream-DCR discovery path
  at `6dae044` and the reason the gateway's IdP leg does not adopt the multi-spelling
  runtime fallback. No adopted/refused item changes.

### R2-2 — the validation requirement's plain-http scenario is now mode-independent, but no design decision covers the issuer-scheme startup refusal in direct mode

- **Severity:** minor
- **Evidence:** delta spec, the validation requirement's third scenario ("Plain-http
  discovery refused without the override") was re-worded this round to refuse startup on
  a plain-http issuer "whichever endpoint source is configured — the discovery fetch in
  discovery mode, like every credential-bearing call the endpoints feed in either mode".
  In direct mode the configured issuer is never fetched and steers no call — it is only
  the exact-string pin's comparison value — so the scenario's stated rationale
  (credential-bearing calls on plain legs) does not justify refusing a plain-http issuer
  there; that refusal is over-strict uniformity, and nothing in D3, D11, or the SIA
  decides it. The scenario's placement is also design-unrecorded: D3 states the plain-http
  refusal at the fetch, D11 states it for the three configured endpoints, and only the
  scenario and task 4.1's parenthetical carry the mode-independent issuer check at
  startup. A from-spec implementer adds a startup refusal no design decision owns.
- **Disposition requested:** one sentence in D11 (or D3) ruling the issuer-scheme check:
  either "a plain-http configured issuer refuses startup in both modes — one rule, one
  refusal, and the issuer is never a plain leg the operator can own" (uniformity, the
  spec's current behavior), or scope the scenario's refusal to discovery mode. Either
  way the design and the scenario must say the same thing.

### R2-3 — the well-formed-absolute-URL clause of the direct-configuration requirement has no scenario and no named test

- **Severity:** minor
- **Evidence:** the direct-configuration requirement normatively requires each configured
  endpoint to be "a well-formed absolute URL", and task 3.4 implements it — but the
  requirement's five scenarios cover the full set, the partial set, plain-http, the
  override, and staleness; none covers a malformed or relative endpoint value, and task
  3.4's unit-test list names none either. A from-spec reimplementation could skip the
  malformed-URL validation and pass every scenario and every named test.
- **Disposition requested:** a sixth scenario ("A malformed or non-absolute configured
  endpoint refuses startup, naming the member") or the addition of the malformed-value
  case to 3.4's test list — one or the other, so the clause is checkable.

### R2-4 — the verification amendment's "origin-bound like every discovered endpoint" can be mis-parsed onto the direct-mode alternative

- **Severity:** minor (wording; the scenario disambiguates)
- **Evidence:** the verification requirement's new clause reads "…resolved only in that
  provider's own published key set — the key set the provider's discovery document names,
  origin-bound like every discovered endpoint, or, where the operator configures the
  endpoints directly, the key-set URL the operator configures". The origin-bound
  qualifier belongs to the first alternative only (D11 deliberately drops the
  origin-bound-to-issuer rule for configured endpoints — split-origin providers are part
  of the compatibility class direct mode exists to absorb), but its comma placement lets
  a reader carry it across the "or" onto the operator-configured URL; read that way the
  requirement would forbid exactly the providers D11 cites. The "Key set resolved from
  the leg's one endpoint source" scenario states the split correctly, so the normative
  content is safe — the requirement sentence should not need its scenario to be parsed
  right.
- **Disposition requested:** re-seat the qualifier inside the discovery alternative
  (e.g., "the key set the provider's discovery document names — origin-bound, like every
  discovered endpoint — or, in direct mode, the operator-configured key-set URL").

### R2-5 — task 1.2's mitigation enumeration is stale against design §6's item 7

- **Severity:** minor
- **Evidence:** task 1.2 cross-checks that every gateway-owned mitigation in design §6
  has a delta-spec requirement, enumerating "(issuer equality, origin-bound endpoints,
  HTTPS-without-override refusal, cache TTL, no-PKCE startup refusal, exact issuer
  pinning scenario, secret-never-logged scenario)". §6 gained item 7 this round — the
  direct-mode startup validation (all-or-nothing refusal, well-formed-URL and
  HTTPS-or-override checks, no-fetch skip) — and none of it is in 1.2's list, so the
  task as written would not cross-check the round's new mitigations against the
  direct-configuration requirement.
- **Disposition requested:** extend 1.2's enumeration with the direct-mode items (the
  all-or-nothing and HTTPS-or-override startup refusals, the no-fetch skip, the
  stale-endpoint fail-closed scenario).

## Observations (verified claims — recorded so the re-pause can rely on them)

The falsification attempts that **failed** — the round-2 claims that held:

1. **D11 coherence, traced end to end.** The discovery requirement is mode-conditioned
   at its opening ("Where no directly-configured endpoint set is present — the default")
   and its first scenario conditions its WHEN on "no endpoint set directly configured";
   no scenario anywhere claims discovery runs when the trio is set. The
   direct-configuration requirement's five scenarios are each testable (a fixture can
   build the WHEN, an assertion can check the THEN): the full-set skip, the partial-set
   startup refusal (the all-or-nothing rule's scenario), the plain-http refusal without
   the override (the HTTPS-unless-back-channel-origin rule's scenario), the override's
   re-addressing of the server-to-server legs only, and the stale-endpoint fail-closed.
   The refresh requirement's re-wording ("the provider's discovered or directly
   configured token endpoint … the same endpoint the code exchange uses") and the
   verification amendment's key-set clause both name the leg's one configured source
   with no stale discovered-everywhere claim (grep-verified: every remaining
   "discovered" in the delta is mode-scoped or mode-split). The inheritance constraint
   holds in both modes: all four legs (authorize, exchange, refresh, JWKS) read the one
   resolution layer — the discovery document's members in discovery mode, the trio in
   direct mode — with the back-channel override re-addressing token and key-set legs
   only, identically in both. Task 3.4 implements the trio's precedence (full set → no
   fetch attempted; partial set → startup refusal naming configured and missing members)
   and its test list mirrors the scenarios. The programmatic diff of all five MODIFIED
   requirements against the main spec shows only declared changes — the round-2
   re-wording introduced no drift (and F4's retained scenario-amendments record still
   reads correctly in the first MODIFIED requirement).
2. **The SIA's mode-conditional narrowing of DT-EP5-1/DT-EP5-2 is sound.** The mode is
   knowable from configuration alone (D11: "at any moment the leg has exactly one
   endpoint source, knowable from the configuration alone, never from runtime events"),
   so a threat row that is absent in direct mode is a checkable statement about a
   configuration, not an unknowable runtime fact; the narrowing is recorded where a
   reader needs it — in the DT-EP5-8 rows ("There is no provider-asserted input in this
   mode, so the forged-document chain of DT-EP5-1 cannot exist"), in §6 item 7
   ("removes DT-EP5-1's and DT-EP5-2's attack classes entirely … a mode-conditional
   narrowing recorded as such"), in §7's delta, and in task 1.1's six-row/two-source
   instruction. DT-EP5-8's own mitigation list follows the fixed control-category order
   with the [mis-use] marker, and its dispositions accept the mistyping residue as the
   DT-EP5-7 operator-trust class and the staleness residue as the mode's priced trade —
   both consistent with the delta's stale-endpoint scenario and task 5.1's operator row.
3. **D12's cited Core facts hold at the cited SHA.** Checkout verified at
   `6dae044afb008e99cdd044ae1dcb97385c4fbefc`, branch `development`, 2026-11-03, with
   the unrelated local working files the checkout-state note describes. `IdentityProvider.java`:
   `jwksUrl` or `userInfoEndpoint` with exactly-one-or-`disableJwtVerification` enforced
   (the constructor throws otherwise), `issuerPattern` a compiled regex matched in
   `matchesIssuer`, `rolePath`/`rolePath`-array with `rolesDelimiter`, `projectPath`,
   `audience`, the logging fields (`loggingKey`/`loggingSalt`/`obfuscateUserEmail`/
   `claimPathsToLog`/`claimsLogLevel`), and the `offlineClient` block with explicit
   `authorizationEndpoint`/`tokenEndpoint` (plus `clientId`/`clientSecret`/`redirectUri`/
   `scopes`) — and no discovery anywhere in that leg. `AccessTokenValidator.java` routes
   a decoded token by regex issuer match across providers with a userinfo fallback for
   opaque tokens (the `JWTDecodeException` path) — exactly as recorded.
   `OauthAuthSettingsValidator.java`: static registration requires exactly
   `CLIENT_ID`/`CLIENT_SECRET`/`AUTHORIZATION_ENDPOINT`/`TOKEN_ENDPOINT`; DCR forbids
   all four. The refused items' premises verified: `issuerPattern` is genuinely a
   multi-provider routing feature (the validator loops providers on match); the chat's
   per-flavor defaults genuinely include `offline_access` (Auth0, AzureAd, AzureB2c,
   Google, Keycloak, PingId in `DEFAULT_SCOPE`).
4. **D12's cited chat facts hold at the cited SHA.** The checkout is dirty on
   `development` exactly as the checkout-state note records (one modified file,
   `apps/chat/src/utils/auth/auth-callbacks.ts`; the recorded fetch failures and the
   stale-working-HEAD caveat are consistent with what is on disk), and `e09fc75b`'s
   objects are present. `provider.types.ts`: `ProviderConfig` requires `issuer`,
   `clientId`, `clientSecret`, `scope` (`@IsNotEmpty` — confidential clients), with
   `rolesClaim`/`adminRoles` optional and `postLogoutRedirectUri` required, and no
   endpoint fields. `provider-builders.ts`: `AUTH_<PROVIDER>_CLIENT_ID` enables a
   provider, the `_SECRET` variable is required, `_HOST` feeds the issuer,
   `_SCOPE` overrides the per-flavor default. The README states discovery runs at
   startup and "discovery fails and the application does not boot", and that the
   configured host is the discovery location with the issuer validated against the
   discovered canonical issuer (an in-cluster discovery URL may return the external
   canonical issuer) — the spec test at that SHA pins the same behavior. The refused
   items (b) and (c) rest on these and are correctly reasoned.
5. **D13's grounding is exact.** `docs/production-roadmap.md` line 26: P1 names "the
   client secrets out of env"; line 91 and §"C3 = P5 + P1 + T3": the packaging is one
   K8s pod + KMS sign-interface + T3's rotation drill; lines 241–242: "secrets out of
   env files" *is* the pod's secret injection" — D13's quoted rationale is verbatim.
   The decision lands where a reader looks: design D13, task 5.1's client-secret
   delivery statement (environment variable from the deployment's `.env`, never argv,
   never a gateway-read file, deployment-side file injection feeding the variable,
   C3's recorded scope), and task 2.3's `.env.example` delivery comment. The
   mounted-file refusal is reasoned against C3's actual plan (a second delivery
   mechanism re-designed immediately by P1, zero gain in the compose deployment), and
   the pre-C3 escape hatch (compose `env_file`, K8s secret env injection) is coherent
   with the gateway knowing one delivery. Never-cut 6's ruling stays consistent with
   ROADMAP's own wording (`.env` local configuration, committed empty placeholder).
6. **Round-1 dispositions survive the round-2 edits.** F3: the verified vs
   live-run-to-verify separation reads correctly in the Context bullet, D1, D9 (all four
   live-run facts), OQ-A (with D11's new recorded remedy — the tfp-path failure now has
   a configuration answer), task 7.1's list (with the endpoint-source record), and task
   5.1's prerequisite row; the by-construction vs provider-configuration separation
   holds in D6, DT-EP5-5's control 3, the invariant table's row 3, and the delta's
   verification amendment note. F1/F2: the mechanism-vocabulary scoping rule and the
   §10 compromise-point delta survive in design §7 and task 1.1, with the round's
   six-row/two-source extension folded into the same bullets coherently. F4's retained
   record, F5's extended file lists and drift-grep scope, F6's defaults ruling (D8,
   task 2.6, proposal, release notes), F7's converse clause and fourth scenario, and
   F8's five-requirement summary all verified present and unchanged in substance.
7. **Standing rules.** The invariant table rules all seven never-cut invariants matching
   ROADMAP's list, with row 2's boundary precise (the gateway's own PKCE on the IdP leg
   vs Core's upstream verifier) and row 6 carrying D13's delivery consistently;
   publication discipline holds (the leak check re-run this pass: PASS, 200 tracked
   files, 3 pre-existing waived findings, 0 unwaived; every tenant/policy/domain
   reference in the round-2 text uses placeholders; no personal paths, org names, or
   real hostnames — grep-verified); the delta spec carries no provenance citations (no
   design.md pointers, no owner/ruling references — the artifacts that cite D-numbers
   are the planning artifacts whose role it is); proposal ↔ design ↔ delta spec ↔ tasks
   ↔ release notes are internally coherent on every D11/D12/D13 claim (the proposal's
   What Changes bullet, Modified Capabilities list, and Impact rows; the release notes'
   both-audience direct-mode and delivery statements and the team note's family
   verdict); `openspec validate generalized-idp-federation` re-run this pass: valid.

## What must change before the re-pause

- **R2-1** (medium): fix the two over-broad wordings in `evidence/owner-round-2.md` and
  record Core's upstream-DCR discovery path in the design's D12 grounding — the owner's
  question was "how does the family configure IdPs, fresh", and the record as written
  would teach them a wrong family picture.
- **R2-2** (minor): give the mode-independent plain-http-issuer startup refusal a design
  ruling (one sentence) or scope the scenario — spec-normative behavior with no decision
  behind it is exactly what this process does not ship.
- R2-3, R2-4, R2-5 (minor): precision fixes that can land in the same pass.

Validation this pass: `openspec validate generalized-idp-federation` — **valid** (exit 0);
`python scripts/check_publication_leaks.py` — **PASS** (200 tracked files, 3 findings all
pre-existing and waived, 0 unwaived).

## Dispositions (revision pass, 2026-11-04)

The five findings, dispositioned by the revision-round author. No D11–D13 mechanism
was re-opened; every fix is a precision fix inside the change folder.

- **R2-1 — accepted (grounding-record accuracy).** The two over-broad wordings in
  `evidence/owner-round-2.md` are fixed to the scoped truth: "no OIDC discovery
  anywhere" now reads "no OIDC discovery anywhere **on that leg**" (the IdP-login
  leg it grammatically attached to), and "are also direct" for the upstream
  clients is replaced by the two-mode truth — static registration direct; DCR
  **discovered** through the `credentials` module's well-known metadata path
  (`ResourceEndpointUtil.java` building `.well-known` URLs in both the RFC 8414
  and the OIDC spellings; `ProtectedResourceMetadataService`/
  `AuthorizationServerMetadataService` fetching the five-spelling fallback set
  off the resource endpoint that feeds registration, whose response supplies the
  endpoints). The record now states that Core itself carries both mental models —
  which strengthens D12's verdict — and why the gateway's IdP leg refuses the
  multi-spelling runtime fallback that upstream path uses: D11's
  configuration-time alternative answers the same spelling-compatibility problem
  with one source per leg chosen by configuration, never by which well-known
  spelling answered. `design.md` D12's grounding paragraph gains the matching
  sentence. No adopted/refused item changed. Coherence checked outward: the
  proposal's and release notes' "Core's explicit-endpoint spelling" claims name
  the static registration's vocabulary — which is what the direct trio matches —
  and stay true under the corrected picture, so neither needed an edit.
- **R2-2 — accepted, uniformity ruled.** `design.md` D11's validation paragraph
  gains the ruling sentence: the configured issuer's scheme is validated at
  startup in both modes — a plain-http issuer refuses startup whether discovery
  would fetch it or the direct trio serves the legs — because the configured
  issuer is the identity anchor either way (the exact pin's comparison value in
  both modes, the discovery fetch's target and the document's validation target
  in discovery mode), and the plain-leg ownership the override grants reaches the
  endpoints the leg calls, never the anchor itself. Uniformity was picked over
  scoping the scenario to discovery mode because it reads truer against the
  design's trust logic: in direct mode the issuer is the one provider-side value
  the leg still pins every token against, so a mode-dependent anchor rule would
  make the weaker mode the exception, not the safer one. The delta spec's
  scenario is re-worded to the same anchor rationale — its prior
  credential-bearing-calls rationale covered discovery mode only — and renamed
  "Plain-http issuer refused without the override" to name what it tests; task
  4.1's parenthetical still points at it correctly (the validation requirement's
  third scenario). Design and scenario now say the same thing.
- **R2-3 — accepted.** The direct-configuration requirement gains the sixth
  scenario, "A malformed or non-absolute configured endpoint refuses startup"
  (WHEN a directly configured value is not a well-formed absolute URL — a
  relative path, a scheme-less or otherwise malformed value — THEN startup
  refuses naming the setting), and task 3.4's unit-test list names the
  malformed-or-non-absolute refusal case. The well-formed-absolute-URL clause is
  now checkable from the spec and the task; a from-spec reimplementation cannot
  skip the validation and pass.
- **R2-4 — accepted.** The verification requirement's key-set clause re-seats the
  qualifier inside the discovery alternative — "the key set the provider's
  discovery document names — origin-bound, like every discovered endpoint — or,
  where the operator configures the endpoints directly, the key-set URL the
  operator configures" — so the qualifier cannot be carried across the "or" onto
  the operator-configured URL. The declared-amendment note is updated to the same
  quoted wording and states the qualifier's scope explicitly (discovered
  endpoints only; the operator-configured key-set URL is operator input at the
  issuer setting's own trust level, not a discovered endpoint). Split-origin
  providers stay admissible in direct mode, as D11 requires.
- **R2-5 — accepted.** Task 1.2's mitigation cross-check list now enumerates
  design §6 item 7's direct-mode mitigations — the all-or-nothing startup refusal
  on a partial set, the well-formed-absolute-URL and HTTPS-or-override checks,
  the no-fetch skip, and the stale-endpoint fail-closed scenario — so the task as
  written cross-checks the round's new mitigations against the
  direct-configuration requirement.

Validation this revision pass: `openspec validate generalized-idp-federation` —
**valid** (exit 0); `python scripts/check_publication_leaks.py` — **PASS** (200
tracked files, 3 findings all pre-existing and waived, 0 unwaived).
