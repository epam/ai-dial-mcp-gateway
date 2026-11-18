# Release notes — apps-with-mcp-endpoints (draft)

### For users

- **DIAL applications with MCP endpoints are now sign-in-able from your tool.** An
  app's MCP endpoint is served through the gateway's front door at
  `/apps/<name>/mcp`: point a harness there and the sign-in works the way
  toolsets always have — discovery, registration, the browser flow, tokens — and
  a live tool call through the front door succeeds with a gateway-signed token.
- **App sign-ins have no approval screen — by design, not by shortcut.** An app
  needs no upstream credential: its MCP endpoint runs on your own identity, and
  DIAL authorizes each call. So the app flow is just the sign-in and the access
  check — no consent screen, no credential hand-off, no third-party round-trip —
  and the audit trail records exactly that (a kind-driven short-circuit entry).
- **A missing or unknown app is told to you plainly.** If the app is not
  registered in DIAL Core, the flow ends with a plain-language page saying so,
  after one sign-in round-trip; if you cannot read the app, you get the
  no-access page naming who to ask. Discovery itself answers any well-formed app
  name a document — the same registry-independent behavior Core's own discovery
  tier has, so no public surface reveals whether an app exists.
- **One correction worth knowing if you validate tokens yourself:** the gateway
  has always put the resource you named into the token's audience alongside the
  deployment marker — and DIAL Core's check reads the marker only; it does not
  match the resource. The documentation now says this plainly. In practice:
  keep sending the `resource` parameter as before; the gateway enforces the
  match at its own endpoints.
- **The sign-in status endpoint is gone.** `GET /dial/<name>/status` no longer
  answers — the path now falls through to Core, whose auth filter refuses an
  unauthenticated call with Core's own 401 (a 404 is what an authenticated
  request would meet) — and no apps equivalent
  ever existed. The question it answered (will my next call work without a
  sign-in) is answered by the call itself: a 401 carrying the gateway's
  challenge means run the sign-in (that is the challenge's job), a 403 means
  you cannot read the resource, and a call that succeeds needed no sign-in.
  Operators who used the endpoint as a per-user sign-in probe lose that probe;
  the audit trail (every sign-in's short-circuit or consent leg is recorded)
  remains the operational diagnostic.

### For the team

- **A second front-door path shape, `/apps/{name}/mcp`, proxied to Core's
  `/v1/deployments/{id}/mcp`.** The kind lives in the path, so the toolset and
  apps registries never collide and the resource URI is unambiguous in both
  directions. The router's apps location carries the toolset location's whole
  discipline — query-string pass-through, no buffering, hide Core's challenge
  and synthesize the gateway's own naming the app's metadata path — plus the
  apps protected-resource route to the gateway. The `/dial/` vs `/apps/` prefix
  asymmetry is kept as authored (the owner's ruling): unifying the path grammar
  — one prefix per concern, retiring the reserved-name class — is recorded in
  the roadmap's deferred table, naturally landing with E1 (the Core merge) or
  as its own change with a migration window.
- **The app flow rides C1's general rule; no new flow machinery.** Identity leg
  → the app read as the user (`GET /openai/applications/{id}` — 403 no-access,
  404 the apps namespace's existence refusal, unreachable fails closed as a
  deployment fault) → the unconditional kind-driven short-circuit, with one
  audit record (`credential_free_short_circuit`) naming the kind. The spec's
  "only existence refusal" wording is now per-namespace (one authenticated read
  per resource kind), the sign-in status requirement is REMOVED entirely —
  both namespaces, the owner's ruling: the endpoint, its router location, and
  the T1-15 threat row are deleted, the 401 challenge shapes and the audit
  trail remain the diagnostic path, and the operational cost (the per-user
  sign-in probe) is recorded in the change's design — and the toolset guard
  requirement is scoped to toolset-shaped resources (the resource's kind
  decides the guard where a surface serves both kinds; the surface list drops
  the status path).
- **Verified against the current Core source, recorded in the change's
  `evidence/`:** the app MCP path and metadata route shapes; the shared
  `toolsets.security` gate that serves the apps 401-challenge tier (there is no
  `apps.security.*`); the app model's lack of authentication kind and per-app
  status; the ops credential API's `SecuredResource` requirement (apps are
  unreachable through it — credential-free by construction); `DIAL_NATIVE` as
  external-services-only (the owner's 2026-11-03 correction respected
  throughout); and the identity-provider entry's marker-only audience check —
  the fact that falsified the spec's implied per-resource enforcement and is
  now stated as it is.
- **A second optional operator restriction, `APPS`** (unset = every
  guard-passing app name served dynamically; set = pinned, with the charset
  startup refusal). Resource inference remains toolset-only and never consults
  it. Entries are names only — no kind to declare, no scopes to echo (the apps
  document's `scopes_supported` is always empty).
- **A disclosed threat with a named remediation home: the gateway has no consent
  page of its own.** A client registered through CIMD on an
  operator-allowlisted origin can craft an `/dial/authorize` link that a
  victim with a live IdP session completes silently — the gateway relays
  nothing client-identifying into the IdP leg, so the IdP cannot name the
  harness client to the user — and the flow then finishes with no user-facing
  decision point anywhere: a stored credential short-circuits the toolset
  flow, and the app path this change adds completes with zero user-visible
  pages — the variant that would not exist without this change, and the
  sharpest form of the class. The code lands on the attacker's registered
  redirect, and the attacker redeems it with their own verifier, holding a
  gateway token as the victim. PKCE, `state`, and single-use codes do not
  bound this class — the attacker holds every binding legitimately; the
  standing control is CIMD allowlist curation. The threat row (T1-25) lands
  with this change; the remediation — a consent/attribution checkpoint naming
  the resolved client and resource, inside a full RFC 9700/OIDC hardening
  pass — is planned as the roadmap's **C2.5 — AS security hardening (RFC 9700
  alignment)**, positioned after C2 (generalized IdP federation) and before
  C3 (the K8s pod), its scope seed also carrying the DPoP (RFC 9449)
  sender-constrained-token evaluation among its items.
- **Security:** the SIA runs in full (medium impact — no new trust boundary,
  credential, or grant type; the priced set is the unconditional consentless
  mint for a whole kind, the apps-namespace inventory widening, the forged
  app-read on the internal leg, the router's new location, RES-7 widened
  cross-kind, and the drive-by hijack via the app path's zero-page
  short-circuit above). The threat-model updates
  (T1-23, T1-24, **T1-25**, T5-8, T6-8 new;
  T1-12/RES-7, T5-3, T6-2/T6-3 amended; **T1-15 retired** — its surface is
  deleted with the status endpoint; M24/M25 added) land in this change, not after
  it.
  Two Core-side asks are recorded: per-issuer path/audience scoping and a
  registry-bound protected-resource route.
- **No deployment-side requirement beyond what toolsets already need:** Core's
  existing `toolsets.security.authorizationServers` configuration is what serves
  the apps tier on Core's side; the router's challenge rewrite keeps the front
  door's answer correct regardless of what that configuration lists.
