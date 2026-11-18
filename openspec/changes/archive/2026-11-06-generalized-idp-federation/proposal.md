# Proposal

## Why

The gateway's identity-provider leg is hardcoded to one provider's URL grammar: the
endpoints are built by string arithmetic (`/realms/{realm}/protocol/openid-connect/...`
derived from the configured issuer), the configuration vocabulary is named after that
provider (`KEYCLOAK_*`, a Keycloak issuer default, a `/dial/callback/keycloak` route),
and the local back-channel split (an internal plain-http base to sidestep self-signed
TLS) is assumed. A deployment whose identity provider is any other OIDC implementation
— the tested case is an external customer-identity provider (a Microsoft Entra
B2C tenant, the tested family's classic flavor — design.md Context/OQ-A, decided;
the External ID successor is the untested alternative) whose issuers vary by
sign-in journey and whose claims vocabulary is custom — cannot be configured at all. The
generalization the production roadmap fixes as this change's outcome: the gateway fronts
any OIDC provider whose MCP incompliances it absorbs, reading the provider's endpoints
and capabilities from standard OIDC discovery instead of provider-specific URL
arithmetic — with, per the owner's round-2 ruling, an explicitly configured endpoint
set as the alternative for providers whose discovery is unavailable (design.md D11).

## What Changes

- **Standard OIDC discovery replaces URL arithmetic.** The provider's authorization,
  token, and key-set endpoints are read from the issuer's
  `.well-known/openid-configuration` document — one spelling of the IdP leg, shared by
  the code exchange, the refresh grant (the fresh-claims mechanism C1 landed), and JWKS
  resolution. The realm-derivation and endpoint-suffix constants are deleted. The
  document is validated (its `issuer` MUST equal the configured issuer; every used
  endpoint MUST share the configured origin), fetched with the existing outbound
  discipline (timeouts, no redirects, size cap), cached with a bounded TTL, and a
  failure fails the leg closed.
- **Direct endpoint configuration is the explicit alternative to discovery.** An
  operator MAY configure the provider's three endpoints directly
  (`IDP_AUTHORIZATION_ENDPOINT`, `IDP_TOKEN_ENDPOINT`, `IDP_JWKS_URI` — the OIDC
  discovery member names and Core's explicit-endpoint spelling) for a provider whose
  discovery is unavailable, nonstandard, or served at a spelling the gateway's fetch
  does not reach; the set is all-or-nothing (a partial set refuses startup), where
  the full set is configured discovery is skipped entirely and the three settings
  serve every leg — exactly one endpoint source per leg, chosen by configuration and
  never by a runtime failure — with startup validation (well-formed absolute URLs;
  HTTPS unless the endpoint shares the back-channel override's origin) and the
  mode's trade stated in the operator reference: endpoint freshness becomes the
  operator's responsibility. The client id, client secret, scopes, and roles claim
  path were always direct settings; discovery only ever owned the three endpoint
  URLs. The client secret is delivered as an environment variable from the
  deployment's `.env` — the same delivery the signing and custody keys use; the
  secret-management move is C3's recorded scope (design.md D11–D13).
- **The back-channel split becomes an optional override, not an assumption.** The
  internal-base setting survives generalization as an explicit, optional back-channel
  base — the deployment convenience for a provider whose browser-facing origin is
  impractical for server-to-server calls (self-signed TLS); a provider with one
  hostname — the single-origin external-provider shape — configures only the issuer.
- **Varying issuers are pinned exactly.** The configured issuer is the one issuer this
  deployment federates — for a provider whose issuers vary by sign-in journey, the one
  federated journey's; issuer matching stays exact-string pinning, so a token whose
  issuer differs in any way — another journey's issuer of the same provider included —
  is refused. No pattern, prefix, or templated issuer matching: the deployment
  federates one provider.
- **BREAKING (configuration):** `KEYCLOAK_*` settings are renamed to `IDP_*` across
  `.env.example`, `docker-compose.yml`, `gateway/settings.py`, `gateway/federation.py`,
  `gateway/idp.py`, `scripts/provision_keycloak.py`, `README.md`,
  `docs/gateway-configuration.md`, `docs/local-environment.md`, and the test/probe
  files that reference them. The identity-leg callback route rotates from
  `/dial/callback/keycloak` to `/dial/callback/idp`, carried consistently through the
  route, the identity-provider client's registered redirect URI, the provisioning
  helper, the probes, and the docs. The identity-provider client must also be
  registered confidentially at the provider, with its secret configured
  (`IDP_CLIENT_SECRET` is required at startup in both toggle positions — the
  owner's round-5 ruling, design.md D5).
- **The gateway is a confidential client at the identity provider.** The identity
  leg's client authenticates with a client secret on every token request — the code
  exchange and the refresh grant alike, in both positions of the leg's PKCE toggle —
  and `IDP_CLIENT_SECRET` is required at startup (a missing secret refuses startup
  naming the setting, whichever way the toggle is set). The toggle
  (`IDP_PKCE_ENABLED`, default on) governs only whether the S256
  challenge/verifier rides on top of the client authentication; a provider that
  cannot support PKCE is absorbed by turning the challenge off while the client
  authentication stays on. The client-facing AS surface — the harness-facing
  authorization endpoint, PKCE-required — is unchanged, and the upstream leg and
  its verifier are untouched.
- **The flow's availability decision becomes the data path's own.** The sign-in
  flow's DIAL-authorization read of a toolset moves from the bucket-based platform
  settings read — Core's admin-only route, which refused non-admin users toolsets
  the MCP data path serves (the false denial the live B2C run exposed, the first
  non-admin identity through the flow) — to the deployment-listing read
  (`GET /openai/toolsets/{name}`), the route whose authorization is the same
  deployment resolution the data path authorizes through: a user the data path
  serves is a user the flow serves, a user it refuses is refused before any
  upstream round-trip, and the refusal pages (no-access, not-registered, fault) are
  unchanged. The listing read also carries the projection the upstream leg builds
  from and the per-caller signed-in statuses, so it is the flow's one toolset read
  (the separate status read is deleted; its route was the same URL) — and **the
  `TOOLSET_BUCKET` setting is retired with the bucket-based read (BREAKING for
  configuration: the setting is removed; a deployment carrying it drops the line)**.
- **The read's refusal classes are split by what Core's answer means.** A 403 at the
  flow's read remains the no-access page — the caller's own lack of access, the data
  path's own refusal of them. A 401 — Core could not validate the sign-in's identity
  token (its provider entry's issuer, key set, or audience, or that key set's
  reachability) — becomes an operator-facing **trust fault**: a fixed page telling
  the user the sign-in cannot proceed and an administrator must check Core's trust
  configuration for the identity provider, the flow consumed like any refusal with
  no credential retained, and a fixed-vocabulary audit reason — never again rendered
  or recorded as an access denial (the conflation the live run exposed: the user was
  shown "You do not have access to this toolset" for an authentication failure whose
  remedy is the operator's, and Core logs no record of its 401s, so the gateway's
  record is the only diagnosable trace — design.md D16).
- **The tested case is the external customer-identity family's classic flavor
  (B2C), with placeholder values; the successor flavor (External ID) is the untested
  alternative, kept in the record for context (design.md Context/OQ-A).** The
  family's issuer and discovery shapes are grounded
  in Microsoft's public documentation; the change's working artifacts carry
  `<tenant>`/`<policy>` placeholders, while the normative delta spec and every
  implementation-facing surface carry none of the family's product vocabulary — the
  boundary design.md D14 states. The live
  acceptance run — in two parts: the controlled acceptance on the local compose
  stack, and the real-world acceptance against the owner's existing
  B2C-configured DIAL deployment and its real app, the same chain in both with
  the `IDP_*` federation profile identical between the parts (the environments'
  Core and public origins are the recorded per-environment delta; task 7.1 states
  the operative criterion) — needs the owner's real values
  and **cannot execute in this authoring pass**; it is an owner-dependent task row
  (task 7.1).
- **Open extension recorded, not built:** opaque-token identity providers via a
  userinfo-federation mode — recorded in `design.md` as a deferred direction with its
  known prerequisites, not implemented here.

## Capabilities

### New Capabilities

(none — the identity-provider leg is part of the existing sign-in capability)

### Modified Capabilities

- `mcp-signin`: the identity-provider leg's requirements change — a new requirement
  for discovery-driven provider configuration (endpoints, validation, caching, the
  back-channel override), a new requirement for the directly-configured endpoint set
  (the explicit alternative source, all-or-nothing with its startup validation), a
  new requirement for the confidential-client shape of the IdP leg (the secret
  required in both toggle positions and presented on every token request; the
  toggle governing the challenge only), amendments to five requirements — the
  authorization-requests, federation-flow, app-flow, refresh, and
  token-verification requirements — re-wording the "public PKCE client" vocabulary to
  the generalized client shape and the key-set/endpoint resolution to the leg's one
  configured source's spelling; the availability-read re-pinning (design.md D15,
  the live-run finding's fix): the federation-flow requirement's authorization-bearing
  read, its denial and unknown-toolset scenarios, and a new public-toolset scenario
  move to the deployment-listing read, with the existence-decision mentions in the
  discovery, toolset-mapping, and name-guard requirements re-pinned with them; and
  the refusal-class split (design.md D16, the second live-run finding's fix): the
  denial scenario scoped to the 403 it is, a new trust-fault scenario for the 401
  (Core cannot validate the sign-in's identity token — an operator-facing fault,
  never an access denial), and the app-flow requirement's refusal enumeration
  aligned to the same four-shape discipline.

## Impact

- `gateway/idp.py` — rewritten endpoint resolution (discovery document client,
  validation, cache; the directly-configured endpoint mode with its startup
  validation and no-fetch skip); the authorization/exchange/refresh/JWKS legs read
  the discovered — or directly configured — endpoints; the client-secret
  authentication becomes required and unconditional (presented on the exchange and
  the refresh grant in both toggle positions), the PKCE toggle governing the
  challenge/verifier only.
- `gateway/core.py` — the flow's toolset read re-points to the deployment-listing
  route (`GET /openai/toolsets/{name}`), one read serving availability, the settings
  projection, and the per-caller statuses; the separate status read, the two-call
  fallback, and the bucket-spelled settings URL are deleted (design.md D15); and
  `_read_json` splits the refusal classes — UNAUTHORIZED (401) raises the new
  trust-fault `CoreError` class (fixed vocabulary, nothing user-identifying) while
  FORBIDDEN (403) keeps the access-denied class (design.md D16).
- `gateway/settings.py` — `KEYCLOAK_*` → `IDP_*` (issuer, client id, client secret,
  client scopes, back-channel base), the directly-configured endpoint trio with its
  all-or-nothing startup refusal, the PKCE toggle with the required-secret startup
  refusal (a missing secret refuses startup in both toggle positions), the
  callback-path constant, the discovery cache settings, and the `toolset_bucket`
  setting's retirement.
- `gateway/federation.py` — callback route and audit leg name rotate to
  provider-neutral spellings; the trust-fault class's fixed page and consumed-flow
  refusal land with the split (design.md D16).
- `scripts/provision_keycloak.py`, `scripts/probe_*.py`, `scripts/spike_*.py` — the
  renamed settings and the new callback spelling.
- `.env.example`, `docker-compose.yml`, `README.md`, `docs/gateway-configuration.md`,
  `docs/local-environment.md` — the renamed configuration vocabulary, the discovery
  semantics, the `TOOLSET_BUCKET` setting's removal, and provider-neutral guidance for varying-issuer external providers; the
  tested family's concrete values arrive with the live run and are recorded in its
  evidence, not in the operator reference (design.md D14).
- `gateway/app.py` (a healthcheck comment), `gateway/__main__.py` (the
  UTC-formatter docstring), `pyproject.toml` (a description comment),
  and `docs/routing.md` (the end-to-end sketch's client name) — stray old-vocabulary
  prose spellings outside the main surfaces, renamed with the rest; the PoC-era and
  historical records (`docs/HANDOFF.md`, `docs/demo-slide.html`,
  `docs/hosting-options.html`, `docs/background/*`) deliberately keep theirs.
- The Keycloak-shaped defaults are retired, not renamed (design.md D8): the settings
  model's issuer default becomes a provider-neutral placeholder, and compose stops
  hardcoding the local back-channel base — the local profile's values move to the
  deployment's `.env`.
- `tests/` — the eight test files referencing the old vocabulary; new tests for
  discovery validation, caching, journey-varying issuer pinning, the direct endpoint
  mode, and the confidential client's both-toggle-position authentication (the
  challenge-off mode included); the availability-read re-pinning re-bases the
  toolset-read fixtures on the listing route and adds the non-admin/public-toolset
  pass case (the regression the live run demands) and the admin-axis refusal
  (design.md D15); the refusal-class split adds the 401→trust-fault and 403→denial
  mapping tests on the listing read (design.md D16).
- `docs/threat-model.md` — the IdP-leg entries are generalized (the back-channel
  trust boundary, the new outbound internet leg to an external IdP, the
  confidential-client secret as process-held secret material — required and
  presented in every deployment, the owner's round-5 ruling, the
  discovery-document
  trust threat), and the availability read's re-pinning lands with its vocabulary
  sweep and the false-denial defect's recorded removal (design.md D15) — and the
  refusal-class split's record lands with them: the trust-fault shape on the
  listing-read row, and the wrong-class diagnosability defect's removal (design.md
  D16) — both
  landed by this change before implementation.
- No change to the client-facing AS surface, the upstream leg, Core's credential API,
  the custody design, or the router's locations (the `callback` alternation already
  covers the new route spelling).
