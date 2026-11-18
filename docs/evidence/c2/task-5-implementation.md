# Task group 5 — operator documentation (tasks 5.1–5.2)

Change: `generalized-idp-federation` (C2). Scope of this record: the operator-facing
documentation of what groups 1–4 landed, the doc-vs-code spot-check behind every
documented behavior, the runnable verifications, and the one cross-group finding the
spot-check surfaced. No commit made. Files touched: `docs/gateway-configuration.md`,
`docs/local-environment.md`, `README.md`, this record — nothing else.

## Task 5.1 — `docs/gateway-configuration.md`

Every element the task row spells, in the doc's own voice, provider-neutral per the
round-3 vocabulary boundary (classes and mechanisms only; the only product-named surface
is the local development realm's own facts):

- **The `IDP_*` settings reference.** The federation-flow settings table gains
  `IDP_DISCOVERY_CACHE_TTL_SECONDS` (300), `IDP_PKCE_ENABLED` (`true`), and the direct
  endpoint trio (`IDP_AUTHORIZATION_ENDPOINT` / `IDP_TOKEN_ENDPOINT` / `IDP_JWKS_URI`,
  unset by default); the `IDP_CLIENT_ID`, `IDP_CLIENT_SECRET`, `IDP_CLIENT_SCOPES`, and
  `IDP_ISSUER` rows are re-worded to provider-class guidance (an external provider's
  client is registered in the provider's own admin console; `openid` in the scopes is a
  per-provider fact — the local realm forbids it, an external provider commonly requires
  it; a varying-issuer provider's configured issuer is the one federated journey's).
- **The endpoint-source section** (`### The identity leg's endpoint source`): discovery
  as the default (fetched at `{IDP_ISSUER}/.well-known/openid-configuration`, lazy
  first use, per-process TTL cache, no startup fetch, fail-closed with no fallback
  construction) and the directly configured trio (no fetch attempted at all,
  all-or-nothing, one source per leg chosen by configuration and never by a runtime
  event); when to choose the trio instead of discovery (discovery unavailable,
  nonstandard, or served at a spelling the issuer-appended fetch does not reach —
  varying-issuer providers often in that class); the mode's trade stated (endpoint
  freshness is the operator's: discovery propagates a provider's endpoint change within
  the TTL, direct mode not at all); the family-alignment note on the names (the OIDC
  discovery member names, matching Core's explicit-endpoint `authorizationEndpoint`/
  `tokenEndpoint` concepts — one vocabulary across a discovery document, Core's
  configuration, and these settings); validation in both modes, including the
  deliberately-differing rule (a direct endpoint is not origin-bound to the issuer —
  operator input at the issuer setting's own trust level; split-origin providers are
  the shape the mode absorbs).
- **The local realm profile** (`### Configuration profiles`): the local development
  instance's own name kept — the override to its internal plain-http port
  (`IDP_BACKCHANNEL_BASE_URL=http://keycloak:8900`,
  `IDP_ISSUER=https://keycloak:8443/realms/dial`), scopes without `openid`.
- **The varying-issuer external-provider profile**: the configured issuer is the one
  sign-in journey's; `ROLES_SOURCE_PATH` to the provider's claim spelling; `openid` in
  the scopes where the provider requires it; `IDP_SSO_SESSION_MAX_SECONDS` to the
  provider's refresh-token window.
- **The operator prerequisite row** (generic terms, no product's property name): a
  varying-issuer provider must be configured for **journey-distinct issuance** — one
  `iss` per sign-in journey; where that is a provider-side setting it must be enabled,
  because with it absent every journey's tokens share one issuer and **every sign-in
  fails at issuer verification**, diagnosable by a from-documentation operator only
  from this stated prerequisite.
- **The override's origin-as-trust-claim warning** (`### The back-channel override is a
  trust claim`): the override's origin is a trust claim exactly as wide as its
  hostname; an endpoint the discovery document names is accepted on any origin the
  override covers, so point it at an origin serving only the identity provider.
- **The no-PKCE mode's priced trade** (`### The no-PKCE mode, and what it costs`):
  off only for a provider that cannot support PKCE; the exchange and refresh grant
  authenticate with the secret; startup refuses the mode without one; the trade priced
  (the challenge binding is gone and the secret is the only remaining bar — on a
  plain-http front door the code is readable on the wire; a strictly weaker position
  than the default's); the client registered confidential at the provider; the mode is
  the identity leg's alone; in the default mode a configured secret is never presented
  on any leg.
- **The client-secret delivery statement** (Secrets section, `IDP_CLIENT_SECRET` row,
  the full shape): an environment variable from the deployment's `.env` — the same
  delivery the signing and custody keys use; never argv, never a file the gateway
  reads; file-mounted or orchestrated injection is the deployment's own mechanism
  *feeding that variable* (the gateway reads the environment slot either way); the
  secret-management move is the production roadmap's secret-management item.
- **The startup-refusals table** gains the five new refusals (no-PKCE without secret;
  partial trio; malformed direct endpoint; plain-http direct endpoint without the
  override; plain-http issuer without the override), each with its why.
- **Consistency touch-ups**: the flow narrative's step 1 now states the redirect
  carries the challenge in the default mode; the Tokens section's PKCE sentence scopes
  itself to the client-facing surface.

## Task 5.2 — `docs/local-environment.md` and `README.md`

- `docs/local-environment.md` gained **the external-provider configuration sketch**
  (`### An external provider's profile (the sketch)`), provider-neutral, explicitly
  "nothing below is a value to copy": the journey issuer pinned exactly, the
  journey-distinct-issuance prerequisite, the client/secret shape (public PKCE by
  default; confidential for the no-PKCE mode), scopes with `openid` where the provider
  requires it, the roles claim path, the refresh-token window, and one-TLS-origin
  providers needing no override. The local realm profile and the `/dial/callback/idp`
  spelling were already carried by group 2's rename sweep and are verified unchanged.
- `README.md` gained the federation-profile paragraph in the Configuration section
  (the `IDP_*` block, discovery default, the direct trio, the placeholder default, the
  pointers to both docs) and the callback spelling in the bring-up sequence (step 2
  states the client is registered against `http://localhost:8090/dial/callback/idp`).

## Doc-vs-code spot-check (each documented behavior → the code that has it)

| Documented behavior | Code that implements it | Result |
|---|---|---|
| Discovery at `{IDP_ISSUER}/.well-known/openid-configuration`, lazy, TTL-cached | `gateway/idp.py` `_DISCOVERY_PATH`, `_discovered_endpoints()`, `_cache_is_fresh()`; `gateway/settings.py` `idp_discovery_cache_ttl_seconds` default 300 | match |
| No startup fetch; boots with the provider unreachable | no fetch at construction (`IdentityProviderClient.__init__` holds no fetch); compose-boot gate green (task 2.6's record, re-run this pass) | match |
| Document `issuer` must equal `IDP_ISSUER` exactly; off-origin endpoint refused; plain http refused without the override; redirects not followed; size-capped; refused whole | `_validated_endpoints()` (issuer equality, `allowed_origins`, scheme check, `_DISCOVERY_MAX_BYTES`); `_fetch_discovery_document()` (`follow_redirects=False`) | match |
| Direct trio: all-or-nothing with partial-set refusal naming configured and missing members | `gateway/settings.py` `_validate_direct_endpoint_set()` (`_DIRECT_ENDPOINT_SETTINGS` order) | match |
| Direct members: well-formed absolute URL, HTTPS unless sharing the override's origin; no issuer-origin binding (split-origin legitimate) | `_validate_direct_endpoint_set()` (the documented "deliberately absent" paragraph matches the validator's comment) | match |
| Direct mode fetches nothing; configured endpoints serve all four legs | `idp.py` `_resolved_without_fetch()` / `_configured_endpoints()` — direct mode answers before any fetch path | match |
| Override: scheme/host swapped, path kept; token/key-set legs re-addressed; authorization endpoint untouched; issuer pin unaffected | `backchannel_addressed()`, `_with_backchannel_applied()`; `verified_claims()` pins `issuer=self.issuer` | match |
| Plain-http issuer refused at startup in both modes, naming the setting | `gateway/settings.py` `_require_https_issuer_without_the_override()` | match |
| No-PKCE mode: no challenge on the redirect; secret on the exchange and the refresh grant; startup refusal naming both settings | `idp.py` `authorization_url()` (challenge only when `idp_pkce_enabled`), `_client_authentication()`, `_post_token()`/`_post_refresh()`; `settings.py` `_require_client_secret_in_no_pkce_mode()` | match |
| Default mode never presents the secret on any leg | `_client_authentication()` returns `{}` when PKCE is on — the opportunistic send removed in group 4 | match |
| Client-facing surface still requires PKCE from harness clients | `gateway/authorize.py` untouched by the mode (group 4's boundary inspection) | match |
| Callback `/dial/callback/idp`, derived not configured | `gateway/settings.py` `IDP_CALLBACK_PATH`, `idp_callback_path` property | match |
| Setting names/defaults as tabulated | `gateway/settings.py`: `idp_issuer` default `https://idp.example.com/`, `idp_client_id` `dial-mcp-proxy`, `idp_client_scopes` `profile,email`, `idp_sso_session_max_seconds` required, `idp_backchannel_base_url`/trio optional (blank = unset) | match |

## Runnable verification (recorded outcomes)

Task 5.2's row — the documented local bring-up sequence, run as written (the stack was
still up from group 2; **no restart was needed** — `compose up -d` reported both
services Running/Healthy in place):

1. `wsl -e docker compose up -d` — both services `Up (healthy)` (gateway health probe
   green; router green). No recreation.
2. `python scripts/provision_keycloak.py` — idempotent: "second run was a no-op"; the
   held client shows `redirectUris = ["http://localhost:8090/dial/callback/idp"]`,
   `publicClient = true`, S256 pinned.
3. `python scripts/probe_gateway_trust.py` — green (negative control: an unpublished
   signer refused; a gateway-signed token resolves a real identity).
4. `python scripts/probe_routing.py` — all 10 probes passed.
5. `python scripts/probe_end_to_end.py` — the full chain through the front door and the
   new callback route: authorize → provider login → callback → exchange → minted token
   (`roles ["admin"]`, `project "proj-alpha"`, refresh present) → live tool call, 200
   with 74 tools.

Task 5.1's row — the settings the local stack reads, run as written: the profile
`IDP_ISSUER=https://keycloak:8443/realms/dial` + `IDP_BACKCHANNEL_BASE_URL=http://keycloak:8900`
drove the e2e run above (the discovery fetch, exchange, and refresh went through the
override's origin with the realm's path kept, the issuer pin exact) — the documented
local-realm profile, the override semantics, and the scopes-without-`openid` guidance
all ran as written. `IDP_SSO_SESSION_MAX_SECONDS=86400` ≥ `GATEWAY_REFRESH_TTL_SECONDS=28800`
(startup check passed — the refusal row's converse), and `ROLES_SOURCE_PATH=roles`
resolved (the minted token carries roles). Not runnable against the local profile, by
design of the local shape: the direct endpoint trio, the no-PKCE mode, and the cache
TTL are off-path here — their behaviors are the unit suite's (below), and the
operator-reference text documents them from the code and spec, spot-checked above.

## Gates run this group

- Publication leak check `python scripts/check_publication_leaks.py` — **PASS** (exit
  0): 211 tracked files, the same 3 pre-existing waived findings (all in
  `docs/evidence/d0a/` and `scripts/import_background.py`), none added by this group.
- The vocabulary-boundary grep over the three docs
  (`entra|b2c|azure|microsoft|tfp|b2clogin|ciamlogin|onmicrosoft|external id|statgpt`)
  — **zero hits** after one self-caught fix: the sketch's first draft said "an external
  identity provider's profile", whose substring hits the pattern list's `external id`
  (the successor product's name); reworded to the docs' established generic spelling
  ("an external provider's profile"). No internal hostname was added beyond the
  D8-scoped local-instance facts these docs already carry.
- `pytest -q` — **601 passed, 1 skipped** (same totals as group 4's record; the
  example-completeness test still green — `.env.example` untouched this round).

## Findings and deviations

1. **FINDING (code surface, groups 3–4 — out of this group's file scope, reported not
   fixed):** `docker-compose.yml`'s gateway environment block does not pass
   `IDP_PKCE_ENABLED`, `IDP_DISCOVERY_CACHE_TTL_SECONDS`, or the direct endpoint trio
   (`IDP_AUTHORIZATION_ENDPOINT` / `IDP_TOKEN_ENDPOINT` / `IDP_JWKS_URI`). The compose
   file deliberately names each setting one by one (no `env_file` into the container,
   and no `.env` inside the image), so a **composed deployment cannot configure these
   five settings** — a no-PKCE or direct-mode profile set in the deployment's `.env`
   never reaches the container. Groups 3/4 landed the settings model, the refusals, and
   the unit coverage; the compose environment block was task 2.3's surface for the
   *renamed* settings only, and no task row extended it to the new ones. The operator
   docs document the settings (they exist and are honored by the settings model and any
   deployment that passes them); the compose gap needs a follow-up row or a group-6
   disposition — a compose deployment that cannot turn the modes on is a gap the review
   gate should see.
2. No deviations from the stated file scope: only the three docs and this record were
   touched (`git status` clean otherwise). One prose fix inside the docs (the
   `external id` pattern hit above) was made and is recorded rather than hidden.
3. The docs read standalone — no design-decision references, no change-folder paths, no
   "per D14" anywhere in the operator-facing text; the vocabulary boundary itself is
   this group's discipline, stated here in the evidence only.
