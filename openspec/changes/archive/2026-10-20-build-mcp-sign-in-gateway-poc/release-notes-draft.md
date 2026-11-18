# Release notes — build-mcp-sign-in-gateway-poc (draft)

### For users

- **Sign in to DIAL MCP toolsets from your harness — no DIAL Chat needed.** Point your
  harness at the toolset's front-door path (for example
  `claude mcp add --transport http notion http://localhost:8090/dial/notion/mcp`),
  complete the one-time browser sign-in (your DIAL identity, then the toolset's own
  consent — the same consent you would have given in Chat), and use the toolset. From
  then on, calls are silent: your harness refreshes its token without a browser, and
  DIAL Core injects your stored toolset credential on every call.
- **Failure states are actionable now.** A missing toolset sign-in answers with the
  gateway's own challenge (never the upstream's dead-end pointer), so your harness
  gets a sign-in flow it can actually complete instead of discarding its session.
- **Scope of this release:** OAuth toolsets only. Toolsets that need an API key are
  not yet reachable through the gateway and keep their existing sign-in path.
- **A gateway restart does not sign you out.** Your tokens are self-contained, so
  restarts never invalidate your session — and where your operator has enabled
  dynamic client registration, your harness's registration is kept on disk and
  survives restarts. If that store is ever lost, your harness simply re-registers
  on its next sign-in; no human action is needed.

### For the team

- **One change carried the whole PoC** (owner decision): the Stage 0 spike, the
  gateway (Python 3.12 + FastAPI), the front-router nginx, the sibling-instance
  configuration (Core env vars, one pre-registered public PKCE Keycloak client, the
  `notion` toolset registration), and the PoC C acceptance gate.
- **The spike ran first with a hard falsification stop**: Core accepting a
  gateway-minted JWT as an additional identity provider was the single untested link;
  everything after it was built only once that link held. Negative controls
  (mismatched issuer, missing audience marker, wrong key) ran before the positive.
- **Design decisions of record:** refresh is a self-contained snapshot with a
  non-sliding 8 h window — never staler than the deployment's own 24 h vanilla bound,
  and the bound is enforced at startup against the configured identity-provider
  access-token lifespan; claim copy is whole-payload-minus-registry-claims with a
  required roles source path
  that fails loudly instead of minting role-less tokens; CIMD registration is primary
  with its SSRF controls specified and an explicit User-Agent on the document fetch;
  the toolset mapping is OAUTH-only with reserved
  names enforced at startup; one flat AS serves all toolsets with `resource`
  (RFC 8707) as the required disambiguator, and a client's `scope` parameter never
  reaches the identity-provider leg.
- **Owner rulings carried:** the OR-2 deviation (one always-on component) and the
  nginx 401 challenge synthesis are accepted and recorded in the change's design.
- **DCR registration records are durable without a database:** one JSON file in a
  mounted volume, loaded at startup, written atomically before the registration
  response is returned; a corrupt store refuses startup with an operator-facing
  error naming the path; a cap refuses new registrations while leaving existing
  ones untouched. The flag stays default-OFF and gates resolution too — with it
  off, the store is preserved but dormant. Loss means one re-registration
  round-trip per harness, self-healing with no human action. DCR is proven
  in-change as tasks with their own evidence rows (flag-off disabled-error →
  register → authorization flow → live toolset call → restart persistence), not
  as a PoC C criterion.
- **The PoC C gate is the exit criterion**: five criteria on a real harness (first
  use, silent repeat + refresh with rotation, mid-session sign-out branch,
  query-string survival, direct-to-Core coexistence). A failing criterion falsifies
  the design and reopens it — it is not patched around.
- **After PoC C, the owner takes the revocation-SLA decision** with the measured
  rotation and staleness numbers; the claims re-fetch upgrade path is prepared in the
  design's refresh options.
- **Security of record:** all seven never-cut invariants were analyzed against the
  change and preserved (the full analysis and rulings are in the change's design);
  the signing key is IdP-grade material, generated and injected — never committed,
  never logged.
