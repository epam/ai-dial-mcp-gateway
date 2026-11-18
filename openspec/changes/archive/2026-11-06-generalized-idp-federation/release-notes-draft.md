# Release notes draft — generalized IdP federation

### For users

The sign-in gateway now fronts any OpenID Connect identity provider, not just the one
it was first built against: the provider's endpoints are read from its standard OIDC
discovery document at the configured issuer, so a provider with journey-varying
issuers and a custom claims vocabulary — the tested case — or any other OIDC
provider, is a configuration profile rather than a code change. The sign-in client
at the identity provider is a confidential client: a client secret is required and
authenticates every token request (delivered as an environment variable from the
deployment's environment — the same delivery every gateway secret uses), and
providers that cannot support PKCE are handled by turning the sign-in leg's PKCE
challenge off — the client authentication stays on regardless.
Deployments whose provider's discovery document is unavailable, nonstandard, or served
at a spelling the gateway's fetch does not reach can instead configure the provider's
three endpoints directly — all three together, with discovery then skipped entirely;
keeping those endpoints current becomes the operator's responsibility. For a provider whose
issuers vary by sign-in journey, the provider must be configured to issue the
federated journey its own distinct issuer — the
configuration reference states this as a prerequisite. **Breaking for existing local
deployments:** the identity-provider settings are renamed (`KEYCLOAK_*` → `IDP_*`) and
the sign-in callback URL changes from `/dial/callback/keycloak` to
`/dial/callback/idp` — an existing `.env` needs its identity-provider entries renamed,
a client secret configured (`IDP_CLIENT_SECRET`, required at startup in both
positions of the PKCE toggle — the identity-provider client must be registered
confidentially at the provider),
the identity-provider issuer and back-channel base set explicitly (the old
deployment-shaped defaults are gone; the settings model now defaults to a neutral
placeholder), and the provider's client re-registered at the new callback URL before
sign-in works
again; sign-ins in flight during the upgrade simply re-run from the tool. A sign-in
fix rides the same release: users who are not DIAL administrators can now complete
the sign-in flow for any toolset they are entitled to call — previously the flow's
availability check consulted an administrator-only route and refused such users
toolsets the DIAL data path itself serves; the check now reads the same
per-toolset authorization the data path applies, so what a user can call, a user
can sign in to. The `TOOLSET_BUCKET` setting is removed with the old check — a
deployment carrying it simply drops the line. A second sign-in fix rides the same
release: when DIAL Core cannot validate the sign-in itself — a trust-configuration
or connectivity problem between Core and the identity provider — the page now says
so and asks for an administrator, where it previously (and wrongly) told the user
they did not have access to the toolset; a sign-in the deployment cannot validate
is the deployment's to fix, not the user's access to grant. Harness
clients see no change: the client-facing sign-in surface, its PKCE requirement, and
the issued tokens are exactly as before.

### For the team

C2 (the roadmap's P4 — generalized IdP federation) as an OpenSpec change: standard OIDC
discovery replaces the Keycloak URL arithmetic with one spelling of the identity leg
(the code exchange, C1's fresh-claims refresh grant, and key-set resolution all read
the discovered endpoints, validated against the configured issuer — exact `issuer`
match, origin-bound endpoints, HTTPS-only without an explicit back-channel override,
per-process TTL cache); journey-varying issuers are pinned exactly (another journey's
token is refused); the identity-provider client is confidential (the secret required
at startup in both toggle positions and presented on every token request;
`IDP_PKCE_ENABLED` governs the challenge/verifier only, absorbing PKCE-incapable
providers by turning the challenge off while the client authentication stays on),
while the client-facing surface's PKCE and the upstream
verifier's custody are untouched; a directly-configured endpoint set
(`IDP_AUTHORIZATION_ENDPOINT`/`IDP_TOKEN_ENDPOINT`/`IDP_JWKS_URI`, all-or-nothing,
discovery skipped entirely where the full set is configured) is the explicit
alternative source for providers whose discovery is unavailable — a round-2 owner
ruling grounded in how DIAL itself configures IdPs (the gateway's discovery mode
matches the chat's issuer-to-discovery shape; the direct trio matches Core's
explicit-endpoint spelling; Core's regex issuer matching is deliberately not
adopted — the exact pin stands); the client secret's delivery is the environment
slot, with file/KMS variants staying in C3's secret-management scope; the
`KEYCLOAK_*`→`IDP_*` rename and the callback
rotation are one lockstep change across settings, compose, the provisioning helper,
the probes, both operator docs, and the tests (the local-dev helper's own
Keycloak-admin settings keep their names — they describe the local instance, not the
gateway's provider abstraction). The SIA is High-impact (the identity leg gains an
external-internet TLS shape and a load-bearing client secret — required and
presented on every token request in every deployment; the discovery document
is a new integrity-critical input), and `docs/threat-model.md`'s IdP-leg entries are
updated by this change before implementation. The live acceptance run against the tested external provider is an
owner-dependent row (real tenant values arrive from the owner; the change's working
artifacts carry the placeholders), and the MCP conformance suite is a conditional
row. Recorded, not built: the userinfo-federation mode for opaque-token providers.
The live B2C run's first non-admin identity also exposed and fixed a false denial in
the flow's availability read: the read was Core's admin-only platform route, which
refused non-admin users toolsets the MCP data path serves, so the availability
oracle is re-pinned to the deployment-listing read — the route authorized by the
same deployment resolution the data path uses, carrying the projection the upstream
leg builds from and the per-caller signed-in statuses, making it the flow's one
toolset read and retiring `TOOLSET_BUCKET`; the field-parity verification, the
semantic notes (a toolset with no auth settings answers a fault either way; an
invalid stored toolset answers the data path's own 404; resource-sourced toolsets
are no longer falsely "not registered"), and the SIA re-pricing (the read's
authorization now equals the data path's — the forged-answer residue is the
existing internal-leg acceptance, and the false-denial class is removed) are
recorded in the change's design (D15) and evidence. The same live run also exposed
the flow's 401/403 conflation — Core's "cannot validate this token" answered as "no
access" on the page and the audit trail, undiagnosable at Core (which logs no record
of its 401s) — so the listing read's refusal classes are split (D16): 403 keeps the
no-access page, 401 becomes the operator-facing trust-fault page with a
fixed-vocabulary audit reason, the flow consumed with no credential retained; the
SIA records the wrong-class diagnosability defect as removed and the forged-answer
residue unchanged (a forged 401 costs one flow, the same as a forged 404).
