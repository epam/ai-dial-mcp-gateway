# D2 — owner sanity test 1: stale claims in the gateway access token

The owner tested the reconciling baseline with a targeted question: stale claims in the
gateway's access token — treatable as an **integrity threat to the access token** — what
does the model say about the relevant attack vectors and mitigations?

## What the model (run A baseline) currently says

The issue is carried as **RES-6 — Role staleness within the refresh window**, a disclosed
residual bounding never-cut invariant 4 (DIAL authorization on every call), not as a
threat row: authorization runs on a gateway-asserted snapshot frozen at issuance; a
revoked user's toolset access can outlive their Keycloak session by up to `refreshTtl`
(locally 8 h, startup-enforced never to exceed the IdP's own access-token lifespan — 24 h
in this deployment). Compensating controls: non-sliding rotation (the rotated refresh
token keeps its original absolute `exp`), the 10-minute access TTL, the next flow
re-authenticating live, the revocation-latency paths (refresh `jti` denylist ≤ 10 min;
key rotation ≤ JWKS cache TTL). Re-open condition: the owner's revocation-SLA decision —
the claims-re-fetch design is the documented upgrade path (= iteration item P2, change
C1, whose delta spec lands the mitigation and whose SIA updates the threat model).
Interlocking residuals: RES-7 (marker-level audience binding only), RES-8 (no per-user
kill of live access tokens — inherent to non-introspected JWTs).

## The owner's classification, assessed

Correct on the CIA axis: the token's cryptographic integrity is intact; what goes stale
is the **fidelity of its claims to the identity provider's current truth** — an integrity
property of the authorization data. Vector classification per the taxonomy: Use Control
Misconfiguration → Elevation of Privilege → **Bypass Authorization** (the attacker's
gain is access beyond current authorization). Attacker class: primarily the **legitimate
business user** (mis-use case), secondarily the token thief — a stolen token retains
stale privileges even after IdP-side revocation, compounding RES-7/RES-8.

## Findings for the reconciliation / review passes

1. **Missing explicit threat row.** Both runs carry stale-claims mis-use only as a
   residual. The merged baseline should carry an explicit EP1 threat row: "stale-claims
   access token used after role revocation/downgrade **[mis-use]**", classified EoP →
   Bypass Authorization, targeting the per-`sub` credential binding, with its own
   8-category mitigation grid (Reduce Attack Surface: the TTL knobs; Authorization:
   Core's per-call DIAL authorization on the snapshot; Detective: the audit trail; the
   remaining categories threat-specific N/A). This raises the canonical threat count
   above the comparison's 54 — the reconciliation record must state the new count.
2. **Cross-reference defect in run A's RES-6**: it cites "(T1-4 bounding" — T1-4 is the
   toolset/leg mix-up threat, not staleness. Fix the pointer to name the new
   stale-claims threat row.
