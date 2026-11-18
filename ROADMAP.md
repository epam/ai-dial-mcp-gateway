# Roadmap

**What this file is.** The plan for the **current iteration** — right now, the proof of
the design (the PoC) — plus the standing security invariants.

**What it is not.** It is not an ultimate roadmap or a final target. This repository will
grow beyond it: later iterations add their own stages here (and move completed ones into
their change folder's record), and the roadmap is expected to be revised as the design
and the product develop.

Stages are criteria-triggered, not calendar-triggered. Each stage is gated on its spec's
conformance rows (`openspec/specs/`) and the gate ladder in `PROCESS.md`.

## Never-cut list

Standing security invariants — permanent, not iteration-scoped. They are never cut, at
any stage, under any schedule pressure:

1. **The upstream credential never leaves Core.** No flow may deliver an upstream
   access/refresh token to a harness, and no component may relay a caller's token
   upstream as its own (token passthrough).
2. **The upstream PKCE verifier never leaves Core.**
3. **Per-user credential isolation.** A stored upstream credential is resolvable only by
   the identity that created it.
4. **DIAL authorization applies to every toolset call** — including calls made with a
   gateway-minted token.
5. **No credential in logs, argv, or error messages.** Failure messages fail closed and
   do not leak.
6. **No hardcoded credentials in the repository.** Local configuration is `.env`
   (gitignored) with committed `.env.example` placeholders.
7. **The gateway's signing key is treated as IdP-grade secret material** — never
   committed, never logged, rotatable.

Scope cuts elsewhere follow the stage order below and are recorded in the change folder.

## Stages of the current iteration

These stages take the repository from empty to a proven design. They are the current
iteration's plan, not the product's end state.

### Stage 0 — Spike: Core accepts a gateway-minted JWT

The single untested link in the design. Everything downstream depends on it.

- Mint an RS256 keypair and a JWT carrying a real user identity (`sub`, roles).
- Register the signer in Core as an additional identity provider
  (`identityProviders.<name>.jwksUrl` + `issuerPattern` + `audience`).
- Confirm Core accepts it: `GET /v1/user/info` resolves the identity, and a toolset MCP
  call with it resolves that user's upstream credential.
- Negative control first: a token with a mismatched issuer is rejected.

**Gate:** Core resolves the identity and the toolset call works, or the design is
revised.

### Stage 1 — Gateway skeleton

The sign-in gateway as an OAuth2 authorization server: discovery documents (protected
resource + AS metadata at the host root), CIMD client resolution (fetch + validate the
client's metadata document; origin allowlist; redirect_uri validation), `/authorize`
entry, `/token`, `/jwks.json`.

### Stage 2 — Federation

The `/authorize` choreography: Keycloak leg (user authentication) → DIAL authorization →
upstream consent leg → `POST /v1/ops/toolset/signin` → issue the gateway's own code and
token. Flow state, TTLs, and the rate limits.

### Stage 3 — Front routing

nginx in front: AS paths → gateway; toolset MCP path → Core direct; the 401 challenge
rewrite; query-string and SSE pass-through.

### Stage 4 — PoC C: the implementation gate

Run the five acceptance criteria end to end. Failure of any criterion is *falsification*
of the design and reopens the cycle — not an unexpected behavior to patch around.

1. Real-harness first use, end to end (CIMD path).
2. Silent repeat use, and refresh with refresh-token rotation.
3. Mid-session upstream expiry takes the sign-in-again branch — not a loop.
4. Query strings survive the front routing on the MCP path.
5. A direct-to-Core client using a Keycloak-issued token coexists with proxy-fronted
   clients.
