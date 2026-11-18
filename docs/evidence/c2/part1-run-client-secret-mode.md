# Part 1, mode 1 — the client-secret mode's live B2C run: PASS

Date: 2026-11-06. Task 7.1 Part 1, the challenge-off position
(`IDP_PKCE_ENABLED=false`). The human signed in at the provider's own
hosted page; the probe (`scripts/probe_end_to_end_interactive.py`,
loopback-capture mode) drove the client side and the assertions.

## The verdict (the probe's own output, tail)

    === step 5: /dial/token ===
      status    200
      access    <redacted len=1337>
        iss      "http://localhost:8090"
        sub      "<tenant-user-sub>"
        aud      ["http://localhost:8090/dial/notion/mcp", "dial-mcp-proxy"]
        roles    ["<tenant-role>"]
      refresh   present
      project   no project claim — the provider carries none; optional by design
    === step 6: a live tool call through the front door (/dial/notion/mcp) ===
      status    200
      tools     77
      first     ["notion-search", "notion-memory-search", "notion-get-tool-access"]
    === smoke verdict ===
      a human signed in at the provider's own page and the flow's token
      authenticated a live tool call: the deployment is wired end to end

## The facts this run verified live

1. **Discovery-mode federation with the tested tenant** — the discovery
   fetch at the tfp-issuer-appended path (the D9 fact (a), pre-verified
   empirically), the document's `issuer` equal to the tfp issuer (fact
   (b)), the exact-string pin (trailing slash included) holding at the
   exchange.
2. **The confidential client (D5's "simply client_secret" mode)** — the
   exchange authenticated with `IDP_CLIENT_SECRET`
   (`client_secret_post`; the provider's discovery document advertises
   exactly that).
3. **The listing-read availability oracle (D15)** — the federated
   non-admin user (`roles=["<tenant-role>"]`) passed availability and
   walked into the upstream consent; the platform route had denied this
   user class unconditionally (the false-denial defect, fixed).
4. **Core trusting the provider** — the `audience` pin corrected to the
   token's actual `aud` (the bare client id; the scope URI form is what
   *mints* the token, not what the token is *to*) — the earlier 401s'
   single root cause.
5. **The roles claim path** — the provider's `roles` claim carried into
   the gateway's minted token verbatim.
6. **The session refresh token present** — with `offline_access` in the
   configured scopes (the operator's Postman-verified set; the D9
   fact's final shape: the confidential client receives refresh tokens
   with `offline_access` granted).
7. **A live tool call** through the front door — the minted token
   authenticated the MCP call (200, 77 tools).

## The debugging trail this run closed (all recorded in the evidence folder)

- the provider's scope semantics (an audience-carrying scope is required
  for an access token to exist at all);
- the availability-oracle defect (the admin-only platform route);
- the 401/403 conflation (the trust-fault split, D16);
- the WSL/GlobalProtect egress outage (infrastructure, not the change).

## Still open in task 7.1

- Part 1, mode 2: the challenge-on position (`IDP_PKCE_ENABLED=true` —
  "secret + PKCE").
- The refresh leg's live verification (fresh claims within the access
  TTL; session revocation ending the refresh capability).
- Part 2: the real deployment + the real app.
