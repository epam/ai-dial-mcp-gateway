# Release notes — pin-implemented-security-behaviors (draft)

### For users

- **No visible change this release.** The sign-in gateway behaves exactly as it did
  before: same flows, same responses, same tokens. This release writes down, as
  specification, four security behaviors the gateway already had — so they are now
  guarantees the gateway must keep meeting, rather than features it happens to have.

### For the team

- **Four implemented security behaviors are now spec-bound** (one delta spec in
  `mcp-signin`: three added requirements, one amended):
  - **RFC 9207 `iss` on every authorization response** — success redirects and
    redirected errors both carry the gateway's issuer, the mix-up defense the flat
    single-issuer design makes necessary (threat model M9, T1-12/T1-13; MCP
    2026-07-28 requires it).
  - **Per-flow lifecycle audit records** — every allocated flow's events (allocation,
    upstream callback, credential-call result, code issuance, leg failures) land on
    the trail under the same credential-free, fixed-vocabulary, bounded-fact
    discipline the refusals already had, so a completed sign-in is attributable end
    to end (M11; T1-16's detective entry; the consent-attribution audit chain).
  - **JWT verification hygiene** — inbound verification pins the algorithm and the
    key selection: the gateway's own tokens against the gateway's own key under its
    own algorithm; the provider leg's `kid` resolved only in that provider's JWKS —
    so token headers can never select key material or algorithm (M20; T4-7's
    algorithm-confusion / embedded-key / `kid`-steering threat).
  - **The toolset-name charset** — a mapped name outside `[a-z0-9-]` refuses startup,
    the shape the router's static locations are written against (M10; T6-2/T6-7).
- **Why spec-only, and how it was verified.** The owner's mandate was to bring the
  spec in sync with the implementation, verifying first that the spec — not the
  implementation — was what needed changing. Each delta was checked against its
  code, its tests, and its threat-model mandate before a line of spec was written;
  the record, with citations, is in the change's `design.md`. Nothing was stopped
  on: all four behaviors are real, correct, and mandated.
- **The threat model's four "flagged" placement notes close** at this change's
  completion (M9, M10, M11, M20 flip from "repo — flagged: candidate spec change"
  to "Placed — spec"): the landing rule — a gateway-owned mitigation that exists
  only in code is not landed — is satisfied for all four.
- **Deliberately not pinned** (owner-excluded, staying repo controls per the threat
  model's notes): the CIMD fetch's JSON content-type, timeouts, and User-Agent;
  outbound-call timeouts and bounded response parsing beyond what the spec already
  pins.
