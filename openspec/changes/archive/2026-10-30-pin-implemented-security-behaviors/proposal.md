# Proposal

## Why

The implementation runs ahead of the spec on four security behaviors: each is real,
tested, and mandated by the threat model's rulings, yet none is pinned as a spec
requirement — exactly the gap the threat model's placement notes flag ("a gateway-owned
mitigation that exists only in prose or code is not landed as a spec requirement": M9's
RFC 9207 `iss`, M10's toolset-name charset, M11's per-flow lifecycle records, M20's JWT
verification hygiene, each marked **flagged: candidate spec change**). The owner's
mandate, verbatim in intent: *"let's bring the spec in sync with implementation. Just
verify that this is the spec that needs to be changed (not the implementation
incorrect)."* So this change is spec-only, and every delta below was verified against
the implementation and its tests before a line of spec was written — the implemented
behavior is real, correct, and threat-model-mandated in all four cases (the verification
record, with file and test citations, is in `design.md` §"Verify-first evidence").

## What Changes

Four delta requirements in `mcp-signin`, pinning behavior the implementation already
has. No code change, no behavior change, no new surface — the deltas are the mechanism
by which the main spec gains these lines when the change is synced.

- **RFC 9207 `iss` in authorization responses** (ADDED requirement). Every
  authorization response the gateway returns to the client — the success redirect with
  the code and every redirected error — MUST carry the `iss` parameter equal to the
  gateway's issuer, so a client that talks to several authorization servers can tell
  which one answered (the mix-up defense the flat single-issuer design makes necessary;
  threat model T1-12/T1-13, mitigation M9). Implementation:
  `gateway/flow.py` (`harness_redirect`), `gateway/errors.py` (`redirect_error`);
  tested on both the success and the error path.
- **Per-flow lifecycle audit records** (ADDED requirement). Every allocated flow MUST
  record its lifecycle events — allocation, upstream callback, credential-call result,
  code issuance, leg failures — under the same credential-free, fixed-vocabulary,
  bounded-fact discipline the spec already pins for pre-allocation refusals, so a
  completed flow's chain is attributable end to end (threat model T1-16's detective
  entry, mitigation M11; the consent-attribution design's audit chain). Implementation:
  `gateway/audit.py`, wired through `gateway/authorize.py`, `gateway/federation.py`,
  `gateway/token.py`; PoC-evidenced.
- **JWT verification hygiene** (ADDED requirement). Inbound token verification MUST pin
  the algorithm and key selection so token headers cannot select key material or
  algorithm: the gateway's own tokens are verified against the gateway's own key with
  the signing key's own pinned algorithm; the provider leg's `kid` is resolved only in
  that provider's own JWKS, under a pinned algorithm, with the issuer checked
  (threat model T4-7 — algorithm confusion, embedded-`jwk`/`x5c`, `kid` steering;
  mitigation M20). Implementation: `gateway/tokens.py` (`decode_own_token`),
  `gateway/idp.py` (`_verified_claims`, `_signing_key`).
- **The toolset-name charset** (MODIFIED requirement — "The toolset mapping is safe to
  configure"). A mapped toolset name MUST match the routed-path charset
  (`[a-z0-9-]`), refused at startup with an operator-facing error naming the setting —
  the shape the router's static regexes (`^/dial/[a-z0-9-]+/status$`,
  `^/dial/(?<tname>[a-z0-9-]+)/mcp$`) assume, so a relaxed code check could not
  silently diverge from the routing (threat model T6-2/T6-7, mitigation M10).
  Implementation: `gateway/settings.py` (`_TOOLSET_NAME`, startup-validated).

**Out of scope** (the owner could not evaluate these; they stay repo controls, per the
threat model's placement notes — no spec text is added for them here):

- The CIMD fetch's JSON content-type, connect/total timeouts, and explicit User-Agent
  (M7's repo-side controls).
- Outbound-call timeouts and bounded response parsing beyond what the spec already
  pins.
- Any change to code, to the main spec directly (the delta spec is the mechanism), to
  `docs/threat-model.md`, or to the method files.

## Capabilities

### New Capabilities

(None — no new capability; all four deltas land in the existing `mcp-signin`
capability.)

### Modified Capabilities

- `mcp-signin`: three ADDED requirements (RFC 9207 `iss` in authorization responses;
  per-flow lifecycle audit records; JWT verification hygiene) and one MODIFIED
  requirement (the toolset-mapping requirement gains the toolset-name charset and its
  startup refusal). No existing requirement is removed or renamed; every other
  requirement is untouched.

## Impact

- **Spec-only diff.** No code, test, configuration, or deployment change; the
  implemented behavior already exists and is green under the current suite. The
  delta's scenarios are written to map onto the existing tests (and, for the JWT
  hygiene scenarios, onto the pinned verification call's library-guaranteed semantics —
  see the verification record for what each scenario rests on).
- **Sync effect.** On sync/archive, `openspec/specs/mcp-signin/spec.md` gains three
  requirements and one amended one. The threat model's M9/M10/M11/M20 placement notes
  then flip from "repo — flagged: candidate spec change" to "Placed — spec"; updating
  those notes is the threat-model follow-through the change's tasks track (the
  threat-model edit itself is not part of this spec-only diff and happens per the
  standing rule at the change's completion, owner-approved).
- **No security impact claimed for the diff itself** — the diff adds no surface and
  changes no behavior; the security review gate runs at focused depth to falsify that
  claim, per the repo's gates. The full SIA is in `design.md`.
