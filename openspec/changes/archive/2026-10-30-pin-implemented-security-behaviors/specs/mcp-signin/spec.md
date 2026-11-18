# Spec Delta

## ADDED Requirements

### Requirement: Authorization responses identify their issuer

Every authorization response returned to the client — the success redirect carrying the code and every error redirected to a validated client redirect URI — MUST carry the `iss` parameter (RFC 9207) equal to the gateway's issuer: the public origin, the same value the authorization-server metadata document advertises. The flat single-issuer design makes the parameter necessary: a client that talks to several authorization servers tells which one answered by `iss` alone.

#### Scenario: Success redirect carries the issuer
- **WHEN** a valid authorization request completes and the browser is redirected back to the harness with the code
- **THEN** the redirect carries `iss` equal to the gateway's issuer, alongside the code and the echoed `state`

#### Scenario: Redirected error carries the issuer
- **WHEN** an authorization request fails after the client and its redirect URI are validated, and the error is redirected to the client
- **THEN** the redirect carries `iss` equal to the gateway's issuer, alongside the error and the echoed `state`

#### Scenario: A harness matches `iss` against the AS metadata document
- **WHEN** a harness that talks to several authorization servers receives the gateway's authorization response and reads its `iss`
- **THEN** the value matches the issuer of the authorization-server metadata document the harness discovered, so the response is attributable to this authorization server and not to another

### Requirement: Flows are audited through their lifecycle

Every allocated flow MUST record its lifecycle events — allocation, the upstream callback, the credential call's fixed-vocabulary result, code issuance, and leg failures with the failing leg's name — under the same discipline pre-allocation refusals are audited with: fixed vocabulary, the non-credential facts (flow id, subject, client id, toolset), each caller-supplied fact truncated to the configured cap. No token, code, key, or free-form caller input may reach a flow record.

#### Scenario: A completed flow's chain is attributable end to end
- **WHEN** a flow completes from allocation to code issuance
- **THEN** the trail carries its lifecycle events under one flow id, each carrying the client id and the toolset, and — once the flow knows the user — the subject, so the sign-in is attributable to the acting user

#### Scenario: A refused or failed leg is recorded with its outcome
- **WHEN** the credential call is refused, or a flow leg fails
- **THEN** the trail records the fixed-vocabulary result or the leg failure with the leg's name — never the counterparty's own response text

#### Scenario: A credential-shaped value never reaches a flow record
- **WHEN** a flow event is recorded after the flow handled credentials — the identity token, the upstream code, the issued code — or a caller offered a credential-shaped value
- **THEN** the record carries identifiers and outcomes only: no token, code, key, or free-form caller input is written

### Requirement: Inbound tokens are verified with pinned algorithm and key selection

Inbound JWT verification MUST pin the algorithm and the key selection, so a token's header can select neither. The gateway's own tokens — codes, access tokens, refresh tokens — are verified against the gateway's own signing key under that key's pinned algorithm, with the issuer checked. The identity provider's tokens are verified under a pinned algorithm and the configured issuer, with the `kid` resolved only in that provider's own published key set; key material embedded in a token header is never used. A token whose header carries no `kid` resolves to the provider's first published RSA signing key — the behavior the implementation has, stated so a from-spec reimplementation cannot silently refuse such tokens; with a single-key key set the resolution is unambiguous, and across rotation its failure mode is fail-closed (a mismatched resolution fails verification, never accepts a forgery kid-resolution would refuse).

#### Scenario: Algorithm confusion refused
- **WHEN** a presented token carries an algorithm other than the pinned one — `alg: none` included
- **THEN** verification refuses it; the algorithm is never taken from the token

#### Scenario: Embedded key refused
- **WHEN** a token's header carries its own key material — an embedded `jwk` or `x5c`
- **THEN** verification ignores it, checks the signature against the pinned key only, and refuses the token

#### Scenario: `kid` outside the provider's key set refused
- **WHEN** an identity token's `kid` names a key absent from the issuing provider's own published key set
- **THEN** the lookup fails and the token is refused as not issued by that provider

## MODIFIED Requirements

### Requirement: The toolset mapping is safe to configure

The mapping MUST list OAuth toolsets only: a non-OAuth toolset MUST be refused at startup, because an OAuth challenge in front of a non-OAuth credential is an unsatisfiable 401 loop the static router cannot exempt an entry from. Toolset names MUST be refused at startup when the router's authorization-surface location would capture their MCP path first — the reserved names `authorize`, `token`, `register`, `revoke`, `callback`, `jwks.json` — because their MCP traffic could then never reach Core. A mapped toolset name MUST match the routed-path charset — lower-case letters, digits, and hyphen (`[a-z0-9-]`) — and a name outside it MUST be refused at startup with an operator-facing error naming the charset, because the router's static locations are written against exactly that shape and a name outside it has no location that matches it at all.

#### Scenario: Non-OAuth mapping refused
- **WHEN** the mapping lists a toolset whose public authentication type is not OAUTH
- **THEN** the gateway refuses to start with an operator-facing error naming the entry

#### Scenario: Reserved name refused
- **WHEN** the mapping lists a toolset named like a reserved front-door path segment
- **THEN** the gateway refuses to start with an operator-facing error naming the reserved names

#### Scenario: Name outside the routed charset refused
- **WHEN** the mapping lists a toolset whose name carries a character outside `[a-z0-9-]` — an upper-case letter, underscore, space, slash, or dot
- **THEN** the gateway refuses to start with an operator-facing error naming the charset, so a name the router's locations could never route fails at configuration time, not in operation
