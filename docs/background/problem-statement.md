# Harness integration with DIAL MCP Toolsets — problem statement and requirements

Status: **draft for review**. This document states the problem and the requirements
identified so far. It deliberately does **not** pick a design; see §6 for the design
question and the options that need deciding.

Companion documents:

- <!-- The May 2026 toolset authentication design is not copied here: it is
     stale and private. Anything it described that still matters is either
     implemented in DIAL Core (cite the source) or stated in this repo. -->
  authentication design (May 2026). Referred to below as **the DIAL Core implementation**.
- [`poc-dial-mcp-signin.md`](poc-dial-mcp-signin.md) — PoC A, the empirical work.
- [`poc-litellm-comparison.md`](poc-litellm-comparison.md) — PoC B, the LiteLLM comparison.

---

## 1. Problem statement

### 1.1 The deployment shape

DIAL Core is used as an LLM proxy and MCP gateway. In this shape **DIAL Chat may not be
installed at all** — it is an optional component, and the DIAL Core implementation already recognises
this (its *"Can Credentials Manager live without UX / Frontend"* section notes that "Chat
is optional for minimal DIAL installation").

What the users actually run is a **harness**: Claude Code, Codex, Claude Desktop,
M365 Copilot, or a custom agent loop. These talk to DIAL Core directly and have no DIAL
front-end in the picture.

### 1.2 Where users get stuck

A user points their harness at a DIAL MCP toolset:

```
claude mcp add --transport http notion http://<dial>/v1/toolset/<id>/mcp
```

and then cannot use it. The toolset requires an **upstream** credential — a token for the
third-party MCP server behind it — and the only designed way to establish that credential
is the DIAL Chat sign-in flow. With no Chat installed, there is no way to do it, and the
harness reports a connection/authentication failure with nothing actionable.

This is the reported complaint: *users must go to Chat to authenticate into the upstream
MCP first.* In a Chat-less deployment, that is not an inconvenience — it is a blocker.

### 1.3 Why it happens (root cause)

Two facts, both verified in PoC A:

1. **Core is a credential-holding proxy.** It stores the upstream token per user and
   injects it at call time. The client holds only a DIAL token. This is deliberate — see
   §2.3 — and the MCP authorisation spec requires it ("MCP servers MUST NOT accept or
   transit any other tokens").
2. **Only Core can complete the upstream sign-in.** The PKCE `code_verifier` for the
   upstream authorisation is generated inside Core and never exposed
   (`ResourceAuthSettingsData` omits it), so no external client can exchange the upstream
   authorisation code. The only designed entry point is
   `POST /v1/ops/toolset/signin`, a DIAL-private operation, and until now the only
   *caller* of it was DIAL Chat.

So the blocker is not that authentication is missing — it is that the **client-facing
surface for establishing the upstream credential is private and undiscoverable**, and its
only driver was a component that may not be installed.

### 1.4 Who is affected

| Actor | Effect |
|---|---|
| End user of a harness | Cannot use an OAuth-protected toolset at all without a Chat detour |
| Deployment owner | Cannot offer toolsets in a Chat-less / LLM-proxy-only deployment |
| Harness vendor | Sees an unactionable 401 from the toolset endpoint |

### 1.5 The authN design already anticipated part of this

The authN design lists it as use case **UC-2** ("External DIAL user wants to invoke DIAL
MCP Toolset directly … non-DIAL App calling DIAL MCP Toolset") and **UC-12** ("API Key
owner wants to create MCP Toolset credentials … and allow 'headless' scenario"), and its
acceptance criteria include *"configure external MCP client (like VSCode Co-pilot or
Cursor) to use DIAL MCP Toolset with authentication"*.

So this is not a new requirement — it is an **unimplemented one**. The PoC set out to
establish whether it can be met without changing the design.

---

## 2. Scope and assumptions

### 2.1 In scope

- Establishing an upstream credential for a DIAL MCP toolset **from a harness, without
  DIAL Chat**.
- The harness→DIAL authentication leg, insofar as it interacts with the above.
- Multiple harnesses, under the assumptions in §2.2.

### 2.2 Out of scope

- Non-MCP toolsets (REST toolsets, OpenAI-function toolsets) — covered by the authN
  design's toolset types.
- Making the *upstream* authorisation non-interactive. Consent is interactive by
  definition; no design removes the user's approval of their own workspace.
- DIAL Chat's own UX.

### 2.3 Assumptions about harnesses

Stated explicitly because they bound the solution:

| # | Assumption | Basis |
|---|---|---|
| A1 | Mature harnesses support MCP, over HTTP/SSE | Table stakes for the protocol |
| A2 | Mature harnesses support the **OAuth2 authorisation-code flow with PKCE** for MCP | The MCP authorisation spec's own model; the most usable way to authenticate |
| A3 | **How a harness stores credentials is harness-specific** | Deliberately not assumed — this is the boundary |

A3 is the load-bearing one. It means a solution must not depend on reading a harness's
credential store, nor on a specific harness's login command, nor on its reconnect
behaviour. Anything harness-specific is an *optimisation*, never a dependency.

### 2.4 Invariants that must not change

Any solution must preserve the toolset design's existing properties:

| # | Invariant | Source |
|---|---|---|
| I1 | The upstream token is stored **in Core, per user**, never in the harness | `forwardAuthToken` defaults to `false`; Core strips the caller's `Authorization` upstream |
| I2 | The upstream PKCE verifier never leaves Core | `ResourceAuthSettingsData` omits it |
| I3 | Credential levels (toolset-global / app / user) and their resolution order | authN design §requirements 5 |
| I4 | DIAL's own authorisation still applies to every toolset call | UC-8 |
| I5 | The upstream credential is established per `authentication_type` (OAUTH, API_KEY, NONE, DIAL_NATIVE) through **one** unified credential API | authN design; `POST /v1/ops/toolset/signin` |

---

## 3. Requirements

Numbered for reference. `MUST`/`SHOULD` per RFC 2119. Items marked *(new)* go beyond the
authN design's existing requirement list; the rest restate or refine it.

### 3.1 Functional

- **FR-1** A user MUST be able to establish an upstream credential for a toolset from a
  harness, with DIAL Chat absent. *(implements UC-2, UC-12)*
- **FR-2** The flow MUST work without the user leaving the harness — i.e. driven by
  running a command / invoking a skill, plus browser interactions for consent.
- **FR-3** A user MUST be able to discover *that* a toolset needs upstream
  authentication, and *which kind* (OAuth2, API key, …), from the toolset's own metadata.
  *(new — see F-2)*
- **FR-4** A user MUST be able to determine whether a toolset is already authenticated,
  and for which level, without making a tool call. *(new; Chat does this today via
  `user_level_auth_status`)*
- **FR-5** Repeat use MUST be silent: no browser interaction when a valid upstream
  credential exists. *(verified achievable — PoC A)*
- **FR-6** The flow SHOULD require no more than **one** interactive consent per leg, and
  SHOULD NOT require re-entering the user's DIAL identity when the harness already holds
  it.
- **FR-7** An expired upstream credential MUST be refreshable without full re-consent.
- **FR-8** When the upstream credential is missing, the harness MUST be told so in a way
  it can act on. *(new — see F-1)*

### 3.2 Security and privacy

- **SR-1** The upstream token MUST NOT be delivered to, or stored by, the harness. *(I1,
  I2; also the MCP spec's token-passthrough prohibition)*
- **SR-2** The upstream credential MUST be bound to the authenticated user's identity,
  and MUST NOT be resolvable by a different user. *(I3; verified in PoC A's isolation
  test)*
- **SR-3** A harness losing or discarding its own DIAL token MUST NOT expose or invalidate
  another user's upstream credential. *(new — see F-3)*
- **SR-4** Consent MUST be attributable to the user who performed it, and auditable.
- **SR-5** The flow MUST NOT require the user to reveal a DIAL API key to the harness in
  place of their identity.
- **SR-6** Client registration against DIAL's identity provider MUST NOT require disabling
  realm security policies. *(new — see F-4)*

### 3.3 Operational

- **OR-1** A deployment that does not run Chat MUST be able to enable the flow by
  configuration only. *(PoC A achieved this for the discovery surface)*
- **OR-2** The solution MUST NOT require an additional always-on component beyond DIAL
  Core and the identity provider. *( constrains the "local shim" option in §6)*
- **OR-3** Failure modes MUST be diagnosable: the caller MUST be able to distinguish
  "not authenticated to DIAL", "authenticated but no upstream credential", and "upstream
  rejected us". *(new — see F-1, F-5)*
- **OR-4** The harness's connection state SHOULD survive a change in upstream credential
  state, so that signing out of a toolset does not force the harness to re-authenticate
  its DIAL session. *(new — see F-3)*

### 3.4 Standards and compatibility

- **CR-1** The toolset endpoint MUST remain a conformant MCP OAuth2 resource server:
  audience-bound tokens (RFC 8707), issuer validation (RFC 9207), and no token
  passthrough.
- **CR-2** Client registration MUST follow the MCP spec's current priority order —
  pre-registered client, then Client ID Metadata Document, then Dynamic Client
  Registration (RFC 7591). *(new — see F-6: the DIAL Core implementation's assumption that DCR is the
  mechanism is now outdated)*
- **CR-3** The solution SHOULD NOT require harness-specific integrations to be developed
  per harness. *(follows A3; a per-harness helper is acceptable only as an interim
  measure)*

---

## 4. Findings from the PoC (evidence)

Each finding is either observed in PoC A/B or verified against Core's source. Full detail
in the companion PoC documents.

### F-1 — Challenge ownership is inverted (defect)

With a valid DIAL token but **no stored upstream credential**, Core injects nothing and
relays the **upstream's** `401` + `WWW-Authenticate` verbatim:

```
no Authorization header    -> 401 + resource_metadata="http://<dial>/…"      (DIAL's)
valid JWT, no stored creds -> 401 + resource_metadata="https://mcp.notion.com/…" (upstream's)
```

The second points the client at an IdP it cannot complete (only Core holds the upstream
verifier). Consequences observed in practice: a harness follows the pointer, fails, and
**discards its own valid DIAL token**, putting the server in a needs-auth state — so a
toolset sign-out also logs the harness out of DIAL. LiteLLM's gateway answers the same
state with *its own* challenge, which is the behaviour FR-8 asks for.

### F-2 — The sign-in requirement is undiscoverable

Core advertises protected-resource metadata and `authorization_servers`, but nothing says
"this toolset needs an upstream sign-in, of this type, starting here". RFC 9728 has no
field for it, and for non-OAuth credential types (`API_KEY`, `DIAL_NATIVE`) there is no
IETF-specified signal at all. A standards-following client therefore has no way to learn
it must run the DIAL-specific step.

### F-3 — Harness state couples to upstream credential state

Because of F-1, the harness's own connection state is entangled with the toolset's
upstream credential state. Signing out of a toolset breaks the harness's *DIAL*
authentication as well (observed). This motivates OR-4.

### F-4 — Client registration is blocked by realm policies, and each fails differently

Keycloak advertises a `registration_endpoint`, but four client-registration policies each
produce a different, misleading error — including *"Offline tokens not allowed for the
user or client"*, which is caused by `fullScopeAllowed=false` and fires even when the
requested scope is unrelated. SR-6 targets this class of problem. Details and the
remediation matrix are in PoC A §4.4.

### F-5 — The private sign-in API is the only Leg-1 entry point

`POST /v1/ops/toolset/signin` is DIAL-private and undiscoverable, and it is the *unified*
credential API across `OAUTH` / `API_KEY` / `NONE` / `DIAL_NATIVE`. A generic OAuth2
client cannot drive it, and a generic MCP client will never find it. This is why PoC A
needed a helper script at all.

### F-6 — The authN design's IdP assumption is now outdated

The authN design concludes: *"we specify KeyCloak as the only 'guaranteed' IdP, supporting
dynamic client registration; if DIAL owner wants DIAL to support standard MCP
authentication, they have to deploy KeyCloak."*

The MCP authorisation spec (rev 2026-07-28) has since **deprecated DCR** in favour of
**Client ID Metadata Documents** (CIMD), and now orders client registration as
pre-registered → CIMD → DCR. So "which IdPs support DCR" is no longer the deciding
question, and Keycloak-specific deployment requirement needs revisiting.

### F-7 — Two consents are irreducible today; one is possible with a Core-side AS

The two legs are separate authorisations against separate IdPs, so two consents. PoC B
showed that LiteLLM collapses them by wrapping delegation in **standard** OAuth endpoints
(`/authorize`, `/token`, `/register` per server) that chain the upstream consent into the
gateway's own authorisation — so a stock client needs no gateway-specific code. DIAL
currently exposes Leg 1 as a private operation instead.

### F-8 — The model is right even though the ergonomics are not

Verified: Core's credential-holding model is what the MCP spec requires (audience binding,
no passthrough), per-user isolation works, and identity is client-independent (tokens from
different Keycloak clients for one user share the same `sub`). The problems are in the
client-facing surface, not the credential model.

---

## 5. Does this call for a change to the toolset design?

**Short answer: no change to the credential model; yes, an addition to its client-facing
surface.** The analysis, split by what the evidence supports:

### 5.1 What must NOT change

- **I1/I2 — Core holds the upstream token.** This is not a preference; the MCP spec
  requires the MCP server to accept only audience-bound tokens and forbids transiting
  others. A "standard MCP client" flow terminates with the client holding the *upstream*
  token, which is exactly what a proxy must avoid. Any solution that hands the harness a
  Notion token is a regression.
- **I5 — the unified credential API.** It serves four credential types, three of which
  have no authorisation-code leg at all. Replacing it with an OAuth-shaped endpoint would
  orphan `API_KEY` and `DIAL_NATIVE`.

### 5.2 What is genuinely missing (the design gap)

Three things, all on the client-facing surface rather than in the credential model:

| Gap | Requirement | Possible remedy |
|---|---|---|
| Core relays the upstream's challenge instead of answering with its own | FR-8, OR-3 | Recognise "no credential stored" and answer with DIAL's own challenge |
| Nothing advertises that an upstream sign-in is needed, or of which type | FR-3, FR-4 | A capability descriptor in the toolset's metadata |
| Leg 1 is a private, undiscoverable operation | FR-1, FR-2, CR-3 | Expose a standards-shaped authorisation surface in front of the same credential store |

### 5.3 The option space (to be decided in the design phase)

| Option | What it is | Effort | Notes |
|---|---|---|---|
| **O-1 — Helper skill** *(current PoC state)* | A harness-side script does the upstream consent and hands Core the code | Low; already works | Solves FR-1/FR-2 for one harness at a time; conflicts with CR-3 as an end state |
| **O-2 — Challenge + capability descriptor** | Fix F-1 and add F-2's metadata; keep Leg 1 as-is | Low–medium | Additive; stops clients walking into the wrong IdP; does not make Leg 1 drivable by a stock client |
| **O-3 — DIAL-hosted authorisation surface** | Core exposes `/authorize` + `/token` per toolset, chaining the upstream consent, in front of the same credential store | High | The LiteLLM shape; makes a *stock* client work with no harness-specific code; collapses two consents into one; leaves the unified credential API intact |

These are not mutually exclusive — O-2 is arguably a prerequisite for O-3, and O-1 is a
stopgap that remains useful while O-3 is built.

### 5.4 Open questions for the design phase

1. **Does O-3 fit DIAL's architecture?** It makes Core an authorisation server for its own
   resources, which is a new role. Does it conflict with the existing identity-provider
   model, or with how `authorization_servers` is currently a trust list?
2. **How should the upstream consent be surfaced in O-3?** Core would need a
   human-facing page (or to delegate to Chat when present), which re-raises the authN
   design's "Credentials Manager without a frontend" question.
3. **What does the capability descriptor look like?** RFC 9728 has no field for it.
   Options: a documented DIAL extension to the metadata; a DIAL-specific media type; or
   driving it from the existing `authentication_type` / `auth_settings` exposure.
4. **How should non-OAuth credential types be signalled?** An API-key toolset needs
   "prompt the human for a key", which no OAuth mechanism expresses.
5. **Does the harness's own token lifecycle interact with O-3?** If Core issues the token
   the harness uses, refresh and revocation become Core's responsibility for that grant.
6. **Is a local shim acceptable?** A harness-neutral alternative to O-3 is a local process
   that holds the DIAL token and exposes an unauthenticated localhost MCP endpoint. It
   avoids all harness-specific integration and the reconnect problem, but adds a resident
   component (OR-2) and a local trust boundary.

---

## 6. References

- MCP authorisation specification, revision 2026-07-28 — client registration priority
  (pre-registration → CIMD → DCR), DCR deprecation, token audience binding and the
  token-passthrough prohibition.
- OAuth Client ID Metadata Document, `draft-ietf-oauth-client-id-metadata-document-00`.
- LiteLLM MCP gateway documentation — `auth_type` taxonomy, `oauth_delegate`,
  `dcr_bridge`, per-server `/register` `/authorize` `/token`.
- authN design: use cases UC-1…UC-12, requirements 1–8, scenarios 1–3.
- PoC A / PoC B: measured evidence for F-1…F-8.

---

*Imported into this repository from the DIAL design archive on 2026-10-17. This copy is the **living** version of this document; the archive copy is a frozen historical record and is not updated. References to the May 2026 toolset authentication design have been replaced with references to the DIAL Core source, because that document predates the MCP specification revision that deprecated Dynamic Client Registration.*
