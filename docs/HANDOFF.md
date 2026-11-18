# Handoff — read this first

You are picking up a **field-proven capability** entering production preparation. The
PoC that built and proved it is archived; this file is the brief, and
[`docs/production-roadmap.md`](production-roadmap.md) is the iteration's scope.

## What this repository is

A **MCP sign-in gateway** for DIAL, plus the proof that it works.

DIAL's MCP toolsets are credential-holding proxies: the *upstream* token (say, Notion's)
is stored inside DIAL Core, scoped per user, and never delivered to a client. A harness
(Claude Code, Codex, Copilot, a custom agent) holds only a DIAL token.

That model is correct — the MCP authorization specification requires it (a server must
accept only audience-bound tokens and must not transit others) — but it leaves a gap:
**the only designed way to establish that upstream credential was DIAL Chat**, and in a
deployment where Core is used as an LLM proxy, Chat may not be installed at all. Users of
harnesses were stuck.

This repository implements the fix: a small **authorization server** that a harness
authenticates against, which performs the upstream sign-in on the user's behalf and then
mints the token the harness uses. It is **not on the MCP data path** — MCP traffic reaches
Core directly, and Core resolves the user's upstream credential itself from the identity
in the token.

## The gateway's role

**Current (shipped):** the toolset sign-in orchestrator — the MCP-compliant OAuth2 AS
for harnesses (discovery, CIMD and gated-DCR registration, strict `resource` binding,
PKCE), the federation orchestrator (Keycloak leg → the attribution interstitial → the
upstream consent → Core's credential API), and the minting authority for the harness's
token (a gateway-signed JWT carrying the user's real identity; Core trusts it as an
extra identity provider).

**The wider role (the DIAL team's use case — now delivered through C2):** the gateway
is **DIAL's MCP-compliance shield**. Many IdPs Core supports are not MCP-compliant —
no CIMD/DCR, quirky scopes and claims; the gateway consumes those incompliances in one
place and represents a perfectly MCP-compliant AS for any harness. C2 delivered the
generalized OIDC federation (lived on Entra B2C), C1.5 added **apps with MCP
endpoints** as sign-in-able resources (credential-free; the flow short-circuits the
upstream stage by kind), and C2.5 hardened the authorization-server surface per RFC
9700. The production deployment shape landed in C3; the remaining production-readiness
item is [`production-roadmap.md`](production-roadmap.md)'s D3.

## Status: the production iteration is through C3; the next stage is D3

The PoC and the production iteration's stages through C3 are archived. Read
[`production-roadmap.md`](production-roadmap.md) §"The iteration, packaged and ordered"
for the authoritative order and each stage's landing note; the short form:

1. **`build-mcp-sign-in-gateway-poc`** — the whole build, gated on five acceptance
   criteria that all closed on real harnesses (first use end to end via CIMD, silent
   repeat use and refresh with rotation adoption, mid-session upstream-credential
   removal taking the sign-in-again branch, query-string survival, and direct-to-Core
   coexistence).
2. **`fix-dcr-response-conformance`** — the RFC 7591 response conformance that Cursor
   (a strict DCR-only harness) exposed, verified live by the same client.
3. **D0a** — the GitLab remote + the public-repo discipline (the leak check in the
   static gate tier). **D1** — the standing threat-modeling/SIA instructions. **D2** —
   the threat-model baseline (`docs/threat-model.md`).
4. **C1** (dynamic toolsets + fresh claims at refresh), **C1.5** (apps with MCP
   endpoints as credential-free sign-in-able resources), **C2** (generalized IdP
   federation, lived on Entra B2C), **C2.5** (AS security hardening: the
   consent/attribution checkpoint with its per-user approved-client registry, the
   redirect-URI admission rule, revoke-on-double-redemption, and the RFC 9700
   conformance ledger — `docs/threat-model.md` §15, 98 recommendations walked and
   dispositioned), **C3** (the production deployment shape: the one nginx-plus-gateway
   pod — `docs/pod-contract.md`, the deployment unit's versioned document — both keysets
   for signing and custody with active+retained entries and the per-entry env/file key
   sources, a KMS sign-interface reserved and refused at startup until it lands, the IdP
   client secret gaining a file-source spelling beside its env spelling, the DCR
   registration store's durable mount as a named requirement, and the key-rotation drill
   run live on both keysets).

**Next: D3** — the closing re-judge of every disclosed residual in the production shape
(K8s ingress TLS, the KMS key, no HA, real users), with the verdicts written into
[`docs/threat-model.md`](threat-model.md); anything it reveals as blocking joins the
iteration's list. **Publication is underway** — the pre-publication cleanup precedes the
move to the `epam` GitHub organization.

The capability spec is [`openspec/specs/mcp-signin/spec.md`](../openspec/specs/mcp-signin/spec.md)
— normative, and the thing a behavior change goes through its own OpenSpec change for.
The design background: [`background/design.md`](background/design.md) and its adversarial
review [`background/design-review.md`](background/design-review.md).

## The design in five lines

1. A harness hits Core's toolset MCP endpoint with no token → Core answers with its own
   protected-resource metadata, advertising **this gateway** as the authorization server.
2. The harness registers (CIMD-first: it presents a URL-shaped client id; Dynamic Client
   Registration is deprecated and only a config-gated fallback).
3. `/authorize` federates: authenticate the user against the deployment's identity
   provider (silent when an SSO session exists) → check DIAL authorization → run the
   **upstream** consent → hand the upstream authorization code to Core's existing
   credential API, which alone can exchange it.
4. The gateway mints its **own** JWT carrying the user's real identity, and the harness
   uses it against Core directly.
5. Core resolves that user's upstream credential and injects the upstream token on every
   call. The upstream token never reaches the harness.

`resource` (RFC 8707) is the **primary and required** toolset disambiguator — it was
measured being sent by Claude Code on both `/authorize` and `/token`, with the per-toolset
value Core publishes.

## Environment

The PoC runs against a local DIAL development instance (see
[`docs/local-environment.md`](local-environment.md) for endpoints, configuration and how
to bring the pieces up). The production deployment target is a **Kubernetes cluster**;
the gateway is not exposed directly — TLS terminates at the cluster's ingress.
Nothing about the instance is committed to this repository except
placeholders in `.env.example`.

## Rules

Read [`CLAUDE.md`](../CLAUDE.md) and [`PROCESS.md`](../PROCESS.md) before writing anything.
In brief: **spec-first** (an OpenSpec change before code, with an independent review and
then an owner review pause before implementation), **probe-fail-first** (a negative
control before any verdict), **one pass, one fresh subagent**, and the gate ladder before
anything is called done.

The never-cut list in [`ROADMAP.md`](../ROADMAP.md) is not negotiable: the upstream token
never leaves Core; the upstream PKCE verifier never leaves Core; per-user credential
isolation; DIAL authorization on every call; no credential in logs, argv or errors.

## Where to start

1. Read this file, then [`production-roadmap.md`](production-roadmap.md) — the
   authoritative plan is its "The iteration, packaged and ordered" section (the order,
   each stage's landing note, and the deferred table); the next stage is **D3**.
2. For the design background: [`background/design.md`](background/design.md) §1–§2, and
   the archived changes' `evidence/` for every finding and its resolution.
3. To run the stack locally: [`local-environment.md`](local-environment.md) walks the
   deployment: the instance, its Core configuration edits, the gateway's provisioning,
   this repository's stack, and the probe battery, in that order.
4. To change anything: [`CLAUDE.md`](../CLAUDE.md) is spec-first — the normative specs
   live under `openspec/specs/`, and a change goes through its own OpenSpec change
   rather than by drift.
