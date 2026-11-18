# Proposal

## Why

Two defects, one symptom cluster. The live dev environment broke twice this week, and
both breaks trace to the same two design gaps:

**F1 — the gateway borrows the toolset's stored `redirect_uri` instead of knowing its
own.** The flow builds the upstream authorization request from the toolset's public
settings projection, including its `redirect_uri` — which is the FIRST entry of Core's
`allowedRedirectUris`, stored at DCR time, and which DIAL Chat's editor overwrites with
Chat's own callback (`{chat-origin}/auth/toolset-signin`) every time a toolset is saved.
So for any UX-created toolset the gateway sends the user's browser to Chat's callback
page, where no gateway flow record exists — broken by construction. The motivating
symptom: when the stored field was replaced with the gateway's callback, sign-in from
Chat broke instead (the upstream had no Chat callback registered). One stored field,
three owners (gateway, Chat, Admin panel), no design that says whose it is. The fix is
structural: the gateway's upstream callback is **derived, not read** —
`{GATEWAY_PUBLIC_ORIGIN}/dial/callback/upstream` — exactly the way its two sibling
callbacks already are, and the toolset's stored field stops being an input to any leg.

**F2 — the front door can only address a fraction of the resources Core can serve.**
The router maps single-segment `[a-z0-9-]+` names, and the gateway's name guard refuses
everything else. But Core serves toolsets and apps at full resource URLs —
`toolsets/public/{name}`, `toolsets/platform/{name}`, `toolsets/{base58-user-bucket}/{name}`,
`applications/public/{name}`, with folders mechanically supported on every resolution
route — and its name rules are wider than `[a-z0-9-]` (toolset keys `^[A-Za-z0-9-_]+$`,
application names `^[A-Za-z0-9._%:-]+$`). Concretely broken today: a toolset name with
an underscore (Core-servable, front-door-refused), an app named `QuickApp.v2` (dots and
uppercase — servable, refused), and every bucket-scoped stored resource (multi-segment —
unroutable). The owner's mandate: support ALL variations Core can serve; any cell ruled
out must be an explicit, reasoned ruling.

The design answer is **pass-through resource paths**: the front door's name segment
becomes a resource path — one or more percent-encoded segments carried verbatim —
routed by a byte-faithful prefix swap (`/dial/{path}/mcp` → `/v1/toolset/{path}/mcp`,
`/apps/{path}/mcp` → `/v1/deployments/{path}/mcp`), with the gateway's guard moving from
a charset check on one segment to a path grammar on all of them. The path IS Core's
deployment id — the same string Core's own listing route (`GET /openai/toolsets/{id}`),
MCP routes, and credential API all key on (verified live: a stored toolset at
`toolsets/public/probets-v2` answers 200 at
`/openai/toolsets/toolsets/public/probets-v2` and resolves on the MCP route at
`/v1/toolset/toolsets/public/probets-v2/mcp`). User buckets need no mapping at all: the
ciphertext segment is data Core itself hands to the client verbatim, and the harness
presents it back through the front door — per-caller isolation stays Core's per-call
access decision, exactly as it is on Core's own surface.

## What Changes

- **The upstream redirect becomes the gateway's own, derived.** The consent branch's
  authorize URL and the credential call's `redirectUri` both carry
  `{GATEWAY_PUBLIC_ORIGIN}/dial/callback/upstream`, derived from configuration; the
  listing read's `redirect_uri` projection is no longer read. The flow record keeps a
  derived value, not a Core-answer value.
- **An operator prerequisite becomes a stated runbook, not folklore.** Core's
  `aidial.toolsets.security.allowedRedirectUris` must carry all three callbacks — the
  gateway's first while any stored-field reader remains, then Chat's
  (`{chat-origin}/auth/toolset-signin`) and Admin's (`{admin-origin}/toolset-signin`) —
  and each dynamically-registered toolset needs Core's repair API re-run afterwards
  (new client id, stored credentials cleared; a one-time re-consent per toolset).
  Statically-registered upstream clients need the gateway callback registered by hand.
  Chat's editor overwrites of the stored field become harmless: nothing of ours reads
  the field.
- **The front door's addressing vocabulary becomes the resource path.** `/dial/{path}/mcp`
  and `/apps/{path}/mcp` where `{path}` is one or more segments, percent-encoded as
  needed, byte-faithfully forwarded to Core's `/v1/toolset/` and `/v1/deployments/`
  prefixes. The MCP data path stays gateway-free (nginx → Core direct) — the change is
  the capture grammar and the guard, not the architecture.
- **The router mechanism changes from a decoded-regex capture to a raw-URI map.**
  Location matching on nginx's normalized (decoded) URI is proven lossy for encoded
  names — a space is answered 400 by nginx itself, and `%3F`/`%23`/`%25` are decoded
  into the proxied request-target where they corrupt the path (measured; see the
  evidence). The new mechanism keys a `map` on `$request_uri` (the raw, never-decoded
  request URI), validates a per-segment grammar, and builds the Core target from the
  raw bytes — so Core receives exactly what the client sent, exactly as it would
  through Core's own port. The 401 challenge synthesis quotes the client's own spelling
  through the same capture (verified live on the nginx image the router runs).
- **The request-time guard becomes a path guard.** Per decoded segment: non-empty; no
  `{`, `}`, `"`, no characters ≤ U+001F (Core's own forbidden set — and exactly the
  characters that break the challenge header's quoting and the HTML pages); no
  trailing dot (a front-door ruling that mirrors Core's creation-side rule and is
  deliberately stricter than its resolution); no `.`/`..` segments. First segment
  (dial namespace only) not a reserved front-door name. Whole decoded path ≤ 900
  UTF-8 bytes (the value of Core's own path-size bound, adopted deliberately on the
  resource path — Core's bound applies to the storage path, so the adoption is
  deliberately stricter at the edge); segment count capped. One canonical
  percent-encoding is derived — under a pinned decode discipline (strict UTF-8,
  invalid and non-shortest sequences refused, `+` literal in path position) — and is
  the resource's identity (flow record, token audience, refresh match); the discovery
  document echoes the offered spelling, mirroring Core's own echo documents.
- **The flow's Core reads address resources by their path.** The listing read becomes
  `GET /openai/toolsets/{resource-path}` and the app read `GET /openai/applications/{resource-path}`
  (the same id Core's own responses carry); the credential call's `url` carries the
  decoded path. The refusal semantics — 403 denial, 401 trust fault, 404 existence
  refusal, deployment fault — are unchanged.
- **The operator restrictions take path entries**, with the startup refusals re-based on
  the path grammar (a configured entry that could never route refuses the start, naming
  the entry and the rule it broke).
- **The matrix is covered cell by cell, with the ruled-out cells ruled out explicitly**
  (design.md's matrix table): config entities, public/platform/user buckets, folders,
  wide-charset app names, and uppercase/underscore toolset names are all addressed;
  what is refused is refused because Core itself refuses it at resolution (its
  forbidden characters; a decoded `/` inside a segment, reachable only as `%2F`, which
  is forwarded byte-faithfully for Core to answer), or by a stated front-door ruling
  (the trailing dot — mirroring Core's creation-side rule, deliberately stricter than
  its resolution), or because the canonical spelling is required (raw non-ASCII in the
  request-target — the encoded form of the same name is served).

**Not in scope (the recorded boundary):** any change to Chat's or Admin's own sign-in
contracts (their callbacks are their own; this change must not regress them — the
runbook's ordering exists for that); Core-side changes (the repair API, the allowlist
semantics, the listing route's grammar are Core's, used as verified, not modified);
path-grammar unification of the `/dial/` vs `/apps/` prefixes (the standing deferred
item); any move of the MCP data path onto the gateway (deliberately not done — the
gateway-free data path is preserved); the `__version`-style client-side conventions
(irrelevant: every resource has one literal URL, no version logic exists Core-side).

## Capabilities

### New Capabilities

(none — the change extends the existing sign-in capability)

### Modified Capabilities

- `mcp-signin`:
  - ADDED — resource paths are the front door's addressing vocabulary (the path
    grammar, the canonical encoding, the pass-through routing and its byte-faithfulness
    property, the matrix coverage and its explicit rulings, the user-bucket mechanism);
  - ADDED — resource paths are guarded at request time (the path guard replacing the
    name guard; REMOVED twin: toolset names are guarded at request time — the
    requirement is renamed because its subject changes from names to paths, and the
    rename is declared rather than silent);
  - MODIFIED — the upstream authorization request arrives complete (the `redirect_uri`
    parameter is the gateway's derived upstream callback, never the toolset's stored
    registration value);
  - MODIFIED — the federation flow (the listing read's id spelling — a declared
    amendment; the derived upstream callback on the consent branch and the credential
    call; the operator's allowlist prerequisite named with its owner);
  - MODIFIED — toolset MCP path answers with the gateway's own challenge (the routed
    path shape is a resource path; the challenge quotes the caller's own spelling);
  - MODIFIED — discovery documents (the resource URI derivation from the path; the
    document's echo rule; the guard references);
  - MODIFIED — authorization requests require a valid resource (the resource URI's
    path shape and the two path guards);
  - MODIFIED — the toolset mapping and the apps restriction (path entries, the
    re-based startup refusals);
  - MODIFIED — app MCP resources are served through the apps front-door path (the path
    shape and the app path guard);
  - MODIFIED — app resources complete the sign-in flow credential-free (the app read's
    id spelling — a declared amendment);
  - MODIFIED — public endpoints are bounded against abuse (the path byte and segment
    caps join the stated bounds);
  - MODIFIED — refusals before flow allocation are audited (the path-guard refusal
    reasons and the offered path as a truncated non-credential fact);
  - MODIFIED — the consent/attribution checkpoint gates every mint on first
    attribution (the decision page's resource naming re-pinned from name to path — a
    declared wording re-pin, no behavior change);
  - MODIFIED — HTML responses carry the web-hardening header family (the
    decision-page scenario's interpolated-value enumeration re-pinned from resource
    name to resource path — declared, no behavior change).

## Impact

- **Code**: `gateway/settings.py` (the path grammar, the canonical encoder, the path
  guard and its refusal reasons, the path-based resource-URI derivations and inverses,
  the restriction validators), `gateway/discovery.py` and `gateway/routes.py` (path
  resolution on the discovery routes), `gateway/authorize.py` and `gateway/token.py`
  (resource resolution over paths), `gateway/flow.py` (the derived upstream callback;
  the listing read's path spelling; the credential call's decoded path), `gateway/core.py`
  (the listing and app read URLs over paths), `gateway/audit.py` (the path-guard reason
  tokens; the path fact's truncation), `router/nginx.conf` (the raw-URI maps, the
  segment grammar, the prefix data-path locations, the re-pointed challenge maps),
  `scripts/probe_routing.py` and a new `scripts/probe_front_door_paths.py` (the
  failing-first instrument), `.env.example` (one new stated setting — the
  segment-count cap, default 32, joining the abuse-bounds family; the callback
  derivation adds none), `docs/gateway-configuration.md`, `docs/routing.md`,
  `docs/local-environment.md` (the three-callback runbook and the repair procedure),
  `docs/pod-contract.md` (the Core-side deployment onboarding: the identity-provider
  entry, the authorization-server advertisement, and the three-callback allowlist,
  in the deployment's placeholder form), `docs/threat-model.md` (the SIA's delta),
  and the test files covering them.
- **Operational**: the front door starts serving multi-segment and encoded resource
  paths; every previously refused-but-servable name (underscores, dots, uppercase,
  bucket-scoped paths) becomes routable, and previously unroutable stored resources
  become sign-in-able. One migration act is required and is the runbook's first step:
  the Core allowlist moves to all three callbacks (gateway first) and each
  dynamically-registered toolset is repaired — until the allowlist carries the
  gateway's callback, the gateway's presented `redirect_uri` fails Core's
  exchange-time validation and every consent fails closed. The router and the gateway
  must deploy together (the grammar and the guard land as one unit; the lockstep
  probes fail a half-deployed pair).
- **Security**: the security impact analysis runs in full (impact level **medium** —
  the change touches the authorization flow's redirect handling and the routing trust
  boundary, adds no new trust boundary, credential, or grant type). It prices the
  redirect-ownership fix (a Core-answer-steered browser destination leaves the flow's
  inputs), the path-guard widening (encoding aliasing, restriction evasion via
  non-canonical spellings, header/page injection via encoded forbidden characters,
  URL injection into the flow's Core reads), the router's new mechanism (grammar drift
  between the map and the guard, ReDoS on the map regex, the `if`-usage class), and
  the mis-use shapes (another user's bucket path presented through the front door;
  an operator configuring the allowlist without the gateway's callback). The
  threat-model updates are part of this change's tasks, not a follow-up.
