# Design — front-door addressing and redirect

The evidence this design stands on lives in this change's `evidence/` folder:
`finding-f1-redirect-uri.md` (the redirect defect), `finding-f2-front-door-addressing.md`
(the addressing defect), `core-resource-addressing-matrix.md` (the matrix, per cell,
with its source and live probes), and `nginx-mechanism-probe.md` (the router mechanism,
measured on the nginx image the router runs). Nothing below cites chat scrollback.

## The shape of the fix

Two decisions carry the whole change:

1. **The gateway owns its upstream callback by deriving it** (D1) — the same discipline
   its two sibling callbacks already follow. One stored field had three owners; the fix
   removes the gateway from that ownership contest entirely.
2. **The front door addresses resources by their Core resource path, carried
   byte-faithfully** (D2) — the path IS Core's deployment id, so the front door needs
   no mapping, no alias table, and no view of Core's registry; it needs only a routing
   grammar strict enough to be unambiguous and a guard strict enough to protect its own
   surfaces.

Everything else in this document is consequence: the router mechanism that makes
byte-faithfulness true (D3), the path grammar and its canonical encoding (D4), the
reserved-name re-scoping (D5), the flow's read spellings (D6), the operator runbook
(D7), and the security analysis of all of it.

## Decisions of record

### D1 — The upstream redirect_uri is derived, never read

The consent branch's upstream authorize URL and the credential call's `redirectUri`
carry `{GATEWAY_PUBLIC_ORIGIN}{UPSTREAM_CALLBACK_PATH}` —
`{origin}/dial/callback/upstream`, a value the gateway computes from its own
configuration. The listing read's `redirect_uri` member is no longer an input to any
leg. The flow record keeps the derived value for the credential call (it is constant
per deployment; storing it keeps the call-site discipline of reading the record).

**Why this shape.** The three callbacks in a deployment (gateway, Chat, Admin) are
self-composed by their owners; Core's `allowedRedirectUris` is the shared registry, and
the stored `auth_settings.redirect_uri` is an artifact of DCR (the first entry, at
registration time) that Chat's editor overwrites with its own callback on every save.
Any reader of the stored field is depending on a value another component edits at will.
Core's exchange-time validation accepts a presented `redirectUri` that is *in the
allowlist* regardless of the stored field — so a component that derives its own
callback and is present in the allowlist is independent of the stored field's fate.

**Alternatives weighed and rejected.**

- *Keep reading the stored field, and fix the deployment so the stored field is always
  the gateway's* (the current local-instance workaround, elevated to a design). Rejected
  as a design because it makes the gateway's correctness depend on every editor of the
  toolset never saving it — a contract no component owns and Chat violates by design.
  It is also the exact shape that broke the live environment twice.
- *Make the stored field authoritative and have Chat/Admin stop overwriting it.*
  Cross-repo: their callbacks are their own contracts (the owner's mandate 2), and the
  field's overwrite behavior is theirs to decide. Reported, not designed here.
- *Add a gateway configuration setting for the upstream callback.* Rejected: the
  callback path is already a constant the router routes by name; a configurable value
  would let three places that must agree (the router's location, the IdP registration,
  the derivation) drift apart — the same reason the two sibling callbacks are constants
  (`docs/gateway-configuration.md`: "derived, not configured").

**The deployment prerequisite, and whose it is.** The derived callback must be present
in Core's `allowedRedirectUris` — Core checks the presented `redirectUri` against that
list at exchange time. This is a Core-configuration fact with an operator owner; the
spec states it as the named prerequisite (the pattern the provider-refresh-token
prerequisite already uses), and the runbook (D7) is its operational home.

### D2 — Resource paths are the front door's addressing vocabulary

The front door's name segment becomes a **resource path**: one or more path segments,
each percent-encoded as needed, whose decoded form is Core's deployment id — a bare
name for config entities (`notion`), `toolsets/{bucket}/{folders…}/{name}` for stored
toolsets, `applications/{bucket}/{folders…}/{name}` for stored apps. The routed shape
`/dial/{path}/mcp` maps to Core's `/v1/toolset/{path}/mcp`; `/apps/{path}/mcp` maps to
`/v1/deployments/{path}/mcp`.

The load-bearing verified fact (`core-resource-addressing-matrix.md`): the path is the
ONE string every Core surface keys on. The MCP route captures it greedily
(`RouteTemplate.TOOL_SET_MCP_PROXY`, `^/v1/toolset/(?<id>.+?)/mcp$`); the deployment
listing route captures it greedily and resolves it through the same dual lookup
(`GET /openai/toolsets/toolsets/public/probets-v2` → 200, `id` echoed verbatim,
measured); the app read route is the same shape for applications. So the front door's
pass-through is not a mapping — it is the same identifier, forwarded.

**User buckets need no mechanism of our own.** The bucket segment for a user's
resources is a Base58 ciphertext of `Users/{sub}` — alphanumeric, single-segment,
per-caller, and decryptable only with Core's secret. No client computes it; every
client receives it verbatim from Core's own responses (`id`/`name` fields). A harness
that learned a resource from Core therefore holds the exact path, presents it through
the front door, and the front door forwards it. Per-caller isolation is unchanged in
kind: Core decrypts the segment, resolves the bucket, and applies the same
`hasReadAccess` chain it applies on its own surface — the owner's own bucket passes,
another user's bucket is refused (403), whatever the caller's token. The ciphertext was
already client-visible data before this change; the front door adds no disclosure.
The change's instrument exercises this cell live (task 8.1's user-bucket row): a
resource created as a user, addressed through the front door by the verbatim
Core-handed path, with the isolation refusal asserted for a second caller.

**Alternatives weighed and rejected.**

- *Operator alias mapping in the router* (the owner's previously discussed direction,
  evaluated per the mandate). A static map of front-door names to Core-side paths:
  rejected. It cannot address user-bucket resources at all — the ciphertext segment
  differs per caller, so no static entry can name another user's path — which would
  force exactly the half-matrix the mandate forbids, or a per-user dynamic mechanism
  that IS pass-through with extra state. It also adds a second name space that must be
  curated and can drift from Core's registry. Pass-through makes it unnecessary.
- *Widening the literal charset* (`[a-z0-9-]` → a bigger character class, still
  single-segment). Rejected: it fixes the charset cells but not the multi-segment
  cells (buckets, folders), and a raw wide charset in a location regex re-creates the
  decoded-URI problems D3 exists to avoid. The grammar must be per-segment and
  encoding-aware or it is neither safe nor complete.
- *Routing the MCP data path through the gateway* so the gateway could resolve names
  against Core. Rejected: the MCP data path is deliberately gateway-free
  (`docs/routing.md`) — nginx → Core direct, the gateway absent from the hot path. The
  pass-through design preserves that property; only the capture grammar changes.
- *A Core-side consult at discovery* (resolve the path against Core before serving the
  document). Rejected twice over: it breaks the registry-independent mirror property
  the spec makes normative, and it costs a Core call on an unauthenticated surface.

### D3 — The router forwards raw bytes, via a map on `$request_uri`

**The measured failure that decides this.** nginx matches `location` regexes against
its **normalized, decoded** URI, and a variable `proxy_pass` does not re-escape the
captured value (both verified on the router's image; `nginx-mechanism-probe.md`). The
naive widening — capture `[^/]+(?:/[^/]+)*` decoded and forward — corrupts exactly the
names the change exists to serve: a request for `/dial/toolsets/public/a%20b/mcp` is
answered **400 by nginx itself**; `%3F` and `%23` arrive at the upstream as literal `?`
and `#` inside the request-target, where any conforming server re-splits the path; a
name containing `%` arrives as a raw `%` (an invalid escape at Core's door); non-ASCII
arrives as raw bytes. Decoded capture is not an option; it is a defect generator.

**The mechanism.** One `map` keyed on `$request_uri` — the raw, never-decoded request
URI — per data-path kind. The map's pattern is the segment grammar (D4) anchored to the
kind's prefix and `/mcp` suffix, and its **match domain is the whole raw request URI**:
the pattern is anchored at both ends with an optional query tail after `/mcp` —
`^/dial/(GRAMMAR)/mcp(\?.*)?$` — admitting nothing after `/mcp` but the query. Both
naive patterns break a normative property: a pattern anchored `$` straight after
`/mcp` never matches a query-bearing session-resume request (`…/mcp?sessionId=<id>`)
and would 404 every one — contradicting the retained query-string-survives requirement
in both namespaces; an unanchored pattern matches `/dial/{path}/mcp/foo` and forwards
it as a data-path request — path aliasing, which the delta's grammar-not-wildcard
clause exists to forbid. On a match the map yields the Core target
(`/v1/toolset/$tseg/mcp`), built from the **raw** captured bytes; on no match it yields
the empty string, and the location's `if ($target = "") { return 404; }` refuses the
request without forwarding. The data-path locations become prefix locations
(`^/dial/`, `^/apps/`) behind the authorization-surface locations, so ordering still
protects the reserved names. The query string rides `$is_args$args` as today (raw),
and the probe's Part 3 exercised the tail live — a query-bearing request forwarded
with the parameter intact, `%2F` in the value included.
Measured on the image: every encoded shape is forwarded byte-identically (`%20`, `%3F`,
`%23`, `%25`, `%C3%A9`, `%2F`), dot-segments and empty segments are refused by the
grammar, and the 401 challenge synthesis works through the stacked maps — the same
named capture that builds the Core target also feeds the challenge map's template, so
the challenge quotes the client's own spelling, encoded characters included.

**Why this is acceptable nginx.** The map is static configuration containing no
operator-supplied names (the T6-7 class — config injection — does not exist here: no
name ever enters the config). The `if` is the documented-safe `return` form. The
grammar's cost is regex complexity — acknowledged and priced (RES-16 widened, T6-P2,
the lockstep probes), not hidden: the grammar is one of the two places (with the
gateway guard) that the path rules live, and the probe battery asserts both — the
shapes both refuse, and the stated asymmetry class (D4) — negative controls first.

### D4 — The path grammar, and the canonical encoding

Two components decide what a resource path is, and they divide the labor — a division stated precisely because the two do not agree on every input, and a claim that they do would be a drift no instrument could detect: the router's map is a **routability filter over the wire form** (which raw spellings may be forwarded onto Core's data-path prefixes), and the gateway's guard is the **authority over the decoded form** (which resources may be named on the gateway's surfaces). The wire grammar admits every `%XX` escape, so one class is asymmetric by design: a wire-conforming spelling whose decoded content the guard refuses — an encoded forbidden character (`%7B`), an escaped trailing dot (`%2e`), an over-length or over-depth path — is forwarded on the data path and refused at discovery and authorize. The class is documented, not papered over: its router-synthesized 401 challenge names a document the gateway answers 404, a dead end by design, and the outcome is same-answer-as-Core — Core refuses these names at resolution too. The lockstep probes assert the asymmetry itself (rows forwarding the class on the data path while the guard's surfaces refuse it), never an agreement between the grammars that does not exist.

**Decoded, per segment** (the gateway's guard — and Core's own rules, which the grammar mirrors rather than invents):

- non-empty; not `.` and not `..` (nginx collapses dot-segments before matching anyway;
  the guard refuses them so its surfaces and the router cannot disagree);
- no `{`, `}`, `"`, and no character ≤ U+001F — Core's own forbidden set for resource
  names (`core-resource-addressing-matrix.md`), and precisely the characters that
  would break the challenge header's quoting or the HTML pages' escaping. Core's set
  also names `/`; the guard omits it because a decoded `/` inside a segment is
  reachable on the wire only as `%2F`, which rides the byte-faithful forwarding
  ruling below — Core's resolution refuses a decoded `/` inside a filename, so the
  answer is Core's own, same-answer behavior;
- no trailing dot — a front-door ruling: it mirrors Core's creation-side rule (its
  write and upload controllers refuse trailing-dot names; its resolution routes do
  not check it — an existing trailing-dot name resolves on Core's own port), so it is
  deliberately stricter than Core's resolution, and it is offered to the owner pause
  as a ruling, never claimed as parity;
- the whole decoded path ≤ 900 UTF-8 bytes — the value of Core's own path-size bound,
  adopted deliberately: Core's bound applies to the resource's absolute storage path
  (bucket location plus relative path), not the resource URL, so the same number
  capping the decoded resource path — longer by its type segment — is deliberately
  stricter at the 890–900-byte edge, an acknowledged edge cut chosen so the front
  door never advertises a path Core must refuse for length;
- a segment-count cap (the gateway's own anti-DoS bound, stated with its value in the
  delta spec) — no Core depth limit exists, so the front door states one.

**Raw, on the wire** (the router's map — the routability filter): each segment is
`unreserved characters | %XX` — `[A-Za-z0-9._~-]` plus percent-escapes (the unreserved
class excludes `%` by construction, so the `%XX` alternative is unambiguous and no
overlapping alternates exist — the ReDoS discipline), with the whole-segment `.`/`..`
and trailing-dot shapes refused. Every character Core can name
is expressible in this form: unreserved characters travel raw, everything else
(space, `?`, `#`, `%`, non-ASCII, `{`, `}` — were they not refused decoded — ) travels
as `%XX`.

**The canonical encoding and the identity rule.** The gateway derives one canonical
spelling per resource path: unreserved characters raw, every other character `%XX`
with uppercase hex, UTF-8 — and the decode step feeding it is pinned: strict UTF-8
(an invalid, over-long, or CESU-8-style surrogate sequence is refused with the guard's
fixed reason — a lossy replacement decode would merge distinct wire spellings onto one
U+FFFD identity, the aliasing merge direction), `+` a literal in path position (never
`unquote_plus`). The canonical resource URI (`{origin}/dial/{path}/mcp`,
`{origin}/apps/{path}/mcp`) is the resource's **identity** — the flow record, the token
audience, the refresh grant's resource match, and the operator restriction's membership
check all use the canonical form, so two spellings of one resource cannot become two
resources (`%78` and `x` are one toolset, one token, one restriction entry). The
authorization and token endpoints accept any guard-passing spelling and canonicalize;
the discovery document's `resource` member echoes the offered spelling (Core's own
protected-resource route echoes the requested path; the mirror property is the stated
reason), which keeps RFC 9728's per-spelling identity true for every spelling a client
can be challenged with — the challenge, by construction, quotes the client's own.

**Alternatives weighed.** *Refuse non-canonical spellings outright* — simpler, but it
breaks real clients whose encoders emit lowercase hex or over-encode, for zero
security gain: canonicalization already gives one identity. Rejected; noted here
because the reviewer should check the reasoning, not take it on faith.

### D5 — Reserved names are re-scoped to the first segment

The reserved front-door names (`authorize`, `token`, `register`, `revoke`, `callback`,
`consent`, `jwks.json`) exist because the router's authorization-surface location
captures `/dial/{segment}/…` **at the first segment**. A multi-segment resource path
can only collide at its first segment — and a stored resource's first segment is its
type segment (`toolsets`, `applications`), never a reserved name. So: the reserved-name
rule applies to the first segment only, in the `/dial/` namespace only; the apps
namespace keeps no reserved names (unchanged — nothing the gateway owns is served
under `/apps/{segment}/…`). A config toolset named `token` or `jwks.json` is refused
exactly as today; `toolsets/public/token` is a legal, routable path.

### D6 — The flow's Core reads address resources by their path

The listing read becomes `GET /openai/toolsets/{resource-path}` (the canonical
percent-encoded path appended to the fixed route prefix — the path is
guard-validated and canonically re-encoded before the URL is built, never concatenated
raw from a caller value); the app read becomes `GET /openai/applications/{resource-path}`.
The credential call's `url` body member carries the **decoded** path — the form Core's
own `id` fields carry and its credential store keys on. The refusal semantics (403
denial, 401 trust fault, 404 existence refusal, unreachable = deployment fault) are
untouched; only the id's spelling changes, and the spelling is the one Core's own
routes accept (verified live for the listing route and the MCP route).

### D7 — The operator runbook: three callbacks, gateway first, then repair

The migration is one ordered procedure, recorded in `docs/local-environment.md` and
`docs/gateway-configuration.md` (tasks 6) — and the deployment contract
`docs/pod-contract.md` gains the Core-side onboarding configuration the same facts
ride on: the identity-provider entry, the authorization-server advertisement, and
the three-callback allowlist, in the deployment's placeholder form (task 6.4). It
exists to satisfy the owner's mandate 3 without regressing Chat or Admin:

1. **Add the gateway's callback to `aidial.toolsets.security.allowedRedirectUris`,
   first** — first, because Core stores the first entry of the upstream's DCR
   **response** as new registrations' `auth_settings.redirect_uri` (verified in the
   Core source: the registration is built from
   `clientRegistrationResponse.getRedirectUris().getFirst()`), and a conforming DCR
   server echoes the registered list in order — Core sends the allowlist in its
   configured order, so the allowlist's first entry is the response's first entry —
   and while any stored-field reader remains (the gateway, until this change's code
   lands; any other deployment component that still reads it), a registration whose
   stored field is another component's callback breaks that reader.
2. **Add Chat's and Admin's callbacks** (`{chat-origin}/auth/toolset-signin`,
   `{admin-origin}/toolset-signin`) to the same list. From this point the allowlist
   carries all three owners' callbacks and Core's exchange-time validation accepts
   each owner's presented value.
3. **Repair every dynamically-registered toolset**
   (`POST /v1/ops/toolset/{bucket}/{path}/repair`): DCR registration happened once, at
   creation, with the then-current allowlist; repair re-runs it with the current list
   so the upstream registers all three callbacks. Consequence, stated not hidden: a
   new client id, all stored credentials cleared — each toolset's users re-consent
   once. Statically-registered (non-DCR) toolsets need the gateway's callback
   registered at the upstream provider by hand.
4. **Land this change's code.** The gateway stops reading the stored field; from here
   on, Chat's editor saves of the stored field are harmless to every party.

Ordering is load-bearing: step 1 before step 3 (repair re-runs DCR and stores the
response's first entry), step 3
before or with step 4 (the pre-fix gateway still reads the stored field, which repair
just set to the gateway's callback — the one value that serves it).

## The matrix — every cell addressed or ruled out by name

The full table with per-cell evidence is `evidence/core-resource-addressing-matrix.md`.
Summary, with the ruling for each cell:

| Cell | Status | Ruling |
|---|---|---|
| Config-entity toolset, bare name | Served (unchanged) | Single-segment path; today's behavior exactly. |
| Config-entity app, bare name | Served (unchanged) | Same, apps namespace. |
| Stored toolset, `public` bucket | **Now served** | Multi-segment path; verified live end to end (create → listing read 200 → MCP route resolves). |
| Stored toolset, `platform` bucket | **Now served** | Same mechanics; access is Core's per-caller decision (a platform-bucket read can 403 for a non-privileged caller — Core's rule, not ours). |
| Stored toolset, user bucket (ciphertext) | **Now served** | The harness presents the path verbatim from Core's own listing; isolation stays Core's access chain (D2). No static mapping could serve this cell — pass-through is the mechanism. Exercised live by the instrument's user-bucket row (task 8.1). |
| Stored app, public/platform/user buckets | **Now served** | Same, `/apps/{applications/...}/mcp` → `/v1/deployments/applications/.../mcp`. |
| Folders (nested paths) | Served mechanically | Every Core resolution route is greedy multi-segment; the CRUD API today refuses folder paths at creation (whole-path single-segment validation — verified live), so such resources arise only through other creation paths; the front door serves whatever Core resolves — the trailing-dot ruling above is the one declared exception, and it refuses a spelling class, never a matrix cell. No cell is closed by us. |
| Toolset names `^[A-Za-z0-9-_]+$` (uppercase, underscore) | **Now served** | Core HEAD's toolset-key rule; underscore is servable by Core *today* and refused by the current front door — a concrete today-broken cell this change fixes. (The live dev instance runs an older Core whose rule is lowercase-only; noted in the matrix, design targets HEAD.) |
| App names `^[A-Za-z0-9._%:-]+$` (dots, colons, uppercase) | **Now served** | Core's application-name rule; dots and colons route raw or encoded per the canonical form. |
| Segments with `{`, `}`, `"`, or control ≤ U+001F | **Refused — Core's own rule** | Not Core-servable: Core's resource-name forbidden set. The refusal is parity, not a cut. Core's set also names `/` — unreachable decoded inside a segment except as `%2F`, which rides the forwarding row below. |
| Trailing dot in any segment | **Refused — a front-door ruling** | Mirrors Core's creation-side rule (write/upload refuse trailing dots; resolution does not — an existing trailing-dot name resolves on Core's own port). Deliberately stricter than Core's resolution; offered to the owner pause as a ruling, not parity. |
| `%2F` inside a segment (encoded slash) | Forwarded byte-faithfully; Core answers | The only reachable spelling of a decoded `/` within a segment; Core's resolution refuses a decoded `/` inside a filename, so the front door forwards the raw bytes and Core refuses it exactly as it would on its own port — same-answer behavior, not a gateway ruling. |
| Raw (unencoded) non-ASCII or unsafe characters in the request-target | **Refused — canonical spelling required** | Every such name IS servable in its encoded form; the refusal is of a non-canonical wire spelling, never of a resource. Rationale: the raw form defeats the map's grammar and re-creates the decoded-URI corruption class. |

The two cells a reviewer should challenge hardest — user buckets (no static mapping
can address them; pass-through is the found mechanism) and the raw-non-ASCII refusal
(a spelling refused, not a resource) — are exactly where the owner's mandate demanded
explicitness, and both rulings are stated as rulings, not omissions.

## Pushback on the owner's framings (the recorded trail)

The owner's rulings are proposals; two factual framings in the brief deserve pushback
with evidence, recorded here per the standing rule:

1. **"Forbidden chars `/ { } "` + control ≤0x1F per segment" understates Core's
   creation-time rules.** Live probes against the dev instance and Core HEAD source
   show *positive* classes at creation: toolset keys `^[A-Za-z0-9-_]+$`
   (`ConfigPostProcessor.RESOURCE_KEY_PATTERN` — uppercase allowed at HEAD; the live
   instance's older build says `[a-z0-9-_]`), application names `^[A-Za-z0-9._%:-]+$`
   (`ConfigResourceController.ENTITY_NAME_PATTERN`), and the toolset CRUD API refuses
   folder paths at creation entirely. The design follows the resolution-time rules for
   its guard where they are resolution-time (the forbidden set, the path-size bound)
   and states the trailing-dot refusal as a front-door ruling that mirrors the
   creation-side constraint and is deliberately stricter than Core's resolution (D4) —
   resolution is what the
   front door participates in, and the ruling is declared rather than smuggled in as
   parity — and records the creation-time classes as matrix facts,
   because a guard built on the creation classes would refuse resources Core resolves
   (and vice versa). No owner decision is overturned; the matrix is more precise than
   the brief.
2. **"Previously discussed: operator alias mapping / widening the charset" — both are
   rejected, with the user-bucket impossibility as the decisive fact** (D2). This is
   not pushback against a mandate — the mandate explicitly permitted rejection with
   reasoning — but the rejection is recorded as a decision of record so the owner
   review pause can overrule it knowingly.

---

## Security impact analysis

Authored with the `security-analysis` skill against
`docs/security-analysis.md`; the taxonomy and control categories are the vendored
operator's, verbatim in `docs/background/instructions/threat-modeling.md`.

### 1. Change description

Business: the gateway's sign-in works for every toolset and app Core can serve, and
the upstream consent returns to the gateway's own callback reliably, independent of
values other components edit. Implementation shape: the flow derives its upstream
`redirect_uri` (D1) and stops reading the listing projection's stored field; the front
door's name segment generalizes to a percent-encoded resource path routed by a
raw-URI map (D2/D3) under a path grammar with a canonical encoding (D4), a
first-segment reserved-name rule (D5), path-addressed Core reads (D6), and a
three-callback allowlist migration runbook (D7). No new endpoint, grant type, trust
boundary, credential, or secret material; the MCP data path stays gateway-free.

### 2. Surface scope — the shape and the touched entry points

This is a **change on existing surfaces**: every route involved exists today; the
change re-grades the guard, the redirect input, and the router's capture. Delta
threats are enumerated per touched entry point; untouched surfaces are covered by the
invariant table below, not re-enumerated. Touched:

- **EP1** — the public OAuth and discovery endpoints: the name guard becomes the path
  guard on the discovery routes, the authorization endpoint's `resource`, and the
  token/refresh resource match; the discovery document's `resource` member is now
  derived from a caller path.
- **EP3** — the browser callbacks and HTML pages: the upstream redirect's
  `redirect_uri` changes source (derived, not read from Core's answer); the
  interstitial and decision pages interpolate a resource path where they interpolated
  a name.
- **EP5** — the server-to-server calls into Core: the listing read and app read URLs
  are built from caller-derived paths; the credential call's `url` body member carries
  a decoded caller-derived path.
- **EP6** — the front router nginx: the data-path locations, their capture mechanism
  (decoded regex → raw-URI map), the challenge synthesis maps, and the refusal `if`.

### 3. Impact level, with reasons

**Medium.** The sensitive assets involved are the authorization flow's redirect
integrity (F1 — a wrong `redirect_uri` steers the consent's code to a destination the
gateway does not control) and the routing trust boundary (F2 — the guard and the
router capture are what keep a caller-chosen path from steering requests). Both are
exposed through the public front door to unauthenticated callers. No new trust
boundary, credential, or grant type is created, and the change's direction is
narrowing on F1 (a Core-answer-steered input leaves the flow) — but F2 widens what
the guard admits, and the router mechanism is new code in a security-load-bearing
position, so "low" would understate it. The level sets the security review gate's
depth: a full-depth gate against this SIA and the threat model.

### 4. Invariant ruling table — the never-cut list

| # | Invariant | Ruling | Reason |
|---|---|---|---|
| 1 | The upstream credential never leaves Core | Preserved | No leg changes what it carries. The credential call's `redirectUri` member changes value (the derived callback), not the credential's custody; the code still transits once, USER level, through Core's API. |
| 2 | The upstream PKCE verifier never leaves Core | Preserved | The verifier was never gateway-held; the consent branch's parameters change only `redirect_uri`'s source. |
| 3 | Per-user credential isolation | Preserved | The sharpest question this change raises, ruled explicitly: a user-bucket resource path (the Base58 ciphertext of `Users/{sub}`) is now front-door-addressable by anyone who holds the string — but the string was always client-visible data Core itself hands out, and isolation was never the segment's secrecy: it is Core's `hasReadAccess` chain, applied identically on the data path (per call) and the flow's listing read (per flow). Another user's ciphertext decodes to their bucket and is refused 403 for a caller without access; the owner's own bucket passes. The gateway mints nothing the data path would honor beyond what Core's per-call check allows. |
| 4 | DIAL authorization applies to every toolset call | Preserved | The data path is untouched (nginx → Core direct; Core's auth filter and deployment resolution precede everything). The flow's listing read remains the same authorization decision the data path makes, now addressed by the resource path — verified live to resolve through the same dual lookup. |
| 5 | No credential in logs, argv, or error messages | Preserved | The new facts on the trail are resource paths — non-credential, guard-validated, truncated to the configured cap, fixed-vocabulary reasons only. The runbook documents configuration acts, never credential values. |
| 6 | No hardcoded credentials in the repository | Preserved | No new secret material exists: the derived callback is a URL, the runbook names placeholders, `.env.example` gains nothing. |
| 7 | The signing key is IdP-grade secret material | Preserved | Untouched — no key handling changes. |

### 5. Threat tables — per touched entry point, the delta threats

#### EP1 — the public OAuth and discovery endpoints

| Attack surface entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| Discovery routes and `/dial/authorize`'s resource resolution | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Encoding-aliasing restriction evasion | The operator restriction's admission decision; the flow-record's resource identity | Integrity | A caller offers a non-canonical spelling of a restricted path (`%78` for `x`, over-encoded UTF-8) hoping the restriction's membership check sees a different string than the flow later serves, admitting a resource the operator excluded. |
| Discovery routes and `/dial/authorize` | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Resource-identity confusion across spellings | The token audience / refresh resource match (the resource identity) | Integrity | Two spellings of one resource (`a%2Fb` collapsed by normalization, mixed-case hex escapes) resolve to different flow records or different audiences on different surfaces, letting a token minted for one spelling be presented as another resource — an MCP mix-up variant. |
| The discovery routes' document build | Injection | Header and page injection via encoded forbidden characters | The 401 challenge header's value (router-synthesized, quoted); the HTML pages' interpolated content | Integrity | A resource path carrying `%22`/`%7D`/`%01` decodes to `"`, `}`, or a control character — breaking the challenge header's quoting or the pages' structure if the guard checks the encoded form instead of the decoded one. |
| The discovery routes (unauthenticated) | Use Control Misconfiguration → Denial of Service → Resource Consumption | Path-shape flood | The audit trail's volume; the guard's CPU per request | Availability | An unauthenticated caller loops long, deep, guard-failing paths — each writing an audit record and costing guard CPU — at a rate the limiter admits but the per-request cost amplifies. |
| The authorization endpoint's `resource` parameter [mis-use] | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Foreign-bucket path as a resource | The flow's listing read; the mint | Integrity | A signed-in user names another user's bucket path (a ciphertext they obtained legitimately, e.g. from a shared listing) as the `resource`, seeking a token minted over a resource the data path would refuse them — the mis-use shape of never-cut 3. |

#### EP3 — the browser callbacks and the HTML pages

| Attack surface entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| The consent branch's upstream redirect (F1) | Use Control Misconfiguration → Elevation of Privilege → Spoofing of caller's identity | Stored-field redirect steering (removed by this change; the row records what it priced) | The upstream authorization code's destination | Integrity | The pre-fix shape: an editor of the toolset (Chat's save) points the stored `redirect_uri` at a callback the gateway does not own, so the consent's code is delivered where no flow record exists — a failure, or worse, a delivery to a page another party controls. The fix removes the input; the row stays so the gate can verify the removal. |
| The interstitial and decision pages | Injection | Path interpolation into HTML | The pages' markup (client_name, resource name interpolation points) | Integrity | A multi-segment, encoded resource path is new interpolant material; a path crafted to carry markup in decoded form (via `%3C%61%3B…`) must not reach the page unescaped — the escape discipline must be proven for the path shape, not assumed from the name shape. |
| The upstream consent leg [mis-use: operator] | Use Control Misconfiguration → Denial of Service → Resource Consumption | Allowlist migration gap | Every consent flow's completability | Availability | An operator applies the allowlist change or the repair procedure partially (the gateway's callback absent, or DCR toolsets unrepaired), so every upstream consent fails at Core's exchange-time validation — a silent-for-the-operator outage with a confusing far-from-its-cause failure shape. |

#### EP5 — the server-to-server calls into Core

| Attack surface entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| The listing read / app read URL build | Injection | URL structure injection into the Core read | The Core route the flow's authorization decision rides on | Integrity | A caller-derived path concatenated raw into the read URL could steer the request off `/openai/toolsets/…` — into another Core route (path confusion inside Core) via dot-segments, empty segments, or encoded separators. |
| The credential call's body | Injection | JSON structure injection via the `url` member | The credential call's target resource | Integrity | The decoded path is caller-derived and now longer and richer than a name; a malformed decode or an unencoded member could alter the JSON body's structure and name a different toolset than the flow's resource. |

#### EP6 — the front router nginx

| Attack surface entry point | Attack type category (full path) | Attack type name | Target sensitive footprint | Compromised | Attack type description |
|---|---|---|---|---|---|
| The data-path map (the new capture) | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Grammar drift between the map and the guard | The routing decision (what reaches Core's `/v1/toolset/` prefix) | Integrity | The nginx grammar (a routability filter over the wire form) and the gateway guard (the authority over the decoded form) are asymmetric by design on one documented class — wire-conforming spellings whose decoded content the guard refuses are forwarded on the data path and refused at discovery/authorize, their challenges dead-ending at 404 documents. The threat is a divergence *beyond* that stated class: a shape the map routes differently than the guard's surfaces resolve, or a new asymmetry nobody documented, yields a challenge whose metadata document is served for a different identity than the path routes — the strict client's sign-in fails, or worse, the restriction is enforced against a different string than the route. |
| The data-path map regex | Use Control Misconfiguration → Denial of Service → Resource Consumption | Regex backtracking on crafted paths | The router's worker CPU | Availability | The segment grammar nests quantifiers over overlapping alphabets (middle-vs-end character classes); a crafted long non-matching URI could drive catastrophic backtracking, stalling router workers. |
| The refusal `if` and the prefix locations | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Prefix-capture leakage beyond the data path | The boundary between the router's authorization-surface locations and the data path | Integrity | The data-path locations widen from anchored single-segment to prefix matches; a crafted path that the authorization-surface alternation does not catch but the prefix location does (e.g. `/dial/consent/../toolsets/x/mcp` after normalization) could route MCP-shaped traffic to the gateway or authorization-shaped traffic to Core. |
| The raw forwarding itself | Use Control Misconfiguration → Elevation of Privilege → Bypass Authorization | Byte-faithful forwarding of refused shapes (`%2F`) | Core's request-target | Integrity | The front door forwards raw bytes including spellings Core itself refuses (encoded slashes inside a segment); the design intends same-answer-as-Core behavior, but if Core's container decodes `%2F` differently than its own port front line expects, the front door becomes a decoder-bypass oracle against Core. |

### 6. Mitigations, per threat, in the fixed control-category order

**T-EP1-a (encoding-aliasing restriction evasion).**
1. Reduce Attack Surface — the canonical encoding is derived once and is the only
   string the restriction is checked against (delta spec: the path-guard requirement).
   2. Isolation — not applicable: the threat lives inside one component's decision,
   no second compartment to isolate the comparison from. 3. Authentication — not
   applicable: the evasion targets an unauthenticated surface's admission rule, which
   no credential can strengthen. 4. Authorization — restriction membership on the
   canonical path, so every spelling of one resource meets one verdict (delta spec).
   5. Data Protection — not applicable: no secret material is involved in the
   comparison. 6. Anti-Injection — the canonicalizer is the input's only path to the
   comparison; it is a pure decode-validate-reencode with no string interpolation
   (delta spec's grammar). 7. Anti-DoS — not applicable: the evasion costs one request,
   its cost is the guard's, priced in T-EP1-d. 8. Detective — the lockstep probe
   battery carries a row asserting a non-canonical spelling of a restricted path is
   refused (tasks: the probe battery extension).

**T-EP1-b (resource-identity confusion across spellings).**
1. Reduce Attack Surface — one identity per resource: the flow record, token audience,
   and refresh match all carry the canonical URI (delta spec). 2. Isolation — not
   applicable: the confusion is between spellings of one identifier inside one
   component, not between components. 3. Authentication — not applicable: no
   credential is forged; the token is genuinely minted, for the wrong identity.
   4. Authorization — the refresh grant's resource match is canonical-vs-canonical;
   a spelling cannot re-key it (delta spec). 5. Data Protection — not applicable: no
   secret material in play. 6. Anti-Injection — nginx's own normalization
   (dot-segment collapse, slash merge) is refused, not trusted: the guard refuses
   `.`/`..` and empty segments so the router's normalization cannot silently re-key a
   path the gateway validated (delta spec; the nginx probe evidence). 7. Anti-DoS —
   not applicable: identity confusion is not volumetric. 8. Detective — the probe
   battery asserts two spellings of one resource yield one document identity and one
   restriction verdict (tasks).

**T-EP1-c (header/page injection via encoded forbidden characters).**
1. Reduce Attack Surface — the guard refuses the decoded forbidden set (`{`, `}`,
   `"`, ≤ U+001F) outright, so the characters never reach any interpolation point
   (delta spec). 2. Isolation — not applicable: the header and the page are the same
   component's outputs. 3. Authentication — not applicable: the injection targets an
   unauthenticated document, not an authenticated caller. 4. Authorization — not
   applicable: the injected content is markup, not a privilege decision.
   5. Data Protection — not applicable: no secret reaches the outputs.
   6. Anti-Injection — the existing escape discipline on the shared page builder, now
   proven (unit rows) for path-shaped interpolants, and the challenge header's value
   built only from the router's fixed template plus a grammar-conforming capture
   (delta spec + nginx evidence). 7. Anti-DoS — not applicable: not volumetric.
   8. Detective — unit rows asserting `%22`/`%7B`/`%01` in any segment are refused
   with the guard's fixed-vocabulary reason (tasks).

**T-EP1-d (path-shape flood).**
1. Reduce Attack Surface — the byte cap (≤ 900 decoded UTF-8 bytes) and the segment
   cap bound every guard input before work proportional to it (delta spec).
   2. Isolation — not applicable: a flood crosses no boundary an isolation control
   could draw inside the pod. 3. Authentication — not applicable: the surface is
   deliberately unauthenticated (discovery). 4. Authorization — not applicable: no
   privilege is sought. 5. Data Protection — not applicable. 6. Anti-Injection —
   not applicable: the flood's payload is volume, not structure. 7. Anti-DoS — the
   existing per-source and global limiter already covers both discovery routes (main
   spec); the caps make each admitted request's cost constant. 8. Detective — the
   limiter's existing no-record-over-limit rule; the audit trail's volume is bounded
   by the same limit as the request rate (main spec, unchanged).

**T-EP1-e (foreign-bucket path as a resource) [mis-use].**
1. Reduce Attack Surface — not applicable: the path is legitimately addressable; the
   cell cannot be closed without closing user buckets (the mandate forbids).
   2. Isolation — Core's bucket isolation is the standing control: the ciphertext
   decodes to `Users/{sub}` and access is decided per caller (Core configuration —
   Core-owned, named here). 3. Authentication — the identity leg is unchanged and
   mandatory. 4. Authorization — the listing read IS the data path's authorization
   decision (main spec): a 403 refuses the flow before any upstream round-trip, and
   the mint never happens (delta spec unchanged semantics, path-addressed).
   5. Data Protection — not applicable: no credential is at stake pre-mint.
   6. Anti-Injection — the read URL is built from the guard-validated canonical path
   (T-EP5-a's mitigation, shared). 7. Anti-DoS — not applicable: the mis-use costs
   one flow. 8. Detective — the flow's audit trail records the resource (the path)
   and the refusal reason, so an operator can see cross-bucket attempts (main spec's
   lifecycle trail, path fact); the instrument's user-bucket row (task 8.1) asserts
   the isolation refusal live — a second caller's 403 through the front door,
   same-answer-as-Core.

**T-EP3-a (stored-field redirect steering — the removed input).**
1. Reduce Attack Surface — the fix itself: the `redirect_uri` is derived, the stored
   field is no longer read, and no editor of the toolset can steer the consent's
   destination (delta spec: the upstream-authorization-request requirement).
   2. Isolation — not applicable: the steering was a data problem, not a compartment
   problem. 3. Authentication — not applicable: the consent's participants are
   unchanged. 4. Authorization — Core's exchange-time allowlist check is the standing
   backstop: a presented `redirect_uri` outside `allowedRedirectUris` fails the
   exchange (Core configuration — the prerequisite D7 names). 5. Data Protection —
   not applicable. 6. Anti-Injection — not applicable post-fix: no caller- or
   Core-answer value enters the redirect's construction. 7. Anti-DoS — not
   applicable. 8. Detective — the migration runbook's verification step: a live
   consent probe per toolset after repair, so a regression to stored-field reading is
   caught by the instrument (tasks).

**T-EP3-b (path interpolation into HTML).**
1. Reduce Attack Surface — the guard's decoded forbidden set removes the
   markup-breaking characters before interpolation (shared with T-EP1-c).
   2. Isolation — not applicable. 3. Authentication — not applicable.
   4. Authorization — not applicable. 5. Data Protection — not applicable.
   6. Anti-Injection — the shared builder's existing escape discipline, with unit
   rows extended to path-shaped, percent-encoded inputs decoding to markup-shaped
   bytes — the discipline is asserted, not assumed (delta spec: the pages'
   requirement unchanged, the proof widened; the rows' home is task 3.6, which names
   the page sites). 7. Anti-DoS — not applicable. 8. Detective — the unit rows are
   the regression detector (task 3.6).

**T-EP3-c (allowlist migration gap) [mis-use: operator].**
1. Reduce Attack Surface — the failure is fail-closed by Core (an unlisted
   `redirect_uri` fails the exchange; no consent completes), so the gap's worst case
   is unavailability, never a mis-delivery (Core's rule, named). 2. Isolation — not
   applicable. 3. Authentication — not applicable. 4. Authorization — the allowlist
   IS the authorization of redirect destinations (Core configuration, D7).
   5. Data Protection — not applicable. 6. Anti-Injection — not applicable.
   7. Anti-DoS — the outage is all-or-nothing, not volumetric. 8. Detective — the
   runbook's per-toolset consent probe and the credential-call audit trail's
   fixed-vocabulary refusal make the gap visible as a burst of one refusal reason
   (tasks; main spec's trail).

**T-EP5-a (URL structure injection into the Core read).**
1. Reduce Attack Surface — the read URL is built only as
   `fixed-prefix + canonical-encoding`: no raw caller substring is ever concatenated
   (delta spec: the flow requirement's read spelling). 2. Isolation — not
   applicable: the injection target is one outbound call. 3. Authentication — the
   read carries the identity token; unchanged. 4. Authorization — the read IS the
   authorization decision; steering it to another route would bypass that decision,
   which is why the URL build is canonical-only (delta spec). 5. Data Protection —
   not applicable. 6. Anti-Injection — the grammar refuses dot-segments and empty
   segments (the steering shapes), and the canonical re-encoding normalizes every
   escape before the URL is built (delta spec). 7. Anti-DoS — not applicable.
   8. Detective — the failing-first probe asserts a stored-toolset listing read
   resolves and a steering shape is refused (tasks).

**T-EP5-b (JSON structure injection via the `url` member).**
1. Reduce Attack Surface — the body member is the decoded, guard-validated path;
   nothing else caller-derived enters the body. 2. Isolation — not applicable.
   3. Authentication — the call authenticates with the identity token; unchanged.
   4. Authorization — the credential lands at USER level keyed to the caller's `sub`
   (never-cut 1/3 machinery, unchanged). 5. Data Protection — not applicable.
   6. Anti-Injection — the body is JSON-encoded by the existing client (a decoded
   string with quotes or braces cannot break structure — and the guard refuses `{}"`
   anyway); unit rows assert a path with every legal punctuation survives the
   round-trip byte-identical (delta spec + tasks). 7. Anti-DoS — not applicable.
   8. Detective — the credential call's fixed-vocabulary result record (main spec).

**T-EP6-a (grammar drift between the map and the guard).**
1. Reduce Attack Surface — the division of labor is stated once (the delta spec's
    path-guard requirement): the map is a routability filter over the wire form, the
   guard is the authority over the decoded form, and the wire-conforming-but-
   guard-refused class is documented as forwarded-on-the-data-path, refused-at-
   discovery, its challenge dead-ending at a 404 document — same-answer-as-Core in
   outcome.
   2. Isolation — the router and the gateway are separate containers with separate
   concerns (unchanged pod shape). 3. Authentication — not applicable: routing
   precedes authentication on the data path by design. 4. Authorization — not
   applicable at the router; Core's per-call authorization is the control downstream
   (unchanged). 5. Data Protection — not applicable. 6. Anti-Injection — the map's
   grammar admits only segment-conforming raw shapes; everything else is refused
   before forwarding (nginx evidence). 7. Anti-DoS — not applicable. 8. Detective —
   **the lockstep probe battery**: rows asserting the documented behavior on both
   sides of the division — the shapes both admit, the shapes both refuse, and the
   asymmetry class itself (a wire-conforming, guard-refused spelling forwarded by the
   router and refused by the guard's surfaces, its challenge dead-ending at the 404
   document) — negative controls first; the standing instrument, extended (tasks).

**T-EP6-b (regex backtracking on crafted paths).**
1. Reduce Attack Surface — the grammar's alternations are character classes and
   bounded groups, no nested unbounded groups over overlapping alternates; the
   request-line buffer bound (`large_client_header_buffers`, 8 KB default — to be
   stated explicitly in the conf) caps the input length upstream of the regex.
   2. Isolation — not applicable. 3. Authentication — not applicable.
   4. Authorization — not applicable. 5. Data Protection — not applicable.
   6. Anti-Injection — not applicable: the payload is length, not structure.
   7. Anti-DoS — the stated buffer bound; the probe battery carries a
   pathological-URI row asserting a fast refusal (tasks); the segment cap bounds the
   gateway-side grammar. 8. Detective — the pathological-URI probe row.

**T-EP6-c (prefix-capture leakage).**
1. Reduce Attack Surface — the authorization-surface locations remain listed before
   the data-path locations, and the map's grammar requires the `/mcp` suffix with
   nothing after it but the optional query — the match domain is the whole raw
   request URI (the delta spec's addressing requirement) — so a prefix-matched path
   without the suffix, or with a path tail after it, is refused by the `if` (nginx
   evidence: no-`/mcp` shapes answer 404; the post-`/mcp` tail is the instrument's
   match-domain row). 2. Isolation — not applicable. 3. Authentication —
   not applicable at the router. 4. Authorization — the reserved first-segment rule
   (D5) keeps the authorization-surface names unreachable as resource paths (delta
   spec). 5. Data Protection — not applicable. 6. Anti-Injection — nginx's
   normalization (dot-segment collapse) is surfaced, not hidden: the guard refuses
   dot-segments so a collapsed path and its uncollapsed spelling cannot disagree
   (delta spec; probe rows). 7. Anti-DoS — not applicable. 8. Detective — probe rows:
   `/dial/authorize/x/mcp` reaches the gateway not Core; a dot-segment path under
   `/dial/` is refused; reserved first segments are refused at discovery and the
   authorize endpoint; a post-`/mcp` path tail is refused 404 (the match-domain
   rows) (tasks).

**T-EP6-d (byte-faithful forwarding of refused shapes).**
1. Reduce Attack Surface — the forwarded bytes are exactly what the client sent and
   exactly what Core's own port would receive; the front door adds no decode step,
   so it adds no decode discrepancy. 2. Isolation — not applicable. 3. Authentication
   — Core's auth filter applies to the forwarded request as to any (unchanged).
   4. Authorization — Core's per-call authorization is unchanged. 5. Data Protection
   — not applicable. 6. Anti-Injection — the map forwards only
   grammar-conforming bytes; a `%2F` inside a segment is forwarded raw for Core to
   answer — same-answer behavior, asserted by a probe row rather than assumed
   (tasks). 7. Anti-DoS — not applicable. 8. Detective — the probe row.

### 7. The grouped mitigation list (the analysis's result)

1. **The derived upstream callback** (delta spec: the upstream-authorization-request
   requirement; the federation flow's amendment) — addresses T-EP3-a; removes the
   stored-field input from the flow entirely. Gateway-owned.
2. **The canonical-encoding identity rule** (delta spec: the resource-path and
   path-guard requirements) — addresses T-EP1-a, T-EP1-b, T-EP5-a; one identity per
   resource across restriction, audience, refresh, and reads. Gateway-owned.
3. **The decoded forbidden-set refusal** (`{`, `}`, `"`, ≤ U+001F; trailing dot;
   dot/empty segments) (delta spec: the path-guard requirement) — addresses
   T-EP1-c, T-EP3-b, T-EP5-a, T-EP6-c. Gateway-owned; the router's grammar is the
   routability filter over the wire form — the stated division of labor (D4),
   asymmetric by design on the encoded-forbidden class.
4. **The raw-URI map with the segment grammar and the `/mcp`-suffix requirement**
   (`router/nginx.conf`) — addresses T-EP6-a, T-EP6-c, T-EP6-d; byte-faithful
   forwarding with refusal of unroutable shapes. Router-owned, verified by the
   battery.
5. **The byte, segment, and request-line caps** (delta spec: the abuse-bounds
   amendment; the conf's stated `large_client_header_buffers`) — addresses
   T-EP1-d, T-EP6-b. Gateway- and router-owned.
6. **The lockstep probe battery, negative controls first** (`scripts/probe_routing.py`
   extended + `scripts/probe_front_door_paths.py`) — addresses T-EP1-a, T-EP1-b,
   T-EP6-a, T-EP6-b, T-EP6-c, T-EP6-d as the recurring detector — the documented
   map/guard asymmetry asserted as the asymmetry it is (T-EP6-a); the change's
   failing-first instrument. Repo-owned.
7. **The three-callback allowlist runbook with repair** (docs; Core configuration —
   operator-owned) — addresses T-EP3-c; makes the migration's gap states visible and
   recoverable.
8. **Core's standing controls, named with their owner** (exchange-time allowlist
   check; `hasReadAccess` chain; per-call authorization) — bound T-EP1-e, T-EP3-a,
   T-EP6-d; unchanged by this change and load-bearing for it.

No threat is left without a mitigation; none is accepted as a residual beyond the
existing register's entries (below).

### 8. Threat-model delta (the entries `docs/threat-model.md` gains or changes)

- **New rows** (numbered into the model's scheme when the tasks land them):
  EP1: encoding-aliasing restriction evasion, resource-identity confusion across
  spellings, encoded-forbidden-character injection, path-shape flood, foreign-bucket
  resource mis-use. EP3: allowlist-migration-gap operator mis-use (the
  stored-field-steering row is *retired*, not added — see below). EP5: URL structure
  injection into the Core reads; JSON structure injection via the `url` member.
  EP6: grammar drift, regex backtracking, prefix-capture leakage, byte-faithful
  forwarding of refused shapes.
- **Changed dispositions**: T5-3 (settings-field content injection) — the
  `redirect_uri` member leaves the flow's inputs; the threat's row narrows to the
  members still read. T6-2 (path-capture misrouting) — re-priced against the new map
  mechanism (the row's subject changes from the location regex to the map grammar).
  T6-7 — unchanged verdict, restated evidence: the map contains no operator-supplied
  names, so the injection class stays empty.
- **Re-judged residuals**: RES-16 (nginx config fragility) — widened honestly: the
  segment grammar joins the fragile set, and the lockstep probes are named as the
  compensating control; the re-open trigger gains "any change to the path grammar or
  the map". RES-7 (marker-level audience binding) — unchanged verdict; the resource
  URI is longer now, the bound is the same.

### 9. Open questions, and the strict gap list

**Open questions (for the independent review 3b and the owner pause 3c):**

1. **The discovery document's echo rule** (D4): echo-offered vs canonical-only. The
   design echoes the offered spelling (Core's mirror). A reviewer should check the
   RFC 9728 identity argument; the owner may prefer the stricter refuse-non-canonical
   rule (one document, one spelling) at the cost of encoder-strict clients.
2. **The segment-count cap's value** — the design states a cap without blessing a
   number; the implementation picks one (proposed: 32) and the spec carries it. Owner
   sign-off on the number is cheap now and expensive after clients depend on deep
   paths.
3. **The `%2F` same-answer claim** (T-EP6-d) rests on Core's container refusing
   encoded slashes like Core's own front line does; the probe row verifies it live
   once, at implementation. If Core's answer differs through the front door vs its
   own port, the design's byte-faithfulness principle is falsified at that cell and
   the ruling reopens.
4. **Whether Chat/Admin need a matching change** to stop overwriting the stored
   `redirect_uri` (cosmetic once this change lands; a cross-repo report, not ours).

**Strict gap list** (where the skill's input allowlist did not suffice):

- *Minor*: the live-Core matrix probes required the dev instance and its Keycloak —
  runtime facts, not repository documents. The skill's allowlist covers this change
  folder and the repo's docs; the probes' results are recorded in `evidence/` so the
  analysis is re-runnable from the folder. No blocking gap.
- *Minor*: the vendored instructions' "stop and let others evaluate" step maps to the
  loop's review points per `docs/security-analysis.md` §6 — no gap, noted for
  completeness.
- *Minor (residual, from the security review gate)*: the path guard admits escape
  **shapes** the router's map refuses — an invalid escape such as `%zz` passes the
  decoded-rule guard but has no routed location. A third, undocumented micro-class beside
  the guard's refusal reasons. Disposition: fail-closed on every leg — the router never
  routes it, and a path that reaches Core is refused there at resolution. Recorded for
  the owner to promote into the guard's reasons if a fourth class is ever wanted; no code
  change is made here.
- *Minor (residual, from the security review gate)*: `_offered_path`'s raw_path-absent
  fallback double-decodes an offered path. Disposition: unreachable through the
  deployment — the router always supplies `raw_path`, so the fallback branch never runs in
  a routed request. Recorded rather than repaired, because a repair would add a path with
  no test that can reach it; the owner can promote it if the router's contract changes.
- *Minor (residual, from the security review gate)*: raw non-ASCII bytes in the request
  target are refused by the **request-target's** wire grammar (the router — probe row 4
  asserts it live), and the gateway's surfaces accept-and-canonicalize a wire-conforming
  spelling (D4) rather than mirroring that refusal. The one residual shape is
  discovery's `_offered_path` `raw_path` fallback, whose latin-1 decode of a raw non-ASCII
  byte yields a **mojibake (phantom) identity** distinct from the byte's real one. A third
  undocumented micro-class beside the router's refusal and the decoded-rule guard.
  Disposition: harmless — the phantom path is nowhere routed and Core reads it as a
  404 (same-answer-as-Core); recorded for the owner to promote into the guard's reasons if
  a class is ever wanted; no code change is made here.
