# Release notes — front-door addressing and redirect (draft)

### For users

- **Sign-in now works for every toolset and app DIAL Core can serve, not just the
  simply-named ones.** The front door addresses resources by their full path:
  a stored toolset in a public, platform, or personal bucket
  (`/dial/toolsets/public/<name>/mcp` and the like), a bucket-scoped app
  (`/apps/applications/public/<name>/mcp`), folder-nested paths, and names with
  underscores, dots, colons, or uppercase letters — all servable by Core, all now
  servable through the gateway. Point your harness at the resource's path exactly as
  DIAL reports it; no configuration is needed on the gateway side.
- **Personal-bucket resources work like any other.** The path DIAL hands your client
  (its per-user bucket segment included) is the path you present through the front
  door; access is still decided per call by DIAL Core, exactly as on Core's own
  endpoint — another user's bucket path is refused for you, your own passes.
- **The upstream consent now reliably returns to the gateway.** The gateway sends its
  own callback (`{gateway-origin}/dial/callback/upstream`) on every upstream
  authorization request, instead of a value stored on the toolset that other editors
  (the Chat toolset editor among them) overwrite with their own callbacks. The
  intermittent shape — the browser landing on a Chat page after an upstream approval,
  or Chat sign-ins breaking after a field fix — is gone by construction.
- **One operator migration is required with this release** (see the team section):
  the Core `allowedRedirectUris` list must carry all three callbacks — the gateway's,
  DIAL Chat's, and the Admin panel's — and each dynamically-registered toolset must
  be repaired afterwards. Until the gateway's callback is in the list, every upstream
  consent fails closed at Core's exchange; after the migration, sign-in from all
  three surfaces coexists.
- **The refusal rules are unchanged in kind** — segments with `{`, `}`, `"`, or
  control characters are refused exactly as Core refuses them; trailing dots are
  refused by the gateway's own (deliberately stricter) ruling; and paths must arrive
  percent-encoded (the standard form every client builder produces); a raw unencoded
  space or non-ASCII byte in the URL is refused rather than guessed at.
- **A refresh token minted before this deploy needs one re-sign-in within the 8-hour
  window.** The resource identity is now canonical (unreserved characters raw, every
  other character `%XX` uppercase hex), and the refresh grant matches the offered
  resource against the token's own on that canonical form. A refresh token issued
  before the deploy carries the older, non-canonical resource spelling, so it fails the
  now-canonical match with `invalid_target` — the client signs in once more, and every
  token minted after the deploy refreshes normally. Only spellings that differ under
  canonicalization are affected; a resource already spelled canonically is untouched.

### For the team

- **The front door's addressing vocabulary is now the Core resource path, carried
  byte-faithfully.** The router's data-path locations moved from decoded single-segment
  regex captures to `map $request_uri` grammars: nginx matches locations against its
  decoded, normalized URI and does not re-escape variable `proxy_pass` values — a
  decoded capture 400s spaces and corrupts `%3F`/`%23`/`%25` into the proxied target
  (measured on the router's image; the evidence is in the change folder). The new
  mechanism forwards the raw bytes, so what Core receives through the front door is
  byte-identical to what the client would have sent to Core's own port.
- **The gateway's name guard became a path guard.** Decoded per-segment rules
  (Core's own forbidden set, plus a stated front-door trailing-dot ruling that
  mirrors Core's creation-side rule and is deliberately stricter than its
  resolution), the first-segment reserved-name scoping (a stored path's first segment
  is its type segment, so `toolsets/public/token` is legal while `/dial/token/…`
  stays reserved), a 900-byte decoded-path cap (the value of Core's own path-size
  bound, adopted deliberately on the resource path), and a stated segment-count cap.
  One canonical percent-encoding is the resource's identity — the flow record, token
  audience, refresh match, and restriction membership all use it, so no spelling game
  can make one resource into two, and invalid UTF-8 escapes are refused outright
  rather than lossily decoded onto one identity. The nginx grammar and the guard are
  a stated division of labor — the map is a routability filter over the wire form,
  the guard is the authority over the decoded form — and the routing probe battery
  asserts both sides, the documented asymmetry class (wire-conforming, guard-refused
  spellings forwarded on the data path and refused at discovery) included, negative
  controls first.
- **F1's fix: the upstream `redirect_uri` is derived, never read.** The consent branch
  and the credential call carry `{GATEWAY_PUBLIC_ORIGIN}/dial/callback/upstream`; the
  listing projection's `redirect_uri` member is no longer an input to any leg. The
  operator runbook (the configuration reference and the local-environment doc) carries
  the three-callback allowlist procedure, the repair-API step, and the ordering — the
  gateway's callback first while any stored-field reader remains. Chat's editor
  overwrites of the stored field become harmless to every party.
- **The MCP data path stays gateway-free.** nginx → Core direct, unchanged; the change
  is the capture grammar and the guard, not the architecture. The SIA (impact level
  medium, full exercise per the standing method) prices the redirect-ownership fix,
  the path-guard widening (encoding aliasing, restriction evasion, header/page
  injection, URL injection into the flow's Core reads), the router mechanism (grammar
  drift, backtracking, prefix leakage), and the mis-use shapes (foreign-bucket paths,
  a partially applied migration). The threat model's updates landed with the change:
  T5-3 narrows (the stored field leaves the flow's inputs), T6-2 is re-priced against
  the map, RES-16 widens honestly (the grammar joins the fragile set; the lockstep
  probes are the compensating control).
- **What was verified before this design was written** (all in the change folder's
  evidence): the Core matrix cell by cell — source at HEAD 894328d6 plus live probes
  against the dev instance (a stored toolset created, read through the listing route
  by its full resource path, resolved on the MCP route, then deleted) — and the nginx
  mechanism's byte-fidelity, refusal, and challenge-synthesis behavior, measured on
  the router's image. Two framings from the finding brief were corrected with
  evidence and recorded as pushback in the design: Core's creation-time name rules are
  positive classes (and stricter than the brief's forbidden-set framing — the CRUD API
  refuses folder paths at creation), and the design targets the resolution-time rules
  the front door actually participates in.
