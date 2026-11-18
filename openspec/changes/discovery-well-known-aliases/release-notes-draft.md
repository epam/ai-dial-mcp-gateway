# Release notes — discovery well-known aliases (draft)

### For users

- **Harnesses that discover OAuth settings through OpenID Connect now find the gateway.**
  The gateway's authorization-server metadata is now also served at
  `/.well-known/openid-configuration`, and at the path-insertion forms
  `/.well-known/oauth-authorization-server/<path>` and
  `/.well-known/openid-configuration/<path>`. Every location returns the same document.
  Its `issuer` is always the gateway's origin. This targets connectors such as
  ChatGPT's that reported "couldn't discover OAuth settings" against an `/apps/<app>/mcp`
  or `/dial/<path>/mcp` resource.
- **Unknown discovery paths return a plain `404`.** Any `/.well-known/` path the gateway
  doesn't serve, including the root `/.well-known/oauth-protected-resource`, now returns
  `404` with a JSON body. Before, it returned DIAL Core's `401` ("At least API-KEY or
  Authorization header must be provided"), which made a discovering client stop. A
  client now moves on to its next discovery step.
- **Nothing changes for clients that already connect.** The `401` challenge, the
  per-resource protected-resource documents, `/.well-known/oauth-authorization-server`,
  and registration work as before. No client configuration changes.
- **The gateway is still not an OpenID Provider.** The document at
  `/.well-known/openid-configuration` describes an OAuth authorization server. It
  doesn't advertise ID tokens or a userinfo endpoint, so an application that wants
  "Sign in with OpenID Connect" can't use the gateway for that.

### For the team

- **The aliases are gateway routes on the existing handler.** The gateway registers its
  metadata handler on the three alias paths, so every alias uses the one
  `authorization_server_metadata()` builder. The router forwards the alias family with
  `~ ^/\.well-known/(oauth-authorization-server|openid-configuration)(/|\z)`. The anchor
  is `\z` because PCRE's `$` also matches before a decoded trailing line break. The issuer
  never echoes the suffix: the gateway has one issuer, the `iss` its tokens and its
  RFC 9207 authorization responses carry. A strict RFC 8414 client discards a
  path-insertion answer (§3.3), and a lenient one gets working endpoints.
- **The router closes `/.well-known/`.** A plain prefix location `location /.well-known/`
  (plus `= /.well-known`) returns `404 {"detail":"Not Found"}` as `application/json`,
  with `X-Content-Type-Options: nosniff` added `always`, for every method. The body is
  the gateway's own unrouted-404 shape; the header is what tells the router's answer from
  the gateway's. It never forwards to Core. Because the location is a plain prefix, nginx
  uses it only when no regex matches, so it can't shadow the protected-resource or alias
  regexes. Never change it to `^~`.
- **The closure also holds on the raw request URI.** nginx picks a location by the
  normalized path but forwards the raw one, and Core matches its templates raw. Two
  `map $request_uri` checks close the gap: the Core location forwards only a raw URI
  that is literally one of Core's templates, and the catch-all `location /` hands any
  raw path spelled in the `/.well-known` namespace (dot segments, merged slashes, or
  percent-encoded characters included) to the closure instead of Core. Both refusals
  are an internal `rewrite … last` to the closure, so its answer is defined once.
- **Core's own discovery surface still reaches Core.** Core serves exactly two
  unauthenticated well-known templates,
  `/.well-known/oauth-protected-resource/v1/{toolset|deployments}/{id}/mcp`. A dedicated
  end-anchored location forwards only those, and only when the raw request spells them. Every other path the closure answers was
  Core's auth-filter `401` before, so no working Core path is lost. A Core release that
  adds a `/.well-known/` route re-opens that location.
- **The SIA rates the change low impact.** It adds no credential surface, trust
  boundary, or grant type. The threat model gains DT-EP1-17 to DT-EP1-19, DT-EP6-7 to
  DT-EP6-10, and M43 to M45, and RES-16's fragile set now includes the well-known
  locations' precedence and the two raw-URI checks. The OpenID Connect location newly
  exposes the gateway to a relying party that misuses an access token as a login. That
  is bounded: the relying party would have to be configured to trust the gateway as an
  OpenID Provider and skip both ID-token and audience validation. The threat model's
  OQ-14 (Core's challenge quoting `$host` without the port) is closed as accepted, with
  no change.
- **The root cause is inferred.** The fall-through is observed. That it's what stopped
  ChatGPT comes from OpenAI's published guide and community reports, because the
  gateway, router, and Core logs can't show which paths ChatGPT probed (see the change's
  finding record). The live ChatGPT reconnect is the confirmation. If it still fails, the
  next step is the open question on the root protected-resource document, which needs
  its own SIA.
- **Noted, not addressed:** the DCR response's `grant_types` is
  `["authorization_code"]`, while the metadata advertises the refresh grant too. That's
  a separate finding. Path-appended discovery forms such as
  `/apps/<app>/mcp/.well-known/openid-configuration` stay out of scope: the data path
  already refuses them with its own `404`, and they never reach Core.
