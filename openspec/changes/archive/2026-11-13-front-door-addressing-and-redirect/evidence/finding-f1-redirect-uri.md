# Finding F1 — the gateway borrows the toolset's stored redirect_uri instead of knowing its own

## Symptom

Sign-in breaks in both directions, depending on who last saved the toolset. A
UX-created toolset (saved through DIAL Chat's editor) breaks the gateway's flow: the
user's browser is sent to Chat's callback page at the consent's end, where no gateway
flow record exists. Conversely, when the dev environment replaced the stored field
with the gateway's callback (the workaround applied this week), sign-in **from Chat**
broke instead — the upstream provider had no Chat callback registered. One stored
field, three owners, no contract; whichever component last wrote it wins, and the
other two lose.

## Evidence

- `gateway/flow.py` — the flow's identity leg stores
  `flow.upstream_redirect_uri = toolset_settings.redirect_uri` from the listing read's
  projection; `upstream_authorization()` builds the upstream authorize URL with
  `"redirect_uri": settings.redirect_uri` (the projection's value); the credential
  call's body carries `"redirectUri": redirect_uri` (the same stored value). Every
  leg's redirect comes from the toolset's stored field.
- DIAL Chat composes its own authorize request with its own callback
  `{chat-origin}/auth/toolset-signin` (`libs/chat-hooks/src/oauth/authorize-url.ts`,
  ai-dial-chat `origin/development` @ e09fc75b3), and the Chat editor **overwrites**
  the stored `authSettings.redirectUri` with Chat's own callback on every toolset save
  (`apps/chat/src/utils/toolsets.ts:153`). A UX-created toolset's stored field points
  at Chat, not the gateway.
- The Admin panel has the same shape: its own callback `{admin-origin}/toolset-signin`,
  self-composed (`ai-dial-admin-frontend`, `ResourceAuthButtons.tsx:80-110`).
- Core's exchange-time validation (`TokenService.resolveRedirectUri`, credentials
  module) accepts the presented `redirectUri` only if it is in Core's configured
  `allowedRedirectUris` **or** equals the stored field; otherwise it falls back to the
  stored one.
- DCR registers the whole current allowlist with the upstream once, at registration
  time (`DynamicResourceRegistrationStrategy.collectRedirectUris`,
  credentials/…/registration/DynamicResourceRegistrationStrategy.java:114-121); Core
  ships a repair API `POST /v1/ops/toolset/{bucket}/{path}/repair`
  (`ToolSetRepairService`) that re-runs DCR with the current list (new client_id, all
  stored credentials cleared; requires `dynamicallyRegistered == true`).
- The gateway's own callback is derivable, not configurable:
  `{GATEWAY_PUBLIC_ORIGIN}/dial/callback/upstream` (`docs/gateway-configuration.md`,
  the two-callbacks-are-derived section; `gateway/settings.py`
  `UPSTREAM_CALLBACK_PATH`).
- The live breakage pair (dev environment, this week): stored field → gateway's
  callback made the gateway's flow work and Chat's fail; the pre-workaround state
  (stored field → Chat's callback, DCR-registered with an allowlist whose first entry
  was the gateway's) made Chat work and the gateway fail.

## Root cause

The flow treats a **contested, mutable artifact** (the toolset's stored
`auth_settings.redirect_uri` — first allowlist entry at DCR time, overwritten by
Chat's editor on every save) as if it were the gateway's own registration fact. It is
not: it is whatever the last editor left there. The gateway has a callback of its own
— fixed path, derived origin — and Core's exchange-time validation is designed for
exactly that shape (present your own callback; be in the allowlist). The flow reading
the stored field is the defect; the deployment workarounds that fight over the field's
value are symptoms.

## Proposed fix

Derive, never read: the consent branch's authorize URL and the credential call's
`redirectUri` carry `{GATEWAY_PUBLIC_ORIGIN}/dial/callback/upstream`, computed from
configuration (design.md D1); the listing read's `redirect_uri` member stops being an
input to any leg. The deployment prerequisite lands with it as a stated runbook:
Core's `allowedRedirectUris` carries all three callbacks (the gateway's first while
any stored-field reader remains), each dynamically-registered toolset is repaired
afterwards, and statically-registered upstream clients get the gateway callback
registered by hand (design.md D7). Chat's editor saves of the stored field become
harmless to every party.
