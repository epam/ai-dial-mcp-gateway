# Finding — the toolset's registered upstream redirect_uri is the retired PoC-A loopback

**Symptom.** A real-harness re-login after toolset sign-out completed the Keycloak
leg, rendered the interstitial, reached Notion's consent, and the user approved —
then the browser was redirected to `http://localhost:8765/callback?code=…&state=…`
and got **connection refused** (nothing listens there; the PoC-A helper that did was
retired). The code died unexchanged (single-use, PKCE-bound to Core's verifier —
harmless).

**Evidence.** The owner's browser URL (captured in session): the redirect target is
`localhost:8765/callback` — the value in the toolset's registered
`auth_settings.redirect_uri` (measured in group 6: `redirect_uri:
http://localhost:8765/callback`, `dynamically_registered: true`). The gateway's flow
correctly redirects to the REGISTERED uri (the upstream only sends the code to a uri
its client registered; Core's `/signin` validates it) — the gateway's behavior is
correct. The defect is the deployment state: the design's amendment (background
design §8 item 5) moves the toolset's upstream redirect to the gateway's own
callback (`E7` = `<public origin>/dial/callback/upstream`), and group 6 appended E7
to Core's `allowedRedirectUris` but **did not re-point the toolset's
`auth_settings.redirect_uri`** — the PoC-A-era value survived the re-confirmation.

**Root cause.** Group 6's provisioning re-confirmed the existing toolset registration
instead of re-pointing its redirect_uri at the gateway's callback; the design
amendment that the allowlist AND the registered redirect both gain E7 was half-applied.

**Proposed fix.** Re-register the toolset with the gateway's upstream callback as its
`auth_settings.redirect_uri` (`PUT /v1/toolsets/platform/notion` with
`redirect_uri: http://localhost:8090/dial/callback/upstream` — dynamic-registration
mode's only permitted field); verify the public settings now carry it and that a
flow's interstitial navigation targets it. If a PUT on an existing toolset does not
re-register the client upstream (measure!), recreate the toolset (the user's stored
credential is already absent; the owner re-consents once afterwards regardless).
Add the re-point to the provisioning script/flow so a fresh deployment cannot
reproduce this.

**Consent-attribution note (not a defect).** Notion's consent screen named the client
"toolsets/platform/notion" — Core's dynamically-registered client, named by Core at
registration. This is the disclosed §6.1 trade (the upstream shows Core's client,
never the harness); the interstitial is the compensating attribution moment.

**Status.** **Fixed** (2026-10-19) — the toolset's stored `redirect_uri` is now the
gateway's upstream callback. The owner's upstream re-consent is pending: the recreate
removed the stored credential, so the next sign-in goes through the consent screen
once.

## Resolution

**What was wrong, restated against the measurement.** The registered
`auth_settings.redirect_uri` was `http://localhost:8765/callback`, the retired PoC-A
loopback:

```
GET /v1/toolsets/platform/notion -> HTTP 200
  client_id              = "Ohk3BbaVnj3lemIy"
  redirect_uri           = "http://localhost:8765/callback"
  dynamically_registered = true
```

**The finding's premise was right; the proposed mechanism was wrong.** The fix it
proposed — `PUT /v1/toolsets/platform/notion` with a new `redirect_uri` — does not
work, and neither does a delete-and-recreate with the new value in the body. Measured,
in order:

| Attempt | Result |
|---|---|
| `PUT` over the existing toolset, `If-None-Match: *` | **412** `Resource already exists` — the idempotency header makes any existing resource a refusal. `redirect_uri` unchanged. |
| `PUT` over the existing toolset, no precondition | **400** `Field 'TOKEN_ENDPOINT' is required for OAUTH authentication.` — Core demands explicit OAuth fields that dynamic-registration mode forbids. `redirect_uri` unchanged. |
| `DELETE` (204) then `PUT` with `redirect_uri: http://localhost:8090/dial/callback/upstream` | **200** — the upstream registration **re-ran** (new `client_id`, new `code_challenge`) but the stored `redirect_uri` came back **still `http://localhost:8765/callback`**. |
| Fresh `PUT` for a *new* toolset carrying `redirect_uri: http://localhost:9999/callback` | **200**, stored `redirect_uri` = `http://localhost:8765/callback`. Core ignored the supplied value entirely and produced a value not in any request. |

That last row is the diagnosis. Core never stores the `redirect_uri` the request body
carries. Its dynamic-registration strategy builds the registration request's
`redirect_uris` from the deployment's configured
`aidial.toolsets.security.allowedRedirectUris` (appending the body's value if it is not
already in that list), and then stores
`registrationResponse.getRedirectUris().getFirst()` — the **first** allowlist entry —
as the toolset's `redirect_uri`:

```
$ javap -p -c .../DynamicResourceRegistrationStrategy.class   # in the Core container
  private java.util.List collectRedirectUris(ResourceAuthSettings settings):
      new ArrayList(allowedRedirectUris)          // configured list, in config order
      if (settings.getRedirectUri() != null && !list.contains(...)) list.add(...)
  ... register with that list ...
      registrationResponse.getRedirectUris().getFirst()   // -> ClientRegistration.redirectUri
```

So the deployment's allowlist was the real defect, not just the toolset's stored value:
it was
`["http://localhost:8765/callback","http://localhost:8090/dial/callback/upstream"]` —
group 6 had **appended** the gateway's callback behind the retired PoC-A loopback, and
Core faithfully stored the first entry. This is exactly the root cause the finding
named (the design amendment was half-applied), one layer below where the finding
looked: the half-applied amendment was the *order* of the allowlist, and the stored
`redirect_uri` was its downstream symptom.

**The fix, in two parts.**

1. **The deployment's allowlist reordered** so the gateway's callback is first:
   `["http://localhost:8090/dial/callback/upstream","http://localhost:8765/callback"]`
   (sibling instance `docker-compose.yml`, config only, not committed there), applied
   with `wsl -e docker compose up -d --force-recreate core`, then the toolset
   re-registered with `scripts/spike_register_toolset.py --replace` (which is the
   delete-then-create path the helper already carried).

2. **The provisioning path hardened** so it cannot reproduce this — see "Stickiness"
   below.

**Verification.**

The public settings now carry the gateway's callback, with the full field set and no
exposed secret material:

```
$ PYTHONUTF8=1 python scripts/spike_register_toolset.py --replace
PUT http://localhost:8081/v1/toolsets/platform/notion -> HTTP 200
GET http://localhost:8081/v1/toolsets/platform/notion -> HTTP 200
  public OAuth settings (no secret material):
    client_id                = "AZqVUmHarBhUjUTW"
    authorization_endpoint   = "https://mcp.notion.com/authorize"
    redirect_uri             = "http://localhost:8090/dial/callback/upstream"
    code_challenge           = "27E0s8XqcXyLA6IMerLhegFxjpiOot9tVGMUUbJ6NzI"
    code_challenge_method    = "S256"
    scopes_supported         = ["default"]
    dynamically_registered   = true
  verifier/secret present  = False

registration verified: the toolset's public OAuth settings are complete
```

`--replace` re-ran the upstream registration, so `client_id` and `code_challenge` are
new values, and the stored credential that had been minted against the old client is
gone — the owner re-consents once on the next sign-in.

**The live flow reaches the interstitial with the new target.** `/dial/authorize`
driven through the front door and the realm's login form (the
`scripts/probe_end_to_end.py` client pattern, credentials from `.env`), stopped at the
interstitial — **the upstream consent was deliberately not completed**; the navigation
target is the evidence:

```
GET /dial/authorize through the front door
  status    302 -> keycloak:8443
  client    dial-mcp-proxy
  scope     profile email
  hop 1: login form submitted -> HTTP 302
=== interstitial reached after 2 hop(s) (HTTP 200) ===
  <meta http-equiv="refresh" content="1; url=https://mcp.notion.com/authorize?response_type=code&amp;client_id=AZqVUmHarBhUjUTW&amp;redirect_uri=http%3A%2F%2Flocalhost%3A8090%2Fdial%2Fcallback%2Fupstream&amp;code_challenge=27E0s8XqcXyLA6IMerLhegFxjpiOot9tVGMUUbJ6NzI&amp;code_challenge_method=S256&amp;state=…&amp;scope=default">
```

`redirect_uri=http%3A%2F%2Flocalhost%3A8090%2Fdial%2Fcallback%2Fupstream` — the
navigation carries the gateway's callback, so the upstream consent now returns to the
gateway (which exchanges the code through Core's sign-in API) instead of to the retired
loopback. This is the same capture shape group 4 recorded for the defect, with the
value moved.

**Stickiness (negative control first).** Three changes, each closing one way the defect
could come back:

| Where | Change |
|---|---|
| `scripts/spike_register_toolset.py` | Its `REDIRECT_URI` default is the gateway's callback (it was the retired loopback), and its docstring states the two facts the measurement exposed: Core stores the allowlist's *first* entry, not the body's value, and a `PUT` over an existing toolset cannot move it. |
| `scripts/spike_register_toolset.py` | The verify step now **fails** when the stored `redirect_uri` is not the gateway's callback, naming the allowlist order as the cause and `--replace` as the remedy. Measured as a negative control: with the allowlist order temporarily reverted and Core recreated, the script reported `redirect_uri = "http://localhost:8765/callback"` and exited **1** with that message. Restoring the order and re-running exits 0. A provisioning step that silently passed on the retired loopback is what let this ship in the first place. |
| `docs/local-environment.md`, `tasks.md` (6.1) | The Core-configuration section now states that the gateway's callback must be **first** in `allowedRedirectUris` and why, documents the delete-and-recreate re-registration path, and points at this finding; task 6.1 says "first", not "append", and its verification names the redirect check. |

**No spec change, no design change.** The gateway's behavior was correct throughout —
it redirects to the toolset's registered callback, as specified (the upstream
authorization requirement pins the upstream `redirect_uri` as a parameter of the
request it must carry). The defect is entirely in the deployment's Core configuration
and its provisioning recipe, which the capability spec does not govern — the same
altitude ruling group 6 recorded for D-12's provisioning script. The `allowedRedirectUris`
list is referenced in the change's design only as a prose deployment fact, and the
background design's §8 item 5 amendment ("`auth_settings.redirect_uri` / the allowlist
gains `https://<host>/dial/callback/upstream`") is satisfied by the fix — it is a
deployment instruction, not a spec row, so nothing normative is left half-applied.
