# Finding — the gateway's HTML pages ship no web-security headers

**Symptom.** The interstitial (and the plain-language error pages) are served with
FastAPI's default headers only — no CSP, no Referrer-Policy, no Cache-Control, no
frame-ancestors/X-Frame-Options, no nosniff. Verified by reading `gateway/flow.py`
(the only `headers=` dict is the outbound credential-API call) and the shipped
template.

**Why it matters on THESE pages specifically (not generic hygiene):**

1. **XSS depth.** The interstitial renders `{client}` — the registrant-supplied
   `client_name` for DCR clients (externally controlled input). Escaping is the
   active layer; a strict CSP (`default-src 'none'`, no script-src needed — the
   auto-continue should be a meta refresh, no JS) is the second layer if escaping
   ever regresses. `base-uri 'none'` included.
2. **Referrer leakage — the sharpest one.** The interstitial renders at the identity
   provider's callback (`/dial/callback/keycloak`), whose URL carries the provider's
   authorization CODE in its query — exchanged server-side before the page renders —
   plus the flow id as `state`. The default `Referer` on the navigation to the upstream
   authorize endpoint carries that callback URL to the upstream page and its
   third-party scripts — a CROSS-PARTY leak (one party's issued code and the flow
   state delivered to a different party's page), not a bounded one, so
   `Referrer-Policy: no-referrer` closes the class for one line — on flow AND error
   pages (error pages reflect user-controlled context).
3. **Caching.** Flow pages (interstitial, callback, error pages) must be
   `Cache-Control: no-store` — a cached interstitial/callback replayed is a
   stale-flow resubmission.
4. **Clickjacking.** An auto-continuing page advances an OAuth flow; framed by an
   attacker page it advances inside a victim's browser with the victim's sessions.
   `frame-ancestors 'none'` + `X-Frame-Options: DENY`.
5. **Sniffing/charset.** `X-Content-Type-Options: nosniff` + explicit
   `charset=utf-8` in the header (the meta tag exists; the header should carry it).

**Scope.** All the gateway's HTML responses: the interstitial and every plain-language
error/flow page. JSON API responses are a separate (smaller) question — the same
no-store/referrer family applies cheaply.

**Spec gate.** The delta spec pins nothing about response headers for the flow pages —
an authoring ripple is required (spec-first), then the implementation (headers on the
page-response path + a header-assertion test per page class).

**Status:** fixed — the implementation landed (below). Every HTML response the gateway
serves now carries the family, asserted per page class and captured live from the composed
stack.

## Implementation (task 4.9)

**One helper, both page classes.** `gateway/pages.py` is the family's home: `PAGE_STYLE`
(the one stylesheet both templates substitute), `page_headers()` (the family),
`html_page()` (the single construction path). The interstitial's response
(`gateway/federation.py`) and the three error/flow builders (`gateway/errors.py`) all go
through `html_page`; the JSON and redirect error responses keep their existing `_NO_STORE`,
unchanged.

**The style permission, and why by hash.** The CSP is

```
default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'sha256-<…>'
```

with the hash computed at import from `PAGE_STYLE` — the very text both templates inject
via `STYLE_BLOCK`, character for character. The two hand-maintained alternatives were
rejected on a failure mode rather than on taste: `'unsafe-inline'` would permit any
injected `<style>` as well as the page's own, and a per-template literal hash is one
stylesheet edit away from authorizing text no page serves. Here the hash and the served
element cannot drift, because they are the same string.

### Verification rows

| Check | Result |
|---|---|
| The interstitial, unit tier (`test_the_interstitial_carries_the_web_hardening_headers`) | Every directive asserted on the real response, plus `no <script` in the body |
| Each error page, unit tier (`test_every_error_page_carries_the_web_hardening_headers`) | All three builders (`flow_expired_page`, `gateway_error_page`, `no_access_page`) asserted, each labelled so a failure names which path lost the family |
| The policy admits no script source | Asserted as a property: no `script-src` directive, no `'unsafe-eval'`, no `'self'`/`http:`/`https:` source — so a *widening* of the policy fails for review rather than passing a stale equality check |
| No `Set-Cookie` on any page | Asserted on every page class (D13's "the gateway serves none") |
| **The style hash is a real control, not decoration** | `assert_hardening_headers` recomputes the SHA-256 from the **served page's own `<style>` text** and compares it to the policy's token — so the assertion is against what was actually sent, not against a copy of the constant |
| **Negative control on the instrument** | A response built outside `html_page` (same body, no headers) is **rejected** for the missing CSP; a page whose stylesheet text was tampered with **fails** the hash comparison. The instrument can therefore distinguish, and the green above is not a probe that passes whatever it is handed |
| `pytest -q` | **337 passed, 1 skipped** (was 335; +2 tests) |
| Static gates | `ruff check`, `ruff format --check`, `mypy` (strict, 36 files) all clean; `bandit` no issues; `pip-audit` no known vulnerabilities |
| Compose-boot | gateway rebuilt and recreated, router restarted (the recorded operational fact); both services healthy; `/healthz` 200 both direct and through the router; Core answering through port 8090 |

### Live capture — the served headers, from the composed stack

The signed-out flow was driven through the front door (`/dial/authorize` → the realm's
login form → the gateway's callback) and stopped at the interstitial. The owner's upstream
credential was **not** established and no consent was given. Redacted: the flow id appears
as a handle only.

**The interstitial, `GET /dial/callback/keycloak` through the router (HTTP 200):**

```
cache-control:          no-store
content-security-policy: default-src 'none'; base-uri 'none'; frame-ancestors 'none';
                         style-src 'sha256-gzbfRETQyopc1MuEj8ONuw6VA6vruqpAc46095zH5yw='
content-type:           text/html; charset=utf-8
pragma:                 no-cache
referrer-policy:        no-referrer
x-content-type-options: nosniff
x-frame-options:        DENY

body: interstitial           continuation host: mcp.notion.com/authorize
parameters delivered:        client_id, code_challenge, code_challenge_method,
                             redirect_uri, response_type, scope, state
state:                       <redacted len=22 sha256=b152307aceae>
script present:              False
```

**A plain-language flow page, `GET /dial/callback/upstream?state=<unknown>` through the
router (HTTP 400, the expired-session page):** the identical header set, byte for byte,
including the same `style-src` hash — one family on both page classes, as designed.

The captured `style-src` token equals the hash the unit helper recomputes from the page it
was served with, so the live header and the served body agree on the composed stack, not
only in the test client.

## Spec ripple (authoring pass)

**What landed, where:**

- **Delta spec** (`specs/mcp-signin/spec.md`): a new ADDED requirement, **"HTML
  responses carry the web-hardening header family"**, placed after the
  arrives-complete requirement (the page-serving requirements stay together), with
  two scenarios — the interstitial carries the headers; an error or flow page
  carries them. The pinned set is exactly the finding's five, with each directive's
  reason stated in the requirement's orbit, not generic hygiene: the CSP excludes
  script execution (the interstitial is script-free by its D12 mechanism), with the
  inline style's satisfaction (nonce / hash / `'unsafe-inline'`) left to the
  implementation; `base-uri 'none'` and `frame-ancestors 'none'` ride the CSP, with
  `X-Frame-Options: DENY` as the legacy spelling of the framing guard.
- **`design.md`**: decision **D13** — one header family on both page classes, each
  directive earned by a page-class reason (the referrer one is the sharpest: the
  interstitial renders at the identity provider's callback whose URL carries the
  provider's code and the flow state, and its own behavior navigates onward — a
  default Referer would carry both cross-party to the upstream's page; the framing
  one: an auto-continuing page advances a flow). Deliberately not pinned, on record: **HSTS/TLS** — termination
  belongs to the router/deployment layer, and the committed router's plain-http
  :8090 listener makes HSTS inert there (a TLS-terminating deployment adds it at its
  own listener, stated where the routing is designed); **cookies** — the gateway
  serves none; **JSON responses** — the RFC 6749 error/redirect responses already
  carry `no-store`, and extending the family to JSON stays a separate, smaller
  question. The never-cut row 5 ruling and the traceability table gained the
  header-family row.
- **`tasks.md`**: task **4.9** — the shared header helper on the interstitial and
  error-page response paths, the header-assertion test per page class, the live
  re-run evidence, and the stale-evidence note (`evidence/group-4.md`'s test-summary
  rows). No router task: the design rules the router adds nothing on the committed
  listener.

**What did not change:** nothing on the page-serving path itself — `gateway/flow.py`
and `gateway/errors.py` are untouched in this pass; the headers exist in spec and
design only until 4.9 lands. The finding stays open until 4.9's evidence row exists.

## Ripple review (fresh reviewer pass) — needs-changes, two corrections

Verified good: the header set (correct, minimal, nothing missing for script-free/
navigation-only pages; XFO alongside frame-ancestors is legacy coverage, not noise);
both scenarios hermetic and falsifiable; D13's other rulings hold against the code
(no Set-Cookie anywhere; plain-http :8090 listener; JSON no-store).

- **F1 (medium — falsified premise, correct in three places).** The finding (leak
  item 2), D13's Referrer-Policy bullet, and the never-cut row-5 extension state the
  interstitial renders "at the upstream callback, whose URL carries the upstream
  code". False: the interstitial renders at the **identity provider's callback**
  (`/dial/callback/keycloak?code=<IdP code>&state=<flow id>`); the code on that URL
  is Keycloak's, already exchanged server-side before the page renders. The leak is
  therefore CROSS-PARTY (an IdP-issued code + flow state delivered to the upstream's
  page and its third-party scripts) — which strengthens no-referrer but invalidates
  the recorded bounded-leak argument ("the upstream issued the code"). Fix all three
  texts; the spec requirement is unaffected (it names no callback).
- **F2 (low — task pointer).** Task 4.9 pins the response path as `gateway/flow.py`;
  the HTMLResponse is constructed at `gateway/federation.py` (~line 118). Name both.

## Ripple review — resolutions (author pass)

- **F1 — resolved.** The leak premise is corrected everywhere it was recorded: leak
  item 2 above, `design.md` D13's Referrer-Policy bullet, and the never-cut row-5
  extension (the header-family sentence on the row-5 ruling). The corrected reasoning:
  the interstitial renders at the identity provider's callback
  (`/dial/callback/keycloak`), whose URL carries the provider's (Keycloak's)
  authorization code — exchanged server-side before the page renders — plus the flow
  id as `state`; NOT the upstream callback or the upstream code. A default `Referer`
  on the page's onward navigation delivers that IdP-issued code and flow state to
  the upstream's page and its third-party scripts — a cross-party leak, not a
  bounded one, which strengthens `Referrer-Policy: no-referrer`. Two further
  repetitions of the same false premise were corrected for the record's internal
  consistency: this file's ripple-summary sentence recapping D13, and `design.md`'s
  traceability-table header-family row. The header set is unchanged; the spec
  requirement names no callback, so no spec change.
- **F2 — resolved.** Task 4.9's file pointer now names both: the page renderer
  (`gateway/flow.py`, `interstitial_page`) and the response construction
  (`gateway/federation.py`, where the interstitial's `HTMLResponse` is built).

