# Security review gate — round 1 (diff 16e655a..HEAD)

Reviewer: independent opus subagent (the security review gate, PROCESS step 8),
full-depth, every "Preserved" ruling attacked directly.

## Never-cut verdicts

All seven rows VERIFIED against the code (1 upstream-token containment incl. no
passthrough; 2 verifier containment incl. the projection assertion in the provisioning
script; 3 per-user isolation incl. flow-id entropy/state/destroy-on-first-use and the
D4 overlay; 4 DIAL authorization incl. the content-decided fallback's ordering;
5 no-credential-in-logs incl. SecretStr/hide_input/fixed-vocabulary; 6 no hardcoded
credentials; 7 key custody incl. gitignore/kid derivation/rotation). Row 3 carries
F6's disclosure gap; row 5 carries F3.

## Findings

- **F1 MAJOR** — blocking synchronous HTTP inside async handlers (cimd.py, idp.py,
  core.py, flow.py — reached from async routes): one slow outbound call (or one
  unauthenticated CIMD fetch, ~10 s) stalls the single event loop — the whole service,
  `/healthz` included (compose would restart a healthy-but-busy gateway). The abuse
  bounds bound counts, not time. **Fix:** offload to a threadpool (anyio.to_thread/
  run_in_executor) or httpx.AsyncClient throughout — one slow leg must not stop the
  rest of the service.
- **F2 MINOR** — per-source rate limit reads the FIRST X-Forwarded-For entry; the
  router APPENDS to client-supplied XFF (`$proxy_add_x_forwarded_for`), so an attacker
  rotates fake first entries and defeats the per-source limit. Fix: prefer the
  router's authoritative `X-Real-IP`, or take the LAST XFF entry.
- **F3 MINOR** — the unhandled-exception handler returns fixed text (correct) but
  never logs the exception (and suppresses Starlette's own logging) — contradicting
  its own comment and the fail-loudly rule. Fix: log type + traceback in the handler.
- **F4 MINOR** — DCR registration body unbounded in bytes (count-only cap): cap the
  request body size and the per-record redirect-URI count/length.
- **F5 MINOR** — `/dial/token`, `/dial/revoke`, and the two callbacks carry no rate
  limit (1–3 RSA verifications per unauthenticated token request — CPU-exhaustion
  path). Fix: the same limiter on the remaining unauthenticated routes.
- **F6 MINOR / disclosure** — the E7 code-injection kill-list covers guessing, not
  INTERCEPTION: an attacker capturing the victim's Keycloak→gateway callback URL
  replays it, then completes the upstream consent in their own browser — the
  attacker's upstream workspace stored under the victim's sub. Control: transport
  security on the public origin (the committed deployment is plain http; D13 defers
  TLS to the deployment layer). Fix: disclose the variant + its control in the
  security impact analysis / threat model.
- **F7 MINOR / disclosure** — the claim-copy blocklist drops `scope` (and `acr`),
  which Core's RuleMatcher can legally key rules on — the silent-never-match class.
  Fix: document the caveat (authorization rules must not key on blocklisted claims).

## Verified sound (attacker-eye pass, no bypass found)

CIMD SSRF control set (all controls implemented, connection pinning, trust_env off);
the loopback-port matcher (keyed on registration, byte-exact elsewhere); the
interstitial (escaping, hash-pinned CSP, fail-closed delivery guard); the DCR store
(atomic write-before-response with rollback, corruption refusal, cap, dormancy);
token minting (marker audience, non-sliding rotation with grace, replay-after-PKCE
ordering); the compose/router (least-privilege env, access_log off, the 401
synthesis). Observation: the catch-all puts Core's full ops API on the harness-facing
origin — not a new class (Core is separately host-published), noted.

## Resolutions — round 1 (authoring pass)

- **F6** — **disclosed.** The security impact analysis now states the interception
  variant: the defense trio (128-bit ids, state round-trip, destroy-on-first-use)
  kills guessing, not interception — an attacker who captures the victim's
  identity-provider callback URL (the provider's code plus the flow id as `state`)
  off the wire can deliver it ahead of the victim's browser, pass the flow lookup on
  a live flow, and complete the upstream consent in their own browser, leaving
  Core storing the attacker's upstream credential under the victim's `sub`. The
  control is named (transport security on the public origin — TLS-front it before
  any real-world use), the residual is recorded as a risk, and row 3 of the
  invariants table points to the disclosure. **Judgment: no spec scenario pins
  it** — the residual is a property of the deployment's transport, not of gateway
  behavior, and a delta-spec row cannot turn a deployment property into one; the
  disclosure in `design.md` and the risk entry are its home.
- **F7** — **documented.** The caveat is stated wherever the blocklist is stated:
  `design.md` D4 and `docs/gateway-configuration.md`'s claim-copy section —
  deployment authorization rules MUST NOT key on a blocklisted claim (`scope`,
  `acr`, or any other name on the list): gateway tokens never carry them and Core's
  RuleMatcher would silently never match. **Judgment: the spec's claim-copy
  requirement does not carry it normatively** — the caveat constrains the
  deployment's Core authorization-rule configuration, which the gateway neither
  enforces nor observes; pinning it as a gateway-behavior requirement would be
  untestable at this boundary, so the design and the configuration reference
  (the document a deployment operator actually reads) carry it.
- F1–F5 are routed to their own implementation passes; this pass touched only the
  disclosure/spec items (F6, F7) and the pre-allocation-refusals logging ripple.
