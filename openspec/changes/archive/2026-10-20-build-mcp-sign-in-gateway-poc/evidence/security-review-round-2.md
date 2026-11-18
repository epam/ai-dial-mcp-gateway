# Security review gate — round 2 (focused re-review of the F1–F5 fixes, diff a6e71c7..HEAD)

Reviewer: fresh opus subagent; the fixes' own new surfaces attacked. F1/F2/F3/F5
VERIFIED sound (offload clean: no shared state in worker threads, no URL-echo into
exceptions, no deadlock, timeouts unchanged; peer binding closes the spoof rotation;
500-logging carries source lines not data; limiter placements correct with the 429-
page rule). F4/4.10 sound as built on their own endpoints; flagged via S1/S2.

## Findings

- **S1 MAJOR** — the refusal-audit surface is unbounded in count AND per-record size:
  no length bound on the caller-supplied facts; the limiter's own 429 branch audits
  (the limiter bounds work, not log volume); the discovery 404 audits on an
  unlimitered route; `/dial/token`'s facts come from an uncapped form (~1 MB
  client_id can land verbatim in the log). Fix: length-bound every fact at the
  `_emit` boundary (truncate, e.g. 256 chars); no caller facts on the
  `rate_limited` branch (volume-refused requests get a facts-free record);
  spec-first: the requirement states facts are length-bounded.
- **S2 MAJOR** — the byte-cap discipline was applied only to `/dial/register`;
  `/dial/token` and `/dial/revoke` read uncapped bodies (`_form_parameters`) — the
  fixes' own bounded-memory claim is false on two surfaces; the only public-origin
  bound is nginx's IMPLICIT 1 MB `client_max_body_size`, stated nowhere. Fix:
  `_capped_body` (settings-configured cap) on both form endpoints; state
  `client_max_body_size` explicitly in the router config as defense-in-depth.
- **S3 MINOR** — the shared 40-token thread pool is a floodable bottleneck: a
  sustained flood of slow-leg requests queues legitimate sign-ins behind the
  attacker's queue (the loop stays responsive — F1 itself is fixed). Record the
  residual; cheap hardening: a capacity limiter on the CIMD fetch specifically so
  an attacker-chosen fetch cannot starve the identity/credential legs.
- **S4 MINOR** — the peer binding (F2) depends on 8091 never being host-published;
  nothing states it. Fix: a comment at the gateway service (and/or nginx) making
  the control self-documenting.

## Dispositions

S1/S2: fixed in the next pass (spec clause first). S3: hardened (capacity limiter) +
residual recorded. S4: documented.
