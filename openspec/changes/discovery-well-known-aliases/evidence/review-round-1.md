# Review round 1 — the independent change-artifact review (`PROCESS.md` step 3b)

The findings of the first independent review of this change's artifacts, recorded
verbatim so they do not live only in chat. Line numbers refer to the artifacts as they
stood at review time (authoring round 1). The disposition of each finding is recorded in
`design.md`, "Review round 1 — dispositions".

---

Verdict: needs another authoring pass, a short one. Nothing BLOCKING.

S1. The instrument cannot tell the router's 404 from the gateway's 404. Where: delta spec line 21 ("none reaches Core or the gateway"); design D4 line 162; D8 W4/W5/W8/W10; tasks 1.2. The closure uses the gateway's own 404 shape ({"detail":"Not Found"}, application/json); nginx drops upstream Server and Date by default, so the two are indistinguishable through the front door. W0 only discriminates Core; a closure mis-written to proxy to the gateway would still pass W4, W5, W8, W10. Fix: give the closure a fixed non-reflecting discriminator header (e.g. `add_header X-Content-Type-Options nosniff always;` — `always` required for 404), pin it in the ADDED requirement and M44, and add W0c: a front-door path the gateway answers with its own 404 (e.g. /.well-known/oauth-protected-resource/dial/x) showing the header absent.

S2. The Core location matches normalized $uri while Core matches its raw path; the closure leaks both directions and DT-EP6-9 prices only one. Where: design D5 line 181; DT-EP6-9 (design line 359, §6 lines 487–517; threat-model row 927); spec line 7 ("MUST NOT forward it to Core"). (i) Into the Core location: raw /.well-known/openid-configuration/../oauth-protected-resource/v1/toolset/x/mcp (curl --path-as-is) normalizes onto the Core regex and is forwarded raw; Core's raw template doesn't match, so Core's 401 + trace header come back on a closed path. Encoded variants (%2e%2e, ..%2F) probably equivalent — measure. (ii) Out of the closure into the catch-all: raw /.well-known/unknown/../../v1/x normalizes to /v1/x, goes through location /, reaches Core with a raw /.well-known/… path → Core 401. W10 never tests this. (iii) PCRE $ matches before a trailing \n from decoded %0A. Not a security break (catch-all already forwards any raw URI to Core) but the spec's absolute MUST is false as written. Fix (a): raw-URI map gate, e.g. `map $request_uri $core_prm_ok { default ""; "~^/\.well-known/oauth-protected-resource/v1/(toolset|deployments)/[^?]+/mcp(\?.*)?$" 1; }` with `if ($core_prm_ok = "") { return 404 ...; }`; or (b) qualify the spec. Extend W10 with both directions, encoded-dot variants, %0A; tasks 1.2 require a verbatim-path client.

S3. D2's rationale misattributes path-insertion probing (design lines 85–87): MCP 2025-03-26 discards the path, so such clients probe root forms. Base the reason on observed client behavior or a client misreading the resource URL as an issuer path. Spec line 49 wording is acceptable.

S4. DT-EP1-18's "the same exposure already existed at the RFC 8414 location" is inaccurate (design line 413; threat-model DT-EP1-18 row and §13 disposition): an OIDC-only RP never fetches oauth-authorization-server, so the OIDC location newly exposes the gateway to that class. Say newly reachable but bounded: the RP must be operator-configured to trust the gateway as an OP, skip ID-token validation, and skip audience validation (M9); keep "no new residual" only with that reasoning.

S5. "One 404 shape whichever component refuses" is overclaimed; MCP path-appending form not dispositioned (spec line 11; design D4 line 162; D7). Data-path refusals (`return 404;` in /dial/ and /apps/) serve nginx's default HTML page (version token unless server_tokens off) — what /apps/<app>/mcp/.well-known/openid-configuration and path-appended PRM forms receive. Fix: scope the sentence to "within the /.well-known/ namespace"; record appending forms in D7 as out of scope with their current answer (router 404, not Core); optionally a probe row asserting they're not Core's answer.

S6. Boundary rows missing (D8): nothing pins the alias regex's (/|$) edge or the Core regex's $ edge. Add rows for /.well-known/oauth-authorization-serverX, /.well-known/openid-configuration.json, …/v1/toolset/<t>/mcp/ (trailing slash) — each the closure's 404.

N1 (design 70; spec 49): RFC 8414 path insertion is §3; §3.1 is the request/example. Cite §3 or §3/§3.1.
N2 (spec 49, design 118): MCP requires verifying code_challenge_methods_supported on any AS metadata, not just at the OIDC location. Reword.
N3 (spec 11; DT-EP6-7): "404 for every method" — POST over client_max_body_size 16384 gets 413; over-long request line 414/400. Add "for any request the server-level bounds admit".
N4 (design 296, 312): "three locations" is four blocks counting `= /.well-known`.
N5 (design 46): gateway port unreachability belongs to docs/pod-contract.md §8.2 (Port non-publication), not §6.
N6 (design 182–184): simplify to "No streaming directives: Core's metadata route answers one JSON document."
N7 (tasks 3.4): also update the catch-all comment in router/nginx.conf (line ~263, "Everything else: Core, unchanged").
N8 (tasks 6.6): the user runs all git writes; agents never commit/push.
N9 (W6): optionally record a one-off mutation run (closure as ^~, W6 failing) in evidence/instrument-run.md as the precedence detector's negative control.
N10 (outside change): untracked pod-named log dumps at repo root — not this change's scope.

Sound per review: nginx precedence (D4) incl. `= /.well-known`; gateway reachability behind alias (uvicorn/Starlette don't resolve dot segments); Core-template claim; standards claims; "low impact" unfalsified; W0b failing-first; tasks implementable; threat-model counts. OQ-1 agree defer root PRM.
