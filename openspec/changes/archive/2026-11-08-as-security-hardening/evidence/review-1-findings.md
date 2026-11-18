# Independent review — round 1 (planning artifacts, before the owner pause)

Reviewer: the PROCESS.md step-3b independent reviewer (a fresh subagent, not the
author). Method: falsification — every falsifiable claim in the package was checked
against the code it cites, the authoritative spec sources the delta must match, the
method documents it must conform to, and (for the load-bearing external facts) the live
public documents the design names. No code was touched; nothing was fixed here.

Inputs read in full: the change folder (proposal, design including the SIA, delta
spec, tasks); `CLAUDE.md`, `PROCESS.md`, `ROADMAP.md` (never-cut list);
`docs/production-roadmap.md` (§"C2.5 — AS security hardening"); `docs/security-analysis.md`;
`docs/threat-model.md` (the T1-25 row and dispositions, the M-register, the grouped
mitigation list, the RES register); the archived C2 change's delta spec (the
authoritative baseline for the three C2-modified requirements this delta re-carries);
the pre-sync main spec (`git show 4519c93^:openspec/specs/mcp-signin/spec.md`, the
authoritative baseline for HTML/claim-copy/public-endpoints); the corrupted on-disk
main spec; `gateway/authorize.py`, `gateway/federation.py`, `gateway/flow.py` (the
cited ranges), `gateway/tokens.py`, `gateway/state.py`, `gateway/pages.py`,
`gateway/app.py`, `gateway/idp.py`, `gateway/audit.py`, `gateway/settings.py`,
`router/nginx.conf`. External, fetched live: the MCP Security Best Practices document
(modelcontextprotocol.io, 2025-06-18 basic/security_best_practices), the MCP
authorization specification (2025-11-25), and RFC 9700 (rfc-editor.org, §2 and §4 in
full). A programmatic unified diff of every MODIFIED requirement (delta vs its
authoritative baseline) was run to catch undeclared drift.

## What held under falsification (so the findings below start from a verified floor)

- **The checkpoint's mechanism survived every attack attempted on it.** The three mint
  paths are exhaustive in the code: `_finish` (the only `issue_code_for_flow` caller)
  has exactly three call sites — the app short-circuit
  (`gateway/federation.py:154`), the toolset stored-credential short-circuit
  (`:194`), and the upstream callback (`:305`) — so no fourth mint path exists to
  bypass the gate. The flow id's secrecy from a link-crafter holds (it is minted
  server-side and crosses only the victim's browser, on the IdP redirect and callback);
  the gateway genuinely sets no cookies anywhere (grep-clean), so the structural
  CSRF argument is sound; the registry's only write path is downstream of a completed
  identity leg, so no unauthenticated escalation exists; the no-operator-bypass
  refusal is correctly grounded in T1-14 (a pre-registered id is wearable; there is no
  client authentication to key an auto-trust on).
- **The external facts are real.** The MCP Security Best Practices document carries
  the Confused Deputy section member-for-member as the design describes (static client
  ID + dynamic registration + consent cookie + crafted link + code to the attacker),
  its mitigation is an exact "MCP proxy servers **MUST** implement per-client consent"
  with the page **before** the third-party authorization flow, a per-user approved-
  client_id registry checked before forwarding, the consent-UI requirements (client
  name, redirect_uri, CSRF protection, no iframing), and the consent-cookie/state
  MUST NOT the design quotes; the same MUST also appears in the authorization spec's
  Security Considerations. The authorization spec mandates
  `Authorization: Bearer` (OAuth 2.1 §5.1.1) and names DPoP nowhere; it makes client
  `state` a SHOULD; `max_age`/`prompt`/`auth_time` appear nowhere in it. RFC 9700
  §2.2.1 is a SHOULD; §2.2.2/§4.14.2 carry the sender-constrained-or-rotation MUST
  (rotation held, M9); §4.11.2 carries the authenticate-before-redirect MUST with the
  silent-authentication exception, the trusts-the-URI SHOULD, and the inform-the-user
  MAY exactly as cited; §2.6 permits CORS at the token endpoint (MAY) and forbids it
  at the authorization endpoint; §2.1 accepts PKCE as the CSRF carrier. The DPoP
  deferral's two-sided precondition is factually right against all of these.
- **The state and CORS rulings are grounded.** The absent-state tolerance and the
  echo-only-when-present behavior are today's code (`gateway/authorize.py:116-118`,
  `gateway/flow.py:462-466`) and were never stated; no CORS middleware exists anywhere
  (`gateway/app.py` builds the app with none — grep-clean); `REGISTRY_CLAIMS` strips
  `acr` but not `auth_time` (`gateway/tokens.py:64-83`), so D7's hygiene rule closes a
  real copy-rule gap.
- **The delta is well-formed.** Every MODIFIED block carries its baseline's complete
  text plus only the declared amendments — verified by mechanical diff of each block
  against the archived C2 delta (authorization-requests, federation-flow,
  app-resource) and the pre-sync spec (HTML, claim-copy, public-endpoints): all
  retained scenarios present and verbatim except the declared re-wordings, SHALL/MUST
  discipline consistent, vocabulary consistent with design.md, and no requirement
  modified that the design leaves untouched. The "(retained)" amendment markers are
  used correctly.
- **The SIA conforms to `docs/security-analysis.md`**: all eight subsections in order;
  the impact level (Medium) is reasoned, not rubber-stamped; the invariant ruling
  table covers all seven never-cut invariants with no row weakened; the EP1/EP3 delta
  threat tables follow the vendored structure with mis-use marked; every one of the
  eight control categories appears for every threat with threat-specific N/A reasons;
  every gateway-owned §6 mitigation maps to a delta requirement (what task 2.2 will
  check holds now). The M24→M7 cross-reference defect the design claims in the threat
  model is real (M24 is the apps front-door surface, `docs/threat-model.md:1897`; the
  CIMD origin allowlist is M7's, `:1881`), and M31 is the next free M-number.
- **Scope fidelity and gates.** All five roadmap scope seeds plus the two first
  acceptance rows are dispositioned with task coverage; group 7's gate order matches
  PROCESS.md's ladder exactly; the roles, lockstep, and evidence conventions match the
  house pattern; publication discipline holds (no real issuer/tenant/org values, no
  internal hostnames, no personal paths — grep-clean).

## Findings

**F1 — should-fix — tasks.md, group 1 (the main-spec repair): the corruption
inventory is incomplete, and its target count contradicts itself.** The group's
defect list names the six mid-line welds (verified at exactly lines 150, 370, 372,
441, 443, 578), the two duplicated blocks, and the stale pre-C2 app-resources twin
(verified: the line-~632 block carries the "public PKCE client"/"three-shape"
wording; the welded 578 block carries C2's). But the corrupted main spec is also
missing **two whole requirements outright** — "End-to-end acceptance on a real
harness gates completion" (pre-sync line 372) and "App MCP resources are served
through the apps front-door path" (pre-sync line 594) have **zero** occurrences in
the on-disk file (not welded, not duplicated: gone), and neither is named in the
repair task. On top of that, task 1.1's verification criterion says "32 line-start
headers in total" while the group preamble and task 1.2 both say 31 (27 pre-sync,
verified, + the C2 delta's 4 ADDED, verified — 31 is correct; the 32 almost
certainly counts the six welded header *occurrences*, 26 line-start + 6 mid-line,
which is the corrupted file's accident, not the target). The safety nets exist — the
reconstruction is requirement-by-requirement against the two sources, 1.2 asserts
the name set equals what the sources jointly define, and the preamble says the
sources govern over any count — so an implementer following 1.2 would recover the
lost requirements; but 1.1's own inspection criteria are wrong, and the one task
everything else builds on should not carry a wrong number and a blind spot.
Suggested direction: add the two lost requirements to the group's defect list (as
blocks to restore verbatim from the pre-sync source), and correct 1.1's "32" to 31.

**F2 — should-fix — the delta spec (and proposal §Modified Capabilities): the
flow-lifecycle audit requirement is not amended for the three new attribution
events.** "Flows are audited through their lifecycle" carries a closed
lifecycle-events enumeration — allocation, the upstream callback, the credential
call's result, code issuance, leg failures — which C1.5 extended by *declared
amendment* when the app events were added (the house precedent for exactly this
situation). This change adds three lifecycle events a flow's trail now carries
between allocation and issuance (`attribution_required`, `attribution_approved`,
`attribution_refused`), and the proposal itself says "the abuse/audit requirements
extend to whatever new surfaces the dispositions add" — but the delta lands the
events only inside the ADDED checkpoint requirement, leaving the lifecycle
requirement's enumeration describing a trail the post-sync spec's own new
requirement contradicts: two requirements, one trail, different event sets. (The
parallel case is argued and holds: the pre-allocation-refusals requirement needs no
amendment because its enumeration is class-based — "`/dial/authorize` validation
refusals" already admits `oversized_state` — and the delta says so; the lifecycle
requirement's enumeration is event-based, which is the difference.) Suggested
direction: a declared MODIFIED block for "Flows are audited through their lifecycle"
adding the attribution events to the enumeration (the retained end-to-end-attributable
scenario needs at most its THEN checked against them), or — if the verdict is that
the ADDED requirement's "under the trail's existing discipline" sentence carries
the extension — a declared statement of that in the delta, so the sync lands one
consistent trail.

**F3 — should-fix — design.md D3 (and the delta's page-content scenario): the
no-scope-list ruling's recorded reasoning is wrong for the toolset consent branch,
and the deviation from the cited MUST is undeclared.** The MCP Security Best
Practices consent-UI requirement the design adopts (verified live) has the MCP-level
consent page **MUST** "display the specific third-party API scopes being requested"
alongside the client name and `redirect_uri` the design does adopt. D3's recorded
reason for omitting any scope display is "presenting scopes the flow does not act on
would be theater" — true for the client-facing `scope` parameter (accepted and
dropped), but false as stated for the toolset consent branch, where the flow *does*
act on third-party scopes: the upstream authorization request carries the toolset's
advertised scopes (the upstream-complete requirement names them; the listing read
carries the public settings the branch builds its URL from), so the scopes being
requested from the third party exist and are knowable at the decision point. The
defensible reasons are available but are not the recorded ones: on the consent
branch the upstream AS's own consent screen — served immediately after the decision
page — is where those scopes are shown to the user, and on both short-circuit paths
no third-party scopes are requested at all. As written, the design leans on this
MUST's authority for D1's central decision while silently declining one of its
members with an inaccurate reason — exactly the shape D10's re-judge walk (which
covers the MCP security considerations) would trip over. Suggested direction:
either show the toolset's advertised scopes on the decision page for the consent
branch (the data is already on the flow record), or keep the omission and correct
the reasoning in D3 and the delta's scenario — naming where the scopes are shown
(the upstream consent screen) and that the short-circuits request none — so the
deviation is declared and priceable rather than accidental.

**F4 — note — the delta spec, app-resource block: one undeclared THEN change.** The
declared amendment says "App sign-in completes with no consent and no credential
call" and "Repeat app sign-in is silent" "each gain the approved-client condition in
their WHEN" — but "Repeat app sign-in is silent"'s THEN also changes ("no consent,
no credential call" gains ", no page of any kind"). The change is right (it is the
zero-click property the checkpoint preserves, and D5's live acceptance proves it),
and it was caught only by mechanical diff — which is the point: this repo's delta
discipline declares every change, and the C2 review caught drift the same way.
Suggested direction: add the THEN to the declared amendment.

**F5 — note — design.md D2 and task 3.5 vs the migration plan: the toolset
stored-credential short-circuit's insertion point is named imprecisely.** D2 and
task 3.5 say the checkpoint is inserted "in `_run_identity_leg`
(`gateway/federation.py:115-176`)", but the stored-credential short-circuit's mint
(the `result.status.signed_in` → `_finish` at `:191-194`) lives in
`_toolset_after_read` (`:179-207`), outside the cited range and function; only the
app short-circuit and the consent-branch interstitial position are in
`_run_identity_leg`. The migration plan gets it right ("the checkpoint insertion in
`_run_identity_leg`/`_toolset_after_read`"). The three paths themselves are named
correctly everywhere, so nothing is missed — the pointer is just under-inclusive
where an implementer will look first. Suggested direction: name both functions in
D2's "Concretely" sentence and in task 3.5.

**F6 — note — proposal §Modified Capabilities / §Impact vs the delta: the CORS
posture's stated home and its actual home differ.** The proposal says "the
**token-grant** requirements gain the CORS/back-channel posture statement" (and D9
says "the delta spec's token-grant requirement"); the delta lands the paragraph in
the public-endpoints/abuse requirement, with a declared in-delta resolution (the
main spec carries no requirement titled for the token grant itself, and the abuse
requirement governs the unauthenticated AS endpoint set the posture spans). The
resolution is sound and declared — but the proposal and design name a requirement
that does not exist, which is precisely the kind of cross-artifact vocabulary drift
the coherence pass exists to catch. Suggested direction: re-word the proposal/design
to the abuse requirement's name (or "the AS-endpoint abuse requirement"), leaving
the delta's resolution note as the record of why.

**F7 — note — design.md, SIA §3: one ruling value outside the method's
vocabulary.** `docs/security-analysis.md` §1 fixes the invariant ruling values as
"Preserved / Preserved with a disclosed bound"; invariant 3 is ruled "Preserved, and
strengthened". The claim is true (the registry is per-user by construction and the
checkpoint removes T1-25's cross-user mint) and weakens nothing — it is simply a
third spelling the method does not define. Suggested direction: "Preserved" with the
strengthening stated in the reason column.

**F8 — note — design.md, SIA §7 (the threat-model delta): DT-EP1-3's landing in
the model is unstated.** §7 lists the new threat rows that land in
`docs/threat-model.md` — DT-EP1-1 (forged approval), DT-EP1-2 (registry flooding),
DT-EP3-1/2/3 (the decision page) — and is silent on DT-EP1-3 (oversized `state`
growth), which §4 tables. Not landing it as a new row is defensible: it is a
narrowing of the existing unauthenticated-allocation class (the flow-record memory
DoS family), not a new threat the change introduces — but the defensible outcome
should be stated, because a delta that tables a threat and never says where it
lands is the shape the "dispositioned, never silently dropped" rule exists to
prevent, and task 2.1's implementer will otherwise have to guess. Suggested
direction: one clause in §7 — DT-EP1-3 is the existing allocation-DoS class narrowed
by the bound, its mitigation in the delta spec, no new model row — or land it as a
row.

**F9 — note — design.md D4: the registry's single-issuer safety is load-bearing and
unstated.** The registry keys `(subject, client_id)` with no issuer dimension.
`sub` values are not globally unique across issuers, so this is safe only because
the deployment's shape is one configured identity provider per process and a
provider change requires a restart — which empties the in-memory registry, so no
cross-issuer `sub` collision can ever be consulted. That chain is real but recorded
nowhere; and OQ-1's future *persistent* registry would inherit the keying without
inheriting the safety (a durable store across a provider migration is exactly where
a stale `(sub, client)` from the old issuer would pass the check for a different
user under the new one). Suggested direction: one sentence in D4 stating the
single-issuer/restart-clears argument, and a caveat clause on OQ-1 so the durable
registry's own change re-keys or re-scopes.

## Verdict

The package's load-bearing claims all held under adversarial checking: the
checkpoint's design is sound against every bypass attempted on it (the three mint
paths are exhaustive in the code, the flow-id binding is secret from the link-crafter
by construction, no cookies exist for a CSRF shape to feed on, the registry has no
unauthenticated write path, and the no-bypass ruling is correctly priced on T1-14);
every external fact D1/D6/D8/D9 rest on was verified live against the MCP best
practices, the MCP authorization specification, and RFC 9700, including the
confused-deputy MUST and its member-for-member match to T1-25 and the DPoP
deferral's two-sided precondition; the delta is mechanically well-formed against its
authoritative baselines with only declared amendments (one undeclared THEN clause
aside); the SIA conforms to the standing method with no never-cut row weakened; and
the scope, tasks, and gates match the roadmap and PROCESS.md. No finding re-opens a
design decision: the nine findings — three should-fix (the repair task's incomplete
corruption inventory and self-contradictory target count, F1; the unamended
flow-lifecycle audit enumeration for the three new attribution events, F2; and the
no-scope-list ruling's inaccurate recorded reasoning against the MCP consent-UI MUST
it cites, F3) and six notes — are completeness and precision defects in artifacts
whose mechanisms are right. F1–F3 should be dispositioned before the owner pause:
F1 because group 1 is the declared precondition of everything else and should not
carry a wrong number and a blind spot into implementation, F2 because the synced
spec must land with one consistent audit trail, and F3 because D1's authority rests
on the very document whose consent-UI member the design silently declines with a
reason that does not hold on one of the three paths. With those three dispositioned
— fix or explicitly ruled — the change is ready for the owner review pause.


