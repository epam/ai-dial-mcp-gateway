# Authoring round 5 — the D5 amendment: the confidential client in every deployment (2026-11-05)

Author: the design author (this pass). This note records the owner's round-5 design
ruling — issued during the live-run setup, after all six task groups had landed and
both review gates had passed — and the revision of the change's artifacts to the
ruled semantics. No implementation code was touched this round: the code delta is
the next round's, executed by implementers against the re-opened tasks 4.1/4.2.
The prior evidence files (rounds 1–4, the task-group implementation records, the
gate records) are historical records and were not re-worded; where they say
"public PKCE client" or "no-PKCE mode" they describe the superseded design.

## The ruling (owner round 5, 2026-11-05)

Verbatim in its intent:

> The gateway is NOT a public client to the identity provider. It is a private
> (confidential) client. The modes are "client secret + PKCE" or "simply
> client_secret" — never "just PKCE". (The "Allow public client flows" toggle at
> the provider was the wrong answer; the design omission was the gateway operating
> as a public client at all.)

The reasoning, as the ruling carries it and as the design now records it (D5):

- **First-party client.** The gateway is a first-party client of the deployment it
  serves — not an untrusted third-party application, which is the class the
  public-client shape exists for.
- **Already holds higher-grade secrets.** The gateway process holds the signing key
  and the custody key; requiring a client secret adds no new custody class, so the
  public client's classic justification (nowhere safe to keep a secret) does not
  apply to it.
- **RFC 9700-aligned shape.** The current OAuth 2.0 Security BCP's shape for a
  confidential client is client authentication plus PKCE — the challenge composed
  on top of the secret, never a public client whose only binding is the challenge.
- **The registration bypass was the symptom.** The old public-client design forced
  a provider-registration bypass at the tested tenant — its "Allow public client
  flows" portal toggle had to be enabled for the SPA/PKCE shape to work — and that
  toggle was the wrong answer to the design omission, not a mode to keep. The
  tenant's client is registered confidentially; no public-client-flows bypass.

## The semantic diff, old vs new, per artifact

**design.md D5** — old title "The confidential-client/no-PKCE mode, and what it
does and does not touch"; the secret's use *conditional and loud*
(`IDP_PKCE_ENABLED=false` requires a secret; the default mode never presents it);
the secret framed as the no-PKCE mode's *compensating control*. New title "The
gateway is a confidential client at the identity provider; the PKCE toggle
governs the challenge only (amended by the owner's round-5 ruling)": the ruling
recorded with its reasoning; the secret **required at startup in both toggle
positions** (a missing or blank `IDP_CLIENT_SECRET` refuses startup naming the
setting either way); the exchange and refresh grant authenticate with the secret
**on every token request, in both modes**; `IDP_PKCE_ENABLED` (default true)
governs **only** whether the S256 challenge/verifier rides on top; the old
public-client mode removed as a design option; never-cut 2's boundary re-verified
and re-stated (below).

**design.md Context (the tested-case record)** — the B2C refresh-token bullet
re-anchored: the SPA/PKCE shape's verified 24-hour fact is no longer the gateway's
shape; the gateway's registration is the confidential (web) shape, whose
refresh-token issuance without `offline_access` is **live-run-to-verify** (the
tested provider is expected to issue refresh tokens by default for its web
registrations too — the run verifies).

**design.md D9** — the registration shape re-worded: a confidential (web) client,
no public-client-flows bypass at the registration; the session-window fact
re-anchored to the confidential shape's 14-day default (the run records the
tenant's actual value). **design.md OQ-A/OQ-B** — OQ-A's live-run list swaps the
SPA/PKCE shape for the confidential registration's issuance; OQ-B re-anchored:
the question is live-run-to-verify for the web shape (the public docs state the
SPA/PKCE shape's fact, not the web shape's). **design.md D13** — the delivery
decision's "required at startup in no-PKCE mode / never presented in the default
mode" clauses replaced with the both-positions requirement and the
every-token-request presentation; the committed `.env.example` placeholder stays
empty (never-cut 6), the running deployment's `.env` supplies it.

**design.md SIA** — §1 business/implementation shape re-worded to the
confidential-client semantics; §2 keeps the **High** level and states the
re-pricing (the secret load-bearing in *every* deployment — a widening of an
already-priced class, not a new class); the invariant table's row 2 re-worded
(the secret as the identity leg's *inherent* control, required at startup either
way); the EP5 delta rows re-worded (the forged-discovery row's secret now
unconditional; the interception row renamed *challenge-off mode* with the control
inherent; the token-endpoint wire row renamed *both modes*; the direct-mode row's
qualifier dropped); the EP4 row re-priced (below); DT-EP5-3/DT-EP5-4/DT-EP4-1
and the grouped list's items 3 and 6 re-worded; §7's threat-model delta
re-priced (below).

**specs/mcp-signin/spec.md** — the requirement re-titled "The identity-provider
client is confidential; the PKCE toggle governs the challenge only" and
re-worded: the secret authenticates every token request in both toggle positions,
required at startup in either position; the toggle governs the challenge/verifier
only. Scenarios: the startup refusal re-worded ("A missing client secret refuses
startup in either toggle position"); the no-challenge scenario stays for the
disabled toggle ("The challenge-off mode runs as a secret-authenticated client
without PKCE"); the old "The default mode never presents the client secret"
converse **replaced** — its property inverts ("The default mode presents the
client secret under the challenge": both bindings on); the client-facing
PKCE requirement scenario unchanged; the never-emitted property ("The client
secret never reaches an output") stays normative, its WHEN widened to either
toggle position. The three "public PKCE client" amendment notes
(authorization-requests, federation-flow, app-resources) re-worded to the
confidential-client shape; the discovery-validation requirement's credential
list drops the no-PKCE qualifier.

**tasks.md** — 4.1/4.2 re-worded to the ruled semantics and **unticked** (they
re-execute next round): 4.1 makes the secret required at startup in both
positions in `gateway/settings.py` with the re-pointed `tests/test_settings.py`,
and carries the local-deployment knock-on (the provisioning helper registers the
client confidentially — `publicClient` false, a generated secret; the local
`.env` gains `IDP_CLIENT_SECRET`; `.env.example`'s comment states the
requirement); 4.2 makes `_client_authentication()` present the secret in both
modes (the `idp_pkce_enabled` branch removed from it) with the toggle governing
the challenge/verifier alone, and re-points the mode tests in
`tests/test_idp.py`/`tests/test_settings.py`/`tests/test_tokens.py` — the
default-mode-never-presents tests invert again; the never-emitted tests stay.
Task 7.1's D9 fact re-worded: **the confidential client** receives session
refresh tokens without `offline_access` (the tested provider issues refresh
tokens by default for its web registrations too — the run verifies). Surgical
coherence edits: task 1.1's re-priced-RES-19 phrase and the round-5 re-price
note; task 1.2's mitigation-list wording; task 5.1's challenge-off trade and the
required-secret delivery statement; the group-4 header.

**proposal.md** — the "confidential-client option" bullet becomes "The gateway is
a confidential client at the identity provider"; the BREAKING bullet gains the
confidential registration and the required secret; the Capabilities bullet and
the `gateway/idp.py`/`gateway/settings.py` Impact lines re-worded.

**release-notes-draft.md** — the users section states the confidential client
(one coherent story: secret required and authenticating every token request;
PKCE-incapable providers handled by turning the challenge off); the breaking
paragraph gains the required secret; the team section re-worded to match.

**docs/threat-model.md** — re-priced by the ruling (the design author landed it
this round, per the standing order that the model is updated before
implementation): RES-19's re-priced paragraph (the override deployments carry the
secret on every token request, both toggle positions — the no-PKCE-only
conditioning superseded); RES-24 re-titled "the challenge-off mode's interception
residue" with the control stated as inherent, not mode-conditional; A18 re-worded
(load-bearing in every deployment; the no-secret deployment exposure class
removed by the ruling); the EP4 entry-point line, section header, and
client-secret row re-priced; the EP5 forged-discovery, interception, and
direct-mode rows re-worded; §1's flow sketch and M13 (the provisioning
convergence) re-worded to the confidential registration; M28 re-worded (the
confidential-client rule); the register rows T4-9 and T5-11 re-priced. The
harness-facing public-client rows (EP1/EP3's DCR and attribution rows, the
client-facing leg's mitigations) are a different client surface and are
deliberately untouched.

## The re-pricing notes

- **The client secret is load-bearing in EVERY deployment.** It is always on the
  token leg's wire and always in process memory — EP4's row and A18's footprints
  now say "every deployment" where they said "no-PKCE mode". The blast radius is
  unchanged (the IdP-leg client only: no gateway mint, no Core access, no
  upstream credential), and in the challenge-on mode a leaked secret alone still
  cannot spend an intercepted code (the verifier is the second binding) — the
  challenge remains a real narrowing there, but the secret is no longer optional
  anywhere.
- **The no-secret deployment exposure class is REMOVED by the ruling.** The prior
  design permitted a deployment with no client secret at all (the public-client
  default mode); that class no longer exists — startup refuses without the secret
  in both toggle positions. Recorded as removed-by-ruling in the SIA (§2, EP4)
  and the threat model (A18, §7's delta note): a narrowing, not a widening.
- **The no-PKCE interception threat's compensating-control statement simplifies.**
  The secret is always sent — the control is inherent (client authentication is
  on in every mode), not mode-conditional. What the toggle drops is the challenge
  binding alone; RES-24 and DT-EP5-3 are re-worded accordingly, and the residue
  (secret-holder on a plain-http front door) keeps its re-open trigger
  (TLS-fronting the public origin).
- **RES-19 re-prices.** The plain-http override deployments carry the client
  secret on that leg on every token request, both toggle positions — a wider
  exposure than the refresh token alone, no longer mode-conditional; the
  external-TLS shape remains the narrowing case.
- **The impact level stays High.** The ruling widens an already-priced class (the
  client secret) to every deployment and removes a weaker exposure class; it adds
  no new entry point, no new grant type, and no new integrity input — so the
  security review gate's depth stays full.
- **The vocabulary boundary (D14) is kept.** The SIA, the delta spec, and the
  release notes stay provider-neutral (class vocabulary only); the ruling's
  concrete portal-toggle name and the registration shape live in the Class B
  zones (D9, the Context record, this note). Mechanism sections use family
  anaphora ("the tested tenant") only.

## Never-cut 2's boundary, re-verified

The invariant — the **upstream** PKCE verifier never leaves Core — is unaffected
by the amendment, re-verified this round on both the spec surface and the code
surface. Spec: the delta spec's amendments touch the identity leg and its client
shape only; the client-facing AS surface's PKCE-required scenario is unchanged,
and no requirement or scenario touches the upstream leg's verifier (Core's, per
toolset, nulled on every public projection). Code: the amendment's entire
implementation surface (the re-opened tasks 4.1/4.2) is `gateway/settings.py`,
`gateway/idp.py` (`_client_authentication()`, the redirect/exchange/refresh
construction), the mode tests, and the provisioning helper's client registration
— the upstream authorize construction and the credential call
(`gateway/federation.py`'s `upstream_authorization`/`complete_upstream_leg` and
their settings sources) are in no task row's file list, and the code as built
confirms the two legs are disjoint (task 4.3's recorded check stands; the next
round re-runs it on its own diff). What the toggle varies is the gateway's own
PKCE on the identity leg only — a different binding on a different leg.

## What this round did NOT do

No implementation code, compose file, `.env.example`, operator doc, probe, or
test was touched — those are the next round's, prescribed by the re-opened tasks
4.1/4.2 (and their local-deployment knock-on). No commit was made. The
never-cut-2 check and the gates (task group 6) re-run on the next round's diff.

## Validation this round

- `openspec validate generalized-idp-federation` — **valid** (exit 0).
- `python scripts/check_publication_leaks.py` — **PASS** (219 tracked files
  scanned; 3 findings, all pre-existing and waived — two in
  `docs/evidence/d0a/review-round-1.md`, one in `scripts/import_background.py`;
  0 unwaived).
