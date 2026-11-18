# Authoring round 3 — the vocabulary-boundary change request (2026-11-04)

Author: the design author (this pass). This note is a new file rather than an append
to `owner-round-2.md` so each round's record stays independently referenceable; the
prior evidence files (`owner-round-2.md`, `review-round-1.md`, `review-round-2.md`)
are historical records and were deliberately not re-worded — they quote the text as
it stood when they were written.

## The owner's request

> I agree with the exact-match principle for the issuer (D6). But I don't want B2C
> vocabulary (e.g. "policies") present in the spec or, worse, in the implementation.
> B2C is an example — we don't do anything B2C-specific, including in the normative
> spec text. Re-formulate.

The directive fixes the outcome — the exact-string issuer pin stays; the tested
provider's product vocabulary leaves the normative spec and the implementation
surface — and the author decided how it is expressed and where the boundary sits.

## The boundary ruling (design.md D14)

Two classes, stated as a checkable rule:

- **Class A — provider-neutral surfaces, zero product vocabulary.** The delta spec
  (all of it: requirement text, scenarios, amendment notes); the release-notes draft
  (both audiences); and every implementation-facing artifact and prescription —
  settings names, code identifiers, route spellings, error text, and the
  operator-facing documentation content the tasks prescribe. These name provider
  classes and mechanisms only. The class vocabulary coined this round and used
  consistently: a **varying-issuer provider** (issuers that vary across the
  provider's sign-in journeys or tenants); a **sign-in journey** (the provider-side
  configuration path that issues tokens — the neutral term for the tested family's
  "policy"/"user flow"); the **one federated journey's issuer** (what the pin
  holds); **journey-distinct issuance** (the provider-side property that makes the
  pin distinguish journeys). Generic "session policy" is not the product concept and
  stays. The D6 mechanism reads, in the owner's own framing: the gateway pins the
  one configured issuer as an exact string, and a token whose issuer differs in any
  way is refused — varying-issuer providers are the general class the pin covers,
  and the tested family merely instantiates that class.
- **Class B — working artifacts, the tested provider named for its own facts only.**
  The design's tested-case record (Context paragraph + D9), the live-run open
  questions (OQ-A, OQ-B), the tasks' live-run rows (7.1, 7.2), the evidence records,
  and the proposal's tested-case identification (its mechanism bullets stay Class A).
  These keep the family's names, flavors, URL grammar (`tfp`, the login hosts, the
  `<tenant>.onmicrosoft.com` paths), and portal settings, because they record
  operational facts about the tested deployment that generic wording cannot state
  without losing their content. Mechanism statements inside Class B zones still use
  Class A vocabulary.

Where the provider-specific operator facts live now (the F3 question this round
forced): the operator reference (task 5.1) states the prerequisite generically — a
varying-issuer provider must be configured for journey-distinct issuance, or its
journeys' tokens share one `iss` no issuer check can distinguish — which is the
honest content for every provider of the class; the tested family's concrete
property name ("Issuer (iss) claim", off by default) and its default-off state live
in the Context/D9 record and the live-run row (task 7.1 verifies with it enabled
and records the portal path). F3's diagnosability rationale survives in generic
form: an operator of any varying-issuer provider who sees every sign-in fail at
issuer verification finds the stated prerequisite in the reference.

The D8 boundary (the local development instance's own Keycloak name and the
helper-scoped `KEYCLOAK_*` settings) is a different, pre-existing boundary and is
untouched: the release notes' remaining Keycloak hits are the rename's own objects
(`KEYCLOAK_*` → `IDP_*`, `/dial/callback/keycloak` → `/dial/callback/idp`, the
local-dev helper's admin settings), not external-provider vocabulary.

## The sweep — patterns, hits, dispositions

Patterns grepped over the whole change folder (case-insensitive): `b2c`, `entra`,
`microsoft`, `azure`, `tfp`, `ciamlogin`, `b2clogin`, `onmicrosoft`, `fabrikam`,
`external id`, `customer-identity`, `polic(y|ies)`, `user flow`, `sibling(-)policy`,
`sign-in policy`, `per-policy`, `tenant`. Every hit found was dispositioned per the
boundary; the post-edit audit re-ran the same patterns.

### specs/mcp-signin/spec.md — 4 re-words, now zero-hit

1. Verification requirement's pinning sentence: "a provider whose issuers vary by
   policy — the issuer embedding the policy or user flow that issued the token — has
   the sign-in policy's issuer configured, and a token from any other issuer,
   another policy of the same tenant included" → "a provider whose issuers vary
   across its sign-in journeys — the issuer embedding the journey that issued the
   token — has the one federated journey's issuer configured, and a token whose
   issuer differs in any way — another journey's issuer of the same provider
   included".
2. The declared amendment note: "the per-policy issuer-pinning sentence … per-policy
   issuer variation is the tested provider family's shape … whether a sibling
   policy's tokens carry a distinct issuer … policy-distinct issuers for sibling
   policies" → the varying-issuer pinning sentence; "issuers that vary across a
   provider's sign-in journeys are the shape that sentence covers" (the
   "tested provider family" provenance phrase also left the spec); "whether another
   journey's tokens carry a distinct issuer … journey-distinct issuers for its
   journeys". The R2-4-dispositioned key-set clause quote is untouched.
3. Scenario "A token from another policy's issuer refused" → "A token from another
   journey's issuer refused" (WHEN: "vary by sign-in journey … another journey of
   the same provider included"; THEN: "the configured issuer is the one this
   deployment federates, and no other journey's token is accepted by it").
4. Scenario "One hostname, no override": "the customer-identity tenant shape" →
   "the common external-provider shape".
   Post-edit grep: the only "polic*" left in the delta spec is generic "session
   policy" (the refresh requirement, unchanged) — ruled not product vocabulary.

### release-notes-draft.md — 4 re-words; family vocabulary now zero

1. Users: "an Entra B2C / External ID tenant (the tested case — per-policy issuers
   and custom claims included)" → "a provider with journey-varying issuers and a
   custom claims vocabulary — the tested case —".
2. Users: "For a classic B2C tenant, the sign-in policy's per-policy issuer setting
   ('Issuer (iss) claim') must be enabled" → "For a provider whose issuers vary by
   sign-in journey, the provider must be configured to issue the federated journey
   its own distinct issuer".
3. Team: "per-policy issuers are pinned exactly (a sibling policy's token is
   refused)" → "journey-varying issuers are pinned exactly (another journey's token
   is refused)".
4. Team: "The live Entra B2C acceptance run … every artifact carries
   `<tenant>`/`<policy>` placeholders" → "The live acceptance run against the tested
   external provider … the change's working artifacts carry the placeholders".
   Remaining hits: D8-scoped Keycloak rename objects only (kept, per the boundary).

### proposal.md — 6 re-words; the family name kept only as Class B tested-case identification

1. Why: the mechanism half of the tested-case clause re-worded ("per-policy issuers
   and a custom-claims vocabulary" → "issuers vary by sign-in journey … claims
   vocabulary is custom"); the family named once, with a Context pointer.
2. Back-channel bullet: "(the B2C/External ID shape)" → "the single-origin
   external-provider shape".
3. The pinning bullet: "**Per-policy issuers are pinned exactly.** … the sign-in
   policy's issuer … another policy of the same tenant … `{tenantid}`-style
   templating" → "**Varying issuers are pinned exactly.** … the one issuer this
   deployment federates … a token whose issuer differs in any way — another
   journey's issuer of the same provider included … no pattern, prefix, or
   templated issuer matching".
4. The tested-case bullet: kept as the family identification (Class B), with the
   placeholder statement scoped to the working artifacts and a D14 pointer added.
5. Impact, docs row: "B2C/External ID configuration guidance with placeholders" →
   "provider-neutral guidance for varying-issuer external providers; the tested
   family's concrete values arrive with the live run and are recorded in its
   evidence, not in the operator reference (design.md D14)".
6. Impact, tests row: "per-policy issuer pinning" → "journey-varying issuer
   pinning".

### design.md — mechanism statements re-worded; the tested-case record kept; D14 added

Re-worded (Class A treatment): Context's framing and closing-placeholder sentences
(placeholders scoped to working artifacts, D14 pointer); Goals' tested-case bullet
(family-flavor reference instead of "classic B2C per-policy issuer or External ID
per-tenant issuer"); Non-Goals ("No live B2C run" → "No live run against the tested
provider"); D1 (the per-provider spelling examples compressed to "the local
instance does; the tested family's flavors … (Context, D9)"; "adding an Entra
table … the B2C table still wrong the day Microsoft moves a segment" → "a table for
the tested family … the day that vendor moves a segment"); D2 ("the B2C/External ID
shape" → "the single-origin external-provider shape"); D4 ("cannot wait on
Microsoft" → "cannot wait on an external internet provider"); **D6 re-titled and
re-written** ("Per-policy issuers" → "Varying-issuer providers"; the two concrete
issuer spellings moved out to Context/D9; "the policy's per-policy 'Issuer (iss)
claim' token-compatibility setting" → "an opt-in per-journey token-compatibility
setting, off by default (verified, Context)", with the live run verifying the
family's concrete setting; "sibling policy" → "sibling journey"; rejected list:
"Entra's `{tenantid}`" → "the tested vendor's `{tenantid}`"); D8 ("the B2C tenant …
created in the Entra portal" → "the tested external tenant … created in the
provider's own admin portal"); D9's framing and task-5.1 reference (the record
itself kept); D10 ("scope- and policy-filtered — fixed on Entra, custom-policy-only
on B2C" → "scope- and provider-configuration-filtered — fixed on one flavor of the
tested family, reachable only through custom journeys on the other"); D11 (both
b2clogin/tfp passages → "the tested family's classic flavor … the
per-journey-issuer-appended path"; the concrete `<tenant>.onmicrosoft.com/{policy}`
spellings moved to OQ-A, D11 keeps the neutral statement with a pointer); D12
("Entra's `{tenantid}` templating" → "the tested vendor's `{tenantid}` templating");
SIA §1 (business description: "a per-policy issuer (the B2C shape)" → the
varying-issuer class statement; the tested case now "the external
customer-identity family's tenant (either flavor — Context, D9)"); SIA §3 invariant
row 3; SIA §4's EP5 row (retitled "varying-issuer providers"; threat renamed
"Another journey's token accepted by a relaxed issuer match"; "classic B2C's
per-policy 'Issuer (iss) claim' setting … tenant-wide default" → "in the tested
family an opt-in per-journey token setting … family-wide default"); SIA §5 DT-EP5-5
(title + controls 3 and 8) and DT-EP5-7 control 1 ("the B2C shape needs none" →
"the single-origin external-provider shape needs none"); SIA §6 item 4 ("the
per-policy scenario … sibling policies refused" → "the varying-issuer scenario …
other journeys' tokens refused"); SIA §7 ("sibling-policy issuer confusion" → "the
other-journey issuer confusion"); Risks' pinning row; Migration step 6.

Kept as Class B: the Context provider-facts paragraph (the verified and
live-run-to-verify record — the canonical home of the family's names, URL grammar,
and the "Issuer (iss) claim" property); D9's body (the tested-case record, now
declared as such in its opening); OQ-A/OQ-B/OQ-E (live-run questions); D14's own
rule text, which must name the vocabulary it forbids.

**New decision D14** records the boundary, the class vocabulary, where the
provider-specific operator facts live, and the grep check.

### tasks.md — implementation prescriptions all neutral; the live-run rows Class B

Re-worded: 1.1 ("sibling-policy issuer confusion" → "the other-journey issuer
confusion (varying-issuer providers, DT-EP5-5)" — it prescribes threat-model
content); 3.3 ("per-policy issuer-pinning tests … a sibling policy's issuer of the
same tenant" → "varying-issuer pinning tests … another journey's issuer of the same
provider"); 3.4 ("the per-policy issuer refusal holds in direct mode" → "the
varying-issuer refusal holds in direct mode"); **5.1 re-written** — the operator
reference now carries provider-class guidance only: the varying-issuer
external-provider profile, the generic journey-distinct-issuance prerequisite row
(with the family's concrete property delegated to design.md D9 and task 7.1), the
direct-mode trigger "the tested family's classic flavor included should its
per-journey-path discovery fact fail (design.md D9)", and the D14 boundary named as
the row's own rule; 5.2 ("the B2C-with-placeholders configuration sketch" → "the
external-provider configuration sketch in provider-neutral terms (design.md D14)");
6.1 (the placeholder statement scoped, D14 pointer added).

Kept/re-anchored: 7.1 (the live-run row — Class B; keeps b2clogin/tfp/`<tenant>.onmicrosoft.com/{policy}`
and now cites the "Issuer (iss) claim" property from design.md D9/Context, since
5.1's row is generic now); 7.2 ("fronting the B2C tenant" → "fronting the tested
external tenant").

### evidence/ — kept

`owner-round-2.md`, `review-round-1.md`, `review-round-2.md` name the family
throughout; they are historical records quoting the text as it stood and are the
boundary's evidence class. This file is the new record.

## Post-edit audit (the D14 check, re-run)

- **Delta spec:** zero hits for every pattern above (including `tenant`,
  `keycloak`, and all product-concept words). The only "polic*" occurrences are
  generic "session policy".
- **Release notes:** zero tested-family hits; remaining `Keycloak` hits are the
  D8-scoped rename objects.
- **Whole change folder:** every remaining hit sits in an enumerated Class B zone —
  design.md's Context paragraph, D9, OQ-A/OQ-B/OQ-E, D14's own rule text, task 7.1,
  the proposal's tested-case identification (Why + the tested-case bullet), and
  `evidence/` — or is a D8-scoped local-instance fact.
- **No task prescribes provider-named identifiers for implementation:** the
  settings trio (`IDP_*`), the callback route, the test names (3.3/3.4), and the
  operator-docs content (5.1/5.2) are all provider-neutral; the only product-named
  prescriptions left are inside the live-run row 7.1 — configuring the owner's real
  tenant, a deployment fact, not an implementation surface — and pointers from
  5.1/6.1 to the D9 record.

## Coherence with rounds 1–2

- **F3 survives, re-homed.** The verified vs live-run-to-verify separation is
  intact (Context, D1, D9, OQ-A, task 7.1); the per-journey issuer setting is now
  formally a provider fact whose canonical homes are Context/D9 and task 7.1, with
  the operator reference carrying the generic prerequisite — the diagnosability
  rationale preserved in generic form. The delta scenario still conditions on
  issuers varying, so its normative content is unchanged.
- **F1/F2 survive.** The threat-model scoping rule and the §10 compromise-point
  delta are untouched in substance; task 1.1's threat-row name is now neutral,
  matching DT-EP5-5's re-worded name, so the task and the SIA stay in lockstep.
- **F4–F8 and R2-1–R2-5 survive** — the re-wording passed through the affected
  clauses only where the product vocabulary was; the R2-4 qualifier-seated key-set
  wording and the R2-2 anchor-rationale scenario are unchanged.
- **D11–D13 are untouched in mechanism**; only their tested-family examples were
  neutralized or pointed at the Class B record.

## Validation this round

- `openspec validate generalized-idp-federation` — **valid** (exit 0).
- `python scripts/check_publication_leaks.py` — **PASS** (202 tracked files
  scanned; 3 findings, all pre-existing and waived, 0 unwaived).
