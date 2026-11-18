# Review gate (8.5) — findings and dispositions

The general review gate's record: `evidence/review-gate-findings.md` (the reviewer's,
unedited here). Verdict: **PASS — 0 blocking, 2 should-fix, 5 notes.** The reviewer
re-ran the full suite fresh (not trusting the evidence files) and walked all 92 delta
scenarios against code and tests; the gate-ordering, atomicity, race-closure, and
partial-property claims were verified and held.

## Should-fix

- **SF-1 — the pre-existing flaky custody test** (`tests/test_custody.py`
  `test_the_envelope_layout_is_version_key_id_nonce_ciphertext`): it asserted a
  one-byte token absent from a RANDOM 12-byte nonce — a ~4.6% chance failure per run
  (the known flake from the C1.5-era notes; the recorded "675 passed" runs had been
  lucky). **Disposition: FIXED** — the assertion now tests the actual property: the
  token appears in no READABLE byte (the header: version + key id); the nonce and
  ciphertext are opaque by design and are not scanned. Full suite re-run after the
  fix: **675 passed, 1 skipped** — the green is now reproducible.
- **SF-2 — `gateway/authorize.py`'s `_single_string` docstring claimed a refusal
  discipline the code does not have** (it said repeated parameters are "refused";
  the endpoint resolves last-wins — the security gate's note 3, seen here at full
  scope). **Disposition: FIXED by correcting the docstring** — it now states the
  actual behavior and its reason: this endpoint's parsing is lenient where the token
  endpoint's refuses, because every value is validated downstream (the resource, the
  PKCE challenge, the state's length bound) before it can affect anything. Enforcing
  the refusal instead would be a behavior change (a spec amendment of its own), not
  a review-gate fix; if the owner wants the refusing shape, it is a candidate for a
  future change.

## Notes

- **N3** — `scheme_admission_refusal` is scheme-deep only: hostless `https:` URIs
  are admitted (no cleartext leg, no host — harmless). Recorded, no change.
- **N4** — refreshing the decision page re-runs the identity leg and can show an
  error page while the parked record stays POST-able — the interstitial's pre-
  existing class, UX-level. Recorded, no change.
- **N5** — `tests/test_limits.py`'s cross-resource registry test is tautological
  (the registry API has no resource axis); the real property is covered behaviorally
  twice in `test_federation.py`. Recorded; the test could be removed at a future
  touch of that file.
- **N6** — the oversize-body scenario enumerates three routes; the consent route is
  a fourth, covered by the requirement's general text and the implementation but not
  the enumeration — fold at that requirement's next amendment (the archive pass
  should carry it).
- **N7** — the `state` echo is value-faithful (decode/re-encode), not
  wire-byte-faithful — the claim's exact meaning, recorded.

## The security gate (8.4), for the complete record

PASS with 0 blocking / 0 should-fix; its three notes were folded before this gate
(the DT-EP1-2 eviction wording, M31's dwell record; note 3 declined as pre-existing
surface posture) — see the gate commit and `evidence/security-gate-findings.md`.
