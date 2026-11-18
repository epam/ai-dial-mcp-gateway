# Finding — identity-token presentation count vs the "at most twice" rule

**Symptom.** On this deployment (Core build whose settings route does not enrich the
per-caller statuses), the flow presents the user's identity token to Core **three**
times: the settings read, the listing-route status fallback, and `/v1/ops/toolset/signin`.
`design.md`'s stated rule is "the identity token used at most twice" (and the token
lifecycle rule it derives from). The group-4 implementation restated the rule inside
`gateway/core.py` ("one step with one credential and one purpose"), but `design.md` and
the `gateway/core.py` module docstring still carry the original letter — three documents,
three units (presentations / purposes / presentations).

**Evidence.** `evidence/spike.md` finding 1 (settings route omits
`user_level_auth_status`); `gateway/core.py` `read_toolset_for_flow` (content-decided
fallback: settings first, listing only when statuses absent); `design.md` security
impact analysis ("used at most twice"); `gateway/core.py` module docstring ("used at
most twice", pre-D-7 two-route model). Core source: `ToolSetController.getToolSet`
(`GET /openai/toolsets/{name}`) calls `deploymentService.findDeployment`, which throws
`PermissionDeniedException` (→ 403) on `!hasReadAccess` — and returns the same settings
fields **plus** the statuses.

**Root cause.** The design's token-use rule was written against the background design's
assumption that one route (settings) serves the whole step. The spike's route finding
broke that assumption; the D-7 fix restored function but accepted an extra presentation
on non-enriching builds without revisiting the rule's letter — and the code docstrings
split between the old and restated units.

**Proposed fix (author's decision, not implementation improvisation).** Choose
deliberately between:

1. **Restate the rule as purposes** — one decision step ("may this user sign in, and are
   they signed in?") + one action (`/signin`); on non-enriching Core builds the step is
   two presentations, on enriching builds one; update design.md and both docstrings to
   the same unit; the exposure delta (one extra internal-network presentation within the
   same flow TTL) stated in the security impact analysis.
2. **Restore the letter** — make the flow's step listing-first where the listing route
   serves settings+statuses+403 in one call (settings route only where the listing route
   does not), keeping two presentations on every build. Requires the author to rule
   which route's 403 is *the* invariant-4 authorization check (both throw
   `PermissionDeniedException` from the same authorization service, but the design has
   so far named the settings route).

Either is defensible; the defect is the three-way inconsistency, not either option.
Spec gate: the delta spec pins no route and no presentation count (it requires the
settings fetch as the user before any upstream round-trip and the short-circuit) —
so no spec delta is expected either way; the author should confirm.

**Owner note (2026-10-19).** In theory the gateway could pin the latest Core and
support only the enriched settings route (upgrading the local instance), but the owner
is not making that change before the PoC ends. Consequences for the author's decision:
the dual-API (content-decided) tolerance **stays for this change**; a Core upgrade is
**not** an available remedy inside this change; both proposed fixes must work on the
current local build. The pin-latest simplification is a post-PoC consideration and
should be recorded as such (an open question or the HA/future-work note), not silently
dropped.

## Resolution (author, 2026-10-19)

**Option 1 confirmed — the rule is stated in purposes, not counts.** The shipped
content-decided fallback stays (it is the dual-API tolerance the owner ruled stays for
this change); option 2 was rejected because it would reorder the flow's reads around a
build-specific route and re-rule the invariant-4 authorization check from the settings
route to the listing route — a behavior change bought to keep a count the count's
owner (the deployment's Core) sets anyway. The unit: the identity token serves the
sign-in flow's one decision step ("may this user sign in, and are they signed in?") and
one action (the credential call), never anything else; on enriching builds the step is
one presentation, on non-enriching builds two (settings read + listing fallback), plus
the credential call's own.

Aligned to that unit: `design.md` (the never-store rule in the memory-zeroization
paragraph, plus a purposes-not-counts paragraph stating the exposure delta — one extra
internal-network presentation to Core within the same flow TTL on non-enriching builds
— and open question 7 recording pin-latest as the post-PoC simplification that collapses
the step to one presentation), the `gateway/core.py` module docstring, the
`read_toolset_for_flow` docstring, and `docs/gateway-configuration.md`'s flow section.
**No spec ripple:** the delta spec pins no route order beyond requiring the settings
fetch as the user before any upstream round-trip (which the shipped fallback keeps) and
no presentation count.
