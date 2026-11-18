# Finding — the interstitial's Continue button lands on a parameter-less upstream URL

**Status:** diagnosed, not fixed. Reproduced live on the composed stack, with controls.
The user's stored upstream credential stays **absent** (no consent was completed here; the
owner re-consents after the fix).

**Symptom.** After an ops sign-out of the `notion` toolset, a real-harness re-login ran
correctly up to the gateway's attribution interstitial. Pressing its **Continue** button
took the browser to:

```
https://mcp.notion.com/authorize?
```

— the toolset's authorization endpoint with **no query parameters at all** (no
`client_id`, no `redirect_uri`, no `code_challenge`, no `state`). Notion answered
`{"error":"invalid_request","error_description":"client_id is required"}`. The flow's own
`state` was absent too, so the round-trip the upstream callback depends on could never
have happened.

Note the shape of the failure: it is **not** an empty page or a gateway error — the
gateway's HTML was correct, the browser was sent to the right host, and every parameter
was silently dropped in transit. That is why nothing failed loudly first.

## Verdict

**The gateway builds the upstream URL correctly. The interstitial's HTML form destroys its
query string when the browser submits it, because a `method="get"` form with no
successful form controls replaces the action URL's query with the empty entry list.**
A real browser then navigates to `…/authorize?` and the upstream rejects it.

This is a **browser-mechanics defect in the interstitial template**, not a settings-read
or URL-builder defect. The unit test is green — it asserts on the page's `action`
attribute text — and was structurally incapable of catching it. The group-6 smoke never
reached the interstitial at all (the user was signed in, so the flow short-circuited).

## Evidence

### 1. The post-signout settings projection is complete — hypothesis (1) is falsified

Read live as the test user in the current post-sign-out state, both routes, token minted
immediately before use (`GET /v1/toolsets/platform/notion` and `GET /openai/toolsets/notion`):

| member | settings route | status route |
|---|---|---|
| `client_id` | present `Ohk3BbaVnj3lemIy` | present (same) |
| `authorization_endpoint` | present `https://mcp.notion.com/authorize` | present (same) |
| `redirect_uri` | present `http://localhost:8765/callback` | present (same) |
| `code_challenge` | present `mNP5WzNVunZyuJG9r0Lb9KuTzs51FhhBRoGi0yCyWM8` | present (same) |
| `code_challenge_method` | present `S256` | present (same) |
| `scopes_supported` | present `["default"]` | present (same) |
| `dynamically_registered` | present `true` | present (same) |
| `code_verifier` / `client_secret` | **absent** (as required) | **absent** |
| `user_level_auth_status` | absent | present `SIGNED_OUT` |
| `global_auth_status` | absent | present `SIGNED_OUT` |

Neither route returns an empty or redacted `auth_settings` — both carry every field the
upstream URL builder consumes. So the D-7 content-decided read is not implicated: the
settings route answered with the statuses absent, the flow fell back to the listing route
exactly as designed, and the `ToolsetSettings` object was complete either way.

**Negative control (run first):** the same read with no token → `GET /v1/toolsets/platform/notion`
→ **HTTP 401**. The instrument reports refusal correctly, so the 200s above mean something.

### 2. The gateway's interstitial is served correctly, with all seven parameters

Driving the flow live (discovery → `/dial/authorize` → the realm's login form → the
gateway's callback) in the signed-out state reaches the interstitial. The page the
gateway served at `GET /dial/callback/keycloak` (redacted capture, `state` shortened):

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Continue to notion</title>
…
<body>
<h1>Connecting notion to DIAL</h1>
<p class="note">You asked <strong>group6-smoke</strong> to use the DIAL toolset …
<p>Continuing to the approval page&hellip;</p>
<form method="get" action="https://mcp.notion.com/authorize?response_type=code&amp;client_id=Ohk3BbaVnj3lemIy&amp;redirect_uri=http%3A%2F%2Flocalhost%3A8765%2Fcallback&amp;code_challenge=mNP5WzNVunZyuJG9r0Lb9KuTzs51FhhBRoGi0yCyWM8&amp;code_challenge_method=S256&amp;state=LkZldIae…&amp;scope=default" id="continue">
<button type="submit">Continue</button>
</form>
</body>
</html>
```

The `action` attribute carries **all seven** parameters — `response_type`, `client_id`,
`redirect_uri`, `code_challenge`, `code_challenge_method`, `state`, `scope`. The URL
builder (`gateway/flow.py:upstream_authorization`) is correct; the HTML escaping of `&`
to `&amp;` is correct HTML. The parameters exist in the page. They simply never reach the
browser's address bar.

### 3. Reproduction in a real browser — the parameters are dropped on submit

The captured interstitial was served from a local origin and driven in headless Chrome
(Chrome/155) over CDP; the page's own Continue button was clicked as a user would:

```
=== the real interstitial, submitted by a click ===
  page served  http://127.0.0.1:8899/index.html   (the captured page verbatim)
  click        document.querySelector('form button').click()
  FINAL_URL:   https://mcp.notion.com/authorize?
  requests:    …/index.html
               https://mcp.notion.com/authorize?        <-- reached the upstream, EMPTY
               https://mcp.notion.com/favicon.ico
```

This is the field symptom exactly, byte for byte: the host is right, the path is right,
the query is empty.

### 4. Controls — the instrument can distinguish, and the mechanism is isolated

Four minimal pages, each submitted the same way in the same browser:

| page | form shape | resulting URL |
|---|---|---|
| **a** | `method=get`, action carries a query, **no controls** | `https://mcp.notion.com/authorize?` — **params dropped** |
| **b** | action carries a query, one hidden control `marker=1` | `https://mcp.notion.com/authorize?marker=1` — **query replaced by the entry list** |
| **c** | action has **no** query, three hidden controls | `https://mcp.notion.com/authorize?response_type=code&client_id=ABC&state=XYZ` — **works** |
| **d** | action carries a query, **two** hidden controls | `…?response_type=code&client_id=ABC` — action's own params gone, controls kept |

Controls (a) and (d) together are the proof: the browser does not *append* the form's
entry list to the action's query, it **replaces** it. With zero successful controls the
replacement is empty, which is the field failure. Control (b) shows that a form with even
one control keeps its own control and loses the action's parameters, so "the form
mechanism" is not fixed by merely having a control present. Control (c) shows the same
probe reports a complete, correct URL when the parameters arrive by another route — so a
red verdict from this instrument is meaningful, not an artifact.

This is the HTML Standard's form-submission rule for `method=get`: the action URL's query
is *mutated* — set to the entry-constructed list — rather than preserved. The gateway's
template has an action with a query and **no** form controls, so the mutation replaces a
full query with nothing.

### 5. Why nothing failed loudly first

* The gateway emitted a page whose *text* is correct; a human reading the HTML, or a test
  asserting on the `action` attribute, sees a complete URL.
* The gateway cannot observe the browser's submission — the parameters are dropped inside
  the browser, after the gateway's response is complete. There is no server-side seam at
  which the loss is visible.
* The failure surfaces to the *upstream*, which answers an OAuth error document
  (`invalid_request`) rather than a page the gateway renders.

## Root cause

Exact chain:

1. The flow reaches `complete_identity_leg` in the signed-out state and reads the toolset
   settings; both Core routes return complete `auth_settings`; the status route answers
   `SIGNED_OUT`, so no short-circuit and the upstream leg is built.
2. `upstream_authorization` (`gateway/flow.py`) builds `UpstreamAuthorization.url` with all
   seven parameters — **correct**.
3. `interstitial_page` interpolates that URL into the template as the `action` of
   `<form method="get" … id="continue">` **and places no successful form controls inside
   the form** (`gateway/flow.py`, the `_INTERSTITIAL` template: a bare
   `<button type="submit">Continue</button>`).
4. The browser submits the form. Per the HTML Standard's get-method submission rule, the
   action URL's query component is **replaced** by the query built from the form's entry
   list. With no successful controls that list is empty, so the browser navigates to the
   path with a **bare `?`**.
5. Every parameter — including the flow's own `state` — is lost in the browser. The
   upstream rejects the request as `invalid_request` (`client_id is required`), and the
   flow cannot continue: the callback will never arrive, so the credential is never
   established.

Why the tests were green: `tests/test_federation.py::test_the_upstream_url_is_built_from_cores_public_settings`
extracts the `action` attribute out of the served HTML and parses *that* string. It
asserts on the template's output, never on the URL a browser would actually reach. The
whole interstitial class of behaviour — "does the browser arrive at the upstream with these
parameters?" — has no test, because the test client does not submit forms. Verified green
on the current tree: `4 passed` (`-k "interstitial or upstream_url"`).

Why the field never saw it before: the group-6 end-to-end smoke
(`scripts/probe_end_to_end.py`) ran against a user who **already held** a stored
credential, so `complete_identity_leg` short-circuited at the signed-in branch and the
interstitial was never rendered. The interstitial path had, in effect, never been executed
live until this field report.

## Proposed fix (not implemented)

Two layers, and the first is the actual defect.

**(a) The interstitial must deliver its parameters — the real fix.** The template must not
rely on the action attribute's query surviving a form submission. Any of:

* Put the parameters in the form as **hidden inputs** and leave the action as the bare
  endpoint (control (c) proves this works) — the most conservative change, since the
  interstitial stays a form and the button stays a button; or
* Make the Continue control an ordinary **anchor** (`<a href="{continue_url}">`), which
  navigates to the URL exactly as written; or
* Have the interstitial **continue itself** (a `location.replace`/meta refresh on the
  built URL).

Worth noting for whoever picks this up: `interstitial_page`'s docstring already says *"The
page continues itself: it is a step the user cannot act on, and stopping there would turn
an attribution notice into a second consent the user has to give"* — but the implementation
puts a manual **Continue** button in front of the user, contradicting its own stated
design. The intended auto-continue, built the obvious way, would not have had this bug. So
the fix should also reconcile the template with the docstring's stated behaviour.

**(b) Fail loudly where the gateway cannot guarantee a complete upstream request.** The
existing settings-read refusal (`gateway/core.py:read_toolset_settings`, the `missing`
list) already refuses an *incomplete projection* loudly before any upstream round-trip —
that layer is sound and is not implicated here. What has no guard is the step *after* the
URL is built: nothing asserts that the URL the browser will actually reach carries the
required parameters. A cheap, testable guard is a browser-shaped test (submit the page and
assert the resulting URL), which is the instrument this finding had to build by hand.

**(c) A regression test that can fail.** A test that renders the interstitial and checks
the `action` attribute is exactly the test that stayed green through this defect. The
replacement must assert on the URL a *form submission* produces (or, if the anchor/
auto-continue form is chosen, on the href/navigation target), not on the attribute text.

## Spec-gate verdict

**No — the delta spec does not pin the upstream authorization redirect's parameters, and
an authoring ripple is required.**

The requirement that governs this leg is `specs/mcp-signin/spec.md`, "The federation flow
establishes the upstream credential through Core", whose normative text is:

> The flow MUST authenticate the user under the gateway's public PKCE client, requesting
> only its client's default scopes; a client's `scope` parameter is never relayed — a
> relayed scope can fail the leg. DIAL authorization is enforced by fetching the toolset
> settings as that user before any upstream round-trip; the upstream code goes to Core's
> credential API at USER level. The flow record MUST be destroyed on first use at the
> upstream callback; the provider's tokens are discarded at flow end.

It pins the **identity-provider** leg's scopes, the authorization check, the credential
call's level, and the callback's destroy-on-first-use. It says nothing about the upstream
authorize URL's parameters. Its scenarios are about what happens *after* approval
("Upstream consent completes" starts at "**WHEN** the user approves the upstream
consent"), about destroy-on-first-use, and about a guessed flow id — none of which is
reachable if the consent screen is never validly reached.

The nearest adjacent statements, and why each falls short:

* `"Flow state lives server-side; the browser carries only the flow id."` — stated for the
  **authorization-request** requirement (flow allocation), not for the upstream redirect.
  It is suggestive that the flow id must travel in the browser, and the upstream callback's
  state round-trip depends on it, but the spec never says the upstream *redirect* must
  carry it as `state`.
* `"…failures fail closed"` (credential-model invariants) — a general invariant, with no
  scenario that covers "the upstream authorization request could not be delivered."
* Acceptance criterion (a), *"first use end to end via CIMD and `resource`"* — this defect
  genuinely falsifies it, but the criterion is a completion gate on the assembled chain,
  not a requirement pinning the redirect's parameters.

So there is a real normative gap: **nothing in the spec states that the upstream
authorization request must reach the upstream endpoint carrying `client_id`,
`redirect_uri`, `code_challenge`, `code_challenge_method`, and the flow id as `state`** —
and nothing states where the failure belongs when it cannot. The gap is exactly what
allowed a green test suite, a green smoke, and a shipped defect.

The ripple should add to the federation-flow requirement (wording for the author, not
fixed here):

1. that the upstream authorization request carries `response_type`, `client_id`,
   `redirect_uri`, the toolset's `code_challenge`/`code_challenge_method`, and the flow id
   as `state`;
2. a scenario stated in terms of **what the upstream endpoint receives**, not what the
   rendered page contains — a page whose text carries the parameters but whose submission
   does not is precisely the failure mode that shipped;
3. that the interstitial delivers the request without requiring any parameter to survive
   anything a browser does to it (or, if the author prefers, that the interstitial
   navigates rather than submits), so the requirement is falsifiable by a browser-shaped
   test;
4. optionally, that a failure to deliver a complete request fails closed with the
   plain-language page rather than an upstream error document.

`openspec validate --changes --strict` should be re-run after the edit.

## Instrumentation, and state restored

Temporary instrumentation was added for this diagnosis and **removed afterwards**:

* two throwaway probe scripts under `scripts/` (a settings-projection reader and an
  interstitial-driving reproducer) — deleted;
* the captured interstitial page written under `.secrets/` (gitignored) — deleted;
* a scratch workspace outside the repository holding the control pages, the local static
  server, the CDP driver, and a headless Chrome profile — deleted, and the headless Chrome
  killed.

No gateway source, spec, test, or configuration was changed. The user's stored upstream
credential was **not** re-established — it stays absent (`user_level_auth_status =
SIGNED_OUT`, `global_auth_status = SIGNED_OUT`, re-measured after the reproducer ran), so
the owner can re-consent once the fix lands.

## Spec ripple (authoring pass)

The authoring ripple this finding called for is landed — specs and design only; the
template fix is the next implementation pass, not done here.

- **Delta spec** (`specs/mcp-signin/spec.md`): a new ADDED requirement, **"The upstream
  authorization request arrives complete"**, placed after the federation-flow
  requirement it ripples. The upstream authorization request MUST reach the upstream
  authorization endpoint carrying `response_type=code`, the registered `client_id`, the
  toolset's public `code_challenge` and `code_challenge_method`, the upstream
  `redirect_uri`, the flow id as `state`, and the toolset's advertised scopes — stated
  as **what the endpoint receives**, never what a rendered page contains, because the
  delivery mechanism is the gateway's choice; a mechanism whose browser step can drop
  parameters MUST NOT be used. Two scenarios: **"Continuation delivers every
  parameter"** — WHEN the user continues from the interstitial, THEN the URL the browser
  navigates to carries every stated parameter (the submission-level assertion this
  finding's §4 controls make falsifiable, not the attribute-level one that stayed
  green); and **"Undeliverable request fails closed"** — the plain-language error page,
  no parameter-less request reaches the upstream. Requirement text 494 chars, within
  the budget.
- **design.md**: a new **D12 — "The interstitial delivers the upstream request; it never
  relies on the browser preserving a URL"** — recording the get-form query-replacement
  root cause as behavior and reason (the submission replaces the action URL's query
  with the successful controls' entry list; the loss happens inside the browser where
  no server-side seam sees it; that is also why an attribute-level test is structurally
  blind to the class), the two acceptable mechanisms (hidden inputs + bare action, or
  the page continuing itself — the implementation pass chooses), the reconciliation
  with the page's stated auto-continue behavior (the manual Continue button is as
  rejected as the query-bearing action), the rejected mechanism on record, and the
  fail-closed rule (the settings-read refusal guards before the URL is built; the
  delivery guard covers the step after it). Plus a traceability row for the new
  requirement in the requirement-traceability table.
- **tasks.md**: a new **task 4.8** in group 4 — fix `_INTERSTITIAL`/`interstitial_page`
  per D12; the regression test MUST assert on the URL a form submission or navigation
  produces (naming the stayed-green attribute-level assertion as the anti-pattern),
  plus the fail-closed branch test and the live signed-out re-run to the interstitial
  verifying the submitted URL. The task notes that `evidence/group-4.md`'s test-summary
  row for `tests/test_federation.py` goes stale on the mechanism detail once the fix
  lands.
- **Left for the next pass**: the template fix itself, both tests, and the live re-run;
  no gateway source changed in this pass, so the user's stored upstream credential stays
  absent for the owner's post-fix re-consent.

`openspec validate --changes --strict` was re-run green after these edits.