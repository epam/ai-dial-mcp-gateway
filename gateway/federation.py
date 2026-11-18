"""The flow's browser-facing routes: the two callbacks.

Every route here is unauthenticated — a browser arrives with nothing but a URL — so each
one's first act is to resolve the flow id it was given and refuse before doing anything
else when it names no live flow. The refusals are plain-language pages rather than OAuth
error documents: the reader is a person in a browser who cannot act on an error code, and
the action available to them (start the sign-in again from the tool) is the same whatever
went wrong.

The upstream callback is where the flow id is *consumed*. The state round-trip is checked
first, so a callback that does not carry back the id it was sent with never touches a
record; the record is then destroyed before the credential call is made, so a replayed
callback — an attacker's own upstream code paired with a victim's flow id — finds nothing
to pair with.

A flow's **refusal** consumes the record too, for the same reason a completed callback
does: the flow is over either way, so its id must not resolve again. The read refusals — a
name Core does not know, and a read the user cannot make — destroy the record and drop the
identity credential it holds, so a re-presented flow id lands on the expired page an
unknown id gets rather than re-running the leg.
"""

from __future__ import annotations

from urllib.parse import parse_qsl

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse

from gateway import errors
from gateway.core import (
    AccessDeniedError,
    AppUnknownError,
    CoreError,
    ToolsetAccessDeniedError,
    ToolsetUnknownError,
    TrustFaultError,
)
from gateway.flow import (
    AppLegResult,
    FlowError,
    ToolsetLegResult,
    UpstreamAuthorization,
    complete_identity_leg,
    complete_upstream_leg,
    core_error_response,
    decision_page,
    harness_redirect,
    identity_error_response,
    interstitial_page,
    issue_code_for_flow,
    mint_navigation_page,
    upstream_authorization,
)
from gateway.idp import IdentityProviderError
from gateway.pages import html_page
from gateway.requests import capped_body
from gateway.runtime import Runtime
from gateway.state import FlowRecord
from gateway.tokens import IssuanceError

router = APIRouter()

# The callback paths, spelled here as the routes they are. They are the same constants the
# identity-provider client's `redirect_uri` and Core's allowlist are built from —
# `Settings.idp_callback_path` and `Settings.upstream_callback_path` — and they are
# declared as literals so the route table reads as the URL map it is.
IDP_CALLBACK_ROUTE = "/dial/callback/idp"
UPSTREAM_CALLBACK_ROUTE = "/dial/callback/upstream"
CONSENT_ROUTE = "/dial/consent"

# The two action tokens the decision page's form posts. They are a closed vocabulary: the
# action is compared against these, never interpolated from a request.
_APPROVE = "approve"
_DENY = "deny"

# The reason the consent route gives when it is handed a body it cannot read as one
# decision. Fixed text, so nothing a request carried can reach the page.
_BAD_CONSENT_REQUEST = (
    "this approval request was malformed; start the sign-in again from your tool"
)

# The reason a deny action leaves the user with. It says nothing was changed and names the
# one action available, and it is a page rather than a redirect: no OAuth error goes to any
# target the client did not offer.
_ATTRIBUTION_DENIED = (
    "you declined to let this client act as you. Nothing was changed, and no sign-in code "
    "was issued. Start the sign-in again from your tool if you change your mind"
)

# The content type the consent POST's body must be sent as. The form the decision page
# renders posts with it, so a body arriving under another type is not the page's own
# submission and is refused before it is parsed.
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

# The reason a callback gives when it cannot resolve the flow it was handed. Fixed text, so
# nothing a request carried can reach the page.
_EXPIRED_FLOW_REASON = (
    "the sign-in session has expired or the sign-in was started again"
)

# The reason a callback gives when the leg reported a failure instead of returning a code.
# The leg's own error text is not relayed: it is a value from an untrusted party, and the
# user's available action is the same either way.
_LEG_REFUSED = (
    "the sign-in was not completed — the provider or the tool declined it, or you "
    "cancelled the approval"
)

# The reason a callback over the limit gives. The reader is a person in a browser, so this
# is the plain-language page and never a redirect: a rate-limited callback is not an OAuth
# error the client could correlate, and redirecting one would send the browser to a URL
# that carries a refusal the harness never asked about.
_TOO_MANY_CALLBACKS = (
    "too many sign-in attempts arrived from this source at once. Wait a moment, then "
    "start the sign-in again from your tool"
)


@router.get(IDP_CALLBACK_ROUTE, response_model=None)
async def idp_callback(request: Request) -> Response:
    """The identity provider's callback: exchange the code, then run the flow forward.

    The flow id arrives as this leg's `state`, so a callback with no live flow never
    reaches the exchange. From here the flow either short-circuits to a code — the user
    already holds a stored upstream credential, so there is nothing to approve — or
    continues through the attribution interstitial to the upstream consent.
    """
    runtime: Runtime = request.app.state.runtime
    if not runtime.limiter.allow(errors.client_source(request)):
        return errors.gateway_error_page(429, _TOO_MANY_CALLBACKS)

    try:
        record = _live_flow(runtime, request.query_params.get("state"))
    except _FlowGoneError as gone:
        return gone.page

    code = request.query_params.get("code")
    if not code or request.query_params.get("error"):
        return errors.gateway_error_page(400, _LEG_REFUSED)

    return await _run_identity_leg(runtime, record, code=code)


async def _run_identity_leg(
    runtime: Runtime, record: FlowRecord, *, code: str
) -> Response:
    """The identity leg and what follows it: a code, the interstitial, or a refusal.

    One function rather than three branches inside the route because each failure here is
    a different audience's page and the ordering that produces them is the flow's own
    concern.

    For an **app** resource the stages after the read are none: the resource is
    credential-free by construction — it carries no authentication kind and no per-app
    status in Core, and its data path runs on the caller's own identity — so there is
    nothing to short-circuit against and no kind to branch on. The flow mints the harness's
    code directly, with one fixed-vocabulary record showing the kind-driven short-circuit.
    This is C1's general rule applied, not a new mechanism: the upstream stage runs only
    when the credential is missing AND the kind makes it establishable by consent, and for
    an app the second conjunct is false by construction.

    For a **toolset** resource the stage order after the read is the routing decision: the
    signed-in check short-circuits to code issuance for any kind when a credential is
    stored, and only then does the kind branch decide whether the consent leg is
    establishable. A toolset whose kind is not OAuth, or whose kind is unreadable, has no
    consent flow that could ever satisfy it, so it is refused on the impossible branch with
    no upstream round-trip.

    A **refusal** here consumes the flow's record; an **operator fault** does not. The
    `FlowError` branch that follows — the upstream request could not be built because the
    toolset's registration is incomplete — is the operator-fault class, the same class as
    the Core-unreachable fault: the user re-runs the flow after an administrator fixes the
    registration, so the record is left for that re-run and its retention stays bounded by
    the flow's own TTL.
    """
    try:
        result = await complete_identity_leg(runtime, record, code=code)
        if isinstance(result, AppLegResult):
            # The checkpoint sits before the mint even here, where nothing rendered
            # before: an approved client mints exactly as the short-circuit always did,
            # and a first attribution renders the decision page instead of the mint.
            gated = _attribution_gate(runtime, record)
            if gated is not None:
                return gated
            # The kind-driven short-circuit, unconditional for this kind: no signed-in
            # check, no kind branch, no credential call, no upstream round-trip — the read
            # already ran and the mint is all that is left.
            runtime.audit.credential_free_short_circuit(record)
            return _finish(runtime, record)
        outcome = _toolset_after_read(runtime, record, result)
        if isinstance(outcome, Response):
            return outcome
        authorization = outcome
    except (IdentityProviderError, CoreError, FlowError) as exc:
        return _leg_failure(runtime, record, exc)

    # The consent branch's checkpoint rides the interstitial's existing position: after the
    # read, before the upstream redirect. On first attribution the decision page replaces
    # the display interstitial for that one presentation; once the client is approved the
    # display interstitial is served verbatim.
    gated = _attribution_gate(runtime, record, continuation=authorization.url)
    if gated is not None:
        return gated

    # Through the page builder, so the response carries the web-hardening header family:
    # the page renders a registrant-supplied client name at the end of a flow whose URL
    # still holds the provider's code, so it needs the policy, the referrer rule, and the
    # framing guard together.
    return html_page(interstitial_page(record, authorization.url))


def _leg_failure(
    runtime: Runtime,
    record: FlowRecord,
    exc: IdentityProviderError | CoreError | FlowError,
) -> Response:
    """The page and audit record a flow-leg failure earns.

    Three classes, three audiences, decided together so the audit reason and the page a
    user sees cannot drift apart: an identity-provider failure is the leg's own page, a
    Core failure is the access-denied/trust-fault/fault mapping (which also consumes the
    flow on its refusal classes), and a `FlowError` is the operator-fault class — the
    upstream request could not be built with every parameter it needs, so it is refused
    here rather than delivered incomplete. That last is a fault an administrator fixes, not
    a refusal of the user's request, so it does not consume the record; the same applies to
    the Core-unreachable fault. A refusal consumes the flow: the record is destroyed and
    its identity material dropped (`_core_read_refusal`, `_consume_refused_flow`).
    """
    if isinstance(exc, IdentityProviderError):
        runtime.audit.flow_leg_failed(record=record, leg="idp", reason=str(exc))
        return identity_error_response(exc)
    if isinstance(exc, CoreError):
        return _core_read_refusal(runtime, record, exc)
    runtime.audit.flow_leg_failed(record=record, leg="upstream", reason=exc.message)
    return errors.gateway_error_page(exc.status_code, exc.message)


def _toolset_after_read(
    runtime: Runtime, record: FlowRecord, result: ToolsetLegResult
) -> Response | UpstreamAuthorization:
    """The toolset flow's routing decision after its settings read.

    The stage order is the decision: the signed-in check short-circuits to code issuance for
    any kind when a credential is stored, and only then does the kind branch decide whether
    the consent leg is establishable. A toolset whose kind is not OAuth, or whose kind is
    unreadable, has no consent flow that could ever satisfy it, so it is refused on the
    impossible branch with no upstream round-trip. Returns the upstream authorization to
    serve, or the refusal's page.
    """
    if result.status.signed_in:
        # The short-circuit: a stored credential at user or global level means there is
        # nothing upstream to approve, so the flow finishes here regardless of kind — once
        # the checkpoint has passed. The gate sits before the mint, so a first attribution
        # renders the decision page where this short-circuit minted silently before, and an
        # approved client mints exactly as it always did.
        gated = _attribution_gate(runtime, record)
        if gated is not None:
            return gated
        return _finish(runtime, record)
    if not result.toolset_settings.is_oauth:
        # The impossible branch: no stored credential, and a kind a consent leg cannot
        # establish. Refused with a plain-language page, no upstream round-trip, and a
        # fixed-vocabulary record. The refusal loops benignly like any auth error until
        # an administrator stores the credential out of band. It is a refusal — the flow
        # is over for the user — so it consumes the record and drops the credential
        # material it holds, exactly as the read refusals do; otherwise the identity
        # access token and the provider's session refresh token would sit in the store
        # until the flow's TTL, re-presentable by anyone holding the flow id.
        runtime.audit.flow_branch_refused(record, reason="non_oauth_toolset")
        _consume_refused_flow(runtime, record)
        return errors.not_consentable_page()
    return upstream_authorization(
        result.toolset_settings,
        record,
        callback_uri=runtime.settings.upstream_callback_uri,
    )


def _attribution_gate(
    runtime: Runtime,
    record: FlowRecord,
    *,
    continuation: str | None = None,
) -> Response | None:
    """The consent/attribution checkpoint: consult the registry, or render the decision page.

    Called after the identity leg completes and before every mint, on all three mint paths.
    The record already carries the resolved client (`client_id`, `client_name`,
    `redirect_uri`) and the addressed resource, and the identity leg's subject is in its
    claim snapshot, so the registry is consulted by `(subject, client_id)`:

    * **Approved** — `None` is returned and the caller proceeds exactly its pre-checkpoint
      way: the short-circuits mint with zero pages, the consent branch serves its display
      interstitial verbatim.
    * **First attribution** — the decision page renders, the flow is parked
      (`awaiting_attribution`), and `attribution_required` is audited. The caller must
      return this response rather than minting. On the consent branch `continuation` is the
      built upstream authorization URL, stored on the record so the approve action can
      continue the flow from the record alone.

    A subject that is absent (the provider asserted no `sub`) cannot be an approved pair, so
    such a flow falls to the decision page — the fail-safe direction, since each such flow
    is a first attribution by construction.
    """
    subject = _subject_of(record)
    if runtime.approved_clients.is_approved(subject, record.client_id):
        return None

    if continuation is not None:
        # The consent branch's continuation: the URL is transient today (only the redirect
        # URI was kept), so the decision point stores it — the approve action continues
        # from the record alone, and the interstitial served after approval reads it from
        # here.
        record.upstream_authorization_url = continuation
    record.awaiting_attribution = True
    runtime.audit.attribution_required(record)
    return html_page(decision_page(record))


def _subject_of(record: FlowRecord) -> str:
    """The flow's provider-verified subject, or an empty string when the leg asserted none.

    The registry's key is `(subject, client_id)`; a flow whose claim snapshot carries no
    `sub` is one the identity leg did not complete as a user, and an empty subject can never
    match an approved pair — so it re-prompts rather than skipping, the fail-safe direction.
    """
    claims = record.identity_claims or {}
    subject = claims.get("sub")
    return subject if isinstance(subject, str) else ""


def _core_read_refusal(
    runtime: Runtime, record: FlowRecord, exc: CoreError
) -> Response:
    """The page a Core read failure gets, with its audit record.

    The DIAL authorization check's refusals reach here through `CoreError`: a refused read
    (403) is the user's own lack of access, a name Core does not know (404) is the resource
    kind's existence refusal and gets the fixed-vocabulary record — `unknown_toolset` for
    the toolset namespace's settings read, `unknown_app` for the apps namespace's app read —
    a 401 is the trust fault (Core could not validate the sign-in's identity token), and
    every other failure is a fault only an operator can read about.

    Every **refusal** ends the flow, so every refusal consumes the flow's record
    (`_consume_refused_flow`) before its page is rendered: the existence refusals, the
    no-access refusal, and the trust fault all destroy the record and drop the credential
    material it holds — for the trust fault that material is the point: the record's
    identity access token and the provider's session refresh token are the very material
    Core could not validate, so retaining them serves no re-run. A fault (the branch that
    reaches `core_error_response` for none of these) does not consume it — the flow is
    meant to be re-run after the operator fixes the cause, and the record's retention stays
    bounded by its own TTL.
    """
    if isinstance(exc, ToolsetUnknownError):
        runtime.audit.flow_branch_refused(record, reason="unknown_toolset")
        _consume_refused_flow(runtime, record)
        return errors.gateway_error_page(exc.status_code, str(exc))
    if isinstance(exc, AppUnknownError):
        runtime.audit.flow_branch_refused(record, reason="unknown_app")
        _consume_refused_flow(runtime, record)
        return errors.gateway_error_page(exc.status_code, str(exc))
    # The audit reason is the exception's own fixed text: the trust-fault class's message
    # is fixed vocabulary chosen in `gateway.core`, distinct from the access-denied
    # class's, so the trail distinguishes an authentication failure from an authorization
    # verdict — the only diagnosable trace the failure has, Core logging no record of its
    # 401s.
    runtime.audit.flow_leg_failed(record=record, leg="authorization", reason=str(exc))
    if isinstance(exc, (AccessDeniedError, TrustFaultError)):
        _consume_refused_flow(runtime, record)
    return core_error_response(exc)


def _consume_refused_flow(runtime: Runtime, record: FlowRecord) -> None:
    """Destroy a refused flow's record and drop the credential material it holds.

    A refusal ends the flow, so the record must not outlive it. Left in the store, the
    record would still hold the identity access token the exchange captured — the read
    discards it only on its success path — and the provider's session refresh token, and a
    re-presented flow id would resolve the record and re-run the leg instead of landing on
    the expired page an unknown id gets. Destroying it here puts a refused flow's id in the
    same state as an id whose flow ended any other way, and keeps the identity token's
    retention bounded by the flow's own TTL rather than extended by the refusal.
    """
    runtime.flows.destroy(record.flow_id)
    record.discard_identity_token()
    record.identity_refresh_token = None


@router.get(UPSTREAM_CALLBACK_ROUTE, response_model=None)
async def upstream_callback(request: Request) -> Response:
    """The upstream's callback: consume the flow, hand the code to Core, issue a code.

    The order is the security property: the state must round-trip the flow id, the record
    is destroyed, and only then is the credential call made.
    """
    runtime: Runtime = request.app.state.runtime
    if not runtime.limiter.allow(errors.client_source(request)):
        return errors.gateway_error_page(429, _TOO_MANY_CALLBACKS)

    try:
        record = _live_flow(runtime, request.query_params.get("state"))
    except _FlowGoneError as gone:
        return gone.page

    code = request.query_params.get("code")
    if not code or request.query_params.get("error"):
        return errors.gateway_error_page(400, _LEG_REFUSED)

    redirect_uri = record.upstream_redirect_uri
    if redirect_uri is None:
        # A record without the callback URI is one whose upstream leg was never built, so
        # there is nothing this code could legitimately be a callback for.
        return errors.flow_expired_page(_EXPIRED_FLOW_REASON)

    # Consumed before anything else happens: from here the flow id can never resolve
    # again, whatever the credential call goes on to do. The callback URI and the claim
    # snapshot are already on the record, so the record stays usable after its removal
    # from the store.
    runtime.flows.destroy(record.flow_id)
    runtime.audit.upstream_callback(record=record)

    outcome = await _credential_call(
        runtime, record, code=code, redirect_uri=redirect_uri
    )
    if outcome is not None:
        return outcome
    return _finish(runtime, record)


@router.post(CONSENT_ROUTE, response_model=None)
async def consent(request: Request) -> Response:
    """The decision page's action: record the attribution and continue, or consume on deny.

    The route reads exactly two facts — the flow id and the chosen action — and derives
    everything else from the flow record, so nothing the browser round-trips can be trusted
    beyond those two. The binding is the flow id itself: 128-bit CSPRNG, server-side
    record, TTL-bounded, the same binding both callbacks ride, and secret from a link
    crafter by construction (it crosses only the victim's browser). The gateway sets no
    cookies and holds no ambient browser authority, so a cross-site POST carries nothing
    the gateway trusts.

    The action is **single-use-per-flow**: the record must be parked at the decision point
    (`awaiting_attribution`), which the checkpoint set when the page rendered. The POST
    clears it, so a re-presented approve, or a POST against a flow already advanced, finds
    it clear and lands on the expired-flow page and allocates nothing — one approval cannot
    mint twice. An approve or deny naming no live flow lands there too, like every other
    flow-id-resolved route.

    The route joins the shared limiter (the callbacks' pattern) and answers no CORS headers
    (the surface's back-channel-only posture). Its responses are pages, never redirects: a
    browser-facing refusal here is a page, and no OAuth error is redirected to any target.
    """
    runtime: Runtime = request.app.state.runtime
    if not runtime.limiter.allow(errors.client_source(request)):
        return errors.gateway_error_page(429, _TOO_MANY_CALLBACKS)

    parameters = await _consent_parameters(runtime, request)
    if parameters is None:
        return errors.gateway_error_page(400, _BAD_CONSENT_REQUEST)
    flow_id, action = parameters

    record = runtime.flows.get(flow_id) if flow_id else None
    if record is None or not record.awaiting_attribution:
        # No live flow, or one whose decision has already been taken: both land on the
        # expired-flow page, and nothing is allocated or written.
        return errors.flow_expired_page(_EXPIRED_FLOW_REASON)

    # The decision is spent the moment it is read: clearing the flag before acting makes
    # the action single-use even under a replayed POST that raced the first one.
    record.awaiting_attribution = False

    if action == _DENY:
        runtime.audit.attribution_refused(record)
        _consume_refused_flow(runtime, record)
        return errors.gateway_error_page(400, _ATTRIBUTION_DENIED)

    return _approve(runtime, record)


def _approve(runtime: Runtime, record: FlowRecord) -> Response:
    """Record the attribution and continue the flow to the stage the decision deferred.

    Approve writes the registry keyed to the flow's own verified subject and audits it, then
    serves the deferred stage: the consent branch's display interstitial (the record stays
    live for the upstream callback), or — on a short-circuit — the mint itself, delivered as
    a navigating page rather than a redirect. The page is mandatory here, not a preference:
    this response follows the decision page's *form* submission, and the page's family-wide
    `form-action 'self'` makes a browser refuse a redirect off the gateway's origin, so a 302
    to the harness's (different-origin) registered `redirect_uri` would strand the user on the
    decision page — the approve appearing to do nothing. The route's own contract already
    says "responses are pages, never redirects"; this is that contract's mint case.
    """
    # Approve: record the attribution keyed to the flow's own verified subject, then
    # continue to the stage the decision point deferred.
    runtime.approved_clients.approve(_subject_of(record), record.client_id)
    runtime.audit.attribution_approved(record)

    continuation = record.upstream_authorization_url
    if continuation is not None:
        # The consent branch: the deferred stage is the upstream redirect, which follows
        # the display interstitial as it always did. The record stays live for the upstream
        # callback to resolve and consume.
        return html_page(interstitial_page(record, continuation))
    # A short-circuit: the deferred stage is the mint itself. The app kind's zero-page
    # short-circuit carries its own trail record — the same one the approved path emits —
    # so the trail still answers that the flow minted with no upstream stage because the
    # resource kind is credential-free. The toolset stored-credential short-circuit's mint
    # carries no such record, exactly as it never did.
    if record.resource_kind == "app":
        runtime.audit.credential_free_short_circuit(record)
    destination = _mint(runtime, record)
    if isinstance(destination, Response):
        # The issuance-failure page: a page already, delivered as one.
        return destination
    return html_page(mint_navigation_page(destination))


async def _consent_parameters(
    runtime: Runtime, request: Request
) -> tuple[str, str] | None:
    """The flow id and the chosen action from the POST body, or `None` if unreadable.

    The body is read under the shared form-body cap, applied while it is read: the endpoint
    is unauthenticated and takes a body, so a request that is merely large must cost the
    gateway a bounded amount of memory. The route reads exactly the two facts the tabs
    carry and ignores any others — the page's remaining facts come from the record, never
    the body — so an extra field is dropped rather than trusted. A repeated parameter or an
    action outside the two-token vocabulary is refused, and the request carries a
    content-type guard like the token endpoint's own form read.
    """
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != _FORM_CONTENT_TYPE:
        return None
    raw = await capped_body(request, runtime.settings.gateway_form_max_body_bytes)
    if raw is None:
        return None
    body = raw.decode("utf-8", errors="replace")
    values: dict[str, str] = {}
    for name, value in parse_qsl(body, keep_blank_values=True):
        if name in values:
            # A repeated parameter is ambiguous — two parsers could read two values.
            return None
        values[name] = value
    action = values.get("action")
    if action not in (_APPROVE, _DENY):
        return None
    return values.get("flow_id", ""), action


async def _credential_call(
    runtime: Runtime,
    record: FlowRecord,
    *,
    code: str,
    redirect_uri: str,
) -> Response | None:
    """Make the credential call, recording its outcome, or return the refusal's page.

    One place for the call and its three outcomes, so the audit's result field and the page
    a user sees are decided together rather than in two ladders that could drift.
    """
    try:
        await complete_upstream_leg(
            runtime, record, code=code, redirect_uri=redirect_uri
        )
    except ToolsetAccessDeniedError as exc:
        runtime.audit.signin_result(record=record, result=_SIGNIN_REFUSED)
        runtime.audit.flow_leg_failed(record=record, leg="signin", reason=str(exc))
        return core_error_response(exc)
    except CoreError as exc:
        runtime.audit.signin_result(record=record, result=_SIGNIN_FAILED)
        runtime.audit.flow_leg_failed(record=record, leg="signin", reason=str(exc))
        return core_error_response(exc)
    except FlowError as exc:
        runtime.audit.signin_result(record=record, result=_SIGNIN_FAILED)
        runtime.audit.flow_leg_failed(record=record, leg="signin", reason=exc.message)
        return errors.gateway_error_page(exc.status_code, exc.message)

    runtime.audit.signin_result(record=record, result=_SIGNIN_ACCEPTED)
    return None


class _FlowGoneError(Exception):
    """A callback whose `state` names no live flow.

    Raised rather than returned so each route reads as the sequence it is: resolve the
    flow, refuse, then work. Carrying the page here is what makes the refusal one line at
    the call site instead of a branch every later line has to be written around.
    """

    def __init__(self, page: Response) -> None:
        super().__init__(_EXPIRED_FLOW_REASON)
        self.page = page


def _live_flow(runtime: Runtime, flow_id: str | None) -> FlowRecord:
    """The live record a callback's `state` names, or a refusal the route renders.

    One function for both callbacks because the answer is the same on both: an absent
    state, an unknown id, and an expired record are one outcome from the browser's side,
    and distinguishing them on the page would only report server-side record state to
    someone who cannot act on it.
    """
    record = runtime.flows.get(flow_id) if flow_id else None
    if record is None:
        raise _FlowGoneError(errors.flow_expired_page(_EXPIRED_FLOW_REASON))
    return record


def _mint(runtime: Runtime, record: FlowRecord) -> str | Response:
    """Mint the harness's code and return its redirect back to the harness, or a page.

    The flow's credentials are dropped here: every use the flow had for the identity token
    is spent, and the provider's session refresh token has just been moved into the pending
    hand-off entry keyed by the code's id — what the code carries forward is the claim
    snapshot, not a credential. A refusal is the one issuance failure an operator can fix —
    a roles path that names no claim this deployment mints — so it is logged with the detail
    and shown as the generic page.

    Clearing the refresh token matters most on the short-circuit, whose record stays in the
    store until its TTL: without the clear, the flow's most powerful credential would sit
    there for the flow's whole lifetime after the flow had no further use for it, while the
    record's claims — all the code still needs — are kept.

    The return is the destination URL on success, or the issuance-failure's page. The two
    callers deliver the destination differently — the callbacks redirect, the consent route
    renders a navigating page (a form submission's redirect is governed by the page's
    `form-action`, so a mint behind the decision page's form cannot be a 302) — so the
    delivery is theirs and this function only mints.
    """
    try:
        code = issue_code_for_flow(runtime, record)
    except IssuanceError as exc:
        runtime.audit.flow_leg_failed(record=record, leg="issuance", reason=str(exc))
        return errors.gateway_error_page(400, _ISSUANCE_FAILED)

    record.discard_identity_token()
    # The pending entry now holds the hand-off copy (`issue_code_for_flow` put it there), so
    # the record has no further use for the provider's refresh token on either path.
    record.identity_refresh_token = None
    runtime.audit.code_issued(record=record)
    return harness_redirect(record, code, runtime.settings)


def _finish(runtime: Runtime, record: FlowRecord) -> Response:
    """Mint the harness's code and redirect the browser back to the harness.

    The callback paths' delivery: the browser arrived by a redirect chain, so a redirect
    continues it. The consent route's approve uses `_mint` directly and renders a navigating
    page instead — see `mint_navigation_page` for why a redirect cannot deliver that mint.
    """
    destination = _mint(runtime, record)
    if isinstance(destination, Response):
        return destination
    return RedirectResponse(
        destination,
        status_code=302,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


# The three outcomes the credential call can have, as the audit's own vocabulary. They are
# fixed strings chosen here rather than Core's response text: a result field that carried a
# library's message would be an unvetted string in the log, and the operator's question is
# answered by the three cases, not by Core's phrasing.
_SIGNIN_ACCEPTED = "accepted"
_SIGNIN_REFUSED = "access_refused"
_SIGNIN_FAILED = "failed"


# The reason the page gives when minting the harness's code was refused. It says the
# operator was told, because a user cannot act on a claims-configuration error and the
# gateway's log says which path was wrong.
_ISSUANCE_FAILED = (
    "the gateway could not issue your access token, and an administrator has to fix its "
    "configuration before the sign-in can work"
)
