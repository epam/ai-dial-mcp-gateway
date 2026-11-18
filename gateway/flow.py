"""The federation flow: identity provider, DIAL authorization, upstream consent, code.

The flow runs in three browser legs and two back-channel calls, and the whole ordering is
an authorization argument rather than a sequence of steps:

1. **Identity provider.** The browser is redirected to the provider under the gateway's
   own PKCE client. The redirect carries the gateway's verifier's challenge and the flow
   id as `state`; the verifier itself never leaves the process. Nothing the client sent
   reaches this leg, so no client-supplied scope can fail it.
2. **Callback, exchange, and the DIAL authorization check.** The code is exchanged over
   the provider's internal base URL, and the resulting identity token is verified against
   the provider's published keys. *Then* the toolset's public settings are read as that
   user: Core answers 403 when the user cannot read the toolset, so DIAL authorization is
   enforced before any upstream round-trip, and a user with no access never reaches a
   consent screen. That same read carries the toolset's authentication kind and the
   caller's per-toolset statuses, and the stages that follow are a routing decision:
   **the signed-in check** short-circuits the upstream stage for any kind when a stored
   credential exists (user or global level), and only then does **the kind branch** decide
   whether the consent leg is establishable — an `OAUTH` toolset continues, any other kind
   (or an unreadable one) is refused on the impossible branch with no upstream round-trip.
3. **Upstream.** The browser passes an attribution interstitial — display only, because
   the upstream consent names Core's client and the harness is invisible there — and is
   sent to the upstream's authorize endpoint built from the toolset's *public* settings:
   Core's client id, Core's published `code_challenge`, the callback URI registered in
   Core, and the flow id as `state`. The verifier is Core's and never appears here.
4. **Callback and `/signin`.** The state must round-trip the flow id, and a code arriving
   with a flow id it does not match is refused before anything is looked up. The flow
   record is destroyed on first use, so a replayed callback finds nothing — and the
   credential API call is made at USER level with the user's identity token, which is what
   makes Core store the credential against that user. The flow never *establishes* a global
   credential: when the short-circuit *uses* an operator-stored one, Core injects it on the
   data path, and the credential call stays USER-level on every establishing path.

Two properties are worth naming because they are what the ordering buys. A **guessed flow
id** cannot inject anything: the state round-trip and the unguessable id mean an attacker
arriving with their own upstream code and a guessed id finds no flow, so no victim's
identity is ever paired with an attacker's code. And the **identity token serves the
flow's one decision step** — "may this user sign in to this toolset, and are they already
signed in?" — **and its one action, the credential call**, after which the flow discards
it. The decision step takes one or two presentations depending on whether the
deployment's Core enriches its settings route with the per-caller statuses, so the use is
stated in purposes rather than counts: the count is a property of the deployment's Core,
not of the flow.

The identity provider's **session-bound refresh token** — captured at the exchange, never a
beyond-session `offline_access` grant — is carried past the flow for the refresh window. Its
custody is `gateway/custody.py`'s: it transits the pending hand-off entry keyed by the issued
code's id and is sealed, encrypted, into the gateway's own refresh token at the code grant.
It never touches the authorization code's payload or any other client-visible artifact, in
plaintext or as ciphertext, because the code is a signed-but-unencrypted JWT.
"""

from __future__ import annotations

import functools
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import anyio
import httpx
from fastapi.responses import HTMLResponse

from gateway import errors
from gateway.codes import CodeBindings, code_challenge_for, issue_code
from gateway.core import (
    AccessDeniedError,
    CoreError,
    ToolsetAccessDeniedError,
    ToolsetSettings,
    ToolsetStatus,
)
from gateway.idp import Identity, IdentityProviderClient, IdentityProviderError
from gateway.pages import STYLE_BLOCK
from gateway.runtime import Runtime
from gateway.settings import Settings
from gateway.state import FlowRecord, new_code_verifier, new_token_id
from gateway.tokens import copied_claims


class FlowError(Exception):
    """A flow leg that could not complete, with a message a browser can read.

    `operator_facing` marks the subset that is a deployment error rather than user state:
    those are recorded with the detail an operator needs and shown to the user as the
    generic expired-session page, because no user action can fix a misconfigured path.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 400,
        operator_facing: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.operator_facing = operator_facing


@dataclass(frozen=True)
class UpstreamAuthorization:
    """The upstream authorize URL, built entirely from the toolset's public settings."""

    url: str
    redirect_uri: str


# How long the attribution page stays up before it navigates on. Short enough that the
# user does not read a stalled page, long enough that the notice is legible: this page's
# whole job is to name the client and the toolset once, and it is a notice, not a prompt.
INTERSTITIAL_CONTINUE_DELAY_SECONDS = 1


# The parameters the upstream authorization request must carry for the upstream endpoint to
# be able to answer it, and the list the delivery guard reads. `scope` is required only
# where the toolset advertises scopes at all: a toolset that advertises none is served
# correctly without the parameter, so demanding it there would refuse a request the
# upstream would have accepted.
UPSTREAM_REQUIRED_PARAMETERS = (
    "response_type",
    "client_id",
    "redirect_uri",
    "code_challenge",
    "code_challenge_method",
    "state",
)


def _undeliverable_parameters(url: str, *, scopes_advertised: bool) -> tuple[str, ...]:
    """The required parameters the finished URL does not carry.

    Read off the **built URL** rather than off the mapping that built it, because the URL
    is what the upstream endpoint receives: a value that was present in the mapping and
    lost on the way into the URL — left empty, or dropped by the encoder — is exactly the
    class this guard exists for. A parameter that is present and empty counts as absent
    (`parse_qs` drops blank values), which is the reading this needs: the upstream rejects
    an empty `client_id` the same way it rejects a missing one.
    """
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    required = list(UPSTREAM_REQUIRED_PARAMETERS)
    if scopes_advertised:
        required.append("scope")
    return tuple(name for name in required if not query.get(name))


async def begin_identity_leg(
    flow: FlowRecord, settings: Settings, idp: IdentityProviderClient
) -> str:
    """Start a flow on the identity-provider leg, returning the browser's destination.

    The verifier is generated here and stored on the flow's server-side record; only its
    challenge travels. The state is the flow id, which is what makes the callback
    resolvable without any browser-held state.

    Asynchronous because the redirect is the identity leg's first use of its endpoint
    set, and in discovery mode the first use fetches the discovery document — a network
    call that runs on a worker thread, like every outbound call the leg makes.
    """
    verifier = new_code_verifier()
    flow.idp_code_verifier = verifier
    flow.idp_state = flow.flow_id
    return await idp.authorization_url(
        state=flow.flow_id, code_challenge=code_challenge_for(verifier)
    )


@dataclass(frozen=True)
class AppLegResult:
    """What an app flow's identity leg leaves: the identity, and nothing further to read.

    An app resource is credential-free by construction, so its read decides only "may this
    user use this app" and "does it exist"; there is no status to short-circuit against and
    no kind to branch on, so no settings projection is carried. The flow mints next.
    """

    identity: Identity


@dataclass(frozen=True)
class ToolsetLegResult:
    """What a toolset flow's identity leg leaves: the listing read and the caller's status.

    Both are carried out of the leg rather than read again later, and that is a decision
    about the token rather than about efficiency: the user's identity token is the flow's
    one credential, and re-reading the toolset after this leg would spend another use of it.
    Every Core call the flow makes on the user's behalf happens here, in one place where the
    two uses can be counted.
    """

    identity: Identity
    toolset_settings: ToolsetSettings
    status: ToolsetStatus


async def complete_identity_leg(
    runtime: Runtime, flow: FlowRecord, *, code: str
) -> AppLegResult | ToolsetLegResult:
    """Exchange the identity-provider callback's code, then make the flow's Core read.

    Order matters and is the point: the read happens *after* the exchange (it needs the
    user's token) and *before* anything upstream — the read is the authorization check. A
    user without access gets a page saying so, and the upstream never learns the flow
    existed.

    The read is the flow's DIAL authorization check for either kind, and it differs by kind:

    * A **toolset** flow reads the toolset's public settings as the user. That read carries
      the authentication kind and the caller's statuses, which steer the stages the caller
      runs next: the signed-in check short-circuits the upstream stage for any kind, and only
      then does the kind branch decide whether the consent leg is establishable.
    * An **app** flow reads the app as the user. The read answers "may this user use this
      app" (403 refuses) and "does it exist" (404 refuses), and for the app kind there is
      nothing to short-circuit against and no kind to branch on — the resource is
      credential-free by construction — so the flow mints next.

    Either way this leg establishes *who* is signing in, never what kind of credential the
    resource uses. The result's type is the kind: an `AppLegResult` or a `ToolsetLegResult`,
    so the caller branches on the read Core actually made.
    """
    identity = await runtime.idp.exchange_code(
        code=code,
        code_verifier=flow.idp_code_verifier or "",
    )
    flow.identity_access_token = identity.access_token
    flow.identity_claims = identity.claims
    # The provider's session refresh token, carried server-side until the code grant seals
    # it into the gateway's own refresh token. It never touches the code payload or any
    # client-visible artifact: at flow end it goes to the pending hand-off entry keyed by
    # the code's id, and the code grant consumes it from there.
    flow.identity_refresh_token = identity.refresh_token
    # The identity token's own remaining life, as a duration, because the flow's clock is
    # monotonic: `expires_at` and this bound have to be comparable, and an absolute
    # wall-clock instant is not. min of the two, because the flow TTL bounds retention
    # while the token's `exp` bounds the token's life.
    flow.identity_expires_at = min(
        flow.expires_at,
        time.monotonic() + _seconds_until(identity.claims.get("exp")),
    )

    if flow.resource_kind == "app":
        # The app read is the whole authorization and existence check for this kind, and its
        # one use of the identity token is spent here.
        await runtime.core.read_app_for_flow(flow.toolset, identity.access_token)
        flow.discard_identity_token()
        return AppLegResult(identity=identity)

    # The toolset read: one request on the deployment-listing route (see
    # `read_toolset_for_flow`) — availability, the settings projection, and the per-caller
    # statuses in one answer — and the refusal on it is the answer to "may this user sign
    # in to this toolset?".
    toolset_settings, status = await runtime.core.read_toolset_for_flow(
        flow.toolset, identity.access_token
    )
    # The upstream callback is the gateway's own, derived from configuration — never the
    # toolset's stored `auth_settings.redirect_uri`, which Core stores from its allowlist's
    # first entry at registration time and other components (DIAL Chat's editor among them)
    # overwrite with their own callbacks. Stored on the record so the credential call reads
    # it from there, the same call-site discipline every other field follows; it is constant
    # per deployment, so no Core answer can steer it.
    flow.upstream_redirect_uri = runtime.settings.upstream_callback_uri
    if status.signed_in:
        # The short-circuit: a stored credential means there is nothing to approve, so
        # both of the token's uses are spent for this path and the credential is dropped
        # here rather than held until the flow's TTL.
        flow.discard_identity_token()
    return ToolsetLegResult(
        identity=identity, toolset_settings=toolset_settings, status=status
    )


def upstream_authorization(
    settings: ToolsetSettings, flow: FlowRecord, *, callback_uri: str
) -> UpstreamAuthorization:
    """Build the upstream authorize URL from the toolset's own public settings.

    Every parameter is the toolset's or Core's, except the callback: `callback_uri` is the
    gateway's own derived upstream callback (`{origin}/dial/callback/upstream`), never the
    toolset's stored `redirect_uri` — the stored field is an artifact of Core's registration
    that other components overwrite, so the gateway derives its own callback the same way
    its two sibling callbacks do. The client id and the challenge are Core's public
    projection, and the scopes are the ones the toolset advertises in its public settings
    (`scopes_supported`, which Core publishes verbatim from the toolset's registration). The
    flow id travels as `state` so
    the callback can be resolved; the verifier that redeems the resulting code stays in
    Core.

    This is the consent branch, the only branch that builds a URL from the projection's
    OAuth fields, so this is where those fields are required: a toolset whose kind is OAuth
    but whose projection is missing one of them cannot be served by consent, and guessing
    the missing half would send the browser somewhere the toolset never named. The settings
    read no longer refuses such a projection, because a non-OAuth toolset has none and is
    served without ever reaching here.

    The URL is then guarded before it leaves this function, because this is the last point
    at which the *request the browser will actually send* is still the gateway's to check:
    from here on it is delivered by a page, and a page that could lose a parameter would
    fail at the upstream as an opaque OAuth error rather than as anything this gateway
    renders. The guard reads the finished URL, so a parameter that is present in the
    projection and absent — or empty — in the URL is caught rather than assumed.
    """
    missing_fields = settings.missing_oauth_fields()
    if missing_fields:
        message = (
            f"this toolset's public OAuth settings in DIAL Core are incomplete "
            f"({', '.join(missing_fields)}); an administrator should re-register the "
            f"toolset"
        )
        raise FlowError(message, status_code=502)

    query = {
        "response_type": "code",
        "client_id": settings.client_id,
        "redirect_uri": callback_uri,
        "code_challenge": settings.code_challenge,
        "code_challenge_method": settings.code_challenge_method,
        "state": flow.flow_id,
    }
    scope = settings.scope_parameter
    if scope:
        query["scope"] = scope
    url = f"{settings.authorization_endpoint}?{urllib.parse.urlencode(query)}"

    missing = _undeliverable_parameters(url, scopes_advertised=bool(scope))
    if missing:
        # Fixed text built here from the *names* of the missing parameters, never from a
        # value from a request or from Core's answer: the caller renders this to a
        # browser, and the audit trail records it for the operator who has to act on it.
        message = (
            "the gateway could not build a complete approval request for this toolset "
            f"({', '.join(missing)}); an administrator should re-register the toolset, "
            "then start the sign-in again"
        )
        raise FlowError(message, status_code=502)

    return UpstreamAuthorization(url=url, redirect_uri=callback_uri)


async def complete_upstream_leg(
    runtime: Runtime, flow: FlowRecord, *, code: str, redirect_uri: str
) -> None:
    """Hand the upstream code to Core's credential API at USER level.

    `credentialsLevel` is a literal `USER`: the level is what makes Core stamp the stored
    credential with the calling token's `sub`, and GLOBAL is an operator action the
    gateway has no path to. The body is the documented sign-in request, and the identity
    token is the user's — which is what the flow's whole ordering exists to produce.
    """
    if flow.identity_access_token is None:
        message = (
            "this sign-in session lost the identity it was established with; start the "
            "sign-in again from your tool"
        )
        raise FlowError(message)

    body: dict[str, Any] = {
        # The credential store keys on the DECODED resource path — the form Core's own `id`
        # fields carry — while the flow record's resource field carries the canonical path
        # (the flow's identity). Both come from one resolution.
        "url": runtime.settings.decoded_path(flow.toolset),
        "credentialsLevel": "USER",
        "authenticationType": "OAUTH",
        "code": code,
        "redirectUri": redirect_uri,
    }
    await _post_credential_signin(runtime, flow, body)


async def _post_credential_signin(
    runtime: Runtime, flow: FlowRecord, body: dict[str, Any]
) -> None:
    """The credential API call itself, with its failures named.

    The request runs on a worker thread: Core's credential call reaches the upstream
    authorization server before it answers, so it is the slowest leg of the flow and the
    one whose duration is set by a third party this gateway does not control. The flow
    record it reads and updates stays on the event loop, so no shared state is touched off
    it — the thread holds nothing but the request it sends.
    """
    settings: Settings = runtime.settings
    url = f"{settings.dial_core_base_url}/v1/ops/toolset/signin"
    try:
        response = await anyio.to_thread.run_sync(
            functools.partial(
                _send_credential_call,
                url,
                body,
                flow.identity_access_token or "",
                settings.gateway_outbound_timeout_seconds,
            )
        )
    except httpx.HTTPError as exc:
        message = f"DIAL Core could not be reached ({type(exc).__name__})"
        raise FlowError(message, status_code=502) from exc

    if response.status_code in (httpx.codes.FORBIDDEN, httpx.codes.UNAUTHORIZED):
        raise ToolsetAccessDeniedError
    if response.status_code not in (httpx.codes.OK, httpx.codes.CREATED):
        message = (
            "DIAL Core could not store the credential this consent was for "
            f"({response.status_code}). Start the sign-in again from your tool."
        )
        raise FlowError(message, status_code=502)


def _send_credential_call(
    url: str, body: dict[str, Any], identity_token: str, timeout: float
) -> httpx.Response:
    """Send the credential call, blocking, for a worker thread to run.

    Module-level and free of the flow record by construction: everything it needs is
    passed in, so the thread touches no state the event loop also reads.
    """
    return httpx.post(
        url,
        json=body,
        headers={
            "Authorization": f"Bearer {identity_token}",
            "Accept": "application/json",
        },
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )


def issue_code_for_flow(runtime: Runtime, flow: FlowRecord) -> str:
    """Mint the authorization code the harness is redirected back with.

    The code carries the identity snapshot, so the token endpoint needs neither the flow
    record nor the identity provider — which is why the flow can be destroyed here and a
    restart cannot strand a harness that already holds a code.

    The code's id is generated here rather than inside `issue_code`, because it is also the
    key the provider's session refresh token is held under until the code grant seals it:
    the flow's own record is gone by then, so the code's id is the only handle the two sides
    share. The token verdict lives in the entry, never in the code — the code is a
    signed-but-unencrypted JWT whose payload anyone holding the code string can read, so
    carrying mintable credential material there would hand it to the client.
    """
    claims = copied_claims(flow.identity_claims or {}, runtime.settings)
    code_id = new_token_id()
    if flow.identity_refresh_token is not None:
        runtime.pending_custody.put(code_id, flow.identity_refresh_token)
    return issue_code(
        runtime.signing_key,
        CodeBindings(
            client_id=flow.client_id,
            redirect_uri=flow.redirect_uri,
            code_challenge=flow.code_challenge,
            code_challenge_method=flow.code_challenge_method,
            resource=flow.resource,
            toolset=flow.toolset,
            subject=str((flow.identity_claims or {}).get("sub", "")),
            claims=claims,
        ),
        issuer=runtime.settings.gateway_public_origin,
        ttl_seconds=runtime.settings.gateway_code_ttl_seconds,
        code_id=code_id,
    )


def harness_redirect(flow: FlowRecord, code: str, settings: Settings) -> str:
    """The redirect back to the harness: the code, the echoed state, and the issuer.

    `iss` is RFC 9207's mix-up defense, and the flat issuer is exactly the shape that needs
    it: every toolset shares one authorization server, so this parameter is what lets a
    client that talks to several servers tell which one answered. The client's own `state`
    is echoed back unchanged, which is how it correlates the callback with its request.
    """
    params = {"code": code, "iss": settings.gateway_public_origin}
    if flow.state is not None:
        params["state"] = flow.state
    separator = "&" if "?" in flow.redirect_uri else "?"
    return f"{flow.redirect_uri}{separator}{urllib.parse.urlencode(params)}"


def mint_navigation_page(destination: str) -> str:
    """A page that hands the browser to `destination`, for a response a redirect cannot be.

    The consent route is the one browser-facing route whose response follows a *form
    submission* — the decision page's approve button. Browsers apply the page's
    `form-action` directive to the redirects of a form submission, and the decision page
    carries the family-wide `form-action 'self'`; the harness's registered `redirect_uri` is
    a different origin (a loopback port, or the harness's own host), so a 302 to it is
    blocked by the browser and the user is left on the decision page — the approve appears
    to do nothing, and a second click finds the decision already spent. The approve
    therefore answers with this page instead of a redirect, and the browser follows the
    meta-refresh *navigation*, which `form-action` does not govern, exactly as the display
    interstitial already delivers the upstream request. The route's own contract says as
    much ("its responses are pages, never redirects"); this is that contract's mint case.

    The same delivery as the interstitial, for the same reason: a `method="get"` form would
    replace its action's query with the form's own controls and silently drop the code, so
    a navigation — the meta refresh, with an anchor beside it for a browser that ignores
    it — is the one delivery that arrives exactly as written.
    """
    return _MINT_PAGE.format(
        destination=_escape(destination),
        refresh_delay=INTERSTITIAL_CONTINUE_DELAY_SECONDS,
        style=STYLE_BLOCK,
    )


def interstitial_page(flow: FlowRecord, continue_url: str) -> str:
    """The attribution page shown before the upstream consent.

    Display-only, and stated as such: the upstream consent screen names Core's client, so
    without this page the user would see no connection between what they clicked in their
    harness and what they are being asked to approve. The `client_name` is preferred over
    the bare client id where the registration carries one — for a dynamically registered
    client that name is registrant-supplied, which is why the page presents it as a name
    and not as a verified fact.

    The page continues itself, with no form and no script. A form would be the wrong
    mechanism for delivering the upstream request: a `method="get"` submission *replaces*
    its action URL's query with the query built from the form's successful controls, so a
    form whose parameters live in the action and whose body carries no controls submits to
    the bare endpoint with every parameter — including the flow id as `state` — silently
    dropped. The loss happens inside the browser, after this response is complete, so no
    server-side seam can see it and the failure surfaces only as the upstream's opaque
    OAuth error. A navigation (`<meta http-equiv="refresh">`, which needs no scripting and
    therefore no script policy) is delivered exactly as written, and the anchor beside it
    is the same navigation for a browser that ignored the refresh.

    The stylesheet is the shared `PAGE_STYLE` block, not a copy: the served page's
    response pins that text by hash in its CSP, so the page that renders and the page the
    policy authorizes have to be the same one.
    """
    tool = _escape(flow.toolset)
    attributed = _escape(flow.client_name or flow.client_id)
    return _INTERSTITIAL.format(
        toolset=tool,
        client=attributed,
        continue_url=_escape(continue_url),
        refresh_delay=INTERSTITIAL_CONTINUE_DELAY_SECONDS,
        style=STYLE_BLOCK,
    )


def decision_page(flow: FlowRecord) -> str:
    """The consent/attribution decision page shown on first attribution.

    The one page on the surface whose whole job is the user's act, so it is the one page
    that does not continue itself: no `meta refresh`, nothing that navigates, and the flow
    waits. It names three facts, each with its own honesty rule:

    * the **resolved client** — the registration's `client_name` where one exists,
      presented as a name and not a verified fact (the name is registrant-supplied through
      CIMD or DCR), with the client id beside it always, because the id is the verifiable
      identifier;
    * the **addressed resource** — its kind and its served name, in the same plain
      vocabulary the interstitial uses;
    * the **registered `redirect_uri`** the code will be delivered to, shown in full, port
      included — the one fact a victim can check against expectation and the one a false
      name cannot forge, because it is the registration's own validated value.

    No scope list is shown: the client-facing surface accepts and drops the `scope`
    parameter, and presenting scopes the flow does not act on would be theater.

    The form posts the flow id and the chosen action, and nothing else; every other fact
    the continuation needs is re-derived from the record at the action, never round-tripped
    through the browser. The page is built through `html_page`, so the web-hardening header
    family — including the family-wide `form-action 'self'` that confines this form to the
    gateway's origin — is inherited by construction, and every interpolated value passes
    the same escape the interstitial uses (`client_name` is registrant-supplied and the
    resource name is caller-path-derived, both hostile text in an HTML context).
    """
    kind_name = _resource_kind_phrase(flow.resource_kind)
    return _DECISION_PAGE.format(
        client_id=_escape(flow.client_id),
        client_name=_escape(flow.client_name or flow.client_id),
        kind=kind_name,
        resource=_escape(flow.toolset),
        redirect_uri=_escape(flow.redirect_uri),
        flow_id=_escape(flow.flow_id),
        style=STYLE_BLOCK,
    )


def _resource_kind_phrase(resource_kind: str) -> str:
    """The resource kind in the pages' plain vocabulary, fixed text chosen here.

    The kind is this gateway's own token (`toolset`/`app`), never a caller value, so it is
    interpolated as a fixed phrase rather than escaped caller text. An unknown value falls
    back to the neutral word so the page never renders an empty slot.
    """
    return {"toolset": "toolset", "app": "app"}.get(resource_kind, "resource")


def _escape(value: str) -> str:
    """Escape a value interpolated into the page.

    Both values come from configuration or from a registration, and the page is HTML:
    escaping here is what keeps a registered name from becoming markup. Escaping the same
    way in the navigation attribute is what keeps a parameter value from closing the
    attribute and turning the URL into markup.
    """
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _seconds_until(expiry: object) -> float:
    """Seconds left on a claim-stated expiry, or zero when it does not state one.

    A token that states no expiry is treated as giving the flow no extra time rather than
    as giving it unlimited time: the safe reading of a missing bound is the shortest one,
    and the identity token is a credential whose retention this is arguing about.
    """
    if not isinstance(expiry, (int, float)):
        return 0.0
    return max(0.0, float(expiry) - time.time())


def core_error_response(exc: CoreError) -> HTMLResponse:
    """Turn a Core refusal into the page its audience expects.

    Two pages, because two different people can act on what Core said: an access-denied
    read — for a toolset or an app — is the user's own lack of access and the page names the
    administrator to ask, while every other Core failure is a fault only an operator can
    diagnose.
    """
    if isinstance(exc, AccessDeniedError):
        return errors.no_access_page(exc.status_code, str(exc))
    return errors.gateway_error_page(exc.status_code, str(exc))


def identity_error_response(exc: IdentityProviderError) -> HTMLResponse:
    """Turn an identity-provider failure into the page a browser can act on.

    The status is the leg's own: a declined sign-in is a 4xx the user can retry, while a
    provider that answered unusably is a 5xx an operator should see.
    """
    return errors.gateway_error_page(exc.status_code, str(exc))


# The page the consent route's approve answers with on a mint path: a navigation to the
# harness's registered redirect, carrying no form. It exists because a form submission's
# redirects are governed by the page's `form-action` (see `mint_navigation_page`), so the
# mint cannot be delivered as a 302 from behind that form. The anchor beside the refresh is
# the fallback for a browser that ignores the refresh, the same pair the interstitial uses.
_MINT_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="{refresh_delay}; url={destination}">
<title>Sign-in complete</title>
{style}
</head>
<body>
<h1>Sign-in complete</h1>
<p>Returning you to your tool&hellip; If nothing happens,
<a href="{destination}">continue</a>.</p>
</body>
</html>
"""


_INTERSTITIAL = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="{refresh_delay}; url={continue_url}">
<title>Continue to {toolset}</title>
{style}
</head>
<body>
<h1>Connecting {toolset} to DIAL</h1>
<p class="note">You asked <strong>{client}</strong> to use the DIAL toolset
<strong>{toolset}</strong>. The next screen asks you to approve access on
{toolset}'s side — it names DIAL, because DIAL is what holds your credential.</p>
<p>Continuing to the approval page&hellip; If nothing happens,
<a href="{continue_url}">continue to {toolset}</a>.</p>
</body>
</html>
"""


# The decision page's markup. A plain server-rendered form, no script and no auto-continue:
# the two buttons carry the action as their value, and the flow id rides a hidden field, so
# the POST body is exactly the flow id and the decision. The action URL is the consent
# route, spelled here as it is in the routing table.
_DECISION_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Approve {client_name}</title>
{style}
</head>
<body>
<h1>Approve access for {client_name}?</h1>
<p class="note"><strong>{client_name}</strong> (client id <code>{client_id}</code>) is
asking to use the DIAL {kind} <strong>{resource}</strong> as you. If you approve, the
sign-in code will be delivered to <code>{redirect_uri}</code>.</p>
<p>This is the first time this client has asked. Approving records your decision for this
client, so future sign-ins from it will not ask again.</p>
<form method="post" action="/dial/consent">
<input type="hidden" name="flow_id" value="{flow_id}">
<button type="submit" name="action" value="approve">Approve</button>
<button type="submit" name="action" value="deny">Deny</button>
</form>
</body>
</html>
"""
