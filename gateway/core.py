"""The gateway's calls into Core on a user's behalf.

The flow's toolset read is one call, on one Core route, serving all three of its
purposes:

* **The deployment-listing read**, `GET /openai/toolsets/{name}` — the route whose
  authorization is the MCP data path's own: Core resolves the toolset through the same
  deployment resolution the data path authorizes every call with, so the read answers
  200 exactly when the user could call the toolset, 403 when that decision refuses
  them, and 404 for a name it does not know. A 401 is neither of those: it is the
  trust fault — Core could not validate the sign-in's identity token, an
  authentication failure whose remedy is the operator's check of Core's provider
  entry, never an access verdict. Its answer carries everything the flow
  decides on: the availability decision (the authorization itself), the public
  authentication settings the upstream leg builds its URL from, and the per-caller
  statuses the signed-in check reads. Deciding availability on this route is what
  makes the flow's "may this user sign in?" and the data path's "may this user call?"
  one decision instead of two that could disagree — the admin-role route the flow read
  before refused non-admin users toolsets the data path serves, the false denial the
  live run exposed.

One read means the statuses come from the listing answer's own enrichment, and their
absence rule is the fail-closed discipline: a listing answer with no readable status at
either level is not signed in, and the flow falls into the kind branch — no second read
is ever made, because asking the same route again could only repeat its answer.

The read is made with the live user's identity token and nothing else. That token is the
one credential the flow holds, and it serves the sign-in flow and nothing else: this
module answers its decision step — "may this user sign in to this toolset, and are they
already signed in?" — and the credential call that follows the step is its one action.
The token is never stored, logged, or carried into any token the gateway mints, and it
is dropped once the action is spent.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass
from typing import Any

import anyio
import httpx

from gateway.settings import Settings

# The statuses Core reports for a toolset's authentication. `SIGNED_IN` is the one the
# flow short-circuits on: the user already holds a stored upstream credential, so the
# upstream consent would be a second approval for something already approved.
SIGNED_IN = "SIGNED_IN"

# The authentication kind the upstream consent leg can establish. The flow runs the
# consent leg only when no credential is stored and the toolset's kind is this one; any
# other kind is refused on the impossible branch. The kind is Core's, read per flow.
OAUTH_AUTHENTICATION_TYPE = "OAUTH"

# The field names the public settings projection carries. Named here so the flow reads a
# field by the name Core publishes it under, and a renamed one fails loudly at this seam
# rather than silently at a redirect URL.
FIELD_CLIENT_ID = "client_id"
FIELD_AUTHORIZATION_ENDPOINT = "authorization_endpoint"
FIELD_CODE_CHALLENGE = "code_challenge"
FIELD_CODE_CHALLENGE_METHOD = "code_challenge_method"
FIELD_SCOPES_SUPPORTED = "scopes_supported"
FIELD_AUTHENTICATION_TYPE = "authentication_type"
FIELD_USER_LEVEL_AUTH_STATUS = "user_level_auth_status"
FIELD_GLOBAL_AUTH_STATUS = "global_auth_status"
FIELD_APP_LEVEL_AUTH_STATUS = "app_level_auth_status"

# The `auth_settings` member the listing answer nests the projection under.
_AUTH_SETTINGS = "auth_settings"


class CoreError(Exception):
    """A Core call the flow cannot continue past.

    Carries a message chosen here and safe to show a browser: it names the failure, never
    the credential the call was made with, and never a value Core returned.
    """

    def __init__(self, message: str, *, status_code: int = 502) -> None:
        super().__init__(message)
        self.status_code = status_code


class TrustFaultError(CoreError):
    """Core could not validate the sign-in's identity token — a trust fault.

    A 401 from Core is an authentication failure, not an authorization verdict: Core
    could not validate the identity token the read was made with — its provider entry
    for the identity provider (the issuer pattern, the key set, the audience) or that
    key set's reachability is the cause, and the remedy is the operator's. Distinct
    from the access-denied class because the two answers have two audiences whose
    actions differ: a 403 tells the user to ask for access; a 401 tells them nothing
    is wrong with their access and the sign-in cannot proceed until an administrator
    checks the trust configuration. Answering a 401 with the no-access page sends the
    user hunting for access they may already hold and the operator hunting for an
    access change that never happened — the wrong-class defect this class removes.

    The message is fixed vocabulary chosen here and names nothing user-identifying:
    no token, claim, caller, or provider value ever reaches the page or its audit
    record, and Core's own logs carry no record of its 401s — the gateway's audit
    record is the only diagnosable trace the failure has.
    """

    def __init__(self) -> None:
        super().__init__(
            "Core could not validate the sign-in's identity token; the administrator "
            "must check the trust configuration for this provider",
        )


class AccessDeniedError(CoreError):
    """Core refused a read, so this user has no access to the resource it named.

    Distinct from the other failures because it is not a fault: it is the answer to the
    flow's DIAL authorization check, and the page a user sees for it says so. The two
    resource kinds name the resource they refused, so the page carries the right word.
    """

    def __init__(self, resource_word: str) -> None:
        super().__init__(
            f"you do not have access to this {resource_word} in DIAL. Ask your DIAL "
            f"administrator to grant it, then start the sign-in again.",
            status_code=403,
        )


class ToolsetAccessDeniedError(AccessDeniedError):
    """Core refused the toolset listing read, so this user has no access to that toolset."""

    def __init__(self) -> None:
        super().__init__("toolset")


class AppAccessDeniedError(AccessDeniedError):
    """Core refused the app read, so this user has no access to that app."""

    def __init__(self) -> None:
        super().__init__("app")


class ToolsetUnknownError(CoreError):
    """Core does not know the offered toolset name.

    For the toolset flow this is the toolset namespace's existence refusal: the
    unauthenticated discovery tier serves every guard-passing name a document, mirroring
    Core's own registry-independent tier, so existence is decided here — post-authentication,
    on Core's own answer. Distinct from the other Core failures because the page and the
    audit record say this is a name the deployment does not serve, not a fault.
    """

    def __init__(self) -> None:
        super().__init__("this toolset is not registered in DIAL Core", status_code=404)


class AppUnknownError(CoreError):
    """Core does not know the offered app name.

    The apps namespace's existence refusal, the sibling of `ToolsetUnknownError`: the app
    flow's authenticated read decides existence exactly where the toolset flow's settings
    read decides it, so the system has one existence refusal per resource kind, both
    post-authentication. Distinct from the other Core failures because the page and the
    audit record say this is a name the deployment does not serve, not a fault.
    """

    def __init__(self) -> None:
        super().__init__("this app is not registered in DIAL Core", status_code=404)


@dataclass(frozen=True)
class ToolsetSettings:
    """The toolset's public settings, as Core publishes them to an authorized user.

    The projection is readable whether or not it carries OAuth fields: a non-OAuth toolset
    has none, and the flow now serves such a toolset through the short-circuit, so refusing
    the read here would refuse a servable toolset. The OAuth fields are read as strings that
    may be empty, and the completeness refusal belongs to the consent branch — the only
    branch that builds a URL from them — where the flow never reaches for a non-OAuth kind.

    The verifier is absent by construction — Core holds it and never projects it — so the
    OAuth fields' presence is itself the property the upstream leg depends on: the gateway
    builds the upstream authorization URL from the challenge, and only Core can redeem the
    code that comes back.

    The projection's `redirect_uri` member is deliberately **not** carried: the gateway's
    upstream callback is derived from its own configuration (the upstream-authorization
    request's discipline), so the stored field is an input to no leg. The listing read still
    tolerates the member (it is simply not read), which is what keeps the parse compatible
    with any Core projection shape.
    """

    # The toolset's authentication kind, as Core reports it. `None` when the projection
    # carries no usable value, which the flow treats as unestablishable — an unreadable
    # kind cannot be a consentable one.
    authentication_type: str | None
    client_id: str
    authorization_endpoint: str
    code_challenge: str
    code_challenge_method: str
    scopes_supported: tuple[str, ...]

    # The per-caller authentication statuses as this same listing answer enriched them,
    # or `None` when the answer carries no readable value at a level. Their absence is
    # the fail-closed rule: not a status the flow can read is not signed in, so an
    # answer without them falls into the kind branch — never a second read.
    user_level_auth_status: str | None = None
    global_auth_status: str | None = None

    @property
    def scope_parameter(self) -> str:
        """The upstream's advertised scopes, as the upstream authorize URL sends them.

        These belong to the upstream leg: they are the scopes the toolset's own client
        carries, unrelated to the gateway's client scopes and read from the toolset's
        public settings rather than from anything a client sent.
        """
        return " ".join(self.scopes_supported)

    @property
    def is_oauth(self) -> bool:
        """Whether this toolset's kind makes an upstream consent leg establishable."""
        return (self.authentication_type or "").upper() == OAUTH_AUTHENTICATION_TYPE

    def missing_oauth_fields(self) -> tuple[str, ...]:
        """The OAuth fields a consent leg needs and this projection does not carry.

        Read off the projection when the consent branch is about to build its URL: a
        toolset whose kind is OAuth but whose projection is missing one of these cannot be
        served by consent, and guessing the missing half would send the browser somewhere
        the toolset never named. Empty for a projection complete enough to build from.
        """
        return tuple(
            field
            for field, value in (
                (FIELD_CLIENT_ID, self.client_id),
                (FIELD_AUTHORIZATION_ENDPOINT, self.authorization_endpoint),
                (FIELD_CODE_CHALLENGE, self.code_challenge),
            )
            if not value
        )


@dataclass(frozen=True)
class ToolsetStatus:
    """A toolset's authentication status as one user sees it.

    `signed_in` answers the question a harness actually asks — "will my next call work
    without a sign-in flow?" — so it is true when either level stores a credential for the
    toolset: a user-level credential for this caller, or a global credential for the
    toolset. Core's third member, the app-level status, is not read here: an app-level
    credential is not a sign-in for a user's flow, so a toolset whose only stored
    credential is app-level fails closed into the kind branch like any not-signed-in
    answer. An absent, unreadable, or FAILED status is not signed in either.
    """

    user_level_auth_status: str | None
    global_auth_status: str | None

    @property
    def signed_in(self) -> bool:
        return SIGNED_IN in (self.user_level_auth_status, self.global_auth_status)


class CoreClient:
    """Core, as the gateway reaches it on a user's behalf."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def _get_json(
        self,
        url: str,
        identity_token: str,
        *,
        access_denied_error: type[CoreError] = ToolsetAccessDeniedError,
        unknown_error: type[CoreError] = ToolsetUnknownError,
    ) -> dict[str, Any]:
        """One authenticated GET, with every failure turned into a named refusal.

        The request runs on a worker thread, so the event loop is not held while Core
        answers: a Core read sits on the browser's callback leg, and the same loop serves
        every other request including the liveness probe. The response is read on the loop
        — it is already in memory, since this is a plain (non-streaming) request.

        The error classes name which namespace's read this is: a 403 becomes the
        caller's access-denied class and a 404 its unknown-name class, so the page and
        the audit record name the resource kind the route actually asked about, while a
        401 raises the trust-fault class both namespaces share — the mapping is
        `_read_json`'s, one answer-to-refusal mapping for both kinds.
        """
        response = await anyio.to_thread.run_sync(
            functools.partial(self._request, url, identity_token)
        )
        return self._read_json(
            response,
            access_denied_error=access_denied_error,
            unknown_error=unknown_error,
        )

    def _request(self, url: str, identity_token: str) -> httpx.Response:
        """Send the authenticated GET, naming a transport failure as a Core error."""
        try:
            return httpx.get(
                url,
                headers={
                    "Authorization": f"Bearer {identity_token}",
                    "Accept": "application/json",
                },
                timeout=self._settings.gateway_outbound_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            )
        except httpx.HTTPError as exc:
            # The exception type, never its message: an httpx error echoes the request it
            # failed on, and the request carried the user's identity token.
            message = f"DIAL Core could not be reached ({type(exc).__name__})"
            raise CoreError(message) from exc

    def _read_json(
        self,
        response: httpx.Response,
        *,
        access_denied_error: type[CoreError] = ToolsetAccessDeniedError,
        unknown_error: type[CoreError] = ToolsetUnknownError,
    ) -> dict[str, Any]:
        """A Core answer as a JSON object, every status and shape turning into a refusal.

        The two denial codes are two classes with different remedies, never one: a 401
        is the trust fault — Core could not validate the sign-in's identity token, an
        authentication failure whose remedy is the operator's — while a 403 is the
        caller's own access-denied class, and a 404 its unknown-name class, so the page
        and the audit record name the resource kind the route actually asked about. The
        mapping is shared by both resource kinds' reads, so an app read's 401 lands on
        the same trust-fault class.
        """
        if response.status_code == httpx.codes.UNAUTHORIZED:
            raise TrustFaultError
        if response.status_code == httpx.codes.FORBIDDEN:
            raise access_denied_error
        if response.status_code == httpx.codes.NOT_FOUND:
            raise unknown_error
        if response.status_code != httpx.codes.OK:
            message = f"DIAL Core answered {response.status_code}"
            raise CoreError(message)

        try:
            document = response.json()
        except ValueError as exc:
            message = "DIAL Core's answer was not valid JSON"
            raise CoreError(message) from exc
        if not isinstance(document, dict):
            message = "DIAL Core's answer was not a JSON object"
            raise CoreError(message)
        return document

    def listing_url(self, resource_path: str) -> str:
        """The deployment-listing read URL for a resource path.

        The path is the flow's already-canonical resource path (guard-validated and
        canonically encoded at resolution), appended to the fixed route prefix — never a raw
        caller substring — so no caller value can steer the read off `/openai/toolsets/…`
        into another Core route.
        """
        return f"{self._settings.dial_core_base_url}/openai/toolsets/{resource_path}"

    def application_url(self, resource_path: str) -> str:
        """The app read URL for a resource path.

        The apps twin of `listing_url`, built the same way from the canonical path.
        """
        return (
            f"{self._settings.dial_core_base_url}/openai/applications/{resource_path}"
        )

    async def read_toolset_settings(
        self, toolset: str, identity_token: str
    ) -> ToolsetSettings:
        """The flow's toolset read — the deployment-listing route, as this user.

        One read serving the decision step's three purposes: availability (the route's
        authorization is the MCP data path's own deployment resolution, so a 403 here is
        the data path's refusal of this user, not an admin gate's), the settings
        projection the consent branch builds its URL from, and the per-caller statuses
        the signed-in check reads off the same answer.

        A refusal is what the flow's authorization check consists of, so an answer with no
        readable authentication settings at all is refused: a projection this gateway can
        read nothing from is a toolset the flow cannot serve. A projection whose OAuth
        fields are absent is *not* refused here — a non-OAuth toolset has none, and the
        flow serves such a toolset through the short-circuit. The OAuth-fields completeness
        refusal belongs to the consent branch, the only branch that builds a URL from them.

        The statuses are read from this same answer's enrichment, and their absence rule
        fails closed: a status that is not readable here is not signed in, and the flow
        falls into the kind branch. No second read is made — this route asked again could
        only repeat its answer.
        """
        document = await self._get_json(self.listing_url(toolset), identity_token)
        auth = document.get(_AUTH_SETTINGS)
        if not isinstance(auth, dict):
            message = (
                "this toolset's settings in DIAL Core carry no authentication "
                "settings, so the gateway cannot run its sign-in"
            )
            raise CoreError(message)

        scopes = auth.get(FIELD_SCOPES_SUPPORTED)
        # Absent defaults to S256 — the only method the gateway's own leg accepts and the
        # common case — while present-but-empty stays empty, so the consent branch's
        # delivery guard can refuse a projection that would deliver the parameter empty.
        method = auth.get(FIELD_CODE_CHALLENGE_METHOD)
        code_challenge_method = "S256" if method is None else str(method)
        return ToolsetSettings(
            authentication_type=_optional_str(auth.get(FIELD_AUTHENTICATION_TYPE)),
            client_id=str(auth.get(FIELD_CLIENT_ID) or ""),
            authorization_endpoint=str(auth.get(FIELD_AUTHORIZATION_ENDPOINT) or ""),
            code_challenge=str(auth.get(FIELD_CODE_CHALLENGE) or ""),
            code_challenge_method=code_challenge_method,
            # The projection's `redirect_uri` member is not read: the gateway derives its
            # own upstream callback (the upstream-authorization request's discipline). The
            # member stays tolerated here for projection-compatibility — no leg consumes it.
            scopes_supported=tuple(scope for scope in scopes if isinstance(scope, str))
            if isinstance(scopes, list)
            else (),
            # The statuses are read from this same answer's enrichment. Their absence is
            # the fail-closed rule, never a signal to ask again: an answer with no
            # readable status at either level is not signed in, and the flow falls into
            # the kind branch — on a Core build whose listing route does not enrich the
            # statuses, no short-circuit ever fires (an OAUTH toolset re-runs its
            # consent, the benign loop; a non-OAuth toolset is refused as ever).
            user_level_auth_status=_optional_str(
                auth.get(FIELD_USER_LEVEL_AUTH_STATUS)
            ),
            global_auth_status=_optional_str(auth.get(FIELD_GLOBAL_AUTH_STATUS)),
        )

    async def read_toolset_for_flow(
        self, toolset: str, identity_token: str
    ) -> tuple[ToolsetSettings, ToolsetStatus]:
        """The flow's Core read: the settings it builds the upstream leg from, and the
        user's current status for the short-circuit.

        One request. The listing read is the flow's availability oracle — its
        authorization is the data path's own deployment resolution, which is what makes
        the 403 refusal the flow's DIAL authorization check — and the same answer
        carries the settings projection and the per-caller statuses, so there is no
        second route to ask: the route asked twice could only repeat its answer.

        It is one decision step with one credential and one purpose, which is what the
        token-use rule cares about: this step and the credential call that follows it
        are the identity token's whole use — answering "may this user sign in to this
        toolset, and are they already signed in?", then establishing the upstream
        credential — and never anything else. The decision step always spends one
        presentation; the credential call adds its own.
        """
        settings = await self.read_toolset_settings(toolset, identity_token)
        return settings, _status_of_settings(settings)

    async def read_app_for_flow(self, app: str, identity_token: str) -> None:
        """Read an app as this user, for the flow's DIAL authorization and existence check.

        `GET /openai/applications/{id}` with the live user's verified identity token, in the
        same trust position as the toolset's listing read: Core answers 403 when the user
        cannot read the app, so DIAL authorization is enforced before any token is minted,
        and 404 when Core does not know the name — the apps namespace's existence refusal.
        A 401 is the trust fault the listing read's is, the one shared mapping raising it.

        Four shapes are distinguished, and the last is load-bearing: an unreachable or
        unreadable answer fails closed as the deployment-fault `CoreError`, never taken for
        an existence answer. This read parses nothing beyond existence and readability —
        the per-service statuses the route may enrich are not read, because for an app they
        are not a sign-in state; the app is credential-free by construction, so the flow has
        nothing to learn from them.
        """
        await self._get_json(
            self.application_url(app),
            identity_token,
            access_denied_error=AppAccessDeniedError,
            unknown_error=AppUnknownError,
        )


def _status_of_settings(settings: ToolsetSettings) -> ToolsetStatus:
    """The statuses the listing read carried, as a status object."""
    return ToolsetStatus(
        user_level_auth_status=settings.user_level_auth_status,
        global_auth_status=settings.global_auth_status,
    )


def _optional_str(value: object) -> str | None:
    """A JSON value as the string it is, or `None` when it is not a string.

    A status Core does not return and a status returned as something other than a string
    are the same thing to this flow: not a status it can read, so not a short-circuit.
    """
    return value if isinstance(value, str) else None
