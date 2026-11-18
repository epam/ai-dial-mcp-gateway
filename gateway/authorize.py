"""The `/dial/authorize` entry.

This endpoint validates a client's authorization request and allocates the flow state
every later leg reads. Group 3 lands it as the entry that validates and allocates: the
redirect that follows it — to the identity provider — is the federation stage's work.

The `resource` parameter is required and is the resource disambiguator. One flat
authorization server serves both resource kinds — toolsets and apps — so the resource is
the only thing that says which one a request is for; a missing one is `invalid_target`
rather than a default, because guessing it would address the issued token to a resource
the client never named. The single escape is the operator's one-toolset inference
setting, which is off by default and resolves only to a toolset.

A client's `scope` parameter is accepted and dropped. The identity-provider leg requests
exactly the gateway's own pre-registered client's default scopes, and relaying a client's
scopes there would fail the whole leg on any scope that client does not carry — including
scopes that are not client scopes in the realm at all. Rejecting the parameter instead
would break the clients that faithfully echo the upstream scopes they were advertised,
which are exactly the well-behaved ones.

Each check refuses by raising, and one handler turns every refusal into the response its
audience expects. Which audience that is depends on how far validation got: until the
client and its redirect URI are established, a redirect would be an open redirect, so the
refusal is answered where it was asked; once they are, the refusal is returned to the
client's own registered redirect URI, as an OAuth client expects.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse

from gateway import errors
from gateway.cimd import (
    CimdError,
    ResolvedClient,
    redirect_uri_allowed,
    resolve_client_async,
)
from gateway.flow import begin_identity_leg, identity_error_response
from gateway.idp import IdentityProviderError
from gateway.runtime import Runtime
from gateway.state import FlowRecord

# The MCP authorization specification and RFC 8707 both settle on this error for a
# resource that is absent or is not one this server serves.
_INVALID_TARGET_DESCRIPTION = (
    "the `resource` parameter must name a toolset or app this gateway serves; it is "
    "required because one authorization server serves both resource kinds"
)

# The refusal for a resource whose URI does not resolve to a path of a kind this gateway
# serves. One description covers the unresolvable shape and every path-guard refusal,
# because the client's remedy is the same and the surface answers them all as
# `invalid_target`; only the audit reason says which class refused it.
_UNKNOWN_RESOURCE_DESCRIPTION = (
    "the `resource` parameter names no toolset or app this gateway serves; it must be the "
    "resource's MCP URL as its protected-resource document advertises it"
)

# PKCE is mandatory, and S256 is the only method accepted: the code is a bearer string in
# a URL, and the challenge is what stops an intercepted one from being redeemed.
_PKCE_DESCRIPTION = "code_challenge is required and code_challenge_method must be S256"

# The bound on a client's `state`. It is optional and echoed verbatim when present, so its
# length is the caller's choice on two artifacts at once — the in-memory flow record and the
# redirect it is echoed on. Every other caller-chosen length on this surface is bounded (the
# audit facts, the body caps), and a fielded client's state is orders of magnitude under
# this: OAuth libraries emit tens of bytes. The refusal is `invalid_request` with its own
# fixed-vocabulary reason, which is what distinguishes it from the shape refusals beside it.
_STATE_MAX_BYTES = 2048
_STATE_REFUSAL_DESCRIPTION = (
    "the `state` parameter is longer than this gateway accepts; a state is a short "
    "correlation string, not a payload"
)

router = APIRouter()


class AuthorizeError(Exception):
    """An authorization request refused at some point during validation.

    `redirect_uri` is set only once the client and its redirect URI have been
    established: until then a redirect would send the error to an unvalidated target,
    which is an open redirect. Its presence is therefore also the answer to which
    response shape the refusal gets.

    `reason` is the audit trail's fixed token for this refusal class, carried on the
    exception so the raise site — which is where the class is decided — states it once,
    and the handler that answers the request records it. It is never rendered into the
    response: what a harness is told is the RFC 6749 `error`/`description` pair, and what
    the operator's log records is this token.
    """

    def __init__(
        self,
        error: str,
        description: str,
        *,
        reason: str,
        redirect_uri: str | None = None,
        status_code: int = 400,
    ) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.reason = reason
        self.redirect_uri = redirect_uri
        self.status_code = status_code


def _single_string(value: object) -> str | None:
    """Read a parameter whose value must be a non-empty string, if present.

    A repeated parameter resolves to the query parser's last-wins reading — this
    endpoint's parsing is lenient where the token endpoint's refuses, because every
    value here is validated downstream (the resource, the PKCE challenge, the
    state's length bound) before it can affect anything. Query strings are parsed
    leniently too (blank values dropped) so that a `?resource=` produced by a
    client's string concatenation is treated as absent rather than as a value.
    """
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        return None
    return value


@router.get("/dial/authorize")
async def authorize(request: Request) -> Response:
    """Validate an authorization request and allocate its flow record."""
    runtime: Runtime = request.app.state.runtime
    settings = runtime.settings

    params = request.query_params
    client_id = _single_string(params.get("client_id"))
    redirect_uri = _single_string(params.get("redirect_uri"))
    resource = _single_string(params.get("resource"))
    # The client's `state` is OPTIONAL and its handling is a stated rule: present, it is
    # stored on the flow record at allocation and echoed back *unchanged* on the final
    # redirect (never modified, filtered, or extended); absent, nothing is echoed — the
    # CSRF binding it does for a client is already carried here by PKCE S256, the required
    # and validated `resource`, single-use short-lived codes, and the unguessable flow id
    # that round-trips every browser leg. The one bound on it is the length check below.
    state = params.get("state")
    if not isinstance(state, str):
        state = None

    # The endpoint is unauthenticated, so its work is bounded first: a flood is turned
    # away before any validation runs and before any state is allocated. The record
    # carries the reason only — a refusal at the rate the limiter exists to bound must not
    # also be a record whose size the caller chooses, or the limiter would bound work and
    # not the log.
    if not runtime.limiter.allow(errors.client_source(request)):
        runtime.audit.flow_refused("rate_limited")
        return errors.oauth_error(
            errors.TEMPORARILY_UNAVAILABLE,
            "too many authorization requests from this source; try again in a minute",
            status_code=429,
        )

    try:
        flow = await _validated_flow(
            runtime,
            response_type=_single_string(params.get("response_type")),
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=_single_string(params.get("code_challenge")),
            code_challenge_method=_single_string(params.get("code_challenge_method")),
            resource=resource,
            state=state,
            client_source=errors.client_source(request),
        )
    except AuthorizeError as refusal:
        runtime.audit.flow_refused(
            refusal.reason,
            client_id=client_id,
            redirect_uri=redirect_uri,
            resource=resource,
            # The value the request offered, kind-neutral: the resource's kind is not
            # known at every refusal class here (an unregistered redirect URI is refused
            # before the resource is resolved), so the field names the value the request
            # offered without claiming a namespace. `resource_kind` is set only where a
            # site serves exactly one kind (the discovery guards).
            name=settings.resource_path_from_resource(resource) if resource else None,
        )
        if refusal.redirect_uri is None:
            return errors.oauth_error(
                refusal.error, refusal.description, status_code=refusal.status_code
            )
        return errors.redirect_error(
            refusal.redirect_uri,
            refusal.error,
            refusal.description,
            state=state,
            issuer=settings.gateway_public_origin,
        )

    runtime.audit.flow_allocated(flow)

    # The validated request's next leg: the identity provider, under this gateway's own
    # PKCE client. The verifier is generated here and stays on the flow's server-side
    # record, so the browser carries a challenge and a flow id and nothing else — and the
    # client's own `scope` parameter is not part of the redirect this builds.
    try:
        destination = await begin_identity_leg(flow, settings, runtime.idp)
    except IdentityProviderError as failure:
        # Building the redirect is the leg's first use of its endpoint set, and where
        # that set cannot be resolved — an unreachable or invalid discovery document —
        # the sign-in fails here, with the leg's own operator-facing page rather than a
        # bare server error.
        return identity_error_response(failure)
    return RedirectResponse(
        destination,
        status_code=302,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


async def _validated_flow(  # noqa: PLR0913 - one keyword per request parameter, validated in one place
    runtime: Runtime,
    *,
    response_type: str | None,
    client_id: str | None,
    redirect_uri: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
    resource: str | None,
    state: str | None,
    client_source: str,
) -> FlowRecord:
    """Validate every parameter of an authorization request, or refuse it.

    The order is the order of trust: the request shape first, then the client, then the
    redirect URI (which is what makes a redirect answerable at all), then PKCE, and the
    resource last because its refusal is a redirect to a target that must already be
    validated to be a redirect target at all.

    Asynchronous because resolving a client can fetch a metadata document, and that fetch
    runs on a worker thread rather than on the event loop every request shares: this
    endpoint is unauthenticated, so its fetch is a request any caller can make slow.
    """
    if state is not None and len(state.encode("utf-8")) > _STATE_MAX_BYTES:
        # The one caller-chosen length on the allocation path that would otherwise be
        # unbounded, bounded with the rest. Refused before anything is resolved or
        # allocated — the client id has not been looked up and no record exists — and
        # answered directly rather than redirected: the redirect URI is not established
        # yet, and a redirect would carry the very state this refusal bounds.
        raise AuthorizeError(
            errors.INVALID_REQUEST,
            _STATE_REFUSAL_DESCRIPTION,
            reason="oversized_state",
        )
    if response_type != "code":
        raise AuthorizeError(
            errors.INVALID_REQUEST,
            "only response_type=code is supported",
            reason="invalid_response_type",
        )
    if client_id is None:
        raise AuthorizeError(
            errors.INVALID_REQUEST, "client_id is required", reason="missing_client_id"
        )

    client = await _resolve_client(client_id, runtime)
    redirect = _present(redirect_uri, "redirect_uri", redirect_uri=None)
    if not redirect_uri_allowed(redirect, client):
        # Answered directly rather than redirected: an unregistered redirect URI is
        # exactly the target an attacker would want an error forwarded to.
        raise AuthorizeError(
            errors.INVALID_REQUEST,
            "redirect_uri is not one this client registered",
            reason="unregistered_redirect_uri",
        )

    if code_challenge is None or (code_challenge_method or "").upper() != "S256":
        raise AuthorizeError(
            errors.INVALID_REQUEST,
            _PKCE_DESCRIPTION,
            reason="unacceptable_code_challenge",
            redirect_uri=redirect,
        )

    resolved = _resolve_resource(resource, runtime, redirect_uri=redirect)
    return runtime.flows.create(
        client_id=client.client_id,
        redirect_uri=redirect,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        # The record carries the resource's canonical identity: the resource URI is rebuilt
        # from the canonical path, so two spellings of one resource are one flow, one
        # audience, one refresh match — never two.
        resource=resolved.resource_uri,
        toolset=resolved.path,
        resource_kind=resolved.kind,
        client_name=client.client_name,
        client_source=client_source,
        state=state,
    )


async def _resolve_client(client_id: str, runtime: Runtime) -> ResolvedClient:
    """Resolve a client id through the priority order, or refuse the request.

    Dynamic registration is tried last and only while it is enabled: the fallback must
    never be the reason a client id resolves, and while the flag is off a stored
    registration stays dormant rather than resolving.
    """
    settings = runtime.settings
    try:
        return await resolve_client_async(client_id, settings, runtime.client_cache)
    except CimdError:
        if not settings.dcr_enabled:
            raise AuthorizeError(
                errors.INVALID_CLIENT,
                "this client id is not registered with the gateway",
                reason="unknown_client",
            ) from None

    record = runtime.registrations.get(client_id)
    if record is None:
        raise AuthorizeError(
            errors.INVALID_CLIENT,
            "this client id is not registered with the gateway; dynamic client "
            "registration is enabled, so register it before authorizing",
            reason="unknown_client",
        )
    redirect_uris = record.get("redirect_uris")
    client_name = record.get("client_name")
    return ResolvedClient(
        client_id=client_id,
        redirect_uris=tuple(uri for uri in redirect_uris if isinstance(uri, str))
        if isinstance(redirect_uris, list)
        else (),
        client_name=client_name if isinstance(client_name, str) else None,
        source="dcr",
    )


class _ResolvedResource:
    """What an authorization request's resource resolves to: kind, canonical path, identity.

    `path` is the resource's canonical path (the decoded resource id, canonically encoded),
    `resource_uri` is the canonical resource URI derived from it (the flow's identity — the
    record's `resource`, the token audience, the refresh match), and `kind` is `toolset` or
    `app`. Both `path` and `resource_uri` are canonical, so two spellings of one resource
    resolve to one identity.
    """

    __slots__ = ("kind", "path", "resource_uri")

    def __init__(self, *, kind: str, path: str, resource_uri: str) -> None:
        self.kind = kind
        self.path = path
        self.resource_uri = resource_uri


def _resolve_resource(
    resource: str | None, runtime: Runtime, *, redirect_uri: str
) -> _ResolvedResource:
    """Resolve the request's resource to a served path of its kind, or refuse the request.

    The resource URI's path shape names the kind — `/dial/{path}/mcp` a toolset,
    `/apps/{path}/mcp` an app — because one flat authorization server serves both kinds, and
    the resource is the only thing that says which resource, and which kind, a request is
    for. The path is one or more segments. Each shape then passes its own kind's guard: the
    toolset guard (decoded per-segment rules, reserved first segment, toolset restriction)
    for a toolset, and the app guard (the decoded rules, apps restriction) for an app.

    This endpoint decides the path's shape and its place in its kind's restriction, and
    nothing more: a guard-passing, admitted path that Core does not know is shape-identical
    to a served one and is refused later, at the flow's authenticated read of that kind —
    the toolset listing read for a toolset, the app read for an app, one existence refusal
    per kind, both post-authentication. No Core call is designed here, so existence cannot
    be decided here.

    An accepted spelling is canonicalized: the resolution returns the canonical path and the
    canonical resource URI, so the flow record, the token audience, and the refresh match
    all carry one identity whatever spelling arrived.

    Each refusal is redirected rather than answered directly: by the time it is reached the
    client and its redirect URI are both validated, so a redirect here goes where the client
    asked and nowhere else. The guard's reason is carried on the exception so the trail
    distinguishes a shape violation from a reserved segment from a restriction exclusion.
    """
    settings = runtime.settings
    if resource is None:
        if settings.gateway_infer_resource_single_toolset:
            # Inference resolves only through the toolset restriction and never to an app.
            entry = next(iter(settings.toolsets))
            # The entry is canonicalized exactly as a request-supplied path is below, so the
            # inferred identity is the one canonical form however the operator spelled the
            # entry: the flow record, the token audience, and the refresh match all carry it.
            canonical = settings.canonical_path(entry) or entry
            return _ResolvedResource(
                kind="toolset",
                path=canonical,
                resource_uri=settings.toolset_resource_uri(canonical),
            )
        raise AuthorizeError(
            errors.INVALID_TARGET,
            _INVALID_TARGET_DESCRIPTION,
            reason="missing_resource",
            redirect_uri=redirect_uri,
        )

    resolved = settings.resource_kind_and_path(resource)
    if resolved is None:
        raise AuthorizeError(
            errors.INVALID_TARGET,
            _UNKNOWN_RESOURCE_DESCRIPTION,
            reason="unknown_resource",
            redirect_uri=redirect_uri,
        )

    kind, path = resolved
    refusal = (
        settings.toolset_guard_refusal(path)
        if kind == "toolset"
        else settings.app_guard_refusal(path)
    )
    if refusal is not None:
        raise AuthorizeError(
            errors.INVALID_TARGET,
            _UNKNOWN_RESOURCE_DESCRIPTION,
            reason=refusal,
            redirect_uri=redirect_uri,
        )
    # The guard has already proven the path decodes strictly (it returns a shape refusal
    # otherwise), so the canonical form is available here; the fallback keeps the resolution
    # total rather than re-raising a class the guard already covered.
    canonical = settings.canonical_path(path) or path
    resource_uri = (
        settings.toolset_resource_uri(canonical)
        if kind == "toolset"
        else settings.app_resource_uri(canonical)
    )
    return _ResolvedResource(kind=kind, path=canonical, resource_uri=resource_uri)


def _present(value: str | None, name: str, *, redirect_uri: str | None) -> str:
    """A required parameter, present and non-empty, or a refusal naming it."""
    if value is None:
        raise AuthorizeError(
            errors.INVALID_REQUEST,
            f"{name} is required",
            # The one parameter this helper serves on this endpoint, and the audit token
            # names it: the helper is not a general one, and a second caller would need its
            # own token rather than silently reusing this.
            reason="missing_redirect_uri",
            redirect_uri=redirect_uri,
        )
    return value
