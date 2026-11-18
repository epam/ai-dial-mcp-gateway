"""Discovery documents, the JWKS, and the dynamic client registration endpoint.

The discovery surface is unauthenticated by necessity — a harness must be able to
discover the authorization server before it has a client identity — so each document is
static, derived entirely from configuration, and carries nothing that varies by caller.

Registration is one of several unauthenticated endpoints that accept a body — the token
and revocation endpoints take one too, which is why each of them reads it under a byte
cap rather than this one having that discipline to itself. The registration endpoint is
the one that is config-gated, off by default: while off it answers the documented
disabled-error and is absent from the authorization-server metadata, so no client is
steered onto a path that cannot register anything. While on, a registration is persisted
before the response is returned: a client caches the id it receives, and answering before
the write would let a restart erase an id the client already holds.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from gateway import errors
from gateway.discovery import (
    AUTHORIZATION_SERVER_PATH,
    AUTHORIZATION_SERVER_PATH_INSERTION,
    OPENID_CONFIGURATION_PATH,
    OPENID_CONFIGURATION_PATH_INSERTION,
    PROTECTED_RESOURCE_PREFIX,
    app_protected_resource_metadata,
    authorization_server_metadata,
    protected_resource_metadata,
)
from gateway.redirect_uris import ADMISSION_RULE, scheme_admission_refusal
from gateway.requests import capped_body
from gateway.runtime import Runtime
from gateway.settings import Settings
from gateway.state import new_client_id
from gateway.store import RegistrationError

router = APIRouter()

# The one field a registration body must carry: without redirect URIs there is nothing an
# authorization request could be validated against, so the registration would be an id
# that can never complete a flow.
_REQUIRED_REGISTRATION_FIELD = "redirect_uris"

# The registration document's response fields, in the names RFC 7591 gives them.
_CLIENT_ID_ISSUED_AT_MEMBER = "client_id_issued_at"

_JSON = "application/json"

# The refusal for a body larger than the configured cap. It names the limit rather than the
# bytes received, so the message is the same for every oversized body and cannot be used to
# probe how much the gateway read before refusing.
_OVERSIZED_BODY = (
    "the request body is larger than this gateway accepts for a registration; a "
    "registration is a small JSON object, so this one is not one"
)

# A registration record whose creation instant is not the string the store writes is not
# one this gateway produced. Answering a substituted time would be a wrong value the
# client caches, so the response fails instead — the same choice the store makes when it
# refuses to start over a record it cannot read.
_UNREADABLE_INSTANT = (
    "the registration record carries no readable creation instant, so this gateway "
    "cannot answer when it was issued"
)


@router.get(AUTHORIZATION_SERVER_PATH)
@router.get(OPENID_CONFIGURATION_PATH)
@router.get(AUTHORIZATION_SERVER_PATH_INSERTION)
@router.get(OPENID_CONFIGURATION_PATH_INSERTION)
async def authorization_server(request: Request) -> JSONResponse:
    """The flat RFC 8414 metadata document for the gateway's single issuer.

    One handler answers the canonical location and every alias a discovering client may
    try (the OpenID Connect location and both path-insertion forms), so the document at
    each is the same builder's output and cannot drift. The path-insertion routes capture a
    suffix and this handler does not take it: no part of the request path reaches the body.
    Every method but `GET` is the framework's `405`, on the aliases as on the canonical path.
    """
    runtime: Runtime = request.app.state.runtime
    return JSONResponse(authorization_server_metadata(runtime.settings))


@router.get(PROTECTED_RESOURCE_PREFIX + "/dial/{path:path}/mcp")
async def protected_resource(path: str, request: Request) -> JSONResponse:
    """The RFC 9728 document for one served toolset, or 404 for a path the guard refuses.

    The route captures the path multi-segment (`{path:path}`), but the offered path it
    resolves is read from the **raw request path** (`request.scope["raw_path"]`), not from
    the path parameter: FastAPI delivers path parameters decoded, and both the guard (which
    decodes the offered path exactly once) and the echo-offered rule (which needs the wire
    spelling) require the form the client actually sent. The decoded parameter is a fallback
    for the shape the router never forwards.

    The served set is decided by the request-time path guard and the optional operator
    restriction, and by nothing else on this surface: a guard-passing, restriction-admitted
    path is served its document whether or not Core's registry holds it. That is the mirror
    property, stated as the justification rather than as an accident. The gateway's
    unauthenticated discovery tier brings nothing Core's own does not: Core's MCP path
    answers an unauthenticated call — for a toolset that exists or one that does not — with
    401 and a challenge naming the protected-resource document, because its auth check
    precedes any registry lookup, and Core's own protected-resource route answers any
    well-formed path with a registry-independent echo document. So no unauthenticated tier
    on either side carries an existence oracle, and existence is decided post-authentication
    at the flow's per-user listing read — the toolset namespace's existence refusal. This route
    therefore makes no Core call at all: it costs the gateway one static document, and its
    availability is the gateway's own.

    Like every other unauthenticated surface here, the work is bounded before it is done:
    this route joins the same per-source and global rate limiter the authorization, token,
    and revocation endpoints use, so the record volume the guard's refusals produce
    is charged against the same limit as the requests that carry them. Past the limit the
    request is answered with the limiter's 429 and writes *nothing* — not even the
    limiter's own `rate_limited` record the other sites write — because a record written per
    refused request would let the log grow at whatever rate the caller chose, which is the
    amplification this bound exists to close. The bound is the limit itself, and it holds
    because the refusal is silent.
    """
    runtime: Runtime = request.app.state.runtime

    # Checked before the path guard, so an over-limit request never reaches the guard and
    # never writes the path-carrying guard record.
    if not runtime.limiter.allow(errors.client_source(request)):
        return errors.oauth_error(
            errors.TEMPORARILY_UNAVAILABLE,
            "too many discovery requests from this source; try again in a minute",
            status_code=429,
        )

    offered = _offered_path(request, path)
    refusal = runtime.settings.toolset_guard_refusal(offered)
    if refusal is not None:
        runtime.audit.flow_refused(refusal, name=offered, resource_kind="toolset")
        return JSONResponse({"detail": "unknown toolset"}, status_code=404)
    return JSONResponse(
        protected_resource_metadata(offered, runtime.settings, offered=offered)
    )


@router.get(PROTECTED_RESOURCE_PREFIX + "/apps/{path:path}/mcp")
async def app_protected_resource(path: str, request: Request) -> JSONResponse:
    """The RFC 9728 document for one served app, or 404 for a path the guard refuses.

    The apps twin of the toolset discovery route: the offered path is read from the raw
    request path for the guard and the echo-offered rule, exactly as the toolset route does.

    The served set is decided by the request-time app path guard and the optional apps
    restriction, and by nothing else on this surface: a guard-passing, restriction-admitted
    path is served its document whether or not Core's registry holds it. That is the mirror
    property, extended to the second namespace. The gateway's apps tier brings nothing Core's
    own does not: Core serves the apps MCP path's unauthenticated 401 challenge and the apps
    metadata route from the **same** `toolsets.security.authorizationServers` configuration
    that serves the toolset tier (there is no apps-specific security configuration), and both
    are registry-independent — its auth check precedes any registry lookup, and its metadata
    document is built from configuration with the requested path echoed as `resource`. So no
    unauthenticated tier on either side carries an existence oracle, and existence is decided
    post-authentication at the flow's app read — the apps namespace's existence refusal. This
    route therefore makes no Core call at all: it costs the gateway one static document, and
    its availability is the gateway's own.

    Like every other unauthenticated surface here, the work is bounded before it is done:
    this route joins the same per-source and global rate limiter the toolset discovery route
    uses, so the record volume the guard's refusals produce is charged against the same limit
    as the requests that carry them. Past the limit the request is answered with the limiter's
    429 and writes *nothing* — not even the limiter's own `rate_limited` record — because a
    record written per refused request would let the log grow at whatever rate the caller
    chose. The bound is the limit itself, and it holds because the refusal is silent.
    """
    runtime: Runtime = request.app.state.runtime

    # Checked before the path guard, so an over-limit request never reaches the guard and
    # never writes the path-carrying guard record.
    if not runtime.limiter.allow(errors.client_source(request)):
        return errors.oauth_error(
            errors.TEMPORARILY_UNAVAILABLE,
            "too many discovery requests from this source; try again in a minute",
            status_code=429,
        )

    offered = _offered_path(request, path)
    refusal = runtime.settings.app_guard_refusal(offered)
    if refusal is not None:
        runtime.audit.flow_refused(refusal, name=offered, resource_kind="app")
        return JSONResponse({"detail": "unknown app"}, status_code=404)
    return JSONResponse(
        app_protected_resource_metadata(offered, runtime.settings, offered=offered)
    )


def _offered_path(request: Request, decoded: str) -> str:
    """The offered spelling of the resource path, as the wire carried it.

    FastAPI delivers the path parameter decoded, and both the guard (which decodes the
    offered path exactly once) and the echo-offered rule (which needs the wire spelling)
    require the form the client sent, so the offered path is read from
    `request.scope["raw_path"]`: the raw request path (bytes, latin-1-preservable) with the
    well-known prefix, the kind segment (`dial`/`apps`), and the trailing `/mcp` suffix
    stripped. The raw path never carries a query string. When the raw path is unavailable or
    does not carry the expected shape, the decoded parameter is returned — a defect reachable
    only through a request shape the router never forwards.
    """
    raw = request.scope.get("raw_path")
    if isinstance(raw, bytes):
        text = raw.decode("latin-1")
        marker = f"{PROTECTED_RESOURCE_PREFIX}/"
        suffix = "/mcp"
        if text.startswith(marker) and text.endswith(suffix):
            rest = text[len(marker) : -len(suffix)]
            kind, _, offered = rest.partition("/")
            if kind in ("dial", "apps") and offered:
                return offered
    return decoded


@router.get("/dial/jwks.json")
async def jwks(request: Request) -> JSONResponse:
    """The public JWKS the deployment's Core verifies gateway tokens against.

    Public key material by construction: the modulus and exponent are what verification
    needs. The private key is not reachable from this document or from any value it is
    derived from. Every keyset entry's public half is published — the active entry first, so
    a kid-less verifier resolves to the key that signs — and the retained entries ride
    beside it, so outstanding tokens verify through a rotation's drain window.
    """
    runtime: Runtime = request.app.state.runtime
    return JSONResponse(runtime.signing_keyset.jwks())


@router.post("/dial/register")
async def register(request: Request) -> Response:
    """Register a client dynamically, when the flag enables it.

    Refusals are plain language because the caller here is a person wiring up a tool as
    often as it is a program, and the two failures it can hit — registration disabled, and
    the store at its cap — are both operator actions rather than client mistakes.
    """
    runtime: Runtime = request.app.state.runtime

    if not runtime.settings.dcr_enabled:
        # The same status a client would get for an endpoint that does not exist, which
        # is what it is: the metadata document does not advertise this path.
        runtime.audit.flow_refused("registration_disabled")
        return errors.oauth_error(
            errors.INVALID_REQUEST,
            "dynamic client registration is not enabled on this gateway; clients "
            "register by presenting a client-id metadata document URL, or are "
            "pre-registered by the operator",
            status_code=404,
        )

    if not runtime.limiter.allow(errors.client_source(request)):
        runtime.audit.flow_refused("rate_limited")
        return errors.oauth_error(
            errors.TEMPORARILY_UNAVAILABLE,
            "too many registration requests from this source; try again in a minute",
            status_code=429,
        )

    body, refusal = await _registration_body(request, runtime.settings)
    if refusal is not None:
        runtime.audit.flow_refused(
            "invalid_registration", client_id=_string_or_none(body.get("client_id"))
        )
        return errors.oauth_error(errors.INVALID_REQUEST, refusal)

    refusal = _registration_refusal(body, runtime.settings)
    if refusal is not None:
        runtime.audit.flow_refused(
            "invalid_registration", client_id=_string_or_none(body.get("client_id"))
        )
        return errors.oauth_error(errors.INVALID_REQUEST, refusal)

    redirect_uris = [
        uri for uri in body[_REQUIRED_REGISTRATION_FIELD] if isinstance(uri, str)
    ]
    client_name = body.get("client_name")
    client_id = new_client_id()
    try:
        record = runtime.registrations.add(client_id, redirect_uris, client_name)
    except RegistrationError as exc:
        # The one way this path fails on the operator's side rather than the client's: the
        # cap. It is reported as a plain-language refusal and the existing registrations
        # are left exactly as they were.
        runtime.audit.flow_refused(
            "registration_cap_reached", client_id=_string_or_none(body.get("client_id"))
        )
        return errors.oauth_error(errors.INVALID_REQUEST, str(exc))

    runtime.audit.client_registered(client_id, source="dcr")
    return JSONResponse(
        {
            "client_id": client_id,
            "redirect_uris": record["redirect_uris"],
            "client_name": record.get("client_name"),
            # Token-endpoint authentication is `none` for every client here: they are
            # all public PKCE clients, and there is no secret to hand out. The value is
            # the RFC 7591 method name, not a credential (bandit B105 triaged).
            "token_endpoint_auth_method": "none",  # nosec B105
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            _CLIENT_ID_ISSUED_AT_MEMBER: _issued_at(record),
        },
        status_code=201,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _issued_at(record: dict[str, object]) -> int:
    """The registration's creation instant as RFC 7591 answers it: epoch seconds.

    The store keeps the instant as an ISO-8601 string because that is the store's own
    at-rest format — unread for arithmetic and an internal detail of the gateway's file.
    RFC 7591 §3.2.1 defines this response member as a JSON number of seconds since
    1970-01-01T00:00:00Z, and a strict client rejects the whole document when the type is
    wrong, so the conversion belongs here at the wire boundary rather than in the store.

    The number is parsed from the stored instant, never sampled fresh: the answered value
    must be the instant the store recorded. A second `now()` would answer a time that
    disagrees with the persisted record by however long the request took, and it would
    answer a new time on the idempotent re-registration branch, where the record being
    returned is an old one.
    """
    created_at = record["created_at"]
    if not isinstance(created_at, str):
        raise RegistrationError(_UNREADABLE_INSTANT)
    return int(datetime.fromisoformat(created_at).timestamp())


async def _registration_body(
    request: Request, settings: Settings
) -> tuple[dict[str, Any], str | None]:
    """The registration request's JSON body, or the reason it is not one.

    The body is read under a byte cap *while it is read*, not after: this endpoint is
    unauthenticated and takes a body, so a request that is merely large must cost the
    gateway a bounded amount of memory rather than however much its sender chose. The cap
    is on the bytes, which is the dimension a body can be unbounded in — the per-record
    bounds below are on what a single registration may *contain*.
    """
    expected = f"the request body must be a JSON object sent as {_JSON}"
    raw = await capped_body(request, settings.dcr_max_body_bytes)
    if raw is None:
        return {}, _OVERSIZED_BODY
    try:
        body: Any = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return {}, expected
    if not isinstance(body, dict):
        return {}, expected
    return body, None


def _string_or_none(value: object) -> str | None:
    """A registration body's value as a string, or `None` when it is not one.

    The audit trail records a client id only when the body presented a string: a refusal
    that carried a number, a list, or a nested object is recorded with no client id at all
    rather than with a rendering of whatever was sent. The field is one the caller
    controls, so the only shape worth copying is the shape this gateway understands.
    """
    return value if isinstance(value, str) else None


def _registration_refusal(body: dict[str, Any], settings: Settings) -> str | None:
    """The reason a registration body is unusable, or `None` when it is usable.

    A registration without redirect URIs would issue a client id no authorization
    request could ever be completed for — the client would discover the problem at its
    first sign-in instead of here. The bounds on the list's length, on each URI's length,
    and on the client name are the per-record half of the size discipline: without them a
    single accepted registration could store a document far larger than the request that
    carried it was allowed to be, and the store's own cap bounds the number of records,
    not their size.

    The other half is the body cap these values are read under, and the settings model
    holds the two together: it refuses a configuration whose per-record maxima could not
    fit inside that cap, so a body the maxima permit is always one the endpoint can read.
    The bounds checked here therefore describe what a registration may contain, and never
    the reason one would be refused for size alone.
    """
    return _redirect_uris_refusal(body, settings) or _client_name_refusal(
        body, settings
    )


def _redirect_uris_refusal(body: dict[str, Any], settings: Settings) -> str | None:
    """The reason the body's `redirect_uris` is unusable, or `None` when it is usable."""
    redirect_uris = body.get(_REQUIRED_REGISTRATION_FIELD)
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return (
            "redirect_uris is required and must list at least one URI; without it no "
            "authorization request could be validated for this client"
        )
    if len(redirect_uris) > settings.dcr_max_redirect_uris:
        return (
            f"redirect_uris must list at most {settings.dcr_max_redirect_uris} URIs; "
            f"a registration with more than that is not one this gateway can serve"
        )
    for uri in redirect_uris:
        if not isinstance(uri, str) or not uri:
            return "every entry in redirect_uris must be a URI string"
        if len(uri) > settings.dcr_max_redirect_uri_length:
            return (
                f"every entry in redirect_uris must be at most "
                f"{settings.dcr_max_redirect_uri_length} characters long"
            )
        # The admission rule, upstream of the exact-match validation: a plain-`http` redirect
        # on a real host is the collector the authorization response would cross in
        # cleartext, so it is refused here rather than admitted and matched against later.
        refusal = scheme_admission_refusal(uri)
        if refusal is not None:
            return f"redirect_uris entry {uri!r} is not admissible: {ADMISSION_RULE}"
    return None


def _client_name_refusal(body: dict[str, Any], settings: Settings) -> str | None:
    """The reason the body's `client_name` is unusable, or `None` when it is usable."""
    client_name = body.get("client_name")
    if client_name is not None and not isinstance(client_name, str):
        return "client_name must be a string when present"
    if isinstance(client_name, str) and (
        len(client_name) > settings.dcr_max_client_name_length
    ):
        return (
            f"client_name must be at most {settings.dcr_max_client_name_length} "
            f"characters long"
        )
    return None
