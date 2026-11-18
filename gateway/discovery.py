"""Discovery documents: the flat authorization-server metadata and per-resource documents.

Two documents, and the split between them is deliberate. The authorization-server
metadata is a single flat document at the host root for a single path-less issuer: every
resource kind shares it, so the endpoint URLs in it are shared too, and a client that
discovered the authorization server once does not have to rediscover it per resource.

The protected-resource document is name-derived and served per resource kind — a toolset's
at `/dial/{name}/mcp`, an app's at `/apps/{name}/mcp`. It carries the resource URI and —
where the operator restriction pins the toolset — the upstream scopes it echoes. It carries
no authentication kind. Under dynamic serving this surface has no kind source: the
restriction entry declares none, and the kind a flow acts on is Core's, read per flow at
the flow's authenticated settings read. Echoing one here would mean a Core call, which
this surface deliberately makes none of.

Neither document advertises scopes on the gateway's behalf. The gateway enforces no
scopes of its own, and a client faithfully echoes the scopes it is advertised — so
advertising any would invite them back, onto a federation leg that fails on a scope its
client does not carry. The toolset's upstream scopes are a different thing and belong to
the upstream leg; they are echoed verbatim on the protected-resource document, where the
client's use of them is informational.
"""

from __future__ import annotations

from typing import Any

from gateway.settings import Settings, ToolsetMapping

# The path prefix RFC 9728 gives a protected-resource document: the resource's own path,
# under the well-known segment.
PROTECTED_RESOURCE_PREFIX = "/.well-known/oauth-protected-resource"

# RFC 8414's well-known path for the authorization-server metadata of a path-less issuer.
AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server"

# The OpenID Connect location a client tries second for a path-less issuer (the MCP
# discovery order: RFC 8414 first, then this). It answers the same RFC 8414 document, so a
# client that tries it finds working endpoints instead of a refusal. The document gains no
# OpenID Provider member: the gateway is not an OpenID Provider, and advertising one would
# invite a relying party to expect an ID token that never arrives.
OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration"

# The path-insertion forms of both locations (RFC 8414 section 3, and the same shape under
# the OpenID Connect suffix): a client that misreads a resource URL as an issuer URL
# inserts the well-known segment before that URL's path. The captured suffix is ignored
# entirely, never read or echoed, and every one of these answers the one canonical
# document. In particular `issuer` is the public origin, never the suffix: the gateway has
# a single issuer, the one every token and RFC 9207 `iss` carries, and a document naming a
# suffixed issuer would assert an identity no token has. A strict client then discards the
# document (its `issuer` differs from the one the client derived), and a lenient one gets
# working endpoints; neither is told anything false.
AUTHORIZATION_SERVER_PATH_INSERTION = AUTHORIZATION_SERVER_PATH + "/{suffix:path}"
OPENID_CONFIGURATION_PATH_INSERTION = OPENID_CONFIGURATION_PATH + "/{suffix:path}"

# Both grants the authorization server serves. The refresh grant is advertised here
# because the document describes the server a client talks to — a client that discovers
# the metadata and is not told it may refresh would discard its refresh token and re-run
# the whole sign-in instead.
GRANT_TYPES_SUPPORTED = ["authorization_code", "refresh_token"]


def authorization_server_metadata(settings: Settings) -> dict[str, Any]:
    """The RFC 8414 metadata document for the gateway's single flat issuer.

    `registration_endpoint` appears only while dynamic client registration is enabled:
    the endpoint answers a documented disabled-error while the flag is off, and
    advertising a registration endpoint that cannot register anything is how a client is
    steered onto a path that fails at the next step instead of at this one.

    No `scopes_supported` member exists here, by the same reasoning — the gateway has no
    scopes, so the document has none.
    """
    origin = settings.gateway_public_origin
    document: dict[str, Any] = {
        "issuer": origin,
        "authorization_endpoint": f"{origin}/dial/authorize",
        "token_endpoint": f"{origin}/dial/token",
        "jwks_uri": f"{origin}/dial/jwks.json",
        # RFC 7009 revocation, advertised because a client that discovers this document is
        # told where it may end a session it started.
        "revocation_endpoint": f"{origin}/dial/revoke",
        "grant_types_supported": list(GRANT_TYPES_SUPPORTED),
        "response_types_supported": ["code"],
        # A public client sends no client authentication, and the gateway holds no
        # secrets to check one against.
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        # The flag a CIMD-capable client reads to register by presenting a URL-shaped
        # client id and making no registration call at all.
        "client_id_metadata_document_supported": True,
        # RFC 9207's support advertisement: the gateway emits `iss` on every authorization
        # response, success and redirected error alike (the mix-up defense the flat issuer
        # makes necessary), and this member states that emission — an unadvertised behavior
        # is invisible to the clients that would rely on it, so the member's presence is
        # normative, not incidental.
        "authorization_response_iss_parameter_supported": True,
    }
    if settings.dcr_enabled:
        document["registration_endpoint"] = f"{origin}/dial/register"
    return document


def protected_resource_metadata(
    path: str, settings: Settings, *, offered: str
) -> dict[str, Any]:
    """The RFC 9728 document for one served toolset's MCP path.

    The document is served from the resource's own path so that a client following a
    `resource_metadata` challenge lands on the document describing exactly the resource
    it was challenged for.

    It is built from configuration and the requested path alone: the `resource` member
    echoes the **offered spelling** of the path (Core's own protected-resource route echoes
    the requested path, and the mirror property carries the echo rule here — the document an
    offered spelling fetches names that spelling's resource, which is the identity RFC 9728
    requires of it; for a canonical spelling the echo and the derivation coincide), the
    single AS issuer is the gateway's own origin, and the scopes echo the operator
    restriction's entry where the toolset is pinned there and are empty otherwise. The
    document consults nothing, so a path Core's registry does not hold is served here exactly
    as one it does.
    """
    entry = settings.restriction_entry(settings.toolsets, path)
    scopes = list(entry.scopes_supported) if isinstance(entry, ToolsetMapping) else []
    return {
        "resource": f"{settings.gateway_public_origin}/dial/{offered}/mcp",
        "authorization_servers": [settings.gateway_public_origin],
        "scopes_supported": scopes,
    }


def protected_resource_path(path: str) -> str:
    """The route a toolset's protected-resource document is served from."""
    return f"{PROTECTED_RESOURCE_PREFIX}/dial/{path}/mcp"


def app_protected_resource_metadata(
    path: str, settings: Settings, *, offered: str
) -> dict[str, Any]:
    """The RFC 9728 document for one served app's MCP path.

    The apps twin of `protected_resource_metadata`, served from the resource's own path so a
    client following an `resource_metadata` challenge lands on the document describing
    exactly the resource it was challenged for. It is built from configuration and the
    requested path alone: the app resource URI derived from the offered spelling (the same
    echo rule as the toolset document), the single AS issuer, and no Core call.

    `scopes_supported` is **always** empty, and there is no authentication-kind extension.
    No upstream leg exists for an app resource to send scopes on, so echoing anything —
    as the toolset document does where the toolset is pinned — would advertise parameters
    no leg can use; and an app carries no authentication kind, so there is none to echo.
    """
    return {
        "resource": f"{settings.gateway_public_origin}/apps/{offered}/mcp",
        "authorization_servers": [settings.gateway_public_origin],
        "scopes_supported": [],
    }


def app_protected_resource_path(path: str) -> str:
    """The route an app's protected-resource document is served from."""
    return f"{PROTECTED_RESOURCE_PREFIX}/apps/{path}/mcp"


def protected_resource_uri(path: str, settings: Settings) -> str:
    """The document's absolute URL, as a challenge quotes it (the offered spelling)."""
    return f"{settings.gateway_public_origin}{protected_resource_path(path)}"
