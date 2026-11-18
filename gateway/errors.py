"""Error responses, and the plain-language pages a browser lands on.

Two error shapes exist because two audiences exist. A harness is an OAuth client and
expects the RFC 6749 error document (a JSON body, or a redirect back to its registered
`redirect_uri` carrying `error`); a human is sitting in a browser and needs a sentence
saying what happened and what to do. Neither shape ever carries token, code, or key
material — a description names the failure, never the value that caused it.
"""

from __future__ import annotations

from urllib.parse import urlencode

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from gateway.pages import STYLE_BLOCK, html_page

# The OAuth error codes this surface emits. Named here so a caller cannot misspell one
# and quietly emit a code no client recognizes.
INVALID_REQUEST = "invalid_request"
INVALID_TARGET = "invalid_target"
INVALID_CLIENT = "invalid_client"
INVALID_GRANT = "invalid_grant"
UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
INVALID_SCOPE = "invalid_scope"
TEMPORARILY_UNAVAILABLE = "temporarily_unavailable"
SERVER_ERROR = "server_error"

# Every response that can carry an error or an issued credential is kept out of caches:
# an authorization code in a redirect URL must not survive in a proxy's cache. This is the
# JSON-and-redirect half of that rule; the HTML pages carry it as one directive of the
# wider header family they are built with (`gateway/pages.py`).
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class ConfigurationError(RuntimeError):
    """A configuration the gateway refuses to run with.

    Raised where the refusal can only be discovered from injected material or from a
    value the settings model does not validate (the signing key's shape), and rendered as
    a startup refusal: a misconfigured gateway must fail the container's start with a
    readable message rather than serve a surface that is silently broken.
    """


def oauth_error(
    error: str,
    description: str,
    *,
    status_code: int = 400,
) -> JSONResponse:
    """A direct RFC 6749 error document, for a request that cannot be redirected.

    Used when the client or its redirect URI is not established — a redirect would then
    be an open redirect, so the error is answered where it was asked.
    """
    return JSONResponse(
        {"error": error, "error_description": description},
        status_code=status_code,
        headers=_NO_STORE,
    )


def redirect_error(
    redirect_uri: str,
    error: str,
    description: str,
    *,
    state: str | None,
    issuer: str,
) -> RedirectResponse:
    """An RFC 6749 error returned to a validated client redirect URI.

    `iss` is included per RFC 9207 so a client that talks to several authorization
    servers can tell which one answered — the mix-up defense the flat issuer makes
    necessary, and the reason the parameter is echoed on the error path too.
    """
    params: dict[str, str] = {
        "error": error,
        "error_description": description,
        "iss": issuer,
    }
    if state is not None:
        params["state"] = state
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(
        f"{redirect_uri}{separator}{urlencode(params)}",
        status_code=302,
        headers=_NO_STORE,
    )


_FLOW_EXPIRED_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign-in session expired</title>
{style}
</head>
<body>
<h1>This sign-in session expired</h1>
<p>{reason}</p>
<p>Nothing was changed. Go back to your tool and start the sign-in again — it takes a
few seconds, and your tool will walk you through it. If it keeps happening, ask your
DIAL administrator to check the sign-in gateway's logs for the reason above.</p>
</body>
</html>
"""


_GATEWAY_ERROR_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sign-in could not complete</title>
{style}
</head>
<body>
<h1>Sign-in could not complete</h1>
<p>{reason}</p>
<p>Go back to your tool and start the sign-in again. Nothing was changed. If it keeps
happening, ask your DIAL administrator to check the sign-in gateway's logs.</p>
</body>
</html>
"""

# The page a user with no access to the toolset lands on. Separate from the generic page
# because it names something the user can act on — asking an administrator for access —
# while the generic page names a failure only an operator can diagnose.
_NO_ACCESS_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>No access to this toolset</title>
{style}
</head>
<body>
<h1>You do not have access to this toolset</h1>
<p>{reason}</p>
<p>Nothing was changed, and no upstream approval was requested.</p>
</body>
</html>
"""


# The page a user lands on when a toolset's credential cannot be established by a consent
# flow at all. Separate from the generic page because it names the actual cause — a
# credential configured directly in DIAL — and the one thing the user can do about it,
# rather than a fault only an operator can read about.
_NOT_CONSENTABLE_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>This toolset cannot be signed in this way</title>
{style}
</head>
<body>
<h1>This toolset cannot be signed in this way</h1>
<p>This toolset's credential is configured directly in DIAL and cannot be established by
a consent flow. Ask your DIAL administrator to store the credential for you, then start
the sign-in again.</p>
<p>Nothing was changed, and no approval was requested.</p>
</body>
</html>
"""


def flow_expired_page(reason: str) -> HTMLResponse:
    """The page a browser lands on when its flow is gone.

    Deliberately plain language and deliberately non-diagnostic: the person reading it is
    a user who cannot act on a flow id, and telling them the state of server-side records
    would be an information leak with no use. The operator gets the specific reason in
    the gateway's own logs.
    """
    return html_page(
        _FLOW_EXPIRED_PAGE.format(style=STYLE_BLOCK, reason=reason),
        status_code=400,
    )


def gateway_error_page(status_code: int, reason: str) -> HTMLResponse:
    """The page a browser lands on when a flow leg failed for a reason it can retry.

    The reason is interpolated as text. Which reasons reach here is a decision made by the
    caller: a message that carried a credential, or a value from a request, must never be
    rendered — every caller passes fixed text chosen by the gateway.
    """
    return html_page(
        _GATEWAY_ERROR_PAGE.format(style=STYLE_BLOCK, reason=reason),
        status_code=status_code,
    )


def no_access_page(status_code: int, reason: str) -> HTMLResponse:
    """The page a user sees when Core refuses the toolset read for their identity.

    A separate page rather than the generic one because this is the one flow failure that
    is not a fault: the user is not a member of the toolset, the message says which
    administrator to ask, and it says explicitly that nothing upstream was requested.
    """
    return html_page(
        _NO_ACCESS_PAGE.format(style=STYLE_BLOCK, reason=reason),
        status_code=status_code,
    )


def not_consentable_page(status_code: int = 400) -> HTMLResponse:
    """The page a user sees when the toolset's kind cannot be established by consent.

    The impossible branch's refusal: a non-OAuth toolset with no stored credential has no
    consent flow that could ever satisfy it, and this page says so in plain language,
    naming the one action available — an administrator storing the credential in DIAL.
    """
    return html_page(
        _NOT_CONSENTABLE_PAGE.format(style=STYLE_BLOCK), status_code=status_code
    )


def client_source(request: Request) -> str:
    """The source address a rate limit is counted against.

    Three candidates, in the order the front router makes them trustworthy:

    * `X-Real-IP` is the router's own statement about the peer it accepted the connection
      from (`$remote_addr`), so nothing a client sends can influence it while a client's
      traffic passes through that router at all.
    * `X-Forwarded-For`'s **last** entry, for a router that sets only that header: the
      router **appends** the real peer to whatever the client sent (`$proxy_add_x_forwarded_for`),
      so the last entry is again the router's own value. The first entry is the client's
      own claim about itself, and reading it would let an attacker rotate a fake one per
      request and defeat the per-source limit entirely.
    * The socket peer, for a direct call with neither header (a development run).

    An attacker who can send a request the front router never touched can set both headers,
    and this value would then be caller-chosen — the same position the socket peer is in for
    a directly-reachable service. That is why the value is never trusted for authorization:
    it only bounds how often one source may allocate state, and the global limit bounds the
    endpoint when the per-source key is worthless.
    """
    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip():
        return real_ip.strip()
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"
