"""Probe the composed front router: the routing map, the challenge, and the query string.

The router is configuration, and configuration that looks right and routes wrong is the
failure this battery exists to catch. It runs against the composed stack (this
repository's `docker compose up`) and asks its questions, in an order that makes the
answers mean something:

1. **The negative control, first.** The same toolset URL, called on Core directly, says
   what the *unrewritten* challenge looks like. Without it, a rewritten 401 that happened
   to quote the gateway's origin could be Core's own answer and the probe would read as a
   pass for the wrong reason. The control must show a *different* challenge, naming Core's
   protected-resource document; the router's answer must name the gateway's.
2. A streamable-HTTP call carrying a session parameter reaches Core with the parameter
   intact — asserted from Core's own log line for the request, which is where the
   parameter either survived the routing or did not.
3. The flat authorization-server metadata is served through the front door.
4. A toolset's protected-resource document is served through the front door.
5. An unauthenticated call on the toolset MCP path answers the gateway's challenge, and
   the upstream's challenge is not visible in it.
6. The gateway's own authorization and token paths are reachable through the front door,
   and answer as the gateway rather than as Core (Core serves nothing at those paths and
   would answer 404).
7. The consent action route (`/dial/consent`) is reachable through the front door and
   answers as the gateway — a POST naming no live flow gets the gateway's expired-flow
   page, never Core's 404. The checkpoint's decision page posts here, so this probe runs in
   lockstep with the route landing.
8. An app's protected-resource document is served through the front door — the apps twin
   of probe 4.
9. An unauthenticated call on the apps MCP path answers the **apps** challenge, quoting the
   apps metadata path and the toolset's not — the apps twin of probe 5.
10. A query parameter on the apps MCP path reaches Core intact — the apps twin of probe 2.
11. A status path under either namespace is refused by the router's own 404 — the
     data-path location's raw-URI map requires the `/mcp` suffix, so the path never reaches
     the gateway or Core and carries no gateway challenge; the status removal made
     checkable.
12. **The well-known group** (W-rows; two more negative controls run before it). Every row
     goes out through `http.client` with the raw path on the request line, because the
     usual client libraries normalize dot segments out of a URL.
     W0 (control): Core's own answer on a discovery path, direct, is its plain-text 401 —
     distinct from the router's closure by status, shape, and its lack of the router's
     `nosniff` header (the trace header, a Core 0.49.0+ opt-in feature, is informational).
     W0c (control): the gateway's own 404 through the front door
     carries no discriminator header. W1 and W2: the OpenID Connect location and the
     path-insertion forms answer the canonical document byte for byte. W4 and W5: every
     unserved `/.well-known/` path, under every method, is the router's closed 404 with
     the discriminator header and no CORS header. W6: the exact AS location and the
     toolset and app documents are still served (precedence). W7: Core's two
     protected-resource templates answer through the front door as they do direct. W8:
     off-template shapes under Core's prefix are closed. W10 (cells a-g): raw spellings
     that normalize across a namespace edge, in both directions, never reach Core. W12:
     the served locations' end edges are closed. W13: the path-appended forms are the
     data path's refusal, never Core's answer.

Each probe prints its request, the status, and the header or field it asserts on; the
battery's verdict is the last line. Nothing here prints a credential: the token is shown
as a redacted handle.

Probe 2 needs a token Core will accept, and the only token Core accepts is one signed by
the key whose JWKS its provider entry names — so the probe **mints one**, exactly as the
Stage 0 spike does, rather than reading a token file that may have expired (they live 10
minutes) or been minted for a different issuer. A stale token is not a routing failure,
and a battery that could not tell the two apart would report the wrong one.

Usage:
    PYTHONUTF8=1 python scripts/probe_routing.py
    PYTHONUTF8=1 python scripts/probe_routing.py --group wellknown   # no token needed
    PYTHONUTF8=1 python scripts/probe_routing.py --no-token  # skip rows that need a token
"""

from __future__ import annotations

import argparse
import http.client
import json
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gateway.keys import SigningKey

from spike_env import (
    SpikeError,
    load_env,
    prefer_ipv4_resolution,
    redact,
    require,
)
from spike_mint_jwt import copy_identity_claims, fetch_identity_token

# The statuses the probes assert on, named so a probe's expectation reads as a status
# rather than as a number.
HTTP_OK = 200
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404

# The public origin the composed router publishes. Matches `GATEWAY_PUBLIC_ORIGIN`; a
# deployment that changed one without the other is a misconfiguration, and this battery
# would fail loudly rather than quietly probing the wrong host.
DEFAULT_ORIGIN = "http://localhost:8090"

# The toolset the local mapping names.
DEFAULT_TOOLSET = "notion"

# The app the acceptance points at. It names a registered app in Core's deployment registry
# (see `scripts/spike_register_app.py`); the routing probes only need its name to be a
# guard-passing, served app name, so a name with no app registered behind it still exercises
# the routing.
DEFAULT_APP = "skills-demo"

# The instance's Core container, read for the request line of the query-string probe. The
# log line is the evidence: it is Core's own record of the URI it received.
DEFAULT_CORE_CONTAINER = "dial-instance-core-1"

# Core reached on its own host-published port, bypassing the router entirely. That is
# what makes it a control: the request never passes through the thing being measured.
DEFAULT_CORE_DIRECT_ORIGIN = "http://localhost:8081"

# The user agent every upstream front end requires; an explicit one, so a probe's failure
# is never the upstream's bot protection.
USER_AGENT = "dial-mcp-gateway-routing-probe/1.0"

# What Core's own challenge quotes: its protected-resource document, on the host Core
# publishes it at. A rewritten challenge that still carried this string would be Core's
# answer wearing the gateway's header, which is exactly the confusion the rewrite exists
# to remove.
CORE_CHALLENGE_HOST = "localhost:8081"

# The path segment the well-known protected-resource prefix puts before the routed path.
PRM_PREFIX = "/.well-known/oauth-protected-resource"


class ProbeError(RuntimeError):
    """A probe's expectation was not met, or the battery could not run it.

    Each subclass below builds its own message from the values it carries, so a failure
    reads the same wherever it is raised. Messages name the URL, the status, and the value
    expected, and never a token or a key — this text is printed and lands in evidence.
    """


class ControlFailedError(ProbeError):
    """Core's own challenge was not what the control expected."""

    def __init__(self, status: int, challenge: str) -> None:
        super().__init__(
            f"expected Core to answer {HTTP_UNAUTHORIZED} with a challenge naming "
            f"{CORE_CHALLENGE_HOST}; it answered {status} with {challenge!r}. Either "
            "Core's answer changed or this probe is not measuring what it thinks it is, "
            "and neither makes the rewrite's answer meaningful"
        )


class DockerUnavailableError(ProbeError):
    """The `wsl -e docker` call the probe needs could not be made or failed."""

    def __init__(self, args: tuple[str, ...], detail: str) -> None:
        super().__init__(f"`wsl -e docker {' '.join(args)}` failed: {detail}")


class AsMetadataStatusError(ProbeError):
    """The flat metadata answered a status other than 200."""

    def __init__(self, status: int) -> None:
        super().__init__(f"the authorization-server metadata answered {status}")


class ProtectedResourceStatusError(ProbeError):
    """The protected-resource document answered a status other than 200."""

    def __init__(self, status: int) -> None:
        super().__init__(f"the protected-resource document answered {status}")


class AsMetadataShapeError(ProbeError):
    """The flat metadata answered, but not with the shape a client needs."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"the flat AS metadata is not usable: {detail}")

    @classmethod
    def wrong_issuer(cls, issuer: object, origin: str) -> AsMetadataShapeError:
        """The document's issuer is not the public origin it was fetched from."""
        return cls(f"its issuer is {issuer!r}, expected {origin!r}")

    @classmethod
    def endpoint_off_origin(
        cls, name: str, value: object, origin: str
    ) -> AsMetadataShapeError:
        """An advertised endpoint is not on the public origin.

        A client following it would leave the origin this router publishes, which is the
        one thing the flat, path-less issuer arrangement is for.
        """
        return cls(f"{name} is {value!r}, which is not on {origin!r}")


class ProtectedResourceShapeError(ProbeError):
    """The protected-resource document answered, but not with the shape a client needs."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"the protected-resource document is not usable: {detail}")

    @classmethod
    def wrong_resource(cls, resource: object) -> ProtectedResourceShapeError:
        """The document names a resource other than the toolset's own MCP path."""
        return cls(f"its resource is {resource!r}")

    @classmethod
    def wrong_authorization_server(
        cls, servers: object, origin: str
    ) -> ProtectedResourceShapeError:
        """The document names an authorization server other than the gateway."""
        return cls(f"its authorization server is {servers!r}, expected [{origin!r}]")

    @classmethod
    def wrong_scopes(cls, scopes: object) -> ProtectedResourceShapeError:
        """The document's `scopes_supported` is not the always-empty list an app carries."""
        return cls(f"its scopes_supported is {scopes!r}, expected []")


class DataPathStatusError(ProbeError):
    """The toolset MCP path answered a status other than 401."""

    def __init__(self, status: int) -> None:
        super().__init__(
            f"the data path answered {status}, expected {HTTP_UNAUTHORIZED}"
        )


class ChallengeNotRewrittenError(ProbeError):
    """The data path's 401 carried no usable gateway challenge."""

    def __init__(self, challenge: str, resource_metadata: str) -> None:
        super().__init__(
            f"the 401 was not rewritten: the challenge does not quote "
            f"{resource_metadata!r}, so a client following it would not reach the "
            f"gateway's metadata. It carried {challenge!r}"
        )


class ChallengeCountError(ProbeError):
    """The data path's 401 carried a number of challenges other than one."""

    def __init__(self, challenges: list[str]) -> None:
        super().__init__(
            f"the 401 carried {len(challenges)} WWW-Authenticate headers, expected "
            f"exactly one: {challenges!r}. More than one leaves a client choosing, and a "
            "client that picks the wrong one cannot complete a sign-in"
        )


class UpstreamChallengeLeakedError(ProbeError):
    """The upstream's challenge reached the client."""

    def __init__(self, challenge: str) -> None:
        super().__init__(
            f"the upstream's challenge reached the client: {challenge!r} quotes "
            f"{CORE_CHALLENGE_HOST}, Core's own protected-resource host, and no harness "
            "can complete a sign-in against it"
        )


class QueryStringLostError(ProbeError):
    """A query parameter did not reach Core, or Core recorded no request for it."""

    def __init__(self, marker: str, *, logged: bool) -> None:
        if logged:
            detail = f"Core's log lines for {marker!r} carried no request.uri naming it"
        else:
            detail = (
                f"Core's log carried no request line containing {marker!r}: the parameter "
                "did not arrive, or Core did not log the request. This probe's call is "
                "authenticated because an unauthenticated one never reaches the point "
                "where Core records the URI"
            )
        super().__init__(f"the query string did not survive the routing: {detail}")


class GatewayPathAnsweredByCoreError(ProbeError):
    """An authorization-surface path answered as Core, not as the gateway."""

    def __init__(self, url: str, status: int, body: str) -> None:
        super().__init__(
            f"{url} answered {status} with {body} — Core's {HTTP_NOT_FOUND} or a body "
            "without an OAuth error means the request never reached the gateway"
        )


class LockstepError(ProbeError):
    """A lockstep row's two surfaces did not agree with the division of labor.

    The map (routability filter over the wire form) and the guard (authority over the
    decoded form) are asymmetric by design on one documented class, so the rows assert the
    division — both admit, both refuse, or the documented asymmetry — and this error names
    which group the shape failed.
    """

    def __init__(
        self, label: str, data_status: int, discovery_status: int, group: str
    ) -> None:
        super().__init__(
            f"the lockstep row {label!r} ({group}) saw data={data_status} "
            f"discovery={discovery_status} — the map and the guard did not hold the "
            "documented division"
        )


def fetch(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    extra_headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], str]:
    """One HTTP call, returning status, headers, and body instead of raising on 4xx.

    The probes assert on refusals as often as on successes — a 401 the router rewrote is
    the point of two of them — so an HTTP error status is a value here, not an exception.
    """
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    headers.update(extra_headers or {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    # The URL is an operator-supplied local endpoint, never user input.
    request = urllib.request.Request(  # noqa: S310 - operator-supplied local endpoint
        url, headers=headers, method=method, data=body
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return (
                response.status,
                dict(response.headers),
                response.read().decode(errors="replace"),
            )
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode(errors="replace")


def docker(*args: str) -> str:
    """Run a command in the WSL docker environment and return its output.

    The probes need Core's log, and Core runs in a container under WSL2 on this host, so
    the read is a `wsl -e docker` call rather than a file read.
    """
    try:
        # `wsl` is resolved by name on purpose: its path differs per installation, and
        # this helper runs on the developer's host rather than in the container. The argv
        # is fixed here, so nothing about the call is caller-supplied.
        completed = subprocess.run(  # noqa: S603
            ["wsl", "-e", "docker", *args],  # noqa: S607 - host-resolved, argv is fixed
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DockerUnavailableError(args, str(exc)) from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode(errors="replace").strip()
        raise DockerUnavailableError(args, f"exited {completed.returncode}: {stderr}")
    return completed.stdout.decode(errors="replace")


def _challenges(headers: dict[str, str]) -> list[str]:
    """Every `WWW-Authenticate` value a response carried.

    All of them, not the first: a response that carried the gateway's challenge *and* the
    upstream's is the failure this router exists to prevent, and reading only one of the
    two would report that response as a pass. Header names are matched case-insensitively
    because their case is not guaranteed on the wire.
    """
    return [
        value for name, value in headers.items() if name.lower() == "www-authenticate"
    ]


def _challenge(headers: dict[str, str]) -> str:
    """The first `WWW-Authenticate` a response carried, for the control's own assertion."""
    challenges = _challenges(headers)
    return challenges[0] if challenges else ""


def negative_control(core_origin: str, toolset: str) -> str:
    """What Core's own challenge looks like, so the rewrite's answer can be told apart.

    Core is reached on its own published port, outside the router. That container is the
    instrument's independence: the control must not travel through the router, or the
    router's own rewrite would be the thing being measured.
    """
    url = f"{core_origin}/v1/toolset/{toolset}/mcp"
    status, headers, _ = fetch(url)
    challenge = _challenge(headers)
    print(f"  request   GET {url}  (direct to Core, outside the router)")
    print(f"  status    {status}")
    print(f"  challenge {challenge!r}")
    if status != HTTP_UNAUTHORIZED or CORE_CHALLENGE_HOST not in challenge:
        raise ControlFailedError(status, challenge)
    print("  verdict   control red — Core's own challenge names its own metadata")
    return challenge


def probe_authorization_server(origin: str) -> None:
    """The flat metadata document is served through the front door."""
    url = f"{origin}/.well-known/oauth-authorization-server"
    status, _, body = fetch(url)
    print(f"  request   GET {url}")
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise AsMetadataStatusError(status)
    document = json.loads(body)
    issuer = document.get("issuer")
    endpoints = {
        key: document.get(key)
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri")
    }
    print(f"  issuer    {issuer}")
    for key, value in endpoints.items():
        print(f"  {key:24s} {value}")
    if issuer != origin:
        raise AsMetadataShapeError.wrong_issuer(issuer, origin)
    for key, value in endpoints.items():
        if not isinstance(value, str) or not value.startswith(origin):
            raise AsMetadataShapeError.endpoint_off_origin(key, value, origin)
    print("  verdict   green — the flat metadata is served, on the public origin")


def probe_protected_resource(origin: str, toolset: str) -> None:
    """A toolset's protected-resource document is served through the front door."""
    url = f"{origin}{PRM_PREFIX}/dial/{toolset}/mcp"
    status, _, body = fetch(url)
    print(f"  request   GET {url}")
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise ProtectedResourceStatusError(status)
    document = json.loads(body)
    print(f"  resource  {document.get('resource')}")
    print(f"  servers   {document.get('authorization_servers')}")
    # The document carries no authentication-kind member: under dynamic serving this surface
    # has no kind source, and the kind a flow acts on is Core's, read per flow. The absence
    # is asserted rather than printed, so a stray member is a probe failure, not a note.
    print(
        f"  kind      {'absent' if 'dial_authentication_type' not in document else 'PRESENT'}"
    )
    if document.get("resource") != f"{origin}/dial/{toolset}/mcp":
        raise ProtectedResourceShapeError.wrong_resource(document.get("resource"))
    if document.get("authorization_servers") != [origin]:
        raise ProtectedResourceShapeError.wrong_authorization_server(
            document.get("authorization_servers"), origin
        )
    print("  verdict   green — the toolset's metadata is served on the public origin")


def probe_app_protected_resource(origin: str, app: str) -> None:
    """An app's protected-resource document is served through the front door.

    The apps twin of the toolset probe: the document names the app's resource URI and the
    single AS issuer, with an always-empty `scopes_supported` (no upstream leg sends scopes
    for an app resource) and no authentication-kind extension.
    """
    url = f"{origin}{PRM_PREFIX}/apps/{app}/mcp"
    status, _, body = fetch(url)
    print(f"  request   GET {url}")
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise ProtectedResourceStatusError(status)
    document = json.loads(body)
    print(f"  resource  {document.get('resource')}")
    print(f"  scopes    {document.get('scopes_supported')}")
    if document.get("resource") != f"{origin}/apps/{app}/mcp":
        raise ProtectedResourceShapeError.wrong_resource(document.get("resource"))
    if document.get("authorization_servers") != [origin]:
        raise ProtectedResourceShapeError.wrong_authorization_server(
            document.get("authorization_servers"), origin
        )
    if document.get("scopes_supported") != []:
        raise ProtectedResourceShapeError.wrong_scopes(document.get("scopes_supported"))
    print("  verdict   green — the app's metadata is served on the public origin")


def probe_app_challenge(origin: str, app: str) -> None:
    """An unauthenticated apps MCP call is answered with the apps challenge *alone*.

    The apps twin of `probe_challenge`: exactly one `WWW-Authenticate`, quoting the apps
    metadata path, and no trace of Core's host.
    """
    url = f"{origin}/apps/{app}/mcp"
    status, headers, _ = fetch(url)
    challenges = _challenges(headers)
    print(f"  request   GET {url}  (no Authorization header)")
    print(f"  status    {status}")
    print(f"  challenges {challenges!r}")
    if status != HTTP_UNAUTHORIZED:
        raise DataPathStatusError(status)
    resource_metadata = f"{origin}{PRM_PREFIX}/apps/{app}/mcp"
    leaked = [value for value in challenges if CORE_CHALLENGE_HOST in value]
    if leaked:
        raise UpstreamChallengeLeakedError(leaked[0])
    if len(challenges) != 1:
        raise ChallengeCountError(challenges)
    challenge = challenges[0]
    if resource_metadata not in challenge:
        raise ChallengeNotRewrittenError(challenge, resource_metadata)
    # The toolset metadata path must not appear: an apps 401 quoting the toolset document
    # would point a strict client at a document whose resource differs from the challenged
    # resource, and its sign-in could not complete.
    if f"{PRM_PREFIX}/dial/" in challenge:
        raise ChallengeNotRewrittenError(challenge, resource_metadata)
    print(f"  resource_metadata  {resource_metadata}")
    print("  verdict   green — the apps 401 names the apps metadata, not the toolset's")


def probe_app_query_string(
    origin: str, app: str, token: str, core_container: str
) -> None:
    """A query parameter on the apps MCP path reaches Core intact.

    Asserted from Core's own log line, which is the only place the loss is visible — a proxy
    that dropped the parameter would still return the response Core produced without it.
    """
    marker = f"probe-app-{uuid.uuid4().hex[:12]}"
    url = f"{origin}/apps/{app}/mcp?{urllib.parse.urlencode({'sessionId': marker})}"
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    status, _, _ = fetch(
        url, method="POST", token=token, extra_headers=headers, body=body
    )
    print(f"  request   POST {url.replace(marker, '<probe-id>')}")
    print(f"  status    {status}")

    get_marker = f"{marker}-get"
    get_url = (
        f"{origin}/apps/{app}/mcp?{urllib.parse.urlencode({'sessionId': get_marker})}"
    )
    get_status, _, _ = fetch(get_url, token=token)
    print(f"  request   GET {get_url.replace(get_marker, '<probe-id>-get')}")
    print(f"  status    {get_status}")

    log = docker("logs", "--since", "3m", core_container)
    for probe_marker in (marker, get_marker):
        seen = [line for line in log.splitlines() if probe_marker in line]
        if not seen:
            raise QueryStringLostError(probe_marker, logged=False)
        if not any(probe_marker in _request_uri(line) for line in seen):
            raise QueryStringLostError(probe_marker, logged=True)
    print("  verdict   green — the parameter reached Core unchanged, on both methods")


def probe_status_path_dropped(origin: str, name: str) -> None:
    """A status path under either namespace is refused by the router, not served here.

    The status surface is removed from the gateway. With the data-path locations now bare
    prefixes (`~ ^/dial/`, `~ ^/apps/`) decided by a raw-URI map whose grammar requires the
    `/mcp` suffix, a non-MCP path under either prefix — `/dial/{name}/status`,
    `/apps/{name}/status` — does not match the map, so the location's
    `if ($dial_target = "") { return 404; }` refuses it before any handler. That is the
    spec-mandated shape ("the `/mcp` suffix present" as a conformance condition; absent, the
    router returns 404), and it replaced the earlier fall-through to Core: the router's
    prefix now owns the whole `/dial/` namespace, so the status path never reaches Core.

    The assertion is that no *gateway* handler serves the path: the response is a bare 404
    with no `WWW-Authenticate` — the gateway's data-path 401 challenge is absent, so the
    request reached neither the gateway nor a data path. (Before this change, the anchored
    data-path location let `/dial/{name}/status` fall through to Core, whose auth filter
    answered an unauthenticated call 401; the status removal is provable either way, and the
    404 is the shape the current router's map produces.)
    """
    for path in (f"/dial/{name}/status", f"/apps/{name}/status"):
        url = f"{origin}{path}"
        status, headers, body = fetch(url)
        challenges = _challenges(headers)
        print(f"  request   GET {url}")
        print(f"  status    {status}")
        print(f"  challenges {challenges!r}")
        if status != HTTP_NOT_FOUND or challenges:
            raise GatewayPathAnsweredByCoreError(url, status, body[:200])
    print(
        "  verdict   green — both status paths are refused by the router's map with no "
        "gateway challenge"
    )


def probe_challenge(origin: str, toolset: str, core_challenge: str) -> None:
    """An unauthenticated MCP call is answered with the gateway's challenge *alone*.

    "Alone" is the load-bearing word. The upstream's challenge reaching a client beside
    the gateway's is a harness following the wrong one — exactly the failure the rewrite
    exists to remove — so the count is asserted as well as the content.
    """
    url = f"{origin}/dial/{toolset}/mcp"
    status, headers, _ = fetch(url)
    challenges = _challenges(headers)
    print(f"  request   GET {url}  (no Authorization header)")
    print(f"  status    {status}")
    print(f"  challenges {challenges!r}")
    if status != HTTP_UNAUTHORIZED:
        raise DataPathStatusError(status)
    resource_metadata = f"{origin}{PRM_PREFIX}/dial/{toolset}/mcp"
    leaked = [value for value in challenges if CORE_CHALLENGE_HOST in value]
    if leaked:
        raise UpstreamChallengeLeakedError(leaked[0])
    if len(challenges) != 1:
        raise ChallengeCountError(challenges)
    challenge = challenges[0]
    if resource_metadata not in challenge:
        raise ChallengeNotRewrittenError(challenge, resource_metadata)
    if challenge.strip() == core_challenge.strip():
        # A rewrite that reproduced Core's own challenge verbatim would satisfy neither
        # client, and this is the case the negative control exists to make visible.
        raise ChallengeNotRewrittenError(challenge, resource_metadata)
    print(f"  resource_metadata  {resource_metadata}")
    print("  verdict   green — the 401 names the gateway's metadata, not Core's")


def probe_query_string(
    origin: str,
    toolset: str,
    token: str,
    core_container: str,
) -> None:
    """A query parameter on the MCP path reaches Core intact.

    The assertion is read from Core's own log line for the request rather than from the
    response: a proxy that dropped the parameter would still return the response Core
    produced without it, so the only place the loss is visible is what Core recorded
    receiving.

    The call carries a token Core accepts on purpose. An unauthenticated request never
    reaches the point in Core where the URI is logged, so the probe would read a routing
    pass as a failure — and, worse, a battery that could not tell those apart could pass
    for the wrong reason if Core's logging changed. What is measured here is the URI Core
    recorded, and the request behind it is one Core actually served.
    """
    marker = f"probe-{uuid.uuid4().hex[:12]}"
    url = f"{origin}/dial/{toolset}/mcp?{urllib.parse.urlencode({'sessionId': marker})}"
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).encode()
    status, _, _ = fetch(
        url, method="POST", token=token, extra_headers=headers, body=body
    )
    print(f"  request   POST {url.replace(marker, '<probe-id>')}")
    print(f"  token     {redact(token)}")
    print(f"  status    {status}")

    # The specification's session resume is a GET on the same path, so it is asked too: a
    # routing that survived a POST's query string could still lose a GET's.
    get_marker = f"{marker}-get"
    get_url = f"{origin}/dial/{toolset}/mcp?{urllib.parse.urlencode({'sessionId': get_marker})}"
    get_status, _, _ = fetch(get_url, token=token)
    print(f"  request   GET {get_url.replace(get_marker, '<probe-id>-get')}")
    print(f"  status    {get_status}")

    log = docker("logs", "--since", "3m", core_container)
    for probe_marker in (marker, get_marker):
        seen = [line for line in log.splitlines() if probe_marker in line]
        if not seen:
            raise QueryStringLostError(probe_marker, logged=False)
        for line in seen:
            uri = _request_uri(line)
            if uri:
                print(f"  core log  request.uri={uri!r}")
        if not any(probe_marker in _request_uri(line) for line in seen):
            raise QueryStringLostError(probe_marker, logged=True)
    print("  verdict   green — the parameter reached Core unchanged, on both methods")


def _request_uri(log_line: str) -> str:
    """The `request.uri` a Core log line carries, which includes the query string."""
    key = '"request.uri":"'
    start = log_line.find(key)
    if start < 0:
        return ""
    start += len(key)
    end = log_line.find('"', start)
    return log_line[start:end] if end > start else ""


def probe_gateway_paths(origin: str) -> None:
    """The gateway's authorize and token paths are reachable through the front door.

    Both are asked with an unusable request on purpose: what is asserted is *whose* answer
    comes back. Core serves nothing at these paths and answers 404, so a gateway-shaped
    OAuth error document is the evidence that the location reached the gateway.
    """
    cases = [
        (
            "the authorization endpoint",
            f"{origin}/dial/authorize",
            "GET",
        ),
        (
            "the token endpoint",
            f"{origin}/dial/token",
            "POST",
        ),
    ]
    for label, url, method in cases:
        headers = {}
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = b""
        status, _, response_body = fetch(
            url, method=method, extra_headers=headers, body=body
        )
        print(f"  request   {method} {url}  ({label}, no usable parameters)")
        print(f"  status    {status}")
        try:
            document = json.loads(response_body)
        except ValueError as exc:
            raise GatewayPathAnsweredByCoreError(
                url, status, f"a non-JSON body: {response_body[:200]!r}"
            ) from exc
        error = document.get("error")
        print(f"  error     {error!r}")
        if status == HTTP_NOT_FOUND or error is None:
            raise GatewayPathAnsweredByCoreError(url, status, response_body[:200])
    print("  verdict   green — both paths answer as the gateway, not as Core")


def probe_consent_route(origin: str) -> None:
    """The consent action route is reachable through the front door.

    The route is POST-only and browser-facing, and it answers a page: a POST naming no live
    flow gets the plain-language expired-flow page, never a redirect and never Core's
    answer. The assertion is *whose* answer comes back — Core serves nothing at
    `/dial/consent` and would answer 404 with no HTML — so the HTML page is the evidence
    the location reached the gateway. A checkpoint whose action route is unrouted is a
    flow that dead-ends at the decision page, which is why this probe runs in lockstep with
    the route landing.
    """
    url = f"{origin}/dial/consent"
    body = urllib.parse.urlencode(
        {"flow_id": "no-such-flow", "action": "approve"}
    ).encode()
    status, headers, response_body = fetch(
        url,
        method="POST",
        extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=body,
    )
    print(f"  request   POST {url}  (an unknown flow id, no cookie)")
    print(f"  status    {status}")
    content_type = next(
        (value for name, value in headers.items() if name.lower() == "content-type"),
        "",
    )
    print(f"  content-type {content_type!r}")
    if status == HTTP_NOT_FOUND:
        raise GatewayPathAnsweredByCoreError(url, status, response_body[:200])
    if "text/html" not in content_type:
        raise GatewayPathAnsweredByCoreError(url, status, response_body[:200])
    print("  verdict   green — the consent route answers as the gateway, not as Core")


# The two surfaces the lockstep rows compare: the router's data path (the map's routability
# filter over the wire form) and the gateway's discovery surface (the guard's authority over
# the decoded form). A shape admitted by both is lockstep; a shape refused by both is too;
# and the documented asymmetry class is forwarded on the data path while refused at
# discovery. These rows assert the division, not an agreement between the two grammars.
_LOCKSTEP_ADMITTED_SHAPES = (
    ("a stored path", "toolsets/public/x"),
    ("a user-bucket alphanumeric segment", "toolsets/abcdef0123456789/x"),
)

_LOCKSTEP_REFUSED_SHAPES = (
    ("dot-segment ..", "a/../b"),
    ("dot-segment .", "a/./b"),
    ("empty segment", "toolsets//public/x"),
    ("trailing dot", "toolsets/public/x."),
    ("reserved first segment", "token"),
)

# The documented asymmetry class: a wire-conforming, guard-refused spelling. The router
# forwards it on the data path (its grammar admits every `%XX` escape); the guard refuses it
# at discovery. Its 401 challenge names a document the gateway answers 404 — a dead end by
# design, same-answer-as-Core in outcome.
_LOCKSTEP_ASYMMETRY_SHAPES = (
    ("encoded forbidden character %7B", "a%7Bb"),
    ("escaped trailing dot %2e", "toolsets/public/x%2e"),
)


def probe_lockstep(bench: str) -> None:
    """The division of labor asserted on both sides: the map and the guard.

    Three row groups, negative controls first in the battery's order and each group a
    property of the *pair*:

    * **both admit** — a guard-passing path answers the gateway's 401 challenge on the data
      path and a 200 document at discovery (the router's map routed it, the guard admitted
      it) — the lockstep the addressing change rests on.
    * **both refuse** — a grammar-refused shape answers 404 on both surfaces: the router's
      grammar refuses the wire form and the guard refuses the decoded form, so neither
      surface admits it.
    * **the documented asymmetry** — a wire-conforming, guard-refused spelling is forwarded
      on the data path (a 401 challenge, not a 404) and refused 404 at discovery. Its
      challenge names a document the gateway answers 404: the dead end the design states,
      and the outcome is same-answer-as-Core, never a served resource.
    """
    prefix = PRM_PREFIX
    print("  -- both sides admit --")
    for label, segment in _LOCKSTEP_ADMITTED_SHAPES:
        data_status, data_headers, _ = fetch(f"{bench}/dial/{segment}/mcp")
        challenges = [
            value
            for name, value in data_headers.items()
            if name.lower() == "www-authenticate"
        ]
        disc_status, _, _ = fetch(f"{bench}{prefix}/dial/{segment}/mcp")
        print(
            f"  {label:38s} data={data_status} challenge={bool(challenges)} "
            f"discovery={disc_status}"
        )
        if data_status != HTTP_UNAUTHORIZED or not challenges or disc_status != HTTP_OK:
            raise LockstepError(label, data_status, disc_status, "both admit")

    print("  -- both sides refuse --")
    for label, segment in _LOCKSTEP_REFUSED_SHAPES:
        data_status, _, _ = fetch(f"{bench}/dial/{segment}/mcp")
        disc_status, _, _ = fetch(f"{bench}{prefix}/dial/{segment}/mcp")
        print(f"  {label:38s} data={data_status} discovery={disc_status}")
        if data_status != HTTP_NOT_FOUND or disc_status != HTTP_NOT_FOUND:
            raise LockstepError(label, data_status, disc_status, "both refuse")

    print(
        "  -- the documented asymmetry (forwarded on the data path, refused at discovery) --"
    )
    for label, segment in _LOCKSTEP_ASYMMETRY_SHAPES:
        data_status, data_headers, _ = fetch(f"{bench}/dial/{segment}/mcp")
        challenges = [
            value
            for name, value in data_headers.items()
            if name.lower() == "www-authenticate"
        ]
        disc_status, _, _ = fetch(f"{bench}{prefix}/dial/{segment}/mcp")
        print(
            f"  {label:38s} data={data_status} challenge={bool(challenges)} "
            f"discovery={disc_status}"
        )
        # The data path forwards it (the map's wire form admits `%XX`), so a 401 challenge
        # or a forwarded answer — never a 404; the guard refuses it at discovery.
        if data_status == HTTP_NOT_FOUND or disc_status != HTTP_NOT_FOUND:
            raise LockstepError(label, data_status, disc_status, "asymmetric")
    print(
        "  verdict   green — the map/guard division holds: both-admit, both-refuse, "
        "and the documented asymmetry"
    )


def probe_lockstep_apps(bench: str, app_segment: str) -> None:
    """The apps-path twin of the lockstep rows.

    The apps namespace's map and guard are the toolset's, over the `/apps/` prefix and
    Core's deployments path. One admitted stored-app path is asserted on both surfaces: the
    apps 401 challenge on the data path and a 200 apps document at discovery. The apps
    namespace carries no reserved-name class, so the reserved-first-segment shape has no
    apps twin and is not asserted here.
    """
    data_status, data_headers, _ = fetch(f"{bench}/apps/{app_segment}/mcp")
    challenges = [
        value
        for name, value in data_headers.items()
        if name.lower() == "www-authenticate"
    ]
    disc_status, _, _ = fetch(f"{bench}{PRM_PREFIX}/apps/{app_segment}/mcp")
    print(
        f"  {('an apps stored path'):38s} data={data_status} challenge={bool(challenges)} "
        f"discovery={disc_status}"
    )
    if data_status != HTTP_UNAUTHORIZED or not challenges or disc_status != HTTP_OK:
        label = "an apps stored path"
        raise LockstepError(label, data_status, disc_status, "both admit")
    # A dot-segment shape is refused by both surfaces in the apps namespace too.
    for label, segment in (("apps dot-segment ..", "a/../b"),):
        data_status, _, _ = fetch(f"{bench}/apps/{segment}/mcp")
        disc_status, _, _ = fetch(f"{bench}{PRM_PREFIX}/apps/{segment}/mcp")
        print(f"  {label:38s} data={data_status} discovery={disc_status}")
        if data_status != HTTP_NOT_FOUND or disc_status != HTTP_NOT_FOUND:
            raise LockstepError(label, data_status, disc_status, "both refuse")
    print("  verdict   green — the apps map/guard division holds")


AUDIENCE_MARKER = "dial-mcp-proxy"


# -- The well-known row group ----------------------------------------------------------
#
# The discovery aliases and the closed `/.well-known/` namespace. Every row here goes out
# through `http.client` with the path exactly as written: `httpx`, `requests`, and
# `urllib` normalize dot segments and some percent-escapes out of a URL before sending,
# which would turn a probe of a raw spelling into a probe of its normalized form and pass
# for the wrong reason. Each row prints the request line it sent, so the run itself shows
# which spelling reached the router.

# Core's trace header: a front-door answer that carries it was produced by Core.
CORE_TRACE_HEADER = "x-dial-trace-id"

# The header only the router's closed namespace sets (the gateway's JSON answers never do),
# which is what tells the router's 404 from the gateway's own identical-looking one.
NOSNIFF_HEADER = "x-content-type-options"

# The closed namespace's fixed body and type; also the gateway's own unrouted-404 shape.
CLOSED_BODY = b'{"detail":"Not Found"}'
JSON_TYPE = "application/json"
# A CORS preflight's request headers: the closure must answer it like any other request.
PREFLIGHT_HEADERS = {
    "Origin": "https://client.example",
    "Access-Control-Request-Method": "GET",
}

AS_METADATA_PATH = "/.well-known/oauth-authorization-server"
OIDC_METADATA_PATH = "/.well-known/openid-configuration"


class WellKnownRowError(ProbeError):
    """A well-known row's expectation was not met; the message names the row and cells."""

    def __init__(self, row: str, detail: str) -> None:
        super().__init__(f"{row}: {detail}")


class WellKnownControlError(ProbeError):
    """A well-known negative control did not show what the later rows rely on."""

    def __init__(self, control: str, expected: str, observed: str) -> None:
        super().__init__(
            f"{control}: expected {expected}; observed {observed}. The discriminator the "
            "later rows rely on does not hold, so none of their verdicts means anything"
        )


@dataclass(frozen=True)
class RawResponse:
    """One answer from the verbatim-path client, with header names lower-cased."""

    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def content_type(self) -> str:
        """The `Content-Type` value, or the empty string."""
        return self.headers.get("content-type", "")

    @property
    def from_core(self) -> bool:
        """Whether Core's trace header is present."""
        return CORE_TRACE_HEADER in self.headers

    @property
    def nosniff(self) -> bool:
        """Whether the router's discriminator header is present."""
        return NOSNIFF_HEADER in self.headers

    @property
    def cors(self) -> list[str]:
        """Every `Access-Control-*` header name the answer carried."""
        return [name for name in self.headers if name.startswith("access-control-")]

    def summary(self) -> str:
        """The one-line shape every row prints under its request line."""
        return (
            f"status {self.status}  type {self.content_type or '-'}  "
            f"core-trace {'PRESENT' if self.from_core else 'absent'}  "
            f"nosniff {'present' if self.nosniff else 'absent'}"
        )

    def describe(self) -> str:
        """A short description for a control's failure message."""
        return f"status {self.status}, type {self.content_type or '-'}, body {self.body[:60]!r}"


def raw_request(
    origin: str,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> RawResponse:
    """Send one request with `path` on the request line exactly as given."""
    parts = urllib.parse.urlsplit(origin)
    connection = http.client.HTTPConnection(
        parts.hostname or "localhost", parts.port, timeout=30
    )
    try:
        sent = {"User-Agent": USER_AGENT, "Accept": "*/*", **(headers or {})}
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        collected: dict[str, str] = {}
        for name, value in response.getheaders():
            key = name.lower()
            collected[key] = f"{collected[key]}, {value}" if key in collected else value
        return RawResponse(response.status, collected, response.read())
    finally:
        connection.close()


def _send(
    origin: str,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> RawResponse:
    """`raw_request`, printing the request line and the answer's shape."""
    print(f"  request   {method} {path} HTTP/1.1   (verbatim, to {origin})")
    response = raw_request(origin, method, path, body=body, headers=headers)
    print(f"  answer    {response.summary()}")
    return response


def _closure_problems(response: RawResponse, *, method: str = "GET") -> list[str]:
    """Why an answer is not the router's closed-namespace 404 (empty when it is)."""
    problems = []
    if response.status != HTTP_NOT_FOUND:
        problems.append(f"status {response.status}, expected {HTTP_NOT_FOUND}")
    if response.from_core:
        problems.append("Core's trace header is present (Core answered)")
    if response.headers.get(NOSNIFF_HEADER, "").lower() != "nosniff":
        problems.append("the router's X-Content-Type-Options: nosniff is absent")
    if not response.content_type.startswith(JSON_TYPE):
        problems.append(f"content type {response.content_type!r}, expected JSON")
    expected_body = b"" if method == "HEAD" else CLOSED_BODY
    if response.body != expected_body:
        problems.append(f"body {response.body[:60]!r}, expected {expected_body!r}")
    if "www-authenticate" in response.headers:
        problems.append("a WWW-Authenticate challenge is present")
    if response.cors:
        problems.append(f"Access-Control headers present: {response.cors}")
    return problems


def _verdict(row: str, failures: list[str], green: str) -> None:
    """Print a row's verdict and raise when any cell failed."""
    if failures:
        raise WellKnownRowError(row, "; ".join(failures))
    print(f"  verdict   green — {green}")


def _check_closure(
    origin: str,
    method: str,
    path: str,
    failures: list[str],
) -> None:
    """Send one request and record a failure unless the router's closure answered.

    A closed path carries no CORS header under any method, so that is always asserted.
    A `POST` carries a small body, which the closure must never read or forward. An
    `OPTIONS` is sent as a CORS preflight (with `Origin` and
    `Access-Control-Request-Method`), which the closure must answer like any other method.
    Every cell requires the closure's `404`: no cell steps above the root, so nginx has
    no reason to refuse any of them with a `400`.
    """
    body = b"{}" if method == "POST" else None
    extra = PREFLIGHT_HEADERS if method == "OPTIONS" else None
    response = _send(origin, method, path, body=body, headers=extra)
    problems = _closure_problems(response, method=method)
    if problems:
        failures.append(f"{method} {path}: " + ", ".join(problems))


def _canonical_document(origin: str) -> bytes:
    """The canonical metadata body, fetched in the same run the aliases are compared to."""
    response = raw_request(origin, "GET", AS_METADATA_PATH)
    if response.status != HTTP_OK:
        raise AsMetadataStatusError(response.status)
    return response.body


def _check_document(
    origin: str,
    path: str,
    canonical: bytes,
    failures: list[str],
    *,
    gateway_answer: bool = False,
) -> None:
    """Send one request and record a failure unless it answered the canonical document."""
    response = _send(origin, "GET", path)
    problems = []
    if response.status != HTTP_OK:
        problems.append(f"status {response.status}, expected {HTTP_OK}")
    elif response.body != canonical:
        problems.append("body is not byte-identical to the canonical document")
    else:
        issuer = json.loads(response.body).get("issuer")
        if issuer != origin:
            problems.append(f"issuer {issuer!r}, expected {origin!r}")
    if response.from_core:
        problems.append("Core's trace header is present")
    if gateway_answer and response.nosniff:
        problems.append("the router's discriminator header is on a gateway answer")
    if problems:
        failures.append(f"GET {path}: " + ", ".join(problems))


def probe_wk_control_core(core_origin: str) -> None:
    """W0, negative control (Core): what Core's own answer on a discovery path looks like.

    The discriminator is status, shape, and the router's header: Core's own answer is a
    `401` that is *not* the router's closed-namespace shape — it carries no
    `X-Content-Type-Options: nosniff`, and it is not the router's fixed JSON 404 body. Those
    three hold on any Core build and any deployment; the so-called trace header
    (`X-Dial-Trace-Id`) is version-dependent (a Core 0.49.0+ opt-in feature,
    `responseTraceHeaders`, off by default), so its absence proves nothing and it is
    recorded informationally rather than asserted on.
    """
    response = _send(core_origin, "GET", OIDC_METADATA_PATH)
    print("  (direct to Core, outside the router)")
    print(f"  record    Core's content-type: {response.content_type or 'none'}")
    trace = (
        "PRESENT"
        if response.from_core
        else (
            "absent — a Core 0.49.0+ opt-in feature (responseTraceHeaders), informational only"
        )
    )
    print(f"  record    X-Dial-Trace-Id: {trace}")
    router_closure = response.content_type.startswith(JSON_TYPE) and (
        response.body == CLOSED_BODY
    )
    if response.status != HTTP_UNAUTHORIZED or response.nosniff or router_closure:
        raise WellKnownControlError(
            "W0",
            "Core's own 401, and not the router's closure (no nosniff, "
            "not the fixed JSON 404 body)",
            f"{response.describe()}, nosniff {response.nosniff}",
        )
    print(
        "  verdict   control red — Core's 401 is its own answer, distinct from the "
        "router's closure"
    )


def probe_wk_control_gateway(origin: str) -> None:
    """W0c, negative control (gateway): the gateway's own 404, without the discriminator."""
    response = _send(origin, "GET", f"{PRM_PREFIX}/dial/x")
    if (
        response.status != HTTP_NOT_FOUND
        or response.body != CLOSED_BODY
        or not response.content_type.startswith(JSON_TYPE)
        or response.nosniff
        or response.from_core
    ):
        raise WellKnownControlError(
            "W0c",
            "the gateway's own JSON 404 with no discriminator header and no Core trace",
            f"{response.describe()}, nosniff {response.nosniff}",
        )
    print("  verdict   control red — the gateway's 404 carries no discriminator header")


def probe_wk_oidc(origin: str) -> None:
    """W1: the OpenID Connect location answers the canonical document, byte for byte."""
    canonical = _canonical_document(origin)
    failures: list[str] = []
    _check_document(origin, OIDC_METADATA_PATH, canonical, failures)
    _verdict(
        "W1", failures, "the OpenID Connect location serves the canonical document"
    )


def probe_wk_path_insertion(origin: str, toolset: str, app: str) -> None:
    """W2: both path-insertion families, three suffixes each, answer the same document."""
    canonical = _canonical_document(origin)
    failures: list[str] = []
    suffixes = (f"/apps/{app}/mcp", f"/dial/{toolset}/mcp", "/")
    for family in (AS_METADATA_PATH, OIDC_METADATA_PATH):
        for suffix in suffixes:
            _check_document(origin, f"{family}{suffix}", canonical, failures)
    _verdict("W2", failures, "every path-insertion form serves the canonical document")


def probe_wk_closed(origin: str) -> None:
    """W4: unserved paths in the namespace get the router's closed 404."""
    failures: list[str] = []
    for path in (
        "/.well-known/oauth-protected-resource",
        "/.well-known/unknown",
        "/.well-known/",
        "/.well-known",
    ):
        _check_closure(origin, "GET", path, failures)
    _verdict("W4", failures, "every unserved well-known path is the router's 404")


def probe_wk_methods(origin: str) -> None:
    """W5: the closure is method-blind and carries no CORS header."""
    failures: list[str] = []
    path = "/.well-known/unknown"
    _check_closure(origin, "POST", path, failures)
    _check_closure(origin, "OPTIONS", path, failures)
    _check_closure(origin, "HEAD", path, failures)
    _verdict("W5", failures, "POST, OPTIONS, HEAD get the router's 404, no CORS header")


def probe_wk_precedence(origin: str, toolset: str, app: str) -> None:
    """W6: the exact AS location and the toolset and app documents are still served."""
    probe_authorization_server(origin)
    probe_protected_resource(origin, toolset)
    probe_app_protected_resource(origin, app)


def _same_document_shape(
    path: str, front: RawResponse, direct: RawResponse, kind: str, name: str
) -> list[str]:
    """Why the front-door answer is not the same kind of document as Core's own.

    Core builds `resource` from the request authority, which differs between the two
    ports, so the bodies are not compared byte for byte. The content type must match, and
    on a `200` the JSON member names must match and `resource` must end with the
    requested resource path.
    """
    problems = []
    if front.content_type != direct.content_type:
        problems.append(
            f"{path}: content type {front.content_type!r} via the front door, "
            f"{direct.content_type!r} direct"
        )
    if front.status != HTTP_OK or direct.status != HTTP_OK:
        return problems
    try:
        front_doc = json.loads(front.body)
        direct_doc = json.loads(direct.body)
    except ValueError:
        return [*problems, f"{path}: a 200 answer is not JSON"]
    if sorted(front_doc) != sorted(direct_doc):
        problems.append(
            f"{path}: members {sorted(front_doc)} via the front door, "
            f"{sorted(direct_doc)} direct"
        )
    suffix = f"/v1/{kind}/{name}/mcp"
    resource = front_doc.get("resource")
    if not isinstance(resource, str) or not resource.endswith(suffix):
        problems.append(f"{path}: resource {resource!r} does not end with {suffix!r}")
    return problems


def probe_wk_core_templates(
    origin: str, core_origin: str, toolset: str, app: str
) -> None:
    """W7: Core's two protected-resource templates answer as Core does, direct.

    The assertion is the equality of the two answers — status and document shape — which
    holds on any Core build. The trace header (`X-Dial-Trace-Id`) is version-dependent (a
    Core 0.49.0+ opt-in feature, `responseTraceHeaders`, off by default), so it is not
    required; when a build does emit it, it must agree across the two answers.
    """
    failures: list[str] = []
    for kind, name in (("toolset", toolset), ("deployments", app)):
        path = f"{PRM_PREFIX}/v1/{kind}/{name}/mcp"
        front = _send(origin, "GET", path)
        print("  (next request: Core direct, outside the router)")
        direct = _send(core_origin, "GET", path)
        if front.status != direct.status:
            failures.append(
                f"{path}: front door {front.status}, Core direct {direct.status}"
            )
        failures.extend(_same_document_shape(path, front, direct, kind, name))
        if front.from_core != direct.from_core:
            failures.append(
                f"{path}: Core's trace header disagrees across the two answers "
                "(front door "
                f"{'present' if front.from_core else 'absent'}, Core direct "
                f"{'present' if direct.from_core else 'absent'})"
            )
        if front.nosniff:
            failures.append(f"{path}: the router's discriminator header is present")
    _verdict(
        "W7", failures, "Core's templates through the front door equal Core direct"
    )


def probe_wk_off_template(origin: str, toolset: str) -> None:
    """W8: shapes under Core's prefix that are not its templates are closed."""
    failures: list[str] = []
    for path in (
        f"{PRM_PREFIX}/v1/toolset/{toolset}/tools",
        f"{PRM_PREFIX}/v1/other",
    ):
        _check_closure(origin, "GET", path, failures)
    _verdict(
        "W8", failures, "off-template shapes under Core's prefix are the router's 404"
    )


def probe_wk_boundaries(origin: str, toolset: str) -> None:
    """W12: the served locations' end edges are closed."""
    failures: list[str] = []
    for path in (
        f"{AS_METADATA_PATH}X",
        f"{OIDC_METADATA_PATH}.json",
        f"{PRM_PREFIX}/v1/toolset/{toolset}/mcp/",
    ):
        _check_closure(origin, "GET", path, failures)
    _verdict("W12", failures, "the served locations' end edges are the router's 404")


def probe_wk_path_appended(origin: str, toolset: str, app: str) -> None:
    """W13: path-appended forms are the data path's refusal, never Core's answer."""
    failures: list[str] = []
    for resource in (f"/apps/{app}/mcp", f"/dial/{toolset}/mcp"):
        for suffix in (
            "/.well-known/openid-configuration",
            "/.well-known/oauth-protected-resource",
        ):
            path = f"{resource}{suffix}"
            response = _send(origin, "GET", path)
            if response.status != HTTP_NOT_FOUND:
                failures.append(f"GET {path}: status {response.status}, expected 404")
            if response.from_core:
                failures.append(f"GET {path}: Core's trace header is present")
            if "www-authenticate" in response.headers:
                failures.append(f"GET {path}: a WWW-Authenticate challenge is present")
    _verdict(
        "W13", failures, "path-appended forms are the router's refusal, not Core's"
    )


def _normalization_cells(toolset: str, app: str) -> dict[str, tuple[str, list[str]]]:
    """W10's cells: label -> (kind of expected answer, raw paths sent)."""
    core_prm = f"/.well-known/oauth-protected-resource/v1/toolset/{toolset}/mcp"
    prm_tail = f"oauth-protected-resource/v1/toolset/{toolset}/mcp"
    return {
        "a": ("document", ["/.well-known/openid-configuration/x/../y"]),
        "b": ("closure", ["/.well-known/openid-configuration/../unknown"]),
        "c": (
            "closure",
            [
                f"/.well-known/openid-configuration/../{prm_tail}",
                f"/.well-known/openid-configuration/%2e%2e/{prm_tail}",
                f"/.well-known/openid-configuration/%2E%2E/{prm_tail}",
                f"/.well-known/openid-configuration/..%2F{prm_tail}",
            ],
        ),
        "d": (
            "closure",
            [
                "/.well-known/unknown/../../v1/x",
                "/.well-known/unknown/%2e%2e/%2e%2e/v1/x",
                "/%2Ewell-known/unknown/../../v1/x",
                "//.well-known/unknown/../../v1/x",
                "/./.well-known/unknown/../../v1/x",
                "/%2F.well-known/unknown/../../v1/x",
                "/%2E%2F.well-known/unknown/../../v1/x",
            ],
        ),
        "e": ("closure", [f"{core_prm}%0A", "/.well-known/openid-configuration%0A"]),
        "f": ("gateway", ["/.well-known/x/../../dial/token"]),
        "g": ("data-path", [f"/.well-known/x/../../apps/{app}/mcp"]),
    }


def probe_wk_normalization(origin: str, toolset: str, app: str, cell: str) -> None:
    """W10, one cell: a raw spelling that normalizes across a namespace edge."""
    kind, paths = _normalization_cells(toolset, app)[cell]
    canonical = _canonical_document(origin) if kind == "document" else b""
    failures: list[str] = []
    for path in paths:
        if kind == "document":
            _check_document(origin, path, canonical, failures, gateway_answer=True)
        elif kind == "closure":
            _check_closure(origin, "GET", path, failures)
        else:
            response = _send(origin, "GET", path)
            print(f"  recorded  the {kind}'s answer: status {response.status}")
            if response.from_core:
                failures.append(f"GET {path}: Core's trace header is present")
            if "www-authenticate" in response.headers:
                failures.append(f"GET {path}: a WWW-Authenticate challenge is present")
            if response.nosniff:
                failures.append(
                    f"GET {path}: the router's closure answered; the request "
                    f"belongs to the {kind}"
                )
    _verdict(f"W10{cell}", failures, "the raw spelling never reaches Core")


def wellknown_probes(
    origin: str, core_origin: str, toolset: str, app: str
) -> list[tuple[str, Callable[[], None]]]:
    """The well-known rows after the controls, in the design's order."""
    rows: list[tuple[str, Callable[[], None]]] = [
        (
            "W1 openid-configuration serves the canonical document",
            lambda: probe_wk_oidc(origin),
        ),
        (
            "W2 path-insertion aliases serve the canonical document",
            lambda: probe_wk_path_insertion(origin, toolset, app),
        ),
        (
            "W4 unserved well-known paths are the router's 404",
            lambda: probe_wk_closed(origin),
        ),
        ("W5 closure is method-blind, no CORS", lambda: probe_wk_methods(origin)),
        (
            "W6 precedence: AS, toolset, and app documents still served",
            lambda: probe_wk_precedence(origin, toolset, app),
        ),
        (
            "W7 Core's templates through the front door equal Core direct",
            lambda: probe_wk_core_templates(origin, core_origin, toolset, app),
        ),
        (
            "W8 off-template shapes under Core's prefix are closed",
            lambda: probe_wk_off_template(origin, toolset),
        ),
    ]
    descriptions = {
        "a": "into the alias location, the document",
        "b": "out of the alias location, the closure",
        "c": "into the Core location from outside its raw spelling, the closure",
        "d": "out of the namespace into the catch-all, the closure",
        "e": "decoded trailing line break, the closure",
        "f": "into a gateway location, the gateway's answer (recorded)",
        "g": "into a data-path location, the data path's refusal (recorded)",
    }
    for cell, description in descriptions.items():
        rows.append(
            (
                f"W10{cell} normalization: {description}",
                partial(probe_wk_normalization, origin, toolset, app, cell),
            )
        )
    rows.append(
        (
            "W12 served locations' end edges are closed",
            lambda: probe_wk_boundaries(origin, toolset),
        )
    )
    rows.append(
        (
            "W13 path-appended forms are the data path's refusal",
            lambda: probe_wk_path_appended(origin, toolset, app),
        )
    )
    return rows


# The existing rows that need a minted token (and Core's request log); `--no-token` skips
# them. `main()` names the rows with these constants and the runner matches on them, so a
# renamed row cannot silently stop being skipped.
QUERY_ROW = "query string survives the routing"
APPS_QUERY_ROW = "query string survives the apps routing"
TOKEN_ROWS = frozenset({QUERY_ROW, APPS_QUERY_ROW})


def mint_probe_token(origin: str) -> str:
    """Mint a token Core accepts, so the query-string probe can measure a served request.

    The probe mints rather than reading a token file: the file would be stale almost
    whenever a later run read it, and a stale token never reaches the point where Core
    records the request URI — producing a log-shaped "routing failure" that is really an
    authentication one. Minting here keeps the two apart.

    The signing key is the gateway's own configured key, not a separately generated one:
    Core's provider entry points at the gateway's JWKS endpoint, so the gateway's key is
    the only one whose tokens Core validates. A probe signing with anything else would be
    measuring its own key, not the deployment's.

    The token lives in memory only and is never written: it is ten minutes of probe
    material, and a file would outlive the run.
    """
    env = load_env()
    payload = copy_identity_claims(
        fetch_identity_token(env), origin, [origin, AUDIENCE_MARKER]
    )
    key = SigningKey(require(env, "GATEWAY_SIGNING_KEY").replace("\\n", "\n"))
    return key.sign(payload)


def main() -> int:
    # Reach the stack on this host: Windows resolves `localhost` to `::1` first and
    # WSL2's IPv4-only port relay hangs on that address (the repo's WSL-NAT flake), so
    # resolution is pinned IPv4-first here. Only which address is tried first changes;
    # the origins dialled and the values asserted are untouched.
    prefer_ipv4_resolution()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN, help="the public origin")
    parser.add_argument(
        "--core-origin",
        default=DEFAULT_CORE_DIRECT_ORIGIN,
        help="Core's own origin, for the negative control (bypasses the router)",
    )
    parser.add_argument(
        "--toolset", default=DEFAULT_TOOLSET, help="a mapped toolset name"
    )
    parser.add_argument(
        "--app",
        default=DEFAULT_APP,
        help="a guard-passing app name, for the apps routing rows",
    )
    parser.add_argument(
        "--core-container",
        default=DEFAULT_CORE_CONTAINER,
        help="the instance's Core container, read for the query-string evidence",
    )
    parser.add_argument(
        "--group",
        choices=("all", "wellknown"),
        default="all",
        help="`wellknown` runs only the controls and the well-known rows (no token)",
    )
    parser.add_argument(
        "--no-token",
        action="store_true",
        help="skip minting a token and the rows that need one (the query-string rows)",
    )
    args = parser.parse_args()
    needs_token = args.group == "all" and not args.no_token

    # Minted before the probes run, so a failure to obtain a real identity token is
    # reported as itself rather than as a routing failure further in.
    token = ""
    if needs_token:
        try:
            token = mint_probe_token(args.origin)
        except (SpikeError, OSError, ValueError) as exc:
            print(f"could not mint the probe token: {type(exc).__name__}: {exc}")
            print(
                "the query-string probe needs a token Core trusts; see "
                "scripts/spike_env.py"
            )
            return 1

    state = {"challenge": ""}

    def record_core_challenge() -> None:
        state["challenge"] = negative_control(args.core_origin, args.toolset)

    existing: list[tuple[str, Callable[[], None]]] = [
        (
            QUERY_ROW,
            lambda: probe_query_string(
                args.origin, args.toolset, token, args.core_container
            ),
        ),
        (
            "flat AS metadata through the router",
            lambda: probe_authorization_server(args.origin),
        ),
        (
            "per-toolset PRM through the router",
            lambda: probe_protected_resource(args.origin, args.toolset),
        ),
        (
            "data-path 401 rewritten to the gateway's challenge",
            lambda: probe_challenge(args.origin, args.toolset, state["challenge"]),
        ),
        (
            "gateway paths reachable through the front door",
            lambda: probe_gateway_paths(args.origin),
        ),
        (
            "consent action route reachable through the front door",
            lambda: probe_consent_route(args.origin),
        ),
        (
            "apps PRM through the router",
            lambda: probe_app_protected_resource(args.origin, args.app),
        ),
        (
            "apps data-path 401 rewritten to the apps challenge",
            lambda: probe_app_challenge(args.origin, args.app),
        ),
        (
            APPS_QUERY_ROW,
            lambda: probe_app_query_string(
                args.origin, args.app, token, args.core_container
            ),
        ),
        (
            "status paths refused by the router's map (no gateway handler)",
            lambda: probe_status_path_dropped(args.origin, args.toolset),
        ),
        (
            "lockstep: the map and the guard hold their documented division",
            lambda: probe_lockstep(args.origin),
        ),
        (
            "lockstep: the apps map/guard division",
            lambda: probe_lockstep_apps(args.origin, f"applications/public/{args.app}"),
        ),
    ]
    wellknown = wellknown_probes(args.origin, args.core_origin, args.toolset, args.app)
    probes = (existing if args.group == "all" else []) + wellknown

    # The controls run FIRST, and a failed control stops the battery: the existing one
    # (Core's own challenge) is carried into the rewrite probe, and the well-known group's
    # two (W0 against Core, W0c against the gateway) establish the discriminators its rows
    # rely on.
    controls: list[tuple[str, Callable[[], None]]] = [
        ("negative control — Core's own challenge", record_core_challenge),
        (
            "W0 negative control — Core's own answer on a discovery path",
            lambda: probe_wk_control_core(args.core_origin),
        ),
        (
            "W0c negative control — the gateway's own 404",
            lambda: probe_wk_control_gateway(args.origin),
        ),
    ]
    return _run_battery(controls, probes, needs_token=needs_token)


def _run_battery(
    controls: list[tuple[str, Callable[[], None]]],
    probes: list[tuple[str, Callable[[], None]]],
    *,
    needs_token: bool,
) -> int:
    """Run the controls (a failure stops the battery), then the probes, then report."""
    total = len(controls) + len(probes)
    results: list[tuple[str, str]] = []
    for index, (name, run) in enumerate(controls, start=1):
        print(f"[{index}/{total}] {name}")
        try:
            run()
        except ProbeError as exc:
            print(f"  FAILED    {exc}")
            results.append((name, "FAIL"))
            print("\nthe control failed, so no later probe's acceptance means anything")
            results.extend((later, "not run") for later, _ in controls[index:])
            results.extend((later, "not run") for later, _ in probes)
            _report(results)
            return 1
        results.append((name, "pass"))
        print()

    for index, (name, run) in enumerate(probes, start=len(controls) + 1):
        print(f"[{index}/{total}] {name}")
        if not needs_token and name in TOKEN_ROWS:
            print("  skipped   needs a minted token (--no-token)")
            results.append((name, "skipped"))
            print()
            continue
        try:
            run()
        except ProbeError as exc:
            print(f"  FAILED    {exc}")
            results.append((name, "FAIL"))
        else:
            results.append((name, "pass"))
        print()

    return _report(results)


def _report(results: list[tuple[str, str]]) -> int:
    """Print the battery's row table and return the process exit code."""
    print("=== battery verdict ===")
    for name, verdict in results:
        print(f"  {verdict:8s}  {name}")
    failed = [name for name, verdict in results if verdict not in ("pass", "skipped")]
    if failed:
        print(f"\n{len(failed)} of {len(results)} probes failed")
        return 1
    skipped = sum(1 for _, verdict in results if verdict == "skipped")
    note = f" ({skipped} skipped)" if skipped else ""
    print(f"\nall {len(results) - skipped} probes passed{note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
