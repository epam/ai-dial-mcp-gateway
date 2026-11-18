"""Probe the front door's resource-path addressing end to end, failing-first.

The front door's name segment became a **resource path** — one or more percent-encoded
segments whose decoded form is Core's deployment id (`toolsets/{bucket}/{name}`,
`applications/{bucket}/{name}`, or a bare config name). This battery is that change's
instrument: it runs against the composed stack and asserts the whole addressing story —
the router forwards raw bytes, the guard is the authority over the decoded form, and one
canonical identity binds the discovery document, the flow's listing read, and the data
path.

**Negative controls run first, and they must FAIL against the fixed stack.** Before any
positive verdict is trusted, the battery proves it can return a failure: two rows assert
the *pre-fix* shapes (an encoded-name MCP call refused by the router; the stored toolset's
full-URL listing read answering 404). On the fixed stack both assertions are false — the
router forwards byte-faithfully, and Core resolves the full-URL path — so the control is
"red as designed", and a control that unexpectedly *holds* means the fix is absent, which
stops the battery before any later acceptance can mean anything.

The rows, after the controls:

* **(2) the stored-toolset chain** — the front door 401 challenges the multi-segment
  metadata path, discovery serves the document, `/dial/authorize` accepts the resource-URI
  path, Core's listing read resolves the same id, and a **live tool call through the front
  door** succeeds. The credential-call and token-exchange legs need a human sign-in against
  a real upstream and are the interactive harness's rows — this battery reports that
  boundary rather than faking a pass.
* **(2b) the user-bucket row** — the same chain for a resource in the caller's own
  ciphertext bucket. The ciphertext is learned from Core's own `GET /v1/bucket` and the
  resource id is copied **verbatim** from Core's `PUT` response — never computed. A second
  realm user (provisioned through the Keycloak admin API, the same access
  `scripts/provision_keycloak.py` uses) is refused 403 on the same front-door path, the
  isolation assertion. Both the resource and the second user are cleaned up.
* **(3) byte-fidelity** — `%20`, `%3F`, `%25`, non-ASCII, `%2F` are forwarded verbatim,
  asserted from the URI Core's own log recorded.
* **(3b) match-domain** — a query-bearing request routes with the parameter forwarded raw
  and intact; a post-`/mcp` path tail is refused 404 and never forwarded.
* **(4) refused shapes** — dot-segments, empty segments, trailing dots, a reserved first
  segment, and raw non-ASCII are refused by the router with 404.
* **(5) canonicalization** — a non-canonical spelling of one resource is accepted at the
  same surfaces as the canonical spelling (one identity). The token-audience-equality leg
  needs a minted token and is reported as the interactive harness's row.
* **(6) bounds** — a pathological long/deep URI answers fast (the ReDoS row), and an
  over-length or over-depth path is refused with the fixed reason, one audit record.

Nothing here prints a credential: every token appears as a redacted handle, and the
fixture names are probe-local, cleaned up by the script. Run with `PYTHONUTF8=1`.

Usage:
    PYTHONUTF8=1 python scripts/probe_front_door_paths.py
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_routing import mint_probe_token
from provision_keycloak import admin_base, login
from spike_env import (
    HTTP_OK,
    load_env,
    prefer_ipv4_resolution,
    redact,
    request,
    request_user_token,
    require,
)

# The statuses the rows assert on, named so a probe reads as a status, not a number.
HTTP_CREATED = 201
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404
HTTP_REDIRECT = 302

# The public origin the composed router publishes; matches `GATEWAY_PUBLIC_ORIGIN`.
DEFAULT_ORIGIN = "http://localhost:8090"

# Core on its own host-published port, outside the router. The listing-read row calls it
# here: the read is Core's, and the front door is deliberately not on it.
DEFAULT_CORE_ORIGIN = "http://localhost:8081"

# The instance's containers, read for the evidence each row can only get from inside: Core's
# recorded request URI (the byte-fidelity rows), the gateway's audit trail (the guard's
# fixed reason).
DEFAULT_CORE_CONTAINER = "dial-instance-core-1"
DEFAULT_GATEWAY_CONTAINER = "ai-dial-mcp-gateway-mcp-signin-gateway-1"

# The probe's own user agent, so a row's failure is never an upstream bot protection.
USER_AGENT = "dial-mcp-gateway-front-door-probe/1.0"

# Where the well-known protected-resource prefix sits before the routed path.
PRM_PREFIX = "/.well-known/oauth-protected-resource"

# The public callback the authorize rows name. It must be a redirect URI the client
# resolves; the rows never follow it (they assert the 302 to the identity provider).
DEFAULT_CALLBACK_URI = "http://127.0.0.1:8767/callback"

# The fixed segment rules the gateway guard enforces on the decoded path, mirrored here so
# the over-limit rows build an input the guard - not the router's grammar - refuses.
RESOURCE_PATH_MAX_SEGMENTS = 32
RESOURCE_PATH_MAX_BYTES = 900

# The gateway's fixed refusal reason for every decoded path-shape failure.
INVALID_RESOURCE_PATH = "invalid_resource_path"

# The ceiling for the pathological-URI row: a refusal slower than this means the grammar
# is backtracking on a crafted path, which the ReDoS discipline forbids.
REDOS_MAX_SECONDS = 5.0


class ProbeError(RuntimeError):
    """A row's expectation was not met, or the battery could not run it.

    Each message names the URL, the status, and the value expected, and never a token or a
    key — this text is printed and lands in evidence.
    """


class ControlHoldsError(ProbeError):
    """A negative control unexpectedly held, so the pre-fix shape is still present.

    The control asserts the *old* behaviour; on the fixed stack it must not hold. When it
    does, the fix has not landed and no later row's acceptance can be trusted.
    """

    def __init__(self, name: str, detail: str) -> None:
        super().__init__(f"negative control {name!r} held: {detail}")


class SetupError(ProbeError):
    """The battery could not establish a precondition it needs (a token, a fixture)."""


class StatusError(ProbeError):
    """A request answered a status the row did not expect."""

    def __init__(self, url: str, status: int, expected: str, detail: str = "") -> None:
        suffix = f": {detail}" if detail else ""
        super().__init__(f"{url} answered HTTP {status}, expected {expected}{suffix}")


class ChallengeError(ProbeError):
    """The 401 challenge did not quote the metadata path the row expected."""

    def __init__(self, url: str, challenges: list[str], expected: str) -> None:
        super().__init__(
            f"{url} answered 401 with {challenges!r}; expected exactly one challenge "
            f"quoting {expected!r}"
        )


class LogMissingError(ProbeError):
    """A fact the row asserts from a container log was not found there."""

    def __init__(self, container: str, what: str) -> None:
        super().__init__(f"{container} logged no {what}")


def docker(*args: str) -> str:
    """Run a command in the WSL docker environment and return its stdout.

    The rows need Core's log and the gateway's audit trail, and both containers run under
    WSL2 on this host, so those reads are `wsl -e docker` calls rather than file reads.
    """
    try:
        completed = subprocess.run(  # noqa: S603
            ["wsl", "-e", "docker", *args],  # noqa: S607 - host-resolved, argv is fixed
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        message = f"`wsl -e docker {' '.join(args)}` failed: {exc}"
        raise ProbeError(message) from exc
    if completed.returncode != 0:
        stderr = completed.stderr.decode(errors="replace").strip()
        message = (
            f"`wsl -e docker {' '.join(args)}` exited {completed.returncode}: {stderr}"
        )
        raise ProbeError(message)
    return completed.stdout.decode(errors="replace")


def _origin_parts(origin: str) -> tuple[str, int]:
    """An origin's host and port, for the raw-path HTTP client."""
    parsed = urllib.parse.urlparse(origin)
    return parsed.hostname or "localhost", parsed.port or 80


def raw_request(  # noqa: PLR0913 - one keyword per request fact the rows vary
    origin: str,
    target: str,
    *,
    method: str = "GET",
    token: str | None = None,
    extra_headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int = 30,
) -> tuple[int, dict[str, str], str]:
    """One HTTP call over a raw socket, so the request-target is sent exactly as given.

    `urllib` is avoided for the routing rows on purpose: a client that normalized a
    dot-segment or re-encoded an escape would probe something other than the bytes the row
    means to send, and the whole point of the map is the raw request URI. `http.client`
    sends the target verbatim.
    """
    host, port = _origin_parts(origin)
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    headers.update(extra_headers or {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = body.encode() if body is not None else None
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        try:
            connection.request(method, target, body=payload, headers=headers)
            response = connection.getresponse()
        except UnicodeEncodeError:
            # `http.client` encodes the request line as ASCII. A raw non-ASCII
            # request-target (the shape the router must refuse) can only be sent over a
            # socket by hand - which is exactly what the refused-shape row needs.
            return _raw_request_latin1(
                host, port, method, target, headers, payload, timeout
            )
        raw = response.read().decode(errors="replace")
        return response.status, dict(response.getheaders()), raw
    finally:
        with contextlib.suppress(OSError):
            connection.close()


def _raw_request_latin1(  # noqa: PLR0913, PLR0917 - one parameter per request fact
    host: str,
    port: int,
    method: str,
    target: str,
    headers: dict[str, str],
    payload: bytes | None,
    timeout: int,
) -> tuple[int, dict[str, str], str]:
    """One request sent over a socket, the target written as latin-1 bytes.

    The only caller is a raw non-ASCII request-target: `http.client` refuses it, and a
    client that percent-encoded it would probe a different request than the row means.
    """
    line = f"{method} {target} HTTP/1.1".encode("latin-1")
    header_bytes = b"".join(
        f"{name}: {value}\r\n".encode("latin-1") for name, value in headers.items()
    )
    if payload is not None:
        header_bytes += f"Content-Length: {len(payload)}\r\n".encode("latin-1")
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(line + b"\r\n" + header_bytes + b"\r\n" + (payload or b""))
        response = http.client.HTTPResponse(sock)
        response.begin()
        raw = response.read().decode(errors="replace")
        return response.status, dict(response.getheaders()), raw


def fetch(
    url: str,
    *,
    method: str = "GET",
    token: str | None = None,
    extra_headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> tuple[int, dict[str, str], str]:
    """One ordinary HTTP call (for the non-path-critical surfaces), returning on 4xx too."""
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    headers.update(extra_headers or {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(  # noqa: S310 - operator-supplied local endpoint
        url, headers=headers, method=method, data=body
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:  # noqa: S310
            return (
                response.status,
                dict(response.headers),
                response.read().decode(errors="replace"),
            )
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read().decode(errors="replace")


def _challenges(headers: dict[str, str]) -> list[str]:
    """Every `WWW-Authenticate` a response carried (case-insensitive header name)."""
    return [
        value for name, value in headers.items() if name.lower() == "www-authenticate"
    ]


def _request_uri(log_line: str) -> str:
    """The `request.uri` a Core log line carries, which includes the query string."""
    key = '"request.uri":"'
    start = log_line.find(key)
    if start < 0:
        return ""
    start += len(key)
    end = log_line.find('"', start)
    return log_line[start:end] if end > start else ""


# The endpoint every probe fixture points at. Core only needs a toolset to be resolvable;
# the MCP fixture service is reachable by Core on the instance network, so a live tool
# call through the front door resolves a real upstream for the no-auth public toolset.
FIXTURE_ENDPOINT = "http://mcp-app-fixture:9000/mcp"


def admin_token(env: dict[str, str]) -> str:
    """A Core-admin identity token, the one that admits the fixture writes.

    The write is admin-gated in Core (`aidial.access.admin.rules`), so the client whose
    claim mapper carries the `admin` role is the one to use — the same client
    `scripts/spike_register_toolset.py` uses.
    """
    return request_user_token(
        env, "KEYCLOAK_TOKEN_CLIENT_ID", "KEYCLOAK_TOKEN_CLIENT_SECRET"
    )


def user_token(env: dict[str, str], username: str, password: str) -> str:
    """A realm user's DIAL identity token through the gateway identity client.

    Identity is client-independent on this realm (tokens from different clients for one
    user share `sub`), so the identity client — the one carrying no admin role — is the
    right one here: it is the identity a real sign-in would carry, which is what the flow
    and the isolation row need.
    """
    token_url = (
        f"{require(env, 'KEYCLOAK_ADMIN_URL').rstrip('/')}"
        f"/realms/dial/protocol/openid-connect/token"
    )
    form = {
        "client_id": require(env, "KEYCLOAK_IDENTITY_CLIENT_ID"),
        "username": username,
        "password": password,
        "grant_type": "password",
    }
    secret = env.get("KEYCLOAK_IDENTITY_CLIENT_SECRET", "")
    if secret:
        form["client_secret"] = secret
    status, body, _ = request("POST", token_url, form=form)
    if status != HTTP_OK:
        message = f"the realm token request for {username!r} failed: {status}"
        raise SetupError(message)
    return json.loads(body)["access_token"]


def test_user_token(env: dict[str, str]) -> str:
    """The `.env` test user's identity token (the bucket owner in the user-bucket row)."""
    return user_token(
        env, require(env, "TEST_USER_NAME"), require(env, "TEST_USER_PASSWORD")
    )


def caller_bucket(env: dict[str, str], core_origin: str, token: str) -> str:
    """The caller's own bucket ciphertext, **learned from Core's own answer**.

    Core computes the Base58 ciphertext of `Users/{sub}`; the probe never does. A leg that
    derived this segment instead of copying Core's answer would be a defect in the row,
    not a tolerance of it — so the value comes from `GET /v1/bucket` or the row fails.
    """
    status, body, _ = request("GET", f"{core_origin}/v1/bucket", token=token)
    if status != HTTP_OK:
        message = f"GET /v1/bucket answered {status}: {body[:200]}"
        raise SetupError(message)
    bucket = json.loads(body).get("bucket")
    if not bucket:
        message = "GET /v1/bucket answered without a bucket segment"
        raise SetupError(message)
    return bucket


def create_stored_toolset(core_origin: str, token: str, bucket: str, name: str) -> str:
    """Create a stored toolset and return the resource id **verbatim from Core**.

    The id is copied from the write's own answer (`url`), never assembled: the resource
    path is Core's to name, and the row must present exactly the path Core handed it.
    """
    body = {
        "display_name": "Front-door probe fixture",
        "endpoint": FIXTURE_ENDPOINT,
        "transport": "HTTP",
        "description": "created by scripts/probe_front_door_paths.py; deleted by it",
    }
    status, response, _ = request(
        "PUT",
        f"{core_origin}/v1/toolsets/{bucket}/{name}",
        body=body,
        token=token,
        headers={"If-None-Match": "*"},
    )
    if status not in (HTTP_OK, HTTP_CREATED):
        message = (
            f"PUT /v1/toolsets/{bucket}/{name} answered {status}: {response[:200]}"
        )
        raise SetupError(message)
    document = json.loads(response)
    resource_id = document.get("url") or f"toolsets/{bucket}/{name}"
    return resource_id


def delete_stored_toolset(core_origin: str, token: str, resource_id: str) -> None:
    """Delete a stored resource by its Core-handed id (bucket/name split from `id`)."""
    # `resource_id` is `toolsets/{bucket}/{name}` (or `applications/...`); the delete route
    # is `/v1/toolsets/{bucket}/{name}`, so the type segment is dropped and the rest kept.
    parts = resource_id.split("/")
    route = f"{core_origin}/v1/toolsets/" + "/".join(parts[1:])
    request("DELETE", route, token=token)


def provision_realm_user(env: dict[str, str]) -> tuple[str, str, str]:
    """Create a second realm user through the Keycloak admin API; return (username, pw, id).

    The harness's `.env` carries only the one test user, so the isolation row's second
    caller is provisioned here — the same admin access `scripts/provision_keycloak.py`
    uses. `requiredActions` is emptied and the name fields set, or Keycloak refuses the
    password grant with "Account is not fully set up".
    """
    base = admin_base(env)
    token = login(env)
    username = f"probe-user-{secrets.token_hex(4)}"
    password = f"Probe-{secrets.token_hex(10)}"
    body = {
        "username": username,
        "enabled": True,
        "email": f"{username}@example.invalid",
        "emailVerified": True,
        "firstName": "Probe",
        "lastName": "User",
        "requiredActions": [],
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    status, response = request(
        "POST",
        f"{base}/users",
        body=body,
        token=token,
        headers={"Content-Type": "application/json"},
    )[:2]
    if status not in (HTTP_CREATED, 204):
        message = f"the realm user create answered {status}: {response[:200]}"
        raise SetupError(message)
    status, body, _ = request(
        "GET", f"{base}/users?username={username}&exact=true", token=token
    )
    users = json.loads(body) if status == HTTP_OK else []
    if not users:
        message = f"the provisioned user {username!r} was not found after create"
        raise SetupError(message)
    return username, password, users[0]["id"]


def delete_realm_user(env: dict[str, str], user_id: str) -> None:
    """Delete a provisioned realm user, so the local realm converges back."""
    token = login(env)
    request("DELETE", f"{admin_base(env)}/users/{user_id}", token=token)


# ----------------------------------------------------------------------------- controls


def control_encoded_name_refused(origin: str) -> None:
    """Negative control (1a): the encoded-name MCP call is *not* refused by the router.

    The pre-fix front door's single-segment capture (`[a-z0-9-]+`) matched neither an
    encoded name nor a multi-segment path, so such a call fell through and never reached
    Core. On the fixed stack the map forwards it byte-faithfully and Core answers it — the
    401 challenge, or a resolved call — so the control must NOT hold: a 404 here would
    mean the map regressed and the addressing fix is absent.
    """
    target = "/dial/toolsets/public/probe%20encoded/mcp"
    status, _, _ = raw_request(origin, target)
    print(f"  request   GET {origin}{target}  (raw; a decoded capture would 400 here)")
    print(f"  status    {status}")
    if status == HTTP_NOT_FOUND:
        raise ControlHoldsError(
            "encoded-name-refused",
            "the encoded-name MCP call answered 404, so the router did not forward it — "
            "the byte-faithful map is absent",
        )
    print(
        "  verdict   red as designed — the encoded name is not refused by the router "
        "(the control's pre-fix shape is gone)"
    )


def control_full_url_listing_404(
    core_origin: str, resource_id: str, token: str
) -> None:
    """Negative control (1b): the stored toolset's full-URL listing read is *not* 404.

    The pre-fix front door's listing read addressed a bare name; the full-URL path
    (`toolsets/public/{name}`) did not resolve. On the fixed stack Core resolves it through
    the same dual lookup the data path uses, so the read answers 200 — the control must NOT
    hold: a 404 here would mean the stored-path addressing is absent.
    """
    status, _, _ = request(
        "GET", f"{core_origin}/openai/toolsets/{resource_id}", token=token
    )
    print(
        f"  request   GET {core_origin}/openai/toolsets/{resource_id}  (direct to Core)"
    )
    print(f"  status    {status}")
    if status == HTTP_NOT_FOUND:
        raise ControlHoldsError(
            "full-url-listing-404",
            "the full-URL listing read answered 404, so Core did not resolve the stored "
            "path — the stored-path addressing is absent",
        )
    print(
        "  verdict   red as designed — the full-URL listing read resolves "
        "(the control's pre-fix shape is gone)"
    )


# ---------------------------------------------------------------- (2) stored-toolset chain


def row_stored_toolset_chain(
    origin: str, core_origin: str, resource_id: str, read_token: str
) -> None:
    """(2) The stored-toolset chain end to end, through the front door.

    The front door 401 challenges the multi-segment metadata path, discovery serves the
    document naming that path, `/dial/authorize` accepts the resource-URI path (a 302 to
    the identity provider), and the flow's listing read resolves the same id. The
    credential-call and token-exchange legs need a human sign-in against a real upstream
    and are the interactive harness's rows — reported here, never faked.
    """
    path = f"{PRM_PREFIX}/dial/{resource_id}/mcp"
    mcp_target = f"/dial/{resource_id}/mcp"

    # The 401 challenge on the data path must quote the multi-segment metadata path.
    status, headers, _ = raw_request(origin, mcp_target)
    challenges = _challenges(headers)
    expected_metadata = f"{origin}{path}"
    print(f"  request   GET {origin}{mcp_target}  (no Authorization header)")
    print(f"  status    {status}")
    print(f"  challenges {challenges!r}")
    if status != HTTP_UNAUTHORIZED:
        raise StatusError(f"{origin}{mcp_target}", status, "401 (the challenge)")
    if len(challenges) != 1 or expected_metadata not in challenges[0]:
        raise ChallengeError(f"{origin}{mcp_target}", challenges, expected_metadata)
    print(f"  resource_metadata  {expected_metadata}")

    # Discovery serves the document for the same path. The document's `resource` member is
    # the resource URI (the protected resource), which is what the challenge's metadata path
    # describes — the metadata path is the challenge's, the resource URI is the document's.
    status, _, body = fetch(f"{origin}{path}")
    print(f"  request   GET {origin}{path}")
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise StatusError(f"{origin}{path}", status, "200 (the discovery document)")
    document = json.loads(body)
    expected_resource = f"{origin}/dial/{resource_id}/mcp"
    if document.get("resource") != expected_resource:
        message = (
            f"the discovery document names resource {document.get('resource')!r}, "
            f"expected {expected_resource!r}"
        )
        raise ProbeError(message)
    print(f"  resource  {document.get('resource')}")

    # The listing read (Core, direct) resolves the same id — the one identifier. The read
    # is authenticated because Core's auth filter precedes routing, so an anonymous call
    # proves nothing about resolution; the echoed `id` is the assertion.
    status, body, _ = request(
        "GET",
        f"{core_origin}/openai/toolsets/{resource_id}",
        token=read_token,
    )
    print(
        f"  request   GET {core_origin}/openai/toolsets/{resource_id}  (listing read)"
    )
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise StatusError(
            f"{core_origin}/openai/toolsets/{resource_id}",
            status,
            "200 (the listing read resolves the stored path)",
        )
    echoed = json.loads(body).get("id")
    print(f"  id        {echoed}")
    if echoed != resource_id:
        message = (
            f"the listing read echoed id {echoed!r}, expected {resource_id!r} — the read "
            "resolved a different resource than the path names"
        )
        raise ProbeError(message)
    print("  verdict   green — the stored path is one identifier end to end")
    print(
        "  note      the credential-call and token-exchange legs need a human upstream "
        "sign-in; they are the interactive harness's rows (deferred)"
    )


def _authorize_target(
    origin: str, resource: str, *, client_id: str, redirect_uri: str
) -> str:
    """The `/dial/authorize` request target for a resource, with the required parameters."""
    query = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "resource": resource,
        "code_challenge": "probe-challenge",
        "code_challenge_method": "S256",
        "state": "probe-state",
    }
    return f"/dial/authorize?{urllib.parse.urlencode(query)}"


def row_authorize_accepts_path(
    origin: str, resource_id: str, *, client_id: str, redirect_uri: str
) -> None:
    """(2, part) `/dial/authorize` accepts the resource-URI path — a 302 to the IdP.

    A guard-passing, admitted resource path allocates a flow and redirects to the identity
    provider; the assertion is that the multi-segment path is *admitted* (302), not refused
    `invalid_target` — the token-mint and audience legs are the interactive harness's.
    """
    resource = f"{origin}/dial/{resource_id}/mcp"
    target = _authorize_target(
        origin, resource, client_id=client_id, redirect_uri=redirect_uri
    )
    status, headers, _ = raw_request(origin, target)
    location = headers.get("location", "")
    print(f"  request   GET {origin}{target.split('?')[0]}?…&resource={resource}")
    print(f"  status    {status}")
    print(f"  location  {location.split('?')[0] if location else '<none>'}")
    if status != HTTP_REDIRECT or "error=" in location:
        message = (
            f"the authorize endpoint did not accept the stored path: HTTP {status}"
            f"{', error in ' + location if location else ''}"
        )
        raise ProbeError(message)
    print(
        "  verdict   green — the multi-segment resource path is admitted at authorize"
    )


def row_live_tool_call(
    origin: str, resource_id: str, *, token: str, core_origin: str
) -> None:
    """(2, part) A live tool call through the front door with a Core-accepted token.

    The call goes through the router to Core's data path (the gateway is deliberately not
    on it). The token is minted the way the routing battery mints one — signed by the
    gateway's own key, whose JWKS Core's provider entry points at — so a 200 with a real
    `tools/list` result proves Core accepted the token and resolved the stored toolset's
    upstream through the front door.

    The fixture toolset points at the local MCP fixture service, which needs no upstream
    credential, so this leg completes without a human sign-in — the only runnable
    end-to-end leg, and the one that makes the addressing claim concrete.
    """
    target = f"/dial/{resource_id}/mcp"
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    status, _, response = raw_request(
        origin,
        target,
        method="POST",
        token=token,
        body=body,
        extra_headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        },
        timeout=60,
    )
    print(f"  request   POST {origin}{target}  (token {redact(token)})")
    print(f"  status    {status}")
    message = _jsonrpc_message(response)
    if status != HTTP_OK or message is None or "result" not in message:
        message = (
            f"the live tool call through the front door failed: HTTP {status}, "
            f"{response[:200]}"
        )
        raise ProbeError(message)
    tools = message["result"].get("tools", [])
    print(f"  tools     {len(tools)}")
    print(f"  first     {json.dumps([tool.get('name') for tool in tools[:3]])}")
    print(
        "  verdict   green — a live tool call resolves the stored toolset through the front door"
    )


def row_apps_twin(origin: str, app_resource_id: str) -> None:
    """(2, apps twin) A stored-app path is routed and challenged under `/apps/`.

    The apps twin of the stored-toolset chain's front-door half: the 401 challenge quotes
    the apps metadata path, and discovery serves the document quoting the app resource.
    """
    path = f"{PRM_PREFIX}/apps/{app_resource_id}/mcp"
    mcp_target = f"/apps/{app_resource_id}/mcp"
    status, headers, _ = raw_request(origin, mcp_target)
    challenges = _challenges(headers)
    expected_metadata = f"{origin}{path}"
    print(f"  request   GET {origin}{mcp_target}  (no Authorization header)")
    print(f"  status    {status}")
    print(f"  challenges {challenges!r}")
    if status != HTTP_UNAUTHORIZED:
        raise StatusError(f"{origin}{mcp_target}", status, "401 (the apps challenge)")
    if len(challenges) != 1 or expected_metadata not in challenges[0]:
        raise ChallengeError(f"{origin}{mcp_target}", challenges, expected_metadata)
    status, _, body = fetch(f"{origin}{path}")
    print(f"  request   GET {origin}{path}")
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise StatusError(
            f"{origin}{path}", status, "200 (the apps discovery document)"
        )
    document = json.loads(body)
    expected_resource = f"{origin}/apps/{app_resource_id}/mcp"
    if document.get("resource") != expected_resource:
        message = (
            f"the apps discovery document names resource {document.get('resource')!r}, "
            f"expected {expected_resource!r}"
        )
        raise ProbeError(message)
    print(f"  resource  {document.get('resource')}")
    print(
        "  verdict   green — the stored-app path is routed and challenged under /apps/"
    )


def _jsonrpc_message(raw: str) -> dict | None:
    """The first JSON-RPC message in a streamable-HTTP body (SSE or plain JSON)."""
    for line in raw.splitlines():
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except ValueError:
                return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


# ------------------------------------------------------------- (2b) the user-bucket row


def row_user_bucket_chain(  # noqa: PLR0913 - one fact per argument the chain needs
    origin: str,
    core_origin: str,
    resource_id: str,
    *,
    owner_token: str,
    env: dict[str, str],
    client_id: str,
    redirect_uri: str,
) -> None:
    """(2b) A user-bucket resource addressed by its verbatim Core-handed path.

    The resource id is Core's own (`toolsets/{ciphertext}/{name}`), never computed. The
    chain's front-door half runs against it — 401 challenge, discovery, authorize, and the
    listing read — and the isolation assertion follows: a second realm user, on the same
    front-door path, is refused by Core's access chain (403), same-answer-as-Core.

    The row's negative-control shape: the ciphertext segment is alphanumeric and
    single-segment — wire-conforming and guard-admitted — so a refusal of it by the router
    or the guard is a defect, never a verdict, and the row fails loudly.
    """
    ciphertext = resource_id.split("/")[1]

    # The ciphertext is alphanumeric and single-segment: the router must forward it and
    # the guard must admit it. A refusal of this shape is a defect in the row.
    if not ciphertext.isalnum():
        message = (
            f"Core handed a non-alphanumeric bucket segment {ciphertext!r}; the row's "
            "premise (a wire-conforming, guard-admitted ciphertext) does not hold"
        )
        raise ProbeError(message)

    # The front-door chain, exactly as for the public toolset.
    row_stored_toolset_chain(origin, core_origin, resource_id, owner_token)
    row_authorize_accepts_path(
        origin, resource_id, client_id=client_id, redirect_uri=redirect_uri
    )

    # The isolation assertion: a second user is refused on the same front-door path. The
    # data path is the sharpest site — Core's per-call check runs there — so it is the one
    # asserted; the listing read is asserted too, since the flow's availability decision is
    # the same decision.
    username, password, user_id = provision_realm_user(env)
    try:
        second = user_token(env, username, password)
        target = f"/dial/{resource_id}/mcp"
        status, _, _ = raw_request(origin, target, token=second)
        print(f"  isolation GET {origin}{target}  (a second user's token)")
        print(f"  status    {status}")
        if status != HTTP_FORBIDDEN:
            message = (
                f"the second user's front-door call answered {status}, expected 403 — "
                "Core's access chain did not refuse a foreign user bucket"
            )
            raise ProbeError(message)
        status, _, _ = request(
            "GET", f"{core_origin}/openai/toolsets/{resource_id}", token=second
        )
        print(
            f"  isolation GET {core_origin}/openai/toolsets/{resource_id}  (listing read)"
        )
        print(f"  status    {status}")
        if status != HTTP_FORBIDDEN:
            message = (
                f"the second user's listing read answered {status}, expected 403 — the "
                "isolation decision differs from the data path's"
            )
            raise ProbeError(message)
        print(
            "  verdict   green — the verbatim user-bucket path is served, isolation intact"
        )
    finally:
        delete_realm_user(env, user_id)


# -------------------------------------------------------------------- (3) byte fidelity


# Each shape is (raw target, the substring Core's recorded URI must contain verbatim).
_BYTE_FIDELITY_SHAPES = (
    ("%20", "a%20b"),
    ("%3F", "a%3Fb"),
    ("%25", "100%25"),
    ("non-ascii", "%C3%A9tape"),
    ("%2F", "a%2Fb"),
)


def row_byte_fidelity(origin: str, core_container: str, *, token: str) -> None:
    """(3) Each encoded shape is forwarded byte-identically, asserted from Core's own log.

    The assertion is read from the URI Core recorded receiving, which is the only place a
    re-encoding is visible — a proxy that decoded and re-encoded an escape would still
    return the response Core produced from the decoded form.
    """
    bucket = "public"
    for label, encoded in _BYTE_FIDELITY_SHAPES:
        marker = f"bf-{secrets.token_hex(6)}"
        name = f"{marker}{encoded}"
        target = f"/dial/toolsets/{bucket}/{name}/mcp"
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        raw_request(
            origin,
            target,
            method="POST",
            token=token,
            body=body,
            extra_headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        log = docker("logs", "--since", "2m", core_container)
        seen = [line for line in log.splitlines() if marker in line]
        uris = {_request_uri(line) for line in seen if _request_uri(line)}
        print(
            f"  shape {label:10s} forwarded; Core recorded {sorted(uris) or '<nothing>'}"
        )
        expected_fragment = f"/v1/toolset/toolsets/{bucket}/{name}/mcp"
        if not any(expected_fragment in uri for uri in uris):
            message = (
                f"the {label} shape was not forwarded byte-identically: Core recorded "
                f"{sorted(uris) or '<no request>'}, expected a URI containing "
                f"{expected_fragment!r}"
            )
            raise ProbeError(message)
    print("  verdict   green — every encoded shape reached Core byte-identically")


# ---------------------------------------------------------------- (3b) match domain


def row_match_domain(origin: str, core_container: str, *, token: str) -> None:
    """(3b) The whole-URI match domain: a query routes, a post-`/mcp` tail is refused.

    A query-bearing session-resume request routes with the parameter forwarded raw and
    intact (`%2F` in the value included); a path tail after `/mcp` is refused 404 and never
    forwarded — the capture cannot alias a longer path onto the data-path prefix.
    """
    marker = f"md-{secrets.token_hex(6)}"
    # The query value carries a `%2F` on purpose: the raw query must ride intact.
    target = f"/dial/notion/mcp?sessionId={marker}%2F1"
    status, _, _ = raw_request(origin, target, token=token)
    print(f"  request   GET {origin}{target}  (query-bearing)")
    print(f"  status    {status}")
    log = docker("logs", "--since", "2m", core_container)
    seen = [line for line in log.splitlines() if marker in line]
    if not any(marker in _request_uri(line) for line in seen):
        message = (
            f"the query parameter {marker!r} did not reach Core: the match domain refused "
            "a query-bearing request, or the parameter was dropped"
        )
        raise ProbeError(message)
    uris = {_request_uri(line) for line in seen if _request_uri(line)}
    if not any("%2F1" in uri for uri in uris):
        message = (
            f"the query value's %2F was not forwarded raw: Core recorded {sorted(uris)}"
        )
        raise ProbeError(message)
    print(f"  core log  {sorted(uris)}")

    # A post-`/mcp` path tail is refused 404 and never forwarded.
    for tail in (f"/dial/{marker}/mcp/extra", f"/apps/{marker}/mcp/extra"):
        status, _, _ = raw_request(origin, tail)
        print(f"  request   GET {origin}{tail}  (path tail after /mcp)")
        print(f"  status    {status}")
        if status != HTTP_NOT_FOUND:
            raise StatusError(f"{origin}{tail}", status, "404 (the tail is refused)")
    print(
        "  verdict   green — the match domain admits the query tail and refuses the path tail"
    )


# --------------------------------------------------------------- (4) refused shapes


# Each shape the router's grammar refuses, with a label for the record.
_REFUSED_SHAPES = (
    ("dot-segment ..", "/dial/a/../b/mcp"),
    ("dot-segment .", "/dial/a/./b/mcp"),
    ("empty segment", "/dial/toolsets//public/x/mcp"),
    ("trailing dot", "/dial/toolsets/public/x./mcp"),
    ("reserved first segment", "/dial/authorize/x/mcp"),
)


def row_refused_shapes(origin: str) -> None:
    """(4) The router refuses the grammar's non-conforming shapes with 404.

    Each shape is sent with the raw target preserved (a client that normalized it would
    probe a different request); the assertion is nginx's own 404, which is the refusal the
    `if ($dial_target = "")` form produces without forwarding.
    """
    for label, target in _REFUSED_SHAPES:
        status, _, _ = raw_request(origin, target)
        print(f"  shape {label:24s} {target} -> {status}")
        if status != HTTP_NOT_FOUND:
            raise StatusError(f"{origin}{target}", status, "404 (the router's refusal)")

    # Raw non-ASCII in the request-target is refused: every such name is servable in its
    # encoded form, so the refusal is of the wire spelling, never a resource. nginx refuses
    # the invalid request line itself (400) before any location runs, which is the router
    # refusing the shape without forwarding — the property asserted.
    raw_target = "/dial/toolsets/public/café/mcp"
    status, _, _ = raw_request(origin, raw_target)
    print(f"  shape raw non-ASCII            {raw_target} -> {status}")
    if status not in (400, HTTP_NOT_FOUND):
        raise StatusError(
            f"{origin}{raw_target}", status, "400 or 404 (raw non-ASCII refused)"
        )
    print("  verdict   green — every non-conforming shape is refused by the router")


# ------------------------------------------------------------- (5) canonicalization


def row_canonicalization(origin: str, core_origin: str, admin_token: str) -> None:
    """(5) A non-canonical spelling resolves to one identity with the canonical one.

    `%78` and `x` are one resource: the discovery document for a `%78`-spelled path echoes
    the offered spelling (the mirror rule) and Core's listing read resolves *both* spellings
    to the same `id` — one identity. The strongest leg — that both spellings mint a token
    with the same audience — needs the interactive harness's mint and is reported as
    deferred.

    The row creates its own fixture whose name ends in `x`, so the `%78` escape folds onto
    the same resource, and cleans it up.
    """
    name = f"probe-canon-{secrets.token_hex(4)}x"
    resource_id = create_stored_toolset(core_origin, admin_token, "public", name)
    folded_id = f"{resource_id[:-1]}%78"
    try:
        if not resource_id.endswith("x"):
            message = (
                f"the fixture id {resource_id!r} does not end in x as the row needs"
            )
            raise ProbeError(message)
        # The discovery document for the non-canonical spelling echoes the offered spelling.
        offered_uri = f"{origin}{PRM_PREFIX}/dial/{folded_id}/mcp"
        status, _, body = fetch(offered_uri)
        print(f"  request   GET {offered_uri}  (non-canonical offering, %78 for x)")
        print(f"  status    {status}")
        if status != HTTP_OK:
            raise StatusError(
                offered_uri, status, "200 (a guard-passing spelling is served)"
            )
        document = json.loads(body)
        expected_resource = f"{origin}/dial/{folded_id}/mcp"
        if document.get("resource") != expected_resource:
            message = (
                f"the discovery document for the offered spelling names "
                f"{document.get('resource')!r}, expected the offered spelling "
                f"{expected_resource!r}"
            )
            raise ProbeError(message)
        print(f"  resource  {document.get('resource')}  (the offered spelling, echoed)")

        # One identity: Core's listing read resolves both spellings to the same id.
        canonical_read = request(
            "GET", f"{core_origin}/openai/toolsets/{resource_id}", token=admin_token
        )
        folded_read = request(
            "GET", f"{core_origin}/openai/toolsets/{folded_id}", token=admin_token
        )
        if canonical_read[0] != HTTP_OK or folded_read[0] != HTTP_OK:
            raise StatusError(
                f"{core_origin}/openai/toolsets/{folded_id}",
                folded_read[0],
                "200 (both spellings resolve)",
            )
        canonical_echo = json.loads(canonical_read[1]).get("id")
        folded_echo = json.loads(folded_read[1]).get("id")
        print(f"  listing   canonical -> {canonical_echo!r}; %78 -> {folded_echo!r}")
        if canonical_echo != folded_echo:
            message = (
                f"the two spellings resolved different identities: {canonical_echo!r} "
                f"vs {folded_echo!r} — canonicalization did not fold them to one"
            )
            raise ProbeError(message)
        print(
            "  note      the token-audience-equality leg (both spellings mint one audience) "
            "needs the interactive harness's mint (deferred)"
        )
        print(
            "  verdict   green — the non-canonical spelling is one identity, echo-offered"
        )
    finally:
        delete_stored_toolset(core_origin, admin_token, resource_id)


# ---------------------------------------------------------------- (6) bounds / ReDoS


def row_bounds(origin: str, gateway_container: str) -> None:
    """(6) The pathological URI is refused fast; an over-bound path is refused with reason.

    The ReDoS row sends a long, deep, non-matching URI and asserts a fast refusal (the
    request-line buffer bound plus the grammar's non-backtracking shape). The over-bound
    row sends a path over the segment cap through the guard's surface (discovery) and
    asserts the fixed-vocabulary reason lands on the audit trail.
    """
    # The ReDoS row: a long, deep, non-matching URI refused quickly by the grammar. The
    # shape is deep and has no `/mcp` suffix, so it is the grammar (not the buffer) that
    # answers — the point of the row — and the length stays under the request-line bound so
    # the regex is what scans it; the timer bounds the scan.
    pathological = "/dial/" + "/".join("a" * 40 for _ in range(90))
    started = time.monotonic()
    status, _, _ = raw_request(origin, pathological, timeout=15)
    elapsed = time.monotonic() - started
    print(
        f"  request   GET {origin}/dial/...(90 segments, {len(pathological)} chars, "
        f"no /mcp suffix)..."
    )
    print(f"  status    {status}  ({elapsed:.3f}s)")
    if status != HTTP_NOT_FOUND:
        raise StatusError(f"{origin}/dial/...", status, "404 (the grammar refuses it)")
    if elapsed > REDOS_MAX_SECONDS:
        message = (
            f"the pathological URI took {elapsed:.3f}s to refuse - the grammar is "
            "backtracking on a crafted path"
        )
        raise ProbeError(message)

    # The request-line buffer bound: a URI past the stated `large_client_header_buffers`
    # bound is refused before any regex scans it (nginx's own 414), which is the upstream
    # cap the ReDoS row's fast refusal rests on.
    over_buffer = "/dial/" + "a" * 5000 + "/mcp"
    status, _, _ = raw_request(origin, over_buffer, timeout=15)
    print(
        f"  request   GET {origin}/dial/<5000 chars>/mcp  (past the request-line buffer)"
    )
    print(f"  status    {status}")
    if status not in (400, 414, HTTP_NOT_FOUND):
        raise StatusError(
            f"{origin}/dial/<over-buffer>",
            status,
            "400, 414, or 404 (the request-line bound refuses it)",
        )

    # The over-bound row: over the segment cap, through the guard's discovery surface.
    deep = "/".join(f"s{index}" for index in range(RESOURCE_PATH_MAX_SEGMENTS + 8))
    over_depth_uri = f"{origin}{PRM_PREFIX}/dial/{deep}/mcp"
    status, _, _ = fetch(over_depth_uri)
    print(
        f"  request   GET {over_depth_uri}  ({RESOURCE_PATH_MAX_SEGMENTS + 8} segments)"
    )
    print(f"  status    {status}")
    if status != HTTP_NOT_FOUND:
        raise StatusError(over_depth_uri, status, "404 (the guard refuses over-depth)")
    if not _audit_carries(gateway_container, INVALID_RESOURCE_PATH, deep[:16]):
        raise LogMissingError(
            gateway_container,
            f"audit record carrying {INVALID_RESOURCE_PATH!r} for the over-depth path",
        )
    print(
        f"  audit     a record carries reason {INVALID_RESOURCE_PATH!r} (fixed vocabulary)"
    )

    # Over-length: exceed the decoded byte cap.
    long_segment = "z" * (RESOURCE_PATH_MAX_BYTES + 50)
    over_len_uri = f"{origin}{PRM_PREFIX}/dial/toolsets/public/{long_segment}/mcp"
    status, _, _ = fetch(over_len_uri)
    print(
        f"  request   GET {origin}{PRM_PREFIX}/dial/toolsets/public/"
        f"<{len(long_segment)} bytes>/mcp"
    )
    print(f"  status    {status}")
    if status != HTTP_NOT_FOUND:
        raise StatusError(over_len_uri, status, "404 (the guard refuses over-length)")
    print(
        "  verdict   green - the pathological URI is refused fast, the over-bound path "
        "with the fixed reason"
    )


def _audit_carries(container: str, reason: str, name_fragment: str) -> bool:
    """Whether the gateway's audit trail carries a record with this reason and name."""
    log = docker("logs", "--since", "2m", container)
    return any(reason in line and name_fragment in line for line in log.splitlines())


# ------------------------------------------------------------------------------- main


def _run_control(name: str, run) -> bool:
    """Run a negative control; return True when it held (the pre-fix shape is present)."""
    print(f"  --- control: {name} ---")
    try:
        run()
    except ControlHoldsError as exc:
        print(f"  FAILED    {exc}")
        return True
    except ProbeError as exc:
        # A control that could not run at all (an unreachable stack) is also a stop, but a
        # different one: report it as an error, not as the control holding.
        print(f"  ERROR     {exc}")
        raise
    return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN, help="the public origin")
    parser.add_argument(
        "--core-origin",
        default=DEFAULT_CORE_ORIGIN,
        help="Core's own origin, for the listing read and the controls",
    )
    parser.add_argument(
        "--core-container", default=DEFAULT_CORE_CONTAINER, help="Core's container name"
    )
    parser.add_argument(
        "--gateway-container",
        default=DEFAULT_GATEWAY_CONTAINER,
        help="the gateway's container name, for the audit trail",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help="the client the authorize rows name (default: GATEWAY_E2E_CLIENT_ID)",
    )
    parser.add_argument(
        "--callback-uri",
        default=DEFAULT_CALLBACK_URI,
        help="the registered redirect URI the authorize rows name (never followed)",
    )
    return parser


def main() -> int:
    # Reach the stack on this host: Windows resolves `localhost` to `::1` first and
    # WSL2's IPv4-only port relay hangs on that address (the repo's WSL-NAT flake), so
    # resolution is pinned IPv4-first here. Only which address is tried first changes;
    # the origins dialled and the values asserted are untouched.
    prefer_ipv4_resolution()
    args = build_parser().parse_args()
    env = load_env()
    client_id = args.client_id or env.get("GATEWAY_E2E_CLIENT_ID")
    if not client_id:
        print("no client id: pass --client-id or set GATEWAY_E2E_CLIENT_ID in .env")
        return 1

    results: list[tuple[str, str]] = []

    # The fixtures are created once and cleaned up in `finally`: the whole battery names
    # them across many rows, and a leftover fixture would drift the local environment.
    # Each is registered the moment it exists, so a failure part-way through the setup —
    # between two creations — cannot leak one already created: the `finally` below deletes
    # every registered fixture, whatever happened.
    admin = admin_token(env)
    owner = test_user_token(env)
    created: list[tuple[str, str]] = []  # (owner token, Core-handed resource id)

    try:
        public_name = f"probe-pub-{secrets.token_hex(4)}"
        public_id = create_stored_toolset(
            args.core_origin, admin, "public", public_name
        )
        created.append((admin, public_id))

        # A stored app path (its existence is never decided on the discovery surface, so a
        # phantom path exercises the apps twin without an app registered in Core).
        app_id = f"applications/public/probe-app-{secrets.token_hex(4)}"

        # The user-bucket fixture: the ciphertext bucket is Core's answer, the id is Core's.
        bucket = caller_bucket(env, args.core_origin, owner)
        ubucket_name = f"probe-ub-{secrets.token_hex(4)}"
        ubucket_id = create_stored_toolset(
            args.core_origin, owner, bucket, ubucket_name
        )
        created.append((owner, ubucket_id))

        # 1. The negative controls run FIRST; a control that holds stops the battery.
        print("[controls] negative controls — run first, and must FAIL against the fix")
        held_x = _run_control(
            "encoded-name-refused", lambda: control_encoded_name_refused(args.origin)
        )
        held_l = _run_control(
            "full-url-listing-404",
            lambda: control_full_url_listing_404(args.core_origin, public_id, admin),
        )
        results.append(
            (
                "control: encoded name not refused by the router",
                "red" if not held_x else "HELD",
            )
        )
        results.append(
            ("control: full-URL listing read resolves", "red" if not held_l else "HELD")
        )
        if held_x or held_l:
            print(
                "\na negative control held, so the fix is absent and no later row's "
                "acceptance means anything"
            )
            _report(results)
            return 1
        print(
            "  controls red as designed — the instrument can fail; two controls prove it"
        )
        print()

        # The rows, in the order they build on one another.
        rows = [
            (
                "(2) stored-toolset chain",
                lambda: row_stored_toolset_chain(
                    args.origin, args.core_origin, public_id, admin
                ),
            ),
            (
                "(2) authorize admits the resource path",
                lambda: row_authorize_accepts_path(
                    args.origin,
                    public_id,
                    client_id=client_id,
                    redirect_uri=args.callback_uri,
                ),
            ),
            (
                "(2) live tool call through the front door",
                lambda: row_live_tool_call(
                    args.origin,
                    public_id,
                    token=mint_probe_token(args.origin),
                    core_origin=args.core_origin,
                ),
            ),
            (
                "(2) apps twin — stored-app path routed and challenged",
                lambda: row_apps_twin(args.origin, app_id),
            ),
            (
                "(2b) user-bucket chain and isolation",
                lambda: row_user_bucket_chain(
                    args.origin,
                    args.core_origin,
                    ubucket_id,
                    owner_token=owner,
                    env=env,
                    client_id=client_id,
                    redirect_uri=args.callback_uri,
                ),
            ),
            (
                "(3) byte fidelity",
                lambda: row_byte_fidelity(
                    args.origin,
                    args.core_container,
                    token=mint_probe_token(args.origin),
                ),
            ),
            (
                "(3b) match domain",
                lambda: row_match_domain(
                    args.origin,
                    args.core_container,
                    token=mint_probe_token(args.origin),
                ),
            ),
            ("(4) refused shapes", lambda: row_refused_shapes(args.origin)),
            (
                "(5) canonicalization",
                lambda: row_canonicalization(args.origin, args.core_origin, admin),
            ),
            (
                "(6) bounds and ReDoS",
                lambda: row_bounds(args.origin, args.gateway_container),
            ),
        ]

        for index, (name, run) in enumerate(rows, start=1):
            print(f"[{index}/{len(rows)}] {name}")
            try:
                run()
            except ProbeError as exc:
                print(f"  FAILED    {exc}")
                results.append((name, "FAIL"))
            else:
                results.append((name, "pass"))
            print()

        return _report(results)
    finally:
        # Cleanup runs whatever happened: the local environment converges back.
        for fixture_token, resource_id in created:
            delete_stored_toolset(args.core_origin, fixture_token, resource_id)


def _report(results: list[tuple[str, str]]) -> int:
    """Print the battery's row table and return the process exit code."""
    print("=== battery verdict ===")
    for name, verdict in results:
        print(f"  {verdict:8s}  {name}")
    failed = [name for name, verdict in results if verdict not in ("pass", "red")]
    if failed:
        print(f"\n{len(failed)} of {len(results)} rows failed or held")
        return 1
    print(f"\nall {len(results)} rows green (controls red as designed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
