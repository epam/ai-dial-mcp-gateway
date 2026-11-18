"""The live end-to-end sign-in smoke, through the front door (deployment provisioning check).

This is the check group 6 exists for: with the gateway's Keycloak client provisioned, the
front router up, and Core's provider entry repointed at the gateway's own JWKS, can a
client walk the whole chain — `/dial/authorize` through the router, the identity provider's
login, the gateway's callback, `/dial/token` — and then make a **live tool call** with the
token it received?

Every step is measured against the composed stack; nothing is simulated. The probe drives
the identity provider's own login form the way a browser would (reading the form's action
URL out of the page it renders and replaying the session cookies), which keeps the whole
run browser-free and repeatable.

The gateway's consent/attribution checkpoint sits between the identity leg and the mint:
on the **first** attribution of a flow to a (user, client) pair the gateway renders its own
decision page — a gateway-owned page, not the identity provider's login form — and waits
for the user's act. The probe completes that act exactly as the page's own form would: it
posts the flow id and `approve` (the default) or `deny` (`--deny`) to the consent route the
form's action names, and continues the chain. The decision page is recognized by
construction (the consent form's action and the flow-id field it carries), never by the
login form's shape, so the probe cannot mistake one for the other.

An approve advances the flow to whichever stage the checkpoint deferred: on the app kind
and the stored-credential short-circuit the mint follows directly (the probe completes to
a live tool call); on the toolset consent branch the display interstitial follows, which
continues to the upstream authorization URL — a stage needing a real provider account this
probe does not hold, so the probe reports that boundary and stops. A **deny** consumes the
flow: the probe asserts the refusal page and that no code was issued, then stops.

A **repeat** sign-in for an already-approved pair renders no decision page and needs no
mode: the flow is zero-click, exactly as before.

`--app` serves the flow as an app resource (no upstream credential, so it mints directly);
the default serves a toolset. Both shapes share one chain, differing only in the front-door
path prefix.

The map step (`/<kind>/<name>/mcp`) is Core's own path — the gateway is deliberately not on
the data path — so the call is made through the router, with the token the gateway minted.
That is the assertion: a token this flow produced is one Core accepts for a real user.

Nothing here prints a credential: the login password comes from `.env`, the token and the
authorization code appear as redacted handles only.

Usage:
    PYTHONUTF8=1 python scripts/probe_end_to_end.py
    PYTHONUTF8=1 python scripts/probe_end_to_end.py --client-id <pre-registered-client>
    PYTHONUTF8=1 python scripts/probe_end_to_end.py --app --toolset <app-name>
    PYTHONUTF8=1 python scripts/probe_end_to_end.py --deny
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import http.client
import json
import re
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import (
    HTTP_OK,
    SpikeError,
    decode_claims,
    load_env,
    redact,
    require,
)

# The public origin the composed router publishes. Matches `GATEWAY_PUBLIC_ORIGIN`.
DEFAULT_ORIGIN = "http://localhost:8090"

# The toolset the local mapping names.
DEFAULT_TOOLSET = "notion"

# Where the probe's callback listener runs. The client below must be one the gateway
# resolves and whose registered redirect URIs include this exact loopback URL.
DEFAULT_CALLBACK_PORT = 8767

# The statuses a redirect chain continues on.
_REDIRECTS = (301, 302, 303, 307, 308)

# The status the consent route answers a denial with: the refusal page, and no redirect
# to any target (a browser-facing refusal here is a page, per the route's own contract).
HTTP_BAD_REQUEST = 400

# How many redirect hops a chain may take before the probe calls it a loop. The observed
# chain is four (Keycloak login -> Keycloak finalize -> gateway callback -> client).
_MAX_HOPS = 8

_USER_AGENT = "dial-mcp-gateway-spike/1.0"

# The consent/attribution checkpoint's action route, the path the decision page's form
# posts to. The gateway owns it; the probe posts the flow id and the chosen action there
# exactly as a browser would.
CONSENT_PATH = "/dial/consent"

# The action tokens the decision page's two buttons carry, and the two outcomes the
# probe can drive.
_APPROVE = "approve"
_DENY = "deny"

# The decision page's own markers: the consent form's action and the flow-id field it
# carries. Detected by construction — a page that carries both IS the decision page — so
# the probe never infers it from the login form's absence.
_DECISION_FORM = re.compile(
    r'<form[^>]*\baction="' + re.escape(CONSENT_PATH) + r'"', re.IGNORECASE
)
_DECISION_FLOW_ID = re.compile(r'name="flow_id"\s+value="([^"]+)"', re.IGNORECASE)


class ChainError(SpikeError):
    """A step of the chain produced something the next step cannot use."""

    def __init__(self, step: str, detail: str) -> None:
        super().__init__(f"{step}: {detail}")


def _lower(headers: Any) -> dict[str, str]:
    """The header set as a plain mapping with lowercase keys.

    nginx answers with `location`, not `Location`, and the message object's own lookup is
    case-insensitive while a mapping built from it by name is not — reading a redirect
    target through the wrong one silently yields `None`.
    """
    return {key.lower(): value for key, value in headers.items()}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that never follows, so each hop of the chain is observable."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


class _Session:
    """A single browser session: one cookie set, replayed on every request.

    Keycloak's login is three requests — the authorize page, the credential submit, and a
    finalize hop — and each sets its own cookie. A probe that kept only the first would
    submit the form and then lose the session, which reads as a failed login rather than
    as a missing cookie.
    """

    def __init__(self) -> None:
        self._cookies: dict[str, str] = {}

    def _absorb(self, message: Any, headers: dict[str, str]) -> None:
        """Keep every cookie this response carried, by name.

        Read from the response's own message rather than from the flattened header
        mapping: a response may set several cookies, and flattening to a `dict` keeps
        only the last of a repeated header — which silently dropped the login session
        cookie and made the next request look like an expired session.
        """
        raws = message.get_all("Set-Cookie") or []
        if not raws:
            single = headers.get("set-cookie")
            raws = [single] if single else []
        for raw in raws:
            name, _, value = raw.split(";")[0].strip().partition("=")
            if name:
                self._cookies[name] = value

    def _header(self) -> dict[str, str]:
        if not self._cookies:
            return {}
        return {"Cookie": "; ".join(f"{k}={v}" for k, v in self._cookies.items())}

    def request(
        self,
        url: str,
        *,
        form: dict[str, str] | None = None,
        raw_body: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, str, dict[str, str]]:
        """One request, returning status, body, and lowercase headers rather than raising."""
        headers = {"User-Agent": _USER_AGENT}
        headers.update(self._header())
        headers.update(extra_headers or {})
        payload: bytes | None = None
        if form is not None:
            payload = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif raw_body is not None:
            payload = raw_body.encode()
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(  # noqa: S310 - a configured local endpoint
            url, data=payload, headers=headers, method="POST" if payload else "GET"
        )
        opener = urllib.request.build_opener(_NoRedirect)
        try:
            response = opener.open(request, timeout=60)
            message = response.headers
            status, body = response.status, response.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            message = exc.headers
            status, body = exc.code, exc.read().decode(errors="replace")
        except urllib.error.URLError as exc:
            raise ChainError(url, f"could not be reached: {exc.reason}") from exc
        response_headers = _lower(message)
        self._absorb(message, response_headers)
        return status, body, response_headers


class _CallbackHandler(BaseHTTPRequestHandler):
    """Catches the client's redirect and stops the listener."""

    captured: ClassVar[dict[str, str]] = {}
    done: ClassVar[threading.Event] = threading.Event()

    @classmethod
    def absorb(cls, query: str) -> None:
        """Record a callback's parameters and mark the chain complete."""
        cls.captured.update(
            {key: value[0] for key, value in urllib.parse.parse_qs(query).items()}
        )
        cls.done.set()

    def do_GET(self) -> None:
        self.absorb(urllib.parse.urlparse(self.path).query)
        self.send_response(HTTP_OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body><h3>sign-in captured</h3></body></html>")
        _CallbackHandler.done.set()

    def log_message(self, *args: object) -> None:
        """Silence the stdlib's per-request logging (it prints the query string)."""


class _ReusableServer(HTTPServer):
    """An HTTP server that can bind a port a previous run left in TIME_WAIT."""

    allow_reuse_address = True
    daemon_threads = True


def _step(number: int, title: str) -> None:
    print(f"=== step {number}: {title} ===")


def _safe(url: str | None) -> str:
    """A URL with its query string dropped, so a redirect target can be reported safely.

    A redirect in this chain can carry an authorization code, and a probe that echoed the
    URL on failure would print a credential into the terminal and into any captured
    evidence. The path and host are what identifies the hop; the query is not needed.
    """
    if not url:
        return "<none>"
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def _mcp_tools_list(run: _Run, token: str) -> tuple[int, dict | None]:
    """Call `tools/list` through the front door and read the first JSON-RPC message.

    The call goes through the router (Core's data path), with the token the flow minted:
    that is what makes this an end-to-end check rather than a unit-level one. The
    response is streamable HTTP — SSE when the server streams, plain JSON otherwise — so
    both shapes are read.
    """
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
    host, port = (
        urllib.parse.urlparse(run.origin).hostname,
        urllib.parse.urlparse(run.origin).port,
    )
    connection = http.client.HTTPConnection(host, port, timeout=120)
    connection.request(
        "POST",
        run.mcp_path,
        body=body,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": _USER_AGENT,
        },
    )
    response = connection.getresponse()
    raw = response.read().decode(errors="replace")
    connection.close()
    for line in raw.splitlines():
        if line.startswith("data:"):
            return response.status, json.loads(line[5:].strip())
    try:
        return response.status, json.loads(raw)
    except ValueError:
        return response.status, None


@dataclass(frozen=True)
class _Run:
    """The configuration one smoke run works against.

    `toolset` is the toolset or app the flow serves — kept as the field name every caller
    already reads — and `kind` is the front-door path shape it is served under (`dial` for
    a toolset, `apps` for an app). The two shapes differ only in their path prefix: a
    toolset's flow may take the upstream consent branch (it can carry a stored credential),
    while an app's mints directly — so the app shape is the one that completes headlessly
    inside this probe.
    """

    origin: str
    toolset: str
    client_id: str
    callback_port: int
    kind: str = "dial"

    @property
    def redirect_uri(self) -> str:
        return f"http://127.0.0.1:{self.callback_port}/callback"

    @property
    def resource(self) -> str:
        return f"{self.origin}/{self.kind}/{self.toolset}/mcp"

    @property
    def mcp_path(self) -> str:
        return f"/{self.kind}/{self.toolset}/mcp"

    @property
    def metadata_path(self) -> str:
        return f"/.well-known/oauth-protected-resource/{self.kind}/{self.toolset}/mcp"


@dataclass(frozen=True)
class _Secrets:
    """The client's own PKCE pair and the state it round-trips."""

    verifier: str
    challenge: str
    state: str


def _new_secrets() -> _Secrets:
    """A fresh PKCE S256 pair and state for one run.

    The pair belongs to the *client* — the gateway verifies it at `/dial/token`, so it is
    the client's proof that the code came back to whoever started the flow.
    """
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return _Secrets(
        verifier=verifier, challenge=challenge, state=secrets.token_urlsafe(16)
    )


def probe_discovery(session: _Session, run: _Run) -> None:
    """The resource metadata a harness reads first, through the front door."""
    _step(1, "discovery through the front door")
    status, body, _headers = session.request(f"{run.origin}{run.metadata_path}")
    if status != HTTP_OK:
        raise ChainError("discovery", f"the resource metadata answered HTTP {status}")
    document = json.loads(body)
    print(f"  resource  {document.get('resource')}")
    print(f"  servers   {json.dumps(document.get('authorization_servers'))}")
    if document.get("resource") != run.resource:
        raise ChainError("discovery", f"metadata names {document.get('resource')!r}")


def probe_authorize(session: _Session, run: _Run, secrets_: _Secrets) -> str:
    """`/dial/authorize`, returning the identity provider URL it redirects to.

    The redirect is where the two legs are stitched together, so the checks here are the
    ones a browser could not make: the scope set is exactly the gateway client's, and no
    `openid` reached the provider.
    """
    _step(2, "/dial/authorize through the front door")
    query = {
        "client_id": run.client_id,
        "redirect_uri": run.redirect_uri,
        "response_type": "code",
        "resource": run.resource,
        "code_challenge": secrets_.challenge,
        "code_challenge_method": "S256",
        "state": secrets_.state,
    }
    status, body, headers = session.request(
        f"{run.origin}/dial/authorize?{urllib.parse.urlencode(query)}"
    )
    location = headers.get("location")
    if status not in _REDIRECTS or not location:
        raise ChainError(
            "authorize",
            f"expected a redirect to the identity provider, got HTTP {status}: "
            f"{body[:200]}",
        )
    target = urllib.parse.urlparse(location)
    relayed = urllib.parse.parse_qs(target.query)
    scopes = " ".join(relayed.get("scope", [])).split()
    print(f"  status    {status} -> {target.netloc}")
    print(f"  client    {relayed.get('client_id', ['<none>'])[0]}")
    print(f"  scope     {' '.join(scopes)}")
    if "openid" in scopes or "offline_access" in scopes:
        raise ChainError(
            "authorize", f"the redirect requested a forbidden scope: {scopes}"
        )
    return location


def _looks_like_html(body: str) -> bool:
    """Whether a response body renders as an HTML page (a gateway page's shape)."""
    return re.search(r"<html[\s>]|<!doctype", body[:4096], re.IGNORECASE) is not None


def _decision_flow_id(body: str) -> str | None:
    """The decision page's flow id, or `None` when the body is not that page.

    The checkpoint's page is recognized by construction: it carries the consent form —
    whose action is the consent route — and the flow-id field that form posts. A page
    with both IS the decision page, so the probe never infers it from the login form's
    absence, and can never submit the provider credential to it.
    """
    if not _DECISION_FORM.search(body):
        return None
    match = _DECISION_FLOW_ID.search(body)
    if match is None:
        return None
    return html.unescape(match.group(1))


def _interstitial_target(body: str) -> str | None:
    """The display interstitial's continuation URL, or `None` when the body is not it.

    The consent branch serves this notice after the decision (approve) — and, for an
    already-approved pair, in place of it. It continues by meta refresh to the upstream
    authorization URL, which needs a real provider account; the probe reports that
    boundary rather than following it.
    """
    if not _looks_like_html(body):
        return None
    # The target is read to the closing quote (a `&amp;`-encoded query contains a `;`, so
    # stopping at `;` would truncate it) and then entity-decoded.
    match = re.search(r'http-equiv="refresh"[^>]*url=([^"]+)"', body, re.IGNORECASE)
    if match is None:
        return None
    return html.unescape(match.group(1))


def drive_login(
    session: _Session, env: dict[str, str], first_url: str, run: _Run
) -> tuple[str, str | None]:
    """Walk the provider's login form and submit the test user's credential.

    The chain is followed by hand, one hop at a time, for two reasons: each hop is
    evidence (which host answered, which form was rendered), and the final hop is the
    client's own redirect URI, whose query string carries an authorization code that must
    not be printed.

    Returns where the flow landed, as ``(kind, value)``:

    * ``("callback", None)`` — the flow reached the client callback on its own: the
      zero-click path an already-approved (user, client) pair takes, and the short-circuit
      paths' mint.
    * ``("decision", flow_id)`` — the consent/attribution checkpoint rendered its decision
      page (a first attribution); the caller drives the user's act.
    * ``("upstream", url)`` — the display interstitial was served, continuing to the
      upstream authorization URL; completing it needs a real provider account.

    The decision page and the interstitial are checked **before** the login form: all
    three are HTML with a `<form>` or a refresh, and the decision page's action is the
    gateway's consent route, so the login handling would otherwise submit the provider
    credential to it. Detection is by each page's own markers, never by absence.
    """
    _step(3, "the identity provider's login form")
    location: str | None = first_url
    status = 302
    hops = 0
    submitted = False
    while (
        status in _REDIRECTS and hops < _MAX_HOPS and not _CallbackHandler.done.is_set()
    ):
        hops += 1
        if location is None:
            raise ChainError("login", "a redirect hop carried no Location")
        target = urllib.parse.urlparse(location)
        if (
            target.hostname in {"127.0.0.1", "localhost"}
            and target.port == run.callback_port
        ):
            print(f"  hop {hops}: reached the client redirect URI")
            _CallbackHandler.absorb(target.query)
            return ("callback", None)
        status, body, headers = session.request(location)
        location = headers.get("location")
        if status != HTTP_OK:
            print(f"  hop {hops}: HTTP {status}")
            continue
        flow_id = _decision_flow_id(body)
        if flow_id is not None:
            print(f"  hop {hops}: the consent/attribution decision page rendered")
            return ("decision", flow_id)
        interstitial = _interstitial_target(body)
        if interstitial is not None:
            print(f"  hop {hops}: the display interstitial rendered")
            return ("upstream", interstitial)
        match = re.search(r'<form[^>]*\baction="([^"]+)"', body)
        if match is None:
            print(f"  hop {hops}: HTTP {status} (no form)")
            continue
        status, _body, headers = session.request(
            html.unescape(match.group(1)),
            form={
                "username": require(env, "TEST_USER_NAME"),
                "password": require(env, "TEST_USER_PASSWORD"),
            },
        )
        location = headers.get("location")
        submitted = True
        print(f"  credentials submitted -> HTTP {status}")
    if not submitted and not _CallbackHandler.done.is_set():
        raise ChainError(
            "login", "the provider never rendered a login form to submit credentials to"
        )
    return ("callback", None)


def complete_checkpoint(session: _Session, run: _Run, flow_id: str, action: str) -> str:
    """Drive the decision page's action exactly as the page's own form would.

    The form posts the flow id and the chosen action to the consent route, and nothing
    else — every other fact the continuation needs the gateway re-derives from its own
    flow record — so the probe sends exactly those two fields.

    Returns where the flow went:

    * ``"continue"`` — the action advanced the flow to the client callback (the mint): the
      approve on a short-circuit path, or any already-approved client. The callback is
      absorbed, so the existing chain steps (callback, token, live call) proceed unchanged.
    * ``"upstream"`` — the consent branch's approve served the display interstitial, which
      continues to the upstream authorization URL; completing it needs a real provider
      account this probe does not hold, so the probe reports the boundary and stops.
    * ``"denied"`` — the deny consumed the flow: the refusal page was served and no code
      was issued.
    """
    _step(4, "the consent/attribution decision page")
    print(f"  flow      {redact(flow_id)}")
    print(f"  action    {action}")
    status, body, headers = session.request(
        f"{run.origin}{CONSENT_PATH}",
        form={"flow_id": flow_id, "action": action},
    )
    print(f"  response  HTTP {status}")
    if action == _DENY:
        if status != HTTP_BAD_REQUEST or not _looks_like_html(body):
            raise ChainError(
                "consent",
                f"the deny answered HTTP {status} without the refusal page: {body[:200]}",
            )
        print("  page      the refusal page — no authorization code was issued")
        return "denied"
    location = headers.get("location")
    if status in _REDIRECTS and location:
        # A redirect delivery (tolerated for forward-compatibility): the mint as a 302.
        target = urllib.parse.urlparse(location)
        if (
            target.hostname in {"127.0.0.1", "localhost"}
            and target.port == run.callback_port
        ):
            print("  redirect  to the client callback (the mint)")
            _CallbackHandler.absorb(target.query)
            return "continue"
        raise ChainError(
            "consent",
            f"the approve redirected off the client callback: {_safe(location)}",
        )
    if status == HTTP_OK and _looks_like_html(body):
        # The approve answers with a navigating page: the mint's page navigates to the
        # client's registered redirect, the consent branch's display interstitial navigates
        # to the upstream authorization URL. Which one this is decides where the flow went,
        # and the delivery is a page (never a redirect) because a form submission's redirect
        # is governed by the decision page's `form-action 'self'`. The target can carry an
        # `&amp;`-encoded query, so it is read to the closing quote (not to a `;`, which the
        # entity itself contains) and then entity-decoded.
        match = re.search(r'http-equiv="refresh"[^>]*url=([^"]+)"', body, re.I)
        target_url = html.unescape(match.group(1)) if match else ""
        target = urllib.parse.urlparse(target_url)
        if (
            target.hostname in {"127.0.0.1", "localhost"}
            and target.port == run.callback_port
        ):
            print("  page      the mint navigating to the client callback")
            _CallbackHandler.absorb(target.query)
            return "continue"
        print(
            f"  page      the display interstitial — continues to {_safe(target_url)}"
        )
        return "upstream"
    raise ChainError("consent", f"the approve answered HTTP {status}: {body[:200]}")


def probe_callback(state: str, *, step: int = 5) -> str:
    """Wait for the client's callback and return the authorization code."""
    _step(step, "the gateway's callback")
    if not _CallbackHandler.done.wait(60):
        raise ChainError("callback", "no client callback arrived")
    print(f"  params    {sorted(_CallbackHandler.captured)}")
    if _CallbackHandler.captured.get("state") != state:
        raise ChainError("callback", "the state parameter did not round-trip")
    code = _CallbackHandler.captured.get("code")
    if not code:
        raise ChainError(
            "callback",
            "no authorization code: "
            f"{_CallbackHandler.captured.get('error')} "
            f"{_CallbackHandler.captured.get('error_description', '')[:200]}",
        )
    print("  state     round-tripped")
    print(f"  code      {redact(code)}")
    return code


def probe_token(
    session: _Session, run: _Run, secrets_: _Secrets, code: str
) -> tuple[str, str | None]:
    """Exchange the code for tokens and report the claims the access token carries.

    Returns the access token and, when the mint issued one, the gateway's refresh token —
    the input a caller's refresh leg may spend, which this step itself never touches.
    """
    _step(6, "/dial/token")
    status, body, _headers = session.request(
        f"{run.origin}/dial/token",
        form={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": run.client_id,
            "redirect_uri": run.redirect_uri,
            "code_verifier": secrets_.verifier,
            "resource": run.resource,
        },
    )
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise ChainError("token", f"the exchange answered HTTP {status}: {body[:300]}")
    tokens = json.loads(body)
    access_token: str = tokens["access_token"]
    claims = decode_claims(access_token)
    print(f"  access    {redact(access_token)}")
    for claim in ("iss", "sub", "aud", "roles"):
        print(f"    {claim:8s} {json.dumps(claims.get(claim))}")
    print(f"  refresh   {'present' if tokens.get('refresh_token') else 'absent'}")
    for claim in ("sub", "roles"):
        if not claims.get(claim):
            raise ChainError("token", f"the minted token carries no {claim!r}")
    # The project claim is optional by design: Core's projectPath is null-safe, and a
    # provider may carry no project attribute for the user, so the token correctly
    # mints with `project: null`. Its presence is reported, never required.
    if claims.get("project"):
        print(f"  project   {json.dumps(claims['project'])}")
    else:
        print(
            "  project   no project claim — the provider carries none; optional by design"
        )
    return access_token, tokens.get("refresh_token")


def probe_live_call(run: _Run, access_token: str, *, step: int = 7) -> None:
    """The point of the whole chain: a live tool call with the token it minted.

    The call goes through the front door to Core's data path (the gateway is deliberately
    not on that path), so a success means Core accepted the gateway's token for a real
    user and resolved that user's stored upstream credential. The step number is a
    parameter because a caller may repeat the call — a refreshed token's own pass through
    the front door is the same assertion, at a later step.
    """
    _step(step, f"a live tool call through the front door ({run.mcp_path})")
    status, message = _mcp_tools_list(run, access_token)
    print(f"  status    {status}")
    if status != HTTP_OK or message is None or "result" not in message:
        raise ChainError("mcp", f"the tool call did not succeed: {str(message)[:300]}")
    tools = message["result"].get("tools", [])
    print(f"  tools     {len(tools)}")
    print(f"  first     {json.dumps([tool.get('name') for tool in tools[:3]])}")


def _resolve_run(args: argparse.Namespace, env: dict[str, str]) -> _Run:
    """The run configuration, refusing an unusable one before any request is made."""
    client_id = args.client_id or env.get("GATEWAY_E2E_CLIENT_ID")
    if not client_id:
        raise ChainError(
            "configuration",
            "no client id: pass --client-id or set GATEWAY_E2E_CLIENT_ID in .env. The "
            "client must be pre-registered with the gateway (or resolvable by CIMD) and "
            "its redirect_uris must include the probe's callback URL",
        )
    return _Run(
        origin=args.origin,
        toolset=args.toolset,
        client_id=client_id,
        callback_port=args.callback_port,
        # `getattr` because this resolver is shared: the interactive probe imports it and
        # its own parser carries no `--app`, so the flag is optional across callers.
        kind="apps" if getattr(args, "app", False) else "dial",
    )


def _handle_landing(
    session: _Session,
    run: _Run,
    kind: str,
    value: str | None,
    *,
    deny: bool,
) -> int | None:
    """Report where the flow landed and drive the checkpoint's act when one is needed.

    Returns an exit code when the flow itself ends here (a deny, or the upstream boundary
    a real account would be needed to cross), or `None` when the caller should continue the
    chain to the callback, token exchange, and live call.
    """
    if kind == "decision":
        # The checkpoint parked the flow at the decision page (a first attribution).
        # Complete the user's act exactly as the page's form would, then read where it went.
        outcome = complete_checkpoint(
            session, run, value or "", _DENY if deny else _APPROVE
        )
        if outcome == "denied":
            print()
            print("=== deny verdict ===")
            print("  the decision page was refused, the refusal page was served, and")
            print("  no authorization code was issued")
            return 0
        if outcome == "upstream":
            print()
            print("=== boundary ===")
            print("  the approve advanced the flow to the upstream authorization page:")
            print(
                "  completing it needs a real provider account this probe does not hold."
            )
            print("  The checkpoint mechanics are proven; the upstream leg is not.")
            return 0
        # outcome == "continue": the approval minted straight to the callback.
        print("  verdict   the approval completed the flow to the mint")
        return None
    if kind == "upstream":
        print()
        print("=== boundary ===")
        print("  the display interstitial was served, continuing to the upstream")
        print("  authorization page — the approved client's notice, which needs a real")
        print(
            "  provider account to complete. The checkpoint is proven; the upstream leg"
        )
        print("  is not.")
        return 0
    print("  verdict   zero-page — an approved pair needs no decision page")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN, help="the public origin")
    parser.add_argument("--toolset", default=DEFAULT_TOOLSET, help="a mapped toolset")
    parser.add_argument(
        "--app",
        action="store_true",
        help="serve the flow as an app resource (`--toolset` names the app) under the "
        "/apps/ front-door path. An app carries no upstream credential, so its flow mints "
        "directly: the app shape is the one that completes headlessly through the "
        "checkpoint, where a toolset may need the upstream consent leg's real account",
    )
    parser.add_argument(
        "--client-id",
        default=None,
        help="a client the gateway resolves (default: GATEWAY_E2E_CLIENT_ID from .env)",
    )
    parser.add_argument(
        "--callback-port",
        type=int,
        default=DEFAULT_CALLBACK_PORT,
        help="the loopback port the client's registered redirect URI names",
    )
    parser.add_argument(
        "--deny",
        action="store_true",
        help="on the consent/attribution decision page, drive the deny action and assert "
        "the refusal shape (no code issued), then stop — instead of the default approve",
    )
    args = parser.parse_args()

    env = load_env()
    run = _resolve_run(args, env)
    secrets_ = _new_secrets()

    listener = _ReusableServer(("127.0.0.1", run.callback_port), _CallbackHandler)
    threading.Thread(target=listener.serve_forever, daemon=True).start()
    session = _Session()
    try:
        probe_discovery(session, run)
        redirect = probe_authorize(session, run, secrets_)
        kind, value = drive_login(session, env, redirect, run)
        landed = _handle_landing(session, run, kind, value, deny=args.deny)
        if landed is not None:
            return landed
        code = probe_callback(secrets_.state)
        access_token, _refresh_token = probe_token(session, run, secrets_, code)
        probe_live_call(run, access_token)
    finally:
        listener.shutdown()

    print()
    print("=== smoke verdict ===")
    print("  the sign-in completed through the front door and the token it minted")
    print("  authenticated a live tool call: the deployment is wired end to end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
