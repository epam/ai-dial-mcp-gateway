"""The live end-to-end sign-in smoke, interactive variant: a human signs in.

This is `probe_end_to_end.py` with one difference: the identity provider's login form is
filled by the HUMAN in a real browser, not by the script replaying a fixture credential.
The harness side of the chain — discovery, the client's authorization request, the code
exchange, the live tool call — stays scripted, and the probe reuses that machinery by
importing it, so the two probes cannot drift apart in what they assert.

Why this variant exists: the scripted probe proves the deployment is wired end to end
with a fixture user. This probe proves the same chain works when the signer is a person
— the case every real harness client is in — where the identity provider's hosted login
page (its SSO page, its MFA, its consent) is whatever the provider renders, and the
harness only ever sees the final redirect back to its own registered redirect URI.

The chain, and where it stops:

1. discovery, `/dial/authorize` with PKCE (S256) and state — scripted. The authorize
   step is this probe's own copy of the shared one: the shared step's scope check still
   encodes the pre-federation fixture policy (it refuses `openid`, which an OIDC
   provider's identity client requests by definition), and this file must not edit the
   probe it imports from. See `authorize_idp_leg`'s docstring.
2. redirects are followed one hop at a time ONLY until an HTML page renders on a host
   that is not the gateway's — that page is the provider's hosted login. The probe
   stops there and prints the URL.
3. the human signs in at that URL in their own browser; whatever pages the provider
   shows next — SSO, MFA, consent — are the provider's, and the probe is blind to all
   of them. The final harness redirect lands on the client's registered loopback
   redirect URI, where the probe IS listening by default: a small local HTTP server,
   bound before the flow started, records the request's code and state and answers the
   browser with one static "sign-in captured" page — no injected content, nothing read
   back from the request. With `--paste` the listener is skipped and the final URL is
   pasted back instead: the fallback when the loopback port is already taken (nothing
   is listening there, so the page fails to load and the URL comes from the address
   bar).
4. the captured (or pasted) callback is verified — the landing must be the registered
   redirect URI, and the state MUST round-trip exactly: a mismatch fails the probe —
   and the code is exchanged and spent exactly as the non-interactive probe spends it.
   One landing this probe does not complete is the gateway's own consent/attribution
   decision page: a first attribution parks the flow there for the user's act, and this
   interactive probe is deliberately hands-off it (it hands the human one URL and is
   blind to what renders after). Landing there is reported as that boundary — a clean
   `ChainError` naming the decision page — never a crash or a misleading "not the
   redirect URI"; the non-interactive probe is the one that drives the consent act.
5. the refresh leg (step 7): the minted gateway refresh token is spent at
   `/dial/token` with `grant_type=refresh_token`, and the refreshed access token must
   be new and must carry the identity claims again — the gateway's refresh grant
   re-reads them from the live provider, so this exercises the fresh-claims read end
   to end — and step 8 repeats the live tool call with the refreshed token through
   the front door.

With `--signout` the flow runs exactly as above through the token exchange — a stored
per-user credential short-circuits the upstream consent leg, so the browser pass is one
quick trip to the provider's page, often SSO-instant — and then stops: no live tool
call, no refresh leg. Instead the minted access token authenticates one direct call to
DIAL Core's ops route, `POST /v1/ops/toolset/signout`, deleting the toolset's stored
per-user credential (Core resolves that credential only by its creating identity, and
exposes no admin surface for it). The probe talks to Core directly for this one
diagnostic call rather than through the gateway's public surface: the gateway exposes
no sign-out relay, and the probe holds the user's own token — a diagnostic tool acting
as the user, with their consent, is its purpose. The request body mirrors the gateway's
own credential-call construction (the sign-in body's url/credentialsLevel/
authenticationType, without the code and redirectUri that only a consent leg carries),
and the verdict is read the way the flow reads it: the deployment listing's per-caller
status, which must no longer read SIGNED_IN.

Nothing here reads a login credential: the human types their own at the provider's page.
The probe never submits anything to the login page, never prints a cookie or a header
body from it, and prints the callback's authorization code only as a redacted handle
(it is single-use, short-lived, and PKCE-bound; the non-interactive probe prints the
same handle for the same code). Run with `PYTHONUTF8=1` on Windows: the console is
cp1252, so every prompt here is plain ASCII regardless.

The wait for the browser is generous (10 minutes by default, `--wait-minutes` to
change) and costs no CPU: the listener thread blocks on the socket accept, and the main
thread sleeps on the capture event, waking once a second only so Ctrl+C stays
responsive on Windows, where a single long wait can hold the interrupt.

The client is resolved the same way the non-interactive probe resolves it: `--client-id`
(whose value may be a CIMD metadata URL — the gateway fetches the document itself at
`/dial/authorize`, so a CIMD client needs no client-side registration step) or the
pre-registered `GATEWAY_E2E_CLIENT_ID` from `.env`. No provider fact is hardcoded: the
login page is recognized by being HTML off the gateway's origin, whatever provider the
deployment fronts.

Usage:
    PYTHONUTF8=1 python scripts/probe_end_to_end_interactive.py
    PYTHONUTF8=1 python scripts/probe_end_to_end_interactive.py --paste
    PYTHONUTF8=1 python scripts/probe_end_to_end_interactive.py --client-id <client>
    PYTHONUTF8=1 python scripts/probe_end_to_end_interactive.py --signout
    PYTHONUTF8=1 python scripts/probe_end_to_end_interactive.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parent))

from probe_end_to_end import (
    _MAX_HOPS,
    _REDIRECTS,
    _USER_AGENT,
    CONSENT_PATH,
    DEFAULT_CALLBACK_PORT,
    DEFAULT_ORIGIN,
    DEFAULT_TOOLSET,
    ChainError,
    _new_secrets,
    _resolve_run,
    _ReusableServer,
    _Run,
    _safe,
    _Secrets,
    _Session,
    _step,
    probe_discovery,
    probe_live_call,
    probe_token,
)
from spike_env import HTTP_OK, decode_claims, load_env, redact


def authorize_idp_leg(
    session: _Session, run: _Run, secrets_: _Secrets, env: dict[str, str]
) -> str:
    """`/dial/authorize` as the client, returning the identity provider URL it redirects to.

    This probe carries its own authorize step rather than importing the shared probe's
    for one reason: the shared step refuses `openid` in the relayed scope, which encoded
    the pre-federation fixture's policy and no longer holds. Under the generalized IdP
    federation the identity leg requests only the gateway identity client's own default
    scopes — an OIDC provider's defaults include `openid` by definition, and the
    operator's verified provider configuration may legitimately include
    `offline_access` (the refresh-token fact depends on it) — so the one check that
    survives every provider is this: where the deployment's `IDP_CLIENT_SCOPES` setting
    is readable, the relayed scope set must equal it exactly, so a scope the operator
    did not configure fails the probe instead of passing unexamined. Whether the relayed
    set carries `offline_access` is reported, never refused.
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
    print(
        f"  offline   relayed offline_access: {'yes' if 'offline_access' in scopes else 'no'}"
    )
    configured = env.get("IDP_CLIENT_SCOPES", "")
    if configured:
        expected = {name.strip() for name in configured.split(",") if name.strip()}
        if set(scopes) != expected:
            raise ChainError(
                "authorize",
                f"the relayed scope set {sorted(scopes)} is not the identity client's "
                f"configured default {sorted(expected)}",
            )
    return location


def _looks_like_html(body: str) -> bool:
    """Whether a response body renders as an HTML page (the login page's shape)."""
    return re.search(r"<html[\s>]|<!doctype", body[:4096], re.IGNORECASE) is not None


def stop_at_login_page(session: _Session, run: _Run, first_url: str) -> str:
    """Follow the chain one hop at a time, stopping at the provider's hosted login page.

    The login page is recognized by construction, not by provider knowledge: it is an
    HTML page served from a host that is not the gateway's. Anything else the chain
    shows before a human has signed in — a gateway page mid-chain, a hop that lands on
    the client callback unearned — is a flow fault and fails the probe, because the
    probe's job is to hand the human exactly one URL and let the provider do the rest.
    """
    _step(3, "the identity provider's login page")
    gateway_netloc = urllib.parse.urlparse(run.origin).netloc
    location: str | None = first_url
    status = _REDIRECTS[0]
    hops = 0
    while status in _REDIRECTS and location is not None and hops < _MAX_HOPS:
        hops += 1
        target = urllib.parse.urlparse(location)
        if target.hostname in {"127.0.0.1", "localhost"} and (
            target.port == run.callback_port
        ):
            raise ChainError(
                "login",
                f"the flow returned to the client callback before any sign-in "
                f"({_safe(location)})",
            )
        if target.netloc == gateway_netloc:
            raise ChainError(
                "login",
                "the gateway answered a page mid-chain before any sign-in "
                f"({_safe(location)}); the flow never reached the provider",
            )
        page_url = location
        status, body, headers = session.request(location)
        location = headers.get("location")
        if status in _REDIRECTS:
            print(f"  hop {hops}: -> {_safe(location)}")
            continue
        if status == HTTP_OK and _looks_like_html(body):
            print(f"  hop {hops}: the login page rendered ({target.netloc})")
            return page_url
        raise ChainError(
            "login",
            f"hop {hops} answered HTTP {status} and no login page ({_safe(page_url)})",
        )
    raise ChainError(
        "login", f"the chain did not reach a login page within {hops} hops"
    )


def print_login_url(login_url: str) -> None:
    """Hand the login URL to the human (it carries state and challenge, no secret)."""
    print("  open this URL in a browser and sign in:")
    print(f"  {login_url}")


def collect_pasted_url(login_url: str) -> str:
    """Hand the login URL to the human and take the final URL back."""
    _step(4, "the human signs in")
    print_login_url(login_url)
    print("  after the sign-in the browser is redirected through the gateway and lands")
    print(
        "  on a URL that fails to load (nothing is listening there) - that is expected."
    )
    print("  Paste the URL the browser landed on and press Enter.")
    try:
        pasted = input("final URL: ").strip().strip('"').strip("'")
    except EOFError:
        raise ChainError(
            "login", "no pasted URL: stdin closed before the sign-in completed"
        ) from None
    if not pasted:
        raise ChainError("login", "no pasted URL: the input was empty")
    return pasted


def _verify_callback_params(params: dict[str, str], state: str) -> str:
    """The shared callback assertions, behind both capture paths.

    The state must round-trip exactly — a mismatched state is a failed probe, never a
    warning, because state is what binds the code the browser brought back to the flow
    this run started — and what came back must be a code, not an OAuth error response.
    """
    if params.get("state") != state:
        raise ChainError("callback", "the state parameter did not round-trip")
    code = params.get("code")
    if not code:
        raise ChainError(
            "callback",
            "no authorization code: "
            f"{params.get('error')} {params.get('error_description', '')[:200]}",
        )
    return code


def _report_callback(params: dict[str, str], code: str) -> None:
    """The callback's evidence line: which parameters landed, the code as a handle."""
    print(f"  params    {sorted(params)}")
    print("  state     round-tripped")
    print(f"  code      {redact(code)}")


def harvest_callback(pasted: str, run: _Run, state: str) -> str:
    """Verify the pasted URL is the client's callback and return the authorization code.

    The origin and the path must be the registered redirect URI's — a code delivered
    anywhere else was not delivered to this client.

    The one landing this probe cannot complete is the gateway's own consent/attribution
    decision page: on a first attribution the flow parks there for the user's act, so a
    human who signs in and stops at that page pastes its URL. That is the checkpoint doing
    its job, not a flow fault, so it is reported as the boundary it is — this interactive
    probe is deliberately hands-off the decision page (it hands the human exactly one URL
    and is blind to whatever the provider and gateway render after it), and the
    non-interactive probe is the one that drives the consent act.
    """
    parsed = urllib.parse.urlparse(pasted)
    if parsed.path == CONSENT_PATH:
        raise ChainError(
            "consent",
            "the browser landed on the gateway's consent/attribution decision page — a "
            "first attribution parks the flow there for the user's act. This interactive "
            "probe does not drive that act: approve (or deny) on the page, or rerun with "
            "the non-interactive probe, which completes it headlessly",
        )
    expected = urllib.parse.urlparse(run.redirect_uri)
    landed = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if (parsed.scheme, parsed.netloc, parsed.path) != (
        expected.scheme,
        expected.netloc,
        expected.path,
    ):
        raise ChainError(
            "callback",
            f"the pasted URL is not the client redirect URI (landed on {landed}, "
            f"expected {run.redirect_uri})",
        )
    params = {
        key: value[0] for key, value in urllib.parse.parse_qs(parsed.query).items()
    }
    code = _verify_callback_params(params, state)
    _report_callback(params, code)
    return code


# The one page the capture listener answers with: static, and nothing from the request
# is rendered back into it.
_CAPTURE_PAGE = (
    "<html><body>"
    "<h2>Sign-in captured</h2>"
    "<p>The probe has what it needs from the flow. You can close this tab and return "
    "to the terminal.</p>"
    "</body></html>"
)


class _LoopbackCapture(BaseHTTPRequestHandler):
    """Catches the browser's final redirect on the client's loopback redirect URI.

    The handler is deliberately dumb: it records the path and the query parameters of
    whatever GET arrives and answers with the one static page. Which pages the human
    saw before landing here — login, MFA, the provider's consent — is the provider's
    business; the listener only cares about the final landing.
    """

    landed_path: ClassVar[str] = ""
    captured: ClassVar[dict[str, str]] = {}
    done: ClassVar[threading.Event] = threading.Event()

    @classmethod
    def reset(cls) -> None:
        """Clear one capture's state, so a listener can be reused by the self-test."""
        cls.landed_path = ""
        cls.captured = {}
        cls.done = threading.Event()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        type(self).landed_path = parsed.path
        type(self).captured = {
            key: value[0] for key, value in urllib.parse.parse_qs(parsed.query).items()
        }
        body = _CAPTURE_PAGE.encode()
        self.send_response(HTTP_OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        type(self).done.set()

    def log_message(self, *args: object) -> None:
        """Silence the stdlib's per-request logging (it prints the query string)."""


def arm_loopback_listener(port: int) -> _ReusableServer:
    """Bind the loopback listener BEFORE the flow starts, serving on a side thread.

    The bind has to precede `/dial/authorize`: the client's registered redirect URI is
    fixed, so a port that cannot be bound is a configuration fault to report before any
    request is spent, not a surprise after the human has signed in. The serve thread
    blocks on the socket accept, so the wait costs no CPU.
    """
    try:
        server = _ReusableServer(("127.0.0.1", port), _LoopbackCapture)
    except OSError as exc:
        raise ChainError(
            "capture",
            f"the loopback port {port} could not be bound ({exc}); something else may "
            f"be listening there. Rerun with --paste to take the final URL by paste "
            f"instead",
        ) from exc
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def wait_for_browser(run: _Run, login_url: str, timeout_seconds: int) -> None:
    """Print the login URL and block until the browser lands on the loopback listener.

    The main thread sleeps on the capture event rather than touching the socket — the
    listener thread owns the accept — and wakes once a second only so Ctrl+C stays
    responsive on Windows. The provider may show the human any number of pages first;
    the listener only cares about the final landing.
    """
    _step(4, "the human signs in (the probe listens on the loopback)")
    print_login_url(login_url)
    print(f"  listening {run.redirect_uri} - the flow's final redirect lands here")
    minutes = timeout_seconds // 60
    print(
        f"  waiting for the browser to return... (Ctrl+C to abort; the wait gives up "
        f"after {minutes} min)"
    )
    deadline = time.monotonic() + timeout_seconds
    next_note = 30
    while not _LoopbackCapture.done.wait(1.0):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChainError(
                "callback",
                f"no browser return within {timeout_seconds} s: the sign-in never "
                f"completed, or the browser landed somewhere this listener does not "
                f"cover",
            )
        if timeout_seconds - remaining >= next_note:
            print(
                f"  ... still waiting ({int(remaining) // 60} min of the wait left; "
                f"Ctrl+C to abort)",
                flush=True,
            )
            next_note += 30


def collect_captured_callback(run: _Run, state: str) -> str:
    """Verify what the loopback listener caught and return the authorization code.

    The socket's own bind proves the request reached 127.0.0.1 on the client's
    registered port; the path must still be the registered redirect URI's path, and the
    state must round-trip exactly — a mismatch fails the probe, exactly as on the paste
    path.
    """
    expected = urllib.parse.urlparse(run.redirect_uri)
    if _LoopbackCapture.landed_path != expected.path:
        raise ChainError(
            "callback",
            f"the browser landed on {_LoopbackCapture.landed_path or '<nothing>'}, not "
            f"on the client redirect URI's path {expected.path}",
        )
    params = dict(_LoopbackCapture.captured)
    code = _verify_callback_params(params, state)
    _report_callback(params, code)
    return code


def probe_refresh(
    session: _Session, run: _Run, refresh_token: str, access_token: str
) -> str:
    """The refresh leg: a fresh access token minted from the flow's refresh token.

    The gateway's refresh grant re-reads the claims from the live provider (RFC 6749 §6
    against the provider's token endpoint) rather than re-minting from a snapshot, so the
    `sub` and `roles` arriving in the refreshed token's claims is the assertion that the
    re-read ran and kept the identity — the fresh-claims behavior, exercised against the
    real provider through the front door. The refreshed access token must be a new one (a
    refresh that returned the presented token would mean nothing was refreshed), and the
    response must carry a refresh token to keep the session refreshable. Whether that
    token is the same one (the gateway persisted it) or a replacement (the gateway
    rotates) is the deployment's configured policy, so the step reports which happened
    and requires neither.
    """
    _step(7, "the refresh leg (/dial/token, grant_type=refresh_token)")
    status, body, _headers = session.request(
        f"{run.origin}/dial/token",
        form={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": run.client_id,
            "resource": run.resource,
        },
    )
    print(f"  status    {status}")
    if status != HTTP_OK:
        raise ChainError("refresh", f"the refresh answered HTTP {status}: {body[:300]}")
    tokens = json.loads(body)
    fresh: str = tokens["access_token"]
    print(f"  access    was {redact(access_token)}")
    print(f"  access    now {redact(fresh)}")
    if fresh == access_token:
        raise ChainError("refresh", "the refresh returned the presented access token")
    claims = decode_claims(fresh)
    for claim in ("iss", "sub", "aud", "roles"):
        print(f"    {claim:8s} {json.dumps(claims.get(claim))}")
    for claim in ("sub", "roles"):
        if not claims.get(claim):
            raise ChainError(
                "refresh",
                f"the refreshed token carries no {claim!r}: the identity leg's "
                f"re-read did not land the claims",
            )
    next_refresh = tokens.get("refresh_token")
    print(f"  refresh   {'present' if next_refresh else 'absent'}")
    if not next_refresh:
        raise ChainError("refresh", "the refresh answered without a refresh token")
    if next_refresh == refresh_token:
        print("  rotation  none: the same refresh token persists")
    else:
        print("  rotation  the refresh token rotated (a replacement was issued)")
    return fresh


# The status Core reports for a level that holds no stored credential. Core builds have
# been observed spelling it either way after a sign-out, so both are the pass verdict —
# the only value that means "signed in" is SIGNED_IN itself.
_SIGNED_OUT_STATUSES = frozenset({"NOT_SIGNED_IN", "SIGNED_OUT"})


def probe_signout(
    session: _Session, run: _Run, access_token: str, env: dict[str, str]
) -> None:
    """Delete the toolset's stored per-user credential through Core's ops sign-out.

    The sign-out is Core's, not the gateway's: a per-user credential resolves only by
    its creating identity, so no other principal could delete it and Core exposes no
    admin surface for one. The probe therefore presents the flow's own minted access
    token — Core trusts it as this user through the dial-mcp-proxy trust entry, the
    same trust that lets it drive a live tool call — and calls the ops route directly,
    skipping the gateway's public surface, which relays no sign-out. This is the one
    diagnostic call the probe makes off the gateway, acting as the user whose token it
    carries and with their consent at the browser step that minted it.

    The request body mirrors the gateway's own credential-call construction — the sign-in
    body's `url`/`credentialsLevel`/`authenticationType` without the `code`/`redirectUri`
    only a consent leg carries. `url` is the toolset's registry name, the same value the
    gateway's sign-in body sends and the key Core stores the credential under.
    """
    _step(9, "the sign-out (Core's ops credential API, as the flow's minted user)")
    core = env.get("DIAL_CORE_URL", "").rstrip("/")
    if not core:
        raise ChainError(
            "signout",
            "no Core base URL: set DIAL_CORE_URL in .env — the sign-out is Core's ops "
            "route, and the gateway exposes none",
        )
    headers = {"Authorization": f"Bearer {access_token}"}
    signout_body = {
        "url": run.toolset,
        "credentialsLevel": "USER",
        "authenticationType": "OAUTH",
    }
    status, body, _headers = session.request(
        f"{core}/v1/ops/toolset/signout",
        raw_body=json.dumps(signout_body),
        extra_headers=headers,
    )
    print(f"  status    {status}")
    print(f"  body      {body[:200]}")
    if status in (400, 403, 404):
        raise ChainError(
            "signout",
            f"Core refused the sign-out with HTTP {status}: {body[:200]}",
        )
    if status != HTTP_OK:
        raise ChainError(
            "signout", f"the sign-out answered HTTP {status}: {body[:200]}"
        )

    _step(10, "the verdict (the listing's per-caller status, as this user)")
    status, body, _headers = session.request(
        f"{core}/openai/toolsets/{run.toolset}", extra_headers=headers
    )
    if status != HTTP_OK:
        raise ChainError(
            "signout", f"the status read answered HTTP {status}: {body[:200]}"
        )
    auth = json.loads(body).get("auth_settings")
    if not isinstance(auth, dict):
        raise ChainError(
            "signout", "the listing answer carries no readable authentication settings"
        )
    user_status = auth.get("user_level_auth_status")
    print(f"  user_level_auth_status = {user_status}")
    print(f"  global_auth_status     = {auth.get('global_auth_status')}")
    if user_status == "SIGNED_IN":
        raise ChainError(
            "signout",
            "the user-level status still reads SIGNED_IN: the credential survived the "
            "sign-out — check the request body's url/credentialsLevel against the "
            "stored one",
        )
    if user_status not in _SIGNED_OUT_STATUSES:
        raise ChainError(
            "signout",
            f"the user-level status reads {user_status!r}, not a signed-out value — "
            "the credential state is unreadable, so the deletion is unproven",
        )
    print("  verdict   the stored per-user credential is deleted")


def _browser_get(url: str) -> tuple[int, str]:
    """One plain GET, the way the returning browser makes it."""
    request = urllib.request.Request(  # noqa: S310 - the probe's own loopback listener
        url, headers={"User-Agent": _USER_AGENT}
    )
    with urllib.request.urlopen(  # noqa: S310 - the probe's own loopback listener
        request, timeout=10
    ) as response:
        return response.status, response.read().decode(errors="replace")


def _check(condition: bool, message: str) -> None:
    """A self-test assertion that names what failed rather than a bare `assert`."""
    if not condition:
        raise ChainError("self-test", message)


def _self_test(port: int) -> int:
    """Exercise the listener and the callback verification with synthetic requests.

    No gateway and no human: the listener is armed exactly as a real run arms it, a
    local HTTP client plays the returning browser, and the verification is asked for
    each verdict it can give.
    """
    run = _Run(
        origin="http://self-test.invalid",
        toolset="self-test",
        client_id="self-test",
        callback_port=port,
    )
    server = arm_loopback_listener(port)
    passed = 0
    try:
        # The capture: the returning browser's GET is answered with the static page
        # and recorded.
        _LoopbackCapture.reset()
        query = urllib.parse.urlencode({"code": "self-test-code", "state": "st-1"})
        status, body = _browser_get(f"http://127.0.0.1:{port}/callback?{query}")
        _check(status == HTTP_OK, f"the capture page answered HTTP {status}")
        _check("Sign-in captured" in body, "the capture page is not the static page")
        code = collect_captured_callback(run, "st-1")
        _check(code == "self-test-code", "the captured code did not come back")
        print(f"  capture   ok (HTTP {status}, the static page, code {redact(code)})")
        passed += 1

        # A state mismatch is a hard failure, exactly as on the paste path.
        _LoopbackCapture.reset()
        forged = urllib.parse.urlencode({"code": "self-test-code", "state": "forged"})
        _browser_get(f"http://127.0.0.1:{port}/callback?{forged}")
        try:
            collect_captured_callback(run, "st-1")
        except ChainError as exc:
            _check(
                "state" in str(exc), f"the mismatch failed with something else: {exc}"
            )
            print(f"  mismatch  refused as a hard failure ({exc})")
            passed += 1
        else:
            raise ChainError("self-test", "a mismatched state was accepted")

        # An OAuth error response is reported, not crashed on.
        _LoopbackCapture.reset()
        denied = urllib.parse.urlencode({"error": "access_denied", "state": "st-1"})
        _browser_get(f"http://127.0.0.1:{port}/callback?{denied}")
        try:
            collect_captured_callback(run, "st-1")
        except ChainError as exc:
            _check(
                "no authorization code" in str(exc),
                f"the error response failed with something else: {exc}",
            )
            print(f"  error     reported, not crashed on ({exc})")
            passed += 1
        else:
            raise ChainError("self-test", "an error response was taken for a code")
    finally:
        server.shutdown()
        server.server_close()
        _LoopbackCapture.reset()
    print(f"self-test: {passed}/3 checks passed on 127.0.0.1:{port}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """The probe's flags, in one place so `main` reads as the chain it drives."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN, help="the public origin")
    parser.add_argument("--toolset", default=DEFAULT_TOOLSET, help="a mapped toolset")
    parser.add_argument(
        "--client-id",
        default=None,
        help="a client the gateway resolves - a pre-registered id or a CIMD metadata "
        "URL (default: GATEWAY_E2E_CLIENT_ID from .env)",
    )
    parser.add_argument(
        "--callback-port",
        type=int,
        default=DEFAULT_CALLBACK_PORT,
        help="the loopback port the client's registered redirect URI names",
    )
    parser.add_argument(
        "--paste",
        action="store_true",
        help="take the final URL by paste instead of the loopback listener (the "
        "fallback when the callback port is already taken)",
    )
    parser.add_argument(
        "--wait-minutes",
        type=int,
        default=10,
        help="how long the loopback capture waits for the browser to return "
        "(default: 10)",
    )
    parser.add_argument(
        "--signout",
        action="store_true",
        help="run the sign-in flow, then delete the toolset's stored per-user "
        "credential through Core's ops sign-out and verify it is gone — no live tool "
        "call, no refresh leg",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="exercise the listener and the callback verification with synthetic "
        "requests - no gateway, no human",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.self_test:
        return _self_test(args.callback_port)

    env = load_env()
    run = _resolve_run(args, env)
    secrets_ = _new_secrets()
    session = _Session()

    # The listener is bound before the flow starts, so a taken port is reported before
    # any request is spent on a flow whose callback nothing would catch.
    listener = None if args.paste else arm_loopback_listener(run.callback_port)
    try:
        probe_discovery(session, run)
        redirect = authorize_idp_leg(session, run, secrets_, env)
        login_url = stop_at_login_page(session, run, redirect)
        if args.paste:
            pasted = collect_pasted_url(login_url)
            code = harvest_callback(pasted, run, secrets_.state)
        else:
            wait_for_browser(run, login_url, args.wait_minutes * 60)
            code = collect_captured_callback(run, secrets_.state)
        access_token, refresh_token = probe_token(session, run, secrets_, code)
        if args.signout:
            probe_signout(session, run, access_token, env)
            print()
            print("=== signout verdict ===")
            print("  a human signed in, the minted token authenticated the sign-out")
            print("  at Core's ops route, and the listing's user-level status no")
            print("  longer reads SIGNED_IN: the stored per-user credential is gone")
            return 0
        probe_live_call(run, access_token)
        if not refresh_token:
            raise ChainError(
                "refresh",
                "the token step minted no refresh token, so the refresh leg cannot "
                "run: the identity client's configuration did not yield "
                "offline_access, or the provider granted no refresh token for the "
                "session",
            )
        refreshed = probe_refresh(session, run, refresh_token, access_token)
        probe_live_call(run, refreshed, step=8)
    except KeyboardInterrupt:
        print()
        print("=== aborted ===")
        print("  the wait was interrupted before the browser returned, so the flow's")
        print(
            "  authorization code (if the sign-in completed) was never spent; rerun "
            "for a fresh flow."
        )
        return 130
    finally:
        if listener is not None:
            listener.shutdown()
            listener.server_close()

    print()
    print("=== smoke verdict ===")
    print("  a human signed in at the provider's own page, the flow's token")
    print("  authenticated a live tool call, and the flow's refresh token minted")
    print("  a fresh token whose claims re-read and whose credential made its own")
    print("  live tool call: the deployment is wired end to end, refresh included")
    return 0


if __name__ == "__main__":
    sys.exit(main())
