"""Establish the test user's upstream credential on the `notion` toolset (Stage 0 spike).

The spike's second precondition. Proving that a minted token resolves *that user's* stored
upstream credential requires a real stored credential, so this helper drives the sign-in
the documented recipe performs: read the toolset's public OAuth settings, build the
upstream authorize URL from them, catch the loopback callback, and hand the authorization
code to Core.

The code is not exchanged here. The PKCE verifier lives only inside Core, so only Core can
exchange it — which is exactly why the code is handed over rather than redeemed, and why
the upstream token never leaves Core.

Core stamps the stored credential with the caller token's `sub`, so the token used here
must belong to the user whose credential is being established. Identity is
client-independent on this realm (tokens from different Keycloak clients for one user
share the same `sub`), so the client choice only decides which claims the token carries.

`--simulate` performs the whole call without a browser by having the script act as the
upstream would in the one respect Core checks: it sends the toolset's own published
`code_challenge` back as the code. That is a synthetic code and the upstream will not
accept it; the mode exists to verify the helper's request shape and Core's handling of it
without a human present, and its result is not credential evidence.

Usage:
    PYTHONUTF8=1 python scripts/spike_establish_credential.py
    PYTHONUTF8=1 python scripts/spike_establish_credential.py --no-browser
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import (
    HTTP_OK,
    load_env,
    request,
    request_user_token,
)

TOOLSET = "notion"

# The violation this helper reports when Core refuses the toolset read.
TOOLSET_READ_FAILED = "reading the toolset failed with HTTP"

# The read used throughout this helper — the deployment-listing route
# (`/openai/toolsets/{name}`), the one read whose authorization matches the MCP data
# path's and which fills in the per-caller auth statuses beside every field the
# upstream authorize URL is built from, so it serves both jobs.
STATUS_ROUTE = f"/openai/toolsets/{TOOLSET}"


class CallbackHandler(BaseHTTPRequestHandler):
    """Captures the upstream consent's callback parameters and stops the server."""

    captured: ClassVar[dict[str, str]] = {}
    done: ClassVar[threading.Event] = threading.Event()

    def do_GET(self) -> None:
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        CallbackHandler.captured.update({k: v[0] for k, v in params.items()})
        answered = "code" in CallbackHandler.captured
        message = (
            "Sign-in captured. Close this tab and return to the terminal."
            if answered
            else "No authorization code arrived in the callback."
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(f"<html><body><h3>{message}</h3></body></html>".encode())
        CallbackHandler.done.set()

    def log_message(self, *args) -> None:
        """Silence the stdlib's default per-request logging (it prints the query string)."""


class ToolsetReadFailed(SystemExit):
    """Core refused the toolset read, so the helper has nothing to build the URL from."""

    def __init__(self, status: int) -> None:
        super().__init__(f"{TOOLSET_READ_FAILED} {status}")


def read_settings(env: dict[str, str], token: str) -> dict:
    core = env["DIAL_CORE_URL"]
    status, body, _ = request("GET", f"{core}{STATUS_ROUTE}", token=token)
    if status != HTTP_OK:
        raise ToolsetReadFailed(status)
    return json.loads(body)["auth_settings"]


def report_status(env: dict[str, str], token: str) -> str:
    settings = read_settings(env, token)
    user_level = settings.get("user_level_auth_status")
    print(f"  user_level_auth_status = {user_level}")
    print(f"  global_auth_status     = {settings.get('global_auth_status')}")
    return user_level


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-browser", action="store_true", help="print the URL only")
    parser.add_argument("--level", default="USER", help="credentials level")
    parser.add_argument(
        "--timeout", type=int, default=300, help="callback wait in seconds"
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="send the published challenge as a synthetic code (no browser, not evidence)",
    )
    args = parser.parse_args()

    env = load_env()
    core = env["DIAL_CORE_URL"]
    token = request_user_token(
        env, "KEYCLOAK_IDENTITY_CLIENT_ID", "KEYCLOAK_IDENTITY_CLIENT_SECRET"
    )

    print("current status:")
    if report_status(env, token) == "SIGNED_IN" and not args.simulate:
        print(
            "already signed in; the credential precondition is established (silent path)"
        )
        return 0

    settings = read_settings(env, token)
    redirect_uri = settings["redirect_uri"]
    parsed = urllib.parse.urlparse(redirect_uri)
    port = parsed.port or 80

    query = {
        "response_type": "code",
        "client_id": settings["client_id"],
        "redirect_uri": redirect_uri,
        "code_challenge": settings["code_challenge"],
        "code_challenge_method": settings["code_challenge_method"],
        "state": "spike=1",
    }
    scopes = settings.get("scopes_supported") or []
    if scopes:
        # These are the *upstream's* advertised scopes, which belong on the upstream
        # authorize URL; they are unrelated to the gateway's own client scopes.
        query["scope"] = " ".join(scopes)
    authorize_url = (
        f"{settings['authorization_endpoint']}?{urllib.parse.urlencode(query)}"
    )

    code: str | None = None
    if args.simulate:
        # The upstream alone can mint a code that Core's hidden verifier will accept, so
        # this cannot complete a real consent. It checks the request shape and Core's
        # handling of the call, nothing more.
        code = settings["code_challenge"]
        print(
            "SIMULATE: sending a synthetic code; this does not establish a credential."
        )
    else:
        server = HTTPServer(("127.0.0.1", port), CallbackHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"listening for the callback on {redirect_uri}")
        print("open this URL and approve the upstream access:\n")
        print(f"  {authorize_url}\n")
        if not args.no_browser:
            webbrowser.open(authorize_url)
        print(f"waiting up to {args.timeout}s for the callback ...")
        if not CallbackHandler.done.wait(args.timeout):
            server.shutdown()
            print("timed out waiting for the authorization code")
            return 1
        server.shutdown()
        code = CallbackHandler.captured.get("code")
        if not code:
            print(
                f"no code in the callback parameters: {sorted(CallbackHandler.captured)}"
            )
            return 1

    status, body, _ = request(
        "POST",
        f"{core}/v1/ops/toolset/signin",
        body={
            "url": TOOLSET,
            "credentials_level": args.level,
            "authentication_type": "OAUTH",
            "code": code,
            "redirect_uri": redirect_uri,
        },
        # Minted here rather than up front: the identity client's access tokens are short
        # lived by design, and a human consent takes longer than one lifespan. This is
        # also the only step whose credential matters — Core stamps the stored credential
        # with the `sub` of the token presented here.
        token=request_user_token(
            env, "KEYCLOAK_IDENTITY_CLIENT_ID", "KEYCLOAK_IDENTITY_CLIENT_SECRET"
        ),
    )
    print(f"POST /v1/ops/toolset/signin -> HTTP {status} {body[:200]}")
    if status not in (200, 201):
        return 1

    print("status now:")
    report_token = request_user_token(
        env, "KEYCLOAK_IDENTITY_CLIENT_ID", "KEYCLOAK_IDENTITY_CLIENT_SECRET"
    )
    return 0 if report_status(env, report_token) == "SIGNED_IN" else 1


if __name__ == "__main__":
    sys.exit(main())
