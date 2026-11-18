"""Shared helpers for the Stage 0 spike scripts.

The spike's helpers are the only place in this repository that talks to the local DIAL
instance directly (Core, Keycloak) rather than to the gateway. They exist so the spike's
falsification gate always has a repeatable, committed way to establish its preconditions
and to mint and present a gateway-shaped token.

Machine credentials (the test user's login, the client credential the token request
needs) come from `.env`, which is gitignored; committed `.env.example` carries the
placeholders. Nothing here prints a credential, a token, or a key.

Run these scripts with `PYTHONUTF8=1`: the Windows console is cp1252 and the local
Keycloak's HTML error bodies are not.
"""

from __future__ import annotations

import base64
import hashlib
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# The one status the spike treats as success for a Keycloak token request.
HTTP_OK = 200

# A DIAL toolset is a credential-holding proxy: Core reaches the upstream MCP server and
# relays the caller's User-Agent. The upstream's front-end (Cloudflare) bans default
# library agents outright with error 1010, which reads as an authentication failure, so
# every request here identifies itself explicitly.
USER_AGENT = "dial-mcp-gateway-spike/1.0"

# Explicitly-typed record of what a spike script must never do.
SECRET_KEYS = frozenset(
    {
        "password",
        "client_secret",
        "access_token",
        "refresh_token",
        "id_token",
        "code",
        "api_key",
        "private_key",
    }
)


class SpikeError(RuntimeError):
    """A spike helper could not complete a step it needs; the message is safe to print."""


class EnvFileError(SpikeError):
    """The repository's `.env` is absent, so no machine credential is available."""

    def __init__(self, path: Path) -> None:
        super().__init__(
            f"{path} is missing. Copy .env.example to .env and fill in the local "
            "values; the spike reads its machine credentials from there."
        )


class EnvValueError(SpikeError):
    """A setting the step needs is absent or still holds its `.env.example` placeholder."""

    def __init__(self, key: str) -> None:
        super().__init__(f".env is missing a real value for {key}")


class HostUnreachableError(SpikeError):
    """An outbound call could not be made at all (DNS, connection, TLS)."""

    def __init__(self, method: str, url: str, reason: object) -> None:
        super().__init__(f"{method} {url} could not be reached: {reason}")


class TokenRequestError(SpikeError):
    """Keycloak refused the token request the step needs."""

    def __init__(self, client_id_key: str, status: int) -> None:
        super().__init__(
            f"the Keycloak token request via {client_id_key} failed with HTTP {status}"
        )


def load_env(path: Path | None = None) -> dict[str, str]:
    """Read the repository's gitignored `.env` as a plain mapping.

    Deliberately not a settings model: the spike scripts are not the gateway, and they
    must not grow a second configuration surface. Only simple `KEY=value` lines are
    understood, which is all the committed `.env.example` contains.
    """
    env_path = path or (REPO_ROOT / ".env")
    values: dict[str, str] = {}
    if not env_path.is_file():
        raise EnvFileError(env_path)
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def require(env: dict[str, str], key: str) -> str:
    """Fetch a required setting, failing with the setting's name rather than `None`."""
    value = env.get(key)
    if not value or value in {"change-me", "generate-me"}:
        raise EnvValueError(key)
    return value


def prefer_ipv4_resolution() -> None:
    """Pin name resolution to IPv4-first for this process, idempotently, once.

    Windows resolves `localhost` to `::1` before `127.0.0.1`, but the local DIAL
    instance runs in WSL2 with NAT networking, which publishes container ports on IPv4
    only: a TCP connect to `[::1]:<port>` half-opens and then hangs with no response, so
    `urllib`/`http.client` time out where `curl` (which prefers IPv4) succeeds. Sorting
    the already-resolved addresses IPv4-first — matching curl's preference — makes the
    probe batteries reach the stack wherever they run. This changes only *which* of the
    addresses Python returns is tried first; never a host, port, or protocol, and never a
    probe's assertions. See the repo's ops notes ("WSL-NAT/VPN flake").
    """
    if getattr(socket.getaddrinfo, "_dial_mcp_ipv4_first", False):
        return
    original = socket.getaddrinfo

    def ipv4_first(*args, **kwargs):
        results = original(*args, **kwargs)
        # A stable sort keeps the original relative order within each family.
        results.sort(key=lambda entry: entry[0] != socket.AF_INET)
        return results

    ipv4_first._dial_mcp_ipv4_first = True  # type: ignore[attr-defined]
    socket.getaddrinfo = ipv4_first  # type: ignore[assignment]


def ssl_context() -> ssl.SSLContext:
    """A context that accepts the local instance's self-signed Keycloak certificate.

    The instance serves Keycloak over a self-signed cert (`CN=keycloak`); the alternative
    to this is trusting that certificate in the Windows store, which the spike does not
    do because it would outlive the spike.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def request(  # noqa: PLR0913
    method: str,
    url: str,
    *,
    body: dict | None = None,
    token: str | None = None,
    form: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> tuple[int, str, dict[str, str]]:
    """One HTTP call, returning status, body, and headers instead of raising.

    Every spike probe needs to record the *failing* responses as evidence, so HTTP errors
    are values here, not exceptions.

    The call's shape is keyword-only: an earlier positional signature read
    `request("POST", url, form)` at one call site and `request("GET", url, token)` at
    another, where a transposed argument would have silently sent a credential as a
    request body. Keyword-only arguments make that mistake a TypeError.

    The argument count is the API's shape, not an accident: this one function is the
    spike's entire HTTP vocabulary, and splitting it would put one request shape behind
    several wrappers for no gain.
    """
    merged = {"Accept": "application/json", "User-Agent": USER_AGENT}
    merged.update(headers or {})
    payload: bytes | None = None
    if form is not None:
        payload = urllib.parse.urlencode(form).encode()
        merged.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif body is not None:
        payload = json.dumps(body).encode()
        merged.setdefault("Content-Type", "application/json")
    if token:
        merged["Authorization"] = f"Bearer {token}"

    # The URL is a `.env`-configured local endpoint, never user input, so the scheme is
    # trusted here.
    req = urllib.request.Request(  # noqa: S310 - configured endpoint, not user input
        url, data=payload, headers=merged, method=method
    )
    try:
        with urllib.request.urlopen(  # noqa: S310 - configured endpoint, not user input
            req, timeout=timeout, context=ssl_context()
        ) as resp:
            return resp.status, resp.read().decode(errors="replace"), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace"), dict(exc.headers)
    except urllib.error.URLError as exc:
        raise HostUnreachableError(method, url, exc.reason) from exc


def decode_claims(token: str) -> dict:
    """Read a JWT's payload without verifying it — for reporting, never for trust."""
    segment = token.split(".")[1]
    segment += "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment))


def redact(token: str) -> str:
    """A stable, non-reversible handle for a credential, safe to print and to commit.

    Evidence must be credential-free by construction: `.gitignore` blocks `*.jwt`, so an
    unredacted capture fails to commit silently. Every script prints handles like this
    one instead of the tokens themselves.
    """
    if not token:
        return "<none>"
    digest = hashlib.sha256(token.encode()).hexdigest()[:12]
    return f"<redacted len={len(token)} sha256={digest}>"


def minted_token_path(name: str) -> Path:
    """Where a minted token lives: gitignored, next to the key it was signed with."""
    return REPO_ROOT / ".secrets" / f"spike-token-{name}.jwt"


def request_user_token(
    env: dict[str, str], client_id_key: str, client_secret_key: str
) -> str:
    """Mint the test user's DIAL identity token through a named Keycloak client.

    The password grant is used deliberately: this is a machine-driven spike, and the
    grant exists on the local realm's public and confidential clients for exactly this
    kind of local automation. The client matters because Keycloak maps claims per client
    — one client carries the `admin` client role that reaches Core's admin rule, another
    carries the `project` attribution Core's `projectPath` reads.
    """
    token_url = f"{require(env, 'KEYCLOAK_ADMIN_URL')}/realms/dial/protocol/openid-connect/token"
    form = {
        "client_id": require(env, client_id_key),
        "username": require(env, "TEST_USER_NAME"),
        "password": require(env, "TEST_USER_PASSWORD"),
        "grant_type": "password",
    }
    secret = env.get(client_secret_key, "")
    if secret:
        form["client_secret"] = secret
    status, body, _ = request("POST", token_url, form=form)
    if status != HTTP_OK:
        raise TokenRequestError(client_id_key, status)
    return json.loads(body)["access_token"]


def write_secret(path: Path, content: str) -> None:
    """Write credential or key material where `.gitignore` keeps it out of the tree."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
