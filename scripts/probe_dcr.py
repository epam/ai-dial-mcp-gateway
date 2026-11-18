"""Verify the dynamic-client-registration fallback against the composed stack.

Dynamic client registration is the config-gated fallback path: CIMD is the designed way a
harness registers, and this endpoint exists for clients that can present no client-id
metadata document. Group 8 proves the fallback live — flag off and flag on — because a
path that is only unit-tested is not proven to be wired into the deployment.

The probe is ordered so each verdict means something:

1. **The surface, as it is now.** The flat authorization-server metadata either
   advertises `registration_endpoint` or does not, and a registration POST either
   succeeds or is answered with the documented disabled-error. Which branch is expected
   is chosen by `--expect`, so the same script runs the flag-off and the flag-on checks.
2. **The refusal branch** (flag on only): a body without `redirect_uris` is refused,
   because such a registration would issue a client id no authorization request could
   ever be completed for.
3. **The registration itself** (`--register`): one registration with a loopback
   `redirect_uri` and a `client_name`, whose returned `client_id` is written to a
   gitignored scratch file so a later run — after a restart, or after a re-enable — can
   present the same id with no re-registration.
4. **The response document's member types** (part of step 3): an RFC 7591 §3.2.1 typed
   sweep over the whole document, so a member whose JSON type is wrong fails the probe
   instead of being printed and passing. This is the assertion that was missing when a
   string `client_id_issued_at` broke every schema-strict client while this probe
   reported green. Its negative control is a hand-built conformant document, which the
   sweep must find no violation in.

Nothing here prints a credential: the endpoint issues no secret, the store holds no
secret, and the `client_id` is shown as a redacted handle while being kept in the
gitignored scratch file the follow-up run reads.

Usage:
    # flag off (or after unsetting it again): the disabled branch
    PYTHONUTF8=1 python scripts/probe_dcr.py --expect disabled
    # flag on: the surface, the refusal branch, and a registration
    PYTHONUTF8=1 python scripts/probe_dcr.py --expect enabled --register
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import HTTP_OK, REPO_ROOT, USER_AGENT, SpikeError, redact, request

# The public origin the composed router publishes. Matches `GATEWAY_PUBLIC_ORIGIN`.
DEFAULT_ORIGIN = "http://localhost:8090"

# The path the registration endpoint is served from, and the well-known document that
# either advertises it or does not.
REGISTER_PATH = "/dial/register"
AS_METADATA_PATH = "/.well-known/oauth-authorization-server"

# The statuses this probe asserts on: RFC 7591 answers a created registration with 201,
# the disabled-error and a missing endpoint are the same 404, a refused body is 400, and
# an accepted authorization request redirects to the identity provider.
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_NOT_FOUND = 404
HTTP_REDIRECT = 302

# The loopback callback this probe's registrations name. A loopback URI is what a native
# harness registers (it binds an ephemeral port per launch and cannot pre-register one),
# so it is the shape worth proving; the port is not part of the match for a loopback
# entry.
DEFAULT_CALLBACK_PORT = 8768

# Where the registered client id is kept between runs. Gitignored (`dcr_client.json`), so
# a client id — which is an identifier a harness caches, not a secret, but is also not
# repository content — never lands in the tree.
SCRATCH_PATH = REPO_ROOT / "dcr_client.json"


class VerdictError(SpikeError):
    """A check did not produce what the flag state says it must."""


class SurfaceError(VerdictError):
    """The advertised surface or the registration endpoint's answer is not the expected one.

    Each refusal is a named constructor rather than a message assembled at the raise site,
    so the wording of a verdict lives with the verdict's own class and a caller cannot
    drift two copies of the same sentence apart.
    """

    def __init__(self, detail: str) -> None:
        super().__init__(
            f"the registration surface is not in its expected state: {detail}"
        )

    @classmethod
    def metadata_status(cls, status: int) -> SurfaceError:
        return cls(f"the metadata document answered HTTP {status}")

    @classmethod
    def not_advertised(
        cls, origin: str, advertised: object, *, expected: bool
    ) -> SurfaceError:
        if expected:
            return cls(
                "the flag is on, so the metadata must advertise the registration "
                f"endpoint at {origin}{REGISTER_PATH}; it advertised {advertised!r}"
            )
        return cls(
            "the flag is off, so the metadata must advertise no registration "
            f"endpoint; it advertised {advertised!r}"
        )

    @classmethod
    def disabled_error_missing(cls, status: int) -> SurfaceError:
        return cls(
            "the flag is off, so the registration endpoint must answer the documented "
            f"disabled-error ({HTTP_NOT_FOUND}); it answered HTTP {status}"
        )


class RefusalError(VerdictError):
    """A registration body the endpoint must refuse was accepted, or vice versa."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"the refusal branch is wrong: {detail}")

    @classmethod
    def not_refused(cls, status: int) -> RefusalError:
        return cls(
            "a registration with no redirect_uris must be refused with a plain-language "
            f"error ({HTTP_BAD_REQUEST}); it answered HTTP {status}"
        )


class RegistrationError(VerdictError):
    """The registration did not produce a usable registration response."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"the registration did not succeed: {detail}")

    @classmethod
    def endpoint_refused(cls, status: int, response: str) -> RegistrationError:
        return cls(f"the endpoint answered HTTP {status}: {response[:300]}")

    @classmethod
    def secret_issued(cls, key: str) -> RegistrationError:
        return cls(
            f"the response carried {key!r}; every client here is a public PKCE client "
            "and no secret may be issued"
        )

    @classmethod
    def not_a_document(cls, kind: str) -> RegistrationError:
        return cls(
            f"the registration response must be a JSON object of RFC 7591 members; got "
            f"{kind}"
        )

    @classmethod
    def no_client_id(cls, kind: str) -> RegistrationError:
        return cls(
            f"the registration response's client_id must be a string the caller can "
            f"cache; got {kind}"
        )


class TypedSweepError(RegistrationError):
    """The response document carries a member whose JSON type RFC 7591 §3.2.1 denies.

    Its own class because this is the failure a schema-strict client reports as a
    document-level rejection: the client discards the *whole* response — including the
    valid members — so the gateway's registration persists while the client's never
    happened, and the client retries. A type check that only printed the document could
    not see this, which is why the sweep is an assertion.
    """

    @classmethod
    def violations(cls, found: dict[str, str]) -> TypedSweepError:
        detail = "; ".join(f"{member}: {why}" for member, why in sorted(found.items()))
        return cls(
            f"the response document does not conform to RFC 7591 §3.2.1 — {detail}. A "
            "schema-strict client rejects the whole document on a type mismatch, so the "
            "registration is lost client-side even though the gateway answered 201"
        )

    @classmethod
    def control_is_broken(cls, found: dict[str, str]) -> TypedSweepError:
        detail = "; ".join(f"{member}: {why}" for member, why in sorted(found.items()))
        return cls(
            f"the sweep reported a violation in the hand-built conformant control "
            f"document ({detail}), so a violation in the live document would be "
            f"indistinguishable from a broken instrument; the sweep itself is wrong"
        )


class AuthorizeError(VerdictError):
    """An authorization request as the registered client did not behave as required."""

    def __init__(self, detail: str) -> None:
        super().__init__(f"the authorization request is wrong: {detail}")

    @classmethod
    def unreachable(cls, url: str, reason: object) -> AuthorizeError:
        return cls(f"GET {url} could not be reached: {reason}")

    @classmethod
    def not_accepted(cls, status: int, response: str) -> AuthorizeError:
        return cls(
            "the registered client's own redirect URI must be accepted and start a "
            f"flow ({HTTP_REDIRECT} to the identity provider); got HTTP {status}: "
            f"{response[:200]}"
        )

    @classmethod
    def not_refused(cls, netloc: str) -> AuthorizeError:
        return cls(
            "a redirect URI this client never registered must be refused; the gateway "
            f"redirected to {netloc}"
        )


class MissingClientIdError(VerdictError):
    """No client id is available to make an authorization request with."""

    def __init__(self) -> None:
        super().__init__(
            f"no client id given and {SCRATCH_PATH.name} does not exist; run with "
            "--register first"
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect handler that never follows, so a redirect is observable as one."""

    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _registration_body(port: int, *, with_redirects: bool) -> dict[str, object]:
    """A registration body: the minimum the endpoint accepts, plus a name.

    `redirect_uris` is the one required field; `client_name` is optional and is what an
    operator sees in the store, so it is sent to prove the field round-trips.
    """
    redirect_uri = f"http://127.0.0.1:{port}/callback"
    body: dict[str, object] = {"client_name": "group8-dcr-probe"}
    if with_redirects:
        body["redirect_uris"] = [redirect_uri]
    return body


def check_surface(origin: str, *, expect_enabled: bool) -> None:
    """The advertised surface and the registration endpoint's answer, per the flag."""
    print(f"=== the authorization-server metadata ({AS_METADATA_PATH}) ===")
    status, body, _headers = request("GET", f"{origin}{AS_METADATA_PATH}")
    if status != HTTP_OK:
        raise SurfaceError.metadata_status(status)
    advertised = json.loads(body).get("registration_endpoint")
    print(f"  registration_endpoint  {advertised or '<absent>'}")

    if expect_enabled:
        # With the flag on, the successful registration is the one `--register` performs,
        # so the store gains exactly the record that check intends. Posting another here
        # would make "one record" unverifiable.
        if advertised != f"{origin}{REGISTER_PATH}":
            raise SurfaceError.not_advertised(origin, advertised, expected=True)
        print("  verdict: green — the registration endpoint is advertised")
        return

    print(f"=== POST {REGISTER_PATH} with the flag off ===")
    body_dict = _registration_body(DEFAULT_CALLBACK_PORT, with_redirects=True)
    # Sent as a raw JSON body so the disabled branch is measured with a body the enabled
    # branch would accept: a refusal then means the flag, not the request.
    status, response, _headers = request(
        "POST",
        f"{origin}{REGISTER_PATH}",
        headers={"Content-Type": "application/json"},
        body=body_dict,
    )
    print(f"  status                 {status}")
    if response:
        try:
            document = json.loads(response)
        except ValueError:
            document = {"_raw": response[:200]}
        for key in ("error", "error_description", "client_id"):
            if key in document:
                value = document[key]
                print(f"  {key:22s} {redact(value) if key == 'client_id' else value}")

    if advertised:
        raise SurfaceError.not_advertised(origin, advertised, expected=False)
    if status != HTTP_NOT_FOUND:
        raise SurfaceError.disabled_error_missing(status)
    print("  verdict: green — no endpoint advertised, disabled-error answered")


# The JSON type of every RFC 7591 §3.2.1 response data member this gateway answers, as
# the RFC's own type table defines them. A member absent from this table is one the
# gateway does not send; a member present in a response but not here is an addition, and
# the sweep reports it rather than letting an unclassified member through.
_NUMBER = "number"
_STRING = "string"
_STRING_LIST = "list of strings"
_EXPECTED_MEMBER_TYPES: dict[str, str] = {
    "client_id": _STRING,
    "redirect_uris": _STRING_LIST,
    "client_name": _STRING,
    "token_endpoint_auth_method": _STRING,
    "grant_types": _STRING_LIST,
    "response_types": _STRING_LIST,
    "client_id_issued_at": _NUMBER,
}

# A registration response a conformant server could answer, member for member, used as the
# sweep's negative control: the sweep must find no violation in it. Without the control a
# violation found in the live document would be indistinguishable from a sweep that
# reports every document as violating.
CONFORMANT_CONTROL: dict[str, object] = {
    "client_id": "control-client-id",
    "redirect_uris": ["http://127.0.0.1:1/callback"],
    "client_name": "a conformant control client",
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code"],
    "response_types": ["code"],
    "client_id_issued_at": 1_792_067_046,
}


def _string_violation(rendered: str, value: object) -> str | None:
    """Why this value is not a JSON string, or `None` when it is one."""
    if isinstance(value, str):
        return None
    return f"expected {rendered}, got {type(value).__name__}"


def _number_violation(rendered: str, value: object) -> str | None:
    """Why this value is not a JSON number of whole seconds, or `None` when it is one.

    `bool` is excluded explicitly: it is a subclass of `int` in Python, so a `true` at
    `client_id_issued_at` would pass an `isinstance` check while being a JSON boolean
    rather than a number — the same class of defect as the string this sweep was written
    for. A fractional number is a JSON number but not a whole number of seconds, so it is
    refused as the value this member does not carry.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return f"expected {rendered}, got {type(value).__name__}"
    if isinstance(value, float) and not value.is_integer():
        return f"expected a whole number of seconds, got {value!r}"
    return None


def _string_list_violation(rendered: str, value: object) -> str | None:
    """Why this value is not a JSON array of strings, or `None` when it is one."""
    if not isinstance(value, list):
        return f"expected {rendered}, got {type(value).__name__}"
    for index, entry in enumerate(value):
        if not isinstance(entry, str):
            return f"expected {rendered}, entry {index} is {type(entry).__name__}"
    return None


# The check each expected type name dispatches to.
_CHECKERS = {
    _STRING: _string_violation,
    _NUMBER: _number_violation,
    _STRING_LIST: _string_list_violation,
}


def _type_violation(member: str, value: object) -> str | None:
    """Why this member's value is not the JSON type RFC 7591 gives it, or `None`."""
    rendered = _EXPECTED_MEMBER_TYPES[member]
    return _CHECKERS[rendered](str(rendered), value)


# The members RFC 7591 §3.2.1 makes required in a response document: without a client id
# there is nothing for the client to cache, and without redirect URIs there is nothing an
# authorization request could be validated against.
_REQUIRED_RESPONSE_MEMBERS = ("client_id", "redirect_uris")


def typed_sweep(document: dict[str, object]) -> dict[str, str]:
    """Every RFC 7591 §3.2.1 member of a response document that violates the RFC.

    The sweep is over the *whole* document, not the one member a known defect touched:
    the defect that motivated it was found by exactly this sweep, and the reason it went
    unnoticed so long is that the instrument printed the member and checked nothing. A
    type defect anywhere in the document costs a schema-strict client the whole
    registration, so a check that looked at one field would recreate the blind spot in a
    narrower place.

    Three classes of violation, all of which are document-level rejections for a
    schema-validating client: a member missing that the RFC requires, a member carrying
    the wrong JSON type, and a member that is no RFC 7591 response member at all.
    """
    found: dict[str, str] = {}
    for member in _REQUIRED_RESPONSE_MEMBERS:
        if member not in document:
            found[member] = "required by RFC 7591 §3.2.1 and absent from the response"
    for member, value in document.items():
        if member not in _EXPECTED_MEMBER_TYPES:
            found[member] = "not an RFC 7591 §3.2.1 registration response member"
            continue
        violation = _type_violation(member, value)
        if violation is not None:
            found[member] = violation
    return found


def check_typed_sweep(document: dict[str, object]) -> None:
    """Assert the response document's member types, with the conformant control.

    Raises `TypedSweepError` when the live document violates, naming every violating
    member and its value's type — a strict client reports this as a document-level
    rejection, so the probe has to report which member caused it.
    """
    print("=== the typed sweep: RFC 7591 §3.2.1 response members ===")
    control_violations = typed_sweep(CONFORMANT_CONTROL)
    print(f"  negative control       {control_violations or 'no violation'}")
    if control_violations:
        raise TypedSweepError.control_is_broken(control_violations)

    violations = typed_sweep(document)
    for member in sorted(_EXPECTED_MEMBER_TYPES):
        if member not in document:
            continue
        value = document[member]
        rendered = redact(value) if member == "client_id" else json.dumps(value)
        mark = "  VIOLATION" if member in violations else ""
        print(f"  {member:22s} {type(value).__name__:6s} {rendered}{mark}")

    if violations:
        raise TypedSweepError.violations(violations)
    print("  verdict: green — every member carries its RFC 7591 §3.2.1 JSON type")


def check_refusal(origin: str) -> None:
    """A registration without `redirect_uris` is refused (flag-on branch only)."""
    print(f"=== the refusal branch: POST {REGISTER_PATH} with no redirect_uris ===")
    status, response, _headers = request(
        "POST",
        f"{origin}{REGISTER_PATH}",
        headers={"Content-Type": "application/json"},
        body=_registration_body(DEFAULT_CALLBACK_PORT, with_redirects=False),
    )
    print(f"  status                 {status}")
    document = json.loads(response) if response else {}
    print(f"  error                  {document.get('error')}")
    print(f"  error_description      {document.get('error_description')}")
    if status != HTTP_BAD_REQUEST:
        raise RefusalError.not_refused(status)
    print("  verdict: green — the registration was refused")


def register(origin: str) -> str:
    """Register a client, record its id in the scratch file, and return the id."""
    print(
        f"=== the registration: POST {REGISTER_PATH} with a loopback redirect_uri ==="
    )
    body = _registration_body(DEFAULT_CALLBACK_PORT, with_redirects=True)
    status, response, _headers = request(
        "POST",
        f"{origin}{REGISTER_PATH}",
        headers={"Content-Type": "application/json"},
        body=body,
    )
    if status != HTTP_CREATED:
        raise RegistrationError.endpoint_refused(status, response)
    parsed: object = json.loads(response)
    if not isinstance(parsed, dict):
        raise RegistrationError.not_a_document(type(parsed).__name__)
    document: dict[str, object] = parsed
    client_id_value = document.get("client_id")
    if not isinstance(client_id_value, str):
        raise RegistrationError.no_client_id(type(client_id_value).__name__)
    client_id = client_id_value
    print(f"  client_id              {redact(client_id)}")
    # The typed sweep is the check this probe was missing: it printed the document and
    # asserted nothing about the members' types, so a type defect on this path passed
    # here while breaking every schema-strict client.
    check_typed_sweep(document)
    for key in ("client_secret", "registration_access_token"):
        if document.get(key):
            raise RegistrationError.secret_issued(key)
    SCRATCH_PATH.write_text(
        json.dumps(
            {
                "client_id": client_id,
                "redirect_uris": document.get("redirect_uris"),
                "callback_port": DEFAULT_CALLBACK_PORT,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"  recorded               {SCRATCH_PATH.name} (gitignored)")
    print("  verdict: green — one registration accepted, no secret issued")
    return client_id


def _request_no_redirect(
    url: str,
) -> tuple[int, str, dict[str, str]]:
    """One GET that never follows a redirect, returning status, body, and headers.

    `spike_env.request` follows redirects, which is right for the scripts that read a
    JSON document and wrong here: the accepted authorization request answers 302 to the
    identity provider, and following it would replace the flow's outcome with the
    provider's login page.
    """
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(  # noqa: S310 - a configured local endpoint
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}
    )
    try:
        with opener.open(req, timeout=30) as response:
            return (
                response.status,
                response.read().decode(errors="replace"),
                {key.lower(): value for key, value in response.headers.items()},
            )
    except urllib.error.HTTPError as exc:
        return (
            exc.code,
            exc.read().decode(errors="replace"),
            {key.lower(): value for key, value in exc.headers.items()},
        )
    except urllib.error.URLError as exc:
        raise AuthorizeError.unreachable(url, exc.reason) from exc


def authorize_probe(origin: str, client_id: str, *, port: int, expect: str) -> None:
    """An authorization request as the registered client, on its registered redirect URI.

    This is the restart-persistence check: after a gateway recreation, the same client id
    with the same registered redirect URI must still start a flow, with no re-registration
    in between. `--expect rejected` is the negative control — a redirect URI the client
    never registered, which must be refused — so a pass cannot come from a gateway that
    accepts anything.

    The control's URI differs in *path*, not in port. A registered loopback URI matches a
    port-varied request by design, so a port-only difference is the accepted case, not a
    refusal; a control built on one would pass for the wrong reason.
    """
    print("=== an authorization request as the registered client ===")
    resource = f"{origin}/dial/notion/mcp"
    redirect = (
        f"http://127.0.0.1:{port}/callback"
        if expect == "accepted"
        else f"http://127.0.0.1:{port}/not-registered"
    )
    query = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect,
            "response_type": "code",
            "resource": resource,
            "code_challenge": "0" * 43,
            "code_challenge_method": "S256",
            "state": "group8-probe",
        }
    )
    # Deliberately not followed: the accepted case ends in a redirect to the identity
    # provider, and a helper that followed it would fetch a login page and report the
    # flow's outcome as that page's status.
    status, response, headers = _request_no_redirect(f"{origin}/dial/authorize?{query}")
    location = headers.get("location") or headers.get("Location") or ""
    target = urllib.parse.urlparse(location)
    print(f"  redirect_uri           {redirect}")
    print(f"  status                 {status}")
    print(f"  location host          {target.netloc or '<none>'}")
    if expect == "accepted":
        if status != HTTP_REDIRECT or not target.netloc:
            raise AuthorizeError.not_accepted(status, response)
        print("  verdict: green — accepted, the registration resolved")
    else:
        if status == HTTP_REDIRECT and target.netloc:
            raise AuthorizeError.not_refused(target.netloc)
        print(f"  body                   {response[:200]}")
        print("  verdict: green — refused, as required for the control")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN, help="the public origin")
    parser.add_argument(
        "--expect",
        choices=("enabled", "disabled"),
        required=True,
        help="which branch the surface must be in",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="perform a registration and record its client id for a later run",
    )
    parser.add_argument(
        "--authorize-client-id",
        default=None,
        help="the client id to use in the authorization request "
        "(default: the id recorded in dcr_client.json)",
    )
    parser.add_argument(
        "--authorize-expect",
        choices=("accepted", "rejected"),
        default=None,
        help="run the authorization request and assert this outcome",
    )
    args = parser.parse_args()

    check_surface(args.origin, expect_enabled=args.expect == "enabled")

    client_id = args.authorize_client_id
    if args.expect == "enabled":
        check_refusal(args.origin)
    if args.register:
        client_id = register(args.origin)

    recorded: dict[str, object] = {}
    if SCRATCH_PATH.is_file():
        recorded = json.loads(SCRATCH_PATH.read_text(encoding="utf-8"))

    if args.authorize_expect:
        if client_id is None:
            if "client_id" not in recorded:
                raise MissingClientIdError
            client_id = str(recorded["client_id"])
        port = int(str(recorded.get("callback_port", DEFAULT_CALLBACK_PORT)))
        authorize_probe(args.origin, client_id, port=port, expect=args.authorize_expect)

    print()
    print("=== probe verdict ===")
    print(f"  the surface is in its expected state ({args.expect})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
