"""Tests for Client ID Metadata Document resolution and its SSRF control set.

Every control is exercised as a negative first and then shown not to break the positive
path, because these controls exist to refuse things — and a control that refuses
everything is indistinguishable from a working one until the positive case is measured.

The fetch is intercepted with respx, which patches httpx's transport. That means these
tests assert the request the gateway builds — its URL, its headers, its `sni_hostname`
extension — rather than the socket it would open; the connection-level behavior
(connecting to the validated address) is asserted through the extension and the URL,
which is what determines where the socket goes.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest
import respx
from gateway.cimd import (
    CimdError,
    ClientMetadataCache,
    ResolvedClient,
    is_url_shaped_client_id,
    redirect_uri_allowed,
    resolve_client,
)
from gateway.settings import Settings

from tests.conftest import TOOLSET_NAME, make_settings

# The document URL a CIMD-capable client presents as its client id. The origin is the
# default allowlist entry.
CLIENT_ID_URL = "https://claude.ai/oauth/claude-code-client-metadata"
CLIENT_REDIRECT_URI = "http://127.0.0.1:8766/callback"

# An allowlisted HTTPS origin and a non-allowlisted one, for the allowlist branches.
ALLOWED_ORIGIN = "https://claude.ai"
OTHER_ORIGIN = "https://evil.example"

# A public address the metadata hosts resolve to. Every fetch test pins the resolution to
# this so no test depends on live DNS.
PUBLIC_ADDRESS = "93.184.216.34"

# The URL the gateway actually requests: the client-id URL re-addressed to the address
# that passed the range check, with the host name kept in the `Host` header. Routes below
# therefore match this, and a route on the name would fail — which is the pinning,
# observed.
PINNED_URL = f"https://{PUBLIC_ADDRESS}/oauth/claude-code-client-metadata"

# The document URL path, reused when a test needs to build another URL on this host.
CLIENT_ID_PATH = "/oauth/claude-code-client-metadata"

# How many documents the bounded-cache test resolves, and how many the cache holds.
CACHE_PROBE_COUNT = 5
CACHE_BOUND = 2

# The default bounds, restated here so a change to a default fails a test that names it.
DEFAULT_DOCUMENT_BYTES = 65_536
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_TOTAL_TIMEOUT = 10.0


def cimd_settings(**overrides: object) -> Settings:
    """Settings with the default allowlist and the CIMD bounds stated explicitly."""
    return make_settings(**overrides)


def document(**overrides: Any) -> dict[str, Any]:
    """A well-formed client-id document, with fields overridable per test."""
    base: dict[str, Any] = {
        "client_id": CLIENT_ID_URL,
        "client_name": "A harness",
        "redirect_uris": [CLIENT_REDIRECT_URI],
    }
    base.update(overrides)
    return base


@pytest.fixture
def public_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve every CIMD host to a public address, so no test touches live DNS."""
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", (PUBLIC_ADDRESS, 443)),
        ],
    )


def route_document(
    router: respx.Router, body: dict[str, Any] | None = None, **kwargs: Any
) -> respx.Route:
    """Route the pinned client-id URL to a well-formed JSON document.

    The route is on the pinned URL rather than on the name because that is where the
    request goes; a route on the name would not match, and its not matching is the
    address pinning working.
    """
    return router.get(PINNED_URL).mock(
        return_value=httpx.Response(
            200,
            json=body if body is not None else document(),
            headers={"content-type": "application/json"},
            **kwargs,
        )
    )


# ------------------------------------------------------------------ the happy path


@respx.mock
def test_a_document_resolves_a_client(public_resolution: None) -> None:
    """The positive control for every refusal below: this is what success looks like."""
    route_document(respx.mock)
    settings = cimd_settings()

    client = resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))

    assert client.client_id == CLIENT_ID_URL
    assert client.redirect_uris == (CLIENT_REDIRECT_URI,)
    assert client.client_name == "A harness"
    assert client.source == "cimd"


@respx.mock
def test_the_fetch_carries_an_explicit_non_default_user_agent(
    public_resolution: None,
) -> None:
    """The origin's bot protection rejects library-default agents outright.

    A default agent would surface as a late, misleading registration failure at a
    harness, so the header is asserted as the behaviour it is rather than left to a
    comment.
    """
    route = route_document(respx.mock)
    settings = cimd_settings()

    resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))

    sent = route.calls[0].request
    user_agent = sent.headers.get("user-agent", "")
    assert user_agent == settings.gateway_cimd_user_agent
    assert "python-httpx" not in user_agent.lower()
    assert "python-urllib" not in user_agent.lower()


@respx.mock
def test_the_fetch_is_addressed_to_the_validated_address(
    public_resolution: None,
) -> None:
    """The connection goes to the address that passed the check, not to the name.

    The check is on the resolved addresses; connecting by name afterwards would let a
    host that answered publicly for the check answer privately for the connection. The
    host name is preserved in the `Host` header and in the TLS extension, so this is a
    pinning rather than a downgrade.
    """
    route = route_document(respx.mock)
    settings = cimd_settings()

    resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))

    sent = route.calls[0].request
    assert sent.url.host == PUBLIC_ADDRESS
    assert sent.headers["host"] == "claude.ai"
    assert sent.extensions.get("sni_hostname") == "claude.ai"


@respx.mock
def test_a_cached_document_is_not_fetched_twice(public_resolution: None) -> None:
    """The cache is what keeps a client's own document from being fetched per request."""
    route = route_document(respx.mock)
    settings = cimd_settings()
    cache = ClientMetadataCache(settings)

    resolve_client(CLIENT_ID_URL, settings, cache)
    resolve_client(CLIENT_ID_URL, settings, cache)

    assert route.call_count == 1


def test_a_cache_entry_expires_after_its_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client's edit of its own document takes effect within the TTL, not never."""
    calls: list[int] = []

    def fake_fetch(client_id: str, settings: Settings) -> dict[str, Any]:
        calls.append(1)
        return document()

    monkeypatch.setattr("gateway.cimd._fetch_document", fake_fetch)
    settings = cimd_settings(gateway_cimd_cache_ttl_seconds=1)
    cache = ClientMetadataCache(settings)

    resolve_client(CLIENT_ID_URL, settings, cache)
    assert len(calls) == 1

    # Move the clock past the TTL rather than sleeping: the cache compares monotonic
    # time, so advancing it is the same measurement without the wall-clock delay.
    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 3600)

    resolve_client(CLIENT_ID_URL, settings, cache)
    assert len(calls) == 2  # noqa: PLR2004 - one fetch before the TTL and one after


def test_the_cache_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A client id must not grow the gateway's memory without limit.

    The bound is the number of cached entries; a new document past it evicts rather than
    accumulating, whichever client id asks.
    """
    monkeypatch.setattr(
        "gateway.cimd._fetch_document",
        lambda client_id, settings: document(client_id=client_id),
    )
    settings = cimd_settings(gateway_cimd_cache_max_entries=2)
    cache = ClientMetadataCache(settings)

    for index in range(CACHE_PROBE_COUNT):
        url = f"https://claude.ai/meta/{index}"
        resolve_client(url, settings, cache)

    # Every document resolved, and the bound's worth are held: the bound is on the cache,
    # not on the number of clients that may exist.
    assert cache.entries == CACHE_BOUND


# ----------------------------------------------------------------- negative controls


@respx.mock
def test_an_http_client_id_is_refused(public_resolution: None) -> None:
    """HTTPS only: an http fetch is observable and modifiable in transit."""
    route = respx.mock.get("http://claude.ai/oauth/meta").mock(
        return_value=httpx.Response(200, json=document())
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="https"):
        resolve_client(
            "http://claude.ai/oauth/meta", settings, ClientMetadataCache(settings)
        )

    assert not route.called


@respx.mock
def test_a_non_allowlisted_origin_is_refused(public_resolution: None) -> None:
    """The allowlist is what keeps a client id from probing arbitrary hosts."""
    route = respx.mock.get(f"{OTHER_ORIGIN}/meta").mock(
        return_value=httpx.Response(200, json=document())
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="allowed origins"):
        resolve_client(f"{OTHER_ORIGIN}/meta", settings, ClientMetadataCache(settings))

    assert not route.called


@respx.mock
def test_a_redirect_is_refused(public_resolution: None) -> None:
    """No redirects: the pivot an SSRF attacker needs, with no legitimate use here."""
    respx.mock.get(PINNED_URL).mock(
        return_value=httpx.Response(
            302, headers={"location": "https://elsewhere.example/"}
        )
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="redirect"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_redirect_to_a_private_address_is_also_refused(
    public_resolution: None,
) -> None:
    """The refusal is on the redirect itself, not on where it points.

    Following it and re-checking would be a second request the control set does not
    authorize; the redirect is where the chain stops.
    """
    respx.mock.get(PINNED_URL).mock(
        return_value=httpx.Response(
            301, headers={"location": "http://169.254.169.254/"}
        )
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="redirect"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.1",
        "172.16.0.1",
        "169.254.169.254",
        "::1",
        "fd00::1",
    ],
)
def test_a_private_loopback_or_link_local_resolution_is_refused(
    monkeypatch: pytest.MonkeyPatch, address: str
) -> None:
    """The metadata service lives at a link-local address, which is one of these."""
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (address, 443))],
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="non-public address"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


def test_a_name_answering_with_one_public_and_one_private_address_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All records are checked, not just the first.

    A host that answers with both would otherwise pass or fail depending on which record
    the resolver happened to return first — a rebinding window made of DNS ordering.
    """
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [
            (2, 1, 6, "", (PUBLIC_ADDRESS, 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ],
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="non-public address"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


def test_a_localhost_hostname_is_refused_even_when_its_origin_is_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The name guard is defense in depth behind the allowlist, not a duplicate of it.

    An allowlist that names a loopback origin is a misconfiguration; the guard refuses
    the name anyway, so the allowlist cannot be the only thing standing between a client
    id and the gateway's own loopback interface.
    """
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (PUBLIC_ADDRESS, 443))],
    )
    settings = cimd_settings(
        gateway_cimd_allowed_origins=f"{ALLOWED_ORIGIN},https://localhost"
    )

    with pytest.raises(CimdError, match="never a metadata origin"):
        resolve_client(
            "https://localhost/oauth/meta", settings, ClientMetadataCache(settings)
        )


@respx.mock
def test_an_oversize_document_is_refused(public_resolution: None) -> None:
    """The cap is enforced while reading, so the memory it bounds is never allocated."""
    settings = cimd_settings(gateway_cimd_max_document_bytes=200)
    # A well-formed document padded past the cap.
    padded = document(client_name="x" * 500)
    respx.mock.get(PINNED_URL).mock(
        return_value=httpx.Response(
            200, json=padded, headers={"content-type": "application/json"}
        )
    )

    with pytest.raises(CimdError, match="larger than 200 bytes"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_non_json_content_type_is_refused(public_resolution: None) -> None:
    """A document served as something else is not the document that was asked for."""
    respx.mock.get(PINNED_URL).mock(
        return_value=httpx.Response(
            200,
            text="<html>not a document</html>",
            headers={"content-type": "text/html"},
        )
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="not application/json"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_non_ok_status_is_refused(public_resolution: None) -> None:
    respx.mock.get(PINNED_URL).mock(return_value=httpx.Response(404))
    settings = cimd_settings()

    with pytest.raises(CimdError, match="404"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_an_unparseable_body_is_refused(public_resolution: None) -> None:
    respx.mock.get(PINNED_URL).mock(
        return_value=httpx.Response(
            200, text="{not json", headers={"content-type": "application/json"}
        )
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="not valid JSON"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_document_naming_another_client_id_is_refused(
    public_resolution: None,
) -> None:
    """A document must declare the URL it is served from.

    Otherwise one allowlisted origin could register a client id belonging to another —
    and the id is what a subsequent authorization request is resolved by.
    """
    route_document(respx.mock, body=document(client_id="https://claude.ai/other"))
    settings = cimd_settings()

    with pytest.raises(CimdError, match="declares client_id"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_document_with_no_redirect_uris_is_refused(public_resolution: None) -> None:
    """Without redirect URIs no authorization request could be validated against it."""
    route_document(respx.mock, body=document(redirect_uris=[]))
    settings = cimd_settings()

    with pytest.raises(CimdError, match="no redirect_uris"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_document_missing_the_redirect_uris_member_is_refused(
    public_resolution: None,
) -> None:
    body = document()
    del body["redirect_uris"]
    route_document(respx.mock, body=body)
    settings = cimd_settings()

    with pytest.raises(CimdError, match="no redirect_uris"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_non_string_redirect_uri_is_refused(public_resolution: None) -> None:
    route_document(respx.mock, body=document(redirect_uris=[1234]))
    settings = cimd_settings()

    with pytest.raises(CimdError, match="non-string redirect_uri"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_non_loopback_http_redirect_uri_refuses_the_whole_document(
    public_resolution: None,
) -> None:
    """The admission rule governs the CIMD document's `redirect_uris`, not the fetch alone.

    A document listing a plain-`http` redirect on a real host is refused as a registration:
    no authorization request ever resolves against it, because the code and the echoed
    `state` would otherwise cross that cleartext leg. The document is refused whole — the
    same refuse-whole discipline the other document validations use.
    """
    route_document(
        respx.mock,
        body=document(redirect_uris=["http://collector.example/callback"]),
    )
    settings = cimd_settings()

    with pytest.raises(CimdError, match="must be `https`"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


@respx.mock
def test_a_loopback_http_redirect_uri_is_admitted_in_a_document(
    public_resolution: None,
) -> None:
    """The RFC 8252 loopback exception: loopback `http`, any port, stays admitted."""
    route_document(
        respx.mock, body=document(redirect_uris=["http://localhost:45002/cb"])
    )
    settings = cimd_settings()

    client = resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))

    assert client.redirect_uris == ("http://localhost:45002/cb",)


@respx.mock
def test_an_https_redirect_uri_is_admitted_in_a_document(
    public_resolution: None,
) -> None:
    route_document(respx.mock, body=document(redirect_uris=["https://app.example/cb"]))
    settings = cimd_settings()

    client = resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))

    assert client.redirect_uris == ("https://app.example/cb",)


@respx.mock
def test_a_transport_failure_is_reported_without_echoing_the_url(
    public_resolution: None,
) -> None:
    """An httpx error can carry the URL it failed on, so only its type is reported."""
    respx.mock.get(PINNED_URL).mock(side_effect=httpx.ConnectError("boom"))
    settings = cimd_settings()

    with pytest.raises(CimdError) as excinfo:
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))

    assert "ConnectError" in str(excinfo.value)
    assert "boom" not in str(excinfo.value)


def test_credentials_in_the_client_id_url_are_refused() -> None:
    """A URL carrying credentials is not a document URL, whatever it resolves to."""
    settings = cimd_settings()

    with pytest.raises(CimdError, match="must not carry credentials"):
        resolve_client(
            "https://user:pass@claude.ai/meta", settings, ClientMetadataCache(settings)
        )


def test_an_empty_allowlist_refuses_every_origin() -> None:
    """With nothing allowlisted, nothing is fetched — the fail-closed direction."""
    settings = cimd_settings(gateway_cimd_allowed_origins="")

    with pytest.raises(CimdError, match="none configured"):
        resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))


# ---------------------------------------------------------------- resolution order


def test_a_pre_registered_client_resolves_without_a_fetch() -> None:
    """The first rung: an operator's own list, with no network and no registration."""
    settings = cimd_settings(
        pre_registered_clients={
            "harness": {
                "redirect_uris": [CLIENT_REDIRECT_URI],
                "client_name": "A pre-registered harness",
            }
        }
    )

    client = resolve_client("harness", settings, ClientMetadataCache(settings))

    assert client.source == "pre_registered"
    assert client.redirect_uris == (CLIENT_REDIRECT_URI,)
    assert client.client_name == "A pre-registered harness"


def test_a_pre_registered_client_wins_over_a_url_shaped_lookup() -> None:
    """Priority is order, not shape: an operator's registration is authoritative.

    A client id listed by the operator resolves from that list even when it looks like a
    URL, so a deployment can pin a client whose document it does not want fetched.
    """
    settings = cimd_settings(
        pre_registered_clients={CLIENT_ID_URL: {"redirect_uris": [CLIENT_REDIRECT_URI]}}
    )

    client = resolve_client(CLIENT_ID_URL, settings, ClientMetadataCache(settings))

    assert client.source == "pre_registered"


def test_an_opaque_unknown_client_id_is_refused() -> None:
    """A non-URL id that is not pre-registered has no path left to resolve by."""
    settings = cimd_settings()

    with pytest.raises(CimdError, match="not registered"):
        resolve_client("some-opaque-id", settings, ClientMetadataCache(settings))


@pytest.mark.parametrize(
    ("client_id", "expected"),
    [
        ("https://claude.ai/meta", True),
        ("http://claude.ai/meta", True),
        ("harness", False),
        ("harness.with.dots", False),
        ("urn:example:client", False),
    ],
)
def test_url_shaped_client_ids_are_recognized_structurally(
    client_id: str, expected: bool
) -> None:
    """The test is scheme-and-host, so a client id that merely contains a dot is not a URL."""
    assert is_url_shaped_client_id(client_id) is expected


# ------------------------------------------------------------- redirect validation


def client_with(*redirect_uris: str) -> ResolvedClient:
    """A pre-registered client whose registration is exactly these redirect URIs.

    The matcher reads nothing but the registration's entries, so a client built here is
    the whole input under test — no settings, no fetch, no network.
    """
    return ResolvedClient(
        client_id="harness",
        redirect_uris=tuple(redirect_uris),
        client_name=None,
        source="pre_registered",
    )


def test_a_loopback_entry_ignores_only_the_port() -> None:
    """A loopback registration matches on scheme, host, and path, with any port.

    The registered entry is an explicit-port loopback URI, the shape a pre-registered
    native client has: a harness cannot pin the ephemeral port it will bind, so a
    registered `:8766` must accept the `:8767` the client actually got. Every other
    component stays exact — the rejections below are the normalizations an implementation
    might apply and this one does not.
    """
    client = client_with(CLIENT_REDIRECT_URI)

    assert redirect_uri_allowed(CLIENT_REDIRECT_URI, client)
    # The port-only difference, which is the whole exception: accepted.
    assert redirect_uri_allowed("http://127.0.0.1:8767/callback", client)
    # Everything else still differs, so it still refuses.
    assert not redirect_uri_allowed(CLIENT_REDIRECT_URI + "/path", client)
    assert not redirect_uri_allowed(CLIENT_REDIRECT_URI.upper(), client)
    assert not redirect_uri_allowed(CLIENT_REDIRECT_URI + "/", client)
    assert not redirect_uri_allowed("https://127.0.0.1:8766/callback", client)
    assert not redirect_uri_allowed("http://localhost:8766/callback", client)
    assert not redirect_uri_allowed(CLIENT_REDIRECT_URI + "?x=1", client)
    assert not redirect_uri_allowed(CLIENT_REDIRECT_URI + "#frag", client)
    assert not redirect_uri_allowed("http://127.0.0.1:8766/other", client)


def test_a_port_less_loopback_entry_matches_an_ephemeral_port() -> None:
    """The live case: a document registering `http://localhost/callback`, port-less.

    A native harness binds an OS-chosen port per launch and presents it on the URI, so a
    port-less loopback registration must accept it; the default port counts as just
    another value. The host is not aliased — `localhost` and `127.0.0.1` are separate
    registrations — and `https` on a loopback host earns nothing.
    """
    client = client_with("http://localhost/callback")

    assert redirect_uri_allowed("http://localhost/callback", client)
    assert redirect_uri_allowed("http://localhost:45002/callback", client)
    assert redirect_uri_allowed("http://localhost:80/callback", client)
    assert not redirect_uri_allowed("http://127.0.0.1:45002/callback", client)
    assert not redirect_uri_allowed("https://localhost:45002/callback", client)
    assert not redirect_uri_allowed("http://localhost:45002/callback/", client)
    assert not redirect_uri_allowed("http://localhost:45002/callback?code=1", client)
    # Scheme and host are case-insensitive on the wire (RFC 3986 §3.1/§3.2.2), so an
    # upper-cased spelling of the same loopback URI is the same URI. The path is not:
    # the rejection for a case-folded path is in the loopback test above.
    assert redirect_uri_allowed("HTTP://LOCALHOST:45002/callback", client)
    assert not redirect_uri_allowed("http://localhost:45002/CALLBACK", client)


def test_an_explicit_port_loopback_entry_matches_a_port_less_request() -> None:
    """The port is ignored on both sides, so a default-port entry matches a bare request.

    A registration that pinned `:80` names the same loopback callback a request arrives
    at with no port at all, and the reverse: nothing about the port distinguishes them.
    """
    client = client_with("http://127.0.0.1:80/callback")

    assert redirect_uri_allowed("http://127.0.0.1/callback", client)
    assert redirect_uri_allowed("http://127.0.0.1:45002/callback", client)
    assert redirect_uri_allowed("http://127.0.0.1:80/callback", client)


def test_a_loopback_entry_covers_the_ipv6_loopback_literal() -> None:
    """`[::1]` is one of the three loopback hosts, so it gets the same port exception."""
    client = client_with("http://[::1]:8766/callback")

    assert redirect_uri_allowed("http://[::1]:8766/callback", client)
    assert redirect_uri_allowed("http://[::1]:45002/callback", client)
    assert not redirect_uri_allowed("https://[::1]:45002/callback", client)
    assert not redirect_uri_allowed("http://[::1]:45002/other", client)
    assert redirect_uri_allowed("http://[::1]/callback", client)


def test_non_loopback_redirect_uri_matching_is_exact() -> None:
    """Every non-loopback registration keeps exact string equality, port included.

    A redirect URI is a security boundary, and the loopback exception is the only one:
    folding case, ignoring a trailing slash, or dropping the port on a real host is a rule
    the specification this implements does not have.
    """
    client = client_with("https://app.example/callback")

    assert redirect_uri_allowed("https://app.example/callback", client)
    assert not redirect_uri_allowed("https://app.example:8443/callback", client)
    assert not redirect_uri_allowed("https://other.example/callback", client)
    assert not redirect_uri_allowed("http://app.example/callback", client)
    assert not redirect_uri_allowed("https://app.example/callback/", client)
    assert not redirect_uri_allowed("https://app.example/Callback", client)

    with_default_port = client_with("https://app.example:443/callback")

    assert not redirect_uri_allowed("https://app.example/callback", with_default_port)


def test_a_loopback_request_earns_no_exception_against_a_real_host() -> None:
    """The exception is keyed on the registered entry, never on the request's value.

    A request that looks like a loopback callback — the exact shape the field harness
    sends — matches nothing against a registration that named a real host, so a hostile
    request cannot self-declare its way into a relaxation the client never registered.
    """
    for registered in (
        "https://app.example/callback",
        "http://app.example:8080/callback",
    ):
        client = client_with(registered)

        assert not redirect_uri_allowed("http://localhost:45002/callback", client)
        assert not redirect_uri_allowed("http://127.0.0.1:45002/callback", client)
        assert not redirect_uri_allowed("http://[::1]:45002/callback", client)
        assert not redirect_uri_allowed(
            "http://localhost:45002/callback?code=1", client
        )


def test_the_loopback_exception_applies_to_the_entry_that_matches() -> None:
    """A registration carrying both kinds is matched entry by entry.

    The loopback entry accepts a port-varied request while the non-loopback one beside it
    stays exact — one entry's exception does not become the whole registration's rule.
    """
    client = client_with("http://localhost/callback", "https://app.example/callback")

    assert redirect_uri_allowed("http://localhost:45002/callback", client)
    assert redirect_uri_allowed("https://app.example/callback", client)
    assert not redirect_uri_allowed("https://app.example:8443/callback", client)
    assert not redirect_uri_allowed("http://localhost:45002/other", client)


def test_a_uri_that_cannot_be_parsed_is_not_a_loopback_target() -> None:
    """A malformed URI earns no exception, and is compared as the string it is.

    An unterminated IPv6 literal makes `urlsplit` raise, so the loopback test cannot read
    a host from it; the case falls through to exact equality, which it fails. Nothing
    about an unparseable value should read as loopback.
    """
    client = client_with("http://localhost:8766/callback")

    assert not redirect_uri_allowed("http://[::1/callback", client)
    assert not redirect_uri_allowed("not a uri", client)
    assert not redirect_uri_allowed("//localhost:8766/callback", client)


def test_a_toolset_name_does_not_leak_into_cimd_settings() -> None:
    """A guard against a future edit that reused one shared settings object here."""
    settings = cimd_settings(toolsets={TOOLSET_NAME: {"scopes_supported": ["default"]}})

    assert settings.gateway_cimd_allowed_origins == "https://claude.ai"
    assert settings.gateway_cimd_max_document_bytes == DEFAULT_DOCUMENT_BYTES
    assert settings.gateway_cimd_connect_timeout_seconds == DEFAULT_CONNECT_TIMEOUT
    assert settings.gateway_cimd_total_timeout_seconds == DEFAULT_TOTAL_TIMEOUT


def test_the_default_allowlist_is_the_flagship_harness_origin() -> None:
    assert make_settings().cimd_allowed_origins == ("https://claude.ai",)
