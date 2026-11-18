"""Client ID Metadata Document resolution, and the fetch controls it needs.

A CIMD-capable client registers by presenting a URL as its client id and making no
registration call: the gateway fetches the document at that URL and treats its
`redirect_uris` as the client's registration. The client steers a server-side request, so
the fetch is a request-forgery surface and every control below is load-bearing rather
than defensive decoration:

* HTTPS only, and the origin must be on the operator's allowlist. The allowlist is what
  keeps a hostile client id from turning the gateway into a probe of arbitrary hosts.
* No redirects. A redirect is the pivot an attacker needs: the allowlisted origin passes
  the first check, then hands the connection to wherever it likes. There is no legitimate
  use for one here.
* Every resolved address is checked against private, loopback, and link-local ranges, and
  the connection is made to an address that passed. The check happens on the resolved
  addresses, not on the hostname, and the connection is pinned to the validated address
  with the original host name preserved for TLS and for the `Host` header — so a name
  that answers with a public address for the check and a private one for the connection
  gains nothing.
* The body is capped while it is read, not after: a cap enforced after reading is a cap
  that has already allocated the memory it was meant to bound.
* Connect and total timeouts, a TTL cache, and a bounded cache size, so a slow or
  unreachable origin cannot hold a request open indefinitely and a client id cannot grow
  the gateway's memory without limit.
* A capacity limiter on the offloaded fetch, so the fetches an unauthenticated caller
  steers cannot occupy the whole shared worker pool — the identity and credential legs
  keep capacity beside them. It bounds a caller's *share* of a shared resource, not the
  resource's memory.
* An explicit `User-Agent`. The origin a flagship harness uses is fronted by bot
  protection that rejects library-default agents outright, so a default agent surfaces as
  a late, misleading registration failure instead of a configuration one.

The fetch itself is synchronous, and deliberately so: the connection pinning below is a
property of the socket this code opens, and it is worth more than the shape of the call.
The request path reaches it through `resolve_client_async`, which runs the blocking fetch
on a worker thread so a slow origin — an unauthenticated caller can point one here —
cannot hold the event loop, and with it every other request including `/healthz`.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import anyio
import httpx

from gateway.redirect_uris import (
    ADMISSION_RULE,
    loopback_target,
    scheme_admission_refusal,
)
from gateway.settings import PreRegisteredClient, Settings

# The content type a metadata document must be served as. A document served as anything
# else is not the document asked for, whatever its bytes look like.
_JSON_CONTENT_TYPE = "application/json"

# Hosts that resolve to themselves in every deployment and are therefore never a
# legitimate metadata origin.
_FORBIDDEN_HOSTNAMES = frozenset(
    {"localhost", "localhost.localdomain", "metadata.google.internal"}
)


class CimdError(Exception):
    """A client-metadata document that could not be fetched or accepted.

    Carries a message safe to show a client and to log: it names the reason, never the
    document's content, and never a value that could be a credential.
    """


@dataclass(frozen=True)
class ResolvedClient:
    """A client resolved to the redirect URIs its registration allows."""

    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str | None
    source: str


def _is_forbidden_address(address: str) -> bool:
    """Whether an address is one a metadata fetch must never connect to.

    Loopback, private, link-local (which is where a cloud instance's metadata service
    lives), and the reserved ranges generally: none of them can host a public client
    metadata document, and each is a legitimate target for an attacker who controls the
    URL.
    """
    parsed = ipaddress.ip_address(address)
    return (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def resolve_addresses(host: str, port: int) -> list[str]:
    """Every address a hostname resolves to, checked for forbidden ranges.

    All records are checked, not just the first: a host that answers with one public and
    one private address would otherwise pass or fail depending on which record the
    resolver happens to return first.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        message = f"could not resolve the client-id document host {host!r}"
        raise CimdError(message) from exc

    addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        message = f"the client-id document host {host!r} resolved to no address"
        raise CimdError(message)
    for address in addresses:
        if _is_forbidden_address(address):
            message = (
                f"the client-id document host {host!r} resolves to {address}, which is "
                f"a private, loopback, or otherwise non-public address"
            )
            raise CimdError(message)
    # IPv4 first: a deployment with no IPv6 route would otherwise see every metadata
    # fetch fail on a name that answers on both, and the set is validated either way.
    return sorted(addresses, key=lambda address: ":" in address)


def _validated_url(client_id: str, settings: Settings) -> tuple[str, str, int]:
    """Parse and check a client-id URL, returning its host, origin, and port.

    Every refusal here happens before any network activity: an http URL, an origin that
    is not allowlisted, one that names a loopback host by name, and one that carries
    credentials are all rejected on the string alone.
    """
    parts = urlsplit(client_id)
    if parts.scheme != "https":
        message = "a client-id document must be served over https"
        raise CimdError(message)
    if parts.username or parts.password:
        message = "a client-id document URL must not carry credentials"
        raise CimdError(message)
    if not parts.hostname:
        message = "a client-id document URL must name a host"
        raise CimdError(message)

    origin = f"https://{parts.netloc}"
    if origin not in settings.cimd_allowed_origins:
        message = (
            f"the client-id document origin {origin!r} is not one of the allowed "
            f"origins ({', '.join(settings.cimd_allowed_origins) or 'none configured'})"
        )
        raise CimdError(message)

    if parts.hostname.lower() in _FORBIDDEN_HOSTNAMES:
        message = (
            f"the client-id document host {parts.hostname!r} is never a metadata origin"
        )
        raise CimdError(message)

    return parts.hostname, origin, parts.port or 443


def _fetch_document(client_id: str, settings: Settings) -> dict[str, Any]:
    """Fetch and parse one metadata document under the full control set.

    The request is addressed to an address that passed `resolve_addresses` rather than to
    the hostname, with the host name kept in the `Host` header and in the TLS SNI
    extension. That ordering is the whole control: the name is resolved and checked
    first, and the connection then goes to the checked address — so a name whose answers
    change between the check and the connection has nothing to change, while TLS still
    validates the certificate against the name the client id named.
    """
    host, _origin, port = _validated_url(client_id, settings)
    addresses = resolve_addresses(host, port)
    parts = urlsplit(client_id)
    connection_url = httpx.URL(
        scheme="https",
        host=addresses[0],
        port=port,
        path=parts.path,
        query=parts.query.encode("utf-8"),
    )

    timeout = httpx.Timeout(
        settings.gateway_cimd_total_timeout_seconds,
        connect=settings.gateway_cimd_connect_timeout_seconds,
    )
    headers = {
        # The `Host` header is set explicitly because the request line carries the
        # address: without it, the origin would be asked for a virtual host named by an
        # IP and would answer for the wrong site (or for none).
        "Host": parts.netloc,
        "User-Agent": settings.gateway_cimd_user_agent,
        "Accept": _JSON_CONTENT_TYPE,
    }

    try:
        with (
            httpx.Client(
                timeout=timeout,
                # Redirects are refused rather than followed: a 3xx is a failed fetch, and
                # reading it as one is the difference between a bounded request and an
                # attacker-chosen second request.
                follow_redirects=False,
                # An ambient proxy would route the request through infrastructure this
                # control set did not validate.
                trust_env=False,
            ) as client,
            client.stream(
                "GET",
                connection_url,
                headers=headers,
                # The TLS handshake still names the host, so certificate verification is
                # against the client id's own name, not the address that passed the check.
                extensions={"sni_hostname": host},
            ) as response,
        ):
            if response.is_redirect:
                message = (
                    f"the client-id document at {client_id!r} answered a redirect; "
                    f"a metadata document must be served directly"
                )
                raise CimdError(message)
            if response.status_code != httpx.codes.OK:
                message = (
                    f"the client-id document at {client_id!r} answered "
                    f"{response.status_code}"
                )
                raise CimdError(message)

            content_type = response.headers.get("content-type", "")
            if content_type.split(";")[0].strip().lower() != _JSON_CONTENT_TYPE:
                message = (
                    f"the client-id document at {client_id!r} was served as "
                    f"{content_type.split(';')[0].strip() or 'no content type'}, not "
                    f"{_JSON_CONTENT_TYPE}"
                )
                raise CimdError(message)

            body = _read_capped(
                response, settings.gateway_cimd_max_document_bytes, client_id
            )
    except httpx.HTTPError as exc:
        # The exception type is reported, never its message: an httpx error can echo the
        # URL it failed on, and the URL is the client-supplied value under scrutiny.
        message = (
            f"the client-id document at {client_id!r} could not be fetched "
            f"({type(exc).__name__})"
        )
        raise CimdError(message) from exc
    except ssl.SSLError as exc:
        message = (
            f"the client-id document at {client_id!r} failed certificate verification"
        )
        raise CimdError(message) from exc

    try:
        document = json.loads(body)
    except ValueError as exc:
        message = f"the client-id document at {client_id!r} is not valid JSON"
        raise CimdError(message) from exc
    if not isinstance(document, dict):
        message = f"the client-id document at {client_id!r} is not a JSON object"
        raise CimdError(message)
    return document


def _read_capped(response: httpx.Response, limit: int, client_id: str) -> str:
    """Read a response body up to a byte limit, refusing anything larger."""
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > limit:
            message = (
                f"the client-id document at {client_id!r} is larger than {limit} bytes"
            )
            raise CimdError(message)
        chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", errors="strict")


def _document_client(
    client_id: str,
    document: dict[str, Any],
) -> ResolvedClient:
    """Validate a fetched document's shape into a resolved client.

    `client_id` must be the URL it was fetched from — a document that names a different
    client is not a registration for the URL asked about, and accepting the mismatch
    would let one origin register a client id belonging to another.
    """
    named = document.get("client_id")
    if named != client_id:
        message = (
            f"the client-id document at {client_id!r} declares client_id {named!r}; a "
            f"document must declare the URL it is served from"
        )
        raise CimdError(message)

    redirect_uris = document.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris:
        message = (
            f"the client-id document at {client_id!r} declares no redirect_uris, so no "
            f"authorization request could be validated against it"
        )
        raise CimdError(message)
    for uri in redirect_uris:
        if not isinstance(uri, str):
            message = f"the client-id document at {client_id!r} carries a non-string redirect_uri"
            raise CimdError(message)
        # The admission rule, upstream of the exact-match validation: a document listing a
        # non-loopback plain-`http` entry is refused whole — the same refuse-whole
        # discipline the other document validations use — because client resolution would
        # otherwise serve a registration whose code and echoed state cross a cleartext leg.
        refusal = scheme_admission_refusal(uri)
        if refusal is not None:
            message = (
                f"the client-id document at {client_id!r} lists a redirect_uri this "
                f"gateway cannot admit ({uri!r}): {ADMISSION_RULE}. The document is "
                f"refused as a registration so no authorization request resolves against it"
            )
            raise CimdError(message)

    client_name = document.get("client_name")
    return ResolvedClient(
        client_id=client_id,
        redirect_uris=tuple(redirect_uris),
        client_name=client_name if isinstance(client_name, str) else None,
        source="cimd",
    )


@dataclass
class _CacheEntry:
    client: ResolvedClient
    expires_at: float


class ClientMetadataCache:
    """A TTL- and size-bounded cache of resolved client-metadata documents.

    Both bounds matter for different reasons: the TTL keeps a client's own edit of its
    document from being ignored indefinitely, and the size bound keeps client ids from
    growing the gateway's memory without limit. An entry is dropped, not refreshed, when
    the cache is full of live entries — the fetch that repopulates it is one request.

    It also carries the **capacity limiter** for offloaded fetches (see
    `resolve_async`): one limiter per cache, because there is one cache per process and
    one worker pool behind it.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._entries: dict[str, _CacheEntry] = {}
        # Sized from configuration so an operator can widen or narrow the share of the
        # pool that attacker-chosen fetches may hold.
        self._fetch_limiter = anyio.CapacityLimiter(
            settings.gateway_cimd_max_concurrent_fetches
        )

    def resolve(self, client_id: str) -> ResolvedClient:
        """Resolve a URL-shaped client id, fetching its document when not cached."""
        cached = self._cached(client_id)
        if cached is not None:
            return cached

        client = _document_client(client_id, _fetch_document(client_id, self._settings))
        self._store(client_id, client, time.monotonic())
        return client

    async def resolve_async(self, client_id: str) -> ResolvedClient:
        """Resolve a client id for a caller on the event loop.

        The fetch is the blocking part — DNS resolution, the TLS handshake, and the capped
        body read — so it runs on a worker thread. Everything that touches this cache's
        memory stays on the event loop and on one thread: the lookup before the fetch and
        the store after it, which is what makes the map safe to share without a lock, and
        keeps the decision to fetch a single one rather than a race between two threads.

        A fetch for the same client id that two requests started concurrently is fetched
        twice and stored twice; the second store wins and both callers get the same
        document, so the cost is a duplicate request rather than a wrong answer.

        The fetch runs under this cache's capacity limiter, and that bound is a
        *fairness* control rather than a memory one. The worker pool is shared with the
        flow's identity and credential legs, and this is the one slow leg whose target an
        unauthenticated caller picks: without the limiter, requests naming slow origins
        could occupy every worker and hold the legs that a real sign-in needs. With it, an
        attacker's fetches can hold at most the limiter's share of the pool, and a
        legitimate leg has capacity beside them. What remains is waiting behind
        attacker-shaped slow requests within the rate limits — the disclosed residual of
        any bounded shared resource — and a caller that waits is bounded in turn by the
        public-endpoint rate limits rather than by the pool.
        """
        cached = self._cached(client_id)
        if cached is not None:
            return cached

        async with self._fetch_limiter:
            document = await anyio.to_thread.run_sync(
                functools.partial(_fetch_document, client_id, self._settings)
            )
        client = _document_client(client_id, document)
        self._store(client_id, client, time.monotonic())
        return client

    def _cached(self, client_id: str) -> ResolvedClient | None:
        """The live cached client for an id, or `None` when it must be fetched."""
        entry = self._entries.get(client_id)
        if entry is not None and entry.expires_at > time.monotonic():
            return entry.client
        return None

    @property
    def entries(self) -> int:
        """How many documents are cached, so a bound can be observed rather than assumed."""
        return len(self._entries)

    @property
    def max_concurrent_fetches(self) -> float:
        """How many fetches this cache's limiter allows at once, for observability.

        A bound that can only be asserted through timing is a bound a test cannot measure
        directly, so the configured share of the pool is readable here.
        """
        return self._fetch_limiter.total_tokens

    def _store(self, client_id: str, client: ResolvedClient, now: float) -> None:
        if len(self._entries) >= self._settings.gateway_cimd_cache_max_entries:
            self._evict(now)
        self._entries[client_id] = _CacheEntry(
            client=client,
            expires_at=now + self._settings.gateway_cimd_cache_ttl_seconds,
        )

    def _evict(self, now: float) -> None:
        expired = [
            key for key, entry in self._entries.items() if entry.expires_at <= now
        ]
        if expired:
            for key in expired:
                del self._entries[key]
            return
        # Nothing has expired, so the oldest entry goes: the cache is bounded, not the
        # number of clients that may exist.
        oldest = min(self._entries, key=lambda key: self._entries[key].expires_at)
        del self._entries[oldest]


def is_url_shaped_client_id(client_id: str) -> bool:
    """Whether a client id names a document rather than an opaque registered id.

    A URL-shaped id is the CIMD path; anything else is looked up among the
    pre-registered ids. The test is deliberately structural — scheme and host — so a
    client id that merely contains a dot is not mistaken for a URL.
    """
    parts = urlsplit(client_id)
    return bool(parts.scheme and parts.netloc)


def _resolve_without_fetch(client_id: str, settings: Settings) -> ResolvedClient | None:
    """The resolution rungs that need no fetch, or `None` when a fetch is required.

    Pre-registered first: the operator's own list, with no fetch and no registration call.
    An id that is not URL-shaped and is not on that list has no path left to resolve by, so
    it is refused here. A URL-shaped id is the one case that needs a document fetch, and it
    is the value that returns `None` — shared by the synchronous and the offloaded async
    entry points, so both orders are the same order.
    """
    pre_registered = settings.pre_registered_clients.get(client_id)
    if pre_registered is not None:
        return _pre_registered_client(client_id, pre_registered)

    if not is_url_shaped_client_id(client_id):
        # The message is fixed text: the client id itself is caller-supplied, and a
        # refusal that echoes it would be a reflection surface on an unauthenticated path.
        message = (
            "this client id is not registered with the gateway: it is neither a "
            "pre-registered client nor a client-id metadata document URL"
        )
        raise CimdError(message)
    return None


def resolve_client(
    client_id: str,
    settings: Settings,
    cache: ClientMetadataCache,
) -> ResolvedClient:
    """Resolve a client id through the whole priority order.

    Pre-registered first (the operator's own list, with no fetch and no registration
    call), then a client-metadata document, then — from the caller — the dynamic
    registration store. Dynamic registration is tried last because it is the config-gated
    fallback: a client id that resolves by either of the first two paths must never
    depend on open registration being enabled.
    """
    without_fetch = _resolve_without_fetch(client_id, settings)
    if without_fetch is not None:
        return without_fetch
    return cache.resolve(client_id)


async def resolve_client_async(
    client_id: str,
    settings: Settings,
    cache: ClientMetadataCache,
) -> ResolvedClient:
    """Resolve a client id through the whole priority order, for a caller on the loop.

    The same order as `resolve_client`, with one difference that is the reason this exists:
    the CIMD fetch happens on a worker thread, so a slow metadata origin stalls this
    request alone rather than the event loop every other request shares. The two
    pre-fetch rungs are pure lookups and stay on the loop, so a client id that resolves
    without a fetch never leaves it.
    """
    without_fetch = _resolve_without_fetch(client_id, settings)
    if without_fetch is not None:
        return without_fetch
    return await cache.resolve_async(client_id)


def _pre_registered_client(
    client_id: str, record: PreRegisteredClient
) -> ResolvedClient:
    return ResolvedClient(
        client_id=client_id,
        redirect_uris=tuple(record.redirect_uris),
        client_name=record.client_name,
        source="pre_registered",
    )


# The loopback rule lives in `gateway.redirect_uris` — `loopback_target` — beside the
# scheme admission rule, so the four admission sites and this matching code read one copy
# and cannot drift.


def redirect_uri_allowed(redirect_uri: str, client: ResolvedClient) -> bool:
    """Whether a redirect URI is one the client's registration allows.

    Exact string comparison, with one exception and no normalizations besides it: a
    redirect URI is a security boundary, so folding case, a trailing slash, or a query is
    a rule the specification this implements does not have.

    The exception is the loopback-port rule (RFC 8252 §7.3/§8.4): a **registered** entry
    that is a loopback `http` URI matches a request that has its scheme, host, and path
    and any port. Both sides are spelled out in `loopback_target`, including that only
    the port is excepted. It is keyed on the registered entry — the client's own fetched
    or configured value — so a request cannot self-declare loopback against a
    registration that named a real host. Every other registered entry keeps exact
    equality, `https` on a loopback host included.
    """
    if redirect_uri in client.redirect_uris:
        return True

    request_target = loopback_target(redirect_uri)
    if request_target is None:
        return False
    # A registered entry that is not loopback `http` yields `None` here and can never
    # equal the request's target, so the exception stays keyed on the registration.
    return any(
        loopback_target(registered) == request_target
        for registered in client.redirect_uris
    )
