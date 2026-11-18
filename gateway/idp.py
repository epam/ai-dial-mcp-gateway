"""The identity-provider leg: the redirect out, and the code exchange back.

The gateway authenticates the human under its own pre-registered client, so the identity
every later step runs as is one the deployment's own identity provider issued — the
gateway never asserts an identity it did not just see authenticated.

The leg has **one endpoint source**, chosen by configuration and never by a runtime
event: either the provider's OpenID Connect discovery document, fetched at the configured
issuer with `/.well-known/openid-configuration` appended, or — where the operator
configured the endpoint trio directly — the operator's three settings alone. No endpoint
the leg uses is ever built by provider-specific URL arithmetic, and a failed discovery
has nothing to fall back to: it fails the leg closed. The direct set replaces discovery
whole, never member-by-member, so at every moment the leg's endpoints come from exactly
one source.

Two of the three endpoints are deliberately addressed differently from how they are
read:

* The **authorization** endpoint is the browser-facing one, kept exactly as its source
  spells it, because the value has to be reachable from the user's browser.
* The **token** endpoint and the **key-set URI** are reached over the back channel: the
  configured back-channel base's origin when the deployment sets one — scheme and host
  swapped, the source's own path kept — and the source's own origin otherwise. A token's
  `iss` is the issuer whichever base the token endpoint was reached on, so the exchange
  is unaffected by the split.

The exchanged token is verified, not merely decoded: it is checked against the provider's
own published keys by `kid`, and its issuer must be the configured one. Taking the
payload on trust because the response arrived over TLS would make the gateway's entire
claim copy rest on transport alone, and the copied `sub` is what Core authorizes with.

The provider's session-bound refresh token is captured at the exchange and carried past
the flow (its custody is `gateway/custody.py`'s — encrypted in the gateway's own refresh
token, never on any client-visible artifact, never logged). No `offline_access` grant is
requested: what is captured is the ordinary, session-bound refresh token the exchange
already issues, a rotating handle to the user's live session rather than a beyond-session
grant. The provider's access token lives only as long as the flow that needed it — the
same reason the flow record carries a TTL.

The **refresh grant** completes the same leg in the other direction: at each gateway
refresh, `refresh_identity` presents the carried provider refresh token to the same
token endpoint the exchange uses (RFC 6749 §6), and the fresh token the grant returns is
verified through the same `_verified_claims` path — one claim vocabulary, one verification
path, at issuance and at refresh alike.

The leg's client is a **confidential client** at the provider: the code exchange and the
refresh grant authenticate with the configured client secret on every token request, in
both positions of the PKCE toggle — the modes are client secret plus PKCE, or client
secret alone, never PKCE alone. On top of that authentication the redirect may carry an
S256 challenge, which is the toggle's only job: on (the default) the redirect carries
the challenge and the exchange presents the verifier, composing the challenge binding
with the client authentication; off, for a provider that cannot support PKCE, the token
requests carry the client authentication alone. The toggle touches nothing else.
"""

from __future__ import annotations

import functools
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit

import anyio
import httpx
import jwt
from jwt import exceptions as jwt_exceptions

from gateway.settings import Settings

# The discovery document's well-known path, joined to the configured issuer. This is
# the suffix-appended OIDC spelling the target providers serve, not the RFC 8414
# host-inserted one. The join is explicit, and the separator is added here — the one
# place the issuer is used as an address — because the issuer's configured spelling is
# the pin the discovery document and every token are compared against and is never
# rewritten to make a path join come out right.
_DISCOVERY_PATH = "/.well-known/openid-configuration"

# The discovery members the leg consumes. The document is read for these three and
# nothing else: an endpoint the leg never uses is never taken from the document either.
_AUTHORIZATION_ENDPOINT_MEMBER = "authorization_endpoint"
_TOKEN_ENDPOINT_MEMBER = "token_endpoint"  # noqa: S105  # nosec B105 - a discovery member name, not a credential
_KEY_SET_MEMBER = "jwks_uri"

# The cap on a discovery document's body, in bytes. The document steers calls that carry
# credential material, so a hostile provider answer is refused before it is parsed whole.
_DISCOVERY_MAX_BYTES = 65_536

# The cap on a token-endpoint answer's body and on the published key set's, in bytes.
# Both are small JSON documents steering or carrying credential material, and both are
# now answered by external providers the deployment does not operate; a bound at
# reading is what keeps a hostile provider answer from being buffered whole before it
# is refused.
_RESPONSE_MAX_BYTES = 65_536

# The only algorithm the provider's asymmetric key is used with here.
_SIGNING_ALGORITHM = "RS256"

# The response type and grants this leg performs. Both are fixed: the flow signs a human in
# and gets one code back, and the refresh grant exchanges the carried session refresh token
# for a fresh token. There is nothing else the flow could ask for.
_RESPONSE_TYPE = "code"
_AUTHORIZATION_CODE_GRANT = "authorization_code"
_REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105  # nosec B105 - the RFC 6749 grant name

# The challenge method the identity leg's redirect carries in the default PKCE mode. The
# `plain` method would put the verifier itself on the wire, so the leg has no mode that
# uses it.
_CODE_CHALLENGE_METHOD = "S256"

# The form content type a token request is sent as.
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

# The provider's OAuth error code for a refresh grant whose session is gone — revoked,
# expired by session policy, or consumed by a lost rotation (RFC 6749 §6). It is the one
# code that says the *session* ended rather than that the gateway's request was wrong, and
# the refresh grant audits it apart from every other failure.
_SESSION_GONE_ERROR = "invalid_grant"


def _monotonic_now() -> float:
    """The discovery cache's clock, in a function so a test can move it."""
    return time.monotonic()


def _origin_of(url: str) -> tuple[str, str]:
    """A URL's origin as its scheme and host, lowercased for the comparison."""
    parts = urlsplit(url)
    return (parts.scheme.lower(), parts.netloc.lower())


class _OversizeError(Exception):
    """A response body crossed its size cap while being read, so it is refused whole."""


def _read_capped(response: httpx.Response, limit: int) -> bytes:
    """Read a streamed response body up to `limit` bytes, refusing anything larger.

    The cap is enforced while reading, in the discipline the CIMD fetch established: the
    read stops the moment the body crosses the limit and the connection is abandoned,
    so the limit bounds what a server can make the gateway buffer, not merely what it
    later parses.
    """
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_bytes():
        total += len(chunk)
        if total > limit:
            raise _OversizeError
        chunks.append(chunk)
    return b"".join(chunks)


def backchannel_addressed(url: str, settings: Settings) -> str:
    """The URL a back-channel call is addressed to.

    The configured override's origin — scheme and host swapped, the URL's own path (and
    query) kept — when the deployment sets one, and the URL unchanged otherwise. The
    override can only re-address the provider's own paths, never invent one.
    """
    override = settings.idp_backchannel_base_url
    if not override:
        return url
    base = urlsplit(override)
    parts = urlsplit(url)
    return urlunsplit((base.scheme, base.netloc, parts.path, parts.query, ""))


@dataclass(frozen=True)
class Endpoints:
    """The identity leg's three endpoints, resolved from its one configured source.

    `authorization_endpoint` is the browser-facing one, kept at its source's own
    spelling; the token endpoint and the key-set URI are the server-to-server pair, so
    the back-channel override's origin is applied to them where one is configured.
    """

    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


class IdentityProviderError(Exception):
    """The identity-provider leg could not complete.

    The message is fixed text safe to show a browser and to log: it names the step, never
    the code, the token, or the verifier the step carried. `status_code` distinguishes the
    two audiences: a refusal the user can retry (the provider declined the sign-in) from a
    provider that answered in a way this gateway cannot use, which is a deployment-side
    fault the operator reads about in the log.
    """

    # The status a leg failure is answered with unless the caller names another. A leg that
    # failed at the provider is a failed sign-in the user can retry, which is a 4xx: nothing
    # about the gateway is broken, and a 5xx would read as a gateway fault in every metric
    # and dashboard the deployment has.
    DEFAULT_STATUS = 400

    def __init__(self, message: str, *, status_code: int = DEFAULT_STATUS) -> None:
        super().__init__(message)
        self.status_code = status_code


class RefreshGrantError(IdentityProviderError):
    """A refresh grant that could not produce a fresh token.

    Carries the one distinction the refresh grant audits apart: whether the *session* is
    gone. `session_ended` is true only when the provider refused the grant with the OAuth
    error code `invalid_grant` — RFC 6749 §6's session-gone code, meaning the session was
    revoked, expired by session policy, or consumed by a lost rotation. Every other failure
    — transport, 5xx, a non-JSON or oversized answer, a missing token, or any other provider
    4xx such as `invalid_client` from a misconfigured secret — is false: it says nothing
    about the session, so it must not read as mass revocation on the audit trail.
    """

    def __init__(
        self,
        message: str,
        *,
        session_ended: bool = False,
        status_code: int = IdentityProviderError.DEFAULT_STATUS,
    ) -> None:
        super().__init__(message, status_code=status_code)
        self.session_ended = session_ended


@dataclass(frozen=True)
class Identity:
    """What a completed identity-provider leg establishes.

    `access_token` is the credential the flow holds, and it serves the sign-in flow and
    nothing else: the flow's one decision step — "may this user sign in to this toolset,
    and are they already signed in?" — and its one action, the credential call, after which
    the flow discards it. The decision step takes one or two presentations depending on
    whether the deployment's Core enriches its settings route with the per-caller statuses,
    so the use is stated in purposes rather than counts: the count is a property of the
    deployment's Core, not of the flow.

    `refresh_token` is the provider's *session-bound* refresh token, captured at the
    exchange and never requested as a beyond-session (`offline_access`) grant. It is
    credential material: it must never be logged, and its only destinations are the pending
    hand-off entry (server state) and, encrypted, the gateway's own refresh token.
    """

    claims: dict[str, object]
    # Both tokens are credential material, so neither has a `repr`: a dataclass's default
    # repr would print them into a debug dump or a traceback, which is the one place
    # credential material must never land. `repr=False` states that where the field is
    # declared rather than leaving it to every call site to remember.
    access_token: str = field(repr=False)
    refresh_token: str | None = field(default=None, repr=False)


class IdentityProviderClient:
    """The configured identity provider's endpoints, as the gateway uses them.

    The endpoint set is resolved from the one configured source — the operator's direct
    trio where set, the discovery document otherwise — lazily on first use and cached per
    client (a gateway process builds one client) for the configured TTL. Resolution never
    constructs an endpoint from the issuer's spelling: where no source yields one, the leg
    fails.
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        # The discovered endpoints and the monotonic instant they were fetched at. The
        # lock serialises the fetch-and-fill so concurrent legs share one fetch rather
        # than racing to fill the same cache entry.
        self._lock = threading.Lock()
        self._discovered: Endpoints | None = None
        self._discovered_at = 0.0
        # The last failed or refused fetch — the fixed-vocabulary refusal it raised and
        # the monotonic instant it was recorded at — is the cache's negative half: a
        # fetch that fills nothing would otherwise leave every leg paying its own fetch
        # attempt for as long as the provider is down, and the one-fetch-per-window
        # bound the cache exists to enforce would hold only while the provider answers.
        self._failure: tuple[str, int] | None = None
        self._failed_at = 0.0

    @property
    def issuer(self) -> str:
        return self._settings.idp_issuer

    @property
    def client_id(self) -> str:
        return self._settings.idp_client_id

    @property
    def scopes(self) -> str:
        """The client's own default scopes, as one space-separated string.

        These are the only scopes either leg requests. They come from configuration and
        from nowhere else: a client-supplied scope relayed onto this leg would fail it on
        any scope the gateway's own client does not carry.
        """
        return " ".join(
            scope.strip()
            for scope in self._settings.idp_client_scopes.split(",")
            if scope.strip()
        )

    @property
    def redirect_uri(self) -> str:
        """The callback this client is registered for, at the gateway's public origin."""
        return (
            f"{self._settings.gateway_public_origin}{self._settings.idp_callback_path}"
        )

    async def authorization_url(self, *, state: str, code_challenge: str) -> str:
        """The browser-facing authorization URL for this client.

        The endpoint is the resolved set's — the discovered document's, or the operator's
        directly configured one — and `scope` is always the client's own set and
        `response_type` always `code`: there is no parameter here a request could steer,
        which is what keeps a client's own `scope` parameter from ever reaching this leg.

        The redirect carries the challenge only when the PKCE toggle is on. The caller
        always derives one — the flow's one shape of this call — and the leg's
        configuration decides whether the redirect carries it, because the configuration
        is this client's, not the caller's: for a provider that cannot support PKCE no
        challenge is sent at all, and the client secret — which authenticates every
        token request in either position — is the leg's only binding on the code.

        Asynchronous because the first use of the leg resolves the endpoint set, and in
        discovery mode that resolution fetches — a network call that runs on a worker
        thread, like every outbound call this leg makes.
        """
        endpoints = await self._endpoints()
        query: dict[str, str] = {
            "response_type": _RESPONSE_TYPE,
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scopes,
            "state": state,
        }
        if self._settings.idp_pkce_enabled:
            query["code_challenge"] = code_challenge
            query["code_challenge_method"] = _CODE_CHALLENGE_METHOD
        return f"{endpoints.authorization_endpoint}?{urlencode(query)}"

    async def exchange_code(self, *, code: str, code_verifier: str) -> Identity:
        """Exchange the callback's code for the user's identity.

        The response is verified against the provider's own published keys before anything
        is read from it: the payload becomes the claim set every minted token is copied
        from, so trusting it unverified would put the whole copy behind transport alone.

        The provider's session refresh token is captured here too. Two refusals guard it,
        and both fail the flow **at sign-in** — the one moment the cause is diagnosable —
        rather than hours later at the first refresh: an exchange that issues no refresh
        token at all (a provider that does not issue them to this client), and a token
        larger than the configured size bound (the carrier it must fit inside is a refresh
        token handed to a harness token store this gateway does not control).

        Asynchronous at the seam, synchronous in the call: the provider's token endpoint and
        its key set are both reached by blocking requests, and each runs on a worker thread
        so a slow provider cannot hold the event loop this callback's browser shares with
        every other request.
        """
        response = await anyio.to_thread.run_sync(
            functools.partial(self._post_token, code=code, code_verifier=code_verifier)
        )

        if response.status_code != httpx.codes.OK:
            message = (
                f"the identity provider refused the code exchange "
                f"({response.status_code}); the sign-in has to be started again"
            )
            # A 5xx from the provider is the provider failing, not the sign-in being
            # declined — the user's retry may well work, but the operator should see it.
            provider_error = response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR
            raise IdentityProviderError(
                message, status_code=502 if provider_error else 400
            )

        document = _response_document(response)
        access_token = _access_token_of(document)
        claims = await self.verified_claims(access_token)
        if not claims.get("sub"):
            message = "the identity token carries no subject"
            raise IdentityProviderError(message)
        refresh_token = _captured_refresh_token(document, self._settings)
        return Identity(
            claims=claims, access_token=access_token, refresh_token=refresh_token
        )

    async def refresh_identity(
        self, provider_refresh_token: str
    ) -> tuple[str, str | None]:
        """Run the provider's refresh grant (RFC 6749 §6) and return the fresh token.

        The grant is posted to the *same* token-endpoint URL the exchange uses — the
        resolved endpoint set's, one spelling and no construction per call — and the URL
        never comes from any request. The client authentication is the confidential
        client's secret on every grant (`_client_authentication`), the outbound timeout
        is the configured one, redirects are not followed, and the response is parsed
        under a size cap with a JSON object required, so a hostile provider answer is
        refused before any claim is read.

        The fresh access token is returned **unverified**, together with the response's own
        new refresh token when it carries one (latest-wins: where the provider rotates its
        refresh token per grant, that one supersedes the carried token; where it does not,
        the caller keeps what it held). Verification runs through `_verified_claims` at the
        caller, so issuance and refresh share one vocabulary and one verification path.

        The second return value is `None` when the response carries no new refresh token, so
        the caller knows to keep the one it presented. A provider refusal carrying the OAuth
        error `invalid_grant` raises with `session_ended` set; every other failure —
        transport, 5xx, non-JSON, oversize, no token, or another 4xx like `invalid_client`
        — raises without it.
        """
        response = await anyio.to_thread.run_sync(
            functools.partial(
                self._post_refresh, provider_refresh_token=provider_refresh_token
            )
        )

        document = _refresh_response_document(response)
        return _access_token_of(document), _optional_refresh_token(document)

    # ------------------------------------------------------------- endpoint resolution

    async def _endpoints(self) -> Endpoints:
        """The resolved endpoint set, fetching discovery on a worker thread when stale.

        Direct mode and a fresh cache answer without a thread hop — both are known
        without any network call — and only a stale or empty cache pays for one. The
        fast path reads the cache without ever waiting on its lock: the fetch that
        fills it holds that lock for its whole duration, and a wait on it would run on
        the event loop, stalling every other request — the health probe included —
        behind one provider's slowness. A contended lock means a fetch is already in
        flight, so there is nothing to read yet anyway; the caller falls through to the
        worker-thread hop and waits there, where every outbound wait belongs.
        """
        without_fetch = self._resolved_without_fetch()
        if without_fetch is not None:
            return without_fetch
        return await anyio.to_thread.run_sync(self._resolved_endpoints)

    def _resolved_endpoints(self) -> Endpoints:
        """The endpoint set from the leg's one configured source.

        The one resolution both modes meet at. Synchronous and blocking, because this is
        the call a worker thread runs: in discovery mode it may fetch the document.
        """
        configured = self._configured_endpoints()
        if configured is not None:
            return _with_backchannel_applied(configured, self._settings)
        return _with_backchannel_applied(self._discovered_endpoints(), self._settings)

    def _resolved_without_fetch(self) -> Endpoints | None:
        """The endpoint set when no fetch is needed to know it, else `None`.

        Direct mode needs no fetch ever — that is the mode's defining property — and a
        cache entry still inside the TTL needs none either. The cache read takes the
        lock without waiting: the fetch thread holds this same lock for the whole
        network fetch, and acquiring it blocking-style here would park the event loop
        on that fetch for up to the outbound timeout. Contended, the lock answers
        immediately and the caller falls through to the worker-thread hop — the fetch
        is in flight, so there is nothing to read yet anyway.
        """
        configured = self._configured_endpoints()
        if configured is not None:
            return _with_backchannel_applied(configured, self._settings)
        if self._lock.acquire(blocking=False):
            try:
                cached = self._discovered
                if cached is not None and self._cache_is_fresh():
                    return _with_backchannel_applied(cached, self._settings)
            finally:
                self._lock.release()
        return None

    def _configured_endpoints(self) -> Endpoints | None:
        """The operator's directly configured trio, or `None` in discovery mode.

        All-or-nothing is enforced at startup — a partial set never reaches this client —
        so this check only separates "no member set" (discovery mode) from the full trio.
        Where the trio is set, no discovery fetch is attempted at all: the mode is chosen
        by configuration, never by a runtime event.
        """
        settings = self._settings
        if (
            settings.idp_authorization_endpoint is None
            or settings.idp_token_endpoint is None
            or settings.idp_jwks_uri is None
        ):
            return None
        return Endpoints(
            authorization_endpoint=settings.idp_authorization_endpoint,
            token_endpoint=settings.idp_token_endpoint,
            jwks_uri=settings.idp_jwks_uri,
        )

    def _discovered_endpoints(self) -> Endpoints:
        """The discovery document's endpoints, from the cache or a fresh fetch.

        The cache is checked and filled under the lock, so legs arriving together share
        one fetch instead of racing to fill the same entry; the TTL is the documented
        bound on how long a provider's endpoint change goes unnoticed. A fetch that
        fails or a document that is refused is recorded for the same window and served
        from it — the same fixed-vocabulary refusal, raised again without a new fetch —
        so an outage costs at most one fetch attempt per window per process however
        many sign-ins arrive, and the first leg after the window retries the provider.
        """
        with self._lock:
            cached = self._discovered
            if cached is not None and self._cache_is_fresh():
                return cached
            failure = self._failure
            if failure is not None and self._failure_is_fresh():
                # The recorded refusal is re-raised as a fresh instance: an exception's
                # traceback grows with every re-raise, and the leg's failures carry no
                # state beyond their fixed text and status anyway.
                raise IdentityProviderError(failure[0], status_code=failure[1])
            try:
                document = _fetch_discovery_document(self._settings)
                endpoints = _validated_endpoints(document, self._settings)
            except IdentityProviderError as exc:
                self._failure = (str(exc), exc.status_code)
                self._failed_at = _monotonic_now()
                raise
            self._discovered = endpoints
            self._discovered_at = _monotonic_now()
            # A success ends the failure's window: the provider answered, so the next
            # staleness is the success cache's, not this record's.
            self._failure = None
            return endpoints

    def _cache_is_fresh(self) -> bool:
        """Whether the cached entry exists and is still inside the configured TTL."""
        cached = self._discovered
        if cached is None:
            return False
        age = _monotonic_now() - self._discovered_at
        return age < self._settings.idp_discovery_cache_ttl_seconds

    def _failure_is_fresh(self) -> bool:
        """Whether a recorded failure is still inside the window it is served for.

        The window is the same TTL the successful entry carries: the documented bound
        on how long the leg runs on what it last learned, in either direction.
        """
        age = _monotonic_now() - self._failed_at
        return age < self._settings.idp_discovery_cache_ttl_seconds

    # ------------------------------------------------------------- the legs themselves

    def _client_authentication(self) -> dict[str, str]:
        """The client authentication every token request on this leg carries.

        The gateway's client is confidential at the provider: both token requests — the
        exchange and the refresh grant — authenticate with the configured secret, in the
        POST body (the form-credential spelling this client's token requests already
        use), whatever the PKCE toggle's position. The toggle governs the challenge only
        (`authorization_url`), never this: client authentication is not
        mode-conditional, and the startup refusal (`_require_client_secret`) guarantees
        the secret exists and is not blank.
        """
        secret = self._settings.idp_client_secret
        return {"client_secret": secret.get_secret_value()}

    def _post_refresh(self, *, provider_refresh_token: str) -> httpx.Response:
        """Send the refresh grant, translating a transport failure into a refusal.

        Blocking by construction: this is the request a worker thread runs. The answer is
        read under a cap enforced while reading (`_read_capped`), so the cap bounds what
        a hostile provider can make the gateway buffer: a body that crosses it is refused
        and the connection abandoned mid-read, and no claim is ever read from an
        over-large document.
        """
        settings = self._settings
        form: dict[str, str] = {
            "grant_type": _REFRESH_TOKEN_GRANT,
            "refresh_token": provider_refresh_token,
            "client_id": self.client_id,
        }
        form.update(self._client_authentication())

        try:
            with httpx.stream(
                "POST",
                self._resolved_endpoints().token_endpoint,
                content=urlencode(form).encode(),
                headers={
                    "Content-Type": _FORM_CONTENT_TYPE,
                    "Accept": "application/json",
                },
                timeout=settings.gateway_outbound_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as response:
                status = response.status_code
                body = _read_capped(response, _RESPONSE_MAX_BYTES)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # The exception type is reported, never its message: an httpx error can echo
            # the request it failed on, and that request carried the refresh token. The
            # URL-parse error class is caught beside the transport errors because it is
            # not one of them — a resolved endpoint the HTTP client cannot address must
            # fail the grant with the same fixed vocabulary as any other transport
            # failure.
            message = (
                f"the identity provider's token endpoint could not be reached "
                f"({type(exc).__name__})"
            )
            raise RefreshGrantError(message, status_code=502) from exc
        except _OversizeError:
            message = (
                "the identity provider's refresh answer is larger than this gateway "
                "accepts"
            )
            raise RefreshGrantError(message) from None
        # The buffered answer is returned in the response shape the shared document
        # readers take: the status and the capped body are all of it any caller reads.
        return httpx.Response(status, content=body)

    def _post_token(self, *, code: str, code_verifier: str) -> httpx.Response:
        """Send the code exchange, translating a transport failure into a refusal.

        Blocking by construction: this is the request a worker thread runs, and it is
        kept as the synchronous call the provider's endpoint has always been reached
        with. The endpoint is the resolved set's token endpoint — the same one the
        refresh grant posts to — so the resolution (and, on first use, the discovery
        fetch) happens here too, off the event loop. The answer is read under a cap
        enforced while reading, the same discipline the refresh grant and the discovery
        fetch obey: this leg serves external providers the deployment does not operate,
        and a body that crosses the cap is refused and the connection abandoned
        mid-read, so the cap bounds what a hostile provider can make the gateway
        buffer. The client authentication is the confidential client's secret on every
        request (`_client_authentication`); the verifier is presented only where a
        challenge was issued — the toggle-on mode.
        """
        settings = self._settings
        form: dict[str, str] = {
            "grant_type": _AUTHORIZATION_CODE_GRANT,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }
        # The verifier is presented only where a challenge was issued — the toggle-on
        # mode. The challenge-off mode sends no challenge on the redirect, so it has no
        # verifier to present; the client secret authenticates both modes' requests
        # (`_client_authentication`).
        if self._settings.idp_pkce_enabled:
            form["code_verifier"] = code_verifier
        form.update(self._client_authentication())

        try:
            with httpx.stream(
                "POST",
                self._resolved_endpoints().token_endpoint,
                content=urlencode(form).encode(),
                headers={
                    "Content-Type": _FORM_CONTENT_TYPE,
                    "Accept": "application/json",
                },
                timeout=settings.gateway_outbound_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as response:
                status = response.status_code
                body = _read_capped(response, _RESPONSE_MAX_BYTES)
        except (httpx.HTTPError, httpx.InvalidURL) as exc:
            # The exception type is reported, never its message: an httpx error can echo
            # the request it failed on, and that request carried the code. A provider that
            # cannot be reached is a gateway-side fault rather than a failed sign-in. The
            # URL-parse error class is caught beside the transport errors because it is
            # not one of them — a resolved endpoint the HTTP client cannot address must
            # fail the leg with the same fixed vocabulary as any other unreachable
            # provider, never as an unhandled error.
            message = (
                f"the identity provider's token endpoint could not be reached "
                f"({type(exc).__name__})"
            )
            raise IdentityProviderError(message, status_code=502) from exc
        except _OversizeError:
            message = (
                "the identity provider's token response is larger than this gateway "
                "accepts"
            )
            raise IdentityProviderError(message) from None
        # The buffered answer is returned in the response shape the shared document
        # readers take: the status and the capped body are all of it any caller reads.
        return httpx.Response(status, content=body)

    async def verified_claims(self, access_token: str) -> dict[str, object]:
        """Verify a token against the provider's published keys, then read its claims.

        Public rather than private because the refresh grant verifies the fresh token the
        provider returns through exactly this path: issuance and refresh share one
        verification path, so a claim set is read and trusted identically at both sites.
        The issuer check is exact-string against the configured issuer — a token naming
        any other issuer, another sign-in journey's included, is refused here.
        """
        try:
            header = jwt.get_unverified_header(access_token)
        except jwt_exceptions.InvalidTokenError as exc:
            message = "the identity token is not a readable JWT"
            raise IdentityProviderError(message) from exc

        key = await self._signing_key(str(header.get("kid", "")))
        try:
            claims: dict[str, object] = jwt.decode(
                access_token,
                key,
                algorithms=[_SIGNING_ALGORITHM],
                issuer=self.issuer,
                # The provider mints this token for its own clients, and its audience is
                # the client that requested it rather than this service; the issuer check
                # and the signature are what establish the token's origin here.
                options={"verify_aud": False},
            )
        except jwt_exceptions.ExpiredSignatureError as exc:
            message = "the identity token has already expired; start the sign-in again"
            raise IdentityProviderError(message) from exc
        except jwt_exceptions.InvalidTokenError as exc:
            message = "the identity token could not be verified"
            raise IdentityProviderError(message) from exc
        return claims

    async def _signing_key(self, kid: str) -> Any:
        """The provider's public key for a `kid`, fetched from its own JWKS.

        The fetch runs on a worker thread, like the token exchange: it is a network call
        the event loop must not make itself, and it happens once per failed key lookup
        rather than once per request, so the thread-hop costs nothing it is not paying
        for. The key set's URL is the resolved set's — the discovery document's or the
        operator's configured one — never a URL built from the issuer.
        """
        response = await anyio.to_thread.run_sync(self._key_set_response)
        if response.status_code != httpx.codes.OK:
            message = f"the identity provider's key set answered {response.status_code}"
            raise IdentityProviderError(message)

        try:
            keys = response.json().get("keys", [])
        except ValueError as exc:
            message = "the identity provider's key set is not valid JSON"
            raise IdentityProviderError(message) from exc

        for document in keys:
            if not isinstance(document, dict):
                continue
            if kid and document.get("kid") != kid:
                continue
            if document.get("kty") != "RSA":
                continue
            if document.get("use") not in (None, "sig"):
                continue
            try:
                return jwt.algorithms.RSAAlgorithm.from_jwk(document)
            except (jwt_exceptions.InvalidKeyError, ValueError) as exc:
                message = "the identity provider published an unreadable signing key"
                raise IdentityProviderError(message) from exc

        message = (
            "the identity provider published no signing key matching the identity "
            "token's key id; the token was not issued by this provider"
        )
        raise IdentityProviderError(message)

    def _key_set_response(self) -> httpx.Response:
        """Fetch the resolved key set; the blocking call a worker thread runs.

        The resolution (and, on first use, the discovery fetch) happens on the same
        thread, so the event loop never waits on the provider.
        """
        return _fetch_key_set(self._settings, self._resolved_endpoints().jwks_uri)


def _with_backchannel_applied(raw: Endpoints, settings: Settings) -> Endpoints:
    """The browser-facing endpoint kept, the server-to-server pair re-addressed.

    The one mapping both endpoint sources go through: the authorization endpoint stays at
    its source's own spelling (the browser must reach it), while the token endpoint and
    the key-set URI are addressed to the back-channel base's origin where one is
    configured — scheme and host swapped, path kept.
    """
    return Endpoints(
        authorization_endpoint=raw.authorization_endpoint,
        token_endpoint=backchannel_addressed(raw.token_endpoint, settings),
        jwks_uri=backchannel_addressed(raw.jwks_uri, settings),
    )


def _fetch_discovery_document(settings: Settings) -> dict[str, Any]:
    """Fetch the provider's discovery document, or refuse the leg.

    The fetch rides the outbound discipline every call on this leg obeys: the configured
    timeout, redirects not followed (a redirected discovery fetch is a redirected
    credential-bearing call in waiting), and the body read under a cap enforced while
    reading — the response is streamed and a body that crosses the cap is refused and
    abandoned mid-read, so the cap bounds what a hostile document server can make the
    gateway buffer, not merely what it later parses. The URL is the configured issuer's
    with the well-known path joined — the issuer's own spelling is never rewritten —
    through the back-channel base when one is set, scheme and host swapped, path kept.
    """
    url = backchannel_addressed(
        f"{settings.idp_issuer.rstrip('/')}{_DISCOVERY_PATH}", settings
    )
    try:
        with httpx.stream(
            "GET",
            url,
            headers={"Accept": "application/json"},
            timeout=settings.gateway_outbound_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as response:
            body = _read_capped(response, _DISCOVERY_MAX_BYTES)
    except _OversizeError:
        message = (
            "the identity provider's discovery document is larger than this gateway "
            "accepts"
        )
        raise IdentityProviderError(message) from None
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        # The exception type is reported, never its message: an httpx error can echo the
        # request it failed on. The refusal is the whole leg's: there is no fallback
        # endpoint construction to fall back to. The URL-parse error class is caught
        # beside the transport errors because it is not one of them — a configured value
        # that passes the startup well-formedness check and that the HTTP client still
        # cannot address must fail the leg with the same fixed vocabulary as any other
        # unreachable provider, never as an unhandled error.
        message = (
            f"the identity provider's discovery document could not be reached "
            f"({type(exc).__name__}); the sign-in cannot proceed until the provider "
            f"answers"
        )
        raise IdentityProviderError(message, status_code=502) from exc
    try:
        document = json.loads(body)
    except ValueError as exc:
        message = "the identity provider's discovery document is not valid JSON"
        raise IdentityProviderError(message) from exc
    if not isinstance(document, dict):
        message = "the identity provider's discovery document is not a JSON object"
        raise IdentityProviderError(message)
    return document


def _validated_endpoints(document: dict[str, Any], settings: Settings) -> Endpoints:
    """The discovery document's three endpoints, or a refusal of the document whole.

    The document steers outbound calls that carry credential material — the code, the
    carried session refresh token — so it is trusted only within bounds, and a document
    that fails any of them is refused whole: no endpoint from it is ever used partially.

    * Its `issuer` must equal the configured issuer exactly — a document claiming another
      authority is not this provider's, and no part of it is taken.
    * Every endpoint the leg would use must share the configured issuer's origin or the
      configured back-channel base's — no endpoint the document names can steer a
      credential-bearing call to another origin.
    * Every endpoint must be HTTPS unless it shares the back-channel base's origin — the
      override is the operator's explicit ownership of a plain leg, and nothing else is.

    The document's own values are never echoed into a refusal: they are a third party's
    strings, and the fixed text is what the operator and the browser both get.
    """
    if document.get("issuer") != settings.idp_issuer:
        message = (
            "the identity provider's discovery document names another issuer than the "
            "one configured; the document is refused whole and no endpoint from it is "
            "used"
        )
        raise IdentityProviderError(message, status_code=502)

    allowed_origins = {_origin_of(settings.idp_issuer)}
    override = settings.idp_backchannel_base_url
    if override:
        allowed_origins.add(_origin_of(override))

    resolved: dict[str, str] = {}
    for member in (
        _AUTHORIZATION_ENDPOINT_MEMBER,
        _TOKEN_ENDPOINT_MEMBER,
        _KEY_SET_MEMBER,
    ):
        value = document.get(member)
        if not isinstance(value, str) or not value:
            message = (
                f"the identity provider's discovery document carries no usable "
                f"{member}; the document is refused whole"
            )
            raise IdentityProviderError(message, status_code=502)
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            message = (
                f"the identity provider's discovery document names a {member} that is "
                f"not an absolute URL; the document is refused whole"
            )
            raise IdentityProviderError(message, status_code=502)
        origin = _origin_of(value)
        if origin not in allowed_origins:
            message = (
                f"the identity provider's discovery document names its {member} on an "
                f"origin that is neither the configured issuer's nor the configured "
                f"back-channel base's; the document is refused whole"
            )
            raise IdentityProviderError(message, status_code=502)
        if parts.scheme != "https" and not (
            override and origin == _origin_of(override)
        ):
            message = (
                f"the identity provider's discovery document names its {member} over "
                f"plain http and no back-channel base owns that origin; the document is "
                f"refused whole"
            )
            raise IdentityProviderError(message, status_code=502)
        resolved[member] = value

    return Endpoints(
        authorization_endpoint=resolved[_AUTHORIZATION_ENDPOINT_MEMBER],
        token_endpoint=resolved[_TOKEN_ENDPOINT_MEMBER],
        jwks_uri=resolved[_KEY_SET_MEMBER],
    )


def _fetch_key_set(settings: Settings, jwks_url: str) -> httpx.Response:
    """Fetch the provider's published key set, or refuse as a leg failure.

    Module-level and synchronous so it can be the call a worker thread runs: it holds no
    state beyond the settings it is handed and the resolved URL it is sent to. The body
    is read under a cap enforced while reading, the same discipline every answer on this
    leg obeys — the key set verifies the tokens the mint copies claims from, and the leg
    serves external providers the deployment does not operate — so a body that crosses
    the cap is refused and the connection abandoned mid-read, never buffered whole.
    """
    try:
        with httpx.stream(
            "GET",
            jwks_url,
            headers={"Accept": "application/json"},
            timeout=settings.gateway_outbound_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        ) as response:
            status = response.status_code
            body = _read_capped(response, _RESPONSE_MAX_BYTES)
    except _OversizeError:
        message = "the identity provider's key set is larger than this gateway accepts"
        raise IdentityProviderError(message) from None
    except (httpx.HTTPError, httpx.InvalidURL) as exc:
        # The exception type is reported, never its message: an httpx error can echo the
        # URL it failed on. The URL-parse error class is caught beside the transport
        # errors because it is not one of them — a key-set URL the HTTP client cannot
        # address must fail the leg with the same fixed vocabulary as any other
        # unreachable provider.
        message = (
            f"the identity provider's key set could not be reached "
            f"({type(exc).__name__})"
        )
        raise IdentityProviderError(message) from exc
    # The buffered answer is returned in the response shape the shared readers take: the
    # status and the capped body are all of it any caller reads.
    return httpx.Response(status, content=body)


def _response_document(response: httpx.Response) -> dict[str, Any]:
    """A token-endpoint response as a JSON object, or a leg failure naming why not."""
    try:
        document = response.json()
    except ValueError as exc:
        message = "the identity provider's token response is not valid JSON"
        raise IdentityProviderError(message) from exc
    if not isinstance(document, dict):
        message = "the identity provider's token response is not a JSON object"
        raise IdentityProviderError(message)
    return document


def _refresh_response_document(response: httpx.Response) -> dict[str, Any]:
    """A refresh-grant response as a JSON object, or a `RefreshGrantError` naming why not.

    The provider's refusal is distinguished here: a response carrying the OAuth error
    `invalid_grant` is the session gone (RFC 6749 §6), and it is the one failure that sets
    `session_ended`. Every other non-200 — including another 4xx such as `invalid_client` —
    is a gateway-side or provider-side fault that says nothing about the session, so it must
    not audit as a session-ended event.

    A response with no `error` member that is nevertheless not 200 is treated as a plain
    provider fault rather than as a session end: the session-ended token is reserved for the
    provider's own `invalid_grant` statement, never inferred from a status code.
    """
    error_code = _error_code_of(response)
    if response.status_code != httpx.codes.OK:
        if error_code == _SESSION_GONE_ERROR:
            message = (
                "the identity provider ended this session: it refused the refresh grant "
                "with invalid_grant, so the sign-in has to be started again"
            )
            raise RefreshGrantError(message, session_ended=True)
        message = (
            f"the identity provider refused the refresh grant ({response.status_code}); "
            f"the sign-in has to be started again"
        )
        provider_error = response.status_code >= httpx.codes.INTERNAL_SERVER_ERROR
        raise RefreshGrantError(message, status_code=502 if provider_error else 400)
    return _response_document(response)


def _error_code_of(response: httpx.Response) -> str | None:
    """The OAuth `error` code in a refusal body, when the body carries a readable one.

    Read defensively: a refusal body that is not JSON, or whose `error` is not a string, has
    no code to key on, so the caller falls back to the status-code reading.
    """
    try:
        document = response.json()
    except ValueError:
        return None
    if not isinstance(document, dict):
        return None
    error = document.get("error")
    return error if isinstance(error, str) else None


def _access_token_of(document: dict[str, Any]) -> str:
    """The access token in a token-endpoint response document.

    A response without one is a completed exchange that established no identity, which is
    a failure of the leg rather than something a later step could recover from.
    """
    access_token = document.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        message = "the identity provider's token response carries no access token"
        raise IdentityProviderError(message)
    return access_token


def _optional_refresh_token(document: dict[str, Any]) -> str | None:
    """The response's own refresh token, when it carries one, else `None`.

    RFC 6749 §6 makes this member optional in a refresh response, so absence is normal: the
    caller keeps the token it presented. A member present but not a non-empty string is
    treated as absent rather than trusted, so a malformed answer cannot supersede a good
    carried token with a value that would fail at the provider.
    """
    refresh_token = document.get("refresh_token")
    if isinstance(refresh_token, str) and refresh_token:
        return refresh_token
    return None


def _captured_refresh_token(document: dict[str, Any], settings: Settings) -> str:
    """The provider's session refresh token from an exchange, or a sign-in refusal.

    The refresh claims re-read requires this token, so its absence is a deployment
    prerequisite the flow refuses **at sign-in** with an operator-facing message, never a
    silent breakage at the first refresh hours later. The same point and the same loudness
    apply to a token over the configured size bound: the carrier it must fit inside is a
    refresh token handed to a harness token store this gateway does not control, so a token
    that cannot fit is a failure whose cause is diagnosable only here.
    """
    refresh_token = document.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        message = (
            "the identity provider's code exchange issued no refresh token for this "
            "client, so the gateway cannot re-read claims at refresh. The provider must "
            "issue refresh tokens to the gateway's client at the code exchange"
        )
        raise IdentityProviderError(message, status_code=502)

    over_bound = len(refresh_token.encode("utf-8")) > (
        settings.gateway_custody_provider_token_max_bytes
    )
    if over_bound:
        message = (
            "the identity provider's refresh token is larger than the "
            f"{settings.gateway_custody_provider_token_max_bytes} bytes "
            "gateway_custody_provider_token_max_bytes allows. The refresh token the "
            "gateway issues must fit inside a harness token store it does not control, "
            "so this token cannot be carried. Raise the bound if the deployment's "
            "harness can hold a larger token"
        )
        raise IdentityProviderError(message, status_code=502)
    return refresh_token
