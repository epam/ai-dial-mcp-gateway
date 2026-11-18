"""Tests for the abuse bounds on the public surface, and the plain-language error pages.

The endpoints covered here are unauthenticated and allocate state, so the bounds are what
keep one caller from consuming the gateway on everyone's behalf. Each bound is exercised
by driving requests past it — not by inspecting the limiter — because the property is
about what a request receives, and a limiter that is configured but never consulted looks
identical to one that works until traffic arrives.

The two limits bound different things: the per-source limit bounds what one caller can do,
and the global limit bounds what the endpoint as a whole accepts. Each is driven with the
other raised out of the way, so every test measures one thing.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from http import HTTPStatus
from pathlib import Path
from typing import cast

import pytest
from fastapi import Request, Response
from fastapi.testclient import TestClient
from gateway.audit import AuditTrail
from gateway.discovery import protected_resource_path
from gateway.errors import (
    client_source,
    flow_expired_page,
    gateway_error_page,
    no_access_page,
    not_consentable_page,
    oauth_error,
    redirect_error,
)
from gateway.state import (
    ApprovedClientRegistry,
    FlowStore,
    RateLimiter,
    ReplayCache,
)

from tests.conftest import (
    LOOPBACK_REDIRECT_URI,
    PRE_REGISTERED_CLIENT_ID,
    TOOLSET_NAME,
    assert_hardening_headers,
    make_client,
    runtime_of,
    surface_settings,
)

ORIGIN = "http://localhost:8090"
RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"

# Small limits, so a test reaches them in a handful of requests and the numbers in the
# assertions are the configured ones rather than a coincidence of traffic.
PER_SOURCE_LIMIT = 3
GLOBAL_LIMIT = 4
FLOW_CAP = 2

# The bounds the store-level tests configure and then observe.
SOURCE_MAP_BOUND = 2
REPLAY_CACHE_BOUND = 2
FLOW_CAP_PROBE_COUNT = FLOW_CAP + 2
PER_SOURCE_PROBE_COUNT = PER_SOURCE_LIMIT + 5

# How many audit records the audit test emits, asserted so a dropped one fails here.
AUDIT_EVENT_COUNT = 3

# The window the recovery test rolls past, in seconds.
WINDOW_SECONDS = 60

# The status a plain-language page answers with: a client error, not a server one.
PAGE_STATUS = HTTPStatus.BAD_REQUEST


def authorize_params(**overrides: str) -> dict[str, str]:
    params = {
        "response_type": "code",
        "client_id": PRE_REGISTERED_CLIENT_ID,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": "a-challenge",
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }
    params.update(overrides)
    return params


def a_flow(store: FlowStore) -> object:
    """Allocate a flow record, so a test can observe what happens to it."""
    return store.create(
        client_id="a-client",
        redirect_uri=LOOPBACK_REDIRECT_URI,
        code_challenge="a-challenge",
        code_challenge_method="S256",
        resource=RESOURCE,
        toolset=TOOLSET_NAME,
        resource_kind="toolset",
        client_name=None,
        client_source="a-source",
        state=None,
    )


# -------------------------------------------------------------------- rate limits


def test_requests_past_the_per_source_limit_are_rejected(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The limit bounds what one source can allocate, and the refusal is actionable."""
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=PER_SOURCE_LIMIT,
        gateway_rate_global_per_minute=PER_SOURCE_LIMIT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        responses = [
            client.get("/dial/authorize", params=authorize_params())
            for _ in range(PER_SOURCE_LIMIT + 1)
        ]

    assert all(r.status_code == HTTPStatus.FOUND for r in responses[:PER_SOURCE_LIMIT])
    excess = responses[-1]
    assert excess.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert excess.json()["error"] == "temporarily_unavailable"


def test_a_rejected_request_allocates_no_flow(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The count is charged before any work, so a flood costs no memory.

    Asserted on the live-record count rather than on the response alone: a refusal that
    had already allocated and then discarded would still have spent the memory this bound
    exists to protect.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=PER_SOURCE_LIMIT,
        gateway_rate_global_per_minute=PER_SOURCE_LIMIT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        for _ in range(PER_SOURCE_PROBE_COUNT):
            client.get("/dial/authorize", params=authorize_params())
        live = runtime_of(client).flows.live_count()

    assert live == PER_SOURCE_LIMIT


def test_the_global_limit_bounds_the_endpoint_overall(
    private_key_pem: str, tmp_path: Path
) -> None:
    """A caller with many addresses is bounded per address, so the global limit bounds
    the endpoint as a whole.

    Driven with the per-source limit raised, so a distinct source per request is never
    charged to it and only one limit is in play.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=GLOBAL_LIMIT * 10,
        gateway_rate_global_per_minute=GLOBAL_LIMIT,
    )

    with make_client(settings, private_key_pem) as client:
        responses = [
            client.get(
                "/dial/authorize",
                params=authorize_params(),
                headers={"x-forwarded-for": f"203.0.113.{index}"},
            )
            for index in range(GLOBAL_LIMIT + 1)
        ]

    assert all(r.status_code == HTTPStatus.FOUND for r in responses[:GLOBAL_LIMIT])
    assert responses[-1].status_code == HTTPStatus.TOO_MANY_REQUESTS


def test_sources_are_counted_separately(private_key_pem: str, tmp_path: Path) -> None:
    """One caller reaching its limit must not refuse another caller.

    This is the property that makes a per-source limit a bound rather than an outage: the
    first source's excess is refused, and a second source's first request is not.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=PER_SOURCE_LIMIT,
        gateway_rate_global_per_minute=PER_SOURCE_LIMIT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        for _ in range(PER_SOURCE_LIMIT + 1):
            client.get(
                "/dial/authorize",
                params=authorize_params(),
                headers={"x-forwarded-for": "203.0.113.1"},
            )
        other_source = client.get(
            "/dial/authorize",
            params=authorize_params(),
            headers={"x-forwarded-for": "203.0.113.2"},
        )

    assert other_source.status_code == HTTPStatus.FOUND


def test_the_limiter_recovers_when_its_window_rolls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A fixed window is a bound on rate, not a lockout.

    Driven by advancing the clock the limiter compares against — the same measurement as
    waiting the window out, without the wait.
    """
    limiter = RateLimiter(
        per_source_limit=1, global_limit=10, window_seconds=WINDOW_SECONDS
    )

    assert limiter.allow("a-source") is True
    assert limiter.allow("a-source") is False

    real_monotonic = time.monotonic
    monkeypatch.setattr(
        time, "monotonic", lambda: real_monotonic() + WINDOW_SECONDS + 1
    )

    assert limiter.allow("a-source") is True


def test_the_per_source_map_is_bounded() -> None:
    """A map keyed by a caller-supplied value is the same exhaustion problem elsewhere."""
    limiter = RateLimiter(per_source_limit=5, global_limit=10_000, max_sources=2)

    for index in range(SOURCE_MAP_BOUND * 5):
        limiter.allow(f"source-{index}")

    assert limiter.source_count() <= SOURCE_MAP_BOUND


def test_the_unauthenticated_routes_are_all_bounded(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Every unauthenticated route that does work is limited, driven one route at a time.

    The per-source limit is what bounds what one caller can do on a surface anyone can
    reach, and each of these routes does work an unauthenticated caller chooses: a token
    request costs RSA verifications, a callback drives a credential exchange, a revocation
    attempt is a signature check. A route that forgot the limiter looks identical to a
    bounded one until traffic arrives, which is why each is driven past the limit here.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=PER_SOURCE_LIMIT,
        gateway_rate_global_per_minute=PER_SOURCE_LIMIT * 10,
    )

    routes: list[tuple[str, Callable[[TestClient], Response]]] = [
        ("token", lambda c: c.post("/dial/token", data={})),
        ("revoke", lambda c: c.post("/dial/revoke", data={})),
        (
            "idp_callback",
            lambda c: c.get("/dial/callback/idp", params={"state": "x"}),
        ),
        (
            "upstream_callback",
            lambda c: c.get("/dial/callback/upstream", params={"state": "x"}),
        ),
        (
            # The consent action: a POST naming no live flow is refused, but only after
            # the limiter has counted it.
            "consent",
            lambda c: c.post(
                "/dial/consent", data={"flow_id": "x", "action": "approve"}
            ),
        ),
        (
            # A guard-failing name, so the discovery route's own refusal branch — the one
            # that writes an audit record — is what the limiter bounds here.
            "protected_resource",
            lambda c: c.get(protected_resource_path("token")),
        ),
    ]

    for label, request in routes:
        with make_client(settings, private_key_pem) as client:
            responses = [request(client) for _ in range(PER_SOURCE_LIMIT + 1)]

        assert responses[-1].status_code == HTTPStatus.TOO_MANY_REQUESTS, label


def test_a_burst_of_discovery_refusals_is_limited_and_writes_nothing(
    private_key_pem: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The discovery guard's record volume is capped: over the limit, no record at all.

    Every guard refusal on this route writes an audit record, so without the limiter an
    unauthenticated caller looping a guard-failing name would grow the operator's log at
    the request rate. The bound is the limit itself, and it holds because an over-limit
    request is answered with the 429 and writes nothing — asserted on both halves, since a
    limiter that still wrote a `rate_limited` record per refused request would leave the
    volume unbounded and would look identical on the status code alone.
    """
    caplog.set_level(logging.INFO, logger="gateway.audit")
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=PER_SOURCE_LIMIT,
        gateway_rate_global_per_minute=PER_SOURCE_LIMIT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        responses = [
            client.get(protected_resource_path("token"))
            for _ in range(PER_SOURCE_LIMIT + 1)
        ]

    # The admitted requests each wrote one guard record; the over-limit one wrote none.
    assert all(
        r.status_code == HTTPStatus.NOT_FOUND for r in responses[:PER_SOURCE_LIMIT]
    )
    excess = responses[-1]
    assert excess.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert excess.json()["error"] == "temporarily_unavailable"

    audit_records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "gateway.audit"
    ]
    assert len(audit_records) == PER_SOURCE_LIMIT
    # Not one of them is the limiter's own refusal: the over-limit request added nothing.
    assert all(r["reason"] != "rate_limited" for r in audit_records)
    assert all(r["event"] == "flow_refused" for r in audit_records)


def test_a_burst_on_the_token_endpoint_is_limited(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The token endpoint's own limit, with the refusal shape a client library expects.

    A 429 carrying `temporarily_unavailable` is what an OAuth client's error handling
    recognizes; the alternative — letting the burst through to the RSA verification — is
    the CPU-exhaustion path this bound exists to close.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=PER_SOURCE_LIMIT,
        gateway_rate_global_per_minute=PER_SOURCE_LIMIT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        for _ in range(PER_SOURCE_LIMIT):
            client.post("/dial/token", data={"grant_type": "refresh_token"})
        excess = client.post("/dial/token", data={"grant_type": "refresh_token"})

    assert excess.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert excess.json()["error"] == "temporarily_unavailable"


def test_a_limited_callback_renders_a_page_rather_than_breaking_the_flow(
    private_key_pem: str, tmp_path: Path
) -> None:
    """A limited callback is a plain-language page, never a broken OAuth redirect.

    The callback is browser-facing: a caller who hits the limit while mid-flow receives a
    page telling them to start again, not a redirect to a URL carrying a refusal the
    harness never asked about — which a browser would follow to a callback that cannot
    interpret it. The page is the same shape every other callback refusal uses.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=PER_SOURCE_LIMIT,
        gateway_rate_global_per_minute=PER_SOURCE_LIMIT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        for _ in range(PER_SOURCE_LIMIT):
            client.get("/dial/callback/upstream", params={"state": "x"})
        limited = client.get("/dial/callback/upstream", params={"state": "x"})

    assert limited.status_code == HTTPStatus.TOO_MANY_REQUESTS
    assert "text/html" in limited.headers["content-type"]
    assert "location" not in limited.headers
    assert "start the sign-in again" in limited.text


def test_traffic_below_the_limit_is_unaffected_on_the_bounded_routes(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The bound refuses the burst, not the traffic: below it every route answers normally.

    Without this the test above could pass on routes that refused everything, so each
    route's ordinary request is driven and asserted to reach its own logic rather than the
    limiter.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_rate_per_source_per_minute=10,
        gateway_rate_global_per_minute=100,
    )

    with make_client(settings, private_key_pem) as client:
        token = client.post("/dial/token", data={})
        # A well-formed form carrying a token this gateway did not issue: the revoke
        # endpoint's ordinary answer is an empty 200, per RFC 7009.
        revoke = client.post(
            "/dial/revoke", data={"token": "not-a-token-this-gateway-issued"}
        )
        callback = client.get("/dial/callback/upstream", params={"state": "x"})

    # Each reached its own refusal, not the limiter's: an `invalid_request` from the token
    # endpoint and the expired-session page from the callback are the ordinary answers.
    assert token.status_code == HTTPStatus.BAD_REQUEST
    assert token.json()["error"] == "invalid_request"
    assert revoke.status_code == HTTPStatus.OK
    assert callback.status_code == HTTPStatus.BAD_REQUEST
    assert "sign-in session expired" in callback.text


# ------------------------------------------------- the form endpoints' body byte cap


def test_an_oversized_token_request_body_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The token endpoint reads its form under a cap, applied while the body is read.

    The endpoint is unauthenticated and takes a body, so a request that is merely large
    must cost the gateway a bounded amount of memory. The body here is a well-formed form
    — one parameter an order of magnitude past the cap — so what is refused is the size
    and not the shape, and the answer is the RFC 6749 error document a client library
    understands.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_form_max_body_bytes=2048,
        # The size bound and the cap are coupled; a small cap needs a matching provider bound.
        gateway_custody_provider_token_max_bytes=512,
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/token",
            content=("grant_type=authorization_code&code=" + "c" * 50_000).encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_request"
    assert "larger than" in response.json()["error_description"]


def test_an_oversized_revocation_body_is_refused(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The same cap on `/dial/revoke`, which reads the same shape of body.

    A revocation request is a handful of short parameters, so a body past the cap is not
    one — and the endpoint is unauthenticated, which is what makes the read the place the
    bound has to be.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_form_max_body_bytes=2048,
        gateway_custody_provider_token_max_bytes=512,
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/revoke",
            content=("token=" + "t" * 50_000).encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_request"
    assert "larger than" in response.json()["error_description"]


def test_a_form_body_at_the_cap_is_still_processed(
    private_key_pem: str, tmp_path: Path
) -> None:
    """The cap bounds size, not legitimate use: a body just under it is parsed normally.

    Without this, the two oversized tests above could pass on endpoints that refused every
    body — a broken endpoint rather than a bounded one. The parameter is long enough to be
    well inside the cap and long enough that the request is a real one of its size class.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_form_max_body_bytes=4096,
        gateway_custody_provider_token_max_bytes=1024,
    )

    with make_client(settings, private_key_pem) as client:
        response = client.post(
            "/dial/token",
            content=("grant_type=refresh_token&refresh_token=" + "t" * 400).encode(),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )

    # It reached validation and was refused as a bad grant, not as an oversized body.
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"


# ------------------------------------------------------------------- the flow cap


def test_the_flow_cap_evicts_the_oldest_records(
    private_key_pem: str, tmp_path: Path
) -> None:
    """Memory is bounded: past the cap, the oldest records go rather than accumulate."""
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_flows_max_live=FLOW_CAP,
        gateway_rate_per_source_per_minute=FLOW_CAP_PROBE_COUNT * 10,
    )

    with make_client(settings, private_key_pem) as client:
        for _ in range(FLOW_CAP_PROBE_COUNT):
            client.get("/dial/authorize", params=authorize_params())
        live = runtime_of(client).flows.live_count()

    assert live == FLOW_CAP


def test_an_evicted_flow_is_gone_from_the_store() -> None:
    """The evicted record is absent, not merely uncounted.

    Asserted through a lookup, because a lookup is what a later leg performs — and a
    record that were present but expired would be a different failure.
    """
    store = FlowStore(max_live=1, ttl_seconds=600)
    first = a_flow(store)
    a_flow(store)

    assert store.get(first.flow_id) is None  # type: ignore[attr-defined]


def test_an_expired_flow_is_not_returned() -> None:
    """A record past its TTL is gone even when the cap was never reached."""
    store = FlowStore(max_live=10, ttl_seconds=600)
    record = a_flow(store)
    # Expire it by moving its own deadline, which is the condition the lookup compares.
    record.expires_at = time.monotonic() - 1  # type: ignore[attr-defined]

    assert store.get(record.flow_id) is None  # type: ignore[attr-defined]


def test_destroying_a_flow_removes_it() -> None:
    """What a callback does on first use, asserted as removal rather than as a flag."""
    store = FlowStore(max_live=10, ttl_seconds=600)
    record = a_flow(store)

    store.destroy(record.flow_id)  # type: ignore[attr-defined]

    assert store.get(record.flow_id) is None  # type: ignore[attr-defined]


# ------------------------------------ the approved-client registry (the checkpoint)

# The cap the registry tests configure and then observe — small, so a test reaches it in a
# handful of approvals and the number in the assertion is the configured one.
REGISTRY_CAP = 2


def test_an_approved_pair_is_consulted_and_passes() -> None:
    """The registry's whole contract: an approved (subject, client) is a hit."""
    registry = ApprovedClientRegistry(max_entries=10)

    assert registry.is_approved("a-subject", "a-client") is False
    registry.approve("a-subject", "a-client")
    assert registry.is_approved("a-subject", "a-client") is True


def test_an_approval_covers_the_client_across_resources() -> None:
    """The key carries no resource: the same client to the same user is one approval.

    The decision the page asks for is the *client's* ("may this client act for me"), named
    on a resource — a per-resource keying would re-prompt for a trust decision the user has
    already made. The resource axis stays gated by the flow's own DIAL authorization read,
    which the registry neither consults nor replaces.
    """
    registry = ApprovedClientRegistry(max_entries=10)
    registry.approve("a-subject", "a-client")

    # A second resource's flow consults the same pair and passes; the registry has no
    # resource axis to key on.
    assert registry.is_approved("a-subject", "a-client") is True


def test_the_registry_is_keyed_by_both_subject_and_client() -> None:
    """Neither half of the key is optional: a different subject or client is a miss."""
    registry = ApprovedClientRegistry(max_entries=10)
    registry.approve("subject-a", "client-1")

    assert registry.is_approved("subject-a", "client-1") is True
    assert registry.is_approved("subject-a", "client-2") is False
    assert registry.is_approved("subject-b", "client-1") is False


def test_the_registry_cap_evicts_the_oldest_approval() -> None:
    """Loss under cap pressure forgets the oldest first, which re-prompts — never skips."""
    registry = ApprovedClientRegistry(max_entries=REGISTRY_CAP)
    registry.approve("subject-1", "client")
    registry.approve("subject-2", "client")
    registry.approve("subject-3", "client")

    assert registry.entry_count() == REGISTRY_CAP
    # The oldest (subject-1) is gone, so its next sign-in re-prompts the decision page.
    assert registry.is_approved("subject-1", "client") is False
    assert registry.is_approved("subject-3", "client") is True


def test_reapproving_does_not_move_an_entrys_age() -> None:
    """A repeat approval is idempotent, so a burst of sign-ins cannot evict older ones."""
    registry = ApprovedClientRegistry(max_entries=REGISTRY_CAP)
    registry.approve("subject-1", "client")
    registry.approve("subject-2", "client")
    # subject-1 approves again: its entry keeps its place, so the cap does not evict it.
    registry.approve("subject-1", "client")

    assert registry.is_approved("subject-1", "client") is True
    assert registry.entry_count() == REGISTRY_CAP


def test_an_empty_subject_is_never_recorded() -> None:
    """A flow whose identity leg asserted no subject cannot write an approval.

    The key is the provider-verified `sub`; an empty one is not a user, so it is refused
    rather than stored — which keeps a flow without a subject re-prompting on every run
    (the fail-safe direction) instead of accumulating an unreachable entry.
    """
    registry = ApprovedClientRegistry(max_entries=10)
    registry.approve("", "client")

    assert registry.entry_count() == 0
    assert registry.is_approved("", "client") is False


# --------------------------------------------------------------- replay cache bounds


def test_a_claimed_value_cannot_be_claimed_twice() -> None:
    cache = ReplayCache(ttl_seconds=300, max_entries=10)

    assert cache.claim("a-value") is True
    assert cache.claim("a-value") is False


def test_a_claim_expires_with_its_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    """The claim outlives the code it protects and then stops mattering."""
    cache = ReplayCache(ttl_seconds=300, max_entries=10)
    cache.claim("a-value")

    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 301)

    assert cache.claim("a-value") is True


def test_the_replay_cache_is_bounded() -> None:
    """The cache is keyed by a value that arrives per request, so it is bounded too."""
    cache = ReplayCache(ttl_seconds=300, max_entries=REPLAY_CACHE_BOUND)

    for index in range(REPLAY_CACHE_BOUND * 5):
        cache.claim(f"value-{index}")

    assert cache.entry_count() <= REPLAY_CACHE_BOUND


# ------------------------------------------------------------------- error pages


def test_an_error_page_is_plain_language() -> None:
    """The page a user reads says what to do; the specifics go to the operator's log.

    A flow id or a record's state would be an information leak with no use to the person
    reading it.
    """
    response = flow_expired_page("the sign-in session has expired")
    body = bytes(response.body).decode()

    assert response.status_code == PAGE_STATUS
    assert "text/html" in response.headers["content-type"]
    assert "expired" in body
    assert "start the sign-in again" in body


def test_every_error_page_carries_the_web_hardening_headers() -> None:
    """Each of the four plain-language pages carries the whole family.

    One assertion per page rather than one over the family's builder: these are four
    separate response classes on separate paths, and the omission this guards against
    is exactly one of them being built without the headers.
    """
    pages = {
        "flow_expired_page": flow_expired_page("the sign-in session has expired"),
        "gateway_error_page": gateway_error_page(502, "the upstream could not be read"),
        "no_access_page": no_access_page(403, "you are not a member of this toolset"),
        "not_consentable_page": not_consentable_page(),
    }

    for name, page in pages.items():
        # The page's name is carried into any failure, so an omission names which of the
        # three paths lost the family rather than only that one did.
        assert_hardening_headers(page, label=name)
        assert "<script" not in bytes(page.body).decode(), name


def test_the_error_page_shape_is_fixed() -> None:
    """The reason is interpolated as text, so a caller cannot extend the page's structure.

    The reason parameter is always a fixed description chosen by the gateway, so this
    asserts the property that keeps it safe to pass one through.
    """
    body = bytes(flow_expired_page("literal <script>alert(1)</script>").body).decode()

    assert body.count("<html") == 1
    assert body.count("<body") == 1


def test_error_responses_are_not_cacheable() -> None:
    response = oauth_error("invalid_request", "something was wrong")

    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_a_redirect_error_goes_to_the_uri_it_was_given() -> None:
    """The error reaches the client's own registered URI, and nowhere else."""
    response = redirect_error(
        LOOPBACK_REDIRECT_URI,
        "invalid_target",
        "no such toolset",
        state="s",
        issuer=ORIGIN,
    )

    assert response.headers["location"].startswith(LOOPBACK_REDIRECT_URI)


def test_a_redirect_error_appends_correctly_when_the_uri_has_a_query() -> None:
    """A registered redirect URI may carry its own query, so the separator is chosen."""
    response = redirect_error(
        f"{LOOPBACK_REDIRECT_URI}?tenant=one",
        "invalid_target",
        "no such toolset",
        state=None,
        issuer=ORIGIN,
    )

    assert f"{LOOPBACK_REDIRECT_URI}?tenant=one&error=" in response.headers["location"]


def test_the_client_source_prefers_the_routers_own_x_real_ip() -> None:
    """`X-Real-IP` is the router's statement about the peer it accepted, not the client's.

    The front router sets it from `$remote_addr`, so while a client's traffic passes
    through that router nothing the client sends can influence it — which is what makes it
    the value to count against rather than either end of a header the client also writes.
    """
    request = as_request(
        headers={
            "x-real-ip": "203.0.113.7",
            "x-forwarded-for": "198.51.100.9, 203.0.113.7",
        },
        peer_host=None,
    )

    assert client_source(request) == "203.0.113.7"


def test_the_client_source_takes_the_last_forwarded_entry() -> None:
    """The router *appends* the real peer, so the last XFF entry is the router's own.

    Reading the first entry would let an attacker prepend a rotating fake address per
    request and defeat the per-source limit entirely: `$proxy_add_x_forwarded_for` puts
    the client's own value first and the router-observed peer last.
    """
    request = as_request(
        headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"}, peer_host=None
    )

    assert client_source(request) == "10.0.0.1"


def test_a_spoofed_first_entry_does_not_change_the_source() -> None:
    """A rotated first entry leaves the counted source where the router put it."""
    sources = {
        client_source(
            as_request(
                headers={"x-forwarded-for": f"203.0.113.{index}, 10.0.0.1"},
                peer_host=None,
            )
        )
        for index in range(5)
    }

    assert sources == {"10.0.0.1"}


def test_the_client_source_falls_back_to_the_socket_peer() -> None:
    """A direct call — a development run — has no forwarded header."""
    request = as_request(headers={}, peer_host="127.0.0.1")

    assert client_source(request) == "127.0.0.1"


def test_the_client_source_is_named_when_nothing_identifies_the_caller() -> None:
    """A request with neither a forwarded header nor a peer still counts somewhere."""
    assert client_source(as_request(headers={}, peer_host=None)) == "unknown"


def as_request(**kwargs: object) -> Request:
    """A `FakeRequest` typed as the `Request` the function under test accepts.

    `client_source` reads two members — `headers` and `client` — and the fakes below carry
    exactly those. The cast states that in one place rather than at each call, so the tests
    read as the parsing they assert.
    """
    return cast(Request, FakeRequest(**kwargs))  # type: ignore[arg-type]


class FakeRequest:
    """The two members `client_source` reads, so the fallbacks can be exercised directly."""

    def __init__(self, *, headers: dict[str, str], peer_host: str | None) -> None:
        self.headers = headers
        self.client = FakeClient(peer_host) if peer_host is not None else None


class FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


def test_the_audit_trail_carries_no_credential_material() -> None:
    """The trail is written from fixed fields, asserted on what it actually emits."""
    records: list[str] = []

    class Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    collector = Collector()
    logger = logging.getLogger("gateway.audit")
    logger.addHandler(collector)
    logger.setLevel(logging.INFO)
    try:
        trail = AuditTrail()
        trail.token_issued(
            subject="a-subject", client_id="a-client", resource="a-resource"
        )
        trail.client_registered("a-client", source="dcr")
        trail.flow_refused("a fixed reason")
    finally:
        logger.removeHandler(collector)

    # The negative control: the collector saw every event, so the field-set assertion
    # below measures the records rather than an empty list.
    assert len(records) == AUDIT_EVENT_COUNT

    allowed = {
        "event",
        "at",
        "subject",
        "client_id",
        # The flow lifecycle events carry a single `resource` fact (the resource URI the
        # flow serves, toolset or app); the pre-allocation `flow_refused` record carries
        # the request's `resource` and its kind-neutral `name` fact too, plus the
        # `resource_kind` the one-kind discovery sites name explicitly.
        "resource",
        "name",
        "resource_kind",
        "source",
        "reason",
        "flow_id",
        # The refusal record's request facts: each is a value the request offered, recorded
        # as its own field, and none of them is a credential.
        "redirect_uri",
    }
    for line in records:
        assert set(json.loads(line)) <= allowed


def test_the_audit_trail_does_not_carry_a_flow_id_it_was_not_given() -> None:
    """Each event records what its caller supplied, so a field cannot appear by accident."""
    records: list[str] = []

    class Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record.getMessage())

    collector = Collector()
    logger = logging.getLogger("gateway.audit")
    logger.addHandler(collector)
    logger.setLevel(logging.INFO)
    try:
        AuditTrail().token_issued(
            subject="a-subject", client_id="a-client", resource="a-resource"
        )
    finally:
        logger.removeHandler(collector)

    body = json.loads(records[0])
    assert "flow_id" not in body
    assert body["event"] == "token_issued"
