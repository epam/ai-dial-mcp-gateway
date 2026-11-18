"""Tests for the one property the whole service depends on: a slow leg blocks only itself.

Every outbound call the gateway makes is synchronous — the metadata fetch's connection
pinning is a property of the socket it opens, and the identity, Core, and credential calls
are the proven call chain. Each one therefore runs on a worker thread, and these tests are
what measure that: the event loop must keep answering while a leg is deliberately held
open by an upstream that never replies.

The instrument is an ASGI transport on the same event loop the app runs on, rather than a
`TestClient`. A `TestClient` drives the app through its own portal thread, so a request it
issued could not distinguish "the loop is free" from "the loop is busy" — the probe has to
share the loop to observe it. The CIMD fetch is the leg exercised because it is the
unauthenticated one: any caller can name a slow origin, so it is the leg whose slowness an
attacker chooses.
"""

from __future__ import annotations

import threading
import time
from http import HTTPStatus
from typing import Any

import anyio
import httpx
import pytest
import respx
from gateway.app import create_app

from tests.conftest import (
    LOOPBACK_REDIRECT_URI,
    TOOLSET_NAME,
    make_runtime,
    mock_discovery_on,
    surface_settings,
)

pytestmark = pytest.mark.anyio

# The CIMD client-id URL and the address it resolves to, reused from the CIMD tests: the
# fetch is addressed to the validated address, so the route is installed there.
CLIENT_ID_URL = "https://claude.ai/oauth/claude-code-client-metadata"
PUBLIC_ADDRESS = "93.184.216.34"
PINNED_URL = f"https://{PUBLIC_ADDRESS}/oauth/claude-code-client-metadata"
CLIENT_ID_PATH = "/oauth/claude-code-client-metadata"

# How long the fake upstream holds the metadata fetch open, and how long the liveness probe
# is allowed to take while it does. The probe's bound is a small fraction of the hold, so a
# probe that was queued behind the fetch could not pass it by accident.
SLOW_SECONDS = 2.0

# How long the probe may take, measured from the moment the fetch entered the outbound
# call. Well inside the hold the upstream applies, so a probe queued behind the fetch —
# which would take at least `SLOW_SECONDS` — cannot pass it by accident.
PROBE_BUDGET_SECONDS = 1.0

ORIGIN = "http://localhost:8090"
RESOURCE = f"{ORIGIN}/dial/{TOOLSET_NAME}/mcp"


def authorize_params() -> dict[str, str]:
    """An authorization request that resolves through the CIMD fetch, and only through it."""
    return {
        "response_type": "code",
        "client_id": CLIENT_ID_URL,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": "a-challenge",
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }


def _slow_document() -> httpx.Response:
    """A metadata document served after a hold, standing in for a slow origin."""
    time.sleep(SLOW_SECONDS)
    return httpx.Response(
        200,
        json={
            "client_id": CLIENT_ID_URL,
            "client_name": "A slow harness",
            "redirect_uris": [LOOPBACK_REDIRECT_URI],
        },
        headers={"content-type": "application/json"},
    )


async def test_healthz_answers_while_a_metadata_fetch_is_held_open(
    private_key_pem: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The F1 defect class, measured: a held-open outbound leg must not stop `/healthz`.

    A blocking fetch on the event loop queues every other request behind it, so the
    liveness probe would answer only after the upstream gave up — and a container
    healthcheck that times out on a healthy-but-busy gateway restarts it.

    Both requests are issued concurrently and the probe's own completion is the
    measurement: it must finish while the fetch is still held open. Timing the probe after
    the fact would not measure this — a loop blocked by the fetch delays the probe's start
    as well as its answer, and the stall would hide inside the caller's own wall clock.
    """
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (PUBLIC_ADDRESS, 443))],
    )
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))
    app = create_app(runtime=make_runtime(settings, private_key_pem))

    # The fake upstream signals its own entry through a `threading.Event`, not an
    # `anyio.Event`: the fetch runs on a worker thread, and a threading primitive is the
    # one that is safe to set from there. The probe awaits it on a worker thread too, so it
    # starts only once the outbound call is genuinely in flight, and issues `/healthz`
    # without ever touching the loop the fetch would be blocking.
    fetch_entered = threading.Event()
    entered_at: list[float] = []
    probe_times: list[tuple[float, httpx.Response]] = []

    def slow_document(_request: httpx.Request) -> httpx.Response:
        entered_at.append(time.monotonic())
        fetch_entered.set()
        return _slow_document()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        with respx.mock(assert_all_called=False) as router:
            mock_discovery_on(router, settings)
            router.get(PINNED_URL).mock(side_effect=slow_document)

            async with anyio.create_task_group() as group:

                async def fetch() -> None:
                    await client.get("/dial/authorize", params=authorize_params())

                async def probe() -> None:
                    await anyio.to_thread.run_sync(
                        fetch_entered.wait, abandon_on_cancel=True
                    )
                    # Timed from the fetch's own entry into the outbound call, which is the
                    # moment a busy loop would start holding every other request.
                    response = await client.get("/healthz")
                    probe_times.append((time.monotonic(), response))
                    group.cancel_scope.cancel()

                group.start_soon(fetch)
                group.start_soon(probe)

    # Both legs produced their measurement, so the timing assertion below compares two
    # recorded instants rather than a value against a default.
    assert entered_at, "the fetch never entered the outbound call"
    assert probe_times, "the probe never completed"
    started = entered_at[0]
    probe_at, probe_response = probe_times[0]
    probe_duration = probe_at - started

    assert probe_response.status_code == HTTPStatus.OK
    assert probe_response.json() == {"status": "ok"}
    assert probe_duration < PROBE_BUDGET_SECONDS, (
        f"/healthz answered {probe_duration:.2f}s after the fetch entered, but the "
        f"upstream holds it for {SLOW_SECONDS}s and the budget is "
        f"{PROBE_BUDGET_SECONDS}s: the probe waited on the event loop the fetch was "
        f"blocking"
    )


async def test_a_held_open_metadata_fetch_still_completes(
    private_key_pem: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half of the property: the offload shields the loop without breaking the leg.

    A fix that answered the probe by abandoning the fetch would pass the test above and
    break the product. The authorization request completes normally, with the document's
    redirect URI accepted, once the slow origin answers.
    """
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (PUBLIC_ADDRESS, 443))],
    )
    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))
    app = create_app(runtime=make_runtime(settings, private_key_pem))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        with respx.mock(assert_all_called=False) as router:
            mock_discovery_on(router, settings)
            route = router.get(PINNED_URL).mock(
                side_effect=lambda _request: _slow_document()
            )
            response = await client.get("/dial/authorize", params=authorize_params())

    assert response.status_code == HTTPStatus.FOUND
    assert route.call_count == 1


# ------------------------------------------- the CIMD fetch's share of the worker pool

# How many fetches the limiter allows at once, and how many more than that the test issues.
# The gap between the two is what the measurement is: the excess must wait its turn.
FETCH_LIMIT = 1
FETCH_EXCESS = FETCH_LIMIT + 2

# A limiter size the sizing test configures and then reads back, distinct from the limit the
# measurement tests use so the two cannot pass by sharing a value.
FETCH_LIMIT_SETTING = 3

# How long each counted fetch holds the worker it runs on. Long enough that fetches issued
# together genuinely overlap when nothing bounds them, short enough that a bounded run of
# them finishes in a fraction of a second.
FETCH_HOLD_SECONDS = 0.25


def client_id_at(index: int) -> str:
    """A distinct URL-shaped client id, so each request is a fetch and not a cache hit."""
    return f"https://claude.ai/oauth/client-{index}"


def pinned_url_for(index: int) -> str:
    """The address-pinned URL one client id's fetch is actually sent to."""
    return f"https://{PUBLIC_ADDRESS}/oauth/client-{index}"


def document_for(index: int) -> dict[str, Any]:
    """A metadata document declaring the URL it is served from, as one must."""
    return {"client_id": client_id_at(index), "redirect_uris": [LOOPBACK_REDIRECT_URI]}


def authorize_params_for(client_id: str) -> dict[str, str]:
    """An authorization request naming this client id and a mapped toolset's resource."""
    return {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": LOOPBACK_REDIRECT_URI,
        "code_challenge": "a-challenge",
        "code_challenge_method": "S256",
        "resource": RESOURCE,
    }


async def measure_fetch_overlap(
    private_key_pem: str, tmp_path: Any, *, limit: int
) -> int:
    """Issue the concurrent fetches under a limiter of `limit`, returning the peak overlap.

    Factored out so the measured test and its control differ in exactly one value: both
    drive the same distinct client ids at the same slow origin through the same instrument,
    with only the limiter's size changed between them.
    """
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_cimd_max_concurrent_fetches=limit,
        gateway_rate_per_source_per_minute=1000,
        gateway_rate_global_per_minute=10_000,
    )
    app = create_app(runtime=make_runtime(settings, private_key_pem))

    in_flight = 0
    high_water = 0
    counter_lock = threading.Lock()

    def counting_fetch(index: int) -> Any:
        """A fetch that holds its worker for a fixed time, recording the overlap."""

        def fetch(_request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, high_water
            with counter_lock:
                in_flight += 1
                high_water = max(high_water, in_flight)
            time.sleep(FETCH_HOLD_SECONDS)
            with counter_lock:
                in_flight -= 1
            return httpx.Response(
                200,
                json=document_for(index),
                headers={"content-type": "application/json"},
            )

        return fetch

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        with respx.mock(assert_all_called=False) as router:
            mock_discovery_on(router, settings)
            for index in range(FETCH_EXCESS):
                router.get(pinned_url_for(index)).mock(
                    side_effect=counting_fetch(index)
                )

            async with anyio.create_task_group() as group:
                for index in range(FETCH_EXCESS):
                    group.start_soon(fetch_once, client, index)

    return high_water


async def test_concurrent_metadata_fetches_are_bounded_by_the_capacity_limiter(
    private_key_pem: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An attacker's fetches cannot hold the shared pool, so the flow's legs keep capacity.

    The worker pool is shared with the identity and credential legs, and this fetch is the
    one slow leg whose target an unauthenticated caller chooses. The instrument is
    concurrency itself: distinct client ids naming distinct slow origins are requested at
    once, and the number of fetches inside the outbound call at any instant is observed.
    With the limiter at one that number must never exceed one; a limiter that were absent,
    or were consulted after the fetch had already started, would show every request in
    flight together — which is exactly the starvation the bound exists to prevent.

    Distinct client ids matter: one id would be a cache hit for every request after the
    first, and the test would then be measuring the cache rather than the limiter. The rate
    limits are raised out of the way for the same reason — the bound under test is the
    capacity limiter, so nothing else may be what refuses a request. The control below is
    the other half: the same instrument, with the limiter widened, must observe the overlap
    — without it this test could pass on an instrument that could never see one.
    """
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (PUBLIC_ADDRESS, 443))],
    )

    high_water = await measure_fetch_overlap(
        private_key_pem, tmp_path, limit=FETCH_LIMIT
    )

    # The negative control first: fetches ran, so the ceiling below measures a populated
    # instrument rather than an instrument nothing reached.
    assert high_water >= 1, "no fetch ever entered the outbound call"
    assert high_water <= FETCH_LIMIT, (
        f"{high_water} metadata fetches ran concurrently with the limiter set to "
        f"{FETCH_LIMIT}: an unauthenticated caller's fetches can occupy the shared worker "
        f"pool and starve the identity and credential legs"
    )


async def test_the_overlap_instrument_detects_an_unbounded_burst(
    private_key_pem: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the test above: with the bound lifted, the same instrument sees it.

    This is what makes the ceiling meaningful. The requests, the origin, the hold, and the
    counter are identical to the bounded test; only the limiter's size changes, from one to
    as many as there are requests. If the ceiling in that test could never be exceeded
    whatever the configuration, this one would fail — so a passing pair says the bound is
    what produced the difference rather than the instrument's own shape.
    """
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (PUBLIC_ADDRESS, 443))],
    )

    high_water = await measure_fetch_overlap(
        private_key_pem, tmp_path, limit=FETCH_EXCESS
    )

    assert high_water > FETCH_LIMIT, (
        f"with the limiter widened to {FETCH_EXCESS} the instrument still saw at most "
        f"{high_water} fetch(es) at once: it cannot detect an unbounded burst, so the "
        f"ceiling it reports in the bounded test means nothing"
    )


async def fetch_once(client: httpx.AsyncClient, index: int) -> None:
    """Drive one authorization request that resolves through the client id's own fetch."""
    await client.get(
        "/dial/authorize", params=authorize_params_for(client_id_at(index))
    )


async def test_the_fetch_limiter_is_sized_by_its_setting(
    private_key_pem: str, tmp_path: Any
) -> None:
    """The bound is an operator setting, so a deployment can widen or narrow the share."""
    settings = surface_settings(
        dcr_store_path=str(tmp_path / "store.json"),
        gateway_cimd_max_concurrent_fetches=FETCH_LIMIT_SETTING,
    )

    assert (
        make_runtime(settings, private_key_pem).client_cache.max_concurrent_fetches
        == FETCH_LIMIT_SETTING
    )


async def test_the_metadata_fetch_runs_off_the_event_loop(
    private_key_pem: str, tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fetch is exercised from a thread, asserted on the thread identity itself.

    The behavioural tests above measure the outcome; this one measures the mechanism, so a
    regression that made the fetch fast enough to hide a return to the loop would still
    fail here. A blocking call must never run on the thread the loop drives.
    """
    monkeypatch.setattr(
        "gateway.cimd.socket.getaddrinfo",
        lambda *args, **kwargs: [(2, 1, 6, "", (PUBLIC_ADDRESS, 443))],
    )
    loop_thread = threading.get_ident()
    seen: list[int] = []

    def observing_fetch(_request: httpx.Request) -> httpx.Response:
        seen.append(threading.get_ident())
        return httpx.Response(
            200,
            json={
                "client_id": CLIENT_ID_URL,
                "redirect_uris": [LOOPBACK_REDIRECT_URI],
            },
            headers={"content-type": "application/json"},
        )

    settings = surface_settings(dcr_store_path=str(tmp_path / "store.json"))
    app = create_app(runtime=make_runtime(settings, private_key_pem))

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://gateway.test"
    ) as client:
        with respx.mock(assert_all_called=False) as router:
            mock_discovery_on(router, settings)
            router.get(PINNED_URL).mock(side_effect=observing_fetch)
            response = await client.get("/dial/authorize", params=authorize_params())

    assert response.status_code == HTTPStatus.FOUND
    # The negative control first: the fetch ran, so the thread assertion measures it.
    assert seen, "the fetch must have run for the thread assertion to mean anything"
    assert seen[0] != loop_thread, "the blocking fetch ran on the event loop's thread"
