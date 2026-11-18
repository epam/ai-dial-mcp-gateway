"""Prove the composed gateway keeps serving while one outbound leg is held open (F1).

The defect this measures is the one a unit test cannot fully close: a synchronous outbound
call made *on* the event loop holds every other request behind it, so a single slow
upstream — and the client-metadata fetch is one any unauthenticated caller can point at a
slow origin — takes `/healthz` with it. A container healthcheck that times out on a
healthy-but-busy gateway restarts it, which is the field consequence.

The probe therefore does three things, in an order that makes the third mean something:

1. **The negative control, first.** A direct `/healthz` call, with nothing in flight, gives
   the gateway's own latency. A probe that only measured "during" would not know whether a
   slow answer was the load or the host.
2. **The slow leg.** An authorization request is sent whose client id is a metadata document
   hosted on a deliberately slow origin, so the gateway enters a fetch it will hold for
   several seconds. The origin must be one the deployment allowlists; the probe takes the
   URL and the origin from its arguments so it states what it is measuring.
3. **`/healthz` during the leg.** Issued at the moment the fetch is in flight. It must
   answer, and answer close to the control's latency. A gateway that fetched on the loop
   would answer this only after the slow origin gave up.

The assertion is on the ratio rather than an absolute bound: the control measures this
host's latency, and the "during" measurement is compared against it. Nothing here prints a
credential — the probe sends no token at all.

Usage:
    PYTHONUTF8=1 python scripts/probe_liveness.py \
        --slow-client-id https://<allowlisted-host>/<path> \
        --slow-seconds 5
"""

from __future__ import annotations

import argparse
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import SpikeError

# The public origin the composed router publishes. Matches `GATEWAY_PUBLIC_ORIGIN`.
DEFAULT_ORIGIN = "http://localhost:8090"

# The toolset the local mapping names.
DEFAULT_TOOLSET = "notion"

# The statuses this probe asserts on.
HTTP_OK = 200
HTTP_FOUND = 302

# How many times the control is sampled, and the multiple of the control's worst sample that
# the "during" answer may reach. Generous on purpose: the assertion is "the loop was free",
# and a bound set at the control's exact value would fail on scheduler noise.
CONTROL_SAMPLES = 3
DURING_BUDGET_MULTIPLE = 10

# A floor on the budget, in seconds: a control that measured a fraction of a millisecond
# would make the multiple meaningless, so the budget never drops below this.
BUDGET_FLOOR_SECONDS = 0.5


class ProbeError(SpikeError):
    """A probe could not complete a step it needs; the message is safe to print."""


class LivenessError(SpikeError):
    """The gateway did not answer a liveness probe with the status this battery expects."""


def _get(url: str, *, timeout: float) -> tuple[int, float, str]:
    """GET a URL, returning its status, its duration, and its body."""
    started = time.monotonic()
    # The URL is the caller's argument, an http(s) URL the operator names on the command
    # line; there is no untrusted input here and no other scheme in play.
    request = urllib.request.Request(  # noqa: S310 - operator-supplied local endpoint
        url, headers={"User-Agent": "dial-mcp-gateway-probe/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read().decode("utf-8", errors="replace")
            return response.status, time.monotonic() - started, body
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")
        return error.code, time.monotonic() - started, body


def _authorize_url(origin: str, toolset: str, client_id: str, redirect_uri: str) -> str:
    """The authorization request whose client id triggers a metadata-document fetch."""
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": "probe-challenge",
            "code_challenge_method": "S256",
            "resource": f"{origin}/dial/{toolset}/mcp",
            "state": uuid.uuid4().hex,
        }
    )
    return f"{origin}/dial/authorize?{query}"


def _result(label: str, passed: bool, detail: str) -> bool:
    mark = "PASS" if passed else "FAIL"
    print(f"[{mark}] {label}: {detail}")
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    parser.add_argument("--toolset", default=DEFAULT_TOOLSET)
    parser.add_argument(
        "--slow-client-id",
        required=True,
        help="A client-id metadata document URL on a slow, allowlisted origin.",
    )
    parser.add_argument(
        "--slow-seconds",
        type=float,
        default=5.0,
        help="How long the slow origin holds its response open.",
    )
    parser.add_argument(
        "--redirect-uri",
        default="http://127.0.0.1:8766/callback",
        help="A redirect URI the document registers.",
    )
    args = parser.parse_args()

    verdicts: list[bool] = []

    print(f"origin={args.origin} slow_client_id={args.slow_client_id}")
    print(f"slow_origin_hold={args.slow_seconds}s")

    # 1. The control: the gateway's own latency with nothing in flight.
    control_times: list[float] = []
    for _ in range(CONTROL_SAMPLES):
        status, duration, _body = _get(f"{args.origin}/healthz", timeout=30)
        if status != HTTP_OK:
            message = f"/healthz answered {status} with nothing in flight"
            raise LivenessError(message)
        control_times.append(duration)
    control_worst = max(control_times)
    budget = max(BUDGET_FLOOR_SECONDS, control_worst * DURING_BUDGET_MULTIPLE)
    print(f"control /healthz: samples={[f'{t:.4f}s' for t in control_times]}")
    verdicts.append(
        _result("control", control_worst < 1.0, f"worst={control_worst:.4f}s")
    )

    # 2. Start the slow leg in a background thread and let it reach the outbound fetch.
    slow_outcome: dict[str, object] = {}

    def slow_leg() -> None:
        try:
            status, duration, body = _get(
                _authorize_url(
                    args.origin, args.toolset, args.slow_client_id, args.redirect_uri
                ),
                timeout=args.slow_seconds + 30,
            )
            slow_outcome["status"] = status
            slow_outcome["duration"] = duration
            slow_outcome["body"] = body
        except Exception as error:  # reported as the probe's own failure, not raised
            slow_outcome["error"] = f"{type(error).__name__}: {error}"

    worker = threading.Thread(target=slow_leg, daemon=True)
    worker.start()

    # Let the request arrive and reach the fetch. A fraction of the hold, so the fetch is
    # certainly in flight when the probe below is issued.
    time.sleep(max(0.5, args.slow_seconds / 5))

    # 3. `/healthz` while the leg is held open.
    probe_status, probe_duration, _body = _get(f"{args.origin}/healthz", timeout=30)
    print(f"during the held-open leg: /healthz {probe_status} in {probe_duration:.4f}s")
    verdicts.append(
        _result(
            "healthz answers during a slow outbound leg",
            probe_status == HTTP_OK and probe_duration < budget,
            f"status={probe_status} duration={probe_duration:.4f}s budget={budget:.4f}s",
        )
    )

    worker.join(timeout=args.slow_seconds + 30)
    if "error" in slow_outcome:
        print(f"[INFO] the slow leg ended with: {slow_outcome['error']}")
    else:
        print(
            f"[INFO] the slow leg answered {slow_outcome.get('status')} "
            f"in {float(slow_outcome.get('duration', 0)):.2f}s "
            f"(the fetch was held for ~{args.slow_seconds}s)"
        )

    passed = all(verdicts)
    print(f"VERDICT: {'PASS' if passed else 'FAIL'}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
