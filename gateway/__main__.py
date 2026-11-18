"""Process entry point.

Reads the environment into `Settings`, wires the gateway's own logging, and hands the app
to uvicorn. Kept separate from `gateway.app` so that importing the package never validates
configuration or installs handlers — a test can import `create_app` with settings of its
own and attach the handlers its assertions inspect, while the container's start fails
loudly if a required setting is missing.
"""

from __future__ import annotations

import logging
import sys
import time

import uvicorn

from gateway.app import create_app
from gateway.settings import Settings

# The logger namespace every module in this package logs under (`gateway.audit`,
# `gateway.store`, `gateway.app`), and therefore the single point at which the service's
# own records can be routed. The audit trail is the reason this exists: its records are
# emitted at INFO, so without a handler and an INFO level somewhere above them the
# platform's root logger — whose level is WARNING and which carries no handlers of its
# own — drops every one of them, and the gateway then has no audit trail an operator can
# read at all.
_PACKAGE_LOGGER = "gateway"

# The attribute that marks the handler this module installs. A process can reach this
# function more than once (a re-import, a test, a future reloader), and an audit trail
# that prints every event twice is worse than one that prints it once: a collector
# reading the log would count two flows where one ran. The mark makes installing the
# handler idempotent without depending on a module-level flag, which a re-import would
# reset.
_HANDLER_MARK = "_dial_mcp_gateway_handler"

# One line per record, and the values a log collector needs to correlate records from
# several processes: when, how severe, which part of the service, and what. The message
# itself is already a JSON document for audit records (see `gateway.audit._emit`), so this
# prefix adds the metadata a line-oriented reader would otherwise have to guess at. A
# traceback appended to an error record is the one thing that legitimately spans lines —
# it is how a failure gets diagnosed.
_FORMAT = "%(asctime)s %(levelname)s %(name)s %(message)s"

# The timestamp format, applied in UTC. Stated here rather than inline so the formatter's
# default and the deployed format cannot drift.
_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S"


class _UtcFormatter(logging.Formatter):
    """A formatter that stamps every record with an unambiguous UTC instant.

    The default formatter renders a naive local time, and `%z` renders nothing at all
    from one — so two hosts in different zones, or one host across a DST change, would
    produce audit lines that cannot be ordered against each other. An operator
    reconstructing a sign-in correlates these stamps against Core's and the identity
    provider's, which log in UTC, so the conversion happens here rather than in the
    reader's head.
    """

    # The name is the standard library's, which is what makes the override take effect;
    # `logging.Formatter` calls it by that name, so it cannot be renamed to suit the rule.
    def formatTime(  # noqa: N802
        self, record: logging.LogRecord, datefmt: str | None = None
    ) -> str:
        rendered = time.strftime(datefmt or _DATE_FORMAT, time.gmtime(record.created))
        # `gmtime` yields no zone offset for a format string to render, so the zone is
        # stated here rather than left for the reader to infer from the deployment.
        return f"{rendered}Z"


def configure_logging() -> None:
    """Route the gateway's own records to standard output at INFO, once.

    Called from `main()` and nowhere else: this is process startup, and a library, a test,
    or a request path must never reconfigure the logging of the process it runs in. That
    is also what keeps the tests hermetic — the suite asserts on audit records through
    handlers it attaches itself, and a configuration applied on import would displace
    them.

    The sink is standard output, which is where a container's log collector already reads
    and where `gateway.audit` says its records belong; the destination is a deployment
    concern. `propagate` is turned off so the records are written exactly once: with
    propagation left on, a deployment that also attaches a root handler would see a
    second copy of every audit record.

    Uvicorn's own loggers are deliberately untouched. Its access log carries request
    lines, which on the callback and token paths include authorization codes and tokens,
    so it stays off — `uvicorn.run` is called with `access_log=False` for the same reason.
    """
    logger = logging.getLogger(_PACKAGE_LOGGER)
    if any(getattr(handler, _HANDLER_MARK, False) for handler in logger.handlers):
        return

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    handler.setFormatter(_UtcFormatter(_FORMAT, datefmt=_DATE_FORMAT))
    setattr(handler, _HANDLER_MARK, True)

    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def main() -> None:
    configure_logging()
    settings = Settings()
    uvicorn.run(
        create_app(settings),
        # Container-internal only: the front router publishes the public port and is the
        # gateway's sole front door, so binding every interface inside the container is
        # required — the router reaches the gateway by container name, not by loopback.
        host="0.0.0.0",  # noqa: S104  # nosec B104
        port=settings.gateway_internal_port,
        # The access log carries request lines, which include authorization codes on the
        # callback paths; it stays off and the gateway emits its own audit records.
        access_log=False,
    )


if __name__ == "__main__":
    main()
