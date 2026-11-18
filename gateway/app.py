"""Application factory.

Builds the FastAPI application the container runs: liveness, the discovery documents, the
client-facing authorization-server surface, and the assembled runtime the routes read.

The app is built through `create_app` rather than at import time, and uvicorn is run with
`--factory`: settings validation and runtime assembly are *startup* concerns, and a
required setting that is missing — or a registration store that cannot be read — must fail
the container's start with a readable error, not produce an un-importable module whose
traceback only says the import failed.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from gateway.authorize import router as authorize_router
from gateway.federation import router as federation_router
from gateway.routes import router as surface_router
from gateway.runtime import Runtime
from gateway.settings import Settings
from gateway.token import router as token_router

# The gateway's own logger for failures that produced a response. Separate from the audit
# logger: an audit record answers "who did what", while this answers "what broke", and the
# two have different readers and different retention.
_LOGGER = logging.getLogger("gateway.app")


def create_app(
    settings: Settings | None = None,
    runtime: Runtime | None = None,
) -> FastAPI:
    """Build the gateway application.

    `settings` and `runtime` are injectable so a test can hand in a configuration without
    touching the environment, and so a refusal path can be exercised without
    process-level setup. A supplied runtime carries its own settings, and the two must
    agree — they are two views of one configuration, and a mismatch would make the app's
    routes read a different configuration than the app reports.
    """
    if runtime is None:
        resolved = settings or Settings()
        runtime = Runtime.build(resolved)
    else:
        resolved = runtime.settings
        if settings is not None and settings is not resolved:
            message = (
                "create_app was given both a runtime and a different settings object; "
                "the routes read the runtime's settings, so passing two would leave the "
                "app reporting a configuration it does not use"
            )
            raise ValueError(message)

    app = FastAPI(
        title="DIAL MCP sign-in gateway",
        # Interactive docs are not part of the surface a harness uses, and on a service
        # whose endpoints handle authorization codes an unauthenticated schema browser
        # is unnecessary exposure.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = resolved
    app.state.runtime = runtime

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        """Liveness probe for the compose-boot gate.

        Deliberately dependency-free: it answers whether this process is up and serving,
        which is what a container healthcheck needs. Reachability of Core or the identity
        provider is measured by the flow paths, not by this probe — a probe that fails
        when a dependency is down would restart a gateway that is working correctly.
        """
        return {"status": "ok"}

    app.include_router(surface_router)
    app.include_router(authorize_router)
    app.include_router(federation_router)
    app.include_router(token_router)

    @app.exception_handler(Exception)
    async def unhandled_error(_request: object, exc: Exception) -> JSONResponse:
        """Answer an unexpected failure without describing it, and log it in full.

        The split is between the two audiences. The client gets a fixed sentence — a stack
        trace or a library message can carry a value from the request (a code, a token, a
        client-supplied string) into a response body, and there is nothing a client can do
        with the detail anyway. The operator gets the exception type and the traceback in
        the gateway's own log, because a bug that produced no record at all is a bug that
        can only be rediscovered, never diagnosed. The failure fails closed rather than
        half-completing either way.

        Defining this handler suppresses Starlette's own 500 logging, so the logging here
        is what stands in for it: without it an unexpected failure would be entirely silent.
        """
        # The exception is passed as `exc_info` rather than read from the ambient
        # exception state: the traceback belongs to the failure being handled here, and
        # it must not depend on this call happening inside the frame that caught it.
        _LOGGER.error(
            "the gateway could not complete a request (%s)",
            type(exc).__name__,
            exc_info=exc,
        )
        return JSONResponse(
            {
                "error": "server_error",
                "error_description": "the gateway could not complete this request",
            },
            status_code=500,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return app
