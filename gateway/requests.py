"""The request-body read the unauthenticated body-bearing endpoints share.

Three endpoints here take a body and none of them authenticates its caller: the
registration endpoint, the token endpoint, and the revocation endpoint. A request that is
merely large therefore costs the gateway memory before any validation runs, and the caller
chooses how large — so each of the three reads its body through the capped read below
rather than through the framework's own `request.body()`, which allocates whatever was
sent and only then leaves the size to be judged.

The cap is applied **while the bytes arrive**, not after: a cap enforced after the body
has been allocated has already allocated the memory it exists to bound, which is the whole
of the property. Reading incrementally means an over-cap body costs the gateway one chunk
past the limit and nothing more.
"""

from __future__ import annotations

from fastapi import Request


async def capped_body(request: Request, limit: int) -> bytes | None:
    """The request body's bytes, or `None` when it exceeds the limit.

    The read is chunked rather than whole: an over-cap body must stop costing memory at
    the cap, and the size of a chunk is the transport's business.

    `None` is the refusal, and it is deliberately not an exception, because each endpoint
    answers an over-cap body in its own audience's error shape — an RFC 6749 error
    document from the token endpoint, a plain-language one from the registration endpoint —
    so the shape belongs to the endpoint and only the measurement belongs here.
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)
    return b"".join(chunks)
