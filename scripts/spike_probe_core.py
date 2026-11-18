"""Present a minted token to Core and record what Core answers (Stage 0 spike).

One instrument serves the negative controls and the positive control: it sends a token to
`GET /v1/user/info` and to the toolset MCP path, and reports the status and a redacted
body. The negative controls are the instrument's proof that it can fail — a probe that
never returns a rejection proves nothing when it returns an acceptance.

Run the negative controls first:
    PYTHONUTF8=1 python scripts/spike_probe_core.py --token .secrets/spike-token-wrong-issuer.jwt
    PYTHONUTF8=1 python scripts/spike_probe_core.py --token .secrets/spike-token-no-audience.jwt
    PYTHONUTF8=1 python scripts/spike_probe_core.py --token .secrets/spike-token-unknown-key.jwt
Then the positive control:
    PYTHONUTF8=1 python scripts/spike_probe_core.py --token .secrets/spike-token-default.jwt --mcp
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import (
    HTTP_OK,
    SpikeError,
    decode_claims,
    load_env,
    redact,
    request,
)


class NoTokenFileError(SpikeError):
    """The token file the probe was pointed at does not exist."""

    def __init__(self, path: Path) -> None:
        super().__init__(f"no token file at {path}")


MCP_INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "dial-mcp-gateway-spike", "version": "0"},
    },
}
MCP_TOOLS_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}


def parse_streamable_http(raw: str) -> dict | None:
    """Read the first JSON-RPC message out of a streamable-HTTP response body.

    A streamable-HTTP reply is SSE (`data:` lines) when the server streams and plain JSON
    when it does not, and both are seen in practice, so both are handled.
    """
    for line in raw.splitlines():
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except ValueError:
                pass
    try:
        return json.loads(raw)
    except ValueError:
        return None


def mcp_call(core: str, toolset: str, payload: dict, token: str, timeout: int = 90):
    return request(
        "POST",
        f"{core}/v1/toolset/{toolset}/mcp",
        body=payload,
        token=token,
        headers={"Accept": "application/json, text/event-stream"},
        timeout=timeout,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", required=True, help="path to a token file")
    parser.add_argument("--toolset", default="notion")
    parser.add_argument("--mcp", action="store_true", help="also exercise the MCP path")
    parser.add_argument("--label", default=None, help="probe name for the record")
    args = parser.parse_args()

    env = load_env()
    core = env["DIAL_CORE_URL"]
    token_path = Path(args.token)
    if not token_path.is_file():
        raise NoTokenFileError(token_path)
    token = token_path.read_text(encoding="utf-8").strip()

    claims = decode_claims(token)
    label = args.label or token_path.stem
    print(f"=== probe: {label} ===")
    print(f"  token      {redact(token)}")
    print(f"  iss        {json.dumps(claims.get('iss'))}")
    print(f"  aud        {json.dumps(claims.get('aud'))}")
    print(f"  sub        {json.dumps(claims.get('sub'))}")
    print()

    status, body, headers = request("GET", f"{core}/v1/user/info", token=token)
    print(f"GET /v1/user/info -> HTTP {status}")
    if status == HTTP_OK:
        info = json.loads(body)
        print(f"  userId   = {info.get('userId')}")
        print(f"  roles    = {json.dumps(info.get('roles'))}")
    else:
        print(f"  body     = {body[:300]}")
    print()

    if not args.mcp:
        return 0

    status, body, headers = mcp_call(core, args.toolset, MCP_INITIALIZE, token)
    print(f"POST /v1/toolset/{args.toolset}/mcp initialize -> HTTP {status}")
    print(f"  WWW-Authenticate = {headers.get('WWW-Authenticate', '<absent>')}")
    message = parse_streamable_http(body)
    if status == HTTP_OK and message and "result" in message:
        server = message["result"].get("serverInfo", {})
        print(f"  serverInfo = {server.get('name')} {server.get('version')}")
    else:
        print(f"  body       = {body[:300]}")
    print()

    status, body, headers = mcp_call(core, args.toolset, MCP_TOOLS_LIST, token)
    print(f"POST /v1/toolset/{args.toolset}/mcp tools/list -> HTTP {status}")
    message = parse_streamable_http(body)
    if status == HTTP_OK and message and "result" in message:
        tools = message["result"].get("tools", [])
        names = [tool.get("name") for tool in tools]
        print(f"  tools      = {len(tools)}")
        print(f"  first      = {json.dumps(names[:5])}")
    else:
        print(f"  body       = {body[:300]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
