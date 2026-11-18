"""Register the `skills-demo` app in DIAL Core through the documented apps recipe.

The apps acceptance run needs a real app resource whose declaration carries an `mcp` block,
because Core's `ApplicationMcpProxyController` refuses an application whose `mcp` block is
null. No app resource exists in this repository's local environment — its Compose stack and
Core's static `config.json` list none — so this script is the committed way to establish the
precondition, the sibling of `scripts/spike_register_toolset.py`.

Two facts shape the call:

- API-managed applications live under the platform bucket and are created through Core's
  configuration-resource route (`PUT /v1/applications/platform/{name}`), a pure upsert
  honoring RFC 7232 `If-None-Match: *` (create-only; `412` when the resource already
  exists). Like the toolset recipe, an app is created through the API, never declared in
  `config.json`, so Core's proxy has a stored declaration to read.
- The app MCP upstream leg attaches no stored credential: the injector sends the app id and
  optional header config only. So the fixture's endpoint needs no upstream credential, and a
  keyless fixture keeps the acceptance hermetic.

`--replace` exists for the same reason it does on the toolset script: a `PUT` over an
existing app answers `412`, so re-registering means deleting first, and the flag does that.

The call is admin-gated in Core: it answers 403 unless the caller's token carries the role
Core's admin rule matches. The token comes from `.env` (gitignored) — never hardcoded — and
nothing here prints it.

Usage:
    PYTHONUTF8=1 python scripts/spike_register_app.py [--replace]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import (
    HTTP_OK,
    load_env,
    request,
    request_user_token,
)

APP = "skills-demo"
APP_BUCKET = "platform"

# The fixture's MCP endpoint, reached by Core by service name on the instance network (the
# `mcp-app-fixture` service in `docker-compose.yml`). A service-name URL rather than a host
# one: Core is the caller on this leg, and it resolves the fixture inside the compose network.
ENDPOINT = "http://mcp-app-fixture:9000/mcp"

# The statuses this helper distinguishes in Core's answer: the write is admin-gated, the
# create-only precondition makes a repeat write distinguishable from a real error, and a
# fresh creation answers either OK or Created.
HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_PRECONDITION_FAILED = 412

# The creation body. An application carries a display name, the upstream endpoint, and the
# `mcp` block Core's apps MCP proxy reads — that block is the whole reason this fixture
# exists: a null `mcp` block is refused by `ApplicationMcpProxyController`.
CREATE_BODY = {
    "display_name": "Skills demo (MCP fixture)",
    "endpoint": ENDPOINT,
    "mcp": {"endpoint": ENDPOINT},
}

# The projection read back to verify the registration. The `mcp` block is the field the
# acceptance depends on; the rest are the identity fields Core serves for any app.
PUBLIC_SETTINGS_FIELDS = ("display_name", "endpoint", "mcp")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="delete the app first, so a repeat registration re-runs cleanly",
    )
    args = parser.parse_args()

    env = load_env()
    core = env["DIAL_CORE_URL"]
    # The admin-authorized client: its user token carries the role Core's admin rule
    # matches, which is what admits the platform-bucket write below.
    token = request_user_token(
        env, "KEYCLOAK_TOKEN_CLIENT_ID", "KEYCLOAK_TOKEN_CLIENT_SECRET"
    )
    app_url = f"{core}/v1/applications/{APP_BUCKET}/{APP}"

    if args.replace:
        status, body, _ = request("DELETE", app_url, token=token)
        print(f"DELETE {app_url} (cleanup) -> HTTP {status} {body[:120]}")

    status, body, _ = request(
        "PUT",
        app_url,
        body=CREATE_BODY,
        token=token,
        headers={"If-None-Match": "*"},
    )
    print(f"PUT {app_url} -> HTTP {status}")
    if status == HTTP_FORBIDDEN:
        print("  the caller's token does not carry Core's admin role; check the .env")
        print("  token client, whose mapper is what puts the role into the token")
        return 1
    if status == HTTP_PRECONDITION_FAILED:
        print("  the app already exists (idempotent success; --replace re-runs it)")
    elif status not in (HTTP_OK, HTTP_CREATED):
        print(f"  body = {body[:400]}")
        return 1
    print()

    status, body, _ = request("GET", app_url, token=token)
    print(f"GET {app_url} -> HTTP {status}")
    if status != HTTP_OK:
        print(f"  body = {body[:400]}")
        return 1

    document = json.loads(body)
    print("  app declaration (no secret material):")
    for field in PUBLIC_SETTINGS_FIELDS:
        print(f"    {field:14s} = {json.dumps(document.get(field))}")

    problems = _declaration_problems(document)
    for problem in problems:
        print(f"  {problem}")
    if problems:
        return 1
    print()
    print("registration verified: the app carries an mcp block Core can proxy")
    return 0


def _declaration_problems(document: dict) -> list[str]:
    """What the read-back says is wrong with the registration, in the order it matters.

    The single load-bearing failure is a missing or null `mcp` block: Core's
    `ApplicationMcpProxyController` refuses an application without one, so the acceptance run
    has no MCP path to reach. The endpoint is checked inside the block because the proxy reads
    it to build the upstream URL.
    """
    problems: list[str] = []
    mcp = document.get("mcp")
    if not isinstance(mcp, dict):
        problems.append(
            "MISSING `mcp` block: Core's apps MCP proxy refuses an application whose "
            "`mcp` block is null, so the acceptance run has no MCP path to reach"
        )
        return problems
    if not mcp.get("endpoint"):
        problems.append(
            "MISSING `mcp.endpoint`: the block carries no upstream URL for Core to proxy to"
        )
    if mcp.get("endpoint") != ENDPOINT:
        problems.append(
            f"the stored endpoint is {json.dumps(mcp.get('endpoint'))}, not the fixture's "
            f"{json.dumps(ENDPOINT)}: the acceptance reaches the fixture by service name on "
            "the instance network, so the two must match"
        )
    return problems


if __name__ == "__main__":
    sys.exit(main())
