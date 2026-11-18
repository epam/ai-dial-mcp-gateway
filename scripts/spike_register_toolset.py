"""Register the `notion` toolset in DIAL Core through the documented recipe (Stage 0 spike).

The spike needs a real OAuth-protected toolset to prove that a token it minted resolves
that user's upstream credential. Establishing one is a precondition, so it lives here as
committed material rather than as an improvised step: if the spike's precondition cannot
be reproduced from this repository, the falsification gate could be blocked by an
environment accident and would prove nothing.

Two facts shape the call:

- Only `PUT` (creation) triggers Core's dynamic client registration against the upstream
  authorization server, so the toolset is created through the API, never declared in
  `config.json` — a config-declared toolset never gets its OAuth settings populated.
- In dynamic-registration mode `redirect_uri` is the only permitted `auth_settings`
  field. Core discovers the client id, endpoints, and scopes from the upstream's own
  metadata; naming any of them is rejected as a forbidden field.

A third fact is what `--replace` exists for: Core does **not** store the `redirect_uri`
this body carries. It registers the deployment's configured `allowedRedirectUris` with the
upstream and stores the **first** entry back as the toolset's `auth_settings.redirect_uri`.
A `PUT` over an existing toolset therefore cannot move that value — it answers `412` with
the idempotency header, and without it, `400` demanding the explicit OAuth fields the
dynamic-registration mode forbids. Re-registering means deleting first (`--replace`), and
the deployment's `allowedRedirectUris` must carry the gateway's callback **first** — see
`docs/local-environment.md` and `evidence/finding-toolset-redirect-uri.md`.

The call is admin-gated in Core: it answers 403 unless the caller's token carries the
role Core's admin rule matches. The token comes from `.env` (gitignored) — never
hardcoded — and nothing here prints it.

Usage:
    PYTHONUTF8=1 python scripts/spike_register_toolset.py
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

TOOLSET = "notion"
TOOLSET_BUCKET = "platform"
ENDPOINT = "https://mcp.notion.com/mcp"

# The statuses this helper distinguishes in Core's answer: the write is admin-gated, the
# precondition header makes a repeat write distinguishable from a real error, and a fresh
# creation answers either OK or Created.
HTTP_CREATED = 201
HTTP_FORBIDDEN = 403
HTTP_PRECONDITION_FAILED = 412

# The upstream callback the toolset's registration names: the gateway's own upstream
# callback, so the upstream consent returns to the gateway (which exchanges the code via
# Core's sign-in API) rather than to a retired local helper's loopback port. Core does not
# store the `redirect_uri` this body carries: it registers the allowlist's entries with the
# upstream and stores the FIRST one back as the toolset's `auth_settings.redirect_uri`, so
# the deployment's `allowedRedirectUris` must carry this value first — see
# `docs/local-environment.md`.
REDIRECT_URI = "http://localhost:8090/dial/callback/upstream"

# The creation body, limited to the fields the dynamic-registration validator permits.
CREATE_BODY = {
    "display_name": "Notion",
    "endpoint": ENDPOINT,
    "transport": "HTTP",
    "description": "Notion MCP (upstream OAuth2, sign-in driven by the client)",
    "auth_settings": {
        "authentication_type": "OAUTH",
        "redirect_uri": REDIRECT_URI,
    },
}

# The projection read back to verify the registration. These are the fields a sign-in
# helper builds the upstream authorize URL from; a missing one breaks the flow.
PUBLIC_SETTINGS_FIELDS = (
    "client_id",
    "authorization_endpoint",
    "redirect_uri",
    "code_challenge",
    "code_challenge_method",
    "scopes_supported",
    "dynamically_registered",
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--replace",
        action="store_true",
        help="delete the toolset first, so the upstream registration step re-runs",
    )
    args = parser.parse_args()

    env = load_env()
    core = env["DIAL_CORE_URL"]
    # The admin-authorized client: its user token carries the role Core's admin rule
    # matches, which is what admits the platform-bucket write below.
    token = request_user_token(
        env, "KEYCLOAK_TOKEN_CLIENT_ID", "KEYCLOAK_TOKEN_CLIENT_SECRET"
    )
    toolset_url = f"{core}/v1/toolsets/{TOOLSET_BUCKET}/{TOOLSET}"

    if args.replace:
        status, body, _ = request("DELETE", toolset_url, token=token)
        print(f"DELETE {toolset_url} (cleanup) -> HTTP {status} {body[:120]}")

    status, body, _ = request(
        "PUT",
        toolset_url,
        body=CREATE_BODY,
        token=token,
        headers={"If-None-Match": "*"},
    )
    print(f"PUT {toolset_url} -> HTTP {status}")
    if status == HTTP_FORBIDDEN:
        print("  the caller's token does not carry Core's admin role; check the .env")
        print("  token client, whose mapper is what puts the role into the token")
        return 1
    if status == HTTP_PRECONDITION_FAILED:
        print("  the toolset already exists (idempotent success; --replace re-runs it)")
    elif status not in (HTTP_OK, HTTP_CREATED):
        print(f"  body = {body[:400]}")
        return 1
    print()

    status, body, _ = request("GET", toolset_url, token=token)
    print(f"GET {toolset_url} -> HTTP {status}")
    if status != HTTP_OK:
        print(f"  body = {body[:400]}")
        return 1

    settings = json.loads(body).get("auth_settings", {})
    print("  public OAuth settings (no secret material):")
    for field in PUBLIC_SETTINGS_FIELDS:
        print(f"    {field:24s} = {json.dumps(settings.get(field))}")

    problems = _projection_problems(settings)
    for problem in problems:
        print(f"  {problem}")
    if problems:
        return 1
    print()
    print("registration verified: the toolset's public OAuth settings are complete")
    return 0


def _projection_problems(settings: dict) -> list[str]:
    """What the read-back says is wrong with the registration, in the order it matters.

    Three failures, each with its own remedy, so they are reported together rather than
    one run at a time.
    """
    problems: list[str] = []
    # The verifier and the client secret must not appear: Core holds both internally,
    # which is why only Core can exchange the upstream authorization code.
    leaked = [key for key in ("code_verifier", "client_secret") if key in settings]
    if leaked:
        problems.append(
            f"UNEXPECTED fields exposed by Core's public projection: {leaked}"
        )

    missing = [field for field in PUBLIC_SETTINGS_FIELDS if settings.get(field) is None]
    if missing:
        problems.append(f"MISSING fields: {missing}")

    # The stored callback is Core's own choice, not this body's: it is the first entry of
    # the deployment's `allowedRedirectUris`. A mismatch means the sign-in flow will send
    # the browser to whatever that entry is, so it is caught here rather than surfacing as
    # a connection failure after a real user has consented upstream.
    stored = settings.get("redirect_uri")
    if stored != REDIRECT_URI:
        problems.append(
            f"the stored redirect_uri is {json.dumps(stored)}, not the gateway's "
            f"callback {json.dumps(REDIRECT_URI)}: Core stores the FIRST entry of "
            "aidial.toolsets.security.allowedRedirectUris. Reorder that list so the "
            "gateway's callback comes first, then re-run this script with --replace."
        )
    return problems


if __name__ == "__main__":
    sys.exit(main())
