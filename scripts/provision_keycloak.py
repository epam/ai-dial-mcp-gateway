"""Provision the gateway's Keycloak client through the realm's Admin API.

The gateway authenticates the human under its own pre-registered confidential client, so
that client has to exist in the realm before any sign-in can complete. This script
creates it, idempotently: run it twice and the second run changes nothing.

What it creates, and why each part is what it is:

* **Confidential, standard flow only.** The gateway is the deployment's own confidential
  client at the identity provider: its secret authenticates every identity-leg token
  request (the code exchange and the refresh grant), in both positions of the PKCE
  toggle. The realm's client is therefore registered confidential — never as a public
  client, for which no secret exists — and the script converges the client's secret to
  the one the local profile holds: `IDP_CLIENT_SECRET` from `.env` where the profile
  carries it, and a freshly generated value written back to `.env` where it does not, so
  the realm and the gateway hold the same credential.
* **PKCE S256 required.** The identity-provider leg sends a challenge and keeps the
  verifier on its own flow record, so an intercepted callback code is not redeemable.
  The challenge composes with the client's secret authentication; it never replaces it.
* **Default scopes `profile,email`.** These are the scopes the identity-provider redirect
  requests, and no others — never `openid` (not a client scope in this realm, so
  requesting it fails the whole leg), never `offline_access` (the gateway acquires no
  beyond-session grant; what it carries is the session-bound refresh token the exchange
  issues, encrypted under its own custody key).
* **A `project` user-attribute mapper and a roles mapper.** Core reads the user's roles
  and project attribution from claims, so the identity token the gateway copies must
  carry them under the names Core's provider entry reads. The roles mapper reads the
  client role of the DIAL chat client, which is where the local realm grants `admin`.
* **The realm's rotation reuse detection, set on.** Beyond the client, the script
  converges one realm-level token-policy fact — `revokeRefreshToken` (see
  `REALM_REVOKE_REFRESH_TOKEN`) — because the custody design presents the provider's
  session refresh token on the internal leg once per refresh and this setting is the
  theft-containment control where that leg is plain HTTP (the dev shape). It is the only
  realm-level field the script manages; everything else the realm holds is left as it is.

The realm's administration credential comes from `.env`
(`KEYCLOAK_ADMIN_USER`/`KEYCLOAK_ADMIN_PASSWORD`), never from this file: a password in a
committed script is a blocking defect. Nothing here prints a credential — the admin token
appears as a redacted handle, and the client secret is written to the local profile's
`.env`, never printed.

Usage:
    PYTHONUTF8=1 python scripts/provision_keycloak.py
    PYTHONUTF8=1 python scripts/provision_keycloak.py --show-token-shape
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import secrets
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from spike_env import (
    HTTP_OK,
    SpikeError,
    decode_claims,
    load_env,
    redact,
    request,
    require,
)

# The realm the local instance serves.
REALM = "dial"

# Whether the realm revokes a refresh-token chain when a superseded token is replayed.
#
# The gateway's custody design presents the provider's session refresh token on the
# internal leg once per refresh; a network peer reading that leg holds a mintable
# credential. On a plain-http internal leg (this deployment's dev shape) rotation reuse
# detection IS the theft-containment control: the gateway's own next refresh races a
# lifted string, the first replay revokes the whole chain for thief and owner alike, and
# the event is loud (`idp_session_ended` on the refresh). Deployments that run TLS'd
# internal legs — the production shape — close the sniffing exposure at the transport,
# and this setting is then defense-in-depth rather than the bound. Keycloak's image
# default leaves it off, so the realm this script owns sets it on.
REALM_REVOKE_REFRESH_TOKEN = True

# The Idle the idle-gap check (e) temporarily sets when the realm's own Idle cannot be
# waited out (it equals Max, or is simply too long). The check needs a gap longer than
# Idle but shorter than Max, which no gap can satisfy when Idle == Max; lowering Idle for
# the duration of the check — and restoring it after — is what makes the check feasible.
# The margin is the slack past Idle the check waits, so the gap is unambiguously longer
# than Idle rather than exactly at it.
IDLE_GAP_TEMPORARY_SECONDS = 300
IDLE_GAP_MARGIN_SECONDS = 30

# The gateway's public origin and the callback the flow returns through. The redirect URI
# must be exactly the path the gateway's own router serves and the flow builds; a
# mismatch surfaces as a refused redirect at the consent screen, far from its cause.
GATEWAY_PUBLIC_ORIGIN = "http://localhost:8090"
GATEWAY_REDIRECT_URI = f"{GATEWAY_PUBLIC_ORIGIN}/dial/callback/idp"

# The scopes the identity-provider redirect *requests*. Keycloak encodes this set in the
# in-token `scope` claim the flow then discards, and it is the string the gateway's
# `IDP_CLIENT_SCOPES` setting mirrors.
REQUESTED_SCOPES = ("profile", "email")

# The client scopes attached to the client as defaults, which is a larger set than the one
# requested: a default scope contributes its mappers whether or not the request names it.
# `basic` is the one that carries the `sub` mapper, and `sub` is the subject Core
# authorizes with — a client without it mints tokens the gateway must refuse. `basic` also
# has `include.in.token.scope` off, so it never appears in the requested scope string; the
# template client's two-scope default set is a template for a client whose subject is not
# needed, and following it literally here would produce unusable tokens.
DEFAULT_CLIENT_SCOPES = ("profile", "email", "basic")

# The DIAL chat client whose client role carries the realm's DIAL roles. The local realm
# grants the `admin` role here (verified against the live realm), so the mapper reads
# from it and a token minted through this client carries the role Core's admin rule
# matches.
ROLES_SOURCE_CLIENT = "dial-chat"

# The claim names the mappers write. `roles` and `project` are the two Core's
# identity-provider entry reads (`rolePath`, `projectPath`); `email` arrives through the
# `email` default client scope.
ROLES_CLAIM = "roles"
PROJECT_CLAIM = "project"

# The name of the client scope that maps `project` in this deployment. The project mapper
# on this background deployment is a custom provider there; the local realm tracks the
# per-user `project` attribute, so the mapper here is the standard user-attribute mapper
# under the same claim name — the claim is what Core reads, and this is the mapper that
# produces it from the local realm's own user attribute.
_PROJECT_USER_ATTRIBUTE = "project"

# What this script is allowed to change about the client it manages. Everything here is a
# property the sign-in depends on; anything else the realm holds for the client stays as
# it is, so a re-run does not flatten unrelated state.
MANAGED_ATTRIBUTES = {
    # The challenge method is pinned to S256 — the only method that does not hand the
    # verifier to anyone who can see the redirect. The challenge composes with the
    # client's secret authentication; it never replaces it.
    "pkce.code.challenge.method": "S256",
    "backchannel.logout.session.required": "true",
    "backchannel.logout.revoke.offline.tokens": "false",
    "realm_client": "false",
}


class AdminLoginError(SpikeError):
    """The realm's administrative credential was refused."""

    def __init__(self, status: int) -> None:
        super().__init__(f"the Keycloak admin login failed with HTTP {status}")


class AdminCallError(SpikeError):
    """A realm administration call the script needs did not succeed."""

    def __init__(self, method: str, path: str, status: int, body: str) -> None:
        super().__init__(f"{method} {path} failed with HTTP {status}: {_trim(body)}")


class ClientMissingError(SpikeError):
    """The client was expected to exist and does not."""

    def __init__(self, client_id: str) -> None:
        super().__init__(f"client {client_id!r} is not in the realm")


class LoginFormMissingError(SpikeError):
    """The authorize redirect did not render the login form."""

    def __init__(self) -> None:
        super().__init__(
            "the authorize redirect did not render the login form; the client may not "
            "exist yet, or its redirect URI may not be registered"
        )


class ScopeMissingError(SpikeError):
    """The realm has no client scope the gateway's redirect would request."""

    def __init__(self, name: str, available: list[str]) -> None:
        super().__init__(
            f"the realm has no client scope named {name!r}, so the gateway's redirect "
            f"could not request it; available: {', '.join(available)}"
        )


class EnvFileMissingError(SpikeError):
    """The local profile's `.env` file, which the secret is written back to, is absent."""

    def __init__(self, path: Path) -> None:
        super().__init__(f"the local profile's .env does not exist at {path}")


def _trim(body: str, limit: int = 300) -> str:
    """A bounded excerpt of a response body, for an error message.

    Keycloak's error bodies describe the *request* that failed, never a credential, so
    the excerpt is safe to print; it is bounded because a validation error can be long.
    """
    collapsed = " ".join(body.split())
    return collapsed[:limit] + ("…" if len(collapsed) > limit else "")


def admin_base(env: dict[str, str]) -> str:
    """The realm's Admin API base URL, reached over the host's admin port."""
    return f"{require(env, 'KEYCLOAK_ADMIN_URL').rstrip('/')}/admin/realms/{REALM}"


def login(env: dict[str, str]) -> str:
    """Exchange the `.env` admin credential for an admin token.

    The token is returned to the caller and never written anywhere: it lives for the
    length of one provisioning run.
    """
    url = (
        f"{require(env, 'KEYCLOAK_ADMIN_URL').rstrip('/')}"
        f"/realms/master/protocol/openid-connect/token"
    )
    status, body, _ = request(
        "POST",
        url,
        form={
            "client_id": "admin-cli",
            "username": require(env, "KEYCLOAK_ADMIN_USER"),
            "password": require(env, "KEYCLOAK_ADMIN_PASSWORD"),
            "grant_type": "password",
        },
    )
    if status != HTTP_OK:
        raise AdminLoginError(status)
    return json.loads(body)["access_token"]


def admin_call(
    method: str,
    url: str,
    token: str,
    payload: dict[str, Any] | None = None,
) -> tuple[int, str]:
    """One administration call, with the failure body surfaced rather than swallowed."""
    status, body, _ = request(
        method,
        url,
        body=payload,
        token=token,
        headers={"Content-Type": "application/json"},
    )
    return status, body


def desired_client(client_id: str, client_secret: str) -> dict[str, Any]:
    """The client representation this script manages.

    Written as the whole shape rather than as a diff so a re-run converges: whatever the
    realm holds for these fields is replaced by exactly this. The secret is part of the
    shape — the realm's client must hold the credential the gateway presents.
    """
    return {
        "clientId": client_id,
        "name": client_id,
        "description": (
            "DIAL MCP sign-in gateway: the gateway's own confidential client, used to "
            "authenticate the human in the browser during the toolset sign-in flow."
        ),
        "enabled": True,
        "protocol": "openid-connect",
        # A confidential client: the gateway authenticates every identity-leg token
        # request with its secret, so the realm's client must expect one. There is no
        # public-client shape to fall back to.
        "publicClient": False,
        # The credential the gateway's token requests present, converged to the local
        # profile's value (the profile's `.env` and the realm hold the same secret).
        "secret": client_secret,
        "bearerOnly": False,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        # No password or client-credentials grant: the only job here is signing a human
        # in through the browser.
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "consentRequired": False,
        "frontchannelLogout": False,
        # Left on, as the template client has it. With it off the realm refuses the code
        # exchange outright — `not_allowed: Offline tokens not allowed for the user or
        # client`, an error about the client's scope configuration that names a scope
        # this client never requests. It also buys nothing here: the client's default
        # scopes are only `profile,email`, so the role-bearing `roles` client scope is
        # absent and no extra role collection enters the token either way.
        "fullScopeAllowed": True,
        "redirectUris": [GATEWAY_REDIRECT_URI],
        "webOrigins": [GATEWAY_PUBLIC_ORIGIN],
        "attributes": dict(MANAGED_ATTRIBUTES),
        "protocolMappers": [
            {
                "name": "project claim (the per-user attribution)",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-attribute-mapper",
                "consentRequired": False,
                "config": {
                    "user.attribute": _PROJECT_USER_ATTRIBUTE,
                    "claim.name": PROJECT_CLAIM,
                    "jsonType.label": "String",
                    "access.token.claim": "true",
                    "id.token.claim": "true",
                    "userinfo.token.claim": "true",
                    "introspection.token.claim": "true",
                },
            },
            {
                "name": "DIAL roles",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-usermodel-client-role-mapper",
                "consentRequired": False,
                "config": {
                    "usermodel.clientRoleMapping.clientId": ROLES_SOURCE_CLIENT,
                    "claim.name": ROLES_CLAIM,
                    "jsonType.label": "String",
                    "multivalued": "true",
                    "access.token.claim": "true",
                    "id.token.claim": "true",
                    "userinfo.token.claim": "true",
                    "introspection.token.claim": "true",
                },
            },
        ],
    }


def find_client(base: str, token: str, client_id: str) -> dict[str, Any] | None:
    """The existing client, by exact client id, or `None` when the realm has none.

    The lookup is by `clientId` rather than by id so a re-run finds the client whatever
    internal id the realm assigned it.
    """
    query = urllib.parse.urlencode({"clientId": client_id})
    status, body = admin_call("GET", f"{base}/clients?{query}", token)
    if status != HTTP_OK:
        raise AdminCallError("GET", "/clients", status, body)
    clients = json.loads(body)
    # Keycloak's `clientId` filter is a contains-match, so an exact filter is applied
    # here: provisioning the wrong client would be a silent, damaging edit.
    for client in clients:
        if client.get("clientId") == client_id:
            return client
    return None


def managed_state_differs(
    existing: dict[str, Any], desired: dict[str, Any]
) -> list[str]:
    """The managed fields whose current value differs from the desired one.

    Reporting the field names makes a re-run's "updated" verdict explain itself: an
    operator reading "redirectUris" learns what drifted.
    """
    differing: list[str] = []
    for field in (
        "redirectUris",
        "webOrigins",
        "publicClient",
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
        "consentRequired",
        "fullScopeAllowed",
        "enabled",
        "protocol",
    ):
        current = existing.get(field)
        wanted = desired[field]
        if isinstance(wanted, list):
            # Keycloak may return the same set in a different order, which is not a
            # difference worth rewriting the client for.
            if sorted(current or []) != sorted(wanted):
                differing.append(field)
        elif current != wanted:
            differing.append(field)

    current_attributes = existing.get("attributes") or {}
    for name, value in MANAGED_ATTRIBUTES.items():
        if current_attributes.get(name) != value:
            differing.append(f"attributes.{name}")

    if _mappers_differ(
        existing.get("protocolMappers") or [], desired["protocolMappers"]
    ):
        differing.append("protocolMappers")
    return differing


def _mappers_differ(
    current: list[dict[str, Any]], wanted: list[dict[str, Any]]
) -> bool:
    """Whether the two mapper sets differ in the properties this script manages.

    Compared by mapper name and the `config` entries, because a mapper's server-assigned
    `id` changes on every write and is not a difference.
    """
    by_name = {mapper.get("name"): mapper for mapper in current}
    for mapper in wanted:
        present = by_name.get(mapper["name"])
        if present is None:
            return True
        if present.get("protocolMapper") != mapper["protocolMapper"]:
            return True
        present_config = present.get("config") or {}
        for key, value in mapper["config"].items():
            if str(present_config.get(key)) != str(value):
                return True
    return False


def create_client(base: str, token: str, client: dict[str, Any]) -> str:
    """Create the client and return the realm-assigned id.

    The created id is read back rather than assumed: Keycloak answers a create with a
    `Location` header, and the client scopes below are addressed by that id.
    """
    status, body = admin_call("POST", f"{base}/clients", token, client)
    if status not in (201, 204):
        raise AdminCallError("POST", "/clients", status, body)
    created = find_client(base, token, client["clientId"])
    if created is None:
        raise AdminCallError(
            "POST", "/clients", status, "the client was not found after creation"
        )
    return created["id"]


def update_client(
    base: str, token: str, client_id: str, client: dict[str, Any]
) -> None:
    """Replace the client's managed representation, keeping its internal id."""
    status, body = admin_call("PUT", f"{base}/clients/{client_id}", token, client)
    if status not in (204, 200):
        raise AdminCallError("PUT", f"/clients/{client_id}", status, body)


def set_default_scopes(
    base: str, token: str, client_id: str, scopes: tuple[str, ...]
) -> list[str]:
    """Converge the client's default scopes to exactly the named set, by scope id.

    Keycloak addresses default client scopes by the scope's own internal id, so the
    realm's scope list is read and resolved by name. A name the realm does not have is a
    refusal rather than a silent omission: the identity-provider redirect requests
    exactly this set, and a missing scope fails the whole authorization leg.

    Scopes the realm attached on its own are removed, not merely left alone. A fresh
    client inherits the realm's default-scope list, which here includes `offline_access`
    — a scope the gateway's flow must never exercise, because it would acquire a
    beyond-session grant the design deliberately does not take (the gateway carries only
    the session-bound refresh token, never an offline one). Removing it is the only way
    the client's carried scopes are the designed set rather than the realm's.
    """
    status, body = admin_call("GET", f"{base}/client-scopes", token)
    if status != HTTP_OK:
        raise AdminCallError("GET", "/client-scopes", status, body)
    available = {scope["name"]: scope["id"] for scope in json.loads(body)}

    status, body = admin_call(
        "GET", f"{base}/clients/{client_id}/default-client-scopes", token
    )
    if status != HTTP_OK:
        raise AdminCallError(
            "GET", f"/clients/{client_id}/default-client-scopes", status, body
        )
    current = {scope["name"]: scope["id"] for scope in json.loads(body)}

    for name in scopes:
        if name not in available:
            raise ScopeMissingError(name, sorted(available))

    changes: list[str] = []
    for name in scopes:
        if name in current:
            continue
        status, body = admin_call(
            "PUT",
            f"{base}/clients/{client_id}/default-client-scopes/{available[name]}",
            token,
        )
        if status not in (204, 200):
            raise AdminCallError(
                "PUT",
                f"/clients/{client_id}/default-client-scopes/{name}",
                status,
                body,
            )
        changes.append(f"+{name}")

    for name, scope_id in current.items():
        if name in scopes:
            continue
        status, body = admin_call(
            "DELETE",
            f"{base}/clients/{client_id}/default-client-scopes/{scope_id}",
            token,
        )
        if status not in (204, 200):
            raise AdminCallError(
                "DELETE",
                f"/clients/{client_id}/default-client-scopes/{name}",
                status,
                body,
            )
        changes.append(f"-{name}")
    return changes


def converge_realm_token_policy(env: dict[str, str]) -> bool:
    """Converge the realm's rotation reuse detection; report whether it changed.

    Only `revokeRefreshToken` is touched (see the constant for why it is set). The realm
    is read first, so a second run that already matches writes nothing and the run is a
    genuine no-op.
    """
    base = admin_base(env)
    token = login(env)
    status, body = admin_call("GET", base, token)
    if status != HTTP_OK:
        raise AdminCallError("GET", "", status, body)
    realm = json.loads(body)
    if realm.get("revokeRefreshToken") == REALM_REVOKE_REFRESH_TOKEN:
        return False
    realm["revokeRefreshToken"] = REALM_REVOKE_REFRESH_TOKEN
    status, body = admin_call("PUT", base, token, realm)
    if status not in (204, 200):
        raise AdminCallError("PUT", "", status, body)
    return True


def _write_client_secret_to_env(value: str) -> bool:
    """Converge the local profile's `.env` on `IDP_CLIENT_SECRET`; report a change.

    The profile the helper itself reads is the one file that must carry the secret beside
    the realm's client: a value in the realm only would leave the gateway with nothing to
    present. An existing line is replaced in place, a missing one appended, and the
    file's other lines are untouched.
    """
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        raise EnvFileMissingError(env_path)
    lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    entry = f"IDP_CLIENT_SECRET={value}"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("IDP_CLIENT_SECRET="):
            if stripped == entry:
                return False
            ending = "\r\n" if line.endswith("\r\n") else "\n"
            lines[index] = entry + ending
            break
    else:
        # Append after making sure the file's last line ends, so the new entry starts
        # on a line of its own.
        if lines and not lines[-1].endswith(("\r\n", "\n")):
            lines[-1] += "\n"
        ending = "\r\n" if lines and lines[-1].endswith("\r\n") else "\n"
        lines.append(entry + ending)
    env_path.write_text("".join(lines), encoding="utf-8")
    return True


def provision(env: dict[str, str], client_id: str) -> str:
    """Create or converge the client, and report which of the two happened.

    The whole operation is idempotent: an existing client whose managed fields already
    match is left untouched, one that has drifted is rewritten to the desired shape, and
    only a client the realm does not have is created. The client's secret is part of the
    converged shape: the profile's `IDP_CLIENT_SECRET` where the local `.env` carries
    one, a freshly generated value written back to the `.env` where it does not.
    """
    base = admin_base(env)
    token = login(env)
    print(f"admin login -> {redact(token)}")

    if converge_realm_token_policy(env):
        print(
            "realm token policy: revokeRefreshToken set to "
            f"{REALM_REVOKE_REFRESH_TOKEN} (rotation reuse detection on)"
        )
    else:
        print(
            "realm token policy: revokeRefreshToken already "
            f"{REALM_REVOKE_REFRESH_TOKEN}; nothing changed"
        )

    env_secret = env.get("IDP_CLIENT_SECRET", "").strip()
    secret = env_secret or secrets.token_urlsafe(32)
    desired = desired_client(client_id, secret)
    existing = find_client(base, token, client_id)

    if existing is None:
        internal_id = create_client(base, token, desired)
        print(f"client {client_id!r} created (id={internal_id})")
        outcome = "created"
    else:
        internal_id = existing["id"]
        differing = managed_state_differs(existing, desired)
        if differing or not env_secret:
            # Where the profile held no secret, the realm's existing one cannot be
            # trusted to match the value about to be written to the profile, so the
            # client is converged to the generated value even when nothing else drifted.
            update_client(base, token, internal_id, desired)
            print(
                f"client {client_id!r} updated to the managed shape; fields that "
                f"differed: {', '.join(sorted(differing)) or 'the client secret'}"
            )
            outcome = "updated"
        else:
            print(f"client {client_id!r} already matches; nothing changed")
            outcome = "unchanged"

    if not env_secret and _write_client_secret_to_env(secret):
        print("client secret: generated and written to .env as IDP_CLIENT_SECRET")

    scope_changes = set_default_scopes(base, token, internal_id, DEFAULT_CLIENT_SCOPES)
    if scope_changes:
        outcome = "updated" if outcome == "unchanged" else outcome
        print(f"default client scopes changed: {', '.join(scope_changes)}")
    print(
        f"default client scopes: {', '.join(DEFAULT_CLIENT_SCOPES)} "
        f"(the client's whole carried set)"
    )
    print(f"redirect URI:          {GATEWAY_REDIRECT_URI}")

    final = find_client(base, token, client_id)
    if final is None:
        raise ClientMissingError(client_id)
    print()
    print("=== client as the realm now holds it (no secret material below) ===")
    for field in (
        "clientId",
        "publicClient",
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
        "redirectUris",
        "fullScopeAllowed",
    ):
        print(f"  {field:28s} = {json.dumps(final.get(field))}")
    print(f"  attributes                   = {json.dumps(final.get('attributes'))}")
    for mapper in final.get("protocolMappers", []):
        config = mapper.get("config") or {}
        print(
            f"  mapper {mapper['name']!r} -> {config.get('claim.name')} "
            f"({mapper['protocolMapper']})"
        )
    return outcome


def verify_claims(env: dict[str, str], client_id: str) -> int:
    """Run a real authorization-code flow against the client and report what it minted.

    The check that matters is not that the client exists but that a token obtained
    *through it* carries the claims Core reads: `sub`, `roles`, `project`, and `email`.
    A mapper that is present but wired to the wrong client role, or a default scope that
    never made it onto the client, both surface here as a missing or empty claim.
    """
    obtained = obtain_session_document(env, client_id)
    if obtained is None:
        return 1
    document, _ = obtained

    access_token = document["access_token"]
    claims = decode_claims(access_token)
    print("=== token minted through the provisioned client (no token shown) ===")
    print(f"  access token = {redact(access_token)}")
    for claim in ("iss", "sub", "roles", "project", "email"):
        print(f"  {claim:9s} = {json.dumps(claims.get(claim))}")
    print(f"  scope     = {document.get('scope')}")
    print(f"  refresh   = {'present' if document.get('refresh_token') else 'absent'}")

    missing = [
        claim for claim in ("sub", "roles", "project", "email") if not claims.get(claim)
    ]
    if missing:
        print(f"FAIL: claims Core reads are absent or empty: {', '.join(missing)}")
        return 1
    print("OK: every claim Core's provider entry reads is present and non-empty")
    return 0


def verify_refresh(env: dict[str, str], client_id: str, *, idle_gap: bool) -> int:
    """Drive the provider facts the refresh-claims re-read depends on, against the realm.

    Every check here is a fact the gateway's design *rests on* but cannot verify at startup,
    so it is driven rather than assumed:

    (a) the code exchange issues a **session-bound** refresh token, and the requested scopes
        never include `offline_access` — the M13 line, as amended;
    (b) the refresh grant against that token returns a fresh **verifiable** token carrying
        the roles path and the per-user attribution claims — the same read the flow performs
        at every refresh;
    (c) a superseded (rotated-out) provider refresh token is refused, and revoking the
        session kills the token — the revocation-propagation fact the acceptance depends on;
    (d) the realm's actual SSO Session Idle/Max values fit the configured refresh window;
    (e) a refresh on a normal cadence survives past the realm's SSO Session Idle — the
        idle-refresh-on-use fact the local window rests on. The realm's own Idle (86400s,
        equal to Max) cannot be waited out and cannot even distinguish renewal from the
        Max cap, so the check temporarily lowers Idle to a short value and restores it
        (opt-in: it still takes minutes, so it is a deliberate long-running check).
    """
    obtained = obtain_session_document(env, client_id)
    if obtained is None:
        return 1
    document, _verifier = obtained

    refresh_token = document.get("refresh_token")
    if not refresh_token:
        print(
            "FAIL (a): the code exchange issued no refresh token for this client. The "
            "refresh claims re-read requires one; a provider must issue session-bound "
            "refresh tokens to this client at the exchange."
        )
        return 1

    failures = 0
    failures += _check_grant_shape(document)
    fresh = refresh_once(env, client_id, refresh_token)
    failures += _check_refresh_read(fresh)
    failures += _check_rotation_reuse(env, client_id, refresh_token, fresh)
    failures += _check_session_window(env)
    failures += _check_idle_gap(env, client_id, idle_gap=idle_gap)
    failures += _check_revocation(env, client_id)
    return 1 if failures else 0


def _check_grant_shape(document: dict[str, Any]) -> int:
    """(a) The exchange's granted scopes never include `offline_access`."""
    granted_scopes = str(document.get("scope", ""))
    if "offline_access" in granted_scopes:
        print(
            f"FAIL (a): the granted scopes include offline_access: {granted_scopes!r}"
        )
        return 1
    print(
        f"OK (a): the exchange issued a session-bound refresh token; scopes = "
        f"{granted_scopes!r} (no offline_access)"
    )
    return 0


def _check_refresh_read(fresh: dict[str, Any] | None) -> int:
    """(b) The refresh grant's fresh token carries the claims Core reads."""
    if fresh is None:
        print("FAIL (b): the refresh grant did not return a usable token")
        return 1
    claims = decode_claims(fresh["access_token"])
    missing = [claim for claim in ("sub", "roles", "project") if not claims.get(claim)]
    if missing:
        print(
            f"FAIL (b): the fresh token is missing claims Core reads: {', '.join(missing)}"
        )
        return 1
    print(
        "OK (b): the refresh grant returned a fresh token carrying sub, roles, and project"
    )
    return 0


def _check_rotation_reuse(
    env: dict[str, str],
    client_id: str,
    refresh_token: str,
    fresh: dict[str, Any] | None,
) -> int:
    """(c, reuse) A superseded provider refresh token is refused on reuse."""
    rotated_out = fresh.get("refresh_token") if fresh else None
    if not rotated_out or rotated_out == refresh_token:
        print(
            "WARN (c): the realm did not rotate the provider refresh token on the grant, "
            "so reuse detection could not be exercised"
        )
        return 0
    if refresh_once(env, client_id, refresh_token) is None:
        print("OK (c): a superseded provider refresh token is refused on reuse")
        return 0
    print(
        "FAIL (c): a superseded provider refresh token was accepted again — the realm's "
        "rotation reuse detection is not revoking the chain"
    )
    return 1


def _check_session_window(env: dict[str, str]) -> int:
    """(d) The realm's SSO Session Idle/Max against the configured refresh window.

    The Max is the operative cap under a normal refresh cadence (grant use renews the idle
    timer), so a window past the Max is a failure; a window past only the Idle is a warning
    the idle-gap check resolves.
    """
    idle = realm_seconds(env, "ssoSessionIdleTimeout")
    maximum = realm_seconds(env, "ssoSessionMaxLifespan")
    configured = int(env.get("GATEWAY_REFRESH_TTL_SECONDS", "28800"))
    print(
        f"  (d) realm SSO Session Idle = {idle}s, Max = {maximum}s, "
        f"GATEWAY_REFRESH_TTL_SECONDS = {configured}s"
    )
    if maximum is not None and configured > maximum:
        print(
            f"FAIL (d): the configured refresh window ({configured}s) exceeds the realm's "
            f"SSO Session Max ({maximum}s): sessions end at the Max with an "
            f"`idp_session_ended` refusal, so the window does not fit the provider policy"
        )
        return 1
    if idle is not None and configured > idle:
        print(
            f"WARN (d): the configured refresh window ({configured}s) exceeds the realm's "
            f"SSO Session Idle ({idle}s); refresh use renews the idle timer, so a normal "
            f"cadence stays inside SSO Session Max — check (e) verifies that below"
        )
        return 0
    print("OK (d): the configured refresh window fits the realm's session policy")
    return 0


def _check_idle_gap(
    env: dict[str, str],
    client_id: str,
    *,
    idle_gap: bool,
) -> int:
    """(e) A refresh past the realm's SSO Session Idle still succeeds, on a live cadence.

    The fact this drives: the gateway's refresh cadence renews the provider session's
    idle timer, so under a normal cadence the operative cap is **SSO Session Max**, not
    Idle — the configured refresh window rests on that fact, and a realm whose idle
    timer is not refreshed by grant use would kill every session at the idle bound.

    Feasibility. The realm's own Idle is 86400s (equal to Max), so waiting it out is not
    a check anyone can run, and a realm with Idle == Max cannot even distinguish "grant
    use renews the idle timer" from "the Max cap applies". When Idle is too long to wait
    inline, the check temporarily lowers it to a short value, drives the cadence, and
    restores the original Idle in a `finally` path — the mutation and its restoration are
    printed, so the realm's transient state is never silent.
    """
    if not idle_gap:
        print("SKIP (e): pass --verify-refresh-idle-gap to run the idle-gap check")
        return 0
    idle = realm_seconds(env, "ssoSessionIdleTimeout") or 0
    if idle <= 0:
        print("WARN (e): the realm declares no SSO Session Idle, so no gap to wait out")
        return 0

    restore_idle: int | None = None
    effective_idle = idle
    if idle > IDLE_GAP_TEMPORARY_SECONDS:
        if not _set_realm_idle(env, IDLE_GAP_TEMPORARY_SECONDS):
            print(
                "WARN (e): the realm's SSO Session Idle is too long to wait out and "
                "could not be lowered temporarily; the check is skipped"
            )
            return 0
        restore_idle = idle
        effective_idle = IDLE_GAP_TEMPORARY_SECONDS
        print(
            f"  (e) temporarily lowered the realm's SSO Session Idle "
            f"{idle}s -> {effective_idle}s for this check; it is restored afterwards"
        )
    try:
        return _drive_idle_gap(env, client_id, effective_idle)
    finally:
        if restore_idle is not None:
            if _set_realm_idle(env, restore_idle):
                print(f"  (e) restored the realm's SSO Session Idle to {restore_idle}s")
            else:
                print(
                    f"  (e) FAILED to restore the realm's SSO Session Idle to "
                    f"{restore_idle}s — restore it by hand"
                )


def _drive_idle_gap(env: dict[str, str], client_id: str, idle: int) -> int:
    """One refresh inside the idle window, then one past it — both must succeed.

    The interval proves the renewal: the second refresh lands more than `idle` seconds
    after the session was created, yet only ~`idle/2 + margin` seconds after the first
    refresh, which succeeded only because the first refresh renewed the idle timer. A
    realm that did not renew on use would have killed the session at the idle bound and
    the second refresh would be refused.
    """
    obtained = obtain_session_document(env, client_id)
    if obtained is None:
        print(
            "FAIL (e): a fresh session could not be established for the idle-gap check"
        )
        return 1
    document, _ = obtained
    token = document.get("refresh_token")
    if not token:
        print("FAIL (e): the fresh session carried no refresh token")
        return 1

    half = idle // 2
    print(f"  (e) refresh 1 at {half}s (inside the {idle}s idle window) ...")
    time.sleep(half)
    first = refresh_once(env, client_id, token)
    if first is None:
        print("FAIL (e): the first refresh (inside the idle window) was refused")
        return 1
    token = first.get("refresh_token") or token

    wait = idle - half + IDLE_GAP_MARGIN_SECONDS
    print(
        f"  (e) refresh 2 at {idle + IDLE_GAP_MARGIN_SECONDS}s from the session's "
        f"creation (past the {idle}s idle window), {wait}s after refresh 1 ..."
    )
    time.sleep(wait)
    if refresh_once(env, client_id, token) is not None:
        print(
            "OK (e): a refresh past the idle window succeeded — grant use renews the "
            "idle timer, so the operative cap is SSO Session Max"
        )
        return 0
    print(
        "FAIL (e): a refresh past the idle window was refused — the idle timer is not "
        "renewed by grant use, so the local window is a fiction"
    )
    return 1


def _check_revocation(env: dict[str, str], client_id: str) -> int:
    """(c, revocation) Revoking the session kills the refresh token.

    Establishes its own session rather than reusing the one the reuse check presents: with
    rotation reuse detection on, that check revokes the whole chain it touches, so a shared
    chain would make this one pass for the reuse check's reason instead of the session's.
    """
    obtained = obtain_session_document(env, client_id)
    if obtained is None:
        print("WARN (c-revocation): a fresh session could not be established")
        return 0
    document, _ = obtained
    token = document.get("refresh_token")
    if not token:
        print("WARN (c-revocation): the fresh session carried no refresh token")
        return 0
    if not revoke_user_sessions(env):
        print(
            "WARN (c-revocation): the session could not be revoked through the Admin API"
        )
        return 0
    if refresh_once(env, client_id, token) is None:
        print(
            "OK (c-revocation): after the session was revoked, the provider refused the "
            "refresh — revocation propagates to the refresh capability"
        )
        return 0
    print(
        "FAIL (c-revocation): the refresh still succeeded after the session was revoked"
    )
    return 1


def obtain_session_document(
    env: dict[str, str], client_id: str
) -> tuple[dict[str, Any], str] | None:
    """Walk a browserless authorization-code flow and return the token-endpoint document.

    The whole flow a real harness drives — authorize, login, callback, code exchange — run
    without a browser so it can stand in a gate. The exchange authenticates the
    confidential client with the profile's `IDP_CLIENT_SECRET` — the same credential the
    gateway presents — because the realm refuses an unauthenticated exchange for this
    client. Returns the exchange's JSON document and the PKCE verifier used, or `None`
    after printing why it could not complete.
    """
    issuer = require(env, "IDP_ISSUER")

    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(16)
    redirect_uri = GATEWAY_REDIRECT_URI

    captured: dict[str, str] = {}
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            captured.update({key: value[0] for key, value in params.items()})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h3>Probe callback</h3></body></html>")
            done.set()

        def log_message(self, *args: object) -> None:
            """Silence the stdlib's per-request logging (it prints the query string)."""

    server = HTTPServer(("127.0.0.1", 8090), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": " ".join(REQUESTED_SCOPES),
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    authorize_url = (
        f"{issuer}/protocol/openid-connect/auth?{urllib.parse.urlencode(params)}"
    )

    try:
        action_url, cookie = drive_login_form(env, authorize_url)
    except SpikeError as exc:
        server.shutdown()
        print(f"verification could not drive the login form: {exc}")
        return None

    # The form is submitted to the action URL the login page itself rendered, which
    # carries the flow's `session_code` and `execution`: the realm's generic
    # `/login-actions/authenticate` path answers 400 without them. The page's session
    # cookie is replayed for the same reason — Keycloak binds the flow to it.
    status, body, headers = request(
        "POST",
        action_url,
        form={"username": env["TEST_USER_NAME"], "password": env["TEST_USER_PASSWORD"]},
        headers={"Cookie": cookie},
    )

    # A successful authentication redirects back to the redirect URI; the callback
    # listener catches the code. A failure re-renders the form with an error.
    if not done.wait(20):
        server.shutdown()
        print(f"login did not complete (HTTP {status}); no code arrived")
        return None
    server.shutdown()
    del body, headers

    code = captured.get("code")
    if not code or captured.get("state") != state:
        print(f"the callback carried no usable code: {sorted(captured)}")
        return None

    status, body, _ = request(
        "POST",
        token_endpoint(env),
        form={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": require(env, "IDP_CLIENT_SECRET"),
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )
    if status != HTTP_OK:
        print(f"the code exchange failed with HTTP {status}: {_trim(body)}")
        return None
    return json.loads(body), verifier


def refresh_once(
    env: dict[str, str], client_id: str, refresh_token: str
) -> dict[str, Any] | None:
    """Perform one provider refresh grant (RFC 6749 §6), or return `None` on refusal.

    The grant authenticates the confidential client with the profile's
    `IDP_CLIENT_SECRET`, as every identity-leg token request does.
    """
    status, body, _ = request(
        "POST",
        token_endpoint(env),
        form={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": require(env, "IDP_CLIENT_SECRET"),
            "refresh_token": refresh_token,
        },
    )
    if status != HTTP_OK:
        return None
    document = json.loads(body)
    return document if document.get("access_token") else None


def token_endpoint(env: dict[str, str]) -> str:
    """The realm's token endpoint as the host-run helper reaches it."""
    return (
        f"{require(env, 'KEYCLOAK_ADMIN_URL').rstrip('/')}"
        f"/realms/{REALM}/protocol/openid-connect/token"
    )


def realm_seconds(env: dict[str, str], member: str) -> int | None:
    """One of the realm's session-timeout members, in seconds, or `None` when absent."""
    token = login(env)
    status, body = admin_call("GET", admin_base(env), token)
    if status != HTTP_OK:
        return None
    value = json.loads(body).get(member)
    return value if isinstance(value, int) else None


def _set_realm_idle(env: dict[str, str], idle: int) -> bool:
    """Set the realm's SSO Session Idle, preserving every other realm field.

    The realm is read and written back whole, because Keycloak's realm PUT replaces the
    representation: a partial write would drop the fields this script does not manage.
    Returns whether the write succeeded, so the caller can report a failed restore rather
    than leave the realm silently mutated.
    """
    base = admin_base(env)
    token = login(env)
    status, body = admin_call("GET", base, token)
    if status != HTTP_OK:
        return False
    realm = json.loads(body)
    realm["ssoSessionIdleTimeout"] = idle
    status, _ = admin_call("PUT", base, token, realm)
    return status in (204, 200)


def revoke_user_sessions(env: dict[str, str]) -> bool:
    """Log the test user out of every session, through the Admin API."""
    token = login(env)
    base = admin_base(env)
    username = require(env, "TEST_USER_NAME")
    query = urllib.parse.urlencode({"username": username, "exact": "true"})
    status, body = admin_call("GET", f"{base}/users?{query}", token)
    if status != HTTP_OK:
        return False
    users = json.loads(body)
    if not users:
        return False
    user_id = users[0]["id"]
    status, _ = admin_call("POST", f"{base}/users/{user_id}/logout", token)
    return status in (204, 200)


_FORM_ACTION = re.compile(r'<form[^>]*\baction="([^"]+)"')


def drive_login_form(env: dict[str, str], authorize_url: str) -> tuple[str, str]:
    """Follow the authorize redirect to the login form; return its action URL and cookie.

    Keycloak's login is a two-step form: the authorize redirect renders an authentication
    page whose form action carries the flow's `session_code` and `execution`, and that
    action — not a fixed path — is what the credential is submitted to. Reading the
    action out of the page is what makes the verification browser-free and runnable in a
    gate.
    """
    del env  # the URL is built by the caller; kept for a symmetric signature
    status, body, headers = request("GET", authorize_url)
    if status != HTTP_OK:
        raise AdminCallError("GET", authorize_url, status, body)
    cookie = "; ".join(
        value.split(";")[0]
        for key, value in headers.items()
        if key.lower() == "set-cookie"
    )
    match = _FORM_ACTION.search(body)
    if match is None or "login-actions/authenticate" not in match.group(1):
        raise LoginFormMissingError
    # The page escapes `&` in the action because it is HTML; the wire URL is unescaped.
    return html.unescape(match.group(1)), cookie


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--client-id",
        default=None,
        help="the client to provision (default: IDP_CLIENT_ID, then dial-mcp-proxy)",
    )
    parser.add_argument(
        "--verify-claims",
        action="store_true",
        help=(
            "after provisioning, complete a real authorization-code flow against the "
            "client and report the claims it minted (drives the realm's login form with "
            "the test user's .env credential; no browser)"
        ),
    )
    parser.add_argument(
        "--verify-refresh",
        action="store_true",
        help=(
            "after provisioning, drive the provider facts the refresh-claims re-read "
            "rests on: the session-bound refresh token at the exchange, the refresh grant "
            "returning fresh verifiable claims, rotation reuse and session revocation, and "
            "the realm's SSO Session Idle/Max against GATEWAY_REFRESH_TTL_SECONDS"
        ),
    )
    parser.add_argument(
        "--verify-refresh-idle-gap",
        action="store_true",
        help=(
            "with --verify-refresh, also drive a refresh cadence past the realm's SSO "
            "Session Idle and prove it still succeeds (lowering Idle temporarily and "
            "restoring it; a minutes-long check)"
        ),
    )
    args = parser.parse_args()

    env = load_env()
    client_id = args.client_id or env.get("IDP_CLIENT_ID") or "dial-mcp-proxy"

    outcome = provision(env, client_id)

    if args.verify_claims:
        print()
        return verify_claims(env, client_id)

    if args.verify_refresh:
        print()
        return verify_refresh(env, client_id, idle_gap=args.verify_refresh_idle_gap)

    print()
    if outcome == "unchanged":
        print("second run was a no-op: the client is already the desired shape")
    return 0


if __name__ == "__main__":
    sys.exit(main())
