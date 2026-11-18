"""The C3 rotation drill instrument: the staged signing rotation and the custody overlap.

This is the drill's scripted leg set. It drives the composed stack through the
documented rotation procedures and records the observables the drill requirement names —
`kid`s, key-ids, JWKS snapshots, Core-acceptance verdicts, the gateway's own custody
refusal class — never key material, never token strings, never envelope contents. The
tokens it handles are shown only as redacted handles; the `kid`/key-id facts it reads come
from a token's unverified *header* and from the custody claim's clear key-id byte, neither
of which is secret.

The instrument is built so it can be proven **able to fail**: the `control` subcommand runs
a deliberately wrong expectation (an old-`kid` token asserted to verify after its retained
entry is removed) and records that it fails. Until that control fails, no verdict from the
legs is trusted.

Discovery of the design decisions here:

* The operator reconfiguration is `.env` alone (the blank-equals-unset rule lets the singular
  spelling be blanked while the structured spelling is set) plus the compose env-list step a
  structured `env` entry's `ref` variable implies. The env-list step is carried by a
  **gitignored override compose file** (`.secrets/rotation/override.yml`), so the drill edits
  no tracked file; the effective environment the container receives is the tracked list plus
  the override, which is exactly "the variable joins the compose environment list".
* The headless sign-in vehicle is the **app** flow (`skills-demo`): an app resource is
  credential-free by construction, so its flow mints directly through the consent checkpoint
  with no upstream consent leg a probe cannot cross. The toolset flow exists too, but it stops
  at the upstream authorization page without a real provider account, so it cannot complete
  headlessly.
* Recreate is always the whole deployment unit (`docker compose up -d --force-recreate`),
  never a single-service restart — the recorded trap that splits the shared namespace.

Run every subcommand through the PowerShell tool (Docker is WSL2 and `wsl` is refused under
this worktree's Bash isolation):

    PYTHONUTF8=1 python scripts/drill_rotation.py status
    PYTHONUTF8=1 python scripts/drill_rotation.py control
    PYTHONUTF8=1 python scripts/drill_rotation.py signing
    PYTHONUTF8=1 python scripts/drill_rotation.py custody
    PYTHONUTF8=1 python scripts/drill_rotation.py restore
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
# The worktree's own root, so `gateway` resolves here rather than to any install of the
# main checkout that happens to sit on the interpreter's path.
sys.path.insert(0, str(SCRIPT_DIR.parent))

# The probe battery's own primitives — the sign-in chain this drill drives is theirs.
from gateway.custody import carried_key_id  # noqa: E402

from probe_end_to_end import (  # noqa: E402
    DEFAULT_ORIGIN,
    _CallbackHandler,
    _handle_landing,
    _mcp_tools_list,
    _new_secrets,
    _ReusableServer,
    _Run,
    _Session,
    drive_login,
    probe_authorize,
    probe_callback,
    probe_discovery,
)
from spike_env import load_env  # noqa: E402

# The repository root, derived from this file so no machine-specific path is committed.
REPO = SCRIPT_DIR.parent
ENV_PATH = REPO / ".env"
ENV_BAK = REPO / ".secrets" / "rotation" / "env-drill.bak"
SCRATCH = REPO / ".secrets" / "rotation"
OVERRIDE = SCRATCH / "override.yml"

PROJECT = "c3-one-pod-and-keysets"
GATEWAY = f"{PROJECT}-mcp-signin-gateway-1"

# The worktree's path as WSL sees it, so `-f` resolves inside WSL rather than as a Windows
# path the Linux compose binary cannot open. Derived from REPO (a `C:\…` path becomes
# `/mnt/c/…`), so no machine-specific path is committed.
_WSL_PREFIX = "/mnt/" + REPO.drive.rstrip(":").lower() if REPO.drive else ""
WSL_DIR = _WSL_PREFIX + REPO.as_posix()[len(REPO.drive) :]
WSL_OVERRIDE = f"{WSL_DIR}/.secrets/rotation/override.yml"

APP = "skills-demo"
CALLBACK_PORT = 8767

# The declared Core JWKS-cache window the pre-publish wait is bound by
# (docs/gateway-configuration.md: 10 minutes).
DECLARED_CACHE_WINDOW_SECONDS = 600

# The two statuses the drill asserts on. Named so a comparison reads as the status rather
# than as a bare number.
HTTP_OK = 200
HTTP_BAD_REQUEST = 400

# The scratch key material the prior pass generated (still usable; verified at start).
SIGNING_OLD_PEM = REPO / ".secrets" / "rot-signing-OLD.pem"
SIGNING_NEW_PEM = REPO / ".secrets" / "rot-signing-NEW.pem"
CUSTODY_OLD_B64 = REPO / ".secrets" / "rot-custody-OLDC.b64"
CUSTODY_NEW_B64 = REPO / ".secrets" / "rot-custody-NEWC.b64"

# The per-entry `ref` environment variable names the structured keysets name. They join the
# compose environment list through the gitignored override.
VAR_SIGN_OLD = "SIGNING_KEY_ROT_OLD"
VAR_SIGN_NEW = "SIGNING_KEY_ROT_NEW"
VAR_CUST_OLD = "CUSTODY_KEY_ROT_OLDC"
VAR_CUST_NEW = "CUSTODY_KEY_ROT_NEWC"


# --------------------------------------------------------------------------- host shell


def wsl(*args: str, timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["wsl", "-e", *args],  # noqa: S607 - host-resolved, argv is fixed
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def compose(
    *args: str, with_override: bool = False, timeout: int = 600
) -> subprocess.CompletedProcess[str]:
    cmd = ["docker", "compose", "-p", PROJECT, "-f", f"{WSL_DIR}/docker-compose.yml"]
    if with_override:
        cmd += ["-f", WSL_OVERRIDE]
    cmd += list(args)
    return wsl(*cmd, timeout=timeout)


def recreate_unit(
    with_override: bool = True, build: bool = True
) -> subprocess.CompletedProcess[str]:
    """Recreate the whole deployment unit (never a single-service restart).

    `--build` is included so the container always runs the current source: a
    recreate-without-build runs whatever image was last built, and the drill's whole point is
    to exercise the code on disk. The layer cache makes this cheap after the first build.
    """
    args = ["up", "-d", "--force-recreate"]
    if build:
        args.append("--build")
    return compose(*args, with_override=with_override)


def gateway_logs(tail: int = 60) -> str:
    return wsl("docker", "logs", "--tail", str(tail), GATEWAY).stdout


def wait_healthy(timeout: int = 120) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = wsl("docker", "inspect", "--format", "{{.State.Health.Status}}", GATEWAY)
        if r.stdout.strip() == "healthy":
            return True
        time.sleep(2)
    return False


# --------------------------------------------------------------------------- env / override


def snapshot_env() -> None:
    if not ENV_BAK.exists():
        ENV_BAK.write_text(ENV_PATH.read_text(encoding="utf-8"), encoding="utf-8")


def restore_env() -> None:
    if ENV_BAK.exists():
        ENV_PATH.write_text(ENV_BAK.read_text(encoding="utf-8"), encoding="utf-8")


def set_env(updates: dict[str, str]) -> None:
    """Rewrite the given keys in `.env` in place, preserving every other line."""
    lines = ENV_PATH.read_text(encoding="utf-8").splitlines()
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            key = s.split("=", 1)[0].strip()
            if key in updates:
                out.append(f"{key}={updates[key]}")
                seen.add(key)
                continue
        out.append(line)
    for key, value in updates.items():
        if key not in seen:
            out.append(f"{key}={value}")
    ENV_PATH.write_text("\n".join(out) + "\n", encoding="utf-8")


def write_override() -> None:
    """The gitignored compose override carrying the per-entry `ref` variables.

    This is the compose env-list step the rotation procedure names: the shipped compose
    forwards a fixed allowlist, so a structured `env` entry's `ref` variable must join the
    effective list before the structured document can read it. The override adds it without
    editing a tracked file.
    """
    body = (
        "services:\n"
        "  mcp-signin-gateway:\n"
        "    environment:\n"
        f"      {VAR_SIGN_OLD}: ${{{VAR_SIGN_OLD}:-}}\n"
        f"      {VAR_SIGN_NEW}: ${{{VAR_SIGN_NEW}:-}}\n"
        f"      {VAR_CUST_OLD}: ${{{VAR_CUST_OLD}:-}}\n"
        f"      {VAR_CUST_NEW}: ${{{VAR_CUST_NEW}:-}}\n"
    )
    OVERRIDE.write_text(body, encoding="utf-8")


def remove_override() -> None:
    if OVERRIDE.exists():
        OVERRIDE.unlink()


# --------------------------------------------------------------------------- keyset config


def signing_structured(*, new_active: bool, old_retained: bool) -> str:
    """The structured signing keyset document for one stage.

    `new_active=False, old_retained=False` -> only the old key, active (pre-rotation).
    `new_active=False, old_retained=True`  -> old active, new retained (pre-publish).
    `new_active=True,  old_retained=True`  -> new active, old retained (post-promote drain).
    `new_active=True,  old_retained=False` -> only the new key, active (post-cut).
    """
    doc: dict[str, dict[str, str]] = {}
    if new_active:
        doc["rot-new"] = {"source": "env", "ref": VAR_SIGN_NEW, "role": "active"}
        if old_retained:
            doc["rot-old"] = {"source": "env", "ref": VAR_SIGN_OLD, "role": "retained"}
    else:
        doc["rot-old"] = {"source": "env", "ref": VAR_SIGN_OLD, "role": "active"}
        if old_retained:
            doc["rot-new"] = {"source": "env", "ref": VAR_SIGN_NEW, "role": "retained"}
    return json.dumps(doc, separators=(",", ":"))


def custody_structured(*, new_active: bool, old_retained: bool) -> str:
    doc: dict[str, dict[str, str]] = {}
    if new_active:
        doc["k-newc"] = {"source": "env", "ref": VAR_CUST_NEW, "role": "active"}
        if old_retained:
            doc["k-oldc"] = {"source": "env", "ref": VAR_CUST_OLD, "role": "retained"}
    else:
        doc["k-oldc"] = {"source": "env", "ref": VAR_CUST_OLD, "role": "active"}
        if old_retained:
            doc["k-newc"] = {"source": "env", "ref": VAR_CUST_NEW, "role": "retained"}
    return json.dumps(doc, separators=(",", ":"))


def configure(sign_doc: str | None, cust_doc: str | None) -> None:
    """Set the drill's `.env` + override, then recreate the unit and wait healthy.

    A blank singular `GATEWAY_SIGNING_KEY` is what frees the structured spelling: the
    blank-equals-unset rule reads it as unset, so the structured document is authoritative.
    """
    updates: dict[str, str] = {}
    if sign_doc is not None:
        updates["GATEWAY_SIGNING_KEY"] = ""  # blank -> unset (the landed rule)
        updates["GATEWAY_SIGNING_KEYS"] = sign_doc
    if cust_doc is not None:
        updates["GATEWAY_CUSTODY_KEYS"] = cust_doc
    # The `env` material the structured entries read, into `.env` where compose interpolates.
    # The container reads raw text, so a PEM's newlines are written escaped (`\n`).
    updates[VAR_SIGN_OLD] = (
        SIGNING_OLD_PEM.read_text(encoding="utf-8").replace("\n", "\\n").strip()
    )
    updates[VAR_SIGN_NEW] = (
        SIGNING_NEW_PEM.read_text(encoding="utf-8").replace("\n", "\\n").strip()
    )
    updates[VAR_CUST_OLD] = CUSTODY_OLD_B64.read_text(encoding="utf-8").strip()
    updates[VAR_CUST_NEW] = CUSTODY_NEW_B64.read_text(encoding="utf-8").strip()
    set_env(updates)
    write_override()
    up = recreate_unit(with_override=True)
    healthy = wait_healthy()
    if not healthy:
        logs = gateway_logs(tail=40)
        message = (
            f"the gateway did not become healthy after reconfigure.\n"
            f"compose rc={up.returncode} stderr={up.stderr[-400:]}\nlog tail:\n{logs[-1500:]}"
        )
        raise SystemExit(message)


# --------------------------------------------------------------------------- observables


def jwks_kids() -> list[str]:
    with urllib.request.urlopen(
        "http://localhost:8090/dial/jwks.json", timeout=30
    ) as resp:
        document = json.loads(resp.read())
    return [key.get("kid") for key in document.get("keys", [])]


def token_kid(token: str) -> str | None:
    """The `kid` from a token's unverified header (a public fact, not secret)."""
    header = token.split(".", maxsplit=1)[0]
    header += "=" * (-len(header) % 4)
    return json.loads(base64.urlsafe_b64decode(header)).get("kid")


def refresh_custody_key_id(refresh_token: str) -> str | None:
    """The custody claim's clear key-id inside a gateway refresh token (a public fact)."""
    payload = refresh_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    document = json.loads(base64.urlsafe_b64decode(payload))
    claim = document.get("custody")
    return carried_key_id(claim) if isinstance(claim, str) else None


def audit_has(token: str, tail: int = 120) -> bool:
    return token in gateway_logs(tail=tail)


# --------------------------------------------------------------------------- sign-in flow

_listener: _ReusableServer | None = None


def _ensure_listener() -> None:
    global _listener  # noqa: PLW0603 - one shared listener for the process lifetime
    if _listener is None:
        _listener = _ReusableServer(("127.0.0.1", CALLBACK_PORT), _CallbackHandler)
        threading.Thread(target=_listener.serve_forever, daemon=True).start()


def refresh(env: dict[str, str], run: _Run, refresh_token: str) -> dict:
    """One refresh at the token endpoint; returns status, body-members, and the new kids."""
    status, body, _hdrs = _Session().request(
        f"{run.origin}/dial/token",
        form={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": run.client_id,
            "resource": run.resource,
        },
    )
    result: dict = {"status": status}
    try:
        tokens = json.loads(body)
    except ValueError:
        result["body"] = body[:200]
        return result
    if status == HTTP_OK:
        result["access_token"] = tokens.get("access_token")
        result["refresh_token"] = tokens.get("refresh_token")
        result["access_kid"] = token_kid(tokens.get("access_token", ""))
        result["refresh_kid"] = token_kid(tokens.get("refresh_token", ""))
        result["refresh_custody_key_id"] = refresh_custody_key_id(
            tokens.get("refresh_token", "")
        )
    else:
        result["error"] = tokens.get("error")
        result["error_description"] = tokens.get("error_description")
    return result


def sign_in(env: dict[str, str], run: _Run) -> dict:
    """A complete headless app sign-in through the front door; returns the minted tokens."""
    _ensure_listener()
    _CallbackHandler.captured.clear()
    _CallbackHandler.done.clear()
    session = _Session()
    secrets_ = _new_secrets()
    probe_discovery(session, run)
    redirect = probe_authorize(session, run, secrets_)
    kind, value = drive_login(session, env, redirect, run)
    landed = _handle_landing(session, run, kind, value, deny=False)
    if landed is not None:
        message = f"the sign-in did not reach the mint (landed kind={kind})"
        raise RuntimeError(message)
    code = probe_callback(secrets_.state)
    status, body, _hdrs = session.request(
        f"{run.origin}/dial/token",
        form={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": run.client_id,
            "redirect_uri": run.redirect_uri,
            "code_verifier": secrets_.verifier,
            "resource": run.resource,
        },
    )
    if status != HTTP_OK:
        message = f"the token exchange answered HTTP {status}: {body[:200]}"
        raise RuntimeError(message)
    tokens = json.loads(body)
    return {
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
        "access_kid": token_kid(tokens["access_token"]),
        "refresh_kid": token_kid(tokens.get("refresh_token", "")),
        "refresh_custody_key_id": refresh_custody_key_id(
            tokens.get("refresh_token", "")
        ),
    }


def core_accepts(access_token: str) -> dict:
    """Whether Core accepts an access token on the app's MCP data path (through the router)."""
    status, message = _mcp_tools_list(_run(), access_token)
    ok = status == HTTP_OK and message is not None and "result" in message
    return {"status": status, "accepted": ok}


def _run() -> _Run:
    env = load_env()
    return _Run(
        origin=DEFAULT_ORIGIN,
        toolset=APP,
        client_id=env.get("GATEWAY_E2E_CLIENT_ID", "group6-smoke"),
        callback_port=CALLBACK_PORT,
        kind="apps",
    )


# --------------------------------------------------------------------------- record


def write_record(name: str, record: dict) -> Path:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / f"transcript-{name}.json"
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- subcommands


def cmd_status(_args: argparse.Namespace) -> int:
    kids = jwks_kids()
    state = wsl(
        "docker", "inspect", "--format", "{{.State.Health.Status}}", GATEWAY
    ).stdout.strip()
    print(f"gateway health: {state}")
    print(f"JWKS kids (active first): {kids}")
    return 0


def cmd_control(_args: argparse.Namespace) -> int:
    """The negative control: prove the instrument can fail before any verdict is trusted.

    The deliberately wrong expectation: an old-`kid` refresh token still verifies after its
    retained entry is removed. The expectation is asserted to hold; it must NOT. A run where
    the assertion holds means the instrument is broken (it cannot see a removal), and the
    control is recorded as a pass only when the wrong expectation fails.
    """
    env = load_env()
    run = _run()
    record: dict = {"subcommand": "control"}

    # Stage 1: only the old signing key, active. Mint a token under the old kid.
    configure(
        signing_structured(new_active=False, old_retained=False),
        custody_structured(new_active=False, old_retained=False),
    )
    record["stage_pre"] = {"jwks_kids": jwks_kids()}
    s = sign_in(env, run)
    record["tokens"] = {
        "access_kid": s["access_kid"],
        "refresh_kid": s["refresh_kid"],
        "custody_key_id": s["refresh_custody_key_id"],
    }
    old_refresh = s["refresh_token"]
    print(
        f"pre-rotation: JWKS {record['stage_pre']['jwks_kids']}, "
        f"minted access kid={s['access_kid']}, refresh kid={s['refresh_kid']}"
    )

    # Stage 2: promote the new key and drop the old entry in one step -> the old kid names
    # no entry, which is exactly the "retained entry removed" state.
    configure(
        signing_structured(new_active=True, old_retained=False),
        custody_structured(new_active=False, old_retained=False),
    )
    record["stage_cut"] = {"jwks_kids": jwks_kids()}
    print(f"post-cut: JWKS {record['stage_cut']['jwks_kids']}")

    # The deliberately wrong expectation: the old-kid refresh token still verifies.
    wrong_expectation_holds = False
    r = refresh(env, run, old_refresh)
    record["wrong_expectation_probe"] = {
        "status": r["status"],
        "error": r.get("error"),
        "custody_key_id": r.get("refresh_custody_key_id"),
    }
    if r["status"] == HTTP_OK:
        wrong_expectation_holds = True

    record["wrong_expectation_holds"] = wrong_expectation_holds
    record["control_failed_as_required"] = not wrong_expectation_holds
    print(
        f"the wrong expectation (old-kid token still verifies after removal): "
        f"{'HELD — instrument broken' if wrong_expectation_holds else 'FAILED as required'}"
    )

    write_record("control", record)
    if wrong_expectation_holds:
        print(
            "CONTROL BROKEN: the old-kid token still verified after its entry was removed."
        )
        return 1
    print("CONTROL OK: the instrument observes the refusal; verdicts may be trusted.")
    return 0


def cmd_signing(args: argparse.Namespace) -> int:
    """The signing leg: pre-publish, cache-window wait, promote, drain, post-cut refusals."""
    env = load_env()
    run = _run()
    record: dict = {"subcommand": "signing", "timestamps": {}}
    t0 = time.time()

    # S0: only the old key. Mint two sessions: A is drained after promotion, B is held
    # un-rotated for the post-cut refusal (an un-rotated old-kid token is what the cut must
    # refuse; a drained one would have rotated onto the new kid).
    configure(
        signing_structured(new_active=False, old_retained=False),
        custody_structured(new_active=False, old_retained=False),
    )
    record["s0_jwks_kids"] = jwks_kids()
    sess_a = sign_in(env, run)
    sess_b = sign_in(env, run)
    record["s0_tokens"] = {
        "access_kid": sess_a["access_kid"],
        "refresh_kid": sess_a["refresh_kid"],
    }
    record["timestamps"]["s0_mint"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)
    )
    record["s0_core_accepts_old_access"] = core_accepts(sess_a["access_token"])
    print(
        f"S0 pre-rotation: JWKS {record['s0_jwks_kids']}, old tokens kid={sess_a['access_kid']}; "
        f"Core accepts old access: {record['s0_core_accepts_old_access']}"
    )

    # S1: pre-publish — the new key is published as retained, not signing.
    configure(
        signing_structured(new_active=False, old_retained=True),
        custody_structured(new_active=False, old_retained=False),
    )
    record["s1_jwks_kids"] = jwks_kids()
    t1 = time.time()
    record["timestamps"]["s1_prepublish"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(t1)
    )
    print(
        f"S1 pre-publish: JWKS {record['s1_jwks_kids']} (new kid published, old still signs)"
    )

    # S1b: wait the declared Core JWKS-cache window (timestamped).
    wait = args.wait_seconds
    print(
        f"S1b waiting the declared cache window: {wait}s (>= {DECLARED_CACHE_WINDOW_SECONDS}s)"
    )
    time.sleep(wait)
    t2 = time.time()
    record["timestamps"]["s1b_waited"] = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(t2)
    )
    record["s1b_elapsed_seconds"] = round(t2 - t1, 1)
    # Mint a FRESH old-kid access token here (the old key is still active after the wait).
    # Its short TTL survives to the post-promotion check, where the S0 token's would not.
    sess_c = sign_in(env, run)
    record["s1b_fresh_old_access_kid"] = sess_c["access_kid"]
    record["s1b_core_accepts_fresh_old_access"] = core_accepts(sess_c["access_token"])
    print(
        f"S1b fresh old-kid access kid={sess_c['access_kid']}; Core accepts: "
        f"{record['s1b_core_accepts_fresh_old_access']}"
    )

    # S2: promote — new active, old retained. Two restarts, zero refusal windows.
    configure(
        signing_structured(new_active=True, old_retained=True),
        custody_structured(new_active=False, old_retained=False),
    )
    record["s2_jwks_kids"] = jwks_kids()
    new = sign_in(env, run)
    record["s2_new_tokens"] = {
        "access_kid": new["access_kid"],
        "refresh_kid": new["refresh_kid"],
    }
    record["s2_core_accepts_new_access"] = core_accepts(new["access_token"])
    # The pre-publish rule's proof: the OLD-kid access token minted after the wait — whose kid
    # Core had published through the whole window — is still accepted at Core after promotion.
    record["s2_core_accepts_prepromotion_old_access"] = core_accepts(
        sess_c["access_token"]
    )
    print(
        f"S2 promote: JWKS {record['s2_jwks_kids']}, new tokens kid={new['access_kid']}; "
        f"Core accepts new: {record['s2_core_accepts_new_access']}; "
        f"pre-promotion old-kid access still accepted: "
        f"{record['s2_core_accepts_prepromotion_old_access']}"
    )

    # S3: drain — the held old-kid session A refreshes; the replacement mints under the NEW kid.
    drain = refresh(env, run, sess_a["refresh_token"])
    record["s3_drain_refresh"] = {
        "status": drain["status"],
        "access_kid": drain.get("access_kid"),
        "refresh_kid": drain.get("refresh_kid"),
    }
    record["s3_drain_core_accepts"] = (
        core_accepts(drain["access_token"])
        if drain["status"] == HTTP_OK
        else {"accepted": False}
    )
    print(
        f"S3 drain: old refresh -> HTTP {drain['status']}, new access kid={drain.get('access_kid')}, "
        f"refresh kid={drain.get('refresh_kid')}; Core accepts: {record['s3_drain_core_accepts']}"
    )

    # S4: remove the retained entry — the closing step of the routine rotation. The held
    # un-rotated session B (still carrying the old kid) is now refused at the gateway.
    configure(
        signing_structured(new_active=True, old_retained=False),
        custody_structured(new_active=False, old_retained=False),
    )
    record["s4_jwks_kids"] = jwks_kids()
    postcut = refresh(env, run, sess_b["refresh_token"])
    record["s4_postcut_refresh"] = {
        "status": postcut["status"],
        "error": postcut.get("error"),
        "invalid_grant_audited": audit_has("invalid_grant"),
    }
    # A fresh sign-in still mints under the new kid and Core accepts it.
    fresh = sign_in(env, run)
    record["s4_fresh_tokens"] = {"access_kid": fresh["access_kid"]}
    record["s4_core_accepts_fresh"] = core_accepts(fresh["access_token"])
    print(
        f"S4 post-cut: JWKS {record['s4_jwks_kids']}; un-rotated old-kid refresh -> "
        f"HTTP {postcut['status']} ({postcut.get('error')}); fresh kid={fresh['access_kid']} "
        f"Core accepts: {record['s4_core_accepts_fresh']}"
    )

    record["verdict"] = {
        "old_tokens_drained": record["s3_drain_refresh"]["status"] == HTTP_OK
        and record["s3_drain_refresh"]["access_kid"] == new["access_kid"],
        "new_tokens_accepted": record["s2_core_accepts_new_access"]["accepted"]
        and record["s4_core_accepts_fresh"]["accepted"],
        "prepublish_respected": record["s2_core_accepts_prepromotion_old_access"][
            "accepted"
        ],
        "postcut_old_refused": record["s4_postcut_refresh"]["status"]
        == HTTP_BAD_REQUEST,
        "cache_wait_observed": record["s1b_elapsed_seconds"]
        >= DECLARED_CACHE_WINDOW_SECONDS,
    }
    write_record("signing", record)
    print(f"SIGNING VERDICT: {json.dumps(record['verdict'])}")
    return 0 if all(record["verdict"].values()) else 1


def cmd_custody(args: argparse.Namespace) -> int:
    """The custody leg: overlap rotation with live sessions, then the emergency cut."""
    env = load_env()
    run = _run()
    record: dict = {"subcommand": "custody", "timestamps": {}}

    # C0: only the old custody key active. Sign in TWICE under k-oldc: one session is
    # rotated in the overlap (C1), the other is held un-rotated for the emergency cut (C2).
    configure(
        signing_structured(new_active=True, old_retained=False),
        custody_structured(new_active=False, old_retained=False),
    )
    record["c0_jwks_kids"] = jwks_kids()
    c0 = sign_in(env, run)
    c0_cut = sign_in(env, run)
    record["c0_tokens"] = {
        "overlap_custody_key_id": c0["refresh_custody_key_id"],
        "cut_custody_key_id": c0_cut["refresh_custody_key_id"],
    }
    record["timestamps"]["c0"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    overlap_refresh = c0["refresh_token"]
    cut_refresh = c0_cut["refresh_token"]
    print(
        f"C0 pre-rotation: both sessions custody key-id={c0['refresh_custody_key_id']}"
    )

    # C1: rotate — k-newc active, k-oldc retained. The live session's refresh token still
    # carries k-oldc; its refresh decrypts under the retained key and re-seals under the
    # active one.
    configure(
        signing_structured(new_active=True, old_retained=False),
        custody_structured(new_active=True, old_retained=True),
    )
    r1 = refresh(env, run, overlap_refresh)
    record["c1_overlap_refresh"] = {
        "status": r1["status"],
        "presented_custody_key_id": c0["refresh_custody_key_id"],
        "resealed_custody_key_id": r1.get("refresh_custody_key_id"),
    }
    print(
        f"C1 overlap rotate: presented custody key-id={c0['refresh_custody_key_id']} -> "
        f"re-sealed key-id={r1.get('refresh_custody_key_id')} (HTTP {r1['status']})"
    )

    # C2: the emergency cut mid-window — remove the retained entry. The held un-rotated
    # session's refresh token still carries k-oldc, and refuses at next presentation in the
    # custody class.
    record["c2_pre_cut_key_id"] = refresh_custody_key_id(cut_refresh)
    configure(
        signing_structured(new_active=True, old_retained=False),
        custody_structured(new_active=True, old_retained=False),
    )  # remove k-oldc
    cut = refresh(env, run, cut_refresh)
    record["c2_cut_refresh"] = {
        "status": cut["status"],
        "error": cut.get("error"),
        "custody_class_audited": audit_has("custody_decrypt_failed"),
    }
    # A fresh session under the active key still works.
    after = sign_in(env, run)
    record["c2_after_tokens"] = {"custody_key_id": after["refresh_custody_key_id"]}
    r_after = refresh(env, run, after["refresh_token"])
    record["c2_after_refresh"] = {
        "status": r_after["status"],
        "resealed_custody_key_id": r_after.get("refresh_custody_key_id"),
    }
    print(
        f"C2 emergency cut: k-oldc-carried token -> HTTP {cut['status']} "
        f"({cut.get('error')}); custody class audited: {record['c2_cut_refresh']['custody_class_audited']};"
        f" fresh session key-id={after['refresh_custody_key_id']} refresh HTTP {r_after['status']}"
    )

    record["verdict"] = {
        "overlap_reseals_under_active": r1["status"] == HTTP_OK
        and r1.get("refresh_custody_key_id") == "k-newc",
        "cut_refuses_in_custody_class": record["c2_cut_refresh"]["status"]
        == HTTP_BAD_REQUEST
        and cut.get("error") == "invalid_grant"
        and record["c2_cut_refresh"]["custody_class_audited"],
        "active_session_survives": r_after["status"] == HTTP_OK
        and r_after.get("refresh_custody_key_id") == "k-newc",
    }
    write_record("custody", record)
    print(f"CUSTODY VERDICT: {json.dumps(record['verdict'])}")
    return 0 if all(record["verdict"].values()) else 1


def cmd_restore(_args: argparse.Namespace) -> int:
    """Restore the working compat profile and recreate the unit healthy."""
    restore_env()
    remove_override()
    # A compat recreate: no override, the tracked compose alone.
    compose("up", "-d", "--force-recreate", with_override=False)
    healthy = wait_healthy()
    kids = jwks_kids() if healthy else []
    print(f"restored: healthy={healthy}, JWKS kids={kids}")
    return 0 if healthy else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(func=cmd_status)
    sub.add_parser("control").set_defaults(func=cmd_control)
    p_sign = sub.add_parser("signing")
    p_sign.add_argument(
        "--wait-seconds", type=int, default=DECLARED_CACHE_WINDOW_SECONDS + 15
    )
    p_sign.set_defaults(func=cmd_signing)
    sub.add_parser("custody").set_defaults(func=cmd_custody)
    sub.add_parser("restore").set_defaults(func=cmd_restore)
    args = parser.parse_args()
    snapshot_env()
    write_override()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
