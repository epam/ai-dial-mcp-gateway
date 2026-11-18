"""Tests for the publication leak check's rule engine.

The rule functions are exercised directly on assembled text rather than through a
scan of this repository, because the fixtures below are the very shapes the check
exists to flag: each one is built from parts — a prefix here, a tail there — instead
of written as a single literal. A fixture written whole would make this committed
file itself a finding, and the baseline would end up waiving the tests that test it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from check_publication_leaks import (
    RULE_PERSONAL_PATH,
    RULE_SECRET_SHAPE,
    RULE_TRACKED_ENV,
    Finding,
    apply_waivers,
    find_personal_paths,
    find_secret_shapes,
    find_tracked_env_files,
    load_waivers,
    scan_file,
)

# A machine-shaped secret value: 32+ credential characters, mixed case, no
# placeholder vocabulary. Split in two so the whole literal never sits in this file.
_MACHINE_SECRET = "Ab3d" + "EfGhIjKlMnOpQrStUvWx0123456789yz"

# Profile-path fixtures, split for the same reason.
_WINDOWS_PROFILE = "C:" + "/Users/" + "alice/notes.txt"
_POSIX_HOME_PROFILE = "/ho" + "me/alice/notes.txt"

# Case-drift profile-directory spellings, split for the same reason: the directory
# name is matched case-insensitively, so every capitalization of it is a finding.
_UPPER_POSIX_HOME = "/HO" + "ME/alice/notes.txt"
_LOWER_POSIX_USERS = "/us" + "ers/alice/notes.txt"
_UPPER_WINDOWS_USERS = "C:/US" + "ERS/alice/notes.txt"

# A PEM private-key fixture's parts: the header as prose and fixtures quote it, and
# a body of pure base64 that only reaches a real key's size when repeated.
_PEM_HEADER = "-----BEGIN PRIVATE KEY-----"
_PEM_FOOTER = "-----END PRIVATE KEY-----"
_PEM_BODY = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xt"

# The same key embedded on one physical line: the literal `\n` escape a `.env`,
# compose, or JSON value uses in place of real newlines, joined at run time.
_ESCAPED_PEM = _PEM_HEADER + "\\n" + _PEM_BODY * 2 + "\\n" + _PEM_FOOTER

# An escaped body too short to be a real key, built from the same parts as the
# multi-line short fixture.
_SHORT_PEM_BODY = "MIIEvQ" + "IBADANBgkqhkiG9w0B"

# A JWT fixture's three segments, joined only at run time.
_JWT = ".".join(
    (
        "eyJ" + "hbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
        "eyJ" + "zdWIiOiJhYmNkZWZnaGlqa2xtIiwibmJtZSI6MTI",
        "c2lnbmF0dXJlLXNlZ21lbnQtbG9uZy1lbnVnaA",
    )
)


def test_personal_path_flags_a_windows_profile_path() -> None:
    lines = [f"SRC = {_WINDOWS_PROFILE!r}", "DST = docs/background"]
    assert find_personal_paths("import.py", lines) == [
        Finding("import.py", 1, RULE_PERSONAL_PATH)
    ]


def test_personal_path_flags_posix_profile_paths() -> None:
    lines = [f"load({_POSIX_HOME_PROFILE!r})", f"# also {_WINDOWS_PROFILE}"]
    assert find_personal_paths("notes.md", lines) == [
        Finding("notes.md", 1, RULE_PERSONAL_PATH),
        Finding("notes.md", 2, RULE_PERSONAL_PATH),
    ]


def test_personal_path_flags_profile_directory_spellings_in_any_case() -> None:
    lines = [
        f"a = {_UPPER_POSIX_HOME}",
        f"b = {_LOWER_POSIX_USERS}",
        f"c = {_UPPER_WINDOWS_USERS}",
    ]
    assert find_personal_paths("probe.py", lines) == [
        Finding("probe.py", 1, RULE_PERSONAL_PATH),
        Finding("probe.py", 2, RULE_PERSONAL_PATH),
        Finding("probe.py", 3, RULE_PERSONAL_PATH),
    ]


def test_personal_path_passes_repo_relative_and_system_paths() -> None:
    lines = ["capture = /tmp/capture.log", "out = data/runs/summary.json"]
    assert find_personal_paths("probe.py", lines) == []


def test_secret_shape_flags_machine_shaped_assignments() -> None:
    lines = [
        f"client_secret = {_MACHINE_SECRET!r}",
        f"IDP_CLIENT_SECRET={_MACHINE_SECRET}",
        f'"client_secret": {_MACHINE_SECRET!r}',
    ]
    assert find_secret_shapes("settings.md", lines) == [
        Finding("settings.md", number, RULE_SECRET_SHAPE) for number in range(1, 4)
    ]


def test_secret_shape_flags_a_jwt_literal_wherever_it_sits() -> None:
    lines = [f"captured = {_JWT!r}", f"authorization: Bearer {_JWT}"]
    assert find_secret_shapes("capture.txt", lines) == [
        Finding("capture.txt", 1, RULE_SECRET_SHAPE),
        Finding("capture.txt", 2, RULE_SECRET_SHAPE),
    ]


def test_secret_shape_flags_a_private_key_block_with_a_real_sized_body() -> None:
    lines = [_PEM_HEADER, _PEM_BODY * 2, _PEM_FOOTER]
    assert find_secret_shapes("key.md", lines) == [
        Finding("key.md", 1, RULE_SECRET_SHAPE)
    ]


def test_secret_shape_flags_a_one_line_escaped_key_in_env_and_compose_values() -> None:
    lines = [f'CLIENT_SECRET="{_ESCAPED_PEM}"', f"private-key: {_ESCAPED_PEM}"]
    assert find_secret_shapes("stack.env", lines) == [
        Finding("stack.env", 1, RULE_SECRET_SHAPE),
        Finding("stack.env", 2, RULE_SECRET_SHAPE),
    ]


def test_secret_shape_passes_an_escaped_header_without_a_payload_after_it() -> None:
    lines = [f'KEY = "{_PEM_HEADER}\\n{_PEM_FOOTER}"', "the header alone, quoted"]
    assert find_secret_shapes("notes.md", lines) == []


def test_secret_shape_passes_an_escaped_body_too_short_to_be_a_key() -> None:
    lines = [f'KEY = "{_PEM_HEADER}\\n{_SHORT_PEM_BODY}"']
    assert find_secret_shapes("test_app.py", lines) == []


def test_secret_shape_passes_a_header_quoted_in_prose() -> None:
    lines = [f"the repr showed `{_PEM_HEADER}\\n`` and nothing more"]
    assert find_secret_shapes("evidence.md", lines) == []


def test_secret_shape_passes_fixture_key_bodies_too_short_to_be_keys() -> None:
    lines = [_PEM_HEADER, "MIIEvQ" + "IBADANBgkqhkiG9w0B", _PEM_FOOTER]
    assert find_secret_shapes("test_app.py", lines) == []


def test_secret_shape_passes_dictionary_shaped_fixture_values() -> None:
    # Synthetic fixture values are lowercase words joined by dashes; the assignment
    # rule is tuned to leave them alone so tests need no waivers for invented
    # credentials.
    lines = ["PROVIDER_REFRESH_TOKEN = the-provider-session-refresh-token"]
    assert find_secret_shapes("test_tokens.py", lines) == []


def test_secret_shape_passes_placeholder_forms() -> None:
    lines = [
        "KEYCLOAK_ADMIN_PASSWORD=change-me",
        "IDP_CLIENT_SECRET=",
        'GATEWAY_CUSTODY_KEYS={"k-2026-11": "<paste>"}',
        "client_secret=<your-secret-here>",
        "client_secret=${KC_CLIENT_SECRET}",
        "password=ChangeMeChangeMeChangeMeChangeMe",
    ]
    assert find_secret_shapes("env.example", lines) == []


def test_secret_shape_passes_urls_and_short_values() -> None:
    lines = [
        'token_url = "https://keycloak:8443/realms/dial/protocol/openid-connect/token"',
        "GATEWAY_ACCESS_TOKEN_TTL_SECONDS=600",
        'client_id = "dial-mcp-proxy"',
    ]
    assert find_secret_shapes("compose.md", lines) == []


def test_tracked_env_flags_every_env_spelling_but_the_template() -> None:
    paths = [
        "config/.env",
        ".env.local",
        ".env",
        ".env.example",
        ".env.test.local",
        "docker-compose.yml",
    ]
    assert find_tracked_env_files(paths) == [
        Finding(".env", 0, RULE_TRACKED_ENV),
        Finding(".env.local", 0, RULE_TRACKED_ENV),
        Finding(".env.test.local", 0, RULE_TRACKED_ENV),
        Finding("config/.env", 0, RULE_TRACKED_ENV),
    ]


def test_scan_file_skips_binary_content() -> None:
    raw = b"\x00\x00" + _WINDOWS_PROFILE.encode("utf-8")
    assert scan_file("logo.png", raw) == []


def test_scan_file_decodes_unreadable_bytes_without_losing_the_lines() -> None:
    raw = b"SRC = " + _WINDOWS_PROFILE.encode("utf-8") + b" \xff\xfe"
    assert scan_file("import.md", raw) == [Finding("import.md", 1, RULE_PERSONAL_PATH)]


def test_load_waivers_reads_file_plus_rule_entries(tmp_path: Path) -> None:
    baseline = tmp_path / "leak-baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "waivers": [
                    {
                        "file": "scripts/import.py",
                        "rule": "personal-path",
                        "reason": "known exposure; awaits the pre-publication cleanup",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert load_waivers(baseline) == {
        ("scripts/import.py", "personal-path"): "known exposure; awaits the "
        "pre-publication cleanup"
    }


def test_load_waivers_refuses_an_unknown_rule(tmp_path: Path) -> None:
    baseline = tmp_path / "leak-baseline.json"
    baseline.write_text(
        json.dumps({"waivers": [{"file": "a.md", "rule": "hostname", "reason": "r"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown rule"):
        load_waivers(baseline)


def test_load_waivers_refuses_an_entry_without_a_reason(tmp_path: Path) -> None:
    baseline = tmp_path / "leak-baseline.json"
    baseline.write_text(
        json.dumps({"waivers": [{"file": "a.md", "rule": "personal-path"}]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reason"):
        load_waivers(baseline)


def test_apply_waivers_separates_the_backlog_from_new_content() -> None:
    findings = [
        Finding("scripts/import.py", 15, RULE_PERSONAL_PATH),
        Finding("docs/new.md", 3, RULE_PERSONAL_PATH),
    ]
    waivers = {
        ("scripts/import.py", RULE_PERSONAL_PATH): (
            "known exposure; awaits the pre-publication cleanup"
        )
    }
    waived, unwaived = apply_waivers(findings, waivers)
    assert waived == [findings[0]]
    assert unwaived == [findings[1]]
