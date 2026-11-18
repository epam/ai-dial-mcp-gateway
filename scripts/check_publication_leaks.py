"""The publication leak check — the machine half of this repo's publication discipline.

The repository is headed for public publication, which exposes its whole history and
cannot be recalled. This script is the repeatable share of keeping that one-way door
safe to walk through: it scans every tracked file for the structural classes of
content publication must not carry, and fails on anything the committed waiver
baseline does not already account for.

What it can and cannot see — the rule set is deliberately narrow:

* **personal paths** — a Windows or POSIX user-profile path (`C:\\Users\\<name>\\...`,
  `/home/<name>/...`, `/Users/<name>/...`). A profile path is a person's name plus a
  machine's layout, and neither belongs in a public repository.
* **secret shapes** — machine-shaped literals: a long mixed-case value assigned to a
  secret-, password-, or token-named key, a PEM private-key block with a real-sized
  body (as base64 follower lines, or on one physical line joined by literal `\n`
  escapes — the `.env`/compose/JSON embedding), or a three-segment `eyJ...` JWT
  literal. The assignment rule is tuned so
  synthetic dictionary-shaped fixtures (lowercase words joined by dashes) pass by
  design — its target is pasted machine-generated material, not a test's invented
  values. The cost of that tuning is a real secret that happens to be all-lowercase
  or all-caps; the review gates remain the backstop for it.
* **a tracked `.env`** — local configuration is gitignored by design, so a
  `.env`-shaped file (any spelling except `.env.example`) inside `git ls-files` is a
  finding on the file itself, whatever its contents turn out to be.

Internal hostnames and instance names are NOT machine-scanned. A deny-list holding
the literal values would itself be a disclosure and would ship with the repository;
an allowlist would turn every legitimate new domain into a gate chore. That class is
held by the `<>` placeholder convention at write time and by the review gates; when
CI/CD lands, a secret scanner with an injected configuration is the off-the-shelf
replacement for this whole check's hostname gap.

Pre-existing exposures are waived, never fixed here: the committed baseline
(`scripts/leak-baseline.json`) maps file + rule to a reason and records no matched
values, so the pre-publication cleanup has a bounded backlog. A waiver is debt on
record — waiving a new exposure in the same change that adds it is a violation of
the discipline, not a use of the baseline.

Usage:
    python scripts/check_publication_leaks.py

Exit status: 0 when every finding is waived, 1 on any unwaived finding, 2 when the
baseline itself cannot be read. The script rebinds its own stdout to UTF-8 so a
finding or waiver reason can never crash the console it reports through.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

# The repository root, resolved from this file so the check behaves the same from any
# working directory; the `git ls-files` call below needs a cwd inside the repository
# regardless of where it is invoked from.
_REPO_ROOT = Path(__file__).resolve().parent.parent

# The committed waiver baseline. It must never contain a matched value: a baseline
# that quoted what it waived would publish the very material it exists to keep out.
_BASELINE_PATH = _REPO_ROOT / "scripts" / "leak-baseline.json"

# The rule vocabulary — the finding classes, and the keys the baseline is keyed by.
# The set is fixed: a new rule class is a discipline change, not a script tweak.
RULE_PERSONAL_PATH = "personal-path"
RULE_SECRET_SHAPE = "secret-shape"  # noqa: S105 - the rule's own id, not a credential
RULE_TRACKED_ENV = "tracked-env"
_RULES = (RULE_PERSONAL_PATH, RULE_SECRET_SHAPE, RULE_TRACKED_ENV)

# A user-profile path in any of its three spellings. The drive letter and the profile
# directory tolerate case drift in text that references them, so the directory name is
# matched case-insensitively — the inline flag is scoped to the directory names so the
# profile-name segment beside it keeps its own matching; a name is a name whether it
# belongs to a person or to a service account.
_PERSONAL_PATH = re.compile(
    r"[A-Za-z]:[/\\]+(?i:users)[/\\]+[A-Za-z0-9_.-]+"
    r"|/(?i:home|users)/[A-Za-z0-9_.-]+"
)

# An assignment of a long literal to a secret-, password-, or token-named key, in any
# of the spellings tracked files use: a Python keyword argument, a `.env`-style bare
# assignment, or a JSON/YAML member (the optional quote before the separator is what
# lets the JSON spelling match). The key matcher is anchored at name boundaries so a
# name that merely contains the word (`token_bucket`, `passwords_url`) still has to
# be followed by an actual assignment before anything is captured.
_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (?<![a-z0-9_-])
    [a-z0-9_-]*(?:secret|passw(?:or)?d|token)[a-z0-9_-]*
    (?![a-z0-9_-])
    ["']?\s*[:=]\s*
    (?:["'](?P<quoted>[^"'\n]{32,})["']|(?P<bare>[A-Za-z0-9+/=_.-]{32,}))
    """
)

# The characters a captured assignment value must consist of entirely. A URL fails it
# (the `:` in the scheme), and so does every substituted template form — `<...>` and
# `${...}` carry characters no credential literal needs, which is what makes the
# placeholder convention machine-enforceable here for free.
_VALUE_CHARSET = re.compile(r"[A-Za-z0-9+/=_.-]+")

# The placeholder vocabulary: values a template states where a real secret would go.
# Matched as case-insensitive substrings, so a long compound placeholder built by
# repeating the word is covered by the same entry.
_PLACEHOLDER_MARKERS = (
    "changeme",
    "change-me",
    "generate-me",
    "replace-me",
    "placeholder",
    "paste-your",
    "your-secret",
    "your-value",
)

# A PEM private-key header. Prose quotes headers and test fixtures carry them over
# fake one-line bodies, so the header alone is not a finding — see the body minimum
# below.
_PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

# A line of nothing but base64: the shape every line of a real key body has.
_BASE64_LINE = re.compile(r"[A-Za-z0-9+/=]{4,}")

# The two-character escape a one-line embedding uses in place of a real newline —
# the shape `.env`, compose, and JSON values give a pasted key written on a single
# physical line. Matched as text, so a real newline can never be mistaken for it.
_ESCAPED_NEWLINE = "\\n"

# How much base64 body a block must carry before it is a key rather than a header
# quoted in prose. The shortest real private key (a P-256 EC key) is several hundred
# base64 characters; 80 sits far below it and far above any fixture.
_PRIVATE_KEY_MIN_BODY_CHARS = 80

# A three-segment JWT literal: a base64url header beginning `eyJ` (the encoding of
# `{"`), a payload beginning the same way, and a signature long enough to be one.
# Nothing a repository legitimately contains is this shape.
_JWT_LITERAL = re.compile(
    r"eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{16,}"
)

# How many bytes to taste before deciding a file is binary. A NUL byte this early is
# the encoding-agnostic binary marker; the rest of a binary file says nothing a text
# rule could read.
_BINARY_SNIFF_BYTES = 8192


@dataclass(frozen=True)
class Finding:
    """One rule hit: the tracked file it is in, its 1-based line, and the rule.

    A file-level finding (a tracked `.env`) carries line 0 — the finding is the
    file's existence, not any line of it.
    """

    file: str
    line: int
    rule: str


@dataclass(frozen=True)
class ScanResult:
    """What a full scan produced: the tracked-list size, and the findings among the
    tracked files, deterministically ordered by file, then line, then rule.

    `files_scanned` is the size of the `git ls-files` list, not a count of files
    whose contents were read: tracked `.env` files (already findings at the file
    level) and paths missing from the worktree are counted as tracked but never
    opened.
    """

    files_scanned: int
    findings: list[Finding]


def find_personal_paths(file: str, lines: Sequence[str]) -> list[Finding]:
    """Every user-profile path in the text, one finding per line it appears on."""
    return [
        Finding(file, number, RULE_PERSONAL_PATH)
        for number, line in enumerate(lines, start=1)
        if _PERSONAL_PATH.search(line)
    ]


def find_secret_shapes(file: str, lines: Sequence[str]) -> list[Finding]:
    """Every machine-shaped secret literal in the text.

    Three detectors share one rule id because they answer one question — is there
    real credential material here? — and a file that trips any of them is a file the
    baseline has to speak to, whichever detector spoke first.
    """
    findings = []
    for number, line in enumerate(lines, start=1):
        if _assignment_of_real_secret_in(line) or _JWT_LITERAL.search(line):
            findings.append(Finding(file, number, RULE_SECRET_SHAPE))
    findings.extend(_private_key_blocks(file, lines))
    return findings


def _assignment_of_real_secret_in(line: str) -> bool:
    """Whether a line assigns machine-shaped secret material to a secret-named key."""
    for match in _SECRET_ASSIGNMENT.finditer(line):
        value = match.group("quoted") or match.group("bare")
        if _looks_like_real_secret(value):
            return True
    return False


def _looks_like_real_secret(value: str) -> bool:
    """Whether an assigned value is machine-shaped secret material.

    Three gates, each of which exists to keep a legitimate spelling out: the value
    must be entirely credential characters, it must not be built from the placeholder
    vocabulary, and it must carry both letter cases — the property that separates
    generated material from the lowercase-word fixtures tests invent. An all-digit or
    single-case value passes here and stays with the review gates.
    """
    if not _VALUE_CHARSET.fullmatch(value):
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return False
    return any(char.isupper() for char in value) and any(
        char.islower() for char in value
    )


def _private_key_blocks(file: str, lines: Sequence[str]) -> list[Finding]:
    """Every PEM private-key block whose body is real-key-sized.

    The finding is reported on the header's line. The body is counted in either
    shape a real key takes: base64 follower lines after a multi-line PEM, or base64
    following literal `\n` escapes on the header's own physical line — the one-line
    `.env`/compose/JSON embedding. The same body minimum applies to both, so a
    header quoted in prose, which carries neither shape of payload, stays a pass.
    """
    findings = []
    for index, line in enumerate(lines):
        if not _PRIVATE_KEY_HEADER.search(line):
            continue
        body_chars = _escaped_body_chars(line)
        for follower in lines[index + 1 :]:
            stripped = follower.strip()
            if not _BASE64_LINE.fullmatch(stripped):
                break
            body_chars += len(stripped)
        if body_chars >= _PRIVATE_KEY_MIN_BODY_CHARS:
            findings.append(Finding(file, index + 1, RULE_SECRET_SHAPE))
    return findings


def _escaped_body_chars(line: str) -> int:
    """How much base64 one physical line carries after literal `\n` escapes.

    Only base64 that follows an escape counts: the text between a quoted header and
    its first escape is prose or punctuation, not a payload, so a header named in a
    sentence contributes nothing here.
    """
    chars = 0
    for segment in line.split(_ESCAPED_NEWLINE)[1:]:
        match = _BASE64_LINE.match(segment)
        if match:
            chars += len(match.group(0))
    return chars


def find_tracked_env_files(paths: Iterable[str]) -> list[Finding]:
    """Every tracked `.env`-shaped file, as a finding on the file itself.

    `.env.example` is the committed placeholder template and the one spelling that is
    supposed to be here; every other `.env` spelling is local configuration that has
    slipped into the index.
    """
    return [
        Finding(path, 0, RULE_TRACKED_ENV)
        for path in sorted(paths)
        if _is_env_shaped(path)
    ]


def _is_env_shaped(path: str) -> bool:
    """Whether a tracked path is a local-configuration file rather than the template."""
    name = PurePosixPath(path).name
    return name == ".env" or (name.startswith(".env.") and name != ".env.example")


def scan_file(file: str, raw: bytes) -> list[Finding]:
    """Both line-rule classes over one tracked file's bytes.

    Binary files are skipped on the NUL-byte taste: their content is not text a
    leaker writes or a reader reads, and decoding it as text would only manufacture
    noise. Text is decoded as UTF-8 with replacement so a stray byte in an otherwise
    readable file cannot crash the scan — the readable lines around it still carry
    the rules.
    """
    if b"\x00" in raw[:_BINARY_SNIFF_BYTES]:
        return []
    lines = raw.decode("utf-8", errors="replace").splitlines()
    return find_personal_paths(file, lines) + find_secret_shapes(file, lines)


def _tracked_files() -> list[str]:
    """The tracked file list, straight from git with no shell in between.

    The argv is fixed here — the repository's own index is the input — and `git` is
    resolved from the PATH because an absolute path would embed this host's
    installation layout into a committed script.
    """
    completed = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607 - PATH-resolved by design, argv fixed
        cwd=_REPO_ROOT,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        message = f"git ls-files failed with status {completed.returncode}: {stderr}"
        raise RuntimeError(message)
    names = completed.stdout.decode("utf-8", errors="replace")
    return [name for name in names.split("\x00") if name]


def scan_repo() -> ScanResult:
    """The full scan: the file-name rule over the tracked list, both line rules over
    every other tracked file."""
    paths = _tracked_files()
    findings = find_tracked_env_files(paths)
    for path in paths:
        if _is_env_shaped(path):
            # The file-level finding already covers it; reading a real `.env`'s
            # contents would only add line-level noise on top of a finding that
            # already fails the file.
            continue
        # A path in the index but missing from the worktree is a transient state
        # mid-commit, not content anyone is about to publish; the scan reads the
        # tree it can see.
        if (_REPO_ROOT / path).is_file():
            findings.extend(scan_file(path, (_REPO_ROOT / path).read_bytes()))
    findings.sort(key=lambda finding: (finding.file, finding.line, finding.rule))
    return ScanResult(files_scanned=len(paths), findings=findings)


def load_waivers(path: Path) -> dict[tuple[str, str], str]:
    """The waiver baseline as a (file, rule) -> reason mapping.

    Invalid entries are refused loudly rather than skipped: a waiver with a typo in
    its rule name would silently waive nothing, and a baseline this loader cannot
    vouch for is a gate that cannot run.
    """
    document = json.loads(path.read_text(encoding="utf-8"))
    entries = document.get("waivers") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        # A document of the wrong shape is a type error, not a value one: nothing
        # about the entries can be read until the shape itself is right.
        message = "the baseline must be a JSON object carrying a 'waivers' list"
        raise TypeError(message)
    waivers: dict[tuple[str, str], str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            message = f"waiver entry {entry!r} is not an object"
            raise TypeError(message)
        file = entry.get("file")
        rule = entry.get("rule")
        reason = entry.get("reason")
        if not (
            isinstance(file, str)
            and isinstance(rule, str)
            and isinstance(reason, str)
            and file
            and rule
            and reason
        ):
            message = (
                f"waiver entry {entry!r} needs non-empty string 'file', 'rule', "
                f"and 'reason'"
            )
            raise ValueError(message)
        if rule not in _RULES:
            message = (
                f"waiver for {file!r} names unknown rule {rule!r}; the rules are: "
                f"{', '.join(_RULES)}"
            )
            raise ValueError(message)
        key = (file, rule)
        if key in waivers:
            message = f"duplicate waiver for {file!r} under {rule!r}"
            raise ValueError(message)
        waivers[key] = reason
    return waivers


def apply_waivers(
    findings: Sequence[Finding], waivers: dict[tuple[str, str], str]
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (waived, unwaived) by the baseline's file + rule keys.

    A waiver covers a file's exposure under one rule, not one line of it — the
    baseline records that a known exposure exists, and pinning it to a line number
    would break on every harmless edit above it.
    """
    waived = [
        finding for finding in findings if (finding.file, finding.rule) in waivers
    ]
    unwaived = [
        finding for finding in findings if (finding.file, finding.rule) not in waivers
    ]
    return waived, unwaived


def main() -> int:
    # The Windows console is cp1252 by default and dies on non-ASCII output; this
    # repo's PYTHONUTF8 discipline covers processes it launches, and this rebind
    # covers every other console the check is run from.
    if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    try:
        waivers = load_waivers(_BASELINE_PATH)
    except (OSError, TypeError, ValueError) as error:
        print(f"cannot read the waiver baseline: {error}", file=sys.stderr)
        return 2
    result = scan_repo()
    for finding in result.findings:
        reason = waivers.get((finding.file, finding.rule))
        suffix = f" (waived: {reason})" if reason is not None else ""
        print(f"{finding.file}:{finding.line}: {finding.rule}{suffix}")
    waived, unwaived = apply_waivers(result.findings, waivers)
    for file, rule in sorted(set(waivers) - {(f.file, f.rule) for f in waived}):
        print(f"note: unused waiver {file} / {rule} - the exposure is gone; remove it")
    print(
        f"summary: scanned {result.files_scanned} tracked files; "
        f"{len(result.findings)} finding(s): {len(waived)} waived, {len(unwaived)} "
        f"unwaived"
    )
    if unwaived:
        print("verdict: FAIL - publication-sensitive content outside the baseline")
        return 1
    print("verdict: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
