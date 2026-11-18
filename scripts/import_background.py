"""Import the harness-integration background docs into this repo, and repair the
references that would otherwise dangle or send a reader (or an agent) somewhere this
repo forbids: the private `documentation` repository, the local instance's scratch
folder, and the stale May-2026 design doc.

The May doc is NOT copied here: it is stale (its DCR conclusion predates the MCP spec
deprecating DCR), and this repo references the DIAL Core source instead.
"""

import argparse
import os
import re
import shutil

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "source",
    help="the background archive's harness-integration folder to import from",
)
SRC = parser.parse_args().source
DST = "docs/background"

FILES = [
    "problem-statement.md",
    "design.md",
    "design-review.md",
    "ideas.scratchpad.md",
    "poc-dial-mcp-signin.md",
    "poc-litellm-comparison.md",
]

PROVENANCE = (
    "\n---\n\n"
    "*Imported into this repository from the DIAL design archive on 2026-10-17. "
    "This copy is the **living** version of this document; the archive copy is a "
    "frozen historical record and is not updated. References to the May 2026 toolset "
    "authentication design have been replaced with references to the DIAL Core source, "
    "because that document predates the MCP specification revision that deprecated "
    "Dynamic Client Registration.*\n"
)

os.makedirs(DST, exist_ok=True)
for name in FILES:
    src = os.path.join(SRC, name)
    dst = os.path.join(DST, name)
    if not os.path.exists(src):
        print(f"  MISSING (skipped): {name}")
        continue
    with open(src, encoding="utf-8") as handle:
        s = handle.read()

    # 1. References to the May 2026 design doc: do not link it (private + stale).
    s = re.sub(
        r"\[`?(\.\./)?mcp_toolset_authentication\.md`\??:?[^\n]*",
        "<!-- The May 2026 toolset authentication design is not copied here: it is\n"
        "     stale and private. Anything it described that still matters is either\n"
        "     implemented in DIAL Core (cite the source) or stated in this repo. -->",
        s,
    )
    s = s.replace("(the authN design)", "(the DIAL Core implementation)")
    s = re.sub(r"\bthe authN design\b", "the DIAL Core implementation", s)

    # 2. Local-instance scratch paths: they are environment, not repo content.
    s = s.replace(".mcp-poc/", "<local-instance>/.mcp-poc/")
    s = s.replace("~/.claude/skills/dial-mcp-signin/", "../gateway/")
    s = s.replace("`skill/`", "`gateway/`").replace("(skill/)", "(../gateway/)")

    s = s + PROVENANCE
    with open(dst, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(s)
    print(f"  imported: {name}")

# the decision record
ddst = os.path.join(DST, "decisions")
os.makedirs(ddst, exist_ok=True)
for d in ("DR-0001-keep-nginx.md",):
    src = os.path.join(SRC, "decisions", d)
    if os.path.exists(src):
        shutil.copy(src, os.path.join(ddst, d))
        print(f"  imported: decisions/{d}")
