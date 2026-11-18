# The production image on the Alpine base — build and scanner evidence

Change: `one-pod-and-keysets` (C3), tasks 3.1–3.3. Scope of this record: the base swap
in `Dockerfile`, the image build, the musl-wheel observation (D5's first named risk), and
the Trivy OS-package scan against the built image (D5's debt-clearing check). The
compose-boot gate — D5's second named risk, the functional check — is group 4's run
(`docs/evidence/c3/`), not this record's. No secrets, tokens, or personal paths in this
file: the build context path is the WSL-visible one, published as-is.

## Task 3.1 — the Dockerfile

The base swap `python:3.12-slim` → `python:3.12-alpine` in **both** stages (builder and
runtime). Everything the slim image earned is carried:

- uid/gid **10001** preserved — Alpine's `addgroup`/`adduser -D -u 10001 -G gateway`
  replaces the Debian `groupadd`/`useradd`, same numeric ids (verified at run time:
  `id -u` = `id -g` = 10001).
- the venv-copied builder pattern is kept unchanged — the Alpine `python` installs its
  interpreter to the same `/usr/local` prefix, so the venv and the `PATH` override work
  as on slim.
- pip removed from the runtime image (both the venv copy and the base's site-packages
  copy), no `.pyc` writes, one container-internal port (`EXPOSE 8091`), the same
  `ENTRYPOINT ["python", "-m", "gateway"]`.

The crypto-library refresh is the adapter precedent's `apk upgrade --no-cache libcrypto3
libssl3`, extended by one package. It runs in **both** stages — the runtime stage is what
the scanner scans. The extension:

- The Alpine base shipped `libuuid` (util-linux) 2.42.1-r0, which Trivy reports with
  **7 HIGH** findings (all util-linux: CVE-2026-53612/53613/53614/76642/78408/78409/78410),
  fixed upstream at 2.42.3-r1 in the same `v3.24/main` repository. The acceptance bar
  (task 3.3 / the delta spec's scanner scenario) is **no HIGH-or-above OS-package
  finding**, so the named-upgrade line covers `libuuid` as well. The packages are named
  individually rather than `apk upgrade` of the whole tree, so a base-image change cannot
  silently pull in an unreviewed package bump.

No builder-stage toolchain fallback was needed (see 3.2). If a musl wheel is ever absent,
the precedented fallback is `apk add --no-cache build-base` in the builder stage only,
never in the runtime image; a comment in the Dockerfile records this.

## Task 3.2 — the build and the musl-wheel observation

### The build

```
wsl -e docker build -t dial-mcp-gateway:c3 \
  /mnt/c/.../ai-dial-mcp-gateway/.claude/worktrees/c3-one-pod-and-keysets
```

Result: **exit 0**, image `dial-mcp-gateway:c3`,
id `sha256:23a5776918932078224d9b5c3e4eff48039e3cc5c9162cbf88c578a7a49067ae`,
size ~115 MB. Base image: `python:3.12-alpine` at
`python@sha256:b64631e04e4920160c50fbe8d8df828f7f35f06f425cb44aa09bca53e708a35a`
(Alpine 3.24.1). One build attempt failed on a transient PyPI read timeout (the known
WSL-NAT/VPN flake) and succeeded on retry; no source change between attempts.

### Wheel availability (D5's first named risk)

**No wheel was missing; no builder toolchain was installed.** Both compiled dependencies
resolved to `musllinux` wheels for CPython 3.12 from PyPI — the evidence is pip's own
download lines in the build log:

- `pydantic_core-2.50.4-cp312-cp312-musllinux_1_1_x86_64.whl` (2.5 MB)
- `cryptography-50.0.2-cp311-abi3-musllinux_1_2_x86_64.whl` (5.0 MB)
- `cffi-2.1.1-cp312-cp312-musllinux_1_2_x86_64.whl` (transitive, via cryptography)

All other dependencies are pure-Python (`*-py3-none-any.whl`). The build log carries **no**
"Building wheel for …" line for anything except the project's own package, i.e. no
dependency was compiled from source.

### Runtime invariants (verified at run time against the built image)

Command (entrypoint overridden to a shell so the checks run, not the app):

```
wsl -e docker run --rm --entrypoint sh dial-mcp-gateway:c3 -c '<checks>'
```

- `command -v pip` → `NO-PIP`; `site-packages` scan for `^pip` → none in the venv **and**
  none in the base's `/usr/local/lib/python3.12/site-packages`.
- `command -v gcc cc make` → `NO-TOOLCHAIN` (no compiler in the runtime image).
- `find /opt/venv -name '*.pyc' | wc -l` → `0` (no bytecode written).
- `id -u` / `id -g` → `10001` / `10001`.
- A smoke import of the compiled dependencies on the musl runtime succeeds:
  `import cryptography, pydantic_core, jwt` and a real 2048-bit RSA keygen run clean.
  (The default entrypoint run reaches the settings validation and refuses for missing
  required env vars — the expected shape, and proof the package imports under musl.)

## Task 3.3 — the Trivy OS-package scan

```
wsl -e trivy image --skip-db-update --severity HIGH,CRITICAL --scanners vuln dial-mcp-gateway:c3
```

Scanned tag: `dial-mcp-gateway:c3`
(id `sha256:23a57769…`). Date: 2026-11-09.

Result — **Alpine OS-package row: 0 vulnerabilities at HIGH/CRITICAL**
(`dial-mcp-gateway:c3 (alpine 3.24.1)  alpine  0`). The recorded Debian-slim debt
(44 HIGH OS-package findings) is cleared. The Python-package rows are all `0` as well;
the loaded crypto libraries are `libcrypto3-3.5.9-r0` / `libssl3-3.5.9-r0` and `libuuid`
is `2.42.3-r1`.

Counter-check (the debt that motivated the `libuuid` extension): before the extension the
same scan reported **7 HIGH, 0 CRITICAL**, all from `libuuid` 2.42.1-r0; after the
extension the row is **0**.

## Follow-up — the fresh-DB bump (2026-11-11)

The task-3.3 green above was against a Trivy vulnerability DB dated **2026-11-01**. A
fresh-DB re-scan on **2026-11-11** (DB `UpdatedAt 2026-11-10 19:01 UTC`; Trivy 0.71.2)
against the same `dial-mcp-gateway:c3` image (`sha256:23a57769…`) reported **19 HIGH, 0
CRITICAL**, all in the Alpine base — the "a stale scanner is not a green gate" case
exactly, and the remedy is the dependency bump rather than a re-triage.

### The finding (fresh DB, before the bump)

The 19 findings, by package and the upstream fix each needs (all `v3.24/main`, all with a
fix available):

| Package | Installed | Fixed | Findings |
| --- | --- | --- | --- |
| krb5-libs | 1.22.2-r1 | 1.22.3-r0 | 16 (CVE-2026-107364, -112315…-112323, -118380, -119079, -40355, -40356, -71199, -71200) |
| musl | 1.2.6-r2 | 1.2.6-r3 | CVE-2026-107891 |
| musl-utils | 1.2.6-r2 | 1.2.6-r3 | CVE-2026-107891 |
| zlib | 1.3.2-r0 | 1.3.2-r1 | CVE-2026-85091 |

### The bump

The `apk upgrade --no-cache` line in **both** stages gained `krb5-libs musl musl-utils
zlib`, keeping the three packages already named (`libcrypto3 libssl3 libuuid`). The
per-package style is unchanged — no whole-tree `apk upgrade` — so a base-image change
still cannot silently pull in an unreviewed package bump. The Dockerfile comment states
the behavior and the reason (the base packages' CVE fixes pinned by name, the scanner
bar); the CVE numbers live here.

Rebuild:
`wsl -e docker build -t dial-mcp-gateway:c3 /mnt/c/.../c3-one-pod-and-keysets`, result
**exit 0**, new image id `sha256:c385759fd90d74f5ad531eeaec69f420b7afb5b974e176e82faa7de9ad346d8f`,
~112 MB, Alpine 3.24.1. Two attempts were lost to the known WSL-NAT flake before the
third built clean — one an `apk` fetch hang (the layer sat ~12 min at 5 s CPU with no
network progress), one a PyPI resolver error in the builder's `pip install .`
(`ResolutionImpossible` on `pyjwt[crypto]==2.15.1`, "no matching distributions available
for your environment"; the pin is unchanged and the same resolution succeeded on the next
attempt). Neither was a source or Dockerfile fault; the third attempt installed the full
set (pyjwt 2.15.1 among it) and exported the image.

### The re-scan (fresh DB, after the bump)

    wsl -e trivy image --skip-db-update --severity HIGH,CRITICAL dial-mcp-gateway:c3

- Alpine OS-package row: **0** (`dial-mcp-gateway:c3 (alpine 3.24.1)  alpine  0`).
- Every Python-package row: **0**.
- Counter-check against the pre-bump image (now dangling, `sha256:23a57769…`), same
  fresh DB: **19 HIGH, 0 CRITICAL** — reproducing the finding, so the bump is what
  cleared it rather than a changed scanner.
- Package versions in the rebuilt image (`apk info -v`): `krb5-libs-1.22.3-r0`,
  `musl-1.2.6-r3`, `musl-utils-1.2.6-r3`, `zlib-1.4-r0` (the `zlib` bump landed even one
  revision past the named fix), alongside the unchanged `libcrypto3-3.5.9-r0` /
  `libssl3-3.5.9-r0` / `libuuid-2.42.3-r1`.

Secret scan clean:

    wsl -e trivy image --skip-db-update --scanners secret dial-mcp-gateway:c3   -> 0 findings

### The functional check

The pod-shaped stack was recreated on the rebuilt image
(`wsl -e docker compose up -d --build`; the gateway container runs image
`sha256:0fe5b5ace560…`, built from this worktree's `Dockerfile`). Both services came up
healthy — the gateway holding the single published port `0.0.0.0:8090->8090/tcp` with its
8091 container-internal, the router healthy and publishing nothing.

    python scripts/probe_routing.py   -> all 11 probes passed   (exit 0)

The battery is green on the bumped base: the negative control red as required, and
front-door routing, both data-path challenge rewrites, query-string survival on both
routes, and the dropped-status fall-through all pass. This is the compose-boot gate
re-confirmed on the bumped image; nothing about the base-package bump changes the
gateway's behavior, and the battery is the check that says so rather than assumes it.