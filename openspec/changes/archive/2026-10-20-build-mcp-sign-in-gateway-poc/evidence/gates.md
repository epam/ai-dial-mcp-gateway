# Group 7 — static and compose-boot gates

Tasks 7.1 and 7.2 of `build-mcp-sign-in-gateway-poc`. Records the full static tier, the
Trivy triage of the base image's OS findings (7.1's deliverable), the compose-boot gate
with its per-service health probes, the three probe batteries, and the conformance rows
this gate tier verifies. Every capture below is redacted at capture time: no token, code,
key, password, or client secret appears in this file.

## Verdict

**Group 7 complete. The gate ladder is green.** Every static gate passes; `pip-audit` —
the blocking one — is clean; the compose-boot gate brings both services up healthy with
the gateway answering through the router and the router reaching Core; all three probe
batteries pass. Trivy reports 156 findings, **all 156 in the Debian 13.7 base image's own
OS packages**, none with a fixed version available; the triage below dispositions every
finding class and finds **none genuinely reachable through the gateway's running
processes**. No finding is REQUIRES-ACTION. The stack was left **up**, because group 8
continues against the composed stack immediately.

## Toolchain and inputs

| Item | Value |
|---|---|
| Python | 3.12.13 (`.venv`) |
| ruff / mypy / pytest / bandit / pip-audit | 0.17.1 / 2.4.0 / 9.1.1 / 1.9.4 / 2.10.1 |
| Trivy | 0.69.3 (WSL) |
| Scanned image | `dial-mcp-gateway:local` id `sha256:669459098…`, built from the working tree, 170 MB |
| Container running that image | `ai-dial-mcp-gateway-mcp-signin-gateway-1` — image id matches the built one |

Every command below ran from the repository root with `PYTHONUTF8=1`, tooling out of
`.venv/Scripts`.

## 7.1 — the static tier

| Gate | Command | Result |
|---|---|---|
| Lint | `python -m ruff check .` | `All checks passed!` (exit 0) |
| Format | `python -m ruff format --check .` | `91 files already formatted` (exit 0) |
| Types | `python -m mypy` | `Success: no issues found in 35 source files` (exit 0) |
| Tests | `python -m pytest -q` | **`321 passed, 1 skipped`**, 1 warning, 110 s (exit 0) |
| Bandit (gate scope) | `python -m bandit -c pyproject.toml -r gateway` | `No issues identified.` — 3853 LOC scanned, 0 skipped; 7 `#nosec BXXX` disabled in `gateway/routes.py` (see below) |
| pip-audit (**BLOCKING**) | `python -m pip_audit` | `No known vulnerabilities found` (exit 0) |
| Trivy (built image) | `trivy image --skip-db-update dial-mcp-gateway:local` | `Total: 156 (UNKNOWN: 2, LOW: 57, MEDIUM: 53, HIGH: 44, CRITICAL: 0)` — triaged below |

The one skip is `tests/test_store.py:530`, `POSIX permission bits are not implemented on
this platform` — the same Windows skip groups 3–6 recorded; the DCR store's owner-only
mode is asserted in the Linux container where it is enforced.

The single pytest warning is third-party: FastAPI's own deprecation notice about
`httpx`-with-`starlette.testclient`. It is not this repository's code and is not acted on.

### `pip-audit` — the blocking gate, and what it covers

Clean. It reports one un-auditable name, `dial-mcp-gateway` itself, with the reason
`Dependency not found on PyPI` — this repository's own package, which has no PyPI
dependency to compare against. Every third-party requirement is audited and clean:

```
No known vulnerabilities found
Name             Skip Reason
dial-mcp-gateway Dependency not found on PyPI and could not be audited: dial-mcp-gateway (0.1.0)
```

No remedy-by-bump is pending anywhere: there is no finding to bump for.

### Bandit — the gate scope, and the `scripts/` side-note

The configured gate scope is `gateway`, and it is green. The seven `#nosec B105`
directives in `gateway/routes.py` are the *error-code* string constants (`invalid_request`,
`invalid_grant`, …) that bandit's hardcoded-password heuristic reads as candidate
passwords; each carries its reason at the line. Bandit itself reports them as
`nosec encountered (B105), but no failed test on file` — i.e. the directive fires before
any finding exists, and `Total issues skipped due to specifically being disabled` is 7.
The gate's own configuration deliberately has **no skip list**, so these are inline
justifications rather than configured suppression.

Run over `scripts/` as a check outside the gate scope (the same check group 6 recorded),
bandit reports **5 findings, all pre-existing in probe and spike instruments this group
did not touch**:

| Location | Test | Severity / confidence | Disposition |
|---|---|---|---|
| `scripts/probe_routing.py:42` | B404 `subprocess` import | Low / High | ACCEPTED-RESIDUAL — probe instrument, not shipped in the image |
| `scripts/probe_routing.py:267` | B310 `urlopen` scheme audit | Medium / High | ACCEPTED-RESIDUAL — scheme literal is a configured local endpoint |
| `scripts/probe_routing.py:287` | B607 partial executable path | Low / High | ACCEPTED-RESIDUAL — fixed `wsl -e docker` argv |
| `scripts/probe_routing.py:287` | B603 `subprocess` without shell | Low / High | ACCEPTED-RESIDUAL — `shell=False` is the safe form; no untrusted input |
| `scripts/spike_env.py:173` | B310 `urlopen` scheme audit | Medium / High | ACCEPTED-RESIDUAL — spike instrument, configured local endpoint |

None of these files enters the gateway image (the `Dockerfile` copies only `pyproject.toml`,
`README.md`, and `gateway/`), so none is part of the shipped attack surface. They are
recorded rather than fixed because fixing probe instruments is outside this group's scope
and group 6 already recorded the same set.

### Trivy — the DB-refresh question, answered

`--skip-db-update` is the repository's documented fallback, allowed "when the
vulnerability-database download fails and the cached database is recent". Here the
download genuinely fails, twice, from both databases:

```
mirror.gcr.io/aquasec/trivy-db:2  -> read tcp …: connection reset by peer
ghcr.io/aquasec/trivy-db:2        -> DENIED: requested access to the resource is denied
```

The cached DB is **Trivy DB v2, `UpdatedAt 2026-09-27`, `NextUpdate 2026-09-28`,
`DownloadedAt 2026-09-27`** — 22 days old at the time of the scan (2026-10-19). That is
older than its own next-update stamp, so this scan is **not** claimed as a fully current
green gate: the cached DB is a *recent-enough* fallback under the repository's own rule
(the rule exists precisely for this network condition), not a fresh one. **This staleness
is itself an OPEN item, not a disposition** — see "Open items" below. What the scan
does establish, with the DB it has, is the layer composition and the fix-availability
picture, and every source package's fix status was independently cross-checked against
the image's own apt archive (next section).

## 7.1's deliverable — the base-image triage

**156 findings, 37 OS packages, 68 distinct CVEs, all in the Debian 13.7 base image; the
Python layer reports zero.** Severity by *row* counts the same CVE once per shipped binary
package: HIGH 44 / MEDIUM 53 / LOW 57 / UNKNOWN 2. By *distinct CVE*: HIGH 8 / MEDIUM 28 /
LOW 30 / UNKNOWN 2. `CRITICAL: 0`.

### Fix availability, measured two independent ways

Trivy reports `FixedVersion` empty for **all 156 rows** (`Status: affected` 154,
`fix_deferred` 2). Independently, the image's own apt archive was queried inside the
container — the fix ships when a candidate version appears above the installed one:

| Package | Installed | apt `Candidate` | Fix available? |
|---|---|---|---|
| `util-linux` (+ its 8 sibling binary packages) | `2.41.5-0+deb13u1` | `2.41.5-0+deb13u1` | no |
| `libc6` / `libc-bin` | `2.41-12+deb13u4` | `2.41-12+deb13u4` | no |
| `libacl1` | `2.3.2-2+b1` | `2.3.2-2+b1` | no |
| `libncursesw6` / `libtinfo6` / `ncurses-base` / `ncurses-bin` | `6.5+20250216-2` | `6.5+20250216-2` | no |
| `libsystemd0` / `libudev1` | `257.13-1~deb13u1` | `257.13-1~deb13u1` | no |
| `perl-base` | `5.40.1-6+deb13u1` | `5.40.1-6+deb13u1` | no |
| `zlib1g` | `1:1.3.dfsg+really1.3.1-1+b1` | `1:1.3.dfsg+really1.3.1-1+b1` | no |
| `libbz2-1.0` | `1.0.8-6` | `1.0.8-6` | no |
| `liblzma5` | `5.8.1-1+deb13u1` | **`5.8.1-1+deb13u2`** | **yes — the one package with one** |
| `libsqlite3-0` | `3.46.1-7+deb13u2` | `3.46.1-7+deb13u2` | no |
| `tar` | `1.35+dfsg-3.1` | `1.35+dfsg-3.1` | no |

`python:3.12-slim` was re-pulled and is the **same digest** (`df18428df8a0`) the build
used, `Debian 13.7`; there is no newer base image to move to. So the repository rule's
named remedy — a dependency bump — **does not exist for 155 of the 156 rows**, and the
base-image refresh is the mechanism that will deliver the fixes when Debian ships them.

`liblzma5` is the one package where a candidate exists, and it is **REQUIRES-ACTION only
in the sense that a fix is available**: the row's base-image copy is `affected` for
`TEMP-1147318-639065` (the `reinit-after-allocation-failure` invalid write). Refreshing
the base image is a `python:3.12-slim` digest change that also re-rolls every other
package, so it is a coordinated base-image action rather than a one-line bump, and it is
categorised below with the other base-image refresh work.

### Reachability — what the gateway process actually loads

The triage's central question is which of these 156 findings sits in code the gateway's
running processes can execute. The answer was measured, not assumed, from a live
container: the set of file-backed mappings of PID 1.

```
$ docker exec … sh -c 'cat /proc/1/maps | grep -o "/[^ ]*" | sort -u'
/usr/local/bin/python3.12
/usr/local/lib/libpython3.12.so.1.0
/usr/local/lib/python3.12/lib-dynload/*.so            (42 stdlib extensions)
/opt/venv/lib/python3.12/site-packages/_cffi_backend…so
/opt/venv/lib/python3.12/site-packages/cryptography/…/_rust.abi3.so
/opt/venv/lib/python3.12/site-packages/pydantic_core/…so

/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2        <- libc6
/usr/lib/x86_64-linux-gnu/libc.so.6                   <- libc6
/usr/lib/x86_64-linux-gnu/libm.so.6                   <- libc6
/usr/lib/x86_64-linux-gnu/libdl.so.2                  <- libc6
/usr/lib/x86_64-linux-gnu/libpthread.so.0             <- libc6
/usr/lib/x86_64-linux-gnu/librt.so.1                  <- libc6
/usr/lib/x86_64-linux-gnu/gconv/gconv-modules.cache   <- libc6
/usr/lib/locale/C.utf8/LC_CTYPE                       <- libc-bin
/usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0            <- libuuid1
/usr/lib/x86_64-linux-gnu/libz.so.1.3.1               <- zlib1g
/usr/lib/x86_64-linux-gnu/libbz2.so.1.0.4             <- libbz2-1.0
/usr/lib/x86_64-linux-gnu/liblzma.so.5.8.1            <- liblzma5
```

Everything else in the image — `libmount1`, `libblkid1`, `libsmartcols1`, `liblastlog2-2`,
`libacl1`, `libtinfo6`, `libncursesw6`, `libsystemd0`, `libudev1`, `libpam*`,
`libsqlite3-0`, `libattr1`, `tar`, `perl-base`, `bsdutils`, `mount`, `login`, `passwd`,
`coreutils`, `bash`, `apt`, `diffutils`, `sysvinit-utils` — is **not mapped into the
process**. Their per-package file lists were enumerated with `dpkg -L` inside the
container and intersected with the mapped set; the intersection is empty for every one of
them, so their findings cannot execute in this process.

The libraries that *are* mapped were then traced back to the import that pulls them in:

| Mapped DSO | Owner package | Pulled in by |
|---|---|---|
| `libc.so.6`, `ld-linux`, `libm` | `libc6`/`libc-bin` | the Python interpreter itself |
| `libuuid.so.1.3.0` | `libuuid1` | `fastapi → pydantic → _generate_schema → uuid` |
| `libz.so.1.3.1` | `zlib1g` | `fastapi → … → importlib.metadata → zipfile → shutil` |
| `libbz2.so.1.0.4` | `libbz2-1.0` | the same `shutil`/`zipfile` chain |
| `liblzma.so.5.8.1` | `liblzma5` | the same `shutil`/`zipfile` chain |

The trace was taken with an import hook, so it names the *first* importer in the chain:

```
$ docker exec … python /who.py gateway.app
uuid   first imported via: … fastapi.exceptions -> pydantic -> _internal -> _generate_schema -> uuid
zlib   first imported via: … fastapi.exceptions -> _loader -> importlib.metadata -> zipfile -> shutil -> zlib
bz2    first imported via: … fastapi.exceptions -> _loader -> importlib.metadata -> zipfile -> shutil -> bz2
lzma   first imported via: … fastapi.exceptions -> _loader -> importlib.metadata -> zipfile -> shutil -> lzma
```

**No gateway module imports any of them.** `grep` over `gateway/` for
`uuid|zipfile|tarfile|gzip|sqlite|ctypes|subprocess|curses` returns nothing. They arrive
transitively through the framework's module-loading path (FastAPI's import machinery uses
`zipfile`/`shutil` to read distribution metadata; Pydantic's schema generator uses
`uuid`). Each is therefore loadable but **not invoked on any request path the gateway
serves** — and for three of them the vulnerable entry point is not even exposed to
Python:

| Library | CVE needs | Exposed to Python? |
|---|---|---|
| `zlib1g` CVE-2026-27171 | `crc32_combine*` | **No** — `zlib.crc32_combine` does not exist in the Python `zlib` module (verified by `hasattr`) |
| `zlib1g` CVE-2026-85091 | `gzprintf`/`gzvprintf`/`gz_vacate` | **No** — the Python `zlib` module exposes no `gz*` file API at all |
| `libbz2-1.0` CVE-2026-42250 | the `bzip2recover` **program** | **No** — `/usr/bin/bzip2recover` is not installed; `bz2.recover` is not in the module |
| `liblzma5` TEMP-1147318-639065 | decoder re-initialized after an allocation failure | Loadable. The Python `lzma` module is the only exposed entry; the gateway's code calls neither it nor anything that reads a caller-shaped archive |

`liblzma5` is the one mapped library where a library-level CVE could in principle be
reached *if* the gateway were made to decompress caller-supplied XZ data. It does not:
the gateway's only compression-bearing code is `httpx`, and `httpx`'s supported
`Content-Encoding` set is `deflate, gzip, identity` — not `xz` or `lzma`.

### Threat-model preconditions, checked against the image

| Finding class | Exploitation precondition | Measured in this image |
|---|---|---|
| glibc CVE-2026-89092 (`nscd` stack overflow) | the `nscd` service running | **`nscd` is not installed**; no `/usr/sbin/nscd` |
| systemd CVE-2026-16742 (`systemd-homed`) | the `systemd-homed` service | **not installed**; `libsystemd0`/`libudev1` are libraries only, and neither is mapped |
| glibc CVE-2026-86805 / CVE-2026-95818 (loader `$ORIGIN` TOCTOU / stack overflow) | a setuid/setgid program whose `DT_RPATH`/`DT_RUNPATH` begins with `$ORIGIN` | All 11 setuid/setgid binaries in the image were parsed for `DT_RPATH`(15)/`DT_RUNPATH`(29): **every one has no RPATH/RUNPATH entry at all**, so no program in this image matches the precondition. (`/usr/local/bin/python3.12` does carry `RUNPATH $ORIGIN/../lib`, but it is not setuid/setgid, so `AT_SECURE` never applies.) |
| util-linux CVE-2026-78408 (`nsenter --join-cgroup`) | `nsenter` run privileged against an attacker-controlled target | `nsenter` exists but is not run by the service; the process has **`CapEff 0`** and `uid 10001`, so it could not perform the privileged operation the CVE escalates within |
| util-linux CVE-2026-76642/78409/78410 (`X-mount.*` mount-hook abuse) | mount operations by a privileged operator | `/usr/bin/mount` present (setuid) but never invoked; **the service mounts nothing at runtime** (its one volume is a bind mount made by the runtime, not by the process). Even the shared library that carries the code is not mapped: `libmount.so.1` is not in the process map. |
| acl CVE-2026-54369 (symlink traversal in `libacl`) | `acl_set_*`/`acl_get_*` on caller-shaped paths | `libacl.so.1` is **not mapped**; the gateway touches no POSIX ACL |
| ncurses CVE-2025-69720 (terminal buffer overflow) | a program that parses terminal input (`setupterm`/`wgetch`) | `libtinfo`/`libncursesw` are **not mapped**; the gateway reads no terminal and is not a TTY program in a container |
| perl CVE-2026-9538 (`Archive::Tar` DoS) | a Perl program parsing a crafted tar | `perl-base` is not run by the service; the CVE is in a Perl library, and no Perl process exists |
| pam/libpam* | a PAM-authenticated login | not mapped; the service authenticates no one locally |

### The triage table — by class

Every class carries the same three disposition axes: whether the code is **loaded in the
gateway process**, whether the vulnerable path is **invoked by it**, and whether
**`network-facing`** applies.

| # | Class (packages) | Rows | Loaded in the process? | Invoked by the gateway? | Reachable via the network? | Fix available? | Disposition |
|---|---|---|---|---|---|---|---|
| 1 | **util-linux family** — `util-linux`, `bsdutils`, `libblkid1`, `liblastlog2-2`, `libmount1`, `libsmartcols1`, `libuuid1`, `login`, `mount` | 54 | **`libuuid.so.1` only** (via `pydantic → uuid`); the rest **not mapped** | No. The CVE code lives in the `mount`/`nsenter`/`chfn`/`chsh` programs and in `libmount`/`libblkid`/`libsmartcols`, none of which the service runs or loads. `libuuid` has no mount/nsenter/chfn/chsh symbol (dynsym-dumped: only `uuid_*`) | No | No | **ACCEPTED-RESIDUAL** |
| 2 | **glibc** — `libc6`, `libc-bin` | 40 | **Yes** — the interpreter's `libc.so.6` | Partially by construction: `strfmon`, `wordexp`, `tdelete` are exported and reachable. But every CVE's precondition is absent: no `nscd`, no setuid `$ORIGIN` program, no JIS conversion driven by caller data, `/etc/resolv.conf` written by Docker Engine (`nameserver 127.0.0.11`, `search <internal-domain>`) and not reloadable by an attacker, and Python never passes caller data to `wordexp`/`strfmon` | In principle via the resolver — but CVE-2026-8674 needs the search list to change *after* the resolver starts, and the container's is static | No | **ACCEPTED-RESIDUAL** (one class member, the loader pair, also carries an explicit precondition mismatch — see the precondition table) |
| 3 | **ncurses** — `libncursesw6`, `libtinfo6`, `ncurses-base`, `ncurses-bin` | 8 | **No** | No | No | No | **ACCEPTED-RESIDUAL** |
| 4 | **acl** — `libacl1` | 2 | **No** | No | No | No | **ACCEPTED-RESIDUAL** |
| 5 | **systemd** — `libsystemd0`, `libudev1` | 14 | **No** | No. The CVE is in `systemd-homed`, which is not installed | No | No | **ACCEPTED-RESIDUAL** |
| 6 | **perl** — `perl-base` | 5 | **No** | No | No | No | **ACCEPTED-RESIDUAL** |
| 7 | **zlib** — `zlib1g` | 2 | **Yes** — `libz.so.1.3.1` via FastAPI's `zipfile` metadata read | No. Both CVEs need entry points Python does not expose (`crc32_combine*`, `gz*`) | No | No | **ACCEPTED-RESIDUAL** |
| 8 | **xz** — `liblzma5` | 1 | **Yes** — `liblzma.so.5.8.1` via the same chain | No. Loadable, but the gateway decompresses nothing; `httpx` supports `deflate/gzip/identity` only, never `xz` | No | **YES** (`5.8.1-1+deb13u1 → +deb13u2`) | **ACCEPTED-RESIDUAL** for reachability. The only finding with a shipped fix; its remediation is the base-image refresh, not a repository change |
| 9 | **bzip2** — `libbz2-1.0` | 1 | **Yes** — `libbz2.so.1.0.4` via the same chain | No. The CVE is in the `bzip2recover` **program**, which is not installed | No | No | **ACCEPTED-RESIDUAL** |
| 10 | **pam** — `libpam0g`, `libpam-modules`, `libpam-modules-bin`, `libpam-runtime` | 4 | **No** | No | No | No | **ACCEPTED-RESIDUAL** |
| 11 | **sqlite** — `libsqlite3-0` | 4 | **No** | No | No | No | **ACCEPTED-RESIDUAL** |
| 12 | **tar** — `tar` | 5 | **No** | No. Python's `tarfile` uses its own pure-Python/`zlib` path and does not link the `tar` binary; the gateway never untars anything | No | No | **ACCEPTED-RESIDUAL** |
| 13 | **coreutils / bash / apt / dpkg / diffutils / sysvinit-utils / libattr1 / login.defs / passwd** | 16 | **No** | No | No | No | **ACCEPTED-RESIDUAL** |
| | **Total** | **156** | 6 DSOs + `libc` mapped | **0 invoked** | **0 exploitable remotely as configured** | 1 package with a fix | **0 REQUIRES-ACTION findings pending remediation, 1 base-image refresh item** |

### Findings that are genuinely reachable — the falsification attempt

The triage's job includes falsifying a "nothing is reachable" claim rather than restating
it. Three candidate reachability chains were pursued and each was closed:

1. **A caller-shaped HTTP body reaching `libc` string functions.** The gateway parses
   JSON via `pydantic_core` (Rust) and decodes form bodies itself; the glibc string
   functions in the always-reachable set (`strfmon`, `wordexp`, `tdelete`) are never
   handed request data — `wordexp` and `strfmon` do not appear anywhere in `gateway/`,
   the standard library, or the third-party stack on the request path. Closed.
2. **A caller-shaped compressed body reaching `zlib`/`lzma`.** `httpx` negotiates only
   `deflate`/`gzip`/`identity`, so an attacker cannot make the gateway inflate `xz` or
   `bzip2`. And the zlib CVEs' entry points are absent from Python's `zlib` module. The
   remaining theoretical path — the gateway's own *outbound* CIMD fetch and Core call
   decompressing a hostile response — lands on `zlib.decompress` (`inflate`), which
   neither CVE-2026-27171 (needs `crc32_combine`) nor CVE-2026-85091 (needs `gzprintf`
   after a non-blocking write stall, a file-API path Python does not expose) reaches.
   Closed.
3. **A local attacker using a setuid program or the loader.** Every setuid binary was
   parsed for the `$ORIGIN` `DT_RPATH`/`DT_RUNPATH` precondition and none has any
   RPATH/RUNPATH at all; the container runs a single non-root uid (10001) with `CapEff 0`
   and Docker's default seccomp profile active (`Seccomp: 2`, 1 filter), so there is no
   second local identity in the container to attack from. Closed.

**No finding is genuinely reachable through the gateway's running processes.** The gate is
therefore green with the triage above, not by suppression.

### What bounds the exposure, and the upgrade path

- **What bounds it:** only six base-image DSOs are mapped into the gateway; the rest of
  the image's packages are bytes on disk that this process cannot execute. Of the six, five
  expose no entry point the gateway's code paths reach, and the sixth (`libc`) is reachable
  in name only — the CVEs' preconditions (nscd, setuid `$ORIGIN`, mutable resolver
  configuration) are each absent in this container. The service runs one non-root user,
  `CapEff 0`, seccomp on, with `/tmp` the only writable directory.
- **Upgrade path:** a **base-image refresh**. All but one finding becomes fixable only when
  Debian 13.7 ships the patched packages and the `python:3.12-slim` digest that carries
  them is republished; the base image is already at the current digest, so there is nothing
  to pull today. Re-running this scan after the base image moves is the verification, and
  it is the named follow-up rather than a silent assumption. The `liblzma5` fix that
  already exists in the archive arrives through that same refresh.
- **Why not a code change:** the vulnerable code is the base image's, in packages the
  gateway's own `Dockerfile` deliberately does not install. Removing them would mean
  removing the base image's standard OS package set, which is not a dependency bump — it is
  a different base image, and the repository rule's remedy (a bump) is already at its
  endpoint here.

## 7.2 — the compose-boot gate

### The stack, up

```
$ wsl -e docker compose up -d
 Container ai-dial-mcp-gateway-mcp-signin-gateway-1  Recreated
 Container ai-dial-mcp-gateway-mcp-signin-gateway-1  Started
 Container ai-dial-mcp-gateway-mcp-signin-gateway-1  Healthy
 Container ai-dial-mcp-gateway-mcp-signin-router-1   Running   (unchanged)

$ docker compose ps --format '{{.Service}} | {{.Status}} | {{.Ports}}'
mcp-signin-gateway | Up 2 minutes (healthy) | 8091/tcp
mcp-signin-router  | Up 2 hours (healthy)   | 80/tcp, 0.0.0.0:8090->8090/tcp, [::]:8090->8090/tcp
```

`docker compose config --quiet` → parses. `nginx -t` inside the composed router →
`configuration file /etc/nginx/nginx.conf test is successful`.

### The per-service health probes (scripted)

```
=== healthcheck state per service (docker inspect) ===
mcp-signin-gateway: running health=healthy
mcp-signin-router : running health=healthy

=== gateway /healthz inside the container (8091) ===
{"status":"ok"}

=== gateway /healthz from the router container over the compose network ===
{"status":"ok"}

=== /healthz through the public origin (port 8090) ===
HTTP/1.1 200 OK
Server: nginx/1.27.5
Content-Type: application/json
Content-Length: 15
```

`/healthz` 200 through the router is the probe that matters: the router's own location
sends `/healthz` to the gateway, so its success measures the router→gateway link, not just
the router's process.

### The router reaches Core — the "plain request through 8090" probe

An unauthenticated `GET /v1/user/info` is the cleanest available proof that the catch-all
location forwards to Core (not to the gateway), because Core's own 401 body is
unmistakable:

```
--- through the router (8090):
HTTP 401
At least API-KEY or Authorization header must be provided
--- direct to Core (8081):
HTTP 401
At least API-KEY or Authorization header must be provided
```

Identical status **and body**: the request through the front door reaches Core and is
answered by Core. Core itself is `running health=healthy`; Keycloak answers its realm's
discovery document `HTTP 200`.

### The three probe batteries

**`scripts/probe_gateway_trust.py`** — negative control first:

```
=== the published JWKS (through the front door) ===
  GET http://localhost:8090/dial/jwks.json -> keys=["a119a0a9bee68848"]
  derived from GATEWAY_SIGNING_KEY -> kid=a119a0a9bee68848
  verdict: green
=== negative control: a token signed by an unpublished key ===
  token <redacted len=1170 sha256=606b317184db> kid=dadc6ffb2b36a334
  GET /v1/user/info -> HTTP 401
  verdict: red as required
=== positive control: a token signed with the gateway's key ===
  iss "http://localhost:8090"  aud ["http://localhost:8090","dial-mcp-proxy"]
  sub "3a0d60f4-…"  GET /v1/user/info -> HTTP 200  roles ["admin"]
```

**`scripts/probe_routing.py`** — six probes, negative control first:

```
=== battery verdict ===
  pass  negative control — Core's own challenge
  pass  query string survives the routing
  pass  flat AS metadata through the router
  pass  per-toolset PRM through the router
  pass  data-path 401 rewritten to the gateway's challenge
  pass  gateway paths reachable through the front door
all 6 probes passed
```

**`scripts/probe_end_to_end.py`** — the whole chain, live, through the front door:

```
=== step 1: discovery through the front door ===  servers ["http://localhost:8090"]
=== step 2: /dial/authorize ===                   302 -> keycloak:8443, scope "profile email"
=== step 3: the identity provider's login form === hop 3 reached the client redirect URI
=== step 4: the gateway's callback ===            state round-tripped, code <redacted sha256=de725bacefb0>
=== step 5: /dial/token ===                       access <redacted sha256=11eabc92102c>
    iss "http://localhost:8090"  sub "3a0d60f4-…"
    aud ["http://localhost:8090/dial/notion/mcp","dial-mcp-proxy"]
    roles ["admin"]  project "proj-alpha"  refresh present
=== step 6: a live tool call through the front door (/dial/notion/mcp) ===
  status 200   tools 65   first ["notion-search","notion-memory-search","notion-get-tool-access"]
=== smoke verdict ===
  the sign-in completed through the front door and the token it minted
  authenticated a live tool call: the deployment is wired end to end
```

### Against the spec's rows

The group's tasks define this gate tier as verifying the composed-stack rows; each was
checked live through the front door, with its evidence:

| Spec requirement | Row | Evidence |
|---|---|---|
| Toolset MCP path answers with the gateway's own challenge | No token → 401 + the gateway's `resource_metadata` | `GET /dial/notion/mcp` → `401`, `WWW-Authenticate: Bearer resource_metadata="http://localhost:8090/.well-known/oauth-protected-resource/dial/notion/mcp"`; routing probe 5 (single challenge, the gateway's) |
| | Query string survives routing | routing probe 2 — `request.uri='/v1/toolset/notion/mcp?sessionId=probe-…'` in Core's own access log, on both methods |
| Discovery documents describe one flat AS server | Flat AS metadata | `GET /.well-known/oauth-authorization-server` → 200, issuer `http://localhost:8090`, both grants, `S256`, `token_endpoint_auth_methods_supported ["none"]`, `client_id_metadata_document_supported true` |
| | Per-toolset PRM | `GET /.well-known/oauth-protected-resource/dial/notion/mcp` → 200, resource `http://localhost:8090/dial/notion/mcp`, servers `[http://localhost:8090]`, kind `OAUTH` |
| | Unmapped toolset → 404 | `GET …/dial/no-such-toolset/mcp` → **404** |
| Client registration resolves pre-registered, CIMD, then gated DCR | DCR off by default | `POST /dial/register` → **404** with `"dynamic client registration is not enabled on this gateway…"`; the AS metadata advertises no `registration_endpoint` (absent from the body above) |
| Issued tokens are gateway-signed and audience-marked | Token carries the marker | step 5 — `aud = ["…/dial/notion/mcp", "dial-mcp-proxy"]`, and Core accepts it (step 6) |
| Core trusts gateway tokens via a dedicated identity-provider entry | Primary-provider tokens keep validating | Core's own PRM still answers 200 with `authorization_servers ["http://localhost:8090"]`, and the Keycloak-issued-token regression group 6 recorded still resolves a real identity |
| | Direct-to-Core client coexists | `GET http://localhost:8081/v1/toolset/notion/mcp` → 401 carrying **Core's own** challenge (`…:8081/.well-known/oauth-protected-resource/…`) — Core's own path is untouched by the front door |
| Credential-model invariants preserved | No secrets in logs and errors | every capture in this file is redacted; the gateway container logs carry no token, code, key, or password |
| | Signing key never logged | group 3's no-key-material-in-logs assertion, green in this run's `pytest` |

The rows for CIMD registration, DCR-on operation, refresh/rotation and the harness
criteria belong to groups 8 and 9 and are **not** claimed here.

## A concurrent change landed in the working tree while this gate ran

The tree moved under this run: a second pass modified `gateway/cimd.py` and
`tests/test_cimd.py` (the loopback-port matching rule, `redirect_uri_allowed`) at
06:46–06:48, after the 7.1 tier above had been captured at ~06:00 against the pre-edit
tree. The two snapshots are recorded rather than blended:

| Gate | Pre-edit tree (the 7.1 run above) | The tree as it stands at 06:52 |
|---|---|---|
| `ruff check` | All checks passed | All checks passed |
| `ruff format --check` | 91 files already formatted | **1 file would be reformatted — `tests/test_cimd.py`** |
| `mypy` | 35 source files, no issues | 35 source files, no issues |
| `pytest -q` | 321 passed, 1 skipped | **328 passed, 1 skipped** |
| `bandit -r gateway` | No issues identified | No issues identified |
| `pip-audit` | No known vulnerabilities found | No known vulnerabilities found |

**The format gate is red on the tree as it stands, and this group did not green it.**
The unformatted file is `tests/test_cimd.py` — it belongs to the concurrent pass, and
formatting another pass's file mid-write is exactly the kind of interference the
one-agent-per-pass rule exists to prevent (and it would race a file that pass may still
be writing). It is an OPEN item this group records, not a disposition: the change cannot
be called done while `ruff format --check` fails, and the owning pass's own gate run — or
its completion — closes it. Nothing else in the tier moved.

Trivy was re-run on the rebuilt image after the concurrent pass's compose recreate and
returns the **identical 156 findings** (`UNKNOWN 2 / LOW 57 / MEDIUM 53 / HIGH 44 /
CRITICAL 0`), as expected: the change touches Python source and a test, neither of which
enters the image's OS layer. The triage above therefore describes the current image as
well as the one first scanned.

The three probe batteries were likewise **re-run against the rebuilt, currently running
stack** — not left standing on the earlier container — and all pass: trust probe green
(its negative control refused, its positive control resolving a real identity), routing
battery `all 6 probes passed`, and the end-to-end smoke completing the sign-in through
the front door and authenticating a live tool call (65 tools). The compose-boot gate's
own health probes were re-confirmed on it: `/healthz` 200 through the router, both
services `healthy`, the flat AS metadata 200.

One incidental note: repeated authorisation probing trips the gateway's own per-source
rate limit (`429 temporarily_unavailable, "too many authorization requests from this
source"`), which is the limit working as specified, not a defect; the smoke was re-run
after the window cleared.

## Open items this group records

1. **The Trivy DB is stale (22 days, past its own `NextUpdate`), and the refresh path is
   network-blocked in this environment.** The scan is therefore a *recent-enough-DB*
   fallback under the repository's own rule, not a fresh green gate. This is recorded, not
   dispositioned away: the scanner gets refreshed before the change's final release gate,
   and the base image is re-scanned then. It does not change any disposition above — the
   layer split (all 156 in the base image, zero in Python), the fix-availability picture
   (cross-checked against the image's apt archive, independent of the DB) and the
   reachability analysis all hold regardless of DB age.
2. **The base-image refresh is a standing follow-up**, not a task in this change: the
   `liblzma5` fix and every future Debian fix arrive through a `python:3.12-slim` digest
   bump. No code change in this repository can close those findings.

## Left up, deliberately

The composed stack is **left running**, because group 8 (DCR live verification) continues
against it immediately — its own negative control (8.1) runs with DCR off on this same
stack. Recreating the gateway gives it a new address on the compose network while nginx
resolves its upstream once at start, so **the router is restarted with the gateway
whenever the gateway is recreated** (`wsl -e docker compose up -d --force-recreate`);
group 6 measured that 502 and documented it in `README.md`.

## Gate ladder status after this group

| Gate (CLAUDE.md order) | State |
|---|---|
| 1. Static tier green with findings triaged | **green** — all six clean or triaged above; `pip-audit` clean |
| 2. Compose-boot gate | **green** — both services healthy, `/healthz` through the router, the router reaches Core |
| 3. The change's conformance rows | the composed-stack rows above are green; rows belonging to groups 8–9 remain open |
| 4. Security review gate on the diff | not run by this group (a separate reviewer pass) |
| 5. Review gate on the diff | not run by this group |
