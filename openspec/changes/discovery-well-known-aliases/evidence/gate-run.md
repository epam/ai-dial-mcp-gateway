# Gate run - discovery well-known aliases

The implementation pass's gate record, against the tree as implemented. Hostnames are the
composed stack's local ones; no credential appears.

## Environment (read first)

The composed stack's DIAL Core and Keycloak come from a sibling instance repository that is
not present on the implementation host, so the compose-boot and re-test runs used this
repository's own compose project (gateway and router, built from this tree) beside a local
stand-in for Core that models the behaviors the routing rows observe (see
`instrument-run.md`). The rows that need a minted identity token and Core's request log (the
two query-string rows) were not run. The owner-run live re-test (W11, tasks 6.5) is the
check against the real Core and the real deployment.

## Lightweight gates

| Gate | Result |
|---|---|
| `ruff check` | green |
| `ruff format --check` | green. On this Windows host the working tree is CRLF while the index is LF, and ruff's default wants LF, so the check is run as `ruff format --check --config 'format.line-ending = "cr-lf"' .`; the same sources are formatted under the repository's default on a LF checkout. |
| `mypy` (`files = gateway, tests`) | 3 errors, all in test files this change did not touch: `tests/test_leak_check.py` (`check_publication_leaks` not importable as a module), `tests/test_idp.py:1454` and `tests/test_federation.py:409` (`str or None` passed where `str` is expected). No error in `gateway/` or in the two test files this change edited. Pre-existing; not opened as a defect here. |
| `pytest -q` | 770 passed, 1 skipped (the new alias rows included) |

## Static gates

| Gate | Result |
|---|---|
| `bandit -r gateway -c pyproject.toml` | no issues (0 low, 0 medium, 0 high) |
| `pip-audit` | no known vulnerabilities (the project itself is not on PyPI, so it is skipped by name) |
| Trivy, the gateway image `dial-mcp-gateway:local` | 0 HIGH or CRITICAL (OS packages and Python packages). Trivy is not installed in WSL on this host, so the scan ran from the `aquasec/trivy` image with a freshly downloaded database. |
| Trivy, the router base image `nginx:1.27-alpine` | **70 HIGH or CRITICAL findings** in the base image's OS packages (`libcrypto3`, `libssl3`, `curl`, `libcurl`, `libxml2`, `libxslt`, `musl`, `pcre2`, `zlib`, `libexpat`, `libpng`, `tiff`, `c-ares`, `nghttp2-libs`, `brotli-libs`). Triage: pre-existing and outside this change - the compose file pins this tag and this change does not touch it; the tag is already at the end of its line (a pull reports it up to date), so the remedy is a base-image bump to a maintained nginx line, which needs its own run of the router checks. Flagged for the owner; not remedied here. |
| `python scripts/check_publication_leaks.py` | exit 0; 308 tracked files scanned, 3 findings, all waived, 0 unwaived |
| grep of the change's new and edited files for hostnames and personal paths | see the closing note of this file |

## Compose-boot

`docker compose up -d --build` from a clean `down`: the gateway reports healthy, then the
router reports healthy (its health probe crosses to the gateway), and `GET /healthz`
through the router answers `200`. Core in this run is the stand-in. The acceptance-profile
fixture was not started.

## Re-test

The same battery first, then the full battery (`probe_routing.py --no-token`), against the
rebuilt stack:

```text
=== battery verdict ===
  pass      negative control — Core's own challenge
  pass      W0 negative control — Core's own answer on a discovery path
  pass      W0c negative control — the gateway's own 404
  skipped   query string survives the routing
  pass      flat AS metadata through the router
  pass      per-toolset PRM through the router
  pass      data-path 401 rewritten to the gateway's challenge
  pass      gateway paths reachable through the front door
  pass      consent action route reachable through the front door
  pass      apps PRM through the router
  pass      apps data-path 401 rewritten to the apps challenge
  skipped   query string survives the apps routing
  pass      status paths refused by the router's map (no gateway handler)
  pass      lockstep: the map and the guard hold their documented division
  pass      lockstep: the apps map/guard division
  pass      W1 openid-configuration serves the canonical document
  pass      W2 path-insertion aliases serve the canonical document
  pass      W4 unserved well-known paths are the router's 404
  pass      W5 closure is method-blind, no CORS
  pass      W6 precedence: AS, toolset, and app documents still served
  pass      W7 Core's templates through the front door equal Core direct
  pass      W8 off-template shapes under Core's prefix are closed
  pass      W10a normalization: into the alias location, the document
  pass      W10b normalization: out of the alias location, the closure
  pass      W10c normalization: into the Core location from outside its raw spelling, the closure
  pass      W10d normalization: out of the namespace into the catch-all, the closure
  pass      W10e normalization: decoded trailing line break, the closure
  pass      W10f normalization: into a gateway location, the gateway's answer (recorded)
  pass      W10g normalization: into a data-path location, the data path's refusal (recorded)
  pass      W12 served locations' end edges are closed
  pass      W13 path-appended forms are the data path's refusal

all 29 probes passed (2 skipped)
```

W0 and W0c stayed passing controls; W1, W2, W4, W5, W8, W10, and W12 passed; the existing
rows (including W6's three) and W7 and W13 stayed green. W3 and W9 are unit rows
(`tests/test_discovery.py`), passing in the suite above. W11 (the live re-test) is
owner-run and not done here.

## Closing note: the hostname and personal-path grep

The new and edited files of this change (the router conf, the three docs, the probe script,
the two gateway modules, the two test modules, and this change's evidence files) were
searched for the user name, the repository's checkout path, a Windows profile path, internal
registry and cluster hostnames, and service-suffix names. No match. Only `localhost` and
reserved example names appear.

## Owner ruling on the router base-image findings

2026-11-16: the 70 HIGH or CRITICAL Trivy findings in `nginx:1.27-alpine` are pre-existing and deferred to a separate change (a bump to a maintained nginx line with its own router-check run). This change ships without the bump.

## Security-gate fix round — gates re-run

After the security gate's SF-1 fix (`$wk_raw_spelling` accepts `%2F` as a separator;
two W10(d) cells added) and the wording corrections (N-1, N-2, N-4; N-3 deferred). No
spec change. The fix's failing-first and passing runs are in `instrument-run.md`.

| Gate | Result |
|---|---|
| `nginx -t` on `nginx:1.27-alpine` | syntax ok, test successful |
| `ruff check` | green |
| `ruff format --check --config 'format.line-ending = "cr-lf"' .` | 281 files already formatted |
| `pytest -q` | 770 passed, 1 skipped |
| `bandit -r gateway -c pyproject.toml` | no issues (0 low, 0 medium, 0 high) |
| `pip-audit` | no known vulnerabilities (the project itself is skipped by name) |
| `python scripts/check_publication_leaks.py` | exit 0: 3 findings, all waived, 0 unwaived |
| compose-boot (`down`, then `up -d --build`, beside the throwaway Core stand-in) | gateway healthy, router healthy, `GET /healthz` through the router `200` |
| `probe_routing.py --group wellknown` | all 19 probes passed (run on the clean boot as well) |
| `probe_routing.py --no-token` | all 29 probes passed (2 skipped) |

The stack, the stand-in container, and the throwaway network were removed afterwards.
`mypy` and Trivy were not re-run: the diff touches no Python under `gateway/` and no image
layer; the earlier records stand.

## General-review fix round - gates re-run

After folding in the general review's findings (`general-review.md`; dispositions in
`design.md`). No spec change, and no change to `router/nginx.conf` or to `gateway/`. The
edits are to the probe script, one new unit row, the docs, and this change's records. The
fix round's mutation runs are in `instrument-run.md`.

| Gate | Result |
|---|---|
| `ruff check` | green |
| `ruff format --check --config 'format.line-ending = "cr-lf"' .` | 282 files already formatted |
| `pytest -q` | 771 passed, 1 skipped (the new row: an alias makes no Core call and writes no audit record) |
| `bandit -r gateway -c pyproject.toml` | no issues (0 low, 0 medium, 0 high) |
| `python scripts/check_publication_leaks.py` | exit 0: 3 findings, all waived, 0 unwaived |
| compose-boot (`down`, then `up -d --build`, beside the throwaway Core stand-in) | gateway healthy, router healthy, `GET /healthz` through the router `200`. Core is the stand-in, as before. |
| `probe_routing.py --group wellknown` | all 19 probes passed |
| `probe_routing.py --no-token` | all 29 probes passed (2 skipped) |

`mypy` reports the same 3 pre-existing errors in files this change did not touch. `pip-audit`
and Trivy were not re-run: no dependency or image layer changed.

**The unrelated `probe_end_to_end.py` change.** The diff includes a wrap in
`scripts/probe_end_to_end.py` (around line 605). It is a formatter-only change that makes
`ruff format --check` pass. It changes no behavior and belongs to no task of this change.

**Still open, owner-run.** Task 6.5 (W11, the live re-test) and task 6.5b (the full
`probe_routing.py`, no flags, against the real composed instance) are preconditions to
archive. The stand-in runs in this file stand in for neither.

The stack, the stand-in container, and the throwaway network were removed afterwards.
