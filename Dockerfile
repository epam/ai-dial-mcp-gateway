# The gateway image.
#
# The service holds the deployment's signing key at runtime, so the image is built to
# carry as little as possible: no build toolchain, no source control metadata, and a
# non-root user that cannot write anywhere except the one mounted volume.
#
# The base is Alpine rather than Debian slim. Fewer pre-installed OS packages means a
# smaller image and a smaller scanned surface, which is what clears the base's
# OS-package debt; the trade is musl rather than glibc, so the compiled dependencies
# must resolve to musllinux wheels.

FROM python:3.12-alpine AS builder

# The base image pins stale packages, and those are the OS-package findings a scanner
# reports; upgrading them keeps the base current. `libcrypto3`/`libssl3` are the crypto
# libraries; `libuuid` (util-linux), `krb5-libs`, `musl`, `musl-utils` and `zlib` are
# upgraded for the same reason — each has an upstream CVE fix the scanner bar requires,
# the `krb5-libs` ReDoS advisory being the current driver. Each package is named rather
# than upgrading the whole tree, so a base-image change cannot silently pull in an
# unreviewed package bump. `--no-cache` so the apk index never lands in the layer.
RUN apk upgrade --no-cache libcrypto3 libssl3 libuuid krb5-libs musl musl-utils zlib

WORKDIR /build

# Only the project metadata and the package are copied, so a change to a test or a doc
# does not invalidate the dependency layer.
COPY pyproject.toml README.md ./
COPY gateway ./gateway

# `--no-cache-dir` keeps pip's wheel cache out of the layer; the venv is copied forward
# into the runtime image, so nothing here is rebuilt there. The dependencies resolve to
# musllinux wheels, so no compiler is needed; if a wheel is ever missing, the fallback is
# `apk add --no-cache build-base` in this builder stage only, never in the runtime image.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .


FROM python:3.12-alpine AS runtime

# The same package refresh as the builder stage — this is the stage the scanner scans, so
# the base's package set must be current here.
RUN apk upgrade --no-cache libcrypto3 libssl3 libuuid krb5-libs musl musl-utils zlib

# A fixed uid/gid so the bind-mounted store's ownership is predictable on the host: the
# store file must be writable by this user and by nobody else, and an image rebuild must
# not change who owns it.
RUN addgroup -g 10001 gateway \
    && adduser -D -u 10001 -G gateway -H -s /sbin/nologin gateway

COPY --from=builder /opt/venv /opt/venv

# The runtime image does not install anything, so pip has no job here — and an installer
# is not inert cargo: pip vendors its own copies of `msgpack` and `setuptools`, which is
# where the image's only HIGH scanner findings live. Removing pip removes the findings
# rather than triaging them, and shrinks the attack surface of the component that holds
# the deployment's signing key.
#
# Both copies go: the one in this venv, and the one the base image ships in its own
# site-packages. Neither is imported at run time — the app's import path is the venv
# alone — so nothing here changes what the gateway can do.
RUN /opt/venv/bin/python -m pip uninstall --yes pip \
    && find /opt/venv -name "__pycache__" -type d -prune -exec rm -rf {} + \
    && rm -rf /opt/venv/lib/python3.12/site-packages/pip \
              /opt/venv/lib/python3.12/site-packages/pip-*.dist-info \
              /usr/local/lib/python3.12/site-packages/pip \
              /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
              /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12

# Unbuffered output so container logs are complete, and no .pyc writes (the filesystem is
# read-only apart from the data volume).
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER gateway

# The container-internal port. The front router is the only thing that reaches it.
EXPOSE 8091

# The module is run rather than uvicorn being invoked directly, so configuration
# validation happens in the gateway's own process and its errors land in the container
# log rather than in a uvicorn argument-parsing traceback.
ENTRYPOINT ["python", "-m", "gateway"]
