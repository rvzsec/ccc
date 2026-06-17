# C³ container image.
#
# Three-stage build:
#   stage 1 (deps):    pip install pinned wheels under --require-hashes
#   stage 2 (runtime): production image - ccc package only, NO tests
#   stage 3 (test):    derives from runtime, adds tests/ - used by `make test`
#
# docker-compose targets:
#   service `ccc`   -> runtime stage (default; tests/ NOT present)
#   service `test`  -> test stage (tests/ added on top of runtime)
#
# Nothing runs on the host. All pip activity is confined to the build container.

# ---------- stage 1: deps ----------
FROM python:3.13-slim-bookworm AS deps

# Pin apt mirror behavior + no recommends to keep surface tiny.
ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

# Build deps for any sdist fallbacks (pydantic-core ships pre-built wheels but
# we keep gcc to make hash-pinning robust against wheel cache misses).
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy ONLY the lockfile first so dep layer caches independently of source.
COPY requirements.lock /build/requirements.lock

# --require-hashes refuses any wheel whose hash doesn't match the lockfile.
# If PyPI is compromised, pip aborts here.
RUN pip install --require-hashes --no-deps -r /build/requirements.lock \
              --target=/build/site-packages

# ---------- stage 2: runtime ----------
FROM python:3.13-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app:/opt/site-packages \
    CCC_STATE_DIR=/state \
    CCC_CONFIG=/config/config.yaml

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tini \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 1000 ccc \
 && useradd --system --uid 1000 --gid ccc --home /app --shell /sbin/nologin ccc \
 && mkdir -p /state /config /app \
 && chown -R ccc:ccc /state /config /app

# Site-packages from stage 1 (hash-verified).
COPY --from=deps /build/site-packages /opt/site-packages

WORKDIR /app

# Source code last (changes most often, cache-friendliest position).
COPY --chown=ccc:ccc ccc/ /app/ccc/
COPY --chown=ccc:ccc pyproject.toml /app/pyproject.toml

USER ccc

# State + config mounted at runtime (NEVER baked into image).
VOLUME ["/state", "/config"]

ENTRYPOINT ["/usr/bin/tini", "--", "python", "-m", "ccc.cli"]
CMD ["--help"]

# ---------- stage 3: test ----------
# Adds tests/ on top of the runtime stage. Production never includes this.
FROM runtime AS test

USER root
COPY --chown=ccc:ccc tests/ /app/tests/
USER ccc

ENTRYPOINT ["/usr/bin/tini", "--", "python", "-m", "unittest", "discover", "-v", "-s", "/app/tests"]
CMD []
