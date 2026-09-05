# One image for both arms of the comparison, parameterized by ARMASEC_LIB.
#
# The two builds differ in exactly one RUN branch. Same base image, same Python, same
# uvicorn, same application module, same command line. Anything else would put a variable
# into the measurement that has nothing to do with the libraries.
#
# The build context is the repository root, not this directory, because the lite arm
# installs armasec-lite from the local source tree rather than from an index. Upstream
# armasec is installed from PyPI and resolves its own dependencies inside its own image:
# armasec 3.0.3 declares pytest<9 and respx as RUNTIME dependencies, so it cannot share a
# dependency resolution with this repository and is deliberately absent from its lockfile.
#
#   docker build -f legacy_comparison_compose/Dockerfile.app --build-arg ARMASEC_LIB=lite .

ARG PYTHON_VERSION=3.12
FROM python:${PYTHON_VERSION}-slim

ARG ARMASEC_LIB=lite
ARG ARMASEC_LEGACY_VERSION=3.0.3
ARG UVICORN_VERSION=0.52.4

ENV ARMASEC_LIB=${ARMASEC_LIB} \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /srv

# Copied into both images so the two builds stay one instruction apart. Installed only in
# the lite arm; the legacy image carries the sources without importing them.
COPY pyproject.toml README.md /srv/lite-src/
COPY armasec_lite /srv/lite-src/armasec_lite

RUN set -eux; \
    case "$ARMASEC_LIB" in \
      lite)   pip install /srv/lite-src ;; \
      legacy) pip install "armasec==${ARMASEC_LEGACY_VERSION}" ;; \
      *)      echo "ARMASEC_LIB must be 'lite' or 'legacy', got '${ARMASEC_LIB}'" >&2; exit 1 ;; \
    esac; \
    pip install "uvicorn==${UVICORN_VERSION}"

COPY legacy_comparison_compose/app/main.py /srv/app/main.py
# Run with `docker exec`, never imported by the server. Import cost has to be measured in a
# bare interpreter, and a bare interpreter is only available from outside the running app.
COPY legacy_comparison_compose/app/probe.py /srv/app/probe.py

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "warning"]
