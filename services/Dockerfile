# syntax=docker/dockerfile:1
# One image for every DOTS Python service; the command selects the service.
#
# Optional build secret "extra_ca": a CA bundle for networks that intercept
# TLS (corporate proxies). Not needed on normal networks or in CI.
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --no-cache-dir uv==0.8.17
COPY pyproject.toml uv.lock ./
COPY services/common/pyproject.toml services/common/pyproject.toml
COPY services/receipts/pyproject.toml services/receipts/pyproject.toml
COPY services/settlement/pyproject.toml services/settlement/pyproject.toml
COPY lab/pyproject.toml lab/pyproject.toml
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    mkdir -p services/common/src/dots_common services/receipts/src/dots_receipts \
      services/settlement/src/dots_settlement lab/src/dots_lab \
 && uv sync --frozen --no-dev --all-packages --no-install-workspace
COPY services/common services/common
COPY services/receipts services/receipts
COPY services/settlement services/settlement
COPY lab/pyproject.toml lab/topology.json lab/
COPY lab/src lab/src
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    uv sync --frozen --no-dev --all-packages --no-editable \
    --reinstall-package dots-common --reinstall-package dots-receipts \
    --reinstall-package dots-settlement --reinstall-package dots-lab
ENV PATH="/app/.venv/bin:$PATH"
RUN useradd --system --uid 10001 dots && mkdir -p /data && chown dots:dots /data
USER dots

# Test runner for the lab: the same code plus dev dependencies and the tests.
FROM runtime AS tester
USER root
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    uv sync --frozen --all-packages --no-editable \
    --reinstall-package dots-common --reinstall-package dots-receipts \
    --reinstall-package dots-settlement --reinstall-package dots-lab
COPY lab/tests lab/tests
COPY lab/scenarios.json lab/scenarios.json
