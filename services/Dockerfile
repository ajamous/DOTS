# syntax=docker/dockerfile:1
# One image for every DOTS Python service; the command selects the service.
#
# Optional build secret "extra_ca": a CA bundle for networks that intercept
# TLS (corporate proxies). Not needed on normal networks or in CI.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export PIP_CERT=/run/secrets/extra_ca; fi; \
    pip install --no-cache-dir uv==0.8.17
COPY pyproject.toml uv.lock ./
COPY services/common/pyproject.toml services/common/pyproject.toml
COPY services/receipts/pyproject.toml services/receipts/pyproject.toml
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    mkdir -p services/common/src/dots_common services/receipts/src/dots_receipts \
 && uv sync --frozen --no-dev --all-packages --no-install-workspace
COPY services/common services/common
COPY services/receipts services/receipts
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export SSL_CERT_FILE=/run/secrets/extra_ca; fi; \
    uv sync --frozen --no-dev --all-packages --no-editable \
    --reinstall-package dots-common --reinstall-package dots-receipts
ENV PATH="/app/.venv/bin:$PATH"
RUN useradd --system --uid 10001 dots
USER dots
