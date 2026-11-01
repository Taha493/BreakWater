# One image for the gateway, the mock upstream, and the demo app. Dependencies come from
# uv.lock; the app runs as a non-root user. The gateway build installs no optional groups;
# the demo app is built with --build-arg UV_GROUPS="--group demo".
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /bin/uv

ARG UV_GROUPS=""
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY sdk ./sdk
RUN uv sync --frozen --no-default-groups ${UV_GROUPS} --no-install-project

COPY gateway ./gateway
COPY scripts ./scripts
COPY demo_app ./demo_app
RUN uv sync --frozen --no-default-groups ${UV_GROUPS} --no-editable

RUN useradd --system --uid 10001 --no-create-home gateway
USER gateway

EXPOSE 8000
CMD ["sh", "-c", "gateway db upgrade && exec uvicorn gateway.main:app --host 0.0.0.0 --port 8000"]
