# Gateway image. Dependencies come from uv.lock; the app runs as a non-root user.
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

COPY gateway ./gateway
COPY scripts ./scripts
RUN uv sync --frozen --no-dev --no-editable

RUN useradd --system --uid 10001 --no-create-home gateway
USER gateway

EXPOSE 8000
CMD ["sh", "-c", "gateway db upgrade && exec uvicorn gateway.main:app --host 0.0.0.0 --port 8000"]
