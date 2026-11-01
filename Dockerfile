# One image for the gateway, the mock upstream, and the demo app. Dependencies come from
# uv.lock; the app runs as a non-root user. The gateway build installs no optional groups;
# the demo app is built with --build-arg UV_GROUPS="--group demo".
# Base images are pinned by digest (tag kept for readability); bump both together.
FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159

COPY --from=ghcr.io/astral-sh/uv:0.12.7@sha256:95f2aa1fe59274951cfe9b0cbc7972e879ff1004bc8945d130a32eb0dbd85945 /uv /bin/uv

ARG UV_GROUPS=""
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH" \
    HF_HOME=/models

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY sdk ./sdk
RUN uv sync --frozen --no-default-groups ${UV_GROUPS} --no-install-project

COPY breakwater ./breakwater
COPY scripts ./scripts
COPY demo_app ./demo_app
RUN uv sync --frozen --no-default-groups ${UV_GROUPS} --no-editable

# /models holds the classifier model (a named volume in compose, so it is downloaded once).
# /app/reports is where `breakwater redteam run` writes its reports by default.
RUN useradd --system --uid 10001 --no-create-home gateway \
    && mkdir -p /models /app/reports && chown gateway /models /app/reports
USER gateway

EXPOSE 8000
CMD ["sh", "-c", "breakwater db upgrade && exec uvicorn breakwater.main:app --host 0.0.0.0 --port 8000"]
