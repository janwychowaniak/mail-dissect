# Two stages: dependencies and the project are built with uv, the runtime carries only a
# virtualenv and the interpreter. Deliberately buildable with the CLASSIC builder as well as
# BuildKit - no RUN --mount, no heredocs, no COPY --link - and CI enforces that with
# DOCKER_BUILDKIT=0, so a machine without BuildKit is never a surprise.
FROM ghcr.io/astral-sh/uv:python3.13-bookworm-slim AS builder
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.13-slim-bookworm AS runtime
LABEL org.opencontainers.image.source="https://github.com/janwychowaniak/mail-dissect"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.description="Deterministic dissection of raw email messages over HTTP"

RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --from=builder --chown=app:app /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
USER app
EXPOSE 8000

# python:slim ships neither curl nor wget, so the check is stdlib. /v1/health answers 200
# whenever the service is alive, including when the optional tools do not - a dead Tika must
# never make an orchestrator restart a working container (SPEC §14.3).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/v1/health', timeout=4)"]

# The app writes its own JSON request line; uvicorn's access log would duplicate it.
CMD ["uvicorn", "--factory", "mail_dissect.app:create_app", \
     "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
