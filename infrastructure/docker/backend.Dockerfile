# One image, two roles: `api` (uvicorn) and `worker` (python -m sieve.worker).
FROM python:3.13-slim AS build

COPY --from=ghcr.io/astral-sh/uv:0.12.23 /uv /bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /app

# Dependencies first, so source edits don't invalidate the dependency layer.
COPY backend/pyproject.toml backend/uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY backend/src ./src
COPY backend/alembic.ini ./
# Editable install: the package resolves to /app/src, which docker-compose bind-mounts in
# development so `--reload` picks up edits. In production /app/src is the copied source.
RUN uv sync --frozen --no-dev


FROM python:3.13-slim AS runtime

RUN useradd --system --uid 10001 --no-create-home sieve
WORKDIR /app
COPY --from=build --chown=root:root /app /app
# The public demo: sample app, pinned advisory snapshot and maintainer reviews (read-only data).
COPY --chown=root:root demo /app/demo
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SIEVE_DEMO_APP_DIR=/app/demo/vulnerable-python-app \
    SIEVE_DEMO_SNAPSHOT_DIR=/app/demo/advisory-snapshot \
    SIEVE_DEMO_REVIEWS_FILE=/app/demo/reviews.json

# The only writable path. The root filesystem is read-only in AWS; ECS seeds the task's scratch
# volume from this VOLUME (ownership included). Temp files and the package cache live here.
RUN mkdir -p /scratch/tmp /scratch/cache /scratch/artifacts && chown -R 10001 /scratch
VOLUME ["/scratch"]
# Artifacts default to a relative var/ path, which is not writable under /app (owned by root).
ENV TMPDIR=/scratch/tmp \
    SIEVE_PACKAGE_CACHE_DIR=/scratch/cache \
    SIEVE_ARTIFACT_ROOT=/scratch/artifacts

USER 10001
EXPOSE 8000
CMD ["uvicorn", "sieve.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
