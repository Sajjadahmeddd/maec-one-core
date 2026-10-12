# MAEC One Core — one image: the API and the built sign-in/admin frontend.
#
#   docker build -t maec-core:latest .
#
# Runs with MAEC_ENV=production unless told otherwise, so it refuses to start
# without SESSION_SECRET and OIDC_PRIVATE_KEY. Configuration comes from the
# environment (deploy/env.production.example); no .env is copied in
# (.dockerignore), and none is read.

# ---------------------------------------------------------------- frontend
FROM node:20-alpine AS frontend
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ----------------------------------------------------------------- service
FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MAEC_ENV=production

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt

COPY pytest.ini ./
COPY backend/ backend/
COPY --from=frontend /build/frontend/dist frontend/dist

# Not root: nothing here needs it.
RUN useradd --system --uid 10001 --home-dir /app maec \
    && chown -R maec /app
USER maec

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=4).status == 200 else 1)"

# Migrations first, and fatal: serving against a half-migrated identity schema
# is worse than not serving. The seed is idempotent and best-effort — it
# creates the first Global Admin from BOOTSTRAP_ADMIN_* and leaves existing
# passwords alone. Then uvicorn, with --no-proxy-headers: Core applies its own
# trusted-proxy list (TRUSTED_PROXIES, OPEN-DECISIONS #6), and uvicorn's
# default would apply a second one that could disagree with it.
CMD ["sh", "-c", "alembic -c backend/identity/alembic.ini upgrade head && (python -m backend.identity.seed || true) && exec uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers ${WEB_CONCURRENCY:-2} --no-proxy-headers --timeout-keep-alive 120"]
