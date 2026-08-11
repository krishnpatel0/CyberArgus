# syntax=docker/dockerfile:1.7
# Single immutable application image reused by every Argus runtime role.

FROM node:22-alpine AS modules-ui-build
WORKDIR /src/modules-ui
COPY modules-ui/package.json modules-ui/package-lock.json ./
RUN npm ci
COPY modules-ui/ ./
ARG VITE_API_BASE_URL=/api
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}
RUN npm run build

FROM golang:1.26-bookworm AS recon-tools
ARG SUBFINDER_VERSION=v2.14.0
ARG DNSX_VERSION=v1.3.0
ARG HTTPX_VERSION=v1.10.0
ENV CGO_ENABLED=0 GOBIN=/out
RUN mkdir -p /out \
    && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
    && go install github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION} \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}

FROM python:3.12-slim-bookworm AS python-wheels
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY backend/requirements.txt ./requirements.txt
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libpq-dev \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --upgrade pip setuptools==84.0.0 wheel \
    && python -m pip wheel --no-build-isolation --wheel-dir /wheels -r requirements.txt

FROM python:3.12-slim-bookworm AS runtime
ARG VCS_URL=""
ARG VCS_REVISION="unknown"
ARG VERSION="dev"
LABEL org.opencontainers.image.title="Argus Unified" \
      org.opencontainers.image.description="Unified defensive threat-intelligence platform" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="${VCS_URL}" \
      org.opencontainers.image.revision="${VCS_REVISION}" \
      org.opencontainers.image.version="${VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend:/app/intel-proxy \
    ARGUS_MODULES_UI_DIR=/app/backend/modules-ui-dist \
    ARGUS_BREACH_DATA_DIR=/data/breach \
    ARGUS_IMAGE_INTEL_DATA_DIR=/data/image-intel \
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates chromium curl dnsutils jq libimage-exiftool-perl libpq5 nmap postgresql-client whois \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 argus \
    && useradd --system --uid 10001 --gid argus --create-home --home-dir /home/argus argus

COPY --from=python-wheels /wheels /wheels
COPY backend/requirements.txt /tmp/requirements.txt
RUN python -m pip install --no-index --find-links=/wheels -r /tmp/requirements.txt \
    && python -c "import telethon; print('Telethon', telethon.__version__)" \
    && rm -rf /wheels /tmp/requirements.txt

WORKDIR /app
COPY --chown=argus:argus backend/ /app/backend/
COPY --chown=argus:argus intel-proxy/ /app/intel-proxy/
COPY --chown=argus:argus recon-engine/ /app/recon-engine/
COPY --chown=argus:argus initdb/ /app/initdb/
COPY --chown=argus:argus config/ /app/config/
COPY --from=modules-ui-build --chown=argus:argus /src/modules-ui/dist/ /app/backend/modules-ui-dist/
COPY --from=recon-tools /out/subfinder /out/dnsx /out/httpx /usr/local/bin/

RUN mkdir -p /app/reports /app/sessions /data/breach /data/image-intel/uploads \
    && chown -R argus:argus /app/reports /app/sessions /data/breach /data/image-intel

USER argus
WORKDIR /app/backend
EXPOSE 8000 9000 9001
CMD ["python", "-m", "arguswatch.scripts.start_api"]
