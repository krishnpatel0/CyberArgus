# Container topology

This directory is the only container definition boundary:

- `Dockerfile` builds the single Argus application image.
- `docker-compose.yml` runs that image under API, worker, scheduler, breach,
  intelligence-proxy, recon, and ingestion roles.
- Official PostgreSQL, Redis, ClickHouse, Elasticsearch, Prometheus, Ollama, and
  Tor images retain independent lifecycle and persistence boundaries.

Do not add per-module Dockerfiles. A new long-running role should reuse the shared
image unless it has an independently justified security or dependency boundary.
Validate changes with:

```powershell
docker compose --project-directory . -f docker/docker-compose.yml config --quiet
```
