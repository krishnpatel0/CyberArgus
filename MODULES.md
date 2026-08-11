# Module ownership map

Use this page to find the correct change boundary before opening a branch. The
repository intentionally keeps the operational topology centralized while
letting teams work independently inside stable domain directories.

| Domain | Backend | Frontend | Tests | Runtime role | Data boundary |
|---|---|---|---|---|---|
| Core CTI platform | [`backend/arguswatch`](backend/arguswatch/README.md) | `backend/arguswatch/static` | `backend/tests/test_*` | `backend`, `celery-worker`, `celery-beat` | PostgreSQL, Redis, reports volume |
| Breach intelligence | [`backend/modules/breach`](backend/modules/breach/README.md) | [`modules-ui/src/modules/breach`](modules-ui/src/modules/breach/README.md) | infrastructure and API tests | `backend`, `breach-search`, `breach-ingest` | ClickHouse, Elasticsearch, Redis, external corpus mount |
| OSINT investigation | [`backend/modules/osint`](backend/modules/osint/README.md) | [`modules-ui/src/modules/osint`](modules-ui/src/modules/osint/README.md) | API/integration tests | `backend` | process-local job state and external sources |
| Image intelligence | [`backend/modules/image_intel`](backend/modules/image_intel/README.md) | [`modules-ui/src/modules/image-intelligence`](modules-ui/src/modules/image-intelligence/README.md) | `test_image_intel.py` | `backend`, `celery-worker` | image-intel volume and configured providers |
| Telegram intelligence | [`backend/modules/telegram_intel`](backend/modules/telegram_intel/README.md) | main dashboard | `test_telegram_intel.py` | `backend`, `celery-worker` | PostgreSQL and Telegram session volume |
| Provider gateway | [`intel-proxy`](intel-proxy/README.md) | none | integration tests | `intel-proxy` | configured external providers |
| Reconnaissance | [`recon-engine`](recon-engine/README.md) | core customer UI | integration tests | `recon-engine` | customer scope in PostgreSQL |

## Shared change boundaries

- HTTP/authentication utilities for the React workspace: `modules-ui/src/shared/api`.
- Shared React state: `modules-ui/src/shared/context`.
- Reusable visualizations: `modules-ui/src/shared/visualization`.
- Core models, schemas, scoring, findings, and persistence: `backend/arguswatch`.
- Database initialization: `initdb` and `clickhouse-init`.
- Deployment topology: `docker`; developer lifecycle: `setup`.

When a change crosses modules, name each affected module in the pull request and
assign reviewers for every boundary. Do not copy shared code to avoid a cross-team
review; extract a narrow, tested shared interface instead.
