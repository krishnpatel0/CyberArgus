# Breach intelligence module

Searches operator-supplied, authorized breach datasets and constructs bounded
record-to-entity connection graphs. The module contains two layers:

- `breach_api.py` is the authenticated adapter mounted by the unified backend.
- `search_engine/` is the internal FastAPI service used through
  `BREACH_API_BASE_URL`; it queries ClickHouse and Elasticsearch and caches safe
  responses in Redis.

## Code map

| Path | Responsibility |
|---|---|
| `breach_api.py` | Unified route adapter, validation, upstream authentication |
| `breach_engine.py` | Local compatibility/search orchestration |
| `database.py` | Database access helpers |
| `search_engine/main.py` | Internal service endpoints and lifecycle |
| `search_engine/services/` | ClickHouse and Elasticsearch query services |
| `search_engine/graph_engine.py` | Bounded breadth-first connection expansion |
| `search_engine/cache.py` | Redis response cache |
| `search_engine/field_catalog.py` | Canonical searchable field definitions |
| `ingest.py` | Explicit CSV-to-ClickHouse ingestion tool |

## Interfaces and state

- Unified routes: `/api/breach/health`, `/api/breach/fields`,
  `/api/breach/search`, `/api/breach/graph/connections`.
- Internal routes: `/health`, `/fields`, `/search/direct`,
  `/search/correlation`, `/search/combined`, `/search/connections`.
- Stores: ClickHouse is the primary corpus store, Elasticsearch provides pivots,
  and Redis stores bounded cached responses.
- Local source data: `data/breach/` or `BREACH_DATA_PATH`; this directory is
  intentionally ignored by Git.

## Development and validation

Do not run this module with a local `.env` or standalone launcher. Start the
unified stack and use `setup/update.ps1` after source changes. The setup process
creates `BREACH_SEARCH_API_KEY` in the root `.env`.

Relevant tests include `backend/tests/test_infrastructure.py` and API smoke tests.
Use synthetic fixtures only; never commit real breach records.
