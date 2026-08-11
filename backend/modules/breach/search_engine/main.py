from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .cache import cache
from .config import settings
from .field_catalog import field_catalog
from .models import CombinedSearchRequest, ConnectionsSearchRequest, CorrelationSearchRequest, DirectSearchRequest, MatchMode, SearchFilter
from .services import clickhouse_service, combined_service, correlation_service

LOGGER = logging.getLogger(__name__)

# Public paths that never require an API key
_PUBLIC_PATHS = {"/", "/health", "/docs", "/redoc", "/openapi.json"}

app = FastAPI(
    title="Argus Breach Search API",
    version="1.0.0",
    description=(
        "Search API for breach/leaked data. "
        "Pass your API key in the **X-API-Key** request header."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    """Enforce API key auth on all non-public endpoints when keys are configured."""
    if request.url.path in _PUBLIC_PATHS or not settings.api_keys:
        return await call_next(request)

    key = request.headers.get("X-API-Key", "")
    if key not in settings.api_keys:
        return JSONResponse(
            status_code=401,
            content={"error": "Invalid or missing API key", "hint": "Pass your key in the X-API-Key header"},
        )
    return await call_next(request)


@app.on_event("startup")
async def _startup_warning():
    if not settings.api_keys:
        LOGGER.warning(
            "\n"
            "  *** SECURITY WARNING ***\n"
            "  No API_KEYS configured in .env — the search API is OPEN to anyone on the network.\n"
            "  Run  python generate_api_key.py  to create a key and lock it down.\n"
        )


def _filters_from_legacy_params(
    field: str | None,
    value: str | None,
    q: str | None,
    match_mode: MatchMode,
) -> list[SearchFilter]:
    filters: list[SearchFilter] = []

    if field and value:
        filters.append(SearchFilter(field=field, value=value, match_mode=match_mode))

    if not q:
        return filters

    try:
        payload = json.loads(q)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid q payload: {exc}") from exc

    if isinstance(payload, dict):
        for key, item_value in payload.items():
            if key and item_value not in (None, ""):
                filters.append(SearchFilter(field=str(key), value=str(item_value), match_mode=match_mode))
        return filters

    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict) and item.get("field") and item.get("value") not in (None, ""):
                filters.append(
                    SearchFilter(
                        field=str(item["field"]),
                        value=str(item["value"]),
                        match_mode=MatchMode(item.get("match_mode", match_mode.value)),
                    )
                )
        return filters

    raise HTTPException(status_code=400, detail="q payload must be an object or a list of field/value objects")


@app.get("/")
def index() -> dict[str, Any]:
    return {
        "service": "Argus Breach Search API",
        "version": "1.0.0",
        "auth": "X-API-Key header required" if settings.api_keys else "open (no key configured)",
        "docs": "/docs",
        "endpoints": [
            "GET  /health",
            "GET  /fields",
            "GET  /search?field=&value=&limit=",
            "GET  /search/{email}",
            "POST /search/direct",
            "POST /search/correlation",
            "POST /search/combined",
            "POST /search/connections",
        ],
    }


@app.get("/health")
def health(full: bool = Query(default=False)) -> dict[str, Any]:
    if not full:
        return {"status": "ok", "service": "unified_search_backend"}

    return {
        "status": "ok",
        "service": "unified_search_backend",
        "clickhouse": clickhouse_service.health_check(),
        "elasticsearch": correlation_service.health_check(),
        "redis": cache.health_check(),
        "field_catalog": {
            "status": "ok",
            "schema_report_path": field_catalog.describe()["schema_report_path"],
        },
    }


@app.get("/fields")
def get_fields() -> list[str]:
    return field_catalog.get_direct_fields()


@app.get("/fields/catalog")
def get_fields_catalog() -> dict[str, Any]:
    return field_catalog.describe()


@app.get("/search")
def legacy_direct_search(
    field: str | None = Query(default=None, description="Single field to search"),
    value: str | None = Query(default=None, description="Single value to match"),
    q: str | None = Query(default=None, description="JSON object or list of field/value filters"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    include_count: bool = Query(default=True),
    match_mode: MatchMode = Query(default=MatchMode.EXACT),
):
    try:
        filters = _filters_from_legacy_params(field, value, q, match_mode)
        request = DirectSearchRequest(
            filters=filters,
            limit=limit,
            offset=offset,
            include_count=include_count,
        )
        return clickhouse_service.search(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/search/{email}")
def legacy_email_search(email: str):
    return clickhouse_service.search(
        DirectSearchRequest(filters=[SearchFilter(field="email", value=email, match_mode=MatchMode.EXACT)])
    )


@app.post("/search/direct")
def search_direct(request: DirectSearchRequest):
    try:
        return clickhouse_service.search(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/search/correlation")
def search_correlation(request: CorrelationSearchRequest):
    try:
        return correlation_service.search(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/search/combined")
def search_combined(request: CombinedSearchRequest):
    try:
        return combined_service.search(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


from pydantic import BaseModel, Field
from .graph_engine import build_connection_graph

class MaltegoGraphRequest(BaseModel):
    seed: str = Field(..., min_length=1)
    seed_type: str = Field(..., pattern="^(phone|email|name)$")
    max_records_per_entity: int = Field(default=100, ge=1, le=200)

@app.post("/search/connections")
async def search_connections(request: MaltegoGraphRequest):
    import hashlib

    # 1. Check Cache
    cache_key = f"graph:v2:{hashlib.sha256(f'{request.seed}:{request.seed_type}:{request.max_records_per_entity}'.encode()).hexdigest()}"
    cached = cache.get_json(cache_key)
    if cached:
        return cached

    # 2. Run BFS
    ch_client = clickhouse_service._get_client()
    try:
        graph = await build_connection_graph(
            seed_value=request.seed,
            seed_type=request.seed_type,
            ch_client=ch_client,
            max_records_per_entity=request.max_records_per_entity
        )

        resp_dict = graph.model_dump()
        if resp_dict.get("nodes"):
            cache.set_json(cache_key, resp_dict, 300)

        return resp_dict
    except Exception as exc:
        if "timeout" in str(exc).lower():
            raise HTTPException(status_code=504, detail="ClickHouse query timed out. Try a more specific seed.")
        raise HTTPException(status_code=500, detail=str(exc))
    finally:
        ch_client.close()
