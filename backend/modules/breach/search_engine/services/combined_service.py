from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..models import CombinedSearchRequest, CorrelationSearchRequest, DirectSearchRequest, MatchMode, SearchFilter
from ..search_utils import PIIType, detect_type
from . import clickhouse_service, correlation_service


def _default_direct_field(query: str) -> str:
    pii_type = detect_type(query)
    if pii_type == PIIType.EMAIL:
        return "email"
    if pii_type == PIIType.PHONE:
        return "phone"
    if pii_type == PIIType.NAME:
        return "name"
    if pii_type == PIIType.IP:
        return "ip"
    if pii_type == PIIType.AADHAAR:
        return "aadhaar"
    return "username"


def _build_direct_request(request: CombinedSearchRequest) -> DirectSearchRequest | None:
    if not request.run_direct:
        return None

    filters = list(request.direct_filters)
    if not filters and request.query:
        filters = [
            SearchFilter(
                field=request.direct_field or _default_direct_field(request.query),
                value=request.query,
                match_mode=MatchMode.EXACT,
            )
        ]

    if not filters:
        return None

    return DirectSearchRequest(
        filters=filters,
        limit=request.direct_limit,
        offset=request.direct_offset,
        include_count=request.direct_include_count,
        use_cache=request.use_cache,
    )


def _build_correlation_request(request: CombinedSearchRequest) -> CorrelationSearchRequest | None:
    if not request.run_correlation:
        return None

    seed = request.correlation_seed or request.query
    if not seed:
        return None

    return CorrelationSearchRequest(
        seed=seed,
        seed_type=request.correlation_seed_type,
        max_depth=request.max_depth,
        max_results_per_query=request.max_results_per_query,
        use_cache=request.use_cache,
    )


def search(request: CombinedSearchRequest) -> dict[str, Any]:
    direct_request = _build_direct_request(request)
    correlation_request = _build_correlation_request(request)

    direct_result = None
    correlation_result = None

    with ThreadPoolExecutor(max_workers=2) as executor:
        direct_future = executor.submit(clickhouse_service.search, direct_request) if direct_request else None
        correlation_future = executor.submit(correlation_service.search, correlation_request) if correlation_request else None

        if direct_future:
            direct_result = direct_future.result()
        if correlation_future:
            correlation_result = correlation_future.result()

    direct_sources = {item.get("source_file") for item in (direct_result or {}).get("results", []) if item.get("source_file")}
    correlation_sources = set((correlation_result or {}).get("summary", {}).get("sources", []))

    return {
        "query": {
            "query": request.query,
            "direct_field": request.direct_field,
            "correlation_seed": request.correlation_seed or request.query,
            "run_direct": bool(direct_request),
            "run_correlation": bool(correlation_request),
        },
        "direct": direct_result,
        "correlation": correlation_result,
        "summary": {
            "direct_results": (direct_result or {}).get("count", 0),
            "correlated_entities": ((correlation_result or {}).get("scan_metadata") or {}).get("total_entities_found", 0),
            "direct_sources": sorted(direct_sources),
            "correlation_sources": sorted(correlation_sources),
            "overlapping_sources": sorted(direct_sources & correlation_sources),
            "all_sources": sorted(direct_sources | correlation_sources),
        },
    }
