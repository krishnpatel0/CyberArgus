from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

import clickhouse_connect

from ..cache import cache
from ..config import settings
from ..field_catalog import field_catalog
from ..models import ConnectionsSearchRequest, DirectSearchRequest, MatchMode, SearchFilter
from ..search_utils import hash_email, json_dumps_sorted, normalize_email

LOGGER = logging.getLogger(__name__)


def _cache_key(request: DirectSearchRequest) -> str:
    payload = {
        "filters": [item.model_dump() if hasattr(item, "model_dump") else item.dict() for item in request.filters],
        "limit": request.limit,
        "offset": request.offset,
        "include_count": request.include_count,
    }
    digest = hashlib.sha256(json_dumps_sorted(payload).encode("utf-8")).hexdigest()
    return f"unified:direct:{digest}"


def _get_client():
    client_kwargs: dict[str, object] = {
        "host": settings.clickhouse_host,
        "port": settings.clickhouse_port,
        "autogenerate_session_id": False,
        "connect_timeout": 2,
        "send_receive_timeout": 30,
    }
    if settings.clickhouse_username:
        client_kwargs["username"] = settings.clickhouse_username
    if settings.clickhouse_password is not None:
        client_kwargs["password"] = settings.clickhouse_password
    return clickhouse_connect.get_client(**client_kwargs)


def _serialize_row(row: tuple[Any, ...]) -> dict[str, Any]:
    source_file, email, email_hash, row_data = row
    try:
        parsed = json.loads(row_data) if isinstance(row_data, str) else row_data
    except json.JSONDecodeError:
        parsed = row_data

    return {
        "source_file": source_file,
        "email": email,
        "data": parsed,
    }


def _string_condition(expression: str, param_key: str, value: str, match_mode: MatchMode, params: dict[str, Any]) -> str:
    if match_mode == MatchMode.EXACT:
        params[param_key] = value
        return f"lowerUTF8({expression}) = lowerUTF8(%({param_key})s)"

    if match_mode == MatchMode.PREFIX:
        params[param_key] = f"{value}%"
    else:
        params[param_key] = f"%{value}%"
    return f"{expression} ILIKE %({param_key})s"


def _build_condition(search_filter: SearchFilter, index: int, params: dict[str, Any]) -> str:
    field_name = search_filter.field.strip()
    value = search_filter.value.strip()
    match_mode = search_filter.match_mode
    value_key = f"v{index}"

    if field_name == "email":
        normalized = normalize_email(value)
        if match_mode == MatchMode.EXACT and normalized and settings.email_hash_salt:
            hash_key = f"h{index}"
            params[hash_key] = hash_email(normalized, settings.email_hash_salt)
            return f"email_hash = %({hash_key})s"
        return _string_condition("email", value_key, value, match_mode, params)

    if field_name == "source_file":
        return _string_condition("source_file", value_key, value, match_mode, params)

    header_conditions: list[str] = []
    for header_index, header_name in enumerate(field_catalog.resolve_clickhouse_headers(field_name)):
        header_key = f"header_{index}_{header_index}"
        params[header_key] = header_name
        expression = f"JSONExtractString(data, %({header_key})s)"
        header_conditions.append(_string_condition(expression, f"{value_key}_{header_index}", value, match_mode, params))

    return "(" + " OR ".join(header_conditions) + ")"


def _run_query(query: str, params: dict[str, Any]):
    client = _get_client()
    try:
        return client.query(query, parameters=params)
    finally:
        client.close()


def search(request: DirectSearchRequest) -> dict[str, Any]:
    start_time = time.perf_counter()
    filters = [
        SearchFilter(field=item.field.strip(), value=item.value.strip(), match_mode=item.match_mode)
        for item in request.filters
        if item.field.strip() and item.value.strip()
    ]

    if not settings.enable_direct_search:
        raise RuntimeError("Direct search is disabled")
    if not filters:
        raise ValueError("At least one search filter is required")

    normalized_request = DirectSearchRequest(
        filters=filters,
        limit=min(request.limit, settings.clickhouse_limit_max),
        offset=request.offset,
        include_count=request.include_count,
        use_cache=request.use_cache,
    )
    cache_key = _cache_key(normalized_request)

    if normalized_request.use_cache:
        cached = cache.get_json(cache_key)
        if cached is not None:
            cached["cache_hit"] = True
            return cached

    params: dict[str, Any] = {"limit": normalized_request.limit, "offset": normalized_request.offset}
    where_conditions = [_build_condition(item, idx, params) for idx, item in enumerate(filters)]
    where_clause = "WHERE " + " AND ".join(where_conditions)
    table_path = settings.clickhouse_table_path

    data_query = f"""
        SELECT source_file, email, email_hash, data
        FROM {table_path}
        {where_clause}
        LIMIT %(limit)s OFFSET %(offset)s
    """

    count_query = f"""
        SELECT count() AS total_count
        FROM {table_path}
        {where_clause}
    """

    data_result = _run_query(data_query, params)
    rows = [_serialize_row(row) for row in data_result.result_rows]

    total_count = len(rows)
    if normalized_request.include_count:
        count_result = _run_query(count_query, params)
        total_count = int(count_result.result_rows[0][0]) if count_result.result_rows else 0

    response = {
        "backend": "clickhouse",
        "count": total_count,
        "limit": normalized_request.limit,
        "offset": normalized_request.offset,
        "results": rows,
        "cache_hit": False,
        "took_ms": round((time.perf_counter() - start_time) * 1000, 2),
    }

    if normalized_request.use_cache:
        cache.set_json(cache_key, response, settings.direct_cache_ttl_seconds)

    return response


def health_check() -> dict[str, Any]:
    if not settings.enable_direct_search:
        return {"status": "disabled"}

    try:
        result = _run_query("SELECT 1", {})
        value = result.result_rows[0][0] if result.result_rows else None
        return {"status": "ok" if value == 1 else "error"}
    except Exception as exc:
        LOGGER.exception("ClickHouse health check failed")
        return {"status": "error", "detail": str(exc)}


def _cache_key_connections(request: ConnectionsSearchRequest) -> str:
    payload = {
        "filters": [item.model_dump() if hasattr(item, "model_dump") else item.dict() for item in request.filters],
        "depth": request.depth,
        "limit": request.limit_per_level,
    }
    digest = hashlib.sha256(json_dumps_sorted(payload).encode("utf-8")).hexdigest()
    return f"unified:connections:{digest}"


def get_connections(request: ConnectionsSearchRequest) -> dict[str, Any]:
    start_time = time.perf_counter()

    if not request.filters:
        raise ValueError("At least one search filter is required as seed")

    cache_key = _cache_key_connections(request)
    if request.use_cache:
        cached = cache.get_json(cache_key)
        if cached:
            cached["cache_hit"] = True
            return cached

    nodes_dict = {}
    edges_set = set()

    def add_node(n_id, label, n_type, val=5, data=None):
        if n_id not in nodes_dict:
            nodes_dict[n_id] = {
                "id": n_id,
                "label": label,
                "type": n_type,
                "val": val,
                "data": data or {}
            }
        else:
            nodes_dict[n_id]["val"] = min(nodes_dict[n_id]["val"] + 1, 20)

    def add_edge(source, target, e_type):
        if source == target:
            return
        edge_key = tuple(sorted([source, target])) + (e_type,)
        edges_set.add(edge_key)

    # 1. Find Initial Seed Records
    params_seeds = {"limit": 30, "offset": 0}
    where_conditions = [_build_condition(item, idx, params_seeds) for idx, item in enumerate(request.filters)]
    where_clause = "WHERE " + " AND ".join(where_conditions)

    query_seeds = f"""
        SELECT source_file, email, email_hash, data
        FROM {settings.clickhouse_table_path}
        {where_clause}
        LIMIT %(limit)s
    """

    result_seeds = _run_query(query_seeds, params_seeds)
    seed_records = [_serialize_row(row) for row in result_seeds.result_rows]

    if not seed_records:
        return {"nodes": [], "links": [], "count": 0, "took_ms": 0, "cache_hit": False}

    frontier_l1 = []

    def process_record(record, is_seed=False):
        data = record.get("data") or {}
        identity_parts = [record.get("source_file", ""), record.get("email", ""), str(data.get("name", ""))]
        identity = "|".join(filter(None, identity_parts))
        rec_id = "record:" + hashlib.md5(identity.encode()).hexdigest()

        source_file = record.get("source_file") or "Unknown Database"

        # Add Record Node
        add_node(rec_id, source_file, "record", val=12 if is_seed else 8, data=record)

        extracted_filters = []

        email = record.get("email")
        if email:
            email = str(email).strip().lower()
            ent_id = f"email:{email}"
            add_node(ent_id, email, "email", val=10 if is_seed else 6)
            add_edge(rec_id, ent_id, "has_email")
            extracted_filters.append(SearchFilter(field="email", value=email))

        for key in ('phone', 'mobile'):
            phone = str(data.get(key, "")).strip()
            if phone and len(phone) > 4:
                ent_id = f"phone:{phone}"
                add_node(ent_id, phone, "phone", val=10 if is_seed else 6)
                add_edge(rec_id, ent_id, "has_phone")
                extracted_filters.append(SearchFilter(field=key, value=phone))

        name = str(data.get('name', "")).strip()
        if not name:
            fname = str(data.get('firstname', "")).strip()
            lname = str(data.get('lastname', "")).strip()
            if fname or lname:
                name = f"{fname} {lname}".strip()

        if name and len(name) > 2:
            ent_id = f"name:{name.lower()}"
            add_node(ent_id, name, "name", val=10 if is_seed else 6)
            add_edge(rec_id, ent_id, "has_name")
            extracted_filters.append(SearchFilter(field='name', value=name))

        return rec_id, extracted_filters

    for record in seed_records:
        rec_id, next_filters = process_record(record, is_seed=True)
        if next_filters:
            frontier_l1.append((rec_id, next_filters))

    def expand_frontier(source_rec_id, filters, limit):
        params = {"limit": limit, "offset": 0}
        conditions = []
        for idx, f in enumerate(filters):
            if f.field in ('email', 'phone', 'mobile', 'name', 'lastname', 'firstname'):
                conditions.append(_build_condition(f, idx, params))

        if not conditions:
            return []

        where_clause = "WHERE " + " OR ".join(conditions)
        query = f"""
            SELECT source_file, email, email_hash, data
            FROM {settings.clickhouse_table_path}
            {where_clause}
            LIMIT %(limit)s
        """

        result = _run_query(query, params)
        found_records = [_serialize_row(row) for row in result.result_rows]

        next_level = []
        for record in found_records:
            new_rec_id, next_filters = process_record(record, is_seed=False)
            if new_rec_id != source_rec_id and next_filters:
                next_level.append((new_rec_id, next_filters))
        return next_level

    all_frontier_l2 = []
    for s_rec_id, s_filters in frontier_l1[:15]:
        l2_items = expand_frontier(s_rec_id, s_filters, 15)
        all_frontier_l2.extend(l2_items)

    if request.depth >= 2:
        for s_rec_id, s_filters in all_frontier_l2[:15]:
            expand_frontier(s_rec_id, s_filters, 8)

    edges_list = [{"source": src, "target": tgt, "label": lbl} for src, tgt, lbl in edges_set]

    response = {
        "nodes": list(nodes_dict.values()),
        "links": edges_list,
        "count": len(nodes_dict),
        "took_ms": round((time.perf_counter() - start_time) * 1000, 2),
        "cache_hit": False
    }

    if request.use_cache:
        cache.set_json(cache_key, response, 3600)

    return response
