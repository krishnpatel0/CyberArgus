import json
import hashlib
import re
import asyncio
import time
from datetime import datetime
from collections import deque
from typing import Any, Optional, List, Dict, Set, Tuple
from pydantic import BaseModel, Field

from .field_catalog import field_catalog

# =====================================================================
# DATA MODELS
# =====================================================================

class GraphNode(BaseModel):
    id: str
    type: str                  # "RECORD" | "EMAIL" | "PHONE" | "NAME" | "ADDRESS"
    label: str
    value: str
    degree: int
    record_data: Optional[Dict] = None
    source_file: Optional[str] = None
    is_seed: bool = False
    warning: Optional[str] = None

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str          # "HAS_EMAIL" | "HAS_PHONE" | "HAS_NAME" | "HAS_ADDRESS"
    shared_value: str

class Graph(BaseModel):
    seed_input: str
    seed_type: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    total_records_found: int
    depth_reached: int
    query_time_ms: float
    created_at: str
    capped: bool = False
    cap_reason: Optional[str] = None

# =====================================================================
# UTILITIES & NORMALIZATION
# =====================================================================

def _get_row_value(row: dict, *keys: str) -> str:
    data = row.get("data") if isinstance(row.get("data"), dict) else {}

    for key in keys:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)

        if isinstance(data, dict):
            nested_value = data.get(key)
            if nested_value not in (None, ""):
                return str(nested_value)

    return ""


def _dedupe_preserve(values: List[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _candidate_headers(*logical_fields: str) -> List[str]:
    headers: List[str] = []
    for field_name in logical_fields:
        headers.extend(field_catalog.resolve_clickhouse_headers(field_name))
        headers.append(field_name)
    return _dedupe_preserve(headers)


def _normalize_clickhouse_row(row_dict: dict) -> dict:
    raw_data = row_dict.get("data")

    if isinstance(raw_data, str):
        try:
            parsed_data = json.loads(raw_data)
        except json.JSONDecodeError:
            parsed_data = {}
    elif isinstance(raw_data, dict):
        parsed_data = raw_data
    else:
        parsed_data = {}

    normalized = dict(row_dict)
    normalized["data"] = parsed_data

    if isinstance(parsed_data, dict):
        for key, value in parsed_data.items():
            normalized.setdefault(key, value)

    return normalized

def build_row_id(row: dict) -> str:
    """Generate a stable SHA256 id for a ClickHouse row using source_file + email + phone."""
    source = str(_get_row_value(row, "source_file")).strip()
    email = str(_get_row_value(row, "email")).strip().lower()
    phone = normalize_phone(_get_row_value(row, "phone", "mobile"))

    raw_str = f"{source}|{email}|{phone}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()

def build_node_id(ntype: str, value: str) -> str:
    """SHA256(type + ":" + value)"""
    raw = f"{ntype.upper()}:{value.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

def normalize_phone(phone: str) -> str:
    if not phone: return ""
    cleaned = re.sub(r"[^\d]", "", str(phone))
    if cleaned.startswith("91") and len(cleaned) == 12: cleaned = cleaned[2:]
    if cleaned.startswith("0") and len(cleaned) == 11: cleaned = cleaned[1:]
    return cleaned if 7 <= len(cleaned) <= 15 else ""

def normalize_name(name: str) -> str:
    if not name: return ""
    return re.sub(r"\s+", " ", str(name)).strip().title()

def extract_pii_entities(row: dict) -> List[Tuple[str, str]]:
    entities = []
    # Email
    email = str(_get_row_value(row, "email")).strip().lower()
    if email and "@" in email:
        entities.append(("EMAIL", email))
    # Phone
    for key in ("phone", "mobile", "contact", "telephone", "cell"):
        p = normalize_phone(_get_row_value(row, key))
        if p: entities.append(("PHONE", p))
    # Name
    name = normalize_name(_get_row_value(row, "name", "full_name", "fullname", "contact_person"))
    if not name:
        fname = str(_get_row_value(row, "firstname", "first_name", "fname")).strip()
        lname = str(_get_row_value(row, "lastname", "last_name", "lname", "surname")).strip()
        if fname or lname: name = normalize_name(f"{fname} {lname}")
    if name and len(name) > 3:
        entities.append(("NAME", name))
    # Address
    addr = str(_get_row_value(row, "address")).strip()
    if addr and len(addr) > 5:
        entities.append(("ADDRESS", addr))

    return list(set(entities))

# =====================================================================
# CLICKHOUSE WRAPPERS
# =====================================================================

def sync_resolve_seed(seed_value: str, seed_type: str, ch_client) -> List[Dict]:
    if hasattr(ch_client, 'mock_query'):
        return ch_client.mock_query("resolve_seed", seed_type, seed_value)

    from .config import settings
    table = settings.clickhouse_table_path
    cols = "source_file, email, email_hash, data"

    params = {"val": seed_value}
    if seed_type == "email":
        params["val"] = seed_value.strip().lower()
        conditions = ["lowerUTF8(email) = lowerUTF8(%(val)s)"]
        for idx, header in enumerate(_candidate_headers("email")):
            h_key = f"email_header_{idx}"
            params[h_key] = header
            conditions.append(f"lowerUTF8(JSONExtractString(data, %({h_key})s)) = lowerUTF8(%(val)s)")
        query = f"SELECT {cols} FROM {table} WHERE {' OR '.join(conditions)} LIMIT 100"
    elif seed_type == "phone":
        val = normalize_phone(seed_value)
        params["val"] = val
        params["val_like"] = f"%{val}"
        conditions = []
        for idx, header in enumerate(_candidate_headers("phone", "mobile", "contact", "telephone", "cell")):
            h_key = f"phone_header_{idx}"
            params[h_key] = header
            digit_expr = f"replaceRegexpAll(JSONExtractString(data, %({h_key})s), '[^0-9]', '')"
            conditions.append(f"{digit_expr} LIKE %(val_like)s")
        query = f"""
            SELECT {cols} FROM {table}
            WHERE {' OR '.join(conditions) if conditions else '0'}
            LIMIT 100
        """
    elif seed_type == "name":
        val = normalize_name(seed_value)
        params["val"] = f"%{val}%"
        conditions = []
        for idx, header in enumerate(_candidate_headers("name", "full_name", "fullname", "contact_person")):
            h_key = f"name_header_{idx}"
            params[h_key] = header
            conditions.append(f"JSONExtractString(data, %({h_key})s) ILIKE %(val)s")
        query = f"""
            SELECT {cols} FROM {table}
            WHERE {' OR '.join(conditions) if conditions else '0'}
               OR concat(JSONExtractString(data, 'first_name'), ' ', JSONExtractString(data, 'last_name')) ILIKE %(val)s
               OR concat(JSONExtractString(data, 'firstname'), ' ', JSONExtractString(data, 'lastname')) ILIKE %(val)s
            LIMIT 100
        """
    else: return []

    result = ch_client.query(query, parameters=params)
    rows = []
    for row in result.result_rows:
        d = dict(zip(result.column_names, row))
        rows.append(_normalize_clickhouse_row(d))
    return rows

def sync_find_records(entity_type: str, entity_value: str, ch_client, limit: int = 200) -> List[Dict]:
    if hasattr(ch_client, 'mock_query'):
        return ch_client.mock_query("find_by_entity", entity_type, entity_value)

    from .config import settings
    table = settings.clickhouse_table_path
    cols = "source_file, email, email_hash, data"

    params = {"val": entity_value, "limit": limit}
    if entity_type == "EMAIL":
        params["val"] = str(entity_value).strip().lower()
        conditions = ["lowerUTF8(email) = lowerUTF8(%(val)s)"]
        for idx, header in enumerate(_candidate_headers("email")):
            h_key = f"email_header_{idx}"
            params[h_key] = header
            conditions.append(f"lowerUTF8(JSONExtractString(data, %({h_key})s)) = lowerUTF8(%(val)s)")
        query = f"SELECT {cols} FROM {table} WHERE {' OR '.join(conditions)} LIMIT %(limit)s"
    elif entity_type == "PHONE":
        params["val"] = normalize_phone(entity_value)
        params["val_like"] = f"%{params['val']}"
        conditions = []
        for idx, header in enumerate(_candidate_headers("phone", "mobile", "contact", "telephone", "cell")):
            h_key = f"phone_header_{idx}"
            params[h_key] = header
            digit_expr = f"replaceRegexpAll(JSONExtractString(data, %({h_key})s), '[^0-9]', '')"
            conditions.append(f"{digit_expr} LIKE %(val_like)s")
        query = f"""
            SELECT {cols} FROM {table}
            WHERE {' OR '.join(conditions) if conditions else '0'}
            LIMIT %(limit)s
        """
    elif entity_type == "NAME":
        params["val"] = f"%{normalize_name(entity_value)}%"
        conditions = []
        for idx, header in enumerate(_candidate_headers("name", "full_name", "fullname", "contact_person")):
            h_key = f"name_header_{idx}"
            params[h_key] = header
            conditions.append(f"JSONExtractString(data, %({h_key})s) ILIKE %(val)s")
        query = f"""
            SELECT {cols} FROM {table}
            WHERE {' OR '.join(conditions) if conditions else '0'}
               OR concat(JSONExtractString(data, 'first_name'), ' ', JSONExtractString(data, 'last_name')) ILIKE %(val)s
               OR concat(JSONExtractString(data, 'firstname'), ' ', JSONExtractString(data, 'lastname')) ILIKE %(val)s
            LIMIT %(limit)s
        """
    elif entity_type == "ADDRESS":
        params["val"] = f"%{entity_value}%"
        conditions = []
        for idx, header in enumerate(_candidate_headers("address")):
            h_key = f"address_header_{idx}"
            params[h_key] = header
            conditions.append(f"JSONExtractString(data, %({h_key})s) ILIKE %(val)s")
        query = f"SELECT {cols} FROM {table} WHERE {' OR '.join(conditions) if conditions else '0'} LIMIT %(limit)s"
    else: return []

    result = ch_client.query(query, parameters=params)
    rows = []
    for row in result.result_rows:
        d = dict(zip(result.column_names, row))
        rows.append(_normalize_clickhouse_row(d))
    return rows

# =====================================================================
# BFS CORE ENGINE
# =====================================================================

async def build_connection_graph(
    seed_value: str,
    seed_type: str,
    ch_client,
    max_records_per_entity: int = 100,
) -> Graph:
    start_time = time.perf_counter()

    # State
    nodes: Dict[str, GraphNode] = {}
    edges: Dict[str, GraphEdge] = {}
    visited_record_ids: Set[str] = set()
    visited_entity_ids: Set[str] = set()

    # Hard Caps
    MAX_RECORDS = 500
    MAX_ENTITIES = 300
    is_capped = False
    cap_reason = None

    # Step 0: Seed Resolution
    seed_rows = await asyncio.to_thread(sync_resolve_seed, seed_value, seed_type, ch_client)

    queue = deque() # (entity_type, entity_value, degree)

    for row in seed_rows:
        rid = build_row_id(row)
        if rid not in visited_record_ids:
            visited_record_ids.add(rid)
            nodes[rid] = GraphNode(
                id=rid, type="RECORD", label=row.get("source_file", "Record"),
                value=rid[:8], degree=0, record_data=row,
                source_file=row.get("source_file"), is_seed=True
            )

            # Extract degree 0 entities
            for etype, evalue in extract_pii_entities(row):
                eid = build_node_id(etype, evalue)
                if eid not in nodes:
                    nodes[eid] = GraphNode(id=eid, type=etype, label=evalue[:20], value=evalue, degree=0)

                # Add edge RECORD -> ENTITY
                edge_id = hashlib.sha256(f"{rid}|{eid}".encode()).hexdigest()
                edges[edge_id] = GraphEdge(id=edge_id, source=rid, target=eid, relationship=f"HAS_{etype}", shared_value=evalue)

                if eid not in visited_entity_ids:
                    queue.append((etype, evalue, 0))

    # BFS Loop
    current_depth = 0
    while queue and not is_capped:
        # Performance: Fan out queries for the current batch in the queue
        batch_size = min(len(queue), 10) # Process in batches of 10 for concurrency control
        tasks = []
        batch_items = []

        for _ in range(batch_size):
            etype, evalue, degree = queue.popleft()
            eid = build_node_id(etype, evalue)
            if eid in visited_entity_ids: continue
            visited_entity_ids.add(eid)

            current_depth = max(current_depth, degree + 1)
            batch_items.append((etype, evalue, eid, degree))
            tasks.append(asyncio.to_thread(sync_find_records, etype, evalue, ch_client, limit=201))

        if not tasks: continue

        results = await asyncio.gather(*tasks)

        for i, rows in enumerate(results):
            etype, evalue, eid, degree = batch_items[i]

            # Short-circuit on large results
            actual_count = len(rows)
            if actual_count > 200:
                nodes[eid].warning = f"Common value — {actual_count} records"
                rows = rows[:10] # Don't expand broad entities, just show a few samples

            for row in rows:
                if len(nodes) >= (MAX_RECORDS + MAX_ENTITIES):
                    is_capped = True
                    cap_reason = "Max node limit reached"
                    break

                rid = build_row_id(row)
                is_new_record = rid not in visited_record_ids
                if is_new_record:
                    visited_record_ids.add(rid)
                    nodes[rid] = GraphNode(
                        id=rid, type="RECORD", label=row.get("source_file", "Record"),
                        value=rid[:8], degree=degree + 1, record_data=row,
                        source_file=row.get("source_file")
                    )

                # Edge
                edge_id = hashlib.sha256(f"{rid}|{eid}".encode()).hexdigest()
                if edge_id not in edges:
                    edges[edge_id] = GraphEdge(id=edge_id, source=rid, target=eid, relationship=f"HAS_{etype}", shared_value=evalue)

                # Expansion logic: only expand 1st degree records to find 2nd degree entities
                if is_new_record and degree < 1:
                    for next_etype, next_evalue in extract_pii_entities(row):
                        next_eid = build_node_id(next_etype, next_evalue)
                        if next_eid not in nodes:
                            if len(nodes) >= (MAX_RECORDS + MAX_ENTITIES): break
                            nodes[next_eid] = GraphNode(id=next_eid, type=next_etype, label=next_evalue[:20], value=next_evalue, degree=degree+1)

                        if next_eid not in visited_entity_ids:
                            queue.append((next_etype, next_evalue, degree + 1))

            if is_capped: break

    return Graph(
        seed_input=seed_value,
        seed_type=seed_type,
        nodes=list(nodes.values()),
        edges=list(edges.values()),
        total_records_found=len(visited_record_ids),
        depth_reached=current_depth,
        query_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
        created_at=datetime.now().isoformat(),
        capped=is_capped,
        cap_reason=cap_reason
    )

# =====================================================================
# MOCK TESTING STEP 2
# =====================================================================
if __name__ == "__main__":
    import json

    class MockCHClient:
        def mock_query(self, action, type_, val):
            if action == "resolve_seed":
                return [{"source_file": "leak1.csv", "email": "target@test.com", "phone": "1234567890", "name": "John Doe"}]
            if action == "find_by_entity":
                if type_ == "EMAIL" and val == "target@test.com":
                    return [
                        {"source_file": "leak1.csv", "email": "target@test.com", "phone": "1234567890", "name": "John Doe"},
                        {"source_file": "leak2.csv", "email": "target@test.com", "phone": "9999999999", "name": "J. Doe"}
                    ]
                if type_ == "PHONE" and val == "9999999999":
                    return [{"source_file": "leak3.csv", "email": "other@test.com", "phone": "9999999999"}]
            return []

    async def run_test():
        print("Running Step 2 BFS Tests...")
        mock_client = MockCHClient()
        graph = await build_connection_graph("target@test.com", "email", mock_client)

        print(f"Graph generated in {graph.query_time_ms}ms")
        print(f"Nodes: {len(graph.nodes)} | Edges: {len(graph.edges)}")

        # Verify degrees
        for node in graph.nodes:
            if node.type == "RECORD":
                print(f"Record Node: {node.label} | Degree: {node.degree} | Seed: {node.is_seed}")

        # Output snippet
        # print(json.dumps(graph.dict(), indent=2))
        print("Step 2 tests completed.")

    asyncio.run(run_test())
