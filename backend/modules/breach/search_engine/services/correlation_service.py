from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from elasticsearch import Elasticsearch

from ..cache import cache
from ..config import settings
from ..models import CorrelationSearchRequest
from ..search_utils import PIIType, detect_type, json_dumps_sorted, normalize_input, normalize_phone

LOGGER = logging.getLogger(__name__)


@dataclass
class Entity:
    entity_id: str
    emails: set[str] = field(default_factory=set)
    phones: set[str] = field(default_factory=set)
    names: set[str] = field(default_factory=set)
    companies: set[str] = field(default_factory=set)
    cities: set[str] = field(default_factory=set)
    states: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    raw_records: list[dict[str, Any]] = field(default_factory=list)

    def merge(self, other: "Entity") -> None:
        self.emails.update(other.emails)
        self.phones.update(other.phones)
        self.names.update(other.names)
        self.companies.update(other.companies)
        self.cities.update(other.cities)
        self.states.update(other.states)
        self.sources.update(other.sources)
        self.raw_records.extend(other.raw_records)

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary_id": self.entity_id,
            "emails": sorted(self.emails),
            "phones": sorted(self.phones),
            "names": sorted(self.names),
            "companies": sorted(self.companies),
            "locations": {
                "cities": sorted(self.cities),
                "states": sorted(self.states),
            },
            "sources": sorted(self.sources),
            "record_count": len(self.raw_records),
        }


def _cache_key(request: CorrelationSearchRequest, normalized_seed: str, pii_type: str) -> str:
    payload = {
        "seed": normalized_seed,
        "seed_type": pii_type,
        "max_depth": request.max_depth,
        "max_results_per_query": request.max_results_per_query,
    }
    digest = hashlib.sha256(json_dumps_sorted(payload).encode("utf-8")).hexdigest()
    return f"unified:correlation:{digest}"


def _get_es_client() -> Elasticsearch:
    scheme = "https" if settings.elasticsearch_use_ssl else "http"
    hosts = [f"{scheme}://{settings.elasticsearch_host}:{settings.elasticsearch_port}"]
    return Elasticsearch(
        hosts=hosts,
        verify_certs=settings.elasticsearch_verify_certs,
        request_timeout=30,
        retry_on_timeout=True,
        max_retries=3,
    )


class CorrelationScanner:
    def __init__(self, request: CorrelationSearchRequest) -> None:
        self.request = request
        self.es = _get_es_client()
        self.index_pattern = f"{settings.elasticsearch_index_prefix}*"
        self.processed_emails: set[str] = set()
        self.processed_phones: set[str] = set()
        self.entities: dict[str, Entity] = {}

    def _search(self, body: dict[str, Any], size: int) -> list[dict[str, Any]]:
        response = self.es.search(index=self.index_pattern, body={**body, "size": size})
        hits = response.get("hits", {}).get("hits", [])
        return [hit.get("_source", {}) for hit in hits]

    def _universal_search(self, query_value: str, size: int) -> list[dict[str, Any]]:
        normalized_phone = normalize_phone(query_value)
        should = [
            {"match": {"email": query_value}},
            {"match": {"email2": query_value}},
            {"term": {"email.keyword": query_value}},
            {"term": {"email2.keyword": query_value}},
            {"match": {"phone": query_value}},
            {"match": {"phone2": query_value}},
            {"wildcard": {"phone": f"*{query_value}*"}},
            {"wildcard": {"phone2": f"*{query_value}*"}},
            {"match": {"first_name": query_value}},
            {"match": {"last_name": query_value}},
            {"match": {"full_name": query_value}},
            {"wildcard": {"first_name": f"*{query_value}*"}},
            {"wildcard": {"last_name": f"*{query_value}*"}},
            {"wildcard": {"full_name": f"*{query_value}*"}},
            {"match": {"city": query_value}},
            {"match": {"state": query_value}},
            {"match": {"company": query_value}},
        ]
        if len(normalized_phone) >= 7:
            should.extend(
                [
                    {"term": {"phone.keyword": normalized_phone}},
                    {"term": {"phone2.keyword": normalized_phone}},
                ]
            )
        return self._search({"query": {"bool": {"should": should, "minimum_should_match": 1}}}, size=size)

    def _search_contacts(self, emails: set[str], phones: set[str], size: int) -> list[dict[str, Any]]:
        should = []

        for email in emails:
            if email not in self.processed_emails:
                self.processed_emails.add(email)
                should.append({"term": {"email.keyword": email}})
                should.append({"term": {"email2.keyword": email}})

        for phone in phones:
            if phone not in self.processed_phones:
                self.processed_phones.add(phone)
                should.append({"term": {"phone.keyword": phone}})
                should.append({"term": {"phone2.keyword": phone}})

        if not should:
            return []

        return self._search({"query": {"bool": {"should": should, "minimum_should_match": 1}}}, size=size)

    def _record_to_entity(self, record: dict[str, Any]) -> Entity | None:
        primary_email = record.get("email") or record.get("email2")
        primary_phone = record.get("phone") or record.get("phone2")

        if not primary_email and not primary_phone:
            return None

        entity_id = str(primary_email).strip().lower() if primary_email else f"phone:{normalize_phone(str(primary_phone))}"
        entity = Entity(entity_id=entity_id)

        for key in ("email", "email2"):
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                entity.emails.add(value.strip().lower())

        for key in ("phone", "phone2"):
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                normalized = normalize_phone(value)
                if normalized:
                    entity.phones.add(normalized)

        value = record.get("full_name")
        if isinstance(value, str) and value.strip():
            entity.names.add(value.strip())

        first_name = str(record.get("first_name", "")).strip()
        last_name = str(record.get("last_name", "")).strip()
        combined_name = " ".join(part for part in (first_name, last_name) if part)
        if combined_name:
            entity.names.add(combined_name)

        for key, target in (
            ("company", entity.companies),
            ("city", entity.cities),
            ("state", entity.states),
            ("source", entity.sources),
        ):
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                target.add(value.strip())

        entity.raw_records.append(record)
        return entity

    def _merge_entity(self, new_entity: Entity) -> None:
        matches = []
        for entity_id, entity in self.entities.items():
            if entity.emails & new_entity.emails:
                matches.append(entity_id)
                continue
            if entity.phones & new_entity.phones:
                matches.append(entity_id)
                continue
            if entity.names & new_entity.names:
                matches.append(entity_id)

        if not matches:
            self.entities[new_entity.entity_id] = new_entity
            return

        primary_id = matches[0]
        self.entities[primary_id].merge(new_entity)
        for duplicate_id in matches[1:]:
            self.entities[primary_id].merge(self.entities[duplicate_id])
            del self.entities[duplicate_id]

    def scan(self, seed_type: PIIType, normalized_seed: str) -> dict[str, Any]:
        frontier_emails: set[str] = set()
        frontier_phones: set[str] = set()
        seed_entities: list[str] = []
        per_query_size = self.request.max_results_per_query

        if seed_type == PIIType.EMAIL:
            exact_records = self._search(
                {
                    "query": {
                        "bool": {
                            "should": [
                                {"term": {"email.keyword": normalized_seed}},
                                {"term": {"email2.keyword": normalized_seed}},
                            ]
                        }
                    }
                },
                size=per_query_size,
            )
        elif seed_type == PIIType.PHONE:
            exact_records = self._search(
                {
                    "query": {
                        "bool": {
                            "should": [
                                {"term": {"phone.keyword": normalized_seed}},
                                {"term": {"phone2.keyword": normalized_seed}},
                            ]
                        }
                    }
                },
                size=per_query_size,
            )
        else:
            exact_records = self._universal_search(normalized_seed, size=per_query_size)

        for record in exact_records:
            entity = self._record_to_entity(record)
            if entity is None:
                continue
            self._merge_entity(entity)
            seed_entities.append(entity.entity_id)
            frontier_emails.update(entity.emails)
            frontier_phones.update(entity.phones)

        if not frontier_emails and not frontier_phones:
            return {
                "backend": "elasticsearch",
                "scan_metadata": {
                    "seed": {"value": normalized_seed, "type": seed_type.value},
                    "depth_reached": 0,
                    "total_entities_found": 0,
                    "exact_matches": 0,
                    "expanded_entities": 0,
                    "total_emails_processed": 0,
                    "total_phones_processed": 0,
                },
                "correlated_entities": [],
                "summary": {
                    "unique_emails": 0,
                    "unique_phones": 0,
                    "unique_names": 0,
                    "unique_companies": 0,
                    "sources": [],
                    "total_records": 0,
                },
            }

        depth_reached = 0
        for depth in range(self.request.max_depth):
            depth_reached = depth + 1
            records = self._search_contacts(frontier_emails, frontier_phones, size=per_query_size)
            if not records:
                break

            new_emails: set[str] = set()
            new_phones: set[str] = set()
            for record in records:
                entity = self._record_to_entity(record)
                if entity is None:
                    continue

                if (entity.emails & frontier_emails) or (entity.phones & frontier_phones) or depth == 0:
                    new_emails.update(entity.emails - self.processed_emails)
                    new_phones.update(entity.phones - self.processed_phones)
                    self._merge_entity(entity)

            frontier_emails = new_emails
            frontier_phones = new_phones
            if not frontier_emails and not frontier_phones:
                break

        exact_count = 0
        correlated_entities = []
        all_emails: set[str] = set()
        all_phones: set[str] = set()
        all_names: set[str] = set()
        all_companies: set[str] = set()
        all_sources: set[str] = set()
        total_records = 0

        for entity_id, entity in self.entities.items():
            entity_payload = entity.to_dict()
            entity_payload["is_exact_match"] = entity_id in seed_entities
            if entity_payload["is_exact_match"]:
                exact_count += 1
            correlated_entities.append(entity_payload)

            all_emails.update(entity.emails)
            all_phones.update(entity.phones)
            all_names.update(entity.names)
            all_companies.update(entity.companies)
            all_sources.update(entity.sources)
            total_records += len(entity.raw_records)

        correlated_entities.sort(key=lambda item: (not item["is_exact_match"], item["primary_id"]))

        return {
            "backend": "elasticsearch",
            "scan_metadata": {
                "seed": {"value": normalized_seed, "type": seed_type.value},
                "depth_reached": depth_reached,
                "total_entities_found": len(self.entities),
                "exact_matches": exact_count,
                "expanded_entities": max(0, len(self.entities) - exact_count),
                "total_emails_processed": len(self.processed_emails),
                "total_phones_processed": len(self.processed_phones),
            },
            "correlated_entities": correlated_entities,
            "summary": {
                "unique_emails": len(all_emails),
                "unique_phones": len(all_phones),
                "unique_names": len(all_names),
                "unique_companies": len(all_companies),
                "sources": sorted(all_sources),
                "total_records": total_records,
            },
        }


def search(request: CorrelationSearchRequest) -> dict[str, Any]:
    if not settings.enable_correlation_search:
        raise RuntimeError("Correlation search is disabled")

    start_time = time.perf_counter()
    valid_types = {item.value for item in PIIType}
    seed_type = PIIType(request.seed_type) if request.seed_type in valid_types else detect_type(request.seed)
    normalized_seed = normalize_input(request.seed, seed_type)
    normalized_request = CorrelationSearchRequest(
        seed=request.seed.strip(),
        seed_type=seed_type.value,
        max_depth=min(request.max_depth, settings.max_correlation_depth),
        max_results_per_query=request.max_results_per_query,
        use_cache=request.use_cache,
    )
    cache_key = _cache_key(normalized_request, normalized_seed, seed_type.value)

    if normalized_request.use_cache:
        cached = cache.get_json(cache_key)
        if cached is not None:
            cached["cache_hit"] = True
            return cached

    scanner = CorrelationScanner(normalized_request)
    response = scanner.scan(seed_type, normalized_seed)
    response["cache_hit"] = False
    response["took_ms"] = round((time.perf_counter() - start_time) * 1000, 2)

    if normalized_request.use_cache:
        cache.set_json(cache_key, response, settings.correlation_cache_ttl_seconds)

    return response


def health_check() -> dict[str, Any]:
    if not settings.enable_correlation_search:
        return {"status": "disabled"}

    try:
        client = _get_es_client()
        info = client.info()
        version = info.get("version", {}).get("number")
        return {"status": "ok", "version": version}
    except Exception as exc:
        LOGGER.exception("Elasticsearch health check failed")
        return {"status": "error", "detail": str(exc)}
