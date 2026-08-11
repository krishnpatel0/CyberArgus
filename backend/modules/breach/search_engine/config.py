from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent

for env_path in (
    BASE_DIR / ".env",
    BASE_DIR.parent / "pii_scanner" / ".env",
):
    if env_path.exists():
        load_dotenv(env_path, override=False)


def _pick_env(*names: str, default: str | None = None) -> str | None:
    for name in names:
        value = os.getenv(name)
        if value is not None and str(value).strip() != "":
            return str(value).strip()
    return default


def _pick_bool(*names: str, default: bool = False) -> bool:
    value = _pick_env(*names)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _pick_int(*names: str, default: int) -> int:
    value = _pick_env(*names)
    if value is None:
        return default
    return int(value)


@dataclass(frozen=True)
class Settings:
    clickhouse_host: str
    clickhouse_port: int
    clickhouse_database: str
    clickhouse_table: str
    clickhouse_username: str | None
    clickhouse_password: str | None
    clickhouse_limit_max: int
    email_hash_salt: str
    elasticsearch_host: str
    elasticsearch_port: int
    elasticsearch_index_prefix: str
    elasticsearch_use_ssl: bool
    elasticsearch_verify_certs: bool
    redis_host: str
    redis_port: int
    redis_db: int
    redis_password: str | None
    redis_decode_responses: bool
    direct_cache_ttl_seconds: int
    correlation_cache_ttl_seconds: int
    max_correlation_depth: int
    correlation_query_size: int
    enable_direct_search: bool
    enable_correlation_search: bool
    field_map_path: Path
    api_keys: tuple[str, ...]  # valid API keys; empty = no auth required

    @property
    def clickhouse_table_path(self) -> str:
        return f"{self.clickhouse_database}.{self.clickhouse_table}"


def get_settings() -> Settings:
    field_map_path = BASE_DIR / "schema_report.json"

    return Settings(
        clickhouse_host=_pick_env("UNIFIED_CLICKHOUSE_HOST", "CH_HOST", default="localhost") or "localhost",
        clickhouse_port=_pick_int("UNIFIED_CLICKHOUSE_PORT", "CH_PORT", default=8123),
        clickhouse_database=_pick_env("UNIFIED_CLICKHOUSE_DATABASE", default="csv_warehouse") or "csv_warehouse",
        clickhouse_table=_pick_env("UNIFIED_CLICKHOUSE_TABLE", default="raw_data") or "raw_data",
        clickhouse_username=_pick_env("UNIFIED_CLICKHOUSE_USERNAME", "CH_USERNAME"),
        clickhouse_password=_pick_env("UNIFIED_CLICKHOUSE_PASSWORD", "CH_PASSWORD"),
        clickhouse_limit_max=_pick_int("UNIFIED_CLICKHOUSE_LIMIT_MAX", default=500),
        email_hash_salt=_pick_env("UNIFIED_EMAIL_HASH_SALT", "SALT", default="") or "",
        elasticsearch_host=_pick_env("UNIFIED_ES_HOST", "ES_HOST", default="localhost") or "localhost",
        elasticsearch_port=_pick_int("UNIFIED_ES_PORT", "ES_PORT", default=9200),
        elasticsearch_index_prefix=_pick_env("UNIFIED_ES_INDEX_PREFIX", "ES_INDEX_PREFIX", default="breach_data_") or "breach_data_",
        elasticsearch_use_ssl=_pick_bool("UNIFIED_ES_USE_SSL", "ES_USE_SSL", default=False),
        elasticsearch_verify_certs=_pick_bool("UNIFIED_ES_VERIFY_CERTS", "ES_VERIFY_CERTS", default=False),
        redis_host=_pick_env("UNIFIED_REDIS_HOST", "REDIS_HOST", default="localhost") or "localhost",
        redis_port=_pick_int("UNIFIED_REDIS_PORT", "REDIS_PORT", default=6379),
        redis_db=_pick_int("UNIFIED_REDIS_DB", "REDIS_DB", default=0),
        redis_password=_pick_env("UNIFIED_REDIS_PASSWORD", "REDIS_PASSWORD"),
        redis_decode_responses=True,
        direct_cache_ttl_seconds=_pick_int("UNIFIED_DIRECT_CACHE_TTL_SECONDS", default=300),
        correlation_cache_ttl_seconds=_pick_int("UNIFIED_CORRELATION_CACHE_TTL_SECONDS", "CACHE_TTL_SECONDS", default=86400),
        max_correlation_depth=_pick_int("MAX_RECURSION_DEPTH", "UNIFIED_MAX_CORRELATION_DEPTH", default=3),
        correlation_query_size=_pick_int("UNIFIED_CORRELATION_QUERY_SIZE", default=250),
        enable_direct_search=_pick_bool("UNIFIED_ENABLE_DIRECT_SEARCH", default=True),
        enable_correlation_search=_pick_bool("UNIFIED_ENABLE_CORRELATION_SEARCH", default=True),
        field_map_path=field_map_path,
        api_keys=tuple(
            k.strip()
            for k in (_pick_env("API_KEYS", "API_KEY", default="") or "").split(",")
            if k.strip()
        ),
    )


settings = get_settings()
