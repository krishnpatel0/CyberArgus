from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .config import settings
from .search_utils import normalize_column_name

LOGGER = logging.getLogger(__name__)

DIRECT_FIELD_DEFAULTS = [
    "email",
    "source_file",
    "name",
    "firstname",
    "lastname",
    "phone",
    "mobile",
    "city",
    "state",
    "companyname",
]

CORRELATION_FIELDS = [
    "email",
    "email2",
    "phone",
    "phone2",
    "full_name",
    "first_name",
    "last_name",
    "company",
    "city",
    "state",
    "country",
    "source",
]


class FieldCatalog:
    def __init__(self, schema_report_path: Path) -> None:
        self.schema_report_path = schema_report_path
        self._field_map: dict[str, list[str]] = {}
        self._direct_fields: list[str] = list(DIRECT_FIELD_DEFAULTS)
        self._load()

    def _load(self) -> None:
        if not self.schema_report_path.exists():
            return

        try:
            report = json.loads(self.schema_report_path.read_text(encoding="utf-8"))
            direct_fields = {"email", "source_file"}

            for item in report.get("column_frequency", []):
                normalized_name = str(item.get("normalized_name", "")).strip()
                if not normalized_name:
                    continue

                headers = [
                    str(header).strip()
                    for header in item.get("example_headers", [])
                    if str(header).strip()
                ][:5]

                self._field_map[normalize_column_name(normalized_name)] = headers
                direct_fields.add(normalized_name)

            self._direct_fields = sorted(direct_fields)
        except Exception:
            LOGGER.exception("Failed to load field catalog from %s", self.schema_report_path)

    def resolve_clickhouse_headers(self, field_name: str) -> list[str]:
        field_key = normalize_column_name(field_name)
        headers = list(self._field_map.get(field_key, []))
        if field_name not in headers:
            headers.insert(0, field_name)
        return headers[:5]

    def get_direct_fields(self) -> list[str]:
        return list(self._direct_fields)

    def get_correlation_fields(self) -> list[str]:
        return list(CORRELATION_FIELDS)

    def describe(self) -> dict[str, Any]:
        return {
            "direct_fields": self.get_direct_fields(),
            "correlation_fields": self.get_correlation_fields(),
            "all_fields": sorted(set(self._direct_fields) | set(CORRELATION_FIELDS)),
            "schema_report_path": str(self.schema_report_path),
        }


field_catalog = FieldCatalog(settings.field_map_path)
