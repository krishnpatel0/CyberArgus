"""Intelbase email lookup integration for OSINT investigations."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import requests


LOOKUP_URL = os.getenv("INTELBASE_EMAIL_LOOKUP_URL", "https://api.intelbase.is/lookup/email")
API_KEY_ENV = "INTELBASE_API_KEY"
TIMEOUT_SECONDS = float(os.getenv("INTELBASE_TIMEOUT_SECONDS", "20"))


class IntelbaseLookupError(RuntimeError):
    """Raised when Intelbase lookup cannot be completed."""


@dataclass
class IntelbasePlatform:
    name: str
    url: str = ""
    confidence: float = 88.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IntelbaseEmailLookup:
    email: str
    exists: bool | None
    valid_format: bool | None
    disposable: bool | None
    deliverable: bool | None
    platforms: list[IntelbasePlatform]
    breaches: list[dict[str, Any]]
    raw_keys: list[str]
    elapsed_ms: int

    @property
    def found(self) -> bool:
        return bool(self.platforms or self.breaches or self.exists or self.deliverable)


def intelbase_enabled() -> bool:
    return bool(os.getenv(API_KEY_ENV, "").strip())


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return email
    safe_local = f"{local[:2]}***{local[-1:]}" if len(local) > 2 else f"{local[:1]}*"
    return f"{safe_local}@{domain}"


def lookup_email(email: str) -> IntelbaseEmailLookup:
    api_key = os.getenv(API_KEY_ENV, "").strip()
    if not api_key:
        raise IntelbaseLookupError(f"{API_KEY_ENV} is not configured")

    started = time.time()
    response = requests.post(
        LOOKUP_URL,
        headers={
            "accept": "application/json",
            "content-type": "application/json",
            "x-api-key": api_key,
            "user-agent": "ArgusWatch-OSINT/1.0",
        },
        json={
            "email": email,
            "timeout_ms": int(TIMEOUT_SECONDS * 1000),
            "include_data_breaches": True,
        },
        timeout=TIMEOUT_SECONDS,
    )
    elapsed_ms = int((time.time() - started) * 1000)

    if response.status_code in (401, 403):
        raise IntelbaseLookupError("Intelbase API key was rejected")
    if response.status_code == 429:
        raise IntelbaseLookupError("Intelbase rate limit reached")
    if response.status_code >= 400:
        raise IntelbaseLookupError(f"Intelbase returned HTTP {response.status_code}")

    try:
        payload = response.json()
    except ValueError as exc:
        raise IntelbaseLookupError("Intelbase returned non-JSON data") from exc

    return _normalize_lookup(email=email, payload=payload, elapsed_ms=elapsed_ms)


def _normalize_lookup(email: str, payload: Any, elapsed_ms: int) -> IntelbaseEmailLookup:
    data = _payload_data(payload)
    return IntelbaseEmailLookup(
        email=email,
        exists=_bool_from_keys(data, ("exists", "found", "registered", "is_registered")),
        valid_format=_bool_from_keys(data, ("valid", "valid_format", "is_valid")),
        disposable=_bool_from_keys(data, ("disposable", "is_disposable")),
        deliverable=_bool_from_keys(data, ("deliverable", "is_deliverable", "mx_valid")),
        platforms=_extract_platforms(data),
        breaches=_extract_breaches(data),
        raw_keys=sorted(data.keys()) if isinstance(data, dict) else [],
        elapsed_ms=elapsed_ms,
    )


def _payload_data(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    for key in ("data", "result", "email", "lookup"):
        nested = payload.get(key)
        if isinstance(nested, (dict, list)):
            return nested
    return payload


def _bool_from_keys(data: Any, keys: tuple[str, ...]) -> bool | None:
    if not isinstance(data, dict):
        return None
    for key in keys:
        if key not in data:
            continue
        value = data.get(key)
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "valid", "found"}
    return None


def _extract_platforms(data: Any) -> list[IntelbasePlatform]:
    records = _collect_records(
        data,
        keys=("platforms", "accounts", "registrations", "sites", "services", "profiles", "results"),
    )
    platforms: list[IntelbasePlatform] = []
    seen: set[str] = set()

    for record in records:
        if isinstance(record, str):
            name = record.strip()
            url = ""
            confidence = 88.0
            metadata: dict[str, Any] = {}
        elif isinstance(record, dict):
            name = str(
                record.get("site")
                or record.get("platform")
                or record.get("service")
                or record.get("name")
                or record.get("domain")
                or ""
            ).strip()
            url = str(record.get("url") or record.get("profile_url") or record.get("link") or "").strip()
            confidence = _safe_score(record.get("confidence") or record.get("score"), default=88.0)
            metadata = _safe_metadata(record)
        else:
            continue

        if not name:
            continue
        dedupe_key = f"{name.lower()}|{url.lower()}"
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        platforms.append(IntelbasePlatform(name=name, url=url, confidence=confidence, metadata=metadata))

    return platforms[:50]


def _extract_breaches(data: Any) -> list[dict[str, Any]]:
    breaches = _collect_records(data, keys=("breaches", "leaks", "breach_data", "compromises"))
    normalized: list[dict[str, Any]] = []
    for breach in breaches[:50]:
        if isinstance(breach, str):
            normalized.append({"name": breach})
        elif isinstance(breach, dict):
            normalized.append(_safe_metadata(breach))
    return normalized


def _collect_records(data: Any, keys: tuple[str, ...]) -> list[Any]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []

    collected: list[Any] = []
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            collected.extend(value)
        elif isinstance(value, dict):
            collected.extend(value.values())
    return collected


def _safe_score(value: Any, default: float) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return default
    if score <= 1:
        score *= 100
    return max(0.0, min(100.0, score))


def _safe_metadata(record: dict[str, Any]) -> dict[str, Any]:
    blocked = {"password", "hash", "token", "api_key", "secret", "credential"}
    metadata: dict[str, Any] = {}
    for key, value in record.items():
        lowered = str(key).lower()
        if any(word in lowered for word in blocked):
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            metadata[str(key)] = value
        elif isinstance(value, list):
            metadata[str(key)] = value[:10]
        elif isinstance(value, dict):
            metadata[str(key)] = {str(k): v for k, v in list(value.items())[:10]}
    return metadata
