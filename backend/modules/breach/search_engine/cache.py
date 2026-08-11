from __future__ import annotations

import json
import logging
from typing import Any

import redis

from .config import settings

LOGGER = logging.getLogger(__name__)


class RedisJSONCache:
    def __init__(self) -> None:
        self._client: redis.Redis | None = None
        self._available = True

    def _get_client(self) -> redis.Redis | None:
        if not self._available:
            return None

        if self._client is None:
            try:
                self._client = redis.Redis(
                    host=settings.redis_host,
                    port=settings.redis_port,
                    db=settings.redis_db,
                    password=settings.redis_password,
                    decode_responses=settings.redis_decode_responses,
                    socket_timeout=2.0,
                    socket_connect_timeout=2.0,
                )
            except Exception:
                LOGGER.exception("Failed to initialize Redis client")
                self._available = False
                return None

        return self._client

    def health_check(self) -> dict[str, Any]:
        client = self._get_client()
        if client is None:
            return {"status": "disabled"}

        try:
            return {"status": "ok" if client.ping() else "error"}
        except Exception as exc:
            return {"status": "error", "detail": str(exc)}

    def get_json(self, key: str) -> Any | None:
        client = self._get_client()
        if client is None:
            return None

        try:
            value = client.get(key)
            return json.loads(value) if value else None
        except Exception:
            LOGGER.exception("Redis cache read failed for key=%s", key)
            return None

    def set_json(self, key: str, value: Any, ttl_seconds: int) -> None:
        client = self._get_client()
        if client is None:
            return

        try:
            client.setex(key, ttl_seconds, json.dumps(value, default=str))
        except Exception:
            LOGGER.exception("Redis cache write failed for key=%s", key)


cache = RedisJSONCache()
