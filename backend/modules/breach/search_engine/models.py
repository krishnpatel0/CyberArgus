from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class MatchMode(str, Enum):
    EXACT = "exact"
    CONTAINS = "contains"
    PREFIX = "prefix"


class SearchFilter(BaseModel):
    field: str = Field(..., min_length=1)
    value: str = Field(..., min_length=1)
    match_mode: MatchMode = MatchMode.EXACT


class DirectSearchRequest(BaseModel):
    filters: list[SearchFilter] = Field(default_factory=list)
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    include_count: bool = True
    use_cache: bool = True


class CorrelationSearchRequest(BaseModel):
    seed: str = Field(..., min_length=1)
    seed_type: str | None = None
    max_depth: int = Field(default=3, ge=0, le=6)
    max_results_per_query: int = Field(default=250, ge=1, le=5000)
    use_cache: bool = True


class CombinedSearchRequest(BaseModel):
    query: str | None = None
    direct_field: str | None = None
    direct_filters: list[SearchFilter] = Field(default_factory=list)
    direct_limit: int = Field(default=25, ge=1, le=500)
    direct_offset: int = Field(default=0, ge=0)
    direct_include_count: bool = True
    correlation_seed: str | None = None
    correlation_seed_type: str | None = None
    max_depth: int = Field(default=3, ge=0, le=6)
    max_results_per_query: int = Field(default=250, ge=1, le=5000)
    run_direct: bool = True
    run_correlation: bool = True
    use_cache: bool = True


class ConnectionsSearchRequest(BaseModel):
    record_id: str | None = None
    filters: list[SearchFilter] = Field(default_factory=list)
    depth: int = Field(default=1, ge=1, le=2)
    limit_per_level: int = Field(default=50, ge=1, le=200)
    use_cache: bool = True
