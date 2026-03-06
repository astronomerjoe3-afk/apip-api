from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AdminKeyOut(BaseModel):
    key_id: str
    label: Optional[str] = None
    active: bool
    scopes: List[str] = Field(default_factory=list)
    created_utc: Optional[str] = None
    updated_utc: Optional[str] = None
    rate_limit: Dict[str, Any] = Field(default_factory=dict)
    daily_limit: Optional[int] = None
    auto_disabled: bool = False
    last_used_utc: Optional[str] = None


class AdminMetricsResponse(BaseModel):
    ok: bool = True
    utc: str
    keys: Dict[str, Any]
    rate_limit: Dict[str, Any]
    warnings: List[str] = Field(default_factory=list)


class AdminKeysListResponse(BaseModel):
    ok: bool = True
    keys: List[AdminKeyOut]
    limit: int
    utc: str


class AdminKeyResponse(BaseModel):
    ok: bool = True
    key: AdminKeyOut


class AdminCreateKeyRequest(BaseModel):
    label: Optional[str] = "web-admin-created"
    scopes: Optional[List[str] | str] = None
    window_limit: Optional[int] = 10
    window_seconds: Optional[int] = 60
    bucket_seconds: Optional[int] = 10
    daily_limit: Optional[int] = 500


class AdminCreateKeyResponse(BaseModel):
    ok: bool = True
    key_id: str
    active: bool
    label: str
    scopes: List[str]
    api_key: str
    utc: str


class AdminToggleKeyResponse(BaseModel):
    ok: bool = True
    key_id: str
    enabled: Optional[bool] = None
    disabled: Optional[bool] = None


class AdminResetCountersResponse(BaseModel):
    ok: bool = True
    key_id: str
    reset: bool
    details: Dict[str, Any]
