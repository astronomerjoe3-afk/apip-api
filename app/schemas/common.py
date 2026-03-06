from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class OkResponse(BaseModel):
    ok: bool = True


class WarningListMixin(BaseModel):
    warnings: List[str] = Field(default_factory=list)


class AuditMetadataMixin(BaseModel):
    utc: Optional[str] = None


class GenericDictModel(BaseModel):
    model_config = {"extra": "allow"}


class KeyValueMap(BaseModel):
    model_config = {"extra": "allow"}
