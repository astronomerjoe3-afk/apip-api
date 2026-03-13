from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class CheckoutSessionRequest(BaseModel):
    purchase_kind: Literal["module_unlock", "subscription"]
    module_id: Optional[str] = None
    plan_id: Optional[str] = None
    origin: Optional[str] = None
    success_path: Optional[str] = None
    cancel_path: Optional[str] = None


class CheckoutConfirmRequest(BaseModel):
    session_id: str = Field(min_length=1)
    module_id: Optional[str] = None


class PortalSessionRequest(BaseModel):
    origin: Optional[str] = None
    return_path: Optional[str] = None
