from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.auth import SessionSecurityOut


class ProfileResponse(BaseModel):
    ok: bool = True
    uid: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    email_verified: Optional[bool] = None
    role: str
    security: Optional[SessionSecurityOut] = None
    utc: str


class ProfileUpdateRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=120)


class ProfileDeleteRequest(BaseModel):
    confirm_text: str = Field(min_length=3, max_length=64)


class ProfileDeleteResponse(BaseModel):
    ok: bool = True
    deleted: dict[str, int | bool | list[str]]
    utc: str
