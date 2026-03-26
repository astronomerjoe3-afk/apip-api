from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SessionLoginRequest(BaseModel):
    id_token: str = Field(min_length=1)


class SessionUserOut(BaseModel):
    uid: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    role: str


class SessionLoginResponse(BaseModel):
    ok: bool = True
    session_token: str
    expires_utc: str
    user: SessionUserOut


class SessionStatusResponse(BaseModel):
    ok: bool = True
    user: SessionUserOut
