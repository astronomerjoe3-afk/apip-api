from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class SessionLoginRequest(BaseModel):
    id_token: str = Field(min_length=1)


class SessionSecurityOut(BaseModel):
    password_policy_version: int = 0
    password_policy_target_version: int = 1
    strong_password_confirmed: bool = False
    strong_password_confirmed_utc: Optional[str] = None
    email_verified: bool = False
    email_verified_utc: Optional[str] = None
    hardening_complete: bool = False
    recommended_actions: list[str] = Field(default_factory=list)
    recommended_next_step: Optional[str] = None


class SessionUserOut(BaseModel):
    uid: str
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    role: str
    security: Optional[SessionSecurityOut] = None


class SessionLoginResponse(BaseModel):
    ok: bool = True
    session_token: str
    expires_utc: str
    user: SessionUserOut


class SessionStatusResponse(BaseModel):
    ok: bool = True
    user: SessionUserOut


class PasswordPolicyUpdateRequest(BaseModel):
    password_policy_version: int = Field(ge=1, le=10)


class PasswordPolicyUpdateResponse(BaseModel):
    ok: bool = True
    security: SessionSecurityOut
