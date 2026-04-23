from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from app.schemas.auth import SessionSecurityOut


class StudentPreferences(BaseModel):
    favorite_modules: list[str] = Field(default_factory=list)
    favorite_lessons: list[str] = Field(default_factory=list)


class StudentLearningState(BaseModel):
    last_module_id: Optional[str] = None
    last_lesson_id: Optional[str] = None
    last_lesson_title: Optional[str] = None
    last_route: Optional[str] = None
    last_visited_utc: Optional[str] = None


class ProfileResponse(BaseModel):
    ok: bool = True
    uid: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    email_verified: Optional[bool] = None
    role: str
    security: Optional[SessionSecurityOut] = None
    preferences: StudentPreferences = Field(default_factory=StudentPreferences)
    learning_state: StudentLearningState = Field(default_factory=StudentLearningState)
    utc: str


class ProfileUpdateRequest(BaseModel):
    display_name: str = Field(min_length=2, max_length=120)


class ProfilePreferencesUpdateRequest(BaseModel):
    favorite_modules: list[str] = Field(default_factory=list)
    favorite_lessons: list[str] = Field(default_factory=list)


class ProfileLearningStateUpdateRequest(BaseModel):
    last_module_id: Optional[str] = Field(default=None, max_length=32)
    last_lesson_id: Optional[str] = Field(default=None, max_length=64)
    last_lesson_title: Optional[str] = Field(default=None, max_length=160)
    last_route: Optional[str] = Field(default=None, max_length=256)


class ProfileDeleteRequest(BaseModel):
    confirm_text: str = Field(min_length=3, max_length=64)


class ProfileDeleteResponse(BaseModel):
    ok: bool = True
    deleted: dict[str, int | bool | list[str]]
    utc: str
