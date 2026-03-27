from __future__ import annotations

from pydantic import BaseModel, Field


class HelpRequestCreateIn(BaseModel):
    category: str = Field(default="general", min_length=2, max_length=80)
    subject: str = Field(min_length=3, max_length=160)
    message: str = Field(min_length=10, max_length=2000)
    module_id: str | None = Field(default=None, max_length=32)
    module_title: str | None = Field(default=None, max_length=160)
    lesson_id: str | None = Field(default=None, max_length=32)
    lesson_title: str | None = Field(default=None, max_length=160)
    page_path: str | None = Field(default=None, max_length=240)


class HelpRequestSummary(BaseModel):
    id: str
    category: str
    status: str
    subject: str
    message: str
    module_id: str | None = None
    module_title: str | None = None
    lesson_id: str | None = None
    lesson_title: str | None = None
    page_path: str | None = None
    created_utc: str | None = None
    updated_utc: str | None = None
    student_uid: str | None = None
    student_email: str | None = None
    student_role: str | None = None


class HelpRequestCreateResponse(BaseModel):
    ok: bool = True
    request: HelpRequestSummary


class HelpRequestListResponse(BaseModel):
    ok: bool = True
    inquiries: list[HelpRequestSummary] = Field(default_factory=list)
