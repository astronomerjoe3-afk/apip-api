from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


InstitutionMembershipRole = Literal["institution_admin", "teacher", "student"]
AssignmentType = Literal["platform_resource", "custom", "external"]
GradingMode = Literal["auto", "manual", "hybrid"]
DiscussionScope = Literal["public_topic", "institution", "class"]
SubmissionState = Literal["submitted", "graded", "resubmission_requested"]


class InstitutionCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: Optional[str] = Field(default=None, max_length=64)
    committed_student_seats: int = Field(default=100, ge=1, le=100000)
    contract_start_utc: Optional[str] = None
    contract_end_utc: Optional[str] = None
    public_community_enabled: bool = False
    status: str = Field(default="active", max_length=32)


class InstitutionMembershipCreateIn(BaseModel):
    uid: str = Field(min_length=1, max_length=128)
    role: InstitutionMembershipRole
    email: Optional[str] = Field(default=None, max_length=320)
    display_name: Optional[str] = Field(default=None, max_length=120)
    status: str = Field(default="active", max_length=32)


class InstitutionClassCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    term: Optional[str] = Field(default=None, max_length=80)
    teacher_uids: list[str] = Field(default_factory=list)
    student_uids: list[str] = Field(default_factory=list)
    topic_focus: Optional[str] = Field(default=None, max_length=120)
    join_code: Optional[str] = Field(default=None, max_length=24)
    status: str = Field(default="active", max_length=32)


class InstitutionAssignmentCreateIn(BaseModel):
    class_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=3, max_length=140)
    assignment_type: AssignmentType = "platform_resource"
    instructions: str = Field(min_length=3, max_length=4000)
    due_utc: Optional[str] = None
    grading_mode: GradingMode = "manual"
    resource_module_ids: list[str] = Field(default_factory=list)
    resource_titles: list[str] = Field(default_factory=list)
    external_resource_url: Optional[str] = Field(default=None, max_length=500)
    allow_resubmission: bool = True
    status: str = Field(default="published", max_length=32)


class InstitutionSubmissionUpsertIn(BaseModel):
    text_response: Optional[str] = Field(default=None, max_length=8000)
    link_url: Optional[str] = Field(default=None, max_length=500)
    attachment_names: list[str] = Field(default_factory=list)


class InstitutionSubmissionGradeIn(BaseModel):
    score: Optional[float] = Field(default=None, ge=0, le=100)
    feedback: Optional[str] = Field(default=None, max_length=4000)
    status: SubmissionState = "graded"


class InstitutionDiscussionCreateIn(BaseModel):
    scope: DiscussionScope
    title: str = Field(min_length=3, max_length=160)
    body: str = Field(min_length=3, max_length=4000)
    institution_id: Optional[str] = Field(default=None, max_length=128)
    class_id: Optional[str] = Field(default=None, max_length=128)
    module_id: Optional[str] = Field(default=None, max_length=24)
