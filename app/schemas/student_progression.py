from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class StudentLessonProgressOut(BaseModel):
    lesson_id: str
    title: Optional[str] = None
    sequence: Optional[int] = None
    best_score: float = 0.0
    latest_score: Optional[float] = None
    attempt_count: int = 0
    completed: bool = False
    can_advance: bool = False
    instructional_can_advance: bool = False
    lab_available: bool = False
    lab_used: bool = False
    status: str = "not_started"
    instructional_status: Optional[str] = "not_started"
    misconception_tags: List[str] = Field(default_factory=list)
    review_due: bool = False
    review_state: str = "not_started"
    review_due_utc: Optional[str] = None
    review_interval_days: Optional[int] = None
    review_count: int = 0
    last_review_score: Optional[float] = None


class StudentModuleProgressOut(BaseModel):
    module_id: str
    module_mastery: float = 0.0
    lessons_completed_count: int = 0
    total_lessons: int = 0
    review_due_count: int = 0
    next_review_utc: Optional[str] = None
    top_misconception_tags: List[str] = Field(default_factory=list)


class StudentLessonProgressResponse(BaseModel):
    ok: bool = True
    module: StudentModuleProgressOut
    lesson: StudentLessonProgressOut


class StudentModuleProgressResponse(BaseModel):
    ok: bool = True
    module: StudentModuleProgressOut
    lessons: List[StudentLessonProgressOut] = Field(default_factory=list)
