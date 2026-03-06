from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class StudentRunnerStageOut(BaseModel):
    key: str
    label: str
    available: bool = True
    completed: bool = False
    active: bool = False


class StudentRunnerLessonOut(BaseModel):
    lesson_id: str
    title: Optional[str] = None
    sequence: Optional[int] = None
    best_score: float = 0.0
    mastery_threshold: float = 0.8
    mastery_achieved: bool = False
    can_advance: bool = False
    lesson_status: str = "not_started"
    next_recommended_action: str = "start_diagnostic"
    stages: List[StudentRunnerStageOut] = Field(default_factory=list)


class StudentRunnerModuleOut(BaseModel):
    module_id: str
    module_mastery: float = 0.0
    lessons_completed_count: int = 0
    total_lessons: int = 0


class StudentRunnerLessonResponse(BaseModel):
    ok: bool = True
    module: StudentRunnerModuleOut
    lesson: StudentRunnerLessonOut
