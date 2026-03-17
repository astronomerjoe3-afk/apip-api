from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class StudentRunnerStageOut(BaseModel):
    key: str
    label: str
    available: bool = True
    completed: bool = False
    active: bool = False


class StudentRunnerDiagnosticOut(BaseModel):
    min_questions: int = 2
    max_questions: int = 5
    target_question_count: int = 2
    completed: bool = False
    asked_count: int = 0
    latest_score: Optional[float] = None


class StudentRunnerMasteryCheckOut(BaseModel):
    min_questions: int = 5
    max_questions: int = 10
    selected_question_count: int = 0
    threshold: float = 0.8
    attempt_count: int = 0
    best_score: float = 0.0
    latest_score: Optional[float] = None
    required_correct: int = 0
    eligible_for_immediate_retest: bool = False
    review_required: bool = False
    review_recommended: bool = False
    weak_concepts: List[str] = Field(default_factory=list)
    recommended_review_refs: List[str] = Field(default_factory=list)


class StudentRunnerLessonOut(BaseModel):
    lesson_id: str
    title: Optional[str] = None
    sequence: Optional[int] = None
    best_score: float = 0.0
    latest_score: Optional[float] = None
    mastery_threshold: float = 0.8
    mastery_achieved: bool = False
    can_advance: bool = False
    instructional_can_advance: bool = False
    lesson_status: str = "not_started"
    instructional_status: Optional[str] = "not_started"
    active_stage: str = "diagnostic"
    instructional_active_stage: Optional[str] = "diagnostic"
    next_recommended_action: str = "start_diagnostic"
    diagnostic: StudentRunnerDiagnosticOut = Field(default_factory=StudentRunnerDiagnosticOut)
    mastery_check: StudentRunnerMasteryCheckOut = Field(default_factory=StudentRunnerMasteryCheckOut)
    stages: List[StudentRunnerStageOut] = Field(default_factory=list)
    instructional_stages: List[StudentRunnerStageOut] = Field(default_factory=list)


class StudentRunnerModuleOut(BaseModel):
    module_id: str
    module_mastery: float = 0.0
    lessons_completed_count: int = 0
    total_lessons: int = 0


class StudentRunnerLessonResponse(BaseModel):
    ok: bool = True
    module: StudentRunnerModuleOut
    lesson: StudentRunnerLessonOut
