from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class StudentQuestionItem(BaseModel):
    type: Optional[str] = None
    prompt: Optional[str] = None
    choices: Optional[List[str]] = None

    model_config = {"extra": "ignore"}


class StudentAnalogicalGrounding(BaseModel):
    analogy_text: Optional[str] = None

    model_config = {"extra": "ignore"}


class StudentSimulationInquiry(BaseModel):
    inquiry_prompts: List[str] = Field(default_factory=list)
    lab_id: Optional[str] = None

    model_config = {"extra": "ignore"}


class StudentConceptReconstruction(BaseModel):
    prompts: List[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StudentDiagnostic(BaseModel):
    items: List[StudentQuestionItem] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StudentTransfer(BaseModel):
    items: List[StudentQuestionItem] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StudentLessonPhases(BaseModel):
    analogical_grounding: StudentAnalogicalGrounding = Field(default_factory=StudentAnalogicalGrounding)
    simulation_inquiry: StudentSimulationInquiry = Field(default_factory=StudentSimulationInquiry)
    concept_reconstruction: StudentConceptReconstruction = Field(default_factory=StudentConceptReconstruction)
    diagnostic: StudentDiagnostic = Field(default_factory=StudentDiagnostic)
    transfer: StudentTransfer = Field(default_factory=StudentTransfer)

    model_config = {"extra": "ignore"}


class StudentLessonOut(BaseModel):
    lesson_id: Optional[str] = None
    title: Optional[str] = None
    sequence: Optional[int] = None
    phases: StudentLessonPhases = Field(default_factory=StudentLessonPhases)

    model_config = {"extra": "ignore"}


class StudentLessonsResponse(BaseModel):
    ok: bool = True
    lessons: List[StudentLessonOut] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class StudentLessonResponse(BaseModel):
    ok: bool = True
    lesson: StudentLessonOut
