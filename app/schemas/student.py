from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class StudentQuestionItem(BaseModel):
    id: Optional[str] = None
    type: Optional[str] = None
    prompt: Optional[str] = None
    choices: List[str] = Field(default_factory=list)
    hint: Optional[str] = None
    feedback: List[str] = Field(default_factory=list)
    answer_index: Optional[int] = None
    accepted_answers: List[str] = Field(default_factory=list)
    acceptance_rules: Dict[str, Any] = Field(default_factory=dict)
    skill_tags: List[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StudentAuthoringContractOut(BaseModel):
    core_concepts: List[str] = Field(default_factory=list)
    worked_examples: List[Dict[str, Any]] = Field(default_factory=list)
    visual_assets: List[Dict[str, Any]] = Field(default_factory=list)
    animation_assets: List[Dict[str, Any]] = Field(default_factory=list)
    simulation_contract: Dict[str, Any] = Field(default_factory=dict)
    assessment_bank_targets: Dict[str, Any] = Field(default_factory=dict)
    scaffold_support: Dict[str, Any] = Field(default_factory=dict)
    visual_clarity_checks: List[str] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StudentPromptBlock(BaseModel):
    prompt: Optional[str] = None
    hint: Optional[str] = None

    model_config = {"extra": "ignore"}


class StudentConceptCapsule(BaseModel):
    prompt: Optional[str] = None
    checks: List[StudentQuestionItem] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StudentAnalogicalGrounding(BaseModel):
    analogy_text: Optional[str] = None
    micro_prompts: List[StudentPromptBlock] = Field(default_factory=list)

    model_config = {"extra": "ignore"}


class StudentSimulationInquiry(BaseModel):
    inquiry_prompts: List[StudentPromptBlock] = Field(default_factory=list)
    lab_id: Optional[str] = None

    model_config = {"extra": "ignore"}


class StudentConceptReconstruction(BaseModel):
    prompts: List[str] = Field(default_factory=list)
    capsules: List[StudentConceptCapsule] = Field(default_factory=list)

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
    authoring_contract: StudentAuthoringContractOut = Field(default_factory=StudentAuthoringContractOut)

    model_config = {"extra": "ignore"}


class StudentLessonsResponse(BaseModel):
    ok: bool = True
    lessons: List[StudentLessonOut] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class StudentLessonResponse(BaseModel):
    ok: bool = True
    lesson: StudentLessonOut
