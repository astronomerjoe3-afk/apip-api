from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class LessonPhaseBlock(BaseModel):
    model_config = {"extra": "allow"}


class LessonPhases(BaseModel):
    analogical_grounding: Optional[Dict[str, Any]] = None
    simulation_inquiry: Optional[Dict[str, Any]] = None
    concept_reconstruction: Optional[Dict[str, Any]] = None
    diagnostic: Optional[Dict[str, Any]] = None
    transfer: Optional[Dict[str, Any]] = None


class LessonOut(BaseModel):
    id: str
    lesson_id: Optional[str] = None
    module_id: Optional[str] = None
    title: Optional[str] = None
    sequence: Optional[int] = None
    updated_utc: Optional[str] = None
    phases: Optional[LessonPhases] = None

    model_config = {"extra": "allow"}


class ModuleOut(BaseModel):
    id: str
    curriculum_id: Optional[str] = None
    title: Optional[str] = None
    sequence: Optional[int] = None
    updated_utc: Optional[str] = None

    model_config = {"extra": "allow"}


class CurriculumOut(BaseModel):
    id: str
    title: Optional[str] = None
    updated_utc: Optional[str] = None

    model_config = {"extra": "allow"}


class SimLabOut(BaseModel):
    id: str

    model_config = {"extra": "allow"}


class CurriculaResponse(BaseModel):
    ok: bool = True
    curricula: List[CurriculumOut]


class ModulesResponse(BaseModel):
    ok: bool = True
    modules: List[ModuleOut]


class ModuleResponse(BaseModel):
    ok: bool = True
    module: ModuleOut


class LessonsResponse(BaseModel):
    ok: bool = True
    lessons: List[LessonOut]
    warnings: List[str] = Field(default_factory=list)


class LessonResponse(BaseModel):
    ok: bool = True
    lesson: LessonOut


class SimLabResponse(BaseModel):
    ok: bool = True
    sim_lab: SimLabOut
