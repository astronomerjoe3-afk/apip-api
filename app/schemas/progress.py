from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ProgressEventIn(BaseModel):
    event_type: str
    duration_seconds: Optional[int] = 0
    score: Optional[float] = None
    confidence: Optional[float] = None
    conflict_level: Optional[float] = None
    sim_depth: Optional[int] = None
    misconception_tags: Optional[List[str] | str] = None
    outcome: Optional[str] = None
    details: Optional[Dict[str, Any] | Any] = None


class MasteryOut(BaseModel):
    score: float
    level: str
    updated_utc: str


class ReadinessOut(BaseModel):
    state: str
    reason: str
    updated_utc: str


class ProgressEventWriteResponse(BaseModel):
    ok: bool = True
    utc: str
    event_id: str
    module_id: str
    stored_event: bool
    mastery: MasteryOut
    readiness: ReadinessOut
    misconception_profile: Dict[str, Any]


class MasteryMapItem(BaseModel):
    module_id: Optional[str] = None
    mastery_score: Optional[float] = 0.0
    readiness: Optional[str] = "not_ready"
    engagement_seconds: Optional[int] = 0
    last_event_utc: Optional[str] = None


class ReviewQueueItemOut(BaseModel):
    module_id: str
    lesson_id: str
    title: Optional[str] = None
    route: str
    review_due: bool = False
    review_state: str = "scheduled"
    review_due_utc: Optional[str] = None
    review_count: int = 0
    last_score: Optional[float] = None
    misconception_tags: List[str] = Field(default_factory=list)
    misconception_summaries: List[Dict[str, str]] = Field(default_factory=list)


class MisconceptionSummaryOut(BaseModel):
    tag: str
    title: str
    diagnosis: str
    repair: str
    notice_next: str


class ProgressMeResponse(BaseModel):
    ok: bool = True
    utc: str
    uid: str
    role: Optional[str] = None
    warnings: List[str] = Field(default_factory=list)
    mastery_map: List[Dict[str, Any]] = Field(default_factory=list)
    modules: List[Dict[str, Any]] = Field(default_factory=list)
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)
    review_due_count: int = 0
    next_review_utc: Optional[str] = None
    review_queue: List[ReviewQueueItemOut] = Field(default_factory=list)
    top_misconception_tags: List[str] = Field(default_factory=list)
    top_misconception_summaries: List[MisconceptionSummaryOut] = Field(default_factory=list)
