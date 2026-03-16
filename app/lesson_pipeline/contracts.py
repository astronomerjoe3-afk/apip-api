from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class DiagramRequest:
    asset_id: str
    phase_key: str
    concept: str
    description: str
    title: str = ""
    template: str = "auto"
    width: int = 1280
    height: int = 720


@dataclass
class AnimationRequest:
    asset_id: str
    phase_key: str
    concept: str
    description: str
    title: str = ""
    duration_sec: int = 8
    engine: str = "svg_html"


@dataclass
class SimulationRequest:
    asset_id: str
    phase_key: str
    lab_id: str
    concept: str
    description: str
    title: str = ""
    engine: str = "p5"


@dataclass
class LessonAssetRequests:
    diagrams: List[DiagramRequest] = field(default_factory=list)
    animations: List[AnimationRequest] = field(default_factory=list)
    simulation: SimulationRequest | None = None

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "LessonAssetRequests":
        diagrams = [DiagramRequest(**item) for item in payload.get("diagrams") or []]
        animations = [AnimationRequest(**item) for item in payload.get("animations") or []]
        simulation_payload = payload.get("simulation")
        simulation = SimulationRequest(**simulation_payload) if isinstance(simulation_payload, dict) else None
        return cls(diagrams=diagrams, animations=animations, simulation=simulation)


@dataclass
class LessonSpec:
    lesson_id: str
    module_id: str
    title: str
    phases: Dict[str, Any]
    asset_requests: LessonAssetRequests = field(default_factory=LessonAssetRequests)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "LessonSpec":
        return cls(
            lesson_id=str(payload["lesson_id"]),
            module_id=str(payload["module_id"]),
            title=str(payload.get("title") or payload["lesson_id"]),
            phases=dict(payload.get("phases") or {}),
            asset_requests=LessonAssetRequests.from_dict(payload.get("asset_requests") or {}),
        )

    @classmethod
    def load(cls, path: str | Path) -> "LessonSpec":
        raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
        return cls.from_dict(raw)

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


@dataclass
class GeneratedAsset:
    asset_id: str
    kind: str
    phase_key: str
    title: str
    concept: str
    storage_path: str
    public_url: str
    mime_type: str
    provider: str
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CompiledLessonPackage:
    lesson_id: str
    module_id: str
    title: str
    phases: Dict[str, Any]
    generated_assets: Dict[str, Any]
    lesson_patch: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def dump(self, path: str | Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
