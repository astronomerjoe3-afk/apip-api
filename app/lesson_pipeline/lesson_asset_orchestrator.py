from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict, List

from app.agents.animation_agent import generate_animation
from app.agents.diagram_agent import generate_diagram
from app.agents.simulation_agent import generate_simulation
from app.lesson_pipeline.contracts import CompiledLessonPackage, GeneratedAsset, LessonSpec


def _ensure_phase(phases: Dict[str, Any], phase_key: str) -> Dict[str, Any]:
    phase = phases.get(phase_key)
    if isinstance(phase, dict):
        return phase
    phases[phase_key] = {}
    return phases[phase_key]


def _append_phase_asset(phases: Dict[str, Any], phase_key: str, asset: GeneratedAsset) -> None:
    phase = _ensure_phase(phases, phase_key)
    assets = phase.get("assets")
    if not isinstance(assets, list):
        assets = []
        phase["assets"] = assets
    assets.append(
        {
            "asset_id": asset.asset_id,
            "kind": asset.kind,
            "title": asset.title,
            "concept": asset.concept,
            "url": asset.public_url,
            "mime_type": asset.mime_type,
            "provider": asset.provider,
            "meta": asset.meta,
        }
    )


def _set_phase_simulation(phases: Dict[str, Any], phase_key: str, asset: GeneratedAsset) -> None:
    phase = _ensure_phase(phases, phase_key)
    phase["generated_lab"] = {
        "asset_id": asset.asset_id,
        "kind": asset.kind,
        "title": asset.title,
        "concept": asset.concept,
        "url": asset.public_url,
        "mime_type": asset.mime_type,
        "provider": asset.provider,
        "meta": asset.meta,
    }


def compile_lesson_assets(
    spec: LessonSpec,
    asset_root: str | Path,
    public_base: str = "/lesson_assets",
) -> CompiledLessonPackage:
    root = Path(asset_root)
    lesson_root = root / spec.module_id / spec.lesson_id

    diagrams_dir = lesson_root / "diagrams"
    animations_dir = lesson_root / "animations"
    simulations_dir = lesson_root / "simulations"

    generated_diagrams: List[GeneratedAsset] = []
    generated_animations: List[GeneratedAsset] = []
    generated_simulation: GeneratedAsset | None = None

    for req in spec.asset_requests.diagrams:
        generated_diagrams.append(
            generate_diagram(
                req=req,
                output_dir=diagrams_dir,
                public_base=public_base,
                module_id=spec.module_id,
                lesson_id=spec.lesson_id,
            )
        )

    for req in spec.asset_requests.animations:
        generated_animations.append(
            generate_animation(
                req=req,
                output_dir=animations_dir,
                public_base=public_base,
                module_id=spec.module_id,
                lesson_id=spec.lesson_id,
            )
        )

    if spec.asset_requests.simulation:
        req = spec.asset_requests.simulation
        generated_simulation = generate_simulation(
            req=req,
            output_dir=simulations_dir / req.lab_id,
            public_base=public_base,
            module_id=spec.module_id,
            lesson_id=spec.lesson_id,
        )

    phases_patch = copy.deepcopy(spec.phases)

    for asset in generated_diagrams:
        _append_phase_asset(phases_patch, asset.phase_key, asset)

    for asset in generated_animations:
        _append_phase_asset(phases_patch, asset.phase_key, asset)

    if generated_simulation:
        _set_phase_simulation(phases_patch, generated_simulation.phase_key, generated_simulation)

    generated_assets: Dict[str, Any] = {
        "diagrams": [asset.to_dict() for asset in generated_diagrams],
        "animations": [asset.to_dict() for asset in generated_animations],
        "simulation": generated_simulation.to_dict() if generated_simulation else None,
    }

    lesson_patch = {
        "lesson_id": spec.lesson_id,
        "module_id": spec.module_id,
        "title": spec.title,
        "phases": phases_patch,
    }

    return CompiledLessonPackage(
        lesson_id=spec.lesson_id,
        module_id=spec.module_id,
        title=spec.title,
        phases=phases_patch,
        generated_assets=generated_assets,
        lesson_patch=lesson_patch,
    )
