from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

try:
    from app.lesson_pipeline.contracts import (
        AnimationRequest,
        DiagramRequest,
        GeneratedAsset,
        LessonSpec,
        SimulationRequest,
    )
    from app.lesson_pipeline.lesson_asset_orchestrator import compile_lesson_assets
except ModuleNotFoundError:
    import sys

    PROJECT_ROOT = Path(__file__).resolve().parents[1]
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from app.lesson_pipeline.contracts import (  # type: ignore[no-redef]
        AnimationRequest,
        DiagramRequest,
        GeneratedAsset,
        LessonSpec,
        SimulationRequest,
    )
    from app.lesson_pipeline.lesson_asset_orchestrator import compile_lesson_assets  # type: ignore[no-redef]


DEFAULT_PUBLIC_BASE = "/lesson_assets"


def default_asset_root() -> Path:
    repo_root = Path(__file__).resolve().parents[1]
    sibling_web_public = repo_root.parent / "apip-web" / "public" / "lesson_assets"
    if sibling_web_public.parent.exists():
        return sibling_web_public
    return repo_root / "lesson_assets"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _record(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _slug(value: Any) -> str:
    raw = _text(value)
    collapsed = re.sub(r"[^a-z0-9]+", "_", raw.lower()).strip("_")
    return collapsed or "lesson_asset"


def _phase_key_from_asset(asset: Dict[str, Any]) -> str:
    return _text(asset.get("phase_key")) or "analogical_grounding"


def _diagram_requests(lesson: Dict[str, Any]) -> List[DiagramRequest]:
    authoring = _record(lesson.get("authoring_contract"))
    requests: List[DiagramRequest] = []
    for index, asset in enumerate(_items(authoring.get("visual_assets")), start=1):
        item = _record(asset)
        asset_id = _text(item.get("asset_id")) or f"{_slug(lesson.get('lesson_id'))}_diagram_{index}"
        title = _text(item.get("title")) or _text(item.get("caption")) or _text(lesson.get("title")) or asset_id
        description = _text(item.get("purpose")) or _text(item.get("caption")) or title
        requests.append(
            DiagramRequest(
                asset_id=asset_id,
                phase_key=_phase_key_from_asset(item),
                concept=_text(item.get("concept")) or _slug(asset_id),
                description=description,
                title=title,
                template=_text(item.get("template")) or "auto",
                width=int(item.get("width") or 1280),
                height=int(item.get("height") or 720),
            )
        )
    return requests


def _animation_requests(lesson: Dict[str, Any]) -> List[AnimationRequest]:
    authoring = _record(lesson.get("authoring_contract"))
    requests: List[AnimationRequest] = []
    for index, asset in enumerate(_items(authoring.get("animation_assets")), start=1):
        item = _record(asset)
        asset_id = _text(item.get("asset_id")) or f"{_slug(lesson.get('lesson_id'))}_animation_{index}"
        title = _text(item.get("title")) or _text(item.get("caption")) or _text(lesson.get("title")) or asset_id
        description = _text(item.get("description")) or _text(item.get("purpose")) or _text(item.get("caption")) or title
        requests.append(
            AnimationRequest(
                asset_id=asset_id,
                phase_key=_phase_key_from_asset(item),
                concept=_text(item.get("concept")) or _slug(asset_id),
                description=description,
                title=title,
                duration_sec=int(item.get("duration_sec") or 8),
                engine=_text(item.get("engine")) or "svg_html",
            )
        )
    return requests


def _simulation_request(lesson: Dict[str, Any], sim_lab: Dict[str, Any] | None) -> SimulationRequest | None:
    phases = _record(lesson.get("phases"))
    simulation_phase = _record(phases.get("simulation_inquiry"))
    authoring = _record(lesson.get("authoring_contract"))
    simulation_contract = _record(authoring.get("simulation_contract"))
    sim = _record(sim_lab)

    lab_id = _text(simulation_phase.get("lab_id")) or _text(sim.get("lab_id"))
    if not lab_id:
        return None

    title = (
        _text(sim.get("title"))
        or _text(simulation_contract.get("title"))
        or f"{_text(lesson.get('title'))} Lab"
    )
    description = (
        _text(sim.get("description"))
        or _text(simulation_contract.get("takeaway"))
        or _text(simulation_contract.get("baseline_case"))
        or f"Interactive lab for {_text(lesson.get('title'))}"
    )
    asset_id = _text(simulation_contract.get("asset_id")) or f"{_slug(lesson.get('lesson_id'))}_simulation"
    concept = _text(sim.get("concept")) or _text(simulation_contract.get("concept")) or _slug(lab_id)

    return SimulationRequest(
        asset_id=asset_id,
        phase_key="simulation_inquiry",
        lab_id=lab_id,
        concept=concept,
        description=description,
        title=title,
        engine=_text(sim.get("engine")) or _text(simulation_contract.get("engine")) or "p5",
    )


def build_lesson_asset_spec(lesson: Dict[str, Any], sim_lab: Dict[str, Any] | None = None) -> LessonSpec:
    return LessonSpec.from_dict(
        {
            "lesson_id": _text(lesson.get("lesson_id") or lesson.get("id")),
            "module_id": _text(lesson.get("module_id")),
            "title": _text(lesson.get("title")),
            "phases": deepcopy(_record(lesson.get("phases"))),
            "asset_requests": {
                "diagrams": [vars(req) for req in _diagram_requests(lesson)],
                "animations": [vars(req) for req in _animation_requests(lesson)],
                "simulation": vars(req) if (req := _simulation_request(lesson, sim_lab)) else None,
            },
        }
    )


def _predicted_storage_path(asset_root: str | Path | None, relative_path: str) -> str:
    if asset_root is None:
        return ""
    return str(Path(asset_root) / Path(relative_path))


def _generated_asset_from_request(
    kind: str,
    lesson: Dict[str, Any],
    public_base: str,
    relative_path: str,
    asset_root: str | Path | None,
    *,
    asset_id: str,
    phase_key: str,
    title: str,
    concept: str,
    mime_type: str,
    provider: str,
    meta: Dict[str, Any],
) -> GeneratedAsset:
    module_id = _text(lesson.get("module_id"))
    lesson_id = _text(lesson.get("lesson_id") or lesson.get("id"))
    return GeneratedAsset(
        asset_id=asset_id,
        kind=kind,
        phase_key=phase_key,
        title=title,
        concept=concept,
        storage_path=_predicted_storage_path(asset_root, relative_path),
        public_url=f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/{relative_path.replace('\\', '/')}",
        mime_type=mime_type,
        provider=provider,
        meta=meta,
    )


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


def plan_lesson_assets(
    lesson: Dict[str, Any],
    sim_lab: Dict[str, Any] | None = None,
    *,
    public_base: str = DEFAULT_PUBLIC_BASE,
    asset_root: str | Path | None = None,
) -> Dict[str, Any]:
    spec = build_lesson_asset_spec(lesson, sim_lab)
    phases_patch = deepcopy(spec.phases)

    generated_diagrams = [
        _generated_asset_from_request(
            "diagram",
            lesson,
            public_base,
            f"diagrams/{request.asset_id}.svg",
            asset_root,
            asset_id=request.asset_id,
            phase_key=request.phase_key,
            title=request.title or request.concept,
            concept=request.concept,
            mime_type="image/svg+xml",
            provider="local_svg_template",
            meta={
                "width": request.width,
                "height": request.height,
                "description": request.description,
                "template": request.template,
            },
        )
        for request in _diagram_requests(lesson)
    ]

    generated_animations = [
        _generated_asset_from_request(
            "animation",
            lesson,
            public_base,
            f"animations/{request.asset_id}.html",
            asset_root,
            asset_id=request.asset_id,
            phase_key=request.phase_key,
            title=request.title or request.concept,
            concept=request.concept,
            mime_type="text/html",
            provider="local_svg_html_animation",
            meta={
                "duration_sec": request.duration_sec,
                "description": request.description,
                "engine": request.engine,
            },
        )
        for request in _animation_requests(lesson)
    ]

    simulation_request = _simulation_request(lesson, sim_lab)
    generated_simulation = (
        _generated_asset_from_request(
            "simulation",
            lesson,
            public_base,
            f"simulations/{simulation_request.lab_id}/index.html",
            asset_root,
            asset_id=simulation_request.asset_id,
            phase_key=simulation_request.phase_key,
            title=simulation_request.title or simulation_request.concept,
            concept=simulation_request.concept,
            mime_type="text/html",
            provider="local_p5_lab",
            meta={
                "lab_id": simulation_request.lab_id,
                "description": simulation_request.description,
                "engine": simulation_request.engine,
            },
        )
        if simulation_request
        else None
    )

    for asset in generated_diagrams:
        _append_phase_asset(phases_patch, asset.phase_key, asset)

    for asset in generated_animations:
        _append_phase_asset(phases_patch, asset.phase_key, asset)

    if generated_simulation:
        _set_phase_simulation(phases_patch, generated_simulation.phase_key, generated_simulation)

    generated_assets = {
        "diagrams": [asset.to_dict() for asset in generated_diagrams],
        "animations": [asset.to_dict() for asset in generated_animations],
        "simulation": generated_simulation.to_dict() if generated_simulation else None,
    }

    return {
        "lesson_id": spec.lesson_id,
        "module_id": spec.module_id,
        "title": spec.title,
        "phases": phases_patch,
        "generated_assets": generated_assets,
        "lesson_patch": {
            "lesson_id": spec.lesson_id,
            "module_id": spec.module_id,
            "title": spec.title,
            "phases": phases_patch,
        },
    }


def apply_planned_assets(
    lesson: Dict[str, Any],
    sim_lab: Dict[str, Any] | None = None,
    *,
    public_base: str = DEFAULT_PUBLIC_BASE,
) -> Dict[str, Any]:
    compiled = plan_lesson_assets(lesson, sim_lab, public_base=public_base)
    lesson["phases"] = deepcopy(compiled["phases"])
    lesson["generated_assets"] = deepcopy(compiled["generated_assets"])
    if sim_lab is not None and compiled["generated_assets"].get("simulation"):
        sim_lab.setdefault("generated_assets", {})
        sim_lab["generated_assets"]["compiled_lab"] = deepcopy(compiled["generated_assets"]["simulation"])
    return compiled


def render_lesson_assets(
    lesson: Dict[str, Any],
    sim_lab: Dict[str, Any] | None = None,
    *,
    asset_root: str | Path | None = None,
    public_base: str = DEFAULT_PUBLIC_BASE,
) -> Dict[str, Any]:
    root = Path(asset_root) if asset_root is not None else default_asset_root()
    compiled = compile_lesson_assets(
        spec=build_lesson_asset_spec(lesson, sim_lab),
        asset_root=root,
        public_base=public_base,
    )
    compiled_payload = compiled.to_dict()
    lesson["phases"] = deepcopy(compiled_payload["phases"])
    lesson["generated_assets"] = deepcopy(compiled_payload["generated_assets"])
    if sim_lab is not None and compiled_payload["generated_assets"].get("simulation"):
        sim_lab.setdefault("generated_assets", {})
        sim_lab["generated_assets"]["compiled_lab"] = deepcopy(compiled_payload["generated_assets"]["simulation"])
    return compiled_payload


def _normalize_pair_sequence(
    lesson_pairs: Sequence[Tuple[str, Dict[str, Any]]],
    sim_pairs: Sequence[Tuple[str, Dict[str, Any]]],
) -> None:
    if len(lesson_pairs) != len(sim_pairs):
        raise ValueError("Each lesson must have one corresponding simulation document.")


def plan_module_assets(
    lesson_pairs: Sequence[Tuple[str, Dict[str, Any]]],
    sim_pairs: Sequence[Tuple[str, Dict[str, Any]]],
    *,
    public_base: str = DEFAULT_PUBLIC_BASE,
) -> List[Dict[str, Any]]:
    _normalize_pair_sequence(lesson_pairs, sim_pairs)
    return [
        apply_planned_assets(lesson_payload, sim_payload, public_base=public_base)
        for (_, lesson_payload), (_, sim_payload) in zip(lesson_pairs, sim_pairs)
    ]


def render_module_assets(
    lesson_pairs: Sequence[Tuple[str, Dict[str, Any]]],
    sim_pairs: Sequence[Tuple[str, Dict[str, Any]]],
    *,
    asset_root: str | Path | None = None,
    public_base: str = DEFAULT_PUBLIC_BASE,
) -> List[Dict[str, Any]]:
    _normalize_pair_sequence(lesson_pairs, sim_pairs)
    return [
        render_lesson_assets(
            lesson_payload,
            sim_payload,
            asset_root=asset_root,
            public_base=public_base,
        )
        for (_, lesson_payload), (_, sim_payload) in zip(lesson_pairs, sim_pairs)
    ]
