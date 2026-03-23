from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


ParticleVisualType = Literal[
    "standard_model_overview",
    "hadron_composition",
    "decay_chain",
    "collision_event",
]


@dataclass
class ParticlePhysicsSpec:
    visual_type: ParticleVisualType
    title: str = ""
    subtitle: str = ""
    hadron_type: str = "proton"
    parent_particle: str = "n"
    decay_products: list[str] | None = None


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> ParticlePhysicsSpec:
    meta = _get_meta(req)
    visual_type = str(meta.get("visual_type") or "standard_model_overview").strip().lower()

    if visual_type not in {
        "standard_model_overview",
        "hadron_composition",
        "decay_chain",
        "collision_event",
    }:
        raise ValueError(
            "Invalid visual_type. Use one of: standard_model_overview, hadron_composition, decay_chain, collision_event."
        )

    decay_products = meta.get("decay_products") or ["p", "e⁻", "ν̄e"]
    if not isinstance(decay_products, list):
        decay_products = ["p", "e⁻", "ν̄e"]

    return ParticlePhysicsSpec(
        visual_type=visual_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        hadron_type=str(meta.get("hadron_type") or "proton").strip().lower(),
        parent_particle=str(meta.get("parent_particle") or "n"),
        decay_products=[str(x) for x in decay_products[:5]],
    )


def _text(
    x: float,
    y: float,
    value: str,
    *,
    fill: str = "white",
    size: int = 18,
    anchor: str = "middle",
    weight: str = "normal",
) -> str:
    return (
        f'<text x="{x:.2f}" y="{y:.2f}" fill="{fill}" text-anchor="{anchor}" '
        f'font-size="{size}" font-family="Arial" font-weight="{weight}">{escape(value)}</text>'
    )


def _rect(
    x: float,
    y: float,
    width: float,
    height: float,
    *,
    fill: str,
    stroke: str = "none",
    stroke_width: int = 0,
    rx: float = 14,
) -> str:
    return (
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" height="{height:.2f}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" rx="{rx:.2f}" />'
    )


def _circle(
    x: float,
    y: float,
    r: float,
    *,
    fill: str,
    stroke: str = "none",
    stroke_width: int = 0,
) -> str:
    return (
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}" />'
    )


def _line(
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    *,
    stroke: str = "#38bdf8",
    stroke_width: int = 4,
    marker_end: bool = False,
) -> str:
    marker = ' marker-end="url(#pp-arrow)"' if marker_end else ""
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}"{marker} />'
    )


def _svg_open(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="pp-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#38bdf8" />
    </marker>
  </defs>
  <rect width="100%" height="100%" fill="#0b1020" />
"""


def _svg_close() -> str:
    return "</svg>"


def _standard_model_svg(spec: ParticlePhysicsSpec, width: int, height: int) -> str:
    parts = [
        _text(width / 2, 70, spec.title or "Standard Model Overview", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    groups = [
        ("Quarks", ["up", "down", "charm", "strange", "top", "bottom"], "#1d4ed8", 120),
        ("Leptons", ["electron", "muon", "tau", "νe", "νμ", "ντ"], "#7c3aed", 420),
        ("Gauge Bosons", ["photon", "gluon", "W⁺", "W⁻", "Z⁰"], "#0f766e", 720),
        ("Higgs", ["Higgs boson"], "#dc2626", 1020),
    ]

    for title, items, color, x in groups:
        h = 80 + len(items) * 42
        parts.append(_rect(x, 170, 180, h, fill="#111827", stroke=color, stroke_width=3, rx=18))
        parts.append(_text(x + 90, 205, title, size=22, weight="bold"))
        for idx, item in enumerate(items):
            parts.append(_text(x + 90, 250 + idx * 34, item, size=18, fill="#e2e8f0"))

    return "".join(parts)


def _hadron_svg(spec: ParticlePhysicsSpec, width: int, height: int) -> str:
    hadron = "Proton" if spec.hadron_type == "proton" else "Neutron"
    quarks = ["u", "u", "d"] if spec.hadron_type == "proton" else ["u", "d", "d"]

    cx = width / 2
    cy = height / 2 + 30
    positions = [(cx - 70, cy + 20), (cx + 70, cy + 20), (cx, cy - 80)]
    colors = {"u": "#38bdf8", "d": "#f97316"}

    parts = [
        _text(width / 2, 70, spec.title or f"{hadron} Composition", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_circle(cx, cy, 150, fill="#111827", stroke="#a78bfa", stroke_width=4))
    parts.append(_text(cx, cy + 185, hadron, size=24, fill="#ddd6fe", weight="bold"))

    for (x, y), q in zip(positions, quarks):
        parts.append(_circle(x, y, 38, fill=colors[q], stroke="#e2e8f0", stroke_width=2))
        parts.append(_text(x, y + 10, q, size=28, weight="bold"))

    parts.append(_line(positions[0][0], positions[0][1], positions[2][0], positions[2][1], stroke="#22c55e", stroke_width=5))
    parts.append(_line(positions[1][0], positions[1][1], positions[2][0], positions[2][1], stroke="#22c55e", stroke_width=5))
    parts.append(_line(positions[0][0], positions[0][1], positions[1][0], positions[1][1], stroke="#22c55e", stroke_width=5))
    parts.append(_text(cx, cy + 230, "Three valence quarks bound by the strong interaction", fill="#bbf7d0", size=18))

    return "".join(parts)


def _decay_chain_svg(spec: ParticlePhysicsSpec, width: int, height: int) -> str:
    parts = [
        _text(width / 2, 70, spec.title or "Particle Decay", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    box_y = 260
    parent_x = 170
    parts.append(_rect(parent_x, box_y, 160, 80, fill="#1d4ed8", stroke="#93c5fd", stroke_width=2, rx=18))
    parts.append(_text(parent_x + 80, box_y + 48, spec.parent_particle, size=32, weight="bold"))

    x = 430
    for idx, product in enumerate(spec.decay_products or []):
        parts.append(_line(parent_x + 160 + idx * 170, box_y + 40, x - 20, box_y + 40, marker_end=True))
        parts.append(_rect(x, box_y, 140, 80, fill="#111827", stroke="#38bdf8", stroke_width=2, rx=18))
        parts.append(_text(x + 70, box_y + 48, product, size=26, weight="bold"))
        x += 180

    return "".join(parts)


def _collision_event_svg(spec: ParticlePhysicsSpec, width: int, height: int) -> str:
    cx = width / 2
    cy = height / 2 + 20

    parts = [
        _text(width / 2, 70, spec.title or "Particle Collision Event", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_line(180, cy, cx, cy, stroke="#38bdf8", stroke_width=5))
    parts.append(_line(width - 180, cy, cx, cy, stroke="#38bdf8", stroke_width=5))
    parts.append(_circle(cx, cy, 12, fill="#facc15"))
    parts.append(_text(cx, cy - 30, "collision", fill="#fde68a", size=18))

    parts.append(_line(cx, cy, cx - 180, cy - 140, stroke="#22c55e", stroke_width=5, marker_end=True))
    parts.append(_line(cx, cy, cx + 200, cy - 120, stroke="#f97316", stroke_width=5, marker_end=True))
    parts.append(_line(cx, cy, cx + 120, cy + 160, stroke="#a78bfa", stroke_width=5, marker_end=True))

    parts.append(_text(cx - 200, cy - 155, "outgoing particle 1", fill="#bbf7d0", size=16))
    parts.append(_text(cx + 220, cy - 135, "outgoing particle 2", fill="#fdba74", size=16))
    parts.append(_text(cx + 145, cy + 185, "outgoing particle 3", fill="#ddd6fe", size=16))

    return "".join(parts)


def generate_particle_physics_visual(
    req: DiagramRequest,
    output_dir: str | Path,
    public_base: str,
    module_id: str,
    lesson_id: str,
) -> GeneratedAsset:
    spec = _parse_spec(req)
    width = int(getattr(req, "width", 1280) or 1280)
    height = int(getattr(req, "height", 720) or 720)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    parts = [_svg_open(width, height)]
    if spec.visual_type == "standard_model_overview":
        parts.append(_standard_model_svg(spec, width, height))
    elif spec.visual_type == "hadron_composition":
        parts.append(_hadron_svg(spec, width, height))
    elif spec.visual_type == "decay_chain":
        parts.append(_decay_chain_svg(spec, width, height))
    else:
        parts.append(_collision_event_svg(spec, width, height))
    parts.append(_svg_close())

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text("".join(parts), encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Particle Physics Visual",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="particle_physics_visual_agent",
        meta={
            "visual_type": spec.visual_type,
            "hadron_type": spec.hadron_type,
            "parent_particle": spec.parent_particle,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
