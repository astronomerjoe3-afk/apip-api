from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


QuantumVisualType = Literal[
    "energy_levels",
    "tunneling_barrier",
    "probability_density",
    "double_slit_pattern",
]


@dataclass
class QuantumPhysicsSpec:
    visual_type: QuantumVisualType
    title: str = ""
    subtitle: str = ""
    level_count: int = 4


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> QuantumPhysicsSpec:
    meta = _get_meta(req)
    visual_type = str(meta.get("visual_type") or "energy_levels").strip().lower()

    if visual_type not in {
        "energy_levels",
        "tunneling_barrier",
        "probability_density",
        "double_slit_pattern",
    }:
        raise ValueError(
            "Invalid visual_type. Use one of: energy_levels, tunneling_barrier, probability_density, double_slit_pattern."
        )

    try:
        level_count = int(meta.get("level_count", 4))
    except Exception:
        level_count = 4

    return QuantumPhysicsSpec(
        visual_type=visual_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        level_count=max(2, min(6, level_count)),
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
    rx: float = 12,
) -> str:
    return (
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" height="{height:.2f}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" rx="{rx:.2f}" />'
    )


def _line(
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    *,
    stroke: str = "#38bdf8",
    stroke_width: int = 4,
    dashed: bool = False,
    marker_end: bool = False,
) -> str:
    dash = ' stroke-dasharray="10 8"' if dashed else ""
    marker = ' marker-end="url(#q-arrow)"' if marker_end else ""
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}"{dash}{marker} />'
    )


def _circle(
    x: float,
    y: float,
    r: float,
    *,
    fill: str,
    stroke: str = "none",
    stroke_width: int = 0,
    fill_opacity: float | None = None,
) -> str:
    opacity = f' fill-opacity="{fill_opacity:.2f}"' if fill_opacity is not None else ""
    return (
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}"{opacity} />'
    )


def _polyline(points: list[tuple[float, float]], *, stroke: str, stroke_width: int = 4) -> str:
    pts = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    return f'<polyline points="{pts}" fill="none" stroke="{stroke}" stroke-width="{stroke_width}" />'


def _svg_open(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="q-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#facc15" />
    </marker>
  </defs>
  <rect width="100%" height="100%" fill="#0b1020" />
"""


def _svg_close() -> str:
    return "</svg>"


def _energy_levels_svg(spec: QuantumPhysicsSpec, width: int, height: int) -> str:
    left = 320
    right = width - 260
    top = 180
    spacing = 78

    parts = [
        _text(width / 2, 70, spec.title or "Quantized Energy Levels", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_line(left, top - 40, left, top + spacing * (spec.level_count - 1) + 40, stroke="#64748b", stroke_width=3))
    parts.append(_text(left - 36, top - 54, "Energy", fill="#94a3b8", size=18))

    ys: list[float] = []
    for i in range(spec.level_count):
        y = top + i * spacing
        ys.append(y)
        parts.append(_line(left, y, right, y, stroke="#38bdf8", stroke_width=4))
        parts.append(_text(left - 30, y + 6, f"n={spec.level_count - i}", fill="#bae6fd", size=18, anchor="end"))

    if len(ys) >= 2:
        parts.append(_line(right - 120, ys[-1], right - 120, ys[0], stroke="#facc15", stroke_width=4, marker_end=True))
        parts.append(_text(right - 86, (ys[-1] + ys[0]) / 2, "photon absorbed", fill="#fde68a", size=18, anchor="start"))

    return "".join(parts)


def _tunneling_svg(spec: QuantumPhysicsSpec, width: int, height: int) -> str:
    base_y = height / 2 + 70
    parts = [
        _text(width / 2, 70, spec.title or "Quantum Tunneling", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_line(120, base_y, width - 120, base_y, stroke="#64748b", stroke_width=3))
    parts.append(_rect(520, base_y - 180, 200, 180, fill="#7c2d12", stroke="#fdba74", stroke_width=2, rx=10))
    parts.append(_text(620, base_y - 194, "Potential barrier", fill="#fdba74", size=20))

    left_points: list[tuple[float, float]] = []
    for i in range(0, 240, 8):
        x = 150 + i
        y = base_y - 30 * math.sin(i / 18)
        left_points.append((x, y))
    parts.append(_polyline(left_points, stroke="#38bdf8"))

    transmitted_points: list[tuple[float, float]] = []
    for i in range(0, 170, 8):
        x = 760 + i
        y = base_y - 14 * math.sin(i / 14)
        transmitted_points.append((x, y))
    parts.append(_polyline(transmitted_points, stroke="#22c55e"))

    parts.append(_text(260, base_y - 80, "incident wave", fill="#bae6fd", size=18))
    parts.append(_text(880, base_y - 60, "transmitted wave", fill="#bbf7d0", size=18))
    parts.append(_text(620, base_y + 50, "Classically forbidden region", fill="#fecaca", size=18))

    return "".join(parts)


def _probability_density_svg(spec: QuantumPhysicsSpec, width: int, height: int) -> str:
    left = 150
    right = width - 150
    mid_y = height / 2 + 20
    amp = 120

    pts: list[tuple[float, float]] = []
    for i in range(0, 361, 4):
        x = left + (right - left) * i / 360
        theta = math.radians(i)
        y = mid_y - (math.sin(theta) ** 2) * amp
        pts.append((x, y))

    parts = [
        _text(width / 2, 70, spec.title or "Probability Density", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_line(left, mid_y, right, mid_y, stroke="#64748b", stroke_width=3))
    parts.append(_polyline(pts, stroke="#a78bfa", stroke_width=5))
    parts.append(_text(width / 2, mid_y + 150, "Position", fill="#e2e8f0", size=20))
    parts.append(_text(54, mid_y - 40, "Probability", fill="#e2e8f0", size=20))
    parts.append(_text(width / 2, mid_y - 150, "High probability where the curve is tall", fill="#ddd6fe", size=18))

    return "".join(parts)


def _double_slit_svg(spec: QuantumPhysicsSpec, width: int, height: int) -> str:
    parts = [
        _text(width / 2, 70, spec.title or "Double-Slit Interference", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    barrier_x = width / 2 - 40
    screen_x = width - 180
    center_y = height / 2 + 20

    parts.append(_rect(barrier_x, 180, 18, height - 280, fill="#64748b"))
    parts.append(_rect(barrier_x + 18, center_y - 90, 18, 34, fill="#0b1020"))
    parts.append(_rect(barrier_x + 18, center_y + 56, 18, 34, fill="#0b1020"))
    parts.append(_text(barrier_x + 8, 160, "slits", fill="#cbd5e1", size=18))

    parts.append(_line(150, center_y, barrier_x, center_y, stroke="#38bdf8", stroke_width=5))
    parts.append(_text(220, center_y - 20, "incoming wave", fill="#bae6fd", size=18))

    parts.append(_line(barrier_x + 36, center_y - 72, screen_x, center_y - 120, stroke="#22c55e", stroke_width=3))
    parts.append(_line(barrier_x + 36, center_y + 72, screen_x, center_y - 120, stroke="#22c55e", stroke_width=3))
    parts.append(_line(barrier_x + 36, center_y - 72, screen_x, center_y + 120, stroke="#22c55e", stroke_width=3))
    parts.append(_line(barrier_x + 36, center_y + 72, screen_x, center_y + 120, stroke="#22c55e", stroke_width=3))

    parts.append(_rect(screen_x, 170, 10, height - 260, fill="#e5e7eb"))
    for i in range(7):
        intensity = 1.0 - abs(3 - i) * 0.16
        cy = center_y - 120 + i * 40
        opacity = max(0.15, intensity)
        parts.append(_circle(screen_x + 42, cy, 14 + 8 * opacity, fill="#a855f7", fill_opacity=opacity))

    parts.append(_text(screen_x + 70, center_y + 165, "interference pattern", fill="#ddd6fe", size=18))

    return "".join(parts)


def generate_quantum_physics_visual(
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
    if spec.visual_type == "energy_levels":
        parts.append(_energy_levels_svg(spec, width, height))
    elif spec.visual_type == "tunneling_barrier":
        parts.append(_tunneling_svg(spec, width, height))
    elif spec.visual_type == "probability_density":
        parts.append(_probability_density_svg(spec, width, height))
    else:
        parts.append(_double_slit_svg(spec, width, height))
    parts.append(_svg_close())

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text("".join(parts), encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Quantum Physics Visual",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="quantum_physics_visual_agent",
        meta={
            "visual_type": spec.visual_type,
            "level_count": spec.level_count,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
