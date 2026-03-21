from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


ThermalStatMechDiagramType = Literal[
    "bounce_chamber_pressure",
    "gas_law_balance",
    "kinetic_theory_bridge",
    "average_dash_energy",
    "partition_expansion",
    "entropy_option_count",
]


@dataclass
class ThermalStatMechDiagramSpec:
    diagram_type: ThermalStatMechDiagramType
    title: str = ""
    subtitle: str = ""
    particle_count: int = 12
    left_count: int = 8
    hot_level: float = 1.5


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> ThermalStatMechDiagramSpec:
    meta = _get_meta(req)
    diagram_type = str(meta.get("diagram_type") or "bounce_chamber_pressure").strip().lower()
    valid_types = {
        "bounce_chamber_pressure",
        "gas_law_balance",
        "kinetic_theory_bridge",
        "average_dash_energy",
        "partition_expansion",
        "entropy_option_count",
    }
    if diagram_type not in valid_types:
        raise ValueError(
            "Invalid diagram_type. Use one of: bounce_chamber_pressure, gas_law_balance, "
            "kinetic_theory_bridge, average_dash_energy, partition_expansion, "
            "entropy_option_count."
        )

    def _int(name: str, default: int) -> int:
        try:
            return int(meta.get(name, default))
        except Exception:
            return default

    def _float(name: str, default: float) -> float:
        try:
            return float(meta.get(name, default))
        except Exception:
            return default

    return ThermalStatMechDiagramSpec(
        diagram_type=diagram_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        particle_count=max(6, _int("particle_count", 12)),
        left_count=max(2, _int("left_count", 8)),
        hot_level=max(0.7, _float("hot_level", 1.5)),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="thermal-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#38bdf8" />
    </marker>
  </defs>
  <rect width="100%" height="100%" fill="#0b1020" />
"""


def _svg_footer() -> str:
    return "</svg>"


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


def _line(
    x1: float,
    y1: float,
    x2: float,
    y2: float,
    *,
    stroke: str = "#e2e8f0",
    stroke_width: int = 4,
    dashed: bool = False,
    marker_end: str = "",
) -> str:
    dash_attr = ' stroke-dasharray="10 8"' if dashed else ""
    marker_attr = f' marker-end="url(#{marker_end})"' if marker_end else ""
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}"{dash_attr}{marker_attr} />'
    )


def _rect(
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    fill: str = "none",
    stroke: str = "#e2e8f0",
    stroke_width: int = 4,
    rx: int = 24,
) -> str:
    return (
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="{rx}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" />'
    )


def _circle(
    cx: float,
    cy: float,
    r: float,
    *,
    fill: str = "none",
    stroke: str = "#e2e8f0",
    stroke_width: int = 3,
) -> str:
    return (
        f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}" />'
    )


def _particle(cx: float, cy: float, vx: float, vy: float, fill: str) -> str:
    return "".join(
        [
            _circle(cx, cy, 9, fill=fill, stroke=fill, stroke_width=0),
            _line(cx, cy, cx + vx, cy + vy, stroke=fill, stroke_width=3, marker_end="thermal-arrow"),
        ]
    )


def _title_block(spec: ThermalStatMechDiagramSpec, width: int) -> str:
    parts = [_text(width / 2, 70, spec.title or "Thermal & Statistical Physics Diagram", size=34, weight="bold")]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))
    return "".join(parts)


def _chamber_particles(x: float, y: float, w: float, h: float, count: int, *, scale: float = 1.0, hot: bool = False) -> str:
    fills = ["#38bdf8", "#60a5fa", "#22c55e", "#facc15"]
    parts = []
    cols = max(3, min(5, count // 2))
    rows = max(2, (count + cols - 1) // cols)
    index = 0
    for row in range(rows):
        for col in range(cols):
            if index >= count:
                break
            px = x + 40 + (w - 80) * (col + 0.5) / cols
            py = y + 40 + (h - 80) * (row + 0.5) / rows
            vx = (16 + (index % 3) * 8) * scale * (1 if index % 2 == 0 else -1)
            vy = (10 + (index % 4) * 5) * scale * (1 if index % 3 else -1)
            parts.append(_particle(px, py, vx, vy, fills[index % len(fills)] if hot else "#93c5fd"))
            index += 1
    return "".join(parts)


def _draw_bounce_chamber_pressure(spec: ThermalStatMechDiagramSpec, width: int, height: int) -> str:
    chamber_x = 190
    chamber_y = 180
    chamber_w = 460
    chamber_h = 300
    callout_x = chamber_x + chamber_w + 150
    callout_y = chamber_y + 245
    parts = [
        _rect(chamber_x, chamber_y, chamber_w, chamber_h, fill="#111827", stroke="#38bdf8", stroke_width=5),
        _text(chamber_x + chamber_w / 2, chamber_y - 26, "Bounce chamber", size=24, fill="#bae6fd"),
        _chamber_particles(chamber_x, chamber_y, chamber_w, chamber_h, spec.particle_count, scale=1.0, hot=True),
        _line(chamber_x + chamber_w, chamber_y + 80, chamber_x + chamber_w + 110, chamber_y + 80, stroke="#f97316", stroke_width=6, marker_end="thermal-arrow"),
        _line(chamber_x + chamber_w, chamber_y + 150, chamber_x + chamber_w + 110, chamber_y + 150, stroke="#f97316", stroke_width=6, marker_end="thermal-arrow"),
        _line(chamber_x + chamber_w, chamber_y + 220, chamber_x + chamber_w + 110, chamber_y + 220, stroke="#f97316", stroke_width=6, marker_end="thermal-arrow"),
        _rect(callout_x, callout_y, 280, 56, fill="#111827", stroke="#f97316", stroke_width=3, rx=18),
        _text(callout_x + 140, callout_y + 36, "wall-hit load = pressure", fill="#fdba74", size=22),
        _text(1015, 245, "More dashers", fill="#cbd5e1", size=20, anchor="start"),
        _text(965, 285, "+ more energetic dashers", fill="#cbd5e1", size=20, anchor="start"),
        _text(940, 325, "= more wall momentum change", fill="#cbd5e1", size=20, anchor="start"),
        _text(width / 2, 560, "Pressure comes from countless momentum-changing collisions with the walls.", fill="#93c5fd", size=22),
    ]
    return "".join(parts)


def _draw_gas_law_balance(width: int, height: int) -> str:
    parts = [
        _rect(120, 190, 350, 280, fill="#111827", stroke="#38bdf8", stroke_width=4),
        _rect(810, 190, 350, 280, fill="#111827", stroke="#22c55e", stroke_width=4),
        _text(295, 285, "pV", size=72, fill="#bae6fd", weight="bold"),
        _text(985, 285, "nRT", size=72, fill="#bbf7d0", weight="bold"),
        _text(295, 350, "wall-hit load x room size", size=22, fill="#cbd5e1"),
        _text(985, 350, "crowd count x dash level", size=22, fill="#cbd5e1"),
        _line(470, 300, 810, 300, stroke="#facc15", stroke_width=8, marker_end="thermal-arrow"),
        _text(640, 272, "balance rule", size=22, fill="#fde68a"),
        _text(190, 540, "Increase T or n at fixed V -> pressure rises", size=20, anchor="start", fill="#93c5fd"),
        _text(190, 575, "Increase V at fixed n and T -> pressure falls", size=20, anchor="start", fill="#93c5fd"),
        _text(985, 540, "Ideal gas law: pV = nRT", size=24, fill="#86efac"),
    ]
    return "".join(parts)


def _draw_kinetic_theory_bridge(width: int, height: int) -> str:
    chamber_x = 90
    chamber_y = 190
    chamber_w = 410
    chamber_h = 280
    parts = [
        _rect(chamber_x, chamber_y, chamber_w, chamber_h, fill="#111827", stroke="#60a5fa", stroke_width=4),
        _text(chamber_x + chamber_w / 2, 165, "Microscopic collision story", size=24, fill="#bae6fd"),
        _chamber_particles(chamber_x, chamber_y, chamber_w, chamber_h, 10, scale=1.2, hot=True),
        _line(chamber_x + chamber_w - 12, chamber_y + 142, chamber_x + chamber_w + 70, chamber_y + 142, stroke="#f97316", stroke_width=6, marker_end="thermal-arrow"),
        _text(chamber_x + chamber_w + 110, chamber_y + 148, "Delta p at wall", size=20, fill="#fdba74"),
        _rect(630, 175, 560, 320, fill="#111827", stroke="#334155", stroke_width=3),
        _text(910, 250, "pV = (1/3) N m <c^2>", size=38, fill="#f8fafc", weight="bold"),
        _text(910, 318, "Compare with pV = NkT", size=28, fill="#cbd5e1"),
        _text(910, 382, "<Ek> = (3/2) kT", size=38, fill="#86efac", weight="bold"),
        _text(910, 436, "Gas law is the chamber summary rule.", size=22, fill="#93c5fd"),
        _text(910, 468, "Kinetic theory is the molecular explanation.", size=22, fill="#93c5fd"),
    ]
    return "".join(parts)


def _draw_average_dash_energy(spec: ThermalStatMechDiagramSpec, width: int, height: int) -> str:
    left_x = 120
    right_x = 720
    chamber_y = 190
    chamber_w = 420
    chamber_h = 270
    hot_scale = max(1.1, spec.hot_level)
    parts = [
        _rect(left_x, chamber_y, chamber_w, chamber_h, fill="#111827", stroke="#38bdf8", stroke_width=4),
        _rect(right_x, chamber_y, chamber_w, chamber_h, fill="#111827", stroke="#f97316", stroke_width=4),
        _text(left_x + chamber_w / 2, 165, "Cool chamber", size=24, fill="#bae6fd"),
        _text(right_x + chamber_w / 2, 165, "Hot chamber", size=24, fill="#fdba74"),
        _chamber_particles(left_x, chamber_y, chamber_w, chamber_h, 10, scale=0.8, hot=False),
        _chamber_particles(right_x, chamber_y, chamber_w, chamber_h, 10, scale=hot_scale, hot=True),
        _text(width / 2, 540, "Temperature tracks average translational kinetic energy per molecule.", size=24, fill="#93c5fd"),
        _text(width / 2, 580, "<Ek> = (3/2) kT", size=34, fill="#bbf7d0", weight="bold"),
    ]
    return "".join(parts)


def _draw_partition_expansion(spec: ThermalStatMechDiagramSpec, width: int, height: int) -> str:
    left_box_x = 90
    right_box_x = 720
    box_y = 200
    box_w = 470
    box_h = 260
    parts = [
        _rect(left_box_x, box_y, box_w, box_h, fill="#111827", stroke="#60a5fa", stroke_width=4),
        _rect(right_box_x, box_y, box_w, box_h, fill="#111827", stroke="#22c55e", stroke_width=4),
        _line(left_box_x + box_w / 2, box_y, left_box_x + box_w / 2, box_y + box_h, stroke="#f8fafc", stroke_width=6),
        _text(left_box_x + box_w / 2, 170, "Before partition drop", size=24, fill="#bae6fd"),
        _text(right_box_x + box_w / 2, 170, "After partition drop", size=24, fill="#bbf7d0"),
        _chamber_particles(left_box_x + 8, box_y, (box_w / 2) - 18, box_h, spec.left_count, scale=1.0, hot=False),
        _text(left_box_x + box_w / 2, 492, "gas crowded on one side", size=20, fill="#cbd5e1"),
        _chamber_particles(right_box_x, box_y, box_w, box_h, spec.particle_count, scale=1.0, hot=False),
        _text(right_box_x + box_w / 2, 492, "more accessible hidden playbooks", size=20, fill="#cbd5e1"),
        _line(595, 330, 680, 330, stroke="#facc15", stroke_width=8, marker_end="thermal-arrow"),
        _text(width / 2, 560, "Removing the partition increases the number of accessible microstates.", size=22, fill="#fde68a"),
    ]
    return "".join(parts)


def _draw_entropy_option_count(width: int, height: int) -> str:
    bars = [50, 110, 280]
    labels = ["all left", "uneven split", "evener spread"]
    colors = ["#64748b", "#60a5fa", "#22c55e"]
    parts = [
        _text(width / 2, 160, "Same visible total, very different hidden option counts", size=24, fill="#93c5fd"),
        _line(180, 500, 1100, 500, stroke="#475569", stroke_width=4),
        _line(180, 250, 180, 500, stroke="#475569", stroke_width=4),
    ]
    for index, value in enumerate(bars):
        bar_x = 270 + index * 230
        bar_h = value
        parts.append(f'<rect x="{bar_x:.2f}" y="{500 - bar_h:.2f}" width="120" height="{bar_h:.2f}" rx="18" fill="{colors[index]}" />')
        parts.append(_text(bar_x + 60, 530, labels[index], size=18, fill="#cbd5e1"))
    parts.extend(
        [
            _text(156, 258, "W", size=30, fill="#f8fafc", weight="bold"),
            _text(910, 255, "S = k ln W", size=42, fill="#fbbf24", weight="bold"),
            _text(910, 308, "larger W -> larger entropy", size=22, fill="#fde68a"),
            _text(width / 2, 590, "Entropy is strongest as an option-count and dispersal idea, not just a 'messiness' slogan.", size=20, fill="#93c5fd"),
        ]
    )
    return "".join(parts)


def _build_svg(spec: ThermalStatMechDiagramSpec, width: int, height: int) -> str:
    body = [_svg_header(width, height), _title_block(spec, width)]
    if spec.diagram_type == "bounce_chamber_pressure":
        body.append(_draw_bounce_chamber_pressure(spec, width, height))
    elif spec.diagram_type == "gas_law_balance":
        body.append(_draw_gas_law_balance(width, height))
    elif spec.diagram_type == "kinetic_theory_bridge":
        body.append(_draw_kinetic_theory_bridge(width, height))
    elif spec.diagram_type == "average_dash_energy":
        body.append(_draw_average_dash_energy(spec, width, height))
    elif spec.diagram_type == "partition_expansion":
        body.append(_draw_partition_expansion(spec, width, height))
    else:
        body.append(_draw_entropy_option_count(width, height))
    body.append(_svg_footer())
    return "".join(body)


def generate_thermal_statmech_diagram(
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

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(_build_svg(spec, width, height), encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Thermal & Statistical Physics Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="thermal_statmech_diagram_agent",
        meta={
            "diagram_type": spec.diagram_type,
            "particle_count": spec.particle_count,
            "left_count": spec.left_count,
            "hot_level": spec.hot_level,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
