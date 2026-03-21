from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


EMType = Literal[
    "bar_magnet_field",
    "straight_wire_field",
    "solenoid_field",
]


@dataclass
class ElectromagnetismDiagramSpec:
    diagram_type: EMType
    title: str = ""
    subtitle: str = ""
    current_direction: str = "out_of_page"


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> ElectromagnetismDiagramSpec:
    meta = _get_meta(req)

    diagram_type = str(meta.get("diagram_type") or "bar_magnet_field").strip().lower()
    if diagram_type not in {"bar_magnet_field", "straight_wire_field", "solenoid_field"}:
        raise ValueError(
            "Invalid diagram_type. Use one of: bar_magnet_field, straight_wire_field, solenoid_field."
        )

    return ElectromagnetismDiagramSpec(
        diagram_type=diagram_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        current_direction=str(meta.get("current_direction") or "out_of_page").strip().lower(),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="field-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#38bdf8" />
    </marker>
  </defs>
  <rect width="100%" height="100%" fill="#0b1020" />
"""


def _svg_footer() -> str:
    return "</svg>"


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


def _rect(x: float, y: float, w: float, h: float, fill: str) -> str:
    return f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="14" fill="{fill}" />'


def _circle(x: float, y: float, r: float, fill: str = "none", stroke: str = "#e2e8f0", stroke_width: int = 4) -> str:
    return (
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" />'
    )


def _path(d: str, stroke: str, stroke_width: int = 4, fill: str = "none", marker_end: str = "") -> str:
    marker_attr = f' marker-end="url(#{marker_end})"' if marker_end else ""
    return f'<path d="{d}" stroke="{stroke}" stroke-width="{stroke_width}" fill="{fill}"{marker_attr} />'


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


def _bar_magnet_svg(width: int, height: int) -> str:
    cx = width / 2
    cy = height / 2 + 20
    magnet_w = 360
    magnet_h = 90
    left = cx - magnet_w / 2
    right = cx + magnet_w / 2

    parts = [
        _rect(left, cy - magnet_h / 2, magnet_w / 2, magnet_h, "#1d4ed8"),
        _rect(cx, cy - magnet_h / 2, magnet_w / 2, magnet_h, "#dc2626"),
        _text(left + magnet_w / 4, cy + 10, "N", size=36, weight="bold"),
        _text(cx + magnet_w / 4, cy + 10, "S", size=36, weight="bold"),
    ]

    for y_shift in (-20, -5, 20, 5):
        if y_shift < 0:
            d = f"M {left + 18} {cy - 20} C {cx - 110} {cy - 170}, {cx + 110} {cy - 170}, {right - 18} {cy - 20}"
        else:
            d = f"M {right - 18} {cy + 20} C {cx + 110} {cy + 170}, {cx - 110} {cy + 170}, {left + 18} {cy + 20}"
        parts.append(_path(d, "#38bdf8", marker_end="field-arrow"))

    parts.append(_text(cx, cy - 170, "Magnetic field lines", fill="#bae6fd", size=22))
    return "".join(parts)


def _straight_wire_svg(width: int, height: int, current_direction: str) -> str:
    cx = width / 2
    cy = height / 2 + 20
    parts = [_circle(cx, cy, 36, fill="#111827", stroke="#fbbf24", stroke_width=5)]

    if current_direction == "into_page":
        parts.append(_line(cx - 16, cy - 16, cx + 16, cy + 16, stroke="#fbbf24", stroke_width=5))
        parts.append(_line(cx - 16, cy + 16, cx + 16, cy - 16, stroke="#fbbf24", stroke_width=5))
        parts.append(_text(cx, cy + 90, "Current into page", fill="#fde68a"))
    else:
        parts.append(_circle(cx, cy, 8, fill="#fbbf24", stroke="#fbbf24", stroke_width=0))
        parts.append(_text(cx, cy + 90, "Current out of page", fill="#fde68a"))

    for r in (90, 150, 210):
        parts.append(_circle(cx, cy, r, stroke="#38bdf8", stroke_width=4))
        parts.append(_text(cx + r + 34, cy - 6, "B", fill="#bae6fd", size=18, anchor="start"))

    parts.append(_text(cx, cy - 280, "Magnetic field around a straight current-carrying wire", fill="#bae6fd", size=24))
    return "".join(parts)


def _solenoid_svg(width: int, height: int) -> str:
    left = 180
    right = width - 180
    cy = height / 2 + 20
    coil_spacing = 70

    parts = []
    x = left
    for _ in range(10):
        parts.append(_circle(x, cy, 24, stroke="#a78bfa", stroke_width=4))
        x += coil_spacing

    parts.append(_line(left - 70, cy, left - 10, cy, stroke="#e2e8f0"))
    parts.append(_line(right + 10, cy, right + 70, cy, stroke="#e2e8f0"))
    parts.append(_line(left + 40, cy - 70, right - 40, cy - 70, stroke="#38bdf8", stroke_width=5, marker_end="field-arrow"))
    parts.append(_line(right - 40, cy + 70, left + 40, cy + 70, stroke="#38bdf8", stroke_width=5, marker_end="field-arrow"))
    parts.append(_text((left + right) / 2, cy - 105, "Magnetic field inside solenoid", fill="#bae6fd", size=22))
    parts.append(_text((left + right) / 2, cy + 120, "Field loops return outside", fill="#cbd5e1", size=18))
    return "".join(parts)


def generate_electromagnetism_diagram(
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

    body = [_text(width / 2, 70, spec.title or "Electromagnetism Diagram", size=34, weight="bold")]
    if spec.subtitle:
        body.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    if spec.diagram_type == "bar_magnet_field":
        body.append(_bar_magnet_svg(width, height))
    elif spec.diagram_type == "straight_wire_field":
        body.append(_straight_wire_svg(width, height, spec.current_direction))
    else:
        body.append(_solenoid_svg(width, height))

    svg = _svg_header(width, height) + "".join(body) + _svg_footer()

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Electromagnetism Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="electromagnetism_diagram_agent",
        meta={
            "diagram_type": spec.diagram_type,
            "current_direction": spec.current_direction,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
