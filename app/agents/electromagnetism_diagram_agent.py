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
    "flux_window",
    "induction_pulse",
    "flux_linkage_coil",
    "lenz_opposition",
]


@dataclass
class ElectromagnetismDiagramSpec:
    diagram_type: EMType
    title: str = ""
    subtitle: str = ""
    current_direction: str = "out_of_page"
    loop_tilt_deg: float = 0.0
    turn_count: int = 1
    change_direction: str = "increasing_inward"


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> ElectromagnetismDiagramSpec:
    meta = _get_meta(req)

    diagram_type = str(meta.get("diagram_type") or "bar_magnet_field").strip().lower()
    valid_diagram_types = {
        "bar_magnet_field",
        "straight_wire_field",
        "solenoid_field",
        "flux_window",
        "induction_pulse",
        "flux_linkage_coil",
        "lenz_opposition",
    }
    if diagram_type not in valid_diagram_types:
        raise ValueError(
            "Invalid diagram_type. Use one of: bar_magnet_field, straight_wire_field, "
            "solenoid_field, flux_window, induction_pulse, flux_linkage_coil, "
            "lenz_opposition."
        )

    return ElectromagnetismDiagramSpec(
        diagram_type=diagram_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        current_direction=str(meta.get("current_direction") or "out_of_page").strip().lower(),
        loop_tilt_deg=float(meta.get("loop_tilt_deg") or 0.0),
        turn_count=max(1, int(meta.get("turn_count") or 1)),
        change_direction=str(meta.get("change_direction") or "increasing_inward").strip().lower(),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="field-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#38bdf8" />
    </marker>
    <marker id="induced-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#f97316" />
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


def _field_threads(left: float, right: float, top: float, bottom: float, count: int, *, inward: bool = True) -> str:
    parts = []
    width = right - left
    for index in range(count):
        x = left + (width * (index + 0.5) / count)
        y_start = top
        y_end = bottom
        if inward:
            parts.append(_line(x, y_start, x, y_end, stroke="#38bdf8", stroke_width=4, marker_end="field-arrow"))
        else:
            parts.append(_line(x, y_end, x, y_start, stroke="#38bdf8", stroke_width=4, marker_end="field-arrow"))
    return "".join(parts)


def _window_loop(cx: float, cy: float, width: float, height: float, tilt_deg: float, *, stroke: str = "#f8fafc") -> str:
    x = cx - width / 2
    y = cy - height / 2
    return (
        f'<g transform="rotate({tilt_deg:.2f} {cx:.2f} {cy:.2f})">'
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" height="{height:.2f}" '
        f'rx="18" fill="none" stroke="{stroke}" stroke-width="7" />'
        f"</g>"
    )


def _coil_turns(left: float, cy: float, spacing: float, turn_count: int) -> str:
    parts = []
    for index in range(turn_count):
        x = left + (index * spacing)
        parts.append(_circle(x, cy, 20, stroke="#a78bfa", stroke_width=4))
    return "".join(parts)


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


def _flux_window_svg(width: int, height: int, tilt_deg: float) -> str:
    cx = width / 2
    cy = height / 2 + 20
    parts = [
        _field_threads(180, 460, 150, 470, 7),
        _window_loop(cx, cy, 190, 140, tilt_deg or 25.0),
        _line(cx, cy - 10, cx, cy - 120, stroke="#facc15", stroke_width=5, marker_end="field-arrow"),
        _text(cx + 46, cy - 116, "window normal", fill="#fde68a", size=18, anchor="start"),
        _text(cx, cy - 165, "Face-on catches the maximum thread count", fill="#bae6fd", size=22),
        _text(cx, cy + 120, "Flux is field through the window, not field strength alone", fill="#cbd5e1", size=18),
        _text(226, 500, "stronger B", fill="#38bdf8", size=18),
        _text(414, 500, "same window", fill="#e2e8f0", size=18),
    ]
    return "".join(parts)


def _induction_pulse_svg(width: int, height: int, change_direction: str) -> str:
    left_cx = width * 0.33
    right_cx = width * 0.72
    cy = height / 2 + 30
    increasing = "increasing" in change_direction
    inward = "outward" not in change_direction
    induced_label = "loop push grows" if increasing else "loop push flips"
    field_label = "through-thread score rises" if increasing else "through-thread score falls"

    parts = [
        _text(width / 2, cy - 170, "Only changing flux creates an induced push", fill="#bae6fd", size=22),
        _rect(100, 170, 380, 300, "#111827"),
        _rect(590, 170, 380, 300, "#111827"),
        _text(left_cx, 205, "Before", fill="#cbd5e1", size=18, weight="bold"),
        _text(right_cx, 205, "During change", fill="#cbd5e1", size=18, weight="bold"),
        _field_threads(180, 400, 250, 430, 4 if increasing else 6, inward=inward),
        _field_threads(670, 900, 240, 440, 7 if increasing else 3, inward=inward),
        _window_loop(left_cx, cy + 30, 150, 110, 10),
        _window_loop(right_cx, cy + 30, 150, 110, 10),
        _line(505, cy + 30, 585, cy + 30, stroke="#f97316", stroke_width=6, marker_end="induced-arrow"),
        _text(545, cy + 8, field_label, fill="#fdba74", size=18),
        _path(
            f"M {right_cx - 85:.2f} {cy + 90:.2f} Q {right_cx - 10:.2f} {cy + 150:.2f} {right_cx + 80:.2f} {cy + 70:.2f}",
            "#f97316",
            stroke_width=6,
            marker_end="induced-arrow",
        ),
        _text(right_cx, cy + 180, induced_label, fill="#fdba74", size=18),
        _text(left_cx, cy + 180, "steady score -> no continuing emf", fill="#94a3b8", size=17),
    ]
    return "".join(parts)


def _flux_linkage_coil_svg(width: int, height: int, turn_count: int) -> str:
    cy = height / 2 + 30
    left = 240
    parts = [
        _text(width / 2, cy - 175, "More linked turns mean a larger total thread score", fill="#bae6fd", size=22),
        _field_threads(180, 940, 220, 460, 9),
        _coil_turns(left, cy, 70, min(turn_count, 8)),
        _text(width / 2, cy - 115, f"{turn_count} turns", fill="#ddd6fe", size=20, weight="bold"),
        _text(width / 2, cy + 90, "Flux linkage N Phi multiplies the through-thread score by the number of turns", fill="#cbd5e1", size=18),
        _line(260, cy - 60, 260, cy - 130, stroke="#facc15", stroke_width=5),
        _text(260, cy - 145, "Phi on each turn", fill="#fde68a", size=18),
        _line(730, cy - 60, 730, cy - 130, stroke="#f97316", stroke_width=5),
        _text(730, cy - 145, "N Phi total", fill="#fdba74", size=18),
    ]
    return "".join(parts)


def _lenz_opposition_svg(width: int, height: int, change_direction: str) -> str:
    cx = width / 2
    cy = height / 2 + 30
    increasing = "increasing" in change_direction
    inward = "outward" not in change_direction
    change_text = "Incoming flux rises" if increasing and inward else (
        "Incoming flux falls" if (not increasing and inward) else (
            "Outgoing flux rises" if increasing else "Outgoing flux falls"
        )
    )
    response_text = "Induced field pushes back against the change"
    induced_inward = (not inward and increasing) or (inward and not increasing)

    parts = [
        _text(cx, cy - 175, "Lenz's law opposes the change, not the field itself", fill="#bae6fd", size=22),
        _field_threads(270, 470, 220, 460, 6, inward=inward),
        _window_loop(cx, cy, 190, 140, 18),
        _path(
            f"M {cx - 110:.2f} {cy + 65:.2f} Q {cx:.2f} {cy + 150:.2f} {cx + 110:.2f} {cy + 65:.2f}",
            "#f97316",
            stroke_width=7,
            marker_end="induced-arrow",
        ),
        _text(cx, cy + 185, change_text, fill="#cbd5e1", size=18),
        _text(cx, cy + 215, response_text, fill="#fdba74", size=18),
        _line(cx, cy - 20, cx, cy - 120 if induced_inward else cy + 120, stroke="#f97316", stroke_width=6, marker_end="induced-arrow"),
        _text(cx + 48, cy - 116 if induced_inward else cy + 138, "induced field", fill="#fdba74", size=18, anchor="start"),
    ]
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
    elif spec.diagram_type == "solenoid_field":
        body.append(_solenoid_svg(width, height))
    elif spec.diagram_type == "flux_window":
        body.append(_flux_window_svg(width, height, spec.loop_tilt_deg))
    elif spec.diagram_type == "induction_pulse":
        body.append(_induction_pulse_svg(width, height, spec.change_direction))
    elif spec.diagram_type == "flux_linkage_coil":
        body.append(_flux_linkage_coil_svg(width, height, spec.turn_count))
    else:
        body.append(_lenz_opposition_svg(width, height, spec.change_direction))

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
            "loop_tilt_deg": spec.loop_tilt_deg,
            "turn_count": spec.turn_count,
            "change_direction": spec.change_direction,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
