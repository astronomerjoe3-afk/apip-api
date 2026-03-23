from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


EquationVisualType = Literal["equation_card", "equation_sheet"]


@dataclass
class VariableNote:
    symbol: str
    meaning: str


@dataclass
class PhysicsEquationSpec:
    visual_type: EquationVisualType
    title: str
    subtitle: str
    equation_text: str
    variable_notes: List[VariableNote]
    secondary_equations: List[str]
    show_units_hint: bool


PRESET_EQUATIONS: Dict[str, Dict[str, Any]] = {
    "newtons_second_law": {
        "title": "Newton’s Second Law",
        "equation_text": "F = ma",
        "variable_notes": [
            {"symbol": "F", "meaning": "net force"},
            {"symbol": "m", "meaning": "mass"},
            {"symbol": "a", "meaning": "acceleration"},
        ],
    },
    "ohms_law": {
        "title": "Ohm’s Law",
        "equation_text": "V = IR",
        "variable_notes": [
            {"symbol": "V", "meaning": "voltage"},
            {"symbol": "I", "meaning": "current"},
            {"symbol": "R", "meaning": "resistance"},
        ],
    },
    "wave_speed": {
        "title": "Wave Speed",
        "equation_text": "v = fλ",
        "variable_notes": [
            {"symbol": "v", "meaning": "wave speed"},
            {"symbol": "f", "meaning": "frequency"},
            {"symbol": "λ", "meaning": "wavelength"},
        ],
    },
    "density": {
        "title": "Density",
        "equation_text": "ρ = m / V",
        "variable_notes": [
            {"symbol": "ρ", "meaning": "density"},
            {"symbol": "m", "meaning": "mass"},
            {"symbol": "V", "meaning": "volume"},
        ],
    },
    "momentum": {
        "title": "Momentum",
        "equation_text": "p = mv",
        "variable_notes": [
            {"symbol": "p", "meaning": "momentum"},
            {"symbol": "m", "meaning": "mass"},
            {"symbol": "v", "meaning": "velocity"},
        ],
    },
    "kinetic_energy": {
        "title": "Kinetic Energy",
        "equation_text": "KE = 1/2 mv²",
        "variable_notes": [
            {"symbol": "KE", "meaning": "kinetic energy"},
            {"symbol": "m", "meaning": "mass"},
            {"symbol": "v", "meaning": "speed"},
        ],
    },
    "gravitational_potential_energy": {
        "title": "Gravitational Potential Energy",
        "equation_text": "Eₚ = mgh",
        "variable_notes": [
            {"symbol": "Eₚ", "meaning": "gravitational potential energy"},
            {"symbol": "m", "meaning": "mass"},
            {"symbol": "g", "meaning": "gravitational field strength"},
            {"symbol": "h", "meaning": "height"},
        ],
    },
}


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_notes(raw_notes: Any) -> List[VariableNote]:
    if not isinstance(raw_notes, list):
        return []
    notes: List[VariableNote] = []
    for item in raw_notes:
        if isinstance(item, dict):
            notes.append(
                VariableNote(
                    symbol=str(item.get("symbol") or ""),
                    meaning=str(item.get("meaning") or ""),
                )
            )
    return notes


def _parse_spec(req: DiagramRequest) -> PhysicsEquationSpec:
    meta = _get_meta(req)

    visual_type = str(meta.get("visual_type") or "equation_card").strip().lower()
    if visual_type not in {"equation_card", "equation_sheet"}:
        raise ValueError("Invalid visual_type. Use one of: equation_card, equation_sheet.")

    equation_key = str(meta.get("equation_key") or "").strip().lower()
    preset = PRESET_EQUATIONS.get(equation_key, {})

    equation_text = str(meta.get("equation_text") or preset.get("equation_text") or "F = ma")
    title = str(meta.get("title") or req.title or preset.get("title") or req.concept or "Physics Equation")
    subtitle = str(meta.get("subtitle") or req.description or "")
    notes = _parse_notes(meta.get("variable_notes") or preset.get("variable_notes") or [])

    secondary_equations: List[str] = []
    raw_secondary = meta.get("secondary_equations") or []
    if isinstance(raw_secondary, list):
        secondary_equations = [str(item) for item in raw_secondary if str(item).strip()]

    return PhysicsEquationSpec(
        visual_type=visual_type,  # type: ignore[arg-type]
        title=title,
        subtitle=subtitle,
        equation_text=equation_text,
        variable_notes=notes,
        secondary_equations=secondary_equations,
        show_units_hint=bool(meta.get("show_units_hint", True)),
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
    rx: float = 16,
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
    stroke: str = "#334155",
    stroke_width: int = 2,
) -> str:
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}" />'
    )


def _equation_card_svg(spec: PhysicsEquationSpec, width: int, height: int) -> str:
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#0b1020" />',
        _text(width / 2, 70, spec.title, size=34, weight="bold"),
    ]

    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_rect(130, 150, width - 260, 160, fill="#111827", stroke="#334155", stroke_width=2, rx=24))
    parts.append(_text(width / 2, 250, spec.equation_text, size=64, weight="bold", fill="#38bdf8"))

    notes_y = 380
    parts.append(_text(width / 2, notes_y - 30, "Variable meanings", size=24, weight="bold", fill="#e2e8f0"))

    if spec.variable_notes:
        box_x = 170
        box_y = notes_y
        box_w = width - 340
        row_h = 46
        box_h = row_h * len(spec.variable_notes) + 26

        parts.append(_rect(box_x, box_y, box_w, box_h, fill="#0f172a", stroke="#334155", stroke_width=2, rx=18))
        for idx, note in enumerate(spec.variable_notes):
            y = box_y + 36 + idx * row_h
            if idx > 0:
                parts.append(_line(box_x + 20, y - 18, box_x + box_w - 20, y - 18))
            parts.append(_text(box_x + 40, y, note.symbol, fill="#fde68a", size=22, anchor="start", weight="bold"))
            parts.append(_text(box_x + 130, y, note.meaning, fill="#e2e8f0", size=22, anchor="start"))
    else:
        parts.append(_text(width / 2, notes_y + 20, "No variable notes provided.", fill="#cbd5e1", size=20))

    if spec.show_units_hint:
        parts.append(
            _text(
                width / 2,
                height - 80,
                "Always keep symbols, units, and meanings connected.",
                fill="#86efac",
                size=18,
            )
        )

    parts.append("</svg>")
    return "".join(parts)


def _equation_sheet_svg(spec: PhysicsEquationSpec, width: int, height: int) -> str:
    equations = [spec.equation_text] + spec.secondary_equations[:5]

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#0b1020" />',
        _text(width / 2, 70, spec.title, size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    panel_x = 120
    panel_y = 150
    panel_w = width - 240
    row_h = 78
    panel_h = row_h * len(equations) + 30

    parts.append(_rect(panel_x, panel_y, panel_w, panel_h, fill="#111827", stroke="#334155", stroke_width=2, rx=22))

    for idx, eq in enumerate(equations):
        y = panel_y + 52 + idx * row_h
        if idx > 0:
            parts.append(_line(panel_x + 22, y - 28, panel_x + panel_w - 22, y - 28))
        parts.append(_text(panel_x + 34, y, f"{idx + 1}.", fill="#facc15", size=24, anchor="start", weight="bold"))
        parts.append(_text(panel_x + 96, y, eq, fill="#38bdf8", size=36, anchor="start", weight="bold"))

    if spec.variable_notes:
        parts.append(_text(width / 2, panel_y + panel_h + 48, "Key variables", size=22, fill="#e2e8f0", weight="bold"))
        note_y = panel_y + panel_h + 80
        for idx, note in enumerate(spec.variable_notes[:6]):
            parts.append(_text(width / 2, note_y + idx * 28, f"{note.symbol} = {note.meaning}", fill="#cbd5e1", size=18))

    parts.append("</svg>")
    return "".join(parts)


def generate_standard_physics_equation(
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

    if spec.visual_type == "equation_sheet":
        svg = _equation_sheet_svg(spec, width, height)
    else:
        svg = _equation_card_svg(spec, width, height)

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title,
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="standard_physics_equation_agent",
        meta={
            "visual_type": spec.visual_type,
            "equation_text": spec.equation_text,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
