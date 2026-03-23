from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


RadiationVisualType = Literal[
    "alpha_beta_gamma_penetration",
    "half_life_curve",
    "nuclear_decay_chain",
    "electromagnetic_spectrum",
]


@dataclass
class RadiationVisualSpec:
    visual_type: RadiationVisualType
    title: str = ""
    subtitle: str = ""
    half_life: float = 1.0
    initial_amount: float = 100.0
    parent_nuclide: str = "U-238"
    daughter_nuclide: str = "Th-234"


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> RadiationVisualSpec:
    meta = _get_meta(req)
    visual_type = str(meta.get("visual_type") or "alpha_beta_gamma_penetration").strip().lower()

    if visual_type not in {
        "alpha_beta_gamma_penetration",
        "half_life_curve",
        "nuclear_decay_chain",
        "electromagnetic_spectrum",
    }:
        raise ValueError(
            "Invalid visual_type. Use one of: alpha_beta_gamma_penetration, half_life_curve, nuclear_decay_chain, electromagnetic_spectrum."
        )

    try:
        half_life = float(meta.get("half_life", 1.0))
    except Exception:
        half_life = 1.0

    try:
        initial_amount = float(meta.get("initial_amount", 100.0))
    except Exception:
        initial_amount = 100.0

    return RadiationVisualSpec(
        visual_type=visual_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        half_life=max(0.1, half_life),
        initial_amount=max(1.0, initial_amount),
        parent_nuclide=str(meta.get("parent_nuclide") or "U-238"),
        daughter_nuclide=str(meta.get("daughter_nuclide") or "Th-234"),
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
    rotate: float | None = None,
) -> str:
    transform = f' transform="rotate({rotate:.2f} {x:.2f} {y:.2f})"' if rotate is not None else ""
    return (
        f'<text x="{x:.2f}" y="{y:.2f}" fill="{fill}" text-anchor="{anchor}" '
        f'font-size="{size}" font-family="Arial" font-weight="{weight}"{transform}>{escape(value)}</text>'
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
    marker = ' marker-end="url(#rad-arrow)"' if marker_end else ""
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}"{dash}{marker} />'
    )


def _polyline(points: list[tuple[float, float]], *, stroke: str, stroke_width: int = 4) -> str:
    pts = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    return f'<polyline points="{pts}" fill="none" stroke="{stroke}" stroke-width="{stroke_width}" />'


def _svg_open(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="rad-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#38bdf8" />
    </marker>
  </defs>
  <rect width="100%" height="100%" fill="#0b1020" />
"""


def _svg_close() -> str:
    return "</svg>"


def _penetration_svg(spec: RadiationVisualSpec, width: int, height: int) -> str:
    y_positions = [240, 370, 500]
    labels = ["Alpha (α)", "Beta (β)", "Gamma (γ)"]
    colors = ["#f97316", "#38bdf8", "#a78bfa"]
    barriers = [
        ("Paper", 560, "#e5e7eb"),
        ("Aluminium", 760, "#94a3b8"),
        ("Lead", 980, "#64748b"),
    ]

    parts = [
        _text(width / 2, 70, spec.title or "Alpha, Beta, Gamma Penetration", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    for name, x, fill in barriers:
        parts.append(_rect(x, 180, 54, 390, fill=fill, stroke="#e2e8f0", stroke_width=1, rx=6))
        parts.append(_text(x + 27, 610, name, fill="#e2e8f0", size=16, rotate=-90))

    for y, label, color in zip(y_positions, labels, colors):
        parts.append(_text(150, y + 6, label, fill=color, size=24, anchor="start", weight="bold"))

    parts.append(_line(280, y_positions[0], 555, y_positions[0], stroke=colors[0], stroke_width=8, marker_end=True))
    parts.append(_line(280, y_positions[1], 755, y_positions[1], stroke=colors[1], stroke_width=8, marker_end=True))
    parts.append(_line(280, y_positions[2], 975, y_positions[2], stroke=colors[2], stroke_width=8, marker_end=True))
    parts.append(_line(980, y_positions[2], 1100, y_positions[2], stroke=colors[2], stroke_width=4, dashed=True))

    return "".join(parts)


def _half_life_svg(spec: RadiationVisualSpec, width: int, height: int) -> str:
    left = 150
    right = width - 110
    top = 170
    bottom = height - 120
    plot_w = right - left
    plot_h = bottom - top

    parts = [
        _text(width / 2, 70, spec.title or "Half-Life Curve", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_rect(left, top, plot_w, plot_h, fill="#111827", stroke="#334155", stroke_width=2, rx=18))
    parts.append(_line(left, bottom, right, bottom, stroke="#64748b", stroke_width=3))
    parts.append(_line(left, top, left, bottom, stroke="#64748b", stroke_width=3))
    parts.append(_text((left + right) / 2, height - 40, "Time", fill="#e2e8f0", size=20))
    parts.append(_text(60, (top + bottom) / 2, "Amount remaining", fill="#e2e8f0", size=20, rotate=-90))

    total_half_lives = 5
    points: list[tuple[float, float]] = []
    for i in range(0, 101):
        half_lives = total_half_lives * i / 100
        x = left + plot_w * i / 100
        y_value = spec.initial_amount * (0.5 ** half_lives)
        y = bottom - (y_value / spec.initial_amount) * plot_h
        points.append((x, y))

    parts.append(_polyline(points, stroke="#38bdf8", stroke_width=5))

    for i in range(total_half_lives + 1):
        x = left + plot_w * i / total_half_lives
        parts.append(_line(x, bottom, x, bottom + 8, stroke="#94a3b8", stroke_width=2))
        parts.append(_text(x, bottom + 30, f"{i}", fill="#94a3b8", size=16))
        if i > 0:
            y_val = spec.initial_amount * (0.5 ** i)
            y = bottom - (y_val / spec.initial_amount) * plot_h
            parts.append(_line(left, y, right, y, stroke="#1f2937", stroke_width=1, dashed=True))
            parts.append(_text(left - 16, y + 5, f"{y_val:.1f}", fill="#94a3b8", size=14, anchor="end"))

    parts.append(_text(right - 130, top + 36, f"T½ = {spec.half_life}", fill="#bae6fd", size=18))

    return "".join(parts)


def _decay_chain_svg(spec: RadiationVisualSpec, width: int, height: int) -> str:
    parts = [
        _text(width / 2, 70, spec.title or "Radioactive Decay", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parent_x = 180
    y = 280
    parts.append(_rect(parent_x, y, 180, 90, fill="#1d4ed8", stroke="#93c5fd", stroke_width=2, rx=18))
    parts.append(_text(parent_x + 90, y + 54, spec.parent_nuclide, size=30, weight="bold"))

    parts.append(_line(360, y + 45, 520, y + 45, marker_end=True))
    parts.append(_text(440, y + 20, "α / β / γ", fill="#facc15", size=20))

    parts.append(_rect(540, y, 180, 90, fill="#111827", stroke="#38bdf8", stroke_width=2, rx=18))
    parts.append(_text(630, y + 54, spec.daughter_nuclide, size=30, weight="bold"))
    parts.append(_text(width / 2, y + 170, "Parent nucleus transforms into a daughter nucleus and emits radiation.", fill="#cbd5e1", size=20))

    return "".join(parts)


def _em_spectrum_svg(spec: RadiationVisualSpec, width: int, height: int) -> str:
    bands = [
        ("Radio", "#1d4ed8"),
        ("Microwave", "#2563eb"),
        ("Infrared", "#ea580c"),
        ("Visible", "#facc15"),
        ("Ultraviolet", "#a855f7"),
        ("X-ray", "#64748b"),
        ("Gamma", "#dc2626"),
    ]

    left = 110
    bar_y = 280
    bar_h = 90
    total_w = width - 220
    band_w = total_w / len(bands)

    parts = [
        _text(width / 2, 70, spec.title or "Electromagnetic Spectrum", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    for idx, (label, color) in enumerate(bands):
        x = left + idx * band_w
        parts.append(_rect(x, bar_y, band_w, bar_h, fill=color, stroke="#0b1020", stroke_width=2, rx=0))
        parts.append(_text(x + band_w / 2, bar_y + 54, label, fill="white", size=18, weight="bold"))

    parts.append(_line(left, bar_y + 150, left + total_w, bar_y + 150, stroke="#38bdf8", stroke_width=4, marker_end=True))
    parts.append(_text(left + 80, bar_y + 190, "long wavelength", fill="#bae6fd", size=18, anchor="start"))
    parts.append(_text(left + total_w - 80, bar_y + 190, "short wavelength", fill="#bae6fd", size=18, anchor="end"))

    parts.append(_line(left + total_w, bar_y + 230, left, bar_y + 230, stroke="#f97316", stroke_width=4, marker_end=True))
    parts.append(_text(left + 80, bar_y + 270, "low frequency", fill="#fdba74", size=18, anchor="start"))
    parts.append(_text(left + total_w - 80, bar_y + 270, "high frequency / energy", fill="#fdba74", size=18, anchor="end"))

    return "".join(parts)


def generate_radioactivity_radiation_visual(
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
    if spec.visual_type == "alpha_beta_gamma_penetration":
        parts.append(_penetration_svg(spec, width, height))
    elif spec.visual_type == "half_life_curve":
        parts.append(_half_life_svg(spec, width, height))
    elif spec.visual_type == "nuclear_decay_chain":
        parts.append(_decay_chain_svg(spec, width, height))
    else:
        parts.append(_em_spectrum_svg(spec, width, height))
    parts.append(_svg_close())

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text("".join(parts), encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Radioactivity & Radiation Visual",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="radioactivity_radiation_visual_agent",
        meta={
            "visual_type": spec.visual_type,
            "half_life": spec.half_life,
            "initial_amount": spec.initial_amount,
            "parent_nuclide": spec.parent_nuclide,
            "daughter_nuclide": spec.daughter_nuclide,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
