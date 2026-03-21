from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


SpaceDiagramType = Literal[
    "solar_system_overview",
    "lunar_phases",
    "earth_sun_seasons",
    "elliptical_orbit",
    "hr_diagram",
    "stellar_lifecycle",
]


@dataclass
class SpaceAstrophysicsDiagramSpec:
    diagram_type: SpaceDiagramType
    title: str = ""
    subtitle: str = ""
    show_labels: bool = True
    note_not_to_scale: bool = True
    highlighted_body: str = ""


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> SpaceAstrophysicsDiagramSpec:
    meta = _get_meta(req)

    diagram_type = str(meta.get("diagram_type") or "solar_system_overview").strip().lower()
    valid_types = {
        "solar_system_overview",
        "lunar_phases",
        "earth_sun_seasons",
        "elliptical_orbit",
        "hr_diagram",
        "stellar_lifecycle",
    }
    if diagram_type not in valid_types:
        raise ValueError(
            "Invalid diagram_type. Use one of: solar_system_overview, lunar_phases, "
            "earth_sun_seasons, elliptical_orbit, hr_diagram, stellar_lifecycle."
        )

    return SpaceAstrophysicsDiagramSpec(
        diagram_type=diagram_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        show_labels=bool(meta.get("show_labels", True)),
        note_not_to_scale=bool(meta.get("note_not_to_scale", True)),
        highlighted_body=str(meta.get("highlighted_body") or "").strip(),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="space-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#38bdf8" />
    </marker>
  </defs>
  <rect width="100%" height="100%" fill="#0b1020" />
"""


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
        f'font-size="{size}" font-family="Arial" font-weight="{weight}"{transform}>'
        f"{escape(value)}</text>"
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


def _ellipse(
    cx: float,
    cy: float,
    rx: float,
    ry: float,
    *,
    fill: str = "none",
    stroke: str = "#e2e8f0",
    stroke_width: int = 3,
) -> str:
    return (
        f'<ellipse cx="{cx:.2f}" cy="{cy:.2f}" rx="{rx:.2f}" ry="{ry:.2f}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" />'
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


def _path(
    d: str,
    *,
    stroke: str = "#e2e8f0",
    stroke_width: int = 4,
    fill: str = "none",
    marker_end: str = "",
) -> str:
    marker_attr = f' marker-end="url(#{marker_end})"' if marker_end else ""
    return f'<path d="{d}" stroke="{stroke}" stroke-width="{stroke_width}" fill="{fill}"{marker_attr} />'


def _solar_system_overview_svg(spec: SpaceAstrophysicsDiagramSpec, width: int, height: int) -> str:
    cx = 260
    cy = height / 2 + 30
    radii = [80, 130, 190, 260, 350]
    planets = [
        ("Mercury", "#9ca3af", 6, 30),
        ("Venus", "#eab308", 8, 75),
        ("Earth", "#3b82f6", 9, 125),
        ("Mars", "#ef4444", 7, 180),
        ("Jupiter", "#f59e0b", 14, 235),
    ]

    parts = [
        _circle(cx, cy, 34, fill="#facc15", stroke="#fde68a", stroke_width=4),
        _text(cx, cy + 70, "Sun", fill="#fde68a", size=22, weight="bold"),
    ]

    for radius in radii:
        parts.append(_circle(cx, cy, radius, stroke="#334155", stroke_width=2))

    for idx, (name, color, planet_r, angle_deg) in enumerate(planets):
        radius = radii[idx]
        theta = math.radians(angle_deg)
        px = cx + radius * math.cos(theta)
        py = cy + radius * math.sin(theta)
        is_highlighted = spec.highlighted_body.lower() == name.lower()
        stroke = "#f8fafc" if is_highlighted else color
        stroke_width = 4 if is_highlighted else 2

        parts.append(_circle(px, py, planet_r, fill=color, stroke=stroke, stroke_width=stroke_width))
        if spec.show_labels:
            parts.append(_text(px, py - 20, name, fill="#e2e8f0", size=16))

    if spec.note_not_to_scale:
        parts.append(_text(width - 120, height - 36, "not to scale", fill="#94a3b8", size=14))

    parts.append(_text(width / 2, 70, spec.title or "Solar System Overview", size=34, weight="bold"))
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    return "".join(parts)


def _phase_icon(index: int, cx: float, cy: float, r: float, phase_name: str) -> str:
    clip_id = f"phase_clip_{index}"
    moon = [_circle(cx, cy, r, fill="#111827", stroke="#e2e8f0", stroke_width=2)]

    if phase_name == "Full Moon":
        moon.append(_circle(cx, cy, r - 1, fill="#f8fafc", stroke="none", stroke_width=0))
    elif phase_name == "New Moon":
        pass
    elif phase_name == "First Quarter":
        moon.extend(
            [
                f'<clipPath id="{clip_id}"><rect x="{cx:.2f}" y="{cy-r:.2f}" width="{r:.2f}" height="{2*r:.2f}" /></clipPath>',
                f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r-1:.2f}" fill="#f8fafc" clip-path="url(#{clip_id})" />',
            ]
        )
    elif phase_name == "Third Quarter":
        moon.extend(
            [
                f'<clipPath id="{clip_id}"><rect x="{cx-r:.2f}" y="{cy-r:.2f}" width="{r:.2f}" height="{2*r:.2f}" /></clipPath>',
                f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r-1:.2f}" fill="#f8fafc" clip-path="url(#{clip_id})" />',
            ]
        )
    elif phase_name == "Waxing Crescent":
        moon.append(_ellipse(cx + 8, cy, r * 0.58, r - 2, fill="#f8fafc", stroke="none", stroke_width=0))
    elif phase_name == "Waning Crescent":
        moon.append(_ellipse(cx - 8, cy, r * 0.58, r - 2, fill="#f8fafc", stroke="none", stroke_width=0))
    elif phase_name == "Waxing Gibbous":
        moon.append(_circle(cx, cy, r - 1, fill="#f8fafc", stroke="none", stroke_width=0))
        moon.append(_ellipse(cx - 8, cy, r * 0.38, r - 2, fill="#111827", stroke="none", stroke_width=0))
    elif phase_name == "Waning Gibbous":
        moon.append(_circle(cx, cy, r - 1, fill="#f8fafc", stroke="none", stroke_width=0))
        moon.append(_ellipse(cx + 8, cy, r * 0.38, r - 2, fill="#111827", stroke="none", stroke_width=0))

    return "".join(moon)


def _lunar_phases_svg(spec: SpaceAstrophysicsDiagramSpec, width: int, height: int) -> str:
    earth_x = width / 2 + 40
    earth_y = height / 2 + 40
    orbit_r = 220
    phases = [
        ("New Moon", -90),
        ("Waxing Crescent", -45),
        ("First Quarter", 0),
        ("Waxing Gibbous", 45),
        ("Full Moon", 90),
        ("Waning Gibbous", 135),
        ("Third Quarter", 180),
        ("Waning Crescent", 225),
    ]

    parts = [
        _text(width / 2, 70, spec.title or "Lunar Phases", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.extend(
        [
            _circle(earth_x, earth_y, 42, fill="#2563eb", stroke="#93c5fd", stroke_width=3),
            _text(earth_x, earth_y + 70, "Earth", fill="#bfdbfe", size=18),
            _line(80, earth_y, earth_x - orbit_r - 40, earth_y, stroke="#fbbf24", stroke_width=6, marker_end="space-arrow"),
            _text(80, earth_y - 24, "Sunlight", fill="#fde68a", size=18, anchor="start"),
            _circle(earth_x, earth_y, orbit_r, stroke="#334155", stroke_width=2),
        ]
    )

    for idx, (phase, angle_deg) in enumerate(phases):
        theta = math.radians(angle_deg)
        mx = earth_x + orbit_r * math.cos(theta)
        my = earth_y + orbit_r * math.sin(theta)
        parts.append(_phase_icon(idx, mx, my, 22, phase))
        if spec.show_labels:
            parts.append(_text(mx, my + 42, phase, fill="#e2e8f0", size=14))

    return "".join(parts)


def _earth_with_axis(cx: float, cy: float, tilt_deg: float, label: str) -> str:
    tilt = math.radians(tilt_deg)
    dx = math.cos(tilt) * 46
    dy = math.sin(tilt) * 46
    return "".join(
        [
            _circle(cx, cy, 28, fill="#2563eb", stroke="#93c5fd", stroke_width=3),
            _line(cx - dx, cy + dy, cx + dx, cy - dy, stroke="#f8fafc", stroke_width=3),
            _text(cx, cy + 56, label, fill="#e2e8f0", size=16),
        ]
    )


def _earth_sun_seasons_svg(spec: SpaceAstrophysicsDiagramSpec, width: int, height: int) -> str:
    sun_x = width / 2
    sun_y = height / 2 + 20
    orbit_r = 240
    tilt_deg = 23.5
    positions = [
        ("June Solstice", 0),
        ("September Equinox", 90),
        ("December Solstice", 180),
        ("March Equinox", 270),
    ]

    parts = [
        _text(width / 2, 70, spec.title or "Earth-Sun Seasons", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.extend(
        [
            _circle(sun_x, sun_y, 46, fill="#facc15", stroke="#fde68a", stroke_width=4),
            _text(sun_x, sun_y + 78, "Sun", fill="#fde68a", size=20, weight="bold"),
            _circle(sun_x, sun_y, orbit_r, stroke="#334155", stroke_width=2),
        ]
    )

    for label, angle_deg in positions:
        theta = math.radians(angle_deg)
        ex = sun_x + orbit_r * math.cos(theta)
        ey = sun_y + orbit_r * math.sin(theta)
        parts.append(_earth_with_axis(ex, ey, tilt_deg, label))

    return "".join(parts)


def _elliptical_orbit_svg(spec: SpaceAstrophysicsDiagramSpec, width: int, height: int) -> str:
    cx = width / 2
    cy = height / 2 + 30
    rx = 330
    ry = 180
    eccentricity = 0.55
    focus_offset = rx * eccentricity
    sun_x = cx - focus_offset

    theta = math.radians(35)
    planet_x = cx + rx * math.cos(theta)
    planet_y = cy + ry * math.sin(theta)

    parts = [
        _text(width / 2, 70, spec.title or "Elliptical Orbit", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.extend(
        [
            _ellipse(cx, cy, rx, ry, stroke="#38bdf8", stroke_width=4),
            _circle(sun_x, cy, 28, fill="#facc15", stroke="#fde68a", stroke_width=4),
            _text(sun_x, cy + 54, "Sun at focus", fill="#fde68a", size=18),
            _circle(planet_x, planet_y, 14, fill="#3b82f6", stroke="#bfdbfe", stroke_width=2),
            _text(planet_x + 24, planet_y - 12, "Planet", fill="#bfdbfe", size=16, anchor="start"),
            _line(cx - rx, cy, cx - rx, cy + 80, stroke="#94a3b8", stroke_width=2, dashed=True),
            _line(cx + rx, cy, cx + rx, cy + 80, stroke="#94a3b8", stroke_width=2, dashed=True),
            _text(cx - rx, cy + 106, "Perihelion side", fill="#cbd5e1", size=15),
            _text(cx + rx, cy + 106, "Aphelion side", fill="#cbd5e1", size=15),
        ]
    )

    return "".join(parts)


def _hr_diagram_svg(spec: SpaceAstrophysicsDiagramSpec, width: int, height: int) -> str:
    plot_x = 150
    plot_y = 170
    plot_w = width - 250
    plot_h = height - 280

    parts = [
        _text(width / 2, 70, spec.title or "H-R Diagram", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_rect(plot_x, plot_y, plot_w, plot_h, fill="#111827", stroke="#334155", stroke_width=2, rx=18))

    for i in range(6):
        tx = plot_x + plot_w * i / 5
        parts.append(_line(tx, plot_y, tx, plot_y + plot_h, stroke="#1f2937", stroke_width=1))
    for i in range(6):
        ty = plot_y + plot_h * i / 5
        parts.append(_line(plot_x, ty, plot_x + plot_w, ty, stroke="#1f2937", stroke_width=1))

    parts.extend(
        [
            _line(plot_x, plot_y + plot_h, plot_x + plot_w, plot_y + plot_h, stroke="#64748b", stroke_width=3),
            _line(plot_x, plot_y, plot_x, plot_y + plot_h, stroke="#64748b", stroke_width=3),
            _text(plot_x + plot_w / 2, height - 48, "Temperature (decreases to the right)", fill="#e2e8f0", size=20),
            _text(52, plot_y + plot_h / 2, "Luminosity", fill="#e2e8f0", size=20, rotate=-90),
        ]
    )

    main_sequence = [
        (plot_x + 80, plot_y + 40),
        (plot_x + 170, plot_y + 90),
        (plot_x + 290, plot_y + 170),
        (plot_x + 430, plot_y + 260),
        (plot_x + 620, plot_y + 350),
    ]
    parts.append(_path("M " + " L ".join(f"{x:.2f} {y:.2f}" for x, y in main_sequence), stroke="#38bdf8", stroke_width=6))
    parts.append(_text(plot_x + 420, plot_y + 210, "Main Sequence", fill="#bae6fd", size=20))

    parts.append(_circle(plot_x + 650, plot_y + 70, 18, fill="#f97316", stroke="#fdba74", stroke_width=2))
    parts.append(_text(plot_x + 720, plot_y + 76, "Red Giants", fill="#fdba74", size=18, anchor="start"))

    parts.append(_circle(plot_x + 180, plot_y + 330, 10, fill="#e5e7eb", stroke="#f8fafc", stroke_width=2))
    parts.append(_text(plot_x + 250, plot_y + 336, "White Dwarfs", fill="#e2e8f0", size=18, anchor="start"))

    return "".join(parts)


def _stellar_lifecycle_svg(spec: SpaceAstrophysicsDiagramSpec, width: int, height: int) -> str:
    parts = [
        _text(width / 2, 70, spec.title or "Stellar Lifecycle", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    boxes = {
        "nebula": (160, 220, 190, 70, "#1d4ed8", "Nebula"),
        "protostar": (420, 220, 190, 70, "#7c3aed", "Protostar"),
        "main_seq": (690, 220, 220, 70, "#0f766e", "Main Sequence Star"),
        "red_giant": (360, 390, 210, 70, "#ea580c", "Red Giant"),
        "white_dwarf": (360, 540, 210, 70, "#64748b", "White Dwarf"),
        "supergiant": (790, 390, 220, 70, "#dc2626", "Supergiant"),
        "neutron_star": (720, 540, 180, 70, "#334155", "Neutron Star"),
        "black_hole": (930, 540, 160, 70, "#111827", "Black Hole"),
    }

    for x, y, w, h, fill, label in boxes.values():
        parts.append(_rect(x, y, w, h, fill=fill, stroke="#e2e8f0", stroke_width=2, rx=18))
        parts.append(_text(x + w / 2, y + 42, label, fill="white", size=22, weight="bold"))

    arrows = [
        ((350, 255), (420, 255)),
        ((610, 255), (690, 255)),
        ((800, 290), (465, 390)),
        ((465, 460), (465, 540)),
        ((910, 290), (900, 390)),
        ((850, 460), (810, 540)),
        ((970, 460), (1010, 540)),
    ]

    for (x1, y1), (x2, y2) in arrows:
        parts.append(_line(x1, y1, x2, y2, stroke="#38bdf8", stroke_width=4, marker_end="space-arrow"))

    parts.append(_text(900, 330, "high mass path", fill="#fecaca", size=18))
    parts.append(_text(465, 330, "lower mass path", fill="#fed7aa", size=18))

    return "".join(parts)


def generate_space_astrophysics_diagram(
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

    if spec.diagram_type == "solar_system_overview":
        body = _solar_system_overview_svg(spec, width, height)
    elif spec.diagram_type == "lunar_phases":
        body = _lunar_phases_svg(spec, width, height)
    elif spec.diagram_type == "earth_sun_seasons":
        body = _earth_sun_seasons_svg(spec, width, height)
    elif spec.diagram_type == "elliptical_orbit":
        body = _elliptical_orbit_svg(spec, width, height)
    elif spec.diagram_type == "hr_diagram":
        body = _hr_diagram_svg(spec, width, height)
    else:
        body = _stellar_lifecycle_svg(spec, width, height)

    svg = _svg_header(width, height) + body + "</svg>"

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Space & Astrophysics Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="space_astrophysics_diagram_agent",
        meta={
            "diagram_type": spec.diagram_type,
            "show_labels": spec.show_labels,
            "note_not_to_scale": spec.note_not_to_scale,
            "highlighted_body": spec.highlighted_body,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
