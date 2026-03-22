from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


AstronomyDiagramType = Literal[
    "solar_court",
    "gravity_rings",
    "day_night_rotation",
    "seasons_tilt",
    "moon_phases",
    "orbit_distance_period",
]


@dataclass
class AstronomyDiagramSpec:
    diagram_type: AstronomyDiagramType
    title: str = ""
    subtitle: str = ""
    orbit_position: int = 0
    moon_position: int = 0
    tilt_deg: float = 23.4


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> AstronomyDiagramSpec:
    meta = _get_meta(req)
    diagram_type = str(meta.get("diagram_type") or "solar_court").strip().lower()
    valid_types = {
        "solar_court",
        "gravity_rings",
        "day_night_rotation",
        "seasons_tilt",
        "moon_phases",
        "orbit_distance_period",
    }
    if diagram_type not in valid_types:
        raise ValueError(
            "Invalid diagram_type. Use one of: solar_court, gravity_rings, "
            "day_night_rotation, seasons_tilt, moon_phases, orbit_distance_period."
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

    return AstronomyDiagramSpec(
        diagram_type=diagram_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        orbit_position=max(0, min(3, _int("orbit_position", 0))),
        moon_position=max(0, min(7, _int("moon_position", 2))),
        tilt_deg=max(0.0, min(35.0, _float("tilt_deg", 23.4))),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="astro-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
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
    stroke: str = "#334155",
    stroke_width: int = 3,
    dashed: bool = False,
) -> str:
    dash_attr = ' stroke-dasharray="10 8"' if dashed else ""
    return (
        f'<ellipse cx="{cx:.2f}" cy="{cy:.2f}" rx="{rx:.2f}" ry="{ry:.2f}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}"{dash_attr} />'
    )


def _rect(
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    fill: str = "none",
    stroke: str = "#e2e8f0",
    stroke_width: int = 3,
    rx: int = 18,
) -> str:
    return (
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="{rx}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" />'
    )


def _title_block(spec: AstronomyDiagramSpec, width: int) -> str:
    parts = [_text(width / 2, 70, spec.title or "Astronomy Diagram", size=34, weight="bold")]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))
    return "".join(parts)


def _sun(cx: float, cy: float, r: float) -> str:
    parts = [_circle(cx, cy, r, fill="#facc15", stroke="#fde68a", stroke_width=5)]
    for dx, dy in [(0, -70), (60, -40), (75, 0), (60, 40), (0, 70), (-60, 40), (-75, 0), (-60, -40)]:
        parts.append(_line(cx + dx * 0.55, cy + dy * 0.55, cx + dx, cy + dy, stroke="#fbbf24", stroke_width=5))
    return "".join(parts)


def _planet(cx: float, cy: float, r: float, fill: str, label: str, label_y: float) -> str:
    return "".join(
        [
            _circle(cx, cy, r, fill=fill, stroke=fill, stroke_width=0),
            _text(cx, label_y, label, size=18, fill="#cbd5e1"),
        ]
    )


def _draw_solar_court(width: int, height: int) -> str:
    cx = 350
    cy = 360
    parts = [
        _sun(cx, cy, 48),
        _text(cx, cy + 8, "Sun", size=24, fill="#0f172a", weight="bold"),
        _ellipse(cx, cy, 130, 90, stroke="#475569"),
        _ellipse(cx, cy, 230, 150, stroke="#475569"),
        _ellipse(cx, cy, 340, 220, stroke="#475569"),
        _planet(cx + 130, cy, 14, "#60a5fa", "planet", cy + 124),
        _planet(cx - 162, cy + 116, 10, "#a78bfa", "dwarf planet", cy + 150),
        _planet(cx + 44, cy - 220, 8, "#cbd5e1", "moon", cy - 194),
        _circle(cx + 14, cy - 154, 6, fill="#f97316", stroke="#f97316", stroke_width=0),
        _text(476, 182, "rock swarm", size=18, fill="#fdba74"),
        _line(572, 166, 514, 206, stroke="#f97316", stroke_width=3),
        _ellipse(970, 310, 125, 70, stroke="#38bdf8", dashed=True),
        _circle(1088, 282, 10, fill="#bae6fd", stroke="#bae6fd", stroke_width=0),
        _text(1050, 220, "ice visitor", size=18, fill="#bae6fd"),
        _line(1026, 232, 1082, 274, stroke="#38bdf8", stroke_width=3),
        _text(920, 130, "One Great Lantern lights the whole court.", size=24, fill="#fde68a"),
        _text(920, 168, "Planets, dwarf planets, moons, asteroids, and comets all belong to one Sun-centered family.", size=18, fill="#cbd5e1"),
    ]
    return "".join(parts)


def _draw_gravity_rings(width: int, height: int) -> str:
    cx = 320
    cy = 360
    parts = [
        _sun(cx, cy, 44),
        _ellipse(cx, cy, 170, 108, stroke="#475569"),
        _planet(cx + 170, cy, 16, "#60a5fa", "world rider", cy + 136),
        _line(cx + 136, cy - 56, cx + 52, cy - 18, stroke="#f97316", stroke_width=6, marker_end="astro-arrow"),
        _text(534, 286, "hub pull = gravity", size=22, fill="#fdba74"),
        _line(cx + 112, cy + 82, cx + 164, cy + 82, stroke="#38bdf8", stroke_width=5, marker_end="astro-arrow"),
        _text(580, 448, "forward motion", size=20, fill="#bae6fd"),
        _text(925, 260, "Ring routes are pull-guided paths, not metal tracks.", size=24, fill="#f8fafc"),
        _text(925, 304, "Gravity keeps planets orbiting the Sun and moons orbiting planets.", size=18, fill="#cbd5e1"),
        _text(925, 346, "Orbit shape comes from hub pull plus continuing forward motion.", size=18, fill="#cbd5e1"),
    ]
    return "".join(parts)


def _draw_day_night_rotation(width: int, height: int) -> str:
    earth_x = 770
    earth_y = 360
    parts = [
        _sun(220, 360, 48),
        _line(288, 360, 676, 360, stroke="#facc15", stroke_width=8),
        _circle(earth_x, earth_y, 112, fill="#2563eb", stroke="#93c5fd", stroke_width=4),
        _rect(earth_x - 112, earth_y - 112, 112, 224, fill="#1e293b", stroke="none", stroke_width=0, rx=0),
        _line(earth_x, earth_y - 148, earth_x, earth_y + 148, stroke="#f8fafc", stroke_width=4),
        _text(earth_x, earth_y - 166, "spin rod", size=18, fill="#f8fafc"),
        _line(earth_x + 80, earth_y - 132, earth_x + 80, earth_y + 132, stroke="#38bdf8", stroke_width=5, marker_end="astro-arrow"),
        _text(earth_x - 40, earth_y - 130, "day-face", size=20, fill="#fde68a"),
        _text(earth_x + 62, earth_y + 144, "night-face", size=20, fill="#cbd5e1"),
        _circle(earth_x - 48, earth_y - 10, 10, fill="#ef4444", stroke="#ef4444", stroke_width=0),
        _text(1000, 308, "Spin makes day and night.", size=26, fill="#f8fafc"),
        _text(1000, 350, "A place moves into and out of sunlight because the world rotates.", size=18, fill="#cbd5e1"),
    ]
    return "".join(parts)


def _draw_seasons_tilt(spec: AstronomyDiagramSpec, width: int, height: int) -> str:
    sun_x = 270
    sun_y = 360
    june_x = 760
    june_y = 250
    dec_x = 760
    dec_y = 470
    tilt = spec.tilt_deg
    tilt_dx = 48
    tilt_dy = 112
    parts = [
        _sun(sun_x, sun_y, 52),
        _line(sun_x + 76, sun_y - 64, june_x - 110, june_y - 36, stroke="#facc15", stroke_width=4),
        _line(sun_x + 76, sun_y + 64, dec_x - 110, dec_y + 36, stroke="#facc15", stroke_width=4),
        _circle(june_x, june_y, 66, fill="#2563eb", stroke="#93c5fd", stroke_width=4),
        _circle(dec_x, dec_y, 66, fill="#2563eb", stroke="#93c5fd", stroke_width=4),
        _line(june_x - tilt_dx, june_y + tilt_dy, june_x + tilt_dx, june_y - tilt_dy, stroke="#f8fafc", stroke_width=4),
        _line(dec_x - tilt_dx, dec_y + tilt_dy, dec_x + tilt_dx, dec_y - tilt_dy, stroke="#f8fafc", stroke_width=4),
        _text(june_x, june_y - 92, "June position", size=20, fill="#bbf7d0"),
        _text(dec_x, dec_y + 104, "December position", size=20, fill="#fecaca"),
        _text(900, 208, "AXIS READ", size=14, fill="#94a3b8", weight="bold", anchor="start"),
        _text(900, 240, f"tilt rod ~ {tilt:.1f} deg", size=22, fill="#f8fafc", weight="bold", anchor="start"),
        _text(900, 288, "The axis keeps the same leaning", size=18, fill="#cbd5e1", anchor="start"),
        _text(900, 312, "direction in space.", size=18, fill="#cbd5e1", anchor="start"),
        _text(900, 362, "One hemisphere tilts toward the", size=18, fill="#cbd5e1", anchor="start"),
        _text(900, 386, "lantern, then away half a year later.", size=18, fill="#cbd5e1", anchor="start"),
        _text(900, 452, "Seasons come from tilt and sunlight", size=18, fill="#fde68a", weight="bold", anchor="start"),
        _text(900, 476, "angle, not distance changes.", size=18, fill="#fde68a", weight="bold", anchor="start"),
    ]
    return "".join(parts)


def _phase_name(index: int) -> str:
    names = [
        "new",
        "waxing crescent",
        "first quarter",
        "waxing gibbous",
        "full",
        "waning gibbous",
        "third quarter",
        "waning crescent",
    ]
    return names[index % len(names)]


def _draw_moon_phases(spec: AstronomyDiagramSpec, width: int, height: int) -> str:
    sun_x = 180
    sun_y = 360
    earth_x = 700
    earth_y = 360
    phase_positions = [
        (earth_x - 140, earth_y),
        (earth_x - 100, earth_y - 100),
        (earth_x, earth_y - 140),
        (earth_x + 100, earth_y - 100),
        (earth_x + 140, earth_y),
        (earth_x + 100, earth_y + 100),
        (earth_x, earth_y + 140),
        (earth_x - 100, earth_y + 100),
    ]
    moon_x, moon_y = phase_positions[spec.moon_position]
    parts = [
        _sun(sun_x, sun_y, 42),
        _line(sun_x + 60, sun_y, earth_x - 126, earth_y, stroke="#facc15", stroke_width=6),
        _circle(earth_x, earth_y, 74, fill="#2563eb", stroke="#93c5fd", stroke_width=4),
        _ellipse(earth_x, earth_y, 150, 150, stroke="#475569", dashed=True),
        _circle(moon_x, moon_y, 24, fill="#e2e8f0", stroke="#cbd5e1", stroke_width=2),
        _line(earth_x, earth_y, moon_x, moon_y, stroke="#38bdf8", stroke_width=3),
        _text(earth_x, earth_y + 6, "Earth", size=20, fill="#f8fafc"),
        _text(moon_x, moon_y - 34, "Moon", size=18, fill="#f8fafc"),
        _text(1030, 246, "Companion-face phase depends on view, not shadow.", size=22, fill="#f8fafc"),
        _text(1030, 288, "The Moon is always half lit by the Sun.", size=18, fill="#cbd5e1"),
        _text(1030, 326, f"Shown phase: {_phase_name(spec.moon_position)}", size=20, fill="#fde68a"),
        _text(1030, 364, "Earth's shadow matters only during a lunar eclipse.", size=18, fill="#cbd5e1"),
    ]
    return "".join(parts)


def _draw_orbit_distance_period(width: int, height: int) -> str:
    sun_x = 270
    sun_y = 360
    parts = [
        _sun(sun_x, sun_y, 46),
        _ellipse(sun_x, sun_y, 130, 92, stroke="#22c55e"),
        _ellipse(sun_x, sun_y, 260, 176, stroke="#60a5fa"),
        _planet(sun_x + 130, sun_y, 12, "#22c55e", "inner world", 486),
        _planet(sun_x + 260, sun_y, 16, "#60a5fa", "outer world", 548),
        _text(900, 248, "shorter year lap", size=22, fill="#bbf7d0"),
        _text(900, 370, "longer year lap", size=22, fill="#bae6fd"),
        _line(734, 260, 854, 260, stroke="#22c55e", stroke_width=5, marker_end="astro-arrow"),
        _line(860, 380, 736, 380, stroke="#60a5fa", stroke_width=5, marker_end="astro-arrow"),
        _text(930, 452, "Farther ring reach usually means a longer orbital period.", size=22, fill="#fde68a"),
        _text(930, 492, "This is the qualitative year-lap idea behind Kepler's third law.", size=18, fill="#cbd5e1"),
    ]
    return "".join(parts)


def _build_svg(spec: AstronomyDiagramSpec, width: int, height: int) -> str:
    body = [_svg_header(width, height), _title_block(spec, width)]
    if spec.diagram_type == "solar_court":
        body.append(_draw_solar_court(width, height))
    elif spec.diagram_type == "gravity_rings":
        body.append(_draw_gravity_rings(width, height))
    elif spec.diagram_type == "day_night_rotation":
        body.append(_draw_day_night_rotation(width, height))
    elif spec.diagram_type == "seasons_tilt":
        body.append(_draw_seasons_tilt(spec, width, height))
    elif spec.diagram_type == "moon_phases":
        body.append(_draw_moon_phases(spec, width, height))
    else:
        body.append(_draw_orbit_distance_period(width, height))
    body.append(_svg_footer())
    return "".join(body)


def generate_astronomy_diagram(
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
        title=spec.title or req.title or "Astronomy Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="astronomy_diagram_agent",
        meta={
            "diagram_type": spec.diagram_type,
            "orbit_position": spec.orbit_position,
            "moon_position": spec.moon_position,
            "tilt_deg": spec.tilt_deg,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
