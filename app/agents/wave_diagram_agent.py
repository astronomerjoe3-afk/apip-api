from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


WaveType = Literal[
    "transverse_wave",
    "longitudinal_wave",
    "standing_wave",
    "travel_pattern",
    "wave_mode_compare",
    "wave_equation",
    "reflection",
    "refraction",
    "diffraction",
    "sound_source",
    "frequency_pitch",
    "ultrasound_range",
    "echo_map",
    "doppler_shift",
    "critical_angle",
    "optical_fiber",
]


@dataclass
class WaveDiagramSpec:
    wave_type: WaveType
    title: str = ""
    subtitle: str = ""
    amplitude: float = 1.0
    wavelength_count: int = 2
    show_labels: bool = True


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> WaveDiagramSpec:
    meta = _get_meta(req)

    wave_type = str(meta.get("wave_type") or "transverse_wave").strip().lower()
    if wave_type not in {
        "transverse_wave",
        "longitudinal_wave",
        "standing_wave",
        "travel_pattern",
        "wave_mode_compare",
        "wave_equation",
        "reflection",
        "refraction",
        "diffraction",
        "sound_source",
        "frequency_pitch",
        "ultrasound_range",
        "echo_map",
        "doppler_shift",
        "critical_angle",
        "optical_fiber",
    }:
        raise ValueError(
            "Invalid wave_type. Use one of: transverse_wave, longitudinal_wave, "
            "standing_wave, travel_pattern, wave_mode_compare, wave_equation, "
            "reflection, refraction, diffraction, sound_source, frequency_pitch, "
            "ultrasound_range, echo_map, doppler_shift, critical_angle, "
            "optical_fiber."
        )

    try:
        amplitude = float(meta.get("amplitude", 1.0))
    except Exception:
        amplitude = 1.0

    try:
        wavelength_count = int(meta.get("wavelength_count", 2))
    except Exception:
        wavelength_count = 2

    return WaveDiagramSpec(
        wave_type=wave_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        amplitude=max(0.5, amplitude),
        wavelength_count=max(1, min(4, wavelength_count)),
        show_labels=bool(meta.get("show_labels", True)),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="wave-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
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
        f'stroke="{stroke}" stroke-width="{stroke_width}" stroke-linecap="round"{dash_attr}{marker_attr} />'
    )


def _path(
    d: str,
    *,
    stroke: str,
    stroke_width: int = 4,
    fill: str = "none",
    marker_end: str = "",
) -> str:
    marker_attr = f' marker-end="url(#{marker_end})"' if marker_end else ""
    return f'<path d="{d}" stroke="{stroke}" stroke-width="{stroke_width}" fill="{fill}"{marker_attr} />'


def _rect(
    x: float,
    y: float,
    width: float,
    height: float,
    *,
    fill: str,
    stroke: str = "none",
    stroke_width: int = 0,
    rx: int = 18,
) -> str:
    stroke_attr = f' stroke="{stroke}" stroke-width="{stroke_width}"' if stroke_width else ""
    return (
        f'<rect x="{x:.2f}" y="{y:.2f}" width="{width:.2f}" height="{height:.2f}" '
        f'rx="{rx}" fill="{fill}"{stroke_attr} />'
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


def _circle(
    x: float,
    y: float,
    r: float,
    *,
    fill: str,
    stroke: str = "none",
    stroke_width: int = 0,
) -> str:
    stroke_attr = f' stroke="{stroke}" stroke-width="{stroke_width}"' if stroke_width else ""
    return f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" fill="{fill}"{stroke_attr} />'


def _panel(x: float, y: float, width: float, height: float, *, title: str, accent: str) -> str:
    return "".join(
        [
            _rect(x, y, width, height, fill="#111827", stroke="#334155", stroke_width=3, rx=26),
            _text(x + 26, y + 38, title, fill=accent, size=24, anchor="start", weight="bold"),
        ]
    )


def _arrow(x1: float, y1: float, x2: float, y2: float, *, stroke: str = "#38bdf8") -> str:
    return _line(x1, y1, x2, y2, stroke=stroke, stroke_width=5, marker_end="wave-arrow")


def _sine_points(left: float, right: float, axis_y: float, *, amplitude: float, cycles: int) -> str:
    points = []
    total_length = right - left
    for i in range(0, 361 * cycles, 6):
        theta = math.radians(i)
        x = left + (total_length * i / (360 * cycles))
        y = axis_y - (math.sin(theta) * amplitude)
        points.append(f"{x:.2f},{y:.2f}")
    return " ".join(points)


def _draw_transverse_wave(spec: WaveDiagramSpec, width: int, height: int) -> str:
    left, right = 120, width - 120
    axis_y = height / 2 + 30
    amp_px = 90 * spec.amplitude
    cycles = spec.wavelength_count
    wavelength_px = (right - left) / cycles

    return "".join(
        [
            _line(left, axis_y, right, axis_y, stroke="#64748b", stroke_width=3),
            f'<polyline points="{_sine_points(left, right, axis_y, amplitude=amp_px, cycles=cycles)}" fill="none" stroke="#38bdf8" stroke-width="5" />',
            _line(left + 40, axis_y, left + 40, axis_y - amp_px, stroke="#fbbf24", marker_end="wave-arrow"),
            _text(left + 72, axis_y - amp_px / 2, "Amplitude", fill="#fde68a", anchor="start"),
            _line(left, axis_y + 120, left + wavelength_px, axis_y + 120, stroke="#86efac", marker_end="wave-arrow"),
            _text(left + wavelength_px / 2, axis_y + 154, "Wavelength lambda", fill="#bbf7d0"),
            _text(left - 10, axis_y - 10, "equilibrium", fill="#94a3b8", anchor="end", size=15),
        ]
    )


def _draw_longitudinal_wave(spec: WaveDiagramSpec, width: int, height: int) -> str:
    left, right = 150, width - 150
    mid_y = height / 2 + 20
    parts = [_line(left, mid_y, right, mid_y, stroke="#334155", stroke_width=2)]

    count = 44
    span = right - left
    for i in range(count):
        t = i / max(1, count - 1)
        density = 0.5 * (1 + math.sin((t * spec.wavelength_count * 2 * math.pi)))
        x = left + (span * t)
        height_scale = 28 + (density * 28)
        stroke = "#38bdf8" if density > 0.5 else "#cbd5e1"
        parts.append(_line(x, mid_y - height_scale, x, mid_y + height_scale, stroke=stroke, stroke_width=3))

    parts.extend(
        [
            _text(left + 180, mid_y - 90, "Compression", fill="#93c5fd"),
            _text(left + 430, mid_y - 90, "Rarefaction", fill="#cbd5e1"),
            _arrow(left + 40, mid_y + 110, left + 220, mid_y + 110, stroke="#86efac"),
            _text(left + 130, mid_y + 145, "Propagation", fill="#bbf7d0"),
        ]
    )
    return "".join(parts)


def _draw_standing_wave(spec: WaveDiagramSpec, width: int, height: int) -> str:
    left, right = 120, width - 120
    axis_y = height / 2 + 20
    amp_px = 90 * spec.amplitude
    cycles = spec.wavelength_count
    total_length = right - left

    pts_a = []
    pts_b = []
    for i in range(0, 361 * cycles, 6):
        theta = math.radians(i)
        x = left + (total_length * i / (360 * cycles))
        y_a = axis_y - (math.sin(theta) * amp_px)
        y_b = axis_y + (math.sin(theta) * amp_px)
        pts_a.append(f"{x:.2f},{y_a:.2f}")
        pts_b.append(f"{x:.2f},{y_b:.2f}")

    parts = [
        _line(left, axis_y, right, axis_y, stroke="#64748b", stroke_width=3),
        f'<polyline points="{" ".join(pts_a)}" fill="none" stroke="#38bdf8" stroke-width="5" />',
        f'<polyline points="{" ".join(pts_b)}" fill="none" stroke="#38bdf8" stroke-width="5" opacity="0.45" />',
    ]

    node_count = cycles + 1
    for i in range(node_count + 1):
        x = left + (total_length * i / max(1, node_count))
        parts.append(_circle(x, axis_y, 6, fill="#facc15"))

    parts.extend(
        [
            _text(left + 140, axis_y - 110, "Standing wave", fill="#bfdbfe"),
            _text(left + 140, axis_y + 150, "Nodes shown in yellow", fill="#fde68a"),
        ]
    )
    return "".join(parts)


def _draw_travel_pattern(width: int, height: int) -> str:
    axis_y = height / 2 + 90
    parts = [
        _panel(90, 180, 1100, 360, title="Pattern travel vs local motion", accent="#93c5fd"),
        _line(150, axis_y, 1130, axis_y, stroke="#475569", stroke_width=4),
        _line(220, axis_y - 130, 220, axis_y + 20, stroke="#38bdf8", stroke_width=10),
        _path("M 220 245 Q 350 200 470 245 Q 590 290 710 245 Q 830 200 950 245", stroke="#38bdf8", stroke_width=6),
        _arrow(260, 220, 420, 220),
        _text(340, 196, "front pattern travels", fill="#bae6fd", size=22),
        _line(610, axis_y + 42, 610, axis_y - 70, stroke="#fbbf24", stroke_width=6, marker_end="wave-arrow"),
        _line(610, axis_y - 70, 610, axis_y + 42, stroke="#fbbf24", stroke_width=6, marker_end="wave-arrow"),
        _text(650, axis_y - 16, "one pad only moves locally", fill="#fde68a", size=22, anchor="start"),
    ]
    for x in range(170, 1110, 70):
        fill = "#38bdf8" if x == 610 else "#cbd5e1"
        parts.append(_circle(x, axis_y, 12, fill=fill))
    return "".join(parts)


def _draw_wave_mode_compare(width: int, height: int) -> str:
    parts = [
        _panel(90, 180, 500, 360, title="Transverse", accent="#93c5fd"),
        _line(150, 380, 530, 380, stroke="#475569", stroke_width=3),
        f'<polyline points="{_sine_points(160, 520, 380, amplitude=75, cycles=2)}" fill="none" stroke="#38bdf8" stroke-width="5" />',
        _arrow(190, 270, 310, 270),
        _text(250, 245, "propagation", fill="#bae6fd"),
        _line(370, 430, 370, 320, stroke="#fbbf24", stroke_width=5, marker_end="wave-arrow"),
        _text(410, 372, "local motion perpendicular to travel", fill="#fde68a", anchor="start"),
        _panel(690, 180, 500, 360, title="Longitudinal", accent="#86efac"),
        _line(760, 380, 1140, 380, stroke="#475569", stroke_width=3),
    ]
    for i, x in enumerate(range(790, 1120, 24)):
        height_scale = 70 if 3 <= i <= 6 or 10 <= i <= 13 else 44
        stroke = "#38bdf8" if height_scale > 50 else "#cbd5e1"
        parts.append(_line(x, 380 - height_scale, x, 380 + height_scale, stroke=stroke, stroke_width=3))
    parts.extend(
        [
            _arrow(790, 270, 920, 270),
            _text(855, 245, "propagation", fill="#bbf7d0"),
            _line(940, 430, 1015, 430, stroke="#fbbf24", stroke_width=5, marker_end="wave-arrow"),
            _text(980, 470, "local motion parallel to travel", fill="#fde68a"),
        ]
    )
    return "".join(parts)


def _draw_wave_equation(width: int, height: int) -> str:
    card_y = 250
    parts = [
        _panel(90, 180, 1100, 360, title="Wave speed relationship", accent="#bfdbfe"),
        _rect(130, card_y, 280, 210, fill="#0f172a", stroke="#334155", stroke_width=3, rx=24),
        _text(270, card_y + 56, "Frequency f", fill="#93c5fd", size=28, weight="bold"),
        _text(270, card_y + 112, "launch rate", fill="#cbd5e1", size=22),
        _arrow(210, card_y + 154, 330, card_y + 154),
        _rect(500, card_y, 280, 210, fill="#0f172a", stroke="#334155", stroke_width=3, rx=24),
        _text(640, card_y + 56, "Wavelength lambda", fill="#86efac", size=28, weight="bold"),
        _text(640, card_y + 112, "front spacing", fill="#cbd5e1", size=22),
        _line(560, card_y + 154, 720, card_y + 154, stroke="#86efac", marker_end="wave-arrow"),
        _rect(870, card_y, 280, 210, fill="#0f172a", stroke="#334155", stroke_width=3, rx=24),
        _text(1010, card_y + 56, "Speed v", fill="#fbbf24", size=28, weight="bold"),
        _text(1010, card_y + 112, "pattern travel rate", fill="#cbd5e1", size=22),
        _arrow(930, card_y + 154, 1080, card_y + 154),
        _rect(440, 90, 400, 70, fill="#1e293b", stroke="#475569", stroke_width=3, rx=22),
        _text(640, 134, "v = f lambda", fill="#f8fafc", size=36, weight="bold"),
    ]
    return "".join(parts)


def _draw_reflection(width: int, height: int) -> str:
    hit_x = 860
    hit_y = 380
    return "".join(
        [
            _panel(100, 180, 1080, 360, title="Reflection from a boundary", accent="#93c5fd"),
            _line(hit_x, 240, hit_x, 500, stroke="#94a3b8", stroke_width=10),
            _line(hit_x - 170, hit_y, hit_x + 120, hit_y, stroke="#38bdf8", stroke_width=4, dashed=True),
            _path(f"M 360 260 L {hit_x} {hit_y}", stroke="#fbbf24", stroke_width=6, marker_end="wave-arrow"),
            _path(f"M {hit_x} {hit_y} L 360 500", stroke="#34d399", stroke_width=6, marker_end="wave-arrow"),
            _text(hit_x - 40, hit_y - 22, "normal", fill="#bae6fd", anchor="end"),
            _text(500, 290, "incident", fill="#fde68a"),
            _text(500, 510, "reflected", fill="#86efac"),
            _text(720, 560, "Equal angles are measured from the normal, not from the wall.", fill="#cbd5e1", size=22),
        ]
    )


def _draw_refraction(width: int, height: int) -> str:
    boundary_x = 690
    hit_y = 360
    return "".join(
        [
            _panel(90, 180, 1100, 360, title="Refraction in a new medium", accent="#86efac"),
            _rect(130, 230, boundary_x - 130, 260, fill="#0f172a", stroke="#334155", stroke_width=2, rx=18),
            _rect(boundary_x, 230, 410, 260, fill="#102a43", stroke="#334155", stroke_width=2, rx=18),
            _line(boundary_x, 240, boundary_x, 500, stroke="#94a3b8", stroke_width=8),
            _line(boundary_x - 180, hit_y, boundary_x + 180, hit_y, stroke="#38bdf8", stroke_width=4, dashed=True),
            _path(f"M 320 250 L {boundary_x} {hit_y}", stroke="#fbbf24", stroke_width=6, marker_end="wave-arrow"),
            _path(f"M {boundary_x} {hit_y} L 1010 430", stroke="#34d399", stroke_width=6, marker_end="wave-arrow"),
            _text(330, 220, "medium 1: faster", fill="#bfdbfe", anchor="start"),
            _text(1010, 220, "medium 2: slower", fill="#bbf7d0"),
            _text(930, 470, "lambda shorter", fill="#86efac"),
            _text(width / 2, 560, "Frequency stays source-set while speed and wavelength change in the new medium.", fill="#cbd5e1", size=21),
        ]
    )


def _critical_angle_panel(x: float, y: float, width: float, height: float, *, title: str, accent: str, state: str) -> str:
    panel_mid_x = x + width / 2
    boundary_y = y + 122
    interface_left = x + 34
    interface_right = x + width - 34
    normal_y_top = y + 42
    normal_y_bottom = y + height - 42
    hit_x = panel_mid_x
    incident_start_x = x + 88
    incident_start_y = y + height - 84

    parts = [
        _panel(x, y, width, height, title=title, accent=accent),
        _rect(x + 26, y + 70, width - 52, 70, fill="#1f2937", stroke="#334155", stroke_width=2, rx=18),
        _rect(x + 26, boundary_y, width - 52, height - 96, fill="#0f172a", stroke="#334155", stroke_width=2, rx=18),
        _line(interface_left, boundary_y, interface_right, boundary_y, stroke="#94a3b8", stroke_width=6),
        _line(hit_x, normal_y_top, hit_x, normal_y_bottom, stroke="#38bdf8", stroke_width=4, dashed=True),
        _path(f"M {incident_start_x} {incident_start_y} L {hit_x} {boundary_y}", stroke="#fbbf24", stroke_width=6, marker_end="wave-arrow"),
        _text(hit_x + 14, boundary_y - 14, "normal", fill="#bae6fd", anchor="start", size=16),
        _text(x + 62, y + 112, "faster medium", fill="#dbeafe", anchor="start", size=16),
        _text(x + 62, y + height - 28, "slower medium", fill="#bbf7d0", anchor="start", size=16),
    ]

    if state == "below":
        parts.extend(
            [
                _path(f"M {hit_x} {boundary_y} L {x + width - 86} {y + 86}", stroke="#34d399", stroke_width=6, marker_end="wave-arrow"),
                _text(panel_mid_x, y + height - 68, "incident < critical angle", fill="#fde68a", size=18),
                _text(panel_mid_x, y + height - 40, "escape: refracted route leaves the slower medium", fill="#cbd5e1", size=17),
            ]
        )
    elif state == "equal":
        parts.extend(
            [
                _path(f"M {hit_x} {boundary_y} L {interface_right - 6} {boundary_y}", stroke="#34d399", stroke_width=6, marker_end="wave-arrow"),
                _text(panel_mid_x, y + height - 68, "incident = critical angle", fill="#fde68a", size=18),
                _text(panel_mid_x, y + height - 40, "skim: refracted route runs along the boundary", fill="#cbd5e1", size=17),
            ]
        )
    else:
        parts.extend(
            [
                _path(f"M {hit_x} {boundary_y} L {x + width - 88} {y + height - 84}", stroke="#34d399", stroke_width=6, marker_end="wave-arrow"),
                _text(panel_mid_x, y + height - 68, "incident > critical angle", fill="#fde68a", size=18),
                _text(panel_mid_x, y + height - 40, "lock-bounce: no refracted route escapes", fill="#cbd5e1", size=17),
            ]
        )
    return "".join(parts)


def _draw_critical_angle(width: int, height: int) -> str:
    panel_width = 344
    gap = 24
    start_x = 100
    panel_y = 180
    panel_height = 380
    return "".join(
        [
            _critical_angle_panel(start_x, panel_y, panel_width, panel_height, title="Below critical", accent="#86efac", state="below"),
            _critical_angle_panel(start_x + panel_width + gap, panel_y, panel_width, panel_height, title="At critical", accent="#fbbf24", state="equal"),
            _critical_angle_panel(start_x + (panel_width + gap) * 2, panel_y, panel_width, panel_height, title="Above critical", accent="#fda4af", state="above"),
        ]
    )


def _draw_optical_fiber(width: int, height: int) -> str:
    core_x = 210
    core_y = 285
    core_width = width - 420
    core_height = 150
    cladding_padding = 52
    zig_points = [
        (core_x + 34, core_y + 102),
        (core_x + 160, core_y + 42),
        (core_x + 320, core_y + 108),
        (core_x + 480, core_y + 42),
        (core_x + 640, core_y + 108),
        (core_x + 800, core_y + 42),
    ]
    zig_path = "M " + " L ".join(f"{x} {y}" for x, y in zig_points)

    parts = [
        _panel(90, 190, 1100, 340, title="Optical fiber lock-bounce", accent="#93c5fd"),
        _rect(core_x - cladding_padding, core_y - cladding_padding, core_width + (cladding_padding * 2), core_height + (cladding_padding * 2), fill="#1f2937", stroke="#334155", stroke_width=3, rx=34),
        _rect(core_x, core_y, core_width, core_height, fill="#0f766e", stroke="#67e8f9", stroke_width=4, rx=28),
        _text(width / 2, core_y - 74, "cladding: lower index, faster escape zone", fill="#cbd5e1", size=20),
        _text(width / 2, core_y + core_height + 78, "core: higher index, slower route zone", fill="#99f6e4", size=20),
        _path(zig_path, stroke="#fbbf24", stroke_width=7),
        _arrow(zig_points[-2][0], zig_points[-2][1], zig_points[-1][0], zig_points[-1][1], stroke="#fbbf24"),
        _line(core_x + 160, core_y + 42, core_x + 160, core_y - 26, stroke="#38bdf8", stroke_width=4, dashed=True),
        _line(core_x + 320, core_y + 108, core_x + 320, core_y + core_height + 26, stroke="#38bdf8", stroke_width=4, dashed=True),
        _text(core_x + 160, core_y - 40, "meet boundary above critical angle", fill="#bae6fd", size=18),
        _text(core_x + 320, core_y + core_height + 48, "bounce stays inside core", fill="#fde68a", size=18),
        _text(width / 2, 560, "Repeated total internal reflection keeps the route guided down the core.", fill="#cbd5e1", size=22),
    ]
    return "".join(parts)


def _draw_diffraction(width: int, height: int) -> str:
    return "".join(
        [
            _panel(90, 180, 500, 360, title="Wide gate", accent="#93c5fd"),
            _line(340, 235, 340, 320, stroke="#94a3b8", stroke_width=12),
            _line(340, 420, 340, 505, stroke="#94a3b8", stroke_width=12),
            _path("M 190 370 C 250 340 290 340 340 370", stroke="#38bdf8", stroke_width=5),
            _path("M 340 370 C 410 355 470 355 540 370", stroke="#38bdf8", stroke_width=5),
            _path("M 340 370 C 420 340 500 332 560 332", stroke="#7dd3fc", stroke_width=4),
            _path("M 340 370 C 420 400 500 410 560 410", stroke="#7dd3fc", stroke_width=4),
            _text(340, 520, "opening much wider than wavelength -> modest spread", fill="#cbd5e1", size=19),
            _panel(690, 180, 500, 360, title="Narrow gate", accent="#86efac"),
            _line(940, 235, 940, 340, stroke="#94a3b8", stroke_width=12),
            _line(940, 400, 940, 505, stroke="#94a3b8", stroke_width=12),
            _path("M 790 370 C 850 340 890 340 940 370", stroke="#38bdf8", stroke_width=5),
            _path("M 940 370 C 995 330 1065 300 1135 300", stroke="#34d399", stroke_width=4),
            _path("M 940 370 C 1035 350 1100 350 1160 370", stroke="#34d399", stroke_width=4),
            _path("M 940 370 C 995 410 1065 440 1135 470", stroke="#34d399", stroke_width=4),
            _text(940, 520, "opening close to wavelength -> strong spread", fill="#cbd5e1", size=19),
        ]
    )


def _draw_sound_source(width: int, height: int) -> str:
    mid_y = height / 2 + 20
    parts = [
        _panel(100, 180, 1080, 360, title="Vibrating source launches sound", accent="#93c5fd"),
        _rect(180, mid_y - 90, 70, 180, fill="#1d4ed8", rx=16),
        _path(
            f"M 250 {mid_y - 60} Q 320 {mid_y - 20} 250 {mid_y + 20} "
            f"Q 320 {mid_y + 60} 250 {mid_y + 100}",
            stroke="#60a5fa",
            stroke_width=5,
        ),
        _line(150, mid_y - 90, 150, mid_y + 90, stroke="#fbbf24", stroke_width=5, marker_end="wave-arrow"),
        _line(150, mid_y + 90, 150, mid_y - 90, stroke="#fbbf24", stroke_width=5, marker_end="wave-arrow"),
        _text(150, mid_y + 130, "vibration", fill="#fde68a"),
    ]
    for i, x in enumerate(range(390, 1110, 34)):
        scale = 80 if i in {0, 1, 5, 6, 10, 11, 15, 16} else 48
        stroke = "#38bdf8" if scale > 60 else "#cbd5e1"
        parts.append(_line(x, mid_y - scale, x, mid_y + scale, stroke=stroke, stroke_width=3))
    parts.extend(
        [
            _text(620, mid_y - 120, "compression", fill="#93c5fd"),
            _text(780, mid_y - 120, "rarefaction", fill="#cbd5e1"),
            _arrow(420, mid_y + 130, 620, mid_y + 130, stroke="#86efac"),
            _text(520, mid_y + 164, "sound pattern travels", fill="#bbf7d0"),
        ]
    )
    return "".join(parts)


def _draw_frequency_pitch(width: int, height: int) -> str:
    return "".join(
        [
            _panel(90, 180, 500, 360, title="Lower frequency", accent="#93c5fd"),
            f'<polyline points="{_sine_points(140, 540, 360, amplitude=65, cycles=1)}" fill="none" stroke="#38bdf8" stroke-width="5" />',
            _rect(170, 430, 320, 24, fill="#334155", rx=12),
            _rect(170, 430, 200, 24, fill="#f59e0b", rx=12),
            _text(340, 500, "same loudness bar", fill="#cbd5e1", size=20),
            _text(340, 540, "lower pitch", fill="#bfdbfe", size=24, weight="bold"),
            _panel(690, 180, 500, 360, title="Higher frequency", accent="#86efac"),
            f'<polyline points="{_sine_points(740, 1140, 360, amplitude=65, cycles=3)}" fill="none" stroke="#34d399" stroke-width="5" />',
            _rect(770, 430, 320, 24, fill="#334155", rx=12),
            _rect(770, 430, 200, 24, fill="#f59e0b", rx=12),
            _text(940, 500, "same loudness bar", fill="#cbd5e1", size=20),
            _text(940, 540, "higher pitch", fill="#bbf7d0", size=24, weight="bold"),
        ]
    )


def _draw_ultrasound_range(width: int, height: int) -> str:
    axis_y = height / 2 + 20
    left, right = 160, width - 160
    audible_end = 860
    return "".join(
        [
            _panel(90, 200, 1100, 320, title="Audible range and ultrasound", accent="#93c5fd"),
            _line(left, axis_y, right, axis_y, stroke="#94a3b8", stroke_width=6),
            _rect(left, axis_y - 26, audible_end - left, 52, fill="#1d4ed8", rx=18),
            _rect(audible_end, axis_y - 26, right - audible_end, 52, fill="#166534", rx=18),
            _text((left + audible_end) / 2, axis_y + 8, "about 20 Hz to 20 kHz", fill="#dbeafe", size=24, weight="bold"),
            _text((audible_end + right) / 2, axis_y + 8, "ultrasound", fill="#dcfce7", size=24, weight="bold"),
            _line(audible_end, axis_y - 70, audible_end, axis_y + 70, stroke="#fbbf24", stroke_width=5),
            _text(audible_end, axis_y - 86, "20 kHz boundary", fill="#fde68a"),
            _text(width / 2, axis_y + 120, "Ultrasound is still sound. It simply sits above the usual hearing range.", fill="#cbd5e1", size=22),
        ]
    )


def _draw_echo_map(width: int, height: int) -> str:
    probe_x = 220
    probe_y = height / 2 + 20
    boundary_x = 930
    return "".join(
        [
            _panel(90, 180, 1100, 360, title="Pulse echo imaging", accent="#93c5fd"),
            _rect(probe_x - 40, probe_y - 80, 80, 160, fill="#1d4ed8", rx=18),
            _text(probe_x, probe_y + 120, "probe", fill="#dbeafe"),
            _line(probe_x + 40, probe_y - 10, boundary_x, probe_y - 10, stroke="#38bdf8", stroke_width=6, marker_end="wave-arrow"),
            _line(boundary_x, probe_y + 40, probe_x + 40, probe_y + 40, stroke="#fbbf24", stroke_width=6, dashed=True, marker_end="wave-arrow"),
            _line(boundary_x, probe_y - 110, boundary_x, probe_y + 110, stroke="#94a3b8", stroke_width=10),
            _text(boundary_x, probe_y - 132, "hidden boundary", fill="#e2e8f0"),
            _arrow(probe_x + 180, probe_y + 120, boundary_x - 10, probe_y + 120, stroke="#86efac"),
            _text((probe_x + boundary_x) / 2, probe_y + 154, "round trip -> divide by 2 for depth", fill="#bbf7d0", size=22),
            _rect(980, 230, 150, 180, fill="#0f172a", stroke="#475569", stroke_width=3, rx=22),
            _text(1055, 280, "scan", fill="#f8fafc", size=26, weight="bold"),
            _line(1015, 335, 1095, 300, stroke="#38bdf8", stroke_width=5),
            _line(1015, 360, 1095, 360, stroke="#fbbf24", stroke_width=5),
            _line(1015, 385, 1095, 340, stroke="#34d399", stroke_width=5),
        ]
    )


def _draw_doppler_shift(width: int, height: int) -> str:
    return "".join(
        [
            _panel(90, 180, 500, 360, title="Toward the probe", accent="#86efac"),
            _rect(160, 320, 90, 90, fill="#1d4ed8", rx=18),
            _circle(420, 360, 34, fill="#0f172a", stroke="#e2e8f0", stroke_width=4),
            _arrow(370, 360, 300, 360),
            _text(420, 308, "3.002 MHz return", fill="#bbf7d0", size=22),
            _text(340, 452, "higher returned frequency", fill="#cbd5e1", size=20),
            _panel(690, 180, 500, 360, title="Away from the probe", accent="#fda4af"),
            _rect(760, 320, 90, 90, fill="#1d4ed8", rx=18),
            _circle(1020, 360, 34, fill="#0f172a", stroke="#e2e8f0", stroke_width=4),
            _arrow(920, 360, 980, 360),
            _text(1020, 308, "2.998 MHz return", fill="#fecdd3", size=22),
            _text(940, 452, "lower returned frequency", fill="#cbd5e1", size=20),
        ]
    )


def generate_wave_diagram(
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

    body = [_text(width / 2, 70, spec.title or "Wave Diagram", size=34, weight="bold")]
    if spec.subtitle:
        body.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    if spec.wave_type == "transverse_wave":
        body.append(_draw_transverse_wave(spec, width, height))
    elif spec.wave_type == "longitudinal_wave":
        body.append(_draw_longitudinal_wave(spec, width, height))
    elif spec.wave_type == "standing_wave":
        body.append(_draw_standing_wave(spec, width, height))
    elif spec.wave_type == "travel_pattern":
        body.append(_draw_travel_pattern(width, height))
    elif spec.wave_type == "wave_mode_compare":
        body.append(_draw_wave_mode_compare(width, height))
    elif spec.wave_type == "wave_equation":
        body.append(_draw_wave_equation(width, height))
    elif spec.wave_type == "reflection":
        body.append(_draw_reflection(width, height))
    elif spec.wave_type == "refraction":
        body.append(_draw_refraction(width, height))
    elif spec.wave_type == "diffraction":
        body.append(_draw_diffraction(width, height))
    elif spec.wave_type == "sound_source":
        body.append(_draw_sound_source(width, height))
    elif spec.wave_type == "frequency_pitch":
        body.append(_draw_frequency_pitch(width, height))
    elif spec.wave_type == "ultrasound_range":
        body.append(_draw_ultrasound_range(width, height))
    elif spec.wave_type == "echo_map":
        body.append(_draw_echo_map(width, height))
    elif spec.wave_type == "critical_angle":
        body.append(_draw_critical_angle(width, height))
    elif spec.wave_type == "optical_fiber":
        body.append(_draw_optical_fiber(width, height))
    else:
        body.append(_draw_doppler_shift(width, height))

    svg = _svg_header(width, height) + "".join(body) + _svg_footer()

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Wave Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="wave_diagram_agent",
        meta={
            "wave_type": spec.wave_type,
            "amplitude": spec.amplitude,
            "wavelength_count": spec.wavelength_count,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
