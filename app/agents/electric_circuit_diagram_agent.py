from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


CircuitType = Literal[
    "simple_series",
    "parallel_lamps",
    "ammeter_voltmeter",
    "charge_current_loop",
    "potential_difference",
    "resistance_iv",
    "power_safety",
    "carrier_loop",
    "checkpoint_rate",
    "voltage_boost",
    "resistance_route",
    "ohmic_rule",
    "loop_ledger",
]


@dataclass
class ElectricCircuitDiagramSpec:
    circuit_type: CircuitType
    title: str = ""
    subtitle: str = ""
    show_current_arrows: bool = True
    closed_switch: bool = True


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> ElectricCircuitDiagramSpec:
    meta = _get_meta(req)

    circuit_type = str(meta.get("circuit_type") or "simple_series").strip().lower()
    if circuit_type not in {
        "simple_series",
        "parallel_lamps",
        "ammeter_voltmeter",
        "charge_current_loop",
        "potential_difference",
        "resistance_iv",
        "power_safety",
        "carrier_loop",
        "checkpoint_rate",
        "voltage_boost",
        "resistance_route",
        "ohmic_rule",
        "loop_ledger",
    }:
        raise ValueError(
            "Invalid circuit_type. Use one of: simple_series, parallel_lamps, "
            "ammeter_voltmeter, charge_current_loop, potential_difference, "
            "resistance_iv, power_safety, carrier_loop, checkpoint_rate, "
            "voltage_boost, resistance_route, ohmic_rule, loop_ledger."
        )

    return ElectricCircuitDiagramSpec(
        circuit_type=circuit_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        show_current_arrows=bool(meta.get("show_current_arrows", True)),
        closed_switch=bool(meta.get("closed_switch", True)),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="current-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#fbbf24" />
    </marker>
    <marker id="energy-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#34d399" />
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
    stroke_width: int = 5,
    dashed: bool = False,
    marker_end: str = "",
) -> str:
    dash_attr = ' stroke-dasharray="10 8"' if dashed else ""
    marker_attr = f' marker-end="url(#{marker_end})"' if marker_end else ""
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}" stroke-linecap="round"{dash_attr}{marker_attr} />'
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
    cx: float,
    cy: float,
    r: float,
    *,
    fill: str = "none",
    stroke: str = "#e2e8f0",
    stroke_width: int = 4,
) -> str:
    return (
        f'<circle cx="{cx:.2f}" cy="{cy:.2f}" r="{r:.2f}" '
        f'fill="{fill}" stroke="{stroke}" stroke-width="{stroke_width}" />'
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


def _battery(x: float, y_top: float, y_bottom: float) -> str:
    mid = (y_top + y_bottom) / 2
    return "".join(
        [
            _line(x, y_top, x, mid - 28),
            _line(x, mid + 28, x, y_bottom),
            _line(x - 18, mid - 18, x + 18, mid - 18, stroke="#60a5fa", stroke_width=4),
            _line(x - 8, mid + 18, x + 8, mid + 18, stroke="#60a5fa", stroke_width=4),
        ]
    )


def _resistor(x1: float, x2: float, y: float, *, color: str = "#f97316") -> str:
    points = [
        (x1, y),
        (x1 + 18, y - 18),
        (x1 + 36, y + 18),
        (x1 + 54, y - 18),
        (x1 + 72, y + 18),
        (x1 + 90, y - 18),
        (x2, y),
    ]
    pts = " ".join(f"{x:.2f},{yy:.2f}" for x, yy in points)
    return f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="5" />'


def _switch(x1: float, x2: float, y: float, closed: bool) -> str:
    if closed:
        return "".join(
            [
                _line(x1, y, x1 + 24, y),
                _line(x1 + 24, y, x2 - 24, y, stroke="#22c55e"),
                _line(x2 - 24, y, x2, y),
            ]
        )
    return "".join(
        [
            _line(x1, y, x1 + 24, y),
            _line(x1 + 24, y, x2 - 18, y - 22, stroke="#ef4444"),
            _line(x2 - 10, y, x2, y),
        ]
    )


def _lamp(cx: float, cy: float, *, r: float = 28) -> str:
    return "".join(
        [
            _circle(cx, cy, r),
            _line(cx - 16, cy - 16, cx + 16, cy + 16, stroke="#facc15", stroke_width=4),
            _line(cx - 16, cy + 16, cx + 16, cy - 16, stroke="#facc15", stroke_width=4),
        ]
    )


def _meter(cx: float, cy: float, label: str) -> str:
    return "".join(
        [
            _circle(cx, cy, 30, fill="#111827", stroke="#93c5fd"),
            _text(cx, cy + 8, label, fill="#dbeafe", size=26, weight="bold"),
        ]
    )


def _current_arrow(x1: float, y1: float, x2: float, y2: float) -> str:
    return _line(x1, y1, x2, y2, stroke="#fbbf24", stroke_width=4, marker_end="current-arrow")


def _token(cx: float, cy: float, label: str = "q") -> str:
    return "".join(
        [
            _circle(cx, cy, 18, fill="#0f172a", stroke="#22c55e", stroke_width=4),
            _text(cx, cy + 6, label, fill="#bbf7d0", size=18, weight="bold"),
        ]
    )


def _card(x: float, y: float, width: float, height: float, *, title: str, accent: str) -> str:
    return "".join(
        [
            _rect(x, y, width, height, fill="#111827", stroke="#334155", stroke_width=3, rx=26),
            _text(x + 28, y + 40, title, fill=accent, size=24, anchor="start", weight="bold"),
        ]
    )


def _draw_simple_series(spec: ElectricCircuitDiagramSpec, width: int, height: int) -> str:
    left, right = 140, width - 140
    top, bottom = 220, height - 160
    battery_x = left
    switch_x1, switch_x2 = 250, 380
    lamp_x = 580
    resistor_x1, resistor_x2 = 820, 980

    parts = [
        _line(left, top, switch_x1, top),
        _switch(switch_x1, switch_x2, top, spec.closed_switch),
        _line(switch_x2, top, lamp_x - 28, top),
        _lamp(lamp_x, top),
        _line(lamp_x + 28, top, resistor_x1, top),
        _resistor(resistor_x1, resistor_x2, top),
        _line(resistor_x2, top, right, top),
        _line(right, top, right, bottom),
        _line(right, bottom, left, bottom),
        _line(left, bottom, left, bottom - 80),
        _battery(battery_x, top + 20, bottom - 20),
        _text(lamp_x, top - 42, "Lamp", fill="#fde68a"),
        _text((resistor_x1 + resistor_x2) / 2, top - 42, "Resistor", fill="#fdba74"),
        _text(switch_x1 + 65, top - 42, "Switch", fill="#86efac"),
        _text(left - 32, (top + bottom) / 2 + 8, "Cell", fill="#93c5fd", anchor="end"),
    ]

    if spec.show_current_arrows:
        parts.extend(
            [
                _current_arrow(430, top - 26, 520, top - 26),
                _current_arrow(right + 26, 280, right + 26, 380),
                _current_arrow(840, bottom + 26, 720, bottom + 26),
            ]
        )

    return "".join(parts)


def _draw_parallel_lamps(spec: ElectricCircuitDiagramSpec, width: int, height: int) -> str:
    left, right = 150, width - 150
    top, bottom = 200, height - 140
    mid_x1, mid_x2 = 350, right - 160
    upper_y, lower_y = 260, 430

    parts = [
        _line(left, top, left + 80, top),
        _line(left, bottom, left + 80, bottom),
        _battery(left, top + 10, bottom - 10),
        _line(left + 80, top, mid_x1, top),
        _line(left + 80, bottom, mid_x1, bottom),
        _line(mid_x1, top, mid_x1, upper_y),
        _line(mid_x1, upper_y, mid_x1, lower_y),
        _line(mid_x1, lower_y, mid_x1, bottom),
        _line(mid_x2, top, mid_x2, upper_y),
        _line(mid_x2, upper_y, mid_x2, lower_y),
        _line(mid_x2, lower_y, mid_x2, bottom),
        _line(mid_x2, top, right, top),
        _line(mid_x2, bottom, right, bottom),
        _line(right, top, right, bottom),
        _line(mid_x1, upper_y, 500, upper_y),
        _lamp(590, upper_y),
        _line(618, upper_y, mid_x2, upper_y),
        _line(mid_x1, lower_y, 500, lower_y),
        _lamp(590, lower_y),
        _line(618, lower_y, mid_x2, lower_y),
        _text(590, upper_y - 46, "Lamp 1", fill="#fde68a"),
        _text(590, lower_y - 46, "Lamp 2", fill="#fde68a"),
        _text(left - 26, (top + bottom) / 2 + 8, "Cell", fill="#93c5fd", anchor="end"),
    ]

    if spec.show_current_arrows:
        parts.extend(
            [
                _current_arrow(420, upper_y - 24, 520, upper_y - 24),
                _current_arrow(420, lower_y - 24, 520, lower_y - 24),
            ]
        )

    return "".join(parts)


def _draw_ammeter_voltmeter(spec: ElectricCircuitDiagramSpec, width: int, height: int) -> str:
    left, right = 140, width - 140
    top, bottom = 220, height - 150
    battery_x = left
    ammeter_x = 340
    resistor_x1, resistor_x2 = 650, 830
    voltmeter_x = 740
    voltmeter_y = 430

    parts = [
        _line(left, top, ammeter_x - 30, top),
        _meter(ammeter_x, top, "A"),
        _line(ammeter_x + 30, top, resistor_x1, top),
        _resistor(resistor_x1, resistor_x2, top),
        _line(resistor_x2, top, right, top),
        _line(right, top, right, bottom),
        _line(right, bottom, left, bottom),
        _line(left, bottom, left, bottom - 80),
        _battery(battery_x, top + 20, bottom - 20),
        _line(resistor_x1 + 10, top, resistor_x1 + 10, voltmeter_y - 30),
        _line(resistor_x2 - 10, top, resistor_x2 - 10, voltmeter_y - 30),
        _line(resistor_x1 + 10, voltmeter_y - 30, voltmeter_x - 30, voltmeter_y - 30),
        _line(resistor_x2 - 10, voltmeter_y - 30, voltmeter_x + 30, voltmeter_y - 30),
        _meter(voltmeter_x, voltmeter_y, "V"),
        _text(ammeter_x, top - 46, "Ammeter", fill="#bfdbfe"),
        _text((resistor_x1 + resistor_x2) / 2, top - 46, "Resistor", fill="#fdba74"),
        _text(voltmeter_x, voltmeter_y + 58, "Voltmeter across resistor", fill="#ddd6fe"),
    ]

    if spec.show_current_arrows:
        parts.append(_current_arrow(420, top - 24, 560, top - 24))

    return "".join(parts)


def _draw_charge_current_loop(width: int, height: int) -> str:
    left, right = 170, width - 170
    top, bottom = 220, height - 170
    lamp_x = right - 120
    y_mid = (top + bottom) / 2

    parts = [
        _line(left, top, lamp_x - 34, top, stroke="#cbd5e1"),
        _lamp(lamp_x, top),
        _line(lamp_x + 34, top, right, top, stroke="#cbd5e1"),
        _line(right, top, right, bottom, stroke="#cbd5e1"),
        _line(right, bottom, left, bottom, stroke="#cbd5e1"),
        _line(left, bottom, left, bottom - 88, stroke="#cbd5e1"),
        _battery(left, top + 24, bottom - 24),
        _text(left - 34, y_mid + 6, "Cell", fill="#93c5fd", anchor="end"),
        _text(lamp_x, top - 46, "Lamp", fill="#fde68a"),
        _text((left + lamp_x) / 2, top - 54, "same I here", fill="#fde68a", size=22),
        _text((lamp_x + right) / 2, top + 58, "same I here", fill="#fde68a", size=22),
    ]

    for cx in (330, 430, 530, 630):
        parts.append(_token(cx, top, "q"))

    parts.extend(
        [
            _current_arrow(270, top - 28, 390, top - 28),
            _current_arrow(690, top - 28, 810, top - 28),
            _text(420, bottom + 52, "Current is charge per second, not charge used up.", fill="#cbd5e1", size=22),
        ]
    )
    return "".join(parts)


def _draw_potential_difference(width: int, height: int) -> str:
    left, right = 170, width - 170
    top, bottom = 230, height - 180
    resistor_x1, resistor_x2 = 760, 960

    parts = [
        _line(left, top, resistor_x1, top),
        _resistor(resistor_x1, resistor_x2, top),
        _line(resistor_x2, top, right, top),
        _line(right, top, right, bottom),
        _line(right, bottom, left, bottom),
        _line(left, bottom, left, bottom - 90),
        _battery(left, top + 24, bottom - 24),
        _token(300, top, "q"),
        _token(520, top, "q"),
        _token(1040, top, "q"),
        _line(left + 60, top - 84, 520, top - 84, stroke="#34d399", stroke_width=5, marker_end="energy-arrow"),
        _text(315, top - 108, "+6 J/C at the cell", fill="#86efac", size=22),
        _line(760, top + 84, 1040, top + 84, stroke="#f87171", stroke_width=5, marker_end="current-arrow"),
        _text(900, top + 118, "-6 J/C at the resistor", fill="#fca5a5", size=22),
        _text(860, top - 46, "Resistor", fill="#fdba74"),
        _text(left - 30, (top + bottom) / 2 + 6, "Cell", fill="#93c5fd", anchor="end"),
        _text(width / 2, bottom + 56, "Potential difference = energy transferred per coulomb.", fill="#cbd5e1", size=22),
    ]
    return "".join(parts)


def _draw_resistance_iv(width: int, height: int) -> str:
    parts = [
        _card(90, 180, 470, 380, title="Route response", accent="#fdba74"),
        _line(170, 300, 430, 300),
        _resistor(430, 520, 300),
        _line(170, 440, 370, 440),
        _resistor(370, 520, 440, color="#fb7185"),
        _current_arrow(210, 268, 330, 268),
        _current_arrow(210, 408, 280, 408),
        _text(308, 242, "low R -> larger I", fill="#fde68a"),
        _text(290, 482, "high R -> smaller I", fill="#fda4af"),
        _card(650, 180, 540, 380, title="I-V view", accent="#93c5fd"),
        _line(740, 500, 1110, 500, stroke="#94a3b8", stroke_width=4),
        _line(740, 500, 740, 250, stroke="#94a3b8", stroke_width=4),
        _path("M 760 470 L 1030 300", stroke="#60a5fa", stroke_width=8),
        _path("M 760 470 L 920 330", stroke="#fb7185", stroke_width=8),
        _text(1040, 300, "lower resistance", fill="#bfdbfe", anchor="start"),
        _text(930, 330, "higher resistance", fill="#fecdd3", anchor="start"),
        _text(1116, 510, "V", fill="#cbd5e1", anchor="start"),
        _text(730, 244, "I", fill="#cbd5e1"),
    ]
    return "".join(parts)


def _draw_power_safety(width: int, height: int) -> str:
    parts = [
        _card(100, 200, 460, 340, title="Same voltage, different current", accent="#fbbf24"),
        _rect(150, 300, 120, 160, fill="#1d4ed8"),
        _rect(360, 270, 120, 190, fill="#f97316"),
        _text(210, 286, "2 A", fill="#dbeafe", size=24, weight="bold"),
        _text(420, 256, "5 A", fill="#ffedd5", size=24, weight="bold"),
        _text(210, 495, "lower power", fill="#bfdbfe", size=22),
        _text(420, 495, "higher power", fill="#fdba74", size=22),
        _card(660, 200, 520, 340, title="Protection path", accent="#fca5a5"),
        _line(760, 360, 1080, 360, stroke="#ef4444", stroke_width=10),
        _line(900, 300, 940, 420, stroke="#f8fafc", stroke_width=8),
        _rect(840, 270, 160, 180, fill="#111827", stroke="#475569", stroke_width=3, rx=24),
        _text(920, 340, "Fuse / breaker", fill="#f8fafc", size=26, weight="bold"),
        _text(920, 388, "opens if current", fill="#fca5a5", size=22),
        _text(920, 420, "becomes unsafe", fill="#fca5a5", size=22),
        _text(width / 2, 610, "Power is an energy-transfer rate. Protection stops dangerous current.", fill="#cbd5e1", size=22),
    ]
    return "".join(parts)


def _draw_carrier_loop(spec: ElectricCircuitDiagramSpec, width: int, height: int) -> str:
    left, right = 120, 760
    top, bottom = 220, 520
    panel_x = 870
    panel_y = 230

    parts = [
        _line(left, top, right, top),
        _line(right, top, right, bottom),
        _line(right, bottom, left, bottom),
        _line(left, bottom, left, bottom - 80),
        _battery(left, top + 24, bottom - 24),
        _switch(430, 570, top, spec.closed_switch),
        _text(500, top - 40, "Loop status", fill="#86efac"),
        _text(500, top + 54, "closed" if spec.closed_switch else "open", fill="#bbf7d0" if spec.closed_switch else "#fecaca", size=22, weight="bold"),
        _text(left - 30, 372, "Cell", fill="#93c5fd", anchor="end"),
        _text(640, bottom + 54, "Charge carriers keep existing even when the route opens.", fill="#cbd5e1", size=21),
        _card(panel_x, panel_y, 300, 250, title="Checkpoint", accent="#fde68a"),
        _rect(panel_x + 78, panel_y + 90, 144, 88, fill="#0f172a", stroke="#475569", stroke_width=3, rx=18),
        _text(panel_x + 150, panel_y + 144, "I", fill="#fde68a", size=38, weight="bold"),
        _text(panel_x + 150, panel_y + 186, "rate meter", fill="#cbd5e1", size=20),
        _text(panel_x + 150, panel_y + 226, "carriers are amount", fill="#86efac", size=20),
    ]

    for cx in (250, 340, 610, 690):
        parts.append(_token(cx, top, "q"))
    for cx in (260, 360, 470, 600):
        parts.append(_token(cx, bottom, "q"))

    parts.append(_current_arrow(250, top - 28, 380, top - 28))
    parts.append(_current_arrow(630, bottom + 28, 500, bottom + 28))
    return "".join(parts)


def _draw_checkpoint_rate(width: int, height: int) -> str:
    parts = [
        _card(110, 200, 480, 340, title="Charge amount", accent="#86efac"),
        _rect(180, 310, 320, 110, fill="#0f172a", stroke="#475569", stroke_width=3, rx=24),
        _token(230, 365, "q"),
        _token(320, 365, "q"),
        _token(410, 365, "q"),
        _text(350, 462, "Many carriers can still mean a small current.", fill="#bbf7d0", size=22),
        _card(680, 200, 500, 340, title="Checkpoint rate", accent="#fde68a"),
        _line(770, 365, 1100, 365, stroke="#e2e8f0", stroke_width=8),
        _rect(910, 290, 18, 150, fill="#fbbf24", rx=8),
        _current_arrow(790, 330, 900, 330),
        _current_arrow(790, 400, 860, 400),
        _text(930, 268, "1 A = 1 C/s", fill="#fde68a", size=24),
        _text(930, 480, "I = Q / t", fill="#f8fafc", size=32, weight="bold"),
    ]
    return "".join(parts)


def _draw_voltage_boost(width: int, height: int) -> str:
    parts = [
        _card(120, 210, 450, 330, title="3 J/C source", accent="#93c5fd"),
        _token(245, 360, "q"),
        _line(280, 360, 430, 360, stroke="#34d399", stroke_width=6, marker_end="energy-arrow"),
        _text(345, 330, "+3 J/C", fill="#86efac", size=24, weight="bold"),
        _text(345, 448, "smaller boost per carrier", fill="#cbd5e1", size=22),
        _card(710, 210, 450, 330, title="9 J/C source", accent="#60a5fa"),
        _token(835, 360, "q"),
        _line(870, 360, 1070, 360, stroke="#34d399", stroke_width=6, marker_end="energy-arrow"),
        _text(970, 330, "+9 J/C", fill="#86efac", size=24, weight="bold"),
        _text(970, 448, "larger boost per carrier", fill="#cbd5e1", size=22),
        _text(width / 2, 600, "Voltage is energy transferred per charge, not stored current.", fill="#cbd5e1", size=22),
    ]
    return "".join(parts)


def _draw_resistance_route(width: int, height: int) -> str:
    parts = [
        _card(90, 190, 500, 360, title="Lower resistance route", accent="#86efac"),
        _line(170, 330, 500, 330, stroke="#34d399", stroke_width=16),
        _line(170, 420, 500, 420, stroke="#38bdf8", stroke_width=10),
        _text(335, 305, "short + wide", fill="#bbf7d0", size=24, weight="bold"),
        _text(335, 470, "easier path for carriers", fill="#cbd5e1", size=22),
        _card(690, 190, 500, 360, title="Higher resistance route", accent="#fda4af"),
        _line(760, 300, 1110, 300, stroke="#fb7185", stroke_width=8),
        _line(760, 420, 1110, 420, stroke="#f97316", stroke_width=18, dashed=True),
        _text(935, 275, "long + narrow + rough", fill="#fecdd3", size=24, weight="bold"),
        _text(935, 470, "same source, smaller current", fill="#cbd5e1", size=22),
    ]
    return "".join(parts)


def _draw_ohmic_rule(width: int, height: int) -> str:
    parts = [
        _card(110, 190, 470, 360, title="Fixed resistance", accent="#bfdbfe"),
        _text(345, 270, "raise V -> raise I", fill="#dbeafe", size=28, weight="bold"),
        _line(190, 380, 470, 380, stroke="#94a3b8", stroke_width=4),
        _line(190, 380, 190, 250, stroke="#94a3b8", stroke_width=4),
        _path("M 210 360 L 450 280", stroke="#60a5fa", stroke_width=8),
        _text(470, 282, "ohmic line", fill="#bfdbfe", anchor="start"),
        _card(700, 190, 470, 360, title="Fixed voltage", accent="#fdba74"),
        _text(935, 270, "raise R -> lower I", fill="#fed7aa", size=28, weight="bold"),
        _rect(790, 340, 110, 90, fill="#0f172a", stroke="#475569", stroke_width=3, rx=20),
        _rect(980, 300, 110, 130, fill="#0f172a", stroke="#475569", stroke_width=3, rx=20),
        _text(845, 394, "2 ohm", fill="#f8fafc", size=24, weight="bold"),
        _text(1035, 372, "6 ohm", fill="#f8fafc", size=24, weight="bold"),
        _text(845, 452, "larger I", fill="#fde68a", size=21),
        _text(1035, 452, "smaller I", fill="#fde68a", size=21),
        _text(width / 2, 606, "Ohm's law is a relationship between voltage, resistance, and current.", fill="#cbd5e1", size=22),
    ]
    return "".join(parts)


def _draw_loop_ledger(width: int, height: int) -> str:
    parts = [
        _card(80, 180, 540, 380, title="Loop A", accent="#86efac"),
        _line(150, 300, 510, 300),
        _resistor(390, 510, 300),
        _line(510, 300, 550, 300),
        _line(550, 300, 550, 470),
        _line(550, 470, 150, 470),
        _line(150, 470, 150, 380),
        _battery(150, 324, 446),
        _text(380, 260, "same source: 8 V", fill="#bbf7d0", size=22),
        _text(390, 520, "R = 2 ohm  ->  I = 4 A", fill="#bbf7d0", size=24, weight="bold"),
        _card(660, 180, 540, 380, title="Loop B", accent="#fda4af"),
        _line(730, 300, 1090, 300),
        _resistor(930, 1090, 300, color="#fb7185"),
        _line(1090, 300, 1130, 300),
        _line(1130, 300, 1130, 470),
        _line(1130, 470, 730, 470),
        _line(730, 470, 730, 380),
        _battery(730, 324, 446),
        _text(960, 260, "same source: 8 V", fill="#fecdd3", size=22),
        _text(960, 520, "R = 4 ohm  ->  I = 2 A", fill="#fecdd3", size=24, weight="bold"),
        _rect(420, 70, 420, 70, fill="#111827", stroke="#334155", stroke_width=3, rx=22),
        _text(630, 115, "Ledger: Q moves, V boosts, R limits, I responds.", fill="#e2e8f0", size=24, weight="bold"),
    ]
    return "".join(parts)


def generate_electric_circuit_diagram(
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

    body = [
        _text(width / 2, 70, spec.title or "Electric Circuit Diagram", size=34, weight="bold"),
    ]
    if spec.subtitle:
        body.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    if spec.circuit_type == "simple_series":
        body.append(_draw_simple_series(spec, width, height))
    elif spec.circuit_type == "parallel_lamps":
        body.append(_draw_parallel_lamps(spec, width, height))
    elif spec.circuit_type == "ammeter_voltmeter":
        body.append(_draw_ammeter_voltmeter(spec, width, height))
    elif spec.circuit_type == "charge_current_loop":
        body.append(_draw_charge_current_loop(width, height))
    elif spec.circuit_type == "potential_difference":
        body.append(_draw_potential_difference(width, height))
    elif spec.circuit_type == "resistance_iv":
        body.append(_draw_resistance_iv(width, height))
    elif spec.circuit_type == "power_safety":
        body.append(_draw_power_safety(width, height))
    elif spec.circuit_type == "carrier_loop":
        body.append(_draw_carrier_loop(spec, width, height))
    elif spec.circuit_type == "checkpoint_rate":
        body.append(_draw_checkpoint_rate(width, height))
    elif spec.circuit_type == "voltage_boost":
        body.append(_draw_voltage_boost(width, height))
    elif spec.circuit_type == "resistance_route":
        body.append(_draw_resistance_route(width, height))
    elif spec.circuit_type == "ohmic_rule":
        body.append(_draw_ohmic_rule(width, height))
    else:
        body.append(_draw_loop_ledger(width, height))

    svg = _svg_header(width, height) + "".join(body) + _svg_footer()

    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Electric Circuit Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="electric_circuit_diagram_agent",
        meta={
            "circuit_type": spec.circuit_type,
            "show_current_arrows": spec.show_current_arrows,
            "closed_switch": spec.closed_switch,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
