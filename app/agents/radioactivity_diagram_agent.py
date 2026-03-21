from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


RadioactivityDiagramType = Literal[
    "vault_house",
    "same_badge_vaults",
    "escape_signals",
    "half_life_crowd",
    "ambient_buzz",
    "decay_ledger",
]


@dataclass
class RadioactivityDiagramSpec:
    diagram_type: RadioactivityDiagramType
    title: str = ""
    subtitle: str = ""
    proton_count: int = 6
    neutron_count: int = 6


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> RadioactivityDiagramSpec:
    meta = _get_meta(req)
    diagram_type = str(meta.get("diagram_type") or "vault_house").strip().lower()
    if diagram_type not in {
        "vault_house",
        "same_badge_vaults",
        "escape_signals",
        "half_life_crowd",
        "ambient_buzz",
        "decay_ledger",
    }:
        raise ValueError(
            "Invalid diagram_type. Use one of: vault_house, same_badge_vaults, "
            "escape_signals, half_life_crowd, ambient_buzz, decay_ledger."
        )

    def _int(name: str, default: int) -> int:
        try:
            return int(meta.get(name, default))
        except Exception:
            return default

    return RadioactivityDiagramSpec(
        diagram_type=diagram_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        proton_count=max(1, _int("proton_count", 6)),
        neutron_count=max(0, _int("neutron_count", 6)),
    )


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="radio-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
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


def _rect(x: float, y: float, w: float, h: float, fill: str, *, stroke: str = "", stroke_width: int = 0) -> str:
    stroke_attr = f' stroke="{stroke}" stroke-width="{stroke_width}"' if stroke else ""
    return f'<rect x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" rx="18" fill="{fill}"{stroke_attr} />'


def _token(cx: float, cy: float, label: str, fill: str, text_fill: str = "#0f172a") -> str:
    return "".join(
        [
            _circle(cx, cy, 18, fill=fill, stroke=fill, stroke_width=0),
            _text(cx, cy + 6, label, fill=text_fill, size=16, weight="bold"),
        ]
    )


def _title_block(spec: RadioactivityDiagramSpec, width: int) -> str:
    parts = [_text(width / 2, 70, spec.title or "Radioactivity Diagram", size=34, weight="bold")]
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))
    return "".join(parts)


def _nucleus_tokens(cx: float, cy: float, protons: int, neutrons: int) -> str:
    parts = [_circle(cx, cy, 86, fill="#111827", stroke="#475569", stroke_width=4)]
    positions = [
        (-34, -28),
        (0, -34),
        (34, -28),
        (-44, 6),
        (-10, 0),
        (24, 8),
        (-26, 38),
        (12, 34),
        (44, 0),
        (0, 52),
        (-56, -8),
        (56, 18),
    ]
    token_index = 0
    for count, label, fill in (
        (protons, "P", "#f87171"),
        (neutrons, "N", "#60a5fa"),
    ):
        for _ in range(count):
            dx, dy = positions[token_index % len(positions)]
            ring = token_index // len(positions)
            parts.append(_token(cx + dx + ring * 8, cy + dy + ring * 8, label, fill))
            token_index += 1
    return "".join(parts)


def _draw_vault_house(spec: RadioactivityDiagramSpec, width: int, height: int) -> str:
    cx = width / 2
    cy = height / 2 + 36
    parts = [
        _circle(cx, cy, 170, stroke="#334155", stroke_width=4),
        _circle(cx, cy, 235, stroke="#1e293b", stroke_width=3, fill="none"),
        _nucleus_tokens(cx, cy, spec.proton_count, spec.neutron_count),
        _text(cx, cy + 4, "Core Vault", size=24, weight="bold"),
        _text(cx, cy + 32, "Nucleus", size=18, fill="#cbd5e1"),
        _circle(cx - 170, cy - 10, 10, fill="#facc15", stroke="#facc15", stroke_width=0),
        _circle(cx + 170, cy + 8, 10, fill="#facc15", stroke="#facc15", stroke_width=0),
        _text(cx + 240, cy - 158, "Orbit Ring", fill="#fde68a", size=22),
        _line(cx + 200, cy - 140, cx + 142, cy - 36, stroke="#fde68a", stroke_width=4, marker_end="radio-arrow"),
        _text(cx - 260, cy - 90, "Identity Badges = protons", fill="#fecaca", anchor="start", size=20),
        _line(cx - 112, cy - 74, cx - 34, cy - 30, stroke="#f87171", stroke_width=4, marker_end="radio-arrow"),
        _text(cx - 260, cy - 40, "Balance Stones = neutrons", fill="#bfdbfe", anchor="start", size=20),
        _line(cx - 112, cy - 26, cx + 18, cy + 6, stroke="#60a5fa", stroke_width=4, marker_end="radio-arrow"),
        _text(cx, height - 52, "The Core Vault fixes identity; the Orbit Ring is outside the nuclear story.", fill="#93c5fd", size=20),
    ]
    return "".join(parts)


def _vault_card(x: float, y: float, title: str, subtitle: str, proton_count: int, neutron_count: int, restless: bool) -> str:
    cx = x + 170
    cy = y + 140
    glow = "#fee2e2" if restless else "#dcfce7"
    label = "restless vault" if restless else "stable vault"
    tone = "#ef4444" if restless else "#16a34a"
    return "".join(
        [
            _rect(x, y, 340, 280, "#111827", stroke=glow, stroke_width=3),
            _text(cx, y + 40, title, size=22, weight="bold"),
            _text(cx, y + 68, subtitle, size=16, fill="#cbd5e1"),
            _nucleus_tokens(cx, cy, proton_count, neutron_count),
            _text(cx, y + 250, f"{label}: {proton_count} badges, {neutron_count} stones", fill=tone, size=18),
        ]
    )


def _draw_same_badge_vaults(width: int, height: int) -> str:
    parts = [
        _vault_card(110, 170, "Same-Badge Vault A", "6 badges, 6 stones", 6, 6, False),
        _vault_card(830, 170, "Same-Badge Vault B", "6 badges, 8 stones", 6, 8, True),
        _text(width / 2, 140, "Same badge count -> same element; different stone count -> different isotope.", fill="#93c5fd", size=22),
        _line(470, 308, 810, 308, stroke="#38bdf8", stroke_width=6, marker_end="radio-arrow"),
        _text(width / 2, 286, "identity stays", fill="#bae6fd", size=18),
        _text(width / 2, 338, "stability can change", fill="#fca5a5", size=18),
    ]
    return "".join(parts)


def _radiation_panel(x: float, y: float, title: str, subtitle: str, color: str, shield: str, penetration: str, symbol: str) -> str:
    parts = [
        _rect(x, y, 340, 300, "#111827", stroke=color, stroke_width=3),
        _text(x + 170, y + 42, title, size=24, weight="bold"),
        _text(x + 170, y + 70, subtitle, size=16, fill="#cbd5e1"),
        _circle(x + 106, y + 156, 54, fill="#1f2937", stroke="#475569", stroke_width=4),
        _text(x + 106, y + 162, "vault", size=18, fill="#cbd5e1"),
        _line(x + 164, y + 156, x + 256, y + 156, stroke=color, stroke_width=7, marker_end="radio-arrow"),
        _text(x + 274, y + 162, symbol, fill=color, size=26, weight="bold"),
        _rect(x + 82, y + 214, 176, 32, "#0f172a", stroke="#334155", stroke_width=2),
        _text(x + 170, y + 236, shield, size=16, fill="#fde68a"),
        _text(x + 170, y + 274, penetration, size=16, fill="#cbd5e1"),
    ]
    return "".join(parts)


def _draw_escape_signals(width: int, height: int) -> str:
    parts = [
        _radiation_panel(60, 180, "Chunk Burst", "alpha radiation", "#f97316", "stopped by paper / skin", "lowest penetration", "alpha"),
        _radiation_panel(470, 180, "Switch Spark", "beta radiation", "#38bdf8", "stopped by foil / plastic", "medium penetration", "beta"),
        _radiation_panel(880, 180, "Glow Flash", "gamma radiation", "#a78bfa", "needs dense shielding", "highest penetration", "gamma"),
        _text(width / 2, 140, "Each escape signal leaves the restless vault in a different way and penetrates differently.", fill="#93c5fd", size=22),
    ]
    return "".join(parts)


def _crowd_column(x: float, top_y: float, count: int, label: str, color: str) -> str:
    parts = [_text(x, top_y - 24, label, size=18, fill="#cbd5e1")]
    token_y = top_y
    token_x = x - 36
    for index in range(count):
        parts.append(_circle(token_x + (index % 4) * 24, token_y + (index // 4) * 24, 8, fill=color, stroke=color, stroke_width=0))
    parts.append(_text(x, top_y + 112, f"{count} restless vaults remain", size=18, fill="#f8fafc"))
    return "".join(parts)


def _draw_half_life_crowd(width: int, height: int) -> str:
    base_y = 250
    cols = [
        (210, 16, "0 settle spans"),
        (470, 8, "1 settle span"),
        (730, 4, "2 settle spans"),
        (990, 2, "3 settle spans"),
    ]
    parts = [
        _text(width / 2, 148, "Settle Span is a crowd rule: equal intervals cut the undecayed group by half.", fill="#93c5fd", size=22),
    ]
    for x, count, label in cols:
        parts.append(_crowd_column(x, base_y, count, label, "#f87171"))
    parts.append(_line(210, 428, 990, 428, stroke="#334155", stroke_width=3))
    parts.append(_text(width / 2, height - 58, "A single vault decays randomly, but a large crowd shows a predictable halving pattern.", fill="#cbd5e1", size=20))
    return "".join(parts)


def _draw_ambient_buzz(width: int, height: int) -> str:
    cx = width / 2
    cy = height / 2 + 18
    parts = [
        _rect(cx - 90, cy - 86, 180, 172, "#111827", stroke="#93c5fd", stroke_width=3),
        _text(cx, cy - 36, "Detector", size=24, weight="bold"),
        _text(cx, cy + 10, "Ambient Buzz", fill="#fde68a", size=22),
        _text(cx, cy + 46, "12 counts / min", fill="#f8fafc", size=26, weight="bold"),
        _text(200, 178, "cosmic rays", fill="#bfdbfe", size=20),
        _line(230, 190, cx - 96, cy - 64, stroke="#38bdf8", stroke_width=4, marker_end="radio-arrow"),
        _text(205, 492, "rocks and soil", fill="#bfdbfe", size=20),
        _line(250, 476, cx - 96, cy + 68, stroke="#38bdf8", stroke_width=4, marker_end="radio-arrow"),
        _text(1070, 186, "food and body", fill="#bfdbfe", size=20),
        _line(1018, 196, cx + 96, cy - 42, stroke="#38bdf8", stroke_width=4, marker_end="radio-arrow"),
        _text(1060, 492, "air and buildings", fill="#bfdbfe", size=20),
        _line(1000, 476, cx + 96, cy + 74, stroke="#38bdf8", stroke_width=4, marker_end="radio-arrow"),
        _text(width / 2, 138, "A detector is rarely silent because background radiation is always present.", fill="#93c5fd", size=22),
    ]
    return "".join(parts)


def _ledger_row(y: float, label: str, before: str, after: str, change: str, color: str) -> str:
    return "".join(
        [
            _text(126, y + 18, label, fill=color, size=22, weight="bold"),
            _rect(220, y - 12, 256, 58, "#111827", stroke="#334155", stroke_width=2),
            _text(348, y + 24, before, size=20),
            _line(490, y + 16, 620, y + 16, stroke="#38bdf8", stroke_width=5, marker_end="radio-arrow"),
            _rect(650, y - 12, 256, 58, "#111827", stroke="#334155", stroke_width=2),
            _text(778, y + 24, after, size=20),
            _text(1080, y + 24, change, fill="#cbd5e1", size=18),
        ]
    )


def _draw_decay_ledger(width: int, height: int) -> str:
    parts = [
        _text(width / 2, 146, "Vault Ledger: badge count and total core-piece count must balance across the arrow.", fill="#93c5fd", size=22),
        _ledger_row(220, "alpha", "badges 84 | total 210", "badges 82 | total 206", "-2 badges, -4 total", "#f97316"),
        _ledger_row(330, "beta", "badges 6 | total 14", "badges 7 | total 14", "+1 badge, total same", "#38bdf8"),
        _ledger_row(440, "gamma", "badges 27 | total 60*", "badges 27 | total 60", "counts unchanged", "#a78bfa"),
        _text(width / 2, height - 64, "Alpha changes both counts, beta changes badge count only, gamma changes the energy state only.", fill="#e2e8f0", size=20),
    ]
    return "".join(parts)


def generate_radioactivity_diagram(
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

    body = [_title_block(spec, width)]
    if spec.diagram_type == "vault_house":
        body.append(_draw_vault_house(spec, width, height))
    elif spec.diagram_type == "same_badge_vaults":
        body.append(_draw_same_badge_vaults(width, height))
    elif spec.diagram_type == "escape_signals":
        body.append(_draw_escape_signals(width, height))
    elif spec.diagram_type == "half_life_crowd":
        body.append(_draw_half_life_crowd(width, height))
    elif spec.diagram_type == "ambient_buzz":
        body.append(_draw_ambient_buzz(width, height))
    else:
        body.append(_draw_decay_ledger(width, height))

    svg = _svg_header(width, height) + "".join(body) + _svg_footer()
    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Radioactivity Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="radioactivity_diagram_agent",
        meta={
            "diagram_type": spec.diagram_type,
            "proton_count": spec.proton_count,
            "neutron_count": spec.neutron_count,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
