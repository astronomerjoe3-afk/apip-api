from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


def _wrap_svg(content: str, width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">\n'
        '  <rect width="100%" height="100%" fill="#0b1020"/>\n'
        f"{content}\n"
        "</svg>\n"
    )


def _heading(req: DiagramRequest) -> str:
    return f"""
  <text x="640" y="80" fill="white" text-anchor="middle" font-size="36" font-family="Arial" font-weight="bold">
    {escape(req.title or req.concept)}
  </text>
  <text x="640" y="120" fill="#aab4d4" text-anchor="middle" font-size="20" font-family="Arial">
    {escape(req.description)}
  </text>
"""


def _prefix_scale_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <rect x="520" y="180" width="240" height="80" rx="18" fill="#1e3a8a"/>
  <text x="640" y="228" fill="white" text-anchor="middle" font-size="28" font-family="Arial" font-weight="bold">kilo</text>
  <text x="640" y="252" fill="#dbeafe" text-anchor="middle" font-size="18" font-family="Arial">x 1000</text>

  <line x1="640" y1="260" x2="640" y2="340" stroke="#93c5fd" stroke-width="6"/>
  <polygon points="640,360 625,330 655,330" fill="#93c5fd"/>

  <rect x="520" y="360" width="240" height="80" rx="18" fill="#14532d"/>
  <text x="640" y="408" fill="white" text-anchor="middle" font-size="28" font-family="Arial" font-weight="bold">base unit</text>
  <text x="640" y="432" fill="#dcfce7" text-anchor="middle" font-size="18" font-family="Arial">meter / gram / second</text>

  <line x1="640" y1="440" x2="640" y2="520" stroke="#86efac" stroke-width="6"/>
  <polygon points="640,540 625,510 655,510" fill="#86efac"/>

  <rect x="520" y="540" width="240" height="80" rx="18" fill="#7c2d12"/>
  <text x="640" y="588" fill="white" text-anchor="middle" font-size="28" font-family="Arial" font-weight="bold">milli</text>
  <text x="640" y="612" fill="#ffedd5" text-anchor="middle" font-size="18" font-family="Arial">x 0.001</text>
""",
        req.width,
        req.height,
    )


def _tool_trust_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <rect x="140" y="220" width="360" height="220" rx="22" fill="#3f3f46"/>
  <text x="320" y="280" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Rough ruler</text>
  <text x="320" y="330" fill="#f4f4f5" text-anchor="middle" font-size="22" font-family="Arial">+/- 1 cm</text>
  <text x="320" y="380" fill="#d4d4d8" text-anchor="middle" font-size="18" font-family="Arial">Lower trust</text>

  <rect x="780" y="220" width="360" height="220" rx="22" fill="#1d4ed8"/>
  <text x="960" y="280" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Precision caliper</text>
  <text x="960" y="330" fill="#eff6ff" text-anchor="middle" font-size="22" font-family="Arial">+/- 0.01 cm</text>
  <text x="960" y="380" fill="#dbeafe" text-anchor="middle" font-size="18" font-family="Arial">Higher trust</text>

  <line x1="500" y1="330" x2="780" y2="330" stroke="#facc15" stroke-width="8"/>
  <polygon points="780,330 744,312 744,348" fill="#facc15"/>
""",
        req.width,
        req.height,
    )


def _energy_transfer_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <rect x="110" y="210" width="430" height="300" rx="28" fill="#111827" stroke="#374151" stroke-width="3"/>
  <text x="325" y="260" fill="#f8fafc" text-anchor="middle" font-size="28" font-family="Arial" font-weight="bold">Force only</text>
  <rect x="210" y="335" width="120" height="80" rx="12" fill="#475569"/>
  <rect x="330" y="305" width="90" height="110" rx="12" fill="#334155"/>
  <line x1="120" y1="375" x2="200" y2="375" stroke="#ef4444" stroke-width="12"/>
  <polygon points="200,375 170,358 170,392" fill="#ef4444"/>
  <text x="325" y="460" fill="#fca5a5" text-anchor="middle" font-size="22" font-family="Arial">No displacement, so no work transfer</text>

  <rect x="740" y="210" width="430" height="300" rx="28" fill="#111827" stroke="#374151" stroke-width="3"/>
  <text x="955" y="260" fill="#f8fafc" text-anchor="middle" font-size="28" font-family="Arial" font-weight="bold">Force plus motion</text>
  <rect x="820" y="335" width="120" height="80" rx="12" fill="#60a5fa"/>
  <line x1="760" y1="375" x2="820" y2="375" stroke="#22c55e" stroke-width="12"/>
  <polygon points="820,375 790,358 790,392" fill="#22c55e"/>
  <line x1="945" y1="430" x2="1070" y2="430" stroke="#38bdf8" stroke-width="10"/>
  <polygon points="1070,430 1040,413 1040,447" fill="#38bdf8"/>
  <text x="955" y="460" fill="#86efac" text-anchor="middle" font-size="22" font-family="Arial">Displacement in the force direction transfers energy</text>
""",
        req.width,
        req.height,
    )


def _energy_stores_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <rect x="90" y="220" width="300" height="250" rx="24" fill="#1d4ed8"/>
  <text x="240" y="280" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Kinetic Store</text>
  <text x="240" y="330" fill="#dbeafe" text-anchor="middle" font-size="24" font-family="Arial">0.5mv^2</text>
  <text x="240" y="385" fill="#eff6ff" text-anchor="middle" font-size="18" font-family="Arial">Speed matters most</text>

  <rect x="490" y="220" width="300" height="250" rx="24" fill="#166534"/>
  <text x="640" y="280" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Height Store</text>
  <text x="640" y="330" fill="#dcfce7" text-anchor="middle" font-size="24" font-family="Arial">mgh</text>
  <text x="640" y="385" fill="#f0fdf4" text-anchor="middle" font-size="18" font-family="Arial">Height and mass set the gain</text>

  <rect x="890" y="220" width="300" height="250" rx="24" fill="#9a3412"/>
  <text x="1040" y="280" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Useful Fraction</text>
  <text x="1040" y="330" fill="#ffedd5" text-anchor="middle" font-size="24" font-family="Arial">useful / total</text>
  <text x="1040" y="385" fill="#fff7ed" text-anchor="middle" font-size="18" font-family="Arial">Efficiency is a share, not a store</text>

  <line x1="390" y1="345" x2="490" y2="345" stroke="#38bdf8" stroke-width="8"/>
  <line x1="790" y1="345" x2="890" y2="345" stroke="#fbbf24" stroke-width="8"/>
""",
        req.width,
        req.height,
    )


def _power_rate_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <rect x="120" y="220" width="420" height="280" rx="28" fill="#111827" stroke="#334155" stroke-width="3"/>
  <text x="330" y="280" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Same energy</text>
  <text x="330" y="340" fill="#93c5fd" text-anchor="middle" font-size="46" font-family="Arial" font-weight="bold">600 J / 10 s</text>
  <text x="330" y="405" fill="#86efac" text-anchor="middle" font-size="32" font-family="Arial">60 W</text>
  <rect x="220" y="435" width="220" height="18" rx="9" fill="#38bdf8"/>

  <rect x="740" y="220" width="420" height="280" rx="28" fill="#111827" stroke="#334155" stroke-width="3"/>
  <text x="950" y="280" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Same energy</text>
  <text x="950" y="340" fill="#cbd5e1" text-anchor="middle" font-size="46" font-family="Arial" font-weight="bold">600 J / 20 s</text>
  <text x="950" y="405" fill="#fbbf24" text-anchor="middle" font-size="32" font-family="Arial">30 W</text>
  <rect x="830" y="435" width="110" height="18" rx="9" fill="#fbbf24"/>
""",
        req.width,
        req.height,
    )


def _current_flow_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <rect x="190" y="210" width="860" height="320" rx="34" fill="none" stroke="#38bdf8" stroke-width="12"/>
  <rect x="215" y="315" width="80" height="110" rx="14" fill="#1d4ed8"/>
  <text x="255" y="365" fill="white" text-anchor="middle" font-size="22" font-family="Arial" font-weight="bold">Cell</text>
  <rect x="940" y="315" width="85" height="110" rx="14" fill="#f59e0b"/>
  <text x="982" y="365" fill="#111827" text-anchor="middle" font-size="22" font-family="Arial" font-weight="bold">Lamp</text>

  <circle cx="395" cy="250" r="18" fill="#f8fafc"/>
  <circle cx="515" cy="250" r="18" fill="#f8fafc"/>
  <circle cx="635" cy="250" r="18" fill="#f8fafc"/>
  <circle cx="755" cy="250" r="18" fill="#f8fafc"/>
  <text x="575" y="190" fill="#93c5fd" text-anchor="middle" font-size="24" font-family="Arial">Current = charge per second</text>
  <text x="640" y="580" fill="#fbbf24" text-anchor="middle" font-size="24" font-family="Arial">Potential difference = energy per charge</text>
""",
        req.width,
        req.height,
    )


def _series_parallel_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <text x="320" y="205" fill="#f8fafc" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Series</text>
  <rect x="120" y="240" width="400" height="250" rx="28" fill="none" stroke="#38bdf8" stroke-width="10"/>
  <rect x="180" y="335" width="70" height="60" rx="10" fill="#1d4ed8"/>
  <rect x="380" y="335" width="70" height="60" rx="10" fill="#f59e0b"/>
  <text x="320" y="455" fill="#93c5fd" text-anchor="middle" font-size="22" font-family="Arial">One route, one current</text>

  <text x="960" y="205" fill="#f8fafc" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Parallel</text>
  <rect x="760" y="240" width="400" height="250" rx="28" fill="none" stroke="#86efac" stroke-width="10"/>
  <line x1="820" y1="305" x2="1100" y2="305" stroke="#86efac" stroke-width="8"/>
  <line x1="820" y1="425" x2="1100" y2="425" stroke="#86efac" stroke-width="8"/>
  <rect x="930" y="275" width="70" height="60" rx="10" fill="#1d4ed8"/>
  <rect x="930" y="395" width="70" height="60" rx="10" fill="#f59e0b"/>
  <text x="960" y="455" fill="#bbf7d0" text-anchor="middle" font-size="22" font-family="Arial">Split branches, rejoin total</text>
""",
        req.width,
        req.height,
    )


def _power_safety_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}

  <rect x="130" y="235" width="420" height="260" rx="26" fill="#111827" stroke="#334155" stroke-width="3"/>
  <text x="340" y="290" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Electrical power</text>
  <text x="340" y="355" fill="#fbbf24" text-anchor="middle" font-size="54" font-family="Arial" font-weight="bold">P = VI</text>
  <text x="340" y="420" fill="#e2e8f0" text-anchor="middle" font-size="22" font-family="Arial">Rate of energy transfer</text>

  <rect x="730" y="235" width="420" height="260" rx="26" fill="#111827" stroke="#334155" stroke-width="3"/>
  <text x="940" y="290" fill="white" text-anchor="middle" font-size="30" font-family="Arial" font-weight="bold">Protection</text>
  <line x1="805" y1="365" x2="1075" y2="365" stroke="#ef4444" stroke-width="14"/>
  <line x1="930" y1="325" x2="950" y2="405" stroke="#f8fafc" stroke-width="10"/>
  <text x="940" y="435" fill="#fca5a5" text-anchor="middle" font-size="22" font-family="Arial">Open the circuit if current is unsafe</text>
""",
        req.width,
        req.height,
    )


def _generic_svg(req: DiagramRequest) -> str:
    return _wrap_svg(
        f"""
  {_heading(req)}
  <rect x="220" y="260" width="840" height="220" rx="24" fill="#111827" stroke="#334155" stroke-width="3"/>
  <text x="640" y="372" fill="#93c5fd" text-anchor="middle" font-size="28" font-family="Arial">
    {escape(req.concept)}
  </text>
""",
        req.width,
        req.height,
    )


def generate_diagram(
    req: DiagramRequest,
    output_dir: str | Path,
    public_base: str,
    module_id: str,
    lesson_id: str,
) -> GeneratedAsset:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    if req.concept == "prefix_scale":
        svg = _prefix_scale_svg(req)
    elif req.concept in {"measurement_precision", "tool_trust"}:
        svg = _tool_trust_svg(req)
    elif req.concept == "energy_transfer":
        svg = _energy_transfer_svg(req)
    elif req.concept == "energy_stores":
        svg = _energy_stores_svg(req)
    elif req.concept == "power_rate":
        svg = _power_rate_svg(req)
    elif req.concept == "current_flow":
        svg = _current_flow_svg(req)
    elif req.concept == "series_parallel":
        svg = _series_parallel_svg(req)
    elif req.concept == "power_safety":
        svg = _power_safety_svg(req)
    else:
        svg = _generic_svg(req)

    filename = f"{req.asset_id}.svg"
    path = output_path / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=req.title or req.concept,
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="local_svg_template",
        meta={
            "width": req.width,
            "height": req.height,
            "description": req.description,
            "template": req.template,
        },
    )
