from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset

GraphType = Literal[
    "generic_xy",
    "kinematics_time_series",
    "projectile_trajectory",
    "circular_motion_xy",
    "circular_motion_components",
    "waveform",
]

Point = Tuple[float, float]


@dataclass
class GraphSeries:
    label: str
    points: List[Point]
    color: str = "#38bdf8"


@dataclass
class GraphAnnotation:
    x: float
    y: float
    text: str
    color: str = "#e2e8f0"
    anchor: str = "middle"
    size: int = 16
    weight: str = "normal"


@dataclass
class PhysicsGraphSpec:
    graph_type: GraphType
    title: str = ""
    subtitle: str = ""
    x_label: str = "x"
    y_label: str = "y"
    show_legend: bool = True
    equal_aspect: bool = False
    series: List[GraphSeries] | None = None
    annotations: List[GraphAnnotation] | None = None
    params: Dict[str, Any] | None = None


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _color_cycle(index: int) -> str:
    palette = [
        "#38bdf8",
        "#f97316",
        "#22c55e",
        "#a78bfa",
        "#facc15",
        "#fb7185",
    ]
    return palette[index % len(palette)]


def _parse_series(meta: Dict[str, Any]) -> List[GraphSeries]:
    raw_series = meta.get("series") or []
    if not isinstance(raw_series, list):
        return []

    series_list: List[GraphSeries] = []
    for idx, item in enumerate(raw_series):
        if not isinstance(item, dict):
            continue

        label = str(item.get("label") or f"Series {idx + 1}")
        color = str(item.get("color") or _color_cycle(idx))
        raw_points = item.get("points") or []
        points: List[Point] = []

        if isinstance(raw_points, list):
            for point in raw_points:
                if isinstance(point, (list, tuple)) and len(point) >= 2:
                    points.append((_as_float(point[0], 0.0), _as_float(point[1], 0.0)))
                elif isinstance(point, dict):
                    points.append((_as_float(point.get("x"), 0.0), _as_float(point.get("y"), 0.0)))

        if points:
            series_list.append(GraphSeries(label=label, points=points, color=color))

    return series_list


def _parse_annotations(meta: Dict[str, Any]) -> List[GraphAnnotation]:
    raw_annotations = meta.get("annotations") or []
    if not isinstance(raw_annotations, list):
        return []

    items: List[GraphAnnotation] = []
    for annotation in raw_annotations:
        if not isinstance(annotation, dict):
            continue
        items.append(
            GraphAnnotation(
                x=_as_float(annotation.get("x"), 0.0),
                y=_as_float(annotation.get("y"), 0.0),
                text=str(annotation.get("text") or ""),
                color=str(annotation.get("color") or "#e2e8f0"),
                anchor=str(annotation.get("anchor") or "middle"),
                size=_as_int(annotation.get("size"), 16),
                weight=str(annotation.get("weight") or "normal"),
            )
        )
    return items


def _parse_spec(req: DiagramRequest) -> PhysicsGraphSpec:
    meta = _get_meta(req)

    graph_type = str(meta.get("graph_type") or "generic_xy").strip().lower()
    if graph_type not in {
        "generic_xy",
        "kinematics_time_series",
        "projectile_trajectory",
        "circular_motion_xy",
        "circular_motion_components",
        "waveform",
    }:
        raise ValueError(
            "Invalid graph_type. Use one of: generic_xy, kinematics_time_series, "
            "projectile_trajectory, circular_motion_xy, circular_motion_components, waveform."
        )

    return PhysicsGraphSpec(
        graph_type=graph_type,  # type: ignore[arg-type]
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        x_label=str(meta.get("x_label") or "x"),
        y_label=str(meta.get("y_label") or "y"),
        show_legend=_as_bool(meta.get("show_legend"), True),
        equal_aspect=_as_bool(meta.get("equal_aspect"), graph_type == "circular_motion_xy"),
        series=_parse_series(meta),
        annotations=_parse_annotations(meta),
        params=meta,
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
    rotate: Optional[float] = None,
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
    stroke_width: int = 3,
    dashed: bool = False,
) -> str:
    dash_attr = ' stroke-dasharray="8 6"' if dashed else ""
    return (
        f'<line x1="{x1:.2f}" y1="{y1:.2f}" x2="{x2:.2f}" y2="{y2:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}"{dash_attr} />'
    )


def _circle(
    x: float,
    y: float,
    r: float,
    *,
    fill: str = "none",
    stroke: str = "#e2e8f0",
    stroke_width: int = 3,
) -> str:
    return (
        f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" fill="{fill}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}" />'
    )


def _polyline(points: List[Tuple[float, float]], *, stroke: str, stroke_width: int = 4) -> str:
    pts = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    return f'<polyline points="{pts}" fill="none" stroke="{stroke}" stroke-width="{stroke_width}" />'


def _polygon(points: List[Tuple[float, float]], *, fill: str, opacity: float) -> str:
    pts = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    return f'<polygon points="{pts}" fill="{fill}" opacity="{opacity:.3f}" />'


def _projectile_series(spec: PhysicsGraphSpec) -> List[GraphSeries]:
    params = spec.params or {}
    speed = _as_float(params.get("speed"), 18.0)
    angle_deg = _as_float(params.get("launch_angle_deg"), 45.0)
    gravity = _as_float(params.get("gravity"), 9.81)
    start_height = _as_float(params.get("start_height"), 0.0)
    sample_count = max(20, _as_int(params.get("sample_count"), 80))

    angle = math.radians(angle_deg)
    ux = speed * math.cos(angle)
    uy = speed * math.sin(angle)

    a = -0.5 * gravity
    b = uy
    c = start_height
    discriminant = max(0.0, (b * b) - (4 * a * c))
    t_flight = (-b - math.sqrt(discriminant)) / (2 * a) if abs(a) > 1e-9 else 0.0
    t_flight = max(t_flight, 0.1)

    points: List[Point] = []
    for i in range(sample_count + 1):
        t = t_flight * i / sample_count
        x = ux * t
        y = start_height + (uy * t) - (0.5 * gravity * t * t)
        points.append((x, max(y, 0.0)))

    return [GraphSeries(label="Projectile path", points=points, color="#38bdf8")]


def _circular_xy_series(spec: PhysicsGraphSpec) -> List[GraphSeries]:
    params = spec.params or {}
    radius = max(0.2, _as_float(params.get("radius"), 2.0))
    sample_count = max(60, _as_int(params.get("sample_count"), 180))
    center_x = _as_float(params.get("center_x"), 0.0)
    center_y = _as_float(params.get("center_y"), 0.0)

    points: List[Point] = []
    for i in range(sample_count + 1):
        theta = (2 * math.pi * i) / sample_count
        x = center_x + (radius * math.cos(theta))
        y = center_y + (radius * math.sin(theta))
        points.append((x, y))

    return [GraphSeries(label="Circular path", points=points, color="#38bdf8")]


def _circular_components_series(spec: PhysicsGraphSpec) -> List[GraphSeries]:
    params = spec.params or {}
    radius = max(0.2, _as_float(params.get("radius"), 2.0))
    omega = max(0.1, _as_float(params.get("angular_speed"), 2.0))
    periods = max(1, _as_int(params.get("periods"), 2))
    sample_count = max(60, _as_int(params.get("sample_count"), 180))

    period = (2 * math.pi) / omega
    total_time = periods * period
    x_points: List[Point] = []
    y_points: List[Point] = []

    for i in range(sample_count + 1):
        t = total_time * i / sample_count
        x_points.append((t, radius * math.cos(omega * t)))
        y_points.append((t, radius * math.sin(omega * t)))

    return [
        GraphSeries(label="x(t)", points=x_points, color="#38bdf8"),
        GraphSeries(label="y(t)", points=y_points, color="#f97316"),
    ]


def _waveform_series(spec: PhysicsGraphSpec) -> List[GraphSeries]:
    params = spec.params or {}
    amplitude = _as_float(params.get("amplitude"), 1.0)
    frequency = _as_float(params.get("frequency"), 1.0)
    phase_deg = _as_float(params.get("phase_deg"), 0.0)
    x_start = _as_float(params.get("x_start"), 0.0)
    x_end = _as_float(params.get("x_end"), 4.0 * math.pi)
    sample_count = max(60, _as_int(params.get("sample_count"), 180))
    phase = math.radians(phase_deg)

    points: List[Point] = []
    for i in range(sample_count + 1):
        x = x_start + ((x_end - x_start) * i / sample_count)
        y = amplitude * math.sin((frequency * x) + phase)
        points.append((x, y))

    return [GraphSeries(label="Waveform", points=points, color="#38bdf8")]


def _resolve_series(spec: PhysicsGraphSpec) -> List[GraphSeries]:
    if spec.graph_type in {"generic_xy", "kinematics_time_series"}:
        return spec.series or []
    if spec.graph_type == "projectile_trajectory":
        return _projectile_series(spec)
    if spec.graph_type == "circular_motion_xy":
        return _circular_xy_series(spec)
    if spec.graph_type == "circular_motion_components":
        return _circular_components_series(spec)
    if spec.graph_type == "waveform":
        return _waveform_series(spec)
    return []


def _get_bounds(spec: PhysicsGraphSpec, series_list: List[GraphSeries]) -> Tuple[float, float, float, float]:
    params = spec.params or {}
    xs = [x for series in series_list for x, _ in series.points]
    ys = [y for series in series_list for _, y in series.points]

    if not xs or not ys:
        x_min = _as_float(params.get("x_min"), 0.0)
        x_max = _as_float(params.get("x_max"), 10.0)
        y_min = _as_float(params.get("y_min"), 0.0)
        y_max = _as_float(params.get("y_max"), 10.0)
        return x_min, x_max, y_min, y_max

    x_min = min(xs)
    x_max = max(xs)
    y_min = min(ys)
    y_max = max(ys)

    if math.isclose(x_min, x_max):
        x_min -= 1.0
        x_max += 1.0
    if math.isclose(y_min, y_max):
        y_min -= 1.0
        y_max += 1.0

    x_pad = 0.08 * (x_max - x_min)
    y_pad = 0.12 * (y_max - y_min)
    x_min -= x_pad
    x_max += x_pad
    y_min -= y_pad
    y_max += y_pad

    if "x_min" in params:
        x_min = _as_float(params.get("x_min"), x_min)
    if "x_max" in params:
        x_max = _as_float(params.get("x_max"), x_max)
    if "y_min" in params:
        y_min = _as_float(params.get("y_min"), y_min)
    if "y_max" in params:
        y_max = _as_float(params.get("y_max"), y_max)

    if math.isclose(x_min, x_max):
        x_max = x_min + 1.0
    if math.isclose(y_min, y_max):
        y_max = y_min + 1.0

    return x_min, x_max, y_min, y_max


def _apply_equal_aspect(
    x_min: float,
    x_max: float,
    y_min: float,
    y_max: float,
    plot_w: float,
    plot_h: float,
) -> Tuple[float, float, float, float]:
    x_span = x_max - x_min
    y_span = y_max - y_min
    if x_span <= 0 or y_span <= 0:
        return x_min, x_max, y_min, y_max

    units_per_px_x = x_span / plot_w
    units_per_px_y = y_span / plot_h
    target = max(units_per_px_x, units_per_px_y)

    new_x_span = target * plot_w
    new_y_span = target * plot_h
    x_mid = (x_min + x_max) / 2
    y_mid = (y_min + y_max) / 2

    return (
        x_mid - (new_x_span / 2),
        x_mid + (new_x_span / 2),
        y_mid - (new_y_span / 2),
        y_mid + (new_y_span / 2),
    )


def _fill_series_indices(params: Dict[str, Any]) -> List[int]:
    raw = params.get("fill_under_series")
    if isinstance(raw, bool):
        return [0] if raw else []
    if isinstance(raw, int):
        return [raw]
    if isinstance(raw, list):
        values: List[int] = []
        for item in raw:
            try:
                values.append(int(item))
            except Exception:
                continue
        return values
    return []


def _build_plot_svg(spec: PhysicsGraphSpec, width: int, height: int) -> str:
    series_list = _resolve_series(spec)
    x_min, x_max, y_min, y_max = _get_bounds(spec, series_list)

    left = 110.0
    right = 90.0
    top = 150.0
    bottom = 110.0
    plot_x = left
    plot_y = top
    plot_w = width - left - right
    plot_h = height - top - bottom

    if spec.equal_aspect:
        x_min, x_max, y_min, y_max = _apply_equal_aspect(x_min, x_max, y_min, y_max, plot_w, plot_h)

    def sx(x: float) -> float:
        return plot_x + (((x - x_min) / (x_max - x_min)) * plot_w)

    def sy(y: float) -> float:
        return plot_y + plot_h - (((y - y_min) / (y_max - y_min)) * plot_h)

    parts: List[str] = []
    parts.append(_text(width / 2, 65, spec.title or "Physics Graph", size=34, weight="bold"))
    if spec.subtitle:
        parts.append(_text(width / 2, 100, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(
        f'<rect x="{plot_x:.2f}" y="{plot_y:.2f}" width="{plot_w:.2f}" height="{plot_h:.2f}" '
        f'fill="#111827" stroke="#334155" stroke-width="2" rx="18" />'
    )

    tick_count = 5
    for i in range(tick_count + 1):
        tx = plot_x + (plot_w * i / tick_count)
        parts.append(_line(tx, plot_y, tx, plot_y + plot_h, stroke="#1f2937", stroke_width=1))
        x_value = x_min + (((x_max - x_min) * i) / tick_count)
        parts.append(_text(tx, plot_y + plot_h + 30, f"{x_value:.2f}", fill="#94a3b8", size=14))

    for i in range(tick_count + 1):
        ty = plot_y + (plot_h * i / tick_count)
        parts.append(_line(plot_x, ty, plot_x + plot_w, ty, stroke="#1f2937", stroke_width=1))
        y_value = y_max - (((y_max - y_min) * i) / tick_count)
        parts.append(_text(plot_x - 16, ty + 5, f"{y_value:.2f}", fill="#94a3b8", size=14, anchor="end"))

    if x_min <= 0 <= x_max:
        parts.append(_line(sx(0.0), plot_y, sx(0.0), plot_y + plot_h, stroke="#64748b", stroke_width=3))
    if y_min <= 0 <= y_max:
        parts.append(_line(plot_x, sy(0.0), plot_x + plot_w, sy(0.0), stroke="#64748b", stroke_width=3))

    parts.append(_text(plot_x + (plot_w / 2), height - 28, spec.x_label, fill="#e2e8f0", size=20))
    parts.append(_text(34, plot_y + (plot_h / 2), spec.y_label, fill="#e2e8f0", size=20, rotate=-90))

    params = spec.params or {}
    fill_indices = set(_fill_series_indices(params))
    fill_opacity = _as_float(params.get("fill_opacity"), 0.18)
    baseline_value = 0.0 if y_min <= 0 <= y_max else y_min
    baseline_y = sy(baseline_value)

    for index, series in enumerate(series_list):
        if not series.points:
            continue
        screen_pts = [(sx(x), sy(y)) for x, y in series.points]
        if index in fill_indices and len(screen_pts) >= 2:
            fill_points = [(screen_pts[0][0], baseline_y), *screen_pts, (screen_pts[-1][0], baseline_y)]
            parts.append(_polygon(fill_points, fill=series.color, opacity=fill_opacity))
        parts.append(_polyline(screen_pts, stroke=series.color, stroke_width=4))
        end_x, end_y = screen_pts[-1]
        parts.append(_circle(end_x, end_y, 4, fill=series.color, stroke=series.color, stroke_width=0))

    if spec.graph_type == "circular_motion_xy" and series_list and series_list[0].points:
        point_x, point_y = series_list[0].points[-1]
        parts.append(_line(sx(0.0), sy(0.0), sx(point_x), sy(point_y), stroke="#facc15", stroke_width=3))
        parts.append(_text(sx(point_x) + 20, sy(point_y) - 16, "r", fill="#fde68a", size=18, anchor="start"))

    for annotation in spec.annotations or []:
        parts.append(
            _text(
                sx(annotation.x),
                sy(annotation.y),
                annotation.text,
                fill=annotation.color,
                anchor=annotation.anchor,
                size=annotation.size,
                weight=annotation.weight,
            )
        )

    if spec.show_legend and series_list:
        legend_x = plot_x + plot_w - 210
        legend_y = plot_y + 20
        box_h = (38 * len(series_list)) + 24
        parts.append(
            f'<rect x="{legend_x:.2f}" y="{legend_y:.2f}" width="190" height="{box_h:.2f}" '
            f'fill="#0f172a" stroke="#334155" stroke-width="2" rx="16" />'
        )
        for index, series in enumerate(series_list):
            yy = legend_y + 26 + (index * 34)
            parts.append(_line(legend_x + 18, yy - 6, legend_x + 58, yy - 6, stroke=series.color, stroke_width=4))
            parts.append(_text(legend_x + 70, yy, series.label, fill="#e2e8f0", size=16, anchor="start"))

    return (
        '<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        '<rect width="100%" height="100%" fill="#0b1020" />'
        + "".join(parts)
        + "</svg>"
    )


def generate_physics_graph(
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

    svg = _build_plot_svg(spec, width, height)
    filename = f"{req.asset_id}.svg"
    path = output_dir / filename
    path.write_text(svg, encoding="utf-8")

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=spec.title or req.title or "Physics Graph",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="physics_graph_agent",
        meta={
            "graph_type": spec.graph_type,
            "x_label": spec.x_label,
            "y_label": spec.y_label,
            "show_legend": spec.show_legend,
            "equal_aspect": spec.equal_aspect,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
