from __future__ import annotations

from dataclasses import dataclass
import math
from pathlib import Path
from typing import Any, Dict, Literal, Optional
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


OpticsSystem = Literal[
    "converging_lens",
    "diverging_lens",
    "concave_mirror",
    "convex_mirror",
    "plane_mirror",
]


@dataclass
class OpticsRayDiagramSpec:
    system_type: OpticsSystem
    object_distance: float
    focal_length: float
    object_height: float = 1.0
    principal_rays: int = 3
    title: str = ""
    subtitle: str = ""
    show_image: bool = True
    show_focal_labels: bool = True
    show_axis_labels: bool = True
    annotation_mode: str = ""
    incident_angle_deg: float = 40.0
    surface_angle_deg: float = 0.0
    guide_line_angle_deg: float = 0.0
    distance_label: str = ""


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _parse_spec(req: DiagramRequest) -> OpticsRayDiagramSpec:
    meta = _get_meta(req)

    system_type = str(meta.get("system_type") or "converging_lens").strip().lower()
    if system_type not in {
        "converging_lens",
        "diverging_lens",
        "concave_mirror",
        "convex_mirror",
        "plane_mirror",
    }:
        raise ValueError(
            "Invalid system_type. Use one of: converging_lens, diverging_lens, "
            "concave_mirror, convex_mirror, plane_mirror."
        )

    def _float(name: str, default: float) -> float:
        try:
            return float(meta.get(name, default))
        except Exception:
            return default

    def _int(name: str, default: int) -> int:
        try:
            return int(meta.get(name, default))
        except Exception:
            return default

    incident_angle_deg = max(5.0, min(80.0, _float("incident_angle_deg", 40.0)))
    surface_angle_deg = _float("surface_angle_deg", 90.0 - incident_angle_deg)
    guide_line_angle_deg = _float("guide_line_angle_deg", incident_angle_deg)

    return OpticsRayDiagramSpec(
        system_type=system_type,  # type: ignore[arg-type]
        object_distance=max(0.2, _float("object_distance", 3.0)),
        focal_length=max(0.2, _float("focal_length", 1.0)),
        object_height=max(0.2, _float("object_height", 1.0)),
        principal_rays=max(2, min(3, _int("principal_rays", 3))),
        title=str(meta.get("title") or req.title or req.concept),
        subtitle=str(meta.get("subtitle") or req.description or ""),
        show_image=bool(meta.get("show_image", True)),
        show_focal_labels=bool(meta.get("show_focal_labels", True)),
        show_axis_labels=bool(meta.get("show_axis_labels", True)),
        annotation_mode=str(meta.get("annotation_mode") or "").strip().lower(),
        incident_angle_deg=incident_angle_deg,
        surface_angle_deg=max(0.0, min(90.0, surface_angle_deg)),
        guide_line_angle_deg=max(0.0, min(90.0, guide_line_angle_deg)),
        distance_label=str(meta.get("distance_label") or ""),
    )


def _signed_focal_length(system_type: OpticsSystem, focal_length: float) -> float:
    if system_type in {"diverging_lens", "convex_mirror"}:
        return -abs(focal_length)
    return abs(focal_length)


def _image_distance(do: float, f_signed: float) -> Optional[float]:
    # 1/f = 1/do + 1/di  =>  1/di = 1/f - 1/do
    denom = (1.0 / f_signed) - (1.0 / do)
    if abs(denom) < 1e-9:
        return None
    return 1.0 / denom


def _line_y_at_x(x1: float, y1: float, x2: float, y2: float, target_x: float) -> float:
    if abs(x2 - x1) < 1e-9:
        return y2
    t = (target_x - x1) / (x2 - x1)
    return y1 + t * (y2 - y1)


def _point_on_circle(cx: float, cy: float, radius: float, angle_deg: float) -> tuple[float, float]:
    angle = math.radians(angle_deg)
    return (cx + (radius * math.cos(angle)), cy + (radius * math.sin(angle)))


def _svg_header(width: int, height: int) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <marker id="ray-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#fbbf24" />
    </marker>
    <marker id="obj-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#22c55e" />
    </marker>
    <marker id="img-arrow" markerWidth="12" markerHeight="12" refX="10" refY="6" orient="auto" markerUnits="strokeWidth">
      <path d="M 0 0 L 12 6 L 0 12 z" fill="#a78bfa" />
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
    stroke: str,
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


def _circle(x: float, y: float, r: float, fill: str) -> str:
    return f'<circle cx="{x:.2f}" cy="{y:.2f}" r="{r:.2f}" fill="{fill}" />'


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


def _arc(
    cx: float,
    cy: float,
    radius: float,
    start_deg: float,
    end_deg: float,
    *,
    stroke: str,
    stroke_width: int = 4,
) -> str:
    start_x, start_y = _point_on_circle(cx, cy, radius, start_deg)
    end_x, end_y = _point_on_circle(cx, cy, radius, end_deg)
    sweep_flag = 1 if end_deg >= start_deg else 0
    large_arc_flag = 0
    return (
        f'<path d="M {start_x:.2f} {start_y:.2f} '
        f'A {radius:.2f} {radius:.2f} 0 {large_arc_flag} {sweep_flag} {end_x:.2f} {end_y:.2f}" '
        f'stroke="{stroke}" stroke-width="{stroke_width}" fill="none" />'
    )


def _connector(points: list[tuple[float, float]], *, stroke: str, stroke_width: int = 3) -> str:
    pts = " ".join(f"{x:.2f},{y:.2f}" for x, y in points)
    return f'<polyline points="{pts}" fill="none" stroke="{stroke}" stroke-width="{stroke_width}" stroke-linecap="round" stroke-linejoin="round" />'


def _mirror_distance_tick(x: float, y1: float, y2: float, *, stroke: str) -> str:
    return "".join(
        [
            _line(x, y1, x, y2, stroke=stroke, stroke_width=3, dashed=True),
            _line(x - 8, y1, x + 8, y1, stroke=stroke, stroke_width=3),
            _line(x - 8, y2, x + 8, y2, stroke=stroke, stroke_width=3),
        ]
    )


def _optical_element_svg(
    system_type: OpticsSystem,
    optic_x: float,
    axis_y: float,
    top_y: float,
    bottom_y: float,
) -> str:
    if system_type == "converging_lens":
        return (
            f'<path d="M {optic_x:.2f} {top_y:.2f} '
            f'Q {optic_x - 26:.2f} {axis_y:.2f} {optic_x:.2f} {bottom_y:.2f}" '
            f'stroke="#60a5fa" stroke-width="5" fill="none" />'
            f'<path d="M {optic_x:.2f} {top_y:.2f} '
            f'Q {optic_x + 26:.2f} {axis_y:.2f} {optic_x:.2f} {bottom_y:.2f}" '
            f'stroke="#60a5fa" stroke-width="5" fill="none" />'
        )

    if system_type == "diverging_lens":
        return (
            f'<path d="M {optic_x:.2f} {top_y:.2f} '
            f'Q {optic_x + 26:.2f} {axis_y:.2f} {optic_x:.2f} {bottom_y:.2f}" '
            f'stroke="#60a5fa" stroke-width="5" fill="none" />'
            f'<path d="M {optic_x:.2f} {top_y:.2f} '
            f'Q {optic_x - 26:.2f} {axis_y:.2f} {optic_x:.2f} {bottom_y:.2f}" '
            f'stroke="#60a5fa" stroke-width="5" fill="none" />'
        )

    if system_type == "concave_mirror":
        return (
            f'<path d="M {optic_x + 18:.2f} {top_y:.2f} '
            f'Q {optic_x - 18:.2f} {axis_y:.2f} {optic_x + 18:.2f} {bottom_y:.2f}" '
            f'stroke="#f87171" stroke-width="6" fill="none" />'
        )

    return (
        f'<path d="M {optic_x - 18:.2f} {top_y:.2f} '
        f'Q {optic_x + 18:.2f} {axis_y:.2f} {optic_x - 18:.2f} {bottom_y:.2f}" '
        f'stroke="#f87171" stroke-width="6" fill="none" />'
    )


def _positions(spec: OpticsRayDiagramSpec, width: int, height: int) -> Dict[str, float]:
    optic_x = width / 2
    axis_y = height / 2
    f_signed = _signed_focal_length(spec.system_type, spec.focal_length)
    di = _image_distance(spec.object_distance, f_signed)

    max_span = max(
        spec.object_distance,
        abs(di) if di is not None else spec.object_distance * 1.4,
        spec.focal_length * 2.2,
        1.0,
    )
    scale_x = min((width * 0.38) / max_span, 180.0)

    m = 0.0 if di is None else -(di / spec.object_distance)
    image_height = m * spec.object_height
    max_height = max(abs(spec.object_height), abs(image_height), 1.0)
    scale_y = min((height * 0.24) / max_height, 180.0)

    object_x = optic_x - (spec.object_distance * scale_x)

    if di is None:
        image_x = optic_x + (width * 0.20)
    elif spec.system_type in {"converging_lens", "diverging_lens"}:
        image_x = optic_x + (di * scale_x)
    else:
        image_x = optic_x - (di * scale_x)

    object_top_y = axis_y - (spec.object_height * scale_y)
    image_top_y = axis_y - (image_height * scale_y)

    return {
        "optic_x": optic_x,
        "axis_y": axis_y,
        "f_signed": f_signed,
        "di": di if di is not None else 0.0,
        "object_x": object_x,
        "object_top_y": object_top_y,
        "image_x": image_x,
        "image_top_y": image_top_y,
        "image_height": image_height,
        "scale_x": scale_x,
        "scale_y": scale_y,
        "left_x": 60.0,
        "right_x": width - 60.0,
        "top_y": 140.0,
        "bottom_y": height - 140.0,
    }


def _plane_mirror_positions(spec: OpticsRayDiagramSpec, width: int, height: int) -> Dict[str, float]:
    mirror_x = width * 0.56
    base_y = height * 0.68
    left_x = 70.0
    right_x = width - 70.0
    top_y = 150.0
    bottom_y = height - 120.0

    scale_x = min((width * 0.22) / max(spec.object_distance, 1.0), 180.0)
    scale_y = min((height * 0.28) / max(spec.object_height, 1.0), 170.0)

    object_x = mirror_x - (spec.object_distance * scale_x)
    image_x = mirror_x + (spec.object_distance * scale_x)
    object_top_y = base_y - (spec.object_height * scale_y)
    image_top_y = object_top_y
    image_base_y = base_y

    angle = spec.incident_angle_deg
    hit_y = object_top_y + ((mirror_x - object_x) * math.tan(math.radians(angle)))
    hit_y = max(top_y + 35.0, min(base_y - 16.0, hit_y))

    secondary_hit_y = min(bottom_y - 40.0, hit_y + max(68.0, spec.object_height * scale_y * 0.75))
    if secondary_hit_y <= hit_y + 24.0:
        secondary_hit_y = min(bottom_y - 16.0, hit_y + 42.0)

    return {
        "mirror_x": mirror_x,
        "base_y": base_y,
        "left_x": left_x,
        "right_x": right_x,
        "top_y": top_y,
        "bottom_y": bottom_y,
        "scale_x": scale_x,
        "scale_y": scale_y,
        "object_x": object_x,
        "object_top_y": object_top_y,
        "image_x": image_x,
        "image_top_y": image_top_y,
        "image_base_y": image_base_y,
        "hit_y": hit_y,
        "secondary_hit_y": secondary_hit_y,
    }


def _draw_axis_and_labels(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    parts = [
        _line(pos["left_x"], pos["axis_y"], pos["right_x"], pos["axis_y"], stroke="#64748b", stroke_width=3),
        _text(540, 70, spec.title or "Optics Ray Diagram", size=34, weight="bold"),
    ]
    if spec.subtitle:
        parts.append(_text(540, 105, spec.subtitle, size=18, fill="#cbd5e1"))
    if spec.show_axis_labels:
        parts.append(_text(88, pos["axis_y"] - 12, "optical axis", size=15, fill="#94a3b8", anchor="start"))
    return "".join(parts)


def _draw_object_and_image(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    parts = [
        _line(
            pos["object_x"],
            pos["axis_y"],
            pos["object_x"],
            pos["object_top_y"],
            stroke="#22c55e",
            stroke_width=5,
            marker_end="obj-arrow",
        ),
        _text(pos["object_x"], pos["axis_y"] + 32, "Object", fill="#86efac", size=18),
    ]

    if spec.show_image:
        virtual = pos["di"] < 0
        parts.append(
            _line(
                pos["image_x"],
                pos["axis_y"],
                pos["image_x"],
                pos["image_top_y"],
                stroke="#a78bfa",
                stroke_width=5,
                marker_end="img-arrow",
                dashed=virtual,
            )
        )
        parts.append(_text(pos["image_x"], pos["axis_y"] + 32, "Image", fill="#d8b4fe", size=18))

    return "".join(parts)


def _draw_focal_points(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    if not spec.show_focal_labels:
        return ""

    parts = []
    f = spec.focal_length * pos["scale_x"]

    if spec.system_type in {"converging_lens", "diverging_lens"}:
        left_f = pos["optic_x"] - f
        right_f = pos["optic_x"] + f
        parts.extend(
            [
                _circle(left_f, pos["axis_y"], 5, "#facc15"),
                _circle(right_f, pos["axis_y"], 5, "#facc15"),
                _text(left_f, pos["axis_y"] + 28, "F", fill="#fde68a", size=16),
                _text(right_f, pos["axis_y"] + 28, "F", fill="#fde68a", size=16),
            ]
        )
    else:
        if spec.system_type == "concave_mirror":
            focus_x = pos["optic_x"] - f
            center_x = pos["optic_x"] - (2 * f)
        else:
            focus_x = pos["optic_x"] + f
            center_x = pos["optic_x"] + (2 * f)
        parts.extend(
            [
                _circle(focus_x, pos["axis_y"], 5, "#facc15"),
                _circle(center_x, pos["axis_y"], 5, "#fca5a5"),
                _text(focus_x, pos["axis_y"] + 28, "F", fill="#fde68a", size=16),
                _text(center_x, pos["axis_y"] + 28, "C", fill="#fecaca", size=16),
            ]
        )

    return "".join(parts)


def _draw_parallel_ray_lens(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    parts = []
    hit_x = pos["optic_x"]
    hit_y = pos["object_top_y"]

    parts.append(_line(pos["object_x"], hit_y, hit_x, hit_y, stroke="#fbbf24", marker_end="ray-arrow"))

    f = spec.focal_length * pos["scale_x"]
    if spec.system_type == "converging_lens":
        focus_x = pos["optic_x"] + f
        y_end = _line_y_at_x(hit_x, hit_y, focus_x, pos["axis_y"], pos["right_x"])
        parts.append(_line(hit_x, hit_y, pos["right_x"], y_end, stroke="#fbbf24", marker_end="ray-arrow"))
        if pos["di"] < 0:
            parts.append(_line(hit_x, hit_y, pos["image_x"], pos["image_top_y"], stroke="#fbbf24", dashed=True))
    else:
        focus_x = pos["optic_x"] - f
        y_end = _line_y_at_x(focus_x, pos["axis_y"], hit_x, hit_y, pos["right_x"])
        parts.append(_line(hit_x, hit_y, pos["right_x"], y_end, stroke="#fbbf24", marker_end="ray-arrow"))
        parts.append(_line(hit_x, hit_y, focus_x, pos["axis_y"], stroke="#fbbf24", dashed=True))

    return "".join(parts)


def _draw_center_ray_lens(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    parts = []
    center_x = pos["optic_x"]
    center_y = pos["axis_y"]

    if pos["di"] >= 0:
        parts.append(
            _line(
                pos["object_x"],
                pos["object_top_y"],
                pos["image_x"],
                pos["image_top_y"],
                stroke="#34d399",
                marker_end="ray-arrow",
            )
        )
    else:
        y_end = _line_y_at_x(
            pos["object_x"],
            pos["object_top_y"],
            center_x,
            center_y,
            pos["right_x"],
        )
        parts.append(
            _line(
                pos["object_x"],
                pos["object_top_y"],
                pos["right_x"],
                y_end,
                stroke="#34d399",
                marker_end="ray-arrow",
            )
        )
        parts.append(
            _line(
                center_x,
                center_y,
                pos["image_x"],
                pos["image_top_y"],
                stroke="#34d399",
                dashed=True,
            )
        )

    return "".join(parts)


def _draw_focus_ray_lens(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    parts = []
    f = spec.focal_length * pos["scale_x"]
    focus_x = pos["optic_x"] - f if spec.system_type == "converging_lens" else pos["optic_x"] + f

    hit_y = _line_y_at_x(
        pos["object_x"],
        pos["object_top_y"],
        focus_x,
        pos["axis_y"],
        pos["optic_x"],
    )

    parts.append(
        _line(
            pos["object_x"],
            pos["object_top_y"],
            pos["optic_x"],
            hit_y,
            stroke="#f472b6",
            marker_end="ray-arrow",
        )
    )
    parts.append(
        _line(
            pos["optic_x"],
            hit_y,
            pos["right_x"],
            hit_y,
            stroke="#f472b6",
            marker_end="ray-arrow",
        )
    )
    return "".join(parts)


def _draw_parallel_ray_mirror(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    parts = []
    hit_x = pos["optic_x"]
    hit_y = pos["object_top_y"]
    parts.append(_line(pos["object_x"], hit_y, hit_x, hit_y, stroke="#fbbf24", marker_end="ray-arrow"))

    f = spec.focal_length * pos["scale_x"]
    if spec.system_type == "concave_mirror":
        focus_x = pos["optic_x"] - f
        y_left = _line_y_at_x(hit_x, hit_y, focus_x, pos["axis_y"], pos["left_x"])
        parts.append(_line(hit_x, hit_y, pos["left_x"], y_left, stroke="#fbbf24", marker_end="ray-arrow"))
        if pos["di"] < 0:
            parts.append(_line(hit_x, hit_y, pos["image_x"], pos["image_top_y"], stroke="#fbbf24", dashed=True))
    else:
        focus_x = pos["optic_x"] + f
        y_left = _line_y_at_x(focus_x, pos["axis_y"], hit_x, hit_y, pos["left_x"])
        parts.append(_line(hit_x, hit_y, pos["left_x"], y_left, stroke="#fbbf24", marker_end="ray-arrow"))
        parts.append(_line(hit_x, hit_y, focus_x, pos["axis_y"], stroke="#fbbf24", dashed=True))

    return "".join(parts)


def _draw_focus_ray_mirror(spec: OpticsRayDiagramSpec, pos: Dict[str, float]) -> str:
    parts = []
    f = spec.focal_length * pos["scale_x"]
    focus_x = pos["optic_x"] - f if spec.system_type == "concave_mirror" else pos["optic_x"] + f

    hit_y = _line_y_at_x(
        pos["object_x"],
        pos["object_top_y"],
        focus_x,
        pos["axis_y"],
        pos["optic_x"],
    )

    parts.append(
        _line(
            pos["object_x"],
            pos["object_top_y"],
            pos["optic_x"],
            hit_y,
            stroke="#f472b6",
            marker_end="ray-arrow",
        )
    )
    parts.append(
        _line(
            pos["optic_x"],
            hit_y,
            pos["left_x"],
            hit_y,
            stroke="#f472b6",
            marker_end="ray-arrow",
        )
    )

    if spec.system_type == "convex_mirror":
        parts.append(
            _line(
                pos["optic_x"],
                hit_y,
                focus_x,
                pos["axis_y"],
                stroke="#f472b6",
                dashed=True,
            )
        )

    return "".join(parts)


def _draw_plane_mirror_scene(spec: OpticsRayDiagramSpec, width: int, height: int) -> str:
    pos = _plane_mirror_positions(spec, width, height)
    parts = [_svg_header(width, height)]
    mirror_x = pos["mirror_x"]
    base_y = pos["base_y"]
    object_x = pos["object_x"]
    object_top_y = pos["object_top_y"]
    image_x = pos["image_x"]
    image_top_y = pos["image_top_y"]
    hit_y = pos["hit_y"]
    secondary_hit_y = pos["secondary_hit_y"]

    parts.append(_text(width / 2, 70, spec.title or "Plane Mirror Ray Diagram", size=34, weight="bold"))
    if spec.subtitle:
        parts.append(_text(width / 2, 105, spec.subtitle, size=18, fill="#cbd5e1"))

    parts.append(_line(mirror_x, pos["top_y"], mirror_x, pos["bottom_y"], stroke="#93c5fd", stroke_width=8))
    parts.append(_text(mirror_x + 26, pos["top_y"] + 18, "mirror surface", fill="#bfdbfe", size=16, anchor="start"))

    parts.append(
        _line(
            object_x,
            base_y,
            object_x,
            object_top_y,
            stroke="#22c55e",
            stroke_width=5,
            marker_end="obj-arrow",
        )
    )
    parts.append(_text(object_x, base_y + 34, "Object", fill="#86efac", size=18))

    if spec.show_image:
        parts.append(
            _line(
                image_x,
                base_y,
                image_x,
                image_top_y,
                stroke="#a78bfa",
                stroke_width=5,
                marker_end="img-arrow",
                dashed=True,
            )
        )
        parts.append(_text(image_x, base_y + 34, "Image", fill="#d8b4fe", size=18))

    guide_left = max(pos["left_x"] + 50.0, mirror_x - 210.0)
    guide_right = min(pos["right_x"] - 20.0, mirror_x + 210.0)
    parts.append(_line(guide_left, hit_y, guide_right, hit_y, stroke="#38bdf8", stroke_width=3, dashed=True))
    if spec.show_axis_labels:
        parts.append(_text(guide_right - 6.0, hit_y - 12.0, "Guide Line", fill="#7dd3fc", size=16, anchor="end"))

    primary_left_y = _line_y_at_x(mirror_x, hit_y, image_x, image_top_y, pos["left_x"])
    parts.append(_line(object_x, object_top_y, mirror_x, hit_y, stroke="#fbbf24", marker_end="ray-arrow"))
    parts.append(_line(mirror_x, hit_y, pos["left_x"], primary_left_y, stroke="#fbbf24", marker_end="ray-arrow"))
    parts.append(_line(mirror_x, hit_y, image_x, image_top_y, stroke="#fbbf24", dashed=True))

    if spec.principal_rays >= 3 or spec.annotation_mode in {"ghost_image", "image_distance", "bounce_panel"}:
        secondary_left_y = _line_y_at_x(mirror_x, secondary_hit_y, image_x, image_top_y, pos["left_x"])
        parts.append(_line(object_x, object_top_y, mirror_x, secondary_hit_y, stroke="#34d399", marker_end="ray-arrow"))
        parts.append(_line(mirror_x, secondary_hit_y, pos["left_x"], secondary_left_y, stroke="#34d399", marker_end="ray-arrow"))
        parts.append(_line(mirror_x, secondary_hit_y, image_x, image_top_y, stroke="#34d399", dashed=True))

    if spec.annotation_mode in {"equal_angles", "bounce_panel"}:
        radius = 54.0
        theta = spec.guide_line_angle_deg
        parts.append(_arc(mirror_x, hit_y, radius, 180.0, 180.0 + theta, stroke="#f97316", stroke_width=4))
        parts.append(_arc(mirror_x, hit_y, radius, 180.0 - theta, 180.0, stroke="#f97316", stroke_width=4))
        parts.append(_text(mirror_x - 102.0, hit_y - 64.0, f"{int(round(theta))} deg", fill="#fdba74", size=16))
        parts.append(_text(mirror_x - 112.0, hit_y + 78.0, f"{int(round(theta))} deg", fill="#fdba74", size=16))
        parts.append(_text(mirror_x - 168.0, hit_y - 112.0, "equal angles", fill="#fde68a", size=16, anchor="start", weight="bold"))

    if spec.annotation_mode == "surface_conversion":
        theta = spec.guide_line_angle_deg
        surface = spec.surface_angle_deg
        guide_radius = 78.0
        surface_radius = 52.0
        guide_mid = 180.0 + (theta / 2.0)
        surface_mid = 270.0 - (surface / 2.0)

        guide_anchor = _point_on_circle(mirror_x, hit_y, guide_radius, guide_mid)
        surface_anchor = _point_on_circle(mirror_x, hit_y, surface_radius, surface_mid)

        parts.append(_arc(mirror_x, hit_y, guide_radius, 180.0, 180.0 + theta, stroke="#22c55e", stroke_width=5))
        parts.append(_arc(mirror_x, hit_y, surface_radius, 270.0 - surface, 270.0, stroke="#ef4444", stroke_width=5))
        parts.append(
            _connector(
                [
                    (guide_anchor[0] - 8.0, guide_anchor[1] - 10.0),
                    (mirror_x - 122.0, hit_y - 124.0),
                    (mirror_x - 232.0, hit_y - 124.0),
                ],
                stroke="#22c55e",
            )
        )
        parts.append(
            _connector(
                [
                    (surface_anchor[0] + 10.0, surface_anchor[1] - 4.0),
                    (mirror_x + 84.0, hit_y - 54.0),
                    (mirror_x + 176.0, hit_y - 54.0),
                ],
                stroke="#ef4444",
            )
        )
        parts.append(_text(mirror_x - 236.0, hit_y - 132.0, f"{int(round(theta))} deg to Guide Line", fill="#86efac", size=17, anchor="start", weight="bold"))
        parts.append(_text(mirror_x + 180.0, hit_y - 62.0, f"{int(round(surface))} deg to surface", fill="#fca5a5", size=17, anchor="start", weight="bold"))
        parts.append(_text(mirror_x + 28.0, hit_y + 104.0, "surface + Guide Line = 90 deg", fill="#cbd5e1", size=15, anchor="start"))

    if spec.annotation_mode in {"ghost_image", "bounce_panel"}:
        parts.append(_text(image_x + 32.0, image_top_y - 12.0, "ghost image", fill="#d8b4fe", size=16, anchor="start", weight="bold"))
        parts.append(_text(image_x - 10.0, base_y + 70.0, "dashed extensions only", fill="#c4b5fd", size=15))

    if spec.annotation_mode == "image_distance":
        upper_y = base_y + 78.0
        parts.append(_mirror_distance_tick((object_x + mirror_x) / 2, base_y + 8.0, upper_y, stroke="#86efac"))
        parts.append(_mirror_distance_tick((mirror_x + image_x) / 2, base_y + 8.0, upper_y, stroke="#d8b4fe"))
        label = spec.distance_label or "same distance"
        parts.append(_text((object_x + mirror_x) / 2, upper_y + 26.0, label, fill="#86efac", size=15))
        parts.append(_text((mirror_x + image_x) / 2, upper_y + 26.0, label, fill="#d8b4fe", size=15))

    parts.append(_svg_footer())
    return "".join(parts)


def _build_svg(spec: OpticsRayDiagramSpec, width: int, height: int) -> str:
    if spec.system_type == "plane_mirror":
        return _draw_plane_mirror_scene(spec, width, height)

    pos = _positions(spec, width, height)
    parts = [_svg_header(width, height)]

    parts.append(_draw_axis_and_labels(spec, pos))
    parts.append(
        _optical_element_svg(
            spec.system_type,
            pos["optic_x"],
            pos["axis_y"],
            pos["top_y"],
            pos["bottom_y"],
        )
    )
    parts.append(_draw_focal_points(spec, pos))
    parts.append(_draw_object_and_image(spec, pos))

    if spec.system_type in {"converging_lens", "diverging_lens"}:
        parts.append(_draw_parallel_ray_lens(spec, pos))
        parts.append(_draw_center_ray_lens(spec, pos))
        if spec.principal_rays >= 3:
            parts.append(_draw_focus_ray_lens(spec, pos))
    else:
        parts.append(_draw_parallel_ray_mirror(spec, pos))
        parts.append(_draw_focus_ray_mirror(spec, pos))

    parts.append(_svg_footer())
    return "".join(parts)


def generate_optics_ray_diagram(
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
        title=spec.title or req.title or "Optics Ray Diagram",
        concept=req.concept,
        storage_path=str(path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="optics_ray_diagram_agent",
        meta={
            "system_type": spec.system_type,
            "object_distance": spec.object_distance,
            "focal_length": spec.focal_length,
            "object_height": spec.object_height,
            "principal_rays": spec.principal_rays,
            "show_image": spec.show_image,
            "annotation_mode": spec.annotation_mode,
            "incident_angle_deg": spec.incident_angle_deg,
            "surface_angle_deg": spec.surface_angle_deg,
            "guide_line_angle_deg": spec.guide_line_angle_deg,
            "distance_label": spec.distance_label,
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
