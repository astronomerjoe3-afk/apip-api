from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Literal, Optional
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset


OpticsSystem = Literal[
    "converging_lens",
    "diverging_lens",
    "concave_mirror",
    "convex_mirror",
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
    }:
        raise ValueError(
            "Invalid system_type. Use one of: converging_lens, diverging_lens, "
            "concave_mirror, convex_mirror."
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
    parts = []

    parts.append(
        _line(
            pos["object_x"],
            pos["axis_y"],
            pos["object_x"],
            pos["object_top_y"],
            stroke="#22c55e",
            stroke_width=5,
            marker_end="obj-arrow",
        )
    )
    parts.append(_text(pos["object_x"], pos["axis_y"] + 32, "Object", fill="#86efac", size=18))

    if spec.show_image:
        virtual = False
        if spec.system_type in {"converging_lens", "diverging_lens"}:
            virtual = pos["di"] < 0
        else:
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

    if spec.system_type == "converging_lens":
        focus_x = pos["optic_x"] - f
    else:
        focus_x = pos["optic_x"] + f

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

    if spec.system_type == "concave_mirror":
        focus_x = pos["optic_x"] - f
    else:
        focus_x = pos["optic_x"] + f

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


def _build_svg(spec: OpticsRayDiagramSpec, width: int, height: int) -> str:
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
            "description": req.description,
            "width": width,
            "height": height,
        },
    )
