from __future__ import annotations

import base64
import os
from pathlib import Path
from typing import Any, Dict, Literal
from xml.sax.saxutils import escape

from app.lesson_pipeline.contracts import DiagramRequest, GeneratedAsset

SupportedSize = Literal["1024x1024", "1024x1536", "1536x1024"]


def _get_meta(req: DiagramRequest) -> Dict[str, Any]:
    raw = getattr(req, "meta", None)
    return raw if isinstance(raw, dict) else {}


def _get_openai_client():
    api_key = (os.getenv("OPENAI_API_KEY") or "").strip()
    if not api_key:
        return None

    try:
        from openai import OpenAI
    except Exception:
        return None

    return OpenAI(api_key=api_key)


def _pick_size(req: DiagramRequest) -> SupportedSize:
    width = int(getattr(req, "width", 1280) or 1280)
    height = int(getattr(req, "height", 720) or 720)

    if width == height:
        return "1024x1024"
    if height > width:
        return "1024x1536"
    return "1536x1024"


def _prompt_from_request(req: DiagramRequest) -> str:
    meta = _get_meta(req)

    subject = str(meta.get("subject") or req.title or req.concept or "physics concept").strip()
    description = str(req.description or "").strip()
    style = str(meta.get("style") or "cinematic educational concept art").strip()
    mood = str(meta.get("mood") or "clear, premium, powerful, science-focused").strip()
    composition = str(
        meta.get("composition")
        or "clean focal composition, no clutter, high contrast, visually explanatory"
    ).strip()
    palette = str(meta.get("palette") or "deep navy, electric blue, gold highlights").strip()
    avoid_text = bool(meta.get("avoid_text_in_image", True))
    extra = str(meta.get("extra_prompt") or "").strip()

    prompt_parts = [
        f"Create a powerful educational visual for: {subject}.",
        description if description else "",
        f"Style: {style}.",
        f"Mood: {mood}.",
        f"Composition: {composition}.",
        f"Color palette: {palette}.",
        "Designed for a physics education platform.",
        "Make it visually strong, conceptually suggestive, and presentation-ready.",
        "Avoid logos, watermarks, UI chrome, and irrelevant stock-photo aesthetics.",
        "No visible text in the image." if avoid_text else "",
        extra,
    ]

    return " ".join(part for part in prompt_parts if part)


def _placeholder_svg(req: DiagramRequest, output_path: Path) -> None:
    title = escape(req.title or req.concept or "General Visual")
    description = escape(req.description or "Physics concept visual")
    width = int(getattr(req, "width", 1280) or 1280)
    height = int(getattr(req, "height", 720) or 720)

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <defs>
    <linearGradient id="bg" x1="0" x2="1" y1="0" y2="1">
      <stop offset="0%" stop-color="#0b1020"/>
      <stop offset="100%" stop-color="#172554"/>
    </linearGradient>
    <radialGradient id="glow" cx="50%" cy="45%" r="45%">
      <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.35"/>
      <stop offset="100%" stop-color="#38bdf8" stop-opacity="0"/>
    </radialGradient>
  </defs>

  <rect width="100%" height="100%" fill="url(#bg)"/>
  <circle cx="{width/2:.1f}" cy="{height/2:.1f}" r="{min(width,height)*0.28:.1f}" fill="url(#glow)"/>

  <rect x="{width*0.14:.1f}" y="{height*0.20:.1f}" width="{width*0.72:.1f}" height="{height*0.60:.1f}"
        rx="28" fill="#0f172a" fill-opacity="0.78" stroke="#334155" stroke-width="3"/>

  <circle cx="{width*0.30:.1f}" cy="{height*0.48:.1f}" r="{min(width,height)*0.06:.1f}" fill="#facc15"/>
  <circle cx="{width*0.50:.1f}" cy="{height*0.40:.1f}" r="{min(width,height)*0.035:.1f}" fill="#38bdf8"/>
  <circle cx="{width*0.66:.1f}" cy="{height*0.56:.1f}" r="{min(width,height)*0.025:.1f}" fill="#a78bfa"/>

  <line x1="{width*0.30:.1f}" y1="{height*0.48:.1f}" x2="{width*0.50:.1f}" y2="{height*0.40:.1f}" stroke="#38bdf8" stroke-width="4"/>
  <line x1="{width*0.50:.1f}" y1="{height*0.40:.1f}" x2="{width*0.66:.1f}" y2="{height*0.56:.1f}" stroke="#a78bfa" stroke-width="4"/>

  <text x="{width/2:.1f}" y="{height*0.30:.1f}" fill="white" text-anchor="middle"
        font-size="38" font-family="Arial" font-weight="bold">{title}</text>
  <text x="{width/2:.1f}" y="{height*0.36:.1f}" fill="#cbd5e1" text-anchor="middle"
        font-size="20" font-family="Arial">{description}</text>
</svg>
"""
    output_path.write_text(svg, encoding="utf-8")


def generate_general_visual_concept(
    req: DiagramRequest,
    output_dir: str | Path,
    public_base: str,
    module_id: str,
    lesson_id: str,
) -> GeneratedAsset:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    meta = _get_meta(req)
    client = _get_openai_client()

    model = str(
        meta.get("model")
        or os.getenv("APIP_GENERAL_IMAGE_MODEL")
        or "gpt-image-1"
    ).strip()
    quality = str(
        meta.get("quality")
        or os.getenv("APIP_GENERAL_IMAGE_QUALITY")
        or "medium"
    ).strip()
    output_format = str(meta.get("output_format") or "png").strip().lower()
    background = str(meta.get("background") or "auto").strip().lower()
    size = _pick_size(req)

    prompt = _prompt_from_request(req)

    if client is not None:
        try:
            kwargs: Dict[str, Any] = {
                "model": model,
                "prompt": prompt,
                "size": size,
                "quality": quality,
                "output_format": output_format,
            }

            if background in {"auto", "opaque", "transparent"}:
                kwargs["background"] = background

            response = client.images.generate(**kwargs)
            image_b64 = response.data[0].b64_json

            filename = f"{req.asset_id}.{output_format}"
            output_path = output_dir / filename
            output_path.write_bytes(base64.b64decode(image_b64))

            public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{filename}"

            mime_type = {
                "png": "image/png",
                "jpeg": "image/jpeg",
                "webp": "image/webp",
            }.get(output_format, "image/png")

            return GeneratedAsset(
                asset_id=req.asset_id,
                kind="diagram",
                phase_key=req.phase_key,
                title=req.title or req.concept or "General Visual",
                concept=req.concept,
                storage_path=str(output_path),
                public_url=public_url,
                mime_type=mime_type,
                provider="general_visual_concept_agent_openai",
                meta={
                    "model": model,
                    "size": size,
                    "quality": quality,
                    "background": background,
                    "description": req.description,
                    "prompt": prompt,
                },
            )
        except Exception as exc:
            fallback_name = f"{req.asset_id}.svg"
            fallback_path = output_dir / fallback_name
            _placeholder_svg(req, fallback_path)

            public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{fallback_name}"

            return GeneratedAsset(
                asset_id=req.asset_id,
                kind="diagram",
                phase_key=req.phase_key,
                title=req.title or req.concept or "General Visual",
                concept=req.concept,
                storage_path=str(fallback_path),
                public_url=public_url,
                mime_type="image/svg+xml",
                provider="general_visual_concept_agent_fallback",
                meta={
                    "description": req.description,
                    "prompt": prompt,
                    "fallback_reason": str(exc)[:300],
                },
            )

    fallback_name = f"{req.asset_id}.svg"
    fallback_path = output_dir / fallback_name
    _placeholder_svg(req, fallback_path)

    public_url = f"{public_base.rstrip('/')}/{module_id}/{lesson_id}/diagrams/{fallback_name}"

    return GeneratedAsset(
        asset_id=req.asset_id,
        kind="diagram",
        phase_key=req.phase_key,
        title=req.title or req.concept or "General Visual",
        concept=req.concept,
        storage_path=str(fallback_path),
        public_url=public_url,
        mime_type="image/svg+xml",
        provider="general_visual_concept_agent_placeholder",
        meta={
            "description": req.description,
            "prompt": prompt,
            "fallback_reason": "OPENAI_API_KEY missing or OpenAI client unavailable",
        },
    )
