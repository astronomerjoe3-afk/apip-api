from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(tags=["debug"])


@router.get("/debug/text")
def debug_text():
    text = "Think of units like currency: you can't meaningfully add 'dollars' to 'meters'—and you can't pay with 'kilo-' without converting."
    return {
        "ok": True,
        "text": text,
        "repr": repr(text),
        "codepoints": [hex(ord(ch)) for ch in text if ch in {"—", "â"}],
    }
