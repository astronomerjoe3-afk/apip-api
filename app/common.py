from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, List, Optional

from fastapi import Request


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def get_client_ip(request: Request) -> Optional[str]:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


def clamp01(x: Optional[float]) -> Optional[float]:
    if x is None:
        return None
    try:
        v = float(x)
    except Exception:
        return None
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def safe_list_str(v: Any, max_items: int = 25, max_len: int = 64) -> List[str]:
    out: List[str] = []
    if v is None:
        return out

    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",") if p.strip()]
    elif isinstance(v, list):
        parts = v
    else:
        parts = [str(v)]

    for p in parts[:max_items]:
        s = str(p).strip()
        if not s:
            continue
        out.append(s[:max_len])

    return out


def is_missing_index_error(e: Exception) -> bool:
    msg = str(e).lower()
    return (
        "requires an index" in msg
        or "create it here" in msg
        or "failed_precondition" in msg
    )


def parse_iso_utc(s: Any) -> float:
    try:
        if not s:
            return 0.0
        return datetime.fromisoformat(str(s)).timestamp()
    except Exception:
        return 0.0


def normalize_module_id(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""

    collapsed = re.sub(r"[^A-Za-z0-9]+", "", raw).upper()
    if collapsed in {"1", "M1", "MODULE1"}:
        return "M1"
    if collapsed in {"F1", "F2", "F3", "F4"}:
        return collapsed
    return raw