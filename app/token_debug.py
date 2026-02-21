from __future__ import annotations

import base64
import json
from typing import Any, Dict


def _b64url_decode(seg: str) -> bytes:
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode("utf-8"))


def decode_jwt_no_verify(token: str) -> Dict[str, Any]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("Token is not a JWT (expected at least 2 dot-separated parts)")

    header_b = _b64url_decode(parts[0])
    payload_b = _b64url_decode(parts[1])

    header = json.loads(header_b.decode("utf-8"))
    payload = json.loads(payload_b.decode("utf-8"))

    return {
        "header": header,
        "payload": payload,
        "claims_of_interest": {
            "aud": payload.get("aud"),
            "iss": payload.get("iss"),
            "sub": payload.get("sub"),
            "user_id": payload.get("user_id"),
            "firebase.sign_in_provider": (payload.get("firebase") or {}).get("sign_in_provider"),
        },
    }