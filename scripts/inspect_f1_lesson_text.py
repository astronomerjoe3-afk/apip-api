from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.db.firestore import get_firestore_client


def main() -> None:
    db = get_firestore_client()

    snap = db.collection("lessons").document("F1_L1").get()
    if not snap.exists:
        print("[ERROR] lessons/F1_L1 not found")
        return

    data = snap.to_dict() or {}
    text = (
        ((data.get("phases") or {}).get("analogical_grounding") or {}).get("analogy_text")
    )

    print("RAW_TEXT:")
    print(text)
    print()
    print("PYTHON_REPR:")
    print(repr(text))
    print()
    print("UNICODE_CODEPOINTS_AROUND_DASH:")
    if isinstance(text, str):
        target = "meters"
        idx = text.find(target)
        start = max(0, idx - 5) if idx >= 0 else 0
        end = min(len(text), idx + 25) if idx >= 0 else min(len(text), 40)
        snippet = text[start:end]
        print(snippet)
        print([hex(ord(ch)) for ch in snippet])


if __name__ == "__main__":
    os.environ.setdefault("GOOGLE_CLOUD_PROJECT", "apip-dev-487809-c949c")
    main()
