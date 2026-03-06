from __future__ import annotations

import os
from copy import deepcopy
from typing import Any, Dict, Iterable, Tuple

from google.cloud import firestore

from app.db.firestore import get_firestore_client


MOJIBAKE_REPLACEMENTS = {
    "â€™": "'",
    "â€˜": "'",
    "â€œ": '"',
    "â€\x9d": '"',
    "â€": '"',
    "â€“": "-",
    "â€”": "—",
    "â€¦": "...",
    "Â±": "±",
    "Ã·": "÷",
    "Ã—": "×",
    "âˆ’": "-",
    "â‰ˆ": "≈",
    "â‰¤": "≤",
    "â‰¥": "≥",
    "canât": "can't",
    "Canât": "Can't",
    "donât": "don't",
    "Donât": "Don't",
    "doesnât": "doesn't",
    "Doesnât": "Doesn't",
    "isnât": "isn't",
    "Isnât": "Isn't",
    "wonât": "won't",
    "Wonât": "Won't",
    "youâre": "you're",
    "Youâre": "You're",
    "itâs": "it's",
    "Itâs": "It's",
    "thatâs": "that's",
    "Thatâs": "That's",
    "thereâs": "there's",
    "Thereâs": "There's",
    "whatâs": "what's",
    "Whatâs": "What's",
    "meters'âand": "meters'—and",
    "room isâlike": "room is—like",
    "2â3": "2–3",
    "mass Ã· volume": "mass ÷ volume",
    "mass Ã— volume": "mass × volume",
}


def _attempt_mojibake_repair(value: str) -> str:
    original = value
    candidates = [original]

    try:
        repaired = original.encode("cp1252", errors="ignore").decode("utf-8", errors="ignore")
        if repaired:
            candidates.append(repaired)
    except Exception:
        pass

    try:
        repaired = original.encode("latin-1", errors="ignore").decode("utf-8", errors="ignore")
        if repaired:
            candidates.append(repaired)
    except Exception:
        pass

    def score(s: str) -> int:
        bad_markers = ["â", "Â", "Ã", "�"]
        return sum(s.count(marker) for marker in bad_markers)

    return min(candidates, key=score)


def _clean_text(value: str) -> str:
    out = _attempt_mojibake_repair(value)
    for bad, good in MOJIBAKE_REPLACEMENTS.items():
        out = out.replace(bad, good)
    return out


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _clean_text(value)

    if isinstance(value, list):
        return [_normalize_value(v) for v in value]

    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for k, v in value.items():
            if k == "commitment_prompt":
                continue
            normalized[k] = _normalize_value(v)
        return normalized

    return value


def normalize_lesson_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    return _normalize_value(deepcopy(doc))


def iter_f1_lessons(db: firestore.Client) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for snap in db.collection("lessons").where(filter=firestore.FieldFilter("module_id", "==", "F1")).stream():
        yield snap.id, (snap.to_dict() or {})


def write_dual_paths(db: firestore.Client, lesson_doc_id: str, payload: Dict[str, Any]) -> None:
    # top-level canonical lesson doc
    db.collection("lessons").document(lesson_doc_id).set(payload, merge=True)

    # optional legacy/module subcollection mirror if present
    mod_ref = db.collection("modules").document("F1").collection("lessons").document(lesson_doc_id)
    if mod_ref.get().exists:
        mod_ref.set(payload, merge=True)


def main() -> None:
    project = (
        os.getenv("GOOGLE_CLOUD_PROJECT")
        or os.getenv("GCP_PROJECT")
        or os.getenv("GCLOUD_PROJECT")
        or "(auto)"
    )
    db = get_firestore_client()

    repaired = 0
    unchanged = 0

    for lesson_doc_id, lesson in iter_f1_lessons(db):
        normalized = normalize_lesson_doc(lesson)
        if normalized != lesson:
            write_dual_paths(db, lesson_doc_id, normalized)
            repaired += 1
            print(f"[UPDATED] lessons/{lesson_doc_id}")
        else:
            unchanged += 1
            print(f"[OK] lessons/{lesson_doc_id} (no change)")

    print(
        {
            "project": project,
            "module_id": "F1",
            "repaired": repaired,
            "unchanged": unchanged,
        }
    )


if __name__ == "__main__":
    main()
