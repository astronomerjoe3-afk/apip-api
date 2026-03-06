from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List


_MOJIBAKE_REPLACEMENTS = {
    "â€™": "'",
    "â€˜": "'",
    "â€œ": '"',
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
    "â€":"\"",
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


def _clean_text(value: str) -> str:
    out = value
    for bad, good in _MOJIBAKE_REPLACEMENTS.items():
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


def normalize_lesson_payload(lesson: Dict[str, Any]) -> Dict[str, Any]:
    lesson_copy = deepcopy(lesson)
    return _normalize_value(lesson_copy)


def normalize_lessons_payload(lessons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_lesson_payload(lesson) for lesson in lessons]


def to_student_lesson_view(lesson: Dict[str, Any]) -> Dict[str, Any]:
    """
    Return only student-safe lesson fields.

    Rules:
    - no commitment_prompt
    - no hidden/internal labels beyond the existing phase buckets
    - preserve prompts/items needed by the runner
    """
    normalized = normalize_lesson_payload(lesson)

    phases = normalized.get("phases") or {}
    if not isinstance(phases, dict):
        phases = {}

    student_phases = {
        "analogical_grounding": phases.get("analogical_grounding") or {},
        "simulation_inquiry": phases.get("simulation_inquiry") or {},
        "concept_reconstruction": phases.get("concept_reconstruction") or {},
        "diagnostic": phases.get("diagnostic") or {},
        "transfer": phases.get("transfer") or {},
    }

    return {
        "id": normalized.get("id"),
        "lesson_id": normalized.get("lesson_id"),
        "module_id": normalized.get("module_id"),
        "title": normalized.get("title"),
        "sequence": normalized.get("sequence"),
        "updated_utc": normalized.get("updated_utc"),
        "phases": student_phases,
    }


def to_student_lessons_view(lessons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [to_student_lesson_view(lesson) for lesson in lessons]
