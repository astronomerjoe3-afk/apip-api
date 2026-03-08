from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List


_MOJIBAKE_REPLACEMENTS = {
    "’": "'",
    "‘": "'",
    "“": '"',
    "�\x9d": '"',
    "�": '"',
    "–": "-",
    "—": "-",
    "…": "...",
    "±": "+/-",
    "÷": "/",
    "×": "x",
    "−": "-",
    "≈": "~",
    "≤": "<=",
    "≥": ">=",
    "can�t": "can't",
    "Can�t": "Can't",
    "don�t": "don't",
    "Don�t": "Don't",
    "doesn�t": "doesn't",
    "Doesn�t": "Doesn't",
    "isn�t": "isn't",
    "Isn�t": "Isn't",
    "won�t": "won't",
    "Won�t": "Won't",
    "you�re": "you're",
    "You�re": "You're",
    "it�s": "it's",
    "It�s": "It's",
    "that�s": "that's",
    "That�s": "That's",
    "there�s": "there's",
    "There�s": "There's",
    "what�s": "what's",
    "What�s": "What's",
    "meters'�and": "meters'�and",
    "room is�like": "room is�like",
    "2�3": "2�3",
    "mass ÷ volume": "mass � volume",
    "mass × volume": "mass � volume",
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
        bad_markers = ["�", "�", "�", "�"]
        return sum(s.count(marker) for marker in bad_markers)

    return min(candidates, key=score)


def _clean_text(value: str) -> str:
    out = _attempt_mojibake_repair(value)
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


def _student_prompt_blocks(items: List[Any] | None) -> List[Dict[str, Any]]:
    safe_blocks: List[Dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, dict):
            safe_blocks.append(
                {
                    "prompt": item.get("prompt"),
                    "hint": item.get("hint"),
                }
            )
        elif isinstance(item, str):
            safe_blocks.append(
                {
                    "prompt": item,
                    "hint": None,
                }
            )
    return safe_blocks


def _student_question_items(items: List[Dict[str, Any]] | None) -> List[Dict[str, Any]]:
    safe_items: List[Dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        safe_items.append(
            {
                "id": item.get("id"),
                "type": item.get("type"),
                "prompt": item.get("prompt"),
                "choices": item.get("choices") or [],
                "hint": item.get("hint"),
                "feedback": item.get("feedback") or [],
                "answer_index": item.get("answer_index"),
                "accepted_answers": item.get("accepted_answers") or [],
            }
        )
    return safe_items


def _student_capsules(capsules: List[Dict[str, Any]] | None) -> List[Dict[str, Any]]:
    safe_capsules: List[Dict[str, Any]] = []
    for capsule in capsules or []:
        if not isinstance(capsule, dict):
            continue
        safe_capsules.append(
            {
                "prompt": capsule.get("prompt"),
                "checks": _student_question_items(capsule.get("checks")),
            }
        )
    return safe_capsules


def to_student_lesson_view(lesson: Dict[str, Any]) -> Dict[str, Any]:
    normalized = normalize_lesson_payload(lesson)

    phases = normalized.get("phases") or {}
    if not isinstance(phases, dict):
        phases = {}

    analogical_grounding = phases.get("analogical_grounding") or {}
    simulation_inquiry = phases.get("simulation_inquiry") or {}
    concept_reconstruction = phases.get("concept_reconstruction") or {}
    diagnostic = phases.get("diagnostic") or {}
    transfer = phases.get("transfer") or {}

    concept_capsules = _student_capsules(concept_reconstruction.get("capsules"))
    reconstruction_prompts = concept_reconstruction.get("prompts") or [
        capsule.get("prompt")
        for capsule in concept_capsules
        if isinstance(capsule, dict) and capsule.get("prompt")
    ]

    return {
        "lesson_id": normalized.get("lesson_id") or normalized.get("id"),
        "title": normalized.get("title"),
        "sequence": normalized.get("sequence") or normalized.get("order"),
        "phases": {
            "analogical_grounding": {
                "analogy_text": analogical_grounding.get("analogy_text"),
                "micro_prompts": _student_prompt_blocks(analogical_grounding.get("micro_prompts")),
            },
            "simulation_inquiry": {
                "lab_id": simulation_inquiry.get("lab_id"),
                "inquiry_prompts": _student_prompt_blocks(simulation_inquiry.get("inquiry_prompts")),
            },
            "concept_reconstruction": {
                "prompts": reconstruction_prompts,
                "capsules": concept_capsules,
            },
            "diagnostic": {
                "items": _student_question_items(diagnostic.get("items")),
            },
            "transfer": {
                "items": _student_question_items(transfer.get("items")),
            },
        },
    }


def to_student_lessons_view(lessons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [to_student_lesson_view(lesson) for lesson in lessons]
