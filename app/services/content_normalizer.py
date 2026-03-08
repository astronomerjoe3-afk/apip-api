from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Optional


_MOJIBAKE_REPLACEMENTS = {
    "â€™": "'",
    "â€˜": "'",
    "â€œ": '"',
    "â€\x9d": '"',
    "â€": '"',
    "â€“": "-",
    "â€”": "-",
    "â€¦": "...",
    "Â±": "+/-",
    "Ã·": "/",
    "Ã—": "x",
    "âˆ’": "-",
    "â‰ˆ": "~",
    "â‰¤": "<=",
    "â‰¥": ">=",
}


def _attempt_mojibake_repair(value: str) -> str:
    candidates = [value]

    for source_encoding in ("cp1252", "latin-1"):
        try:
            repaired = value.encode(source_encoding, errors="ignore").decode("utf-8", errors="ignore")
        except Exception:
            repaired = ""
        if repaired:
            candidates.append(repaired)

    def score(text: str) -> int:
        bad_markers = ("â", "Â", "Ã", "ï")
        return sum(text.count(marker) for marker in bad_markers)

    return min(candidates, key=score)


def _clean_text(value: str) -> str:
    cleaned = _attempt_mojibake_repair(value)
    for bad, good in _MOJIBAKE_REPLACEMENTS.items():
        cleaned = cleaned.replace(bad, good)
    return cleaned


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _clean_text(value)

    if isinstance(value, list):
        return [_normalize_value(item) for item in value]

    if isinstance(value, dict):
        normalized: Dict[str, Any] = {}
        for key, item in value.items():
            if key == "commitment_prompt":
                continue
            normalized[key] = _normalize_value(item)
        return normalized

    return value


def normalize_lesson_payload(lesson: Dict[str, Any]) -> Dict[str, Any]:
    return _normalize_value(deepcopy(lesson))


def normalize_lessons_payload(lessons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_lesson_payload(lesson) for lesson in lessons]


def _student_prompt_blocks(items: Optional[List[Any]]) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []
    for item in items or []:
        if isinstance(item, dict):
            blocks.append(
                {
                    "prompt": item.get("prompt"),
                    "hint": item.get("hint"),
                }
            )
        elif isinstance(item, str):
            blocks.append(
                {
                    "prompt": item,
                    "hint": None,
                }
            )
    return blocks


def _student_question_items(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    questions: List[Dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        questions.append(
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
    return questions


def _student_capsules(capsules: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    output: List[Dict[str, Any]] = []
    for capsule in capsules or []:
        if not isinstance(capsule, dict):
            continue
        output.append(
            {
                "prompt": capsule.get("prompt"),
                "checks": _student_question_items(capsule.get("checks")),
            }
        )
    return output


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
