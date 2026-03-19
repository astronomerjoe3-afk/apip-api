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


def _first_present(item: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in item and item.get(key) is not None:
            return item.get(key)
    return None


def _choice_strings(value: Any) -> List[str]:
    choices: List[str] = []
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, dict):
                label = entry.get("label") or entry.get("text") or entry.get("value")
                if label is not None:
                    choices.append(str(label))
            elif entry is not None:
                choices.append(str(entry))
    return choices


def _text_strings(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(entry) for entry in value if entry is not None and str(entry).strip()]
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def _feedback_strings(value: Any) -> List[str]:
    if isinstance(value, dict):
        return [str(entry) for entry in value.values() if entry is not None]
    if isinstance(value, list):
        return [str(entry) for entry in value if entry is not None]
    return []


def _accepted_answers(item: Dict[str, Any], choices: List[str]) -> List[str]:
    accepted = _first_present(item, "accepted_answers", "acceptedAnswers", "correct_answers", "correctAnswers", "acceptable_answers")
    values = _choice_strings(accepted)
    correct_answer = _first_present(item, "correct_answer", "correctAnswer")
    if isinstance(correct_answer, str) and correct_answer.strip() and not choices:
        values.append(correct_answer)
    return values


def _acceptance_rules(item: Dict[str, Any]) -> Dict[str, Any]:
    raw = item.get("acceptance_rules")
    if not isinstance(raw, dict):
        return {}
    phrase_groups: List[List[str]] = []
    for group in raw.get("phrase_groups") or []:
        if isinstance(group, list):
            phrases = [str(phrase) for phrase in group if phrase is not None and str(phrase).strip()]
            if phrases:
                phrase_groups.append(phrases)
    return {"phrase_groups": phrase_groups} if phrase_groups else {}


def _answer_index(item: Dict[str, Any], choices: List[str]) -> Any:
    raw = _first_present(item, "answer_index", "answerIndex", "correct_index", "correctIndex", "correct_choice_index", "correctChoiceIndex")
    if isinstance(raw, int):
        return raw
    correct_answer = _first_present(item, "correct_answer", "correctAnswer")
    if isinstance(correct_answer, str):
        for index, choice in enumerate(choices):
            if str(choice).strip().lower() == correct_answer.strip().lower():
                return index
    return raw


def _student_question_items(items: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    questions: List[Dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue

        choices = _choice_strings(_first_present(item, "choices", "options", "answers"))
        feedback = _feedback_strings(_first_present(item, "feedback", "option_feedback", "optionFeedback", "rationales"))
        if len(feedback) < len(choices):
            feedback = feedback + [str(_first_present(item, "hint", "explanation", "teaching_focus") or "")] * (len(choices) - len(feedback))

        questions.append(
            {
                "id": _first_present(item, "id", "item_id", "question_id"),
                "type": _first_present(item, "type", "item_type"),
                "prompt": _first_present(item, "prompt", "question", "stem"),
                "choices": choices,
                "hint": _first_present(item, "hint", "explanation", "teaching_focus"),
                "feedback": feedback,
                "answer_index": _answer_index(item, choices),
                "accepted_answers": _accepted_answers(item, choices),
                "acceptance_rules": _acceptance_rules(item),
                "skill_tags": _text_strings(item.get("skill_tags")),
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


def _student_authoring_contract(authoring: Any) -> Dict[str, Any]:
    if not isinstance(authoring, dict):
        return {}
    return {
        "worked_examples": deepcopy(authoring.get("worked_examples") or []),
        "visual_assets": deepcopy(authoring.get("visual_assets") or []),
        "animation_assets": deepcopy(authoring.get("animation_assets") or []),
        "simulation_contract": deepcopy(authoring.get("simulation_contract") or {}),
        "assessment_bank_targets": deepcopy(authoring.get("assessment_bank_targets") or {}),
        "scaffold_support": deepcopy(authoring.get("scaffold_support") or {}),
    }


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
        "authoring_contract": _student_authoring_contract(normalized.get("authoring_contract")),
    }


def to_student_lessons_view(lessons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [to_student_lesson_view(lesson) for lesson in lessons]
