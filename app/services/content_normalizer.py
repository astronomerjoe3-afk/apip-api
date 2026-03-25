from __future__ import annotations

from copy import deepcopy
from itertools import product
import re
from typing import Any, Dict, List, Optional

from scripts.lesson_authoring_contract import (
    default_assessment_alignment,
    default_competency_mapping,
    default_spiral_reinforcement,
)
from app.services.technical_words_catalog import ensure_minimum_technical_words, module_code_from_lesson


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

_SHORT_ACCEPTED_MIN = 10
_SHORT_ACCEPTED_MAX = 15
_ASSESSMENT_TEXT_ACRONYMS = {
    "AC",
    "DC",
    "EM",
    "EMF",
    "GPE",
    "IGCSE",
    "IR",
    "IV",
    "KE",
    "RMS",
    "SHM",
    "SI",
    "SUVAT",
    "UV",
}
_ASSESSMENT_TEXT_LOWERCASE_TOKENS = {
    "a",
    "c",
    "cm",
    "ev",
    "g",
    "gev",
    "hz",
    "j",
    "kg",
    "km",
    "m",
    "ma",
    "mev",
    "mm",
    "ms",
    "mv",
    "n",
    "nm",
    "pa",
    "s",
    "v",
    "w",
}
_LOW_SIGNAL_VARIANT_WORDS = {
    "and",
    "because",
    "bigger",
    "both",
    "branch",
    "different",
    "first",
    "greater",
    "less",
    "main",
    "more",
    "not",
    "only",
    "path",
    "rather",
    "route",
    "same",
    "smaller",
    "than",
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


def _normalize_assessment_text(value: str) -> str:
    single_line = " ".join(str(value or "").strip().split())
    if not single_line:
        return single_line

    letters = re.findall(r"[A-Za-z]", single_line)
    if len(letters) < 2:
        lowered = single_line.lower()
        if lowered in _ASSESSMENT_TEXT_LOWERCASE_TOKENS:
            return lowered
        uppered = single_line.upper()
        if uppered in _ASSESSMENT_TEXT_ACRONYMS:
            return uppered
        return single_line

    uppercase_count = sum(1 for letter in letters if letter.isupper())
    lowercase_count = sum(1 for letter in letters if letter.islower())
    is_shouty = lowercase_count == 0 or uppercase_count / len(letters) > 0.92
    if not is_shouty or re.search(r"[=^_<>]", single_line):
        return single_line

    normalized = single_line.lower()
    normalized = re.sub(
        r'^(\s*["\'“”‘’(\[]*)([a-z])',
        lambda match: f"{match.group(1)}{match.group(2).upper()}",
        normalized,
        count=1,
    )

    for acronym in _ASSESSMENT_TEXT_ACRONYMS:
        title_case = acronym[:1] + acronym[1:].lower()
        normalized = re.sub(rf"\b{re.escape(title_case)}\b", acronym, normalized)

    for token in _ASSESSMENT_TEXT_LOWERCASE_TOKENS:
        capitalized_token = token[:1].upper() + token[1:]
        normalized = re.sub(rf"\b{re.escape(capitalized_token)}\b", token, normalized)

    normalized = re.sub(
        r"\b([a-z]{1,2})-(\d+)\b",
        lambda match: (
            f"{match.group(1).upper()}-{match.group(2)}"
            if len(match.group(1)) == 1
            else f"{match.group(1)[0].upper()}{match.group(1)[1:].lower()}-{match.group(2)}"
        ),
        normalized,
    )
    return normalized


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


def _accepted_answer_key(value: str) -> str:
    return " ".join(str(value).strip().lower().rstrip(".!?").split())


def _append_unique_answer(values: List[str], candidate: str) -> None:
    text = str(candidate or "").strip()
    if not text:
        return
    key = _accepted_answer_key(text)
    if not key:
        return
    if any(_accepted_answer_key(existing) == key for existing in values):
        return
    values.append(text)


def _meaningful_phrase(phrase: str) -> bool:
    words = [word for word in re.split(r"[^a-z0-9+-]+", phrase.lower()) if word]
    if not words:
        return False
    return any(word not in _LOW_SIGNAL_VARIANT_WORDS for word in words)


def _generated_short_answer_variants(accepted_answers: List[str], phrase_groups: List[List[str]]) -> List[str]:
    values: List[str] = []
    for answer in accepted_answers:
        _append_unique_answer(values, answer)

    for answer in list(values):
        lowered = answer.lower()
        if lowered.startswith("because "):
            _append_unique_answer(values, answer[8:].strip())
        else:
            _append_unique_answer(values, f"Because {answer[0].lower()}{answer[1:]}" if len(answer) > 1 else f"Because {answer.lower()}")

    for group in phrase_groups:
        for phrase in group:
            if _meaningful_phrase(phrase):
                _append_unique_answer(values, f"{phrase} matters")
                _append_unique_answer(values, f"Because {phrase} matters")
            if len(values) >= _SHORT_ACCEPTED_MIN:
                break
        if len(values) >= _SHORT_ACCEPTED_MIN:
            break

    if phrase_groups and len(values) < _SHORT_ACCEPTED_MIN:
        limited_groups = [group[:4] for group in phrase_groups[:4] if group]
        if limited_groups:
            for combo in product(*limited_groups):
                joined = " ".join(str(part).strip() for part in combo if str(part).strip())
                if not joined:
                    continue
                _append_unique_answer(values, joined)
                _append_unique_answer(values, f"Because {joined}")
                if len(values) >= _SHORT_ACCEPTED_MIN:
                    break

    return values[:_SHORT_ACCEPTED_MAX]


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

        choices = [_normalize_assessment_text(choice) for choice in _choice_strings(_first_present(item, "choices", "options", "answers"))]
        feedback = [_normalize_assessment_text(entry) for entry in _feedback_strings(_first_present(item, "feedback", "option_feedback", "optionFeedback", "rationales"))]
        if len(feedback) < len(choices):
            normalized_hint = _normalize_assessment_text(str(_first_present(item, "hint", "explanation", "teaching_focus") or ""))
            feedback = feedback + [normalized_hint] * (len(choices) - len(feedback))

        accepted_answers = [_normalize_assessment_text(answer) for answer in _accepted_answers(item, choices)]
        acceptance_rules = _acceptance_rules(item)
        qtype = str(_first_present(item, "type", "item_type") or "").strip().lower()
        if qtype == "short":
            accepted_answers = _generated_short_answer_variants(
                accepted_answers,
                acceptance_rules.get("phrase_groups") or [],
            )

        questions.append(
            {
                "id": _first_present(item, "id", "item_id", "question_id"),
                "type": _first_present(item, "type", "item_type"),
                "prompt": _normalize_assessment_text(str(_first_present(item, "prompt", "question", "stem") or "")),
                "choices": choices,
                "hint": _normalize_assessment_text(str(_first_present(item, "hint", "explanation", "teaching_focus") or "")),
                "feedback": feedback,
                "answer_index": _answer_index(item, choices),
                "accepted_answers": accepted_answers,
                "acceptance_rules": acceptance_rules,
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


def _student_authoring_contract(authoring: Any, lesson: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(authoring, dict):
        authoring = {}
    module_code = module_code_from_lesson(lesson)
    return {
        "core_concepts": deepcopy(authoring.get("core_concepts") or []),
        "technical_words": ensure_minimum_technical_words(authoring.get("technical_words") or [], module_code, lesson=lesson),
        "formulas": deepcopy(authoring.get("formulas") or []),
        "analogy_map": deepcopy(authoring.get("analogy_map") or {}),
        "worked_examples": deepcopy(authoring.get("worked_examples") or []),
        "visual_assets": deepcopy(authoring.get("visual_assets") or []),
        "animation_assets": deepcopy(authoring.get("animation_assets") or []),
        "simulation_contract": deepcopy(authoring.get("simulation_contract") or {}),
        "assessment_bank_targets": deepcopy(authoring.get("assessment_bank_targets") or {}),
        "scaffold_support": deepcopy(authoring.get("scaffold_support") or {}),
        "visual_clarity_checks": deepcopy(authoring.get("visual_clarity_checks") or []),
    }


def _inferred_spiral_focus(lesson: Dict[str, Any]) -> List[Dict[str, Any]]:
    lesson_code = str(lesson.get("lesson_id") or lesson.get("id") or lesson.get("module_id") or "").upper()
    if lesson_code.startswith("A") or lesson_code.startswith("MA"):
        target_level, target_stage = ("level_3", "analytical_derivation")
    elif lesson_code.startswith("M"):
        target_level, target_stage = ("level_2", "quantitative")
    else:
        target_level, target_stage = ("level_1", "intuitive")

    spiral = default_spiral_reinforcement()
    stages = [
        deepcopy(stage)
        for stage in spiral.get("stages") or []
        if stage.get("level") == target_level and stage.get("stage") == target_stage
    ]
    return stages or [deepcopy((spiral.get("stages") or [])[0])]


def _student_curriculum_contract(authoring: Any, lesson: Dict[str, Any]) -> Dict[str, Any]:
    authored = authoring if isinstance(authoring, dict) else {}
    assessment_alignment = deepcopy(authored.get("assessment_alignment") or default_assessment_alignment())
    competency_mapping = deepcopy(authored.get("competency_mapping") or default_competency_mapping())
    authored_spiral = authored.get("spiral_reinforcement") if isinstance(authored.get("spiral_reinforcement"), dict) else {}
    spiral_reinforcement = deepcopy(authored_spiral or default_spiral_reinforcement())

    if not isinstance(assessment_alignment, dict):
        assessment_alignment = default_assessment_alignment()
    if not assessment_alignment.get("paper_structure"):
        assessment_alignment["paper_structure"] = deepcopy(default_assessment_alignment()["paper_structure"])
    if not assessment_alignment.get("auto_generation_outputs"):
        assessment_alignment["auto_generation_outputs"] = deepcopy(default_assessment_alignment()["auto_generation_outputs"])

    if not isinstance(competency_mapping, dict):
        competency_mapping = default_competency_mapping()
    if not competency_mapping.get("metrics"):
        competency_mapping["metrics"] = deepcopy(default_competency_mapping()["metrics"])

    if not isinstance(spiral_reinforcement, dict):
        spiral_reinforcement = default_spiral_reinforcement()
    if not spiral_reinforcement.get("stages"):
        spiral_reinforcement["stages"] = deepcopy(default_spiral_reinforcement()["stages"])
    if not authored_spiral or not spiral_reinforcement.get("lesson_stage_focus"):
        spiral_reinforcement["lesson_stage_focus"] = _inferred_spiral_focus(lesson)

    return {
        "assessment_alignment": assessment_alignment,
        "competency_mapping": competency_mapping,
        "spiral_reinforcement": spiral_reinforcement,
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
        "authoring_contract": {
            **_student_authoring_contract(normalized.get("authoring_contract"), normalized),
            **_student_curriculum_contract(normalized.get("authoring_contract"), normalized),
        },
    }


def to_student_lessons_view(lessons: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [to_student_lesson_view(lesson) for lesson in lessons]
