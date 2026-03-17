from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Sequence

NEXTGEN_REQUIRED_PHASES = (
    "diagnostic",
    "analogical_grounding",
    "simulation_inquiry",
    "concept_reconstruction",
    "transfer",
)

QUESTION_TYPES = {"mcq", "short"}
CORE_REPRESENTATION_KINDS = {"words", "formula"}
OPTIONAL_REPRESENTATION_KINDS = {"diagram", "graph", "table", "model", "equation_story"}


class LessonAuthoringContractError(ValueError):
    """Raised when a next-generation lesson package misses required authoring pieces."""


def _record(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _whole_number(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    raw = _text(value)
    return int(raw) if raw.isdigit() else None


def _require(condition: bool, message: str, errors: List[str]) -> None:
    if not condition:
        errors.append(message)


def _validate_tags(tags: Sequence[Any], allowlist: Sequence[str], errors: List[str], label: str) -> None:
    clean = [_text(tag) for tag in tags if _text(tag)]
    _require(bool(clean), f"{label}: at least one misconception tag is required.", errors)
    for tag in clean:
        if allowlist and tag not in allowlist:
            errors.append(f"{label}: tag '{tag}' is not in the module allowlist.")


def _validate_question(item: Dict[str, Any], allowlist: Sequence[str], errors: List[str], label: str) -> None:
    qtype = _text(item.get("type"))
    _require(qtype in QUESTION_TYPES, f"{label}: question type must be one of {sorted(QUESTION_TYPES)}.", errors)
    _require(bool(_text(item.get("id")) or _text(item.get("question_id"))), f"{label}: missing question id.", errors)
    _require(bool(_text(item.get("prompt"))), f"{label}: missing prompt.", errors)
    _require(bool(_text(item.get("hint"))), f"{label}: missing hint.", errors)
    _require(bool(_items(item.get("feedback"))), f"{label}: feedback must not be empty.", errors)
    _validate_tags(_items(item.get("misconception_tags")), allowlist, errors, label)
    if qtype == "mcq":
        choices = [_text(choice) for choice in _items(item.get("choices")) if _text(choice)]
        answer_index = item.get("answer_index")
        _require(len(choices) >= 4, f"{label}: mcq questions need at least 4 choices.", errors)
        _require(isinstance(answer_index, int) and 0 <= answer_index < len(choices), f"{label}: mcq answer_index is invalid.", errors)
    if qtype == "short":
        accepted = [_text(answer) for answer in _items(item.get("accepted_answers")) if _text(answer)]
        _require(bool(accepted), f"{label}: short questions need accepted answers.", errors)


def _validate_prompt_block(item: Dict[str, Any], errors: List[str], label: str) -> None:
    _require(bool(_text(item.get("prompt"))), f"{label}: missing prompt text.", errors)
    _require(bool(_text(item.get("hint"))), f"{label}: missing hint text.", errors)


def _validate_formula(item: Dict[str, Any], errors: List[str], label: str) -> None:
    _require(bool(_text(item.get("equation"))), f"{label}: missing equation.", errors)
    _require(bool(_text(item.get("meaning"))), f"{label}: missing conceptual meaning.", errors)
    units = [_text(unit) for unit in _items(item.get("units")) if _text(unit)]
    _require(bool(units), f"{label}: list at least one valid unit form.", errors)
    _require(bool(_text(item.get("conditions"))), f"{label}: explain when the relationship applies.", errors)


def _validate_representation(item: Dict[str, Any], errors: List[str], label: str) -> None:
    kind = _text(item.get("kind"))
    valid_kinds = CORE_REPRESENTATION_KINDS | OPTIONAL_REPRESENTATION_KINDS
    _require(kind in valid_kinds, f"{label}: representation kind must be one of {sorted(valid_kinds)}.", errors)
    _require(bool(_text(item.get("purpose"))), f"{label}: representation needs a purpose statement.", errors)


def _validate_worked_example(item: Dict[str, Any], errors: List[str], label: str) -> None:
    _require(bool(_text(item.get("prompt"))), f"{label}: missing example prompt.", errors)
    steps = [_text(step) for step in _items(item.get("steps")) if _text(step)]
    _require(len(steps) >= 3, f"{label}: worked examples need at least 3 reasoning steps.", errors)
    _require(bool(_text(item.get("final_answer"))), f"{label}: missing final answer.", errors)
    _require(bool(_text(item.get("why_it_matters"))), f"{label}: explain the conceptual takeaway.", errors)


def _validate_visual(item: Dict[str, Any], errors: List[str], label: str) -> None:
    _require(bool(_text(item.get("asset_id"))), f"{label}: missing asset id.", errors)
    _require(bool(_text(item.get("purpose"))), f"{label}: missing visual purpose.", errors)
    _require(bool(_text(item.get("caption"))), f"{label}: missing visual caption.", errors)


def validate_nextgen_lesson(lesson: Dict[str, Any], allowlist: Sequence[str]) -> List[str]:
    errors: List[str] = []
    lesson_id = _text(lesson.get("lesson_id") or lesson.get("id") or "lesson")
    _require(bool(_text(lesson.get("id"))), f"{lesson_id}: missing top-level id.", errors)
    _require(bool(_text(lesson.get("lesson_id"))), f"{lesson_id}: missing top-level lesson_id.", errors)
    _require(bool(_text(lesson.get("module_id")) or _text(lesson.get("moduleId"))), f"{lesson_id}: missing module id.", errors)
    _require(bool(_text(lesson.get("title"))), f"{lesson_id}: missing lesson title.", errors)

    phases = _record(lesson.get("phases"))
    for phase in NEXTGEN_REQUIRED_PHASES:
        _require(phase in phases, f"{lesson_id}: missing phase '{phase}'.", errors)

    diagnostic = _record(phases.get("diagnostic"))
    diagnostic_items = [_record(item) for item in _items(diagnostic.get("items"))]
    _require(len(diagnostic_items) >= 3, f"{lesson_id}: diagnostic needs at least 3 items for fresh-attempt variation.", errors)
    for index, item in enumerate(diagnostic_items, start=1):
        _validate_question(item, allowlist, errors, f"{lesson_id} diagnostic item {index}")

    grounding = _record(phases.get("analogical_grounding"))
    _require(bool(_text(grounding.get("analogy_text"))), f"{lesson_id}: analogy text is required.", errors)
    _require(bool(_text(grounding.get("commitment_prompt"))), f"{lesson_id}: analogy commitment prompt is required.", errors)
    micro_prompts = [_record(item) for item in _items(grounding.get("micro_prompts"))]
    _require(len(micro_prompts) >= 2, f"{lesson_id}: analogy stage needs at least 2 micro-prompts.", errors)
    for index, item in enumerate(micro_prompts, start=1):
        _validate_prompt_block(item, errors, f"{lesson_id} analogy micro-prompt {index}")

    simulation = _record(phases.get("simulation_inquiry"))
    _require(bool(_text(simulation.get("lab_id"))), f"{lesson_id}: simulation stage needs a lab id.", errors)
    inquiry_prompts = [_record(item) for item in _items(simulation.get("inquiry_prompts"))]
    _require(len(inquiry_prompts) >= 2, f"{lesson_id}: simulation stage needs at least 2 inquiry prompts.", errors)
    for index, item in enumerate(inquiry_prompts, start=1):
        _validate_prompt_block(item, errors, f"{lesson_id} simulation inquiry {index}")

    reconstruction = _record(phases.get("concept_reconstruction"))
    prompts = [_text(prompt) for prompt in _items(reconstruction.get("prompts")) if _text(prompt)]
    _require(len(prompts) >= 2, f"{lesson_id}: concept reconstruction needs at least 2 prompts.", errors)
    capsules = [_record(item) for item in _items(reconstruction.get("capsules"))]
    _require(bool(capsules), f"{lesson_id}: concept reconstruction needs at least one capsule.", errors)
    for index, capsule in enumerate(capsules, start=1):
        _require(bool(_text(capsule.get("prompt"))), f"{lesson_id} capsule {index}: missing prompt.", errors)
        checks = [_record(item) for item in _items(capsule.get("checks"))]
        _require(bool(checks), f"{lesson_id} capsule {index}: needs at least one check.", errors)
        for check_index, item in enumerate(checks, start=1):
            _validate_question(item, allowlist, errors, f"{lesson_id} capsule {index} check {check_index}")

    transfer = _record(phases.get("transfer"))
    transfer_items = [_record(item) for item in _items(transfer.get("items"))]
    _require(len(transfer_items) >= 3, f"{lesson_id}: transfer needs at least 3 items.", errors)
    for index, item in enumerate(transfer_items, start=1):
        _validate_question(item, allowlist, errors, f"{lesson_id} transfer item {index}")

    authoring = _record(lesson.get("authoring_contract"))
    _require(bool(authoring), f"{lesson_id}: missing authoring_contract block for next-generation lessons.", errors)
    concept_targets = [_text(item) for item in _items(authoring.get("concept_targets")) if _text(item)]
    _require(len(concept_targets) >= 2, f"{lesson_id}: authoring_contract.concept_targets needs at least 2 targets.", errors)
    _require("prerequisite_lessons" in authoring, f"{lesson_id}: authoring_contract.prerequisite_lessons key is required.", errors)
    _validate_tags(_items(authoring.get("misconception_focus")), allowlist, errors, f"{lesson_id} authoring misconception focus")

    formulas = [_record(item) for item in _items(authoring.get("formulas"))]
    _require(bool(formulas), f"{lesson_id}: authoring_contract.formulas needs at least one formula entry.", errors)
    for index, item in enumerate(formulas, start=1):
        _validate_formula(item, errors, f"{lesson_id} formula {index}")

    representations = [_record(item) for item in _items(authoring.get("representations"))]
    _require(len(representations) >= 3, f"{lesson_id}: authoring_contract.representations needs at least 3 entries.", errors)
    seen_kinds = {_text(item.get("kind")) for item in representations if _text(item.get("kind"))}
    _require(CORE_REPRESENTATION_KINDS.issubset(seen_kinds), f"{lesson_id}: representations must include both words and formula views.", errors)
    _require(bool(seen_kinds & OPTIONAL_REPRESENTATION_KINDS), f"{lesson_id}: add at least one non-text representation such as diagram, graph, table, or model.", errors)
    for index, item in enumerate(representations, start=1):
        _validate_representation(item, errors, f"{lesson_id} representation {index}")

    analogy_map = _record(authoring.get("analogy_map"))
    _require(bool(_text(analogy_map.get("comparison"))), f"{lesson_id}: analogy_map.comparison is required.", errors)
    mapping = [_text(item) for item in _items(analogy_map.get("mapping")) if _text(item)]
    _require(len(mapping) >= 2, f"{lesson_id}: analogy_map.mapping needs at least 2 explicit correspondences.", errors)
    _require(bool(_text(analogy_map.get("limit"))), f"{lesson_id}: analogy_map.limit is required.", errors)
    _require(bool(_text(analogy_map.get("prediction_prompt"))), f"{lesson_id}: analogy_map.prediction_prompt is required.", errors)

    worked_examples = [_record(item) for item in _items(authoring.get("worked_examples"))]
    _require(len(worked_examples) >= 2, f"{lesson_id}: provide at least 2 worked examples, including a contrast or non-example.", errors)
    for index, item in enumerate(worked_examples, start=1):
        _validate_worked_example(item, errors, f"{lesson_id} worked example {index}")

    visual_assets = [_record(item) for item in _items(authoring.get("visual_assets"))]
    _require(bool(visual_assets), f"{lesson_id}: at least one visual asset is required.", errors)
    for index, item in enumerate(visual_assets, start=1):
        _validate_visual(item, errors, f"{lesson_id} visual {index}")

    simulation_contract = _record(authoring.get("simulation_contract"))
    _require(bool(_text(simulation_contract.get("baseline_case"))), f"{lesson_id}: simulation_contract.baseline_case is required.", errors)
    comparison_tasks = [_text(item) for item in _items(simulation_contract.get("comparison_tasks")) if _text(item)]
    _require(len(comparison_tasks) >= 2, f"{lesson_id}: simulation_contract.comparison_tasks needs at least 2 comparison tasks.", errors)
    _require(bool(_text(simulation_contract.get("watch_for"))), f"{lesson_id}: simulation_contract.watch_for is required.", errors)
    _require(bool(_text(simulation_contract.get("takeaway"))), f"{lesson_id}: simulation_contract.takeaway is required.", errors)

    reflection_prompts = [_text(item) for item in _items(authoring.get("reflection_prompts")) if _text(item)]
    _require(bool(reflection_prompts), f"{lesson_id}: add at least one reflection prompt.", errors)

    mastery_skills = [_text(item) for item in _items(authoring.get("mastery_skills")) if _text(item)]
    _require(len(mastery_skills) >= 5, f"{lesson_id}: authoring_contract.mastery_skills needs at least 5 distinct skills.", errors)

    variation_plan = _record(authoring.get("variation_plan"))
    _require(bool(_text(variation_plan.get("diagnostic"))), f"{lesson_id}: explain fresh-attempt diagnostic variation.", errors)
    _require(bool(_text(variation_plan.get("concept_gate"))), f"{lesson_id}: explain concept-gate retry variation.", errors)
    _require(bool(_text(variation_plan.get("mastery"))), f"{lesson_id}: explain mastery variation and no-repeat policy.", errors)

    assessment_targets = _record(authoring.get("assessment_bank_targets"))
    if assessment_targets:
        diagnostic_pool_min = _whole_number(assessment_targets.get("diagnostic_pool_min"))
        if diagnostic_pool_min is not None:
            _require(
                len(diagnostic_items) >= diagnostic_pool_min,
                f"{lesson_id}: diagnostic pool must contain at least {diagnostic_pool_min} items when assessment_bank_targets.diagnostic_pool_min is declared.",
                errors,
            )
        concept_gate_pool_min = _whole_number(assessment_targets.get("concept_gate_pool_min"))
        concept_gate_count = sum(len(_items(capsule.get("checks"))) for capsule in capsules)
        if concept_gate_pool_min is not None:
            _require(
                concept_gate_count >= concept_gate_pool_min,
                f"{lesson_id}: concept gate pool must contain at least {concept_gate_pool_min} checks when assessment_bank_targets.concept_gate_pool_min is declared.",
                errors,
            )
        mastery_pool_min = _whole_number(assessment_targets.get("mastery_pool_min"))
        if mastery_pool_min is not None:
            _require(
                len(transfer_items) >= mastery_pool_min,
                f"{lesson_id}: transfer pool must contain at least {mastery_pool_min} items when assessment_bank_targets.mastery_pool_min is declared.",
                errors,
            )
        _require(
            bool(_text(assessment_targets.get("fresh_attempt_policy"))),
            f"{lesson_id}: assessment_bank_targets.fresh_attempt_policy is required when assessment_bank_targets is declared.",
            errors,
        )

    visual_clarity_checks = [_text(item) for item in _items(authoring.get("visual_clarity_checks")) if _text(item)]
    if authoring.get("visual_clarity_checks") is not None:
        _require(
            len(visual_clarity_checks) >= 3,
            f"{lesson_id}: visual_clarity_checks should describe at least 3 concrete readability checks when present.",
            errors,
        )

    release_checks = [_text(item) for item in _items(authoring.get("release_checks")) if _text(item)]
    _require(len(release_checks) >= 4, f"{lesson_id}: authoring_contract.release_checks needs at least 4 release checks.", errors)

    return errors


def validate_nextgen_module(module_doc: Dict[str, Any], lessons: Sequence[Dict[str, Any]], sim_labs: Sequence[Dict[str, Any]], allowlist: Sequence[str]) -> None:
    errors: List[str] = []
    module_id = _text(module_doc.get("module_id") or module_doc.get("id") or "module")
    _require(bool(_text(module_doc.get("id")) or _text(module_doc.get("module_id"))), f"{module_id}: module needs an id.", errors)
    _require(bool(_text(module_doc.get("title"))), f"{module_id}: module needs a title.", errors)
    _require(bool(_text(module_doc.get("description"))), f"{module_id}: module needs a description.", errors)
    mastery_outcomes = [_text(item) for item in _items(module_doc.get("mastery_outcomes")) if _text(item)]
    _require(len(mastery_outcomes) >= 4, f"{module_id}: include at least 4 module mastery outcomes.", errors)
    allowlist_items = [_text(item) for item in _items(module_doc.get("misconception_tag_allowlist")) if _text(item)]
    _require(bool(allowlist_items), f"{module_id}: misconception_tag_allowlist is required.", errors)
    _require(bool(_text(module_doc.get("content_version"))), f"{module_id}: content_version is required.", errors)
    _require(bool(_text(module_doc.get("authoring_standard"))), f"{module_id}: authoring_standard is required for next-generation modules.", errors)

    _require(len(lessons) >= 6, f"{module_id}: next-generation modules should contain at least 6 lessons.", errors)
    _require(len(sim_labs) >= len(lessons), f"{module_id}: provide one simulation/lab configuration per lesson.", errors)

    for lesson in lessons:
        errors.extend(validate_nextgen_lesson(_record(lesson), allowlist_items or allowlist))

    if errors:
        raise LessonAuthoringContractError("\n".join(errors))


def nextgen_lesson_template(module_id: str, lesson_id: str, sequence: int, title: str) -> Dict[str, Any]:
    return {
        "id": lesson_id,
        "lesson_id": lesson_id,
        "moduleId": module_id,
        "module_id": module_id,
        "sequence": sequence,
        "order": sequence,
        "title": title,
        "updated_utc": "REPLACE_WITH_UTC_TIMESTAMP",
        "phases": {
            "diagnostic": {
                "two_tier": True,
                "items": [
                    {"id": f"{lesson_id}_D1", "question_id": f"{lesson_id}_D1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"]},
                    {"id": f"{lesson_id}_D2", "question_id": f"{lesson_id}_D2", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"]},
                    {"id": f"{lesson_id}_D3", "question_id": f"{lesson_id}_D3", "type": "short", "prompt": "", "accepted_answers": [""], "hint": "", "feedback": [""], "misconception_tags": ["REPLACE_TAG"]},
                ],
            },
            "analogical_grounding": {
                "analogy_text": "",
                "commitment_prompt": "",
                "micro_prompts": [
                    {"prompt": "", "hint": ""},
                    {"prompt": "", "hint": ""},
                ],
            },
            "simulation_inquiry": {
                "lab_id": f"{lesson_id.lower()}_lab",
                "inquiry_prompts": [
                    {"prompt": "", "hint": ""},
                    {"prompt": "", "hint": ""},
                ],
            },
            "concept_reconstruction": {
                "prompts": ["", ""],
                "capsules": [
                    {
                        "prompt": "",
                        "checks": [
                            {"id": f"{lesson_id}_C1", "question_id": f"{lesson_id}_C1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"]}
                        ],
                    }
                ],
            },
            "transfer": {
                "items": [
                    {"id": f"{lesson_id}_T1", "question_id": f"{lesson_id}_T1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"]},
                    {"id": f"{lesson_id}_T2", "question_id": f"{lesson_id}_T2", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"]},
                    {"id": f"{lesson_id}_T3", "question_id": f"{lesson_id}_T3", "type": "short", "prompt": "", "accepted_answers": [""], "hint": "", "feedback": [""], "misconception_tags": ["REPLACE_TAG"]},
                ],
            },
        },
        "authoring_contract": {
            "concept_targets": ["", ""],
            "prerequisite_lessons": [],
            "misconception_focus": ["REPLACE_TAG"],
            "formulas": [
                {"equation": "", "meaning": "", "units": [""], "conditions": ""},
            ],
            "representations": [
                {"kind": "words", "purpose": ""},
                {"kind": "formula", "purpose": ""},
                {"kind": "diagram", "purpose": ""},
            ],
            "analogy_map": {
                "comparison": "",
                "mapping": ["", ""],
                "limit": "",
                "prediction_prompt": "",
            },
            "worked_examples": [
                {"prompt": "", "steps": ["", "", ""], "final_answer": "", "why_it_matters": ""},
                {"prompt": "", "steps": ["", "", ""], "final_answer": "", "why_it_matters": ""},
            ],
            "visual_assets": [
                {"asset_id": f"{lesson_id.lower()}-visual.svg", "purpose": "", "caption": ""},
            ],
            "simulation_contract": {
                "baseline_case": "",
                "comparison_tasks": ["", ""],
                "watch_for": "",
                "takeaway": "",
            },
            "reflection_prompts": [""],
            "mastery_skills": ["", "", "", "", ""],
            "variation_plan": {
                "diagnostic": "New contexts, numbers, or representation on each fresh attempt.",
                "concept_gate": "Retries must rotate to a different quick-check prompt.",
                "mastery": "No repeated stems in one attempt; retests must change context or data.",
            },
            "release_checks": [
                "Every mastery-tested relationship is explicitly taught before mastery.",
                "Every formula is shown with meaning, units, and conditions.",
                "At least one non-text representation is used and checked.",
                "Visuals are readable on desktop and mobile.",
            ],
        },
    }


def nextgen_module_doc_template(module_id: str, title: str, description: str, allowlist: Sequence[str]) -> Dict[str, Any]:
    return {
        "id": module_id,
        "module_id": module_id,
        "title": title,
        "description": description,
        "sequence": 4,
        "level": "Advanced Foundation",
        "estimated_minutes": 120,
        "mastery_outcomes": ["", "", "", ""],
        "misconception_tag_allowlist": list(allowlist),
        "content_version": "REPLACE_WITH_VERSION",
        "authoring_standard": "lesson_authoring_spec_v1",
        "updated_utc": "REPLACE_WITH_UTC_TIMESTAMP",
    }


def clone_template(data: Dict[str, Any]) -> Dict[str, Any]:
    return deepcopy(data)
