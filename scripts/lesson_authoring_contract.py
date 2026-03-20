from __future__ import annotations

from copy import deepcopy
import re
from typing import Any, Dict, List, Sequence

NEXTGEN_REQUIRED_PHASES = (
    "diagnostic",
    "analogical_grounding",
    "simulation_inquiry",
    "concept_reconstruction",
    "transfer",
)

AUTHORING_STANDARD_V1 = "lesson_authoring_spec_v1"
AUTHORING_STANDARD_V2 = "lesson_authoring_spec_v2"
AUTHORING_STANDARD_V3 = "lesson_authoring_spec_v3"
LATEST_AUTHORING_STANDARD = AUTHORING_STANDARD_V3

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


def _uses_v2_plus(authoring_standard: str) -> bool:
    return _text(authoring_standard).lower() in {AUTHORING_STANDARD_V2, AUTHORING_STANDARD_V3}


def _uses_v3(authoring_standard: str) -> bool:
    return _text(authoring_standard).lower() == AUTHORING_STANDARD_V3


_NUMERIC_SHORT_ANSWER_RE = re.compile(
    r"^\s*[-+]?(?:\d+(?:\.\d+)?|\.\d+)(?:\s*[a-zA-Z0-9/%^_+\-*/.=()]+)?\s*$"
)


def _looks_numeric_short_answer(value: Any) -> bool:
    raw = _text(value)
    return bool(raw) and bool(_NUMERIC_SHORT_ANSWER_RE.fullmatch(raw))


def _question_needs_authored_phrase_groups(item: Dict[str, Any]) -> bool:
    accepted = [_text(answer) for answer in _items(item.get("accepted_answers")) if _text(answer)]
    return bool(accepted) and not all(_looks_numeric_short_answer(answer) for answer in accepted)


def _validate_skill_tags(item: Dict[str, Any], errors: List[str], label: str) -> None:
    skill_tags = [_text(tag) for tag in _items(item.get("skill_tags")) if _text(tag)]
    _require(bool(skill_tags), f"{label}: at least one skill tag is required for spec v3 question coverage checks.", errors)


def _validate_tags(tags: Sequence[Any], allowlist: Sequence[str], errors: List[str], label: str) -> None:
    clean = [_text(tag) for tag in tags if _text(tag)]
    _require(bool(clean), f"{label}: at least one misconception tag is required.", errors)
    for tag in clean:
        if allowlist and tag not in allowlist:
            errors.append(f"{label}: tag '{tag}' is not in the module allowlist.")


def _validate_question(
    item: Dict[str, Any],
    allowlist: Sequence[str],
    errors: List[str],
    label: str,
    *,
    authoring_standard: str = AUTHORING_STANDARD_V1,
) -> None:
    qtype = _text(item.get("type"))
    use_v3 = _uses_v3(authoring_standard)
    _require(qtype in QUESTION_TYPES, f"{label}: question type must be one of {sorted(QUESTION_TYPES)}.", errors)
    _require(bool(_text(item.get("id")) or _text(item.get("question_id"))), f"{label}: missing question id.", errors)
    _require(bool(_text(item.get("prompt"))), f"{label}: missing prompt.", errors)
    _require(bool(_text(item.get("hint"))), f"{label}: missing hint.", errors)
    _require(bool(_items(item.get("feedback"))), f"{label}: feedback must not be empty.", errors)
    _validate_tags(_items(item.get("misconception_tags")), allowlist, errors, label)
    if use_v3:
        _validate_skill_tags(item, errors, label)
    acceptance_rules = _record(item.get("acceptance_rules"))
    if qtype == "mcq":
        choices = [_text(choice) for choice in _items(item.get("choices")) if _text(choice)]
        answer_index = item.get("answer_index")
        _require(len(choices) >= 4, f"{label}: mcq questions need at least 4 choices.", errors)
        _require(isinstance(answer_index, int) and 0 <= answer_index < len(choices), f"{label}: mcq answer_index is invalid.", errors)
        _require(not acceptance_rules, f"{label}: acceptance_rules only apply to short questions.", errors)
    if qtype == "short":
        accepted = [_text(answer) for answer in _items(item.get("accepted_answers")) if _text(answer)]
        _require(bool(accepted), f"{label}: short questions need accepted answers.", errors)
        if acceptance_rules:
            phrase_groups = [_items(group) for group in _items(acceptance_rules.get("phrase_groups"))]
            _require(bool(phrase_groups), f"{label}: acceptance_rules.phrase_groups needs at least one phrase group.", errors)
            for group_index, group in enumerate(phrase_groups, start=1):
                phrases = [_text(phrase) for phrase in group if _text(phrase)]
                _require(
                    bool(phrases),
                    f"{label}: acceptance_rules.phrase_groups[{group_index}] needs at least one phrase.",
                    errors,
                )
        if use_v3 and _question_needs_authored_phrase_groups(item):
            _require(
                bool(acceptance_rules.get("phrase_groups")),
                f"{label}: spec v3 conceptual short answers need acceptance_rules.phrase_groups so valid student wording can score.",
                errors,
            )


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


def _validate_worked_example(item: Dict[str, Any], errors: List[str], label: str, *, require_answer_reason: bool = False) -> None:
    _require(bool(_text(item.get("prompt"))), f"{label}: missing example prompt.", errors)
    steps = [_text(step) for step in _items(item.get("steps")) if _text(step)]
    _require(len(steps) >= 3, f"{label}: worked examples need at least 3 reasoning steps.", errors)
    _require(bool(_text(item.get("final_answer"))), f"{label}: missing final answer.", errors)
    if require_answer_reason:
        _require(bool(_text(item.get("answer_reason"))), f"{label}: explain why the final answer follows from the reasoning.", errors)
    _require(bool(_text(item.get("why_it_matters"))), f"{label}: explain the conceptual takeaway.", errors)


def _validate_visual(item: Dict[str, Any], errors: List[str], label: str) -> None:
    _require(bool(_text(item.get("asset_id"))), f"{label}: missing asset id.", errors)
    _require(bool(_text(item.get("purpose"))), f"{label}: missing visual purpose.", errors)
    _require(bool(_text(item.get("caption"))), f"{label}: missing visual caption.", errors)


def _validate_scaffold_support(item: Dict[str, Any], errors: List[str], label: str) -> None:
    _require(bool(_text(item.get("core_idea"))), f"{label}: scaffold_support.core_idea is required.", errors)
    _require(bool(_text(item.get("reasoning"))), f"{label}: scaffold_support.reasoning is required.", errors)
    _require(
        bool(_text(item.get("check_for_understanding"))),
        f"{label}: scaffold_support.check_for_understanding is required.",
        errors,
    )
    _require(bool(_text(item.get("common_trap"))), f"{label}: scaffold_support.common_trap is required.", errors)
    analogy_bridge = _record(item.get("analogy_bridge"))
    _require(bool(_text(analogy_bridge.get("body"))), f"{label}: scaffold_support.analogy_bridge.body is required.", errors)
    _require(
        bool(_text(analogy_bridge.get("check_for_understanding"))),
        f"{label}: scaffold_support.analogy_bridge.check_for_understanding is required.",
        errors,
    )
    extra_sections = [_record(entry) for entry in _items(item.get("extra_sections"))]
    for index, section in enumerate(extra_sections, start=1):
        _require(bool(_text(section.get("heading"))), f"{label}: extra section {index} needs a heading.", errors)
        _require(bool(_text(section.get("body"))), f"{label}: extra section {index} needs a body.", errors)


def _validate_simulation_contract(
    item: Dict[str, Any],
    errors: List[str],
    label: str,
    *,
    require_v3_fields: bool = False,
) -> None:
    _require(bool(_text(item.get("baseline_case"))), f"{label}: baseline_case is required.", errors)
    comparison_tasks = [_text(entry) for entry in _items(item.get("comparison_tasks")) if _text(entry)]
    _require(len(comparison_tasks) >= 2, f"{label}: comparison_tasks needs at least 2 comparisons.", errors)
    _require(bool(_text(item.get("watch_for"))), f"{label}: watch_for is required.", errors)
    _require(bool(_text(item.get("takeaway"))), f"{label}: takeaway is required.", errors)

    if not require_v3_fields:
        return

    _require(bool(_text(item.get("asset_id"))), f"{label}: asset_id is required for spec v3 lesson-specific explorers.", errors)
    _require(bool(_text(item.get("concept"))), f"{label}: concept is required for spec v3 lesson-specific explorers.", errors)
    _require(bool(_text(item.get("focus_prompt"))), f"{label}: focus_prompt is required for spec v3 lesson-specific explorers.", errors)

    controls = [_record(entry) for entry in _items(item.get("controls"))]
    _require(len(controls) >= 2, f"{label}: controls should describe at least 2 adjustable variables in spec v3.", errors)
    for index, control in enumerate(controls, start=1):
        _require(bool(_text(control.get("variable"))), f"{label}: control {index} needs a variable key.", errors)
        _require(bool(_text(control.get("label"))), f"{label}: control {index} needs a learner-facing label.", errors)
        _require(bool(_text(control.get("why_it_matters"))), f"{label}: control {index} needs a why_it_matters note.", errors)

    readouts = [_record(entry) for entry in _items(item.get("readouts"))]
    _require(len(readouts) >= 2, f"{label}: readouts should describe at least 2 learner-facing outputs in spec v3.", errors)
    for index, readout in enumerate(readouts, start=1):
        _require(bool(_text(readout.get("label"))), f"{label}: readout {index} needs a label.", errors)
        _require(bool(_text(readout.get("meaning"))), f"{label}: readout {index} needs a meaning statement.", errors)


def _looks_example_specific_core_concept(value: str) -> bool:
    cleaned = _text(value).lower()
    if not cleaned:
        return False
    specific_patterns = (
        r"^rearrange\s+\d",
        r"^substitute\s+into\s+.*\d",
        r"^find\s+total\s+energy\s+with\s+.*\d",
        r"^take\s+\d+(?:\.\d+)?%",
        r"^\w+\s*=\s*[\d.]+\s*[x*]",
        r"^\d+(?:\.\d+)?\s*[a-z/%^_]+\s*(?:=|vs)",
    )
    return any(re.search(pattern, cleaned) for pattern in specific_patterns)


def _validate_core_concepts(items: Sequence[Any], errors: List[str], label: str) -> None:
    concepts = [_text(item) for item in items if _text(item)]
    _require(len(concepts) >= 4, f"{label}: core_concepts needs at least 4 general lesson anchors.", errors)
    for index, concept in enumerate(concepts, start=1):
        _require(
            not _looks_example_specific_core_concept(concept),
            f"{label}: core concept {index} looks like a frozen one-off example rather than a general teaching statement.",
            errors,
        )


def _validate_phase_skill_coverage(items: Sequence[Dict[str, Any]], errors: List[str], label: str, minimum: int) -> None:
    unique_tags = {
        _text(tag)
        for item in items
        for tag in _items(item.get("skill_tags"))
        if _text(tag)
    }
    _require(
        len(unique_tags) >= minimum,
        f"{label}: spec v3 requires at least {minimum} distinct skill tags to keep attempts broad and conceptually varied.",
        errors,
    )


def validate_nextgen_lesson(lesson: Dict[str, Any], allowlist: Sequence[str], authoring_standard: str = AUTHORING_STANDARD_V1) -> List[str]:
    errors: List[str] = []
    lesson_id = _text(lesson.get("lesson_id") or lesson.get("id") or "lesson")
    use_v2_plus = _uses_v2_plus(authoring_standard)
    use_v3 = _uses_v3(authoring_standard)
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
        _validate_question(item, allowlist, errors, f"{lesson_id} diagnostic item {index}", authoring_standard=authoring_standard)

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
            _validate_question(
                item,
                allowlist,
                errors,
                f"{lesson_id} capsule {index} check {check_index}",
                authoring_standard=authoring_standard,
            )

    transfer = _record(phases.get("transfer"))
    transfer_items = [_record(item) for item in _items(transfer.get("items"))]
    _require(len(transfer_items) >= 3, f"{lesson_id}: transfer needs at least 3 items.", errors)
    for index, item in enumerate(transfer_items, start=1):
        _validate_question(item, allowlist, errors, f"{lesson_id} transfer item {index}", authoring_standard=authoring_standard)

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
        _validate_worked_example(item, errors, f"{lesson_id} worked example {index}", require_answer_reason=use_v2_plus)

    visual_assets = [_record(item) for item in _items(authoring.get("visual_assets"))]
    _require(bool(visual_assets), f"{lesson_id}: at least one visual asset is required.", errors)
    for index, item in enumerate(visual_assets, start=1):
        _validate_visual(item, errors, f"{lesson_id} visual {index}")

    simulation_contract = _record(authoring.get("simulation_contract"))
    _validate_simulation_contract(simulation_contract, errors, lesson_id, require_v3_fields=use_v3)

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
    if use_v3:
        _require(bool(assessment_targets), f"{lesson_id}: spec v3 requires authoring_contract.assessment_bank_targets.", errors)

    visual_clarity_checks = [_text(item) for item in _items(authoring.get("visual_clarity_checks")) if _text(item)]
    if authoring.get("visual_clarity_checks") is not None:
        _require(
            len(visual_clarity_checks) >= 3,
            f"{lesson_id}: visual_clarity_checks should describe at least 3 concrete readability checks when present.",
            errors,
        )
    if use_v3:
        _require(bool(visual_clarity_checks), f"{lesson_id}: spec v3 requires visual_clarity_checks for deliberate readability review.", errors)
        _validate_core_concepts(authoring.get("core_concepts") or [], errors, lesson_id)
        _validate_phase_skill_coverage(diagnostic_items, errors, f"{lesson_id} diagnostic", 2)
        _validate_phase_skill_coverage(
            [item for capsule in capsules for item in [_record(check) for check in _items(capsule.get("checks"))]],
            errors,
            f"{lesson_id} concept gate",
            2,
        )
        _validate_phase_skill_coverage(transfer_items, errors, f"{lesson_id} transfer", 3)

    release_checks = [_text(item) for item in _items(authoring.get("release_checks")) if _text(item)]
    _require(len(release_checks) >= 4, f"{lesson_id}: authoring_contract.release_checks needs at least 4 release checks.", errors)

    if use_v2_plus:
        scaffold_support = _record(authoring.get("scaffold_support"))
        _require(bool(scaffold_support), f"{lesson_id}: authoring_contract.scaffold_support is required for spec v2 lessons.", errors)
        if scaffold_support:
            _validate_scaffold_support(scaffold_support, errors, lesson_id)

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

    authoring_standard = _text(module_doc.get("authoring_standard")) or AUTHORING_STANDARD_V1

    for lesson in lessons:
        errors.extend(validate_nextgen_lesson(_record(lesson), allowlist_items or allowlist, authoring_standard))

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
                    {"id": f"{lesson_id}_D1", "question_id": f"{lesson_id}_D1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"]},
                    {"id": f"{lesson_id}_D2", "question_id": f"{lesson_id}_D2", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"]},
                    {"id": f"{lesson_id}_D3", "question_id": f"{lesson_id}_D3", "type": "short", "prompt": "", "accepted_answers": [""], "acceptance_rules": {"phrase_groups": [[""], [""]]}, "hint": "", "feedback": [""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"]},
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
                            {"id": f"{lesson_id}_C1", "question_id": f"{lesson_id}_C1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"]}
                        ],
                    }
                ],
            },
            "transfer": {
                "items": [
                    {"id": f"{lesson_id}_T1", "question_id": f"{lesson_id}_T1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"]},
                    {"id": f"{lesson_id}_T2", "question_id": f"{lesson_id}_T2", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"]},
                    {"id": f"{lesson_id}_T3", "question_id": f"{lesson_id}_T3", "type": "short", "prompt": "", "accepted_answers": [""], "acceptance_rules": {"phrase_groups": [[""], [""]]}, "hint": "", "feedback": [""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"]},
                ],
            },
        },
        "authoring_contract": {
            "concept_targets": ["", ""],
            "core_concepts": ["", "", "", ""],
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
                {"prompt": "", "steps": ["", "", ""], "final_answer": "", "answer_reason": "", "why_it_matters": ""},
                {"prompt": "", "steps": ["", "", ""], "final_answer": "", "answer_reason": "", "why_it_matters": ""},
            ],
            "visual_assets": [
                {"asset_id": f"{lesson_id.lower()}-visual.svg", "purpose": "", "caption": ""},
            ],
            "simulation_contract": {
                "asset_id": f"{lesson_id.lower()}-lab",
                "concept": "REPLACE_CONCEPT",
                "baseline_case": "",
                "focus_prompt": "",
                "controls": [
                    {"variable": "", "label": "", "why_it_matters": ""},
                    {"variable": "", "label": "", "why_it_matters": ""},
                ],
                "readouts": [
                    {"label": "", "meaning": ""},
                    {"label": "", "meaning": ""},
                ],
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
            "scaffold_support": {
                "core_idea": "",
                "reasoning": "",
                "check_for_understanding": "",
                "common_trap": "",
                "analogy_bridge": {
                    "body": "",
                    "check_for_understanding": "",
                },
                "extra_sections": [],
            },
            "release_checks": [
                "Every mastery-tested relationship is explicitly taught before mastery.",
                "Every formula is shown with meaning, units, and conditions.",
                "At least one non-text representation is used and checked.",
                "Visuals are readable on desktop and mobile.",
            ],
            "visual_clarity_checks": [
                "No label, caption, or equation is clipped on desktop.",
                "No label, caption, or equation is clipped on mobile.",
                "The most important quantity is readable without overlapping arrows or shapes.",
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
        "authoring_standard": LATEST_AUTHORING_STANDARD,
        "updated_utc": "REPLACE_WITH_UTC_TIMESTAMP",
    }


def clone_template(data: Dict[str, Any]) -> Dict[str, Any]:
    return deepcopy(data)
