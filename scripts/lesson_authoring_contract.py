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
ASSESSMENT_PAPER_FORMATS = {
    "paper_1": "multiple_choice",
    "paper_2": "structured",
    "paper_4": "extended",
    "paper_5": "practical_investigation",
    "paper_6": "alternative_to_practical",
}
ASSESSMENT_EXAM_STYLES = set(ASSESSMENT_PAPER_FORMATS.values())
COMPETENCY_METRIC_KEYS = {
    "igcse_readiness_score",
    "topic_mastery_index",
    "practical_competency_rating",
    "exam_simulation_performance",
}
SPIRAL_STAGE_SEQUENCE = (
    {
        "level": "level_1",
        "stage": "intuitive",
        "description": "Concept first appears in an intuitive meaning-first form.",
    },
    {
        "level": "level_2",
        "stage": "quantitative",
        "description": "Concept returns in a quantitative problem-solving form.",
    },
    {
        "level": "level_3",
        "stage": "analytical_derivation",
        "description": "Concept returns in an analytical or derivation-level form.",
    },
)
SPIRAL_LEVEL_STAGE_PAIRS = {
    ("level_1", "intuitive"),
    ("level_2", "quantitative"),
    ("level_3", "analytical_derivation"),
}


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


def default_assessment_alignment() -> Dict[str, Any]:
    return {
        "exam_board": "Cambridge IGCSE",
        "paper_structure": [
            {"paper_id": paper_id, "label": paper_id.replace("_", " ").title(), "format": exam_style}
            for paper_id, exam_style in ASSESSMENT_PAPER_FORMATS.items()
        ],
        "auto_generation_outputs": [
            "timed_mock_exams",
            "topic_level_past_paper_simulations",
            "weakness_heatmaps",
        ],
    }


def default_competency_mapping() -> Dict[str, Any]:
    labels = {
        "igcse_readiness_score": "IGCSE readiness score",
        "topic_mastery_index": "Topic mastery index",
        "practical_competency_rating": "Practical competency rating",
        "exam_simulation_performance": "Exam simulation performance",
    }
    return {
        "metrics": [
            {"key": key, "label": labels[key]}
            for key in (
                "igcse_readiness_score",
                "topic_mastery_index",
                "practical_competency_rating",
                "exam_simulation_performance",
            )
        ]
    }


def default_spiral_reinforcement() -> Dict[str, Any]:
    return {
        "stages": [deepcopy(item) for item in SPIRAL_STAGE_SEQUENCE],
        "lesson_stage_focus": [deepcopy(SPIRAL_STAGE_SEQUENCE[0])],
    }


def default_question_assessment_schema(
    question_type: str,
    phase_key: str = "",
    raw_schema: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    normalized_type = _text(question_type).lower()
    normalized_phase = _text(phase_key).lower()
    exam_paper = "paper_1" if normalized_type == "mcq" else "paper_2"
    exam_style = ASSESSMENT_PAPER_FORMATS[exam_paper]
    spiral_level, spiral_stage = (
        ("level_2", "quantitative")
        if normalized_phase == "transfer"
        else ("level_1", "intuitive")
    )
    competency_tags = (
        ["igcse_readiness_score", "topic_mastery_index"]
        if normalized_phase == "diagnostic"
        else ["topic_mastery_index", "exam_simulation_performance"]
    )

    schema = {
        "exam_paper": exam_paper,
        "exam_style": exam_style,
        "spiral_level": spiral_level,
        "spiral_stage": spiral_stage,
        "competency_tags": competency_tags,
    }
    raw = _record(raw_schema)
    if _text(raw.get("exam_paper")):
        schema["exam_paper"] = _text(raw.get("exam_paper"))
        schema["exam_style"] = ASSESSMENT_PAPER_FORMATS.get(schema["exam_paper"], exam_style)
    if _text(raw.get("exam_style")):
        schema["exam_style"] = _text(raw.get("exam_style"))
    if _text(raw.get("spiral_level")):
        schema["spiral_level"] = _text(raw.get("spiral_level"))
    if _text(raw.get("spiral_stage")):
        schema["spiral_stage"] = _text(raw.get("spiral_stage"))
    raw_competencies = [_text(tag) for tag in _items(raw.get("competency_tags")) if _text(tag)]
    if raw_competencies:
        schema["competency_tags"] = raw_competencies
    if schema["exam_paper"] in {"paper_5", "paper_6"} and "practical_competency_rating" not in schema["competency_tags"]:
        schema["competency_tags"] = [*schema["competency_tags"], "practical_competency_rating"]
    return schema


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
        _validate_question_assessment_schema(item, errors, label)
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


def _validate_technical_words(items: Sequence[Any], errors: List[str], label: str) -> None:
    for index, entry in enumerate(items, start=1):
        record = _record(entry)
        _require(bool(_text(record.get("term"))), f"{label}: technical_words[{index}] needs a term.", errors)
        _require(bool(_text(record.get("meaning"))), f"{label}: technical_words[{index}] needs a meaning.", errors)


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


def _validate_question_assessment_schema(item: Dict[str, Any], errors: List[str], label: str) -> None:
    schema = _record(item.get("assessment_schema"))
    _require(bool(schema), f"{label}: assessment_schema is required for authored exam alignment.", errors)
    if not schema:
        return

    exam_paper = _text(schema.get("exam_paper"))
    exam_style = _text(schema.get("exam_style"))
    spiral_level = _text(schema.get("spiral_level"))
    spiral_stage = _text(schema.get("spiral_stage"))
    competency_tags = [_text(tag) for tag in _items(schema.get("competency_tags")) if _text(tag)]

    _require(exam_paper in ASSESSMENT_PAPER_FORMATS, f"{label}: assessment_schema.exam_paper must be one of {sorted(ASSESSMENT_PAPER_FORMATS)}.", errors)
    _require(exam_style in ASSESSMENT_EXAM_STYLES, f"{label}: assessment_schema.exam_style must be one of {sorted(ASSESSMENT_EXAM_STYLES)}.", errors)
    if exam_paper in ASSESSMENT_PAPER_FORMATS and exam_style in ASSESSMENT_EXAM_STYLES:
        _require(
            ASSESSMENT_PAPER_FORMATS[exam_paper] == exam_style,
            f"{label}: assessment_schema.exam_style must match the declared exam paper format.",
            errors,
        )
    _require(
        (spiral_level, spiral_stage) in SPIRAL_LEVEL_STAGE_PAIRS,
        f"{label}: assessment_schema spiral pair must be one of {sorted(SPIRAL_LEVEL_STAGE_PAIRS)}.",
        errors,
    )
    _require(bool(competency_tags), f"{label}: assessment_schema.competency_tags needs at least one competency metric.", errors)
    for competency in competency_tags:
        _require(
            competency in COMPETENCY_METRIC_KEYS,
            f"{label}: competency tag '{competency}' is not one of the supported learner metrics.",
            errors,
        )


def _validate_assessment_alignment(item: Dict[str, Any], errors: List[str], label: str) -> None:
    _require(bool(_text(item.get("exam_board"))), f"{label}: exam_board is required.", errors)
    paper_structure = [_record(entry) for entry in _items(item.get("paper_structure"))]
    _require(len(paper_structure) == len(ASSESSMENT_PAPER_FORMATS), f"{label}: paper_structure should declare Paper 1, 2, 4, 5, and 6.", errors)
    seen_papers = set()
    for index, paper in enumerate(paper_structure, start=1):
        paper_id = _text(paper.get("paper_id"))
        paper_format = _text(paper.get("format"))
        _require(paper_id in ASSESSMENT_PAPER_FORMATS, f"{label}: paper_structure[{index}] uses an unsupported paper id.", errors)
        if paper_id in ASSESSMENT_PAPER_FORMATS:
            seen_papers.add(paper_id)
            _require(
                paper_format == ASSESSMENT_PAPER_FORMATS[paper_id],
                f"{label}: paper_structure[{index}] format must match the declared paper id.",
                errors,
            )
        _require(bool(_text(paper.get("label"))), f"{label}: paper_structure[{index}] needs a learner-facing label.", errors)
    _require(
        seen_papers == set(ASSESSMENT_PAPER_FORMATS),
        f"{label}: paper_structure must include every supported paper id exactly once.",
        errors,
    )
    outputs = [_text(entry) for entry in _items(item.get("auto_generation_outputs")) if _text(entry)]
    _require(
        outputs == ["timed_mock_exams", "topic_level_past_paper_simulations", "weakness_heatmaps"],
        f"{label}: auto_generation_outputs must list timed_mock_exams, topic_level_past_paper_simulations, and weakness_heatmaps.",
        errors,
    )


def _validate_competency_mapping(item: Dict[str, Any], errors: List[str], label: str) -> None:
    metrics = [_record(entry) for entry in _items(item.get("metrics"))]
    _require(len(metrics) == len(COMPETENCY_METRIC_KEYS), f"{label}: metrics should declare the four learner competency outputs.", errors)
    seen_metrics = set()
    for index, metric in enumerate(metrics, start=1):
        key = _text(metric.get("key"))
        seen_metrics.add(key)
        _require(key in COMPETENCY_METRIC_KEYS, f"{label}: metrics[{index}] uses an unsupported competency key.", errors)
        _require(bool(_text(metric.get("label"))), f"{label}: metrics[{index}] needs a learner-facing label.", errors)
    _require(
        seen_metrics == COMPETENCY_METRIC_KEYS,
        f"{label}: metrics must include igcse_readiness_score, topic_mastery_index, practical_competency_rating, and exam_simulation_performance.",
        errors,
    )


def _validate_spiral_reinforcement(item: Dict[str, Any], errors: List[str], label: str) -> None:
    stages = [_record(entry) for entry in _items(item.get("stages"))]
    _require(len(stages) == len(SPIRAL_STAGE_SEQUENCE), f"{label}: stages should declare the three spiral reinforcement levels.", errors)
    seen_pairs = set()
    for index, stage in enumerate(stages, start=1):
        pair = (_text(stage.get("level")), _text(stage.get("stage")))
        seen_pairs.add(pair)
        _require(pair in SPIRAL_LEVEL_STAGE_PAIRS, f"{label}: stages[{index}] uses an unsupported spiral pair.", errors)
        _require(bool(_text(stage.get("description"))), f"{label}: stages[{index}] needs a description.", errors)
    _require(
        seen_pairs == SPIRAL_LEVEL_STAGE_PAIRS,
        f"{label}: stages must include Level 1 intuitive, Level 2 quantitative, and Level 3 analytical/derivation.",
        errors,
    )
    focus = [_record(entry) for entry in _items(item.get("lesson_stage_focus"))]
    _require(bool(focus), f"{label}: lesson_stage_focus needs at least one stage target.", errors)
    for index, stage in enumerate(focus, start=1):
        pair = (_text(stage.get("level")), _text(stage.get("stage")))
        _require(pair in SPIRAL_LEVEL_STAGE_PAIRS, f"{label}: lesson_stage_focus[{index}] uses an unsupported spiral pair.", errors)


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
    technical_words = [_record(item) for item in _items(authoring.get("technical_words"))]
    if technical_words:
        _validate_technical_words(technical_words, errors, f"{lesson_id} authoring")

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

    assessment_alignment = _record(authoring.get("assessment_alignment"))
    competency_mapping = _record(authoring.get("competency_mapping"))
    spiral_reinforcement = _record(authoring.get("spiral_reinforcement"))
    if use_v3:
        _validate_assessment_alignment(assessment_alignment, errors, f"{lesson_id}: authoring_contract.assessment_alignment")
        _validate_competency_mapping(competency_mapping, errors, f"{lesson_id}: authoring_contract.competency_mapping")
        _validate_spiral_reinforcement(spiral_reinforcement, errors, f"{lesson_id}: authoring_contract.spiral_reinforcement")

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
                    {"id": f"{lesson_id}_D1", "question_id": f"{lesson_id}_D1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"], "assessment_schema": default_question_assessment_schema("mcq", "diagnostic")},
                    {"id": f"{lesson_id}_D2", "question_id": f"{lesson_id}_D2", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"], "assessment_schema": default_question_assessment_schema("mcq", "diagnostic")},
                    {"id": f"{lesson_id}_D3", "question_id": f"{lesson_id}_D3", "type": "short", "prompt": "", "accepted_answers": [""], "acceptance_rules": {"phrase_groups": [[""], [""]]}, "hint": "", "feedback": [""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"], "assessment_schema": default_question_assessment_schema("short", "diagnostic")},
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
                            {"id": f"{lesson_id}_C1", "question_id": f"{lesson_id}_C1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"], "assessment_schema": default_question_assessment_schema("mcq", "concept_reconstruction")}
                        ],
                    }
                ],
            },
            "transfer": {
                "items": [
                    {"id": f"{lesson_id}_T1", "question_id": f"{lesson_id}_T1", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"], "assessment_schema": default_question_assessment_schema("mcq", "transfer")},
                    {"id": f"{lesson_id}_T2", "question_id": f"{lesson_id}_T2", "type": "mcq", "prompt": "", "choices": ["", "", "", ""], "answer_index": 0, "hint": "", "feedback": ["", "", "", ""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"], "assessment_schema": default_question_assessment_schema("mcq", "transfer")},
                    {"id": f"{lesson_id}_T3", "question_id": f"{lesson_id}_T3", "type": "short", "prompt": "", "accepted_answers": [""], "acceptance_rules": {"phrase_groups": [[""], [""]]}, "hint": "", "feedback": [""], "misconception_tags": ["REPLACE_TAG"], "skill_tags": ["REPLACE_SKILL"], "assessment_schema": default_question_assessment_schema("short", "transfer")},
                ],
            },
        },
        "authoring_contract": {
            "concept_targets": ["", ""],
            "core_concepts": ["", "", "", ""],
            "technical_words": [],
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
            "assessment_alignment": default_assessment_alignment(),
            "competency_mapping": default_competency_mapping(),
            "spiral_reinforcement": default_spiral_reinforcement(),
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
