from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.revised_advanced_curriculum_modules_clean import (
        A6_CONTENT_VERSION as _A6_CONTENT_VERSION_RAW,
        A6_MODULE_DOC as _A6_MODULE_DOC_RAW,
        A6_LESSONS as _A6_LESSONS_RAW,
        A6_SIM_LABS as _A6_SIM_LABS_RAW,
        A7_CONTENT_VERSION as _A7_CONTENT_VERSION_RAW,
        A7_MODULE_DOC as _A7_MODULE_DOC_RAW,
        A7_LESSONS as _A7_LESSONS_RAW,
        A7_SIM_LABS as _A7_SIM_LABS_RAW,
    )
    from scripts.revised_advanced_curriculum_modules_tail import (
        A8_CONTENT_VERSION as _A8_CONTENT_VERSION_RAW,
        A8_MODULE_DOC as _A8_MODULE_DOC_RAW,
        A8_LESSONS as _A8_LESSONS_RAW,
        A8_SIM_LABS as _A8_SIM_LABS_RAW,
        A9_CONTENT_VERSION as _A9_CONTENT_VERSION_RAW,
        A9_MODULE_DOC as _A9_MODULE_DOC_RAW,
        A9_LESSONS as _A9_LESSONS_RAW,
        A9_SIM_LABS as _A9_SIM_LABS_RAW,
        A10_CONTENT_VERSION as _A10_CONTENT_VERSION_RAW,
        A10_MODULE_DOC as _A10_MODULE_DOC_RAW,
        A10_LESSONS as _A10_LESSONS_RAW,
        A10_SIM_LABS as _A10_SIM_LABS_RAW,
        A11_CONTENT_VERSION as _A11_CONTENT_VERSION_RAW,
        A11_MODULE_DOC as _A11_MODULE_DOC_RAW,
        A11_LESSONS as _A11_LESSONS_RAW,
        A11_SIM_LABS as _A11_SIM_LABS_RAW,
    )
    from scripts.revised_core_curriculum_modules import acceptance_groups, mcq, short, worked
except ModuleNotFoundError:
    from revised_advanced_curriculum_modules_clean import (
        A6_CONTENT_VERSION as _A6_CONTENT_VERSION_RAW,
        A6_MODULE_DOC as _A6_MODULE_DOC_RAW,
        A6_LESSONS as _A6_LESSONS_RAW,
        A6_SIM_LABS as _A6_SIM_LABS_RAW,
        A7_CONTENT_VERSION as _A7_CONTENT_VERSION_RAW,
        A7_MODULE_DOC as _A7_MODULE_DOC_RAW,
        A7_LESSONS as _A7_LESSONS_RAW,
        A7_SIM_LABS as _A7_SIM_LABS_RAW,
    )
    from revised_advanced_curriculum_modules_tail import (
        A8_CONTENT_VERSION as _A8_CONTENT_VERSION_RAW,
        A8_MODULE_DOC as _A8_MODULE_DOC_RAW,
        A8_LESSONS as _A8_LESSONS_RAW,
        A8_SIM_LABS as _A8_SIM_LABS_RAW,
        A9_CONTENT_VERSION as _A9_CONTENT_VERSION_RAW,
        A9_MODULE_DOC as _A9_MODULE_DOC_RAW,
        A9_LESSONS as _A9_LESSONS_RAW,
        A9_SIM_LABS as _A9_SIM_LABS_RAW,
        A10_CONTENT_VERSION as _A10_CONTENT_VERSION_RAW,
        A10_MODULE_DOC as _A10_MODULE_DOC_RAW,
        A10_LESSONS as _A10_LESSONS_RAW,
        A10_SIM_LABS as _A10_SIM_LABS_RAW,
        A11_CONTENT_VERSION as _A11_CONTENT_VERSION_RAW,
        A11_MODULE_DOC as _A11_MODULE_DOC_RAW,
        A11_LESSONS as _A11_LESSONS_RAW,
        A11_SIM_LABS as _A11_SIM_LABS_RAW,
    )
    from revised_core_curriculum_modules import acceptance_groups, mcq, short, worked


_RIGOUR_OUTCOMES = [
    "Use units, conditions, and limiting cases to test whether a formal relation is being applied appropriately.",
    "Translate advanced equations back into mechanism-based physics language instead of leaving them as detached symbol strings.",
]


def _bump_version(value: str) -> str:
    stem, sep, tail = value.rpartition("_v")
    if sep and tail.isdigit():
        return f"{stem}_v{int(tail) + 1}"
    return f"{value}_v2"


def _append_unique_strings(items: Sequence[str], additions: Sequence[str]) -> List[str]:
    merged: List[str] = []
    seen = set()
    for entry in [*items, *additions]:
        text = str(entry).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(text)
    return merged


def _term_group(term: str) -> List[str]:
    normalized = str(term).strip().lower()
    words = [part for part in normalized.replace("-", " ").split() if part]
    items = [normalized]
    if words:
        items.append(words[0])
        items.append(words[-1])
    deduped: List[str] = []
    seen = set()
    for item in items:
        if item and item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped or ["term"]


def _definition_choices(terms: Sequence[Dict[str, Any]], index: int) -> Tuple[str, List[str]]:
    entries = [dict(item) for item in terms if item]
    target = entries[index % len(entries)]
    distractors = [str(entry.get("meaning") or "") for entry in entries if entry.get("term") != target.get("term")][:3]
    while len(distractors) < 3:
        distractors.append("It is a different lesson idea, not the one being defined here.")
    return str(target.get("term") or "the lesson term"), [str(target.get("meaning") or ""), *distractors[:3]]


def _units_text(units: Sequence[Any]) -> str:
    rendered = [str(item).strip() for item in units if str(item).strip()]
    return ", ".join(rendered[:4]) if rendered else "the stated lesson units"


def _ensure_short_variants(item: Dict[str, Any]) -> None:
    accepted = [str(answer).strip() for answer in item.get("accepted_answers") or [] if str(answer).strip()]
    if not accepted:
        return
    variants = list(accepted)
    base = accepted[0].rstrip(".")
    if base:
        variants.append(base)
        variants.append(base.replace("Because ", "").replace("because ", ""))
        variants.append(base.split(",")[0])
    item["accepted_answers"] = _append_unique_strings([], variants)[:6]


def _extra_question_banks(lesson_id: str, lesson: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    contract = dict(lesson["authoring_contract"])
    diagnostic = list(lesson["phases"]["diagnostic"]["items"])
    terms = [dict(item) for item in contract.get("technical_words") or []]
    skills = list(contract.get("mastery_skills") or [])
    while len(skills) < 5:
        skills.append(f"{lesson_id.lower()}_skill_{len(skills) + 1}")
    formula = dict((contract.get("formulas") or [{}])[0])
    equation = str(formula.get("equation") or "the main relation")
    conditions = str(formula.get("conditions") or "the stated lesson condition holds")
    units_text = _units_text(formula.get("units") or [])
    title = str(lesson.get("title") or lesson_id)
    term_a = str((terms[0] if terms else {}).get("term") or "the first lesson quantity")
    term_b = str((terms[1] if len(terms) > 1 else terms[0] if terms else {}).get("term") or "the second lesson quantity")
    why_item = dict(diagnostic[1] if len(diagnostic) > 1 else {})
    compare_item = dict(diagnostic[5] if len(diagnostic) > 5 else why_item)
    why_answers = [str(answer) for answer in why_item.get("accepted_answers") or []] or [f"Because {title.lower()} has to be explained through its main mechanism, not just named."]
    why_groups = deepcopy((why_item.get("acceptance_rules") or {}).get("phrase_groups") or [["mechanism"], ["explain"]])
    compare_answers = [str(answer) for answer in compare_item.get("accepted_answers") or []] or [f"Because {term_a} and {term_b} must stay separate in {title.lower()}."]
    compare_groups = deepcopy((compare_item.get("acceptance_rules") or {}).get("phrase_groups") or [_term_group(term_a), _term_group(term_b), ["different", "separate"]])
    term_d, term_d_choices = _definition_choices(terms or [{"term": "lesson term", "meaning": "It is one of the technical ideas used in this lesson."}], 3)
    term_c, term_c_choices = _definition_choices(terms or [{"term": "lesson term", "meaning": "It is one of the technical ideas used in this lesson."}], 2)

    diagnostic_extra = [
        mcq(
            f"{lesson_id.replace('_', '')}_D7",
            f"Which lesson meaning best matches {term_d}?",
            term_d_choices,
            0,
            f"Keep {term_d} tied to the lesson instead of treating it as a vague label.",
            skill_tags=[skills[2]],
        ),
        mcq(
            f"{lesson_id.replace('_', '')}_D8",
            f"Which unit set best matches the main relation in {title.lower()}?",
            [
                units_text,
                "Only names matter here, so units can be ignored.",
                "Any mixed units work automatically because the symbols fix the physics.",
                "Units matter only after the final line is written.",
            ],
            0,
            "Use the lesson's stated units to keep the formal relation physically consistent.",
            skill_tags=[skills[3]],
        ),
        short(
            f"{lesson_id.replace('_', '')}_D9",
            f"Which mechanism must stay visible when you explain {title.lower()}?",
            why_answers,
            "Answer with the main mechanism or cause-and-effect story, not only the topic name.",
            skill_tags=[skills[1]],
            acceptance_rules=acceptance_groups(*why_groups),
        ),
        mcq(
            f"{lesson_id.replace('_', '')}_D10",
            f"Why should the stated condition for {title.lower()} stay visible before using {equation}?",
            [
                f"Because the relation is only trustworthy when {conditions.lower()}",
                "Because the condition only changes presentation, not the physics.",
                "Because equations become universally valid once memorized.",
                "Because conditions can be ignored until after the calculation is finished.",
            ],
            0,
            "Tie the relation to its physical condition before you use it.",
            skill_tags=[skills[3]],
        ),
    ]

    concept_extra = [
        short(
            f"{lesson_id.replace('_', '')}_C5",
            f"What distinction should stay clear while you reason through {title.lower()}?",
            compare_answers,
            "Keep the lesson's contrast or separation explicit.",
            skill_tags=[skills[0]],
            acceptance_rules=acceptance_groups(*compare_groups),
        ),
        mcq(
            f"{lesson_id.replace('_', '')}_C6",
            f"Which lesson meaning best matches {term_c}?",
            term_c_choices,
            0,
            f"Keep {term_c} connected to the lesson's actual role.",
            skill_tags=[skills[2]],
        ),
        mcq(
            f"{lesson_id.replace('_', '')}_C7",
            f"Which statement adds rigour to {title.lower()}?",
            [
                f"State the condition, keep the quantities separate, and translate {equation} back into words.",
                "Use the equation name only and assume the physical meaning will be obvious later.",
                "Ignore units because the symbols already contain the explanation.",
                "Collapse the linked quantities into one everyday label.",
            ],
            0,
            "A rigorous answer keeps the condition, quantities, and interpretation together.",
            skill_tags=[skills[4]],
        ),
        mcq(
            f"{lesson_id.replace('_', '')}_C8",
            f"Which unit check best protects {title.lower()}?",
            [
                f"Keep the variables in {units_text} before substituting into the relation.",
                "Convert the answer units only if the final number looks strange.",
                "Skip unit checks because advanced equations already enforce consistency.",
                "Choose whichever units make the arithmetic shortest, even if they are mixed.",
            ],
            0,
            "Use units as a physics check, not only as decoration after the calculation.",
            skill_tags=[skills[3]],
        ),
    ]

    mastery_extra = [
        mcq(
            f"{lesson_id.replace('_', '')}_M7",
            f"Which statement best protects the formal side of {title.lower()}?",
            [
                f"The relation {equation} should be used with its condition and units still visible.",
                "Once the lesson title is named, the formal relation no longer matters.",
                "Units can be repaired later without changing the physical meaning.",
                "A strong answer hides the mechanism and focuses only on the symbol order.",
            ],
            0,
            "Keep the relation, the units, and the condition connected.",
            skill_tags=[skills[4]],
        ),
        short(
            f"{lesson_id.replace('_', '')}_M8",
            f"Why is it not enough to name {title.lower()} without explaining the mechanism?",
            why_answers,
            "Use the lesson's main explanatory mechanism.",
            skill_tags=[skills[1]],
            acceptance_rules=acceptance_groups(*why_groups),
        ),
        mcq(
            f"{lesson_id.replace('_', '')}_M9",
            f"Which statement best protects the separation between {term_a} and {term_b} in {title.lower()}?",
            [
                f"{term_a} and {term_b} must stay as different parts of the same lesson story.",
                f"{term_a} and {term_b} are interchangeable once the equation is memorized.",
                f"{term_a} matters only in diagrams while {term_b} matters only in words.",
                f"{term_a} can replace {term_b} whenever a numerical answer is required.",
            ],
            0,
            "Keep the two lesson quantities or ideas distinct.",
            skill_tags=[skills[0]],
        ),
        short(
            f"{lesson_id.replace('_', '')}_M10",
            f"What separation must stay visible if you want a rigorous answer in {title.lower()}?",
            compare_answers,
            "Keep the lesson's main distinction explicit.",
            skill_tags=[skills[0]],
            acceptance_rules=acceptance_groups(*compare_groups),
        ),
    ]

    for item in [*diagnostic_extra, *concept_extra, *mastery_extra]:
        if item.get("type") == "short":
            _ensure_short_variants(item)

    return {
        "diagnostic": diagnostic_extra,
        "concept": concept_extra,
        "mastery": mastery_extra,
    }


def _enrich_lesson_payload(lesson: Dict[str, Any], sim_doc: Dict[str, Any]) -> None:
    lesson_id = str(lesson["id"])
    contract = lesson["authoring_contract"]
    diagnostic = lesson["phases"]["diagnostic"]["items"]
    concept = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
    mastery = lesson["phases"]["transfer"]["items"]
    extras = _extra_question_banks(lesson_id, lesson)

    diagnostic.extend(deepcopy(extras["diagnostic"]))
    concept.extend(deepcopy(extras["concept"]))
    mastery.extend(deepcopy(extras["mastery"]))

    contract["assessment_bank_targets"] = {
        "diagnostic_pool_min": 10,
        "concept_gate_pool_min": 8,
        "mastery_pool_min": 10,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }

    formula = dict((contract.get("formulas") or [{}])[0])
    equation = str(formula.get("equation") or "the main relation")
    conditions = str(formula.get("conditions") or "the stated physical condition holds")
    units_text = _units_text(formula.get("units") or [])
    title = str(lesson.get("title") or lesson_id)

    contract["core_concepts"] = _append_unique_strings(
        contract.get("core_concepts") or [],
        [
            "The formal relation must be read with its units and conditions, not as a detached symbol string.",
            "A strong answer keeps the underlying mechanism and the named quantities visible together.",
        ],
    )

    representations = list(contract.get("representations") or [])
    if not any(str(item.get("kind") or "") == "equation_story" for item in representations):
        representations.append(
            {
                "kind": "equation_story",
                "purpose": f"Explains how {equation} stays tied to the physical mechanism, units, and conditions in {title.lower()}.",
            }
        )
    contract["representations"] = representations

    contract["worked_examples"] = list(contract.get("worked_examples") or [])
    contract["worked_examples"].append(
        worked(
            f"When is {equation} safe to use in {title.lower()}?",
            [
                "Name the physical quantities the relation is connecting.",
                "Check the stated physical condition before using the relation.",
                "Keep the lesson units consistent before interpreting the result.",
            ],
            f"Use {equation} only when {conditions}, with the lesson units {units_text} kept consistent.",
            "The relation is trustworthy only when its assumptions and units stay visible together.",
            "This adds rigour by tying the equation to its physical limits instead of treating it as a plug-in rule.",
        )
    )
    contract["worked_examples"].append(
        worked(
            f"What distinction makes {title.lower()} scientifically sharp?",
            [
                "Identify the two linked ideas or quantities the lesson is trying to keep separate.",
                "State how they work together without collapsing them into one vague label.",
                "Translate that distinction back into the formal physics language of the lesson.",
            ],
            str(contract["core_concepts"][0]),
            "The answer works because it keeps the lesson's main distinction and mechanism visible together.",
            "This raises the conceptual depth of the lesson beyond naming the topic or formula alone.",
        )
    )

    scaffold_support = dict(contract.get("scaffold_support") or {})
    extra_sections = list(scaffold_support.get("extra_sections") or [])
    extra_sections.append(
        {
            "heading": "Formal condition",
            "body": f"Use {equation} only when {conditions}.",
            "check_for_understanding": "What physical condition must be checked before this relation is used?",
        }
    )
    extra_sections.append(
        {
            "heading": "Unit check",
            "body": f"Keep the variables in {units_text} so the relation stays physically consistent.",
            "check_for_understanding": "Which units keep this relation internally consistent before you substitute values?",
        }
    )
    scaffold_support["extra_sections"] = extra_sections
    contract["scaffold_support"] = scaffold_support

    contract["reflection_prompts"] = _append_unique_strings(
        contract.get("reflection_prompts") or [],
        [
            f"Which condition or unit check stops {title.lower()} from becoming a blind plug-in formula?",
            f"How would you explain {title.lower()} without collapsing its linked quantities into one vague label?",
        ],
    )

    clarity_checks = list(contract.get("visual_clarity_checks") or [])
    clarity_checks.append("No picture labels, axes, arrows, or callouts clip on desktop or mobile layouts.")
    clarity_checks.append("Formal relation callouts stay readable without covering the main geometry, field, or comparison area.")
    contract["visual_clarity_checks"] = _append_unique_strings([], clarity_checks)

    release_checks = list(contract.get("release_checks") or [])
    release_checks.append("Every lesson keeps at least 10 diagnostic, 8 concept-gate, and 10 mastery questions with lesson-owned stems.")
    release_checks.append("Every lesson keeps units, conditions, and mechanism language visible instead of reducing the topic to one formula.")
    contract["release_checks"] = _append_unique_strings([], release_checks)

    simulation_contract = dict(contract.get("simulation_contract") or {})
    comparison_tasks = list(simulation_contract.get("comparison_tasks") or [])
    comparison_tasks.append("Keep one variable fixed, change one variable deliberately, and state which physical quantity responded.")
    comparison_tasks.append("State the unit or condition check that keeps the comparison physically valid before you summarize it.")
    simulation_contract["comparison_tasks"] = _append_unique_strings([], comparison_tasks)

    controls = list(simulation_contract.get("controls") or [])
    if len(controls) < 3:
        controls.append(
            {
                "variable": "comparison_mode",
                "label": "Comparison mode",
                "why_it_matters": "It keeps one advanced variable change visible at a time instead of mixing several effects together.",
            }
        )
    readouts = list(simulation_contract.get("readouts") or [])
    if len(readouts) < 3:
        readouts.append(
            {
                "label": "Rigour check",
                "meaning": "Keeps the condition, units, or invariant visible while the comparison is being made.",
            }
        )
    simulation_contract["controls"] = controls
    simulation_contract["readouts"] = readouts
    simulation_contract["takeaway"] = f"{simulation_contract.get('takeaway') or ''} Keep the condition, units, and mechanism visible while you compare cases.".strip()
    contract["simulation_contract"] = simulation_contract

    lesson_sim = dict(lesson.get("sim") or {})
    lesson_sim["instructions"] = _append_unique_strings(
        lesson_sim.get("instructions") or [],
        [
            "Keep one variable fixed, change one variable deliberately, and explain which quantity responds.",
            "State the unit or condition check that keeps the comparison physically valid before you summarize it.",
            "Run a second comparison case and say what stayed invariant while the main variable changed.",
            "Link the explorer result back to the formal relation instead of stopping at a visual description.",
        ],
    )
    lesson_sim["outcomes"] = _append_unique_strings(
        lesson_sim.get("outcomes") or [],
        [
            "Explain the formal relation in words, with its physical condition still visible.",
            "Use units and assumptions as checks instead of treating the equation as a detached symbol string.",
            "Identify which variable changed, which stayed fixed, and why that matters physically.",
            "Compare two valid cases without collapsing a whole-system quantity into an average quantity.",
            "Summarize the mechanism, the condition, and the formal relation in one rigorous statement.",
        ],
    )
    lesson_sim["fields"] = _append_unique_strings(lesson_sim.get("fields") or [], ["comparison_mode"])
    lesson_sim["depth"] = "advanced"
    lesson["sim"] = lesson_sim

    simulation_phase = dict(lesson["phases"].get("simulation_inquiry") or {})
    generated_lab = dict(simulation_phase.get("generated_lab") or {})
    generated_lab["instructions"] = list(lesson_sim.get("instructions") or generated_lab.get("instructions") or [])
    generated_lab["outcomes"] = list(lesson_sim.get("outcomes") or generated_lab.get("outcomes") or [])
    generated_lab["fields"] = list(lesson_sim.get("fields") or generated_lab.get("fields") or [])
    generated_lab["depth"] = lesson_sim.get("depth") or generated_lab.get("depth") or "advanced"
    simulation_phase["generated_lab"] = generated_lab
    lesson["phases"]["simulation_inquiry"] = simulation_phase

    sim_doc["description"] = f"{sim_doc.get('description') or ''} Keep units, conditions, and comparison logic visible as you explore.".strip()
    sim_doc["instructions"] = _append_unique_strings(
        sim_doc.get("instructions") or [],
        [
            "Keep one variable fixed, change one variable deliberately, and explain which quantity responds.",
            "State the unit or condition check that keeps the comparison physically valid before you summarize it.",
            "Run a second comparison case and say what stayed invariant while the main variable changed.",
            "Link the explorer result back to the formal relation instead of stopping at a visual description.",
        ],
    )
    sim_doc["outcomes"] = _append_unique_strings(
        sim_doc.get("outcomes") or [],
        [
            "Explain the formal relation in words, with its physical condition still visible.",
            "Use units and assumptions as checks instead of treating the equation as a detached symbol string.",
            "Identify which variable changed, which stayed fixed, and why that matters physically.",
            "Compare two valid cases without collapsing a whole-system quantity into an average quantity.",
            "Summarize the mechanism, the condition, and the formal relation in one rigorous statement.",
        ],
    )
    sim_doc["fields"] = _append_unique_strings(sim_doc.get("fields") or [], ["comparison_mode"])
    sim_doc["depth"] = "advanced"


def _enrich_bundle(
    *,
    content_version: str,
    module_doc: Dict[str, Any],
    lesson_pairs: List[Tuple[str, Dict[str, Any]]],
    sim_pairs: List[Tuple[str, Dict[str, Any]]],
) -> Tuple[str, Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    version = _bump_version(content_version)
    enriched_module_doc = deepcopy(module_doc)
    enriched_lesson_pairs = deepcopy(lesson_pairs)
    enriched_sim_pairs = deepcopy(sim_pairs)

    enriched_module_doc["content_version"] = version
    enriched_module_doc["mastery_outcomes"] = _append_unique_strings(
        enriched_module_doc.get("mastery_outcomes") or [],
        _RIGOUR_OUTCOMES,
    )
    enriched_module_doc["release_checks"] = _append_unique_strings(
        enriched_module_doc.get("release_checks") or [],
        [
            "Every A6-A11 lesson uses 10 diagnostic, 8 concept-gate, and 10 mastery questions before any stem repeats.",
            "Every A6-A11 explorer keeps the formal condition, units, and comparison logic visible during the task.",
        ],
    )

    for (_, lesson), (_, sim_doc) in zip(enriched_lesson_pairs, enriched_sim_pairs):
        _enrich_lesson_payload(lesson, sim_doc)

    return version, enriched_module_doc, enriched_lesson_pairs, enriched_sim_pairs


A6_CONTENT_VERSION, A6_MODULE_DOC, A6_LESSONS, A6_SIM_LABS = _enrich_bundle(
    content_version=_A6_CONTENT_VERSION_RAW,
    module_doc=_A6_MODULE_DOC_RAW,
    lesson_pairs=_A6_LESSONS_RAW,
    sim_pairs=_A6_SIM_LABS_RAW,
)
A7_CONTENT_VERSION, A7_MODULE_DOC, A7_LESSONS, A7_SIM_LABS = _enrich_bundle(
    content_version=_A7_CONTENT_VERSION_RAW,
    module_doc=_A7_MODULE_DOC_RAW,
    lesson_pairs=_A7_LESSONS_RAW,
    sim_pairs=_A7_SIM_LABS_RAW,
)
A8_CONTENT_VERSION, A8_MODULE_DOC, A8_LESSONS, A8_SIM_LABS = _enrich_bundle(
    content_version=_A8_CONTENT_VERSION_RAW,
    module_doc=_A8_MODULE_DOC_RAW,
    lesson_pairs=_A8_LESSONS_RAW,
    sim_pairs=_A8_SIM_LABS_RAW,
)
A9_CONTENT_VERSION, A9_MODULE_DOC, A9_LESSONS, A9_SIM_LABS = _enrich_bundle(
    content_version=_A9_CONTENT_VERSION_RAW,
    module_doc=_A9_MODULE_DOC_RAW,
    lesson_pairs=_A9_LESSONS_RAW,
    sim_pairs=_A9_SIM_LABS_RAW,
)
A10_CONTENT_VERSION, A10_MODULE_DOC, A10_LESSONS, A10_SIM_LABS = _enrich_bundle(
    content_version=_A10_CONTENT_VERSION_RAW,
    module_doc=_A10_MODULE_DOC_RAW,
    lesson_pairs=_A10_LESSONS_RAW,
    sim_pairs=_A10_SIM_LABS_RAW,
)
A11_CONTENT_VERSION, A11_MODULE_DOC, A11_LESSONS, A11_SIM_LABS = _enrich_bundle(
    content_version=_A11_CONTENT_VERSION_RAW,
    module_doc=_A11_MODULE_DOC_RAW,
    lesson_pairs=_A11_LESSONS_RAW,
    sim_pairs=_A11_SIM_LABS_RAW,
)
