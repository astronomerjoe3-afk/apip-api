from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.lesson_authoring_contract import AUTHORING_STANDARD_V3
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_builder import build_nextgen_module_bundle
except ModuleNotFoundError:
    from lesson_authoring_contract import AUTHORING_STANDARD_V3
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_builder import build_nextgen_module_bundle

try:
    from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
except ModuleNotFoundError:
    from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc


def _tw(term: str, meaning: str, why_it_matters: str) -> Dict[str, str]:
    return {"term": term, "meaning": meaning, "why_it_matters": why_it_matters}


def safe_tags(allowlist: Sequence[str], tags: Sequence[str]) -> List[str]:
    allowed = set(str(tag) for tag in allowlist)
    return [str(tag) for tag in tags if str(tag) in allowed]


def mcq(
    allowlist: Sequence[str],
    qid: str,
    prompt: str,
    choices: Sequence[str],
    answer_index: int,
    hint: str,
    tags: Sequence[str],
    *,
    skill_tags: Sequence[str],
) -> Dict[str, Any]:
    return {
        "id": qid,
        "question_id": qid,
        "kind": "mcq",
        "type": "mcq",
        "prompt": prompt,
        "choices": list(choices),
        "answer_index": answer_index,
        "hint": hint,
        "feedback": [hint for _ in choices],
        "misconception_tags": safe_tags(allowlist, tags),
        "skill_tags": [str(tag) for tag in skill_tags],
    }


def short(
    allowlist: Sequence[str],
    qid: str,
    prompt: str,
    accepted_answers: Sequence[str],
    hint: str,
    tags: Sequence[str],
    *,
    skill_tags: Sequence[str],
    acceptance_rules: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    item = {
        "id": qid,
        "question_id": qid,
        "kind": "short",
        "type": "short",
        "prompt": prompt,
        "accepted_answers": list(accepted_answers),
        "hint": hint,
        "feedback": [hint],
        "misconception_tags": safe_tags(allowlist, tags),
        "skill_tags": [str(tag) for tag in skill_tags],
    }
    if acceptance_rules:
        item["acceptance_rules"] = deepcopy(acceptance_rules)
    return item


def acceptance_groups(*groups: Sequence[str]) -> Dict[str, Any]:
    return {"phrase_groups": [list(group) for group in groups]}


def prompt_block(prompt: str, hint: str) -> Dict[str, str]:
    return {"prompt": prompt, "hint": hint}


def relation(equation: str, meaning: str, units: Sequence[str], conditions: str) -> Dict[str, Any]:
    return {"equation": equation, "meaning": meaning, "units": list(units), "conditions": conditions}


def representation(kind: str, purpose: str) -> Dict[str, str]:
    return {"kind": kind, "purpose": purpose}


def worked(prompt: str, steps: Sequence[str], final_answer: str, answer_reason: str, why_it_matters: str) -> Dict[str, Any]:
    return {
        "prompt": prompt,
        "steps": list(steps),
        "final_answer": final_answer,
        "answer_reason": answer_reason,
        "why_it_matters": why_it_matters,
    }


def visual(
    asset_id: str,
    concept: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    template: str = "general_visual",
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": template,
        "meta": deepcopy(meta or {}),
    }


def animation(asset_id: str, concept: str, title: str, description: str) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "description": description,
        "duration_sec": 8,
    }


def extra_section(heading: str, body: str, check_for_understanding: str) -> Dict[str, str]:
    return {"heading": heading, "body": body, "check_for_understanding": check_for_understanding}


def scaffold(
    core_idea: str,
    reasoning: str,
    check: str,
    trap: str,
    analogy_body: str,
    analogy_check: str,
    extras: Sequence[Dict[str, str]],
) -> Dict[str, Any]:
    return {
        "core_idea": core_idea,
        "reasoning": reasoning,
        "check_for_understanding": check,
        "common_trap": trap,
        "analogy_bridge": {"body": analogy_body, "check_for_understanding": analogy_check},
        "extra_sections": list(extras),
    }


def assessment_targets(
    *,
    diagnostic_pool_min: int = 6,
    concept_gate_pool_min: int = 4,
    mastery_pool_min: int = 6,
) -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": diagnostic_pool_min,
        "concept_gate_pool_min": concept_gate_pool_min,
        "mastery_pool_min": mastery_pool_min,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile layouts.",
        "Key arrows, fronts, field lines, or orbit paths stay visually separated from text and readouts.",
        "Captions and summary callouts remain readable without clipping into the busiest part of the diagram.",
    ]


def _term_bank(config: Dict[str, Any]) -> Dict[str, Dict[str, str]]:
    return deepcopy(dict(config.get("term_bank") or {}))


def _lesson_terms(config: Dict[str, Any], lesson: Dict[str, Any]) -> List[Dict[str, str]]:
    bank = _term_bank(config)
    return [deepcopy(bank[key]) for key in lesson.get("terms") or [] if key in bank]


def _definition_choices(config: Dict[str, Any], lesson: Dict[str, Any], index: int) -> Tuple[str, List[str]]:
    terms = _lesson_terms(config, lesson)
    target = terms[index % len(terms)]
    distractors = [entry["meaning"] for entry in terms if entry["term"] != target["term"]][:3]
    while len(distractors) < 3:
        distractors.append("It is a different idea from the one this lesson is defining.")
    return target["term"], [target["meaning"], *distractors[:3]]


def _module_release_checks(config: Dict[str, Any]) -> List[str]:
    title = str(config["module_title"])
    return [
        f"Every lesson stays inside the {title} analogy family instead of swapping worlds halfway through.",
        "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
        "Every lesson-owned assessment bank prefers unseen questions before repeating the same stem.",
        "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
        "Every technical-word card remains lesson-specific so the vocabulary load grows incrementally.",
        "Every visual keeps labels, callouts, and summary text readable without clipping.",
    ]


def _analogy_map(config: Dict[str, Any], lesson: Dict[str, Any]) -> Dict[str, Any]:
    focus = str(lesson["focus"])
    return {
        "model_name": str(config["model_name"]),
        "focus": focus,
        "comparison": f"The {config['model_name']} keeps this lesson inside one coherent world while {focus}.",
        "mapping": list(config["analogy_mapping"]),
        "limit": str(config["analogy_limit"]),
        "prediction_prompt": f"Use the {config['model_name']} to predict what should happen when {focus}.",
    }


def _definition_question(
    config: Dict[str, Any],
    lesson: Dict[str, Any],
    lesson_id: str,
    question_id: str,
    index: int,
    prompt_prefix: str,
    skill_tag: str,
) -> Dict[str, Any]:
    term, choices = _definition_choices(config, lesson, index)
    return mcq(
        config["allowlist"],
        question_id,
        f"{prompt_prefix} {term} mean in this lesson?",
        choices,
        0,
        f"Keep {term} tied to this lesson's actual topic.",
        lesson["misconception_focus"],
        skill_tags=[skill_tag],
    )


def _formula_mcq(
    config: Dict[str, Any],
    lesson: Dict[str, Any],
    question_id: str,
    *,
    skill_tag: str,
) -> Dict[str, Any]:
    question = dict(lesson["formula_question"])
    return mcq(
        config["allowlist"],
        question_id,
        str(question["prompt"]),
        list(question["choices"]),
        int(question["answer_index"]),
        str(question["hint"]),
        lesson["misconception_focus"],
        skill_tags=[skill_tag],
    )


def _statement_mcq(config: Dict[str, Any], lesson: Dict[str, Any], question_id: str, *, skill_tag: str) -> Dict[str, Any]:
    question = dict(lesson["statement_question"])
    return mcq(
        config["allowlist"],
        question_id,
        str(question["prompt"]),
        list(question["choices"]),
        int(question["answer_index"]),
        str(question["hint"]),
        lesson["misconception_focus"],
        skill_tags=[skill_tag],
    )


def _apply_mcq(config: Dict[str, Any], lesson: Dict[str, Any], question_id: str, *, skill_tag: str) -> Dict[str, Any]:
    question = dict(lesson["apply_question"])
    return mcq(
        config["allowlist"],
        question_id,
        str(question["prompt"]),
        list(question["choices"]),
        int(question["answer_index"]),
        str(question["hint"]),
        lesson["misconception_focus"],
        skill_tags=[skill_tag],
    )


def _numeric_mcq(config: Dict[str, Any], lesson: Dict[str, Any], question_id: str, *, skill_tag: str) -> Dict[str, Any]:
    question = dict(lesson.get("numeric_question") or lesson["formula_question"])
    return mcq(
        config["allowlist"],
        question_id,
        str(question["prompt"]),
        list(question["choices"]),
        int(question["answer_index"]),
        str(question["hint"]),
        lesson["misconception_focus"],
        skill_tags=[skill_tag],
    )


def _short_item(
    config: Dict[str, Any],
    lesson: Dict[str, Any],
    question_id: str,
    prompt_key: str,
    answers_key: str,
    groups_key: str,
    hint: str,
    skill_tag: str,
) -> Dict[str, Any]:
    return short(
        config["allowlist"],
        question_id,
        str(lesson[prompt_key]),
        list(lesson[answers_key]),
        hint,
        lesson["misconception_focus"],
        skill_tags=[skill_tag],
        acceptance_rules=acceptance_groups(*lesson[groups_key]),
    )


def _diagnostic_items(config: Dict[str, Any], lesson: Dict[str, Any], lesson_id: str) -> List[Dict[str, Any]]:
    skills = list(lesson["mastery_skills"])
    return [
        _statement_mcq(config, lesson, f"{lesson_id.replace('_', '')}_D1", skill_tag=skills[0]),
        _short_item(config, lesson, f"{lesson_id.replace('_', '')}_D2", "why_prompt", "why_answers", "why_groups", "Use the lesson's main cause-and-effect language.", skills[1]),
        _definition_question(config, lesson, lesson_id, f"{lesson_id.replace('_', '')}_D3", 0, "What does", skills[2]),
        _formula_mcq(config, lesson, f"{lesson_id.replace('_', '')}_D4", skill_tag=skills[3]),
        _apply_mcq(config, lesson, f"{lesson_id.replace('_', '')}_D5", skill_tag=skills[4]),
        _short_item(config, lesson, f"{lesson_id.replace('_', '')}_D6", "compare_prompt", "compare_answers", "compare_groups", "Keep the lesson's contrast visible.", skills[0]),
    ]


def _concept_items(config: Dict[str, Any], lesson: Dict[str, Any], lesson_id: str) -> List[Dict[str, Any]]:
    skills = list(lesson["mastery_skills"])
    return [
        _short_item(config, lesson, f"{lesson_id.replace('_', '')}_C1", "why_prompt", "why_answers", "why_groups", "Use the lesson's key explanatory language.", skills[1]),
        _definition_question(config, lesson, lesson_id, f"{lesson_id.replace('_', '')}_C2", 1, "Which definition best matches", skills[2]),
        _formula_mcq(config, lesson, f"{lesson_id.replace('_', '')}_C3", skill_tag=skills[3]),
        _apply_mcq(config, lesson, f"{lesson_id.replace('_', '')}_C4", skill_tag=skills[4]),
    ]


def _mastery_items(config: Dict[str, Any], lesson: Dict[str, Any], lesson_id: str) -> List[Dict[str, Any]]:
    skills = list(lesson["mastery_skills"])
    return [
        _apply_mcq(config, lesson, f"{lesson_id.replace('_', '')}_M1", skill_tag=skills[4]),
        _short_item(config, lesson, f"{lesson_id.replace('_', '')}_M2", "compare_prompt", "compare_answers", "compare_groups", "Keep the two lesson ideas separate while you answer.", skills[0]),
        _definition_question(config, lesson, lesson_id, f"{lesson_id.replace('_', '')}_M3", 2, "Which lesson meaning best matches", skills[2]),
        _numeric_mcq(config, lesson, f"{lesson_id.replace('_', '')}_M4", skill_tag=skills[3]),
        _statement_mcq(config, lesson, f"{lesson_id.replace('_', '')}_M5", skill_tag=skills[0]),
        _short_item(config, lesson, f"{lesson_id.replace('_', '')}_M6", "why_prompt", "why_answers", "why_groups", "Keep the lesson's main mechanism visible.", skills[1]),
    ]


def _worked_examples(config: Dict[str, Any], lesson: Dict[str, Any]) -> List[Dict[str, Any]]:
    formula = dict(lesson["formula"])
    statement = dict(lesson["statement_question"])
    apply = dict(lesson["apply_question"])
    return [
        worked(
            f"Why is this lesson's anchor statement true? {lesson['why_prompt']}",
            [
                "Name the physical distinction the lesson is trying to protect.",
                "Link that distinction to the analogy model rather than to a memorized slogan.",
                "State the explanation in one clean sentence.",
            ],
            str(lesson["why_answers"][0]),
            "The answer works because it keeps the lesson's key relationship or mechanism visible.",
            "This shows students what a good short scientific explanation sounds like in this module.",
        ),
        worked(
            str(formula["equation"]),
            [
                "Identify which quantity the lesson relation is connecting.",
                "Use the relation only under the condition written in the lesson formula line.",
                "Explain the result in words rather than stopping at the symbol string.",
            ],
            str(formula["meaning"]),
            "The formula is a compressed summary of the lesson story, not a replacement for the story.",
            "This keeps the relation conceptual before it becomes a calculation tool.",
        ),
        worked(
            str(apply["prompt"]),
            [
                "Identify the lesson's main contrast or invariant first.",
                "Check which option keeps that contrast visible.",
                "Reject choices that collapse two different ideas into one vague statement.",
            ],
            str(apply["choices"][int(apply["answer_index"])]),
            "The correct choice keeps the lesson's specific distinction intact.",
            "This gives students a model for how to reason through transfer questions.",
        ),
    ]


def _lesson_visual(config: Dict[str, Any], lesson: Dict[str, Any], lesson_id: str) -> Dict[str, Any]:
    lesson_visual = dict(lesson.get("visual") or {})
    concept = str(lesson_visual.get("concept") or config.get("visual_concept") or "general_visual_concept")
    template = str(lesson_visual.get("template") or config.get("visual_template") or "general_visual")
    meta = deepcopy(dict(lesson_visual.get("meta") or {}))
    return visual(
        f"{lesson_id.lower()}_{lesson['slug']}",
        concept,
        str(lesson_visual.get("title") or lesson["title"]),
        str(lesson_visual.get("purpose") or f"Visualise the {lesson['title']} idea inside the {config['model_name']}."),
        str(lesson_visual.get("caption") or lesson["focus"]),
        template=template,
        meta=meta,
    )


def _lesson_animation(config: Dict[str, Any], lesson: Dict[str, Any], lesson_id: str) -> Dict[str, Any]:
    concept = str((lesson.get("visual") or {}).get("concept") or config.get("visual_concept") or "general_visual_concept")
    return animation(
        f"{lesson_id.lower()}_{lesson['slug']}_motion",
        concept,
        f"{lesson['title']} motion",
        f"Animate the {lesson['title']} idea inside the {config['model_name']} so the main pattern stays visible over time.",
    )


def _simulation_contract(config: Dict[str, Any], lesson: Dict[str, Any], lesson_id: str) -> Dict[str, Any]:
    return {
        "asset_id": f"{lesson_id.lower()}_{lesson['slug']}_sim",
        "concept": str(lesson["sim_concept"]),
        "focus_prompt": str(lesson["sim_focus_prompt"]),
        "baseline_case": str(lesson["sim_baseline"]),
        "comparison_tasks": list(lesson["sim_tasks"]),
        "watch_for": str(lesson["sim_watch_for"]),
        "takeaway": str(lesson["sim_takeaway"]),
        "controls": [{"variable": var, "label": label, "why_it_matters": why} for var, label, why in lesson["sim_controls"]],
        "readouts": [{"label": label, "meaning": meaning} for label, meaning in lesson["sim_readouts"]],
    }


def _lesson_contract(config: Dict[str, Any], lesson: Dict[str, Any], lesson_id: str) -> Dict[str, Any]:
    return {
        "concept_targets": list(lesson["concept_targets"]),
        "core_concepts": list(lesson["core_concepts"]),
        "prerequisite_lessons": list(lesson.get("prerequisite_lessons") or []),
        "misconception_focus": list(lesson["misconception_focus"]),
        "technical_words": _lesson_terms(config, lesson),
        "formulas": [deepcopy(lesson["formula"])],
        "representations": [
            representation("words", f"Explains the {lesson['title']} idea in sentence form before any calculation or classification."),
            representation("formula", f"Condenses the {lesson['title']} relation into a reusable formal statement."),
            representation(str(lesson.get("representation_kind") or "diagram"), f"Keeps the {lesson['title']} geometry, field, route, or scale visible."),
        ],
        "analogy_map": _analogy_map(config, lesson),
        "worked_examples": _worked_examples(config, lesson),
        "visual_assets": [_lesson_visual(config, lesson, lesson_id)],
        "animation_assets": [_lesson_animation(config, lesson, lesson_id)],
        "simulation_contract": _simulation_contract(config, lesson, lesson_id),
        "reflection_prompts": list(lesson["reflection_prompts"]),
        "mastery_skills": list(lesson["mastery_skills"]),
        "variation_plan": {
            "diagnostic": "Fresh attempts rotate between definition, mechanism, misconception, and formula-meaning prompts before repeating stems.",
            "concept_gate": "Concept checks vary between explanation, definition, relation meaning, and scenario application.",
            "mastery": "Mastery alternates between transfer scenarios, concise explanations, definitions, and relation-use items before repeating prompts.",
        },
        "assessment_bank_targets": assessment_targets(),
        "scaffold_support": scaffold(
            str(lesson["core_idea"]),
            str(lesson["reasoning"]),
            str(lesson["check_prompt"]),
            str(lesson["trap"]),
            str(lesson["analogy_body"]),
            str(lesson["analogy_check"]),
            [extra_section(*section) for section in lesson.get("scaffold_extras") or []],
        ),
        "visual_clarity_checks": visual_checks(str(lesson["slug"]).replace("_", " ")),
        "release_checks": _module_release_checks(config),
    }


def _lesson_spec(config: Dict[str, Any], lesson: Dict[str, Any], lesson_index: int) -> Dict[str, Any]:
    lesson_id = f"{config['module_id']}_L{lesson_index}"
    diagnostic = _diagnostic_items(config, lesson, lesson_id)
    concept_checks = _concept_items(config, lesson, lesson_id)
    mastery = _mastery_items(config, lesson, lesson_id)
    return {
        "id": lesson_id,
        "title": str(lesson["title"]),
        "sim": {
            "lab_id": f"{lesson_id.lower()}_{lesson['slug']}_lab",
            "title": f"{lesson['title']} explorer",
            "description": str(lesson["sim_description"]),
            "instructions": [
                str(lesson["sim_baseline"]),
                *[str(item) for item in lesson["sim_tasks"]],
            ],
            "outcomes": [str(lesson["sim_takeaway"]), str(lesson["focus"]), str(lesson["core_idea"])],
            "fields": [control[0] for control in lesson["sim_controls"]],
            "depth": str(lesson["sim_depth"]),
        },
        "diagnostic": diagnostic,
        "analogy_text": str(lesson["focus"]),
        "commitment_prompt": str(lesson["commitment_prompt"]),
        "micro_prompts": [
            prompt_block(str(lesson["micro_prompts"][0][0]), str(lesson["micro_prompts"][0][1])),
            prompt_block(str(lesson["micro_prompts"][1][0]), str(lesson["micro_prompts"][1][1])),
        ],
        "inquiry": [
            prompt_block(str(lesson["inquiry_prompts"][0][0]), str(lesson["inquiry_prompts"][0][1])),
            prompt_block(str(lesson["inquiry_prompts"][1][0]), str(lesson["inquiry_prompts"][1][1])),
        ],
        "recon_prompts": list(lesson["recon_prompts"]),
        "capsule_prompt": str(lesson["capsule_prompt"]),
        "capsule_checks": concept_checks,
        "transfer": mastery,
        "contract": _lesson_contract(config, lesson, lesson_id),
    }


MODULE_CONFIGS: Dict[str, Dict[str, Any]] = {}


def module_info(module_id: str) -> Dict[str, Any]:
    return deepcopy(MODULE_CONFIGS[module_id])


_MODULE_CACHE: Dict[str, Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]] = {}


def build_expansion_bundle(module_id: str) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    key = str(module_id).upper()
    if key in _MODULE_CACHE:
        cached = _MODULE_CACHE[key]
        return deepcopy(cached[0]), deepcopy(cached[1]), deepcopy(cached[2])

    config = module_info(key)
    module_spec = {
        "authoring_standard": AUTHORING_STANDARD_V3,
        "module_description": str(config["module_description"]),
        "mastery_outcomes": list(config["mastery_outcomes"]),
        "lessons": [_lesson_spec(config, lesson, index) for index, lesson in enumerate(config["lessons"], start=1)],
    }
    bundle = build_nextgen_module_bundle(
        module_id=key,
        module_title=str(config["module_title"]),
        module_spec=module_spec,
        allowlist=list(config["allowlist"]),
        content_version=str(config["content_version"]),
        release_checks=_module_release_checks(config),
        sequence=int(config["sequence"]),
        level=str(config["level"]),
        estimated_minutes=int(config["estimated_minutes"]),
        authoring_standard=AUTHORING_STANDARD_V3,
        plan_assets=True,
        public_base="/lesson_assets",
    )
    _MODULE_CACHE[key] = (deepcopy(bundle[0]), deepcopy(bundle[1]), deepcopy(bundle[2]))
    return build_expansion_bundle(key)


def seed_module_cli(module_id: str, description: str | None = None) -> None:
    info = module_info(module_id)
    parser = argparse.ArgumentParser(description=description or f"Seed module {module_id}")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    asset_root = args.asset_root or default_asset_root()
    module_doc, lesson_pairs, sim_pairs = build_expansion_bundle(module_id)

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", module_id)]
    plan.extend(("lessons", doc_id) for doc_id, _ in lesson_pairs)
    plan.extend(("sim_labs", doc_id) for doc_id, _ in sim_pairs)

    for collection, doc_id in plan:
        if collection == "modules":
            upsert_doc(db, collection, doc_id, module_doc, bool(args.apply))
        elif collection == "lessons":
            payload = next(payload for payload_id, payload in lesson_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, bool(args.apply))
        else:
            payload = next(payload for payload_id, payload in sim_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, bool(args.apply))
