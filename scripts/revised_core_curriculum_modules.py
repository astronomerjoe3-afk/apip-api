from __future__ import annotations

import argparse
from copy import deepcopy
from importlib import import_module
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


GENERIC_ALLOWLIST = [
    "concept_blend_confusion",
    "term_definition_confusion",
    "cause_effect_confusion",
    "comparison_confusion",
    "formula_role_confusion",
    "representation_confusion",
]


def tw(term: str, meaning: str, why_it_matters: str) -> Dict[str, str]:
    return {"term": term, "meaning": meaning, "why_it_matters": why_it_matters}


def acceptance_groups(*groups: Sequence[str]) -> Dict[str, Any]:
    return {"phrase_groups": [list(group) for group in groups]}


def relation(equation: str, meaning: str, units: Sequence[str], conditions: str) -> Dict[str, Any]:
    return {"equation": equation, "meaning": meaning, "units": list(units), "conditions": conditions}


def mcq(
    qid: str,
    prompt: str,
    choices: Sequence[str],
    answer_index: int,
    hint: str,
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
        "answer_index": int(answer_index),
        "hint": hint,
        "feedback": [hint for _ in choices],
        "misconception_tags": list(GENERIC_ALLOWLIST[:3]),
        "skill_tags": [str(tag) for tag in skill_tags],
    }


def short(
    qid: str,
    prompt: str,
    accepted_answers: Sequence[str],
    hint: str,
    *,
    skill_tags: Sequence[str],
    acceptance_rules: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "id": qid,
        "question_id": qid,
        "kind": "short",
        "type": "short",
        "prompt": prompt,
        "accepted_answers": list(accepted_answers),
        "hint": hint,
        "feedback": [hint],
        "misconception_tags": list(GENERIC_ALLOWLIST[:3]),
        "skill_tags": [str(tag) for tag in skill_tags],
        "acceptance_rules": deepcopy(acceptance_rules),
    }


def prompt_block(prompt: str, hint: str) -> Dict[str, str]:
    return {"prompt": prompt, "hint": hint}


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


def visual(asset_id: str, concept: str, title: str, purpose: str, caption: str) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": "general_visual",
        "meta": {},
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


def assessment_targets() -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": 6,
        "concept_gate_pool_min": 4,
        "mastery_pool_min": 6,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"All {topic} labels remain fully visible on desktop and mobile layouts.",
        "Key geometry and comparison text stay separated from the busiest part of the diagram.",
        "Summary callouts remain readable without clipping.",
    ]


def _definition_choices(terms: Sequence[Dict[str, str]], index: int) -> Tuple[str, List[str]]:
    entries = list(terms)
    target = entries[index % len(entries)]
    distractors = [entry["meaning"] for entry in entries if entry["term"] != target["term"]][:3]
    while len(distractors) < 3:
        distractors.append("It is a different lesson idea, not the one being defined here.")
    return target["term"], [target["meaning"], *distractors[:3]]


def _generic_statement_choices(summary: str) -> List[str]:
    return [
        summary,
        "The lesson works even if you ignore the main mechanism and only keep the label.",
        "The lesson says the opposite process causes the effect in every case.",
        "The lesson depends on naming the object only, not on the physical relationship.",
    ]


def _generic_formula_choices(equation: str) -> List[str]:
    return [
        equation,
        "The lesson has no reusable relation because only names matter here.",
        "The lesson relation runs backward from effect to cause as a universal rule.",
        "Only one variable matters, so the rest of the relation can be ignored.",
    ]


def _skills(slug: str) -> List[str]:
    return [
        f"{slug}_summary",
        f"{slug}_mechanism",
        f"{slug}_definition",
        f"{slug}_relation",
        f"{slug}_application",
    ]


def _lesson_spec(module_id: str, model_name: str, blueprint: Dict[str, Any], lesson_index: int) -> Dict[str, Any]:
    lesson_id = f"{module_id}_L{lesson_index}"
    slug = str(blueprint["slug"])
    skills = _skills(slug)
    terms = list(blueprint["terms"])
    term0, choices0 = _definition_choices(terms, 0)
    term1, choices1 = _definition_choices(terms, 1)
    term2, choices2 = _definition_choices(terms, 2)
    formula = deepcopy(blueprint["formula"])
    diagnostic = [
        mcq(f"{module_id}L{lesson_index}_D1", f"Which statement best matches {blueprint['title'].lower()}?", _generic_statement_choices(str(blueprint["summary"])), 0, "Keep the lesson's central distinction visible.", skill_tags=[skills[0]]),
        short(f"{module_id}L{lesson_index}_D2", str(blueprint["why_prompt"]), list(blueprint["why_answers"]), "Use the lesson's main cause-and-effect language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(*blueprint["why_groups"])),
        mcq(f"{module_id}L{lesson_index}_D3", f"What does {term0} mean in this lesson?", choices0, 0, f"Keep {term0} tied to this lesson's actual topic.", skill_tags=[skills[2]]),
        mcq(f"{module_id}L{lesson_index}_D4", f"Which relation best belongs to {blueprint['title'].lower()}?", _generic_formula_choices(str(formula["equation"])), 0, "Use the lesson's formal relation as a compact summary of the idea.", skill_tags=[skills[3]]),
        mcq(f"{module_id}L{lesson_index}_D5", str(blueprint["apply_prompt"]), list(blueprint["apply_choices"]), int(blueprint["apply_answer_index"]), "Choose the option that keeps the lesson's mechanism visible.", skill_tags=[skills[4]]),
        short(f"{module_id}L{lesson_index}_D6", str(blueprint["compare_prompt"]), list(blueprint["compare_answers"]), "Keep the lesson contrast explicit while you answer.", skill_tags=[skills[0]], acceptance_rules=acceptance_groups(*blueprint["compare_groups"])),
    ]
    concept = [
        short(f"{module_id}L{lesson_index}_C1", str(blueprint["why_prompt"]), list(blueprint["why_answers"]), "Use the lesson's key explanatory language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(*blueprint["why_groups"])),
        mcq(f"{module_id}L{lesson_index}_C2", f"Which definition best matches {term1}?", choices1, 0, f"Keep {term1} tied to the lesson idea.", skill_tags=[skills[2]]),
        mcq(f"{module_id}L{lesson_index}_C3", f"Which relation best fits this lesson?", _generic_formula_choices(str(formula["equation"])), 0, "Use the formal relation as a summary of the physics.", skill_tags=[skills[3]]),
        mcq(f"{module_id}L{lesson_index}_C4", str(blueprint["apply_prompt"]), list(blueprint["apply_choices"]), int(blueprint["apply_answer_index"]), "Keep the lesson logic visible in the scenario.", skill_tags=[skills[4]]),
    ]
    mastery = [
        mcq(f"{module_id}L{lesson_index}_M1", str(blueprint["apply_prompt"]), list(blueprint["apply_choices"]), int(blueprint["apply_answer_index"]), "Use the lesson mechanism in the new context.", skill_tags=[skills[4]]),
        short(f"{module_id}L{lesson_index}_M2", str(blueprint["compare_prompt"]), list(blueprint["compare_answers"]), "Keep both sides of the lesson contrast visible.", skill_tags=[skills[0]], acceptance_rules=acceptance_groups(*blueprint["compare_groups"])),
        mcq(f"{module_id}L{lesson_index}_M3", f"Which lesson meaning best matches {term2}?", choices2, 0, f"Keep {term2} tied to this lesson.", skill_tags=[skills[2]]),
        mcq(f"{module_id}L{lesson_index}_M4", f"Which relation belongs here?", _generic_formula_choices(str(formula["equation"])), 0, "Use the lesson's compact relation rather than a label-only guess.", skill_tags=[skills[3]]),
        mcq(f"{module_id}L{lesson_index}_M5", f"Which statement best protects {blueprint['title'].lower()}?", _generic_statement_choices(str(blueprint["summary"])), 0, "The best summary keeps the lesson distinction clear.", skill_tags=[skills[0]]),
        short(f"{module_id}L{lesson_index}_M6", str(blueprint["why_prompt"]), list(blueprint["why_answers"]), "Keep the lesson mechanism visible.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(*blueprint["why_groups"])),
    ]
    return {
        "id": lesson_id,
        "title": str(blueprint["title"]),
        "sim": {
            "lab_id": f"{lesson_id.lower()}_{slug}_lab",
            "title": f"{blueprint['title']} explorer",
            "description": str(blueprint["sim_description"]),
            "instructions": [str(blueprint["sim_baseline"]), *[str(item) for item in blueprint["sim_tasks"]]],
            "outcomes": [str(blueprint["sim_takeaway"]), str(blueprint["focus"]), str(blueprint["core_concepts"][0])],
            "fields": [control[0] for control in blueprint["sim_controls"]],
            "depth": str(blueprint.get("sim_depth") or "core"),
        },
        "diagnostic": diagnostic,
        "analogy_text": str(blueprint["focus"]),
        "commitment_prompt": f"Commit to reading {blueprint['title'].lower()} through the {model_name} before switching back to formal terms.",
        "micro_prompts": [
            prompt_block(f"What should stay constant when you explain {blueprint['title'].lower()}?", str(blueprint["core_concepts"][0])),
            prompt_block(f"What weak shortcut should you avoid in {blueprint['title'].lower()}?", str(blueprint["trap"])),
        ],
        "inquiry": [
            prompt_block(str(blueprint["sim_tasks"][0]), "Run the baseline case before changing the controls."),
            prompt_block(str(blueprint["sim_tasks"][1] if len(blueprint["sim_tasks"]) > 1 else blueprint["sim_tasks"][0]), "Compare one change at a time so the pattern stays readable."),
        ],
        "recon_prompts": [
            f"Rewrite {blueprint['title'].lower()} without using vague everyday language.",
            f"State the physical relationship that the {model_name} is protecting in this lesson.",
        ],
        "capsule_prompt": f"Use one strong sentence to summarise {blueprint['title'].lower()}.",
        "capsule_checks": concept,
        "transfer": mastery,
        "contract": {
            "concept_targets": list(blueprint["concept_targets"]),
            "core_concepts": list(blueprint["core_concepts"]),
            "prerequisite_lessons": list(blueprint.get("prerequisite_lessons") or []),
            "misconception_focus": list(GENERIC_ALLOWLIST[:4]),
            "technical_words": deepcopy(terms),
            "formulas": [formula],
            "representations": [
                representation("words", f"Explains {blueprint['title'].lower()} in sentence form first."),
                representation("formula", f"Condenses {blueprint['title'].lower()} into a reusable formal relation."),
                representation(str(blueprint.get("representation_kind") or "diagram"), f"Keeps the {blueprint['title'].lower()} pattern visible."),
            ],
            "analogy_map": {
                "model_name": model_name,
                "focus": str(blueprint["focus"]),
                "comparison": f"The {model_name} keeps this lesson inside one coherent world while {blueprint['focus'].lower()}",
                "mapping": list(blueprint["analogy_mapping"]),
                "limit": str(blueprint["analogy_limit"]),
                "prediction_prompt": f"Use the {model_name} to predict what should happen when {blueprint['focus'].lower()}",
            },
            "worked_examples": [
                worked(str(blueprint["why_prompt"]), ["Name the physical relationship the lesson is protecting.", "Tie that relationship back to the analogy rather than to a memorized slogan.", "State the explanation in one clean sentence."], str(blueprint["why_answers"][0]), "The answer works because it keeps the lesson's main mechanism visible.", "This models what a concise scientific explanation sounds like in this module."),
                worked(f"Which relation belongs to {blueprint['title'].lower()}?", ["Identify which quantities or ideas the lesson is linking.", "Use the relation only under its stated condition.", "Translate the relation back into words."], str(formula["equation"]), str(formula["meaning"]), "This keeps the relation conceptual before it becomes an algebra step."),
                worked(str(blueprint["apply_prompt"]), ["Identify the lesson's main contrast or invariant first.", "Check which option keeps that contrast visible.", "Reject label-only answers that hide the mechanism."], str(blueprint["apply_choices"][int(blueprint["apply_answer_index"])]), "The correct choice protects the lesson's specific distinction.", "This gives learners a transfer pattern they can reuse."),
            ],
            "visual_assets": [visual(f"{lesson_id.lower()}_{slug}", str(blueprint.get("visual_concept") or "general_visual_concept"), str(blueprint["title"]), f"Visualise {blueprint['title'].lower()} inside the {model_name}.", str(blueprint["focus"]))],
            "animation_assets": [animation(f"{lesson_id.lower()}_{slug}_motion", str(blueprint.get("visual_concept") or "general_visual_concept"), f"{blueprint['title']} motion", f"Animate the {blueprint['title'].lower()} idea so the changing pattern stays visible over time.")],
            "simulation_contract": {
                "asset_id": f"{lesson_id.lower()}_{slug}_sim",
                "concept": str(blueprint["sim_concept"]),
                "focus_prompt": str(blueprint["sim_focus_prompt"]),
                "baseline_case": str(blueprint["sim_baseline"]),
                "comparison_tasks": list(blueprint["sim_tasks"]),
                "watch_for": str(blueprint["sim_watch_for"]),
                "takeaway": str(blueprint["sim_takeaway"]),
                "controls": [{"variable": var, "label": label, "why_it_matters": why} for var, label, why in blueprint["sim_controls"]],
                "readouts": [{"label": label, "meaning": meaning} for label, meaning in blueprint["sim_readouts"]],
            },
            "reflection_prompts": list(blueprint["reflection_prompts"]),
            "mastery_skills": skills,
            "variation_plan": {
                "diagnostic": "Fresh attempts rotate between explanation, definition, relation, and scenario prompts before repeating stems.",
                "concept_gate": "Concept checks vary between concise explanation, definition, relation meaning, and scenario application.",
                "mastery": "Mastery alternates between transfer scenarios, concise explanations, definitions, and relation-use items before repeating prompts.",
            },
            "assessment_bank_targets": assessment_targets(),
            "scaffold_support": scaffold(
                str(blueprint["core_concepts"][0]),
                f"Read {blueprint['title'].lower()} by keeping the lesson's main mechanism visible before touching equations or labels.",
                f"What physical relationship should stay visible when you explain {blueprint['title'].lower()}?",
                str(blueprint["trap"]),
                f"The {model_name} keeps this lesson readable by making {blueprint['focus'].lower()}.",
                str(blueprint["analogy_check"]),
                [extra_section("Lesson bridge", str(blueprint["focus"]), str(blueprint["analogy_check"]))],
            ),
            "visual_clarity_checks": visual_checks(str(blueprint["title"]).lower()),
            "release_checks": [
                f"Every lesson stays inside the {model_name} analogy family.",
                "Every lesson uses lesson-owned assessment banks and lesson-specific technical words.",
                "Every explorer is lesson-specific and every visual stays readable without clipping.",
                "Every lesson keeps at least four general core concepts and full authored release checks.",
            ],
        },
    }


def _build_generated_bundle(*, module_id: str, module_title: str, content_version: str, sequence: float, level: str, estimated_minutes: int, model_name: str, module_description: str, mastery_outcomes: Sequence[str], lessons: Sequence[Dict[str, Any]]) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    module_spec = {"authoring_standard": AUTHORING_STANDARD_V3, "module_description": module_description, "mastery_outcomes": list(mastery_outcomes), "lessons": [_lesson_spec(module_id, model_name, lesson, index) for index, lesson in enumerate(lessons, start=1)]}
    module_doc, lesson_pairs, sim_pairs = build_nextgen_module_bundle(module_id=module_id, module_title=module_title, module_spec=module_spec, allowlist=GENERIC_ALLOWLIST, content_version=content_version, release_checks=[f"Every lesson stays inside the {model_name} analogy family.", "Every lesson uses lesson-owned assessment banks and lesson-specific technical words.", "Every explorer is lesson-specific and every visual stays readable without clipping.", "Every lesson keeps at least four general core concepts and four release checks in the authored contract."], sequence=int(sequence), level=level, estimated_minutes=estimated_minutes, authoring_standard=AUTHORING_STANDARD_V3, plan_assets=True, public_base="/lesson_assets")
    module_doc["sequence"] = sequence
    return module_doc, lesson_pairs, sim_pairs


def _set_visual_asset(
    lesson: Dict[str, Any],
    *,
    asset_id: str,
    concept: str,
    template: str,
    title: str,
    purpose: str,
    caption: str,
    meta: Dict[str, Any],
) -> None:
    lesson["authoring_contract"]["visual_assets"] = [
        {
            "asset_id": asset_id,
            "concept": concept,
            "phase_key": "analogical_grounding",
            "title": title,
            "purpose": purpose,
            "caption": caption,
            "template": template,
            "meta": deepcopy(meta),
        }
    ]


def _update_short_item(
    item: Dict[str, Any],
    *,
    accepted_answers: Sequence[str],
    phrase_groups: Sequence[Sequence[str]],
) -> None:
    item["accepted_answers"] = [str(answer) for answer in accepted_answers]
    item["acceptance_rules"] = acceptance_groups(*phrase_groups)


def _load_seed_bundle(module_path: str, prefix: str) -> Tuple[str, Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    seed_module = import_module(module_path)
    return getattr(seed_module, f"{prefix}_CONTENT_VERSION"), deepcopy(getattr(seed_module, f"{prefix}_MODULE_DOC")), deepcopy(getattr(seed_module, f"{prefix}_LESSONS")), deepcopy(getattr(seed_module, f"{prefix}_SIM_LABS"))


def _clone_bundle(*, module_path: str, source_prefix: str, target_prefix: str, module_title: str, module_description: str, content_version: str, sequence: float, level: str, estimated_minutes: int, mastery_outcomes: Sequence[str]) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    _, module_doc, lesson_pairs, sim_pairs = _load_seed_bundle(module_path, source_prefix)
    lab_id_map: Dict[str, str] = {}
    new_sim_pairs: List[Tuple[str, Dict[str, Any]]] = []
    for sim_id, payload in sim_pairs:
        new_sim_id = sim_id.replace(source_prefix.lower(), target_prefix.lower(), 1)
        cloned = deepcopy(payload)
        cloned["lab_id"] = new_sim_id
        cloned["id"] = new_sim_id
        cloned["module_id"] = target_prefix
        lab_id_map[sim_id] = new_sim_id
        new_sim_pairs.append((new_sim_id, cloned))
    new_lessons: List[Tuple[str, Dict[str, Any]]] = []
    for lesson_id, payload in lesson_pairs:
        new_lesson_id = lesson_id.replace(source_prefix, target_prefix, 1)
        cloned = deepcopy(payload)
        cloned["lesson_id"] = new_lesson_id
        cloned["id"] = new_lesson_id
        cloned["module_id"] = target_prefix
        sim_lab_id = cloned.get("phases", {}).get("simulation_inquiry", {}).get("lab_id")
        if isinstance(sim_lab_id, str) and sim_lab_id in lab_id_map:
            cloned["phases"]["simulation_inquiry"]["lab_id"] = lab_id_map[sim_lab_id]
        new_lessons.append((new_lesson_id, cloned))
    module_doc["id"] = target_prefix
    module_doc["module_id"] = target_prefix
    module_doc["title"] = module_title
    module_doc["module_title"] = module_title
    module_doc["module_description"] = module_description
    module_doc["mastery_outcomes"] = list(mastery_outcomes)
    module_doc["content_version"] = content_version
    module_doc["sequence"] = sequence
    module_doc["level"] = level
    module_doc["estimated_minutes"] = estimated_minutes
    return module_doc, new_lessons, new_sim_pairs


def _token_groups(terms: Sequence[Dict[str, str]], extras: Sequence[str] | None = None) -> List[List[str]]:
    groups: List[List[str]] = []
    for entry in list(terms)[:4]:
        term = str(entry.get("term") or "").strip()
        if term:
            groups.append([term, term.lower()])
    for extra in extras or []:
        if extra:
            groups.append([str(extra)])
    return groups[:6] if groups else [["lesson"], ["idea"]]


def auto_blueprint(
    *,
    slug: str,
    title: str,
    focus: str,
    terms: Sequence[Dict[str, str]],
    core_concepts: Sequence[str],
    equation: str,
    meaning: str,
    units: Sequence[str],
    conditions: str,
    summary: str,
    why_prompt: str,
    why_answer: str,
    compare_prompt: str,
    compare_answer: str,
    apply_prompt: str,
    apply_choices: Sequence[str],
    apply_answer_index: int,
    sim_concept: str,
    sim_focus_prompt: str,
    sim_description: str,
    sim_baseline: str,
    sim_tasks: Sequence[str],
    sim_takeaway: str,
    sim_controls: Sequence[Tuple[str, str, str]],
    sim_readouts: Sequence[Tuple[str, str]],
    reflection_prompt: str,
    trap: str,
    analogy_check: str,
    analogy_mapping: Sequence[str],
    visual_concept: str = "general_visual_concept",
) -> Dict[str, Any]:
    concept_list = [str(item) for item in core_concepts]
    while len(concept_list) < 4:
        concept_list.append(f"Keep {title.lower()} readable by holding the main relationship steady.")
    concept_targets = [slug, f"{slug}_reasoning", f"{slug}_transfer"]
    mastery_skills = _skills(slug)
    formula = relation(equation, meaning, units, conditions)
    statement_question = {
        "prompt": f"Which statement best protects {title.lower()}?",
        "choices": _generic_statement_choices(summary),
        "answer_index": 0,
        "hint": "Keep the lesson's main distinction visible.",
    }
    formula_question = {
        "prompt": f"Which relation best belongs to {title.lower()}?",
        "choices": _generic_formula_choices(equation),
        "answer_index": 0,
        "hint": "Use the lesson relation as a compact summary of the idea.",
    }
    return {
        "slug": slug,
        "title": title,
        "focus": focus,
        "terms": list(terms),
        "concept_targets": concept_targets,
        "core_concepts": concept_list,
        "formula": formula,
        "statement_question": statement_question,
        "formula_question": formula_question,
        "numeric_question": deepcopy(formula_question),
        "summary": summary,
        "core_idea": concept_list[0],
        "reasoning": f"Read {title.lower()} by keeping {focus} visible before you switch to labels or equations.",
        "check_prompt": f"What physical relationship should stay visible when you explain {title.lower()}?",
        "analogy_body": f"The {title} lesson stays readable when the {focus} stays visible inside the analogy world.",
        "why_prompt": why_prompt,
        "why_answers": [why_answer],
        "why_groups": _token_groups(terms, [slug.replace("_", " ")]),
        "compare_prompt": compare_prompt,
        "compare_answers": [compare_answer],
        "compare_groups": _token_groups(terms, ["different", "compare"]),
        "apply_prompt": apply_prompt,
        "apply_choices": list(apply_choices),
        "apply_answer_index": apply_answer_index,
        "sim_concept": sim_concept,
        "sim_focus_prompt": sim_focus_prompt,
        "sim_description": sim_description,
        "sim_baseline": sim_baseline,
        "sim_tasks": list(sim_tasks),
        "sim_depth": "core",
        "sim_watch_for": trap,
        "sim_takeaway": sim_takeaway,
        "sim_controls": list(sim_controls),
        "sim_readouts": list(sim_readouts),
        "reflection_prompts": [reflection_prompt],
        "misconception_focus": list(GENERIC_ALLOWLIST[:4]),
        "mastery_skills": mastery_skills,
        "trap": trap,
        "analogy_check": analogy_check,
        "analogy_mapping": list(analogy_mapping),
        "analogy_limit": "The analogy makes the relationships readable, but students should still translate back into the formal physics terms and conditions.",
        "scaffold_extras": [("Lesson bridge", focus, analogy_check)],
        "commitment_prompt": f"Commit to reading {title.lower()} through the analogy before switching back to formal terms.",
        "micro_prompts": [
            (f"What should stay constant when you explain {title.lower()}?", concept_list[0]),
            (f"What shortcut should you avoid in {title.lower()}?", trap),
        ],
        "inquiry_prompts": [
            (list(sim_tasks)[0], "Run the baseline case before changing the controls."),
            (list(sim_tasks)[1] if len(list(sim_tasks)) > 1 else list(sim_tasks)[0], "Change one thing at a time so the pattern stays readable."),
        ],
        "recon_prompts": [
            f"Rewrite {title.lower()} without vague everyday language.",
            f"State the physical relationship that the analogy is protecting in this lesson.",
        ],
        "capsule_prompt": f"Use one strong sentence to summarise {title.lower()}.",
        "visual_concept": visual_concept,
    }


def _f5_l1_extras(lesson_tag: str, skills: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "diagnostic": [
            mcq(f"{lesson_tag}_D7", "Which pair correctly matches the main orbit in the Earth-Moon-Sun system?", ["Earth orbits the Sun and the Moon orbits Earth", "Earth orbits the Moon and the Sun orbits Earth", "The Moon orbits the Sun directly while Earth stays fixed", "All three bodies orbit Earth in the same way"], 0, "Keep host body and orbit route matched correctly.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_D8", "A scale sketch uses 1 cm for 100,000 km. If Earth and Moon are shown 3 cm apart, what real distance does that represent?", ["300000 km", "300,000 km", "300000"], "Multiply the scale value by the number of centimeters on the sketch.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["300000", "300,000", "300000 km", "300,000 km"])),
            mcq(f"{lesson_tag}_D9", "Which clue best shows the Earth-Moon-Sun picture should be treated as one linked system?", ["The same positions help explain day-night, phases, eclipses, and orbit ideas together", "Each sky pattern needs a separate cause because the bodies are unrelated", "The Moon shines by making its own light", "Scale does not matter once the Sun is drawn"], 0, "Look for the answer that keeps several sky patterns on one board.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_D10", "Why should gravity stay in the Earth-Moon-Sun story even when no rope or rail is drawn?", ["because gravity keeps the bodies in orbit and linked as one system", "because gravity is the pull that keeps the routes organized", "because gravity keeps Earth and Moon on their paths"], "Use pull-and-orbit language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["gravity", "pull"], ["orbit", "path", "route", "linked"])),
        ],
        "concept": [
            mcq(f"{lesson_tag}_C5", "Which sentence best protects the idea of a shared skycourt?", ["One system picture can explain several sky patterns at once", "Every sky pattern needs its own unrelated rule", "The Moon and Earth use the same route around the Sun", "Scale can be ignored because the diagram is always exact"], 0, "Keep the linked-system idea visible.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_C6", "Why is an orbit weaker if it is described as a painted track in space?", ["because gravity and sideways motion make the path rather than a fixed rail", "because an orbit is a gravity-guided path not a built track", "because the route comes from pull and motion"], "Use gravity-guided path language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["gravity", "pull"], ["path", "route", "orbit"], ["track", "rail", "fixed"])),
            mcq(f"{lesson_tag}_C7", "If the Moon circles Earth while Earth circles the Sun, which statement is strongest?", ["The system has linked motions on different scales", "Earth and Moon must be the same type of body", "The Moon cannot affect any Earth-sky pattern", "The Sun is not part of the system idea"], 0, "Keep the nested-motion picture visible.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_C8", "A model uses 1 cm for 50,000 km. What real distance does 4 cm represent?", ["200000 km", "200,000 km", "200000"], "Multiply the model distance by the scale.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["200000", "200,000", "200000 km", "200,000 km"])),
        ],
        "mastery": [
            short(f"{lesson_tag}_M7", "A poster shows Earth, Moon, and Sun almost touching. What is the most important correction?", ["the distances are heavily compressed and the scale is not realistic", "the picture is not to scale and the real distances are much larger", "the sketch exaggerates closeness because real space is much bigger"], "Answer with scale-compression language.", skill_tags=[skills[0]], acceptance_rules=acceptance_groups(["scale", "not to scale", "compressed", "larger"], ["distance", "far", "space"])),
            mcq(f"{lesson_tag}_M8", "Why is the Moon not placed in the same category as Earth in this lesson?", ["Because the Moon mainly orbits Earth while Earth orbits the Sun", "Because the Moon is made of light", "Because the Moon never moves", "Because only Earth has gravity"], 0, "Use main-host language.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_M9", "At a scale of 1 cm to 200,000 km, what real distance does 2 cm represent?", ["400000 km", "400,000 km", "400000"], "Use the same scale factor for the full distance.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["400000", "400,000", "400000 km", "400,000 km"])),
            mcq(f"{lesson_tag}_M10", "Which explanation best keeps the Earth-Moon-Sun lesson rich rather than split into separate facts?", ["Use one linked system with gravity, orbit, and scale on the same board", "Teach day-night, phases, and seasons as unrelated lists", "Ignore the Sun once the Moon is introduced", "Treat orbit as decoration rather than cause"], 0, "Choose the option that keeps the three-body system together.", skill_tags=[skills[4]]),
        ],
    }


def _f5_l2_extras(lesson_tag: str, skills: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "diagnostic": [
            short(f"{lesson_tag}_D7", "Earth turns 360 degrees in 24 hours. How many degrees does it turn in 6 hours?", ["90", "90 degrees"], "Use a proportional part of one full turn.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["90", "90 degrees"])),
            mcq(f"{lesson_tag}_D8", "What is the strongest explanation for one city moving from night into day?", ["Earth rotates and carries the city into the lit half", "Earth moves much closer to the Sun each morning", "The Moon shines more strongly at sunrise", "Earth finishes a full year each day"], 0, "Keep the turning-Earth mechanism visible.", skill_tags=[skills[4]]),
            mcq(f"{lesson_tag}_D9", "Which thing stays fixed in the simple day-night model while Earth spins?", ["The sunlight direction from the Sun", "The city marker itself in space", "The day side on the surface", "Earth's orbit position changes every few seconds"], 0, "The Sun's direction sets the lit half while Earth turns through it.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_D10", "Why can sunrise happen without Earth completing a whole orbit around the Sun?", ["because Earth only needs to rotate until the place faces sunlight", "because spin brings the place into the lit half", "because rotation not yearly orbit causes day and night"], "Use spin-and-sunlight language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["spin", "rotate", "rotation", "turn"], ["sunlight", "lit", "face the Sun", "day side"])),
        ],
        "concept": [
            mcq(f"{lesson_tag}_C5", "If Earth turns about 15 degrees each hour, how far does it turn in 3 hours?", ["45 degrees", "30 degrees", "60 degrees", "90 degrees"], 0, "Multiply the turn per hour by the number of hours.", skill_tags=[skills[3]]),
            short(f"{lesson_tag}_C6", "Why does Earth not need one full year to change one place from day to night?", ["because rotation changes the lit side much faster than orbit", "because one spin not one orbit makes day and night", "because Earth turns on its axis every day"], "Separate spin timing from orbit timing.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["spin", "rotation", "turn", "axis"], ["day", "night", "lit", "dark"])),
            mcq(f"{lesson_tag}_C7", "Which pair correctly matches the timescale?", ["day -> one rotation, year -> one orbit", "day -> one orbit, year -> one rotation", "day -> one eclipse, year -> one phase cycle", "day -> no motion, year -> rotation only"], 0, "Keep the two motions separate.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_C8", "A place goes from noon to midnight. What fraction of a full turn has Earth made for that place?", ["half a turn", "1/2 turn", "180 degrees"], "Noon to midnight is opposite sides of one full spin.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["half", "1/2", "180"])),
        ],
        "mastery": [
            mcq(f"{lesson_tag}_M7", "At about 15 degrees per hour, how far does Earth rotate in 4 hours?", ["60 degrees", "45 degrees", "75 degrees", "120 degrees"], 0, "Multiply the turn per hour by 4.", skill_tags=[skills[3]]),
            short(f"{lesson_tag}_M8", "How is rotation different from orbit in the day-night lesson?", ["rotation is Earth spinning on its axis while orbit is Earth moving around the Sun", "spin is on the axis and orbit is the path around the Sun", "rotation turns Earth and orbit carries Earth around the Sun"], "Name both motions clearly.", skill_tags=[skills[0]], acceptance_rules=acceptance_groups(["spin", "rotation", "axis"], ["orbit", "around the Sun", "path"])),
            mcq(f"{lesson_tag}_M9", "Two cities on opposite sides of Earth are compared at the same moment. Which statement is strongest?", ["One can be on the day side while the other is on the night side because Earth is rotating", "They must both have noon because the Sun is one star", "They can only differ if the Moon blocks the Sun", "They can only differ once Earth completes a year"], 0, "Use the half-lit Earth picture.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_M10", "Why is 'the Sun goes around Earth once each day' a weak scientific explanation for the pattern we see?", ["because the apparent daily motion is better explained by Earth rotating", "because the daily sky pattern is a viewpoint effect from Earth's spin", "because Earth turning explains the changing view of the Sun"], "Use apparent-motion and rotation language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["rotate", "spin", "Earth turns"], ["apparent", "view", "seen", "pattern", "sky"])),
        ],
    }


def _f5_l3_extras(lesson_tag: str, skills: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "diagnostic": [
            mcq(f"{lesson_tag}_D7", "If the Northern Hemisphere leans toward the Sun, what is most likely true?", ["It receives more direct sunlight", "It must be farther from the Sun", "The Southern Hemisphere gets the same season", "Earth's axis has flipped"], 0, "Use tilt and sunlight angle together.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_D8", "About six months after June in the Northern Hemisphere, which hemisphere leans more toward the Sun?", ["Southern Hemisphere", "the south", "south"], "Half a year later, the seasonal lean swaps hemispheres.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["south", "southern"])),
            mcq(f"{lesson_tag}_D9", "If Earth had no axial tilt, which seasonal claim is strongest?", ["Season differences would be much smaller because the lean effect would be removed", "Summer would become hotter because Earth would be closer to the Sun", "Earth would stop rotating", "The Moon would cause all seasons"], 0, "Remove tilt first, then ask what seasonal cause remains.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_D10", "Why can opposite hemispheres have opposite seasons at the same time?", ["because the tilted axis makes one hemisphere lean toward the Sun while the other leans away", "because the same tilt gives opposite sunlight angles in opposite hemispheres", "because tilt affects the two hemispheres in opposite ways"], "Use opposite-hemisphere tilt language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["tilt", "axis", "lean"], ["opposite", "one hemisphere", "other hemisphere", "north", "south"])),
        ],
        "concept": [
            mcq(f"{lesson_tag}_C5", "Which statement best matches the season-switch model?", ["Earth keeps roughly the same axis direction in space as it orbits", "Earth flips its axis every half year", "Earth must get much nearer the Sun in summer", "The Moon changes Earth's axis each month"], 0, "Keep the fixed axis direction visible.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_C6", "Why is a simple distance-from-the-Sun story too weak to explain seasons?", ["because opposite hemispheres have opposite seasons at the same time", "because the same Earth-Sun distance cannot give opposite seasons in different hemispheres", "because tilt and sunlight angle explain the pattern better than distance alone"], "Use opposite-hemisphere language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["opposite", "north", "south", "hemisphere"], ["same time", "same distance", "distance alone", "tilt"])),
            mcq(f"{lesson_tag}_C7", "Which sunlight description usually fits the hemisphere tilted toward the Sun?", ["more direct sunlight and longer daylight", "less direct sunlight and shorter daylight", "no daylight at all", "the same sunlight angle as the opposite hemisphere"], 0, "Tie the lean to the sunlight angle.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_C8", "If Earth's tilt were 0 degrees, what would happen to the strong seasonal contrast?", ["it would be much smaller or nearly disappear", "there would be little or no strong seasonal contrast", "seasons would weaken a lot"], "Answer with no-tilt, weaker-season language.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["little", "less", "weaker", "smaller", "no strong"], ["season"])),
        ],
        "mastery": [
            mcq(f"{lesson_tag}_M7", "It is December. Which hemisphere is more likely tilted toward the Sun?", ["Southern Hemisphere", "Northern Hemisphere", "both equally by tilt", "neither because tilt no longer matters"], 0, "Use the six-month swap idea.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_M8", "About how long after June does the main seasonal lean swap to the opposite hemisphere?", ["about six months", "6 months", "half a year"], "A half-year shift reverses the tilt advantage.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["six", "6", "half"], ["month", "year"])),
            mcq(f"{lesson_tag}_M9", "Which statement best protects the role of a solstice in this lesson?", ["It is a point where one hemisphere leans most toward or away from the Sun", "It is when Earth stops moving for a day", "It is the moment the Moon causes winter", "It is just the date Earth is closest to the Sun"], 0, "Use maximum lean, not distance, as the anchor.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_M10", "Why is tilt a stronger seasonal cause than simple Earth-Sun distance?", ["because tilt changes sunlight angle and hemisphere lean while distance alone cannot explain opposite seasons", "because tilt changes which hemisphere gets more direct sunlight", "because opposite seasonal patterns follow lean not simple closeness"], "Use tilt-plus-sunlight-angle language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["tilt", "lean"], ["sunlight angle", "direct sunlight", "opposite seasons", "hemisphere"])),
        ],
    }


def _f5_l4_extras(lesson_tag: str, skills: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "diagnostic": [
            mcq(f"{lesson_tag}_D7", "Starting from new moon, which named phase appears after about one quarter of the Moon's orbit?", ["first quarter", "full moon", "third quarter", "solar eclipse"], 0, "Move a quarter of the way around the orbit from the new-moon position.", skill_tags=[skills[3]]),
            short(f"{lesson_tag}_D8", "Starting from new moon, what phase appears after about half an orbit?", ["full moon", "the full moon"], "Half an orbit from new moon places the Moon opposite the Sun in the sky.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["full moon", "full"])),
            mcq(f"{lesson_tag}_D9", "Which statement stays true all month in the phase model?", ["The Sun lights half of the Moon all the time", "Earth's shadow covers part of the Moon every night", "The Moon makes its own light", "The lit half appears and disappears physically"], 0, "Keep the half-lit Moon constant.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_D10", "Why are ordinary Moon phases not just small eclipses every month?", ["because phases come from viewing the lit half while eclipses need a special shadow alignment", "because phases are a viewpoint change and eclipses are special shadow events", "because Earth's shadow is not the normal cause of phases"], "Separate viewing angle from special shadow alignment.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["view", "viewing angle", "lit half", "see"], ["eclipse", "shadow", "special alignment", "rare"])),
        ],
        "concept": [
            mcq(f"{lesson_tag}_C5", "Which alignment best matches a lunar eclipse?", ["Earth between Sun and Moon", "Moon between Earth and Sun every month", "Sun between Earth and Moon", "No special alignment is needed"], 0, "A lunar eclipse is a shadow event with Earth in the middle.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_C6", "At first quarter, what fraction of the Moon's orbit has passed since new moon?", ["one quarter", "1/4", "quarter"], "First quarter matches about one quarter of the orbit from new moon.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["quarter", "1/4", "one quarter"])),
            mcq(f"{lesson_tag}_C7", "Which sentence best protects the phase model?", ["A crescent means we see only a small part of the Moon's lit half", "A crescent means most of the Moon is unlit by the Sun", "A crescent means Earth's shadow is nearly covering the Moon", "A crescent means the Moon has stopped reflecting sunlight"], 0, "Use visible part of the lit half.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_C8", "Why can a crescent Moon still belong to a half-lit Moon?", ["because the Sun still lights half the Moon even though we see only a small part of that half", "because the lit half stays the same while our view changes", "because the visible part changes, not the fact that half is sunlit"], "Keep constant lighting separate from changing viewpoint.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["half lit", "half", "sun lights half"], ["see", "view", "visible part", "small part"])),
        ],
        "mastery": [
            mcq(f"{lesson_tag}_M7", "A diagram shows Earth, Moon, and Sun at right angles with the Moon half-way around from new moon. Which phase is strongest?", ["first quarter", "full moon", "new moon", "lunar eclipse"], 0, "A right-angle position from Earth gives a quarter phase.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_M8", "If the Moon moves from new moon to the opposite side of Earth, what phase is expected?", ["full moon", "the full moon"], "Opposite the Sun from Earth's viewpoint gives full moon.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["full moon", "full"])),
            mcq(f"{lesson_tag}_M9", "Which explanation best separates ordinary phases from eclipses?", ["Phases are normal viewing changes; eclipses are special alignment events", "Phases are small eclipses that happen every month", "Eclipses happen because the Moon stops reflecting light", "Phases and eclipses are the same event with different names"], 0, "Keep monthly geometry separate from rare shadow cases.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_M10", "Why is Earth's shadow not the everyday explanation for the changing Moon shape?", ["because the changing shape comes from how much of the lit half we can see", "because phases are a viewing-angle story not a constant shadow story", "because the visible lit fraction changes as the Moon orbits Earth"], "Use visible-lit-half language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["see", "visible", "view"], ["lit half", "sunlit", "lit fraction"], ["orbit", "moves around Earth", "phase"])),
        ],
    }


def _f5_l5_extras(lesson_tag: str, skills: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "diagnostic": [
            mcq(f"{lesson_tag}_D7", "Which option is classified as a moon in the Solar System family?", ["a body that mainly orbits a planet or dwarf planet", "any body that orbits the Sun", "a rocky body in the asteroid belt only", "the central star"], 0, "Classify by main host body first.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_D8", "If a body mainly orbits a larger world instead of the Sun directly, what broad category fits best?", ["moon", "natural satellite", "a moon"], "Use host-body language.", skill_tags=[skills[2]], acceptance_rules=acceptance_groups(["moon", "satellite"])),
            mcq(f"{lesson_tag}_D9", "Why should not every round Sun-orbiting body be called a full planet?", ["Because the Solar System has other categories such as dwarf planets, asteroids, and comets", "Because anything that moves in space is a star", "Because shape never matters in astronomy", "Because moons and planets are always the same thing"], 0, "Keep the category system visible.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_D10", "In one shared time window, an inner world completes 4 laps while an outer world completes 1. Which has the shorter year?", ["the inner world", "inner world", "the inner planet"], "More completed laps in the same time means a shorter orbital period.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["inner"], ["short", "year", "lap", "orbit"])),
        ],
        "concept": [
            mcq(f"{lesson_tag}_C5", "Which statement best distinguishes a dwarf planet from a moon in this school-level model?", ["A dwarf planet orbits the Sun directly, while a moon mainly orbits a larger world", "A dwarf planet makes its own light, while a moon does not", "A dwarf planet never moves", "A moon must be larger than a dwarf planet"], 0, "Use main host body as the first clue.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_C6", "What two clues should you read together when classifying a Solar System body?", ["what the body is and what it mainly orbits", "body type and main host", "its category and its main host body"], "Use body type plus main host.", skill_tags=[skills[0]], acceptance_rules=acceptance_groups(["body", "type", "category"], ["orbit", "host", "mainly orbits"])),
            mcq(f"{lesson_tag}_C7", "Which small-body description best matches a comet?", ["an icy visitor that can develop a coma or tail near the Sun", "a rocky moon around Earth", "a planet that has cleared its orbit", "the central lantern of the system"], 0, "Separate icy visitors from rocky swarm pieces.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_C8", "Why is a body that mainly orbits a planet not usually called a planet in this lesson?", ["because its main host is the planet, so it fits the moon or satellite role", "because planets orbit the Sun directly in this simplified family model", "because host body helps separate moons from planets"], "Use main-host classification language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["host", "orbit", "planet"], ["moon", "satellite", "not a planet", "planet orbits the Sun"])),
        ],
        "mastery": [
            mcq(f"{lesson_tag}_M7", "Which pair is matched correctly?", ["asteroid -> mostly rocky small body, comet -> icy small body", "asteroid -> icy visitor, comet -> rocky belt body", "moon -> central star, planet -> companion rider", "dwarf planet -> object that orbits nothing"], 0, "Keep rocky and icy small-body roles distinct.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_M8", "If an inner world completes more laps than an outer world in the same time, which one has the longer orbital period?", ["the outer world", "outer world", "the outer planet"], "Fewer laps in the same interval means a longer year.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["outer"], ["long", "period", "year", "lap", "orbit"])),
            mcq(f"{lesson_tag}_M9", "Why are classroom Solar System drawings often misleading if taken literally?", ["Because they compress huge distances and often cannot keep true size and true distance at once", "Because they show the exact size and distance perfectly", "Because scale never matters in astronomy", "Because the Sun is not really central"], 0, "Use compressed-scale language.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_M10", "Why is sorting Solar System bodies into planet, moon, asteroid, comet, and dwarf planet useful?", ["because the categories show different roles in one Sun-centered family", "because body type and main host give different jobs in the Solar System", "because not every orbiting body behaves or belongs in the same way"], "Use category-and-role language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["category", "sort", "different roles", "type"], ["family", "Solar System", "host", "orbit"])),
        ],
    }


def _f5_l6_extras(lesson_tag: str, skills: Sequence[str]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "diagnostic": [
            short(f"{lesson_tag}_D7", "If Earth rotates once per day, how many full rotations happen in 2 days?", ["2", "2 rotations", "two"], "Use one rotation per day.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["2", "two"])),
            mcq(f"{lesson_tag}_D8", "What real motion best explains the Sun seeming to cross the sky each day?", ["Earth's rotation", "Earth's yearly orbit alone", "the Moon blocking and unblocking the Sun", "the Sun orbiting Earth once each day"], 0, "Treat the daily sky sweep as apparent motion caused by spin.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_D9", "About how many days are in one Earth year?", ["365", "365 days", "about 365"], "Use the year as one full orbit around the Sun.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["365", "365 days", "about 365"])),
            mcq(f"{lesson_tag}_D10", "Why are many Solar System diagrams not true scale drawings?", ["Because real distances are huge and the sketch is heavily compressed", "Because the Sun is actually small enough to fit near Earth on the page", "Because scale models are impossible in science", "Because day and year are the same motion"], 0, "Use large-distance compression language.", skill_tags=[skills[0]]),
        ],
        "concept": [
            mcq(f"{lesson_tag}_C5", "Which pair correctly matches the motion and time?", ["one day -> one rotation, one year -> one orbit", "one day -> one orbit, one year -> one rotation", "one day -> one eclipse, one year -> one phase", "one day -> no motion, one year -> only apparent motion"], 0, "Keep daily and yearly motions separate.", skill_tags=[skills[2]]),
            short(f"{lesson_tag}_C6", "Why is apparent sky motion not the whole real-motion story?", ["because what we see from Earth is a viewpoint effect and different real motions cause day and year", "because appearance in the sky and the real motion causing it are not exactly the same thing", "because Earth's viewpoint can make one motion look different from the real arrangement"], "Use viewpoint-versus-real-motion language.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["view", "apparent", "seems", "appearance"], ["real motion", "rotation", "orbit", "cause"])),
            mcq(f"{lesson_tag}_C7", "In the same time interval, an inner world completes 6 laps while an outer world completes 1. Which statement is strongest?", ["The outer world has the longer orbital period", "The inner world has the longer orbital period", "Both worlds have the same year", "Lap count gives no clue about year length"], 0, "More laps in the same interval means a shorter period.", skill_tags=[skills[4]]),
            short(f"{lesson_tag}_C8", "If an outer world completes 1 lap while an inner world completes 6 in the same interval, which has the longer year?", ["the outer world", "outer world", "the outer planet"], "Fewer laps in the same interval means a longer year.", skill_tags=[skills[3]], acceptance_rules=acceptance_groups(["outer"], ["long", "year", "period", "orbit", "lap"])),
        ],
        "mastery": [
            mcq(f"{lesson_tag}_M7", "Which statement best corrects the claim 'the Sun really goes around Earth once each day'?", ["The daily sweep is an apparent motion that is better explained by Earth's rotation", "The claim is correct because the sky shows it directly", "The Moon causes the Sun to circle Earth", "A day is the same thing as a year"], 0, "Use apparent motion plus rotation.", skill_tags=[skills[1]]),
            short(f"{lesson_tag}_M8", "How is a day different from a year in the Earth-Sun story?", ["a day comes from rotation while a year comes from orbit", "day is one spin and year is one orbit", "rotation gives the day and orbit gives the year"], "Name both motions clearly.", skill_tags=[skills[0]], acceptance_rules=acceptance_groups(["day", "rotation", "spin"], ["year", "orbit"])),
            mcq(f"{lesson_tag}_M9", "Which scale-model claim is strongest?", ["A useful model can preserve the pattern while still compressing the real distances heavily", "A classroom sketch always keeps true size and true distance together", "Scale is irrelevant once planets are labeled", "Compression means the model is scientifically useless"], 0, "A model can still teach the pattern without being literal size-for-size and distance-for-distance.", skill_tags=[skills[0]]),
            short(f"{lesson_tag}_M10", "Why should daily sky appearance and yearly orbit timing not be collapsed into one motion story?", ["because day and year come from different motions and apparent motion is a viewpoint effect", "because rotation and orbit answer different timing questions", "because the sky can look as if something moves even when a different real motion causes it"], "Keep appearance separate from cause.", skill_tags=[skills[1]], acceptance_rules=acceptance_groups(["day", "rotation", "spin"], ["year", "orbit"], ["apparent", "view", "appearance", "look"])),
        ],
    }


def _f5_extra_question_banks(lesson_number: int, slug: str) -> Dict[str, List[Dict[str, Any]]]:
    lesson_tag = f"F5L{lesson_number}"
    skills = _skills(slug)
    if lesson_number == 1:
        return _f5_l1_extras(lesson_tag, skills)
    if lesson_number == 2:
        return _f5_l2_extras(lesson_tag, skills)
    if lesson_number == 3:
        return _f5_l3_extras(lesson_tag, skills)
    if lesson_number == 4:
        return _f5_l4_extras(lesson_tag, skills)
    if lesson_number == 5:
        return _f5_l5_extras(lesson_tag, skills)
    return _f5_l6_extras(lesson_tag, skills)


def _upgrade_f5_bundle(
    module_doc: Dict[str, Any],
    lesson_pairs: List[Tuple[str, Dict[str, Any]]],
    blueprints: Sequence[Dict[str, Any]],
) -> None:
    module_doc["content_version"] = "20260323_f5_lantern_ring_skycourt_v2"

    visual_specs = {
        1: {
            "concept": "astronomy_diagram",
            "template": "astronomy_diagram",
            "title": "Earth, Moon, and Sun in One Court",
            "purpose": "Show the Earth-Moon-Sun family as one linked skycourt system.",
            "caption": "Keep Earth, Moon, and Sun on one board so orbit, gravity, and scale stay connected.",
            "meta": {"diagram_type": "solar_court", "title": "Earth, Moon, and Sun in One Court", "subtitle": "One shared skycourt keeps the system linked."},
        },
        2: {
            "concept": "astronomy_diagram",
            "template": "astronomy_diagram",
            "title": "Spin Makes Day and Night",
            "purpose": "Show one rotating Earth moving a city between lit and dark halves.",
            "caption": "Day and night stay tied to spin when the lit half and city marker stay visible together.",
            "meta": {"diagram_type": "day_night_rotation", "title": "Spin Makes Day and Night", "subtitle": "Rotation carries places into and out of sunlight."},
        },
        3: {
            "concept": "astronomy_diagram",
            "template": "astronomy_diagram",
            "title": "Tilt Makes Seasons",
            "purpose": "Compare opposite orbit positions while the axis keeps one space direction.",
            "caption": "Tilt and sunlight angle stay readable when June and December share one seasons board.",
            "meta": {"diagram_type": "seasons_tilt", "title": "Tilt Makes Seasons", "subtitle": "Tilt plus orbit position changes the sunlight angle."},
        },
        4: {
            "concept": "astronomy_diagram",
            "template": "astronomy_diagram",
            "title": "Moon Phases and Eclipses",
            "purpose": "Keep the Moon half lit while the Earth viewpoint changes.",
            "caption": "Phases stay separate from eclipses when the lit half and the shadow line-up are not mixed.",
            "meta": {"diagram_type": "moon_phases", "title": "Moon Phases and Eclipses", "subtitle": "Viewing angle changes the phase; special alignment creates eclipses."},
        },
        5: {
            "concept": "space_astrophysics_diagram",
            "template": "space_astrophysics_diagram",
            "title": "Solar System Family",
            "purpose": "Show planets, moons, dwarf planets, asteroids, and comets in one Sun-centered family.",
            "caption": "Host body and body type stay clearer when the Solar System family is drawn with one central Sun.",
            "meta": {"diagram_type": "solar_system_overview", "title": "Solar System Family", "subtitle": "One Sun-centered family with several body types.", "highlighted_body": "Earth"},
        },
        6: {
            "concept": "astronomy_diagram",
            "template": "astronomy_diagram",
            "title": "Apparent Sky Motion and Scale",
            "purpose": "Compare inner and outer orbits while keeping day and year as different motions.",
            "caption": "Apparent motion, real motion, and orbital timing stay clearer when inner and outer laps are shown together.",
            "meta": {"diagram_type": "orbit_distance_period", "title": "Apparent Sky Motion and Scale", "subtitle": "Farther ring reach usually means a longer year lap."},
        },
    }

    why_updates = {
        1: (
            [
                "because one linked Earth-Moon-Sun system picture explains day-night, phases, eclipses, and orbit ideas together",
                "because the same shared system diagram helps explain several sky patterns at once",
                "because keeping Earth, Moon, and Sun on one board links the main sky patterns together",
            ],
            [["one", "shared", "linked", "same"], ["system", "board", "diagram", "picture"], ["day", "phase", "eclipse", "orbit", "pattern"]],
        ),
        2: (
            [
                "because Earth rotates so a place turns into sunlight and later turns away again",
                "because spin carries a place onto the lit half and then back into darkness",
                "because rotation changes whether a place faces the Sun",
            ],
            [["spin", "rotate", "rotation", "turn"], ["sunlight", "lit", "face the Sun", "day"], ["dark", "night", "away"]],
        ),
        3: (
            [
                "because the fixed tilt makes different hemispheres lean toward the Sun at different orbit positions",
                "because the same axis direction gives different sunlight angles as Earth moves around the Sun",
                "because tilt and orbit position change which hemisphere gets more direct sunlight",
            ],
            [["tilt", "axis", "lean"], ["sunlight", "direct", "angle", "toward the Sun"], ["hemisphere", "north", "south", "orbit"]],
        ),
        4: (
            [
                "because phases come from how we view the Moon's lit half while eclipses need a special shadow alignment",
                "because the Moon stays half lit and our view changes as it moves",
                "because phases are a viewing-angle story rather than an ordinary shadow story",
            ],
            [["view", "visible", "see", "viewing angle"], ["lit half", "sunlit", "half lit"], ["eclipse", "shadow", "special alignment", "rare"]],
        ),
        5: (
            [
                "because planets, moons, asteroids, comets, and dwarf planets play different roles in one Sun-centered family",
                "because body type and main host help keep Solar System categories clear",
                "because not every orbiting body belongs in the same category",
            ],
            [["category", "sort", "type", "role"], ["family", "Solar System", "Sun-centered"], ["host", "orbit", "planet", "moon", "comet", "asteroid", "dwarf"]],
        ),
        6: (
            [
                "because apparent sky motion is what we see, while rotation and orbit are the real motions causing day and year",
                "because day and year come from different motions even if the sky appearance can look simple",
                "because viewpoint can change how motion looks in the sky",
            ],
            [["apparent", "view", "appearance", "seems"], ["rotation", "spin", "day"], ["orbit", "year", "real motion"]],
        ),
    }

    compare_updates = {
        1: (
            [
                "an orbit is a gravity-guided path rather than a rigid track or rail",
                "orbit means pull plus motion making a curved path, not a built rail",
                "a track is fixed, but an orbit is produced by gravity and motion",
            ],
            [["gravity", "pull"], ["path", "route", "orbit"], ["track", "rail", "fixed"]],
        ),
        2: (
            [
                "rotation is Earth spinning on its axis while orbit is Earth traveling around the Sun",
                "spin turns Earth on its axis, but orbit carries Earth around the Sun",
                "rotation is local turning and orbit is the larger route around the Sun",
            ],
            [["spin", "rotation", "axis"], ["orbit", "around the Sun", "route"]],
        ),
        3: (
            [
                "distance alone is too weak because opposite hemispheres have opposite seasons at the same time",
                "tilt explains opposite hemispheres better than a simple near-far story",
                "the same Earth-Sun distance cannot by itself explain opposite seasonal patterns",
            ],
            [["opposite", "north", "south", "hemisphere"], ["distance", "tilt", "lean", "same time"]],
        ),
        4: (
            [
                "a phase is a normal view of the lit half while an eclipse is a special shadow alignment",
                "phases are viewing-angle changes, but eclipses are shadow events",
                "a phase is ordinary monthly geometry, while an eclipse needs a rare line-up",
            ],
            [["phase", "view", "lit half", "viewing"], ["eclipse", "shadow", "alignment", "rare"]],
        ),
        5: (
            [
                "a moon mainly orbits a larger world, while a planet or dwarf planet orbits the Sun directly in this simplified family model",
                "main host separates moons from Sun-orbiting worlds",
                "a moon's route is around a larger world instead of directly around the Sun",
            ],
            [["moon", "satellite"], ["planet", "Sun", "host", "orbit"]],
        ),
        6: (
            [
                "a day comes from rotation while a year comes from one orbit around the Sun",
                "day belongs to spin and year belongs to orbit",
                "rotation sets the day, but orbit sets the year",
            ],
            [["day", "rotation", "spin"], ["year", "orbit"]],
        ),
    }

    simulation_enrichments = {
        1: {
            "control": ("scale_cue", "Scale cue", "It keeps the Earth-Moon-Sun board from being mistaken for literal size."),
            "readout": ("system_link", "System link", "It reminds learners that Earth and Moon belong inside one Sun-lit system."),
        },
        2: {
            "control": ("sun_direction", "Sun direction", "It keeps the sunlight direction fixed while Earth rotates."),
            "readout": ("day_fraction", "Day fraction", "It shows how much of the spin cycle has carried the city through daylight."),
        },
        3: {
            "control": ("hemisphere_view", "Hemisphere view", "It compares north and south seasonal lean on the same board."),
            "readout": ("season_reason", "Season reason", "It states which hemisphere currently gets the more direct sunlight."),
        },
        4: {
            "control": ("earth_viewpoint", "Earth viewpoint", "It keeps the observer position visible while the Moon moves."),
            "readout": ("lit_half_rule", "Lit-half rule", "It keeps the always-half-lit Moon idea visible during every phase."),
        },
        5: {
            "control": ("neighborhood_rule", "Neighborhood rule", "It helps compare dwarf planets with planets during sorting."),
            "readout": ("host_clue", "Host clue", "It reports whether the selected body mainly belongs to the Sun or a larger world."),
        },
        6: {
            "control": ("view_mode", "View mode", "It switches between sky appearance language and real-motion language."),
            "readout": ("scale_warning", "Scale warning", "It keeps the compressed-model warning visible while day and year are compared."),
        },
    }

    for lesson_index, ((_, lesson), blueprint) in enumerate(zip(lesson_pairs, blueprints), start=1):
        slug = str(blueprint["slug"])
        contract = lesson["authoring_contract"]
        diagnostic = lesson["phases"]["diagnostic"]["items"]
        concept = lesson["phases"]["concept_reconstruction"]["capsules"][0]["checks"]
        mastery = lesson["phases"]["transfer"]["items"]
        simulation_contract = contract["simulation_contract"]

        why_answers, why_groups = why_updates[lesson_index]
        compare_answers, compare_groups = compare_updates[lesson_index]

        _update_short_item(diagnostic[1], accepted_answers=why_answers, phrase_groups=why_groups)
        _update_short_item(diagnostic[5], accepted_answers=compare_answers, phrase_groups=compare_groups)
        _update_short_item(concept[0], accepted_answers=why_answers, phrase_groups=why_groups)
        _update_short_item(mastery[1], accepted_answers=compare_answers, phrase_groups=compare_groups)
        _update_short_item(mastery[5], accepted_answers=why_answers, phrase_groups=why_groups)

        extras = _f5_extra_question_banks(lesson_index, slug)
        diagnostic.extend(deepcopy(extras["diagnostic"]))
        concept.extend(deepcopy(extras["concept"]))
        mastery.extend(deepcopy(extras["mastery"]))

        contract["assessment_bank_targets"] = {
            "diagnostic_pool_min": 10,
            "concept_gate_pool_min": 8,
            "mastery_pool_min": 10,
            "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
        }

        visual_spec = visual_specs[lesson_index]
        _set_visual_asset(
            lesson,
            asset_id=str(contract["visual_assets"][0]["asset_id"]),
            concept=str(visual_spec["concept"]),
            template=str(visual_spec["template"]),
            title=str(visual_spec["title"]),
            purpose=str(visual_spec["purpose"]),
            caption=str(visual_spec["caption"]),
            meta=deepcopy(dict(visual_spec["meta"])),
        )

        clarity_checks = [str(item) for item in contract.get("visual_clarity_checks") or []]
        extra_clip_check = "No picture labels, angle marks, or callouts clip on desktop or mobile layouts."
        if extra_clip_check not in clarity_checks:
            clarity_checks.append(extra_clip_check)
        contract["visual_clarity_checks"] = clarity_checks

        enrichment = simulation_enrichments[lesson_index]
        controls = [tuple(item) for item in simulation_contract.get("controls") or []]
        readouts = [tuple(item) for item in simulation_contract.get("readouts") or []]
        if len(controls) < 3:
            controls.append(enrichment["control"])
        if len(readouts) < 3:
            readouts.append(enrichment["readout"])
        simulation_contract["controls"] = controls
        simulation_contract["readouts"] = readouts


F5_CONTENT_VERSION = "20260323_f5_lantern_ring_skycourt_v2"
F5_MODULE_TITLE = "Observable Earth and Sky"
F5_MODULE_DESCRIPTION = "One lantern lights the court, Earth spins for day and night, tilted laps make seasons, and changing viewpoints explain phases, eclipses, and Solar System patterns."
F5_MASTERY_OUTCOMES = [
    "Explain day and night as Earth's rotation.",
    "Explain seasons with tilt and orbit position rather than simple distance claims.",
    "Explain phases and eclipses with Sun-Earth-Moon geometry.",
    "Describe the Solar System as a Sun-centered family shaped by gravity and scale.",
]

_F5_BLUEPRINTS = [
    auto_blueprint(
        slug="skycourt_family",
        title="Earth, Moon, and Sun in One Court",
        focus="Earth, Moon, and Sun stay on one shared skycourt instead of turning into disconnected facts",
        terms=[
            tw("Earth-Moon-Sun system", "The Earth-Moon-Sun system is the linked set of bodies whose positions explain many everyday sky patterns.", "It keeps day, month, and year ideas inside one connected model."),
            tw("Orbit", "An orbit is the curved path one body follows around another because of gravity.", "It links the sky pattern to motion rather than to an invisible rail."),
            tw("Gravity", "Gravity is the pull that keeps planets and moons on their routes.", "It is the reason the family stays organized."),
            tw("Scale", "Scale compares how large the bodies and distances are relative to one another.", "It stops the Solar System from being imagined as tightly packed."),
        ],
        core_concepts=[
            "The Earth, Moon, and Sun should be read as one linked system.",
            "Gravity keeps the family organized into orbits.",
            "Scale matters because real distances are much larger than simple diagrams suggest.",
        ],
        equation="orbit route <- gravity + sideways motion",
        meaning="A stable orbit needs both inward pull and forward motion.",
        units=["qualitative"],
        conditions="Use as a conceptual rule for introductory orbit reasoning.",
        summary="Earth, Moon, and Sun patterns make sense when the three bodies are kept on one gravity-linked board.",
        why_prompt="Why is it useful to keep Earth, Moon, and Sun in one system picture?",
        why_answer="Because the same positions help explain day-night, phases, eclipses, and orbit ideas together.",
        compare_prompt="How is an orbit different from a rigid track?",
        compare_answer="An orbit is a gravity-guided path, not a built rail in space.",
        apply_prompt="Which statement best fits the skycourt model?",
        apply_choices=[
            "Earth, Moon, and Sun should be explained as one linked system with gravity and motion.",
            "Each sky pattern should be memorized separately because the bodies are unrelated.",
            "Orbit paths are rigid lines painted into space.",
            "Scale does not matter because classroom diagrams show the exact distances.",
        ],
        apply_answer_index=0,
        sim_concept="sun_earth_moon_overview",
        sim_focus_prompt="Keep all three bodies visible while you explain the changing sky pattern.",
        sim_description="Explore one skycourt with Earth, Moon, and Sun on the same board.",
        sim_baseline="Start with the Sun at the center, Earth on its route, and the Moon around Earth.",
        sim_tasks=[
            "Trace the route of Earth around the Sun and the Moon around Earth.",
            "Compare what changes in the sky when the positions change.",
        ],
        sim_takeaway="The Earth-Moon-Sun family should stay on one shared board so the sky stories do not split apart.",
        sim_controls=[
            ("earth_position", "Earth route position", "It changes the viewing geometry."),
            ("moon_position", "Moon route position", "It changes which side of the Moon is seen from Earth."),
        ],
        sim_readouts=[
            ("system_view", "Shows Earth, Moon, and Sun on one board."),
            ("gravity_prompt", "Keeps the orbit story tied to pull and motion."),
        ],
        reflection_prompt="Why does one shared Earth-Moon-Sun diagram help more than three separate facts?",
        trap="Do not turn the three-body system into unrelated mini-topics.",
        analogy_check="What must stay on the same skycourt when you explain a new Earth-Moon-Sun pattern?",
        analogy_mapping=[
            "Lantern = Sun",
            "Court walker = Earth",
            "Companion lantern-ball = Moon",
            "Ring routes = orbits",
        ],
        visual_concept="skycourt_family",
    ),
    auto_blueprint(
        slug="day_night_spin",
        title="Spin Makes Day and Night",
        focus="Earth's spin carries places into and out of sunlight",
        terms=[
            tw("Rotation", "Rotation is the turning of a body about its own axis.", "It is the direct cause of day and night."),
            tw("Axis", "An axis is the imaginary line about which a body rotates.", "It gives the spin and tilt story a fixed reference."),
            tw("Day side", "The day side is the half of Earth facing the Sun.", "It shows that daylight is a geometry story."),
            tw("Night side", "The night side is the half turned away from the Sun.", "It explains darkness without needing Earth to finish an orbit."),
        ],
        core_concepts=[
            "Day and night come from rotation, not yearly orbit.",
            "At any moment, one half of Earth is lit and the other half is dark.",
            "A place changes from day to night because Earth spins.",
        ],
        equation="one full spin ≈ 24 h",
        meaning="A full rotation gives the day-night cycle.",
        units=["hours"],
        conditions="Use for the introductory Earth-rotation model.",
        summary="Day and night happen because Earth rotates, carrying places into and out of sunlight.",
        why_prompt="Why does rotation explain day and night better than revolution around the Sun?",
        why_answer="Because a place becomes lit or dark as Earth turns, even before Earth completes a large orbit.",
        compare_prompt="How is rotation different from orbit in the skycourt model?",
        compare_answer="Rotation is Earth turning on its axis, while orbit is Earth traveling around the Sun.",
        apply_prompt="Which statement best explains daylight change at one city?",
        apply_choices=[
            "The city moves from the lit half to the dark half as Earth spins.",
            "The city moves closer to the Sun every morning.",
            "The Moon blocks the Sun each night.",
            "Earth must complete a full year before day can change to night.",
        ],
        apply_answer_index=0,
        sim_concept="earth_rotation_day_night",
        sim_focus_prompt="Track one city marker while Earth spins.",
        sim_description="Watch one city rotate through the lit and dark halves of Earth.",
        sim_baseline="Start with the city just inside the dark half of Earth.",
        sim_tasks=[
            "Rotate Earth until the city crosses into sunlight.",
            "Keep the Sun fixed and compare how the lit half stays in place while Earth turns.",
        ],
        sim_takeaway="Day and night become clearer when one city marker is followed through a full spin.",
        sim_controls=[
            ("rotation_angle", "Earth spin angle", "It controls where the city sits relative to sunlight."),
            ("city_marker", "City marker", "It gives one fixed place to track."),
        ],
        sim_readouts=[
            ("lit_status", "Shows whether the city is on the day or night side."),
            ("spin_fraction", "Shows how far through one rotation Earth has turned."),
        ],
        reflection_prompt="Why is one rotating Earth enough to explain day and night?",
        trap="Do not switch day-night into an orbit-distance story.",
        analogy_check="What stays fixed while Earth spins through day and night?",
        analogy_mapping=[
            "Lantern = Sunlight source",
            "Spinning court ball = Earth",
            "Axis rod = Earth's axis",
            "Lit half = day side",
        ],
        visual_concept="day_night_spin",
    ),
    auto_blueprint(
        slug="season_tilt",
        title="Tilt Makes Seasons",
        focus="Earth keeps the same axis direction in space while different orbit positions change sunlight angle",
        terms=[
            tw("Tilt", "Tilt is the leaning of Earth's axis relative to its orbit.", "It is the main cause of the seasonal difference."),
            tw("Sunlight angle", "Sunlight angle is the angle at which sunlight reaches a surface.", "More direct sunlight usually gives stronger heating."),
            tw("Hemisphere", "A hemisphere is one half of Earth divided by the equator.", "Opposite hemispheres experience opposite season patterns."),
            tw("Solstice", "A solstice is a point in the year when one hemisphere leans most toward or away from the Sun.", "It helps anchor the seasonal geometry."),
        ],
        core_concepts=[
            "Seasons come from tilt and sunlight angle, not from Earth simply being nearer or farther from the Sun.",
            "Opposite hemispheres experience opposite seasonal lean.",
            "The axis direction stays roughly fixed in space during the orbit.",
        ],
        equation="season pattern <- tilt + orbit position",
        meaning="Season differences are set by fixed tilt combined with where Earth is on its orbit.",
        units=["qualitative"],
        conditions="Use for introductory season geometry.",
        summary="Seasons are caused by Earth's tilted axis keeping the same space direction while Earth moves around the Sun.",
        why_prompt="Why is fixed axis direction important in the seasons lesson?",
        why_answer="Because the same tilt points different hemispheres toward the Sun at different orbit positions, changing sunlight angle.",
        compare_prompt="Why is the seasons story not just a distance-from-the-Sun story?",
        compare_answer="Because opposite hemispheres experience opposite seasons at the same time, which distance alone cannot explain.",
        apply_prompt="Which statement best explains the seasonal switch?",
        apply_choices=[
            "Tilt and orbit position change which hemisphere leans toward the Sun.",
            "Earth gets summer only when it is much closer to the Sun.",
            "The Moon blocks sunlight more often in winter.",
            "The axis flips direction every half year.",
        ],
        apply_answer_index=0,
        sim_concept="season_tilt_compare",
        sim_focus_prompt="Compare June and December while keeping the axis direction fixed.",
        sim_description="Use a June-December comparison board to keep tilt and sunlight angle visible together.",
        sim_baseline="Start with the same axis direction for both orbital positions.",
        sim_tasks=[
            "Move Earth halfway around its orbit without rotating the axis direction in space.",
            "Compare which hemisphere leans toward the Sun in each position.",
        ],
        sim_takeaway="Seasons stay readable when tilt and orbit position are kept together on one board.",
        sim_controls=[
            ("orbit_position", "Orbit position", "It changes which hemisphere leans toward the Sun."),
            ("tilt_angle", "Axis tilt", "It controls the seasonal geometry."),
        ],
        sim_readouts=[
            ("hemisphere_focus", "Shows which hemisphere leans toward the Sun."),
            ("sunlight_angle", "Shows whether the sunlight is more direct or less direct."),
        ],
        reflection_prompt="Why do opposite hemispheres have opposite seasons at the same time?",
        trap="Do not replace the tilt story with a simple near-far distance claim.",
        analogy_check="Which two things must be read together to explain seasons well?",
        analogy_mapping=[
            "Lantern = Sun",
            "Tilt rod = Earth's axis",
            "Opposite sides of the court = opposite orbital positions",
            "Direct beam angle = sunlight angle",
        ],
        visual_concept="season_tilt",
    ),
    auto_blueprint(
        slug="moon_phases_eclipses",
        title="Moon Phases and Eclipses",
        focus="the Moon stays half lit while our viewing angle changes, and eclipses are special alignment cases",
        terms=[
            tw("Moon phase", "A Moon phase is the visible shape of the lit part of the Moon seen from Earth.", "It separates the regular monthly pattern from rare eclipse events."),
            tw("Eclipse", "An eclipse is a special alignment where one body enters another's shadow or blocks its light.", "It is not the everyday reason for phases."),
            tw("Shadow", "A shadow is the region where light is blocked.", "It matters in eclipses, not in ordinary phases."),
            tw("Viewing angle", "Viewing angle is the line of sight from Earth to the lit half of the Moon.", "It explains why the visible phase changes."),
        ],
        core_concepts=[
            "The Moon is always half lit by the Sun.",
            "Phases come from changing viewpoint, not Earth's shadow.",
            "Eclipses are special alignment events, not the monthly phase rule.",
        ],
        equation="visible phase <- lit half + viewing angle",
        meaning="Moon phases depend on how much of the lit half is visible from Earth.",
        units=["qualitative"],
        conditions="Use for introductory Moon phase reasoning.",
        summary="Moon phases come from our changing view of the Moon's lit half, while eclipses need a special shadow alignment.",
        why_prompt="Why are Moon phases not just small eclipses every month?",
        why_answer="Because phases come from how we view the Moon's lit half, while eclipses need a rare shadow alignment.",
        compare_prompt="How is a Moon phase different from an eclipse?",
        compare_answer="A phase is a normal viewing-angle change, while an eclipse is a special shadow event.",
        apply_prompt="Which statement best explains a crescent Moon?",
        apply_choices=[
            "We can see only a small part of the Moon's lit half from Earth.",
            "Earth blocks most of the Sun's light from reaching the Moon every month.",
            "The Moon stops reflecting sunlight during part of its orbit.",
            "The lit half of the Moon disappears and then grows back.",
        ],
        apply_answer_index=0,
        sim_concept="moon_phase_geometry",
        sim_focus_prompt="Keep the lit half and the Earth viewpoint visible at the same time.",
        sim_description="Compare normal phases and rare eclipse alignments on one Moon-geometry board.",
        sim_baseline="Start with the Moon half lit and Earth viewing from the side.",
        sim_tasks=[
            "Move the Moon around Earth and watch how the visible lit fraction changes.",
            "Line up a special straight-shadow case and compare it with the normal phase pattern.",
        ],
        sim_takeaway="Phases and eclipses stay distinct when the lit half and the shadow alignment are kept separate.",
        sim_controls=[
            ("moon_position", "Moon orbit position", "It changes the viewing angle."),
            ("alignment_mode", "Alignment mode", "It compares normal phases with eclipse geometry."),
        ],
        sim_readouts=[
            ("visible_fraction", "Shows how much of the lit half is visible from Earth."),
            ("shadow_event", "Flags when an actual eclipse alignment appears."),
        ],
        reflection_prompt="Why is Earth's shadow not the ordinary explanation for Moon phases?",
        trap="Do not use Earth's shadow to explain every Moon phase.",
        analogy_check="What stays constant about the Moon even while its phase changes?",
        analogy_mapping=[
            "Lantern = Sun",
            "Court watcher = Earth observer",
            "Moon ball = Moon",
            "Special shadow line-up = eclipse",
        ],
        visual_concept="moon_phases",
    ),
    auto_blueprint(
        slug="solar_system_overview",
        title="Solar System Family",
        focus="the Solar System is one Sun-centered family with different body types and very large scale differences",
        terms=[
            tw("Planet", "A planet is a major body that orbits the Sun and has cleared much of its orbital neighborhood in the simplified school model.", "It keeps planets separate from other Sun-orbiting bodies."),
            tw("Moon", "A moon is a natural satellite that mainly orbits a planet or dwarf planet.", "It stops every orbiting body from being called a planet."),
            tw("Asteroid", "An asteroid is a mostly rocky small body orbiting the Sun.", "It helps separate rocky debris from icy visitors."),
            tw("Comet", "A comet is an icy small body that can develop a glowing coma or tail when near the Sun.", "It gives the Solar System a different small-body category from asteroids."),
        ],
        core_concepts=[
            "The Solar System contains several body types, not only planets.",
            "Moons mainly orbit larger worlds rather than the Sun directly.",
            "Scale in the Solar System is much larger than a small classroom sketch suggests.",
        ],
        equation="Solar System = Sun + planets + moons + smaller bodies",
        meaning="The Solar System is an organized family around the Sun, not one single object type.",
        units=["qualitative"],
        conditions="Use for introductory classification and system overview.",
        summary="The Solar System is a Sun-centered family containing planets, moons, asteroids, comets, and other bodies.",
        why_prompt="Why is it useful to sort Solar System bodies into categories?",
        why_answer="Because planets, moons, asteroids, and comets belong to different roles in the Sun-centered family.",
        compare_prompt="How is a moon different from a planet in the Solar System story?",
        compare_answer="A moon mainly orbits a larger world, while a planet orbits the Sun directly.",
        apply_prompt="Which statement best fits Solar System organization?",
        apply_choices=[
            "Not every body orbiting in the Solar System is a planet.",
            "Everything near the Sun should be called a star.",
            "Moons and planets are the same category because both can move in orbit.",
            "Scale does not matter once the Sun is drawn in the middle.",
        ],
        apply_answer_index=0,
        sim_concept="solar_system_sorter",
        sim_focus_prompt="Keep host body and body type visible during sorting.",
        sim_description="Sort Solar System bodies while keeping the Sun-centered family readable.",
        sim_baseline="Start with one planet, one moon, one asteroid, and one comet on the board.",
        sim_tasks=[
            "Sort bodies by what they orbit and by what type of body they are.",
            "Compare one planet with one moon and one asteroid with one comet.",
        ],
        sim_takeaway="Solar System classification gets stronger when host body and body type are read together.",
        sim_controls=[
            ("body_type", "Body type", "It changes the classification clues."),
            ("host_body", "Main host", "It helps separate planets from moons."),
        ],
        sim_readouts=[
            ("classification", "Shows the current Solar System category."),
            ("host_readout", "Shows what the selected body mainly belongs to."),
        ],
        reflection_prompt="Why should moons, planets, asteroids, and comets not all be grouped into one category?",
        trap="Do not turn every Sun-orbiting body into a planet.",
        analogy_check="What two clues should you read together when you classify a Solar System body?",
        analogy_mapping=[
            "Central lantern = Sun",
            "Court family = Solar System",
            "Companion rider = moon",
            "Icy visitor = comet",
        ],
        visual_concept="solar_system_family",
    ),
    auto_blueprint(
        slug="sky_motion_scale",
        title="Apparent Sky Motion and Scale",
        focus="daily sky motion and orbital timing must be read alongside large Earth-Sun-planet scale differences",
        terms=[
            tw("Apparent motion", "Apparent motion is how an object seems to move in the sky from our viewpoint.", "It helps separate sky appearance from the real motion causing it."),
            tw("Year", "A year is the time taken for Earth to complete one orbit around the Sun.", "It links orbit to a time pattern different from daily rotation."),
            tw("Satellite", "A satellite is any body that orbits another body.", "It keeps natural and artificial orbit stories grounded in gravity."),
            tw("Scale model", "A scale model keeps relative size or distance by shrinking everything with one chosen ratio.", "It shows why most Solar System drawings are not true-size and true-distance at once."),
        ],
        core_concepts=[
            "Some sky motion is apparent from Earth's viewpoint rather than literal wandering across a fixed dome.",
            "A day and a year come from different motions.",
            "Solar System scale is so large that classroom diagrams are heavily compressed.",
        ],
        equation="one full orbit ≈ 365 d",
        meaning="A year comes from Earth's orbit, not from one rotation.",
        units=["days"],
        conditions="Use for introductory Earth-Sun timing.",
        summary="Apparent sky motion, orbit timing, and Solar System scale must be kept together so day and year do not collapse into one motion story.",
        why_prompt="Why is apparent sky motion not enough by itself to explain the real motion of Earth and the Sun?",
        why_answer="Because the sky appearance comes from our viewpoint, while day and year are caused by different real motions.",
        compare_prompt="How is a day different from a year in the Earth-Sun story?",
        compare_answer="A day comes from Earth's rotation, while a year comes from Earth's orbit around the Sun.",
        apply_prompt="Which statement best keeps scale and motion clear?",
        apply_choices=[
            "A classroom sketch can show the pattern, but the real distances are far larger than the drawing suggests.",
            "If the Sun seems to move across the sky, the Sun must orbit Earth once each day.",
            "A day and a year are two names for the same motion.",
            "Orbit timing can be read without thinking about viewpoint or scale.",
        ],
        apply_answer_index=0,
        sim_concept="sky_motion_scale",
        sim_focus_prompt="Compare apparent motion, real motion, and scale on the same board.",
        sim_description="Use one board to compare daily sky appearance, yearly orbit timing, and compressed Solar System scale.",
        sim_baseline="Start with one day marker, one year marker, and a compressed scale bar.",
        sim_tasks=[
            "Compare what seems to move across the sky in one day with what really rotates.",
            "Switch from the day marker to the year marker and compare the timescales.",
        ],
        sim_takeaway="Sky motion becomes less confusing when apparent motion, real motion, and scale are kept in separate slots.",
        sim_controls=[
            ("time_mode", "Time mode", "It switches between day-scale and year-scale patterns."),
            ("scale_bar", "Scale bar", "It reminds students that real distances are huge."),
        ],
        sim_readouts=[
            ("motion_story", "Shows whether the board is describing apparent or real motion."),
            ("time_scale", "Shows whether the focus is a day or a year."),
        ],
        reflection_prompt="Why is the visible sky pattern not the whole real-motion story?",
        trap="Do not mistake apparent motion in the sky for the full real motion causing it.",
        analogy_check="What must stay separate when you compare daily sky appearance with yearly orbit timing?",
        analogy_mapping=[
            "Skycourt dome = observed sky",
            "Spinning court ball = Earth's rotation",
            "Ring route = yearly orbit",
            "Compressed map = scale model",
        ],
        visual_concept="sky_motion_scale",
    ),
]

F5_MODULE_DOC, F5_LESSONS, F5_SIM_LABS = _build_generated_bundle(
    module_id="F5",
    module_title=F5_MODULE_TITLE,
    content_version=F5_CONTENT_VERSION,
    sequence=5,
    level="foundations",
    estimated_minutes=75,
    model_name="Lantern-Ring Skycourt Model",
    module_description=F5_MODULE_DESCRIPTION,
    mastery_outcomes=F5_MASTERY_OUTCOMES,
    lessons=_F5_BLUEPRINTS,
)
_upgrade_f5_bundle(F5_MODULE_DOC, F5_LESSONS, _F5_BLUEPRINTS)


M9_CONTENT_VERSION = "20260323_m9_carrier_switchyard_v1"
M9_MODULE_TITLE = "Electrical Quantities and Circuits"
M9_MODULE_DESCRIPTION = "Carriers circulate around boosted loops, one-lane chains and branch decks set the network behaviour, and power and safety depend on how the loop is organized."
M9_MASTERY_OUTCOMES = [
    "Explain charge as the conserved carrier quantity and current as charge flow rate.",
    "Explain voltage as energy transferred per unit charge and resistance as a route property.",
    "Use Ohm's law conceptually for ohmic cases.",
    "Distinguish series and parallel behaviour and connect power and safety to current, voltage, and resistance.",
]

_M9_BLUEPRINTS = [
    auto_blueprint(
        slug="charge_carriers",
        title="Charge Carriers in a Closed Loop",
        focus="the moving thing is the carrier, and a complete loop is required before steady current can circulate",
        terms=[
            tw("Charge", "Charge is the conserved carrier quantity moving around the circuit.", "It is the moving stuff, not the same thing as current."),
            tw("Carrier", "A carrier is a moving charged particle in the circuit model.", "It turns abstract charge into something trackable."),
            tw("Complete circuit", "A complete circuit is an unbroken loop that allows carriers to circulate.", "Without it, steady current cannot continue."),
            tw("Conservation", "Conservation means the quantity is accounted for rather than being used up.", "It protects the idea that charge keeps circulating."),
        ],
        core_concepts=[
            "Charge is the moving carrier quantity.",
            "A complete loop is needed for steady current.",
            "Charge is not used up by the first component.",
        ],
        equation="charge is conserved in the loop",
        meaning="The same carrier quantity keeps circulating around a complete circuit.",
        units=["qualitative"],
        conditions="Use as the foundational charge model before rate and voltage relations.",
        summary="A circuit works as a loop of moving charge carriers rather than as a pipe that uses current up.",
        why_prompt="Why does a broken loop stop the current even though charge still exists in the circuit parts?",
        why_answer="Because the carriers need one complete route to keep circulating steadily past every point.",
        compare_prompt="How is charge different from current in the loop model?",
        compare_answer="Charge is the carrier quantity itself, while current is the rate at which that charge passes a point.",
        apply_prompt="Which statement best matches the carrier-loop idea?",
        apply_choices=[
            "The same carriers circulate around a complete loop instead of being used up.",
            "The battery pours a fixed amount of current into the first component until it runs out.",
            "Charge disappears after it passes through one device.",
            "A loop can stay open and still carry the same steady current.",
        ],
        apply_answer_index=0,
        sim_concept="charge_carrier_loop",
        sim_focus_prompt="Track the carriers and the loop status separately.",
        sim_description="Watch carrier tokens circulate only when the loop is complete.",
        sim_baseline="Start with a closed loop and visible carrier tokens.",
        sim_tasks=[
            "Open the loop and compare what happens to carrier circulation.",
            "Close the loop again and explain why the same carriers can pass a checkpoint repeatedly.",
        ],
        sim_takeaway="Charge and complete-loop reasoning should come before current formulas.",
        sim_controls=[
            ("switch_state", "Loop switch", "It decides whether the route is complete."),
            ("carrier_count", "Carrier count", "It lets students compare amount with flow rate later."),
        ],
        sim_readouts=[
            ("loop_status", "Shows whether the circuit is complete or broken."),
            ("carrier_flow", "Shows whether carriers are circulating steadily."),
        ],
        reflection_prompt="Why should a circuit be described as circulating charge rather than as 'electricity getting used up'?",
        trap="Do not treat the battery as a tank of current that gets poured out.",
        analogy_check="What has to exist before the carriers can keep circulating?",
        analogy_mapping=[
            "Carrier tokens = charge",
            "Closed track = complete circuit",
            "Checkpoint = current-measurement point",
            "Lift station = source",
        ],
        visual_concept="carrier_loop",
    ),
    auto_blueprint(
        slug="current_rate",
        title="Current as Checkpoint Rate",
        focus="current counts how much charge passes a point each second",
        terms=[
            tw("Current", "Current is the rate of charge flow past a point.", "It tells how fast charge passes a checkpoint, not how much charge exists overall."),
            tw("Ampere", "An ampere is one coulomb of charge passing a point each second.", "It links the unit of current to charge and time."),
            tw("Coulomb", "A coulomb is the unit of electric charge.", "It is the counted carrier quantity inside the current definition."),
            tw("Rate", "A rate compares one quantity with time.", "It stops current from being confused with total amount."),
        ],
        core_concepts=[
            "Current is a rate, not an amount.",
            "The same amount of charge can give different currents if the time changes.",
            "An ampere means coulombs per second.",
        ],
        equation="I = Q / t",
        meaning="Current equals charge divided by time.",
        units=["A", "C", "s"],
        conditions="Use for steady or average charge flow through a checkpoint.",
        summary="Current tells how quickly charge passes a chosen point in the circuit.",
        why_prompt="Why can two loops contain charge but have different currents?",
        why_answer="Because current depends on how much charge passes each second, not only on how much charge is present.",
        compare_prompt="How is 1 A different from 1 C?",
        compare_answer="1 A is a rate of 1 coulomb each second, while 1 C is just an amount of charge.",
        apply_prompt="What current flows if 12 C passes a point in 3 s?",
        apply_choices=["4 A", "36 A", "9 A", "0.25 A"],
        apply_answer_index=0,
        sim_concept="current_checkpoint_rate",
        sim_focus_prompt="Compare charge amount and charge-per-second on one board.",
        sim_description="Use a checkpoint meter to read current as charge per second.",
        sim_baseline="Start with 12 C passing the checkpoint in 3 s.",
        sim_tasks=[
            "Keep charge fixed and change the time to compare the new current.",
            "Keep the time fixed and change the charge passing the checkpoint.",
        ],
        sim_takeaway="Current becomes clearer when it is always read as charge per second.",
        sim_controls=[
            ("charge_amount", "Charge passing the checkpoint", "It changes the numerator in the rate."),
            ("time_interval", "Time interval", "It changes the denominator in the rate."),
        ],
        sim_readouts=[
            ("current_value", "Shows the checkpoint rate in amperes."),
            ("rate_story", "Explains whether the change came from charge, time, or both."),
        ],
        reflection_prompt="Why is current better described as 'charge per second' than as 'amount of electricity'?",
        trap="Do not collapse current into total charge.",
        analogy_check="What two quantities must you compare to define current?",
        analogy_mapping=[
            "Checkpoint = ammeter point",
            "Carriers per second = current",
            "Charge pile = total charge",
            "Clock = time interval",
        ],
        visual_concept="current_rate",
    ),
    auto_blueprint(
        slug="voltage_boost",
        title="Voltage as Boost per Carrier",
        focus="the source gives each carrier an energy boost, which is voltage",
        terms=[
            tw("Voltage", "Voltage is the energy transferred per unit charge.", "It describes what each carrier gets, not how many carriers pass."),
            tw("Potential difference", "Potential difference is another name for voltage between two points.", "It reminds students that voltage is a difference, not a pile."),
            tw("Joule", "A joule is a unit of energy.", "It is the energy part of the voltage story."),
            tw("Energy per charge", "Energy per charge compares how much energy each unit of charge receives.", "It is the core meaning of voltage."),
        ],
        core_concepts=[
            "Voltage tells how much energy each charge gets.",
            "Voltage is not the same thing as current.",
            "A battery provides an energy-per-charge boost around the loop.",
        ],
        equation="V = ΔE / Q",
        meaning="Voltage equals energy transferred per unit charge.",
        units=["V", "J", "C"],
        conditions="Use when comparing energy change for charge moving between two points.",
        summary="Voltage is the energy-per-charge boost supplied between two points in the circuit.",
        why_prompt="Why is voltage not just 'more current'?",
        why_answer="Because voltage describes energy per charge, while current describes charge flow rate.",
        compare_prompt="How is voltage different from total energy stored in the battery?",
        compare_answer="Voltage is the energy per charge, not the whole energy store by itself.",
        apply_prompt="What voltage is supplied if 18 J is transferred to 3 C of charge?",
        apply_choices=["6 V", "15 V", "54 V", "0.17 V"],
        apply_answer_index=0,
        sim_concept="voltage_boost",
        sim_focus_prompt="Keep the energy-per-carrier story visible.",
        sim_description="Compare different lift-station boosts for the same carrier tokens.",
        sim_baseline="Start with a 6 J per C boost at the source.",
        sim_tasks=[
            "Double the boost per carrier and compare the voltage.",
            "Hold the voltage fixed and explain why current could still change in a different loop.",
        ],
        sim_takeaway="Voltage stays clearer when it is treated as energy per charge rather than as a stronger current label.",
        sim_controls=[
            ("boost_per_charge", "Boost per carrier", "It directly sets the voltage."),
            ("source_setting", "Source setting", "It changes the energy gain at the lift station."),
        ],
        sim_readouts=[
            ("voltage_value", "Shows the current source voltage."),
            ("energy_story", "Explains how much energy each carrier receives."),
        ],
        reflection_prompt="Why is energy per charge the key phrase in the voltage definition?",
        trap="Do not call voltage 'the amount of current in the battery.'",
        analogy_check="What does the source give to each carrier?",
        analogy_mapping=[
            "Lift station = battery or cell",
            "Boost per token = voltage",
            "Carrier token = charge",
            "Energy ledger = joules gained and lost",
        ],
        visual_concept="voltage_boost",
    ),
    auto_blueprint(
        slug="resistance_route",
        title="Resistance as Route Drag",
        focus="resistance is a property of the path that limits current for a given voltage",
        terms=[
            tw("Resistance", "Resistance is how strongly a path limits current for a given voltage.", "It belongs to the route, not to the battery."),
            tw("Material", "Material is what the conductor is made from.", "Different materials can oppose carrier motion differently."),
            tw("Length", "Length is how long the current path is.", "Longer paths usually give larger resistance."),
            tw("Cross-sectional area", "Cross-sectional area is how wide the conductor is across its cut surface.", "Wider paths usually reduce resistance."),
        ],
        core_concepts=[
            "Resistance is a route property.",
            "Longer routes usually increase resistance.",
            "Wider routes usually reduce resistance.",
        ],
        equation="R = V / I",
        meaning="Resistance is the ratio of voltage to current for an ohmic case.",
        units=["ohm", "V", "A"],
        conditions="Use for simple ohmic conductor reasoning.",
        summary="Resistance is the path's opposition to current, shaped by material and geometry.",
        why_prompt="Why should resistance be described as a route property rather than a battery property?",
        why_answer="Because changing the path material, length, or width changes the current even with the same source.",
        compare_prompt="How does a longer wire usually differ from a wider wire in resistance?",
        compare_answer="A longer wire usually has more resistance, while a wider wire usually has less resistance.",
        apply_prompt="Which change usually increases the resistance of one uniform wire?",
        apply_choices=[
            "Making the wire longer while keeping the material and width the same.",
            "Making the wire wider while keeping the material the same.",
            "Replacing the wire with a lower-resistance material.",
            "Shortening the same wire.",
        ],
        apply_answer_index=0,
        sim_concept="route_drag",
        sim_focus_prompt="Compare material and geometry changes on one current path.",
        sim_description="Use a drag board to compare long, short, wide, and narrow current routes.",
        sim_baseline="Start with one medium-length, medium-width route.",
        sim_tasks=[
            "Increase the route length while holding width fixed.",
            "Increase the route width while holding length fixed.",
        ],
        sim_takeaway="Resistance makes more sense when it stays attached to the route instead of the source.",
        sim_controls=[
            ("route_length", "Route length", "Longer paths usually increase resistance."),
            ("route_width", "Route width", "Wider paths usually reduce resistance."),
        ],
        sim_readouts=[
            ("drag_index", "Shows the relative route drag."),
            ("current_change", "Shows the effect on current for the same source."),
        ],
        reflection_prompt="Why can the same battery give a different current in a different wire path?",
        trap="Do not treat resistance as something the battery decides by itself.",
        analogy_check="What part of the loop is resistance attached to?",
        analogy_mapping=[
            "Route drag = resistance",
            "Narrow lane = smaller cross-sectional area",
            "Long lane = greater length",
            "Smooth or rough surface = material difference",
        ],
        visual_concept="resistance_route",
    ),
    auto_blueprint(
        slug="ohms_rule",
        title="Ohm's Law on an Ohmic Route",
        focus="for an ohmic route, current depends jointly on voltage and resistance",
        terms=[
            tw("Ohm's law", "Ohm's law says that for an ohmic conductor, current is proportional to voltage when temperature and resistance stay fixed.", "It gives a simple rule for many circuit calculations."),
            tw("Ohmic", "Ohmic describes a conductor or component that follows the simple proportional current-voltage rule.", "It warns students that not every component behaves this way."),
            tw("Proportional", "Proportional means one quantity changes by the same factor as another.", "It explains the straight-line current-voltage relation."),
            tw("Gradient", "Gradient is the steepness of a graph line.", "It helps interpret resistance on I-V or V-I graphs."),
        ],
        core_concepts=[
            "At fixed resistance, larger voltage gives larger current.",
            "At fixed voltage, larger resistance gives smaller current.",
            "Ohm's law is a simple proportional rule for ohmic components.",
        ],
        equation="I = V / R",
        meaning="Current equals voltage divided by resistance for an ohmic route.",
        units=["A", "V", "ohm"],
        conditions="Use for ohmic conductors under conditions where resistance stays constant.",
        summary="Ohm's law links current, voltage, and resistance for simple ohmic cases.",
        why_prompt="Why does doubling the voltage double the current only when the resistance stays fixed?",
        why_answer="Because Ohm's law compares current with voltage through one unchanged resistance value.",
        compare_prompt="How is an ohmic route different from a route that changes behaviour as conditions change?",
        compare_answer="An ohmic route keeps a simple proportional current-voltage rule, while a changing route does not keep the same resistance rule.",
        apply_prompt="What current flows through a 6 ohm resistor on 12 V?",
        apply_choices=["2 A", "18 A", "0.5 A", "72 A"],
        apply_answer_index=0,
        sim_concept="ohms_law",
        sim_focus_prompt="Hold one quantity fixed while you change the other.",
        sim_description="Compare voltage-current changes on an ohmic route.",
        sim_baseline="Start with 6 V across a 3 ohm route.",
        sim_tasks=[
            "Double the voltage while keeping the route the same.",
            "Double the resistance while keeping the voltage the same.",
        ],
        sim_takeaway="Ohm's law is easiest to trust when one quantity is held fixed while the other changes.",
        sim_controls=[
            ("voltage_setting", "Voltage setting", "It changes the source boost."),
            ("resistance_setting", "Resistance setting", "It changes the route drag."),
        ],
        sim_readouts=[
            ("current_value", "Shows the resulting current."),
            ("proportional_story", "Explains whether the change came from voltage or resistance."),
        ],
        reflection_prompt="Why is 'hold the resistance fixed' an important part of Ohm's law reasoning?",
        trap="Do not use Ohm's law as if every component keeps the same resistance in every condition.",
        analogy_check="Which two control changes reveal the Ohm's law pattern most clearly?",
        analogy_mapping=[
            "Boost-per-token = voltage",
            "Route drag = resistance",
            "Checkpoint rate = current",
            "Simple rate rule = Ohm's law",
        ],
        visual_concept="ohms_law",
    ),
    auto_blueprint(
        slug="circuit_networks",
        title="Series and Parallel Circuit Behaviour",
        focus="one-lane chains keep one current, while branch decks share voltage and split current",
        terms=[
            tw("Series circuit", "A series circuit has one path, so the same current passes through each component in the chain.", "It explains why one break stops the whole chain."),
            tw("Parallel circuit", "A parallel circuit has branches connected between the same two junctions.", "It explains why branches share voltage while current can split."),
            tw("Power", "Power is the rate of electrical energy transfer.", "It links brightness and heating to what happens each second in a component."),
            tw("Fuse", "A fuse is a safety device that melts and opens the circuit if the current becomes too large.", "It shows how protection depends on current, not only on voltage labels."),
        ],
        core_concepts=[
            "Series circuits have one common current path.",
            "Parallel branches share the same potential difference.",
            "Power and safety both depend on how current and voltage behave in the network.",
        ],
        equation="P = IV",
        meaning="Power equals current multiplied by voltage.",
        units=["W", "A", "V"],
        conditions="Use for electrical power in circuit components.",
        summary="Circuits are organized networks where series and parallel rules shape current, voltage, power, and safety.",
        why_prompt="Why can two parallel branches have different currents but the same voltage?",
        why_answer="Because both branches connect across the same two junctions, so they share the same potential difference even if their resistances differ.",
        compare_prompt="How is a series circuit different from a parallel circuit?",
        compare_answer="A series circuit has one path with the same current everywhere, while a parallel circuit has branches that share voltage and split current.",
        apply_prompt="Which statement best matches circuit safety and network behaviour?",
        apply_choices=[
            "A fuse protects by opening the circuit when the current becomes dangerously large.",
            "Adding a parallel branch always increases total resistance and lowers total current.",
            "Series circuits share the same voltage across every possible branch.",
            "Power means the same thing as charge.",
        ],
        apply_answer_index=0,
        sim_concept="series_parallel_safety",
        sim_focus_prompt="Compare one-lane chains and branch decks on the same network board.",
        sim_description="Explore series paths, parallel branches, and the safety effect of large current.",
        sim_baseline="Start with one simple series chain and then add a parallel branch.",
        sim_tasks=[
            "Compare the current in one series chain with the split currents in a branch deck.",
            "Raise the current until the protection limit is reached and explain the fuse action.",
        ],
        sim_takeaway="Circuit behaviour and safety are easiest to read when current, voltage, and branch structure stay separate.",
        sim_controls=[
            ("branch_count", "Branch count", "It changes whether the network is one-lane or split."),
            ("load_setting", "Load setting", "It changes current and power in the network."),
        ],
        sim_readouts=[
            ("branch_voltage", "Shows the shared voltage across a parallel branch."),
            ("current_warning", "Shows when the current becomes unsafe."),
        ],
        reflection_prompt="Why should current, voltage, power, and safety be read together in the network lesson?",
        trap="Do not say that current is used up by the first component in the circuit.",
        analogy_check="What stays shared in a branch deck, and what can split?",
        analogy_mapping=[
            "One-lane chain = series circuit",
            "Branch deck = parallel circuit",
            "Task station shed rate = power",
            "Guard link = fuse",
        ],
        visual_concept="circuit_networks",
    ),
]

M9_MODULE_DOC, M9_LESSONS, M9_SIM_LABS = _build_generated_bundle(
    module_id="M9",
    module_title=M9_MODULE_TITLE,
    content_version=M9_CONTENT_VERSION,
    sequence=9,
    level="core",
    estimated_minutes=95,
    model_name="Carrier-Loop Switchyard Model",
    module_description=M9_MODULE_DESCRIPTION,
    mastery_outcomes=M9_MASTERY_OUTCOMES,
    lessons=_M9_BLUEPRINTS,
)


M10_CONTENT_VERSION = "20260323_m10_field_weave_realigned_v1"
M10_MODULE_DOC, M10_LESSONS, M10_SIM_LABS = _clone_bundle(
    module_path="scripts.seed_m12_module",
    source_prefix="M12",
    target_prefix="M10",
    module_title="Magnetism and Electromagnetic Effects",
    module_description="Field towers, coils, motor kicks, induction, and transformers all stay inside one field-weave story.",
    content_version=M10_CONTENT_VERSION,
    sequence=10,
    level="core",
    estimated_minutes=90,
    mastery_outcomes=[
        "Map magnetic fields around magnets, wires, and coils.",
        "Explain electromagnets, motor effect, induction, and transformers.",
        "Connect changing magnetic fields to generators and power transmission.",
    ],
)

M11_CONTENT_VERSION = "20260323_m11_core_vault_realigned_v1"
M11_MODULE_DOC, M11_LESSONS, M11_SIM_LABS = _clone_bundle(
    module_path="scripts.seed_m13_module",
    source_prefix="M13",
    target_prefix="M11",
    module_title="Atomic Structure and Radioactivity",
    module_description="Nuclear identity, isotopes, radiation types, half-life, and detector readings stay inside one core-vault story.",
    content_version=M11_CONTENT_VERSION,
    sequence=11,
    level="core",
    estimated_minutes=90,
    mastery_outcomes=[
        "Describe atomic structure, isotopes, and radiation types.",
        "Interpret half-life, background radiation, and decay changes.",
        "Balance simple nuclear changes conceptually and numerically.",
    ],
)


M12_CONTENT_VERSION = "20260323_m12_core_forge_v1"
M12_MODULE_TITLE = "Nuclear Energy and Applications"
M12_MODULE_DESCRIPTION = "Core bundles store binding credit; split chains, fusion joins, and tagged emissions can be harvested, traced, and managed inside one reactor story."
M12_MASTERY_OUTCOMES = [
    "Explain that nuclear energy comes from changes in the nucleus and binding energy ideas.",
    "Distinguish fission, fusion, and chain-reaction control.",
    "Explain how reactors, tracers, and industrial uses connect benefits with risk and waste management.",
    "Compare nuclear technologies by linking their useful applications, hazards, and waste decisions to the same core physics.",
]

_M12_BLUEPRINTS = [
    auto_blueprint(
        slug="nuclear_store",
        title="Energy from the Nucleus",
        focus="nuclear energy comes from the nucleus and its binding arrangement, not from ordinary chemical changes",
        terms=[
            tw("Nucleus", "The nucleus is the dense central core of the atom containing protons and neutrons.", "Nuclear energy changes belong here, not in the outer electrons."),
            tw("Binding energy", "Binding energy is the energy associated with holding the nucleus together.", "It explains why nuclear changes can release very large energies."),
            tw("Mass defect", "Mass defect is the difference between the mass of a nucleus and the masses of its separate nucleons.", "It links binding ideas to energy release."),
            tw("Nucleon", "A nucleon is a proton or neutron inside the nucleus.", "It keeps nuclear calculations tied to the particles involved."),
        ],
        core_concepts=[
            "Nuclear energy comes from the nucleus, not from ordinary chemical rearrangement.",
            "Binding arrangements matter because energy is released when the nuclear store changes.",
            "Small mass changes can correspond to large energy changes.",
        ],
        equation="E = mc^2",
        meaning="A small change in mass corresponds to a large change in energy.",
        units=["J", "kg", "m/s"],
        conditions="Use when relating mass change to energy release or absorption.",
        summary="Nuclear energy is tied to changes in the nucleus and its binding energy, not to ordinary electron-level chemistry.",
        why_prompt="Why can nuclear changes release far more energy than ordinary chemical changes?",
        why_answer="Because the energy change comes from the nucleus and binding energy, not only from outer-electron rearrangement.",
        compare_prompt="How is nuclear energy different from ordinary chemical energy?",
        compare_answer="Nuclear energy comes from changes in the nucleus, while chemical energy comes from electron-level bond changes.",
        apply_prompt="Which statement best fits nuclear energy?",
        apply_choices=[
            "Nuclear energy is released when the binding arrangement of the nucleus changes.",
            "Nuclear energy comes only from charges moving in wires.",
            "Nuclear changes are just large versions of ordinary heating with no change in the nucleus.",
            "Chemical bonds always release more energy than nuclear changes.",
        ],
        apply_answer_index=0,
        sim_concept="nuclear_energy_store",
        sim_focus_prompt="Keep the nuclear store separate from ordinary chemical energy stories.",
        sim_description="Compare nucleus-level energy changes with ordinary chemical-scale changes.",
        sim_baseline="Start with one stable nucleus and one altered binding arrangement.",
        sim_tasks=[
            "Compare a nucleus-level energy release with a much smaller chemical-scale release.",
            "Track how a tiny mass change corresponds to a large energy change.",
        ],
        sim_takeaway="Nuclear energy is clearer when the nucleus is treated as its own energy store.",
        sim_controls=[
            ("mass_change", "Mass change", "It sets the size of the energy change."),
            ("binding_state", "Binding arrangement", "It compares more-stable and less-stable cases."),
        ],
        sim_readouts=[
            ("energy_release", "Shows the energy associated with the mass change."),
            ("store_type", "Shows whether the energy story is nuclear or chemical."),
        ],
        reflection_prompt="Why is it important to say that nuclear energy comes from the nucleus itself?",
        trap="Do not collapse nuclear energy into an ordinary chemistry story.",
        analogy_check="Where does the main energy change happen in the core-forge model?",
        analogy_mapping=[
            "Core bundle = nucleus",
            "Binding credit = binding energy",
            "Missing mass = mass defect",
            "Energy release = forge output",
        ],
        visual_concept="nuclear_store",
    ),
    auto_blueprint(
        slug="fission_chain",
        title="Fission and Chain Reactions",
        focus="splitting a heavy nucleus can release energy and extra neutrons that trigger further splits",
        terms=[
            tw("Fission", "Fission is the splitting of a heavy nucleus into smaller nuclei.", "It is the main nuclear process used in present power stations."),
            tw("Chain reaction", "A chain reaction happens when one fission event releases neutrons that cause more fission events.", "It explains both power generation and accident risk."),
            tw("Neutron", "A neutron is an uncharged nucleon that can trigger fission in suitable nuclei.", "It is the key traveler in the chain-reaction story."),
            tw("Control rod", "A control rod absorbs neutrons inside a reactor.", "It helps keep the chain reaction at a safe rate."),
        ],
        core_concepts=[
            "Fission splits heavy nuclei and releases energy.",
            "Extra neutrons can make the reaction continue in a chain.",
            "Control means keeping the neutron-driven chain at a steady safe rate.",
        ],
        equation="one fission -> energy + daughter nuclei + neutrons",
        meaning="A fission event can release energy and neutrons that continue the process.",
        units=["qualitative"],
        conditions="Use as the conceptual nuclear-reaction pattern before detailed balancing.",
        summary="Fission releases energy and neutrons, and those neutrons can sustain a chain reaction if not controlled.",
        why_prompt="Why can one fission event lead to many more fission events?",
        why_answer="Because the first split can release neutrons that go on to trigger more heavy nuclei to split.",
        compare_prompt="How is a controlled chain reaction different from an uncontrolled one?",
        compare_answer="A controlled chain reaction keeps the fission rate steady, while an uncontrolled one allows the rate to rise dangerously.",
        apply_prompt="What is the main job of control rods in a fission reactor?",
        apply_choices=[
            "They absorb neutrons so the chain reaction stays under control.",
            "They create extra neutrons to speed the reaction up.",
            "They convert all radiation directly into electricity.",
            "They turn fission into fusion.",
        ],
        apply_answer_index=0,
        sim_concept="fission_chain",
        sim_focus_prompt="Keep neutron flow and fission rate on the same board.",
        sim_description="Explore how neutron release makes a chain reaction and how control rods steady it.",
        sim_baseline="Start with one heavy nucleus and one incoming neutron.",
        sim_tasks=[
            "Increase the number of neutrons released and compare the chain growth.",
            "Insert control rods and compare the new steady reaction rate.",
        ],
        sim_takeaway="Fission is safest conceptually when the neutron chain is kept visible from the start.",
        sim_controls=[
            ("neutron_release", "Neutrons released", "It controls how quickly the chain can spread."),
            ("control_rod_depth", "Control rod depth", "It changes how many neutrons are absorbed."),
        ],
        sim_readouts=[
            ("reaction_rate", "Shows whether the chain is steady, shrinking, or growing."),
            ("neutron_balance", "Shows how many neutrons continue the chain."),
        ],
        reflection_prompt="Why is neutron control the core safety question in fission?",
        trap="Do not describe a chain reaction as if it keeps the same rate automatically.",
        analogy_check="What turns one split into a chain of splits?",
        analogy_mapping=[
            "Heavy core bundle = fissile nucleus",
            "Released sparks = neutrons",
            "Control gate = control rods",
            "Forge chain = chain reaction",
        ],
        visual_concept="fission_chain",
    ),
    auto_blueprint(
        slug="fusion_join",
        title="Fusion and the Joining Route",
        focus="fusion joins light nuclei under extreme conditions and can release energy by moving toward a more stable binding arrangement",
        terms=[
            tw("Fusion", "Fusion is the joining of light nuclei to form a heavier nucleus.", "It powers stars and contrasts with fission."),
            tw("Temperature", "Temperature here measures how energetic the particles are.", "Very high temperature helps nuclei get close enough to fuse."),
            tw("Pressure", "Pressure keeps the fusion fuel crowded enough for collisions to occur.", "It helps explain why fusion needs extreme conditions."),
            tw("Plasma", "A plasma is a state of matter made of charged particles.", "Fusion fuel is usually in a plasma state."),
        ],
        core_concepts=[
            "Fusion joins light nuclei instead of splitting heavy ones.",
            "Fusion needs extreme conditions so nuclei can overcome repulsion.",
            "Fusion can release energy by producing a more stable bound nucleus.",
        ],
        equation="fusion joins light nuclei -> energy release",
        meaning="Joining light nuclei can release energy when the final binding arrangement is more stable.",
        units=["qualitative"],
        conditions="Use for introductory fusion reasoning.",
        summary="Fusion is a joining process that needs extreme conditions and releases energy when the resulting nucleus is more stable.",
        why_prompt="Why does fusion need much more extreme conditions than ordinary chemical burning?",
        why_answer="Because nuclei must get extremely close together before they can join, which requires very high energy conditions.",
        compare_prompt="How is fusion different from fission?",
        compare_answer="Fusion joins light nuclei, while fission splits heavy nuclei.",
        apply_prompt="Which statement best fits fusion?",
        apply_choices=[
            "Fusion joins light nuclei under extreme conditions and powers stars.",
            "Fusion is the splitting of uranium in a power station fuel rod.",
            "Fusion happens easily at room temperature in everyday wires.",
            "Fusion is only another name for radioactive decay.",
        ],
        apply_answer_index=0,
        sim_concept="fusion_conditions",
        sim_focus_prompt="Keep joining, extreme conditions, and energy release on one board.",
        sim_description="Compare mild conditions with the extreme conditions needed for fusion.",
        sim_baseline="Start with two light nuclei at low temperature and low pressure.",
        sim_tasks=[
            "Raise the temperature and pressure to compare the likelihood of joining.",
            "Compare a fusion case with a fission case and explain the opposite process.",
        ],
        sim_takeaway="Fusion should be remembered as a joining process that needs extreme conditions.",
        sim_controls=[
            ("temperature_level", "Temperature level", "It changes particle energy."),
            ("pressure_level", "Pressure level", "It changes how crowded the fusion fuel becomes."),
        ],
        sim_readouts=[
            ("join_likelihood", "Shows whether the nuclei are likely to overcome repulsion."),
            ("process_label", "Keeps fusion distinct from fission."),
        ],
        reflection_prompt="Why is 'joining light nuclei' the best anchor phrase for fusion?",
        trap="Do not confuse fusion with a high-temperature version of fission.",
        analogy_check="What two extreme conditions help the joining route work?",
        analogy_mapping=[
            "Light bundles = light nuclei",
            "Forge pressure = confinement pressure",
            "Heat gate = high temperature",
            "Joined core = fusion product",
        ],
        visual_concept="fusion_join",
    ),
    auto_blueprint(
        slug="reactor_overview",
        title="Reactor Control and Energy Transfer",
        focus="a reactor uses controlled fission to release thermal energy that is then transferred through a power station system",
        terms=[
            tw("Reactor", "A reactor is the part of a power station where the controlled nuclear chain reaction happens.", "It keeps the nuclear source distinct from the full station."),
            tw("Coolant", "A coolant is a fluid that carries thermal energy away from the reactor core.", "It shows how heat leaves the reactor safely."),
            tw("Moderator", "A moderator slows neutrons so fission can be sustained more effectively in some reactors.", "It is a separate control idea from control rods."),
            tw("Turbine", "A turbine is a device turned by a moving fluid to help generate electricity.", "It links nuclear heat to the familiar power-station chain."),
        ],
        core_concepts=[
            "The reactor is only one part of the power station.",
            "Controlled fission releases thermal energy that is carried away by a coolant.",
            "The station still turns heat into electricity through turbines and generators.",
        ],
        equation="reactor heat -> steam flow -> turbine -> generator",
        meaning="A nuclear station uses a thermal-energy chain to make electricity.",
        units=["qualitative"],
        conditions="Use for the introductory reactor-overview story.",
        summary="A nuclear power station uses controlled fission as a heat source and then follows a familiar heat-to-electricity route.",
        why_prompt="Why should the reactor not be described as if it directly makes electricity by itself?",
        why_answer="Because the reactor first provides controlled thermal energy, which is then transferred through the rest of the station to generate electricity.",
        compare_prompt="How is a control rod different from a coolant in a reactor?",
        compare_answer="A control rod changes the neutron chain, while a coolant carries heat away from the reactor.",
        apply_prompt="Which statement best describes the role of coolant in a reactor system?",
        apply_choices=[
            "Coolant carries thermal energy away from the core to the rest of the station system.",
            "Coolant is the same thing as a control rod because both absorb neutrons.",
            "Coolant directly becomes electrical current in the wires.",
            "Coolant makes fusion happen inside the reactor core.",
        ],
        apply_answer_index=0,
        sim_concept="reactor_overview",
        sim_focus_prompt="Keep neutron control and thermal transfer as separate stories.",
        sim_description="Trace energy from controlled fission in the core to electricity in the rest of the station.",
        sim_baseline="Start with a steady controlled chain reaction in the reactor core.",
        sim_tasks=[
            "Follow the energy into the coolant and then into the turbine-generator chain.",
            "Compare the effect of changing the control level with changing the heat-transfer path.",
        ],
        sim_takeaway="A reactor is best understood as a controlled heat source inside a larger power-station chain.",
        sim_controls=[
            ("control_level", "Control level", "It changes the reaction rate in the core."),
            ("coolant_flow", "Coolant flow", "It changes how thermal energy is carried away."),
        ],
        sim_readouts=[
            ("core_state", "Shows whether the reactor is under control."),
            ("power_chain", "Shows where the energy is in the station pathway."),
        ],
        reflection_prompt="Why does a reactor overview need both a control story and an energy-transfer story?",
        trap="Do not collapse the whole power station into only the reactor core.",
        analogy_check="What part of the station carries heat away from the core?",
        analogy_mapping=[
            "Core forge = reactor core",
            "Cooling river = coolant",
            "Control gate = control rods or moderator role",
            "Spin wheel = turbine-generator path",
        ],
        visual_concept="reactor_overview",
    ),
    auto_blueprint(
        slug="radioisotope_uses",
        title="Radioisotopes in Medicine and Industry",
        focus="tagged emissions and decay patterns can be used in tracing, imaging, thickness checks, and treatment",
        terms=[
            tw("Radioisotope", "A radioisotope is an isotope that is radioactive.", "It links nuclear physics to useful applications."),
            tw("Tracer", "A tracer is a small amount of radioactive material used to track movement or distribution in a system.", "It shows how decay can become a measurement tool."),
            tw("Dose", "Dose measures the energy absorbed by living tissue from radiation.", "It keeps useful application tied to safety."),
            tw("Sterilization", "Sterilization is the process of killing microorganisms on equipment or materials.", "It is one major practical use of radiation."),
        ],
        core_concepts=[
            "Radioisotopes can be useful because their emissions can be detected.",
            "Medicine and industry use radioactivity in tracing, imaging, treatment, and process control.",
            "Useful application still requires attention to dose and safety.",
        ],
        equation="useful application <- detectable emission + controlled exposure",
        meaning="A radioisotope is useful when its emissions can be detected and managed safely.",
        units=["qualitative"],
        conditions="Use for introductory radioisotope applications.",
        summary="Radioisotopes can be used in medicine and industry because their emissions can be detected and controlled.",
        why_prompt="Why can a tracer be useful in medicine or industry?",
        why_answer="Because a small radioactive source can be detected as it moves through a system, revealing the path or location.",
        compare_prompt="How is a medical tracer different from uncontrolled contamination?",
        compare_answer="A tracer uses a controlled small source for a clear measurement purpose, while contamination is unwanted radioactive presence.",
        apply_prompt="Which is a valid radioisotope application?",
        apply_choices=[
            "Using a tracer to follow the movement of a substance through a system.",
            "Calling any radioactive source safe because it is useful.",
            "Assuming a larger dose is always better for imaging.",
            "Treating all industrial radiation uses as identical to a nuclear reactor.",
        ],
        apply_answer_index=0,
        sim_concept="radioisotope_applications",
        sim_focus_prompt="Compare useful detection with managed exposure.",
        sim_description="Explore tracers, imaging, sterilization, and industrial checks on one application board.",
        sim_baseline="Start with one tracer path and one detector.",
        sim_tasks=[
            "Use a tracer to follow movement through a simple system.",
            "Compare a useful application case with a too-large-dose warning case.",
        ],
        sim_takeaway="Radioisotope applications make the most sense when usefulness and controlled exposure stay linked.",
        sim_controls=[
            ("application_type", "Application type", "It changes the purpose of the radioactive source."),
            ("source_level", "Source level", "It changes how detectable and how risky the source becomes."),
        ],
        sim_readouts=[
            ("detector_signal", "Shows whether the application signal can be read."),
            ("safety_flag", "Warns when the exposure grows beyond the intended safe range."),
        ],
        reflection_prompt="Why does a useful radioisotope application still need a safety story?",
        trap="Do not treat usefulness as if it automatically removes radiation risk.",
        analogy_check="What two things must stay together in a good application story?",
        analogy_mapping=[
            "Tagged spark = radioisotope emission",
            "Trace path = medical or industrial tracing",
            "Dose gauge = exposure limit",
            "Useful readout = detector result",
        ],
        visual_concept="radioisotope_uses",
    ),
    auto_blueprint(
        slug="benefits_hazards_waste",
        title="Benefits, Hazards, and Waste Management",
        focus="nuclear technologies should be judged by benefits, hazards, and long-term waste responsibilities together",
        terms=[
            tw("Hazard", "A hazard is a source of possible harm.", "It keeps nuclear risk language precise."),
            tw("Waste management", "Waste management is the safe handling, storage, and disposal of radioactive waste.", "It is a long-term part of the nuclear story."),
            tw("Containment", "Containment is keeping radioactive material within controlled barriers.", "It is central to nuclear safety."),
            tw("Benefit-risk comparison", "A benefit-risk comparison weighs the advantages of a technology against its possible harms.", "It supports balanced nuclear decisions."),
        ],
        core_concepts=[
            "Nuclear technologies bring real benefits but also real hazards.",
            "Waste management and containment are long-term responsibilities, not optional extras.",
            "A balanced judgment should compare benefits and risks together.",
        ],
        equation="good nuclear decision <- benefit + hazard + waste responsibility",
        meaning="Nuclear technology should be evaluated as a trade-off that includes long-term management.",
        units=["qualitative"],
        conditions="Use for introductory evaluation of nuclear technologies.",
        summary="Nuclear technologies should be evaluated through benefits, hazards, containment, and waste management together.",
        why_prompt="Why is waste management part of the nuclear-energy story instead of an afterthought?",
        why_answer="Because radioactive waste can remain hazardous for long periods, so safe storage and handling are part of the technology itself.",
        compare_prompt="How is a benefit-risk comparison different from saying nuclear is only good or only bad?",
        compare_answer="A benefit-risk comparison weighs the advantages and hazards together instead of pretending only one side exists.",
        apply_prompt="Which statement best fits nuclear evaluation?",
        apply_choices=[
            "A good evaluation compares benefits, hazards, containment, and waste management together.",
            "If a technology gives large energy output, waste management no longer matters.",
            "Containment is only useful for old reactors, not for modern nuclear applications.",
            "Any hazard means a technology has no possible benefit.",
        ],
        apply_answer_index=0,
        sim_concept="nuclear_benefits_risks",
        sim_focus_prompt="Keep benefit, hazard, and long-term management on the same decision board.",
        sim_description="Compare nuclear energy applications with their safety and waste responsibilities.",
        sim_baseline="Start with one nuclear benefit and one linked management cost.",
        sim_tasks=[
            "List one strong benefit and one linked hazard for the same technology.",
            "Add a long-term waste case and explain why it changes the overall judgment.",
        ],
        sim_takeaway="Nuclear decisions are strongest when benefit, hazard, and waste management are read together.",
        sim_controls=[
            ("technology_case", "Technology case", "It switches between different nuclear applications."),
            ("management_level", "Management level", "It compares stronger and weaker containment and waste planning."),
        ],
        sim_readouts=[
            ("benefit_panel", "Shows the main advantage of the selected case."),
            ("hazard_panel", "Shows the linked safety and waste responsibilities."),
        ],
        reflection_prompt="Why is long-term waste management part of the main nuclear judgment rather than a side note?",
        trap="Do not evaluate nuclear technology using only its energy output or only its hazard label.",
        analogy_check="What must stay on the same board when you judge a nuclear technology?",
        analogy_mapping=[
            "Forge output = nuclear benefit",
            "Containment wall = safety barrier",
            "Waste vault = long-term storage",
            "Balance board = benefit-risk judgment",
        ],
        visual_concept="nuclear_benefits_risks",
    ),
]

M12_MODULE_DOC, M12_LESSONS, M12_SIM_LABS = _build_generated_bundle(
    module_id="M12",
    module_title=M12_MODULE_TITLE,
    content_version=M12_CONTENT_VERSION,
    sequence=12,
    level="core",
    estimated_minutes=95,
    model_name="Core-Forge Reactor Model",
    module_description=M12_MODULE_DESCRIPTION,
    mastery_outcomes=M12_MASTERY_OUTCOMES,
    lessons=_M12_BLUEPRINTS,
)


M13_CONTENT_VERSION = "20260323_m13_lantern_ring_realigned_v1"
M13_MODULE_DOC, M13_LESSONS, M13_SIM_LABS = _clone_bundle(
    module_path="scripts.seed_m14_module",
    source_prefix="M14",
    target_prefix="M13",
    module_title="Earth and the Solar System",
    module_description="One lantern lights the court, hub pull shapes the ring routes, spin makes day and night, tilt makes seasons, and changing viewpoints explain phases and eclipses.",
    content_version=M13_CONTENT_VERSION,
    sequence=13,
    level="core",
    estimated_minutes=90,
    mastery_outcomes=[
        "Describe Solar System body types and orbit organization.",
        "Explain day and night, seasons, phases, and eclipses with Earth-Moon-Sun geometry.",
        "Relate orbital distance to year length and scale.",
    ],
)

M14_CONTENT_VERSION = "20260323_m14_beacon_city_realigned_v1"
M14_MODULE_DOC, M14_LESSONS, M14_SIM_LABS = _clone_bundle(
    module_path="scripts.seed_m15_module",
    source_prefix="M15",
    target_prefix="M14",
    module_title="Stars and the Universe",
    module_description="Stars are self-lit beacons, galaxies are beacon-cities, signal-years measure the huge spacing between them, and redshift supports the modern expansion story.",
    content_version=M14_CONTENT_VERSION,
    sequence=14,
    level="core",
    estimated_minutes=90,
    mastery_outcomes=[
        "Distinguish stars from reflective worlds and describe broad stellar lifecycle ideas.",
        "Explain galaxies, the Milky Way, light-years, redshift, and expansion evidence.",
        "Describe the Big Bang as expansion of space from a hot dense early state.",
    ],
)


_REVISED_BUNDLES: Dict[str, Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]] = {
    "F5": (F5_MODULE_DOC, F5_LESSONS, F5_SIM_LABS),
    "M9": (M9_MODULE_DOC, M9_LESSONS, M9_SIM_LABS),
    "M10": (M10_MODULE_DOC, M10_LESSONS, M10_SIM_LABS),
    "M11": (M11_MODULE_DOC, M11_LESSONS, M11_SIM_LABS),
    "M12": (M12_MODULE_DOC, M12_LESSONS, M12_SIM_LABS),
    "M13": (M13_MODULE_DOC, M13_LESSONS, M13_SIM_LABS),
    "M14": (M14_MODULE_DOC, M14_LESSONS, M14_SIM_LABS),
}


def revised_bundle(module_id: str) -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    normalized = str(module_id or "").strip().upper()
    if normalized not in _REVISED_BUNDLES:
        raise KeyError(f"Unsupported revised curriculum module: {module_id}")
    module_doc, lesson_pairs, sim_pairs = _REVISED_BUNDLES[normalized]
    return deepcopy(module_doc), deepcopy(lesson_pairs), deepcopy(sim_pairs)


def seed_module_cli(module_id: str) -> None:
    normalized = str(module_id or "").strip().upper()
    parser = argparse.ArgumentParser(description=f"Seed revised curriculum module {normalized}")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    asset_root = args.asset_root or default_asset_root()
    module_doc, lesson_pairs, sim_pairs = revised_bundle(normalized)

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", normalized)]
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


if __name__ == "__main__":
    import sys

    target_module = "F5"
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        target_module = sys.argv.pop(1)
    seed_module_cli(target_module)
