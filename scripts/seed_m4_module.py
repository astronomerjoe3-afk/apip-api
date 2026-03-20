from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_builder import build_nextgen_module_bundle
    from scripts.lesson_authoring_contract import AUTHORING_STANDARD_V2
except ModuleNotFoundError:
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_builder import build_nextgen_module_bundle
    from lesson_authoring_contract import AUTHORING_STANDARD_V2

try:
    from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
except ModuleNotFoundError:
    from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc


M4_MODULE_ID = "M4"
M4_CONTENT_VERSION = "20260321_m4_pressure_intro_v2"
M4_MODULE_TITLE = "Pressure"
M4_ALLOWLIST = [
    "pressure_force_confusion",
    "pressure_area_confusion",
    "same_depth_shape_confusion",
    "fluid_pressure_direction_confusion",
    "liquid_density_confusion",
    "atmospheric_pressure_confusion",
    "total_pressure_confusion",
]

VALID_REPRESENTATION_KINDS = {
    "diagram",
    "equation_story",
    "formula",
    "graph",
    "model",
    "table",
    "words",
}


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M4_ALLOWLIST)
    return [str(tag) for tag in tags if str(tag) in allowed]


def mcq(
    qid: str,
    prompt: str,
    choices: Sequence[str],
    answer_index: int,
    hint: str,
    tags: Sequence[str],
    *,
    skill_tags: Sequence[str] | None = None,
) -> Dict[str, Any]:
    item = {
        "id": qid,
        "question_id": qid,
        "kind": "mcq",
        "type": "mcq",
        "prompt": prompt,
        "choices": list(choices),
        "answer_index": answer_index,
        "hint": hint,
        "feedback": [hint for _ in choices],
        "misconception_tags": safe_tags(tags),
    }
    if skill_tags:
        item["skill_tags"] = [str(tag) for tag in skill_tags]
    return item


def short(
    qid: str,
    prompt: str,
    accepted_answers: Sequence[str],
    hint: str,
    tags: Sequence[str],
    *,
    acceptance_rules: Dict[str, Any] | None = None,
    skill_tags: Sequence[str] | None = None,
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
        "misconception_tags": safe_tags(tags),
    }
    if acceptance_rules:
        item["acceptance_rules"] = deepcopy(acceptance_rules)
    if skill_tags:
        item["skill_tags"] = [str(tag) for tag in skill_tags]
    return item


def acceptance_groups(*groups: Sequence[str]) -> Dict[str, Any]:
    return {"phrase_groups": [list(group) for group in groups]}


def prompt_block(prompt: str, hint: str) -> Dict[str, str]:
    return {"prompt": prompt, "hint": hint}


def formula(equation: str, meaning: str, units: Sequence[str], conditions: str) -> Dict[str, Any]:
    return {
        "equation": equation,
        "meaning": meaning,
        "units": list(units),
        "conditions": conditions,
    }


def representation(kind: str, purpose: str) -> Dict[str, str]:
    raw = str(kind or "").strip().lower().replace("-", "_").replace(" ", "_")
    if raw not in VALID_REPRESENTATION_KINDS:
        if "formula" in raw or "equation" in raw:
            raw = "formula"
        elif "word" in raw or "language" in raw:
            raw = "words"
        elif "story" in raw:
            raw = "equation_story"
        elif "table" in raw:
            raw = "table"
        elif "graph" in raw:
            raw = "graph"
        elif "model" in raw:
            raw = "model"
        else:
            raw = "diagram"
    return {"kind": raw, "purpose": purpose}


def worked(
    prompt: str,
    steps: Sequence[str],
    final_answer: str,
    answer_reason: str,
    why_it_matters: str,
) -> Dict[str, Any]:
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
    phase_key: str = "analogical_grounding",
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": phase_key,
        "title": title,
        "purpose": purpose,
        "caption": caption,
    }


def animation(
    asset_id: str,
    concept: str,
    title: str,
    description: str,
    *,
    phase_key: str = "analogical_grounding",
    duration_sec: int = 8,
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": phase_key,
        "title": title,
        "description": description,
        "duration_sec": duration_sec,
    }


def extra_section(heading: str, body: str, check_for_understanding: str = "") -> Dict[str, str]:
    section = {"heading": heading, "body": body}
    if check_for_understanding:
        section["check_for_understanding"] = check_for_understanding
    return section


def scaffold(
    core_idea: str,
    reasoning: str,
    check_for_understanding: str,
    common_trap: str,
    analogy_body: str,
    analogy_check: str,
    *,
    extra_sections: Sequence[Dict[str, str]] | None = None,
) -> Dict[str, Any]:
    return {
        "core_idea": core_idea,
        "reasoning": reasoning,
        "check_for_understanding": check_for_understanding,
        "common_trap": common_trap,
        "analogy_bridge": {
            "body": analogy_body,
            "check_for_understanding": analogy_check,
        },
        "extra_sections": list(extra_sections or []),
    }


def assessment_targets(diagnostic_pool_min: int, concept_gate_pool_min: int, mastery_pool_min: int) -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": diagnostic_pool_min,
        "concept_gate_pool_min": concept_gate_pool_min,
        "mastery_pool_min": mastery_pool_min,
        "fresh_attempt_policy": (
            "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem."
        ),
    }


def contract(
    *,
    concept_targets: Sequence[str],
    prerequisite_lessons: Sequence[str],
    misconception_focus: Sequence[str],
    formulas: Sequence[Dict[str, Any]],
    representations: Sequence[Dict[str, Any]],
    analogy_map: Dict[str, Any],
    worked_examples: Sequence[Dict[str, Any]],
    visual_assets: Sequence[Dict[str, Any]],
    animation_assets: Sequence[Dict[str, Any]],
    simulation_contract: Dict[str, Any],
    reflection_prompts: Sequence[str],
    mastery_skills: Sequence[str],
    variation_plan: Dict[str, str],
    scaffold_support: Dict[str, Any],
) -> Dict[str, Any]:
    normalized_representations = [deepcopy(item) for item in representations]
    normalized_kinds = {str(item.get("kind") or "").strip() for item in normalized_representations}
    anchor_formula = str(formulas[0].get("equation") or "").strip() if formulas else "the formal relation"
    anchor_target = str(concept_targets[0] or "").strip() if concept_targets else "the core lesson idea"

    if "words" not in normalized_kinds:
        normalized_representations.insert(
            0,
            {
                "kind": "words",
                "purpose": f"States {anchor_target} in plain language before the symbols take over.",
            },
        )
        normalized_kinds.add("words")
    if "formula" not in normalized_kinds:
        normalized_representations.append(
            {
                "kind": "formula",
                "purpose": f"Compresses the pressure relationship into {anchor_formula} once the Patch-Dome pattern is clear.",
            }
        )
        normalized_kinds.add("formula")
    if not normalized_kinds.intersection({"diagram", "graph", "table", "model", "equation_story"}):
        normalized_representations.append(
            {
                "kind": "diagram",
                "purpose": "Keeps the Patch-Dome geometry visible while the variables change.",
            }
        )

    while len(normalized_representations) < 3:
        normalized_representations.append(
            {
                "kind": "diagram",
                "purpose": "Supports a second visual comparison of the same pressure rule.",
            }
        )

    normalized_mastery_skills: List[str] = []
    for skill in list(mastery_skills) + [
        f"Explain {anchor_target} in clear pressure language",
        f"Use {anchor_formula} accurately in direct and inverse cases",
        "Compare two pressure situations by tracking which variable changed",
        "Reject the main misconception using Patch-Dome evidence",
        "Translate between Patch-Dome language and formal physics symbols",
    ]:
        cleaned = str(skill or "").strip()
        if cleaned and cleaned not in normalized_mastery_skills:
            normalized_mastery_skills.append(cleaned)

    normalized_variation_plan = deepcopy(variation_plan)
    parameter_axis = str(normalized_variation_plan.get("parameter_axis") or "").strip()
    representation_axis = str(normalized_variation_plan.get("representation_axis") or "").strip()
    misconception_axis = str(normalized_variation_plan.get("misconception_axis") or "").strip()
    normalized_variation_plan["diagnostic"] = str(
        normalized_variation_plan.get("diagnostic")
        or f"Rotate the opening questions across {parameter_axis or 'different numeric and qualitative cases'} so each fresh attempt surfaces the same misconception in a new way."
    )
    normalized_variation_plan["concept_gate"] = str(
        normalized_variation_plan.get("concept_gate")
        or f"Use retries that revisit the same idea through {representation_axis or 'new representations and comparisons'} rather than repeating the same stem."
    )
    normalized_variation_plan["mastery"] = str(
        normalized_variation_plan.get("mastery")
        or f"Prefer unseen mastery stems by varying {parameter_axis or 'the governing variables'} and {representation_axis or 'the representation'}, while still checking {misconception_axis or 'the core misconception'}."
    )

    return {
        "concept_targets": list(concept_targets),
        "prerequisite_lessons": list(prerequisite_lessons),
        "misconception_focus": safe_tags(misconception_focus),
        "formulas": [deepcopy(item) for item in formulas],
        "representations": normalized_representations,
        "analogy_map": deepcopy(analogy_map),
        "worked_examples": [deepcopy(item) for item in worked_examples],
        "visual_assets": [deepcopy(item) for item in visual_assets],
        "animation_assets": [deepcopy(item) for item in animation_assets],
        "simulation_contract": deepcopy(simulation_contract),
        "reflection_prompts": list(reflection_prompts),
        "mastery_skills": normalized_mastery_skills[:5],
        "variation_plan": normalized_variation_plan,
        "scaffold_support": deepcopy(scaffold_support),
    }


def patch_dome_map(model_focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Patch-Dome Model of Pressure",
        "focus": model_focus,
        "comparison": f"The Patch-Dome keeps solids, liquids, and air in one pressure world by asking how much push reaches each equal patch in {model_focus}.",
        "mapping": [
            "Total Push -> force",
            "Patch Spread -> area",
            "Patch Load -> pressure",
            "Layer Stack / Sky Blanket -> the amount of fluid above the patch",
        ],
        "limit": "The model explains pressure cleanly, but the formal equations still depend on which physical factors belong to the situation.",
        "prediction_prompt": f"Using the Patch-Dome alone, predict what should happen when {model_focus}.",
        "mapping_rows": [
            {"patch_dome": "Total Push", "physics": "Force", "student_meaning": "How hard something presses overall"},
            {"patch_dome": "Patch Spread", "physics": "Area", "student_meaning": "How many equal patches share that push"},
            {"patch_dome": "Patch Load", "physics": "Pressure", "student_meaning": "How much push reaches each patch"},
            {"patch_dome": "Layer Stack", "physics": "Depth in a liquid", "student_meaning": "How much liquid is above the patch"},
            {"patch_dome": "Liquid Weightiness", "physics": "Density", "student_meaning": "How heavy each liquid layer is"},
            {"patch_dome": "World Pull", "physics": "Gravitational field strength", "student_meaning": "How strongly the world pulls the layers down"},
            {"patch_dome": "Sky Blanket", "physics": "Atmosphere", "student_meaning": "How much air is above the patch"},
        ],
    }


def lesson_l1() -> Dict[str, Any]:
    return {
        "id": "M4_L1",
        "title": "Patch Load: Pressure Is Push Per Patch",
        "sim": {
            "lab_id": "m4_patch_spread_lab",
            "title": "Patch spread explorer",
            "description": "Compare the same total push spread across different numbers of identical sensor patches.",
            "instructions": [
                "Keep the push fixed while changing the footprint width.",
                "Compare a spike-like footprint with a broad platform.",
                "Explain every result using patch load, not force alone.",
            ],
            "outcomes": [
                "pressure_force_confusion",
                "pressure_area_confusion",
            ],
            "fields": [
                "total_push",
                "patch_spread",
                "patch_load",
                "comparison_pressure",
            ],
            "depth": "number of push-versus-area comparisons explained correctly as pressure differences rather than force differences",
        },
        "analogy_text": (
            "In the Patch-Dome, every floor is tiled with equal sensor patches. The total push can stay the same while the "
            "number of patches sharing that push changes. The important question is not the whole push by itself; it is how "
            "crowded that push becomes on each patch."
        ),
        "commitment_prompt": "Before you calculate, decide whether the problem is asking about total push or patch load.",
        "micro_prompts": [
            prompt_block("What changes if the same push is squeezed onto fewer patches?", "Name what happens to each patch, not to the total push."),
            prompt_block("Why can two objects press with the same force but different pressure?", "Keep the footprint or patch spread visible."),
            prompt_block("What does one sensor patch reading stand for in this lesson?", "Use the phrase push per patch or force per area."),
        ],
        "inquiry": [
            prompt_block("Keep total push fixed and shrink the footprint. What changes?", "Track pressure, not just force."),
            prompt_block("Now widen the footprint while keeping the push the same. What changes?", "Ask how many patches share the push."),
            prompt_block("Which setup protects fragile floor patches best, and why?", "Use patch-load language."),
        ],
        "recon_prompts": [
            "Pressure is not the total push. It is how concentrated that push becomes on each patch.",
            "The same force can give different pressure if the contact area changes.",
            "A smaller footprint raises pressure because fewer patches share the same total push.",
        ],
        "capsule_prompt": "Use the Patch-Dome idea to separate force from pressure before formal symbols appear.",
        "capsule_checks": [
            mcq("M4L1_C1", "Which statement best separates force from pressure?", ["Force is total push; pressure is push per patch", "Pressure is the same thing as force", "Pressure is force only when the object is heavy", "Force and pressure always rise together"], 0, "Keep total push separate from per-patch load.", ["pressure_force_confusion"]),
            mcq("M4L1_C2", "A 400 N push is spread over twice the area. What happens to the pressure?", ["it doubles", "it halves", "it stays the same", "it becomes zero"], 1, "At fixed force, more area means less pressure.", ["pressure_area_confusion"]),
            mcq("M4L1_C3", "Why do snowshoes reduce pressure compared with ordinary boots?", ["They reduce gravity", "They increase area so the push is shared by more patches", "They increase force", "They remove mass"], 1, "Think in terms of shared patches.", ["pressure_area_confusion"]),
            short("M4L1_C4", "Why can the same total push give different patch loads?", ["because the push can be spread over different areas", "because the number of patches sharing it can change", "because pressure depends on area as well as force"], "Use area or patch-spread language.", ["pressure_area_confusion"], acceptance_rules=acceptance_groups(["same push", "same force", "total push", "same pressure source"], ["area", "surface area", "contact area", "patch", "spread", "footprint"], ["different", "change", "smaller", "larger", "matters", "depends", "shared"])),
            mcq("M4L1_C5", "What does one patch sensor reading represent in this model?", ["total weight of the object", "pressure at that patch", "mass of the whole object", "total force divided by time"], 1, "One patch reads patch load.", ["pressure_force_confusion"]),
            mcq("M4L1_C6", "Which change definitely raises pressure if the total push stays the same?", ["using a smaller contact area", "waiting longer", "turning the object sideways without changing area", "making the object wider and lighter at the same time"], 0, "Fewer sharing patches means higher pressure.", ["pressure_area_confusion"]),
        ],
        "diagnostic": [
            mcq("M4L1_D1", "Two objects press on the floor with the same force. Which one gives the greater pressure?", ["the one with the larger area", "the one with the smaller area", "they must give the same pressure", "the one with the brighter color"], 1, "Pressure depends on both force and area.", ["pressure_area_confusion"]),
            mcq("M4L1_D2", "What is pressure measuring in this module?", ["the whole push only", "push per unit area", "mass per unit area", "depth per unit area"], 1, "Patch load means push per patch.", ["pressure_force_confusion"]),
            mcq("M4L1_D3", "Why does a sharp nail enter wood more easily than a flat block with the same push?", ["The nail has less mass", "The nail makes the pressure greater by using a smaller area", "Wood attracts nails", "Pressure depends only on time"], 1, "Same push on fewer patches means higher pressure.", ["pressure_area_confusion"]),
            short("M4L1_D4", "A 600 N push acts on an area of 0.30 m^2. What pressure is produced?", ["2000 Pa", "2000"], "Use pressure = force / area.", ["pressure_area_confusion"], acceptance_rules=acceptance_groups(["2000"])),
            mcq("M4L1_D5", "If the same push is spread over more patches, each patch feels...", ["more load", "less load", "the same load because force is unchanged", "zero load"], 1, "More sharing patches means less load per patch.", ["pressure_area_confusion"]),
            short("M4L1_D6", "Why is 'greater force means greater pressure' not always safe?", ["because area might also change", "because pressure depends on area as well as force", "because the same force on different areas gives different pressure"], "Use force-and-area language together.", ["pressure_force_confusion"], acceptance_rules=acceptance_groups(["area", "surface area", "contact area", "patch", "spread", "footprint"], ["depends", "also", "too", "as well", "change", "different", "matters"])) ,
            mcq("M4L1_D7", "A fragile floor has to be protected. Which change helps most if the total push cannot be reduced?", ["use a narrower foot", "use a wider platform", "make the object taller", "turn off gravity"], 1, "Increase the area sharing the push.", ["pressure_area_confusion"]),
            mcq("M4L1_D8", "What stays the same when one footprint is replaced by another wider footprint but the object is unchanged?", ["pressure", "contact area", "total push", "patch load"], 2, "The whole push can stay fixed even while its spread changes.", ["pressure_force_confusion"]),
        ],
        "transfer": [
            mcq("M4L1_M1", "A rescue pod pushes down with the same weight before and after a redesign. What change would lower floor pressure most directly?", ["smaller feet", "larger feet", "brighter paint", "longer time standing still"], 1, "At fixed force, larger area lowers pressure.", ["pressure_area_confusion"]),
            mcq("M4L1_M2", "A designer says two pads give the same pressure because the total force is the same. What is the best correction?", ["Pressure can still differ if the areas differ", "Pressure ignores area completely", "Pressure depends only on mass", "Pressure is only for liquids"], 0, "Area must stay visible.", ["pressure_force_confusion"]),
            short("M4L1_M3", "A 900 N push is spread over 0.45 m^2. What pressure is produced?", ["2000 Pa", "2000"], "Use P = F/A.", ["pressure_area_confusion"], acceptance_rules=acceptance_groups(["2000"])),
            mcq("M4L1_M4", "Which statement best matches the Patch-Dome model?", ["Pressure is the whole push", "Pressure is how crowded the push is on each patch", "Pressure only exists in water", "Pressure always points downward"], 1, "Keep patch load central.", ["pressure_force_confusion"]),
            mcq("M4L1_M5", "Two shoes apply the same total force. Shoe A covers twice the area of Shoe B. How do their pressures compare?", ["Shoe A gives twice the pressure", "Shoe A gives half the pressure", "They give equal pressure", "Shoe A gives four times the pressure"], 1, "Double area at fixed force halves pressure.", ["pressure_area_confusion"]),
            short("M4L1_M6", "Why do flat training shoes mark the floor less than spikes under the same athlete?", ["because the same force is spread over a larger area", "because the force is shared over more patches", "because the pressure is lower when the area is larger"], "Use same-force-larger-area language.", ["pressure_area_confusion"], acceptance_rules=acceptance_groups(["same", "force", "push"], ["larger", "more", "wider"], ["area", "patch", "spread"], ["lower", "less"], ["pressure"])),
            mcq("M4L1_M7", "If both force and area double together, what happens to the pressure?", ["it doubles", "it halves", "it stays the same", "it becomes zero"], 2, "Equal scaling leaves force/area unchanged.", ["pressure_area_confusion"]),
            mcq("M4L1_M8", "Which unit matches pressure?", ["N", "Pa", "kg", "J"], 1, "Pressure is measured in pascals.", ["pressure_force_confusion"]),
        ],
        "contract": contract(
            concept_targets=[
                "Pressure as force per unit area",
                "Force versus pressure distinction",
                "Area dependence of pressure in solids",
            ],
            prerequisite_lessons=[],
            misconception_focus=["pressure_force_confusion", "pressure_area_confusion"],
            formulas=[
                formula("P = F / A", "Patch load equals total push divided by patch spread", ["Pa", "N", "m^2"], "Use when one total push acts across one contact area."),
            ],
            representations=[
                representation("patch grid", "Shows that changing the number of equal patches changes the load per patch."),
                representation("footprint comparison", "Shows the same push with different contact areas."),
            ],
            analogy_map=patch_dome_map("solids: same total push, different patch spread"),
            worked_examples=[
                worked(
                    "A 600 N block stands on a base area of 0.30 m^2. Find the pressure.",
                    [
                        "Classify the story as pressure from total push and contact area.",
                        "Use P = F / A.",
                        "Substitute 600 / 0.30 and state the unit.",
                    ],
                    "The pressure is 2000 Pa.",
                    "Pressure is total push divided by area, so 600 N spread over 0.30 m^2 gives 2000 Pa.",
                    "This is the first Patch-Dome calculation: same push, count how crowded it becomes on each patch.",
                ),
                worked(
                    "Two feet both press with 480 N. Foot A covers 0.24 m^2 and Foot B covers 0.12 m^2. Which gives greater pressure?",
                    [
                        "Keep the total push comparison visible: both pushes are the same.",
                        "Compute each pressure with P = F / A.",
                        "Compare the per-patch loads and explain why the smaller area wins.",
                    ],
                    "Foot B gives the greater pressure: 4000 Pa compared with 2000 Pa for Foot A.",
                    "With the same 480 N push, halving the area doubles the pressure, so the smaller footprint overloads each patch more.",
                    "This example keeps force and pressure distinct instead of treating them as interchangeable.",
                ),
                worked(
                    "A floor patch must stay below 2500 Pa. If the total push is 500 N, what minimum contact area is needed?",
                    [
                        "Rearrange P = F / A to A = F / P.",
                        "Substitute A = 500 / 2500.",
                        "State the answer as a minimum area because smaller would exceed the safe patch load.",
                    ],
                    "The contact area must be at least 0.20 m^2.",
                    "A = F / P gives 0.20 m^2, so any smaller area would make the pressure larger than the allowed patch load.",
                    "Pressure design often works backward from a safe patch load to the needed footprint.",
                ),
            ],
            visual_assets=[
                visual("m4-l1-patch-load", "pressure_solids", "Patch Load on Equal Floor Sensors", "Compares the same push on wide and narrow footprints.", "Pressure becomes how much push reaches each equal patch."),
            ],
            animation_assets=[
                animation("m4-l1-patch-load-shift", "pressure_solids", "Crowding the Push", "Shows one fixed push crowding onto fewer and then more patches."),
            ],
            simulation_contract={
                "asset_id": "m4_l1_patch_spread_lab",
                "concept": "pressure_solids",
                "baseline_case": "Use one push on a medium footprint.",
                "comparison_tasks": [
                    "Keep the push fixed and halve the footprint area.",
                    "Keep the push fixed and double the footprint area.",
                ],
                "watch_for": "Students must keep total push separate from patch load.",
                "takeaway": "Pressure in solids is push per patch, not push alone.",
            },
            reflection_prompts=[
                "Why can two equal forces create different pressures?",
                "What does one sensor patch reading stand for?",
            ],
            mastery_skills=[
                "Use P = F / A in solids",
                "Distinguish force from pressure",
                "Explain why area changes pressure",
            ],
            variation_plan={
                "parameter_axis": "Vary total push and contact area separately.",
                "representation_axis": "Move between patch grids, footprints, and symbols.",
                "misconception_axis": "Confront force-pressure confusion directly.",
            },
            scaffold_support=scaffold(
                "Pressure is not the whole push. Pressure is how much of that push each equal patch receives.",
                "Name the total push first, then ask how many equal patches share it. Only after that use P = F / A.",
                "If the same object keeps the same push but stands on fewer patches, what happens to each patch load?",
                "Do not call large force and large pressure the same thing. Area decides whether the push is crowded or shared.",
                "The Patch-Dome works because it always asks the same question: how much push reaches each equal patch?",
                "In the dome, what changes when the same push is squeezed onto fewer patches?",
                extra_sections=[
                    extra_section("Same push, different crowding", "A force story can stay unchanged while a pressure story changes dramatically, because the number of patches sharing the push may change."),
                    extra_section("Patch-load design thinking", "Real pressure problems often ask how to redesign the footprint so fragile patches survive even when the total push cannot be reduced."),
                ],
            ),
        ),
    }


def lesson_l2() -> Dict[str, Any]:
    return {
        "id": "M4_L2",
        "title": "Footprint Rescue and Pressure Design",
        "sim": {
            "lab_id": "m4_footprint_design_lab",
            "title": "Footprint rescue lab",
            "description": "Design contact areas to keep fragile patches under a safe pressure limit.",
            "instructions": [
                "Set a floor safety limit.",
                "Change push and area to see when the design becomes safe or unsafe.",
                "Work backward from a safe patch load to a required footprint.",
            ],
            "outcomes": ["pressure_area_confusion", "pressure_force_confusion"],
            "fields": ["total_push", "contact_area", "pressure", "safe_limit"],
            "depth": "number of safe-footprint design decisions justified with pressure rather than vague weight language",
        },
        "analogy_text": (
            "The Patch Rescue station inside the dome is a design problem: the total push is given, the floor patch limit is given, "
            "and students must redesign the footprint so no patch is overloaded."
        ),
        "commitment_prompt": "When the problem gives a safe pressure limit, decide whether you are solving for force, area, or patch load before you substitute numbers.",
        "micro_prompts": [
            prompt_block("If safe pressure is fixed and the push increases, what must happen to the area?", "Use the rearranged equation idea."),
            prompt_block("Why is this still a pressure problem and not just a force problem?", "A safe limit belongs to pressure, not raw force."),
            prompt_block("What is a minimum safe area answer telling you physically?", "It is the smallest footprint that keeps each patch under the limit."),
        ],
        "inquiry": [
            prompt_block("Set a safe limit and test a footprint that fails. Why does it fail?", "Compare the patch load with the limit."),
            prompt_block("Now widen the footprint until the design just becomes safe.", "Think of the area as the design variable."),
            prompt_block("Finally, raise the total push and redesign again.", "Keep the same limit visible."),
        ],
        "recon_prompts": [
            "Pressure design often works backward from a safe limit.",
            "If the safe patch load is fixed, larger push demands larger area.",
            "Rearranging the equation is still the same physics story: crowding a push onto patches.",
        ],
        "capsule_prompt": "Use pressure design language rather than one-way formula recall.",
        "capsule_checks": [
            mcq("M4L2_C1", "A floor allows at most 3000 Pa. A push of 600 N must be supported safely. Which area is just enough?", ["0.10 m^2", "0.20 m^2", "0.30 m^2", "0.50 m^2"], 1, "Use A = F / P.", ["pressure_area_confusion"]),
            mcq("M4L2_C2", "If the safe pressure limit stays fixed and the total push doubles, the minimum safe area must...", ["halve", "stay the same", "double", "become zero"], 2, "At fixed limit, area scales with force.", ["pressure_area_confusion"]),
            short("M4L2_C3", "Why is a 'minimum safe area' answer still about pressure?", ["because the area is chosen so the pressure stays below the limit", "because the goal is to keep the patch load safe", "because the footprint controls pressure"], "Keep the safety limit in the explanation.", ["pressure_force_confusion"], acceptance_rules=acceptance_groups(["area", "footprint", "contact area"], ["pressure", "patch load", "pressure limit", "limit", "safe", "allowed"], ["keep", "below", "under", "within", "controls", "meet"])),
            mcq("M4L2_C4", "A design produces exactly the allowed pressure. What does that mean?", ["The design is at the safe threshold", "The design has zero force", "The design must fail", "Pressure no longer matters"], 0, "Exactly the limit means threshold, not failure by itself.", ["pressure_area_confusion"]),
            mcq("M4L2_C5", "Which statement is strongest?", ["A heavy object always gives dangerous pressure", "A light object can still give large pressure if its area is small", "Area never matters if the object is heavy", "Pressure only matters in liquids"], 1, "Small area can create large pressure even for modest force.", ["pressure_force_confusion"]),
            mcq("M4L2_C6", "What does rearranging A = F / P preserve?", ["the same physical relationship between push, spread, and patch load", "a completely new law", "only the units, not the meaning", "nothing physical"], 0, "Rearranging preserves the same relationship.", ["pressure_area_confusion"]),
        ],
        "diagnostic": [
            mcq("M4L2_D1", "A support must keep pressure below 2500 Pa. With a push of 1000 N, what minimum area is needed?", ["0.25 m^2", "0.40 m^2", "2.5 m^2", "4.0 m^2"], 1, "Use A = F / P.", ["pressure_area_confusion"]),
            mcq("M4L2_D2", "If area stays fixed and total push rises, pressure...", ["falls", "stays the same", "rises", "becomes unrelated"], 2, "At fixed area, pressure follows force.", ["pressure_area_confusion"]),
            short("M4L2_D3", "A patch limit is 4000 Pa and the footprint is 0.20 m^2. What maximum push can this design support?", ["800 N", "800"], "Use F = PA.", ["pressure_area_confusion"], acceptance_rules=acceptance_groups(["800"])),
            mcq("M4L2_D4", "What makes this lesson more than repeating P = F/A?", ["It asks students to design from a pressure limit backward to an area or force", "It changes pressure into energy", "It says area can be ignored", "It turns pressure into velocity"], 0, "Design problems work backward from a condition.", ["pressure_force_confusion"]),
            mcq("M4L2_D5", "Which redesign would lower pressure without changing the push?", ["smaller footprint", "more concentrated contact", "larger footprint", "sharper edge"], 2, "Wider spread lowers patch load.", ["pressure_area_confusion"]),
            short("M4L2_D6", "Why can a moderate push still be unsafe on a fragile surface?", ["because the area can be too small", "because the push can be crowded onto too few patches", "because pressure depends on spread as well as push"], "Use patch-spread language.", ["pressure_force_confusion"], acceptance_rules=acceptance_groups(["area", "patch", "spread", "footprint"], ["small", "few", "crowded"], ["pressure"])),
            mcq("M4L2_D7", "A student says 'we only need the force, not the area' in a safety design problem. What is the best correction?", ["Safety here is about pressure, so area is essential", "Force already includes area", "Area only matters in water", "Safety never depends on pressure"], 0, "Pressure limits require area.", ["pressure_force_confusion"]),
            mcq("M4L2_D8", "If both the push and the allowed pressure double, the required area will...", ["halve", "stay the same", "double", "quadruple"], 1, "A = F / P. Doubling both leaves the ratio unchanged.", ["pressure_area_confusion"]),
        ],
        "transfer": [
            mcq("M4L2_M1", "A rescue sled pushes with 1200 N on a snow surface that can tolerate 3000 Pa. Which minimum area is needed?", ["0.10 m^2", "0.20 m^2", "0.40 m^2", "0.60 m^2"], 2, "Use A = F / P.", ["pressure_area_confusion"]),
            short("M4L2_M2", "A plate of area 0.50 m^2 must stay at 2400 Pa or below. What is the greatest push allowed?", ["1200 N", "1200"], "Use F = PA.", ["pressure_area_confusion"], acceptance_rules=acceptance_groups(["1200"])),
            mcq("M4L2_M3", "Which statement best fits a good footprint redesign?", ["Keep the same dangerous footprint because the force is unchanged", "Increase the spread so the same push is shared by more patches", "Decrease the area so the object looks smaller", "Ignore the pressure limit"], 1, "Patch rescue means sharing the push.", ["pressure_area_confusion"]),
            mcq("M4L2_M4", "A design is exactly on the limit. Which judgment is strongest?", ["It is just safe but has no extra margin", "It is automatically unsafe", "It has zero pressure", "It no longer depends on area"], 0, "Threshold is not the same as margin.", ["pressure_area_confusion"]),
            short("M4L2_M5", "Why does doubling the push require doubling the area when the safe pressure limit is unchanged?", ["because area must rise in step with force to keep the same pressure", "because pressure equals force divided by area", "because the ratio must stay constant"], "Keep the fixed-limit idea visible.", ["pressure_area_confusion"], acceptance_rules=acceptance_groups(["force", "push"], ["area"], ["same", "keep", "constant", "fixed"], ["pressure", "ratio"])),
            mcq("M4L2_M6", "Which variable is the bridge quantity in a safety design story?", ["pressure limit", "mass only", "time only", "color only"], 0, "The whole design is built around a patch-load limit.", ["pressure_force_confusion"]),
            mcq("M4L2_M7", "If an object uses a footprint twice as large as necessary, what is true?", ["It will create twice the safe pressure", "It will create less pressure than the limit", "The force must double", "The pressure becomes zero"], 1, "Larger area than minimum gives extra margin.", ["pressure_area_confusion"]),
            mcq("M4L2_M8", "Which answer uses the strongest design language?", ["The object is heavy", "The footprint keeps patch load below the allowed limit", "The object looks stable", "The floor is probably fine"], 1, "Design language should mention limit and patch load.", ["pressure_force_confusion"]),
        ],
        "contract": contract(
            concept_targets=["Backward pressure design", "Safe pressure thresholds", "Rearranging P = F/A with meaning"],
            prerequisite_lessons=["M4_L1"],
            misconception_focus=["pressure_area_confusion", "pressure_force_confusion"],
            formulas=[
                formula("P = F / A", "Patch load from total push and spread", ["Pa", "N", "m^2"], "Use when force and area are known."),
                formula("A = F / P", "Minimum area required for a safe patch load", ["m^2", "N", "Pa"], "Use when a pressure limit is given."),
                formula("F = PA", "Maximum push supported by a footprint at a given patch load", ["N", "Pa", "m^2"], "Use when pressure and area are known."),
            ],
            representations=[
                representation("safety threshold bar", "Shows whether the design is below, on, or above the safe patch-load limit."),
                representation("footprint redesign board", "Makes area the design variable rather than a forgotten denominator."),
            ],
            analogy_map=patch_dome_map("designing safe footprints from patch-load limits"),
            worked_examples=[
                worked("A fragile floor allows at most 3000 Pa. A 900 N machine must stand on it. What minimum area is needed?", ["Recognize a safe-limit design story, so area is the unknown.", "Use A = F / P.", "Substitute 900 / 3000 and interpret the result as a minimum area."], "The minimum area is 0.30 m^2.", "The safe patch-load limit is 3000 Pa, so the footprint has to spread the 900 N push over at least 0.30 m^2.", "This is backward pressure reasoning: the condition tells you the footprint you must build."),
                worked("A support plate has area 0.40 m^2 and the floor limit is 2500 Pa. What maximum push can it support safely?", ["Recognize that pressure and area are known while force is unknown.", "Use F = PA.", "Substitute 2500 x 0.40 and state the result as a maximum safe push."], "The maximum safe push is 1000 N.", "At 2500 Pa across 0.40 m^2, the largest allowed push is 1000 N; anything larger would exceed the patch limit.", "This example shows how the same pressure relationship can also set a safe force limit."),
                worked("A pod presses with 800 N. Design A uses 0.16 m^2 and Design B uses 0.32 m^2. The safe limit is 3000 Pa. Which design is safe?", ["Find each pressure using P = F / A.", "Compare each result with the 3000 Pa limit.", "Use the limit to justify the design judgment, not a guess based on size alone."], "Only Design B is safe.", "Design A gives 5000 Pa, which exceeds the limit, while Design B gives 2500 Pa, which stays under the allowed patch load.", "Good pressure design compares patch load with a criterion instead of just comparing object size informally."),
            ],
            visual_assets=[visual("m4-l2-footprint-rescue", "pressure_design", "Footprint Rescue Board", "Shows safe and unsafe footprints against the same floor limit.", "Pressure design works backward from a safe patch-load limit.")],
            animation_assets=[animation("m4-l2-footprint-rescue-shift", "pressure_design", "Growing the Footprint", "Shows the same push moving from unsafe to safe as area increases.")],
            simulation_contract={
                "asset_id": "m4_l2_footprint_design_lab",
                "concept": "pressure_design",
                "baseline_case": "Use one push and one safe pressure limit.",
                "comparison_tasks": ["Redesign an unsafe footprint until it becomes safe.", "Keep the limit fixed and compare two different pushes."],
                "watch_for": "Students should justify safe or unsafe by comparing pressure with the limit.",
                "takeaway": "Design problems work backward from patch-load limits to areas and forces.",
            },
            reflection_prompts=["Why does a minimum safe area answer still belong to pressure physics?", "What does being exactly on the pressure limit mean physically?"],
            mastery_skills=["Rearrange P = F/A", "Design for safe pressure", "Compare designs with a pressure limit"],
            variation_plan={
                "parameter_axis": "Vary force and safe limit to change the needed area.",
                "representation_axis": "Move between threshold bars, numbers, and patch boards.",
                "misconception_axis": "Confront the idea that force alone decides safety.",
            },
            scaffold_support=scaffold(
                "Pressure design means working backward from a safe patch-load limit to the footprint or maximum push that is allowed.",
                "Write the pressure limit first, then decide whether area or force is the unknown. Rearranging the equation is still the same push-per-patch story.",
                "If the safe pressure stays fixed and the push doubles, what must happen to the footprint?",
                "Do not treat the denominator as an afterthought. In design problems, area is often the whole point.",
                "The Patch Rescue station turns pressure into a planning tool: how wide must the footprint become so no patch is overloaded?",
                "In the dome, why does a 'minimum safe area' answer talk about pressure rather than just size?",
                extra_sections=[
                    extra_section("Threshold thinking", "Safe, just-safe, and unsafe are pressure judgments. The patch-load limit is what gives the design its meaning."),
                    extra_section("Backward equations still tell one story", "A = F / P and F = PA are not new laws. They are the same crowding relationship seen from different design questions."),
                ],
            ),
        ),
    }


def lesson_l3() -> Dict[str, Any]:
    return {
        "id": "M4_L3",
        "title": "Liquid Layer Stack and Depth Load",
        "sim": {
            "lab_id": "m4_liquid_stack_lab",
            "title": "Liquid stack explorer",
            "description": "Change depth, density, and World Pull to see how liquid pressure grows with layer stack.",
            "instructions": [
                "Keep the liquid fixed and compare shallow and deep patches.",
                "Keep the depth fixed and compare light and dense liquids.",
                "Explain the change as more or heavier layers above the patch.",
            ],
            "outcomes": ["liquid_density_confusion", "same_depth_shape_confusion"],
            "fields": ["depth", "liquid_density", "world_grip", "liquid_pressure"],
            "depth": "number of liquid-pressure comparisons explained correctly as layer-stack effects rather than container-size effects",
        },
        "analogy_text": (
            "In the Liquid Chamber, every window patch asks the same question: how heavy is the liquid stack above me? "
            "Deeper patches have more layers above them, denser liquids give heavier layers, and stronger World Pull makes every layer press harder."
        ),
        "commitment_prompt": "Before calculating, decide whether the liquid-pressure change came from depth, density, or World Pull.",
        "micro_prompts": [
            prompt_block("Why does a deeper patch feel more load?", "Use layer-stack language, not container-width language."),
            prompt_block("If depth stays the same but the liquid gets denser, what happens?", "Heavier layers matter."),
            prompt_block("What three things build hydrostatic pressure in this model?", "Name depth, liquid weightiness, and World Pull."),
        ],
        "inquiry": [
            prompt_block("Keep the liquid the same and slide the patch deeper. What happens?", "More layers above means more patch load."),
            prompt_block("Now keep depth fixed and switch to a denser liquid. What happens?", "Heavier layers matter even at the same depth."),
            prompt_block("Finally change World Pull. What changes and why?", "Stronger pull makes each layer press harder."),
        ],
        "recon_prompts": [
            "Liquid pressure grows with depth because deeper patches carry more liquid above them.",
            "Liquid pressure also depends on liquid density and World Pull.",
            "The formal summary p = rhogh compresses the layer-stack story.",
        ],
        "capsule_prompt": "Treat liquid pressure as a location story inside a fluid, not as a container-size story.",
        "capsule_checks": [
            mcq("M4L3_C1", "Which patch in the same resting liquid has the greater pressure?", ["the deeper patch", "the shallower patch", "they are always equal", "the one on the wider side of the tank"], 0, "Depth matters because of the liquid above.", ["same_depth_shape_confusion"]),
            mcq("M4L3_C2", "Which formal relation matches the liquid layer-stack story?", ["P = F/A", "p = rhogh", "E = Pt", "F = ma"], 1, "Depth, density, and g belong here.", ["liquid_density_confusion"]),
            short("M4L3_C3", "Why does a denser liquid give greater pressure at the same depth?", ["because each layer is heavier", "because density makes the liquid stack heavier", "because rho is larger in rhogh"], "Use heavier-layer language.", ["liquid_density_confusion"], acceptance_rules=acceptance_groups(["denser", "density", "rho"], ["heavier", "more weight", "greater weight", "more mass"], ["layer", "stack", "same depth", "same level", "same height"])),
            mcq("M4L3_C4", "If depth doubles while density and g stay fixed, the liquid pressure becomes...", ["half", "the same", "double", "four times"], 2, "p is directly proportional to h.", ["liquid_density_confusion"]),
            mcq("M4L3_C5", "What does g represent in p = rhogh here?", ["charge", "World Pull", "time", "volume"], 1, "It is the world's pull on the liquid layers.", ["liquid_density_confusion"]),
            mcq("M4L3_C6", "Which statement is strongest?", ["Depth alone explains all liquid pressure", "Depth, density, and World Pull all matter", "Only container shape matters", "Liquid pressure is always the same everywhere"], 1, "Keep all three factors visible.", ["liquid_density_confusion"]),
        ],
        "diagnostic": [
            mcq("M4L3_D1", "Why is pressure greater deeper in a liquid?", ["Because the container is wider there", "Because more liquid layers are above the patch", "Because the liquid gets older", "Because depth changes the area"], 1, "Use layer-stack language.", ["same_depth_shape_confusion"]),
            mcq("M4L3_D2", "Which variable would increase liquid pressure at the same depth?", ["lower density", "weaker gravity", "greater density", "smaller tank width"], 2, "Heavier layers give larger pressure.", ["liquid_density_confusion"]),
            short("M4L3_D3", "Water has density 1000 kg/m^3. At depth 3 m with g = 10 N/kg, what hydrostatic pressure is produced?", ["30000 Pa", "30000"], "Use p = rhogh.", ["liquid_density_confusion"], acceptance_rules=acceptance_groups(["30000"])),
            mcq("M4L3_D4", "If the same liquid is compared at 2 m and 5 m depth, which patch has greater pressure?", ["2 m patch", "5 m patch", "equal pressure", "cannot tell"], 1, "The deeper patch carries the larger stack.", ["same_depth_shape_confusion"]),
            short("M4L3_D5", "What three factors set liquid pressure in p = rhogh?", ["density, gravitational field strength, and depth", "rho g and h", "liquid density, world pull, and depth"], "Name density, g, and depth.", ["liquid_density_confusion"], acceptance_rules=acceptance_groups(["density", "rho"], ["g", "world pull", "gravitational"], ["depth", "height"])),
            mcq("M4L3_D6", "A student says width of the container changes pressure at a point more than depth. What is the best correction?", ["Width is irrelevant at a given depth in the same liquid", "Width always doubles pressure", "Only width matters in liquids", "Pressure does not exist sideways"], 0, "Point pressure depends on depth, density, and g, not width.", ["same_depth_shape_confusion"]),
            mcq("M4L3_D7", "If the same liquid depth is moved to a stronger-gravity world, the pressure will...", ["decrease", "stay the same", "increase", "become zero"], 2, "g is one of the factors.", ["liquid_density_confusion"]),
            mcq("M4L3_D8", "Which wording best matches the Patch-Dome for liquids?", ["Pressure is the whole amount of liquid", "Pressure is the load each patch feels from the liquid stack above", "Pressure only acts at the bottom", "Pressure is the same as density"], 1, "Pressure belongs to the location and its overlying layers.", ["fluid_pressure_direction_confusion"]),
        ],
        "transfer": [
            mcq("M4L3_M1", "At what depth in water (rho = 1000 kg/m^3, g = 10 N/kg) is the hydrostatic pressure 50000 Pa?", ["2 m", "5 m", "10 m", "50 m"], 1, "Use h = p / rho g.", ["liquid_density_confusion"]),
            short("M4L3_M2", "A liquid has density 800 kg/m^3. At depth 4 m with g = 10 N/kg, what pressure is produced?", ["32000 Pa", "32000"], "Use p = rhogh.", ["liquid_density_confusion"], acceptance_rules=acceptance_groups(["32000"])),
            mcq("M4L3_M3", "Two liquids are at the same depth on the same world. Liquid A is denser than Liquid B. Which patch feels more pressure?", ["A", "B", "equal pressure", "cannot tell"], 0, "Denser liquid means heavier layers.", ["liquid_density_confusion"]),
            mcq("M4L3_M4", "What should stay visible before using p = rhogh?", ["the layer-stack story at that location", "the color of the tank", "the total amount of liquid everywhere", "the force on only the bottom"], 0, "Pressure belongs to a location in the liquid.", ["same_depth_shape_confusion"]),
            short("M4L3_M5", "Why does doubling depth double liquid pressure when density and g stay fixed?", ["because pressure is directly proportional to depth", "because there are twice as many layers above", "because h doubles in rhogh"], "Use direct-proportion or layer-stack language.", ["liquid_density_confusion"], acceptance_rules=acceptance_groups(["depth", "h"], ["double", "direct"], ["layer", "stack", "above", "rhogh"])),
            mcq("M4L3_M6", "Which claim is wrong?", ["A denser liquid gives greater pressure at the same depth", "Stronger gravity gives greater pressure at the same depth", "A wider tank gives greater pressure at the same depth", "A deeper patch gives greater pressure"], 2, "Width is not one of the hydrostatic factors.", ["same_depth_shape_confusion"]),
            mcq("M4L3_M7", "A patch pressure is 20000 Pa at 2 m depth in one liquid. At the same depth in another liquid the pressure is 40000 Pa on the same world. What is true?", ["The second liquid is less dense", "The second liquid is more dense", "The depths are unequal", "Pressure has no relation to density"], 1, "Same depth and same g make density the deciding factor.", ["liquid_density_confusion"]),
            mcq("M4L3_M8", "Which statement best keeps the analogy true?", ["Liquid pressure grows because deeper patches carry more or heavier layers above", "Liquid pressure grows because bottom patches are larger", "Liquid pressure points downward only", "Liquid pressure depends mainly on tank shape"], 0, "Stick with the layer-stack story.", ["same_depth_shape_confusion"]),
        ],
        "contract": contract(
            concept_targets=["Liquid pressure as rhogh", "Depth dependence", "Density and g effects"],
            prerequisite_lessons=["M4_L1"],
            misconception_focus=["same_depth_shape_confusion", "liquid_density_confusion"],
            formulas=[formula("p = rhogh", "Hydrostatic pressure from liquid density, World Pull, and depth", ["Pa", "kg/m^3", "N/kg", "m"], "Use for a resting liquid of roughly constant density.")],
            representations=[
                representation("liquid stack meter", "Shows that deeper patches carry more liquid above."),
                representation("depth comparison windows", "Compares shallow and deep patches in the same liquid."),
            ],
            analogy_map=patch_dome_map("liquid layer stacks and depth load"),
            worked_examples=[
                worked("Water has density 1000 kg/m^3. Find the hydrostatic pressure at depth 4 m when g = 10 N/kg.", ["Identify a resting-liquid pressure story, so use p = rhogh.", "Substitute 1000 x 10 x 4.", "State the result as pressure at that depth."], "The hydrostatic pressure is 40000 Pa.", "At 4 m depth, the water stack gives 1000 x 10 x 4 = 40000 Pa of pressure.", "This is the direct quantitative form of the layer-stack idea."),
                worked("Two windows are at the same 3 m depth, one in water and one in oil of density 800 kg/m^3. Which feels greater pressure?", ["Keep depth and g the same across the comparison.", "Use density as the deciding factor in p = rhogh.", "Compare 1000 x 10 x 3 with 800 x 10 x 3."], "The water window feels greater pressure.", "At the same depth and same g, the denser liquid gives the greater pressure because its layers are heavier.", "This keeps density visible instead of letting depth do all the explanatory work."),
                worked("A liquid patch feels 60000 Pa on a world where g = 10 N/kg. The liquid density is 1200 kg/m^3. How deep is the patch?", ["Use p = rhogh with depth as the unknown.", "Rearrange to h = p / (rho g).", "Substitute 60000 / (1200 x 10)."], "The depth is 5 m.", "60000 divided by 12000 gives 5, so the patch is 5 m below the surface.", "This inverse problem shows that the same relation also solves for depth when the pressure is known."),
            ],
            visual_assets=[visual("m4-l3-liquid-stack", "liquid_pressure", "Liquid Stack Board", "Shows shallow and deep windows in the same resting liquid.", "Deeper patches carry more liquid stack above them.")],
            animation_assets=[animation("m4-l3-liquid-stack-rise", "liquid_pressure", "Rising Depth Load", "Shows pressure increasing as a patch moves deeper in one liquid.")],
            simulation_contract={
                "asset_id": "m4_l3_liquid_stack_lab",
                "concept": "liquid_pressure",
                "baseline_case": "Use one liquid at one depth.",
                "comparison_tasks": ["Keep density fixed and compare two depths.", "Keep depth fixed and compare two liquid densities."],
                "watch_for": "Students should explain change using depth, density, and World Pull rather than vessel shape.",
                "takeaway": "Liquid pressure grows with rho, g, and h because deeper patches carry heavier layer stacks.",
            },
            reflection_prompts=["Why does a deeper patch feel more pressure?", "Why can two liquids at the same depth still give different pressure?"],
            mastery_skills=["Use p = rhogh", "Explain depth and density effects", "Solve direct and inverse hydrostatic problems"],
            variation_plan={
                "parameter_axis": "Vary depth, density, and g separately.",
                "representation_axis": "Move between layer-stack stories, windows, and equations.",
                "misconception_axis": "Confront the false idea that width or shape controls point pressure.",
            },
            scaffold_support=scaffold(
                "Liquid pressure comes from the weight of the liquid stack above a patch, so it grows with density, World Pull, and depth.",
                "Name the location first, then ask how much liquid is above it, how heavy that liquid is, and how strongly the world pulls the layers down. After that, use p = rhogh.",
                "If two patches are in the same liquid but one is deeper, what extra story does the deeper patch have above it?",
                "Do not let tank shape replace depth in your explanation. Point pressure in a resting liquid depends on rho, g, and h.",
                "In the Liquid Chamber, deeper patches feel a bigger layer stack, denser liquids make each layer heavier, and stronger World Pull makes every layer press harder.",
                "In the dome, what changes if the patch stays at the same depth but the liquid becomes denser?",
                extra_sections=[
                    extra_section("Location, not total tank", "Hydrostatic pressure belongs to the patch location in the liquid. The total amount of liquid elsewhere in the tank is not the key quantity."),
                    extra_section("Three-factor thinking", "p = rhogh is stronger than a height-only story because density and World Pull still matter when depth is unchanged."),
                ],
            ),
        ),
    }


def lesson_l4() -> Dict[str, Any]:
    return {
        "id": "M4_L4",
        "title": "Same Level, Same Liquid, Same Patch Load",
        "sim": {
            "lab_id": "m4_same_level_lab",
            "title": "Same-level showdown",
            "description": "Compare equal-depth patches in differently shaped vessels and prove the patch load still matches.",
            "instructions": [
                "Choose one depth and compare patches in narrow and wide tanks.",
                "Keep the liquid and world fixed.",
                "Explain why the readings match even when the vessel shapes do not.",
            ],
            "outcomes": ["same_depth_shape_confusion", "fluid_pressure_direction_confusion"],
            "fields": ["depth", "equal_level_pressure", "shape_a", "shape_b"],
            "depth": "number of equal-level comparisons correctly explained without using total-liquid or vessel-width misconceptions",
        },
        "analogy_text": (
            "The Equal-Level Window in the Patch-Dome is designed to defeat a common trap. Two patches can sit in wildly different vessels, "
            "but if they are at the same level in the same resting liquid, they read the same patch load."
        ),
        "commitment_prompt": "Before answering, check whether the patches are at the same depth in the same liquid.",
        "micro_prompts": [
            prompt_block("If two windows are at the same level in the same liquid, what should match?", "Use same-depth rule language."),
            prompt_block("Why does tank shape fail to change the pressure at a given depth?", "Pressure belongs to the location, not the outline of the container."),
            prompt_block("What must stay the same for the same-level rule to hold?", "Name liquid and depth."),
        ],
        "inquiry": [
            prompt_block("Compare a narrow vessel and a wide vessel at the same marked depth. What do the patch meters show?", "Equal level should match."),
            prompt_block("Move one patch deeper while leaving the other at the old level. What changes?", "Depth breaks the equality."),
            prompt_block("Switch one vessel to a different liquid. Does the same-level rule still hold?", "Same liquid matters too."),
        ],
        "recon_prompts": [
            "In the same resting liquid, equal depth means equal pressure.",
            "Container shape does not change pressure at a point when depth is the same.",
            "Same-level matching fails if the liquid changes or the depth changes.",
        ],
        "capsule_prompt": "Use the same-level rule to defeat vessel-shape misconceptions.",
        "capsule_checks": [
            mcq("M4L4_C1", "Two patches are at the same depth in the same liquid but in different-shaped vessels. What is true?", ["Their pressures are equal", "The wider vessel gives greater pressure", "The narrower vessel gives greater pressure", "Pressure cannot be compared"], 0, "Same depth in the same liquid means same pressure.", ["same_depth_shape_confusion"]),
            mcq("M4L4_C2", "Which change would break the same-level rule?", ["changing only the vessel shape", "keeping the same liquid and same depth", "moving one patch to a different depth", "keeping both patches level"], 2, "Depth is a real factor; shape is not.", ["same_depth_shape_confusion"]),
            short("M4L4_C3", "Why does vessel shape not change the pressure at one depth in a resting liquid?", ["because pressure depends on depth, density, and g, not on shape", "because the same-depth patches have the same layer stack above them", "because pressure belongs to the location"], "Use same-depth or location language.", ["same_depth_shape_confusion"], acceptance_rules=acceptance_groups(["same", "depth", "level", "location", "point"], ["shape", "vessel", "container", "tank"], ["not", "does not", "doesn't", "cannot"], ["pressure", "layer", "stack"])),
            mcq("M4L4_C4", "Two patches are level, but one liquid is denser. What happens?", ["The pressures stay equal", "The denser liquid gives greater pressure", "The less dense liquid gives greater pressure", "Pressure becomes zero"], 1, "Same depth is not enough if the liquid changes.", ["liquid_density_confusion"]),
            mcq("M4L4_C5", "Which statement best keeps the Patch-Dome analogy true?", ["Shape does not fool the liquid", "Wide tanks always press harder", "Bottom patches always read more because they are on the bottom", "Pressure depends mainly on how much liquid the tank holds"], 0, "Location wins over shape.", ["same_depth_shape_confusion"]),
            mcq("M4L4_C6", "Why is the same-level rule a location rule?", ["Because pressure belongs to the point in the fluid", "Because shape and size always give equal pressure", "Because pressure is a vector", "Because only bottoms matter"], 0, "Pressure is tied to the location in the fluid.", ["fluid_pressure_direction_confusion"]),
        ],
        "diagnostic": [
            mcq("M4L4_D1", "Which patch has the greater pressure in the same liquid?", ["the one in the wider container at the same depth", "the one in the narrower container at the same depth", "they are equal if their depths match", "the one closer to the wall"], 2, "Equal depth in the same liquid means equal pressure.", ["same_depth_shape_confusion"]),
            mcq("M4L4_D2", "Why is 'more water in the wide tank means more pressure at the side window' wrong?", ["Because pressure at the window depends on the local depth, not the total liquid elsewhere", "Because wide tanks remove pressure", "Because pressure exists only at the bottom", "Because water in wide tanks is less dense"], 0, "Keep pressure local to the patch.", ["same_depth_shape_confusion"]),
            short("M4L4_D3", "Two windows are both 2 m below the surface in the same water tank. What can you say about their pressures?", ["they are equal", "same pressure", "equal pressure"], "Use equal-depth language.", ["same_depth_shape_confusion"], acceptance_rules=acceptance_groups(["equal", "same"], ["pressure"])),
            mcq("M4L4_D4", "Which condition must be true for the same-level rule?", ["same liquid and same depth", "same container shape only", "same total amount of liquid", "same window size only"], 0, "Both liquid and depth matter.", ["same_depth_shape_confusion"]),
            mcq("M4L4_D5", "If one equal-level patch is changed to oil while the other stays in water, what happens?", ["They must still have equal pressure", "The pressures can differ because the liquids differ", "Pressure disappears", "Shape becomes the only factor"], 1, "Same level alone is not enough if the liquid changes.", ["liquid_density_confusion"]),
            short("M4L4_D6", "Why is pressure at a point called a location property here?", ["because it belongs to the point in the fluid", "because the point's depth and liquid determine it", "because shape elsewhere does not decide it"], "Use point or location language.", ["fluid_pressure_direction_confusion"], acceptance_rules=acceptance_groups(["point", "location"], ["fluid", "depth", "liquid"], ["determine", "belongs", "not shape"])),
            mcq("M4L4_D7", "A student compares two bottom patches at the same depth in connected water vessels of different width. Which statement is strongest?", ["The wider branch has higher pressure", "The pressures match because the depths and liquid match", "The narrower branch has higher pressure", "Bottom pressure cannot be compared"], 1, "Same water, same depth, same pressure.", ["same_depth_shape_confusion"]),
            mcq("M4L4_D8", "What changes pressure at a patch more directly than vessel shape?", ["depth", "paint color", "window size", "tank width"], 0, "Depth is a real factor.", ["same_depth_shape_confusion"]),
        ],
        "transfer": [
            mcq("M4L4_M1", "Two windows are both 1.5 m below the water surface, one in a narrow tower and one in a wide tank. Which claim is right?", ["The narrow tower gives more pressure", "The wide tank gives more pressure", "They give the same pressure", "The wider tank gives half"], 2, "Equal depth in the same liquid means equal pressure.", ["same_depth_shape_confusion"]),
            short("M4L4_M2", "Why does equal depth beat vessel shape in a same-liquid comparison?", ["because the local layer stack above the patch matches", "because pressure depends on depth not shape", "because the location determines the pressure"], "Use local depth or layer-stack language.", ["same_depth_shape_confusion"], acceptance_rules=acceptance_groups(["depth", "level", "location"], ["shape", "container", "vessel"], ["same", "match"], ["pressure", "layer"])),
            mcq("M4L4_M3", "Which setup should give unequal pressure?", ["same liquid, same depth, different shapes", "same liquid, different depths", "same liquid, same depth, connected vessels", "same liquid, same depth, one side wall and one bottom"], 1, "Changing depth is enough to change pressure.", ["same_depth_shape_confusion"]),
            mcq("M4L4_M4", "At one same-depth location in a resting liquid, what is not needed to determine the pressure?", ["density", "g", "depth", "tank width"], 3, "Width is not part of p = rhogh.", ["same_depth_shape_confusion"]),
            short("M4L4_M5", "A water patch at 3 m depth has pressure p. Another water patch at the same depth in a different-shaped container has what pressure?", ["the same pressure", "same pressure", "p"], "Equal depth in the same liquid gives equal pressure.", ["same_depth_shape_confusion"], acceptance_rules=acceptance_groups(["same", "equal", "p"], ["pressure"])),
            mcq("M4L4_M6", "Why does this lesson matter beyond one formula?", ["It stops students from inventing shape effects that the fluid does not actually have", "It proves all containers have the same volume", "It removes density from the story", "It turns pressure into force only"], 0, "The rule fights a common misconception.", ["same_depth_shape_confusion"]),
            mcq("M4L4_M7", "If two equal-level windows are in different liquids, which quantity must be compared next?", ["the window area", "the liquid density", "the tank width", "the total liquid mass"], 1, "Same depth with different liquids points to density.", ["liquid_density_confusion"]),
            mcq("M4L4_M8", "Which statement best fits the dome model?", ["Pressure belongs to the whole container", "Pressure belongs to the fluid location and equal levels in one liquid match", "Pressure belongs only to bottoms", "Pressure is a direction pointing downward"], 1, "Keep pressure local to the point.", ["fluid_pressure_direction_confusion"]),
        ],
        "contract": contract(
            concept_targets=["Same-depth rule", "Container-shape independence", "Pressure as a location property"],
            prerequisite_lessons=["M4_L3"],
            misconception_focus=["same_depth_shape_confusion", "fluid_pressure_direction_confusion"],
            formulas=[formula("p = rhogh", "Hydrostatic pressure at a point", ["Pa", "kg/m^3", "N/kg", "m"], "Use the same liquid and same depth rule to compare points before calculating.")],
            representations=[
                representation("equal-level windows", "Highlights same-depth comparisons across different vessel shapes."),
                representation("shape contrast tank", "Shows that shape changes the outline, not the same-depth pressure."),
            ],
            analogy_map=patch_dome_map("same level, same liquid, same patch load"),
            worked_examples=[
                worked("Two side windows are both 2 m below the water surface, one in a narrow tube and one in a wide tank. Compare the pressure.", ["Check the two conditions: same liquid and same depth.", "Recognize that vessel shape is not in p = rhogh.", "State the same-depth rule directly."], "The pressures are equal.", "Because both windows are in the same liquid at the same depth, the patch load matches even though the vessel shapes differ.", "This is the key misconception-fighting example for pressure in liquids."),
                worked("A water window and an oil window are both 3 m below their surfaces on the same world. Water has density 1000 kg/m^3 and oil has density 800 kg/m^3. Which pressure is greater?", ["Notice that the depths match, so density becomes the deciding factor.", "Use p = rhogh conceptually or numerically.", "Compare 1000 x 10 x 3 with 800 x 10 x 3."], "The water window has greater pressure.", "At the same depth and same g, the denser liquid gives the larger pressure, so water wins over oil here.", "This example keeps students from overgeneralizing the same-level rule beyond the same liquid."),
                worked("In one water tank, a bottom patch and a side patch are both 1.5 m below the surface. Which has greater pressure?", ["Treat both as locations in the same resting liquid.", "Use the same-depth rule before thinking about surface orientation.", "State the pressure comparison clearly, then leave force direction for the next lesson."], "They have the same pressure.", "Pressure at a point depends on the location in the liquid, so equal depth in the same water gives equal pressure even on different surfaces.", "This prepares the next lesson's distinction between scalar pressure and directional force on a patch."),
            ],
            visual_assets=[visual("m4-l4-same-level", "same_depth_rule", "Equal-Level Window", "Compares equal-depth patches in differently shaped vessels.", "Shape does not fool the liquid at the same level.")],
            animation_assets=[animation("m4-l4-same-level-match", "same_depth_rule", "Equal-Level Match", "Shows same-depth patches reading equally while the vessel outline changes.")],
            simulation_contract={
                "asset_id": "m4_l4_same_level_lab",
                "concept": "same_depth_rule",
                "baseline_case": "Compare one depth in two vessel shapes with the same liquid.",
                "comparison_tasks": ["Keep the same depth and change only vessel shape.", "Break the equal-depth condition and compare again."],
                "watch_for": "Students should name same liquid and same depth before claiming equal pressure.",
                "takeaway": "Same level in the same resting liquid means the same patch load, even when shapes differ.",
            },
            reflection_prompts=["Why does a wider container not automatically give greater pressure at the same depth?", "What exactly has to match before equal pressure can be claimed?"],
            mastery_skills=["Apply the same-depth rule", "Reject shape misconceptions", "Compare pressure as a location property"],
            variation_plan={
                "parameter_axis": "Vary depth or liquid while keeping shape visible as a distractor.",
                "representation_axis": "Use equal-level markers, windows, and connected-vessel sketches.",
                "misconception_axis": "Target container-width and total-liquid misconceptions.",
            },
            scaffold_support=scaffold(
                "In the same resting liquid, equal depth means equal pressure, no matter how the vessel shape looks.",
                "Check same liquid first, then same depth. If both conditions hold, say the pressures match before you even think about the container outline.",
                "If two windows sit at the same level in one liquid, what should you expect their patch meters to show?",
                "Do not let total amount of liquid or vessel width replace the local depth story.",
                "The Equal-Level Window teaches one of the most important Patch-Dome rules: shape does not fool the liquid.",
                "In the dome, what must stay the same before equal patch load can be claimed in two different vessels?",
                extra_sections=[
                    extra_section("Local rule, not whole-container rule", "The same-depth rule compares specific points in a fluid. It is not a statement about whole containers being equivalent in every way."),
                    extra_section("Set up the conditions first", "Same liquid and same depth are the two non-negotiables. If either changes, equality may fail."),
                ],
            ),
        ),
    }


def lesson_l5() -> Dict[str, Any]:
    return {
        "id": "M4_L5",
        "title": "Pressure at a Point, Force on a Patch",
        "sim": {
            "lab_id": "m4_surface_patch_lab",
            "title": "Surface patch explorer",
            "description": "Place wall, floor, and slanted patches at the same fluid location and compare pressure with force direction.",
            "instructions": [
                "Keep the depth fixed and rotate the patch.",
                "Notice that the pressure value stays the same at the location.",
                "Track how the force direction changes to stay perpendicular to the patch.",
            ],
            "outcomes": ["fluid_pressure_direction_confusion", "total_pressure_confusion"],
            "fields": ["depth", "pressure", "patch_area", "force_on_patch", "surface_angle"],
            "depth": "number of surface-orientation comparisons explained with scalar pressure and perpendicular force language",
        },
        "analogy_text": (
            "At one point in the Patch-Dome liquid, the patch load belongs to the location itself. A wall patch, floor patch, or slanted patch "
            "placed there all inherit the same pressure value. What changes is the direction of the force on that patch: it acts perpendicular to the surface."
        ),
        "commitment_prompt": "Before answering, decide whether the question is asking for the pressure at the location or the force on a particular patch.",
        "micro_prompts": [
            prompt_block("Does pressure itself point downward in this lesson?", "Keep pressure scalar and force directional."),
            prompt_block("What decides the direction of the force due to pressure?", "It is the patch orientation, not a pressure arrow."),
            prompt_block("What extra quantity is needed to turn pressure into force on a surface?", "Area matters here."),
        ],
        "inquiry": [
            prompt_block("Place a wall patch and a floor patch at the same depth. What stays the same?", "The pressure value at the location."),
            prompt_block("Rotate the patch. What changes?", "The force direction stays perpendicular."),
            prompt_block("Now increase the patch area while keeping pressure fixed. What happens to the force?", "Use F = pA."),
        ],
        "recon_prompts": [
            "Pressure in a fluid is a scalar quantity at a location.",
            "The force due to pressure on a surface acts perpendicular to that surface.",
            "At fixed pressure, a larger patch area gives a larger total force.",
        ],
        "capsule_prompt": "Separate scalar pressure from the directional force on a chosen patch.",
        "capsule_checks": [
            mcq("M4L5_C1", "At one point in a resting liquid, pressure is best described as...", ["a downward vector only", "a scalar value for that location", "the same thing as force", "zero on side walls"], 1, "Pressure belongs to the point, not to one direction only.", ["fluid_pressure_direction_confusion"]),
            mcq("M4L5_C2", "The force due to pressure on a wall patch acts...", ["downward", "upward", "perpendicular to the wall", "parallel to the wall"], 2, "Force on the patch acts normal to the surface.", ["fluid_pressure_direction_confusion"]),
            mcq("M4L5_C3", "If pressure at a location stays fixed but patch area doubles, the force on that patch...", ["halves", "stays the same", "doubles", "becomes zero"], 2, "Use F = pA.", ["total_pressure_confusion"]),
            short("M4L5_C4", "Why can a wall patch and a floor patch at the same depth have the same pressure but different force directions?", ["because pressure belongs to the location but force acts perpendicular to the chosen surface", "because the patch chooses the force direction", "because pressure is scalar but force has direction"], "Use location-versus-surface language.", ["fluid_pressure_direction_confusion"], acceptance_rules=acceptance_groups(["pressure"], ["location", "point", "same depth", "same place"], ["force"], ["perpendicular", "normal", "surface", "patch", "orientation", "direction"])),
            mcq("M4L5_C5", "Which equation links patch pressure to force on one surface area?", ["P = F/A", "F = pA", "E = Pt", "F = ma"], 1, "Once pressure is known at a point, area gives the force on a chosen patch.", ["total_pressure_confusion"]),
            mcq("M4L5_C6", "Which claim is wrong?", ["A slanted patch can feel a force perpendicular to it", "Pressure at a point can be the same on nearby wall and floor patches", "Pressure only acts downward in liquids", "A larger area patch can feel a larger force at the same pressure"], 2, "Pressure is not a single downward arrow.", ["fluid_pressure_direction_confusion"]),
        ],
        "diagnostic": [
            mcq("M4L5_D1", "What changes when you place a slanted patch at the same fluid location?", ["the pressure value only", "the pressure value and density", "the direction of the force on the patch", "the depth of the patch"], 2, "Pressure value can stay the same while force direction changes.", ["fluid_pressure_direction_confusion"]),
            mcq("M4L5_D2", "Which statement best describes pressure at a point in a liquid?", ["It points downward only", "It belongs to the location as a scalar value", "It vanishes on side walls", "It is equal to force automatically"], 1, "Pressure is scalar here.", ["fluid_pressure_direction_confusion"]),
            short("M4L5_D3", "A patch of area 0.20 m^2 is at a point where pressure is 12000 Pa. What force acts on the patch?", ["2400 N", "2400"], "Use F = pA.", ["total_pressure_confusion"], acceptance_rules=acceptance_groups(["2400"])),
            mcq("M4L5_D4", "A wall patch and a floor patch sit at the same depth in the same liquid. Which statement is strongest?", ["They must feel different pressures because one is sideways", "They can feel the same pressure but different force directions", "The wall patch feels zero pressure", "The floor patch must always feel more pressure"], 1, "Separate pressure value from force direction.", ["fluid_pressure_direction_confusion"]),
            short("M4L5_D5", "Why does a larger patch feel a larger force at the same pressure?", ["because force equals pressure times area", "because more area collects the same pressure over more surface", "because F = pA"], "Use pressure-times-area language.", ["total_pressure_confusion"], acceptance_rules=acceptance_groups(["pressure", "p"], ["area"], ["force", "f"], ["times", "multiplies", "more surface"])),
            mcq("M4L5_D6", "What decides the direction of the force from fluid pressure on a surface?", ["the color of the liquid", "the surface orientation", "the container shape far away", "the total liquid volume only"], 1, "The patch orientation matters.", ["fluid_pressure_direction_confusion"]),
            mcq("M4L5_D7", "If a patch is moved deeper while its area stays fixed, what happens to the force on it in the same liquid?", ["it decreases", "it stays the same", "it increases", "it becomes unrelated to pressure"], 2, "Deeper means larger pressure, so F = pA grows too.", ["total_pressure_confusion"]),
            mcq("M4L5_D8", "Which sentence is safest?", ["Pressure and force are the same thing", "Pressure is the value at the location; force is what that pressure does to a chosen area", "Force decides the pressure direction", "Pressure vanishes on slanted surfaces"], 1, "Keep scalar pressure separate from force on area.", ["pressure_force_confusion"]),
        ],
        "transfer": [
            mcq("M4L5_M1", "A rectangular tank window has area 0.50 m^2 at a point where pressure is 16000 Pa. What force acts on the window?", ["3200 N", "8000 N", "16000 N", "32000 N"], 1, "Use F = pA.", ["total_pressure_confusion"]),
            short("M4L5_M2", "Why can fluid push on a side wall even though the liquid is not 'falling sideways'?", ["because pressure exists at the location and the force acts perpendicular to the wall", "because pressure is scalar and the wall sets the force direction", "because the patch chooses the direction of the force"], "Use scalar-pressure or perpendicular-force language.", ["fluid_pressure_direction_confusion"], acceptance_rules=acceptance_groups(["pressure"], ["scalar", "location", "point"], ["perpendicular", "normal", "wall", "surface", "patch"])),
            mcq("M4L5_M3", "At one point in a fluid, which pair can both be true?", ["same pressure and same force direction on every patch", "same pressure but different force directions on different patches", "different pressure but same force direction automatically", "zero pressure on slanted patches"], 1, "Pressure stays with the location; direction stays with the surface.", ["fluid_pressure_direction_confusion"]),
            mcq("M4L5_M4", "If the pressure on a patch doubles and area stays fixed, the force on that patch...", ["halves", "stays the same", "doubles", "quadruples"], 2, "Use F = pA.", ["total_pressure_confusion"]),
            short("M4L5_M5", "A patch force is 1800 N and the pressure is 9000 Pa. What is the patch area?", ["0.20 m^2", "0.2 m^2", "0.2"], "Use A = F / p.", ["total_pressure_confusion"], acceptance_rules=acceptance_groups(["0.2", "0.20"])),
            mcq("M4L5_M6", "Which statement best fixes the misconception 'pressure points downward'?", ["Pressure is a scalar at a point; the force on a surface is perpendicular to that surface", "Pressure is always a downward force", "Pressure only exists at bottoms", "Pressure disappears on side walls"], 0, "Use scalar-versus-force language.", ["fluid_pressure_direction_confusion"]),
            mcq("M4L5_M7", "A larger floor patch and a smaller floor patch sit at the same depth in the same liquid. Which is true?", ["They feel different pressures", "They feel the same pressure but different total forces", "They feel different densities", "They must feel the same total force"], 1, "Same pressure at location; different area changes force.", ["total_pressure_confusion"]),
            mcq("M4L5_M8", "Why is this lesson a step beyond just p = rhogh?", ["It adds the distinction between scalar pressure and force on a chosen surface", "It removes area from the story", "It says pressure has no relation to force", "It turns pressure into momentum"], 0, "This lesson links point pressure to surface force correctly.", ["fluid_pressure_direction_confusion"]),
        ],
        "contract": contract(
            concept_targets=["Pressure as scalar", "Force perpendicular to a surface", "Force from pressure via F = pA"],
            prerequisite_lessons=["M4_L3", "M4_L4"],
            misconception_focus=["fluid_pressure_direction_confusion", "total_pressure_confusion", "pressure_force_confusion"],
            formulas=[formula("F = pA", "Force on a chosen surface patch equals pressure at the location times patch area", ["N", "Pa", "m^2"], "Use after pressure at the location is known.")],
            representations=[
                representation("surface patch compass", "Shows that the force direction changes with patch orientation while pressure stays fixed at the location."),
                representation("force-on-window panel", "Links pressure value to area and total force."),
            ],
            analogy_map=patch_dome_map("pressure as location value, force as patch-specific direction"),
            worked_examples=[
                worked("A tank window of area 0.30 m^2 is at a point where liquid pressure is 15000 Pa. Find the force on the window.", ["Identify that pressure at the location is already known.", "Use F = pA.", "Substitute 15000 x 0.30 and state the unit."], "The force on the window is 4500 N.", "Force on a chosen patch equals pressure times area, so 15000 Pa over 0.30 m^2 gives 4500 N.", "This is the bridge from point pressure to a real force on a surface."),
                worked("A wall patch and a floor patch are both 2 m below the water surface. Compare their pressures and the directions of the forces on them.", ["Use the same-depth rule first: same water and same depth means same pressure.", "Then identify the patch orientations.", "State the force directions as perpendicular to each patch."], "The pressures are equal, but the wall-patch force is horizontal while the floor-patch force is vertical.", "Pressure belongs to the location, so it matches at equal depth. The direction changes only because each patch faces differently.", "This keeps pressure from being mistaken for a single downward arrow."),
                worked("At one fluid location the pressure is 10000 Pa. A small patch has area 0.10 m^2 and a large patch has area 0.40 m^2. Compare the forces.", ["Keep the pressure fixed across the comparison.", "Use F = pA for each patch.", "Compare how area changes the total force even though the pressure is unchanged."], "The small patch feels 1000 N and the large patch feels 4000 N.", "The same pressure acts at the location, but the larger area collects that pressure over more surface, so the total force is larger.", "This example keeps pressure and force separate while still linking them correctly."),
            ],
            visual_assets=[visual("m4-l5-surface-normal", "surface_force", "Surface Patch Compass", "Compares wall, floor, and slanted patches at one depth.", "Pressure stays with the location; force turns to stay perpendicular to the patch.")],
            animation_assets=[animation("m4-l5-surface-normal-turn", "surface_force", "Turning the Patch", "Shows force direction rotating with the patch while pressure stays fixed.")],
            simulation_contract={
                "asset_id": "m4_l5_surface_patch_lab",
                "concept": "surface_force",
                "baseline_case": "Use one pressure value and one patch area.",
                "comparison_tasks": ["Rotate the patch while keeping depth fixed.", "Keep pressure fixed and compare two patch areas."],
                "watch_for": "Students should say that pressure stays the same at the location while force direction or size can change.",
                "takeaway": "Pressure is scalar at a point; force from pressure acts perpendicular to the chosen surface and grows with area.",
            },
            reflection_prompts=["Why can the same pressure produce different force directions on different surfaces?", "Why can the same pressure produce different force sizes on different areas?"],
            mastery_skills=["Use F = pA", "Separate pressure from force direction", "Explain perpendicular-force behavior in fluids"],
            variation_plan={
                "parameter_axis": "Vary depth, area, and patch orientation separately.",
                "representation_axis": "Move between same-depth comparisons, force arrows, and surface-area calculations.",
                "misconception_axis": "Attack the idea that pressure points downward or equals force.",
            },
            scaffold_support=scaffold(
                "Pressure is a scalar value at a fluid location. The force due to that pressure on a chosen surface acts perpendicular to the surface and scales with area.",
                "Find the pressure at the location first. Then, if the question asks about a real surface, use the patch orientation for direction and the patch area for force size.",
                "If you rotate a patch while leaving it at the same fluid location, what changes and what stays the same?",
                "Do not talk as if pressure itself is a downward arrow. That mixes up pressure with the force on one chosen surface.",
                "The patch chooses the direction of the force, but the fluid location supplies the pressure value.",
                "In the dome, what extra information turns a pressure value into a specific force on a surface?",
                extra_sections=[
                    extra_section("Pressure value versus force response", "Pressure answers what the fluid is doing at the location. Force answers what that pressure does to a chosen patch of given area and orientation."),
                    extra_section("Perpendicular is the rule", "Force due to pressure acts normal to the patch. That is why floor, wall, and slanted surfaces can all feel fluid force correctly."),
                ],
            ),
        ),
    }


def lesson_l6() -> Dict[str, Any]:
    return {
        "id": "M4_L6",
        "title": "Sky Blanket and Total Pressure Missions",
        "sim": {
            "lab_id": "m4_sky_blanket_lab",
            "title": "Sky blanket explorer",
            "description": "Compare atmospheric pressure with altitude and combine it with liquid pressure in mixed pressure missions.",
            "instructions": [
                "Move between a low station and a high station to compare Sky Blanket load.",
                "Add liquid depth below a free surface and combine atmospheric pressure with hydrostatic pressure.",
                "Explain every total pressure answer as sky load plus liquid stack load.",
            ],
            "outcomes": ["atmospheric_pressure_confusion", "total_pressure_confusion"],
            "fields": ["altitude", "atmospheric_pressure", "depth", "liquid_pressure", "total_pressure"],
            "depth": "number of altitude-plus-liquid missions solved as sky-blanket load plus liquid-stack load rather than as disconnected formulas",
        },
        "analogy_text": (
            "The Sky Deck makes air visible as a fluid. Low stations have a thicker Sky Blanket above them, so atmospheric patch load is greater there. "
            "Once a patch is also below a liquid surface, the total patch load becomes sky blanket plus liquid stack."
        ),
        "commitment_prompt": "First decide whether the patch is in air only, liquid only, or liquid plus the Sky Blanket above the surface.",
        "micro_prompts": [
            prompt_block("Why is atmospheric pressure lower on a mountain?", "Use less-air-above language."),
            prompt_block("What does p_total = p_atm + rhogh mean physically?", "Add sky blanket and liquid stack."),
            prompt_block("Why is air still part of pressure even though it is invisible?", "Air still has weight and layers."),
        ],
        "inquiry": [
            prompt_block("Compare the patch load at sea level and on a high station. What changes?", "More air above means larger atmospheric pressure."),
            prompt_block("Now add liquid depth below an open surface. What extra contribution appears?", "The liquid stack adds rhogh."),
            prompt_block("Explain a total pressure reading with words before symbols.", "Use sky blanket + liquid stack."),
        ],
        "recon_prompts": [
            "Atmospheric pressure comes from the weight of the air above and decreases with altitude.",
            "Pressure below the surface of an open liquid can be written as p_total = p_atm + rhogh.",
            "A mixed pressure mission is still one patch-load story: sky blanket plus liquid stack.",
        ],
        "capsule_prompt": "Keep atmospheric pressure real and combine it cleanly with liquid pressure.",
        "capsule_checks": [
            mcq("M4L6_C1", "Why is atmospheric pressure lower at high altitude?", ["Because there is less air above the patch", "Because gravity stops working", "Because air has no weight", "Because pressure only exists in water"], 0, "Use the sky-blanket idea.", ["atmospheric_pressure_confusion"]),
            mcq("M4L6_C2", "What does p_total = p_atm + rhogh mean in words?", ["total pressure equals sky-blanket load plus liquid-stack load", "pressure equals force plus energy", "liquid pressure replaces atmospheric pressure", "air pressure is zero in liquids"], 0, "Add atmosphere and liquid contributions.", ["total_pressure_confusion"]),
            short("M4L6_C3", "Why can air produce pressure even though it is invisible?", ["because air has weight and layers above us", "because the atmosphere is a fluid with weight", "because there is air above the patch"], "Use weight-of-air language.", ["atmospheric_pressure_confusion"], acceptance_rules=acceptance_groups(["air", "atmosphere"], ["weight", "layers", "above", "overhead", "fluid"], ["pressure", "presses", "load"])),
            mcq("M4L6_C4", "At a fixed liquid depth, what happens to total pressure if atmospheric pressure drops?", ["it rises", "it falls", "it stays the same", "it becomes only rhogh automatically"], 1, "Total pressure includes the atmospheric part.", ["total_pressure_confusion"]),
            mcq("M4L6_C5", "Which statement is strongest?", ["Atmospheric pressure is unrelated to altitude", "Air is also a fluid, so lower altitude means more air above and more pressure", "Only solids create pressure", "Air pressure points upward only"], 1, "The sky blanket is still a fluid story.", ["atmospheric_pressure_confusion"]),
            mcq("M4L6_C6", "Which quantity must be added to hydrostatic pressure to get total pressure below an open liquid surface?", ["mass", "atmospheric pressure", "volume", "area"], 1, "Open-surface total pressure includes the atmosphere above.", ["total_pressure_confusion"]),
        ],
        "diagnostic": [
            mcq("M4L6_D1", "Why is atmospheric pressure generally higher at sea level than on a mountain?", ["More air lies above sea level", "Sea level has no gravity", "Mountains remove density from water", "Pressure depends only on area"], 0, "Use sky-blanket language.", ["atmospheric_pressure_confusion"]),
            mcq("M4L6_D2", "What is the total pressure 2 m below the surface of water if p_atm = 100000 Pa, rho = 1000 kg/m^3, and g = 10 N/kg?", ["20000 Pa", "100000 Pa", "120000 Pa", "140000 Pa"], 2, "Add p_atm + rhogh.", ["total_pressure_confusion"]),
            short("M4L6_D3", "Water is open to the atmosphere. At depth 5 m, with p_atm = 100000 Pa, rho = 1000 kg/m^3, and g = 10 N/kg, what is the total pressure?", ["150000 Pa", "150000"], "Add atmospheric and hydrostatic pressure.", ["total_pressure_confusion"], acceptance_rules=acceptance_groups(["150000"])),
            mcq("M4L6_D4", "Which change lowers atmospheric pressure most directly?", ["going to a lower altitude", "going to a higher altitude", "using a wider window", "painting the tank"], 1, "Higher altitude means less air above.", ["atmospheric_pressure_confusion"]),
            short("M4L6_D5", "Why is total pressure below an open liquid surface larger than rhogh alone?", ["because atmospheric pressure is also pressing on the surface", "because the sky blanket adds to the liquid stack", "because total pressure includes air pressure plus hydrostatic pressure"], "Mention the atmosphere or sky blanket explicitly.", ["total_pressure_confusion"], acceptance_rules=acceptance_groups(["atmosphere", "air", "sky"], ["add", "plus", "also"], ["pressure", "surface", "rhogh", "liquid"])),
            mcq("M4L6_D6", "Which statement is wrong?", ["Air is also a fluid", "Atmospheric pressure comes from the weight of air above", "Atmospheric pressure increases with altitude", "Total pressure in an open liquid includes atmospheric pressure"], 2, "Atmospheric pressure decreases with altitude.", ["atmospheric_pressure_confusion"]),
            mcq("M4L6_D7", "If atmospheric pressure stays the same but depth doubles in the same liquid, total pressure...", ["increases", "decreases", "stays the same", "becomes only atmospheric"], 0, "The liquid part grows while the atmospheric part stays fixed.", ["total_pressure_confusion"]),
            mcq("M4L6_D8", "What does the Sky Blanket represent in this model?", ["temperature", "the atmosphere pressing because of the air above", "electric field", "contact area only"], 1, "Air layers above the patch create atmospheric pressure.", ["atmospheric_pressure_confusion"]),
        ],
        "transfer": [
            mcq("M4L6_M1", "A mountain station has less atmospheric pressure mainly because...", ["there is less air above it", "the liquid density changes", "its patches are smaller", "force and pressure become the same"], 0, "Use less-air-above reasoning.", ["atmospheric_pressure_confusion"]),
            short("M4L6_M2", "At depth 3 m in water, with p_atm = 100000 Pa, what is the total pressure if rho = 1000 kg/m^3 and g = 10 N/kg?", ["130000 Pa", "130000"], "Use p_total = p_atm + rhogh.", ["total_pressure_confusion"], acceptance_rules=acceptance_groups(["130000"])),
            mcq("M4L6_M3", "Which quantity stays the same when moving from sea level to a mountain in the same liquid tank if depth and liquid are unchanged?", ["atmospheric pressure", "rhogh", "total pressure", "air above"], 1, "The liquid stack part can stay the same while the atmospheric part changes.", ["total_pressure_confusion"]),
            mcq("M4L6_M4", "Why is air pressure part of the same pressure family as solid and liquid pressure in this module?", ["Because pressure is always push per patch, and air can load patches too", "Because air is solid", "Because atmospheric pressure ignores area", "Because liquid pressure disappears in air"], 0, "The unifying idea is patch load.", ["atmospheric_pressure_confusion"]),
            short("M4L6_M5", "Why does the atmosphere matter in an open liquid pressure problem?", ["because it presses on the surface and adds to the total pressure", "because atmospheric pressure is part of p_total", "because the sky blanket adds before the liquid stack does"], "Use add-to-total language.", ["total_pressure_confusion"], acceptance_rules=acceptance_groups(["atmosphere", "air", "sky"], ["add", "plus", "part of"], ["total", "pressure", "surface"])),
            mcq("M4L6_M6", "At which location is atmospheric pressure generally greater?", ["a valley station", "a high mountain station", "they must be equal", "pressure only exists underwater"], 0, "Lower altitude means more air above.", ["atmospheric_pressure_confusion"]),
            mcq("M4L6_M7", "A liquid patch is open to the atmosphere. Which expression gives the pressure due only to the liquid layers, not the total?", ["p_atm", "rhogh", "p_atm + rhogh", "F/A only"], 1, "rhogh is the hydrostatic contribution only.", ["total_pressure_confusion"]),
            mcq("M4L6_M8", "Which statement best fits a full Patch-Dome capstone answer?", ["Name the sky blanket, the liquid stack, and how they combine at the patch", "Say pressure is just force", "Ignore the atmosphere unless the question says mountain", "Talk only about container shape"], 0, "Capstone answers combine the contributions explicitly.", ["total_pressure_confusion"]),
        ],
        "contract": contract(
            concept_targets=["Atmospheric pressure from air weight", "Altitude effect", "Total pressure in an open liquid"],
            prerequisite_lessons=["M4_L3", "M4_L4", "M4_L5"],
            misconception_focus=["atmospheric_pressure_confusion", "total_pressure_confusion"],
            formulas=[formula("p_total = p_atm + rhogh", "Total pressure below an open liquid surface", ["Pa", "Pa", "kg/m^3", "N/kg", "m"], "Use when atmospheric pressure above the liquid surface matters.")],
            representations=[
                representation("sky blanket meter", "Shows more air above low stations and less air above high stations."),
                representation("open-surface pressure ladder", "Separates atmospheric and liquid contributions to total pressure."),
            ],
            analogy_map=patch_dome_map("sky blanket plus liquid stack"),
            worked_examples=[
                worked("Find the total pressure 2 m below the surface of water when p_atm = 100000 Pa, rho = 1000 kg/m^3, and g = 10 N/kg.", ["Identify an open-surface liquid problem, so total pressure includes atmosphere and liquid.", "Find the liquid part: rhogh = 1000 x 10 x 2 = 20000 Pa.", "Add atmospheric pressure: 100000 + 20000."], "The total pressure is 120000 Pa.", "Open-surface total pressure is atmospheric pressure plus hydrostatic pressure, so 100000 Pa + 20000 Pa = 120000 Pa.", "This is the module's capstone pressure sum: sky blanket plus liquid stack."),
                worked("Why is atmospheric pressure lower on a mountain station than at sea level?", ["Treat air as a fluid with layers and weight.", "Compare how much air lies above each station.", "State the patch-load consequence for the lower and higher station."], "Atmospheric pressure is lower on the mountain because there is less air above that patch.", "The sky blanket is thinner at high altitude, so the patch carries less air weight above it and the atmospheric pressure is smaller.", "This keeps atmospheric pressure inside the same unified pressure world as liquids and solids."),
                worked("Water is open to the atmosphere. At one station p_atm = 90000 Pa. At depth 4 m in water with rho = 1000 kg/m^3 and g = 10 N/kg, find the total pressure.", ["Find the liquid stack contribution first: rhogh = 1000 x 10 x 4 = 40000 Pa.", "Keep the local atmospheric pressure visible because it is not sea-level standard here.", "Add 90000 Pa + 40000 Pa."], "The total pressure is 130000 Pa.", "Total pressure below the open surface combines the local atmospheric pressure with the liquid contribution, so 90000 Pa + 40000 Pa = 130000 Pa.", "This example keeps altitude and liquid depth in the same pressure account."),
            ],
            visual_assets=[visual("m4-l6-sky-blanket", "atmospheric_pressure", "Sky Blanket Board", "Compares low and high stations and then adds liquid depth below an open surface.", "Air also loads patches, and total open-liquid pressure adds sky blanket to liquid stack.")],
            animation_assets=[animation("m4-l6-sky-blanket-shift", "atmospheric_pressure", "Rising to Higher Altitude", "Shows atmospheric pressure falling as the sky blanket thins.")],
            simulation_contract={
                "asset_id": "m4_l6_sky_blanket_lab",
                "concept": "atmospheric_pressure",
                "baseline_case": "Start at a low station with one open-surface liquid depth.",
                "comparison_tasks": ["Compare sea-level and mountain atmospheric pressure.", "Keep altitude fixed and change liquid depth to see the total pressure sum."],
                "watch_for": "Students should explain total pressure as atmosphere plus liquid contribution rather than as one unexplained number.",
                "takeaway": "Air is also a fluid. Low altitude means more sky blanket, and open-liquid total pressure adds that sky load to rhogh.",
            },
            reflection_prompts=["Why is atmospheric pressure lower higher up?", "Why is total pressure below an open liquid surface larger than rhogh alone?"],
            mastery_skills=["Explain atmospheric pressure conceptually", "Use p_total = p_atm + rhogh", "Solve mixed air-plus-liquid pressure problems"],
            variation_plan={
                "parameter_axis": "Vary altitude and liquid depth independently.",
                "representation_axis": "Move between sky-blanket stories, open-surface diagrams, and total-pressure sums.",
                "misconception_axis": "Confront the idea that air pressure is negligible or unrelated to fluid pressure.",
            },
            scaffold_support=scaffold(
                "Air is also a fluid, so atmospheric pressure comes from the weight of the air above. Below an open liquid surface, total pressure is sky blanket plus liquid stack.",
                "Decide first whether the patch is in air only or in liquid open to the air. If it is open to the atmosphere, keep p_atm visible and then add the liquid part rhogh.",
                "If a liquid patch is open to the air, what two contributions must you look for before calculating total pressure?",
                "Do not treat rhogh as automatically the total pressure in every liquid problem. Open surfaces still have the atmosphere above them.",
                "The Sky Deck makes the invisible atmosphere visible as a blanket of air layers pressing on the dome. Once a liquid sits beneath it, the patch load becomes sky blanket plus liquid stack.",
                "In the dome, why does climbing higher lower the patch load from the sky blanket?",
                extra_sections=[
                    extra_section("Air belongs in the pressure family", "Atmospheric pressure is not a separate magical topic. It is another example of patch load from layers above."),
                    extra_section("Open-surface bookkeeping", "Below an open liquid surface, total pressure is an addition problem: atmospheric contribution plus hydrostatic contribution."),
                ],
            ),
        ),
    }


M4_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V2,
    "module_description": (
        "Pressure in solids, liquid pressure, and atmospheric pressure. Separate pressure from force, track how area and depth "
        "matter, and use the main pressure equations carefully."
    ),
    "mastery_outcomes": [
        "Explain pressure in solids as force spread over area rather than force alone.",
        "Use and rearrange P = F/A to analyse and design safe footprints.",
        "Explain liquid pressure as growing with density, World Pull, and depth.",
        "Use the same-depth rule to reject vessel-shape misconceptions.",
        "Distinguish scalar pressure at a point from the force due to pressure on a surface.",
        "Explain atmospheric pressure as the weight of the air above and compare altitude effects.",
        "Use p_total = p_atm + rhogh in mixed pressure missions.",
    ],
    "lessons": [
        lesson_l1(),
        lesson_l2(),
        lesson_l3(),
        lesson_l4(),
        lesson_l5(),
        lesson_l6(),
    ],
}


for lesson in M4_SPEC["lessons"]:
    lesson["contract"]["assessment_bank_targets"] = assessment_targets(8, 6, 8)


RELEASE_CHECKS = [
    "Every lesson keeps pressure distinct from total force and shows what area or location is doing.",
    "Every worked example states why the answer follows, not just the arithmetic.",
    "Every simulation contract requires at least one comparison and one misconception-facing explanation.",
    "Pressure in solids, liquids, and air stays inside one Patch-Dome world instead of three disconnected topic worlds.",
]


M4_MODULE_DOC, M4_LESSONS, M4_SIM_LABS = build_nextgen_module_bundle(
    module_id=M4_MODULE_ID,
    module_title=M4_MODULE_TITLE,
    module_spec=M4_SPEC,
    allowlist=M4_ALLOWLIST,
    content_version=M4_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=8,
    level="Module 4",
    estimated_minutes=270,
    authoring_standard=AUTHORING_STANDARD_V2,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M4 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    apply = bool(args.apply)
    asset_root = args.asset_root or default_asset_root()

    module_doc = deepcopy(M4_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M4_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M4_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M4_MODULE_ID)]
    plan.extend(("lessons", doc_id) for doc_id, _ in lesson_pairs)
    plan.extend(("sim_labs", doc_id) for doc_id, _ in sim_pairs)

    for collection, doc_id in plan:
        if collection == "modules":
            upsert_doc(db, collection, doc_id, module_doc, apply)
        elif collection == "lessons":
            payload = next(payload for payload_id, payload in lesson_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, apply)
        else:
            payload = next(payload for payload_id, payload in sim_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, apply)


if __name__ == "__main__":
    main()
