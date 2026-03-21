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


A2_MODULE_ID = "A2"
A2_CONTENT_VERSION = "20260321_a2_charge_terrace_mesh_v1"
A2_MODULE_TITLE = "Advanced Electricity"
A2_ALLOWLIST = [
    "field_force_same_confusion",
    "field_exists_without_test_charge_confusion",
    "field_direction_negative_charge_confusion",
    "equipotential_energy_change_confusion",
    "equipotential_parallel_field_confusion",
    "potential_current_same_confusion",
    "uniform_field_voltage_distance_confusion",
    "capacitor_charge_crosses_gap_confusion",
    "capacitance_charge_voltage_same_confusion",
    "capacitance_geometry_confusion",
    "capacitor_energy_location_confusion",
    "node_potential_everywhere_different_confusion",
    "junction_current_loss_confusion",
    "parallel_voltage_current_mixup",
    "kvl_all_voltages_equal_confusion",
    "complex_circuit_branch_voltage_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(A2_ALLOWLIST)
    return [str(tag) for tag in tags if str(tag) in allowed]


def mcq(
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
        "misconception_tags": safe_tags(tags),
        "skill_tags": [str(tag) for tag in skill_tags],
    }


def short(
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
        "misconception_tags": safe_tags(tags),
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


def visual(asset_id: str, concept: str, title: str, purpose: str, caption: str) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": "auto",
        "meta": {"module_family": "charge_terrace_mesh"},
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
        "diagnostic_pool_min": 10,
        "concept_gate_pool_min": 8,
        "mastery_pool_min": 10,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile layouts.",
        "Field arrows, terrace labels, and plate or node markers remain separated so the electric story does not collapse into one crowded cluster.",
        "Potential, current, and capacitance badges stay outside the main geometry so value cues do not hide the physical meaning.",
        "Guide labels for nodes, loops, and capacitor decks stay readable without clipping into plate gaps or branch paths.",
    ]


def terrace_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Charge-Terrace Mesh Model",
        "focus": focus,
        "comparison": f"The Charge-Terrace world keeps field, potential, capacitance, and Kirchhoff analysis inside one electric-height story while {focus}.",
        "mapping": [
            "Scout charge -> positive test charge",
            "Terrace height -> electric potential",
            "Terrace drop -> potential difference",
            "Slope arrow -> electric field",
            "Same-terrace line -> equipotential path",
            "Lift tower -> cell or emf source",
            "Drop ramp -> resistor or component voltage drop",
            "Node platform -> common-potential node",
            "Split-Deck Store -> capacitor",
            "Hold capacity -> capacitance",
            "Junction count rule -> Kirchhoff current law",
            "Loop height rule -> Kirchhoff voltage law",
        ],
        "limit": "The terrace picture is a meaning-first map, but learners still need the formal field, potential, capacitance, and circuit-law equations.",
        "prediction_prompt": f"Use the Charge-Terrace mesh to predict what should happen when {focus}.",
    }


def sim_contract(
    asset_id: str,
    concept: str,
    focus_prompt: str,
    baseline_case: str,
    comparison_tasks: Sequence[str],
    watch_for: str,
    takeaway: str,
    controls: Sequence[Tuple[str, str, str]],
    readouts: Sequence[Tuple[str, str]],
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "focus_prompt": focus_prompt,
        "baseline_case": baseline_case,
        "comparison_tasks": list(comparison_tasks),
        "watch_for": watch_for,
        "takeaway": takeaway,
        "controls": [
            {"variable": variable, "label": label, "why_it_matters": why_it_matters}
            for variable, label, why_it_matters in controls
        ],
        "readouts": [{"label": label, "meaning": meaning} for label, meaning in readouts],
    }


def contract(
    *,
    concept_targets: Sequence[str],
    core_concepts: Sequence[str],
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
    visual_clarity_checks: Sequence[str],
) -> Dict[str, Any]:
    return {
        "concept_targets": list(concept_targets),
        "core_concepts": list(core_concepts),
        "prerequisite_lessons": list(prerequisite_lessons),
        "misconception_focus": safe_tags(misconception_focus),
        "formulas": [deepcopy(item) for item in formulas],
        "representations": [deepcopy(item) for item in representations],
        "analogy_map": deepcopy(analogy_map),
        "worked_examples": [deepcopy(item) for item in worked_examples],
        "visual_assets": [deepcopy(item) for item in visual_assets],
        "animation_assets": [deepcopy(item) for item in animation_assets],
        "simulation_contract": deepcopy(simulation_contract),
        "reflection_prompts": list(reflection_prompts),
        "mastery_skills": list(mastery_skills),
        "variation_plan": deepcopy(variation_plan),
        "assessment_bank_targets": assessment_targets(),
        "scaffold_support": deepcopy(scaffold_support),
        "visual_clarity_checks": list(visual_clarity_checks),
    }


def sim(
    lab_id: str,
    title: str,
    description: str,
    instructions: Sequence[str],
    outcomes: Sequence[str],
    fields: Sequence[str],
    depth: str,
) -> Dict[str, Any]:
    return {
        "lab_id": lab_id,
        "title": title,
        "description": description,
        "instructions": list(instructions),
        "outcomes": list(outcomes),
        "fields": list(fields),
        "depth": depth,
    }


def lesson_spec(
    lesson_id: str,
    title: str,
    sim_meta: Dict[str, Any],
    diagnostic: Sequence[Dict[str, Any]],
    analogy_text: str,
    commitment_prompt: str,
    micro_prompts: Sequence[Dict[str, str]],
    inquiry: Sequence[Dict[str, str]],
    recon_prompts: Sequence[str],
    capsule_prompt: str,
    capsule_checks: Sequence[Dict[str, Any]],
    transfer: Sequence[Dict[str, Any]],
    contract_payload: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "id": lesson_id,
        "title": title,
        "sim": deepcopy(sim_meta),
        "diagnostic": list(diagnostic),
        "analogy_text": analogy_text,
        "commitment_prompt": commitment_prompt,
        "micro_prompts": list(micro_prompts),
        "inquiry": list(inquiry),
        "recon_prompts": list(recon_prompts),
        "capsule_prompt": capsule_prompt,
        "capsule_checks": list(capsule_checks),
        "transfer": list(transfer),
        "contract": deepcopy(contract_payload),
    }


def lesson_one() -> Dict[str, Any]:
    diagnostic = [
        mcq("A2L1_D1", "In the terrace model, a positive scout near a positive source charge is pushed...", ["away from the source", "toward the source", "sideways only", "nowhere"], 0, "A positive source creates outward field direction for a positive scout.", ["field_force_same_confusion"], skill_tags=["field_direction"]),
        mcq("A2L1_D2", "Electric field at a point is best described as...", ["force per unit positive charge", "total force on any object", "energy stored per unit charge", "current per unit area"], 0, "Field is the local push per unit positive test charge.", ["field_force_same_confusion"], skill_tags=["field_definition"]),
        mcq("A2L1_D3", "If the field at a point doubles for the same test charge, the force on that test charge...", ["doubles", "halves", "stays the same", "reverses automatically"], 0, "F = qE for a fixed charge.", ["field_force_same_confusion"], skill_tags=["field_force_relation"]),
        mcq("A2L1_D4", "Which statement is strongest?", ["The field exists at the location even before the scout is placed there.", "The field appears only when the scout charge is inserted.", "The field belongs only to negative charges.", "The field is the same as the force on the scout."], 0, "The field belongs to the location created by source charges.", ["field_exists_without_test_charge_confusion"], skill_tags=["field_exists_without_probe"]),
        mcq("A2L1_D5", "A negative scout in a rightward electric field feels a force...", ["leftward", "rightward", "upward", "zero"], 0, "A negative charge feels force opposite to field direction.", ["field_direction_negative_charge_confusion"], skill_tags=["negative_charge_force"]),
        mcq("A2L1_D6", "A steeper terrace slope corresponds to...", ["a stronger electric field", "a smaller electric field", "zero potential difference", "an equipotential route"], 0, "Stronger field means steeper slope.", ["field_force_same_confusion"], skill_tags=["field_strength"]),
        mcq("A2L1_D7", "Using E = F / q, a 6 N force on a 2 C positive scout gives field strength...", ["3 N/C", "12 N/C", "4 N/C", "0.33 N/C"], 0, "Divide force by charge.", ["field_force_same_confusion"], skill_tags=["field_calculation"]),
        mcq("A2L1_D8", "Which picture matches the field around an isolated negative source charge?", ["arrows pointing inward", "arrows pointing outward", "arrows tangential to circles", "no arrows anywhere"], 0, "Field points toward a negative source for a positive scout.", ["field_direction_negative_charge_confusion"], skill_tags=["field_direction"]),
        short("A2L1_D9", "Why is electric field not the same quantity as electric force?", ["Because field belongs to the location and gives force per unit charge, while force depends on the particular charge placed there.", "Because electric field is the local push map, but force depends on both that field and the charge used as the probe."], "Separate the location quantity from the test-charge quantity.", ["field_force_same_confusion"], skill_tags=["field_definition", "field_force_relation"], acceptance_rules=acceptance_groups(["field", "location", "point"], ["force per unit charge", "per unit positive charge"], ["force", "depends on the charge", "particular charge"])) ,
        short("A2L1_D10", "Why does a negative scout not move in the same direction as the field arrow?", ["Because the field arrow is defined by the force on a positive scout, so a negative charge feels force in the opposite direction.", "Because electric field direction follows a positive test charge, so a negative test charge is pushed opposite to that arrow."], "Use positive-test-charge language explicitly.", ["field_direction_negative_charge_confusion"], skill_tags=["negative_charge_force", "field_direction"], acceptance_rules=acceptance_groups(["positive scout", "positive test charge"], ["negative charge"], ["opposite direction", "opposite the field", "opposite to the arrow"])) ,
    ]
    concept = [
        mcq("A2L1_C1", "At a point where E = 5 N/C to the right, the force on a +3 C scout is...", ["15 N to the right", "15 N to the left", "8 N to the right", "2 N to the right"], 0, "Use F = qE.", ["field_force_same_confusion"], skill_tags=["field_force_relation"]),
        mcq("A2L1_C2", "At the same point, the force on a -3 C scout is...", ["15 N to the left", "15 N to the right", "5 N to the left", "3 N to the right"], 0, "A negative charge reverses the force direction.", ["field_direction_negative_charge_confusion"], skill_tags=["negative_charge_force"]),
        mcq("A2L1_C3", "If the field near a source becomes weaker with distance, the terrace picture says the surface is becoming...", ["less steep", "more steep", "perfectly flat only", "higher only"], 0, "Weaker field means less slope.", ["field_force_same_confusion"], skill_tags=["field_strength"]),
        mcq("A2L1_C4", "Which is the best probe for defining field direction?", ["a positive test charge", "a negative test charge", "a neutral object", "a capacitor plate"], 0, "Field direction is defined using a positive scout.", ["field_exists_without_test_charge_confusion"], skill_tags=["field_definition"]),
        mcq("A2L1_C5", "If a 1.5 C scout feels 9 N, the field strength is...", ["6 N/C", "13.5 N/C", "7.5 N/C", "0.17 N/C"], 0, "E = F / q.", ["field_force_same_confusion"], skill_tags=["field_calculation"]),
        mcq("A2L1_C6", "Which summary is strongest?", ["Field lines show what a positive scout would do at each point.", "Field lines show the path every charge must permanently travel.", "Field is the same thing as current.", "Field exists only inside wires."], 0, "Field is a spatial push map for a positive scout.", ["field_exists_without_test_charge_confusion"], skill_tags=["field_definition"]),
        short("A2L1_C7", "Why is it useful to imagine a tiny scout charge even though the field exists without it?", ["Because the scout lets us reveal the direction and strength of the local push without claiming the field depends on the scout.", "Because the scout is a probe for the field map, not the source of the field itself."], "Make the scout a probe, not the creator.", ["field_exists_without_test_charge_confusion"], skill_tags=["field_exists_without_probe"], acceptance_rules=acceptance_groups(["scout", "probe", "test charge"], ["reveal", "show", "measure"], ["field exists", "not create", "not source"])) ,
        short("A2L1_C8", "A learner says, 'A bigger test charge creates a bigger field there.' What is the correction?", ["The field at the location is set by the source charges; a bigger test charge only feels a bigger force in that same field.", "Changing the test charge changes the force, not the field created by the source."], "Keep source-created field separate from test-charge force.", ["field_force_same_confusion"], skill_tags=["field_definition", "field_force_relation"], acceptance_rules=acceptance_groups(["field", "set by source", "location"], ["test charge"], ["force changes", "not the field", "same field"])) ,
    ]
    mastery = [
        mcq("A2L1_M1", "A +2 C scout in a 7 N/C field feels force...", ["14 N in the field direction", "14 N opposite the field", "9 N in the field direction", "3.5 N in the field direction"], 0, "Multiply q by E.", ["field_force_same_confusion"], skill_tags=["field_force_relation"]),
        mcq("A2L1_M2", "A -2 C scout in that same field feels force...", ["14 N opposite the field", "14 N in the field direction", "5 N opposite the field", "7 N in the field direction"], 0, "Negative charge flips the force direction.", ["field_direction_negative_charge_confusion"], skill_tags=["negative_charge_force"]),
        mcq("A2L1_M3", "If force is 18 N on a +3 C scout, the field is...", ["6 N/C", "54 N/C", "15 N/C", "0.17 N/C"], 0, "E = F / q.", ["field_force_same_confusion"], skill_tags=["field_calculation"]),
        mcq("A2L1_M4", "Which quantity belongs to the location rather than the chosen scout?", ["electric field", "force on that scout", "weight of that scout", "charge on that scout"], 0, "The field belongs to the location.", ["field_force_same_confusion"], skill_tags=["field_definition"]),
        mcq("A2L1_M5", "Near a positive source charge the field direction is...", ["away from the charge", "toward the charge", "clockwise", "undefined"], 0, "Positive source means outward field.", ["field_force_same_confusion"], skill_tags=["field_direction"]),
        mcq("A2L1_M6", "Near a negative source charge the field direction is...", ["toward the charge", "away from the charge", "upward only", "zero always"], 0, "Negative source means inward field.", ["field_direction_negative_charge_confusion"], skill_tags=["field_direction"]),
        short("A2L1_M7", "Why does a stronger field mean a steeper terrace map?", ["Because stronger field means a larger force per unit positive charge, which the model represents as a steeper local slope.", "Because the field is the slope arrow, so increasing field strength means making the electric terrace steeper."], "Link slope and force-per-unit-charge directly.", ["field_force_same_confusion"], skill_tags=["field_strength"], acceptance_rules=acceptance_groups(["stronger field", "field strength"], ["steeper", "slope"], ["force per unit charge", "positive charge"])) ,
        short("A2L1_M8", "Summarize Lesson 1 in one strong sentence.", ["Electric field is the local push map at a point, defined for a positive scout and separate from the force felt by any particular charge.", "The field belongs to the location, and force on a charge comes from combining that field with the charge placed there."], "Keep the summary focused on field as a location quantity.", ["field_force_same_confusion"], skill_tags=["field_definition"], acceptance_rules=acceptance_groups(["field", "location", "point"], ["positive scout", "positive test charge"], ["force", "particular charge", "depends"])) ,
        mcq("A2L1_M9", "A learner puts a neutral object at a point and says the field must now be zero because there is no force formula to use. The best correction is...", ["The field can still exist there; the test object choice does not create or erase the field.", "Neutral objects create infinite field.", "Field only exists where current flows.", "Field becomes voltage automatically."], 0, "Field belongs to the space around source charges.", ["field_exists_without_test_charge_confusion"], skill_tags=["field_exists_without_probe"]),
        mcq("A2L1_M10", "Best final lesson summary:", ["The field is the slope, the scout is only the probe, and negative charges feel force opposite to the field.", "The field is the same as the force on every charge.", "A scout charge creates the field wherever it moves.", "Field arrows point where negative charges must travel."], 0, "That statement keeps the model distinctions intact.", ["field_force_same_confusion", "field_direction_negative_charge_confusion"], skill_tags=["field_definition", "negative_charge_force"]),
    ]
    return lesson_spec(
        "A2_L1",
        "Scout Charges and Slope Arrows",
        sim(
            "a2_field_slope_lab",
            "Scout slope lab",
            "Place positive and negative scouts on the terrace map and compare the local field arrow with the actual force direction.",
            ["Choose the source sign.", "Read the local field arrow.", "Switch the scout sign and compare the force direction."],
            ["Describe electric field as a location quantity.", "Separate field direction from force direction on negative charges.", "Use E = F / q in a simple case."],
            ["source_sign", "scout_sign", "distance", "field_strength", "force_direction"],
            "Field-force distinction.",
        ),
        diagnostic,
        "The arena is covered by invisible electric terraces. A positive scout charge reveals the slope arrow at each point, but the slope already exists before the scout arrives. Positive sources push the scout away, negative sources pull it inward, and a negative scout flips the force direction even though the field arrow itself does not flip.",
        "Treat the field as the map of the place before you talk about the force on a chosen charge.",
        [
            prompt_block("What does the slope arrow represent?", "It shows the electric field direction for a positive scout."),
            prompt_block("What changes when you swap a positive scout for a negative scout?", "The force direction reverses, but the field at the point does not."),
        ],
        [
            prompt_block("Keep the same source charge and move the scout farther away.", "The slope should become less steep, so the field weakens."),
            prompt_block("Keep the same field and flip the scout sign.", "The force direction should reverse even though the field arrow stays the same."),
        ],
        [
            "Why is the field a property of the location rather than of the chosen scout?",
            "Why is a negative charge pushed opposite to the field arrow?",
        ],
        "Use the terrace map to keep field, force, and test charge from collapsing into one vague idea.",
        concept,
        mastery,
        contract(
            concept_targets=["Interpret electric field as force per unit positive charge.", "Use a positive scout to define field direction.", "Distinguish field direction from force direction on negative charges."],
            core_concepts=["Electric field belongs to the location, not to the chosen test charge.", "Field direction is defined using a positive scout charge.", "Force on a charge follows F = qE.", "A stronger field means a steeper terrace slope."],
            prerequisite_lessons=["M10_L1", "M10_L3"],
            misconception_focus=["field_force_same_confusion", "field_exists_without_test_charge_confusion", "field_direction_negative_charge_confusion"],
            formulas=[relation("E = F / q", "Electric field is force per unit charge.", ["N/C"], "Use with a positive test-charge definition."), relation("F = qE", "Force on a charge in an electric field.", ["N"], "The sign of q sets whether the force follows or opposes the field.")],
            representations=[representation("words", "Explains the field as a local slope map."), representation("formula", "Connects field to force and charge."), representation("diagram", "Shows field arrows around source charges."), representation("model", "Uses the Charge-Terrace scout and slope picture.")],
            analogy_map=terrace_map("the learner compares the slope arrow with the force on positive and negative scouts"),
            worked_examples=[worked("A +2 C scout is placed in a 4 N/C field. Find the force.", ["Use F = qE.", "Substitute 2 x 4.", "Keep the force in the field direction for a positive charge."], "8 N in the field direction", "Positive charges follow the field arrow in the model.", "This anchors the basic force-field link."), worked("A -3 C scout is placed in a 5 N/C rightward field. Describe the force.", ["Use F = qE for the magnitude.", "Compute 3 x 5 = 15 N.", "Reverse the direction because the charge is negative."], "15 N opposite the field", "Negative charges feel force opposite to the field direction.", "This protects the sign-direction distinction."), worked("A learner says the field gets bigger because they used a bigger test charge. Diagnose the error.", ["Keep the source charges responsible for the field.", "Note that changing the probe changes the force only.", "Restore the idea of field as a location quantity."], "The learner is mixing field with force", "Field belongs to the point; force depends on the chosen charge.", "This blocks the biggest lesson-one confusion.")],
            visual_assets=[visual("a2_l1_slope_map_diagram", "field_slope", "Slope arrows show the local electric push", "Show positive and negative source charges, the local field direction, and the difference between field arrow and force on positive versus negative scouts.", "The field is the slope map; the scout only reveals it.")],
            animation_assets=[animation("a2_l1_slope_map_animation", "field_slope", "Positive and negative scouts in one field", "Animate the same field arrow while positive and negative scouts feel opposite force directions.")],
            simulation_contract=sim_contract(
                "a2_l1_field_slope_sim",
                "field_slope",
                "Compare source sign, scout sign, and distance so the local field stays separate from the chosen charge.",
                "Start with a positive source and a positive scout at moderate distance.",
                ["Flip the source sign and compare the field arrow.", "Keep the field fixed and flip the scout sign to compare the force."],
                "Watch for the field staying tied to the location while only the force direction changes for a negative scout.",
                "Electric field is the local slope map, and the chosen scout only tells you how a specific charge responds to it.",
                controls=[("source_sign", "Source sign", "Changes whether the terrace slopes away from or toward the source."), ("scout_sign", "Scout sign", "Changes whether the force follows or opposes the field."), ("distance", "Distance", "Changes field strength through terrace steepness.")],
                readouts=[("Field arrow", "Shows the local field direction for a positive scout."), ("Force arrow", "Shows the actual force on the chosen scout."), ("Field strength", "Shows the magnitude of the local electric field.")],
            ),
            reflection_prompts=["Explain why the same field can push positive and negative charges in opposite directions without the field itself changing.", "Describe why electric field is better thought of as a location map than as a property of the moving charge."],
            mastery_skills=["field_definition", "field_direction", "field_force_relation", "negative_charge_force", "field_strength"],
            variation_plan={"diagnostic": "Fresh attempts rotate between field-direction statements, positive-versus-negative scout comparisons, and simple E = F / q prompts with new numbers.", "concept_gate": "Concept checks vary between probe-language corrections, field-map interpretations, and short force-direction explanations.", "mastery": "Mastery alternates between conceptual summaries, sign-direction reasoning, and quick field-force calculations so new attempts prefer new stems and values."},
            scaffold_support=scaffold("Field is the slope of the electric terrace.", "Read the field arrow from the location first, then decide what a chosen charge would do there.", "Which part belongs to the point, and which part depends on the charge you place there?", "Treating field and force as the same quantity.", "The terrace exists before the scout arrives. The scout only reveals the local slope arrow.", "Why does a negative scout not redefine the field arrow itself?", extras=[extra_section("Scout rule", "The field arrow is always defined by the force on a positive scout, even if you later place a negative charge there.", "Which charge defines the field direction?"), extra_section("Steepness rule", "A steeper terrace means a stronger field, because a positive scout would feel more force per unit charge there.", "What does a steeper slope mean physically?")]),
            visual_clarity_checks=visual_checks("field-map"),
        ),
    )


def lesson_two() -> Dict[str, Any]:
    diagnostic = [
        mcq("A2L2_D1", "Terrace height stands for...", ["electric potential", "current", "force", "resistance"], 0, "Terrace height is the electric height per unit charge.", ["potential_current_same_confusion"], skill_tags=["potential_meaning"]),
        mcq("A2L2_D2", "A terrace drop is best matched to...", ["potential difference", "electric field line count", "resistance only", "capacitance"], 0, "A drop between two points is potential difference.", ["potential_current_same_confusion"], skill_tags=["potential_difference"]),
        mcq("A2L2_D3", "Moving along the same equipotential line changes electric potential by...", ["0 V", "1 V", "the electric field value", "the current value"], 0, "Equipotential means same potential everywhere on that route.", ["equipotential_energy_change_confusion"], skill_tags=["equipotential_reasoning"]),
        mcq("A2L2_D4", "Equipotential lines are drawn...", ["perpendicular to electric field lines", "parallel to electric field lines", "only inside capacitors", "only inside wires"], 0, "Field crosses equipotential paths, not runs along them.", ["equipotential_parallel_field_confusion"], skill_tags=["field_equipotential_link"]),
        mcq("A2L2_D5", "Delta V = Delta U / q means voltage is...", ["energy change per unit charge", "current divided by resistance", "force per unit charge", "charge per unit time"], 0, "Potential difference is energy change per unit charge.", ["potential_current_same_confusion"], skill_tags=["potential_difference"]),
        mcq("A2L2_D6", "If a charge moves from 12 V to 7 V, the terrace drop is...", ["5 V", "19 V", "7 V", "-5 C"], 0, "Potential difference is the change in electric height.", ["potential_current_same_confusion"], skill_tags=["potential_difference"]),
        mcq("A2L2_D7", "A same-terrace route requires...", ["no change in electric potential energy for the same charge", "zero field everywhere in the whole region", "zero charge everywhere", "a battery"], 0, "Along an equipotential path there is no potential change.", ["equipotential_energy_change_confusion"], skill_tags=["equipotential_reasoning"]),
        mcq("A2L2_D8", "If a 3 C charge loses 12 J of electric potential energy, the terrace drop is...", ["4 V", "36 V", "9 V", "0.25 V"], 0, "Use Delta V = Delta U / q.", ["potential_current_same_confusion"], skill_tags=["voltage_calculation"]),
        short("A2L2_D9", "Why does moving along a same-terrace line require no energy change?", ["Because the potential is the same at every point on that line, so there is no potential difference to change the charge's electric potential energy.", "Because an equipotential path has zero terrace drop, so the energy per charge does not change along it."], "Use same-potential or zero-drop language.", ["equipotential_energy_change_confusion"], skill_tags=["equipotential_reasoning"], acceptance_rules=acceptance_groups(["same potential", "equipotential", "same terrace"], ["no potential difference", "zero drop"], ["no energy change", "potential energy does not change"])) ,
        short("A2L2_D10", "Why are equipotential lines perpendicular to field lines?", ["Because the field points in the direction of greatest potential decrease, so it crosses same-potential lines rather than running along them.", "Because the field arrow goes across terrace levels, while an equipotential route stays on one terrace height."], "Use slope-versus-same-terrace language.", ["equipotential_parallel_field_confusion"], skill_tags=["field_equipotential_link"], acceptance_rules=acceptance_groups(["field", "slope", "downhill"], ["equipotential", "same terrace", "same potential"], ["perpendicular", "crosses", "not along"])) ,
    ]
    concept = [
        mcq("A2L2_C1", "A 2 C charge gains 10 J of electric potential energy. The potential rise is...", ["5 V", "20 V", "8 V", "0.2 V"], 0, "Delta V = Delta U / q.", ["potential_current_same_confusion"], skill_tags=["voltage_calculation"]),
        mcq("A2L2_C2", "Which path needs no work in the ideal same-potential picture?", ["one that stays on the same equipotential line", "one that moves across many equipotential lines", "one that crosses the strongest field", "one that moves toward a battery"], 0, "No drop means no energy change.", ["equipotential_energy_change_confusion"], skill_tags=["equipotential_reasoning"]),
        mcq("A2L2_C3", "If the field arrows point downward on a terrace map, potential is higher...", ["higher up the map", "lower down the map", "the same everywhere", "only at the wire"], 0, "Field points downhill for a positive scout.", ["equipotential_parallel_field_confusion"], skill_tags=["potential_field_relation"]),
        mcq("A2L2_C4", "Which statement is strongest?", ["Potential is electric energy level per unit charge.", "Potential is current stored at a point.", "Potential is the same as force.", "Potential is the same as resistance."], 0, "Potential is energy per unit charge.", ["potential_current_same_confusion"], skill_tags=["potential_meaning"]),
        mcq("A2L2_C5", "A charge moves through a 9 V drop. If q = 3 C, the energy change magnitude is...", ["27 J", "12 J", "6 J", "3 J"], 0, "Delta U = q Delta V.", ["potential_current_same_confusion"], skill_tags=["voltage_calculation"]),
        mcq("A2L2_C6", "If two points lie on the same equipotential line, the field between them along that line is best described as...", ["not pushing along the path", "parallel to the path", "equal to the current", "the same as the resistance"], 0, "Field is across equipotentials, not along them.", ["equipotential_parallel_field_confusion"], skill_tags=["field_equipotential_link"]),
        short("A2L2_C7", "A learner says, 'Voltage is how much current is there.' What correction do you make?", ["Voltage is a terrace drop or energy change per unit charge, whereas current is the rate of charge flow.", "Potential difference measures electric height change per charge, not how many charges pass each second."], "Separate voltage from current explicitly.", ["potential_current_same_confusion"], skill_tags=["potential_difference"], acceptance_rules=acceptance_groups(["voltage", "potential difference", "terrace drop"], ["energy per unit charge", "height difference"], ["current", "rate of charge flow", "not current"])) ,
        short("A2L2_C8", "Why is node height language often more useful than talking vaguely about 'how much electricity is there'?", ["Because node height tells the electric potential at a place, so differences between node heights immediately give voltage across components.", "Because potential describes the electric energy level per charge at points, which is more precise than vague electricity language."], "Tie potential to node or point language.", ["potential_current_same_confusion"], skill_tags=["potential_meaning", "potential_difference"], acceptance_rules=acceptance_groups(["node", "point", "place"], ["potential", "height", "energy level"], ["difference", "voltage across"])) ,
    ]
    mastery = [
        mcq("A2L2_M1", "A 4 C charge drops 20 J in electric potential energy. The voltage drop is...", ["5 V", "80 V", "16 V", "0.2 V"], 0, "Divide energy change by charge.", ["potential_current_same_confusion"], skill_tags=["voltage_calculation"]),
        mcq("A2L2_M2", "Two points on one equipotential line differ in potential by...", ["0 V", "1 V", "the field strength", "the current in the circuit"], 0, "Same equipotential means no difference.", ["equipotential_energy_change_confusion"], skill_tags=["equipotential_reasoning"]),
        mcq("A2L2_M3", "If a positive charge moves naturally in the field direction, it moves toward...", ["lower potential", "higher potential", "the same potential only", "zero charge only"], 0, "The field is the downhill direction for a positive scout.", ["equipotential_parallel_field_confusion"], skill_tags=["potential_field_relation"]),
        mcq("A2L2_M4", "Equipotential lines are most useful because they...", ["show routes of equal electric height", "show current directions", "show resistance values only", "replace all field arrows"], 0, "They show same-potential routes.", ["equipotential_energy_change_confusion"], skill_tags=["equipotential_reasoning"]),
        mcq("A2L2_M5", "A charge of 6 C experiences a 3 V rise. The energy gain is...", ["18 J", "9 J", "2 J", "0.5 J"], 0, "Delta U = q Delta V.", ["potential_current_same_confusion"], skill_tags=["voltage_calculation"]),
        mcq("A2L2_M6", "Which statement must be true at a point where an equipotential line and an electric field line meet?", ["They cross at right angles in the simple picture", "They are parallel", "They must both stop", "They define equal current"], 0, "Field crosses equipotential routes.", ["equipotential_parallel_field_confusion"], skill_tags=["field_equipotential_link"]),
        short("A2L2_M7", "Why can two different branches in a circuit still have the same terrace drop between their end nodes?", ["Because voltage depends on the difference in node potential, so branches between the same two nodes share the same terrace drop.", "Because the branch voltage is set by the heights of the nodes at its ends, not by how much current happens to flow in each branch."], "Use end-node height language.", ["potential_current_same_confusion"], skill_tags=["potential_difference"], acceptance_rules=acceptance_groups(["same two nodes", "end nodes"], ["same potential difference", "same voltage", "same terrace drop"], ["not current", "independent of branch current"])) ,
        short("A2L2_M8", "Summarize Lesson 2 in one sentence.", ["Potential is electric height per unit charge, and equipotential routes are same-height paths with no terrace drop between their points.", "Voltage is a terrace drop between points, while equipotential paths stay at one electric height and so require no energy change."], "Keep the summary focused on height and drop language.", ["potential_current_same_confusion", "equipotential_energy_change_confusion"], skill_tags=["potential_meaning", "equipotential_reasoning"], acceptance_rules=acceptance_groups(["potential", "electric height", "energy per unit charge"], ["voltage", "drop", "difference"], ["equipotential", "same height", "same potential"])) ,
        mcq("A2L2_M9", "If the field is uniform and points left, the potential is higher on the...", ["right", "left", "same on both sides", "only at the midpoint"], 0, "Field points from high to low potential for a positive scout.", ["equipotential_parallel_field_confusion"], skill_tags=["potential_field_relation"]),
        mcq("A2L2_M10", "Best summary of lesson structure:", ["Field is slope; potential is height; equipotentials are same-height routes.", "Field, potential, and current are the same thing.", "Equipotential lines show fastest current routes.", "Voltage measures charge stored at one point."], 0, "That preserves the key distinctions.", ["potential_current_same_confusion"], skill_tags=["potential_meaning", "field_equipotential_link"]),
    ]
    return lesson_spec(
        "A2_L2",
        "Terrace Height and Equipotential Paths",
        sim(
            "a2_equipotential_lab",
            "Equipotential terrace lab",
            "Compare field arrows with equipotential routes so potential height and energy change stop being mixed up with flow.",
            ["Place point A and point B on the map.", "Trace a same-terrace route.", "Move across terrace levels and compare the drop."],
            ["Read potential as electric height.", "Explain why same-terrace paths require no energy change.", "Use Delta V = Delta U / q in a simple case."],
            ["point_a", "point_b", "potential_difference", "equipotential_path", "energy_change"],
            "Potential-height reasoning.",
        ),
        diagnostic,
        "The terrace map now has height labels as well as slope arrows. The field tells a positive scout which way is downhill, while terrace height tells how much electric energy per charge the location represents. Routes drawn on one terrace level are same-terrace or equipotential paths, so charges moving along them do not change electric height.",
        "Read electric height first, then decide whether the move is across terraces or along one terrace.",
        [prompt_block("What does one terrace height mean physically?", "It is the electric potential or energy level per unit charge."), prompt_block("What is special about a same-terrace path?", "There is no terrace drop along it.")],
        [prompt_block("Move between two points on the same terrace line.", "The potential change should stay zero."), prompt_block("Move across several terrace levels.", "The field should point across those levels, not along them.")],
        ["Why is potential better thought of as electric height than as current?", "Why do field arrows cross equipotential routes rather than follow them?"],
        "Keep electric height, terrace drop, and same-height routes visible at the same time.",
        concept,
        mastery,
        contract(
            concept_targets=["Interpret electric potential as energy per unit charge.", "Explain equipotential paths as same-height routes.", "Connect field direction to decreasing electric potential."],
            core_concepts=["Electric potential is electric energy level per unit charge.", "Potential difference is a terrace drop between two points.", "Equipotential paths are routes of no potential change.", "Electric field lines cross equipotentials at right angles in the simple model."],
            prerequisite_lessons=["A2_L1", "M10_L3"],
            misconception_focus=["equipotential_energy_change_confusion", "equipotential_parallel_field_confusion", "potential_current_same_confusion"],
            formulas=[relation("Delta V = Delta U / q", "Potential difference is energy change per unit charge.", ["V", "J/C"], "Use for changes between two points."), relation("Delta U = q Delta V", "Electric potential-energy change for a charge moving through a voltage difference.", ["J"], "The sign depends on the direction of motion and charge.")],
            representations=[representation("words", "Explains electric height and same-terrace paths."), representation("formula", "Links voltage to energy change per charge."), representation("diagram", "Shows terrace lines and field arrows."), representation("model", "Uses the Charge-Terrace height map.")],
            analogy_map=terrace_map("the learner compares same-height routes with moves across terrace drops"),
            worked_examples=[worked("A 2 C charge loses 10 J. Find the potential drop.", ["Use Delta V = Delta U / q.", "Compute 10 / 2.", "State the 5 V drop."], "5 V drop", "Voltage is energy change per unit charge.", "This anchors potential difference as a quotient."), worked("Two points lie on the same equipotential line. Compare their potentials.", ["Read the same-terrace rule.", "No terrace drop appears between the points.", "Conclude the potentials match."], "Their potential difference is 0 V", "Same-terrace routes have no electric height change.", "This fixes the equipotential idea."), worked("A learner says field lines and equipotential lines should run together. Diagnose the issue.", ["Keep the field as the downhill direction.", "Keep the equipotential route as same height.", "Conclude the field crosses same-height routes instead of following them."], "The learner is mixing slope and flat routes", "Slope and same-height path are different roles in the map.", "This blocks a major spatial misconception.")],
            visual_assets=[visual("a2_l2_equipotential_diagram", "equipotential_paths", "Equipotential routes stay on one electric terrace", "Show field arrows crossing same-terrace lines, with two routes between points that either stay on one terrace or cross levels.", "Field is slope; equipotential is same height.")],
            animation_assets=[animation("a2_l2_equipotential_animation", "equipotential_paths", "Moving across and along terraces", "Animate a charge moving along one equipotential and then across terrace levels to compare energy change.")],
            simulation_contract=sim_contract(
                "a2_l2_equipotential_sim",
                "equipotential_paths",
                "Place two points on the terrace map and compare same-height travel with downhill travel.",
                "Start with points placed on different terraces and one visible equipotential route.",
                ["Move both points onto the same equipotential line.", "Keep one point fixed and move the other across terrace levels."],
                "Watch for zero potential change along a same-terrace route and for field arrows always crossing terrace lines.",
                "Potential is height, and equipotential routes are same-height paths rather than current paths.",
                controls=[("point_a", "Point A", "Sets one terrace location."), ("point_b", "Point B", "Sets the comparison location."), ("route_mode", "Route mode", "Switches between along-terrace and cross-terrace moves.")],
                readouts=[("Potential at A", "Shows the electric height at point A."), ("Potential at B", "Shows the electric height at point B."), ("Delta V", "Shows the terrace drop between the two points.")],
            ),
            reflection_prompts=["Explain why a charge can move along an equipotential route without changing electric potential energy.", "Describe how field arrows and equipotential routes work together on the terrace map."],
            mastery_skills=["potential_meaning", "potential_difference", "equipotential_reasoning", "field_equipotential_link", "voltage_calculation"],
            variation_plan={"diagnostic": "Fresh attempts rotate between potential-definition items, equipotential statements, and simple Delta V = Delta U / q calculations with new values.", "concept_gate": "Concept checks vary between same-terrace reasoning, field-equipotential geometry, and voltage-versus-current corrections.", "mastery": "Mastery alternates between equipotential explanations, potential-energy calculations, and node-height interpretations so fresh attempts prefer new stems first."},
            scaffold_support=scaffold("Potential is electric height; voltage is the drop between heights.", "If two points stay on one terrace, there is no drop. If a path crosses terraces, there is a potential difference to account for.", "Are these two points on one terrace or on different terraces?", "Treating voltage as another word for current.", "The Charge-Terrace map makes electric height visible so same-potential paths look flat and terrace drops look like real changes in level.", "Why does the field cross the terrace lines instead of following them?", extras=[extra_section("Same-terrace rule", "Equipotential means same potential at every point on that route.", "What is Delta V along one equipotential?"), extra_section("Height rule", "Field points downhill for a positive scout, so higher potential lies opposite the field arrow.", "Which side of the slope is higher potential?")]),
            visual_clarity_checks=visual_checks("equipotential-map"),
        ),
    )


def lesson_three() -> Dict[str, Any]:
    diagnostic = [
        mcq("A2L3_D1", "A uniform field between parallel plates is best described as...", ["nearly constant in size and direction across the central gap", "strong only at one plate edge", "circular around each plate", "parallel to the plates"], 0, "Between large parallel plates the field is approximately uniform.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field"]),
        mcq("A2L3_D2", "For parallel plates, the field direction is...", ["from the positive plate to the negative plate", "from the negative plate to the positive plate", "parallel to the plates", "undefined until current flows"], 0, "Field goes from positive to negative.", ["uniform_field_voltage_distance_confusion"], skill_tags=["plate_field_direction"]),
        mcq("A2L3_D3", "In a uniform field, E = Delta V / d means the field gets larger when...", ["the same voltage appears across a smaller gap", "the same voltage appears across a larger gap", "charge is removed", "current is zero"], 0, "Smaller d with the same Delta V makes the slope steeper.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"]),
        mcq("A2L3_D4", "If Delta V = 12 V and d = 3 m, the uniform field is...", ["4 V/m", "36 V/m", "9 V/m", "0.25 V/m"], 0, "Divide voltage by distance.", ["uniform_field_voltage_distance_confusion"], skill_tags=["field_calculation"]),
        mcq("A2L3_D5", "If the plate separation doubles while voltage stays fixed, the field strength...", ["halves", "doubles", "stays the same", "quadruples"], 0, "E is inversely proportional to d.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"]),
        mcq("A2L3_D6", "If the voltage doubles while the gap stays fixed, the field strength...", ["doubles", "halves", "stays the same", "drops to zero"], 0, "E scales with Delta V for fixed d.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"]),
        mcq("A2L3_D7", "Uniform field lines between plates are drawn...", ["straight and parallel", "radial from a point", "spiraling", "only at the midpoint"], 0, "Uniform field means evenly spaced parallel lines.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field"]),
        mcq("A2L3_D8", "A positive charge released in the plate gap moves first...", ["toward the negative plate", "toward the positive plate", "parallel to the plates", "nowhere"], 0, "Positive charges follow the field.", ["uniform_field_voltage_distance_confusion"], skill_tags=["plate_field_direction"]),
        short("A2L3_D9", "Why is a bigger terrace drop across the same plate gap a stronger field?", ["Because the same distance now contains a larger potential difference, so the electric slope is steeper and E is larger.", "Because in a uniform field E depends on voltage drop per distance, so more volts across the same gap means a stronger field."], "Use voltage-per-distance language.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"], acceptance_rules=acceptance_groups(["same distance", "same gap"], ["bigger voltage", "larger potential difference"], ["steeper", "stronger field", "Delta V per d"])) ,
        short("A2L3_D10", "Why is a uniform field called a straight terrace slope?", ["Because the field strength and direction stay nearly constant across the region, so the electric height changes evenly with distance.", "Because equal distances give equal voltage changes in the central plate gap, which is like one steady slope."], "Keep constant slope language visible.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field"], acceptance_rules=acceptance_groups(["field strength", "direction", "constant"], ["equal distance", "evenly", "steady slope"], ["uniform field"])) ,
    ]
    concept = [
        mcq("A2L3_C1", "A 24 V drop across a 6 mm gap gives field strength...", ["4000 V/m", "4 V/m", "144 V/m", "0.25 V/m"], 0, "Convert 6 mm to 0.006 m, then divide.", ["uniform_field_voltage_distance_confusion"], skill_tags=["field_calculation"]),
        mcq("A2L3_C2", "If a plate gap changes from 4 mm to 2 mm while voltage stays fixed, the field strength...", ["doubles", "halves", "stays fixed", "drops to zero"], 0, "Halving d doubles E.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"]),
        mcq("A2L3_C3", "Which statement is strongest?", ["A uniform field links electric slope to voltage drop per distance.", "A uniform field means no potential difference exists.", "A uniform field exists only in wires.", "A uniform field makes all charges move at the same speed."], 0, "Uniform field is a slope-with-constant-gradient picture.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field"]),
        mcq("A2L3_C4", "A negative charge in a rightward uniform field is pushed...", ["leftward", "rightward", "upward", "not at all"], 0, "Negative charges move opposite the field.", ["field_direction_negative_charge_confusion"], skill_tags=["plate_field_direction"]),
        mcq("A2L3_C5", "If E = 3000 V/m across a 0.02 m gap, the voltage is...", ["60 V", "150 V", "60000 V", "15 V"], 0, "Use Delta V = Ed.", ["uniform_field_voltage_distance_confusion"], skill_tags=["voltage_from_field"]),
        mcq("A2L3_C6", "Between large parallel plates, equipotential lines are drawn...", ["parallel to the plates", "perpendicular to the plates", "radially outward", "as closed circles"], 0, "Equipotential surfaces are parallel to the plates in the simple picture.", ["equipotential_parallel_field_confusion"], skill_tags=["field_equipotential_link"]),
        short("A2L3_C7", "Why are the equipotential lines between parallel plates parallel to the plates?", ["Because the field is perpendicular to the plates in the uniform-gap model, and equipotential lines must be perpendicular to the field.", "Because each plate is a same-potential surface in the simple model, so the same-potential layers in the gap lie parallel to the plates."], "Link plate orientation to field and equipotential orientation.", ["equipotential_parallel_field_confusion"], skill_tags=["field_equipotential_link"], acceptance_rules=acceptance_groups(["field", "perpendicular to plates"], ["equipotential", "parallel to plates"], ["same potential", "same terrace"])) ,
        short("A2L3_C8", "A learner says, 'Doubling the voltage automatically doubles the gap field only because more current would flow.' What is the correction?", ["The uniform field depends on voltage drop per distance, not on current, so for the same gap doubling voltage doubles E.", "Current is not the definition here; E changes because Delta V over the same d is larger."], "Keep field and current separate.", ["uniform_field_voltage_distance_confusion", "potential_current_same_confusion"], skill_tags=["uniform_field_relation"], acceptance_rules=acceptance_groups(["voltage over distance", "Delta V / d"], ["same gap", "same distance"], ["not current", "field", "doubles"])) ,
    ]
    mastery = [
        mcq("A2L3_M1", "A 120 V drop across a 0.03 m gap gives field strength...", ["4000 V/m", "3600 V/m", "90 V/m", "0.00025 V/m"], 0, "120 / 0.03 = 4000.", ["uniform_field_voltage_distance_confusion"], skill_tags=["field_calculation"]),
        mcq("A2L3_M2", "A field of 2500 V/m across a 0.04 m gap corresponds to voltage...", ["100 V", "62500 V", "62.5 V", "10 V"], 0, "Delta V = Ed.", ["uniform_field_voltage_distance_confusion"], skill_tags=["voltage_from_field"]),
        mcq("A2L3_M3", "If the voltage halves and the gap halves, the field strength...", ["stays the same", "halves", "doubles", "becomes zero"], 0, "E = Delta V / d, so both changes cancel.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"]),
        mcq("A2L3_M4", "In the central region between the plates, a positive scout tends to move...", ["toward lower potential in the field direction", "toward higher potential in the field direction", "along equipotential lines", "randomly"], 0, "A positive scout moves downhill in potential.", ["uniform_field_voltage_distance_confusion"], skill_tags=["potential_field_relation"]),
        mcq("A2L3_M5", "Which change most increases uniform field strength?", ["same voltage with smaller plate gap", "same voltage with larger plate gap", "same gap with smaller voltage", "remove the plates"], 0, "Smaller d at fixed V steepens the field.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"]),
        mcq("A2L3_M6", "If plate A is positive and plate B is negative, the field points...", ["from A to B", "from B to A", "parallel to the plates", "nowhere in the gap"], 0, "Field direction is from positive to negative.", ["uniform_field_voltage_distance_confusion"], skill_tags=["plate_field_direction"]),
        short("A2L3_M7", "Why is E = Delta V / d a slope equation in this lesson?", ["Because it measures how much electric terrace height changes per meter across the plate gap.", "Because in a uniform field the voltage drop is spread evenly across the distance, so the field is the electric drop per distance."], "Use slope-per-distance language.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"], acceptance_rules=acceptance_groups(["voltage drop", "terrace drop", "height change"], ["per distance", "per meter", "divide by d"], ["slope", "uniform field"])) ,
        short("A2L3_M8", "Why does a negative charge move opposite to the field even in a uniform plate field?", ["Because the field direction is defined for a positive scout, so a negative charge feels the force in the opposite direction.", "Because the uniform field is still an electric field, and force on a negative charge reverses relative to that field."], "Keep the test-charge sign rule alive in the plate setting.", ["field_direction_negative_charge_confusion"], skill_tags=["plate_field_direction"], acceptance_rules=acceptance_groups(["positive scout", "positive test charge"], ["negative charge"], ["opposite", "reverse", "opposite the field"])) ,
        mcq("A2L3_M9", "If the plates stay 5 mm apart but the voltage rises from 10 V to 30 V, the field becomes...", ["three times larger", "two times larger", "the same", "one third as large"], 0, "For fixed d, E scales with V.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field_relation"]),
        mcq("A2L3_M10", "Best lesson summary:", ["Uniform plate fields turn voltage drop per distance into a straight electric slope.", "Uniform fields mean charges stop moving.", "Plate fields and equipotential ideas are unrelated.", "Current is the same thing as field strength."], 0, "That sentence keeps the advanced meaning intact.", ["uniform_field_voltage_distance_confusion"], skill_tags=["uniform_field", "uniform_field_relation"]),
    ]
    return lesson_spec(
        "A2_L3",
        "Uniform Fields Between Plates",
        sim(
            "a2_uniform_field_lab",
            "Uniform plate-field lab",
            "Vary plate voltage and gap spacing so the electric slope between the plates can be read as a uniform field.",
            ["Set the plate voltage.", "Change the plate separation.", "Read the field strength and direction across the gap."],
            ["Use E = Delta V / d conceptually and numerically.", "Describe the direction of a uniform plate field.", "Explain how voltage and distance jointly set field strength."],
            ["plate_voltage", "plate_gap", "field_strength", "field_direction", "equipotential_spacing"],
            "Uniform-field reasoning.",
        ),
        diagnostic,
        "Two large facing plates create a region where the terraces slope almost evenly from one side to the other. The positive plate is the high terrace, the negative plate is the low terrace, and the field in the gap is the local slope arrow. The bigger the drop across the same gap, the steeper the slope. The smaller the gap for the same drop, the steeper again.",
        "Think 'voltage drop per distance' before touching the algebra.",
        [prompt_block("What sets the field direction between the plates?", "It runs from the positive plate toward the negative plate."), prompt_block("What two things set the field strength in the gap?", "The voltage across the plates and the plate separation.")],
        [prompt_block("Keep the voltage fixed and shrink the gap.", "The field should become stronger."), prompt_block("Keep the gap fixed and raise the voltage.", "The field should also become stronger.")],
        ["Why is a uniform plate field a straight terrace slope?", "Why do the field and equipotential directions stay perpendicular in the gap?"],
        "Use the plate gap to see a clean link between voltage drop and electric slope.",
        concept,
        mastery,
        contract(
            concept_targets=["Describe the direction and shape of a uniform plate field.", "Use E = Delta V / d for a uniform field.", "Explain how voltage and plate spacing affect field strength."],
            core_concepts=["Between large parallel plates the field is approximately uniform.", "The field points from the positive plate to the negative plate.", "In a uniform field, E = Delta V / d.", "Stronger fields come from larger voltage drops across the same distance or the same drop across smaller distance."],
            prerequisite_lessons=["A2_L1", "A2_L2"],
            misconception_focus=["uniform_field_voltage_distance_confusion", "equipotential_parallel_field_confusion", "field_direction_negative_charge_confusion"],
            formulas=[relation("E = Delta V / d", "Uniform field strength equals voltage drop per distance.", ["V/m", "N/C"], "Use for approximately uniform regions such as the gap between large parallel plates."), relation("Delta V = Ed", "Potential difference across a uniform field region.", ["V"], "Use when field strength and plate spacing are known.")],
            representations=[representation("words", "Explains field as voltage drop per distance."), representation("formula", "Links uniform field strength to voltage and gap."), representation("diagram", "Shows parallel plates, field arrows, and equipotential layers."), representation("model", "Uses the terrace-gap slope picture.")],
            analogy_map=terrace_map("the learner compares plate voltage and gap spacing to read the straight electric slope"),
            worked_examples=[worked("A 20 V drop appears across a 0.01 m plate gap. Find E.", ["Use E = Delta V / d.", "Compute 20 / 0.01.", "State the uniform field strength."], "2000 V/m", "Uniform field is voltage drop per distance.", "This is the signature calculation for the lesson."), worked("A field of 1500 V/m fills a 0.04 m gap. Find the voltage.", ["Use Delta V = Ed.", "Multiply 1500 by 0.04.", "State the plate voltage difference."], "60 V", "Uniform field and terrace drop are linked both ways.", "This keeps the algebra flexible."), worked("A learner says the field only changes because more current flows. Diagnose the issue.", ["Remove current from the definition.", "Keep the same gap and compare voltage per distance.", "Restore field as slope, not current."], "The learner is using the wrong quantity", "Uniform field is set by voltage difference and spacing, not by current.", "This protects the field-voltage distinction.")],
            visual_assets=[visual("a2_l3_uniform_plate_diagram", "uniform_plate_field", "Parallel plates create a straight electric slope", "Show large facing plates with a uniform field in the gap, equipotential layers, and labels tying Delta V and d to E.", "Uniform field is terrace drop per distance.")],
            animation_assets=[animation("a2_l3_uniform_plate_animation", "uniform_plate_field", "Changing plate gap and voltage", "Animate the field becoming steeper when the voltage increases or the gap shrinks.")],
            simulation_contract=sim_contract(
                "a2_l3_uniform_plate_sim",
                "uniform_plate_field",
                "Vary voltage and gap spacing between plates so the field strength reads like an adjustable straight slope.",
                "Begin with a moderate plate voltage and a medium gap.",
                ["Double the voltage while keeping the gap fixed.", "Halve the gap while keeping the voltage fixed."],
                "Watch for field direction staying the same while the steepness changes with Delta V and d.",
                "Uniform fields are best understood as straight electric slopes set by voltage drop over distance.",
                controls=[("plate_voltage", "Plate voltage", "Sets the terrace drop across the gap."), ("plate_gap", "Plate gap", "Sets the distance over which the drop occurs."), ("scout_sign", "Scout sign", "Shows how force direction depends on charge sign even though the field stays fixed.")],
                readouts=[("Field strength E", "Shows the current uniform field strength."), ("Gap d", "Shows the distance between the plates."), ("Voltage Delta V", "Shows the potential difference between the plates.")],
            ),
            reflection_prompts=["Explain why a smaller plate gap makes the field stronger when the voltage stays fixed.", "Describe why equipotential layers between the plates are parallel to the plates."],
            mastery_skills=["uniform_field", "uniform_field_relation", "field_calculation", "voltage_from_field", "plate_field_direction"],
            variation_plan={"diagnostic": "Fresh attempts rotate between direction questions, simple E = Delta V / d items, and plate-gap comparison statements.", "concept_gate": "Concept checks vary between field-versus-current wording, equipotential orientation, and uniform-field proportional reasoning.", "mastery": "Mastery alternates between field calculations, scaling changes, and explanation prompts about slope, gap, and sign."},
            scaffold_support=scaffold("Uniform field means one steady electric slope.", "Between parallel plates, the voltage drop is spread across the gap, so field strength is simply drop per distance.", "What happens to the same voltage drop if you squeeze it into a smaller gap?", "Letting current language replace field language.", "A straight terrace slope makes the plate region feel like one clean hill from high plate to low plate.", "Why does shrinking the gap steepen the electric hill?", extras=[extra_section("Direction rule", "Field points from the positive plate toward the negative plate.", "Which plate is the high terrace?"), extra_section("Scaling rule", "For fixed gap, more volts means a stronger field; for fixed volts, less distance means a stronger field.", "What two knobs change E?")]),
            visual_clarity_checks=visual_checks("uniform-plate"),
        ),
    )


def lesson_four() -> Dict[str, Any]:
    diagnostic = [
        mcq("A2L4_D1", "A capacitor in the terrace model is best described as...", ["two facing conductors storing separated charge across a gap", "one plate that lets charge pass through the gap", "a resistor with zero voltage", "a battery that makes current"], 0, "A capacitor stores equal and opposite charge on facing plates.", ["capacitor_charge_crosses_gap_confusion"], skill_tags=["capacitor_definition"]),
        mcq("A2L4_D2", "Capacitance means...", ["charge stored per unit voltage", "voltage stored per unit current", "energy stored per unit resistance", "current stored per unit time"], 0, "C = Q / V.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_definition"]),
        mcq("A2L4_D3", "If a capacitor has C = 4 F and V = 3 V, the stored charge is...", ["12 C", "7 C", "1.3 C", "0.75 C"], 0, "Use Q = CV.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_calculation"]),
        mcq("A2L4_D4", "If a capacitor stores 8 C at 2 V, its capacitance is...", ["4 F", "16 F", "6 F", "0.25 F"], 0, "Use C = Q / V.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_calculation"]),
        mcq("A2L4_D5", "For parallel plates, increasing plate area tends to...", ["increase capacitance", "decrease capacitance", "leave capacitance unchanged", "reverse the field"], 0, "Larger facing area means larger capacitance.", ["capacitance_geometry_confusion"], skill_tags=["capacitance_geometry"]),
        mcq("A2L4_D6", "For parallel plates, increasing plate separation tends to...", ["decrease capacitance", "increase capacitance", "leave capacitance unchanged", "double the charge automatically"], 0, "Wider gap means smaller capacitance.", ["capacitance_geometry_confusion"], skill_tags=["capacitance_geometry"]),
        mcq("A2L4_D7", "Charges crossing the gap between the plates is...", ["not part of the simple capacitor model", "the main reason the capacitor stores charge", "how current stays the same through the dielectric", "required for C = Q/V"], 0, "Charge builds on facing surfaces; it does not cross the insulating gap.", ["capacitor_charge_crosses_gap_confusion"], skill_tags=["capacitor_definition"]),
        mcq("A2L4_D8", "Where is the stored energy mainly located in this model?", ["in the electric field between the plates", "inside only the positive plate", "inside only the negative plate", "inside the wires only"], 0, "The field-filled gap stores the energy.", ["capacitor_energy_location_confusion"], skill_tags=["capacitor_energy"]),
        short("A2L4_D9", "Why does a capacitor need two facing decks rather than one isolated plate in this model?", ["Because capacitance depends on separated opposite charge across a gap and the electric field between the facing conductors.", "Because the split-deck store works by holding equal and opposite charge on two facing conductors with a terrace drop between them."], "Use separated-charge language.", ["capacitor_charge_crosses_gap_confusion"], skill_tags=["capacitor_definition"], acceptance_rules=acceptance_groups(["two facing", "two conductors", "two plates"], ["opposite charge", "separated charge"], ["field between", "gap", "terrace drop"])) ,
        short("A2L4_D10", "Why is capacitance not the same thing as the amount of charge stored?", ["Because capacitance is the ratio Q/V for the device, while the actual stored charge depends on both the capacitance and the voltage across it.", "Because capacitance is a property of the capacitor's geometry and material, not simply the current amount of charge sitting on it."], "Separate device property from actual stored charge.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_definition"], acceptance_rules=acceptance_groups(["capacitance", "Q/V", "ratio"], ["property", "device", "geometry"], ["charge", "depends on voltage", "not same"])) ,
    ]
    concept = [
        mcq("A2L4_C1", "A capacitor has C = 5 F and V = 6 V. The stored charge is...", ["30 C", "11 C", "1.2 C", "0.83 C"], 0, "Q = CV.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_calculation"]),
        mcq("A2L4_C2", "A capacitor stores 18 C when V = 9 V. Its capacitance is...", ["2 F", "162 F", "9 F", "0.5 F"], 0, "C = Q / V.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_calculation"]),
        mcq("A2L4_C3", "If the same capacitor is charged to a larger voltage, the stored charge...", ["increases in proportion", "must stay fixed", "falls to zero", "changes sign only"], 0, "For fixed C, Q = CV.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_definition"]),
        mcq("A2L4_C4", "Which geometry change gives the largest capacitance for parallel plates?", ["large area and small separation", "small area and large separation", "small area and small separation", "large area and large separation"], 0, "Big area and small gap increase capacitance.", ["capacitance_geometry_confusion"], skill_tags=["capacitance_geometry"]),
        mcq("A2L4_C5", "Which statement is strongest?", ["A capacitor stores energy in the electric field between separated charges.", "A capacitor stores current in one plate.", "A capacitor stores only resistance.", "A capacitor lets charges jump the gap."], 0, "Field energy in the gap is the right picture.", ["capacitor_energy_location_confusion"], skill_tags=["capacitor_energy"]),
        mcq("A2L4_C6", "If area doubles and separation stays fixed, capacitance...", ["increases", "decreases", "stays the same", "must become zero"], 0, "More facing area gives more capacitance.", ["capacitance_geometry_confusion"], skill_tags=["capacitance_geometry"]),
        short("A2L4_C7", "Why does increasing plate separation reduce capacitance?", ["Because the same separated-charge arrangement now creates a wider gap, so the capacitor stores less charge for each volt across it.", "Because a larger gap weakens the split-deck store, so Q per V is smaller."], "Use charge-per-volt or store-weakening language.", ["capacitance_geometry_confusion"], skill_tags=["capacitance_geometry"], acceptance_rules=acceptance_groups(["larger gap", "greater separation"], ["less charge per volt", "smaller Q/V", "smaller capacitance"], ["field", "store", "weaker"])) ,
        short("A2L4_C8", "A learner says, 'The capacitor stores energy because charges pile up randomly on one plate.' What correction is needed?", ["The capacitor stores equal and opposite separated charge on two facing plates, and the energy is stored in the electric field across the gap.", "It is not random charge on one plate; it is separated charge on both plates with energy in the field between them."], "Use two-plate and field-energy language.", ["capacitor_energy_location_confusion", "capacitor_charge_crosses_gap_confusion"], skill_tags=["capacitor_energy", "capacitor_definition"], acceptance_rules=acceptance_groups(["two plates", "two conductors", "facing"], ["equal and opposite", "separated charge"], ["field between", "gap", "energy stored"])) ,
    ]
    mastery = [
        mcq("A2L4_M1", "A 12 F capacitor charged to 2 V stores...", ["24 C", "14 C", "6 C", "0.17 C"], 0, "Q = CV.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_calculation"]),
        mcq("A2L4_M2", "A capacitor storing 30 C at 10 V has capacitance...", ["3 F", "300 F", "20 F", "0.33 F"], 0, "C = Q / V.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_calculation"]),
        mcq("A2L4_M3", "If the same capacitor's voltage doubles, the stored charge...", ["doubles", "halves", "stays the same", "changes only if current is present"], 0, "Fixed C gives Q proportional to V.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_definition"]),
        mcq("A2L4_M4", "If plate area is made larger while gap and material stay the same, the capacitor can...", ["store more charge for the same voltage", "store less charge for the same voltage", "store the same charge but more current", "lose its field"], 0, "Larger area increases capacitance.", ["capacitance_geometry_confusion"], skill_tags=["capacitance_geometry"]),
        mcq("A2L4_M5", "If the gap becomes larger while the same voltage is applied, the capacitance...", ["decreases", "increases", "stays the same", "becomes negative"], 0, "Greater separation lowers capacitance.", ["capacitance_geometry_confusion"], skill_tags=["capacitance_geometry"]),
        mcq("A2L4_M6", "Which statement is true of the gap between capacitor plates?", ["It holds the electric field but charge does not cross it in the simple model.", "It is where charge must flow continuously across.", "It is the same thing as an ideal wire.", "It has no role in stored energy."], 0, "Gap field yes; direct charge crossing no.", ["capacitor_charge_crosses_gap_confusion"], skill_tags=["capacitor_definition"]),
        short("A2L4_M7", "Why does C = Q / V describe a capacitor property rather than a one-off event only?", ["Because for a fixed capacitor the ratio of stored charge to voltage is set by the geometry and material of the device.", "Because capacitance tells how much charge per volt that split-deck store can hold, so it belongs to the device design."], "Use ratio and device-property language.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_definition"], acceptance_rules=acceptance_groups(["ratio", "Q over V", "charge per volt"], ["device", "geometry", "material", "property"], ["fixed capacitor", "same capacitor"])) ,
        short("A2L4_M8", "Why is the field between the plates the right place to say the energy is stored?", ["Because opposite charges on the two plates create the electric field in the gap, and that field carries the stored energy.", "Because the capacitor stores energy in the separated-charge field between the facing plates rather than in one plate alone."], "Keep the energy location physical and geometric.", ["capacitor_energy_location_confusion"], skill_tags=["capacitor_energy"], acceptance_rules=acceptance_groups(["field between the plates", "gap"], ["energy stored"], ["opposite charges", "separated charge", "facing plates"])) ,
        mcq("A2L4_M9", "A capacitor of 0.5 F is charged to 20 V. The stored charge is...", ["10 C", "40 C", "20 C", "0.025 C"], 0, "Q = CV.", ["capacitance_charge_voltage_same_confusion"], skill_tags=["capacitance_calculation"]),
        mcq("A2L4_M10", "Best lesson summary:", ["Capacitance is charge stored per volt by two facing conductors, and the stored energy lives in the field across the gap.", "Capacitance is just the amount of charge currently present.", "A capacitor works by sending charge across the gap.", "Gap size has no effect on the store."], 0, "That is the core terrace-store idea.", ["capacitance_charge_voltage_same_confusion", "capacitor_energy_location_confusion"], skill_tags=["capacitor_definition", "capacitor_energy"]),
    ]
    return lesson_spec(
        "A2_L4",
        "Split-Deck Stores and Capacitance",
        sim(
            "a2_capacitor_lab",
            "Split-deck store lab",
            "Change plate area, gap size, and source voltage to compare stored charge, capacitance, and the field in the gap.",
            ["Set plate area and gap.", "Charge the capacitor with a chosen voltage.", "Read the stored charge and hold capacity."],
            ["Explain capacitance as Q per V.", "Relate plate geometry to capacitance.", "Describe the field gap as the energy store."],
            ["plate_area", "plate_gap", "source_voltage", "stored_charge", "capacitance"],
            "Capacitance reasoning.",
        ),
        diagnostic,
        "The Split-Deck Store is a pair of facing decks with a no-cross gap between them. The source pulls charge apart so one deck becomes positive and the other negative. The gap fills with electric field, and the store is judged by how much charge it can hold for each volt of terrace drop across the plates.",
        "Treat capacitance as the store's charge-per-volt capacity, not as a synonym for charge.",
        [prompt_block("What do the two plates hold?", "They hold equal and opposite separated charge."), prompt_block("What does capacitance measure?", "Charge stored per unit voltage.")],
        [prompt_block("Increase the plate area.", "The capacitor should hold more charge per volt."), prompt_block("Increase the plate gap.", "The hold capacity should decrease.")],
        ["Why does a capacitor need separated charge on two facing plates?", "Why is capacitance a device property rather than simply the stored charge value?"],
        "Keep the two-plate geometry, the field in the gap, and the Q per V ratio visible together.",
        concept,
        mastery,
        contract(
            concept_targets=["Define capacitance as Q/V.", "Explain a capacitor as separated charge on two facing conductors.", "Relate plate geometry to capacitance and field storage."],
            core_concepts=["A capacitor stores equal and opposite separated charge on two facing conductors.", "Capacitance is charge stored per unit voltage.", "For parallel plates, larger area increases capacitance and larger separation decreases it.", "The stored energy is located in the electric field between the plates."],
            prerequisite_lessons=["A2_L2", "A2_L3"],
            misconception_focus=["capacitor_charge_crosses_gap_confusion", "capacitance_charge_voltage_same_confusion", "capacitance_geometry_confusion", "capacitor_energy_location_confusion"],
            formulas=[relation("C = Q / V", "Capacitance is stored charge per unit voltage.", ["F", "C/V"], "Use for any capacitor."), relation("Q = CV", "Stored charge on a capacitor.", ["C"], "Use when capacitance and voltage are known.")],
            representations=[representation("words", "Explains separated charge and field storage."), representation("formula", "Connects capacitance, charge, and voltage."), representation("diagram", "Shows facing plates, gap field, and separated charge."), representation("model", "Uses the Split-Deck Store analogy.")],
            analogy_map=terrace_map("the learner compares charge separation, field-filled gap, and charge-per-volt capacity"),
            worked_examples=[worked("A 3 F capacitor is charged to 4 V. Find the stored charge.", ["Use Q = CV.", "Multiply 3 by 4.", "State the stored charge on the plates."], "12 C", "Stored charge scales with both capacitance and voltage.", "This anchors the main calculation."), worked("A capacitor stores 15 C at 5 V. Find C.", ["Use C = Q / V.", "Divide 15 by 5.", "State the capacitance."], "3 F", "Capacitance is the charge-per-volt ratio.", "This keeps the ratio meaning alive."), worked("A learner says charges must cross the gap for the capacitor to work. Diagnose the issue.", ["Keep the gap insulating in the simple model.", "Put opposite charges on facing surfaces instead.", "Store the energy in the field between them."], "The learner is using the wrong mechanism", "Capacitors store separated charge across a gap rather than sending charge through it.", "This protects the core device picture.")],
            visual_assets=[visual("a2_l4_split_deck_diagram", "capacitor_store", "Facing decks hold separated charge across a field-filled gap", "Show two plates with opposite surface charge, field lines in the gap, and labels tying Q, V, and C together.", "Capacitance is the hold capacity of the split-deck store.")],
            animation_assets=[animation("a2_l4_split_deck_animation", "capacitor_store", "Charging the split-deck store", "Animate opposite charges building on the facing plates while the gap field strengthens.")],
            simulation_contract=sim_contract(
                "a2_l4_split_deck_sim",
                "capacitor_store",
                "Vary plate area, plate separation, and charging voltage to compare stored charge with hold capacity.",
                "Start with a medium plate area, a small gap, and a modest source voltage.",
                ["Double the plate area and compare capacitance.", "Increase the gap while keeping the same voltage and compare the new stored charge."],
                "Watch for the difference between capacitance itself and the actual charge stored at a chosen voltage.",
                "Capacitance is the device's hold capacity in charge per volt, while the field in the gap is where the energy is stored.",
                controls=[("plate_area", "Plate area", "Changes how much facing deck area can hold separated charge."), ("plate_gap", "Plate gap", "Changes how difficult it is to maintain separated charge for the same voltage."), ("source_voltage", "Source voltage", "Sets the terrace drop across the capacitor.")],
                readouts=[("Capacitance C", "Shows the hold capacity of the device."), ("Stored charge Q", "Shows the separated charge on the plates."), ("Gap field", "Shows the field in the space between the plates.")],
            ),
            reflection_prompts=["Explain why a capacitor with larger area can store more charge for the same voltage.", "Describe why the field in the gap is the right place to locate the stored energy."],
            mastery_skills=["capacitor_definition", "capacitance_definition", "capacitance_calculation", "capacitance_geometry", "capacitor_energy"],
            variation_plan={"diagnostic": "Fresh attempts rotate between plate-gap ideas, Q = CV prompts, and capacitor-versus-charge language corrections.", "concept_gate": "Concept checks vary between geometry reasoning, field-storage language, and short explanations about separated charge.", "mastery": "Mastery alternates between numeric capacitance problems and conceptual field-gap explanations so new attempts prefer unseen stems and values."},
            scaffold_support=scaffold("A capacitor is a split-deck store for separated charge.", "Keep charge, voltage, and capacitance separate: Q is what is stored, V is the terrace drop, and C is the store's charge-per-volt capacity.", "Are you being asked for the stored charge or for the charge-per-volt capacity?", "Calling capacitance 'the amount of charge' or letting charges cross the gap in the story.", "The two facing decks and their field-filled gap are what make the store possible.", "Why is one isolated charged plate not the full capacitor story?", extras=[extra_section("Ratio rule", "C = Q / V tells how much separated charge the store can hold for each volt.", "What does one farad mean in words?"), extra_section("Geometry rule", "Area helps the store; separation weakens it.", "Which geometry change raises capacitance?")]),
            visual_clarity_checks=visual_checks("split-deck"),
        ),
    )


def lesson_five() -> Dict[str, Any]:
    diagnostic = [
        mcq("A2L5_D1", "A node platform is best described as...", ["all points connected by ideal wire and sharing one potential", "all points carrying the same current only", "all resistors in a branch", "the battery only"], 0, "Ideal-wire-connected points form one node platform.", ["node_potential_everywhere_different_confusion"], skill_tags=["node_potential"]),
        mcq("A2L5_D2", "Kirchhoff's current law says...", ["current entering a node equals current leaving it", "all currents in a circuit are equal", "all voltages at a node are zero", "currents are created at junctions"], 0, "It is charge conservation at a node.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_D3", "If 5 A enters a node and 2 A leaves through one branch, the current in the other leaving branch is...", ["3 A", "7 A", "2.5 A", "10 A"], 0, "Incoming must equal outgoing.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_D4", "Branches connected between the same two nodes share...", ["the same potential difference", "the same resistance", "the same current always", "the same power always"], 0, "Same end nodes means same node-height difference.", ["parallel_voltage_current_mixup", "node_potential_everywhere_different_confusion"], skill_tags=["parallel_voltage"]),
        mcq("A2L5_D5", "Two parallel branches can have different currents because...", ["their resistances can differ even though their node-to-node voltage is the same", "their voltages must differ", "charge is destroyed in one branch", "the battery chooses one branch randomly"], 0, "Same voltage does not force same current when branch resistances differ.", ["parallel_voltage_current_mixup"], skill_tags=["branch_current_split"]),
        mcq("A2L5_D6", "If 1 A and 4 A leave a node, the entering current must be...", ["5 A", "4 A", "3 A", "1 A"], 0, "Sum in equals sum out.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_D7", "Which statement is strongest?", ["Ideal wires in the simple model have negligible voltage drop.", "Ideal wires create extra voltage as current moves.", "Each point on one wire must have different potential.", "Parallel branches always have equal current."], 0, "That is why one wire-connected region is one node.", ["node_potential_everywhere_different_confusion"], skill_tags=["node_potential"]),
        mcq("A2L5_D8", "A branch with larger resistance under the same branch voltage usually carries...", ["smaller current", "larger current", "the same current", "negative current automatically"], 0, "Same voltage with bigger resistance gives less current for an ohmic branch.", ["parallel_voltage_current_mixup"], skill_tags=["branch_current_split"]),
        short("A2L5_D9", "Why are ideal-wire-connected points colored as one platform in the terrace model?", ["Because ideal wires have negligible voltage drop, so all those points share the same electric potential or terrace height.", "Because one node platform means one potential level across every ideal-wire-connected point."], "Use same-potential platform language.", ["node_potential_everywhere_different_confusion"], skill_tags=["node_potential"], acceptance_rules=acceptance_groups(["ideal wire", "wire connected"], ["same potential", "same terrace", "same node height"], ["negligible drop", "zero drop"])) ,
        short("A2L5_D10", "Why is KCL a charge-bookkeeping rule rather than a battery rule?", ["Because it applies at any node and says charge does not build up there in the steady picture, so current in equals current out.", "Because current conservation at a junction comes from charge conservation, not from what the battery 'wants' to do."], "Use node bookkeeping language.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"], acceptance_rules=acceptance_groups(["charge conservation", "charge bookkeeping"], ["node", "junction"], ["in equals out", "entering equals leaving"])) ,
    ]
    concept = [
        mcq("A2L5_C1", "A current of 7 A enters a node. If 3 A leaves by one branch and 1 A leaves by another, the third leaving branch carries...", ["3 A", "4 A", "5 A", "11 A"], 0, "7 = 3 + 1 + I.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_C2", "If two branches are connected between nodes X and Y, each branch has...", ["the same voltage across it", "the same current in it", "the same resistance", "the same power only"], 0, "Same end nodes means same potential difference.", ["parallel_voltage_current_mixup"], skill_tags=["parallel_voltage"]),
        mcq("A2L5_C3", "If one parallel branch has twice the resistance of another under the same branch voltage, it carries...", ["less current", "more current", "the same current", "zero current necessarily"], 0, "More drag means less current for the same voltage.", ["parallel_voltage_current_mixup"], skill_tags=["branch_current_split"]),
        mcq("A2L5_C4", "Which question is often most useful in a complex circuit?", ["What are the node heights at the ends of the component?", "How many wires were drawn on the page?", "Which branch looks longer on the diagram?", "Which battery was placed first?"], 0, "Node-height thinking reveals component voltage cleanly.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_potential"]),
        mcq("A2L5_C5", "If branch 1 carries 2 A and branch 2 carries 5 A, the total current before the split is...", ["7 A", "3 A", "10 A", "2.5 A"], 0, "Total current equals the sum of branch currents.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_C6", "Why can two branches have the same voltage but different current?", ["Because branch current also depends on branch resistance", "Because voltage automatically equals current", "Because KCL is violated in one branch", "Because one branch has no node"], 0, "Same voltage does not force same current.", ["parallel_voltage_current_mixup"], skill_tags=["parallel_voltage", "branch_current_split"]),
        short("A2L5_C7", "A learner says, 'Parallel means equal current in each branch.' What correction is needed?", ["Parallel means equal potential difference across each branch; the currents can differ depending on branch resistance.", "Branches in parallel share the same node-to-node voltage, not necessarily the same current."], "Use same-voltage, not same-current, language.", ["parallel_voltage_current_mixup"], skill_tags=["parallel_voltage", "branch_current_split"], acceptance_rules=acceptance_groups(["parallel", "branches"], ["same voltage", "same potential difference", "same node-to-node drop"], ["current can differ", "depends on resistance", "not same current"])) ,
        short("A2L5_C8", "Why is the node-platform idea powerful in complex circuits?", ["Because it lets you group ideal-wire-connected points as one potential level, so component voltages become differences between node heights.", "Because once node heights are known, branch voltages are just differences between the two end nodes."], "Use node-height simplification language.", ["complex_circuit_branch_voltage_confusion", "node_potential_everywhere_different_confusion"], skill_tags=["node_potential"], acceptance_rules=acceptance_groups(["ideal wire", "wire connected"], ["same potential", "same node"], ["voltage difference", "node heights", "component voltage"])) ,
    ]
    mastery = [
        mcq("A2L5_M1", "If 9 A enters a node and 4 A leaves in one branch, the current in the other leaving branch is...", ["5 A", "13 A", "4.5 A", "1 A"], 0, "Use KCL.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_M2", "Two resistors are in parallel between the same nodes. The correct statement is...", ["They share the same voltage.", "They share the same current.", "They must have the same resistance.", "They must have the same power."], 0, "Parallel branches share node-to-node voltage.", ["parallel_voltage_current_mixup"], skill_tags=["parallel_voltage"]),
        mcq("A2L5_M3", "A 12 V source feeds two parallel branches. One branch has higher resistance. Compared with the lower-resistance branch, it carries...", ["less current", "more current", "the same current", "no voltage"], 0, "Same branch voltage, different resistance.", ["parallel_voltage_current_mixup"], skill_tags=["branch_current_split"]),
        mcq("A2L5_M4", "Which statement about a single ideal wire segment is strongest?", ["All points on it are at the same potential in the simple model.", "The current halves along it.", "The voltage rises along it.", "It acts like a capacitor."], 0, "That is the node-platform rule.", ["node_potential_everywhere_different_confusion"], skill_tags=["node_potential"]),
        mcq("A2L5_M5", "A branch current split of 2 A and 6 A recombines later. The recombined current is...", ["8 A", "4 A", "12 A", "3 A"], 0, "Branch currents add on recombination.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_M6", "A component connected between node P and node Q has voltage best described as...", ["the potential difference between P and Q", "the current through node P only", "the sum of all currents in the circuit", "the resistance of the wire alone"], 0, "Component voltage is node-height difference.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_potential"]),
        short("A2L5_M7", "Why is it wrong to say current is used up at a junction where it splits?", ["Because charge is conserved, so the incoming current is shared between the branches and the branch currents add back to the same total.", "Because splitting means the current divides, not that current disappears; KCL keeps the current bookkeeping balanced."], "Use divide-and-recombine language, not used-up language.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"], acceptance_rules=acceptance_groups(["charge conserved", "current conserved"], ["split", "divide", "shared"], ["adds back", "recombine", "not used up"])) ,
        short("A2L5_M8", "Why can the same node-to-node voltage produce different branch currents?", ["Because current depends on the resistance of each branch, so equal branch voltage does not force equal branch current.", "Because the voltage is shared equally across the branches, but the route drag in each branch can be different."], "Keep voltage and current roles separate.", ["parallel_voltage_current_mixup"], skill_tags=["parallel_voltage", "branch_current_split"], acceptance_rules=acceptance_groups(["same voltage", "same node-to-node"], ["different resistance", "route drag"], ["different current", "not equal"])) ,
        mcq("A2L5_M9", "If 2 A enters a node from one side and 1 A enters from another, the total leaving current is...", ["3 A", "2 A", "1 A", "0.5 A"], 0, "Currents entering add before leaving.", ["junction_current_loss_confusion"], skill_tags=["kirchhoff_current_law"]),
        mcq("A2L5_M10", "Best lesson summary:", ["Node platforms carry one potential, branch voltages can match while currents split, and KCL keeps the current bookkeeping balanced.", "Every branch in parallel must carry the same current.", "Ideal wires create large voltage drops.", "Current is lost whenever a junction appears."], 0, "That is the right terrace-network summary.", ["junction_current_loss_confusion", "parallel_voltage_current_mixup"], skill_tags=["node_potential", "kirchhoff_current_law"]),
    ]
    return lesson_spec(
        "A2_L5",
        "Node Platforms and the Junction Count Rule",
        sim(
            "a2_node_platform_lab",
            "Node platform lab",
            "Compare node heights and branch currents in a split network so same-voltage and current-splitting ideas stay separate.",
            ["Set the source voltage.", "Change the two branch resistances.", "Read node heights and branch currents."],
            ["Identify node platforms.", "Apply KCL at a junction.", "Explain why parallel branches share voltage but not necessarily current."],
            ["source_voltage", "branch_resistance_1", "branch_resistance_2", "branch_current_1", "branch_current_2"],
            "KCL and node-height reasoning.",
        ),
        diagnostic,
        "A complex circuit becomes easier when the ideal-wire parts are colored as one terrace platform. Each platform has one electric height. Branches between the same two platforms therefore have the same terrace drop, even though the checkpoint rate can split unevenly. At each node, what comes in must come out again: the junction count rule is just charge bookkeeping.",
        "Find the node platforms first, then compare branch voltage and branch current separately.",
        [prompt_block("What do all ideal-wire-connected points share?", "They share the same potential."), prompt_block("What must be true of current at a steady node?", "Total current in equals total current out.")],
        [prompt_block("Keep the source fixed and raise one branch resistance.", "That branch current should shrink while the branch voltage stays the same."), prompt_block("Read the two branch end nodes.", "The branch voltages should match because the end nodes match.")],
        ["Why do parallel branches share voltage but not necessarily current?", "Why is KCL best read as a bookkeeping rule at nodes?"],
        "Use node colors and checkpoint counts to stop branch voltage and branch current from merging into one idea.",
        concept,
        mastery,
        contract(
            concept_targets=["Identify node platforms as same-potential regions.", "Apply Kirchhoff's current law at junctions.", "Explain why parallel branches share voltage but can carry different currents."],
            core_concepts=["Ideal-wire-connected points lie on the same node platform and share one potential.", "At any node, current entering equals current leaving.", "Parallel branches between the same two nodes share the same potential difference.", "Branch current can differ because branch resistance can differ."],
            prerequisite_lessons=["M11_L2", "A2_L2"],
            misconception_focus=["node_potential_everywhere_different_confusion", "junction_current_loss_confusion", "parallel_voltage_current_mixup", "complex_circuit_branch_voltage_confusion"],
            formulas=[relation("sum I in = sum I out", "Kirchhoff current law at a node.", ["A"], "Use for steady-state junction bookkeeping."), relation("V component = V node high - V node low", "A component's potential difference is the difference between the heights of its end nodes.", ["V"], "Use when analyzing complex networks by node platforms.")],
            representations=[representation("words", "Explains node platforms and branch splitting."), representation("formula", "Captures current bookkeeping and node-to-node voltage."), representation("diagram", "Shows node platforms, branches, and checkpoint counts."), representation("model", "Uses the terrace-network picture of nodes and branches.")],
            analogy_map=terrace_map("the learner colors node platforms and audits branch currents at a junction"),
            worked_examples=[worked("A node has 6 A entering and one branch carrying 2 A away. Find the other leaving current.", ["Apply KCL.", "Set 6 = 2 + I.", "Solve for I."], "4 A", "Charge does not accumulate at the steady node.", "This anchors the junction count rule."), worked("Two branches connect the same node pair. Explain what they share.", ["Read the end nodes.", "Notice the same node-to-node height difference.", "Conclude the branch voltage matches."], "They share the same potential difference", "Branch voltage comes from the end-node heights, not from branch current.", "This protects the parallel-voltage idea."), worked("A learner says current is used up in the first branch. Diagnose the issue.", ["Keep charge conservation at the node.", "Split the current instead of destroying it.", "Recombine the branch currents to recover the total."], "The learner is breaking charge bookkeeping", "KCL is a conservation statement, not a battery preference.", "This blocks a central network misconception.")],
            visual_assets=[visual("a2_l5_node_platform_diagram", "node_platforms", "Node platforms reveal hidden equal-potential regions", "Show a split network with node platforms colored, equal branch voltage marked, and current splitting at a junction.", "Parallel branches share node-to-node terrace drop while current splits.")],
            animation_assets=[animation("a2_l5_node_platform_animation", "node_platforms", "Current split and recombination", "Animate current dividing at one node, flowing through unequal branches, and recombining at a later node.")],
            simulation_contract=sim_contract(
                "a2_l5_node_platform_sim",
                "node_platforms",
                "Change branch resistances in a split deck and compare the node heights with the split and recombined currents.",
                "Start with equal branches between the same two nodes.",
                ["Increase one branch resistance and compare the branch currents.", "Keep the branch end nodes fixed and compare the unchanged branch voltage."],
                "Watch for the branch voltage staying the same while the current split changes with branch resistance.",
                "Node-height analysis reveals why branch voltages can match even when branch currents do not.",
                controls=[("source_voltage", "Source voltage", "Sets the overall terrace rise feeding the branch deck."), ("branch_resistance_1", "Branch 1 resistance", "Changes one branch current without moving the end nodes."), ("branch_resistance_2", "Branch 2 resistance", "Changes the second branch current for comparison.")],
                readouts=[("Node heights", "Shows the terrace heights of the main platforms."), ("Branch currents", "Shows how the total current splits across the branches."), ("Main current", "Shows the recombined current and supports KCL bookkeeping.")],
            ),
            reflection_prompts=["Explain why node-platform thinking is more powerful than following each wire separately in a complex circuit.", "Describe how KCL and same-node voltage work together in a parallel section."],
            mastery_skills=["node_potential", "kirchhoff_current_law", "parallel_voltage", "branch_current_split", "node_height_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between KCL arithmetic, ideal-wire node statements, and branch-voltage-versus-branch-current distinctions.", "concept_gate": "Concept checks vary between node-platform explanations, parallel-branch corrections, and short KCL reasoning prompts.", "mastery": "Mastery alternates between junction calculations, branch-voltage/current interpretation, and summary statements about node heights."},
            scaffold_support=scaffold("Node height is the hidden structure under a complex circuit.", "Color the ideal-wire-connected regions first, then read every component voltage as the difference between two node heights and every junction current using KCL.", "Do these two points lie on one node platform or on different ones?", "Thinking parallel means same current instead of same node-to-node voltage.", "The terrace mesh becomes manageable once the circuit is broken into flat node platforms connected by drops and splits.", "Why does a branch current split not require a branch voltage split too?", extras=[extra_section("Node rule", "Ideal wires are flat walkways in the simple model, so they do not change terrace height.", "What is the voltage drop along an ideal wire?"), extra_section("Junction rule", "The node count balances because charge does not build up at the node in steady state.", "What must entering current equal?")]),
            visual_clarity_checks=visual_checks("node-platform"),
        ),
    )


def lesson_six() -> Dict[str, Any]:
    diagnostic = [
        mcq("A2L6_D1", "Kirchhoff's voltage law says that around a closed loop...", ["the total potential rises and drops add to zero", "all component voltages are equal", "current must be zero", "resistance must be equal"], 0, "The loop returns to its starting terrace height.", ["kvl_all_voltages_equal_confusion"], skill_tags=["kirchhoff_voltage_law"]),
        mcq("A2L6_D2", "An ideal wire segment contributes to a loop audit by...", ["approximately 0 V drop", "creating the full source rise", "doubling every resistor drop", "absorbing current"], 0, "Ideal wires are flat walkways in the simple model.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["loop_height_rule"]),
        mcq("A2L6_D3", "A loop contains a 12 V lift tower and two drops of 5 V and 7 V. The loop audit gives...", ["0 V total", "24 V total", "12 V total", "2 V total"], 0, "Rises and drops balance to zero.", ["kvl_all_voltages_equal_confusion"], skill_tags=["kirchhoff_voltage_law"]),
        mcq("A2L6_D4", "If a branch lies between a 10 V node and a 4 V node, the branch voltage magnitude is...", ["6 V", "14 V", "4 V", "10 V"], 0, "Component voltage is node-height difference.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"]),
        mcq("A2L6_D5", "Which statement is strongest?", ["Different components in one loop can have different voltage drops as long as the full loop balances.", "All voltages in one loop must be equal.", "Only batteries can have voltage.", "Parallel branches cannot share voltage."], 0, "KVL is a sum rule, not an equality-of-all-drops rule.", ["kvl_all_voltages_equal_confusion"], skill_tags=["kirchhoff_voltage_law"]),
        mcq("A2L6_D6", "A source raises charges by 18 V around a loop. One resistor drops 11 V. The remaining drop elsewhere must be...", ["7 V", "29 V", "18 V", "11 V"], 0, "The loop must balance back to zero net change.", ["kvl_all_voltages_equal_confusion"], skill_tags=["loop_audit"]),
        mcq("A2L6_D7", "In a complex circuit, a component's potential difference is best found from...", ["the heights of the nodes at its ends", "the number of symbols in the branch", "the total current in the whole circuit only", "the battery current rating"], 0, "Node heights reveal component voltage.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"]),
        mcq("A2L6_D8", "If a full walk around a loop ends 3 V above the starting terrace, the audit is...", ["incomplete or inconsistent", "perfectly valid", "proof all voltages are equal", "proof current is zero"], 0, "A closed loop must return to the starting height.", ["kvl_all_voltages_equal_confusion"], skill_tags=["loop_height_rule"]),
        short("A2L6_D9", "Why is KVL an energy-bookkeeping rule?", ["Because the battery raises electric potential and components lower it, so a full closed walk must balance all rises and drops back to the starting energy level per charge.", "Because the loop audit tracks electric height gains and losses around a closed path, which is conservation of energy per charge."], "Use closed-loop height balance language.", ["kvl_all_voltages_equal_confusion"], skill_tags=["loop_height_rule"], acceptance_rules=acceptance_groups(["closed loop", "full walk"], ["rises and drops", "height gains and losses"], ["balance", "sum to zero", "same starting level"])) ,
        short("A2L6_D10", "Why is it wrong to say KVL means all voltages are equal?", ["Because KVL says the algebraic sum of the rises and drops around a loop is zero, not that every component has the same voltage drop.", "Because components can have different voltage changes; the rule is about the loop balance, not equality of all voltages."], "Use sum-rule language, not all-equal language.", ["kvl_all_voltages_equal_confusion"], skill_tags=["kirchhoff_voltage_law"], acceptance_rules=acceptance_groups(["sum", "algebraic sum", "add to zero"], ["rises and drops", "voltage changes"], ["not all equal", "different component voltages"])) ,
    ]
    concept = [
        mcq("A2L6_C1", "A loop has a 9 V battery and drops of 4 V and 2 V so far. The missing drop is...", ["3 V", "7 V", "15 V", "11 V"], 0, "The total drops must equal the total rise.", ["kvl_all_voltages_equal_confusion"], skill_tags=["loop_audit"]),
        mcq("A2L6_C2", "Two nodes are at 15 V and 6 V. A resistor between them has voltage drop magnitude...", ["9 V", "21 V", "15 V", "6 V"], 0, "Take the difference between node heights.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"]),
        mcq("A2L6_C3", "Which statement is strongest?", ["A mesh audit becomes easier when node heights are known.", "Loop rules make node potentials unnecessary.", "Every branch in a complex circuit has different voltage by default.", "Ideal wires must always be high-resistance drops."], 0, "Node heights reveal branch voltages cleanly.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["mesh_audit"]),
        mcq("A2L6_C4", "A loop contains one 6 V rise and one 6 V drop. The net loop change is...", ["0 V", "12 V", "6 V", "-6 V"], 0, "Closed loop balance.", ["kvl_all_voltages_equal_confusion"], skill_tags=["kirchhoff_voltage_law"]),
        mcq("A2L6_C5", "A component connected between nodes at the same potential has voltage...", ["0 V", "equal to the current", "equal to the resistance", "infinite"], 0, "Same node height means no drop.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"]),
        mcq("A2L6_C6", "If an ideal wire is modeled as flat, then its voltage drop is...", ["negligible", "always the largest in the loop", "equal to the source emf", "undefined"], 0, "Flat walkway means no meaningful drop.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["loop_height_rule"]),
        short("A2L6_C7", "Why can two different branches still have the same voltage drop in a complex circuit?", ["Because they connect the same pair of nodes, so the voltage across each branch is the same node-height difference.", "Because branch voltage depends on the end-node potentials, not on the detailed path through the branch."], "Use same-end-node language.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"], acceptance_rules=acceptance_groups(["same two nodes", "same pair of nodes"], ["same voltage", "same potential difference", "same height difference"], ["path does not matter", "not the detailed branch path"])) ,
        short("A2L6_C8", "A learner says, 'Since KVL is true, every resistor in the loop must drop the same voltage.' What correction is needed?", ["KVL only says the total rises and drops around the full loop balance; individual resistors can have different voltage drops.", "The loop sum must be zero, but component drops need not be equal to each other."], "Keep the global balance separate from local drops.", ["kvl_all_voltages_equal_confusion"], skill_tags=["kirchhoff_voltage_law"], acceptance_rules=acceptance_groups(["total", "sum", "full loop"], ["balance", "zero"], ["different resistor drops", "not equal", "component voltages can differ"])) ,
    ]
    mastery = [
        mcq("A2L6_M1", "A loop has a 15 V source and drops of 4 V, 5 V, and x V. x is...", ["6 V", "10 V", "14 V", "24 V"], 0, "Drops must total 15 V.", ["kvl_all_voltages_equal_confusion"], skill_tags=["loop_audit"]),
        mcq("A2L6_M2", "Nodes A and B are at 18 V and 11 V. A component between them has potential difference magnitude...", ["7 V", "29 V", "18 V", "11 V"], 0, "Subtract the node heights.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"]),
        mcq("A2L6_M3", "A closed loop contains rises of 5 V and 7 V. The total drops must be...", ["12 V", "7 V", "5 V", "0 V"], 0, "Loop gains and losses balance.", ["kvl_all_voltages_equal_confusion"], skill_tags=["kirchhoff_voltage_law"]),
        mcq("A2L6_M4", "If one branch of a complex circuit joins nodes at 9 V and 3 V, any other branch joining the same nodes has voltage...", ["6 V", "12 V", "3 V", "9 V"], 0, "Same end nodes give same branch voltage.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"]),
        mcq("A2L6_M5", "Which is the best first move in a complex-circuit voltage problem?", ["Identify node platforms and label their heights", "Assume every resistor has equal voltage", "Ignore the battery and start with current only", "Treat every wire as a major drop"], 0, "Node platforms expose the hidden structure.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["mesh_audit"]),
        mcq("A2L6_M6", "If a loop audit gives +2 V instead of 0 V after a full walk, the statement is...", ["the audit has an error or a missing rise/drop", "the circuit proves KVL is false", "all voltages are equal", "the battery creates current directly"], 0, "Closed loops must return to the starting height.", ["kvl_all_voltages_equal_confusion"], skill_tags=["loop_height_rule"]),
        short("A2L6_M7", "Why is node-height thinking useful in complex circuits even before you calculate every current?", ["Because once the node potentials are known, each component voltage is just the difference between its two end nodes.", "Because node heights turn many complicated branch questions into simple height differences across components."], "Use node-to-component simplification language.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["mesh_audit", "node_voltage_difference"], acceptance_rules=acceptance_groups(["node potential", "node height"], ["component voltage", "height difference", "between end nodes"], ["simplify", "easier", "complex circuits"])) ,
        short("A2L6_M8", "Summarize KVL in terrace language.", ["A full closed walk around the circuit must return to the starting terrace height, so all rises and drops balance to zero.", "Batteries lift charges up the terrace and components bring them down again, so the closed-loop height change is zero."], "Keep the summary focused on lift, drop, and return.", ["kvl_all_voltages_equal_confusion"], skill_tags=["loop_height_rule", "kirchhoff_voltage_law"], acceptance_rules=acceptance_groups(["closed loop", "full walk"], ["starting height", "same level"], ["rises and drops", "lift and drop"], ["zero", "balance"])) ,
        mcq("A2L6_M9", "If a component lies entirely on one node platform in the ideal-wire model, its voltage is...", ["0 V", "equal to the battery voltage", "equal to the current", "impossible to know"], 0, "One node platform means no terrace drop.", ["complex_circuit_branch_voltage_confusion"], skill_tags=["node_voltage_difference"]),
        mcq("A2L6_M10", "Best final summary of A2:", ["Fields are slopes, voltages are terrace drops, capacitors store separated charge across a field gap, and Kirchhoff rules keep the mesh balanced.", "Current alone explains every advanced-electricity idea.", "All voltages in all branches must be equal.", "Capacitors store charge by letting it cross the gap."], 0, "That captures the full Charge-Terrace mesh model.", ["kvl_all_voltages_equal_confusion", "complex_circuit_branch_voltage_confusion"], skill_tags=["kirchhoff_voltage_law", "mesh_audit"]),
    ]
    return lesson_spec(
        "A2_L6",
        "Loop Height Rule and Mesh Audit",
        sim(
            "a2_mesh_audit_lab",
            "Mesh audit lab",
            "Walk around loops, read node heights, and balance rises and drops to solve unknown voltages in a complex circuit.",
            ["Label the node platforms.", "Choose one closed loop.", "Track each rise and drop until the loop closes."],
            ["Apply Kirchhoff's voltage law.", "Find component voltage from node heights.", "Use loop balance to solve an unknown drop."],
            ["source_rise", "drop_one", "drop_two", "node_height_a", "node_height_b"],
            "Loop-audit reasoning.",
        ),
        diagnostic,
        "The final terrace layer is the mesh audit. Ideal wires become flat walkways, batteries become lift towers, and resistors become drop ramps. If you walk a full closed route through the network, every rise and drop must bring you back to your starting terrace height. In a complex circuit, the cleanest move is often to label the node heights first and then treat each component voltage as an end-node difference.",
        "Audit the node heights and loop rises/drops before you chase every branch detail.",
        [prompt_block("What must a full closed walk around the mesh return to?", "The starting terrace height."), prompt_block("What is a component voltage in node language?", "The height difference between its end nodes.")],
        [prompt_block("Keep the source rise fixed and adjust one unknown drop.", "The loop total should return to zero."), prompt_block("Move to a branch between known nodes and compare its voltage with the node-height difference.", "The branch voltage should match the node drop.")],
        ["Why is KVL a conservation rule rather than a component-equality rule?", "Why do node platforms simplify complex-circuit voltage questions so strongly?"],
        "Use the mesh audit to turn complex loops into height bookkeeping instead of guesswork.",
        concept,
        mastery,
        contract(
            concept_targets=["Apply Kirchhoff's voltage law as a closed-loop balance rule.", "Find component voltage from node-height differences.", "Use node platforms and loop audits together in complex circuits."],
            core_concepts=["Around any closed loop, the total rises and drops in potential sum to zero.", "Ideal wires have negligible voltage drop in the simple model.", "Component voltage is the difference between the potentials of its end nodes.", "Complex circuits become manageable when node heights and loop balances are tracked systematically."],
            prerequisite_lessons=["A2_L5", "M11_L1"],
            misconception_focus=["kvl_all_voltages_equal_confusion", "complex_circuit_branch_voltage_confusion", "node_potential_everywhere_different_confusion"],
            formulas=[relation("sum Delta V = 0", "Kirchhoff voltage law around a closed loop.", ["V"], "Use for loop audits in complex circuits."), relation("V component = V node high - V node low", "Component voltage as node-height difference.", ["V"], "Use for any component whose end-node potentials are known.")],
            representations=[representation("words", "Explains loop height balance and node analysis."), representation("formula", "Captures KVL and node-height differences."), representation("diagram", "Shows lift towers, drop ramps, and node platforms in one mesh."), representation("model", "Uses the Charge-Terrace mesh audit picture.")],
            analogy_map=terrace_map("the learner labels node heights, walks closed loops, and balances all rises and drops"),
            worked_examples=[worked("A loop has a 12 V lift and drops of 5 V and 3 V. Find the missing drop.", ["Apply loop balance.", "Set 12 = 5 + 3 + x.", "Solve x = 4."], "4 V", "The full loop must return to its starting height.", "This anchors KVL as a balance rule."), worked("A resistor connects nodes at 14 V and 9 V. Find its voltage drop magnitude.", ["Read the node heights.", "Subtract 14 - 9.", "State the 5 V drop."], "5 V", "Component voltage is node-height difference.", "This keeps node analysis concrete."), worked("A learner says KVL means every resistor in a loop has the same drop. Diagnose the issue.", ["Keep the total-sum rule.", "Allow different components to drop different amounts.", "Balance them only in the full loop."], "The learner is turning a sum rule into an equality rule", "KVL audits the whole loop, not each component individually.", "This blocks the most common KVL wording error.")],
            visual_assets=[visual("a2_l6_mesh_audit_diagram", "mesh_audit", "Loop audits track terrace rises and drops through a complex mesh", "Show a source lift, several component drops, node-height labels, and one closed audit path whose total returns to zero.", "Node heights plus loop balance turn complex circuits into terrain bookkeeping.")],
            animation_assets=[animation("a2_l6_mesh_audit_animation", "mesh_audit", "Walking a closed loop through the mesh", "Animate a full loop audit around a complex circuit, adding rises and drops until the start height is recovered.")],
            simulation_contract=sim_contract(
                "a2_l6_mesh_audit_sim",
                "mesh_audit",
                "Adjust node heights and component drops, then walk a closed loop until the total rise and drop balances.",
                "Begin with one source rise and two known drops, leaving one drop unknown.",
                ["Solve the missing drop from loop balance.", "Move to a branch between known nodes and compare its voltage with the node-height difference."],
                "Watch for ideal wires contributing no meaningful drop and for the full loop always returning to the starting node height.",
                "Kirchhoff's laws are conservation rules expressed as node bookkeeping and loop-height balance.",
                controls=[("source_rise", "Source rise", "Sets the terrace lift around the chosen loop."), ("drop_one", "Drop 1", "Sets one component voltage drop."), ("drop_two", "Drop 2", "Sets another component voltage drop or branch value.")],
                readouts=[("Loop sum", "Shows the algebraic total of all rises and drops around the chosen loop."), ("Node heights", "Shows the terrace heights of the key nodes."), ("Unknown drop", "Shows the missing drop inferred from the audit.")],
            ),
            reflection_prompts=["Explain why the full loop must return to its starting terrace height in the Charge-Terrace model.", "Describe why node potentials are often the hidden structure underneath complex-circuit voltage problems."],
            mastery_skills=["kirchhoff_voltage_law", "loop_height_rule", "node_voltage_difference", "mesh_audit", "node_height_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between loop-balance statements, node-height differences, and simple missing-drop arithmetic with new values.", "concept_gate": "Concept checks vary between KVL wording corrections, node-platform voltage explanations, and simple branch-voltage reasoning.", "mastery": "Mastery alternates between loop-audit calculations, node-difference prompts, and summary statements about mesh analysis so fresh attempts prefer new stems first."},
            scaffold_support=scaffold("A closed loop must climb and descend back to the same electric height.", "Identify the nodes, then audit one loop at a time by listing each lift and each drop.", "Does this full walk return to the same terrace height where it started?", "Interpreting KVL as 'all voltages are equal' instead of 'all rises and drops balance'.", "The mesh audit is like hiking a terrace circuit: after a full lap, the total climb and descent must cancel.", "Why can one loop contain several different voltage drops and still satisfy KVL?", extras=[extra_section("Loop rule", "List each source rise and component drop with its sign, then force the closed-loop total to zero.", "What should the total be at the end?"), extra_section("Node rule", "Whenever node heights are known, component voltage is only the difference between the two node levels.", "What sets a branch voltage?")]),
            visual_clarity_checks=visual_checks("mesh-audit"),
        ),
    )


A2_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Electric fields, electric potential, capacitance, and Kirchhoff analysis taught through the Charge-Terrace Mesh Model so learners read advanced electricity as one electric-height world of slopes, terraces, split-deck stores, node platforms, and loop audits.",
    "mastery_outcomes": [
        "Explain electric field as a spatial push map for a positive test charge.",
        "Distinguish electric field from electric potential and read voltage as terrace drop or energy change per charge.",
        "Use uniform-field reasoning between plates to connect E, Delta V, and distance conceptually and quantitatively.",
        "Explain capacitance as stored charge per volt and as energy stored in the electric field between separated charges.",
        "Use Kirchhoff current and voltage laws as conservation tools in complex circuits.",
        "Reason about potential differences in advanced circuits by tracking node platforms and loop-height balance.",
    ],
    "lessons": [lesson_one(), lesson_two(), lesson_three(), lesson_four(), lesson_five(), lesson_six()],
}


RELEASE_CHECKS = [
    "Every lesson keeps field, potential, capacitance, and Kirchhoff reasoning inside one Charge-Terrace mesh story.",
    "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
    "Every lesson-owned assessment bank supports fresh unseen diagnostic, concept-gate, and mastery questions before repeats.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example explains why the answer follows instead of naming only the final value.",
    "Every advanced-electricity visual keeps field arrows, terrace labels, node heights, and circuit drops readable without clipping.",
]


A2_MODULE_DOC, A2_LESSONS, A2_SIM_LABS = build_nextgen_module_bundle(
    module_id=A2_MODULE_ID,
    module_title=A2_MODULE_TITLE,
    module_spec=A2_SPEC,
    allowlist=A2_ALLOWLIST,
    content_version=A2_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=19,
    level="Module A2",
    estimated_minutes=360,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module A2 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(A2_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A2_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A2_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    plan: List[Tuple[str, str]] = [("modules", A2_MODULE_ID)]
    plan.extend(("lessons", doc_id) for doc_id, _ in lesson_pairs)
    plan.extend(("sim_labs", doc_id) for doc_id, _ in sim_pairs)
    print_preview(f"Module {A2_MODULE_ID}: {A2_MODULE_TITLE}", plan)
    db = init_firebase(project) if args.apply else None

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
    main()
