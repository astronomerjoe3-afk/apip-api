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


A4_MODULE_ID = "A4"
A4_CONTENT_VERSION = "20260322_a4_bounce_chamber_count_v1"
A4_MODULE_TITLE = "Thermal & Statistical Physics"
A4_ALLOWLIST = [
    "pressure_weight_confusion",
    "pressure_all_walls_confusion",
    "temperature_total_energy_confusion",
    "equilibrium_no_motion_confusion",
    "volume_collision_rate_confusion",
    "ideal_gas_formula_only_confusion",
    "gas_law_ratio_confusion",
    "kinetic_theory_disconnect_confusion",
    "mean_square_speed_confusion",
    "same_temperature_same_average_ke_confusion",
    "entropy_disorder_only_confusion",
    "microstate_macrostate_confusion",
    "partition_entropy_confusion",
    "spontaneous_change_preference_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(A4_ALLOWLIST)
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


def visual(
    asset_id: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    diagram_type: str,
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    resolved_meta = {"diagram_type": diagram_type, **deepcopy(meta or {})}
    return {
        "asset_id": asset_id,
        "concept": "thermal_statmech_diagram",
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": "thermal_statmech_diagram",
        "meta": resolved_meta,
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
        "Chamber walls, particles, arrows, and formula labels remain separated so microscopic and macroscopic ideas do not collapse together.",
        "Before-and-after states stay visually distinct whenever chambers, partitions, or energy levels are being compared.",
        "Option-count, pressure, and temperature labels stay outside the busiest particle regions so the physics remains readable.",
    ]


def bounce_chamber_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Bounce-Chamber Count Model",
        "focus": focus,
        "comparison": f"The Bounce-Chamber world keeps ideal-gas behaviour, kinetic theory, and entropy inside one hidden-movers story while {focus}.",
        "mapping": [
            "Micro-dashers -> gas molecules",
            "Chamber -> gas container",
            "Crowd count -> N or n",
            "Room size -> volume",
            "Wall-hit load -> pressure",
            "Dash level -> temperature",
            "Average dash energy -> mean translational kinetic energy",
            "Dashboard state -> macrostate",
            "Hidden playbook -> microstate",
            "Option count -> W",
            "Spread score -> entropy",
        ],
        "limit": "The chamber story makes the physics intuitive, but learners still need the formal gas-law, kinetic-theory, and entropy equations.",
        "prediction_prompt": f"Use the Bounce-Chamber model to predict what should happen when {focus}.",
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
        "controls": [{"variable": a, "label": b, "why_it_matters": c} for a, b, c in controls],
        "readouts": [{"label": a, "meaning": b} for a, b in readouts],
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


# Lesson authoring content appended below.


def build_mcqs(rows: Sequence[Tuple[str, str, Sequence[str], int, str, Sequence[str], Sequence[str]]]) -> List[Dict[str, Any]]:
    return [
        mcq(qid, prompt, choices, answer_index, hint, tags, skill_tags=skill_tags)
        for qid, prompt, choices, answer_index, hint, tags, skill_tags in rows
    ]


def build_shorts(
    rows: Sequence[Tuple[str, str, Sequence[str], str, Sequence[str], Sequence[str], Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    return [
        short(
            qid,
            prompt,
            accepted_answers,
            hint,
            tags,
            skill_tags=skill_tags,
            acceptance_rules=acceptance_rules,
        )
        for qid, prompt, accepted_answers, hint, tags, skill_tags, acceptance_rules in rows
    ]


def lesson_one() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("A4L1_D1", "In the Bounce-Chamber model, wall-hit load stands for...", ["pressure", "volume", "entropy", "mole"], 0, "Pressure is the steady effect of molecular wall collisions.", ["pressure_weight_confusion"], ["pressure_from_collisions"]),
        ("A4L1_D2", "Gas pressure in a sealed chamber mainly comes from...", ["many random molecular collisions with the walls", "the gas resting on the floor only", "the molecules stopping at equilibrium", "entropy acting directly on the walls"], 0, "Pressure is a collision story.", ["pressure_weight_confusion", "equilibrium_no_motion_confusion"], ["pressure_from_collisions"]),
        ("A4L1_D3", "At fixed chamber size and dash level, adding more dashers makes the pressure...", ["increase", "decrease", "stay the same", "become zero"], 0, "More dashers means more wall hits.", ["gas_law_ratio_confusion"], ["pressure_compare_n"]),
        ("A4L1_D4", "At fixed crowd count and temperature, making the chamber larger tends to make pressure...", ["decrease", "increase", "stay the same", "depend only on mass"], 0, "A larger chamber lowers the wall-hit rate.", ["volume_collision_rate_confusion"], ["pressure_compare_v"]),
        ("A4L1_D5", "At fixed crowd count and volume, heating the gas tends to make pressure...", ["increase", "decrease", "stay the same", "reverse sign"], 0, "Hotter molecules hit faster and harder.", ["temperature_total_energy_confusion"], ["pressure_compare_t"]),
        ("A4L1_D6", "A gas at equilibrium in a sealed box has molecules that...", ["still move randomly and keep colliding", "stop moving completely", "only sit on the bottom wall", "all move at the same speed"], 0, "Equilibrium means steady macrostate, not frozen particles.", ["equilibrium_no_motion_confusion"], ["equilibrium_motion"]),
        ("A4L1_D7", "Doubling the number of molecules at fixed volume and temperature would make pressure roughly...", ["double", "halve", "stay the same", "quarter"], 0, "Pressure is proportional to crowd count when V and T stay fixed.", ["gas_law_ratio_confusion"], ["pressure_compare_n"]),
        ("A4L1_D8", "Doubling the chamber volume at fixed crowd count and temperature would make pressure roughly...", ["half", "double", "stay the same", "quadruple"], 0, "More room means fewer wall hits per area.", ["volume_collision_rate_confusion"], ["pressure_compare_v"]),
    ]) + build_shorts([
        ("A4L1_D9", "Why is 'pressure is wall-hit load' stronger than 'pressure is just the gas's weight'?", ["Because gas pressure comes from random molecular collisions on the walls in all directions, not just from weight pressing downward.", "Because the molecules keep hitting every wall, so pressure is a collision effect rather than only a downward weight effect."], "Mention collisions and all-wall pressure, not only downward weight.", ["pressure_weight_confusion", "pressure_all_walls_confusion"], ["pressure_from_collisions"], acceptance_groups(["collision", "wall hit", "hit the walls"], ["all directions", "all walls", "not just downward"], ["not just weight", "not only weight"])),
        ("A4L1_D10", "Why does a larger chamber lower pressure if the same molecules stay at the same temperature?", ["Because the molecules have more room, so they strike the walls less often and the average wall-hit load falls.", "Because increasing volume reduces the collision rate with the walls when crowd count and temperature stay fixed."], "Use room-size and collision-rate language.", ["volume_collision_rate_confusion"], ["pressure_compare_v"], acceptance_groups(["more room", "larger chamber", "bigger volume"], ["hit the walls less often", "collision rate falls"], ["pressure falls", "wall-hit load falls"])),
    ])
    concept = build_mcqs([
        ("A4L1_C1", "Which statement is strongest?", ["Pressure is the macroscopic effect of huge numbers of molecular wall collisions.", "Pressure is the weight of gas alone.", "Pressure means molecules stop moving.", "Pressure is a kind of entropy."], 0, "Keep the collision story central.", ["pressure_weight_confusion", "equilibrium_no_motion_confusion"], ["pressure_from_collisions"]),
        ("A4L1_C2", "A chamber keeps the same molecules and the same volume, but the temperature rises. The best explanation for the pressure change is...", ["molecules hit the walls more energetically", "the chamber mass disappears", "volume must shrink", "entropy becomes zero"], 0, "Hotter molecules carry more kinetic energy.", ["temperature_total_energy_confusion"], ["pressure_compare_t"]),
        ("A4L1_C3", "Why does pressure act on the side walls as well as the floor?", ["Because molecules move randomly and collide with all walls", "Because gravity pushes the gas sideways", "Because the gas only wants to expand sideways", "Because entropy only acts horizontally"], 0, "Pressure is not a floor-only idea.", ["pressure_all_walls_confusion"], ["pressure_from_collisions"]),
        ("A4L1_C4", "If crowd count and dash level stay fixed while room size shrinks, pressure should...", ["increase", "decrease", "stay the same", "become undefined"], 0, "Smaller volume raises the collision rate.", ["volume_collision_rate_confusion"], ["pressure_compare_v"]),
        ("A4L1_C5", "A steady macrostate means...", ["pressure and temperature are stable while molecules still move", "molecules stop completely", "the chamber has no collisions", "all molecules share one speed"], 0, "Steady averages do not mean frozen molecules.", ["equilibrium_no_motion_confusion"], ["equilibrium_motion"]),
        ("A4L1_C6", "Which change would definitely raise pressure at fixed volume?", ["adding molecules or heating the gas", "making the chamber larger", "removing all collisions", "redefining entropy"], 0, "Both higher crowd count and higher temperature raise pressure.", ["gas_law_ratio_confusion", "temperature_total_energy_confusion"], ["pressure_compare_n"]),
    ]) + build_shorts([
        ("A4L1_C7", "Explain why a hotter gas gives a larger pressure at fixed volume.", ["Because the molecules have greater average kinetic energy, so their collisions with the walls are harder and more frequent in momentum change.", "Because temperature raises the average dash energy, which makes wall collisions produce a larger wall-hit load."], "Link temperature to average kinetic energy and wall momentum change.", ["temperature_total_energy_confusion"], ["pressure_compare_t"], acceptance_groups(["hotter", "higher temperature"], ["greater average kinetic energy", "more energetic"], ["harder collisions", "greater wall-hit load", "larger pressure"])),
        ("A4L1_C8", "A learner says, 'At equilibrium the gas has settled down so the particles are basically still.' What correction should you make?", ["At equilibrium the macrostate is steady, but the molecules still move randomly and collide continually.", "Equilibrium means steady pressure and temperature, not that the microscopic motion has stopped."], "Contrast steady averages with ongoing molecular motion.", ["equilibrium_no_motion_confusion"], ["equilibrium_motion"], acceptance_groups(["equilibrium"], ["macrostate", "pressure and temperature", "steady"], ["molecules still move", "still collide", "not still"])),
    ])
    mastery = build_mcqs([
        ("A4L1_M1", "A gas in a rigid chamber is heated. Which outcome is most likely?", ["Pressure rises because the wall-hit load rises.", "Pressure falls because molecules spread out more.", "Pressure stays fixed because volume is fixed.", "Pressure becomes zero because equilibrium returns."], 0, "Rigid volume does not stop pressure from changing.", ["temperature_total_energy_confusion"], ["pressure_compare_t"]),
        ("A4L1_M2", "If the number of molecules is cut in half at fixed volume and temperature, pressure should...", ["halve", "double", "stay the same", "quadruple"], 0, "Half the crowd gives about half the wall-hit load.", ["gas_law_ratio_confusion"], ["pressure_compare_n"]),
        ("A4L1_M3", "Which statement best protects against the pressure-weight misconception?", ["Pressure is a collision effect on all walls.", "Pressure only belongs at the base of the chamber.", "Pressure vanishes when gravity is weak.", "Pressure means molecules stop moving."], 0, "Use all-wall collision language.", ["pressure_weight_confusion", "pressure_all_walls_confusion"], ["pressure_from_collisions"]),
        ("A4L1_M4", "A chamber becomes twice as large with the same molecules at the same temperature. The best reasoning is...", ["Pressure falls because the wall collision rate per area drops.", "Pressure rises because the gas weighs more.", "Pressure stays fixed because the molecules are unchanged.", "Pressure must become negative."], 0, "Room size changes the wall-hit story.", ["volume_collision_rate_confusion"], ["pressure_compare_v"]),
        ("A4L1_M5", "Which variable change gives the biggest clue that temperature is about molecular motion?", ["Hotter gas produces harder wall collisions.", "Hotter gas always has more molecules.", "Hotter gas has a larger mass number.", "Hotter gas loses all entropy."], 0, "Temperature tracks average kinetic energy, not amount of gas.", ["temperature_total_energy_confusion"], ["pressure_compare_t"]),
        ("A4L1_M7", "A gas with the same volume and particle count but a lower temperature should have...", ["lower pressure", "higher pressure", "the same pressure", "no collisions"], 0, "Cooler dashers carry less average kinetic energy.", ["temperature_total_energy_confusion"], ["pressure_compare_t"]),
        ("A4L1_M8", "Best first explanation when pressure rises after crowd count rises:", ["More molecules mean more wall impacts per second.", "The chamber becomes heavier, so pressure must rise.", "Entropy directly forces the pressure upward.", "Volume always shrinks at the same time."], 0, "More dashers means more momentum transfer events.", ["gas_law_ratio_confusion"], ["pressure_compare_n"]),
        ("A4L1_M9", "What remains true at equilibrium?", ["Molecules still move while average macroscopic quantities stay steady.", "Every molecule has stopped.", "Pressure exists only on the floor.", "Volume no longer matters."], 0, "Do not freeze the gas in your mental model.", ["equilibrium_no_motion_confusion"], ["equilibrium_motion"]),
    ]) + build_shorts([
        ("A4L1_M6", "Summarize gas pressure in one strong sentence.", ["Gas pressure is the steady macroscopic wall-hit load produced by huge numbers of random molecular collisions.", "Pressure in a gas comes from molecules colliding with the walls in all directions."], "Keep collisions and walls in the answer.", ["pressure_weight_confusion"], ["pressure_from_collisions"], acceptance_groups(["pressure"], ["collision", "wall hit", "molecules hitting"], ["walls", "all directions", "macroscopic"])),
        ("A4L1_M10", "Why is the Bounce-Chamber picture useful for pressure?", ["Because it lets you explain pressure from microscopic wall collisions instead of memorizing it as a mysterious bulk property.", "Because the chamber story connects particle motion, wall hits, and the visible pressure reading in one model."], "Link microscopic collisions to visible pressure.", ["ideal_gas_formula_only_confusion"], ["pressure_from_collisions"], acceptance_groups(["collision", "wall hit", "particle motion"], ["visible pressure", "macroscopic"], ["not mysterious", "model", "explain"])),
    ])
    return lesson_spec(
        "A4_L1",
        "Pressure as Wall-Hit Load",
        sim("a4_wall_hit_builder_lab", "Wall-hit builder lab", "Change chamber size, crowd count, and dash level so gas pressure becomes a collision story instead of a memorized label.", ["Hold two variables fixed while changing the third.", "Compare small and large chambers.", "Explain every pressure change using wall-hit language."], ["Explain pressure through molecular collisions.", "Predict how pressure changes with volume, particle count, and temperature.", "Protect against the 'pressure is just weight' misconception."], ["particle_count", "chamber_volume", "temperature_level", "pressure_readout"], "Bounce-chamber pressure reasoning."),
        diagnostic,
        "The Bounce-Chamber world begins with hidden movers striking the walls. Pressure is the average wall-hit load from huge numbers of momentum-changing collisions. A larger chamber spreads those collisions out. More dashers or hotter dashers raise the wall-hit load.",
        "Commit to pressure as an all-wall collision story rather than a floor-only weight story.",
        [prompt_block("What changes pressure besides the gas simply existing?", "Crowd count, room size, and dash level all matter."), prompt_block("What stays true at equilibrium?", "The molecules still move randomly and keep colliding.")],
        [prompt_block("Keep temperature fixed and shrink the chamber.", "The wall-hit load should rise."), prompt_block("Keep chamber size fixed and add more dashers.", "More collisions should raise pressure.")],
        ["Why is pressure better described as wall-hit load than as gas weight?", "Why does equilibrium not mean the molecules stop moving?"],
        "Keep the pressure story microscopic and physical before moving to gas-law formulas.",
        concept,
        mastery,
        contract(concept_targets=["Explain gas pressure as the effect of molecular wall collisions.", "Predict pressure changes when crowd count, room size, or dash level changes.", "Distinguish a steady macrostate from frozen microscopic motion."], core_concepts=["Pressure is a collision effect on all the chamber walls.", "More molecules raise pressure at fixed volume and temperature.", "Larger volume lowers pressure when crowd count and temperature stay fixed.", "Equilibrium keeps the macrostate steady while molecules still move randomly."], prerequisite_lessons=[], misconception_focus=["pressure_weight_confusion", "pressure_all_walls_confusion", "equilibrium_no_motion_confusion", "volume_collision_rate_confusion"], formulas=[relation("p ∝ wall collision rate x momentum change per collision", "Conceptual pressure rule from collisions.", ["Pa"], "Use as the meaning-first rule before the full ideal-gas law."), relation("pV = nRT", "Macroscopic chamber balance rule linking pressure, volume, amount, and temperature.", ["Pa m^3"], "Useful once the learner already trusts the collision story.")], representations=[representation("words", "Describes pressure as wall-hit load from hidden dashers."), representation("diagram", "Shows molecules colliding with all chamber walls."), representation("formula", "Links the chamber story to pV = nRT."), representation("model", "Keeps room size, crowd count, and dash level in one visible world.")], analogy_map=bounce_chamber_map("the learner compares how crowd count, room size, and dash level reshape wall-hit load"), worked_examples=[worked("At fixed chamber size and temperature, the crowd count doubles. What happens to pressure?", ["Keep volume and dash level fixed.", "Notice that more molecules hit the walls each second.", "Infer the new pressure trend from the increased wall-hit rate."], "Pressure doubles", "With volume and temperature fixed, doubling the number of molecules doubles the collision-driven wall-hit load.", "This is the cleanest route from the particle story into gas-law proportional reasoning."), worked("At fixed crowd count and temperature, the chamber volume doubles. What happens to pressure?", ["Keep the same number of molecules and the same dash level.", "Give the molecules more room.", "Infer the lower wall-hit rate and lower pressure."], "Pressure halves", "The same molecules now take longer between wall collisions, so the average pressure falls.", "This protects students from thinking pressure is unchanged when the particles themselves are unchanged.")], visual_assets=[visual("a4-l1-bounce-chamber-pressure", "Pressure as wall-hit load", "Show pressure as the steady effect of hidden dashers bouncing on the walls.", "Pressure is not the gas simply resting in the chamber. It is the average wall-hit load from many collisions.", diagram_type="bounce_chamber_pressure", meta={"particle_count": 12})], animation_assets=[], simulation_contract=sim_contract("a4_l1_wall_hit_builder_sim", "bounce_chamber_pressure", "Change one chamber variable at a time until pressure feels like a collision result rather than a mysterious label.", "Start with a medium crowd count, medium room size, and medium dash level.", ["Keep volume fixed and raise the dash level.", "Keep temperature fixed and double the crowd count.", "Keep crowd count and temperature fixed while expanding the room."], "Watch for pressure following the collision story every time a variable changes.", "Pressure is wall-hit load created by hidden dashers, and each gas-law variable changes that wall-hit story in a specific way.", controls=[("particle_count", "Crowd count", "Changes how many dashers can hit the walls."), ("chamber_volume", "Room size", "Changes how frequently the dashers reach the walls."), ("temperature_level", "Dash level", "Changes how energetic the wall collisions are.")], readouts=[("Pressure", "Shows the current wall-hit load."), ("Collision note", "Summarizes whether the chamber has more hits, fewer hits, or harder hits."), ("Macrostate", "Shows which variables are being held fixed.")]), reflection_prompts=["Explain why pressure acts on all the chamber walls rather than only downward.", "Explain why equilibrium does not mean the molecules have stopped moving."], mastery_skills=["pressure_from_collisions", "pressure_compare_n", "pressure_compare_v", "pressure_compare_t", "equilibrium_motion"], variation_plan={"diagnostic": "Fresh attempts rotate between all-wall collision explanations, fixed-variable pressure comparisons, and equilibrium checks before any repeat stems.", "concept_gate": "Concept-gate retries swap in new volume, temperature, and crowd-count stories so the same pressure misconception is tested from different angles.", "mastery": "Mastery varies ratio-style pressure changes and short collision explanations with new variable combinations before reusing a previous stem."}, scaffold_support=scaffold("Pressure is wall-hit load from hidden dashers.", "A gas seems smooth macroscopically because countless random collisions average into one steady pressure reading.", "Which chamber change alters the wall-hit story most directly in this example?", "Treating pressure as the gas simply resting on the floor of the container.", "The Bounce-Chamber model keeps pressure tied to molecular collisions on every wall, so pressure remains a dynamic motion story even at equilibrium.", "Why is 'all-wall collision load' better language than 'weight of the gas'?", extras=[extra_section("Macrostate vs microscopic motion", "Pressure and temperature can stay steady while the dashers continue to move and collide randomly.", "What stays steady, and what keeps changing, at equilibrium?"), extra_section("Volume changes", "A larger chamber does not remove collisions. It spreads them out over more space and time.", "Why does more room reduce wall-hit load if nothing else changes?")]), visual_clarity_checks=visual_checks("bounce-chamber pressure")),
    )


def lesson_two() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("A4L2_D1", "The ideal gas law in mole form is...", ["pV = nRT", "p = F/A", "E = mc^2", "S = k ln W"], 0, "The chamber balance rule is pV = nRT.", ["ideal_gas_formula_only_confusion"], ["use_ideal_gas_law"]),
        ("A4L2_D2", "At fixed n and T, increasing V makes p...", ["decrease", "increase", "stay the same", "become zero automatically"], 0, "The balance rule forces pressure down when volume rises.", ["gas_law_ratio_confusion"], ["gas_law_volume_ratio"]),
        ("A4L2_D3", "At fixed V and n, doubling T makes p...", ["double", "halve", "stay the same", "quarter"], 0, "Pressure is proportional to temperature at fixed V and n.", ["gas_law_ratio_confusion"], ["gas_law_temperature_ratio"]),
        ("A4L2_D4", "At fixed V and T, tripling n makes p...", ["triple", "third", "stay the same", "double"], 0, "More amount of gas means more pressure at fixed V and T.", ["gas_law_ratio_confusion"], ["gas_law_amount_ratio"]),
        ("A4L2_D5", "Which pressure is correct for n = 1 mol, T = 300 K, V = 0.025 m^3 using R = 8.31?", ["about 99 700 Pa", "about 10 Pa", "about 6900 Pa", "about 750 000 Pa"], 0, "Use p = nRT/V.", ["ideal_gas_formula_only_confusion"], ["use_ideal_gas_law"]),
        ("A4L2_D6", "The particle form of the ideal gas law is...", ["pV = NkT", "pV = Nm", "p = Nk/V^2", "p = RT only"], 0, "N counts molecules, not moles.", ["ideal_gas_formula_only_confusion"], ["particle_form"]),
        ("A4L2_D7", "If p and T stay fixed while n doubles, V must...", ["double", "halve", "stay the same", "become zero"], 0, "More gas at the same pressure and temperature needs more room.", ["gas_law_ratio_confusion"], ["gas_law_amount_ratio"]),
        ("A4L2_D8", "Which symbol counts molecules rather than moles?", ["N", "n", "R", "p"], 0, "N is number of molecules.", ["ideal_gas_formula_only_confusion"], ["particle_form"]),
    ]) + build_shorts([
        ("A4L2_D9", "Why is pV = nRT better thought of as a chamber balance rule than as a random memory test?", ["Because it links wall-hit load, room size, crowd count, and dash level in one relationship, so each variable has a physical role.", "Because the ideal gas law summarizes how pressure, volume, amount of gas, and temperature balance inside the chamber."], "Name the four balancing variables.", ["ideal_gas_formula_only_confusion"], ["chamber_balance_meaning"], acceptance_groups(["pressure", "wall-hit load"], ["volume", "room size"], ["amount of gas", "n", "crowd count"], ["temperature", "dash level"], ["balance", "relationship"])),
        ("A4L2_D10", "Why does increasing volume lower pressure when n and T stay fixed?", ["Because the same molecules with the same average dash energy now occupy more space, so wall collisions become less frequent.", "Because at fixed amount of gas and temperature, a larger room spreads the wall-hit load over a lower collision rate."], "Use fixed n, fixed T, more room, fewer hits language.", ["gas_law_ratio_confusion", "volume_collision_rate_confusion"], ["gas_law_volume_ratio"], acceptance_groups(["fixed n", "same amount"], ["fixed temperature", "same dash level"], ["larger volume", "more room"], ["fewer wall collisions", "lower collision rate"], ["pressure falls", "lower pressure"])),
    ])
    concept = build_mcqs([
        ("A4L2_C1", "A gas has p = 200 kPa and V = 0.010 m^3. If temperature is unchanged and volume becomes 0.020 m^3, pressure becomes...", ["100 kPa", "200 kPa", "400 kPa", "50 kPa"], 0, "Use inverse proportionality at fixed n and T.", ["gas_law_ratio_confusion"], ["gas_law_volume_ratio"]),
        ("A4L2_C2", "A gas keeps the same volume and amount, while absolute temperature rises from 300 K to 450 K. Pressure becomes...", ["1.5 times the original pressure", "0.5 times the original pressure", "double the original pressure", "unchanged"], 0, "Pressure follows temperature directly here.", ["gas_law_ratio_confusion"], ["gas_law_temperature_ratio"]),
        ("A4L2_C3", "Which statement connects pV = nRT and pV = NkT correctly?", ["Both describe the same macrostate, but one counts moles and the other counts molecules.", "They describe different gases that cannot be compared.", "The particle form ignores temperature.", "The mole form ignores pressure."], 0, "n and N are two ways of counting how much gas there is.", ["ideal_gas_formula_only_confusion"], ["particle_form"]),
        ("A4L2_C4", "A sample has n = 2 mol, T = 300 K, p = 100 kPa. If the amount doubles and pressure is held fixed, volume must...", ["double", "halve", "stay the same", "triple"], 0, "At fixed p and T, V is proportional to n.", ["gas_law_ratio_confusion"], ["gas_law_amount_ratio"]),
        ("A4L2_C5", "Which variable set fully specifies the ideal-gas macrostate in this module?", ["pressure, volume, temperature, and amount of gas", "pressure and mass only", "volume and entropy only", "temperature and force only"], 0, "The macrostate dashboard needs p, V, T, and amount.", ["ideal_gas_formula_only_confusion"], ["chamber_balance_meaning"]),
        ("A4L2_C6", "If both n and T double while V stays fixed, pressure should...", ["become four times as large", "double", "stay the same", "halve"], 0, "Pressure is proportional to both n and T when V stays fixed.", ["gas_law_ratio_confusion"], ["gas_law_amount_ratio"]),
    ]) + build_shorts([
        ("A4L2_C7", "Explain the difference between n and N in the gas-law forms.", ["n counts amount of gas in moles, while N counts the actual number of molecules.", "The mole form uses n, but the particle form uses N for the crowd count of molecules."], "Mention moles versus molecules directly.", ["ideal_gas_formula_only_confusion"], ["particle_form"], acceptance_groups(["n"], ["moles", "amount of gas"], ["N"], ["molecules", "particles", "crowd count"])),
        ("A4L2_C8", "A learner says, 'If pressure changes, the ideal gas law is broken.' What correction should you make?", ["The ideal gas law tells how pressure changes when volume, temperature, or amount of gas changes. A pressure change can still fit the law perfectly.", "The gas law is a balance relationship, so pressure is allowed to change when the other variables change."], "Use balance-rule language, not 'fixed equation' language.", ["ideal_gas_formula_only_confusion"], ["chamber_balance_meaning"], acceptance_groups(["pressure can change", "allowed to change"], ["volume", "temperature", "amount of gas"], ["still fit the law", "balance relationship"])),
    ])
    mastery = build_mcqs([
        ("A4L2_M1", "For a gas at fixed n and T, pressure is inversely proportional to...", ["volume", "temperature", "molecule mass", "entropy"], 0, "That is Boyle-style behaviour inside the ideal-gas law.", ["gas_law_ratio_confusion"], ["gas_law_volume_ratio"]),
        ("A4L2_M2", "A gas has p = 150 kPa, V = 0.012 m^3, T = 300 K. If T rises to 600 K at fixed volume and amount, p becomes...", ["300 kPa", "150 kPa", "75 kPa", "450 kPa"], 0, "Pressure doubles with absolute temperature here.", ["gas_law_ratio_confusion"], ["gas_law_temperature_ratio"]),
        ("A4L2_M3", "Which result is correct for N = 5 x 10^23 molecules, T = 300 K, pV = NkT with k = 1.38 x 10^-23?", ["about 2070 J", "about 20 J", "about 2.07 x 10^6 J", "about 690 J"], 0, "Compute NkT.", ["ideal_gas_formula_only_confusion"], ["particle_form"]),
        ("A4L2_M4", "At fixed pressure and temperature, if the amount of gas is cut to one third, the volume should...", ["drop to one third", "triple", "stay fixed", "double"], 0, "Volume tracks amount directly in this case.", ["gas_law_ratio_confusion"], ["gas_law_amount_ratio"]),
        ("A4L2_M5", "What does pV represent most naturally in the Bounce-Chamber model?", ["wall-hit load multiplied by room size", "the number of microstates", "temperature per molecule", "weight times height"], 0, "Keep the chamber meaning attached to the symbol.", ["ideal_gas_formula_only_confusion"], ["chamber_balance_meaning"]),
        ("A4L2_M7", "If p and n stay fixed while T doubles, volume must...", ["double", "halve", "stay the same", "fall to zero"], 0, "At fixed p and n, V is proportional to T.", ["gas_law_ratio_confusion"], ["gas_law_temperature_ratio"]),
        ("A4L2_M8", "Which statement best compares the two gas-law forms?", ["pV = nRT is mole-count language; pV = NkT is molecule-count language.", "One form is correct and the other is wrong.", "The particle form removes temperature.", "The mole form works only for liquids."], 0, "They are two count languages for the same ideal-gas relation.", ["ideal_gas_formula_only_confusion"], ["particle_form"]),
        ("A4L2_M9", "A gas has fixed volume. Both amount and absolute temperature fall to half their original values. Pressure becomes...", ["one quarter of the original pressure", "half", "the same", "double"], 0, "Pressure scales with both factors here.", ["gas_law_ratio_confusion"], ["gas_law_amount_ratio"]),
    ]) + build_shorts([
        ("A4L2_M6", "Summarize the ideal gas law in one strong sentence.", ["The ideal gas law says that pressure times volume balances amount of gas times temperature, so the chamber variables must be read together.", "pV = nRT is the chamber balance rule linking wall-hit load, room size, crowd count, and dash level."], "State the four variables and the balance idea.", ["ideal_gas_formula_only_confusion"], ["chamber_balance_meaning"], acceptance_groups(["pressure", "wall-hit load"], ["volume", "room size"], ["amount of gas", "n", "crowd count"], ["temperature", "dash level"], ["balance", "linked together"])),
        ("A4L2_M10", "Why is pV = NkT a useful bridge between the gas law and the hidden-dasher picture?", ["Because N counts actual molecules, so the particle form keeps the macroscopic gas law connected to the microscopic crowd.", "Because pV = NkT shows that the same chamber balance can be written directly in particle-count language."], "Use molecule-count bridge language.", ["ideal_gas_formula_only_confusion"], ["particle_form"], acceptance_groups(["N", "particle count", "molecules"], ["bridge", "connects", "same balance"], ["gas law", "macroscopic"], ["microscopic", "hidden dashers"])),
    ])
    return lesson_spec(
        "A4_L2",
        "Build the Chamber Balance Rule",
        sim("a4_chamber_resize_lab", "Chamber resize lab", "Vary p, V, T, and amount of gas so the ideal gas law behaves like one balance rule instead of separate tricks.", ["Hold two variables fixed and compare the others.", "Use ratio reasoning before full substitution.", "Switch between mole-count and molecule-count language."], ["Use pV = nRT confidently.", "Interpret pV = NkT as the same law written with molecule count.", "Predict proportional changes when one or two variables are changed."], ["pressure", "volume", "temperature", "amount_of_gas"], "Ideal-gas balance reasoning."),
        diagnostic,
        "The chamber now gets a compact balance rule. Pressure times room size is balanced by crowd count times dash level. In mole language this becomes pV = nRT. In molecule language it becomes pV = NkT. Both are the same chamber story written with different counting systems.",
        "Commit to the ideal gas law as a balance relationship between physical chamber variables.",
        [prompt_block("Which side of the gas law holds the chamber response?", "pV is the wall-hit side."), prompt_block("Which variables can force pressure to change?", "Volume, amount of gas, and temperature all can.")],
        [prompt_block("Keep temperature fixed and double the volume.", "Pressure should halve."), prompt_block("Keep volume fixed and double the temperature.", "Pressure should double.")],
        ["Why is pV = nRT a balance rule rather than a random symbol string?", "Why can pV = NkT and pV = nRT both describe the same gas?"],
        "Keep each symbol tied to a chamber role before you treat the law algebraically.",
        concept,
        mastery,
        contract(concept_targets=["Use the ideal gas law to compare pressure, volume, temperature, and amount of gas.", "Interpret pV = nRT and pV = NkT as two count-languages for the same macrostate.", "Explain the ideal gas law as a chamber balance rule rather than a memorized formula."], core_concepts=["The ideal gas law links pressure, volume, amount of gas, and temperature in one balance.", "Pressure is inversely related to volume when amount and temperature stay fixed.", "Pressure is directly related to temperature and amount of gas when volume stays fixed.", "The particle form and mole form describe the same ideal-gas macrostate."], prerequisite_lessons=["A4_L1"], misconception_focus=["ideal_gas_formula_only_confusion", "gas_law_ratio_confusion", "volume_collision_rate_confusion"], formulas=[relation("pV = nRT", "Mole-count form of the ideal gas law.", ["Pa m^3"], "Use when amount of gas is given in moles."), relation("pV = NkT", "Particle-count form of the ideal gas law.", ["Pa m^3"], "Use when the gas amount is expressed as number of molecules.")], representations=[representation("words", "Describes the ideal gas law as a chamber balance rule."), representation("diagram", "Places pV and nRT on two sides of one chamber balance board."), representation("formula", "Shows both the mole and particle forms."), representation("table", "Compares which variables are fixed and which variable responds.")], analogy_map=bounce_chamber_map("the learner balances wall-hit load, room size, crowd count, and dash level inside one gas-law dashboard"), worked_examples=[worked("At fixed amount of gas and temperature, the chamber volume doubles. What happens to pressure?", ["Keep n and T fixed.", "Use pV = constant in this comparison.", "Infer the inverse change in pressure."], "Pressure halves", "Pressure and volume are inversely related when n and T stay fixed.", "This is the cleanest route into ideal-gas ratio reasoning."), worked("At fixed volume and amount, temperature rises from 300 K to 450 K. What happens to pressure?", ["Keep V and n fixed.", "Compare the temperature ratio 450/300.", "Apply the same ratio to pressure."], "Pressure becomes 1.5 times larger", "Pressure is directly proportional to absolute temperature in this fixed-volume case.", "This protects students from mixing absolute-temperature reasoning with vague 'hotter means a bit more' talk.")], visual_assets=[visual("a4-l2-gas-law-balance", "Chamber balance rule", "Show pV and nRT as two sides of the same Bounce-Chamber balance.", "The ideal gas law is easier to trust when each symbol keeps its chamber meaning.", diagram_type="gas_law_balance")], animation_assets=[], simulation_contract=sim_contract("a4_l2_chamber_resize_sim", "gas_law_balance", "Change one gas-law variable at a time until the chamber balance rule feels physically grounded.", "Start with a baseline chamber state and change only one variable first.", ["Keep n and T fixed while changing V.", "Keep n and V fixed while changing T.", "Switch between n and N language for the same chamber state."], "Watch for the same law surviving in both mole-count and molecule-count forms.", "The ideal gas law is one chamber balance rule told with either moles or molecules.", controls=[("pressure", "Pressure", "Shows the wall-hit side of the balance."), ("volume", "Room size", "Changes the chamber space available to the dashers."), ("temperature", "Dash level", "Changes the average kinetic-energy level."), ("amount_of_gas", "Crowd count", "Changes how many dashers share the chamber.")], readouts=[("pV", "Shows the left-hand side of the chamber balance."), ("nRT", "Shows the mole-count form of the right-hand side."), ("NkT", "Shows the molecule-count form of the right-hand side.")]), reflection_prompts=["Explain why pV = nRT is easier to remember after you give each symbol a chamber meaning.", "Explain how pV = NkT says the same thing as pV = nRT using a different count system."], mastery_skills=["use_ideal_gas_law", "gas_law_volume_ratio", "gas_law_temperature_ratio", "gas_law_amount_ratio", "particle_form", "chamber_balance_meaning"], variation_plan={"diagnostic": "Fresh attempts rotate between direct substitution, fixed-variable ratio stories, and particle-form interpretation questions before any repeated stem.", "concept_gate": "Concept-gate retries swap in new proportional changes and new n-versus-N wording so learners cannot rely on one memorized example.", "mastery": "Mastery alternates between algebraic gas-law use, qualitative chamber-balance explanations, and particle-count comparisons before repeating a question family."}, scaffold_support=scaffold("pV = nRT is the chamber balance rule.", "The formula stops being arbitrary when pressure, room size, amount, and temperature all stay tied to a physical chamber role.", "Which variables are being held fixed in this ideal-gas comparison?", "Treating the gas law as a fixed recipe without tracking which quantities are allowed to change.", "The Bounce-Chamber model turns pV = nRT into a balance board: the wall-hit side and the crowd-dash side must match.", "Why does the balance-board story make the symbols easier to remember?", extras=[extra_section("Two count languages", "n counts moles while N counts molecules, but both describe how much gas is in the chamber.", "What changes when you switch from n to N, and what stays the same?"), extra_section("Absolute temperature", "Gas-law proportionality uses kelvin because the chamber balance tracks absolute dash level, not an arbitrary Celsius offset.", "Why would Celsius be a bad proportional-temperature scale here?")]), visual_clarity_checks=visual_checks("gas-law balance")),
    )


def lesson_three() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("A4L3_D1", "The kinetic-theory relation for an ideal gas is...", ["pV = (1/3) N m <c^2>", "p = F/A only", "S = k ln W", "V = IR"], 0, "This is the microscopic bridge formula.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_equation"]),
        ("A4L3_D2", "In pV = (1/3) N m <c^2>, the symbol <c^2> stands for...", ["mean square speed", "square of the mean speed necessarily", "average pressure", "number of moles"], 0, "It is the average of the squared speeds.", ["mean_square_speed_confusion"], ["mean_square_speed_meaning"]),
        ("A4L3_D3", "If mean-square speed rises while N, m, and V stay fixed, pressure should...", ["rise", "fall", "stay unchanged", "vanish"], 0, "Pressure grows with the molecular-speed term.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_pressure_compare"]),
        ("A4L3_D4", "Why does wall momentum change matter in kinetic theory?", ["Because pressure comes from repeated molecular momentum changes at the walls.", "Because entropy is stored in the walls.", "Because volume becomes a force.", "Because temperature is the total energy of the chamber."], 0, "Pressure is built from collision momentum change.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"]),
        ("A4L3_D5", "If N doubles at fixed m and <c^2> and the chamber volume is unchanged, pressure should...", ["double", "halve", "stay the same", "quarter"], 0, "More particles means larger pV for the same speed term.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_pressure_compare"]),
        ("A4L3_D6", "For N = 3 x 10^23, m = 2 x 10^-26 kg, and <c^2> = 9 x 10^4 m^2/s^2, the value of pV is...", ["180 J", "18 J", "540 J", "60 J"], 0, "Compute (1/3)Nm<c^2>.", ["kinetic_theory_disconnect_confusion"], ["use_kinetic_theory"]),
        ("A4L3_D7", "Comparing pV = NkT with pV = (1/3)Nm<c^2> lets you conclude that temperature is linked to...", ["molecular kinetic energy", "gas weight only", "entropy only", "container shape only"], 0, "That comparison gives the energy link.", ["kinetic_theory_disconnect_confusion", "temperature_total_energy_confusion"], ["micro_to_macro_bridge"]),
        ("A4L3_D8", "Which quantity is averaged in the speed term?", ["the square of the speed", "the pressure", "the number of molecules", "the entropy"], 0, "Mean square speed matters, not a casual average speed statement.", ["mean_square_speed_confusion"], ["mean_square_speed_meaning"]),
    ]) + build_shorts([
        ("A4L3_D9", "Why does kinetic theory make the ideal gas law feel less like a memorized formula?", ["Because it shows how the macroscopic gas law comes from molecular collisions and speed statistics.", "Because it derives pressure and the gas law from the hidden dashers instead of asking you to memorize the relation blindly."], "Mention microscopic collisions and the macroscopic law together.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"], acceptance_groups(["microscopic", "molecular", "hidden dashers"], ["collision", "speed statistics", "momentum change"], ["macroscopic gas law", "ideal gas law"], ["not memorized", "derive", "comes from"])),
        ("A4L3_D10", "Why is mean square speed stronger than just saying 'average speed' in this pressure formula?", ["Because the pressure derivation depends on averaging c squared, so the square must stay inside the average.", "Because the kinetic-theory result uses the mean of the squared speeds rather than the square of one casual average speed."], "Use average-of-squares language.", ["mean_square_speed_confusion"], ["mean_square_speed_meaning"], acceptance_groups(["mean square", "average of squared speeds"], ["not average speed", "not square of the mean"], ["pressure formula", "kinetic theory"])),
    ])
    concept = build_mcqs([
        ("A4L3_C1", "If <c^2> becomes four times larger at fixed N, m, and V, pressure becomes...", ["four times larger", "twice as large", "half as large", "unchanged"], 0, "Pressure follows the mean-square-speed term directly here.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_pressure_compare"]),
        ("A4L3_C2", "A gas with pV = 90 J and N = 2 x 10^23 molecules has average translational kinetic energy per molecule...", ["(3/2)(90/2x10^23) J", "90 J", "45 J", "90/N^2 J"], 0, "Use pV = NkT and <Ek> = 3/2 kT together.", ["kinetic_theory_disconnect_confusion"], ["energy_from_kT"]),
        ("A4L3_C3", "Which statement about pV = (1/3)Nm<c^2> is strongest?", ["It is the microscopic explanation of the ideal gas law.", "It replaces the need for pV = nRT.", "It proves molecules stop at equilibrium.", "It is only about entropy."], 0, "Microscopic explanation is the key role.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"]),
        ("A4L3_C4", "If N, m, and <c^2> stay fixed but volume doubles, pressure should...", ["halve", "double", "stay the same", "quadruple"], 0, "Use the pV product relation.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_pressure_compare"]),
        ("A4L3_C5", "In the derivation, why does a single wall collision matter?", ["It supplies the momentum-change step that is later averaged over many molecules.", "It sets the entropy directly.", "It defines the volume.", "It removes temperature from the story."], 0, "One collision gives the microscopic force step.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"]),
        ("A4L3_C6", "Which quantity depends on the square of speed in the kinetic-theory bridge?", ["molecular kinetic energy and the pressure bridge term", "pressure only in solids", "entropy only", "mole number only"], 0, "Square-speed dependence is central here.", ["mean_square_speed_confusion"], ["mean_square_speed_meaning"]),
    ]) + build_shorts([
        ("A4L3_C7", "Explain why pV = (1/3)Nm<c^2> and pV = NkT together show that temperature is tied to molecular motion.", ["Because both equal pV, so comparing them links the speed-squared term and kinetic energy to temperature.", "Because the microscopic collision equation and the gas law share the same pV, which reveals that temperature tracks molecular kinetic energy."], "Use compare-the-two-equations language.", ["kinetic_theory_disconnect_confusion", "temperature_total_energy_confusion"], ["micro_to_macro_bridge"], acceptance_groups(["compare", "both equal pV", "same pV"], ["speed squared", "motion", "kinetic"], ["temperature", "kT"])),
        ("A4L3_C8", "Correct the statement 'mean square speed is just the same as average speed.'", ["Mean square speed uses the average of c squared, so it is not the same quantity as ordinary average speed.", "The kinetic-theory formula needs the average of the squared speeds, not just a simple average speed value."], "Keep the square inside the average.", ["mean_square_speed_confusion"], ["mean_square_speed_meaning"], acceptance_groups(["mean of the squared speeds", "average of c squared"], ["not average speed", "different quantity"], ["kinetic-theory formula", "pressure bridge"])),
    ])
    mastery = build_mcqs([
        ("A4L3_M1", "For N = 6 x 10^23, m = 5 x 10^-26 kg, and <c^2> = 3 x 10^5 m^2/s^2, the value of pV is...", ["3000 J", "300 J", "9000 J", "1000 J"], 0, "Compute (1/3)Nm<c^2>.", ["kinetic_theory_disconnect_confusion"], ["use_kinetic_theory"]),
        ("A4L3_M2", "If the mean-square speed term doubles at fixed N, m, and V, pressure...", ["doubles", "halves", "stays fixed", "falls to zero"], 0, "Pressure follows the speed term directly here.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_pressure_compare"]),
        ("A4L3_M3", "Why is pressure still a macroscopic quantity in kinetic theory?", ["Because the wall forces from many collisions average into one steady pressure reading.", "Because one molecule creates the full pressure alone.", "Because mean square speed is a macrostate.", "Because entropy is pressure."], 0, "Many events average into one visible quantity.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"]),
        ("A4L3_M4", "Which statement best compares the two pV expressions?", ["One is microscopic, one is macroscopic, and they describe the same gas.", "They apply to different states of matter only.", "They cannot both be true at once.", "One is about entropy and the other about electricity."], 0, "Same gas, two levels of description.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"]),
        ("A4L3_M5", "If molecule mass m increases while N, <c^2>, and V stay fixed, pressure should...", ["increase", "decrease", "stay the same", "reverse sign"], 0, "The formula carries m directly.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_pressure_compare"]),
        ("A4L3_M7", "A learner squares the average speed and uses that in place of <c^2>. The key correction is...", ["The formula needs the mean of the squared speeds, not the square of a casual average speed.", "That is always exactly the same thing.", "Pressure does not depend on speed at all.", "You should replace N with n instead."], 0, "Protect the mean-square-speed idea.", ["mean_square_speed_confusion"], ["mean_square_speed_meaning"]),
        ("A4L3_M8", "If pressure stays fixed while volume doubles and N and m are unchanged, the mean-square speed term must...", ["halve", "double", "stay the same", "become zero"], 0, "Keep pV consistent.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_pressure_compare"]),
        ("A4L3_M9", "Best first interpretation of pV = (1/3)Nm<c^2>:", ["Pressure and volume can be explained from molecular count, mass, and motion.", "Entropy equals pressure times volume.", "The gas law only works for one molecule.", "Temperature is the total energy of the gas."], 0, "The equation bridges visible gas behaviour and hidden molecular motion.", ["kinetic_theory_disconnect_confusion"], ["kinetic_theory_equation"]),
    ]) + build_shorts([
        ("A4L3_M6", "Summarize what kinetic theory adds to the gas law.", ["Kinetic theory explains the gas law by building pressure from molecular collisions and speed statistics.", "It turns the ideal gas law from a macrostate rule into a microscopic collision explanation."], "Use collision-explanation language.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"], acceptance_groups(["collision", "molecular", "hidden dashers"], ["explains", "builds", "derives"], ["gas law", "macrostate"], ["pressure"])),
        ("A4L3_M10", "Why is the phrase 'hidden-dasher statistics' useful in this lesson?", ["Because pressure is not caused by one molecule but by averaged statistics of many molecular collisions and speeds.", "Because the chamber pressure emerges from the combined statistics of huge numbers of hidden movers."], "Mention many-particle averages, not one special collision.", ["kinetic_theory_disconnect_confusion"], ["micro_to_macro_bridge"], acceptance_groups(["many molecules", "huge numbers", "statistics"], ["collision", "speed"], ["average", "emerges", "pressure"])),
    ])
    return lesson_spec(
        "A4_L3",
        "Bridge Gas Law and Kinetic Theory",
        sim("a4_dash_level_lab", "Dash-level lab", "Track how count, mass, and mean-square speed build pressure so the kinetic-theory bridge feels like a derivation, not a slogan.", ["Change one microscopic factor at a time.", "Watch the pV readout.", "Compare the microscopic bridge with the ideal-gas summary."], ["Use pV = (1/3)Nm<c^2>.", "Explain the role of mean square speed.", "Connect the kinetic-theory bridge to the ideal gas law."], ["molecule_count", "molecule_mass", "mean_square_speed", "pressure_volume"], "Microscopic bridge reasoning."),
        diagnostic,
        "The chamber balance rule now gets a molecular explanation. Each wall collision changes momentum. Huge numbers of those collisions average into pressure. That microscopic story leads to pV = (1/3)Nm<c^2>. When you compare it with pV = NkT, temperature becomes visibly tied to molecular motion.",
        "Commit to the gas law as something that can be explained from hidden-dasher collisions and statistics.",
        [prompt_block("What microscopic event creates pressure in the derivation?", "Momentum-changing wall collisions."), prompt_block("Why does the squared speed appear?", "Kinetic theory averages c squared, not just casual speed.")],
        [prompt_block("Keep N and V fixed and increase <c^2>.", "Pressure should rise."), prompt_block("Keep p fixed and double V.", "The speed term must fall if count and mass stay fixed.")],
        ["Why does kinetic theory make the ideal gas law feel derived rather than memorized?", "Why must the square stay inside the speed average?"],
        "Keep the microscopic bridge explicit before you move to average kinetic energy.",
        concept,
        mastery,
        contract(concept_targets=["Use the kinetic-theory pressure bridge relation.", "Explain why mean square speed rather than casual average speed appears in the bridge.", "Connect microscopic collisions to the macroscopic gas law."], core_concepts=["Pressure can be built from molecular momentum changes at the walls.", "The microscopic bridge relation links pV to particle count, mass, and mean-square speed.", "Mean square speed is an average of squared speeds, not the square of a casual average speed.", "Comparing the microscopic bridge with pV = NkT ties temperature to molecular motion."], prerequisite_lessons=["A4_L1", "A4_L2"], misconception_focus=["kinetic_theory_disconnect_confusion", "mean_square_speed_confusion", "temperature_total_energy_confusion"], formulas=[relation("pV = (1/3) N m <c^2>", "Microscopic pressure-volume bridge from kinetic theory.", ["J", "Pa m^3"], "Use for ideal-gas particles in random motion."), relation("pV = NkT", "Particle-count gas law.", ["J", "Pa m^3"], "Compare with the kinetic-theory bridge to connect temperature to motion.")], representations=[representation("words", "Explains pressure through momentum-changing wall collisions."), representation("diagram", "Shows microscopic collisions feeding a macroscopic pressure reading."), representation("formula", "Links the collision story to pV = (1/3)Nm<c^2> and pV = NkT."), representation("equation_story", "Shows how comparing two pV relations reveals the temperature-motion link.")], analogy_map=bounce_chamber_map("the learner compares microscopic collision statistics with the visible gas-law dashboard"), worked_examples=[worked("Given N = 3 x 10^23, m = 2 x 10^-26 kg, and <c^2> = 9 x 10^4 m^2/s^2, find pV.", ["Use pV = (1/3)Nm<c^2>.", "Multiply N, m, and <c^2> first.", "Divide by 3 and state the unit."], "180 J", "The microscopic bridge gives the same pV product as the gas law.", "This is the fastest way to show that the kinetic-theory expression is numerically usable."), worked("If mean-square speed doubles while N, m, and V stay fixed, what happens to pressure?", ["Keep the other factors fixed.", "Notice that p is proportional to <c^2> here.", "Apply the same factor change to pressure."], "Pressure doubles", "The bridge shows pressure following the speed-squared term directly when the other factors are fixed.", "This protects learners from treating the speed term as decorative.")], visual_assets=[visual("a4-l3-kinetic-theory-bridge", "Microscopic bridge to the gas law", "Show wall momentum change, the kinetic-theory bridge, and the gas-law comparison on one board.", "Kinetic theory explains why the gas law works by connecting pressure to particle count, mass, and motion.", diagram_type="kinetic_theory_bridge")], animation_assets=[], simulation_contract=sim_contract("a4_l3_dash_level_sim", "kinetic_theory_bridge", "Change microscopic collision factors until the pV bridge feels like a real explanation of the gas law.", "Start with a moderate count, mass, and mean-square speed.", ["Double the mean-square speed term and compare pressure.", "Keep p fixed and expand the chamber.", "Compare the bridge output with the gas-law pV value."], "Watch for the same pV story appearing from both the microscopic and macroscopic sides.", "Kinetic theory gives the molecular explanation for the same chamber balance seen in the gas law.", controls=[("molecule_count", "Molecule count", "Sets how many hidden dashers share the chamber."), ("molecule_mass", "Molecule mass", "Changes the momentum carried by each collision."), ("mean_square_speed", "Mean-square speed", "Tracks the motion term that feeds pressure."), ("chamber_volume", "Room size", "Lets you compare p and pV reasoning.")], readouts=[("pV bridge", "Shows the microscopic pV value from kinetic theory."), ("Gas-law pV", "Shows the matching pV value from the macroscopic side."), ("Bridge note", "Explains which microscopic factor changed the result.")]), reflection_prompts=["Explain why the pressure bridge uses mean square speed rather than a casual average speed.", "Explain how the kinetic-theory bridge helps you trust the ideal gas law."], mastery_skills=["kinetic_theory_equation", "mean_square_speed_meaning", "kinetic_theory_pressure_compare", "use_kinetic_theory", "micro_to_macro_bridge", "energy_from_kT"], variation_plan={"diagnostic": "Fresh attempts rotate between bridge-equation recall, speed-term meaning, and simple proportional changes in microscopic factors.", "concept_gate": "Concept-gate retries alternate between new pV calculations, compare-the-two-equations prompts, and mean-square-speed corrections.", "mastery": "Mastery varies bridge calculations, fixed-variable reasoning, and short micro-to-macro explanations before repeating a previous stem."}, scaffold_support=scaffold("Kinetic theory is the microscopic bridge behind the gas law.", "The gas law stops feeling magical when wall momentum change, particle count, and speed statistics visibly build the pressure term.", "Which microscopic factor is being changed in this bridge example?", "Treating pV = (1/3)Nm<c^2> as a disconnected formula unrelated to the gas law.", "The Bounce-Chamber model shows that the same visible pV comes from hidden dashers changing momentum at the walls.", "Why does comparing two pV equations reveal something deep about temperature?", extras=[extra_section("One collision to many collisions", "A single wall bounce gives the momentum-change step; many collisions give the stable pressure average.", "Why is one collision not enough to explain the full pressure reading?"), extra_section("Mean square speed", "The square stays inside the average because the derivation depends on c squared, not a casual verbal speed average.", "Why is <c^2> not the same as '(average c)^2'?")]), visual_clarity_checks=visual_checks("kinetic-theory bridge")),
    )


def lesson_four() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("A4L4_D1", "For an ideal gas, temperature is linked most directly to...", ["average translational kinetic energy per molecule", "total energy of the whole sample only", "entropy only", "container volume only"], 0, "Temperature tracks the average dash energy, not the total energy alone.", ["temperature_total_energy_confusion"], ["average_ke_meaning"]),
        ("A4L4_D2", "The relation connecting average translational kinetic energy and temperature is...", ["<Ek> = (3/2)kT", "pV = nRT", "S = k ln W", "F = ma"], 0, "This is the molecular energy rule.", ["temperature_total_energy_confusion"], ["use_three_half_kT"]),
        ("A4L4_D3", "At the same absolute temperature, two different ideal gases have the same...", ["average translational kinetic energy per molecule", "molecular mass", "rms speed", "entropy automatically"], 0, "Same T means same average translational kinetic energy per molecule.", ["same_temperature_same_average_ke_confusion"], ["same_T_same_avg_ke"]),
        ("A4L4_D4", "At the same temperature, a lighter gas compared with a heavier gas typically has...", ["higher rms speed", "lower average kinetic energy", "the same speed because T is the same", "zero pressure"], 0, "Same average kinetic energy can still mean different speeds for different masses.", ["same_temperature_same_average_ke_confusion"], ["mass_speed_compare"]),
        ("A4L4_D5", "If absolute temperature doubles, the average translational kinetic energy per molecule...", ["doubles", "halves", "stays the same", "quadruples"], 0, "It is proportional to T.", ["temperature_total_energy_confusion"], ["temperature_energy_ratio"]),
        ("A4L4_D6", "Using k = 1.38 x 10^-23 J/K, the average translational kinetic energy at 300 K is about...", ["6.2 x 10^-21 J", "4.1 x 10^-23 J", "3.0 J", "2.1 x 10^-20 J"], 0, "Use (3/2)kT.", ["temperature_total_energy_confusion"], ["use_three_half_kT"]),
        ("A4L4_D7", "Which statement is strongest?", ["Temperature is an average-per-molecule motion measure, not the total energy of the whole sample.", "Temperature is the same thing as total energy.", "Temperature measures volume directly.", "Temperature removes molecular randomness."], 0, "Keep average-per-molecule language visible.", ["temperature_total_energy_confusion"], ["average_ke_meaning"]),
        ("A4L4_D8", "If two samples of the same gas are at the same temperature but one has twice as many molecules, the larger sample has...", ["the same average kinetic energy per molecule but more total energy overall", "twice the average kinetic energy per molecule", "half the average kinetic energy per molecule", "the same total energy necessarily"], 0, "Average per molecule and total energy must be separated.", ["temperature_total_energy_confusion"], ["average_ke_meaning"]),
    ]) + build_shorts([
        ("A4L4_D9", "Why does same temperature not force same molecular speed for different gases?", ["Because same temperature means the same average kinetic energy per molecule, but different molecular masses give different speeds for that same energy.", "Because lighter and heavier molecules can share the same average dash energy while moving at different speeds."], "Mention same energy but different masses and speeds.", ["same_temperature_same_average_ke_confusion"], ["mass_speed_compare"], acceptance_groups(["same temperature", "same average kinetic energy"], ["different masses", "lighter", "heavier"], ["different speeds", "rms speed"])),
        ("A4L4_D10", "Why is temperature better described as an average than as a total?", ["Because temperature tracks the average translational kinetic energy per molecule, while total energy also depends on how many molecules are present.", "Because temperature is a per-molecule motion level, not the total energy stored by the whole sample."], "Contrast average per molecule with total amount.", ["temperature_total_energy_confusion"], ["average_ke_meaning"], acceptance_groups(["average", "per molecule"], ["not total", "total energy"], ["how many molecules", "sample size"])),
    ])
    concept = build_mcqs([
        ("A4L4_C1", "If T rises from 300 K to 450 K, average translational kinetic energy per molecule becomes...", ["1.5 times larger", "half as large", "double", "unchanged"], 0, "Average kinetic energy is proportional to T.", ["temperature_total_energy_confusion"], ["temperature_energy_ratio"]),
        ("A4L4_C2", "Two ideal gases are at the same temperature. The stronger conclusion is...", ["They have the same average translational kinetic energy per molecule.", "They must have the same rms speed.", "They must have the same mass.", "They must have the same entropy."], 0, "Same temperature fixes the average kinetic-energy level.", ["same_temperature_same_average_ke_confusion"], ["same_T_same_avg_ke"]),
        ("A4L4_C3", "If a molecule's mass doubles while the temperature stays the same, the key idea is...", ["the average kinetic energy per molecule stays the same, so the speed pattern adjusts", "the average kinetic energy doubles", "temperature halves", "pressure becomes zero"], 0, "Mass changes speed, not the temperature-energy link.", ["same_temperature_same_average_ke_confusion"], ["mass_speed_compare"]),
        ("A4L4_C4", "For T = 400 K, the average translational kinetic energy per molecule is closest to...", ["8.3 x 10^-21 J", "4.1 x 10^-21 J", "2.1 x 10^-20 J", "5.5 x 10^-22 J"], 0, "Use (3/2)kT.", ["temperature_total_energy_confusion"], ["use_three_half_kT"]),
        ("A4L4_C5", "Which statement protects against the total-energy misconception?", ["Doubling the number of molecules can double total energy without changing temperature.", "Doubling the number of molecules must double temperature.", "Temperature only measures mass.", "Average kinetic energy depends on volume only."], 0, "Keep total and average separate.", ["temperature_total_energy_confusion"], ["average_ke_meaning"]),
        ("A4L4_C6", "At fixed temperature, which gas would usually have the larger rms speed?", ["the lighter gas", "the heavier gas", "both exactly the same", "speed cannot be discussed"], 0, "Lighter molecules move faster for the same average energy.", ["same_temperature_same_average_ke_confusion"], ["mass_speed_compare"]),
    ]) + build_shorts([
        ("A4L4_C7", "Explain why <Ek> = (3/2)kT is a powerful bridge between macroscopic temperature and microscopic motion.", ["Because it turns temperature into a direct average-energy statement for individual molecules.", "Because it shows that the dash level on the chamber dashboard is really the average translational kinetic energy per molecule."], "Use average-energy-per-molecule language.", ["temperature_total_energy_confusion"], ["use_three_half_kT"], acceptance_groups(["temperature"], ["average kinetic energy", "average translational kinetic energy"], ["per molecule", "individual molecules"], ["bridge", "direct link"])),
        ("A4L4_C8", "A learner says, 'If the temperature is the same, the speeds must be the same.' What correction should you make?", ["Same temperature fixes average kinetic energy per molecule, but different molecular masses can still give different speeds.", "At one temperature, lighter molecules typically move faster even though the average kinetic-energy level is the same."], "Keep temperature linked to energy, not one forced speed value.", ["same_temperature_same_average_ke_confusion"], ["same_T_same_avg_ke"], acceptance_groups(["same temperature"], ["same average kinetic energy"], ["different masses", "lighter", "heavier"], ["different speeds", "rms speed"])),
    ])
    mastery = build_mcqs([
        ("A4L4_M1", "Using <Ek> = (3/2)kT, doubling T makes average kinetic energy per molecule...", ["double", "halve", "stay the same", "quadruple"], 0, "The relation is directly proportional.", ["temperature_total_energy_confusion"], ["temperature_energy_ratio"]),
        ("A4L4_M2", "A gas sample has twice as many molecules as another sample of the same gas but both are at 300 K. Which statement is correct?", ["They have the same average kinetic energy per molecule.", "The larger sample has twice the average kinetic energy per molecule.", "The smaller sample has the higher temperature automatically.", "The larger sample has the lower total energy automatically."], 0, "Average per molecule is unchanged by sample size alone.", ["temperature_total_energy_confusion"], ["average_ke_meaning"]),
        ("A4L4_M3", "At the same temperature, helium and oxygen molecules have the same...", ["average translational kinetic energy per molecule", "rms speed", "molecular mass", "pressure in every possible container"], 0, "Same T gives same average kinetic energy per molecule.", ["same_temperature_same_average_ke_confusion"], ["same_T_same_avg_ke"]),
        ("A4L4_M4", "Which gas should have the greater rms speed at the same temperature?", ["the lighter gas", "the heavier gas", "both equal", "rms speed is unrelated to temperature"], 0, "Same average energy means lighter gas moves faster.", ["same_temperature_same_average_ke_confusion"], ["mass_speed_compare"]),
        ("A4L4_M5", "At 600 K, average translational kinetic energy per molecule compared with 300 K is...", ["twice as large", "half as large", "the same", "four times as large"], 0, "The relationship is linear in T.", ["temperature_total_energy_confusion"], ["temperature_energy_ratio"]),
        ("A4L4_M7", "If one gas sample has a larger total internal energy than another, can the two still have the same temperature?", ["Yes, if the larger-energy sample also has more molecules.", "No, same temperature always means the same total energy.", "No, temperature and total energy are identical.", "Only if the gases are different elements."], 0, "Total and average must be separated carefully.", ["temperature_total_energy_confusion"], ["average_ke_meaning"]),
        ("A4L4_M8", "Which expression belongs directly to this lesson's molecular energy rule?", ["<Ek> = (3/2)kT", "pV = nRT only", "S = k ln W only", "F = ma"], 0, "This is the direct temperature-energy link.", ["temperature_total_energy_confusion"], ["use_three_half_kT"]),
        ("A4L4_M9", "If two gases have the same average translational kinetic energy per molecule, they must have the same...", ["temperature", "mass", "speed", "volume"], 0, "The average-energy level fixes T.", ["same_temperature_same_average_ke_confusion"], ["same_T_same_avg_ke"]),
    ]) + build_shorts([
        ("A4L4_M6", "Summarize the meaning of temperature for an ideal gas in one sentence.", ["For an ideal gas, temperature measures the average translational kinetic energy per molecule.", "Temperature is the average dash-energy level of the hidden molecules, not the total energy of the whole sample."], "Keep average-per-molecule language visible.", ["temperature_total_energy_confusion"], ["average_ke_meaning"], acceptance_groups(["temperature"], ["average kinetic energy", "average translational kinetic energy", "dash-energy level"], ["per molecule", "hidden molecules"], ["not total energy", "not whole sample"])),
        ("A4L4_M10", "Why is the Bounce-Chamber phrase 'dash level' a good analogy for temperature?", ["Because it captures temperature as the average motion-energy level of the hidden dashers rather than a total amount.", "Because the dash level tells how energetic the molecules are on average, which is exactly the temperature meaning for an ideal gas."], "Use average motion-energy language.", ["temperature_total_energy_confusion"], ["average_ke_meaning"], acceptance_groups(["average", "on average"], ["motion energy", "kinetic energy", "dash level"], ["molecules", "hidden dashers"], ["temperature meaning"])),
    ])
    return lesson_spec(
        "A4_L4",
        "Temperature as Average Dash Energy",
        sim("a4_average_dash_energy_lab", "Average dash energy lab", "Compare cooler and hotter molecular crowds so temperature stays tied to average translational kinetic energy.", ["Hold sample size fixed and raise temperature.", "Compare different gas masses at the same temperature.", "Separate average-per-molecule energy from total energy of the sample."], ["Use <Ek> = (3/2)kT conceptually and numerically.", "Explain same-temperature average kinetic energy clearly.", "Protect against confusing average energy with total energy."], ["temperature", "average_kinetic_energy", "molecule_mass", "rms_speed_hint"], "Molecular-energy reasoning."),
        diagnostic,
        "The Bounce-Chamber story now makes temperature precise. Dash level is not the total energy of the chamber. It is the average translational kinetic energy per molecule. That is why the same temperature gives the same average energy per molecule even for different gases.",
        "Commit to temperature as an average molecular-energy idea rather than a total-energy idea.",
        [prompt_block("What does temperature track for an ideal gas?", "Average translational kinetic energy per molecule."), prompt_block("What can change total energy without changing temperature?", "The number of molecules in the sample.")],
        [prompt_block("Keep temperature fixed and compare a light gas with a heavy gas.", "Same average energy does not force same speed."), prompt_block("Double the temperature and watch the average energy rule.", "Average kinetic energy should double.")],
        ["Why is temperature an average-per-molecule idea rather than a total-energy idea?", "Why can equal temperature allow different molecular speeds for different gases?"],
        "Keep temperature tied to average molecular motion before entropy enters the picture.",
        concept,
        mastery,
        contract(concept_targets=["Interpret temperature as average translational kinetic energy per molecule.", "Use <Ek> = (3/2)kT.", "Explain why same temperature does not force the same molecular speed for different masses."], core_concepts=["Temperature is an average-per-molecule energy idea, not a total-energy idea.", "For an ideal gas, average translational kinetic energy is proportional to absolute temperature.", "Different molecular masses can have different speeds at the same temperature.", "Sample size can change total energy without changing the average-energy meaning of temperature."], prerequisite_lessons=["A4_L2", "A4_L3"], misconception_focus=["temperature_total_energy_confusion", "same_temperature_same_average_ke_confusion"], formulas=[relation("<Ek> = (3/2)kT", "Average translational kinetic energy per molecule for an ideal gas.", ["J"], "Use with absolute temperature in kelvin."), relation("pV = NkT", "Particle-count gas law that links temperature to the microscopic energy rule.", ["Pa m^3"], "Useful when bridging macrostate and molecular-energy reasoning.")], representations=[representation("words", "Frames temperature as average dash energy."), representation("diagram", "Compares cooler and hotter chambers with different motion arrows."), representation("formula", "Connects average molecular energy directly to temperature."), representation("model", "Keeps sample size and molecular mass separate from the meaning of temperature.")], analogy_map=bounce_chamber_map("the learner compares cool and hot dash levels while separating average molecular energy from total sample energy"), worked_examples=[worked("Find the average translational kinetic energy per molecule at 300 K.", ["Use <Ek> = (3/2)kT.", "Substitute k = 1.38 x 10^-23 J/K and T = 300 K.", "State the energy in joules."], "6.2 x 10^-21 J", "The temperature rule gives a direct average-energy value per molecule.", "This is the cleanest numerical bridge between temperature and molecular motion."), worked("Two gases are at the same temperature, but one gas has lighter molecules. Compare their average kinetic energies and typical speeds.", ["Keep the temperature the same.", "Same T means same average kinetic energy per molecule.", "Infer that the lighter molecules can still have higher speeds for that same energy level."], "Same average kinetic energy, but the lighter gas has higher typical speed", "Equal temperature fixes average energy, not one universal molecular speed.", "This protects students from the 'same temperature means same speed' trap.")], visual_assets=[visual("a4-l4-average-dash-energy", "Cool and hot dash levels", "Compare cooler and hotter chambers so temperature stays visible as an average molecular-energy level.", "Temperature is the average dash-energy level of the molecules, not the total energy of the whole sample.", diagram_type="average_dash_energy", meta={"hot_level": 1.7})], animation_assets=[], simulation_contract=sim_contract("a4_l4_average_dash_energy_sim", "average_dash_energy", "Change temperature, molecule mass, and sample size until average dash energy stays distinct from total energy.", "Start with the same gas in a cool chamber and a hot chamber.", ["Hold temperature fixed and change molecule mass.", "Hold temperature fixed and double sample size.", "Double temperature and compare the average dash energy."], "Watch for same-temperature average energy staying fixed even when mass or sample size changes.", "Temperature is the average dash-energy level per molecule, and that meaning survives changes in mass or sample size.", controls=[("temperature", "Dash level", "Sets the average molecular-energy level."), ("molecule_mass", "Molecule mass", "Helps compare same-energy but different-speed cases."), ("sample_size", "Crowd count", "Lets you separate total energy from average energy.")], readouts=[("Average kinetic energy", "Shows the per-molecule energy level."), ("Speed comparison", "Indicates how mass changes speed for the same temperature."), ("Total energy note", "Shows how adding more molecules can change total energy without changing temperature.")]), reflection_prompts=["Explain why a larger gas sample can have more total energy without being hotter.", "Explain why same temperature does not force same molecular speed for all gases."], mastery_skills=["average_ke_meaning", "use_three_half_kT", "same_T_same_avg_ke", "mass_speed_compare", "temperature_energy_ratio"], variation_plan={"diagnostic": "Fresh attempts rotate between same-temperature comparisons, average-versus-total-energy distinctions, and direct use of <Ek> = (3/2)kT.", "concept_gate": "Concept-gate retries alternate between mass-versus-speed reasoning and new average-energy calculations.", "mastery": "Mastery varies short conceptual corrections and proportional-temperature calculations before repeating a previous structure."}, scaffold_support=scaffold("Temperature tracks average translational kinetic energy per molecule.", "The chamber dashboard looks macroscopic, but temperature secretly tells you about the average motion energy of each hidden dasher.", "Which quantity in this example is an average per molecule, and which belongs to the whole sample?", "Treating temperature as if it were automatically the total energy of the whole gas sample.", "Dash level is a better phrase than 'total energy' because it points straight at the average molecular-energy level that temperature actually tracks.", "Why can one sample have more total energy without having a higher temperature?", extras=[extra_section("Same temperature, different masses", "Equal temperature fixes the average energy level, but lighter molecules can still move faster than heavier ones.", "Why does mass change speed without changing the temperature meaning?"), extra_section("Sample size", "Adding more molecules changes the total internal energy, but it does not change the average-energy meaning of temperature by itself.", "What changes when sample size changes at the same temperature?")]), visual_clarity_checks=visual_checks("average dash energy")),
    )


def lesson_five() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("A4L5_D1", "A macrostate is best described as...", ["the visible state such as p, V, T, and amount", "one exact list of every molecular position and speed", "a single collision event", "the molecular mass only"], 0, "Macrostate means the visible dashboard state.", ["microstate_macrostate_confusion"], ["macrostate_meaning"]),
        ("A4L5_D2", "A microstate is...", ["one exact hidden arrangement of positions and speeds", "the same thing as pressure", "the total gas amount only", "the visible dashboard state"], 0, "Microstate means one exact hidden playbook.", ["microstate_macrostate_confusion"], ["microstate_meaning"]),
        ("A4L5_D3", "When a partition is removed and gas spreads into a larger volume, entropy tends to...", ["increase", "decrease", "stay fixed always", "become negative"], 0, "More accessible arrangements means larger entropy.", ["partition_entropy_confusion", "spontaneous_change_preference_confusion"], ["partition_entropy_reasoning"]),
        ("A4L5_D4", "Why is the evenly spread gas macrostate more likely than all the gas staying in one corner?", ["It has many more compatible microstates.", "It has fewer molecules.", "It removes all collisions.", "It forces temperature to zero."], 0, "Multiplicity is the key idea.", ["entropy_disorder_only_confusion", "microstate_macrostate_confusion"], ["multiplicity_compare"]),
        ("A4L5_D5", "Removing a partition without adding molecules increases the number of accessible...", ["microstates", "molecular masses", "species of gas", "wall materials"], 0, "The key change is in accessible arrangements.", ["partition_entropy_confusion"], ["accessible_microstates"]),
        ("A4L5_D6", "Which statement is strongest?", ["Equilibrium means the macrostate is steady while molecules still move randomly through many microstates.", "Equilibrium means every molecule has stopped.", "Equilibrium means there is only one microstate.", "Equilibrium means entropy is zero."], 0, "Steady macrostate does not mean frozen molecules.", ["equilibrium_no_motion_confusion", "microstate_macrostate_confusion"], ["macro_micro_equilibrium"]),
        ("A4L5_D7", "If two macrostates are possible, the one with the larger number of compatible microstates is...", ["more probable", "less probable", "impossible", "always lower in entropy"], 0, "More microstates means more probable macrostate.", ["spontaneous_change_preference_confusion"], ["multiplicity_compare"]),
        ("A4L5_D8", "Why can a gas spread into a larger chamber volume spontaneously?", ["Because the larger-volume macrostate has many more accessible hidden arrangements.", "Because the molecules want to slow down.", "Because pressure disappears.", "Because the gas becomes a liquid."], 0, "Expansion is a multiplicity story.", ["partition_entropy_confusion", "entropy_disorder_only_confusion"], ["partition_entropy_reasoning"]),
    ]) + build_shorts([
        ("A4L5_D9", "Explain the difference between a macrostate and a microstate.", ["A macrostate is the visible state such as pressure, volume, temperature, and amount, while a microstate is one exact hidden arrangement of molecular positions and speeds.", "The macrostate is the chamber dashboard you can see, but a microstate is one detailed playbook for where every molecule is and how it moves."], "Contrast visible dashboard state with one exact hidden arrangement.", ["microstate_macrostate_confusion"], ["macro_micro_language"], acceptance_groups(["macrostate", "visible state", "dashboard"], ["pressure", "volume", "temperature", "amount"], ["microstate", "hidden arrangement", "exact arrangement"], ["positions", "speeds", "velocities"])),
        ("A4L5_D10", "Why does removing a partition increase entropy even though no new molecules are added?", ["Because the same molecules can occupy many more accessible microstates when the available volume increases.", "Because opening the extra space increases the number of hidden playbooks that fit the chamber state."], "Use available volume and more microstates language.", ["partition_entropy_confusion"], ["partition_entropy_reasoning"], acceptance_groups(["more volume", "extra space", "available volume"], ["more microstates", "more hidden arrangements", "more playbooks"], ["entropy increases", "spread score rises"])) ,
    ])
    concept = build_mcqs([
        ("A4L5_C1", "A macrostate with a larger multiplicity is more likely because...", ["more microstates produce it", "it has less volume", "the molecules stop moving", "it has fewer collisions"], 0, "Probability follows multiplicity here.", ["spontaneous_change_preference_confusion"], ["multiplicity_compare"]),
        ("A4L5_C2", "Four molecules can be all-left, all-right, or split between two sides. Which macrostate is most probable after a divider is removed?", ["roughly evenly split", "all left", "all right", "the one with the fewest microstates"], 0, "Balanced sharing usually has the largest multiplicity.", ["spontaneous_change_preference_confusion"], ["partition_entropy_reasoning"]),
        ("A4L5_C3", "Which change can increase accessible microstates without changing molecule number?", ["making more volume available", "changing the wall color", "removing temperature from the model", "freezing all motion"], 0, "More volume means more arrangements.", ["partition_entropy_confusion"], ["accessible_microstates"]),
        ("A4L5_C4", "Why is 'entropy is just disorder' too weak?", ["Because the stronger idea is the number of microstates or how spread matter and energy can be.", "Because entropy only measures volume.", "Because entropy equals pressure.", "Because disorder is a formula."], 0, "Microstate count is the stronger concept.", ["entropy_disorder_only_confusion"], ["entropy_not_just_disorder"]),
        ("A4L5_C5", "A steady equilibrium gas in a chamber still moves through many...", ["microstates", "volumes", "elements", "pressures"], 0, "Microstates keep changing even when the macrostate is steady.", ["microstate_macrostate_confusion"], ["macro_micro_equilibrium"]),
        ("A4L5_C6", "If all other factors are alike, a larger accessible volume usually means...", ["greater entropy", "smaller entropy", "no microstates", "less probable spreading"], 0, "More available arrangements raises entropy.", ["partition_entropy_confusion"], ["partition_entropy_reasoning"]),
    ]) + build_shorts([
        ("A4L5_C7", "Why is the 'all in one corner' gas arrangement so unlikely after the partition is removed?", ["Because very few microstates correspond to that concentrated macrostate compared with the huge number of spread-out microstates.", "Because the concentrated state has a much smaller multiplicity than the spread state."], "Use few-versus-many microstates language.", ["spontaneous_change_preference_confusion"], ["multiplicity_compare"], acceptance_groups(["few microstates", "small multiplicity"], ["many microstates", "spread state", "larger multiplicity"], ["unlikely", "less probable"])),
        ("A4L5_C8", "Correct the statement 'At equilibrium the gas has found one final arrangement and stays there.'", ["At equilibrium the macrostate stays steady, but the molecules still move through many changing microstates.", "Equilibrium is a stable visible state, not one frozen hidden arrangement."], "Contrast steady macrostate with changing microstates.", ["microstate_macrostate_confusion", "equilibrium_no_motion_confusion"], ["macro_micro_equilibrium"], acceptance_groups(["equilibrium", "macrostate", "visible state"], ["steady", "stable"], ["many microstates", "changing microstates", "not one arrangement"])),
    ])
    mastery = build_mcqs([
        ("A4L5_M1", "Best meaning of multiplicity W:", ["the number of microstates compatible with a macrostate", "the pressure times volume", "the molecular mass", "the average speed"], 0, "Multiplicity counts compatible hidden arrangements.", ["microstate_macrostate_confusion"], ["multiplicity_meaning"]),
        ("A4L5_M2", "A gas spontaneously fills both halves of a container after a partition is removed because...", ["the spread macrostate has far more compatible microstates", "gravity pushes it sideways", "temperature becomes zero", "the molecules stop colliding"], 0, "Spontaneous expansion follows larger multiplicity.", ["partition_entropy_confusion", "spontaneous_change_preference_confusion"], ["partition_entropy_reasoning"]),
        ("A4L5_M3", "Which statement best compares macrostate and microstate?", ["A macrostate is the visible summary, while a microstate is one exact hidden arrangement.", "A macrostate is one molecule.", "A microstate is the container volume only.", "They are identical terms."], 0, "Keep dashboard versus playbook visible.", ["microstate_macrostate_confusion"], ["macro_micro_language"]),
        ("A4L5_M4", "If a macrostate can be produced by more hidden arrangements than another, it is...", ["more probable", "less probable", "impossible", "lower in entropy automatically than all others"], 0, "Probability grows with multiplicity.", ["spontaneous_change_preference_confusion"], ["multiplicity_compare"]),
        ("A4L5_M5", "Why does larger available volume matter statistically?", ["It allows more positions and therefore more compatible microstates.", "It removes temperature from the gas law.", "It makes every molecule identical.", "It eliminates pressure."], 0, "Volume changes accessible playbooks.", ["partition_entropy_confusion"], ["accessible_microstates"]),
        ("A4L5_M7", "Which statement protects against the 'entropy is just mess' trap?", ["Entropy is better tied to the number of compatible microstates than to a vague idea of messiness.", "Entropy is only the container shape.", "Entropy means pressure falls.", "Entropy stops molecular motion."], 0, "Option count is the stronger concept.", ["entropy_disorder_only_confusion"], ["entropy_not_just_disorder"]),
        ("A4L5_M8", "After a partition is removed, which macrostate has the highest multiplicity for many gas molecules?", ["the spread-out macrostate", "all molecules left", "all molecules right", "the one with the fewest arrangements"], 0, "Spread-out distributions dominate by count.", ["spontaneous_change_preference_confusion"], ["multiplicity_compare"]),
        ("A4L5_M9", "What can stay constant while microstates keep changing?", ["the macrostate at equilibrium", "the number of collisions becoming zero", "molecular motion stopping", "accessible volume vanishing"], 0, "Equilibrium is a steady visible state with ongoing microscopic motion.", ["microstate_macrostate_confusion", "equilibrium_no_motion_confusion"], ["macro_micro_equilibrium"]),
    ]) + build_shorts([
        ("A4L5_M6", "Summarize why spontaneous expansion is a statistical story.", ["Spontaneous expansion is favored because the larger-volume macrostate has overwhelmingly more compatible microstates.", "The gas spreads because the expanded state has a much bigger hidden option count."], "Use larger multiplicity language.", ["partition_entropy_confusion", "spontaneous_change_preference_confusion"], ["partition_entropy_reasoning"], acceptance_groups(["larger volume", "expanded state"], ["more microstates", "bigger option count", "larger multiplicity"], ["spontaneous", "favored", "more probable"])),
        ("A4L5_M10", "Why is the phrase 'hidden playbook' useful for a microstate?", ["Because it reminds you that a microstate is one exact unseen arrangement of positions and speeds beneath the same visible chamber state.", "Because the hidden playbook phrase captures the detailed molecular arrangement that sits underneath the macrostate dashboard."], "Link hidden playbook to exact detailed arrangement.", ["microstate_macrostate_confusion"], ["microstate_meaning"], acceptance_groups(["hidden playbook", "exact arrangement", "detailed arrangement"], ["positions", "speeds", "velocities"], ["macrostate", "visible state", "dashboard"])) ,
    ])
    return lesson_spec(
        "A4_L5",
        "Open the Partition and Count the Options",
        sim("a4_partition_drop_lab", "Partition drop lab", "Remove the divider, compare concentrated and spread-out chamber states, and explain the result with multiplicity instead of vague disorder talk.", ["Start with all the gas in one side.", "Remove the partition.", "Compare concentrated and spread-out macrostates by hidden option count."], ["Distinguish macrostate and microstate.", "Explain free expansion statistically.", "Link more accessible microstates to higher entropy."], ["partition_state", "available_volume", "macrostate_balance", "option_count"], "Macrostate versus microstate reasoning."),
        diagnostic,
        "The chamber now gets a statistical layer. The dashboard state is what you can see: pressure, volume, temperature, and amount. But beneath that dashboard sits a huge hidden playbook of exact molecular positions and speeds. When a partition is removed, the gas spreads because the larger-volume macrostate has far more compatible hidden playbooks.",
        "Commit to spontaneous expansion as a microstate-count story rather than a vague 'gas likes disorder' slogan.",
        [prompt_block("What does the macrostate show?", "The visible dashboard: pressure, volume, temperature, and amount."), prompt_block("What changes most when a partition is removed?", "The number of accessible hidden arrangements grows enormously.")],
        [prompt_block("Start with gas on one side only.", "Now remove the divider and compare the accessible space."), prompt_block("Compare a concentrated macrostate with a spread-out one.", "The spread state should have far more compatible microstates.")],
        ["Why is the spread-out gas state more probable than the cornered state?", "Why can equilibrium keep the same macrostate while microstates keep changing?"],
        "Keep the hidden-playbook story visible before you compress it into entropy language.",
        concept,
        mastery,
        contract(concept_targets=["Distinguish macrostate and microstate cleanly.", "Explain why free expansion into larger volume increases entropy.", "Use multiplicity as the reason spread-out states are more probable."], core_concepts=["A macrostate is the visible dashboard state.", "A microstate is one exact hidden arrangement of molecular positions and speeds.", "Greater accessible volume means more compatible microstates.", "Spontaneous expansion is favored because the spread-out macrostate has much larger multiplicity."], prerequisite_lessons=["A4_L1", "A4_L2", "A4_L4"], misconception_focus=["microstate_macrostate_confusion", "partition_entropy_confusion", "spontaneous_change_preference_confusion", "entropy_disorder_only_confusion"], formulas=[relation("W = multiplicity", "Counts how many microstates match a given macrostate.", ["dimensionless"], "Use as the hidden option-count idea behind entropy."), relation("larger W -> larger entropy", "Conceptual statistical rule for comparing macrostates.", ["concept only"], "Most useful before writing S = k ln W explicitly.")], representations=[representation("words", "Describes dashboard state and hidden playbook side by side."), representation("diagram", "Shows gas confined on one side and then spread through the whole chamber."), representation("formula", "Uses multiplicity language before the entropy formula."), representation("table", "Compares concentrated and spread-out macrostates by accessible microstates.")], analogy_map=bounce_chamber_map("the learner removes a partition and compares the visible dashboard state with the hidden playbook count"), worked_examples=[worked("A gas starts in the left half of a chamber and then the divider is removed. Explain why the gas spreads out.", ["Compare the available volume before and after removal.", "Notice that the spread-out state allows many more molecular arrangements.", "Use multiplicity to explain the spontaneous change."], "The spread-out state is favored because it has far more compatible microstates", "Statistical physics explains the direction of spontaneous change through option count.", "This is the cleanest bridge from gas behaviour to entropy thinking."), worked("Two chamber descriptions have the same pressure, volume, temperature, and amount, but one description lists every molecular position and speed. Identify the macrostate and the microstate.", ["Look for the visible summary variables.", "Look for the exact molecular details.", "Name which description belongs to each level."], "The dashboard variables define the macrostate; the exact molecular details define the microstate", "This protects students from swapping the two statistical levels.", "The distinction is the foundation for the rest of entropy reasoning.")], visual_assets=[visual("a4-l5-partition-expansion", "Partition drop and multiplicity", "Show the chamber before and after a divider is removed so multiplicity stays visible as the reason for spreading.", "The spread-out state is more probable because it allows far more hidden arrangements, not because the molecules stop obeying the gas law.", diagram_type="partition_expansion", meta={"left_particles": 6, "right_particles": 6})], animation_assets=[], simulation_contract=sim_contract("a4_l5_partition_expansion_sim", "partition_expansion", "Open and close the partition while comparing concentrated and spread-out macrostates by their hidden option counts.", "Begin with the gas on one side of the chamber and note the visible dashboard state.", ["Open the partition and watch the gas spread into a larger volume.", "Compare the concentrated and spread-out multiplicity readouts.", "Explain why the macrostate can settle while microstates keep changing."], "Watch for the spread-out state winning by option count, not by a special force.", "Free expansion is a statistical preference for the macrostate with overwhelmingly more compatible microstates.", controls=[("partition_position", "Partition position", "Switches between confined and open chamber states."), ("particle_count", "Crowd count", "Changes how many dashers contribute to the multiplicity story."), ("available_volume", "Available volume", "Changes how much chamber space the gas can explore.")], readouts=[("Macrostate", "Shows the visible chamber summary."), ("Option count", "Shows the relative hidden playbook count."), ("Spread note", "Explains why the broader state is statistically favored.")]), reflection_prompts=["Explain why the gas does not need new molecules to gain entropy when a partition is removed.", "Explain why a macrostate can stay steady while the microstate keeps changing."], mastery_skills=["macrostate_meaning", "microstate_meaning", "macro_micro_language", "partition_entropy_reasoning", "multiplicity_compare", "accessible_microstates", "macro_micro_equilibrium", "entropy_not_just_disorder"], variation_plan={"diagnostic": "Fresh attempts rotate between macrostate-versus-microstate identification, free-expansion explanations, and multiplicity comparisons before any repeated wording.", "concept_gate": "Concept-gate retries use new concentrated-versus-spread scenarios and new macrostate/microstate contrasts so learners must reason from the option-count idea.", "mastery": "Mastery alternates between statistical expansion questions, multiplicity judgments, and short macrostate-versus-microstate explanations before repeating a question family."}, scaffold_support=scaffold("A spread-out chamber state wins because it fits more hidden playbooks.", "The dashboard state hides molecular detail, but that hidden detail decides which macrostates are overwhelmingly more probable.", "Which part of this description belongs to the visible dashboard, and which part belongs to the hidden playbook?", "Calling entropy only 'messiness' without explaining that it tracks the number of compatible microstates.", "The partition story works because opening more volume creates far more possible hidden arrangements for the same molecules.", "Why is the spread state statistically favored even though no new molecules appear?", extras=[extra_section("Dashboard versus playbook", "Macrostate is the visible summary. Microstate is the exact molecular detail beneath it.", "Why do many different microstates fit the same macrostate?"), extra_section("Spread beats crowding", "When more volume is available, a spread-out distribution can be built in vastly more ways than an all-in-one-corner state.", "Why does 'more ways' matter for spontaneity?")]), visual_clarity_checks=visual_checks("partition expansion")),
    )


def lesson_six() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        ("A4L6_D1", "In the Bounce-Chamber model, spread score stands for...", ["entropy", "pressure", "volume", "molecular mass"], 0, "Spread score is the entropy idea.", ["entropy_disorder_only_confusion"], ["entropy_meaning"]),
        ("A4L6_D2", "The statistical entropy relation is...", ["S = k ln W", "pV = nRT", "<Ek> = (3/2)kT", "F = ma"], 0, "This ties entropy to multiplicity.", ["entropy_disorder_only_confusion"], ["use_s_equals_klnw"]),
        ("A4L6_D3", "If the number of accessible microstates W increases, entropy S...", ["increases", "decreases", "stays fixed", "must become zero"], 0, "Larger W means larger entropy.", ["spontaneous_change_preference_confusion"], ["entropy_compare_w"]),
        ("A4L6_D4", "Why is entropy better described by option count than by 'messiness'?", ["Because the key statistical idea is how many hidden arrangements fit the same macrostate.", "Because messiness is a unit.", "Because entropy measures pressure directly.", "Because disorder means molecular mass."], 0, "Option count is the stronger concept.", ["entropy_disorder_only_confusion"], ["entropy_not_just_disorder"]),
        ("A4L6_D5", "If W doubles, the entropy change is...", ["positive", "negative", "zero", "impossible to compare"], 0, "Doubling W raises ln W.", ["spontaneous_change_preference_confusion"], ["entropy_compare_w"]),
        ("A4L6_D6", "Why does heat flow spontaneously from hot to cold?", ["Because the combined system can access more probable energy distributions and larger total multiplicity.", "Because hot objects lose pressure automatically.", "Because entropy means motion stops.", "Because cold always destroys energy."], 0, "Energy sharing increases accessible arrangements.", ["spontaneous_change_preference_confusion"], ["spontaneous_energy_sharing"]),
        ("A4L6_D7", "Which statement is strongest?", ["A spontaneous process tends toward a macrostate with a larger option count.", "A spontaneous process always lowers entropy.", "A spontaneous process stops molecular motion.", "A spontaneous process removes all collisions."], 0, "Spontaneity follows larger multiplicity.", ["spontaneous_change_preference_confusion"], ["spontaneous_change_reasoning"]),
        ("A4L6_D8", "A macrostate with W = 1000 compared with one with W = 10 has...", ["higher entropy", "lower entropy", "the same entropy", "no defined entropy"], 0, "Higher W means higher S.", ["entropy_disorder_only_confusion"], ["entropy_compare_w"]),
    ]) + build_shorts([
        ("A4L6_D9", "Why is entropy linked to option count?", ["Because entropy measures how many hidden microstates are compatible with the same visible macrostate.", "Because the more hidden playbooks a macrostate has, the larger its entropy is."], "Use hidden arrangements and same macrostate language.", ["entropy_disorder_only_confusion", "microstate_macrostate_confusion"], ["entropy_meaning"], acceptance_groups(["entropy"], ["microstates", "hidden arrangements", "hidden playbooks"], ["same macrostate", "visible state"], ["more", "number of", "count"])),
        ("A4L6_D10", "Why does larger W mean a larger spread score?", ["Because S = k ln W increases when W increases, so a macrostate with more compatible microstates has greater entropy.", "Because the entropy formula uses the logarithm of the option count, so more accessible playbooks means a higher spread score."], "Mention both W and entropy increasing together.", ["spontaneous_change_preference_confusion"], ["use_s_equals_klnw"], acceptance_groups(["S = k ln W", "ln W"], ["W increases", "more microstates", "larger option count"], ["entropy increases", "spread score increases"])),
    ])
    concept = build_mcqs([
        ("A4L6_C1", "For two macrostates, W1 > W2 implies...", ["S1 > S2", "S1 < S2", "S1 = S2", "entropy cannot be compared"], 0, "Entropy follows the logarithm of W.", ["spontaneous_change_preference_confusion"], ["entropy_compare_w"]),
        ("A4L6_C2", "If W changes from 100 to 10000, the stronger entropy conclusion is...", ["entropy increases", "entropy decreases", "entropy stays the same", "the system leaves statistical physics"], 0, "Bigger W means bigger S.", ["spontaneous_change_preference_confusion"], ["entropy_compare_w"]),
        ("A4L6_C3", "Why does an evenly shared energy distribution between two bodies often dominate statistically?", ["Because it can be realized by more combined microstates.", "Because it makes temperature vanish.", "Because it reduces all pressure to zero.", "Because it removes molecular motion."], 0, "Combined multiplicity drives the preference.", ["spontaneous_change_preference_confusion"], ["spontaneous_energy_sharing"]),
        ("A4L6_C4", "Which statement protects against the 'entropy is disorder only' shortcut?", ["Entropy is better treated as multiplicity or matter-and-energy dispersal.", "Entropy measures only appearance.", "Entropy means no structure can exist.", "Entropy is a replacement for pressure."], 0, "Dispersal and multiplicity are stronger than vague disorder talk.", ["entropy_disorder_only_confusion"], ["entropy_not_just_disorder"]),
        ("A4L6_C5", "If a spontaneous process makes more microstates accessible, then the most reliable entropy trend is...", ["upward", "downward", "always zero", "undefined"], 0, "Accessible microstates and entropy rise together.", ["spontaneous_change_preference_confusion"], ["spontaneous_change_reasoning"]),
        ("A4L6_C6", "Which formula belongs to the statistical extension of this module?", ["S = k ln W", "pV = nRT", "I = V/R", "c = f lambda"], 0, "This is the compact option-count formula.", ["entropy_disorder_only_confusion"], ["use_s_equals_klnw"]),
    ]) + build_shorts([
        ("A4L6_C7", "Explain why heat flow from hot to cold can be described as a multiplicity story.", ["Because sharing energy more evenly usually gives the combined system many more accessible microstates, so that direction is overwhelmingly more probable.", "Because the hot-cold pair moves toward a larger total option count when energy spreads out more evenly."], "Use combined system and more microstates language.", ["spontaneous_change_preference_confusion"], ["spontaneous_energy_sharing"], acceptance_groups(["hot to cold", "energy sharing"], ["more microstates", "larger total option count", "greater multiplicity"], ["more probable", "spontaneous"])),
        ("A4L6_C8", "Correct the statement 'Entropy is just a fancy word for chaos.'", ["Entropy is better defined through the number of compatible microstates or the spread of matter and energy, not a vague idea of chaos.", "Chaos is too vague; the stronger physics idea is multiplicity or option count behind a macrostate."], "Replace vague chaos talk with multiplicity language.", ["entropy_disorder_only_confusion"], ["entropy_not_just_disorder"], acceptance_groups(["not just", "too vague"], ["microstates", "multiplicity", "option count"], ["macrostate", "spread of matter and energy", "dispersal"])),
    ])
    mastery = build_mcqs([
        ("A4L6_M1", "If W increases by a factor of 10, entropy...", ["increases", "decreases", "stays fixed", "must become negative"], 0, "Larger W gives larger ln W.", ["spontaneous_change_preference_confusion"], ["entropy_compare_w"]),
        ("A4L6_M2", "Which macrostate has the greater entropy?", ["the one with more compatible microstates", "the one with fewer compatible microstates", "the one with the smaller volume automatically", "the one with zero motion"], 0, "Entropy compares option counts.", ["entropy_disorder_only_confusion"], ["entropy_meaning"]),
        ("A4L6_M3", "A student uses S = k ln W. What must W represent?", ["the number of compatible microstates", "the weight of the gas", "the wall-hit load", "the average speed"], 0, "W is multiplicity.", ["microstate_macrostate_confusion"], ["use_s_equals_klnw"]),
        ("A4L6_M4", "Why is the spread-out gas state usually the spontaneous one?", ["Because it has a much larger option count and therefore larger entropy.", "Because it has no molecules.", "Because it removes the ideal gas law.", "Because the wall collisions stop."], 0, "Spontaneity follows multiplicity.", ["spontaneous_change_preference_confusion"], ["spontaneous_change_reasoning"]),
        ("A4L6_M5", "Heat-match idea for entropy: when W grows, S...", ["grows too", "falls", "stays fixed", "changes sign each cycle"], 0, "Entropy follows the logarithm of W.", ["spontaneous_change_preference_confusion"], ["entropy_compare_w"]),
        ("A4L6_M7", "Best advanced summary of entropy in this module:", ["entropy tracks how many hidden arrangements fit the same visible state", "entropy is only how messy something looks", "entropy means molecules stop moving", "entropy equals temperature"], 0, "Option count is the advanced summary.", ["entropy_disorder_only_confusion"], ["entropy_meaning"]),
        ("A4L6_M8", "Which direction of change is statistically favored?", ["toward the macrostate with larger multiplicity", "toward the macrostate with fewer options", "toward zero pressure only", "toward frozen molecules"], 0, "Probability favors larger multiplicity.", ["spontaneous_change_preference_confusion"], ["spontaneous_change_reasoning"]),
        ("A4L6_M9", "If two possible macrostates have W values 50 and 5000, the second one has...", ["higher entropy", "lower entropy", "the same entropy", "no macrostate"], 0, "Higher W means higher S.", ["spontaneous_change_preference_confusion"], ["entropy_compare_w"]),
    ]) + build_shorts([
        ("A4L6_M6", "Summarize entropy in one strong sentence for this module.", ["Entropy measures how many hidden microstates fit the same visible macrostate, so larger option count means larger entropy.", "Entropy is the spread score of the chamber because it grows when more hidden playbooks are available for the same dashboard state."], "Keep hidden arrangements and same visible state together.", ["entropy_disorder_only_confusion", "microstate_macrostate_confusion"], ["entropy_meaning"], acceptance_groups(["entropy", "spread score"], ["microstates", "hidden arrangements", "hidden playbooks"], ["same macrostate", "same visible state", "dashboard state"], ["larger option count", "more options", "more microstates"])),
        ("A4L6_M10", "Why does the Bounce-Chamber story say spontaneous change heads toward bigger option counts?", ["Because macrostates with larger multiplicity are overwhelmingly more probable, so spontaneous change tends to move that way.", "Because the chamber naturally evolves toward states with many more compatible hidden playbooks."], "Use more probable and larger multiplicity language.", ["spontaneous_change_preference_confusion"], ["spontaneous_change_reasoning"], acceptance_groups(["larger multiplicity", "bigger option count", "more compatible microstates"], ["more probable", "overwhelmingly more probable"], ["spontaneous change", "tends to move"])),
    ])
    return lesson_spec(
        "A4_L6",
        "Entropy as Spread Score",
        sim("a4_option_count_boss", "Option-count boss", "Compare microstate counts and energy-sharing patterns so entropy becomes an option-count idea instead of a vague disorder slogan.", ["Compare two macrostates with different W values.", "Raise or lower the option count.", "Explain the direction of spontaneous change using multiplicity."], ["Use S = k ln W conceptually.", "Compare entropy by comparing W.", "Explain why spontaneous change heads toward bigger option counts."], ["option_count", "entropy_level", "energy_sharing", "macrostate_choice"], "Entropy and spontaneity reasoning."),
        diagnostic,
        "The final chamber rule is the spread score. Entropy measures how many hidden arrangements fit the same visible state. That is why the option-count formula S = k ln W is so powerful: larger option count means larger entropy. Spontaneous change heads toward macrostates with overwhelmingly larger multiplicity.",
        "Commit to entropy as option count and dispersal, not as a vague label for messiness.",
        [prompt_block("What does W count?", "How many hidden playbooks fit the same visible state."), prompt_block("Why is S = k ln W useful?", "It compresses the option-count story into one formula.")],
        [prompt_block("Compare two states with different W values.", "The state with larger W should have larger entropy."), prompt_block("Think about hot-to-cold energy sharing.", "The favored direction should be the one with more combined microstates.")],
        ["Why is entropy stronger as an option-count idea than as a disorder slogan?", "Why does spontaneous change head toward larger multiplicity?"],
        "Close the module by turning the hidden-playbook idea into the formal entropy rule.",
        concept,
        mastery,
        contract(concept_targets=["Explain entropy as a multiplicity or option-count idea.", "Use S = k ln W qualitatively.", "Explain spontaneous change as motion toward larger accessible multiplicity."], core_concepts=["Entropy grows when the number of compatible microstates grows.", "S = k ln W compresses the option-count story into one formula.", "Macrostates with larger multiplicity are overwhelmingly more probable.", "Entropy is better understood as dispersal and multiplicity than as vague disorder."], prerequisite_lessons=["A4_L5"], misconception_focus=["entropy_disorder_only_confusion", "spontaneous_change_preference_confusion", "microstate_macrostate_confusion"], formulas=[relation("S = k ln W", "Statistical entropy relation linking entropy to multiplicity.", ["J K^-1"], "Use as the compact form of the option-count idea."), relation("larger W -> larger S", "Qualitative entropy comparison rule.", ["concept only"], "Useful when comparing likely macrostates without full calculation.")], representations=[representation("words", "Frames entropy as spread score and option count."), representation("diagram", "Shows two macrostates with different option counts."), representation("formula", "Uses S = k ln W as the compact statistical statement."), representation("model", "Connects spontaneous change to larger multiplicity in the Bounce-Chamber world.")], analogy_map=bounce_chamber_map("the learner compares chamber states by hidden option count and uses that to explain spontaneity"), worked_examples=[worked("Two macrostates have W = 10^3 and W = 10^6. Which has greater entropy?", ["Compare the two W values.", "Remember that larger W gives larger ln W.", "State which macrostate has the higher entropy."], "The state with W = 10^6 has higher entropy", "Entropy follows the logarithm of multiplicity, so larger option count still means larger entropy.", "This is the cleanest comparison task for S = k ln W."), worked("Explain why heat flows from hot to cold using the option-count idea.", ["Treat the two bodies as one combined system.", "Compare uneven and more-even energy sharing.", "State that the more-even distribution allows more combined microstates."], "Hot-to-cold flow is favored because it increases the combined option count", "Spontaneous energy sharing follows multiplicity, not vague intention.", "This anchors entropy to energy dispersal instead of mystery.")], visual_assets=[visual("a4-l6-entropy-option-count", "Option count and spread score", "Compare low-option and high-option chamber states so entropy becomes a count story rather than a stylistic label.", "Entropy is larger when the same visible state can be built in more hidden ways, and spontaneous change tends toward that larger option count.", diagram_type="entropy_option_count", meta={"w_low": 8, "w_high": 56})], animation_assets=[], simulation_contract=sim_contract("a4_l6_entropy_option_count_sim", "entropy_option_count", "Compare macrostate options, multiplicity, and energy sharing until entropy reads like a count story instead of a slogan.", "Start with two possible chamber states and compare their W values.", ["Increase the accessible option count.", "Compare a concentrated and a spread-out macrostate.", "Switch to an energy-sharing view and explain the favored direction."], "Watch for larger W always pushing the entropy reading upward.", "Entropy is the spread score because it grows when more hidden playbooks fit the same visible state.", controls=[("option_count", "Option count", "Changes the multiplicity W available to the macrostate."), ("macrostate_choice", "Macrostate choice", "Compares concentrated and spread-out outcomes."), ("energy_sharing", "Energy sharing", "Shows how hot-cold sharing changes total multiplicity.")], readouts=[("Entropy", "Shows the spread score linked to W."), ("Multiplicity note", "Explains why the larger W state is more probable."), ("Spontaneous direction", "Labels which way the combined system is statistically favored to move.")]), reflection_prompts=["Explain why S = k ln W is stronger than saying entropy is just messiness.", "Explain why spontaneous change points toward larger multiplicity in the Bounce-Chamber model."], mastery_skills=["entropy_meaning", "use_s_equals_klnw", "entropy_compare_w", "entropy_not_just_disorder", "spontaneous_energy_sharing", "spontaneous_change_reasoning"], variation_plan={"diagnostic": "Fresh attempts rotate between W comparisons, S = k ln W interpretation, and spontaneity explanations so repeated stems are unlikely.", "concept_gate": "Concept-gate retries alternate between entropy-language corrections and new multiplicity comparison cases.", "mastery": "Mastery varies option-count comparisons, short conceptual entropy summaries, and spontaneity explanations before repeating a previous question family."}, scaffold_support=scaffold("Entropy is the spread score set by hidden option count.", "The chamber looks simple from the outside, but the hidden number of ways to realize that visible state decides which macrostates are statistically favored.", "What hidden count is changing when entropy changes in this example?", "Using 'disorder' as a vague substitute for explaining multiplicity or matter-and-energy dispersal.", "The option-count story is stronger because it explains both gas expansion and energy sharing with the same statistical rule.", "Why does larger multiplicity make a macrostate statistically dominant?", extras=[extra_section("Logarithm note", "The logarithm keeps entropy manageable while preserving the rule that larger multiplicity means larger entropy.", "Why does the formula still rank larger W as larger S?"), extra_section("Spontaneous direction", "A spontaneous process is statistically favored when it moves the system toward macrostates with many more compatible microstates.", "Why is probability tied to multiplicity here?")]), visual_clarity_checks=visual_checks("entropy option count")),
    )


A4_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Ideal gas law, kinetic theory, and conceptual entropy taught through the Bounce-Chamber Count Model so pressure, temperature, macrostate, microstate, and spontaneity stay inside one coherent advanced thermal-statistical story.",
    "mastery_outcomes": [
        "Explain gas pressure as the macroscopic effect of molecular wall collisions.",
        "Use the ideal gas law conceptually and algebraically as a chamber balance rule.",
        "Connect pV = (1/3) N m <c^2> and <Ek> = (3/2)kT to microscopic molecular motion.",
        "Interpret temperature as average translational kinetic energy per molecule, not total sample energy.",
        "Distinguish macrostate and microstate and explain free expansion statistically.",
        "Explain entropy as an option-count and dispersal idea using S = k ln W qualitatively.",
    ],
    "lessons": [
        lesson_one(),
        lesson_two(),
        lesson_three(),
        lesson_four(),
        lesson_five(),
        lesson_six(),
    ],
}


RELEASE_CHECKS = [
    "Every lesson keeps Bounce-Chamber language visible across pressure, gas laws, kinetic theory, temperature, macrostate, microstate, and entropy.",
    "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
    "Every lesson-owned assessment bank supports fresh unseen diagnostic, concept-gate, and mastery questions before repeats.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example explains why the answer follows instead of naming only the final value.",
    "Every A4 visual keeps wall-hit load, chamber geometry, average dash energy, partition states, and option-count comparisons readable without clipping.",
]


A4_MODULE_DOC, A4_LESSONS, A4_SIM_LABS = build_nextgen_module_bundle(
    module_id=A4_MODULE_ID,
    module_title=A4_MODULE_TITLE,
    module_spec=A4_SPEC,
    allowlist=A4_ALLOWLIST,
    content_version=A4_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=21,
    level="Module A4",
    estimated_minutes=360,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module A4 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(A4_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A4_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A4_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", A4_MODULE_ID)]
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
    main()
