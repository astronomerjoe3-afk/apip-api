from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_builder import build_nextgen_module_bundle
    from scripts.lesson_authoring_contract import AUTHORING_STANDARD_V3
except ModuleNotFoundError:
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_builder import build_nextgen_module_bundle
    from lesson_authoring_contract import AUTHORING_STANDARD_V3

try:
    from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
except ModuleNotFoundError:
    from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc


M6_MODULE_ID = "M6"
M6_CONTENT_VERSION = "20260323_m6_thermal_transfer_gas_behaviour_v4"
M6_MODULE_TITLE = "Thermal Transfer and Gas Behaviour"
M6_ALLOWLIST = [
    "heat_temperature_confusion",
    "same_energy_same_temp_change_confusion",
    "mass_heating_confusion",
    "specific_heat_capacity_confusion",
    "latent_heat_temperature_rise_confusion",
    "phase_change_energy_confusion",
    "conduction_particle_flow_confusion",
    "metal_conduction_reason_confusion",
    "convection_heat_rises_confusion",
    "radiation_medium_confusion",
    "transfer_route_mixing_confusion",
    "multi_stage_heat_calculation_confusion",
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
    allowed = set(M6_ALLOWLIST)
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


def relation(equation: str, meaning: str, units: Sequence[str], conditions: str) -> Dict[str, Any]:
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
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile.",
        "The core comparison readouts are not overlapped by arrows, beams, or route markers.",
        "The key meter, equation, or caption remains readable without hidden text or clipping.",
    ]


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
    normalized_representations = [deepcopy(item) for item in representations]
    normalized_kinds = {str(item.get("kind") or "").strip() for item in normalized_representations}
    if "words" not in normalized_kinds:
        normalized_representations.insert(0, {"kind": "words", "purpose": "States the thermal idea in plain language before symbols."})
    if "formula" not in normalized_kinds:
        anchor = str(formulas[0].get("equation") or "").strip() if formulas else "the formal statement"
        normalized_representations.append({"kind": "formula", "purpose": f"Compresses the key relation into {anchor} after the model is clear."})
    if not ({item.get("kind") for item in normalized_representations} & {"diagram", "graph", "table", "model", "equation_story"}):
        normalized_representations.append({"kind": "diagram", "purpose": "Keeps the Level-Forge comparison visible while variables change."})

    normalized_skills: List[str] = []
    for skill in mastery_skills:
        cleaned = str(skill or "").strip()
        if cleaned and cleaned not in normalized_skills:
            normalized_skills.append(cleaned)

    return {
        "concept_targets": list(concept_targets),
        "core_concepts": list(core_concepts),
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
        "mastery_skills": normalized_skills[:5],
        "variation_plan": deepcopy(variation_plan),
        "assessment_bank_targets": assessment_targets(8, 6, 8),
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
    *,
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
    resolved_contract = deepcopy(contract_payload)
    declared_skills = [
        str(skill).strip()
        for skill in resolved_contract.get("mastery_skills") or []
        if str(skill).strip()
    ]
    for item in [*diagnostic, *capsule_checks, *transfer]:
        for skill in item.get("skill_tags") or []:
            cleaned = str(skill).strip()
            if cleaned and cleaned not in declared_skills:
                declared_skills.append(cleaned)
    resolved_contract["mastery_skills"] = declared_skills
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
        "contract": resolved_contract,
    }


def forge_map(model_focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Level-Forge Model of Thermal Transfer",
        "focus": model_focus,
        "comparison": f"The Level-Forge keeps heating, phase change, and transfer routes inside one forge world by tracking Warmth Level, Build Size, Level Cost, Form Gates, and the Forge Ledger while {model_focus}.",
        "mapping": [
            "Warmth Level -> temperature",
            "Transfer Energy -> heat transferred",
            "Build Size -> mass",
            "Level Cost -> specific heat capacity",
            "Form Gate -> melting or boiling point",
            "Morph Fee -> latent heat",
            "Touch Relay -> conduction",
            "Carrier Loop -> convection",
            "Glow Cast -> radiation",
            "Forge Ledger -> quantitative heat calculations",
        ],
        "limit": "The Level-Forge organizes the relationships, but the formal thermal terms and equations still matter when you explain a mechanism or calculate a total transfer.",
        "prediction_prompt": f"Using the Level-Forge alone, predict what should happen when {model_focus}.",
    }


def warmup_relation() -> Dict[str, Any]:
    return relation(
        "Q = m c delta T",
        "Transfer energy for a temperature change depends on mass, specific heat capacity, and the temperature change while the state stays the same.",
        ["J", "kg", "J/kg degree C", "degree C"],
        "Use when the material is warming or cooling without melting or boiling.",
    )


def latent_relation() -> Dict[str, Any]:
    return relation(
        "Q = m L",
        "Transfer energy for a state change depends on the mass and the specific latent heat.",
        ["J", "kg", "J/kg"],
        "Use during melting or boiling when the temperature stays constant while the form changes.",
    )


def ledger_relation() -> Dict[str, Any]:
    return relation(
        "Q_total = sum of stage energies",
        "A multi-stage thermal mission adds the energy from each warming, cooling, melting, or boiling stage.",
        ["J"],
        "Use when the process contains more than one distinct stage or route.",
    )


def lesson_l1() -> Dict[str, Any]:
    return lesson_spec(
        lesson_id="M6_L1",
        title="Warmth Level Is Not Transfer Energy",
        sim_meta=sim(
            "m6_warmth_level_lab",
            "Warmth Level lab",
            "Compare Warmth Level with Transfer Energy, Build Size, and Level Cost in the Level-Forge.",
            [
                "Start two forge blocks with the same Warmth Level.",
                "Send in the same Transfer Energy and compare how the Warmth Level responds when size or cost changes.",
                "Use the Forge Ledger to keep the hand-off event separate from the temperature reading.",
            ],
            [
                "Explain why the same Transfer Energy does not always cause the same temperature change.",
                "Distinguish Warmth Level from the Transfer Energy ledger.",
            ],
            ["warmth_level", "transfer_energy", "build_size", "level_cost"],
            "Use the lab to separate state reading from energy hand-off before formulas become formal.",
        ),
        diagnostic=[
            mcq("M6L1_D1", "Which Level-Forge term stands for temperature?", ["Warmth Level", "Transfer Energy", "Morph Fee", "Glow Cast"], 0, "Warmth Level tells how hot or cold the block is now.", ["heat_temperature_confusion"], skill_tags=["temperature_reading"]),
            mcq("M6L1_D2", "Two blocks start at the same Warmth Level and each receive 400 J. Which statement must be true?", ["They received the same Transfer Energy", "They must rise by the same number of levels", "They must end at the same temperature", "They must have the same mass"], 0, "The hand-off can match even when the temperature response differs.", ["same_energy_same_temp_change_confusion"], skill_tags=["energy_transfer_compare"]),
            short("M6L1_D3", "Why is saying 'the block contains heat' weaker than the Level-Forge language?", ["Because heat is Transfer Energy handed in or out, while Warmth Level is the block's temperature reading."], "Keep the stored state and the transfer event separate.", ["heat_temperature_confusion"], acceptance_rules=acceptance_groups(["heat", "transfer energy", "energy transferred"], ["temperature", "warmth level", "how hot"], ["not stored", "handed in", "handed out", "transfer"]), skill_tags=["heat_vs_temperature"]),
            mcq("M6L1_D4", "A small iron block and a large iron block both receive the same Transfer Energy. Which is most likely to happen?", ["The smaller block rises more in Warmth Level", "They rise by exactly the same amount", "The larger block always gets hotter", "Neither block can change temperature"], 0, "A larger Build Size needs more energy for the same level rise.", ["mass_heating_confusion", "same_energy_same_temp_change_confusion"], skill_tags=["mass_effect"]),
            mcq("M6L1_D5", "A forge block cools. Which statement is strongest?", ["Transfer Energy is leaving the block", "Its heat content is staying fixed", "Warmth Level and Transfer Energy mean the same thing", "Cooling can happen without any energy transfer"], 0, "Cooling is energy transfer out of the block.", ["heat_temperature_confusion"], skill_tags=["cooling_story"]),
            short("M6L1_D6", "Why might two equal-energy heating missions end with different Warmth Level rises?", ["Because Build Size and Level Cost can be different, so the same Transfer Energy can produce different temperature changes."], "Name both mass and material cost if you can.", ["same_energy_same_temp_change_confusion", "specific_heat_capacity_confusion"], acceptance_rules=acceptance_groups(["build size", "mass"], ["level cost", "specific heat capacity"], ["same transfer", "same energy"], ["different temperature change", "different warmth level rise"]), skill_tags=["response_compare"]),
            mcq("M6L1_D7", "Which readout answers 'how hot is it right now?'", ["Warmth Level meter", "Transfer Energy ledger", "Morph Fee meter", "Route selector"], 0, "Temperature is the present-state reading.", ["heat_temperature_confusion"], skill_tags=["temperature_reading"]),
            mcq("M6L1_D8", "A copper block and a water block have the same mass and each receive the same Transfer Energy. What extra idea decides whether their Warmth Level rises match?", ["Level Cost", "Only the initial color", "Only the route name", "Only the block shape"], 0, "Different materials charge different energy per kilogram per degree.", ["specific_heat_capacity_confusion", "same_energy_same_temp_change_confusion"], skill_tags=["material_cost"]),
        ],
        analogy_text="In the Level-Forge, Warmth Level is the block's temperature meter, while Transfer Energy is the energy handed into or out of the block. The same payment can move different blocks by different numbers of levels because Build Size and Level Cost still matter.",
        commitment_prompt="If two blocks start on the same Warmth Level and receive the same Transfer Energy, what else must you inspect before predicting the level rise?",
        micro_prompts=[
            prompt_block("Which meter tells how hot the block is now?", "Look for the state reading, not the hand-off counter."),
            prompt_block("Which meter records the energy hand-off event?", "The ledger tracks transfer even when the level rise differs."),
        ],
        inquiry=[
            prompt_block("Keep the Transfer Energy fixed and change Build Size. What happens to the Warmth Level rise?", "Bigger blocks cost more to raise by the same number of levels."),
            prompt_block("Keep size fixed and change Level Cost. What happens now?", "Higher Level Cost means the same energy buys fewer levels."),
        ],
        recon_prompts=[
            "Explain the difference between Warmth Level and Transfer Energy without using the words as if they meant the same thing.",
            "Explain why equal-energy heating does not always produce equal temperature rise.",
        ],
        capsule_prompt="Keep the state reading and the energy hand-off separate.",
        capsule_checks=[
            mcq("M6L1_C1", "Which statement is strongest?", ["Warmth Level is temperature, while Transfer Energy is the hand-off event", "Temperature is a stored type of heat", "Heat and temperature are always the same number", "Warmth Level only matters during cooling"], 0, "Keep the state and transfer ideas separate.", ["heat_temperature_confusion"], skill_tags=["heat_vs_temperature"]),
            short("M6L1_C2", "Why does a larger Build Size usually rise less in Warmth Level for the same Transfer Energy?", ["Because more mass needs more energy for the same temperature rise."], "State the mass rule directly.", ["mass_heating_confusion"], acceptance_rules=acceptance_groups(["more mass", "larger build size"], ["more energy needed", "needs more transfer"], ["same temperature rise", "same level rise"]), skill_tags=["mass_effect"]),
            mcq("M6L1_C3", "Which Level-Forge term stands for material-specific heating difficulty?", ["Level Cost", "Glow Cast", "Warmth Level", "Carrier Loop"], 0, "Level Cost maps to specific heat capacity.", ["specific_heat_capacity_confusion"], skill_tags=["material_cost"]),
            short("M6L1_C4", "Why is 'same energy, same temperature rise' not always valid?", ["Because mass and specific heat capacity can differ between the objects."], "Name both the amount of material and the material property.", ["same_energy_same_temp_change_confusion", "specific_heat_capacity_confusion"], acceptance_rules=acceptance_groups(["mass", "build size"], ["specific heat capacity", "level cost"], ["can differ", "not always the same"]), skill_tags=["energy_transfer_compare"]),
            mcq("M6L1_C5", "When a block cools, which statement best matches the model?", ["Transfer Energy leaves while Warmth Level may fall", "Heat stays stored but temperature disappears", "No energy moves because cooling is passive", "Cooling changes mass first"], 0, "Cooling is still a transfer story.", ["heat_temperature_confusion"], skill_tags=["cooling_story"]),
            mcq("M6L1_C6", "Which pair should you keep distinct?", ["Warmth Level and Transfer Energy", "Build Size and mass", "Level Cost and specific heat capacity", "Glow Cast and radiation"], 0, "The model is most useful when temperature and transferred energy are not collapsed together.", ["heat_temperature_confusion"], skill_tags=["temperature_reading"]),
        ],
        transfer=[
            mcq("M6L1_M1", "A mug of tea and a bathtub of water are both at 40 degree C. Which statement is strongest?", ["They share a temperature reading, but that does not tell you the same total transfer history", "They must contain the same heat", "They must need the same energy to cool by 5 degree C", "They must have the same mass"], 0, "A shared temperature does not erase differences in mass or total energy story.", ["heat_temperature_confusion", "same_energy_same_temp_change_confusion"], skill_tags=["heat_vs_temperature"]),
            mcq("M6L1_M2", "Two 1 kg blocks start at the same Warmth Level and each receive 1000 J. Block A rises more than Block B. What is the best explanation?", ["Block A has a lower Level Cost", "Block A has a higher Morph Fee", "Block A had no mass", "The same energy always causes the same rise"], 0, "If the masses match, the material cost is the most direct difference.", ["specific_heat_capacity_confusion"], skill_tags=["material_cost"]),
            short("M6L1_M3", "Why can a small hot pan and a large warm pan be different ideas even if one sounds 'hotter'?", ["Because temperature tells how hot they are, but mass and material still affect the total transfer needed to change them."], "Do not treat 'hotter' and 'more energy involved' as identical.", ["heat_temperature_confusion", "mass_heating_confusion"], acceptance_rules=acceptance_groups(["temperature", "how hot"], ["mass", "amount of material"], ["different transfer", "different energy needed", "not the same total energy story"]), skill_tags=["state_vs_total"]),
            mcq("M6L1_M4", "Which change would definitely alter the Transfer Energy needed for the same Warmth Level rise in the same material?", ["Increasing Build Size", "Repainting the block", "Changing the route name only", "Renaming the meter"], 0, "Mass is directly in the heating rule.", ["mass_heating_confusion"], skill_tags=["mass_effect"]),
            short("M6L1_M5", "A learner says 'heat is just another word for temperature.' How would you correct them?", ["Temperature is the Warmth Level reading, while heat means energy transferred because of a temperature difference."], "Name one as a reading and the other as a transfer.", ["heat_temperature_confusion"], acceptance_rules=acceptance_groups(["temperature", "warmth level", "how hot"], ["heat", "energy transferred", "transfer energy"], ["difference", "not the same", "separate"]), skill_tags=["heat_vs_temperature"]),
            mcq("M6L1_M6", "If the same Transfer Energy raises block A by 8 levels and block B by 2 levels, which claim is safest?", ["At least one of mass or Level Cost differs", "Their masses must be identical", "Their Level Costs must be identical", "Transfer Energy is not involved"], 0, "Different responses point to size or material cost differences.", ["same_energy_same_temp_change_confusion", "specific_heat_capacity_confusion"], skill_tags=["response_compare"]),
            mcq("M6L1_M7", "Which question is answered by the Warmth Level meter rather than the Forge Ledger?", ["What temperature is the block now?", "How much energy has crossed so far?", "Which route is operating?", "How much latent fee has been paid?"], 0, "Warmth Level is a state readout.", ["heat_temperature_confusion"], skill_tags=["temperature_reading"]),
            mcq("M6L1_M8", "A block ends at the same Warmth Level it started with after a full cycle. Which statement can still be true?", ["Transfer Energy flowed in and then later out", "No energy moved at any point", "Mass changed instead of energy transferring", "Temperature and heat became identical"], 0, "The ledger can show movement even if the final temperature matches the start.", ["heat_temperature_confusion"], skill_tags=["cooling_story"]),
        ],
        contract_payload=contract(
            concept_targets=[
                "Separate temperature from heat transferred before any quantitative heating work begins.",
                "Explain qualitatively why equal-energy heating can produce different temperature changes.",
            ],
            core_concepts=[
                "Warmth Level stands for temperature, which is a present-state reading rather than an energy-transfer event.",
                "Heat means energy transferred because of a temperature difference, so it should not be spoken of as a stored substance inside the object.",
                "The same Transfer Energy does not guarantee the same temperature rise because mass and specific heat capacity still matter.",
                "Cooling is energy transfer out of the object, not the disappearance of a special temperature substance.",
            ],
            prerequisite_lessons=["M5_L4", "M5_L5", "M5_L6"],
            misconception_focus=["heat_temperature_confusion", "same_energy_same_temp_change_confusion", "mass_heating_confusion", "specific_heat_capacity_confusion"],
            formulas=[warmup_relation()],
            representations=[
                representation("words", "State clearly that temperature is a reading and heat is transferred energy."),
                representation("model", "Use the Level-Forge meters to separate state from hand-off."),
                representation("table", "Compare equal-energy heating runs with different masses or materials."),
            ],
            analogy_map=forge_map("students compare the Warmth Level meter with the Forge Ledger"),
            worked_examples=[
                worked("Two blocks start at the same Warmth Level and each receive 600 J. One rises by 6 levels and one rises by 2. What should you conclude first?", ["Keep the equal Transfer Energy fixed first.", "Notice that the temperature responses differ.", "Conclude that mass, Level Cost, or both are different."], "At least one of Build Size or Level Cost differs between the blocks.", "Equal energy does not force equal temperature rise.", "This blocks the idea that temperature change depends on energy alone."),
                worked("A learner says 'the tea contains more heat because it is hotter than the room.' How should the Level-Forge correct this?", ["Treat the tea's temperature as a Warmth Level reading.", "Treat heat as the energy transfer that can occur because of the temperature difference.", "State that the tea is hotter, but 'heat' names the transfer event rather than a stored substance."], "The tea has a higher temperature, but heat refers to the energy transferred between the tea and its surroundings.", "The model keeps state reading and transfer event separate.", "This addresses the most common language trap in thermal physics."),
                worked("A small copper block and a large copper block start together and each receive the same energy payment. Which rises faster, and why?", ["Keep the material the same so Level Cost is fixed.", "Compare only the Build Size.", "State that the smaller block rises more because less mass needs less energy per degree."], "The smaller copper block rises more in temperature.", "With the same material, a smaller mass needs less energy for the same temperature change.", "This builds the mass idea before the full equation is used heavily."),
            ],
            visual_assets=[visual("m6-l1-warmth-level", "warmth_level", "Warmth Level and Forge Ledger", "Shows the temperature meter beside the transfer ledger so the learner can keep state and hand-off distinct.", "Warmth Level answers how hot the block is now, while the ledger answers how much energy has crossed.")],
            animation_assets=[animation("m6-l1-transfer-ledger", "warmth_level", "The same payment, different level rise", "Shows equal energy packets entering blocks with different size or cost so the Warmth Level changes by different amounts.")],
            simulation_contract={
                "asset_id": "m6_l1_warmth_level_lab",
                "concept": "warmth_level",
                "baseline_case": "Start two forge blocks at the same Warmth Level and give each the same Transfer Energy.",
                "focus_prompt": "How can the same energy payment produce different Warmth Level rises?",
                "controls": [
                    {"variable": "transfer_energy", "label": "Transfer Energy", "why_it_matters": "Keeps the energy hand-off visible."},
                    {"variable": "build_size", "label": "Build Size", "why_it_matters": "Shows how more mass changes the response."},
                    {"variable": "level_cost", "label": "Level Cost", "why_it_matters": "Shows how different materials charge different energy per degree."},
                ],
                "readouts": [
                    {"label": "Warmth Level", "meaning": "Shows the temperature reading right now."},
                    {"label": "Forge Ledger", "meaning": "Shows how much Transfer Energy has been paid in or out."},
                    {"label": "Level rise", "meaning": "Shows the resulting temperature change."},
                ],
                "comparison_tasks": [
                    "Keep Transfer Energy fixed and compare a small block with a large block.",
                    "Keep size fixed and compare a low-cost block with a high-cost block.",
                ],
                "watch_for": "Students should not talk as if the block stores heat as a substance or as if equal energy must cause equal temperature rise.",
                "takeaway": "Temperature is the Warmth Level reading, while heat names the Transfer Energy crossing because of a temperature difference.",
            },
            reflection_prompts=[
                "Why is it useful to keep Warmth Level and Transfer Energy as separate ideas in the Level-Forge?",
                "Why can equal-energy heating missions produce different temperature rises?",
            ],
            mastery_skills=[
                "Distinguish temperature from heat transferred",
                "Compare equal-energy heating outcomes qualitatively",
                "Explain mass effects on temperature change",
                "Explain material-cost effects on temperature change",
                "Describe cooling as energy transfer out",
            ],
            variation_plan={
                "diagnostic": "Rotate hot-object language, same-energy comparisons, and cooling interpretations so the distinction appears in several contexts.",
                "concept_gate": "Retry using a different pair of blocks or a different language trap before repeating any stem.",
                "mastery": "Use unseen masses, materials, and wording variations before repeating earlier warm-level prompts.",
            },
            scaffold_support=scaffold(
                "Warmth Level is the temperature reading now, while Transfer Energy is the energy handed in or out. The model is strongest when those two ideas stay separate.",
                "Ask first what is being measured right now and what has crossed the boundary. Then ask what mass and Level Cost would do to the response before predicting the temperature rise.",
                "Which meter answers 'how hot is it now', and which meter answers 'how much energy crossed'?",
                "Do not talk as if an object simply 'contains heat'. That language hides the difference between a temperature reading and an energy transfer.",
                "In the Level-Forge, the Warmth Level meter can stay separate from the Forge Ledger, so learners can see that a matching energy payment does not force a matching level rise.",
                "Why can the ledger match while the Warmth Level rises do not?",
                extra_sections=[
                    extra_section("Same payment, different response", "Build Size and Level Cost both affect how much Warmth Level change a given payment can buy."),
                    extra_section("Cooling still uses the ledger", "When a block cools, the energy story has not disappeared; the transfer has simply reversed direction."),
                ],
            ),
            visual_clarity_checks=visual_checks("Warmth Level"),
        ),
    )


def lesson_l2() -> Dict[str, Any]:
    return lesson_spec(
        lesson_id="M6_L2",
        title="Build Size, Level Cost, and Q = m c delta T",
        sim_meta=sim(
            "m6_level_cost_lab",
            "Level Cost calculator lab",
            "Use the Forge Ledger to connect mass, specific heat capacity, temperature change, and transfer energy.",
            [
                "Choose a material cost, a build size, and a target level rise.",
                "Predict the energy bill before the calculator reveals the Forge Ledger total.",
                "Rearrange the rule when the unknown is the level rise or the Level Cost.",
            ],
            [
                "Calculate thermal energy transfers with Q = m c delta T.",
                "Explain specific heat capacity as energy per kilogram per degree.",
            ],
            ["mass", "specific_heat_capacity", "delta_t", "transfer_energy"],
            "Use the lab to turn the Level-Forge warm-up rule into formal energy bookkeeping.",
        ),
        diagnostic=[
            mcq("M6L2_D1", "What does specific heat capacity mean most directly?", ["The energy needed for 1 kg to change by 1 degree C", "The total heat stored in any hot object", "The temperature where melting starts", "The route used for heating"], 0, "Specific heat capacity is an energy-per-kilogram-per-degree idea.", ["specific_heat_capacity_confusion"], skill_tags=["shc_definition"]),
            short("M6L2_D2", "Why can water and copper of the same mass show different temperature rises after the same energy transfer?", ["Because their specific heat capacities are different, so the same energy buys a different temperature change."], "Use material-cost language.", ["specific_heat_capacity_confusion", "same_energy_same_temp_change_confusion"], acceptance_rules=acceptance_groups(["specific heat capacity", "level cost"], ["different", "not the same"], ["temperature change", "warmth level rise"]), skill_tags=["material_compare"]),
            mcq("M6L2_D3", "If mass doubles while c and delta T stay the same, what happens to Q?", ["Q doubles", "Q halves", "Q stays the same", "Q becomes zero"], 0, "Mass is a direct multiplier in the heating rule.", ["mass_heating_confusion"], skill_tags=["equation_scale"]),
            short("M6L2_D4", "In the Level-Forge, what does Level Cost stand for?", ["It stands for specific heat capacity: the energy needed per kilogram for each degree of temperature change."], "Say both 'per kilogram' and 'per degree' if you can.", ["specific_heat_capacity_confusion"], acceptance_rules=acceptance_groups(["specific heat capacity", "level cost"], ["per kilogram", "for 1 kg"], ["per degree", "per degree c", "per temperature change"]), skill_tags=["shc_definition"]),
            mcq("M6L2_D5", "Which quantity is not part of Q = m c delta T for ordinary warming?", ["Latent heat", "Mass", "Specific heat capacity", "Temperature change"], 0, "Latent heat belongs to a state-change rule, not the ordinary warm-up rule.", ["phase_change_energy_confusion"], skill_tags=["formula_selection"]),
            short("M6L2_D6", "What do the units J/kg degree C mean for specific heat capacity?", ["They mean joules needed for 1 kilogram to change by 1 degree C."], "Translate the unit into an energy-per-mass-per-degree sentence.", ["specific_heat_capacity_confusion"], acceptance_rules=acceptance_groups(["joules", "energy"], ["1 kilogram", "per kilogram"], ["1 degree", "per degree c", "temperature change"]), skill_tags=["unit_meaning"]),
            mcq("M6L2_D7", "If Q and c stay fixed but mass gets larger, what happens to the temperature change?", ["It gets smaller", "It gets larger", "It becomes a latent heat change", "It becomes impossible"], 0, "The same energy must be shared across more material.", ["mass_heating_confusion"], skill_tags=["mass_effect"]),
            short("M6L2_D8", "A 2 kg block with c = 500 J/kg degree C warms by 3 degree C. How much energy is transferred?", ["3000 J", "3000"], "Use Q = m c delta T.", ["multi_stage_heat_calculation_confusion"], skill_tags=["heating_calculation"]),
        ],
        analogy_text="The Level-Forge warm-up rule says bigger block x higher Level Cost x bigger level rise means more Transfer Energy is needed. The formal equation Q = m c delta T simply compresses that bookkeeping into symbols.",
        commitment_prompt="If you must raise a block by more levels, or raise a bigger block, or use a higher-cost material, what happens to the Forge Ledger total?",
        micro_prompts=[
            prompt_block("Which part of the warm-up rule stands for mass?", "Build Size tells how much material has to be moved up the levels."),
            prompt_block("Which part stands for material heating difficulty?", "Level Cost is the specific heat capacity part of the rule."),
        ],
        inquiry=[
            prompt_block("Hold c and delta T steady, then double the mass. What happens to Q?", "One multiplier doubling doubles the product."),
            prompt_block("Hold mass and Q steady, then increase c. What happens to delta T?", "If the energy bill is fixed, a higher cost buys fewer degrees."),
        ],
        recon_prompts=[
            "Explain specific heat capacity in words before quoting the equation.",
            "Explain why Q = m c delta T matches the Level-Forge warm-up rule.",
        ],
        capsule_prompt="Use the formal rule without losing the meaning of each multiplier.",
        capsule_checks=[
            mcq("M6L2_C1", "Which phrase best defines c?", ["Energy needed per kilogram per degree", "Energy needed only at melting", "Stored heat inside the block", "The block's current Warmth Level"], 0, "Keep c as a per-kilogram-per-degree cost.", ["specific_heat_capacity_confusion"], skill_tags=["shc_definition"]),
            short("M6L2_C2", "Why does a larger c usually mean a smaller temperature change for the same Q and m?", ["Because the same energy must pay a higher cost per kilogram per degree, so it buys fewer degrees."], "Tie the cost idea to the smaller temperature rise.", ["specific_heat_capacity_confusion"], acceptance_rules=acceptance_groups(["same energy", "same q"], ["higher cost", "higher c", "specific heat capacity"], ["smaller temperature change", "fewer degrees", "smaller level rise"]), skill_tags=["material_compare"]),
            mcq("M6L2_C3", "Two blocks have the same mass and the same temperature rise. Which needs more energy?", ["The one with the larger c", "They always need the same energy", "The one with the smaller c", "The cooler one only"], 0, "With m and delta T fixed, the larger c multiplies Q upward.", ["specific_heat_capacity_confusion"], skill_tags=["equation_scale"]),
            short("M6L2_C4", "A 4 kg block warms more slowly than a 1 kg block when both get the same energy transfer. Why?", ["Because the larger mass needs more energy for the same temperature rise."], "Use the mass part of Q = m c delta T.", ["mass_heating_confusion"], acceptance_rules=acceptance_groups(["larger mass", "4 kg", "more material"], ["more energy needed", "same temperature rise"], ["same energy", "same transfer"]), skill_tags=["mass_effect"]),
            short("M6L2_C5", "A 3 kg block has c = 200 J/kg degree C and receives 1200 J. What is delta T?", ["2 degree C", "2"], "Rearrange delta T = Q / (m c).", ["multi_stage_heat_calculation_confusion"], acceptance_rules=acceptance_groups(["2", "2 degree c", "2 c", "2 degrees", "2 degree"]), skill_tags=["heating_calculation"]),
            mcq("M6L2_C6", "Which sentence keeps the equation meaningful?", ["Q grows when any of m, c, or delta T grows while the others stay fixed", "Q only depends on temperature", "Mass never matters in heating", "Specific heat capacity only matters during boiling"], 0, "Each multiplier matters in an ordinary temperature change.", ["mass_heating_confusion", "specific_heat_capacity_confusion"], skill_tags=["equation_scale"]),
        ],
        transfer=[
            short("M6L2_M1", "How much energy is needed to warm 5 kg of water with c = 4200 J/kg degree C by 2 degree C?", ["42000 J", "42000"], "Multiply mass, c, and delta T carefully.", ["multi_stage_heat_calculation_confusion"], skill_tags=["heating_calculation"]),
            mcq("M6L2_M2", "Two 1 kg blocks each receive 5000 J. Block A rises by more degrees than Block B. Which statement is strongest?", ["Block A has a lower specific heat capacity", "Block A must be larger", "Block B received no energy", "Temperature and energy are the same"], 0, "With equal masses and equal energy, c is the clearest difference.", ["specific_heat_capacity_confusion"], skill_tags=["material_compare"]),
            short("M6L2_M3", "Why does a larger Build Size increase the Forge Ledger bill for the same level rise?", ["Because more mass means more material must be raised through the same temperature change."], "Explain the mass multiplier in words.", ["mass_heating_confusion"], acceptance_rules=acceptance_groups(["more mass", "larger build size", "more material"], ["same temperature change", "same level rise"], ["more energy", "bigger ledger bill"]), skill_tags=["mass_effect"]),
            short("M6L2_M4", "A 2 kg metal block with c = 500 J/kg degree C receives 6000 J. What temperature rise does it get?", ["6 degree C", "6"], "Use delta T = Q / (m c).", ["multi_stage_heat_calculation_confusion"], acceptance_rules=acceptance_groups(["6", "6 degree c", "6 c", "6 degrees", "6 degree"]), skill_tags=["heating_calculation"]),
            mcq("M6L2_M5", "Which material has the higher c if equal masses receive the same energy but material X rises less in temperature than material Y?", ["Material X", "Material Y", "They must have the same c", "You can only tell the mass"], 0, "The higher-cost material shows the smaller rise for the same payment.", ["specific_heat_capacity_confusion"], skill_tags=["material_compare"]),
            short("M6L2_M6", "Why is water often called a high-Level-Cost material in this model?", ["Because it needs a large amount of energy per kilogram for each degree of temperature change."], "Translate the property into the forge language.", ["specific_heat_capacity_confusion"], acceptance_rules=acceptance_groups(["large amount of energy", "high energy"], ["per kilogram", "for 1 kg"], ["per degree", "for each degree", "temperature change"]), skill_tags=["unit_meaning"]),
            short("M6L2_M7", "A 0.5 kg block with c = 800 J/kg degree C warms by 10 degree C. Find Q.", ["4000 J", "4000"], "Apply Q = m c delta T directly.", ["multi_stage_heat_calculation_confusion"], skill_tags=["heating_calculation"]),
            mcq("M6L2_M8", "Which lesson rule matches Q = m c delta T most directly?", ["bigger block x higher Level Cost x bigger level rise = more Transfer Energy", "bigger Morph Fee x darker surface = more radiation", "more contact x less energy = more heating", "same route name = same temperature change"], 0, "The equation is the formal version of the warm-up rule.", ["specific_heat_capacity_confusion"], skill_tags=["formula_selection"]),
        ],
        contract_payload=contract(
            concept_targets=[
                "Define specific heat capacity as energy per kilogram per degree.",
                "Use Q = m c delta T quantitatively and still explain what each factor means.",
            ],
            core_concepts=[
                "Specific heat capacity tells how much energy each kilogram needs for each degree of temperature change.",
                "The same energy transfer can produce different temperature changes when mass or specific heat capacity differs.",
                "Q = m c delta T is an energy-bookkeeping rule for temperature changes that happen without melting or boiling.",
                "A correct heating calculation is strongest when the learner can explain the mass, material, and level-rise parts in words as well as symbols.",
            ],
            prerequisite_lessons=["M6_L1"],
            misconception_focus=["mass_heating_confusion", "specific_heat_capacity_confusion", "same_energy_same_temp_change_confusion", "multi_stage_heat_calculation_confusion"],
            formulas=[
                warmup_relation(),
                relation("delta T = Q / (m c)", "Temperature change can be found by dividing the transfer energy by the mass and specific heat capacity product.", ["degree C"], "Use when Q, m, and c are known and there is no state change."),
                relation("c = Q / (m delta T)", "Specific heat capacity can be found experimentally from measured energy, mass, and temperature change.", ["J/kg degree C"], "Use when the substance stays in the same state and the other three quantities are known."),
            ],
            representations=[
                representation("words", "Explain what c means before calculating."),
                representation("formula", "Use Q = m c delta T and its rearrangements."),
                representation("table", "Compare masses, materials, temperature changes, and energy bills across different runs."),
            ],
            analogy_map=forge_map("students pay the warm-up bill and compare different Level Costs"),
            worked_examples=[
                worked("How much energy is needed to warm 2 kg of water by 4 degree C if c = 4200 J/kg degree C?", ["Write Q = m c delta T.", "Substitute 2, 4200, and 4.", "Multiply to get the Forge Ledger total."], "33600 J", "The energy bill is the product of mass, specific heat capacity, and temperature change.", "This gives the formal calculator version of the warm-up rule."),
                worked("Two equal-mass blocks receive the same energy, but block A rises by fewer degrees than block B. What should you infer about c?", ["Keep the mass and Q the same first.", "Notice that the smaller temperature rise means the energy bought fewer degrees.", "Infer that block A has the larger specific heat capacity."], "Block A has the larger specific heat capacity.", "A higher c means the same payment buys fewer degrees of temperature rise.", "This is the qualitative reading behind the calculation rule."),
                worked("A learner says specific heat capacity means 'how much heat is stored inside a hot object.' How should you correct them?", ["Keep c attached to a process, not a stored amount.", "State that c is energy needed per kilogram per degree of temperature change.", "Link it to how much energy is needed for warming rather than a stored substance called heat."], "Specific heat capacity is an energy-per-kilogram-per-degree property, not a stored quantity of heat.", "The property tells you the cost of changing temperature, not how much heat an object contains.", "This protects the language distinction from Lesson 1 while formalizing the heating rule."),
            ],
            visual_assets=[visual("m6-l2-level-cost", "specific_heat_capacity", "Level Cost sets the bill", "Shows three forge blocks with the same target rise but different masses or costs so the ledger totals differ.", "Mass, Level Cost, and level rise all multiply together in the heating bill.")],
            animation_assets=[animation("m6-l2-ledger-bill", "specific_heat_capacity", "The warm-up bill grows", "Shows the Forge Ledger total rising as mass, Level Cost, or delta T increases.")],
            simulation_contract={
                "asset_id": "m6_l2_level_cost_lab",
                "concept": "specific_heat_capacity",
                "baseline_case": "Start with a 1 kg forge block, medium Level Cost, and a 5 degree target rise.",
                "focus_prompt": "How does the warm-up bill change when mass, Level Cost, or target rise changes?",
                "controls": [
                    {"variable": "mass", "label": "Build Size", "why_it_matters": "Controls how much material must be heated."},
                    {"variable": "specific_heat_capacity", "label": "Level Cost", "why_it_matters": "Controls the energy needed per kilogram per degree."},
                    {"variable": "delta_t", "label": "Target level rise", "why_it_matters": "Controls how many degrees must be bought with energy."},
                ],
                "readouts": [
                    {"label": "Forge Ledger total", "meaning": "Shows the total transferred energy required."},
                    {"label": "Energy per kilogram per degree", "meaning": "Shows what the Level Cost means in formal terms."},
                    {"label": "Predicted level rise", "meaning": "Shows delta T when the bill is fixed and the other factors change."},
                ],
                "comparison_tasks": [
                    "Double the mass while keeping c and delta T fixed.",
                    "Keep Q fixed and compare a low-cost material with a high-cost material.",
                ],
                "watch_for": "Students should not treat c as stored heat or forget that mass and temperature change are separate multipliers.",
                "takeaway": "Q = m c delta T is the Level-Forge warm-up rule written formally.",
            },
            reflection_prompts=[
                "Why is specific heat capacity best explained as energy per kilogram per degree rather than as stored heat?",
                "How does the Level-Forge warm-up rule become Q = m c delta T?",
            ],
            mastery_skills=[
                "Define specific heat capacity accurately",
                "Calculate heating energy with Q = m c delta T",
                "Rearrange the heating rule",
                "Compare materials by specific heat capacity",
                "Explain mass effects in thermal calculations",
            ],
            variation_plan={
                "diagnostic": "Rotate definitions, unit-meaning prompts, and same-energy comparisons across different materials and masses.",
                "concept_gate": "Retry with a different unknown variable or a different wording of the Level Cost meaning before repeating a stem.",
                "mastery": "Use unseen masses, materials, and rearrangements before repeating any previous heating calculation.",
            },
            scaffold_support=scaffold(
                "Q = m c delta T is just the warm-up bill: more mass, a higher Level Cost, or a larger temperature rise all increase the energy required.",
                "Say what each factor means first, then decide which quantity is unknown, and only then substitute the numbers. The physics is stronger when the learner can tell the story as well as perform the multiplication or division.",
                "If two blocks need different energy bills for the same rise, which factors might differ?",
                "Do not recite the equation as four letters only. If you forget what c means, you will not know whether the answer makes physical sense.",
                "The Level-Forge makes c feel like an energy price tag, so the learner can see why a larger price tag means fewer degrees bought by the same payment.",
                "Why does a higher Level Cost make the same energy transfer buy fewer levels?",
                extra_sections=[
                    extra_section("Units carry meaning", "J/kg degree C means joules per kilogram for each degree of temperature change."),
                    extra_section("Rearranging keeps the same story", "When delta T or c is unknown, the equation is rearranged, but the meaning of the multipliers does not change."),
                ],
            ),
            visual_clarity_checks=visual_checks("Level Cost"),
        ),
    )


def lesson_l3() -> Dict[str, Any]:
    return lesson_spec(
        lesson_id="M6_L3",
        title="Form Gates, Morph Fees, and Latent Heat",
        sim_meta=sim(
            "m6_form_gate_lab",
            "Form Gate lab",
            "Watch energy continue to enter while the Warmth Level plateaus at a Form Gate.",
            [
                "Heat a forge block until it reaches a Form Gate.",
                "Keep adding Transfer Energy and watch the Morph Fee meter fill while the Warmth Level stays flat.",
                "Compare different masses to see how the total Morph Fee changes.",
            ],
            [
                "Explain latent heat as energy used for a state change without a temperature rise.",
                "Calculate state-change energy with Q = m L.",
            ],
            ["mass", "latent_heat", "state_gate", "transfer_energy"],
            "Use the lab to turn a temperature plateau into an energy-destination story instead of a contradiction.",
        ),
        diagnostic=[
            mcq("M6L3_D1", "A heating graph reaches melting and then stays flat while energy still enters. What is the strongest explanation?", ["Energy is paying the Morph Fee for a state change", "The heater has switched off", "Temperature and energy can never be linked", "The mass has disappeared"], 0, "A plateau at a Form Gate means energy is going into the state change.", ["latent_heat_temperature_rise_confusion", "phase_change_energy_confusion"], skill_tags=["plateau_interpretation"]),
            mcq("M6L3_D2", "In the Level-Forge, a Form Gate stands for...", ["the temperature where a state change begins", "the total heat stored inside a block", "the best conduction route", "the block's mass"], 0, "A Form Gate is a state-change temperature boundary.", ["phase_change_energy_confusion"], skill_tags=["gate_meaning"]),
            short("M6L3_D3", "Why can Transfer Energy enter while the Warmth Level stays constant at a Form Gate?", ["Because the energy is being used for the state change itself rather than for a temperature rise."], "Name the state-change fee rather than extra temperature rise.", ["latent_heat_temperature_rise_confusion", "phase_change_energy_confusion"], acceptance_rules=acceptance_groups(["energy", "transfer energy"], ["state change", "morph fee", "latent heat"], ["temperature stays constant", "warmth level stays flat", "no temperature rise"]), skill_tags=["latent_definition"]),
            mcq("M6L3_D4", "What does the Morph Fee stand for?", ["Specific latent heat", "Specific heat capacity", "Thermal conductivity", "Temperature difference"], 0, "Morph Fee is the per-kilogram state-change energy.", ["phase_change_energy_confusion"], skill_tags=["gate_meaning"]),
            short("M6L3_D5", "How much energy is needed to melt 2 kg of a material with L = 250000 J/kg?", ["500000 J", "500000"], "Use Q = m L.", ["multi_stage_heat_calculation_confusion"], skill_tags=["latent_calculation"]),
            mcq("M6L3_D6", "If the mass doubles while L stays the same, what happens to the Morph Fee total?", ["It doubles", "It halves", "It stays the same", "It becomes a temperature rise"], 0, "Mass is the direct multiplier in Q = m L.", ["phase_change_energy_confusion"], skill_tags=["latent_scale"]),
            short("M6L3_D7", "What is the difference between Level Cost and Morph Fee?", ["Level Cost is for changing temperature, while Morph Fee is for changing state at constant temperature."], "Separate temperature-change cost from state-change cost.", ["specific_heat_capacity_confusion", "phase_change_energy_confusion"], acceptance_rules=acceptance_groups(["level cost", "specific heat capacity"], ["morph fee", "latent heat"], ["temperature change", "change temperature"], ["state change", "constant temperature", "form change"]), skill_tags=["formula_selection"]),
            mcq("M6L3_D8", "Which statement is strongest during boiling at constant temperature?", ["Energy is still being transferred in even though the temperature stays constant", "No energy enters because the temperature is flat", "The liquid's mass must be zero", "Specific heat capacity becomes the same as latent heat"], 0, "A flat temperature does not mean zero transfer.", ["latent_heat_temperature_rise_confusion"], skill_tags=["plateau_interpretation"]),
        ],
        analogy_text="At a Form Gate, the block has reached the temperature where a state change begins. Extra Transfer Energy must now pay the Morph Fee, so the Warmth Level can stay flat while the form changes.",
        commitment_prompt="If the Warmth Level stops rising but the Forge Ledger keeps increasing, what job is the energy doing now?",
        micro_prompts=[
            prompt_block("What does a Form Gate stand for in thermal physics?", "It is the temperature where the state starts to change."),
            prompt_block("What does the Morph Fee meter represent?", "It tracks the latent-heat payment during melting or boiling."),
        ],
        inquiry=[
            prompt_block("Heat the same mass to a Form Gate and keep adding energy. What happens to the Warmth Level?", "The level can stay flat while the state changes."),
            prompt_block("Double the mass at the same gate. What happens to the total Morph Fee?", "More mass means a larger total latent-energy bill."),
        ],
        recon_prompts=[
            "Explain why a temperature plateau does not mean energy transfer has stopped.",
            "Explain the difference between a Level Cost payment and a Morph Fee payment.",
        ],
        capsule_prompt="Use the Form Gate to explain constant-temperature state changes.",
        capsule_checks=[
            mcq("M6L3_C1", "Which statement best describes latent heat?", ["Energy for changing state without a temperature rise", "Energy stored only in hot objects", "A route for convection only", "The same as specific heat capacity"], 0, "Latent heat is a state-change energy idea.", ["phase_change_energy_confusion"], skill_tags=["latent_definition"]),
            short("M6L3_C2", "Why can the Warmth Level stay flat during melting even though the heater is still on?", ["Because the added energy is being used to change the state instead of raising the temperature."], "Say what the energy is paying for.", ["latent_heat_temperature_rise_confusion"], acceptance_rules=acceptance_groups(["energy", "added energy", "transfer energy"], ["state change", "morph fee", "latent heat"], ["temperature stays constant", "warmth level stays flat"]), skill_tags=["plateau_interpretation"]),
            mcq("M6L3_C3", "A bigger mass of ice at 0 degree C needs a bigger total energy to melt because...", ["Q = m L, so the mass multiplies the fee", "temperature must rise first", "latent heat is a temperature reading", "conduction doubles automatically"], 0, "Mass directly scales the total latent-energy bill.", ["phase_change_energy_confusion"], skill_tags=["latent_scale"]),
            short("M6L3_C4", "How much energy is needed to boil 0.5 kg of a liquid with L = 400000 J/kg?", ["200000 J", "200000"], "Use Q = m L.", ["multi_stage_heat_calculation_confusion"], skill_tags=["latent_calculation"]),
            mcq("M6L3_C5", "Which pair is matched correctly?", ["Level Cost -> temperature change, Morph Fee -> state change", "Level Cost -> boiling point, Morph Fee -> mass", "Level Cost -> radiation, Morph Fee -> conduction", "Level Cost -> mass, Morph Fee -> temperature"], 0, "Keep ordinary warming and state change as separate costs.", ["phase_change_energy_confusion", "specific_heat_capacity_confusion"], skill_tags=["formula_selection"]),
            mcq("M6L3_C6", "A learner says 'if temperature is flat, no energy is entering.' Which response is strongest?", ["That is wrong because state change can absorb energy at constant temperature", "That is right because flat means zero transfer", "That is right because all heating must raise temperature", "That is right because latent heat means zero energy"], 0, "A plateau is a different energy destination, not a zero-energy stage.", ["latent_heat_temperature_rise_confusion"], skill_tags=["plateau_interpretation"]),
        ],
        transfer=[
            short("M6L3_M1", "How much energy is needed to melt 0.25 kg of a solid with L = 120000 J/kg?", ["30000 J", "30000"], "Use Q = m L carefully.", ["multi_stage_heat_calculation_confusion"], skill_tags=["latent_calculation"]),
            mcq("M6L3_M2", "Which statement best explains a flat section on a heating graph at boiling?", ["Energy is still entering, but it is changing state rather than raising temperature", "The energy transfer has stopped completely", "The mass is becoming zero", "Specific heat capacity has disappeared"], 0, "Keep the state-change payment visible.", ["latent_heat_temperature_rise_confusion"], skill_tags=["plateau_interpretation"]),
            short("M6L3_M3", "Why is 'temperature must always rise when energy enters' too weak?", ["Because at a phase-change temperature the energy can be used for the state change without increasing the temperature."], "Connect added energy to the state change.", ["latent_heat_temperature_rise_confusion"], acceptance_rules=acceptance_groups(["energy", "added energy"], ["phase change", "state change", "latent heat"], ["without increasing temperature", "constant temperature", "warmth level stays flat"]), skill_tags=["latent_definition"]),
            mcq("M6L3_M4", "Which quantity would make the total energy to melt a sample larger if the substance stays the same?", ["Larger mass", "Lower initial temperature only", "A shinier surface", "A shorter wire"], 0, "For pure melting at one gate, Q = m L.", ["phase_change_energy_confusion"], skill_tags=["latent_scale"]),
            short("M6L3_M5", "A 3 kg sample has L = 80000 J/kg. Find the total state-change energy.", ["240000 J", "240000"], "Multiply mass by latent heat.", ["multi_stage_heat_calculation_confusion"], skill_tags=["latent_calculation"]),
            short("M6L3_M6", "How would you explain the Morph Fee to a classmate?", ["It is the extra energy per kilogram needed to change state while the temperature stays constant."], "Include per kilogram and constant temperature.", ["phase_change_energy_confusion"], acceptance_rules=acceptance_groups(["extra energy", "energy needed"], ["per kilogram", "for each kilogram"], ["change state", "phase change"], ["temperature stays constant", "no temperature rise"]), skill_tags=["gate_meaning"]),
            mcq("M6L3_M7", "Which lesson move is strongest before choosing Q = m L?", ["Check that the stage is a state change at constant temperature", "Look only at the route", "Ignore the mass", "Assume temperature must rise"], 0, "Choose the latent-heat rule only when the stage is a constant-temperature state change.", ["phase_change_energy_confusion"], skill_tags=["formula_selection"]),
            mcq("M6L3_M8", "Why does a 2 kg block need twice the Morph Fee of a 1 kg block if they are the same material and same state change?", ["Because the state-change energy is proportional to mass", "Because the larger block must have a higher temperature", "Because latent heat is a route name", "Because the warmer block has more stored heat"], 0, "Mass scales the total fee directly.", ["phase_change_energy_confusion"], skill_tags=["latent_scale"]),
        ],
        contract_payload=contract(
            concept_targets=[
                "Explain latent heat as a constant-temperature state-change payment.",
                "Use Q = m L and explain when that rule applies.",
            ],
            core_concepts=[
                "A Form Gate is the temperature where a state change begins.",
                "At a state-change temperature, added energy can change the form without increasing the temperature.",
                "Specific latent heat is the energy needed per kilogram for the state change itself.",
                "Q = m L is a stage-specific ledger rule that applies during melting or boiling rather than during ordinary warming.",
            ],
            prerequisite_lessons=["M6_L1", "M6_L2"],
            misconception_focus=["latent_heat_temperature_rise_confusion", "phase_change_energy_confusion", "multi_stage_heat_calculation_confusion", "specific_heat_capacity_confusion"],
            formulas=[latent_relation(), ledger_relation()],
            representations=[
                representation("words", "Explain why temperature can stay constant while energy still enters."),
                representation("graph", "Use a heating plateau to show constant-temperature energy transfer."),
                representation("formula", "Use Q = m L for the state-change stage."),
            ],
            analogy_map=forge_map("students reach a Form Gate and start paying the Morph Fee"),
            worked_examples=[
                worked("How much energy is needed to melt 0.8 kg of ice if L = 334000 J/kg?", ["Write Q = m L.", "Substitute 0.8 and 334000.", "Multiply to find the total Morph Fee."], "267200 J", "The total state-change energy is mass times specific latent heat.", "This turns the Form Gate story into a quantitative rule."),
                worked("A learner says a flat melting section means the heater has stopped working. How should the model correct this?", ["Keep the heater on in the story.", "Redirect the incoming energy to the Morph Fee instead of temperature rise.", "State that the form is changing while the temperature stays constant."], "The heater can still be transferring energy; the energy is being used for the state change.", "The plateau shows a different energy destination, not zero energy transfer.", "This directly addresses the flat-graph misconception."),
                worked("Why is Level Cost not the same as Morph Fee?", ["Tie Level Cost to temperature change first.", "Tie Morph Fee to changing state at the gate.", "State that one pays for degrees while the other pays for the form change."], "Level Cost is for temperature change; Morph Fee is for state change at constant temperature.", "The two rules answer different stages of the thermal mission.", "This prevents students from swapping Q = m c delta T and Q = m L blindly."),
            ],
            visual_assets=[visual("m6-l3-form-gate", "latent_heat", "The Form Gate plateau", "Shows energy continuing to enter while the Warmth Level stays flat at a state-change gate.", "A flat temperature does not mean zero energy transfer; it means the energy is paying the Morph Fee.")],
            animation_assets=[animation("m6-l3-plateau-fee", "latent_heat", "Paying the Morph Fee", "Shows the Warmth Level flattening while the Morph Fee meter fills during a state change.")],
            simulation_contract={
                "asset_id": "m6_l3_form_gate_lab",
                "concept": "latent_heat",
                "baseline_case": "Start heating a forge block until it reaches a Form Gate, then continue the same energy input.",
                "focus_prompt": "Why can the Forge Ledger keep rising while the Warmth Level stays flat at the gate?",
                "controls": [
                    {"variable": "mass", "label": "Build Size", "why_it_matters": "Controls the total Morph Fee for the sample."},
                    {"variable": "latent_heat", "label": "Morph Fee rate", "why_it_matters": "Controls the energy needed per kilogram for the state change."},
                    {"variable": "transfer_energy", "label": "Energy input", "why_it_matters": "Shows that energy keeps entering through the plateau stage."},
                ],
                "readouts": [
                    {"label": "Warmth Level", "meaning": "Shows when the temperature has reached the Form Gate."},
                    {"label": "Morph Fee meter", "meaning": "Shows how much of the state-change payment has been covered."},
                    {"label": "Forge Ledger total", "meaning": "Shows that the energy transfer continues through the plateau."},
                ],
                "comparison_tasks": [
                    "Keep the same material and compare a small mass with a large mass at the Form Gate.",
                    "Compare a case where the energy is still warming the block with one where the energy is paying the Morph Fee.",
                ],
                "watch_for": "Students should not claim that a flat temperature means the energy transfer has stopped.",
                "takeaway": "Latent heat is the state-change payment that can absorb energy while the temperature stays constant.",
            },
            reflection_prompts=[
                "Why can a heating graph show a flat section even though the heater is still transferring energy?",
                "How is the Morph Fee different from the Level Cost?",
            ],
            mastery_skills=[
                "Interpret heating plateaus",
                "Explain latent heat conceptually",
                "Calculate with Q = m L",
                "Distinguish temperature change from state change",
                "Choose the correct thermal stage rule",
            ],
            variation_plan={
                "diagnostic": "Rotate melting and boiling contexts, graph readings, and language traps about flat temperature stages.",
                "concept_gate": "Retry with a different state-change example or a different Morph Fee size before reusing a previous stem.",
                "mastery": "Use unseen masses, latent heats, and plateau interpretations before repeating any earlier state-change prompt.",
            },
            scaffold_support=scaffold(
                "At a Form Gate, added energy can go into the state change itself, so the temperature can stay constant while the total energy transfer keeps increasing.",
                "Check first whether the stage is ordinary warming or a state change. If the temperature is flat at a melting or boiling point, direct the energy to the Morph Fee and use Q = m L.",
                "What clue tells you the stage is paying a Morph Fee rather than buying more temperature rise?",
                "Do not assume that every energy input must raise the temperature. Flat temperature at a Form Gate is still a real energy-transfer stage.",
                "The Level-Forge makes latent heat visible as a gate fee, so the learner can see why the ledger climbs even when the Warmth Level pauses.",
                "Why can the ledger climb while the Warmth Level stays flat?",
                extra_sections=[
                    extra_section("Flat does not mean off", "A heating plateau means energy is being redirected into the state change, not that the heater has stopped."),
                    extra_section("Choose the stage rule first", "Use Q = m c delta T for ordinary warming and Q = m L for the state-change stage."),
                ],
            ),
            visual_clarity_checks=visual_checks("Form Gate"),
        ),
    )


def lesson_l4() -> Dict[str, Any]:
    return lesson_spec(
        lesson_id="M6_L4",
        title="Touch Relay and Conduction",
        sim_meta=sim(
            "m6_touch_relay_lab",
            "Touch Relay lab",
            "Watch thermal energy pass through direct contact without the whole solid moving.",
            [
                "Touch a hot block to one end of a relay chain.",
                "Compare a metal chain with an insulating chain.",
                "Use the far-end Warmth Level to explain how energy crossed the material.",
            ],
            [
                "Explain conduction as energy transfer by direct contact.",
                "Explain why metals conduct well without saying the whole solid flows.",
            ],
            ["conductivity", "contact_path", "temperature_difference", "far_end_level"],
            "Use the relay chain to show contact-based transfer through a solid path.",
        ),
        diagnostic=[
            mcq("M6L4_D1", "Touch Relay stands for which transfer route?", ["Conduction", "Convection", "Radiation", "Evaporation"], 0, "Touch Relay needs direct contact.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            mcq("M6L4_D2", "Which statement best matches conduction in a metal spoon handle?", ["Energy is passed along through contact, with electrons helping in metals", "The whole metal flows from the hot end to the cool end", "Heat rises through empty space only", "Warm air currents carry the spoon"], 0, "In metals, electrons help the contact-based relay.", ["conduction_particle_flow_confusion", "metal_conduction_reason_confusion"], skill_tags=["mechanism_explanation"]),
            short("M6L4_D3", "Why is 'the solid moves along the rod' a weak conduction explanation?", ["Because conduction passes energy through the material by contact without the whole solid flowing from one end to the other."], "Separate energy transfer from bulk movement.", ["conduction_particle_flow_confusion"], acceptance_rules=acceptance_groups(["energy transferred", "passed along", "contact"], ["without the whole solid moving", "not bulk movement", "solid does not flow"]), skill_tags=["mechanism_explanation"]),
            mcq("M6L4_D4", "Why do metals usually conduct thermal energy well?", ["Their free electrons help carry energy through the metal", "They always have higher temperature", "They create convection currents inside solids", "Radiation cannot leave them"], 0, "Metals have an extra helper for the relay.", ["metal_conduction_reason_confusion"], skill_tags=["metal_explanation"]),
            mcq("M6L4_D5", "Which situation is conduction rather than convection or radiation?", ["A pan handle warming from the hot pan", "Warm air rising above a heater", "Sunlight warming a satellite", "Smoke circulating in a room"], 0, "Look for direct contact through a solid path.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            short("M6L4_D6", "Why is foam or plastic useful as insulation in many cases?", ["Because it is a poor conductor, so it slows the Touch Relay of thermal energy."], "Name the slower relay rather than only saying it is 'cold'.", ["transfer_route_mixing_confusion"], acceptance_rules=acceptance_groups(["poor conductor", "insulator"], ["slows", "reduces"], ["conduction", "touch relay", "thermal energy transfer"]), skill_tags=["insulation_reasoning"]),
            mcq("M6L4_D7", "If two metal blocks are separated by a vacuum gap, which claim is strongest?", ["Conduction cannot cross the gap because direct contact is missing", "Conduction becomes stronger because there is less matter", "Convection starts inside the solid", "The blocks must have the same temperature"], 0, "Touch Relay needs contact.", ["conduction_particle_flow_confusion", "transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            mcq("M6L4_D8", "A colder far end of a rod later becomes warmer. What is the best explanation?", ["Energy has been passed along the rod from the hot end", "The cold end created its own heat", "The rod's mass changed first", "Only radiation could do that"], 0, "Conduction can spread thermal energy through the solid.", ["conduction_particle_flow_confusion"], skill_tags=["mechanism_explanation"]),
        ],
        analogy_text="Touch Relay passes Transfer Energy from block to block through direct contact. The solid path stays in place while the relay carries energy from the hotter end toward the cooler end. In metals, free electrons help the relay run faster.",
        commitment_prompt="If the solid path does not move as a whole, how can the far end still warm up?",
        micro_prompts=[
            prompt_block("What ingredient must Touch Relay have?", "The route only works when direct contact exists."),
            prompt_block("Why are metals strong Touch Relay materials?", "Remember the extra help from free electrons."),
        ],
        inquiry=[
            prompt_block("Compare a metal bar and an insulating bar with the same starting temperatures. Which far end warms faster?", "A stronger conductor relays energy more quickly."),
            prompt_block("Break the contact path with a gap. What happens to Touch Relay?", "Without contact, conduction cannot bridge the gap."),
        ],
        recon_prompts=[
            "Explain conduction in a solid without saying the solid itself flows from one end to the other.",
            "Explain why metals usually conduct thermal energy better than many other solids.",
        ],
        capsule_prompt="Keep contact-based transfer separate from bulk movement and from waves.",
        capsule_checks=[
            mcq("M6L4_C1", "Which sentence best defines conduction?", ["Energy transfer through direct contact", "Energy transfer by moving fluid regions", "Energy transfer by electromagnetic waves only", "Energy transfer only during boiling"], 0, "Contact is the defining clue.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            short("M6L4_C2", "Why does a metal spoon handle warm when its far end is in soup?", ["Because conduction passes energy along the spoon by contact, with electrons helping in the metal."], "Use contact and metal-electron language together.", ["conduction_particle_flow_confusion", "metal_conduction_reason_confusion"], acceptance_rules=acceptance_groups(["conduction", "contact", "passed along"], ["electrons", "free electrons", "metal"]), skill_tags=["metal_explanation"]),
            mcq("M6L4_C3", "Which route is ruled out in an isolated solid bar?", ["Convection", "Conduction", "Cooling", "Temperature change"], 0, "A solid bar does not set up convection currents through bulk fluid motion.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            short("M6L4_C4", "Why is saying 'hot particles travel across the solid' weaker than the relay model?", ["Because conduction is energy passed through contact in the solid, not the whole material flowing across."], "Reject bulk travel language.", ["conduction_particle_flow_confusion"], acceptance_rules=acceptance_groups(["energy passed", "energy transferred", "contact"], ["not whole material moving", "not bulk flow", "solid does not flow"]), skill_tags=["mechanism_explanation"]),
            mcq("M6L4_C5", "Why is a wooden handle often safer than a metal handle?", ["Wood is a poorer conductor, so less energy is relayed quickly to the hand", "Wood has no temperature", "Wood causes convection inside the solid", "Wood makes radiation impossible"], 0, "Poor conduction helps protect the hand.", ["transfer_route_mixing_confusion"], skill_tags=["insulation_reasoning"]),
            mcq("M6L4_C6", "Which statement is strongest about metals?", ["They conduct well partly because electrons help transfer thermal energy", "They conduct well because the whole solid drifts toward the cold end", "They only transfer energy by radiation", "They have no contact route"], 0, "Metals add electron help to the contact relay.", ["metal_conduction_reason_confusion"], skill_tags=["metal_explanation"]),
        ],
        transfer=[
            mcq("M6L4_M1", "Which kitchen example is mostly conduction?", ["A metal pan handle becoming hot", "Warm air circulating above the pan", "Sunlight crossing a window", "Steam rising toward the ceiling"], 0, "Look for the direct solid contact route.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            short("M6L4_M2", "Why is a double-glazed window useful for reducing conduction?", ["Because it breaks or weakens the direct contact path for thermal energy transfer."], "Conduction falls when the contact pathway is weakened.", ["conduction_particle_flow_confusion"], acceptance_rules=acceptance_groups(["breaks", "reduces", "weakens"], ["contact path", "direct contact"], ["conduction", "thermal energy transfer"]), skill_tags=["insulation_reasoning"]),
            mcq("M6L4_M3", "A rod is heated at one end and later the far end warms. Which explanation is best?", ["Energy was relayed through the rod by contact", "The far end created its own energy", "Warm air carried the rod's atoms along", "The solid started convecting"], 0, "The energy passes through the solid path.", ["conduction_particle_flow_confusion"], skill_tags=["mechanism_explanation"]),
            short("M6L4_M4", "Why do metals often feel colder than wood at the same room temperature?", ["Because metals conduct thermal energy away from the hand faster, so the hand loses energy more quickly."], "The temperature can match while the transfer rate differs.", ["metal_conduction_reason_confusion", "heat_temperature_confusion"], acceptance_rules=acceptance_groups(["conduct", "conduction"], ["away from the hand", "faster"], ["same temperature", "room temperature"]), skill_tags=["metal_explanation"]),
            mcq("M6L4_M5", "Which change would most directly reduce Touch Relay through a cooking utensil handle?", ["Use a poorer conductor for the handle", "Paint the handle red", "Increase the air currents in the room", "Move the handle closer to sunlight"], 0, "Change the material pathway, not the color name.", ["transfer_route_mixing_confusion"], skill_tags=["insulation_reasoning"]),
            short("M6L4_M6", "Why can conduction not be the route from the Sun to Earth?", ["Because conduction needs direct contact, and space between them is essentially a vacuum gap."], "Use the missing-contact idea.", ["transfer_route_mixing_confusion", "radiation_medium_confusion"], acceptance_rules=acceptance_groups(["direct contact", "contact"], ["vacuum", "gap", "empty space"], ["cannot", "not conduction"]), skill_tags=["route_identification"]),
            mcq("M6L4_M7", "Which statement is strongest about a metal rod compared with a plastic rod in the same setup?", ["The metal usually relays thermal energy more quickly", "The plastic always starts hotter", "The metal causes convection through the solid", "The plastic has no mass"], 0, "The difference is conductivity, not whether mass exists.", ["metal_conduction_reason_confusion"], skill_tags=["metal_explanation"]),
            mcq("M6L4_M8", "What should you say first before deciding the route is conduction?", ["There is a direct contact path from hot region to cooler region", "The object is black", "The fluid rises", "The energy crosses a vacuum"], 0, "Contact is the first check for conduction.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
        ],
        contract_payload=contract(
            concept_targets=[
                "Explain conduction as contact-based transfer rather than bulk movement.",
                "Explain why metals conduct well and why insulators slow the relay.",
            ],
            core_concepts=[
                "Conduction transfers thermal energy through direct contact from hotter regions toward cooler regions.",
                "A solid can conduct without the whole solid moving from place to place.",
                "Metals conduct well partly because free electrons help transfer thermal energy efficiently.",
                "Insulators slow the Touch Relay by making the contact route less effective.",
            ],
            prerequisite_lessons=["M6_L1", "M6_L2"],
            misconception_focus=["conduction_particle_flow_confusion", "metal_conduction_reason_confusion", "transfer_route_mixing_confusion", "heat_temperature_confusion"],
            formulas=[warmup_relation()],
            representations=[
                representation("words", "State the conduction mechanism without using bulk-flow language."),
                representation("diagram", "Show a hot end, a cold end, and the contact relay through the solid."),
                representation("model", "Use the Touch Relay chain to track thermal energy step by step."),
            ],
            analogy_map=forge_map("students watch Touch Relay pass energy through a contact chain"),
            worked_examples=[
                worked("A saucepan handle becomes hot even though the flame is only under the base. How should the model explain that?", ["Identify the metal handle as a continuous contact path.", "Relay energy from the hot end toward the cooler end.", "Note that the whole solid has not flowed; the energy has been passed through it."], "The handle warms by conduction through the metal.", "Conduction uses direct contact through the solid path, and metals conduct especially well.", "This connects everyday equipment to the mechanism instead of to vague 'heat travels' language."),
                worked("A learner says conduction means hot particles physically travel across the bar. How should the lesson correct that?", ["Keep the solid bar in place.", "Describe energy being passed along through contact instead of the whole solid moving.", "Add that electrons help in metals but do not mean the solid itself flows."], "Conduction is an energy-transfer relay, not bulk motion of the solid.", "The mechanism is contact-based energy transfer through the material.", "This blocks a persistent misconception about solids behaving like fluids."),
                worked("Why is a wooden pan handle often safer than a metal one?", ["Compare the two materials as relay paths.", "State that wood is a poorer conductor.", "Conclude that thermal energy reaches the hand less quickly through the wooden handle."], "The wooden handle relays thermal energy more slowly.", "A poorer conductor reduces the rate of Touch Relay to the hand.", "This keeps the material property visible in a practical safety context."),
            ],
            visual_assets=[visual("m6-l4-touch-relay", "conduction", "Touch Relay through a solid", "Shows thermal energy passing through a contact chain without the whole solid moving.", "Conduction uses contact through the material; in metals, electrons help the relay run faster.")],
            animation_assets=[animation("m6-l4-relay-chain", "conduction", "The relay reaches the far end", "Shows a hot end driving thermal energy through a metal chain until the far end warms.")],
            simulation_contract={
                "asset_id": "m6_l4_touch_relay_lab",
                "concept": "conduction",
                "baseline_case": "Start with one hot end and one cool end connected by a solid relay chain.",
                "focus_prompt": "How does energy reach the far end when the solid path stays in place?",
                "controls": [
                    {"variable": "conductivity", "label": "Material relay strength", "why_it_matters": "Changes how effective the contact path is."},
                    {"variable": "temperature_difference", "label": "End-to-end temperature difference", "why_it_matters": "Changes the drive for thermal transfer."},
                    {"variable": "contact_path", "label": "Contact path quality", "why_it_matters": "Shows why a gap or insulation weakens conduction."},
                ],
                "readouts": [
                    {"label": "Far-end Warmth Level", "meaning": "Shows how strongly the relay has reached the cooler end."},
                    {"label": "Relay rate", "meaning": "Shows how quickly energy is being passed through the path."},
                    {"label": "Path status", "meaning": "Shows whether the contact route is continuous or broken."},
                ],
                "comparison_tasks": [
                    "Compare a metal relay chain with an insulating chain.",
                    "Compare an unbroken contact path with a path that contains a gap or insulated section.",
                ],
                "watch_for": "Students should not explain conduction as if the solid itself flows from hot to cold.",
                "takeaway": "Conduction is a contact relay through the material, and metals conduct especially well because electrons help the transfer.",
            },
            reflection_prompts=[
                "How does Touch Relay explain conduction without saying the whole solid flows?",
                "Why are metals often better conductors than wood or foam?",
            ],
            mastery_skills=[
                "Identify conduction contexts",
                "Explain conduction mechanisms",
                "Explain why metals conduct well",
                "Explain insulation in contact pathways",
                "Separate conduction from convection and radiation",
            ],
            variation_plan={
                "diagnostic": "Rotate kitchen, building, and metal-vs-insulator contexts while keeping the contact-route idea central.",
                "concept_gate": "Retry with a different material comparison or a different wording of the no-bulk-flow correction before repeating a stem.",
                "mastery": "Use unseen practical contexts and route-mixing traps before repeating any previous conduction question.",
            },
            scaffold_support=scaffold(
                "Conduction transfers thermal energy through direct contact. The solid path can stay in place while energy is passed along from hotter regions toward cooler regions.",
                "Check first for contact. Then decide whether the material is a strong or weak conductor, and explain the result without saying the whole solid flows.",
                "What must be present before Touch Relay can operate?",
                "Do not confuse conduction with the whole solid moving, and do not switch to convection language inside a solid bar.",
                "The Level-Forge makes conduction feel like a hand-to-hand relay along a contact chain, so the learner can see why the path matters more than the path's name.",
                "Why does breaking the contact path weaken or stop Touch Relay?",
                extra_sections=[
                    extra_section("Metals have an extra helper", "In metals, electrons help carry thermal energy, which is why metal pathways often relay energy quickly."),
                    extra_section("Insulators change the pathway", "Foam, wood, and trapped air help because they make the conduction route less effective."),
                ],
            ),
            visual_clarity_checks=visual_checks("Touch Relay"),
        ),
    )


def lesson_l5() -> Dict[str, Any]:
    return lesson_spec(
        lesson_id="M6_L5",
        title="Carrier Loop and Convection",
        sim_meta=sim(
            "m6_carrier_loop_lab",
            "Carrier Loop lab",
            "See warm fluid regions rise and cooler regions sink as a convection current forms.",
            [
                "Heat the fluid from one side or from below.",
                "Track a warm parcel and a cool parcel around the loop.",
                "Compare a fluid setup with a solid setup where no Carrier Loop can form.",
            ],
            [
                "Explain convection as thermal transfer by moving fluid regions.",
                "Explain why 'heat rises' is weaker than a full convection-current story.",
            ],
            ["heating_position", "fluid_motion", "parcel_density", "loop_strength"],
            "Use moving parcels to show why convection belongs to liquids and gases rather than solids.",
        ),
        diagnostic=[
            mcq("M6L5_D1", "Carrier Loop stands for which transfer route?", ["Convection", "Conduction", "Radiation", "Refraction"], 0, "Carrier Loop needs moving fluid regions.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            mcq("M6L5_D2", "Which statement best explains why a warm fluid parcel rises?", ["It expands, becomes less dense, and is pushed upward by the surrounding cooler fluid", "Heat itself floats upward like a substance", "The parcel has no mass once heated", "Conduction has stopped"], 0, "Convection is bulk fluid motion caused by density differences.", ["convection_heat_rises_confusion"], skill_tags=["mechanism_explanation"]),
            short("M6L5_D3", "Why is 'heat rises' weaker than the Carrier Loop explanation?", ["Because it is the warmer fluid region that rises while cooler fluid moves in to replace it."], "Talk about moving fluid, not heat as a floating substance.", ["convection_heat_rises_confusion"], acceptance_rules=acceptance_groups(["warmer fluid", "warm fluid region", "parcel"], ["rises", "moves up"], ["cooler fluid", "cool fluid"], ["moves in", "replaces it", "sinks"]), skill_tags=["mechanism_explanation"]),
            mcq("M6L5_D4", "Why can convection happen in water but not inside a fixed solid block?", ["Convection needs bulk motion of the fluid", "Convection only works above 100 degree C", "Solids have no temperature", "Radiation blocks it"], 0, "Carrier Loop needs a moving fluid.", ["transfer_route_mixing_confusion"], skill_tags=["medium_reasoning"]),
            mcq("M6L5_D5", "Which sequence best matches a convection current near a heater?", ["Warm parcel rises, cool parcel sinks, and a loop forms", "Hot particles travel through the solid wall", "Energy crosses the room only by radiation", "The same air stays fixed in place"], 0, "Look for the loop of moving fluid regions.", ["convection_heat_rises_confusion"], skill_tags=["current_sequence"]),
            short("M6L5_D6", "Why can a radiator warm a room efficiently when placed low down?", ["Because it warms nearby air, which rises while cooler air sinks toward the radiator and sets up a convection current."], "Use the loop language instead of 'heat rises' alone.", ["convection_heat_rises_confusion"], acceptance_rules=acceptance_groups(["warms air", "warm air"], ["rises", "moves up"], ["cooler air", "cool air"], ["sinks", "moves in", "convection current"]), skill_tags=["current_sequence"]),
            mcq("M6L5_D7", "Which context is mostly convection?", ["Boiling water circulating in a pot", "A metal spoon handle warming", "Sunlight crossing space", "A hot plate touching a pan base"], 0, "Moving liquid regions are the key clue.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            mcq("M6L5_D8", "A learner says convection is just conduction in a fluid. Which reply is strongest?", ["Convection involves bulk fluid motion carrying energy around", "That is always correct", "Convection needs a vacuum", "Convection never changes density"], 0, "Convection is a moving-fluid route, not just static contact.", ["convection_heat_rises_confusion", "transfer_route_mixing_confusion"], skill_tags=["medium_reasoning"]),
        ],
        analogy_text="Carrier Loop sends Transfer Energy by moving warm fluid regions around the forge space. When a parcel warms, it expands and becomes less dense, so it rises while cooler, denser fluid moves in underneath to complete the loop.",
        commitment_prompt="If a heated parcel rises, what must happen to the surrounding cooler fluid for the loop to continue?",
        micro_prompts=[
            prompt_block("What has to be able to move for Carrier Loop to work?", "Only a fluid can set up the full circulation."),
            prompt_block("Why does a warm parcel rise?", "Tie the motion to expansion and density change."),
        ],
        inquiry=[
            prompt_block("Heat the bottom of a fluid and follow one warm parcel. What path does it trace?", "Look for a loop, not a one-way climb of 'heat'."),
            prompt_block("Compare a liquid setup with a solid setup. Which one can form a Carrier Loop?", "Only the fluid can move as a bulk region."),
        ],
        recon_prompts=[
            "Explain why 'heat rises' is too weak as a full convection explanation.",
            "Explain why convection belongs to liquids and gases rather than solids.",
        ],
        capsule_prompt="Keep the moving-fluid story visible in every convection explanation.",
        capsule_checks=[
            mcq("M6L5_C1", "Which phrase best defines convection?", ["Thermal energy transfer by moving fluid regions", "Thermal energy transfer through direct contact only", "Thermal energy transfer by electromagnetic waves only", "Thermal energy transfer only at melting"], 0, "Bulk motion of the fluid is the defining feature.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            short("M6L5_C2", "Why does warm fluid rise in a Carrier Loop?", ["Because heating makes it expand and become less dense than the surrounding cooler fluid."], "Use expansion and density together.", ["convection_heat_rises_confusion"], acceptance_rules=acceptance_groups(["expand", "expands"], ["less dense", "lower density"], ["cooler fluid", "surrounding fluid"]), skill_tags=["mechanism_explanation"]),
            mcq("M6L5_C3", "Which statement is strongest about solids?", ["They cannot form convection currents because they do not flow as bulk fluid regions", "They conduct only by radiation", "They always have lower temperature", "They have no particles"], 0, "A fixed solid cannot set up the carrier loop.", ["transfer_route_mixing_confusion"], skill_tags=["medium_reasoning"]),
            short("M6L5_C4", "What is missing from the sentence 'heat rises'?", ["It misses that warm fluid rises while cooler fluid sinks or moves in to complete the convection current."], "A full loop needs both up and down movement.", ["convection_heat_rises_confusion"], acceptance_rules=acceptance_groups(["warm fluid", "warm parcel"], ["rises", "moves up"], ["cooler fluid", "cool fluid"], ["sinks", "moves in", "replaces"]), skill_tags=["current_sequence"]),
            mcq("M6L5_C5", "Which home-heating setup relies strongly on convection?", ["A radiator warming room air from below", "A vacuum flask gap", "Sunlight crossing space", "A metal fork touching soup"], 0, "Moving warm air is the clue.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            mcq("M6L5_C6", "Which order best matches a convection current in water heated from below?", ["Warmer water rises, cooler water sinks, circulation forms", "Particles in the solid flow upward", "Radiation forms a current in the vacuum", "The same water stays still"], 0, "Look for the full carrier loop.", ["convection_heat_rises_confusion"], skill_tags=["current_sequence"]),
        ],
        transfer=[
            mcq("M6L5_M1", "Which weather or room example is mainly convection?", ["Warm air from a heater rising toward the ceiling", "A metal bench warming in sunlight only", "A spoon handle heating through the metal", "Light crossing a vacuum gap"], 0, "Warm moving air is a convection clue.", ["transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            short("M6L5_M2", "Why does cooler fluid move toward the heater in a convection current?", ["Because the warmer fluid has risen away, so cooler and denser fluid moves in to replace it."], "The loop needs replacement flow.", ["convection_heat_rises_confusion"], acceptance_rules=acceptance_groups(["warm fluid", "warmer fluid"], ["rises", "moves away"], ["cooler fluid", "cool fluid"], ["moves in", "replaces it"]), skill_tags=["current_sequence"]),
            mcq("M6L5_M3", "Which change would strengthen a Carrier Loop most directly?", ["Increase the temperature difference between warm and cool regions", "Break contact in a metal rod only", "Polish the surface until it shines", "Move the setup into a vacuum"], 0, "A stronger temperature difference drives a stronger fluid current.", ["convection_heat_rises_confusion"], skill_tags=["mechanism_explanation"]),
            short("M6L5_M4", "Why can soup near the top of a pot become hot even if the flame is below?", ["Because convection carries warm liquid upward while cooler liquid sinks and circulates."], "Use the moving-liquid loop story.", ["convection_heat_rises_confusion"], acceptance_rules=acceptance_groups(["convection", "carrier loop"], ["warm liquid", "warmer liquid"], ["upward", "rises"], ["cooler liquid", "cool liquid"], ["sinks", "circulates"]), skill_tags=["current_sequence"]),
            mcq("M6L5_M5", "Which statement most clearly separates convection from conduction?", ["Convection needs bulk motion of a fluid, while conduction does not", "Convection only happens in metals", "Conduction needs a vacuum", "Convection means temperature and heat are the same"], 0, "The moving-fluid distinction is the key.", ["transfer_route_mixing_confusion"], skill_tags=["medium_reasoning"]),
            short("M6L5_M6", "Why would a solid metal block not set up a Carrier Loop inside itself?", ["Because the solid does not flow as a moving fluid region, so convection currents cannot form inside it."], "Name the missing bulk fluid motion.", ["transfer_route_mixing_confusion"], acceptance_rules=acceptance_groups(["solid", "does not flow", "fixed solid"], ["moving fluid", "bulk motion"], ["cannot form convection", "no carrier loop"]), skill_tags=["medium_reasoning"]),
            mcq("M6L5_M7", "A learner says a convection current means hotness floating upward by itself. Which reply is strongest?", ["No, the fluid itself moves; warm regions rise and cool regions sink", "Yes, heat is a substance that floats", "Yes, only the temperature meter rises", "No, nothing moves in convection"], 0, "The fluid motion matters, not a floating heat substance.", ["convection_heat_rises_confusion", "heat_temperature_confusion"], skill_tags=["mechanism_explanation"]),
            mcq("M6L5_M8", "Which setup would prevent a full Carrier Loop?", ["Replacing the fluid with a fixed solid path", "Heating the fluid from below", "Allowing warm and cool regions to exchange positions", "Giving the fluid space to circulate"], 0, "Without a moving fluid, the loop cannot form.", ["transfer_route_mixing_confusion"], skill_tags=["medium_reasoning"]),
        ],
        contract_payload=contract(
            concept_targets=[
                "Explain convection as thermal transfer by moving fluid regions.",
                "Correct the phrase 'heat rises' into a full convection-current explanation.",
            ],
            core_concepts=[
                "Convection transfers thermal energy by bulk movement of liquids or gases.",
                "A warmer fluid region can expand and become less dense than surrounding cooler fluid.",
                "A convection current is a loop in which warm fluid rises and cooler fluid moves in or sinks to replace it.",
                "Convection belongs to fluids because the medium itself must be able to move as a bulk region.",
            ],
            prerequisite_lessons=["M6_L1", "M6_L4"],
            misconception_focus=["convection_heat_rises_confusion", "transfer_route_mixing_confusion", "heat_temperature_confusion"],
            formulas=[relation("warmer parcel -> expands -> lower density -> rises", "A simple chain showing why heating can drive a convection current in a fluid.", ["qualitative route"], "Use as a reasoning chain for fluids rather than as a numeric equation.")],
            representations=[
                representation("words", "Explain a full convection loop rather than only saying 'heat rises'."),
                representation("diagram", "Show warm rising parcels and cool sinking parcels in one loop."),
                representation("model", "Use the Carrier Loop path to keep the motion visible."),
            ],
            analogy_map=forge_map("students follow a warm parcel around a Carrier Loop"),
            worked_examples=[
                worked("Why does air above a radiator rise while cooler room air moves in below?", ["Warm the nearby air first.", "Explain that the warm air expands and becomes less dense.", "Complete the current by bringing cooler air in below while the warm air rises."], "The radiator sets up a convection current in the room air.", "Convection is the movement of the fluid carrying energy around the space.", "This translates a room-heating example into the full loop explanation."),
                worked("A learner says 'convection is just heat floating upward.' How should the lesson correct that?", ["Keep heat as transferred energy, not a floating substance.", "Move the fluid parcel instead.", "State that warm fluid rises while cooler fluid moves in or sinks to complete the loop."], "Convection is moving-fluid transfer, not a substance called heat floating upward.", "The current needs the medium itself to move.", "This targets the most common convection shortcut language."),
                worked("Why can boiling water circulate but a hot metal block cannot form the same loop inside itself?", ["Identify water as a fluid that can move in bulk.", "Identify the solid block as a fixed solid path.", "Conclude that only the fluid can set up the current."], "Boiling water can convect because it is a moving fluid, while a fixed solid cannot form a Carrier Loop.", "Convection depends on the motion of the medium itself.", "This keeps conduction and convection from blending together."),
            ],
            visual_assets=[visual("m6-l5-carrier-loop", "convection", "The Carrier Loop current", "Shows a warm parcel rising and a cool parcel sinking so the full convection loop is visible.", "Convection is not just upward motion; it is a full circulation of moving fluid regions.")],
            animation_assets=[animation("m6-l5-loop-current", "convection", "A warm parcel completes the loop", "Shows warm fluid rising, moving across, cooling, and sinking to complete the Carrier Loop.")],
            simulation_contract={
                "asset_id": "m6_l5_carrier_loop_lab",
                "concept": "convection",
                "baseline_case": "Start with a fluid heated from below so one warm parcel can begin to rise.",
                "focus_prompt": "What moves in a convection current, and why does the loop continue instead of stopping after one parcel rises?",
                "controls": [
                    {"variable": "heating_position", "label": "Heating position", "why_it_matters": "Changes where the warm parcel forms."},
                    {"variable": "fluid_motion", "label": "Fluid mobility", "why_it_matters": "Shows why a fluid can form the loop while a solid cannot."},
                    {"variable": "temperature_difference", "label": "Warm-cool contrast", "why_it_matters": "Changes how strongly the loop is driven."},
                ],
                "readouts": [
                    {"label": "Parcel density", "meaning": "Shows why a warmed parcel tends to rise."},
                    {"label": "Loop strength", "meaning": "Shows how strongly the full current is circulating."},
                    {"label": "Path trace", "meaning": "Shows the complete route of the moving fluid region."},
                ],
                "comparison_tasks": [
                    "Compare a fluid setup with a solid setup where no Carrier Loop can form.",
                    "Compare weak and strong warm-cool contrasts in the same fluid.",
                ],
                "watch_for": "Students should not explain convection as a substance called heat floating upward by itself.",
                "takeaway": "Convection is thermal energy carried by moving fluid regions in a loop, with warm fluid rising and cooler fluid replacing it.",
            },
            reflection_prompts=[
                "Why is 'heat rises' too weak as a full explanation of convection?",
                "Why can convection happen in liquids and gases but not in a fixed solid?",
            ],
            mastery_skills=[
                "Identify convection contexts",
                "Explain convection currents",
                "Explain density-change reasoning in fluids",
                "Separate convection from conduction",
                "Use full-loop language rather than shortcut phrases",
            ],
            variation_plan={
                "diagnostic": "Rotate water, air, and room-heating contexts while keeping the moving-fluid loop visible.",
                "concept_gate": "Retry with different parcel paths or different shortcut-language corrections before repeating a stem.",
                "mastery": "Use unseen domestic, weather, and lab contexts before repeating any earlier convection explanation.",
            },
            scaffold_support=scaffold(
                "Convection is thermal energy carried by moving fluid regions. Warm parcels can rise, cooler parcels can replace them, and the current becomes a loop rather than a single upward motion.",
                "Check first whether the medium can move as a fluid. Then explain how warming changes density, why the warm parcel rises, and how cooler fluid completes the loop.",
                "What two parcel motions must you mention to explain a full convection current?",
                "Do not stop at 'heat rises'. That shortcut hides the moving-fluid mechanism and the return path of the cooler fluid.",
                "The Carrier Loop makes convection visible as moving parcels rather than floating heat, so the learner can describe the whole current clearly.",
                "Why is a full convection explanation stronger when it includes both rising warm fluid and returning cool fluid?",
                extra_sections=[
                    extra_section("Fluids, not solids", "Convection needs bulk motion of the medium, which is why the route belongs to liquids and gases."),
                    extra_section("A loop, not a slogan", "The strongest convection explanations include expansion, density change, rising warm fluid, and replacement by cooler fluid."),
                ],
            ),
            visual_clarity_checks=visual_checks("Carrier Loop"),
        ),
    )


def lesson_l6() -> Dict[str, Any]:
    return lesson_spec(
        lesson_id="M6_L6",
        title="Glow Cast and the Forge Ledger",
        sim_meta=sim(
            "m6_glow_cast_ledger_lab",
            "Glow Cast and Ledger lab",
            "Compare radiation across a gap and then total the warm-up and Morph Fee stages in one Forge Ledger mission.",
            [
                "Send energy across a vacuum gap with Glow Cast.",
                "Change the surface finish and see how strongly the target block absorbs the beam.",
                "Then total a warm-up stage, a Form Gate stage, and another warm-up stage in the same mission ledger.",
            ],
            [
                "Explain radiation as the route that can cross a vacuum.",
                "Add multi-stage thermal calculations by summing the separate stage energies.",
            ],
            ["surface_finish", "beam_intensity", "vacuum_gap", "ledger_total"],
            "Use the beam plus ledger to connect route choice with staged energy bookkeeping.",
        ),
        diagnostic=[
            mcq("M6L6_D1", "Glow Cast stands for which route?", ["Radiation", "Conduction", "Convection", "Evaporation"], 0, "Glow Cast is the wave route.", ["radiation_medium_confusion", "transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            mcq("M6L6_D2", "Why can the Sun warm Earth even though space is mostly empty?", ["Radiation can cross a vacuum as electromagnetic waves", "Conduction is strongest in a vacuum", "Convection currents fill empty space", "Temperature itself travels without energy"], 0, "Glow Cast is the only route here that can cross the gap.", ["radiation_medium_confusion"], skill_tags=["radiation_explanation"]),
            short("M6L6_D3", "Why is radiation the correct route across a vacuum gap?", ["Because radiation transfers energy by electromagnetic waves and does not need a material medium."], "Mention waves and no medium.", ["radiation_medium_confusion"], acceptance_rules=acceptance_groups(["electromagnetic waves", "waves", "radiation"], ["does not need a medium", "no medium", "can cross vacuum", "empty space"]), skill_tags=["radiation_explanation"]),
            mcq("M6L6_D4", "Which surface usually absorbs Glow Cast most effectively?", ["A dark, dull surface", "A shiny silver surface", "Any surface at random", "Only a liquid surface"], 0, "Dark, dull surfaces are strong absorbers and emitters.", ["radiation_medium_confusion"], skill_tags=["surface_reasoning"]),
            short("M6L6_D5", "A process warms a 1 kg block from 20 degree C to 50 degree C with c = 400 J/kg degree C. How much energy is needed?", ["12000 J", "12000"], "Use Q = m c delta T for the warming stage.", ["multi_stage_heat_calculation_confusion"], skill_tags=["stage_calculation"]),
            short("M6L6_D6", "A 1 kg block at its melting point then melts with L = 300000 J/kg. How much extra energy is needed for that stage?", ["300000 J", "300000"], "Use Q = m L for the state-change stage.", ["multi_stage_heat_calculation_confusion", "phase_change_energy_confusion"], skill_tags=["stage_calculation"]),
            short("M6L6_D7", "Why do multi-stage thermal problems use a Forge Ledger sum?", ["Because each warming or state-change stage has its own energy bill and the total is the sum of the stages."], "Name the separate stages before adding them.", ["multi_stage_heat_calculation_confusion"], acceptance_rules=acceptance_groups(["each stage", "separate stages", "warming and state change"], ["energy bill", "energy needed"], ["sum", "add", "total"]), skill_tags=["ledger_reasoning"]),
            mcq("M6L6_D8", "If a target block is across a vacuum gap, which route pair is ruled out?", ["Conduction and convection", "Radiation and conduction", "Only radiation", "None of them"], 0, "A vacuum blocks the contact and moving-fluid routes.", ["radiation_medium_confusion", "transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
        ],
        analogy_text="Glow Cast sends Transfer Energy across a gap by waves, so it can work even when no medium fills the space. Once the energy reaches the target block, the Forge Ledger can total the later warm-up and Morph Fee stages one by one.",
        commitment_prompt="If a mission has warm-up, state change, and warm-up again, what should the Forge Ledger do with those stages?",
        micro_prompts=[
            prompt_block("Which route still works across empty space?", "Only Glow Cast can cross the vacuum gap."),
            prompt_block("What is the first bookkeeping move in a multi-stage thermal mission?", "Split the process into separate stages before calculating."),
        ],
        inquiry=[
            prompt_block("Compare a dark dull target and a shiny target facing the same beam. Which absorbs more?", "Surface finish changes how strongly the beam is taken in."),
            prompt_block("Break a mission into warm-up, Form Gate, and warm-up again. How should the ledger total be built?", "Add each stage bill separately rather than forcing one formula over the whole mission."),
        ],
        recon_prompts=[
            "Explain why Glow Cast is the only route that can cross a vacuum gap.",
            "Explain why multi-stage thermal calculations are stage-by-stage ledger sums rather than one blind formula.",
        ],
        capsule_prompt="Choose the route first, then total the stage bills accurately.",
        capsule_checks=[
            mcq("M6L6_C1", "Which statement best defines radiation in this module?", ["Energy transfer by electromagnetic waves that can cross a vacuum", "Energy transfer only by moving fluids", "Energy transfer only by direct contact", "Energy transfer only during boiling"], 0, "Radiation is the wave route.", ["radiation_medium_confusion"], skill_tags=["radiation_explanation"]),
            short("M6L6_C2", "Why can conduction and convection not transfer energy from the Sun to Earth across space?", ["Because both need a medium or direct contact, while space is a vacuum gap."], "Name the missing medium or contact.", ["radiation_medium_confusion", "transfer_route_mixing_confusion"], acceptance_rules=acceptance_groups(["need a medium", "need matter", "need contact"], ["vacuum", "gap", "empty space"], ["cannot", "not conduction", "not convection"]), skill_tags=["route_identification"]),
            mcq("M6L6_C3", "What should you do first in a problem that warms a solid, melts it, then warms the liquid?", ["Split it into separate stages and add the stage energies", "Use only Q = m L for the whole mission", "Use only Q = m c delta T once", "Ignore the state change"], 0, "Multi-stage problems are ledger sums.", ["multi_stage_heat_calculation_confusion"], skill_tags=["ledger_reasoning"]),
            short("M6L6_C4", "A 1 kg sample warms by 10 degree C with c = 500 J/kg degree C. Find that stage energy.", ["5000 J", "5000"], "Use Q = m c delta T for the temperature-change stage.", ["multi_stage_heat_calculation_confusion"], skill_tags=["stage_calculation"]),
            short("M6L6_C5", "A 1 kg sample then melts with L = 200000 J/kg. Find the state-change stage energy.", ["200000 J", "200000"], "Use Q = m L for the gate stage.", ["multi_stage_heat_calculation_confusion"], skill_tags=["stage_calculation"]),
            mcq("M6L6_C6", "Which surface is usually the poorer absorber of Glow Cast?", ["A shiny, silver surface", "A dark, dull surface", "A blackened surface", "A matte surface"], 0, "Shiny silver surfaces are poorer absorbers and emitters.", ["radiation_medium_confusion"], skill_tags=["surface_reasoning"]),
        ],
        transfer=[
            mcq("M6L6_M1", "Which space-heating example is mainly radiation?", ["A satellite panel absorbing sunlight", "A spoon handle heating from soup", "Air circulating above a heater", "Water rising in a pan"], 0, "Across a vacuum gap, the wave route is the key clue.", ["radiation_medium_confusion", "transfer_route_mixing_confusion"], skill_tags=["route_identification"]),
            short("M6L6_M2", "Why is a dark, dull kettle side usually a stronger absorber of thermal radiation than a shiny one?", ["Because dark, dull surfaces absorb radiation more effectively than shiny surfaces."], "Surface finish matters for Glow Cast.", ["radiation_medium_confusion"], acceptance_rules=acceptance_groups(["dark", "dull", "matte"], ["absorb", "better absorber", "takes in more"], ["radiation", "glow cast"]), skill_tags=["surface_reasoning"]),
            short("M6L6_M3", "A 2 kg block with c = 300 J/kg degree C warms by 20 degree C. Find the warming-stage energy.", ["12000 J", "12000"], "Use the ordinary warm-up rule for that stage.", ["multi_stage_heat_calculation_confusion"], skill_tags=["stage_calculation"]),
            short("M6L6_M4", "That same 2 kg block then melts with L = 150000 J/kg. Find the state-change stage energy.", ["300000 J", "300000"], "Use Q = m L for the gate stage.", ["multi_stage_heat_calculation_confusion"], skill_tags=["stage_calculation"]),
            short("M6L6_M5", "Using the last two stages, what is the total energy so far?", ["312000 J", "312000"], "Add the warm-up and state-change stage bills.", ["multi_stage_heat_calculation_confusion"], skill_tags=["ledger_reasoning"]),
            short("M6L6_M6", "Why is one formula not enough for every multi-stage heating mission?", ["Because different stages can involve temperature change or state change, so each stage uses its own rule before the totals are added."], "Choose the stage rule first, then add.", ["multi_stage_heat_calculation_confusion", "phase_change_energy_confusion"], acceptance_rules=acceptance_groups(["different stages", "warming and state change", "temperature change and phase change"], ["own rule", "different formula"], ["add", "sum", "total"]), skill_tags=["ledger_reasoning"]),
            mcq("M6L6_M7", "Which pair is matched correctly?", ["Glow Cast -> radiation across a gap; Forge Ledger -> total stage bookkeeping", "Glow Cast -> convection; Forge Ledger -> temperature only", "Glow Cast -> conduction through a solid; Forge Ledger -> route name", "Glow Cast -> latent heat; Forge Ledger -> mass only"], 0, "One names the route across the gap and the other names the total bookkeeping method.", ["radiation_medium_confusion", "multi_stage_heat_calculation_confusion"], skill_tags=["formula_selection"]),
            mcq("M6L6_M8", "A warm block sits across a vacuum from a cooler block. Which route can still transfer energy directly between them?", ["Radiation", "Conduction", "Convection", "Only latent heat"], 0, "The vacuum leaves Glow Cast as the working route.", ["radiation_medium_confusion"], skill_tags=["radiation_explanation"]),
        ],
        contract_payload=contract(
            concept_targets=[
                "Explain radiation as the transfer route that can cross a vacuum.",
                "Solve multi-stage thermal missions by summing separate warming and state-change stages.",
            ],
            core_concepts=[
                "Radiation transfers energy by electromagnetic waves and does not need a material medium.",
                "Dark, dull surfaces are usually stronger absorbers and emitters of thermal radiation than shiny, silver surfaces.",
                "A multi-stage thermal process must be split into warming and state-change stages before the total is calculated.",
                "The total thermal energy for a complex mission is the sum of the separate stage energies rather than one formula applied blindly to the whole process.",
            ],
            prerequisite_lessons=["M6_L2", "M6_L3", "M6_L4", "M6_L5"],
            misconception_focus=["radiation_medium_confusion", "transfer_route_mixing_confusion", "multi_stage_heat_calculation_confusion", "phase_change_energy_confusion"],
            formulas=[warmup_relation(), latent_relation(), ledger_relation()],
            representations=[
                representation("words", "State why radiation can cross a vacuum and why staged problems need separate bills."),
                representation("diagram", "Show the beam crossing a gap and the stage ledger below it."),
                representation("equation_story", "Connect warm-up bills, Morph Fees, and the total sum."),
            ],
            analogy_map=forge_map("students send Glow Cast across a gap and then total a staged mission in the Forge Ledger"),
            worked_examples=[
                worked("Why is radiation the correct route for energy transfer from the Sun to Earth?", ["Identify the gap between the Sun and Earth as effectively a vacuum.", "Rule out conduction and convection because they need matter or direct contact.", "Choose radiation because electromagnetic waves can cross the gap."], "Radiation is the correct route because it can cross a vacuum.", "Glow Cast works without a material medium.", "This is the signature radiation context students must recognize quickly."),
                worked("A 1 kg sample warms by 10 degree C with c = 400 J/kg degree C, then melts with L = 250000 J/kg. Find the total energy.", ["Use Q = m c delta T for the warming stage to get 4000 J.", "Use Q = m L for the melting stage to get 250000 J.", "Add the two stage bills to get the Forge Ledger total."], "254000 J", "Multi-stage thermal problems are totals built from separate stage rules.", "This makes the stage-by-stage bookkeeping explicit."),
                worked("A learner uses only Q = m c delta T for a process that includes melting. How should the Forge Ledger correct that move?", ["Split the mission into its separate stages first.", "Use the warm-up rule only where temperature is changing.", "Use the latent-heat rule at the Form Gate, then add the totals."], "The process needs at least two stage rules: warming and melting, then a sum.", "A state-change stage has its own energy rule and cannot be hidden inside one ordinary warming formula.", "This addresses the capstone bookkeeping mistake directly."),
            ],
            visual_assets=[visual("m6-l6-glow-cast-ledger", "radiation_ledger", "Glow Cast crosses the gap", "Shows radiation crossing a vacuum gap and a staged Forge Ledger underneath for the warm-up and Morph Fee totals.", "Radiation chooses the route across the gap, and the Forge Ledger totals the separate thermal stages afterward.")],
            animation_assets=[animation("m6-l6-beam-ledger", "radiation_ledger", "Beam first, ledger next", "Shows a beam heating the target block across a gap and then the energy being split into warm-up and gate stages in the ledger.")],
            simulation_contract={
                "asset_id": "m6_l6_glow_cast_ledger_lab",
                "concept": "radiation_ledger",
                "baseline_case": "Start with a source block beaming energy across a vacuum gap toward a cooler target, then run a two-stage heating mission on the target.",
                "focus_prompt": "Which route can cross the gap, and how should the total energy be built once the target starts warming and changing state?",
                "controls": [
                    {"variable": "beam_intensity", "label": "Glow Cast intensity", "why_it_matters": "Changes how strongly the target receives radiation."},
                    {"variable": "surface_finish", "label": "Target surface finish", "why_it_matters": "Changes how strongly the target absorbs the beam."},
                    {"variable": "mission_stage", "label": "Forge Ledger stage", "why_it_matters": "Lets the learner total warm-up and state-change stages one by one."},
                ],
                "readouts": [
                    {"label": "Gap status", "meaning": "Shows that the route crosses a vacuum gap."},
                    {"label": "Absorbed beam energy", "meaning": "Shows how much Glow Cast reaches the target."},
                    {"label": "Forge Ledger total", "meaning": "Shows the running total of the separate thermal stages."},
                ],
                "comparison_tasks": [
                    "Compare a dark dull target with a shiny target facing the same beam.",
                    "Compare a one-stage warm-up mission with a warm-up plus Form Gate mission and total the stage bills.",
                ],
                "watch_for": "Students should not use conduction or convection across a vacuum or force one equation over an entire multi-stage process.",
                "takeaway": "Radiation is the gap-crossing route, and multi-stage thermal missions are solved by adding the separate stage energies in the Forge Ledger.",
            },
            reflection_prompts=[
                "Why is Glow Cast the only Level-Forge route that can cross a vacuum gap?",
                "Why are multi-stage thermal questions strongest when you split them into stage bills before adding the total?",
            ],
            mastery_skills=[
                "Identify radiation contexts",
                "Explain radiation in a vacuum",
                "Reason about absorption and surface finish",
                "Calculate stage energies with Q = m c delta T and Q = m L",
                "Add multi-stage thermal totals accurately",
            ],
            variation_plan={
                "diagnostic": "Rotate space, beam, and surface-finish contexts alongside simple stage-bill questions so route choice and bookkeeping are both checked early.",
                "concept_gate": "Retry with different surface comparisons or different warm-up plus gate stage totals before repeating a previous stem.",
                "mastery": "Use unseen multi-stage numbers and route-identification contexts before repeating any previous capstone prompt.",
            },
            scaffold_support=scaffold(
                "Glow Cast is the route that can cross a vacuum, and the Forge Ledger solves complex heating by adding the separate energy bills for each stage.",
                "Choose the route first: a vacuum gap points to radiation. Then split the target process into stages, choose the correct rule for each stage, and add the totals carefully.",
                "If a process includes both warming and melting, what should you do before any arithmetic?",
                "Do not force one formula over the whole mission. Warm-up stages and state-change stages need different rules before they can be summed.",
                "The Level-Forge makes the capstone mission manageable by letting the learner pick Glow Cast for the gap and then total each later bill in the Forge Ledger.",
                "Why is the ledger sum stronger than one blind formula in a multi-stage process?",
                extra_sections=[
                    extra_section("Vacuum means waves", "If there is no medium across the gap, conduction and convection are ruled out and radiation is the working route."),
                    extra_section("Stage-by-stage bookkeeping", "A good thermal solution names each stage first, chooses the correct rule, and then totals the separate energies."),
                ],
            ),
            visual_clarity_checks=visual_checks("Glow Cast and Forge Ledger"),
        ),
    )

M6_BANK_EXPANSIONS: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
    "M6_L1": {
        "diagnostic": [
            mcq(
                "M6L1_D9",
                "Two 1 kg blocks with the same Level Cost start at the same Warmth Level. Block A receives 400 J and Block B receives 800 J. Which rises more?",
                [
                    "Block B, because the larger transfer gives the larger Warmth Level rise for the same kind of block",
                    "Block A, because smaller numbers always heat faster",
                    "They rise equally because the starting Warmth Level matched",
                    "Neither can rise without a Form Gate",
                ],
                0,
                "For the same mass and Level Cost, a larger transfer gives a larger temperature rise.",
                ["same_energy_same_temp_change_confusion"],
                skill_tags=["warming_compare"],
            ),
            short(
                "M6L1_D10",
                "If Transfer Energy leaves a block for cooler surroundings, what can happen to its Warmth Level?",
                [
                    "It can decrease because energy is being transferred out of the block.",
                    "Its temperature can fall when energy leaves the block.",
                ],
                "If energy leaves, the temperature reading can drop.",
                ["heat_temperature_confusion"],
                acceptance_rules=acceptance_groups(
                    ["energy leaves", "transferred out", "energy transferred out", "loses transfer energy"],
                    ["warmth level", "temperature"],
                    ["decrease", "fall", "drop", "go down"],
                ),
                skill_tags=["cooling_direction"],
            ),
        ],
        "concept": [
            mcq(
                "M6L1_C7",
                "Two blocks have the same Level Cost and receive the same Transfer Energy. One is 1 kg and one is 3 kg. Which rises more in Warmth Level?",
                ["The 1 kg block", "The 3 kg block", "They rise equally", "Neither can change"],
                0,
                "With the same energy and material, the smaller mass shows the larger temperature rise.",
                ["mass_heating_confusion"],
                skill_tags=["mass_effect"],
            ),
            short(
                "M6L1_C8",
                "Why is knowing only the Warmth Level not enough to know the next heating bill?",
                [
                    "Because the energy needed also depends on the mass and the Level Cost.",
                    "Because temperature alone does not tell you the amount of material or the specific heat capacity.",
                ],
                "A heating bill needs more than the current temperature reading.",
                ["heat_temperature_confusion", "specific_heat_capacity_confusion"],
                acceptance_rules=acceptance_groups(
                    ["warmth level", "temperature"],
                    ["mass", "build size", "amount of material"],
                    ["level cost", "specific heat capacity"],
                ),
                skill_tags=["bill_reasoning"],
            ),
        ],
        "transfer": [
            mcq(
                "M6L1_M9",
                "Block A needs 200 J for each Warmth Level rise and Block B needs 400 J for each Warmth Level rise. If each receives 800 J, which gains more levels?",
                ["Block A", "Block B", "They gain the same number of levels", "Neither can rise"],
                0,
                "The lower Level Cost means the same payment buys more level rises.",
                ["specific_heat_capacity_confusion", "same_energy_same_temp_change_confusion"],
                skill_tags=["level_cost_compare"],
            ),
            short(
                "M6L1_M10",
                "Why is 'the hotter object has more heat' a weak comparison between a spark and a bathtub?",
                [
                    "Because temperature tells how hot something is, but the total energy story also depends on mass and material.",
                    "Because a tiny hot object and a large warm object can imply very different energy-transfer stories.",
                ],
                "Separate 'how hot' from the amount of material and the transfer needed.",
                ["heat_temperature_confusion", "mass_heating_confusion"],
                acceptance_rules=acceptance_groups(
                    ["temperature", "hotter", "how hot"],
                    ["mass", "amount of material", "size"],
                    ["different energy", "different transfer", "not the same total energy story", "different energy story"],
                ),
                skill_tags=["state_vs_total"],
            ),
        ],
    },
    "M6_L2": {
        "diagnostic": [
            short(
                "M6L2_D9",
                "A 2 kg block has c = 400 J/kg degree C and warms by 5 degree C. How much Transfer Energy is needed?",
                ["4000 J", "4000"],
                "Use Q = m c delta T.",
                ["specific_heat_capacity_confusion"],
                skill_tags=["heating_bill"],
            ),
            mcq(
                "M6L2_D10",
                "Two 1 kg blocks receive the same Transfer Energy. Block X has a lower specific heat capacity than Block Y. Which shows the larger temperature rise?",
                [
                    "Block X, because the same energy buys more degrees when c is lower",
                    "Block Y, because the higher c always heats faster",
                    "They rise equally because the masses match",
                    "Neither rises unless the state changes",
                ],
                0,
                "Lower specific heat capacity means the same energy gives a larger temperature change.",
                ["specific_heat_capacity_confusion", "same_energy_same_temp_change_confusion"],
                skill_tags=["material_compare"],
            ),
        ],
        "concept": [
            short(
                "M6L2_C7",
                "A 3 kg block receives 9000 J and has c = 300 J/kg degree C. What temperature rise does that produce?",
                ["10 degree C", "10 C", "10", "10 degrees"],
                "Rearrange Q = m c delta T to find delta T.",
                ["specific_heat_capacity_confusion"],
                skill_tags=["formula_rearrangement"],
            ),
            mcq(
                "M6L2_C8",
                "If mass and temperature rise stay the same but specific heat capacity doubles, what happens to the heating bill Q?",
                ["It doubles", "It halves", "It stays the same", "It becomes zero"],
                0,
                "Q is proportional to c when the other factors stay fixed.",
                ["specific_heat_capacity_confusion"],
                skill_tags=["heating_bill"],
            ),
        ],
        "transfer": [
            short(
                "M6L2_M9",
                "A block receives 5000 J. Its mass is 2 kg and c = 250 J/kg degree C. What temperature rise follows?",
                ["10 degree C", "10 C", "10", "10 degrees"],
                "Use delta T = Q / (m c).",
                ["specific_heat_capacity_confusion"],
                skill_tags=["formula_rearrangement"],
            ),
            mcq(
                "M6L2_M10",
                "Two equal masses warm by the same temperature rise. Material X needs 6000 J while Material Y needs 3000 J. Which has the larger specific heat capacity?",
                [
                    "Material X",
                    "Material Y",
                    "They must have the same specific heat capacity",
                    "There is not enough information because mass is missing",
                ],
                0,
                "For the same m and delta T, the one that needs more energy has the larger c.",
                ["specific_heat_capacity_confusion"],
                skill_tags=["material_compare"],
            ),
        ],
    },
    "M6_L3": {
        "diagnostic": [
            short(
                "M6L3_D9",
                "A 2 kg sample melts with L = 150000 J/kg. How much energy is needed for the state-change stage?",
                ["300000 J", "300000"],
                "Use Q = m L for the Form Gate stage.",
                ["phase_change_energy_confusion"],
                skill_tags=["latent_bill"],
            ),
            mcq(
                "M6L3_D10",
                "Two samples of the same substance are both at the Form Gate and each receives the same energy. One sample has half the mass of the other. Which finishes melting first?",
                [
                    "The smaller-mass sample",
                    "The larger-mass sample",
                    "They must finish together",
                    "Neither can melt at constant temperature",
                ],
                0,
                "The smaller mass has the smaller total Morph Fee.",
                ["phase_change_energy_confusion", "latent_heat_temperature_rise_confusion"],
                skill_tags=["gate_compare"],
            ),
        ],
        "concept": [
            short(
                "M6L3_C7",
                "A 0.5 kg sample has L = 200000 J/kg. What Morph Fee is needed in total?",
                ["100000 J", "100000"],
                "Multiply mass by latent heat.",
                ["phase_change_energy_confusion"],
                skill_tags=["latent_bill"],
            ),
            mcq(
                "M6L3_C8",
                "Which heating-curve section best represents a pure state-change stage for a pure substance?",
                [
                    "A flat temperature section while energy continues to enter",
                    "A steadily rising temperature line",
                    "A falling temperature line with no energy transfer",
                    "A random zigzag of temperature",
                ],
                0,
                "A plateau shows energy entering while temperature stays constant at the change point.",
                ["latent_heat_temperature_rise_confusion"],
                skill_tags=["plateau_interpretation"],
            ),
        ],
        "transfer": [
            short(
                "M6L3_M9",
                "A 1 kg sample warms by 20 degree C with c = 500 J/kg degree C and then melts with L = 200000 J/kg. What total energy is needed?",
                ["210000 J", "210000"],
                "Add the warm-up bill and the gate bill.",
                ["phase_change_energy_confusion", "multi_stage_heat_calculation_confusion"],
                skill_tags=["ledger_total"],
            ),
            mcq(
                "M6L3_M10",
                "Two 1 kg samples are at their melting points. Sample A has a larger latent heat than Sample B. Which needs the larger Morph Fee to melt completely?",
                ["Sample A", "Sample B", "They need the same fee because the masses match", "Neither needs extra energy at the Form Gate"],
                0,
                "With the same mass, the larger latent heat means the larger state-change bill.",
                ["phase_change_energy_confusion"],
                skill_tags=["gate_compare"],
            ),
        ],
    },
    "M6_L4": {
        "diagnostic": [
            mcq(
                "M6L4_D9",
                "Which setup gives the strongest Touch Relay from hot end to cool end?",
                [
                    "A metal bar in direct contact all the way through",
                    "A plastic bar in direct contact all the way through",
                    "A metal bar with a gap in the middle",
                    "Warm air rising above a heater",
                ],
                0,
                "Good conduction needs both a good conductor and an unbroken contact path.",
                ["conduction_particle_flow_confusion", "metal_conduction_reason_confusion"],
                skill_tags=["path_compare"],
            ),
            short(
                "M6L4_D10",
                "Why do saucepans often use wood or plastic handles?",
                [
                    "Because those materials are poor conductors, so less thermal energy is relayed to the hand.",
                    "Because they reduce conduction from the hot pan to the hand.",
                ],
                "Explain the safer handle as a weaker conduction path.",
                ["transfer_route_mixing_confusion", "conduction_particle_flow_confusion"],
                acceptance_rules=acceptance_groups(
                    ["poor conductor", "insulator", "less conductive"],
                    ["reduce", "slow", "less"],
                    ["conduction", "touch relay", "thermal energy"],
                    ["hand", "handle"],
                ),
                skill_tags=["insulation_reasoning"],
            ),
        ],
        "concept": [
            mcq(
                "M6L4_C7",
                "Two identical metal bars stay in full contact. Bar A has a 20 degree C end-to-end difference and Bar B has a 60 degree C difference. Which has the stronger conduction drive?",
                [
                    "Bar B, because the larger temperature difference drives the stronger relay",
                    "Bar A, because a smaller difference is easier to conduct",
                    "They conduct equally because the material matches",
                    "Neither conducts unless the solid moves",
                ],
                0,
                "A larger temperature difference gives a stronger push for conduction.",
                ["conduction_particle_flow_confusion"],
                skill_tags=["path_compare"],
            ),
            short(
                "M6L4_C8",
                "Why can an air gap reduce conduction in a mug wall or lunch box?",
                [
                    "Because it weakens the direct contact path and air is a poor conductor.",
                    "Because conduction falls when the contact path is interrupted or replaced by a poorer conductor.",
                ],
                "Use both the weakened path and the poor-conductor idea if you can.",
                ["conduction_particle_flow_confusion", "transfer_route_mixing_confusion"],
                acceptance_rules=acceptance_groups(
                    ["air gap", "gap", "air"],
                    ["breaks", "weakens", "interrupts", "reduces"],
                    ["contact path", "direct contact"],
                    ["poor conductor", "insulator", "conduction"],
                ),
                skill_tags=["insulation_reasoning"],
            ),
        ],
        "transfer": [
            mcq(
                "M6L4_M9",
                "Pins fixed with wax drop off a heated metal rod one after another from the hot end. What is the best explanation?",
                [
                    "Energy is relayed through the rod by conduction, with particle contact and metal electrons carrying it along",
                    "Hot metal flows along the rod toward the pins",
                    "Convection currents inside the solid carry the energy to the pins",
                    "The cooler end becomes hottest first because cold attracts heat",
                ],
                0,
                "The rod stays in place while the energy passes through it.",
                ["conduction_particle_flow_confusion", "metal_conduction_reason_confusion"],
                skill_tags=["mechanism_explanation"],
            ),
            short(
                "M6L4_M10",
                "Why can a metal bench and a wooden bench at the same outdoor temperature feel different to your hand?",
                [
                    "Because the metal conducts thermal energy away from the hand faster than the wood.",
                    "Because the metal relays energy from your hand more quickly even when the temperature reading matches.",
                ],
                "Use transfer rate, not just temperature, in the explanation.",
                ["metal_conduction_reason_confusion", "heat_temperature_confusion"],
                acceptance_rules=acceptance_groups(
                    ["metal", "conducts", "conduction"],
                    ["away from the hand", "from your hand", "faster"],
                    ["same temperature", "same outdoor temperature", "same reading"],
                ),
                skill_tags=["metal_explanation"],
            ),
        ],
    },
    "M6_L5": {
        "diagnostic": [
            mcq(
                "M6L5_D9",
                "Which setup most strongly supports a Carrier Loop convection current?",
                [
                    "Heating a liquid from below so the warmed fluid can rise",
                    "Heating a solid metal block evenly from all sides",
                    "Keeping a fluid at one uniform temperature",
                    "Placing the heater above the fluid so no cooler fluid can sink underneath",
                ],
                0,
                "Convection current needs a fluid and a temperature difference that can drive circulation.",
                ["convection_heat_rises_confusion", "transfer_route_mixing_confusion"],
                skill_tags=["loop_setup"],
            ),
            short(
                "M6L5_D10",
                "Why does smoke above a candle rise and then spread?",
                [
                    "Because the warmed air becomes less dense and rises, then cooler air moves in and the flow spreads out.",
                    "Because warm air rises in a convection current while surrounding cooler air replaces it.",
                ],
                "Explain the motion as a moving fluid loop, not as floating heat.",
                ["convection_heat_rises_confusion"],
                acceptance_rules=acceptance_groups(
                    ["warm air", "warmed air", "warmer fluid"],
                    ["less dense", "lower density", "rises", "moves up"],
                    ["cooler air", "cool air", "cooler fluid"],
                    ["moves in", "replaces it", "sinks", "spreads"],
                ),
                skill_tags=["current_sequence"],
            ),
        ],
        "concept": [
            mcq(
                "M6L5_C7",
                "Which change would weaken a Carrier Loop most?",
                [
                    "Replacing the fluid with a solid block",
                    "Increasing the temperature contrast",
                    "Cooling the top of the liquid",
                    "Allowing the warm parcel to rise freely",
                ],
                0,
                "Convection needs bulk fluid motion, so a solid blocks the route entirely.",
                ["transfer_route_mixing_confusion"],
                skill_tags=["medium_reasoning"],
            ),
            short(
                "M6L5_C8",
                "Why does cooling the top of a liquid help the convection loop continue?",
                [
                    "Because the cooled fluid becomes denser and sinks, helping the return flow.",
                    "Because cooler fluid at the top can move downward and complete the circulation.",
                ],
                "Use density and return-flow language together.",
                ["convection_heat_rises_confusion"],
                acceptance_rules=acceptance_groups(
                    ["cool", "cooled", "cooler fluid"],
                    ["denser", "more dense", "higher density"],
                    ["sinks", "moves down", "returns"],
                    ["loop", "circulation", "current"],
                ),
                skill_tags=["current_sequence"],
            ),
        ],
        "transfer": [
            mcq(
                "M6L5_M9",
                "Which explanation best fits a daytime sea breeze?",
                [
                    "Land warms nearby air, that air rises, and cooler sea air moves in toward the land",
                    "Sea water conducts through the sand and pushes the air sideways",
                    "Radiation alone carries the warm air across the beach with no fluid motion",
                    "Only the warm air moves; cooler air does not take part",
                ],
                0,
                "A breeze is a moving-air loop caused by uneven heating.",
                ["convection_heat_rises_confusion"],
                skill_tags=["current_sequence"],
            ),
            short(
                "M6L5_M10",
                "Why are high vents useful for removing warm air from a room?",
                [
                    "Because warmer air rises and collects higher up, so the vent lets it leave while cooler air can replace it.",
                    "Because convection tends to carry the warmer, less dense air upward toward the vent.",
                ],
                "Use warm-air rise plus replacement flow if you can.",
                ["convection_heat_rises_confusion"],
                acceptance_rules=acceptance_groups(
                    ["warm air", "warmer air", "less dense air"],
                    ["rises", "moves up", "collects higher"],
                    ["vent", "leave", "escape"],
                    ["cooler air", "replacement air", "moves in", "replace"],
                ),
                skill_tags=["loop_setup"],
            ),
        ],
    },
    "M6_L6": {
        "diagnostic": [
            short(
                "M6L6_D9",
                "A 2 kg block warms by 10 degree C with c = 400 J/kg degree C. How much energy is needed for that warm-up stage?",
                ["8000 J", "8000"],
                "Use Q = m c delta T for the temperature-change stage.",
                ["multi_stage_heat_calculation_confusion"],
                skill_tags=["stage_calculation"],
            ),
            short(
                "M6L6_D10",
                "A 1 kg sample warms by 4 degree C with c = 500 J/kg degree C and then melts with L = 100000 J/kg. What total energy is needed?",
                ["102000 J", "102000"],
                "Add the warm-up stage and the gate stage.",
                ["multi_stage_heat_calculation_confusion", "phase_change_energy_confusion"],
                skill_tags=["ledger_total"],
            ),
        ],
        "concept": [
            mcq(
                "M6L6_C7",
                "Two targets face the same radiant beam. Which usually absorbs more of it?",
                ["The dark, dull target", "The shiny silver target", "They always absorb exactly the same amount", "Only the colder target can absorb radiation"],
                0,
                "Dark, dull surfaces are usually better absorbers than shiny ones.",
                ["radiation_medium_confusion"],
                skill_tags=["surface_reasoning"],
            ),
            short(
                "M6L6_C8",
                "Why should route choice come before equation choice in a thermal mission?",
                [
                    "Because the context tells you whether the transfer is conduction, convection, or radiation before you start the energy bookkeeping.",
                    "Because you first need to identify the transfer route and the stages before choosing the correct calculation rule.",
                ],
                "Name the route first, then choose the stage rule.",
                ["transfer_route_mixing_confusion", "multi_stage_heat_calculation_confusion"],
                acceptance_rules=acceptance_groups(
                    ["route", "conduction", "convection", "radiation"],
                    ["before", "first", "come before"],
                    ["equation", "stage rule", "calculation"],
                    ["stage", "bookkeeping", "mission"],
                ),
                skill_tags=["formula_selection"],
            ),
        ],
        "transfer": [
            short(
                "M6L6_M9",
                "A 2 kg sample warms by 15 degree C with c = 200 J/kg degree C and then melts with L = 150000 J/kg. What total energy is needed?",
                ["306000 J", "306000"],
                "Find the warm-up bill, find the gate bill, then add them.",
                ["multi_stage_heat_calculation_confusion", "phase_change_energy_confusion"],
                skill_tags=["ledger_total"],
            ),
            mcq(
                "M6L6_M10",
                "Which full solution sequence is strongest for a block heated across a vacuum gap and then melted?",
                [
                    "Identify radiation across the gap, calculate any warm-up stages with Q = m c delta T, calculate the melting stage with Q = m L, then add the stage totals",
                    "Use Q = m L for the whole problem because melting appears somewhere in it",
                    "Use only Q = m c delta T because the block warms before melting",
                    "Ignore the route and add the temperatures first",
                ],
                0,
                "A strong solution chooses the route and then totals the relevant stages one by one.",
                ["radiation_medium_confusion", "multi_stage_heat_calculation_confusion"],
                skill_tags=["formula_selection"],
            ),
        ],
    },
}


def enrich_m6_lesson(lesson: Dict[str, Any]) -> Dict[str, Any]:
    lesson_copy = deepcopy(lesson)
    extras = M6_BANK_EXPANSIONS.get(str(lesson_copy.get("id") or ""), {})
    if not extras:
        return lesson_copy

    phases = dict(lesson_copy.get("phases") or {})

    diagnostic_phase = dict(phases.get("diagnostic") or {})
    diagnostic_phase["items"] = list(diagnostic_phase.get("items") or []) + [deepcopy(item) for item in extras.get("diagnostic", [])]
    phases["diagnostic"] = diagnostic_phase

    concept_phase = dict(phases.get("concept_reconstruction") or {})
    capsules = list(concept_phase.get("capsules") or [])
    if capsules:
        first_capsule = deepcopy(dict(capsules[0] or {}))
        first_capsule["checks"] = list(first_capsule.get("checks") or []) + [deepcopy(item) for item in extras.get("concept", [])]
        capsules[0] = first_capsule
        concept_phase["capsules"] = capsules
    phases["concept_reconstruction"] = concept_phase

    transfer_phase = dict(phases.get("transfer") or {})
    transfer_phase["items"] = list(transfer_phase.get("items") or []) + [deepcopy(item) for item in extras.get("transfer", [])]
    phases["transfer"] = transfer_phase

    lesson_copy["phases"] = phases
    return lesson_copy


M6_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": (
        "Thermal transfer and gas behaviour: heating and cooling, specific heat capacity, latent heat, conduction, "
        "convection, radiation, and gas-behaviour preparation are tracked as staged thermal changes."
    ),
    "mastery_outcomes": [
        "Explain the difference between temperature and heat transferred.",
        "Explain specific heat capacity as the energy needed per kilogram per degree.",
        "Use Q = m c delta T for ordinary temperature-change stages.",
        "Explain latent heat as energy needed for a state change without a temperature rise.",
        "Use Q = m L for melting and boiling stages.",
        "Distinguish conduction, convection, and radiation clearly and identify when each route applies.",
        "Explain why radiation can cross a vacuum while conduction and convection cannot.",
        "Solve multi-stage thermal problems by summing the separate stage energies.",
        "Apply the same thermal-bookkeeping rules across new materials, route contexts, and staged heating missions.",
    ],
    "lessons": [
        enrich_m6_lesson(lesson_l1()),
        enrich_m6_lesson(lesson_l2()),
        enrich_m6_lesson(lesson_l3()),
        enrich_m6_lesson(lesson_l4()),
        enrich_m6_lesson(lesson_l5()),
        enrich_m6_lesson(lesson_l6()),
    ],
}


RELEASE_CHECKS = [
    "Every lesson keeps temperature separate from heat transferred rather than letting the terms collapse into one vague story.",
    "Every lesson uses the Level-Forge analogy to support the formal thermal relationships instead of replacing them with slogans.",
    "Every worked example states why the answer follows, not just the classification or arithmetic.",
    "Every stage-based calculation keeps ordinary warming and state change as separate ledger entries before the total is added.",
    "Every Try It in Action explorer is backed by lesson-specific simulation copy and contracts rather than generic fallback wording.",
    "Every lesson-owned assessment bank is broad enough to prefer unseen questions on fresh attempts before repeating earlier stems.",
]


M6_MODULE_DOC, M6_LESSONS, M6_SIM_LABS = build_nextgen_module_bundle(
    module_id=M6_MODULE_ID,
    module_title=M6_MODULE_TITLE,
    module_spec=M6_SPEC,
    allowlist=M6_ALLOWLIST,
    content_version=M6_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=10,
    level="Module 6",
    estimated_minutes=300,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def _sync_assessed_skills(lesson_pairs: Sequence[Tuple[str, Dict[str, Any]]]) -> None:
    for _, lesson in lesson_pairs:
        contract = lesson.get("authoring_contract") or {}
        declared: List[str] = []
        for skill in contract.get("mastery_skills") or []:
            cleaned = str(skill).strip()
            if cleaned and cleaned not in declared:
                declared.append(cleaned)
        concept_items: List[Dict[str, Any]] = []
        for capsule in lesson.get("phases", {}).get("concept_reconstruction", {}).get("capsules", []):
            concept_items.extend(capsule.get("checks") or [])
        mastery_items = lesson.get("phases", {}).get("transfer", {}).get("items") or []
        for item in [*concept_items, *mastery_items]:
            for skill in item.get("skill_tags") or []:
                cleaned = str(skill).strip()
                if cleaned and cleaned not in declared:
                    declared.append(cleaned)
        contract["mastery_skills"] = declared


_sync_assessed_skills(M6_LESSONS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M6 into Firestore")
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

    module_doc = deepcopy(M6_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M6_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M6_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M6_MODULE_ID)]
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
