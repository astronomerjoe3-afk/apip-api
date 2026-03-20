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


M3_MODULE_ID = "M3"
M3_CONTENT_VERSION = "20260320_m3_lift_launch_v3"
M3_MODULE_TITLE = "Energy Stores, Hand-offs & Ledger Reasoning"
M3_ALLOWLIST = [
    "energy_force_confusion",
    "energy_used_up_confusion",
    "height_store_variable_confusion",
    "motion_store_speed_squared_confusion",
    "work_hand_off_confusion",
    "power_energy_rate_confusion",
    "efficiency_power_distinction_confusion",
    "ledger_balance_confusion",
    "energy_equation_choice_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M3_ALLOWLIST)
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


def extra_section(heading: str, body: str) -> Dict[str, str]:
    return {"heading": heading, "body": body}


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
    return {
        "concept_targets": list(concept_targets),
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
        "scaffold_support": deepcopy(scaffold_support),
    }


def lesson_l1() -> Dict[str, Any]:
    return {
        "id": "M3_L1",
        "title": "Lift-Launch World and the Energy Ledger",
        "sim": {
            "lab_id": "m3_lift_launch_ledger_lab",
            "title": "Lift-Launch ledger explorer",
            "description": "Track how input energy becomes store gain or leak trail inside one mission world.",
            "instructions": [
                "Raise the pod without launching it and decide which store changes.",
                "Compare a clean transfer with a leaky one while keeping the input fixed.",
                "Explain every mission step with a balanced energy ledger statement.",
            ],
            "outcomes": [
                "energy_force_confusion",
                "energy_used_up_confusion",
                "ledger_balance_confusion",
            ],
            "fields": [
                "deck_level",
                "motion_pace",
                "machine_input",
                "useful_store_gain",
                "leak_trail",
                "ledger_balance",
            ],
            "depth": "number of mission steps explained as balanced store-and-transfer stories instead of loose formula recall",
        },
        "analogy_text": (
            "In the Lift-Launch arena, the mission pod can hold energy in a Height Store or Motion Store. "
            "Lifts and launchers hand energy into those stores, the Leak Trail shows wasted spread into heat, sound, "
            "or vibration, and the Energy Ledger must balance every step."
        ),
        "commitment_prompt": "Before you calculate anything, decide whether the story is about a store, a hand-off, or a leak trail.",
        "micro_prompts": [
            prompt_block(
                "Compare a raised pod that is still with a low pod that is moving fast.",
                "Both can hold energy, but they hold it in different stores.",
            ),
            prompt_block(
                "Compare 120 J input becoming 120 J useful with 120 J input becoming 90 J useful and 30 J leak.",
                "The ledger has to balance in both stories.",
            ),
            prompt_block(
                "A learner says the missing energy is gone. Challenge that claim using the Leak Trail.",
                "If it is not in a useful store, it must appear elsewhere in the ledger.",
            ),
        ],
        "diagnostic": [
            mcq(
                "M3L1_D1",
                "Which statement best fits the Lift-Launch model of energy?",
                [
                    "Energy sits in stores, moves by hand-offs, and is tracked across the mission.",
                    "Energy is just another name for the pushing force.",
                    "Energy only exists when the pod is moving.",
                    "Energy vanishes as soon as a task is finished.",
                ],
                0,
                "This module treats energy as stored, transferred, and accounted for.",
                ["energy_force_confusion", "energy_used_up_confusion"],
            ),
            mcq(
                "M3L1_D2",
                "A pod is lifted to a higher deck and held still. Which store has increased?",
                [
                    "Height Store",
                    "Motion Store",
                    "No store because the pod is not moving",
                    "Only Leak Trail",
                ],
                0,
                "Height can store energy even when the pod is not moving.",
                ["energy_force_confusion", "energy_used_up_confusion"],
            ),
            short(
                "M3L1_D3",
                "A machine inputs 120 J. The pod gains 90 J of useful store energy. How much goes into the Leak Trail?",
                ["30 J", "30"],
                "Use the ledger: input = useful gain + leak trail.",
                ["ledger_balance_confusion"],
            ),
            mcq(
                "M3L1_D4",
                "If students say energy was 'used up', which response best repairs the idea?",
                [
                    "It must be found in a store gain or in the Leak Trail.",
                    "It really disappears once the machine stops.",
                    "It turns into force, which replaces it.",
                    "It stays nowhere until a new formula is chosen.",
                ],
                0,
                "Energy is accounted for; it does not simply vanish.",
                ["energy_used_up_confusion", "ledger_balance_confusion"],
            ),
        ],
        "inquiry": [
            prompt_block(
                "Build one mission where the input all becomes useful store gain and one where part of it leaks away.",
                "The totals can match even when the useful share changes.",
            ),
            prompt_block(
                "Keep the machine input fixed while changing the leak trail.",
                "The useful store gain must shrink if the same input now leaks more.",
            ),
            prompt_block(
                "Explain a full mission step using a ledger sentence before using any formal equation.",
                "Name where the energy starts, where it goes, and what leaks away.",
            ),
        ],
        "recon_prompts": [
            "Explain why energy is not the same thing as force in the Lift-Launch world.",
            "Explain why 'missing energy' is really an accounting problem, not evidence that energy vanished.",
        ],
        "capsule_prompt": (
            "Energy lives in stores, moves by hand-offs, and the ledger must balance: input energy equals useful gain plus leak trail."
        ),
        "capsule_checks": [
            mcq(
                "M3L1_C1",
                "If the pod is high but not moving, what can still be true?",
                [
                    "It still holds energy in a store.",
                    "It cannot have energy because speed is zero.",
                    "Only a force store can exist.",
                    "Its energy must all be lost.",
                ],
                0,
                "Stillness does not erase stored energy.",
                ["energy_force_confusion", "energy_used_up_confusion"],
            ),
            short(
                "M3L1_C2",
                "A launcher inputs 200 J and 140 J becomes useful Motion Store. What is the leak trail?",
                ["60 J", "60"],
                "Subtract useful gain from total input.",
                ["ledger_balance_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L1_T1",
                "A pod loses 150 J from Height Store and gains 118 J in Motion Store. How much leaks away during the descent?",
                ["32 J", "32"],
                "Use the ledger again: store lost = store gained + leak.",
                ["ledger_balance_confusion"],
            ),
            short(
                "M3L1_T2",
                "Why must the Energy Ledger balance in every mission step?",
                [
                    "Because energy is tracked across stores and leaks rather than disappearing.",
                    "Because energy is accounted for in stores or leak trail.",
                    "Because energy must be conserved in a closed system.",
                    "Because total energy is conserved and must still be accounted for.",
                ],
                "Answer in terms of energy being stored, transferred, or spread out rather than destroyed.",
                ["energy_used_up_confusion", "ledger_balance_confusion"],
                acceptance_rules=acceptance_groups(
                    ("energy",),
                    ("conserved", "conservation", "accounted for", "balanced", "tracked"),
                    ("store", "stored", "stores", "system", "leak", "trail", "waste", "spread", "ledger"),
                ),
                skill_tags=["concept_explanation", "energy_accounting"],
            ),
            mcq(
                "M3L1_T3",
                "Which mission statement stays faithful to the Lift-Launch world?",
                [
                    "If no useful store rises, the input must show up somewhere else in the ledger.",
                    "If no store rises, the input energy no longer needs tracking.",
                    "Leak Trail means the machine did no transfer at all.",
                    "Stores only matter after the equations are memorized.",
                ],
                0,
                "The ledger keeps every joule visible somewhere.",
                ["ledger_balance_confusion", "energy_used_up_confusion"],
            ),
        ],
        "contract": contract(
            concept_targets=[
                "Treat energy as a store-and-transfer system rather than as a force label.",
                "Track useful gains and leak trail with a balanced ledger statement.",
                "Name Height Store and Motion Store before formal equations appear.",
            ],
            prerequisite_lessons=[],
            misconception_focus=[
                "energy_force_confusion",
                "energy_used_up_confusion",
                "ledger_balance_confusion",
            ],
            formulas=[
                formula(
                    "input energy = useful gain + wasted spread",
                    "Every machine input must show up as useful store gain, useful output, or leak trail.",
                    ["J"],
                    "Use for one mission step when you are accounting for where the transferred energy went.",
                ),
                formula(
                    "store lost from one place = store gained elsewhere + leak trail",
                    "When energy leaves one store, it must reappear in another place or as spread-out waste.",
                    ["J"],
                    "Use when one store empties into another during a mission sequence.",
                ),
            ],
            representations=[
                representation("words", "Describe the mission in terms of stores, hand-offs, and leak trail."),
                representation("table", "Use a ledger table to track input, useful gain, and wasted spread."),
                representation("model", "Use the Lift-Launch arena as the conceptual world before the formal names appear."),
                representation("formula", "Summarize the ledger balance with an accounting equation."),
            ],
            analogy_map={
                "comparison": "The Lift-Launch arena stands for an energy system where stores, transfers, and leaks can all be tracked.",
                "mapping": [
                    "The mission pod stands for the object whose energy stores are changing.",
                    "The Height Store and Motion Store stand for gravitational potential energy and kinetic energy.",
                    "The Leak Trail stands for dissipated energy spreading into heat, sound, or vibration.",
                ],
                "limit": "Real energy systems do not contain literal glowing stores or a visible ledger board; those are teaching devices.",
                "prediction_prompt": "If the useful store gain gets smaller while the same input stays fixed, what must happen somewhere else in the ledger?",
            },
            worked_examples=[
                worked(
                    "A lift inputs 400 J to raise a pod. After the lift, the Height Store has increased by 320 J. Find the leak trail.",
                    [
                        "Name the ledger story first: machine input must equal useful store gain plus leak trail.",
                        "Write 400 J = 320 J + leak trail.",
                        "Subtract 320 J from 400 J to find the missing part.",
                    ],
                    "Leak Trail = 80 J.",
                    "The ledger has to balance, so the 80 J that did not become Height Store must be the spread-out leak.",
                    "This makes 'missing energy' into an accounting step instead of a mystery.",
                ),
                worked(
                    "A pod drops and loses 150 J from Height Store. Its Motion Store rises by 118 J before it reaches the lower deck. Find the leak trail during the drop.",
                    [
                        "Treat the drop as energy leaving one store and entering another plus leaks.",
                        "Write 150 J = 118 J + leak trail.",
                        "Subtract 118 J from 150 J to find what spread into the Leak Trail.",
                    ],
                    "Leak Trail = 32 J.",
                    "Because the Height Store loss must reappear somewhere, the 32 J difference is the leaked part of the transfer.",
                    "This is the first step toward full ledger-style energy transfer calculations.",
                ),
            ],
            visual_assets=[
                visual(
                    "m3-l1-energy-ledger",
                    "energy_ledger",
                    "Lift-Launch energy ledger",
                    "Show the pod, stores, machine input, and leak trail in one accounting picture.",
                    "The world introduces energy as stores, hand-offs, and balanced accounting.",
                )
            ],
            animation_assets=[
                animation(
                    "m3-l1-energy-ledger-flow",
                    "energy_ledger",
                    "Ledger flow comparison",
                    "Animate clean and leaky transfers so the useful gain and leak trail can be compared.",
                )
            ],
            simulation_contract={
                "asset_id": "m3_l1_lift_launch_ledger_lab",
                "concept": "energy_ledger",
                "baseline_case": "Start with a 120 J machine input that raises a pod and leaks 20 J.",
                "comparison_tasks": [
                    "Hold the input fixed while increasing the leak trail.",
                    "Hold the leak fixed while increasing the useful store gain.",
                    "Compare a pure Height Store mission with a pure Motion Store mission.",
                ],
                "watch_for": "Students should name the store change first and then justify the ledger balance.",
                "takeaway": "Energy is stored, transferred, and accounted for across the whole mission.",
            },
            reflection_prompts=[
                "Explain why the Lift-Launch model makes energy easier to track than a disconnected list of formulas."
            ],
            mastery_skills=[
                "Identify Height Store and Motion Store in a mission story.",
                "Use a ledger statement to calculate leak trail or useful gain.",
                "Reject the idea that energy is a force.",
                "Reject the idea that energy simply disappears.",
                "Explain energy bookkeeping in words before formal equations.",
            ],
            variation_plan={
                "diagnostic": "Rotate between store-identification, leak-trail subtraction, and energy-not-force misconception prompts.",
                "concept_gate": "Switch between ledger-balance calculations and store-versus-leak explanation checks.",
                "mastery": "Use new mission stories with different store changes and leak values so no retry reuses the same accounting frame.",
            },
            scaffold_support=scaffold(
                "Energy sits in stores, moves by hand-offs, and the ledger must balance every mission step.",
                "Name the store story before you touch a number. Then decide whether the question is asking for useful gain, leak trail, or a store change, and write the balance in words before you calculate it.",
                "If a mission step has 200 J input and only 150 J useful gain, what must you look for next?",
                "Do not call energy a force, and do not call the untracked part 'gone.' The job is to find where it went.",
                "The Lift-Launch analogy helps because it makes stores, hand-offs, and leaks visible. The point is not the game art; the point is the accounting structure.",
                "In the analogy, what does the Leak Trail teach you that the store readouts alone cannot?",
                extra_sections=[
                    extra_section(
                        "Formal names arrive later",
                        "This lesson builds the bookkeeping world first so later equations summarize patterns students already trust.",
                    )
                ],
            ),
        ),
    }


def lesson_l2() -> Dict[str, Any]:
    return {
        "id": "M3_L2",
        "title": "Height Store and Gravitational Potential Energy",
        "sim": {
            "lab_id": "m3_height_store_lab",
            "title": "Height Store explorer",
            "description": "Vary load, deck level, and world grip to see how Height Store grows.",
            "instructions": [
                "Raise the same pod to several deck levels while keeping load fixed.",
                "Compare light and heavy pods reaching the same deck.",
                "Change the world grip and explain what happens to the same lift mission.",
            ],
            "outcomes": [
                "height_store_variable_confusion",
                "energy_equation_choice_confusion",
            ],
            "fields": [
                "load_rating",
                "deck_level",
                "world_grip",
                "height_store",
                "comparison_reasoning",
            ],
            "depth": "number of height-store comparisons justified with mass, height, and world-grip reasoning",
        },
        "analogy_text": (
            "The Height Store grows when the pod is lifted because it now has room to fall. In Lift-Launch terms, "
            "that store depends on three things at once: Load Rating, Deck Level, and World Grip."
        ),
        "commitment_prompt": "Before choosing any relationship, ask which of load, deck level, and world grip changed in the mission.",
        "micro_prompts": [
            prompt_block(
                "Compare a 2 kg pod and a 6 kg pod raised to the same deck in the same world.",
                "The heavier pod gains more Height Store at the same height.",
            ),
            prompt_block(
                "Compare the same pod lifted 3 m and 9 m in the same world.",
                "More deck height gives more Height Store directly.",
            ),
            prompt_block(
                "Compare the same lift mission in a weak-grip world and a strong-grip world.",
                "A stronger world pull makes the height store larger for the same mass and height.",
            ),
        ],
        "diagnostic": [
            mcq(
                "M3L2_D1",
                "Which set of variables determines Height Store in the Lift-Launch model?",
                [
                    "Load Rating, World Grip, and Deck Level",
                    "Speed, time, and color",
                    "Power, current, and resistance",
                    "Only Deck Level",
                ],
                0,
                "Height Store depends on the load, the field, and the height.",
                ["height_store_variable_confusion"],
            ),
            mcq(
                "M3L2_D2",
                "If the same pod is lifted twice as high in the same world, its Height Store becomes...",
                ["twice as large", "four times as large", "half as large", "unchanged"],
                0,
                "Height enters directly into mgh.",
                ["height_store_variable_confusion"],
            ),
            short(
                "M3L2_D3",
                "A 4 kg pod is lifted 5 m in a world where g = 10 N/kg. What Height Store does it gain?",
                ["200 J", "200"],
                "Use Height Store = mgh.",
                ["height_store_variable_confusion"],
            ),
            mcq(
                "M3L2_D4",
                "What does increasing World Grip do to the Height Store for the same pod and deck level?",
                [
                    "It increases the store directly.",
                    "It leaves the store unchanged.",
                    "It only affects Motion Store.",
                    "It removes the role of mass.",
                ],
                0,
                "A stronger gravitational field gives a larger mgh value.",
                ["height_store_variable_confusion"],
            ),
        ],
        "inquiry": [
            prompt_block(
                "Hold Load Rating and World Grip fixed while you change only the Deck Level.",
                "The store should scale directly with height.",
            ),
            prompt_block(
                "Hold Deck Level fixed while you compare a light pod and a heavy pod.",
                "Heavier pods gain more Height Store at the same height.",
            ),
            prompt_block(
                "Explain why the same height gain is not the same energy gain in every world.",
                "World Grip has to stay visible in the story.",
            ),
        ],
        "recon_prompts": [
            "Explain why gravitational potential energy is not a height-only quantity.",
            "Explain how the Lift-Launch Height Store prepares students to understand E_p = mgh.",
        ],
        "capsule_prompt": (
            "Height Store depends on load, world grip, and deck level together. The formal summary is E_p = mgh."
        ),
        "capsule_checks": [
            mcq(
                "M3L2_C1",
                "For the same pod and world, tripling the Deck Level makes the Height Store...",
                ["three times as large", "nine times as large", "one third as large", "unchanged"],
                0,
                "Height is a direct factor in mgh.",
                ["height_store_variable_confusion"],
            ),
            short(
                "M3L2_C2",
                "A 2 kg pod gains 60 J of Height Store in a world where g = 10 N/kg. Through what height was it lifted?",
                ["3 m", "3"],
                "Rearrange E_p = mgh when height is the unknown.",
                ["height_store_variable_confusion", "energy_equation_choice_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L2_T1",
                "A 6 kg pod is lifted 4 m where g = 10 N/kg. What Height Store does it gain?",
                ["240 J", "240"],
                "Use mgh directly.",
                ["height_store_variable_confusion"],
            ),
            mcq(
                "M3L2_T2",
                "Two pods reach the same deck in the same world. Pod A has double the mass of Pod B. Which statement is true?",
                [
                    "Pod A gains double the Height Store.",
                    "Both gain the same Height Store because the height is the same.",
                    "Pod A gains four times the Height Store.",
                    "Pod A gains half the Height Store.",
                ],
                0,
                "Mass changes Height Store directly.",
                ["height_store_variable_confusion"],
            ),
            short(
                "M3L2_T3",
                "A pod gains 300 J of Height Store when lifted 5 m in a world with g = 10 N/kg. What is its mass?",
                ["6 kg", "6"],
                "Rearrange E_p = mgh when mass is the unknown.",
                ["height_store_variable_confusion", "energy_equation_choice_confusion"],
            ),
        ],
        "contract": contract(
            concept_targets=[
                "Use the Lift-Launch Height Store to motivate gravitational potential energy.",
                "Keep mass, world grip, and height visible in every comparison.",
                "Rearrange mgh when one variable is unknown.",
            ],
            prerequisite_lessons=["M3_L1"],
            misconception_focus=[
                "height_store_variable_confusion",
                "energy_equation_choice_confusion",
            ],
            formulas=[
                formula(
                    "Height Store proportional to Load Rating x World Grip x Deck Level",
                    "Before the formal name appears, students should see the store growing with mass, field strength, and height together.",
                    ["J"],
                    "Use as the conceptual pattern before the compact equation is revealed.",
                ),
                formula(
                    "E_p = mgh",
                    "Gravitational potential energy equals mass times gravitational field strength times height change.",
                    ["J"],
                    "Use when a lifting story changes the object's height in a gravitational field.",
                ),
            ],
            representations=[
                representation("words", "Explain why a heavier pod or stronger world gives a larger Height Store."),
                representation("diagram", "Show pods on different decks in worlds with different grip strengths."),
                representation("table", "Compare several lift missions by mass, height, world grip, and Height Store."),
                representation("formula", "Calculate or rearrange mgh."),
            ],
            analogy_map={
                "comparison": "Height Store is the Lift-Launch name for gravitational potential energy.",
                "mapping": [
                    "Load Rating maps to mass.",
                    "Deck Level maps to height above the chosen reference.",
                    "World Grip maps to gravitational field strength g.",
                ],
                "limit": "The analogy gives a visible shelf-like store, but gravitational potential energy is a property of the mass-field-position system.",
                "prediction_prompt": "If the world grip doubles while the same pod reaches the same deck, what should happen to the Height Store?",
            },
            worked_examples=[
                worked(
                    "A 5 kg pod is lifted 8 m in a world where g = 10 N/kg. Find the Height Store gained.",
                    [
                        "Identify the quantity: this is a Height Store or gravitational potential energy story.",
                        "Write E_p = mgh.",
                        "Substitute 5, 10, and 8 to get 5 x 10 x 8.",
                    ],
                    "Height Store gained = 400 J.",
                    "The pod's mass, world grip, and deck level all contribute directly, so E_p = 5 x 10 x 8 = 400 J.",
                    "This makes the store rule concrete before students compare more subtle cases.",
                ),
                worked(
                    "A learner says 'only the height matters because gravitational potential energy is about height.' Evaluate the claim.",
                    [
                        "Check the full relationship instead of the name alone.",
                        "Notice that E_p = mgh contains mass and world grip as well as height.",
                        "Compare two pods lifted to the same height: the heavier one gains more Height Store.",
                    ],
                    "The claim is wrong because Height Store depends on mass and world grip as well as height.",
                    "The equation shows three direct factors, so a height-only explanation leaves out two essential variables.",
                    "This blocks a common simplification before it turns into a persistent formula error.",
                ),
            ],
            visual_assets=[
                visual(
                    "m3-l2-height-store",
                    "height_store",
                    "Height Store comparison",
                    "Compare how load, world grip, and deck level change the same store.",
                    "Higher, heavier, or stronger-grip lift missions all create more Height Store.",
                )
            ],
            animation_assets=[
                animation(
                    "m3-l2-height-store-rise",
                    "height_store",
                    "Rising deck comparison",
                    "Animate the same pod reaching higher decks in different worlds to compare store growth.",
                )
            ],
            simulation_contract={
                "asset_id": "m3_l2_height_store_lab",
                "concept": "height_store",
                "baseline_case": "Start with a 3 kg pod lifted 4 m where g = 10 N/kg.",
                "comparison_tasks": [
                    "Double the height while keeping the same pod and world.",
                    "Double the mass while keeping the same height and world.",
                    "Change world grip while keeping mass and height fixed.",
                ],
                "watch_for": "Students should say which variable changed before they predict how the store changes.",
                "takeaway": "Height Store is gravitational potential energy, and it depends on mass, g, and height together.",
            },
            reflection_prompts=[
                "Why is it dangerous to remember only the word 'height' and ignore the other factors in gravitational potential energy?"
            ],
            mastery_skills=[
                "Calculate Height Store with E_p = mgh.",
                "Explain why mass affects gravitational potential energy.",
                "Explain why world grip affects gravitational potential energy.",
                "Compare direct proportional changes in height-store stories.",
                "Rearrange mgh to solve for height or mass.",
            ],
            variation_plan={
                "diagnostic": "Rotate between direct mgh calculations, one-variable proportionality checks, and world-grip interpretation questions.",
                "concept_gate": "Swap between rearrangement items and explanatory comparisons that hold one or two variables fixed.",
                "mastery": "Use fresh lift missions with different masses, heights, and worlds so students must choose the changing factor each time.",
            },
            scaffold_support=scaffold(
                "Height Store grows with load, world grip, and deck level together.",
                "Decide first that the story is about lifting to a higher position in a gravitational field. Then name the three factors m, g, and h before you substitute any numbers.",
                "If two pods reach the same deck in the same world but one is heavier, which factor tells you their Height Stores differ?",
                "Do not let the word 'height' trick you into deleting mass or world grip from the story.",
                "The Lift-Launch shelf image is useful because it makes the store look bigger for heavier pods and higher decks. The real takeaway is the three-factor pattern.",
                "In the analogy, what does changing the World Grip knob teach you about the formal equation?",
            ),
        ),
    }


def lesson_l3() -> Dict[str, Any]:
    return {
        "id": "M3_L3",
        "title": "Motion Store and Kinetic Energy",
        "sim": {
            "lab_id": "m3_motion_store_lab",
            "title": "Motion Store explorer",
            "description": "Use a Motion Grid to compare how mass and speed fill the Motion Store.",
            "instructions": [
                "Keep load fixed and increase motion pace to see the Motion Grid grow.",
                "Compare doubling load with doubling speed.",
                "Use the grid to explain why speed matters more strongly than many learners expect.",
            ],
            "outcomes": [
                "motion_store_speed_squared_confusion",
                "energy_equation_choice_confusion",
            ],
            "fields": [
                "load_rating",
                "motion_pace",
                "motion_store",
                "grid_area",
                "comparison_reasoning",
            ],
            "depth": "number of mass-speed comparisons justified with the squared-speed idea rather than one-variable shortcuts",
        },
        "analogy_text": (
            "The Motion Store grows when the pod moves faster, and the Motion Grid makes the growth visible. "
            "Load Rating matters directly, but Motion Pace matters especially strongly because doubling speed makes the store four times larger."
        ),
        "commitment_prompt": "Before you compare cases, decide whether the main change came from load, from speed, or from both together.",
        "micro_prompts": [
            prompt_block(
                "Compare a 2 kg pod at 4 m/s with the same pod at 8 m/s.",
                "Doubling speed does much more than doubling the number written beside the speed slider.",
            ),
            prompt_block(
                "Compare doubling load with doubling speed for the same pod mission.",
                "One is a direct factor; the other is squared.",
            ),
            prompt_block(
                "A learner says 'speed only adds a bit more energy because it is just one number getting bigger.' Repair that idea.",
                "Use the Motion Grid to make the squared effect visible.",
            ),
        ],
        "diagnostic": [
            mcq(
                "M3L3_D1",
                "If the same pod doubles its speed, its Motion Store becomes...",
                ["four times as large", "twice as large", "half as large", "unchanged"],
                0,
                "Kinetic energy depends on speed squared.",
                ["motion_store_speed_squared_confusion"],
            ),
            mcq(
                "M3L3_D2",
                "If the same speed is kept but the load doubles, the Motion Store becomes...",
                ["twice as large", "four times as large", "half as large", "unchanged"],
                0,
                "Mass changes the store directly.",
                ["motion_store_speed_squared_confusion"],
            ),
            short(
                "M3L3_D3",
                "A 3 kg pod moves at 4 m/s. What Motion Store does it have?",
                ["24 J", "24"],
                "Use E_k = 0.5mv^2.",
                ["motion_store_speed_squared_confusion"],
            ),
            mcq(
                "M3L3_D4",
                "Which change usually increases Motion Store more strongly?",
                [
                    "doubling speed",
                    "doubling mass",
                    "doubling the time shown on the clock",
                    "doubling the deck level",
                ],
                0,
                "The squared-speed term dominates the comparison.",
                ["motion_store_speed_squared_confusion"],
            ),
        ],
        "inquiry": [
            prompt_block(
                "Use the Motion Grid to compare 3 m/s, 6 m/s, and 9 m/s for the same pod.",
                "Look for a faster-than-linear growth pattern.",
            ),
            prompt_block(
                "Keep speed fixed and change only Load Rating.",
                "This change is simpler and proportional.",
            ),
            prompt_block(
                "Explain why a light fast pod can outrank a heavy slow pod in Motion Store.",
                "You need the full relationship, not one favored variable.",
            ),
        ],
        "recon_prompts": [
            "Explain why kinetic energy is a speed-squared story rather than a speed-only story.",
            "Explain why the Motion Grid is a better teaching picture than just reading the formula out loud.",
        ],
        "capsule_prompt": (
            "Motion Store depends on Load Rating and Motion Pace, with speed squared. The formal relationship is E_k = 0.5mv^2."
        ),
        "capsule_checks": [
            mcq(
                "M3L3_C1",
                "Which variable is squared in the Motion Store equation?",
                ["speed", "mass", "time", "height"],
                0,
                "Only the speed term is squared.",
                ["motion_store_speed_squared_confusion"],
            ),
            short(
                "M3L3_C2",
                "A 2 kg pod has 64 J of Motion Store. What is v^2?",
                ["64", "64 m^2/s^2"],
                "Solve 64 = 0.5 x 2 x v^2.",
                ["motion_store_speed_squared_confusion", "energy_equation_choice_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L3_T1",
                "A 4 kg pod moves at 5 m/s. What Motion Store does it have?",
                ["50 J", "50"],
                "Substitute into E_k = 0.5mv^2.",
                ["motion_store_speed_squared_confusion"],
            ),
            mcq(
                "M3L3_T2",
                "Which pod has the larger Motion Store?",
                [
                    "a 2 kg pod at 8 m/s",
                    "a 4 kg pod at 4 m/s",
                    "they are equal",
                    "there is not enough information",
                ],
                0,
                "Use the full equation rather than comparing one variable only.",
                ["motion_store_speed_squared_confusion"],
            ),
            short(
                "M3L3_T3",
                "Why does doubling speed not just double the Motion Store?",
                [
                    "Because kinetic energy depends on speed squared.",
                    "Because the speed term is squared in 0.5mv^2.",
                ],
                "Mention the squared-speed relationship, not just 'it gets bigger.'",
                ["motion_store_speed_squared_confusion"],
                acceptance_rules=acceptance_groups(
                    ("speed", "v"),
                    ("square", "squared", "v^2"),
                ),
                skill_tags=["concept_explanation", "speed_squared_reasoning"],
            ),
        ],
        "contract": contract(
            concept_targets=[
                "Use the Motion Store to motivate kinetic energy as a mass-and-speed-squared relationship.",
                "Compare the effects of changing mass and speed without collapsing them together.",
                "Rearrange kinetic-energy relationships when one variable is unknown.",
            ],
            prerequisite_lessons=["M3_L1"],
            misconception_focus=[
                "motion_store_speed_squared_confusion",
                "energy_equation_choice_confusion",
            ],
            formulas=[
                formula(
                    "Motion Store proportional to Load Rating x (Motion Pace)^2",
                    "Before the compact formula appears, students should see that speed changes the store much more strongly than a direct factor.",
                    ["J"],
                    "Use as the conceptual pattern behind the Motion Grid.",
                ),
                formula(
                    "E_k = 0.5mv^2",
                    "Kinetic energy equals one half times mass times speed squared.",
                    ["J"],
                    "Use for translational motion when mass and speed are known or can be solved for.",
                ),
            ],
            representations=[
                representation("words", "Explain why speed is the stronger lever in kinetic energy."),
                representation("graph", "Use the Motion Grid or area growth idea to show the squared-speed effect."),
                representation("table", "Compare mass, speed, and Motion Store across several pods."),
                representation("formula", "Calculate or rearrange E_k = 0.5mv^2."),
            ],
            analogy_map={
                "comparison": "Motion Store is the Lift-Launch name for kinetic energy.",
                "mapping": [
                    "Load Rating maps to mass.",
                    "Motion Pace maps to speed.",
                    "The Motion Grid makes the speed-squared dependence visible.",
                ],
                "limit": "A real moving object does not carry a literal grid inside it; the grid is only revealing the mathematical growth pattern.",
                "prediction_prompt": "If the same pod doubles its Motion Pace, how should the Motion Grid change?",
            },
            worked_examples=[
                worked(
                    "A 3 kg pod moves at 6 m/s. Find the Motion Store.",
                    [
                        "Identify the quantity as kinetic energy or Motion Store.",
                        "Write E_k = 0.5mv^2 and square the speed first: 6^2 = 36.",
                        "Calculate 0.5 x 3 x 36.",
                    ],
                    "Motion Store = 54 J.",
                    "The speed must be squared before multiplying, so E_k = 0.5 x 3 x 36 = 54 J.",
                    "This keeps the key operation in the right order and blocks the common 'forget the square' error.",
                ),
                worked(
                    "A learner says doubling mass and doubling speed have the same effect on Motion Store because both just make the object 'more energetic.' Evaluate the claim.",
                    [
                        "Use the actual relationship instead of the vague phrase 'more energetic.'",
                        "Doubling mass multiplies E_k by 2, while doubling speed multiplies E_k by 4 because the speed term is squared.",
                        "So the two changes do not have the same effect.",
                    ],
                    "The claim is wrong because doubling speed quadruples the Motion Store, while doubling mass only doubles it.",
                    "The speed change is stronger because kinetic energy depends on v^2, not on v alone.",
                    "This contrast is central to later high-speed launch and gate-smash energy reasoning.",
                ),
            ],
            visual_assets=[
                visual(
                    "m3-l3-motion-store-grid",
                    "motion_store",
                    "Motion Grid comparison",
                    "Show how speed and load fill the Motion Store differently.",
                    "The Motion Grid makes the squared-speed effect visible instead of leaving it as a hidden algebraic detail.",
                )
            ],
            animation_assets=[
                animation(
                    "m3-l3-motion-store-rise",
                    "motion_store",
                    "Motion Store growth",
                    "Animate several speed doublings so the Motion Grid area grows faster than linearly.",
                )
            ],
            simulation_contract={
                "asset_id": "m3_l3_motion_store_lab",
                "concept": "motion_store",
                "baseline_case": "Start with a 2 kg pod moving at 4 m/s.",
                "comparison_tasks": [
                    "Double the speed while keeping the load fixed.",
                    "Double the load while keeping the speed fixed.",
                    "Compare a heavy slow pod with a light fast pod.",
                ],
                "watch_for": "Students should say when speed is the dominant change and justify it with v^2.",
                "takeaway": "Motion Store is kinetic energy, and speed matters more strongly because it is squared.",
            },
            reflection_prompts=[
                "Why does the speed-squared idea make kinetic energy especially important in high-speed mission planning?"
            ],
            mastery_skills=[
                "Calculate Motion Store with E_k = 0.5mv^2.",
                "Explain why speed has a squared effect.",
                "Compare mass and speed changes correctly.",
                "Rearrange kinetic-energy relationships for unknowns.",
                "Reject one-variable comparison shortcuts.",
            ],
            variation_plan={
                "diagnostic": "Rotate between direct E_k questions, factor-comparison prompts, and speed-squared misconception checks.",
                "concept_gate": "Swap between narrative comparisons and algebraic rearrangement tasks.",
                "mastery": "Use fresh mass-speed combinations and contrast cases so students cannot rely on memorized numeric patterns.",
            },
            scaffold_support=scaffold(
                "Motion Store depends on load directly and on speed through a squared relationship.",
                "Name the story as a moving-store problem first. Then write E_k = 0.5mv^2, square the speed, and only then multiply by the mass term and the one-half factor.",
                "If the same pod doubles its speed, what should you expect before you touch the calculator?",
                "Do not compare moving objects by speed alone or by mass alone when both matter.",
                "The Motion Grid is helpful because it makes the speed-squared growth feel less arbitrary. Students can see why the store jumps sharply as speed increases.",
                "In the analogy, why does the Motion Grid grow faster than the speed slider itself?",
            ),
        ),
    }


def lesson_l4() -> Dict[str, Any]:
    return {
        "id": "M3_L4",
        "title": "Energy Hand-offs and Work Done",
        "sim": {
            "lab_id": "m3_energy_handoff_lab",
            "title": "Energy hand-off explorer",
            "description": "Decide when a machine is handing energy into a store and which work equation matches the mission story.",
            "instructions": [
                "Compare a lift that raises a pod with a push that moves the pod along a track.",
                "Match a store increase to W = ΔE and a force-distance story to W = Fd.",
                "Explain why no displacement means no work done by that force.",
            ],
            "outcomes": [
                "work_hand_off_confusion",
                "energy_equation_choice_confusion",
            ],
            "fields": [
                "force",
                "distance",
                "store_change",
                "work_done",
                "equation_choice",
            ],
            "depth": "number of mission stories matched to the correct hand-off equation with a clear reason",
        },
        "analogy_text": (
            "In Lift-Launch, any increase in Height Store or Motion Store requires an Energy Hand-off. "
            "When the hand-off is described by a store change, use W = ΔE. When the story gives a steady force through a distance in the force direction, use W = Fd."
        ),
        "commitment_prompt": "Before you calculate, decide whether the story is giving you a store change directly or a force acting through a distance.",
        "micro_prompts": [
            prompt_block(
                "Compare a launcher that gives the pod 500 J of Motion Store with a push of 50 N through 10 m.",
                "Both describe work done, but one begins with a store change and the other begins with force and distance.",
            ),
            prompt_block(
                "Compare pushing a crate 4 m with pushing a wall that does not move.",
                "A force can exist without doing work if it causes no displacement.",
            ),
            prompt_block(
                "A lift raises the pod and the Height Store rises by 240 J. Which equation family starts the job more directly?",
                "Use the description that the story gives you most directly.",
            ),
        ],
        "diagnostic": [
            mcq(
                "M3L4_D1",
                "A lift increases a pod's Height Store by 300 J with negligible leak. How much work does the lift do?",
                ["300 J", "150 J", "30 J", "0 J"],
                0,
                "Use W = ΔE when the store gain is given directly.",
                ["work_hand_off_confusion", "energy_equation_choice_confusion"],
            ),
            short(
                "M3L4_D2",
                "A steady 60 N push moves the pod 5 m in the force direction. What work is done?",
                ["300 J", "300"],
                "Use W = Fd for an aligned force-distance story.",
                ["work_hand_off_confusion"],
            ),
            mcq(
                "M3L4_D3",
                "A learner pushes hard on a sealed gate but the gate does not move. What work is done on the gate by that push?",
                ["0 J", "some work because the push feels hard", "equal to the force only", "it cannot be known"],
                0,
                "No displacement in the force direction means no work is done by that force in the simple model.",
                ["work_hand_off_confusion"],
            ),
            mcq(
                "M3L4_D4",
                "Which first question helps you choose between W = ΔE and W = Fd?",
                [
                    "Does the story give a store change directly or a force-through-distance story?",
                    "Is the pod painted blue or orange?",
                    "How long is the mission soundtrack?",
                    "Is the battery already fully charged?",
                ],
                0,
                "Equation choice should come from the physics story, not from grabbing familiar symbols.",
                ["energy_equation_choice_confusion"],
            ),
        ],
        "inquiry": [
            prompt_block(
                "Build one mission where the store change is given directly and one where only force and distance are given.",
                "The correct equation family should change with the information given.",
            ),
            prompt_block(
                "Keep the same force but change the distance moved.",
                "For aligned force and motion, work grows directly with distance.",
            ),
            prompt_block(
                "Remove the displacement while keeping the push visible.",
                "The hand-off should vanish when that force causes no motion.",
            ),
        ],
        "recon_prompts": [
            "Explain why work is best understood as an energy hand-off rather than as effort.",
            "Explain why choosing the right work equation is a story-interpretation problem before it is an algebra problem.",
        ],
        "capsule_prompt": (
            "Work is the energy hand-off. Use W = ΔE when the store change is the given story, and W = Fd when a force acts through a distance in the force direction."
        ),
        "capsule_checks": [
            mcq(
                "M3L4_C1",
                "If a pod gains 180 J of Motion Store and leaks are negligible, what work has been done on it?",
                ["180 J", "90 J", "18 J", "0 J"],
                0,
                "With negligible leak, the work equals the store gain.",
                ["work_hand_off_confusion", "energy_equation_choice_confusion"],
            ),
            short(
                "M3L4_C2",
                "A 25 N launcher pushes through 8 m in the same direction. What work is done?",
                ["200 J", "200"],
                "Multiply force by distance.",
                ["work_hand_off_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L4_T1",
                "A pod's Height Store rises by 450 J during a lift, with no leak mentioned. What work is done by the lift?",
                ["450 J", "450"],
                "Use W = ΔE when the store change is the given information.",
                ["work_hand_off_confusion", "energy_equation_choice_confusion"],
            ),
            short(
                "M3L4_T2",
                "A constant 40 N force moves the pod 9 m along the track. What work is done?",
                ["360 J", "360"],
                "Use W = Fd.",
                ["work_hand_off_confusion"],
            ),
            mcq(
                "M3L4_T3",
                "Which explanation is strongest?",
                [
                    "Work means an energy hand-off, so the equation choice depends on whether the story gives a store change or a force-distance transfer.",
                    "Work means effort, so the harder the machine feels, the bigger the answer.",
                    "Work is always force times distance even when no distance is given.",
                    "Work and power are the same because both use joules somewhere.",
                ],
                0,
                "The correct equation must match the physical hand-off story.",
                ["work_hand_off_confusion", "energy_equation_choice_confusion"],
            ),
        ],
        "contract": contract(
            concept_targets=[
                "Treat work as the energy hand-off that fills or empties stores.",
                "Choose between W = ΔE and W = Fd from the mission description.",
                "Reject effort-only and no-displacement work misconceptions.",
            ],
            prerequisite_lessons=["M3_L1", "M3_L2", "M3_L3"],
            misconception_focus=[
                "work_hand_off_confusion",
                "energy_equation_choice_confusion",
            ],
            formulas=[
                formula(
                    "W = ΔE",
                    "Work done is the change in energy when the hand-off is described through a store gain or loss.",
                    ["J"],
                    "Use when the problem gives the energy change directly.",
                ),
                formula(
                    "W = Fd",
                    "For an aligned force and displacement, work equals force multiplied by distance.",
                    ["J"],
                    "Use when a force causes displacement in the force direction.",
                ),
            ],
            representations=[
                representation("words", "Explain work as an energy hand-off rather than as effort."),
                representation("diagram", "Show lift, launcher, and push stories with store changes and track motion."),
                representation("equation_story", "Match the story type to W = ΔE or W = Fd."),
                representation("formula", "Calculate the work numerically once the story is classified."),
            ],
            analogy_map={
                "comparison": "Energy Hand-off is the Lift-Launch name for work done.",
                "mapping": [
                    "A lift handing energy into Height Store stands for work increasing gravitational potential energy.",
                    "A launcher or push through distance stands for force doing work along the track.",
                ],
                "limit": "Not every real work problem contains a visible machine panel announcing the store gain; the analogy is only making the transfer story explicit.",
                "prediction_prompt": "If the force stays but the pod does not move, what should happen to the hand-off value?",
            },
            worked_examples=[
                worked(
                    "A launcher increases a pod's Motion Store by 520 J, and leaks are negligible. Find the work done by the launcher.",
                    [
                        "Identify the story as a direct store-change hand-off.",
                        "Use W = ΔE because the energy gain is given directly.",
                        "Set W = 520 J.",
                    ],
                    "Work done = 520 J.",
                    "Because the launcher handed 520 J into the Motion Store, the work done equals that energy change.",
                    "This keeps students from forcing a force-distance equation onto the wrong kind of problem.",
                ),
                worked(
                    "A lift raises a pod so its Height Store increases from 120 J to 420 J with negligible leak. Find the work done.",
                    [
                        "Identify the story as a direct store-change hand-off.",
                        "Find the energy change first: ΔE = 420 J - 120 J = 300 J.",
                        "Use W = ΔE because the store increase is the given story.",
                    ],
                    "Work done = 300 J.",
                    "With negligible leak, the lift's work equals the Height Store increase, so W = ΔE = 300 J.",
                    "This gives students a genuine ΔE example where they must calculate the change before naming the work done.",
                ),
            ],
            visual_assets=[
                visual(
                    "m3-l4-energy-handoff",
                    "energy_handoff",
                    "Energy Hand-off board",
                    "Contrast store-change hand-offs with force-distance hand-offs in the same Lift-Launch world.",
                    "Work is one idea with two common entry routes: store change or force through distance.",
                )
            ],
            animation_assets=[
                animation(
                    "m3-l4-energy-handoff-flow",
                    "energy_handoff",
                    "Hand-off route comparison",
                    "Animate one mission described by ΔE and another described by Fd so the equation choice becomes visible.",
                )
            ],
            simulation_contract={
                "asset_id": "m3_l4_energy_handoff_lab",
                "concept": "energy_handoff",
                "baseline_case": "Start with a launcher that gives 200 J Motion Store and a separate push of 40 N through 5 m.",
                "comparison_tasks": [
                    "Decide which work route fits each mission story.",
                    "Hold force fixed and increase distance.",
                    "Hold the push but set distance to zero.",
                ],
                "watch_for": "Students should justify equation choice before doing arithmetic.",
                "takeaway": "Work is the energy hand-off, and the story tells you whether ΔE or Fd is the right entry point.",
            },
            reflection_prompts=[
                "Why is equation choice in work problems really a question about the type of energy hand-off taking place?"
            ],
            mastery_skills=[
                "Recognize work as an energy hand-off.",
                "Choose between W = ΔE and W = Fd.",
                "Calculate work from store change.",
                "Calculate work from force and distance.",
                "Reject effort-only and no-displacement misconceptions.",
            ],
            variation_plan={
                "diagnostic": "Rotate between direct ΔE stories, aligned force-distance stories, and no-displacement traps.",
                "concept_gate": "Swap numerical work calculations with equation-choice explanations.",
                "mastery": "Use new machine, lift, launcher, and track contexts so students must read the story rather than memorize a stem pattern.",
            },
            scaffold_support=scaffold(
                "Work is the energy hand-off that fills or empties stores.",
                "Classify the mission first. If the story gives a store change, use W = ΔE. If it gives a force acting through a distance in the same direction, use W = Fd. Then calculate.",
                "If a problem tells you the pod gained 300 J of Motion Store, what should you think about before using any other equation?",
                "Do not grab W = Fd just because it looks familiar. The story decides the route.",
                "The Lift-Launch model is powerful here because it makes the 'hand-off' idea common across lifts, launches, and pushes. The equations are just different ways into that same story.",
                "In the analogy, what clue tells you that ΔE is the cleaner starting point?",
            ),
        ),
    }


def lesson_l5() -> Dict[str, Any]:
    return {
        "id": "M3_L5",
        "title": "Transfer Rate, Useful Yield, and Machine Choice",
        "sim": {
            "lab_id": "m3_rate_yield_lab",
            "title": "Rate and yield explorer",
            "description": "Compare how fast machines transfer energy and how much of that transfer becomes useful.",
            "instructions": [
                "Hold the useful transfer fixed while changing the time taken.",
                "Hold the input fixed while changing the useful share and leak trail.",
                "Compare a high-power wasteful machine with a lower-power efficient machine.",
            ],
            "outcomes": [
                "power_energy_rate_confusion",
                "efficiency_power_distinction_confusion",
            ],
            "fields": [
                "machine_input",
                "time_taken",
                "useful_output",
                "transfer_rate",
                "useful_yield",
            ],
            "depth": "number of comparisons that keep rate and useful share conceptually separate while still calculating both correctly",
        },
        "analogy_text": (
            "The Transfer Rate Meter shows how quickly energy hand-offs happen, while the Useful Yield Meter shows what fraction of the input became the intended useful result. "
            "A machine can be fast but wasteful, or slower but efficient."
        ),
        "commitment_prompt": "Before you calculate, decide whether the question is about how fast the transfer happens, how much becomes useful, or both.",
        "micro_prompts": [
            prompt_block(
                "Compare two machines that each transfer 600 J, but one finishes in 3 s and the other in 6 s.",
                "Same total energy does not mean the same transfer rate.",
            ),
            prompt_block(
                "Compare two machines that each take 10 s, but one turns 80% of its input into useful output and the other turns 40% useful.",
                "Useful Yield is a fraction of input, not a timing measure.",
            ),
            prompt_block(
                "Can a very powerful machine still have poor Useful Yield?",
                "Power and efficiency judge different aspects of the mission.",
            ),
        ],
        "diagnostic": [
            mcq(
                "M3L5_D1",
                "Which statement defines Transfer Rate most accurately?",
                [
                    "how much energy is transferred each second",
                    "the useful fraction of the input",
                    "the total mass times the speed",
                    "the number of stores in the mission",
                ],
                0,
                "Power is energy transferred per second.",
                ["power_energy_rate_confusion"],
            ),
            short(
                "M3L5_D2",
                "A machine transfers 600 J in 3 s. What is its Transfer Rate?",
                ["200 W", "200"],
                "Use P = E / t.",
                ["power_energy_rate_confusion"],
            ),
            short(
                "M3L5_D3",
                "A machine takes in 500 J and gives 350 J of useful output. What is its Useful Yield as a percentage?",
                ["70%", "70"],
                "Use efficiency = useful output / total input x 100%.",
                ["efficiency_power_distinction_confusion"],
            ),
            mcq(
                "M3L5_D4",
                "Which statement can be true?",
                [
                    "A machine can be high-power but low-efficiency.",
                    "A machine with higher power must have higher efficiency.",
                    "A machine with 100% efficiency must take zero time.",
                    "Efficiency and power are the same quantity with different units.",
                ],
                0,
                "Power and efficiency answer different questions about the same machine.",
                ["power_energy_rate_confusion", "efficiency_power_distinction_confusion"],
            ),
        ],
        "inquiry": [
            prompt_block(
                "Keep total transferred energy fixed and shorten the transfer time.",
                "The rate should rise even though the total stays the same.",
            ),
            prompt_block(
                "Keep machine input fixed and change only the useful output.",
                "Useful Yield changes while total input stays put.",
            ),
            prompt_block(
                "Compare a fast wasteful machine with a slower efficient one.",
                "Students should learn to describe both judgments without collapsing them into one word.",
            ),
        ],
        "recon_prompts": [
            "Explain why power is a rate question but efficiency is a share question.",
            "Explain how one machine could beat another on power while losing on Useful Yield.",
        ],
        "capsule_prompt": (
            "Transfer Rate is power: P = E / t or P = W / t. Useful Yield is efficiency: useful output divided by total input, often written as a percentage."
        ),
        "capsule_checks": [
            mcq(
                "M3L5_C1",
                "If the same 400 J is transferred in half the time, the Transfer Rate becomes...",
                ["twice as large", "half as large", "unchanged", "zero"],
                0,
                "For the same energy, less time means higher power.",
                ["power_energy_rate_confusion"],
            ),
            short(
                "M3L5_C2",
                "A machine takes in 800 J and gives 600 J useful output. What is the Useful Yield percentage?",
                ["75%", "75"],
                "Divide useful output by total input, then convert to percent.",
                ["efficiency_power_distinction_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L5_T1",
                "A launcher transfers 960 J in 8 s. What is its power?",
                ["120 W", "120"],
                "Divide energy by time.",
                ["power_energy_rate_confusion"],
            ),
            short(
                "M3L5_T2",
                "A machine runs at 150 W for 12 s. How much energy does it transfer?",
                ["1800 J", "1800"],
                "Use E = Pt.",
                ["power_energy_rate_confusion"],
            ),
            short(
                "M3L5_T3",
                "Can a machine be powerful but inefficient? Explain briefly.",
                [
                    "Yes. Power is how quickly energy is transferred, while efficiency is the useful fraction of the input.",
                    "Yes, because a machine can transfer energy quickly but waste a lot of it.",
                ],
                "Mention both the fast transfer-rate idea and the useful-fraction idea.",
                ["power_energy_rate_confusion", "efficiency_power_distinction_confusion"],
                acceptance_rules=acceptance_groups(
                    ("yes", "it can"),
                    ("power", "rate", "quickly", "fast"),
                    ("efficiency", "useful", "waste", "fraction"),
                ),
                skill_tags=["concept_explanation", "rate_vs_yield"],
            ),
        ],
        "contract": contract(
            concept_targets=[
                "Distinguish Transfer Rate from Useful Yield in one machine story.",
                "Calculate power from energy and time and reverse the relationship when needed.",
                "Calculate efficiency as a useful-output fraction and interpret it conceptually.",
            ],
            prerequisite_lessons=["M3_L4"],
            misconception_focus=[
                "power_energy_rate_confusion",
                "efficiency_power_distinction_confusion",
            ],
            formulas=[
                formula(
                    "P = E / t and P = W / t",
                    "Power is the rate of energy transfer or the rate of doing work.",
                    ["W", "J/s"],
                    "Use when a total transfer and the time interval are known.",
                ),
                formula(
                    "efficiency = useful output / total input x 100%",
                    "Efficiency is the useful share of the input, often expressed as a percentage.",
                    ["%", "fraction"],
                    "Use when both the useful output and the total input are known or can be found.",
                ),
            ],
            representations=[
                representation("words", "Separate how fast a transfer happens from how useful that transfer is."),
                representation("table", "Compare machines by input, useful output, time, power, and efficiency."),
                representation("graph", "Show equal-energy different-time cases and equal-input different-yield cases."),
                representation("formula", "Calculate power, energy, time, or efficiency."),
            ],
            analogy_map={
                "comparison": "Transfer Rate is the power meter and Useful Yield is the efficiency meter in Lift-Launch.",
                "mapping": [
                    "A faster meter means more joules are transferred each second.",
                    "A higher Useful Yield meter means more of the input became the intended useful output.",
                ],
                "limit": "Real machines do not carry two perfect meters that announce their physics; the meters only separate two distinct judgments for learners.",
                "prediction_prompt": "If two machines transfer the same total energy but one finishes sooner, which meter changes and which one might stay the same?",
            },
            worked_examples=[
                worked(
                    "A lift transfers 1200 J in 6 s. Find the Transfer Rate.",
                    [
                        "Identify the quantity as power because the question asks how quickly energy is transferred.",
                        "Use P = E / t.",
                        "Calculate 1200 / 6.",
                    ],
                    "Transfer Rate = 200 W.",
                    "Power is the number of joules transferred each second, so 1200 J in 6 s gives 200 W.",
                    "This makes rate different from total amount right at the point of calculation.",
                ),
                worked(
                    "A launcher takes in 900 J and gives the pod 540 J of useful Motion Store. Find the Useful Yield.",
                    [
                        "Identify the quantity as efficiency because the question asks about the useful share of the input.",
                        "Use efficiency = useful output / total input x 100%.",
                        "Calculate 540 / 900 = 0.6, then convert to 60%.",
                    ],
                    "Useful Yield = 60%.",
                    "The useful share is 540 out of 900, so the machine converts 60% of its input into the intended output.",
                    "This keeps 'efficient' from collapsing into 'fast' or 'large.'",
                ),
            ],
            visual_assets=[
                visual(
                    "m3-l5-rate-yield",
                    "transfer_rate_yield",
                    "Rate and yield board",
                    "Contrast a fast wasteful machine with a slower efficient machine using separate meters.",
                    "Power and efficiency are different judgments, even when they describe the same mission machine.",
                )
            ],
            animation_assets=[
                animation(
                    "m3-l5-rate-yield-compare",
                    "transfer_rate_yield",
                    "Machine choice comparison",
                    "Animate the same total transfer happening at different rates and with different useful shares.",
                )
            ],
            simulation_contract={
                "asset_id": "m3_l5_rate_yield_lab",
                "concept": "transfer_rate_yield",
                "baseline_case": "Start with a machine that transfers 600 J in 6 s and converts 75% of that input usefully.",
                "comparison_tasks": [
                    "Keep the input fixed while changing the time taken.",
                    "Keep the input fixed while changing the useful output share.",
                    "Compare two machines where one wins on rate and the other wins on yield.",
                ],
                "watch_for": "Students should say which quantity is being judged before they calculate it.",
                "takeaway": "Power asks how fast the hand-off happens; efficiency asks how much of it is useful.",
            },
            reflection_prompts=[
                "Why can a machine that looks impressive because it is fast still be a poor choice in an energy-limited mission?"
            ],
            mastery_skills=[
                "Calculate power from energy and time.",
                "Rearrange power relationships to find energy or time.",
                "Calculate efficiency as a percentage.",
                "Interpret efficiency as a useful share, not as speed.",
                "Compare machines using both rate and yield without collapsing them together.",
            ],
            variation_plan={
                "diagnostic": "Rotate between power-definition prompts, direct P = E / t items, percentage-yield items, and rate-versus-yield distinctions.",
                "concept_gate": "Swap numeric calculation tasks with concept explanations about why power and efficiency are different.",
                "mastery": "Use fresh machine contexts that change input, time, and useful output independently so students must decide what is being asked.",
            },
            scaffold_support=scaffold(
                "Transfer Rate tells how fast the hand-off happens; Useful Yield tells what fraction of the input was useful.",
                "Ask two separate questions in order: first, is this a rate question or a useful-share question? Then choose P = E/t or the efficiency fraction. Only after that should you calculate.",
                "If two machines transfer the same energy but one finishes sooner, which quantity has clearly changed?",
                "Do not call an efficient machine powerful just because it wastes less, and do not call a powerful machine efficient just because it is fast.",
                "The dual-meter Lift-Launch picture is useful because it stops students from treating 'good machine' as one vague label. Rate and yield stay separate all the way through.",
                "In the analogy, what does the Useful Yield meter tell you that the Transfer Rate meter cannot?",
            ),
        ),
    }


def lesson_l6() -> Dict[str, Any]:
    return {
        "id": "M3_L6",
        "title": "Ledger Missions and Energy Accounting",
        "sim": {
            "lab_id": "m3_ledger_missions_lab",
            "title": "Ledger mission planner",
            "description": "Solve multi-step missions by choosing the right equation family and balancing the full energy ledger.",
            "instructions": [
                "Plan a mission that lifts the pod, launches it, and delivers useful output at the target.",
                "Track useful gains and leak trail at each step rather than only at the end.",
                "Explain why your chosen equation was the correct first step before doing the next calculation.",
            ],
            "outcomes": [
                "ledger_balance_confusion",
                "energy_equation_choice_confusion",
                "efficiency_power_distinction_confusion",
            ],
            "fields": [
                "load_rating",
                "deck_level",
                "motion_pace",
                "machine_input",
                "transfer_time",
                "useful_output",
                "leak_trail",
                "ledger_entries",
            ],
            "depth": "number of multi-step missions solved with justified equation choice and a balanced full-mission ledger",
        },
        "analogy_text": (
            "The Lift-Launch mission planner is where the whole module comes together. A real mission may lift the pod, launch it, leak some energy, and still need enough useful output at the end. "
            "The Energy Ledger must stay balanced across the entire chain, and each step demands the right relationship for that stage."
        ),
        "commitment_prompt": "Before you touch the numbers, mark the mission steps and choose the right equation family for each step.",
        "micro_prompts": [
            prompt_block(
                "A lift inputs 1500 J at 60% Useful Yield. What useful Height Store is gained before you ask about height?",
                "Pick the efficiency step first, then move to the store equation.",
            ),
            prompt_block(
                "A pod loses 500 J of Height Store and reaches the target with 420 J of Motion Store. What happened to the rest?",
                "Use the ledger before inventing a new equation.",
            ),
            prompt_block(
                "Two students start the same mission, but one begins with mgh and the other begins with efficiency. Which start is justified depends on which quantity the story gives first.",
                "Equation choice is part of the physics reasoning, not an afterthought.",
            ),
        ],
        "diagnostic": [
            short(
                "M3L6_D1",
                "A launcher inputs 900 J and operates at 80% Useful Yield. How much useful Motion Store can it give the pod?",
                ["720 J", "720"],
                "Find the useful share first.",
                ["efficiency_power_distinction_confusion", "energy_equation_choice_confusion"],
            ),
            short(
                "M3L6_D2",
                "A pod loses 500 J from Height Store and gains 380 J in Motion Store on the way down. How much leaks away?",
                ["120 J", "120"],
                "Use the ledger balance.",
                ["ledger_balance_confusion"],
            ),
            mcq(
                "M3L6_D3",
                "A mission brief gives mass, deck level, and world grip and asks for the useful store gained by lifting. Which equation family is the best first step?",
                ["gravitational potential energy", "kinetic energy", "power only", "efficiency only"],
                0,
                "Choose the relationship that matches the physical store being discussed.",
                ["energy_equation_choice_confusion"],
            ),
            mcq(
                "M3L6_D4",
                "Which planning statement is strongest?",
                [
                    "Use the ledger to map the steps, then choose the matching equation for each step.",
                    "Write down every formula you remember and hope one fits.",
                    "Start with power in every energy problem because it has the most letters.",
                    "Ignore the leak trail until the very end because it is usually small.",
                ],
                0,
                "Mixed missions are solved by story structure first, not by random formula grabbing.",
                ["energy_equation_choice_confusion", "ledger_balance_confusion"],
            ),
        ],
        "inquiry": [
            prompt_block(
                "Plan one mission that starts with a lift and one that starts with a launcher.",
                "The first equation should depend on the first store or transfer in the story.",
            ),
            prompt_block(
                "Hold the final useful target fixed while changing the leak trail.",
                "Students should see how extra leak increases the required input.",
            ),
            prompt_block(
                "Explain a full mission in ledger sentences before compressing it into a few linked equations.",
                "The planner is meant to keep the reasoning visible.",
            ),
        ],
        "recon_prompts": [
            "Explain why multi-step energy missions are really bookkeeping-and-choice problems before they are arithmetic problems.",
            "Explain how the Lift-Launch model helps students tell the difference between a useful gain, a transfer rate, and a leak trail in one long mission.",
        ],
        "capsule_prompt": (
            "In a full mission, choose the right relationship for each step, carry useful gains and leaks through the ledger, and only then move to the next equation."
        ),
        "capsule_checks": [
            short(
                "M3L6_C1",
                "A lift inputs 2000 J at 75% Useful Yield. How much Height Store does the pod gain?",
                ["1500 J", "1500"],
                "Find the useful output before moving on.",
                ["efficiency_power_distinction_confusion", "energy_equation_choice_confusion"],
            ),
            mcq(
                "M3L6_C2",
                "A launcher gives the pod 600 J of useful Motion Store, and 90 J leaks away. How much total input was required?",
                ["690 J", "510 J", "600 J", "90 J"],
                0,
                "Input equals useful gain plus leak.",
                ["ledger_balance_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L6_T1",
                "A lift inputs 1800 J at 60% Useful Yield. The useful output becomes Height Store. How much Height Store is gained?",
                ["1080 J", "1080"],
                "Use efficiency first because the useful share is being asked for.",
                ["efficiency_power_distinction_confusion", "energy_equation_choice_confusion"],
            ),
            short(
                "M3L6_T2",
                "A pod reaches the bottom of a drop having lost 700 J of Height Store. Its Motion Store at the bottom is 560 J. How much leaked away during the drop?",
                ["140 J", "140"],
                "Use the ledger: store lost = store gained + leak.",
                ["ledger_balance_confusion"],
            ),
            mcq(
                "M3L6_T3",
                "A mission asks whether a gate needing 650 J of Motion Store can be opened. Your launcher gives 800 J input at 70% Useful Yield. What is the best conclusion?",
                [
                    "No, because only 560 J becomes useful Motion Store.",
                    "Yes, because 800 J is bigger than 650 J.",
                    "Yes, because power was not mentioned.",
                    "No, because efficiency only matters for lifts.",
                ],
                0,
                "Find the useful output before comparing it with the required store target.",
                ["efficiency_power_distinction_confusion", "energy_equation_choice_confusion", "ledger_balance_confusion"],
            ),
        ],
        "contract": contract(
            concept_targets=[
                "Solve multi-step energy missions by balancing the ledger across the entire chain.",
                "Choose the right equation family from the physical story at each step.",
                "Use useful gains, leaks, and store changes to justify whether a mission succeeds.",
            ],
            prerequisite_lessons=["M3_L1", "M3_L2", "M3_L3", "M3_L4", "M3_L5"],
            misconception_focus=[
                "ledger_balance_confusion",
                "energy_equation_choice_confusion",
                "efficiency_power_distinction_confusion",
            ],
            formulas=[
                formula(
                    "E_start + input energy = E_end + useful output + leak trail",
                    "A full mission balances the starting stores, machine inputs, ending stores, useful outputs, and leaks.",
                    ["J"],
                    "Use when tracking an entire sequence of energy transfers across several steps.",
                ),
                formula(
                    "Choose mgh, 0.5mv^2, W = ΔE, W = Fd, P = E / t, or efficiency from the story step being described",
                    "No single equation owns the whole mission; the solver must match each step to the correct relation.",
                    ["J", "W", "%"],
                    "Use in planning before the arithmetic begins.",
                ),
            ],
            representations=[
                representation("words", "Explain the mission as a chain of store changes, hand-offs, useful outputs, and leaks."),
                representation("table", "Use a step-by-step Energy Ledger with one row per mission stage."),
                representation("model", "Use the Lift-Launch mission planner to keep store and transfer stories distinct."),
                representation("formula", "Link the correct equations across several justified steps."),
            ],
            analogy_map={
                "comparison": "The mission planner is the Lift-Launch version of a full energy-transfer calculation.",
                "mapping": [
                    "Each mission step maps to a specific store change or hand-off in the real physics story.",
                    "The planner's Useful Yield and Leak Trail columns map to efficiency and dissipated energy accounting.",
                    "The final gate or lift target maps to a useful output or required store amount.",
                ],
                "limit": "Real exam problems do not arrive with colored planner boxes already drawn; students must build the structure mentally or on paper.",
                "prediction_prompt": "If leak trail rises while the final useful target stays fixed, what must happen to the required input?",
            },
            worked_examples=[
                worked(
                    "A lift inputs 1500 J at 60% Useful Yield to raise a 30 kg pod in a world where g = 10 N/kg. Find the Height Store gained and then the height reached.",
                    [
                        "Plan the mission in two steps: first useful output from efficiency, then height from E_p = mgh.",
                        "Useful Height Store gain = 0.60 x 1500 J = 900 J.",
                        "Set 900 = 30 x 10 x h and solve for h.",
                    ],
                    "The pod gains 900 J of Height Store and reaches 3 m.",
                    "Efficiency gives the useful store gain first, and that 900 J becomes the input to the mgh step, so h = 900 / 300 = 3 m.",
                    "This example shows why equation choice and order matter in a chained mission.",
                ),
                worked(
                    "A pod drops and loses 800 J of Height Store. On the way to the gate, 150 J leaks away. Does it arrive with enough Motion Store to open a gate that needs 700 J?",
                    [
                        "Use the ledger first: Height Store lost = Motion Store gained + leak trail.",
                        "Write 800 J = Motion Store gained + 150 J.",
                        "Solve for Motion Store gained and compare it with the gate requirement.",
                    ],
                    "The pod reaches the gate with 650 J of Motion Store, so it does not have enough to open the 700 J gate.",
                    "After the 150 J leak, only 650 J remains as useful Motion Store, which is less than the 700 J target.",
                    "This is the capstone idea: energy problems become careful ledger reasoning instead of disconnected formula hunting.",
                ),
            ],
            visual_assets=[
                visual(
                    "m3-l6-ledger-missions",
                    "energy_ledger_mission",
                    "Ledger mission planner",
                    "Show a full lift-launch-target sequence with useful gains, leaks, and equation choice notes.",
                    "The planner turns mixed energy problems into visible bookkeeping and justified equation choice.",
                )
            ],
            animation_assets=[
                animation(
                    "m3-l6-ledger-mission-chain",
                    "energy_ledger_mission",
                    "Full mission chain",
                    "Animate a lift, launch, leak, and target hit sequence while the ledger fills step by step.",
                )
            ],
            simulation_contract={
                "asset_id": "m3_l6_ledger_missions_lab",
                "concept": "energy_ledger_mission",
                "baseline_case": "Start with a mission that lifts the pod, leaks 20% during launch, and must reach a target store threshold.",
                "comparison_tasks": [
                    "Solve one mission that begins with a lift and another that begins with a launcher.",
                    "Increase leak trail while keeping the final target fixed.",
                    "Compare two different equation routes and justify which one should come first.",
                ],
                "watch_for": "Students should plan in steps and explain why each equation belongs to that step.",
                "takeaway": "Extended energy problems are ledger-and-choice problems, not formula lotteries.",
            },
            reflection_prompts=[
                "How does the Lift-Launch mission planner change the way you think about long energy-transfer calculations?"
            ],
            mastery_skills=[
                "Choose the correct energy relationship for the first step of a mixed mission.",
                "Use efficiency to find useful store gains or required inputs.",
                "Use the ledger to find leak trail in multi-step transfers.",
                "Link one justified calculation into the next step.",
                "Judge whether a full mission succeeds by comparing useful output with the target requirement.",
            ],
            variation_plan={
                "diagnostic": "Rotate between full-ledger subtraction, efficiency-first planning, and equation-choice judgment prompts.",
                "concept_gate": "Swap between multistep numerical chains and mission-planning explanations.",
                "mastery": "Use fresh lift-launch-target missions with different leak levels and starting information so students must build the sequence anew each time.",
            },
            scaffold_support=scaffold(
                "A full energy mission is solved by stepwise ledger reasoning and justified equation choice.",
                "Mark the mission stages first. For each stage, write what changes store, what leaks, and what the target is. Then choose the equation that matches that stage and carry the result forward.",
                "If a mission gives total input and efficiency before it asks about height or speed, which quantity should you find first?",
                "Do not treat a multi-step mission like one giant plug-in exercise. The structure matters before the arithmetic.",
                "The Lift-Launch planner is deliberately explicit so students can see why mixed energy questions are really controlled bookkeeping. Once that structure is secure, the formal equations stop feeling disconnected.",
                "In the analogy, why is it dangerous to jump straight to a familiar formula without first marking the mission steps?",
            ),
        ),
    }


M3_SPEC = {
    "module_description": (
        "Module 3 upgrades energy into a full Lift-Launch system: the pod carries Height Store and Motion Store, "
        "machines perform Energy Hand-offs, Transfer Rate and Useful Yield stay distinct, and every multi-step mission "
        "is solved by balancing an Energy Ledger across useful gains and leak trail."
    ),
    "mastery_outcomes": [
        "Explain energy as stores, hand-offs, leaks, and balanced ledger entries rather than as a disconnected list of formulas.",
        "Use Height Store reasoning and E_p = mgh to compare and calculate gravitational potential energy in different worlds.",
        "Use Motion Store reasoning and E_k = 0.5mv^2 to compare and calculate kinetic energy, including the squared-speed effect.",
        "Treat work as an energy hand-off and choose correctly between W = ΔE and W = Fd from the mission story.",
        "Distinguish Transfer Rate from Useful Yield by calculating power and efficiency without collapsing them into one idea.",
        "Solve multi-step energy missions by choosing the right relationship at each step and balancing the full Energy Ledger.",
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


M3_BANK_EXPANSIONS: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
    "M3_L1": {
        "diagnostic": [
            mcq(
                "M3L1_D5",
                "Which mission description shows a hand-off rather than a store?",
                [
                    "The launcher transfers 180 J into the pod.",
                    "The pod currently has 180 J of Motion Store.",
                    "The pod is on the high deck.",
                    "The pod is heavier than before.",
                ],
                0,
                "A hand-off is an energy-transfer event, not a stored amount.",
                ["work_hand_off_confusion"],
            ),
            short(
                "M3L1_D6",
                "A mission inputs 500 J and 80 J leaks away. How much useful store gain remains?",
                ["420 J", "420"],
                "Use the ledger: input = useful gain + leak trail.",
                ["ledger_balance_confusion"],
            ),
        ],
        "capsule_checks": [
            short(
                "M3L1_C3",
                "In a few words, where does the 'missing' energy go if useful gain is smaller than input?",
                ["into the Leak Trail", "into leaks", "into wasted energy", "into heat or sound"],
                "Use Leak Trail or wasted-spread language, not disappearance language.",
                ["energy_used_up_confusion", "ledger_balance_confusion"],
                acceptance_rules=acceptance_groups(
                    ("leak", "waste", "heat", "sound", "spread"),
                ),
            ),
            mcq(
                "M3L1_C4",
                "Why is 'energy is a force' a weak statement?",
                [
                    "Because stores and transfers answer different questions from forces.",
                    "Because forces never matter in physics.",
                    "Because only motion can have force.",
                    "Because energy and force are the same unit.",
                ],
                0,
                "Keep energy-accounting language separate from force language.",
                ["energy_force_confusion"],
            ),
        ],
        "transfer": [
            mcq(
                "M3L1_T4",
                "If useful gain rises while input stays fixed, what must happen to the Leak Trail?",
                ["It must shrink.", "It must grow.", "It must stay fixed.", "It becomes irrelevant."],
                0,
                "Input still equals useful gain plus leak trail.",
                ["ledger_balance_confusion"],
            ),
            short(
                "M3L1_T5",
                "Why is energy not the same as force in the Lift-Launch model?",
                [
                    "Because energy is stored or transferred while force is a push interaction.",
                    "Because stores and hand-offs are different from forces.",
                ],
                "Use store-transfer language versus push-interaction language.",
                ["energy_force_confusion"],
                acceptance_rules=acceptance_groups(
                    ("store", "stored", "transfer", "hand-off", "ledger", "leak"),
                    ("force", "push", "interaction"),
                ),
            ),
            mcq(
                "M3L1_T6",
                "A pod is both high and moving. Which claim is strongest?",
                [
                    "It can hold both Height Store and Motion Store at once.",
                    "It must choose only one store.",
                    "It cannot hold energy while moving.",
                    "Only the Leak Trail can exist.",
                ],
                0,
                "Different stores can coexist in one mission state.",
                ["energy_force_confusion"],
            ),
        ],
    },
    "M3_L2": {
        "diagnostic": [
            mcq(
                "M3L2_D5",
                "If the same pod is lifted to the same height on a stronger-gravity world, the Height Store is...",
                ["larger", "smaller", "unchanged", "zero"],
                0,
                "World Grip is one of the three factors in the store.",
                ["height_store_variable_confusion"],
            ),
            short(
                "M3L2_D6",
                "A 3 kg pod gains 150 J of Height Store on a world with g = 10 N/kg. How high was it raised?",
                ["5 m", "5"],
                "Use h = E / mg.",
                ["height_store_variable_confusion"],
            ),
        ],
        "capsule_checks": [
            short(
                "M3L2_C3",
                "Why can a still pod have Height Store?",
                [
                    "Because being high gives room to fall in a gravitational field.",
                    "Because height stores energy even when pace is zero.",
                    "Because gravitational potential energy depends on position not motion.",
                    "Because the pod has energy because of where it is in the gravitational field.",
                ],
                "Explain it as position in a field, not as motion.",
                ["height_store_variable_confusion"],
                acceptance_rules=acceptance_groups(
                    ("high", "height", "position", "raised"),
                    ("fall", "gravitational", "gravity", "field", "potential"),
                ),
            ),
            mcq(
                "M3L2_C4",
                "Which formal equation summarizes the Height Store pattern?",
                ["E_p = mgh", "E_k = 0.5mv^2", "P = E / t", "W = Fd"],
                0,
                "Use the load-height-World-Grip equation.",
                ["height_store_variable_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L2_T4",
                "A 6 kg pod is raised 5 m on a world where g = 10 N/kg. What Height Store is gained?",
                ["300 J", "300"],
                "Use E_p = mgh.",
                ["height_store_variable_confusion"],
            ),
            short(
                "M3L2_T5",
                "A pod gains 360 J of Height Store when lifted 9 m on a world where g = 10 N/kg. What is its mass?",
                ["4 kg", "4"],
                "Use m = E / gh.",
                ["height_store_variable_confusion"],
            ),
            mcq(
                "M3L2_T6",
                "Why is 'gravitational potential energy depends only on height' incomplete?",
                [
                    "Because mass and field strength matter too.",
                    "Because height never matters.",
                    "Because only speed matters.",
                    "Because potential energy is only a force story.",
                ],
                0,
                "Keep all three mgh factors visible.",
                ["height_store_variable_confusion"],
            ),
        ],
    },
    "M3_L3": {
        "diagnostic": [
            mcq(
                "M3L3_D5",
                "If a pod's speed doubles while its mass stays the same, the Motion Store becomes...",
                ["four times as large", "twice as large", "half as large", "unchanged"],
                0,
                "The speed term is squared.",
                ["motion_store_speed_squared_confusion"],
            ),
            short(
                "M3L3_D6",
                "A pod has 100 J of Motion Store and mass 2 kg. What speed does it have?",
                ["10 m/s", "10"],
                "Use E_k = 0.5mv^2 and solve for v.",
                ["motion_store_speed_squared_confusion"],
            ),
        ],
        "capsule_checks": [
            short(
                "M3L3_C3",
                "Why does doubling speed not just double Motion Store?",
                [
                    "Because speed is squared.",
                    "Because kinetic energy depends on v squared.",
                    "Because doubling speed quadruples the store.",
                ],
                "Use the squared-speed idea in your answer.",
                ["motion_store_speed_squared_confusion"],
                acceptance_rules=acceptance_groups(
                    ("speed", "v"),
                    ("squared", "square", "v^2", "quadruple", "four times"),
                ),
            ),
            mcq(
                "M3L3_C4",
                "Which formal equation summarizes Motion Store?",
                ["E_k = 0.5mv^2", "E_p = mgh", "P = E / t", "W = Fd"],
                0,
                "Use the load-and-speed-squared equation.",
                ["motion_store_speed_squared_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L3_T4",
                "A 5 kg pod moves at 4 m/s. What Motion Store does it have?",
                ["40 J", "40"],
                "Use E_k = 0.5mv^2.",
                ["motion_store_speed_squared_confusion"],
            ),
            short(
                "M3L3_T5",
                "A pod has 162 J of Motion Store and mass 4 kg. What speed does it have?",
                ["9 m/s", "9"],
                "Solve E_k = 0.5mv^2 for v.",
                ["motion_store_speed_squared_confusion"],
            ),
            mcq(
                "M3L3_T6",
                "Which explanation best repairs 'fast means a little more energy'?",
                [
                    "Because Motion Store rises sharply with speed and can quadruple when speed doubles.",
                    "Because mass never matters.",
                    "Because energy depends only on the route shape.",
                    "Because moving fast removes Height Store automatically.",
                ],
                0,
                "The squared-speed effect is the key repair.",
                ["motion_store_speed_squared_confusion"],
            ),
        ],
    },
    "M3_L4": {
        "diagnostic": [
            mcq(
                "M3L4_D5",
                "A machine increases the pod's store energy by 180 J. What is the cleanest work statement?",
                [
                    "The machine did 180 J of work on the pod.",
                    "The machine had 180 W of power.",
                    "The machine had 180 N of force.",
                    "The pod had 180 m of displacement.",
                ],
                0,
                "When store change is known, work matches the energy transferred.",
                ["work_hand_off_confusion"],
            ),
            short(
                "M3L4_D6",
                "A launcher transfers 96 J into Motion Store while 24 J leaks away. How much input work did it do?",
                ["120 J", "120"],
                "Input work must cover useful gain plus leak.",
                ["work_hand_off_confusion", "ledger_balance_confusion"],
            ),
        ],
        "capsule_checks": [
            short(
                "M3L4_C3",
                "Why is 'work = effort' a poor physics definition?",
                [
                    "Because work is energy transferred.",
                    "Because work measures hand-off not how hard something feels.",
                    "Because effort language misses the transfer idea.",
                ],
                "Use hand-off or energy-transfer language.",
                ["work_hand_off_confusion"],
                acceptance_rules=acceptance_groups(
                    ("energy", "transfer", "hand-off", "store change", "change in store"),
                ),
            ),
            mcq(
                "M3L4_C4",
                "Which choice is usually cleaner if the question already tells you how much a store changed?",
                ["W = ΔE", "W = Fd first", "P = E / t", "efficiency = output / input"],
                0,
                "Start from the quantity the story gives directly.",
                ["work_hand_off_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L4_T4",
                "A 20 N push acts through 3 m in the same direction. What work is done?",
                ["60 J", "60"],
                "Use W = Fd in the simple aligned-force case.",
                ["work_hand_off_confusion"],
            ),
            short(
                "M3L4_T5",
                "Why is no-displacement pushing not counted as work in the simple model?",
                [
                    "Because there is no movement in the force direction.",
                    "Because work needs displacement in the force direction.",
                ],
                "Use force-direction displacement language.",
                ["work_hand_off_confusion"],
                acceptance_rules=acceptance_groups(
                    ("no movement", "no displacement", "did not move", "wall does not move"),
                    ("force direction", "same direction", "aligned"),
                    ("work", "hand-off", "transfer"),
                    ("nothing moves", "nothing moved", "stays still", "stationary"),
                    ("line of force", "direction of the force", "aligned direction"),
                    ("required", "needed", "must have", "has to have"),
                    ("no work", "zero work", "no hand-off", "no transfer"),
                ),
            ),
            mcq(
                "M3L4_T6",
                "Which statement keeps work and power separate?",
                [
                    "Work is the total hand-off; power is how fast the hand-off happens.",
                    "Work is rate and power is amount.",
                    "Work and power are interchangeable.",
                    "Power measures useful fraction only.",
                ],
                0,
                "Total transfer and rate are different ideas.",
                ["work_hand_off_confusion", "power_energy_rate_confusion"],
            ),
        ],
    },
    "M3_L5": {
        "diagnostic": [
            mcq(
                "M3L5_D5",
                "Which comparison keeps efficiency the same but changes power?",
                [
                    "Same input and useful fraction, shorter time.",
                    "Same input and time, bigger useful fraction.",
                    "Same useful output and bigger leak with same input.",
                    "Same time and lower input.",
                ],
                0,
                "Changing time changes power; changing useful fraction changes efficiency.",
                ["power_energy_rate_confusion", "efficiency_power_distinction_confusion"],
            ),
            short(
                "M3L5_D6",
                "A machine runs at 250 W for 8 s. How much energy does it transfer?",
                ["2000 J", "2000"],
                "Use E = Pt.",
                ["power_energy_rate_confusion"],
            ),
        ],
        "capsule_checks": [
            short(
                "M3L5_C3",
                "How can a machine be powerful but inefficient?",
                [
                    "It can transfer energy quickly but waste a lot of the input.",
                    "It can have a high rate but a lot of leak trail.",
                    "It can have high power and low useful yield.",
                ],
                "Keep transfer rate and useful fraction separate in your wording.",
                ["power_energy_rate_confusion", "efficiency_power_distinction_confusion"],
                acceptance_rules=acceptance_groups(
                    ("fast", "quickly", "high rate", "powerful", "high power"),
                    ("waste", "leak", "low efficiency", "low useful yield", "wasteful"),
                ),
            ),
            mcq(
                "M3L5_C4",
                "Which formula matches Transfer Rate?",
                ["P = E / t", "E_p = mgh", "E_k = 0.5mv^2", "efficiency = output / input x 100%"],
                0,
                "Transfer Rate is power.",
                ["power_energy_rate_confusion"],
            ),
        ],
        "transfer": [
            short(
                "M3L5_T4",
                "A machine transfers 1800 J in 6 s. What is its power?",
                ["300 W", "300"],
                "Use P = E / t.",
                ["power_energy_rate_confusion"],
            ),
            short(
                "M3L5_T5",
                "Why can two machines have the same power but different efficiency?",
                [
                    "Because they can transfer energy at the same rate but waste different amounts.",
                    "Because rate and useful fraction are different ideas.",
                    "Because the same power does not force the same useful yield.",
                ],
                "Use rate-versus-yield language.",
                ["efficiency_power_distinction_confusion"],
                acceptance_rules=acceptance_groups(
                    ("same rate", "same power", "same transfer rate"),
                    ("different waste", "different useful fraction", "different efficiency", "different yield", "different useful output"),
                ),
            ),
            mcq(
                "M3L5_T6",
                "A machine has 80% efficiency but low power. Which statement is strongest?",
                [
                    "It is good at avoiding waste but not especially fast at transferring energy.",
                    "It must be more powerful than every inefficient machine.",
                    "Its useful output must exceed its input.",
                    "It cannot do useful work.",
                ],
                0,
                "High yield does not automatically mean high rate.",
                ["efficiency_power_distinction_confusion", "power_energy_rate_confusion"],
            ),
        ],
    },
    "M3_L6": {
        "diagnostic": [
            mcq(
                "M3L6_D5",
                "A gate needs 600 J. The mission delivers 540 J at the final step. Which judgment is correct?",
                [
                    "The mission fails by 60 J.",
                    "The mission succeeds by 60 J.",
                    "The mission fails by 540 J.",
                    "The mission succeeds because some energy arrived.",
                ],
                0,
                "Compare the final useful amount with the target threshold.",
                ["ledger_balance_confusion", "energy_equation_choice_confusion"],
            ),
            short(
                "M3L6_D6",
                "A mission must supply 800 J of useful output and the final machine is 80% efficient. What input energy is required?",
                ["1000 J", "1000"],
                "Required input = useful output / efficiency.",
                ["efficiency_power_distinction_confusion", "energy_equation_choice_confusion"],
            ),
        ],
        "capsule_checks": [
            short(
                "M3L6_C3",
                "What should you decide before choosing equations in a long energy mission?",
                [
                    "Which store or hand-off each step describes.",
                    "The mission stages and ledger changes.",
                    "What changes, what leaks, and what the target is.",
                    "Which result from one step becomes the input to the next.",
                    "What output or bridge quantity each stage provides.",
                ],
                "Use store-change planning language, not just 'pick a formula'.",
                ["energy_equation_choice_confusion", "ledger_balance_confusion"],
                acceptance_rules=acceptance_groups(
                    ("step", "stage", "sequence", "order", "plan"),
                    ("store", "transfer", "hand-off", "leak", "target", "quantity", "result", "output", "input", "bridge"),
                ),
            ),
            mcq(
                "M3L6_C4",
                "Which judgment best fits a final target check?",
                [
                    "Compare the final useful amount with the required target.",
                    "Compare the starting amount with the largest equation.",
                    "Use the longest equation available.",
                    "Ignore any leaks after the first step.",
                ],
                0,
                "The final target cares about the final useful amount.",
                ["energy_equation_choice_confusion", "ledger_balance_confusion"],
            ),
        ],
        "transfer": [
            mcq(
                "M3L6_T4",
                "A lift inputs 2000 J at 70% Useful Yield. The next stage leaks 200 J before the gate. How much energy reaches the gate?",
                ["1200 J", "1400 J", "1800 J", "600 J"],
                0,
                "Find the useful lift gain first, then subtract the later leak.",
                ["energy_equation_choice_confusion", "ledger_balance_confusion"],
            ),
            short(
                "M3L6_T5",
                "Why should a long energy problem start with a mission plan instead of a formula guess?",
                [
                    "Because you need to know which step creates the next needed quantity.",
                    "Because stores, leaks, and targets must be separated first.",
                    "Because equation choice depends on the story sequence.",
                    "Because one step provides the input needed by the next.",
                    "Because later equations depend on earlier results.",
                ],
                "Use step-sequence and equation-choice language.",
                ["energy_equation_choice_confusion", "ledger_balance_confusion"],
                acceptance_rules=acceptance_groups(
                    ("step", "sequence", "stage"),
                    ("next quantity", "store", "leak", "target", "result", "output", "input", "bridge quantity"),
                    ("equation choice", "which equation", "formula", "equation", "depends", "provides", "feeds"),
                ),
            ),
            short(
                "M3L6_T6",
                "A pod loses 900 J from Height Store and gains 720 J of Motion Store by the gate. How much leaked away in that stage?",
                ["180 J", "180"],
                "Store lost = useful gain + leak.",
                ["ledger_balance_confusion"],
            ),
        ],
    },
}

M3_SECONDARY_BANK_EXPANSIONS: Dict[str, Dict[str, List[Dict[str, Any]]]] = {
    "M3_L1": {
        "diagnostic": [
            mcq(
                "M3L1_D7",
                "A pod stands on a high deck and also moves quickly. Which statement is strongest?",
                [
                    "It can hold both Height Store and Motion Store in the same mission state.",
                    "It must choose one store only.",
                    "Only the Leak Trail can exist if it is moving.",
                    "It has no energy because no transfer is happening now.",
                ],
                0,
                "Different stores can coexist in one story.",
                ["energy_force_confusion", "energy_used_up_confusion"],
            ),
            short(
                "M3L1_D8",
                "Why is the Leak Trail important in the Lift-Launch analogy?",
                [
                    "Because it shows where energy spreads out instead of becoming useful gain.",
                    "Because it keeps the ledger balanced by tracking wasted spread.",
                ],
                "Use leak, waste, spread, or balancing language.",
                ["energy_used_up_confusion", "ledger_balance_confusion"],
                acceptance_rules=acceptance_groups(
                    ("leak", "trail", "waste", "spread"),
                    ("balance", "account", "tracked"),
                ),
            ),
        ],
        "capsule_checks": [
            mcq(
                "M3L1_C5",
                "Which statement keeps store language and transfer language correctly separated?",
                [
                    "A store is what the pod has; a hand-off is how energy moves into or out of it.",
                    "A store and a hand-off are the same thing described twice.",
                    "The hand-off is only the force while the store is only the speed.",
                    "Leak Trail is another name for Motion Store.",
                ],
                0,
                "The lesson separates what energy is doing from where it sits.",
                ["energy_force_confusion", "work_hand_off_confusion"],
            ),
            short(
                "M3L1_C6",
                "Finish the idea: input energy = ...",
                [
                    "useful gain + leak trail",
                    "useful output + leak trail",
                ],
                "Use the ledger balance sentence.",
                ["ledger_balance_confusion"],
                acceptance_rules=acceptance_groups(
                    ("useful", "gain", "output"),
                    ("leak", "trail", "waste"),
                ),
            ),
        ],
        "transfer": [
            mcq(
                "M3L1_T7",
                "A machine inputs 900 J. The useful gain is 540 J and 180 J becomes Leak Trail. What must be true?",
                [
                    "Another 180 J must be accounted for somewhere else in the ledger.",
                    "The 180 J difference can be ignored because some energy is useful.",
                    "The machine created extra energy.",
                    "The useful gain should be changed to 900 J.",
                ],
                0,
                "Balanced accounting must still track the missing 180 J.",
                ["ledger_balance_confusion"],
            ),
            short(
                "M3L1_T8",
                "Why is it useful to treat an energy mission as a ledger of stores, hand-offs, and leaks rather than as a force story?",
                [
                    "Because it asks where energy is stored, transferred, or leaked rather than only what push acts now.",
                    "Because ledger reasoning tracks stores and hand-offs instead of confusing energy with force.",
                ],
                "Use store-transfer-ledger language against push-force language.",
                ["energy_force_confusion"],
                acceptance_rules=acceptance_groups(
                    ("store", "stored", "transfer", "hand-off", "ledger", "leak"),
                    ("force", "push"),
                    ("different", "rather than", "not the same"),
                ),
            ),
        ],
    },
    "M3_L2": {
        "diagnostic": [
            mcq(
                "M3L2_D7",
                "If the same Height Store is to be kept while World Grip doubles, what must happen to the lift height if mass stays fixed?",
                ["It must halve.", "It must double.", "It stays the same.", "It must quadruple."],
                0,
                "Keep the product mgh constant.",
                ["height_store_variable_confusion"],
            ),
            mcq(
                "M3L2_D8",
                "Which explanation best fits the Lift-Launch analogy?",
                [
                    "Height Store belongs to being high in a gravitational field, not to motion itself.",
                    "Height Store appears only when the pod is moving upward.",
                    "Height Store depends on time spent on the deck.",
                    "Height Store is another name for launch force.",
                ],
                0,
                "The analogy still points back to position in a field.",
                ["height_store_variable_confusion"],
            ),
        ],
        "capsule_checks": [
            mcq(
                "M3L2_C5",
                "Which change definitely doubles Height Store while the other two factors stay fixed?",
                ["doubling the height", "doubling the waiting time", "doubling the pod color brightness", "doubling the leak trail"],
                0,
                "Use the direct proportionality of mgh.",
                ["height_store_variable_confusion"],
            ),
            short(
                "M3L2_C6",
                "What does the World Grip setting stand for in formal physics?",
                [
                    "gravitational field strength",
                    "g",
                ],
                "Use the formal field-strength name or g.",
                ["height_store_variable_confusion"],
                acceptance_rules=acceptance_groups(
                    ("gravitational", "field", "strength"),
                    ("g",),
                ),
            ),
        ],
        "transfer": [
            short(
                "M3L2_T7",
                "A 4 kg pod has 320 J of Height Store on a world where g = 10 N/kg. How high is it above the reference level?",
                ["8 m", "8"],
                "Use h = E / mg.",
                ["height_store_variable_confusion"],
            ),
            mcq(
                "M3L2_T8",
                "Two worlds give the same Height Store to the same pod at the same deck level. What must be true?",
                [
                    "Their World Grip values are the same.",
                    "Their Motion Stores are the same.",
                    "Their launchers must be identical.",
                    "Their Leak Trails must be zero.",
                ],
                0,
                "At fixed mass and height, equal Height Store means equal g.",
                ["height_store_variable_confusion"],
            ),
        ],
    },
    "M3_L3": {
        "diagnostic": [
            mcq(
                "M3L3_D7",
                "If the same pod triples its speed, what happens to its Motion Store?",
                ["It becomes nine times as large.", "It triples.", "It doubles.", "It stays the same."],
                0,
                "Tripling speed multiplies v squared by nine.",
                ["motion_store_speed_squared_confusion"],
            ),
            mcq(
                "M3L3_D8",
                "Which comparison best shows the stronger speed effect?",
                [
                    "same mass, doubled speed",
                    "same speed, doubled mass",
                    "same speed, same mass",
                    "same mass, same color",
                ],
                0,
                "Hold mass fixed if you want to expose the speed-squared effect.",
                ["motion_store_speed_squared_confusion"],
            ),
        ],
        "capsule_checks": [
            mcq(
                "M3L3_C5",
                "Which statement is correct for equal speeds?",
                [
                    "The heavier pod has the larger Motion Store.",
                    "The lighter pod always has the larger Motion Store.",
                    "Both must have the same Motion Store regardless of mass.",
                    "Motion Store depends only on pace.",
                ],
                0,
                "At fixed speed, Motion Store is proportional to mass.",
                ["motion_store_speed_squared_confusion"],
            ),
            short(
                "M3L3_C6",
                "What formal symbol in the equation explains the sharp growth with pace?",
                ["v^2", "speed squared"],
                "Point to the squared speed term.",
                ["motion_store_speed_squared_confusion"],
                acceptance_rules=acceptance_groups(
                    ("v^2", "speed squared", "velocity squared", "squared"),
                ),
            ),
        ],
        "transfer": [
            short(
                "M3L3_T7",
                "A 3 kg pod moves at 10 m/s. What Motion Store does it have?",
                ["150 J", "150"],
                "Use E_k = 0.5mv^2.",
                ["motion_store_speed_squared_confusion"],
            ),
            mcq(
                "M3L3_T8",
                "Two pods have the same mass. Pod A has four times the Motion Store of Pod B. What is the best speed comparison?",
                [
                    "Pod A is moving twice as fast.",
                    "Pod A is moving four times as fast.",
                    "Pod A is moving the same speed.",
                    "Speed cannot be compared from Motion Store.",
                ],
                0,
                "At fixed mass, a fourfold energy rise means a doubled speed.",
                ["motion_store_speed_squared_confusion"],
            ),
        ],
    },
    "M3_L4": {
        "diagnostic": [
            mcq(
                "M3L4_D7",
                "Which story is most clearly a direct W = ΔE story?",
                [
                    "A pod's Motion Store rises by 260 J.",
                    "A force of 13 N acts through 2 m in the same direction.",
                    "A machine runs for 4 s at 90 W.",
                    "A pod is twice as heavy as before.",
                ],
                0,
                "Use the store change directly when it is already given.",
                ["work_hand_off_confusion"],
            ),
            mcq(
                "M3L4_D8",
                "If the same aligned force acts through twice the distance, the work done...",
                ["doubles", "quadruples", "halves", "stays the same"],
                0,
                "In the simple aligned case, work is proportional to distance.",
                ["work_hand_off_confusion"],
            ),
        ],
        "capsule_checks": [
            mcq(
                "M3L4_C5",
                "What must be true before you trust the simple W = Fd rule used in this lesson?",
                [
                    "The displacement story must be along the force direction.",
                    "The machine must be 100% efficient.",
                    "The object must be moving fast already.",
                    "The force must be the largest one in the problem.",
                ],
                0,
                "The model keeps the aligned-displacement condition explicit.",
                ["work_hand_off_confusion"],
            ),
            short(
                "M3L4_C6",
                "What does work measure in one phrase in this energy story?",
                [
                    "energy transferred",
                    "an energy hand-off",
                ],
                "Use transfer or hand-off language.",
                ["work_hand_off_confusion"],
                acceptance_rules=acceptance_groups(
                    ("energy",),
                    ("transfer", "hand-off"),
                ),
            ),
        ],
        "transfer": [
            short(
                "M3L4_T7",
                "A store rises by 240 J with no leak. How much work was done on the pod?",
                ["240 J", "240"],
                "With no leak, the work equals the store gain.",
                ["work_hand_off_confusion"],
            ),
            mcq(
                "M3L4_T8",
                "Why is work a better idea than 'effort' in this energy story?",
                [
                    "Because it tracks the actual transfer that changes stores.",
                    "Because effort always has units of joules.",
                    "Because effort tells you the useful fraction automatically.",
                    "Because effort removes the need for displacement.",
                ],
                0,
                "Work belongs to store change and transfer, not how hard something felt.",
                ["work_hand_off_confusion"],
            ),
        ],
    },
    "M3_L5": {
        "diagnostic": [
            mcq(
                "M3L5_D7",
                "Two machines have the same power. Which statement can still be true?",
                [
                    "One can be more efficient than the other.",
                    "They must waste the same amount.",
                    "They must transfer the same total energy in any time interval.",
                    "They must have the same Useful Yield and input energy.",
                ],
                0,
                "Equal rate does not force equal useful fraction.",
                ["efficiency_power_distinction_confusion"],
            ),
            mcq(
                "M3L5_D8",
                "A machine transfers 2400 J in 8 s. What is its power?",
                ["300 W", "200 W", "2408 W", "19200 W"],
                0,
                "Use P = E / t.",
                ["power_energy_rate_confusion"],
            ),
        ],
        "capsule_checks": [
            mcq(
                "M3L5_C5",
                "Which change raises efficiency without changing power in principle?",
                [
                    "A larger fraction of the same input becomes useful output while the transfer rate stays fixed.",
                    "The transfer time halves while the useful fraction stays fixed.",
                    "The input energy becomes larger in the same time with the same useful fraction.",
                    "The machine color changes to green.",
                ],
                0,
                "Useful fraction and transfer rate can be varied separately.",
                ["efficiency_power_distinction_confusion", "power_energy_rate_confusion"],
            ),
            short(
                "M3L5_C6",
                "What does power compare in one sentence?",
                [
                    "how much energy is transferred each second",
                    "energy transferred per unit time",
                ],
                "Use transfer-per-time language.",
                ["power_energy_rate_confusion"],
                acceptance_rules=acceptance_groups(
                    ("energy", "work", "transfer", "hand-off"),
                    ("time", "second", "per", "rate", "quickly"),
                ),
            ),
        ],
        "transfer": [
            short(
                "M3L5_T7",
                "A machine is 75% efficient and receives 1600 J of input. How much useful output does it deliver?",
                ["1200 J", "1200"],
                "Take 75% of the input.",
                ["efficiency_power_distinction_confusion"],
            ),
            mcq(
                "M3L5_T8",
                "Which judgment best fits an efficient but low-power machine?",
                [
                    "It wastes little energy but may still take a long time.",
                    "It must transfer more energy each second than every inefficient machine.",
                    "It cannot do a useful job.",
                    "Its useful output must exceed its input.",
                ],
                0,
                "Good yield does not guarantee a high rate.",
                ["efficiency_power_distinction_confusion", "power_energy_rate_confusion"],
            ),
        ],
    },
    "M3_L6": {
        "diagnostic": [
            mcq(
                "M3L6_D7",
                "A mission gives the useful lift gain and then asks for the speed after launch. What is the best first judgment?",
                [
                    "That useful lift gain is the starting energy for the next stage.",
                    "That power must be found before every other quantity.",
                    "That the biggest formula should be used first.",
                    "That leaks can be ignored because the useful gain is known.",
                ],
                0,
                "Use the previous stage output as the next stage input.",
                ["energy_equation_choice_confusion"],
            ),
            mcq(
                "M3L6_D8",
                "Which planner sentence is strongest?",
                [
                    "Stores, leaks, and targets must be mapped before equation choice.",
                    "The formal equation should be chosen before the mission is read.",
                    "Any energy equation can start the problem if the units match.",
                    "Long energy problems are just one substitution with more numbers.",
                ],
                0,
                "The planner is there to control the sequence.",
                ["energy_equation_choice_confusion", "ledger_balance_confusion"],
            ),
        ],
        "capsule_checks": [
            mcq(
                "M3L6_C5",
                "If a later stage leaks energy, when should that leak be applied?",
                [
                    "At the stage where it occurs, before the final target check.",
                    "Only after the target check.",
                    "Only if the mission already fails.",
                    "Never, because useful gain already includes every later change.",
                ],
                0,
                "Later leaks change the amount that reaches the next stage.",
                ["ledger_balance_confusion", "energy_equation_choice_confusion"],
            ),
            short(
                "M3L6_C6",
                "What is the final comparison in many mission problems?",
                [
                    "final useful amount against the target",
                    "compare the final useful energy to the required target",
                ],
                "Use final-useful-versus-target language.",
                ["energy_equation_choice_confusion"],
                acceptance_rules=acceptance_groups(
                    ("final", "useful"),
                    ("target", "required", "threshold", "goal"),
                    ("compare", "against", "to"),
                ),
            ),
        ],
        "transfer": [
            short(
                "M3L6_T7",
                "A mission needs 900 J after a stage that keeps only 75% of its incoming energy. How much energy must enter that stage?",
                ["1200 J", "1200"],
                "Work backward through the useful fraction.",
                ["energy_equation_choice_confusion"],
            ),
            mcq(
                "M3L6_T8",
                "Why is backward planning sometimes the cleanest move in M3_L6?",
                [
                    "Because the final target can tell you the earlier required store or input.",
                    "Because backward steps remove the need for efficiency.",
                    "Because working backward turns every problem into power only.",
                    "Because the first stage never matters if the final stage is known.",
                ],
                0,
                "Capstone missions often need the target traced back through earlier stages.",
                ["energy_equation_choice_confusion", "ledger_balance_confusion"],
            ),
        ],
    },
}

M3_EXTRA_SCAFFOLD_SECTIONS: Dict[str, List[Dict[str, str]]] = {
    "M3_L1": [
        {
            "heading": "Store versus hand-off test",
            "body": "Ask whether the sentence is naming energy the pod has now, or energy moving between places now. That single choice keeps stores, hand-offs, and leaks from collapsing into one vague idea.",
        },
        {
            "heading": "Ledger sentence frame",
            "body": "Train yourself to say: input hand-off = useful gain + Leak Trail. That sentence is the conceptual template underneath the arithmetic.",
        },
    ],
    "M3_L2": [
        {
            "heading": "Reference level awareness",
            "body": "Height Store depends on a chosen reference level. The important move is to track the height difference that actually changes the store, not just to notice that an object is 'high'.",
        },
        {
            "heading": "Proportional check before substitution",
            "body": "Before calculating, ask what would happen if one factor doubled while the other two stayed fixed. That builds the mgh relationship as a pattern rather than as a memorized string.",
        },
    ],
    "M3_L3": [
        {
            "heading": "Why speed is the surprise factor",
            "body": "Mass changes Motion Store directly, but speed changes it through a squared term. That is why qualitative predictions about fast motion often fail unless the squared effect is kept visible.",
        },
        {
            "heading": "Compare first, calculate second",
            "body": "Use quick comparisons such as same mass with doubled speed or same speed with doubled mass before you substitute numbers. This keeps the physical meaning ahead of the arithmetic.",
        },
    ],
    "M3_L4": [
        {
            "heading": "Two routes to the same hand-off",
            "body": "Sometimes work is easiest from force and distance; sometimes it is easiest from the store change. Advanced reasoning means choosing the route that matches the information the story actually gives.",
        },
        {
            "heading": "Displacement is not optional",
            "body": "A large force by itself does not guarantee work. In the simple lesson model, the transfer only counts when there is displacement in the force direction.",
        },
    ],
    "M3_L5": [
        {
            "heading": "Rate versus yield split",
            "body": "Power answers how quickly the hand-off happens. Efficiency answers how much of the input becomes useful. Keep those questions separate even when the same machine problem contains both.",
        },
        {
            "heading": "Machine-comparison habit",
            "body": "When two machines are compared, decide whether the story is comparing total transfer, time, useful fraction, or some combination. That habit stops 'more powerful' from being used as a synonym for 'better at everything'.",
        },
    ],
    "M3_L6": [
        {
            "heading": "Mission map before equations",
            "body": "Long problems become manageable when you mark the stages, the store changes, the leaks, and the final target before touching the formulas. The map is part of the physics, not an optional note.",
        },
        {
            "heading": "Backward planning is allowed",
            "body": "If the target is known at the end, work backward through later yields or leaks to find what an earlier stage had to provide. That is more advanced than grabbing the first familiar equation.",
        },
    ],
}

M3_EXTRA_WORKED_EXAMPLES: Dict[str, Dict[str, Any]] = {
    "M3_L1": worked(
        "A mission inputs 720 J. The useful store gain is 480 J, split equally between Height Store and Motion Store. Find the Leak Trail and each store amount.",
        [
            "Start with the full ledger: input = useful gain + Leak Trail.",
            "Subtract 480 J from 720 J to find the leaked part.",
            "Then split the 480 J useful gain equally between the two stores.",
        ],
        "Leak Trail = 240 J, Height Store = 240 J, Motion Store = 240 J.",
        "The leaked part is the difference between total input and useful gain, and the useful gain can then be partitioned between stores without changing the ledger total.",
        "This pushes the ledger beyond one missing-number step into a fuller accounting story.",
    ),
    "M3_L2": worked(
        "A 3 kg pod on a world where g = 8 N/kg is raised from 2 m to 9 m above the reference level. Find the Height Store gained.",
        [
            "Use the height change, not just the final height above the picture.",
            "Compute the rise: 9 m - 2 m = 7 m.",
            "Use E_p = mgh with 3 kg, 8 N/kg, and 7 m.",
        ],
        "Height Store gained = 168 J.",
        "The store change depends on the 7 m rise, so E_p = 3 x 8 x 7 = 168 J.",
        "This keeps reference-level reasoning visible instead of assuming height always starts from zero.",
    ),
    "M3_L3": worked(
        "Pod A has mass 2 kg and speed 12 m/s. Pod B has mass 8 kg and speed 6 m/s. Compare their Motion Stores.",
        [
            "Use E_k = 0.5mv^2 for each pod rather than guessing from speed alone.",
            "Pod A: 0.5 x 2 x 12^2 = 144 J.",
            "Pod B: 0.5 x 8 x 6^2 = 144 J.",
        ],
        "The two pods have equal Motion Store: 144 J each.",
        "The heavier slower pod can match the lighter faster pod because kinetic energy depends on both mass and the square of speed.",
        "This prevents students from assuming the faster object must always have more Motion Store.",
    ),
    "M3_L4": worked(
        "A 30 N force acts through 6 m in the force direction, but 25% of the input hand-off becomes Leak Trail. Find the useful store gain.",
        [
            "Find the total input work first: W = Fd = 30 x 6 = 180 J.",
            "Find the leaked part: 25% of 180 J = 45 J.",
            "Subtract the leak from the total hand-off to get the useful gain.",
        ],
        "Useful store gain = 135 J.",
        "The aligned push supplies 180 J, and after 45 J leaks away, 135 J remains as useful store change.",
        "This links the force-distance route to the ledger route in one combined example.",
    ),
    "M3_L5": worked(
        "Machine A transfers 2400 J in 8 s at 75% efficiency. Machine B transfers 2400 J in 4 s at 50% efficiency. Compare their power and useful output.",
        [
            "Find each power from total transfer and time.",
            "Machine A power = 2400/8 = 300 W; Machine B power = 2400/4 = 600 W.",
            "Then find useful output from efficiency: A gives 1800 J useful while B gives 1200 J useful.",
        ],
        "Machine B is more powerful, but Machine A produces the larger useful output from the same input.",
        "Power compares the rate of transfer, while efficiency compares the useful fraction, so different machines can win on different measures.",
        "This is the cleanest way to stop students from collapsing 'better' into one single machine label.",
    ),
    "M3_L6": worked(
        "A gate needs 1000 J. A launch stage loses 20% of the useful lift energy, and the lift itself is 80% efficient. What minimum lift input is required?",
        [
            "Work backward from the gate: if 80% remains after launch, divide 1000 J by 0.80 to find the useful lift energy needed.",
            "That gives 1250 J useful lift energy before launch losses.",
            "Now divide 1250 J by the lift efficiency 0.80 to find the required lift input.",
        ],
        "Minimum lift input = 1562.5 J.",
        "The gate target must be traced backward through the launch loss and then through the lift efficiency, so 1000/0.80/0.80 = 1562.5 J.",
        "This is capstone-level mission planning because the target is used to reconstruct earlier requirements.",
    ),
}

for lesson in M3_SPEC["lessons"]:
    extra_bank = M3_BANK_EXPANSIONS.get(lesson["id"], {})
    secondary_bank = M3_SECONDARY_BANK_EXPANSIONS.get(lesson["id"], {})
    lesson["diagnostic"].extend(deepcopy(extra_bank.get("diagnostic", [])))
    lesson["diagnostic"].extend(deepcopy(secondary_bank.get("diagnostic", [])))
    lesson["capsule_checks"].extend(deepcopy(extra_bank.get("capsule_checks", [])))
    lesson["capsule_checks"].extend(deepcopy(secondary_bank.get("capsule_checks", [])))
    lesson["transfer"].extend(deepcopy(extra_bank.get("transfer", [])))
    lesson["transfer"].extend(deepcopy(secondary_bank.get("transfer", [])))
    lesson["contract"]["assessment_bank_targets"] = assessment_targets(8, 6, 8)
    lesson["contract"]["worked_examples"].append(deepcopy(M3_EXTRA_WORKED_EXAMPLES[lesson["id"]]))
    scaffold_support = lesson["contract"].setdefault("scaffold_support", {})
    scaffold_support.setdefault("extra_sections", [])
    scaffold_support["extra_sections"].extend(deepcopy(M3_EXTRA_SCAFFOLD_SECTIONS.get(lesson["id"], [])))


RELEASE_CHECKS = [
    "Every lesson keeps stores, hand-offs, rate, and yield conceptually distinct before combining equations.",
    "Every worked example states why the final answer follows instead of stopping at substitution only.",
    "Every simulation contract requires at least one comparison and at least one ledger-style explanation.",
    "Every mixed mission demands justified equation choice and explicit leak accounting rather than formula grabbing.",
]


M3_MODULE_DOC, M3_LESSONS, M3_SIM_LABS = build_nextgen_module_bundle(
    module_id=M3_MODULE_ID,
    module_title=M3_MODULE_TITLE,
    module_spec=M3_SPEC,
    allowlist=M3_ALLOWLIST,
    content_version=M3_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=7,
    level="Module 3",
    estimated_minutes=270,
    authoring_standard=AUTHORING_STANDARD_V2,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M3 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    apply = bool(args.apply)
    db = init_firebase(project) if apply else None

    module_doc = deepcopy(M3_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M3_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M3_SIM_LABS]

    asset_root = args.asset_root or str(default_asset_root())
    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    plan: List[Tuple[str, str]] = [("modules", M3_MODULE_ID)]
    plan.extend(("lessons", doc_id) for doc_id, _ in lesson_pairs)
    plan.extend(("sim_labs", doc_id) for doc_id, _ in sim_pairs)

    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    if args.compile_assets:
        print(f"Asset root: {asset_root}")
        print(f"Public base: {args.public_base}")
    print_preview("Planned upserts", plan)

    upsert_doc(db, "modules", M3_MODULE_ID, module_doc, apply)
    for doc_id, payload in lesson_pairs:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in sim_pairs:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)
    print("DONE")


if __name__ == "__main__":
    main()
