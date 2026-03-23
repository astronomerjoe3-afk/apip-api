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

M11_MODULE_ID = "M11"
M11_CONTENT_VERSION = "20260321_m11_switchyard_loop_v2"
M11_MODULE_TITLE = "Circuits"
M11_ALLOWLIST = [
    "series_current_confusion",
    "series_voltage_share_confusion",
    "parallel_voltage_confusion",
    "parallel_current_split_confusion",
    "current_used_up_confusion",
    "added_branch_raises_resistance_confusion",
    "power_current_confusion",
    "power_energy_confusion",
    "diagram_picture_confusion",
    "safety_voltage_only_confusion",
    "short_circuit_confusion",
    "fuse_parallel_confusion",
    "equivalent_resistance_confusion",
    "mixed_network_reduction_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M11_ALLOWLIST)
    return [str(tag) for tag in tags if str(tag) in allowed]


def mcq(qid: str, prompt: str, choices: Sequence[str], answer_index: int, hint: str, tags: Sequence[str], *, skill_tags: Sequence[str]) -> Dict[str, Any]:
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


def short(qid: str, prompt: str, accepted_answers: Sequence[str], hint: str, tags: Sequence[str], *, skill_tags: Sequence[str], acceptance_rules: Dict[str, Any] | None = None) -> Dict[str, Any]:
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


def worked(prompt: str, steps: Sequence[str], final_answer: str, answer_reason: str, why_it_matters: str) -> Dict[str, Any]:
    return {"prompt": prompt, "steps": list(steps), "final_answer": final_answer, "answer_reason": answer_reason, "why_it_matters": why_it_matters}


def visual(
    asset_id: str,
    concept: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    template: str = "auto",
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    circuit_type_map = {
        "series_chain": "series_chain",
        "parallel_branch": "parallel_branch",
        "power_shed": "power_station",
        "route_map": "route_map",
        "guard_link_safety": "guard_link",
        "equivalent_drag": "equivalent_drag",
    }
    resolved_meta = deepcopy(meta or {})
    resolved_template = template
    if resolved_template == "auto" and concept in circuit_type_map:
        resolved_template = "electric_circuit_diagram"
    if concept in circuit_type_map and "circuit_type" not in resolved_meta:
        resolved_meta["circuit_type"] = circuit_type_map[concept]
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": resolved_template,
        "meta": resolved_meta,
    }


def animation(asset_id: str, concept: str, title: str, description: str) -> Dict[str, Any]:
    return {"asset_id": asset_id, "concept": concept, "phase_key": "analogical_grounding", "title": title, "description": description, "duration_sec": 8}


def extra_section(heading: str, body: str, check_for_understanding: str) -> Dict[str, str]:
    return {"heading": heading, "body": body, "check_for_understanding": check_for_understanding}


def scaffold(core_idea: str, reasoning: str, check: str, trap: str, analogy_body: str, analogy_check: str, extras: Sequence[Dict[str, str]]) -> Dict[str, Any]:
    return {"core_idea": core_idea, "reasoning": reasoning, "check_for_understanding": check, "common_trap": trap, "analogy_bridge": {"body": analogy_body, "check_for_understanding": analogy_check}, "extra_sections": list(extras)}


def assessment_targets() -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": 10,
        "concept_gate_pool_min": 8,
        "mastery_pool_min": 10,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery on every fresh attempt before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile.",
        "Circuit symbols, branch arrows, and checkpoint labels stay separated from the path geometry.",
        "Voltage, current, resistance, and power labels do not overlap in a way that merges distinct quantities.",
        "The primary comparison in each picture keeps the source, path structure, and readouts visually distinct in one scan.",
        "Any calculation cue shown in the visual stays readable enough for a learner to follow the circuit logic without guessing.",
    ]


def switchyard_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Switchyard-Loop Model",
        "focus": focus,
        "comparison": f"The Switchyard-Loop world keeps route shape, shared branch boost, task-station shedding, and protection in one network story while {focus}.",
        "mapping": ["Carrier tokens -> charge carriers", "Lift station -> battery or source", "Checkpoint rate -> current", "Boost per token -> voltage", "Drag section -> resistance", "Task station -> resistor or lamp", "One-lane chain -> series circuit", "Branch deck -> parallel circuit", "Guard link -> fuse or breaker", "Equivalent drag -> equivalent resistance"],
        "limit": "The model organizes network rules, but learners still need formal circuit language and standard schematic symbols.",
        "prediction_prompt": f"Use the Switchyard-Loop world to predict what should happen when {focus}.",
    }


def sim_contract(asset_id: str, concept: str, focus_prompt: str, baseline_case: str, comparison_tasks: Sequence[str], watch_for: str, takeaway: str, controls: Sequence[Tuple[str, str, str]], readouts: Sequence[Tuple[str, str]]) -> Dict[str, Any]:
    return {"asset_id": asset_id, "concept": concept, "focus_prompt": focus_prompt, "baseline_case": baseline_case, "comparison_tasks": list(comparison_tasks), "watch_for": watch_for, "takeaway": takeaway, "controls": [{"variable": a, "label": b, "why_it_matters": c} for a, b, c in controls], "readouts": [{"label": a, "meaning": b} for a, b in readouts]}


def contract(*, concept_targets: Sequence[str], core_concepts: Sequence[str], prerequisite_lessons: Sequence[str], misconception_focus: Sequence[str], formulas: Sequence[Dict[str, Any]], representations: Sequence[Dict[str, Any]], analogy_map: Dict[str, Any], worked_examples: Sequence[Dict[str, Any]], visual_assets: Sequence[Dict[str, Any]], animation_assets: Sequence[Dict[str, Any]], simulation_contract: Dict[str, Any], reflection_prompts: Sequence[str], mastery_skills: Sequence[str], variation_plan: Dict[str, str], scaffold_support: Dict[str, Any], visual_clarity_checks: Sequence[str]) -> Dict[str, Any]:
    return {"concept_targets": list(concept_targets), "core_concepts": list(core_concepts), "prerequisite_lessons": list(prerequisite_lessons), "misconception_focus": safe_tags(misconception_focus), "formulas": [deepcopy(item) for item in formulas], "representations": [deepcopy(item) for item in representations], "analogy_map": deepcopy(analogy_map), "worked_examples": [deepcopy(item) for item in worked_examples], "visual_assets": [deepcopy(item) for item in visual_assets], "animation_assets": [deepcopy(item) for item in animation_assets], "simulation_contract": deepcopy(simulation_contract), "reflection_prompts": list(reflection_prompts), "mastery_skills": list(mastery_skills), "variation_plan": deepcopy(variation_plan), "assessment_bank_targets": assessment_targets(), "scaffold_support": deepcopy(scaffold_support), "visual_clarity_checks": list(visual_clarity_checks)}


def sim(lab_id: str, title: str, description: str, instructions: Sequence[str], outcomes: Sequence[str], fields: Sequence[str], depth: str) -> Dict[str, Any]:
    return {"lab_id": lab_id, "title": title, "description": description, "instructions": list(instructions), "outcomes": list(outcomes), "fields": list(fields), "depth": depth}


def lesson_spec(lesson_id: str, title: str, sim_meta: Dict[str, Any], diagnostic: Sequence[Dict[str, Any]], analogy_text: str, commitment_prompt: str, micro_prompts: Sequence[Dict[str, str]], inquiry: Sequence[Dict[str, str]], recon_prompts: Sequence[str], capsule_prompt: str, capsule_checks: Sequence[Dict[str, Any]], transfer: Sequence[Dict[str, Any]], contract_payload: Dict[str, Any]) -> Dict[str, Any]:
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
    return {"id": lesson_id, "title": title, "sim": deepcopy(sim_meta), "diagnostic": list(diagnostic), "analogy_text": analogy_text, "commitment_prompt": commitment_prompt, "micro_prompts": list(micro_prompts), "inquiry": list(inquiry), "recon_prompts": list(recon_prompts), "capsule_prompt": capsule_prompt, "capsule_checks": list(capsule_checks), "transfer": list(transfer), "contract": resolved_contract}

def series_lesson() -> Dict[str, Any]:
    d = [
        mcq("M11L1_D1", "In a one-lane chain, what is true about the current?", ["It is the same everywhere in the chain.", "It is biggest at the battery only.", "It is used up by the first lamp.", "It is zero at the last component."], 0, "One path means the same current passes every station.", ["series_current_confusion", "current_used_up_confusion"], skill_tags=["series_current"]),
        mcq("M11L1_D2", "What happens to a one-lane chain if one component opens?", ["The whole current stops.", "Only the last component turns off.", "Current skips the broken component.", "The voltage becomes zero everywhere forever."], 0, "Breaking the only path stops the whole loop.", ["series_current_confusion"], skill_tags=["series_open_effect"]),
        mcq("M11L1_D3", "Three resistors of 2 ohm, 3 ohm, and 5 ohm are in series. Total resistance is...", ["10 ohm", "5 ohm", "15 ohm", "1 ohm"], 0, "Series resistances add directly.", ["equivalent_resistance_confusion"], skill_tags=["series_resistance_calc"]),
        short("M11L1_D4", "Why is the current the same through each series component?", ["Because there is only one path, so every carrier goes through every station.", "Because a one-lane chain gives the carriers no alternative path."], "Use one-path language.", ["series_current_confusion"], skill_tags=["series_current"], acceptance_rules=acceptance_groups(["one path", "one route", "single path", "one-lane"], ["every carrier", "same carriers", "same current"], ["every component", "each station", "each resistor"])),
        mcq("M11L1_D5", "In series, the source voltage is...", ["shared across the components", "the same current at each point", "used up by the first resistor only", "always bigger than resistance"], 0, "Series components share the total supply voltage.", ["series_voltage_share_confusion"], skill_tags=["series_voltage_share"]),
        mcq("M11L1_D6", "Adding another resistor in series usually makes the total current...", ["smaller", "larger", "unchanged", "negative"], 0, "More total resistance means less current for the same source.", ["equivalent_resistance_confusion"], skill_tags=["series_current_change"]),
        short("M11L1_D7", "A learner says, 'the first lamp uses some current, so less current reaches the second lamp.' What is the correction?", ["The same current goes through both lamps in series; what changes is the energy per charge across the stations.", "Current is the same around a one-path series loop, even though voltage is shared."], "Correct current-used-up language.", ["current_used_up_confusion", "series_current_confusion"], skill_tags=["series_current"], acceptance_rules=acceptance_groups(["same current"], ["series", "one path", "one-lane"], ["not used up", "does not get used up", "goes through both"])),
        mcq("M11L1_D8", "A 12 V battery is connected to two equal resistors in series. Each resistor gets...", ["6 V", "12 V", "24 V", "2 V"], 0, "Equal series resistors share the voltage equally.", ["series_voltage_share_confusion"], skill_tags=["series_voltage_share"]),
    ]
    c = [
        short("M11L1_C1", "How would you explain a one-lane chain without using the word series?", ["There is only one route, so every carrier must pass through every station.", "It is a single path circuit, so the same current goes through each component."], "Use one-route language.", ["series_current_confusion"], skill_tags=["series_current"], acceptance_rules=acceptance_groups(["one route", "one path", "single path", "one-lane"], ["same current", "every carrier"], ["every component", "every station"])),
        mcq("M11L1_C2", "What is added directly in a series chain?", ["resistances", "currents", "branch voltages", "fuses"], 0, "Series resistances add.", ["equivalent_resistance_confusion"], skill_tags=["series_resistance_calc"]),
        mcq("M11L1_C3", "If total series resistance rises while the battery stays the same, the current...", ["falls", "rises", "stays exactly the same", "becomes voltage"], 0, "Same source with more resistance means less current.", ["equivalent_resistance_confusion"], skill_tags=["series_current_change"]),
        short("M11L1_C4", "Why is saying 'current is shared in series' weaker than the proper rule?", ["Because current is the same everywhere in series; it is the voltage that is shared across components.", "Because a one-lane chain keeps one common current while the boost drop is divided."], "Separate current and voltage roles.", ["series_current_confusion", "series_voltage_share_confusion"], skill_tags=["series_voltage_share"], acceptance_rules=acceptance_groups(["current"], ["same everywhere", "same in every component"], ["voltage", "potential difference", "boost drop"], ["shared", "divided"])),
        mcq("M11L1_C5", "Which failure mode matches a one-lane chain?", ["One break stops the whole loop.", "One branch can fail and the others keep going.", "Adding more routes increases current without limit.", "Voltage is different at the same two points."], 0, "A single break stops a single path.", ["series_current_confusion"], skill_tags=["series_open_effect"]),
        short("M11L1_C6", "What does the source do in a one-lane chain if current is the same everywhere?", ["It provides the total voltage, which is then shared across the series stations.", "It gives the carriers the energy that the components divide into separate voltage drops."], "Use source-voltage language.", ["series_voltage_share_confusion"], skill_tags=["series_voltage_share"], acceptance_rules=acceptance_groups(["source", "battery"], ["voltage", "boost", "energy"], ["shared", "divided", "across"], ["series", "stations", "components"])),
    ]
    t = [
        mcq("M11L1_M1", "A chain has resistors 4 ohm and 6 ohm in series on a 20 V source. Total resistance is...", ["10 ohm", "2.4 ohm", "24 ohm", "6 ohm"], 0, "Series resistances add.", ["equivalent_resistance_confusion"], skill_tags=["series_resistance_calc"]),
        mcq("M11L1_M2", "For that same chain, the current is...", ["2 A", "20 A", "10 A", "0.5 A"], 0, "I = V/R = 20/10.", ["equivalent_resistance_confusion"], skill_tags=["series_current_calc"]),
        short("M11L1_M3", "Why do both resistors carry the same current in that chain?", ["Because the circuit is one continuous path, so the same charge flow passes both resistors.", "Because one-lane chains do not let the current split before rejoining."], "Use one-continuous-path language.", ["series_current_confusion"], skill_tags=["series_current"], acceptance_rules=acceptance_groups(["one path", "continuous path", "single route"], ["same current", "same charge flow"], ["both resistors", "each resistor"])),
        mcq("M11L1_M4", "If a third resistor is added in series to the same battery, the new total current will be...", ["smaller than before", "larger than before", "the same as before", "equal to the battery voltage"], 0, "More series resistance lowers current.", ["equivalent_resistance_confusion"], skill_tags=["series_current_change"]),
        short("M11L1_M5", "A student says, 'the first resistor takes most of the current.' What should you say?", ["In series the current is the same through every resistor; what can differ is the voltage drop across each resistor.", "A one-path chain does not use up current at the first resistor."], "Correct current-used-up language.", ["current_used_up_confusion", "series_current_confusion"], skill_tags=["series_current"], acceptance_rules=acceptance_groups(["same current"], ["series", "one path"], ["voltage drop", "potential difference"], ["different", "can differ", "shared"])),
        mcq("M11L1_M6", "Two equal resistors in series across 18 V each get...", ["9 V", "18 V", "36 V", "4.5 V"], 0, "Equal series resistors share equally.", ["series_voltage_share_confusion"], skill_tags=["series_voltage_share"]),
        short("M11L1_M7", "Why is a one-lane chain a good name for a series circuit?", ["Because every carrier must visit every station in order on one route.", "Because there are no side branches where the flow can split."], "Use route-order language.", ["series_current_confusion"], skill_tags=["series_current"], acceptance_rules=acceptance_groups(["every carrier", "must pass", "visit every station"], ["one route", "one path", "no branches"], ["in order"])),
        mcq("M11L1_M8", "Best summary of series behavior:", ["same current, shared voltage, resistances add", "shared current, same voltage, resistances cancel", "same current, same voltage, resistances never matter", "different current, same current, shared power"], 0, "That is the core series summary.", ["series_current_confusion", "series_voltage_share_confusion", "equivalent_resistance_confusion"], skill_tags=["series_summary"]),
    ]
    d.extend([
        mcq("M11L1_D9", "Three equal 4 ohm resistors are in series on a 12 V source. The voltage across one resistor is...", ["4 V", "12 V", "8 V", "1 V"], 0, "Equal series resistors share the source voltage equally.", ["series_voltage_share_confusion"], skill_tags=["series_voltage_share"]),
        short("M11L1_D10", "Why does a larger resistor in a series chain take a larger share of the source voltage?", ["Because the same current passes through every series resistor, so the larger resistance needs a larger voltage drop.", "Because series current stays common, so the bigger resistance gets the bigger potential difference."], "Use same-current and larger-drop language.", ["series_voltage_share_confusion"], skill_tags=["series_voltage_share"], acceptance_rules=acceptance_groups(["same current", "series current"], ["larger resistance", "bigger resistor"], ["larger voltage drop", "bigger potential difference", "more voltage"])) ,
    ])
    c.extend([
        mcq("M11L1_C7", "A 9 V one-lane chain carries 1.5 A. Its total resistance is...", ["6 ohm", "13.5 ohm", "7.5 ohm", "1.5 ohm"], 0, "Use R = V/I = 9/1.5.", ["equivalent_resistance_confusion"], skill_tags=["series_current_calc"]),
        short("M11L1_C8", "Why can the total current fall even though the battery voltage stays fixed when another series resistor is added?", ["Because the added series resistor raises the total resistance, so the same source voltage drives a smaller current.", "Because one more station increases the total drag seen by the source."], "Use fixed-source and larger-total-resistance language.", ["equivalent_resistance_confusion"], skill_tags=["series_current_change"], acceptance_rules=acceptance_groups(["same source voltage", "battery stays fixed", "fixed voltage"], ["more resistance", "larger total resistance", "more total drag"], ["smaller current", "less current", "current falls"])) ,
    ])
    t.extend([
        mcq("M11L1_M9", "A 24 V source feeds 3 ohm and 9 ohm resistors in series. The current is...", ["2 A", "8 A", "12 A", "3 A"], 0, "Total resistance is 12 ohm, so I = 24/12.", ["equivalent_resistance_confusion"], skill_tags=["series_current_calc"]),
        mcq("M11L1_M10", "In that same chain, the voltage across the 9 ohm resistor is...", ["18 V", "6 V", "24 V", "9 V"], 0, "Use V = IR = 2 x 9.", ["series_voltage_share_confusion"], skill_tags=["series_voltage_share"]),
    ])
    return {"d": d, "c": c, "t": t}


def parallel_lesson() -> Dict[str, Any]:
    d = [
        mcq("M11L2_D1", "In a branch deck, what is the same across each branch?", ["voltage", "current", "resistance", "power"], 0, "Parallel branches share the same potential difference.", ["parallel_voltage_confusion"], skill_tags=["parallel_voltage"]),
        mcq("M11L2_D2", "What happens to the total current when two branch currents rejoin?", ["They add together.", "They cancel to zero.", "Only the smaller current continues.", "The voltage doubles instead."], 0, "Branch currents add to the total current.", ["parallel_current_split_confusion"], skill_tags=["parallel_current_sum"]),
        mcq("M11L2_D3", "Why can two parallel branches have different currents?", ["Because they can have different resistance while the same voltage acts across each branch.", "Because each branch has a different battery.", "Because current is always random in parallel.", "Because voltage is used up by the first branch."], 0, "Parallel branches can share voltage but carry different current.", ["parallel_current_split_confusion", "parallel_voltage_confusion"], skill_tags=["parallel_current_compare"]),
        short("M11L2_D4", "Why is adding a new parallel branch usually able to increase the total current from the source?", ["Because it gives another path, so the equivalent resistance becomes smaller.", "Because more branches reduce the total drag seen by the source."], "Use extra-path and lower-resistance language.", ["added_branch_raises_resistance_confusion", "equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"], acceptance_rules=acceptance_groups(["another path", "extra path", "more branches"], ["lower", "smaller", "reduced"], ["resistance", "drag", "equivalent resistance"], ["more current", "increase current"])),
        mcq("M11L2_D5", "Two resistors of 6 ohm and 3 ohm are in parallel. Their equivalent resistance must be...", ["less than 3 ohm", "between 3 ohm and 6 ohm", "greater than 9 ohm", "exactly 9 ohm"], 0, "Parallel equivalent resistance is below the smallest branch resistance.", ["equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"]),
        mcq("M11L2_D6", "If one branch in a parallel circuit opens, the other branch usually...", ["can keep operating", "must also stop immediately", "gets zero voltage", "becomes series"], 0, "Independent branches can keep working.", ["parallel_current_split_confusion"], skill_tags=["branch_independence"]),
        short("M11L2_D7", "What does a junction do to the current in a parallel circuit?", ["It splits the current into branch currents and those branch currents add again when they rejoin.", "It divides the flow among the branches and later recombines it."], "Use split-and-rejoin language.", ["parallel_current_split_confusion"], skill_tags=["parallel_current_sum"], acceptance_rules=acceptance_groups(["split", "divide"], ["branch current", "branches"], ["rejoin", "add", "recombine"])),
        mcq("M11L2_D8", "Best summary of parallel behavior:", ["same voltage across branches, current splits, equivalent resistance falls", "same current in every branch, voltage adds, resistance rises", "current disappears in one branch, voltage becomes current", "one branch decides all the others"], 0, "That is the core parallel summary.", ["parallel_voltage_confusion", "parallel_current_split_confusion", "added_branch_raises_resistance_confusion"], skill_tags=["parallel_summary"]),
    ]
    c = [
        short("M11L2_C1", "How would you explain a branch deck in one sentence?", ["A branch deck gives several paths between the same two junctions, so the branches share the same voltage while current can split.", "It is a parallel network with common branch voltage and split current."], "Use same-junction language.", ["parallel_voltage_confusion", "parallel_current_split_confusion"], skill_tags=["parallel_summary"], acceptance_rules=acceptance_groups(["same two junctions", "same endpoints", "same points"], ["same voltage", "shared voltage"], ["current", "split", "branches"])),
        mcq("M11L2_C2", "If one branch has larger resistance than another under the same branch voltage, its current will be...", ["smaller", "larger", "the same", "undefined"], 0, "At the same branch voltage, the higher-resistance branch carries less current.", ["parallel_current_split_confusion"], skill_tags=["parallel_current_compare"]),
        mcq("M11L2_C3", "Branch currents 2 A and 3 A rejoin. Total current is...", ["5 A", "1 A", "6 A", "2.5 A"], 0, "Branch currents add.", ["parallel_current_split_confusion"], skill_tags=["parallel_current_sum"]),
        short("M11L2_C4", "Why is saying 'adding a branch increases resistance because there is more wire' weak at this stage?", ["Because an added parallel branch creates another path, so the equivalent resistance decreases rather than increases.", "Because extra branches reduce the total drag seen by the source."], "Use equivalent-resistance language.", ["added_branch_raises_resistance_confusion", "equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"], acceptance_rules=acceptance_groups(["extra branch", "another path", "parallel branch"], ["decrease", "lower", "reduce"], ["equivalent resistance", "total drag"])),
        mcq("M11L2_C5", "Which quantity is shared across every branch because the branches meet the same two points?", ["voltage", "current", "charge amount", "fuse rating"], 0, "Parallel branches share the same voltage.", ["parallel_voltage_confusion"], skill_tags=["parallel_voltage"]),
        short("M11L2_C6", "Why can one parallel branch fail while another keeps working?", ["Because each branch has its own path between the same junctions, so one open branch does not necessarily break the others.", "Because the remaining branch still has a complete route."], "Use independent-path language.", ["parallel_current_split_confusion"], skill_tags=["branch_independence"], acceptance_rules=acceptance_groups(["each branch", "separate path", "own path"], ["complete route", "still complete", "others keep working", "independent"])),
    ]
    t = [
        mcq("M11L2_M1", "A 12 V source feeds two parallel branches of 6 ohm and 3 ohm. Branch currents are...", ["2 A and 4 A", "12 A and 4 A", "2 A and 2 A", "6 A and 3 A"], 0, "Use I = V/R on each branch.", ["parallel_voltage_confusion", "parallel_current_split_confusion"], skill_tags=["parallel_current_calc"]),
        mcq("M11L2_M2", "The total current in that network is...", ["6 A", "2 A", "4 A", "9 A"], 0, "Add the branch currents.", ["parallel_current_split_confusion"], skill_tags=["parallel_current_sum"]),
        short("M11L2_M3", "Why do those two branches carry different current even though they have the same voltage?", ["Because the branch resistances are different, so the same branch voltage drives different branch currents.", "Because voltage is shared in parallel but current depends on each branch resistance."], "Use same-V different-R language.", ["parallel_voltage_confusion", "parallel_current_split_confusion"], skill_tags=["parallel_current_compare"], acceptance_rules=acceptance_groups(["same voltage", "shared voltage"], ["different resistance", "branch resistance"], ["different current", "branch current"])),
        mcq("M11L2_M4", "Equivalent resistance of a parallel deck must always be...", ["less than the smallest branch resistance", "greater than the largest branch resistance", "the simple sum of all branches", "equal to the source voltage"], 0, "That is the key comparison rule for parallel resistance.", ["equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"]),
        short("M11L2_M5", "Why does adding another parallel branch often make the source current larger?", ["Because the extra branch lowers the equivalent resistance, so the same source voltage can drive more total current.", "Because the source now sees a smaller overall drag."], "Use lower-equivalent-resistance language.", ["added_branch_raises_resistance_confusion", "equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"], acceptance_rules=acceptance_groups(["extra branch", "another branch"], ["lower", "smaller"], ["equivalent resistance", "overall drag"], ["more current", "larger total current"])),
        mcq("M11L2_M6", "If one branch opens in a two-branch parallel circuit, the other branch...", ["can still carry current", "must always stop too", "gets zero voltage immediately", "turns into a battery"], 0, "A remaining complete branch can keep working.", ["parallel_current_split_confusion"], skill_tags=["branch_independence"]),
        short("M11L2_M7", "What is the cleanest branch-deck summary for voltage and current?", ["Voltage is the same across each branch, while current splits among the branches and adds again at the junction.", "Parallel branches share voltage and split current."], "Use shared-voltage and split-current language.", ["parallel_voltage_confusion", "parallel_current_split_confusion"], skill_tags=["parallel_summary"], acceptance_rules=acceptance_groups(["same voltage", "shared voltage"], ["current", "split", "branch current"], ["add", "rejoin", "sum"])),
        mcq("M11L2_M8", "Best reason a parallel network is often more reliable for separate devices:", ["One branch can fail without automatically opening the others.", "It forces the same current through every device.", "It always gives zero resistance.", "It turns voltage into current at each junction."], 0, "Branch independence is a core practical parallel idea.", ["parallel_current_split_confusion"], skill_tags=["branch_independence"]),
    ]
    d.extend([
        mcq("M11L2_D9", "Two equal 6 ohm branches are connected in parallel across a 12 V source. The current in each branch is...", ["2 A", "1 A", "6 A", "12 A"], 0, "Each branch gets the full 12 V, so I = 12/6.", ["parallel_voltage_confusion", "parallel_current_split_confusion"], skill_tags=["parallel_current_calc"]),
        short("M11L2_D10", "Why can the source current be larger than either single branch current in a parallel network?", ["Because the branch currents add together when they rejoin at the source path.", "Because total current is the sum of the separate branch currents."], "Use add-when-they-rejoin language.", ["parallel_current_split_confusion"], skill_tags=["parallel_current_sum"], acceptance_rules=acceptance_groups(["branch currents", "currents in the branches"], ["add", "sum", "rejoin", "recombine"], ["source current", "total current"])) ,
    ])
    c.extend([
        mcq("M11L2_C7", "A 12 V source feeds branches of 4 ohm and 6 ohm. The total current is...", ["5 A", "2 A", "3 A", "10 A"], 0, "Branch currents are 3 A and 2 A, so total current is 5 A.", ["parallel_voltage_confusion", "parallel_current_split_confusion"], skill_tags=["parallel_current_sum"]),
        short("M11L2_C8", "Why must the equivalent resistance of a parallel deck be below the smallest branch resistance?", ["Because every added branch gives another path for the current, so the total drag seen by the source becomes smaller than any one branch alone.", "Because the source sees several routes in parallel rather than just one branch."], "Use extra-path and smaller-total-drag language.", ["equivalent_resistance_confusion", "added_branch_raises_resistance_confusion"], skill_tags=["parallel_equivalent"], acceptance_rules=acceptance_groups(["another path", "extra path", "several routes", "parallel"], ["smaller", "lower"], ["equivalent resistance", "total drag"], ["than the smallest branch", "than one branch alone"])) ,
    ])
    t.extend([
        mcq("M11L2_M9", "A 12 V source feeds 4 ohm and 12 ohm branches in parallel. The equivalent resistance is...", ["3 ohm", "16 ohm", "4 ohm", "8 ohm"], 0, "The branch currents are 3 A and 1 A, so total current is 4 A and Req = 12/4 = 3 ohm.", ["equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"]),
        mcq("M11L2_M10", "For that same network, the total current from the source is...", ["4 A", "3 A", "1 A", "12 A"], 0, "Add the 3 A and 1 A branch currents.", ["parallel_current_split_confusion"], skill_tags=["parallel_current_sum"]),
    ])
    return {"d": d, "c": c, "t": t}


def power_lesson() -> Dict[str, Any]:
    d = [
        mcq("M11L3_D1", "Power in a circuit is best described as...", ["energy transferred each second", "current used up per lamp", "the total charge stored in a battery", "how many wires are present"], 0, "Power is the rate of energy transfer.", ["power_energy_confusion", "power_current_confusion"], skill_tags=["power_definition"]),
        mcq("M11L3_D2", "Which relation matches power for a component?", ["P = IV", "P = I/R", "P = Q/t", "P = V + I"], 0, "Power is current times voltage across the component.", ["power_current_confusion"], skill_tags=["power_formula"]),
        mcq("M11L3_D3", "A lamp has 2 A through it and 6 V across it. Its power is...", ["12 W", "3 W", "8 W", "1/3 W"], 0, "Use P = IV.", ["power_current_confusion"], skill_tags=["power_calculation"]),
        short("M11L3_D4", "Why can a lamp glow more strongly when its shed rate is larger?", ["Because a larger power means more energy is transferred by the lamp each second.", "Because the lamp is shedding energy faster each second."], "Use power-as-rate language.", ["power_energy_confusion"], skill_tags=["brightness_reasoning"], acceptance_rules=acceptance_groups(["more energy", "energy transferred", "shed"], ["per second", "each second", "rate"], ["power", "larger power", "higher power"])),
        mcq("M11L3_D5", "If the current stays the same but the voltage across a device doubles, the power...", ["doubles", "halves", "stays the same", "becomes resistance"], 0, "At fixed current, doubling voltage doubles power.", ["power_current_confusion"], skill_tags=["power_compare"]),
        mcq("M11L3_D6", "Which statement keeps current and power separate?", ["Current is charge flow rate; power is energy transfer rate.", "Current and power are the same in different units.", "Power is how much charge there is.", "Current is voltage per second."], 0, "Current and power answer different questions.", ["power_current_confusion"], skill_tags=["power_definition"]),
        short("M11L3_D7", "Why is 'the lamp uses current up' still weak in a power lesson?", ["Because the current can stay the same in series while the lamp transfers energy, so the better idea is power dissipation.", "Because what matters here is energy shed per second, not current being destroyed."], "Correct current-used-up language with power language.", ["current_used_up_confusion", "power_current_confusion"], skill_tags=["power_definition"], acceptance_rules=acceptance_groups(["current"], ["not used up", "same current", "not destroyed"], ["energy", "power", "shed", "transferred"], ["per second", "rate"])),
        mcq("M11L3_D8", "Two lamps have the same current, but one has a larger voltage across it. Which has the larger power?", ["the one with the larger voltage", "they must have the same power", "the one with the smaller voltage", "neither can have power"], 0, "P = IV, so the larger voltage gives larger power at the same current.", ["power_current_confusion"], skill_tags=["power_compare"]),
    ]
    c = [
        short("M11L3_C1", "How would you explain power without using the word watt?", ["Power is how much energy a station sheds each second.", "Power tells how fast energy is transferred at the component."], "Use rate-of-energy language.", ["power_energy_confusion"], skill_tags=["power_definition"], acceptance_rules=acceptance_groups(["energy", "shed", "transferred"], ["each second", "per second", "rate"], ["power"])),
        mcq("M11L3_C2", "A station has 3 V across it and 4 A through it. The power is...", ["12 W", "7 W", "1 W", "0.75 W"], 0, "Use P = IV.", ["power_current_confusion"], skill_tags=["power_calculation"]),
        mcq("M11L3_C3", "If both current and voltage increase, the power usually...", ["increases", "decreases automatically", "stays fixed", "becomes resistance"], 0, "Power rises when more current and/or more voltage act together.", ["power_current_confusion"], skill_tags=["power_compare"]),
        short("M11L3_C4", "Why is a brighter lamp often a higher-power lamp?", ["Because it is transferring more energy each second into light and heat.", "Because the shed rate at the lamp is larger."], "Use shed-rate language.", ["power_energy_confusion"], skill_tags=["brightness_reasoning"], acceptance_rules=acceptance_groups(["more energy", "energy transferred", "shed"], ["each second", "per second", "rate"], ["light", "heat", "power"])),
        mcq("M11L3_C5", "Which quantity is a rate of charge flow rather than a rate of energy transfer?", ["current", "power", "voltage", "resistance"], 0, "Current is charge flow rate; power is energy transfer rate.", ["power_current_confusion"], skill_tags=["power_definition"]),
        short("M11L3_C6", "Why does P = IV fit the Switchyard story of a task station?", ["Because more carriers per second and/or more boost drop per carrier means more energy is shed each second.", "Because power depends on current and voltage together."], "Use both-flow-and-boost-drop language.", ["power_current_confusion", "power_energy_confusion"], skill_tags=["power_formula"], acceptance_rules=acceptance_groups(["current", "carriers per second", "flow"], ["voltage", "boost drop", "energy per charge"], ["more energy", "shed", "transferred"], ["each second", "rate"])),
    ]
    t = [
        mcq("M11L3_M1", "A heater has 5 A through it and 8 V across it. Its power is...", ["40 W", "13 W", "3 W", "0.625 W"], 0, "P = IV.", ["power_current_confusion"], skill_tags=["power_calculation"]),
        mcq("M11L3_M2", "Another heater has the same 5 A but only 4 V. Compared with the first heater, its power is...", ["half as large", "twice as large", "the same", "impossible to compare"], 0, "At the same current, halving voltage halves power.", ["power_current_confusion"], skill_tags=["power_compare"]),
        short("M11L3_M3", "Why is power a better idea than 'used-up current' when comparing lamp brightness?", ["Because brightness depends on how much energy the lamp transfers each second, not on current being consumed.", "Because power tracks the lamp's energy shed rate."], "Use rate-of-energy-transfer language.", ["power_energy_confusion", "current_used_up_confusion"], skill_tags=["brightness_reasoning"], acceptance_rules=acceptance_groups(["energy", "shed", "transferred"], ["each second", "rate"], ["not", "rather than"], ["used-up current", "current consumed", "current used up"])),
        mcq("M11L3_M4", "A station's power can increase if...", ["either the current or the voltage across it increases", "the number of symbols on the diagram increases", "the fuse is removed", "the resistance unit changes to volts"], 0, "Power depends on both current and voltage.", ["power_current_confusion"], skill_tags=["power_compare"]),
        short("M11L3_M5", "What does a task station shed when it has power dissipation?", ["It sheds energy each second into forms like heat and light.", "It transfers electrical energy into other forms at a rate."], "Use energy-transfer language.", ["power_energy_confusion"], skill_tags=["power_definition"], acceptance_rules=acceptance_groups(["energy"], ["heat", "light", "other forms", "transferred"], ["each second", "rate", "power"])),
        mcq("M11L3_M6", "If a lamp has 12 W of power, that means it transfers...", ["12 J each second", "12 C each second", "12 V each second", "12 ohm each second"], 0, "1 W = 1 J/s.", ["power_energy_confusion"], skill_tags=["power_unit"]),
        short("M11L3_M7", "Why can the same series current pass two lamps even when one has a larger power?", ["Because power depends on both current and voltage drop, so the lamp with the larger voltage drop can have the larger power even at the same current.", "Because same current does not force same power if the voltage drops differ."], "Use same-current different-voltage-drop language.", ["power_current_confusion", "series_voltage_share_confusion"], skill_tags=["power_compare"], acceptance_rules=acceptance_groups(["same current"], ["voltage drop", "potential difference"], ["different", "larger"], ["power"])),
        mcq("M11L3_M8", "Best summary of component power:", ["power is the energy transfer rate at the component", "power is the charge stored in the source", "power is identical to current", "power is how many branches there are"], 0, "That is the clean summary.", ["power_energy_confusion"], skill_tags=["power_definition"]),
    ]
    d.extend([
        mcq("M11L3_D9", "A component transfers 30 J of energy each second. Its power is...", ["30 W", "30 V", "30 A", "1/30 W"], 0, "Power is energy transferred per second.", ["power_energy_confusion"], skill_tags=["power_unit"]),
        short("M11L3_D10", "Why does the statement '1 W = 1 J/s' matter in circuit reasoning?", ["Because it shows that power tells you how much energy is transferred each second.", "Because watts are joules per second, so power is a rate of energy transfer."], "Use joules-per-second language.", ["power_energy_confusion"], skill_tags=["power_unit"], acceptance_rules=acceptance_groups(["1 watt", "w"], ["1 joule per second", "joules per second", "j/s"], ["energy"], ["each second", "rate", "transferred"])) ,
    ])
    c.extend([
        mcq("M11L3_C7", "A lamp is rated at 24 W and has 12 V across it. The current is...", ["2 A", "12 A", "24 A", "0.5 A"], 0, "Use I = P/V = 24/12.", ["power_current_confusion"], skill_tags=["power_calculation"]),
        short("M11L3_C8", "Why can two devices have the same power even when their currents are different?", ["Because power depends on both current and voltage, so a different voltage can balance a different current.", "Because the same energy-transfer rate can come from different I and V combinations."], "Use both-current-and-voltage language.", ["power_current_confusion"], skill_tags=["power_compare"], acceptance_rules=acceptance_groups(["power"], ["current", "different currents"], ["voltage", "different voltage"], ["same rate", "same energy transfer", "balance"])) ,
    ])
    t.extend([
        mcq("M11L3_M9", "A heater transfers 18 J each second. Its power is...", ["18 W", "18 V", "18 A", "1.8 W"], 0, "Power is joules per second.", ["power_energy_confusion"], skill_tags=["power_unit"]),
        mcq("M11L3_M10", "A device runs at 12 W while 3 A flows through it. The voltage across it is...", ["4 V", "36 V", "9 V", "0.25 V"], 0, "Use V = P/I = 12/3.", ["power_current_confusion"], skill_tags=["power_calculation"]),
    ])
    return {"d": d, "c": c, "t": t}


def route_map_lesson() -> Dict[str, Any]:
    d = [
        mcq("M11L4_D1", "A circuit diagram should be read as...", ["a symbolic map of connections", "a realistic picture of where every part sits physically", "a graph of current against time", "proof that current is used up"], 0, "A schematic shows connection logic, not furniture layout.", ["diagram_picture_confusion"], skill_tags=["diagram_meaning"]),
        mcq("M11L4_D2", "Why can two circuits that look physically different still be the same circuit?", ["Because the same connection pattern can be drawn in more than one layout.", "Because batteries decide every circuit is identical.", "Because resistance never matters in diagrams.", "Because wires store current."], 0, "Equivalent connection logic matters more than the picture shape.", ["diagram_picture_confusion"], skill_tags=["diagram_equivalence"]),
        mcq("M11L4_D3", "What does a route map help you see most clearly?", ["which components are connected in series or parallel", "the exact color of the wires", "the microscopic carrier count", "the cost of the battery"], 0, "Schematics organize the network rules.", ["diagram_picture_confusion"], skill_tags=["diagram_connections"]),
        short("M11L4_D4", "Why is a schematic better than a realistic sketch for circuit reasoning?", ["Because it shows the connections clearly with standard symbols instead of distracting physical details.", "Because a route map makes the network logic easier to read than a picture of the hardware."], "Use symbolic-map language.", ["diagram_picture_confusion"], skill_tags=["diagram_meaning"], acceptance_rules=acceptance_groups(["connections", "network", "logic"], ["clear", "standard symbols", "schematic", "route map"], ["not", "rather than"], ["picture", "realistic sketch", "physical details"])),
        mcq("M11L4_D5", "If two lamps are drawn one after another on the same path, the route map is showing...", ["series connection", "parallel branches", "a short circuit", "a fuse symbol"], 0, "One path through both components means series.", ["diagram_picture_confusion"], skill_tags=["series_parallel_from_map"]),
        mcq("M11L4_D6", "If two components are connected between the same two junctions, the route map is showing...", ["parallel connection", "series only", "no current anywhere", "a battery with zero voltage"], 0, "Same two junctions means parallel.", ["diagram_picture_confusion"], skill_tags=["series_parallel_from_map"]),
        short("M11L4_D7", "What should you look for first when decoding a route map?", ["Look for the junctions and the paths between them.", "Start by tracing which components share one path and which components sit on separate branches."], "Use junction and path language.", ["diagram_picture_confusion"], skill_tags=["diagram_connections"], acceptance_rules=acceptance_groups(["junction", "junctions"], ["path", "paths", "branches"], ["first", "start", "trace"])),
        mcq("M11L4_D8", "Best summary of a route map:", ["It is a symbolic connection map for the circuit.", "It is a photograph of the hardware.", "It tells you the circuit is always parallel.", "It only matters after all calculations are finished."], 0, "That is the core idea for diagrams.", ["diagram_picture_confusion"], skill_tags=["diagram_meaning"]),
    ]
    c = [
        short("M11L4_C1", "How would you explain a route map in one sentence?", ["A route map uses standard symbols to show how the circuit is connected.", "A schematic is a symbolic drawing of the network connections."], "Use standard-symbols and connection language.", ["diagram_picture_confusion"], skill_tags=["diagram_meaning"], acceptance_rules=acceptance_groups(["standard symbols", "symbolic", "schematic", "route map"], ["connections", "network", "connected"])) ,
        mcq("M11L4_C2", "A physically bent wire drawn straight on a schematic changes...", ["nothing important about the circuit logic", "the voltage of the battery", "the number of charges in the loop", "the resistance of every component"], 0, "The drawing style can change without changing the connection logic.", ["diagram_picture_confusion"], skill_tags=["diagram_equivalence"]),
        mcq("M11L4_C3", "Which map clue tells you components are parallel?", ["they share the same two junctions", "they sit next to each other on the page", "they have the same symbol shape", "they use the same color"], 0, "Shared junctions define parallel branches.", ["diagram_picture_confusion"], skill_tags=["series_parallel_from_map"]),
        short("M11L4_C4", "Why is the physical layout on the table less important than the connection pattern?", ["Because the circuit behavior depends on how components are connected, not on where they happen to sit physically.", "Because series and parallel are connection rules, not picture-position rules."], "Use connection-pattern language.", ["diagram_picture_confusion"], skill_tags=["diagram_equivalence"], acceptance_rules=acceptance_groups(["connected", "connection pattern", "network"], ["not", "rather than"], ["physical layout", "picture position", "where they sit"])) ,
        mcq("M11L4_C5", "Which first move best supports diagram reading?", ["mark the junctions and trace each path", "guess the current from the symbol shapes", "count only the batteries", "ignore the wires"], 0, "Start from the connections.", ["diagram_picture_confusion"], skill_tags=["diagram_connections"]),
        short("M11L4_C6", "Why can a route map help with later resistance reduction work?", ["Because it makes the series and parallel sections easier to identify step by step.", "Because a clean schematic lets you spot which parts share one path and which parts form branches."], "Use identify-series-and-parallel language.", ["diagram_picture_confusion", "mixed_network_reduction_confusion"], skill_tags=["diagram_connections"], acceptance_rules=acceptance_groups(["series", "parallel"], ["identify", "spot", "see"], ["step by step", "reduction", "clean schematic"])) ,
    ]
    t = [
        mcq("M11L4_M1", "Two resistors connected one after another with no branch between them are...", ["series", "parallel", "shorted", "unguarded"], 0, "One path through both means series.", ["diagram_picture_confusion"], skill_tags=["series_parallel_from_map"]),
        mcq("M11L4_M2", "Two lamps connected between the same two junctions are...", ["parallel", "series", "open circuit", "insulation"], 0, "Same two junctions means parallel.", ["diagram_picture_confusion"], skill_tags=["series_parallel_from_map"]),
        short("M11L4_M3", "Why is 'this drawing looks spread out, so it must be parallel' weak?", ["Because parallel is decided by shared junctions and branch connections, not by how spread out the picture looks.", "Because layout on the page is not the same as network structure."], "Use junction-not-layout language.", ["diagram_picture_confusion"], skill_tags=["diagram_equivalence"], acceptance_rules=acceptance_groups(["junction", "shared junctions", "connections", "branches"], ["not", "rather than"], ["spread out", "layout", "picture looks"])) ,
        mcq("M11L4_M4", "A good route-map translation from a classroom circuit should keep...", ["the connection logic and symbols clear", "every wire drawn to exact scale", "the desk position of each component", "only the battery visible"], 0, "Schematics preserve connections, not appearance.", ["diagram_picture_confusion"], skill_tags=["diagram_meaning"]),
        short("M11L4_M5", "What is the best first explanation of why a schematic is useful?", ["It strips away physical detail and shows the important electrical connections clearly.", "It lets you reason about the network without needing a literal picture."], "Use strips-away-detail language.", ["diagram_picture_confusion"], skill_tags=["diagram_meaning"], acceptance_rules=acceptance_groups(["connections", "network"], ["clear", "clearly", "shows"], ["strip", "remove", "without"], ["physical detail", "literal picture"])) ,
        mcq("M11L4_M6", "Which pair most likely sits on the same branch?", ["two components between the same split and rejoin junctions", "two components anywhere on the same page", "two batteries of the same voltage", "two wires drawn straight"], 0, "Branches are defined by junction structure.", ["diagram_picture_confusion"], skill_tags=["diagram_connections"]),
        short("M11L4_M7", "How does route-map reading prepare you for circuit calculations?", ["It helps you identify the series and parallel structure before you calculate anything.", "It shows which parts share one path and which parts share the same two junctions."], "Use identify-structure-first language.", ["diagram_picture_confusion", "mixed_network_reduction_confusion"], skill_tags=["diagram_connections"], acceptance_rules=acceptance_groups(["series", "parallel", "structure"], ["identify", "see", "spot"], ["before", "first"], ["calculate", "reduction"])) ,
        mcq("M11L4_M8", "Best summary of route maps:", ["They are symbolic network maps, not realistic pictures.", "They are only useful after you know the answer.", "They show how current gets used up.", "They force every circuit to be series."], 0, "That is the route-map summary.", ["diagram_picture_confusion"], skill_tags=["diagram_meaning"]),
    ]
    d.extend([
        mcq("M11L4_D9", "A route map shows a 4 ohm resistor in series with a parallel pair of 8 ohm and 8 ohm. The best first reduction is to...", ["reduce the 8 ohm branch pair to 4 ohm", "add all three resistors to get 20 ohm", "ignore the branch pair and calculate current first", "treat every resistor as if it had the same current"], 0, "The same-two-junction branch pair is the first valid block.", ["diagram_picture_confusion", "mixed_network_reduction_confusion"], skill_tags=["diagram_connections"]),
        short("M11L4_D10", "Why is redrawing a circuit after one valid reduction a useful step?", ["Because the redraw makes the new simpler series or parallel structure easier to see and stops you combining the wrong parts.", "Because each redraw shows the next valid block clearly."], "Use redraw-and-see-the-new-structure language.", ["mixed_network_reduction_confusion"], skill_tags=["diagram_connections"], acceptance_rules=acceptance_groups(["redraw", "draw again"], ["simpler structure", "next structure", "new structure"], ["see", "identify", "clear"], ["valid block", "wrong parts", "combine"])) ,
    ])
    c.extend([
        mcq("M11L4_C7", "An 8 ohm and 8 ohm branch pair has been reduced to 4 ohm. If that 4 ohm block is in series with another 4 ohm resistor, the total is...", ["8 ohm", "4 ohm", "16 ohm", "2 ohm"], 0, "Once the branch pair becomes 4 ohm, the remaining series step is 4 + 4.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_network_calc"]),
        short("M11L4_C8", "Why can a neat schematic support calculations better than a realistic sketch?", ["Because it makes the valid series and parallel sections visible before you start any calculations.", "Because the symbolic map reveals the actual connection pattern that the algebra must follow."], "Use valid-sections-before-calculations language.", ["diagram_picture_confusion", "mixed_network_reduction_confusion"], skill_tags=["diagram_connections"], acceptance_rules=acceptance_groups(["series", "parallel", "valid sections", "connection pattern"], ["visible", "clear", "reveals"], ["before", "start"], ["calculations", "algebra"])) ,
    ])
    t.extend([
        mcq("M11L4_M9", "A route map shows a 12 V source feeding a 2 ohm resistor in series with a parallel pair of 3 ohm and 6 ohm. The first reduction gives...", ["2 ohm for the branch pair", "9 ohm for the branch pair", "3 ohm for the branch pair", "6 ohm for the branch pair"], 0, "The 3 ohm and 6 ohm pair reduce to 2 ohm in parallel.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_network_calc"]),
        mcq("M11L4_M10", "For that same route map, the total current from the 12 V source is...", ["3 A", "6 A", "2 A", "12 A"], 0, "The total resistance is 2 ohm + 2 ohm = 4 ohm, so I = 12/4.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_network_calc"]),
    ])
    return {"d": d, "c": c, "t": t}


def safety_lesson() -> Dict[str, Any]:
    d = [
        mcq("M11L5_D1", "A short circuit is dangerous mainly because it creates...", ["a very low-resistance path that can cause a very large current", "extra voltage in every wire automatically", "more batteries in the loop", "less charge in the circuit"], 0, "Low resistance can drive dangerously large current.", ["short_circuit_confusion", "safety_voltage_only_confusion"], skill_tags=["short_circuit_risk"]),
        mcq("M11L5_D2", "What should a fuse or breaker do when the current becomes unsafe?", ["open the circuit", "increase the current further", "store the extra current", "remove all resistance permanently"], 0, "Protection devices interrupt unsafe current.", ["fuse_parallel_confusion"], skill_tags=["fuse_role"]),
        mcq("M11L5_D3", "Why can overloaded wires overheat?", ["Because large current causes more energy dissipation in the wires.", "Because current disappears into the insulation.", "Because the battery becomes smaller.", "Because voltage turns into resistance."], 0, "Unsafe current can heat wires rapidly.", ["safety_voltage_only_confusion"], skill_tags=["overload_heating"]),
        short("M11L5_D4", "Why is 'danger only comes from high voltage' too weak in this lesson?", ["Because overload currents and short circuits can also be dangerous by overheating wires.", "Because safety depends on more than voltage alone; current and fault paths matter too."], "Use overload and short-circuit language.", ["safety_voltage_only_confusion", "short_circuit_confusion"], skill_tags=["safety_reasoning"], acceptance_rules=acceptance_groups(["not only", "more than", "not just"], ["voltage"], ["current", "overload", "short circuit", "fault"], ["dangerous", "heating", "overheat"])) ,
        mcq("M11L5_D5", "Where is a fuse normally placed in the safety story?", ["in series with the part of the circuit it protects", "in parallel across the battery", "outside the circuit so no current reaches it", "only on one branch of every resistor"], 0, "A guard link works by sitting in the current path.", ["fuse_parallel_confusion"], skill_tags=["fuse_position"]),
        mcq("M11L5_D6", "What is insulation for?", ["to keep people away from live conductive parts", "to increase the battery voltage", "to create more charge", "to make every resistor parallel"], 0, "Insulation is a protection barrier.", ["safety_voltage_only_confusion"], skill_tags=["insulation_role"]),
        short("M11L5_D7", "Why is a fault bridge more dangerous than an ordinary extra branch?", ["Because it creates an unintended very low-resistance path that can draw a much larger current.", "Because the fault route bypasses the normal load and lets the current surge."], "Use low-resistance shortcut language.", ["short_circuit_confusion"], skill_tags=["short_circuit_risk"], acceptance_rules=acceptance_groups(["low resistance", "very low resistance", "shortcut", "bypass"], ["large current", "more current", "surge"], ["fault", "short circuit"])) ,
        mcq("M11L5_D8", "Best summary of circuit safety here:", ["guard links stop unsafe current, and insulation blocks unsafe contact", "safety only means using the biggest battery", "short circuits are safe because resistance is small", "fuses work best in parallel"], 0, "That is the core safety summary.", ["safety_voltage_only_confusion", "short_circuit_confusion", "fuse_parallel_confusion"], skill_tags=["safety_summary"]),
    ]
    c = [
        short("M11L5_C1", "How would you explain a guard link in one sentence?", ["A guard link is a fuse or breaker that opens the circuit if the current becomes unsafe.", "It is a safety device placed in series to interrupt excessive current."], "Use open-the-circuit language.", ["fuse_parallel_confusion"], skill_tags=["fuse_role"], acceptance_rules=acceptance_groups(["fuse", "breaker", "guard link"], ["open", "break", "interrupt"], ["circuit", "current"], ["unsafe", "excessive", "too large"])) ,
        mcq("M11L5_C2", "Why does a short circuit often increase current strongly?", ["Because the resistance becomes much smaller.", "Because the battery forgets its voltage.", "Because charge is used up faster.", "Because the fuse adds resistance to zero."], 0, "Lower resistance with the same source can drive larger current.", ["short_circuit_confusion"], skill_tags=["short_circuit_risk"]),
        mcq("M11L5_C3", "Which protection idea is about blocking contact rather than interrupting current?", ["insulation", "fuse", "breaker", "ammeter"], 0, "Insulation keeps users away from live parts.", ["safety_voltage_only_confusion"], skill_tags=["insulation_role"]),
        short("M11L5_C4", "Why must a fuse be in series rather than in parallel with the load?", ["Because it must carry the same circuit current so it can open the path when that current becomes too large.", "Because a parallel fuse would not reliably interrupt the main current path."], "Use same-current-path language.", ["fuse_parallel_confusion"], skill_tags=["fuse_position"], acceptance_rules=acceptance_groups(["series", "same current", "main current path"], ["open", "interrupt"], ["too large", "unsafe", "excessive"])) ,
        mcq("M11L5_C5", "Which condition most directly warns of overheating risk?", ["large current through a low-resistance fault path", "a neat-looking diagram", "equal branch voltages", "a resistor label written clearly"], 0, "Large current is the heating danger.", ["short_circuit_confusion", "safety_voltage_only_confusion"], skill_tags=["overload_heating"]),
        short("M11L5_C6", "Why is a safety lesson still part of the circuit physics rather than just a list of rules?", ["Because the dangers come from current, resistance, and energy dissipation in real paths.", "Because safety devices are responding to physical circuit conditions like overload and fault current."], "Use physics-of-danger language.", ["safety_voltage_only_confusion", "short_circuit_confusion"], skill_tags=["safety_reasoning"], acceptance_rules=acceptance_groups(["current", "resistance", "energy", "dissipation"], ["danger", "overload", "fault", "heating"], ["physics", "physical", "circuit conditions"])) ,
    ]
    t = [
        mcq("M11L5_M1", "A damaged wire creates a near-zero-resistance path across the source. This is...", ["a short circuit", "a safe extra branch", "a route map", "a lamp"], 0, "That is the classic short-circuit story.", ["short_circuit_confusion"], skill_tags=["short_circuit_risk"]),
        mcq("M11L5_M2", "Why can that fault become dangerous so quickly?", ["Because the small resistance allows a very large current and rapid heating.", "Because all voltage disappears forever.", "Because the current turns into charge.", "Because the battery becomes parallel."], 0, "Low resistance can drive a dangerous current surge.", ["short_circuit_confusion", "safety_voltage_only_confusion"], skill_tags=["overload_heating"]),
        short("M11L5_M3", "What should the fuse do in that situation?", ["It should open the circuit and stop the unsafe current.", "It should break the current path before the heating keeps growing."], "Use interrupt-the-path language.", ["fuse_parallel_confusion"], skill_tags=["fuse_role"], acceptance_rules=acceptance_groups(["open", "break", "interrupt"], ["circuit", "path"], ["unsafe current", "large current", "overload"])) ,
        mcq("M11L5_M4", "Which placement is correct for a fuse protecting a circuit?", ["in series in the main current path", "in parallel across the source", "outside the loop", "only across one resistor lead"], 0, "The fuse must be in the current path it protects.", ["fuse_parallel_confusion"], skill_tags=["fuse_position"]),
        short("M11L5_M5", "Why is insulation different from a fuse or breaker?", ["Insulation blocks unsafe contact, while fuses and breakers interrupt unsafe current.", "Insulation protects by separation, not by opening the loop."], "Use contact-versus-current language.", ["safety_voltage_only_confusion", "fuse_parallel_confusion"], skill_tags=["insulation_role"], acceptance_rules=acceptance_groups(["insulation"], ["contact", "touch", "live parts"], ["fuse", "breaker", "open", "interrupt"], ["current"])) ,
        mcq("M11L5_M6", "Which is the clearest safety summary for a fault bridge?", ["It creates an unintended low-resistance path that can cause excessive current.", "It is a harmless extra branch because branches are always safe.", "It shares voltage in a useful way.", "It reduces power in every wire automatically."], 0, "Fault bridges are dangerous shortcuts.", ["short_circuit_confusion"], skill_tags=["short_circuit_risk"]),
        short("M11L5_M7", "Why is 'more voltage is the only thing that makes a circuit dangerous' incomplete?", ["Because dangerous current and heating can also come from low resistance and fault paths.", "Because overloads and short circuits matter, not voltage alone."], "Use low-resistance and overload language.", ["safety_voltage_only_confusion", "short_circuit_confusion"], skill_tags=["safety_reasoning"], acceptance_rules=acceptance_groups(["not only", "not just", "incomplete"], ["voltage"], ["current", "overload", "short circuit", "low resistance", "heating"])) ,
        mcq("M11L5_M8", "Best final safety summary:", ["shorts and overloads are dangerous because they can drive large current, so guard links and insulation matter", "all safety comes only from using tiny batteries", "fuses work best when placed in parallel", "safety has nothing to do with resistance"], 0, "That is the full safety summary.", ["safety_voltage_only_confusion", "short_circuit_confusion", "fuse_parallel_confusion"], skill_tags=["safety_summary"]),
    ]
    d.extend([
        mcq("M11L5_D9", "A 12 V source accidentally drives current through a 2 ohm fault path. The current is...", ["6 A", "2 A", "24 A", "0.17 A"], 0, "Use I = V/R = 12/2.", ["short_circuit_confusion"], skill_tags=["short_circuit_risk"]),
        mcq("M11L5_D10", "A 3 A fuse is protecting that path. It should...", ["open because 6 A is above its rating", "stay closed because current is always safe in faults", "raise the voltage to stop the current", "move into parallel automatically"], 0, "The guard link should interrupt current above its safe rating.", ["fuse_parallel_confusion", "short_circuit_confusion"], skill_tags=["fuse_role"]),
    ])
    c.extend([
        mcq("M11L5_C7", "If a 12 V source drives current through a 4 ohm fault path, the current is...", ["3 A", "4 A", "12 A", "48 A"], 0, "Use I = V/R = 12/4.", ["short_circuit_confusion"], skill_tags=["short_circuit_risk"]),
        short("M11L5_C8", "Why does lowering the resistance of a fault path raise the heating risk even if the battery is unchanged?", ["Because the lower resistance lets a larger current flow, and that larger current can cause more energy dissipation in the wires.", "Because the same source can drive a much bigger current through the shortcut path."], "Use lower-resistance larger-current heating language.", ["short_circuit_confusion", "safety_voltage_only_confusion"], skill_tags=["overload_heating"], acceptance_rules=acceptance_groups(["lower resistance", "smaller resistance", "fault path"], ["larger current", "more current", "current rises"], ["heating", "overheat", "more energy dissipation"])) ,
    ])
    t.extend([
        mcq("M11L5_M9", "A damaged cable leaves a 1 ohm fault across a 12 V supply. The current is...", ["12 A", "1 A", "6 A", "24 A"], 0, "Use I = V/R = 12/1.", ["short_circuit_confusion"], skill_tags=["short_circuit_risk"]),
        short("M11L5_M10", "Why is a 5 A fuse more likely to open during that 12 A fault than during a normal 2 A run?", ["Because the fault current is above the fuse rating while the normal current is below it, so the fuse interrupts the unsafe case.", "Because the guard link is designed to break the path only when the current becomes too large."], "Use above-rating and below-rating language.", ["fuse_parallel_confusion", "short_circuit_confusion"], skill_tags=["fuse_role"], acceptance_rules=acceptance_groups(["above", "exceeds", "greater than"], ["fuse rating", "5 a"], ["below", "normal current", "2 a"], ["open", "interrupt", "break the path"])) ,
    ])
    return {"d": d, "c": c, "t": t}


def equivalent_lesson() -> Dict[str, Any]:
    d = [
        mcq("M11L6_D1", "Equivalent resistance means...", ["one single resistance that has the same effect as the whole network", "the largest resistor in the circuit", "the same as total current", "the safety rating of a fuse"], 0, "Equivalent resistance is the one-resistor replacement for the network.", ["equivalent_resistance_confusion"], skill_tags=["equivalent_definition"]),
        mcq("M11L6_D2", "When simplifying a mixed network, a good first move is to...", ["identify a clear series or parallel section and reduce it", "add every resistor together no matter the layout", "assume all branches have the same current", "remove the battery from the picture"], 0, "Mixed networks are reduced step by step.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_reduction_method"]),
        mcq("M11L6_D3", "Two resistors 2 ohm and 3 ohm in series reduce to...", ["5 ohm", "1.2 ohm", "6 ohm", "0.5 ohm"], 0, "Series resistances add.", ["equivalent_resistance_confusion"], skill_tags=["series_resistance_calc"]),
        mcq("M11L6_D4", "Two resistors 6 ohm and 3 ohm in parallel reduce to...", ["2 ohm", "9 ohm", "4.5 ohm", "3 ohm"], 0, "1/R = 1/6 + 1/3 gives 1/2, so R = 2 ohm.", ["equivalent_resistance_confusion"], skill_tags=["parallel_resistance_calc"]),
        short("M11L6_D5", "Why must a mixed network be reduced step by step rather than by one big shortcut?", ["Because some parts are series and some are parallel, so you have to simplify the actual structure in stages.", "Because the network logic decides which resistors combine directly and which do not."], "Use structure-in-stages language.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_reduction_method"], acceptance_rules=acceptance_groups(["step by step", "stages", "one section at a time"], ["series", "parallel", "structure", "network logic"], ["combine directly", "simplify"])) ,
        mcq("M11L6_D6", "What is always true for a parallel equivalent resistance?", ["It is less than the smallest branch resistance.", "It is greater than every branch resistance.", "It is the direct sum of all branch resistances.", "It must equal the battery voltage."], 0, "Parallel equivalent resistance is below the smallest branch.", ["equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"]),
        short("M11L6_D7", "Why is equivalent resistance useful before finding total current?", ["Because it turns the whole network into one effective resistance that can be used with the source voltage.", "Because it lets you treat the network like one simpler resistor first."], "Use one-effective-resistor language.", ["equivalent_resistance_confusion"], skill_tags=["equivalent_definition"], acceptance_rules=acceptance_groups(["one", "single", "effective"], ["resistance", "resistor"], ["source voltage", "find current", "simpler"])) ,
        mcq("M11L6_D8", "Best summary of network reduction:", ["reduce clear series and parallel parts until one total resistance remains", "add every resistance first, then guess the current", "ignore the junctions", "treat every circuit as one-lane only"], 0, "That is the mixed-network method.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_reduction_method"]),
    ]
    c = [
        short("M11L6_C1", "How would you explain equivalent resistance without using the word equivalent?", ["It is the one resistance that would limit the source current in the same way as the whole network.", "It is the single drag that matches the effect of the full circuit."], "Use same-effect language.", ["equivalent_resistance_confusion"], skill_tags=["equivalent_definition"], acceptance_rules=acceptance_groups(["one", "single"], ["resistance", "drag"], ["same effect", "same current", "matches"], ["whole network", "full circuit"])) ,
        mcq("M11L6_C2", "Which pair can be combined directly as series?", ["two resistors on one path with no branch between them", "any two resistors drawn near each other", "any two resistors connected to a battery", "only equal resistors"], 0, "Series reduction needs one uninterrupted path between them.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_reduction_method"]),
        mcq("M11L6_C3", "Which pair can be combined directly as parallel?", ["two resistors connected between the same two junctions", "two resistors with the same value", "two resistors touching the same battery", "two resistors drawn vertically"], 0, "Parallel reduction needs the same two junctions.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_reduction_method"]),
        short("M11L6_C4", "Why is 'just add all the resistors' wrong for a mixed circuit?", ["Because only series sections add directly; parallel sections follow a different rule.", "Because the network must be reduced according to its actual series-and-parallel structure."], "Use different-rule-for-parallel language.", ["mixed_network_reduction_confusion", "equivalent_resistance_confusion"], skill_tags=["mixed_reduction_method"], acceptance_rules=acceptance_groups(["series", "add"], ["parallel", "different rule"], ["structure", "network"])) ,
        mcq("M11L6_C5", "If you add another parallel branch to a network, the total equivalent resistance usually...", ["decreases", "increases", "stays fixed", "turns into current"], 0, "More parallel paths lower the equivalent resistance.", ["equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"]),
        short("M11L6_C6", "Why does reduction help before a total-current calculation?", ["Because once the network is replaced by one total resistance, the source-current step becomes straightforward.", "Because the total resistance lets you treat the whole circuit as one simpler load."], "Use one-total-resistance language.", ["equivalent_resistance_confusion"], skill_tags=["equivalent_definition"], acceptance_rules=acceptance_groups(["one total resistance", "single resistance", "simpler load"], ["source current", "total current", "whole circuit"])) ,
    ]
    t = [
        mcq("M11L6_M1", "A circuit has a 2 ohm resistor in series with a parallel pair of 6 ohm and 3 ohm. The parallel pair reduces to...", ["2 ohm", "9 ohm", "3 ohm", "1 ohm"], 0, "6 ohm parallel 3 ohm gives 2 ohm.", ["equivalent_resistance_confusion"], skill_tags=["parallel_resistance_calc"]),
        mcq("M11L6_M2", "The total resistance of that network is then...", ["4 ohm", "5 ohm", "2 ohm", "11 ohm"], 0, "Add the 2 ohm series resistor to the 2 ohm equivalent.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_network_calc"]),
        short("M11L6_M3", "Why was it correct to simplify the branch pair before adding the series resistor?", ["Because the branch pair was a clear parallel section, and only after reducing it could the remaining series path be added.", "Because mixed networks are simplified one valid section at a time."], "Use valid-section language.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_reduction_method"], acceptance_rules=acceptance_groups(["parallel section", "branch pair"], ["reduce", "simplify"], ["then", "after"], ["series"])) ,
        mcq("M11L6_M4", "That 4 ohm total resistance on a 12 V source gives a total current of...", ["3 A", "4 A", "48 A", "1/3 A"], 0, "I = V/R = 12/4.", ["equivalent_resistance_confusion"], skill_tags=["mixed_network_calc"]),
        short("M11L6_M5", "What does the final 4 ohm value represent?", ["It is the single equivalent resistance of the whole network.", "It is the one resistance that would have the same overall effect on the source current."], "Use whole-network language.", ["equivalent_resistance_confusion"], skill_tags=["equivalent_definition"], acceptance_rules=acceptance_groups(["single", "one"], ["equivalent resistance", "resistance"], ["whole network", "overall effect", "same source current"])) ,
        mcq("M11L6_M6", "If an extra parallel branch is added to the middle section, the total resistance will most likely...", ["decrease below 4 ohm", "increase above 4 ohm", "stay exactly 4 ohm", "become 12 V"], 0, "Extra branches lower equivalent resistance.", ["equivalent_resistance_confusion"], skill_tags=["parallel_equivalent"]),
        short("M11L6_M7", "Why is equivalent-drag language helpful in the Switchyard model?", ["Because it lets a complicated network be treated as one effective route drag for the source.", "Because the source sees one total drag after the reduction is finished."], "Use one-effective-drag language.", ["equivalent_resistance_confusion"], skill_tags=["equivalent_definition"], acceptance_rules=acceptance_groups(["one", "single", "effective"], ["drag", "resistance"], ["source", "complicated network", "whole network"])) ,
        mcq("M11L6_M8", "Best final summary of mixed-network reduction:", ["identify a valid series or parallel block, reduce it, redraw, and repeat", "multiply every resistor by the battery voltage", "always add all the resistors first", "ignore parallel branches until the end"], 0, "That is the correct reduction workflow.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_reduction_method"]),
    ]
    d.extend([
        mcq("M11L6_D9", "Two equal 8 ohm branches in parallel reduce to...", ["4 ohm", "8 ohm", "16 ohm", "2 ohm"], 0, "Equal parallel resistors halve when there are two of them.", ["equivalent_resistance_confusion"], skill_tags=["parallel_resistance_calc"]),
        mcq("M11L6_D10", "That 4 ohm equivalent in series with a 2 ohm resistor gives a total of...", ["6 ohm", "2 ohm", "8 ohm", "4 ohm"], 0, "Series resistances add.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_network_calc"]),
    ])
    c.extend([
        mcq("M11L6_C7", "A reduced network has a total resistance of 6 ohm on a 12 V source. The total current is...", ["2 A", "6 A", "0.5 A", "18 A"], 0, "Use I = V/R = 12/6.", ["equivalent_resistance_confusion"], skill_tags=["mixed_network_calc"]),
        short("M11L6_C8", "Why must the total current step wait until the full equivalent resistance is known?", ["Because the source current depends on the resistance of the whole network, not just one unfinished section.", "Because only the final single effective resistance tells you the total load seen by the source."], "Use whole-network-load language.", ["equivalent_resistance_confusion", "mixed_network_reduction_confusion"], skill_tags=["equivalent_definition"], acceptance_rules=acceptance_groups(["whole network", "full network", "total load"], ["final", "single", "effective"], ["resistance"], ["total current", "source current"])) ,
    ])
    t.extend([
        mcq("M11L6_M9", "A 16 V source feeds a 4 ohm resistor in series with a parallel pair of 8 ohm and 8 ohm. The total resistance is...", ["8 ohm", "12 ohm", "4 ohm", "16 ohm"], 0, "The 8 ohm parallel pair becomes 4 ohm, then 4 ohm + 4 ohm = 8 ohm.", ["mixed_network_reduction_confusion"], skill_tags=["mixed_network_calc"]),
        mcq("M11L6_M10", "For that same network, the total current is...", ["2 A", "4 A", "8 A", "0.5 A"], 0, "Use I = V/R = 16/8.", ["equivalent_resistance_confusion"], skill_tags=["mixed_network_calc"]),
    ])
    return {"d": d, "c": c, "t": t}


def build_m11_lesson(
    *,
    lesson_id: str,
    title: str,
    bank: Dict[str, Any],
    lab_id: str,
    lab_title: str,
    lab_description: str,
    lab_instructions: Sequence[str],
    lab_outcomes: Sequence[str],
    lab_fields: Sequence[str],
    lab_depth: str,
    analogy_text: str,
    commitment_prompt: str,
    micro_prompts: Sequence[Dict[str, str]],
    inquiry: Sequence[Dict[str, str]],
    recon_prompts: Sequence[str],
    capsule_prompt: str,
    concept_targets: Sequence[str],
    core_concepts: Sequence[str],
    prerequisite_lessons: Sequence[str],
    misconception_focus: Sequence[str],
    formulas: Sequence[Dict[str, Any]],
    representations: Sequence[Dict[str, Any]],
    analogy_focus: str,
    worked_examples: Sequence[Dict[str, Any]],
    visual_asset: Dict[str, Any],
    animation_asset: Dict[str, Any],
    simulation_contract: Dict[str, Any],
    reflection_prompts: Sequence[str],
    mastery_skills: Sequence[str],
    variation_plan: Dict[str, str],
    scaffold_support: Dict[str, Any],
    visual_topic: str,
) -> Dict[str, Any]:
    return lesson_spec(
        lesson_id,
        title,
        sim(lab_id, lab_title, lab_description, lab_instructions, lab_outcomes, lab_fields, lab_depth),
        bank["d"],
        analogy_text,
        commitment_prompt,
        micro_prompts,
        inquiry,
        recon_prompts,
        capsule_prompt,
        bank["c"],
        bank["t"],
        contract(
            concept_targets=concept_targets,
            core_concepts=core_concepts,
            prerequisite_lessons=prerequisite_lessons,
            misconception_focus=misconception_focus,
            formulas=formulas,
            representations=representations,
            analogy_map=switchyard_map(analogy_focus),
            worked_examples=worked_examples,
            visual_assets=[visual_asset],
            animation_assets=[animation_asset],
            simulation_contract=simulation_contract,
            reflection_prompts=reflection_prompts,
            mastery_skills=mastery_skills,
            variation_plan=variation_plan,
            scaffold_support=scaffold_support,
            visual_clarity_checks=visual_checks(visual_topic),
        ),
    )


def series_lesson_spec() -> Dict[str, Any]:
    bank = series_lesson()
    return build_m11_lesson(
        lesson_id="M11_L1",
        title="One-Lane Chains and Series Current",
        bank=bank,
        lab_id="m11_series_chain_lab",
        lab_title="Series chain lab",
        lab_description="Build a one-lane chain and watch the same current pass every station while the source voltage is shared.",
        lab_instructions=["Build a single-path chain with two or three stations.", "Add another series resistor and compare the current.", "Track current and boost drop separately."],
        lab_outcomes=["Explain why the same current flows through every series component.", "Explain why series resistance adds.", "Explain why the source voltage is shared across the stations."],
        lab_fields=["source_voltage", "resistor_a", "resistor_b", "resistor_c"],
        lab_depth="Series current, shared voltage, and resistance addition.",
        analogy_text="A one-lane chain is the simplest switchyard. Every carrier must visit every task station in order, so the chain carries one common current all the way through.",
        commitment_prompt="Name the path structure before you calculate. If the network is really one-lane, the same current story should stay visible everywhere.",
        micro_prompts=[prompt_block("What is the route shape?", "One uninterrupted path."), prompt_block("What does one uninterrupted path imply about current?", "The same current flows through every station.")],
        inquiry=[prompt_block("Add a third series station.", "The total drag rises and the current falls."), prompt_block("Compare equal and unequal stations.", "The current stays the same; the voltage drops can differ.")],
        recon_prompts=["Why is current not used up by the first series station?", "Why does a one-lane chain make current equality such a strong rule?"],
        capsule_prompt="Series means one path, so current equality comes first and resistance addition follows.",
        concept_targets=["Explain why one path gives the same current everywhere.", "Explain why series resistance adds.", "Explain why source voltage is shared across series stations."],
        core_concepts=["In a one-lane chain, every carrier passes every station.", "Series circuits carry the same current through each component.", "Series resistances add to one larger total resistance.", "The source voltage is divided into component voltage drops."],
        prerequisite_lessons=["M10_L5"],
        misconception_focus=["series_current_confusion", "series_voltage_share_confusion", "current_used_up_confusion", "equivalent_resistance_confusion"],
        formulas=[relation("R_series = R1 + R2 + ...", "Series resistances add.", ["ohm"], "Use when resistors sit on one uninterrupted path."), relation("I = V / R", "Total current follows the source voltage and total series resistance.", ["A", "V", "ohm"], "Use after finding the total series resistance.")],
        representations=[representation("words", "States same-current and shared-voltage rules in sentence form."), representation("formula", "Adds series resistance and then applies Ohm's law to the whole chain."), representation("diagram", "Shows a one-lane chain with no branch junctions."), representation("table", "Compares current and voltage drop at each series station.")],
        analogy_focus="the class is tracking one-lane current and shared boost drops through a series chain",
        worked_examples=[
            worked("A 20 V source drives 4 ohm and 6 ohm in series. Find the total resistance and current.", ["Add the series resistances first.", "Use the source voltage with the total resistance.", "Keep the same-current rule visible."], "R_total = 10 ohm and I = 2 A", "One path means the whole chain can be reduced to one total drag before current is found.", "This is the foundational series workflow."),
            worked("Two equal resistors share 18 V in series. What is the voltage across each?", ["Recognize equal series components.", "Keep the same series current idea in mind.", "Share the total source voltage equally."], "Each resistor has 9 V across it", "Equal series components share the source voltage equally.", "This helps separate same-current from same-voltage thinking."),
            worked("A learner says the first resistor takes most of the current. Fix the sentence.", ["Check the path shape.", "Use the same-current rule.", "Then talk about voltage drop instead."], "The current is the same through every series resistor; it is the voltage drop that can differ.", "Series current is common to the path, so 'used-up current' is the wrong story.", "This directly corrects one of the most persistent series misconceptions."),
        ],
        visual_asset=visual("m11-l1-series-chain", "series_chain", "One-lane chain", "Shows one series path with the same checkpoint rate through each task station.", "The diagram keeps one-path current and shared voltage drops visible together.", template="electric_circuit_diagram", meta={"circuit_type": "series_chain"}),
        animation_asset=animation("m11-l1-series-current", "series_chain", "Series current", "Shows carriers moving through one chain so the same current story stays visible at every station."),
        simulation_contract=sim_contract("m11-l1-series-chain-lab", "series_chain", "What does one uninterrupted path force the current to do?", "Start with two series stations and compare current before and after adding another series resistor.", ["Keep the source fixed while adding a series station.", "Compare current equality with voltage sharing."], "Do not call voltage or current 'used up' without separating the two stories.", "One path means one common current, while resistance adds and voltage is shared.", [("source_voltage", "Source voltage", "Sets the total boost available to the chain."), ("resistor_a", "Station A drag", "Contributes to the total series resistance."), ("resistor_b", "Station B drag", "Contributes to the total series resistance.")], [("Total current", "Shows the same current value for the whole chain."), ("Voltage drop at A", "Shows one share of the source voltage."), ("Voltage drop at B", "Shows another share of the source voltage.")]),
        reflection_prompts=["Why does one path force the same current through every series station?", "Why is it more accurate to say voltage is shared than to say current is used up in series?"],
        mastery_skills=["series_current", "series_voltage_share", "series_resistance_calc", "series_current_calc", "series_summary"],
        variation_plan={"diagnostic": "Rotate between one-path current, shared voltage, and added-series-resistance stems.", "concept_gate": "Vary between sentence explanations, structure recognition, and source-versus-component voltage prompts.", "mastery": "Mix numeric series totals, same-current explanations, and current-used-up corrections before repeating stems."},
        scaffold_support=scaffold("A one-lane chain keeps one common current throughout the path.", "Identify the route structure first, then separate current equality from voltage sharing.", "If there is only one path, what must every carrier do?", "Do not say the first series component uses up the current when the better story is shared voltage drop.", "In the Switchyard world, one-lane chains force every carrier through every station.", "What does the one-lane rule tell you about current before you calculate anything?", [extra_section("Series resistance", "Every extra station in the same path adds more drag to the total route.", "What happens to the total resistance when another series resistor is added?"), extra_section("Shared voltage", "The source boost is divided across the series stations as separate voltage drops.", "Which quantity is shared in series: current or voltage?")]),
        visual_topic="series-chain",
    )


def parallel_lesson_spec() -> Dict[str, Any]:
    bank = parallel_lesson()
    return build_m11_lesson(
        lesson_id="M11_L2",
        title="Branch Decks and Shared Voltage",
        bank=bank,
        lab_id="m11_branch_deck_lab",
        lab_title="Branch deck lab",
        lab_description="Split the flow across several branches and compare shared branch voltage with different branch currents.",
        lab_instructions=["Build two branches between the same two junctions.", "Change one branch resistance at a time.", "Watch current split and rejoin while branch voltage stays shared."],
        lab_outcomes=["Explain why parallel branches share voltage.", "Explain why branch currents can differ.", "Explain why adding branches lowers equivalent resistance."],
        lab_fields=["source_voltage", "branch_a_resistance", "branch_b_resistance", "branch_count"],
        lab_depth="Parallel voltage, current splitting, and equivalent resistance.",
        analogy_text="A branch deck gives carriers several routes between the same two junctions. The boost-per-token across each branch is the same, but the flow can split unevenly before rejoining.",
        commitment_prompt="Trace the common junctions first. If the branches share the same two endpoints, keep the shared-voltage rule visible before you start computing currents.",
        micro_prompts=[prompt_block("What do the branches share?", "The same two junctions."), prompt_block("What does sharing the same two junctions imply?", "They share the same branch voltage.")],
        inquiry=[prompt_block("Raise one branch resistance.", "That branch current falls while the branch voltage stays the same."), prompt_block("Add another branch.", "The source current rises because the total resistance falls.")],
        recon_prompts=["Why can branch currents differ even though branch voltage is the same?", "Why does adding a branch lower the total resistance instead of raising it?"],
        capsule_prompt="Parallel means shared voltage across branches, split current at the junctions, and a smaller equivalent resistance than any one branch alone.",
        concept_targets=["Explain why parallel branches share voltage.", "Explain why branch currents split and recombine.", "Explain why parallel equivalent resistance is less than the smallest branch."],
        core_concepts=["Branches connected between the same two junctions share the same voltage.", "Current splits among parallel branches and recombines after the junction.", "Branch currents can differ because branch resistances can differ.", "Adding a parallel path lowers the total equivalent resistance."],
        prerequisite_lessons=["M11_L1"],
        misconception_focus=["parallel_voltage_confusion", "parallel_current_split_confusion", "added_branch_raises_resistance_confusion", "equivalent_resistance_confusion"],
        formulas=[relation("I_total = I1 + I2 + ...", "Branch currents add to the main current.", ["A"], "Use at junctions where currents split and rejoin."), relation("1 / R_parallel = 1 / R1 + 1 / R2 + ...", "Parallel branches reduce the equivalent resistance.", ["ohm"], "Use for branches between the same two junctions.")],
        representations=[representation("words", "Explains shared branch voltage and split current in sentence form."), representation("formula", "Applies current addition and parallel-resistance relations."), representation("diagram", "Shows two or more branches between common junctions."), representation("table", "Compares branch resistance, branch current, and branch voltage.")],
        analogy_focus="the class is comparing branch currents while keeping the shared branch boost fixed",
        worked_examples=[
            worked("A 12 V source feeds 6 ohm and 3 ohm branches in parallel. Find each branch current.", ["Recognize that each branch sees the same 12 V.", "Use I = V/R on each branch separately.", "State why the currents differ."], "The branch currents are 2 A and 4 A", "Shared branch voltage does not force equal current when the branch resistances differ.", "This is the core branch-current pattern."),
            worked("The two branch currents above rejoin. What is the total current?", ["Keep the branch currents separate first.", "Use the junction rule.", "Add the rejoining currents."], "The total current is 6 A", "Parallel currents add when branches rejoin.", "This locks in the split-and-sum picture."),
            worked("A learner says adding a new branch increases resistance because there is more wire. Fix the sentence.", ["Think in terms of available paths.", "State what happens to equivalent resistance.", "Then connect that to total current."], "An added branch gives another path, so the equivalent resistance decreases and the source current can increase.", "Parallel resistance is about easier overall flow, not about the drawing looking larger.", "This directly addresses a major network misconception."),
        ],
        visual_asset=visual("m11-l2-branch-deck", "parallel_branch", "Branch deck", "Shows shared branch voltage and split current through unequal branch drags.", "The branch deck keeps same-voltage and split-current ideas visible together.", template="electric_circuit_diagram", meta={"circuit_type": "parallel_branch"}),
        animation_asset=animation("m11-l2-branch-split", "parallel_branch", "Branch split", "Shows carriers dividing across branches and recombining at the rejoin junction."),
        simulation_contract=sim_contract("m11-l2-branch-deck-lab", "parallel_branch", "What stays the same across each branch, and what is allowed to differ?", "Start with two unequal branches connected between the same two junctions.", ["Change one branch drag while keeping the source fixed.", "Add another branch and compare the total current."], "Do not import the series current rule into a branch deck.", "Branch voltage is shared, but branch currents depend on branch resistance.", [("source_voltage", "Source voltage", "Sets the common branch voltage."), ("branch_a_resistance", "Branch A drag", "Controls the first branch current."), ("branch_b_resistance", "Branch B drag", "Controls the second branch current.")], [("Branch A current", "Shows the current in branch A."), ("Branch B current", "Shows the current in branch B."), ("Total current", "Shows the sum of the branch currents.")]),
        reflection_prompts=["Why can two parallel branches have different currents even though they share the same voltage?", "Why does adding a new branch usually lower the total equivalent resistance?"],
        mastery_skills=["parallel_voltage", "parallel_current_sum", "parallel_current_compare", "parallel_equivalent", "parallel_summary"],
        variation_plan={"diagnostic": "Rotate between shared-voltage, split-current, and added-branch prompts.", "concept_gate": "Vary between same-two-junction reasoning, branch-current comparison, and branch independence prompts.", "mastery": "Mix numeric branch-current calculations, equivalent-resistance reasoning, and natural-language branch summaries before repeating stems."},
        scaffold_support=scaffold("A branch deck shares the same branch voltage while the current is allowed to split.", "Find the common junctions first, then keep voltage and current roles separate.", "If two branches connect between the same two points, what should match across them?", "Do not import the same-current rule from series into a parallel network.", "In the Switchyard world, the same entry and exit junctions give each branch the same boost-per-token.", "Which quantity is shared across the branches, and which quantity can split?", [extra_section("Current split", "The branch currents can be different if the branch drags are different, and they add again when the flow rejoins.", "What happens to the total current when branch currents rejoin?"), extra_section("Equivalent drag", "An extra branch makes the total route easier overall, so the equivalent resistance falls.", "Why does adding a branch usually increase the source current?")]),
        visual_topic="branch-deck",
    )


def power_lesson_spec() -> Dict[str, Any]:
    bank = power_lesson()
    return build_m11_lesson(
        lesson_id="M11_L3",
        title="Task Stations and Shed Rate",
        bank=bank,
        lab_id="m11_shed_rate_lab",
        lab_title="Shed-rate lab",
        lab_description="Compare lamps and resistor stations by how much energy they shed each second.",
        lab_instructions=["Set current and voltage at a task station.", "Compare a dim and a bright lamp.", "Track power as energy transfer rate instead of current used up."],
        lab_outcomes=["Explain power as energy transfer rate.", "Use P = IV for component power.", "Connect larger power with larger shed rate and often greater brightness."],
        lab_fields=["station_voltage", "station_current", "station_type", "comparison_mode"],
        lab_depth="Component power and shed-rate reasoning.",
        analogy_text="Every task station in the switchyard sheds some of the carriers' boost. What matters is not whether current gets used up, but how much energy the station transfers each second.",
        commitment_prompt="Before you say a device is bright or hot, say what the station is shedding each second. That keeps power on the energy-transfer side of the story.",
        micro_prompts=[prompt_block("What does power measure here?", "Energy transferred each second."), prompt_block("What two circuit quantities set component power?", "Current and voltage across the component.")],
        inquiry=[prompt_block("Keep current fixed and double the voltage drop.", "The power doubles."), prompt_block("Keep voltage fixed and increase current.", "The power rises because more energy is transferred each second.")],
        recon_prompts=["Why is power a better idea than 'used-up current' for lamp brightness?", "Why does P = IV fit the Switchyard story of a task station?"],
        capsule_prompt="Power is the shed rate at a task station: more current and/or more voltage drop means more energy transferred each second.",
        concept_targets=["Explain power as the rate of energy transfer at a component.", "Use P = IV conceptually and quantitatively.", "Explain why brighter or hotter devices often have larger power dissipation."],
        core_concepts=["Power tells how much energy a component transfers each second.", "Component power depends on both current and voltage across the component.", "A device can have the same current as another and still have different power if its voltage drop is different.", "Power is not the same thing as current."],
        prerequisite_lessons=["M11_L1", "M11_L2"],
        misconception_focus=["power_current_confusion", "power_energy_confusion", "current_used_up_confusion", "series_voltage_share_confusion"],
        formulas=[relation("P = IV", "Power is current times potential difference across the component.", ["W", "A", "V"], "Use when current and voltage across a component are known."), relation("1 W = 1 J/s", "Power is energy transfer per second.", ["W", "J", "s"], "Use when translating watts back into the energy-rate meaning.")],
        representations=[representation("words", "Explains power as shed rate or energy transfer rate."), representation("formula", "Uses P = IV and 1 W = 1 J/s."), representation("diagram", "Shows stations with different current and voltage-drop combinations."), representation("table", "Compares station current, station voltage, and station power.")],
        analogy_focus="the class is comparing how strongly different task stations shed energy each second",
        worked_examples=[
            worked("A lamp has 2 A through it and 6 V across it. Find its power.", ["Use the component power rule P = IV.", "Multiply current by voltage.", "Translate the answer back into J/s."], "P = 12 W", "The lamp transfers 12 J of energy each second.", "This makes power feel like a physical rate, not just a number."),
            worked("Two lamps have the same current, but one has a larger voltage drop. Which is brighter in the model?", ["Keep the current comparison fixed.", "Compare the voltage drops.", "Use P = IV conceptually."], "The lamp with the larger voltage drop has the larger power and is likely brighter.", "Same current does not force same power when voltage drops differ.", "This helps students stop collapsing current and power together."),
            worked("A student says a lamp is bright because it uses up more current. Fix the sentence.", ["Keep current and power separate.", "State what power measures.", "Then connect brightness to energy transfer rate."], "A lamp is bright because it transfers more energy each second, not because it destroys current.", "Power is the right language for brightness and heating comparisons.", "This corrects a very common circuits misunderstanding."),
        ],
        visual_asset=visual("m11-l3-shed-rate", "power_shed", "Task stations and shed rate", "Shows two task stations with different current and voltage-drop combinations and compares their power.", "The visual keeps current and energy-shed rate clearly separated.", template="electric_circuit_diagram", meta={"circuit_type": "power_station"}),
        animation_asset=animation("m11-l3-power-compare", "power_shed", "Power compare", "Shows two stations shedding different amounts of energy per second as current and voltage change."),
        simulation_contract=sim_contract("m11-l3-shed-rate-lab", "power_shed", "What makes one task station shed more energy each second than another?", "Start with two stations and compare one current value with two different voltage drops.", ["Keep current fixed while changing voltage.", "Then keep voltage fixed while changing current."], "Do not turn power into a second name for current.", "Power is the station's energy-transfer rate, and P = IV ties flow and voltage drop together.", [("station_voltage", "Station voltage", "Sets the boost drop across the station."), ("station_current", "Station current", "Sets how many carriers per second reach the station."), ("station_type", "Station type", "Switches between lamp and heater style loads.")], [("Station power", "Shows the shed rate in watts."), ("Energy each second", "Translates watts back into joules per second."), ("Brightness/heat cue", "Shows the visible effect of larger power.")]),
        reflection_prompts=["Why is power a better language than used-up current when comparing lamp brightness?", "Why can two components have the same current but different power?"],
        mastery_skills=["power_definition", "power_formula", "power_calculation", "power_compare", "brightness_reasoning"],
        variation_plan={"diagnostic": "Rotate between power definition, P = IV, and brightness-as-shed-rate prompts.", "concept_gate": "Vary between current-versus-power contrasts, lamp/heater reasoning, and energy-per-second language.", "mastery": "Mix numeric power calculations, J/s translations, and current-versus-power explanations before repeating stems."},
        scaffold_support=scaffold("A task station's power is how much energy it sheds each second.", "Keep current and voltage drop visible together before you talk about power.", "If a component has a larger power, what is larger each second?", "Do not say a lamp is bright because it uses up current when the better idea is energy shed per second.", "A brighter or hotter station is one that is shedding more energy from the carriers each second.", "Which two circuit quantities together tell you the station's shed rate?", [extra_section("Watts as J/s", "A watt is a joule per second, so power is always a rate story.", "What does 12 W mean in joules each second?"), extra_section("Same current, different power", "At the same current, a component with a larger voltage drop has a larger power.", "Why does a larger voltage drop matter for power if the current stays fixed?")]),
        visual_topic="shed-rate",
    )


def route_map_lesson_spec() -> Dict[str, Any]:
    bank = route_map_lesson()
    return build_m11_lesson(
        lesson_id="M11_L4",
        title="Route Maps and Circuit Diagrams",
        bank=bank,
        lab_id="m11_route_map_lab",
        lab_title="Route-map lab",
        lab_description="Translate physical circuit layouts into schematic route maps and use the connection logic to identify series and parallel sections.",
        lab_instructions=["Compare a physical layout with a route map of the same network.", "Mark the junctions and trace each path.", "Identify the series and parallel sections before any calculation."],
        lab_outcomes=["Explain why schematics are symbolic.", "Read circuit diagrams by tracing junctions and paths.", "Identify series and parallel sections from a route map."],
        lab_fields=["layout_mode", "junction_count", "branch_count", "station_count"],
        lab_depth="Schematic reading and structure recognition.",
        analogy_text="A route map in the switchyard is like a transit map: it is not a picture of the hardware table. It is a symbolic map of how the network is connected.",
        commitment_prompt="Start with the junctions and the paths, not with how pretty or realistic the picture looks. The connection pattern is the physics.",
        micro_prompts=[prompt_block("What does a route map preserve?", "The network connections."), prompt_block("What should you mark first when decoding it?", "The junctions and the paths between them.")],
        inquiry=[prompt_block("Redraw the same circuit in a new layout.", "The physics stays the same if the connections stay the same."), prompt_block("Mark two shared junctions.", "That is the clue for a parallel branch.")],
        recon_prompts=["Why can two drawings look different but still represent the same circuit?", "Why is a schematic helpful before resistance reduction?"],
        capsule_prompt="A circuit diagram is a symbolic route map of the network, and the first reading move is to trace junctions and paths.",
        concept_targets=["Explain why circuit diagrams are symbolic maps rather than realistic pictures.", "Read schematics by tracing connections.", "Identify series and parallel sections from route maps."],
        core_concepts=["A schematic shows electrical connections, not physical placement.", "Series sections are identified by one path with no branch between components.", "Parallel sections are identified by shared junction pairs.", "Diagram reading prepares later resistance reduction by exposing the network structure."],
        prerequisite_lessons=["M11_L1", "M11_L2"],
        misconception_focus=["diagram_picture_confusion", "mixed_network_reduction_confusion"],
        formulas=[relation("same junction pair -> parallel; one uninterrupted path -> series", "Route-map reading turns connection clues into structure labels.", ["none"], "Use as a reading rule before numerical work.")],
        representations=[representation("words", "Defines a route map as a symbolic connection diagram."), representation("formula", "Captures the reading rules for identifying series and parallel from the map."), representation("diagram", "Compares the physical layout with the schematic layout."), representation("table", "Lists the clues for series and parallel from a map."), representation("model", "Shows the same network in more than one valid drawing form.")],
        analogy_focus="the class is using a route map to see the network logic more clearly than a realistic hardware picture would",
        worked_examples=[
            worked("Two lamps are drawn between the same two junctions. What kind of connection is this?", ["Ignore the physical spacing on the page.", "Find the shared junctions.", "Name the branch structure from the connection rule."], "It is a parallel connection", "Shared junction pairs are the defining clue for parallel branches.", "This helps students read structure from a map instead of from page layout."),
            worked("Two resistors are drawn one after another with no branch between them. What kind of connection is this?", ["Trace the path through both components.", "Check whether the current can split.", "Name the structure."], "It is a series connection", "One uninterrupted path is the defining series clue.", "This reinforces that series and parallel are connection ideas, not visual styles."),
            worked("A student says the spread-out drawing must be parallel because it looks wider. Fix the sentence.", ["Ignore page width and focus on connections.", "Check the junction structure.", "State the correct test for parallel."], "Parallel is decided by shared junctions, not by how spread out the picture looks.", "Diagram reading must stay grounded in circuit structure.", "This corrects a classic schematic-reading mistake."),
        ],
        visual_asset=visual("m11-l4-route-map", "route_map", "Route maps", "Shows one physical layout and one schematic view of the same network with the matching junction logic highlighted.", "The route map strips away layout detail so the series and parallel structure is easier to read.", template="electric_circuit_diagram", meta={"circuit_type": "route_map"}),
        animation_asset=animation("m11-l4-map-translation", "route_map", "Map translation", "Morphs a classroom layout into a symbolic route map while preserving the same connections."),
        simulation_contract=sim_contract("m11-l4-route-map-lab", "route_map", "How do you tell what kind of network you have from the route map alone?", "Start with one physical layout and its schematic, then mark the junctions and branch paths.", ["Redraw the same network in a different layout.", "Trace a branch deck and then a one-lane section on the route map."], "Do not treat the route map as a literal picture of the hardware positions.", "A route map is useful because it makes the connection structure easier to read.", [("layout_mode", "Layout view", "Switches between physical and schematic views."), ("junction_count", "Junction markers", "Highlights the shared nodes in the network."), ("branch_count", "Branch count", "Shows how many alternate paths exist.")], [("Series section cue", "Highlights one uninterrupted path."), ("Parallel section cue", "Highlights shared branch endpoints."), ("Map equivalence cue", "Shows that different drawings can represent the same network.")]),
        reflection_prompts=["Why can two schematics look different but still represent the same circuit?", "Why is route-map reading a useful skill before combined-resistance work?"],
        mastery_skills=["diagram_meaning", "diagram_connections", "diagram_equivalence", "series_parallel_from_map", "reduction_prep"],
        variation_plan={"diagnostic": "Rotate between symbolic-map meaning, series/parallel recognition, and layout-versus-connection prompts.", "concept_gate": "Vary between junction tracing, route-map explanation, and map equivalence items.", "mastery": "Mix structure recognition, natural-language schematic explanations, and preparation-for-reduction prompts before repeating stems."},
        scaffold_support=scaffold("A route map is a symbolic connection map, not a picture of the hardware.", "Mark the junctions first and trace the paths between them before you name any circuit structure.", "What should stay the same when two different drawings really represent the same circuit?", "Do not mistake page layout for circuit structure.", "In the Switchyard world, the route map helps you see the network logic more clearly than the physical layout does.", "Which clue on the route map tells you a branch deck is present?", [extra_section("Series clue", "A one-path section with no branch between components is a series section.", "What route-map feature tells you two components are in series?"), extra_section("Parallel clue", "If two components sit between the same two junctions, they form a parallel section.", "What route-map feature tells you two components are parallel?")]),
        visual_topic="route-map",
    )


def safety_lesson_spec() -> Dict[str, Any]:
    bank = safety_lesson()
    return build_m11_lesson(
        lesson_id="M11_L5",
        title="Guard Links, Fault Bridges, and Safety",
        bank=bank,
        lab_id="m11_guard_link_lab",
        lab_title="Guard-link lab",
        lab_description="Trigger overloads and fault bridges in the switchyard, then compare how fuses, breakers, and insulation protect the loop and the user.",
        lab_instructions=["Build a normal protected circuit.", "Introduce a fault bridge and compare the current.", "Place the guard link correctly and compare with insulation-only protection."],
        lab_outcomes=["Explain why low-resistance faults are dangerous.", "Explain what fuses and breakers do.", "Explain why insulation and guard links protect in different ways."],
        lab_fields=["source_voltage", "fault_toggle", "guard_link_rating", "insulation_toggle"],
        lab_depth="Short circuits, overloads, and protection.",
        analogy_text="A fault bridge is a dangerous shortcut in the switchyard. It lets carriers rush through an unintended low-drag path, so the guard link must open the loop before wires overheat.",
        commitment_prompt="Name the dangerous route condition first. Safety in circuits is about what the network makes current do, not just about saying the battery looks powerful.",
        micro_prompts=[prompt_block("What makes a short circuit dangerous?", "Its very low resistance can allow a very large current."), prompt_block("What should the guard link do?", "Open the circuit when the current becomes unsafe.")],
        inquiry=[prompt_block("Toggle on a fault bridge.", "The current surges because the path resistance collapses."), prompt_block("Raise the guard-link protection level too high.", "The circuit is less protected against overload.")],
        recon_prompts=["Why is a short circuit more dangerous than an ordinary extra branch?", "Why must a fuse be placed in series with the circuit it protects?"],
        capsule_prompt="Safety depends on preventing dangerous current and dangerous contact: guard links interrupt unsafe flow, and insulation blocks unsafe touch.",
        concept_targets=["Explain why short circuits and overloads are dangerous.", "Explain how fuses and breakers protect a circuit.", "Explain why insulation and protective barriers matter as a different kind of safety measure."],
        core_concepts=["A short circuit creates an unintended very low-resistance path.", "Low resistance can allow dangerously large current and rapid heating.", "A fuse or breaker protects by opening the circuit when current becomes unsafe.", "Insulation and protective barriers reduce the risk of unsafe contact with live parts."],
        prerequisite_lessons=["M11_L2", "M11_L3"],
        misconception_focus=["short_circuit_confusion", "safety_voltage_only_confusion", "fuse_parallel_confusion"],
        formulas=[relation("large current with low resistance can cause rapid heating", "Faults and overloads are dangerous because current and heating can rise quickly.", ["A"], "Use as a safety consequence statement rather than a plug-in formula.")],
        representations=[representation("words", "Explains fault current, protection devices, and insulation."), representation("formula", "Connects low resistance, large current, and unsafe heating in one rule story."), representation("diagram", "Shows a guarded main path and a dangerous fault bridge."), representation("table", "Compares fuse, breaker, and insulation roles."), representation("model", "Highlights safe and unsafe current routes in the Switchyard world.")],
        analogy_focus="the class is comparing a protected loop with a fault bridge and watching how the guard link responds",
        worked_examples=[
            worked("A worn wire creates a near-zero-resistance shortcut across the load. What kind of fault is this?", ["Notice that the new path is unintended.", "Notice that its resistance is extremely small.", "Name the circuit condition."], "It is a short circuit", "The defining feature is the unintended low-resistance path.", "This gives a clear physical meaning to the phrase short circuit."),
            worked("Why can that short circuit become dangerous so quickly?", ["Keep the source the same.", "Notice what the tiny resistance does to current.", "Then state the heating consequence."], "It can drive a very large current and rapid heating", "The safety danger comes from large current in the fault path.", "This connects circuit safety back to the electrical quantities already learned."),
            worked("Where should the fuse be placed, and why?", ["Ask which path current must follow in normal operation.", "Place the fuse in that same path.", "State how that placement lets it interrupt unsafe current."], "The fuse should be in series in the main current path", "A fuse protects only if it carries the same current as the circuit it is meant to interrupt.", "This blocks the common fuse-in-parallel mistake."),
        ],
        visual_asset=visual("m11-l5-guard-link", "guard_link_safety", "Guard links and fault bridges", "Shows a protected loop, a dangerous low-resistance fault path, and the guard link opening before overheating spreads.", "The visual separates fault path, current surge, and protection action clearly.", template="electric_circuit_diagram", meta={"circuit_type": "guard_link"}),
        animation_asset=animation("m11-l5-fault-trip", "guard_link_safety", "Fault trip", "Shows current surging through a fault bridge and the guard link opening the loop."),
        simulation_contract=sim_contract("m11-l5-guard-link-lab", "guard_link_safety", "What turns an ordinary circuit into a dangerous fault, and how does the protection respond?", "Start with a normal protected circuit, then toggle in a low-resistance fault path.", ["Add a fault bridge and compare the current.", "Move or retune the guard link and compare the protection outcome."], "Do not reduce safety to a battery-only story; the whole network matters.", "Faults and overloads are dangerous because they can drive large current, and protection works by interrupting that unsafe flow.", [("source_voltage", "Source voltage", "Keeps the supply side visible while the fault path changes."), ("fault_toggle", "Fault bridge", "Adds or removes the dangerous low-resistance shortcut."), ("guard_link_rating", "Guard-link rating", "Sets the current level where protection trips.")], [("Main current", "Shows the total current in the protected loop."), ("Fault warning", "Flags when a dangerous shortcut is present."), ("Guard-link status", "Shows whether the protection has opened the circuit.")]),
        reflection_prompts=["Why is a short circuit more dangerous than an ordinary extra branch?", "Why must a fuse or breaker sit in the main current path to protect the circuit properly?"],
        mastery_skills=["short_circuit_risk", "fuse_role", "fuse_position", "insulation_role", "safety_reasoning", "safety_summary"],
        variation_plan={"diagnostic": "Rotate between short-circuit, fuse, breaker, and insulation prompts.", "concept_gate": "Vary between low-resistance danger, series fuse placement, and voltage-versus-current safety reasoning.", "mastery": "Mix fault explanations, protection placement, and safety-summary wording before repeating stems."},
        scaffold_support=scaffold("Circuit safety is about stopping dangerous current and blocking dangerous contact.", "Name the fault path first, then decide what makes it dangerous and how the protection responds.", "What is the main electrical reason a short circuit is dangerous?", "Do not say only high voltage makes circuits dangerous when low-resistance faults and overload current are the main story here.", "In the Switchyard world, the guard link is the safety lock that opens when the loop starts pushing too many carriers through a dangerous path.", "What should a guard link do when the current becomes unsafe?", [extra_section("Fault bridges", "A fault bridge is an unintended low-resistance shortcut that can drive a large current.", "Why is a shortcut path more dangerous than an ordinary branch?"), extra_section("Protection roles", "Fuses and breakers interrupt unsafe current, while insulation protects by stopping unsafe contact.", "How is insulation protecting in a different way from a fuse?")]),
        visual_topic="guard-link",
    )


def equivalent_lesson_spec() -> Dict[str, Any]:
    bank = equivalent_lesson()
    return build_m11_lesson(
        lesson_id="M11_L6",
        title="Equivalent Drag and Network Reduction",
        bank=bank,
        lab_id="m11_equivalent_drag_lab",
        lab_title="Equivalent-drag lab",
        lab_description="Reduce mixed networks step by step until one total resistance remains, then use it to find the source current.",
        lab_instructions=["Identify one clear series or parallel section.", "Reduce that section to one equivalent drag.", "Redraw and repeat until one total resistance remains."],
        lab_outcomes=["Explain equivalent resistance as one matching drag for the full network.", "Reduce mixed circuits step by step.", "Use the final equivalent resistance to find total current."],
        lab_fields=["series_value", "parallel_a", "parallel_b", "source_voltage"],
        lab_depth="Combined resistance and mixed-network reduction.",
        analogy_text="Equivalent drag is the switchyard move that turns a complicated route network into one effective path resistance. The source only sees the total drag, so the network must be reduced in valid stages.",
        commitment_prompt="Do not attack the whole network at once. Mark a valid series or parallel block, reduce it, redraw, and then continue.",
        micro_prompts=[prompt_block("What does equivalent drag mean?", "One effective resistance for the whole network."), prompt_block("How should mixed networks be simplified?", "Step by step through valid series or parallel sections.")],
        inquiry=[prompt_block("Reduce a parallel pair first.", "That gives one equivalent branch drag."), prompt_block("Then combine the remaining series section.", "The total resistance becomes easier to calculate.")],
        recon_prompts=["Why is reduction a structural process rather than one big shortcut?", "Why is the final equivalent resistance useful before finding current?"],
        capsule_prompt="Network reduction works by replacing valid series and parallel sections with one equivalent drag until one total resistance remains.",
        concept_targets=["Explain equivalent resistance as the one resistance matching the whole network.", "Reduce mixed networks in valid steps.", "Use the final equivalent resistance to find source current."],
        core_concepts=["Equivalent resistance is one effective resistance for the whole network.", "Series sections add directly.", "Parallel sections reduce to a resistance smaller than the smallest branch.", "Mixed networks must be simplified step by step according to the actual structure."],
        prerequisite_lessons=["M11_L1", "M11_L2", "M11_L4"],
        misconception_focus=["equivalent_resistance_confusion", "mixed_network_reduction_confusion", "added_branch_raises_resistance_confusion"],
        formulas=[relation("R_series = R1 + R2 + ...", "Series sections add directly.", ["ohm"], "Use for one-path sections."), relation("1 / R_parallel = 1 / R1 + 1 / R2 + ...", "Parallel branches reduce to a smaller equivalent resistance.", ["ohm"], "Use for branches sharing the same two junctions."), relation("I = V / R_total", "Total current can be found once the whole network has been reduced to one total resistance.", ["A", "V", "ohm"], "Use after finding the final equivalent resistance.")],
        representations=[representation("words", "Explains equivalent resistance and the stepwise reduction method."), representation("formula", "Uses series addition, parallel reduction, and then total current."), representation("diagram", "Highlights one valid reduction block at a time."), representation("model", "Shows the reduce-redraw-repeat workflow.")],
        analogy_focus="the class is reducing a mixed network into one equivalent drag so the source-current step becomes simple",
        worked_examples=[
            worked("A 2 ohm resistor is in series with a parallel pair of 6 ohm and 3 ohm. Reduce the network.", ["Reduce the parallel pair first.", "Then add the remaining series resistor.", "State the final equivalent resistance."], "The network reduces to 4 ohm", "The parallel pair gives 2 ohm, which then adds with the series 2 ohm.", "This is the core mixed-network workflow."),
            worked("The 4 ohm equivalent network above is connected to a 12 V source. Find the total current.", ["Use the total equivalent resistance.", "Apply I = V/R to the full network.", "Report the source current."], "The total current is 3 A", "Once the network is reduced, the source sees one total resistance.", "This shows why reduction matters before current calculations."),
            worked("A learner says you should just add all resistors in a mixed network. Fix the method.", ["Check which parts are really series.", "Check which parts are really parallel.", "Reduce one valid block at a time."], "Mixed networks must be reduced according to the actual series-and-parallel structure, not by adding everything at once.", "Only some parts combine directly, so structure matters.", "This corrects the biggest reduction mistake."),
        ],
        visual_asset=visual("m11-l6-equivalent-drag", "equivalent_drag", "Equivalent drag", "Shows a mixed network being reduced in stages to one total resistance before total current is found.", "The visual makes the valid reduction order easy to follow.", template="electric_circuit_diagram", meta={"circuit_type": "equivalent_drag"}),
        animation_asset=animation("m11-l6-reduction-steps", "equivalent_drag", "Reduction steps", "Animates a mixed network reducing one valid section at a time until one total resistance remains."),
        simulation_contract=sim_contract("m11-l6-equivalent-drag-lab", "equivalent_drag", "How do you reduce a mixed network without destroying its structure?", "Start with one series section and one clear parallel pair in the same network.", ["Reduce the parallel pair first, then redraw the remaining series path.", "Compare the final total current before and after adding an extra branch."], "Do not add every resistor at once without checking the structure.", "Equivalent drag turns a complicated network into one effective resistance, but only after valid stepwise reduction.", [("series_value", "Series drag", "Sets the one-path section of the mixed network."), ("parallel_a", "Branch A drag", "Controls the first branch in the parallel section."), ("parallel_b", "Branch B drag", "Controls the second branch in the parallel section.")], [("Parallel equivalent", "Shows the reduced value of the branch deck."), ("Total resistance", "Shows the full network after stepwise reduction."), ("Total current", "Uses the source voltage and total resistance together.")]),
        reflection_prompts=["Why must a mixed network be reduced step by step instead of by one giant shortcut?", "Why is the final equivalent resistance so useful before finding total current?"],
        mastery_skills=["equivalent_definition", "series_resistance_calc", "parallel_resistance_calc", "parallel_equivalent", "mixed_reduction_method", "mixed_network_calc"],
        variation_plan={"diagnostic": "Rotate between equivalent-resistance meaning, direct series/parallel reduction, and mixed-method prompts.", "concept_gate": "Vary between valid-block recognition, same-effect language, and why-not-add-everything explanations.", "mastery": "Mix numeric mixed-network reductions, source-current calculations, and natural-language reduction explanations before repeating stems."},
        scaffold_support=scaffold("Equivalent drag is the one total resistance that matches the effect of the whole network.", "Identify a valid series or parallel block, reduce it, redraw, and repeat until only one resistance remains.", "What should you reduce first in a mixed network: everything at once, or one valid block at a time?", "Do not add all resistors together without checking whether the network section is really series or really parallel.", "The Switchyard model lets the source 'see' one final drag only after the network has been simplified correctly.", "Why is the final equivalent resistance useful before finding total current?", [extra_section("Series first or parallel first?", "You reduce whichever valid block is clearly available; the important rule is that the block must really be series or parallel.", "What makes a reduction step valid?"), extra_section("Final current", "Once one total resistance remains, the total source current can be found with the source voltage and that one resistance.", "Why does reduction make the final current step easier?")]),
        visual_topic="equivalent-drag",
    )


M11_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Series and parallel circuits, power dissipation, circuit diagrams, safety, and combined resistance calculations taught through the Switchyard-Loop Model so students track one-lane chains, branch decks, task stations, route maps, and guard links in one circuit world.",
    "mastery_outcomes": [
        "Distinguish clearly between series and parallel circuit behavior.",
        "Explain power dissipation as the rate of energy transfer at a component.",
        "Read and draw circuit diagrams as symbolic route maps.",
        "Explain why short circuits and overloads are dangerous and how protection devices respond.",
        "Calculate combined resistance by reducing series, parallel, and mixed networks step by step.",
        "Explain circuit networks with clean current, voltage, resistance, and safety language.",
    ],
    "lessons": [
        series_lesson_spec(),
        parallel_lesson_spec(),
        power_lesson_spec(),
        route_map_lesson_spec(),
        safety_lesson_spec(),
        equivalent_lesson_spec(),
    ],
}


RELEASE_CHECKS = [
    "Every lesson keeps the Switchyard-Loop world of chains, branches, stations, route maps, and guard links coherent.",
    "Every explorer is lesson-specific and does not fall back to generic simulation wording.",
    "Every lesson-owned bank supports fresh unseen diagnostic, concept-gate, and mastery questions before repeats.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example includes answer reasoning and not just a final value.",
    "Every visual keeps current, voltage, branch, and safety labels readable without clipping or quantity collapse.",
]


M11_MODULE_DOC, M11_LESSONS, M11_SIM_LABS = build_nextgen_module_bundle(
    module_id=M11_MODULE_ID,
    module_title=M11_MODULE_TITLE,
    module_spec=M11_SPEC,
    allowlist=M11_ALLOWLIST,
    content_version=M11_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=15,
    level="Module 11",
    estimated_minutes=320,
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


_sync_assessed_skills(M11_LESSONS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M11 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(M11_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M11_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M11_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M11_MODULE_ID)]
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
