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


M10_MODULE_ID = "M10"
M10_CONTENT_VERSION = "20260321_m10_carrier_loop_v1"
M10_MODULE_TITLE = "Electrical Quantities"
M10_ALLOWLIST = [
    "charge_current_confusion",
    "charge_used_up_confusion",
    "current_as_amount_confusion",
    "closed_loop_confusion",
    "battery_stores_current_confusion",
    "battery_same_current_confusion",
    "voltage_current_confusion",
    "voltage_total_energy_confusion",
    "resistance_route_property_confusion",
    "resistance_geometry_confusion",
    "ohms_law_universal_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M10_ALLOWLIST)
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
    concept: str,
    title: str,
    purpose: str,
    caption: str,
    *,
    template: str = "auto",
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    circuit_type_map = {
        "charge_carriers": "carrier_loop",
        "current_rate": "checkpoint_rate",
        "voltage_boost": "voltage_boost",
        "resistance_drag": "resistance_route",
        "ohms_law": "ohmic_rule",
        "quantity_ledger": "loop_ledger",
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
        "diagnostic_pool_min": 8,
        "concept_gate_pool_min": 6,
        "mastery_pool_min": 8,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile.",
        "Carrier arrows, checkpoint counters, and boost labels stay readable without overlapping the loop geometry.",
        "Voltage, current, and resistance callouts remain visually separated so the diagram does not collapse the quantities together.",
    ]


def carrier_loop_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Carrier-Loop Ledger Model",
        "focus": focus,
        "comparison": f"The Carrier-Loop world keeps charge, current, voltage, resistance, and Ohm's law in one system while {focus}.",
        "mapping": [
            "Carrier token -> charge",
            "Carrier count -> quantity of charge",
            "Checkpoint rate -> current",
            "Lift station -> battery or cell",
            "Boost per token -> voltage",
            "Route drag -> resistance",
            "Ohmic route -> resistor or ohmic conductor",
            "Loop ledger -> charge and energy accounting",
        ],
        "limit": "The model organizes the quantities clearly, but students still need the formal circuit language and should not treat the analogy as if beads literally cause the electrical effects.",
        "prediction_prompt": f"Use the Carrier-Loop world to predict what should happen when {focus}.",
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


# Lesson builders are added in smaller patches to keep edits reliable.


def carriers_lesson() -> Dict[str, Any]:
    d = [
        mcq("M10L1_D1", "In the Carrier-Loop model, what is the moving thing in the loop?", ["carrier tokens", "current only", "resistance", "voltage"], 0, "Charge is represented by the moving carrier tokens.", ["charge_current_confusion"], skill_tags=["charge_definition"]),
        mcq("M10L1_D2", "A loop can contain many carrier tokens but still have low current when...", ["the tokens move past the checkpoint slowly", "the battery stores less current", "the tokens disappear halfway around", "the voltage becomes the same as charge"], 0, "Current is about rate, not just amount.", ["current_as_amount_confusion", "charge_current_confusion"], skill_tags=["charge_vs_current"]),
        mcq("M10L1_D3", "What is the strongest reason an open switch stops current?", ["the carrier loop is broken, so carriers cannot complete the route", "the battery loses its voltage forever", "the resistor becomes shorter", "charge is used up at the lamp"], 0, "A complete route is needed for sustained current.", ["closed_loop_confusion"], skill_tags=["closed_loop"]),
        short("M10L1_D4", "Why is it weak to say that charge gets used up around the loop?", ["Because the carriers keep circulating around the loop and charge is conserved.", "Because the charge remains in the circuit while the energy per carrier changes."], "Keep charge conservation separate from energy transfer.", ["charge_used_up_confusion"], skill_tags=["charge_conservation"], acceptance_rules=acceptance_groups(["charge", "carriers", "tokens"], ["conserved", "remain", "keep circulating", "still there"], ["energy", "boost", "changes"])) ,
        mcq("M10L1_D5", "Which sentence best separates charge from current?", ["Charge is the carrier quantity; current is the rate at which it passes a point.", "Charge is just another word for voltage.", "Current is the total number of carriers in the whole loop.", "Charge measures resistance."], 0, "Charge and current are linked but not the same quantity.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["charge_vs_current"]),
        mcq("M10L1_D6", "If the same carrier tokens keep circulating, what changes at the lift station?", ["the energy each token receives", "whether charge still exists", "the material of the wire", "the direction of the magnetic field"], 0, "The source boosts each carrier; it does not make charge disappear and reappear.", ["battery_stores_current_confusion", "charge_used_up_confusion"], skill_tags=["battery_role"]),
        short("M10L1_D7", "What does a closed loop allow that a broken loop does not?", ["It allows carriers to circulate all the way around the path.", "It gives the moving charge a complete route back to the source."], "A sustained current needs a complete path.", ["closed_loop_confusion"], skill_tags=["closed_loop"], acceptance_rules=acceptance_groups(["complete", "closed", "full"], ["loop", "path", "route"], ["carriers", "charge", "tokens"], ["circulate", "flow", "move all the way"])) ,
        mcq("M10L1_D8", "What should you track first if you want to avoid calling everything 'electricity'?", ["which quantity is moving and what it represents", "which color the battery has", "how bright the room is", "what the final current answer should be"], 0, "Start by identifying the moving carriers and the quantity they represent.", ["charge_current_confusion"], skill_tags=["quantity_identification"]),
    ]
    c = [
        short("M10L1_C1", "How does the Carrier-Loop model represent charge?", ["Charge is represented by the carrier tokens moving around the loop.", "The tokens stand for the conserved charge in the circuit."], "Use carrier-token language.", ["charge_current_confusion"], skill_tags=["charge_definition"], acceptance_rules=acceptance_groups(["carrier", "token"], ["charge"], ["move", "circulate", "loop"])) ,
        mcq("M10L1_C2", "Which quantity can stay the same while current changes?", ["the total carrier count in the loop", "the fact that current is a rate", "the route being open", "the rule that voltage is energy per charge"], 0, "A loop can contain the same charge but have a different flow rate.", ["current_as_amount_confusion"], skill_tags=["charge_vs_current"]),
        mcq("M10L1_C3", "Which sentence best explains why charge is conserved?", ["The same carriers circulate; they are not destroyed at each component.", "The battery replaces used charge with new charge.", "Charge exists only near the battery.", "Resistance turns charge into light."], 0, "Conservation means the charge remains in the loop.", ["charge_used_up_confusion"], skill_tags=["charge_conservation"]),
        short("M10L1_C4", "Why is 'battery stores current' a weak statement?", ["Because the battery provides energy per charge, not a tank of current.", "Because current depends on the whole loop, not on the battery alone storing it."], "Separate the source role from the current result.", ["battery_stores_current_confusion", "battery_same_current_confusion"], skill_tags=["battery_role"], acceptance_rules=acceptance_groups(["battery", "source"], ["energy", "boost", "per charge", "voltage"], ["not", "rather than"], ["current tank", "stores current", "same current"])) ,
        mcq("M10L1_C5", "A loop is broken. Which statement stays true?", ["charge still exists, but sustained current stops", "the battery instantly becomes zero volts forever", "the wire gets wider", "resistance becomes negative"], 0, "Broken loop stops the flow, not the existence of charge.", ["closed_loop_confusion", "charge_used_up_confusion"], skill_tags=["closed_loop"]),
        short("M10L1_C6", "What is the cleanest two-part distinction between charge and current?", ["Charge is the amount of carrier stuff, and current is how fast it passes a checkpoint.", "Charge is the quantity of carriers, while current is the rate of charge flow."], "Use amount-versus-rate language.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["charge_vs_current"], acceptance_rules=acceptance_groups(["charge"], ["amount", "quantity", "carriers"], ["current"], ["rate", "per second", "flow"])) ,
    ]
    t = [
        mcq("M10L1_M1", "Which statement best fits the Carrier-Loop model?", ["Carrier tokens represent charge and keep circulating.", "Current is stored inside the battery and released only once.", "Resistance is the moving stuff.", "Voltage is the same as the number of carriers."], 0, "Charge is the conserved moving quantity in the loop.", ["charge_current_confusion", "battery_stores_current_confusion"], skill_tags=["charge_definition"]),
        short("M10L1_M2", "A learner says, 'the bulb uses up the charge.' What should you say instead?", ["The carriers keep circulating; what changes is the energy they carry, not whether the charge still exists.", "Charge is conserved in the loop, while the energy per carrier can be transferred."], "Correct charge-loss language with conservation language.", ["charge_used_up_confusion"], skill_tags=["charge_conservation"], acceptance_rules=acceptance_groups(["charge", "carriers"], ["conserved", "keep circulating", "still there"], ["energy", "boost", "transferred", "changes"])) ,
        mcq("M10L1_M3", "A loop with a complete path and a loop with a broken path differ mainly in...", ["whether sustained current can circulate", "how much charge exists in the universe", "whether voltage is measured in amperes", "whether resistance can ever matter"], 0, "A closed path is required for a steady current.", ["closed_loop_confusion"], skill_tags=["closed_loop"]),
        mcq("M10L1_M4", "Which quantity is an amount rather than a rate?", ["charge", "current", "power", "speed"], 0, "Charge is the amount; current is a rate.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["charge_vs_current"]),
        short("M10L1_M5", "Why can the same carriers go around the loop again and again?", ["Because the circuit is a loop and the charge is conserved rather than used up.", "Because a closed loop lets the carriers circulate repeatedly."], "Tie repeated circulation to conservation and a closed path.", ["charge_used_up_confusion", "closed_loop_confusion"], skill_tags=["closed_loop", "charge_conservation"], acceptance_rules=acceptance_groups(["closed", "loop", "complete"], ["carriers", "charge"], ["circulate", "go around again", "repeat"], ["conserved", "not used up"])) ,
        mcq("M10L1_M6", "Best first question before you use any electrical equation:", ["What is moving, and what quantity does it represent?", "What is the final answer in amperes?", "How bright is the lamp?", "Which color wire is longest?"], 0, "Quantity identification comes first.", ["charge_current_confusion"], skill_tags=["quantity_identification"]),
        short("M10L1_M7", "Why is current not the same thing as 'how much charge is in the loop'?", ["Because current measures how much charge passes a point each second, not the total amount present.", "Because current is a flow rate, while charge is the quantity of carriers in the loop."], "Keep amount and rate distinct.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["charge_vs_current"], acceptance_rules=acceptance_groups(["current"], ["rate", "per second", "passes a point", "flow"], ["charge"], ["amount", "total", "quantity"])) ,
        mcq("M10L1_M8", "Which claim about the battery is strongest at this stage?", ["It gives energy per carrier at the lift station.", "It contains a fixed tank of current.", "It consumes charge as the loop runs.", "It decides current without the route mattering."], 0, "The source gives energy per charge; current depends on the whole loop.", ["battery_stores_current_confusion", "battery_same_current_confusion"], skill_tags=["battery_role"]),
    ]
    return lesson_spec("M10_L1", "Carrier Tokens and Conserved Charge", sim("m10_carrier_loop_lab", "Carrier loop lab", "Meet the moving carriers and distinguish conserved charge from the idea of current.", ["Close and open the loop.", "Change the carrier count.", "Watch what circulates and what stops."], ["Explain charge as the moving carrier quantity.", "Explain why a complete loop is needed for current.", "Explain why charge is not used up."], ["carrier_count", "loop_state", "checkpoint_rate", "energy_per_carrier"], "Charge and closed-loop reasoning."), d, "The Carrier-Loop starts with identical tokens already in the loop, and the first job is to notice that the moving things are the carriers themselves.", "Before you use any circuit label, point to what is moving and decide whether you are talking about amount or rate.", [prompt_block("What quantity do the moving tokens represent?", "They represent charge."), prompt_block("What is needed for the tokens to keep circulating?", "A complete closed loop.")], [prompt_block("Open the loop and describe what changes.", "The circulation stops because the route is broken."), prompt_block("Close the loop again and compare charge conservation with current flow.", "The same carriers circulate; they are not used up.")], ["Explain why 'charge gets used up' is weaker than 'the energy per carrier changes around the loop.'", "Explain why a broken loop stops current without making charge stop existing."], "Keep moving carriers, current as rate, and energy transfer as separate ideas from the very start.", c, t, contract(concept_targets=["Explain charge as the conserved moving carrier quantity in a loop.", "Explain why a complete route is needed for sustained current.", "Separate amount of charge from current as a rate."], core_concepts=["Charge is the carrier quantity moving around the loop.", "A steady current needs a complete closed path.", "Charge is conserved rather than used up at each component.", "Current is related to motion of charge but is not the same as the total amount of charge present."], prerequisite_lessons=["F4_L1"], misconception_focus=["charge_current_confusion", "charge_used_up_confusion", "current_as_amount_confusion", "closed_loop_confusion", "battery_stores_current_confusion"], formulas=[relation("charge is conserved in a closed loop", "The same carriers circulate around the circuit instead of being used up.", ["C"], "Use as the first bookkeeping statement before defining current and voltage.")], representations=[representation("words", "Separates charge count from current."), representation("formula", "States the conservation rule for charge in a closed loop before current is defined as a rate."), representation("diagram", "Shows carriers circulating around a closed route."), representation("table", "Compares closed-loop and open-loop cases.")], analogy_map=carrier_loop_map("the class is deciding what the moving carriers represent and why they need a complete loop"), worked_examples=[worked("A student says a lamp uses up the charge. What is the better description?", ["Ask what continues moving around the loop.", "Separate the carrier quantity from the energy transfer.", "State what changes at components."], "The carriers keep circulating; the energy per carrier changes, but the charge is conserved.", "Charge is the conserved moving quantity, so it is not destroyed at the lamp.", "This blocks one of the biggest early circuit confusions."), worked("Why does opening the switch stop current immediately in the simple loop model?", ["Check whether the route is complete.", "Ask whether carriers can still circulate all the way around.", "State the consequence for sustained current."], "Current stops because the loop is broken and the carriers no longer have a complete path.", "A steady current needs a closed path, not just a battery somewhere in the diagram.", "This gives a clean closed-loop rule before later circuit analysis."), worked("A loop contains many carrier tokens but only a tiny checkpoint rate. What idea is that teaching?", ["Separate the amount in the loop from the rate past one point.", "Name the amount as charge and the rate as current.", "State the distinction explicitly."], "It teaches that a large amount of charge does not automatically mean a large current.", "Charge and current are different quantities, so amount and rate should not be collapsed.", "This makes later current definitions much easier to trust.")], visual_assets=[visual("m10-l1-carrier-loop", "charge_carriers", "Carrier loop", "Shows circulating tokens in a closed loop and the difference between closed and open paths.", "The carrier count, loop switch, and checkpoint should be easy to track separately.")], animation_assets=[animation("m10-l1-carrier-motion", "charge_carriers", "Carrier motion", "Shows the same tokens circulating around the closed loop while the open-loop case stalls.")], simulation_contract=sim_contract("m10-l1-carrier-loop-lab", "charge_carriers", "What is moving in the loop, and what changes when the route opens?", "Start with a closed loop and a modest number of carrier tokens, then break the loop.", ["Compare a closed route with an open route.", "Increase the carrier count and compare that with the checkpoint rate story."], "Do not call the moving carriers 'current' before you decide whether you mean amount or rate.", "Charge is the moving carrier quantity, and a steady current needs a closed loop.", [("carrier_count", "Carrier count", "Keeps the amount of moving charge visible."), ("loop_state", "Loop state", "Shows whether a complete route exists."), ("checkpoint_meter", "Checkpoint meter", "Separates the flow-rate idea from the total carrier count.")], [("Carrier count", "Shows how much carrier quantity is in the loop."), ("Checkpoint rate", "Shows how much charge passes a point each second."), ("Loop status", "Shows whether a complete route exists.")]), reflection_prompts=["Why is charge better modeled as carrier tokens than as a vague amount of electricity?", "Why does opening a loop stop current without meaning that charge has been destroyed?"], mastery_skills=["charge_definition", "charge_conservation", "closed_loop", "charge_vs_current", "battery_role"], variation_plan={"diagnostic": "Fresh attempts rotate between moving-carrier identification, closed-loop reasoning, and charge-versus-current stems.", "concept_gate": "Concept checks vary between conservation language, battery-role language, and amount-versus-rate explanations.", "mastery": "Mastery mixes closed-loop reasoning, conserved-charge explanations, and charge-versus-current distinctions before repeating any prompt."}, scaffold_support=scaffold("Charge is the moving carrier quantity in the loop, and it is conserved.", "Point to the moving carriers first, then decide whether the question is about amount of charge or current as a rate.", "If the same carriers keep circling, what does that tell you about charge?", "Do not say that a component uses up charge when the better story is that it transfers energy from each carrier.", "Carrier tokens go around a loop; the loop only sustains current while the route stays complete.", "Which part of the model shows conservation, and which part shows a broken circuit?", [extra_section("Amount versus rate", "A loop can contain many carriers while still showing only a small checkpoint rate. That is why charge and current are not the same quantity.", "What is the difference between how many tokens exist and how many pass a point each second?"), extra_section("Battery role", "The source station gives energy per carrier. It is not a tank that stores current waiting to be poured out.", "Why is 'battery stores current' weaker than 'battery boosts each carrier'?")]), visual_clarity_checks=visual_checks("charge-carrier")))


def current_lesson() -> Dict[str, Any]:
    d = [
        mcq("M10L2_D1", "Current is best defined as...", ["rate of charge flow", "amount of resistance", "energy per charge", "number of batteries"], 0, "Current measures charge passing a point each second.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["current_definition"]),
        mcq("M10L2_D2", "Two loops contain the same total charge. Which one has the larger current?", ["the loop where more charge passes the checkpoint each second", "the loop with more voltage symbols on the page", "the loop with longer wires only", "the loop with the heavier battery"], 0, "Current is about checkpoint rate.", ["current_as_amount_confusion"], skill_tags=["current_rate_reasoning"]),
        mcq("M10L2_D3", "12 C pass a checkpoint in 3 s. The current is...", ["4 A", "36 A", "0.25 A", "9 A"], 0, "Use I = Q/t.", ["charge_current_confusion"], skill_tags=["current_calculation"]),
        short("M10L2_D4", "Why can a loop with many carriers still have a small current?", ["Because current depends on how fast charge passes the checkpoint, not only on how much charge is in the loop.", "Because a large carrier count can still move slowly past a point."], "Keep amount and rate separate.", ["current_as_amount_confusion", "charge_current_confusion"], skill_tags=["charge_vs_current"], acceptance_rules=acceptance_groups(["current"], ["rate", "per second", "passes", "flow"], ["not", "rather than"], ["amount", "many carriers", "total charge"])) ,
        mcq("M10L2_D5", "What does 1 A mean?", ["1 C passes a point each second", "1 J is stored in the battery", "1 V is on the source", "1 resistor is in the loop"], 0, "1 A = 1 C/s.", ["charge_current_confusion"], skill_tags=["current_unit"]),
        mcq("M10L2_D6", "If the same carriers go round faster, the current...", ["increases", "decreases to zero", "becomes voltage", "must stay the same"], 0, "Faster checkpoint rate means larger current.", ["current_as_amount_confusion"], skill_tags=["current_rate_reasoning"]),
        short("M10L2_D7", "What is the difference between carrier count and checkpoint rate?", ["Carrier count is how much charge is in the loop, while checkpoint rate is the current.", "Carrier count is the amount of charge, but checkpoint rate tells how much passes a point each second."], "Use amount-versus-rate language.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["charge_vs_current"], acceptance_rules=acceptance_groups(["carrier count", "charge", "amount"], ["checkpoint rate", "current"], ["passes a point", "per second", "rate"])) ,
        mcq("M10L2_D8", "Which statement keeps current and energy separate?", ["Current counts charge flow rate; energy transfer is a different question.", "Current is the same as the energy in the battery.", "Current is how much voltage is stored.", "Current and resistance are always equal."], 0, "Current is about charge flow rate, not energy content.", ["charge_current_confusion", "voltage_total_energy_confusion"], skill_tags=["current_definition"]),
    ]
    c = [
        short("M10L2_C1", "How would you explain current without using the word electricity?", ["Current is how much charge passes a checkpoint each second.", "Current is the rate of charge flow around the loop."], "Use charge-flow language.", ["charge_current_confusion"], skill_tags=["current_definition"], acceptance_rules=acceptance_groups(["current"], ["charge"], ["rate", "per second", "flow"])) ,
        mcq("M10L2_C2", "A loop has fewer carriers than another loop, but they pass the checkpoint twice as fast. What must you compare to decide current?", ["charge per second at the checkpoint", "battery color", "wire temperature only", "symbol order"], 0, "Current needs a rate comparison.", ["current_as_amount_confusion"], skill_tags=["current_rate_reasoning"]),
        mcq("M10L2_C3", "24 C pass a point in 6 s. What is the current?", ["4 A", "18 A", "0.25 A", "30 A"], 0, "Use I = Q/t.", ["charge_current_confusion"], skill_tags=["current_calculation"]),
        short("M10L2_C4", "Why is 'current is how much charge is in the wire' weak?", ["Because current is the rate charge passes a point, not the total amount present in the wire.", "Because current is about charge flow per second rather than charge amount."], "Correct the quantity mix-up.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["charge_vs_current"], acceptance_rules=acceptance_groups(["current"], ["rate", "per second", "passes a point", "flow"], ["not", "rather than"], ["amount", "total", "in the wire"])) ,
        mcq("M10L2_C5", "If 5 C pass each second, the current is...", ["5 A", "5 V", "5 ohm", "5 J"], 0, "Ampere means coulomb per second.", ["charge_current_confusion"], skill_tags=["current_unit"]),
        short("M10L2_C6", "What stays more useful in the Carrier-Loop story: 'how many tokens exist' or 'how many pass each second' when you are defining current?", ["How many pass each second, because current is a rate.", "The passing-per-second idea, because current measures checkpoint rate."], "Tie current to the checkpoint meter.", ["current_as_amount_confusion"], skill_tags=["current_definition"], acceptance_rules=acceptance_groups(["pass", "checkpoint"], ["each second", "per second", "rate"], ["current"])) ,
    ]
    t = [
        mcq("M10L2_M1", "18 C pass a checkpoint in 2 s. The current is...", ["9 A", "16 A", "36 A", "0.11 A"], 0, "I = Q/t.", ["charge_current_confusion"], skill_tags=["current_calculation"]),
        short("M10L2_M2", "Why can a loop with many carriers still produce a weak checkpoint rate?", ["Because the carriers can move slowly, so only a small amount of charge passes the checkpoint each second.", "Because current depends on charge per second, not only on how many carriers exist."], "Use amount-versus-rate reasoning.", ["current_as_amount_confusion"], skill_tags=["current_rate_reasoning"], acceptance_rules=acceptance_groups(["current"], ["charge per second", "passes the checkpoint", "rate"], ["not", "rather than"], ["many carriers", "amount"])) ,
        mcq("M10L2_M3", "Which quantity is measured in amperes?", ["current", "charge", "voltage", "resistance"], 0, "Current is measured in amperes.", ["charge_current_confusion"], skill_tags=["current_unit"]),
        mcq("M10L2_M4", "0.5 C pass the checkpoint each second. The current is...", ["0.5 A", "2 A", "0.5 V", "2 ohm"], 0, "Current equals charge per second.", ["charge_current_confusion"], skill_tags=["current_calculation"]),
        short("M10L2_M5", "A learner says, 'current is the number of carriers in the circuit.' What would you fix?", ["I would say current is how fast charge passes a point, not the total number of carriers in the circuit.", "I would replace amount language with charge-flow-per-second language."], "Keep current as a rate.", ["charge_current_confusion", "current_as_amount_confusion"], skill_tags=["charge_vs_current"], acceptance_rules=acceptance_groups(["current"], ["rate", "per second", "passes a point", "flow"], ["not", "rather than"], ["number of carriers", "total", "amount"])) ,
        mcq("M10L2_M6", "Which comparison can double current most directly in this model, if the route and source stay otherwise simple?", ["twice as much charge passing the checkpoint each second", "twice the number of labels on the page", "half the symbol size", "twice the battery mass"], 0, "Current doubles when the checkpoint rate doubles.", ["current_as_amount_confusion"], skill_tags=["current_rate_reasoning"]),
        short("M10L2_M7", "What does the equation I = Q/t summarize in one sentence?", ["It says current is charge passing per unit time.", "It says current equals the amount of charge that passes each second."], "Translate the equation back into words.", ["charge_current_confusion"], skill_tags=["current_equation_meaning"], acceptance_rules=acceptance_groups(["current"], ["charge"], ["time", "second", "per second", "unit time"], ["passes"])) ,
        mcq("M10L2_M8", "Best first quantity to read from the checkpoint meter:", ["how much charge passes each second", "how much energy the battery stored last week", "the total resistance in every possible circuit", "the mass of the wire"], 0, "The checkpoint meter is a current meter.", ["charge_current_confusion"], skill_tags=["current_definition"]),
    ]
    return lesson_spec(
        "M10_L2",
        "Checkpoint Rate and Current",
        sim("m10_checkpoint_rate_lab", "Checkpoint rate lab", "Distinguish total carrier count from current by counting how many carriers pass a checkpoint each second.", ["Change carrier count.", "Change carrier speed.", "Read the checkpoint meter in C/s and A."], ["Define current as rate of charge flow.", "Calculate current from charge and time.", "Keep amount-versus-rate distinctions stable."], ["carrier_count", "carrier_speed", "checkpoint_rate", "time_window"], "Current definition and rate reasoning."),
        d,
        "At the checkpoint gate, the key question becomes not 'how many carriers exist?' but 'how many pass this point each second?'",
        "Before you calculate current, decide what counts as the amount of charge and what counts as the time interval.",
        [prompt_block("What does the checkpoint rate measure?", "It measures charge passing a point each second."), prompt_block("What does 1 A mean in carrier language?", "1 C of charge passes the point each second.")],
        [prompt_block("Keep the carrier count fixed and raise the motion rate.", "The checkpoint rate rises because more charge passes each second."), prompt_block("Keep the motion rate fixed and change the carrier count.", "Now compare how amount and rate interact instead of calling them the same thing.")],
        ["Explain why many carriers in the loop do not automatically guarantee a large current.", "Explain how I = Q/t is a rate statement rather than an amount statement."],
        "Use the checkpoint as the measuring idea, so current stays tied to charge per second.",
        c,
        t,
        contract(
            concept_targets=["Define current as the rate of charge flow.", "Calculate current from charge and time.", "Separate current from the total amount of charge in a loop."],
            core_concepts=["Current measures how much charge passes a point each second.", "Current is a rate, not the total amount of charge in the loop.", "A loop can contain a large amount of charge and still have a small current if the checkpoint rate is small.", "The equation I = Q/t summarizes the charge-per-time definition of current."],
            prerequisite_lessons=["M10_L1", "F4_L1"],
            misconception_focus=["charge_current_confusion", "current_as_amount_confusion", "voltage_total_energy_confusion"],
            formulas=[relation("I = Q / t", "Current equals charge passing a point divided by the time taken.", ["A", "C", "s"], "Use when charge flow and elapsed time are known.")],
            representations=[representation("words", "Defines current as charge passing a checkpoint per second."), representation("formula", "Translates current into charge-per-time language."), representation("diagram", "Shows carriers crossing one chosen point."), representation("table", "Compares many-carrier slow loops with fewer-carrier fast loops.")],
            analogy_map=carrier_loop_map("the class is measuring charge flow at one checkpoint"),
            worked_examples=[worked("12 C pass a checkpoint in 3 s. What is the current?", ["Identify Q = 12 C.", "Identify t = 3 s.", "Use I = Q/t and keep the ampere unit."], "4 A", "Current is charge per time, so 12 C divided by 3 s gives 4 A.", "This makes the current definition computational, not just verbal."), worked("Two loops contain the same total charge, but one loop shows twice as many carriers passing the checkpoint each second. Which has the larger current?", ["Ignore the total charge for a moment.", "Compare only the checkpoint rate.", "State the current result from the rate comparison."], "The loop with twice the checkpoint rate has twice the current.", "Current depends on rate of passage, not just on how much charge exists in the system.", "This protects the amount-versus-rate distinction."), worked("A learner says, 'current is the number of carriers in the loop.' What is the better sentence?", ["Identify the quantity the learner has named.", "Compare that quantity with what the checkpoint meter actually reads.", "State the corrected definition."], "Current is how much charge passes a point each second.", "The loop can hold many carriers while current remains small, so amount and rate must be separated.", "This blocks one of the most persistent circuit misconceptions.")],
            visual_assets=[visual("m10-l2-checkpoint-rate", "current_rate", "Checkpoint rate", "Shows current as carriers crossing one checkpoint per second.", "The charge amount and the rate display must remain visually separate.")],
            animation_assets=[animation("m10-l2-checkpoint-flow", "current_rate", "Checkpoint flow", "Shows more and fewer carriers crossing the same checkpoint within the same time window.")],
            simulation_contract=sim_contract("m10-l2-checkpoint-rate-lab", "current_rate", "How does the checkpoint rate differ from the total carrier count in the loop?", "Start with a moderate carrier count and a slow movement rate, then compare with a faster run.", ["Change the carrier count and the carrier speed separately.", "Read the current in charge per second instead of talking vaguely about more electricity."], "Do not let 'many carriers' replace the actual current definition.", "Current is the checkpoint rate of charge flow, not the amount of charge stored in the loop.", [("carrier_count", "Carrier count", "Controls how much charge is present."), ("carrier_speed", "Carrier speed", "Changes how fast carriers reach the checkpoint."), ("time_window", "Time window", "Makes the per-second meaning explicit.")], [("Charge passed", "Shows how much charge crossed the checkpoint in the chosen time."), ("Current", "Reports the charge-per-second rate."), ("Carrier count", "Keeps the amount of charge distinct from the rate.")]),
            reflection_prompts=["Why does a loop with many carriers not automatically have a large current?", "How does I = Q/t summarize the idea of a checkpoint meter?"],
            mastery_skills=["current_definition", "current_rate_reasoning", "current_calculation", "current_unit", "current_equation_meaning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between unit meaning, checkpoint-rate reasoning, and simple current calculations.", "concept_gate": "Concept checks vary between amount-versus-rate explanations and translated uses of I = Q/t.", "mastery": "Mastery mixes numeric current calculations, definition checks, and charge-versus-current explanations before repeating any prompt."},
            scaffold_support=scaffold("Current is the rate at which charge passes a chosen point in the loop.", "Choose the checkpoint, then ask how much charge passes it in a given time interval.", "If twice as much charge passes the same point each second, what happens to the current?", "Do not replace current with the total number of carriers in the whole circuit.", "The checkpoint meter counts passing tokens, not stored tokens.", "What does the checkpoint gate tell you that the total carrier count does not?", [extra_section("Unit meaning", "1 A means 1 C of charge passes a point each second.", "What do the letters C and s mean in that sentence?"), extra_section("Amount versus rate again", "A loop can have many carriers and still show a small checkpoint rate if they move slowly past the gate.", "Why is current a rate rather than a stock?")]),
            visual_clarity_checks=visual_checks("current-rate"),
        ),
    )


def voltage_lesson() -> Dict[str, Any]:
    d = [
        mcq("M10L3_D1", "In the Carrier-Loop model, voltage is best represented as...", ["boost per token", "number of tokens in the loop", "roughness of the route", "checkpoint count per second"], 0, "Voltage is the energy boost given to each carrier.", ["voltage_current_confusion", "voltage_total_energy_confusion"], skill_tags=["voltage_definition"]),
        mcq("M10L3_D2", "A 12-boost lift station gives each token...", ["more energy per pass than a 6-boost station", "twice as much resistance", "the same current in every loop", "a larger amount of charge"], 0, "Higher voltage means more energy per charge.", ["voltage_current_confusion", "voltage_total_energy_confusion"], skill_tags=["energy_per_charge"]),
        mcq("M10L3_D3", "18 J of energy are given to 3 C of charge. The voltage is...", ["6 V", "15 V", "21 V", "54 V"], 0, "Use V = delta E / Q.", ["voltage_total_energy_confusion"], skill_tags=["voltage_calculation"]),
        short("M10L3_D4", "Why is voltage better described as boost per carrier than as 'more current'?", ["Because voltage tells how much energy each unit of charge receives, while current is the rate of charge flow.", "Because voltage is energy per charge, not the same quantity as current."], "Separate energy-per-charge from rate-of-flow language.", ["voltage_current_confusion", "voltage_total_energy_confusion"], skill_tags=["voltage_vs_current"], acceptance_rules=acceptance_groups(["voltage"], ["energy per charge", "boost per carrier"], ["current"], ["rate", "flow"], ["not", "rather than"])) ,
        mcq("M10L3_D5", "Which statement about the battery is strongest?", ["It gives energy to each carrier as it passes through.", "It stores a fixed tank of current.", "It destroys old charge and creates new charge only.", "It decides the current without the route mattering."], 0, "The source gives energy per carrier.", ["battery_stores_current_confusion", "voltage_total_energy_confusion"], skill_tags=["battery_role"]),
        mcq("M10L3_D6", "What does 1 V mean?", ["1 J of energy per 1 C of charge", "1 C per second", "1 ohm of resistance", "1 battery cell exactly"], 0, "1 V = 1 J/C.", ["voltage_total_energy_confusion"], skill_tags=["voltage_unit"]),
        short("M10L3_D7", "Why can two circuits have the same current but different voltages?", ["Because current is rate of charge flow, while voltage is the energy each unit of charge receives.", "Because equal flow rate does not guarantee equal energy per charge."], "Keep flow rate separate from boost-per-carrier.", ["voltage_current_confusion"], skill_tags=["voltage_vs_current"], acceptance_rules=acceptance_groups(["current"], ["same", "equal"], ["voltage"], ["energy per charge", "boost"], ["different"])) ,
        mcq("M10L3_D8", "Which quantity belongs most clearly to the source role in this lesson?", ["voltage", "resistance only", "the number of carrier tokens only", "mirror angle"], 0, "The lift station provides the voltage.", ["voltage_current_confusion"], skill_tags=["source_quantity"]),
    ]
    c = [
        short("M10L3_C1", "How would you explain voltage in one sentence using the Carrier-Loop model?", ["Voltage is the energy boost each carrier gets at the lift station.", "Voltage is how much energy per charge the source provides."], "Use boost-per-token language.", ["voltage_current_confusion", "voltage_total_energy_confusion"], skill_tags=["voltage_definition"], acceptance_rules=acceptance_groups(["voltage"], ["energy per charge", "boost", "each carrier"], ["source", "lift station"])) ,
        mcq("M10L3_C2", "24 J are given to 6 C of charge. The voltage is...", ["4 V", "18 V", "30 V", "0.25 V"], 0, "V = delta E / Q.", ["voltage_total_energy_confusion"], skill_tags=["voltage_calculation"]),
        mcq("M10L3_C3", "If the source voltage doubles while the route stays ohmic and unchanged, what changes first conceptually?", ["each carrier gets a bigger energy boost", "charge is destroyed twice as fast", "resistance must double too", "the definition of current changes"], 0, "Voltage acts per carrier.", ["voltage_current_confusion"], skill_tags=["energy_per_charge"]),
        short("M10L3_C4", "Why is it weak to treat voltage as the same quantity as current?", ["Because voltage is energy per charge, while current is charge per second.", "Because voltage tells the boost per carrier, but current tells the flow rate."], "Separate the two definitions cleanly.", ["voltage_current_confusion"], skill_tags=["voltage_vs_current"], acceptance_rules=acceptance_groups(["voltage"], ["energy per charge", "boost per carrier"], ["current"], ["charge per second", "flow rate"], ["not", "rather than"])) ,
        mcq("M10L3_C5", "What formal equation matches the boost-per-token idea?", ["V = delta E / Q", "I = Q/t", "P = W/t", "v = f lambda"], 0, "Voltage is energy per unit charge.", ["voltage_total_energy_confusion"], skill_tags=["voltage_equation"]),
        short("M10L3_C6", "Why does a bigger voltage not automatically mean 'more charge exists'?", ["Because voltage tells the energy per charge, not the amount of charge in the circuit.", "Because the source can give each carrier a bigger boost without creating more charge."], "Keep amount of charge separate from energy per charge.", ["voltage_total_energy_confusion", "charge_current_confusion"], skill_tags=["voltage_definition"], acceptance_rules=acceptance_groups(["voltage"], ["energy per charge", "boost"], ["not", "rather than"], ["amount of charge", "more charge", "carrier count"])) ,
    ]
    t = [
        mcq("M10L3_M1", "30 J are transferred to 5 C of charge. The voltage is...", ["6 V", "25 V", "35 V", "150 V"], 0, "V = delta E / Q.", ["voltage_total_energy_confusion"], skill_tags=["voltage_calculation"]),
        short("M10L3_M2", "What should you say instead of 'the battery sends current into the circuit'?", ["The battery gives energy per charge to the carriers, and the current depends on the whole loop.", "The source provides voltage to each carrier rather than storing a fixed current to pour out."], "Correct the battery-current myth with source-role language.", ["battery_stores_current_confusion", "battery_same_current_confusion", "voltage_current_confusion"], skill_tags=["battery_role"], acceptance_rules=acceptance_groups(["battery", "source"], ["energy per charge", "boost", "voltage"], ["current"], ["depends on the whole loop", "not stored"])) ,
        mcq("M10L3_M3", "Which unit matches voltage?", ["J/C", "C/s", "A/s", "ohm/s"], 0, "Voltage is measured in joules per coulomb.", ["voltage_total_energy_confusion"], skill_tags=["voltage_unit"]),
        mcq("M10L3_M4", "A 9 V source and a 3 V source differ mainly in...", ["the energy given to each coulomb of charge", "how many carriers exist in the universe", "whether resistance is allowed", "whether current can be measured"], 0, "Voltage compares energy per charge.", ["voltage_total_energy_confusion"], skill_tags=["energy_per_charge"]),
        short("M10L3_M5", "Why can the same source give different currents in different loops even though its voltage is fixed?", ["Because the voltage is the boost per carrier, but the actual current also depends on the route resistance.", "Because a fixed energy-per-charge source can still drive different flow rates when the loop drag changes."], "Bring route resistance back into the story.", ["battery_same_current_confusion", "voltage_current_confusion"], skill_tags=["source_and_route"], acceptance_rules=acceptance_groups(["voltage", "boost", "energy per charge"], ["current"], ["depends on", "also depends on"], ["resistance", "route drag", "whole loop"])) ,
        mcq("M10L3_M6", "Best meaning of 12 V:", ["each coulomb gets 12 J of energy", "12 C pass each second", "the circuit contains 12 carriers", "the resistance is 12 ohm"], 0, "Use the J/C meaning.", ["voltage_total_energy_confusion"], skill_tags=["voltage_unit"]),
        short("M10L3_M7", "What does the equation V = delta E / Q say in words?", ["Voltage is the energy transferred per unit charge.", "Voltage is the change in energy for each coulomb of charge."], "Translate the equation into meaning.", ["voltage_total_energy_confusion"], skill_tags=["voltage_equation_meaning"], acceptance_rules=acceptance_groups(["voltage"], ["energy", "change in energy", "transferred"], ["per charge", "per unit charge", "each coulomb"])) ,
        mcq("M10L3_M8", "Which quantity should you read from the lift station before you think about the route?", ["boost per token", "wire width", "checkpoint number only", "mirror normal"], 0, "The lift station is where the voltage role is shown.", ["voltage_current_confusion"], skill_tags=["source_quantity"]),
    ]
    return lesson_spec(
        "M10_L3",
        "Lift Stations and Voltage",
        sim("m10_lift_station_lab", "Lift station lab", "Treat voltage as energy per charge by watching each carrier receive a boost at the source.", ["Change the boost per token.", "Keep the route fixed at first.", "Compare energy per carrier with flow rate."], ["Explain voltage as energy per charge.", "Calculate voltage from energy and charge.", "Separate voltage from current."], ["boost_per_token", "charge_packet", "voltage_readout", "current_response"], "Voltage and source-role reasoning."),
        d,
        "The Lift Station does not create current as a substance; it gives each passing carrier a boost that can later be transferred elsewhere in the loop.",
        "Before you say 'more current,' ask whether the question is really about energy per carrier instead.",
        [prompt_block("What does the Lift Station give to each token?", "It gives an energy boost per token."), prompt_block("What formal quantity matches boost per token?", "Voltage, or energy per unit charge.")],
        [prompt_block("Raise the source boost while keeping the route the same.", "Notice that the energy per carrier changes first."), prompt_block("Now compare the same current with a different source boost.", "Equal current and equal voltage are not the same statement.")],
        ["Explain why voltage is better described as energy per charge than as 'more current.'", "Explain how V = delta E / Q compresses the boost-per-token story into one equation."],
        "Keep the source role visible: the lift station boosts each carrier, while the current describes the resulting flow rate.",
        c,
        t,
        contract(
            concept_targets=["Define voltage as energy transferred per unit charge.", "Calculate voltage from energy and charge.", "Separate voltage from current and total stored energy."],
            core_concepts=["Voltage is the energy boost given to each unit of charge.", "Voltage is not the same quantity as current.", "A bigger voltage means more energy per charge, not necessarily more charge exists.", "The equation V = delta E / Q summarizes voltage as energy per charge."],
            prerequisite_lessons=["M10_L2", "F4_L2"],
            misconception_focus=["battery_stores_current_confusion", "battery_same_current_confusion", "voltage_current_confusion", "voltage_total_energy_confusion"],
            formulas=[relation("V = delta E / Q", "Voltage equals energy transferred per unit charge.", ["V", "J", "C"], "Use when the source or a component's energy-per-charge change is known.")],
            representations=[representation("words", "Defines voltage as the energy boost each unit of charge receives."), representation("formula", "Expresses energy per charge as a formal ratio."), representation("diagram", "Shows the source boosting each carrier."), representation("table", "Separates same-current and same-voltage cases.")],
            analogy_map=carrier_loop_map("the class is separating boost per carrier from rate of carrier flow"),
            worked_examples=[worked("18 J of energy are given to 3 C of charge. What is the voltage?", ["Read delta E = 18 J.", "Read Q = 3 C.", "Use V = delta E / Q and keep the volt unit."], "6 V", "Voltage is energy per charge, so 18 J divided by 3 C gives 6 V.", "This makes the source boost quantitative."), worked("Why is 'voltage is just more current' a weak sentence?", ["Define current first.", "Define voltage second.", "State why the two quantities are different."], "Voltage is energy per charge, while current is charge flow rate.", "The two quantities are related in circuits, but they are not the same physical meaning.", "This blocks one of the central electrical-quantities confusions."), worked("A 12 V source and a 6 V source are connected to the same simple route. What differs at the source itself before you discuss current?", ["Look only at the source role first.", "Ask what each carrier receives.", "State the difference in energy per charge."], "Each carrier gets twice the energy boost from the 12 V source.", "Voltage is boost per carrier, so the larger source gives more energy to each unit of charge.", "This keeps source language clean before moving to Ohm's law.")],
            visual_assets=[visual("m10-l3-lift-station", "voltage_boost", "Lift station", "Shows the source giving each carrier an energy boost.", "The boost ledger and the checkpoint rate should stay visually separate.")],
            animation_assets=[animation("m10-l3-source-boost", "voltage_boost", "Source boost", "Shows carriers receiving a larger or smaller energy boost at the lift station.")],
            simulation_contract=sim_contract("m10-l3-lift-station-lab", "voltage_boost", "What changes when the source gives each carrier a larger boost?", "Start with one fixed route and compare a small source boost with a larger one.", ["Hold the route fixed and change the boost per token.", "Compare equal-current and equal-voltage language instead of collapsing them."], "Do not describe voltage as stored current.", "Voltage is energy per charge supplied by the source.", [("boost_per_token", "Boost per token", "Represents the voltage role of the source."), ("charge_packet", "Charge packet", "Lets students connect voltage to energy-per-charge calculations."), ("route_drag", "Route drag", "Keeps the source role separate from the path role.")], [("Voltage", "Shows energy per unit charge."), ("Energy packet", "Shows how much energy a chosen amount of charge would receive."), ("Current response", "Shows that flow rate is a separate quantity from the boost itself.")]),
            reflection_prompts=["Why is voltage better described as boost per carrier than as more current?", "How does V = delta E / Q keep total energy and energy per charge separate?"],
            mastery_skills=["voltage_definition", "energy_per_charge", "voltage_calculation", "voltage_equation_meaning", "voltage_vs_current"],
            variation_plan={"diagnostic": "Fresh attempts rotate between source-role meaning, J/C unit meaning, and simple voltage calculations.", "concept_gate": "Concept checks vary between battery-role explanations and voltage-versus-current distinctions.", "mastery": "Mastery mixes numeric V = delta E / Q, source-role reasoning, and voltage-current separation before repeating any prompt."},
            scaffold_support=scaffold("Voltage is the energy given to each unit of charge by the source.", "Read the source role first, then decide how much energy each carrier gets before talking about current.", "If each carrier gets a bigger boost, which quantity at the source has changed?", "Do not call voltage 'more current' when the cleaner idea is energy per charge.", "The Lift Station boosts each token by a certain amount; that is the source's voltage story.", "What stays the same when the source boost changes: the definition of current or the meaning of voltage?", [extra_section("Unit meaning", "1 V means 1 J of energy per 1 C of charge.", "How does that wording block the 'voltage equals current' mistake?"), extra_section("Battery myth", "A battery does not store current like water in a tank. It provides energy per carrier, and the current then depends on the whole route.", "Why can the same battery produce different currents in different circuits?")]),
            visual_clarity_checks=visual_checks("voltage-boost"),
        ),
    )


def resistance_lesson() -> Dict[str, Any]:
    d = [
        mcq("M10L4_D1", "Resistance is best modeled as...", ["route drag", "number of carriers", "energy per charge", "current itself"], 0, "Resistance belongs to the path, not to the moving carriers as a quantity.", ["resistance_route_property_confusion"], skill_tags=["resistance_definition"]),
        mcq("M10L4_D2", "If a wire is made longer but nothing else changes, the resistance usually...", ["increases", "decreases to zero", "becomes voltage", "must stay the same"], 0, "Longer route means more drag.", ["resistance_geometry_confusion"], skill_tags=["length_effect"]),
        mcq("M10L4_D3", "If a route becomes wider while material and length stay the same, the resistance usually...", ["decreases", "increases", "becomes current", "must equal the voltage"], 0, "A wider route makes it easier for carriers to move.", ["resistance_geometry_confusion"], skill_tags=["width_effect"]),
        short("M10L4_D4", "Why is resistance better treated as a path property than as something the battery 'decides'?", ["Because resistance depends on the route material and geometry, while the battery provides voltage.", "Because resistance belongs to the path, not to the source."], "Keep source role and path role separate.", ["resistance_route_property_confusion", "battery_same_current_confusion"], skill_tags=["source_vs_route"], acceptance_rules=acceptance_groups(["resistance"], ["path", "route", "material", "geometry"], ["battery", "source"], ["not", "rather than"], ["belongs to"])) ,
        mcq("M10L4_D5", "Which route should have the greatest resistance if the material is the same?", ["a long narrow route", "a short wide route", "a short smooth route", "a wide short route"], 0, "Long and narrow gives more drag.", ["resistance_geometry_confusion"], skill_tags=["geometry_compare"]),
        mcq("M10L4_D6", "Two circuits use the same battery. One has a rougher route. Which statement is strongest?", ["The rougher route has greater resistance.", "The battery loses its voltage identity.", "The charge is used up earlier.", "Current and resistance become the same quantity."], 0, "Resistance belongs to the route.", ["resistance_route_property_confusion", "battery_same_current_confusion"], skill_tags=["resistance_definition"]),
        short("M10L4_D7", "How can changing the wire shape change resistance even when the material stays the same?", ["Making it longer raises resistance, while making it wider lowers resistance.", "Resistance depends on geometry as well as material, so length and width matter."], "Use geometry language.", ["resistance_geometry_confusion"], skill_tags=["geometry_effects"], acceptance_rules=acceptance_groups(["longer", "length"], ["higher", "more", "raise"], ["wider", "width"], ["lower", "less", "reduce"], ["resistance"])) ,
        mcq("M10L4_D8", "Which phrase best separates resistance from current?", ["resistance is route difficulty; current is flow rate", "resistance is moving charge; current is path length", "resistance is voltage per charge; current is total energy", "they are the same quantity with different names"], 0, "One is a path property and the other is a flow rate.", ["resistance_route_property_confusion", "charge_current_confusion"], skill_tags=["resistance_vs_current"]),
    ]
    c = [
        short("M10L4_C1", "How would you explain resistance in the Carrier-Loop model?", ["Resistance is the route drag that makes it harder for carriers to move.", "Resistance is how strongly the path opposes the carrier flow."], "Use route-drag language.", ["resistance_route_property_confusion"], skill_tags=["resistance_definition"], acceptance_rules=acceptance_groups(["resistance"], ["route drag", "path difficulty", "opposes", "harder"])) ,
        mcq("M10L4_C2", "Two wires are made of the same material. Which has less resistance?", ["the shorter wider wire", "the longer narrower wire", "they must have the same resistance always", "the one with the bigger battery only"], 0, "Shorter and wider means less drag.", ["resistance_geometry_confusion"], skill_tags=["geometry_compare"]),
        mcq("M10L4_C3", "Which change should increase resistance most directly for one material?", ["increase the length", "increase the width", "reduce the roughness", "replace the circuit with a mirror"], 0, "More length means more resistance.", ["resistance_geometry_confusion"], skill_tags=["length_effect"]),
        short("M10L4_C4", "Why is 'the battery makes the resistance' a weak statement?", ["Because the resistance is a property of the route and material, while the battery provides the voltage.", "Because resistance belongs to the path, not to the source itself."], "Separate source and route roles.", ["resistance_route_property_confusion", "battery_same_current_confusion"], skill_tags=["source_vs_route"], acceptance_rules=acceptance_groups(["resistance"], ["route", "path", "material"], ["battery", "source"], ["not", "rather than"], ["belongs"])) ,
        mcq("M10L4_C5", "If you double the width of the same route, the resistance should usually...", ["fall", "rise", "become current", "become voltage"], 0, "A wider route lowers drag.", ["resistance_geometry_confusion"], skill_tags=["width_effect"]),
        short("M10L4_C6", "Why can the same source give different currents in two circuits with different routes?", ["Because the route resistance can be different, even when the source voltage is the same.", "Because current depends on route drag as well as source boost."], "Bring route resistance into the current story.", ["battery_same_current_confusion", "resistance_route_property_confusion"], skill_tags=["source_and_route"], acceptance_rules=acceptance_groups(["same source", "same voltage", "battery"], ["different current"], ["resistance", "route drag", "path"], ["different"])) ,
    ]
    t = [
        mcq("M10L4_M1", "Which route should carry the least current with the same battery?", ["the longest narrowest route", "the shortest widest route", "the smoothest shortest route", "the route with the fewest labels"], 0, "Greater resistance means less current for the same source.", ["resistance_geometry_confusion"], skill_tags=["geometry_compare"]),
        short("M10L4_M2", "What should happen to resistance if the route is made twice as long and everything else stays the same?", ["It should increase because the carriers face more route drag.", "A longer path should have greater resistance."], "Use longer-path language.", ["resistance_geometry_confusion"], skill_tags=["length_effect"], acceptance_rules=acceptance_groups(["longer", "twice as long", "length"], ["more", "greater", "higher", "increase"], ["resistance", "drag"])) ,
        mcq("M10L4_M3", "Which sentence is strongest?", ["Resistance belongs to the path and material.", "Resistance is stored in the battery and sent out with the current.", "Resistance is the same as charge.", "Resistance only depends on how many symbols are drawn."], 0, "Resistance is a route property.", ["resistance_route_property_confusion"], skill_tags=["resistance_definition"]),
        mcq("M10L4_M4", "A short thick wire and a long thin wire are made of the same material. Which has greater resistance?", ["the long thin wire", "the short thick wire", "they must match", "whichever has more current"], 0, "Long and thin gives more resistance.", ["resistance_geometry_confusion"], skill_tags=["geometry_compare"]),
        short("M10L4_M5", "Why is route width part of the resistance story?", ["Because a wider route gives carriers more room to move, so the resistance is lower.", "Because width affects how difficult the path is for the carriers."], "Use more-room or less-drag language.", ["resistance_geometry_confusion"], skill_tags=["width_effect"], acceptance_rules=acceptance_groups(["wider", "width", "more room"], ["lower", "less"], ["resistance", "drag"])) ,
        mcq("M10L4_M6", "Which pair best matches the path-role idea?", ["battery -> voltage, route -> resistance", "battery -> resistance, route -> current store", "battery -> charge destruction, route -> voltage only", "battery -> light, route -> sound"], 0, "Separate source and route roles.", ["resistance_route_property_confusion", "battery_same_current_confusion"], skill_tags=["source_vs_route"]),
        short("M10L4_M7", "A learner says, 'if the battery is the same, the current must be the same.' What correction should you make?", ["I would say the route resistance can change, so the same voltage can still give different currents.", "I would say current depends on both the source boost and the route drag."], "Correct the fixed-current battery myth.", ["battery_same_current_confusion", "resistance_route_property_confusion"], skill_tags=["source_and_route"], acceptance_rules=acceptance_groups(["same battery", "same voltage", "source"], ["different current"], ["resistance", "route drag"], ["depends on", "can change"])) ,
        mcq("M10L4_M8", "Best one-line summary of resistance:", ["route difficulty for charge flow", "energy per charge from the source", "amount of charge in the loop", "the checkpoint count itself"], 0, "Resistance is route difficulty, not a source quantity.", ["resistance_route_property_confusion"], skill_tags=["resistance_definition"]),
    ]
    return lesson_spec("M10_L4", "Route Drag and Resistance", sim("m10_route_drag_lab", "Route drag lab", "Explore how route material and geometry change resistance.", ["Change route length.", "Change route width.", "Compare smooth and rough path materials."], ["Explain resistance as a path property.", "Explain why longer paths raise resistance.", "Explain why wider paths lower resistance."], ["route_length", "route_width", "route_drag", "current_response"], "Resistance and geometry reasoning."), d, "Some parts of the loop are smooth, wide, and easy. Others are long, narrow, or rough. The route itself helps decide how much current can flow.", "Before you blame the battery, inspect the route: its material, length, and width all matter.", [prompt_block("What part of the model represents resistance?", "The route drag or path difficulty."), prompt_block("What two shape features matter most in this lesson?", "Length and width.")], [prompt_block("Lengthen the route while holding the source fixed.", "The current should fall because resistance rises."), prompt_block("Now widen the route and compare again.", "The path becomes easier, so resistance falls.")], ["Explain why resistance belongs to the route rather than to the battery.", "Explain why two circuits with the same battery can still have different currents."], "Track route properties explicitly, or you will accidentally blame the source for what the path is doing.", c, t, contract(concept_targets=["Define resistance as a property of the route.", "Explain qualitatively how length and width change resistance.", "Explain why the same source can give different currents in different routes."], core_concepts=["Resistance is the route drag opposing charge flow.", "For the same material, longer routes have greater resistance.", "For the same material, wider routes have smaller resistance.", "Resistance belongs to the path and material, not to the source."], prerequisite_lessons=["M10_L3", "F4_L3"], misconception_focus=["resistance_route_property_confusion", "resistance_geometry_confusion", "battery_same_current_confusion"], formulas=[relation("resistance rises with length and falls with width", "For one material, geometry changes how hard the path makes current flow.", ["ohm"], "Use qualitatively in this module before later resistivity detail.")], representations=[representation("words", "Keeps resistance as a path property."), representation("formula", "States the qualitative length-and-width rule for resistance."), representation("diagram", "Shows long, short, narrow, and wide sections."), representation("table", "Separates source-fixed cases from route-changed cases.")], analogy_map=carrier_loop_map("the class is comparing long, short, wide, and narrow routes"), worked_examples=[worked("Two wires are made from the same material. One is long and thin; the other is short and thick. Which has greater resistance?", ["Keep the material fixed.", "Compare length first.", "Compare width second and combine the effects."], "The long thin wire has the greater resistance.", "Greater length raises resistance and smaller width raises it further.", "This builds the geometry story without extra formalism."), worked("Why can the same battery produce different currents in two different loops?", ["Keep the source role fixed.", "Inspect the route drag in each loop.", "State what that means for the current."], "Because the route resistance can differ even when the source voltage is the same.", "Current depends on both the source boost and the route drag.", "This directly attacks the 'battery gives the same current' misconception."), worked("A learner says resistance is a thing the battery sends into the circuit. What is the better picture?", ["Ask what part of the model resistance belongs to.", "Name the path properties that create it.", "State the corrected role."], "Resistance is a property of the route and material, not something the battery sends out.", "The source provides voltage; the route provides drag.", "This keeps the source and path jobs distinct for later circuit work.")], visual_assets=[visual("m10-l4-route-drag", "resistance_drag", "Route drag", "Shows how length, width, and roughness change the path difficulty.", "Long, narrow, and rough should read as higher drag than short, wide, and smooth.")], animation_assets=[animation("m10-l4-drag-compare", "resistance_drag", "Drag compare", "Shows current slowing in long and narrow routes and recovering in short and wide routes.")], simulation_contract=sim_contract("m10-l4-route-drag-lab", "resistance_drag", "How do route material and geometry change the resistance?", "Start with one smooth medium-length route, then lengthen it before widening it.", ["Change length while keeping width fixed.", "Change width while keeping length fixed.", "Compare smooth and rough route materials."], "Do not describe resistance as if it were stored in the battery.", "Resistance belongs to the route and changes with material and geometry.", [("route_length", "Route length", "Longer routes raise resistance."), ("route_width", "Route width", "Wider routes lower resistance."), ("route_material", "Route material", "Shows that material matters as well as geometry.")], [("Resistance index", "Shows the path difficulty directly."), ("Current response", "Shows how the same source produces different currents when resistance changes."), ("Route summary", "Keeps the material and geometry story readable.")]), reflection_prompts=["Why does resistance belong to the route rather than to the battery?", "Why do longer and narrower routes usually give greater resistance?"], mastery_skills=["resistance_definition", "source_vs_route", "geometry_compare", "length_effect", "width_effect"], variation_plan={"diagnostic": "Fresh attempts rotate between route-property meaning, same-material geometry comparisons, and source-versus-route stems.", "concept_gate": "Concept checks vary between length, width, and battery-versus-route explanations.", "mastery": "Mastery mixes geometry comparisons, source-and-route reasoning, and qualitative current predictions before repeating any prompt."}, scaffold_support=scaffold("Resistance is the route difficulty that opposes charge flow.", "Look at the path length, width, and material before deciding what resistance should do.", "If the source stays the same but the path gets rougher, what should happen to the resistance?", "Do not treat resistance as a thing stored in the battery.", "A draggy route slows the carrier flow even when the lift station is unchanged.", "Which part of the model decides the resistance: the lift station or the route?", [extra_section("Length matters", "A longer route gives the carriers more difficult path to negotiate, so resistance rises.", "What happens to resistance when the same wire is made longer?"), extra_section("Width matters", "A wider route gives more room for charge flow, so resistance falls.", "Why does a wider path lower the route drag?")]), visual_clarity_checks=visual_checks("resistance-geometry")))


def ohm_law_lesson() -> Dict[str, Any]:
    d = [
        mcq("M10L5_D1", "For an ohmic route, the simple rate rule is...", ["I = V/R", "V = Q/t", "R = Q/t", "I = QR"], 0, "Ohm's law for an ohmic route is I = V/R.", ["ohms_law_universal_confusion"], skill_tags=["ohms_law"]),
        mcq("M10L5_D2", "If voltage doubles while resistance stays fixed in an ohmic route, the current...", ["doubles", "halves", "stays fixed by the battery only", "becomes the same as resistance"], 0, "More voltage gives proportionally more current when resistance is fixed.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_proportionality"]),
        mcq("M10L5_D3", "If resistance doubles while voltage stays fixed in an ohmic route, the current...", ["halves", "doubles", "stays the same", "becomes voltage"], 0, "More resistance means less current.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_proportionality"]),
        mcq("M10L5_D4", "A 12 V source across a 4 ohm ohmic route gives current...", ["3 A", "16 A", "48 A", "0.33 A"], 0, "Use I = V/R.", ["ohms_law_universal_confusion"], skill_tags=["current_from_ohms_law"]),
        short("M10L5_D5", "Why is Ohm's law better introduced as a rate rule for an ohmic route than as a formula to memorize?", ["Because it says current depends jointly on voltage and resistance in a simple proportional way for an ohmic route.", "Because it summarizes how fixed drag and source boost set the current in a route that behaves ohmically."], "Keep the proportional rule visible.", ["ohms_law_universal_confusion"], skill_tags=["ohms_law_meaning"], acceptance_rules=acceptance_groups(["current"], ["depends", "set by"], ["voltage", "boost"], ["resistance", "drag"], ["ohmic", "proportional"])) ,
        mcq("M10L5_D6", "What is the strongest warning about Ohm's law?", ["It works cleanly for ohmic routes, but not every component is ohmic.", "It always works for every electrical device without exception.", "It replaces the meanings of current and voltage.", "It proves that resistance is created by the battery."], 0, "Ohm's law is empirical and not universal.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_condition"]),
        short("M10L5_D7", "How does increasing route drag affect current when the source voltage stays fixed?", ["It reduces the current because current is inversely related to resistance in an ohmic route.", "More resistance means less carrier flow for the same voltage."], "Use fixed-voltage inverse language.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_proportionality"], acceptance_rules=acceptance_groups(["more", "increase"], ["resistance", "route drag"], ["less", "reduce", "lower"], ["current", "flow"], ["same voltage", "fixed voltage"])) ,
        mcq("M10L5_D8", "Which pair should give the same current in an ohmic route?", ["6 V across 3 ohm and 12 V across 6 ohm", "6 V across 3 ohm and 6 V across 6 ohm", "12 V across 3 ohm and 6 V across 6 ohm", "3 V across 12 ohm and 6 V across 3 ohm"], 0, "Both equal 2 A.", ["ohms_law_universal_confusion"], skill_tags=["compare_ohms_law"]),
    ]
    c = [
        short("M10L5_C1", "What does I = V/R say in words?", ["Current equals voltage divided by resistance for an ohmic route.", "For an ohmic route, current depends on the source voltage and the route resistance."], "Translate the equation into words.", ["ohms_law_universal_confusion"], skill_tags=["ohms_law_meaning"], acceptance_rules=acceptance_groups(["current"], ["voltage"], ["divided by", "depends on"], ["resistance"], ["ohmic"])) ,
        mcq("M10L5_C2", "A 9 V source across a 3 ohm resistor gives current...", ["3 A", "6 A", "12 A", "0.33 A"], 0, "I = V/R.", ["ohms_law_universal_confusion"], skill_tags=["current_from_ohms_law"]),
        mcq("M10L5_C3", "If the current doubles while resistance stays fixed in an ohmic resistor, what must happen to the voltage?", ["it doubles", "it halves", "it disappears", "it becomes resistance"], 0, "For fixed R, V and I are proportional.", ["ohms_law_universal_confusion"], skill_tags=["voltage_from_ohms_law"]),
        short("M10L5_C4", "Why is it weak to say that a battery always gives the same current?", ["Because in an ohmic route the current depends on both the voltage and the resistance of the whole loop.", "Because the same source can produce different currents in routes with different resistance."], "Bring both variables into the current story.", ["battery_same_current_confusion", "ohms_law_universal_confusion"], skill_tags=["ohms_law_meaning"], acceptance_rules=acceptance_groups(["same battery", "same source", "voltage"], ["different current"], ["resistance", "whole loop", "route drag"], ["depends on"])) ,
        mcq("M10L5_C5", "A resistor has 8 V across it and current 2 A. Its resistance is...", ["4 ohm", "16 ohm", "10 ohm", "0.25 ohm"], 0, "Use R = V/I.", ["ohms_law_universal_confusion"], skill_tags=["resistance_from_ohms_law"]),
        short("M10L5_C6", "What does the word 'ohmic' warn you to remember?", ["It warns that the simple V, I, and R proportional rule applies to routes that behave ohmically, not to every component automatically.", "It reminds you that Ohm's law is a simple rule for ohmic elements, not a universal law for all devices."], "Keep the empirical limit visible.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_condition"], acceptance_rules=acceptance_groups(["ohmic"], ["not every", "not all", "only some"], ["component", "route", "element"], ["simple rule", "proportional", "Ohm"])) ,
    ]
    t = [
        mcq("M10L5_M1", "15 V across a 5 ohm ohmic resistor gives current...", ["3 A", "10 A", "20 A", "75 A"], 0, "I = V/R.", ["ohms_law_universal_confusion"], skill_tags=["current_from_ohms_law"]),
        short("M10L5_M2", "How would you predict the effect of doubling resistance at fixed voltage in an ohmic route?", ["I would predict the current halves because current is inversely related to resistance when voltage is fixed.", "I would say more route drag gives less current for the same source voltage."], "Use inverse reasoning at fixed voltage.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_proportionality"], acceptance_rules=acceptance_groups(["double", "more", "increase"], ["resistance", "drag"], ["half", "halve", "less", "lower"], ["current"], ["fixed voltage", "same voltage"])) ,
        mcq("M10L5_M3", "Which route is definitely described as ohmic in this lesson?", ["a route that shows current proportional to voltage when resistance is fixed", "a route that always has the highest current", "a route with zero resistance only", "a route that stores current in the source"], 0, "Ohmic means it follows the simple proportional rule.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_condition"]),
        mcq("M10L5_M4", "A resistor carries 2 A when 6 V is applied. If the same resistor gets 12 V, the current should be...", ["4 A", "1 A", "2 A", "24 A"], 0, "For a fixed ohmic resistor, doubling V doubles I.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_proportionality"]),
        short("M10L5_M5", "Why is Ohm's law useful conceptually before it is useful algebraically?", ["Because it keeps current tied to both source voltage and route resistance instead of treating either one alone as the whole story.", "Because it summarizes the rate rule for how boost and drag together set the current in an ohmic route."], "Use two-factor language.", ["ohms_law_universal_confusion"], skill_tags=["ohms_law_meaning"], acceptance_rules=acceptance_groups(["current"], ["voltage", "boost"], ["resistance", "drag"], ["together", "both", "jointly"], ["ohmic"])) ,
        mcq("M10L5_M6", "A 10 V source produces 2 A in an ohmic route. The resistance is...", ["5 ohm", "12 ohm", "20 ohm", "0.2 ohm"], 0, "R = V/I.", ["ohms_law_universal_confusion"], skill_tags=["resistance_from_ohms_law"]),
        short("M10L5_M7", "A learner says, 'higher voltage means the battery sends more current all by itself.' What should you add?", ["I would add that the route resistance still matters, so voltage alone does not decide the current.", "I would say the current depends on both the voltage and the resistance."], "Keep both variables visible.", ["battery_same_current_confusion", "ohms_law_universal_confusion"], skill_tags=["ohms_law_meaning"], acceptance_rules=acceptance_groups(["current"], ["depends on", "both"], ["voltage"], ["resistance"], ["not", "not alone"])) ,
        mcq("M10L5_M8", "Which statement best respects the status of Ohm's law?", ["It is a simple relationship for ohmic elements.", "It proves that every circuit element is identical.", "It replaces the meaning of voltage.", "It shows that charge is used up."], 0, "Ohm's law is a useful simple model for ohmic behavior.", ["ohms_law_universal_confusion"], skill_tags=["ohmic_condition"]),
    ]
    return lesson_spec("M10_L5", "Ohmic Routes and the Rate Rule", sim("m10_ohmic_route_lab", "Ohmic route lab", "Discover the simple current-voltage-resistance rule for ohmic routes.", ["Change voltage with resistance fixed.", "Change resistance with voltage fixed.", "Compare ohmic and non-ohmic route behavior."], ["Use Ohm's law conceptually.", "Calculate current, voltage, or resistance for ohmic routes.", "Remember that not every element is ohmic."], ["voltage", "resistance", "current", "ohmic_toggle"], "Ohm's-law reasoning."), d, "In an ohmic route, the current responds to the source boost and the route drag in a clean predictable way.", "Before solving, decide which quantity is fixed and which one you are changing.", [prompt_block("What happens to current if voltage rises while resistance stays fixed in an ohmic route?", "It rises proportionally."), prompt_block("What happens to current if resistance rises while voltage stays fixed?", "It falls.")], [prompt_block("Keep the route ohmic and raise the source voltage.", "The current should rise in proportion."), prompt_block("Now hold the voltage fixed and increase the route drag.", "The current should fall as resistance rises.")], ["Explain why I = V/R is a two-quantity control rule rather than a one-quantity slogan.", "Explain why the word 'ohmic' matters in this lesson."], "Use the rule as a compact summary of boost and drag, not as a magic memory trick.", c, t, contract(concept_targets=["Use Ohm's law conceptually as a relationship between current, voltage, and resistance for ohmic routes.", "Calculate current, voltage, or resistance for simple ohmic cases.", "Explain why the same source can give different currents in different resistive routes."], core_concepts=["For an ohmic route, current depends on both voltage and resistance.", "At fixed resistance, a larger voltage gives a larger current.", "At fixed voltage, a larger resistance gives a smaller current.", "Ohm's law is a simple rule for ohmic behavior, not a guarantee that every component behaves that way."], prerequisite_lessons=["M10_L4", "F4_L3"], misconception_focus=["battery_same_current_confusion", "ohms_law_universal_confusion", "voltage_current_confusion", "resistance_route_property_confusion"], formulas=[relation("I = V / R", "For an ohmic route, current equals voltage divided by resistance.", ["A", "V", "ohm"], "Use for ohmic conductors or resistors."), relation("V = I R", "Voltage across an ohmic resistor equals current times resistance.", ["V", "A", "ohm"], "Use when current and resistance are known.")], representations=[representation("words", "Explains that voltage and resistance jointly control current in an ohmic route."), representation("formula", "Shows the simple ohmic rate rule."), representation("table", "Compares fixed-R and fixed-V changes."), representation("diagram", "Keeps boost and drag visible in one loop.")], analogy_map=carrier_loop_map("the class is testing how source boost and route drag together set the checkpoint rate"), worked_examples=[worked("A 12 V source is connected to a 4 ohm ohmic resistor. What is the current?", ["Read V = 12 V.", "Read R = 4 ohm.", "Use I = V/R and keep the ampere unit."], "3 A", "For an ohmic resistor, current equals voltage divided by resistance.", "This locks the proportional rule to a simple numeric case."), worked("The same resistor carries 2 A at 6 V. What current should it carry at 12 V?", ["Keep the resistance fixed.", "Notice the voltage doubles.", "Use proportional reasoning before any new algebra."], "4 A", "In an ohmic resistor, doubling voltage at fixed resistance doubles current.", "This builds Ohm's law as a pattern, not just a plug-in exercise."), worked("Why does the same battery not guarantee the same current in every circuit?", ["Keep the source voltage fixed.", "Compare the route resistance in different circuits.", "State what the rule predicts."], "Because different resistances give different currents even with the same source voltage.", "Ohm's law keeps both voltage and resistance in the current story.", "This directly corrects one of the common battery myths.")], visual_assets=[visual("m10-l5-ohmic-rule", "ohms_law", "Ohmic rule", "Shows current responding to voltage and resistance in a proportional way.", "Fixed-voltage and fixed-resistance comparisons must stay easy to read.")], animation_assets=[animation("m10-l5-ohmic-response", "ohms_law", "Ohmic response", "Shows current rising with source boost and falling with route drag in an ohmic route.")], simulation_contract=sim_contract("m10-l5-ohmic-route-lab", "ohms_law", "How do voltage and resistance jointly control the current in an ohmic route?", "Start with one ohmic route and compare a low-voltage case with a higher-voltage case before changing the resistance.", ["Hold resistance fixed and change the voltage.", "Hold voltage fixed and change the resistance.", "Toggle between ohmic and non-ohmic behavior to keep the condition visible."], "Do not treat Ohm's law as if it applied automatically to every possible component.", "For an ohmic route, current rises with voltage and falls with resistance.", [("voltage", "Source voltage", "Shows the energy-per-charge boost supplied by the source."), ("resistance", "Route resistance", "Shows the drag opposing charge flow."), ("ohmic_toggle", "Ohmic behavior toggle", "Keeps the condition for the simple rule visible.")], [("Current", "Shows the resulting checkpoint rate."), ("Predicted ohmic current", "Makes the proportional rule explicit."), ("Route status", "Shows whether the route is behaving ohmically.")]), reflection_prompts=["Why is Ohm's law better treated as a relationship than as an isolated formula?", "Why does the word 'ohmic' belong in careful explanations of I = V/R?"], mastery_skills=["ohms_law", "ohms_law_meaning", "ohmic_proportionality", "current_from_ohms_law", "ohmic_condition"], variation_plan={"diagnostic": "Fresh attempts rotate between fixed-V, fixed-R, and equation-meaning stems.", "concept_gate": "Concept checks vary between translated equation meaning, battery myth correction, and ohmic-condition prompts.", "mastery": "Mastery mixes numeric Ohm's law, proportional reasoning, and same-source-different-current explanations before repeating any prompt."}, scaffold_support=scaffold("For an ohmic route, current is controlled jointly by voltage and resistance.", "Ask which variable is fixed before predicting the change in current.", "If voltage stays fixed and resistance doubles, what happens to the current?", "Do not speak as if the battery alone decides the current.", "A strong lift with a draggy route and a weak lift with an easy route can produce very different currents.", "Which quantity belongs to the source, and which quantity belongs to the route, in I = V/R?", [extra_section("Fixed-resistance thinking", "With resistance fixed, voltage and current rise or fall together in an ohmic route.", "If voltage doubles at fixed resistance, what happens to current?"), extra_section("Fixed-voltage thinking", "With voltage fixed, a larger resistance reduces current.", "Why does a draggier route lower the checkpoint rate?")]), visual_clarity_checks=visual_checks("ohmic-rule")))


def ledger_lesson() -> Dict[str, Any]:
    d = [
        mcq("M10L6_D1", "Which pair best keeps current and voltage separate?", ["current = charge per second, voltage = energy per charge", "current = energy per charge, voltage = total charge", "current = route drag, voltage = charge used up", "current = battery size, voltage = carrier count"], 0, "Use rate-versus-energy-per-charge language.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["quantity_separation"]),
        mcq("M10L6_D2", "Two circuits use the same battery, but one has higher resistance. Which one has smaller current if the route is ohmic?", ["the higher-resistance circuit", "the lower-resistance circuit", "they must always match", "the one with more symbols"], 0, "Same voltage with more resistance means less current.", ["battery_same_current_confusion", "ohms_law_universal_confusion"], skill_tags=["compare_loops"]),
        short("M10L6_D3", "Why is a loop ledger useful in electrical quantities?", ["Because it keeps charge, current, voltage, and resistance from being collapsed into one vague idea.", "Because it tracks what moves, what each carrier gets, and what limits the flow."], "Use quantity-separation language.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["ledger_reasoning"], acceptance_rules=acceptance_groups(["charge", "current", "voltage", "resistance", "quantities"], ["separate", "distinguish", "keep apart", "track"], ["what moves", "what each carrier gets", "what limits the flow"])) ,
        mcq("M10L6_D4", "A loop has the same current as another loop but fewer carriers in total. The strongest conclusion is...", ["same current does not automatically mean same total charge in the loop", "the voltages must be zero", "resistance has disappeared", "charge is not conserved"], 0, "Same current does not force the same charge amount.", ["current_as_amount_confusion", "charge_current_confusion"], skill_tags=["quantity_separation"]),
        mcq("M10L6_D5", "A source gives 12 J to 3 C of charge, and the loop current is 1 A. Which pair is correct?", ["4 V and 1 A", "12 V and 3 A", "3 V and 4 A", "4 ohm and 1 C"], 0, "Use V = delta E / Q and read I separately.", ["voltage_current_confusion", "voltage_total_energy_confusion"], skill_tags=["multi_quantity_calc"]),
        short("M10L6_D6", "Why does doubling voltage not create new carriers?", ["Because voltage changes the energy per carrier, not whether charge exists in the loop.", "Because the source can give each carrier a bigger boost without creating more charge."], "Keep boost separate from carrier creation.", ["voltage_total_energy_confusion", "charge_used_up_confusion"], skill_tags=["quantity_separation"], acceptance_rules=acceptance_groups(["voltage"], ["energy per charge", "boost"], ["not", "rather than"], ["new carriers", "more charge", "create charge"])) ,
        mcq("M10L6_D7", "Best first question before choosing I = Q/t, V = delta E/Q, or I = V/R:", ["Which quantity is unknown, and what physical meaning does it have?", "Which number is largest?", "Which symbol has the nicest unit?", "Which answer looks neatest?"], 0, "Equation choice should follow quantity meaning.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["choose_equation"]),
        short("M10L6_D8", "Why can the same voltage appear in two loops but the currents differ?", ["Because the route resistances can be different even when the source voltage is the same.", "Because current depends on both voltage and resistance, so equal source boost does not force equal flow."], "Use same-source different-route language.", ["battery_same_current_confusion", "ohms_law_universal_confusion"], skill_tags=["compare_loops"], acceptance_rules=acceptance_groups(["same voltage", "same source"], ["different current"], ["resistance", "route drag"], ["depends on"])) ,
    ]
    c = [
        short("M10L6_C1", "How would you separate charge, current, and voltage in one sentence?", ["Charge is the carrier quantity, current is charge flow rate, and voltage is energy per charge.", "Charge is what moves, current is how fast it passes a point, and voltage is the boost each unit of charge receives."], "Keep the three quantities in one clean sentence.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["quantity_separation"], acceptance_rules=acceptance_groups(["charge"], ["carrier", "moves", "quantity"], ["current"], ["rate", "passes a point", "per second"], ["voltage"], ["energy per charge", "boost"])) ,
        mcq("M10L6_C2", "A loop has 2 A of current. Another also has 2 A. What else must you still ask to compare the circuits properly?", ["their voltage and resistance story", "whether current exists", "whether charge is conserved in the universe", "whether a mirror is present"], 0, "Same current does not finish the electrical story.", ["voltage_current_confusion", "battery_same_current_confusion"], skill_tags=["compare_loops"]),
        mcq("M10L6_C3", "A source gives 15 J to 5 C of charge. The voltage is...", ["3 V", "10 V", "20 V", "75 V"], 0, "Use V = delta E / Q.", ["voltage_total_energy_confusion"], skill_tags=["multi_quantity_calc"]),
        short("M10L6_C4", "Why is choosing the right equation part of the physics rather than just algebra here?", ["Because each equation matches a different physical quantity: flow rate, energy per charge, or the ohmic rate rule.", "Because you must know whether the unknown is current, voltage, charge, time, or resistance before choosing the equation."], "Use quantity-choice language.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["choose_equation"], acceptance_rules=acceptance_groups(["equation"], ["matches", "choose"], ["current", "voltage", "charge", "time", "resistance"], ["physical quantity", "meaning"])) ,
        mcq("M10L6_C5", "If two loops have the same voltage but different resistance, which quantity should differ in an ohmic comparison?", ["current", "the definition of charge", "the meaning of voltage", "the existence of the source"], 0, "Same V with different R gives different I.", ["battery_same_current_confusion", "ohms_law_universal_confusion"], skill_tags=["compare_loops"]),
        short("M10L6_C6", "Why is 'the battery sends electricity' weaker than the ledger language in this module?", ["Because the ledger separates moving charge, current as flow rate, voltage as energy per charge, and resistance as route drag.", "Because the ledger says who moves, what each carrier gets, and what limits the flow instead of using one vague word."], "Use separated-quantity language.", ["charge_current_confusion", "voltage_current_confusion", "resistance_route_property_confusion"], skill_tags=["ledger_reasoning"], acceptance_rules=acceptance_groups(["charge", "current", "voltage", "resistance"], ["separate", "ledger", "who moves", "what each carrier gets", "limits the flow"], ["not", "rather than"], ["electricity"])) ,
    ]
    t = [
        mcq("M10L6_M1", "Which matched pair is correct?", ["charge -> carrier quantity; current -> rate", "charge -> resistance; current -> energy per charge", "charge -> route drag; current -> total energy", "charge -> battery size; current -> token count"], 0, "Keep the meanings clean.", ["charge_current_confusion"], skill_tags=["quantity_separation"]),
        short("M10L6_M2", "A learner says, 'same battery means same current.' What is the best correction now?", ["The same source voltage can still produce different currents if the route resistance changes.", "Current depends on both the source boost and the route drag, so equal batteries do not force equal currents."], "Use same-source different-route language.", ["battery_same_current_confusion", "ohms_law_universal_confusion"], skill_tags=["compare_loops"], acceptance_rules=acceptance_groups(["same battery", "same source", "same voltage"], ["different current"], ["resistance", "route drag"], ["depends on"])) ,
        mcq("M10L6_M3", "12 C pass a point in 4 s. The source gives 24 J to that 12 C. Which pair is correct?", ["3 A and 2 V", "4 A and 12 V", "48 A and 2 V", "3 A and 24 V"], 0, "Use I = Q/t and V = delta E/Q separately.", ["charge_current_confusion", "voltage_total_energy_confusion"], skill_tags=["multi_quantity_calc"]),
        mcq("M10L6_M4", "Which question should push you toward V = delta E/Q instead of I = Q/t?", ["How much energy does each coulomb receive?", "How much charge passes each second?", "How long is the wire?", "How rough is the route?"], 0, "Equation choice follows the quantity meaning.", ["voltage_total_energy_confusion"], skill_tags=["choose_equation"]),
        short("M10L6_M5", "Why can a circuit keep the same carriers while still changing current and voltage descriptions?", ["Because the same charge can circulate while the flow rate and the energy per charge are different quantities.", "Because carrier existence, checkpoint rate, and source boost are separate parts of the electrical story."], "Keep charge, current, and voltage separate.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["quantity_separation"], acceptance_rules=acceptance_groups(["same carriers", "same charge"], ["current", "flow rate"], ["voltage", "energy per charge", "boost"], ["different", "separate"])) ,
        mcq("M10L6_M6", "A source gives 8 V to two ohmic loops. Loop A has 2 ohm; Loop B has 4 ohm. Which current pair is correct?", ["4 A in A and 2 A in B", "2 A in A and 4 A in B", "4 A in both", "2 A in both"], 0, "I = V/R for each loop.", ["ohms_law_universal_confusion"], skill_tags=["compare_loops"]),
        short("M10L6_M7", "What does a good loop ledger stop you from collapsing into one vague word?", ["It stops you from collapsing charge, current, voltage, and resistance into one vague idea of electricity.", "It forces you to track what moves, what is supplied per charge, and what limits the rate."], "Use separated-quantity language.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["ledger_reasoning"], acceptance_rules=acceptance_groups(["charge", "current", "voltage", "resistance"], ["separate", "track", "ledger"], ["vague electricity", "one vague word", "what moves", "what is supplied", "what limits"])) ,
        mcq("M10L6_M8", "Best first move in a mixed electrical-quantities problem:", ["name the unknown quantity before choosing the equation", "pick the longest equation", "substitute every number at once", "start by assuming the battery sets the current"], 0, "Physical meaning comes before algebra choice.", ["charge_current_confusion", "voltage_current_confusion"], skill_tags=["choose_equation"]),
    ]
    return lesson_spec("M10_L6", "Loop Ledger and Quantity Separation", sim("m10_loop_ledger_lab", "Loop ledger lab", "Compare two loops and use the ledger to keep charge, current, voltage, and resistance separate.", ["Compare two loops with the same source.", "Change one route resistance at a time.", "Match each unknown to the right equation."], ["Separate the main electrical quantities cleanly.", "Choose equations from physical meaning rather than pattern matching.", "Explain why the same source can still produce different currents."], ["source_voltage", "loop_a_resistance", "loop_b_resistance", "loop_comparison"], "Quantity separation and mixed reasoning."), d, "The Loop Ledger is where the module comes together: who moves, what each carrier gets, how fast they pass, and what route drag limits them.", "Name the unknown quantity before you touch an equation, or the symbols will all start to look like one vague electrical blur.", [prompt_block("Which quantity is the carrier stuff?", "Charge."), prompt_block("Which quantity is energy per charge?", "Voltage.")], [prompt_block("Compare two loops with the same source and different route drag.", "The currents can differ because the resistance differs."), prompt_block("Now compare a current question with a voltage question.", "The correct equation depends on the meaning of the unknown.")], ["Explain why choosing the equation is part of the physics here.", "Explain how the ledger keeps charge, current, voltage, and resistance from collapsing into one word."], "The ledger makes the module coherent by keeping the quantities separate but connected.", c, t, contract(concept_targets=["Separate charge, current, voltage, and resistance in one coherent loop story.", "Choose equations by physical meaning rather than by pattern matching.", "Compare loops with the same source but different resistance."], core_concepts=["Charge is the conserved carrier quantity.", "Current is the rate of charge flow.", "Voltage is energy per charge supplied by the source.", "Resistance is route drag that limits the flow for a given source."], prerequisite_lessons=["M10_L5"], misconception_focus=["charge_current_confusion", "voltage_current_confusion", "battery_same_current_confusion", "voltage_total_energy_confusion"], formulas=[relation("I = Q / t", "Current is charge flow rate.", ["A", "C", "s"], "Use when charge and time are known."), relation("V = delta E / Q", "Voltage is energy per charge.", ["V", "J", "C"], "Use when energy transfer per charge is known."), relation("I = V / R", "For an ohmic route, current depends on voltage and resistance.", ["A", "V", "ohm"], "Use for ohmic comparisons.")], representations=[representation("words", "Separates charge, current, voltage, and resistance in sentence form before equation choice."), representation("formula", "Lists the defining equations for flow rate, energy per charge, and ohmic current."), representation("table", "Separates who moves, what each carrier gets, and what limits the rate."), representation("diagram", "Shows the same source giving different currents in different routes.")], analogy_map=carrier_loop_map("the class is using the loop ledger to decide which quantity is being asked for"), worked_examples=[worked("12 C pass a point in 4 s, and the source gives 24 J to that charge. What are the current and voltage?", ["Use I = Q/t for the flow-rate part.", "Use V = delta E/Q for the energy-per-charge part.", "Report the two quantities separately."], "Current = 3 A and voltage = 2 V", "The same data set can answer different questions when the quantities are kept separate.", "This is the capstone separation skill for the module."), worked("Two loops use the same 8 V source. Loop A has 2 ohm and Loop B has 4 ohm. Compare the currents.", ["Notice the source voltage is the same.", "Apply I = V/R to each loop separately.", "Compare the resulting currents."], "Loop A has 4 A, and Loop B has 2 A", "Equal source voltage does not force equal current when the resistances differ.", "This directly breaks the 'battery gives the same current' misconception."), worked("A learner uses I = Q/t for a voltage question. What is the fix?", ["Name the unknown quantity first.", "Match the quantity to its defining relationship.", "Choose the equation that fits the meaning."], "Use V = delta E/Q if the question is about energy per charge.", "Equation choice is part of the physics because each formula refers to a different quantity.", "This is the final discipline the ledger is designed to build.")], visual_assets=[visual("m10-l6-loop-ledger", "quantity_ledger", "Loop ledger", "Shows two loops with the same source but different route drag and clearly separated readouts.", "Each quantity should stay visually separate while the loops are compared side by side.")], animation_assets=[animation("m10-l6-ledger-compare", "quantity_ledger", "Ledger compare", "Shows side-by-side loops with the same source voltage and different resistances so the current difference stays visible.")], simulation_contract=sim_contract("m10-l6-loop-ledger-lab", "quantity_ledger", "How do you keep charge, current, voltage, and resistance separate when comparing two loops?", "Start with two loops using the same source and compare them before changing one route resistance.", ["Compare same-voltage different-resistance loops.", "Pick the right equation for current, voltage, or rate questions instead of mixing them."], "Do not collapse all electrical quantities into the word electricity.", "The loop ledger separates what moves, what each carrier gets, and what limits the current.", [("source_voltage", "Source voltage", "Keeps the boost per carrier visible in both loops."), ("loop_a_resistance", "Loop A resistance", "Controls the drag in the first loop."), ("loop_b_resistance", "Loop B resistance", "Controls the drag in the second loop.")], [("Loop A current", "Shows the current in the first loop."), ("Loop B current", "Shows the current in the second loop."), ("Equation cue", "Reminds learners which quantity each equation belongs to.")]), reflection_prompts=["Why is choosing the correct equation part of the physics, not just the algebra, in this module?", "How does the loop ledger stop charge, current, voltage, and resistance from collapsing into one vague idea?"], mastery_skills=["quantity_separation", "ledger_reasoning", "choose_equation", "compare_loops", "multi_quantity_calc"], variation_plan={"diagnostic": "Fresh attempts rotate between quantity-separation, same-source-different-current, and mixed current-voltage prompts.", "concept_gate": "Concept checks vary between ledger language, equation-choice reasoning, and same-voltage different-resistance comparisons.", "mastery": "Mastery mixes mixed-quantity calculations, compare-loop reasoning, and ledger explanations before repeating any prompt."}, scaffold_support=scaffold("A good loop ledger separates what moves, what each carrier gets, and what limits the flow.", "Name the quantity first, then choose the equation that matches its meaning.", "If the unknown is energy per charge, should you reach first for current or voltage language?", "Do not call everything electricity when the module is teaching several distinct quantities.", "The ledger keeps the moving carriers, the checkpoint rate, the lift boost, and the route drag on separate lines.", "Which line in the ledger tells you about current, and which line tells you about voltage?", [extra_section("Same source, different current", "Two loops can share the same source voltage and still carry different currents because the route resistance can differ.", "Why does equal source voltage not force equal current?"), extra_section("Equation choice", "I = Q/t, V = delta E/Q, and I = V/R answer different kinds of question. Choose by meaning, not by symbol panic.", "What should you identify before choosing one of those equations?")]), visual_clarity_checks=visual_checks("loop-ledger")))


M10_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Charge, current, voltage, resistance, and Ohm's law taught through the Carrier-Loop and Flow-Grid 2.0 models so students separate moving carriers, flow rate, energy per charge, and route drag.",
    "mastery_outcomes": [
        "Explain charge as the conserved carrier quantity in a circuit.",
        "Define current as the rate of charge flow and calculate it from I = Q/t.",
        "Explain voltage as energy per unit charge and calculate it from V = delta E/Q.",
        "Explain resistance as a property of route material and geometry.",
        "Use Ohm's law conceptually and quantitatively for ohmic routes.",
        "Keep charge, current, voltage, and resistance distinct when comparing loops.",
    ],
    "lessons": [carriers_lesson(), current_lesson(), voltage_lesson(), resistance_lesson(), ohm_law_lesson(), ledger_lesson()],
}


RELEASE_CHECKS = [
    "Every lesson keeps charge carriers, current, voltage, resistance, and Ohm's law in one Carrier-Loop world.",
    "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
    "Every lesson-owned assessment bank is broad enough to prefer unseen questions before repeated stems.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example explains why the answer follows instead of naming only the final label.",
    "Every electrical-quantity visual keeps carriers, checkpoints, boosts, and route-drag labels readable without clipping.",
]


M10_MODULE_DOC, M10_LESSONS, M10_SIM_LABS = build_nextgen_module_bundle(
    module_id=M10_MODULE_ID,
    module_title=M10_MODULE_TITLE,
    module_spec=M10_SPEC,
    allowlist=M10_ALLOWLIST,
    content_version=M10_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=14,
    level="Module 10",
    estimated_minutes=300,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M10 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(M10_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M10_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M10_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M10_MODULE_ID)]
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


