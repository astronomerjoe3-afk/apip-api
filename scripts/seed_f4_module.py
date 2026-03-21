from __future__ import annotations

import argparse
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

try:
    import firebase_admin
    from firebase_admin import credentials
    from google.cloud import firestore
except ModuleNotFoundError:
    firebase_admin = None
    credentials = None
    firestore = None

try:
    from scripts.lesson_authoring_contract import validate_nextgen_module
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_scaffold import build_nextgen_module_scaffold
except ModuleNotFoundError:
    from lesson_authoring_contract import validate_nextgen_module
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_scaffold import build_nextgen_module_scaffold

F4_MODULE_ID = "F4"
F4_CONTENT_VERSION = "20260321_f4_flow_grid_v4"
F4_ALLOWLIST = [
    "charge_current_rate_confusion",
    "current_used_up_confusion",
    "potential_difference_energy_confusion",
    "cell_component_energy_flow_confusion",
    "resistance_current_relationship_confusion",
    "iv_graph_reasoning_confusion",
    "series_circuit_rule_confusion",
    "parallel_circuit_rule_confusion",
    "power_energy_circuit_confusion",
    "electrical_safety_confusion",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_project_id(cli_project: str | None) -> str:
    return cli_project or os.getenv("GOOGLE_CLOUD_PROJECT") or os.getenv("GCP_PROJECT") or os.getenv("GCLOUD_PROJECT") or "apip-dev-487809-c949c"


def init_firebase(project_id: str) -> firestore.Client:
    if firebase_admin is None or credentials is None or firestore is None:
        raise RuntimeError("firebase_admin is required to seed F4 into Firestore.")
    if not firebase_admin._apps:
        firebase_admin.initialize_app(credentials.ApplicationDefault(), {"projectId": project_id})
    return firestore.Client(project=project_id)


def upsert_doc(db: firestore.Client, collection: str, doc_id: str, data: Dict[str, Any], apply: bool) -> None:
    ref = db.collection(collection).document(doc_id)
    if apply:
        ref.set(data, merge=True)
        print(f"UPSERT {collection}/{doc_id}")
    else:
        print(f"[DRY] UPSERT {collection}/{doc_id}")


def print_preview(title: str, items: List[Tuple[str, str]]) -> None:
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)
    for collection, doc_id in items:
        print(f"- {collection}/{doc_id}")
    print("=" * 72 + "\n")


def safe_tags(tags: List[str]) -> List[str]:
    return [tag for tag in tags if tag in F4_ALLOWLIST]


def make_mcq(qid: str, prompt: str, choices: List[str], answer_index: int, hint: str, tags: List[str]) -> Dict[str, Any]:
    return {"id": qid, "question_id": qid, "type": "mcq", "prompt": prompt, "choices": choices, "answer_index": answer_index, "hint": hint, "feedback": [hint for _ in choices], "misconception_tags": safe_tags(tags)}


def make_short(qid: str, prompt: str, accepted_answers: List[str], hint: str, tags: List[str]) -> Dict[str, Any]:
    return {"id": qid, "question_id": qid, "type": "short", "prompt": prompt, "accepted_answers": accepted_answers, "hint": hint, "feedback": [hint], "misconception_tags": safe_tags(tags)}


def prompt_block(prompt: str, hint: str) -> Dict[str, Any]:
    return {"prompt": prompt, "hint": hint}


def formula(eq: str, meaning: str, units: List[str], conditions: str) -> Dict[str, Any]:
    return {"equation": eq, "meaning": meaning, "units": units, "conditions": conditions}


def rep(kind: str, purpose: str) -> Dict[str, Any]:
    return {"kind": kind, "purpose": purpose}


def example(prompt: str, steps: List[str], final_answer: str, why: str) -> Dict[str, Any]:
    return {"prompt": prompt, "steps": steps, "final_answer": final_answer, "why_it_matters": why}


def vis(
    asset_id: str,
    purpose: str,
    caption: str,
    *,
    template: str = "auto",
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    normalized_asset_id = asset_id[:-4] if asset_id.endswith(".svg") else asset_id
    graph_spec_map = {
        "f4-l3-resistance-iv": {
            "graph_type": "generic_xy",
            "title": "Resistance and I-V Graph Reasoning",
            "subtitle": "A steeper straight I-V line means more current per volt and therefore lower resistance.",
            "x_label": "Voltage (V)",
            "y_label": "Current (A)",
            "show_legend": True,
            "x_min": 0,
            "x_max": 8,
            "y_min": 0,
            "y_max": 4.5,
            "series": [
                {
                    "label": "Line A: lower resistance",
                    "points": [[0, 0], [2, 1.4], [4, 2.8], [6, 4.2]],
                    "color": "#38bdf8",
                },
                {
                    "label": "Line B: higher resistance",
                    "points": [[0, 0], [2, 0.8], [4, 1.6], [6, 2.4]],
                    "color": "#f97316",
                },
            ],
            "annotations": [
                {"x": 4.8, "y": 3.5, "text": "steeper = lower R", "color": "#86efac", "anchor": "start"},
            ],
        }
    }
    circuit_type_map = {
        "f4-l1-charge-current": "charge_current_loop",
        "f4-l2-potential-difference": "potential_difference",
        "f4-l3-resistance-iv": "resistance_iv",
        "f4-l4-series-circuit": "simple_series",
        "f4-l5-parallel-circuit": "parallel_lamps",
        "f4-l6-power-safety": "power_safety",
    }
    resolved_meta = dict(graph_spec_map.get(normalized_asset_id) or {})
    resolved_meta.update(dict(meta or {}))
    resolved_template = template
    if resolved_template == "auto" and normalized_asset_id in graph_spec_map:
        resolved_template = "physics_graph"
    circuit_type = circuit_type_map.get(normalized_asset_id)
    if resolved_template == "auto" and circuit_type:
        resolved_template = "electric_circuit_diagram"
    if normalized_asset_id not in graph_spec_map and circuit_type and "circuit_type" not in resolved_meta:
        resolved_meta["circuit_type"] = circuit_type
    return {
        "asset_id": normalized_asset_id,
        "purpose": purpose,
        "caption": caption,
        "template": resolved_template,
        "meta": resolved_meta,
    }


RELEASE_CHECKS = [
    "Every mastery-tested relationship is explicitly taught before mastery.",
    "Every formula is shown with meaning, units, and conditions.",
    "At least one non-text representation is used and checked.",
    "Visuals are readable on desktop and mobile.",
]

F4_MODULE_DOC, _LESSONS, _SIMS = build_nextgen_module_scaffold(
    F4_MODULE_ID,
    "Electric Circuits & Energy Flow",
    "Build on F3 by treating circuits as flow-grid systems where push, stream rate, and path difficulty explain the behavior before the formulas are introduced.",
    [
        "Charge, Current, and Closed Circuits",
        "Potential Difference and Energy per Charge",
        "Resistance and I-V Graph Reasoning",
        "Series Circuits and Shared Voltage",
        "Parallel Circuits and Branch Current",
        "Electric Power, Energy, and Safety",
    ],
    F4_ALLOWLIST,
    sequence=4,
    level="Foundation 4",
    estimated_minutes=150,
)
F4_MODULE_DOC.update({
    "content_version": F4_CONTENT_VERSION,
    "mastery_outcomes": [
        "Explain current as rate of charge flow.",
        "Use potential difference as energy transferred per unit charge.",
        "Reason with resistance and simple I-V graphs.",
        "Explain current, voltage, and resistance in series circuits.",
        "Explain current splitting and shared voltage in parallel circuits.",
        "Use circuit power and energy ideas and connect them to safety.",
    ],
    "misconception_tag_allowlist": F4_ALLOWLIST,
    "authoring_standard": "lesson_authoring_spec_v1",
    "updated_utc": utc_now(),
})
LESSON_BY_ID = {str(lesson["lesson_id"]): lesson for lesson in _LESSONS}
SIM_BY_LESSON = {str(lesson["lesson_id"]): sim for lesson, sim in zip(_LESSONS, _SIMS)}


def configure_sim(lesson_id: str, lab_id: str, title: str, description: str, instructions: List[str], outcomes: List[str], fields: List[str], depth: str) -> None:
    lesson = LESSON_BY_ID[lesson_id]
    sim = SIM_BY_LESSON[lesson_id]
    lesson["phases"]["simulation_inquiry"]["lab_id"] = lab_id
    sim.update({"lab_id": lab_id, "module_id": F4_MODULE_ID, "title": title, "description": description, "instructions": instructions, "expected_outcomes": outcomes, "telemetry_schema_hint": {"fields": fields, "sim_depth_meaning": depth}, "updated_utc": utc_now()})


def configure_lesson(lesson_id: str, analogy: str, commitment: str, micro: List[Dict[str, Any]], diagnostic: List[Dict[str, Any]], inquiry: List[Dict[str, Any]], recon: List[str], capsule_prompt: str, capsule_checks: List[Dict[str, Any]], transfer: List[Dict[str, Any]], contract: Dict[str, Any]) -> None:
    lesson = LESSON_BY_ID[lesson_id]
    lesson["updated_utc"] = utc_now()
    lesson["phases"]["diagnostic"] = {"two_tier": True, "items": diagnostic, "notes": "Use the opening check to surface the main misconception before the lesson deepens it."}
    lesson["phases"]["analogical_grounding"] = {"analogy_text": analogy, "commitment_prompt": commitment, "micro_prompts": micro}
    lesson["phases"]["simulation_inquiry"]["inquiry_prompts"] = inquiry
    lesson["phases"]["concept_reconstruction"] = {"prompts": recon, "capsules": [{"prompt": capsule_prompt, "checks": capsule_checks}]}
    lesson["phases"]["transfer"] = {"items": transfer, "notes": "Use transfer to check whether the idea survives a new context or representation."}
    contract["misconception_focus"] = safe_tags(contract["misconception_focus"])
    contract["release_checks"] = list(RELEASE_CHECKS)
    lesson["authoring_contract"] = contract
configure_sim("F4_L1", "f4_charge_current_lab", "Charge and Current Explorer", "Use the Flow-Grid loop to track packet stream rate around one closed route so current is seen as a whole-system flow, not as something a component uses up.", [
    "Change the charge moved each second and compare the current.",
    "Check the current before and after one lamp in a simple series loop.",
    "Open the loop and explain why the current drops everywhere.",
], ["charge_current_rate_confusion", "current_used_up_confusion"], ["charge_changes", "time_changes", "before_after_checks", "loop_explanations"], "number of comparisons linked to a correct current-conservation explanation")

configure_lesson(
    "F4_L1",
    "The Flow-Grid model starts with a closed city route carrying energy packets: the source station keeps pushing packets around the loop, and the stream rate past any checkpoint is the current.",
    "Predict what stays the same and what can change when the same packet stream passes different checkpoints in one closed route.",
    [prompt_block("Compare packet amount with packet stream rate.", "Charge is an amount; current is charge per second."), prompt_block("Compare the stream rate before and after one device on the same closed route.", "The lamp transfers energy but does not use current up.")],
    [
        make_mcq("F4L1_D1", "Current is best described as...", ["the rate of flow of charge", "energy per charge", "opposition to current", "stored charge"], 0, "Current tells how much charge passes a point each second.", ["charge_current_rate_confusion"]),
        make_short("F4L1_D2", "24 C pass a point in 6 s. What current is shown?", ["4 A"], "Use I = Q / t.", ["charge_current_rate_confusion"]),
        make_mcq("F4L1_D3", "In one simple series loop, the current after a lamp is...", ["the same as before the lamp", "smaller because current was used up", "zero", "larger"], 0, "The same charge flow continues around the loop.", ["current_used_up_confusion"]),
    ],
    [prompt_block("Double the charge in the same time.", "The current doubles."), prompt_block("Check current at two loop positions.", "A single path gives the same current everywhere.")],
    ["Explain the difference between charge and current.", "Explain why a lamp can transfer energy without using current up."],
    "Current is the rate of charge flow around a closed loop.",
    [make_mcq("F4L1_C1", "If 12 C pass in 3 s, the current is...", ["4 A", "9 A", "36 A", "0.25 A"], 0, "Divide charge by time.", ["charge_current_rate_confusion"])],
    [
        make_short("F4L1_T1", "15 C pass in 5 s. What current is shown?", ["3 A"], "Use I = Q / t.", ["charge_current_rate_confusion"]),
        make_short("F4L1_T2", "A current of 2 A flows for 12 s. How much charge passes?", ["24 C"], "Use Q = It.", ["charge_current_rate_confusion"]),
        make_mcq("F4L1_T3", "Why can a bulb get hot even though the current stays the same through it?", ["It transfers electrical energy while the same charge keeps flowing", "It stores current", "It creates extra charge", "It removes charge from the loop"], 0, "Energy transfer is not the same as current loss.", ["current_used_up_confusion", "cell_component_energy_flow_confusion"]),
    ],
    {
        "concept_targets": ["Treat current as a rate of charge flow.", "Use charge conservation to explain same-current reasoning in a simple loop."],
        "prerequisite_lessons": ["F3_L1", "F3_L3"],
        "misconception_focus": ["charge_current_rate_confusion", "current_used_up_confusion"],
        "formulas": [formula("I = Q / t", "Current is charge flow rate.", ["A", "C/s"], "Use when charge moved and time are known."), formula("Q = It", "Total charge moved equals current times time.", ["C"], "Use when current stays constant for the interval.")],
        "representations": [rep("words", "Separate charge amount from current rate."), rep("formula", "Link current to charge and time."), rep("diagram", "Show equal current at two points in one loop.")],
        "analogy_map": {"comparison": "A Flow-Grid loop stands for a closed circuit with one complete engineered route.", "mapping": ["Energy packets stand for moving charge carriers in the route.", "Packet stream rate past a checkpoint represents current."], "limit": "Real circuits do not contain visible packets moving like delivery tokens; the model is for current and route continuity.", "prediction_prompt": "If the source station pushes harder in the same closed route, what happens to the packet stream rate at every checkpoint?"},
        "worked_examples": [example("18 C pass in 3 s. Find the current.", ["Identify the quantity: current.", "Write I = Q / t.", "Substitute 18 and 3, then divide."], "6 A", "The answer is a rate, not a total amount."), example("A learner says a lamp uses current up. Evaluate the claim.", ["Start with the closed-loop idea.", "Separate charge flow from energy transfer.", "Conclude the current stays the same through the lamp."], "The claim is wrong.", "This prevents energy loss from being confused with current loss.")],
        "visual_assets": [vis("f4-l1-charge-current.svg", "Show current as charge per second and equal current at two loop points.", "One loop picture separates charge amount from current rate.")],
        "simulation_contract": {"baseline_case": "Start with 12 C in 4 s.", "comparison_tasks": ["Double the charge in the same time.", "Compare two points in one loop."], "watch_for": "Current changes with charge-per-second rate, not because a component uses current up.", "takeaway": "A closed single-path loop has the same current everywhere."},
        "reflection_prompts": ["Explain why charge conservation helps you reject the idea that a lamp uses current up."],
        "mastery_skills": ["Calculate current from charge and time.", "Calculate charge from current and time.", "Distinguish current from charge.", "Explain same current in a simple loop.", "Reject the current-used-up misconception."],
        "variation_plan": {"diagnostic": "Rotate numeric current items with simple loop reasoning.", "concept_gate": "Swap between current calculation and same-current explanation.", "mastery": "Use numeric, verbal, and diagram prompts without repeating diagnostic stems."},
    },
)

configure_sim("F4_L2", "f4_potential_difference_lab", "Potential Difference Explorer", "Use the Flow-Grid source station to compare how much energy each packet gains or loses, so potential difference is understood as energy transferred per charge.", [
    "Keep charge fixed and compare two potential differences.",
    "Keep potential difference fixed and change the charge moved.",
    "Compare a cell with a lamp in the same loop.",
], ["potential_difference_energy_confusion", "cell_component_energy_flow_confusion"], ["pd_changes", "charge_changes", "cell_component_checks", "energy_per_charge_explanations"], "number of comparisons linked to a correct energy-per-charge explanation")

configure_lesson(
    "F4_L2",
    "In the Flow-Grid model, the source station gives each packet an energy boost, so potential difference is the amount of energy transferred to each packet rather than the number of packets moving.",
    "Predict whether the question is about how many packets move or how much energy each packet gains or loses.",
    [prompt_block("Compare two source stations driving the same packet stream.", "More volts means more energy per coulomb."), prompt_block("Compare the role of a source station with the role of a device on the route.", "A cell gives charge electrical energy; a component transfers it away.")],
    [
        make_mcq("F4L2_D1", "Potential difference is best described as...", ["energy transferred per unit charge", "charge per second", "opposition to current", "power per second"], 0, "Potential difference compares energy transfer with charge.", ["potential_difference_energy_confusion"]),
        make_short("F4L2_D2", "24 J are transferred by 6 C. What is the potential difference?", ["4 V"], "Use V = E / Q.", ["potential_difference_energy_confusion"]),
        make_mcq("F4L2_D3", "As charge passes through a resistor, what happens?", ["The same charge passes through but transfers electrical energy", "The charge disappears", "The current stops", "The resistor creates more charge"], 0, "Charge can stay the same while electrical energy per charge drops.", ["cell_component_energy_flow_confusion"]),
    ],
    [prompt_block("Keep charge fixed and raise the potential difference.", "More energy is transferred per coulomb."), prompt_block("Keep voltage fixed and double the charge.", "Total energy transfer doubles.")],
    ["Explain why potential difference is energy per charge.", "Explain how a cell and a component play different energy roles."],
    "Potential difference tells how much energy is transferred for each coulomb.",
    [make_mcq("F4L2_C1", "If each coulomb gains 3 J, the potential difference is...", ["3 V", "3 A", "0.33 V", "cannot be found"], 0, "A volt is a joule per coulomb.", ["potential_difference_energy_confusion"])],
    [
        make_short("F4L2_T1", "15 J are transferred by 3 C. What potential difference is involved?", ["5 V"], "Use V = E / Q.", ["potential_difference_energy_confusion"]),
        make_mcq("F4L2_T2", "Two components carry the same charge. Which transfers more energy to the charges?", ["the one with greater potential difference", "the one with smaller potential difference", "they transfer the same energy", "the one with smaller current"], 0, "For the same charge, larger potential difference means larger energy transfer.", ["potential_difference_energy_confusion"]),
        make_mcq("F4L2_T3", "Why can the same charge return to the cell with less electrical energy than it left with?", ["Components transferred some of its electrical energy to other stores", "Some charge leaked out", "Potential difference and energy are unrelated", "Current always decreases after each component"], 0, "The charge can stay the same while its energy per coulomb changes.", ["cell_component_energy_flow_confusion", "current_used_up_confusion"]),
    ],
    {
        "concept_targets": ["Interpret potential difference as energy transferred per coulomb.", "Distinguish the role of a cell from the role of an energy-transfer component."],
        "prerequisite_lessons": ["F4_L1", "F3_L1"],
        "misconception_focus": ["potential_difference_energy_confusion", "cell_component_energy_flow_confusion"],
        "formulas": [formula("V = E / Q", "Potential difference is energy transferred per charge.", ["V", "J/C"], "Use when energy and charge are known."), formula("E = VQ", "Total electrical energy transfer equals volts times charge.", ["J"], "Use when charge and potential difference are known.")],
        "representations": [rep("words", "Separate charge flow from energy per charge."), rep("formula", "Link volts, joules, and coulombs."), rep("model", "Show the same charge circulating with changed electrical energy per coulomb.")],
        "analogy_map": {"comparison": "A source station giving each packet an energy boost stands for a cell giving energy to each coulomb.", "mapping": ["Packets represent moving charge.", "Energy boost per packet represents potential difference or energy per charge."], "limit": "Charges are not literally lifted upward; the model only tracks energy gain per packet.", "prediction_prompt": "If the source station gives each packet a bigger energy boost while the packet count stays the same, what changes?"},
        "worked_examples": [example("A cell transfers 12 J to 3 C. Find the potential difference.", ["Identify that the question asks for energy per charge.", "Write V = E / Q.", "Substitute 12 and 3, then divide."], "4 V", "Volts describe energy transferred for each coulomb."), example("A learner says the charge leaving a lamp must be smaller because the lamp used energy. Evaluate the claim.", ["Separate charge amount from energy per charge.", "Recall that the same charge can keep circulating.", "Conclude that energy per charge can drop without charge disappearing."], "The claim is wrong.", "This prevents charge loss from being confused with energy transfer.")],
        "visual_assets": [vis("f4-l2-potential-difference.svg", "Show a cell increasing electrical energy per coulomb and a lamp decreasing it for the same charge.", "One loop picture shows charge conservation and energy-per-charge change together.")],
        "simulation_contract": {"baseline_case": "Start with 3 C and 4 V.", "comparison_tasks": ["Keep charge fixed and compare 2 V with 6 V.", "Keep voltage fixed and compare 2 C with 5 C."], "watch_for": "Potential difference tells energy per charge; total energy also depends on charge moved.", "takeaway": "Cells and components change energy per charge, not the existence of the circulating charge."},
        "reflection_prompts": ["Explain how the same charge can circulate while its electrical energy per coulomb changes."],
        "mastery_skills": ["Calculate potential difference from energy and charge.", "Calculate energy transfer from potential difference and charge.", "Explain potential difference as energy per charge.", "Distinguish the role of a cell from that of a resistor or lamp.", "Reject the idea that charge is used up when energy is transferred."],
        "variation_plan": {"diagnostic": "Rotate V = E/Q calculations with cell-versus-component explanations.", "concept_gate": "Swap between numeric volts questions and qualitative role questions.", "mastery": "Use calculation, system explanation, and comparison prompts without repeating diagnostic stems."},
    },
)
configure_sim("F4_L3", "f4_resistance_iv_lab", "Resistance and I-V Explorer", "Vary source push and path difficulty together so the stream-rate relationship emerges before the formal current-voltage-resistance equation.", ["Keep resistance fixed and increase voltage.", "Keep voltage fixed and compare low and high resistance.", "Compare two straight I-V lines with different steepness."], ["resistance_current_relationship_confusion", "iv_graph_reasoning_confusion"], ["voltage_changes", "resistance_changes", "graph_comparisons", "ohmic_explanations"], "number of voltage-resistance comparisons linked to a correct I-V explanation")

configure_lesson(
    "F4_L3",
    "In the Flow-Grid model, resistance is path difficulty: for the same source push, a harder route with tighter gates lets fewer packets through each second.",
    "Decide whether the question is about how current changes, how resistance changes, or what the graph means.",
    [prompt_block("Keep voltage fixed and compare low resistance with high resistance.", "Greater resistance gives a smaller current."), prompt_block("Compare two straight I-V lines.", "For an ohmic component, a steeper I-V line means lower resistance.")],
    [make_short("F4L3_D1", "A resistor has 12 V across it and a current of 3 A. What is the resistance?", ["4 ohm", "4 ohms", "4 O"], "Use R = V / I.", ["resistance_current_relationship_confusion"]), make_mcq("F4L3_D2", "If resistance doubles while voltage stays the same, the current will...", ["halve", "double", "stay the same", "become zero"], 0, "At fixed voltage, current decreases when resistance increases.", ["resistance_current_relationship_confusion"]), make_mcq("F4L3_D3", "A straight current-voltage graph through the origin shows that...", ["current is proportional to voltage", "resistance disappears", "current stays fixed", "voltage depends on time only"], 0, "For an ohmic component, current rises in direct proportion to voltage.", ["iv_graph_reasoning_confusion"])],
    [prompt_block("Double the voltage at fixed resistance.", "The current doubles for an ohmic component."), prompt_block("Keep voltage fixed and compare 2 ohms with 6 ohms.", "Greater resistance gives less current.")],
    ["Explain why resistance is not the same thing as current.", "Explain how an I-V graph can show lower or higher resistance."],
    "For an ohmic component, resistance can be found from R = V / I and the I-V line is straight through the origin.",
    [make_mcq("F4L3_C1", "Which line on a straight I-V graph has the lower resistance?", ["the steeper line", "the flatter line", "both are the same", "you cannot tell"], 0, "More current per volt means lower resistance.", ["iv_graph_reasoning_confusion"])],
    [make_short("F4L3_T1", "A 6 V supply drives 3 A through a component. What resistance does it have?", ["2 ohm", "2 ohms", "2 O"], "Use R = V / I.", ["resistance_current_relationship_confusion"]), make_short("F4L3_T2", "An ohmic resistor has a resistance of 4 ohms and a potential difference of 12 V. What current flows?", ["3 A"], "Use I = V / R.", ["resistance_current_relationship_confusion"]), make_mcq("F4L3_T3", "Why does a steeper straight I-V line mean lower resistance?", ["More current flows for each volt", "The component stores more charge", "Current no longer depends on voltage", "Steeper always means more resistance"], 0, "Slope compares current gained for each extra volt.", ["iv_graph_reasoning_confusion"])],
    {"concept_targets": ["Use resistance as the relationship between voltage and current for an ohmic component.", "Interpret simple I-V graph steepness as evidence about resistance."], "prerequisite_lessons": ["F4_L1", "F4_L2", "F2_L3"], "misconception_focus": ["resistance_current_relationship_confusion", "iv_graph_reasoning_confusion"], "formulas": [formula("R = V / I", "Resistance compares how much voltage is needed for a given current.", ["ohm", "V/A"], "Use for ohmic components or when defining resistance from data."), formula("I = V / R", "For an ohmic component, current increases with voltage and decreases with resistance.", ["A"], "Use when the resistor is treated as ohmic.")], "representations": [rep("words", "Describe resistance as opposition that changes the current response."), rep("formula", "Connect voltage, current, and resistance quantitatively."), rep("graph", "Use I-V graph steepness to compare resistance visually.")], "analogy_map": {"comparison": "A harder Flow-Grid route with narrower gates stands for greater resistance reducing current.", "mapping": ["Packets per second represent current.", "Gate tightness or route difficulty represents resistance."], "limit": "Real resistance depends on material behavior, not on literal traffic jams; the model is only tracking relative difficulty.", "prediction_prompt": "If the route becomes harder but the same source push is maintained, what happens to the packet stream rate?"}, "worked_examples": [example("A resistor has 8 V across it and a current of 2 A. Find the resistance.", ["Identify the voltage-current-resistance relationship.", "Write R = V / I.", "Substitute 8 and 2, then divide."], "4 ohms", "Resistance compares volts required for each ampere."), example("Two straight I-V lines pass through the origin. Line A is steeper than line B. Which has the lower resistance?", ["Look at current per volt.", "A steeper line means more current for each volt.", "More current per volt means lower resistance."], "Line A has the lower resistance.", "This blocks the common mistake that steeper always means more resistance.")], "visual_assets": [vis("f4-l3-resistance-iv.svg", "Show two I-V lines with different steepness and label the lower-resistance line clearly.", "The graph links algebraic resistance to visual slope reasoning.")], "simulation_contract": {"baseline_case": "Start with an ohmic resistor at 6 V and 3 A.", "comparison_tasks": ["Double the voltage at fixed resistance.", "Keep voltage fixed and compare low and high resistance."], "watch_for": "On an ohmic component, current changes directly with voltage and inversely with resistance.", "takeaway": "Resistance tells how current responds to voltage; it is not a second kind of current."}, "reflection_prompts": ["Explain why a steeper straight I-V line means lower resistance."], "mastery_skills": ["Calculate resistance from voltage and current.", "Calculate current from voltage and resistance.", "Explain how resistance changes current.", "Interpret straight-line I-V graphs.", "Compare resistance using graph steepness and formula reasoning."], "variation_plan": {"diagnostic": "Mix numeric resistance calculations with current-change and graph-reading prompts.", "concept_gate": "Swap between formula use and graph interpretation.", "mastery": "Rotate algebra, graph, and qualitative reasoning without repeated stems."}},
)
configure_sim("F4_L4", "f4_series_circuit_lab", "Series Circuit Explorer", "Use a single-route Flow-Grid network so same-current reasoning, shared voltage, and added path difficulty are seen together.", ["Add a resistor in series and compare the loop current.", "Use equal and unequal resistors and compare voltage sharing.", "State what stays the same everywhere in one series loop."], ["series_circuit_rule_confusion", "potential_difference_energy_confusion"], ["component_count_changes", "current_checks", "voltage_share_checks", "series_explanations"], "number of series comparisons linked to a correct one-path explanation")

configure_lesson(
    "F4_L4",
    "A series circuit is like one hiking trail with several climbs: every hiker takes the same path, but the total climb is shared across the stages.",
    "Predict what must be the same everywhere in one single-path loop and what must be shared between components.",
    [prompt_block("Compare the current at the start, middle, and end of one series loop.", "A single path gives the same current everywhere."), prompt_block("Compare one resistor with two resistors in series.", "Adding series resistance lowers the current and shares the supply voltage.")],
    [make_mcq("F4L4_D1", "In a series circuit, the current through each component is...", ["the same", "largest near the cell", "smallest after the last component", "equal only if the components are identical"], 0, "A single path means the same current through each component.", ["series_circuit_rule_confusion"]), make_mcq("F4L4_D2", "A 12 V supply is shared by two identical lamps in series. The potential difference across each lamp is...", ["6 V", "12 V", "24 V", "3 V"], 0, "Identical series components share the supply potential difference equally.", ["series_circuit_rule_confusion", "potential_difference_energy_confusion"]), make_mcq("F4L4_D3", "If an extra resistor is added in series to the same supply, the total current will...", ["decrease", "increase", "stay the same", "become zero"], 0, "Adding series resistance lowers the current.", ["series_circuit_rule_confusion"])],
    [prompt_block("Add a second resistor in series.", "More total resistance gives less current."), prompt_block("Use equal resistors and then unequal resistors.", "The current stays common, but the voltage drops need not be equal.")],
    ["Explain why current is the same everywhere in a series circuit.", "Explain why adding components in series usually makes the current smaller."],
    "A series circuit has one current everywhere, but the supply voltage is shared across the components and the total resistance adds.",
    [make_short("F4L4_C1", "Two resistors of 2 ohms and 4 ohms are connected in series. What is the total resistance?", ["6 ohm", "6 ohms", "6 O"], "Add the resistances in series.", ["series_circuit_rule_confusion"])],
    [make_mcq("F4L4_T1", "A learner says the resistor closest to the cell gets the biggest current in a series loop. What is the best correction?", ["The same current passes through every component in one complete series route", "The first resistor always gets the largest current because it is nearest the source", "Current must fade as it moves through the loop", "The current depends only on which resistor is drawn first"], 0, "One route means one shared current everywhere in the loop.", ["series_circuit_rule_confusion"]), make_mcq("F4L4_T2", "Two unequal resistors are connected in series. Which statement must be true?", ["The current is the same in both resistors, but their potential differences can be different", "The larger resistor must carry the larger current", "Each resistor gets the full supply potential difference", "The current splits equally between the two resistors"], 0, "Series circuits keep one current even when the voltage drops differ.", ["series_circuit_rule_confusion", "potential_difference_energy_confusion"]), make_mcq("F4L4_T3", "Why are two identical lamps in series usually dimmer than one lamp on the same supply?", ["They share the supply voltage and the total current is lower", "Each lamp creates extra current", "The current doubles", "Potential difference cannot exist in series"], 0, "Series components share the supply and increased total resistance lowers current.", ["series_circuit_rule_confusion", "potential_difference_energy_confusion"]), make_mcq("F4L4_T4", "If one lamp breaks and opens the path in a series circuit, what happens to the rest of the loop?", ["The whole loop stops because the single route is broken", "Only the broken lamp goes out while the rest stay lit", "The battery increases its voltage to keep the current moving", "The current reroutes around the broken lamp"], 0, "A series circuit needs one complete route for the current to continue.", ["series_circuit_rule_confusion"])],
    {"concept_targets": ["Use the single-path model to explain same-current reasoning in series circuits.", "Explain voltage sharing and resistance addition in series circuits."], "prerequisite_lessons": ["F4_L1", "F4_L2", "F4_L3"], "misconception_focus": ["series_circuit_rule_confusion", "potential_difference_energy_confusion"], "formulas": [formula("R_total = R1 + R2 + ...", "In series, total resistance is the sum of the component resistances.", ["ohm"], "Use when components are connected end-to-end in one path."), formula("V_total = V1 + V2 + ...", "The supply voltage is shared across the series components.", ["V"], "Use when comparing the separate voltage drops in a series circuit.")], "representations": [rep("words", "Explain single-path current and shared voltage."), rep("formula", "Quantify total resistance and voltage sharing."), rep("diagram", "Show equal current labels and shared voltage drops on one path.")], "analogy_map": {"comparison": "One Flow-Grid route with several difficult sections stands for one series path with several voltage drops.", "mapping": ["Every packet taking the same route represents the same current everywhere in series.", "The total source push shared across route sections represents the supply voltage being split."], "limit": "Charges are not hikers making choices; the analogy only helps with one-route flow and shared push change.", "prediction_prompt": "If the single route adds another difficult section, what happens to the stream rate and the push share across the route?"}, "worked_examples": [example("A 12 V supply is connected to two identical lamps in series. Find the potential difference across each lamp.", ["Recognize that identical series components share the supply voltage equally.", "Take the 12 V supply and split it between the two lamps.", "Divide 12 V by 2."], "6 V across each lamp", "This links shared voltage to the one-path series model."), example("A learner says the first resistor must take most of the current because it is closest to the cell. Evaluate the claim.", ["Start with the single-path model.", "The same charge per second must pass every point on the path.", "Conclude that position does not give a resistor a larger current."], "The claim is wrong.", "This blocks route-order misconceptions about current.")], "visual_assets": [vis("f4-l4-series-circuit.svg", "Show one path with equal current labels and a shared supply voltage split across two components.", "The series picture connects current sameness with voltage sharing.")], "simulation_contract": {"baseline_case": "Start with one resistor on a 12 V supply.", "comparison_tasks": ["Add a second resistor in series.", "Use equal and unequal resistors to compare voltage sharing."], "watch_for": "Series circuits keep one common current, but total resistance rises and the supply voltage is shared.", "takeaway": "Series reasoning is one path, one current, and shared voltage drops."}, "reflection_prompts": ["Explain why current sameness and voltage sharing can both be true in the same series circuit."], "mastery_skills": ["Identify the current rule for series circuits.", "Find total resistance in series.", "Use total resistance to find current.", "Explain shared voltage in series.", "Reject route-order misconceptions about current."], "variation_plan": {"diagnostic": "Rotate between same-current, shared-voltage, and added-resistance prompts.", "concept_gate": "Swap between single-path reasoning and simple series calculations.", "mastery": "Mix numeric, verbal, and diagram items without repeating diagnostic stems."}},
)
configure_sim("F4_L5", "f4_parallel_circuit_lab", "Parallel Circuit Explorer", "Use the split-route Flow-Grid network so equal branch push, stream splitting, and recombination are seen together.", ["Add a second branch and compare the total current.", "Measure the potential difference across each branch.", "Remove one branch and explain what changes and what stays the same."], ["parallel_circuit_rule_confusion", "current_used_up_confusion"], ["branch_count_changes", "branch_current_checks", "supply_voltage_checks", "parallel_explanations"], "number of branching-circuit comparisons linked to a correct split-and-recombine explanation")

configure_lesson(
    "F4_L5",
    "A parallel circuit is the Flow-Grid split-route network: packets leave the same source points, move along different branches, and rejoin, so branch push stays the same while stream rate divides and recombines.",
    "Predict which quantity stays the same across split routes and which quantity divides or recombines.",
    [prompt_block("Compare the driving force across two branches connected to the same source station.", "Each branch spans the same two points, so each gets the same potential difference."), prompt_block("Compare the total packet stream entering a junction with the branch streams leaving it.", "The total current is the sum of the branch currents.")],
    [make_mcq("F4L5_D1", "In a parallel circuit, the potential difference across each branch is...", ["the same as the supply", "shared equally only if the branches are identical", "zero in the weaker branch", "always smaller than the supply"], 0, "Each branch connects across the same two supply points.", ["parallel_circuit_rule_confusion"]), make_short("F4L5_D2", "Two parallel branches carry 0.2 A and 0.3 A. What total current enters the junction?", ["0.5 A"], "Add the branch currents.", ["parallel_circuit_rule_confusion"]), make_mcq("F4L5_D3", "If another branch is added in parallel to the same supply, the total current drawn usually...", ["increases", "decreases", "stays the same", "becomes zero"], 0, "Adding another branch gives another path, so the total current increases.", ["parallel_circuit_rule_confusion"])],
    [prompt_block("Add a second branch.", "Total current increases even though branch voltage stays the same."), prompt_block("Choose branch currents that add neatly.", "Branch currents add to the total current when the paths rejoin.")],
    ["Explain why potential difference is the same across each parallel branch.", "Explain why total current can increase when another branch is added."],
    "In parallel, each branch gets the full supply potential difference, while the total current splits into branch currents and recombines afterward.",
    [make_mcq("F4L5_C1", "If one branch carries 0.4 A and another carries 0.6 A, the total current is...", ["1.0 A", "0.2 A", "0.6 A", "0.4 A"], 0, "Add the branch currents.", ["parallel_circuit_rule_confusion"])],
    [make_short("F4L5_T1", "A parallel circuit has branch currents of 0.4 A and 0.6 A. What total current leaves the cell?", ["1.0 A", "1 A"], "The total current is the sum of the branch currents.", ["parallel_circuit_rule_confusion"]), make_mcq("F4L5_T2", "If one lamp in a parallel pair is removed, what happens to the other lamp?", ["It can stay lit because its own branch is still complete", "It must go out because all current was used up", "It becomes brighter because the voltage disappears", "It receives zero potential difference"], 0, "Each branch can still be complete on its own.", ["parallel_circuit_rule_confusion", "current_used_up_confusion"]), make_mcq("F4L5_T3", "Why can adding another branch make a battery drain faster?", ["The total resistance falls, so the battery supplies more total current", "Potential difference across each branch becomes zero", "Current is used up faster in the first branch", "The battery creates less charge"], 0, "Another branch can reduce overall resistance and increase total current.", ["parallel_circuit_rule_confusion"])],
    {"concept_targets": ["Use shared branch voltage to explain parallel circuits.", "Use current splitting and recombination to explain total current in a parallel network."], "prerequisite_lessons": ["F4_L1", "F4_L2", "F4_L4"], "misconception_focus": ["parallel_circuit_rule_confusion", "current_used_up_confusion"], "formulas": [formula("I_total = I1 + I2 + ...", "In parallel, the total current is the sum of the branch currents.", ["A"], "Use at a junction or for a simple parallel network."), formula("V_branch = V_supply", "Each parallel branch has the same potential difference as the supply.", ["V"], "Use when the branches connect across the same two supply points.")], "representations": [rep("words", "Explain branch current splitting and equal branch voltage."), rep("formula", "Relate total current to branch currents and branch voltage to supply voltage."), rep("diagram", "Show branches leaving and rejoining the main path.")], "analogy_map": {"comparison": "A road network with branches leaving and rejoining the main route stands for a parallel circuit.", "mapping": ["Cars splitting between branches represent current splitting.", "Each branch sharing the same start and finish points represents equal branch voltage."], "limit": "Charges in circuits are not cars choosing roads; the analogy only helps with split paths and shared endpoints.", "prediction_prompt": "If a second branch opens between the same two points, what should happen to total flow and branch voltage?"}, "worked_examples": [example("Two branches carry 0.3 A and 0.5 A. Find the total current supplied by the cell.", ["Identify that the circuit is parallel.", "Write I_total = I1 + I2.", "Add 0.3 A and 0.5 A."], "0.8 A", "The total current comes from adding branch flows."), example("A learner says the branch with the larger current must also have the larger potential difference. Evaluate the claim.", ["In a simple parallel circuit each branch spans the same supply points.", "That means each branch has the same potential difference.", "Different branch currents can still happen because the resistances differ."], "The claim is wrong.", "This separates shared voltage from branch-specific current.")], "visual_assets": [vis("f4-l5-parallel-circuit.svg", "Show equal branch voltage labels and branch currents adding to the total current.", "The junction picture connects current splitting with shared branch voltage.")], "simulation_contract": {"baseline_case": "Start with one branch on a fixed supply.", "comparison_tasks": ["Add a second branch and compare total current.", "Change one branch current and check that the total current updates as the sum."], "watch_for": "Branch voltage stays tied to the supply while current splits and recombines.", "takeaway": "Parallel circuits are defined by shared branch voltage and split-recombine current."}, "reflection_prompts": ["Explain why equal branch voltage and unequal branch current can both be true in the same parallel circuit."], "mastery_skills": ["Identify the branch-voltage rule in parallel circuits.", "Add branch currents to find total current.", "Explain what changes when another branch is added.", "Reject current-used-up and branch-voltage misconceptions.", "Interpret simple branch diagrams conceptually."], "variation_plan": {"diagnostic": "Rotate shared-voltage questions, branch-current totals, and added-branch comparisons.", "concept_gate": "Swap between junction-current and branch-voltage reasoning.", "mastery": "Blend calculations, diagram interpretation, and explanation prompts without repeated stems."}},
)

configure_sim("F4_L6", "f4_power_safety_lab", "Electrical Power and Safety Explorer", "Use the Flow-Grid source station, stream rate, and safety gate together so power, total energy transfer, and protection are understood as one system story.", ["Hold voltage fixed and raise the current.", "Hold power fixed and increase the running time.", "Compare two devices and judge which needs the higher protection rating."], ["power_energy_circuit_confusion", "electrical_safety_confusion"], ["voltage_changes", "current_changes", "time_changes", "safety_explanations"], "number of power-energy comparisons linked to a correct current-safety explanation")

configure_lesson(
    "F4_L6",
    "In the Flow-Grid model, electrical power is how quickly the source station drives energized packets through the route, while a safety gate cuts the route if the packet stream grows so large that dangerous heating becomes likely.",
    "Decide whether the question is about energy transferred each second, total energy transferred over time, or why a safety gate must cut the route when the stream rate becomes too large.",
    [prompt_block("Compare two routes on the same source push but with different stream rates.", "At the same voltage, the route carrying the larger current transfers more energy each second and therefore has greater power."), prompt_block("Compare the same route running briefly and for a long time.", "Power is a rate, so total transferred energy still depends on how long that rate continues.")],
    [make_short("F4L6_D1", "A device uses 12 V and 3 A. What power does it use?", ["36 W"], "Use P = VI.", ["power_energy_circuit_confusion"]), make_short("F4L6_D2", "A 60 W lamp runs for 30 s. How much electrical energy does it transfer?", ["1800 J"], "Use E = Pt.", ["power_energy_circuit_confusion"]), make_mcq("F4L6_D3", "Why does a fuse protect a circuit?", ["It melts and breaks the circuit when the current becomes too large", "It raises the potential difference", "It stores excess charge", "It makes wires have zero resistance"], 0, "A fuse opens the circuit if the current becomes dangerously large.", ["electrical_safety_confusion"])],
    [prompt_block("Keep voltage fixed and increase current.", "Power rises because more energy is transferred each second."), prompt_block("Keep power fixed and increase the running time.", "The total transferred energy grows because the same rate acts for longer.")],
    ["Explain how P = VI and E = Pt work together in one circuit story.", "Explain why excessive current is a safety issue and how a fuse or circuit breaker responds."],
    "Electrical power is the rate of energy transfer in the Flow-Grid system, and safety devices interrupt the route when current becomes large enough to create dangerous heating in the wires.",
    [make_mcq("F4L6_C1", "Two devices are on the same supply voltage. Which one has the greater power?", ["the one with the larger current", "the one with the smaller current", "they must have the same power", "you need the resistance only"], 0, "At fixed voltage, greater current means greater power because P = VI.", ["power_energy_circuit_confusion"])],
    [make_mcq("F4L6_T1", "Two heaters run on the same voltage. Heater A draws 2 A and heater B draws 5 A. Which has the greater power?", ["heater B", "heater A", "they have the same power", "you need the running time first"], 0, "At the same voltage, the device with the larger current has the greater power.", ["power_energy_circuit_confusion"]), make_short("F4L6_T2", "A kettle uses 230 V and 10 A. What power does it use?", ["2300 W"], "Use P = VI.", ["power_energy_circuit_confusion"]), make_mcq("F4L6_T3", "Why should a circuit breaker open the circuit instead of simply allowing the current to keep rising?", ["Large currents can cause dangerous heating in wires and appliances", "Current is harmless once the voltage is fixed", "A larger current always makes a circuit more efficient", "Opening the circuit increases stored charge"], 0, "Protection devices reduce fire and shock risk by stopping excessive current.", ["electrical_safety_confusion"])],
    {"concept_targets": ["Use voltage, current, power, and time as one circuit-energy story.", "Explain electrical safety through excessive current, heating, and protective devices."], "prerequisite_lessons": ["F3_L3", "F4_L2", "F4_L3"], "misconception_focus": ["power_energy_circuit_confusion", "electrical_safety_confusion"], "formulas": [formula("P = VI", "Electrical power is the rate at which a circuit transfers energy.", ["W"], "Use when voltage and current are known."), formula("E = Pt", "Total electrical energy transferred depends on power and running time.", ["J"], "Use when the power is treated as constant over the interval."), formula("E = VIt", "Circuit energy transfer can be linked directly to voltage, current, and time together.", ["J"], "Use when one device runs at a steady voltage and current for a stated time.")], "representations": [rep("words", "Link circuit power to energy-transfer rate and connect high current to safety risk."), rep("formula", "Use P = VI, E = Pt, and E = VIt as one connected set."), rep("table", "Compare two devices by voltage, current, power, runtime, and energy transferred.")], "analogy_map": {"comparison": "A Flow-Grid source station driving energized packets through a route stands for a powered circuit transferring electrical energy.", "mapping": ["Energy transferred each second through the route represents electrical power.", "A safety gate that snaps open when the stream rate becomes too large stands for a fuse or circuit breaker."], "limit": "Real circuits do not contain literal packet gates, so the model is only tracking transfer rate, total energy over time, and protective cut-off.", "prediction_prompt": "If the same route carries the same power for longer, what happens to the total energy transferred?"}, "worked_examples": [example("A device uses 12 V and 2 A. Find its power.", ["Identify that circuit power can be found from voltage and current.", "Write P = VI.", "Substitute 12 and 2, then multiply."], "24 W", "Power is the energy-transfer rate."), example("A learner says a fuse is there to increase power when the current is large. Evaluate the claim.", ["Start with the purpose of a fuse.", "Large currents cause greater heating and danger.", "Conclude that a fuse protects by breaking the circuit, not by raising power."], "The claim is wrong.", "This ties the formula story to safety instead of leaving safety as a slogan.")], "visual_assets": [vis("f4-l6-power-safety.svg", "Show two same-voltage devices with different currents and label the higher-power case next to a fuse warning path.", "One picture connects current, power, heating, and protection.")], "simulation_contract": {"baseline_case": "Start with a 12 V route carrying 2 A for 10 s.", "comparison_tasks": ["Raise the current at the same voltage and compare power.", "Keep power fixed but run for longer and compare total transferred energy.", "Compare a safe route current with a route current above the protection threshold."], "watch_for": "Power tells how fast the Flow-Grid transfers energy, while safety depends on interrupting dangerously large current before heating becomes dangerous.", "takeaway": "A complete circuit story links energy each second, total energy over time, and the safety gate that stops excessive current."}, "reflection_prompts": ["Explain how circuit power, total energy used, and fuse action fit into one coherent story about electrical energy transfer and safety."], "mastery_skills": ["Calculate power from voltage and current.", "Calculate energy from power and time.", "Compare devices on the same supply using current and power.", "Explain fuse and insulation safety conceptually.", "Connect current, heating, and protection in one explanation."], "variation_plan": {"diagnostic": "Rotate P = VI calculations, E = Pt calculations, and safety-purpose questions.", "concept_gate": "Swap between power-rate reasoning and fuse-safety reasoning.", "mastery": "Use mixed numeric and safety-explanation prompts without repeating diagnostic stems."}},
)
F4_LESSONS: List[Tuple[str, Dict[str, Any]]] = [(str(lesson["lesson_id"]), lesson) for lesson in _LESSONS]
F4_SIM_LABS: List[Tuple[str, Dict[str, Any]]] = [(str(sim["lab_id"]), sim) for sim in _SIMS]

validate_nextgen_module(F4_MODULE_DOC, [payload for _, payload in F4_LESSONS], [payload for _, payload in F4_SIM_LABS], F4_ALLOWLIST)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module F4 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    db = init_firebase(project)
    apply = bool(args.apply)
    asset_root = args.asset_root or default_asset_root()

    lesson_pairs = [(doc_id, payload) for doc_id, payload in F4_LESSONS]
    sim_pairs = [(doc_id, payload) for doc_id, payload in F4_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    plan: List[Tuple[str, str]] = [("modules", F4_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in lesson_pairs] + [("sim_labs", doc_id) for doc_id, _ in sim_pairs]
    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    print_preview("Planned upserts", plan)

    upsert_doc(db, "modules", F4_MODULE_ID, F4_MODULE_DOC, apply)
    for doc_id, payload in lesson_pairs:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in sim_pairs:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)

    print("DONE")


if __name__ == "__main__":
    main()













