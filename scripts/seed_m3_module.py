from __future__ import annotations

import argparse
import json
from copy import deepcopy
from typing import List, Tuple

try:
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_builder import build_nextgen_module_bundle
except ModuleNotFoundError:
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_builder import build_nextgen_module_bundle

try:
    from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
except ModuleNotFoundError:
    from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc


M3_MODULE_ID = "M3"
M3_CONTENT_VERSION = "20260317_m3_energy_circuits_v1"
M3_ALLOWLIST = [
    "work_energy_transfer_confusion",
    "kinetic_energy_relationship_error",
    "gravitational_potential_energy_error",
    "power_rate_confusion",
    "efficiency_calculation_error",
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


M3_SPEC = {
    "module_description": "Module 3 uses Energy Ledger and Flow-Grid to connect work, stores, power, current, voltage, resistance, and safety as one transfer story.",
    "mastery_outcomes": [
        "Explain work as energy transferred only when force causes motion in the force direction.",
        "Compare kinetic and gravitational potential energy with efficiency in one store-and-transfer model.",
        "Use power as transfer rate and keep it separate from efficiency.",
        "Explain current as charge per second and potential difference as energy per charge.",
        "Use resistance and network rules to predict current in series and parallel circuits.",
        "Connect electrical power, total energy transfer, and protection in one safety explanation.",
    ],
    "lessons": [],
}

M3_SPEC["lessons"].extend(
    [
        {
            "id": "M3_L1",
            "title": "Work and Energy Transfer",
            "sim": {
                "lab_id": "m3_work_transfer_lab",
                "title": "Energy Ledger explorer",
                "description": "Compare moving and non-moving force stories.",
                "instructions": ["Keep the force and change the motion.", "Change the distance moved.", "Reverse the motion direction."],
                "outcomes": ["work_energy_transfer_confusion"],
                "fields": ["force", "distance", "direction", "transfer_explanation"],
                "depth": "number of force-motion comparisons explained correctly",
            },
            "analogy_text": "Energy Ledger records work only when force causes motion in the force direction.",
            "commitment_prompt": "Decide whether the story has force only, motion only, or force causing motion.",
            "micro_prompts": [
                {"prompt": "Compare a moving crate with a rigid wall.", "hint": "The force can exist in both stories, but the transfer changes."},
                {"prompt": "Compare 1 m and 4 m under the same force.", "hint": "More distance in the force direction means more work."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L1_D1", "prompt": "Work is done when...", "choices": ["a force causes movement in the force direction", "a force feels difficult", "an object is heavy", "time passes"], "answer_index": 0, "hint": "Work links force with displacement.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_D2", "prompt": "A wall does not move while pushed. What work is done on it?", "choices": ["0 J", "non-zero because the force exists", "equal to the push size", "cannot be known"], "answer_index": 0, "hint": "No displacement means no work on the wall.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "short", "id": "M3L1_D3", "prompt": "A 5 N force moves a box 2 m in the same direction. What work is done?", "accepted_answers": ["10 J", "10"], "hint": "Use W = Fd.", "tags": ["work_energy_transfer_confusion"]},
            ],
            "inquiry": [
                {"prompt": "Hold force fixed and vary displacement.", "hint": "Watch how transfer scales with distance."},
                {"prompt": "Keep the push but remove the motion.", "hint": "The transfer story changes immediately."},
            ],
            "recon_prompts": ["Explain why force alone does not guarantee work.", "Explain why work is an energy-transfer story."],
            "capsule_prompt": "Check for force causing displacement before you calculate work.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L1_C1", "prompt": "If distance doubles at the same force, work is...", "choices": ["twice as large", "half as large", "unchanged", "zero"], "answer_index": 0, "hint": "Work scales with distance for a fixed force.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_C2", "prompt": "1 J of work means...", "choices": ["1 J of energy is transferred", "1 N of force exists", "1 s has passed", "1 kg is moving"], "answer_index": 0, "hint": "Work is measured in joules because it is energy transferred.", "tags": ["work_energy_transfer_confusion"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L1_T1", "prompt": "A 12 N force moves an object 3 m in the same direction. What work is done?", "accepted_answers": ["36 J", "36"], "hint": "Multiply force by distance in the force direction.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_T2", "prompt": "Why is no work done on a held-still book?", "choices": ["the book does not move through a distance", "gravity disappears", "the book has no energy", "time is too short"], "answer_index": 0, "hint": "Holding force exists, but the displacement is zero.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_T3", "prompt": "What most directly increases work for the same force?", "choices": ["more displacement", "more time only", "more mass only", "a brighter color"], "answer_index": 0, "hint": "Work grows with distance when the force stays the same.", "tags": ["work_energy_transfer_confusion"]},
            ],
            "contract": {
                "concept_targets": ["Treat work as energy transferred by force through displacement.", "Separate force presence from transfer."],
                "prerequisite_lessons": ["F3_L1", "M2_L1"],
                "misconception_focus": ["work_energy_transfer_confusion"],
                "formulas": [
                    {"equation": "W = Fd", "meaning": "Work done equals force times displacement in the force direction.", "units": ["J"], "conditions": "Use when force and displacement are aligned."},
                    {"equation": "1 J = 1 N m", "meaning": "A joule is the work done by 1 N through 1 m.", "units": ["J"], "conditions": "Use when interpreting units."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain why work requires both force and displacement."},
                    {"kind": "diagram", "purpose": "Show force and displacement on the same object."},
                    {"kind": "formula", "purpose": "Quantify transferred energy."},
                ],
                "analogy_map": {"comparison": "Energy Ledger stands for recorded transfer by force through motion.", "mapping": ["Force is the push acting now.", "Ledger tokens appear only when that push causes motion."], "limit": "Real energy transfer is not a visible token drop.", "prediction_prompt": "If the push stays but the object does not move, what should happen to the ledger?"},
                "worked_examples": [
                    {"prompt": "A 4 N force moves a box 5 m. Find the work done.", "steps": ["Identify force and displacement.", "Use W = Fd.", "Multiply 4 by 5."], "final_answer": "20 J", "why_it_matters": "This anchors work to force causing motion."},
                    {"prompt": "A learner says holding a suitcase still does work on it because the force feels hard. Evaluate the claim.", "steps": ["Check whether the suitcase moves.", "Notice the displacement is zero.", "Conclude no work is transferred to the suitcase."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks effort-only reasoning."},
                ],
                "visual_assets": [{"asset_id": "m3-l1-energy-transfer", "concept": "energy_transfer", "phase_key": "analogical_grounding", "title": "Work transfers energy", "purpose": "Contrast a moving crate with a rigid wall.", "caption": "Force plus displacement transfers energy."}],
                "animation_assets": [{"asset_id": "m3-l1-energy-transfer-anim", "concept": "energy_transfer", "phase_key": "analogical_grounding", "title": "Energy transfer in motion", "description": "Animate a moving and a non-moving force case.", "duration_sec": 8}],
                "simulation_contract": {"asset_id": "m3_l1_energy_transfer_lab", "concept": "energy_transfer", "baseline_case": "Start with a 5 N push moving a crate 2 m.", "comparison_tasks": ["Keep the force but remove the motion.", "Double the distance under the same force."], "watch_for": "Students should say transfer only happens when force causes displacement.", "takeaway": "Work is transferred energy, not effort by itself."},
                "reflection_prompts": ["Explain why a force can exist without doing work on the object."],
                "mastery_skills": ["Identify when work is done.", "Calculate work from force and distance.", "Interpret joules as transferred energy.", "Reject no-motion work misconceptions.", "Explain work qualitatively."],
                "variation_plan": {"diagnostic": "Rotate moving-object, no-motion, and doubled-distance stories.", "concept_gate": "Swap between explanation prompts and direct work calculations.", "mastery": "Change the force, distance, and context while keeping the same structure."},
            },
        },
        {
            "id": "M3_L2",
            "title": "Energy Stores and Efficiency",
            "sim": {
                "lab_id": "m3_energy_store_lab",
                "title": "Energy store explorer",
                "description": "Track motion energy, height energy, and useful output.",
                "instructions": ["Raise and lower the same object.", "Double the speed and compare the motion-energy change.", "Compare useful and wasted output from the same input."],
                "outcomes": ["kinetic_energy_relationship_error", "gravitational_potential_energy_error", "efficiency_calculation_error"],
                "fields": ["mass", "speed", "height", "useful_fraction"],
                "depth": "number of store and efficiency comparisons explained with the right relationship",
            },
            "analogy_text": "Energy Ledger can store tokens in a motion vault or a height shelf. Efficiency asks how much of the input reaches the useful output lane.",
            "commitment_prompt": "Decide whether the question is about a store, a change in a store, or useful fraction.",
            "micro_prompts": [
                {"prompt": "Compare doubling mass with doubling speed for motion energy.", "hint": "Speed has the stronger effect because it is squared."},
                {"prompt": "Compare useful output with total input energy.", "hint": "Efficiency is a fraction of the full input."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L2_D1", "prompt": "Which change gives the largest increase in kinetic energy for the same object?", "choices": ["doubling the speed", "doubling the height", "doubling the time", "doubling the paint"], "answer_index": 0, "hint": "Kinetic energy depends strongly on speed because speed is squared.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "mcq", "id": "M3L2_D2", "prompt": "Gravitational potential energy increases most directly when...", "choices": ["height increases", "current increases", "speed doubles", "resistance falls"], "answer_index": 0, "hint": "Height above the reference level matters.", "tags": ["gravitational_potential_energy_error"]},
                {"kind": "short", "id": "M3L2_D3", "prompt": "A machine takes in 200 J and delivers 150 J usefully. What is its efficiency?", "accepted_answers": ["75%", "0.75"], "hint": "Efficiency = useful output / total input.", "tags": ["efficiency_calculation_error"]},
            ],
            "inquiry": [
                {"prompt": "Hold mass fixed and vary speed.", "hint": "The motion store grows very quickly with speed."},
                {"prompt": "Keep input energy fixed and change the useful fraction.", "hint": "Efficiency compares useful output with the whole input."},
            ],
            "recon_prompts": ["Explain why doubling speed changes kinetic energy more strongly than doubling mass.", "Explain why efficiency is about useful fraction rather than disappearing energy."],
            "capsule_prompt": "Name the store first, then use the right relationship, then compare useful output with total input.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L2_C1", "prompt": "If speed doubles for the same mass, kinetic energy becomes...", "choices": ["four times as large", "twice as large", "half as large", "unchanged"], "answer_index": 0, "hint": "The squared speed term makes the increase stronger.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "mcq", "id": "M3L2_C2", "prompt": "An efficiency of 60% means...", "choices": ["60% of the input becomes useful output", "40% of the input vanishes", "60 J always leaves the machine", "the machine stores no energy"], "answer_index": 0, "hint": "Efficiency compares useful output with total input.", "tags": ["efficiency_calculation_error"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L2_T1", "prompt": "A 2 kg trolley moves at 4 m/s. What kinetic energy does it have?", "accepted_answers": ["16 J", "16"], "hint": "Use KE = 0.5mv^2.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "short", "id": "M3L2_T2", "prompt": "A 5 kg object is raised 6 m with g = 10 N/kg. What gravitational potential energy gain occurs?", "accepted_answers": ["300 J", "300"], "hint": "Use GPE = mgh.", "tags": ["gravitational_potential_energy_error"]},
                {"kind": "mcq", "id": "M3L2_T3", "prompt": "A device is more efficient than another if it...", "choices": ["delivers a larger useful fraction of the same input", "always uses more total energy", "always runs faster", "never warms up"], "answer_index": 0, "hint": "Efficiency is about useful fraction.", "tags": ["efficiency_calculation_error"]},
            ],
            "contract": {
                "concept_targets": ["Compare kinetic and gravitational potential energy through their variables.", "Use efficiency as a useful-output fraction."],
                "prerequisite_lessons": ["F3_L2", "F3_L3", "M3_L1"],
                "misconception_focus": ["kinetic_energy_relationship_error", "gravitational_potential_energy_error", "efficiency_calculation_error"],
                "formulas": [
                    {"equation": "KE = 0.5mv^2", "meaning": "Kinetic energy depends on mass and especially on speed.", "units": ["J"], "conditions": "Use for motion-energy calculations."},
                    {"equation": "GPE = mgh", "meaning": "Gravitational potential energy depends on mass, field strength, and height.", "units": ["J"], "conditions": "Use near Earth's surface for height changes."},
                    {"equation": "efficiency = useful output / total input", "meaning": "Efficiency compares the useful part with the full input.", "units": ["fraction", "%"], "conditions": "Use when useful and total energy or power are known."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Compare stores and useful output in a system story."},
                    {"kind": "diagram", "purpose": "Show energy moving between stores and useful versus wasted outputs."},
                    {"kind": "formula", "purpose": "Quantify KE, GPE, and efficiency."},
                ],
                "analogy_map": {"comparison": "Energy Ledger stores stand for named energy stores, while the useful-output lane stands for the target share of the input.", "mapping": ["The motion vault stands for kinetic energy.", "The height shelf stands for gravitational potential energy.", "The useful-output lane stands for efficiency as a fraction of input."], "limit": "Real systems do not move literal tokens between labeled shelves.", "prediction_prompt": "If speed doubles while mass stays fixed, which store changes most strongly and why?"},
                "worked_examples": [
                    {"prompt": "A 3 kg cart moves at 2 m/s. Find its kinetic energy.", "steps": ["Use KE = 0.5mv^2.", "Square the speed first.", "Multiply 0.5 x 3 x 4."], "final_answer": "6 J", "why_it_matters": "Students must respect the squared-speed relationship."},
                    {"prompt": "A machine takes in 500 J and gives 350 J usefully. Find the efficiency.", "steps": ["Write efficiency = useful / total.", "Substitute 350 / 500.", "Convert to a percentage if needed."], "final_answer": "70%", "why_it_matters": "This separates useful fraction from total size."},
                ],
                "visual_assets": [{"asset_id": "m3-l2-energy-stores", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Compare energy stores", "purpose": "Show motion energy, height energy, and useful-output comparison in one ledger view.", "caption": "Store type and useful fraction must stay separate."}],
                "animation_assets": [{"asset_id": "m3-l2-energy-stores-anim", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Energy store shift", "description": "Animate the change between motion energy and height energy.", "duration_sec": 8}],
                "simulation_contract": {"asset_id": "m3_l2_energy_store_lab", "concept": "energy_stores", "baseline_case": "Start with one object at low speed and low height.", "comparison_tasks": ["Double the speed for the same mass.", "Keep input fixed and compare useful outputs."], "watch_for": "Students should say speed is squared in kinetic energy and efficiency is useful over total.", "takeaway": "Store type, variable dependence, and useful fraction are different ideas."},
                "reflection_prompts": ["Explain why speed often changes kinetic energy more dramatically than mass does."],
                "mastery_skills": ["Calculate kinetic energy.", "Calculate gravitational potential energy.", "Calculate efficiency.", "Compare store changes qualitatively.", "Reject efficiency misconceptions."],
                "variation_plan": {"diagnostic": "Rotate store-identification, squared-speed, and useful-fraction prompts.", "concept_gate": "Swap between kinetic-energy comparisons and efficiency explanations.", "mastery": "Vary mass, speed, height, and useful-output contexts without repeating the same stem."},
            },
        },
    ]
)

M3_SPEC["lessons"].extend(
    [
        {
            "id": "M3_L3",
            "title": "Power and Rate Stories",
            "sim": {
                "lab_id": "m3_power_rate_lab",
                "title": "Rate meter explorer",
                "description": "Compare the same energy transfer across different times.",
                "instructions": ["Keep energy fixed and change the time.", "Keep time fixed and change the energy transferred.", "Compare two machines with the same useful output but different total rates."],
                "outcomes": ["power_rate_confusion", "efficiency_calculation_error"],
                "fields": ["energy_input", "time_taken", "power_output", "efficiency_notes"],
                "depth": "number of rate comparisons explained correctly through energy-per-second reasoning",
            },
            "analogy_text": "The Rate Meter on Energy Ledger shows how many energy tokens are transferred each second. Power is transfer speed, while efficiency still asks what fraction of the input was useful.",
            "commitment_prompt": "Decide whether the question is about total energy, rate of transfer, or useful fraction.",
            "micro_prompts": [
                {"prompt": "Compare the same 600 J transferred in 10 s and in 20 s.", "hint": "The total is the same, but the rate is different."},
                {"prompt": "Compare a powerful device with an efficient device.", "hint": "A device can transfer energy quickly without being especially efficient."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L3_D1", "prompt": "Power tells you...", "choices": ["energy transferred each second", "total energy transferred only", "the useful fraction only", "the charge moved"], "answer_index": 0, "hint": "Power is a rate of transfer.", "tags": ["power_rate_confusion"]},
                {"kind": "short", "id": "M3L3_D2", "prompt": "A motor transfers 240 J in 12 s. What power does it have?", "accepted_answers": ["20 W", "20"], "hint": "Use power = energy / time.", "tags": ["power_rate_confusion"]},
                {"kind": "mcq", "id": "M3L3_D3", "prompt": "Two machines transfer the same total energy, but one does it in less time. Which is more powerful?", "choices": ["the faster one", "the slower one", "they have the same power", "the one with more mass"], "answer_index": 0, "hint": "Same energy in less time means a greater rate.", "tags": ["power_rate_confusion"]},
            ],
            "inquiry": [
                {"prompt": "Keep the total energy the same and change only the time.", "hint": "The rate meter changes even when the total stays fixed."},
                {"prompt": "Compare useful output fraction with transfer speed.", "hint": "Power and efficiency answer different questions."},
            ],
            "recon_prompts": ["Explain why high power does not automatically mean high efficiency.", "Explain why the same energy transfer can correspond to different powers."],
            "capsule_prompt": "Power is energy per second; efficiency is useful fraction.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L3_C1", "prompt": "If the same energy is transferred in half the time, the power is...", "choices": ["twice as large", "half as large", "unchanged", "zero"], "answer_index": 0, "hint": "Less time for the same energy means a greater rate.", "tags": ["power_rate_confusion"]},
                {"kind": "mcq", "id": "M3L3_C2", "prompt": "Which statement best compares power and efficiency?", "choices": ["Power is rate; efficiency is useful fraction", "Power and efficiency are the same quantity", "Efficiency is energy per second", "Power only matters in electrical circuits"], "answer_index": 0, "hint": "They describe different aspects of a process.", "tags": ["power_rate_confusion", "efficiency_calculation_error"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L3_T1", "prompt": "A kettle transfers 1800 J in 30 s. What power does it use?", "accepted_answers": ["60 W", "60"], "hint": "Use P = E / t.", "tags": ["power_rate_confusion"]},
                {"kind": "short", "id": "M3L3_T2", "prompt": "A machine runs at 50 W for 8 s. How much energy does it transfer?", "accepted_answers": ["400 J", "400"], "hint": "Use E = Pt.", "tags": ["power_rate_confusion"]},
                {"kind": "mcq", "id": "M3L3_T3", "prompt": "A device transfers energy quickly but wastes a large share. Which statement fits?", "choices": ["it has high power but low efficiency", "it has low power and high efficiency", "it has no power", "it has no energy transfer"], "answer_index": 0, "hint": "Rate and useful fraction are separate ideas.", "tags": ["power_rate_confusion", "efficiency_calculation_error"]},
            ],
            "contract": {
                "concept_targets": ["Use power as energy-transfer rate.", "Separate power from efficiency in one process story."],
                "prerequisite_lessons": ["F3_L3", "M3_L2"],
                "misconception_focus": ["power_rate_confusion", "efficiency_calculation_error"],
                "formulas": [
                    {"equation": "P = E / t", "meaning": "Power is the rate of energy transfer.", "units": ["W", "J/s"], "conditions": "Use when total energy transferred and time are known."},
                    {"equation": "E = Pt", "meaning": "Total energy transferred equals power multiplied by time.", "units": ["J"], "conditions": "Use when power is constant over the interval."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain rate versus useful fraction."},
                    {"kind": "table", "purpose": "Compare energy, time, power, and efficiency across devices."},
                    {"kind": "formula", "purpose": "Calculate power or energy from the same relationship."},
                ],
                "analogy_map": {"comparison": "The Rate Meter stands for power as energy transferred each second.", "mapping": ["A faster ticking meter means a larger power.", "The efficiency slider still compares useful output with total input."], "limit": "The meter is not a real object inside the system.", "prediction_prompt": "If two devices transfer the same energy but one does it faster, what changes?"},
                "worked_examples": [
                    {"prompt": "A heater transfers 900 J in 15 s. Find the power.", "steps": ["Write P = E / t.", "Substitute 900 and 15.", "Divide to find the rate."], "final_answer": "60 W", "why_it_matters": "This keeps power tied to rate."},
                    {"prompt": "A learner says the more efficient machine must always be more powerful. Evaluate the claim.", "steps": ["Separate rate from useful fraction.", "Notice that efficiency does not say how much energy is transferred each second.", "Conclude that one can be larger without the other."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks power-efficiency collapse."},
                ],
                "visual_assets": [{"asset_id": "m3-l3-power-rate", "concept": "power_rate", "phase_key": "analogical_grounding", "title": "Rate versus usefulness", "purpose": "Compare two transfer stories with different rates and useful fractions.", "caption": "Power and efficiency must stay separate."}],
                "animation_assets": [{"asset_id": "m3-l3-power-rate-anim", "concept": "power_rate", "phase_key": "analogical_grounding", "title": "Rate meter comparison", "description": "Animate the same energy transfer over different times.", "duration_sec": 8}],
                "simulation_contract": {"asset_id": "m3_l3_power_rate_lab", "concept": "power_rate", "baseline_case": "Start with 600 J transferred in 20 s.", "comparison_tasks": ["Keep energy fixed and shorten the time.", "Keep time fixed and raise useful output."], "watch_for": "Students should keep power and efficiency as separate comparisons.", "takeaway": "Power tells how fast energy is transferred; efficiency tells how much is useful."},
                "reflection_prompts": ["Explain how a machine can be powerful without being very efficient."],
                "mastery_skills": ["Calculate power.", "Calculate energy from power and time.", "Compare rates qualitatively.", "Separate rate from useful fraction.", "Interpret watts as joules per second."],
                "variation_plan": {"diagnostic": "Rotate between rate definitions, P = E / t, and same-energy-different-time comparisons.", "concept_gate": "Swap between numerical power and conceptual efficiency-versus-power items.", "mastery": "Blend calculations and explanation prompts across new device stories."},
            },
        },
        {
            "id": "M3_L4",
            "title": "Current and Potential Difference",
            "sim": {
                "lab_id": "m3_flow_grid_lab",
                "title": "Flow-Grid explorer",
                "description": "Track charge packets and energy per packet in one closed-loop story.",
                "instructions": ["Compare current at different checkpoints.", "Raise the energy boost per packet.", "Compare the source station with a lamp on the same route."],
                "outcomes": ["charge_current_rate_confusion", "current_used_up_confusion", "potential_difference_energy_confusion", "cell_component_energy_flow_confusion"],
                "fields": ["charge_per_second", "energy_per_charge", "loop_continuity", "component_energy_notes"],
                "depth": "number of loop comparisons explained correctly through current and voltage reasoning",
            },
            "analogy_text": "Flow-Grid uses a closed route of moving charge packets. Current is the packet stream rate; potential difference is the energy boost or drop for each packet.",
            "commitment_prompt": "Decide first whether the question is about charge per second or energy per charge.",
            "micro_prompts": [
                {"prompt": "Compare charge amount with charge flow rate.", "hint": "Current is charge per second, not total charge."},
                {"prompt": "Compare current with potential difference.", "hint": "Current tells flow rate; potential difference tells energy per charge."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L4_D1", "prompt": "Current is best described as...", "choices": ["charge passing a point each second", "energy transferred per charge", "difficulty of the route", "total charge stored"], "answer_index": 0, "hint": "Current is a rate of charge flow.", "tags": ["charge_current_rate_confusion"]},
                {"kind": "mcq", "id": "M3L4_D2", "prompt": "Why can a lamp transfer energy without using current up?", "choices": ["the same charge keeps flowing while its energy per charge changes", "the lamp creates extra charge", "current disappears after the lamp", "only the cell carries current"], "answer_index": 0, "hint": "Charge can keep circulating while energy is transferred.", "tags": ["current_used_up_confusion", "cell_component_energy_flow_confusion"]},
                {"kind": "short", "id": "M3L4_D3", "prompt": "18 C pass a point in 3 s. What current flows?", "accepted_answers": ["6 A", "6"], "hint": "Use I = Q / t.", "tags": ["charge_current_rate_confusion"]},
            ],
            "inquiry": [
                {"prompt": "Track the same loop current before and after one device.", "hint": "The closed route keeps the same current through one path."},
                {"prompt": "Raise the source energy boost while keeping the packet stream comparison in mind.", "hint": "Voltage changes energy per charge, not charge count by itself."},
            ],
            "recon_prompts": ["Explain why current is not used up by one component in a closed loop.", "Explain how voltage differs from current in the Flow-Grid story."],
            "capsule_prompt": "Current is charge per second. Potential difference is energy per charge.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L4_C1", "prompt": "If each coulomb gains 4 J from a source, the potential difference is...", "choices": ["4 V", "4 A", "0.25 V", "cannot be found"], "answer_index": 0, "hint": "A volt is a joule per coulomb.", "tags": ["potential_difference_energy_confusion"]},
                {"kind": "mcq", "id": "M3L4_C2", "prompt": "In one complete loop with no branches, the current at two different checkpoints is...", "choices": ["the same", "always larger near the cell", "used up after the lamp", "unrelated"], "answer_index": 0, "hint": "One path means one common current.", "tags": ["charge_current_rate_confusion", "current_used_up_confusion"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L4_T1", "prompt": "24 J are transferred to 6 C. What potential difference is involved?", "accepted_answers": ["4 V", "4"], "hint": "Use V = E / Q.", "tags": ["potential_difference_energy_confusion"]},
                {"kind": "mcq", "id": "M3L4_T2", "prompt": "What changes if each charge packet gets a larger energy boost but the packet stream stays the same?", "choices": ["potential difference", "current only", "resistance only", "charge amount only"], "answer_index": 0, "hint": "More energy per charge means higher potential difference.", "tags": ["potential_difference_energy_confusion"]},
                {"kind": "mcq", "id": "M3L4_T3", "prompt": "Which statement best corrects 'the lamp uses current up'?", "choices": ["the lamp transfers energy while the same charge keeps flowing", "the lamp stores the current permanently", "current turns directly into voltage", "the cell receives no returning charge"], "answer_index": 0, "hint": "Separate charge flow from energy transfer.", "tags": ["current_used_up_confusion", "cell_component_energy_flow_confusion"]},
            ],
            "contract": {
                "concept_targets": ["Use current as charge-flow rate.", "Use potential difference as energy transferred per charge."],
                "prerequisite_lessons": ["F4_L1", "F4_L2", "M3_L3"],
                "misconception_focus": ["charge_current_rate_confusion", "current_used_up_confusion", "potential_difference_energy_confusion", "cell_component_energy_flow_confusion"],
                "formulas": [
                    {"equation": "I = Q / t", "meaning": "Current is charge passing a point per second.", "units": ["A", "C/s"], "conditions": "Use for a stated charge flow in a given time."},
                    {"equation": "V = E / Q", "meaning": "Potential difference is the energy transferred to each coulomb.", "units": ["V", "J/C"], "conditions": "Use when energy transfer and charge are known."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Tell the loop-flow and energy-per-charge story clearly."},
                    {"kind": "diagram", "purpose": "Show one complete loop with checkpoints and source/component roles."},
                    {"kind": "formula", "purpose": "Calculate current or potential difference."},
                ],
                "analogy_map": {"comparison": "Flow-Grid maps current to packet stream rate and voltage to energy boost per packet.", "mapping": ["Packets represent moving charge.", "Packet stream rate represents current.", "Energy boost per packet represents potential difference."], "limit": "Charges are not visible packets and sources are not literal booster stations.", "prediction_prompt": "If the packet stream stays the same but each packet gets more energy, what changes?"},
                "worked_examples": [
                    {"prompt": "12 C pass a point in 4 s. Find the current.", "steps": ["Use current = charge / time.", "Substitute 12 and 4.", "Divide to get the rate."], "final_answer": "3 A", "why_it_matters": "This keeps current tied to charge-flow rate."},
                    {"prompt": "A learner says a resistor uses current up because the lamp gets hot. Evaluate the claim.", "steps": ["Separate charge flow from energy transfer.", "Notice that the same loop current can continue through the component.", "Conclude that the resistor transfers energy without destroying current."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks a central circuit misconception."},
                ],
                "visual_assets": [{"asset_id": "m3-l4-current-flow", "concept": "current_flow", "phase_key": "analogical_grounding", "title": "Current versus voltage", "purpose": "Show a closed loop with packet stream rate and energy boost per packet labeled separately.", "caption": "Current and potential difference answer different questions."}],
                "animation_assets": [{"asset_id": "m3-l4-current-flow-anim", "concept": "current_flow", "phase_key": "analogical_grounding", "title": "Closed-loop flow", "description": "Animate charge flow and energy-per-charge change around a loop.", "duration_sec": 8}],
                "simulation_contract": {"asset_id": "m3_l4_flow_grid_lab", "concept": "current_flow", "baseline_case": "Start with one complete loop carrying a steady packet stream.", "comparison_tasks": ["Compare two checkpoints in the same loop.", "Increase the energy boost per packet at the source."], "watch_for": "Students should say current is flow rate and voltage is energy per charge.", "takeaway": "Current and potential difference must stay separate in a circuit explanation."},
                "reflection_prompts": ["Explain why current staying the same around one loop does not mean nothing changes at a component."],
                "mastery_skills": ["Calculate current.", "Calculate potential difference.", "Explain current-used-up misconceptions.", "Separate current and voltage.", "Describe source and component roles."],
                "variation_plan": {"diagnostic": "Rotate current-definition, voltage-definition, and current-used-up prompts.", "concept_gate": "Swap between I = Q / t and V = E / Q questions.", "mastery": "Vary charge values, time values, and circuit stories without reusing the same wording."},
            },
        },
    ]
)

M3_SPEC["lessons"].extend(
    [
        {
            "id": "M3_L5",
            "title": "Resistance and Network Rules",
            "sim": {
                "lab_id": "m3_network_rules_lab",
                "title": "Network rules explorer",
                "description": "Compare one-loop and branched circuits while changing route difficulty.",
                "instructions": ["Increase resistance in one loop and compare the current.", "Compare current at two checkpoints in the same series loop.", "Open a second branch and compare branch current with total current."],
                "outcomes": ["resistance_current_relationship_confusion", "iv_graph_reasoning_confusion", "series_circuit_rule_confusion", "parallel_circuit_rule_confusion"],
                "fields": ["supply_voltage", "route_resistance", "branch_state", "current_reasoning"],
                "depth": "number of resistance and network comparisons explained through current and voltage structure",
            },
            "analogy_text": "Flow-Grid route width stands for resistance. A narrower route makes the same energy boost drive a smaller charge stream. In one loop the same stream passes each checkpoint, while branches split and rejoin the stream.",
            "commitment_prompt": "Decide whether the question is about route difficulty, one-loop current, or branch splitting.",
            "micro_prompts": [
                {"prompt": "Compare the same source with a wide route and a narrow route.", "hint": "Higher resistance means a smaller current for the same potential difference."},
                {"prompt": "Compare one loop with a branched loop.", "hint": "Series current stays common in one path, but branch currents split in parallel."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L5_D1", "prompt": "If the same voltage acts across a larger resistance, the current is...", "choices": ["smaller", "larger", "unchanged", "always zero"], "answer_index": 0, "hint": "Ohm's law links a larger resistance to a smaller current when voltage stays fixed.", "tags": ["resistance_current_relationship_confusion"]},
                {"kind": "mcq", "id": "M3L5_D2", "prompt": "In a one-loop series circuit, the current at two different checkpoints is...", "choices": ["the same", "always larger near the cell", "smaller after each component", "unpredictable"], "answer_index": 0, "hint": "One complete path means one common current.", "tags": ["series_circuit_rule_confusion"]},
                {"kind": "short", "id": "M3L5_D3", "prompt": "A resistor has 6 V across it and 2 A through it. What is its resistance?", "accepted_answers": ["3 ohm", "3 ohms", "3"], "hint": "Use R = V / I.", "tags": ["resistance_current_relationship_confusion", "iv_graph_reasoning_confusion"]},
            ],
            "inquiry": [
                {"prompt": "Hold the source fixed and increase one resistor.", "hint": "Watch the current shrink as route difficulty rises."},
                {"prompt": "Open a second branch and compare branch current with total current.", "hint": "Branch currents add back to the total current."},
            ],
            "recon_prompts": ["Explain why resistance changes current without meaning that current is used up.", "Explain how series and parallel network rules describe different route structures."],
            "capsule_prompt": "Use route difficulty for resistance, common stream for series, and split streams for parallel.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L5_C1", "prompt": "When resistance doubles at the same voltage, the current becomes...", "choices": ["half as large", "twice as large", "unchanged", "four times as large"], "answer_index": 0, "hint": "For a fixed voltage, current changes inversely with resistance.", "tags": ["resistance_current_relationship_confusion"]},
                {"kind": "mcq", "id": "M3L5_C2", "prompt": "Which statement best fits a parallel circuit?", "choices": ["branch currents split and rejoin while the potential difference across each branch can match the source", "current is always the same in every branch and nowhere else", "resistance disappears when branches are added", "only one path can carry current"], "answer_index": 0, "hint": "Parallel means multiple paths across the same source.", "tags": ["parallel_circuit_rule_confusion", "series_circuit_rule_confusion"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L5_T1", "prompt": "A 12 V source drives a 4 ohm resistor. What current flows?", "accepted_answers": ["3 A", "3"], "hint": "Use I = V / R.", "tags": ["resistance_current_relationship_confusion"]},
                {"kind": "mcq", "id": "M3L5_T2", "prompt": "Why does a steeper I-V graph for an ohmic component indicate a lower resistance?", "choices": ["more current is produced for the same voltage", "the component uses current up faster", "the voltage disappears", "the graph no longer shows a relationship"], "answer_index": 0, "hint": "Gradient compares current response to the same voltage change.", "tags": ["iv_graph_reasoning_confusion"]},
                {"kind": "mcq", "id": "M3L5_T3", "prompt": "Two branch currents in a parallel section are 1.5 A and 2.5 A. What total current enters the split?", "choices": ["4.0 A", "1.0 A", "2.5 A", "cannot be found"], "answer_index": 0, "hint": "Total current equals the sum of the branch currents.", "tags": ["parallel_circuit_rule_confusion"]},
            ],
            "contract": {
                "concept_targets": ["Use resistance as route difficulty that changes current for a given voltage.", "Separate one-loop series rules from branched parallel rules."],
                "prerequisite_lessons": ["F4_L2", "F4_L3", "M3_L4"],
                "misconception_focus": ["resistance_current_relationship_confusion", "iv_graph_reasoning_confusion", "series_circuit_rule_confusion", "parallel_circuit_rule_confusion"],
                "formulas": [
                    {"equation": "V = IR", "meaning": "Potential difference, current, and resistance are linked in an ohmic relationship.", "units": ["V", "A", "ohm"], "conditions": "Use for components following Ohm's law at constant temperature."},
                    {"equation": "R = V / I", "meaning": "Resistance compares the energy boost per charge with the resulting charge-flow rate.", "units": ["ohm"], "conditions": "Use when voltage and current for one component are known."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain route difficulty, common current, and branch splitting in a coherent network story."},
                    {"kind": "diagram", "purpose": "Show one-loop and branched circuits with labeled current paths."},
                    {"kind": "formula", "purpose": "Calculate current or resistance from Ohm's law."},
                ],
                "analogy_map": {"comparison": "Flow-Grid route width maps to resistance, one route maps to series, and branching lanes map to parallel.", "mapping": ["Narrower routes stand for larger resistance.", "A single shared route stands for a series loop with one common current.", "Branching lanes stand for parallel paths where current splits and rejoins."], "limit": "Charges do not literally choose lanes like vehicles, and not every component is perfectly ohmic.", "prediction_prompt": "If one branch is added beside another, what should happen to the split current story?"},
                "worked_examples": [
                    {"prompt": "A resistor has 10 V across it and carries 2 A. Find its resistance.", "steps": ["Choose the voltage-current-resistance relationship.", "Substitute 10 and 2 into R = V / I.", "Divide 10 by 2 to get the route difficulty."], "final_answer": "5 ohm", "why_it_matters": "This anchors resistance to voltage and current together."},
                    {"prompt": "A learner says current must be smaller after each lamp in a series loop because some of it gets used up. Evaluate the claim.", "steps": ["Picture one complete route with no branches.", "Notice that the same charge stream must pass each checkpoint in that route.", "Separate current from energy transfer at components.", "Conclude that the series current stays the same around the loop."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks both current-used-up and series-rule confusion."},
                ],
                "visual_assets": [{"asset_id": "m3-l5-network-rules", "concept": "series_parallel", "phase_key": "analogical_grounding", "title": "Series and parallel routes", "purpose": "Show route difficulty, one-loop current, and branch splitting in one view.", "caption": "Resistance changes current, and network structure changes how current is shared."}],
                "animation_assets": [{"asset_id": "m3-l5-network-rules-anim", "concept": "series_parallel", "phase_key": "analogical_grounding", "title": "Network rule comparison", "description": "Animate current in one loop versus a branched loop.", "duration_sec": 8}],
                "simulation_contract": {"asset_id": "m3_l5_network_rules_lab", "concept": "series_parallel", "baseline_case": "Start with one 6 V loop and one resistor.", "comparison_tasks": ["Increase the resistance in the one-loop circuit.", "Add a second branch and compare total current with branch current."], "watch_for": "Students should separate resistance, current, and network structure instead of collapsing them into one rule.", "takeaway": "Resistance sets how strongly voltage drives current, while series and parallel describe how routes are connected."},
                "reflection_prompts": ["Explain why a branch current can change without meaning the source voltage disappeared."],
                "mastery_skills": ["Use Ohm's law to calculate current or resistance.", "Interpret simple I-V relationships.", "State the common-current rule for series loops.", "State the split-current rule for parallel branches.", "Reject current-used-up explanations in network questions."],
                "variation_plan": {"diagnostic": "Rotate between fixed-voltage resistance comparisons, common-current series checks, and simple resistance calculations.", "concept_gate": "Swap between I-V reasoning and series-versus-parallel explanation prompts.", "mastery": "Vary voltage, resistance, graph descriptions, and network layouts without repeating the same stem."},
            },
        },
        {
            "id": "M3_L6",
            "title": "Electrical Power and Protection",
            "sim": {
                "lab_id": "m3_power_safety_lab",
                "title": "Power and protection explorer",
                "description": "Compare electrical power, total energy transfer, and protective cut-off decisions.",
                "instructions": ["Keep voltage fixed and change the current.", "Run the same power for different times and compare total energy transfer.", "Raise the current above a protection limit and explain what should happen."],
                "outcomes": ["power_energy_circuit_confusion", "electrical_safety_confusion"],
                "fields": ["supply_voltage", "device_current", "run_time", "protection_limit"],
                "depth": "number of power, energy, and protection stories explained through one electrical transfer model",
            },
            "analogy_text": "Flow-Grid's power meter tracks electrical energy transfer each second, while the safety gate breaks the route when the current rises beyond the safe limit. Power tells rate; protection prevents dangerous heating.",
            "commitment_prompt": "Decide whether the question is about electrical power, total energy over time, or a safety response.",
            "micro_prompts": [
                {"prompt": "Compare two devices on the same voltage but with different currents.", "hint": "At the same voltage, larger current means larger power."},
                {"prompt": "Compare a safe current with a current above the protection limit.", "hint": "Protection responds to excessive current, not to a random warning label."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L6_D1", "prompt": "Electrical power is calculated using...", "choices": ["power = voltage x current", "power = voltage / current only", "power = charge x time", "power = resistance / current"], "answer_index": 0, "hint": "In circuits, power depends on both voltage and current.", "tags": ["power_energy_circuit_confusion"]},
                {"kind": "short", "id": "M3L6_D2", "prompt": "A device uses 12 V and 3 A. What electrical power does it transfer?", "accepted_answers": ["36 W", "36"], "hint": "Use P = VI.", "tags": ["power_energy_circuit_confusion"]},
                {"kind": "mcq", "id": "M3L6_D3", "prompt": "Why does a fuse or breaker open a circuit?", "choices": ["to stop excessive current before overheating causes damage", "to raise the voltage", "to store current for later", "to make the lamp brighter"], "answer_index": 0, "hint": "Protection devices interrupt unsafe current.", "tags": ["electrical_safety_confusion"]},
            ],
            "inquiry": [
                {"prompt": "Hold voltage fixed and increase current.", "hint": "The power meter climbs because more electrical energy is transferred each second."},
                {"prompt": "Keep the same power but vary the run time.", "hint": "Total transferred energy depends on both power and time."},
            ],
            "recon_prompts": ["Explain how electrical power and total electrical energy are connected but not identical.", "Explain why protection devices are triggered by unsafe current conditions."],
            "capsule_prompt": "Use power for rate, energy for total over time, and protection for unsafe current.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L6_C1", "prompt": "If voltage stays the same and current doubles, electrical power becomes...", "choices": ["twice as large", "half as large", "unchanged", "zero"], "answer_index": 0, "hint": "Power tracks voltage multiplied by current.", "tags": ["power_energy_circuit_confusion"]},
                {"kind": "mcq", "id": "M3L6_C2", "prompt": "A breaker trips most directly because...", "choices": ["the current has risen to an unsafe level", "the current disappeared", "the voltage became zero", "resistance no longer exists"], "answer_index": 0, "hint": "Protection responds to dangerous current flow.", "tags": ["electrical_safety_confusion"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L6_T1", "prompt": "A heater transfers 240 W for 15 s. How much energy is transferred?", "accepted_answers": ["3600 J", "3600"], "hint": "Use E = Pt.", "tags": ["power_energy_circuit_confusion"]},
                {"kind": "mcq", "id": "M3L6_T2", "prompt": "Which device transfers more electrical power at the same voltage?", "choices": ["the one with the larger current", "the one with the smaller current", "they always transfer the same power", "the one with the shorter wire"], "answer_index": 0, "hint": "At fixed voltage, current decides the power size.", "tags": ["power_energy_circuit_confusion"]},
                {"kind": "mcq", "id": "M3L6_T3", "prompt": "Why is using an overrated fuse unsafe for a small appliance?", "choices": ["it may allow damaging current to keep flowing instead of disconnecting in time", "it makes the appliance more efficient", "it always lowers the voltage to zero", "it guarantees less heating"], "answer_index": 0, "hint": "Protection must match the safe current range of the device.", "tags": ["electrical_safety_confusion"]},
            ],
            "contract": {
                "concept_targets": ["Use electrical power as voltage times current and connect it to total transferred energy over time.", "Explain circuit protection as a mechanism that interrupts unsafe current."],
                "prerequisite_lessons": ["F4_L3", "M3_L3", "M3_L5"],
                "misconception_focus": ["power_energy_circuit_confusion", "electrical_safety_confusion"],
                "formulas": [
                    {"equation": "P = VI", "meaning": "Electrical power is the rate of electrical energy transfer set by voltage and current together.", "units": ["W"], "conditions": "Use for a component when voltage across it and current through it are known."},
                    {"equation": "E = Pt", "meaning": "Total electrical energy transferred equals power multiplied by time.", "units": ["J"], "conditions": "Use when power is steady over the interval."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain rate, total transfer, and safety response in one electrical story."},
                    {"kind": "diagram", "purpose": "Show a source, load, and protective device with labeled current and power flow."},
                    {"kind": "formula", "purpose": "Calculate electrical power and total energy transfer."},
                ],
                "analogy_map": {"comparison": "Flow-Grid's power meter maps to electrical energy transferred each second, and the safety gate maps to a fuse or breaker that opens when current is unsafe.", "mapping": ["A faster meter reading stands for larger electrical power.", "A longer run time stands for more total transferred energy.", "A closing safety gate stands for a protective cut-off when current rises too high."], "limit": "Real protection devices depend on heating and design details, not on a literal gate deciding to shut.", "prediction_prompt": "If a device draws more current at the same voltage, what changes first: the power reading or the run time?"},
                "worked_examples": [
                    {"prompt": "A lamp uses 6 V and 0.5 A. Find the electrical power.", "steps": ["Choose the voltage-current power relationship.", "Substitute 6 and 0.5 into P = VI.", "Multiply to get the transfer rate."], "final_answer": "3 W", "why_it_matters": "This links circuit power to the same rate idea learned earlier."},
                    {"prompt": "A learner says a fuse exists to make circuits more powerful. Evaluate the claim.", "steps": ["Recall that a fuse is a protection device.", "Link overheating risk to excessive current, not extra power output.", "Explain that the fuse opens the circuit when current becomes unsafe.", "Conclude that its purpose is protection, not performance."], "final_answer": "The claim is wrong.", "why_it_matters": "This grounds safety in a clear current-based mechanism."},
                ],
                "visual_assets": [{"asset_id": "m3-l6-power-safety", "concept": "power_safety", "phase_key": "analogical_grounding", "title": "Power and protection", "purpose": "Show electrical power flow, total energy over time, and protective cut-off in one circuit view.", "caption": "Power measures rate, and protection interrupts unsafe current."}],
                "animation_assets": [{"asset_id": "m3-l6-power-safety-anim", "concept": "power_safety", "phase_key": "analogical_grounding", "title": "Protection trigger", "description": "Animate current rising, power increasing, and a safety cut-off opening the route.", "duration_sec": 8}],
                "simulation_contract": {"asset_id": "m3_l6_power_safety_lab", "concept": "power_safety", "baseline_case": "Start with a 12 V device drawing 1 A.", "comparison_tasks": ["Increase current at the same voltage and compare power.", "Raise the current above the protection limit and explain why the circuit should open."], "watch_for": "Students should tie unsafe current to overheating risk and protection, not to vague danger language.", "takeaway": "Electrical power tells transfer rate, total energy grows with time, and protection interrupts unsafe current."},
                "reflection_prompts": ["Explain why a device can have a high power rating without that meaning any fuse would be safe to use with it."],
                "mastery_skills": ["Calculate electrical power from voltage and current.", "Calculate total electrical energy from power and time.", "Compare circuit power at fixed voltage.", "Explain how fuses and breakers protect circuits.", "Reject vague or magical safety explanations."],
                "variation_plan": {"diagnostic": "Rotate between P = VI calculations, power comparisons at fixed voltage, and protection-purpose questions.", "concept_gate": "Swap between rate-versus-total-energy checks and fuse-mechanism explanations.", "mastery": "Vary voltage, current, run time, and safety stories while keeping the same power-protection structure."},
            },
        },
    ]
)


RELEASE_CHECKS = [
    "Every formula is taught with meaning, units, and conditions before mastery uses it.",
    "Every lesson includes a generated visual asset and a usable simulation contract.",
    "Rate, store, and network ideas stay distinct instead of collapsing into one slogan.",
    "Safety claims are tied to a concrete mechanism rather than generic warning language.",
]


M3_MODULE_DOC, M3_LESSONS, M3_SIM_LABS = build_nextgen_module_bundle(
    module_id=M3_MODULE_ID,
    module_title="Energy, Circuits & Safe Systems",
    module_spec=M3_SPEC,
    allowlist=M3_ALLOWLIST,
    content_version=M3_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=7,
    level="Module 3",
    estimated_minutes=225,
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

    plan: List[Tuple[str, str]] = [("modules", M3_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in lesson_pairs] + [("sim_labs", doc_id) for doc_id, _ in sim_pairs]
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
