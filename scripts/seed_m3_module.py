from __future__ import annotations

import argparse
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
M3_CONTENT_VERSION = "20260317_m3_energy_work_power_v2"
M3_ALLOWLIST = [
    "work_energy_transfer_confusion",
    "kinetic_energy_relationship_error",
    "gravitational_potential_energy_error",
    "power_rate_confusion",
    "efficiency_calculation_error",
    "energy_transfer_calculation_error",
]


M3_SPEC = {
    "module_description": (
        "Module 3 develops quantitative energy reasoning through work done, kinetic energy, "
        "gravitational potential energy, power, efficiency, and extended energy-transfer calculations."
    ),
    "mastery_outcomes": [
        "Calculate work done as energy transferred when force causes displacement in the force direction.",
        "Calculate and compare kinetic energy and gravitational potential energy using the correct variables.",
        "Use power equations to connect transfer rate, total energy, and time.",
        "Calculate efficiency as a useful-output fraction and interpret it as a percentage.",
        "Select and combine the right equations in mixed energy-transfer calculations.",
    ],
    "lessons": [],
}


M3_SPEC["lessons"].extend(
    [
        {
            "id": "M3_L1",
            "title": "Work Done and Energy Transfer",
            "sim": {
                "lab_id": "m3_work_transfer_lab",
                "title": "Work transfer explorer",
                "description": "Compare force-only stories with force-plus-displacement stories.",
                "instructions": [
                    "Keep the force fixed and change the distance moved.",
                    "Compare a moving object with a rigid wall.",
                    "Reverse the motion direction and explain the sign of the transfer.",
                ],
                "outcomes": ["work_energy_transfer_confusion"],
                "fields": ["force", "distance", "motion_case", "work_done"],
                "depth": "number of force-displacement stories interpreted correctly as work transfer or no work transfer",
            },
            "analogy_text": "Energy Ledger records work only when a force causes displacement in the force direction.",
            "commitment_prompt": "Check first whether the force actually causes movement through a distance.",
            "micro_prompts": [
                {"prompt": "Compare pushing a moving crate with pushing a wall that does not move.", "hint": "Force exists in both stories, but only one has displacement."},
                {"prompt": "Compare 2 m and 6 m of motion under the same force.", "hint": "For a fixed force, more displacement means more work done."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L1_D1", "prompt": "Work is done on an object when...", "choices": ["a force causes displacement in the force direction", "a force simply exists", "time passes while the object is held", "the object has a large mass"], "answer_index": 0, "hint": "Work links force with displacement.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_D2", "prompt": "A wall does not move while being pushed. What work is done on the wall?", "choices": ["0 J", "some work because the push is hard", "equal to the force only", "cannot be known"], "answer_index": 0, "hint": "No displacement means no work done on the wall.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "short", "id": "M3L1_D3", "prompt": "A 5 N force moves a box 2 m in the same direction. What work is done?", "accepted_answers": ["10 J", "10"], "hint": "Use W = Fd when force and displacement are aligned.", "tags": ["work_energy_transfer_confusion"]},
            ],
            "inquiry": [
                {"prompt": "Hold force fixed and vary the displacement.", "hint": "Watch work scale directly with distance."},
                {"prompt": "Keep the push but remove the motion.", "hint": "The transfer should disappear when displacement becomes zero."},
            ],
            "recon_prompts": [
                "Explain why force alone does not guarantee work done.",
                "Explain why work and energy transfer are measured in the same unit.",
            ],
            "capsule_prompt": "Work needs force and displacement together, not force by itself.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L1_C1", "prompt": "If the distance doubles while the force stays the same, the work done is...", "choices": ["twice as large", "half as large", "unchanged", "zero"], "answer_index": 0, "hint": "Work is proportional to distance for a fixed force.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_C2", "prompt": "1 joule of work means...", "choices": ["1 joule of energy is transferred", "1 newton of force exists", "1 second has passed", "1 kilogram is moving"], "answer_index": 0, "hint": "Work is measured in joules because it measures energy transferred.", "tags": ["work_energy_transfer_confusion"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L1_T1", "prompt": "A 12 N force moves an object 3 m in the same direction. What work is done?", "accepted_answers": ["36 J", "36"], "hint": "Multiply force by displacement.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_T2", "prompt": "Why is no work done on a held-still book?", "choices": ["the book does not move through a distance", "gravity disappears", "the book has no energy", "the force is too small to matter"], "answer_index": 0, "hint": "Without displacement, work done on the book is zero.", "tags": ["work_energy_transfer_confusion"]},
                {"kind": "mcq", "id": "M3L1_T3", "prompt": "Which change most directly increases work done for the same force?", "choices": ["greater displacement", "more waiting time", "a different color", "less discussion"], "answer_index": 0, "hint": "For the same force, more distance means more work done.", "tags": ["work_energy_transfer_confusion"]},
            ],
            "contract": {
                "concept_targets": [
                    "Treat work done as energy transferred by force through displacement.",
                    "Separate effort or force presence from actual transferred energy.",
                ],
                "prerequisite_lessons": ["F3_L1", "M2_L1"],
                "misconception_focus": ["work_energy_transfer_confusion"],
                "formulas": [
                    {"equation": "W = Fd", "meaning": "Work done equals force multiplied by displacement in the force direction.", "units": ["J"], "conditions": "Use when force and displacement are along the same line."},
                    {"equation": "1 J = 1 N m", "meaning": "A joule is the work done when a 1 N force acts through 1 m.", "units": ["J"], "conditions": "Use when interpreting the unit of work."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain why work needs both force and displacement."},
                    {"kind": "diagram", "purpose": "Show force and motion on the same object."},
                    {"kind": "formula", "purpose": "Calculate transferred energy."},
                ],
                "analogy_map": {
                    "comparison": "Energy Ledger stands for recorded transfer caused by force through motion.",
                    "mapping": ["The push stands for the force acting on the object.", "Ledger tokens appear only when that force produces displacement."],
                    "limit": "Real energy transfer is not a visible token drop in space.",
                    "prediction_prompt": "If the push stays but the object does not move, what should happen to the ledger record?",
                },
                "worked_examples": [
                    {"prompt": "A 4 N force moves a box 5 m. Find the work done.", "steps": ["Identify force and displacement.", "Use W = Fd.", "Multiply 4 by 5."], "final_answer": "20 J", "why_it_matters": "This anchors work to force causing motion."},
                    {"prompt": "A learner says holding a suitcase still does work on it because the force feels hard. Evaluate the claim.", "steps": ["Check whether the suitcase moves.", "Notice that the displacement is zero.", "Conclude that no work is done on the suitcase."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks effort-only reasoning."},
                ],
                "visual_assets": [
                    {"asset_id": "m3-l1-work-transfer", "concept": "energy_transfer", "phase_key": "analogical_grounding", "title": "Work transfers energy", "purpose": "Contrast force without motion against force with displacement.", "caption": "Force plus displacement transfers energy."}
                ],
                "animation_assets": [
                    {"asset_id": "m3-l1-work-transfer-anim", "concept": "energy_transfer", "phase_key": "analogical_grounding", "title": "Work done comparison", "description": "Animate a moving crate and a non-moving wall under a push.", "duration_sec": 8}
                ],
                "simulation_contract": {
                    "asset_id": "m3_l1_work_transfer_lab",
                    "concept": "energy_transfer",
                    "baseline_case": "Start with a 5 N push moving a crate 2 m.",
                    "comparison_tasks": ["Keep the force but remove the motion.", "Double the displacement under the same force."],
                    "watch_for": "Students should say that work only happens when force causes displacement.",
                    "takeaway": "Work is transferred energy, not effort by itself.",
                },
                "reflection_prompts": ["Explain why a force can exist without doing work on the object."],
                "mastery_skills": [
                    "Identify when work is done.",
                    "Calculate work from force and distance.",
                    "Interpret joules as transferred energy.",
                    "Reject no-motion work misconceptions.",
                    "Explain work qualitatively.",
                ],
                "variation_plan": {
                    "diagnostic": "Rotate moving-object, no-motion, and doubled-distance stories.",
                    "concept_gate": "Swap between explanation prompts and direct W = Fd questions.",
                    "mastery": "Vary force, distance, and context while keeping the same work structure.",
                },
            },
        },
        {
            "id": "M3_L2",
            "title": "Kinetic Energy",
            "sim": {
                "lab_id": "m3_kinetic_energy_lab",
                "title": "Kinetic energy explorer",
                "description": "Compare how mass and speed change kinetic energy.",
                "instructions": ["Keep mass fixed and change the speed.", "Keep speed fixed and change the mass.", "Compare doubling mass with doubling speed."],
                "outcomes": ["kinetic_energy_relationship_error"],
                "fields": ["mass", "speed", "kinetic_energy", "comparison_reasoning"],
                "depth": "number of mass-speed comparisons explained correctly with the squared-speed relationship",
            },
            "analogy_text": "Energy Ledger stores motion energy in a motion vault. Speed changes the size of that store more dramatically because it is squared.",
            "commitment_prompt": "Decide whether the change comes from mass, speed, or both before choosing the relationship.",
            "micro_prompts": [
                {"prompt": "Compare doubling mass with doubling speed for the same moving object.", "hint": "Speed has the stronger effect because the speed term is squared."},
                {"prompt": "Compare a heavy slow object with a light fast object.", "hint": "You need the full relationship, not a single-variable shortcut."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L2_D1", "prompt": "For the same object, which change increases kinetic energy most?", "choices": ["doubling the speed", "doubling the time", "doubling the color", "doubling the distance moved yesterday"], "answer_index": 0, "hint": "Kinetic energy depends on speed squared.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "mcq", "id": "M3L2_D2", "prompt": "If mass doubles while speed stays the same, kinetic energy becomes...", "choices": ["twice as large", "four times as large", "half as large", "unchanged"], "answer_index": 0, "hint": "Mass changes kinetic energy directly, not as a square.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "short", "id": "M3L2_D3", "prompt": "A 2 kg trolley moves at 3 m/s. What kinetic energy does it have?", "accepted_answers": ["9 J", "9"], "hint": "Use KE = 0.5mv^2.", "tags": ["kinetic_energy_relationship_error"]},
            ],
            "inquiry": [
                {"prompt": "Hold mass fixed and vary the speed.", "hint": "The motion store should grow rapidly as speed rises."},
                {"prompt": "Hold speed fixed and vary the mass.", "hint": "The change is direct and proportional."},
            ],
            "recon_prompts": [
                "Explain why doubling speed changes kinetic energy more strongly than doubling mass.",
                "Explain why you cannot compare moving objects accurately by looking at speed alone.",
            ],
            "capsule_prompt": "Kinetic energy depends on mass and on speed squared.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L2_C1", "prompt": "If speed doubles for the same mass, kinetic energy becomes...", "choices": ["four times as large", "twice as large", "half as large", "unchanged"], "answer_index": 0, "hint": "The speed term is squared.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "mcq", "id": "M3L2_C2", "prompt": "Which variable is squared in the kinetic energy equation?", "choices": ["speed", "mass", "time", "force"], "answer_index": 0, "hint": "Only the speed term is squared in KE = 0.5mv^2.", "tags": ["kinetic_energy_relationship_error"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L2_T1", "prompt": "A 4 kg cart moves at 5 m/s. What is its kinetic energy?", "accepted_answers": ["50 J", "50"], "hint": "Substitute into KE = 0.5mv^2.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "mcq", "id": "M3L2_T2", "prompt": "Which object has the larger kinetic energy?", "choices": ["a 2 kg object at 6 m/s", "a 4 kg object at 3 m/s", "they are equal", "there is not enough information because both are moving"], "answer_index": 0, "hint": "Estimate with the full equation, not one variable only.", "tags": ["kinetic_energy_relationship_error"]},
                {"kind": "short", "id": "M3L2_T3", "prompt": "A 3 kg bicycle has 24 J of kinetic energy. If KE = 0.5mv^2, what is v^2?", "accepted_answers": ["16", "16 m^2/s^2"], "hint": "Rearrange 24 = 0.5 x 3 x v^2.", "tags": ["kinetic_energy_relationship_error", "energy_transfer_calculation_error"]},
            ],
            "contract": {
                "concept_targets": [
                    "Calculate kinetic energy using mass and speed.",
                    "Explain the squared-speed relationship in comparisons.",
                ],
                "prerequisite_lessons": ["F3_L2", "M3_L1"],
                "misconception_focus": ["kinetic_energy_relationship_error"],
                "formulas": [
                    {"equation": "KE = 0.5mv^2", "meaning": "Kinetic energy depends on how much mass is moving and how fast it is moving.", "units": ["J"], "conditions": "Use for translational motion when mass and speed are known."}
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain why speed matters strongly in kinetic energy."},
                    {"kind": "diagram", "purpose": "Show motion comparisons for different masses and speeds."},
                    {"kind": "formula", "purpose": "Calculate kinetic energy numerically."},
                ],
                "analogy_map": {
                    "comparison": "The motion vault stands for stored kinetic energy in a moving object.",
                    "mapping": ["A heavier object stands for a larger mass term.", "A faster object fills the vault much more quickly because speed is squared."],
                    "limit": "Energy is not a visible liquid filling a box.",
                    "prediction_prompt": "If the same object doubles its speed, how should the motion vault change?",
                },
                "worked_examples": [
                    {"prompt": "A 3 kg cart moves at 2 m/s. Find its kinetic energy.", "steps": ["Write KE = 0.5mv^2.", "Square the speed first.", "Multiply 0.5 x 3 x 4."], "final_answer": "6 J", "why_it_matters": "This keeps students from skipping the square."},
                    {"prompt": "A learner says doubling mass and doubling speed have the same effect on kinetic energy. Evaluate the claim.", "steps": ["Compare the mass term with the squared-speed term.", "Notice that doubling mass doubles KE, but doubling speed multiplies KE by four.", "Conclude that the claim is wrong."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks the most common comparison error."},
                ],
                "visual_assets": [
                    {"asset_id": "m3-l2-kinetic-energy", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Kinetic energy depends on speed strongly", "purpose": "Show how mass and speed affect the motion store differently.", "caption": "Speed changes kinetic energy more strongly because it is squared."}
                ],
                "animation_assets": [
                    {"asset_id": "m3-l2-kinetic-energy-anim", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Motion store comparison", "description": "Animate mass and speed changes feeding the same kinetic-energy store.", "duration_sec": 8}
                ],
                "simulation_contract": {
                    "asset_id": "m3_l2_kinetic_energy_lab",
                    "concept": "energy_stores",
                    "baseline_case": "Start with a 2 kg trolley moving at 4 m/s.",
                    "comparison_tasks": ["Double the speed while keeping mass fixed.", "Double the mass while keeping speed fixed."],
                    "watch_for": "Students should say speed is squared while mass changes kinetic energy directly.",
                    "takeaway": "Kinetic energy depends on mass and especially on speed.",
                },
                "reflection_prompts": ["Explain why speed usually changes kinetic energy more dramatically than mass does."],
                "mastery_skills": [
                    "Calculate kinetic energy.",
                    "Compare the effects of changing mass and speed.",
                    "Use the squared-speed idea correctly.",
                    "Reject one-variable comparison shortcuts.",
                    "Rearrange simple kinetic-energy relationships.",
                ],
                "variation_plan": {
                    "diagnostic": "Rotate speed-squared comparisons, direct calculations, and mass-versus-speed prompts.",
                    "concept_gate": "Swap between numerical KE questions and qualitative comparison items.",
                    "mastery": "Vary mass, speed, and rearrangement structure without repeating stems.",
                },
            },
        },
    ]
)


M3_SPEC["lessons"].extend(
    [
        {
            "id": "M3_L5",
            "title": "Efficiency",
            "sim": {
                "lab_id": "m3_efficiency_lab",
                "title": "Efficiency explorer",
                "description": "Compare useful output, wasted output, and total input in systems.",
                "instructions": ["Keep total input fixed and change the useful output.", "Compare two devices with different useful fractions.", "Connect percentage efficiency to the same fraction written in decimal form."],
                "outcomes": ["efficiency_calculation_error"],
                "fields": ["total_input", "useful_output", "wasted_output", "efficiency_percent"],
                "depth": "number of useful-output comparisons explained correctly as a fraction of total input",
            },
            "analogy_text": "Energy Ledger sends all input into a system, but only part reaches the useful-output lane. Efficiency measures that useful fraction.",
            "commitment_prompt": "Check which quantity is total input, which is useful output, and which is the fraction you need to compare.",
            "micro_prompts": [
                {"prompt": "Compare 80 J useful from 100 J input with 80 J useful from 160 J input.", "hint": "The same useful output can correspond to different efficiencies if the total input changes."},
                {"prompt": "Compare useful output and wasted output in one device.", "hint": "Wasted energy does not vanish; it is the part not counted as useful."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L5_D1", "prompt": "Efficiency compares...", "choices": ["useful output with total input", "useful output with time only", "wasted output with mass only", "power with speed only"], "answer_index": 0, "hint": "Efficiency is a useful fraction, not a rate.", "tags": ["efficiency_calculation_error"]},
                {"kind": "short", "id": "M3L5_D2", "prompt": "A machine takes in 200 J and gives 150 J usefully. What is its efficiency?", "accepted_answers": ["75%", "0.75"], "hint": "Efficiency = useful output / total input.", "tags": ["efficiency_calculation_error"]},
                {"kind": "mcq", "id": "M3L5_D3", "prompt": "Which statement is true about efficiency?", "choices": ["it cannot be greater than 100%", "it is always larger for bigger machines", "it tells how fast a machine works", "it makes wasted energy disappear"], "answer_index": 0, "hint": "Useful output cannot exceed total input.", "tags": ["efficiency_calculation_error"]},
            ],
            "inquiry": [
                {"prompt": "Hold total input fixed and raise the useful output.", "hint": "The useful fraction should rise."},
                {"prompt": "Keep useful output fixed and raise the total input.", "hint": "The efficiency should fall because the fraction becomes smaller."},
            ],
            "recon_prompts": [
                "Explain why efficiency is a fraction rather than a separate type of energy.",
                "Explain why a machine can transfer a lot of energy and still be inefficient.",
            ],
            "capsule_prompt": "Efficiency asks what fraction of the total input becomes useful output.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L5_C1", "prompt": "An efficiency of 60% means...", "choices": ["60% of the input becomes useful output", "40% of the input disappears", "the machine always outputs 60 J", "the machine has no wasted energy"], "answer_index": 0, "hint": "Efficiency compares useful output with the whole input.", "tags": ["efficiency_calculation_error"]},
                {"kind": "mcq", "id": "M3L5_C2", "prompt": "If useful output stays the same but total input increases, efficiency becomes...", "choices": ["smaller", "larger", "unchanged", "exactly 100%"], "answer_index": 0, "hint": "The denominator gets larger while the numerator stays fixed.", "tags": ["efficiency_calculation_error"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L5_T1", "prompt": "A system takes in 2400 J and produces 1800 J usefully. What is the efficiency?", "accepted_answers": ["75%", "0.75"], "hint": "Divide useful output by total input.", "tags": ["efficiency_calculation_error"]},
                {"kind": "short", "id": "M3L5_T2", "prompt": "A device is 40% efficient and receives 500 J. What useful output does it provide?", "accepted_answers": ["200 J", "200"], "hint": "Useful output = efficiency x total input.", "tags": ["efficiency_calculation_error", "energy_transfer_calculation_error"]},
                {"kind": "mcq", "id": "M3L5_T3", "prompt": "Which device is more efficient?", "choices": ["the one giving 90 J useful from 100 J input", "the one giving 120 J useful from 160 J input", "they are equally efficient", "there is not enough information because the useful output values differ"], "answer_index": 0, "hint": "Compare useful fraction, not useful amount alone.", "tags": ["efficiency_calculation_error"]},
            ],
            "contract": {
                "concept_targets": [
                    "Calculate efficiency as useful output divided by total input.",
                    "Interpret efficiency as a fraction or percentage without confusing it with power.",
                ],
                "prerequisite_lessons": ["F3_L3", "M3_L1", "M3_L4"],
                "misconception_focus": ["efficiency_calculation_error"],
                "formulas": [
                    {"equation": "efficiency = useful output / total input", "meaning": "Efficiency compares the useful part with the full input.", "units": ["fraction"], "conditions": "Use when useful and total energy or power are known."},
                    {"equation": "efficiency (%) = (useful output / total input) x 100", "meaning": "Percentage efficiency expresses the same fraction out of 100.", "units": ["%"], "conditions": "Use when reporting efficiency as a percentage."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain useful output and wasted output clearly."},
                    {"kind": "diagram", "purpose": "Show one input splitting into useful and wasted parts."},
                    {"kind": "formula", "purpose": "Calculate efficiency and useful output numerically."},
                ],
                "analogy_map": {
                    "comparison": "The useful-output lane stands for the share of the input that reaches the intended outcome.",
                    "mapping": ["All input tokens represent the total input.", "Only the tokens reaching the useful lane count toward efficiency."],
                    "limit": "Real systems do not sort energy into visible lanes.",
                    "prediction_prompt": "If the useful output stays the same but the total input rises, what happens to the useful fraction?",
                },
                "worked_examples": [
                    {"prompt": "A machine takes in 500 J and gives 350 J usefully. Find the efficiency.", "steps": ["Write efficiency = useful / total.", "Substitute 350 / 500.", "Convert to 0.70 or 70%."], "final_answer": "70%", "why_it_matters": "This anchors efficiency to a fraction of the whole input."},
                    {"prompt": "A learner says an efficiency of 60% means 40% of the energy disappeared. Evaluate the claim.", "steps": ["Separate useful output from wasted output.", "Notice that the non-useful part is not counted as useful but is still transferred.", "Conclude that the claim is wrong."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks the common 'vanishing energy' misconception."},
                ],
                "visual_assets": [
                    {"asset_id": "m3-l5-efficiency", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Efficiency is a useful fraction", "purpose": "Show total input splitting into useful and wasted outputs.", "caption": "Efficiency compares the useful part with the whole input."}
                ],
                "animation_assets": [
                    {"asset_id": "m3-l5-efficiency-anim", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Useful versus wasted output", "description": "Animate the same input splitting into useful and wasted pathways.", "duration_sec": 8}
                ],
                "simulation_contract": {
                    "asset_id": "m3_l5_efficiency_lab",
                    "concept": "energy_stores",
                    "baseline_case": "Start with 100 J input and 75 J useful output.",
                    "comparison_tasks": ["Keep the input fixed and increase the useful output.", "Keep the useful output fixed and increase the total input."],
                    "watch_for": "Students should compare useful output with total input rather than useful output alone.",
                    "takeaway": "Efficiency is a useful fraction, not a separate store or a rate.",
                },
                "reflection_prompts": ["Explain why a large useful output does not automatically mean high efficiency."],
                "mastery_skills": [
                    "Calculate efficiency as a fraction or percentage.",
                    "Calculate useful output from efficiency and total input.",
                    "Compare devices by useful fraction.",
                    "Separate useful and wasted output clearly.",
                    "Reject impossible efficiency claims above 100%.",
                ],
                "variation_plan": {
                    "diagnostic": "Rotate useful-fraction definitions, direct percentage calculations, and above-100% checks.",
                    "concept_gate": "Swap between efficiency interpretation and useful-output calculation prompts.",
                    "mastery": "Vary input, useful output, and decimal-versus-percent contexts without repeating stems.",
                },
            },
        },
        {
            "id": "M3_L6",
            "title": "Energy Transfer Calculations",
            "sim": {
                "lab_id": "m3_energy_transfer_calculations_lab",
                "title": "Energy calculation planner",
                "description": "Select and connect work, store, power, and efficiency relationships in multi-step problems.",
                "instructions": ["Decide which equation fits a work story, a store story, a power story, or an efficiency story.", "Solve a calculation in stages instead of guessing one formula.", "Check that each answer keeps the units and physical meaning consistent."],
                "outcomes": ["work_energy_transfer_confusion", "kinetic_energy_relationship_error", "gravitational_potential_energy_error", "power_rate_confusion", "efficiency_calculation_error", "energy_transfer_calculation_error"],
                "fields": ["known_quantities", "chosen_equation", "intermediate_value", "final_answer"],
                "depth": "number of multi-step energy problems solved by selecting and linking the correct equations",
            },
            "analogy_text": "Energy Ledger becomes a planning board in extended problems: first identify the story, then choose the right equation, then connect one result to the next step.",
            "commitment_prompt": "Name the calculation type first: work, kinetic energy, gravitational potential energy, power, or efficiency.",
            "micro_prompts": [
                {"prompt": "Compare a pushing problem with a lifting problem.", "hint": "One starts with work done, the other may end with GPE or use GPE directly."},
                {"prompt": "Compare a power-time question with an efficiency question.", "hint": "One asks about rate over time, while the other asks about useful fraction."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L6_D1", "prompt": "Which equation best matches 'A 40 N force pushes an object 5 m'?", "choices": ["W = Fd", "KE = 0.5mv^2", "P = E / t", "efficiency = useful / total"], "answer_index": 0, "hint": "This is a force-through-distance story.", "tags": ["work_energy_transfer_confusion", "energy_transfer_calculation_error"]},
                {"kind": "short", "id": "M3L6_D2", "prompt": "A 200 W machine runs for 5 s. How much energy is transferred?", "accepted_answers": ["1000 J", "1000"], "hint": "Use E = Pt.", "tags": ["power_rate_confusion", "energy_transfer_calculation_error"]},
                {"kind": "short", "id": "M3L6_D3", "prompt": "A system is 25% efficient and takes in 400 J. What useful output does it deliver?", "accepted_answers": ["100 J", "100"], "hint": "Useful output = efficiency x total input.", "tags": ["efficiency_calculation_error", "energy_transfer_calculation_error"]},
            ],
            "inquiry": [
                {"prompt": "Sort a set of problems by the first equation they need.", "hint": "The right first step depends on the physical story, not on which numbers look familiar."},
                {"prompt": "Use one result as the next step in a two-stage calculation.", "hint": "Intermediate values often become the input for a second equation."},
            ],
            "recon_prompts": [
                "Explain how you decide which energy equation to start with in a mixed problem.",
                "Explain why unit checks help you catch wrong formula choices in extended calculations.",
            ],
            "capsule_prompt": "Extended energy questions are solved by identifying the story, choosing the equation, and checking the units.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L6_C1", "prompt": "Which equation would you use first to find the height reached when GPE gain is known?", "choices": ["GPE = mgh", "W = Fd", "P = E / t", "efficiency = useful / total"], "answer_index": 0, "hint": "Start with the relationship that already contains GPE and height.", "tags": ["gravitational_potential_energy_error", "energy_transfer_calculation_error"]},
                {"kind": "mcq", "id": "M3L6_C2", "prompt": "Which check is most useful after finishing a multi-step energy calculation?", "choices": ["whether the units and physical meaning fit the answer", "whether the numbers look large", "whether the answer is a multiple of 10", "whether the object is brightly colored"], "answer_index": 0, "hint": "Unit checks help catch wrong equation choices.", "tags": ["energy_transfer_calculation_error"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L6_T1", "prompt": "A 50 N force pushes a box 4 m. The transferred 200 J becomes gravitational potential energy for a 5 kg load. Use g = 10 N/kg. How high is the load lifted?", "accepted_answers": ["4 m", "4"], "hint": "Find the work first, then set that equal to GPE.", "tags": ["work_energy_transfer_confusion", "gravitational_potential_energy_error", "energy_transfer_calculation_error"]},
                {"kind": "short", "id": "M3L6_T2", "prompt": "A 400 W hoist works for 15 s and is 60% efficient. How much useful energy output does it provide?", "accepted_answers": ["3600 J", "3600"], "hint": "Find total energy with E = Pt, then take 60% of it.", "tags": ["power_rate_confusion", "efficiency_calculation_error", "energy_transfer_calculation_error"]},
                {"kind": "mcq", "id": "M3L6_T3", "prompt": "Which plan best solves 'A 2 kg trolley speeds up to 5 m/s, then compare its kinetic energy with the GPE needed to raise it 2.5 m using g = 10 N/kg'?", "choices": ["calculate KE with 0.5mv^2, calculate GPE with mgh, then compare the two values", "calculate power first because all energy problems start with rate", "calculate efficiency because every comparison is a useful fraction", "use only W = Fd because distance always matters most"], "answer_index": 0, "hint": "Pick the equation that matches each physical part of the story.", "tags": ["kinetic_energy_relationship_error", "gravitational_potential_energy_error", "energy_transfer_calculation_error"]},
            ],
            "contract": {
                "concept_targets": [
                    "Select the correct equation for each energy story in a mixed problem.",
                    "Link equations across multi-step calculations while keeping units consistent.",
                ],
                "prerequisite_lessons": ["M3_L1", "M3_L2", "M3_L3", "M3_L4", "M3_L5"],
                "misconception_focus": ["work_energy_transfer_confusion", "kinetic_energy_relationship_error", "gravitational_potential_energy_error", "power_rate_confusion", "efficiency_calculation_error", "energy_transfer_calculation_error"],
                "formulas": [
                    {"equation": "W = Fd", "meaning": "Use this when force causes displacement.", "units": ["J"], "conditions": "Use when force and displacement are aligned."},
                    {"equation": "KE = 0.5mv^2", "meaning": "Use this for motion energy.", "units": ["J"], "conditions": "Use when mass and speed are known."},
                    {"equation": "GPE = mgh", "meaning": "Use this for height-related energy gain.", "units": ["J"], "conditions": "Use near Earth's surface for height changes."},
                    {"equation": "P = E / t and E = Pt", "meaning": "Use these when transfer rate and time are involved.", "units": ["W", "J"], "conditions": "Use when the story is about rate over time."},
                    {"equation": "efficiency = useful output / total input", "meaning": "Use this when the story is about useful fraction.", "units": ["fraction", "%"], "conditions": "Use when useful and total values are both known or linked."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain the formula-selection plan before calculating."},
                    {"kind": "table", "purpose": "Organize known quantities, chosen equations, and intermediate values."},
                    {"kind": "formula", "purpose": "Carry out multi-step energy calculations accurately."},
                ],
                "analogy_map": {
                    "comparison": "The planning board version of Energy Ledger stands for sorting mixed problems into the right energy story before calculating.",
                    "mapping": ["Each column on the board stands for one equation family.", "An intermediate result moving to the next column stands for a multi-step calculation."],
                    "limit": "Real problem solving is more flexible than moving tokens between fixed columns.",
                    "prediction_prompt": "If a problem gives force and distance first, which column should you use before anything else?",
                },
                "worked_examples": [
                    {"prompt": "A 300 W machine runs for 12 s. Find the total energy transferred, then find the useful output if it is 50% efficient.", "steps": ["Use E = Pt to find total energy: 300 x 12 = 3600 J.", "Use efficiency as 0.50 of the total input.", "Calculate useful output as 1800 J."], "final_answer": "1800 J", "why_it_matters": "This models how one equation can feed the next step."},
                    {"prompt": "A learner solves a lifting problem with P = E / t even though no time is given. Evaluate the plan.", "steps": ["Look at the physical story and the quantities given.", "Notice that the problem is about height gain, not rate over time.", "Choose GPE = mgh instead."], "final_answer": "The plan is wrong because the equation does not match the story.", "why_it_matters": "This trains formula selection instead of number matching."},
                ],
                "visual_assets": [
                    {"asset_id": "m3-l6-energy-transfer-calculations", "concept": "power_rate", "phase_key": "analogical_grounding", "title": "Choose the right energy equation", "purpose": "Show mixed energy stories being sorted into work, stores, power, and efficiency.", "caption": "Extended problems start with equation choice, not guesswork."}
                ],
                "animation_assets": [
                    {"asset_id": "m3-l6-energy-transfer-calculations-anim", "concept": "power_rate", "phase_key": "analogical_grounding", "title": "Multi-step energy planning", "description": "Animate one result feeding the next equation in a multi-step energy problem.", "duration_sec": 8}
                ],
                "simulation_contract": {
                    "asset_id": "m3_l6_energy_transfer_calculations_lab",
                    "concept": "power_rate",
                    "baseline_case": "Start with one energy-and-time story, then connect its result to a second step.",
                    "comparison_tasks": ["Choose the first equation for several different energy stories.", "Use one intermediate answer to complete a second calculation."],
                    "watch_for": "Students should select equations by physical meaning and check units after each step.",
                    "takeaway": "Extended energy calculations are solved by matching the story to the right relationship and linking steps carefully.",
                },
                "reflection_prompts": ["Explain how you decide whether a mixed problem starts with work, a store equation, power, or efficiency."],
                "mastery_skills": [
                    "Choose the correct energy equation from context.",
                    "Carry out two-step energy calculations.",
                    "Link intermediate answers into a second equation.",
                    "Check units and physical meaning at each step.",
                    "Avoid number-matching shortcuts when selecting formulas.",
                ],
                "variation_plan": {
                    "diagnostic": "Rotate first-equation choice, direct E = Pt, and useful-output prompts.",
                    "concept_gate": "Swap between unit-check questions and two-step calculation plans.",
                    "mastery": "Blend work, store, power, and efficiency stories so formula choice must stay deliberate.",
                },
            },
        },
    ]
)


M3_SPEC["lessons"].extend(
    [
        {
            "id": "M3_L3",
            "title": "Gravitational Potential Energy",
            "sim": {
                "lab_id": "m3_gravitational_potential_energy_lab",
                "title": "Height store explorer",
                "description": "Compare how mass and height change gravitational potential energy.",
                "instructions": ["Keep mass fixed and change the height.", "Keep height fixed and change the mass.", "Compare equal height gains for different masses."],
                "outcomes": ["gravitational_potential_energy_error"],
                "fields": ["mass", "height", "field_strength", "gpe_gain"],
                "depth": "number of mass-height comparisons explained correctly with the mgh relationship",
            },
            "analogy_text": "Energy Ledger stores gravitational potential energy on a height shelf. Raising the object or increasing its mass increases the stored amount.",
            "commitment_prompt": "Check whether the question is about mass, gravitational field strength, height, or a combination of them.",
            "micro_prompts": [
                {"prompt": "Compare doubling the mass with doubling the height.", "hint": "Both changes double gravitational potential energy if the other variables stay fixed."},
                {"prompt": "Compare lifting two objects to the same shelf height.", "hint": "The heavier object gains more gravitational potential energy."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L3_D1", "prompt": "Gravitational potential energy increases most directly when...", "choices": ["height increases", "color changes", "time passes", "speed stays constant"], "answer_index": 0, "hint": "Height above the reference level matters in GPE.", "tags": ["gravitational_potential_energy_error"]},
                {"kind": "mcq", "id": "M3L3_D2", "prompt": "If mass doubles while height stays the same, gravitational potential energy becomes...", "choices": ["twice as large", "four times as large", "half as large", "unchanged"], "answer_index": 0, "hint": "GPE changes directly with mass.", "tags": ["gravitational_potential_energy_error"]},
                {"kind": "short", "id": "M3L3_D3", "prompt": "A 3 kg object is raised 5 m. Use g = 10 N/kg. What GPE gain occurs?", "accepted_answers": ["150 J", "150"], "hint": "Use GPE = mgh.", "tags": ["gravitational_potential_energy_error"]},
            ],
            "inquiry": [
                {"prompt": "Hold mass fixed and vary the height.", "hint": "Watch the height shelf rise in direct proportion."},
                {"prompt": "Hold height fixed and vary the mass.", "hint": "Heavier objects gain more energy at the same height."},
            ],
            "recon_prompts": [
                "Explain why doubling height and doubling mass can produce the same proportional change in GPE.",
                "Explain what the gravitational field strength contributes in the mgh relationship.",
            ],
            "capsule_prompt": "Gravitational potential energy depends on mass, field strength, and height.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L3_C1", "prompt": "If height doubles while mass and g stay the same, GPE becomes...", "choices": ["twice as large", "four times as large", "half as large", "unchanged"], "answer_index": 0, "hint": "GPE is directly proportional to height.", "tags": ["gravitational_potential_energy_error"]},
                {"kind": "mcq", "id": "M3L3_C2", "prompt": "In GPE = mgh, the symbol g stands for...", "choices": ["gravitational field strength", "grams", "gradient", "graph"], "answer_index": 0, "hint": "g describes the strength of the gravitational field.", "tags": ["gravitational_potential_energy_error"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L3_T1", "prompt": "An 8 kg box is lifted onto a shelf 2 m high. Use g = 10 N/kg. What GPE gain occurs?", "accepted_answers": ["160 J", "160"], "hint": "Multiply mass, field strength, and height.", "tags": ["gravitational_potential_energy_error"]},
                {"kind": "mcq", "id": "M3L3_T2", "prompt": "Which object gains more GPE when lifted through the same height?", "choices": ["the heavier object", "the lighter object", "both gain the same regardless of mass", "the object with the brighter color"], "answer_index": 0, "hint": "At the same height, larger mass means larger GPE gain.", "tags": ["gravitational_potential_energy_error"]},
                {"kind": "short", "id": "M3L3_T3", "prompt": "A 5 kg climber gains 250 J of GPE. Use g = 10 N/kg. How high did the climber rise?", "accepted_answers": ["5 m", "5"], "hint": "Rearrange 250 = 5 x 10 x h.", "tags": ["gravitational_potential_energy_error", "energy_transfer_calculation_error"]},
            ],
            "contract": {
                "concept_targets": [
                    "Calculate gravitational potential energy from mass, g, and height.",
                    "Explain direct proportionality in the mgh relationship.",
                ],
                "prerequisite_lessons": ["F3_L2", "M3_L1"],
                "misconception_focus": ["gravitational_potential_energy_error"],
                "formulas": [
                    {"equation": "GPE = mgh", "meaning": "Gravitational potential energy depends on mass, field strength, and height gain.", "units": ["J"], "conditions": "Use near Earth's surface for height changes."}
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain why lifted objects gain gravitational potential energy."},
                    {"kind": "diagram", "purpose": "Show height gain and reference level clearly."},
                    {"kind": "formula", "purpose": "Calculate GPE numerically."},
                ],
                "analogy_map": {
                    "comparison": "The height shelf stands for stored gravitational potential energy.",
                    "mapping": ["Higher placement stands for larger height gain.", "A heavier object stands for a larger mass term on the shelf."],
                    "limit": "Energy is not literally stacked on a visible shelf.",
                    "prediction_prompt": "If two objects rise through the same height, what happens when one has twice the mass?",
                },
                "worked_examples": [
                    {"prompt": "A 4 kg bag is lifted 3 m. Use g = 10 N/kg. Find the GPE gain.", "steps": ["Write GPE = mgh.", "Substitute 4, 10, and 3.", "Multiply to get 120."], "final_answer": "120 J", "why_it_matters": "This anchors the three-factor structure of the equation."},
                    {"prompt": "A learner says doubling height matters but doubling mass does not. Evaluate the claim.", "steps": ["Inspect the m and h terms in GPE = mgh.", "Notice that both mass and height affect GPE directly.", "Conclude that the claim is wrong."], "final_answer": "The claim is wrong.", "why_it_matters": "This blocks one-variable reasoning in GPE problems."},
                ],
                "visual_assets": [
                    {"asset_id": "m3-l3-gravitational-potential-energy", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Height changes gravitational potential energy", "purpose": "Show how mass and height change the height store.", "caption": "Gravitational potential energy grows with mass and height."}
                ],
                "animation_assets": [
                    {"asset_id": "m3-l3-gravitational-potential-energy-anim", "concept": "energy_stores", "phase_key": "analogical_grounding", "title": "Height store comparison", "description": "Animate objects rising to different heights and masses on the height store.", "duration_sec": 8}
                ],
                "simulation_contract": {
                    "asset_id": "m3_l3_gravitational_potential_energy_lab",
                    "concept": "energy_stores",
                    "baseline_case": "Start with a 2 kg object lifted 3 m using g = 10 N/kg.",
                    "comparison_tasks": ["Double the height while keeping mass fixed.", "Double the mass while keeping height fixed."],
                    "watch_for": "Students should keep the three factors of mgh separate and proportional.",
                    "takeaway": "Gravitational potential energy depends on mass, field strength, and height.",
                },
                "reflection_prompts": ["Explain why the same height gain does not give every object the same GPE gain."],
                "mastery_skills": [
                    "Calculate GPE.",
                    "Compare mass and height effects directly.",
                    "Use g correctly in simple problems.",
                    "Rearrange the mgh relationship.",
                    "Reject one-variable-only explanations.",
                ],
                "variation_plan": {
                    "diagnostic": "Rotate direct calculations, proportionality comparisons, and g-meaning prompts.",
                    "concept_gate": "Swap between numerical GPE items and mass-versus-height reasoning.",
                    "mastery": "Vary mass, height, and rearrangement steps without repeating the same story.",
                },
            },
        },
        {
            "id": "M3_L4",
            "title": "Power Equations",
            "sim": {
                "lab_id": "m3_power_equations_lab",
                "title": "Power rate explorer",
                "description": "Compare the same energy transfer across different times and rates.",
                "instructions": ["Keep energy fixed and change the time.", "Keep time fixed and change the energy transferred.", "Compare power and total energy as separate ideas."],
                "outcomes": ["power_rate_confusion", "energy_transfer_calculation_error"],
                "fields": ["energy_transferred", "time_taken", "power", "rate_reasoning"],
                "depth": "number of energy-time comparisons explained correctly through transfer rate",
            },
            "analogy_text": "The Rate Meter on Energy Ledger shows how many joules are transferred each second. Power is transfer rate, not total energy itself.",
            "commitment_prompt": "Decide whether the question asks for total energy, time, or transfer rate before choosing the equation.",
            "micro_prompts": [
                {"prompt": "Compare 600 J transferred in 10 s with 600 J transferred in 20 s.", "hint": "The total is the same, but the rate is different."},
                {"prompt": "Compare 300 J in 5 s with 600 J in 10 s.", "hint": "Different numbers can still produce the same power if the ratio matches."},
            ],
            "diagnostic": [
                {"kind": "mcq", "id": "M3L4_D1", "prompt": "Power tells you...", "choices": ["energy transferred each second", "total energy only", "mass multiplied by height", "the useful fraction only"], "answer_index": 0, "hint": "Power is a rate of energy transfer.", "tags": ["power_rate_confusion"]},
                {"kind": "short", "id": "M3L4_D2", "prompt": "A motor transfers 240 J in 12 s. What power does it have?", "accepted_answers": ["20 W", "20"], "hint": "Use P = E / t.", "tags": ["power_rate_confusion"]},
                {"kind": "mcq", "id": "M3L4_D3", "prompt": "Two machines transfer the same energy, but one does it in less time. Which is more powerful?", "choices": ["the faster one", "the slower one", "they are equally powerful", "the heavier one"], "answer_index": 0, "hint": "Less time for the same energy means a greater rate.", "tags": ["power_rate_confusion"]},
            ],
            "inquiry": [
                {"prompt": "Keep the total energy the same and change only the time.", "hint": "The rate meter changes even when the total stays fixed."},
                {"prompt": "Keep time fixed and increase the energy transferred.", "hint": "A larger numerator means a larger rate."},
            ],
            "recon_prompts": [
                "Explain why power and total energy are related but not identical quantities.",
                "Explain how the same power can come from different energy-time pairs.",
            ],
            "capsule_prompt": "Power is joules per second, so the equation depends on both energy and time.",
            "capsule_checks": [
                {"kind": "mcq", "id": "M3L4_C1", "prompt": "If the same energy is transferred in half the time, the power is...", "choices": ["twice as large", "half as large", "unchanged", "zero"], "answer_index": 0, "hint": "For fixed energy, less time means higher power.", "tags": ["power_rate_confusion"]},
                {"kind": "mcq", "id": "M3L4_C2", "prompt": "1 watt is equal to...", "choices": ["1 joule per second", "1 joule per kilogram", "1 newton per metre", "1 second per joule"], "answer_index": 0, "hint": "A watt measures energy transferred each second.", "tags": ["power_rate_confusion"]},
            ],
            "transfer": [
                {"kind": "short", "id": "M3L4_T1", "prompt": "A heater transfers 1800 J in 30 s. What power does it use?", "accepted_answers": ["60 W", "60"], "hint": "Divide energy by time.", "tags": ["power_rate_confusion"]},
                {"kind": "short", "id": "M3L4_T2", "prompt": "A machine runs at 50 W for 8 s. How much energy does it transfer?", "accepted_answers": ["400 J", "400"], "hint": "Use E = Pt.", "tags": ["power_rate_confusion", "energy_transfer_calculation_error"]},
                {"kind": "mcq", "id": "M3L4_T3", "prompt": "Which device is more powerful?", "choices": ["the one transferring 900 J in 15 s", "the one transferring 900 J in 30 s", "they are the same", "the answer depends only on mass"], "answer_index": 0, "hint": "Compare energy per second, not energy alone.", "tags": ["power_rate_confusion"]},
            ],
            "contract": {
                "concept_targets": [
                    "Use power as the rate of energy transfer.",
                    "Move flexibly between P = E / t and E = Pt.",
                ],
                "prerequisite_lessons": ["F3_L3", "M3_L1"],
                "misconception_focus": ["power_rate_confusion", "energy_transfer_calculation_error"],
                "formulas": [
                    {"equation": "P = E / t", "meaning": "Power is the rate at which energy is transferred.", "units": ["W", "J/s"], "conditions": "Use when total energy transfer and time are known."},
                    {"equation": "E = Pt", "meaning": "Total energy transferred equals power multiplied by time.", "units": ["J"], "conditions": "Use when power is steady over the time interval."},
                ],
                "representations": [
                    {"kind": "words", "purpose": "Explain transfer rate in plain language."},
                    {"kind": "table", "purpose": "Compare energy, time, and power across several devices."},
                    {"kind": "formula", "purpose": "Calculate power or energy numerically."},
                ],
                "analogy_map": {
                    "comparison": "The Rate Meter stands for how quickly the ledger records transferred energy.",
                    "mapping": ["A faster ticking meter stands for larger power.", "A longer run time stands for more time over which transfer continues."],
                    "limit": "A real system does not contain a literal meter deciding its power.",
                    "prediction_prompt": "If two devices transfer the same energy but one does it faster, what changes?",
                },
                "worked_examples": [
                    {"prompt": "A heater transfers 900 J in 15 s. Find the power.", "steps": ["Write P = E / t.", "Substitute 900 and 15.", "Divide to get 60."], "final_answer": "60 W", "why_it_matters": "This ties power directly to rate."},
                    {"prompt": "A learner says power and total energy are the same thing. Evaluate the claim.", "steps": ["Recall that power measures energy per second.", "Notice that total energy also depends on how long the transfer lasts.", "Conclude that the claim is wrong."], "final_answer": "The claim is wrong.", "why_it_matters": "This prevents students from collapsing rate into amount."},
                ],
                "visual_assets": [
                    {"asset_id": "m3-l4-power-equations", "concept": "power_rate", "phase_key": "analogical_grounding", "title": "Power compares transfer rate", "purpose": "Show the same energy transferred over different times.", "caption": "Power is how fast energy is transferred."}
                ],
                "animation_assets": [
                    {"asset_id": "m3-l4-power-equations-anim", "concept": "power_rate", "phase_key": "analogical_grounding", "title": "Rate meter comparison", "description": "Animate identical energy transfers happening over different time intervals.", "duration_sec": 8}
                ],
                "simulation_contract": {
                    "asset_id": "m3_l4_power_equations_lab",
                    "concept": "power_rate",
                    "baseline_case": "Start with 600 J transferred in 20 s.",
                    "comparison_tasks": ["Keep energy fixed and shorten the time.", "Keep time fixed and increase the energy transferred."],
                    "watch_for": "Students should keep total energy separate from the rate of transfer.",
                    "takeaway": "Power tells how quickly energy is transferred.",
                },
                "reflection_prompts": ["Explain how two devices can transfer different total energies yet have the same power."],
                "mastery_skills": [
                    "Calculate power from energy and time.",
                    "Calculate energy from power and time.",
                    "Interpret watts as joules per second.",
                    "Compare rates qualitatively.",
                    "Avoid confusing amount with rate.",
                ],
                "variation_plan": {
                    "diagnostic": "Rotate rate-definition, direct P = E / t, and same-energy-different-time prompts.",
                    "concept_gate": "Swap between unit-meaning checks and rearrangement questions.",
                    "mastery": "Vary energy, time, and rate-comparison contexts without repeating the same stem.",
                },
            },
        },
    ]
)


M3_SPEC["lessons"] = sorted(
    M3_SPEC["lessons"],
    key=lambda lesson: int(str(lesson["id"]).split("_L")[-1]),
)


RELEASE_CHECKS = [
    "Every formula is taught with meaning, units, and conditions before mastery uses it.",
    "Every lesson includes a generated visual asset and a usable simulation contract.",
    "Work, stores, power, and efficiency stay distinct instead of collapsing into one slogan.",
    "Extended calculation prompts require correct equation choice, substitution, and unit checks.",
]


M3_MODULE_DOC, M3_LESSONS, M3_SIM_LABS = build_nextgen_module_bundle(
    module_id=M3_MODULE_ID,
    module_title="Energy, Work & Power",
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
