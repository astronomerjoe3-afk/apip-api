from __future__ import annotations

import argparse
import json
from copy import deepcopy
from typing import Any, Dict, List, Tuple

try:
    from scripts.lesson_authoring_contract import validate_nextgen_module
    from scripts.module_asset_pipeline import default_asset_root, plan_module_assets, render_module_assets
    from scripts.nextgen_module_scaffold import build_nextgen_module_scaffold
except ModuleNotFoundError:
    from lesson_authoring_contract import validate_nextgen_module
    from module_asset_pipeline import default_asset_root, plan_module_assets, render_module_assets
    from nextgen_module_scaffold import build_nextgen_module_scaffold

M2_MODULE_ID = "M2"
M2_CONTENT_VERSION = "20260317_m2_force_systems_v2"
M2_ALLOWLIST = [
    "motion_implies_force_confusion",
    "balanced_force_rest_confusion",
    "resultant_force_vector_confusion",
    "newton_first_law_confusion",
    "force_mass_acceleration_confusion",
    "third_law_pair_confusion",
    "momentum_force_confusion",
    "momentum_conservation_system_confusion",
    "torque_force_location_confusion",
    "centre_of_mass_material_confusion",
    "stability_weight_confusion",
    "vector_resolution_component_confusion",
]
M2_SPEC = json.loads(r'''
{
  "module_description": "Module 2 uses Thruster-Deck to connect force arrows, motion change, collisions, spin, balance, and vector resolution: what arrows act, where they act, and how hard the craft is to change.",
  "mastery_outcomes": [
    "Combine drive arrows into one Master Arrow and explain why zero Master Arrow means no motion change rather than no motion.",
    "Use Newton's laws to connect resultant force, mass, inertia, and acceleration in words and calculations.",
    "Distinguish Carry Score from force and use system-level momentum conservation in closed dock exchanges.",
    "Explain turning effect as the product of push size and perpendicular reach rather than as force alone.",
    "Use Balance Core and Footprint Zone reasoning to predict centre-of-mass shifts, stability, and tipping.",
    "Resolve angled drive arrows into components and reassemble resultants without treating diagonal vectors as mysterious."
  ],
  "lessons": [
    {
      "id": "M2_L1",
      "title": "Resultant Forces and Cruise State",
      "sim": {
        "lab_id": "m2_resultant_force_lab",
        "title": "Master Arrow explorer",
        "description": "Use visible drive arrows to combine pushes into one Master Arrow and separate zero net force from zero motion.",
        "instructions": [
          "Build one balanced-thruster case and one unbalanced-thruster case.",
          "Keep the craft already cruising while you change the Master Arrow to zero.",
          "Compare two different arrow sets that lead to the same Master Arrow."
        ],
        "outcomes": [
          "resultant_force_vector_confusion",
          "motion_implies_force_confusion",
          "balanced_force_rest_confusion"
        ],
        "fields": [
          "forward_drive_arrow",
          "backward_drive_arrow",
          "side_drive_arrow",
          "master_arrow_explanations"
        ],
        "depth": "number of arrow combinations explained correctly in terms of Master Arrow and cruise-state reasoning"
      },
      "analogy_text": "Drive Arrows are the pushes acting now, but the craft responds to their combined Master Arrow. The Master Arrow is what decides whether motion changes.",
      "commitment_prompt": "Before you answer, decide whether the question is about individual Drive Arrows or the combined Master Arrow.",
      "micro_prompts": [
        { "prompt": "Compare a craft with two equal opposite thrusters to one craft with no thrusters firing at all.", "hint": "Both can have zero Master Arrow, but only one case still contains forces." },
        { "prompt": "Compare a stopped craft with zero Master Arrow and a cruising craft with zero Master Arrow.", "hint": "Zero Master Arrow means no motion change, not automatically no motion." }
      ],
      "diagnostic": [
        { "kind": "mcq", "id": "M2L1_D1", "prompt": "In the Thruster-Deck model, the Master Arrow stands for...", "choices": ["the combined overall push on the craft", "the speed of the craft", "the mass of the craft", "the momentum of the craft"], "answer_index": 0, "hint": "The Master Arrow is the combined or resultant force.", "tags": ["resultant_force_vector_confusion"] },
        { "kind": "mcq", "id": "M2L1_D2", "prompt": "A cargo craft is already cruising right with zero Master Arrow. What happens next on a friction-free deck?", "choices": ["it keeps cruising at constant velocity", "it must slow down and stop", "it must speed up to the right", "it must turn around"], "answer_index": 0, "hint": "Zero net force means zero acceleration, so the motion stays unchanged.", "tags": ["motion_implies_force_confusion", "balanced_force_rest_confusion", "newton_first_law_confusion"] },
        { "kind": "short", "id": "M2L1_D3", "prompt": "Two Drive Arrows act on the same craft: 9 N forward and 4 N backward. What is the Master Arrow?", "accepted_answers": ["5 N forward", "5 forward", "5 N"], "hint": "Subtract opposite arrows and keep the direction of the larger side.", "tags": ["resultant_force_vector_confusion"] }
      ],
      "inquiry": [
        { "prompt": "Match three different Drive Arrow sets to the same Master Arrow.", "hint": "Many different force sets can collapse into one overall push." },
        { "prompt": "Keep the Master Arrow at zero while switching between stopped and cruising start states.", "hint": "Zero net force does not force one particular velocity value." }
      ],
      "recon_prompts": [
        "Explain why the Master Arrow matters more than any one Drive Arrow when you predict motion change.",
        "Explain why zero Master Arrow can describe both rest and steady cruising."
      ],
      "capsule_prompt": "Combine the arrows first, then decide whether the craft changes its motion.",
      "capsule_checks": [
        { "kind": "mcq", "id": "M2L1_C1", "prompt": "If the Master Arrow is zero, the acceleration is...", "choices": ["zero", "always forward", "always backward", "equal to the speed"], "answer_index": 0, "hint": "Zero resultant force means zero acceleration.", "tags": ["newton_first_law_confusion", "balanced_force_rest_confusion"] },
        { "kind": "short", "id": "M2L1_C2", "prompt": "A craft has 12 N left and 3 N right. What Master Arrow remains?", "accepted_answers": ["9 N left", "9 left", "9 N"], "hint": "Subtract opposite sides and keep the direction of the larger side.", "tags": ["resultant_force_vector_confusion"] }
      ],
      "transfer": [
        { "kind": "mcq", "id": "M2L1_T1", "prompt": "Which question is the Master Arrow meant to answer most directly?", "choices": ["how the craft's motion changes", "what speed the craft already has", "how heavy the craft is", "what route shape it follows"], "answer_index": 0, "hint": "The Master Arrow is the combined force story, so it decides acceleration.", "tags": ["resultant_force_vector_confusion", "motion_implies_force_confusion"] },
        { "kind": "mcq", "id": "M2L1_T2", "prompt": "Balanced Drive Arrows mean that the craft...", "choices": ["has zero acceleration and can be resting or cruising steadily", "must be at rest", "must move forward", "must have no forces at all"], "answer_index": 0, "hint": "Balanced forces tell you about acceleration, not about a guaranteed speed.", "tags": ["balanced_force_rest_confusion", "motion_implies_force_confusion"] },
        { "kind": "mcq", "id": "M2L1_T3", "prompt": "A craft has zero Master Arrow while moving north. Which motion story fits?", "choices": ["constant velocity north", "speeding up north", "stopping immediately", "accelerating south"], "answer_index": 0, "hint": "With zero net force, the existing motion continues unchanged.", "tags": ["newton_first_law_confusion", "motion_implies_force_confusion"] }
      ],
      "contract": {
        "concept_targets": [
          "Treat resultant force as the vector sum of all Drive Arrows.",
          "Use Newton's first-law reasoning to separate zero net force from zero motion."
        ],
        "prerequisite_lessons": ["F2_L5", "F2_L6", "M1_L3"],
        "misconception_focus": ["motion_implies_force_confusion", "balanced_force_rest_confusion", "resultant_force_vector_confusion", "newton_first_law_confusion"],
        "formulas": [
          { "equation": "F_net = sum of forces", "meaning": "The resultant force is the combined vector effect of all the forces acting on the craft.", "units": ["N"], "conditions": "Use after accounting for direction." },
          { "equation": "F_net = 0 -> a = 0", "meaning": "Zero resultant force means zero acceleration, so the motion does not change.", "units": ["m/s^2"], "conditions": "Use for balanced-force stories." }
        ],
        "representations": [
          { "kind": "words", "purpose": "Separate individual Drive Arrows from the single Master Arrow." },
          { "kind": "diagram", "purpose": "Use force-arrow diagrams to combine forces." },
          { "kind": "formula", "purpose": "Link the combined force to the zero-acceleration case." }
        ],
        "analogy_map": {
          "comparison": "Drive Arrows are force vectors and the Master Arrow is the resultant force.",
          "mapping": [
            "A visible Drive Arrow stands for one push acting on the craft.",
            "The Master Arrow stands for the combined overall push that determines motion change."
          ],
          "limit": "Real objects do not show cartoon arrows floating beside them; the model is only making force direction and combination visible.",
          "prediction_prompt": "If two opposite Drive Arrows cancel to zero, what can the craft still be doing?"
        },
        "worked_examples": [
          {
            "prompt": "A craft is moving west at 3 m/s while 14 N east and 9 N west act on it. Find the Master Arrow and predict the immediate motion change.",
            "steps": [
              "Combine the opposite Drive Arrows first because they act along the same line: 14 N east and 9 N west leave 5 N east.",
              "That leftover 5 N east is the Master Arrow, so the acceleration points east because the resultant force sets the motion change.",
              "Keep the current velocity separate from the new acceleration: the craft is still moving west at this moment.",
              "An eastward acceleration acting on a westward-moving craft makes it slow down first rather than instantly reverse direction."
            ],
            "final_answer": "Master Arrow = 5 N east, so the craft accelerates east; because it was moving west, it immediately slows down while still traveling west.",
            "why_it_matters": "This forces students to separate current motion from the new motion change caused by the resultant force."
          },
          {
            "prompt": "A craft cruises east at 5 m/s with 7 N forward and 7 N backward. Evaluate the claim that it must stop because the Master Arrow is zero.",
            "steps": [
              "Equal opposite forces give a zero Master Arrow because 7 N forward cancels 7 N backward.",
              "Zero Master Arrow means zero acceleration, so the velocity does not change.",
              "The craft already has a velocity of 5 m/s east, and with zero acceleration that existing motion can continue unchanged.",
              "So no resultant force does not demand rest; it only means there is no motion change."
            ],
            "final_answer": "The claim is wrong: zero Master Arrow means zero acceleration, so the craft can keep cruising east at 5 m/s because its motion is not changing.",
            "why_it_matters": "This directly blocks the classic motion-implies-force misconception with a concrete cruising example."
          }
        ],
        "visual_assets": [
          { "asset_id": "m2-l1-master-arrow.svg", "purpose": "Show multiple Drive Arrows combining into one Master Arrow and contrast zero Master Arrow at rest with zero Master Arrow in cruise.", "caption": "The diagram keeps balanced-force and constant-velocity reasoning in the same visual world." }
        ],
        "simulation_contract": {
          "baseline_case": "Start with 10 N forward and 6 N backward on a craft that is already cruising.",
          "comparison_tasks": ["Set equal opposite arrows to make zero Master Arrow.", "Create two different arrow sets that produce the same Master Arrow."],
          "watch_for": "Students should talk about the combined Master Arrow before they talk about the motion.",
          "takeaway": "Motion changes only when the Master Arrow is non-zero; motion can continue unchanged even when the Master Arrow is zero."
        },
        "reflection_prompts": ["Explain how the Thruster-Deck model helps you reject the idea that motion always needs a continuing force."],
        "mastery_skills": ["Combine same-line forces into a resultant.", "Recognize balanced and unbalanced force cases.", "Predict acceleration direction from the resultant force.", "Explain zero net force without forcing zero velocity.", "Reject motion-implies-force reasoning."],
        "variation_plan": {
          "diagnostic": "Rotate between opposite-force subtraction, same-direction addition, and steady-cruise misconception checks.",
          "concept_gate": "Switch between zero-resultant motion stories and diagram-based Master Arrow questions on retries.",
          "mastery": "Use new arrow sets, cruising contexts, and vector-language stems so repeated attempts do not reuse the same story frame."
        }
      }
    },
    {
      "id": "M2_L2",
      "title": "Load Rating, Motion Shift, and Newton Laws",
      "sim": {
        "lab_id": "m2_motion_shift_lab",
        "title": "Load rating explorer",
        "description": "Compare how the same Master Arrow changes light and heavy craft, then separate force pairs from acceleration outcomes.",
        "instructions": ["Run the same Master Arrow on light and heavy craft.", "Double the Master Arrow while the load stays fixed.", "Compare equal and opposite interaction arrows on two different craft."],
        "outcomes": ["force_mass_acceleration_confusion", "third_law_pair_confusion", "motion_implies_force_confusion"],
        "fields": ["master_arrow", "load_rating", "motion_shift", "interaction_pair_explanations"],
        "depth": "number of cases explained correctly using Master Arrow divided by Load Rating plus interaction-pair reasoning"
      },
      "analogy_text": "Load Rating tells how stubborn the craft is, while Motion Shift tells how quickly its motion changes. The same Master Arrow gives a smaller Motion Shift when the Load Rating is larger.",
      "commitment_prompt": "Before you answer, decide whether the question is about one craft responding to a Master Arrow or about two objects exerting an interaction pair.",
      "micro_prompts": [
        {"prompt": "Compare two craft with different Load Ratings under the same Master Arrow.", "hint": "The lighter craft changes motion more because the same push is shared across less mass."},
        {"prompt": "Compare the force pair in a kick interaction with the acceleration of each object.", "hint": "Equal force pair does not force equal acceleration because the masses can differ."}
      ],
      "diagnostic": [
        {"kind": "mcq", "id": "M2L2_D1", "prompt": "The same 12 N Master Arrow acts on two craft. Which craft has the larger Motion Shift?", "choices": ["the craft with the lower Load Rating", "the craft with the higher Load Rating", "both change equally", "the one already moving faster"], "answer_index": 0, "hint": "The same net force gives more acceleration when the mass is smaller.", "tags": ["force_mass_acceleration_confusion"]},
        {"kind": "mcq", "id": "M2L2_D2", "prompt": "When Craft A pushes Dock Pod B, the matching third-law force acts...", "choices": ["on B back on A", "on A in the same direction", "only on the lighter object", "only after motion starts"], "answer_index": 0, "hint": "The matched pair acts on two different objects.", "tags": ["third_law_pair_confusion"]},
        {"kind": "short", "id": "M2L2_D3", "prompt": "A 15 N Master Arrow acts on a 5 kg craft. What Motion Shift occurs?", "accepted_answers": ["3 m/s^2", "3", "3 m/s/s"], "hint": "Use acceleration equals net force divided by mass.", "tags": ["force_mass_acceleration_confusion"]}
      ],
      "inquiry": [
        {"prompt": "Keep the Master Arrow fixed and slide the Load Rating up and down.", "hint": "Watch the Motion Shift shrink as the craft becomes harder to change."},
        {"prompt": "Compare one interaction pair on two craft with different masses.", "hint": "Equal force pair can still produce different acceleration outcomes."}
      ],
      "recon_prompts": ["Explain why force changes motion rather than causing motion to exist.", "Explain why equal third-law forces do not guarantee equal acceleration."],
      "capsule_prompt": "Combine forces into the Master Arrow, then compare that push with the Load Rating.",
      "capsule_checks": [
        {"kind": "mcq", "id": "M2L2_C1", "prompt": "For the same Master Arrow, increasing the Load Rating makes the Motion Shift...", "choices": ["smaller", "larger", "unchanged", "equal to the speed"], "answer_index": 0, "hint": "Mass resists motion change.", "tags": ["force_mass_acceleration_confusion"]},
        {"kind": "mcq", "id": "M2L2_C2", "prompt": "Third-law force pairs are equal and opposite, but they act on...", "choices": ["different objects", "the same object", "only moving objects", "only equal masses"], "answer_index": 0, "hint": "Matched force pairs act across an interaction.", "tags": ["third_law_pair_confusion"]}
      ],
      "transfer": [
        {"kind": "mcq", "id": "M2L2_T1", "prompt": "If the same craft experiences twice the Master Arrow, the acceleration is...", "choices": ["twice as large", "half as large", "unchanged", "zero"], "answer_index": 0, "hint": "For fixed mass, acceleration tracks net force.", "tags": ["force_mass_acceleration_confusion"]},
        {"kind": "mcq", "id": "M2L2_T2", "prompt": "Why can equal and opposite third-law forces still produce different motion changes?", "choices": ["the masses can differ", "one force is actually larger", "only one object feels the force", "the pair cancels because it acts on one object"], "answer_index": 0, "hint": "Force pair equality does not erase mass differences.", "tags": ["third_law_pair_confusion", "force_mass_acceleration_confusion"]},
        {"kind": "short", "id": "M2L2_T3", "prompt": "A 20 N Master Arrow acts on a 4 kg craft. What Motion Shift occurs?", "accepted_answers": ["5 m/s^2", "5", "5 m/s/s"], "hint": "Acceleration is net force divided by mass.", "tags": ["force_mass_acceleration_confusion"]}
      ],
      "contract": {
        "concept_targets": ["Use the same Master Arrow with different Load Ratings to reason about acceleration.", "Treat third-law forces as matched interaction arrows on different objects."],
        "prerequisite_lessons": ["F2_L6", "M2_L1"],
        "misconception_focus": ["force_mass_acceleration_confusion", "third_law_pair_confusion", "motion_implies_force_confusion"],
        "formulas": [
          {"equation": "a = F_net / m", "meaning": "Acceleration comes from the net force shared across the mass of the craft.", "units": ["m/s^2"], "conditions": "Use after combining forces into the Master Arrow."},
          {"equation": "F_net = ma", "meaning": "Net force equals mass times acceleration, so mass and acceleration must be read together.", "units": ["N"], "conditions": "Use for one object after identifying the resultant force."}
        ],
        "representations": [
          {"kind": "words", "purpose": "Link Master Arrow, Load Rating, and Motion Shift in one sentence."},
          {"kind": "diagram", "purpose": "Show matched interaction arrows on two different objects."},
          {"kind": "formula", "purpose": "Summarize how force and mass set acceleration."}
        ],
        "analogy_map": {
          "comparison": "Load Rating maps to mass, Motion Shift maps to acceleration, and the Master Arrow maps to net force.",
          "mapping": ["A heavier cargo craft is harder to change because it has more mass.", "A larger Motion Shift means the velocity changes faster because the net force is larger for that mass."],
          "limit": "Real engines and interactions are messier than the model, but the analogy keeps the force and mass structure visible.",
          "prediction_prompt": "If the same Master Arrow acts on a lighter and a heavier craft, which one changes motion more and why?"
        },
        "worked_examples": [
          {
            "prompt": "The same 18 N Master Arrow acts east on a 3 kg scout and a 6 kg freighter. Find each Motion Shift and explain the difference.",
            "steps": [
              "Use the one-object rule a = F_net / m for each craft because the question is about response to the same Master Arrow.",
              "For the 3 kg scout, a = 18 / 3 = 6 m/s^2 east.",
              "For the 6 kg freighter, a = 18 / 6 = 3 m/s^2 east.",
              "The scout accelerates more because the same net force is shared across less mass, so the Motion Shift is larger."
            ],
            "final_answer": "Scout: 6 m/s^2 east; freighter: 3 m/s^2 east, because the same Master Arrow produces a bigger Motion Shift when less mass resists the change.",
            "why_it_matters": "This keeps force, mass, and acceleration tied together in one comparison rather than as isolated facts."
          },
          {
            "prompt": "During a collision, a sensor shows an 8 N force on a 2 kg pod and an 8 N opposite force on a 4 kg pod. Evaluate the claim that the heavier pod pushes back harder.",
            "steps": [
              "Use Newton's third law first: the interaction forces on the two objects must be equal in size and opposite in direction.",
              "So neither object pushes harder here; both forces are 8 N.",
              "Now compare the responses with a = F / m: the 2 kg pod gets 8 / 2 = 4 m/s^2, while the 4 kg pod gets 8 / 4 = 2 m/s^2.",
              "The heavier pod accelerates less because it has more mass, not because it pushes back harder."
            ],
            "final_answer": "The claim is wrong: the force pair is 8 N on each object, but the 2 kg pod accelerates at 4 m/s^2 and the 4 kg pod at 2 m/s^2 because equal forces on different masses give different accelerations.",
            "why_it_matters": "This cleanly separates third-law force equality from second-law acceleration differences."
          }
        ],
        "visual_assets": [
          {"asset_id": "m2-l2-load-rating.svg", "purpose": "Compare the same Master Arrow on a light and heavy craft and place the matched third-law pair on two objects.", "caption": "The diagram keeps mass, acceleration, and interaction-pair reasoning visible together."}
        ],
        "simulation_contract": {
          "baseline_case": "Start with one 10 N Master Arrow on a craft of 2 kg, then compare with 5 kg.",
          "comparison_tasks": ["Keep the force fixed and vary the Load Rating.", "Keep the Load Rating fixed and vary the Master Arrow."],
          "watch_for": "Students should name the net force first and the mass second before predicting acceleration.",
          "takeaway": "Acceleration depends on both the Master Arrow and the Load Rating, while third-law pairs act on different objects."
        },
        "reflection_prompts": ["Explain how Thruster-Deck helps you separate equal interaction forces from unequal acceleration outcomes."],
        "mastery_skills": ["Use F equals ma with the net force.", "Compare mass effects under the same force.", "Recognize Newton first and second law stories.", "Identify third-law force pairs correctly.", "Reject the heavier-object-pushes-back-harder misconception."],
        "variation_plan": {
          "diagnostic": "Rotate between same-force-different-mass stories, direct acceleration calculations, and third-law pair identification.",
          "concept_gate": "Swap between conceptual comparison items and matched-pair recognition on retries.",
          "mastery": "Vary force values, masses, and interaction stories so students cannot rely on one memorized template."
        }
      }
    },
    {
      "id": "M2_L3",
      "title": "Carry Score and Dock Exchange",
      "sim": {
        "lab_id": "m2_dock_exchange_lab",
        "title": "Dock exchange explorer",
        "description": "Track Carry Score through docking missions so momentum is seen as carried motion rather than as force.",
        "instructions": ["Compare a light fast craft with a heavy slower craft.", "Dock two craft and predict the shared motion.", "Keep the dock closed while total Carry Score is redistributed."],
        "outcomes": ["momentum_force_confusion", "momentum_conservation_system_confusion"],
        "fields": ["load_rating", "speed", "carry_score", "system_total"],
        "depth": "number of collision stories explained with system momentum rather than single-object force language"
      },
      "analogy_text": "Carry Score belongs to a moving craft because of both its load and its speed. In a closed dock exchange, the system total is shared rather than lost.",
      "commitment_prompt": "Before you answer, decide whether the question is about one object carry score or the total carry score of the closed dock.",
      "micro_prompts": [
        {"prompt": "Compare a heavy slow craft with a light fast craft.", "hint": "Carry Score depends on both mass and speed, so do not compare speed alone."},
        {"prompt": "Treat the docking pair as one closed system before and after impact.", "hint": "Conserve the total Carry Score of the system, not one object by itself."}
      ],
      "diagnostic": [
        {"kind": "mcq", "id": "M2L3_D1", "prompt": "Which craft has the greater Carry Score?", "choices": ["a 4 kg craft at 3 m/s", "a 2 kg craft at 5 m/s", "they have the same Carry Score", "speed alone decides"], "answer_index": 0, "hint": "Momentum uses both mass and velocity.", "tags": ["momentum_force_confusion"]},
        {"kind": "mcq", "id": "M2L3_D2", "prompt": "In a closed dock collision, what is conserved?", "choices": ["the total Carry Score of the system", "the speed of each object", "the force on one object", "the mass of the lighter object only"], "answer_index": 0, "hint": "Conserve system momentum, not each object speed.", "tags": ["momentum_conservation_system_confusion"]},
        {"kind": "short", "id": "M2L3_D3", "prompt": "A 3 kg craft moves at 4 m/s. What Carry Score does it have?", "accepted_answers": ["12 kg m/s", "12", "12 Ns"], "hint": "Momentum equals mass times velocity.", "tags": ["momentum_force_confusion"]}
      ],
      "inquiry": [
        {"prompt": "Hold the dock closed and compare system total before and after impact.", "hint": "The distribution can change while the total stays fixed."},
        {"prompt": "Dock two craft and solve for the shared final speed.", "hint": "Add the total Carry Score first, then divide by the combined mass if they stick."}
      ],
      "recon_prompts": ["Explain why momentum is not the same thing as force.", "Explain why conservation belongs to the closed system total rather than to one object alone."],
      "capsule_prompt": "Track the total Carry Score of the dock system before you talk about the final motion.",
      "capsule_checks": [
        {"kind": "mcq", "id": "M2L3_C1", "prompt": "Why can a heavy slow craft and a light fast craft have the same Carry Score?", "choices": ["because momentum depends on both mass and speed", "because only force matters", "because speed never matters", "because all moving craft have equal Carry Score"], "answer_index": 0, "hint": "Momentum combines mass with velocity.", "tags": ["momentum_force_confusion"]},
        {"kind": "mcq", "id": "M2L3_C2", "prompt": "What is the strongest reason to draw a system boundary around both craft in a collision?", "choices": ["to conserve total momentum of the closed system", "to make each speed stay fixed", "to remove mass from the problem", "to turn force into energy"], "answer_index": 0, "hint": "Use the whole system for conservation reasoning.", "tags": ["momentum_conservation_system_confusion"]}
      ],
      "transfer": [
        {"kind": "mcq", "id": "M2L3_T1", "prompt": "A learner says the faster craft must always have the larger Carry Score. Best correction?", "choices": ["mass matters too, so speed alone does not decide", "speed alone always decides", "force equals momentum", "Carry Score belongs only to heavy objects"], "answer_index": 0, "hint": "Momentum depends on both mass and velocity.", "tags": ["momentum_force_confusion"]},
        {"kind": "mcq", "id": "M2L3_T2", "prompt": "When two craft dock in a closed bay, what can change while total momentum stays fixed?", "choices": ["the way the total is shared between craft", "the total system momentum", "the total mass of the system", "the fact that time passes"], "answer_index": 0, "hint": "Redistribution is allowed even when the total is conserved.", "tags": ["momentum_conservation_system_confusion"]},
        {"kind": "short", "id": "M2L3_T3", "prompt": "Two 2 kg craft stick together. One moves at 4 m/s and the other is at rest. What common speed do they have after docking?", "accepted_answers": ["2 m/s", "2"], "hint": "Conserve momentum then divide by the combined mass.", "tags": ["momentum_conservation_system_confusion"]}
      ],
      "contract": {
        "concept_targets": ["Treat momentum as carried motion rather than as force.", "Use a closed-system view when you conserve momentum."],
        "prerequisite_lessons": ["F3_L4", "F3_L5", "M2_L2"],
        "misconception_focus": ["momentum_force_confusion", "momentum_conservation_system_confusion"],
        "formulas": [
          {"equation": "p = mv", "meaning": "Momentum combines mass and velocity into one carried-motion quantity.", "units": ["kg m/s"], "conditions": "Use for one moving object."},
          {"equation": "total p before = total p after", "meaning": "In a closed system, momentum is redistributed rather than created or destroyed.", "units": ["kg m/s"], "conditions": "Use when external forces are negligible."}
        ],
        "representations": [
          {"kind": "words", "purpose": "Differentiate momentum from force and from speed alone."},
          {"kind": "diagram", "purpose": "Show the system boundary and the share of momentum before and after docking."},
          {"kind": "formula", "purpose": "Summarize single-object momentum and system conservation."}
        ],
        "analogy_map": {
          "comparison": "Carry Score maps to momentum and Dock Exchange maps to momentum conservation in a closed system.",
          "mapping": ["A heavy or fast craft carries more momentum.", "A closed dock exchange redistributes the total Carry Score among the craft."],
          "limit": "Real collisions can involve deformation and external forces, so the closed-system condition must be checked.",
          "prediction_prompt": "If the total system Carry Score is 12 before docking, what must be true after docking in a closed bay?"
        },
        "worked_examples": [
          {
            "prompt": "Take east as positive. A 3 kg craft moves east at 4 m/s and docks with a 1 kg craft moving west at 2 m/s. Find the shared final velocity.",
            "steps": [
              "Calculate each signed Carry Score first: the 3 kg craft has +12 kg m/s and the 1 kg craft has -2 kg m/s.",
              "Add them to get the closed-system total before docking: +10 kg m/s.",
              "Because the craft stick together, the combined mass after docking is 4 kg and that same total momentum must still be shared by the whole system.",
              "Solve v = total momentum / combined mass = 10 / 4 = 2.5 m/s, and keep the positive sign to show the final motion is east."
            ],
            "final_answer": "The shared final velocity is 2.5 m/s east, because the closed system keeps its total +10 kg m/s Carry Score and that total is shared across 4 kg after docking.",
            "why_it_matters": "This makes students keep the system total and the sign of momentum visible all the way through the collision."
          },
          {
            "prompt": "Compare a 5 kg cargo craft moving east at 2 m/s with a 2 kg scout moving east at 5 m/s. Which has the larger Carry Score?",
            "steps": [
              "Calculate the cargo craft's Carry Score: 5 x 2 = 10 kg m/s east.",
              "Calculate the scout's Carry Score: 2 x 5 = 10 kg m/s east.",
              "The totals match even though one craft is heavier and the other is faster.",
              "So speed alone does not decide Carry Score; mass and velocity must be considered together."
            ],
            "final_answer": "They have the same Carry Score of 10 kg m/s east, because momentum depends on mass and velocity together rather than on speed alone.",
            "why_it_matters": "This directly blocks the idea that the faster object must always carry more momentum."
          }
        ],
        "visual_assets": [
          {"asset_id": "m2-l3-dock-exchange.svg", "purpose": "Show single-object Carry Score and total system momentum across a closed docking event.", "caption": "The diagram separates force talk from momentum redistribution."}
        ],
        "simulation_contract": {
          "baseline_case": "Start with a 3 kg craft moving at 4 m/s toward a 1 kg craft at rest.",
          "comparison_tasks": ["Keep the total momentum fixed while changing the mass split.", "Build two different collisions with the same system total momentum."],
          "watch_for": "Students should state the system total before they chase the final speed.",
          "takeaway": "Momentum is carried motion, and conservation belongs to the closed system total."
        },
        "reflection_prompts": ["Explain why momentum conservation is a system rule rather than a rule about one object keeping the same speed."],
        "mastery_skills": ["Calculate momentum from mass and velocity.", "Compare momentum conceptually.", "Conserve total momentum in a closed system.", "Distinguish momentum from force.", "Solve simple docking speed questions."],
        "variation_plan": {
          "diagnostic": "Rotate between speed-versus-momentum comparisons, direct p equals mv calculations, and closed-system conservation recognition.",
          "concept_gate": "Swap between single-object Carry Score items and system-boundary conservation items on retries.",
          "mastery": "Vary the masses, speeds, and collision stories so learners must reapply system reasoning instead of reusing one calculation shell."
        }
      }
    },
    {
      "id": "M2_L4",
      "title": "Spin Pull and Turning Effect",
      "sim": {
        "lab_id": "m2_spin_pull_lab",
        "title": "Spin pull explorer",
        "description": "Use off-centre pushes and reach distance to make torque a location-sensitive idea instead of another word for force.",
        "instructions": ["Push through the center line and then off-center.", "Keep force size fixed while changing the perpendicular reach.", "Compare strong-small-reach with weak-large-reach cases."],
        "outcomes": ["torque_force_location_confusion"],
        "fields": ["push_size", "perpendicular_reach", "spin_pull", "translation_vs_rotation"],
        "depth": "number of turning cases explained with both force size and line of action"
      },
      "analogy_text": "Spin Pull depends on how hard you push and how far the push line sits from the pivot. The same force can make a very different turning effect when the reach changes.",
      "commitment_prompt": "Before you answer, decide whether the question is about push size only or about push size plus perpendicular reach.",
      "micro_prompts": [
        {"prompt": "Compare the same force through the center with the same force at the edge.", "hint": "Where the force acts matters because torque needs a turning reach."},
        {"prompt": "Keep force fixed and slide the push point farther from the pivot.", "hint": "The turning effect grows when the perpendicular reach grows."}
      ],
      "diagnostic": [
        {"kind": "mcq", "id": "M2L4_D1", "prompt": "Which change makes a larger Spin Pull when the push stays the same?", "choices": ["increase the perpendicular reach", "decrease the reach", "move the push through the pivot", "remove the direction"], "answer_index": 0, "hint": "Torque depends on force and perpendicular distance.", "tags": ["torque_force_location_confusion"]},
        {"kind": "mcq", "id": "M2L4_D2", "prompt": "A push through the pivot gives what turning effect?", "choices": ["zero", "maximum", "equal to the force", "equal to the speed"], "answer_index": 0, "hint": "No perpendicular reach means no turning effect.", "tags": ["torque_force_location_confusion"]},
        {"kind": "short", "id": "M2L4_D3", "prompt": "A 6 N push acts 0.5 m from the pivot. What Spin Pull is produced?", "accepted_answers": ["3 N m", "3"], "hint": "Multiply force by perpendicular reach.", "tags": ["torque_force_location_confusion"]}
      ],
      "inquiry": [
        {"prompt": "Compare one centred push and one off-centre push with the same force.", "hint": "The off-centre push can rotate the craft because it has turning reach."},
        {"prompt": "Build two different force-reach pairs that give the same Spin Pull.", "hint": "A smaller force can match a larger one if the reach changes."}
      ],
      "recon_prompts": ["Explain why torque is not the same thing as force.", "Explain why the line of action matters when you predict rotation."],
      "capsule_prompt": "Ask how hard the push is and how far its line of action sits from the pivot.",
      "capsule_checks": [
        {"kind": "mcq", "id": "M2L4_C1", "prompt": "If force stays fixed and the perpendicular reach doubles, the Spin Pull...", "choices": ["doubles", "halves", "stays the same", "becomes zero"], "answer_index": 0, "hint": "Torque scales with perpendicular distance.", "tags": ["torque_force_location_confusion"]},
        {"kind": "mcq", "id": "M2L4_C2", "prompt": "Why can two equal pushes create different turning results?", "choices": ["they can act at different reaches", "one of the pushes is not real", "mass alone sets torque", "rotation ignores force direction"], "answer_index": 0, "hint": "Location matters, not just size.", "tags": ["torque_force_location_confusion"]}
      ],
      "transfer": [
        {"kind": "mcq", "id": "M2L4_T1", "prompt": "Why is a door handle placed far from the hinges?", "choices": ["to increase turning effect for the same force", "to decrease torque", "to remove the need for force", "to reduce the door mass"], "answer_index": 0, "hint": "Greater reach gives more turning effect.", "tags": ["torque_force_location_confusion"]},
        {"kind": "mcq", "id": "M2L4_T2", "prompt": "A centered push can translate a craft without rotating it because...", "choices": ["the turning reach is zero", "the force has no direction", "torque equals mass", "the craft becomes weightless"], "answer_index": 0, "hint": "A force through the pivot line gives no turning moment.", "tags": ["torque_force_location_confusion"]},
        {"kind": "short", "id": "M2L4_T3", "prompt": "A 4 N push acts 0.3 m from the pivot. What Spin Pull is produced?", "accepted_answers": ["1.2 N m", "1.2"], "hint": "Multiply force by perpendicular reach.", "tags": ["torque_force_location_confusion"]}
      ],
      "contract": {
        "concept_targets": ["Treat torque as force times perpendicular reach.", "Use line-of-action reasoning to separate translation from rotation."],
        "prerequisite_lessons": ["M2_L1", "M2_L2"],
        "misconception_focus": ["torque_force_location_confusion"],
        "formulas": [
          {"equation": "torque = force x perpendicular reach", "meaning": "Turning effect depends on both how hard you push and how far the push acts from the pivot line.", "units": ["N m"], "conditions": "Use the perpendicular distance from pivot to line of action."}
        ],
        "representations": [
          {"kind": "words", "purpose": "State what changes when the push point moves."},
          {"kind": "diagram", "purpose": "Show pivot, force arrow, and perpendicular reach on one picture."},
          {"kind": "formula", "purpose": "Summarize turning effect numerically."}
        ],
        "analogy_map": {
          "comparison": "Spin Pull maps to torque and the reach from pivot makes the turning effect visible.",
          "mapping": ["A farther push point creates more turning for the same force.", "A centered push can translate without rotating because the reach is zero."],
          "limit": "Real bodies can deform, but the model still captures the core dependence on force and perpendicular distance.",
          "prediction_prompt": "What happens to Spin Pull if the reach grows while the force stays the same?"
        },
        "worked_examples": [
          {
            "prompt": "Compare two door pushes: 6 N applied 0.5 m from the hinge and 3 N applied 1.0 m from the hinge. Which gives the larger Spin Pull?",
            "steps": [
              "Use Spin Pull = force x perpendicular reach for each case, because torque depends on both quantities together.",
              "First push: 6 x 0.5 = 3 N m.",
              "Second push: 3 x 1.0 = 3 N m.",
              "The Spin Pull values match, so neither push is larger; different force-reach combinations can give the same turning effect."
            ],
            "final_answer": "Both pushes give the same Spin Pull of 3 N m, because torque depends on the product of force and perpendicular reach, not on force size alone.",
            "why_it_matters": "This stops students from assuming the biggest force automatically gives the biggest turning effect."
          },
          {
            "prompt": "A 4 N push is applied once through the hinge line and once 0.8 m from the hinge. Explain which case turns the door.",
            "steps": [
              "A force through the hinge line has zero perpendicular reach, so its Spin Pull is 4 x 0 = 0 N m.",
              "The off-centre push has Spin Pull = 4 x 0.8 = 3.2 N m.",
              "The force still exists in both cases, but only the off-centre case has a turning reach.",
              "So only the second push creates rotation."
            ],
            "final_answer": "Only the 0.8 m case turns the door, giving 3.2 N m, because a force through the pivot has zero perpendicular reach and therefore zero Spin Pull.",
            "why_it_matters": "This links zero-torque cases directly to line-of-action reasoning."
          }
        ],
        "visual_assets": [
          {"asset_id": "m2-l4-spin-pull.svg", "purpose": "Show centred and off-centre pushes with the same force and compare their torque.", "caption": "The diagram labels the perpendicular reach so the turning effect can be read directly."}
        ],
        "simulation_contract": {
          "baseline_case": "Start with the same 6 N push first through the center line and then 0.5 m away.",
          "comparison_tasks": ["Keep force fixed and vary reach.", "Keep torque fixed and compare different force-reach combinations."],
          "watch_for": "Students should mention reach or line of action before naming the torque.",
          "takeaway": "Turning effect depends on both the push and where it acts."
        },
        "reflection_prompts": ["Explain why the same force can give different turning outcomes on the same object."],
        "mastery_skills": ["Calculate torque from force and distance.", "Predict how changing reach changes turning effect.", "Recognize zero torque cases.", "Separate force from torque.", "Use everyday hinge examples accurately."],
        "variation_plan": {
          "diagnostic": "Rotate between centered-force stories, reach comparisons, and direct torque calculations.",
          "concept_gate": "Swap between conceptual line-of-action judgments and simple torque calculations on retries.",
          "mastery": "Vary the force, distance, and object context so students must reason from structure, not from one door example."
        }
      }
    },
    {
      "id": "M2_L5",
      "title": "Balance Core and Stability",
      "sim": {
        "lab_id": "m2_balance_core_lab",
        "title": "Balance core explorer",
        "description": "Move cargo and support width so centre of mass and stability stay in one visible system.",
        "instructions": ["Shift cargo left and right.", "Raise and lower the load stack.", "Widen and narrow the Footprint Zone." ],
        "outcomes": ["centre_of_mass_material_confusion", "stability_weight_confusion"],
        "fields": ["cargo_position", "balance_core", "footprint_zone", "stability_result"],
        "depth": "number of balance stories explained with both centre of mass and support-area reasoning"
      },
      "analogy_text": "The Balance Core marks the mass-balance point of the craft, while the Footprint Zone shows the safe support area. Stability depends on keeping the Balance Core above that zone.",
      "commitment_prompt": "Before you answer, decide whether the question is about total mass or about where that mass sits relative to the support area.",
      "micro_prompts": [
        {"prompt": "Move the same cargo farther to one side.", "hint": "The Balance Core shifts because the mass distribution changed."},
        {"prompt": "Keep the mass the same but widen the Footprint Zone.", "hint": "A wider support base can improve stability even without changing the mass."}
      ],
      "diagnostic": [
        {"kind": "mcq", "id": "M2L5_D1", "prompt": "What most directly changes the Balance Core location?", "choices": ["moving cargo to a new position", "renaming the craft", "changing the paint color", "waiting longer"], "answer_index": 0, "hint": "Centre of mass depends on mass distribution.", "tags": ["centre_of_mass_material_confusion"]},
        {"kind": "mcq", "id": "M2L5_D2", "prompt": "When is a craft most likely to tip?", "choices": ["when the Balance Core moves outside the Footprint Zone", "when the mass is large", "when the deck is blue", "when time passes"], "answer_index": 0, "hint": "Stability depends on the centre of gravity staying over the base.", "tags": ["stability_weight_confusion"]},
        {"kind": "short", "id": "M2L5_D3", "prompt": "A crate is moved to the left side of the deck. In which direction does the Balance Core shift?", "accepted_answers": ["left"], "hint": "The balance point shifts toward the moved mass.", "tags": ["centre_of_mass_material_confusion"]}
      ],
      "inquiry": [
        {"prompt": "Keep the same mass but move it upward and sideways.", "hint": "High and off-centre mass can make tipping easier."},
        {"prompt": "Compare narrow and wide Footprint Zones with the same Balance Core.", "hint": "Support width changes stability even when the centre of mass stays the same."}
      ],
      "recon_prompts": ["Explain why heavier does not automatically mean more stable.", "Explain why centre of mass can matter even when total mass stays unchanged." ],
      "capsule_prompt": "Ask where the Balance Core is and whether it still lies over the support base.",
      "capsule_checks": [
        {"kind": "mcq", "id": "M2L5_C1", "prompt": "Why can a heavy craft still tip?", "choices": ["because the Balance Core can move outside the support base", "because heavy objects lose mass", "because torque vanishes", "because heavier objects have zero centre of mass"], "answer_index": 0, "hint": "Mass alone does not guarantee stability.", "tags": ["stability_weight_confusion"]},
        {"kind": "mcq", "id": "M2L5_C2", "prompt": "What usually improves stability if the Balance Core stays at the same height and position?", "choices": ["widening the Footprint Zone", "making the craft taller", "removing all supports", "increasing speed"], "answer_index": 0, "hint": "A wider base gives more margin before tipping.", "tags": ["stability_weight_confusion"]}
      ],
      "transfer": [
        {"kind": "mcq", "id": "M2L5_T1", "prompt": "Why can the centre of mass lie in empty space for some objects?", "choices": ["because it is a balance point, not a chunk of material", "because matter disappears there", "because only circles have centres of mass", "because mass is measured in newtons"], "answer_index": 0, "hint": "Centre of mass is a balance idea, not always a literal material point.", "tags": ["centre_of_mass_material_confusion"]},
        {"kind": "mcq", "id": "M2L5_T2", "prompt": "What usually happens to stability when the same load is placed higher above the deck?", "choices": ["stability decreases", "stability increases automatically", "nothing changes", "the Footprint Zone disappears"], "answer_index": 0, "hint": "A higher centre of mass makes tipping easier.", "tags": ["stability_weight_confusion"]},
        {"kind": "short", "id": "M2L5_T3", "prompt": "If the Balance Core moves beyond the right edge of the Footprint Zone, what happens?", "accepted_answers": ["it tips", "the craft tips", "tipping begins"], "hint": "Once the line of action passes outside the base, the craft starts to tip.", "tags": ["stability_weight_confusion"]}
      ],
      "contract": {
        "concept_targets": ["Use centre-of-mass location rather than total mass alone to explain stability.", "Connect stability to whether the line of action stays over the support base."],
        "prerequisite_lessons": ["M2_L4"],
        "misconception_focus": ["centre_of_mass_material_confusion", "stability_weight_confusion"],
        "formulas": [
          {"equation": "stable if line of action of weight stays inside base", "meaning": "Stability depends on where the weight line falls relative to the support area.", "units": ["m"], "conditions": "Use for tipping judgments."},
          {"equation": "balanced if clockwise turning = anticlockwise turning", "meaning": "Balanced objects match turning effects around the support point.", "units": ["N m"], "conditions": "Use for simple static balance situations."}
        ],
        "representations": [
          {"kind": "words", "purpose": "Explain why stability is geometric as well as massive."},
          {"kind": "diagram", "purpose": "Show the Balance Core above or beyond the Footprint Zone."},
          {"kind": "formula", "purpose": "Summarize the balance and tipping conditions."}
        ],
        "analogy_map": {
          "comparison": "Balance Core maps to centre of mass and Footprint Zone maps to the base of support.",
          "mapping": ["Moving cargo shifts the Balance Core.", "A wider Footprint Zone can keep the Balance Core safely inside the support region."],
          "limit": "Real stability also depends on surface effects and motion, but the model captures the centre-of-mass rule clearly.",
          "prediction_prompt": "What changes first when cargo is moved toward one edge: the total mass or the Balance Core position?"
        },
        "worked_examples": [
          {
            "prompt": "A stack's Balance Core line lands 0.05 m inside the right edge of a narrow base. On a wider platform with the same load position, the line lands 0.30 m inside the edge. Which setup is more stable and why?",
            "steps": [
              "Stability depends on whether the Balance Core line stays inside the Footprint Zone and how much safety margin remains before it reaches the edge.",
              "The narrow base leaves only 0.05 m of margin, so a small extra shift could push the line outside the base and start tipping.",
              "The wider base leaves 0.30 m of margin with the same load position, so the weight line is much farther from the tipping threshold.",
              "Therefore the wider platform is more stable because it gives more support width under the same Balance Core line."
            ],
            "final_answer": "The wider platform is more stable, because the Balance Core line stays much farther inside the Footprint Zone and leaves a larger safety margin before tipping begins.",
            "why_it_matters": "This keeps stability tied to support geometry instead of to weight language alone."
          },
          {
            "prompt": "A crate is moved from the centre of the deck to the left side while total mass stays the same. Predict the Balance Core shift and the tipping risk.",
            "steps": [
              "The total mass has not changed, so the key change is the mass distribution across the deck.",
              "Because the crate moves left, the Balance Core shifts left toward the moved mass.",
              "That leftward shift moves the weight line closer to the left edge of the Footprint Zone.",
              "So tipping risk increases if that line gets too close to, or crosses, the base edge."
            ],
            "final_answer": "The Balance Core shifts left, and tipping risk rises if that line moves close to or beyond the left edge, because stability depends on where the mass is located, not only on how much mass there is.",
            "why_it_matters": "This prevents students from treating centre of mass as just a label instead of a predictive stability tool."
          }
        ],
        "visual_assets": [
          {"asset_id": "m2-l5-balance-core.svg", "purpose": "Show how moving cargo and changing base width affect centre of mass and tipping.", "caption": "The diagram labels Balance Core and Footprint Zone on the same craft."}
        ],
      "simulation_contract": {
        "baseline_case": "Start with a centered load over a medium base, then move it toward one edge.",
        "comparison_tasks": ["Keep mass fixed and change cargo position.", "Keep the Balance Core fixed and widen the base."],
        "watch_for": "Students should talk about centre of mass before they talk about heavy or light.",
        "takeaway": "Stability depends on where the Balance Core sits relative to the Footprint Zone."
      },
      "reflection_prompts": ["Explain why making an object heavier does not guarantee making it more stable."],
      "mastery_skills": ["Predict centre-of-mass shifts.", "Judge stability from support geometry.", "Use base-of-support reasoning.", "Explain tipping conceptually.", "Separate mass from stability."],
      "variation_plan": {
        "diagnostic": "Rotate between cargo-shift, base-width, and tipping-threshold stories.",
        "concept_gate": "Swap between Balance Core location questions and stability comparison items on retries.",
        "mastery": "Vary load placement, base width, and object shape so students must reapply the same structure in new contexts."
      }
      }
    },
    {
      "id": "M2_L6",
      "title": "Arrow Split and Vector Resolution",
      "sim": {
        "lab_id": "m2_arrow_split_lab",
        "title": "Arrow split explorer",
        "description": "Split diagonal Drive Arrows into deck-aligned parts so vector reasoning feels like organized arrow bookkeeping.",
        "instructions": ["Split one diagonal arrow into horizontal and vertical parts.", "Recombine two perpendicular components into one Master Arrow.", "Compare different component pairs that give the same resultant."],
        "outcomes": ["vector_resolution_component_confusion", "resultant_force_vector_confusion"],
        "fields": ["arrow_angle", "horizontal_component", "vertical_component", "resultant_arrow"],
        "depth": "number of angled-force stories explained through component structure rather than mystery-vector language"
      },
      "analogy_text": "Arrow Split breaks one diagonal Drive Arrow into simpler deck-aligned pushes. The pieces are not extra forces; they are a clearer way to reason about one angled push.",
      "commitment_prompt": "Before you answer, decide whether you need the full diagonal arrow or its horizontal and vertical parts.",
      "micro_prompts": [
        {"prompt": "Split one diagonal arrow into forward and sideways pieces.", "hint": "The components help you combine forces one direction at a time."},
        {"prompt": "Compare combining forces directly with combining their components first.", "hint": "Components can make the same resultant easier to see and calculate."}
      ],
      "diagnostic": [
        {"kind": "mcq", "id": "M2L6_D1", "prompt": "Why is Arrow Split useful?", "choices": ["it turns one angled push into simpler perpendicular parts", "it creates two new physical forces", "it removes direction from the force", "it makes mass unnecessary"], "answer_index": 0, "hint": "Components are a reasoning tool for one angled vector.", "tags": ["vector_resolution_component_confusion"]},
        {"kind": "mcq", "id": "M2L6_D2", "prompt": "Which statement about components is correct?", "choices": ["they add back to the original vector", "they replace the need for direction", "they are always larger than the original vector", "they only work in one dimension"], "answer_index": 0, "hint": "Components recombine to recover the original vector.", "tags": ["vector_resolution_component_confusion"]},
        {"kind": "short", "id": "M2L6_D3", "prompt": "A force has components 6 N east and 8 N north. What is the resultant magnitude?", "accepted_answers": ["10 N", "10"], "hint": "Use the right-triangle result for 6, 8, 10.", "tags": ["vector_resolution_component_confusion", "resultant_force_vector_confusion"]}
      ],
      "inquiry": [
        {"prompt": "Split one diagonal arrow and compare the horizontal and vertical bookkeeping.", "hint": "Work direction by direction before recombining the result."},
        {"prompt": "Create two different component pairs that rebuild the same resultant magnitude and direction.", "hint": "Different components can be compared before you recombine the final arrow."}
      ],
      "recon_prompts": ["Explain why components are not extra forces.", "Explain why vector resolution helps before you combine multiple angled pushes."],
      "capsule_prompt": "Split the angled arrow into aligned parts, combine those parts, then rebuild the Master Arrow.",
      "capsule_checks": [
        {"kind": "mcq", "id": "M2L6_C1", "prompt": "When two horizontal components oppose each other, what do you do first?", "choices": ["subtract and keep the larger direction", "add them regardless of direction", "ignore the vertical parts forever", "treat them as masses"], "answer_index": 0, "hint": "Combine components on one axis the same way you combine same-line forces.", "tags": ["vector_resolution_component_confusion", "resultant_force_vector_confusion"]},
        {"kind": "mcq", "id": "M2L6_C2", "prompt": "Why do physicists resolve a diagonal force into components before combining several forces?", "choices": ["it organizes the vector sum by axis", "it removes the need for units", "it turns vectors into scalars", "it makes the original arrow disappear"], "answer_index": 0, "hint": "Component reasoning is structured vector bookkeeping.", "tags": ["vector_resolution_component_confusion"]}
      ],
      "transfer": [
        {"kind": "mcq", "id": "M2L6_T1", "prompt": "A diagonal arrow is split into east and north components. What must be true?", "choices": ["those components add back to the original arrow", "the original arrow was two separate pushes", "the components are unrelated to direction", "the resultant must be smaller than each component"], "answer_index": 0, "hint": "Components reconstruct the original vector.", "tags": ["vector_resolution_component_confusion"]},
        {"kind": "mcq", "id": "M2L6_T2", "prompt": "Why can component reasoning help with 2D resultants?", "choices": ["it lets you combine one axis at a time", "it removes all angles from physics", "it makes direction irrelevant", "it works only for vertical arrows"], "answer_index": 0, "hint": "Axis-by-axis combination reduces confusion.", "tags": ["vector_resolution_component_confusion"]},
        {"kind": "short", "id": "M2L6_T3", "prompt": "A force has components 3 N east and 4 N north. What resultant magnitude does that give?", "accepted_answers": ["5 N", "5"], "hint": "Use the 3, 4, 5 triangle.", "tags": ["vector_resolution_component_confusion", "resultant_force_vector_confusion"]}
      ],
      "contract": {
        "concept_targets": ["Use components to reason about one angled vector and about multi-force resultants.", "Treat component resolution as structured bookkeeping rather than as a mysterious trick."],
        "prerequisite_lessons": ["M2_L1", "M2_L2"],
        "misconception_focus": ["vector_resolution_component_confusion", "resultant_force_vector_confusion"],
        "formulas": [
          {"equation": "F_x = F cos theta and F_y = F sin theta", "meaning": "An angled force can be expressed as perpendicular components on chosen axes.", "units": ["N"], "conditions": "Use for resolved components on perpendicular axes."},
          {"equation": "F_net = vector sum of components", "meaning": "Combine horizontal parts with horizontal parts and vertical parts with vertical parts before rebuilding the resultant.", "units": ["N"], "conditions": "Use after resolving all angled forces onto the same axes."}
        ],
      "representations": [
        {"kind": "words", "purpose": "Explain what component resolution is doing conceptually."},
        {"kind": "diagram", "purpose": "Show one angled arrow with its perpendicular components."},
        {"kind": "formula", "purpose": "Summarize component resolution and recombination."}
      ],
      "analogy_map": {
        "comparison": "Arrow Split maps to vector resolution into components.",
        "mapping": ["One angled Drive Arrow can be replaced by simpler perpendicular parts.", "Those parts recombine to recover the same original vector."],
        "limit": "Components are a mathematical redescription of one force, not extra physical pushes.",
        "prediction_prompt": "Why is it easier to combine several angled pushes after you resolve them onto common axes?"
      },
      "worked_examples": [
        {
          "prompt": "A diagonal force is resolved into 8 N east and 6 N north. Another 3 N west force acts at the same time. Find the net horizontal component, the net vertical component, and the resultant magnitude.",
          "steps": [
            "Combine one axis at a time: horizontally, 8 N east and 3 N west leave 5 N east.",
            "The vertical axis has only 6 N north, so the net vertical component stays 6 N north.",
            "Now rebuild the resultant from the perpendicular components using Pythagoras: magnitude = sqrt(5^2 + 6^2) = sqrt(61) ≈ 7.8 N.",
            "The final arrow points northeast because both net components are positive on their chosen axes."
          ],
          "final_answer": "Net components = 5 N east and 6 N north, so the resultant is about 7.8 N northeast, because components must be combined axis by axis before rebuilding the final arrow.",
          "why_it_matters": "This ties component bookkeeping directly to the rebuilt 2D resultant."
        },
        {
          "prompt": "A learner says resolving a 10 N diagonal arrow into 6 N east and 8 N north creates two new extra forces. Evaluate the claim.",
          "steps": [
            "Start with the meaning of components: they are a different description of one original vector on chosen axes.",
            "Check the numbers: 6 N east and 8 N north recombine to the same 10 N diagonal because sqrt(6^2 + 8^2) = 10.",
            "Since the components rebuild the original arrow, they are not extra pushes acting in addition to it.",
            "So resolution changes the bookkeeping, not the physics."
          ],
          "final_answer": "The claim is wrong: 6 N east and 8 N north are component descriptions of the same 10 N arrow, because they recombine to the original vector rather than adding extra physical forces.",
          "why_it_matters": "This blocks the common mistake of treating components as new forces instead of as a structured redescription."
        }
      ],
      "visual_assets": [
        {"asset_id": "m2-l6-arrow-split.svg", "purpose": "Show one diagonal arrow, its components, and the rebuilt resultant.", "caption": "The diagram turns vector resolution into visible arrow bookkeeping."}
      ],
      "simulation_contract": {
        "baseline_case": "Start with one diagonal arrow and display its resolved components.",
        "comparison_tasks": ["Compare direct vector combination with component-by-component combination.", "Build two different component sets that recreate the same resultant."],
        "watch_for": "Students should explain that components are not new forces.",
        "takeaway": "Vector resolution is a structured way to understand and combine angled forces."
      },
      "reflection_prompts": ["Explain why Arrow Split is a bookkeeping move rather than a claim that one force has become two separate pushes." ],
      "mastery_skills": ["Resolve an angled vector into components.", "Combine components axis by axis.", "Rebuild resultants from perpendicular parts.", "Distinguish components from separate forces.", "Solve simple 2D resultant magnitudes."],
      "variation_plan": {
        "diagnostic": "Rotate between conceptual component statements, simple 3-4-5 resultant calculations, and axis-combination questions.",
        "concept_gate": "Swap between one-vector resolution items and multi-component combination items on retries.",
        "mastery": "Vary the axes, component values, and story contexts so students must actively rebuild the vector structure each time."
      }
      }
    }
  ]
}''')

try:
    from scripts.seed_m1_module import utc_now, get_project_id, init_firebase, upsert_doc, print_preview
except ModuleNotFoundError:
    from seed_m1_module import utc_now, get_project_id, init_firebase, upsert_doc, print_preview

def safe_tags(tags: List[str]) -> List[str]:
    return [tag for tag in tags if tag in M2_ALLOWLIST]

def make_mcq(qid: str, prompt: str, choices: List[str], answer_index: int, hint: str, tags: List[str]) -> Dict[str, Any]:
    feedback = [hint for _ in choices]
    return {"id": qid, "question_id": qid, "type": "mcq", "prompt": prompt, "choices": choices, "answer_index": answer_index, "hint": hint, "feedback": feedback, "misconception_tags": safe_tags(tags)}

def make_short(qid: str, prompt: str, accepted_answers: List[str], hint: str, tags: List[str]) -> Dict[str, Any]:
    return {"id": qid, "question_id": qid, "type": "short", "prompt": prompt, "accepted_answers": accepted_answers, "hint": hint, "feedback": [hint], "misconception_tags": safe_tags(tags)}

RELEASE_CHECKS = [
    "Every mastery-tested relationship is explicitly taught before mastery.",
    "Every core force idea is represented in words plus at least one non-text view.",
    "Every lesson has a readable visual asset and a usable simulation contract.",
    "Conceptual understanding is checked before calculation-only mastery.",
]

M2_MODULE_DOC, _LESSONS, _SIMS = build_nextgen_module_scaffold(
    M2_MODULE_ID,
    "Forces, Momentum, Spin & Stability",
    M2_SPEC["module_description"],
    [lesson["title"] for lesson in M2_SPEC["lessons"]],
    M2_ALLOWLIST,
    sequence=6,
    level="Module 2",
    estimated_minutes=225,
)
M2_MODULE_DOC.update({
    "content_version": M2_CONTENT_VERSION,
    "mastery_outcomes": list(M2_SPEC["mastery_outcomes"]),
    "misconception_tag_allowlist": M2_ALLOWLIST,
    "authoring_standard": "lesson_authoring_spec_v1",
    "updated_utc": utc_now(),
})
LESSON_BY_ID = {str(lesson["lesson_id"]): lesson for lesson in _LESSONS}
SIM_BY_LESSON = {str(lesson["lesson_id"]): sim for lesson, sim in zip(_LESSONS, _SIMS)}

def build_question(spec: Dict[str, Any]) -> Dict[str, Any]:
    if str(spec.get("kind") or "") == "mcq":
        return make_mcq(str(spec["id"]), str(spec["prompt"]), list(spec["choices"]), int(spec["answer_index"]), str(spec["hint"]), list(spec["tags"]))
    return make_short(str(spec["id"]), str(spec["prompt"]), list(spec["accepted_answers"]), str(spec["hint"]), list(spec["tags"]))

def configure_sim(spec: Dict[str, Any]) -> None:
    lesson = LESSON_BY_ID[str(spec["id"])]
    sim = SIM_BY_LESSON[str(spec["id"])]
    sim_spec = spec["sim"]
    lesson["phases"]["simulation_inquiry"]["lab_id"] = str(sim_spec["lab_id"])
    sim.update({"lab_id": str(sim_spec["lab_id"]), "module_id": M2_MODULE_ID, "title": str(sim_spec["title"]), "description": str(sim_spec["description"]), "instructions": list(sim_spec["instructions"]), "expected_outcomes": list(sim_spec["outcomes"]), "telemetry_schema_hint": {"fields": list(sim_spec["fields"]), "sim_depth_meaning": str(sim_spec["depth"])} , "updated_utc": utc_now()})

def configure_lesson(spec: Dict[str, Any]) -> None:
    lesson = LESSON_BY_ID[str(spec["id"])]
    lesson["updated_utc"] = utc_now()
    lesson["phases"]["diagnostic"] = {"two_tier": True, "items": [build_question(item) for item in spec["diagnostic"]], "notes": "Use the opening check to surface the main force or momentum misconception before the lesson deepens it."}
    lesson["phases"]["analogical_grounding"] = {"analogy_text": str(spec["analogy_text"]), "commitment_prompt": str(spec["commitment_prompt"]), "micro_prompts": [{"prompt": str(item["prompt"]), "hint": str(item["hint"])} for item in spec["micro_prompts"]]}
    lesson["phases"]["simulation_inquiry"]["inquiry_prompts"] = [{"prompt": str(item["prompt"]), "hint": str(item["hint"])} for item in spec["inquiry"]]
    lesson["phases"]["concept_reconstruction"] = {"prompts": list(spec["recon_prompts"]), "capsules": [{"prompt": str(spec["capsule_prompt"]), "checks": [build_question(item) for item in spec["capsule_checks"]]}]}
    lesson["phases"]["transfer"] = {"items": [build_question(item) for item in spec["transfer"]], "notes": "Use transfer to check whether the idea survives a fresh context or representation."}
    contract = dict(spec["contract"])
    contract["misconception_focus"] = safe_tags(list(contract["misconception_focus"]))
    contract["formulas"] = list(contract["formulas"])
    contract["representations"] = list(contract["representations"])
    contract["worked_examples"] = list(contract["worked_examples"])
    contract["visual_assets"] = list(contract["visual_assets"])
    contract["release_checks"] = list(RELEASE_CHECKS)
    lesson["authoring_contract"] = contract


def spec_mcq(
    qid: str,
    prompt: str,
    choices: List[str],
    answer_index: int,
    hint: str,
    tags: List[str],
) -> Dict[str, Any]:
    return {
        "kind": "mcq",
        "id": qid,
        "prompt": prompt,
        "choices": choices,
        "answer_index": answer_index,
        "hint": hint,
        "tags": tags,
    }


def spec_short(
    qid: str,
    prompt: str,
    accepted_answers: List[str],
    hint: str,
    tags: List[str],
) -> Dict[str, Any]:
    return {
        "kind": "short",
        "id": qid,
        "prompt": prompt,
        "accepted_answers": accepted_answers,
        "hint": hint,
        "tags": tags,
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


M2_LESSON_CONCEPTS = {
    "M2_L1": "master_arrow",
    "M2_L2": "load_rating",
    "M2_L3": "dock_exchange",
    "M2_L4": "spin_pull",
    "M2_L5": "balance_core",
    "M2_L6": "arrow_split",
}

M2_LESSON_VISUAL_TITLES = {
    "M2_L1": "Master Arrow Systems Board",
    "M2_L2": "Load Rating Response Board",
    "M2_L3": "Dock Exchange Ledger Board",
    "M2_L4": "Spin Pull Reach Board",
    "M2_L5": "Balance Core Stability Board",
    "M2_L6": "Arrow Split Bookkeeping Board",
}

M2_ANALOGY_UPDATES = {
    "M2_L1": (
        "Treat Thruster-Deck like a mission-control force ledger: many separate thruster entries can collapse into one net steering instruction. "
        "The craft responds to that net instruction, not to the loudest single entry."
    ),
    "M2_L2": (
        "Load Rating works like a response budget in a flight computer. The same steering command sent to two craft does not buy the same motion shift if one craft carries more inertia."
    ),
    "M2_L3": (
        "Carry Score is like a signed docking ledger. Each moving craft brings momentum credit or debt, and a closed docking event must preserve the system total even while redistributing the share."
    ),
    "M2_L4": (
        "Spin Pull is leverage accounting: a push buys turning effect only through its perpendicular reach from the pivot. The same force can buy very different rotation stories."
    ),
    "M2_L5": (
        "Balance Core works like a support-permit rule. The weight line must land inside the allowed support zone, and widening the zone changes stability without changing the mass total."
    ),
    "M2_L6": (
        "Arrow Split is vector bookkeeping for mission control. One diagonal command is rewritten into axis-aligned entries so several angled forces can be combined without losing the original meaning."
    ),
}

M2_COMMITMENT_UPDATES = {
    "M2_L1": "Before answering, decide whether the question is about one visible force entry or the net system instruction.",
    "M2_L2": "Before answering, separate one-object response reasoning from two-object interaction-pair reasoning.",
    "M2_L3": "Before answering, decide whether the question is about one craft's momentum or the closed-system total.",
    "M2_L4": "Before answering, name the pivot and the perpendicular reach before you talk about turning.",
    "M2_L5": "Before answering, trace where the Balance Core line lands relative to the Footprint Zone.",
    "M2_L6": "Before answering, decide whether the clean route is to resolve by axis before rebuilding the final arrow.",
}

M2_EXTRA_DIAGNOSTIC = {
    "M2_L1": [
        spec_mcq("M2L1_D6", "A craft has 14 N east and 5 N west. What Master Arrow remains?", ["9 N east", "9 N west", "19 N east", "0 N"], 0, "Subtract opposite directions and keep the larger direction.", ["resultant_force_vector_confusion"]),
        spec_mcq("M2L1_D7", "A craft is already moving west and the Master Arrow becomes zero. What happens next?", ["it keeps moving west at constant velocity", "it must stop at once", "it accelerates east", "all forces vanish because it is moving"], 0, "Zero Master Arrow means no acceleration, so the current velocity stays unchanged.", ["motion_implies_force_confusion", "newton_first_law_confusion"]),
        spec_short("M2L1_D8", "In a few words, what does zero Master Arrow mean?", ["no motion change", "zero acceleration", "no acceleration", "motion stays unchanged", "constant velocity if already moving", "no resultant force", "zero resultant force", "no net force", "zero net force"], "Zero Master Arrow tells you about acceleration, not about one special speed value.", ["newton_first_law_confusion", "balanced_force_rest_confusion"]),
    ],
    "M2_L2": [
        spec_mcq("M2L2_D6", "A 18 N Master Arrow acts on a 3 kg craft. What Motion Shift occurs?", ["6 m/s^2", "9 m/s^2", "3 m/s^2", "54 m/s^2"], 0, "Use acceleration = net force / mass.", ["force_mass_acceleration_confusion"]),
        spec_short("M2L2_D7", "In a few words, why can equal third-law forces still produce different accelerations?", ["the masses can differ", "different masses", "because the masses are different", "same force on different masses"], "Equal interaction forces do not force equal accelerations because mass still matters.", ["third_law_pair_confusion", "force_mass_acceleration_confusion"]),
        spec_mcq("M2L2_D8", "If the mass stays fixed and the Master Arrow triples, the acceleration becomes...", ["three times as large", "one third as large", "unchanged", "zero"], 0, "For fixed mass, acceleration scales directly with net force.", ["force_mass_acceleration_confusion"]),
    ],
    "M2_L3": [
        spec_short("M2L3_D6", "What two quantities set Carry Score?", ["mass and velocity", "mass and speed", "load and velocity", "mass times velocity"], "Momentum depends on both how much mass moves and how fast it moves.", ["momentum_force_confusion"]),
        spec_mcq("M2L3_D7", "Which pair has the same Carry Score?", ["5 kg at 2 m/s and 2 kg at 5 m/s", "5 kg at 2 m/s and 5 kg at 5 m/s", "2 kg at 4 m/s and 1 kg at 8 m/s", "3 kg at 4 m/s and 2 kg at 4 m/s"], 0, "Compare mass times velocity in each case.", ["momentum_force_confusion"]),
        spec_short("M2L3_D8", "A 6 kg craft moves at -2 m/s. What Carry Score does it have?", ["-12 kg m/s", "-12", "-12 Ns"], "Momentum keeps the sign of the velocity.", ["momentum_force_confusion"]),
    ],
    "M2_L4": [
        spec_short("M2L4_D6", "What two things decide Spin Pull?", ["force and perpendicular reach", "force and distance from pivot", "force and moment arm", "force and reach"], "Turning effect depends on push size and perpendicular reach together.", ["torque_force_location_confusion"]),
        spec_mcq("M2L4_D7", "Which pair gives the same Spin Pull?", ["4 N at 0.5 m and 2 N at 1.0 m", "4 N at 0.5 m and 4 N at 1.0 m", "8 N at 0.25 m and 8 N at 1.0 m", "6 N at 0.2 m and 2 N at 0.2 m"], 0, "Compare force x reach for each pair.", ["torque_force_location_confusion"]),
        spec_short("M2L4_D8", "A 10 N push acts 0.3 m from the pivot. What Spin Pull is produced?", ["3 N m", "3"], "Use torque = force x perpendicular reach.", ["torque_force_location_confusion"]),
    ],
    "M2_L5": [
        spec_short("M2L5_D6", "If cargo is moved to the right, which way does the Balance Core shift?", ["right", "to the right"], "The center-of-mass position shifts toward the moved mass.", ["centre_of_mass_material_confusion"]),
        spec_mcq("M2L5_D7", "If the Balance Core stays in the same place but the base becomes wider, stability usually...", ["increases", "decreases", "stays impossible to judge", "depends only on color"], 0, "A wider support zone gives more margin before tipping.", ["stability_weight_confusion"]),
        spec_mcq("M2L5_D8", "Which event marks the tipping threshold most directly?", ["the weight line reaches or crosses the base edge", "the object becomes heavier", "the object starts moving fast", "the support area changes color"], 0, "Tipping begins when the center-of-mass line leaves the support region.", ["stability_weight_confusion", "centre_of_mass_material_confusion"]),
    ],
    "M2_L6": [
        spec_short("M2L6_D6", "In a few words, what are components?", ["one force rewritten on chosen axes", "parts of one vector on axes", "one vector resolved on axes", "one force split into axis parts"], "Components are a cleaner description of one angled force.", ["vector_resolution_component_confusion"]),
        spec_mcq("M2L6_D7", "A force has components 8 N east and 15 N north. What resultant magnitude does that give?", ["17 N", "7 N", "23 N", "15 N"], 0, "Use the 8-15-17 right triangle.", ["vector_resolution_component_confusion", "resultant_force_vector_confusion"]),
        spec_mcq("M2L6_D8", "A force already has 3 N east horizontally. If another 5 N east component is added, the new horizontal total is...", ["8 N east", "2 N east", "8 N west", "15 N east"], 0, "Same-direction components add on the same axis.", ["resultant_force_vector_confusion"]),
    ],
}

M2_EXTRA_CONCEPT = {
    "M2_L1": [
        spec_mcq("M2L1_C5", "Which pair leaves the same Master Arrow?", ["11 N right with 3 N left, and 8 N right only", "7 N right with 7 N left, and 7 N right only", "6 N left with 2 N right, and 6 N right with 2 N left", "4 N right with 1 N left, and 1 N right with 4 N left"], 0, "Compare the net push in each case.", ["resultant_force_vector_confusion"]),
        spec_short("M2L1_C6", "Why must you combine Drive Arrows before predicting motion?", ["because the resultant force decides the motion change", "because the Master Arrow decides acceleration", "motion depends on the net force", "the combined force predicts the change"], "Predict motion from the combined force, not from one isolated arrow.", ["resultant_force_vector_confusion", "motion_implies_force_confusion"]),
    ],
    "M2_L2": [
        spec_short("M2L2_C5", "What real quantity is the lesson's Load Rating standing in for?", ["mass"], "Load Rating is the mass term in the model.", ["force_mass_acceleration_confusion"]),
        spec_mcq("M2L2_C6", "The same 10 N interaction pair acts on a 2 kg craft and a 5 kg craft. Which has the smaller acceleration?", ["the 5 kg craft", "the 2 kg craft", "they match because the forces match", "the faster craft"], 0, "For the same force, the larger mass accelerates less.", ["force_mass_acceleration_confusion", "third_law_pair_confusion"]),
    ],
    "M2_L3": [
        spec_mcq("M2L3_C5", "A closed system has 18 kg m/s total Carry Score before docking and a total mass of 6 kg after docking. What shared speed follows?", ["3 m/s", "6 m/s", "12 m/s", "18 m/s"], 0, "Shared speed = total momentum / combined mass.", ["momentum_conservation_system_confusion"]),
        spec_short("M2L3_C6", "In a few words, what is conserved in a closed Dock Exchange?", ["total system carry score", "total momentum", "system momentum", "the total carry score of the system"], "The conserved quantity belongs to the whole closed system.", ["momentum_conservation_system_confusion"]),
    ],
    "M2_L4": [
        spec_mcq("M2L4_C5", "If a force acts through the pivot and the force doubles, the Spin Pull becomes...", ["0 N m", "double", "half", "impossible to tell"], 0, "No perpendicular reach still means no torque.", ["torque_force_location_confusion"]),
        spec_short("M2L4_C6", "Why are door handles placed far from hinges?", ["to increase turning effect for the same force", "to increase torque for the same force", "to give a larger moment arm", "to give more Spin Pull"], "More perpendicular reach gives more turning effect for the same push.", ["torque_force_location_confusion"]),
    ],
    "M2_L5": [
        spec_short("M2L5_C5", "In a few words, what decides whether tipping begins?", ["the weight line leaves the base", "the Balance Core line leaves the Footprint Zone", "the center of mass line goes outside the support area", "the line of action of weight reaches the edge"], "Tipping begins when the center-of-mass line no longer lands inside the support area.", ["stability_weight_confusion", "centre_of_mass_material_confusion"]),
        spec_mcq("M2L5_C6", "If total mass stays the same but the load is raised higher, the craft is usually...", ["easier to tip", "more stable", "unchanged in stability", "impossible to compare"], 0, "A higher center of mass is less forgiving.", ["stability_weight_confusion"]),
    ],
    "M2_L6": [
        spec_short("M2L6_C5", "Why combine components axis by axis?", ["to organize the vector sum", "to keep directions clear", "to combine one direction at a time", "to do the bookkeeping cleanly"], "Axis-by-axis work keeps multi-force vector sums readable.", ["vector_resolution_component_confusion"]),
        spec_mcq("M2L6_C6", "If the vertical components are 7 N up and 9 N down, the net vertical component is...", ["2 N down", "2 N up", "16 N down", "16 N up"], 0, "Subtract opposite directions and keep the larger direction.", ["resultant_force_vector_confusion", "vector_resolution_component_confusion"]),
    ],
}

M2_EXTRA_TRANSFER = {
    "M2_L1": [
        spec_mcq("M2L1_T4", "A craft has 4 N north, 4 N south, and 6 N east. What Master Arrow remains?", ["6 N east", "2 N east", "8 N east", "0 N"], 0, "Cancel the vertical pair first, then read the remaining horizontal push.", ["resultant_force_vector_confusion"]),
        spec_mcq("M2L1_T5", "Which story gives the strongest evidence of zero Master Arrow rather than zero motion?", ["a craft already cruising steadily while the forces balance", "a craft that is stopped on the launch pad", "a craft with one forward thruster only", "a craft that keeps speeding up"], 0, "Zero Master Arrow fixes acceleration, not one special speed.", ["motion_implies_force_confusion", "balanced_force_rest_confusion"]),
        spec_short("M2L1_T6", "A craft is moving in a straight east-west line, and its westward speed is increasing. Which direction must the Master Arrow point?", ["west", "to the west", "the Master Arrow points west"], "In a straight east-west motion story, increasing westward speed means the acceleration and Master Arrow both point west.", ["resultant_force_vector_confusion"]),
        spec_short("M2L1_T7", "In a few words, what does the Master Arrow decide?", ["how motion changes", "acceleration", "the motion change", "which way acceleration points"], "The Master Arrow determines the acceleration story.", ["motion_implies_force_confusion", "newton_first_law_confusion"]),
        spec_mcq("M2L1_T8", "Why can balanced arrows and no arrows both give zero Master Arrow without being the same force story?", ["balanced arrows still mean forces are acting and cancelling, while no arrows mean no forces act", "both stories prove the craft must be stationary", "no arrows always mean the craft is accelerating", "balanced arrows always mean one hidden force is larger"], 0, "The Master Arrow can match even when the underlying force story differs.", ["balanced_force_rest_confusion", "motion_implies_force_confusion", "resultant_force_vector_confusion"]),
    ],
    "M2_L2": [
        spec_mcq("M2L2_T4", "Which pair gives the same acceleration?", ["15 N on 3 kg and 30 N on 6 kg", "15 N on 3 kg and 15 N on 6 kg", "12 N on 2 kg and 18 N on 2 kg", "10 N on 5 kg and 20 N on 5 kg"], 0, "Compare F / m for each case.", ["force_mass_acceleration_confusion"]),
        spec_short("M2L2_T5", "In a few words, what is Newton's first law in this lesson's language?", ["no Master Arrow means no motion change", "zero Master Arrow means zero acceleration", "no resultant means no velocity change", "zero net force means no acceleration"], "Say the zero-resultant rule directly.", ["newton_first_law_confusion", "motion_implies_force_confusion"]),
        spec_mcq("M2L2_T6", "Why do third-law force pairs not cancel in one F = ma calculation?", ["because they act on different objects", "because one is always larger", "because only moving objects feel them", "because mass removes one of them"], 0, "Cancellation only applies to forces on the same object.", ["third_law_pair_confusion"]),
        spec_short("M2L2_T7", "A 18 N Master Arrow acts on a 1.5 kg craft. What Motion Shift occurs?", ["12 m/s^2", "12", "12 m/s/s"], "Use acceleration = net force / mass.", ["force_mass_acceleration_confusion"]),
        spec_mcq("M2L2_T8", "If the same craft's acceleration quadruples, the Master Arrow must have...", ["quadrupled", "halved", "stayed the same", "become zero"], 0, "For fixed mass, force and acceleration scale together.", ["force_mass_acceleration_confusion"]),
    ],
    "M2_L3": [
        spec_mcq("M2L3_T4", "A 2 kg craft moving at 5 m/s sticks to a 3 kg craft at rest. What shared speed follows?", ["2 m/s", "5 m/s", "2.5 m/s", "1 m/s"], 0, "Conserve total momentum, then divide by combined mass.", ["momentum_conservation_system_confusion"]),
        spec_short("M2L3_T5", "Why is force language alone not enough to solve the shared final speed?", ["because the conserved quantity is total momentum", "because system momentum is conserved", "because you need the total Carry Score", "because force is not the conserved quantity"], "The shared final speed comes from conserving system momentum.", ["momentum_force_confusion", "momentum_conservation_system_confusion"]),
        spec_mcq("M2L3_T6", "Which statement can be true?", ["a heavier slower craft can match the momentum of a lighter faster craft", "the faster craft must always have more momentum", "momentum depends on speed only", "mass does not matter once objects move"], 0, "Momentum compares mass with velocity together.", ["momentum_force_confusion"]),
        spec_short("M2L3_T7", "A 4 kg craft moves at 3 m/s and a 2 kg craft moves at -1 m/s. What total Carry Score do they have together?", ["10 kg m/s", "10"], "Add the signed momenta: 12 plus negative 2.", ["momentum_conservation_system_confusion", "momentum_force_confusion"]),
        spec_mcq("M2L3_T8", "If the total system Carry Score before docking is zero, the shared final speed after they stick is...", ["0 m/s", "always 1 m/s", "equal to the larger incoming speed", "impossible to tell"], 0, "Zero total momentum means zero shared momentum after docking too.", ["momentum_conservation_system_confusion"]),
    ],
    "M2_L4": [
        spec_mcq("M2L4_T4", "Which pair gives the same Spin Pull?", ["12 N at 0.25 m and 6 N at 0.5 m", "12 N at 0.25 m and 12 N at 0.5 m", "6 N at 0.5 m and 3 N at 0.25 m", "8 N at 0.4 m and 8 N at 0.2 m"], 0, "Compare force x reach.", ["torque_force_location_confusion"]),
        spec_short("M2L4_T5", "In a few words, what does perpendicular reach mean?", ["shortest distance from pivot to line of action", "distance from pivot to line of action", "moment arm", "perpendicular distance from the pivot"], "Reach is the perpendicular distance from the pivot to the force line.", ["torque_force_location_confusion"]),
        spec_mcq("M2L4_T6", "If the same force is moved farther from the pivot, the turning effect...", ["increases", "decreases", "stays the same", "becomes zero"], 0, "A larger reach gives a larger torque for the same force.", ["torque_force_location_confusion"]),
        spec_short("M2L4_T7", "A 5 N push acts 0.8 m from the pivot. What Spin Pull is produced?", ["4 N m", "4"], "Multiply force by reach.", ["torque_force_location_confusion"]),
        spec_mcq("M2L4_T8", "Which push can create both translation and rotation?", ["an off-center push whose line misses the pivot", "a push exactly through the pivot", "only a zero force", "no push can do both"], 0, "Missing the pivot line can create a turning effect while still pushing the object.", ["torque_force_location_confusion"]),
    ],
    "M2_L5": [
        spec_mcq("M2L5_T4", "Two craft have the same total mass, but one has a much wider base. Which is usually more stable?", ["the wider-base craft", "the narrower-base craft", "they are equally stable because mass matches", "you can only compare if the color matches"], 0, "Base width changes the support margin.", ["stability_weight_confusion"]),
        spec_short("M2L5_T5", "Why is 'heavier means more stable' a weak rule?", ["because stability depends on center of mass and support width", "because center of mass and base matter too", "because weight alone does not decide tipping", "because geometry matters as well as mass"], "Stability is a geometry-and-distribution question, not just a total-mass question.", ["stability_weight_confusion", "centre_of_mass_material_confusion"]),
        spec_mcq("M2L5_T6", "Cargo is moved left until the Balance Core line crosses the support edge. What begins?", ["tipping", "perfect balance", "zero weight", "instant acceleration upward"], 0, "Crossing the support edge marks the tipping condition.", ["stability_weight_confusion"]),
        spec_short("M2L5_T7", "What does the Footprint Zone stand for?", ["base of support", "support area", "support region", "the area under the object"], "The Footprint Zone is the base-of-support idea in the model.", ["stability_weight_confusion"]),
        spec_mcq("M2L5_T8", "If the base stays the same but the load is lowered, the craft usually becomes...", ["more stable", "less stable", "unchanged", "impossible to compare"], 0, "A lower center of mass usually increases the tipping margin.", ["stability_weight_confusion"]),
    ],
    "M2_L6": [
        spec_mcq("M2L6_T4", "A force has components 12 N east and 5 N north. What resultant magnitude does that give?", ["13 N", "7 N", "17 N", "12 N"], 0, "Use the 5-12-13 triangle.", ["vector_resolution_component_confusion", "resultant_force_vector_confusion"]),
        spec_short("M2L6_T5", "What stays the same after Arrow Split?", ["the original vector", "the same resultant", "the same overall force", "the same diagonal force"], "Resolving into components does not change the original force represented.", ["vector_resolution_component_confusion"]),
        spec_mcq("M2L6_T6", "If the net horizontal component is zero, what remains of the resultant?", ["only the vertical component", "no force at all", "only the original diagonal arrow", "two extra forces"], 0, "With zero horizontal part, the resultant lies fully on the vertical axis.", ["resultant_force_vector_confusion"]),
        spec_short("M2L6_T7", "Two horizontal components are 8 N east and 6 N west. What net horizontal component remains?", ["2 N east", "2 east", "2 N"], "Subtract opposite directions and keep the larger direction.", ["resultant_force_vector_confusion"]),
        spec_mcq("M2L6_T8", "Why are components not extra forces?", ["they are one original force rewritten on chosen axes", "they replace the original force permanently", "they only exist after the object moves", "they remove the need for vector direction"], 0, "Resolution changes the description, not the physics interaction.", ["vector_resolution_component_confusion"]),
    ],
}


def enrich_m2_lessons() -> None:
    M2_MODULE_DOC["module_description"] = (
        "Module 2 treats force ideas as a systems-control story: net force, inertia, momentum, torque, stability, and vector resolution are used to explain what changes, what stays invariant, and why."
    )
    M2_MODULE_DOC["identity_note"] = (
        "M2 builds beyond F2, F3, and M1 by treating force and motion ideas as structured system models rather than as first-pass intuition."
    )

    for lesson_id, lesson in LESSON_BY_ID.items():
        phases = lesson["phases"]
        analogical = phases["analogical_grounding"]
        analogical["analogy_text"] = M2_ANALOGY_UPDATES[lesson_id]
        analogical["commitment_prompt"] = M2_COMMITMENT_UPDATES[lesson_id]

        phases["diagnostic"]["items"].extend(build_question(item) for item in M2_EXTRA_DIAGNOSTIC[lesson_id])
        phases["concept_reconstruction"]["capsules"][0]["checks"].extend(build_question(item) for item in M2_EXTRA_CONCEPT[lesson_id])
        phases["transfer"]["items"].extend(build_question(item) for item in M2_EXTRA_TRANSFER[lesson_id])

        contract = lesson["authoring_contract"]
        contract["assessment_bank_targets"] = assessment_targets(6, 4, 8)
        contract["visual_assets"] = [
            {
                "asset_id": f"{lesson_id.lower()}_diagram",
                "concept": M2_LESSON_CONCEPTS[lesson_id],
                "phase_key": "analogical_grounding",
                "title": M2_LESSON_VISUAL_TITLES[lesson_id],
                "purpose": f"Show the main system-model structure for {lesson['title']} with a clearer comparison diagram.",
                "caption": f"{lesson['title']} visual summary",
            }
        ]
        contract["animation_assets"] = [
            {
                "asset_id": f"{lesson_id.lower()}_animation",
                "concept": M2_LESSON_CONCEPTS[lesson_id],
                "phase_key": "analogical_grounding",
                "title": f"{lesson['title']} animation",
                "description": f"Animate the key comparison structure for {lesson['title']}.",
                "duration_sec": 8,
            }
        ]
        simulation_contract = dict(contract.get("simulation_contract") or {})
        simulation_contract.update(
            {
                "asset_id": f"{lesson_id.lower()}_simulation",
                "concept": M2_LESSON_CONCEPTS[lesson_id],
                "engine": "p5",
            }
        )
        contract["simulation_contract"] = simulation_contract

        phases["concept_reconstruction"]["prompts"].append(
            f"Explain how {lesson['title']} uses a system rule or bookkeeping move that goes beyond the earlier intuition-only foundation lessons."
        )

for lesson_spec in M2_SPEC["lessons"]:
    configure_sim(lesson_spec)
    configure_lesson(lesson_spec)

enrich_m2_lessons()

M2_LESSONS: List[Tuple[str, Dict[str, Any]]] = [(str(lesson["lesson_id"]), lesson) for lesson in _LESSONS]
M2_SIM_LABS: List[Tuple[str, Dict[str, Any]]] = [(str(sim["lab_id"]), sim) for sim in _SIMS]

validate_nextgen_module(M2_MODULE_DOC, [payload for _, payload in M2_LESSONS], [payload for _, payload in M2_SIM_LABS], M2_ALLOWLIST)
plan_module_assets(M2_LESSONS, M2_SIM_LABS, public_base="/lesson_assets")

def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M2 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()
    project = get_project_id(args.project)
    apply = bool(args.apply)
    db = init_firebase(project) if apply else None

    module_doc = deepcopy(M2_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M2_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M2_SIM_LABS]

    asset_root = args.asset_root or str(default_asset_root())
    if args.compile_assets:
        render_module_assets(
            lesson_pairs,
            sim_pairs,
            asset_root=asset_root,
            public_base=args.public_base,
        )

    plan: List[Tuple[str, str]] = [("modules", M2_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in lesson_pairs] + [("sim_labs", doc_id) for doc_id, _ in sim_pairs]
    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    if args.compile_assets:
        print(f"Asset root: {asset_root}")
        print(f"Public base: {args.public_base}")
    print_preview("Planned upserts", plan)
    upsert_doc(db, "modules", M2_MODULE_ID, module_doc, apply)
    for doc_id, payload in lesson_pairs:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in sim_pairs:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)
    print("DONE")

if __name__ == "__main__":
    main()
