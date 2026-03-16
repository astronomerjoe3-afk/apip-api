from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import firebase_admin
from firebase_admin import credentials
from google.cloud import firestore

try:
    from scripts.lesson_authoring_contract import validate_nextgen_module
    from scripts.nextgen_module_scaffold import build_nextgen_module_scaffold
except ModuleNotFoundError:
    from lesson_authoring_contract import validate_nextgen_module
    from nextgen_module_scaffold import build_nextgen_module_scaffold

M2_MODULE_ID = "M2"
M2_CONTENT_VERSION = "20260316_m2_thruster_deck_v1"
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
        { "kind": "short", "id": "M2L1_T1", "prompt": "A craft has 7 N east and 11 N west. What is the Master Arrow?", "accepted_answers": ["4 N west", "4 west", "4 N"], "hint": "Compare the opposite sides and keep the larger direction.", "tags": ["resultant_force_vector_confusion"] },
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
            "prompt": "A craft has 10 N forward and 6 N backward. Find the Master Arrow and predict the motion change.",
            "steps": [
              "Compare the opposite forces first because they act on the same line.",
              "Subtract the smaller from the larger: 10 - 6 = 4 N.",
              "Keep the direction of the larger side, so the Master Arrow is 4 N forward.",
              "A non-zero Master Arrow means the craft accelerates forward."
            ],
            "final_answer": "Master Arrow = 4 N forward, so the craft accelerates forward.",
            "why_it_matters": "Students must combine forces before they talk about motion."
          },
          {
            "prompt": "A learner says a moving craft must still have a forward Master Arrow. Evaluate the claim.",
            "steps": [
              "Start with Newton's first-law idea from Thruster-Deck.",
              "Zero Master Arrow means zero motion change, not zero motion.",
              "A craft can already be cruising and keep cruising even while the Master Arrow is zero.",
              "So motion alone is not evidence of a continuing resultant force."
            ],
            "final_answer": "The claim is wrong.",
            "why_it_matters": "This directly blocks the classic motion-implies-force misconception."
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
          {"prompt": "A 12 N Master Arrow acts on a 3 kg craft. Predict the Motion Shift.", "steps": ["Use the Master Arrow, not one isolated force.", "Identify the Load Rating as 3 kg.", "Divide 12 N by 3 kg to get 4 m/s^2.", "State that the acceleration points with the Master Arrow."], "final_answer": "Motion Shift = 4 m/s^2 in the direction of the Master Arrow.", "why_it_matters": "This keeps force, mass, and acceleration tied together rather than memorized apart."},
          {"prompt": "A student says the heavier craft pushes back harder in a collision. Evaluate the claim.", "steps": ["Use the third-law idea of matched interaction arrows.", "State that the forces are equal and opposite on different objects.", "Explain that the masses can still give different accelerations.", "Separate force-pair equality from motion-change equality."], "final_answer": "The claim is wrong because the force pair is equal and opposite even when the accelerations differ.", "why_it_matters": "Students often mix up third-law forces with second-law acceleration outcomes."}
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
          {"prompt": "Compare a 5 kg craft at 2 m/s with a 2 kg craft at 5 m/s.", "steps": ["Calculate the first Carry Score as 10 kg m/s.", "Calculate the second Carry Score as 10 kg m/s.", "State that equal momentum can come from different mass-speed combinations.", "Reject the idea that speed alone decides momentum."], "final_answer": "They have the same Carry Score of 10 kg m/s.", "why_it_matters": "This blocks the speed-only misconception."},
          {"prompt": "Two 2 kg craft dock. One moves at 4 m/s and the other is at rest. Find the final speed.", "steps": ["Find total momentum before docking: 8 kg m/s.", "Add the masses to get 4 kg after docking.", "Divide total momentum by total mass.", "State the common speed as 2 m/s."], "final_answer": "Final shared speed = 2 m/s.", "why_it_matters": "This makes conservation a system calculation instead of a memorized slogan."}
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
          {"prompt": "A 5 N push acts 0.4 m from a pivot. Find the Spin Pull.", "steps": ["Read the force as 5 N.", "Read the perpendicular reach as 0.4 m.", "Multiply to get 2 N m.", "State that this is a turning effect, not a force."], "final_answer": "Spin Pull = 2 N m.", "why_it_matters": "This prevents students from renaming force as torque without using the reach."},
          {"prompt": "Compare opening a door near the hinges and at the handle.", "steps": ["Keep the force idea the same in both cases.", "Notice that the handle is farther from the pivot.", "Infer that the same force creates a larger turning effect there.", "Connect that to everyday design."], "final_answer": "The handle gives the larger turning effect because the reach is larger.", "why_it_matters": "The everyday door story makes off-centre force reasoning stick."}
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
          {"prompt": "A crate is moved to the right side of a deck. Predict the Balance Core shift.", "steps": ["Keep the total mass in mind.", "Notice that the mass distribution moved right.", "Shift the Balance Core toward the moved mass.", "Use that shift to judge the new stability."], "final_answer": "The Balance Core shifts right.", "why_it_matters": "This makes centre of mass a balance idea, not just a name."},
          {"prompt": "Compare a narrow base and a wide base with the same Balance Core location.", "steps": ["Hold the centre of mass fixed.", "Compare how close the weight line is to the base edge in each case.", "See that the wider base gives more safety margin.", "Conclude that support width affects stability."], "final_answer": "The wider base is more stable.", "why_it_matters": "This blocks the idea that weight alone decides stability."}
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
        {"prompt": "Resolve a 10 N force into 6 N east and 8 N north components and rebuild the resultant.", "steps": ["Treat the 6 N and 8 N as perpendicular parts.", "Combine them with the right-triangle relation.", "Recover a 10 N resultant.", "State that the components rebuild the same original force."], "final_answer": "The components rebuild a 10 N resultant.", "why_it_matters": "This keeps component reasoning tied to the original vector."},
        {"prompt": "Two horizontal components are 9 N east and 5 N west. Combine them.", "steps": ["Work on one axis only first.", "Subtract the smaller from the larger.", "Keep the larger direction, east.", "Carry that net horizontal part into the final resultant."], "final_answer": "Net horizontal component = 4 N east.", "why_it_matters": "This connects vector resolution back to the same resultant-force reasoning used earlier."}
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

for lesson_spec in M2_SPEC["lessons"]:
    configure_sim(lesson_spec)
    configure_lesson(lesson_spec)

M2_LESSONS: List[Tuple[str, Dict[str, Any]]] = [(str(lesson["lesson_id"]), lesson) for lesson in _LESSONS]
M2_SIM_LABS: List[Tuple[str, Dict[str, Any]]] = [(str(sim["lab_id"]), sim) for sim in _SIMS]

validate_nextgen_module(M2_MODULE_DOC, [payload for _, payload in M2_LESSONS], [payload for _, payload in M2_SIM_LABS], M2_ALLOWLIST)

def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M2 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    project = get_project_id(args.project)
    db = init_firebase(project)
    apply = bool(args.apply)
    plan: List[Tuple[str, str]] = [("modules", M2_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in M2_LESSONS] + [("sim_labs", doc_id) for doc_id, _ in M2_SIM_LABS]
    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    print_preview("Planned upserts", plan)
    upsert_doc(db, "modules", M2_MODULE_ID, M2_MODULE_DOC, apply)
    for doc_id, payload in M2_LESSONS:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in M2_SIM_LABS:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)
    print("DONE")

if __name__ == "__main__":
    main()
