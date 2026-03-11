import argparse
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import firebase_admin
from firebase_admin import credentials
from google.cloud import firestore


F2_MODULE_ID = "F2"
F2_ALLOWLIST = [
    "distance_displacement_confusion",
    "speed_calculation_error",
    "velocity_direction_confusion",
    "acceleration_sign_confusion",
    "distance_time_graph_error",
    "velocity_time_graph_error",
    "resultant_force_error",
    "balanced_force_motion_confusion",
    "fma_relationship_error",
    "inertia_force_confusion",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_project_id(cli_project: str | None) -> str:
    return (
        cli_project
        or os.getenv("GOOGLE_CLOUD_PROJECT")
        or os.getenv("GCP_PROJECT")
        or os.getenv("GCLOUD_PROJECT")
        or "apip-dev-487809-c949c"
    )


def init_firebase(project_id: str) -> firestore.Client:
    if not firebase_admin._apps:
        cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred, {"projectId": project_id})
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
    return [tag for tag in tags if tag in F2_ALLOWLIST]


def make_mcq(qid: str, prompt: str, choices: List[str], correct_index: int, hint: str, tags: List[str]) -> Dict[str, Any]:
    feedback = [hint for _ in choices]
    if 0 <= correct_index < len(feedback):
        feedback[correct_index] = hint
    return {
        "id": qid,
        "question_id": qid,
        "type": "mcq",
        "prompt": prompt,
        "choices": choices,
        "answer_index": correct_index,
        "hint": hint,
        "feedback": feedback,
        "misconception_tags": safe_tags(tags),
    }


def make_short(qid: str, prompt: str, accepted_answers: List[str], hint: str, tags: List[str]) -> Dict[str, Any]:
    return {
        "id": qid,
        "question_id": qid,
        "type": "short",
        "prompt": prompt,
        "accepted_answers": accepted_answers,
        "hint": hint,
        "feedback": [hint],
        "misconception_tags": safe_tags(tags),
    }


def prompt_block(prompt: str, hint: str) -> Dict[str, Any]:
    return {"prompt": prompt, "hint": hint}


F2_MODULE_DOC: Dict[str, Any] = {
    "id": F2_MODULE_ID,
    "module_id": F2_MODULE_ID,
    "title": "Motion, Forces & Graphs",
    "description": (
        "Distance, displacement, speed, velocity, acceleration, motion graphs, "
        "resultant force, and the force-mass-acceleration relationship."
    ),
    "sequence": 2,
    "level": "Foundation",
    "estimated_minutes": 100,
    "mastery_outcomes": [
        "Distinguish distance from displacement and calculate average speed.",
        "Explain velocity and acceleration, including the meaning of sign.",
        "Interpret slope and shape on distance-time graphs.",
        "Use slope and area on velocity-time graphs.",
        "Find resultant force and relate balanced forces to motion.",
        "Use F = ma and connect inertia to everyday motion.",
    ],
    "misconception_tag_allowlist": F2_ALLOWLIST,
    "updated_utc": utc_now(),
}

F2_SIM_LABS: List[Tuple[str, Dict[str, Any]]] = [
    ("f2_motion_map_lab", {"lab_id": "f2_motion_map_lab", "module_id": F2_MODULE_ID, "title": "Motion Map Lab", "description": "Compare distance travelled, displacement, and average speed for the same journey.", "instructions": ["Build a journey with a forward part, a return part, and a travel time.", "Compare the total path length with the start-to-finish displacement.", "Use the total distance and total time to compute average speed."], "expected_outcomes": ["distance_displacement_confusion", "speed_calculation_error"], "telemetry_schema_hint": {"fields": ["path_changes", "time_changes", "checks_completed"], "sim_depth_meaning": "number of meaningful journey comparisons completed"}, "updated_utc": utc_now()}),
    ("f2_acceleration_lab", {"lab_id": "f2_acceleration_lab", "module_id": F2_MODULE_ID, "title": "Velocity and Acceleration Lab", "description": "Change the start velocity, finish velocity, and time to see how acceleration behaves.", "instructions": ["Compare speed change over the same time interval.", "Notice when acceleration is positive, zero, or negative.", "Relate the sign to the chosen positive direction."], "expected_outcomes": ["velocity_direction_confusion", "acceleration_sign_confusion"], "telemetry_schema_hint": {"fields": ["velocity_changes", "time_changes", "sign_checks"], "sim_depth_meaning": "number of acceleration scenarios explored"}, "updated_utc": utc_now()}),
    ("f2_distance_time_graph_lab", {"lab_id": "f2_distance_time_graph_lab", "module_id": F2_MODULE_ID, "title": "Distance-Time Graph Lab", "description": "Change the slope and pauses on a distance-time graph and connect them to motion.", "instructions": ["Compare shallow and steep segments.", "Add a flat section to represent a pause.", "Explain what the line shape says about speed."], "expected_outcomes": ["distance_time_graph_error", "speed_calculation_error"], "telemetry_schema_hint": {"fields": ["segment_changes", "pause_changes", "interpretation_checks"], "sim_depth_meaning": "number of graph interpretations tested"}, "updated_utc": utc_now()}),
    ("f2_velocity_time_graph_lab", {"lab_id": "f2_velocity_time_graph_lab", "module_id": F2_MODULE_ID, "title": "Velocity-Time Graph Lab", "description": "Use slope and area to interpret acceleration and displacement on a velocity-time graph.", "instructions": ["Change the start velocity, end velocity, and time interval.", "Use the slope to discuss acceleration.", "Use the area to discuss displacement in one direction."], "expected_outcomes": ["velocity_time_graph_error", "acceleration_sign_confusion"], "telemetry_schema_hint": {"fields": ["velocity_changes", "duration_changes", "graph_checks"], "sim_depth_meaning": "number of slope-area comparisons completed"}, "updated_utc": utc_now()}),
    ("f2_force_balance_lab", {"lab_id": "f2_force_balance_lab", "module_id": F2_MODULE_ID, "title": "Force Balance Lab", "description": "Compare left and right forces to find the resultant and predict the motion change.", "instructions": ["Set equal and unequal opposing forces.", "Find the resultant force and its direction.", "Explain when balanced forces mean constant velocity instead of rest."], "expected_outcomes": ["resultant_force_error", "balanced_force_motion_confusion"], "telemetry_schema_hint": {"fields": ["force_changes", "balance_checks", "direction_checks"], "sim_depth_meaning": "number of resultant-force comparisons completed"}, "updated_utc": utc_now()}),
    ("f2_fma_lab", {"lab_id": "f2_fma_lab", "module_id": F2_MODULE_ID, "title": "Force, Mass, and Motion Lab", "description": "Change force and mass to see how acceleration responds and connect the result to inertia.", "instructions": ["Hold mass fixed and raise the force.", "Hold force fixed and raise the mass.", "Explain why a lighter object speeds up more under the same force."], "expected_outcomes": ["fma_relationship_error", "inertia_force_confusion"], "telemetry_schema_hint": {"fields": ["force_changes", "mass_changes", "comparison_checks"], "sim_depth_meaning": "number of F=ma scenarios explored"}, "updated_utc": utc_now()}),
]

F2_LESSONS: List[Tuple[str, Dict[str, Any]]] = []


def add_lesson(doc_id: str, sequence: int, title: str, analogy: str, sim_lab_id: str | None, diagnostic_items: List[Dict[str, Any]], transfer_items: List[Dict[str, Any]], reconstruction_prompts: List[str], inquiry_prompts: List[Dict[str, Any]], capsule_prompt: str, capsule_checks: List[Dict[str, Any]]) -> None:
    F2_LESSONS.append((doc_id, {"id": doc_id, "lesson_id": doc_id, "moduleId": F2_MODULE_ID, "module_id": F2_MODULE_ID, "sequence": sequence, "order": sequence, "title": title, "updated_utc": utc_now(), "phases": {"diagnostic": {"two_tier": True, "items": diagnostic_items, "notes": "Start with quick checks to expose the main misconception before the lesson opens."}, "analogical_grounding": {"analogy_text": analogy, "commitment_prompt": "Before moving on, make a short prediction about what the motion or force pattern means.", "micro_prompts": [prompt_block(reconstruction_prompts[0], reconstruction_prompts[0])]}, "simulation_inquiry": {"lab_id": sim_lab_id, "inquiry_prompts": inquiry_prompts}, "concept_reconstruction": {"prompts": reconstruction_prompts, "capsules": [{"prompt": capsule_prompt, "checks": capsule_checks}]}, "transfer": {"items": transfer_items, "notes": "Use transfer questions to check whether the idea survives a new context."}}}))


add_lesson("F2_L1", 1, "Distance, Displacement, and Speed", "Distance is the whole path walked, while displacement is the straight start-to-finish arrow.", "f2_motion_map_lab", [make_mcq("F2L1_D1", "Which quantity needs direction to be complete?", ["distance", "speed", "displacement", "time"], 2, "Displacement needs both size and direction.", ["distance_displacement_confusion"]), make_mcq("F2L1_D2", "A runner covers 120 m in 20 s. What is the average speed?", ["4 m/s", "5 m/s", "6 m/s", "8 m/s"], 2, "Use speed = distance / time.", ["speed_calculation_error"])], [make_mcq("F2L1_T1", "A learner walks 10 m east and then 4 m west. Which pair is correct?", ["distance 6 m, displacement 6 m east", "distance 14 m, displacement 6 m east", "distance 14 m, displacement 14 m east", "distance 6 m, displacement 14 m east"], 1, "Distance is total path length, while displacement keeps the net change with direction.", ["distance_displacement_confusion"]), make_short("F2L1_T2", "A cyclist travels 300 m in 60 s. What is the average speed?", ["5", "5 m/s"], "Divide the total distance by the total time.", ["speed_calculation_error"]), make_mcq("F2L1_T3", "Which quantity is scalar?", ["displacement", "velocity", "speed", "force"], 2, "Scalars need size only.", ["distance_displacement_confusion"])], ["Explain why distance and displacement can differ for the same journey.", "Explain what average speed compares."], [prompt_block("Compare total path length with start-to-finish change.", "A return part changes displacement differently from distance."), prompt_block("Change the travel time without changing the path.", "Average speed depends on total distance and total time together.")], "Distance counts the whole path, while displacement keeps the start-to-finish change with direction.", [make_mcq("F2L1_C1", "A student walks 8 m east and 3 m west. Which statement is correct?", ["Distance is 11 m and displacement is 5 m east", "Distance is 5 m and displacement is 11 m east", "Distance is 11 m and displacement is 11 m east", "Distance is 5 m and displacement is 5 m east"], 0, "Add the full path for distance, then keep the net direction for displacement.", ["distance_displacement_confusion"])])
add_lesson("F2_L2", 2, "Velocity and Acceleration", "Velocity is speed with direction, and acceleration tells how much the velocity changes each second.", "f2_acceleration_lab", [make_mcq("F2L2_D1", "Velocity is best described as...", ["speed with direction", "speed without units", "distance per mass", "always positive"], 0, "Velocity includes direction.", ["velocity_direction_confusion"]), make_mcq("F2L2_D2", "Velocity changes from 4 m/s to 10 m/s in 3 s. What is the acceleration?", ["1 m/s^2", "2 m/s^2", "3 m/s^2", "6 m/s^2"], 1, "Use acceleration = change in velocity / time.", ["acceleration_sign_confusion"])], [make_mcq("F2L2_T1", "Velocity changes from 12 m/s to 4 m/s in 2 s. If forward is positive, what is the acceleration?", ["-4 m/s^2", "-8 m/s^2", "4 m/s^2", "8 m/s^2"], 0, "A decrease in forward velocity gives negative acceleration in this sign convention.", ["acceleration_sign_confusion"]), make_short("F2L2_T2", "Velocity changes from 0 m/s to 15 m/s in 5 s. What is the acceleration?", ["3", "3 m/s^2"], "Use acceleration = change in velocity / time.", ["acceleration_sign_confusion"])], ["Explain how velocity differs from speed.", "Explain what the sign of acceleration means."], [prompt_block("Change the start and finish velocities.", "A bigger velocity change in the same time gives a bigger acceleration."), prompt_block("Make the finish velocity smaller than the start velocity.", "Negative acceleration depends on the chosen positive direction.")], "Velocity includes direction, and acceleration compares the change in velocity with time.", [make_mcq("F2L2_C1", "Two objects move at the same speed in opposite directions. What changes?", ["The velocity changes", "The velocity stays the same", "The time becomes zero", "The displacement becomes a scalar"], 0, "Velocity changes when direction changes.", ["velocity_direction_confusion"])])
add_lesson("F2_L3", 3, "Distance-Time Graphs", "A distance-time graph is like a motion story drawn as a line: the slope tells how quickly the story is moving.", "f2_distance_time_graph_lab", [make_mcq("F2L3_D1", "A horizontal section on a distance-time graph means the object is...", ["speeding up", "moving back", "stopped", "experiencing zero time"], 2, "If distance is not changing, the object is not moving.", ["distance_time_graph_error"]), make_mcq("F2L3_D2", "A steeper straight line on a distance-time graph means...", ["slower speed", "faster speed", "negative force", "less time exists"], 1, "The slope represents speed on a distance-time graph.", ["distance_time_graph_error"])], [make_mcq("F2L3_T1", "A distance-time graph becomes steeper later. The object is...", ["stopping", "moving at constant speed", "speeding up", "balanced"], 2, "A bigger slope later means a bigger speed later.", ["distance_time_graph_error"]), make_short("F2L3_T2", "A straight graph rises 12 m in 4 s. What is the speed?", ["3", "3 m/s"], "Use slope = distance / time for a straight section.", ["speed_calculation_error", "distance_time_graph_error"])], ["Explain how slope links to speed on a distance-time graph.", "Explain why a flat section means the object is stopped."], [prompt_block("Compare a shallow slope and a steep slope.", "The steeper section represents the faster motion."), prompt_block("Add a pause between two moving sections.", "A pause creates a flat section because the distance stops changing.")], "On a distance-time graph, slope shows speed and a flat section shows no change in distance.", [make_mcq("F2L3_C1", "If the graph line becomes steeper later, what does that mean?", ["The object slows down", "The object keeps the same speed", "The object moves faster later", "Time stops"], 2, "A steeper line means a greater speed.", ["distance_time_graph_error"])])
add_lesson("F2_L4", 4, "Velocity-Time Graphs", "A velocity-time graph has two big clues: slope tells acceleration, and the area under the line tells displacement in one direction.", "f2_velocity_time_graph_lab", [make_mcq("F2L4_D1", "The area under a velocity-time graph represents...", ["mass", "displacement", "force", "power"], 1, "Area combines velocity with time.", ["velocity_time_graph_error"]), make_mcq("F2L4_D2", "The slope of a velocity-time graph represents...", ["acceleration", "mass", "density", "work"], 0, "Slope compares the change in velocity with time.", ["velocity_time_graph_error"])], [make_mcq("F2L4_T1", "Velocity rises from 2 m/s to 8 m/s in 3 s. What is the acceleration?", ["1 m/s^2", "2 m/s^2", "3 m/s^2", "6 m/s^2"], 1, "Use acceleration = change in velocity / time.", ["velocity_time_graph_error", "acceleration_sign_confusion"]), make_short("F2L4_T2", "An object moves at 4 m/s for 5 s. What displacement is shown by the graph area?", ["20", "20 m"], "For constant velocity, area is velocity x time.", ["velocity_time_graph_error"])], ["Explain what slope means on a velocity-time graph.", "Explain what area means on a velocity-time graph."], [prompt_block("Change the start velocity, end velocity, and duration.", "A steeper line means a larger acceleration."), prompt_block("Keep the velocity positive and stretch the time interval.", "A larger area means a larger displacement in the same direction.")], "On a velocity-time graph, slope means acceleration and area means displacement.", [make_mcq("F2L4_C1", "How does constant positive velocity appear on a velocity-time graph?", ["A horizontal line above zero", "A vertical line", "A downward curve", "A line that always crosses zero"], 0, "Constant positive velocity stays at one positive value.", ["velocity_time_graph_error"])])
add_lesson("F2_L5", 5, "Resultant Force and Balanced Motion", "Opposite forces are like tug-of-war pulls. Equal pulls balance out, while a bigger pull leaves a resultant force in its own direction.", "f2_force_balance_lab", [make_mcq("F2L5_D1", "5 N left and 5 N right give a resultant force of...", ["0 N", "5 N", "10 N", "2.5 N"], 0, "Equal opposite forces cancel.", ["resultant_force_error"]), make_mcq("F2L5_D2", "7 N right and 2 N left give a resultant force of...", ["5 N right", "5 N left", "9 N right", "9 N left"], 0, "Subtract opposite forces and keep the bigger direction.", ["resultant_force_error"])], [make_mcq("F2L5_T1", "Balanced forces mean an object can be...", ["only stopped", "only speeding up", "at rest or moving at constant velocity", "massless"], 2, "Zero resultant force means no change in velocity.", ["balanced_force_motion_confusion"]), make_short("F2L5_T2", "10 N right and 6 N left give what resultant force?", ["4", "4 N", "4 N right"], "Subtract the opposite forces and keep the bigger direction.", ["resultant_force_error"])], ["Explain the difference between balanced and unbalanced forces.", "Explain why zero resultant force does not always mean the object is at rest."], [prompt_block("Make the left and right forces equal.", "Balanced forces give zero resultant force."), prompt_block("Make one force larger than the other.", "Unbalanced forces leave a resultant in the direction of the larger force.")], "Balanced forces mean zero resultant force and no change in velocity.", [make_mcq("F2L5_C1", "If the resultant force on a moving object is zero, the object can...", ["stop immediately", "keep moving at constant velocity", "speed up", "reverse direction by itself"], 1, "Zero resultant force means no change in velocity.", ["balanced_force_motion_confusion"])])
add_lesson("F2_L6", 6, "Force, Mass, and Motion (Wrap-up)", "The same shove changes a light trolley more than a heavy one, so acceleration depends on both the force and the mass.", "f2_fma_lab", [make_mcq("F2L6_D1", "A 12 N resultant force acts on a 3 kg trolley. What is the acceleration?", ["2 m/s^2", "3 m/s^2", "4 m/s^2", "12 m/s^2"], 2, "Use a = F / m.", ["fma_relationship_error"]), make_mcq("F2L6_D2", "The same force acts on two objects. Which object accelerates more?", ["the more massive one", "the less massive one", "both equally", "the one with the bigger volume"], 1, "For the same force, less mass gives more acceleration.", ["fma_relationship_error"])], [make_mcq("F2L6_T1", "Why does a seatbelt help in a sudden stop?", ["It removes mass", "It provides the force that changes your motion with the car", "It removes inertia", "It makes the car lighter"], 1, "A force is needed to change the passenger's motion with the car.", ["inertia_force_confusion"]), make_short("F2L6_T2", "A 2 kg trolley accelerates at 3 m/s^2. What resultant force acts on it?", ["6", "6 N"], "Use F = ma.", ["fma_relationship_error"])], ["Explain how force, mass, and acceleration are linked.", "Explain inertia with one safety example."], [prompt_block("Hold mass fixed and increase the force.", "Acceleration increases when the same mass feels a larger resultant force."), prompt_block("Hold force fixed and increase the mass.", "Acceleration decreases when the same force has to move more mass.")], "F = ma links resultant force, mass, and acceleration, while inertia resists changes in motion.", [make_mcq("F2L6_C1", "A passenger leans forward when a car stops because...", ["the passenger has no mass", "inertia keeps the body moving while the car slows", "balanced forces increase speed", "velocity has no direction"], 1, "Inertia resists sudden changes in motion.", ["inertia_force_confusion"])])


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module F2 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    project = get_project_id(args.project)
    db = init_firebase(project)
    apply = bool(args.apply)

    plan: List[Tuple[str, str]] = [("modules", F2_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in F2_LESSONS] + [("sim_labs", doc_id) for doc_id, _ in F2_SIM_LABS]
    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    print_preview("Planned upserts", plan)

    upsert_doc(db, "modules", F2_MODULE_ID, F2_MODULE_DOC, apply)
    for doc_id, payload in F2_LESSONS:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in F2_SIM_LABS:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)

    print("DONE")


if __name__ == "__main__":
    main()
