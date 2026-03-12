import argparse
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import firebase_admin
from firebase_admin import credentials
from google.cloud import firestore


F3_MODULE_ID = "F3"
F3_CONTENT_VERSION = "20260313_f3_launch_v1"
F3_ALLOWLIST = [
    "work_energy_transfer_confusion",
    "kinetic_energy_relationship_error",
    "gravitational_potential_energy_error",
    "power_rate_confusion",
    "efficiency_calculation_error",
    "momentum_vector_confusion",
    "momentum_conservation_confusion",
    "impulse_force_time_confusion",
    "collision_safety_reasoning_confusion",
    "braking_energy_comparison_confusion",
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
    return [tag for tag in tags if tag in F3_ALLOWLIST]


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


def f3_micro_prompts(doc_id: str) -> List[Dict[str, Any]]:
    prompts = {
        "F3_L1": [prompt_block("Compare a moving crate with a hard push on a wall that never moves.", "A force only transfers energy as work when there is movement in the force direction.")],
        "F3_L2": [prompt_block("Compare doubling the mass with doubling the speed for the same moving object.", "Kinetic energy depends on speed more strongly because speed is squared.")],
        "F3_L3": [prompt_block("Imagine two machines doing the same job, but one finishes sooner and wastes less energy.", "Power compares rate, while efficiency compares useful output with total input.")],
        "F3_L4": [prompt_block("Compare two colliding trolleys before and after impact instead of following one trolley only.", "Conservation of momentum is about the total momentum of the system when external forces are negligible.")],
        "F3_L5": [prompt_block("Compare catching an egg with rigid hands and with hands that move backward.", "The same momentum change over a longer time means a smaller average force.")],
        "F3_L6": [prompt_block("Compare braking at moderate speed and high speed before you talk about stopping force.", "Higher speed raises both momentum and kinetic energy, so stopping becomes harder in more than one way.")],
    }
    return prompts.get(doc_id, [prompt_block("Use the analogy to decide what changes, what is conserved, and what is being transferred.", "Match the analogy carefully before using the formula.")])


F3_MODULE_DOC: Dict[str, Any] = {
    "id": F3_MODULE_ID,
    "module_id": F3_MODULE_ID,
    "title": "Energy, Momentum & Interactions",
    "description": (
        "Build on F2 by tracing how forces transfer energy, comparing kinetic and gravitational energy stores, "
        "using power and efficiency to judge processes, and explaining collisions, impulse, and braking through momentum."
    ),
    "sequence": 3,
    "level": "Foundation 3",
    "estimated_minutes": 135,
    "content_version": F3_CONTENT_VERSION,
    "mastery_outcomes": [
        "Explain work as a force transferring energy through distance in the force direction.",
        "Compare kinetic and gravitational potential energy and reason about how each changes.",
        "Use power and efficiency to judge how quickly and how effectively a process transfers energy.",
        "Treat momentum as a directed quantity and apply conservation in simple isolated interactions.",
        "Use impulse and force-time reasoning to connect momentum change with collision safety.",
        "Explain braking and crash safety using both momentum and energy ideas instead of one formula alone.",
    ],
    "misconception_tag_allowlist": F3_ALLOWLIST,
    "updated_utc": utc_now(),
}

F3_SIM_LABS: List[Tuple[str, Dict[str, Any]]] = [
    (
        "f3_work_transfer_lab",
        {
            "lab_id": "f3_work_transfer_lab",
            "module_id": F3_MODULE_ID,
            "title": "Work and Energy Transfer Lab",
            "description": "Change force and distance together so work is seen as transferred energy, not just a memorized multiplication.",
            "instructions": [
                "Hold the force fixed and change the distance moved.",
                "Hold the distance fixed and change the force.",
                "Compare a moving object with a case where no movement happens.",
                "Explain what the numerical work value means physically in each setup.",
            ],
            "expected_outcomes": ["work_energy_transfer_confusion"],
            "telemetry_schema_hint": {
                "fields": ["force_changes", "distance_changes", "movement_checks", "transfer_explanations"],
                "sim_depth_meaning": "number of work comparisons linked to a clear energy-transfer explanation",
            },
            "updated_utc": utc_now(),
        },
    ),
    (
        "f3_energy_stores_lab",
        {
            "lab_id": "f3_energy_stores_lab",
            "module_id": F3_MODULE_ID,
            "title": "Energy Stores Lab",
            "description": "Compare how mass, speed, and height affect kinetic and gravitational potential energy.",
            "instructions": [
                "Change mass while speed stays fixed and compare the kinetic energy.",
                "Change speed while mass stays fixed and notice the stronger effect on kinetic energy.",
                "Change height while mass stays fixed and compare the gravitational potential energy.",
                "Explain where the energy is stored in each setup.",
            ],
            "expected_outcomes": ["kinetic_energy_relationship_error", "gravitational_potential_energy_error"],
            "telemetry_schema_hint": {
                "fields": ["mass_changes", "speed_changes", "height_changes", "store_explanations"],
                "sim_depth_meaning": "number of mass-speed-height comparisons interpreted with the right energy store",
            },
            "updated_utc": utc_now(),
        },
    ),
    (
        "f3_power_efficiency_lab",
        {
            "lab_id": "f3_power_efficiency_lab",
            "module_id": F3_MODULE_ID,
            "title": "Power and Efficiency Lab",
            "description": "Separate the rate of transfer from the fraction that is useful.",
            "instructions": [
                "Keep the transferred energy fixed and shorten the time to compare power.",
                "Keep the input fixed and change the useful output to compare efficiency.",
                "Compare two processes that have the same power but different efficiency.",
                "Explain why a fast machine is not automatically an efficient one.",
            ],
            "expected_outcomes": ["power_rate_confusion", "efficiency_calculation_error"],
            "telemetry_schema_hint": {
                "fields": ["energy_changes", "time_changes", "useful_output_changes", "comparison_checks"],
                "sim_depth_meaning": "number of rate-versus-efficiency comparisons justified correctly",
            },
            "updated_utc": utc_now(),
        },
    ),
    (
        "f3_momentum_lab",
        {
            "lab_id": "f3_momentum_lab",
            "module_id": F3_MODULE_ID,
            "title": "Momentum Interaction Lab",
            "description": "Combine mass and velocity into momentum, then compare the total before and after a simple collision.",
            "instructions": [
                "Change the incoming mass and speed of one trolley.",
                "Change the second trolley mass while it starts at rest.",
                "Predict the joined speed after the collision from total momentum.",
                "Explain why momentum needs direction when two objects move in opposite directions.",
            ],
            "expected_outcomes": ["momentum_vector_confusion", "momentum_conservation_confusion"],
            "telemetry_schema_hint": {
                "fields": ["mass_changes", "velocity_changes", "collision_predictions", "system_checks"],
                "sim_depth_meaning": "number of collision cases interpreted with total system momentum",
            },
            "updated_utc": utc_now(),
        },
    ),
    (
        "f3_impulse_lab",
        {
            "lab_id": "f3_impulse_lab",
            "module_id": F3_MODULE_ID,
            "title": "Impulse and Force-Time Lab",
            "description": "Link the area of a force-time interaction to impulse and to the resulting momentum change.",
            "instructions": [
                "Set a momentum change target and compare short and long stopping times.",
                "Use average force multiplied by time to calculate impulse.",
                "Compare two force-time rectangles with the same area.",
                "Explain why increasing stopping time reduces force for the same momentum change.",
            ],
            "expected_outcomes": ["impulse_force_time_confusion", "collision_safety_reasoning_confusion"],
            "telemetry_schema_hint": {
                "fields": ["force_changes", "time_changes", "impulse_checks", "safety_explanations"],
                "sim_depth_meaning": "number of force-time comparisons linked to the same or different impulse",
            },
            "updated_utc": utc_now(),
        },
    ),
    (
        "f3_braking_safety_lab",
        {
            "lab_id": "f3_braking_safety_lab",
            "module_id": F3_MODULE_ID,
            "title": "Braking and Safety Lab",
            "description": "Compare how speed, mass, and stopping time change momentum, kinetic energy, and average stopping force together.",
            "instructions": [
                "Change the speed while mass stays fixed and compare momentum with kinetic energy.",
                "Change the mass while speed stays fixed and compare how both quantities respond.",
                "Shorten and lengthen the stopping time for the same vehicle.",
                "Explain why safety features often work by increasing the stopping time and spreading the energy transfer.",
            ],
            "expected_outcomes": ["braking_energy_comparison_confusion", "collision_safety_reasoning_confusion"],
            "telemetry_schema_hint": {
                "fields": ["mass_changes", "speed_changes", "time_changes", "safety_reasoning"],
                "sim_depth_meaning": "number of braking comparisons explained with both momentum and energy ideas",
            },
            "updated_utc": utc_now(),
        },
    ),
]

F3_LESSONS: List[Tuple[str, Dict[str, Any]]] = []


def add_lesson(doc_id: str, sequence: int, title: str, analogy: str, sim_lab_id: str | None, diagnostic_items: List[Dict[str, Any]], transfer_items: List[Dict[str, Any]], reconstruction_prompts: List[str], inquiry_prompts: List[Dict[str, Any]], capsule_prompt: str, capsule_checks: List[Dict[str, Any]]) -> None:
    F3_LESSONS.append((doc_id, {"id": doc_id, "lesson_id": doc_id, "moduleId": F3_MODULE_ID, "module_id": F3_MODULE_ID, "sequence": sequence, "order": sequence, "title": title, "updated_utc": utc_now(), "phases": {"diagnostic": {"two_tier": True, "items": diagnostic_items, "notes": "Use the opening check to surface the main conceptual gap before the lesson deepens it."}, "analogical_grounding": {"analogy_text": analogy, "commitment_prompt": "Before moving on, predict what should change, what should stay linked, or what should be conserved.", "micro_prompts": f3_micro_prompts(doc_id)}, "simulation_inquiry": {"lab_id": sim_lab_id, "inquiry_prompts": inquiry_prompts[:1]}, "concept_reconstruction": {"prompts": reconstruction_prompts, "capsules": [{"prompt": capsule_prompt, "checks": capsule_checks}]}, "transfer": {"items": transfer_items, "notes": "Use transfer questions to check whether the deeper idea survives in a new context."}}}))


add_lesson(
    "F3_L1",
    1,
    "Work and Energy Transfer",
    "Doing work in physics is like paying movers to shift a heavy crate: the transfer only counts when the crate actually moves in the direction of the push.",
    "f3_work_transfer_lab",
    [
        make_mcq("F3L1_D1", "A force does work on an object only when...", ["the object moves in the direction of the force", "the object has mass", "the force is large", "time passes while the force exists"], 0, "Work in physics means a force transfers energy by causing movement in its direction.", ["work_energy_transfer_confusion"]),
        make_short("F3L1_D2", "A 15 N force pushes a box 4 m in the same direction. What work is done?", ["60 J"], "Use work = force x distance moved in the force direction.", ["work_energy_transfer_confusion"]),
    ],
    [
        make_mcq("F3L1_T1", "A learner pushes hard on a wall but the wall does not move. What work is done on the wall?", ["0 J", "some work because a force exists", "the work equals the learner's mass", "it depends only on time"], 0, "No movement means no work is done on the wall, even if effort is felt.", ["work_energy_transfer_confusion"]),
        make_short("F3L1_T2", "A 25 N force pulls a trolley 3 m in the same direction. What work is done?", ["75 J"], "Multiply the force by the distance moved in the force direction.", ["work_energy_transfer_confusion"]),
    ],
    [
        "Explain why force alone is not enough for work to be done.",
        "Explain what it means to say that work transfers energy to or from an object.",
    ],
    [
        prompt_block("Keep the force fixed and change the distance moved.", "More distance in the force direction means more work is done."),
        prompt_block("Compare a moving case with a no-movement case.", "No movement means no work is transferred to the object by that force."),
    ],
    "Work measures energy transferred by a force when the object moves in the force direction, so both force and displacement matter together.",
    [
        make_mcq("F3L1_C1", "If the work done doubles while the force stays the same, what must happen to the distance moved in the force direction?", ["It doubles", "It halves", "It stays the same", "It becomes zero"], 0, "With force fixed, work changes in direct proportion to distance.", ["work_energy_transfer_confusion"]),
    ],
)

add_lesson(
    "F3_L2",
    2,
    "Kinetic and Gravitational Potential Energy",
    "Think of energy like money stored in two different accounts: a motion account for kinetic energy and a height account for gravitational potential energy.",
    "f3_energy_stores_lab",
    [
        make_mcq("F3L2_D1", "Which change has the strongest effect on kinetic energy for the same object?", ["doubling the mass", "doubling the speed", "doubling the time", "changing the direction only"], 1, "Kinetic energy depends on speed squared, so speed changes have a stronger effect.", ["kinetic_energy_relationship_error"]),
        make_short("F3L2_D2", "A 2 kg trolley moves at 4 m/s. What is its kinetic energy?", ["16 J"], "Use kinetic energy = 0.5 x m x v^2.", ["kinetic_energy_relationship_error"]),
    ],
    [
        make_mcq("F3L2_T1", "A 5 kg bag is lifted 3 m. Take g = 10 N/kg. How much gravitational potential energy is gained?", ["15 J", "50 J", "150 J", "300 J"], 2, "Use GPE = mgh.", ["gravitational_potential_energy_error"]),
        make_mcq("F3L2_T2", "If speed doubles while mass stays the same, kinetic energy becomes...", ["twice as large", "four times as large", "eight times as large", "unchanged"], 1, "Because speed is squared in the kinetic energy formula, doubling speed quadruples KE.", ["kinetic_energy_relationship_error"]),
    ],
    [
        "Explain why speed has a stronger effect on kinetic energy than mass does.",
        "Explain where the extra energy is stored when an object is lifted higher.",
    ],
    [
        prompt_block("Hold mass fixed and compare two different speeds.", "The faster object stores much more kinetic energy because speed is squared."),
        prompt_block("Hold mass fixed and raise the height.", "GPE rises in direct proportion to height when g stays fixed."),
    ],
    "Kinetic energy is the energy of motion and depends on mass and speed, while gravitational potential energy depends on weight and height above a reference level.",
    [
        make_mcq("F3L2_C1", "Which change always increases gravitational potential energy if g stays fixed?", ["greater height", "less time", "smaller speed", "changing direction only"], 0, "GPE depends on mass, g, and height, so greater height raises it.", ["gravitational_potential_energy_error"]),
    ],
)

add_lesson(
    "F3_L3",
    3,
    "Power and Efficiency",
    "Power is like how fast water fills a bucket, while efficiency is how much of that water ends up in the useful bucket instead of spilling away.",
    "f3_power_efficiency_lab",
    [
        make_mcq("F3L3_D1", "Power is best described as...", ["energy stored per unit mass", "the rate of energy transfer", "the total useful energy only", "force multiplied by mass"], 1, "Power tells how quickly energy is transferred or work is done.", ["power_rate_confusion"]),
        make_short("F3L3_D2", "A machine transfers 600 J in 3 s. What is its power?", ["200 W"], "Use power = energy transferred / time.", ["power_rate_confusion"]),
    ],
    [
        make_mcq("F3L3_T1", "A device takes in 500 J and delivers 350 J as useful output. What is its efficiency?", ["35%", "50%", "70%", "85%"], 2, "Efficiency = useful output / total input x 100%.", ["efficiency_calculation_error"]),
        make_mcq("F3L3_T2", "Two motors transfer the same energy, but one does it in half the time. Compared with the slower motor, the faster motor has...", ["half the power", "the same power", "double the power", "double the efficiency automatically"], 2, "For the same energy, less time means greater power.", ["power_rate_confusion"]),
    ],
    [
        "Explain the difference between how much energy is transferred and how quickly it is transferred.",
        "Explain why a process can be powerful without being very efficient.",
    ],
    [
        prompt_block("Keep the energy transferred fixed and shorten the time.", "Less time for the same transfer means greater power."),
        prompt_block("Keep the input fixed and change the useful output.", "Efficiency compares the useful part with the total input."),
    ],
    "Power measures the rate of transfer, while efficiency measures how much of the input becomes the useful output instead of wasted energy.",
    [
        make_mcq("F3L3_C1", "If a lamp transfers the same energy in half the time, what happens to its power?", ["It halves", "It doubles", "It stays the same", "It becomes zero"], 1, "For the same energy, halving the time doubles the power.", ["power_rate_confusion"]),
    ],
)

add_lesson(
    "F3_L4",
    4,
    "Momentum and Conservation",
    "Momentum is like a signed movement budget: mass tells how much moving stuff there is, velocity tells how strongly and in which direction it is being carried.",
    "f3_momentum_lab",
    [
        make_mcq("F3L4_D1", "Momentum depends directly on...", ["mass and velocity", "mass and time", "force and height", "energy and temperature"], 0, "Momentum is found from mass multiplied by velocity.", ["momentum_vector_confusion"]),
        make_short("F3L4_D2", "A 2 kg trolley moves at 3 m/s east. What is its momentum?", ["6 kg m/s east", "6 kg m/s to the east"], "Use momentum = mass x velocity and keep the direction.", ["momentum_vector_confusion"]),
    ],
    [
        make_mcq("F3L4_T1", "A 2 kg trolley moving at 5 m/s hits a 3 kg trolley at rest and they stick together. What speed do they move at afterward?", ["1 m/s", "2 m/s", "2.5 m/s", "5 m/s"], 1, "Total momentum before = total momentum after for this isolated collision, so 10 = 5v.", ["momentum_conservation_confusion"]),
        make_mcq("F3L4_T2", "Which situation is best modelled by direct conservation of momentum?", ["two trolleys colliding on a low-friction track", "a falling ball with strong air resistance", "a rocket with engines firing", "a car accelerating because of its engine"], 0, "Use conservation most directly when external forces are negligible during the interaction.", ["momentum_conservation_confusion"]),
    ],
    [
        "Explain why momentum answers must keep direction or a sign convention.",
        "Explain what must be approximately true before you use conservation of momentum in a collision.",
    ],
    [
        prompt_block("Change the incoming mass while the second trolley starts at rest.", "A larger incoming mass gives a larger incoming momentum if the speed stays the same."),
        prompt_block("Keep the incoming trolley the same and increase the second trolley mass.", "The same total momentum shared by more mass gives a lower common speed after a sticking collision."),
    ],
    "Momentum combines mass with velocity, so conservation of momentum is a whole-system rule that works when external forces during the interaction are negligible.",
    [
        make_mcq("F3L4_C1", "Two equal trolleys move toward each other with equal speed. What is the total momentum of the system?", ["zero", "equal to one trolley's momentum", "double one trolley's momentum in the same direction", "impossible to tell"], 0, "Equal and opposite momenta cancel in the system total.", ["momentum_conservation_confusion"]),
    ],
)

add_lesson(
    "F3_L5",
    5,
    "Impulse and Force-Time Reasoning",
    "Catching an egg with hands that move backward is like stretching the stopping story: the same momentum change is spread over more time, so the force becomes smaller.",
    "f3_impulse_lab",
    [
        make_mcq("F3L5_D1", "Impulse is equal to...", ["force x time", "force / time", "momentum / time", "mass x acceleration only"], 0, "Impulse is the product of force and interaction time, and it equals the change in momentum.", ["impulse_force_time_confusion"]),
        make_short("F3L5_D2", "A force of 200 N acts for 0.3 s. What impulse is delivered?", ["60 N s", "60 Ns", "60 kg m/s"], "Use impulse = force x time.", ["impulse_force_time_confusion"]),
    ],
    [
        make_mcq("F3L5_T1", "If the same change in momentum happens over a longer time, the average force is...", ["larger", "smaller", "unchanged", "always zero"], 1, "For the same impulse, increasing the time reduces the average force.", ["collision_safety_reasoning_confusion", "impulse_force_time_confusion"]),
        make_mcq("F3L5_T2", "What does the area under a force-time graph represent?", ["momentum only", "impulse", "acceleration", "power"], 1, "Force-time area represents impulse, which equals the change in momentum.", ["impulse_force_time_confusion"]),
    ],
    [
        "Explain why airbags and padded surfaces reduce force during a collision.",
        "Explain how a force-time graph can tell you about momentum change.",
    ],
    [
        prompt_block("Keep the momentum change target fixed and increase the stopping time.", "The same impulse spread over more time means the average force becomes smaller."),
        prompt_block("Compare two force-time rectangles with the same area.", "Different force and time pairs can produce the same impulse if the area is the same."),
    ],
    "Impulse links force and time to the change in momentum, so collision safety often depends on increasing the stopping time rather than removing the momentum change itself.",
    [
        make_mcq("F3L5_C1", "If the interaction time doubles for the same impulse, what happens to the average force?", ["It doubles", "It halves", "It stays the same", "It becomes negative"], 1, "For a fixed impulse, force and time trade off inversely.", ["impulse_force_time_confusion"]),
    ],
)

add_lesson(
    "F3_L6",
    6,
    "Braking, Collisions, and Safety",
    "A crash is like closing a fast-moving account: momentum tells how much motion must be changed, while kinetic energy tells how much energy must be dissipated during the stop.",
    "f3_braking_safety_lab",
    [
        make_mcq("F3L6_D1", "If speed doubles for the same mass, which quantity definitely becomes four times larger?", ["momentum", "kinetic energy", "stopping time", "mass"], 1, "Kinetic energy depends on speed squared.", ["braking_energy_comparison_confusion"]),
        make_short("F3L6_D2", "A 1000 kg car moves at 12 m/s. What is its momentum?", ["12000 kg m/s", "12000 kg m/s forward", "12000 kg m/s east"], "Use momentum = mass x velocity.", ["momentum_vector_confusion"]),
    ],
    [
        make_mcq("F3L6_T1", "Why does a crumple zone reduce injury risk?", ["It removes all momentum instantly", "It increases stopping time and reduces average force", "It makes the car massless", "It increases the collision speed"], 1, "The same momentum change over a longer time means a smaller average force.", ["collision_safety_reasoning_confusion"]),
        make_mcq("F3L6_T2", "Why is high speed especially dangerous in braking?", ["Momentum and kinetic energy both fall when speed rises", "Momentum doubles and kinetic energy quadruples when speed doubles", "Only mass matters for braking", "Kinetic energy stays unchanged if mass stays the same"], 1, "Higher speed raises both momentum and kinetic energy, and kinetic energy rises especially quickly.", ["braking_energy_comparison_confusion"]),
    ],
    [
        "Explain one reason stopping distance grows with speed using energy or force ideas.",
        "Explain why good safety design often spreads the stop over more time and distance.",
    ],
    [
        prompt_block("Keep mass fixed and raise the speed.", "Momentum rises in direct proportion to speed, but kinetic energy rises much faster because speed is squared."),
        prompt_block("Keep the vehicle the same and lengthen the stopping time.", "A longer stop reduces the average force even though the total momentum change is the same."),
    ],
    "Braking and collision safety must be explained with both momentum change and energy dissipation, because high speed makes both the motion change and the energy removal more demanding.",
    [
        make_mcq("F3L6_C1", "A car and a truck move at the same speed. Which has the greater momentum?", ["the car", "the truck", "they have the same momentum", "you need the stopping time first"], 1, "At the same speed, the vehicle with the larger mass has the greater momentum.", ["momentum_vector_confusion"]),
    ],
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module F3 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    project = get_project_id(args.project)
    db = init_firebase(project)
    apply = bool(args.apply)

    plan: List[Tuple[str, str]] = [("modules", F3_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in F3_LESSONS] + [("sim_labs", doc_id) for doc_id, _ in F3_SIM_LABS]
    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    print_preview("Planned upserts", plan)

    upsert_doc(db, "modules", F3_MODULE_ID, F3_MODULE_DOC, apply)
    for doc_id, payload in F3_LESSONS:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in F3_SIM_LABS:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)

    print("DONE")


if __name__ == "__main__":
    main()
