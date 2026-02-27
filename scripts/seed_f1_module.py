import os
import argparse
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import firebase_admin
from firebase_admin import credentials
from google.cloud import firestore


# ----------------------------
# Helpers
# ----------------------------

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
    """
    Uses ADC (Application Default Credentials). On Cloud Run this is automatic.
    Locally, ensure `gcloud auth application-default login` has been done.
    """
    if not firebase_admin._apps:
        cred = credentials.ApplicationDefault()
        firebase_admin.initialize_app(cred, {"projectId": project_id})
    return firestore.Client(project=project_id)


def upsert_doc(db: firestore.Client, collection: str, doc_id: str, data: Dict[str, Any], apply: bool) -> None:
    ref = db.collection(collection).document(doc_id)
    if apply:
        ref.set(data, merge=True)
        print(f"✅ UPSERT {collection}/{doc_id}")
    else:
        print(f"[DRY] UPSERT {collection}/{doc_id}")


def print_preview(title: str, items: List[Tuple[str, str]]) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)
    for col, doc_id in items:
        print(f"- {col}/{doc_id}")
    print("=" * 80 + "\n")


# ----------------------------
# Seed Data (F1)
# ----------------------------

F1_MODULE_ID = "F1"

F1_ALLOWLIST = [
    "unit_conversion",
    "si_prefixes",
    "scalar_vs_vector",
    "reading_scales",
    "significant_figures",
    "rounding_rules",
    "precision_vs_accuracy",
    "random_vs_systematic_error",
    "uncertainty_estimation",
    "density_concept",
    "density_units",
]

F1_MODULE_DOC: Dict[str, Any] = {
    "module_id": F1_MODULE_ID,
    "title": "Physical Quantities & Measurement",
    "description": (
        "Foundations of measurement in physics: SI units and prefixes, scalars vs vectors, "
        "instrument reading, significant figures, density, and introductory uncertainty."
    ),
    "sequence": 1,
    "level": "Foundation",
    "estimated_minutes": 90,
    "mastery_outcomes": [
        "Use SI base units and common derived units appropriately.",
        "Convert quantities using SI prefixes and unit factors.",
        "Distinguish scalars and vectors in context.",
        "Read measurements from common instruments/scales.",
        "Apply significant figures and rounding rules in calculations.",
        "Compute density from mass and volume and report with units.",
        "Give a basic estimate of measurement uncertainty and discuss precision vs accuracy.",
    ],
    # This is what your backend now uses to filter misconception tags for F1
    "misconception_tag_allowlist": F1_ALLOWLIST,
    "updated_utc": utc_now(),
}

F1_SIM_LABS: List[Tuple[str, Dict[str, Any]]] = [
    (
        "f1_density_lab",
        {
            "lab_id": "f1_density_lab",
            "module_id": F1_MODULE_ID,
            "title": "Density Lab (Mass & Volume)",
            "description": "Estimate density using mass/volume measurements and report with correct units and sig figs.",
            "instructions": [
                "Choose an object with a given mass and volume (provided by the simulation).",
                "Compute density = mass / volume.",
                "Report density with units and appropriate significant figures.",
                "Reflect on how measurement uncertainty affects density."
            ],
            "expected_outcomes": [
                "density_concept",
                "density_units",
                "significant_figures",
                "uncertainty_estimation",
            ],
            "telemetry_schema_hint": {
                "fields": ["steps_completed", "retries", "time_on_task_seconds"],
                "sim_depth_meaning": "count of meaningful interactions (e.g., readings, recalculations, checks)"
            },
            "updated_utc": utc_now(),
        },
    ),
    (
        "f1_precision_lab",
        {
            "lab_id": "f1_precision_lab",
            "module_id": F1_MODULE_ID,
            "title": "Precision vs Accuracy Lab",
            "description": "Compare repeated measurements; distinguish precision and accuracy; discuss error types.",
            "instructions": [
                "Take multiple readings of the same quantity.",
                "Compute a simple spread (range) and discuss consistency.",
                "Compare to a known/accepted value to discuss accuracy.",
                "Label sources of random vs systematic error."
            ],
            "expected_outcomes": [
                "precision_vs_accuracy",
                "random_vs_systematic_error",
                "uncertainty_estimation",
                "reading_scales",
            ],
            "telemetry_schema_hint": {
                "fields": ["n_trials", "range", "time_on_task_seconds"],
                "sim_depth_meaning": "number of trials + analysis actions"
            },
            "updated_utc": utc_now(),
        },
    ),
]

# Lessons live in top-level collection "lessons" (your API uses db.collection("lessons").where("module_id" ...))
# We will assign stable IDs: F1_L1 ... F1_L6
F1_LESSONS: List[Tuple[str, Dict[str, Any]]] = []

def make_mcq(qid: str, prompt: str, choices: List[str], correct_index: int, tags: List[str]) -> Dict[str, Any]:
    # tags must be allowlisted for module F1
    safe_tags = [t for t in tags if t in F1_ALLOWLIST]
    return {
        "question_id": qid,
        "type": "mcq",
        "prompt": prompt,
        "choices": choices,
        "correct_index": correct_index,
        "misconception_tags": safe_tags,
    }

def make_short(qid: str, prompt: str, tags: List[str]) -> Dict[str, Any]:
    safe_tags = [t for t in tags if t in F1_ALLOWLIST]
    return {
        "question_id": qid,
        "type": "short",
        "prompt": prompt,
        "misconception_tags": safe_tags,
    }

def add_lesson(doc_id: str, sequence: int, title: str, analogy: str, sim_lab_id: str | None,
               diagnostic_items: List[Dict[str, Any]], transfer_items: List[Dict[str, Any]],
               reconstruction_prompts: List[str]) -> None:
    F1_LESSONS.append(
        (
            doc_id,
            {
                "lesson_id": doc_id,
                "module_id": F1_MODULE_ID,
                "sequence": sequence,
                "title": title,
                "updated_utc": utc_now(),
                # The UI can render this directly to implement the 5-phase loop
                "phases": {
                    "diagnostic": {
                        "two_tier": True,
                        "items": diagnostic_items,
                        "notes": "Two-tier: answer + confidence. Use misconception tags for feedback routing."
                    },
                    "analogical_grounding": {
                        "analogy_text": analogy,
                        "commitment_prompt": "Before moving on, write 1 sentence predicting what will happen and why."
                    },
                    "simulation_inquiry": {
                        "lab_id": sim_lab_id,
                        "inquiry_prompts": [
                            "Record at least 2 measurements.",
                            "Check your units before calculating anything.",
                            "Explain whether your measurement is precise, accurate, or both."
                        ] if sim_lab_id else [],
                    },
                    "concept_reconstruction": {
                        "prompts": reconstruction_prompts
                    },
                    "transfer": {
                        "items": transfer_items,
                        "notes": "Transfer is scored; log event_type=transfer with score and tags."
                    },
                },
            },
        )
    )


# Lesson 1 — SI units & prefixes
add_lesson(
    doc_id="F1_L1",
    sequence=1,
    title="SI Units & Prefixes (The 'Currency' of Physics)",
    analogy=(
        "Think of units like currency: you can’t meaningfully add 'dollars' to 'meters'—"
        "and you can’t pay with 'kilo-' without converting. Prefixes are like denominations "
        "(cents, dollars, thousands). Good physics starts by keeping the 'currency' consistent."
    ),
    sim_lab_id=None,
    diagnostic_items=[
        make_mcq(
            "F1L1_D1",
            "Which is the correct SI unit for mass?",
            ["meter (m)", "kilogram (kg)", "second (s)", "newton (N)"],
            1,
            ["unit_conversion"]
        ),
        make_mcq(
            "F1L1_D2",
            "1 millimeter (mm) equals:",
            ["10^-3 m", "10^-2 m", "10^3 m", "10^-6 m"],
            0,
            ["si_prefixes", "unit_conversion"]
        ),
        make_short(
            "F1L1_D3",
            "Convert 2.5 km to meters.",
            ["unit_conversion", "si_prefixes"]
        ),
    ],
    transfer_items=[
        make_mcq(
            "F1L1_T1",
            "Which conversion is correct?",
            ["3.0 m = 300 cm", "3.0 m = 30 cm", "3.0 m = 3 cm", "3.0 m = 3000 cm"],
            0,
            ["unit_conversion"]
        ),
        make_short(
            "F1L1_T2",
            "Convert 4500 g to kg.",
            ["unit_conversion", "si_prefixes"]
        ),
    ],
    reconstruction_prompts=[
        "Explain why unit consistency matters before doing calculations.",
        "Write a rule-of-thumb for converting using prefixes (kilo-, milli-, micro-).",
    ],
)

# Lesson 2 — Scalars vs vectors
add_lesson(
    doc_id="F1_L2",
    sequence=2,
    title="Scalars vs Vectors",
    analogy=(
        "A scalar is like a 'thermometer reading'—only a size. A vector is like a 'walking instruction'—"
        "size plus direction. Confusing them is like saying 'walk 5' without telling where."
    ),
    sim_lab_id=None,
    diagnostic_items=[
        make_mcq(
            "F1L2_D1",
            "Which quantity is a vector?",
            ["temperature", "mass", "displacement", "time"],
            2,
            ["scalar_vs_vector"]
        ),
        make_mcq(
            "F1L2_D2",
            "Speed is a scalar because it has:",
            ["magnitude only", "direction only", "no units", "negative values only"],
            0,
            ["scalar_vs_vector"]
        ),
    ],
    transfer_items=[
        make_short(
            "F1L2_T1",
            "Give one example each of a scalar and a vector from everyday life.",
            ["scalar_vs_vector"]
        )
    ],
    reconstruction_prompts=[
        "In your own words, define scalar and vector.",
        "Explain why 'velocity' is different from 'speed'.",
    ],
)

# Lesson 3 — Reading instruments/scales
add_lesson(
    doc_id="F1_L3",
    sequence=3,
    title="Reading Scales & Instruments",
    analogy=(
        "Reading a scale is like reading a map grid: your precision is limited by the smallest division. "
        "If the ruler has millimeter marks, pretending you know micrometers is 'inventing' information."
    ),
    sim_lab_id="f1_precision_lab",
    diagnostic_items=[
        make_mcq(
            "F1L3_D1",
            "A ruler's smallest division is 1 mm. A reasonable reported uncertainty is closest to:",
            ["±1 mm", "±0.5 mm", "±0.1 mm", "±2 mm"],
            1,
            ["reading_scales", "uncertainty_estimation"]
        ),
        make_mcq(
            "F1L3_D2",
            "If you consistently read too high due to a zero error, this is best described as:",
            ["random error", "systematic error", "no error", "rounding error only"],
            1,
            ["random_vs_systematic_error"]
        ),
    ],
    transfer_items=[
        make_short(
            "F1L3_T1",
            "State one difference between random error and systematic error.",
            ["random_vs_systematic_error"]
        ),
        make_short(
            "F1L3_T2",
            "A scale has 0.2 cm divisions. What is a reasonable uncertainty to report?",
            ["reading_scales", "uncertainty_estimation"]
        ),
    ],
    reconstruction_prompts=[
        "Explain what limits the precision of a measurement on an instrument.",
        "Describe how you would detect a systematic error in an instrument.",
    ],
)

# Lesson 4 — Significant figures & rounding
add_lesson(
    doc_id="F1_L4",
    sequence=4,
    title="Significant Figures & Rounding Rules",
    analogy=(
        "Significant figures are 'honesty rules' for numbers. If your measurement is rough, your final answer "
        "must be rough too. Reporting extra digits is like adding fake detail to a blurry photo."
    ),
    sim_lab_id=None,
    diagnostic_items=[
        make_mcq(
            "F1L4_D1",
            "How many significant figures are in 0.00450?",
            ["2", "3", "4", "5"],
            1,
            ["significant_figures"]
        ),
        make_mcq(
            "F1L4_D2",
            "Round 12.349 to 3 significant figures:",
            ["12.3", "12.4", "12.35", "12.34"],
            1,
            ["rounding_rules", "significant_figures"]
        ),
    ],
    transfer_items=[
        make_short(
            "F1L4_T1",
            "Calculate (2.5)(3.42) and report the result with correct significant figures.",
            ["significant_figures"]
        ),
        make_short(
            "F1L4_T2",
            "Explain why we do not keep too many digits in a final physics answer.",
            ["significant_figures", "precision_vs_accuracy"]
        ),
    ],
    reconstruction_prompts=[
        "Write the rule for sig figs in multiplication/division.",
        "Write the rule for sig figs in addition/subtraction.",
    ],
)

# Lesson 5 — Density (concept + units)
add_lesson(
    doc_id="F1_L5",
    sequence=5,
    title="Density: Mass, Volume, and Units",
    analogy=(
        "Density is 'how tightly packed' matter is—like how crowded a room is: people per square meter. "
        "In physics it's mass per volume, and units matter (kg/m^3 vs g/cm^3)."
    ),
    sim_lab_id="f1_density_lab",
    diagnostic_items=[
        make_mcq(
            "F1L5_D1",
            "Density is defined as:",
            ["mass × volume", "mass ÷ volume", "volume ÷ mass", "mass + volume"],
            1,
            ["density_concept"]
        ),
        make_mcq(
            "F1L5_D2",
            "Which unit is appropriate for density?",
            ["kg", "m^3", "kg/m^3", "N"],
            2,
            ["density_units"]
        ),
    ],
    transfer_items=[
        make_short(
            "F1L5_T1",
            "A block has mass 200 g and volume 50 cm^3. Calculate density in g/cm^3.",
            ["density_concept", "density_units", "significant_figures"]
        ),
        make_short(
            "F1L5_T2",
            "Convert 4.0 g/cm^3 to kg/m^3 (show the conversion idea).",
            ["unit_conversion", "density_units"]
        ),
    ],
    reconstruction_prompts=[
        "Explain density using your own everyday example.",
        "Explain why using the wrong density units can cause huge errors.",
    ],
)

# Lesson 6 — Uncertainty + precision vs accuracy (wrap-up)
add_lesson(
    doc_id="F1_L6",
    sequence=6,
    title="Uncertainty, Precision, and Accuracy (Wrap-up)",
    analogy=(
        "Precision is how tightly your shots group; accuracy is whether the group hits the bullseye. "
        "Uncertainty is your honest estimate of how 'wide' the group could be given your instrument and method."
    ),
    sim_lab_id="f1_precision_lab",
    diagnostic_items=[
        make_mcq(
            "F1L6_D1",
            "A set of measurements are very close to each other but far from the true value. This is:",
            ["accurate but not precise", "precise but not accurate", "both accurate and precise", "neither"],
            1,
            ["precision_vs_accuracy"]
        ),
        make_short(
            "F1L6_D2",
            "Give one source of systematic error and one source of random error in a measurement.",
            ["random_vs_systematic_error"]
        ),
    ],
    transfer_items=[
        make_short(
            "F1L6_T1",
            "You measure length as 12.4 cm with a ruler of 1 mm divisions. Report the value with a reasonable uncertainty.",
            ["uncertainty_estimation", "reading_scales"]
        ),
        make_short(
            "F1L6_T2",
            "In 2–3 sentences, explain the difference between precision and accuracy using an example.",
            ["precision_vs_accuracy"]
        ),
    ],
    reconstruction_prompts=[
        "Explain why uncertainty is part of every measurement.",
        "Describe how you would improve precision in an experiment without necessarily improving accuracy.",
    ],
)


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module F1 (Physical Quantities & Measurement) into Firestore")
    parser.add_argument("--project", default=None, help="GCP/Firebase project id (defaults from env)")
    parser.add_argument("--apply", action="store_true", help="Actually write to Firestore (default is dry-run)")
    args = parser.parse_args()

    project_id = get_project_id(args.project)
    db = init_firebase(project_id)

    apply = bool(args.apply)

    to_upsert: List[Tuple[str, str]] = []
    to_upsert.append(("modules", F1_MODULE_ID))
    for doc_id, _ in F1_LESSONS:
        to_upsert.append(("lessons", doc_id))
    for lab_id, _ in F1_SIM_LABS:
        to_upsert.append(("sim_labs", lab_id))

    print(f"Project: {project_id}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY-RUN (no writes)'}")
    print_preview("Planned upserts", to_upsert)

    # 1) Module
    upsert_doc(db, "modules", F1_MODULE_ID, F1_MODULE_DOC, apply)

    # 2) Lessons
    for doc_id, data in F1_LESSONS:
        upsert_doc(db, "lessons", doc_id, data, apply)

    # 3) Sim labs
    for lab_id, data in F1_SIM_LABS:
        upsert_doc(db, "sim_labs", lab_id, data, apply)

    print("\nDONE")
    print(f"- Module: modules/{F1_MODULE_ID}")
    print(f"- Lessons: {len(F1_LESSONS)} docs in lessons collection")
    print(f"- Sim labs: {len(F1_SIM_LABS)} docs in sim_labs collection")
    if not apply:
        print("\nTip: re-run with --apply to write to Firestore.")


if __name__ == "__main__":
    main()