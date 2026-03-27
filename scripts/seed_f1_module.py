from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Tuple

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


F1_MODULE_ID = "F1"
F1_CONTENT_VERSION = "20260323_f1_measure_map_curriculum_v4"
F1_ALLOWLIST = [
    "unit_label_confusion",
    "prefix_scale_error",
    "unit_selection_confusion",
    "scalar_vector_confusion",
    "directional_description_confusion",
    "instrument_choice_confusion",
    "scale_reading_confusion",
    "resolution_uncertainty_confusion",
    "significant_figure_count_error",
    "reporting_rule_confusion",
    "density_relationship_error",
    "density_unit_confusion",
    "accuracy_precision_confusion",
    "random_systematic_error_confusion",
    "uncertainty_estimation_error",
]


def mcq(
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


def short(qid: str, prompt: str, accepted_answers: List[str], hint: str, tags: List[str]) -> Dict[str, Any]:
    return {
        "kind": "short",
        "id": qid,
        "prompt": prompt,
        "accepted_answers": accepted_answers,
        "hint": hint,
        "tags": tags,
    }


def prompt_block(prompt: str, hint: str) -> Dict[str, str]:
    return {"prompt": prompt, "hint": hint}


def formula(equation: str, meaning: str, units: List[str], conditions: str) -> Dict[str, Any]:
    return {
        "equation": equation,
        "meaning": meaning,
        "units": units,
        "conditions": conditions,
    }


def rep(kind: str, purpose: str) -> Dict[str, str]:
    return {"kind": kind, "purpose": purpose}


def example(prompt: str, steps: List[str], final_answer: str, why_it_matters: str) -> Dict[str, Any]:
    return {
        "prompt": prompt,
        "steps": steps,
        "final_answer": final_answer,
        "why_it_matters": why_it_matters,
    }


def vis(asset_id: str, concept: str, title: str, purpose: str, caption: str) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
    }


def anim(asset_id: str, concept: str, title: str, description: str, duration_sec: int = 8) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "description": description,
        "duration_sec": duration_sec,
    }


def assessment_targets(diagnostic_pool_min: int, concept_gate_pool_min: int, mastery_pool_min: int) -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": diagnostic_pool_min,
        "concept_gate_pool_min": concept_gate_pool_min,
        "mastery_pool_min": mastery_pool_min,
        "fresh_attempt_policy": (
            "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery attempts before recycling any prior stems."
        ),
    }


F1_SPEC: Dict[str, Any] = {
    "module_description": (
        "Physics begins when the world is tagged with units, checked with tools, and turned into maps that show pattern instead of guesswork. "
        "Foundation 1 covers SI units and conversion, base and derived quantities, scalar and vector first ideas, measuring length, mass, time, and temperature, "
        "precision, accuracy, simple uncertainty, density, and reading, plotting, and interpreting simple graphs."
    ),
    "mastery_outcomes": [
        "Use SI units and prefixes fluently while keeping complete measurements tied to the correct unit tag.",
        "Recognize base and simple derived quantities and separate scalar descriptions from direction-tagged vector descriptions.",
        "Choose suitable measuring instruments for length, mass, time, and temperature, then read scales honestly.",
        "Distinguish precision, accuracy, and simple uncertainty while recognizing why repeated readings and confidence language matter.",
        "Calculate density, interpret it as how much matter is packed into a chosen volume, and connect it to floating or sinking.",
        "Read, plot, and interpret simple graphs as map-plots of pattern rather than as pictures of the apparatus.",
    ],
    "lessons": [],
}


F1_SPEC["lessons"].append(
    {
        "id": "F1_L1",
        "title": "SI Units, Prefixes, and Complete Measurements",
        "sim": {
            "lab_id": "f1_metric_prefix_lab",
            "title": "Unit and prefix explorer",
            "description": "Compare one physical length as the unit size changes from kilometres down to millimetres.",
            "instructions": [
                "Keep the same length and swap the unit from km to m to cm to mm.",
                "Choose a classroom object and decide which unit keeps the number readable.",
                "Explain why the number changes even though the physical length does not.",
            ],
            "outcomes": ["unit_label_confusion", "prefix_scale_error", "unit_selection_confusion"],
            "fields": ["base_length_m", "from_unit", "to_unit", "reported_value", "unit_choice_reasoning"],
            "depth": "number of scale swaps explained correctly as unit-size changes instead of length changes",
        },
        "analogy_text": (
            "Treat measurement like a shared currency system: the physical quantity is the purchase, while units are the denominations. "
            "A quantity written in kilometres, metres, or millimetres is still the same purchase, but the number changes because the denomination changes."
        ),
        "commitment_prompt": "Before converting, decide whether the unit got larger or smaller and predict whether the number should shrink or grow.",
        "micro_prompts": [
            prompt_block(
                "Compare writing the same road length in kilometres and in metres.",
                "A smaller unit needs more copies, so the number grows while the distance stays the same.",
            ),
            prompt_block(
                "Compare the phrases '4', '4 cm', and '4 s'.",
                "Only the versions with units tell you what the number is measuring.",
            ),
        ],
        "diagnostic": [
            mcq("F1L1_D1", "Which is the correct SI unit for mass?", ["m", "kg", "s", "N"], 1, "Mass is measured in kilograms in the SI system.", ["unit_selection_confusion"]),
            mcq("F1L1_D2", "Which statement is a complete measurement?", ["18", "18 cm", "length", "centimetres"], 1, "A complete measurement needs a number and a unit.", ["unit_label_confusion"]),
            mcq("F1L1_D3", "Which prefix means one-thousandth of the base unit?", ["kilo-", "centi-", "milli-", "mega-"], 2, "One-thousandth corresponds to milli-.", ["prefix_scale_error"]),
            mcq("F1L1_D4", "Which unit is most suitable for the thickness of a coin?", ["km", "m", "cm", "mm"], 3, "A very small thickness is best reported in millimetres.", ["unit_selection_confusion"]),
            short("F1L1_D5", "Convert 0.45 kg to g.", ["450 g", "450"], "Use 1 kg = 1000 g.", ["prefix_scale_error"]),
            short("F1L1_D6", "Convert 2.8 km to m.", ["2800 m", "2800"], "Use 1 km = 1000 m.", ["prefix_scale_error"]),
        ],
        "inquiry": [
            prompt_block("Keep the physical length fixed and swap only the unit size.", "The number should change because the unit size changed."),
            prompt_block("Compare an ant, a notebook, and a road trip.", "Match the unit to the scale before reporting the number."),
        ],
        "recon_prompts": [
            "Explain why the same number can mean completely different things once the unit changes.",
            "Explain why smaller units usually create bigger numbers for the same physical quantity.",
        ],
        "capsule_prompt": "A scientific measurement must keep the quantity, the number, and the unit tied together.",
        "capsule_checks": [
            mcq("F1L1_C1", "If the unit changes from metres to centimetres for the same length, the number usually becomes...", ["smaller", "larger", "zero", "negative"], 1, "A smaller unit needs more copies of itself.", ["prefix_scale_error"]),
            mcq("F1L1_C2", "Why is '5' less useful than '5 cm'?", ["The bare number is always wrong", "The unit tells what quantity and scale the number belongs to", "The unit makes the value exact", "The unit removes uncertainty"], 1, "Units tell the reader what the number means.", ["unit_label_confusion"]),
            short("F1L1_C3", "Convert 3.5 m to cm.", ["350 cm", "350"], "Use 1 m = 100 cm.", ["prefix_scale_error"]),
            mcq("F1L1_C4", "Which unit is most suitable for the distance between two cities?", ["mm", "cm", "m", "km"], 3, "Large travel distances are usually reported in kilometres.", ["unit_selection_confusion"]),
            mcq("F1L1_C5", "Why must units match before you compare two measurements directly?", ["Because matching units stop the formula from changing", "Because otherwise the numbers may describe different-sized unit chunks", "Because all SI numbers must be equal", "Because units decide direction"], 1, "You can only compare like-sized units directly.", ["unit_label_confusion", "prefix_scale_error"]),
        ],
        "transfer": [
            short("F1L1_T1", "Convert 3.2 km to m.", ["3200 m", "3200"], "Multiply by 1000 when moving from km to m.", ["prefix_scale_error"]),
            short("F1L1_T2", "Convert 0.035 m to mm.", ["35 mm", "35"], "Use 1 m = 1000 mm.", ["prefix_scale_error"]),
            short("F1L1_T3", "Convert 2500 mg to g.", ["2.5 g", "2.5"], "Use 1000 mg = 1 g.", ["prefix_scale_error"]),
            mcq("F1L1_T4", "A learner writes '14' for the mass of a book. What is missing?", ["A graph", "A unit", "A direction", "A decimal point"], 1, "A bare number is incomplete in science.", ["unit_label_confusion"]),
            mcq("F1L1_T5", "Which unit is most suitable for the width of a notebook?", ["km", "m", "cm", "mg"], 2, "Notebook width is usually easiest to describe in centimetres.", ["unit_selection_confusion"]),
            short("F1L1_T6", "Convert 400 cm to m.", ["4 m", "4"], "Use 100 cm = 1 m.", ["prefix_scale_error"]),
            mcq("F1L1_T7", "Which pair describes the same length?", ["0.8 m and 8 cm", "0.8 m and 80 cm", "0.8 m and 800 cm", "0.8 m and 0.08 cm"], 1, "1 m = 100 cm, so 0.8 m = 80 cm.", ["prefix_scale_error"]),
            mcq("F1L1_T8", "Why do scientists prefer SI units?", ["They make numbers shorter", "They provide a shared standard for communication and calculation", "They remove all mistakes", "They work only for length"], 1, "SI units are shared standards.", ["unit_label_confusion", "unit_selection_confusion"]),
        ],
        "contract": {
            "concept_targets": [
                "Keep number and unit together as one measurement statement.",
                "Use prefixes as scale changes rather than as different quantities.",
            ],
            "prerequisite_lessons": [],
            "misconception_focus": ["unit_label_confusion", "prefix_scale_error", "unit_selection_confusion"],
            "formulas": [
                formula("1 km = 1000 m", "A larger prefixed unit contains many base units.", ["km", "m"], "Use when replacing kilometres with metres."),
                formula("1 m = 100 cm = 1000 mm", "One base unit can be rewritten using smaller unit chunks.", ["m", "cm", "mm"], "Use when converting to smaller length units."),
            ],
            "representations": [
                rep("words", "Explain why the number changes while the physical quantity stays the same."),
                rep("table", "Organise common units, prefixes, and example conversions."),
                rep("formula", "Show exact equivalences such as 1 km = 1000 m."),
            ],
            "analogy_map": {
                "comparison": "Measurement as shared currency compares units with denominations.",
                "mapping": ["The physical quantity is the purchase being described.", "The unit is the denomination used to count that purchase."],
                "limit": "Units are not money; the analogy only helps you track scale and shared standards.",
                "prediction_prompt": "If you change from a large denomination to a smaller one for the same purchase, what should happen to the number written beside it?",
            },
            "worked_examples": [
                example("Convert 2.5 km to m.", ["Notice that kilometres are larger units than metres.", "Replace each kilometre with 1000 m.", "Multiply 2.5 by 1000."], "2500 m", "This keeps the physical distance the same while changing the counting unit."),
                example("A learner writes '7' for the time of a race. Evaluate the report.", ["Ask what quantity the number is supposed to describe.", "Notice that the unit is missing.", "Rewrite the report with a number and a unit, such as 7 s."], "The report is incomplete.", "This blocks the habit of treating bare numbers as finished scientific measurements."),
            ],
            "visual_assets": [
                vis("f1-l1-prefix-scale", "prefix_scale", "Prefix ladder", "Show how the same base unit is renamed with larger and smaller prefixes.", "The same quantity can be written with different unit sizes."),
            ],
            "animation_assets": [
                anim("f1-l1-unit-conversion-anim", "unit_conversion", "Conversion in motion", "Animate one length being rewritten from kilometres to metres to centimetres."),
            ],
            "simulation_contract": {
                "asset_id": "f1_l1_metric_prefix_lab",
                "concept": "prefix_scale",
                "baseline_case": "Start with 2.5 m and rewrite it as cm and mm.",
                "comparison_tasks": ["Swap between a larger unit and a smaller unit for the same distance.", "Choose a sensible unit for a tiny object and for a long journey."],
                "watch_for": "Students should say that the unit size changed, not the physical quantity.",
                "takeaway": "Smaller units give larger numbers for the same physical quantity, and complete measurements always keep the unit attached.",
            },
            "reflection_prompts": ["Explain why 5, 5 m, and 5 s do not mean the same thing even though the number is the same."],
            "mastery_skills": ["Choose suitable SI units.", "Convert between common metric units.", "Explain prefix scale changes.", "Spot incomplete measurements.", "Keep unit meaning attached to numeric values."],
            "variation_plan": {
                "diagnostic": "Rotate unit-choice, completeness, and conversion items across length, mass, and time.",
                "concept_gate": "Swap between prefix direction reasoning and complete-measurement explanation.",
                "mastery": "Mix conversions, unit choice, and explanation prompts so fresh attempts reuse ideas without reusing stems.",
            },
            "assessment_bank_targets": assessment_targets(6, 5, 8),
            "visual_clarity_checks": [
                "Every visual keeps the unit symbol next to the quantity label.",
                "Explorer comparisons show the same physical quantity before and after the unit swap.",
                "Captions explicitly say whether the unit became larger or smaller.",
            ],
        },
    }
)


RELEASE_CHECKS = [
    "Every F1 lesson includes lesson-owned diagnostic, concept-gate, and mastery banks large enough to support fresh-attempt rotation.",
    "Every Try It in Action explorer is backed by a lesson-specific simulation contract instead of generic fallback copy.",
    "Every lesson balances conceptual explanation with qualitative or quantitative calculation practice where appropriate.",
    "Every visual and animation clarifies the core comparison the lesson depends on for understanding.",
]


def _finalize_bundle() -> Tuple[Dict[str, Any], List[Tuple[str, Dict[str, Any]]], List[Tuple[str, Dict[str, Any]]]]:
    F1_SPEC["lessons"] = sorted(
        F1_SPEC["lessons"],
        key=lambda lesson: int(str(lesson["id"]).split("_L")[-1]),
    )
    return build_nextgen_module_bundle(
        module_id=F1_MODULE_ID,
        module_title="Scientific Measurement and Representation",
        module_spec=F1_SPEC,
        allowlist=F1_ALLOWLIST,
        content_version=F1_CONTENT_VERSION,
        release_checks=RELEASE_CHECKS,
        sequence=1,
        level="Foundation 1",
        estimated_minutes=210,
        plan_assets=True,
        public_base="/lesson_assets",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module F1 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    apply = bool(args.apply)
    db = init_firebase(project) if apply else None

    module_doc = deepcopy(F1_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in F1_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in F1_SIM_LABS]

    asset_root = args.asset_root or str(default_asset_root())
    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    plan: List[Tuple[str, str]] = [("modules", F1_MODULE_ID)] + [("lessons", doc_id) for doc_id, _ in lesson_pairs] + [("sim_labs", doc_id) for doc_id, _ in sim_pairs]
    print(f"Project: {project}")
    print(f"Mode: {'APPLY (writes enabled)' if apply else 'DRY RUN (no writes)'}")
    if args.compile_assets:
        print(f"Asset root: {asset_root}")
        print(f"Public base: {args.public_base}")
    print_preview("Planned upserts", plan)

    upsert_doc(db, "modules", F1_MODULE_ID, module_doc, apply)
    for doc_id, payload in lesson_pairs:
        upsert_doc(db, "lessons", doc_id, payload, apply)
    for doc_id, payload in sim_pairs:
        upsert_doc(db, "sim_labs", doc_id, payload, apply)
    print("DONE")
F1_SPEC["lessons"].append(
    {
        "id": "F1_L6",
        "title": "Accuracy, Precision, Error, and Uncertainty",
        "sim": {
            "lab_id": "f1_accuracy_precision_lab",
            "title": "Accuracy and precision explorer",
            "description": "Compare grouped readings, biased readings, and uncertainty estimates from repeated measurements.",
            "instructions": [
                "Move the cluster center to model bias and move the spread to model scatter.",
                "Compare a tight cluster away from the true value with a loose cluster around it.",
                "Estimate uncertainty from repeated readings and explain whether the main issue is accuracy or precision.",
            ],
            "outcomes": ["accuracy_precision_confusion", "random_systematic_error_confusion", "uncertainty_estimation_error"],
            "fields": ["cluster_center", "cluster_spread", "true_value", "mean_reading", "estimated_uncertainty"],
            "depth": "number of reading sets correctly classified as accurate, precise, both, or neither with a justified uncertainty estimate",
        },
        "analogy_text": (
            "Measurement quality is like archery practice at a target. "
            "Accuracy asks whether the arrows land near the bullseye, while precision asks whether the arrows land close to one another."
        ),
        "commitment_prompt": "Before describing a reading set, decide separately how close it is to the true value and how tightly grouped it is.",
        "micro_prompts": [
            prompt_block("Compare a tight cluster far from the bullseye with a loose cluster around it.", "One can be precise without being accurate, and the other can be fairly accurate without being very precise."),
            prompt_block("Compare repeated readings with random scatter against repeated readings with a constant offset.", "Scatter suggests random error, while a one-direction offset suggests systematic bias."),
        ],
        "diagnostic": [
            mcq("F1L6_D1", "A set of readings are very close to one another but far from the accepted value. This set is...", ["accurate and precise", "precise but not accurate", "accurate but not precise", "neither"], 1, "Tight grouping shows precision, while distance from the true value shows poor accuracy.", ["accuracy_precision_confusion"]),
            mcq("F1L6_D2", "Which situation best suggests systematic error?", ["Readings scatter above and below the true value", "Every reading is shifted high by the same amount", "The unit is written clearly", "The scale has fine divisions"], 1, "A repeated same-direction shift suggests systematic bias.", ["random_systematic_error_confusion"]),
            mcq("F1L6_D3", "Which situation best suggests random error?", ["A zero error affects every reading equally", "Readings vary unpredictably from trial to trial", "The tool is correctly calibrated", "The unit changes"], 1, "Scatter from one reading to the next suggests random error.", ["random_systematic_error_confusion"]),
            short("F1L6_D4", "Three readings are 9.8 cm, 10.0 cm, and 10.2 cm. What is the mean?", ["10.0 cm", "10.0"], "Add the readings and divide by 3.", ["accuracy_precision_confusion"]),
            short("F1L6_D5", "For the readings 9.8 cm, 10.0 cm, and 10.2 cm, estimate the uncertainty from half the range.", ["0.2 cm", "+/- 0.2 cm"], "The range is 0.4 cm, so half the range is 0.2 cm.", ["uncertainty_estimation_error"]),
            mcq("F1L6_D6", "Why is reporting an uncertainty useful?", ["It replaces the measurement", "It shows the likely spread or limit of trust in the reported value", "It proves the result is exact", "It removes random error"], 1, "Uncertainty tells the reader how much trust the measurement deserves.", ["uncertainty_estimation_error"]),
        ],
        "inquiry": [
            prompt_block("Keep the spread tight and move the cluster away from the true value.", "Precision can stay strong even while accuracy gets worse."),
            prompt_block("Keep the cluster centered and widen the spread.", "Accuracy can look reasonable on average even when precision becomes poor."),
        ],
        "recon_prompts": [
            "Explain why accuracy and precision should not be treated as synonyms.",
            "Explain how repeated readings can help you estimate uncertainty even when they do not remove all error.",
        ],
        "capsule_prompt": "A trustworthy measurement description keeps accuracy, precision, error type, and uncertainty as separate ideas.",
        "capsule_checks": [
            mcq("F1L6_C1", "What does precision mainly describe?", ["Closeness to the accepted value", "Closeness of repeated readings to one another", "The size of the unit only", "Whether the value is an integer"], 1, "Precision is about grouping, not about the bullseye itself.", ["accuracy_precision_confusion"]),
            mcq("F1L6_C2", "What does accuracy mainly describe?", ["Closeness to the accepted or true value", "Closeness of repeated readings to one another only", "The number of decimal places", "Whether a tool is expensive"], 0, "Accuracy is about closeness to the target value.", ["accuracy_precision_confusion"]),
            short("F1L6_C3", "The readings 4.9 s, 5.1 s, and 5.0 s are taken. What is the mean?", ["5.0 s", "5.0"], "Add the readings and divide by 3.", ["accuracy_precision_confusion"]),
            mcq("F1L6_C4", "Why can a zero error make results inaccurate even when they are very precise?", ["Because precision and accuracy are the same", "Because a repeated bias can keep the readings tightly grouped away from the true value", "Because uncertainty disappears", "Because units control the error"], 1, "Bias can shift the whole cluster.", ["accuracy_precision_confusion", "random_systematic_error_confusion"]),
            mcq("F1L6_C5", "Why estimate uncertainty from repeated measurements?", ["To hide disagreement", "To describe the spread of plausible values shown by the repeated data", "To force the answer to be exact", "To replace the mean value"], 1, "The spread helps show the trust range of the measurement.", ["uncertainty_estimation_error"]),
        ],
        "transfer": [
            mcq("F1L6_T1", "Which set is most likely accurate but not very precise?", ["Readings tightly grouped around a wrong value", "Readings spread around the true value", "Readings tightly grouped around the true value", "Readings all identical and wrong"], 1, "The average is near the true value, but the scatter is large.", ["accuracy_precision_confusion"]),
            mcq("F1L6_T2", "Which set is most likely precise but inaccurate?", ["A tight cluster far from the true value", "A wide cluster around the true value", "A wide cluster far from the true value", "A single reading only"], 0, "Tight grouping with bias gives precision without accuracy.", ["accuracy_precision_confusion"]),
            short("F1L6_T3", "The readings are 19.8 g, 20.0 g, and 20.2 g. What is the mean?", ["20.0 g", "20.0"], "Add and divide by 3.", ["accuracy_precision_confusion"]),
            short("F1L6_T4", "For 19.8 g, 20.0 g, and 20.2 g, estimate the uncertainty from half the range.", ["0.2 g", "+/- 0.2 g"], "The range is 0.4 g, so half the range is 0.2 g.", ["uncertainty_estimation_error"]),
            mcq("F1L6_T5", "A thermometer always reads 0.5 C too low. Which correction best addresses the issue?", ["Take more repeated readings only", "Recognize and correct the systematic offset", "Change the unit to kelvin", "Ignore the bias because the readings agree"], 1, "The repeated same-direction error is the problem to address.", ["random_systematic_error_confusion"]),
            mcq("F1L6_T6", "Why should uncertainty be reported with the measured value?", ["Because the value is meaningless without a decoration", "Because the uncertainty tells how much trust the reader should place in the value", "Because uncertainty is always larger than the value", "Because it replaces units"], 1, "The value and its trust range belong together.", ["uncertainty_estimation_error"]),
            mcq("F1L6_T7", "A class repeats a measurement many times and the readings scatter above and below the mean. Which issue is most visible?", ["systematic offset only", "random error", "unit conversion", "significant figures only"], 1, "Scatter around the mean signals random error.", ["random_systematic_error_confusion"]),
            mcq("F1L6_T8", "What makes the best description of a data set?", ["Only the mean value", "The mean together with a comment on accuracy, precision, and uncertainty", "Only the highest reading", "Only the smallest division"], 1, "Good reporting keeps the trust story beside the value.", ["accuracy_precision_confusion", "uncertainty_estimation_error"]),
        ],
        "contract": {
            "concept_targets": [
                "Separate accuracy, precision, random error, and systematic error clearly.",
                "Estimate a simple uncertainty from repeated readings and report it honestly.",
            ],
            "prerequisite_lessons": ["F1_L3", "F1_L4"],
            "misconception_focus": ["accuracy_precision_confusion", "random_systematic_error_confusion", "uncertainty_estimation_error"],
            "formulas": [
                formula("mean reading = total of readings / number of readings", "The mean gives one representative value for repeated measurements.", ["same unit as the readings"], "Use when repeated readings are taken for the same quantity."),
                formula("estimated uncertainty from repeats ≈ (highest reading - lowest reading) / 2", "Half the range gives a simple estimate of the spread shown by repeated readings.", ["same unit as the readings"], "Use for introductory uncertainty estimates from repeated measurements."),
            ],
            "representations": [
                rep("words", "Explain how accuracy and precision differ."),
                rep("diagram", "Use a target-board cluster picture to compare bias and scatter."),
                rep("formula", "Find the mean and an introductory uncertainty estimate."),
            ],
            "analogy_map": {
                "comparison": "An archery target compares accuracy and precision with closeness to the bullseye and closeness within the group.",
                "mapping": ["The bullseye stands for the true or accepted value.", "The spread of arrows stands for the spread of repeated readings."],
                "limit": "Measurements are not literal arrows, so the analogy only helps with target closeness and grouping.",
                "prediction_prompt": "If all the arrows move together away from the bullseye but stay tightly grouped, what changed in the measurement story?",
            },
            "worked_examples": [
                example("The readings are 9.8 cm, 10.0 cm, and 10.2 cm. Find the mean and estimate the uncertainty from half the range.", ["Add the readings and divide by 3 to get the mean.", "Find the range by subtracting the smallest from the largest reading.", "Take half of that range and keep the same unit."], "Mean = 10.0 cm, uncertainty = +/- 0.2 cm", "This links repeated readings to both a central value and a trust estimate."),
                example("A learner says a tight cluster far from the true value must still be accurate because the readings agree. Evaluate the claim.", ["Look at the tight grouping and identify that as precision.", "Compare the cluster with the true value and notice the offset.", "Conclude that agreement alone does not guarantee accuracy."], "The claim is wrong.", "This blocks the common habit of treating agreement among readings as proof of truth."),
            ],
            "visual_assets": [
                vis("f1-l6-accuracy-precision", "accuracy_precision", "Target-board comparison", "Show tight and loose clusters both on and off the bullseye.", "Accuracy and precision answer different trust questions about the same reading set."),
            ],
            "animation_assets": [
                anim("f1-l6-accuracy-precision-anim", "accuracy_precision", "Cluster movement animation", "Animate a reading cluster changing spread and center relative to a true value."),
            ],
            "simulation_contract": {
                "asset_id": "f1_l6_accuracy_precision_lab",
                "concept": "accuracy_precision",
                "baseline_case": "Start with a tight cluster centered on the true value.",
                "comparison_tasks": ["Move the cluster away from the true value while keeping it tight.", "Widen the cluster while keeping the center close to the true value."],
                "watch_for": "Students should keep closeness to the true value separate from closeness among the repeated readings.",
                "takeaway": "Good measurement reporting explains both where the readings sit and how tightly they agree, then adds an uncertainty that matches the data.",
            },
            "reflection_prompts": ["Explain how a set of measurements can be precise without being accurate and why the uncertainty still matters."],
            "mastery_skills": ["Identify accurate versus precise data sets.", "Distinguish random error from systematic error.", "Calculate a mean from repeated readings.", "Estimate an introductory uncertainty from repeated data.", "Report a value with a justified uncertainty statement."],
            "variation_plan": {
                "diagnostic": "Rotate data-set classification, error-type, mean, and half-range uncertainty items.",
                "concept_gate": "Swap between target-board reasoning and repeated-reading calculations.",
                "mastery": "Mix mean-and-uncertainty calculations with evaluation of biased and scattered data sets without repeating the same numbers.",
            },
            "assessment_bank_targets": assessment_targets(6, 5, 8),
            "visual_clarity_checks": [
                "Target-board visuals clearly separate cluster center from cluster spread.",
                "Repeated-reading tables use the same unit in the raw values, mean, and uncertainty.",
                "Error examples label random scatter and systematic offset with different visual cues.",
            ],
        },
    }
)


F1_SPEC["lessons"].append(
    {
        "id": "F1_L5",
        "title": "Density, Packing, and Float-or-Sink Reasoning",
        "sim": {
            "lab_id": "f1_density_packing_lab",
            "title": "Density explorer",
            "description": "Compare how changing mass and volume changes density and float-or-sink outcomes.",
            "instructions": [
                "Keep the volume fixed and change the mass.",
                "Keep the mass fixed and change the volume.",
                "Compare an object's density with the density of water and explain the float-or-sink result.",
            ],
            "outcomes": ["density_relationship_error", "density_unit_confusion"],
            "fields": ["mass", "volume", "density", "reference_density", "float_sink_reasoning"],
            "depth": "number of mass-volume comparisons explained through density rather than through size or weight alone",
        },
        "analogy_text": (
            "Density is like how tightly luggage is packed into a suitcase. "
            "Two suitcases can look equally full from the outside, but the one with more mass packed into the same space is denser."
        ),
        "commitment_prompt": "Before deciding whether something is dense, ask what happened to both the mass and the volume.",
        "micro_prompts": [
            prompt_block("Compare two blocks with the same volume but different masses.", "The heavier block packs more mass into the same space, so it is denser."),
            prompt_block("Compare two samples with the same mass but different volumes.", "Spreading the same mass through more space lowers the density."),
        ],
        "diagnostic": [
            mcq("F1L5_D1", "Density is best described as...", ["mass per unit volume", "volume per second", "force per area", "mass per unit time"], 0, "Density compares how much mass is packed into a volume.", ["density_relationship_error"]),
            mcq("F1L5_D2", "Which equation is correct for density?", ["density = mass x volume", "density = mass / volume", "density = volume / mass", "density = mass + volume"], 1, "Density uses mass divided by volume.", ["density_relationship_error"]),
            short("F1L5_D3", "A block has mass 40 g and volume 20 cm^3. What is its density?", ["2 g/cm^3", "2"], "Use density = mass / volume.", ["density_relationship_error", "density_unit_confusion"]),
            mcq("F1L5_D4", "Two cubes have the same volume, but cube A has more mass. Which is denser?", ["cube A", "cube B", "they have the same density", "it cannot be decided"], 0, "At fixed volume, more mass means greater density.", ["density_relationship_error"]),
            mcq("F1L5_D5", "If the mass stays the same and the volume increases, the density...", ["increases", "stays the same", "decreases", "becomes a vector"], 2, "The same mass is now spread through more space.", ["density_relationship_error"]),
            short("F1L5_D6", "A material has density 0.8 g/cm^3. Compared with water at 1.0 g/cm^3, will it float or sink?", ["float", "it floats"], "Lower density than water means it floats.", ["density_relationship_error"]),
        ],
        "inquiry": [
            prompt_block("Hold volume fixed and double the mass.", "Density doubles because twice as much mass is packed into the same space."),
            prompt_block("Hold mass fixed and double the volume.", "Density halves because the same mass is spread through more space."),
        ],
        "recon_prompts": [
            "Explain why a larger object is not automatically denser than a smaller one.",
            "Explain why float-or-sink reasoning depends on density comparison, not on mass alone.",
        ],
        "capsule_prompt": "Density is a relationship between mass and volume, so both quantities must be considered together.",
        "capsule_checks": [
            mcq("F1L5_C1", "What happens to density if mass doubles while volume stays fixed?", ["it halves", "it doubles", "it stays the same", "it becomes zero"], 1, "Mass and density increase together when volume stays fixed.", ["density_relationship_error"]),
            mcq("F1L5_C2", "What happens to density if volume doubles while mass stays fixed?", ["it doubles", "it stays the same", "it halves", "it becomes a unit"], 2, "The same mass is spread through twice the volume.", ["density_relationship_error"]),
            short("F1L5_C3", "A sample has mass 90 g and volume 30 cm^3. Find the density.", ["3 g/cm^3", "3"], "Divide mass by volume.", ["density_relationship_error", "density_unit_confusion"]),
            mcq("F1L5_C4", "Why can a small steel ball sink while a larger wooden block floats?", ["Because size alone decides sinking", "Because density matters more than size alone", "Because wood has no mass", "Because steel has no volume"], 1, "The comparison is about density, not size alone.", ["density_relationship_error"]),
            mcq("F1L5_C5", "Why should the density unit stay with the answer?", ["Because density has no value without units", "Because the unit shows what mass-per-volume comparison was used", "Because units replace the calculation", "Because units make all materials equal"], 1, "The unit explains the scale of the comparison.", ["density_unit_confusion"]),
        ],
        "transfer": [
            short("F1L5_T1", "A block has mass 120 g and volume 60 cm^3. Find the density.", ["2 g/cm^3", "2"], "Use density = mass / volume.", ["density_relationship_error", "density_unit_confusion"]),
            short("F1L5_T2", "A liquid has density 1.2 g/cm^3 and volume 50 cm^3. Find its mass.", ["60 g", "60"], "Use mass = density x volume.", ["density_relationship_error"]),
            short("F1L5_T3", "A material has mass 200 g and density 4 g/cm^3. Find its volume.", ["50 cm^3", "50"], "Use volume = mass / density.", ["density_relationship_error"]),
            mcq("F1L5_T4", "Two samples have the same density. Which statement must be true?", ["They have the same mass only", "Their mass-to-volume ratios are equal", "They have the same volume only", "They must float"], 1, "Equal density means equal mass-per-volume ratio.", ["density_relationship_error"]),
            mcq("F1L5_T5", "Which sample has the greater density?", ["80 g in 40 cm^3", "80 g in 80 cm^3", "they are equal", "there is not enough information"], 0, "2 g/cm^3 is greater than 1 g/cm^3.", ["density_relationship_error"]),
            mcq("F1L5_T6", "A learner says a large hollow object must sink because it has more mass than a pebble. What is the best reply?", ["Sinking depends on density comparison, not mass alone", "Large objects always sink", "Mass never matters", "Pebbles have no density"], 0, "The mass-volume relationship decides density.", ["density_relationship_error"]),
            mcq("F1L5_T7", "Why is kg/m^3 or g/cm^3 a sensible density unit?", ["Because density compares mass with volume", "Because density is a vector", "Because the denominator should always be time", "Because units are optional in density"], 0, "Density is mass per volume.", ["density_unit_confusion"]),
            mcq("F1L5_T8", "An object has density 0.6 g/cm^3. What happens in water?", ["It sinks because its mass is positive", "It floats because its density is less than water's density", "It stays exactly halfway by rule", "Nothing can be predicted"], 1, "Lower density than water means floating.", ["density_relationship_error"]),
        ],
        "contract": {
            "concept_targets": [
                "Treat density as a mass-per-volume relationship rather than as a size label.",
                "Use density comparison to reason about floating and sinking.",
            ],
            "prerequisite_lessons": ["F1_L1", "F1_L3"],
            "misconception_focus": ["density_relationship_error", "density_unit_confusion"],
            "formulas": [
                formula("density = mass / volume", "Density compares how much mass is packed into each unit volume.", ["g/cm^3", "kg/m^3"], "Use when mass and volume are both known."),
                formula("mass = density x volume", "Rearranging the density relationship lets you recover mass from density and volume.", ["g", "kg"], "Use when density and volume are known."),
            ],
            "representations": [
                rep("words", "Explain density as packing rather than as size or weight alone."),
                rep("diagram", "Show two same-volume blocks with different mass packing."),
                rep("formula", "Calculate density, mass, or volume from the relationship."),
            ],
            "analogy_map": {
                "comparison": "Packed luggage in a suitcase compares density with how tightly mass is packed into space.",
                "mapping": ["The suitcase space stands for volume.", "The amount of luggage mass packed into that space stands for density."],
                "limit": "Real materials are not literally suitcases of luggage; the analogy only tracks how much mass is packed into a given volume.",
                "prediction_prompt": "If the suitcase size stays fixed but much more mass is packed inside, what happens to the density story?",
            },
            "worked_examples": [
                example("A sample has mass 60 g and volume 20 cm^3. Find its density.", ["Write the density equation.", "Substitute 60 for mass and 20 for volume.", "Divide 60 by 20 and keep the density unit."], "3 g/cm^3", "This ties the relationship directly to the meaning of packed mass per volume."),
                example("A learner says a bigger block must always be denser. Evaluate the claim.", ["Ask what happened to both the mass and the volume.", "Notice that size alone only describes volume.", "Conclude that density cannot be decided without the mass-volume relationship."], "The claim is wrong.", "This blocks the size-equals-density shortcut."),
            ],
            "visual_assets": [
                vis("f1-l5-density-packing", "density_packing", "Mass packing comparison", "Show equal spaces with different masses packed inside.", "Density compares how tightly mass is packed into a volume."),
            ],
            "animation_assets": [
                anim("f1-l5-density-packing-anim", "density_packing", "Packing and floating animation", "Animate mass packing changing while the float-or-sink result updates."),
            ],
            "simulation_contract": {
                "asset_id": "f1_l5_density_packing_lab",
                "concept": "density_packing",
                "baseline_case": "Start with mass 40 g and volume 20 cm^3, then compare it with water.",
                "comparison_tasks": ["Keep volume fixed and change mass.", "Keep mass fixed and change volume."],
                "watch_for": "Students should compare density to the reference fluid instead of treating weight or size alone as the deciding factor.",
                "takeaway": "Density is the mass-per-volume story behind floating, sinking, and material comparison.",
            },
            "reflection_prompts": ["Explain why a large floating object can still be less dense than a small sinking object."],
            "mastery_skills": ["Calculate density from mass and volume.", "Rearrange the density equation for mass or volume.", "Keep density units attached correctly.", "Compare densities qualitatively.", "Use density comparison to explain floating and sinking."],
            "variation_plan": {
                "diagnostic": "Rotate direct calculations, same-mass versus same-volume comparisons, and float-or-sink prompts.",
                "concept_gate": "Swap between formula use and density-as-packing explanations.",
                "mastery": "Mix calculation, comparison, and float-or-sink reasoning so the same density idea appears in fresh contexts.",
            },
            "assessment_bank_targets": assessment_targets(6, 5, 8),
            "visual_clarity_checks": [
                "Mass and volume labels are shown beside every density visual.",
                "Reference-density comparisons clearly mark which density is greater.",
                "Float-or-sink visuals distinguish density comparison from sheer object size.",
            ],
        },
    }
)


F1_SPEC["lessons"].append(
    {
        "id": "F1_L4",
        "title": "Significant Figures and Reporting Calculations",
        "sim": {
            "lab_id": "f1_significant_figures_lab",
            "title": "Significant figures explorer",
            "description": "Compare how rounding and reporting rules change the final written result.",
            "instructions": [
                "Count significant figures in values with leading and trailing zeros.",
                "Round one value to a chosen number of significant figures.",
                "Compare an addition result with a multiplication result to see why the reporting rule changes.",
            ],
            "outcomes": ["significant_figure_count_error", "reporting_rule_confusion"],
            "fields": ["raw_value", "sig_fig_target", "operation_kind", "reported_result", "precision_reasoning"],
            "depth": "number of reporting decisions justified from the precision rule instead of from habit",
        },
        "analogy_text": (
            "Reporting a calculation is like copying a message onto a final scoreboard. "
            "You must keep every digit that carries real information, but you should not invent extra digits the original message never gave you."
        ),
        "commitment_prompt": "Before reporting a result, decide whether the task is about counting reliable digits, decimal places, or least-precise input data.",
        "micro_prompts": [
            prompt_block("Compare 0.00450 with 4500.", "Leading zeros only place the decimal point, while trailing zeros can sometimes show real precision."),
            prompt_block("Compare 12.4 + 0.33 with 12.4 x 0.33.", "Addition follows decimal places, while multiplication follows significant figures."),
        ],
        "diagnostic": [
            mcq("F1L4_D1", "How many significant figures are in 0.00450?", ["2", "3", "4", "5"], 1, "The leading zeros do not count, but the trailing zero after the decimal does count.", ["significant_figure_count_error"]),
            mcq("F1L4_D2", "Round 12.349 to 3 significant figures.", ["12.3", "12.4", "12.35", "12.30"], 0, "Keep 1, 2, and 3, then use the next digit 4 to decide the rounding.", ["significant_figure_count_error"]),
            mcq("F1L4_D3", "Which result is reported correctly for 2.5 x 3.42?", ["8.55", "8.6", "8.550", "8.5500"], 1, "The answer should keep 2 significant figures because 2.5 has 2 significant figures.", ["reporting_rule_confusion"]),
            mcq("F1L4_D4", "Which result is reported correctly for 12.4 + 0.33?", ["12.73", "12.7", "12.730", "13"], 1, "Addition follows the least number of decimal places, which is 1 decimal place here.", ["reporting_rule_confusion"]),
            short("F1L4_D5", "Round 0.006781 to 2 significant figures.", ["0.0068"], "Count from the first non-zero digit, then round using the next digit.", ["significant_figure_count_error"]),
            short("F1L4_D6", "Calculate 4.8 / 2.0 and report it correctly.", ["2.4"], "The answer should keep 2 significant figures.", ["reporting_rule_confusion"]),
        ],
        "inquiry": [
            prompt_block("Hold the raw value fixed and change only the number of significant figures requested.", "The underlying value stays the same, but the reported precision changes."),
            prompt_block("Use the same pair of numbers once in addition and once in multiplication.", "The reporting rule depends on the operation, not just on the calculator output."),
        ],
        "recon_prompts": [
            "Explain why a calculator can produce more digits than the measurement data really deserves.",
            "Explain why addition and multiplication do not use exactly the same reporting rule.",
        ],
        "capsule_prompt": "A final reported answer should be no more precise than the information that produced it.",
        "capsule_checks": [
            mcq("F1L4_C1", "Which zeros in 0.0300 count as significant?", ["none of them", "only the zero before the 3", "the two trailing zeros after the 3", "all three zeros"], 2, "The trailing zeros after the decimal show reported precision here.", ["significant_figure_count_error"]),
            mcq("F1L4_C2", "Why is 8.550 often a poor final answer for 2.5 x 3.42?", ["Because the decimal point is wrong", "Because it claims more precision than the least precise factor supports", "Because multiplication always removes decimals", "Because trailing zeros never count"], 1, "The product should not pretend to be more precise than the measurements allow.", ["reporting_rule_confusion"]),
            short("F1L4_C3", "Round 958.4 to 2 significant figures.", ["960"], "Keep 9 and 5, then round using the next digit 8.", ["significant_figure_count_error"]),
            mcq("F1L4_C4", "Which operation rule is correct?", ["Addition uses least significant figures", "Multiplication uses least decimal places", "Multiplication uses least significant figures", "All operations use the same rule"], 2, "Multiplication and division follow the least significant figures rule.", ["reporting_rule_confusion"]),
            mcq("F1L4_C5", "Why do significant figures matter in science?", ["They decorate the answer", "They show the level of precision that the data honestly supports", "They remove all uncertainty", "They replace units"], 1, "The goal is honest reporting, not fancy formatting.", ["significant_figure_count_error", "reporting_rule_confusion"]),
        ],
        "transfer": [
            mcq("F1L4_T1", "How many significant figures are in 230.0?", ["2", "3", "4", "5"], 2, "The decimal point shows that the trailing zero is significant.", ["significant_figure_count_error"]),
            mcq("F1L4_T2", "Which is the best rounded form of 0.07896 to 3 significant figures?", ["0.0790", "0.0789", "0.079", "0.080"], 2, "Keep 7, 8, and 9, then round up because the next digit is 6.", ["significant_figure_count_error"]),
            short("F1L4_T3", "Calculate 5.6 x 1.24 and report the result correctly.", ["6.9"], "The exact product is 6.944, which rounds to 2 significant figures.", ["reporting_rule_confusion"]),
            short("F1L4_T4", "Calculate 14.25 + 3.1 and report the result correctly.", ["17.4"], "Addition follows the least number of decimal places.", ["reporting_rule_confusion"]),
            mcq("F1L4_T5", "Which statement is true?", ["Leading zeros always count as significant", "Trailing zeros after a decimal point can show real precision", "Units decide the number of significant figures", "Calculator display digits are always all significant"], 1, "Trailing zeros after a decimal can show reported precision.", ["significant_figure_count_error"]),
            mcq("F1L4_T6", "A student reports 3.141592 for a measurement that was only given to 2 significant figures. The main issue is...", ["the number is too small", "the answer claims unsupported precision", "the unit must be wrong", "rounding is only for addition"], 1, "The problem is over-reporting the precision.", ["reporting_rule_confusion"]),
            short("F1L4_T7", "Round 4072 to 3 significant figures.", ["4070"], "Keep 4, 0, and 7, then round using the next digit 2.", ["significant_figure_count_error"]),
            mcq("F1L4_T8", "Why might 12.73 be less suitable than 12.7 for reporting 12.4 + 0.33?", ["Because the answer must be an integer", "Because the least precise addend only supports 1 decimal place", "Because 0.33 has too many zeros", "Because addition ignores precision"], 1, "The least precise decimal place controls the reported sum.", ["reporting_rule_confusion"]),
        ],
        "contract": {
            "concept_targets": [
                "Count significant figures reliably in common scientific values.",
                "Report calculations with a precision rule that matches the operation used.",
            ],
            "prerequisite_lessons": ["F1_L1", "F1_L3"],
            "misconception_focus": ["significant_figure_count_error", "reporting_rule_confusion"],
            "formulas": [
                formula("reported sum or difference decimal places = least decimal places in the inputs", "Addition and subtraction follow the least precise decimal place shown by the original measurements.", ["same unit as the calculation"], "Use when combining measured values by addition or subtraction."),
                formula("reported product or quotient significant figures = least significant figures in the inputs", "Multiplication and division follow the least precise significant-figure count among the measured values.", ["same derived unit as the calculation"], "Use when multiplying or dividing measured values."),
            ],
            "representations": [
                rep("words", "Explain why reported answers should not invent precision."),
                rep("table", "Compare significant-figure counts and decimal-place limits across several values."),
                rep("formula", "Report arithmetic results using the correct rule."),
            ],
            "analogy_map": {
                "comparison": "A scoreboard copy compares a final reported value with the message quality of the original data.",
                "mapping": ["The original message stands for the raw measurements and their limited precision.", "The scoreboard display stands for the final reported result."],
                "limit": "Digits are not literally messages being copied by hand; the analogy only helps with keeping or trimming reliable detail.",
                "prediction_prompt": "If the original message is blurry in one place, what should happen to the final scoreboard copy in that same place?",
            },
            "worked_examples": [
                example("Count the significant figures in 0.00450.", ["Ignore the leading zeros because they only locate the decimal point.", "Count 4 and 5.", "Count the trailing zero because it comes after the decimal and signals precision."], "3 significant figures", "This blocks the common mistake of counting every visible digit automatically."),
                example("Calculate 2.5 x 3.42 and report it properly.", ["Do the calculator multiplication first to get 8.55.", "Notice that the least precise factor, 2.5, has 2 significant figures.", "Round the product to 2 significant figures."], "8.6", "This keeps reporting tied to data quality rather than to calculator display length."),
            ],
            "visual_assets": [
                vis("f1-l4-significant-figures", "significant_figures", "Reliable digits map", "Show which digits carry information and which digits only place the decimal point.", "Significant figures track the digits the measurement can honestly support."),
            ],
            "animation_assets": [
                anim("f1-l4-significant-figures-anim", "significant_figures", "Rounding in motion", "Animate a value being rounded to different significant-figure targets."),
            ],
            "simulation_contract": {
                "asset_id": "f1_l4_significant_figures_lab",
                "concept": "significant_figures",
                "baseline_case": "Start with 12.349 and round it to 3 significant figures.",
                "comparison_tasks": ["Report one addition result using decimal places.", "Report one multiplication result using significant figures."],
                "watch_for": "Students should justify the reporting rule from the operation and the least precise input, not from preference for more digits.",
                "takeaway": "A final scientific result should keep the digits that the measurement truly supports and discard the rest.",
            },
            "reflection_prompts": ["Explain why a calculator answer can be mathematically correct but still scientifically over-precise."],
            "mastery_skills": ["Count significant figures in common decimal values.", "Round values to a stated number of significant figures.", "Use decimal-place rules for addition and subtraction.", "Use significant-figure rules for multiplication and division.", "Explain why honest reporting matters in science."],
            "variation_plan": {
                "diagnostic": "Rotate sig-fig counting, rounding, addition-reporting, and multiplication-reporting prompts across different values.",
                "concept_gate": "Swap between counting rules and operation-specific reporting decisions.",
                "mastery": "Mix direct calculations with evaluation of over-precise answers so the idea transfers beyond one numeric example.",
            },
            "assessment_bank_targets": assessment_targets(6, 5, 8),
            "visual_clarity_checks": [
                "Digit highlights clearly separate counted digits from placeholder zeros.",
                "Rounding steps show the kept digit and the deciding next digit side by side.",
                "Addition and multiplication examples are visually labeled with different reporting rules.",
            ],
        },
    }
)


F1_SPEC["lessons"].append(
    {
        "id": "F1_L3",
        "title": "Choosing Instruments, Reading Scales, and Resolution",
        "sim": {
            "lab_id": "f1_measurement_precision_lab",
            "title": "Measurement precision explorer",
            "description": "Compare how different tools change reading detail, trust, and uncertainty.",
            "instructions": [
                "Measure the same object with a coarse ruler and a fine caliper.",
                "Compare repeated readings and decide which tool gives tighter agreement.",
                "Introduce a zero error and explain why it biases every reading.",
            ],
            "outcomes": ["instrument_choice_confusion", "scale_reading_confusion", "resolution_uncertainty_confusion"],
            "fields": ["tool_name", "smallest_division", "reading_value", "reported_uncertainty", "zero_error"],
            "depth": "number of tool-choice and uncertainty claims tied to the instrument resolution instead of guesswork",
        },
        "analogy_text": (
            "Choosing an instrument is like choosing between a thick marker and a fine technical pen. "
            "Both can draw a line, but only the finer pen can describe tiny details honestly."
        ),
        "commitment_prompt": "Before reading a tool, decide whether its smallest division is fine enough for the object you want to measure.",
        "micro_prompts": [
            prompt_block("Compare measuring a desk length with a metre rule and the thickness of a sheet of card with a micrometer screw gauge.", "The best tool depends on the size of the detail you need to resolve, not on using one tool for every job."),
            prompt_block("Compare reading a scale with 1 cm divisions and one with 0.1 cm divisions.", "The finer scale supports a smaller uncertainty because it shows smaller changes."),
        ],
        "diagnostic": [
            mcq("F1L3_D1", "Which tool is most suitable for measuring the thickness of a sheet of card?", ["metre rule", "kitchen scale", "caliper", "micrometer screw gauge"], 3, "A very small thickness needs the finest suitable length tool.", ["instrument_choice_confusion"]),
            mcq("F1L3_D2", "What does instrument resolution tell you?", ["How heavy the tool is", "The smallest change the tool can show", "The color of the scale", "The true value of the object"], 1, "Resolution is the smallest step the instrument can show.", ["resolution_uncertainty_confusion"]),
            mcq("F1L3_D3", "A ruler's smallest division is 1 mm. A reasonable reading uncertainty is closest to...", ["+/- 5 mm", "+/- 0.5 mm", "+/- 10 mm", "+/- 1 cm"], 1, "A common estimate is about half the smallest division.", ["resolution_uncertainty_confusion"]),
            mcq("F1L3_D4", "A balance reads 0.20 g too high every time because of zero error. This is mainly...", ["random scatter", "systematic error", "improved precision", "unit conversion"], 1, "A repeated offset in one direction is systematic.", ["resolution_uncertainty_confusion", "random_systematic_error_confusion"]),
            short("F1L3_D5", "A scale's smallest division is 0.2 cm. Give a reasonable uncertainty.", ["0.1 cm", "+/- 0.1 cm"], "Use about half the smallest division.", ["uncertainty_estimation_error"]),
            short("F1L3_D6", "A stopwatch records 12.4 s, 12.5 s, and 12.3 s. What is the mean time?", ["12.4 s", "12.4"], "Add the readings and divide by 3.", ["scale_reading_confusion"]),
        ],
        "inquiry": [
            prompt_block("Keep the object fixed and swap only the tool.", "Better resolution changes the trust in the reading, not the object's true size."),
            prompt_block("Repeat the reading three times with and without zero error.", "Scatter and bias are different problems and should be described separately."),
        ],
        "recon_prompts": [
            "Explain why the best instrument is not always the fanciest instrument.",
            "Explain how a zero error can make repeated readings look precise but still be misleading.",
        ],
        "capsule_prompt": "Good measurement starts with a sensible tool choice and an honest uncertainty.",
        "capsule_checks": [
            mcq("F1L3_C1", "Why is a micrometer screw gauge preferred over a ruler for the thickness of a sheet of card?", ["It is always cheaper", "It gives a finer resolution for tiny lengths", "It changes the card thickness", "It removes all uncertainty"], 1, "The finer tool matches the smaller scale of the object.", ["instrument_choice_confusion"]),
            mcq("F1L3_C2", "A reading that shifts every time by the same amount suggests...", ["random error", "systematic error", "better accuracy", "a unit mistake"], 1, "The clue is the repeated same-direction shift.", ["random_systematic_error_confusion"]),
            short("F1L3_C3", "A thermometer scale's smallest division is 2 C. Give a reasonable uncertainty.", ["1 C", "+/- 1 C", "1°C", "+/- 1°C", "±1 C", "±1°C", "1 degree C", "+/- 1 degree C", "1 Celsius", "+/- 1 Celsius"], "Use about half the smallest division.", ["uncertainty_estimation_error"]),
            mcq("F1L3_C4", "Which statement about repeated readings is best?", ["One reading is always enough", "Closely agreeing repeated readings usually show better precision", "Precision means the reading must equal the textbook answer", "Repeated readings remove all systematic error"], 1, "Small scatter supports better precision.", ["resolution_uncertainty_confusion"]),
            mcq("F1L3_C5", "Why should the reported precision match the tool?", ["Because extra digits make the answer true", "Because reporting more detail than the tool shows is dishonest precision", "Because units become optional", "Because zero error disappears"], 1, "A tool limits the detail you can support.", ["scale_reading_confusion", "resolution_uncertainty_confusion"]),
        ],
        "transfer": [
            mcq("F1L3_T1", "Which tool is best for timing a 100 m race?", ["caliper", "stopwatch", "measuring cylinder", "balance"], 1, "Choose the tool that measures time.", ["instrument_choice_confusion"]),
            mcq("F1L3_T2", "Which tool is best for finding the volume of an irregular stone by displacement?", ["stopwatch", "measuring cylinder", "metre rule", "ammeter"], 1, "The cylinder lets you compare water level changes.", ["instrument_choice_confusion"]),
            short("F1L3_T3", "A ruler's smallest division is 0.1 cm. Give a reasonable uncertainty.", ["0.05 cm", "+/- 0.05 cm"], "Half of 0.1 cm is 0.05 cm.", ["uncertainty_estimation_error"]),
            short("F1L3_T4", "The readings 5.1 cm, 5.3 cm, and 5.2 cm are taken. What is the mean?", ["5.2 cm", "5.2"], "Add and divide by 3.", ["scale_reading_confusion"]),
            mcq("F1L3_T5", "Two learners use the same faulty ruler with a zero offset. Their results are close to one another but all too high. Which statement fits best?", ["accurate but not precise", "precise but biased", "random but unbiased", "exact and certain"], 1, "Close agreement can still sit around a biased value.", ["resolution_uncertainty_confusion", "random_systematic_error_confusion"]),
            mcq("F1L3_T6", "Why might a metre rule be a better choice than a caliper for measuring classroom door width?", ["The door width is too large for the caliper to use conveniently", "The caliper has no scale", "Resolution never matters", "Doors do not have length"], 0, "Suitability depends on the object's scale as well as the tool's resolution.", ["instrument_choice_confusion"]),
            mcq("F1L3_T7", "If repeated readings scatter unpredictably around one value, the main issue is...", ["a direction mistake", "random error", "unit conversion", "systematic error only"], 1, "Scatter is the key clue for random error.", ["random_systematic_error_confusion"]),
            mcq("F1L3_T8", "What makes a reported measurement trustworthy?", ["Many decimal places alone", "A suitable tool, a careful reading, and an honest uncertainty", "Using the smallest possible unit always", "Ignoring repeated readings"], 1, "Trust comes from method and honest reporting, not decorative digits.", ["instrument_choice_confusion", "resolution_uncertainty_confusion"]),
        ],
        "contract": {
            "concept_targets": [
                "Choose instruments by matching their range and resolution to the task.",
                "Read scales honestly and attach a reasonable uncertainty to the result.",
            ],
            "prerequisite_lessons": ["F1_L1"],
            "misconception_focus": ["instrument_choice_confusion", "scale_reading_confusion", "resolution_uncertainty_confusion"],
            "formulas": [
                formula("reading uncertainty ≈ smallest division / 2", "A simple scale reading is usually trusted to about half the smallest marked division.", ["same unit as the scale"], "Use for basic analog scales when a more specific method is not given."),
                formula("mean reading = total of readings / number of readings", "The mean gives one representative value from repeated measurements.", ["same unit as the readings"], "Use when repeated readings are taken under the same conditions."),
            ],
            "representations": [
                rep("words", "Explain why tool choice and uncertainty are linked."),
                rep("diagram", "Show coarse and fine scales on two different instruments."),
                rep("formula", "Estimate uncertainty and mean from actual readings."),
            ],
            "analogy_map": {
                "comparison": "A thick marker versus a fine technical pen compares coarse and fine measuring tools.",
                "mapping": ["The fine pen stands for a tool with finer resolution.", "The width of the line stands for the uncertainty built into the mark you can make."],
                "limit": "A measuring tool does more than draw a line; the analogy only tracks how much detail the tool can honestly show.",
                "prediction_prompt": "If the line made by the pen is much thicker than the detail you want to mark, what problem will the measurement face?",
            },
            "worked_examples": [
                example("A thermometer scale's smallest division is 2 C. Estimate a reasonable uncertainty.", ["Identify the smallest division on the scale.", "Take about half of that division.", "Keep the same unit in the uncertainty statement."], "+/- 1 C", "This prevents uncertainty from being guessed without reference to the scale."),
                example("Three readings of a pencil length are 14.2 cm, 14.1 cm, and 14.3 cm. Find the mean and comment briefly on the precision.", ["Add the three readings.", "Divide by 3 to get the mean.", "Notice that the readings are close together, so the set is fairly precise."], "Mean = 14.2 cm", "This ties a numerical average to a qualitative precision judgment."),
            ],
            "visual_assets": [
                vis("f1-l3-tool-trust", "measurement_precision", "Tool trust comparison", "Show how fine divisions improve resolution and shrink uncertainty.", "Better resolution supports smaller uncertainty when the measurement is done carefully."),
            ],
            "animation_assets": [
                anim("f1-l3-tool-trust-anim", "measurement_precision", "Tool resolution animation", "Animate the same object being measured with a coarse ruler, a caliper, and a micrometer screw gauge."),
            ],
            "simulation_contract": {
                "asset_id": "f1_l3_measurement_precision_lab",
                "concept": "measurement_precision",
                "baseline_case": "Start with a ruler and then compare the same object with a caliper and a micrometer screw gauge.",
                "comparison_tasks": ["Compare the smallest division on each tool.", "Introduce a zero error and explain how it shifts every reading."],
                "watch_for": "Students should separate precision, uncertainty, and zero-error bias instead of mixing them into one vague idea of 'wrong'.",
                "takeaway": "Good measurement needs a sensible tool, a careful reading, and an uncertainty that matches the tool.",
            },
            "reflection_prompts": ["Explain why repeated readings can look precise even when a zero error is still making them unfairly high."],
            "mastery_skills": ["Choose a suitable measuring instrument.", "Estimate a reasonable uncertainty from the scale.", "Calculate a mean from repeated readings.", "Distinguish random scatter from systematic bias.", "Report a measurement without claiming false precision."],
            "variation_plan": {
                "diagnostic": "Rotate tool-choice, scale-reading, uncertainty, and repeated-reading items across length, time, and temperature contexts.",
                "concept_gate": "Swap between zero-error reasoning and resolution-based uncertainty questions.",
                "mastery": "Mix tool choice, mean calculation, and precision-versus-bias explanations without repeating the same apparatus story.",
            },
            "assessment_bank_targets": assessment_targets(6, 5, 8),
            "visual_clarity_checks": [
                "Every scale visual labels the smallest division explicitly.",
                "Uncertainty examples use the same unit as the measured value.",
                "Zero-error examples make the bias direction visually obvious.",
            ],
        },
    }
)


F1_SPEC["lessons"].append(
    {
        "id": "F1_L2",
        "title": "Scalars, Vectors, and Directional Descriptions",
        "sim": {
            "lab_id": "f1_vector_direction_lab",
            "title": "Vector direction explorer",
            "description": "Compare how changing magnitude and changing direction affect a vector description.",
            "instructions": [
                "Keep the magnitude fixed and rotate the direction arrow.",
                "Keep the direction fixed and change only the magnitude.",
                "Compare route length with start-to-finish arrow in a journey that turns around.",
            ],
            "outcomes": ["scalar_vector_confusion", "directional_description_confusion"],
            "fields": ["magnitude", "angle_deg", "distance_value", "displacement_value", "classification_reasoning"],
            "depth": "number of size-versus-direction comparisons interpreted correctly as scalar or vector changes",
        },
        "analogy_text": (
            "Imagine sending supplies across a map. A scalar is like writing only how much cargo is being sent. "
            "A vector is like drawing an arrow on the map that says how much cargo and exactly which way it must go."
        ),
        "commitment_prompt": "Before classifying a quantity, ask whether the answer is complete without a direction.",
        "micro_prompts": [
            prompt_block("Compare '6 m' with '6 m north'.", "The direction word turns the description into a vector."),
            prompt_block("Compare a round trip distance with the displacement arrow from start to finish.", "Distance tracks the route length, while displacement tracks the net change with direction."),
        ],
        "diagnostic": [
            mcq("F1L2_D1", "Which quantity is a vector?", ["speed", "mass", "displacement", "temperature"], 2, "Displacement needs magnitude and direction.", ["scalar_vector_confusion"]),
            mcq("F1L2_D2", "Which quantity is a scalar?", ["force", "velocity", "distance", "acceleration"], 2, "Distance needs magnitude only.", ["scalar_vector_confusion"]),
            mcq("F1L2_D3", "Which description must be a vector?", ["6 kg", "6 s", "6 m north", "6 cm"], 2, "The direction word is the clue.", ["directional_description_confusion"]),
            mcq("F1L2_D4", "A runner goes 8 m east and 8 m west back to the start. What is the displacement?", ["16 m east", "16 m", "0 m", "8 m west"], 2, "Displacement is the start-to-finish change.", ["directional_description_confusion"]),
            short("F1L2_D5", "A cyclist travels 120 m in 20 s. What is the average speed?", ["6 m/s", "6"], "Use speed = distance / time.", ["scalar_vector_confusion"]),
            short("F1L2_D6", "A drone moves 30 m north in 10 s. What is the average velocity?", ["3 m/s north", "3 north", "3"], "Use velocity = displacement / time and keep the direction.", ["directional_description_confusion"]),
        ],
        "inquiry": [
            prompt_block("Keep the arrow length fixed and rotate it.", "A vector changes when its direction changes, even if its size does not."),
            prompt_block("Compare one bent route with the straight arrow from start to finish.", "The route length and the net displacement are not the same idea."),
        ],
        "recon_prompts": [
            "Explain why velocity is not just speed with a fancier name.",
            "Explain why a round trip can have a large distance but zero displacement.",
        ],
        "capsule_prompt": "Vectors need both size and direction, while scalars need size only.",
        "capsule_checks": [
            mcq("F1L2_C1", "What extra information turns speed into velocity?", ["time", "direction", "mass", "temperature"], 1, "Velocity is speed plus direction.", ["directional_description_confusion"]),
            mcq("F1L2_C2", "Two vectors can have the same magnitude but still be different because...", ["they use different units only", "their directions can differ", "vectors ignore direction", "their mass changes"], 1, "Direction matters for vectors.", ["scalar_vector_confusion"]),
            mcq("F1L2_C3", "Which statement best compares distance and displacement?", ["Both always need direction", "Distance is route length, while displacement is the start-to-finish change with direction", "Displacement ignores direction", "Distance is always smaller"], 1, "One tracks the route, the other the net change.", ["directional_description_confusion"]),
            short("F1L2_C4", "A car moves 20 m east in 4 s. What is its average velocity?", ["5 m/s east", "5"], "Use displacement divided by time and keep the direction.", ["directional_description_confusion"]),
            mcq("F1L2_C5", "If an object keeps the same speed but turns around, which quantity must change?", ["temperature", "velocity", "mass", "time"], 1, "A direction change changes a vector quantity.", ["scalar_vector_confusion", "directional_description_confusion"]),
        ],
        "transfer": [
            mcq("F1L2_T1", "Which pair contains only scalars?", ["speed and mass", "velocity and force", "displacement and acceleration", "force and weight"], 0, "Scalars do not need direction.", ["scalar_vector_confusion"]),
            mcq("F1L2_T2", "Which pair contains only vectors?", ["distance and time", "mass and temperature", "velocity and force", "speed and volume"], 2, "Vectors need magnitude and direction.", ["scalar_vector_confusion"]),
            mcq("F1L2_T3", "Why can an object have the same speed but a different velocity later?", ["Its unit changed", "Its direction changed", "Its mass doubled", "Its clock changed"], 1, "Velocity includes direction, unlike speed.", ["directional_description_confusion"]),
            short("F1L2_T4", "A learner walks 18 m in 6 s. What is the average speed?", ["3 m/s", "3"], "Use total distance divided by total time.", ["scalar_vector_confusion"]),
            short("F1L2_T5", "A robot moves 12 m west in 3 s. What is the average velocity?", ["4 m/s west", "4"], "Use displacement divided by time and keep the west direction.", ["directional_description_confusion"]),
            mcq("F1L2_T6", "A car completes one full lap and finishes where it started. Which statement is correct?", ["Distance is zero and displacement is zero", "Distance is not zero, but displacement is zero", "Displacement is larger than distance", "Both need the same direction word"], 1, "A full lap can give zero net change but non-zero route length.", ["directional_description_confusion"]),
            mcq("F1L2_T7", "Which description is most clearly a vector?", ["250 g", "250 cm^3", "250 m south", "250 s"], 2, "The direction word shows a vector.", ["scalar_vector_confusion"]),
            mcq("F1L2_T8", "Which statement is true?", ["Scalars always stay positive", "Vectors have magnitude and direction", "Distance and displacement are interchangeable", "Velocity ignores direction"], 1, "Vectors need both parts.", ["scalar_vector_confusion"]),
        ],
        "contract": {
            "concept_targets": [
                "Classify scalar and vector quantities with confidence.",
                "Use direction language to separate route length from directed change.",
            ],
            "prerequisite_lessons": ["F1_L1"],
            "misconception_focus": ["scalar_vector_confusion", "directional_description_confusion"],
            "formulas": [
                formula("speed = distance / time", "Average speed uses the full route length over the total time.", ["m/s"], "Use when only route length matters."),
                formula("velocity = displacement / time", "Average velocity uses start-to-finish change and keeps direction.", ["m/s"], "Use when directed change matters."),
            ],
            "representations": [
                rep("words", "Separate descriptions that need direction from those that do not."),
                rep("diagram", "Show a route and a displacement arrow on the same map."),
                rep("formula", "Compare the speed and velocity relationships."),
            ],
            "analogy_map": {
                "comparison": "Cargo amount versus cargo arrow compares scalar and vector information.",
                "mapping": ["Cargo amount stands for magnitude only.", "A map arrow stands for magnitude together with direction."],
                "limit": "Not every vector is a literal arrow drawn on a map; the analogy only tracks the extra directional information.",
                "prediction_prompt": "If the cargo amount stays the same but the map arrow turns, what changed in the vector description?",
            },
            "worked_examples": [
                example("A learner says '5 m east' is a scalar because it uses one number. Evaluate the claim.", ["Look for whether a direction is included.", "Notice the word east.", "Conclude that the description is a vector because it gives magnitude and direction."], "The claim is wrong.", "This stops learners from focusing on the number alone and missing the direction information."),
                example("A walker goes 10 m east and 4 m west. Compare distance with displacement.", ["Add the full route to find distance: 10 + 4 = 14 m.", "Compare start and finish for displacement: 6 m east.", "State that the two quantities answer different questions."], "Distance = 14 m, displacement = 6 m east.", "This anchors the difference between route length and directed change."),
            ],
            "visual_assets": [
                vis("f1-l2-vector-arrow", "scalar_vector", "Arrow versus amount", "Show how an arrow carries direction while a scalar label does not.", "Vectors keep size and direction together."),
            ],
            "animation_assets": [
                anim("f1-l2-vector-arrow-anim", "scalar_vector", "Vector change animation", "Animate a vector changing by rotation and then by magnitude."),
            ],
            "simulation_contract": {
                "asset_id": "f1_l2_vector_direction_lab",
                "concept": "scalar_vector",
                "baseline_case": "Start with a vector of magnitude 4 pointing east.",
                "comparison_tasks": ["Rotate the arrow while keeping the magnitude fixed.", "Keep the direction fixed and change only the magnitude."],
                "watch_for": "Students should say that either magnitude or direction can change a vector, while scalars ignore direction.",
                "takeaway": "Direction is not an optional decoration; it is part of the quantity when the quantity is a vector.",
            },
            "reflection_prompts": ["Explain why a round trip can have a large distance but zero displacement."],
            "mastery_skills": ["Classify scalar and vector quantities.", "Use direction words correctly.", "Separate speed from velocity.", "Separate distance from displacement.", "Calculate simple average speed and average velocity."],
            "variation_plan": {
                "diagnostic": "Rotate between classification items, route-versus-arrow comparisons, and simple speed or velocity calculations.",
                "concept_gate": "Swap direction-based classification with short distance-versus-displacement checks.",
                "mastery": "Mix quantity classification, route reasoning, and simple average calculations without repeating the same journey story.",
            },
            "assessment_bank_targets": assessment_targets(6, 5, 8),
            "visual_clarity_checks": [
                "Every vector visual shows a clear arrowhead and labelled direction.",
                "Route diagrams separate the travelled path from the start-to-finish arrow.",
                "Formula examples keep direction words attached to velocity answers.",
            ],
        },
    }
)


F1_MODULE_DOC, F1_LESSONS, F1_SIM_LABS = _finalize_bundle()
F1_MODULE_DOC.update(
    {
        "description": F1_SPEC["module_description"],
        "module_description": F1_SPEC["module_description"],
        "analogy_model_name": "Measure-Map Studio Model",
        "anchor_sentence": "Physics begins when the world is tagged with units, checked with tools, and turned into maps that show pattern instead of guesswork.",
        "curriculum_focus": [
            "SI units and unit conversion",
            "base and derived quantities",
            "scalars and vectors as first ideas",
            "measuring length, mass, time, and temperature",
            "precision, accuracy, and simple uncertainty",
            "density",
            "reading, plotting, and interpreting simple graphs",
        ],
    }
)


if __name__ == "__main__":
    main()
