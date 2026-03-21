from __future__ import annotations

import argparse
import math
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


A3_MODULE_ID = "A3"
A3_CONTENT_VERSION = "20260321_a3_thread_window_pulse_v1"
A3_MODULE_TITLE = "Fields & Electromagnetic Theory"
A3_ALLOWLIST = [
    "flux_equals_field_only_confusion",
    "orientation_irrelevant_flux_confusion",
    "steady_flux_induces_current_confusion",
    "change_source_only_motion_confusion",
    "faster_change_same_emf_confusion",
    "flux_linkage_equals_flux_confusion",
    "turns_do_not_matter_confusion",
    "lenz_opposes_field_not_change_confusion",
    "dc_vs_ac_size_only_confusion",
    "frequency_period_confusion",
    "peak_equals_rms_confusion",
    "average_equals_rms_confusion",
    "sinusoid_formula_time_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(A3_ALLOWLIST)
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
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": template,
        "meta": deepcopy(meta or {}),
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
        "diagnostic_pool_min": 10,
        "concept_gate_pool_min": 8,
        "mastery_pool_min": 10,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile layouts.",
        "Field-thread, window, induced-direction, and waveform labels remain separated so the time-varying story never collapses into one line bundle.",
        "Flux, linkage, period, peak, and RMS callouts stay readable without clipping into the graph or loop geometry.",
        "Direction arrows and sign cues keep the opposition story and AC reversal story visible at a glance.",
    ]


def thread_window_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Thread-Window Pulse Model",
        "focus": focus,
        "comparison": f"The Thread-Window world keeps flux, induction, AC, and RMS inside one time-varying field story while {focus}.",
        "mapping": [
            "Field threads -> magnetic field",
            "Window loop -> conducting loop or coil area",
            "Through-thread score -> magnetic flux",
            "Thread-link total -> flux linkage",
            "Window tilt -> orientation of the area to the field",
            "Loop push -> induced emf",
            "Oppose-turn rule -> Lenz's law",
            "One-way drive -> direct current",
            "Swing drive -> alternating current",
            "Beat clock -> period and frequency",
            "Crest level -> peak value",
            "Heat-match level -> RMS value",
        ],
        "limit": "The model keeps the changing-field relationships coherent, but learners still need the formal language of flux, linkage, Faraday, Lenz, sinusoidal AC, frequency, period, and RMS.",
        "prediction_prompt": f"Use the Thread-Window model to predict what should happen when {focus}.",
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


def waveform_points(peak: float, *, cycles: float = 1.0, points: int = 64) -> List[List[float]]:
    samples: List[List[float]] = []
    end_x = cycles
    for index in range(points + 1):
        x = end_x * index / points
        y = peak * math.sin((2 * math.pi * cycles * index) / points)
        samples.append([round(x, 4), round(y, 4)])
    return samples


def line_points(y_value: float, *, end_x: float = 1.0) -> List[List[float]]:
    return [[0.0, round(y_value, 4)], [round(end_x, 4), round(y_value, 4)]]


def lesson_one() -> Dict[str, Any]:
    diagnostic = [
        mcq("A3L1_D1", "In the Thread-Window model, the through-thread score stands for...", ["magnetic flux", "induced emf", "resistance", "RMS current"], 0, "Flux is the field-through-window score.", ["flux_equals_field_only_confusion"], skill_tags=["flux_meaning"]),
        mcq("A3L1_D2", "If field strength stays the same but the loop area doubles, the flux in the face-on case...", ["doubles", "halves", "stays the same", "becomes zero"], 0, "In the perpendicular case, flux is proportional to area.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"]),
        mcq("A3L1_D3", "A face-on window loop catches the maximum thread count because...", ["the area faces the field directly", "the wire gets heavier", "the resistance becomes zero", "the loop push is already induced"], 0, "Flux is largest when the field is perpendicular to the loop area.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"]),
        mcq("A3L1_D4", "Tilting the loop away from face-on usually makes the flux...", ["smaller", "larger", "negative automatically", "independent of angle"], 0, "Tilt reduces the perpendicular component through the loop.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"]),
        mcq("A3L1_D5", "Which list gives the three main factors that set the through-thread score?", ["field strength, area, and orientation", "mass, charge, and temperature", "current, resistance, and power", "period, peak, and RMS"], 0, "Flux depends on field, area, and tilt.", ["flux_equals_field_only_confusion", "orientation_irrelevant_flux_confusion"], skill_tags=["flux_meaning"]),
        mcq("A3L1_D6", "For a perpendicular loop in a 0.5 T field with area 0.4 m^2, the flux is...", ["0.20 Wb", "0.90 Wb", "0.80 Wb", "0.05 Wb"], 0, "Use Phi = BA for the perpendicular case.", ["flux_equals_field_only_confusion"], skill_tags=["use_flux_ba"]),
        mcq("A3L1_D7", "A stronger field through the same loop and the same orientation gives...", ["larger flux", "smaller flux", "zero flux", "the same flux"], 0, "More field threads pass through the same window.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"]),
        short("A3L1_D8", "Why is flux not just another word for magnetic field strength?", ["Because flux depends on how much magnetic field passes through the loop area, so area and orientation matter as well as field strength.", "Because magnetic flux is a field-through-area quantity, not just the field strength by itself."], "Mention field strength together with area or orientation.", ["flux_equals_field_only_confusion"], skill_tags=["flux_meaning"], acceptance_rules=acceptance_groups(["field", "threads"], ["through", "area", "window"], ["orientation", "tilt", "face-on"], ["not just", "not only"])),
        short("A3L1_D9", "Why can two loops in the same field have different flux values?", ["Because the loops can have different areas or different orientations, so different amounts of field pass through them.", "Because flux depends on the window size and tilt, so the same field can give different through-thread scores."], "Use area and tilt language.", ["orientation_irrelevant_flux_confusion"], skill_tags=["flux_compare"], acceptance_rules=acceptance_groups(["same field"], ["different area", "different size", "different window"], ["orientation", "tilt"], ["different flux", "through-thread score"])),
        mcq("A3L1_D10", "If the loop turns edge-on to the field, the through-thread score becomes...", ["very small or zero", "maximum", "equal to field strength only", "equal to RMS"], 0, "Edge-on loops catch almost no perpendicular field.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"]),
    ]
    concept = [
        mcq("A3L1_C1", "A loop of area 0.30 m^2 is face-on in a 0.8 T field. The flux is...", ["0.24 Wb", "1.10 Wb", "0.50 Wb", "2.40 Wb"], 0, "Use Phi = BA.", ["flux_equals_field_only_confusion"], skill_tags=["use_flux_ba"]),
        mcq("A3L1_C2", "If the same loop area stays fixed but the field doubles, the flux...", ["doubles", "halves", "stays the same", "must become negative"], 0, "Flux scales directly with field in the same orientation.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"]),
        mcq("A3L1_C3", "Which statement is strongest?", ["Magnetic flux is field passing through area, so orientation matters.", "Magnetic flux only measures field strength.", "Magnetic flux appears only when current flows.", "Magnetic flux and induced emf are the same thing."], 0, "Use field-through-area language.", ["flux_equals_field_only_confusion", "orientation_irrelevant_flux_confusion"], skill_tags=["flux_meaning"]),
        short("A3L1_C4", "Why does turning the window loop away from face-on reduce the through-thread score?", ["Because less of the field passes perpendicularly through the loop area when the loop is tilted.", "Because tilt reduces the perpendicular component through the loop, so the magnetic flux becomes smaller."], "Use perpendicular-component language.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"], acceptance_rules=acceptance_groups(["tilt", "turning"], ["perpendicular", "component", "through"], ["smaller flux", "less through-thread"])),
        mcq("A3L1_C5", "A face-on loop has flux 0.6 Wb. If the area is tripled while the field stays unchanged, the new flux is...", ["1.8 Wb", "0.2 Wb", "0.9 Wb", "3.0 Wb"], 0, "Tripling area triples flux in the same orientation.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"]),
        mcq("A3L1_C6", "Which orientation gives the largest flux for a fixed area and field strength?", ["field perpendicular to the window area", "field parallel to the window area", "45-degree tilt only", "any orientation gives the same flux"], 0, "Face-on to the field means maximum through-thread score.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"]),
        short("A3L1_C7", "A learner says, 'A tiny loop in a huge field always has more flux than a big loop in a moderate field.' What correction should you make?", ["Flux depends on both field strength and area, so a bigger loop in a moderate field can still have more flux than a tiny loop in a stronger field.", "You must compare field strength, loop area, and orientation together, not field strength alone."], "Restore the full BA or BA cos(theta) idea.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"], acceptance_rules=acceptance_groups(["field strength"], ["area", "window size"], ["orientation", "tilt", "compare together"], ["flux"])),
        mcq("A3L1_C8", "If a loop faces the field directly and then is turned partly away, which quantity definitely changes?", ["magnetic flux", "the loop's number of turns", "the wire's resistance only", "RMS voltage"], 0, "Changing orientation changes flux.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"]),
    ]
    mastery = [
        mcq("A3L1_M1", "A loop of area 0.50 m^2 sits face-on in a 1.2 T field. The flux is...", ["0.60 Wb", "1.70 Wb", "0.42 Wb", "2.40 Wb"], 0, "Phi = BA = 1.2 x 0.50.", ["flux_equals_field_only_confusion"], skill_tags=["use_flux_ba"]),
        mcq("A3L1_M2", "Two face-on loops are in the same 0.4 T field. Loop P has area 0.2 m^2 and loop Q has area 0.6 m^2. Which is correct?", ["Loop Q has three times the flux of loop P.", "Loop P has three times the flux of loop Q.", "Both have equal flux.", "Neither has flux without current."], 0, "Flux scales with area when B is fixed.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"]),
        mcq("A3L1_M3", "A loop with face-on flux 0.9 Wb is tilted so the through-thread score falls. Which statement is strongest?", ["The perpendicular component through the loop became smaller.", "The magnetic field stopped existing.", "Area must have become zero.", "The induced emf must now be constant."], 0, "Tilt changes the effective through-area component.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"]),
        mcq("A3L1_M4", "If both field strength and area are doubled for a face-on loop, the flux...", ["becomes four times as large", "doubles", "halves", "stays the same"], 0, "Both factors multiply together.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"]),
        short("A3L1_M5", "Summarize the through-thread score in one strong sentence.", ["Magnetic flux is the amount of magnetic field passing through a loop area, so it depends on field strength, window size, and orientation.", "The through-thread score measures field through the window, not field strength alone."], "Include field, area, and orientation.", ["flux_equals_field_only_confusion", "orientation_irrelevant_flux_confusion"], skill_tags=["flux_meaning"], acceptance_rules=acceptance_groups(["magnetic flux", "through-thread score"], ["field", "threads"], ["area", "window"], ["orientation", "tilt"], ["not just", "not only"])),
        mcq("A3L1_M6", "A loop in a fixed field is turned from edge-on toward face-on. The flux should...", ["increase", "decrease", "stay zero always", "reverse because of RMS"], 0, "More field passes through the loop area as it faces the field more directly.", ["orientation_irrelevant_flux_confusion"], skill_tags=["tilt_effect"]),
        mcq("A3L1_M7", "A loop in a 0.25 T field has area 0.80 m^2 and is face-on. The flux is...", ["0.20 Wb", "0.55 Wb", "1.05 Wb", "3.20 Wb"], 0, "0.25 x 0.80 = 0.20.", ["flux_equals_field_only_confusion"], skill_tags=["use_flux_ba"]),
        short("A3L1_M8", "Why is 'field-through-window' better language than 'field strength only' when teaching flux?", ["Because flux is about how much field passes through the loop area, so the window size and angle must stay in the story.", "Because field-through-window reminds you to include area and tilt instead of treating flux as just B."], "Contrast field strength with field-through-area.", ["flux_equals_field_only_confusion"], skill_tags=["flux_meaning"], acceptance_rules=acceptance_groups(["field through", "passes through"], ["window", "area", "loop"], ["angle", "tilt", "orientation"], ["not just field strength", "not only B"])),
        mcq("A3L1_M9", "Which change guarantees a larger flux if orientation stays face-on?", ["increasing either field strength or loop area", "making the wire thinner only", "reducing the number of turns only", "switching from AC to DC"], 0, "For one loop, flux grows with B or A in the same orientation.", ["flux_equals_field_only_confusion"], skill_tags=["flux_compare"]),
        mcq("A3L1_M10", "Best lesson summary:", ["Flux is the field-through-window score set by field strength, area, and tilt.", "Flux is just another name for magnetic field strength.", "Flux only matters after induction begins.", "Flux is an AC-only quantity."], 0, "That captures the whole Thread-Window idea for Lesson 1.", ["flux_equals_field_only_confusion", "orientation_irrelevant_flux_confusion"], skill_tags=["flux_meaning"]),
    ]
    return lesson_spec(
        "A3_L1",
        "Catch the Field Threads",
        sim("a3_window_catch_lab", "Window catch lab", "Vary field strength, loop area, and loop tilt so magnetic flux feels like a through-window score instead of a bare symbol.", ["Set a field strength and a loop area.", "Turn the window from face-on to edge-on.", "Compare the through-thread score each time."], ["Explain magnetic flux as field-through-area.", "Compare how strength, size, and tilt affect flux.", "Use the perpendicular-case flux relation confidently."], ["field_strength", "loop_area", "loop_tilt", "flux_value"], "Flux reasoning."),
        diagnostic,
        "The Thread-Window world starts with a simple question: how many field threads pass through the loop window? A stronger field gives more threads, a bigger window catches more threads, and a tilted window catches fewer threads straight through. That full through-window score is magnetic flux.",
        "Commit to the idea that flux is field-through-window, not just field strength with a new name.",
        [prompt_block("What sets the through-thread score besides field strength?", "Window size and tilt matter too."), prompt_block("When is the through-thread score largest?", "When the loop faces the field directly.")],
        [prompt_block("Increase the field strength while keeping the same window.", "The through-thread score should rise."), prompt_block("Tilt the window away from face-on.", "The through-thread score should fall.")],
        ["Why is magnetic flux a through-area idea rather than a field-only idea?", "Why can two loops in the same field still have different flux values?"],
        "Rebuild magnetic flux as a field-through-window score before moving to induction.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain magnetic flux as field passing through loop area.", "Compare the effects of field strength, loop area, and loop tilt on flux.", "Use Phi = BA confidently in the perpendicular case."],
            core_concepts=["Magnetic flux is not just field strength.", "Larger area gives larger flux in the same field and orientation.", "Tilting the loop reduces the perpendicular field through the window.", "Face-on orientation gives the maximum through-thread score."],
            prerequisite_lessons=[],
            misconception_focus=["flux_equals_field_only_confusion", "orientation_irrelevant_flux_confusion"],
            formulas=[relation("Phi = BA", "Flux for a loop facing the field directly.", ["Wb", "T m^2"], "Use when the field is perpendicular to the loop area."), relation("Phi = BA cos(theta)", "General orientation form for flux.", ["Wb"], "Use to explain how tilt changes the perpendicular component.")],
            representations=[representation("words", "Describes flux as a field-through-window score."), representation("diagram", "Shows field threads, a loop window, and changing tilt."), representation("formula", "Links flux to B, A, and orientation."), representation("table", "Compares strong-vs-weak fields and large-vs-small windows.")],
            analogy_map=thread_window_map("the learner compares strong fields, larger windows, and tilted loops"),
            worked_examples=[worked("A face-on loop of area 0.40 m^2 is in a 0.50 T field. Find the flux.", ["Use the face-on relation Phi = BA.", "Multiply 0.50 by 0.40.", "State the answer with the flux unit."], "0.20 Wb", "Face-on flux comes from field times area.", "This is the cleanest entry point into flux calculations."), worked("Two loops are in the same field. Loop A is larger than Loop B. Compare the flux values when both are face-on.", ["Keep the field strength fixed.", "Compare the window areas.", "Larger area means more field threads through the window."], "The larger loop has the larger flux.", "Flux depends on the size of the window as well as the field.", "This protects students from the 'flux = field only' trap.")],
            visual_assets=[visual("a3-l1-flux-window", "electromagnetism_diagram", "Field threads through the window loop", "Show how field strength, window size, and tilt change the through-thread score.", "Flux is the through-thread score: more threads, a larger window, or a more face-on window give a larger value.", template="electromagnetism_diagram", meta={"diagram_type": "flux_window", "loop_tilt_deg": 18})],
            animation_assets=[],
            simulation_contract=sim_contract("a3_l1_window_catch_sim", "flux_window", "Change field strength, area, and tilt until the through-thread score feels like a real physical quantity.", "Start with a medium field, a medium window, and a face-on orientation.", ["Double the loop area and compare the flux.", "Keep the same loop and tilt it away from face-on.", "Compare a stronger field through a small loop with a weaker field through a large loop."], "Watch for the through-thread score changing whenever field strength, area, or tilt changes.", "Flux is best understood as field through area, not as a field-only number.", controls=[("field_strength", "Field strength", "Changes how densely the field threads fill space."), ("loop_area", "Loop area", "Changes the size of the window catching the field."), ("loop_tilt", "Loop tilt", "Changes how directly the field passes through the window.")], readouts=[("Flux", "Shows the current through-thread score."), ("Orientation note", "Shows whether the window is face-on or tilted.")]),
            reflection_prompts=["Explain why magnetic flux depends on more than field strength alone.", "Use the window idea to explain why tilt changes magnetic flux."],
            mastery_skills=["flux_meaning", "flux_compare", "tilt_effect", "use_flux_ba", "orientation_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between field-only confusions, area comparisons, tilt judgments, and small face-on flux calculations.", "concept_gate": "Concept-gate retries alternate between explanation prompts and new Phi = BA values so the same surface stem is less likely to repeat.", "mastery": "Mastery varies lesson-owned field, area, and tilt comparisons while still prioritizing unseen stems first."},
            scaffold_support=scaffold("Flux is the through-thread score.", "Magnetic flux becomes easier when the learner imagines actual field threads passing through a real window rather than memorizing a disconnected symbol.", "What three things set how many field threads pass through the window?", "Treating flux as if it were only the field strength.", "A stronger thread field, a larger window, and a more face-on window all raise the through-thread score because more field passes through the loop.", "Why can the same field give different through-thread scores in two different windows?", extras=[extra_section("Face-on versus tilted", "Maximum flux happens when the loop faces the field directly and the area catches the greatest perpendicular thread flow.", "Why does the score fall when the window turns away?"), extra_section("Through-window language", "Keep saying 'field through area' so the meaning stays physical before the symbol appears.", "What is missing from the phrase 'flux is field strength'?")]),
            visual_clarity_checks=visual_checks("flux-window"),
        ),
    )


def lesson_two() -> Dict[str, Any]:
    diagnostic = [
        mcq("A3L2_D1", "A loop push is induced only when...", ["magnetic flux changes", "there is any magnetic field at all", "the wire is thick", "the circuit has AC only"], 0, "Induction needs changing flux, not merely existing flux.", ["steady_flux_induces_current_confusion"], skill_tags=["induced_emf_from_change"]),
        mcq("A3L2_D2", "Which change can induce an emf in a loop?", ["rotating the loop in a magnetic field", "leaving a fixed loop in a steady unchanged field", "painting the wire", "measuring RMS"], 0, "Changing orientation changes flux.", ["change_source_only_motion_confusion", "steady_flux_induces_current_confusion"], skill_tags=["identify_change_source"]),
        mcq("A3L2_D3", "If the flux in a loop stays perfectly constant, the induced emf is...", ["zero", "maximum", "equal to the field strength", "equal to RMS current"], 0, "No flux change means no induced emf.", ["steady_flux_induces_current_confusion"], skill_tags=["steady_flux_no_induction"]),
        mcq("A3L2_D4", "A faster change of flux usually gives...", ["a larger induced emf", "a smaller induced emf", "exactly the same induced emf", "zero induced emf"], 0, "Induced emf grows with rate of change of flux.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        mcq("A3L2_D5", "Which of these is NOT a way to change flux?", ["leaving field, area, and angle all unchanged", "changing the field strength", "changing the loop area", "changing the loop angle"], 0, "Induction needs one of the flux-setting factors to change.", ["steady_flux_induces_current_confusion"], skill_tags=["identify_change_source"]),
        mcq("A3L2_D6", "If the flux changes by 0.40 Wb in 0.20 s, the average induced emf magnitude is...", ["2.0 V", "0.20 V", "0.80 V", "4.0 V"], 0, "Use magnitude = change in flux / time.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        mcq("A3L2_D7", "Moving a magnet toward a loop can induce emf because it...", ["changes the flux through the loop", "changes the wire color", "creates RMS by itself", "removes the loop area"], 0, "The motion matters because it changes flux.", ["change_source_only_motion_confusion"], skill_tags=["identify_change_source"]),
        short("A3L2_D8", "Why does a stationary magnet inside a stationary loop not keep inducing current forever?", ["Because once the magnetic flux stops changing, the induced emf stops too.", "Because induction needs a changing flux, not just flux being present."], "Use change-in-flux language.", ["steady_flux_induces_current_confusion"], skill_tags=["steady_flux_no_induction"], acceptance_rules=acceptance_groups(["flux", "through-thread score"], ["changing", "change"], ["stops", "no longer"], ["induced emf", "current", "loop push"])),
        short("A3L2_D9", "Why can rotating a loop create an induced emf even if the field strength stays the same?", ["Because rotating the loop changes its orientation and therefore changes the magnetic flux through it.", "Because the tilt changes the through-thread score even in the same field."], "Link rotation to changing orientation and flux.", ["change_source_only_motion_confusion"], skill_tags=["identify_change_source"], acceptance_rules=acceptance_groups(["rotating", "tilt", "orientation"], ["changes flux", "changes through-thread score"], ["same field", "field strength stays the same"])),
        mcq("A3L2_D10", "Which statement is strongest?", ["Induction is a change-caused effect.", "Induction happens whenever magnetic flux exists.", "Induction needs AC but not magnets.", "Induction and flux are the same thing."], 0, "Keep induction tied to change.", ["steady_flux_induces_current_confusion"], skill_tags=["induced_emf_from_change"]),
    ]
    concept = [
        mcq("A3L2_C1", "The flux through a loop changes from 0.10 Wb to 0.50 Wb in 0.20 s. The average induced emf magnitude is...", ["2.0 V", "3.0 V", "0.40 V", "0.08 V"], 0, "0.40 / 0.20 = 2.0.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        mcq("A3L2_C2", "Which change would definitely induce emf in a loop?", ["shrinking the loop area in a steady field", "keeping the loop still in an unchanged field", "using a thicker wire only", "labelling the poles"], 0, "Changing area changes flux.", ["change_source_only_motion_confusion", "steady_flux_induces_current_confusion"], skill_tags=["identify_change_source"]),
        mcq("A3L2_C3", "If the same flux change happens in half the time, the average induced emf magnitude...", ["doubles", "halves", "stays the same", "becomes zero"], 0, "Same change over less time means larger rate.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        short("A3L2_C4", "Why is 'changing flux causes induction' stronger language than 'a magnet causes induction'?", ["Because a magnet only induces emf when it changes the magnetic flux through the loop, not simply because a magnet exists nearby.", "Because the real cause is changing flux, and the magnet is only one possible way to make that change happen."], "Separate the object from the physical cause.", ["change_source_only_motion_confusion", "steady_flux_induces_current_confusion"], skill_tags=["induced_emf_from_change"], acceptance_rules=acceptance_groups(["changing flux", "change in through-thread score"], ["magnet is one way", "not the only way"], ["real cause", "stronger language"])),
        mcq("A3L2_C5", "A loop experiences a flux change of 0.24 Wb in 0.60 s. The average induced emf magnitude is...", ["0.40 V", "0.84 V", "1.44 V", "0.10 V"], 0, "0.24 / 0.60 = 0.40.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        mcq("A3L2_C6", "Which situation gives zero induced emf?", ["unchanged flux in the loop", "rapidly increasing flux", "rapidly decreasing flux", "repeated rotation"], 0, "Only steady unchanged flux gives zero induced emf.", ["steady_flux_induces_current_confusion"], skill_tags=["steady_flux_no_induction"]),
        short("A3L2_C7", "Name two different ways to change magnetic flux through a loop.", ["You can change the field strength and also change the loop orientation or area.", "For example, move the magnet to change field strength, or rotate the loop to change orientation."], "Any two valid flux-changing methods are fine.", ["change_source_only_motion_confusion"], skill_tags=["identify_change_source"], acceptance_rules=acceptance_groups(["field strength", "magnet closer", "magnet farther"], ["area", "size", "orientation", "tilt", "rotation"])),
        mcq("A3L2_C8", "Best summary of induction:", ["A changing through-thread score creates a loop push.", "A magnetic field automatically creates a permanent loop push.", "Induction only depends on resistance.", "Induction is the same as direct current."], 0, "That is the Thread-Window summary.", ["steady_flux_induces_current_confusion"], skill_tags=["induced_emf_from_change"]),
    ]
    mastery = [
        mcq("A3L2_M1", "Flux changes from 0.70 Wb to 0.10 Wb in 0.30 s. The average induced emf magnitude is...", ["2.0 V", "0.60 V", "0.20 V", "2.3 V"], 0, "Magnitude is 0.60 / 0.30 = 2.0.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        mcq("A3L2_M2", "If the flux change is the same but the time taken is three times longer, the average induced emf magnitude...", ["becomes one-third as large", "triples", "stays the same", "becomes zero"], 0, "Longer time for the same change means smaller rate.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        mcq("A3L2_M3", "Which action can induce emf without moving the loop through space?", ["changing the magnetic field strength around it", "keeping everything unchanged", "removing the circuit labels", "using DC instead of AC always"], 0, "Field strength itself can change over time.", ["change_source_only_motion_confusion"], skill_tags=["identify_change_source"]),
        mcq("A3L2_M4", "Which statement is incorrect?", ["A steady unchanged flux keeps inducing the same emf forever.", "Changing the loop angle can change flux.", "Changing flux can induce emf.", "Faster flux change usually gives larger induced emf."], 0, "Steady flux does not keep inducing emf.", ["steady_flux_induces_current_confusion"], skill_tags=["steady_flux_no_induction"]),
        short("A3L2_M5", "Why is a fixed loop in a fixed steady field a no-induction case?", ["Because the magnetic flux through the loop is not changing, so there is no induced emf.", "Because induction needs change in flux, and here the through-thread score stays constant."], "Connect no change to no induction.", ["steady_flux_induces_current_confusion"], skill_tags=["steady_flux_no_induction"], acceptance_rules=acceptance_groups(["flux", "through-thread score"], ["not changing", "constant", "steady"], ["no induced emf", "no loop push"])),
        mcq("A3L2_M6", "A loop's flux changes by 0.15 Wb in 0.05 s. The average induced emf magnitude is...", ["3.0 V", "0.75 V", "7.5 V", "0.10 V"], 0, "0.15 / 0.05 = 3.0.", ["faster_change_same_emf_confusion"], skill_tags=["change_rate_reasoning"]),
        mcq("A3L2_M7", "The strongest causal statement is that induced emf depends on...", ["the rate of flux change", "whether the loop wire is shiny", "field strength alone", "area alone"], 0, "Induction is governed by how fast the flux changes.", ["faster_change_same_emf_confusion"], skill_tags=["induced_emf_from_change"]),
        short("A3L2_M8", "Summarize induction in one sentence using the Thread-Window model.", ["A loop push is induced when the through-thread score changes, and faster change gives a stronger push.", "Changing flux creates induced emf around the loop, while steady flux does not."], "Use change-caused language.", ["steady_flux_induces_current_confusion", "faster_change_same_emf_confusion"], skill_tags=["induced_emf_from_change"], acceptance_rules=acceptance_groups(["changing flux", "through-thread score changes"], ["induced emf", "loop push"], ["faster", "rate", "stronger"])),
        mcq("A3L2_M9", "Which pair both induce emf?", ["rotating the loop and changing the field strength", "leaving the loop still and the field unchanged", "adding insulation and renaming the axes", "measuring RMS and leaving flux fixed"], 0, "Both actions change flux.", ["change_source_only_motion_confusion"], skill_tags=["identify_change_source"]),
        mcq("A3L2_M10", "Best lesson summary:", ["Induction is caused by changing flux, not by steady flux alone.", "Any magnetic field automatically creates a continuous emf.", "Induction and flux are interchangeable words.", "Only moving magnets can ever cause induction."], 0, "That captures the correct induction story.", ["steady_flux_induces_current_confusion", "change_source_only_motion_confusion"], skill_tags=["induced_emf_from_change"]),
    ]
    return lesson_spec(
        "A3_L2",
        "Trigger the Loop Push",
        sim("a3_pulse_trigger_lab", "Pulse trigger lab", "Change flux by moving, rotating, or resizing the window loop and compare the induced loop push.", ["Create one slow flux change.", "Repeat with the same flux change in less time.", "Try a no-change case and compare the readout."], ["Explain why induction needs changing flux.", "Compare fast and slow flux changes quantitatively.", "Name several ways to create induction."], ["delta_flux", "delta_time", "average_emf", "change_source"], "Induction reasoning."),
        diagnostic,
        "Once the through-thread score is understood, induction becomes a change story. A steady score does nothing new. But if the score changes because the field changes, the window rotates, or the area changes, the loop feels a push around its edge. Faster change means a stronger push.",
        "Commit to induction as a change-caused effect rather than a magnet-is-present effect.",
        [prompt_block("What must happen before a loop push appears?", "The through-thread score must change."), prompt_block("What makes a stronger loop push?", "A faster change in the through-thread score.")],
        [prompt_block("Create a small flux change over a long time.", "The induced emf should be small."), prompt_block("Now make the same change in less time.", "The induced emf should be larger.")],
        ["Why does a steady magnetic field not keep inducing current in a steady loop?", "Why is changing flux better language than moving magnet when describing induction?"],
        "Keep induction tied to changing flux before adding turns or direction rules.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain induced emf as a consequence of changing flux.", "Compare different ways of changing flux in a loop.", "Use average induced emf magnitude as change in flux divided by time."],
            core_concepts=["Steady unchanged flux gives no induced emf.", "Changing field strength, area, or orientation can induce emf.", "Faster flux change gives larger induced emf magnitude.", "The field itself is not enough; change is the cause."],
            prerequisite_lessons=["A3_L1"],
            misconception_focus=["steady_flux_induces_current_confusion", "change_source_only_motion_confusion", "faster_change_same_emf_confusion"],
            formulas=[relation("|E| = DeltaPhi / Delta t", "Average induced emf magnitude for one loop.", ["V"], "Use magnitude form before the direction rule is introduced.")],
            representations=[representation("words", "Describes induction as a change-caused loop push."), representation("diagram", "Shows before-and-after thread counts through the loop."), representation("formula", "Connects emf magnitude to flux change over time."), representation("table", "Contrasts steady-flux and changing-flux cases.")],
            analogy_map=thread_window_map("the learner compares slow and fast changes of the through-thread score"),
            worked_examples=[worked("A loop's flux changes by 0.40 Wb in 0.20 s. Find the average induced emf magnitude.", ["Use average emf magnitude = change in flux / time.", "Compute 0.40 / 0.20.", "State the answer in volts."], "2.0 V", "Induction strength depends on how quickly flux changes.", "This is the core induction calculation."), worked("A magnet sits still inside a fixed loop after being moved in. Explain the detector reading.", ["Notice that the flux stops changing once the magnet and loop stop moving relative to one another.", "No further change means no further induced emf.", "Separate presence from change."], "The induced emf drops to zero.", "Steady flux does not keep producing induction.", "This protects against the most common induction myth.")],
            visual_assets=[visual("a3-l2-induction-pulse", "electromagnetism_diagram", "Changing flux triggers the loop push", "Show before-and-after thread counts with a loop and the induced pulse caused by the change.", "Only a changing through-thread score creates a loop push, and the faster change creates the stronger effect.", template="electromagnetism_diagram", meta={"diagram_type": "induction_pulse", "change_direction": "increase"})],
            animation_assets=[],
            simulation_contract=sim_contract("a3_l2_pulse_trigger_sim", "induction_pulse", "Make the through-thread score change slowly, quickly, or not at all, then compare the loop push each time.", "Start with a moderate increase in flux over 1 second.", ["Repeat the same flux change in half the time.", "Keep the flux steady and compare the zero-emf case.", "Change the source of the flux change by rotating the loop instead of changing the field."], "Watch for the loop push appearing only during change and growing when the rate of change grows.", "Induction is about change in flux, not about the magnetic field merely being present.", controls=[("delta_flux", "Flux change", "Sets how much the through-thread score changes."), ("delta_time", "Change time", "Sets how quickly the flux change happens."), ("change_source", "Change source", "Switches between field, area, and orientation changes.")], readouts=[("Average emf", "Shows the size of the induced loop push."), ("Change status", "Shows whether flux is rising, falling, or steady.")]),
            reflection_prompts=["Explain why changing flux is stronger language than moving magnet for induction.", "Describe what happens to induced emf when the same flux change happens in less time."],
            mastery_skills=["induced_emf_from_change", "identify_change_source", "change_rate_reasoning", "steady_flux_no_induction", "emf_size_compare"],
            variation_plan={"diagnostic": "Fresh attempts rotate between no-change cases, change-source identification, and quick change-over-time calculations.", "concept_gate": "Concept-gate retries swap in new flux and time values plus new wording about what actually causes induction.", "mastery": "Mastery varies lesson-owned rate-of-change calculations and explanation stems while prioritizing unseen items."},
            scaffold_support=scaffold("Only changing flux creates the loop push.", "Induction becomes much cleaner when learners track the through-thread score first and then ask whether that score is changing over time.", "What must change before an induced emf appears?", "Thinking a magnetic field automatically causes a permanent induced current.", "A steady thread field through a steady window does not keep creating a push. The push appears only while the through-thread score is changing.", "Why is a still magnet in a still loop a no-induction case?", extras=[extra_section("Many change routes", "Flux can change because field strength changes, area changes, or the window tilts.", "Which of those changes is happening in your example?"), extra_section("Rate matters", "The same flux change in less time gives a larger induced emf because the change rate is bigger.", "What happens to the emf if the time doubles?")]),
            visual_clarity_checks=visual_checks("induction-pulse"),
        ),
    )


def lesson_three() -> Dict[str, Any]:
    diagnostic = [
        mcq("A3L3_D1", "Flux linkage means...", ["total linked flux for all turns of the coil", "flux through one turn only no matter what", "the same thing as resistance", "the peak of an AC waveform"], 0, "Flux linkage is the total thread-link score for many turns.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        mcq("A3L3_D2", "If a coil has more turns and each turn experiences the same flux change, the induced emf usually...", ["gets larger", "gets smaller", "stays the same", "must become DC"], 0, "More turns mean more total linkage change.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"]),
        mcq("A3L3_D3", "A 10-turn coil with 0.20 Wb through each turn has flux linkage...", ["2.0 Wb-turn", "0.20 Wb-turn", "10.2 Wb-turn", "20 Wb-turn"], 0, "Use NPhi = 10 x 0.20.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        mcq("A3L3_D4", "Which statement is strongest?", ["Flux linkage multiplies flux per turn by the number of turns.", "Flux linkage ignores the number of turns.", "More turns always reduce induction.", "Flux linkage is the same as current."], 0, "Total linkage grows with turns.", ["flux_linkage_equals_flux_confusion", "turns_do_not_matter_confusion"], skill_tags=["flux_linkage"]),
        mcq("A3L3_D5", "If the same flux change happens in one loop and then in a 20-turn coil, the 20-turn coil has...", ["larger induced emf magnitude", "the same induced emf magnitude", "zero induced emf", "only DC"], 0, "More turns amplify the total linkage change.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"]),
        mcq("A3L3_D6", "A coil's flux linkage changes by 3.0 Wb-turn in 0.50 s. The average induced emf magnitude is...", ["6.0 V", "1.5 V", "3.5 V", "0.6 V"], 0, "Use change in linkage over time.", ["turns_do_not_matter_confusion"], skill_tags=["use_faraday_average"]),
        mcq("A3L3_D7", "A single-turn loop and a 12-turn coil experience the same flux per turn. Which has larger flux linkage?", ["the 12-turn coil", "the single-turn loop", "they are equal", "neither has linkage"], 0, "More turns mean more total linkage.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        short("A3L3_D8", "Why is flux linkage not the same as flux through one turn?", ["Because flux linkage counts the total linked flux across all the turns, not just one turn.", "Because the thread-link total multiplies flux per turn by the number of turns in the coil."], "Mention all turns, not one turn.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"], acceptance_rules=acceptance_groups(["all turns", "number of turns", "coil"], ["flux per turn", "one turn"], ["total", "multiply", "linkage"])),
        short("A3L3_D9", "Why can adding turns make the induced emf larger even if the flux per turn stays the same?", ["Because each turn experiences the flux change, so the total flux linkage changes by a larger amount.", "Because more linked windows give a bigger total thread-link change and therefore a larger induced emf."], "Use linkage-change language.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"], acceptance_rules=acceptance_groups(["more turns", "coil"], ["larger flux linkage", "bigger total change"], ["larger induced emf", "stronger loop push"])),
        mcq("A3L3_D10", "Which quantity belongs directly in Faraday's law for a many-turn coil?", ["NPhi", "only B", "only A", "only current"], 0, "The law is about change of flux linkage.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
    ]
    concept = [
        mcq("A3L3_C1", "A 15-turn coil has 0.08 Wb through each turn. The flux linkage is...", ["1.2 Wb-turn", "0.08 Wb-turn", "15.08 Wb-turn", "7.5 Wb-turn"], 0, "15 x 0.08 = 1.2.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        mcq("A3L3_C2", "Flux linkage changes from 4.0 Wb-turn to 1.0 Wb-turn in 0.50 s. The average induced emf magnitude is...", ["6.0 V", "2.0 V", "1.5 V", "8.0 V"], 0, "3.0 / 0.50 = 6.0.", ["turns_do_not_matter_confusion"], skill_tags=["use_faraday_average"]),
        mcq("A3L3_C3", "If the number of turns doubles while the same flux per turn and the same rate of change are maintained, the induced emf magnitude...", ["doubles", "halves", "stays the same", "becomes zero"], 0, "More turns double the linkage change.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"]),
        short("A3L3_C4", "Why does Faraday's law use change in flux linkage for a coil instead of flux through one turn only?", ["Because the coil has many turns and the total induced effect depends on the total linkage change across all of them.", "Because each turn contributes to the total thread-link change, so NPhi is the right quantity for the whole coil."], "Use total-for-all-turns language.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"], acceptance_rules=acceptance_groups(["coil", "many turns"], ["total", "all turns"], ["flux linkage", "NPhi"], ["induced effect", "emf"])),
        mcq("A3L3_C5", "A coil has 20 turns and flux per turn 0.05 Wb. The flux linkage is...", ["1.0 Wb-turn", "0.25 Wb-turn", "4.0 Wb-turn", "20 Wb-turn"], 0, "20 x 0.05 = 1.0.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        mcq("A3L3_C6", "A coil's linkage change is the same in two experiments, but one change happens faster. Which gives the larger emf magnitude?", ["the faster change", "the slower change", "they are the same", "the one with fewer turns automatically"], 0, "Rate of linkage change matters.", ["faster_change_same_emf_confusion"], skill_tags=["linkage_rate_reasoning"]),
        short("A3L3_C7", "A learner says, 'Turns only matter because there is more wire, not because of flux linkage.' What correction should you make?", ["Turns matter because each turn links the flux, so the total flux linkage and its rate of change increase.", "The key reason is more linked turns, not just more wire length."], "Restore linkage language rather than wire-only language.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"], acceptance_rules=acceptance_groups(["turns", "each turn"], ["flux linkage", "linked flux", "NPhi"], ["not just wire", "total change"])),
        mcq("A3L3_C8", "Best summary of Lesson 3:", ["More linked windows give a larger total thread-link change and a larger induced effect.", "Turns do not matter if the field is magnetic.", "Flux linkage and flux are always identical.", "Faraday's law ignores time."], 0, "That captures linkage clearly.", ["flux_linkage_equals_flux_confusion", "turns_do_not_matter_confusion"], skill_tags=["flux_linkage"]),
    ]
    mastery = [
        mcq("A3L3_M1", "A 40-turn coil has flux per turn 0.03 Wb. The flux linkage is...", ["1.2 Wb-turn", "0.03 Wb-turn", "43 Wb-turn", "0.75 Wb-turn"], 0, "40 x 0.03 = 1.2.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        mcq("A3L3_M2", "Flux linkage changes by 2.4 Wb-turn in 0.20 s. The average induced emf magnitude is...", ["12 V", "0.48 V", "2.2 V", "4.8 V"], 0, "2.4 / 0.20 = 12.", ["turns_do_not_matter_confusion"], skill_tags=["use_faraday_average"]),
        mcq("A3L3_M3", "If the number of turns is tripled while the same flux change per turn and time are preserved, the induced emf magnitude...", ["triples", "halves", "stays the same", "becomes AC automatically"], 0, "Tripling turns triples the linkage change.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"]),
        mcq("A3L3_M4", "A 12-turn coil has 0.15 Wb-turn flux linkage. The flux per turn is...", ["0.0125 Wb", "1.8 Wb", "0.15 Wb", "12.15 Wb"], 0, "Divide linkage by turns: 0.15 / 12.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        short("A3L3_M5", "Why is it useful to think of a coil as many linked windows rather than one window?", ["Because each turn links the changing flux, so the total thread-link score and induced effect grow with the number of turns.", "Because the many-window picture makes flux linkage and Faraday's law physically meaningful."], "Use many-linked-windows language.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"], acceptance_rules=acceptance_groups(["many turns", "many windows"], ["linked flux", "flux linkage", "thread-link"], ["larger emf", "induced effect"])),
        mcq("A3L3_M6", "A coil changes from 0.50 Wb-turn linkage to 2.00 Wb-turn linkage in 0.75 s. The average induced emf magnitude is...", ["2.0 V", "1.5 V", "3.0 V", "2.5 V"], 0, "1.50 / 0.75 = 2.0.", ["turns_do_not_matter_confusion"], skill_tags=["use_faraday_average"]),
        mcq("A3L3_M7", "Which statement about flux and flux linkage is correct?", ["Flux is per loop window; flux linkage totals that over all turns.", "Flux linkage ignores the number of turns.", "Flux is always larger than flux linkage.", "They are unrelated topics."], 0, "Per-turn flux and total linkage are different but connected.", ["flux_linkage_equals_flux_confusion"], skill_tags=["flux_linkage"]),
        short("A3L3_M8", "Summarize Faraday's many-turn idea in one sentence.", ["A coil's induced emf depends on how quickly its total flux linkage changes, so more turns can give a stronger induced effect.", "Faraday's law for a coil is about the rate of change of NPhi, not just one-turn flux."], "Mention total linkage and rate.", ["flux_linkage_equals_flux_confusion", "turns_do_not_matter_confusion"], skill_tags=["use_faraday_average"], acceptance_rules=acceptance_groups(["rate of change", "changes quickly"], ["flux linkage", "NPhi", "total linked flux"], ["more turns", "coil"], ["induced emf", "induced effect"])),
        mcq("A3L3_M9", "If the flux per turn and change time are both unchanged, which coil gives the larger induced emf magnitude?", ["the coil with more turns", "the coil with fewer turns", "both the same always", "neither"], 0, "More turns means more linkage change.", ["turns_do_not_matter_confusion"], skill_tags=["turns_effect"]),
        mcq("A3L3_M10", "Best lesson summary:", ["Flux linkage is the total thread-link score, and Faraday's law tracks how quickly that total changes.", "Turns only matter because the coil is heavier.", "Flux linkage is the same as resistance.", "Faraday's law needs peak current only."], 0, "That is the clean Thread-Window summary.", ["flux_linkage_equals_flux_confusion", "turns_do_not_matter_confusion"], skill_tags=["flux_linkage"]),
    ]
    return lesson_spec(
        "A3_L3",
        "Link the Turns",
        sim("a3_flux_linkage_lab", "Flux linkage lab", "Compare single loops and coils with many turns so linkage and Faraday's law stop feeling like separate topics.", ["Set the same flux per turn in different coils.", "Increase the number of turns and compare linkage.", "Keep the same linkage change but vary the time."], ["Calculate flux linkage and average induced emf.", "Explain why more turns increase the effect.", "Separate per-turn flux from total linkage."], ["turn_count", "flux_per_turn", "flux_linkage", "average_emf"], "Flux-linkage reasoning."),
        diagnostic,
        "One window gives one through-thread score. A coil gives many linked windows, so the total thread-link score is larger. Faraday's law becomes the law of how quickly that total linkage changes. That is why turn count matters so much in generators and coils.",
        "Commit to the idea that a coil is many linked windows, not just one loop with extra wire.",
        [prompt_block("What does NPhi count that Phi alone does not?", "It counts the total linked flux over all turns."), prompt_block("Why do more turns strengthen the induced effect?", "Because the total linkage changes more.")],
        [prompt_block("Compare a 1-turn loop and a 10-turn coil with the same flux per turn.", "The 10-turn coil should have ten times the linkage."), prompt_block("Keep the linkage change the same but change the time taken.", "The faster change gives the larger emf.")],
        ["Why is flux linkage the natural quantity for a coil?", "Why can adding turns increase emf even if the field itself is not stronger?"],
        "Link Faraday's law to many-turn coils before moving to the opposition rule.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain flux linkage as the total linked flux across all turns.", "Use average emf magnitude as change in flux linkage divided by time.", "Explain why more turns strengthen induction."],
            core_concepts=["Flux linkage is not the same as flux through one turn.", "More turns multiply the total linked flux.", "The induced effect depends on the rate of change of flux linkage.", "Turn count matters because each turn links the field change."],
            prerequisite_lessons=["A3_L1", "A3_L2"],
            misconception_focus=["flux_linkage_equals_flux_confusion", "turns_do_not_matter_confusion", "faster_change_same_emf_confusion"],
            formulas=[relation("Flux linkage = NPhi", "Total linked flux for a coil of N turns.", ["Wb-turn"], "Use when the same flux passes each turn."), relation("|E| = Delta(NPhi) / Delta t", "Average induced emf magnitude for a coil.", ["V"], "Use when flux linkage changes over a measured time.")],
            representations=[representation("words", "Describes a coil as many linked windows."), representation("diagram", "Shows turns sharing the same changing field."), representation("formula", "Connects NPhi and average induced emf."), representation("table", "Compares one turn with many turns.")],
            analogy_map=thread_window_map("the learner compares one linked window with many linked windows in the same field"),
            worked_examples=[worked("A 10-turn coil has 0.20 Wb through each turn. Find the flux linkage.", ["Use linkage = NPhi.", "Multiply 10 by 0.20.", "State the total linked flux."], "2.0 Wb-turn", "Linkage totals the same per-turn flux over all turns.", "This is the essential NPhi calculation."), worked("A coil's linkage changes by 3.0 Wb-turn in 0.50 s. Find the average induced emf magnitude.", ["Use average emf magnitude = change in linkage / time.", "Compute 3.0 / 0.50.", "State the answer in volts."], "6.0 V", "Faraday's law is a rate-of-linkage-change law.", "This connects linkage directly to induction.")],
            visual_assets=[visual("a3-l3-flux-linkage", "electromagnetism_diagram", "Many linked windows strengthen the effect", "Show a multi-turn coil sharing the same field so total linkage becomes visible.", "More linked turns mean a larger total thread-link change and therefore a larger induced effect.", template="electromagnetism_diagram", meta={"diagram_type": "flux_linkage_coil", "turn_count": 5})],
            animation_assets=[],
            simulation_contract=sim_contract("a3_l3_flux_linkage_sim", "flux_linkage_coil", "Change the number of turns and watch how the total thread-link score and induced effect respond.", "Start with a moderate flux per turn and a 5-turn coil.", ["Compare a 1-turn loop and a 10-turn coil at the same flux per turn.", "Keep the same coil and change the rate of linkage change.", "Find settings that double linkage without changing flux per turn."], "Watch for flux per turn staying the same while total linkage still grows with turn count.", "Faraday's law for a coil is about how quickly NPhi changes, not just about one turn in isolation.", controls=[("turn_count", "Turn count", "Sets how many linked windows the coil contains."), ("flux_per_turn", "Flux per turn", "Sets the through-thread score for each turn."), ("change_time", "Change time", "Sets how rapidly the total linkage changes.")], readouts=[("Flux linkage", "Shows the total thread-link score NPhi."), ("Average emf", "Shows the induced effect from the linkage change.")]),
            reflection_prompts=["Explain why flux linkage is the natural quantity for a coil rather than one-turn flux only.", "Describe why more turns increase the induced effect even without strengthening the field itself."],
            mastery_skills=["flux_linkage", "turns_effect", "use_faraday_average", "linkage_rate_reasoning", "coil_scaling_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between NPhi calculations, more-turns comparisons, and explanations of why linkage is a total.", "concept_gate": "Concept-gate retries alternate between new linkage values, rate comparisons, and wording checks about many linked windows.", "mastery": "Mastery varies lesson-owned linkage and emf calculations with new turn counts and time intervals before any repeats."},
            scaffold_support=scaffold("A coil is many linked windows.", "Flux linkage becomes intuitive when the learner imagines each extra turn as one more window catching the same field change.", "What does multiplying by N physically mean in the Thread-Window story?", "Thinking that more turns matter only because the wire is longer.", "Each turn is another window catching the field threads, so the total thread-link score grows with turn count and so does the induced effect when that score changes.", "Why is the many-window picture better than a one-window picture for a coil?", extras=[extra_section("Per turn versus total", "Keep flux per turn separate from total linkage so students can see what is being multiplied.", "Which quantity belongs to one turn and which belongs to the whole coil?"), extra_section("Faraday as rate law", "The key comparison is how quickly NPhi changes, not just the size of NPhi itself.", "What happens if the same linkage change takes twice as long?")]),
            visual_clarity_checks=visual_checks("flux-linkage"),
        ),
    )


def lesson_four() -> Dict[str, Any]:
    diagnostic = [
        mcq("A3L4_D1", "Lenz's law says the induced effect opposes...", ["the change in flux", "the magnetic field itself no matter what", "the wire only", "the RMS value"], 0, "The opposition is to the change, not to the existence of the field.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"]),
        mcq("A3L4_D2", "If flux through a loop is increasing inward, the induced effect should act to...", ["oppose that increase", "help the increase happen faster", "ignore the change", "remove all magnetic field everywhere"], 0, "The induced response resists the change that caused it.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"]),
        mcq("A3L4_D3", "If the flux change reverses direction, the induced response...", ["reverses too", "must stay the same", "disappears forever", "becomes RMS"], 0, "Opposing the change means responding to the sign of the change.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"]),
        mcq("A3L4_D4", "Which statement is strongest?", ["Lenz's law explains the minus sign as opposition to the flux change.", "Lenz's law means induced current destroys magnetic fields.", "Lenz's law means induction stops energy transfer.", "Lenz's law only matters for AC."], 0, "Opposition-to-change is the key meaning.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"]),
        mcq("A3L4_D5", "A loop is moved so the outward flux through it is decreasing. The induced effect should try to...", ["support outward flux to oppose the decrease", "increase inward flux because inward is always correct", "do nothing because flux exists", "reverse RMS"], 0, "Opposition means resisting the decrease.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"]),
        mcq("A3L4_D6", "Why is there a minus sign in Faraday's law?", ["to show the induced effect opposes the change in flux linkage", "to make the emf smaller than current", "to say flux is always negative", "to convert AC to DC"], 0, "The sign is a direction rule, not a size rule.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"]),
        mcq("A3L4_D7", "Which description matches a correct Lenz reasoning step?", ["First identify whether the flux is increasing or decreasing, then decide what opposes that change.", "First name the wire color, then choose any current direction.", "First find RMS, then guess the field direction.", "Oppose the field without checking the change."], 0, "Read the change first, then oppose it.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["oppose_change_diagnosis"]),
        short("A3L4_D8", "Why is 'opposes the change' stronger language than 'opposes the field'?", ["Because the induced effect resists the increase or decrease in flux, not the mere presence of flux itself.", "Because a steady magnetic field can exist without induction, so Lenz's law must be about the change rather than the field alone."], "Use change-versus-existence language.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"], acceptance_rules=acceptance_groups(["opposes", "resists"], ["change", "increase", "decrease"], ["not just field", "not mere field", "not existence"])),
        short("A3L4_D9", "If the change in flux reverses, why should the induced direction also reverse?", ["Because the induced effect always opposes the actual change, so reversing the change reverses what is needed to oppose it.", "Because the opposition rule follows the sign of the flux change."], "Link direction to the sign of the change.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"], acceptance_rules=acceptance_groups(["reverse", "reverses"], ["change in flux", "change"], ["oppose", "opposition", "needed response"])),
        mcq("A3L4_D10", "Best first question in a Lenz problem:", ["Is the flux increasing or decreasing?", "What is the RMS value?", "What is the resistance of the wire?", "Which direction looks nicer?"], 0, "Start by diagnosing the change.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["oppose_change_diagnosis"]),
    ]
    concept = [
        mcq("A3L4_C1", "Outward flux through a loop is increasing. The induced effect must try to create...", ["an inward effect that opposes the increase", "more outward effect to help it", "no magnetic effect at all", "RMS only"], 0, "Oppose the increase.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"]),
        mcq("A3L4_C2", "Inward flux through a loop is decreasing. The induced effect must try to create...", ["more inward effect to oppose the decrease", "outward effect to help the decrease", "no effect because there is already flux", "only DC"], 0, "Oppose the decrease by supporting the lost direction.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"]),
        mcq("A3L4_C3", "If the same size of flux change happens faster, the induced emf magnitude...", ["gets larger even though the opposition idea stays the same", "gets smaller because Lenz stops it", "stays the same always", "becomes AC automatically"], 0, "Magnitude still follows rate; Lenz sets direction.", ["faster_change_same_emf_confusion", "lenz_opposes_field_not_change_confusion"], skill_tags=["energy_source_reasoning"]),
        short("A3L4_C4", "Why does Lenz's law help conserve energy in induction rather than allowing free energy?", ["Because the induced effect opposes the change, so work must be done to keep changing the flux and creating emf.", "Because the opposition rule means you have to supply energy to overcome the induced response."], "Connect opposition to required work or energy input.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["energy_source_reasoning"], acceptance_rules=acceptance_groups(["oppose", "resist"], ["work", "energy input", "supply energy"], ["change in flux", "changing field"])),
        mcq("A3L4_C5", "Which statement about the minus sign in Faraday's law is correct?", ["It encodes the Lenz opposition rule.", "It means the emf is always numerically negative.", "It converts flux into RMS.", "It only applies to DC."], 0, "The minus sign is a direction statement.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"]),
        mcq("A3L4_C6", "If a learner opposes the field without checking whether the flux is increasing or decreasing, the reasoning is...", ["incomplete and often wrong", "always correct", "good enough for AC", "equivalent to RMS"], 0, "You must oppose the change, not the field blindly.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["oppose_change_diagnosis"]),
        short("A3L4_C7", "Give a strong one-line method for solving a Lenz direction question.", ["First decide whether flux is increasing or decreasing, then choose the induced direction that opposes that change.", "Read the sign of the flux change first and make the induced response resist it."], "State a clear two-step method.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["oppose_change_diagnosis"], acceptance_rules=acceptance_groups(["first", "start"], ["increasing or decreasing", "sign of change"], ["oppose", "resist"], ["induced direction", "response"])),
        mcq("A3L4_C8", "Best lesson summary:", ["Lenz's law tells you which induced direction resists the change in flux.", "Lenz's law says induction removes all fields.", "Lenz's law means current and emf are always negative.", "Lenz's law is only a graph rule."], 0, "That is the core direction rule.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"]),
    ]
    mastery = [
        mcq("A3L4_M1", "Outward flux through a loop is decreasing because the magnet is moving away. The induced response should try to create...", ["outward effect to oppose the decrease", "inward effect to help the decrease", "no effect because the magnet is leaving", "RMS only"], 0, "Oppose the decrease in outward flux.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"]),
        mcq("A3L4_M2", "Inward flux is increasing rapidly. Which statement is strongest?", ["The induced effect must oppose that increase, and its magnitude is larger if the change is faster.", "Lenz's law makes the induced emf zero.", "A faster change gives smaller emf because opposition cancels it.", "The induced response ignores rate."], 0, "Direction comes from Lenz; size still comes from rate.", ["lenz_opposes_field_not_change_confusion", "faster_change_same_emf_confusion"], skill_tags=["energy_source_reasoning"]),
        mcq("A3L4_M3", "A correct Lenz explanation must mention...", ["what change in flux is happening", "only the final current direction", "only the field source name", "the RMS of the circuit"], 0, "The key is the change being opposed.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["oppose_change_diagnosis"]),
        mcq("A3L4_M4", "If the flux change reverses from increasing outward to decreasing outward, the induced response should...", ["reverse", "stay the same", "become zero forever", "switch to DC"], 0, "The opposition tracks the sign of the change.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["direction_from_change"]),
        short("A3L4_M5", "Why does Lenz's law stop induction from becoming a free-energy machine?", ["Because the induced response resists the change, so an external agent must do work to keep changing the flux.", "Because the opposition rule means energy has to be supplied to overcome the induced effect."], "Use resist-change and do-work language.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["energy_source_reasoning"], acceptance_rules=acceptance_groups(["resist", "oppose"], ["change in flux", "change"], ["work", "energy input", "external agent"])),
        mcq("A3L4_M6", "Which diagnosis is correct for the statement 'The induced current opposes the magnetic field'?", ["It is incomplete; the induced current opposes the change in flux, not the field in a blanket way.", "It is always fully correct.", "It only fails for AC.", "It only applies when RMS is used."], 0, "Opposition is to change, not existence.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"]),
        mcq("A3L4_M7", "If the same change in linkage happens in less time, the induced emf magnitude...", ["increases", "decreases", "stays fixed because of Lenz", "must reverse sign"], 0, "Lenz sets direction; rate sets magnitude.", ["faster_change_same_emf_confusion"], skill_tags=["energy_source_reasoning"]),
        short("A3L4_M8", "Summarize the oppose-turn rule in one sentence.", ["The induced effect always acts in the direction that resists the change in flux that produced it.", "Lenz's law says the induced response opposes the changing flux, not the field in a blanket way."], "Keep the word change visible.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"], acceptance_rules=acceptance_groups(["induced effect", "induced response"], ["oppose", "resist"], ["change in flux", "changing flux"], ["not just field", "the produced change"])),
        mcq("A3L4_M9", "Best first move in a new Lenz question:", ["Identify the direction of the flux change before deciding the induced response.", "Calculate RMS first.", "Ignore whether flux is rising or falling.", "Oppose the field automatically."], 0, "Always diagnose the change first.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["oppose_change_diagnosis"]),
        mcq("A3L4_M10", "Best lesson summary:", ["Lenz's law gives the induced direction by opposing the flux change and helps explain where the required energy comes from.", "Lenz's law removes magnetic fields completely.", "Lenz's law means induced emf is always numerically negative.", "Lenz's law and Faraday's law are unrelated."], 0, "That captures direction plus energy meaning.", ["lenz_opposes_field_not_change_confusion"], skill_tags=["lenz_opposes_change"]),
    ]
    return lesson_spec(
        "A3_L4",
        "Use the Oppose-Turn Rule",
        sim("a3_oppose_turn_lab", "Oppose-turn lab", "Track increasing and decreasing flux cases so induced direction feels like a response to change rather than a memorized sign rule.", ["Choose whether the flux is increasing or decreasing.", "Predict the induced response.", "Reverse the change and compare the new direction."], ["Use Lenz's law to choose direction.", "Explain why reversing the change reverses the response.", "Connect the opposition rule to energy transfer."], ["flux_direction", "flux_change", "induced_direction", "energy_note"], "Lenz reasoning."),
        diagnostic,
        "The Thread-Window story now gains its direction rule. The loop push does not help the change that produced it. It resists that change. If the through-thread score is rising, the induced response acts to reduce that rise. If the score is falling, the induced response acts to support what is being lost. That is Lenz's law.",
        "Commit to opposing the change itself, not the magnetic field as a vague object.",
        [prompt_block("What must you identify first in a Lenz problem?", "Whether the flux is increasing or decreasing."), prompt_block("What does the induced response try to do?", "Resist that change.")],
        [prompt_block("Set a case with increasing flux.", "Predict a response that resists the increase."), prompt_block("Reverse the change.", "The induced response should reverse too.")],
        ["Why is 'opposes the change' stronger than 'opposes the field'?", "Why does the induced response reverse when the change reverses?"],
        "Use change-first reasoning so the minus sign in Faraday's law becomes meaningful instead of decorative.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain Lenz's law as opposition to the change in flux.", "Predict how induced response changes when the flux change reverses.", "Explain why the opposition rule protects energy conservation."],
            core_concepts=["The induced effect opposes the change in flux, not the field in a blanket way.", "Reversing the change reverses the induced response.", "Faraday's minus sign is a direction rule.", "Opposition to change explains why external work is needed to keep induction going."],
            prerequisite_lessons=["A3_L2", "A3_L3"],
            misconception_focus=["lenz_opposes_field_not_change_confusion", "faster_change_same_emf_confusion"],
            formulas=[relation("E = - d(NPhi) / dt", "Faraday-Lenz law in sign form.", ["V"], "The minus sign expresses opposition to the change in flux linkage.")],
            representations=[representation("words", "Describes the induced effect as a resist-the-change response."), representation("diagram", "Shows rising or falling flux and the induced opposition."), representation("formula", "Uses the minus sign in Faraday's law as a direction rule."), representation("equation_story", "Tracks change -> induced response -> energy requirement.")],
            analogy_map=thread_window_map("the learner predicts which way the induced response must act when the through-thread score rises or falls"),
            worked_examples=[worked("Outward flux through a loop is decreasing. What should the induced response try to do?", ["Identify the change: outward flux is being lost.", "Apply Lenz's law: oppose the decrease.", "So the induced response must try to support outward flux."], "Support outward flux", "The response resists the loss, not the field in the abstract.", "This is the cleanest Lenz pattern."), worked("Explain the minus sign in Faraday's law without using algebra only.", ["Say that induction is triggered by change.", "Then say the induced effect resists that change.", "Tie the minus sign to that opposition rule."], "The minus sign encodes Lenz's law", "Sign is about direction and cause, not just symbol style.", "This turns the formal law back into physics.")],
            visual_assets=[visual("a3-l4-lenz-opposition", "electromagnetism_diagram", "Oppose-turn rule for changing flux", "Show a changing thread pattern through a loop and the induced response that resists the change.", "Lenz's law says the induced effect opposes the increase or decrease in the through-thread score that produced it.", template="electromagnetism_diagram", meta={"diagram_type": "lenz_opposition", "change_direction": "increase"})],
            animation_assets=[],
            simulation_contract=sim_contract("a3_l4_oppose_turn_sim", "lenz_opposition", "Set a flux change, then decide which induced response would resist it and why.", "Start with an increasing flux case and predict the opposing response.", ["Reverse the change and compare how the induced response reverses.", "Compare a fast change and a slow change so direction and size do not get mixed up.", "Explain the energy story behind the opposition rule."], "Watch for the difference between opposing a change and opposing a field blindly.", "Lenz's law is the direction rule that keeps induction physically honest and energy-aware.", controls=[("flux_change_sign", "Flux change sign", "Sets whether the through-thread score is rising or falling."), ("flux_change_rate", "Change rate", "Separates the size of the response from its direction rule."), ("field_direction", "Reference field direction", "Keeps the story tied to an explicit field orientation.")], readouts=[("Change diagnosis", "Shows whether flux is increasing or decreasing."), ("Induced response", "Shows the direction that opposes the change.")]),
            reflection_prompts=["Explain why Lenz's law opposes the change in flux rather than the field in a blanket way.", "Describe how the opposition rule helps explain where the energy in induction comes from."],
            mastery_skills=["lenz_opposes_change", "direction_from_change", "energy_source_reasoning", "oppose_change_diagnosis", "faraday_sign_meaning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between increasing-flux and decreasing-flux cases plus wording checks about what is actually opposed.", "concept_gate": "Concept-gate retries alternate between sign-of-change judgments and short explanations of the minus sign and energy meaning.", "mastery": "Mastery varies lesson-owned direction cases and energy prompts while preferring unseen items first."},
            scaffold_support=scaffold("The induced response resists the change.", "Lenz's law becomes much easier when learners first name the change and only then choose the induced direction that would resist it.", "What is changing in your loop before you talk about induced direction?", "Opposing the field itself without checking whether the flux is increasing or decreasing.", "The loop responds like a system trying to resist being forced away from its current state: rise is resisted by a response against the rise, and loss is resisted by a response against the loss.", "Why must a reversed change produce a reversed induced response?", extras=[extra_section("Change-first method", "Solve Lenz questions in two steps: diagnose the sign of the flux change, then choose the induced response that resists that sign.", "Which step comes first and why?"), extra_section("Energy link", "Because the induced response resists the change, work must be done to keep changing the flux and maintain the induced effect.", "How does opposition to change stop free energy?")]),
            visual_clarity_checks=visual_checks("lenz-opposition"),
        ),
    )


def lesson_five() -> Dict[str, Any]:
    diagnostic = [
        mcq("A3L5_D1", "One-way drive is the Thread-Window name for...", ["direct current", "alternating current", "RMS current", "flux linkage"], 0, "One-way drive means current stays in one direction.", ["dc_vs_ac_size_only_confusion"], skill_tags=["dc_ac_distinction"]),
        mcq("A3L5_D2", "Swing drive is the Thread-Window name for...", ["alternating current", "direct current", "steady flux", "static charge"], 0, "Swing drive reverses direction periodically.", ["dc_vs_ac_size_only_confusion"], skill_tags=["dc_ac_distinction"]),
        mcq("A3L5_D3", "Which waveform feature tells you AC is not just weak DC?", ["it crosses zero and reverses sign", "it has a smaller peak", "it always has larger resistance", "it removes flux"], 0, "AC reverses direction; DC does not.", ["dc_vs_ac_size_only_confusion"], skill_tags=["waveform_interpretation"]),
        mcq("A3L5_D4", "If the period of a waveform is 0.02 s, the frequency is...", ["50 Hz", "20 Hz", "0.5 Hz", "500 Hz"], 0, "Use f = 1/T.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        mcq("A3L5_D5", "Which statement about a sinusoidal AC is correct?", ["its instantaneous value can be positive, zero, or negative", "it stays positive at all times", "it is just a constant voltage", "it cannot be described by a graph"], 0, "AC swings through positive and negative values.", ["dc_vs_ac_size_only_confusion"], skill_tags=["waveform_interpretation"]),
        mcq("A3L5_D6", "The crest level of an AC waveform is the...", ["peak value", "RMS value", "average value over a cycle", "resistance"], 0, "Crest level means the maximum magnitude.", ["peak_equals_rms_confusion"], skill_tags=["use_sinusoid_model"]),
        mcq("A3L5_D7", "If frequency increases, the period...", ["decreases", "increases", "stays the same", "becomes RMS"], 0, "Frequency and period are inverses.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        short("A3L5_D8", "Why is AC not the same as small DC?", ["Because AC reverses direction periodically and crosses zero, while DC stays in one direction.", "Because the key difference is time behaviour and reversal, not just size."], "Use reversal and time-pattern language.", ["dc_vs_ac_size_only_confusion"], skill_tags=["dc_ac_distinction"], acceptance_rules=acceptance_groups(["AC", "alternating"], ["reverses", "changes direction", "crosses zero"], ["DC", "direct"], ["one direction", "steady direction"], ["not just smaller", "not just size"])),
        short("A3L5_D9", "What does the beat clock mean for an AC waveform?", ["It means the repeating timing of the waveform, described by period and frequency.", "It is how fast the AC repeats its cycle."], "Link beat clock to period or frequency.", ["frequency_period_confusion"], skill_tags=["period_frequency"], acceptance_rules=acceptance_groups(["period", "frequency", "repeats"], ["cycle", "beat clock", "timing"])),
        mcq("A3L5_D10", "The Cambridge sinusoid model for an AC quantity is of the form...", ["x = x0 sin(omega t)", "x = x0 + t", "x = BA", "x = V0/sqrt(2)"], 0, "This is the time-varying sinusoidal model.", ["sinusoid_formula_time_confusion"], skill_tags=["use_sinusoid_model"]),
    ]
    concept = [
        mcq("A3L5_C1", "A sinusoidal voltage has period 0.04 s. Its frequency is...", ["25 Hz", "4 Hz", "0.25 Hz", "40 Hz"], 0, "f = 1 / 0.04.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        mcq("A3L5_C2", "Which graph definitely shows DC?", ["a horizontal line that stays above zero", "a sine wave crossing zero", "a graph that alternates positive and negative", "a repeated waveform"], 0, "DC stays one-sided and unchanging in sign.", ["dc_vs_ac_size_only_confusion"], skill_tags=["waveform_interpretation"]),
        mcq("A3L5_C3", "If a sinusoidal current has peak value 4 A, which statement is correct?", ["its instantaneous value can be anywhere between -4 A and +4 A", "it always equals 4 A", "its RMS must be 4 A", "its average over a full cycle is 4 A"], 0, "Peak is maximum magnitude, not every instant.", ["peak_equals_rms_confusion"], skill_tags=["use_sinusoid_model"]),
        short("A3L5_C4", "Why does AC need a time graph to tell its story more than DC does?", ["Because AC changes size and direction with time, so the waveform shows the full repeating pattern.", "Because a time graph makes the reversal and repeating cycle visible."], "Use changing-with-time language.", ["dc_vs_ac_size_only_confusion"], skill_tags=["waveform_interpretation"], acceptance_rules=acceptance_groups(["changes with time", "repeats", "cycle"], ["direction", "reverses", "crosses zero"], ["graph", "waveform"])),
        mcq("A3L5_C5", "A waveform repeats 120 times each second. Its frequency is...", ["120 Hz", "120 s", "1/120 Hz", "0.0083 Hz"], 0, "Frequency is cycles per second.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        mcq("A3L5_C6", "If frequency doubles, the period...", ["halves", "doubles", "is unchanged", "becomes zero"], 0, "T = 1/f.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        short("A3L5_C7", "A learner says, 'AC is just weaker DC because the values are small.' What correction should you make?", ["AC and DC differ by direction behaviour over time: AC reverses periodically, while DC stays in one direction.", "Size alone does not decide AC or DC; reversal with time does."], "Restore time behaviour and reversal.", ["dc_vs_ac_size_only_confusion"], skill_tags=["dc_ac_distinction"], acceptance_rules=acceptance_groups(["AC", "alternating"], ["reverses", "direction", "changes sign"], ["DC", "direct"], ["one direction"], ["not size", "not just small"])),
        mcq("A3L5_C8", "Best summary of Lesson 5:", ["DC is one-way drive, AC is swing drive, and period/frequency describe the repeat clock.", "AC is just weaker DC with smaller numbers.", "Period and frequency are unrelated.", "Peak value and RMS are the same thing."], 0, "That is the Thread-Window summary of AC and DC.", ["dc_vs_ac_size_only_confusion", "frequency_period_confusion"], skill_tags=["dc_ac_distinction"]),
    ]
    mastery = [
        mcq("A3L5_M1", "An AC waveform has frequency 60 Hz. Its period is about...", ["0.0167 s", "60 s", "0.60 s", "6.0 s"], 0, "T = 1/60.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        mcq("A3L5_M2", "Which statement about x = x0 sin(omega t) is correct?", ["x0 is the peak value", "x0 is the frequency", "omega is the RMS value", "t is the resistance"], 0, "x0 is the crest level.", ["sinusoid_formula_time_confusion"], skill_tags=["use_sinusoid_model"]),
        mcq("A3L5_M3", "A graph remains positive and constant with time. It is best described as...", ["DC", "sinusoidal AC", "flux linkage", "RMS only"], 0, "One-way steady drive is DC.", ["dc_vs_ac_size_only_confusion"], skill_tags=["dc_ac_distinction"]),
        mcq("A3L5_M4", "A sinusoidal current has peak 10 A. At some instants its value is zero because...", ["the waveform crosses the axis during each cycle", "peak and RMS cancel", "AC has no time dependence", "DC forces it"], 0, "AC swings through zero as it reverses.", ["sinusoid_formula_time_confusion"], skill_tags=["waveform_interpretation"]),
        short("A3L5_M5", "Why is frequency a 'beat clock' idea?", ["Because it tells how many full AC cycles happen each second.", "Because it is the repetition rate of the swing drive."], "Connect beat clock to cycles per second.", ["frequency_period_confusion"], skill_tags=["period_frequency"], acceptance_rules=acceptance_groups(["cycles per second", "repetition rate", "how often"], ["frequency", "beat clock", "repeats"])),
        mcq("A3L5_M6", "If the period changes from 0.05 s to 0.10 s, the frequency...", ["halves", "doubles", "stays the same", "becomes negative"], 0, "Longer period means lower frequency.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        mcq("A3L5_M7", "Which quantity is the crest level of a sine-wave voltage?", ["maximum magnitude of the voltage", "average over a full cycle", "effective heating value", "time for one cycle"], 0, "Crest level means peak.", ["peak_equals_rms_confusion"], skill_tags=["use_sinusoid_model"]),
        short("A3L5_M8", "Summarize one-way drive versus swing drive in one sentence.", ["DC keeps the push in one direction, while AC swings positive and negative and reverses direction repeatedly.", "One-way drive is DC and swing drive is AC because AC keeps reversing with time."], "Keep the reversal idea visible.", ["dc_vs_ac_size_only_confusion"], skill_tags=["dc_ac_distinction"], acceptance_rules=acceptance_groups(["DC", "one-way"], ["AC", "swing"], ["reverses", "positive and negative", "changes direction"])),
        mcq("A3L5_M9", "A wave repeats every 0.25 s. The frequency is...", ["4 Hz", "0.25 Hz", "25 Hz", "2 Hz"], 0, "1 / 0.25 = 4.", ["frequency_period_confusion"], skill_tags=["period_frequency"]),
        mcq("A3L5_M10", "Best lesson summary:", ["AC and DC are different time-patterns, and period/frequency describe how fast the AC pattern repeats.", "AC is just smaller DC.", "Only RMS tells AC apart from DC.", "Frequency is the peak current."], 0, "That captures the full lesson clearly.", ["dc_vs_ac_size_only_confusion", "frequency_period_confusion"], skill_tags=["dc_ac_distinction"]),
    ]
    ac_series = waveform_points(3.0, cycles=1.0, points=72)
    dc_series = line_points(2.0, end_x=1.0)
    return lesson_spec(
        "A3_L5",
        "Sort One-Way and Swing Drives",
        sim("a3_drive_sorter_lab", "Drive sorter lab", "Compare DC and AC time traces so one-way and swing drive become distinct time patterns instead of vague labels.", ["Set one-way drive and read the flat trace.", "Switch to swing drive and change the frequency.", "Compare period, peak, and instantaneous value."], ["Distinguish AC from DC using waveform behaviour.", "Relate frequency and period quantitatively.", "Interpret peak value and sinusoidal change over time."], ["mode", "peak_value", "frequency", "period", "instantaneous_value"], "AC/DC reasoning."),
        diagnostic,
        "The Thread-Window story now becomes a time-pattern story. One-way drive keeps the push in one direction: DC. Swing drive rises, falls, crosses zero, reverses, and repeats: AC. Period and frequency tell how fast the swing repeats, while the crest level tells the maximum magnitude reached.",
        "Commit to AC and DC as different time behaviours rather than different sizes of the same thing.",
        [prompt_block("What makes AC different from DC at the deepest level?", "AC reverses direction periodically while DC does not."), prompt_block("How are period and frequency related?", "They are inverses: f = 1/T.")],
        [prompt_block("Look at the DC trace first.", "It should stay on one side of zero."), prompt_block("Now increase AC frequency.", "The cycles should repeat more often and the period should shrink.")],
        ["Why is AC not just a small version of DC?", "Why is period/frequency language better than saying an AC source is 'fast' or 'slow' without precision?"],
        "Keep time-pattern language strong before introducing RMS.",
        concept,
        mastery,
        contract(
            concept_targets=["Distinguish direct current from alternating current through their time behaviour.", "Use period and frequency as inverse measures of repetition rate.", "Interpret peak value and sinusoidal form for AC quantities."],
            core_concepts=["DC stays one-sided in time.", "AC reverses sign and repeats periodically.", "Frequency and period describe the beat clock of AC.", "Peak value is not the same as RMS or average over a cycle."],
            prerequisite_lessons=[],
            misconception_focus=["dc_vs_ac_size_only_confusion", "frequency_period_confusion", "peak_equals_rms_confusion", "sinusoid_formula_time_confusion"],
            formulas=[relation("f = 1 / T", "Frequency and period relation.", ["Hz", "s"], "Use for any repeating waveform."), relation("x = x0 sin(omega t)", "Sinusoidal AC model.", ["same unit as x"], "x0 is the peak value and omega sets the angular speed of the cycle.")],
            representations=[representation("graph", "Shows DC as one-way and AC as swing drive."), representation("words", "Describes AC and DC as different time patterns."), representation("formula", "Uses f = 1/T and sinusoidal form."), representation("table", "Compares peak, period, and frequency.")],
            analogy_map=thread_window_map("the learner compares one-way and swing drives on a time graph"),
            worked_examples=[worked("An AC waveform has period 0.02 s. Find the frequency.", ["Use f = 1/T.", "Compute 1 / 0.02.", "State the answer in hertz."], "50 Hz", "Frequency counts how often the swing repeats each second.", "This is the core period-frequency calculation."), worked("A learner says AC is just weaker DC. Correct the statement.", ["State that AC reverses direction periodically.", "State that DC stays in one direction.", "Make time behaviour the real difference, not size alone."], "AC and DC are different time behaviours", "Reversal is the defining feature of AC.", "This protects against the most common AC/DC confusion.")],
            visual_assets=[visual("a3-l5-dc-ac-waveform", "physics_graph", "One-way and swing drives on a time graph", "Show a DC line and a sinusoidal AC trace on the same axes so reversal and repetition become visible.", "DC stays one-sided in time, while AC crosses zero and reverses on a beat clock set by the frequency.", template="physics_graph", meta={"graph_type": "generic_xy", "title": "One-Way Drive vs Swing Drive", "subtitle": "Time behaviour distinguishes DC from AC", "x_label": "Time (cycles)", "y_label": "Push / current", "show_legend": True, "series": [{"label": "Swing drive (AC)", "color": "#38bdf8", "points": ac_series}, {"label": "One-way drive (DC)", "color": "#f97316", "points": dc_series}]})],
            animation_assets=[],
            simulation_contract=sim_contract("a3_l5_drive_sorter_sim", "drive_sorter", "Switch between one-way and swing drive while reading the waveform, the peak, and the beat clock.", "Start with a medium-peak AC trace at low frequency, then compare it with a DC trace.", ["Increase AC frequency and watch the period shrink.", "Pause the time marker at several points to compare instantaneous values.", "Compare a DC trace and an AC trace with the same peak magnitude."], "Watch for AC crossing zero and reversing sign while DC stays on one side of the axis.", "AC and DC are different time-patterns, and period/frequency make that difference measurable.", controls=[("drive_mode", "Drive mode", "Switches between one-way drive and swing drive."), ("peak_value", "Peak value", "Sets the crest level of the drive."), ("frequency", "Frequency", "Sets how quickly the swing repeats."), ("time_marker", "Time marker", "Shows the instantaneous value at a chosen point.")], readouts=[("Period", "Shows the cycle time of the swing drive."), ("Instantaneous value", "Shows the current graph value at the chosen time.")]),
            reflection_prompts=["Explain why AC is not just weak DC by referring to the time graph.", "Describe how period and frequency work together to describe the beat clock of an AC waveform."],
            mastery_skills=["dc_ac_distinction", "period_frequency", "use_sinusoid_model", "waveform_interpretation", "peak_value_reading"],
            variation_plan={"diagnostic": "Fresh attempts rotate between AC-vs-DC waveform judgments, quick period-frequency conversions, and peak-value interpretations.", "concept_gate": "Concept-gate retries alternate between graph-reading stems and new numerical period or frequency values.", "mastery": "Mastery varies lesson-owned AC/DC classification and timing calculations with unseen stems preferred first."},
            scaffold_support=scaffold("DC is one-way drive and AC is swing drive.", "The waveform view makes the key difference visible: DC stays one-sided, while AC crosses zero and reverses repeatedly on a beat clock.", "What on the time graph proves that a signal is AC rather than DC?", "Treating AC and DC as different sizes instead of different time behaviours.", "The swing drive rises, falls, crosses zero, and reverses direction, while the one-way drive keeps pointing the same way through time.", "Why does a graph reveal the AC/DC difference more clearly than a single number?", extras=[extra_section("Beat clock", "Period tells the time for one full cycle, and frequency tells how many cycles happen each second.", "If the cycles repeat faster, what happens to the period?"), extra_section("Crest level", "Peak value is the maximum magnitude reached by the AC waveform, not the value at every instant.", "Why can an AC with peak 4 A still be zero at some times?")]),
            visual_clarity_checks=visual_checks("dc-ac-waveform"),
        ),
    )


def lesson_six() -> Dict[str, Any]:
    diagnostic = [
        mcq("A3L6_D1", "RMS value is best described as the...", ["effective DC-equivalent value for heating in a resistor", "peak value of the AC", "simple average over a full cycle", "frequency"], 0, "RMS is the heat-match level.", ["peak_equals_rms_confusion", "average_equals_rms_confusion"], skill_tags=["rms_meaning"]),
        mcq("A3L6_D2", "For a sine wave, Vrms equals...", ["V0 / sqrt(2)", "V0", "2V0", "V0 / 2"], 0, "Cambridge uses peak divided by root 2.", ["peak_equals_rms_confusion"], skill_tags=["use_vrms"]),
        mcq("A3L6_D3", "Why do we need RMS instead of the ordinary average for a full sine-wave cycle?", ["because the ordinary average over a full cycle is zero", "because peak value cannot be measured", "because DC has no resistance", "because period is negative"], 0, "The simple average hides the heating effect.", ["average_equals_rms_confusion"], skill_tags=["rms_meaning"]),
        mcq("A3L6_D4", "If a sinusoidal current has peak 10 A, its RMS current is about...", ["7.1 A", "10 A", "5.0 A", "14.1 A"], 0, "10 / sqrt(2) is about 7.1.", ["peak_equals_rms_confusion"], skill_tags=["use_irms"]),
        mcq("A3L6_D5", "Which statement is strongest?", ["RMS compares AC with the DC value that would give the same heating in a resistor.", "RMS is just the top of the graph.", "RMS is the arithmetic average over a cycle.", "RMS only matters for magnets."], 0, "Heat-match language is the cleanest.", ["peak_equals_rms_confusion", "average_equals_rms_confusion"], skill_tags=["power_equivalence"]),
        mcq("A3L6_D6", "If the peak voltage of a sine wave doubles, the RMS voltage...", ["doubles", "halves", "stays the same", "becomes zero"], 0, "Vrms is proportional to the peak for a sine wave.", ["peak_equals_rms_confusion"], skill_tags=["use_vrms"]),
        mcq("A3L6_D7", "Which value is larger for a sine-wave AC: peak or RMS?", ["peak", "RMS", "they are equal", "they swap each half-cycle"], 0, "RMS is lower than peak by a factor of root 2.", ["peak_equals_rms_confusion"], skill_tags=["rms_meaning"]),
        short("A3L6_D8", "Why is RMS called the heat-match level?", ["Because it is the DC value that would produce the same heating effect in a resistor as the AC does.", "Because RMS matches the resistive power or heating effect of the AC."], "Use same-heating or same-power language.", ["average_equals_rms_confusion"], skill_tags=["power_equivalence"], acceptance_rules=acceptance_groups(["same heating", "same power", "same resistive effect"], ["DC value", "equivalent DC", "heat-match"], ["resistor"])),
        short("A3L6_D9", "Why is RMS not the same as the simple average of a full sine wave?", ["Because the simple average over a full cycle is zero, but RMS is designed to match the effective heating effect.", "Because positive and negative parts cancel in the ordinary average, while RMS keeps track of effective size."], "Contrast cancellation with effective heating.", ["average_equals_rms_confusion"], skill_tags=["rms_meaning"], acceptance_rules=acceptance_groups(["average", "full cycle"], ["zero", "cancel"], ["RMS", "effective", "heating"])),
        mcq("A3L6_D10", "A sinusoidal voltage has peak 20 V. Vrms is closest to...", ["14.1 V", "20 V", "10 V", "28.3 V"], 0, "20 / sqrt(2) is about 14.1.", ["peak_equals_rms_confusion"], skill_tags=["use_vrms"]),
    ]
    concept = [
        mcq("A3L6_C1", "A sine-wave supply has peak voltage 325 V. The RMS voltage is about...", ["230 V", "325 V", "162.5 V", "460 V"], 0, "325 / sqrt(2) is about 230.", ["peak_equals_rms_confusion"], skill_tags=["use_vrms"]),
        mcq("A3L6_C2", "A sine-wave current has peak value 6 A. The RMS current is about...", ["4.2 A", "6 A", "3.0 A", "8.5 A"], 0, "6 / sqrt(2) is about 4.2.", ["peak_equals_rms_confusion"], skill_tags=["use_irms"]),
        mcq("A3L6_C3", "Which value would produce the same heating in a resistor as a 10 V RMS AC supply?", ["10 V DC", "14.1 V DC", "7.1 V DC", "0 V DC"], 0, "RMS is the DC-equivalent heating value.", ["average_equals_rms_confusion"], skill_tags=["power_equivalence"]),
        short("A3L6_C4", "Why is peak value alone not enough to compare AC heating with DC heating?", ["Because heating depends on the effective value over time, and RMS gives that DC-equivalent effect while peak only tells the maximum instant.", "Because peak is just the crest level, but RMS tells the effective resistive effect."], "Contrast maximum instant with effective heating.", ["peak_equals_rms_confusion"], skill_tags=["rms_meaning"], acceptance_rules=acceptance_groups(["peak", "maximum"], ["RMS", "effective", "heat-match"], ["heating", "resistive effect"], ["not enough", "only instant"])),
        mcq("A3L6_C5", "If a sine-wave peak current is 14.1 A, the RMS current is...", ["10.0 A", "14.1 A", "7.05 A", "20.0 A"], 0, "14.1 / sqrt(2) is about 10.0.", ["peak_equals_rms_confusion"], skill_tags=["use_irms"]),
        mcq("A3L6_C6", "Why is the arithmetic average of a full sine wave not a good measure of heating?", ["because positive and negative halves cancel to zero even though heating still happens", "because the peak changes into DC", "because resistance vanishes", "because frequency becomes RMS"], 0, "The ordinary average hides the real energy effect.", ["average_equals_rms_confusion"], skill_tags=["rms_meaning"]),
        short("A3L6_C7", "A learner says, 'RMS is just the middle height of the sine wave.' What correction should you make?", ["RMS is the effective DC-equivalent value for heating, not a visual midpoint or a simple average height.", "RMS comes from effective power comparison, so it is not just a geometric halfway level on the graph."], "Restore effective-heating language.", ["peak_equals_rms_confusion", "average_equals_rms_confusion"], skill_tags=["rms_meaning"], acceptance_rules=acceptance_groups(["effective", "DC-equivalent", "same heating"], ["not midpoint", "not middle height", "not average"])),
        mcq("A3L6_C8", "Best summary of Lesson 6:", ["RMS is the heat-match value that compares sinusoidal AC with an equivalent DC effect in a resistor.", "RMS is always equal to peak.", "RMS is the arithmetic average over a cycle.", "RMS only matters for period calculations."], 0, "That is the central RMS idea.", ["peak_equals_rms_confusion", "average_equals_rms_confusion"], skill_tags=["rms_meaning"]),
    ]
    mastery = [
        mcq("A3L6_M1", "A sine-wave voltage has peak 50 V. Vrms is about...", ["35.4 V", "50 V", "25 V", "70.7 V"], 0, "50 / sqrt(2) is about 35.4.", ["peak_equals_rms_confusion"], skill_tags=["use_vrms"]),
        mcq("A3L6_M2", "A sine-wave current has peak 12 A. Irms is about...", ["8.5 A", "12 A", "6.0 A", "17.0 A"], 0, "12 / sqrt(2) is about 8.5.", ["peak_equals_rms_confusion"], skill_tags=["use_irms"]),
        mcq("A3L6_M3", "An AC supply has 20 V RMS across a resistor. Which DC supply gives the same heating?", ["20 V DC", "28.3 V DC", "14.1 V DC", "0 V DC"], 0, "RMS is the equal-heating DC value.", ["average_equals_rms_confusion"], skill_tags=["power_equivalence"]),
        mcq("A3L6_M4", "If the peak value of a sine wave is multiplied by 3, the RMS value...", ["is also multiplied by 3", "is divided by 3", "stays the same", "becomes zero"], 0, "Peak and RMS scale together for a sine wave.", ["peak_equals_rms_confusion"], skill_tags=["use_vrms"]),
        short("A3L6_M5", "Why is the average AC over a full cycle zero while the resistor still heats up?", ["Because positive and negative values cancel in the simple average, but heating depends on the effective size of the current or voltage and that is captured by RMS.", "Because the sign reversal cancels the ordinary average, yet the resistor still gets energy transfer in both halves of the cycle."], "Separate signed average from heating effect.", ["average_equals_rms_confusion"], skill_tags=["rms_meaning"], acceptance_rules=acceptance_groups(["average", "full cycle"], ["zero", "cancel"], ["heating", "energy transfer", "resistor"], ["RMS", "effective"])),
        mcq("A3L6_M6", "A supply has 100 V peak. Vrms is closest to...", ["70.7 V", "100 V", "50 V", "141 V"], 0, "100 / sqrt(2) is about 70.7.", ["peak_equals_rms_confusion"], skill_tags=["use_vrms"]),
        mcq("A3L6_M7", "Which pair is correct for a sinusoidal AC?", ["RMS is smaller than peak, but equal to the heating-equivalent DC value.", "RMS equals peak and also equals the simple average.", "Peak is smaller than RMS.", "RMS is unrelated to resistor heating."], 0, "RMS is effective, not peak.", ["peak_equals_rms_confusion", "average_equals_rms_confusion"], skill_tags=["power_equivalence"]),
        short("A3L6_M8", "Summarize RMS in one strong sentence.", ["RMS is the effective DC-equivalent value of a sinusoidal AC for heating or power in a resistor.", "The heat-match level is the RMS value, which tells what DC value would produce the same resistive effect."], "Keep effective DC-equivalent heating language.", ["peak_equals_rms_confusion", "average_equals_rms_confusion"], skill_tags=["rms_meaning"], acceptance_rules=acceptance_groups(["RMS", "heat-match"], ["effective", "equivalent DC", "same heating"], ["resistor", "power", "resistive effect"])),
        mcq("A3L6_M9", "A sine-wave current has Irms = 5 A. The peak current is closest to...", ["7.1 A", "5 A", "3.5 A", "10 A"], 0, "Peak = Irms x sqrt(2).", ["peak_equals_rms_confusion"], skill_tags=["use_irms"]),
        mcq("A3L6_M10", "Best lesson summary:", ["RMS is the heat-match level that lets sinusoidal AC be compared fairly with DC in a resistor.", "RMS is just the top of the graph.", "RMS is the same as the simple average over a cycle.", "RMS only tells frequency."], 0, "That captures the full effective-value idea.", ["peak_equals_rms_confusion", "average_equals_rms_confusion"], skill_tags=["rms_meaning"]),
    ]
    rms_level = round(3.0 / math.sqrt(2), 4)
    rms_wave = waveform_points(3.0, cycles=1.0, points=72)
    return lesson_spec(
        "A3_L6",
        "Match the Heat Level",
        sim("a3_heat_match_lab", "Heat-match lab", "Compare peak, RMS, and equivalent DC values so the resistor-heating meaning of RMS becomes concrete.", ["Set a peak AC value.", "Read the RMS value.", "Compare the resistor-heating effect with an equivalent DC supply."], ["Use Vrms and Irms for sine waves.", "Explain why RMS is not the arithmetic average.", "Relate RMS to equal heating in a resistor."], ["peak_value", "rms_value", "equivalent_dc", "power_match"], "RMS reasoning."),
        diagnostic,
        "Swing drive creates another problem: over a full cycle, a sine wave averages to zero, but a resistor still warms up. The right comparison is not the ordinary average. It is the heat-match level: the DC value that would give the same heating effect. That effective value is the RMS value.",
        "Commit to RMS as an effective heating value rather than a graph midpoint or a simple average.",
        [prompt_block("Why is the ordinary average of a full sine wave not enough?", "Because positive and negative halves cancel."), prompt_block("What does RMS compare AC with?", "The equivalent DC value that gives the same heating.")],
        [prompt_block("Set a new peak value.", "Watch RMS change with it."), prompt_block("Compare the AC with the equivalent DC readout.", "The heating effect should match.")],
        ["Why is RMS better than the ordinary average when discussing resistor heating?", "Why is the peak value larger than the RMS value for a sine wave?"],
        "Close the module by connecting sinusoidal AC to a meaningful effective comparison with DC.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain RMS as the effective DC-equivalent value for resistive heating.", "Use V_rms = V0 / sqrt(2) and I_rms = I0 / sqrt(2) for sine waves.", "Explain why the simple average over a full cycle is not the same as RMS."],
            core_concepts=["RMS is a heat-match value.", "Peak value is larger than RMS for a sine wave.", "The ordinary average of a full sine wave is zero.", "RMS is used because it compares AC and DC fairly for resistor power."],
            prerequisite_lessons=["A3_L5"],
            misconception_focus=["peak_equals_rms_confusion", "average_equals_rms_confusion"],
            formulas=[relation("V_rms = V0 / sqrt(2)", "RMS voltage for a sinusoidal AC.", ["V"], "Use when V0 is the peak voltage."), relation("I_rms = I0 / sqrt(2)", "RMS current for a sinusoidal AC.", ["A"], "Use when I0 is the peak current.")],
            representations=[representation("graph", "Shows a sine wave with RMS levels marked."), representation("words", "Describes RMS as a heat-match value."), representation("formula", "Connects peak and RMS values."), representation("table", "Matches AC heating to equivalent DC heating.")],
            analogy_map=thread_window_map("the learner compares the crest level with the heat-match level for a resistor"),
            worked_examples=[worked("A sine-wave voltage has peak 20 V. Find the RMS voltage.", ["Use V_rms = V0 / sqrt(2).", "Compute 20 / sqrt(2).", "State the answer in volts."], "14.1 V", "RMS is smaller than the peak by a factor of root 2 for a sine wave.", "This is the standard RMS calculation."), worked("Explain why the average AC over a full cycle can be zero while the resistor still heats up.", ["Notice that positive and negative halves cancel in the signed average.", "Remember that heating depends on effective magnitude, not signed average.", "Use RMS as the correct comparison value."], "The average is zero but RMS is not", "Average and effective value are different ideas.", "This protects the whole reason RMS exists.")],
            visual_assets=[visual("a3-l6-rms-heat-match", "physics_graph", "Crest level and heat-match level on the sine wave", "Show a sine wave with horizontal RMS lines so the effective value is compared directly with the peak.", "RMS is the heat-match level: lower than the crest, but equal to the DC value that gives the same resistive effect.", template="physics_graph", meta={"graph_type": "generic_xy", "title": "Crest Level vs Heat-Match Level", "subtitle": "RMS compares sinusoidal AC with equal-heating DC", "x_label": "Time (cycles)", "y_label": "Voltage / current", "show_legend": True, "series": [{"label": "Swing drive", "color": "#38bdf8", "points": rms_wave}, {"label": "+RMS", "color": "#f97316", "points": line_points(rms_level, end_x=1.0)}, {"label": "-RMS", "color": "#22c55e", "points": line_points(-rms_level, end_x=1.0)}]})],
            animation_assets=[],
            simulation_contract=sim_contract("a3_l6_heat_match_sim", "heat_match", "Change the peak value and compare the resulting RMS level with the equivalent DC heating effect.", "Start with a moderate sine-wave peak and compare the AC and DC heating readouts.", ["Double the peak and compare how the RMS changes.", "Pause at several instants and compare the instantaneous value with the steady RMS level.", "Explain why the signed average can be zero even while heating stays non-zero."], "Watch for RMS staying below the crest level while still matching the DC heating effect.", "RMS is the effective value that turns AC heating into a meaningful DC comparison.", controls=[("peak_value", "Peak value", "Sets the crest level of the sine wave."), ("resistance", "Resistor value", "Keeps the heating comparison tied to a load."), ("time_marker", "Time marker", "Shows the instantaneous value against the steady RMS level.")], readouts=[("RMS value", "Shows the heat-match level for the current peak."), ("Equivalent DC", "Shows the DC value that would heat the resistor the same way.")]),
            reflection_prompts=["Explain why RMS is a better heating measure than the ordinary average for a sine-wave AC.", "Describe the relationship between peak and RMS values for a sinusoidal waveform."],
            mastery_skills=["rms_meaning", "use_vrms", "use_irms", "power_equivalence", "peak_rms_relation"],
            variation_plan={"diagnostic": "Fresh attempts rotate between peak-to-RMS conversions and explanations of why RMS is not the simple average.", "concept_gate": "Concept-gate retries alternate between new peak values, equal-heating DC comparisons, and explanation stems about the full-cycle average.", "mastery": "Mastery varies lesson-owned Vrms and Irms calculations plus short effective-value explanations with unseen stems preferred first."},
            scaffold_support=scaffold("RMS is the heat-match level.", "A sine wave needs an effective-value idea because the signed average hides the real resistor-heating effect. RMS solves that comparison problem cleanly.", "What DC value would give the same heating effect as this AC?", "Treating RMS as either the peak or the simple average of the sine wave.", "The crest level shows the largest instant, but the heat-match level shows the steady DC value that would warm the same resistor equally strongly.", "Why does the resistor still heat even when the signed average over a full cycle is zero?", extras=[extra_section("Peak versus effective", "Peak is a maximum instant. RMS is an effective steady comparison value. They answer different questions.", "Which one would you use for equal-heating comparison?"), extra_section("Average trap", "Positive and negative halves cancel in the ordinary average, so average cannot represent the real heating effect of AC.", "Why does cancellation make the ordinary average misleading here?")]),
            visual_clarity_checks=visual_checks("rms-heat-match"),
        ),
    )


A3_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Magnetic flux, induction, flux linkage, Lenz's law, AC, and RMS taught through the Thread-Window Pulse Model so learners keep time-varying fields, loop response, and effective AC values inside one coherent advanced-electromagnetism story.",
    "mastery_outcomes": [
        "Explain magnetic flux as field-through-area rather than as field strength alone.",
        "Explain induction as the result of changing flux or changing flux linkage.",
        "Use turn count and linkage to reason about Faraday's law in coils.",
        "Apply Lenz's law as opposition to the change in flux rather than to the field in a blanket way.",
        "Distinguish clearly between DC and sinusoidal AC using waveform, period, frequency, and peak language.",
        "Use RMS values as effective DC-equivalent heating values for sinusoidal AC in resistive contexts.",
    ],
    "lessons": [
        lesson_one(),
        lesson_two(),
        lesson_three(),
        lesson_four(),
        lesson_five(),
        lesson_six(),
    ],
}


RELEASE_CHECKS = [
    "Every lesson keeps the same Thread-Window language visible across flux, induction, linkage, opposition, AC, and RMS.",
    "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
    "Every lesson-owned assessment bank supports fresh unseen diagnostic, concept-gate, and mastery questions before repeats.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example explains why the answer follows instead of naming only the final value.",
    "Every A3 visual keeps field threads, window orientation, induced direction, waveform axes, and RMS levels readable without clipping.",
]


A3_MODULE_DOC, A3_LESSONS, A3_SIM_LABS = build_nextgen_module_bundle(
    module_id=A3_MODULE_ID,
    module_title=A3_MODULE_TITLE,
    module_spec=A3_SPEC,
    allowlist=A3_ALLOWLIST,
    content_version=A3_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=20,
    level="Module A3",
    estimated_minutes=360,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module A3 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(A3_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A3_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A3_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", A3_MODULE_ID)]
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
