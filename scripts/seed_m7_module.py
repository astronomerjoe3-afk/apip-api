from __future__ import annotations

import argparse
from copy import deepcopy
from typing import Any, Dict, List, Sequence, Tuple

try:
    from scripts.module_asset_pipeline import default_asset_root, render_module_assets
    from scripts.nextgen_module_builder import build_nextgen_module_bundle
    from scripts.lesson_authoring_contract import AUTHORING_STANDARD_V3
except ModuleNotFoundError:
    from module_asset_pipeline import default_asset_root, render_module_assets
    from nextgen_module_builder import build_nextgen_module_bundle
    from lesson_authoring_contract import AUTHORING_STANDARD_V3

try:
    from scripts.seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc
except ModuleNotFoundError:
    from seed_m1_module import get_project_id, init_firebase, print_preview, upsert_doc


M7_MODULE_ID = "M7"
M7_CONTENT_VERSION = "20260323_m7_waves_vibrations_v2"
M7_MODULE_TITLE = "Waves and Vibrations"
M7_ALLOWLIST = [
    "medium_moves_with_wave_confusion",
    "energy_disturbance_confusion",
    "transverse_direction_confusion",
    "longitudinal_direction_confusion",
    "front_line_phase_confusion",
    "wave_speed_relation_confusion",
    "frequency_sets_speed_confusion",
    "reflection_angle_confusion",
    "reflection_refraction_mixup",
    "boundary_frequency_change_confusion",
    "diffraction_opening_size_confusion",
    "diffraction_sound_only_confusion",
]

VALID_REPRESENTATION_KINDS = {
    "diagram",
    "equation_story",
    "formula",
    "graph",
    "model",
    "table",
    "words",
}


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M7_ALLOWLIST)
    return [str(tag) for tag in tags if str(tag) in allowed]


def mcq(
    qid: str,
    prompt: str,
    choices: Sequence[str],
    answer_index: int,
    hint: str,
    tags: Sequence[str],
    *,
    skill_tags: Sequence[str] | None = None,
) -> Dict[str, Any]:
    item = {
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
    }
    if skill_tags:
        item["skill_tags"] = [str(tag) for tag in skill_tags]
    return item


def short(
    qid: str,
    prompt: str,
    accepted_answers: Sequence[str],
    hint: str,
    tags: Sequence[str],
    *,
    acceptance_rules: Dict[str, Any] | None = None,
    skill_tags: Sequence[str] | None = None,
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
    }
    if acceptance_rules:
        item["acceptance_rules"] = deepcopy(acceptance_rules)
    if skill_tags:
        item["skill_tags"] = [str(tag) for tag in skill_tags]
    return item


def acceptance_groups(*groups: Sequence[str]) -> Dict[str, Any]:
    return {"phrase_groups": [list(group) for group in groups]}


def prompt_block(prompt: str, hint: str) -> Dict[str, str]:
    return {"prompt": prompt, "hint": hint}


def relation(equation: str, meaning: str, units: Sequence[str], conditions: str) -> Dict[str, Any]:
    return {
        "equation": equation,
        "meaning": meaning,
        "units": list(units),
        "conditions": conditions,
    }


def representation(kind: str, purpose: str) -> Dict[str, str]:
    raw = str(kind or "").strip().lower().replace("-", "_").replace(" ", "_")
    if raw not in VALID_REPRESENTATION_KINDS:
        if "formula" in raw or "equation" in raw:
            raw = "formula"
        elif "word" in raw or "language" in raw:
            raw = "words"
        elif "story" in raw:
            raw = "equation_story"
        elif "table" in raw:
            raw = "table"
        elif "graph" in raw:
            raw = "graph"
        elif "model" in raw:
            raw = "model"
        else:
            raw = "diagram"
    return {"kind": raw, "purpose": purpose}


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
    phase_key: str = "analogical_grounding",
    template: str = "auto",
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": phase_key,
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": template,
        "meta": deepcopy(meta or {}),
    }


def animation(
    asset_id: str,
    concept: str,
    title: str,
    description: str,
    *,
    phase_key: str = "analogical_grounding",
    duration_sec: int = 8,
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": phase_key,
        "title": title,
        "description": description,
        "duration_sec": duration_sec,
    }


def extra_section(heading: str, body: str, check_for_understanding: str = "") -> Dict[str, str]:
    section = {"heading": heading, "body": body}
    if check_for_understanding:
        section["check_for_understanding"] = check_for_understanding
    return section


def scaffold(
    core_idea: str,
    reasoning: str,
    check_for_understanding: str,
    common_trap: str,
    analogy_body: str,
    analogy_check: str,
    *,
    extra_sections: Sequence[Dict[str, str]] | None = None,
) -> Dict[str, Any]:
    return {
        "core_idea": core_idea,
        "reasoning": reasoning,
        "check_for_understanding": check_for_understanding,
        "common_trap": common_trap,
        "analogy_bridge": {
            "body": analogy_body,
            "check_for_understanding": analogy_check,
        },
        "extra_sections": list(extra_sections or []),
    }


def assessment_targets(diagnostic_pool_min: int, concept_gate_pool_min: int, mastery_pool_min: int) -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": diagnostic_pool_min,
        "concept_gate_pool_min": concept_gate_pool_min,
        "mastery_pool_min": mastery_pool_min,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile.",
        "The moving arrows, fronts, and comparison callouts do not overlap the key explanation text.",
        "Every caption, formula, and summary bar remains readable without clipping or hidden words.",
    ]


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
    normalized_representations = [deepcopy(item) for item in representations]
    normalized_kinds = {str(item.get("kind") or "").strip() for item in normalized_representations}
    if "words" not in normalized_kinds:
        normalized_representations.insert(0, {"kind": "words", "purpose": "States the main wave idea in plain language before symbols."})
    if "formula" not in normalized_kinds:
        anchor = str(formulas[0].get("equation") or "").strip() if formulas else "the formal statement"
        normalized_representations.append({"kind": "formula", "purpose": f"Compresses the key relationship into {anchor} after the model is clear."})
    if not ({item.get("kind") for item in normalized_representations} & {"diagram", "graph", "table", "model", "equation_story"}):
        normalized_representations.append({"kind": "diagram", "purpose": "Keeps the Signal-Stadium comparison visible while the variables change."})

    normalized_skills: List[str] = []
    for skill in mastery_skills:
        cleaned = str(skill or "").strip()
        if cleaned and cleaned not in normalized_skills:
            normalized_skills.append(cleaned)

    return {
        "concept_targets": list(concept_targets),
        "core_concepts": list(core_concepts),
        "prerequisite_lessons": list(prerequisite_lessons),
        "misconception_focus": safe_tags(misconception_focus),
        "formulas": [deepcopy(item) for item in formulas],
        "representations": normalized_representations,
        "analogy_map": deepcopy(analogy_map),
        "worked_examples": [deepcopy(item) for item in worked_examples],
        "visual_assets": [deepcopy(item) for item in visual_assets],
        "animation_assets": [deepcopy(item) for item in animation_assets],
        "simulation_contract": deepcopy(simulation_contract),
        "reflection_prompts": list(reflection_prompts),
        "mastery_skills": normalized_skills[:5],
        "variation_plan": deepcopy(variation_plan),
        "assessment_bank_targets": assessment_targets(8, 6, 8),
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
    *,
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


def stadium_map(model_focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Signal-Stadium Model of Waves",
        "focus": model_focus,
        "comparison": f"The Signal-Stadium keeps wave ideas in one arena by tracking the Beat Tower, Signal Pads, Pulse Gap, Ripple Run, Front Line, and boundary features while {model_focus}.",
        "mapping": [
            "Beat Tower -> source",
            "Signal Pads -> points in the medium",
            "Beat Rate -> frequency",
            "Pulse Gap -> wavelength",
            "Ripple Run -> wave speed",
            "Cross-Sway Mode -> transverse wave",
            "Push-Squeeze Mode -> longitudinal wave",
            "Bounce Wall -> reflection",
            "Pace Zone -> medium",
            "Turn Bend -> refraction",
            "Gate Spread -> diffraction",
            "Front Line -> wavefront",
        ],
        "limit": "The stadium helps organize local motion, speed, wavelength, and boundary behavior, but the formal wave terms and relationships are still needed for exam-style explanations and calculations.",
        "prediction_prompt": f"Using the Signal-Stadium alone, predict what should happen when {model_focus}.",
    }


def sim_contract(
    *,
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
        "controls": [
            {"variable": variable, "label": label, "why_it_matters": why}
            for variable, label, why in controls
        ],
        "readouts": [
            {"label": label, "meaning": meaning}
            for label, meaning in readouts
        ],
    }


def lesson_l1() -> Dict[str, Any]:
    diagnostic = [
        mcq("M7L1_D1", "In the Signal-Stadium, what travels from the Beat Tower across the arena?", ["The disturbance pattern", "The pads themselves", "The whole floor", "The wall"], 0, "The pattern travels across the pads; the pads only respond locally.", ["medium_moves_with_wave_confusion"], skill_tags=["pattern_vs_medium"]),
        mcq("M7L1_D2", "A pad rises as a front reaches it and then settles back. What does that show?", ["Local oscillation in place", "The pad has traveled with the wave", "The source switched off", "The front stopped at that pad"], 0, "One pad moves locally while the front continues onward.", ["medium_moves_with_wave_confusion"], skill_tags=["local_oscillation"]),
        short("M7L1_D3", "Why does the model say the pattern travels but each pad stays in place?", ["Because each pad only oscillates locally while the disturbance moves on.", "Because the wavefront travels, but each pad only pulses in place."], "Keep local pad motion separate from the traveling front.", ["medium_moves_with_wave_confusion", "energy_disturbance_confusion"], acceptance_rules=acceptance_groups(["pad", "pads", "medium"], ["local", "in place", "oscillate", "pulse"], ["pattern", "front", "wave", "disturbance"], ["travels", "moves on", "crosses"]), skill_tags=["pattern_vs_medium"]),
        mcq("M7L1_D4", "What does a Front Line represent in this lesson?", ["Pads in the same phase", "The path one pad travels", "The source tower itself", "A line of moving matter"], 0, "A wavefront joins positions that are in step together.", ["front_line_phase_confusion"], skill_tags=["phase_front"]),
        mcq("M7L1_D5", "What does the wave mainly carry across the arena?", ["Energy in the disturbance", "A row of pads", "Extra matter from the source", "Permanent pad motion"], 0, "Waves carry energy through a disturbance pattern.", ["energy_disturbance_confusion"], skill_tags=["energy_transfer"]),
        short("M7L1_D6", "A marker on water bobs up and down as ripples pass. Why is that not evidence that the water moves along with the wave?", ["Because the marker mainly oscillates locally while the ripple pattern travels past.", "Because the ripple moves on, but the water particle mostly moves around a local position."], "Use local motion language, not bulk travel language.", ["medium_moves_with_wave_confusion"], acceptance_rules=acceptance_groups(["marker", "water particle", "particle"], ["local", "around", "oscillate", "bob"], ["pattern", "ripple", "wave"], ["passes", "moves on", "travels past"]), skill_tags=["evidence_reasoning"]),
        mcq("M7L1_D7", "Pads stay still until the front reaches them, then pulse briefly. What is actually moving?", ["The disturbance timing from pad to pad", "The pads across the stadium", "The whole medium as one block", "Only the source tower"], 0, "The travel pattern moves from pad to pad.", ["medium_moves_with_wave_confusion"], skill_tags=["pattern_vs_medium"]),
        mcq("M7L1_D8", "Which statement best matches one pad after a pulse has passed?", ["It returns near its original place while later pads respond", "It keeps drifting with the pulse forever", "It becomes the new source", "It stores the whole wave inside itself"], 0, "The pad does not become the traveling wave; it just takes its turn in the pattern.", ["medium_moves_with_wave_confusion"], skill_tags=["local_oscillation"]),
    ]
    concept = [
        short("M7L1_C1", "Why is a wave not the same thing as the pads moving across the field?", ["Because the disturbance travels while the pads only oscillate locally.", "Because the pattern moves across the medium, but the medium stays near its own place."], "Separate travel of the pattern from motion of the medium.", ["medium_moves_with_wave_confusion"], acceptance_rules=acceptance_groups(["pattern", "disturbance", "wave"], ["travels", "moves across"], ["pad", "medium"], ["local", "in place", "oscillate"]), skill_tags=["pattern_vs_medium"]),
        mcq("M7L1_C2", "Which observation best supports the idea that the medium does not travel with the wave?", ["Different pads pulse in turn while each one stays near its starting place", "The same pad glows brightly", "The source repeats the pulse", "The wall reflects the pulse"], 0, "Pads take turns moving, but they do not march across the stadium.", ["medium_moves_with_wave_confusion"], skill_tags=["evidence_reasoning"]),
        mcq("M7L1_C3", "A Front Line joins which pads?", ["Pads at the same stage of the cycle", "Pads with the biggest amplitude only", "Only pads nearest the source", "Pads that travel fastest"], 0, "A wavefront is about phase, not amplitude or location alone.", ["front_line_phase_confusion"], skill_tags=["phase_front"]),
        short("M7L1_C4", "How can a wave carry energy if the medium is not carried all the way across?", ["Because the disturbance transfers energy from one part of the medium to the next while each part only moves locally.", "Because energy passes along the pattern even though the material itself mainly oscillates in place."], "Focus on disturbance transfer, not medium travel.", ["energy_disturbance_confusion"], acceptance_rules=acceptance_groups(["energy"], ["transfer", "passes", "moves along"], ["pattern", "disturbance"], ["medium", "material", "pads"], ["local", "in place", "oscillate"]), skill_tags=["energy_transfer"]),
        mcq("M7L1_C5", "If a front crosses 12 m in 3 s, what is the wave speed?", ["4 m/s", "9 m/s", "36 m/s", "0.25 m/s"], 0, "Wave speed is distance divided by time for the moving front.", ["wave_speed_relation_confusion"], skill_tags=["wave_speed_basic"]),
        mcq("M7L1_C6", "Which statement best keeps wave travel and local motion separate?", ["The front crosses the arena while each pad pulses where it is", "The pads march across the arena in rows", "Only the source pad moves", "The whole stadium floor flows with the wave"], 0, "Keep the local response and the traveling pattern as different ideas.", ["medium_moves_with_wave_confusion"], skill_tags=["pattern_vs_medium"]),
    ]
    transfer = [
        short("M7L1_M1", "A ripple crosses 18 m in 6 s. What is its Ripple Run?", ["3 m/s", "3", "3 m s^-1"], "Use wave speed = distance / time.", ["wave_speed_relation_confusion"], acceptance_rules=acceptance_groups(["3", "3.0"], ["m/s", "m s^-1", "meters per second", "metres per second"]), skill_tags=["wave_speed_basic"]),
        mcq("M7L1_M2", "In a stadium crowd wave, what is most like the wave?", ["The pattern moving around the stadium", "One student running around the stadium", "All students changing seats permanently", "The stadium roof vibrating"], 0, "The pattern travels while each person only stands and sits locally.", ["medium_moves_with_wave_confusion"], skill_tags=["pattern_vs_medium"]),
        short("M7L1_M3", "In a stadium wave, what travels even though each person only stands and sits locally?", ["The pattern travels around the stadium.", "The disturbance pattern moves around, not the people."], "State what travels and what stays local.", ["medium_moves_with_wave_confusion"], acceptance_rules=acceptance_groups(["pattern", "disturbance", "wave"], ["travels", "moves around"], ["not", "rather than"], ["people", "pads", "medium"]), skill_tags=["pattern_vs_medium"]),
        mcq("M7L1_M4", "Two pads light up on the same Front Line. What does that tell you?", ["They are in the same phase", "They have the same mass", "They are both sources", "They move with different speeds"], 0, "Wavefronts connect same-phase points.", ["front_line_phase_confusion"], skill_tags=["phase_front"]),
        mcq("M7L1_M5", "Which explanation is strongest for a bobbing cork on water?", ["It moves mostly up and down while the ripple energy moves across", "It proves the water travels with the wave", "It becomes part of the source", "It always moves in a straight line with the wave"], 0, "Use local oscillation plus traveling disturbance language.", ["medium_moves_with_wave_confusion", "energy_disturbance_confusion"], skill_tags=["evidence_reasoning"]),
        short("M7L1_M6", "Why can two pads 4 m apart still belong to the same Front Line?", ["Because a front line joins points that are in the same phase even at different positions.", "Because they can be at the same stage of the pattern at the same time."], "Use same-phase language.", ["front_line_phase_confusion"], acceptance_rules=acceptance_groups(["same", "matching"], ["phase", "stage"], ["front line", "wavefront"]), skill_tags=["phase_front"]),
        mcq("M7L1_M7", "A pulse takes 2.5 s to cross 10 m. Which speed matches the wave?", ["4 m/s", "25 m/s", "12.5 m/s", "0.25 m/s"], 0, "Speed is distance / time: 10 / 2.5 = 4.", ["wave_speed_relation_confusion"], skill_tags=["wave_speed_basic"]),
        short("M7L1_M8", "Why is the sentence 'the pads move across the arena' a weak wave description?", ["Because the pads only move locally while the disturbance pattern crosses the arena.", "Because the pattern crosses the arena, not the medium itself."], "The wave is the travel pattern, not the medium drifting across.", ["medium_moves_with_wave_confusion"], acceptance_rules=acceptance_groups(["pad", "medium"], ["local", "oscillate", "pulse"], ["pattern", "disturbance", "wave"], ["crosses", "travels across"]), skill_tags=["pattern_vs_medium"]),
    ]
    return lesson_spec(
        lesson_id="M7_L1",
        title="Traveling Patterns and Local Pulses",
        sim_meta=sim("m7_travel_pattern_lab", "Travel pattern lab", "Watch a front cross the Signal-Stadium while each pad only pulses locally.", ["Start with one traveling front and watch which quantity belongs to the pad and which belongs to the front.", "Move the front farther across the board without changing the local oscillation size.", "Compare the front crossing time with one pad's local motion story."], ["Separate local pad motion from traveling pattern motion.", "Use front-line language correctly.", "Calculate a simple wave speed from distance and time."], ["beat_rate_hz", "front_position_m", "pad_amplitude_cm", "wave_speed_m_per_s"], "Use it to anchor the first wave idea: the pattern travels while the medium pulses locally."),
        diagnostic=diagnostic,
        analogy_text="In the Signal-Stadium, the Beat Tower launches a front across many signal pads. Each pad pulses where it is, but the front pattern crosses the stadium. That is the same distinction a real wave needs: local motion at each point, yet a traveling disturbance overall.",
        commitment_prompt="Before the formal language appears, decide which part of the story travels and which part only responds locally.",
        micro_prompts=[prompt_block("What is moving across the stadium: the pads or the pattern?", "Name the traveler and the local responder separately."), prompt_block("How could the arena carry energy if the pads do not migrate across it?", "Think disturbance transfer rather than bulk travel.")],
        inquiry=[prompt_block("Watch one pad and one front together. Which one crosses the arena?", "The crossing quantity is the pattern, not the pad."), prompt_block("Track how long the front takes to cross a known distance.", "That lets you calculate Ripple Run directly.")],
        recon_prompts=["Explain the difference between local oscillation and pattern travel in one sentence.", "Use the phrase Front Line to describe what several pads can share at once."],
        capsule_prompt="Keep the traveling-pattern anchor visible before you label wave types or formulas.",
        capsule_checks=concept,
        transfer=transfer,
        contract_payload=contract(
            concept_targets=["Distinguish local motion from the traveling pattern.", "Explain that waves transfer energy without carrying the whole medium across.", "Use front-line language for same-phase positions."],
            core_concepts=["A wave is a traveling disturbance pattern, not the bulk medium moving across.", "Each point in the medium responds locally as the pattern passes.", "A wavefront joins points that are in the same phase.", "Wave speed can be found from distance traveled by the front divided by time."],
            prerequisite_lessons=["F2_L3"],
            misconception_focus=["medium_moves_with_wave_confusion", "energy_disturbance_confusion", "front_line_phase_confusion", "wave_speed_relation_confusion"],
            formulas=[relation("wave speed = distance / time", "Wave speed tells how quickly the front crosses the medium.", ["m/s"], "Use when the front travel distance and time are known.")],
            representations=[representation("words", "States the distinction between local pad motion and traveling pattern."), representation("formula", "Connects front distance and crossing time to wave speed."), representation("diagram", "Shows the same front crossing several pads while each pad only pulses locally.")],
            analogy_map=stadium_map("the class is separating local pad motion from pattern travel"),
            worked_examples=[worked("A front crosses four pads. Each pad rises briefly then settles. What is traveling?", ["Notice that each pad only moves when the front reaches it.", "Compare one pad's local motion with the order in which later pads respond.", "Name the quantity that progresses across the row."], "The disturbance pattern is traveling; each pad only pulses locally.", "Successive pads respond in turn, so the traveler is the pattern rather than any one pad.", "This example blocks the very common mistake of treating the medium itself as the wave."), worked("A ripple crosses 12 m in 3 s. Find the Ripple Run.", ["Identify the front travel distance and the front travel time.", "Use wave speed = distance / time.", "Divide 12 by 3 and keep the speed unit."], "4 m/s", "The front covers 12 m every 3 s, so it travels 4 m each second.", "A simple speed calculation gives students a quantitative anchor before v = f lambda appears."), worked("Two pads are far apart but on the same Front Line. What does that mean?", ["Recall that a wavefront joins positions at the same stage of the cycle.", "Ignore the distance between the pads for this question.", "Describe what the two pads share instead."], "They are in the same phase.", "Wavefronts organize same-phase positions, not nearest-neighbor distance.", "This keeps wavefront language precise before reflection and refraction are introduced.")],
            visual_assets=[visual("m7-l1-travel-pattern", "travel_pattern", "Traveling pattern, local pads", "Shows one front crossing a line of pads while each pad only moves around its own position.", "The pattern travels across the stadium, while each pad only pulses locally.", template="wave_diagram", meta={"wave_type": "travel_pattern"})],
            animation_assets=[animation("m7-l1-pad-sequence", "travel_pattern", "Pads respond one after another", "Shows one front crossing the row while pads pulse locally in sequence rather than drifting across the arena.")],
            simulation_contract=sim_contract(asset_id="m7-l1-travel-pattern-lab", concept="travel_pattern", focus_prompt="Which quantity belongs to the local pad, and which belongs to the traveling pattern?", baseline_case="Start with one front crossing evenly spaced pads while one selected pad pulses locally.", comparison_tasks=["Push the front farther across the arena without changing the selected pad amplitude.", "Change the beat rate and compare which number belongs to the source and which belongs to one pad."], watch_for="The selected pad should still stay near one place even while the front keeps advancing across the board.", takeaway="The core wave anchor is that the pattern travels while each point in the medium only pulses locally.", controls=[("beat_rate", "Beat rate", "Shows how often the source launches fronts."), ("front_position", "Front position", "Makes the traveling pattern visible apart from any one pad."), ("pad_amplitude", "Pad amplitude", "Shows the local motion size without implying that the pad travels across the arena.")], readouts=[("Selected pad motion", "Shows what one pad is doing locally right now."), ("Front travel distance", "Shows how far the pattern has crossed the stadium."), ("Ripple Run", "Shows the front speed from its travel distance and time.")]),
            reflection_prompts=["What is moving across the stadium: the pads or the pattern?", "How can a wave transfer energy without carrying the whole medium across?"],
            mastery_skills=["pattern_vs_medium", "local_oscillation", "phase_front", "wave_speed_basic", "energy_transfer"],
            variation_plan={"diagnostic": "Fresh attempts rotate among pattern-vs-medium prompts, same-phase prompts, and simple front-speed items so the opening check does not repeat the same stem.", "concept_gate": "Concept checks vary between same-phase language, energy-transfer language, and local-motion evidence before unlocking the explorer.", "mastery": "Mastery mixes conceptual explanations with simple front-speed calculations and new contexts like stadium waves or water ripples before any stem repeats."},
            scaffold_support=scaffold("A wave is a traveling pattern built from local motion at many points in the medium.", "Watch one pad first, then watch the whole front. The pad only pulses in place, but the front crosses the arena. That is how the model protects local motion from pattern travel.", "If one pad returns near its starting place after the front passes, what part of the story is still traveling onward?", "Do not say the medium itself marches across the arena with the wave. The pattern moves on; the local point just takes its turn.", "The Signal-Stadium helps because each pad is visibly local while the front line is visibly traveling.", "In the analogy, what is the difference between what the Beat Tower sends and what one pad does when that signal reaches it?", extra_sections=[extra_section("Front Lines", "A Front Line joins pads that are in the same phase. It is not the path of one pad; it is a map of the traveling pattern at one moment.", "Why can two pads far apart still sit on the same Front Line?"), extra_section("Energy without bulk travel", "The pattern can carry energy onward because one region pushes or pulls the next, even though no single pad has to cross the whole arena.", "What is transferred onward if the pad itself is not?")]),
            visual_clarity_checks=visual_checks("travel-pattern"),
        ),
    )


def lesson_l2() -> Dict[str, Any]:
    diagnostic = [
        mcq("M7L2_D1", "A ripple travels to the right while each pad moves up and down. Which wave style is this?", ["Cross-Sway Mode (transverse)", "Push-Squeeze Mode (longitudinal)", "Neither", "Both at once"], 0, "Compare local pad motion with travel direction.", ["transverse_direction_confusion"], skill_tags=["wave_type_classification"]),
        mcq("M7L2_D2", "A sound-style ripple has compressions and rarefactions along the same line it travels. Which mode matches?", ["Push-Squeeze Mode (longitudinal)", "Cross-Sway Mode (transverse)", "Reflection", "Diffraction"], 0, "Longitudinal motion is parallel to propagation.", ["longitudinal_direction_confusion"], skill_tags=["wave_type_classification"]),
        short("M7L2_D3", "What decides whether a wave is transverse or longitudinal?", ["The direction of local motion compared with the direction the wave travels.", "Whether the disturbance is perpendicular or parallel to the direction of travel."], "Use a comparison between local motion and propagation.", ["transverse_direction_confusion", "longitudinal_direction_confusion"], acceptance_rules=acceptance_groups(["motion", "disturbance", "particle"], ["compare", "relative", "with"], ["direction of travel", "wave direction", "propagation"], ["perpendicular", "parallel"]), skill_tags=["motion_vs_propagation"]),
        mcq("M7L2_D4", "If local motion is perpendicular to propagation, what is the angle between them?", ["90 degrees", "0 degrees", "45 degrees", "180 degrees"], 0, "Perpendicular directions meet at 90 degrees.", ["transverse_direction_confusion"], skill_tags=["angle_relation"]),
        mcq("M7L2_D5", "If local motion is parallel to propagation, what is the angle between them?", ["0 degrees", "90 degrees", "45 degrees", "It cannot be described"], 0, "Parallel directions point along the same line.", ["longitudinal_direction_confusion"], skill_tags=["angle_relation"]),
        mcq("M7L2_D6", "Which statement best matches one transverse run?", ["The medium moves across the travel direction while the pattern goes forward.", "The medium travels with the wave.", "Only the source moves.", "The wave must travel upward."], 0, "Transverse describes local motion relative to travel direction.", ["transverse_direction_confusion", "medium_moves_with_wave_confusion"], skill_tags=["direction_language"]),
        short("M7L2_D7", "Why is 'the wave goes up and down' a weak definition of transverse?", ["Because transverse compares local motion with propagation, not the wave's overall path on the page.", "Because you must compare disturbance direction with travel direction, not just say up and down."], "Use relation language, not page-direction language.", ["transverse_direction_confusion"], acceptance_rules=acceptance_groups(["compare", "relative"], ["local motion", "disturbance"], ["travel direction", "propagation"], ["not", "rather than"], ["up and down", "page direction"]), skill_tags=["direction_language"]),
        mcq("M7L2_D8", "A row of air particles repeatedly bunches and spreads left-right while the pattern also moves left-right. Which label fits best?", ["Longitudinal wave", "Transverse wave", "Stationary wave", "Reflected wave"], 0, "Parallel local motion and propagation means longitudinal.", ["longitudinal_direction_confusion"], skill_tags=["representation_match"]),
    ]
    concept = [
        mcq("M7L2_C1", "Which pair correctly matches wave type to local motion?", ["Transverse -> perpendicular, longitudinal -> parallel", "Transverse -> parallel, longitudinal -> perpendicular", "Both -> perpendicular", "Both -> parallel"], 0, "Keep the comparison with propagation visible.", ["transverse_direction_confusion", "longitudinal_direction_confusion"], skill_tags=["wave_type_classification"]),
        short("M7L2_C2", "Why can a transverse wave still travel horizontally even if the pads move vertically?", ["Because the local pad motion can be vertical while the pattern itself propagates horizontally.", "Because transverse means local motion is perpendicular to travel, not that the whole wave travels vertically."], "Separate local motion from propagation direction.", ["transverse_direction_confusion", "medium_moves_with_wave_confusion"], acceptance_rules=acceptance_groups(["local motion", "pads", "disturbance"], ["vertical", "up and down"], ["pattern", "wave"], ["horizontal", "propagates", "travels"], ["perpendicular"]), skill_tags=["motion_vs_propagation"]),
        mcq("M7L2_C3", "Which stadium run is Push-Squeeze Mode?", ["Pads compress and spread along the direction the front moves", "Pads sway sideways while the front moves forward", "Pads stay still while the wall moves", "A front bounces at a wall"], 0, "Push-Squeeze is the longitudinal mode.", ["longitudinal_direction_confusion"], skill_tags=["representation_match"]),
        mcq("M7L2_C4", "What one comparison must be made before naming a wave type?", ["Compare disturbance direction with propagation direction", "Compare amplitude with wavelength", "Compare source height with wave speed", "Compare reflection with refraction"], 0, "Wave type is decided by a directional comparison.", ["transverse_direction_confusion", "longitudinal_direction_confusion"], skill_tags=["motion_vs_propagation"]),
        mcq("M7L2_C5", "A ripple has local motion at 90 degrees to travel direction. Which label fits?", ["Transverse", "Longitudinal", "Refraction", "Diffraction"], 0, "90 degrees means perpendicular.", ["transverse_direction_confusion"], skill_tags=["angle_relation"]),
        short("M7L2_C6", "Why is sound in air modeled as longitudinal in this lesson?", ["Because the air particles vibrate back and forth parallel to the direction the sound travels.", "Because the compressions and rarefactions form along the same line as the wave direction."], "Use parallel-motion language.", ["longitudinal_direction_confusion"], acceptance_rules=acceptance_groups(["particles", "air", "compressions", "rarefactions"], ["parallel", "same line", "along"], ["direction of travel", "wave direction", "propagation"]), skill_tags=["direction_language"]),
    ]
    transfer = [
        mcq("M7L2_M1", "A rope pulse moves right while the rope moves up-down. What type is the wave?", ["Transverse", "Longitudinal", "Neither", "Reflected"], 0, "The local motion is perpendicular to travel.", ["transverse_direction_confusion"], skill_tags=["wave_type_classification"]),
        short("M7L2_M2", "State one defining feature of a longitudinal wave.", ["The local disturbance is parallel to the direction of travel.", "Particles oscillate back and forth along the same line the wave moves."], "Give a parallel-motion definition.", ["longitudinal_direction_confusion"], acceptance_rules=acceptance_groups(["parallel", "same line", "along"], ["travel direction", "propagation", "wave direction"]), skill_tags=["direction_language"]),
        mcq("M7L2_M3", "A stadium display shows pads swaying left-right while fronts move forward. Which mode is shown?", ["Cross-Sway Mode", "Push-Squeeze Mode", "Bounce Wall Mode", "Gate Spread Mode"], 0, "Sideways local motion relative to forward travel is Cross-Sway.", ["transverse_direction_confusion"], skill_tags=["representation_match"]),
        mcq("M7L2_M4", "Which statement is false for a longitudinal wave?", ["Local motion is perpendicular to propagation", "Compressions and rarefactions can form", "Local motion is parallel to propagation", "The pattern can still travel"], 0, "Perpendicular motion would make it transverse instead.", ["longitudinal_direction_confusion"], skill_tags=["wave_type_classification"]),
        short("M7L2_M5", "Why is 'sideways motion' not enough by itself to prove a wave is transverse?", ["Because you must know sideways relative to the direction of travel.", "Because transverse depends on a comparison with propagation, not just one page direction."], "Sideways compared with what?", ["transverse_direction_confusion"], acceptance_rules=acceptance_groups(["compare", "relative"], ["sideways", "local motion", "disturbance"], ["direction of travel", "propagation"]), skill_tags=["motion_vs_propagation"]),
        mcq("M7L2_M6", "If local motion and propagation are parallel, what is the angle between them?", ["0 degrees", "90 degrees", "180 degrees", "30 degrees"], 0, "Parallel means angle 0 degrees.", ["longitudinal_direction_confusion"], skill_tags=["angle_relation"]),
        mcq("M7L2_M7", "Which everyday example best fits a transverse description?", ["A string pulse moving along a rope", "Sound compressions in air", "Air pumped through a syringe", "Water flowing through a pipe"], 0, "A rope pulse gives perpendicular local motion and travel.", ["transverse_direction_confusion"], skill_tags=["representation_match"]),
        short("M7L2_M8", "A student says, 'The wave is vertical, so it must be transverse.' Why is that weak reasoning?", ["Because wave type depends on disturbance direction relative to propagation, not on whether the drawing looks vertical.", "Because you must compare local motion with wave travel, not just describe the picture."], "Use relative-direction language.", ["transverse_direction_confusion"], acceptance_rules=acceptance_groups(["compare", "relative"], ["disturbance", "local motion"], ["propagation", "travel"], ["not", "rather than"], ["picture", "drawing", "vertical"]), skill_tags=["direction_language"]),
    ]
    return lesson_spec(
        lesson_id="M7_L2",
        title="Cross-Sway and Push-Squeeze",
        sim_meta=sim("m7_mode_match_lab", "Mode match lab", "Switch between Cross-Sway and Push-Squeeze so wave type comes from local motion relative to travel direction.", ["Start with one front moving right and compare sideways pad motion with forward squeeze motion.", "Use the motion arrows to compare perpendicular and parallel cases.", "Explain the angle between local motion and travel direction in both modes."], ["Classify transverse and longitudinal waves correctly.", "Use relation language instead of page-direction language.", "Keep local motion separate from propagation."], ["mode_toggle", "travel_direction_deg", "pad_motion_angle_deg", "beat_rate_hz"], "Use it to compare transverse and longitudinal motion inside one stadium."),
        diagnostic=diagnostic,
        analogy_text="The Signal-Stadium can run in Cross-Sway Mode, where the pads move across the direction the front travels, or Push-Squeeze Mode, where the pads bunch and spread along the direction the front travels. The wave type comes from that comparison.",
        commitment_prompt="Before using the labels transverse or longitudinal, decide how local motion lines up with the wave's travel.",
        micro_prompts=[prompt_block("If the front travels right but one pad moves up and down, what relationship do you see?", "Name the angle or the word perpendicular."), prompt_block("If compressions move right and the particles also move left-right, what relationship do you see?", "Name the word parallel.")],
        inquiry=[prompt_block("Switch between Cross-Sway and Push-Squeeze. Which thing changes: the travel direction or the local motion rule?", "Keep propagation fixed and compare the pad response."), prompt_block("Read the angle between the local motion arrow and the travel arrow.", "90 degrees signals transverse; 0 degrees signals longitudinal.")],
        recon_prompts=["Describe transverse and longitudinal by comparing local motion with wave travel.", "Explain why a page direction such as 'up-down' is not enough on its own."],
        capsule_prompt="Keep the local-motion-versus-propagation comparison visible before naming the wave type.",
        capsule_checks=concept,
        transfer=transfer,
        contract_payload=contract(
            concept_targets=["Classify transverse and longitudinal waves from the relation between local motion and propagation.", "Use perpendicular and parallel precisely when describing wave type.", "Block the misconception that page direction alone decides wave type."],
            core_concepts=["Wave type is decided by comparing local disturbance direction with propagation direction.", "Transverse waves have local motion perpendicular to propagation.", "Longitudinal waves have local motion parallel to propagation.", "Page direction words like up and down are not enough unless they are compared with the wave's travel direction."],
            prerequisite_lessons=["M7_L1"],
            misconception_focus=["transverse_direction_confusion", "longitudinal_direction_confusion", "medium_moves_with_wave_confusion"],
            formulas=[relation("transverse: disturbance ⟂ propagation; longitudinal: disturbance ∥ propagation", "Wave type comes from the geometric relation between local disturbance direction and propagation direction.", ["degrees"], "Use when classifying a wave as transverse or longitudinal.")],
            representations=[representation("words", "Defines the two wave styles by directional comparison."), representation("model", "Shows Cross-Sway and Push-Squeeze in the Signal-Stadium."), representation("formula", "Compresses the perpendicular/parallel classification into a compact symbolic relation.")],
            analogy_map=stadium_map("the class is comparing local pad motion with propagation direction"),
            worked_examples=[worked("A front moves right while the pads move up and down. What type is the wave?", ["Name the travel direction first.", "Name the local pad motion second.", "Compare them: they are perpendicular."], "The wave is transverse.", "Transverse means local disturbance perpendicular to propagation.", "This keeps students from using vague page-language instead of a directional comparison."), worked("Sound travels right through air while the air particles oscillate left-right. What type is the wave?", ["Track the wave's travel direction.", "Track the particle motion direction.", "Compare them: both are along the same line."], "The wave is longitudinal.", "Longitudinal means the disturbance is parallel to the direction of travel.", "This blocks the mistake of treating sound as transverse because of how it is drawn."), worked("A student says a wave is transverse because the diagram is tall and vertical. Why is that weak?", ["Ignore the page layout first.", "Ask how one point in the medium moves.", "Compare that local motion with the direction the wave propagates."], "The claim is weak because wave type depends on the motion-propagation relation, not the picture's orientation.", "A diagram can be drawn many ways, but the physical classification still comes from relative direction.", "This keeps the wave-type rule robust across different drawings.")],
            visual_assets=[visual("m7-l2-mode-match", "wave_type", "Cross-Sway and Push-Squeeze", "Shows the same travel direction with two different local-motion rules.", "Wave style depends on the relation between local motion and travel direction.", template="wave_diagram", meta={"wave_type": "wave_mode_compare"})],
            animation_assets=[animation("m7-l2-mode-toggle", "wave_type", "Mode toggle", "Shows the same front moving forward while the local pad response switches between perpendicular and parallel motion.")],
            simulation_contract=sim_contract(asset_id="m7-l2-mode-match-lab", concept="wave_type", focus_prompt="Is the local disturbance perpendicular or parallel to the wave's travel?", baseline_case="Start with a right-moving front and switch the pads between Cross-Sway and Push-Squeeze.", comparison_tasks=["Keep propagation fixed and compare 90 degree local motion with 0 degree local motion.", "Reverse the travel direction and check that the classification still comes from the relation, not the page layout."], watch_for="Students should compare local motion with travel direction rather than using words like up or down without context.", takeaway="Transverse and longitudinal are relation words: they compare disturbance direction with propagation.", controls=[("mode", "Wave mode", "Switches between Cross-Sway and Push-Squeeze."), ("travel_direction", "Travel direction", "Shows that page direction alone is not the classification rule."), ("motion_angle", "Local motion angle", "Makes the perpendicular or parallel relation explicit.")], readouts=[("Wave style", "Shows whether the current run is transverse or longitudinal."), ("Motion-travel angle", "Shows the angle between local motion and propagation."), ("Propagation arrow", "Shows the direction the pattern is traveling.")]),
            reflection_prompts=["How can you tell whether a stadium ripple is Cross-Sway or Push-Squeeze?", "Why is 'up and down' not enough on its own to define a transverse wave?"],
            mastery_skills=["wave_type_classification", "motion_vs_propagation", "angle_relation", "representation_match", "direction_language"],
            variation_plan={"diagnostic": "Fresh attempts rotate between classification cases, angle comparisons, and weak-definition critiques so students do not keep seeing the same rope or sound stem.", "concept_gate": "Concept checks vary between direct mode classification and explanation of why page direction is not enough.", "mastery": "Mastery mixes new contexts, angle-language items, and explanation prompts so the final bank remains broad and lesson-owned."},
            scaffold_support=scaffold("Wave type is set by how one point in the medium moves compared with the direction the pattern travels.", "Name the wave's travel direction, then name the local motion. Only after that comparison should you say transverse or longitudinal.", "If a point in the medium moves at 90 degrees to the front's travel, which mode is shown?", "Do not call a wave transverse just because the picture rises and falls on the page. The comparison with propagation is what matters.", "Cross-Sway and Push-Squeeze keep the travel direction fixed while the local pad rule changes, so the classification stays relational.", "What must stay visible in your mind before you use the words transverse or longitudinal?", extra_sections=[extra_section("Perpendicular and Parallel", "Perpendicular means 90 degrees to the direction of travel; parallel means along the same line as the direction of travel.", "Which angle belongs to a transverse wave?"), extra_section("Page direction trap", "A diagram can be rotated, redrawn, or viewed from another angle. The physics classification still comes from local motion relative to propagation.", "Why can two diagrams with different orientation still represent the same wave type?")]),
            visual_clarity_checks=visual_checks("wave-type"),
        ),
    )


def lesson_l3() -> Dict[str, Any]:
    diagnostic = [
        mcq("M7L3_D1", "What does Beat Rate measure?", ["How many fronts are launched each second", "How far apart the fronts are", "How wide the barrier is", "How high the wall is"], 0, "Beat Rate is frequency.", ["wave_speed_relation_confusion"], skill_tags=["frequency_meaning"]),
        mcq("M7L3_D2", "What does Pulse Gap measure?", ["The spacing between matching fronts", "The energy in one pad", "The wall angle", "The source height"], 0, "Pulse Gap is wavelength.", ["wave_speed_relation_confusion"], skill_tags=["wavelength_meaning"]),
        mcq("M7L3_D3", "A wave has f = 5 Hz and λ = 2 m. What is v?", ["10 m/s", "7 m/s", "3 m/s", "2.5 m/s"], 0, "Use v = f lambda.", ["wave_speed_relation_confusion"], skill_tags=["wave_equation_use"]),
        short("M7L3_D4", "State the wave-speed relation for Beat Rate, Pulse Gap, and Ripple Run.", ["v = f lambda", "wave speed = frequency x wavelength", "Ripple Run = Beat Rate x Pulse Gap"], "The wave relation multiplies frequency by wavelength.", ["wave_speed_relation_confusion"], acceptance_rules=acceptance_groups(["v", "wave speed", "ripple run"], ["=", "is"], ["f", "frequency", "beat rate"], ["lambda", "wavelength", "pulse gap"]), skill_tags=["wave_equation_use"]),
        mcq("M7L3_D5", "If a front crosses 24 m in 3 s, what is Ripple Run?", ["8 m/s", "21 m/s", "72 m/s", "0.125 m/s"], 0, "Use distance / time for speed.", ["wave_speed_relation_confusion"], skill_tags=["wave_speed_basic"]),
        mcq("M7L3_D6", "Which quantity is set by the source?", ["Frequency", "Wave speed in the medium", "Refraction angle", "Diffraction spread only"], 0, "The source sets how often it launches fronts.", ["frequency_sets_speed_confusion"], skill_tags=["source_vs_medium"]),
        short("M7L3_D7", "Why is it weak to say 'higher frequency always means a faster wave'?", ["Because wave speed also depends on the medium, so in one new medium the wavelength can change instead.", "Because frequency, wavelength, and speed are linked, and a boundary can change speed while the source keeps frequency fixed."], "Do not treat frequency as the only driver of wave speed in every situation.", ["frequency_sets_speed_confusion"], acceptance_rules=acceptance_groups(["speed", "wave speed"], ["depends", "also depends"], ["medium", "pace zone"], ["frequency"], ["wavelength", "lambda", "can change", "adjusts"]), skill_tags=["source_vs_medium"]),
        mcq("M7L3_D8", "If v = 12 m/s and f = 3 Hz, what is λ?", ["4 m", "9 m", "15 m", "36 m"], 0, "Rearrange lambda = v / f.", ["wave_speed_relation_confusion"], skill_tags=["formula_rearrangement"]),
    ]
    concept = [
        mcq("M7L3_C1", "Which sentence best defines wavelength?", ["Distance between matching points on neighboring fronts", "Number of fronts each second", "Time for one front to leave the source", "Amount of energy per front"], 0, "Wavelength is a spacing idea.", ["wave_speed_relation_confusion"], skill_tags=["wavelength_meaning"]),
        short("M7L3_C2", "How does the equation v = fλ connect Beat Rate and Pulse Gap to Ripple Run?", ["Wave speed equals frequency multiplied by wavelength.", "Ripple Run comes from how often fronts are launched and how far apart matching fronts are."], "Use rate-times-spacing language.", ["wave_speed_relation_confusion"], acceptance_rules=acceptance_groups(["speed", "ripple run"], ["equals", "comes from"], ["frequency", "beat rate"], ["wavelength", "pulse gap"]), skill_tags=["wave_equation_use"]),
        mcq("M7L3_C3", "A source keeps the same frequency, but the wave enters a new medium. Which quantity can change because of the medium?", ["Wave speed", "Source frequency", "The fact that it is a wave", "Number of peaks drawn on the page"], 0, "The medium controls the speed; the source keeps the frequency.", ["frequency_sets_speed_confusion"], skill_tags=["source_vs_medium"]),
        mcq("M7L3_C4", "If Beat Rate doubles while Pulse Gap stays the same in one medium, what happens to Ripple Run?", ["It doubles", "It halves", "It stays the same", "It becomes zero"], 0, "v = f lambda so doubling f doubles v if lambda stays fixed.", ["wave_speed_relation_confusion"], skill_tags=["wave_equation_use"]),
        short("M7L3_C5", "Why should students not treat v = fλ as if frequency alone sets speed in all situations?", ["Because the medium matters too, so at boundaries frequency can stay fixed while speed and wavelength change.", "Because the equation links three quantities, and a new medium can change wave speed without the source changing frequency."], "The medium-source distinction matters.", ["frequency_sets_speed_confusion"], acceptance_rules=acceptance_groups(["medium", "new medium", "pace zone"], ["changes", "can change"], ["speed", "wavelength", "lambda"], ["frequency"], ["stays", "stays fixed", "source keeps"]), skill_tags=["source_vs_medium"]),
        mcq("M7L3_C6", "A wave has λ = 0.5 m and f = 8 Hz. What is v?", ["4 m/s", "8.5 m/s", "16 m/s", "0.0625 m/s"], 0, "Multiply frequency by wavelength.", ["wave_speed_relation_confusion"], skill_tags=["wave_equation_use"]),
    ]
    transfer = [
        mcq("M7L3_M1", "A Beat Tower launches 6 fronts each second and matching fronts are 1.5 m apart. What is Ripple Run?", ["9 m/s", "4 m/s", "7.5 m/s", "1.5 m/s"], 0, "Use v = f lambda.", ["wave_speed_relation_confusion"], skill_tags=["wave_equation_use"]),
        short("M7L3_M2", "What is Beat Rate in formal wave language?", ["Frequency", "f", "Beat Rate is frequency."], "Beat Rate is the source frequency.", ["wave_speed_relation_confusion"], acceptance_rules=acceptance_groups(["frequency", "f"], ["beat rate"]), skill_tags=["frequency_meaning"]),
        mcq("M7L3_M3", "If a wave speed is 20 m/s and its frequency is 4 Hz, what is the Pulse Gap?", ["5 m", "16 m", "24 m", "80 m"], 0, "Rearrange lambda = v / f.", ["wave_speed_relation_confusion"], skill_tags=["formula_rearrangement"]),
        short("M7L3_M4", "Why is source frequency a source setting rather than a medium setting?", ["Because the source decides how many fronts are launched each second.", "Because the Beat Tower controls the launch rate, while the medium affects how the fronts travel."], "Keep source and medium roles separate.", ["frequency_sets_speed_confusion"], acceptance_rules=acceptance_groups(["source", "beat tower"], ["decides", "sets", "controls"], ["how many fronts", "frequency", "beat rate"], ["each second"]), skill_tags=["source_vs_medium"]),
        mcq("M7L3_M5", "Which quantity changes if matching fronts are farther apart while the beat rate stays fixed?", ["Wave speed", "Frequency only", "Neither", "Reflection angle"], 0, "With v = f lambda, bigger lambda at fixed f means bigger v.", ["wave_speed_relation_confusion"], skill_tags=["wavelength_meaning"]),
        mcq("M7L3_M6", "A wave crosses 30 m in 5 s. If its frequency is 2 Hz, what is the wavelength?", ["3 m", "6 m", "10 m", "15 m"], 0, "Speed is 6 m/s, then lambda = 6 / 2.", ["wave_speed_relation_confusion"], skill_tags=["multi_step_wave_equation"]),
        short("M7L3_M7", "Why can two waves have the same Ripple Run but different Beat Rates?", ["Because a lower frequency can be matched by a larger wavelength, or a higher frequency by a smaller wavelength, to keep v the same.", "Because wave speed depends on the product of frequency and wavelength, so different pairs can give the same speed."], "Same speed does not force the same f or lambda separately.", ["wave_speed_relation_confusion"], acceptance_rules=acceptance_groups(["speed", "ripple run"], ["same"], ["frequency", "beat rate"], ["wavelength", "lambda"], ["different", "can differ", "compensate", "product"]), skill_tags=["equation_reasoning"]),
        mcq("M7L3_M8", "Which sentence best keeps the equation conceptual?", ["Wave speed comes from how often fronts are launched and how far apart matching fronts are", "Wave speed is just a formula to memorize", "Frequency always changes the medium", "Wavelength is the same as amplitude"], 0, "Keep the physical meaning visible.", ["wave_speed_relation_confusion"], skill_tags=["equation_reasoning"]),
    ]
    return lesson_spec(
        lesson_id="M7_L3",
        title="Beat Rate, Pulse Gap, and Ripple Run",
        sim_meta=sim("m7_vflambda_lab", "Beat-Rate and Pulse-Gap lab", "Change frequency and wavelength deliberately so the relation v = f lambda becomes visible.", ["Start with a steady source and measure the spacing between matching fronts.", "Change beat rate while holding pulse gap fixed, then change pulse gap while holding beat rate fixed.", "Rebuild the same speed with a different pair of frequency and wavelength values."], ["Use v = f lambda conceptually and numerically.", "Separate the source setting from the medium setting.", "Rearrange the relation when one variable is unknown."], ["beat_rate_hz", "pulse_gap_m", "ripple_run_m_per_s", "front_cross_time_s"], "Use it to make the wave-speed relation visible as a system, not a formula-only rule."),
        diagnostic=diagnostic,
        analogy_text="In the Signal-Stadium, the Beat Tower sets how many fronts leave each second, the Pulse Gap shows how far apart matching fronts are, and the Ripple Run shows how quickly the front crosses the arena. Those three ideas belong together.",
        commitment_prompt="Before using the symbol form, decide which quantity is a source rate, which is a spacing, and which is the crossing speed.",
        micro_prompts=[prompt_block("If the tower launches more fronts each second, which quantity changes first?", "Start with the source setting, not the medium."), prompt_block("If matching fronts are farther apart, which quantity has changed?", "That is the wavelength story.")],
        inquiry=[prompt_block("Keep one variable fixed and change the other so you can see how the product builds the speed.", "Do not change everything at once."), prompt_block("Try two different pairs of beat rate and pulse gap that give the same Ripple Run.", "That shows the equation is a relationship, not a single-value rule.")],
        recon_prompts=["Explain v = f lambda in words before you use it in numbers.", "State which quantity the source sets and which quantity a new medium can change."],
        capsule_prompt="Keep the physical meaning of frequency, wavelength, and speed visible before you calculate.",
        capsule_checks=concept,
        transfer=transfer,
        contract_payload=contract(
            concept_targets=["Define frequency, wavelength, and wave speed clearly.", "Use v = f lambda conceptually and numerically.", "Protect the source-versus-medium distinction in wave problems."],
            core_concepts=["Frequency is the number of fronts launched each second by the source.", "Wavelength is the spacing between matching points on neighboring fronts.", "Wave speed links frequency and wavelength through v = f lambda.", "The source sets frequency, while the medium can affect wave speed and therefore wavelength."],
            prerequisite_lessons=["M7_L1", "M7_L2"],
            misconception_focus=["wave_speed_relation_confusion", "frequency_sets_speed_confusion"],
            formulas=[relation("v = f lambda", "Wave speed equals frequency multiplied by wavelength.", ["m/s", "Hz", "m"], "Use for waves in a given situation when frequency and wavelength are linked to speed.")],
            representations=[representation("words", "Explains Beat Rate, Pulse Gap, and Ripple Run in stadium language."), representation("formula", "Shows the formal relation v = f lambda."), representation("table", "Compares different pairs of frequency and wavelength that produce different or equal speeds.")],
            analogy_map=stadium_map("the class is connecting launch rate, front spacing, and front speed"),
            worked_examples=[worked("A wave has f = 4 Hz and lambda = 3 m. Find the speed.", ["Identify the known frequency and wavelength.", "Use v = f lambda.", "Multiply 4 by 3 and attach m/s."], "12 m/s", "The relation multiplies fronts per second by meters per front to give meters per second.", "This example anchors the equation in units and meaning."), worked("A wave moves at 18 m/s with frequency 6 Hz. Find the wavelength.", ["Start from v = f lambda.", "Rearrange to lambda = v / f.", "Divide 18 by 6 and attach meters."], "3 m", "If each second contains 6 fronts and the front pattern covers 18 m, the matching fronts must be 3 m apart.", "This example shows that rearranging the formula keeps the same physical story."), worked("Why can two waves have the same speed but different frequencies?", ["Recall that speed depends on the product f lambda.", "Imagine one wave with more fronts per second but smaller spacing.", "Compare it with another wave with fewer fronts per second but wider spacing."], "Because different frequency-wavelength pairs can produce the same product.", "The equation links the quantities, so same speed does not force the same frequency or wavelength separately.", "This keeps the relation conceptual rather than purely mechanical.")],
            visual_assets=[visual("m7-l3-vflambda", "wave_equation", "Beat Rate, Pulse Gap, and Ripple Run", "Shows launch rate, front spacing, and front speed on one board.", "Wave speed comes from the product of frequency and wavelength.", template="wave_diagram", meta={"wave_type": "wave_equation"})],
            animation_assets=[animation("m7-l3-front-spacing", "wave_equation", "Spacing and rate together", "Shows fronts leaving faster or farther apart so students can compare how the crossing speed changes.")],
            simulation_contract=sim_contract(asset_id="m7-l3-vflambda-lab", concept="wave_equation", focus_prompt="How do Beat Rate and Pulse Gap combine to make Ripple Run?", baseline_case="Start with one steady launch rate and one visible front spacing, then read the resulting speed.", comparison_tasks=["Double the Beat Rate and compare the new Ripple Run while Pulse Gap stays fixed.", "Keep Beat Rate fixed but widen the Pulse Gap to compare the new Ripple Run."], watch_for="Students should keep frequency as a source setting and avoid saying it alone determines speed in every context.", takeaway="v = f lambda is a relationship among rate, spacing, and speed, not a memorized slogan.", controls=[("beat_rate", "Beat rate", "Changes how many fronts launch each second."), ("pulse_gap", "Pulse gap", "Changes the spacing between matching fronts."), ("cross_distance", "Track distance", "Lets learners connect crossing distance and time to wave speed.")], readouts=[("Beat Rate", "Shows the source frequency in Hz."), ("Pulse Gap", "Shows wavelength as front spacing."), ("Ripple Run", "Shows wave speed in m/s from the current setup.")]),
            reflection_prompts=["Why does the equation v = f lambda make physical sense in the Signal-Stadium?", "Why is it weak to say frequency alone determines wave speed in every situation?"],
            mastery_skills=["frequency_meaning", "wavelength_meaning", "wave_equation_use", "formula_rearrangement", "source_vs_medium"],
            variation_plan={"diagnostic": "Fresh attempts alternate between definition items, direct substitutions, rearrangements, and source-versus-medium prompts.", "concept_gate": "Concept checks vary between qualitative explanation of the formula and simple numerical application.", "mastery": "Mastery mixes multi-step speed questions, rearrangements, and conceptual same-speed/different-frequency reasoning before stems repeat."},
            scaffold_support=scaffold("Wave speed is built from how often fronts are launched and how far apart matching fronts are.", "Say what each symbol means first: frequency is launch rate, wavelength is front spacing, and speed is how fast the front crosses the arena. Then use the relation.", "If the source sends more fronts each second while spacing stays fixed, what happens to the speed?", "Do not treat v = f lambda as if frequency automatically sets speed in every medium. The relation has three linked quantities.", "The stadium keeps the launch rate and front spacing visible at the same time, so the speed relation feels like one coherent system.", "What do Beat Rate and Pulse Gap each contribute to Ripple Run?", extra_sections=[extra_section("Source versus medium", "The Beat Tower sets the frequency. A new medium or pace zone can change speed, which then changes wavelength if the frequency stays fixed.", "Which quantity is most directly set by the source?"), extra_section("Same speed, different pair", "Different frequency-wavelength pairs can still give the same speed if their product matches.", "Can two different front patterns cross the arena at the same speed?")]),
            visual_clarity_checks=visual_checks("wave-equation"),
        ),
    )


def lesson_l4() -> Dict[str, Any]:
    diagnostic = [
        mcq("M7L4_D1", "What is a Bounce Wall in formal wave language?", ["A reflecting boundary", "A slower medium", "A source", "A diffraction gate"], 0, "Bounce Wall means reflection.", ["reflection_angle_confusion"], skill_tags=["reflection_classification"]),
        mcq("M7L4_D2", "A front hits a flat wall at 30 degrees to the normal. What is the reflected angle to the normal?", ["30 degrees", "60 degrees", "15 degrees", "90 degrees"], 0, "Reflection keeps equal incident and reflected angles.", ["reflection_angle_confusion"], skill_tags=["angle_of_reflection"]),
        short("M7L4_D3", "What simple geometry rule does reflection keep at a flat wall?", ["The angle of incidence equals the angle of reflection.", "Incident angle equals reflected angle."], "State the equal-angle rule.", ["reflection_angle_confusion"], acceptance_rules=acceptance_groups(["angle of incidence", "incident angle"], ["equals", "same as"], ["angle of reflection", "reflected angle"]), skill_tags=["angle_of_reflection"]),
        mcq("M7L4_D4", "Which line should the reflection angles be measured from?", ["The normal to the wall", "The wall surface", "The source tower", "The wavefront itself"], 0, "Angles are measured from the normal.", ["reflection_angle_confusion"], skill_tags=["normal_line"]),
        mcq("M7L4_D5", "Which statement best distinguishes reflection from refraction?", ["Reflection is a bounce at a boundary; refraction is a turn in a new medium", "Reflection always speeds the wave up", "Refraction always means a wall", "They are just two names for the same effect"], 0, "Keep bounce and medium-change turning separate.", ["reflection_refraction_mixup"], skill_tags=["boundary_reasoning"]),
        mcq("M7L4_D6", "If the incident front strikes the wall head-on along the normal, what happens after reflection?", ["It goes back along the same line", "It turns 90 degrees", "It speeds up", "It diffracts around the wall"], 0, "Head-on reflection retraces the line.", ["reflection_angle_confusion"], skill_tags=["boundary_reasoning"]),
        short("M7L4_D7", "Why should reflection angles be measured from the normal instead of the wall surface?", ["Because the reflection rule is written as equal angles to the normal.", "Because the normal gives the standard reference line for comparing incident and reflected directions."], "Use reference-line language.", ["reflection_angle_confusion"], acceptance_rules=acceptance_groups(["normal"], ["reference", "measured from", "standard line"], ["incident", "reflected", "reflection rule"]), skill_tags=["normal_line"]),
        mcq("M7L4_D8", "A reflected front leaves a flat wall. Which statement stays true?", ["Reflected angle matches incident angle", "Frequency must double", "The medium has changed", "The wave becomes longitudinal"], 0, "A reflecting wall preserves the reflection geometry.", ["reflection_angle_confusion"], skill_tags=["wavefront_reflection"]),
    ]
    concept = [
        mcq("M7L4_C1", "What one phrase best summarizes wave reflection at a flat wall?", ["Equal angles to the normal", "Same speed in every direction", "Wavefronts stop at the wall", "Frequency becomes zero"], 0, "Reflection keeps equal angles.", ["reflection_angle_confusion"], skill_tags=["angle_of_reflection"]),
        short("M7L4_C2", "Why is a Bounce Wall not the same as a Pace Zone?", ["Because a Bounce Wall reflects the wave back, while a Pace Zone changes speed and can refract it.", "Because reflection is a boundary bounce, not a speed-change turn through a new medium."], "Compare reflection with refraction clearly.", ["reflection_refraction_mixup"], acceptance_rules=acceptance_groups(["bounce wall", "reflection"], ["bounce", "reflect", "back"], ["pace zone", "new medium", "refraction"], ["speed change", "turn"]), skill_tags=["boundary_reasoning"]),
        mcq("M7L4_C3", "Which diagram clue shows the normal line?", ["A line drawn perpendicular to the wall", "A line drawn along the wall", "A line connecting two wave peaks", "Any arrow from the source"], 0, "The normal is perpendicular to the boundary.", ["reflection_angle_confusion"], skill_tags=["normal_line"]),
        mcq("M7L4_C4", "If an incident ray makes 50 degrees to the normal, the reflected ray makes:", ["50 degrees to the normal", "40 degrees to the normal", "50 degrees to the wall", "100 degrees to the wall"], 0, "Same angle, same reference line.", ["reflection_angle_confusion"], skill_tags=["angle_of_reflection"]),
        short("M7L4_C5", "Why does a wavefront 'bounce' rather than pass straight through a reflecting wall?", ["Because the boundary reflects the disturbance back into the original medium.", "Because a reflecting wall redirects the wave back instead of letting it continue into a new medium."], "Use boundary-redirect language.", ["reflection_refraction_mixup"], acceptance_rules=acceptance_groups(["boundary", "wall"], ["reflects", "redirects", "bounces"], ["back", "into the original medium", "away from the wall"]), skill_tags=["wavefront_reflection"]),
        mcq("M7L4_C6", "Which sentence best matches head-on reflection?", ["The reflected wave retraces the incident path", "The reflected wave travels along the wall", "The reflected wave must refract", "The reflected wave must stop"], 0, "Head-on to the normal means same line back.", ["reflection_angle_confusion"], skill_tags=["boundary_reasoning"]),
    ]
    transfer = [
        mcq("M7L4_M1", "A ray strikes a mirror at 25 degrees to the normal. What is the reflected angle?", ["25 degrees", "65 degrees", "50 degrees", "115 degrees"], 0, "Use equal angles.", ["reflection_angle_confusion"], skill_tags=["angle_of_reflection"]),
        short("M7L4_M2", "State the reflection law for a plane boundary.", ["Angle of incidence equals angle of reflection.", "The incident angle equals the reflected angle."], "Keep both angles tied to the normal.", ["reflection_angle_confusion"], acceptance_rules=acceptance_groups(["incident", "incidence"], ["equals", "same as"], ["reflection", "reflected"]), skill_tags=["angle_of_reflection"]),
        mcq("M7L4_M3", "A wavefront diagram shows a line drawn at right angles to the wall. What is that line?", ["The normal", "The wavelength", "The amplitude", "The source path"], 0, "Right angles to the wall define the normal.", ["reflection_angle_confusion"], skill_tags=["normal_line"]),
        mcq("M7L4_M4", "Which comparison is correct?", ["Reflection is a bounce; refraction is a turn in a new medium", "Reflection and refraction both require the same medium speed", "Reflection always changes frequency", "Refraction is just a special kind of reflection"], 0, "Keep the boundary stories separate.", ["reflection_refraction_mixup"], skill_tags=["boundary_reasoning"]),
        short("M7L4_M5", "Why is measuring from the wall surface itself a risky way to use the reflection law?", ["Because the equal-angle law is defined relative to the normal, not the wall surface.", "Because the normal is the correct reference line for comparing incident and reflected directions."], "Name the correct reference line.", ["reflection_angle_confusion"], acceptance_rules=acceptance_groups(["normal"], ["reference", "measured from", "correct line"], ["not"], ["wall surface"]), skill_tags=["normal_line"]),
        mcq("M7L4_M6", "An incident ray is 10 degrees to the wall surface. What is its angle to the normal?", ["80 degrees", "10 degrees", "90 degrees", "100 degrees"], 0, "Normal and surface are 90 degrees apart.", ["reflection_angle_confusion"], skill_tags=["normal_line"]),
        mcq("M7L4_M7", "The incident ray is 80 degrees to the normal. Which reflected angle matches?", ["80 degrees to the normal", "10 degrees to the normal", "80 degrees to the wall", "20 degrees to the wall"], 0, "Angle equality uses the normal.", ["reflection_angle_confusion"], skill_tags=["angle_of_reflection"]),
        short("M7L4_M8", "Why is a reflecting wall a boundary behavior rather than a medium-change behavior?", ["Because the wave is redirected at the same boundary instead of entering a new medium with a different speed.", "Because reflection is a bounce at a boundary, not a speed-change turn into another region."], "Separate bounce from refraction.", ["reflection_refraction_mixup"], acceptance_rules=acceptance_groups(["reflection", "reflecting wall", "boundary"], ["bounce", "redirect"], ["not"], ["new medium", "speed change", "refraction"]), skill_tags=["wavefront_reflection"]),
    ]
    return lesson_spec(
        lesson_id="M7_L4",
        title="Bounce Walls and Front Lines",
        sim_meta=sim("m7_reflection_wall_lab", "Bounce Wall lab", "Send wavefronts toward a flat wall and read the equal-angle geometry from the normal.", ["Start with a diagonal front and draw the normal line first.", "Measure the incident angle to the normal, then compare the reflected angle.", "Repeat with a head-on hit to see the path retrace itself."], ["Explain reflection as a boundary bounce.", "Use the normal correctly.", "Apply equal-angle reflection numerically."], ["incident_angle_deg", "wall_angle_deg", "reflected_angle_deg", "normal_line"], "Use it to make reflection a geometry story rather than a memorized slogan."),
        diagnostic=diagnostic,
        analogy_text="A Bounce Wall sends the front back across the Signal-Stadium. The key geometric question is how the incident direction compares with the reflected direction when both are measured from the normal line.",
        commitment_prompt="Before solving any angle question, identify the boundary and draw the normal.",
        micro_prompts=[prompt_block("What reference line should reflection angles be measured from?", "Do not measure from the wall surface."), prompt_block("If the front hits head-on along the normal, what path should it follow after reflection?", "Think retrace.")],
        inquiry=[prompt_block("Rotate the incident direction and watch how the reflected direction changes.", "The two angles should stay matched to the normal."), prompt_block("Compare a Bounce Wall with a Pace Zone boundary.", "One bounces; the other turns because speed changes.")],
        recon_prompts=["Explain why reflection is a bounce rather than a medium-change turn.", "State the reflection law using the normal."],
        capsule_prompt="Keep the normal line and the equal-angle rule visible before you read any reflected path.",
        capsule_checks=concept,
        transfer=transfer,
        contract_payload=contract(
            concept_targets=["Explain reflection as a boundary bounce.", "Use the normal line as the reference for reflection angles.", "Apply equal-angle reflection in words and numbers."],
            core_concepts=["Reflection is a change of direction at a boundary.", "For a flat reflector, the angle of incidence equals the angle of reflection.", "Both reflection angles are measured from the normal to the boundary.", "Head-on reflection sends the wave back along the same line."],
            prerequisite_lessons=["M7_L1", "M7_L3"],
            misconception_focus=["reflection_angle_confusion", "reflection_refraction_mixup"],
            formulas=[relation("angle of incidence = angle of reflection", "Reflection at a flat boundary keeps equal angles measured from the normal.", ["degrees"], "Use for a plane reflecting boundary.")],
            representations=[representation("words", "States the reflection law and the role of the normal."), representation("diagram", "Shows incident front, normal, wall, and reflected front."), representation("formula", "Compresses the equal-angle rule into one statement.")],
            analogy_map=stadium_map("the class is reading reflection geometry from a Bounce Wall"),
            worked_examples=[worked("A ray strikes a wall at 35 degrees to the normal. Find the reflected angle.", ["Read the incident angle from the normal.", "Apply the equal-angle reflection rule.", "Keep the same reference line for the answer."], "35 degrees to the normal", "Plane reflection keeps equal incident and reflected angles to the normal.", "This gives a clear numerical anchor for the rule."), worked("A front hits the wall head-on along the normal. What happens next?", ["Notice that the incident angle is zero.", "Apply equal-angle reflection.", "Describe the outgoing path."], "It returns along the same line.", "If the incident angle is zero, the reflected angle is also zero, so the path retraces itself.", "This helps students understand the extreme case instead of just the general picture."), worked("A student measures the ray angle from the wall surface and gets confused. What should they do instead?", ["Draw the normal line first.", "Convert any surface-based angle into a normal-based angle if needed.", "Apply the law using the normal."], "Measure from the normal, not from the wall surface.", "The reflection law is defined relative to the normal, so the normal is the correct reference line.", "This blocks a very common reflection-angle mistake.")],
            visual_assets=[visual("m7-l4-bounce-wall", "reflection", "Bounce Wall reflection", "Shows a front hitting a flat wall with the normal line and equal reflected geometry.", "Reflection is a boundary bounce measured from the normal.", template="wave_diagram", meta={"wave_type": "reflection"})],
            animation_assets=[animation("m7-l4-reflection-bounce", "reflection", "Front bounce", "Shows an incoming front meeting a wall and leaving with matching geometry to the normal.")],
            simulation_contract=sim_contract(asset_id="m7-l4-bounce-wall-lab", concept="reflection", focus_prompt="How does the front leave the wall when you measure both directions from the normal?", baseline_case="Start with one diagonal front striking a flat wall and display the normal line clearly.", comparison_tasks=["Change the incident angle and compare the reflected angle.", "Send the front head-on along the normal and compare that special case."], watch_for="Students should measure incident and reflected angles from the normal, not from the wall surface.", takeaway="Reflection is a predictable boundary bounce with equal incident and reflected angles.", controls=[("incident_angle", "Incident angle", "Changes how the front approaches the wall."), ("wall_orientation", "Wall orientation", "Changes the normal line and therefore the measured geometry."), ("front_spacing", "Front spacing", "Keeps the wavefront pattern visible as geometry changes.")], readouts=[("Incident angle", "Shows the incoming angle to the normal."), ("Reflected angle", "Shows the outgoing angle to the normal."), ("Normal line", "Shows the reference line required for reflection.")]),
            reflection_prompts=["Why must reflection angles be measured from the normal?", "How is a Bounce Wall different from a Pace Zone boundary?"],
            mastery_skills=["reflection_classification", "angle_of_reflection", "normal_line", "wavefront_reflection", "boundary_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between equal-angle questions, normal-line questions, and reflection-versus-refraction distinctions.", "concept_gate": "Concept checks vary between explanation of the normal and direct equal-angle applications.", "mastery": "Mastery mixes angle calculations, reference-line conversions, and explanation prompts about reflection as boundary bounce."},
            scaffold_support=scaffold("Reflection is a boundary bounce whose geometry is read from the normal line.", "Draw the normal first. Then compare the incident direction with the reflected direction using that same reference line.", "What one line should be drawn before you trust any reflection angle on a diagram?", "Do not measure from the wall surface and then call it the incident angle in the reflection law. The law is about angles to the normal.", "The Bounce Wall keeps the same stadium world but reverses the front direction in a predictable geometric way.", "In the analogy, what does the normal line help you compare?", extra_sections=[extra_section("Head-on reflection", "When the incident path lies along the normal, the angle is zero and the reflected path retraces the same line.", "What happens to the path when the incident angle is zero?"), extra_section("Bounce versus turn", "Reflection is a bounce at a boundary. Refraction is a turn in a new medium because speed changes there.", "Why is a Pace Zone not a Bounce Wall?")]),
            visual_clarity_checks=visual_checks("reflection"),
        ),
    )


def lesson_l5() -> Dict[str, Any]:
    diagnostic = [
        mcq("M7L5_D1", "What is a Pace Zone in formal wave language?", ["A medium where the wave speed may differ", "A reflecting wall", "A diffraction gate", "A source"], 0, "A Pace Zone stands for a medium.", ["boundary_frequency_change_confusion"], skill_tags=["refraction_classification"]),
        mcq("M7L5_D2", "What stays the same when a wave crosses into a new medium from the same source?", ["Frequency", "Wave speed", "Wavelength", "Direction in every case"], 0, "The source keeps the frequency fixed.", ["boundary_frequency_change_confusion"], skill_tags=["boundary_frequency_constant"]),
        mcq("M7L5_D3", "A wave enters a slower medium. Which quantity must change if frequency stays the same?", ["Wavelength", "Frequency", "Source beat rate", "The fact that it is a wave"], 0, "v = f lambda and fixed f means lambda must change with v.", ["boundary_frequency_change_confusion", "frequency_sets_speed_confusion"], skill_tags=["speed_wavelength_link"]),
        short("M7L5_D4", "Why does a front bend at a Pace Zone boundary?", ["Because the wave speed changes in the new medium.", "Because different parts of the front change speed as they enter the new medium."], "Refraction is a speed-change story.", ["reflection_refraction_mixup", "boundary_frequency_change_confusion"], acceptance_rules=acceptance_groups(["speed", "wave speed"], ["changes", "becomes slower", "becomes faster"], ["new medium", "pace zone", "boundary"]), skill_tags=["refraction_classification"]),
        mcq("M7L5_D5", "If a light wave enters a slower medium, how does it bend?", ["Toward the normal", "Away from the normal", "Back along its path", "It never bends"], 0, "Slower light bends toward the normal.", ["boundary_frequency_change_confusion"], skill_tags=["slower_medium_bending"]),
        mcq("M7L5_D6", "Which statement best distinguishes refraction from reflection?", ["Refraction is a turn caused by a speed change in a new medium", "Refraction is the same as bouncing off a wall", "Refraction always keeps the same wavelength", "Refraction needs no boundary"], 0, "Keep speed-change turning distinct from bouncing.", ["reflection_refraction_mixup"], skill_tags=["refraction_classification"]),
        short("M7L5_D7", "Why is it weak to say 'the wave bends because the frequency changed'?", ["Because the source keeps the frequency fixed across the boundary, and the speed change makes the wavelength change instead.", "Because refraction comes from a speed change in the new medium, not from the source changing frequency at the boundary."], "Use source-fixed frequency language.", ["boundary_frequency_change_confusion", "frequency_sets_speed_confusion"], acceptance_rules=acceptance_groups(["frequency"], ["stays", "fixed", "same"], ["source"], ["speed", "wavelength", "lambda"], ["changes", "adjusts"]), skill_tags=["boundary_frequency_constant"]),
        mcq("M7L5_D8", "If a wave enters a faster medium with the same frequency, what happens to wavelength?", ["It increases", "It decreases", "It becomes zero", "It must stay the same"], 0, "Higher speed at fixed frequency means larger wavelength.", ["boundary_frequency_change_confusion"], skill_tags=["speed_wavelength_link"]),
    ]
    concept = [
        mcq("M7L5_C1", "What causes refraction in the Signal-Stadium?", ["A change in wave speed across a boundary", "A reflection law", "A change in source frequency at the boundary", "A disappearing wavefront"], 0, "Refraction is a medium-speed story.", ["reflection_refraction_mixup"], skill_tags=["refraction_classification"]),
        short("M7L5_C2", "When a wave enters a new Pace Zone, which quantity belongs to the source and stays fixed?", ["Frequency stays fixed because it is set by the source.", "The Beat Rate stays the same because the source keeps launching fronts at the same rate."], "Use source-setting language.", ["boundary_frequency_change_confusion"], acceptance_rules=acceptance_groups(["frequency", "beat rate"], ["stays", "same", "fixed"], ["source"]), skill_tags=["boundary_frequency_constant"]),
        mcq("M7L5_C3", "If the speed falls in the new medium and frequency stays the same, what happens to wavelength?", ["It decreases", "It increases", "It stays the same", "It becomes unpredictable"], 0, "Smaller v at fixed f means smaller lambda.", ["boundary_frequency_change_confusion"], skill_tags=["speed_wavelength_link"]),
        mcq("M7L5_C4", "Which sentence best matches a slower medium for light?", ["The ray bends toward the normal", "The ray reflects with equal angles", "The ray must diffract more", "The frequency doubles"], 0, "This lesson uses the standard light refraction rule.", ["boundary_frequency_change_confusion"], skill_tags=["slower_medium_bending"]),
        short("M7L5_C5", "Why is refraction not just 'weird reflection'?", ["Because the wave enters a new medium where its speed changes, instead of bouncing back from a boundary.", "Because refraction is a speed-change turn through a new medium, while reflection is a bounce back."], "Compare the two boundary stories directly.", ["reflection_refraction_mixup"], acceptance_rules=acceptance_groups(["refraction"], ["new medium", "pace zone"], ["speed change", "turn"], ["reflection"], ["bounce", "back"]), skill_tags=["refraction_classification"]),
        mcq("M7L5_C6", "A wave enters a faster medium from the same source. Which combination is correct?", ["Same frequency, larger wavelength", "Larger frequency, same wavelength", "Smaller frequency, larger wavelength", "Same frequency, same wavelength"], 0, "Fixed source frequency with higher speed means larger wavelength.", ["boundary_frequency_change_confusion"], skill_tags=["speed_wavelength_link"]),
    ]
    transfer = [
        mcq("M7L5_M1", "A wave changes from 12 m/s to 8 m/s at a boundary while its frequency stays 4 Hz. What is the new wavelength?", ["2 m", "3 m", "4 m", "32 m"], 0, "Use lambda = v / f in the new medium.", ["boundary_frequency_change_confusion"], skill_tags=["boundary_calculation"]),
        short("M7L5_M2", "Why can frequency stay fixed while wavelength changes at a boundary?", ["Because the source still sets the frequency, but the new medium changes the wave speed.", "Because the launch rate is kept by the source while the medium changes how far apart matching fronts become."], "Keep source and medium roles separate.", ["boundary_frequency_change_confusion", "frequency_sets_speed_confusion"], acceptance_rules=acceptance_groups(["source", "beat tower"], ["frequency", "beat rate"], ["same", "fixed"], ["medium", "pace zone"], ["speed", "wavelength", "lambda"], ["changes"]), skill_tags=["boundary_frequency_constant"]),
        mcq("M7L5_M3", "A light ray enters a slower medium. Which statement is correct?", ["It bends toward the normal", "It bends away from the normal", "It always reflects completely", "Its frequency must rise"], 0, "Use the standard slower-medium bending rule for light.", ["boundary_frequency_change_confusion"], skill_tags=["slower_medium_bending"]),
        mcq("M7L5_M4", "If a wave goes from 5 m/s to 10 m/s with frequency 2 Hz unchanged, what happens to wavelength?", ["It doubles from 2.5 m to 5 m", "It halves", "It stays 2.5 m", "It becomes 20 m"], 0, "Higher speed at fixed f means higher lambda.", ["boundary_frequency_change_confusion"], skill_tags=["boundary_calculation"]),
        short("M7L5_M5", "What is the strongest reason a front turns at a Pace Zone boundary?", ["Different parts of the front enter the new speed zone at different times, so the front pivots.", "The front bends because one side changes speed before the other as it crosses the boundary."], "Use the front-pivot idea.", ["reflection_refraction_mixup", "boundary_frequency_change_confusion"], acceptance_rules=acceptance_groups(["front", "one side", "different parts"], ["change speed", "slower", "faster"], ["different times", "before the other", "pivots", "turns"]), skill_tags=["pace_zone_reasoning"]),
        mcq("M7L5_M6", "Which quantity would a source have to change deliberately to alter frequency?", ["Its launch rate", "The refracting boundary", "The wall angle", "The gate width"], 0, "Frequency is a source setting.", ["frequency_sets_speed_confusion"], skill_tags=["boundary_frequency_constant"]),
        mcq("M7L5_M7", "A wave crosses into a slower medium and still keeps the same frequency. What is strongest?", ["The wavelength becomes shorter", "The source launches fewer fronts each second", "The wave must reflect instead", "Nothing changes"], 0, "Fixed f with lower v means lower lambda.", ["boundary_frequency_change_confusion"], skill_tags=["speed_wavelength_link"]),
        short("M7L5_M8", "Why is 'frequency changed, so the wave bent' a weak explanation of refraction?", ["Because bending is caused by a speed change in the new medium while the source frequency stays fixed.", "Because the medium changes wave speed and wavelength; the source frequency does not suddenly change at the boundary."], "Keep the causal story with the medium.", ["frequency_sets_speed_confusion", "boundary_frequency_change_confusion"], acceptance_rules=acceptance_groups(["medium", "new medium", "pace zone"], ["changes", "sets"], ["speed", "wavelength", "lambda"], ["frequency"], ["stays", "same", "fixed"]), skill_tags=["pace_zone_reasoning"]),
    ]
    return lesson_spec(
        lesson_id="M7_L5",
        title="Pace Zones and Turn Bends",
        sim_meta=sim("m7_refraction_zone_lab", "Pace Zone lab", "Send fronts into slower and faster zones so speed change, wavelength change, and turning stay linked.", ["Launch one diagonal front at the boundary between two pace zones.", "Keep the source frequency fixed while you swap between slower and faster second zones.", "Read the speed and wavelength on each side of the boundary before explaining the bend."], ["Explain refraction as a speed-change turn.", "State that frequency stays fixed across the boundary.", "Calculate new wavelength from the new speed and fixed frequency."], ["zone_speed_m_per_s", "zone_frequency_hz", "wavelength_m", "turn_direction"], "Use it to make refraction a medium-change story rather than a bounce story."),
        diagnostic=diagnostic,
        analogy_text="A Pace Zone is a part of the Signal-Stadium where fronts travel at a different speed. When a diagonal front reaches that new zone, one part of the front changes speed before the rest, so the whole front turns.",
        commitment_prompt="Before you describe the bend, decide what changes at the boundary and what stays fixed because of the source.",
        micro_prompts=[prompt_block("At a Pace Zone boundary, which quantity is controlled by the source and should stay fixed?", "Do not let the boundary steal the source's job."), prompt_block("If the front slows down in the new zone, what else must change if frequency stays fixed?", "Use v = f lambda.")],
        inquiry=[prompt_block("Compare a slower second zone with a faster second zone.", "Look for speed and wavelength changes before you explain the turn."), prompt_block("Track what happens to one side of the front first.", "That helps explain why the whole front bends.")],
        recon_prompts=["Explain refraction as a speed-change turn rather than a bounce.", "State what happens to frequency and wavelength at the boundary."],
        capsule_prompt="Keep the source-fixed frequency and the medium-set speed visible before you describe the bending.",
        capsule_checks=concept,
        transfer=transfer,
        contract_payload=contract(
            concept_targets=["Explain refraction as turning caused by a speed change in a new medium.", "State that frequency stays fixed across the boundary.", "Use speed and wavelength changes together when describing a new medium."],
            core_concepts=["Refraction happens when a wave enters a new medium where its speed changes.", "The source keeps the frequency fixed across the boundary.", "If wave speed changes while frequency stays fixed, wavelength changes too.", "For light entering a slower medium, the ray bends toward the normal."],
            prerequisite_lessons=["M7_L3", "M7_L4"],
            misconception_focus=["reflection_refraction_mixup", "boundary_frequency_change_confusion", "frequency_sets_speed_confusion"],
            formulas=[relation("v = f lambda with f constant across the boundary", "At a boundary the source frequency stays fixed, so a speed change is matched by a wavelength change.", ["m/s", "Hz", "m"], "Use when a wave enters a new medium from the same source.")],
            representations=[representation("words", "Explains why speed change causes turning at a boundary."), representation("diagram", "Shows a front entering a new pace zone and bending."), representation("formula", "Keeps v = f lambda tied to the constant-frequency boundary rule.")],
            analogy_map=stadium_map("the class is explaining why a front turns in a new Pace Zone"),
            worked_examples=[worked("A wave enters a new medium with speed 6 m/s and frequency 3 Hz. Find the wavelength there.", ["Use lambda = v / f in the new medium.", "Substitute 6 and 3.", "Attach the wavelength unit."], "2 m", "With frequency fixed by the source, the new medium's speed sets the new wavelength.", "This ties the boundary story directly to the wave equation."), worked("Why does a front bend when one side enters the slower zone first?", ["Track one edge of the front as it crosses the boundary.", "Notice that the leading edge slows first.", "Describe how that changes the front's orientation."], "The front pivots because one side changes speed before the other.", "Refraction is a turning caused by uneven arrival into the new speed zone across the front.", "This keeps refraction geometric and causal rather than mysterious."), worked("A student says the wave bends because the frequency changed at the boundary. Why is that weak?", ["Recall what sets frequency.", "Identify what the new medium actually controls.", "State what quantity adjusts because of the speed change."], "The explanation is weak because the source keeps frequency fixed; the new medium changes speed, so wavelength adjusts.", "Boundaries do not reset the source frequency; they change wave speed through the medium.", "This directly blocks the common v = f lambda misconception.")],
            visual_assets=[visual("m7-l5-pace-zone", "refraction", "Pace Zone turn", "Shows one front entering a slower and faster zone with direction change, speed change, and wavelength change.", "Refraction is a turn caused by a speed change in a new medium.", template="wave_diagram", meta={"wave_type": "refraction"})],
            animation_assets=[animation("m7-l5-boundary-turn", "refraction", "Boundary turn", "Shows one side of the front entering the new zone first so the front bends as speed changes.")],
            simulation_contract=sim_contract(asset_id="m7-l5-pace-zone-lab", concept="refraction", focus_prompt="What changes at the boundary, and how does that produce the turning front?", baseline_case="Start with one diagonal front crossing from a faster zone into a slower zone while frequency stays fixed.", comparison_tasks=["Compare a slower second zone with a faster second zone.", "Keep the same source setting but swap the boundary to show that wavelength responds to the new speed."], watch_for="Students should describe frequency as source-set and speed as medium-set, then connect the speed change to wavelength and turning.", takeaway="Refraction is a speed-change turn in a new medium, not a weird form of reflection.", controls=[("zone_speed", "Second-zone speed", "Controls how fast the front can travel in the new medium."), ("frequency", "Source frequency", "Shows that the launch rate is held fixed by the source."), ("entry_angle", "Boundary approach angle", "Makes the turning front visible.")], readouts=[("Source frequency", "Shows the fixed frequency from the Beat Tower."), ("New-zone wavelength", "Shows the wavelength after speed changes in the second zone."), ("Turn direction", "Shows whether the ray bends toward or away from the normal.")]),
            reflection_prompts=["Why does the Pulse Gap change in a new Pace Zone even when the Beat Rate stays the same?", "Why is refraction not the same as reflection?"],
            mastery_skills=["refraction_classification", "boundary_frequency_constant", "speed_wavelength_link", "slower_medium_bending", "pace_zone_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between frequency-fixed prompts, wavelength-change prompts, and slower/faster-zone bending prompts.", "concept_gate": "Concept checks vary between identifying the cause of refraction and applying the constant-frequency idea.", "mastery": "Mastery mixes conceptual boundary reasoning with numerical speed-wavelength updates and new bending contexts."},
            scaffold_support=scaffold("Refraction is a turn caused by a speed change in a new medium, while the source frequency stays fixed.", "Ask three questions in order: what medium is the wave entering, what happens to speed there, and what must happen to wavelength if the source keeps frequency fixed?", "If the new medium is slower, what two linked changes should you expect besides the bend itself?", "Do not say the boundary changes the source frequency. The boundary changes the speed the medium allows.", "The Pace Zone makes the medium's role visible by changing the front speed without changing how often the Beat Tower launches fronts.", "Which quantity belongs to the Beat Tower and which belongs to the Pace Zone?", extra_sections=[extra_section("Toward or away from the normal", "For light, entering a slower medium bends the ray toward the normal, while entering a faster medium bends it away from the normal.", "What happens for light in a slower second zone?"), extra_section("Front pivot", "A diagonal front bends because one side of the front enters the new speed zone first, so the front rotates as it crosses.", "Why can one front turn even though the source keeps the same frequency?")]),
            visual_clarity_checks=visual_checks("refraction"),
        ),
    )


def lesson_l6() -> Dict[str, Any]:
    diagnostic = [
        mcq("M7L6_D1", "What is Gate Spread in formal wave language?", ["Diffraction", "Reflection", "Refraction", "Absorption"], 0, "Gate Spread stands for diffraction.", ["diffraction_opening_size_confusion"], skill_tags=["diffraction_classification"]),
        mcq("M7L6_D2", "When is diffraction most noticeable?", ["When the opening size is comparable to the wavelength", "When the wall is very shiny", "When frequency is zero", "When the source is switched off"], 0, "Comparable opening size and wavelength gives stronger spread.", ["diffraction_opening_size_confusion"], skill_tags=["opening_vs_wavelength"]),
        short("M7L6_D3", "Why does a narrow gate usually cause more spreading than a wide gate?", ["Because the opening size is closer to the wavelength, so diffraction is stronger.", "Because a narrow gap makes the wave bend and spread more when its size is comparable to lambda."], "Compare opening size with wavelength.", ["diffraction_opening_size_confusion"], acceptance_rules=acceptance_groups(["opening", "gap", "gate"], ["comparable", "similar", "closer"], ["wavelength", "lambda"], ["diffraction", "spreading"], ["stronger", "more"]), skill_tags=["opening_vs_wavelength"]),
        mcq("M7L6_D4", "Which statement is correct about diffraction?", ["It can happen for all waves", "It belongs only to sound", "It means the wave stops", "It only happens at mirrors"], 0, "Diffraction is a general wave behavior.", ["diffraction_sound_only_confusion"], skill_tags=["all_waves_diffraction"]),
        mcq("M7L6_D5", "A gap is very wide compared with the wavelength. What happens to the spread after the gap?", ["There is less noticeable diffraction", "There is maximum diffraction", "The wave must reflect instead", "The frequency doubles"], 0, "Wider-than-wavelength openings spread less strongly.", ["diffraction_opening_size_confusion"], skill_tags=["opening_vs_wavelength"]),
        mcq("M7L6_D6", "What best describes diffraction around an obstacle?", ["The wave bends around the edge into the hidden region", "The source frequency disappears", "The wall becomes a new source only", "The medium changes speed"], 0, "Diffraction is bending around edges or openings.", ["diffraction_opening_size_confusion"], skill_tags=["obstacle_spread"]),
        short("M7L6_D7", "Why is 'diffraction is only for sound' a weak claim?", ["Because all waves can diffract; it is just easier to notice in some cases.", "Because diffraction is a general wave behavior, not something unique to sound."], "Use all-waves language.", ["diffraction_sound_only_confusion"], acceptance_rules=acceptance_groups(["all", "any"], ["waves"], ["diffraction", "diffract"], ["not", "rather than"], ["only sound", "sound only"]), skill_tags=["all_waves_diffraction"]),
        mcq("M7L6_D8", "What comparison matters most when predicting diffraction strength at a gate?", ["Gap width compared with wavelength", "Amplitude compared with force", "Wall angle compared with time", "Frequency compared with density only"], 0, "Opening size versus wavelength is the key comparison.", ["diffraction_opening_size_confusion"], skill_tags=["comparative_reasoning"]),
    ]
    concept = [
        mcq("M7L6_C1", "What makes diffraction a boundary behavior rather than a wave source behavior?", ["It happens when a wave meets an opening or edge", "It changes the source frequency", "It replaces the medium with a new one", "It only belongs to the source tower"], 0, "Diffraction is about what boundaries do to the pattern.", ["diffraction_opening_size_confusion"], skill_tags=["diffraction_classification"]),
        short("M7L6_C2", "Why does a gap comparable to the wavelength give strong Gate Spread?", ["Because the opening size is similar to the wavelength, so the wave spreads strongly after the gap.", "Because diffraction is strongest when the gate size is of the same order as lambda."], "Use size-comparison language.", ["diffraction_opening_size_confusion"], acceptance_rules=acceptance_groups(["opening", "gap", "gate"], ["same size", "comparable", "similar"], ["wavelength", "lambda"], ["diffraction", "spread"], ["strong", "stronger", "large"]), skill_tags=["opening_vs_wavelength"]),
        mcq("M7L6_C3", "Which gate setup gives the strongest diffraction for a 2 cm wavelength?", ["A 2 cm opening", "A 40 cm opening", "A 1 m opening", "A wall with no opening at all"], 0, "Comparable size gives the strongest spread.", ["diffraction_opening_size_confusion"], skill_tags=["size_comparison"]),
        mcq("M7L6_C4", "What is the best reason a wave can reach a 'hidden corner' after a narrow gate?", ["The wavefront spreads after the opening", "The frequency becomes larger", "The reflected angle changes", "The source moves closer"], 0, "Diffraction sends the pattern into regions not directly in line with the opening.", ["diffraction_opening_size_confusion"], skill_tags=["obstacle_spread"]),
        short("M7L6_C5", "How is diffraction different from refraction?", ["Diffraction is spreading around openings or edges, while refraction is turning because wave speed changes in a new medium.", "Diffraction is a gate-or-edge spread, not a speed-change turn into another medium."], "Compare boundary causes, not just final directions.", ["reflection_refraction_mixup", "diffraction_opening_size_confusion"], acceptance_rules=acceptance_groups(["diffraction"], ["opening", "edge", "spread"], ["refraction"], ["speed change", "new medium", "turn"]), skill_tags=["comparative_reasoning"]),
        mcq("M7L6_C6", "Which sentence best matches a very wide opening?", ["The wave continues with only slight spreading", "The wave must stop", "The wave always bends 90 degrees", "The source frequency changes"], 0, "Wide openings diffract less dramatically.", ["diffraction_opening_size_confusion"], skill_tags=["size_comparison"]),
    ]
    transfer = [
        mcq("M7L6_M1", "A 5 cm wavelength meets a 5 cm gate. What should you expect?", ["Strong diffraction", "Almost no diffraction", "A reflection law only", "A frequency change"], 0, "Comparable sizes mean strong spread.", ["diffraction_opening_size_confusion"], skill_tags=["opening_vs_wavelength"]),
        short("M7L6_M2", "State one condition that makes diffraction especially noticeable.", ["When the opening size is comparable to the wavelength.", "When the gap width is similar to lambda."], "Use opening-versus-wavelength language.", ["diffraction_opening_size_confusion"], acceptance_rules=acceptance_groups(["opening", "gap", "gate"], ["comparable", "similar", "same order"], ["wavelength", "lambda"]), skill_tags=["opening_vs_wavelength"]),
        mcq("M7L6_M3", "Which wave can diffract through a doorway?", ["Any wave with wavelength comparable to the doorway size", "Only sound", "Only light", "Only water"], 0, "Diffraction is universal across waves.", ["diffraction_sound_only_confusion"], skill_tags=["all_waves_diffraction"]),
        mcq("M7L6_M4", "A 1 m wavelength meets a 20 m opening. Which outcome is strongest?", ["Little spreading", "Strong spreading", "Reflection only", "Zero transmission"], 0, "The opening is much larger than the wavelength.", ["diffraction_opening_size_confusion"], skill_tags=["size_comparison"]),
        short("M7L6_M5", "Why can a wave reach an area behind an obstacle edge?", ["Because diffraction bends the wave around the edge into that region.", "Because the wave spreads around the edge instead of staying in a straight narrow beam."], "Use edge-spread language.", ["diffraction_opening_size_confusion"], acceptance_rules=acceptance_groups(["diffraction", "spread", "bend"], ["around"], ["edge", "obstacle"], ["into", "reach"], ["region", "corner", "hidden area"]), skill_tags=["obstacle_spread"]),
        mcq("M7L6_M6", "Which pair shows stronger diffraction?", ["2 cm wavelength through a 2 cm gap", "2 cm wavelength through a 2 m gap", "2 mm wavelength through a 2 m gap", "All have the same diffraction"], 0, "Comparable sizes spread most strongly.", ["diffraction_opening_size_confusion"], skill_tags=["comparative_reasoning"]),
        mcq("M7L6_M7", "Which explanation best rejects the claim that diffraction belongs only to sound?", ["All waves can diffract; it is just easier to notice when size scales fit", "Only sound uses openings", "Light never reaches edges", "Water waves cannot bend"], 0, "The phenomenon is general, not sound-only.", ["diffraction_sound_only_confusion"], skill_tags=["all_waves_diffraction"]),
        short("M7L6_M8", "Why does a wide gate usually give less noticeable Gate Spread than a narrow one?", ["Because the wide opening is much larger than the wavelength, so diffraction is weaker.", "Because spreading is strongest when the gate size is closer to the wavelength, which is less true for a wide gate."], "Compare opening size to wavelength again.", ["diffraction_opening_size_confusion"], acceptance_rules=acceptance_groups(["wide", "larger"], ["opening", "gate", "gap"], ["much larger", "less comparable"], ["wavelength", "lambda"], ["diffraction", "spread"], ["weaker", "less"]), skill_tags=["comparative_reasoning"]),
    ]
    return lesson_spec(
        lesson_id="M7_L6",
        title="Gate Spread and Hidden Corners",
        sim_meta=sim("m7_diffraction_gate_lab", "Gate Spread lab", "Compare narrow and wide openings so diffraction becomes an opening-versus-wavelength story.", ["Launch one front toward a wide opening and then toward a narrow opening.", "Keep wavelength fixed and compare the spread patterns after the gate.", "Place an obstacle edge and compare how much signal reaches the hidden region."], ["Explain diffraction as spreading around openings and edges.", "Use opening-size versus wavelength language.", "State that diffraction belongs to all waves, not sound only."], ["wavelength_cm", "gate_width_cm", "spread_angle_deg", "edge_toggle"], "Use it to make diffraction a size-comparison boundary behavior."),
        diagnostic=diagnostic,
        analogy_text="In the Signal-Stadium, a gate can be wide or narrow. After the front passes through, it may continue mostly straight or spread strongly into a broad fan. The strongest spread appears when gate width is comparable to the Pulse Gap.",
        commitment_prompt="Before naming the spread, compare the opening size with the wavelength.",
        micro_prompts=[prompt_block("Which comparison matters most: gate width with amplitude, or gate width with wavelength?", "Pick the size comparison that actually controls diffraction."), prompt_block("Would a very wide gate or a gate close to one wavelength give stronger spread?", "Think comparable sizes.")],
        inquiry=[prompt_block("Hold wavelength fixed and narrow the gate.", "Watch how the spread pattern changes."), prompt_block("Now hold the gate fixed and change wavelength.", "See how the same gate can become more or less diffracting depending on lambda.")],
        recon_prompts=["Explain why a narrow gate spreads a wave more strongly than a very wide gate.", "State why diffraction is not limited to sound waves."],
        capsule_prompt="Keep the opening-size-versus-wavelength comparison visible before you judge how much the front will spread.",
        capsule_checks=concept,
        transfer=transfer,
        contract_payload=contract(
            concept_targets=["Explain diffraction as spreading around openings and edges.", "Use opening size compared with wavelength to judge diffraction strength.", "State that diffraction is a general wave behavior."],
            core_concepts=["Diffraction is the spreading of a wave around an opening or edge.", "Diffraction is strongest when the opening size is comparable to the wavelength.", "Very wide openings usually produce less noticeable diffraction.", "Diffraction can happen for all waves, not only sound waves."],
            prerequisite_lessons=["M7_L3", "M7_L5"],
            misconception_focus=["diffraction_opening_size_confusion", "diffraction_sound_only_confusion", "reflection_refraction_mixup"],
            formulas=[relation("strongest diffraction when opening size ≈ lambda", "Diffraction becomes more noticeable when the opening width is comparable to the wavelength.", ["m"], "Use as a comparison rule when judging diffraction strength.")],
            representations=[representation("words", "States the opening-versus-wavelength rule for diffraction."), representation("diagram", "Shows narrow and wide gates with different spread patterns."), representation("formula", "Compresses the strongest-diffraction condition into an opening-size comparison.")],
            analogy_map=stadium_map("the class is comparing gate width with wavelength to predict spreading"),
            worked_examples=[worked("A 4 cm wavelength meets a 4 cm opening. What should you predict?", ["Compare opening size with wavelength.", "Notice they are comparable.", "Use the diffraction strength rule."], "Strong diffraction", "Comparable opening size and wavelength make Gate Spread pronounced.", "This gives students a direct, predictive use of the comparison rule."), worked("A 4 cm wavelength meets a 40 cm opening. What should you predict now?", ["Compare the new opening size with the same wavelength.", "Notice the opening is much larger than lambda.", "Decide how the spread should change."], "Less noticeable diffraction", "A much wider opening reduces the relative size effect and the spreading becomes less dramatic.", "This contrast example helps students reason comparatively rather than memorizing one slogan."), worked("A student says diffraction only belongs to sound. Why is that weak?", ["Ask what diffraction actually is.", "Notice it is a wave behavior at openings and edges.", "Apply that to waves in general, not to one named topic."], "The claim is weak because diffraction can happen for all waves.", "Diffraction is a general wave behavior whose visibility depends on wavelength and opening size, not on whether the wave is sound.", "This protects students from a very common over-association with sound.")],
            visual_assets=[visual("m7-l6-gate-spread", "diffraction", "Gate Spread comparison", "Shows a wide gate and a narrow gate with different spread patterns plus an edge case.", "Diffraction is strongest when the opening size is comparable to the wavelength.", template="wave_diagram", meta={"wave_type": "diffraction"})],
            animation_assets=[animation("m7-l6-gate-fan", "diffraction", "Opening comparison", "Shows one front passing through openings of different widths and spreading by different amounts.")],
            simulation_contract=sim_contract(asset_id="m7-l6-gate-spread-lab", concept="diffraction", focus_prompt="How does the opening size compared with the wavelength change the spread pattern?", baseline_case="Start with one wavelength and compare a very wide gate with a gate close to one wavelength.", comparison_tasks=["Keep wavelength fixed and shrink the gate width.", "Keep gate width fixed and increase the wavelength to make the sizes more comparable."], watch_for="Students should talk about comparable size, not treat diffraction as a sound-only trick.", takeaway="Diffraction is opening-and-edge spreading, strongest when opening size and wavelength are similar.", controls=[("wavelength", "Wavelength", "Lets learners compare the same gate against different wave scales."), ("gate_width", "Gate width", "Directly changes how comparable the opening is to the wavelength."), ("edge_mode", "Edge mode", "Shows diffraction around an obstacle edge as well as through a gate.")], readouts=[("Wavelength", "Shows the current pulse gap."), ("Gate-width ratio", "Shows how opening size compares with wavelength."), ("Spread pattern", "Shows whether the outgoing front stays narrow or fans out strongly.")]),
            reflection_prompts=["Why does a narrow gate spread a wave more strongly than a wide gate?", "Why is it weak to say diffraction belongs only to sound?"],
            mastery_skills=["diffraction_classification", "opening_vs_wavelength", "obstacle_spread", "all_waves_diffraction", "comparative_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between gate-width comparisons, edge cases, and sound-only misconception checks.", "concept_gate": "Concept checks vary between qualitative size-comparison questions and explanation of hidden-region spreading.", "mastery": "Mastery mixes new wavelength-opening pairs, edge-spread explanations, and general all-wave diffraction statements before a stem repeats."},
            scaffold_support=scaffold("Diffraction is wave spreading around openings and edges, and it is strongest when the opening size is comparable to the wavelength.", "Compare the gate width with the wavelength before you predict the outgoing pattern. Then decide whether the front should stay narrow or fan out strongly.", "What opening-size comparison should you make first when judging how much a wave will spread after a gate?", "Do not treat diffraction as a sound-only fact or as random blurring. It is a predictable wave response to an opening or edge.", "The Signal-Stadium makes diffraction visual because one gate can be wide, narrow, or close to one wavelength while the front pattern stays visible throughout.", "In the analogy, why does a gate close to one Pulse Gap produce stronger spread?", extra_sections=[extra_section("Wide gate versus narrow gate", "A wide gate usually lets the front continue with only slight spread, while a gate close to one wavelength produces a much broader fan.", "Which gate gives the stronger spread for the same wavelength?"), extra_section("Edges and hidden corners", "Diffraction also happens around obstacle edges, which is why waves can reach regions that are not directly in line with the opening.", "How can a wave reach a hidden region behind an edge?")]),
            visual_clarity_checks=visual_checks("diffraction"),
        ),
    )


M7_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": (
        "Waves and vibrations: transverse and longitudinal waves, wave speed, reflection, refraction, and diffraction "
        "are read as travelling patterns built from local vibrations."
    ),
    "mastery_outcomes": [
        "Distinguish wave travel from local motion in the medium.",
        "Classify waves as transverse or longitudinal by comparing local motion with propagation direction.",
        "Define frequency, wavelength, and wave speed clearly.",
        "Use v = f lambda conceptually and numerically.",
        "Explain reflection as a boundary bounce with equal angles to the normal.",
        "Explain refraction as a turn caused by a speed change in a new medium while frequency stays fixed.",
        "Explain diffraction as spreading around openings and edges, strongest when opening size is comparable to wavelength.",
        "Use wavefront language to describe fronts, boundaries, and pattern travel across new contexts.",
    ],
    "lessons": [
        lesson_l1(),
        lesson_l2(),
        lesson_l3(),
        lesson_l4(),
        lesson_l5(),
        lesson_l6(),
    ],
}


RELEASE_CHECKS = [
    "Every lesson keeps the traveling-pattern idea distinct from local pad motion in the medium.",
    "Every lesson uses the Signal-Stadium analogy inside the lesson content while keeping the formal module introduction concise.",
    "Every worked example states why the answer follows, not just the classification or arithmetic.",
    "Every Try It in Action explorer is backed by lesson-specific simulation copy and contracts rather than generic fallback wording.",
    "Every lesson-owned assessment bank is broad enough to prefer unseen questions on fresh attempts before repeating earlier stems.",
    "Every boundary lesson keeps reflection, refraction, and diffraction as distinct stories instead of blending them into one vague boundary effect.",
]


M7_MODULE_DOC, M7_LESSONS, M7_SIM_LABS = build_nextgen_module_bundle(
    module_id=M7_MODULE_ID,
    module_title=M7_MODULE_TITLE,
    module_spec=M7_SPEC,
    allowlist=M7_ALLOWLIST,
    content_version=M7_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=11,
    level="Module 7",
    estimated_minutes=300,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M7 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    apply = bool(args.apply)
    asset_root = args.asset_root or default_asset_root()

    module_doc = deepcopy(M7_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M7_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M7_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M7_MODULE_ID)]
    plan.extend(("lessons", doc_id) for doc_id, _ in lesson_pairs)
    plan.extend(("sim_labs", doc_id) for doc_id, _ in sim_pairs)

    for collection, doc_id in plan:
        if collection == "modules":
            upsert_doc(db, collection, doc_id, module_doc, apply)
        elif collection == "lessons":
            payload = next(payload for payload_id, payload in lesson_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, apply)
        else:
            payload = next(payload for payload_id, payload in sim_pairs if payload_id == doc_id)
            upsert_doc(db, collection, doc_id, payload, apply)


if __name__ == "__main__":
    main()
