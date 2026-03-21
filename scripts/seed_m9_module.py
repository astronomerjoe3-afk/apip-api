from __future__ import annotations

import argparse
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


M9_MODULE_ID = "M9"
M9_CONTENT_VERSION = "20260321_m9_echo_scout_v2"
M9_MODULE_TITLE = "Sound"
M9_ALLOWLIST = [
    "sound_needs_vibration_confusion",
    "sound_as_air_stream_confusion",
    "local_particle_motion_confusion",
    "compression_rarefaction_confusion",
    "longitudinal_wave_confusion",
    "source_frequency_confusion",
    "pitch_loudness_confusion",
    "sound_speed_frequency_confusion",
    "audible_range_confusion",
    "ultrasound_not_sound_confusion",
    "echo_reflection_confusion",
    "echo_time_distance_confusion",
    "ultrasound_image_without_echo_confusion",
    "doppler_motion_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M9_ALLOWLIST)
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


def animation(asset_id: str, concept: str, title: str, description: str) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": concept,
        "phase_key": "analogical_grounding",
        "title": title,
        "description": description,
        "duration_sec": 8,
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
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery on every fresh attempt before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile.",
        "The compression bands, arrows, and echo routes do not overlap the explanation text.",
        "Every caption, frequency label, and ultrasound readout remains readable without clipping.",
        "The key physics comparison uses deliberate color contrast so source, medium, and measurement roles are not visually merged.",
        "Any calculation cue shown in the picture keeps the round-trip, frequency, or shift logic readable in one scan.",
    ]


def echo_scout_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Echo-Scout Model of Sound",
        "focus": focus,
        "comparison": f"The Echo-Scout arena keeps vibrating sources, pitch, ultrasound, echoes, and Doppler flow in one world while {focus}.",
        "mapping": [
            "Scout Beacon -> vibrating sound source",
            "Air Crowd -> medium / air particles",
            "Squeeze Band -> compression",
            "Release Band -> rarefaction",
            "Ping Rate -> frequency",
            "Tone Height -> pitch",
            "Hear Zone -> audible range",
            "Super-Scout Mode -> ultrasound",
            "Echo Return -> reflected ultrasound pulse",
            "Hidden Boundary -> tissue or material interface",
            "Map Console -> ultrasound image",
            "Flow Tracker -> Doppler ultrasound",
        ],
        "limit": "The model organizes the ideas, but students still need the formal sound-wave language and should not treat the analogy as a literal crowd marching across the room.",
        "prediction_prompt": f"Use the Echo-Scout model to predict what should happen when {focus}.",
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


# Lesson builders are appended below in smaller patches to keep edits reliable.

# M9 lessons start here.


def sound_launch_lesson() -> Dict[str, Any]:
    d = [
        mcq("M9L1_D1", "A Scout Beacon is the...", ["vibrating source that starts the sound", "echo image", "listener only", "boundary that reflects sound"], 0, "The beacon is the vibrating source.", ["sound_needs_vibration_confusion"], skill_tags=["source_classification"]),
        mcq("M9L1_D2", "A sound in air begins when...", ["the source vibrates", "air glows", "the listener walks closer", "particles drift across the room"], 0, "No wiggle, no sound.", ["sound_needs_vibration_confusion"], skill_tags=["sound_launch"]),
        mcq("M9L1_D3", "A loudspeaker cone moving forward and backward mainly creates...", ["a traveling pressure pattern", "a packet of air that flies to the ear", "light waves", "a vacuum"], 0, "The wave pattern travels; the air mostly shuttles locally.", ["sound_as_air_stream_confusion", "local_particle_motion_confusion"], skill_tags=["pressure_pattern"]),
        short("M9L1_D4", "Why must a tuning fork vibrate before it can be heard?", ["Because its vibration launches the sound disturbance into the surrounding air.", "Because a sound starts only when the source oscillates and pushes on the nearby air."], "A source has to oscillate to launch sound.", ["sound_needs_vibration_confusion"], skill_tags=["sound_launch"], acceptance_rules=acceptance_groups(["vibrate", "oscillate"], ["launch", "start", "create"], ["sound", "disturbance", "wave"], ["air", "medium"])) ,
        mcq("M9L1_D5", "The frequency of the sound matches the...", ["frequency of the vibrating source", "distance to the listener", "loudness only", "echo time"], 0, "The source sets the frequency.", ["source_frequency_confusion"], skill_tags=["source_frequency"]),
        mcq("M9L1_D6", "Which object can act as a Scout Beacon?", ["a vocal cord", "a shadow", "a mirror", "a thermometer"], 0, "A vibrating object can launch sound.", ["sound_needs_vibration_confusion"], skill_tags=["source_examples"]),
        short("M9L1_D7", "What is weak about saying that sound is just air blown from the source?", ["Because the air particles only move back and forth locally while the disturbance pattern travels outward.", "Because the pattern travels through the air crowd instead of one packet of air marching to the listener."], "Separate local particle motion from wave travel.", ["sound_as_air_stream_confusion", "local_particle_motion_confusion"], skill_tags=["medium_vs_pattern"], acceptance_rules=acceptance_groups(["particles", "air"], ["back and forth", "oscillate", "local"], ["pattern", "disturbance", "wave"], ["travels", "outward"], ["not", "rather than"], ["blown", "packet"])) ,
        mcq("M9L1_D8", "If the source stops vibrating, what stops first?", ["new sound waves being launched", "the speed of sound in air", "the meaning of pitch", "all echoes already in flight"], 0, "No new vibration means no new launches.", ["sound_needs_vibration_confusion"], skill_tags=["sound_launch"]),
        mcq("M9L1_D9", "A Scout Beacon makes 180 vibrations in 1.5 s. What frequency does it launch?", ["120 Hz", "180 Hz", "270 Hz", "90 Hz"], 0, "Frequency is vibrations per second: 180 / 1.5 = 120.", ["source_frequency_confusion"], skill_tags=["frequency_value"]),
        mcq("M9L1_D10", "Two beacons vibrate at the same frequency, but one listener stands farther away. Which statement stays strongest?", ["The launched sound frequency is still set by the source vibration rate.", "Distance to the listener sets the sound frequency.", "The farther sound cannot be launched.", "The medium becomes the source."], 0, "Listener distance does not set the launch frequency.", ["source_frequency_confusion"], skill_tags=["source_frequency"]),
    ]
    c = [
        short("M9L1_C1", "How does the vibrating source control the sound frequency?", ["The sound frequency matches how many vibrations the source makes each second.", "The source sets the frequency because each vibration cycle launches one sound cycle."], "Link frequency to vibrations per second.", ["source_frequency_confusion"], skill_tags=["source_frequency"], acceptance_rules=acceptance_groups(["frequency"], ["matches", "same as", "set by"], ["vibration", "cycle", "oscillation"], ["each second", "per second"])) ,
        mcq("M9L1_C2", "Which sentence is strongest?", ["The source vibrates, and the air relays the disturbance.", "The listener creates the sound by hearing it.", "The air packet itself travels from source to ear.", "The echo forms before the source vibrates."], 0, "Source and medium have different jobs.", ["sound_needs_vibration_confusion", "sound_as_air_stream_confusion"], skill_tags=["source_medium_roles"]),
        mcq("M9L1_C3", "A ruler vibrates 300 times each second. The launched sound frequency is...", ["300 Hz", "30 Hz", "3000 Hz", "it cannot be known"], 0, "Frequency is cycles per second.", ["source_frequency_confusion"], skill_tags=["frequency_value"]),
        short("M9L1_C4", "Why does a source have to push on nearby particles to make sound in air?", ["Because the surrounding air is the medium that carries the disturbance away from the source.", "Because the vibration must create compressions and rarefactions in the nearby air to start the wave."], "Sound in air needs the nearby medium.", ["sound_needs_vibration_confusion", "compression_rarefaction_confusion"], skill_tags=["medium_role"], acceptance_rules=acceptance_groups(["air", "medium"], ["carry", "relay"], ["disturbance", "wave", "sound"], ["compression", "rarefaction", "push"])) ,
        mcq("M9L1_C5", "Which event launches a new sound cycle?", ["one full vibration cycle of the source", "one blink from the listener", "one echo return", "one boundary reflection only"], 0, "Each vibration cycle launches a sound cycle.", ["source_frequency_confusion"], skill_tags=["cycle_link"]),
        short("M9L1_C6", "Why is 'no wiggle, no sound' a strong first rule?", ["Because a sound source must vibrate before any pressure wave can be launched.", "Because without source vibration there is no oscillation to start the sound pattern."], "Keep the source requirement explicit.", ["sound_needs_vibration_confusion"], skill_tags=["sound_launch"], acceptance_rules=acceptance_groups(["no", "without"], ["vibrate", "wiggle", "oscillation"], ["no sound", "cannot launch", "cannot start"], ["pressure wave", "pattern", "disturbance"])) ,
        mcq("M9L1_C7", "A beacon completes 240 vibrations in 2 s. What sound frequency is launched?", ["120 Hz", "240 Hz", "480 Hz", "60 Hz"], 0, "Frequency is vibrations per second: 240 / 2 = 120.", ["source_frequency_confusion"], skill_tags=["frequency_value"]),
        short("M9L1_C8", "Why does hearing a note not mean the medium itself traveled from the source to your ear?", ["Because the medium relays the disturbance locally while the sound pattern is what travels outward.", "Because nearby particles oscillate around their positions instead of the whole air mass marching to the listener."], "Keep medium relay and wave travel separate.", ["sound_as_air_stream_confusion", "local_particle_motion_confusion"], skill_tags=["medium_vs_pattern"], acceptance_rules=acceptance_groups(["medium", "air", "particles"], ["relay", "oscillate", "local"], ["pattern", "disturbance", "wave"], ["travels", "outward"], ["not", "rather than"], ["march", "whole air mass", "travel to your ear"])) ,
    ]
    t = [
        mcq("M9L1_M1", "A string vibrates 440 times each second. What frequency does it launch?", ["440 Hz", "44 Hz", "4.4 Hz", "880 Hz"], 0, "Frequency matches source vibrations per second.", ["source_frequency_confusion"], skill_tags=["frequency_value"]),
        short("M9L1_M2", "A classmate says the speaker blows one lump of air to your ear. What should you say instead?", ["The speaker creates a traveling pressure pattern while the air particles only oscillate locally.", "The sound wave moves outward, but the air mostly shuttles back and forth in place."], "Correct the medium-motion picture.", ["sound_as_air_stream_confusion", "local_particle_motion_confusion"], skill_tags=["medium_vs_pattern"], acceptance_rules=acceptance_groups(["pressure pattern", "wave", "disturbance"], ["travels", "moves outward"], ["air particles", "air"], ["back and forth", "oscillate", "local"], ["not", "rather than"], ["lump", "packet", "blown"])) ,
        mcq("M9L1_M3", "Which one is a source-behavior statement?", ["A higher vibration rate gives a higher sound frequency.", "A farther listener lowers the sound frequency.", "An echo sets the source frequency.", "A boundary creates the first vibration."], 0, "The source sets the frequency.", ["source_frequency_confusion"], skill_tags=["source_frequency"]),
        mcq("M9L1_M4", "Which object is definitely not acting as a sound source in this lesson?", ["the wall that only reflects the sound", "a vocal cord", "a tuning fork", "a speaker cone"], 0, "A reflector is not the original source.", ["echo_reflection_confusion"], skill_tags=["source_classification"]),
        short("M9L1_M5", "Why is hearing evidence that something vibrated, even when you cannot see the source move?", ["Because a sound must begin with a vibrating source, even if the motion is too small to see directly.", "Because the heard wave implies an oscillating source launched it."], "Use the source-first rule.", ["sound_needs_vibration_confusion"], skill_tags=["source_inference"], acceptance_rules=acceptance_groups(["sound", "heard"], ["must", "implies"], ["vibrate", "oscillate"], ["source"])) ,
        mcq("M9L1_M6", "If a source vibrates faster but everything else stays the same, the sound launched has...", ["a higher frequency", "a lower speed in the same air", "no change at all", "a guaranteed louder sound"], 0, "Faster source vibration means higher frequency, not necessarily louder or faster.", ["source_frequency_confusion", "pitch_loudness_confusion", "sound_speed_frequency_confusion"], skill_tags=["source_frequency"]),
        short("M9L1_M7", "What two jobs should you keep separate in a sound-launch story?", ["The source vibrates to start the wave, and the medium relays the disturbance outward.", "The source creates the wave while the air carries it on."], "Separate source and medium roles.", ["sound_needs_vibration_confusion", "sound_as_air_stream_confusion"], skill_tags=["source_medium_roles"], acceptance_rules=acceptance_groups(["source"], ["vibrate", "create", "start"], ["medium", "air"], ["relay", "carry"], ["wave", "disturbance"])) ,
        mcq("M9L1_M8", "Best first question in the Echo-Scout model:", ["What is vibrating?", "How far is the echo already?", "Which lens is used?", "How bright is the light?"], 0, "The source vibration comes first.", ["sound_needs_vibration_confusion"], skill_tags=["prediction_habit"]),
        mcq("M9L1_M9", "A beacon makes 90 vibrations in 0.30 s. What frequency does it launch?", ["300 Hz", "90 Hz", "30 Hz", "270 Hz"], 0, "Frequency is vibrations per second: 90 / 0.30 = 300.", ["source_frequency_confusion"], skill_tags=["frequency_value"]),
        short("M9L1_M10", "Two beacons launch the same frequency, but one swings more strongly. What stays the same and what may differ?", ["The frequency stays the same, while the disturbance strength or amplitude may differ.", "They can launch the same pitch-setting frequency even if one source shakes the nearby air more strongly."], "Separate launch rate from disturbance strength.", ["source_frequency_confusion", "pitch_loudness_confusion"], skill_tags=["source_medium_roles"], acceptance_rules=acceptance_groups(["frequency", "same"], ["strength", "amplitude", "shake more strongly"], ["may differ", "can differ"], ["launch", "disturbance", "pitch-setting"])) ,
    ]
    return lesson_spec(
        "M9_L1",
        "Scout Beacons and Sound Launch",
        sim("m9_wake_beacon_lab", "Wake the Beacon lab", "Start sound by vibrating the beacon and linking source motion to launched frequency.", ["Set the beacon vibration.", "Watch the nearby air respond.", "Compare vibration rate with launched frequency."], ["Explain why sound needs a vibrating source.", "Separate the source from the medium.", "Connect source frequency to sound frequency."], ["beacon_rate_hz", "beacon_amplitude", "launched_frequency_hz", "nearby_air_response"], "Sound-launch reasoning."),
        d,
        "A Scout Beacon makes sound only when it wiggles, and that wiggle launches a squeeze-release pattern into the Air Crowd.",
        "Before naming any sound property, point to what is vibrating.",
        [prompt_block("What must the Scout Beacon do before any sound exists?", "It must vibrate."), prompt_block("What determines the launched Ping Rate?", "The beacon's vibration rate.")],
        [prompt_block("Increase the beacon rate and compare the launched frequency.", "The sound follows the source."), prompt_block("Pause the beacon and watch what stops.", "No new vibration means no new sound launch.")],
        ["Explain why the source must vibrate before any sound can travel.", "Explain why sound in air is not the same as a blob of air shot across the room."],
        "Keep the source job, the medium job, and the launched frequency visible before moving to wave details.",
        c,
        t,
        contract(
            concept_targets=["Explain that sound begins with a vibrating source.", "Connect the source vibration rate to the sound frequency.", "Separate a traveling sound pattern from a packet of air drifting across the room."],
            core_concepts=["A sound in air begins with a vibrating source.", "The source launches a pressure disturbance into the nearby medium.", "The sound frequency matches the source frequency.", "The disturbance travels outward even though the medium itself does not march across the room."],
            prerequisite_lessons=["M7_L2"],
            misconception_focus=["sound_needs_vibration_confusion", "sound_as_air_stream_confusion", "local_particle_motion_confusion", "source_frequency_confusion"],
            formulas=[relation("source frequency = sound frequency", "The launch rate of the vibrating source sets the wave frequency.", ["Hz"], "Use for sound produced by a vibrating source.")],
            representations=[representation("words", "Explains the source-medium relationship."), representation("diagram", "Shows a beacon launching compressions into nearby air."), representation("formula", "States the source-frequency link.")],
            analogy_map=echo_scout_map("the class is deciding how a Scout Beacon launches sound"),
            worked_examples=[
                worked("A tuning fork vibrates 256 times each second. What sound frequency does it launch?", ["Read vibrations per second.", "Use the source-frequency link.", "Keep the unit Hz."], "256 Hz", "The sound frequency matches the source frequency.", "This locks the source-to-wave link numerically."),
                worked("A classmate says sound is air blown from a speaker to your ear. What is the better description?", ["Identify the moving source first.", "Describe the nearby air being pushed and released.", "Separate local air motion from pattern travel."], "A traveling pressure pattern moves outward while the air oscillates locally.", "Sound is a wave pattern in the medium, not a chunk of air traveling from source to listener.", "This blocks the 'air stream' misconception early."),
                worked("A speaker stops vibrating. What stops immediately?", ["Check what quantity depends directly on the source motion.", "Note that existing waves can still be in flight for a moment.", "State what is no longer created."], "No new sound waves are launched.", "The source vibration is the cause of new launches.", "This clarifies cause and effect in sound production."),
            ],
            visual_assets=[visual("m9-l1-beacon-launch", "sound_source", "Beacon launch", "Shows the source vibrating and pushing on nearby air.", "The source and the first squeeze band should stay visually distinct.", template="wave_diagram", meta={"wave_type": "sound_source"})],
            animation_assets=[animation("m9-l1-beacon-pulse", "sound_source", "Beacon pulse", "Shows the beacon oscillating while a squeeze-release pattern spreads outward.")],
            simulation_contract=sim_contract("m9-l1-wake-beacon-lab", "sound_source", "How does the vibrating Scout Beacon start the traveling sound pattern?", "Start with a quiet beacon, then make it vibrate slowly before increasing the rate.", ["Change the vibration rate and compare the launched frequency.", "Pause the source and notice that no new sound waves are created."], "Do not describe the sound as a chunk of air flying across the room.", "No wiggle, no sound: the vibrating source launches the disturbance and sets its frequency.", [("beacon_rate", "Beacon vibration rate", "Sets how many sound cycles are launched each second."), ("beacon_amplitude", "Beacon swing size", "Shows how strongly the nearby air is disturbed."), ("sound_status", "Launch status", "Makes the source requirement explicit.")], [("Launched frequency", "The sound frequency created by the source."), ("Nearby air response", "Shows that the medium is being disturbed, not transported."), ("Source state", "Confirms whether the beacon is vibrating.")]),
            reflection_prompts=["Why must a Scout Beacon vibrate before sound can exist?", "Why is a traveling sound wave different from air being blown from source to listener?"],
            mastery_skills=["sound_launch", "source_frequency", "source_medium_roles", "medium_vs_pattern", "prediction_habit"],
            variation_plan={"diagnostic": "Fresh attempts rotate between source-identification, source-frequency, and medium-versus-pattern stems.", "concept_gate": "Concept checks vary between launch causation and air-stream misconception prompts.", "mastery": "Mastery mixes numeric source-frequency, source-medium separation, and reasoning-about-launch stems before repeating any prompt."},
            scaffold_support=scaffold("A sound begins only when a source vibrates and disturbs the nearby medium.", "Point to what is vibrating first, then describe what the medium does with that disturbance.", "If the source is perfectly still, can any new sound wave be launched?", "Do not treat sound as a moving lump of air instead of a disturbance pattern.", "The Scout Beacon launches the sound, but the Air Crowd relays it onward.", "Which part of the story belongs to the source, and which part belongs to the medium?", [extra_section("Source sets frequency", "The number of source vibrations each second becomes the sound frequency.", "If the source doubles its vibration rate, what happens to the sound frequency?"), extra_section("Pattern not packet", "The air near the source is pushed and released, but the whole roomful of air does not march from the source to the listener.", "Why is 'packet of air' a weak description of sound?")]),
            visual_clarity_checks=visual_checks("sound-launch"),
        ),
    )


def relay_lesson() -> Dict[str, Any]:
    d = [
        mcq("M9L2_D1", "A Squeeze Band is a region where particles are...", ["closer together than usual", "farther apart than usual", "moving in circles", "absent"], 0, "Compression means crowded particles.", ["compression_rarefaction_confusion"], skill_tags=["compression_identification"]),
        mcq("M9L2_D2", "A Release Band is a region where particles are...", ["more spread out than usual", "tightly packed", "standing still forever", "all moving upward"], 0, "Rarefaction means spread out.", ["compression_rarefaction_confusion"], skill_tags=["rarefaction_identification"]),
        mcq("M9L2_D3", "Sound in air is mainly a...", ["longitudinal pressure wave", "transverse light wave", "stream of air", "surface ripple"], 0, "Sound in air is longitudinal.", ["longitudinal_wave_confusion"], skill_tags=["wave_classification"]),
        short("M9L2_D4", "How do air particles move when a sound passes through them?", ["They oscillate back and forth around their resting positions.", "They move to and fro locally while the wave pattern travels onward."], "Local particles shuttle; the pattern travels.", ["local_particle_motion_confusion", "longitudinal_wave_confusion"], skill_tags=["particle_motion"], acceptance_rules=acceptance_groups(["back and forth", "to and fro", "oscillate"], ["resting position", "around their place", "local"], ["wave", "pattern"], ["travels", "onward"])) ,
        mcq("M9L2_D5", "In a longitudinal wave, local particle motion is...", ["parallel to the direction of travel", "perpendicular to the direction of travel", "random with no pattern", "always circular"], 0, "Longitudinal means parallel.", ["longitudinal_wave_confusion"], skill_tags=["longitudinal_motion"]),
        mcq("M9L2_D6", "If there is no medium to relay the disturbance, sound...", ["cannot travel there", "becomes light", "gets louder", "must move faster"], 0, "Sound needs a medium.", ["sound_needs_vibration_confusion"], skill_tags=["medium_need"]),
        short("M9L2_D7", "Why is sound in air described with compressions and rarefactions?", ["Because the vibration creates alternating crowded and spread-out pressure regions in the air.", "Because the air crowd forms squeeze bands and release bands that move outward as the wave travels."], "Use alternating pressure-region language.", ["compression_rarefaction_confusion"], skill_tags=["pressure_regions"], acceptance_rules=acceptance_groups(["crowded", "compression", "squeeze"], ["spread out", "rarefaction", "release"], ["alternating"], ["air", "pressure", "regions"])) ,
        mcq("M9L2_D8", "Which statement is strongest?", ["The pattern travels, but each particle only shuttles locally.", "Each particle rides from the source to the listener.", "Sound pushes the whole medium one way only.", "The medium stays motionless while the pattern moves."], 0, "Pattern travel and particle motion are different.", ["local_particle_motion_confusion", "sound_as_air_stream_confusion"], skill_tags=["medium_vs_pattern"]),
        mcq("M9L2_D9", "A sensor counts 6 compressions passing it each second. What is the sound frequency?", ["6 Hz", "3 Hz", "12 Hz", "60 Hz"], 0, "Each compression per second is one cycle rate clue here, so the frequency is 6 Hz.", ["compression_rarefaction_confusion", "source_frequency_confusion"], skill_tags=["pressure_count_frequency"]),
        short("M9L2_D10", "Why is a rarefaction not an empty gap with no air particles?", ["Because the particles are more spread out there, but the medium is still present.", "Because a rarefaction is a low-pressure region, not empty space."], "Rarefaction means reduced crowding, not no medium.", ["compression_rarefaction_confusion"], skill_tags=["rarefaction_identification"], acceptance_rules=acceptance_groups(["rarefaction"], ["spread out", "lower pressure", "less crowded"], ["not", "rather than"], ["empty", "no particles", "no air"])) ,
    ]
    c = [
        short("M9L2_C1", "Why is a sound wave in air called longitudinal?", ["Because the air particles move parallel to the direction the wave travels.", "Because the local particle motion is along the same line as the wave propagation."], "Longitudinal means parallel local motion.", ["longitudinal_wave_confusion"], skill_tags=["longitudinal_motion"], acceptance_rules=acceptance_groups(["parallel", "same line"], ["particle motion", "local motion"], ["wave travel", "propagation", "direction"])) ,
        mcq("M9L2_C2", "Which region has higher pressure than usual?", ["compression / Squeeze Band", "rarefaction / Release Band", "echo return", "audible range"], 0, "Compression is the crowded high-pressure region.", ["compression_rarefaction_confusion"], skill_tags=["compression_identification"]),
        short("M9L2_C3", "Why does the Air Crowd relay the pattern without marching away from the source?", ["Because each particle passes the push to its neighbor and then returns near its own resting position.", "Because the disturbance is relayed through local oscillations rather than bulk drift across the room."], "The relay is local, not bulk transport.", ["local_particle_motion_confusion", "sound_as_air_stream_confusion"], skill_tags=["relay_reasoning"], acceptance_rules=acceptance_groups(["neighbor", "relay", "pass"], ["resting position", "own place", "local"], ["not", "rather than"], ["drift", "march", "bulk"])) ,
        mcq("M9L2_C4", "A line of particles showing crowded, spread, crowded, spread regions is representing...", ["compressions and rarefactions", "pitch and loudness", "light rays", "critical angles"], 0, "Those alternating regions are the sound-wave pattern.", ["compression_rarefaction_confusion"], skill_tags=["pressure_regions"]),
        mcq("M9L2_C5", "Why is 'sound moves because air itself travels to you' weak?", ["Because the particles mainly oscillate locally while the disturbance is what travels.", "Because sound does not need any medium.", "Because pitch blocks air motion.", "Because ultrasound is not sound."], 0, "Sound wave travel is not bulk air transport.", ["sound_as_air_stream_confusion", "local_particle_motion_confusion"], skill_tags=["medium_vs_pattern"]),
        short("M9L2_C6", "Why can sound not travel through a vacuum?", ["Because there are no particles there to pass on the compressions and rarefactions.", "Because without a medium there is no Air Crowd to relay the sound disturbance."], "Sound needs particles to relay the disturbance.", ["sound_needs_vibration_confusion"], skill_tags=["medium_need"], acceptance_rules=acceptance_groups(["no particles", "no medium", "vacuum"], ["relay", "pass on", "carry"], ["compression", "rarefaction", "disturbance", "sound"])) ,
        mcq("M9L2_C7", "If 4 compressions pass one point each second, what is the wave frequency?", ["4 Hz", "2 Hz", "8 Hz", "40 Hz"], 0, "Counting the repeated pressure cycles gives the frequency.", ["compression_rarefaction_confusion", "source_frequency_confusion"], skill_tags=["pressure_count_frequency"]),
        short("M9L2_C8", "Why do a compression and the rarefaction after it still belong to one wave?", ["Because they are alternating parts of the same repeating pressure pattern.", "Because one longitudinal sound wave is built from a sequence of crowded and spread-out regions."], "Keep the alternating regions inside one pattern.", ["compression_rarefaction_confusion"], skill_tags=["pressure_regions"], acceptance_rules=acceptance_groups(["alternating", "sequence", "repeating"], ["same", "one"], ["pressure pattern", "wave"], ["compression"], ["rarefaction"])) ,
    ]
    t = [
        mcq("M9L2_M1", "Which statement correctly compares a compression and a rarefaction?", ["Compression is crowded high pressure; rarefaction is spread low pressure.", "Compression is quiet; rarefaction is loud.", "Compression means faster sound; rarefaction means slower sound.", "Compression is the source; rarefaction is the listener."], 0, "Know the two alternating regions.", ["compression_rarefaction_confusion"], skill_tags=["compression_identification"]),
        short("M9L2_M2", "A student says the air at the back of the room must eventually arrive at the front when sound travels. What correction should you make?", ["The particles mainly move back and forth locally, so the pressure pattern travels without the whole roomful of air drifting across.", "Sound transfers the disturbance through local oscillations rather than carrying each air parcel across the room."], "Correct bulk-drift thinking.", ["sound_as_air_stream_confusion", "local_particle_motion_confusion"], skill_tags=["relay_reasoning"], acceptance_rules=acceptance_groups(["back and forth", "oscillate", "local"], ["pattern", "disturbance"], ["travels"], ["not", "rather than"], ["drift", "carry each air", "whole room"])) ,
        mcq("M9L2_M3", "A sound wave in air is most like...", ["a line of particles being squeezed and released along the travel direction", "a rope flicked up and down", "a beam of light in a vacuum", "a stationary pattern with no moving disturbance"], 0, "Use the longitudinal picture.", ["longitudinal_wave_confusion"], skill_tags=["wave_classification"]),
        mcq("M9L2_M4", "Which one would stop a sound from reaching you?", ["removing the medium", "raising the pitch", "making the source brighter", "changing the mirror angle"], 0, "Sound needs a medium.", ["sound_needs_vibration_confusion"], skill_tags=["medium_need"]),
        short("M9L2_M5", "Why are compressions and rarefactions part of one sound wave instead of two different waves?", ["Because they are alternating parts of the same traveling pressure pattern.", "Because one sound wave carries a repeating sequence of crowded and spread regions."], "Keep the alternating pattern together.", ["compression_rarefaction_confusion"], skill_tags=["pressure_regions"], acceptance_rules=acceptance_groups(["alternating", "sequence", "repeating"], ["same", "one"], ["pressure pattern", "wave"], ["crowded", "compression"], ["spread", "rarefaction"])) ,
        mcq("M9L2_M6", "If the local particle motion were perpendicular to the travel direction, the wave would be...", ["transverse rather than longitudinal", "still sound in air", "an echo only", "ultrasound automatically"], 0, "Parallel motion is what makes this sound wave longitudinal.", ["longitudinal_wave_confusion"], skill_tags=["longitudinal_motion"]),
        short("M9L2_M7", "What two questions help you separate medium motion from wave motion?", ["Ask where the pattern goes and how each particle moves around its own position.", "Track the travel of the disturbance separately from the local oscillation of one particle."], "Separate pattern motion from particle motion.", ["local_particle_motion_confusion"], skill_tags=["medium_vs_pattern"], acceptance_rules=acceptance_groups(["pattern", "disturbance"], ["goes", "travels"], ["particle", "one particle", "each particle"], ["moves", "oscillates"], ["own position", "local"])) ,
        mcq("M9L2_M8", "Best label for the Air Crowd in formal physics:", ["the medium", "the image", "the echo console", "the source frequency"], 0, "The air crowd is the medium.", ["sound_needs_vibration_confusion"], skill_tags=["medium_need"]),
        mcq("M9L2_M9", "Ten compressions pass a detector in 2 s. What is the frequency?", ["5 Hz", "10 Hz", "20 Hz", "2 Hz"], 0, "Frequency is cycles per second: 10 / 2 = 5.", ["compression_rarefaction_confusion", "source_frequency_confusion"], skill_tags=["pressure_count_frequency"]),
        short("M9L2_M10", "A particle shuffles right then left while the wave moves right across the room. What actually travels to the listener?", ["The disturbance pattern travels to the listener, while the particle only oscillates locally.", "The compression-rarefaction wave moves on, but that one particle does not journey across the room."], "Protect the distinction between local motion and propagation.", ["local_particle_motion_confusion", "sound_as_air_stream_confusion"], skill_tags=["relay_reasoning"], acceptance_rules=acceptance_groups(["disturbance", "pattern", "wave"], ["travels", "moves on"], ["particle"], ["oscillates", "local", "does not journey"], ["listener", "across the room"])) ,
    ]
    return lesson_spec(
        "M9_L2",
        "Squeeze Bands, Release Bands, and Crowd Relay",
        sim("m9_crowd_relay_lab", "Crowd Relay lab", "Track compressions, rarefactions, and local particle motion in a longitudinal wave.", ["Choose one particle to follow.", "Watch squeeze bands pass through the line.", "Compare particle motion with wave travel."], ["Identify compressions and rarefactions.", "Describe longitudinal motion correctly.", "Separate pattern travel from particle motion."], ["particle_shift", "compression_spacing", "wave_direction", "medium_status"], "Longitudinal-wave reasoning."),
        d,
        "The Air Crowd relays the Echo-Scout message by forming traveling Squeeze Bands and Release Bands while each particle only shuttles locally.",
        "Before saying how sound moves, say what one particle does and what the pattern does.",
        [prompt_block("What is a Squeeze Band?", "A crowded high-pressure region."), prompt_block("What direction do particles move in a longitudinal wave?", "Parallel to the wave travel.")],
        [prompt_block("Track one particle and one squeeze band separately.", "One stays local while the other travels."), prompt_block("Remove the medium and decide what happens to the relay.", "No medium means no sound relay.")],
        ["Explain why sound in air is called a longitudinal wave.", "Explain why the Air Crowd relays the wave without all drifting across the room."],
        "Keep compression, rarefaction, particle motion, and wave travel as separate ideas before judging any sound diagram.",
        c,
        t,
        contract(
            concept_targets=["Identify compressions and rarefactions in a sound wave.", "Describe sound in air as a longitudinal wave.", "Separate local particle motion from wave-pattern travel."],
            core_concepts=["A compression is a crowded high-pressure region and a rarefaction is a spread-out low-pressure region.", "Sound in air is a longitudinal pressure wave.", "The particles move back and forth parallel to the direction of wave travel.", "The medium relays the pattern without all drifting from source to listener."],
            prerequisite_lessons=["M9_L1"],
            misconception_focus=["compression_rarefaction_confusion", "longitudinal_wave_confusion", "local_particle_motion_confusion", "sound_as_air_stream_confusion"],
            formulas=[relation("compression + rarefaction pattern -> longitudinal pressure wave", "Sound in air is modeled as alternating crowded and spread-out pressure regions.", ["wave model"], "Use for conceptual sound-wave descriptions.")],
            representations=[representation("words", "Defines compressions, rarefactions, and local motion."), representation("diagram", "Shows squeeze bands passing through a line of particles."), representation("formula", "Summarizes the compression-rarefaction longitudinal-wave rule.")],
            analogy_map=echo_scout_map("the class is tracing how the Air Crowd relays a sound wave"),
            worked_examples=[worked("A sound wave passes through air. What are the crowded regions called?", ["Identify the high-pressure region.", "Use the sound-wave vocabulary.", "Keep the opposite region in mind too."], "Compressions / Squeeze Bands", "The crowded parts of a sound wave are compressions.", "This anchors the basic sound-wave vocabulary."), worked("Why is sound in air longitudinal?", ["Compare particle motion with wave travel.", "Notice that both are along the same line.", "State the formal label."], "Because the particle motion is parallel to the wave travel.", "Longitudinal waves are classified by the relation between local motion and propagation.", "This connects the sound unit back to general wave ideas."), worked("Why does hearing a sound not mean air from the source has arrived at the listener?", ["Track one particle instead of the whole pattern.", "Notice that it oscillates locally.", "State what is actually traveling."], "The pressure pattern travels while particles mostly oscillate locally.", "This blocks the bulk-air misconception.", "This keeps wave travel and medium travel separate.")],
            visual_assets=[visual("m9-l2-crowd-relay", "longitudinal_wave", "Crowd relay", "Shows compressions and rarefactions moving through the air crowd.", "Particle arrows and pressure bands should stay visually separate.", template="wave_diagram", meta={"wave_type": "longitudinal_wave"})],
            animation_assets=[animation("m9-l2-pressure-wave", "longitudinal_wave", "Pressure wave", "Shows a squeeze-release pattern traveling while each particle oscillates locally.")],
            simulation_contract=sim_contract("m9-l2-crowd-relay-lab", "longitudinal_wave", "How does the Air Crowd relay the sound pattern without all marching across the arena?", "Start with one compression moving through evenly spaced particles while one particle is highlighted.", ["Switch between showing particle arrows and pressure bands.", "Compare what changes when the medium is removed."], "Do not describe the whole medium as traveling with the sound.", "A sound wave is a traveling longitudinal pressure pattern made of compressions and rarefactions.", [("particle_shift", "Particle motion", "Shows local to-and-fro motion."), ("pressure_band_spacing", "Band spacing", "Makes compressions and rarefactions visible."), ("medium_toggle", "Medium present", "Tests whether the relay can exist.")], [("Wave type", "Confirms that the motion is longitudinal."), ("Highlighted particle", "Shows local motion only."), ("Pressure region", "Labels compression or rarefaction at the chosen point.")]),
            reflection_prompts=["Why does the Air Crowd relay the sound wave without drifting across the room?", "How do compressions and rarefactions help describe sound in air?"],
            mastery_skills=["compression_identification", "rarefaction_identification", "longitudinal_motion", "particle_motion", "relay_reasoning"],
            variation_plan={"diagnostic": "Fresh attempts rotate between compression vocabulary, longitudinal classification, and medium-role stems.", "concept_gate": "Concept checks vary between particle-motion explanations and compression-rarefaction identification.", "mastery": "Mastery mixes medium-need, particle-motion, and alternating-pressure questions before repeating a stem."},
            scaffold_support=scaffold("Sound in air is a longitudinal pressure wave made of compressions and rarefactions.", "Follow one particle and one pressure band at the same time so you do not confuse local motion with wave travel.", "If a sound wave moves right, which way does one air particle move?", "Do not say that the whole roomful of air moves from the source to the listener.", "The Echo-Scout arena shows a crowd passing on a message by squeeze and release, not by everyone marching across.", "Which feature travels farther: the squeeze band or one particle?", [extra_section("Compression clue", "A compression is where particles are closer together and the pressure is higher than usual.", "What should happen to spacing inside a Squeeze Band?"), extra_section("Medium requirement", "Without a medium there is nothing to relay the disturbance, so ordinary sound cannot travel.", "Why does a vacuum stop the relay?")]),
            visual_clarity_checks=visual_checks("sound-wave"),
        ),
    )


def pitch_lesson() -> Dict[str, Any]:
    d = [
        mcq("M9L3_D1", "Ping Rate maps to the physics term...", ["frequency", "loudness", "echo time", "intensity drop"], 0, "Ping Rate means frequency.", ["source_frequency_confusion"], skill_tags=["frequency_definition"]),
        mcq("M9L3_D2", "Tone Height maps to...", ["pitch", "speed of sound", "distance", "pressure only"], 0, "Tone Height means pitch.", ["pitch_loudness_confusion"], skill_tags=["pitch_definition"]),
        mcq("M9L3_D3", "A 500 Hz tone means...", ["500 vibration cycles each second", "500 meters per second", "500 decibels", "500 echoes each minute"], 0, "Hertz means cycles per second.", ["source_frequency_confusion"], skill_tags=["cycles_per_second"]),
        mcq("M9L3_D4", "Which tone is higher in pitch?", ["800 Hz", "200 Hz", "they sound the same", "cannot tell"], 0, "Higher frequency means higher pitch.", ["pitch_loudness_confusion"], skill_tags=["pitch_comparison"]),
        short("M9L3_D5", "Why can a sound be high-pitched without being loud?", ["Because pitch depends on frequency while loudness depends on intensity or amplitude.", "Because a higher frequency does not automatically mean a larger amplitude."], "Pitch and loudness are different ideas.", ["pitch_loudness_confusion"], skill_tags=["pitch_vs_loudness"], acceptance_rules=acceptance_groups(["pitch"], ["frequency"], ["loudness", "amplitude", "intensity"], ["different", "separate", "not the same"])) ,
        mcq("M9L3_D6", "In the same air at the same conditions, a 1000 Hz sound compared with a 500 Hz sound has...", ["about the same speed but a shorter wavelength", "double the speed", "half the speed", "the same wavelength"], 0, "Frequency does not strongly set sound speed in the same medium.", ["sound_speed_frequency_confusion"], skill_tags=["frequency_speed_separation"]),
        mcq("M9L3_D7", "If frequency rises while sound speed in the medium stays the same, wavelength...", ["gets shorter", "gets longer", "stays exactly the same", "becomes zero"], 0, "Higher frequency in the same medium means shorter wavelength.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_relation"]),
        short("M9L3_D8", "What does the ear mainly use to judge pitch?", ["The frequency of the sound wave.", "How many sound cycles arrive each second."], "Pitch tracks frequency.", ["pitch_loudness_confusion"], skill_tags=["pitch_definition"], acceptance_rules=acceptance_groups(["frequency", "cycles per second"], ["pitch", "tone height"], ["judge", "hear", "use"])) ,
        mcq("M9L3_D9", "A 750 Hz tone compared with a 250 Hz tone in the same air will sound...", ["higher in pitch", "lower in pitch", "exactly the same pitch", "higher only because it is louder"], 0, "Higher frequency means higher pitch.", ["pitch_loudness_confusion"], skill_tags=["pitch_comparison"]),
        short("M9L3_D10", "Why is a 600 Hz note not automatically louder than a 300 Hz note?", ["Because frequency sets pitch, while loudness depends on amplitude or intensity.", "Because a higher frequency does not guarantee a bigger sound-strength signal."], "Separate pitch from loudness.", ["pitch_loudness_confusion"], skill_tags=["pitch_vs_loudness"], acceptance_rules=acceptance_groups(["frequency", "pitch"], ["loudness", "amplitude", "intensity"], ["not", "does not"], ["same", "guarantee", "automatically"])) ,
    ]
    c = [
        short("M9L3_C1", "How does Ping Rate set Tone Height in the Echo-Scout model?", ["A higher ping rate means a higher heard tone because pitch follows frequency.", "More vibration cycles each second give a higher pitch."], "Tone Height is the ear's reading of frequency.", ["pitch_loudness_confusion", "source_frequency_confusion"], skill_tags=["pitch_relation"], acceptance_rules=acceptance_groups(["higher", "more"], ["ping rate", "frequency", "cycles per second"], ["higher pitch", "higher tone"])) ,
        mcq("M9L3_C2", "Which change can raise pitch without automatically raising loudness?", ["increase frequency only", "increase amplitude only", "move the listener away", "wait for an echo"], 0, "Pitch follows frequency, not amplitude.", ["pitch_loudness_confusion"], skill_tags=["pitch_vs_loudness"]),
        mcq("M9L3_C3", "A 250 Hz sound and a 500 Hz sound in the same air most strongly differ in...", ["frequency and wavelength", "speed only", "medium only", "whether they are sound"], 0, "Same medium keeps speed roughly the same; the wavelength changes.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_relation"]),
        short("M9L3_C4", "Why is 'higher frequency means faster sound in air' weak?", ["Because sound speed is mainly set by the medium and conditions, not by frequency alone.", "Because changing frequency in the same air mostly changes wavelength, not the sound speed."], "Separate medium-set speed from source-set frequency.", ["sound_speed_frequency_confusion"], skill_tags=["frequency_speed_separation"], acceptance_rules=acceptance_groups(["speed"], ["medium", "conditions"], ["not", "rather than"], ["frequency"], ["wavelength", "changes"])) ,
        mcq("M9L3_C5", "At 340 m/s, a 680 Hz tone has wavelength...", ["0.50 m", "2.0 m", "340 m", "680 m"], 0, "Use lambda = v / f.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_calculation"]),
        short("M9L3_C6", "Why is Hz a good unit for frequency?", ["Because it counts how many cycles happen each second.", "Because one hertz means one cycle per second."], "Frequency is a rate.", ["source_frequency_confusion"], skill_tags=["cycles_per_second"], acceptance_rules=acceptance_groups(["cycle", "vibration"], ["per second", "each second"], ["hertz", "Hz"])) ,
        mcq("M9L3_C7", "At 340 m/s, a 170 Hz sound has wavelength...", ["2.0 m", "0.5 m", "170 m", "510 m"], 0, "Use lambda = 340 / 170 = 2.0 m.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_calculation"]),
        short("M9L3_C8", "Why does doubling frequency halve wavelength when the sound speed stays fixed?", ["Because wavelength is speed divided by frequency, so more cycles each second leave less distance per cycle.", "Because with the same sound speed, increasing frequency means each cycle takes up a shorter length."], "Use the fixed-speed relationship.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_relation"], acceptance_rules=acceptance_groups(["speed", "fixed", "same"], ["divided by", "per"], ["frequency"], ["less distance per cycle", "shorter wavelength", "shorter length"])) ,
    ]
    t = [
        mcq("M9L3_M1", "Which tone would sound lowest in pitch?", ["120 Hz", "960 Hz", "500 Hz", "720 Hz"], 0, "Lower frequency means lower pitch.", ["pitch_loudness_confusion"], skill_tags=["pitch_comparison"]),
        short("M9L3_M2", "A source vibrates 400 times each second. What pitch clue does that give?", ["It launches a 400 Hz sound, so the pitch is set by that 400 Hz frequency.", "The tone height is the pitch that matches a frequency of 400 cycles per second."], "State both the frequency and the pitch link.", ["source_frequency_confusion", "pitch_loudness_confusion"], skill_tags=["pitch_relation"], acceptance_rules=acceptance_groups(["400", "400 Hz"], ["pitch", "tone height"], ["frequency", "cycles per second"])) ,
        mcq("M9L3_M3", "Two sounds are equally loud, but one is higher in pitch. The higher one must have...", ["the higher frequency", "the greater speed in the same air", "the bigger echo time", "the longer wavelength"], 0, "Equal loudness does not block a pitch comparison.", ["pitch_loudness_confusion", "sound_speed_frequency_confusion"], skill_tags=["pitch_vs_loudness"]),
        mcq("M9L3_M4", "At 340 m/s, a 340 Hz tone has wavelength...", ["1.0 m", "0.5 m", "340 m", "680 m"], 0, "Use lambda = v / f.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_calculation"]),
        short("M9L3_M5", "How do pitch and loudness answer different questions?", ["Pitch tells how high or low the sound is and comes from frequency, while loudness tells how strong it seems and relates to intensity or amplitude.", "Pitch is frequency-based, but loudness depends on sound strength rather than tone height."], "Keep the two hearing ideas separate.", ["pitch_loudness_confusion"], skill_tags=["pitch_vs_loudness"], acceptance_rules=acceptance_groups(["pitch"], ["high", "low", "frequency"], ["loudness"], ["strength", "amplitude", "intensity"], ["different", "separate"])) ,
        mcq("M9L3_M6", "A 1020 Hz sound in air and a 510 Hz sound in the same air most likely have...", ["about the same speed but different wavelengths", "different speeds but same wavelength", "different speeds and same wavelength", "the same pitch"], 0, "Same medium keeps speed roughly the same.", ["sound_speed_frequency_confusion"], skill_tags=["frequency_speed_separation"]),
        short("M9L3_M7", "Why does doubling frequency halve wavelength when the sound speed stays fixed?", ["Because wavelength equals speed divided by frequency, so with fixed speed a larger frequency leaves less distance per cycle.", "Because if the same speed is shared among more cycles each second, each cycle must be shorter."], "Use the fixed-speed reasoning.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_relation"], acceptance_rules=acceptance_groups(["speed", "fixed"], ["divided by", "per"], ["frequency"], ["wavelength", "shorter", "less distance per cycle"])) ,
        mcq("M9L3_M8", "Best first check when comparing two tones:", ["Ask which has the higher frequency before you talk about pitch.", "Assume the louder one is higher.", "Assume the faster one in the same air is higher.", "Ignore the unit Hz."], 0, "Pitch comparison starts with frequency.", ["pitch_loudness_confusion"], skill_tags=["prediction_habit"]),
        mcq("M9L3_M9", "A sound in air has wavelength 0.25 m and speed 340 m/s. What is its frequency?", ["1360 Hz", "85 Hz", "680 Hz", "0.74 Hz"], 0, "Use f = v / lambda = 340 / 0.25 = 1360 Hz.", ["sound_speed_frequency_confusion"], skill_tags=["wavelength_calculation"]),
        short("M9L3_M10", "Two sounds have the same frequency but different loudness bars. What stays the same and what differs?", ["The pitch stays the same because the frequency is the same, while the loudness differs.", "They share one tone height but differ in sound strength or amplitude."], "Keep pitch tied to frequency even when loudness changes.", ["pitch_loudness_confusion"], skill_tags=["pitch_vs_loudness"], acceptance_rules=acceptance_groups(["same frequency"], ["same pitch", "same tone height"], ["loudness", "strength", "amplitude"], ["differs", "different"])) ,
    ]
    return lesson_spec(
        "M9_L3",
        "Ping Rate, Pitch, and Frequency",
        sim("m9_pitch_match_lab", "Pitch Match lab", "Match pitch by adjusting frequency and keep loudness separate from tone height.", ["Set one target tone.", "Adjust the ping rate.", "Compare pitch, loudness, and wavelength deliberately."], ["Connect frequency to pitch.", "Keep loudness separate from pitch.", "Explain frequency changes without claiming speed changes in the same medium."], ["frequency_hz", "amplitude_level", "wavelength_m", "tone_height"], "Pitch-frequency reasoning."),
        d,
        "In the Echo-Scout arena, Ping Rate controls Tone Height: more squeeze-release cycles each second create a higher heard pitch.",
        "Before describing a tone, decide whether the question is about pitch, loudness, or wave speed.",
        [prompt_block("What does Hz count?", "Cycles each second."), prompt_block("Which property tracks Tone Height?", "Frequency.")],
        [prompt_block("Raise the ping rate and hold loudness steady.", "Pitch should rise without needing a louder sound."), prompt_block("Keep the medium the same and compare two frequencies.", "Speed stays about the same while wavelength changes.")],
        ["Explain why higher pitch does not automatically mean louder sound.", "Explain why changing frequency in the same air changes wavelength more directly than sound speed."],
        "Keep frequency, pitch, loudness, and wavelength from collapsing into one idea.",
        c,
        t,
        contract(
            concept_targets=["Define frequency as cycles per second.", "Connect pitch to frequency while separating it from loudness.", "Explain that frequency changes in the same medium mainly affect wavelength rather than sound speed."],
            core_concepts=["Frequency counts how many cycles happen each second.", "Pitch is the perception of frequency.", "Loudness and pitch are different quantities.", "In the same medium under fixed conditions, sound speed depends mainly on the medium, so changing frequency changes wavelength more directly."],
            prerequisite_lessons=["M7_L3", "M9_L1", "M9_L2"],
            misconception_focus=["source_frequency_confusion", "pitch_loudness_confusion", "sound_speed_frequency_confusion"],
            formulas=[relation("frequency = cycles per second", "Frequency tells how many complete sound cycles occur each second.", ["Hz"], "Use when converting vibration count to frequency."), relation("v = f lambda", "If sound speed stays fixed in one medium, changing frequency changes wavelength.", ["m/s", "Hz", "m"], "Use in the same medium under fixed conditions.")],
            representations=[representation("words", "Explains pitch, loudness, and speed as separate ideas."), representation("table", "Compares low and high frequencies with their pitches."), representation("formula", "Links frequency, speed, and wavelength.")],
            analogy_map=echo_scout_map("the class is matching Ping Rate to Tone Height"),
            worked_examples=[worked("A source vibrates 500 times each second. What is the sound frequency?", ["Count cycles each second.", "Attach the Hz unit.", "State the frequency."], "500 Hz", "Frequency is cycles per second.", "This anchors the meaning of Hz."), worked("Two tones are equally loud, but one has the higher frequency. Which has the higher pitch?", ["Ignore loudness because it is being held steady.", "Compare the frequencies.", "Translate frequency into pitch."], "The higher-frequency tone has the higher pitch.", "Pitch tracks frequency, not loudness.", "This blocks one of the most common sound confusions."), worked("A sound travels at 340 m/s in air and has frequency 680 Hz. What is its wavelength?", ["Use lambda = v / f.", "Divide 340 by 680.", "Keep the metre unit."], "0.50 m", "At fixed sound speed, wavelength is inversely related to frequency.", "This links the sound unit back to wave mathematics without changing the conceptual focus.")],
            visual_assets=[visual("m9-l3-pitch-meter", "frequency_pitch", "Pitch meter", "Shows ping rate, tone height, and separate loudness information.", "The pitch meter and the loudness bar should not be merged visually.", template="wave_diagram", meta={"wave_type": "frequency_pitch"})],
            animation_assets=[animation("m9-l3-ping-rate", "frequency_pitch", "Ping-rate comparison", "Shows two tones with different frequencies but deliberately separate loudness bars.")],
            simulation_contract=sim_contract("m9-l3-pitch-match-lab", "frequency_pitch", "How does changing Ping Rate alter Tone Height without forcing a change in loudness?", "Start with a mid-frequency tone and an unchanged medium.", ["Raise and lower the ping rate while holding loudness steady.", "Keep the same sound speed in air and watch the wavelength shorten as frequency rises."], "Do not use loudness words when the task is asking about pitch.", "Pitch follows frequency, while loudness and sound speed answer different questions.", [("ping_rate", "Ping rate", "Sets the sound frequency and therefore the pitch."), ("loudness_level", "Loudness", "Shows that amplitude can change separately."), ("medium_speed", "Medium speed", "Keeps the same-air speed condition visible.")], [("Frequency", "Counts cycles each second."), ("Tone height", "Shows the heard pitch."), ("Wavelength", "Changes when frequency changes in the same medium.")]),
            reflection_prompts=["Why can a sound be high-pitched without being loud?", "Why does changing frequency in the same air mainly change wavelength rather than speed?"],
            mastery_skills=["frequency_definition", "pitch_definition", "pitch_vs_loudness", "frequency_speed_separation", "wavelength_calculation"],
            variation_plan={"diagnostic": "Fresh attempts rotate between Hz meaning, pitch comparison, and loudness-separation stems.", "concept_gate": "Concept checks vary between pitch-language and speed-versus-frequency reasoning.", "mastery": "Mastery mixes frequency calculation, wavelength calculation, and pitch-versus-loudness stems before repeating any prompt."},
            scaffold_support=scaffold("Tone Height comes from Ping Rate, not from loudness.", "Name the frequency first, then decide whether the question is about pitch, loudness, or wavelength.", "If the frequency doubles in the same medium, what happens to pitch?", "Do not let 'higher note' turn into 'louder sound' or 'faster sound' automatically.", "The Echo-Scout meter keeps Ping Rate and Tone Height linked while a separate bar handles loudness.", "Which display belongs to pitch, and which one belongs to loudness?", [extra_section("Pitch versus loudness", "Pitch follows frequency, while loudness depends on sound strength rather than tone height.", "Why can two equally loud sounds have different pitches?"), extra_section("Same medium rule", "In the same air under fixed conditions, a higher frequency sound usually keeps about the same speed but has a shorter wavelength.", "What changes first when frequency rises in the same air?")]),
            visual_clarity_checks=visual_checks("pitch"),
        ),
    )


def ultrasound_lesson() -> Dict[str, Any]:
    d = [
        mcq("M9L4_D1", "The Hear Zone for most humans is roughly...", ["20 Hz to 20,000 Hz", "2 Hz to 200 Hz", "200 Hz to 200,000 Hz", "20 kHz to 2 MHz"], 0, "Use the usual audible range.", ["audible_range_confusion"], skill_tags=["audible_range"]),
        mcq("M9L4_D2", "Super-Scout Mode means...", ["ultrasound above human hearing", "a different wave that is not sound", "louder audible sound only", "echoes without frequency"], 0, "Ultrasound is still sound.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_definition"]),
        mcq("M9L4_D3", "Which frequency is ultrasound?", ["40 kHz", "4 kHz", "400 Hz", "40 Hz"], 0, "Above 20 kHz is ultrasound.", ["audible_range_confusion", "ultrasound_not_sound_confusion"], skill_tags=["frequency_band"]),
        mcq("M9L4_D4", "Which frequency is still in the human hearing range?", ["15 kHz", "45 kHz", "2 MHz", "60 kHz"], 0, "15 kHz is still audible for many people.", ["audible_range_confusion"], skill_tags=["frequency_band"]),
        short("M9L4_D5", "Why can ultrasound be sound even though humans cannot hear it?", ["Because it is still a sound wave, just with a frequency above the human audible range.", "Because ultrasound is ordinary sound at a very high frequency beyond human hearing."], "Ultrasound changes the frequency band, not the wave type.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_definition"], acceptance_rules=acceptance_groups(["sound"], ["frequency", "high frequency"], ["above", "beyond"], ["human hearing", "audible range"])) ,
        mcq("M9L4_D6", "A medical probe often uses MHz frequencies because it is working with...", ["ultrasound", "audible bass notes", "visible light", "electric current"], 0, "Medical scanning uses ultrasound.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_application"]),
        mcq("M9L4_D7", "Which sentence is strongest?", ["Ultrasound is still sound, so it can reflect from boundaries.", "Ultrasound cannot reflect because humans cannot hear it.", "Ultrasound is light in disguise.", "Ultrasound works without waves."], 0, "It is still a sound wave and still reflects.", ["ultrasound_not_sound_confusion", "echo_reflection_confusion"], skill_tags=["ultrasound_application"]),
        short("M9L4_D8", "Why is calling ultrasound a 'special medical beam' weak?", ["Because it is still sound and works by sending high-frequency sound pulses into a medium.", "Because ultrasound is not a new kind of wave; it is sound above the audible range."], "Keep the wave type correct.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_definition"], acceptance_rules=acceptance_groups(["still sound", "sound"], ["high frequency", "above the audible range"], ["not", "rather than"], ["special beam", "different kind of wave"])) ,
        mcq("M9L4_D9", "Which frequency is far into the ultrasound range used for scanning?", ["2 MHz", "2 kHz", "200 Hz", "20 Hz"], 0, "MHz frequencies are ultrasound and common in scanning.", ["ultrasound_not_sound_confusion", "audible_range_confusion"], skill_tags=["ultrasound_application"]),
        short("M9L4_D10", "Why can a bat or a medical probe use ultrasound even though humans cannot hear it?", ["Because ultrasound is still high-frequency sound that can travel in a medium and reflect from boundaries.", "Because being beyond human hearing does not stop the wave behaving like sound."], "Hearing limit and wave behavior are different issues.", ["ultrasound_not_sound_confusion", "echo_reflection_confusion"], skill_tags=["ultrasound_application"], acceptance_rules=acceptance_groups(["ultrasound", "high-frequency sound"], ["reflect", "travel in a medium", "behave like sound"], ["not", "does not"], ["hear", "human hearing"])) ,
    ]
    c = [
        short("M9L4_C1", "What makes 25 kHz ultrasound rather than ordinary audible sound?", ["Its frequency is above the upper limit of typical human hearing.", "25 kHz lies beyond the normal human audible range, so it counts as ultrasound."], "Use the 20 kHz boundary idea.", ["audible_range_confusion", "ultrasound_not_sound_confusion"], skill_tags=["frequency_band"], acceptance_rules=acceptance_groups(["above", "beyond"], ["20 kHz", "human hearing", "audible range"], ["ultrasound"])) ,
        mcq("M9L4_C2", "Which property keeps ultrasound in the same family as audible sound?", ["It is still a sound wave in a medium.", "It is visible.", "It always travels in a vacuum.", "It must be louder."], 0, "Ultrasound is still sound.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_definition"]),
        mcq("M9L4_C3", "Why is ultrasound useful for hidden-object scanning?", ["Because high-frequency sound pulses can reflect from boundaries and be timed.", "Because only visible light can reveal hidden objects.", "Because ultrasound needs no medium.", "Because frequency alone makes an image appear instantly."], 0, "Ultrasound scanning depends on echoes.", ["ultrasound_image_without_echo_confusion", "echo_reflection_confusion"], skill_tags=["ultrasound_application"]),
        short("M9L4_C4", "Why does being above human hearing not stop ultrasound from reflecting?", ["Because reflection depends on wave behavior at boundaries, not on whether humans can hear the frequency.", "Because ultrasound is still sound and still reflects when it meets a boundary."], "Hearing range and reflection are different issues.", ["ultrasound_not_sound_confusion", "echo_reflection_confusion"], skill_tags=["echo_boundary"], acceptance_rules=acceptance_groups(["reflect", "reflection"], ["boundary"], ["not", "regardless"], ["hear", "hearing", "audible"])) ,
        mcq("M9L4_C5", "Which frequency definitely belongs in the Hear Zone?", ["2 kHz", "200 kHz", "3 MHz", "80 kHz"], 0, "2 kHz is comfortably audible.", ["audible_range_confusion"], skill_tags=["frequency_band"]),
        short("M9L4_C6", "How should you compare audible sound and ultrasound in one sentence?", ["Both are sound waves, but ultrasound has a frequency above human hearing.", "Ultrasound is the high-frequency end of sound, while audible sound lies in the human hearing range."], "Use same-wave-family language.", ["ultrasound_not_sound_confusion", "audible_range_confusion"], skill_tags=["audible_range"], acceptance_rules=acceptance_groups(["both", "same family", "sound"], ["ultrasound"], ["above", "beyond", "high frequency"], ["human hearing", "audible"])) ,
        mcq("M9L4_C7", "Which frequency lies just outside the Hear Zone and therefore counts as ultrasound?", ["22 kHz", "18 kHz", "2 kHz", "200 Hz"], 0, "22 kHz is above the usual 20 kHz upper limit.", ["audible_range_confusion", "ultrasound_not_sound_confusion"], skill_tags=["frequency_band"]),
        short("M9L4_C8", "Why is 18 kHz usually classed as audible while 30 kHz is classed as ultrasound?", ["Because 18 kHz is below the usual upper hearing limit, while 30 kHz is above it.", "Because the 20 kHz boundary separates the normal Hear Zone from ultrasound."], "Use the boundary explicitly.", ["audible_range_confusion"], skill_tags=["audible_range"], acceptance_rules=acceptance_groups(["18 kHz", "below"], ["20 kHz", "hearing limit", "boundary"], ["30 kHz", "above"], ["audible", "ultrasound"])) ,
    ]
    t = [
        mcq("M9L4_M1", "Which set is ordered from audible to ultrasound?", ["10 kHz, 18 kHz, 30 kHz", "30 kHz, 10 kHz, 18 kHz", "2 MHz, 10 Hz, 5 kHz", "25 kHz, 15 kHz, 5 kHz"], 0, "The first two are audible, the third is ultrasound.", ["audible_range_confusion"], skill_tags=["frequency_band"]),
        short("M9L4_M2", "A 3 MHz medical pulse is still sound. Why?", ["Because MHz ultrasound is still a sound wave, just far above the human hearing range.", "Because medical ultrasound uses very high-frequency sound rather than a different wave type."], "Keep the wave type correct even at very high frequency.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_application"], acceptance_rules=acceptance_groups(["sound"], ["MHz", "high frequency"], ["above", "beyond"], ["human hearing", "audible range"])) ,
        mcq("M9L4_M3", "Which one is not ultrasound?", ["12 kHz", "40 kHz", "100 kHz", "2 MHz"], 0, "12 kHz is audible, not ultrasound.", ["audible_range_confusion"], skill_tags=["frequency_band"]),
        mcq("M9L4_M4", "Why can ultrasound help reveal hidden boundaries?", ["It can send pulses that reflect and return from inside the object or body.", "It works with no wave motion at all.", "It only works because humans hear it.", "It replaces echoes with brightness."], 0, "Ultrasound imaging is pulse-and-echo based.", ["ultrasound_image_without_echo_confusion", "echo_reflection_confusion"], skill_tags=["ultrasound_application"]),
        short("M9L4_M5", "What is the best correction to 'ultrasound is not really sound'?", ["Ultrasound is real sound; it is simply sound with frequency above the audible range.", "Ultrasound stays in the sound family even though humans cannot hear it."], "Correct the category, not just the application.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_definition"], acceptance_rules=acceptance_groups(["ultrasound"], ["sound"], ["above", "beyond", "high frequency"], ["audible range", "human hearing"])) ,
        mcq("M9L4_M6", "A 25 kHz pulse compared with a 5 kHz pulse in the same medium is...", ["higher in frequency and still a sound wave", "a different kind of wave", "unable to reflect", "automatically louder"], 0, "Frequency band changes, not wave family.", ["ultrasound_not_sound_confusion"], skill_tags=["ultrasound_definition"]),
        short("M9L4_M7", "Why is the Hear Zone useful in this lesson?", ["It marks the frequency range humans can hear, so anything above it can be identified as ultrasound.", "It helps classify whether a sound is audible or ultrasonic."], "The hearing boundary is a classification tool.", ["audible_range_confusion"], skill_tags=["audible_range"], acceptance_rules=acceptance_groups(["human hearing", "audible"], ["range", "zone"], ["above", "identify", "classify"], ["ultrasound"])) ,
        mcq("M9L4_M8", "Best first question when you see a new sound frequency:", ["Is it inside the Hear Zone or in Super-Scout Mode?", "How bright is the beam?", "Is the mirror tilted?", "How much current flows?"], 0, "Start by classifying the frequency band.", ["audible_range_confusion"], skill_tags=["prediction_habit"]),
        mcq("M9L4_M9", "A 0.8 MHz pulse is how many kilohertz?", ["800 kHz", "80 kHz", "8 kHz", "0.8 kHz"], 0, "1 MHz = 1000 kHz, so 0.8 MHz = 800 kHz.", ["ultrasound_not_sound_confusion"], skill_tags=["frequency_band"]),
        short("M9L4_M10", "How can 40 kHz and 4 kHz belong to the same wave family even though only one is ultrasound?", ["Because both are sound waves in a medium; they differ only in frequency band.", "Because ultrasound is the high-frequency end of sound, not a separate kind of wave."], "Keep family and classification separate.", ["ultrasound_not_sound_confusion", "audible_range_confusion"], skill_tags=["ultrasound_definition"], acceptance_rules=acceptance_groups(["both", "same wave family", "sound"], ["differ", "only"], ["frequency", "frequency band"], ["ultrasound", "high-frequency end"])) ,
    ]
    return lesson_spec(
        "M9_L4",
        "Hear Zone and Super-Scout Mode",
        sim("m9_super_scout_lab", "Super-Scout lab", "Compare audible sound with ultrasound and classify frequencies against the hearing range.", ["Set one frequency inside the Hear Zone.", "Move it above 20 kHz.", "Keep asking whether it is still sound and what it can still do."], ["Identify the audible range.", "Classify ultrasound correctly.", "Explain why ultrasound can still reflect from hidden boundaries."], ["frequency_hz", "hear_zone_status", "wave_family", "scan_ready"], "Audible-versus-ultrasound reasoning."),
        d,
        "Super-Scout Mode is still sound, but its Ping Rate is so high that it lies above the normal Hear Zone.",
        "Before using the word ultrasound, compare the frequency with the Hear Zone boundary.",
        [prompt_block("What frequency marks the top of the normal Hear Zone?", "About 20 kHz."), prompt_block("Does moving above the Hear Zone stop the wave from being sound?", "No. It is still sound.")],
        [prompt_block("Slide from 5 kHz to 40 kHz and classify the sound.", "Watch where it crosses out of the Hear Zone."), prompt_block("Keep the wave family label visible while you enter Super-Scout Mode.", "Ultrasound is still sound.")],
        ["Explain why ultrasound is classified by frequency rather than by being a new wave type.", "Explain why ultrasound can still reflect from hidden boundaries even though humans cannot hear it."],
        "Keep hearing range, wave family, and echo behavior as separate questions.",
        c,
        t,
        contract(
            concept_targets=["State the approximate human audible range.", "Define ultrasound as sound above that range.", "Explain why ultrasound is still sound and can still reflect from boundaries."],
            core_concepts=["Most humans hear roughly 20 Hz to 20,000 Hz.", "Ultrasound is sound above the audible range.", "Ultrasound is still a sound wave in a medium.", "Ultrasound scanning works because high-frequency sound pulses can reflect and return from boundaries."],
            prerequisite_lessons=["M9_L3"],
            misconception_focus=["audible_range_confusion", "ultrasound_not_sound_confusion", "echo_reflection_confusion", "ultrasound_image_without_echo_confusion"],
            formulas=[relation("ultrasound > 20 kHz", "Ultrasound is classified by lying above the upper limit of normal human hearing.", ["Hz", "kHz"], "Use when deciding whether a sound is audible or ultrasonic.")],
            representations=[representation("words", "Classifies audible and ultrasonic sound."), representation("diagram", "Shows audible and ultrasound bands on one frequency scale."), representation("formula", "Summarizes the frequency boundary that classifies ultrasound.")],
            analogy_map=echo_scout_map("the class is comparing the Hear Zone with Super-Scout Mode"),
            worked_examples=[worked("Is 15 kHz audible or ultrasound?", ["Compare 15 kHz with 20 kHz.", "Notice it is below the upper hearing limit.", "Classify it."], "Audible sound", "15 kHz lies within the usual human hearing range.", "This anchors the boundary correctly."), worked("Is 40 kHz audible or ultrasound?", ["Compare 40 kHz with 20 kHz.", "Notice it lies above the hearing limit.", "State that it is still sound."], "Ultrasound", "Ultrasound is high-frequency sound above the audible range.", "This blocks the 'not really sound' misconception."), worked("Why can an ultrasound probe still form echoes?", ["Ask what kind of wave it is.", "Notice that it is still sound in a medium.", "Remember that sound reflects from boundaries."], "Because ultrasound is still sound and can reflect from boundaries.", "Echo behavior depends on wave interaction with boundaries, not on whether humans can hear the frequency.", "This keeps classification and mechanism connected.")],
            visual_assets=[visual("m9-l4-hear-zone", "ultrasound_range", "Hear Zone scale", "Shows audible and ultrasound bands on one frequency line.", "The 20 kHz boundary should remain easy to read.", template="wave_diagram", meta={"wave_type": "ultrasound_range"})],
            animation_assets=[animation("m9-l4-frequency-sweep", "ultrasound_range", "Frequency sweep", "Shows a frequency moving from audible sound into Super-Scout Mode while keeping the wave-family label fixed.")],
            simulation_contract=sim_contract("m9-l4-super-scout-lab", "ultrasound_range", "When does a sound leave the Hear Zone and enter Super-Scout Mode?", "Start with an audible tone and raise the frequency past 20 kHz.", ["Classify several example frequencies against the Hear Zone.", "Keep the 'still sound' label visible as the tone enters ultrasound."], "Do not treat ultrasound as a different kind of wave just because humans cannot hear it.", "Ultrasound is the high-frequency end of sound, and it still behaves like sound at boundaries.", [("frequency", "Frequency", "Controls whether the sound is audible or ultrasound."), ("hear_zone_band", "Hear Zone band", "Shows the human hearing window."), ("scan_mode", "Scan-ready mode", "Links ultrasound classification to imaging use.")], [("Zone status", "Shows audible or ultrasonic classification."), ("Wave family", "Confirms the wave is still sound."), ("Boundary use", "Reminds the learner that ultrasound can still reflect.")]),
            reflection_prompts=["Why is ultrasound still sound even though humans cannot hear it?", "Why can ultrasound be useful for hidden-boundary scanning?"],
            mastery_skills=["audible_range", "frequency_band", "ultrasound_definition", "ultrasound_application", "echo_boundary"],
            variation_plan={"diagnostic": "Fresh attempts rotate between frequency-band classification and ultrasound-definition stems.", "concept_gate": "Concept checks vary between Hear-Zone reasoning and 'still sound' explanations.", "mastery": "Mastery mixes frequency-band sorting, medical-probe examples, and hidden-boundary reasoning before any repeated stem is preferred."},
            scaffold_support=scaffold("Ultrasound is sound above the Hear Zone, not a different wave family.", "Compare the frequency with the hearing range first, then decide whether it is audible or ultrasonic.", "Is 25 kHz inside or outside the Hear Zone?", "Do not let 'cannot hear it' turn into 'it is not sound.'", "Super-Scout Mode is just the high-frequency part of the same sound-wave world.", "Which fact classifies a sound as ultrasound: its frequency or the tool using it?", [extra_section("Hear Zone boundary", "Most human hearing sits roughly between 20 Hz and 20,000 Hz, so frequencies above that top edge are ultrasonic.", "What is special about 20 kHz in this lesson?"), extra_section("Still sound at boundaries", "Ultrasound can still reflect from boundaries because it is still sound moving through a medium.", "Why does hearing ability not decide whether reflection can happen?")]),
            visual_clarity_checks=visual_checks("ultrasound"),
        ),
    )


def echo_lesson() -> Dict[str, Any]:
    d = [
        mcq("M9L5_D1", "An Echo Return is the...", ["reflected sound pulse coming back", "source vibration itself", "pitch heard by the ear", "air crowd"], 0, "Echo return means the reflected pulse.", ["echo_reflection_confusion"], skill_tags=["echo_definition"]),
        mcq("M9L5_D2", "A Hidden Boundary is a place where...", ["the sound meets a change in material and some of it reflects", "the source vibrates faster", "pitch becomes loudness", "sound becomes light"], 0, "Boundaries reflect some sound.", ["echo_reflection_confusion", "ultrasound_image_without_echo_confusion"], skill_tags=["boundary_reflection"]),
        short("M9L5_D3", "Why does a longer echo return time usually mean a deeper boundary?", ["Because the pulse has had farther to travel before coming back.", "Because the sound took a longer round trip, so the reflecting boundary is farther away."], "Longer time means a longer round trip.", ["echo_time_distance_confusion"], skill_tags=["echo_time_reasoning"], acceptance_rules=acceptance_groups(["longer", "more time"], ["farther", "deeper"], ["round trip", "travel"], ["back"])) ,
        mcq("M9L5_D4", "Why is there a divide by 2 in echo-distance calculations?", ["because the measured time covers the trip out and the trip back", "because pitch halves in tissue", "because ultrasound is not sound", "because only half the pulse reflects"], 0, "Echo time is a round-trip time.", ["echo_time_distance_confusion"], skill_tags=["round_trip"]),
        mcq("M9L5_D5", "Ultrasound images are built from...", ["many reflected echoes from boundaries", "one note held continuously with no reflections", "light rays only", "current changes"], 0, "Imaging is pulse-and-echo mapping.", ["ultrasound_image_without_echo_confusion"], skill_tags=["image_build"]),
        mcq("M9L5_D6", "If two echoes return, the earlier one most likely came from...", ["the nearer boundary", "the farther boundary", "the louder boundary only", "a source vibrating slower"], 0, "Shorter return time means nearer boundary.", ["echo_time_distance_confusion"], skill_tags=["echo_order"]),
        short("M9L5_D7", "What measurement lets the scanner estimate how far away a boundary is?", ["The echo return time together with the sound speed in the medium.", "How long the pulse takes to return, combined with the wave speed."], "Distance comes from speed and return time.", ["echo_time_distance_confusion"], skill_tags=["echo_depth"], acceptance_rules=acceptance_groups(["echo return time", "time to return"], ["sound speed", "wave speed", "speed"], ["distance", "depth", "far away"])) ,
        mcq("M9L5_D8", "If a pulse reflects from a boundary 3 m deep in a medium where sound speed is 1500 m/s, the return time is...", ["0.004 s", "0.002 s", "0.001 s", "4 s"], 0, "Round trip is 6 m, so time = 6 / 1500 = 0.004 s.", ["echo_time_distance_confusion"], skill_tags=["echo_calculation"]),
        mcq("M9L5_D9", "A pulse returns after 0.003 s in a 1500 m/s medium. What boundary depth does that suggest?", ["2.25 m", "4.5 m", "1.50 m", "0.75 m"], 0, "Depth = 1500 x 0.003 / 2 = 2.25 m.", ["echo_time_distance_confusion"], skill_tags=["echo_calculation"]),
        short("M9L5_D10", "Why can one strong echo not map a whole organ or region by itself?", ["Because one echo gives only one boundary clue, while a full image needs many timed echoes from many positions.", "Because mapping needs multiple returns to place many boundaries, not one loud reflection only."], "One return is one clue, not a full map.", ["ultrasound_image_without_echo_confusion"], skill_tags=["image_build"], acceptance_rules=acceptance_groups(["one", "single"], ["echo", "return"], ["one boundary clue", "one clue"], ["many", "multiple"], ["image", "map", "many positions"])) ,
    ]
    c = [
        short("M9L5_C1", "How does one echo turn into a depth estimate?", ["Use the return time to find the round-trip distance, then halve it to get the boundary depth.", "Multiply sound speed by echo time for the full path and divide by two for the one-way depth."], "Echo timing gives round-trip distance first.", ["echo_time_distance_confusion"], skill_tags=["echo_depth"], acceptance_rules=acceptance_groups(["return time", "echo time"], ["speed"], ["round trip", "full path"], ["divide by two", "halve"], ["depth", "distance"])) ,
        mcq("M9L5_C2", "Why is the return time from a deeper boundary larger?", ["because the pulse has farther to go out and back", "because higher pitch always slows down", "because the source vibrates faster", "because the image is virtual"], 0, "Depth makes the round trip longer.", ["echo_time_distance_confusion"], skill_tags=["echo_time_reasoning"]),
        mcq("M9L5_C3", "Which statement is strongest?", ["Ultrasound imaging depends on echoes reflected from boundaries.", "Ultrasound images appear without any reflection.", "Only the source frequency matters for the picture.", "Boundaries matter only for loudness."], 0, "Imaging is built from reflected echoes.", ["ultrasound_image_without_echo_confusion", "echo_reflection_confusion"], skill_tags=["image_build"]),
        short("M9L5_C4", "Why do scanners send many pulses rather than only one?", ["Because many echoes from many boundaries are needed to build up a picture across the region.", "Because one echo gives only one depth clue, but many returns together can map the structure."], "One pulse gives one clue; many pulses build an image.", ["ultrasound_image_without_echo_confusion"], skill_tags=["image_build"], acceptance_rules=acceptance_groups(["many", "multiple"], ["echoes", "returns"], ["picture", "image", "map"], ["one", "single"], ["depth clue", "structure"])) ,
        mcq("M9L5_C5", "A pulse takes 0.006 s to return in a medium where sound speed is 2000 m/s. Boundary depth?", ["6 m", "12 m", "3 m", "1.5 m"], 0, "Depth = 2000 x 0.006 / 2 = 6 m.", ["echo_time_distance_confusion"], skill_tags=["echo_calculation"]),
        short("M9L5_C6", "Why is an echo picture a map of boundaries rather than of empty space alone?", ["Because echoes return most clearly from places where materials change and some sound reflects.", "Because boundary changes create the reflections that tell the scanner where structures are."], "Echoes mark interfaces.", ["echo_reflection_confusion", "ultrasound_image_without_echo_confusion"], skill_tags=["boundary_reflection"], acceptance_rules=acceptance_groups(["boundary", "interface", "materials change"], ["reflect", "echo"], ["tell", "show", "map"], ["structure"])) ,
        mcq("M9L5_C7", "A boundary is 1.5 m deep in a medium where sound speed is 1500 m/s. What return time should the probe read?", ["0.002 s", "0.001 s", "0.003 s", "0.004 s"], 0, "Round trip is 3 m, so time = 3 / 1500 = 0.002 s.", ["echo_time_distance_confusion"], skill_tags=["echo_calculation"]),
        short("M9L5_C8", "Why would using the wrong sound speed give the wrong boundary depth even if the echo time were measured perfectly?", ["Because the depth calculation converts time into distance using the sound speed, so the speed value matters directly.", "Because the same return time corresponds to a different distance if the wave travels at a different speed."], "Time needs the correct wave speed to become distance.", ["echo_time_distance_confusion"], skill_tags=["echo_depth"], acceptance_rules=acceptance_groups(["sound speed", "wave speed"], ["converts", "turns"], ["time"], ["distance", "depth"], ["different", "wrong"])) ,
    ]
    t = [
        mcq("M9L5_M1", "A pulse returns after 0.002 s in a medium where sound speed is 1500 m/s. Depth?", ["1.5 m", "3.0 m", "0.75 m", "6.0 m"], 0, "Depth = 1500 x 0.002 / 2 = 1.5 m.", ["echo_time_distance_confusion"], skill_tags=["echo_calculation"]),
        short("M9L5_M2", "Why does the scanner divide the pulse distance by 2 before placing the boundary?", ["Because the measured time includes both the trip to the boundary and the trip back to the probe.", "Because the echo time is round-trip time, but the image needs the one-way depth."], "The image uses one-way depth, not round-trip path length.", ["echo_time_distance_confusion"], skill_tags=["round_trip"], acceptance_rules=acceptance_groups(["trip out and back", "round trip"], ["divide by 2", "halve"], ["one-way", "depth", "boundary"])) ,
        mcq("M9L5_M3", "Two echoes return: one at 0.001 s and one at 0.004 s. Which boundary is farther?", ["the 0.004 s boundary", "the 0.001 s boundary", "they are the same depth", "it cannot be decided"], 0, "Longer return time means farther depth in the same medium.", ["echo_time_distance_confusion"], skill_tags=["echo_order"]),
        mcq("M9L5_M4", "Which phrase best describes the Map Console image?", ["a picture built from many timed echoes", "a picture that appears without any reflection", "a measure of loudness only", "a record of visible light"], 0, "Imaging comes from many echoes.", ["ultrasound_image_without_echo_confusion"], skill_tags=["image_build"]),
        short("M9L5_M5", "A classmate says the scanner knows depth just by pitch. What is the better explanation?", ["Depth comes from the echo return time together with sound speed, not from pitch alone.", "The scanner uses timed echoes and wave speed to place boundaries, rather than reading depth directly from pitch."], "Correct the timing logic.", ["echo_time_distance_confusion"], skill_tags=["echo_depth"], acceptance_rules=acceptance_groups(["echo return time", "timed echoes"], ["speed"], ["depth", "place boundaries"], ["not", "rather than"], ["pitch"])) ,
        mcq("M9L5_M6", "A 4 m deep boundary in a 1600 m/s medium gives return time...", ["0.005 s", "0.0025 s", "0.010 s", "0.0016 s"], 0, "Round trip is 8 m, so time = 8 / 1600 = 0.005 s.", ["echo_time_distance_confusion"], skill_tags=["echo_calculation"]),
        short("M9L5_M7", "Why can stronger echoes help the scanner distinguish some boundaries more clearly?", ["Because stronger reflected returns give a clearer signal from that boundary.", "Because a boundary that reflects more of the pulse sends back a more noticeable echo."], "Echo strength affects signal clarity.", ["echo_reflection_confusion"], skill_tags=["boundary_reflection"], acceptance_rules=acceptance_groups(["stronger", "more noticeable", "clearer"], ["echo", "reflected return", "signal"], ["boundary"])) ,
        mcq("M9L5_M8", "Best first move in an echo-depth problem:", ["decide whether the time given is round-trip time", "assume the boundary depth equals speed x time", "change pitch first", "ignore the medium speed"], 0, "Echo time is usually the round trip.", ["echo_time_distance_confusion"], skill_tags=["prediction_habit"]),
        mcq("M9L5_M9", "Three echoes return at 0.001 s, 0.003 s, and 0.005 s in the same medium. Which boundary is deepest?", ["the 0.005 s boundary", "the 0.001 s boundary", "they are all the same depth", "the 0.003 s boundary"], 0, "In one medium, the longest return time means the greatest depth.", ["echo_time_distance_confusion"], skill_tags=["echo_order"]),
        short("M9L5_M10", "Why do simple echo-depth problems usually assume one known medium before calculating?", ["Because the calculation needs one known sound speed to turn return time into distance.", "Because if the wave speed changes from region to region, one simple speed x time / 2 step would no longer represent the whole path cleanly."], "The speed assumption belongs inside the depth model.", ["echo_time_distance_confusion"], skill_tags=["echo_depth"], acceptance_rules=acceptance_groups(["known", "one"], ["sound speed", "wave speed"], ["turn", "convert"], ["time"], ["distance", "depth"])) ,
    ]
    return lesson_spec(
        "M9_L5",
        "Echo Returns and Hidden-Boundary Mapping",
        sim("m9_scout_scan_lab", "Scout Scan lab", "Use echo return times to locate hidden boundaries and build a simple ultrasound map.", ["Send one pulse.", "Read the first echo time.", "Add more boundaries and compare multiple returns."], ["Explain how echoes reveal hidden boundaries.", "Calculate depth from echo time.", "Explain why a scan needs many pulses."], ["sound_speed_m_per_s", "echo_time_s", "boundary_depth_m", "echo_strength"], "Echo-mapping reasoning."),
        d,
        "In Scout Scan mode, fast sound pulses bounce from Hidden Boundaries and return as echoes that can be timed to place features on the Map Console.",
        "Before doing any calculation, ask whether the time shown is the whole round trip.",
        [prompt_block("What does an Echo Return tell you first?", "How long the pulse took to come back."), prompt_block("Why is there usually a divide by two?", "The time covers the path out and back.")],
        [prompt_block("Move one boundary farther away and compare the echo time.", "Deeper boundary means longer return time."), prompt_block("Add a second boundary and compare which echo arrives first.", "Nearer boundaries return sooner.")],
        ["Explain why timed echoes can reveal the depth of hidden boundaries.", "Explain why one echo gives one clue but many echoes can build an image."],
        "Keep boundary reflection, round-trip timing, and image building connected.",
        c,
        t,
        contract(
            concept_targets=["Explain how echoes from boundaries reveal hidden structures.", "Use echo return time and sound speed to estimate depth.", "Explain why a scanner needs many echoes to build an image."],
            core_concepts=["Some of an ultrasound pulse reflects when it meets a boundary between different materials.", "Longer echo return times usually mean greater depth in the same medium.", "Depth is based on one-way distance even though the measured time covers a round trip.", "Ultrasound images are built from many echoes returned from many boundaries."],
            prerequisite_lessons=["M9_L4"],
            misconception_focus=["echo_reflection_confusion", "echo_time_distance_confusion", "ultrasound_image_without_echo_confusion"],
            formulas=[relation("depth = sound speed x echo time / 2", "Echo timing first gives round-trip distance; halving gives the one-way depth.", ["m/s", "s", "m"], "Use for pulse-echo depth estimates in one medium.")],
            representations=[representation("words", "Explains how boundary reflections become map clues."), representation("diagram", "Shows a pulse traveling out and an echo returning."), representation("formula", "Converts round-trip time into depth.")],
            analogy_map=echo_scout_map("the class is using Echo Returns to place hidden boundaries on the Map Console"),
            worked_examples=[worked("A pulse returns after 0.002 s in a medium where sound speed is 1500 m/s. Find the depth.", ["Multiply speed by return time to get the round-trip distance.", "1500 x 0.002 = 3 m.", "Divide by two to get the one-way depth."], "1.5 m", "Echo timing gives round-trip distance first, but the image needs one-way depth.", "This makes the divide-by-two step meaningful."), worked("Two echoes return at different times from the same probe direction. Which one came from the nearer boundary?", ["Compare the return times.", "Shorter time means less total travel.", "Choose the earlier echo."], "The earlier echo came from the nearer boundary.", "In the same medium, less travel time means less distance.", "This supports multi-boundary interpretation."), worked("Why can one pulse not build a full image by itself?", ["Ask what information one timed return contains.", "Notice it gives only one boundary clue along one direction.", "State what more pulses add."], "One pulse gives only one boundary clue; many pulses are needed for an image.", "Imaging needs many depth clues across the region.", "This keeps pulse-echo imaging from becoming magical.")],
            visual_assets=[visual("m9-l5-echo-map", "echo_imaging", "Echo map", "Shows a pulse leaving the probe, reflecting from a boundary, and returning to build a depth clue.", "The outgoing pulse, returning echo, and boundary depth label should remain visually distinct.", template="wave_diagram", meta={"wave_type": "echo_map"})],
            animation_assets=[animation("m9-l5-echo-return", "echo_imaging", "Echo return", "Shows one pulse, one reflected echo, and the timed depth calculation.")],
            simulation_contract=sim_contract("m9-l5-scout-scan-lab", "echo_imaging", "How does echo return time become a boundary depth on the Map Console?", "Start with one boundary and one clearly labeled round-trip echo time.", ["Change the boundary depth and compare the new echo time.", "Add a second boundary and compare which return arrives first and why."], "Do not forget that the displayed time is for the trip out and back unless the problem states otherwise.", "Pulse-echo imaging turns return times into one-way depths: first convert the round-trip distance, then divide by two before building a picture from many such clues.", [("echo_time", "Echo return time", "Controls how far the pulse has traveled altogether."), ("sound_speed", "Sound speed", "Converts time into distance."), ("boundary_layout", "Boundary layout", "Shows why many returns are needed for a map.")], [("Boundary depth", "The one-way depth inferred from the echo."), ("Round-trip distance", "The full out-and-back path length."), ("Echo order", "Shows which boundary is nearer or farther.")]),
            reflection_prompts=["Why does a scanner divide the pulse distance by two before placing a boundary?", "How do many echoes build a map rather than a single depth clue?"],
            mastery_skills=["echo_definition", "boundary_reflection", "echo_depth", "round_trip", "echo_calculation"],
            variation_plan={"diagnostic": "Fresh attempts rotate between echo vocabulary, boundary reflection, and round-trip-time stems.", "concept_gate": "Concept checks vary between divide-by-two reasoning and image-building explanations.", "mastery": "Mastery mixes numeric depth problems, echo-order comparisons, and scanner-explanation stems before repeating any prompt."},
            scaffold_support=scaffold("Echo timing works because the pulse travels out to a boundary and then back to the probe.", "Find the round-trip distance first, then convert it into one-way depth before you place the boundary.", "If the echo time doubles in the same medium, what happens to the depth?", "Do not put the boundary at speed x time unless you have already checked whether the time is out-and-back.", "Scout Scan mode uses one return time as one depth clue, and many depth clues build the full map.", "Why is one echo not enough for a full picture?", [extra_section("Round-trip warning", "Echo time usually includes both the forward journey and the return journey, so the one-way depth is smaller than speed x time.", "Why is the divide-by-two step physically necessary?"), extra_section("Many pulses, one map", "A full scan needs many echoes from many directions or positions so the scanner can assemble a picture instead of only one depth mark.", "What extra information does a second pulse add?")]),
            visual_clarity_checks=visual_checks("echo-map"),
        ),
    )


def doppler_lesson() -> Dict[str, Any]:
    d = [
        mcq("M9L6_D1", "A Flow Tracker in this module means...", ["Doppler ultrasound", "a plane mirror", "a converging lens", "a heat transfer route"], 0, "Flow Tracker maps to Doppler ultrasound.", ["doppler_motion_confusion"], skill_tags=["doppler_definition"]),
        mcq("M9L6_D2", "If blood moves toward the probe, the returned frequency is usually...", ["higher", "lower", "unchanged because motion never matters", "zero"], 0, "Approaching targets give a higher return frequency.", ["doppler_motion_confusion"], skill_tags=["toward_shift"]),
        mcq("M9L6_D3", "If blood moves away from the probe, the returned frequency is usually...", ["lower", "higher", "always unchanged", "equal to zero"], 0, "Receding targets give a lower return frequency.", ["doppler_motion_confusion"], skill_tags=["away_shift"]),
        short("M9L6_D4", "What does Doppler ultrasound add beyond a still boundary picture?", ["It shows or measures motion such as flow direction or speed.", "It uses frequency shifts in the returning sound to track moving targets like blood flow."], "Doppler adds motion information.", ["doppler_motion_confusion"], skill_tags=["doppler_use"], acceptance_rules=acceptance_groups(["motion", "moving target", "flow"], ["direction", "speed"], ["frequency shift", "returning sound", "doppler"])) ,
        mcq("M9L6_D5", "If there is no Doppler frequency shift from a region, the strongest conclusion is...", ["there may be no motion toward or away from the probe there", "the sound was not ultrasound", "the image must be bright", "the boundary disappeared"], 0, "No shift suggests no motion along the beam direction.", ["doppler_motion_confusion"], skill_tags=["zero_shift"]),
        mcq("M9L6_D6", "Which sentence is strongest?", ["Doppler ultrasound still uses sound waves and echo returns, but it focuses on motion information.", "Doppler replaces echoes with light.", "Doppler is not sound at all.", "Doppler only measures loudness."], 0, "It is still ultrasound and still uses returning sound.", ["doppler_motion_confusion", "ultrasound_not_sound_confusion"], skill_tags=["doppler_use"]),
        short("M9L6_D7", "Why can frequency shifts reveal motion?", ["Because motion changes the returned sound frequency compared with the transmitted one.", "Because an approaching or receding target changes the echo frequency, and that shift can be interpreted as motion."], "Motion changes return frequency.", ["doppler_motion_confusion"], skill_tags=["shift_reasoning"], acceptance_rules=acceptance_groups(["motion", "moving"], ["changes", "shift"], ["returned frequency", "echo frequency"], ["approach", "recede", "toward", "away"])) ,
        mcq("M9L6_D8", "A return frequency slightly above the transmitted frequency suggests the target is...", ["moving toward the probe", "moving away from the probe", "definitely stationary", "not a sound reflector"], 0, "Higher return frequency means approaching motion.", ["doppler_motion_confusion"], skill_tags=["toward_shift"]),
        mcq("M9L6_D9", "A transmitted pulse is 4.000 MHz and the return is 4.003 MHz. The motion clue is...", ["toward the probe", "away from the probe", "definitely no motion", "not ultrasound"], 0, "A higher return frequency suggests approaching motion.", ["doppler_motion_confusion"], skill_tags=["toward_shift"]),
        short("M9L6_D10", "Why is 'higher returned frequency means louder sound' weak in Doppler work?", ["Because the key clue is a frequency shift caused by motion, not a loudness change.", "Because Doppler reads motion from how the return frequency changes relative to the transmitted pulse."], "Keep shift-sign reasoning separate from loudness.", ["doppler_motion_confusion", "pitch_loudness_confusion"], skill_tags=["shift_reasoning"], acceptance_rules=acceptance_groups(["frequency shift", "returned frequency"], ["motion"], ["not", "rather than"], ["loudness", "louder"])) ,
    ]
    c = [
        short("M9L6_C1", "How does the Flow Tracker decide whether motion is toward or away from the probe?", ["A higher returned frequency suggests motion toward the probe, while a lower one suggests motion away.", "It compares the returned frequency with the transmitted one and reads the sign of the shift."], "Read the direction from the shift sign.", ["doppler_motion_confusion"], skill_tags=["flow_direction"], acceptance_rules=acceptance_groups(["higher", "toward"], ["lower", "away"], ["returned frequency", "shift"], ["compare", "with the transmitted", "baseline"])) ,
        mcq("M9L6_C2", "Why is Doppler ultrasound useful in medicine?", ["It can reveal blood flow direction or speed.", "It makes sound visible without echoes.", "It turns sound into heat.", "It removes the need for any medium."], 0, "Doppler is valuable for flow information.", ["doppler_motion_confusion"], skill_tags=["doppler_use"]),
        mcq("M9L6_C3", "A transmitted pulse is 3.000 MHz and the return is 3.002 MHz. The target is most likely...", ["moving toward the probe", "moving away from the probe", "completely stationary", "not reflecting at all"], 0, "Higher return frequency means approaching motion.", ["doppler_motion_confusion"], skill_tags=["toward_shift"]),
        short("M9L6_C4", "Why is 'Doppler only makes a still picture brighter' weak?", ["Because Doppler is used to measure motion information from frequency shifts, not just to brighten a still image.", "Because its special job is flow and motion tracking, such as blood movement."], "Keep Doppler tied to motion.", ["doppler_motion_confusion"], skill_tags=["doppler_use"], acceptance_rules=acceptance_groups(["motion", "flow"], ["frequency shift"], ["not", "rather than"], ["brighter", "still picture", "brightness"])) ,
        mcq("M9L6_C5", "A return with lower frequency than the transmitted pulse indicates...", ["motion away from the probe", "motion toward the probe", "a hotter object", "no reflection"], 0, "Lower return frequency means receding motion.", ["doppler_motion_confusion"], skill_tags=["away_shift"]),
        short("M9L6_C6", "Why is Doppler still part of the sound module rather than a separate wave topic?", ["Because it still uses ultrasound waves and returning echoes, but interprets their frequency shifts to reveal motion.", "Because Doppler ultrasound is still an ultrasound echo method with added motion analysis."], "Keep the wave family and the extra purpose together.", ["doppler_motion_confusion", "ultrasound_not_sound_confusion"], skill_tags=["doppler_definition"], acceptance_rules=acceptance_groups(["ultrasound", "sound"], ["returning echoes", "echo method"], ["frequency shifts", "shift"], ["motion", "flow"])) ,
        mcq("M9L6_C7", "A transmitted pulse is 3.500 MHz and the return is 3.497 MHz. Best motion clue?", ["away from the probe", "toward the probe", "exactly stationary", "the signal is brighter"], 0, "The lower return frequency indicates receding motion.", ["doppler_motion_confusion"], skill_tags=["away_shift"]),
        short("M9L6_C8", "Why can zero Doppler shift still occur even when blood is present?", ["Because Doppler mainly detects motion toward or away from the probe, so zero shift does not mean nothing is there.", "Because flow that has no toward-or-away component along the beam can give little or no shift."], "Zero shift is a motion-direction clue, not proof of emptiness.", ["doppler_motion_confusion"], skill_tags=["zero_shift"], acceptance_rules=acceptance_groups(["zero shift"], ["does not mean", "not"], ["nothing is there", "empty"], ["toward or away", "along the beam", "probe"])) ,
    ]
    t = [
        mcq("M9L6_M1", "A return frequency lower than the transmitted pulse most strongly means...", ["the target is moving away", "the target is moving toward", "the target is stationary", "the medium vanished"], 0, "Receding motion lowers the returned frequency.", ["doppler_motion_confusion"], skill_tags=["away_shift"]),
        short("M9L6_M2", "How could a doctor use Doppler ultrasound to study a blood vessel?", ["By sending ultrasound into the vessel and using frequency shifts in the returning echoes to infer blood flow direction or speed.", "By comparing the transmitted and returned frequencies to track blood movement."], "Use motion-tracking language.", ["doppler_motion_confusion"], skill_tags=["doppler_use"], acceptance_rules=acceptance_groups(["ultrasound"], ["returned echoes", "returning sound", "echoes"], ["frequency shift", "compare frequencies"], ["blood flow", "movement", "direction", "speed"])) ,
        mcq("M9L6_M3", "Which pair matches the correct shift story?", ["toward -> higher return frequency, away -> lower return frequency", "toward -> lower, away -> higher", "toward -> no shift, away -> no shift", "toward -> louder only, away -> quieter only"], 0, "Keep the shift directions straight.", ["doppler_motion_confusion"], skill_tags=["flow_direction"]),
        mcq("M9L6_M4", "A transmitted pulse is 5.000 MHz and the return is 4.998 MHz. Best interpretation?", ["the target is moving away", "the target is moving toward", "the target is definitely still", "the signal is not ultrasound"], 0, "The return frequency fell slightly, so the target is receding.", ["doppler_motion_confusion"], skill_tags=["away_shift"]),
        short("M9L6_M5", "Why does zero Doppler shift not always mean 'no blood in the vessel'?", ["Because it mainly means no motion toward or away from the probe is being detected along that beam direction.", "Because Doppler reads motion along the probe direction, so zero shift does not prove the vessel is empty."], "Zero shift is not the same as 'nothing there.'", ["doppler_motion_confusion"], skill_tags=["zero_shift"], acceptance_rules=acceptance_groups(["zero shift"], ["not", "does not prove"], ["toward or away", "along the beam", "probe direction"], ["empty", "no blood", "nothing there"])) ,
        mcq("M9L6_M6", "Which description keeps Doppler and ordinary echo imaging linked correctly?", ["Both use ultrasound echoes, but Doppler focuses on motion through frequency shifts.", "Doppler uses light, while imaging uses sound.", "Doppler ignores echoes completely.", "Ordinary imaging already measures flow direction directly without shifts."], 0, "Doppler extends echo use to motion information.", ["doppler_motion_confusion", "ultrasound_not_sound_confusion"], skill_tags=["doppler_definition"]),
        short("M9L6_M7", "What single comparison lies at the heart of Doppler flow tracking?", ["Comparing the returned frequency with the transmitted frequency.", "Checking how the echo frequency shifts relative to the original pulse."], "Flow tracking starts from a frequency comparison.", ["doppler_motion_confusion"], skill_tags=["shift_reasoning"], acceptance_rules=acceptance_groups(["compare", "comparison"], ["returned frequency", "echo frequency"], ["transmitted", "original", "baseline"], ["shift"])) ,
        mcq("M9L6_M8", "Best first question when reading a Doppler result:", ["Is the returned frequency higher, lower, or unchanged compared with the transmitted pulse?", "How bright is the image?", "How loud is the audible tone?", "Which lens is being used?"], 0, "The shift sign is the key first clue.", ["doppler_motion_confusion"], skill_tags=["prediction_habit"]),
        mcq("M9L6_M9", "A transmitted pulse is 2.500 MHz and the return is also 2.500 MHz. What is the most cautious conclusion?", ["No toward-or-away motion is being detected along that beam direction.", "The vessel is definitely empty.", "The pulse was not ultrasound.", "The target must be moving toward the probe."], 0, "Equal frequencies suggest no detected shift along the beam, not proof of emptiness.", ["doppler_motion_confusion"], skill_tags=["zero_shift"]),
        short("M9L6_M10", "How are ordinary pulse-echo imaging and Doppler flow tracking linked in one sentence?", ["Both use ultrasound echoes, but Doppler adds motion information by comparing returned and transmitted frequency.", "Both are ultrasound methods; Doppler extends echo imaging by reading frequency shifts for motion."], "Keep the family connection explicit.", ["doppler_motion_confusion", "ultrasound_not_sound_confusion"], skill_tags=["doppler_definition"], acceptance_rules=acceptance_groups(["both", "ultrasound", "echoes"], ["doppler"], ["adds", "extends"], ["motion"], ["frequency shift", "compare returned and transmitted"])) ,
    ]
    return lesson_spec(
        "M9_L6",
        "Flow Tracker and Doppler Ultrasound",
        sim("m9_flow_tracker_lab", "Flow Tracker lab", "Interpret Doppler frequency shifts to infer motion direction and flow information.", ["Set a transmitted pulse.", "Move the target toward and away.", "Compare the returned frequency with the original."], ["Explain how Doppler reveals motion.", "Infer motion direction from frequency shifts.", "Link Doppler ultrasound to blood-flow measurement."], ["transmitted_frequency", "returned_frequency", "shift_direction", "flow_status"], "Doppler-flow reasoning."),
        d,
        "Flow Tracker mode listens for how moving targets nudge the returning Echo Return upward or downward in frequency.",
        "Before naming the motion, compare the returned frequency with the transmitted one.",
        [prompt_block("What does a higher returned frequency usually mean?", "Motion toward the probe."), prompt_block("What does a lower returned frequency usually mean?", "Motion away from the probe.")],
        [prompt_block("Move the target toward the probe and compare the returned frequency.", "Watch the shift turn positive."), prompt_block("Reverse the target motion and compare again.", "Now the shift should turn negative.")],
        ["Explain how Doppler ultrasound reveals flow direction.", "Explain why Doppler is still part of ultrasound rather than a separate kind of wave."],
        "Keep echo use, frequency shift, and motion interpretation tied together.",
        c,
        t,
        contract(
            concept_targets=["Explain that Doppler ultrasound reveals motion through frequency shifts.", "Infer toward and away motion from the sign of the shift.", "Describe how Doppler methods can measure blood flow."],
            core_concepts=["Doppler ultrasound still uses ultrasound echoes, but it focuses on motion information.", "A higher returned frequency usually indicates motion toward the probe.", "A lower returned frequency usually indicates motion away from the probe.", "Doppler ultrasound can show blood flow direction and help estimate speed."],
            prerequisite_lessons=["M9_L5"],
            misconception_focus=["doppler_motion_confusion", "ultrasound_not_sound_confusion"],
            formulas=[relation("toward motion -> higher return frequency; away motion -> lower return frequency", "Doppler flow tracking interprets the sign of the echo frequency shift.", ["frequency shift"], "Use for qualitative Doppler reasoning.")],
            representations=[representation("words", "Explains how motion changes returned frequency."), representation("diagram", "Shows approaching and receding flow relative to a probe."), representation("formula", "Summarizes how shift direction maps to motion toward or away from the probe.")],
            analogy_map=echo_scout_map("the class is using Flow Tracker mode to interpret moving echoes"),
            worked_examples=[worked("A returned frequency is slightly higher than the transmitted one. What direction is the target moving?", ["Compare return with transmit.", "Notice the positive shift.", "Read the direction from the sign."], "Toward the probe", "Approaching motion raises the returned frequency.", "This anchors the sign convention."), worked("A blood vessel gives a lower returned frequency than the transmitted pulse. What is the likely flow clue?", ["Compare the frequencies.", "Notice that the return is lower.", "Interpret the shift as receding motion along the beam."], "The blood is moving away from the probe along that direction.", "Receding motion lowers the returned frequency.", "This connects Doppler reasoning to a real medical context."), worked("Why does Doppler belong in the sound module?", ["Identify the wave family.", "Notice it still uses ultrasound and echoes.", "State what extra information it extracts."], "Because Doppler ultrasound is still sound-based echo imaging with added motion analysis.", "Doppler extends ultrasound rather than replacing it with a new wave family.", "This keeps the module conceptually unified.")],
            visual_assets=[visual("m9-l6-flow-tracker", "doppler_flow", "Flow tracker", "Shows how approaching and receding flow change the returned frequency.", "The shift arrows and direction labels should stay easy to compare.", template="wave_diagram", meta={"wave_type": "doppler_shift"})],
            animation_assets=[animation("m9-l6-doppler-shift", "doppler_flow", "Doppler shift", "Shows the returned frequency moving above and below the transmitted value as the target reverses direction.")],
            simulation_contract=sim_contract("m9-l6-flow-tracker-lab", "doppler_flow", "How does the returned frequency change when the target moves toward or away from the probe?", "Start with a stationary target, then move it toward the probe before reversing the motion.", ["Compare positive, negative, and zero frequency shifts.", "Use a blood-flow example and explain what the shift says about direction."], "Do not treat Doppler as a brightness trick; it is a motion-reading method based on frequency comparison.", "Doppler ultrasound interprets frequency shifts in returning echoes to reveal motion direction and flow.", [("transmitted_frequency", "Transmitted frequency", "Sets the reference pulse."), ("target_motion", "Target motion", "Creates toward, away, or zero-shift cases."), ("shift_scale", "Shift scale", "Makes the sign and size of the change readable.")], [("Returned frequency", "Shows the echo frequency after interacting with the moving target."), ("Shift sign", "Shows whether the return is above, below, or equal to the transmitted value."), ("Flow clue", "Interprets the shift as toward, away, or no detected motion along the beam.")]),
            reflection_prompts=["Why does a higher returned frequency suggest motion toward the probe?", "How does Doppler ultrasound extend pulse-echo imaging into flow tracking?"],
            mastery_skills=["doppler_definition", "toward_shift", "away_shift", "zero_shift", "doppler_use"],
            variation_plan={"diagnostic": "Fresh attempts rotate between shift-sign interpretation and Doppler-definition stems.", "concept_gate": "Concept checks vary between motion-direction reasoning and Doppler-versus-still-image explanations.", "mastery": "Mastery mixes toward/away examples, baseline-versus-return comparisons, and blood-flow applications before repeating any prompt."},
            scaffold_support=scaffold("Flow Tracker mode works by comparing returned frequency with transmitted frequency.", "Read the sign of the shift before you talk about motion direction or blood flow.", "If the returned frequency is higher than the transmitted one, what motion direction should you test first?", "Do not treat Doppler as if it were only a brighter version of an ordinary ultrasound image.", "The Echo-Scout Flow Tracker extends echo mapping by asking whether moving targets push the return frequency upward or downward.", "What single comparison turns a return pulse into a motion clue?", [extra_section("Toward versus away", "Approaching motion raises the returned frequency, while receding motion lowers it.", "Which shift sign should mean 'toward'?"), extra_section("Still ultrasound", "Doppler remains part of ultrasound because it still uses sound waves and returning echoes; it simply reads them for motion.", "Why is Doppler not a separate wave family?")]),
            visual_clarity_checks=visual_checks("doppler-flow"),
        ),
    )


M9_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Sound production, compressions and rarefactions, frequency and pitch, and ultrasound applications taught through the Echo-Scout model of sound.",
    "mastery_outcomes": [
        "Explain sound production as vibration launching a longitudinal pressure wave.",
        "Describe compressions and rarefactions and explain how the medium relays the disturbance.",
        "Connect frequency to pitch without confusing it with loudness.",
        "Explain that sound speed in a given medium is not set mainly by frequency and relate frequency changes to wavelength changes.",
        "Identify ultrasound as high-frequency sound above the audible range.",
        "Explain how echo-based ultrasound reveals hidden boundaries and how Doppler ultrasound tracks flow.",
    ],
    "lessons": [sound_launch_lesson(), relay_lesson(), pitch_lesson(), ultrasound_lesson(), echo_lesson(), doppler_lesson()],
}


RELEASE_CHECKS = [
    "Every lesson keeps vibrating source, pressure-pattern relay, pitch, and ultrasound applications in one coherent sound world.",
    "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
    "Every lesson-owned assessment bank is broad enough to prefer unseen questions before repeated stems.",
    "Every short-answer bank accepts varied scientifically correct wording through authored phrase groups.",
    "Every worked example explains why the answer follows instead of naming only the final label.",
    "Every sound visual keeps compressions, echoes, and frequency labels readable without clipping.",
]


M9_MODULE_DOC, M9_LESSONS, M9_SIM_LABS = build_nextgen_module_bundle(
    module_id=M9_MODULE_ID,
    module_title=M9_MODULE_TITLE,
    module_spec=M9_SPEC,
    allowlist=M9_ALLOWLIST,
    content_version=M9_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=13,
    level="Module 9",
    estimated_minutes=300,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M9 into Firestore")
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

    module_doc = deepcopy(M9_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M9_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M9_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M9_MODULE_ID)]
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
