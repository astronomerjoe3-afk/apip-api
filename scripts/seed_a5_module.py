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


A5_MODULE_ID = "A5"
A5_CONTENT_VERSION = "20260322_a5_packet_pattern_frame_v1"
A5_MODULE_TITLE = "Modern Physics"
A5_ALLOWLIST = [
    "brightness_beats_threshold_confusion",
    "intensity_sets_electron_energy_confusion",
    "photoelectron_delay_confusion",
    "wave_particle_switch_confusion",
    "pattern_means_smear_confusion",
    "de_broglie_light_only_confusion",
    "nuclear_equals_chemical_confusion",
    "mass_defect_energy_from_nothing_confusion",
    "binding_energy_direction_confusion",
    "fixed_c_source_motion_confusion",
    "time_dilation_broken_clock_confusion",
    "length_contraction_visual_squash_confusion",
    "simultaneity_absolute_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(A5_ALLOWLIST)
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


def worked(prompt: str, steps: Sequence[str], final_answer: str, answer_reason: str, why_it_matters: str) -> Dict[str, Any]:
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
        f"The main {topic} labels stay visible on desktop and mobile layouts.",
        "Packet, pattern, bundle, and frame labels remain separated so the story never collapses into one crowded block.",
        "Threshold markers, wavelength notes, binding labels, and frame captions stay readable without clipping.",
        "Arrows, event markers, and comparison captions stay deliberate enough for physics reasoning rather than decoration.",
    ]


def packet_pattern_frame_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Packet-Pattern Frame Model",
        "focus": focus,
        "comparison": f"The Packet-Pattern Frame world keeps packet events, probability patterns, core binding, and moving frames connected while {focus}.",
        "mapping": [
            "Flash packet -> photon",
            "Packet grade -> frequency",
            "Beam count -> intensity",
            "Release gate -> metal surface",
            "Unlock toll -> work function",
            "Escape runner -> photoelectron",
            "Bonus kick -> maximum kinetic energy",
            "Pattern map -> probability distribution",
            "Hit dot -> detection event",
            "Track seed -> matter particle",
            "Core bundle -> nucleus",
            "Bind credit -> binding energy",
            "Mass stamp -> rest mass",
            "Frame pod -> inertial frame",
            "Pulse clock -> light clock",
            "Signal cap -> speed of light",
            "Tick stretch -> time dilation",
            "Span squeeze -> length contraction",
            "Same-now slip -> relativity of simultaneity",
        ],
        "limit": "The model keeps modern-physics ideas coherent, but learners still need the formal language of photons, de Broglie wavelength, mass defect, and Lorentz factors.",
        "prediction_prompt": f"Use the Packet-Pattern Frame model to predict what should happen when {focus}.",
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
    simulation_contract: Dict[str, Any],
    reflection_prompts: Sequence[str],
    mastery_skills: Sequence[str],
    variation_plan: Dict[str, str],
    scaffold_support: Dict[str, Any],
    visual_clarity_checks: Sequence[str],
) -> Dict[str, Any]:
    return {
        "assessment_bank_targets": assessment_targets(),
        "concept_targets": list(concept_targets),
        "core_concepts": list(core_concepts),
        "prerequisite_lessons": list(prerequisite_lessons),
        "misconception_focus": list(misconception_focus),
        "formulas": list(formulas),
        "representations": list(representations),
        "analogy_map": deepcopy(analogy_map),
        "worked_examples": list(worked_examples),
        "visual_assets": list(visual_assets),
        "animation_assets": [],
        "simulation_contract": deepcopy(simulation_contract),
        "reflection_prompts": list(reflection_prompts),
        "mastery_skills": list(mastery_skills),
        "variation_plan": deepcopy(variation_plan),
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


def build_mcqs(prefix: str, rows: Sequence[Tuple[str, Sequence[str], int, str, Sequence[str], Sequence[str]]]) -> List[Dict[str, Any]]:
    return [mcq(f"{prefix}{index + 1}", prompt, choices, answer_index, hint, tags, skill_tags=skills) for index, (prompt, choices, answer_index, hint, tags, skills) in enumerate(rows)]


def build_shorts(prefix: str, rows: Sequence[Tuple[str, Sequence[str], str, Sequence[str], Sequence[str], Dict[str, Any]]]) -> List[Dict[str, Any]]:
    return [short(f"{prefix}{index + 1}", prompt, answers, hint, tags, skill_tags=skills, acceptance_rules=rules) for index, (prompt, answers, hint, tags, skills, rules) in enumerate(rows)]


def lesson_one() -> Dict[str, Any]:
    diagnostic = build_mcqs(
        "A5L1_D",
        [
            ("In the Packet-Pattern Frame model, the packet grade stands for...", ["frequency", "intensity", "work function", "mass defect"], 0, "Packet grade tracks photon frequency.", ["brightness_beats_threshold_confusion"], ["photon_energy"]),
            ("A low-frequency bright beam fails at the release gate when...", ["no single packet can pay the unlock toll", "the metal is too shiny", "the intensity is too low", "electrons need time to warm up"], 0, "Threshold is a per-packet energy condition.", ["brightness_beats_threshold_confusion", "photoelectron_delay_confusion"], ["threshold_reasoning"]),
            ("Increasing beam count at fixed packet grade mainly changes...", ["how many photoelectrons are emitted", "the maximum kinetic energy of each photoelectron", "the work function of the metal", "the threshold frequency"], 0, "Intensity changes packet number, not energy per packet.", ["intensity_sets_electron_energy_confusion"], ["intensity_vs_count"]),
            ("The unlock toll in formal physics is the...", ["work function", "frequency", "wavelength", "binding energy"], 0, "The work function is the minimum energy needed to free an electron.", ["brightness_beats_threshold_confusion"], ["work_function_meaning"]),
            ("If the light frequency is below threshold, photoelectrons are emitted...", ["not at all", "after a long delay", "with small kinetic energy", "only if intensity is doubled"], 0, "Below threshold there are no emitted electrons.", ["brightness_beats_threshold_confusion", "photoelectron_delay_confusion"], ["threshold_reasoning"]),
            ("A photoelectron is the...", ["emitted electron", "incoming photon", "metal ion", "nucleus"], 0, "The escape runner is the emitted electron.", ["photoelectron_delay_confusion"], ["photoelectric_terms"]),
            ("Which change raises the energy of each flash packet?", ["increase frequency", "increase intensity", "increase metal area", "increase beam count"], 0, "Photon energy depends on frequency.", ["intensity_sets_electron_energy_confusion"], ["photon_energy"]),
            ("Why is emission immediate above threshold?", ["one photon can transfer enough energy in a single interaction", "the metal first stores brightness", "electrons need to build momentum gradually", "current in the wire pushes them out"], 0, "The photoelectric effect shows prompt packet transfer.", ["photoelectron_delay_confusion"], ["instant_emission"]),
        ],
    ) + build_shorts(
        "A5L1_D",
        [
            (
                "Why can a dim high-frequency beam eject electrons while a bright low-frequency beam cannot?",
                [
                    "Because each photon in the high-frequency beam can have enough energy to exceed the work function, while low-frequency photons cannot even if many arrive.",
                    "Because threshold depends on energy per photon, not on brightness alone.",
                ],
                "Mention energy per photon and the work function threshold.",
                ["brightness_beats_threshold_confusion", "intensity_sets_electron_energy_confusion"],
                ["threshold_reasoning", "photon_energy"],
                acceptance_groups(["frequency", "high frequency", "photon energy", "energy per photon"], ["work function", "threshold", "unlock toll"], ["brightness", "intensity", "many photons"], ["not enough", "cannot eject", "still fails"]),
            ),
            (
                "What does beam count mean in this model?",
                [
                    "It means how many photons arrive each second, so it is the intensity or packet count of the beam.",
                    "It is the number of packets arriving per second.",
                ],
                "Link beam count to photon arrival rate or intensity.",
                ["intensity_sets_electron_energy_confusion"],
                ["intensity_vs_count"],
                acceptance_groups(["number of photons", "photons per second", "packet count"], ["intensity", "beam count", "arrival rate"]),
            ),
        ],
    )
    concept = build_mcqs(
        "A5L1_C",
        [
            ("A metal has threshold frequency f0. Which beam definitely ejects electrons?", ["frequency above f0", "frequency below f0 but very bright", "frequency equal to zero but intense", "any beam if left on long enough"], 0, "Only photons above threshold work.", ["brightness_beats_threshold_confusion"], ["threshold_reasoning"]),
            ("If frequency stays fixed above threshold and intensity doubles, the number of emitted electrons should...", ["increase", "stay the same", "drop to zero", "reverse direction"], 0, "More photons above threshold means more emitted electrons.", ["intensity_sets_electron_energy_confusion"], ["intensity_vs_count"]),
            ("Which statement best matches the photoelectric evidence?", ["energy transfer is packet-based", "energy transfer is always continuous", "electrons absorb half a photon each", "light energy depends only on brightness"], 0, "Photoelectric data supports photons.", ["brightness_beats_threshold_confusion"], ["packet_meaning"]),
            ("The threshold frequency is linked directly to the...", ["work function of the metal", "intensity of the beam", "mass of the electron", "distance to the source"], 0, "Different metals have different work functions.", ["brightness_beats_threshold_confusion"], ["work_function_meaning"]),
            ("At fixed intensity, increasing frequency above threshold makes photoelectrons...", ["more energetic", "more delayed", "impossible to emit", "identical in kinetic energy"], 0, "Higher frequency means greater photon energy.", ["intensity_sets_electron_energy_confusion"], ["photon_energy"]),
            ("Why is the release gate model stronger than a 'light warms electrons out' story?", ["it explains the sharp threshold and immediate emission", "it removes the need for photons", "it predicts lower frequency gives faster electrons", "it says brightness and frequency do the same job"], 0, "Threshold plus prompt emission are the key clues.", ["photoelectron_delay_confusion", "brightness_beats_threshold_confusion"], ["packet_meaning"]),
        ],
    ) + build_shorts(
        "A5L1_C",
        [
            (
                "What does the threshold frequency tell you about a metal?",
                [
                    "It tells you the minimum photon frequency needed to eject electrons from that metal.",
                    "It is the lowest frequency that gives enough photon energy to overcome the work function.",
                ],
                "Use minimum frequency or enough photon energy language.",
                ["brightness_beats_threshold_confusion"],
                ["work_function_meaning", "threshold_reasoning"],
                acceptance_groups(["minimum", "lowest"], ["frequency", "photon"], ["work function", "enough energy", "threshold"], ["eject electrons", "photoelectrons"]),
            ),
            (
                "Why does increasing intensity below threshold still fail?",
                [
                    "Because it adds more low-energy photons, but no single photon has enough energy to free an electron.",
                    "Because intensity changes photon number, not photon energy, so the threshold is still not met.",
                ],
                "Keep photon number separate from photon energy.",
                ["brightness_beats_threshold_confusion", "intensity_sets_electron_energy_confusion"],
                ["threshold_reasoning", "intensity_vs_count"],
                acceptance_groups(["more photons", "more packets", "higher intensity"], ["not enough energy", "each photon", "single photon"], ["threshold", "work function", "unlock toll"]),
            ),
        ],
    )
    mastery = build_mcqs(
        "A5L1_M",
        [
            ("Which change can turn a no-emission beam into an emission beam without changing intensity?", ["raise frequency above threshold", "increase exposure time", "increase metal thickness", "lower intensity"], 0, "Frequency controls packet energy.", ["brightness_beats_threshold_confusion"], ["threshold_reasoning"]),
            ("Two beams have equal intensity. Beam A has higher frequency than beam B. Above threshold, Beam A gives photoelectrons with...", ["greater maximum kinetic energy", "the same maximum kinetic energy", "smaller work function", "no immediate emission"], 0, "Higher frequency means more energy per photon.", ["intensity_sets_electron_energy_confusion"], ["photon_energy"]),
            ("Why does a threshold frequency support the photon model?", ["because emission depends on single-packet energy", "because brightness can never matter", "because electrons are made of photons", "because all metals share one work function"], 0, "Threshold is an all-or-nothing per-photon clue.", ["brightness_beats_threshold_confusion"], ["packet_meaning"]),
            ("If the metal is changed to one with a larger work function, the threshold frequency...", ["increases", "decreases", "stays fixed for all metals", "becomes the intensity"], 0, "Larger work function means higher threshold frequency.", ["brightness_beats_threshold_confusion"], ["work_function_meaning"]),
            ("What is the best role of intensity in the packet picture above threshold?", ["it changes how many electrons can be emitted per second", "it sets the work function", "it changes photon frequency", "it removes the threshold"], 0, "Intensity is packet rate.", ["intensity_sets_electron_energy_confusion"], ["intensity_vs_count"]),
            ("Which observation is hardest for a classical continuous-wave energy story?", ["instant emission only above threshold frequency", "light travelling in vacuum", "metals reflecting light", "electron attraction to nuclei"], 0, "Classical theory struggles with prompt threshold behaviour.", ["photoelectron_delay_confusion"], ["packet_meaning"]),
            ("A beam has photons just above threshold. The emitted electrons will have...", ["small maximum kinetic energy", "no emission", "very large kinetic energy regardless of frequency", "negative kinetic energy"], 0, "Most energy is used paying the work function, leaving little extra.", ["intensity_sets_electron_energy_confusion"], ["threshold_edge_case"]),
            ("The strongest one-sentence lesson summary is...", ["frequency sets photon energy, intensity sets photon count", "intensity sets photon energy, frequency sets count", "brightness and frequency do identical jobs", "threshold depends on intensity only"], 0, "That is the clean modern summary.", ["brightness_beats_threshold_confusion", "intensity_sets_electron_energy_confusion"], ["packet_meaning"]),
        ],
    ) + build_shorts(
        "A5L1_M",
        [
            (
                "Why is the photoelectric effect described as all-or-nothing per photon?",
                [
                    "Because each emitted electron is freed by one photon transferring enough energy in a single interaction to overcome the work function.",
                    "Because one photon must individually exceed the work function for emission to occur.",
                ],
                "Use one-photon and work-function language.",
                ["brightness_beats_threshold_confusion", "photoelectron_delay_confusion"],
                ["packet_meaning", "threshold_reasoning"],
                acceptance_groups(["one photon", "single photon", "each photon"], ["work function", "enough energy", "threshold"], ["single interaction", "immediate", "all or nothing"]),
            ),
            (
                "A student says, 'A brighter beam always gives more energetic electrons.' Correct them.",
                [
                    "Brighter light means more photons per second, so it can increase the number of emitted electrons, but the maximum kinetic energy depends on photon frequency, not brightness.",
                    "Intensity changes count, whereas frequency changes energy per photon and therefore the maximum kinetic energy.",
                ],
                "Separate count from energy per photon.",
                ["intensity_sets_electron_energy_confusion"],
                ["intensity_vs_count", "frequency_vs_kmax"],
                acceptance_groups(["brightness", "intensity"], ["more photons", "number emitted", "count"], ["frequency", "photon energy"], ["kinetic energy", "maximum kinetic energy"]),
            ),
        ],
    )
    return lesson_spec(
        "A5_L1",
        "Beat the Release Gate",
        sim(
            "a5_release_gate_lab",
            "Release gate lab",
            "Vary packet grade and beam count independently so threshold frequency, immediate emission, and count-versus-energy reasoning stay clean.",
            ["Start below threshold and increase intensity only.", "Raise frequency above threshold.", "Compare how count and electron energy respond."],
            ["Explain threshold frequency.", "Separate photon energy from photon count.", "Predict immediate emission once a photon can pay the unlock toll."],
            ["packet_grade", "beam_count", "work_function", "emission_count", "runner_kick"],
            "Threshold reasoning.",
        ),
        diagnostic,
        "The Packet-Pattern Frame world begins with the release gate. A flash packet arrives, and either it can pay the unlock toll or it cannot. If its packet grade is too low, nothing happens even when many packets arrive. If one packet is strong enough, an electron escapes immediately. That is why the photoelectric effect forces a packet view of light rather than a brightness-only view.",
        "Commit to threshold as a per-photon rule, not a brightness buildup rule.",
        [
            prompt_block("What does packet grade control?", "The energy of each photon."),
            prompt_block("What does beam count control?", "How many photons arrive each second."),
        ],
        [
            prompt_block("Keep frequency below threshold first.", "Intensity should still fail to produce photoelectrons."),
            prompt_block("Then raise frequency slightly above threshold.", "Emission should begin immediately."),
        ],
        [
            "Why does one bright low-frequency beam still fail if every packet is too weak?",
            "Why does the threshold story make frequency more fundamental than brightness for emission?",
        ],
        "Use the release-gate model to explain threshold, immediate emission, and the separate roles of frequency and intensity.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Explain why the photoelectric effect requires discrete photon energy.",
                "Relate threshold frequency to the work function of a metal.",
                "Separate the role of intensity from the role of frequency in photoemission.",
            ],
            core_concepts=[
                "Each photon carries energy E = hf.",
                "Emission requires one photon to exceed the work function threshold.",
                "Intensity changes photon count rather than energy per photon.",
                "Above threshold, emission is immediate because energy transfer is not gradual buildup.",
            ],
            prerequisite_lessons=[],
            misconception_focus=[
                "brightness_beats_threshold_confusion",
                "intensity_sets_electron_energy_confusion",
                "photoelectron_delay_confusion",
            ],
            formulas=[
                relation("E = h f", "Photon energy relation.", ["J"], "Use to connect frequency to the energy of each photon."),
            ],
            representations=[
                representation("threshold diagram", "Shows a gate with a minimum per-packet energy."),
                representation("words", "Explains frequency as packet grade and intensity as packet count."),
                representation("comparison table", "Contrasts below-threshold and above-threshold beams."),
                representation("cause chain", "Links packet grade -> gate outcome -> emission."),
            ],
            analogy_map=packet_pattern_frame_map("the learner tests whether packets can beat the release gate"),
            worked_examples=[
                worked("Why does a bright beam below threshold fail?", ["Identify that intensity changes photon count.", "Recall that each photon still has the same low energy.", "Conclude that no single photon can pay the work function."], "No emission occurs", "Many weak packets do not combine to free one electron in the photoelectric effect.", "This is the cleanest threshold argument."),
                worked("Why can a dim high-frequency beam still work?", ["Link high frequency to high photon energy using E = hf.", "Compare that energy with the work function.", "Conclude that even a small number of photons can eject electrons if each is above threshold."], "Emission can occur immediately", "Threshold depends on per-photon energy, not on brightness alone.", "This protects the packet interpretation."),
                worked("What changes when intensity increases above threshold?", ["Keep the frequency fixed so photon energy stays fixed.", "Increase the number of photons arriving per second.", "Infer that more electrons may be emitted, but each keeps the same maximum energy."], "Emission count rises, but Kmax does not", "Intensity controls event rate rather than energy per event.", "This is the essential intensity-frequency split."),
            ],
            visual_assets=[
                visual(
                    "a5-l1-release-gate",
                    "modern_physics_diagram",
                    "Threshold beats brightness at the release gate",
                    "Show low-grade bright packets failing and high-grade packets succeeding so the threshold remains a per-photon rule.",
                    "The unlock toll is paid per photon, so brightness alone cannot replace threshold frequency.",
                    template="modern_physics_diagram",
                    meta={"diagram_type": "photoelectric_threshold"},
                )
            ],
            simulation_contract=sim_contract(
                "a5_l1_release_gate_sim",
                "photoelectric_gate",
                "Change packet grade and beam count separately, then explain why threshold depends on photon energy rather than brightness.",
                "Start below threshold and double the beam count before you change the packet grade.",
                [
                    "Raise beam count while keeping packet grade below the unlock toll.",
                    "Raise packet grade just above threshold and watch emission begin immediately.",
                    "Compare how emission count and runner kick respond to grade and count changes.",
                ],
                "Watch for the difference between more packets and more energetic packets.",
                "Threshold frequency is a single-packet energy rule, and intensity only changes how many packets arrive.",
                controls=[
                    ("packet_grade", "Packet grade", "Sets photon frequency and therefore energy per packet."),
                    ("beam_count", "Beam count", "Sets how many photons arrive per second."),
                    ("unlock_toll", "Unlock toll", "Represents the work function of the metal."),
                ],
                readouts=[
                    ("Emission count", "Shows how many electrons are released."),
                    ("Maximum runner kick", "Shows the largest photoelectron kinetic energy."),
                ],
            ),
            reflection_prompts=[
                "Explain why a bright low-frequency beam can still fail at the release gate.",
                "Describe the separate jobs of packet grade and beam count in the photoelectric effect.",
            ],
            mastery_skills=["packet_meaning", "threshold_reasoning", "photon_energy", "intensity_vs_count", "instant_emission"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between threshold judgments, intensity-versus-frequency comparisons, and short explanations of immediate emission.",
                "concept_gate": "Concept-gate retries alternate between new threshold scenarios and explanation stems about why brightness cannot replace frequency.",
                "mastery": "Mastery prefers unseen lesson-owned threshold, count, and immediate-emission questions before repeating any stem.",
            },
            scaffold_support=scaffold(
                "A photon must individually beat the unlock toll.",
                "The photoelectric effect becomes coherent when learners treat threshold as a per-photon condition and brightness as a packet-count condition.",
                "What does one photon need to do by itself before any electron can escape?",
                "Letting many weak photons combine into one successful photoelectron event.",
                "The release gate behaves like a checkpoint that each packet must beat on its own. A crowd of underqualified packets still fails, but one strong enough packet works immediately.",
                "Why does the gate story make emission prompt instead of delayed?",
                extras=[
                    extra_section("Threshold first", "Ask whether one photon can pay the toll before asking how many photons arrive. That order stops most intensity-frequency confusions.", "Which question should you answer first in a photoelectric problem?"),
                    extra_section("Count versus energy", "A busier beam means more photon events per second, but the energy of each event still comes from frequency.", "What changes if the beam gets brighter but the colour stays the same?"),
                ],
            ),
            visual_clarity_checks=visual_checks("photoelectric threshold"),
        ),
    )


def lesson_two() -> Dict[str, Any]:
    diagnostic = build_mcqs(
        "A5L2_D",
        [
            ("The photoelectric equation is best written as...", ["hf = phi + Kmax", "hf = phiKmax", "Kmax = phi - hf", "hf = I + Kmax"], 0, "Photon energy is shared between work function and maximum kinetic energy.", ["intensity_sets_electron_energy_confusion"], ["photoelectric_equation"]),
            ("In hf = phi + Kmax, the work function phi is the energy used to...", ["free the electron from the metal", "increase intensity", "change the wavelength in vacuum", "create the photon"], 0, "The work function is the unlock toll.", ["brightness_beats_threshold_confusion"], ["work_function_meaning"]),
            ("Above threshold, if frequency increases while the metal stays the same, Kmax...", ["increases", "decreases", "stays fixed", "becomes the work function"], 0, "More photon energy leaves more leftover kinetic energy.", ["intensity_sets_electron_energy_confusion"], ["frequency_vs_kmax"]),
            ("At fixed frequency above threshold, doubling intensity changes Kmax by...", ["nothing", "doubling it", "halving it", "making it zero"], 0, "Kmax depends on photon energy, not beam count.", ["intensity_sets_electron_energy_confusion"], ["kmax_vs_intensity"]),
            ("When frequency is exactly at threshold, Kmax is...", ["zero", "equal to hf", "equal to intensity", "negative"], 0, "All photon energy is used to free the electron.", ["brightness_beats_threshold_confusion"], ["threshold_edge_case"]),
            ("Maximum kinetic energy means...", ["the largest possible photoelectron kinetic energy", "the average photon energy", "the work function of the surface", "the total beam power"], 0, "Kmax is about the most energetic emitted electrons.", ["intensity_sets_electron_energy_confusion"], ["photoelectric_terms"]),
            ("A steeper graph of Kmax against frequency would mean...", ["greater rise in electron energy per rise in frequency", "greater beam intensity", "a lower speed of light", "a smaller work function automatically"], 0, "The graph ties photon energy rise to kinetic-energy rise.", ["intensity_sets_electron_energy_confusion"], ["graph_reasoning"]),
            ("Why is the intercept on the frequency axis meaningful?", ["it marks the threshold frequency", "it shows the intensity", "it gives the wavelength directly", "it shows the electron mass"], 0, "Kmax becomes zero at threshold frequency.", ["brightness_beats_threshold_confusion"], ["graph_reasoning"]),
        ],
    ) + build_shorts(
        "A5L2_D",
        [
            (
                "What happens to the leftover photon energy after the work function is paid?",
                [
                    "It appears as the maximum kinetic energy of the emitted photoelectron.",
                    "After the unlock toll is paid, the remaining energy becomes the electron's kinetic energy.",
                ],
                "Use leftover-energy or kinetic-energy language.",
                ["intensity_sets_electron_energy_confusion"],
                ["energy_bookkeeping", "photoelectric_equation"],
                acceptance_groups(["leftover", "remaining"], ["kinetic energy", "Kmax", "bonus kick"], ["electron", "photoelectron"]),
            ),
            (
                "Why does the photoelectric equation support an energy-bookkeeping view?",
                [
                    "Because the photon energy is split between the work function and the electron's maximum kinetic energy.",
                    "Because hf accounts for both paying the work function and giving any extra energy to the emitted electron.",
                ],
                "Show where the incoming photon energy goes.",
                ["brightness_beats_threshold_confusion", "intensity_sets_electron_energy_confusion"],
                ["energy_bookkeeping", "photoelectric_equation"],
                acceptance_groups(["hf", "photon energy"], ["work function", "unlock toll"], ["kinetic energy", "Kmax", "leftover"]),
            ),
        ],
    )
    concept = build_mcqs(
        "A5L2_C",
        [
            ("A photon has energy 5 eV and the work function is 2 eV. Kmax is...", ["3 eV", "7 eV", "2 eV", "0 eV"], 0, "Use hf = phi + Kmax.", ["intensity_sets_electron_energy_confusion"], ["use_photoelectric_eq"]),
            ("If the work function stays fixed but frequency falls closer to threshold, Kmax...", ["falls", "rises", "stays the same", "becomes intensity"], 0, "Smaller photon energy leaves less leftover energy.", ["intensity_sets_electron_energy_confusion"], ["frequency_vs_kmax"]),
            ("Which graph statement is correct?", ["Kmax vs frequency is linear above threshold", "Kmax vs intensity gives the threshold frequency", "Kmax is always zero above threshold", "frequency and Kmax are unrelated"], 0, "The Einstein photoelectric equation predicts a straight line above threshold.", ["intensity_sets_electron_energy_confusion"], ["graph_reasoning"]),
            ("At threshold frequency, the photoelectron just...", ["escapes with zero maximum kinetic energy", "escapes with maximum beam intensity", "stays trapped because threshold is impossible", "moves faster than light"], 0, "Threshold means barely enough energy to escape.", ["brightness_beats_threshold_confusion"], ["threshold_edge_case"]),
            ("Why does increasing intensity above threshold not shift the threshold frequency?", ["because the metal's work function is unchanged", "because intensity changes photon energy", "because photons merge into one larger photon", "because electrons stop obeying quantum ideas"], 0, "Threshold belongs to the metal and photon energy condition.", ["intensity_sets_electron_energy_confusion"], ["work_function_meaning"]),
            ("Best reason why the photoelectric equation is not a heating equation:", ["it tracks one-photon energy transfer to one electron event", "it only works for hot metals", "it ignores kinetic energy", "it says intensity is the same as frequency"], 0, "The photoelectric effect is event-based, not bulk warming.", ["photoelectron_delay_confusion"], ["energy_bookkeeping"]),
        ],
    ) + build_shorts(
        "A5L2_C",
        [
            (
                "How does Kmax change if the photon frequency rises while the work function stays fixed?",
                [
                    "Kmax increases because each photon brings more energy, so more is left after the work function is paid.",
                    "The maximum kinetic energy rises with frequency once the threshold is exceeded.",
                ],
                "Link higher frequency to greater leftover energy.",
                ["intensity_sets_electron_energy_confusion"],
                ["frequency_vs_kmax"],
                acceptance_groups(["frequency rises", "higher frequency"], ["more energy", "higher photon energy"], ["kinetic energy", "Kmax", "leftover"], ["increases", "rises"]),
            ),
            (
                "Why does intensity mostly change the number of photoelectrons rather than Kmax?",
                [
                    "Because intensity changes how many photons arrive, but the energy of each photon is still set by frequency.",
                    "Beam count affects how many emission events happen, not the energy of each individual event.",
                ],
                "Keep count and per-photon energy separate.",
                ["intensity_sets_electron_energy_confusion"],
                ["kmax_vs_intensity", "intensity_vs_count"],
                acceptance_groups(["intensity", "beam count"], ["number of photons", "more photons"], ["frequency", "energy per photon"], ["Kmax", "kinetic energy"]),
            ),
        ],
    )
    mastery = build_mcqs(
        "A5L2_M",
        [
            ("A metal has work function 1.8 eV. Light of energy 2.5 eV ejects electrons with Kmax...", ["0.7 eV", "4.3 eV", "1.8 eV", "0 eV"], 0, "Subtract the work function from photon energy.", ["intensity_sets_electron_energy_confusion"], ["use_photoelectric_eq"]),
            ("If Kmax is zero, the light frequency is...", ["at the threshold frequency", "well above threshold", "below threshold with high intensity", "unrelated to threshold"], 0, "Zero maximum kinetic energy means just enough energy to escape.", ["brightness_beats_threshold_confusion"], ["threshold_edge_case"]),
            ("Which change raises Kmax for the same metal?", ["increase frequency", "increase intensity only", "increase beam area only", "run the beam for longer"], 0, "Kmax follows photon energy.", ["intensity_sets_electron_energy_confusion"], ["frequency_vs_kmax"]),
            ("A larger work function means that, for the same photon frequency above threshold, Kmax is...", ["smaller", "larger", "unchanged", "equal to intensity"], 0, "More energy is spent on the unlock toll.", ["brightness_beats_threshold_confusion"], ["work_function_compare"]),
            ("The slope of a Kmax-f graph tells you that...", ["kinetic energy rises as photon frequency rises", "intensity controls threshold", "photons lose mass in the metal", "the electron mass changes"], 0, "It is the linear energy-transfer story.", ["intensity_sets_electron_energy_confusion"], ["graph_reasoning"]),
            ("Which statement is strongest?", ["frequency changes the energy of each photoelectron event, intensity changes how many events occur", "frequency and intensity do the same job", "intensity determines the threshold", "Kmax is set by beam count only"], 0, "This is the clean full summary.", ["brightness_beats_threshold_confusion", "intensity_sets_electron_energy_confusion"], ["energy_bookkeeping"]),
            ("If the photon energy is just slightly bigger than phi, emitted electrons have...", ["small Kmax", "huge Kmax", "zero emission", "negative work function"], 0, "Only a little energy remains after the toll is paid.", ["intensity_sets_electron_energy_confusion"], ["threshold_edge_case"]),
            ("What does the photoelectric graph intercept on the Kmax axis depend on?", ["the work function and threshold relationship", "intensity only", "beam area only", "electron count only"], 0, "The line structure comes from hf = phi + Kmax.", ["brightness_beats_threshold_confusion"], ["graph_reasoning"]),
        ],
    ) + build_shorts(
        "A5L2_M",
        [
            (
                "Explain the phrase 'pay the toll, keep the kick' in formal physics terms.",
                [
                    "It means photon energy first pays the work function, and any remaining energy appears as the maximum kinetic energy of the photoelectron.",
                    "In hf = phi + Kmax, phi is the unlock toll and Kmax is the leftover kick.",
                ],
                "Translate both parts into phi and Kmax.",
                ["brightness_beats_threshold_confusion", "intensity_sets_electron_energy_confusion"],
                ["energy_bookkeeping", "photoelectric_equation"],
                acceptance_groups(["photon energy", "hf"], ["work function", "phi", "unlock toll"], ["kinetic energy", "Kmax", "leftover", "kick"]),
            ),
            (
                "A student says, 'Intensity changes Kmax because more light means stronger electrons.' Correct them.",
                [
                    "Intensity changes how many photons hit the surface, so it mainly changes how many electrons are emitted, while Kmax depends on frequency and the work function.",
                    "More light means more events, not more energy per photoelectron when the frequency is fixed.",
                ],
                "Separate event count from energy per event.",
                ["intensity_sets_electron_energy_confusion"],
                ["kmax_vs_intensity", "frequency_vs_kmax"],
                acceptance_groups(["intensity", "more light"], ["more photons", "more events", "more electrons"], ["frequency", "energy per photon"], ["Kmax", "kinetic energy"]),
            ),
        ],
    )
    return lesson_spec(
        "A5_L2",
        "Pay the Toll, Keep the Kick",
        sim(
            "a5_packet_kick_lab",
            "Packet kick lab",
            "Track how photon energy is split between the unlock toll and the leftover kick so the photoelectric equation reads like bookkeeping rather than a symbol trick.",
            ["Choose a work function.", "Raise photon frequency above threshold.", "Compare Kmax while changing intensity separately."],
            ["Use hf = phi + Kmax.", "Explain threshold-edge cases.", "Predict how Kmax responds to frequency or work-function changes."],
            ["packet_grade", "unlock_toll", "beam_count", "photon_energy", "runner_kick"],
            "Energy bookkeeping.",
        ),
        diagnostic,
        "Once a packet can beat the release gate, one more question matters: how much energy is left after the unlock toll is paid? The photoelectric equation answers that cleanly. Photon energy enters, the work function is paid, and the bonus kick appears as the maximum kinetic energy of the photoelectron. This is not a brightness story. It is a one-event energy-bookkeeping story.",
        "Commit to the photoelectric equation as bookkeeping for one photon and one electron event.",
        [
            prompt_block("What is paid first in the photoelectric equation?", "The work function phi."),
            prompt_block("What does the leftover energy become?", "The maximum kinetic energy Kmax."),
        ],
        [
            prompt_block("Start exactly at threshold.", "Kmax should be zero."),
            prompt_block("Now raise the packet grade without changing beam count.", "Kmax should rise because more energy is left over."),
        ],
        [
            "Why does the photoelectric equation act like an energy budget rather than a heating rule?",
            "Why can the beam count rise while the bonus kick stays the same?",
        ],
        "Use the equation to keep threshold, work function, and maximum kinetic energy in one causal chain.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Apply hf = phi + Kmax as an energy-bookkeeping equation.",
                "Explain threshold frequency as the case where Kmax just falls to zero.",
                "Separate changes in Kmax from changes in emission rate.",
            ],
            core_concepts=[
                "Photon energy first pays the work function.",
                "Any leftover energy appears as the maximum kinetic energy of the photoelectron.",
                "Frequency changes Kmax at fixed metal; intensity mainly changes the number of events.",
                "The threshold point is the zero-leftover edge case.",
            ],
            prerequisite_lessons=["A5_L1"],
            misconception_focus=[
                "brightness_beats_threshold_confusion",
                "intensity_sets_electron_energy_confusion",
            ],
            formulas=[
                relation("h f = phi + Kmax", "Einstein photoelectric equation.", ["J"], "Use when one photon ejects one electron from a given metal."),
                relation("Kmax = h f - phi", "Rearranged maximum kinetic energy relation.", ["J"], "Valid only above threshold frequency."),
            ],
            representations=[
                representation("equation story", "Tracks incoming photon energy, unlock toll, and leftover kick."),
                representation("graph", "Shows Kmax rising with frequency above threshold."),
                representation("threshold edge case", "Shows Kmax = 0 when frequency is exactly at threshold."),
                representation("comparison table", "Contrasts frequency changes with intensity changes."),
            ],
            analogy_map=packet_pattern_frame_map("the learner tracks where photon energy goes after a release-gate success"),
            worked_examples=[
                worked("Photon energy is 5 eV and work function is 2 eV. What is Kmax?", ["Write hf = phi + Kmax.", "Substitute 5 eV for hf and 2 eV for phi.", "Calculate the leftover energy."], "3 eV", "The bonus kick is whatever remains after the toll is paid.", "This is the core photoelectric calculation."),
                worked("Why is Kmax zero at threshold frequency?", ["Say that threshold means the photon has just enough energy to free the electron.", "Notice that no energy is left over after paying phi.", "Conclude Kmax = 0."], "No leftover kinetic energy remains", "Threshold is the exact boundary between no emission and emission with leftover energy.", "This turns the threshold idea into a calculation boundary."),
                worked("Intensity doubles while frequency stays fixed above threshold. What changes?", ["Keep hf fixed because frequency is unchanged.", "Note that phi is set by the metal and is unchanged.", "Conclude Kmax stays the same while the event rate can increase."], "Kmax stays the same; emission count can rise", "Intensity adds more packets, not more energy per packet.", "This protects the frequency-intensity split."),
            ],
            visual_assets=[
                visual(
                    "a5-l2-packet-kick",
                    "modern_physics_diagram",
                    "Pay the work-function toll, then keep the leftover kick",
                    "Show photon energy being split into the unlock toll and the photoelectron's maximum kinetic energy.",
                    "The photoelectric equation is best read as energy bookkeeping: incoming packet energy becomes toll plus bonus kick.",
                    template="modern_physics_diagram",
                    meta={"diagram_type": "photoelectric_energy_budget"},
                )
            ],
            simulation_contract=sim_contract(
                "a5_l2_packet_kick_sim",
                "packet_kick",
                "Change photon energy and work function, then explain what happens to the leftover kinetic-energy kick.",
                "Set the photon energy just above threshold so the leftover kick starts small.",
                [
                    "Increase photon energy while keeping the work function fixed.",
                    "Keep photon energy fixed and raise the work function.",
                    "Double beam count and compare the event count with the unchanged Kmax.",
                ],
                "Watch for Kmax responding to photon energy and work function, not to brightness alone.",
                "The photoelectric equation is a clean input-output energy budget for one emitted electron event.",
                controls=[
                    ("packet_grade", "Packet grade", "Sets the energy entering in each photon."),
                    ("unlock_toll", "Unlock toll", "Represents the metal work function."),
                    ("beam_count", "Beam count", "Lets learners test intensity without changing photon energy."),
                ],
                readouts=[
                    ("Photon energy", "Shows the incoming packet energy."),
                    ("Maximum kick", "Shows the leftover kinetic energy after the work function is paid."),
                ],
            ),
            reflection_prompts=[
                "Explain why Kmax is an energy-leftover idea rather than a brightness idea.",
                "Describe what the threshold case looks like in hf = phi + Kmax.",
            ],
            mastery_skills=["photoelectric_equation", "use_photoelectric_eq", "frequency_vs_kmax", "kmax_vs_intensity", "energy_bookkeeping"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between symbolic interpretations, threshold-edge questions, and quick comparisons of frequency versus intensity changes.",
                "concept_gate": "Concept-gate retries alternate between new phi-hf pairings and explanation prompts about why intensity does not set Kmax.",
                "mastery": "Mastery prefers unseen lesson-owned calculations, graph reasoning, and correction-of-misconception stems before repeating any item.",
            },
            scaffold_support=scaffold(
                "Photon energy is split into toll plus leftover kick.",
                "The photoelectric equation becomes intuitive when learners read it as a two-stage energy budget rather than as a memorized formula.",
                "What two places can the incoming photon energy go?",
                "Treating Kmax as if it comes from beam brightness instead of leftover photon energy.",
                "A successful packet first unlocks the gate, then uses any remaining credit to launch the escape runner faster.",
                "Why does the runner get no bonus kick right at threshold?",
                extras=[
                    extra_section("Threshold edge case", "At threshold, the packet can free the electron but cannot spare any extra kinetic energy. This is why Kmax falls to zero there.", "What makes the threshold point special on a Kmax graph?"),
                    extra_section("Count versus kick", "A busier beam can create more successful escapes per second, but the kick of each success still depends on photon energy and work function.", "What changes when only the beam count rises?"),
                ],
            ),
            visual_clarity_checks=visual_checks("photoelectric energy budget"),
        ),
    )


def lesson_three() -> Dict[str, Any]:
    diagnostic = build_mcqs(
        "A5L3_D",
        [
            ("A hit dot in the Packet-Pattern Frame model represents...", ["one localized detection event", "a spread-out classical wave", "the work function", "a magnetic field line"], 0, "Detections occur as localized events.", ["wave_particle_switch_confusion"], ["hit_dot_meaning"]),
            ("A pattern map represents...", ["the distribution built from many detection events", "one photoelectron only", "a nuclear mass defect", "a light-clock tick"], 0, "The pattern is the distribution over many hits.", ["pattern_means_smear_confusion"], ["pattern_distribution"]),
            ("Wave-particle duality is strongest described as...", ["localized detections with wave-like distributions", "particles turning into water waves", "waves becoming matter only when watched", "electrons losing mass"], 0, "Keep dot-events and pattern-rules together.", ["wave_particle_switch_confusion"], ["duality_meaning"]),
            ("The de Broglie relation is...", ["lambda = h/p", "E = hf", "E = mc^2", "v = u + at"], 0, "Matter wavelength is h divided by momentum.", ["de_broglie_light_only_confusion"], ["debroglie_relation"]),
            ("If momentum increases, the de Broglie wavelength...", ["decreases", "increases", "stays the same", "becomes the work function"], 0, "Wavelength and momentum are inversely related.", ["de_broglie_light_only_confusion"], ["momentum_vs_wavelength"]),
            ("Sending particles one at a time through a two-path setup still builds an interference pattern because...", ["the distribution is wave-like even though detections are discrete", "the particles are really classical waves only", "the detector makes up dots later", "intensity creates work function"], 0, "Single events can accumulate into a pattern.", ["wave_particle_switch_confusion", "pattern_means_smear_confusion"], ["dot_to_pattern"]),
            ("Which quantity can have a de Broglie wavelength?", ["an electron", "only visible light", "only photons", "only nuclei at rest"], 0, "Matter particles can have wavelengths too.", ["de_broglie_light_only_confusion"], ["matter_wave_evidence"]),
            ("The best meaning of 'pattern + hit' is...", ["a particle is detected locally, but repeated detections follow a wave-like distribution", "a particle must choose to be one thing only", "all particles are smeared out continuously", "detection is never localized"], 0, "Keep both sides of the evidence.", ["wave_particle_switch_confusion"], ["duality_meaning"]),
        ],
    ) + build_shorts(
        "A5L3_D",
        [
            (
                "Why do single detection events still support a wave-like model?",
                [
                    "Because each event is a localized hit, but many repeated hits build a distribution that follows wave-like rules.",
                    "Because the pattern appears in the statistics of many dots rather than in one dot alone.",
                ],
                "Use repeated-hits build-a-pattern language.",
                ["wave_particle_switch_confusion", "pattern_means_smear_confusion"],
                ["dot_to_pattern", "pattern_distribution"],
                acceptance_groups(["many hits", "many dots", "repeated detections"], ["pattern", "distribution", "interference"], ["single hit", "localized", "discrete"]),
            ),
            (
                "What does the de Broglie relation say about moving matter?",
                [
                    "It says moving matter particles have a wavelength given by h divided by momentum.",
                    "It assigns matter a wavelength lambda = h/p.",
                ],
                "Mention wavelength and momentum together.",
                ["de_broglie_light_only_confusion"],
                ["debroglie_relation"],
                acceptance_groups(["matter", "particle", "electron"], ["wavelength", "lambda"], ["momentum", "p"], ["h/p", "h divided by p"]),
            ),
        ],
    )
    concept = build_mcqs(
        "A5L3_C",
        [
            ("An electron's momentum is doubled. Its de Broglie wavelength becomes...", ["half as large", "twice as large", "unchanged", "equal to c"], 0, "Use lambda = h/p.", ["de_broglie_light_only_confusion"], ["momentum_vs_wavelength"]),
            ("Which statement best protects against the 'switching identity' mistake?", ["modern particles require both hit-dot and pattern-map descriptions", "particles are ordinary waves all the time", "particles are ordinary marbles until observed", "waves and particles are unrelated topics"], 0, "Experiments require both kinds of description.", ["wave_particle_switch_confusion"], ["duality_meaning"]),
            ("A diffraction pattern built from electrons shows that...", ["matter can show wave-like behavior", "electrons stop being particles forever", "frequency equals work function", "nuclear binding has changed"], 0, "Electron diffraction is matter-wave evidence.", ["de_broglie_light_only_confusion"], ["matter_wave_evidence"]),
            ("Why is one hit dot not enough to reveal the pattern map?", ["one event is localized; the distribution appears only after many events", "one event already contains the entire interference graph", "one event sets the work function", "one event fixes simultaneity"], 0, "The pattern is statistical across many detections.", ["pattern_means_smear_confusion"], ["dot_to_pattern"]),
            ("If momentum is smaller, lambda = h/p predicts the wavelength is...", ["larger", "smaller", "unchanged", "zero"], 0, "Less momentum means larger wavelength.", ["de_broglie_light_only_confusion"], ["momentum_vs_wavelength"]),
            ("Best summary of lesson 3:", ["detections are discrete, but the overall distribution is wave-like", "particles are always smeared out continuously", "waves cannot be detected locally", "matter has no wavelength"], 0, "That is the clean modern-physics summary.", ["wave_particle_switch_confusion", "pattern_means_smear_confusion"], ["duality_meaning"]),
        ],
    ) + build_shorts(
        "A5L3_C",
        [
            (
                "Why is the phrase 'pattern + hit' stronger than saying a particle simply switches between wave and particle?",
                [
                    "Because it keeps both experimental facts visible at once: localized detection events and wave-like distributions.",
                    "Because the evidence demands both a dot-event description and a pattern description, not a simple identity swap.",
                ],
                "Name both localized detections and wave-like distributions.",
                ["wave_particle_switch_confusion"],
                ["duality_meaning"],
                acceptance_groups(["localized", "hit", "dot", "detection"], ["pattern", "distribution", "wave-like"], ["both", "at once", "together"]),
            ),
            (
                "How does electron diffraction support the de Broglie idea?",
                [
                    "It shows electrons producing a wave-like pattern, so matter particles must be associated with wavelength as well as localized hits.",
                    "It gives experimental evidence that moving matter has de Broglie wavelength.",
                ],
                "Use electron pattern plus wavelength language.",
                ["de_broglie_light_only_confusion", "wave_particle_switch_confusion"],
                ["matter_wave_evidence", "debroglie_relation"],
                acceptance_groups(["electron diffraction", "electrons"], ["pattern", "interference", "wave-like"], ["wavelength", "de Broglie", "matter wave"]),
            ),
        ],
    )
    mastery = build_mcqs(
        "A5L3_M",
        [
            ("A proton and an electron have the same momentum. Their de Broglie wavelengths are...", ["the same", "larger for the proton", "larger for the electron automatically because of mass", "zero for both"], 0, "lambda depends on momentum, not directly on type.", ["de_broglie_light_only_confusion"], ["debroglie_relation"]),
            ("Which statement is best?", ["single detections are local, but the accumulated pattern reveals probability structure", "the pattern is visible inside each single dot", "localized detection disproves wave behavior", "wave behavior removes all localization"], 0, "Distribution and detection play different roles.", ["pattern_means_smear_confusion"], ["pattern_distribution"]),
            ("When particle momentum increases greatly, the de Broglie wavelength becomes...", ["shorter", "longer", "fixed by intensity", "equal to the work function"], 0, "Inverse relation again.", ["de_broglie_light_only_confusion"], ["momentum_vs_wavelength"]),
            ("Which result would most directly support matter-wave behavior?", ["electrons producing a diffraction pattern", "electrons having negative charge", "nuclei containing protons", "light travelling at c"], 0, "Diffraction is the key wave-style evidence.", ["de_broglie_light_only_confusion"], ["matter_wave_evidence"]),
            ("Why do many single-particle runs matter in duality experiments?", ["they reveal the probability pattern built from discrete events", "they make each particle more massive", "they lower the work function", "they remove localization"], 0, "The statistics are the wave-like clue.", ["pattern_means_smear_confusion"], ["dot_to_pattern"]),
            ("A learner says, 'If the detector shows dots, there cannot be any wave idea.' The best correction is...", ["the dots are the detections, while the wave idea describes the distribution of many dots", "the detector is wrong", "waves cannot ever make dots", "dot patterns prove classical mechanics"], 0, "Keep hit and pattern together.", ["wave_particle_switch_confusion"], ["duality_meaning"]),
            ("What does lambda = h/p predict about faster-moving matter in general?", ["greater momentum gives shorter wavelength", "greater momentum gives longer wavelength", "momentum and wavelength are unrelated", "wavelength becomes zero for all motion"], 0, "Faster in the momentum sense means shorter wavelength.", ["de_broglie_light_only_confusion"], ["momentum_vs_wavelength"]),
            ("Best one-line summary:", ["modern particles give localized hits that build wave-like patterns", "modern particles are really only waves", "modern particles are really only marbles", "modern particles ignore momentum"], 0, "That keeps both experimental sides visible.", ["wave_particle_switch_confusion", "pattern_means_smear_confusion"], ["duality_meaning"]),
        ],
    ) + build_shorts(
        "A5L3_M",
        [
            (
                "Why is it useful to say 'pattern map' rather than 'smeared particle'?",
                [
                    "Because the pattern map describes the distribution of many detection outcomes without pretending that each detected particle arrives as a classical smear.",
                    "Because localized hit events remain real even when the overall statistics follow a wave-like map.",
                ],
                "Protect localized detection while explaining the distribution.",
                ["pattern_means_smear_confusion", "wave_particle_switch_confusion"],
                ["pattern_distribution", "duality_meaning"],
                acceptance_groups(["distribution", "pattern map", "probability"], ["localized", "hit", "dot", "detection"], ["not smeared", "not a classical smear"]),
            ),
            (
                "Explain how de Broglie's relation links motion to pattern size.",
                [
                    "It links wavelength to momentum through lambda = h/p, so larger momentum means a smaller associated wavelength and a tighter pattern scale.",
                    "Momentum sets the matter wavelength inversely, which changes the spacing scale in wave-like behavior.",
                ],
                "Use inverse relation language.",
                ["de_broglie_light_only_confusion"],
                ["debroglie_relation", "momentum_vs_wavelength"],
                acceptance_groups(["lambda = h/p", "h over p"], ["momentum"], ["wavelength"], ["inverse", "smaller", "larger"]),
            ),
        ],
    )
    return lesson_spec(
        "A5_L3",
        "Build the Pattern Map",
        sim(
            "a5_pattern_map_lab",
            "Pattern map lab",
            "Launch one particle at a time and let the hit dots build up into a distribution so wave-like pattern and localized detection stay on the same board.",
            ["Fire single particles one at a time.", "Watch the dot distribution accumulate.", "Change momentum and compare the spacing scale."],
            ["Explain pattern plus hit language.", "Use lambda = h/p conceptually.", "Connect matter-wave evidence to diffraction-style results."],
            ["particle_count", "momentum", "path_gap", "hit_map", "pattern_spacing"],
            "Pattern reasoning.",
        ),
        diagnostic,
        "The Packet-Pattern Frame world now shifts from packet events to distributions. One photon or electron lands as one hit dot. But if the same setup is repeated many times, the dots build a pattern map. Modern physics keeps both facts together: localized detections and wave-like distributions. The same dual story extends to matter through the de Broglie relation, where moving particles carry wavelength as well as momentum.",
        "Commit to pattern plus hit, not identity switching.",
        [
            prompt_block("What does one event look like at the detector?", "A localized hit dot."),
            prompt_block("What appears only after many events?", "The pattern map or distribution."),
        ],
        [
            prompt_block("Run one-particle events first.", "The display should show scattered dots, not an instant full pattern."),
            prompt_block("Keep firing identical particles.", "A structured distribution should emerge from the accumulated dots."),
        ],
        [
            "Why is one dot not enough to reveal the pattern map?",
            "Why does electron diffraction force wavelength language for matter?",
        ],
        "Use localized hits and built-up patterns together so duality stays evidential rather than mystical.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Explain wave-particle duality as localized detections plus wave-like distributions.",
                "Use de Broglie's relation to link particle momentum and wavelength.",
                "Interpret diffraction evidence as support for matter-wave behavior.",
            ],
            core_concepts=[
                "Single detections are localized events.",
                "The distribution of many events follows wave-like rules.",
                "Matter particles can have de Broglie wavelength lambda = h/p.",
                "Higher momentum means shorter de Broglie wavelength.",
            ],
            prerequisite_lessons=["A5_L1", "A5_L2"],
            misconception_focus=[
                "wave_particle_switch_confusion",
                "pattern_means_smear_confusion",
                "de_broglie_light_only_confusion",
            ],
            formulas=[
                relation("lambda = h / p", "de Broglie wavelength relation.", ["m"], "Use for moving matter particles as well as in conceptual wavelength comparisons."),
            ],
            representations=[
                representation("dot map", "Shows single localized detections."),
                representation("distribution map", "Shows the built-up pattern from many events."),
                representation("diffraction comparison", "Compares particle hits with the wave-like distribution they build."),
                representation("equation story", "Links increasing momentum to decreasing wavelength."),
            ],
            analogy_map=packet_pattern_frame_map("the learner builds a pattern map from repeated hit dots"),
            worked_examples=[
                worked("Why does one electron at the detector appear as a dot?", ["Recognize that detection is localized.", "Treat the event as one hit at one place.", "Keep this separate from the wider distribution built later."], "Detection is discrete and local", "Single events are particle-like in detection.", "This anchors the hit-dot side of duality."),
                worked("Why does an electron diffraction pattern still support wave ideas?", ["Repeat the one-electron run many times.", "Observe that the overall distribution forms a structured pattern.", "Conclude that the statistics follow wave-like rules even though each hit is local."], "The pattern is wave-like, the hits are discrete", "Both descriptions are needed because experiments show both facts.", "This is the cleanest duality argument."),
                worked("Momentum doubles for a matter particle. What happens to lambda?", ["Use lambda = h/p.", "Notice that h stays constant while p doubles.", "Conclude that lambda halves."], "The wavelength halves", "Momentum and wavelength are inversely related.", "This is the core de Broglie reasoning."),
            ],
            visual_assets=[
                visual(
                    "a5-l3-hit-pattern",
                    "modern_physics_diagram",
                    "Hit dots build a wave-like pattern map",
                    "Show discrete detections accumulating into an interference-style distribution so localized hits and pattern structure remain separate but linked.",
                    "Each event is a dot, but many dots build a pattern map that reveals the wave-like rule.",
                    template="modern_physics_diagram",
                    meta={"diagram_type": "duality_pattern_build"},
                )
            ],
            simulation_contract=sim_contract(
                "a5_l3_pattern_map_sim",
                "hit_pattern",
                "Send one particle at a time through the setup, then explain how the final map is built from discrete hits.",
                "Begin with a very small number of particles so the board only shows a few dots.",
                [
                    "Increase the number of identical runs and watch the distribution appear.",
                    "Raise the particle momentum and compare the pattern spacing idea through lambda = h/p.",
                    "Explain why one hit and the many-hit map answer different questions.",
                ],
                "Watch for learners collapsing the distribution into a single smeared particle.",
                "Modern duality is strongest when hit events and pattern distributions are described together rather than as a simple identity swap.",
                controls=[
                    ("particle_count", "Particle count", "Sets how many single detection events are accumulated."),
                    ("momentum", "Momentum", "Changes the de Broglie wavelength scale."),
                    ("path_layout", "Path layout", "Keeps the setup fixed while the map is built."),
                ],
                readouts=[
                    ("Hit dots", "Shows each localized detection event."),
                    ("Pattern map", "Shows the accumulated distribution after many events."),
                ],
            ),
            reflection_prompts=[
                "Explain why a pattern map needs many hit dots rather than one.",
                "Describe how de Broglie's relation lets matter join the pattern story.",
            ],
            mastery_skills=["duality_meaning", "dot_to_pattern", "pattern_distribution", "debroglie_relation", "momentum_vs_wavelength"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between dot-versus-pattern meaning, matter-wave evidence, and momentum-wavelength reasoning.",
                "concept_gate": "Concept-gate retries alternate between duality explanation stems and new de Broglie comparisons with unseen wording.",
                "mastery": "Mastery prefers unseen lesson-owned diffraction, de Broglie, and misconception-correction items before any repeats.",
            },
            scaffold_support=scaffold(
                "Detections are local, but distributions are wave-like.",
                "Duality becomes easier when learners separate what one event tells you from what many repeated events tell you.",
                "What does one event show, and what only appears after many events?",
                "Treating the pattern map as if each particle literally arrives as a classical smear.",
                "A scout dropping one pin at a time can still reveal a route pattern when many identical trips are plotted on one board.",
                "Why does the pattern belong to the set of many events rather than to one isolated hit?",
                extras=[
                    extra_section("Matter joins the pattern story", "de Broglie's relation gives moving matter a wavelength, so diffraction and interference are not light-only ideas.", "What makes electron diffraction such strong evidence for matter waves?"),
                    extra_section("Inverse link", "Because lambda = h/p, larger momentum means shorter wavelength and therefore a different pattern scale.", "What happens to wavelength when momentum grows?"),
                ],
            ),
            visual_clarity_checks=visual_checks("duality pattern"),
        ),
    )


def lesson_four() -> Dict[str, Any]:
    diagnostic = build_mcqs(
        "A5L4_D",
        [
            ("A core bundle in this model is the...", ["atomic nucleus", "photoelectron", "light clock", "wave pattern"], 0, "The core bundle stands for the nucleus.", ["nuclear_equals_chemical_confusion"], ["nucleus_meaning"]),
            ("Binding credit represents...", ["binding energy", "beam intensity", "frequency", "time dilation"], 0, "Binding credit is the energy tied up in holding the nucleus together.", ["binding_energy_direction_confusion"], ["binding_energy_meaning"]),
            ("Mass defect means...", ["products and reactants differ slightly in mass, and the difference links to energy", "mass vanishes without explanation", "chemical bonds store the same kind of energy", "frequency changes speed of light"], 0, "Mass defect is an energy-linked mass difference.", ["mass_defect_energy_from_nothing_confusion"], ["mass_defect_meaning"]),
            ("A reaction releases nuclear energy when the products are...", ["more tightly bound overall", "less tightly bound overall", "chemically more reactive only", "heavier with no energy change"], 0, "Greater binding can release energy.", ["binding_energy_direction_confusion"], ["binding_compare"]),
            ("Which formula links mass change and energy?", ["Delta E = Delta m c^2", "E = hf", "lambda = h/p", "v = u + at"], 0, "Use the mass-energy relation.", ["mass_defect_energy_from_nothing_confusion"], ["use_emc2"]),
            ("Nuclear energy differs from chemical energy mainly because it involves...", ["changes in nuclear binding energy", "ordinary electron-shell bonds only", "beam intensity only", "wave patterns only"], 0, "Nuclear changes happen in the nucleus.", ["nuclear_equals_chemical_confusion"], ["nuclear_vs_chemical"]),
            ("If a nucleus moves to a state with larger binding energy per nucleon, it tends to...", ["be more stable", "be less stable automatically", "lose all mass instantly", "ignore energy conservation"], 0, "Greater binding per nucleon usually means tighter binding and greater stability.", ["binding_energy_direction_confusion"], ["binding_compare"]),
            ("The mass stamp in this model corresponds to...", ["rest mass", "intensity", "wavelength", "frequency"], 0, "Mass stamp is rest-mass content.", ["mass_defect_energy_from_nothing_confusion"], ["mass_energy_link"]),
        ],
    ) + build_shorts(
        "A5L4_D",
        [
            (
                "Why is nuclear energy not just chemical energy on a bigger scale?",
                [
                    "Because nuclear energy comes from changes in binding energy in the nucleus, whereas chemical energy comes from electron-bond rearrangements.",
                    "Because the energy source is the nucleus and mass defect, not ordinary chemical bonding.",
                ],
                "Contrast nucleus-level binding with electron-bond changes.",
                ["nuclear_equals_chemical_confusion"],
                ["nuclear_vs_chemical"],
                acceptance_groups(["nucleus", "nuclear"], ["binding energy", "mass defect"], ["chemical", "electron bonds", "electron-shell"]),
            ),
            (
                "What does mass defect mean physically?",
                [
                    "It means a small difference in mass corresponds to a change in energy, often because the nucleus has changed its binding energy.",
                    "It is the mass difference between before and after that links to energy release or absorption through c^2.",
                ],
                "Use mass difference plus energy-link language.",
                ["mass_defect_energy_from_nothing_confusion"],
                ["mass_defect_meaning", "mass_energy_link"],
                acceptance_groups(["mass difference", "defect"], ["energy", "released", "absorbed"], ["c^2", "binding energy"]),
            ),
        ],
    )
    concept = build_mcqs(
        "A5L4_C",
        [
            ("A reaction releases energy when the total mass of the products is...", ["smaller than the total mass of the reactants", "larger than the total mass of the reactants", "unchanged in every case", "equal only in chemical reactions"], 0, "Released energy corresponds to a drop in total mass.", ["mass_defect_energy_from_nothing_confusion"], ["mass_defect_meaning"]),
            ("Why can tighter binding release energy?", ["because the final nucleus sits at a lower energy state", "because energy is created from nothing", "because nuclei ignore conservation", "because electrons change colour"], 0, "Lower-energy, more tightly bound states can release the difference.", ["binding_energy_direction_confusion"], ["binding_compare"]),
            ("The strongest reason c^2 appears in nuclear energy is that...", ["mass and energy are linked quantitatively by relativity", "c^2 is just a unit conversion with no meaning", "it only applies to photons", "it replaces binding energy"], 0, "Mass-energy equivalence is the bridge.", ["mass_defect_energy_from_nothing_confusion"], ["mass_energy_link"]),
            ("If two nuclei rearrange into a more tightly bound final bundle, the binding-energy story predicts...", ["energy release", "no energy change", "automatic chemical reaction only", "loss of conservation laws"], 0, "More tightly bound products can release energy.", ["binding_energy_direction_confusion"], ["binding_compare"]),
            ("Which statement best fits mass defect?", ["a little mass change can correspond to a large energy change because c^2 is large", "mass defect means mass is destroyed without a trace", "mass defect only happens in chemistry", "mass defect changes the speed of light"], 0, "The coefficient c^2 makes the energy change large.", ["mass_defect_energy_from_nothing_confusion"], ["use_emc2"]),
            ("Best summary of lesson 4:", ["nuclear energy comes from binding-energy changes and mass defect in the nucleus", "nuclear energy is just brighter chemistry", "mass defect means energy is not conserved", "binding energy is the same as beam intensity"], 0, "That is the core nuclear-energy summary.", ["nuclear_equals_chemical_confusion", "mass_defect_energy_from_nothing_confusion"], ["nuclear_vs_chemical"]),
        ],
    ) + build_shorts(
        "A5L4_C",
        [
            (
                "Why can a small mass defect correspond to a large released energy?",
                [
                    "Because the mass-energy relation multiplies the mass change by c squared, which is a very large factor.",
                    "Because even a tiny mass difference corresponds to a large energy difference through Delta E = Delta m c^2.",
                ],
                "Mention c squared as the large conversion factor.",
                ["mass_defect_energy_from_nothing_confusion"],
                ["use_emc2", "mass_energy_link"],
                acceptance_groups(["Delta E = Delta m c^2", "c^2", "speed of light squared"], ["small mass", "tiny mass difference"], ["large energy", "big energy"]),
            ),
            (
                "What does it mean to say the final core bundle is 'more tightly bound'?",
                [
                    "It means the nucleons are in a lower-energy, more stable arrangement, so energy can be released in reaching that state.",
                    "It means more binding energy has been gained in holding the nucleus together, making the final bundle more stable.",
                ],
                "Use lower-energy or more-stable language.",
                ["binding_energy_direction_confusion"],
                ["binding_compare", "binding_energy_meaning"],
                acceptance_groups(["lower energy", "more stable", "tighter", "more tightly bound"], ["release energy", "energy released", "binding energy"]),
            ),
        ],
    )
    mastery = build_mcqs(
        "A5L4_M",
        [
            ("A reaction has a mass decrease of 0.002 kg. This means energy is...", ["released", "destroyed", "unrelated to the reaction", "necessarily chemical only"], 0, "Loss of mass corresponds to released energy.", ["mass_defect_energy_from_nothing_confusion"], ["mass_energy_link"]),
            ("Which final state is more likely to release energy?", ["a more tightly bound nucleus", "a less tightly bound nucleus", "a larger work function", "a shorter wavelength"], 0, "Tighter binding is the favorable release direction.", ["binding_energy_direction_confusion"], ["binding_compare"]),
            ("Why is binding energy called a 'credit' in the analogy?", ["because it reflects energy associated with holding the nucleus together", "because nuclei pay photons with it", "because it is the same as intensity", "because it is a clock reading"], 0, "Binding credit is stored in the arrangement of the nucleus.", ["binding_energy_direction_confusion"], ["binding_energy_meaning"]),
            ("What is the biggest correction to 'nuclear energy is chemical energy on a bigger scale'?", ["nuclear energy comes from the nucleus and mass defect, not ordinary electron bonds", "nuclear energy is just brighter light", "chemical bonds use c^2 directly", "nuclei are electrons"], 0, "The site and mechanism are different.", ["nuclear_equals_chemical_confusion"], ["nuclear_vs_chemical"]),
            ("If reactants are less tightly bound than products, then the products usually have...", ["lower total mass-energy", "higher total mass-energy automatically", "no binding energy", "a different speed of light"], 0, "Lower-energy products can have lower total mass.", ["mass_defect_energy_from_nothing_confusion", "binding_energy_direction_confusion"], ["mass_energy_link"]),
            ("Why does the nucleus matter so much more than electrons here?", ["because nuclear binding changes are much larger in energy scale than chemical bond changes", "because electrons have no energy", "because nuclei ignore charge", "because photons cannot enter nuclei"], 0, "Nuclear and chemical energy scales differ greatly.", ["nuclear_equals_chemical_confusion"], ["nuclear_vs_chemical"]),
            ("Best interpretation of mass defect:", ["it is bookkeeping evidence that energy has been released or absorbed through a change in rest mass", "it means conservation fails", "it means nuclei are fictitious", "it means c changes"], 0, "Mass defect is conservation-aware bookkeeping.", ["mass_defect_energy_from_nothing_confusion"], ["mass_defect_meaning"]),
            ("Which sentence is strongest?", ["tighter final core bundles can release energy because binding and rest mass have changed", "energy release means the nucleus gained loose particles", "all binding changes absorb energy", "nuclear reactions ignore relativity"], 0, "This connects binding to mass-energy cleanly.", ["binding_energy_direction_confusion", "mass_defect_energy_from_nothing_confusion"], ["binding_compare"]),
        ],
    ) + build_shorts(
        "A5L4_M",
        [
            (
                "Explain how binding-energy change and mass defect tell the same story.",
                [
                    "A reaction that leads to a more tightly bound final nucleus lowers the system's mass-energy, so the mass defect corresponds to the released binding-energy difference.",
                    "The drop in mass tracks the energy released when the nuclear bundle becomes more tightly bound.",
                ],
                "Link tighter binding to lower mass-energy.",
                ["mass_defect_energy_from_nothing_confusion", "binding_energy_direction_confusion"],
                ["mass_energy_link", "binding_compare"],
                acceptance_groups(["more tightly bound", "binding energy"], ["mass defect", "mass difference"], ["released energy", "lower mass-energy", "c^2"]),
            ),
            (
                "A student says, 'Mass just disappears in nuclear reactions.' Correct them.",
                [
                    "Mass is not simply disappearing without explanation; a change in mass corresponds to a change in energy according to Delta E = Delta m c^2.",
                    "The mass difference is accounted for as released or absorbed energy, so conservation is preserved.",
                ],
                "Use conservation and mass-energy language.",
                ["mass_defect_energy_from_nothing_confusion"],
                ["mass_defect_meaning", "mass_energy_link"],
                acceptance_groups(["not disappear", "conserved", "accounted for"], ["energy", "Delta E = Delta m c^2", "mass-energy"], ["released", "absorbed"]),
            ),
        ],
    )
    return lesson_spec(
        "A5_L4",
        "Rebuild the Core Bundle",
        sim(
            "a5_core_bundle_lab",
            "Core bundle lab",
            "Compare before-and-after nuclei so binding-energy change and mass defect are read as one modern-physics story.",
            ["Compare two nuclear rearrangements.", "Check which final bundle is more tightly bound.", "Read the linked mass and energy change."],
            ["Explain binding energy qualitatively.", "Use Delta E = Delta m c^2 conceptually and numerically.", "Separate nuclear from chemical energy stories."],
            ["binding_before", "binding_after", "mass_before", "mass_after", "energy_release"],
            "Binding reasoning.",
        ),
        diagnostic,
        "The Packet-Pattern Frame story now turns inward to the core bundle. Nuclei are tightly bound systems, and some rearrangements lead to more stable, more tightly bound final bundles. When that happens, energy can be released. The released energy is not invented from nowhere. It corresponds to a drop in mass stamp through the mass-energy link Delta E = Delta m c^2. Nuclear energy is therefore a binding-energy and mass-defect story, not just chemistry scaled up.",
        "Commit to nuclear energy as a core-binding story rather than a chemistry story.",
        [
            prompt_block("What part of the atom changes in nuclear energy processes?", "The nucleus or core bundle."),
            prompt_block("What does a mass defect correspond to?", "An energy change through Delta E = Delta m c^2."),
        ],
        [
            prompt_block("Compare a looser and a tighter final core bundle.", "The tighter final bundle should be the release case."),
            prompt_block("Watch the mass stamps before and after.", "A smaller final total mass means energy has been released."),
        ],
        [
            "Why is 'more tightly bound' not the same as 'contains more ordinary chemical energy'?",
            "How do binding-energy change and mass defect become the same story in different language?",
        ],
        "Use core-bundle language to keep binding energy, mass defect, and energy release inside one coherent nuclear model.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Explain nuclear energy as a change in binding energy of the nucleus.",
                "Interpret mass defect as a mass-energy bookkeeping difference.",
                "Distinguish clearly between nuclear and chemical energy changes.",
            ],
            core_concepts=[
                "Nuclear reactions change the binding of the nucleus, not just electron bonds.",
                "More tightly bound final bundles can release energy.",
                "A mass defect corresponds to an energy change through Delta E = Delta m c^2.",
                "Mass-energy bookkeeping preserves conservation rather than violating it.",
            ],
            prerequisite_lessons=[],
            misconception_focus=[
                "nuclear_equals_chemical_confusion",
                "mass_defect_energy_from_nothing_confusion",
                "binding_energy_direction_confusion",
            ],
            formulas=[
                relation("Delta E = Delta m c^2", "Mass-energy relation for a mass change.", ["J"], "Use when a rest-mass difference is converted to or from energy."),
            ],
            representations=[
                representation("bundle comparison", "Shows before-and-after nuclei with different binding tightness."),
                representation("mass-energy ledger", "Tracks mass difference and the associated energy change."),
                representation("words", "Separates nuclear binding from chemical bonding."),
                representation("cause chain", "Links tighter binding -> lower mass-energy -> release."),
            ],
            analogy_map=packet_pattern_frame_map("the learner compares core bundles before and after a nuclear rearrangement"),
            worked_examples=[
                worked("Why can a more tightly bound final nucleus release energy?", ["Compare the initial and final binding arrangements.", "Recognize that the final arrangement is lower in energy.", "State that the difference can be released."], "Energy is released", "Lower-energy final binding allows the difference to emerge as released energy.", "This is the core binding-energy argument."),
                worked("What does a mass decrease mean in a nuclear reaction?", ["Write Delta E = Delta m c^2.", "Note that a smaller final mass means some mass-energy has left the system.", "Interpret that as released energy."], "Released energy corresponds to the mass defect", "Mass defect is bookkeeping, not disappearance without explanation.", "This protects conservation language."),
                worked("Why is nuclear energy not just chemical energy scaled up?", ["Identify that chemical energy involves electron bonds.", "Identify that nuclear energy involves nucleus-level binding changes.", "Conclude that the mechanism and scale are different."], "They are different physical processes", "Where the energy comes from matters conceptually.", "This protects the curriculum distinction."),
            ],
            visual_assets=[
                visual(
                    "a5-l4-core-bundle",
                    "modern_physics_diagram",
                    "Tighter core bundles release binding credit",
                    "Compare looser and tighter nuclei with matching mass-stamp and energy-release labels so the binding story remains visible.",
                    "Nuclear energy is released when a rearrangement leads to a more tightly bound final core bundle with lower mass-energy.",
                    template="modern_physics_diagram",
                    meta={"diagram_type": "nuclear_binding_credit"},
                )
            ],
            simulation_contract=sim_contract(
                "a5_l4_core_bundle_sim",
                "core_binding",
                "Compare nuclear bundles before and after rearrangement, then explain how tighter binding and mass defect connect.",
                "Start with a small before-and-after binding difference so the energy release is easy to track.",
                [
                    "Choose which final arrangement is more tightly bound.",
                    "Compare the total mass stamps before and after.",
                    "Translate the mass difference into released energy language.",
                ],
                "Watch for nuclear binding being confused with ordinary chemical bonding.",
                "Nuclear energy is a binding-energy and mass-defect story inside the core bundle.",
                controls=[
                    ("binding_before", "Initial bundle binding", "Sets how tightly the starting nucleus is held together."),
                    ("binding_after", "Final bundle binding", "Lets learners compare the final binding state."),
                    ("mass_scale", "Mass stamp scale", "Keeps the linked mass-energy bookkeeping visible."),
                ],
                readouts=[
                    ("Mass defect", "Shows the before-after mass difference."),
                    ("Released energy", "Shows the energy linked to the binding change."),
                ],
            ),
            reflection_prompts=[
                "Explain why a more tightly bound final nucleus can release energy.",
                "Describe how Delta E = Delta m c^2 keeps nuclear energy consistent with conservation.",
            ],
            mastery_skills=["binding_energy_meaning", "binding_compare", "mass_defect_meaning", "use_emc2", "nuclear_vs_chemical"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between binding-direction judgments, nuclear-versus-chemical contrasts, and quick mass-defect meaning checks.",
                "concept_gate": "Concept-gate retries alternate between new tighter-versus-looser bundle scenarios and short explanations of why c^2 matters.",
                "mastery": "Mastery prefers unseen lesson-owned binding, mass-defect, and misconception-correction prompts before repeats.",
            },
            scaffold_support=scaffold(
                "Tighter final core bundles can release energy.",
                "Nuclear energy becomes coherent when learners compare before-and-after binding rather than imagining energy being created from nowhere.",
                "Which state is more tightly bound, and what does that imply about the system energy?",
                "Calling nuclear energy chemical energy with bigger numbers or saying mass simply vanishes.",
                "A tighter strapped bundle can settle into a lower-energy arrangement, and the change shows up as released credit plus a smaller mass stamp.",
                "Why does a more stable final bundle correspond to released energy rather than created energy?",
                extras=[
                    extra_section("Mass stamp link", "The same reaction can be described with binding-energy language or with mass-defect language because the two are linked by Delta E = Delta m c^2.", "How do mass defect and binding-energy change tell one story?"),
                    extra_section("Nuclear versus chemical", "Chemical energy comes from electron-bond rearrangements. Nuclear energy comes from the nucleus itself, so its scale and mechanism are different.", "What part of the atom is doing the important work here?"),
                ],
            ),
            visual_clarity_checks=visual_checks("nuclear binding"),
        ),
    )


def lesson_five() -> Dict[str, Any]:
    diagnostic = build_mcqs(
        "A5L5_D",
        [
            ("A frame pod stands for an...", ["inertial frame", "atomic nucleus", "photon", "photoelectron"], 0, "A frame pod is an observer's inertial frame.", ["fixed_c_source_motion_confusion"], ["frame_meaning"]),
            ("The signal cap is the...", ["speed of light in vacuum", "beam intensity", "work function", "binding energy"], 0, "The signal cap is c.", ["fixed_c_source_motion_confusion"], ["c_invariance"]),
            ("A pulse clock is used because...", ["light travel makes the fixed-c rule visible inside a clock", "it measures work function", "it tracks chemical energy", "it removes momentum"], 0, "A light clock turns c into a timing device.", ["time_dilation_broken_clock_confusion"], ["light_clock_reasoning"]),
            ("Special relativity starts from the rule that...", ["all inertial observers measure the same speed of light in vacuum", "light speed depends on source speed", "time is absolute", "length is absolute"], 0, "Invariant c is the starting postulate.", ["fixed_c_source_motion_confusion"], ["c_invariance"]),
            ("Tick stretch is the model name for...", ["time dilation", "length contraction", "simultaneity", "work function"], 0, "Tick stretch means moving clocks run slower relative to another frame.", ["time_dilation_broken_clock_confusion"], ["time_dilation_meaning"]),
            ("Why does a moving light clock tick more slowly from another frame's viewpoint?", ["the light has a longer diagonal path while c stays fixed", "the light speeds up", "the mirrors shrink vertically", "the clock is broken"], 0, "Longer path plus same c means longer tick interval.", ["time_dilation_broken_clock_confusion"], ["light_clock_reasoning"]),
            ("Proper time is the time interval measured...", ["by the clock at rest with the events", "only by the fastest observer", "only in the laboratory", "from the work function"], 0, "Proper time belongs to the frame where the clock is at rest.", ["time_dilation_broken_clock_confusion"], ["proper_time"]),
            ("The Lorentz factor gamma becomes larger when...", ["relative speed approaches c", "relative speed falls to zero", "frequency decreases", "mass defect vanishes"], 0, "Gamma grows as speed gets closer to c.", ["fixed_c_source_motion_confusion"], ["gamma_compare"]),
        ],
    ) + build_shorts(
        "A5L5_D",
        [
            (
                "Why does the fixed speed of light force time dilation?",
                [
                    "Because if all inertial observers measure the same light speed, then a moving light clock must take longer per tick when its light follows a longer path in another frame.",
                    "Because the same c with a longer observed light path means a longer tick interval in another frame.",
                ],
                "Use same c plus longer light path language.",
                ["fixed_c_source_motion_confusion", "time_dilation_broken_clock_confusion"],
                ["c_invariance", "light_clock_reasoning"],
                acceptance_groups(["same speed of light", "c is constant", "invariant c"], ["longer path", "diagonal path"], ["longer time", "ticks slower", "time dilation"]),
            ),
            (
                "What does 'moving clocks run slower' really mean?",
                [
                    "It means that relative to another inertial frame, a moving clock records less elapsed proper time between the same pair of events.",
                    "It is a frame-dependent measurement effect, not a broken-clock fault.",
                ],
                "Keep frame dependence and proper time visible.",
                ["time_dilation_broken_clock_confusion"],
                ["time_dilation_meaning", "proper_time"],
                acceptance_groups(["frame", "relative", "another observer"], ["moving clock", "proper time", "less elapsed time"], ["not broken", "not faulty", "measurement effect"]),
            ),
        ],
    )
    concept = build_mcqs(
        "A5L5_C",
        [
            ("If relative speed is zero, gamma is...", ["1", "0", "infinite", "c"], 0, "No relative motion means no dilation.", ["fixed_c_source_motion_confusion"], ["gamma_compare"]),
            ("A moving light clock viewed from outside has a longer light path because...", ["the mirrors move sideways while the light travels", "light speed increases", "time becomes absolute", "the work function changes"], 0, "The outside observer sees a diagonal path.", ["time_dilation_broken_clock_confusion"], ["light_clock_reasoning"]),
            ("Which statement about time dilation is correct?", ["it is a consequence of invariant c, not bad clocks", "it means only photons have time", "it only happens in nuclei", "it means c changes"], 0, "Time dilation follows from the postulates.", ["time_dilation_broken_clock_confusion"], ["time_dilation_meaning"]),
            ("Proper time is usually the...", ["shortest time interval between the events measured in a frame where the clock is at rest", "largest time because the clock is moving", "time measured only with lasers", "same in all frames"], 0, "The rest-frame clock measures proper time.", ["time_dilation_broken_clock_confusion"], ["proper_time"]),
            ("If gamma rises, the time interval seen for the moving clock from another frame...", ["increases", "decreases", "stays unchanged", "becomes zero"], 0, "Delta t = gamma Delta tau.", ["time_dilation_broken_clock_confusion"], ["use_time_dilation"]),
            ("Best summary of lesson 5:", ["invariant light speed forces frame-dependent time measurements", "time dilation means clocks are mechanically damaged", "source motion changes c", "all frames keep identical times"], 0, "That is the relativistic core.", ["fixed_c_source_motion_confusion", "time_dilation_broken_clock_confusion"], ["c_invariance"]),
        ],
    ) + build_shorts(
        "A5L5_C",
        [
            (
                "Why is a light clock such a good relativity model?",
                [
                    "Because its tick is defined by light travel, so any argument about invariant light speed immediately becomes an argument about time measurement.",
                    "Because it makes the fixed value of c part of the clock itself.",
                ],
                "Tie light travel directly to tick timing.",
                ["fixed_c_source_motion_confusion"],
                ["light_clock_reasoning", "c_invariance"],
                acceptance_groups(["light clock", "pulse clock"], ["light travel", "c", "speed of light"], ["tick", "time measurement", "clock"]),
            ),
            (
                "How does proper time differ from dilated time?",
                [
                    "Proper time is measured by the clock at rest with the events, while dilated time is the longer interval measured from a frame in which that clock is moving.",
                    "The rest-frame clock measures proper time, and other frames can measure a larger interval for the moving clock.",
                ],
                "Use rest-frame versus moving-frame language.",
                ["time_dilation_broken_clock_confusion"],
                ["proper_time", "use_time_dilation"],
                acceptance_groups(["proper time", "rest frame", "clock at rest"], ["moving frame", "another observer"], ["longer interval", "dilated time"]),
            ),
        ],
    )
    mastery = build_mcqs(
        "A5L5_M",
        [
            ("A spaceship clock measures 2.0 s between two ticks in its own rest frame. If gamma = 3, another frame measures...", ["6.0 s", "2.0 s", "1.5 s", "0.67 s"], 0, "Use Delta t = gamma Delta tau.", ["time_dilation_broken_clock_confusion"], ["use_time_dilation"]),
            ("If gamma = 2, the moving clock appears to run...", ["at half the tick rate relative to that frame's coordinate time", "twice as fast", "with the same tick rate", "with negative time"], 0, "More coordinate time passes between moving-clock ticks.", ["time_dilation_broken_clock_confusion"], ["time_dilation_meaning"]),
            ("Which assumption is essential to the light-clock derivation?", ["c is the same in all inertial frames", "lengths never change", "time is absolute", "mass never changes"], 0, "Invariant c is the start.", ["fixed_c_source_motion_confusion"], ["c_invariance"]),
            ("A larger relative speed gives a larger gamma, which means...", ["stronger time dilation", "no time dilation", "lower light speed", "smaller proper time in the moving frame itself"], 0, "Gamma tracks how strong the effect is.", ["time_dilation_broken_clock_confusion"], ["gamma_compare"]),
            ("Which statement corrects 'moving clocks are broken'?", ["time dilation is a frame effect that follows from c being invariant", "moving clocks lose batteries", "moving clocks only work for photons", "time dilation is caused by intensity"], 0, "This is the key misconception shield.", ["time_dilation_broken_clock_confusion"], ["time_dilation_meaning"]),
            ("If Delta tau = 4 microseconds and gamma = 1.25, Delta t is...", ["5 microseconds", "3.2 microseconds", "4 microseconds", "1.25 microseconds"], 0, "Multiply by gamma.", ["time_dilation_broken_clock_confusion"], ["use_time_dilation"]),
            ("What stays invariant across inertial frames in special relativity?", ["the speed of light in vacuum", "all time intervals", "all lengths", "all simultaneity judgments"], 0, "Only c stays fixed in the postulates.", ["fixed_c_source_motion_confusion"], ["c_invariance"]),
            ("Best one-line summary:", ["the fixed light-speed cap forces moving clocks to be measured differently in different frames", "clocks break near high speed", "high speed changes c", "proper time is the same as dilated time"], 0, "That keeps the cause-and-effect chain intact.", ["fixed_c_source_motion_confusion", "time_dilation_broken_clock_confusion"], ["light_clock_reasoning"]),
        ],
    ) + build_shorts(
        "A5L5_M",
        [
            (
                "Explain why longer light paths matter in the moving-clock argument.",
                [
                    "If light must travel a longer path in another frame but still moves at the same speed c, then the time for one tick must be longer in that frame.",
                    "The longer diagonal path combined with invariant c produces a longer tick interval.",
                ],
                "Use path length plus fixed c.",
                ["fixed_c_source_motion_confusion", "time_dilation_broken_clock_confusion"],
                ["light_clock_reasoning", "time_dilation_meaning"],
                acceptance_groups(["longer path", "diagonal path"], ["same speed of light", "c"], ["longer time", "tick takes longer", "time dilation"]),
            ),
            (
                "A student says, 'Time dilation means the travelling clock is faulty.' Correct them.",
                [
                    "Time dilation is not a fault in the clock; it is the consistent frame-dependent result of keeping the speed of light the same in all inertial frames.",
                    "The clock works normally in its own rest frame, but other frames compare it differently because relativity changes time bookkeeping.",
                ],
                "Say frame effect, not damage.",
                ["time_dilation_broken_clock_confusion"],
                ["time_dilation_meaning", "proper_time"],
                acceptance_groups(["not broken", "not faulty"], ["frame", "relative", "another observer"], ["speed of light", "c"], ["rest frame", "works normally"]),
            ),
        ],
    )
    return lesson_spec(
        "A5_L5",
        "Ride the Pulse Clock",
        sim(
            "a5_pulse_clock_lab",
            "Pulse clock lab",
            "Compare identical light clocks in moving frame pods so invariant c turns directly into time-dilation reasoning.",
            ["Set a relative speed.", "Compare the rest-frame and outside-frame light path.", "Read the two tick intervals."],
            ["Explain time dilation from a light-clock model.", "Use gamma with proper time.", "Reject broken-clock explanations."],
            ["relative_speed", "gamma", "proper_time", "dilated_time", "light_path"],
            "Frame reasoning.",
        ),
        diagnostic,
        "The Packet-Pattern Frame story now enters the frame pod. Each pod carries the same pulse clock, and every inertial observer must measure the same signal cap c for light in vacuum. That single rule has a price: observers in relative motion cannot all agree on the same clock bookkeeping. The moving light path looks longer from another frame, so the tick interval must stretch. Time dilation is therefore not a fault in clocks. It is the geometric consequence of keeping c invariant.",
        "Commit to invariant c as the cause of time dilation.",
        [
            prompt_block("What is fixed in every inertial frame?", "The speed of light in vacuum."),
            prompt_block("What then has to adjust in the light-clock story?", "The measured time interval between ticks."),
        ],
        [
            prompt_block("Start with zero relative speed.", "Both clock descriptions should match."),
            prompt_block("Then raise the relative speed.", "The outside-frame path and tick interval should grow."),
        ],
        [
            "Why does the same value of c matter more than any claim about clocks being broken?",
            "How does a longer observed light path force a longer observed tick interval?",
        ],
        "Use the pulse-clock picture to keep time dilation geometric, causal, and tied to invariant c.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Explain why invariant light speed leads to time dilation.",
                "Interpret proper time and coordinate time in the light-clock model.",
                "Use gamma to compare rest-frame and moving-frame time intervals.",
            ],
            core_concepts=[
                "Every inertial frame measures the same c in vacuum.",
                "A moving light clock has a longer observed light path from another frame.",
                "Longer path with the same c means longer tick time.",
                "Proper time is measured by the clock at rest with the events.",
            ],
            prerequisite_lessons=[],
            misconception_focus=[
                "fixed_c_source_motion_confusion",
                "time_dilation_broken_clock_confusion",
            ],
            formulas=[
                relation("Delta t = gamma Delta tau", "Time-dilation relation.", ["s"], "Delta tau is proper time measured in the rest frame of the clock."),
            ],
            representations=[
                representation("light-clock diagram", "Shows diagonal light path in the moving-frame view."),
                representation("frame comparison", "Compares proper time and dilated time."),
                representation("words", "Explains time dilation as a frame effect rather than a mechanical fault."),
                representation("gamma table", "Shows stronger effects as speed approaches c."),
            ],
            analogy_map=packet_pattern_frame_map("the learner compares tick counts in different moving frame pods"),
            worked_examples=[
                worked("Why does a moving light clock tick more slowly from another frame?", ["Keep c fixed in both frames.", "Notice the outside observer sees a longer diagonal light path.", "Conclude the tick interval must be longer in that frame."], "The outside frame measures a longer tick time", "Same c plus longer path forces longer time.", "This is the conceptual root of time dilation."),
                worked("A clock measures 2 s of proper time and gamma = 3. What interval does another frame assign?", ["Use Delta t = gamma Delta tau.", "Multiply 3 by 2 s.", "State the coordinate-time interval."], "6 s", "The moving clock accumulates less proper time than the larger interval seen from the other frame.", "This is the standard calculation."),
                worked("Why is the clock not broken?", ["Look in the clock's own rest frame.", "See that it works normally there and measures proper time.", "Interpret the disagreement as frame-dependent timing, not malfunction."], "The effect is relational, not a fault", "Relativity changes measurements between frames, not the quality of the device.", "This protects the main misconception."),
            ],
            visual_assets=[
                visual(
                    "a5-l5-light-clock",
                    "modern_physics_diagram",
                    "A moving pulse clock stretches its tick",
                    "Show the same light clock in its rest frame and in another moving frame so the longer path and longer tick remain linked.",
                    "When c stays fixed, the longer observed light path in another frame forces a longer tick interval.",
                    template="modern_physics_diagram",
                    meta={"diagram_type": "light_clock_time_dilation"},
                )
            ],
            simulation_contract=sim_contract(
                "a5_l5_pulse_clock_sim",
                "pulse_clock",
                "Raise the relative speed between frame pods, then explain why the moving pulse clock stretches its tick.",
                "Start with the pods at rest relative to each other so the paths and tick intervals match.",
                [
                    "Increase relative speed and compare the rest-frame and outside-frame light paths.",
                    "Read proper time and dilated time together.",
                    "Explain why keeping c fixed forces the timing difference.",
                ],
                "Watch for time dilation being blamed on clock damage rather than on frame geometry with invariant c.",
                "Time dilation follows from insisting that every inertial frame still measures the same signal cap c.",
                controls=[
                    ("relative_speed", "Relative speed", "Sets how strongly the frame comparison departs from the rest case."),
                    ("proper_time", "Proper-time tick", "Keeps the clock's own tick interval visible."),
                    ("clock_height", "Clock height", "Maintains the same rest-frame clock geometry while the outside path changes."),
                ],
                readouts=[
                    ("Gamma", "Shows the Lorentz factor for the chosen speed."),
                    ("Dilated tick", "Shows the longer interval assigned from the other frame."),
                ],
            ),
            reflection_prompts=[
                "Explain why invariant c and a longer observed light path together force time dilation.",
                "Describe the difference between proper time and the dilated interval seen from another frame.",
            ],
            mastery_skills=["c_invariance", "light_clock_reasoning", "time_dilation_meaning", "use_time_dilation", "proper_time"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between invariant-c statements, light-clock geometry prompts, and proper-time vocabulary checks.",
                "concept_gate": "Concept-gate retries alternate between new gamma scenarios and short explanations of why time dilation is not clock damage.",
                "mastery": "Mastery prefers unseen lesson-owned time-dilation calculations and frame-explanation stems before repeating any item.",
            },
            scaffold_support=scaffold(
                "Invariant c forces moving clocks to be compared differently.",
                "The light-clock model is powerful because it makes the postulate about c immediately visible in clock timing.",
                "If c stays fixed, what must happen when another frame sees a longer light path?",
                "Treating time dilation as a broken device instead of as consistent frame bookkeeping.",
                "Each frame pod trusts its own pulse clock, but when one pod watches the other's light zig-zag across a longer route, the tick must stretch if the signal cap never changes.",
                "Why is the moving clock perfectly normal in its own pod?",
                extras=[
                    extra_section("Proper-time anchor", "Proper time is measured where the clock rests. That frame is the clean anchor for time-dilation comparisons.", "Which frame owns the proper time in a light-clock problem?"),
                    extra_section("Gamma as strength", "The Lorentz factor tells how strong the time-stretch effect is for a given relative speed, and it grows as the speed approaches c.", "What happens to gamma when speed gets closer to c?"),
                ],
            ),
            visual_clarity_checks=visual_checks("light-clock relativity"),
        ),
    )


def lesson_six() -> Dict[str, Any]:
    diagnostic = build_mcqs(
        "A5L6_D",
        [
            ("Span squeeze is the model name for...", ["length contraction", "time dilation", "photoelectric threshold", "binding energy"], 0, "Span squeeze means length contraction.", ["length_contraction_visual_squash_confusion"], ["length_contraction_meaning"]),
            ("Same-now slip refers to...", ["relativity of simultaneity", "work function", "de Broglie wavelength", "binding energy"], 0, "Different frames can disagree on simultaneity.", ["simultaneity_absolute_confusion"], ["simultaneity_meaning"]),
            ("Length contraction applies to lengths measured...", ["along the direction of motion", "perpendicular to all motion only", "only by the object itself in its rest frame", "only for light beams"], 0, "Contraction is along the motion direction.", ["length_contraction_visual_squash_confusion"], ["length_direction"]),
            ("Proper length is the length measured...", ["in the rest frame of the object", "only by the fastest observer", "after contraction in another frame", "by counting photons"], 0, "Proper length belongs to the object's rest frame.", ["length_contraction_visual_squash_confusion"], ["proper_length"]),
            ("If gamma increases, the moving length observed from another frame becomes...", ["shorter along the motion direction", "longer", "unchanged", "equal to c"], 0, "L = L0/gamma.", ["length_contraction_visual_squash_confusion"], ["use_length_contraction"]),
            ("Relativity of simultaneity means...", ["two events that are simultaneous in one frame need not be simultaneous in another", "all observers must agree on every now-moment", "time dilation disappears", "light speed changes with source speed"], 0, "Simultaneity is frame-dependent.", ["simultaneity_absolute_confusion"], ["simultaneity_meaning"]),
            ("Why do time dilation and length contraction belong to the same rulebook?", ["both follow from keeping c invariant across inertial frames", "both are caused by bad rulers", "both happen only in nuclei", "they are unrelated accidents"], 0, "Invariant c drives the whole relativity package.", ["fixed_c_source_motion_confusion", "length_contraction_visual_squash_confusion"], ["frame_measurement"]),
            ("The mass-energy relation belongs in this lesson because...", ["the same invariant c that shapes frames also appears in E = mc^2", "mass-energy and relativity are unrelated", "only photons need c", "c changes in moving frames"], 0, "Modern physics ties mass-energy and frames through the same c.", ["fixed_c_source_motion_confusion"], ["mass_energy_link"]),
        ],
    ) + build_shorts(
        "A5L6_D",
        [
            (
                "Why is proper length longer than the contracted length?",
                [
                    "Because proper length is measured in the object's own rest frame, while another frame moving relative to it measures a shorter length along the direction of motion.",
                    "Because the rest frame measures the full length, and motion-aligned comparison frames measure the contracted span.",
                ],
                "Use rest-frame and direction-of-motion language.",
                ["length_contraction_visual_squash_confusion"],
                ["proper_length", "length_direction"],
                acceptance_groups(["proper length", "rest frame"], ["shorter", "contracted"], ["direction of motion", "along the motion"]),
            ),
            (
                "What does same-now slip tell you about simultaneity?",
                [
                    "It tells you simultaneity is frame-dependent, so different inertial observers can disagree about whether two separated events happened at the same time.",
                    "Different moving frames need not share one universal now.",
                ],
                "Use frame-dependent now-language.",
                ["simultaneity_absolute_confusion"],
                ["simultaneity_meaning", "frame_comparison"],
                acceptance_groups(["simultaneous", "same now", "simultaneity"], ["frame", "observer"], ["disagree", "not universal", "different"]),
            ),
        ],
    )
    concept = build_mcqs(
        "A5L6_C",
        [
            ("If a rod has proper length 12 m and gamma = 3, another frame moving relative to it measures...", ["4 m", "12 m", "36 m", "9 m"], 0, "Use L = L0/gamma.", ["length_contraction_visual_squash_confusion"], ["use_length_contraction"]),
            ("Which frame measures proper length?", ["the frame where the object is at rest", "any frame where the object moves", "only the fastest frame", "the frame with highest intensity"], 0, "Proper length belongs to the rest frame.", ["length_contraction_visual_squash_confusion"], ["proper_length"]),
            ("Why is simultaneity not universal in special relativity?", ["because keeping c invariant changes how separated events are time-ordered across frames", "because clocks are broken", "because space disappears", "because frequency changes"], 0, "Same c prevents one universal now-map.", ["simultaneity_absolute_confusion"], ["frame_comparison"]),
            ("A length perpendicular to the motion is usually treated as...", ["not length-contracted in this basic treatment", "more contracted than parallel lengths", "forced to zero", "equal to gamma times the proper length"], 0, "The basic contraction is along the motion direction.", ["length_contraction_visual_squash_confusion"], ["length_direction"]),
            ("Which statement best links lesson 6 back to lesson 5?", ["time intervals, lengths, and simultaneity all become frame-dependent once c is fixed", "only time changes, everything else stays absolute", "only lengths change, time stays absolute", "c changes so the old rules return"], 0, "Relativity changes several measurement categories together.", ["fixed_c_source_motion_confusion", "simultaneity_absolute_confusion"], ["frame_measurement"]),
            ("Best summary of lesson 6:", ["moving observers cannot keep one universal clock map if they all keep the same speed of light", "relativity changes nothing but diagram style", "simultaneity is absolute after all", "length contraction is only a drawing trick"], 0, "That is the frame-layer takeaway.", ["fixed_c_source_motion_confusion", "simultaneity_absolute_confusion"], ["frame_comparison"]),
        ],
    ) + build_shorts(
        "A5L6_C",
        [
            (
                "Why does length contraction apply only along the motion direction in this course treatment?",
                [
                    "Because the frame disagreement comes from how space and time are mixed along the direction of relative motion, so the contraction is for lengths parallel to that motion.",
                    "Because the motion-aligned dimension is the one affected in the standard length-contraction formula.",
                ],
                "Keep the direction of motion visible.",
                ["length_contraction_visual_squash_confusion"],
                ["length_direction", "length_contraction_meaning"],
                acceptance_groups(["direction of motion", "parallel"], ["length contraction", "contracted"], ["along", "motion-aligned"]),
            ),
            (
                "How does simultaneity connect to the fixed speed of light?",
                [
                    "If all frames keep the same c, then they cannot all share one universal way of deciding which separated events happened at the same time.",
                    "Invariant light speed forces frame-dependent simultaneity judgments.",
                ],
                "Link universal c to non-universal simultaneity.",
                ["simultaneity_absolute_confusion", "fixed_c_source_motion_confusion"],
                ["simultaneity_meaning", "c_invariance"],
                acceptance_groups(["same speed of light", "invariant c"], ["simultaneous", "same time", "same now"], ["frame", "observer"], ["not universal", "disagree"]),
            ),
        ],
    )
    mastery = build_mcqs(
        "A5L6_M",
        [
            ("A spacecraft has proper length 30 m and gamma = 2. Another frame measures...", ["15 m", "30 m", "60 m", "45 m"], 0, "Halve the proper length because L = L0/gamma.", ["length_contraction_visual_squash_confusion"], ["use_length_contraction"]),
            ("Two separated flashes are simultaneous in one frame. Another frame moving relative to the first may find that they...", ["occur at different times", "must still be simultaneous", "cancel out", "change c"], 0, "That is relativity of simultaneity.", ["simultaneity_absolute_confusion"], ["simultaneity_meaning"]),
            ("Which length is the proper length?", ["the object's rest-frame length", "the shortest measured length in any frame", "the length in the lab by default", "the gamma-scaled length"], 0, "Proper length is rest-frame length.", ["length_contraction_visual_squash_confusion"], ["proper_length"]),
            ("Why is span squeeze not a mere drawing trick?", ["because it is the quantitative frame-dependent length measurement predicted by relativity", "because rulers break at high speed", "because it only changes perspective art", "because it changes c"], 0, "Length contraction is a measured frame effect.", ["length_contraction_visual_squash_confusion"], ["length_contraction_meaning"]),
            ("Which formula is used in this lesson for contraction?", ["L = L0/gamma", "Delta t = gamma Delta tau", "E = hf", "Delta E = Delta m"], 0, "Use the length formula.", ["length_contraction_visual_squash_confusion"], ["use_length_contraction"]),
            ("Why is same-now slip part of relativity rather than a side note?", ["because frame comparisons of time and space must include when events are judged simultaneous", "because simultaneity is less important than length always", "because only photons need simultaneity", "because it fixes work functions"], 0, "Without simultaneity, the frame story is incomplete.", ["simultaneity_absolute_confusion"], ["frame_comparison"]),
            ("Which statement best links modern physics together?", ["packet events, pattern maps, core binding, and frame effects all use one rulebook built around discrete interactions and invariant c", "modern physics is four unrelated shocks", "only relativity matters", "only the photoelectric effect matters"], 0, "The family story matters here.", ["fixed_c_source_motion_confusion"], ["modern_unity"]),
            ("Why does E = mc^2 belong naturally beside relativity?", ["because the same constant c that governs frame effects also sets the mass-energy link", "because c changes with the observer", "because it only applies to photons", "because it replaces the need for frames"], 0, "Mass-energy and relativity share the same c.", ["fixed_c_source_motion_confusion"], ["mass_energy_link"]),
        ],
    ) + build_shorts(
        "A5L6_M",
        [
            (
                "Explain why one universal 'same now' cannot survive if c is invariant.",
                [
                    "Because if every inertial frame measures the same speed of light, then different moving frames must use different space-time bookkeeping and can disagree on whether separated events were simultaneous.",
                    "Invariant c forces frame-dependent simultaneity, so one universal now-map is impossible.",
                ],
                "Use invariant c plus frame-dependent simultaneity.",
                ["simultaneity_absolute_confusion", "fixed_c_source_motion_confusion"],
                ["simultaneity_meaning", "frame_comparison"],
                acceptance_groups(["same speed of light", "invariant c"], ["simultaneous", "same now", "same time"], ["frame", "observer"], ["not universal", "disagree", "different bookkeeping"]),
            ),
            (
                "How does Module A5 connect relativity and nuclear energy in one sentence?",
                [
                    "They are linked by the same constant c: relativity keeps c invariant across frames, and mass-energy uses the same c in E = mc^2 to connect mass stamp and energy.",
                    "The same speed-of-light constant that drives frame effects also sets the scale of mass-energy conversion.",
                ],
                "Use the shared role of c.",
                ["fixed_c_source_motion_confusion", "mass_defect_energy_from_nothing_confusion"],
                ["mass_energy_link", "modern_unity"],
                acceptance_groups(["c", "speed of light"], ["relativity", "frames"], ["mass-energy", "E = mc^2", "mass defect"], ["same constant", "shared link"]),
            ),
        ],
    )
    return lesson_spec(
        "A5_L6",
        "Compare the Frame Maps",
        sim(
            "a5_frame_map_lab",
            "Frame map lab",
            "Compare moving observers' clocks, rods, and event markers so length contraction and simultaneity live on the same frame board.",
            ["Choose a relative speed.", "Read proper length and contracted length.", "Place two separated events and compare simultaneity judgments."],
            ["Use L = L0/gamma.", "Explain relativity of simultaneity.", "Connect frame effects back to invariant c and E = mc^2."],
            ["relative_speed", "gamma", "proper_length", "contracted_length", "event_order"],
            "Frame-map reasoning.",
        ),
        diagnostic,
        "The frame layer of the Packet-Pattern Frame world goes beyond tick stretch. If all moving observers keep the same signal cap c, then they also cannot share one universal map of lengths and 'same now' moments. Motion-aligned spans squeeze, and separated events that are simultaneous in one frame need not stay simultaneous in another. This is why relativity is a frame-bookkeeping theory rather than just a strange clock trick. It also closes the module: the same c that fixes frame comparisons also appears in the mass-energy link of the core-bundle story.",
        "Commit to relativity as one coordinated frame rulebook for time, length, and simultaneity.",
        [
            prompt_block("Which frame measures proper length?", "The object's rest frame."),
            prompt_block("Can all moving frames share one universal 'same now'?", "No, simultaneity is frame-dependent."),
        ],
        [
            prompt_block("Start with zero relative speed.", "Length and simultaneity comparisons should match."),
            prompt_block("Increase the relative speed.", "The moving length contracts and event timing judgments can diverge."),
        ],
        [
            "Why is length contraction not just a picture that looks squashed?",
            "Why must simultaneity join the story if time and length are already frame-dependent?",
        ],
        "Use the frame-map board to keep contraction, simultaneity, and the shared role of c together.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Explain length contraction as a frame-dependent measurement along the direction of motion.",
                "Explain relativity of simultaneity as frame-dependent disagreement about separated event timing.",
                "Connect frame effects and mass-energy through the shared role of c.",
            ],
            core_concepts=[
                "Proper length is measured in the object's rest frame.",
                "Moving lengths contract along the direction of motion by the factor 1/gamma.",
                "Separated events need not remain simultaneous across inertial frames.",
                "Invariant c underlies time dilation, length contraction, simultaneity shifts, and the mass-energy link.",
            ],
            prerequisite_lessons=["A5_L5"],
            misconception_focus=[
                "fixed_c_source_motion_confusion",
                "length_contraction_visual_squash_confusion",
                "simultaneity_absolute_confusion",
            ],
            formulas=[
                relation("L = L0 / gamma", "Length-contraction relation.", ["m"], "Use for lengths measured parallel to the direction of relative motion."),
                relation("Delta E = Delta m c^2", "Mass-energy relation revisited.", ["J"], "Included here to connect the frame layer back to the core-bundle layer."),
            ],
            representations=[
                representation("rod comparison", "Shows proper length beside contracted length."),
                representation("event map", "Shows two events judged simultaneous in one frame but not another."),
                representation("words", "Explains why one universal now-map cannot survive invariant c."),
                representation("concept bridge", "Links relativity and mass-energy through the same constant c."),
            ],
            analogy_map=packet_pattern_frame_map("the learner compares length and simultaneity maps across moving frame pods"),
            worked_examples=[
                worked("A rod has proper length 12 m and gamma = 3. What length is measured from another frame?", ["Use L = L0/gamma.", "Substitute 12 m and gamma = 3.", "Calculate the contracted length."], "4 m", "The moving-frame measurement is shorter along the motion direction.", "This is the core contraction calculation."),
                worked("Why can two flashes be simultaneous in one frame but not another?", ["Keep c invariant in both frames.", "Compare how the frames assign times to separated events.", "Conclude that simultaneity depends on the frame."], "Simultaneity is frame-dependent", "One universal 'same now' would conflict with the relativity postulates.", "This anchors the simultaneity shift."),
                worked("How does E = mc^2 connect back to relativity?", ["Identify c as the invariant speed from the relativity postulates.", "Notice that the same c appears in the mass-energy relation.", "Conclude that frame physics and mass-energy share one modern-physics constant."], "Mass-energy and relativity are linked by the same c", "This closes the module by unifying the frame and core stories.", "It helps the module feel like one modern layer rather than separate chapters."),
            ],
            visual_assets=[
                visual(
                    "a5-l6-frame-slip",
                    "modern_physics_diagram",
                    "Frame maps disagree on span and same-now",
                    "Show a rest-frame rod and event pair beside a moving-frame comparison so contraction and simultaneity stay on one board.",
                    "Once c is invariant, moving observers cannot all keep the same length map or the same simultaneity map.",
                    template="modern_physics_diagram",
                    meta={"diagram_type": "length_and_simultaneity"},
                )
            ],
            simulation_contract=sim_contract(
                "a5_l6_frame_map_sim",
                "frame_map",
                "Change relative speed and compare lengths and simultaneity judgments across two frame pods.",
                "Start with matching frames before adding relative motion.",
                [
                    "Increase speed and compare proper length with contracted length.",
                    "Mark two separated events that are simultaneous in one frame and inspect the other frame's timing.",
                    "Explain how the same c behind time dilation also forces these other frame effects.",
                ],
                "Watch for contraction being treated as a visual trick and simultaneity being treated as universal.",
                "Relativity is a connected rulebook: if c stays fixed, time, length, and simultaneity all become frame-dependent together.",
                controls=[
                    ("relative_speed", "Relative speed", "Sets the strength of gamma and all frame effects."),
                    ("proper_length", "Proper length", "Sets the rest-frame length for comparison."),
                    ("event_spacing", "Event spacing", "Lets the simultaneity comparison remain visibly separated in space."),
                ],
                readouts=[
                    ("Contracted length", "Shows the moving-frame length along the direction of motion."),
                    ("Simultaneity verdict", "Shows whether the two frames agree about the event timing."),
                ],
            ),
            reflection_prompts=[
                "Explain why one universal simultaneity map is incompatible with invariant c.",
                "Describe how length contraction and time dilation belong to the same frame rulebook.",
            ],
            mastery_skills=["length_contraction_meaning", "use_length_contraction", "proper_length", "simultaneity_meaning", "frame_comparison", "mass_energy_link"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between proper-length vocabulary, simultaneity judgments, and quick invariant-c connections.",
                "concept_gate": "Concept-gate retries alternate between new contraction calculations and short explanations of why simultaneity is not universal.",
                "mastery": "Mastery prefers unseen lesson-owned contraction, simultaneity, and modern-physics-unity prompts before repeating any item.",
            },
            scaffold_support=scaffold(
                "A fixed c means frames cannot all share one length map or one now-map.",
                "Length contraction and simultaneity become much easier when learners see them as consequences of the same postulates that already produced time dilation.",
                "If c stays fixed, what other measurements besides time must become frame-dependent?",
                "Thinking contraction is merely visual squash or thinking simultaneity stays universal despite relativity.",
                "Frame pods keep their own coherent maps, but once they move relative to each other they can no longer keep one universal ruler layout or one universal 'same now' stamp while preserving the same light-speed cap.",
                "Why does relativity of simultaneity matter even after you already know about time dilation?",
                extras=[
                    extra_section("Proper versus contracted length", "Proper length is the full rest-frame span. Contracted length is the shorter moving-frame measurement along the motion direction.", "Which frame owns the proper length?"),
                    extra_section("Shared role of c", "The same c that forces frame disagreement also sets the scale of mass-energy conversion in E = mc^2, tying relativity back to the nuclear-energy story.", "Why does c connect the frame and core layers of the module?"),
                ],
            ),
            visual_clarity_checks=visual_checks("relativity frame map"),
        ),
    )


A5_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Photoelectric threshold, wave-particle duality, nuclear binding energy, and special relativity taught through the Packet-Pattern Frame Model so learners keep photons, probability patterns, core bundles, and moving frames inside one coherent modern-physics story.",
    "mastery_outcomes": [
        "Explain the photoelectric effect using photon energy, threshold frequency, work function, and maximum kinetic energy.",
        "Describe wave-particle duality as localized detections together with wave-like distributions and use de Broglie's relation conceptually.",
        "Explain nuclear energy through binding-energy changes, mass defect, and Delta E = Delta m c^2.",
        "Explain special relativity through invariant light speed, time dilation, length contraction, and relativity of simultaneity.",
        "Connect mass-energy and frame effects through the shared role of the invariant speed of light.",
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
    "Every lesson keeps the Packet-Pattern Frame language visible across packets, patterns, core bundles, and frame pods.",
    "Every explorer is backed by a lesson-specific simulation contract instead of generic fallback wording.",
    "Every lesson-owned assessment bank supports fresh unseen diagnostic, concept-gate, and mastery questions before repeats.",
    "Every conceptual short answer accepts varied scientifically correct wording through authored phrase groups.",
    "Every visual keeps packet, pattern, core, and frame labels readable without clipping or overlap.",
    "Every lesson balances conceptual interpretation with qualitative or quantitative modern-physics reasoning.",
]


A5_MODULE_DOC, A5_LESSONS, A5_SIM_LABS = build_nextgen_module_bundle(
    module_id=A5_MODULE_ID,
    module_title=A5_MODULE_TITLE,
    module_spec=A5_SPEC,
    allowlist=A5_ALLOWLIST,
    content_version=A5_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=24,
    level="Module A5",
    estimated_minutes=390,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module A5 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(A5_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A5_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in A5_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", A5_MODULE_ID)]
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
