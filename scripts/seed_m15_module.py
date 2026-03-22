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


M15_MODULE_ID = "M15"
M15_CONTENT_VERSION = "20260322_m15_beacon_city_stretchmap_v2"
M15_MODULE_TITLE = "Universe"
M15_ALLOWLIST = [
    "star_reflects_light_confusion",
    "fusion_core_energy_confusion",
    "mass_same_star_fate_confusion",
    "galaxy_equals_universe_confusion",
    "milky_way_equals_solar_system_confusion",
    "light_year_time_confusion",
    "light_year_small_distance_confusion",
    "redshift_cooling_confusion",
    "redshift_color_only_confusion",
    "farther_smaller_redshift_confusion",
    "big_bang_center_explosion_confusion",
    "expansion_into_space_confusion",
]


def safe_tags(tags: Sequence[str]) -> List[str]:
    allowed = set(M15_ALLOWLIST)
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
    title: str,
    purpose: str,
    caption: str,
    *,
    diagram_type: str,
    meta: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    return {
        "asset_id": asset_id,
        "concept": "space_astrophysics_diagram",
        "phase_key": "analogical_grounding",
        "title": title,
        "purpose": purpose,
        "caption": caption,
        "template": "space_astrophysics_diagram",
        "meta": {"diagram_type": diagram_type, **deepcopy(meta or {})},
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


def assessment_targets(
    *,
    diagnostic_pool_min: int = 3,
    concept_gate_pool_min: int = 2,
    mastery_pool_min: int = 3,
) -> Dict[str, Any]:
    return {
        "diagnostic_pool_min": diagnostic_pool_min,
        "concept_gate_pool_min": concept_gate_pool_min,
        "mastery_pool_min": mastery_pool_min,
        "fresh_attempt_policy": "Prefer unseen lesson-owned questions in diagnostic, concept-gate, and mastery before repeating any previous stem.",
    }


def visual_checks(topic: str) -> List[str]:
    return [
        f"The main {topic} labels stay fully visible on desktop and mobile layouts.",
        "Beacon, galaxy, distance-scale, and wavelength labels stay separate enough that the astronomy relationships remain easy to parse.",
        "Scale notes and comparison captions stay outside the busiest diagram regions so the visual reads like physics rather than decoration.",
        "Color shifts, city markers, and stellar-path branches remain clear enough to support qualitative reasoning without clipped text.",
    ]


def beacon_city_map(focus: str) -> Dict[str, Any]:
    return {
        "model_name": "Beacon-City Stretchmap Model",
        "focus": focus,
        "comparison": f"The Beacon-City Stretchmap world keeps stars, stellar lifecycles, galaxies, light-year distances, redshift, and cosmic expansion inside one beacons-on-a-stretchmap story while {focus}.",
        "mapping": [
            "Beacon -> star",
            "Glow cradle -> nebula / stellar nursery",
            "Young spark -> protostar",
            "Steady beacon -> main-sequence star",
            "Swollen ember -> red giant / red supergiant",
            "White ember -> white dwarf",
            "Blast bloom -> supernova",
            "Dense spark -> neutron star",
            "Dark well -> black hole",
            "Beacon-city -> galaxy",
            "Home spiral city -> Milky Way",
            "Signal-year -> light-year",
            "Stretch-red drift -> redshift",
            "Great Unfurling -> Big Bang / cosmic expansion",
        ],
        "limit": "The model keeps the astronomy story coherent, but learners still need the formal terms fusion, main sequence, galaxy, light-year, redshift, and Big Bang.",
        "prediction_prompt": f"Use the Beacon-City Stretchmap model to predict what should happen when {focus}.",
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


def build_mcqs(rows: Sequence[Tuple[str, str, Sequence[str], int, str, Sequence[str], Sequence[str]]]) -> List[Dict[str, Any]]:
    return [mcq(qid, prompt, choices, answer_index, hint, tags, skill_tags=skill_tags) for qid, prompt, choices, answer_index, hint, tags, skill_tags in rows]


def build_shorts(
    rows: Sequence[Tuple[str, str, Sequence[str], str, Sequence[str], Sequence[str], Dict[str, Any]]]
) -> List[Dict[str, Any]]:
    return [
        short(qid, prompt, accepted_answers, hint, tags, skill_tags=skill_tags, acceptance_rules=acceptance_rules)
        for qid, prompt, accepted_answers, hint, tags, skill_tags, acceptance_rules in rows
    ]


def lesson_one() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        (
            "M15L1_D1",
            "In the Beacon-City model, a beacon stands for a...",
            ["star", "planet", "moon", "galaxy"],
            0,
            "A beacon is a star because it makes its own light.",
            ["star_reflects_light_confusion"],
            ["identify_star"],
        ),
        (
            "M15L1_D2",
            "Which object is best described as self-lit?",
            ["the Sun", "the Moon", "Earth", "Venus by reflection"],
            0,
            "Stars are self-lit; planets and moons mainly reflect.",
            ["star_reflects_light_confusion"],
            ["luminous_vs_reflective", "identify_star"],
        ),
    ]) + build_shorts([
        (
            "M15L1_D3",
            "Why is a star better modeled as a beacon than as a mirror?",
            [
                "Because a star makes its own light, while a mirror only reflects light from somewhere else.",
                "Because a star is self-luminous rather than just reflecting another light source.",
            ],
            "Use self-lit versus reflected language.",
            ["star_reflects_light_confusion"],
            ["luminous_vs_reflective", "fusion_energy"],
            acceptance_groups(
                ["star", "beacon"],
                ["makes", "produces", "self-lit", "luminous"],
                ["light"],
                ["mirror", "reflect"],
            ),
        ),
    ])
    concept = build_mcqs([
        (
            "M15L1_C1",
            "Which comparison is strongest?",
            [
                "star: self-lit, planet: mostly reflective",
                "star: reflective, planet: self-lit",
                "star and planet both self-lit",
                "star and planet both only reflective",
            ],
            0,
            "Stars make light; planets mainly reflect.",
            ["star_reflects_light_confusion"],
            ["luminous_vs_reflective", "identify_star"],
        ),
    ]) + build_shorts([
        (
            "M15L1_C2",
            "Explain why a bright planet still is not a star.",
            [
                "Because the planet is bright mainly by reflecting starlight, while a star makes its own light.",
                "Because brightness by reflection is not the same as self-luminous fusion-powered light.",
            ],
            "Contrast reflection with self-produced light.",
            ["star_reflects_light_confusion"],
            ["luminous_vs_reflective", "fusion_energy"],
            acceptance_groups(
                ["planet"],
                ["reflect", "reflection"],
                ["star"],
                ["makes", "produces", "self-lit"],
                ["light"],
            ),
        ),
    ])
    mastery = build_mcqs([
        (
            "M15L1_M1",
            "Which object is most likely to be a star?",
            [
                "a body producing its own light by core fusion",
                "a cold rock reflecting sunlight",
                "a moon shining by reflection",
                "a dust cloud lit by a nearby star",
            ],
            0,
            "A star is self-lit and fusion-powered.",
            ["star_reflects_light_confusion", "fusion_core_energy_confusion"],
            ["identify_star", "luminous_vs_reflective", "fusion_energy"],
        ),
        (
            "M15L1_M3",
            "Which statement keeps astronomy language accurate?",
            [
                "The Sun is a star because it is a luminous sphere powered by fusion.",
                "The Sun is a planet because it looks bright.",
                "Earth is a star because we see it in sunlight.",
                "The Moon is a star because it glows at night.",
            ],
            0,
            "The Sun is our nearest star.",
            ["star_reflects_light_confusion", "fusion_core_energy_confusion"],
            ["identify_star"],
        ),
    ]) + build_shorts([
        (
            "M15L1_M2",
            "Summarize the beacon idea in one strong sentence.",
            [
                "A star is a self-lit beacon because fusion in its core releases the energy that makes it shine.",
                "Stars are self-luminous beacons powered by core fusion.",
            ],
            "Keep self-lit and fusion together.",
            ["star_reflects_light_confusion", "fusion_core_energy_confusion"],
            ["fusion_energy"],
            acceptance_groups(
                ["star", "beacon"],
                ["self-lit", "luminous"],
                ["fusion"],
                ["core"],
                ["shine", "light", "energy"],
            ),
        ),
    ])
    return lesson_spec(
        "M15_L1",
        "Light the Beacon",
        sim(
            "m15_light_beacon_lab",
            "Light the beacon",
            "Compare self-lit and reflective objects so the star-versus-planet distinction stays physical instead of visual only.",
            [
                "Switch between self-lit and reflective objects.",
                "Compare the light source status of a star and a planet.",
            ],
            [
                "Explain stars as luminous bodies.",
                "Separate fusion-powered light from reflected light.",
            ],
            ["luminous_source", "reflected_source", "fusion_toggle"],
            "Self-lit versus illuminated reasoning.",
        ),
        diagnostic,
        "A beacon is a body that shines by itself. In astronomy that means a star: fusion in the core releases energy, so the star is self-lit instead of borrowing brightness by reflection.",
        "Commit to asking where the light comes from before classifying the object.",
        [
            prompt_block("What makes a beacon a beacon?", "It produces its own light."),
            prompt_block("What powers a star's light?", "Fusion in the core."),
        ],
        [
            prompt_block("Compare a self-lit body and a reflective body.", "Only the self-lit one matches the star story."),
            prompt_block("Keep apparent brightness separate from light source.", "A reflective body can still look bright."),
        ],
        [
            "Why is a star stronger as a beacon than as a mirror?",
            "Why does fusion matter in the definition of a star?",
        ],
        "Start the module by separating luminous stars from illuminated objects before any larger cosmic structures appear.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Explain a star as a luminous body that makes its own light.",
                "Link star light to fusion in the core.",
            ],
            core_concepts=[
                "Stars are self-lit.",
                "Planets and moons mainly reflect starlight.",
                "Fusion in a star's core releases the energy that makes it shine.",
                "Apparent brightness alone does not decide whether something is a star.",
            ],
            prerequisite_lessons=["M14_L1"],
            misconception_focus=["star_reflects_light_confusion", "fusion_core_energy_confusion"],
            formulas=[
                relation(
                    "fusion in core -> light + heat",
                    "Core fusion is the star's internal energy source.",
                    ["concept only"],
                    "Use as the causal story for why stars shine.",
                )
            ],
            representations=[
                representation("words", "Separates luminous stars from reflective planets."),
                representation("formula", "fusion in core -> light + heat"),
                representation("diagram", "Compares a self-lit beacon with a reflective world."),
                representation("model", "Uses the Beacon language to anchor the distinction."),
            ],
            analogy_map=beacon_city_map("the learner compares a self-lit star with an illuminated planet"),
            worked_examples=[
                worked(
                    "A bright object in the sky stops being lit by outside light but still emits energy. Is it better classified as a star or a planet?",
                    [
                        "Ask whether the object makes its own light.",
                        "Notice that internal emission continues even when reflected light is removed.",
                        "Classify it using the light-source rule.",
                    ],
                    "It is better classified as a star.",
                    "Stars are luminous bodies; reflective planets do not stay bright by their own emission in this model.",
                    "This protects students from using brightness alone as the classifier.",
                ),
                worked(
                    "A learner says, 'Venus is as bright as a star, so Venus is basically a star.' How do you correct that?",
                    [
                        "Separate apparent brightness from light source.",
                        "Ask whether Venus makes its own light or reflects sunlight.",
                        "State the stronger classification rule.",
                    ],
                    "Venus is not a star because it mainly reflects sunlight rather than producing its own light by fusion.",
                    "The source of the light matters more than how bright the object appears.",
                    "This keeps the module anchored in causal physics rather than appearance alone.",
                ),
            ],
            visual_assets=[
                visual(
                    "m15-l1-star-vs-planet",
                    "Self-lit beacons are different from reflective worlds",
                    "Show a fusion-powered star and a reflective planet on one board so luminous and illuminated bodies stay distinct.",
                    "The lesson 1 board keeps core fusion and reflected light apart before galaxies and redshift are introduced.",
                    diagram_type="star_vs_planet",
                )
            ],
            animation_assets=[],
            simulation_contract=sim_contract(
                "m15_l1_beacon_sim",
                "self_lit_beacon",
                "Switch between self-made light and reflected light until the star rule feels automatic.",
                "Start with one beacon and one reflective world under the same comparison light.",
                [
                    "Toggle whether the object makes its own light.",
                    "Compare identical apparent brightness with different light sources.",
                ],
                "Watch the classification change only when the light source changes, not when apparent brightness changes.",
                "Stars are self-lit because fusion powers their emission.",
                controls=[
                    ("light_source_mode", "Light source", "Switches between self-lit and reflective cases."),
                    ("fusion_level", "Fusion level", "Shows whether the star's core is powering the beacon."),
                    ("apparent_brightness", "Apparent brightness", "Tests the difference between appearance and cause."),
                ],
                readouts=[
                    ("Beacon status", "Tells whether the object counts as self-lit."),
                    ("Light origin", "Names whether the light is emitted or reflected."),
                ],
            ),
            reflection_prompts=["Explain why a star is stronger as a self-lit beacon than as a reflective object."],
            mastery_skills=["identify_star", "luminous_vs_reflective", "fusion_energy", "classify_light_source", "star_to_galaxy_bridge"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between luminous-versus-reflective, source-check, and fusion-cause prompts.",
                "concept_gate": "Concept-gate retries alternate between brightness traps and stronger star-definition prompts.",
                "mastery": "Mastery varies classification, correction, and one-sentence summary tasks before repeating an earlier star-light family.",
            },
            scaffold_support=scaffold(
                "A star is a self-lit beacon.",
                "The correct comparison is about the source of the light, not only about how bright the object looks.",
                "How would you test whether something is a star using the Beacon model?",
                "A bright reflected object can trick you if you use appearance instead of cause.",
                "A beacon shines by itself, so a star belongs in the beacon role while a planet usually does not.",
                "Which part of the analogy matches fusion in the core?",
                [
                    extra_section("Cause first", "Ask where the light comes from before naming the object.", "What would you ask about the source of the light?"),
                    extra_section("Brightness trap", "A reflective body can still look bright, so brightness alone is too weak.", "Why is brightness not enough by itself?"),
                ],
            ),
            visual_clarity_checks=visual_checks("star-versus-planet"),
        ),
    )


def lesson_two() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        (
            "M15L2_D1",
            "In the Beacon-City model, a glow cradle stands for a...",
            ["nebula / stellar nursery", "galaxy", "black hole", "light-year"],
            0,
            "Stars begin in gas-and-dust clouds.",
            ["mass_same_star_fate_confusion"],
            ["identify_stellar_birth"],
        ),
        (
            "M15L2_D2",
            "A young spark stands for a...",
            ["protostar", "white dwarf", "galaxy", "redshift"],
            0,
            "A protostar is a forming star.",
            ["mass_same_star_fate_confusion"],
            ["identify_stellar_birth"],
        ),
        (
            "M15L2_D3",
            "Case 1: two stars begin with very different masses. What is most likely to differ later?",
            [
                "their life path and final remnant",
                "whether they are stars at all",
                "whether galaxies exist",
                "whether light-years are distances",
            ],
            0,
            "Mass shapes the stellar life path.",
            ["mass_same_star_fate_confusion"],
            ["mass_life_path"],
        ),
    ]) + build_shorts([
        (
            "M15L2_D4",
            "Why do not all stars end the same way?",
            [
                "Because a star's mass changes its life path and final remnant.",
                "Because stellar evolution depends strongly on mass, so low-mass and high-mass stars end differently.",
            ],
            "Use mass-dependent path language.",
            ["mass_same_star_fate_confusion"],
            ["mass_life_path"],
            acceptance_groups(["mass"], ["changes", "depends", "shapes"], ["life path", "remnant"]),
        ),
    ])
    concept = build_mcqs([
        (
            "M15L2_C1",
            "Which path is strongest for a low-mass beacon?",
            [
                "glow cradle -> young spark -> steady beacon -> swollen ember -> white ember",
                "glow cradle -> galaxy -> redshift -> black hole",
                "steady beacon -> no change forever",
                "protostar -> galaxy city",
            ],
            0,
            "Low-mass stars usually end as white dwarfs after giant stages.",
            ["mass_same_star_fate_confusion"],
            ["mass_life_path"],
        ),
        (
            "M15L2_C2",
            "Case 2: star A ends as a white dwarf and star B ends as a neutron star. What is the best inference?",
            [
                "star B began with greater mass",
                "star A began with greater mass",
                "mass made no difference",
                "both were galaxies",
            ],
            0,
            "The neutron-star path usually belongs to a more massive origin star.",
            ["mass_same_star_fate_confusion"],
            ["stellar_remnants"],
        ),
    ]) + build_shorts([
        (
            "M15L2_C3",
            "Explain why a stellar lifecycle diagram branches rather than staying as one single line.",
            [
                "Because stars with different masses follow different later paths and end in different remnants.",
                "Because mass changes the later evolution, so the stellar life cycle must branch.",
            ],
            "Use branch-by-mass reasoning.",
            ["mass_same_star_fate_confusion"],
            ["mass_life_path"],
            acceptance_groups(["mass"], ["different"], ["path", "branch", "remnant"]),
        ),
    ])
    mastery = build_mcqs([
        (
            "M15L2_M1",
            "Which remnant is most consistent with a lower-mass star?",
            ["white dwarf", "black hole", "galaxy city", "redshift trail"],
            0,
            "Lower-mass stars can leave white dwarfs.",
            ["mass_same_star_fate_confusion"],
            ["stellar_remnants"],
        ),
        (
            "M15L2_M2",
            "Case 3: star X is 2 solar masses and star Y is 25 solar masses. Which one is more likely to follow the blast-bloom path?",
            ["star Y", "star X", "both equally", "neither because only galaxies explode"],
            0,
            "The more massive star is more likely to go supernova.",
            ["mass_same_star_fate_confusion"],
            ["supernova_path"],
        ),
    ]) + build_shorts([
        (
            "M15L2_M3",
            "Summarize the mass rule in one strong sentence.",
            [
                "A star's mass shapes its later life path and final remnant, so not all stars die the same way.",
                "Mass decides which stellar branch and remnant become possible.",
            ],
            "Keep mass tied to branch and ending.",
            ["mass_same_star_fate_confusion"],
            ["mass_life_path"],
            acceptance_groups(["mass"], ["shapes", "changes", "decides"], ["life path", "branch"], ["remnant", "ending"]),
        ),
    ])
    return lesson_spec(
        "M15_L2",
        "Choose the Star Path",
        sim(
            "m15_star_path_lab",
            "Choose the star path",
            "Move one forming star onto low-mass or high-mass branches so the lifecycle becomes a mass-shaped story rather than a memorized chain.",
            ["Start at a glow cradle.", "Adjust stellar mass and compare the later path."],
            ["Describe major stellar stages.", "Explain that mass changes the final path and remnant."],
            ["stellar_mass", "stage_branch", "remnant_type"],
            "Mass-dependent stellar evolution.",
        ),
        diagnostic,
        "Every beacon begins in a glow cradle, then forms as a young spark and spends a long time as a steady beacon. Later, mass matters: some stars swell and fade into white embers, while more massive ones can end in a blast bloom and leave dense sparks or dark wells.",
        "Commit to reading the stellar life path as a branch shaped by mass rather than as one universal ending.",
        [
            prompt_block("What is the long stable stage called?", "The main-sequence or steady beacon stage."),
            prompt_block("What changes the later path most strongly?", "The star's mass."),
        ],
        [
            prompt_block("Compare a lower-mass star with a higher-mass star.", "The higher-mass star can follow the supernova branch."),
            prompt_block("Keep early stages shared but later stages branched.", "That is why the lifecycle diagram branches."),
        ],
        ["Why does a stellar lifecycle branch?", "Why is a supernova not the ending for every star?"],
        "This lesson turns stellar evolution into a causal branch story instead of a flat list of stage names.",
        concept,
        mastery,
        contract(
            concept_targets=[
                "Describe the broad stellar lifecycle from nebula to remnant.",
                "Explain that stellar mass changes the later path and remnant.",
            ],
            core_concepts=[
                "Stars form in nebulae.",
                "Protostars become main-sequence stars.",
                "Lower-mass and higher-mass stars do not share identical endings.",
                "Massive stars can explode as supernovae and leave neutron stars or black holes.",
            ],
            prerequisite_lessons=["M15_L1"],
            misconception_focus=["mass_same_star_fate_confusion"],
            formulas=[
                relation(
                    "higher mass -> more dramatic later branch",
                    "Stellar mass is the main variable that changes the later path.",
                    ["concept only"],
                    "Use qualitatively when comparing stellar lifecycles.",
                )
            ],
            representations=[
                representation("words", "Tracks the star from birth cloud to remnant."),
                representation("formula", "higher mass -> different later branch and remnant"),
                representation("diagram", "Shows the lifecycle branch by mass."),
                representation("model", "Keeps stellar stages inside the Beacon-City story."),
            ],
            analogy_map=beacon_city_map("the learner compares low-mass and high-mass stellar endings"),
            worked_examples=[
                worked(
                    "A low-mass star and a high-mass star are compared after the main sequence. Why should their final outcomes not be assumed identical?",
                    [
                        "Start with the shared early stages.",
                        "Ask what variable changes the later branch.",
                        "Use mass to explain why the endings can differ.",
                    ],
                    "Their mass changes the later lifecycle path, so their final remnants need not be the same.",
                    "The stellar lifecycle is a branch, not a one-line script.",
                    "This prevents the common overgeneralization that every star ends the same way.",
                ),
                worked(
                    "A learner says, 'all red giants eventually become black holes.' How do you respond?",
                    [
                        "Separate lower-mass and higher-mass branches.",
                        "Notice that black holes belong to very massive endings.",
                        "Place white dwarfs on the lower-mass route.",
                    ],
                    "That is incorrect because lower-mass stars can end as white dwarfs rather than black holes.",
                    "Black holes are not the universal endpoint; mass decides which remnants are possible.",
                    "This keeps the mass-dependence explicit.",
                ),
            ],
            visual_assets=[
                visual(
                    "m15-l2-stellar-lifecycle",
                    "Mass changes the later star path",
                    "Show one stellar lifecycle board with low-mass and high-mass branches so remnant differences stay visible.",
                    "The lesson 2 visual keeps stellar birth, stable shining, swelling, explosion, and remnant paths on one clear map.",
                    diagram_type="stellar_lifecycle",
                )
            ],
            animation_assets=[],
            simulation_contract=sim_contract(
                "m15_l2_stellar_path_sim",
                "stellar_path_branch",
                "Change the star's mass and watch the later lifecycle path branch.",
                "Start with a medium-mass forming star in a glow cradle.",
                ["Lower the mass and compare the later remnant.", "Raise the mass and compare the supernova branch."],
                "Watch the later stages branch only when the mass setting changes.",
                "Mass shapes the later stellar path and final remnant.",
                controls=[
                    ("stellar_mass", "Stellar mass", "Chooses the low-mass or high-mass branch."),
                    ("stage_position", "Life stage", "Moves the star along the lifecycle."),
                    ("remnant_focus", "Remnant focus", "Highlights the likely endpoint for the current branch."),
                ],
                readouts=[
                    ("Current branch", "Summarizes whether the star is on a lower-mass or higher-mass route."),
                    ("Likely remnant", "Names the remnant most consistent with the chosen mass."),
                ],
            ),
            reflection_prompts=["Explain why the stellar lifecycle is stronger as a mass-shaped branch than as one fixed chain."],
            mastery_skills=["identify_stellar_birth", "main_sequence", "mass_life_path", "supernova_path", "stellar_remnants"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between birth-stage, main-sequence, and mass-branch checks.",
                "concept_gate": "Concept-gate retries alternate between low-mass versus high-mass path comparisons.",
                "mastery": "Mastery varies stage-order, branch-choice, remnant, and misconception-correction tasks before repeating an earlier stellar-path family.",
            },
            scaffold_support=scaffold(
                "Stars share broad early stages, but mass changes the later branch.",
                "A lifecycle diagram branches because the same beginning does not guarantee the same ending.",
                "Which variable should you check before predicting the remnant?",
                "Students often flatten the whole lifecycle into one script and lose the role of mass.",
                "The beacon grows from a glow cradle into a steady beacon, then the later route depends on how massive the beacon is.",
                "Which analogy term signals that the path can split later?",
                [
                    extra_section("Shared start", "Many stars share the glow cradle, young spark, and steady beacon stages before later differences appear.", "Which stages are often shared before the branch?"),
                    extra_section("Mass branch", "Use mass to decide whether the path ends quietly or explosively.", "Why does mass matter more than color-name memorization here?"),
                ],
            ),
            visual_clarity_checks=visual_checks("stellar lifecycle"),
        ),
    )


def lesson_three() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        (
            "M15L3_D1",
            "In the Beacon-City model, a beacon-city stands for a...",
            ["galaxy", "single star", "light-year", "redshift"],
            0,
            "A beacon-city is a galaxy.",
            ["galaxy_equals_universe_confusion"],
            ["identify_galaxy"],
        ),
        (
            "M15L3_D2",
            "Our home spiral city is the...",
            ["Milky Way", "Sun", "Earth", "Andromeda"],
            0,
            "The Milky Way is our home galaxy.",
            ["milky_way_equals_solar_system_confusion"],
            ["identify_milky_way"],
        ),
        (
            "M15L3_D3",
            "Which statement is strongest?",
            [
                "The Solar System is inside the Milky Way.",
                "The Milky Way is inside the Solar System.",
                "A galaxy is one single star.",
                "The Milky Way is the whole universe.",
            ],
            0,
            "The Solar System is one tiny part of the Milky Way.",
            ["milky_way_equals_solar_system_confusion", "galaxy_equals_universe_confusion"],
            ["solar_system_in_galaxy"],
        ),
    ]) + build_shorts([
        (
            "M15L3_D4",
            "Why is the Milky Way stronger as a beacon-city than as a single beacon?",
            [
                "Because the Milky Way contains many stars, gas, and dust bound together by gravity, not just one star.",
                "Because a galaxy is a huge gravity-bound collection of beacons rather than one beacon.",
            ],
            "Use many-stars-plus-gravity language.",
            ["galaxy_equals_universe_confusion"],
            ["identify_galaxy"],
            acceptance_groups(["Milky Way", "galaxy", "beacon-city"], ["many", "collection"], ["stars", "beacons"], ["gravity", "bound"]),
        ),
    ])
    concept = build_mcqs([
        (
            "M15L3_C1",
            "Which statement best matches a galaxy?",
            [
                "A gravity-bound system of stars, gas, and dust",
                "One star with planets",
                "One unit of distance",
                "A redder wavelength",
            ],
            0,
            "That is the galaxy definition used here.",
            ["galaxy_equals_universe_confusion"],
            ["gravity_bound_galaxy"],
        ),
        (
            "M15L3_C2",
            "Which comparison is strongest?",
            [
                "star = one beacon, galaxy = many beacons bound together",
                "star = many galaxies, galaxy = one beacon",
                "star = distance unit, galaxy = temperature",
                "star = redshift, galaxy = fusion",
            ],
            0,
            "One star and many-stars bound together are different scales.",
            ["galaxy_equals_universe_confusion"],
            ["star_to_galaxy_bridge"],
        ),
    ]) + build_shorts([
        (
            "M15L3_C3",
            "Explain why a galaxy is stronger as a city of beacons than as a single beacon.",
            [
                "Because a galaxy contains many stars together, while a single star is only one beacon.",
                "Because the galaxy story is a many-beacon gravity-bound system rather than one beacon alone.",
            ],
            "Use one-star versus many-stars language.",
            ["galaxy_equals_universe_confusion"],
            ["star_to_galaxy_bridge"],
            acceptance_groups(["galaxy"], ["many", "collection"], ["stars", "beacons"], ["single", "one"], ["star", "beacon"]),
        ),
    ])
    mastery = build_mcqs([
        (
            "M15L3_M1",
            "Which object is the better example of a galaxy?",
            ["a spiral system containing billions of stars", "one star with planets", "one bright comet", "one Moon"],
            0,
            "A galaxy is a huge bound system of stars.",
            ["galaxy_equals_universe_confusion"],
            ["identify_galaxy"],
        ),
        (
            "M15L3_M2",
            "The Milky Way is best described as...",
            ["our home spiral galaxy", "the whole universe", "one star near Earth", "a unit of time"],
            0,
            "The Milky Way is our home galaxy.",
            ["milky_way_equals_solar_system_confusion", "galaxy_equals_universe_confusion"],
            ["identify_milky_way"],
        ),
    ]) + build_shorts([
        (
            "M15L3_M3",
            "Summarize the beacon-city idea in one strong sentence.",
            [
                "A galaxy is a gravity-bound beacon-city containing many stars, and the Milky Way is our home spiral galaxy.",
                "Beacon-cities are galaxies: huge star systems held together by gravity.",
            ],
            "Keep many stars, gravity, and the Milky Way together.",
            ["galaxy_equals_universe_confusion", "milky_way_equals_solar_system_confusion"],
            ["identify_milky_way", "solar_system_in_galaxy", "gravity_bound_galaxy"],
            acceptance_groups(["galaxy", "beacon-city"], ["gravity", "bound"], ["many", "collection"], ["stars", "beacons"], ["Milky Way"]),
        ),
    ])
    return lesson_spec(
        "M15_L3",
        "Build the Beacon-City",
        sim(
            "m15_beacon_city_lab",
            "Build the beacon-city",
            "Compare one star, one Solar System, and one galaxy so the Milky Way scale story stays organized.",
            ["Place the Sun inside the Milky Way map.", "Compare a star with a galaxy city."],
            ["Describe a galaxy as a gravity-bound system.", "Identify the Milky Way as our home galaxy."],
            ["galaxy_type", "sun_location", "star_count_scale"],
            "Galaxy structure and scale.",
        ),
        diagnostic,
        "A beacon-city is a huge gravity-bound collection of beacons. In astronomy that means a galaxy: many stars, gas, and dust held together by gravity. Our home spiral city is the Milky Way, and the Solar System sits inside it rather than equaling it.",
        "Commit to keeping star, Solar System, galaxy, and universe on different scales.",
        [
            prompt_block("What is a beacon-city?", "A gravity-bound galaxy."),
            prompt_block("What is our home spiral city?", "The Milky Way."),
        ],
        [
            prompt_block("Compare one star with one galaxy.", "A galaxy contains many stars."),
            prompt_block("Place the Solar System inside the Milky Way.", "The smaller system belongs inside the larger one."),
        ],
        ["Why is the Milky Way not the whole universe?", "Why does the word gravity matter in the galaxy definition?"],
        "This lesson scales the module outward so students can place the Sun inside the Milky Way without collapsing star, galaxy, and universe into one object.",
        concept,
        mastery,
        contract(
            concept_targets=["Define a galaxy as a gravity-bound collection of stars, gas, and dust.", "Identify the Milky Way as our home spiral galaxy."],
            core_concepts=[
                "A star is not a galaxy.",
                "Galaxies are gravity-bound systems.",
                "The Milky Way is our home galaxy.",
                "The Solar System is inside the Milky Way rather than equal to it.",
            ],
            prerequisite_lessons=["M15_L1"],
            misconception_focus=["galaxy_equals_universe_confusion", "milky_way_equals_solar_system_confusion"],
            formulas=[
                relation(
                    "galaxy = many stars + gas + dust held by gravity",
                    "A galaxy is a large bound system rather than one star.",
                    ["concept only"],
                    "Use as the structural rule for beacon-cities.",
                )
            ],
            representations=[
                representation("words", "Separates star, Solar System, galaxy, and universe scales."),
                representation("formula", "galaxy = many stars + gas + dust held by gravity"),
                representation("diagram", "Shows the Milky Way as a spiral beacon-city with the Sun inside it."),
                representation("model", "Uses the city-of-beacons comparison."),
            ],
            analogy_map=beacon_city_map("the learner places the Sun correctly inside the Milky Way and separates one star from one galaxy"),
            worked_examples=[
                worked(
                    "A learner says, 'the Milky Way is basically our Solar System but bigger.' How do you correct that?",
                    [
                        "Compare the scale of one star system with the scale of a galaxy.",
                        "Notice that the Milky Way contains many stars, not just our Sun.",
                        "Place the Solar System inside the Milky Way.",
                    ],
                    "The Milky Way is a galaxy containing many stars, and the Solar System is only one tiny system inside it.",
                    "A galaxy and a Solar System are not the same category or scale.",
                    "This prevents the common Milky-Way-equals-Solar-System collapse.",
                ),
                worked(
                    "Why is gravity included in the galaxy definition rather than treated as an extra detail?",
                    [
                        "Ask what makes the stars count as one system rather than a random scatter.",
                        "Use gravity as the binding cause.",
                        "State the galaxy definition with binding included.",
                    ],
                    "Gravity matters because it is what holds the stars, gas, and dust together as one galaxy.",
                    "Without gravity, the beacon-city idea loses its physical reason for being one system.",
                    "This keeps the galaxy idea causal rather than descriptive only.",
                ),
            ],
            visual_assets=[
                visual(
                    "m15-l3-galaxy-milky-way",
                    "Galaxies are gravity-bound beacon-cities",
                    "Show the Milky Way as a spiral beacon-city with the Sun marked inside it so scale stays readable.",
                    "The lesson 3 visual keeps one star, one Solar System, and one galaxy on clearly separated scales.",
                    diagram_type="galaxy_milky_way",
                )
            ],
            animation_assets=[],
            simulation_contract=sim_contract(
                "m15_l3_galaxy_sim",
                "galaxy_city_builder",
                "Place the Sun and compare one beacon with one beacon-city.",
                "Start with a spiral galaxy map and no labels turned on.",
                ["Reveal the Sun's location inside the Milky Way.", "Compare a single star icon with the whole galaxy boundary."],
                "Watch the scale shift from one beacon to a city of beacons bound together.",
                "The Milky Way is a galaxy city, not the whole universe and not the Solar System itself.",
                controls=[
                    ("galaxy_type", "Galaxy type", "Switches between a spiral and a less structured city silhouette."),
                    ("sun_location", "Sun marker", "Shows where our Solar System belongs inside the Milky Way."),
                    ("scale_view", "Scale view", "Compares star scale with galaxy scale."),
                ],
                readouts=[
                    ("Current city", "Names the selected galaxy type and the idea of one bound system."),
                    ("Sun placement", "Confirms whether the Sun is being read as inside the Milky Way."),
                ],
            ),
            reflection_prompts=["Explain why the Milky Way is stronger as a gravity-bound beacon-city than as a single beacon or as the whole universe."],
            mastery_skills=["identify_galaxy", "identify_milky_way", "solar_system_in_galaxy", "gravity_bound_galaxy", "star_to_galaxy_bridge"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between galaxy-definition, Milky-Way, and scale-comparison prompts.",
                "concept_gate": "Concept-gate retries alternate between one-star versus many-stars and Solar-System-inside-galaxy reasoning.",
                "mastery": "Mastery varies summary, correction, and placement tasks before repeating an earlier galaxy-scale family.",
            },
            scaffold_support=scaffold(
                "A galaxy is a gravity-bound city of stars.",
                "The important move is separating one beacon from a city of beacons and then placing our local system inside that city.",
                "How would you explain the Milky Way without calling it either one star or all of space?",
                "Students often confuse galaxy, Solar System, and universe because they lose the scale hierarchy.",
                "A beacon-city is many beacons held together, so the galaxy analogy makes scale and gravity visible together.",
                "What part of the analogy corresponds to gravity holding the city together?",
                [
                    extra_section("Scale ladder", "Keep star, Solar System, galaxy, and universe on a clear ladder of size.", "Which of those four is the largest?"),
                    extra_section("Home city", "The Milky Way is home, but it is still one galaxy among many.", "Why does 'home galaxy' not mean 'whole universe'?"),
                ],
            ),
            visual_clarity_checks=visual_checks("galaxy-scale"),
        ),
    )


def lesson_four() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        (
            "M15L4_D1",
            "A signal-year stands for a...",
            ["distance", "time only", "brightness level", "star stage"],
            0,
            "A light-year is a distance, not a time.",
            ["light_year_time_confusion"],
            ["identify_light_year"],
        ),
        (
            "M15L4_D2",
            "Which statement is strongest?",
            [
                "A light-year is the distance light travels in one year.",
                "A light-year is the time light takes to turn red.",
                "A light-year is the age of a star.",
                "A light-year is the same as one galaxy.",
            ],
            0,
            "Keep the unit as distance.",
            ["light_year_time_confusion"],
            ["identify_light_year"],
        ),
        (
            "M15L4_D3",
            "Case 1: two stars are 4 signal-years and 400 signal-years away. Which one is farther?",
            ["the 400 signal-year star", "the 4 signal-year star", "both are equally far", "cannot be compared"],
            0,
            "More signal-years means greater distance.",
            ["light_year_time_confusion", "light_year_small_distance_confusion"],
            ["compare_distances"],
        ),
    ]) + build_shorts([
        (
            "M15L4_D4",
            "Why is a light-year about distance rather than time?",
            [
                "Because it names how far light travels in one year, so it is a distance unit.",
                "Because the year appears in the definition only as the travel time used to define a distance.",
            ],
            "Use distance-defined-by-travel language.",
            ["light_year_time_confusion"],
            ["identify_light_year"],
            acceptance_groups(["distance"], ["light", "signal"], ["travels"], ["one year"]),
        ),
    ])
    concept = build_mcqs([
        (
            "M15L4_C1",
            "Case 2: star A is 8 light-years away and star B is 80 light-years away. Which statement is strongest?",
            ["Star B is 10 times farther away.", "Star A is farther away.", "They are the same distance because both use light-years.", "You cannot compare distances in light-years."],
            0,
            "The numbers compare distances directly.",
            ["light_year_time_confusion"],
            ["compare_distances"],
        ),
        (
            "M15L4_C2",
            "What idea makes the light-year useful in astronomy?",
            ["Cosmic scales are enormous.", "Stars shine by reflection.", "Galaxies are always identical.", "Redshift is a unit of length."],
            0,
            "The unit exists because space scales are large.",
            ["light_year_small_distance_confusion"],
            ["distance_scale"],
        ),
    ]) + build_shorts([
        (
            "M15L4_C3",
            "Explain why the word 'year' in light-year can mislead students.",
            [
                "Because the word year looks like a time unit even though a light-year is actually a distance.",
                "Because the definition uses one year of travel to define a distance, not a duration for the object.",
            ],
            "Use apparent-time versus actual-distance language.",
            ["light_year_time_confusion"],
            ["identify_light_year"],
            acceptance_groups(["year"], ["looks", "sounds"], ["time"], ["but", "even though"], ["distance", "light-year"]),
        ),
    ])
    mastery = build_mcqs([
        (
            "M15L4_M1",
            "Which object is farther away?",
            ["the object at 300 light-years", "the object at 30 light-years", "they are equal", "light-years cannot compare distance"],
            0,
            "More light-years means greater distance.",
            ["light_year_time_confusion"],
            ["compare_distances"],
        ),
        (
            "M15L4_M2",
            "Case 3: source A is 2 light-years away and source B is 6 light-years away. Which is 3 times farther?",
            ["source B", "source A", "both", "neither"],
            0,
            "6 is 3 times 2, so B is three times farther.",
            ["light_year_time_confusion"],
            ["compare_distances"],
        ),
    ]) + build_shorts([
        (
            "M15L4_M3",
            "Summarize the signal-year idea in one strong sentence.",
            [
                "A signal-year is the distance light travels in one year, so it is a distance unit for huge cosmic scales.",
                "A light-year is a distance unit used for very large astronomical separations.",
            ],
            "Keep distance and scale together.",
            ["light_year_time_confusion", "light_year_small_distance_confusion"],
            ["identify_light_year", "distance_scale"],
            acceptance_groups(["light-year", "signal-year"], ["distance"], ["light"], ["one year"], ["huge", "cosmic", "astronomical"]),
        ),
    ])
    return lesson_spec(
        "M15_L4",
        "Switch to Signal-Years",
        sim(
            "m15_signal_year_lab",
            "Switch to signal-years",
            "Scale cosmic distance with one clear light-year ruler so astronomy distances stop sounding like times.",
            ["Compare two cosmic distances in light-years.", "Switch between kilometres and light-years."],
            ["Explain a light-year as distance.", "Compare large cosmic distances quantitatively."],
            ["distance_value", "unit_view", "scale_compare"],
            "Light-year distance scale.",
        ),
        diagnostic,
        "A signal-year is not a time label attached to a star. It is a distance: how far a light signal travels in one year. Astronomers use it because cosmic distances are so large that everyday units become awkward.",
        "Commit to reading light-year as a distance scale before mixing it into galaxy and expansion evidence.",
        [
            prompt_block("What does a signal-year measure?", "Distance."),
            prompt_block("Why use it?", "Because cosmic distances are enormous."),
        ],
        [
            prompt_block("Compare 4 light-years with 400 light-years.", "The second is farther away."),
            prompt_block("Switch between km and light-year scales.", "The light-year scale is more convenient for cosmic distances."),
        ],
        ["Why is a light-year a distance even though the word 'year' appears in it?", "Why do astronomers prefer light-years for very large separations?"],
        "This lesson gives the module its distance language so galaxies and expansion can be read on the right scale.",
        concept,
        mastery,
        contract(
            concept_targets=["Explain a light-year as a distance unit.", "Use light-years to compare large cosmic distances."],
            core_concepts=[
                "A light-year is the distance light travels in one year.",
                "Light-year is not a time unit.",
                "Cosmic distances are huge.",
                "Larger light-year values mean greater distance.",
            ],
            prerequisite_lessons=["M15_L3"],
            misconception_focus=["light_year_time_confusion", "light_year_small_distance_confusion"],
            formulas=[
                relation(
                    "distance = speed x time",
                    "A light-year uses one year of light travel to define a distance.",
                    ["km", "light-year"],
                    "Use conceptually to explain why a light-year is a distance.",
                )
            ],
            representations=[
                representation("words", "Defines light-year as distance, not time."),
                representation("formula", "distance = speed x time"),
                representation("diagram", "Shows distance scales from local to galactic."),
                representation("equation_story", "Connects travel time with distance definition."),
            ],
            analogy_map=beacon_city_map("the learner switches from everyday units to signal-years for cosmic distance"),
            worked_examples=[
                worked(
                    "Star A is 5 light-years away and star B is 50 light-years away. Which is farther and by what factor?",
                    [
                        "Read both measurements as distances.",
                        "Compare the numbers 50 and 5.",
                        "State the factor difference.",
                    ],
                    "Star B is farther, and it is 10 times farther away.",
                    "Because light-year is a distance unit, the numerical comparison works directly.",
                    "This helps students treat the unit quantitatively rather than as a vague astronomy label.",
                ),
                worked(
                    "A learner says, 'The Milky Way is 100,000 light-years across, so it must be 100,000 years old.' How do you correct that?",
                    [
                        "Separate age from distance.",
                        "Explain what a light-year measures.",
                        "Reinterpret the statement as galaxy size.",
                    ],
                    "The statement is describing the size of the Milky Way, not its age, because a light-year is a distance unit.",
                    "The word year in the unit can mislead learners unless the distance definition is kept explicit.",
                    "This targets one of the most persistent astronomy unit confusions.",
                ),
            ],
            visual_assets=[
                visual(
                    "m15-l4-light-year-scale",
                    "Signal-years are distance markers, not clock readings",
                    "Show local and galactic distance scales with a light-year ruler so the unit reads as spatial scale.",
                    "The lesson 4 visual turns the light-year into a clear distance ladder rather than a time-like label.",
                    diagram_type="light_year_scale",
                )
            ],
            animation_assets=[],
            simulation_contract=sim_contract(
                "m15_l4_signal_year_sim",
                "signal_year_scale",
                "Switch between kilometre-scale and light-year-scale views until the unit reads as distance automatically.",
                "Start with one nearby star and one much farther star.",
                ["Compare the two distances in light-years.", "Toggle a km view to see why the numbers become awkward."],
                "Watch the same physical separation look manageable in light-years and cumbersome in kilometres.",
                "Light-year is a distance unit chosen for huge scales.",
                controls=[
                    ("distance_value", "Distance value", "Changes the size of the separation being measured."),
                    ("unit_view", "Unit view", "Switches between kilometre and light-year style readouts."),
                    ("comparison_target", "Comparison target", "Adds a second object for farther-nearer comparisons."),
                ],
                readouts=[
                    ("Current distance", "Shows the selected separation in the active unit."),
                    ("Scale comment", "Explains why the chosen unit is or is not convenient."),
                ],
            ),
            reflection_prompts=["Explain why a light-year should be read as a distance marker instead of as a clock reading."],
            mastery_skills=["identify_light_year", "distance_scale", "compare_distances", "unit_reasoning", "scale_unit_choice"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between distance-definition, larger-smaller, and unit-purpose prompts.",
                "concept_gate": "Concept-gate retries alternate between direct distance comparisons and unit-correction explanations.",
                "mastery": "Mastery varies comparison, summary, and misconception-correction tasks before repeating an earlier distance-scale family.",
            },
            scaffold_support=scaffold(
                "A signal-year is a distance unit.",
                "The year in the name is part of the definition, but the quantity being measured is distance.",
                "How would you explain a light-year to stop someone from calling it a time unit?",
                "The word year tempts students to read the unit as time unless the travel-distance story is held in place.",
                "A signal-year is how far the light signal gets across the stretchmap in one year, so it belongs on the map as distance.",
                "What in the analogy makes this a map distance rather than a clock duration?",
                [
                    extra_section("Name trap", "The word year is what causes most of the confusion, so name the quantity before using the number.", "What physical quantity is being measured?"),
                    extra_section("Scale tool", "Astronomers use light-years because cosmic distances are enormous, not because stars age in light-years.", "Why is the unit helpful for galaxies?"),
                ],
            ),
            visual_clarity_checks=visual_checks("distance-scale"),
        ),
    )


def lesson_five() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        (
            "M15L5_D1",
            "Stretch-red drift stands for...",
            ["redshift", "fusion", "stellar mass", "light-year"],
            0,
            "Stretch-red drift is the analogy for redshift.",
            ["redshift_cooling_confusion"],
            ["identify_redshift"],
        ),
        (
            "M15L5_D2",
            "What happens to light when the stretchmap expands while the light is traveling?",
            [
                "its wavelength is stretched longer",
                "its source becomes a planet",
                "its galaxy becomes the Milky Way",
                "it stops being light",
            ],
            0,
            "Expansion stretches the light to longer wavelengths.",
            ["redshift_cooling_confusion", "redshift_color_only_confusion"],
            ["stretch_wavelength"],
        ),
        (
            "M15L5_D3",
            "Case 1: light from galaxy A is stretched more than light from galaxy B. Which one is more redshifted?",
            ["galaxy A", "galaxy B", "both equally", "cannot tell"],
            0,
            "Greater stretching means greater redshift.",
            ["farther_smaller_redshift_confusion"],
            ["compare_redshift"],
        ),
    ]) + build_shorts([
        (
            "M15L5_D4",
            "Why does stretching the map make light redder?",
            [
                "Because the wavelength of the traveling light is stretched longer, which shifts it toward the red end.",
                "Because expansion stretches the light's wavelength and longer wavelengths are redder.",
            ],
            "Use wavelength-stretch language.",
            ["redshift_cooling_confusion", "redshift_color_only_confusion"],
            ["stretch_wavelength"],
            acceptance_groups(["stretch", "stretched", "expand"], ["wavelength"], ["longer"], ["red", "redder"]),
        ),
    ])
    concept = build_mcqs([
        (
            "M15L5_C1",
            "Case 2: emitted wavelength 400 nm, observed wavelength 520 nm. Which is stronger?",
            ["redshift occurred", "blueshift occurred", "no wavelength change", "the source stopped emitting"],
            0,
            "Observed longer than emitted means redshift.",
            ["redshift_cooling_confusion"],
            ["stretch_wavelength"],
        ),
        (
            "M15L5_C2",
            "Which explanation best matches cosmological redshift?",
            [
                "space stretching the traveling light",
                "a lamp running out of battery",
                "stars reflecting less light",
                "galaxies turning into planets",
            ],
            0,
            "Expansion stretches light itself.",
            ["redshift_cooling_confusion", "expansion_into_space_confusion"],
            ["identify_redshift"],
        ),
    ]) + build_shorts([
        (
            "M15L5_C3",
            "Why is the phrase 'farther city, bigger redshift' useful evidence language?",
            [
                "Because more distant galaxies generally show greater wavelength stretch, which supports the expansion picture.",
                "Because larger redshift usually appears for farther galaxies, so the pattern supports expansion.",
            ],
            "Connect distance pattern to evidence.",
            ["farther_smaller_redshift_confusion"],
            ["redshift_evidence"],
            acceptance_groups(["farther", "more distant"], ["bigger", "greater"], ["redshift"], ["supports", "evidence", "expansion"]),
        ),
    ])
    mastery = build_mcqs([
        (
            "M15L5_M1",
            "Observed wavelength 700 nm compared with emitted wavelength 500 nm suggests...",
            ["redshift", "blueshift", "no shift", "star death"],
            0,
            "Longer observed wavelength means redshift.",
            ["redshift_cooling_confusion"],
            ["stretch_wavelength"],
        ),
        (
            "M15L5_M2",
            "Galaxy A has z = 0.05 and galaxy B has z = 0.50. Which broad conclusion is stronger?",
            [
                "Galaxy B shows the greater redshift and is usually farther away.",
                "Galaxy A must be farther.",
                "They are identical in recession evidence.",
                "Redshift and distance are unrelated.",
            ],
            0,
            "Larger z usually corresponds to stronger recession evidence.",
            ["farther_smaller_redshift_confusion"],
            ["compare_redshift"],
        ),
    ]) + build_shorts([
        (
            "M15L5_M3",
            "Summarize stretch-red drift in one strong sentence.",
            [
                "Stretch-red drift means light arrives with a longer wavelength because space expanded while the light was traveling.",
                "Cosmological redshift is stretched light from the expansion of space.",
            ],
            "Keep expansion and longer wavelength together.",
            ["redshift_cooling_confusion"],
            ["identify_redshift"],
            acceptance_groups(["light"], ["longer"], ["wavelength"], ["space", "universe", "expands"], ["traveling", "while traveling"]),
        ),
    ])
    return lesson_spec(
        "M15_L5",
        "Read the Stretch-Red Drift",
        sim(
            "m15_redshift_lab",
            "Read the stretch-red drift",
            "Stretch one traveling wavelength across an expanding map so redshift becomes a geometry-and-wavelength story.",
            ["Change the map stretch factor.", "Compare near and far galaxy light."],
            ["Interpret redshift qualitatively.", "Use larger redshift as evidence for expansion."],
            ["stretch_factor", "observed_wavelength", "distance_rank"],
            "Qualitative cosmological redshift.",
        ),
        diagnostic,
        "When the stretchmap itself grows, a traveling light wave can be stretched too. Longer wavelength means redder light, so the arriving city-light shows stretch-red drift. Bigger stretch generally goes with farther receding beacon-cities.",
        "Commit to redshift as stretched wavelength from expansion rather than as 'the source just got redder.'",
        [
            prompt_block("What changes in redshift?", "The wavelength becomes longer."),
            prompt_block("What does larger redshift usually suggest?", "Greater recession and usually greater distance."),
        ],
        [
            prompt_block("Compare emitted and observed wavelength.", "Observed longer means redshift."),
            prompt_block("Compare near and far galaxies.", "Farther ones usually show larger redshift."),
        ],
        ["Why does stretching space make light redder?", "Why is redshift useful evidence for expansion rather than just a colour label?"],
        "This lesson gives the module its observational evidence bridge from light and distance to cosmic expansion.",
        concept,
        mastery,
        contract(
            concept_targets=["Describe cosmological redshift as stretched wavelength.", "Use larger redshift as qualitative evidence for greater recession and expansion."],
            core_concepts=[
                "Redshift means longer observed wavelength.",
                "Expansion can stretch traveling light.",
                "Farther galaxies generally show larger cosmological redshifts.",
                "Redshift is not explained merely by saying the source became cooler.",
            ],
            prerequisite_lessons=["M15_L4"],
            misconception_focus=["redshift_cooling_confusion", "redshift_color_only_confusion", "farther_smaller_redshift_confusion"],
            formulas=[
                relation(
                    "longer observed wavelength -> redshift",
                    "Cosmological redshift is read from wavelength increase.",
                    ["nm"],
                    "Use qualitatively when comparing spectra.",
                ),
                relation(
                    "larger redshift -> generally greater recession",
                    "The farther-city bigger-redshift pattern supports expansion.",
                    ["concept only"],
                    "Use as qualitative evidence language.",
                ),
            ],
            representations=[
                representation("words", "Explains redshift as stretched wavelength."),
                representation("formula", "observed wavelength > emitted wavelength -> redshift"),
                representation("diagram", "Shows wavelength stretching across an expanding map."),
                representation("graph", "Supports ranking larger and smaller redshifts."),
            ],
            analogy_map=beacon_city_map("the learner reads galaxy light getting stretched redder as the map expands"),
            worked_examples=[
                worked(
                    "A spectral line is emitted at 500 nm and observed at 650 nm. What qualitative conclusion is strongest?",
                    [
                        "Compare emitted with observed wavelength.",
                        "Notice the observed wavelength is longer.",
                        "Translate longer wavelength into the redshift language.",
                    ],
                    "The light is redshifted.",
                    "Redshift is the longer-wavelength arrival of the same light.",
                    "This anchors the phenomenon in wavelength comparison rather than in vague colour description.",
                ),
                worked(
                    "Two galaxies are compared. One shows a much larger redshift than the other. What broad inference is strongest?",
                    [
                        "Use the farther-city bigger-redshift pattern.",
                        "Treat redshift as evidence of stronger recession.",
                        "State the broad distance comparison cautiously.",
                    ],
                    "The one with the larger redshift is usually farther away and receding more strongly.",
                    "Cosmological redshift is one of the key clues that the universe is expanding.",
                    "This connects the wavelength evidence to the expansion model.",
                ),
            ],
            visual_assets=[
                visual(
                    "m15-l5-redshift-expansion",
                    "Stretching the map stretches the light",
                    "Show near and far beacon-city spectra with different wavelength stretch so redshift reads as evidence.",
                    "The lesson 5 visual keeps emitted wavelength, observed wavelength, and distance trend on one board.",
                    diagram_type="redshift_expansion",
                )
            ],
            animation_assets=[],
            simulation_contract=sim_contract(
                "m15_l5_redshift_sim",
                "stretch_red_drift",
                "Change the stretch factor and compare how near and far galaxy light arrives.",
                "Start with one emitted wavelength and no map stretch.",
                ["Increase the stretch factor and compare the observed wavelength.", "Place one galaxy farther away and compare the redshift size."],
                "Watch the wavelength bars lengthen as the map stretch increases.",
                "Greater wavelength stretch means greater redshift, and farther galaxies usually show more of it.",
                controls=[
                    ("stretch_factor", "Stretch factor", "Changes how much the map expands during travel."),
                    ("distance_rank", "Galaxy distance", "Compares a nearer and farther beacon-city."),
                    ("emitted_wavelength", "Emitted wavelength", "Keeps the starting signal visible before stretching."),
                ],
                readouts=[
                    ("Observed wavelength", "Shows the wavelength after stretching."),
                    ("Redshift read", "Summarizes whether the current case is smaller or larger redshift."),
                ],
            ),
            reflection_prompts=["Explain why cosmological redshift is stronger as a stretchmap effect than as a 'cooling source' explanation."],
            mastery_skills=["identify_redshift", "stretch_wavelength", "compare_redshift", "redshift_evidence", "wavelength_comparison"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between wavelength-change, larger-smaller redshift, and misconception-correction prompts.",
                "concept_gate": "Concept-gate retries alternate between numeric wavelength comparisons and expansion-evidence summaries.",
                "mastery": "Mastery varies ranking, summary, and correction tasks before repeating an earlier redshift family.",
            },
            scaffold_support=scaffold(
                "Redshift is stretched wavelength.",
                "The important move is comparing emitted and observed wavelength, then linking bigger stretch to the expansion picture.",
                "How would you explain why redshift is about wavelength rather than just colour appearance?",
                "Students often say 'it just looks red' or 'the source cooled' and lose the wavelength-stretch cause.",
                "When the stretchmap grows, the light wave crossing it grows in wavelength too, so the arriving signal shifts redward.",
                "Which part of the analogy corresponds to wavelength getting longer during travel?",
                [
                    extra_section("Measure the change", "Compare emitted wavelength with observed wavelength to anchor the idea in a measurable change.", "What became longer?"),
                    extra_section("Pattern as evidence", "Use the farther-city bigger-redshift trend as evidence for expansion rather than as a stand-alone fact.", "Why does the trend support expansion?"),
                ],
            ),
            visual_clarity_checks=visual_checks("redshift"),
        ),
    )


def lesson_six() -> Dict[str, Any]:
    diagnostic = build_mcqs([
        (
            "M15L6_D1",
            "The Great Unfurling stands for the...",
            ["Big Bang and expanding universe", "death of the Sun", "one supernova", "Moon phases"],
            0,
            "The Great Unfurling is the Big Bang / expansion model.",
            ["big_bang_center_explosion_confusion"],
            ["identify_big_bang"],
        ),
        (
            "M15L6_D2",
            "Which statement is strongest?",
            [
                "The Big Bang model says the universe began hot and dense and has been expanding.",
                "The Big Bang was ordinary shrapnel from one point into empty space.",
                "The Big Bang means galaxies do not move apart.",
                "The Big Bang is just another word for one star explosion.",
            ],
            0,
            "Use hot-dense-plus-expanding space language.",
            ["big_bang_center_explosion_confusion", "expansion_into_space_confusion"],
            ["identify_big_bang"],
        ),
        (
            "M15L6_D3",
            "Case 1: if farther galaxies usually show larger redshifts, what broad model does that support?",
            ["an expanding universe", "a perfectly static universe", "a Solar-System-only model", "all galaxies collapsing toward us"],
            0,
            "The redshift pattern supports expansion.",
            ["big_bang_center_explosion_confusion"],
            ["expansion_evidence"],
        ),
    ]) + build_shorts([
        (
            "M15L6_D4",
            "Why is 'expanding map' better than 'ordinary explosion' as a Big Bang analogy?",
            [
                "Because the Big Bang model describes space itself expanding, not matter flying from one centre into empty space.",
                "Because the stretchmap analogy keeps the expansion in space itself rather than in debris moving into outside emptiness.",
            ],
            "Use space-expands rather than explosion-centre language.",
            ["big_bang_center_explosion_confusion", "expansion_into_space_confusion"],
            ["space_expands"],
            acceptance_groups(["space"], ["expand", "expanding"], ["not", "rather than"], ["centre", "center", "explosion"], ["empty space", "outside"]),
        ),
    ])
    concept = build_mcqs([
        (
            "M15L6_C1",
            "Which statement best fits the Great Unfurling model?",
            [
                "The whole stretchmap expands, so distant light arrives redder.",
                "One giant bomb threw galaxies through empty space from one point.",
                "The universe is static but stars change colour.",
                "The Milky Way stays fixed while nothing else exists.",
            ],
            0,
            "Keep expansion of the map and redshift together.",
            ["big_bang_center_explosion_confusion", "expansion_into_space_confusion"],
            ["identify_big_bang"],
        ),
        (
            "M15L6_C2",
            "Case 2: if galaxy C has z = 0.01 and galaxy D has z = 0.40, which broad expansion inference is stronger?",
            [
                "D is usually farther and fits the expansion trend more strongly.",
                "C must be farther.",
                "The pattern argues against expansion.",
                "Redshift values cannot support any inference.",
            ],
            0,
            "Larger redshift fits the farther-galaxy trend.",
            ["farther_smaller_redshift_confusion"],
            ["expansion_evidence"],
        ),
    ]) + build_shorts([
        (
            "M15L6_C3",
            "Why do astronomers treat redshift as evidence for expansion and not just as an isolated color fact?",
            [
                "Because the distance-redshift pattern across many galaxies fits the expansion model.",
                "Because the widespread farther-city bigger-redshift trend supports an expanding universe.",
            ],
            "Connect the pattern across galaxies to the model.",
            ["farther_smaller_redshift_confusion"],
            ["expansion_evidence"],
            acceptance_groups(["pattern", "trend"], ["farther", "more distant"], ["bigger", "larger"], ["redshift"], ["supports", "evidence"], ["expansion"]),
        ),
    ])
    mastery = build_mcqs([
        (
            "M15L6_M1",
            "Which statement is the best correction to 'the Big Bang was a blast from one spot into empty space'?",
            [
                "The model describes space itself expanding from an early hot, dense state.",
                "The model says the Milky Way exploded.",
                "The model says stars stopped shining.",
                "The model says only nearby galaxies exist.",
            ],
            0,
            "Use expansion-of-space language.",
            ["big_bang_center_explosion_confusion", "expansion_into_space_confusion"],
            ["space_expands"],
        ),
        (
            "M15L6_M2",
            "Case 3: galaxies with larger redshifts are generally...",
            [
                "farther away in the expansion evidence pattern",
                "closer to us than low-redshift galaxies",
                "proof that light-year is time",
                "evidence against expansion",
            ],
            0,
            "Larger cosmological redshift usually goes with greater distance.",
            ["farther_smaller_redshift_confusion"],
            ["expansion_evidence"],
        ),
    ]) + build_shorts([
        (
            "M15L6_M3",
            "Summarize the Great Unfurling idea in one strong sentence.",
            [
                "The Great Unfurling means the universe began hot and dense and has been expanding, so distant galaxy light arrives redshifted.",
                "The Big Bang model describes an expanding universe, and galaxy redshift patterns are key evidence for it.",
            ],
            "Keep hot-dense beginning, expansion, and redshift evidence together.",
            ["big_bang_center_explosion_confusion", "expansion_into_space_confusion"],
            ["identify_big_bang"],
            acceptance_groups(["hot", "dense"], ["expand", "expanding"], ["universe"], ["redshift", "redshifted"], ["evidence", "galaxy light"]),
        ),
    ])
    return lesson_spec(
        "M15_L6",
        "Great Unfurling Evidence",
        sim(
            "m15_unfurling_lab",
            "Great Unfurling evidence",
            "Link redshift pattern and expansion language so the Big Bang model reads as evidence-based rather than slogan-based.",
            ["Compare several galaxy redshifts.", "Switch between centre-explosion and expanding-space descriptions."],
            ["Describe the Big Bang as an expanding-universe model.", "Use galaxy redshift patterns as evidence for expansion."],
            ["redshift_rank", "model_phrase", "distance_pattern"],
            "Big Bang and expansion evidence.",
        ),
        diagnostic,
        "The Great Unfurling is not an ordinary explosion from one spot into empty space. It is the whole stretchmap of space expanding from an early hot, dense state. As that happens, distant city-light arrives stretched redder, and the farther-city bigger-redshift pattern becomes evidence for expansion.",
        "Commit to the expanding-space picture before you summarize the Big Bang evidence.",
        [
            prompt_block("What is the stronger Big Bang picture?", "A hot, dense early universe that expanded."),
            prompt_block("What pattern supports expansion?", "Farther galaxies usually show larger redshifts."),
        ],
        [
            prompt_block("Compare low and high redshift galaxies.", "The larger redshift usually belongs to the farther one."),
            prompt_block("Compare 'explosion into space' with 'space expands.'", "The second is the stronger model."),
        ],
        ["Why is the Big Bang not best imagined as an ordinary explosion from one centre?", "Why does the galaxy redshift pattern support expansion?"],
        "This lesson closes the module by connecting the distance, wavelength, and expansion ideas into one evidence-based universe story.",
        concept,
        mastery,
        contract(
            concept_targets=["Describe the Big Bang as an expanding-universe model.", "Use redshift patterns as evidence for cosmic expansion."],
            core_concepts=[
                "The Big Bang model describes an early hot, dense universe that expanded.",
                "Expansion means space itself changes scale.",
                "Cosmological redshift supports expansion.",
                "The farther-galaxy larger-redshift pattern is key evidence language.",
            ],
            prerequisite_lessons=["M15_L5"],
            misconception_focus=["big_bang_center_explosion_confusion", "expansion_into_space_confusion", "farther_smaller_redshift_confusion"],
            formulas=[
                relation(
                    "larger redshift -> stronger recession evidence",
                    "The distance-redshift trend supports cosmic expansion.",
                    ["concept only"],
                    "Use qualitatively in this lesson.",
                )
            ],
            representations=[
                representation("words", "Defines the Big Bang as an expanding-universe model."),
                representation("formula", "larger redshift -> stronger expansion evidence"),
                representation("diagram", "Shows hot-dense beginning, expansion, and redshift evidence on one board."),
                representation("table", "Ranks galaxy distance and redshift qualitatively."),
            ],
            analogy_map=beacon_city_map("the learner uses redshift evidence to support an expanding-universe picture"),
            worked_examples=[
                worked(
                    "A learner says, 'The Big Bang was just one giant bomb at one place in space.' What is the strongest correction?",
                    [
                        "Replace the explosion image with the stretchmap image.",
                        "State that the model describes space itself expanding from an early hot, dense state.",
                        "Avoid assigning one special centre in outside space.",
                    ],
                    "The Big Bang model is about the expansion of space itself, not an ordinary explosion from one centre into empty space.",
                    "That is the crucial geometric correction behind the modern model.",
                    "This addresses one of the most persistent misconceptions in cosmology teaching.",
                ),
                worked(
                    "Galaxy A shows much larger cosmological redshift than galaxy B. Why is that relevant to the Big Bang model?",
                    [
                        "Use the farther-city bigger-redshift pattern.",
                        "Interpret larger redshift as stronger expansion evidence.",
                        "Connect the pattern to the expanding-universe idea.",
                    ],
                    "The larger redshift suggests galaxy A is usually farther away and fits the expansion pattern more strongly, which supports the Big Bang model.",
                    "The model is evidence-based: redshift patterns are one of the main clues.",
                    "This keeps cosmology linked to observation.",
                ),
            ],
            visual_assets=[
                visual(
                    "m15-l6-big-bang-timeline",
                    "The Great Unfurling is an expanding map, not a centre explosion",
                    "Show hot-dense early conditions, expansion of space, and a redshift evidence trend on one board.",
                    "The lesson 6 visual closes the module by tying Big Bang language to the distance-redshift evidence pattern.",
                    diagram_type="big_bang_timeline",
                )
            ],
            animation_assets=[],
            simulation_contract=sim_contract(
                "m15_l6_unfurling_sim",
                "great_unfurling_evidence",
                "Compare model language and redshift evidence until the expansion story becomes coherent.",
                "Start with three galaxies at different distances on the same stretchmap.",
                ["Rank their redshifts and compare the expansion claim.", "Switch between a centre-explosion caption and an expanding-space caption."],
                "Watch which caption still fits when the whole stretchmap and the redshift pattern are shown together.",
                "The Big Bang model is an expanding-universe model supported by galaxy redshift evidence.",
                controls=[
                    ("redshift_rank", "Galaxy redshifts", "Changes the comparative redshift pattern across the galaxies."),
                    ("model_phrase", "Model phrase", "Switches between stronger and weaker verbal descriptions."),
                    ("distance_pattern", "Distance pattern", "Shows whether the farther-city bigger-redshift trend is present."),
                ],
                readouts=[
                    ("Evidence status", "Says whether the current pattern supports expansion strongly or weakly."),
                    ("Model match", "Indicates which description best matches the current evidence."),
                ],
            ),
            reflection_prompts=["Explain why the expanding-map description is stronger than an ordinary explosion description for the Big Bang model."],
            mastery_skills=["identify_big_bang", "space_expands", "expansion_evidence", "redshift_pattern_reasoning", "expansion_language"],
            variation_plan={
                "diagnostic": "Fresh attempts rotate between model-language, redshift-pattern, and misconception-correction prompts.",
                "concept_gate": "Concept-gate retries alternate between centre-explosion corrections and larger-redshift evidence comparisons.",
                "mastery": "Mastery varies summary, explanation, and galaxy-pattern tasks before repeating an earlier expansion-evidence family.",
            },
            scaffold_support=scaffold(
                "The Great Unfurling is the expansion of the map itself.",
                "Use the redshift pattern as evidence and the expanding-space wording as the correct model description.",
                "How would you explain the Big Bang without saying 'an explosion from one spot'?",
                "Students often keep a centre-explosion picture because it feels familiar, but it misdescribes what is expanding.",
                "The whole stretchmap unfurls, so the city spacing changes everywhere and the traveling light stretches with it.",
                "What feature of the analogy corrects the idea of a single centre blast?",
                [
                    extra_section("Model language", "Choose language that keeps the geometry right before adding evidence.", "Which phrase preserves the geometry best?"),
                    extra_section("Evidence pattern", "Use the farther-city bigger-redshift pattern to connect the model to observation.", "What observation pattern supports expansion?"),
                ],
            ),
            visual_clarity_checks=visual_checks("cosmic expansion"),
        ),
    )


M15_SPEC = {
    "authoring_standard": AUTHORING_STANDARD_V3,
    "module_description": "Stars, stellar lifecycles, galaxies, the Milky Way, light-years, cosmological redshift, and the Big Bang taught through the Beacon-City Stretchmap Model so self-lit stars, gravity-bound galaxies, cosmic distance scale, and expansion evidence stay inside one coherent universe story.",
    "mastery_outcomes": [
        "Explain stars as luminous bodies powered by fusion in their cores.",
        "Outline the stellar lifecycle qualitatively and explain why stellar mass changes the final path.",
        "Describe galaxies as gravity-bound collections of stars and identify the Milky Way as our home galaxy.",
        "Explain a light-year as a distance measure for huge cosmic scales.",
        "Interpret redshift qualitatively as stretched light from receding galaxies in an expanding universe.",
        "Explain the Big Bang as a hot, dense early-universe model supported by redshift evidence.",
    ],
    "lessons": [lesson_one(), lesson_two(), lesson_three(), lesson_four(), lesson_five(), lesson_six()],
}


RELEASE_CHECKS = [
    "Every lesson keeps the Beacon-City Stretchmap language of beacons, beacon-cities, signal-years, stretch-red drift, and the Great Unfurling coherent.",
    "Every explorer uses lesson-specific controls and readouts instead of the generic simulation fallback.",
    "Every lesson keeps one dedicated authored visual and one lesson-specific simulation contract.",
    "Every M15 visual keeps star, galaxy, distance, wavelength, and expansion labels readable without clipping or overlap.",
]


M15_MODULE_DOC, M15_LESSONS, M15_SIM_LABS = build_nextgen_module_bundle(
    module_id=M15_MODULE_ID,
    module_title=M15_MODULE_TITLE,
    module_spec=M15_SPEC,
    allowlist=M15_ALLOWLIST,
    content_version=M15_CONTENT_VERSION,
    release_checks=RELEASE_CHECKS,
    sequence=22,
    level="Module 15",
    estimated_minutes=320,
    authoring_standard=AUTHORING_STANDARD_V3,
    plan_assets=True,
    public_base="/lesson_assets",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed Module M15 into Firestore")
    parser.add_argument("--project", default=None)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--compile-assets", action="store_true")
    parser.add_argument("--asset-root", default="")
    parser.add_argument("--public-base", default="/lesson_assets")
    args = parser.parse_args()

    project = get_project_id(args.project)
    init_firebase(project)
    asset_root = args.asset_root or default_asset_root()
    module_doc = deepcopy(M15_MODULE_DOC)
    lesson_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M15_LESSONS]
    sim_pairs = [(doc_id, deepcopy(payload)) for doc_id, payload in M15_SIM_LABS]

    if args.compile_assets:
        render_module_assets(lesson_pairs, sim_pairs, asset_root=asset_root, public_base=args.public_base)

    print_preview(module_doc, lesson_pairs, sim_pairs)
    db = init_firebase(project)
    plan: List[Tuple[str, str]] = [("modules", M15_MODULE_ID)]
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
